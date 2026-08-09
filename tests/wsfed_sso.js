const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
const { addBrowserAccessFlags } = require("./browser_flags");
const { assertEdgeLandingContract } = require("./edge_landing_contract");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'wsfed_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// WS-Federation Passive Requestor Profile SSO test. Mirrors saml_sso.js, but:
//   - the sign-in request is a top-level browser navigation (wa=wsignin1.0) and
//     is NOT signed (no SP key to load — passive profile);
//   - the IdP is the dedicated Keycloak 8.0.1 + cloudtrust wsfed side-car;
//   - the IdP POSTs a wresult (WS-Trust RSTR carrying a SAML assertion) to a
//     landing at the debugger's /wsfed, which hands it to wsfed_response.html
//     where the token is rendered.
//
// That landing is one of two implementations, and this test drives both without
// caring which: the api backend's Express route (POST /wsfed -> stash ->
// ?id=<stash>), or, on the STATIC S3 + CloudFront deployments, the Lambda@Edge in
// infra/edge/wsfed_landing.js (POST /wsfed -> sessionStorage -> ?posted=1). The
// second one exists because the passive profile has no redirect response binding:
// SAML's static deployments dodge this by asking the IdP to return the response
// over HTTP-Redirect to a static page (see responseProtocolBinding() in
// saml_request.js), and WS-Federation has no such option — the token comes back
// as a POST or not at all, so a static site needs code at the edge to catch it.
// The assertions below are written against what the user sees, so they hold for
// either landing; tests/edge_landing_contract.js separately guards the one thing
// that cannot be checked through the browser, namely that the Lambda and the
// page still agree on the hand-off key names.
//
// Then it signs the user out (wa=wsignout1.0) in the same browser, because that
// leg needs the session the sign-in established — see wsfedSignOutActivities().
// Sign-out returns no token, so what is asserted is the wa the IdP was actually
// sent (read back off the landing's redirect) and that the session is really
// gone: signing in again must require credentials rather than silently issuing a
// second token off a surviving SSO cookie.
// Env: WSFED_METADATA_URL (the side-car descriptor), WSFED_REALM (the wtrealm ==
// the provisioned client id), WSFED_USER (login user; password == username).

async function waitForValue(driver, locator, predicate, message, timeout) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return predicate(v || "");
    } catch (e) { return false; }
  }, timeout || waitTime, message);
}

async function clickByValue(driver, value) {
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

async function setField(driver, id, value) {
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e){ e.value = arguments[1];" +
    " e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); }",
    id, value);
}

async function setChecked(driver, id, want) {
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e && e.checked!==arguments[1]){ e.checked=arguments[1];" +
    " e.dispatchEvent(new Event('change',{bubbles:true})); }",
    id, !!want);
}

async function setRadio(driver, id) {
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e){ e.checked=true;" +
    " e.dispatchEvent(new Event('change',{bubbles:true})); }",
    id);
}

async function getValue(driver, id) {
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); return e ? e.value : null;", id);
}
async function elementExists(driver, id) {
  return await driver.executeScript("return !!document.getElementById(arguments[0]);", id);
}

// The sign-out operation label recorded in the shared Operations History — must
// match wsfed_history.js's OP_SIGN_OUT exactly.
var OP_SIGN_OUT = "Sign Out (wsignout1.0)";

// Assert the Operations History (on whichever page is currently loaded) resolved
// the given operation to Success — a green saml-ok Result cell. This is the
// user-visible confirmation that the call a button dispatched actually completed:
// for the sign-out it proves the Logout button's request went out AND the IdP
// reported it done, not merely that a button was clicked.
async function assertOperationSuccess(driver, operationLabel, timeout) {
  await driver.wait(async function () {
    return await driver.executeScript(function (op) {
      var box = document.getElementById('wsfed_operation_history');
      if (!box) return false;
      var rows = box.getElementsByTagName('tr');
      for (var i = 0; i < rows.length; i++) {
        var cells = rows[i].getElementsByTagName('td');
        if (!cells.length) continue;
        var isOp = false;
        for (var c = 0; c < cells.length; c++) {
          if (cells[c].textContent.indexOf(op) >= 0) { isOp = true; break; }
        }
        if (!isOp) continue;
        var result = cells[cells.length - 1];
        return result.className.indexOf('saml-ok') >= 0 && /Success/.test(result.textContent);
      }
      return false;
    }, operationLabel);
  }, timeout, "the Operations History did not record '" + operationLabel + "' as Success.");
}

// The passive sign-in endpoint is the descriptor URL without the trailing
// "/descriptor" (Keycloak serves both under /protocol/wsfed). Deriving it makes
// the test robust to any metadata-parsing quirk in the (EOL) extension's
// descriptor format, while metadata loading is still exercised below.
function deriveEndpoint(metadataUrl) {
  return String(metadataUrl || "").replace(/\/descriptor\/?(\?.*)?$/, "");
}

// ---------------------------------------------------------------------------
// Option combination for a single run, read from the environment (run-report.js
// spawns one process per combination — see its WS-Fed job loop). Every option
// the wsfed_request workflow supports and that this test drives is here:
//   WSFED_MODE          "signin" (default) | "signout" (sign-in then sign-out)
//   WSFED_SIGN          "on" | "off"  — the "Digitally sign request" checkbox
//   WSFED_SIG_BINDING   "redirect" | "enveloped"      (when signing)
//   WSFED_SIG_ALG       "rsa-sha256"|"rsa-sha1"|"rsa-sha384"|"rsa-sha512"
//   WSFED_INITIATE      "back" | "front"  — the "Initiate From" radios
//   WSFED_OPT_PARAMS    "true" — set the optional passthrough params (wctx/wct/
//                       wfresh/wauth/wp) once
//   WSFED_INCLUDE_WREQ  "true" — include an (unsigned) inline wreq
// ---------------------------------------------------------------------------
var SIG_ALG_URIS = {
  "rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "rsa-sha1":   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  "rsa-sha384": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  "rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
};

function combinationFromEnv() {
  var binding = (process.env.WSFED_SIG_BINDING || "redirect").toLowerCase();
  return {
    mode: (process.env.WSFED_MODE || "signin").toLowerCase(),
    sign: (process.env.WSFED_SIGN || "off").toLowerCase() === "on",
    binding: binding,
    sigAlg: (process.env.WSFED_SIG_ALG || "rsa-sha256").toLowerCase(),
    initiate: (process.env.WSFED_INITIATE || "back").toLowerCase(),
    optionalParams: (process.env.WSFED_OPT_PARAMS || "") === "true",
    // Enveloped signing needs an inline wreq to sign, so it implies one.
    includeWreq: (process.env.WSFED_INCLUDE_WREQ || "") === "true" || (binding === "enveloped")
  };
}

function comboLabel(combo) {
  var sign = combo.sign ? (combo.binding + "+" + combo.sigAlg) : "unsigned";
  return "mode=" + combo.mode + " sign=" + sign + " initiate=" + combo.initiate +
    (combo.optionalParams ? " +optparams" : "") +
    (combo.includeWreq && !combo.sign ? " +wreq" : "");
}

// A minimal, valid WS-Trust RequestSecurityToken to place in wreq — enough for
// the enveloped-signature path to have real XML to sign, and for the inline-wreq
// path to carry a token-type request.
function sampleWreqXml() {
  return '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>' +
    '</wst:RequestSecurityToken>';
}

// Apply a combination to the form BEFORE the sign-in is sent. Returns nothing;
// throws (with a rebuild hint) if a signed run is asked for but the signing
// controls are absent — i.e. the client bundle predates the signing feature.
async function applyCombination(driver, combo, timeout) {
  log.info("Applying combination: " + comboLabel(combo));

  // Initiate From. On a backend-available target both radios are live; on a
  // static one "backend" is disabled, so only set what exists/works.
  if (combo.initiate === "front") { await setRadio(driver, "wsfed_initiateFromFrontEnd"); }
  else { if (await elementExists(driver, "wsfed_initiateFromBackEnd")) await setRadio(driver, "wsfed_initiateFromBackEnd"); }

  // Optional passthrough params (wctx echoed back; the rest the IdP mostly
  // ignores). whr is intentionally omitted: it is a home-realm hint that needs a
  // federated IdP alias configured at the side-car, and an unknown value breaks
  // login — that would be an IdP-config failure, not a workflow one.
  if (combo.optionalParams) {
    await setField(driver, "wsfed_context", "wsfed-test-ctx");
    await setChecked(driver, "wsfed_include_wct", true);
    await setField(driver, "wsfed_freshness", "60");
    await setField(driver, "wsfed_auth_type", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
    await setField(driver, "wsfed_policy", "urn:wsfed:test:policy");
  }

  if (!combo.sign) {
    // Ensure signing is off (the page default is ON) when it exists.
    if (await elementExists(driver, "wsfed_sign_request")) await setChecked(driver, "wsfed_sign_request", false);
    // An unsigned inline-wreq run still needs the wreq itself.
    if (combo.includeWreq) {
      await setChecked(driver, "wsfed_include_wreq", true);
      await setField(driver, "wsfed_wreq", sampleWreqXml());
    }
    return;
  }

  // Signed run. The signing controls only exist in a client bundle built with
  // the request-signing feature; fail loudly (not silently unsigned) otherwise.
  assert(await elementExists(driver, "wsfed_sign_request"),
    "WSFED_SIGN=on but the 'Digitally sign request' control is absent — rebuild the client bundle " +
    "(the request-signing feature must be compiled into public/js/wsfed_request.js).");
  await setChecked(driver, "wsfed_sign_request", true);

  // A key pair is required to sign (otherwise the page degrades to unsigned).
  await clickByValue(driver, "Generate Keys");
  await waitForValue(driver, By.id("wsfed_rp_private_key"),
    function (v) { return /PRIVATE KEY/.test(v); },
    "the RP key pair was not generated (needed to sign the request).", timeout);

  await setField(driver, "wsfed_sig_binding", combo.binding);
  await setField(driver, "wsfed_sig_alg", SIG_ALG_URIS[combo.sigAlg] || SIG_ALG_URIS["rsa-sha256"]);

  if (combo.binding === "enveloped") {
    // Selecting the enveloped binding auto-enables the inline wreq; give it real
    // XML to sign.
    await setChecked(driver, "wsfed_include_wreq", true);
    await setField(driver, "wsfed_wreq", sampleWreqXml());
  }
  // No explicit rebuild needed: the generated request auto-updates on every
  // field change across the panes, and Generate Keys rebuilds once the key
  // exists — so the last field set above has already refreshed the request.
}

// Verify — client-side, before the round trip — that the debugger actually
// produced the requested signature. This is the deterministic heart of the
// signing feature; whether the (EOL) IdP then honours it is a separate, best-
// effort concern (the passive profile does not require request signing).
async function assertSignatureGenerated(driver, combo, timeout) {
  await waitForValue(driver, By.id("wsfed_call_status"),
    function (v) { return /signature|signed query string/i.test(v); },
    "the request-signature status never appeared.", timeout);
  var status = await getValue(driver, "wsfed_call_status");
  var req = (await getValue(driver, "wsfed_generated_request")) || "";
  log.info("Signing status: " + status);
  if (combo.binding === "redirect") {
    assert(/signed query string/i.test(status),
      "expected a redirect-binding query-string signature; status was: " + status);
    assert(req.indexOf("SigAlg=") >= 0 && req.indexOf("Signature=") >= 0,
      "the generated request is missing the SigAlg/Signature parameters.");
  } else {
    assert(/enveloped signature on the inline wreq/i.test(status),
      "expected an enveloped signature on the inline wreq; status was: " + status);
    assert(decodeURIComponent(req).indexOf("Signature") >= 0,
      "the generated request's wreq is missing the enveloped ds:Signature.");
  }
}

async function wsfedActivities(driver, metadataUrl, realm, user, combo) {
  log.debug("Entering wsfedActivities().");
  combo = combo || combinationFromEnv();
  // Keycloak's login page + the WS-Fed round-trip need a generous timeout.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the WS-Federation Test Tools page.");
  await driver.get(baseUrl + "/wsfed_request.html");

  // Load + parse the IdP metadata (best-effort: it populates the sign-in
  // endpoint + signer cert; we don't hard-fail on descriptor-format quirks).
  log.info("Load IdP metadata from " + metadataUrl);
  var mdField = By.id("wsfed_metadata_url");
  await driver.wait(until.elementLocated(mdField), waitTime);
  await driver.findElement(mdField).clear();
  await driver.findElement(mdField).sendKeys(metadataUrl);
  try {
    await clickByValue(driver, "Load Metadata");
    await waitForValue(driver, By.id("wsfed_metadata_status"),
      function (v) { return v.indexOf("Parsed metadata") >= 0; },
      "metadata parse status", loginWait);
    log.info("Metadata parsed.");
  } catch (e) {
    log.warn("Metadata load/parse did not complete cleanly (" + e.message + ") — continuing with the derived endpoint.");
  }

  // Ensure the passive sign-in endpoint + RP realm (wtrealm) are set. Set the
  // endpoint explicitly (derived) so the flow does not depend on the parse.
  var endpoint = await driver.findElement(By.id("wsfed_signin_endpoint")).getAttribute("value");
  if (!endpoint) { endpoint = deriveEndpoint(metadataUrl); await setField(driver, "wsfed_signin_endpoint", endpoint); }
  log.info("Sign-in endpoint: " + endpoint);
  await setField(driver, "wsfed_realm", realm);

  // Apply the option combination for this run (signing, initiate-from, optional
  // params, inline wreq), then — for a signed run — confirm the debugger built
  // the requested signature before we hand off to the IdP.
  await applyCombination(driver, combo, loginWait);
  if (combo.sign) { await assertSignatureGenerated(driver, combo, loginWait); }

  // wreply decides whether this test can work at all, and the page's DEFAULT is
  // what is being checked — not something the test sets, because the default is
  // the deployment's own statement about where its landing is. The static
  // response page is the one value that cannot work: the IdP POSTs the token,
  // and a POST to a static object is answered 403/405, so the round trip would
  // end at the last hop with nothing to show. Assert it here rather than letting
  // the wait below time out saying only "the response page never loaded".
  var reply = await driver.findElement(By.id("wsfed_reply")).getAttribute("value");
  log.info("wreply (the page's default): " + reply);
  assert(reply, "wsfed_reply (wreply) is empty, so the IdP has nowhere to return the token.");
  assert(!/\/wsfed_response\.html(\?|$)/.test(reply),
    "wreply defaults to the static response page (" + reply + "), which cannot receive the IdP's POST. " +
    "On a static deployment it should be the /wsfed landing answered by the Lambda@Edge — set " +
    "wsfedEdgeLanding: true in the client env config for this target and redeploy the site bundle " +
    "(see infra/edge/wsfed_landing.js).");

  // Send the sign-in request (wa=wsignin1.0). Button value is "Call IdP (Sign In)".
  log.info("Call IdP (Sign In). wtrealm=" + realm);
  await clickByValue(driver, "Call IdP (Sign In)");

  // Keycloak login (same login form as the other tests; user == password).
  log.info("Log in at Keycloak.");
  var username = By.id("username");
  var password = By.id("password");
  var kcLogin = By.id("kc-login");
  await driver.wait(until.elementLocated(username), loginWait);
  await driver.wait(until.elementIsVisible(driver.findElement(username)), loginWait);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(password).clear();
  await driver.findElement(password).sendKeys(user);
  await driver.findElement(kcLogin).click();

  // Land on the response page. The landing at /wsfed got there first and handed
  // the wresult over — the api one by stashing it and passing ?id=, the edge one
  // by putting it in sessionStorage and passing ?posted=1. Either way the page
  // reports the same thing, so the assertion does not need to know which.
  log.info("Wait for the WS-Federation response page.");
  await driver.wait(until.urlContains("wsfed_response.html"), loginWait,
    "the IdP's POST never reached a landing that could forward it to the response page. " +
    "On a static deployment that is what a missing (or not-yet-applied) Lambda@Edge looks like: " +
    "CloudFront answers the POST to /wsfed from S3 with 403/405 and the browser stops there.");
  log.info("Landed at: " + (await driver.getCurrentUrl()));
  await waitForValue(driver, By.id("wsfed_resp_status"),
    function (v) { return v.indexOf("wresult loaded.") >= 0; },
    "wresult was not loaded on the response page.", loginWait);

  var respXml = await driver.findElement(By.id("wsfed_response_xml")).getAttribute("value");
  log.info("wresult (first 1500 chars):\n" + (respXml || "").substring(0, 1500));

  // Core assertions: the wresult is a WS-Trust RSTR and the extracted token is a
  // SAML assertion.
  assert(respXml.indexOf("RequestSecurityTokenResponse") >= 0,
    "wresult is not a WS-Trust RequestSecurityTokenResponse — see the logged wresult above.");
  await waitForValue(driver, By.id("wsfed_token_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 && v.indexOf("no <wst:RequestedSecurityToken") < 0; },
    "No SAML Assertion was extracted from the wresult.", loginWait);

  // Best-effort: validate the token signature (exercises the button; the IdP
  // cert is embedded in the assertion's KeyInfo). Logged, not hard-asserted, so
  // a signature-format quirk of the EOL extension doesn't fail the basic flow.
  try {
    await clickByValue(driver, "Validate Signature");
    await driver.sleep(500);
    var sig = await driver.findElement(By.id("wsfed_sig_status")).getAttribute("value");
    log.info("Signature validation: " + sig);
  } catch (e) { log.warn("Signature validation step skipped: " + e.message); }

  log.info("WS-Federation SSO round-trip succeeded.");
  log.debug("Leaving wsfedActivities().");
}

// ---------------------------------------------------------------------------
// Sign-out (wa=wsignout1.0), driven from the same page, after the sign-in above.
//
// The passive profile's sign-out is a top-level navigation like the sign-in, and
// it returns NO token — so there is nothing to inspect, and the only things worth
// asserting are what actually happened:
//
//   1. the browser came back to wreply as a sign-out and not as a sign-in: the
//      /wsfed landing gets no wresult, so it redirects to
//      wsfed_response.html?signout=<the wa it received, or 1>, and the page says
//      so. Note that the wa on that final hop is the extension's choice, not
//      ours — see the assertion below.
//   2. the IdP session is really gone. This is the assertion that matters and the
//      one a redirect alone does not make: signing in again must land on
//      Keycloak's login form rather than silently minting a second token off a
//      surviving SSO cookie.
//
// The page's own Sign Out button is used, with the endpoint falling back to the
// sign-in endpoint exactly as buildSignOutUrl() does — Keycloak advertises both
// under /protocol/wsfed.
// ---------------------------------------------------------------------------
async function wsfedSignOutActivities(driver, metadataUrl, realm) {
  log.debug("Entering wsfedSignOutActivities().");
  var loginWait = Math.max(waitTime, 15000);

  log.info("Return to the WS-Federation Test Tools page to sign out.");
  await driver.get(baseUrl + "/wsfed_request.html");
  await driver.wait(until.elementLocated(By.id("wsfed_metadata_url")), waitTime);

  // The sign-out endpoint may have come from the descriptor; if it did not, the
  // page falls back to the sign-in endpoint, so make sure at least one is set.
  var pre = await driver.executeScript(
    "return { signout: (document.getElementById('wsfed_signout_endpoint') || {}).value || ''," +
    "         signin: (document.getElementById('wsfed_signin_endpoint') || {}).value || ''," +
    "         realm: (document.getElementById('wsfed_realm') || {}).value || ''," +
    "         reply: (document.getElementById('wsfed_reply') || {}).value || '' };");
  if (!pre.signin) { await setField(driver, "wsfed_signin_endpoint", deriveEndpoint(metadataUrl)); }
  if (!pre.realm) { await setField(driver, "wsfed_realm", realm); }
  // wreply is where the IdP sends the browser afterwards, and it is what makes the
  // sign-out observable here at all. The page defaults it to the /wsfed landing —
  // Express's or the edge one, depending on the deployment; if that default is
  // missing there is no landing at all and this leg cannot be checked, which is
  // worth saying rather than guessing a URL.
  assert(pre.reply,
    "wsfed_reply (wreply) is empty, so the IdP has nowhere to return the browser after sign-out. " +
    "The page normally defaults it to the /wsfed landing.");
  log.info("Sign-out preconditions: endpoint=" + (pre.signout || pre.signin) +
           " wtrealm=" + (pre.realm || realm) + " wreply=" + pre.reply);

  log.info("Click Sign Out (wa=wsignout1.0).");
  await clickByValue(driver, "Sign Out");

  // Back on the response page, with the sign-out flag the landing passed on. Both
  // landings redirect to ?signout=<wa or 1>, so this leg is identical on either.
  await driver.wait(until.urlContains("wsfed_response.html"), loginWait,
    "the IdP did not return the browser to the wreply landing after sign-out.");
  var url = await driver.getCurrentUrl();
  assert(url.indexOf("signout=") >= 0,
    "the sign-out landing should carry the signout flag rather than a token id. Got: " + url);
  // Which flag value arrives is decided by the extension, not by us, and it is
  // deliberately not asserted to be "wsignout1.0" — that would be wrong. Reading
  // WSFedService.handleLogoutRequest and WSFedLoginProtocol at tag 8.0.1-1.0: the
  // sign-out request stashes wreply, marks this client's session LOGGED_OUT and
  // calls browserLogout; the browser then comes back through finishLogout, which
  // builds the redirect with the wctx and NO wa at all. So the landing sees no wa
  // and falls back to signout=1 (both implementations do; that fallback is one of
  // the things the edge Lambda copies from the Express route deliberately). A run where another client is still in the
  // session instead passes through frontchannelLogout, which does send
  // wa=wsignoutcleanup1.0. Both are correct WS-Federation behaviour, so all three
  // values are accepted and the one that arrived is logged.
  var flag = decodeURIComponent((url.match(/[?&]signout=([^&]*)/) || [])[1] || "");
  assert(["1", "wsignout1.0", "wsignoutcleanup1.0"].indexOf(flag) >= 0,
    "the sign-out landing's flag should be the wa the IdP sent (wsignout1.0 / wsignoutcleanup1.0) or the " +
    "api's fallback when it sends none. Got: '" + flag + "' from " + url);
  log.info("Sign-out landed with signout=" + flag +
           (flag === "1" ? " (finishLogout sends no wa — see the comment above)." : "."));
  await waitForValue(driver, By.id("wsfed_resp_status"),
    function (v) { return /[Ss]igned out/.test(v); },
    "the response page did not report the sign-out.", loginWait);
  var status = await driver.findElement(By.id("wsfed_resp_status")).getAttribute("value");
  log.info("Sign-out landing: " + status);

  // The Logout (Sign Out) button's operation is recorded in the shared history as
  // "Sent" when clicked, then resolved here on the response page. Assert it landed
  // on Success — the user-visible sign that the logout call completed.
  await assertOperationSuccess(driver, OP_SIGN_OUT, loginWait);
  log.info("Operations History records the sign-out as Success.");

  // And no token came back with it: sign-out returns none.
  var leftover = await driver.findElement(By.id("wsfed_response_xml")).getAttribute("value");
  assert(!leftover || leftover.indexOf("RequestSecurityTokenResponse") < 0,
    "a sign-out must not deliver a token, but the response page is showing an RSTR.");

  // The real check: the IdP session is gone, so signing in again has to
  // re-authenticate. If the SSO cookie survived, this navigation goes straight
  // back to the response page with a fresh token and never shows a login form.
  log.info("Sign in again — Keycloak must now ask for credentials.");
  await driver.get(baseUrl + "/wsfed_request.html");
  await driver.wait(until.elementLocated(By.id("wsfed_signin_endpoint")), waitTime);
  // callIdp() refuses to navigate with an empty endpoint or wtrealm — it only sets
  // a status — so make sure both are filled. Without this, a page that came back
  // with empty fields would look like the IdP never answered.
  var again = await driver.executeScript(
    "return { signin: (document.getElementById('wsfed_signin_endpoint') || {}).value || ''," +
    "         realm: (document.getElementById('wsfed_realm') || {}).value || '' };");
  if (!again.signin) { await setField(driver, "wsfed_signin_endpoint", deriveEndpoint(metadataUrl)); }
  if (!again.realm) { await setField(driver, "wsfed_realm", realm); }
  await clickByValue(driver, "Call IdP (Sign In)");
  var outcome = await driver.wait(async function () {
    var here = await driver.getCurrentUrl();
    if (here.indexOf("wsfed_response.html") >= 0) { return "token"; }
    var fields = await driver.findElements(By.id("username"));
    if (fields.length) { return "login"; }
    return null;
  }, loginWait, "after signing out, a second sign-in neither showed a login form nor returned a token.");
  assert.strictEqual(outcome, "login",
    "after wa=wsignout1.0 the IdP session must be gone, so the second sign-in should have shown " +
    "Keycloak's login form. Instead it issued a token without asking — the sign-out did not end the " +
    "session at the IdP.");

  log.info("WS-Federation sign-out succeeded: the IdP reported the sign-out and the session was ended " +
           "(the next sign-in required credentials again).");
  log.debug("Leaving wsfedSignOutActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // Private Network Access (the IdP side-car is on this host's loopback while the
  // page may be a deployed https site) AND secure context (Validate Signature
  // needs window.crypto.subtle, which does not exist on a plain-http non-localhost
  // origin like the container's http://client:3000). See browser_flags.js.
  addBrowserAccessFlags(options, baseUrl);

  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    const metadataUrl = process.env.WSFED_METADATA_URL;
    const realm = process.env.WSFED_REALM || "urn:wsfed:test:rp";
    const user = process.env.WSFED_USER || "wsfed";
    const combo = combinationFromEnv();
    assert(metadataUrl, "WSFED_METADATA_URL environment variable is not set.");

    // Cheap, no browser, and it fails with a message that names the cause —
    // so it runs before the round trip rather than after it.
    assertEdgeLandingContract(log);

    log.info("WS-Federation run: " + comboLabel(combo));
    await wsfedActivities(driver, metadataUrl, realm, user, combo);
    // Sign-out needs the session the sign-in just established, so it runs in the
    // same browser, in this order, and only for the dedicated sign-out job.
    if (combo.mode === "signout") {
      await wsfedSignOutActivities(driver, metadataUrl, realm);
    }
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0, 8000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" + blogs.map(function (e) { return e.level.name + ": " + e.message; }).join("\n"));
      }
    } catch (e2) { /* ignore */ }
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('wsfed_sso')
  .description("Run WS-Federation Passive Requestor SSO test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
