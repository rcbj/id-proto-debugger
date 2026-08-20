// File: rfc9700_flows.js
//
// ---------------------------------------------------------------------------
// Every OAuth2 / OIDC grant this debugger supports, driven through
// oauth2_oidc_1.html and oauth2_oidc_2.html with **BOTH SIDES IN RFC 9700
// MODE** — the debugger's compliance checkbox on, and the mock STS started
// with STS_OAUTH2_RFC9700=true.
//
// That pairing is the point of the file. The existing OAuth2 / OIDC jobs run
// this same matrix with both sides permissive, and between them the two passes
// ask different questions:
//
//   permissive  — does the debugger still work against a server that
//                 implements none of this? (Most servers. It is why the
//                 checkbox exists.)
//   compliant   — when the server DOES enforce RFC 9700, does the client meet
//                 it? An authorization server in that mode refuses a redirect
//                 URI it has not been given, refuses PKCE it cannot verify,
//                 refuses a response type that would put an access token in
//                 the address bar, and issues over https only. A client that
//                 quietly sent the wrong thing in the permissive pass is
//                 indistinguishable from one that did not; here it fails.
//
// The negatives matter more than the positives and are a job of their own
// (RFC9700_FLOW=refused). A compliance mode that issues a token on the happy
// path looks finished and can be worth nothing: what it is FOR is refusing the
// Implicit Grant, refusing the password grant, refusing a code presented
// twice, and refusing a response whose state or nonce does not match. Those
// cannot be reached from the happy path by definition.
//
// The always-on half — the headers, the 303, the form_post landing, and the
// callback not being an open redirector — is checked over plain HTTP at the
// start of every job, before a browser is built. Those are not behind the
// checkbox (see rfc9700.js's note on why), and they are cheap enough to assert
// on every run rather than in one job somebody might skip.
//
// The STS is located from WSTRUST_STS_URL, as the other STS-backed jobs are.
// RFC9700_FLOW selects what to run.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "rfc9700_flows",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

// The identity typed at the mock's sign-in screen. The mock checks no
// password, so this is simply the name every token then describes — which is
// why it can be, and is, generated per run: the mock keeps a users page, an
// authentication log and a statistics pane keyed by the name presented, and a
// name every test shares makes all of that unattributable. The prefix names
// this file so a row in any of them can be traced back to it. Pin it with
// RFC9700_USER (or RANDOM_USERNAME_STAMP) to re-drive a failed run.
const USER = process.env.RFC9700_USER || usernameFor("rfc9700-flows");
// The mock registers no clients, so this is any string — but it must be the
// same one throughout, because requirement 13.1 compares the token's sub
// against it.
const CLIENT_ID = "rfc9700-debugger";

// ---------------------------------------------------------------------------
// What each job runs. `label` is the option text in the grant selector, which
// is what a user picks and therefore what this picks.
//
// Three of the debugger's eleven grants survive RFC 9700 mode and are driven
// end to end here. What is absent is as deliberate as what is present:
//
//   the three Implicit variants and two of the three Hybrids — refused by
//     requirement 1.11, and the `refused` job proves it rather than this one
//     quietly not listing them;
//   Resource Owner Password Credentials — refused by 5.1, same;
//   the Device Authorization Grant — the debugger permits it (RFC 9700 says
//     nothing against it) but the mock STS in RFC 9700 mode publishes no
//     device_authorization_endpoint, so there is nothing to drive it against.
//     Stated here rather than left as an absence somebody has to account for.
// ---------------------------------------------------------------------------
const FLOWS = {
  authorization_grant: {
    label: "OAuth2 Authorization Code Grant",
    responseType: "code",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  oidc_authorization_code_flow: {
    label: "OIDC Authorization Code Flow(code)",
    responseType: "code",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  oidc_hybrid_code_id_token: {
    label: "OIDC Hybrid(code id_token)",
    responseType: "code id_token",
    scope: "openid profile email offline_access",
    exchangesCode: true
  },
  client_credential: {
    label: "OAuth2 Client Credential",
    responseType: "",
    scope: "openid profile",
    exchangesCode: false
  }
};

// The grants RFC 9700 mode must refuse, and the requirement each one meets.
const REFUSED_GRANTS = {
  implicit_grant: "1.11",
  oidc_implicit_flow: "1.11",
  oidc_implicit_flow_id_token: "1.11",
  oidc_hybrid_code_token: "1.11",
  oidc_hybrid_code_id_token_token: "1.11",
  resource_owner: "5.1"
};


// ---------------------------------------------------------------------------
// Plain HTTP, for the checks that need no browser.
// ---------------------------------------------------------------------------

// One request, no redirect following, self-signed certificates accepted. The
// mock STS in RFC 9700 mode is HTTPS with a certificate it generated at
// startup, which is the whole reason for the last part.
function request(url, options) {
  log.debug("Entering request(). url=" + url);
  var opts = options || {};
  return new Promise(function (resolve, reject) {
    var parsed = new URL(url);
    var lib = parsed.protocol === "https:" ? https : http;
    var req = lib.request(url, {
      method: opts.method || "GET",
      headers: opts.headers || {},
      rejectUnauthorized: false
    }, function (res) {
      var body = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) { body += chunk; });
      res.on("end", function () {
        log.debug("Leaving request(). status=" + res.statusCode);
        resolve({ status: res.statusCode, headers: res.headers, body: body });
      });
    });
    req.on("error", reject);
    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}

// The always-on posture, over the wire rather than over the source.
// tests/rfc9700_client.js asserts the same properties by reading
// client/server.js; this asserts that the running deployment actually sends
// them, which is a different claim — a reverse proxy, a CDN or a build that
// serves public/ some other way can drop every one of them.
async function checkAlwaysOnPosture() {
  log.debug("Entering checkAlwaysOnPosture().");
  log.info("Entering checkAlwaysOnPosture().");

  const page = await request(baseUrl + "/oauth2_oidc_2.html");
  assert.strictEqual(page.status, 200,
    "The debugger's token page did not answer 200.");
  assert.strictEqual(page.headers["referrer-policy"], "no-referrer",
    "Requirement 10.2: the page that receives an authorization response is " +
    "served without Referrer-Policy: no-referrer, so the response's URL " +
    "travels to every link and resource on it.");
  assert.strictEqual(page.headers["x-frame-options"], "DENY",
    "Requirement 14.1: X-Frame-Options is not DENY.");
  assert.ok(/frame-ancestors 'none'/.test(
      page.headers["content-security-policy"] || ""),
    "Requirement 14.1: the Content-Security-Policy does not restrict " +
    "frame-ancestors. RFC 9700 section 4.16 asks for CSP Level 2 and that " +
    "is the clause it means.");

  // 12.1 and 11.1, on the GET landing.
  const got = await request(baseUrl + "/callback?code=abc&state=xyz");
  assert.strictEqual(got.status, 303,
    "Requirement 12.1: GET /callback answered " + got.status + " rather " +
    "than 303.");
  assert.ok(got.headers.location.indexOf("/oauth2_oidc_2.html") !== -1,
    "GET /callback did not forward to the token page: " +
    got.headers.location);

  // 11.1 for real: a request that TRIES to choose the destination, under
  // three of the parameter names that usually work.
  //
  // What is asserted is the ORIGIN AND PATH of the Location, not the absence
  // of the attacker's host from the whole header — because /callback copies
  // the authorization response's parameters through to the page, and an
  // attacker's string sitting in the QUERY of a URL whose destination is this
  // deployment's own page is not a redirect anywhere. Getting that distinction
  // wrong in the assertion is how a test comes to demand a fix that would
  // break every identity provider sending a vendor parameter.
  const openRedirect = await request(baseUrl +
    "/callback?code=abc&state=xyz&redirect_uri=https://evil.example.com/" +
    "&return_to=https://evil.example.com/&url=https://evil.example.com/");
  const landed = new URL(openRedirect.headers.location);
  assert.strictEqual(landed.origin + landed.pathname,
    new URL(baseUrl).origin + "/oauth2_oidc_2.html",
    "Requirement 11.1: /callback forwarded to a destination taken from the " +
    "request — " + openRedirect.headers.location + ". An open redirector on " +
    "a registered redirect_uri is how an authorization code is stolen from a " +
    "client that did everything else right.");

  // 10.4 and 12.1, on the form_post landing.
  const posted = await request(baseUrl + "/callback", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "code=the-code&state=the-state&iss=" +
          encodeURIComponent("https://op.example.com")
  });
  assert.strictEqual(posted.status, 303,
    "Requirement 12.1: POST /callback answered " + posted.status + ". A 307 " +
    "would replay the method and the body — which here IS the authorization " +
    "response — onto the next hop.");
  assert.ok(posted.headers.location.indexOf("#") !== -1,
    "Requirement 10.4: the form_post landing did not put the response in a " +
    "fragment: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("?") === -1,
    "Requirement 10.4: the form_post landing put the response in a QUERY " +
    "string, which is the address bar and the history entry this response " +
    "mode exists to keep it out of: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("the-code") !== -1,
    "The form_post landing dropped the code: " + posted.headers.location);
  assert.ok(posted.headers.location.indexOf("evil") === -1);

  log.info("Leaving checkAlwaysOnPosture(). The always-on posture holds.");
  log.debug("Leaving checkAlwaysOnPosture().");
}

// The other side of the pairing this file is named for. A run against an STS
// that is NOT in RFC 9700 mode would pass most of these assertions and prove
// nothing, so it is refused by name rather than allowed to look green.
async function requireCompliantSts(stsUrl) {
  log.debug("Entering requireCompliantSts().");
  const report = await request(stsUrl + "/oauth2/rfc9700");
  assert.strictEqual(report.status, 200,
    "The STS at " + stsUrl + " does not publish GET /oauth2/rfc9700, so it " +
    "predates its own RFC 9700 support. This job needs a build that has it.");
  const parsed = JSON.parse(report.body);
  assert.strictEqual(parsed.enabled, true,
    "The STS at " + stsUrl + " is NOT in RFC 9700 mode. Start it with " +
    "STS_OAUTH2_RFC9700=true. Running this job against a permissive server " +
    "would exercise the client's checks against a server that never " +
    "disagrees with them, which is the one arrangement that proves nothing.");
  log.info("The STS is in RFC 9700 mode.");
  log.debug("Leaving requireCompliantSts().");
  return parsed;
}

// An RFC 9700 authorization server compares redirect_uri by exact string
// match against URIs it was given, so the debugger's callback has to be one of
// them. This is not a workaround for the test: it is the registration step the
// specification requires, and doing it here is what makes the pairing honest.
async function registerRedirectUri(stsUrl) {
  log.debug("Entering registerRedirectUri().");
  const body = JSON.stringify({ key: "oauth2.redirectUris",
                                value: baseUrl + "/callback" });
  const res = await request(stsUrl + "/admin-api/config/set", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Content-Length": Buffer.byteLength(body) },
    body: body
  });
  assert.strictEqual(res.status, 200,
    "Could not register " + baseUrl + "/callback with the STS: " +
    res.status + " " + res.body.slice(0, 300));
  log.info("Registered " + baseUrl + "/callback with the STS.");
  log.debug("Leaving registerRedirectUri().");
}


// ---------------------------------------------------------------------------
// The browser.
// ---------------------------------------------------------------------------
async function buildDriver() {
  log.debug("Entering buildDriver().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  // The mock STS in RFC 9700 mode is HTTPS on a certificate it generated at
  // startup, so nothing has an anchor for it. This is the whole reason the
  // pairing needs a flag the permissive pass does not: with the mode off the
  // STS is plain http and every one of these runs happily without it.
  options.addArguments("--ignore-certificate-errors");
  options.setAcceptInsecureCerts(true);
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  log.debug("Leaving buildDriver().");
  return await new Builder().forBrowser("chrome").setChromeOptions(options)
      .setLoggingPrefs(prefs).build();
}

// Tick the compliance checkbox, wherever on the workflow we happen to be.
// Returns nothing; the caller asserts what it wanted from it.
async function enableComplianceMode(driver) {
  log.debug("Entering enableComplianceMode().");
  log.info("Entering enableComplianceMode().");
  const box = By.id("rfc9700_mode");
  await driver.wait(until.elementLocated(box), waitTime);
  if (!(await driver.findElement(box).isSelected())) {
    // Clicked through the DOM rather than by Selenium's own click, because the
    // Configuration Parameters pane can be collapsed on any visit after the
    // first (initializeUIPostDebuggerInitialization() collapses it once
    // discovery has run) and an invisible control is "not interactable" — the
    // hazard tests/CLAUDE.md records against the grant selector, which is two
    // rows below this one.
    await driver.executeScript("arguments[0].click();",
                               await driver.findElement(box));
  }
  assert.strictEqual(await driver.executeScript(
    "return window.localStorage.getItem('rfc9700_mode');"), "true",
    "The RFC 9700 checkbox did not record the mode as on.");
  log.info("Leaving enableComplianceMode().");
  log.debug("Leaving enableComplianceMode().");
}

// Which grant options the selector has disabled, as an array of values.
async function disabledGrants(driver) {
  log.debug("Entering disabledGrants().");
  const values = await driver.executeScript(
    "return Array.from(document.querySelectorAll(" +
    "'#authorization_grant_type option')).filter(function (o) {" +
    "return o.disabled; }).map(function (o) { return o.value; });");
  log.debug("Leaving disabledGrants(). n=" + values.length);
  return values;
}

// Fill in the authorization request and return what the page built.
async function prepareRequest(driver, flow) {
  log.debug("Entering prepareRequest(). flow=" + flow.label);
  log.info("Entering prepareRequest(). flow=" + flow.label);
  const selector = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(selector), waitTime);
  if (!(await driver.findElement(selector).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(selector)),
                      waitTime);
  }
  await new Select(await driver.findElement(selector))
      .selectByVisibleText(flow.label);

  const clientIdField = By.id("client_id");
  await driver.wait(until.elementLocated(clientIdField), waitTime);
  if (!(await driver.findElement(clientIdField).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(
    driver.findElement(clientIdField)), waitTime);

  for (const [id, value] of [["client_id", CLIENT_ID],
                             ["scope", flow.scope],
                             ["redirect_uri", baseUrl + "/callback"]]) {
    await driver.findElement(By.id(id)).clear();
    await driver.findElement(By.id(id)).sendKeys(value);
  }
  // Typing does not always redraw the preview (it is rebuilt on change and
  // keypress handlers that clear() + sendKeys() do not reliably fire), so ask.
  await driver.executeScript(
    "oauth2_oidc_1.recalculateAuthorizationRequestDescription();");
  const preview = await driver.findElement(
    By.id("display_authz_request_form_textarea1")).getAttribute("value");
  log.info("Authorization request preview:\n" + preview);
  log.debug("Leaving prepareRequest().");
  return preview;
}

// The mock's sign-in screen, which reuses Keycloak's field ids.
async function signIn(driver, user) {
  log.debug("Entering signIn().");
  log.info("Entering signIn(). user=" + user);
  const username = By.id("username");
  try {
    await driver.wait(until.elementLocated(username), waitTime * 3);
    await driver.wait(until.elementIsVisible(driver.findElement(username)),
                      waitTime);
  } catch (e) {
    // No sign-in screen means the authorization request was refused. In this
    // job that is the interesting failure, so say where the browser is rather
    // than reporting a timeout on a field.
    throw new Error("The STS did not show its sign-in screen, so it refused " +
      "the authorization request. The browser is at: " +
      (await driver.getCurrentUrl()));
  }
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  const password = await driver.findElements(By.id("password"));
  if (password.length) {
    await password[0].clear();
    await password[0].sendKeys(user);
  }
  await driver.findElement(By.id("kc-login")).click();
  log.info("Leaving signIn().");
  log.debug("Leaving signIn().");
}

// The text of one of the three RFC 9700 report panes.
async function reportText(driver, id) {
  log.debug("Entering reportText(). id=" + id);
  const panes = await driver.findElements(By.id(id));
  if (!panes.length) {
    log.debug("Leaving reportText(). No pane.");
    return "";
  }
  const text = await panes[0].getText();
  log.debug("Leaving reportText(). " + text.length + " characters.");
  return text;
}

// Assert that a report names a requirement, and that the row is not a failing
// one. The id is what is asserted rather than the wording: a report that fires
// under the wrong id sends a reader to the wrong section of the specification,
// and the wording is the part that is allowed to be improved.
function assertReportSays(text, id, what) {
  log.debug("Entering assertReportSays(). id=" + id);
  assert.ok(text.indexOf("(" + id + ")") !== -1,
    what + ": the report does not mention requirement " + id + ". It said:\n" +
    text);
  log.debug("Leaving assertReportSays().");
}

function assertNotRefused(text, what) {
  log.debug("Entering assertNotRefused().");
  assert.ok(text.indexOf("Refused.") === -1,
    what + ": RFC 9700 mode refused this step. The report said:\n" + text);
  log.debug("Leaving assertNotRefused().");
}


// ---------------------------------------------------------------------------
// The jobs.
// ---------------------------------------------------------------------------

// The happy path for one grant, both sides compliant.
async function runFlow(driver, flowKey, stsUrl) {
  log.debug("Entering runFlow(). flowKey=" + flowKey);
  const flow = FLOWS[flowKey];
  assert.ok(flow, "Unknown RFC9700_FLOW: " + flowKey);

  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await enableComplianceMode(driver);
  await populateMetadata(driver,
                         stsUrl + "/.well-known/openid-configuration");

  // Requirement 8.1: every endpoint the metadata populated must be https. The
  // STS is on the loopback interface here, so this would also pass over plain
  // http — which is why the assertion is on the SCHEME the STS published
  // rather than on the check's verdict.
  const issuer = await driver.findElement(By.id("issuer")).getAttribute(
    "value");
  assert.ok(issuer.indexOf("https://") === 0,
    "Requirement 8.1: the STS in RFC 9700 mode published a plain-http " +
    "issuer (" + issuer + "). It binds its main port as HTTPS in that mode, " +
    "so this means the pairing is not what it claims to be.");

  if (!flow.exchangesCode) {
    // The Client Credentials grant never visits the authorization endpoint,
    // so there is no authorization request, no state, no nonce and no code —
    // and, importantly, RFC 9700 mode must not invent findings about their
    // absence. That is the whole of what this branch checks.
    log.info("Client Credentials: no authorization request to make.");
    await driver.get(baseUrl + "/oauth2_oidc_2.html");
    const response = await reportText(driver, "rfc9700_response_report");
    assert.strictEqual(response, "",
      "RFC 9700 mode drew an authorization-response report for a grant that " +
      "makes no authorization request. It said:\n" + response);
    log.debug("Leaving runFlow(). Client Credentials.");
    return;
  }

  const preview = await prepareRequest(driver, flow);

  // What the request must carry, before it is sent. Checked here rather than
  // afterwards because everything downstream still looks plausible when one of
  // these is missing — a server that does not enforce PKCE issues a perfectly
  // good token to a request that carried no challenge.
  assert.ok(/response_type=/.test(preview) &&
            preview.indexOf("response_type=" + flow.responseType) !== -1,
    "The request does not carry response_type=" + flow.responseType + ":\n" +
    preview);
  assert.ok(/code_challenge=\S+/.test(preview),
    "Requirement 1.6: the request carries no code_challenge:\n" + preview);
  assert.ok(/code_challenge_method=S256/.test(preview),
    "Requirement 1.7: the request does not use S256:\n" + preview);
  assert.ok(/state=\S+/.test(preview),
    "Requirement 2.1: the request carries no state:\n" + preview);
  assert.ok(/nonce=\S+/.test(preview),
    "Requirement 3.3: the request carries no nonce:\n" + preview);
  // Requirement 10.4. The mock STS advertises form_post in RFC 9700 mode and
  // this build has a backend to receive it, so both conditions hold and the
  // client must ask for it.
  assert.ok(/response_mode=form_post/.test(preview),
    "Requirement 10.4: the STS advertises form_post and this build has a " +
    "/callback to receive it, so the request should have asked for it:\n" +
    preview);

  const sentState = await driver.findElement(By.id("state")).getAttribute(
    "value");
  const sentNonce = await driver.findElement(
    By.id("nonce_field")).getAttribute("value");

  await driver.executeScript("oauth2_oidc_1.triggerAuthZEndpointCall();");
  await signIn(driver, USER);
  await driver.wait(until.urlContains("oauth2_oidc_2.html"), waitTime * 2);
  // The page reads the response and then removes it from the URL, so give the
  // ready() handler its chance before looking.
  await driver.wait(async function () {
    return !!(await reportText(driver, "rfc9700_response_report"));
  }, waitTime * 2, "The RFC 9700 authorization-response report never drew.");

  // Requirement 10.1: the response is out of the address bar. With form_post
  // it was never in a query string at all, and the fragment the landing used
  // to carry it across is gone too.
  const landedAt = await driver.getCurrentUrl();
  log.info("Landed at: " + landedAt);
  assert.ok(landedAt.indexOf("?") === -1 && landedAt.indexOf("#") === -1,
    "Requirement 10.1: the authorization response is still in the address " +
    "bar, and therefore in this history entry: " + landedAt);
  assert.ok(landedAt.indexOf(sentState) === -1);

  const responseReport = await reportText(driver, "rfc9700_response_report");
  log.info("Authorization response report:\n" + responseReport);
  assertNotRefused(responseReport, "the authorization response");
  assertReportSays(responseReport, "2.2", "state");
  assertReportSays(responseReport, "2.5", "the RFC 9207 iss parameter");
  assert.ok(/state matches/i.test(responseReport),
    "Requirement 2.2: the report does not say the state matched:\n" +
    responseReport);
  assert.ok(/iss matches/i.test(responseReport),
    "Requirement 2.5: the STS advertises the iss parameter and the report " +
    "does not say it matched:\n" + responseReport);

  // Requirement 3.1 needs the code, and the URL no longer has it — which is
  // itself the thing 10.1 just asserted. It is read off the field the page
  // filled, which is where the token request will take it from.
  const code = await driver.findElement(By.id("code")).getAttribute("value");
  assert.ok(code && code.length > 4,
    "The Token Request pane opened with no authorization code in it. With " +
    "response_mode=form_post the code arrives in the landing's fragment " +
    "rather than in a query string, so this is where that goes wrong.");

  // Exchange it.
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
    await driver.findElement(By.className("token_btn")));
  await driver.findElement(By.className("token_btn")).click();
  await driver.wait(async function () {
    return (await reportText(driver, "rfc9700_token_report"))
      .indexOf("Token Response") !== -1;
  }, waitTime * 3, "The RFC 9700 token-response report never drew.");

  const tokenReport = await reportText(driver, "rfc9700_token_report");
  log.info("Token response report:\n" + tokenReport);
  assertNotRefused(tokenReport, "the token response");
  assertReportSays(tokenReport, "3.2", "the ID Token nonce");
  assert.ok(/nonce matches/i.test(tokenReport),
    "Requirement 3.2: the report does not say the ID Token's nonce matched " +
    "the value sent (" + sentNonce + "):\n" + tokenReport);
  assertReportSays(tokenReport, "2.7", "the ID Token issuer");
  assertReportSays(tokenReport, "4.2", "the access token's audience");

  const accessToken = await driver.executeScript(
    "return window.localStorage.getItem('token_access_token');");
  assert.ok(accessToken && accessToken.length > 20,
    "No access token was issued. RFC 9700 mode discards a token set whose " +
    "nonce or issuer does not check out, so this is either that or the " +
    "exchange itself failing.");
  log.info("Access token issued and accepted by every applicable check.");

  // Requirement 3.1, live: the same code, a second time. This is the one that
  // cannot be reached from the happy path and is most of why this job exists —
  // a server that answers a replayed code has a defect, and a client that
  // presents one has already made it unfindable.
  // The pane has to be re-opened first: a successful exchange collapses the
  // Token Request fieldset, so the button is present and invisible and
  // Selenium reports "element not interactable" — which reads as a broken
  // page rather than as a pane that did what it was supposed to. Re-expanding
  // is also what a person would do to press it again.
  await driver.executeScript(
    "document.getElementById('token_fieldset').style.display = 'block';");
  await driver.wait(until.elementIsVisible(
    driver.findElement(By.className("token_btn"))), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
    await driver.findElement(By.className("token_btn")));
  await driver.findElement(By.className("token_btn")).click();
  await driver.wait(async function () {
    return (await reportText(driver, "rfc9700_token_report"))
      .indexOf("Refused.") !== -1;
  }, waitTime * 2,
    "Requirement 3.1: presenting the same authorization code a second time " +
    "was not refused. The report said:\n" +
    (await reportText(driver, "rfc9700_token_report")));
  const replayReport = await reportText(driver, "rfc9700_token_report");
  assertReportSays(replayReport, "3.1", "the replayed code");
  log.info("A replayed authorization code was refused, citing 3.1.");

  log.debug("Leaving runFlow().");
}

// The negatives: what RFC 9700 mode is actually for.
async function runRefusals(driver, stsUrl) {
  log.debug("Entering runRefusals().");
  log.info("Entering runRefusals().");

  await driver.get(baseUrl + "/oauth2_oidc_1.html");

  // Before the mode is on, NOTHING is disabled. This is the mode-off contract
  // seen from the browser, and it is the assertion that would catch the day a
  // check started firing unconditionally — at which point this debugger would
  // refuse to talk to most of the identity providers it exists for.
  await driver.executeScript(
    "window.localStorage.setItem('rfc9700_mode', 'false');");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  const beforeMode = await disabledGrants(driver);
  assert.deepStrictEqual(beforeMode, [],
    "With the RFC 9700 checkbox CLEAR, the grant selector has options " +
    "disabled: " + beforeMode.join(", ") + ". Nothing in this mode may act " +
    "until it is switched on.");
  const beforeReport = await reportText(driver, "rfc9700_request_report");
  assert.strictEqual(beforeReport, "",
    "With the mode off, an RFC 9700 report was drawn anyway:\n" +
    beforeReport);
  log.info("The mode-off contract holds: nothing disabled, nothing drawn.");

  // Now on.
  await enableComplianceMode(driver);
  const disabled = await disabledGrants(driver);
  Object.keys(REFUSED_GRANTS).forEach(function (grant) {
    assert.ok(disabled.indexOf(grant) !== -1,
      "Requirement " + REFUSED_GRANTS[grant] + ": the grant '" + grant +
      "' is still selectable in RFC 9700 mode. Disabled: " +
      disabled.join(", "));
  });
  // And the ones that survive are still selectable. A mode that disabled
  // everything would satisfy the assertion above and be useless.
  ["authorization_grant", "oidc_authorization_code_flow",
   "oidc_hybrid_code_id_token", "client_credential",
   "device_authorization_grant"].forEach(function (grant) {
    assert.ok(disabled.indexOf(grant) === -1,
      "The grant '" + grant + "' was disabled in RFC 9700 mode. It should " +
      "not be: RFC 9700 refuses response types that return an access token " +
      "from the authorization endpoint, and this returns none.");
  });
  log.info("Six grants refused, five left standing.");

  // Each disabled option carries its own reason. Six controls sharing one
  // generic sentence would tell a reader nothing about which rule they met.
  for (const grant of Object.keys(REFUSED_GRANTS)) {
    const title = await driver.executeScript(
      "var o = document.querySelector('#authorization_grant_type " +
      "option[value=\"" + grant + "\"]'); return o ? o.title : null;");
    assert.ok(title && title.length > 40,
      "The disabled grant '" + grant + "' carries no reason a reader could " +
      "use. Its title is: " + title);
    assert.ok(/RFC 9700/.test(title),
      "The reason on '" + grant + "' does not cite RFC 9700: " + title);
  }
  log.info("Every refused grant states its own reason.");

  // The refusal must also hold at the ACT, not only at the control. A stored
  // configuration or a hand-edited form can reach the request with a grant the
  // selector would not have offered, and the selector is a control while the
  // request is the thing that leaves the browser.
  await populateMetadata(driver, stsUrl + "/.well-known/openid-configuration");
  //
  // The option has to be RE-ENABLED before it can be selected — assigning a
  // disabled option to a select's value leaves the value empty, which is why
  // the first version of this check passed for the wrong reason. Re-enabling
  // it is also the realistic bypass: a browser's developer tools do exactly
  // this, and so does a cached copy of the page from before the mode existed.
  // The point is that the request is refused anyway, because `disabled` is a
  // property of a control and the rule is a property of the request.
  const forced = await driver.executeScript(
    "var sel = document.getElementById('authorization_grant_type');" +
    "sel.querySelector('option[value=\"implicit_grant\"]').disabled = false;" +
    "sel.value = 'implicit_grant';" +
    "document.getElementById('response_type').value = 'token';" +
    "var v = oauth2_oidc_1.rfc9700GateAuthorizationRequest(false);" +
    "return JSON.stringify({ok: v.ok, selected: sel.value," +
    "ids: v.blocked.map(function (f) { return f.id; })});");
  const verdict = JSON.parse(forced);
  assert.strictEqual(verdict.selected, "implicit_grant",
    "The test could not actually select the Implicit Grant, so what follows " +
    "would pass for the wrong reason.");
  assert.strictEqual(verdict.ok, false,
    "Requirement 1.11: an Implicit Grant forced past the selector was not " +
    "refused at the request.");
  assert.ok(verdict.ids.indexOf("1.11") !== -1,
    "The forced Implicit Grant was refused under " + verdict.ids.join(", ") +
    " rather than 1.11.");
  log.info("A grant forced past the selector is still refused at the " +
           "request, citing 1.11.");

  // Requirement 7.1: with the mode on and no metadata retrieved, the request
  // is refused. Endpoints typed by hand are the misconfiguration section 7
  // exists to remove, and they are also how somebody points this at half of
  // one server and half of another.
  const noMetadata = await driver.executeScript(
    "window.localStorage.removeItem('discovery_info');" +
    "document.getElementById('authorization_grant_type').value = " +
    "'oidc_authorization_code_flow';" +
    "document.getElementById('response_type').value = 'code';" +
    "var v = oauth2_oidc_1.rfc9700GateAuthorizationRequest(false);" +
    "return JSON.stringify({ok: v.ok, ids: v.blocked.map(function (f) {" +
    "return f.id; })});");
  const noMetadataVerdict = JSON.parse(noMetadata);
  assert.strictEqual(noMetadataVerdict.ok, false,
    "Requirement 7.1: a request built from hand-typed endpoints was not " +
    "refused.");
  assert.ok(noMetadataVerdict.ids.indexOf("7.1") !== -1,
    "It was refused under " + noMetadataVerdict.ids.join(", ") +
    " rather than 7.1.");
  log.info("A request with no metadata behind it is refused, citing 7.1.");

  // And the whole thing is REVERSIBLE. A control left disabled after the mode
  // is switched off is indistinguishable from a broken page, and it is the
  // failure a test that only ever turns the mode ON can never see.
  await driver.executeScript(
    "document.getElementById('rfc9700_mode').checked = false;" +
    "oauth2_oidc_1.onRfc9700ModeChange();");
  const afterOff = await disabledGrants(driver);
  assert.deepStrictEqual(afterOff, [],
    "Turning RFC 9700 mode off left grants disabled: " + afterOff.join(", ") +
    ". Everything the mode does has to be reversible, or the switch is a " +
    "one-way door with a checkbox on it.");
  const pkceNo = await driver.findElement(By.id("usePKCE-no"));
  assert.strictEqual(await pkceNo.getAttribute("disabled"), null,
    "Turning RFC 9700 mode off left the 'no PKCE' option disabled.");
  log.info("Turning the mode off restored every control it had taken away.");

  log.debug("Leaving runRefusals().");
}


async function test() {
  log.debug("Entering test().");
  const stsUrl = (process.env.WSTRUST_STS_URL || "").replace(/\/$/, "");
  assert.ok(stsUrl,
    "WSTRUST_STS_URL is not set. This job needs the mock STS, started in " +
    "RFC 9700 mode (STS_OAUTH2_RFC9700=true).");
  const flowKey = process.env.RFC9700_FLOW || "oidc_authorization_code_flow";

  // Everything that needs no browser, first: it is cheap, and a failure here
  // explains every browser failure that would have followed it.
  await checkAlwaysOnPosture();
  await requireCompliantSts(stsUrl);
  await registerRedirectUri(stsUrl);

  const driver = await buildDriver();
  try {
    if (flowKey === "refused") {
      await runRefusals(driver, stsUrl);
    } else {
      await runFlow(driver, flowKey, stsUrl);
    }
    log.info("Test completed successfully. flow=" + flowKey);
  } catch (error) {
    log.error(error.stack || error.message);
    for (const entry of await driver.manage().logs()
                                   .get(logging.Type.BROWSER)) {
      if (entry.level.name === "SEVERE") {
        log.error("browser: " + entry.message.slice(0, 400));
      }
    }
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("rfc9700_flows")
  .description("Every surviving grant, with the debugger AND the mock STS " +
               "both in RFC 9700 mode — plus the refusals, which are what " +
               "the mode is for.")
  .addOption(new Option("-u, --url <url>", "Set base URL."))
  .addOption(new Option("-b, --browser",
    "Display browser (only works within device)."))
  .action(function (options) {
    if (options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });
program.parse(process.argv);

test();
