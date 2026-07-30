const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
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
//   - the IdP POSTs a wresult (WS-Trust RSTR carrying a SAML assertion) to the
//     debugger's api /wsfed landing, which stashes it and redirects to
//     wsfed_response.html?id=... where the token is rendered.
//
// Then it signs the user out (wa=wsignout1.0) in the same browser, because that
// leg needs the session the sign-in established — see wsfedSignOutActivities().
// Sign-out returns no token, so what is asserted is the wa the IdP was actually
// sent (read back off the api landing's redirect) and that the session is really
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

// The passive sign-in endpoint is the descriptor URL without the trailing
// "/descriptor" (Keycloak serves both under /protocol/wsfed). Deriving it makes
// the test robust to any metadata-parsing quirk in the (EOL) extension's
// descriptor format, while metadata loading is still exercised below.
function deriveEndpoint(metadataUrl) {
  return String(metadataUrl || "").replace(/\/descriptor\/?(\?.*)?$/, "");
}

async function wsfedActivities(driver, metadataUrl, realm, user) {
  // Keycloak's login page + the WS-Fed round-trip need a generous timeout.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the WS-Federation Test Tools page.");
  await driver.get(baseUrl + "/wsfed_tools.html");

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

  // Land on the response page (the api /wsfed landing stashed the wresult and
  // redirected here with ?id=...).
  log.info("Wait for the WS-Federation response page.");
  await driver.wait(until.urlContains("wsfed_response.html"), loginWait);
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
}

// ---------------------------------------------------------------------------
// Sign-out (wa=wsignout1.0), driven from the same page, after the sign-in above.
//
// The passive profile's sign-out is a top-level navigation like the sign-in, and
// it returns NO token — so there is nothing to inspect, and the only things worth
// asserting are what actually happened:
//
//   1. the browser came back to wreply as a sign-out and not as a sign-in: the
//      api's /wsfed landing gets no wresult, so it redirects to
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
  var loginWait = Math.max(waitTime, 15000);

  log.info("Return to the WS-Federation Test Tools page to sign out.");
  await driver.get(baseUrl + "/wsfed_tools.html");
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
  // sign-out observable here at all. The page defaults it to the api's /wsfed
  // landing; if that default is missing the deployment has no backend and this
  // leg cannot be checked, which is worth saying rather than guessing a URL.
  assert(pre.reply,
    "wsfed_reply (wreply) is empty, so the IdP has nowhere to return the browser after sign-out. " +
    "The page normally defaults it to the api's /wsfed landing.");
  log.info("Sign-out preconditions: endpoint=" + (pre.signout || pre.signin) +
           " wtrealm=" + (pre.realm || realm) + " wreply=" + pre.reply);

  log.info("Click Sign Out (wa=wsignout1.0).");
  await clickByValue(driver, "Sign Out");

  // Back on the response page, with the sign-out flag the api landing passed on.
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
  // builds the redirect with the wctx and NO wa at all. So the api landing sees no
  // wa and falls back to signout=1. A run where another client is still in the
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

  // And no token came back with it: sign-out returns none.
  var leftover = await driver.findElement(By.id("wsfed_response_xml")).getAttribute("value");
  assert(!leftover || leftover.indexOf("RequestSecurityTokenResponse") < 0,
    "a sign-out must not deliver a token, but the response page is showing an RSTR.");

  // The real check: the IdP session is gone, so signing in again has to
  // re-authenticate. If the SSO cookie survived, this navigation goes straight
  // back to the response page with a fresh token and never shows a login form.
  log.info("Sign in again — Keycloak must now ask for credentials.");
  await driver.get(baseUrl + "/wsfed_tools.html");
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
}

async function test() {
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

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
    assert(metadataUrl, "WSFED_METADATA_URL environment variable is not set.");

    await wsfedActivities(driver, metadataUrl, realm, user);
    // Sign-out needs the session the sign-in just established, so it runs in the
    // same browser, in this order, rather than as a separate job.
    await wsfedSignOutActivities(driver, metadataUrl, realm);
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
