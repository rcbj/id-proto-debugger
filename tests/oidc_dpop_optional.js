// File: oidc_dpop_optional.js
//
// DPoP (RFC 9449) is OPTIONAL on the OAuth2 / OIDC workflow, and this is what
// says so. Three states, driven through oauth2_oidc_1.html / oauth2_oidc_2.html
// against the mock STS:
//
//   1. OFF, which is the default — no dpop_jkt on the authorization request, no
//      DPoP header on the Token Request, and an ordinary Bearer token back.
//   2. ON — a key pair is generated in the pane, dpop_jkt travels with the
//      authorization request, the Token Request carries a proof, and the access
//      token comes back with cnf.jkt naming that key.
//   3. OFF again — the key is discarded and the exchange is Bearer once more.
//
// And the case this test exists for. Before 2026-08-05 both DPoP touchpoints on
// these pages read the SD-JWT VC workflow's switch (`sdjwtvc_dpop_enabled`),
// neither read was gated on that workflow being active, and the two workflows
// share one localStorage — so turning DPoP on once in VC issuance step 2 put a
// dpop_jkt on every OAuth2/OIDC authorization request and a proof on every
// browser-direct Token Request, with no control on these pages to stop it. DPoP
// was, from this workflow's point of view, mandatory. Phase 4 sets exactly that
// state — the VC switch on, this workflow's switch off — and requires a Bearer
// token. It fails against the old code, which is the only reason it is here.
//
// The thumbprint is recomputed in node from the public JWK in storage (RFC 7638
// section 3.1: the required members, lexicographic, no whitespace) rather than
// read from the pane, so "the token is bound to this key" is checked against
// the arithmetic and not against the page agreeing with itself.
//
// The STS mock is located from WSTRUST_STS_URL, as the other STS-backed tests
// are. It needs no identity provider and no api service.

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const crypto = require("crypto");
const assert = require("assert");
const { Command, Option } = require('commander');
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oidc_dpop_optional',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select,
       waitTime, log, assert });

const CLIENT_ID = process.env.CLIENT_ID || "oidc-dpop-test-client";
const SCOPE = process.env.SCOPE || "openid profile";
const USER = process.env.OIDC_FLOW_USER || "dpopuser";
const FLOW_LABEL = "OIDC Authorization Code Flow(code)";

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function claimsOf(token) {
  log.debug("Entering claimsOf().");
  const parts = String(token).split(".");
  assert.strictEqual(parts.length, 3, "Expected a three-part JWS, got " +
                     parts.length + " part(s).");
  log.debug("Leaving claimsOf().");
  return JSON.parse(b64uDecode(parts[1]).toString("utf8"));
}

// RFC 7638 section 3.1. Only the required members, lexicographic, no whitespace
// — the three ways this goes silently wrong, each of which yields a thumbprint
// that is stable, plausible and wrong.
function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  let canonical;
  if (jwk.kty === "EC") {
    canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === "RSA") {
    canonical = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  } else if (jwk.kty === "OKP") {
    canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error("Cannot thumbprint a " + jwk.kty + " key.");
  }
  log.debug("Leaving thumbprint().");
  return b64u(crypto.createHash("sha256").update(JSON.stringify(canonical),
              "utf8").digest());
}

const wait = (milliseconds) => {
  log.debug("Entering wait().");
  log.debug("Leaving wait().");
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
};

async function storage(driver, key) {
  log.debug("Entering storage().");
  log.debug("Leaving storage().");
  return await driver.executeScript(
      "return window.localStorage.getItem(arguments[0]);", key);
}

// --- the pane ---------------------------------------------------------------

async function openDebugger2(driver) {
  log.debug("Entering openDebugger2().");
  await driver.get(baseUrl + "/oauth2_oidc_2.html");
  await driver.wait(until.elementLocated(By.id("dpop_enabled")), waitTime * 3);
  log.debug("Leaving openDebugger2().");
}

async function setDpop(driver, on) {
  log.debug("Entering setDpop().");
  log.info("Entering setDpop(). on=" + on);
  const box = By.id("dpop_enabled");
  await driver.wait(until.elementLocated(box), waitTime);
  const checked = await driver.findElement(box).isSelected();
  if (checked !== on) {
    await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                               await driver.findElement(box));
    await driver.findElement(box).click();
  }
  assert.strictEqual(await driver.findElement(box).isSelected(), on,
    "The DPoP checkbox did not take the state asked for.");
  if (on) {
    // Ticking generates the key pair, which is asynchronous (Web Crypto).
    await driver.wait(async function () {
      return !!(await storage(driver, "oauth_dpop_public_jwk"));
    }, waitTime * 5, "No DPoP key pair appeared after switching DPoP on.");
  }
  log.info("Leaving setDpop().");
  log.debug("Leaving setDpop().");
}

// --- one run of the flow ----------------------------------------------------

async function runAuthorizationCodeFlow(driver, { expectJkt }) {
  log.debug("Entering runAuthorizationCodeFlow().");
  log.info("Entering runAuthorizationCodeFlow(). expectJkt=" + (expectJkt ||
           "(none)"));
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")),
                    waitTime * 3);
  await new Select(await driver.findElement(By.id("authorization_grant_type")))
    .selectByVisibleText(FLOW_LABEL);
  // Expanded if it is not already, rather than clicked unconditionally. Once
  // the page has been through discovery it remembers (debugger_initialized) and
  // opens this fieldset itself, so a blind click COLLAPSES it and every field
  // below is "element not interactable" — which reads as a broken page rather
  // than as a toggle pressed twice.
  await driver.wait(until.elementLocated(By.id("client_id")), waitTime);
  if (!(await driver.findElement(By.id("client_id")).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(By.id(
                    "client_id"))), waitTime);
  await driver.findElement(By.id("client_id")).clear();
  await driver.findElement(By.id("client_id")).sendKeys(CLIENT_ID);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys(SCOPE);
  await driver.findElement(By.id("redirect_uri")).clear();
  await driver.findElement(By.id("redirect_uri")).sendKeys(baseUrl +
                           "/callback");
  await driver.executeScript(
      "oauth2_oidc_1.recalculateAuthorizationRequestDescription();");

  // What the authorization request is about to carry. RFC 9449 section 10:
  // dpop_jkt is what binds the CODE, and it can only travel here.
  const preview =
      await driver.findElement(By.id("display_authz_request_form_textarea1"))
                              .getAttribute("value");
  const sentJkt = (preview.match(/dpop_jkt=([^&\n]*)/) || [])[1] || "";
  if (expectJkt) {
    assert.strictEqual(sentJkt, expectJkt,
      "The authorization request should carry dpop_jkt=" + expectJkt +
          ", and carries \"" +
      sentJkt + "\". Request:\n" + preview);
  } else {
    assert.strictEqual(sentJkt, "",
      "DPoP is off for this workflow, and the authorization request still " +
          "carries dpop_jkt=" +
      sentJkt + ". Request:\n" + preview);
  }

  await driver.findElement(By.css(
                           "input[type=\"submit\"][value=\"Authorize\"]"))
                           .click();

  // Sign in only if asked to. This test runs the flow four times in one
  // browser, and the OP keeps a session — so the second and later passes come
  // straight back with the response, which is correct behaviour and not
  // something to wait for a login screen through. Whichever arrives first
  // decides.
  await driver.wait(async function () {
    if ((await driver.getCurrentUrl())
        .indexOf("/oauth2_oidc_2.html") >= 0) return "returned";
    return (await driver.findElements(By.id("username"))).length ?
            "login" : false;
  }, waitTime * 4,
      "Neither the OP's login screen nor a return to oauth2_oidc_2.html " +
          "arrived.");

  if ((await driver.findElements(By.id("username"))).length) {
    await driver.findElement(By.id("username")).clear();
    await driver.findElement(By.id("username")).sendKeys(USER);
    const passwordFields = await driver.findElements(By.id("password"));
    if (passwordFields.length) {
      await passwordFields[0].sendKeys(USER);
    }
    await driver.findElement(By.id("kc-login")).click();
  }
  await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 5);

  // Browser-direct, because the api does not forward DPoP proofs — and because
  // that keeps this test off the api service entirely.
  await driver.wait(until.elementLocated(By.id("token_initiateFromFrontEnd")),
                    waitTime * 3);
  const frontEnd =
      await driver.findElement(By.id("token_initiateFromFrontEnd"));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             frontEnd);
  await frontEnd.click();

  await driver.findElement(By.id("token_client_id")).clear();
  await driver.findElement(By.id("token_client_id")).sendKeys(CLIENT_ID);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope")).sendKeys(SCOPE);
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(baseUrl +
                           "/callback");
  await driver.findElement(By.className("token_btn")).click();

  let accessToken = "";
  await driver.wait(async function () {
    const fields = await driver.findElements(By.id("token_access_token"));
    if (!fields.length) return false;
    accessToken = await fields[0].getAttribute("value");
    return !!(accessToken && accessToken.split(".").length === 3);
  }, waitTime * 6, "The Token Request produced no access token.");

  log.info("Leaving runAuthorizationCodeFlow().");
  log.debug("Leaving runAuthorizationCodeFlow().");
  return { accessToken: accessToken, claims: claimsOf(accessToken) };
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless. The tests image pins Chrome 121, where plain
    // --headless selects the OLD headless implementation — and in that one
    // --unsafely-treat-insecure-origin-as-secure has no effect, so on the
    // containerized suite's http://client:3000 origin window.crypto.subtle
    // stays undefined and the DPoP key pair is never generated. The symptom is
    // a timeout waiting for a key, naming nothing about crypto or headless
    // mode. Invisible locally: from Chrome 132 the old mode is gone and
    // --headless IS the new one, so this passes on a modern browser and fails
    // only in CI.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm.
  options.addArguments("--disable-dev-shm-usage");
  // The private-network flags AND the secure-context relaxing, from one place.
  // The second is what this test cannot run without in the containerized suite:
  // the debugger is served from http://client:3000 — plain HTTP on a DNS name,
  // which is NOT a secure context — so window.crypto.subtle is undefined there
  // and the DPoP key pair can never be generated. The failure would be a
  // timeout waiting for a key, naming nothing about crypto or about the origin.
  // See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder()
    .forBrowser("chrome").setChromeOptions(options)
        .setLoggingPrefs(loggingPrefs).build();

  try {
    const stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
    const stsBase = stsUrl.replace(/\/sts\/?$/, "");
    const discovery = process.env.DISCOVERY_ENDPOINT ||
                      (stsBase + "/.well-known/openid-configuration");

    await driver.manage().deleteAllCookies();
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    await driver.executeScript("window.localStorage.clear();");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    await populateMetadata(driver, discovery);

    // --- 1. the default -----------------------------------------------------
    await openDebugger2(driver);
    assert.strictEqual(await driver.findElement(By.id("dpop_enabled"))
                       .isSelected(), false,
      "DPoP must be OFF by default on the OAuth2/OIDC workflow. A debugger " +
          "that sender-constrains " +
      "tokens without being asked cannot demonstrate the Bearer exchange the " +
          "specifications " +
      "describe first.");
    assert.ok(!(await storage(driver, "oauth_dpop_private_jwk")),
      "A DPoP private key exists before DPoP was ever switched on.");
    let run = await runAuthorizationCodeFlow(driver, { expectJkt: "" });
    assert.ok(!run.claims.cnf,
      "DPoP is off, and the access token came back sender-constrained " +
          "anyway (cnf=" +
      JSON.stringify(run.claims.cnf) + ").");
    log.info("[off] OK — no dpop_jkt, no proof, and an ordinary Bearer token.");

    // --- 2. switched on -----------------------------------------------------
    await openDebugger2(driver);
    await setDpop(driver, true);
    const publicJwk = JSON.parse(await storage(driver,
        "oauth_dpop_public_jwk"));
    const expectedJkt = thumbprint(publicJwk);
    const storedJkt = await storage(driver, "oauth_dpop_jkt");
    assert.strictEqual(storedJkt, expectedJkt,
      "The page recorded jkt " + storedJkt +
          " for a key whose RFC 7638 thumbprint is " +
      expectedJkt + ".");
    assert.ok(!(await storage(driver, "sdjwtvc_dpop_private_jwk")),
      "Switching DPoP on here generated a key in the SD-JWT VC workflow's " +
          "storage. The two " +
      "workflows must not share key material.");

    run = await runAuthorizationCodeFlow(driver, { expectJkt: expectedJkt });
    assert.ok(run.claims.cnf && run.claims.cnf.jkt,
      "DPoP is on and a proof was sent, but the access token came back with " +
          "no cnf.jkt.");
    assert.strictEqual(run.claims.cnf.jkt, expectedJkt,
      "The token is bound to " + run.claims.cnf.jkt +
          ", not to this page's key (" +
      expectedJkt + ").");
    // Read from the RESULTS pane, not the request form: the success handler
    // collapses the form, so a verdict rendered there would be true and
    // invisible.
    const verdictEl = await driver.findElements(By.id("dpop_result_status"));
    assert.ok(verdictEl.length,
      "The Token Endpoint Results pane says nothing about the binding that " +
          "was just obtained.");
    const verdictText = await verdictEl[0].getText();
    assert.ok(/sender-constrained/i.test(verdictText),
      "The results pane does not report the binding. It says: \"" +
          verdictText + "\".");
    assert.ok(await verdictEl[0].isDisplayed(),
      "The binding verdict is in the page but not visible.");
    log.info("[on] OK — dpop_jkt on the authorization request, a proof on " +
             "the Token Request, and " +
             "cnf.jkt = the RFC 7638 thumbprint of the pane's key.");

    // --- 3. switched off again ----------------------------------------------
    await openDebugger2(driver);
    await setDpop(driver, false);
    assert.ok(!(await storage(driver, "oauth_dpop_private_jwk")),
      "Switching DPoP off left the private key in storage. A key nothing " +
          "will use again is one a " +
      "later session can bind a token to by accident.");
    run = await runAuthorizationCodeFlow(driver, { expectJkt: "" });
    assert.ok(!run.claims.cnf,
      "DPoP was switched off and the token still came back bound (cnf=" +
      JSON.stringify(run.claims.cnf) + ").");
    log.info("[off again] OK — the key was discarded and the exchange is " +
             "Bearer once more.");

    // --- 4. the VC workflow's switch must not decide for this one -----------
    // The regression this test exists for. Both DPoP touchpoints on these pages
    // used to read sdjwtvc_dpop_enabled with no check that the VC workflow was
    // running, and the two workflows share one localStorage.
    await openDebugger2(driver);
    await driver.executeScript(
      "window.localStorage.setItem('sdjwtvc_dpop_enabled','1');" +
      "window.localStorage.setItem('sdjwtvc_dpop_alg','ES256');" +
      "window.localStorage.setItem('sdjwtvc_dpop_jkt'," +
          "'a-vc-workflow-key-thumbprint');");
    // A real key pair for that workflow, so the leak would have everything it
    // needs to build a proof — seeding only the flag would prove nothing, since
    // dpopContext() returns null without a key and the request would be Bearer
    // for the wrong reason.
    await driver.executeScript(
      "return window.crypto.subtle.generateKey({name:'ECDSA'," +
          "namedCurve:'P-256'},true,['sign','verify'])" +
      "  .then(function(p){ return Promise.all([" +
      "    window.crypto.subtle.exportKey('jwk',p.publicKey)," +
      "    window.crypto.subtle.exportKey('jwk',p.privateKey)]); })" +
      "  .then(function(jwks){" +
      "    window.localStorage.setItem('sdjwtvc_dpop_public_jwk', " +
          "JSON.stringify(jwks[0]));" +
      "    window.localStorage.setItem('sdjwtvc_dpop_private_jwk', " +
          "JSON.stringify(jwks[1]));" +
      "    return true; });");
    assert.ok(await storage(driver, "sdjwtvc_dpop_private_jwk"),
      "The VC workflow's DPoP key was not seeded, so this phase would pass " +
          "vacuously.");
    await openDebugger2(driver);
    assert.strictEqual(await driver.findElement(By.id("dpop_enabled"))
                       .isSelected(), false,
      "The VC workflow's DPoP switch turned this workflow's checkbox on.");
    run = await runAuthorizationCodeFlow(driver, { expectJkt: "" });
    assert.ok(!run.claims.cnf,
      "The SD-JWT VC workflow's DPoP switch bound an OAuth2/OIDC token (cnf=" +
      JSON.stringify(run.claims.cnf) +
                     "). DPoP is meant to be optional here, and this is the " +
      "state in which it was mandatory.");
    log.info("[vc switch on, this one off] OK — the VC workflow's DPoP no " +
             "longer decides for the " +
             "OAuth2/OIDC workflow.");

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oidc_dpop_optional')
  .description("DPoP is optional on the OAuth2/OIDC workflow: off by " +
      "default, on when asked.")
  .addOption(new Option("-u, --url <url>",
      "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser",
      "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
