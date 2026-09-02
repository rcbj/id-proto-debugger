const { Builder, By, until, logging } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_token_exchange',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000"

// The public static-content deployments (test.idptools.com / idptools.com) have
// no api backend, and Keycloak's introspection endpoint is not CORS-enabled, so
// a browser introspection call is blocked. Against those targets the test
// EXPECTS that CORS/network error instead of an active introspection result.
var STATIC_CONTENT_SITE_HOSTS = ["test.idptools.com", "idptools.com"];
function isStaticContentSite(url) {
  log.debug("Entering isStaticContentSite().");
  try {
    log.debug("Leaving isStaticContentSite().");
    return STATIC_CONTENT_SITE_HOSTS.includes(new URL(url).hostname);
  } catch (e) {
    log.debug("Leaving isStaticContentSite().");
    return false;
  }
}
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });

// Obtains an access token (the subject token for the exchange) via the OIDC
// Authorization Code flow using the requesting (confidential) client.

// Extracts the JSON object embedded in a result textarea (after the
// "Response Body:" preamble) and parses it.
function parseEmbeddedJson(text) {
  log.debug("Entering parseEmbeddedJson().");
  var start = text.indexOf("{");
  var end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    log.debug("Leaving parseEmbeddedJson().");
    return null;
  }
  try {
    log.debug("Leaving parseEmbeddedJson().");
    return JSON.parse(text.substring(start, end + 1));
  } catch (e) {
    log.debug("Leaving parseEmbeddedJson().");
    return null;
  }
}

// Drives the Token Exchange (RFC 8693) pane: sets the requesting client
// credentials and target audience, submits the exchange, and returns the parsed
// token endpoint response (which contains the issued access_token).
async function exchangeTokenViaUI(driver, audience_client_id, client_id,
                                  client_secret) {
  log.debug("Entering exchangeTokenViaUI().");
  log.info("Performing token exchange via the UI. audience=" +
           audience_client_id);

  const subjectToken = By.id("tokenexchange_subject_token");
  await driver.wait(until.elementLocated(subjectToken), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });",
                             await driver.findElement(subjectToken));
  await driver.wait(until.elementIsVisible(driver.findElement(subjectToken)),
                    waitTime);

  // The subject token defaults to the most recent access token.
  const subjectValue =
      await driver.findElement(subjectToken).getAttribute("value");
  assert(subjectValue && subjectValue.length > 0,
    "Token Exchange subject token was not pre-populated with the latest " +
        "access token.");

  // Authenticate as the requesting client and target the audience client.
  const clientIdField =
      await driver.findElement(By.id("tokenexchange_client_id"));
  await clientIdField.clear();
  await clientIdField.sendKeys(client_id);
  const clientSecretField =
      await driver.findElement(By.id("tokenexchange_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }
  const audienceField =
      await driver.findElement(By.id("tokenexchange_audience"));
  await audienceField.clear();
  await audienceField.sendKeys(audience_client_id);

  // Submit (defaults: Impersonation, requested_token_type=access_token,
  // backend).
  const exchangeBtn = await driver.findElement(By.id("tokenexchange_btn"));
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", exchangeBtn);
  await exchangeBtn.click();

  const resultArea = By.id("tokenexchange_result_textarea");
  await driver.wait(until.elementLocated(resultArea), waitTime);
  await driver.wait(async () => {
    try {
      const v = await driver.findElement(resultArea).getAttribute("value");
      return !!v && v.indexOf("HTTP Status:") !== -1;
    } catch (e) {
      return false;
    }
  }, waitTime, "Token exchange produced no result.");

  const resultText = await driver.findElement(resultArea).getAttribute("value");
  log.info("Token exchange result: " + resultText.replace(/\n/g, " | "));
  assert(resultText.indexOf("HTTP Status: 200") !== -1,
    "Token exchange did not return HTTP 200. Result: " + resultText);

  const parsed = parseEmbeddedJson(resultText);
  assert(parsed !== null,
         "Could not parse the token exchange response JSON. Result: " +
         resultText);
  assert(parsed.access_token,
         "Token exchange response did not contain an access_token. Response: " +
         JSON.stringify(parsed));
  log.info("issued_token_type=" + parsed.issued_token_type + ", token_type=" +
           parsed.token_type);
  log.debug("Leaving exchangeTokenViaUI().");
  return parsed;
}

// The three tabs on the Token Exchange Results pane: what came back, the
// exchange that carried it, and the tokens it issued.
//
// Worth asserting rather than assuming for the reason `token_http_exchange.js`
// gives at length about the pane above this one: the interesting half of this
// exchange CANNOT BE OBSERVED BY THE PAGE. This pane's default is to have the
// **api** call the token endpoint, so the request that matters is made by
// another process, and the browser can only show it because the api hands back
// what it saw under `http_exchange` (`buildHttpTrace()` in `api/server.js`,
// switched on per call by `http_trace: true` — which POST /tokenexchange did
// not support at all until this pane grew a tab to show it). Every link in
// that chain fails SILENTLY: the pane goes on rendering and shows the
// browser's own call to the api instead, which is a perfectly plausible HTTP
// exchange with the wrong URL in it. So the URL is asserted to be the token
// ENDPOINT, read off the page's own field rather than written out here, and
// the note is asserted to name the end that actually made the call — which is
// read off the page too, since a static deployment has no api at all
// (`backendAvailable: false` disables the Back radio) and the browser makes
// the call itself.
//
// The Tokens tab is asserted against the response the Result tab was parsed
// out of, so a panel that drew the PREVIOUS exchange's token — the failure a
// pane rebuilt on every call invites — fails here rather than being read as a
// successful exchange.
async function verifyTokenExchangeTabs(driver, exchange) {
  log.debug("Entering verifyTokenExchangeTabs().");
  log.info("Checking the Token Exchange Results pane's three tabs.");
  const strips = await driver.findElements(
      By.css("#tokenexchange_endpoint_result .dbg-tabs"));
  assert.strictEqual(strips.length, 1,
    "The Token Exchange Results pane should carry exactly one tab strip. " +
    "It is rebuilt on every call and attachHttpTab() is idempotent for that " +
    "reason; " + strips.length + " strips means two sets of buttons driving " +
    "one set of panels.");

  const labels = [];
  for (const which of ["result", "http", "tokens"]) {
    const tab = await driver.findElement(
        By.id("tokenexchange_result_tab_" + which));
    labels.push(await tab.getText());
  }
  log.info("Tabs: " + labels.join(" | "));
  assert.strictEqual(labels[0], "Result",
    "The first tab should be Result, and it should stay first: it is what " +
    "was in this pane before there were any tabs at all.");
  assert.ok(labels[1].indexOf("HTTP") === 0,
    "The second tab should be the HTTP one. It reads \"" + labels[1] + "\".");
  assert.ok(labels[1].indexOf("200") >= 0,
    "The HTTP tab's own LABEL carries the status, so that a collapsed pane " +
    "still says what came back. It reads \"" + labels[1] + "\".");
  assert.strictEqual(labels[2], "Tokens",
    "The third tab should be Tokens. It reads \"" + labels[2] + "\".");

  // Which end made the call, off the page rather than assumed: a static
  // deployment has no api and the Back radio is disabled there.
  const proxied = await driver.findElement(
      By.id("tokenexchange_initiateFromBackEnd")).isSelected();
  const tokenEndpoint = await driver.findElement(
      By.id("tokenexchange_token_endpoint")).getAttribute("value");
  assert.ok(tokenEndpoint,
    "The pane has no token endpoint in it, so nothing below can mean " +
    "anything.");

  await driver.findElement(By.id("tokenexchange_result_tab_http")).click();
  const httpPanel = await driver.findElement(
      By.id("tokenexchange_result_tabpanel_http"));
  await driver.wait(until.elementIsVisible(httpPanel), waitTime);
  const httpText = await httpPanel.getText();
  assert.ok(httpText.indexOf(tokenEndpoint) >= 0,
    "The HTTP tab should show the exchange with the TOKEN ENDPOINT (" +
    tokenEndpoint + "). Showing the browser's own call to the api instead " +
    "is what a missing http_exchange looks like, and it looks perfectly " +
    "plausible. The panel reads: " + httpText.slice(0, 600));
  assert.ok(httpText.indexOf("HTTP 200") >= 0,
    "The HTTP tab should carry the response as well as the request. It " +
    "reads: " + httpText.slice(0, 600));
  if (proxied) {
    assert.ok(httpText.indexOf("Sent by the api") >= 0,
      "This exchange was proxied, so the note must say so — a fallback to " +
      "the browser's own call that did not name itself would be a debugger " +
      "showing the wrong URL with a straight face. It reads: " +
      httpText.slice(0, 600));
  } else {
    assert.ok(httpText.indexOf("Sent by this browser") >= 0,
      "This exchange was made from the browser, so the note must say so. " +
      "It reads: " + httpText.slice(0, 600));
  }
  log.info("The HTTP tab names the token endpoint and the end that called " +
           "it.");

  await driver.findElement(By.id("tokenexchange_result_tab_tokens")).click();
  const tokensPanel = await driver.findElement(
      By.id("tokenexchange_result_tabpanel_tokens"));
  await driver.wait(until.elementIsVisible(tokensPanel), waitTime);
  const issued = await driver.findElement(By.id("tokenexchange_access_token"))
      .getAttribute("value");
  assert.strictEqual(issued, exchange.access_token,
    "The Tokens tab should show the token THIS exchange issued. The pane is " +
    "rebuilt on every call, so a stale one here reads as a successful " +
    "exchange and is not one.");
  const issuedType = await tokensPanel.findElement(
      By.css('[data-token-field="issued_token_type"]')).getAttribute("value");
  assert.strictEqual(issuedType, exchange.issued_token_type,
    "RFC 8693 section 2.2.1 puts the issued token in `access_token` whatever " +
    "type it is, so `issued_token_type` is the only thing that says which. " +
    "The pane shows \"" + issuedType + "\" and the response said \"" +
    exchange.issued_token_type + "\".");

  // The storage the Issued Token / Introspect Token / Revoke Token controls
  // beside it resolve through. Those pages take a TYPE and read a key; a row
  // whose links act on a token other than the one above it is worse than one
  // with no links at all.
  const stored = await driver.executeScript(
      "return localStorage.getItem('tokenexchange_access_token');");
  assert.strictEqual(stored, exchange.access_token,
    "The issued token should be in localStorage under " +
    "tokenexchange_access_token, which is what token_detail.html, " +
    "introspection.html and the Revoke button resolve " +
    "?type=tokenexchange_access to.");

  await driver.findElement(By.id("tokenexchange_result_tab_result")).click();
  log.info("The Tokens tab shows this exchange's token, and the pages beside " +
           "it can find it.");
  log.debug("Leaving verifyTokenExchangeTabs().");
}

// Introspects an arbitrary token value via the Introspection page, using the
// confidential client that is permitted to call the Introspection Endpoint.
async function introspectTokenValue(driver, token, client_id, client_secret) {
  log.debug("Entering introspectTokenValue().");
  log.info("Introspecting the exchanged token via the Introspection page.");
  await driver.get(baseUrl + "/introspection.html?type=access");

  const tokenField = By.id("introspection_token");
  await driver.wait(until.elementLocated(tokenField), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(tokenField)),
                    waitTime);

  const endpointValue =
      await driver.findElement(By.id("introspection_endpoint"))
      .getAttribute("value");
  assert(endpointValue && endpointValue.length > 0,
    "Introspection endpoint was not populated from the discovery document.");

  // Replace whatever token was auto-loaded with the exchanged token.
  await driver.findElement(tokenField).clear();
  await driver.findElement(tokenField).sendKeys(token);
  await new Select(await driver.findElement(By.id(
                   "introspection_token_type_hint"))).selectByValue(
                   "access_token");

  // Use the backend to avoid browser CORS restrictions on the IdP.
  await driver.findElement(By.id("introspection_initiateFromBackEnd")).click();

  // Authenticate the introspection call as the confidential client.
  await new Select(await driver.findElement(By.id(
                   "introspection_authentication_type"))).selectByValue(
                   "basic_auth");
  const clientIdField =
      await driver.findElement(By.id("introspection_client_id"));
  await clientIdField.clear();
  await clientIdField.sendKeys(client_id);
  const clientSecretField =
      await driver.findElement(By.id("introspection_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }

  await driver.findElement(By.css('input[value="Introspect Token"]')).click();

  const output = By.id("introspection_output");
  await driver.wait(async () => {
    try {
      const v = (await driver.findElement(output).getAttribute("value") ||
          "").trim();
      return v.length > 0;
    } catch (e) {
      return false;
    }
  }, waitTime, "Introspection produced no output.");

  const outputText = (await driver.findElement(output).getAttribute("value") ||
      "").trim();
  log.info("Introspection output: " + outputText.replace(/\n/g, " "));
  log.debug("Leaving introspectTokenValue().");
  return outputText;
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless. This page fetches the discovery document
    // itself, from a Keycloak that is http://keycloak:8080 on the
    // containerized stack while the page is now https — and the OLD headless
    // implementation in the Chrome 121 this image pins IGNORES
    // --allow-running-insecure-content, so that XHR is blocked with
    // readyState 4 / status 0 and no console entry naming mixed content.
    // What the test then reports is a missing Populate button. See section 1
    // of browser_flags.js.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak,
  // which browsers otherwise block (mixed content / Private Network Access).
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  // THE STACK'S CERTIFICATE, AS AN EXACT KEY PIN. The client and the api serve
  // https (common/tls_listener.js), on a self-signed pair generated per run, so
  // without this Chrome stops on a certificate interstitial and every
  // assertion below reports a missing element on a page titled "Privacy
  // error". See browser_flags.js.
  browserFlags.addStsTrustFlags(options);
  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET || "";
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;
    // The target client whose audience the exchanged token will be aimed at.
    const audience_client_id = process.env.AUDIENCE_CLIENT_ID;
    // The confidential client permitted to call the Introspection Endpoint.
    const introspection_client_id = process.env.INTROSPECTION_CLIENT_ID;
    const introspection_client_secret = process.env.INTROSPECTION_CLIENT_SECRET;

    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    assert(audience_client_id,
           "AUDIENCE_CLIENT_ID environment variable is not set.");
    assert(introspection_client_id,
           "INTROSPECTION_CLIENT_ID environment variable is not set.");
    assert(introspection_client_secret,
           "INTROSPECTION_CLIENT_SECRET environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      // Throw rather than exit. This is inside the try whose finally quits
      // the browser, and process.exit() is synchronous termination: it would
      // skip that finally and orphan a full Chrome. The catch below records
      // the failure and the exit happens once the driver is gone.
      throw new Error("PKCE_ENABLED must be true or false. Got: " +
                      pkce_enabled);
    }

    log.info("Kicking off test.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken() to obtain the subject token.");
    const subject_token = await getAccessTokenAuthCode(driver, client_id,
        client_secret, scope, pkce_enabled, { baseUrl });
    assert(subject_token, "No subject access token was obtained.");

    // Exchange the subject token (RFC 8693) for a token aimed at the audience.
    const exchange = await exchangeTokenViaUI(driver, audience_client_id,
        client_id, client_secret);
    // Before navigating anywhere: the pane is rebuilt on every call and the
    // introspection step below leaves this page entirely.
    await verifyTokenExchangeTabs(driver, exchange);
    const exchanged_access_token = exchange.access_token;
    assert.notStrictEqual(jwt.decode(exchanged_access_token,
                          { complete: true }), null,
      "The exchanged access token could not be decoded as a JWT.");

    // Confirm the exchanged token is valid by introspecting it.
    log.info("Validating the exchanged access token via introspection.");
    const introspection = await introspectTokenValue(driver,
        exchanged_access_token, introspection_client_id,
        introspection_client_secret);
    let parsed = null;
    try {
      parsed = JSON.parse(introspection);
    } catch (e) {
      parsed = null;
    }
    assert(parsed !== null, "Introspection output was not valid JSON: " +
           introspection);

    if (isStaticContentSite(baseUrl)) {
      // No backend + Keycloak introspection endpoint is not CORS-enabled, so
      // the browser introspection call is blocked. Expect that CORS/network
      // error (readyState 0 / status 0 / status "error"). The token exchange
      // itself was already confirmed above (HTTP 200 with an issued access
      // token).
      assert(parsed.status === "error" && parsed.request &&
             parsed.request.status === 0,
        "Introspection on a static site was expected to be blocked by CORS " +
            "(status 0 error), " +
        "but got: " + introspection);
      log.info("Token exchange succeeded; introspection was blocked by CORS " +
               "as expected on the static site.");
    } else {
      assert.strictEqual(parsed.active, true,
        "Introspection reported the exchanged token as not valid (expected " +
            "active=true). Output: " + introspection);
      log.info("Token exchange succeeded and the issued access token was " +
               "confirmed valid via introspection.");
    }
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oauth2_token_exchange')
  .description("Run test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
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
