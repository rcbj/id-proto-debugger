const { Builder, By, until, logging } = require("selenium-webdriver");
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
var baseUrl = "http://localhost:3000"

// The public static-content deployments (test.idptools.com / idptools.com) have
// no api backend, and Keycloak's introspection endpoint is not CORS-enabled, so
// a browser introspection call is blocked. Against those targets the test
// EXPECTS that CORS/network error instead of an active introspection result.
var STATIC_CONTENT_SITE_HOSTS = ["test.idptools.com", "idptools.com"];
function isStaticContentSite(url) {
  try {
    return STATIC_CONTENT_SITE_HOSTS.includes(new URL(url).hostname);
  } catch (e) {
    return false;
  }
}
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode } = require("../common/tests.js")({ By, until, Select, waitTime, log, jwt, assert });

// Obtains an access token (the subject token for the exchange) via the OIDC
// Authorization Code flow using the requesting (confidential) client.

// Extracts the JSON object embedded in a result textarea (after the
// "Response Body:" preamble) and parses it.
function parseEmbeddedJson(text) {
  var start = text.indexOf("{");
  var end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    return null;
  }
  try {
    return JSON.parse(text.substring(start, end + 1));
  } catch (e) {
    return null;
  }
}

// Drives the Token Exchange (RFC 8693) pane: sets the requesting client
// credentials and target audience, submits the exchange, and returns the parsed
// token endpoint response (which contains the issued access_token).
async function exchangeTokenViaUI(driver, audience_client_id, client_id, client_secret) {
  log.info("Performing token exchange via the UI. audience=" + audience_client_id);

  const subjectToken = By.id("tokenexchange_subject_token");
  await driver.wait(until.elementLocated(subjectToken), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", await driver.findElement(subjectToken));
  await driver.wait(until.elementIsVisible(driver.findElement(subjectToken)), waitTime);

  // The subject token defaults to the most recent access token.
  const subjectValue = await driver.findElement(subjectToken).getAttribute("value");
  assert(subjectValue && subjectValue.length > 0,
    "Token Exchange subject token was not pre-populated with the latest access token.");

  // Authenticate as the requesting client and target the audience client.
  const clientIdField = await driver.findElement(By.id("tokenexchange_client_id"));
  await clientIdField.clear();
  await clientIdField.sendKeys(client_id);
  const clientSecretField = await driver.findElement(By.id("tokenexchange_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }
  const audienceField = await driver.findElement(By.id("tokenexchange_audience"));
  await audienceField.clear();
  await audienceField.sendKeys(audience_client_id);

  // Submit (defaults: Impersonation, requested_token_type=access_token, backend).
  const exchangeBtn = await driver.findElement(By.id("tokenexchange_btn"));
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", exchangeBtn);
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
  assert(parsed !== null, "Could not parse the token exchange response JSON. Result: " + resultText);
  assert(parsed.access_token, "Token exchange response did not contain an access_token. Response: " + JSON.stringify(parsed));
  log.info("issued_token_type=" + parsed.issued_token_type + ", token_type=" + parsed.token_type);
  return parsed;
}

// Introspects an arbitrary token value via the Introspection page, using the
// confidential client that is permitted to call the Introspection Endpoint.
async function introspectTokenValue(driver, token, client_id, client_secret) {
  log.info("Introspecting the exchanged token via the Introspection page.");
  await driver.get(baseUrl + "/introspection.html?type=access");

  const tokenField = By.id("introspection_token");
  await driver.wait(until.elementLocated(tokenField), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(tokenField)), waitTime);

  const endpointValue = await driver.findElement(By.id("introspection_endpoint")).getAttribute("value");
  assert(endpointValue && endpointValue.length > 0,
    "Introspection endpoint was not populated from the discovery document.");

  // Replace whatever token was auto-loaded with the exchanged token.
  await driver.findElement(tokenField).clear();
  await driver.findElement(tokenField).sendKeys(token);
  await new Select(await driver.findElement(By.id("introspection_token_type_hint"))).selectByValue("access_token");

  // Use the backend to avoid browser CORS restrictions on the IdP.
  await driver.findElement(By.id("introspection_initiateFromBackEnd")).click();

  // Authenticate the introspection call as the confidential client.
  await new Select(await driver.findElement(By.id("introspection_authentication_type"))).selectByValue("basic_auth");
  const clientIdField = await driver.findElement(By.id("introspection_client_id"));
  await clientIdField.clear();
  await clientIdField.sendKeys(client_id);
  const clientSecretField = await driver.findElement(By.id("introspection_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }

  await driver.findElement(By.css('input[value="Introspect Token"]')).click();

  const output = By.id("introspection_output");
  await driver.wait(async () => {
    try {
      const v = (await driver.findElement(output).getAttribute("value") || "").trim();
      return v.length > 0;
    } catch (e) {
      return false;
    }
  }, waitTime, "Introspection produced no output.");

  const outputText = (await driver.findElement(output).getAttribute("value") || "").trim();
  log.info("Introspection output: " + outputText.replace(/\n/g, " "));
  return outputText;
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak, which
  // browsers otherwise block (mixed content / Private Network Access).
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

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    assert(audience_client_id, "AUDIENCE_CLIENT_ID environment variable is not set.");
    assert(introspection_client_id, "INTROSPECTION_CLIENT_ID environment variable is not set.");
    assert(introspection_client_secret, "INTROSPECTION_CLIENT_SECRET environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      log.info("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    log.info("Kicking off test.");
    await driver.get(baseUrl + "/debugger.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken() to obtain the subject token.");
    const subject_token = await getAccessTokenAuthCode(driver, client_id, client_secret, scope, pkce_enabled, { baseUrl });
    assert(subject_token, "No subject access token was obtained.");

    // Exchange the subject token (RFC 8693) for a token aimed at the audience.
    const exchange = await exchangeTokenViaUI(driver, audience_client_id, client_id, client_secret);
    const exchanged_access_token = exchange.access_token;
    assert.notStrictEqual(jwt.decode(exchanged_access_token, { complete: true }), null,
      "The exchanged access token could not be decoded as a JWT.");

    // Confirm the exchanged token is valid by introspecting it.
    log.info("Validating the exchanged access token via introspection.");
    const introspection = await introspectTokenValue(driver, exchanged_access_token, introspection_client_id, introspection_client_secret);
    let parsed = null;
    try {
      parsed = JSON.parse(introspection);
    } catch (e) {
      parsed = null;
    }
    assert(parsed !== null, "Introspection output was not valid JSON: " + introspection);

    if (isStaticContentSite(baseUrl)) {
      // No backend + Keycloak introspection endpoint is not CORS-enabled, so the
      // browser introspection call is blocked. Expect that CORS/network error
      // (readyState 0 / status 0 / status "error"). The token exchange itself was
      // already confirmed above (HTTP 200 with an issued access token).
      assert(parsed.status === "error" && parsed.request && parsed.request.status === 0,
        "Introspection on a static site was expected to be blocked by CORS (status 0 error), " +
        "but got: " + introspection);
      log.info("Token exchange succeeded; introspection was blocked by CORS as expected on the static site.");
    } else {
      assert.strictEqual(parsed.active, true,
        "Introspection reported the exchanged token as not valid (expected active=true). Output: " + introspection);
      log.info("Token exchange succeeded and the issued access token was confirmed valid via introspection.");
    }
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
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
