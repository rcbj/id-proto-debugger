const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_token_revocation',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode } = require("../common/tests.js")({ By, until, Select, waitTime, log, jwt, assert });

// The public static-content deployments (test.idptools.com / idptools.com) have
// no api backend, and Keycloak's introspection endpoint is not CORS-enabled, so
// token introspection cannot run from the browser there. Used to skip the
// introspection-based validation for those targets while keeping it for the
// containerized/local backend build.
var STATIC_CONTENT_SITE_HOSTS = ["test.idptools.com", "idptools.com"];
function isStaticContentSite(url) {
  try {
    return STATIC_CONTENT_SITE_HOSTS.includes(new URL(url).hostname);
  } catch (e) {
    return false;
  }
}

// Drive the new Token Revocation pane: click the "Revoke Token" button rendered
// next to the token of the given type (which populates the pane AND submits the
// revocation in one action), then wait for the results pane to report a
// successful (HTTP 200) RFC 7009 response.
async function revokeTokenViaUI(driver, type) {
  log.info("Revoking token via UI. type=" + type);
  const revokeBtn = By.css(`input.revoke_token_btn[data-revoke-type='${type}']`);
  await driver.wait(until.elementLocated(revokeBtn), waitTime);
  const btnEl = await driver.findElement(revokeBtn);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", btnEl);
  await driver.wait(until.elementIsVisible(btnEl), waitTime);
  await btnEl.click();

  const resultArea = By.id("revocation_result_textarea");
  await driver.wait(until.elementLocated(resultArea), waitTime);
  await driver.wait(async () => {
    try {
      const v = await driver.findElement(resultArea).getAttribute("value");
      return !!v && v.indexOf("HTTP Status: 200") !== -1;
    } catch (e) {
      return false;
    }
  }, waitTime, "Token revocation result did not report HTTP 200 for type=" + type);

  const finalText = await driver.findElement(resultArea).getAttribute("value");
  log.info("Revocation result (" + type + "): " + finalText.replace(/\n/g, " | "));
  assert(finalText.indexOf("HTTP Status: 200") !== -1,
    "Revocation call for " + type + " did not return HTTP 200.");
  return finalText;
}

// Follows the "Introspect Token" link next to the given token (access or
// refresh) on debugger2.html, runs the introspection on introspection.html
// (authenticating the client via HTTP Basic, through the backend to avoid
// browser CORS restrictions), and returns the raw introspection output JSON.
async function introspectTokenViaUI(driver, type, client_id, client_secret) {
  log.info("Introspecting token via UI. type=" + type);

  // Click the "Introspect Token" link rendered next to the token field.
  const link = By.css(`a[href="/introspection.html?type=${type}"]`);
  await driver.wait(until.elementLocated(link), waitTime);
  const linkEl = await driver.findElement(link);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", linkEl);
  await linkEl.click();

  // We are now on introspection.html. Configure client authentication.
  const clientIdField = By.id("introspection_client_id");
  await driver.wait(until.elementLocated(clientIdField), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(clientIdField)), waitTime);

  // The introspection endpoint should have been populated from the discovery
  // document when the metadata was loaded.
  const endpointValue = await driver.findElement(By.id("introspection_endpoint")).getAttribute("value");
  assert(endpointValue && endpointValue.length > 0,
    "Introspection endpoint was not populated from the discovery document.");

  // Use the backend to avoid browser CORS restrictions on the IdP.
  await driver.findElement(By.id("introspection_initiateFromBackEnd")).click();

  // Authenticate the client via HTTP Basic with its credentials.
  await new Select(await driver.findElement(By.id("introspection_authentication_type"))).selectByValue("basic_auth");
  await driver.findElement(clientIdField).clear();
  await driver.findElement(clientIdField).sendKeys(client_id);
  const clientSecretField = await driver.findElement(By.id("introspection_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }

  // Trigger the introspection call.
  await driver.findElement(By.css('input[value="Introspect Token"]')).click();

  // Wait for the output textarea to be populated.
  const output = By.id("introspection_output");
  await driver.wait(async () => {
    try {
      const v = (await driver.findElement(output).getAttribute("value") || "").trim();
      return v.length > 0;
    } catch (e) {
      return false;
    }
  }, waitTime, "Introspection produced no output for type=" + type);

  const outputText = (await driver.findElement(output).getAttribute("value") || "").trim();
  log.info("Introspection output (" + type + "): " + outputText.replace(/\n/g, " "));
  return outputText;
}

// Asserts that an introspection response reports the token as no longer valid
// (RFC 7662 returns {"active": false} for a revoked/unknown token).
function assertTokenInactive(outputText, type) {
  let parsed = null;
  try {
    parsed = JSON.parse(outputText);
  } catch (e) {
    parsed = null;
  }
  assert(parsed !== null,
    "Introspection output for the " + type + " token was not valid JSON: " + outputText);
  assert(parsed.active === false,
    "Introspection reported the " + type + " token as still valid (expected active=false). Output: " + outputText);
}

// Returns from introspection.html to debugger2.html via the "Return to
// debugger" link, which re-renders the token panes (and their Introspect/Revoke
// controls) from local storage.
async function returnToDebugger(driver) {
  log.info("Returning to debugger2.html.");
  const link = By.css('a[href="/debugger2.html?redirectFromTokenDetail=true"]');
  await driver.wait(until.elementLocated(link), waitTime);
  await driver.findElement(link).click();
  // Wait until the token results pane (with its Introspect links) is rendered.
  await driver.wait(until.elementLocated(By.css('a[href="/introspection.html?type=refresh"]')), waitTime);
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
    // Public (PKCE) clients may have no secret; treat it as optional.
    const client_secret = process.env.CLIENT_SECRET || "";
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;
    // The Token Introspection Endpoint must be called by a client that is
    // permitted to introspect. The public/PKCE client used to obtain the tokens
    // is not, so introspection authenticates as the confidential client.
    const introspection_client_id = process.env.INTROSPECTION_CLIENT_ID;
    const introspection_client_secret = process.env.INTROSPECTION_CLIENT_SECRET;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
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

    // Load the debugger, populate IdP metadata from discovery, and run the
    // OIDC Authorization Code flow to obtain an access token and refresh token.
    log.info("Kicking off test.");
    await driver.get(baseUrl + "/debugger.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    const { access_token, refresh_token } = await getAccessTokenAuthCode(driver, client_id, client_secret, scope, pkce_enabled, { baseUrl, returnRefreshToken: true });
    assert(access_token, "No access token was retrieved.");
    assert(refresh_token, "No refresh token was retrieved.");

    // Revoke both tokens through the new Token Revocation pane.
    //
    // Order matters: revoke the REFRESH token first, then the access token.
    // Revoking the access token terminates the Keycloak user session, which also
    // invalidates the refresh token's session and makes the subsequent refresh
    // token revocation call fail. Revoking the refresh token first leaves the
    // access token (a self-contained JWT) independently revocable afterwards.
    log.info("Revoking the refresh token via the UI.");
    await revokeTokenViaUI(driver, "refresh");
    log.info("Revoking the access token via the UI.");
    await revokeTokenViaUI(driver, "access");

    // Validate the revocation via the Introspection page. This uses the backend
    // to reach Keycloak's introspection endpoint (which is not CORS-enabled), so
    // it cannot run against the static-content deployments (no backend). For
    // those targets, skip introspection: revocation was already confirmed by the
    // HTTP 200 responses above. The containerized/local backend build still
    // performs full introspection-based validation.
    if (isStaticContentSite(baseUrl)) {
      log.info("Static content site (" + baseUrl + "): skipping introspection-based " +
               "validation (introspection endpoint is not browser-accessible without a " +
               "backend). Revocation was confirmed by the HTTP 200 responses above.");
    } else {
      // Verify the revoked access token is reported as no longer valid by the
      // Introspection page, reached via its "Introspect Token" link.
      log.info("Validating the revoked access token via the Introspection page.");
      const accessIntrospection = await introspectTokenViaUI(driver, "access", introspection_client_id, introspection_client_secret);
      assertTokenInactive(accessIntrospection, "access");

      // Return to the debugger so the refresh token's Introspect link is available.
      await returnToDebugger(driver);

      // Verify the revoked refresh token is reported as no longer valid.
      log.info("Validating the revoked refresh token via the Introspection page.");
      const refreshIntrospection = await introspectTokenViaUI(driver, "refresh", introspection_client_id, introspection_client_secret);
      assertTokenInactive(refreshIntrospection, "refresh");

      log.info("Both the access token and refresh token were revoked and confirmed invalid via introspection.");
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
  .name('oauth2_token_revocation')
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
