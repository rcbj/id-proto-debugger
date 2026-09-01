const { Builder, By, until, logging } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_authorization_code',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode, verifyAccessToken } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });



async function logout(driver) {
  log.debug("Entering logout().");
  log.info("Entering logout().");

  // Locate the logout controls and set the post-logout redirect URI, then
  // trigger logout
  log.info("Find logout Button");
  logout_button = By.id("logout_btn");
  log.info("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  log.info("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  log.info("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(
                    logout_post_redirect_uri)), waitTime);
  log.info("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri)
                           .sendKeys(logout_post_redirect_uri_value);
  log.info("Click logout_btn.");
  await driver.findElement(logout_button).click();

  // Confirm logout on the Keycloak logout page
  log.info("Wait for kc_logout.");
  kc_logout = By.id("kc-logout");
  await driver.wait(until.elementLocated(kc_logout), waitTime);
  log.info("Wait for kc-logout to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(kc_logout)),
                    waitTime);

  log.info("Click kc_logout.");
  await driver.findElement(kc_logout).click();

  // Follow the link back to the debugger front page
  log.info("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  await driver.findElement(returnToDebugLink).click();

  // Re-expand the authorization section and confirm the client_id field is
  // back, verifying we returned to the debugger
  log.info("Find authz_expand_button.");
  authz_expand_button = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  log.info("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(
                    authz_expand_button)), waitTime);

  log.info("Find client_id.");
  client_id = By.id("client_id");
  log.info("Wait for client_id");
  await driver.findElement(client_id);
  log.info("Wait for client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id)),
                    waitTime);
  log.debug("Leaving logout().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if(headless) {
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

  // Enable browser-level logging and build the Chrome WebDriver
  log.info("Enabling selinium logging.");
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
    // Read test configuration from environment variables and assert all are
    // present
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED

    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");

    // Coerce the PKCE_ENABLED string into a boolean, aborting on an invalid
    // value
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

    // Drive the full flow: load the app, populate IdP metadata, run the auth
    // code grant, verify the resulting token, then log out
    log.info("Kicking off test.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    let access_token = await getAccessTokenAuthCode(driver, client_id,
        client_secret, scope, pkce_enabled, { baseUrl,
        grantType: "OAuth2 Authorization Code Grant" });
    log.info("Access token: " + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, { user });
    log.info("Logging out.");
    await logout(driver);
    log.info("Test completed successfully.")
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
  .name('oauth_authorization_code')
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
    if(!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
      logout_post_redirect_uri_value = options.url + "/logout.html";
    }
    if(!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
