const { Builder, By, until } = require("selenium-webdriver");
const browserFlags = require("./browser_flags.js");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_client_credentials',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "https://localhost:3000"
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenClientCredentials, verifyAccessToken } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });



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
  // THE STACK'S CERTIFICATE, AS AN EXACT KEY PIN. The client and the api serve
  // https (common/tls_listener.js), on a self-signed pair generated per run, so
  // without this Chrome stops on a certificate interstitial and every
  // assertion below reports a missing element on a page titled "Privacy
  // error". See browser_flags.js.
  browserFlags.addStsTrustFlags(options);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    // Read test configuration from environment variables
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    log.info("Set environment variables.");

    // Ensure all required environment variables are present before proceeding
    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    log.info("Assertions completed successfully.");

    // Load the debugger, populate IdP metadata, then request and validate the
    // access token
    log.info("Starting driver.get() run.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    log.info("Completed driver.get() run.");
    log.info("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Completed populateMetadata().");
    log.info("Retrieve access_token.");
    let access_token = await getAccessTokenClientCredentials(driver, client_id,
        client_secret, scope);
    log.info("Obtained token: " + access_token);
    log.info("Validating token.");
    await verifyAccessToken(access_token, client_id, scope,
                            { clientIdClaim: "client_id",
                            verifyIdentityClaims: false });
    log.info("Token validated.");
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
  .name('oauth_client_credentials')
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
    }
    if(!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });
 
program.parse(process.argv).opts();

test();
