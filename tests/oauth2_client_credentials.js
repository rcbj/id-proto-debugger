const { Builder, By, until } = require("selenium-webdriver");
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
var baseUrl = "http://localhost:3000"
var headless = true;
var waitTime = appconfig.waitTime;

async function populateMetadata(driver, discovery_endpoint) {
  log.info("Entering populateMetadata().");
  // Resolve locators for the discovery endpoint field and its action buttons
  log.info("Find oidc_discovery_endpoint.");
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  log.info("Find btn_oidc_discovery_endpoint.");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  log.info("Find btn_oidc_populate_meta_data.");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  log.info("Wait for oidc_discovery_endpoint.");
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  log.info("Wait for oidc_discovery_endpoint.");
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  // Enter discovery endpoint
  log.info("Find & Clear oidc_discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).clear();
  log.info("Find & Send Keys discovery_endpoint.");
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint); 
  log.info("Find & Click btn_oidc_discovery_endpoint.");
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  log.info("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  log.info("Find btn_oidc_populate_meta_data.");
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  log.info("Execute script.");
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  log.info("Find & Click btn_oidc_populate_meta_data.");
  await driver.findElement(btn_oidc_populate_meta_data).click();
  log.info("Leaving populateMetadata().");
}

async function getAccessToken(driver, client_id, client_secret, scope) {
  log.info("Entering getAccessToken().");
  // Resolve locators for the grant type selector and client ID field
  log.info("Find authorization_grant_type.");
  authorization_grant_type = By.id("authorization_grant_type");
  log.info("Find token_client_id.");
  token_client_id = By.id("token_client_id");

  // Select client credential login type
  log.info("Find visible text 'OAuth2 Client Credential' and select.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Client Credential');
  log.info("Find token_client_id element.");

  log.info("Find token_client_id.");
  token_client_id = By.id("token_client_id");
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  log.info("Switch to client_credential grant.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Client Credential');
  log.info("Wait until element is visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  // Resolve locators for the credential inputs, submit button, and result/error fields
  log.info("Find token_client_secret.")
  token_client_secret = By.id("token_client_secret");
  log.info("Find token_scope.");
  token_scope = By.id("token_scope");
  log.info("Find token_btn.");
  token_btn = By.className("token_btn");
  log.info("Find token_btn.");
  token_access_token = By.id("token_access_token");
  log.info("Find display_token_error_form_textarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Submit credentials
  log.info("Find token_client_id & clear.");
  await driver.findElement(token_client_id).clear();
  log.info("Find token_client_id and send keys.");
  await driver.findElement(token_client_id).sendKeys(client_id);
  log.info("Find token_client_secret & clear.");
  await driver.findElement(token_client_secret).clear();
  log.info("Find token_client_secret and send keys.");
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  log.info("Find token_scope and clear.");
  await driver.findElement(token_scope).clear();
  log.info("Find token_scope and send keys.");
  await driver.findElement(token_scope).sendKeys(scope);
  log.info("Find token_btn and click().");
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    await driver.wait(until.elementLocated(element), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    return element;
  }

  try {
    let visibleAccessTokenElement = await Promise.any([
      waitForVisibility(token_access_token),
      waitForVisibility(display_token_error_form_textarea1)
    ]);
    log.info("Returning visibleAccessTokenElement value.");
    return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  } catch (e) {
    log.error("An error occurred: " + e.message);
  }
}

async function verifyAccessToken(access_token, client_id, scope) {
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

  let decoded_access_token = jwt.decode(access_token, { complete: true });
  let response_text = access_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_access_token.payload.client_id, client_id, "Access token client ID does not match client ID.");
  assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
}

async function test() {
  const options = new chrome.Options();
  if(headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak, which
  // browsers otherwise block (mixed content / Private Network Access).
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");
    // Read test configuration from environment variables
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    log.info("Set environment variables.");

    // Ensure all required environment variables are present before proceeding
    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    log.info("Assertions completed successfully.");

    // Load the debugger, populate IdP metadata, then request and validate the access token
    log.info("Starting driver.get() run.");
    await driver.get(baseUrl);
    log.info("Completed driver.get() run.");
    log.info("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Completed populateMetadata().");
    log.info("Retrieve access_token.");
    let access_token = await getAccessToken(driver, client_id, client_secret, scope);
    log.info("Obtained token: " + access_token);
    log.info("Validating token.");
    await verifyAccessToken(access_token, client_id, scope);
    log.info("Token validated.");
    log.info("Test completed successfully.")
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
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
