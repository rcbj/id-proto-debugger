const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_resource_owner_password_credentials_grant',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = appconfig.waitTime;

async function populateMetadata(driver, discovery_endpoint) {
  log.info("Entering populateMetadata().");
  // Locate the discovery endpoint field and its related buttons
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

async function verifyAccessToken(access_token, client_id, scope, user, audience, issuer) {
  // Helper to confirm every requested scope is present in the token's scopes
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

  // Decode the JWT and assert its claims match the expected client, scopes, user, audience and issuer
  let decoded_access_token = jwt.decode(access_token, { complete: true });
  let response_text = access_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_access_token.payload.azp, client_id, "Access token AZP does not match client ID.");
  assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
  assert.strictEqual(decoded_access_token.payload.sub, user, "Access token SUB does not match user ID: access_token.payload.sub=" + decoded_access_token.payload.sub + " , user=" + user);
  assert.strictEqual(decoded_access_token.payload.aud, audience, "Access token aud does not match " + audience);
  assert.strictEqual(decoded_access_token.payload.iss, issuer, "Access token iss does not match " + issuer);
  assert.strictEqual(decoded_access_token.payload.given_name, client_id, "Access token given_name does not match.");
  assert.strictEqual(decoded_access_token.payload.family_name, client_id, "Access token family_name does not match.");
  assert.strictEqual(decoded_access_token.payload.email, `${client_id}@iyasec.io`, "Access token email does not match.");
  assert.strictEqual(decoded_access_token.payload.typ, "Bearer", "Access Token typ does not match.");
}

async function getAccessToken(driver, client_id, client_secret, scope, username, password) {
  log.info("Entering getAccessToken().");

  // Select Resource Owner Password Credential grant type on debugger.html
  log.info("Find authorization_grant_type.");
  const authorization_grant_type = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(authorization_grant_type), waitTime);
  log.info("Select 'OAuth2 Resource Owner Password Credential Grant'.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Resource Owner Password Credential Grant');

  // Wait for debugger2.html to load
  log.info("Wait for token_client_id on debugger2.html.");
  const token_client_id = By.id("token_client_id");
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  // Select OIDC No
  log.info("Click noCheckOIDCArtifacts.");
  const noCheckOIDCArtifacts = By.id("noCheckOIDCArtifacts");
  await driver.wait(until.elementLocated(noCheckOIDCArtifacts), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(noCheckOIDCArtifacts));
  await driver.findElement(noCheckOIDCArtifacts).click();

  // Select PKCE No
  log.info("Click usePKCE-no.");
  const usePKCENo = By.id("usePKCE-no");
  await driver.wait(until.elementLocated(usePKCENo), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(usePKCENo));
  await driver.findElement(usePKCENo).click();

  // Collapse config pane
  log.info("Collapse config pane.");
  const config_expand_button = By.id("config_expand_button");
  await driver.wait(until.elementLocated(config_expand_button), waitTime);
  const configBtnEl = await driver.findElement(config_expand_button);
  const configBtnVal = await configBtnEl.getAttribute("value");
  if (configBtnVal === "Hide") {
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", configBtnEl);
    await configBtnEl.click();
  }

  // Select POST auth style
  log.info("Click token_postAuthStyleCheckToken.");
  const token_postAuthStyleCheckToken = By.id("token_postAuthStyleCheckToken");
  await driver.wait(until.elementLocated(token_postAuthStyleCheckToken), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_postAuthStyleCheckToken));
  await driver.findElement(token_postAuthStyleCheckToken).click();

  // Select Back-end initiation
  log.info("Click token_initiateFromBackEnd.");
  const token_initiateFromBackEnd = By.id("token_initiateFromBackEnd");
  await driver.wait(until.elementLocated(token_initiateFromBackEnd), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_initiateFromBackEnd));
  await driver.findElement(token_initiateFromBackEnd).click();

  // Fill in credentials
  log.info("Fill token_client_id.");
  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);

  log.info("Fill token_client_secret.");
  const token_client_secret = By.id("token_client_secret");
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);

  log.info("Fill token_scope.");
  const token_scope = By.id("token_scope");
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);

  log.info("Fill token_username.");
  const token_username = By.id("token_username");
  await driver.wait(until.elementLocated(token_username), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_username)), waitTime);
  await driver.findElement(token_username).clear();
  await driver.findElement(token_username).sendKeys(client_id);

  log.info("Fill token_password.");
  const token_password = By.id("token_password");
  await driver.wait(until.elementLocated(token_password), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_password)), waitTime);
  await driver.findElement(token_password).clear();
  await driver.findElement(token_password).sendKeys(password);

  // Click Get Token
  log.info("Click token_btn.");
  const token_btn = By.className("token_btn");
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_btn));
  await driver.findElement(token_btn).click();

  // Get access token result: wait for either the token or the error field to appear, then return its value
  async function waitForVisibility(element) {
    log.info("Waiting for " + element);
    await driver.wait(until.elementLocated(element), waitTime);
    log.info("Waiting for " + element + "is visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    log.info("Returning " + element);
    return element;
  }

  log.info("Find token_access_token.");
  token_access_token = By.id("token_access_token");

  log.info("Find display_token_error_form_texarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  log.info("Begin returning token.");
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");

  log.info("Leaving getAccessToken().");
}

async function logout(driver) {
  log.info("Entering logout().");
  // Locate the logout controls, set the post-logout redirect URI and trigger logout
  log.info("Find logout Button");
  logout_button = By.id("logout_btn");
  log.info("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  log.info("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  log.info("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(logout_post_redirect_uri)), waitTime);
  log.info("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri).sendKeys(logout_post_redirect_uri_value);
  log.info("Click logout_btn.");
  await driver.findElement(logout_button).click();

  // Follow the link back to the debugger's front page
  log.info("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  await driver.findElement(returnToDebugLink).click();
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
    const username = process.env.USER;
    const password = client_id;
    const audience = process.env.AUDIENCE;
    log.info("Set environment variables.");

    // Verify all required environment variables are present
    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(username, "USER environment variable is not set.");
    assert(audience, "AUDIENCE environment variable is not set.");
    log.info("Assertions completed successfully.");

    // Drive the full flow: load the app, populate IdP metadata, obtain and verify a token, then log out
    log.info("Starting driver.get() run.");
    await driver.get(baseUrl);
    log.info("Completed driver.get() run.");
    log.info("Starting populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Completed populateMetadata().");
    log.info("Retrieve access_token.");
    const access_token = await getAccessToken(driver, client_id, client_secret, scope, username, password);
    log.info("Found access_token=" + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, username, "account", audience);
    log.info("Logging out.");
    await logout(driver);
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
  .name('oauth2_resource_owner_password_credentials_grant')
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
    // Apply CLI overrides for the base URL and headless/visible browser mode
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
