const { Builder, By, until, logging } = require("selenium-webdriver");
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
var baseUrl = "http://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = appconfig.waitTime;

async function populateMetadata(driver, discovery_endpoint) {
  // Locate the discovery/metadata form controls on the debugger page
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  // Enter discovery endpoint
  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint); 
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
}

async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
  log.info("Entering getAccessToken().");

  // Build the By locators for every form element used across the flow:
  // grant type selector, PKCE toggle, authorize/token forms, and the Keycloak login page
  log.info("Find authorization_grant_type.");
  authorization_grant_type = By.id("authorization_grant_type");
  log.info("Find usePKCE-yes.");
  usePKCE_yes = By.id("usePKCE-yes");
  log.info("Find usePKCE-no.");
  usePKCE_no = By.id("usePKCE-no");
  log.info("Find authz_expand_button");
  authz_expand_button = By.id("authz_expand_button");
  log.info("Find client_id.");
  client_id_ = By.id("client_id");
  log.info("Find scope.");
  scope_ = By.id("scope");
  log.info("find token_client_id.");
  token_client_id = By.id("token_client_id");
  log.info("Find token_client_secret.");
  token_client_secret = By.id("token_client_secret");
  log.info("Find token_scope.");
  token_scope = By.id("token_scope");
  log.info("Find btn_authorize.");
  btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
  log.info("Find username.");
  keycloak_username = By.id("username");
  log.info("Find password.");
  keycloak_password = By.id("password");
  log.info("Find kc-login");
  keycloak_kc_login = By.id("kc-login");
  log.info("Find token_btn.");
  token_btn = By.className("token_btn");
  log.info("Find token_access_token.");
  token_access_token = By.id("token_access_token");
  log.info("Find display_token_error_form_texarea1.");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select the OAuth2 Authorization Code Grant and wait for the PKCE radio buttons to render
  log.info("Set authorization_grant_type to oauth2 Authorizaton Code Grant.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Authorization Code Grant');
  log.info("Waiting for usePKCE_yes");
  await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
  log.info("Waiting for usePKCE_yes to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
  log.info("Waiting for usePKCE_no.");
  await driver.wait(until.elementLocated(usePKCE_no), waitTime);
  log.info("Waiting for usePKCE to be visible");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

  // Toggle PKCE on or off depending on the test parameter
  if (pkce_enabled) {
    log.info("Click usePKCE_yes.");
    await driver.findElement(usePKCE_yes).click();
  } else {
    log.info("Click usePKCE_no.");
    await driver.findElement(usePKCE_no).click();
  }

  // Expand the authorization section to reveal the client_id field
  log.info("Find authz_expand_button.");
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  log.info("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
  log.info("Click authz_expand_button.");
  await driver.findElement(authz_expand_button).click();
  log.info("Locate client_id_.");
  await driver.wait(until.elementLocated(client_id_), waitTime);
  log.info("Find client_id_.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

  // Submit credentials
  log.info("Clear client_id_.");
  await driver.findElement(client_id_).clear();
  log.info("Set client_id value.");
  await driver.findElement(client_id_).sendKeys(client_id);
  log.info("Clear scope_.");
  await driver.findElement(scope_).clear();
  log.info("Set scope value.");
  await driver.findElement(scope_).sendKeys(scope);
  log.info("Find token_redirect_uri.");
  redirect_uri = By.id("redirect_uri");
  log.info("Clear redirect_uri.");
  await driver.findElement(redirect_uri).clear();
  log.info("Set redirect_uri value: redirect_uri=" + redirect_uri + ", redirect_uri=" + baseUrl + "/callback");
  await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
  log.info("Click btn_authorize button.");
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    log.info("Wait for keycloak_username.");
    await driver.wait(until.elementLocated(keycloak_username), waitTime);
    log.info("Wait for keycloak_username to be visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
  } catch (error) {
    log.error("Unable to log into keycloak.");
    authz_error_report = await driver.findElement(By.id("authz-error-report"));
    authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  log.info("Clear keycloak_username.");
  await driver.findElement(keycloak_username).clear();
  log.info("Set keycloak_username value.");
  await driver.findElement(keycloak_username).sendKeys(client_id);
  log.info("Clear keycloak_password.");
  await driver.findElement(keycloak_password).clear();
  log.info("Set client_id value.");
  await driver.findElement(keycloak_password).sendKeys(client_id);
  log.info("Click keycloak_kc_login button.");
  await driver.findElement(keycloak_kc_login).click();

  // Submit credentials (again)
  log.info("Locate token_client_id.");
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  log.info("Wait for token_client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  log.info("Clear token_client_id.");
  await driver.findElement(token_client_id).clear();
  log.info("Set token_client_id value.");
  await driver.findElement(token_client_id).sendKeys(client_id);
  log.info("Clear token_client_secret.");
  await driver.findElement(token_client_secret).clear();
  log.info("Set token_client_secret value.");
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  log.info("Clear token_scope.");
  await driver.findElement(token_scope).clear();
  log.info("Set token_scope value.");
  await driver.findElement(token_scope).sendKeys(scope);
  log.info("Find token_redirect_uri.");
  token_redirect_uri = By.id("token_redirect_uri");
  log.info("Clear token_redirect_uri.");
  await driver.findElement(token_redirect_uri).clear();
  log.info("Set token_redirect_uri value: token_redirect_uri=" + token_redirect_uri + ", redirect_uri=" + baseUrl + "/callback");
  await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
  log.info("Click token_btn button.");
  await driver.findElement(token_btn).click();

  // Get access token result: helper that resolves once an element is located and visible
  async function waitForVisibility(element) {
    log.info("Waiting for " + element);
    await driver.wait(until.elementLocated(element), waitTime);
    log.info("Waiting for " + element + "is visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    log.info("Returning " + element);
    return element;
  }

  // Race the success token field against the error textarea, then return whichever appeared first
  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  log.info("Begin returning token.");
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
}

async function verifyAccessToken(access_token, client_id, scope, user) {
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

  // Decode the JWT and assert its claims match the expected client, scope, and user
  let decoded_access_token = jwt.decode(access_token, { complete: true });
  let response_text = access_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_access_token.payload.azp, client_id, "Access token AZP does not match client ID.");
  assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
  assert.strictEqual(decoded_access_token.payload.sub, user, "Access token SUB does not match user ID.");
  assert.strictEqual(decoded_access_token.payload.given_name, client_id, "Access token given_name does not match.");
  assert.strictEqual(decoded_access_token.payload.family_name, client_id, "Access token family_name does not match.");
  assert.strictEqual(decoded_access_token.payload.email, `${client_id}@iyasec.io`, "Access token email does not match.");
}

async function logout(driver) {
  log.info("Entering logout().");

  // Locate the logout controls and set the post-logout redirect URI, then trigger logout
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

  // Confirm logout on the Keycloak logout page
  log.info("Wait for kc_logout.");
  kc_logout = By.id("kc-logout");
  await driver.wait(until.elementLocated(kc_logout), waitTime);
  log.info("Wait for kc-logout to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(kc_logout)), waitTime);

  log.info("Click kc_logout.");
  await driver.findElement(kc_logout).click();

  // Follow the link back to the debugger front page
  log.info("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  await driver.findElement(returnToDebugLink).click();

  // Re-expand the authorization section and confirm the client_id field is back, verifying we returned to the debugger
  log.info("Find authz_expand_button.");
  authz_expand_button = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  log.info("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);

  log.info("Find client_id.");
  client_id = By.id("client_id");
  log.info("Wait for client_id");
  await driver.findElement(client_id);
  log.info("Wait for client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id)), waitTime);
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

  // Enable browser-level logging and build the Chrome WebDriver
  log.info("Enabling selinium logging.");
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    // Read test configuration from environment variables and assert all are present
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");

    // Coerce the PKCE_ENABLED string into a boolean, aborting on an invalid value
    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      log.info("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    // Drive the full flow: load the app, populate IdP metadata, run the auth code grant,
    // verify the resulting token, then log out
    log.info("Kicking off test.");
    await driver.get(baseUrl);
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    let access_token = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    log.info("Access token: " + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, user);
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
