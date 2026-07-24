const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oidc_authorization_code',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var audience = "http://localhost:8080/realms/debugger-testing";
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenAuthCode, verifyAccessToken } = require("../common/tests.js")({ By, until, Select, waitTime, log, jwt, assert });

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, {complete: true});
}

const wait = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds));




async function getIDToken(driver)
{
  log.info("Entering getIDToken().");
  // Read the ID token value from the token_id_token field on debugger2.html
  log.info("Find token_id_token.");
  token_id_token = By.id("token_id_token");
  log.info("Find token_id_token element.");
  return await driver.findElement(token_id_token).getAttribute("value");
}

async function getRefreshToken(driver)
{
  log.info("Entering getRefreshToken().");
  // Read the refresh token value from the token_refresh_token field on debugger2.html
  log.info("Find token_refresh_token.");
  let token_refresh_token = By.id("token_refresh_token");
  log.info("Find token_refresh_token element.");
  return await driver.findElement(token_refresh_token).getAttribute("value");
}


async function verifyIDToken(id_token, client_id, user, audience, issuer) {
  log.info("Entering verifyIDToken().");
  let decoded_id_token = jwt.decode(id_token, { complete: true });
  let response_text = id_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_id_token, null, "Cannot decode ID token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_id_token.payload.azp, client_id, "ID token AZP does not match client ID.");
  assert.strictEqual(decoded_id_token.payload.aud, audience, "ID token aud does not match " + audience);
  assert.strictEqual(decoded_id_token.payload.iss, issuer, "ID token iss does not match " + issuer);
  assert.strictEqual(decoded_id_token.payload.sub, user, "ID token SUB does not match user ID.");
  assert.strictEqual(decoded_id_token.payload.given_name, client_id, "ID token given_name does not match.");
  assert.strictEqual(decoded_id_token.payload.family_name, client_id, "ID token family_name does not match.");
  assert.strictEqual(decoded_id_token.payload.email, `${client_id}@iyasec.io`, "ID token email does not match.");
  assert.strictEqual(decoded_id_token.payload.typ, "ID", "ID Token typ does not match.");
}

async function verifyRefreshToken(refresh_token, client_id, user, audience, issuer) {
  log.info("Entering verifyRefreshToken().");
  let decoded_refresh_token = jwt.decode(refresh_token, { complete: true });
  let response_text = refresh_token.match(/responseText: (.*)/);

  assert.notStrictEqual(decoded_refresh_token, null, "Cannot decode Refresh token. Request result: " + (response_text ? response_text[1] : "no response text"));
  assert.strictEqual(decoded_refresh_token.payload.aud, audience, "Refresh token aud does not match " + audience);
  assert.strictEqual(decoded_refresh_token.payload.iss, issuer, "Refresh token iss does not match " + issuer);
  assert.strictEqual(decoded_refresh_token.payload.azp, client_id, "Refresh token AZP does not match client ID.");
  assert.strictEqual(decoded_refresh_token.payload.typ, "Offline", "Refresh Token typ does not match.");
}

async function tokenDetailPage(driver, type)
{
  log.info("Entering tokenDetailPage(). type=" + type + ".");
  try {
    var token_field = "";
    var link_text = "";
    if ( type === "access_token") {
      token_field = "token_access_token";
      link_text = "Access Token";
    } else if ( type === "refresh_token") {
      token_field = "token_refresh_token";
      link_text = "Refresh Token";
    } else if ( type === "id_token") {
      token_field = "token_id_token";
      link_text = "ID Token";
    } else if ( type == "refresh_access_token") {
      token_field = "refresh_access_token";
      link_text = "Latest Access Token";
    } else if ( type == "refresh_refresh_token") {
      token_field = "refresh_refresh_token";
      link_text = "Latest Refresh Token";
    } else if ( type == "refresh_id_token" ) {
      token_field = "refresh_id_token";
      link_text = "Latest ID Token";
    }
    // Find the token detail link on the debugger2.html page.
    log.info("Find token detail link.");
    tokenDetailLink = By.partialLinkText(link_text);
    log.info("Locate token detail link.");
    await driver.wait(until.elementLocated(tokenDetailLink), waitTime);
    log.info("Click link to go to the token detail page for " + type + " token.");
    await driver.findElement(tokenDetailLink).click();

    // Find the jwt_payload field to confirm you are on the token_detail.html page.
    var jwt_payload = By.id("jwt_payload");
    log.info("Waiting for jwt_payload");
    var jwt_payload_element = await driver.wait(until.elementLocated(jwt_payload), waitTime);
    log.info("jwt_payload_element: " + JSON.stringify(jwt_payload_element));
    log.info("Waiting for jwt_payload to be visible.");
    await driver.wait(until.elementIsVisible(jwt_payload_element), waitTime);

    // Confirm that the value in the jwt_payload text field matches the expected payload value.
    token = await driver.executeScript("return window.localStorage.getItem(\"" + token_field + "\");")
    log.info("token (from local storage): " + token);
    log.info("Decode JWT.");
    const decodedJWT = decodeJWT(token);
    log.info("decodedJWT: " + JSON.stringify(decodedJWT.payload, null, 2));
    log.info("Waiting ten seconds.");
    await wait(waitTime);
    log.info("Wait for JWT Payload to be populated in jwt_payload field.");
    log.info("jwt_payload_element: " + JSON.stringify(jwt_payload_element));
    const fromJWTPayloadJWT= await jwt_payload_element.getAttribute("value");
    log.info("jwt_payload_element.text(): " + fromJWTPayloadJWT);
    if (fromJWTPayloadJWT === JSON.stringify(decodedJWT.payload, null, 2)) {
      log.info("jwt_payload_element has expected value.");
    } else {
      log.info("jwt_payload_element does not have expected value.");
      throw new Error("jwt_payload_element does not have expected value. jwt_payload.text=" +
                      fromJWTPayloadJWT +
                      ", localStorage('" +
                      token_field +
                     "')=" +
                     JSON.stringify(decodedJWT.payload, null, 2));
    }

    // Click Copy button for JWT Header on JSON tab.
    log.info("Click JWT Header Copy button on JSON tab.");
    const jsonHeaderCopyBtn = By.xpath("//div[@id='json']//td[.//label[contains(text(),'JWT Header:')]]//button[text()='Copy']");
    await driver.wait(until.elementLocated(jsonHeaderCopyBtn), waitTime);
    await driver.findElement(jsonHeaderCopyBtn).click();
    log.info("JWT Header Copy button clicked.");

    // Click Copy button for JWT Payload on JSON tab.
    log.info("Click JWT Payload Copy button on JSON tab.");
    const jsonPayloadCopyBtn = By.xpath("//div[@id='json']//td[.//label[contains(text(),'JWT Payload:')]]//button[text()='Copy']");
    await driver.wait(until.elementLocated(jsonPayloadCopyBtn), waitTime);
    await driver.findElement(jsonPayloadCopyBtn).click();
    log.info("JWT Payload Copy button clicked.");

    // Switch to the Key Pairs view.
    log.info("Switch to the key pair view.");
    keyPairButton = By.id("key_pair_button");
    log.info("Locate key_pair_button.");
    await driver.wait(until.elementLocated(keyPairButton), waitTime);
    log.info("Click button to switch to Key Pair View");
    await driver.findElement(keyPairButton).click();

    // Confirm key-pair view is visible.
    keyPairJWTPayload = By.id("key_pair_jwt_payload");
    log.info("Locate keyPairJWTPayload.");
    await driver.wait(until.elementLocated(keyPairJWTPayload), waitTime);
    log.info("Wait for keyPairJWTPayload to be visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(keyPairJWTPayload)), waitTime);

    // Click Copy button for JWT Header on Key Pairs tab.
    log.info("Click JWT Header Copy button on Key Pairs tab.");
    const keyPairHeaderCopyBtn = By.xpath("//div[@id='key-pair']//td[.//label[contains(text(),'JWT Header:')]]//button[text()='Copy']");
    await driver.wait(until.elementLocated(keyPairHeaderCopyBtn), waitTime);
    await driver.findElement(keyPairHeaderCopyBtn).click();
    log.info("Key Pairs JWT Header Copy button clicked.");

    // Click Copy button for JWT Payload on Key Pairs tab.
    log.info("Click JWT Payload Copy button on Key Pairs tab.");
    const keyPairPayloadCopyBtn = By.xpath("//div[@id='key-pair']//td[.//label[contains(text(),'JWT Payload:')]]//button[text()='Copy']");
    await driver.wait(until.elementLocated(keyPairPayloadCopyBtn), waitTime);
    await driver.findElement(keyPairPayloadCopyBtn).click();
    log.info("Key Pairs JWT Payload Copy button clicked.");

    // Scroll to the Claims Validation section and run validation.
    log.info("Scroll to Claims Validation section.");
    const validateClaimsBtn = await driver.findElement(By.css("input[value='Validate Claims']"));
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", validateClaimsBtn);

    // Set JWT purpose to OIDC ID Token to exercise the full set of validations.
    log.info("Set JWT purpose to OIDC ID Token.");
    await new Select(await driver.findElement(By.id("jwt_purpose"))).selectByValue("oidc_id_token");

    log.info("Click Validate Claims button.");
    await validateClaimsBtn.click();
    await wait(2000);

    // Read and report the validation output.
    const validationOutput = await driver.findElement(By.id("jwt_claims_validation_output")).getAttribute("value");
    log.info("Claims validation output:\n" + validationOutput);

    // Claims validation output is logged above for inspection; no assertion is
    // made on its contents.
    log.info("Claims validation completed.");

    // Return to the debugger.
    log.info("Find return to debugger link.");
    returnToDebugger = By.partialLinkText('Return to debugger');
    log.info("Locate return to debugger link.");
    await driver.wait(until.elementLocated(returnToDebugger), waitTime);
    log.info("Click link to go back to debugger2.");
    await driver.findElement(returnToDebugger).click();

    // Make sure you see the access_token on the debugger2.html page.
    log.info("Find token_access_token.");
    token = By.id(token_field);
    log.info("Wait for " + token_field);
    await driver.findElement(token);
    log.info("Wait for " + token_field + " to be visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(token)), waitTime);
    log.info("Leaving tokenDetailPage().");
  } catch(e) {
    log.error("An error occurred: " + e.stack);
    process.exit(1);
  }
}

async function refresh_token_call(driver, client_id, scope, user, access, audience) {
  log.info("Entering refresh_token_call().");
  // Locate and click the refresh button to exchange the refresh token for new tokens
  log.info("Find Refresh Button");
  refresh_btn = By.id("refresh_btn");
  log.info("Locate refresh_btn.");
  await driver.wait(until.elementLocated(refresh_btn), waitTime);
  log.info("Wait for refresh_btn to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(refresh_btn)), waitTime);
  log.info("Click refresh_btn. Making refresh token call.");
  await driver.findElement(refresh_btn).click();
  log.info("Waiting for call to complete.");
  await wait(4000);
  // Read and verify the newly issued access token
  log.info("Finding refresh_access_token.");
  var refresh_access_token = By.id("refresh_access_token");
  log.info("Locate refresh_access_token.");
  var refresh_access_token_element = await driver.wait(until.elementLocated(refresh_access_token), waitTime);
  log.info("Waiting for refresh_access_token to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(refresh_btn)), waitTime);
  var refresh_access_token_value = await driver.findElement(refresh_access_token).getAttribute("value");

  log.info("Calling verifyAccessToken().");
  await verifyAccessToken(refresh_access_token_value, client_id, scope, { user, audience: access, issuer: audience, verifyTyp: true });

  // Read and verify the newly issued refresh token
  var refresh_refresh_token = By.id("refresh_refresh_token");
  log.info("Locate refresh_refresh_token.");
  await driver.wait(until.elementLocated(refresh_refresh_token), waitTime);
  log.info("Waiting for refresh_refresh_token to be visible.");
  await driver.wait(until.elementIsVisible( driver.findElement(refresh_refresh_token)), waitTime);
  var refresh_refresh_token_value = await driver.findElement(refresh_refresh_token).getAttribute("value");

  log.info("Calling verifyRefreshToken().");
  await verifyRefreshToken(refresh_refresh_token_value, client_id, user, audience, audience);

  // Read and verify the newly issued ID token
  var refresh_id_token = By.id("refresh_id_token");
  log.info("Locate refresh_id_token.");
  await driver.wait(until.elementLocated(refresh_id_token), waitTime);
  log.info("Waiting for refresh_id_token to be visible.");
  await driver.wait(until.elementIsVisible( driver.findElement(refresh_id_token)), waitTime);
  var refresh_id_token_value = await driver.findElement(refresh_id_token).getAttribute("value");

  log.info("Calling verifyIDToken().");
  await verifyIDToken(refresh_id_token_value, client_id, user, client_id, audience)

  log.info("Leaving refresh_token_call().");
}

async function logout(driver) {
  log.info("Entering logout().");
  // Locate the post-logout redirect field and set it to the logout landing page
  log.info("Find logout Button");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  log.info("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  log.info("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(logout_post_redirect_uri)), waitTime);
  log.info("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri).sendKeys(logout_post_redirect_uri_value);
  // Locate and click the logout button to trigger the OIDC logout
  logout_button = By.id("logout_btn");
  log.info("Locate logout_button.");
  await driver.wait(until.elementLocated(logout_button), waitTime);
  log.info("Waiting for logout_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(logout_button)), waitTime);
  log.info("Click logout_btn.");
  await driver.findElement(logout_button).click();

  // Follow the link back to the debugger front page
  returnToDebugLink = By.partialLinkText('Return to debugger');
  log.info("Locate returnToDebugLink.");
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  log.info("Click link to return to the front page of the debugger.");
  await driver.findElement(returnToDebugLink).click();

  // Confirm the debugger form is back by waiting for the expand button and client_id
  log.info("Find authz_expand_button.");
  authz_expand_button = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  log.info("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);

  log.info("Find client_id.");
  client_id = By.id("client_id");
  log.info("Locate client_id");
  await driver.wait(until.elementLocated(client_id), waitTime);
  log.info("Wait for client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id)), waitTime);
}

async function test() {
  const options = new chrome.Options();
  if(headless) {
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
  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .build();

  try {
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    const audience = process.env.AUDIENCE;
    let pkce_enabled = process.env.PKCE_ENABLED

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    assert(audience, "AUDIENCE environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      log.info("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    log.info("Clear all cookies.");
    await driver.manage().deleteAllCookies();
    log.info("Kicking off test.");
    await driver.get(baseUrl + "/debugger.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    let access_token = await getAccessTokenAuthCode(driver, client_id, client_secret, scope, pkce_enabled, { baseUrl });
    log.info("Access token: " + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, { user, audience: "account", issuer: audience, verifyTyp: true });
    log.info("Calling getIDToken().");
    let id_token = await getIDToken(driver);
    log.info("ID Token: " + id_token);
    log.info("Calling verifyIDToken()");
    await verifyIDToken(id_token, client_id, user, client_id, audience)
    let refresh_token = await getRefreshToken(driver);
    log.info("Refresh Token: " + refresh_token);
    log.info("Calling verifyRefreshToken()");
    await verifyRefreshToken(refresh_token, client_id, user, audience, audience);
    log.info("Go to access_token detail page.");
    await tokenDetailPage(driver, "access_token");
    log.info("Go to refresh_token detail page.");
    await tokenDetailPage(driver, "refresh_token");
    log.info("Go to id_token detail page.");
    await tokenDetailPage(driver, "id_token");
    log.info("Making refresh_token_call().");
    await refresh_token_call(driver, client_id, scope, user, "account", audience);
    log.info("Go to refresh_access_token detail page.");
    await tokenDetailPage(driver, "refresh_access_token");
    log.info("Go to refresh_refresh_token detail page.");
    await tokenDetailPage(driver, "refresh_refresh_token");
    log.info("Go to refresh_id_token detail page.");
    await tokenDetailPage(driver, "refresh_id_token");
    log.info("Making refresh_token_call().");
    await refresh_token_call(driver, client_id, scope, user, "account", audience);
    log.info("Go to refresh_access_token detail page.");
    await tokenDetailPage(driver, "refresh_access_token");
    log.info("Go to refresh_refresh_token detail page.");
    await tokenDetailPage(driver, "refresh_refresh_token");
    log.info("Go to refresh_id_token detail page.");
    await tokenDetailPage(driver, "refresh_id_token");
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
