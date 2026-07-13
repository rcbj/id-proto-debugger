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

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, {complete: true});
}

const wait = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds));

async function populateMetadata(driver, discovery_endpoint) {
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
  // Locate all the form/login elements used across this flow up front
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

  // Select OIDC Authorization Code Flow 
  log.info("Set authorization_grant_type to OIDC Authorizaton Code Authentication Flow.");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  log.info("Waiting for usePKCE_yes");
  await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
  log.info("Waiting for usePKCE_yes to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
  log.info("Waiting for usePKCE_no.");
  await driver.wait(until.elementLocated(usePKCE_no), waitTime);
  log.info("Waiting for usePKCE to be visible");
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

  // Toggle PKCE on or off depending on the test configuration
  if (pkce_enabled) {
    log.info("Click usePKCE_yes.");
    await driver.findElement(usePKCE_yes).click();
  } else {
    log.info("Click usePKCE_no.");
    await driver.findElement(usePKCE_no).click();
  }

  // Expand the advanced authorization section and wait for client_id to appear
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

  // Get access token result
  async function waitForVisibility(element) {
    log.info("Waiting for " + element);
    await driver.wait(until.elementLocated(element), waitTime);
    log.info("Waiting for " + element + "is visible.");
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    log.info("Returning " + element);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  log.info("Begin returning token.");
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
}

async function verifyAccessToken(access_token, client_id, scope, user, audience, issuer) {
  async function compareScopes(scope1, scope2) {
    scope1 = scope1.split(" ");
    scope2 = scope2.split(" ");

    return scope2.every(element => scope1.includes(element));
  }

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
  await verifyAccessToken(refresh_access_token_value, client_id, scope, user, access, audience);

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
    await driver.get(baseUrl);
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    let access_token = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    log.info("Access token: " + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, user, "account", audience);
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
