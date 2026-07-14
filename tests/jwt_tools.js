const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'jwt_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Client-side crypto (key generation, signing, JWE, format conversion) is fast
// but can exceed the 2s element-wait on a busy CI host, so results get a
// generous, separate timeout.
var cryptoWait = Math.max(waitTime, 15000);

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, { complete: true });
}

// ===========================================================================
// OIDC Authorization Code flow (adapted from oidc_authorization_code.js) — used
// only to obtain a real ID Token to feed into the JWT Tools "Encoded JWT" box.
// ===========================================================================
async function populateMetadata(driver, discovery_endpoint) {
  var oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  var btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  var btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint);
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
}

async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
  log.info("Entering getAccessToken().");
  var authorization_grant_type = By.id("authorization_grant_type");
  var usePKCE_yes = By.id("usePKCE-yes");
  var usePKCE_no = By.id("usePKCE-no");
  var authz_expand_button = By.id("authz_expand_button");
  var client_id_ = By.id("client_id");
  var scope_ = By.id("scope");
  var token_client_id = By.id("token_client_id");
  var token_client_secret = By.id("token_client_secret");
  var token_scope = By.id("token_scope");
  var btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
  var keycloak_username = By.id("username");
  var keycloak_password = By.id("password");
  var keycloak_kc_login = By.id("kc-login");
  var token_btn = By.className("token_btn");
  var token_access_token = By.id("token_access_token");
  var display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select OIDC Authorization Code Flow
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
  await driver.wait(until.elementLocated(usePKCE_no), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

  if (pkce_enabled) {
    await driver.findElement(usePKCE_yes).click();
  } else {
    await driver.findElement(usePKCE_no).click();
  }

  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
  await driver.findElement(authz_expand_button).click();
  await driver.wait(until.elementLocated(client_id_), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

  await driver.findElement(client_id_).clear();
  await driver.findElement(client_id_).sendKeys(client_id);
  await driver.findElement(scope_).clear();
  await driver.findElement(scope_).sendKeys(scope);
  var redirect_uri = By.id("redirect_uri");
  await driver.findElement(redirect_uri).clear();
  await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    await driver.wait(until.elementLocated(keycloak_username), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
  } catch (error) {
    log.error("Unable to log into keycloak.");
    var authz_error_report = await driver.findElement(By.id("authz-error-report"));
    var authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  await driver.findElement(keycloak_username).clear();
  await driver.findElement(keycloak_username).sendKeys(client_id);
  await driver.findElement(keycloak_password).clear();
  await driver.findElement(keycloak_password).sendKeys(client_id);
  await driver.findElement(keycloak_kc_login).click();

  // Back on debugger2.html — submit the token request
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);
  var token_redirect_uri = By.id("token_redirect_uri");
  await driver.findElement(token_redirect_uri).clear();
  await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(token_btn).click();

  async function waitForVisibility(element) {
    await driver.wait(until.elementLocated(element), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);
  return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
}

async function getIDToken(driver) {
  log.info("Entering getIDToken().");
  var token_id_token = By.id("token_id_token");
  await driver.wait(until.elementLocated(token_id_token), waitTime);
  return await driver.findElement(token_id_token).getAttribute("value");
}

// ===========================================================================
// JWT Tools UI helpers
// ===========================================================================
async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

async function setInput(driver, locator, text) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
}

async function getValue(driver, locator) {
  return await driver.findElement(locator).getAttribute("value");
}

// Wait until a field's value satisfies pred(value), then return the value.
async function waitForValue(driver, locator, pred, msg, timeout) {
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return pred(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  return await getValue(driver, locator);
}

// Click a toggle-switch by its wrapping <label> (the checkbox itself is
// display:none, so it is not directly clickable).
async function clickToggle(driver, checkboxId) {
  await click(driver, By.xpath("//label[.//input[@id='" + checkboxId + "']]"));
}

function onclickBtn(fn) {
  return By.xpath("//input[@onclick=\"return jwt_tools." + fn + "();\"]");
}

async function addCustomClaim(driver, name, value, type) {
  log.info("Adding custom claim: name=" + name + ", value=" + value + ", type=" + type);
  await setInput(driver, By.id("custom_claim_name"), name);
  await setInput(driver, By.id("custom_claim_value"), value);
  await new Select(driver.findElement(By.id("custom_claim_type"))).selectByValue(type);
  await new Select(driver.findElement(By.id("custom_claim_target"))).selectByValue("jwt_tools_payload");
  await click(driver, onclickBtn("addClaim"));
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf('"' + name + '"') !== -1; },
    "Claim '" + name + "' was not added to the JWT Payload.");
}

// The original JWT Tools coverage: open Tools from the debugger, add claims,
// check compliance, sign + X.509-verify, and encrypt + decrypt.
async function jwtToolsActivities(driver) {
  log.info("Navigate back to debugger.html.");
  await driver.get(baseUrl + "/debugger.html");

  log.info("Expand the Tools pane.");
  await click(driver, By.id("tools_expand_button"));

  log.info("Click the JWT Tools link.");
  var jwtToolsLink = By.css('a[href="/jwt_tools.html?from=debugger.html"]');
  await driver.wait(until.elementLocated(jwtToolsLink), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(jwtToolsLink)), waitTime);
  await click(driver, jwtToolsLink);

  log.info("Wait for JWT Tools page to load.");
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf('"iss"') !== -1; },
    "JWT Tools page did not load / default payload not populated.");

  // ---- Pane 1: add custom claims + RFC compliance -------------------------
  await addCustomClaim(driver, "customString", "hello world", "string");
  await addCustomClaim(driver, "customNumber", "42", "number");
  await addCustomClaim(driver, "customBool", "true", "boolean");

  log.info("Click Check RFC Compliance.");
  await click(driver, onclickBtn("checkCompliance"));
  var compliance = await waitForValue(driver, By.id("compliance_output"),
    function (v) { return v.indexOf("PASS") !== -1; },
    "Compliance output was not produced.");
  log.info("Compliance output:\n" + compliance);
  assert.ok(compliance.indexOf("PASS") !== -1, "Expected at least one PASS in compliance output.");
  assert.ok(compliance.indexOf("FAIL") === -1, "Compliance output contained a FAIL:\n" + compliance);
  log.info("Compliance check passed with no FAIL entries.");

  // ---- Pane 2: signing (JWS) ----------------------------------------------
  log.info("Generate signing keys.");
  await click(driver, onclickBtn("generateSigningKeys"));
  await waitForValue(driver, By.id("sign_public_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "Signing public key (PEM) was not generated.");

  log.info("Toggle keys to JWK.");
  await clickToggle(driver, "sign_key_jwk");
  await waitForValue(driver, By.id("sign_private_key"),
    function (v) { return v.trim().charAt(0) === "{"; },
    "Signing private key did not convert to JWK.");

  log.info("Toggle keys back to PEM.");
  await clickToggle(driver, "sign_key_jwk");
  await waitForValue(driver, By.id("sign_private_key"),
    function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
    "Signing private key did not convert back to PEM.");

  log.info("Download signing keys in PEM format.");
  await new Select(driver.findElement(By.id("sign_ks_format"))).selectByValue("pem");
  await click(driver, onclickBtn("downloadSigningKeys"));
  await waitForValue(driver, By.id("sign_status"),
    function (v) { return v.indexOf("Downloaded PEM") !== -1; },
    "Signing keys were not downloaded in PEM format.");

  log.info("Generate Signed JWT.");
  await click(driver, onclickBtn("signJWT"));
  var signedJwt = await waitForValue(driver, By.id("jwt_tools_signed"),
    function (v) { return v.split(".").length === 3; },
    "Signed JWT was not produced.");
  log.info("Signed JWT produced (" + signedJwt.length + " chars).");

  log.info("Select X.509 verification type.");
  await new Select(driver.findElement(By.id("jwt_verification_type"))).selectByValue("x509");
  await waitForValue(driver, By.id("jwt_verification_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "X.509 verification key was not auto-populated with the public key.");

  log.info("Verify the signature.");
  await click(driver, onclickBtn("verifyJWT"));
  var verifyOut = await waitForValue(driver, By.id("jwt_verification_output"),
    function (v) { return v.indexOf("Signature Verified:") !== -1; },
    "Verification output was not produced.");
  log.info("Verification output: " + verifyOut);
  assert.ok(verifyOut.indexOf("Signature Verified: true") !== -1,
    "Expected signature verification to succeed. Output: " + verifyOut);
  log.info("Signature verification succeeded.");

  // ---- Pane 3: encryption (JWE) -------------------------------------------
  log.info("Generate encryption keys.");
  await click(driver, onclickBtn("generateEncryptionKeys"));
  await waitForValue(driver, By.id("jwe_public_key"),
    function (v) { return v.indexOf("BEGIN PUBLIC KEY") !== -1; },
    "Encryption public key (PEM) was not generated.");

  log.info("Toggle encryption keys to JWK.");
  await clickToggle(driver, "jwe_key_jwk");
  await waitForValue(driver, By.id("jwe_private_key"),
    function (v) { return v.trim().charAt(0) === "{"; },
    "Encryption private key did not convert to JWK.");

  log.info("Toggle encryption keys back to PEM.");
  await clickToggle(driver, "jwe_key_jwk");
  await waitForValue(driver, By.id("jwe_private_key"),
    function (v) { return v.indexOf("BEGIN PRIVATE KEY") !== -1; },
    "Encryption private key did not convert back to PEM.");

  log.info("Download encryption keys.");
  await click(driver, onclickBtn("downloadEncryptionKeys"));
  await waitForValue(driver, By.id("jwe_status"),
    function (v) { return v.indexOf("Downloaded") !== -1; },
    "Encryption keys were not downloaded.");

  var plaintext = (await getValue(driver, By.id("jwe_plaintext"))).trim();
  assert.ok(plaintext.length > 0, "Payload to Encrypt is empty.");

  log.info("Encrypt the JWT.");
  await click(driver, onclickBtn("encryptJWT"));
  await waitForValue(driver, By.id("jwt_tools_jwe"),
    function (v) { return v.split(".").length === 5; },
    "JWE (5-part compact) was not produced.");

  log.info("Decrypt the JWT.");
  await click(driver, onclickBtn("decryptJWT"));
  var decrypted = await waitForValue(driver, By.id("jwe_decrypt_output"),
    function (v) { return v.trim().length > 0; },
    "Decryption output was not produced.");

  assert.strictEqual(decrypted.trim(), plaintext,
    "Decryption output does not match the Payload to Encrypt value.");
  log.info("Decryption output matches the Payload to Encrypt value.");
}

// Obtain a real ID Token via the OIDC Authorization Code grant, paste it into
// the JWT Tools "Encoded JWT" field, and confirm the decoded Payload matches.
async function idTokenDecodeActivities(driver, id_token) {
  log.info("Navigate to jwt_tools.html to paste the ID Token.");
  await driver.get(baseUrl + "/jwt_tools.html");

  // Wait for the page's own onload to populate the default payload first.
  await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v.indexOf("garbage") !== -1; },
    "JWT Tools default payload did not load.");

  log.info("Paste the ID Token into the Encoded JWT field.");
  await driver.executeScript(
    "var el = document.getElementById('jwt_tools_encoded');" +
    "el.value = arguments[0];" +
    "el.dispatchEvent(new Event('input', { bubbles: true }));",
    id_token);

  // The derived payload the field should now show.
  var expectedPayload = JSON.stringify(decodeJWT(id_token).payload, null, 2);

  var actualPayload = await waitForValue(driver, By.id("jwt_tools_payload"),
    function (v) { return v === expectedPayload; },
    "JWT Payload field did not match the ID Token's decoded payload.");

  assert.strictEqual(actualPayload, expectedPayload,
    "JWT Payload field does not match the ID Token's derived payload.");
  log.info("JWT Payload field matches the ID Token's derived payload.");

  // The signed ID Token should also have populated the Sign pane fields.
  var signed = await getValue(driver, By.id("jwt_tools_signed"));
  assert.strictEqual(signed, id_token, "Signed JWT field was not populated with the ID Token.");
  var verifyInput = await getValue(driver, By.id("verify_input"));
  assert.strictEqual(verifyInput, id_token, "JWT to Verify field was not populated with the ID Token.");
  log.info("Sign pane fields populated from the pasted ID Token.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");

    // ---- OIDC Authorization Code flow config ------------------------------
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const client_secret = process.env.CLIENT_SECRET;
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(client_secret, "CLIENT_SECRET environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    pkce_enabled = (pkce_enabled === "true");

    // ---- Obtain an ID Token via OIDC Authorization Code -------------------
    log.info("Clear all cookies.");
    await driver.manage().deleteAllCookies();
    log.info("Load the debugger and run the OIDC Authorization Code flow.");
    await driver.get(baseUrl);
    await populateMetadata(driver, discovery_endpoint);
    let access_token = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    let decoded_access = decodeJWT(access_token);
    assert.notStrictEqual(decoded_access, null, "Could not obtain/decode an access token from the OIDC flow.");
    let id_token = await getIDToken(driver);
    assert.notStrictEqual(decodeJWT(id_token), null, "Could not obtain/decode an ID token from the OIDC flow.");
    log.info("Obtained ID Token (" + id_token.length + " chars).");

    // ---- Paste the ID Token into JWT Tools and verify the decoded payload -
    await idTokenDecodeActivities(driver, id_token);

    // ---- Run the standard JWT Tools activities ----------------------------
    await jwtToolsActivities(driver);

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
  .name('jwt_tools')
  .description("Run JWT Tools UI test.")
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
