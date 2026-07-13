const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_device_authorization',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"
var headless = true;
var waitTime = appconfig.waitTime;

async function populateMetadata(driver, discovery_endpoint) {
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

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

// On debugger.html: select the Device Authorization Grant, enter client_id and
// scope, and click Authorize. This POSTs to the device authorization endpoint
// and navigates to debugger2.html where the device/user codes are displayed.
async function requestDeviceAuthorization(driver, client_id, scope) {
  log.info("Entering requestDeviceAuthorization().");
  const grantType = By.id("authorization_grant_type");
  await driver.wait(until.elementLocated(grantType), waitTime);
  await new Select(await driver.findElement(grantType)).selectByVisibleText('OAuth2 Device Authorization Grant');

  const authzExpand = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authzExpand), waitTime);
  const clientIdField = By.id("client_id");
  await driver.wait(until.elementLocated(clientIdField), waitTime);
  if (!(await driver.findElement(clientIdField).isDisplayed())) {
    await driver.findElement(authzExpand).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(clientIdField)), waitTime);

  await driver.findElement(clientIdField).clear();
  await driver.findElement(clientIdField).sendKeys(client_id);
  const scopeField = By.id("scope");
  await driver.findElement(scopeField).clear();
  await driver.findElement(scopeField).sendKeys(scope);

  const authorizeBtn = By.css('input[type="submit"][value="Authorize"]');
  await driver.findElement(authorizeBtn).click();

  // The device authorization response is shown on debugger2.html.
  await driver.wait(until.elementLocated(By.id("device_user_code")), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(By.id("device_user_code"))), waitTime);
  log.info("Leaving requestDeviceAuthorization().");
}

async function findEls(driver, by) {
  try {
    return await driver.findElements(by);
  } catch (e) {
    return [];
  }
}

// Approves the device at the Keycloak verification URI. The device verification
// flow spans several pages (enter user code, login, grant consent) whose order
// can vary, so this walks the pages, acting on whichever one is shown, until
// there are no more forms to submit.
async function approveDeviceAuthorization(driver, verification_uri, user_code, username, password) {
  log.info("Approving device authorization at " + verification_uri);
  await driver.get(verification_uri);

  var granted = false;
  for (var i = 0; i < 10 && !granted; i++) {
    await driver.sleep(700);
    var codeInput = await findEls(driver, By.id("device-user-code"));
    var userInput = await findEls(driver, By.id("username"));
    var passwordInput = await findEls(driver, By.id("password"));
    var cancelBtn = await findEls(driver, By.id("kc-cancel"));
    var loginBtn = await findEls(driver, By.id("kc-login"));

    if (codeInput.length > 0) {
      log.info("Device verification: submitting user code.");
      var existing = await codeInput[0].getAttribute("value");
      if (!existing) {
        await codeInput[0].clear();
        await codeInput[0].sendKeys(user_code);
      }
      var submit = await findEls(driver, By.css("input[type=submit], button[type=submit]"));
      if (submit.length > 0) {
        await submit[0].click();
      }
      continue;
    }
    if (userInput.length > 0 && passwordInput.length > 0) {
      log.info("Device verification: logging in.");
      await userInput[0].clear();
      await userInput[0].sendKeys(username);
      await passwordInput[0].clear();
      await passwordInput[0].sendKeys(password);
      if (loginBtn.length > 0) {
        await loginBtn[0].click();
      } else {
        var submit = await findEls(driver, By.css("input[type=submit], button[type=submit]"));
        if (submit.length > 0) {
          await submit[0].click();
        }
      }
      continue;
    }
    if (cancelBtn.length > 0 && loginBtn.length > 0) {
      log.info("Device verification: granting consent.");
      await loginBtn[0].click();
      granted = true;
      continue;
    }
    // No recognizable form remains; the device has been verified.
    log.info("Device verification: no further action required.");
    granted = true;
  }
  assert(granted, "Unable to approve the device authorization at the verification URI.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
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
    const scope = process.env.SCOPE;
    const user = process.env.USER;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");

    // Load the debugger, populate IdP metadata from discovery, and initiate the
    // device authorization request.
    log.info("Kicking off test.");
    await driver.get(baseUrl);
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);

    log.info("Requesting device authorization.");
    await requestDeviceAuthorization(driver, client_id, scope);

    // Read the device authorization response shown in the token pane.
    const user_code = await driver.findElement(By.id("device_user_code")).getAttribute("value");
    const verification_uri = await driver.findElement(By.id("device_verification_uri")).getAttribute("value");
    const device_code = await driver.findElement(By.id("device_code")).getAttribute("value");
    log.info("user_code=" + user_code + ", verification_uri=" + verification_uri);
    assert(user_code, "No user_code was returned from the device authorization endpoint.");
    assert(verification_uri, "No verification_uri was returned from the device authorization endpoint.");
    assert(device_code, "No device_code was returned from the device authorization endpoint.");

    // Approve the device. The realm user shares the client's name/password,
    // matching how configureKeycloak() provisions per-flow users.
    await approveDeviceAuthorization(driver, verification_uri, user_code, client_id, client_id);

    // Return to the debugger (device_code persists in local storage) and poll
    // the token endpoint for the access token.
    log.info("Returning to the debugger to obtain the access token.");
    await driver.get(baseUrl + "/debugger2.html");
    const token_btn = By.className("token_btn");
    await driver.wait(until.elementLocated(By.id("device_code")), waitTime);
    await driver.wait(async () => {
      try {
        return !!(await driver.findElement(By.id("device_code")).getAttribute("value"));
      } catch (e) {
        return false;
      }
    }, waitTime, "Device code was not restored on the token exchange page.");
    await driver.wait(until.elementLocated(token_btn), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_btn)), waitTime);
    await driver.findElement(token_btn).click();

    async function waitForVisibility(element) {
      await driver.wait(until.elementLocated(element), waitTime);
      await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
      return element;
    }
    const token_access_token = By.id("token_access_token");
    const display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");
    let visibleElement = await Promise.any([
      waitForVisibility(token_access_token),
      waitForVisibility(display_token_error_form_textarea1)
    ]);

    const access_token = await driver.findElement(visibleElement).getAttribute("value");
    log.info("Access token result: " + access_token);
    const decoded = jwt.decode(access_token, { complete: true });
    assert.notStrictEqual(decoded, null,
      "The device flow did not return a decodable access token. Result: " + access_token);
    assert.strictEqual(decoded.payload.azp, client_id,
      "Access token azp does not match the device client id.");

    log.info("Device Authorization Grant succeeded and returned a valid access token.");
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
  .name('oauth2_device_authorization')
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
