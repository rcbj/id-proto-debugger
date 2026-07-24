const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'wstrust',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// Set a field's value and fire change/input so the page persists it and rebuilds
// the request (the .stored controls auto-save + auto-rebuild on change).
async function setField(driver, id, value) {
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e){ e.value=arguments[1];" +
    " e.dispatchEvent(new Event('input')); e.dispatchEvent(new Event('change')); }",
    id, value
  );
}

async function setChecked(driver, id, on) {
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e && e.checked!==arguments[1]){ e.checked=arguments[1];" +
    " e.dispatchEvent(new Event('change')); }",
    id, !!on
  );
}

async function clickByValue(driver, value) {
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(e), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await e.click();
}

async function textOf(driver, id) {
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(!e) return '';" +
    " return (e.value !== undefined && e.value !== null && e.value !== '') ? e.value : (e.textContent || '');",
    id
  );
}

// Fill the WS-Trust config page for the given operation and send. `targetToken`
// (for renew/validate/cancel) is pasted into the Target Token field.
async function configureAndSend(driver, stsUrl, op, opts) {
  opts = opts || {};
  log.info("Load the WS-Trust Test Tools page (op=" + op + ", sign=" + !!opts.sign + ", route=" + (opts.route || "back") + ", version=" + (opts.version || "default") + ").");
  await driver.get(baseUrl + "/wstrust_tools.html");
  await driver.wait(until.elementLocated(By.id("wst_sts_url")), waitTime);

  await setField(driver, "wst_sts_url", stsUrl);
  // Select the WS-Trust version first so its option-gating (Bearer key type,
  // ActAs) is applied before the rest of the fields are set.
  if (opts.version) await setField(driver, "wst_trust_version", opts.version);
  await setField(driver, "wst_operation", op);
  await setField(driver, "wst_token_type", opts.tokenType || "saml2");
  // UsernameToken credential (the mock STS accepts wstrust/wstrust).
  await setField(driver, "wst_cred_mode", "usernametoken");
  await setField(driver, "wst_username", "wstrust");
  await setField(driver, "wst_password", "wstrust");

  // Routing: "back" (default) sends through the API proxy (POST /wstrust);
  // "front" makes the browser call the STS directly (the mock STS returns
  // permissive CORS headers so this works in the suite). Both are available
  // wherever the WS-Trust jobs run (they are skipped on the backend-less static
  // deployment, where only frontend routing exists).
  var useBackend = (opts.route || "back") !== "front";
  await setChecked(driver, "wst_initiateFromBackEnd", useBackend);
  await setChecked(driver, "wst_initiateFromFrontEnd", !useBackend);

  if (op !== "issue" && opts.targetToken) {
    await setField(driver, "wst_target_token", opts.targetToken);
  }

  if (opts.sign) {
    // Enable signing FIRST so the signing section (and its "Generate Keys"
    // button) is revealed — clickByValue waits for visibility, and the section
    // is hidden while signing is off.
    await setChecked(driver, "wst_sign_request", true);
    // Generate a signing key pair. RSA-2048 keygen in pure JS can take a few
    // seconds, so allow a generous timeout (not the small generic waitTime).
    var keygenWait = Math.max(waitTime, 30000);
    await clickByValue(driver, "Generate Keys");
    // Wait on the key material itself — generateKeys() sets a transient
    // "Key pair generated." status but immediately re-signs, overwriting it.
    await driver.wait(async function () {
      var k = await textOf(driver, "wst_sp_private_key");
      return k.indexOf("PRIVATE KEY") >= 0;
    }, keygenWait, "Signing key pair was not generated.");
    // The generated request should now contain a signature.
    await driver.wait(async function () {
      var r = await textOf(driver, "wst_generated_request");
      return r.indexOf("Signature") >= 0;
    }, keygenWait, "Signed request did not contain a ds:Signature.");
  }

  log.info("Send the RequestSecurityToken.");
  await clickByValue(driver, "Send Request");

  log.info("Wait for the WS-Trust response page.");
  await driver.wait(until.urlContains("wstrust_response.html"), Math.max(waitTime, 15000));
  await driver.wait(async function () {
    var s = await textOf(driver, "wst_resp_status");
    return s.indexOf("response loaded") >= 0 || s.indexOf("could not parse") >= 0;
  }, Math.max(waitTime, 15000), "WS-Trust response was not rendered.");
}

async function wstrustActivities(driver, stsUrl, op, sign, route, version, encrypt) {
  var targetToken = null;

  // Renew/Validate/Cancel need an existing token: Issue one first and capture it.
  // The pre-step always uses backend routing (reliable) just to mint a token.
  if (op !== "issue") {
    log.info("Pre-step: Issue a token to " + op + ".");
    await configureAndSend(driver, stsUrl, "issue", { route: "back" });
    var respXml = await textOf(driver, "wst_response_xml");
    log.info("Issue RSTR (first 800 chars):\n" + (respXml || "").substring(0, 800));
    targetToken = await textOf(driver, "wst_token_xml");
    assert(targetToken && targetToken.indexOf("<") >= 0, "Pre-step Issue did not yield a token to " + op + ".");
  }

  await configureAndSend(driver, stsUrl, op, { sign: sign, targetToken: targetToken, route: route, version: version });

  var respXml = await textOf(driver, "wst_response_xml");
  var fields = await textOf(driver, "wst_fields_table");
  var tokenXml = await textOf(driver, "wst_token_xml");
  log.info("Response RSTR (first 1200 chars):\n" + (respXml || "").substring(0, 1200));

  assert(respXml && respXml.indexOf("RequestSecurityTokenResponse") >= 0,
    "Response is not a RequestSecurityTokenResponse — see the logged RSTR.");

  // Encrypted-token scenario: the STS returned an <saml:EncryptedAssertion>;
  // decrypt it on the response page with the requestor key (prefilled from the
  // signing key generated on the tools page) and confirm a plaintext assertion.
  if (encrypt) {
    var encToken = await textOf(driver, "wst_token_xml");
    assert(encToken.indexOf("EncryptedData") >= 0 || encToken.indexOf("EncryptedAssertion") >= 0,
      "Expected an encrypted token in the response, got: " + (encToken || "").slice(0, 160));
    log.info("Encrypted token received; decrypting on the response page.");
    await clickByValue(driver, "Decrypt");
    await driver.wait(async function () {
      var s = await textOf(driver, "wst_dec_status");
      return s.indexOf("Decrypted") >= 0 || s.indexOf("failed") >= 0;
    }, Math.max(waitTime, 10000), "Decrypt did not complete.");
    var decStatus = await textOf(driver, "wst_dec_status");
    var decToken = await textOf(driver, "wst_token_xml");
    assert(decToken.indexOf("Assertion") >= 0 && decToken.indexOf("EncryptedData") < 0,
      "Decrypted token is not a plaintext assertion. status=" + decStatus);
    log.info("WS-Trust encrypted-token decrypt succeeded.");
    return;
  }

  if (op === "issue" || op === "renew") {
    assert(tokenXml && (tokenXml.indexOf("Assertion") >= 0 || tokenXml.indexOf("BinarySecurityToken") >= 0),
      "No issued token in the " + op + " response.");
  } else if (op === "validate") {
    assert(fields.indexOf("valid") >= 0, "Validate response did not report a valid status. Fields: " + fields);
  } else if (op === "cancel") {
    assert(fields.indexOf("RequestedTokenCancelled") >= 0 || respXml.indexOf("RequestedTokenCancelled") >= 0,
      "Cancel response did not include RequestedTokenCancelled.");
  }

  log.info("WS-Trust " + op + (sign ? " (signed)" : "") + " round-trip succeeded.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
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
    const stsUrl = process.env.WSTRUST_STS_URL;
    const op = (process.env.WSTRUST_OP || "issue").toLowerCase();
    const sign = (process.env.WSTRUST_SIGN === "true" || process.env.WSTRUST_SIGN === "1");
    const route = (process.env.WSTRUST_ROUTE || "back").toLowerCase();
    const version = (process.env.WSTRUST_VERSION || "").trim();
    const encrypt = (process.env.WSTRUST_ENCRYPT === "true" || process.env.WSTRUST_ENCRYPT === "1");
    assert(stsUrl, "WSTRUST_STS_URL environment variable is not set.");
    assert(["issue", "renew", "validate", "cancel"].indexOf(op) >= 0, "WSTRUST_OP must be issue, renew, validate, or cancel.");
    assert(["front", "back"].indexOf(route) >= 0, "WSTRUST_ROUTE must be front or back.");
    assert(version === "" || ["1.0", "1.1", "1.2", "1.3", "1.4"].indexOf(version) >= 0, "WSTRUST_VERSION must be 1.0–1.4 (or empty for the page default).");

    // Encrypted-token scenario: ask the STS to encrypt (?encrypt=1) and sign the
    // request so it carries the requestor cert the STS encrypts to.
    var effectiveStsUrl = stsUrl, effectiveSign = sign;
    if (encrypt) {
      effectiveStsUrl = stsUrl + (stsUrl.indexOf("?") >= 0 ? "&" : "?") + "encrypt=1";
      effectiveSign = true;
    }

    await wstrustActivities(driver, effectiveStsUrl, op, effectiveSign, route, version, encrypt);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 6000 chars):\n" + (src || "").substring(0, 6000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) {
        log.error("Browser console:\n" + blogs.map(function (e) { return e.level.name + ": " + e.message; }).join("\n"));
      }
    } catch (e2) { /* ignore */ }
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('wstrust')
  .description("Run WS-Trust test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
