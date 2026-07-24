const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_encrypted_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

async function waitForValue(driver, locator, predicate, message, timeout) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(async function () {
    try { var v = await driver.findElement(locator).getAttribute("value"); return predicate(v || ""); }
    catch (e) { return false; }
  }, timeout || waitTime, message);
}
async function textOf(driver, id) {
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(!e) return '';" +
    " return (e.value !== undefined && e.value !== null && e.value !== '') ? e.value : (e.textContent || '');", id);
}
async function clickByValue(driver, value) {
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(e), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await e.click();
}

async function loadIdpMetadata(driver, metadataUrl, metadataFile) {
  if (metadataFile) {
    log.info("Upload IdP metadata from local file: " + metadataFile);
    var fileInput = By.id("saml_metadata_file");
    await driver.wait(until.elementLocated(fileInput), waitTime);
    await driver.findElement(fileInput).sendKeys(path.resolve(metadataFile));
  } else {
    log.info("Enter metadata URL and load metadata.");
    var mdField = By.id("saml_metadata_url");
    await driver.wait(until.elementLocated(mdField), waitTime);
    await driver.findElement(mdField).clear();
    await driver.findElement(mdField).sendKeys(metadataUrl);
    await clickByValue(driver, "Load Metadata");
  }
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; }, "Metadata was not loaded/parsed.");
}

async function encryptedSsoActivities(driver, metadataUrl, spEntityId, user, metadataFile) {
  var loginWait = Math.max(waitTime, 15000);
  log.info("Load the SAML Test Tools page (encrypted SP, POST binding).");
  await driver.get(baseUrl + "/saml_tools.html");
  await loadIdpMetadata(driver, metadataUrl, metadataFile);

  // Use the ENCRYPTED SP client's entityID and the fixed SP key pair (its cert
  // is registered on Keycloak as both the signing AND the encryption cert).
  await driver.findElement(By.id("saml_sp_entity_id")).clear();
  await driver.findElement(By.id("saml_sp_entity_id")).sendKeys(spEntityId);
  var spKey = fs.readFileSync(path.join(__dirname, "fixtures", "sp-key.pem"), "utf8");
  var spCert = fs.readFileSync(path.join(__dirname, "fixtures", "sp-cert.pem"), "utf8");
  await driver.executeScript(
    "document.getElementById('saml_sp_private_key').value = arguments[0];" +
    "document.getElementById('saml_sp_public_key').value = arguments[1];", spKey, spCert);

  // POST binding (encrypted assertion is returned to the ACS via POST).
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value='post'; s.dispatchEvent(new Event('change')); }");

  log.info("Call IdP (POST, encrypted client).");
  await clickByValue(driver, "Call IdP");

  log.info("Log in at Keycloak.");
  await driver.wait(until.elementLocated(By.id("username")), loginWait);
  await driver.wait(until.elementIsVisible(driver.findElement(By.id("username"))), loginWait);
  await driver.findElement(By.id("username")).clear();
  await driver.findElement(By.id("username")).sendKeys(user);
  await driver.findElement(By.id("password")).clear();
  await driver.findElement(By.id("password")).sendKeys(user);
  await driver.findElement(By.id("kc-login")).click();

  log.info("Wait for the SAML response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait);
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("Response") >= 0; }, "SAMLResponse XML was not displayed.", loginWait);

  // The response must carry an EncryptedAssertion (no plaintext Assertion).
  var respXml = await textOf(driver, "saml_resp_xml");
  log.info("SAMLResponse (first 1200 chars):\n" + (respXml || "").substring(0, 1200));
  assert(respXml.indexOf("EncryptedAssertion") >= 0 || respXml.indexOf("EncryptedData") >= 0,
    "Response did not contain an EncryptedAssertion — is saml.encrypt=true on the client?");

  // Guard against a stale client bundle that predates the decryption feature.
  var hasFn = await driver.executeScript(
    "return typeof (window.saml_response && window.saml_response.decryptAssertion) === 'function';");
  assert(hasFn, "saml_response.decryptAssertion is not defined — the client bundle is stale; rebuild the client image.");

  // Decrypt on the response page with the SP private key (what a user would do;
  // set it explicitly rather than relying on the localStorage prefill).
  log.info("Decrypt the EncryptedAssertion on the response page.");
  await driver.executeScript(
    "var e=document.getElementById('saml_dec_key'); if(e){ e.value = arguments[0]; }", spKey);
  var keyLen = await driver.executeScript(
    "var e=document.getElementById('saml_dec_key'); return e ? (e.value || '').length : 0;");
  assert(keyLen > 0, "Failed to set the decryption key field (saml_dec_key).");
  // Fire the Decrypt button via a scripted element.click() rather than a native
  // Selenium click. The button sits low on a tall page; in the headless
  // viewport the synthetic mouse click intermittently lands off-target and never
  // triggers the onclick (no intercept error is raised), so decryptAssertion()
  // silently never runs (~5/8 runs under load). A scripted click still dispatches
  // to the real button's onclick="…decryptAssertion()" binding — it just isn't
  // subject to coordinate/scroll geometry.
  var clicked = await driver.executeScript(
    "var b=document.querySelector(\"input[value='Decrypt']\"); if(!b) return false;" +
    " b.scrollIntoView({block:'center'}); b.click(); return true;");
  assert(clicked, "Could not find the Decrypt button to click.");

  // Wait for a TERMINAL decrypt status written by decryptAssertion() after the
  // click. We must NOT key off the assertion-XML pane or the pre-click status:
  //   - before decrypting, saml_assertion_xml holds the note
  //     "(no <Assertion> — …)", which contains the word "Assertion" and no
  //     "EncryptedData", so an assertion-text check passes spuriously; and
  //   - render() pre-seeds the status with "…paste/confirm the recipient key…",
  //     which contains "paste".
  // Matching either lets the wait return before the (synchronous) click handler
  // has updated the DOM, so the decStatus assert below then reads the stale
  // render message and fails intermittently under load. Only the outcomes
  // decryptAssertion() sets are terminal.
  try {
    await driver.wait(async function () {
      var s = await textOf(driver, "saml_dec_status");
      return /Decrypted|Decryption failed|No <xenc/i.test(s);
    }, loginWait, "decrypt-wait");
  } catch (e) {
    throw new Error("Decrypt did not complete. dec_status=\"" + (await textOf(driver, "saml_dec_status")) + "\"");
  }
  var decStatus = await textOf(driver, "saml_dec_status");
  assert(decStatus.indexOf("Decrypted") >= 0, "Decryption did not succeed: " + decStatus);

  // The decrypted plaintext assertion should now be shown, and its attributes
  // (incl. NameID) rendered.
  var assertionXml = await textOf(driver, "saml_assertion_xml");
  assert(assertionXml.indexOf("Assertion") >= 0 && assertionXml.indexOf("EncryptedData") < 0,
    "Decrypted assertion not shown. status=" + decStatus + " assertion=" + assertionXml.slice(0, 200));
  await driver.wait(async function () {
    var t = await driver.executeScript(
      "var e=document.getElementById('saml_attrs_table'); return e ? (e.textContent || '') : '';");
    return t.indexOf("NameID") >= 0;
  }, loginWait, "Attributes table (from the decrypted assertion) did not include a NameID row.");

  log.info("SAML EncryptedAssertion decryption succeeded.");
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

  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).setLoggingPrefs(loggingPrefs).build();
  try {
    const metadataUrl = process.env.SAML_METADATA_URL;
    const metadataFile = process.env.SAML_METADATA_FILE;
    const spEntityId = process.env.SAML_ENC_SP_ENTITY_ID;
    const user = process.env.SAML_USER || "saml";
    assert(metadataUrl || metadataFile, "Set SAML_METADATA_URL or SAML_METADATA_FILE.");
    assert(spEntityId, "SAML_ENC_SP_ENTITY_ID environment variable is not set.");
    await encryptedSsoActivities(driver, metadataUrl, spEntityId, user, metadataFile);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0, 8000));
      var blogs = await driver.manage().logs().get("browser");
      if (blogs && blogs.length) log.error("Browser console:\n" + blogs.map(function (e) { return e.level.name + ": " + e.message; }).join("\n"));
    } catch (e2) { /* ignore */ }
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('saml_encrypted_sso')
  .description("Run SAML EncryptedAssertion decryption test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
