const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const { Command, Option } = require('commander');
// The SP key pair is generated per run and passed in through the environment;
// it is deliberately not stored in this repository. See common/sp_keypair.js.
const { readSpKeyPair } = require("../common/sp_keypair.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_sso',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// Poll a field's value until the predicate passes (or timeout).
async function waitForValue(driver, locator, predicate, message, timeout) {
  await driver.wait(until.elementLocated(locator), waitTime);
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return predicate(v || "");
    } catch (e) { return false; }
  }, timeout || waitTime, message);
}

async function clickByValue(driver, value) {
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var elArtifact = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(elArtifact), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", elArtifact);
  await elArtifact.click();
}

// Load the IdP metadata into the IdP Metadata pane, then wait for it to parse.
// Two modes:
//   - URL load (default): type the metadata URL and click "Load Metadata", which
//     fetches + parses the descriptor (directly, or via the API metadata proxy).
//   - File upload (metadataFile set, i.e. SAML_METADATA_FILE): push a local
//     metadata file straight into the hidden file <input>, so the document is
//     parsed entirely in the browser with no cross-origin fetch. remote-run-tests.sh
//     uses this against the deployed HTTPS site, which can't fetch the local
//     http Keycloak descriptor (mixed content / CORS).
async function loadIdpMetadata(driver, metadataUrl, metadataFile) {
  if (metadataFile) {
    log.info("Upload IdP metadata from local file: " + metadataFile);
    var fileInput = By.id("saml_metadata_file");
    await driver.wait(until.elementLocated(fileInput), waitTime);
    // The <input type=file> is display:none; Selenium sends the path to it
    // directly (file inputs don't require visibility), firing its onchange
    // handler → onMetadataFileChange() → parse.
    await driver.findElement(fileInput).sendKeys(path.resolve(metadataFile));
  } else {
    log.info("Enter metadata URL and load metadata.");
    var mdField = By.id("saml_metadata_url");
    await driver.wait(until.elementLocated(mdField), waitTime);
    await driver.findElement(mdField).clear();
    await driver.findElement(mdField).sendKeys(metadataUrl);
    await clickByValue(driver, "Load Metadata");
  }

  // Wait for the metadata to actually load + parse. The Configuration Parameters
  // fields carry sample/dummy defaults, so "endpoint is non-empty" no longer
  // proves the real IdP values were loaded — wait for the parsed status instead.
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "Metadata was not loaded/parsed.");
}

async function samlActivities(driver, metadataUrl, spEntityId, user, binding, metadataFile) {
  // The Keycloak v2 login page (PatternFly + JS modules) can take several seconds
  // to render #username on a cold browser, and POST-binding processing + request
  // signature validation add latency — so give the login/response round-trip a
  // generous timeout regardless of the small generic waitTime.
  var loginWait = Math.max(waitTime, 15000);

  log.info("Load the SAML Test Tools page (binding=" + binding + ").");
  await driver.get(baseUrl + "/saml_request.html");

  // Load + parse the IdP metadata (URL fetch, or file upload when metadataFile set).
  await loadIdpMetadata(driver, metadataUrl, metadataFile);

  // Ensure SP entityID matches the provisioned client.
  var spField = By.id("saml_sp_entity_id");
  await driver.findElement(spField).clear();
  await driver.findElement(spField).sendKeys(spEntityId);

  // Leave the NameID format at its default "(none)" — the AuthnRequest then
  // sends a <NameIDPolicy> without a Format, so Keycloak returns its default
  // NameID (rather than possibly rejecting a requested format). This exercises
  // the default "nothing chosen" behavior.

  // The SP signing key pair generated for this run. Its certificate is
  // registered on the Keycloak client, which validates the AuthnRequest
  // signature — so the request must be signed with THIS key, not one the page
  // generates for itself.
  log.info("Load this run's SP signing key pair (matches the cert registered on Keycloak).");
  var spPair = readSpKeyPair();
  var spKey = spPair.privateKey;
  var spCert = spPair.certificate;
  await driver.executeScript(
    "document.getElementById('saml_sp_private_key').value = arguments[0];" +
    "document.getElementById('saml_sp_public_key').value = arguments[1];",
    spKey, spCert
  );

  // Select the binding under test (redirect / post / artifact).
  log.info("Select binding: " + binding);
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value = arguments[0]; s.dispatchEvent(new Event('change')); }",
    binding
  );
  var selected = await driver.findElement(By.id("saml_binding")).getAttribute("value");
  assert.strictEqual(selected, binding, "Binding '" + binding + "' is not available in the selector.");

  // Send the (signed) AuthnRequest via the selected binding.
  log.info("Call IdP (" + binding + ").");
  await clickByValue(driver, "Call IdP");

  // Keycloak login (same login page as the OIDC tests).
  log.info("Log in at Keycloak.");
  var username = By.id("username");
  var password = By.id("password");
  var kcLogin = By.id("kc-login");
  await driver.wait(until.elementLocated(username), loginWait);
  await driver.wait(until.elementIsVisible(driver.findElement(username)), loginWait);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(password).clear();
  await driver.findElement(password).sendKeys(user);
  await driver.findElement(kcLogin).click();

  // Land on the response page (ACS stashed the response and redirected here).
  log.info("Wait for the SAML response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait);
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("Response") >= 0; },
    "SAMLResponse XML was not displayed.", loginWait);

  // Log the response for diagnosis (truncated). Invaluable when the IdP returns
  // a SAML error status instead of an assertion.
  var respXml = await driver.findElement(By.id("saml_resp_xml")).getAttribute("value");
  log.info("SAMLResponse (first 1500 chars):\n" + (respXml || "").substring(0, 1500));

  // Assertion present. Reject the "(no <Assertion> …)" placeholder the page
  // shows for an error/encrypted response (the bare substring "Assertion" would
  // otherwise false-positive on that placeholder).
  await waitForValue(driver, By.id("saml_assertion_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 && v.indexOf("no <Assertion") < 0; },
    "No <Assertion> in the SAMLResponse (likely a SAML error status) — see the logged response above.", loginWait);

  // Attributes tab includes a NameID row. Assert on the table's textContent
  // (readable even while the tab is the hidden one) rather than getText(), which
  // returns "" for a display:none element — otherwise this races the tab-switch
  // click taking effect / the bundle wiring its onclick handler (that race made
  // POST flake even though the row was rendered). The click still exercises the
  // tab UI, but the pass/fail no longer hinges on visibility timing.
  log.info("Check the Attributes table for a NameID row.");
  try {
    await driver.wait(async function () {
      var txt = await driver.executeScript(
        "var e=document.getElementById('saml_attrs_table'); return e ? (e.textContent || '') : '';");
      return txt.indexOf("NameID") >= 0;
    }, loginWait, "Attributes table did not include a NameID row.");
    try { await driver.findElement(By.id("tab_attrs_btn")).click(); } catch (e) { /* best-effort UI exercise */ }
  } catch (e) {
    // Dump what the page actually rendered so we can see why the NameID row is
    // missing (empty table => a render error; a table without NameID => the
    // assertion lacked one).
    var axml = await driver.findElement(By.id("saml_assertion_xml")).getAttribute("value");
    var atbl = await driver.executeScript(
      "var e=document.getElementById('saml_attrs_table'); return e ? (e.textContent || '') : '(missing)';");
    log.error("Assertion XML (first 3000 chars):\n" + (axml || "").substring(0, 3000));
    log.error("Attributes table text:\n" + (atbl || "(empty)"));
    throw e;
  }

  log.info("SAML SSO round-trip succeeded.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
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
    const metadataUrl = process.env.SAML_METADATA_URL;
    // Optional: upload a local metadata file instead of fetching a URL (used by
    // remote-run-tests.sh against the deployed site — see loadIdpMetadata).
    const metadataFile = process.env.SAML_METADATA_FILE;
    const spEntityId = process.env.SAML_SP_ENTITY_ID;
    const user = process.env.SAML_USER || "saml";
    const binding = (process.env.SAML_BINDING || "redirect").toLowerCase();
    assert(metadataUrl || metadataFile, "Set SAML_METADATA_URL (URL load) or SAML_METADATA_FILE (file upload).");
    assert(spEntityId, "SAML_SP_ENTITY_ID environment variable is not set.");
    assert(["redirect", "post", "artifact"].indexOf(binding) >= 0, "SAML_BINDING must be redirect, post, or artifact.");

    await samlActivities(driver, metadataUrl, spEntityId, user, binding, metadataFile);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    // Dump the current URL, page source, and browser console to diagnose failures
    // (an IdP error page vs the login form; a JS exception during page render).
    try {
      log.error("Current URL: " + (await driver.getCurrentUrl()));
      var src = await driver.getPageSource();
      log.error("Page source (first 8000 chars):\n" + (src || "").substring(0, 8000));
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
  .name('saml_sso')
  .description("Run SAML SSO test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
