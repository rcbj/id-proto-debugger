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
var log = bunyan.createLogger({ name: 'saml_logout',
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
  var elBtn = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(elBtn), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", elBtn);
  await elBtn.click();
}

async function selectBinding(driver, binding) {
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value = arguments[0]; s.dispatchEvent(new Event('change')); }",
    binding
  );
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
  log.debug("Entering loadIdpMetadata().");
  if (metadataFile) {
    log.info("Upload IdP metadata from local file: " + metadataFile);
    var fileInput = By.id("saml_metadata_file");
    await driver.wait(until.elementLocated(fileInput), waitTime);
    // The <input type=file> is display:none; Selenium sends the path to it
    // directly (file inputs don't require visibility), firing its onchange
    // handler → onMetadataFileChange() → parse.
    await driver.findElement(fileInput).sendKeys(path.resolve(metadataFile));
  } else {
    var mdField = By.id("saml_metadata_url");
    await driver.wait(until.elementLocated(mdField), waitTime);
    await driver.findElement(mdField).clear();
    await driver.findElement(mdField).sendKeys(metadataUrl);
    await clickByValue(driver, "Load Metadata");
  }
  // Wait for the real metadata to load + parse (the config fields carry sample
  // defaults, so "non-empty" no longer proves the IdP values were populated).
  await waitForValue(driver, By.id("saml_metadata_status"),
    function (v) { return v.indexOf("Loaded and parsed") >= 0; },
    "Metadata was not loaded/parsed.");
  log.debug("Leaving loadIdpMetadata().");
}

// Perform an SP-initiated SSO login. This establishes the Keycloak SSO session
// (session cookie) AND — when the response page renders — saves the NameID /
// SessionIndex to localStorage, both of which the subsequent LogoutRequest needs.
async function ssoLogin(driver, metadataUrl, spEntityId, user, binding, loginWait, metadataFile) {
  log.debug("Entering ssoLogin().");
  log.info("SLO test — step 1: SSO login (binding=" + binding + ").");
  await driver.get(baseUrl + "/saml_request.html");

  // Load + parse the IdP metadata (URL fetch, or file upload when metadataFile set).
  await loadIdpMetadata(driver, metadataUrl, metadataFile);

  var spField = By.id("saml_sp_entity_id");
  await driver.findElement(spField).clear();
  await driver.findElement(spField).sendKeys(spEntityId);

  // This run's SP signing key pair (its cert is registered on the Keycloak
  // client, so both the AuthnRequest and the LogoutRequest signatures validate).
  var spPair = readSpKeyPair();
  var spKey = spPair.privateKey;
  var spCert = spPair.certificate;
  await driver.executeScript(
    "document.getElementById('saml_sp_private_key').value = arguments[0];" +
    "document.getElementById('saml_sp_public_key').value = arguments[1];",
    spKey, spCert
  );

  await selectBinding(driver, binding);
  await clickByValue(driver, "Call IdP");

  log.info("Log in at Keycloak.");
  var username = By.id("username");
  await driver.wait(until.elementLocated(username), loginWait);
  await driver.wait(until.elementIsVisible(driver.findElement(username)), loginWait);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  await driver.findElement(By.id("password")).clear();
  await driver.findElement(By.id("password")).sendKeys(user);
  await driver.findElement(By.id("kc-login")).click();

  // Land on the response page; the assertion render persists the subject for SLO.
  await driver.wait(until.urlContains("saml_response.html"), loginWait);
  await waitForValue(driver, By.id("saml_assertion_xml"),
    function (v) { return v.indexOf("Assertion") >= 0 && v.indexOf("no <Assertion") < 0; },
    "SSO did not yield an assertion — cannot exercise logout.", loginWait);
  log.info("SSO login complete; Keycloak session established.");
  log.debug("Leaving ssoLogin().");
}

async function samlLogout(driver, metadataUrl, spEntityId, user, binding, metadataFile) {
  log.debug("Entering samlLogout().");
  // Keycloak's login + logout round-trips can take several seconds on a cold
  // browser, so give the navigations a generous timeout.
  var loginWait = Math.max(waitTime, 15000);

  await ssoLogin(driver, metadataUrl, spEntityId, user, binding, loginWait, metadataFile);

  // ---- step 2: Single Logout ----
  log.info("SLO test — step 2: return to SAML Test Tools and trigger Single Logout.");
  await driver.get(baseUrl + "/saml_request.html");
  await driver.wait(until.elementLocated(By.id("saml_binding")), waitTime);
  await driver.executeScript(
    "var s=document.getElementById('saml_binding'); if(s){ s.value = arguments[0]; }", binding);

  // Wait for singleLogout()'s preconditions to be restored from localStorage —
  // otherwise it bails (without navigating). The SLO endpoint checked depends on
  // the binding (POST uses saml_slo_post; redirect uses saml_slo_redirect).
  await driver.wait(async function () {
    var d = await driver.executeScript(
      "return {" +
      " nameid: (localStorage.getItem('saml_last_nameid')||'')," +
      " sloPost: ((document.getElementById('saml_slo_post')||{}).value||'')," +
      " sloRedirect: ((document.getElementById('saml_slo_redirect')||{}).value||'')," +
      " priv: (((document.getElementById('saml_sp_private_key')||{}).value||'').length>0)," +
      " version: ((document.getElementById('saml_version')||{}).value||'') };");
    var slo = (binding === 'post') ? d.sloPost : d.sloRedirect;
    return d.nameid && slo && d.priv && d.version === '2.0';
  }, loginWait, "Logout preconditions not restored (NameID / SLO endpoint / SP key / version).");

  var pre = await driver.executeScript(
    "return { nameid: (localStorage.getItem('saml_last_nameid')||'(none)')," +
    " slo: ((document.getElementById(arguments[0]==='post'?'saml_slo_post':'saml_slo_redirect')||{}).value||'(none)') };", binding);
  log.info("Logout preconditions ready (" + binding + "): NameID=" + pre.nameid + " SLO=" + pre.slo);

  // Trigger logout with a SCRIPTED click on the button (which fires its real
  // onclick handler). A Selenium native .click() here is intermittently swallowed
  // — the on-load auto-build re-renders the Generated AuthnRequest field, so the
  // button can shift between click-point computation and dispatch and the handler
  // never fires (leaving the browser on saml_request.html). element.click() in the
  // page is immune to that and reliably invokes singleLogout().
  var lb = await driver.findElement(By.xpath("//input[contains(@onclick,'singleLogout')]"));
  await driver.wait(until.elementIsVisible(lb), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' }); arguments[0].click();", lb);

  // ---- step 3: verify the LogoutResponse ----
  log.info("Wait for the LogoutResponse on the response page.");
  await driver.wait(until.urlContains("saml_response.html"), loginWait);
  await waitForValue(driver, By.id("saml_resp_xml"),
    function (v) { return v.indexOf("LogoutResponse") >= 0; },
    "LogoutResponse XML was not displayed.", loginWait);

  var respXml = await driver.findElement(By.id("saml_resp_xml")).getAttribute("value");
  log.info("LogoutResponse (first 1200 chars):\n" + (respXml || "").substring(0, 1200));

  // The Details table must identify the message as a LogoutResponse and report a
  // Success status. Read textContent (works regardless of which tab is visible).
  try {
    await driver.wait(async function () {
      var txt = await driver.executeScript(
        "var e=document.getElementById('saml_resp_details'); return e ? (e.textContent || '') : '';");
      return txt.indexOf("LogoutResponse") >= 0 && txt.indexOf("Success") >= 0;
    }, loginWait, "LogoutResponse did not report a Success status in the Details table.");
  } catch (e) {
    var details = await driver.executeScript(
      "var e=document.getElementById('saml_resp_details'); return e ? (e.textContent || '') : '(missing)';");
    log.error("Details table text:\n" + (details || "(empty)"));
    throw e;
  }

  log.info("SAML Single Logout succeeded (LogoutResponse status Success).");
  log.debug("Leaving samlLogout().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) { options.addArguments("--headless"); }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages under coverage.
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
    // SLO front-channel binding: redirect (default) or post. Both are reliable.
    const binding = (process.env.SAML_BINDING || "redirect").toLowerCase();
    assert(metadataUrl || metadataFile, "Set SAML_METADATA_URL (URL load) or SAML_METADATA_FILE (file upload).");
    assert(spEntityId, "SAML_SP_ENTITY_ID environment variable is not set.");
    assert(["redirect", "post"].indexOf(binding) >= 0, "SAML_BINDING must be redirect or post for logout.");

    await samlLogout(driver, metadataUrl, spEntityId, user, binding, metadataFile);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
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
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('saml_logout')
  .description("Run SAML Single Logout test.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });

program.parse(process.argv).opts();

test();
