const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oidc_dynamic_client_registration',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"

// The public static-content deployments (test.idptools.com / idptools.com) have
// no api backend, and Dynamic Client Registration is a server-side operation:
// Keycloak's Trusted Hosts registration policy rejects any request carrying an
// Origin header ("Invalid origin"), so DCR cannot run from the browser there.
// Against those targets the test verifies the attempt fails rather than
// exercising the full create/read/update/delete lifecycle.
var STATIC_CONTENT_SITE_HOSTS = ["test.idptools.com", "idptools.com"];
function isStaticContentSite(url) {
  try {
    return STATIC_CONTENT_SITE_HOSTS.includes(new URL(url).hostname);
  } catch (e) {
    return false;
  }
}
var headless = true;
var waitTime = appconfig.waitTime;

// Drive the OIDC Discovery pane: enter the discovery endpoint, retrieve the
// metadata, and click "Populate Meta Data". This also fills the Dynamic Client
// Registration pane (registration_endpoint + a default client metadata document)
// from the discovery metadata.
async function populateMetadata(driver, discovery_endpoint) {
  log.info("Entering populateMetadata().");
  const oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  const btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  const btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint);
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
  log.info("Leaving populateMetadata().");
}

// Expand the Dynamic Client Registration fieldset if it is collapsed.
async function expandDcrPane(driver) {
  log.info("Expanding the Dynamic Client Registration pane.");
  const metadataField = By.id("dcr_client_metadata");
  await driver.wait(until.elementLocated(By.id("dcr_expand_button")), waitTime);
  await driver.wait(until.elementLocated(metadataField), waitTime);
  if (!(await driver.findElement(metadataField).isDisplayed())) {
    await driver.findElement(By.id("dcr_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(metadataField)), waitTime);
}

async function setFieldValue(driver, id, value) {
  const el = await driver.findElement(By.id(id));
  await el.clear();
  await el.sendKeys(value);
}

// Set a large/structured value (e.g. the client metadata JSON) directly via the
// DOM to avoid sendKeys escaping issues with braces, quotes, and newlines.
async function setFieldValueViaScript(driver, id, value) {
  await driver.executeScript(
    "document.getElementById(arguments[0]).value = arguments[1];", id, value);
}

async function getFieldValue(driver, id) {
  return await driver.findElement(By.id(id)).getAttribute("value");
}

async function clickButtonByValue(driver, value) {
  const btn = By.css('input[type="button"][value="' + value + '"], input[type="submit"][value="' + value + '"]');
  const el = await driver.findElement(btn);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

// Clear the response area, run the action, and wait for a fresh response to be
// rendered into #dcr_response_textarea, returning the parsed JSON.
async function performAndReadResponse(driver, value) {
  await driver.executeScript("document.getElementById('dcr_response_textarea').value = '';");
  await driver.executeScript("document.getElementById('display_dcr_error_class').innerHTML = '';");
  await clickButtonByValue(driver, value);
  await driver.wait(async () => {
    const v = await getFieldValue(driver, "dcr_response_textarea");
    return !!(v && v.trim().length > 0);
  }, waitTime, 'No response appeared after clicking "' + value + '".');
  const raw = await getFieldValue(driver, "dcr_response_textarea");
  log.debug(value + " response: " + raw);
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error('Response after "' + value + '" was not valid JSON: ' + raw);
  }
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
    // Optional: a bearer token presented when creating the client. Providers
    // such as Keycloak require an initial access token for registration.
    const initial_access_token = process.env.INITIAL_ACCESS_TOKEN || "";

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");

    // Open the debugger and seed the Dynamic Client Registration pane from the
    // provider's discovery metadata, then expand the pane for editing.
    log.info("Kicking off test.");
    await driver.get(baseUrl);

    log.info("Populating metadata from discovery.");
    await populateMetadata(driver, discovery_endpoint);

    await expandDcrPane(driver);

    // The Registration Endpoint and Client Metadata should be pre-filled from
    // the discovery metadata by the Populate Meta Data step above.
    const registration_endpoint = await getFieldValue(driver, "registration_endpoint");
    assert(registration_endpoint,
      "Registration Endpoint was not populated from the discovery metadata (registration_endpoint).");
    const metadata_json = await getFieldValue(driver, "dcr_client_metadata");
    assert(metadata_json && metadata_json.trim().length > 0,
      "Client Metadata was not populated from the discovery metadata.");
    log.info("registration_endpoint=" + registration_endpoint);

    if (initial_access_token) {
      await setFieldValue(driver, "dcr_initial_access_token", initial_access_token);
    }

    // Give the client a recognizable name so the update step can be verified.
    const original_client_name = "DCR Test Client " + Date.now();
    const metadata = JSON.parse(metadata_json);
    metadata.client_name = original_client_name;
    // Keycloak rejects "openid" in the requested scope on the registration
    // (create) request, so request a fixed scope that omits it.
    metadata.scope = "email profile offline_access";
    await setFieldValueViaScript(driver, "dcr_client_metadata", JSON.stringify(metadata, null, 2));

    // On the static-content deployments there is no backend proxy, and Keycloak
    // rejects browser-origin registration ("Invalid origin"), so DCR cannot run
    // from the browser at all. Verify the create attempt fails (an error is
    // surfaced) rather than registering a client, then stop — the full CRUD
    // lifecycle below only applies to the containerized/local backend build.
    if (isStaticContentSite(baseUrl)) {
      log.info("Static content site: Dynamic Client Registration is not available from the " +
               "browser (no backend proxy; the IdP rejects browser origins). Verifying the " +
               "registration attempt fails as expected.");
      await driver.executeScript("document.getElementById('dcr_response_textarea').value = '';");
      await driver.executeScript("document.getElementById('display_dcr_error_class').innerHTML = '';");
      await clickButtonByValue(driver, "Register New Client");
      await driver.wait(async () => {
        const errs = await driver.findElements(By.id("dcr_error_textarea"));
        if (errs.length === 0) {
          return false;
        }
        const v = await errs[0].getAttribute("value");
        return !!(v && v.trim().length > 0);
      }, waitTime, "Expected Dynamic Client Registration to fail from the browser on the static " +
         "site, but no error was reported.");
      log.info("Dynamic Client Registration was correctly unavailable from the browser on the static site.");
      log.info("Test completed successfully.");
      return;
    }

    // ---- CREATE -------------------------------------------------------------
    log.info("Creating (registering) a new client.");
    const created = await performAndReadResponse(driver, "Register New Client");
    assert(created.client_id,
      "Create did not return a client_id. Response: " + JSON.stringify(created));
    assert(created.registration_client_uri,
      "Create did not return a registration_client_uri (the client configuration endpoint).");
    assert(created.registration_access_token,
      "Create did not return a registration_access_token.");
    const created_client_id = created.client_id;
    log.info("Created client_id=" + created_client_id);

    // The create handler should have copied the configuration endpoint, the
    // registration access token, and the new client_id into the page.
    assert.strictEqual(await getFieldValue(driver, "registration_client_uri"),
      created.registration_client_uri,
      "Registration Client URI field was not populated after create.");
    assert.strictEqual(await getFieldValue(driver, "client_id"), created_client_id,
      "The Authorization Code flow client_id field was not updated after create.");

    // ---- READ ---------------------------------------------------------------
    log.info("Reading the client registration.");
    const read = await performAndReadResponse(driver, "Read Client");
    assert.strictEqual(read.client_id, created_client_id,
      "Read returned a different client_id than was created.");
    assert.strictEqual(read.client_name, original_client_name,
      "Read returned an unexpected client_name.");

    // ---- UPDATE -------------------------------------------------------------
    // The Read step refreshed the metadata editor with the full registration
    // (including client_id, which RFC 7592 requires on update). Change the
    // client_name and update.
    log.info("Updating the client registration.");
    const updated_client_name = original_client_name + " (updated)";
    const read_metadata = JSON.parse(await getFieldValue(driver, "dcr_client_metadata"));
    read_metadata.client_name = updated_client_name;
    await setFieldValueViaScript(driver, "dcr_client_metadata", JSON.stringify(read_metadata, null, 2));

    const updated = await performAndReadResponse(driver, "Update Client");
    assert.strictEqual(updated.client_id, created_client_id,
      "Update changed or dropped the client_id.");
    assert.strictEqual(updated.client_name, updated_client_name,
      "Update did not persist the new client_name. Response: " + JSON.stringify(updated));

    // Confirm the update by reading again.
    const reread = await performAndReadResponse(driver, "Read Client");
    assert.strictEqual(reread.client_name, updated_client_name,
      "Re-read did not reflect the updated client_name.");

    // ---- DELETE -------------------------------------------------------------
    log.info("Deleting the client registration.");
    const deleted = await performAndReadResponse(driver, "Delete Client");
    // The proxy normalizes the IdP's 204 No Content to a 200 JSON summary.
    assert(deleted.message,
      "Delete did not return a success summary. Response: " + JSON.stringify(deleted));

    // A read after delete must fail; the error is surfaced in the error pane.
    log.info("Verifying the client no longer exists.");
    await driver.executeScript("document.getElementById('display_dcr_error_class').innerHTML = '';");
    await driver.executeScript("document.getElementById('dcr_response_textarea').value = '';");
    await clickButtonByValue(driver, "Read Client");
    await driver.wait(async () => {
      const errs = await driver.findElements(By.id("dcr_error_textarea"));
      if (errs.length === 0) {
        return false;
      }
      const v = await errs[0].getAttribute("value");
      return !!(v && v.trim().length > 0);
    }, waitTime, "Reading a deleted client did not produce an error as expected.");
    log.info("Confirmed the deleted client can no longer be read.");

    log.info("Dynamic Client Registration create/read/update/delete succeeded.");
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
  .name('oidc_dynamic_client_registration')
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
