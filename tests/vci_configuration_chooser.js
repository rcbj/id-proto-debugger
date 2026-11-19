// SPDX-License-Identifier: MIT
//
// The "Credential to request" chooser on vc-issuance-1.html.
//
// It lists the issuer's own credential configurations first, then a
// built-in example for every format this wallet can request
// (vc_formats.builtInConfiguration()), so a format the issuer does not
// advertise, or a page with no metadata retrieved yet, still offers every
// format. Choosing a built-in entry fills the Credential configuration
// section with a valid combination for that format. And Clear forgets the
// issuer's entries and keeps the built-in ones.
//
// The issuer document is PLANTED in localStorage, the way
// metadata_schema_validation.js does it, so this needs only the client.

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vci_configuration_chooser",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var waitTime = Number(process.env.TEST_WAIT_TIME_MS) > 0 ?
    Number(process.env.TEST_WAIT_TIME_MS) : (appconfig.waitTime || 2000);
var baseUrl = "https://localhost:3000";

// Every format with a built-in entry; anoncreds has none (a CL credential
// is issued against a blinded link secret, which a Credential Request has
// no member for).
const BUILT_IN = ["dc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc",
                  "vc+jwt", "vc+sd-jwt", "vc+cose", "jpt", "sd-cwt",
                  "mso_mdoc"];

// A two-entry issuer document, enough to have an issuer group.
const ISSUER_DOC = {
  credential_issuer: "https://issuer.example",
  credential_endpoint: "https://issuer.example/credential",
  credential_configurations_supported: {
    IdentityCredential: {
      format: "dc+sd-jwt", vct: "urn:example:identity",
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256"],
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"] } }
    },
    UniversityDegree: {
      format: "jwt_vc_json",
      credential_definition: {
        type: ["VerifiableCredential", "UniversityDegreeCredential"] }
    }
  }
};

async function pageBundleReady(driver) {
  log.debug("Entering pageBundleReady().");
  await waitForContent.waitForPageBundle(driver,
    "the page this test just navigated to");
  log.debug("Leaving pageBundleReady().");
}

// The chooser's groups: label -> option values. Read in the page; no logger
// there (see the root CLAUDE.md on code run by executeScript).
async function readChooser(driver) {
  log.debug("Entering readChooser().");
  var groups = await driver.executeScript(
    "var s = document.getElementById('vci_credential_configuration_select');" +
    "if (!s) return null; var out = {};" +
    "Array.prototype.forEach.call(s.querySelectorAll('optgroup')," +
    " function (g) { out[g.label] = Array.prototype.map.call(" +
    "  g.querySelectorAll('option'), function (o) { return o.value; }); });" +
    "return { groups: out, value: s.value };");
  log.debug("Leaving readChooser().");
  return groups;
}

function builtInGroup(chooser) {
  log.debug("Entering builtInGroup().");
  var name = Object.keys(chooser.groups).filter(function (k) {
    return /^Built in/.test(k);
  })[0];
  log.debug("Leaving builtInGroup().");
  return name ? chooser.groups[name] : null;
}

function issuerGroup(chooser) {
  log.debug("Entering issuerGroup().");
  log.debug("Leaving issuerGroup().");
  return chooser.groups["Offered by this issuer"] || null;
}

function assertEveryBuiltIn(chooser, when) {
  log.debug("Entering assertEveryBuiltIn().");
  assert.deepStrictEqual(builtInGroup(chooser),
    BUILT_IN.map(function (f) { return "builtin:" + f; }),
    "every format has a built-in entry " + when);
  log.debug("Leaving assertEveryBuiltIn().");
}

// Choose an option and fire the change its inline onchange listens for.
async function choose(driver, value) {
  log.debug("Entering choose(). " + value);
  await driver.executeScript(
    "var s = document.getElementById('vci_credential_configuration_select');" +
    "s.value = arguments[0];" +
    "s.dispatchEvent(new Event('change', { bubbles: true }));", value);
  log.debug("Leaving choose().");
}

async function fieldValue(driver, id) {
  log.debug("Entering fieldValue(). " + id);
  log.debug("Leaving fieldValue().");
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? e.value : null;", id);
}

async function test() {
  log.debug("Entering test().");
  var options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage", "--window-size=1500,1400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    // 1. No metadata at all: every built-in entry, and no issuer group.
    await loadUrl(driver, baseUrl + "/vc-issuance-1.html");
    await pageBundleReady(driver);
    await driver.executeScript("window.localStorage.clear();");
    await driver.navigate().refresh();
    await pageBundleReady(driver);
    await driver.wait(until.elementLocated(
      By.id("vci_credential_configuration_select")), waitTime);
    var chooser = await readChooser(driver);
    assert.strictEqual(issuerGroup(chooser), null,
      "no issuer group before any metadata is retrieved");
    assertEveryBuiltIn(chooser, "with no metadata retrieved");
    log.info("PASS with no metadata, the chooser offers all " +
             BUILT_IN.length + " formats.");

    // 2. A built-in entry fills the section with a valid combination.
    await choose(driver, "builtin:mso_mdoc");
    await driver.wait(async function () {
      return (await fieldValue(driver, "vci_format")) === "mso_mdoc";
    }, waitTime, "choosing builtin:mso_mdoc should set the format");
    assert.strictEqual(await fieldValue(driver, "vci_doctype"),
      "org.iso.18013.5.1.mDL", "an mdoc carries its doctype");
    assert.strictEqual(await fieldValue(driver,
      "vci_cryptographic_binding_methods_supported"), "cose_key");
    assert.strictEqual(await fieldValue(driver,
      "vci_credential_configuration_id"), "builtin:mso_mdoc");
    assert.strictEqual(await fieldValue(driver, "vci_vct"), "",
      "an mdoc has no vct");
    var note = await driver.findElement(By.id("vci_configuration_note"))
      .getText();
    assert.ok(/built-in example/.test(note),
      "the note says the entry is not the issuer's: " + note);
    await choose(driver, "builtin:sd-cwt");
    await driver.wait(async function () {
      return (await fieldValue(driver, "vci_format")) === "sd-cwt";
    }, waitTime, "choosing builtin:sd-cwt should set the format");
    assert.strictEqual(await fieldValue(driver, "vci_proof_types_supported"),
      "cwt", "proof types follow the format");
    assert.strictEqual(await fieldValue(driver, "vci_doctype"), "",
      "the previous format's doctype does not linger");
    log.info("PASS a built-in entry fills a valid combination.");

    // 2b. Typing a different format by hand carries the built-in entry, the
    // type members and the chooser with it.
    await driver.executeScript(
      "var f = document.getElementById('vci_format');" +
      "f.dispatchEvent(new Event('focus'));" +
      "f.value = 'mso_mdoc';" +
      "f.dispatchEvent(new Event('change', { bubbles: true }));");
    await driver.wait(async function () {
      return (await readChooser(driver)).value === "builtin:mso_mdoc";
    }, waitTime, "the chooser should follow a typed format");
    assert.strictEqual(await fieldValue(driver,
      "vci_credential_configuration_id"), "builtin:mso_mdoc");
    assert.strictEqual(await fieldValue(driver, "vci_doctype"),
      "org.iso.18013.5.1.mDL", "a typed mso_mdoc gains its doctype");
    assert.strictEqual(await fieldValue(driver,
      "vci_cryptographic_binding_methods_supported"), "cose_key");
    log.info("PASS a typed format change carries the section with it.");

    // 2c. Clear All empties the section, and the chooser names nothing
    // while still offering every format.
    await driver.findElement(By.id("config_clear_button")).click();
    await driver.wait(async function () {
      return (await readChooser(driver)).value === "";
    }, waitTime, "after Clear All the chooser should name no credential");
    chooser = await readChooser(driver);
    assertEveryBuiltIn(chooser, "after Clear All");
    assert.strictEqual(await fieldValue(driver, "vci_format"), "");

    // 2d. Restore Defaults: the chooser and the section agree again.
    await driver.findElement(By.id("config_defaults_button")).click();
    await driver.wait(async function () {
      return (await readChooser(driver)).value === "builtin:dc+sd-jwt";
    }, waitTime, "Restore Defaults should select the default format");
    assert.strictEqual(await fieldValue(driver,
      "vci_credential_configuration_id"), "builtin:dc+sd-jwt",
      "the section names the entry the chooser shows");
    assert.strictEqual(await fieldValue(driver, "vci_format"), "dc+sd-jwt");
    assert.ok(await fieldValue(driver, "vci_vct"), "an SD-JWT VC has a vct");
    assert.strictEqual(await fieldValue(driver, "vci_doctype"), "");
    log.info("PASS Clear All and Restore Defaults keep the chooser and " +
             "the section in agreement.");

    // 3. An issuer document: its entries first, the built-in ones after.
    await driver.executeScript(
      "localStorage.setItem('vci_credential_configuration_id', '');" +
      "localStorage.setItem('vci_info', arguments[0]);",
      JSON.stringify(ISSUER_DOC));
    await driver.navigate().refresh();
    await pageBundleReady(driver);
    await driver.wait(until.elementLocated(
      By.id("vci_credential_configuration_select")), waitTime);
    chooser = await readChooser(driver);
    assert.deepStrictEqual(issuerGroup(chooser),
      ["IdentityCredential", "UniversityDegree"],
      "the issuer's entries are listed");
    assertEveryBuiltIn(chooser, "beside the issuer's");
    assert.deepStrictEqual(Object.keys(chooser.groups)[0],
      "Offered by this issuer", "the issuer's group comes first");
    log.info("PASS the issuer's entries come first, the built-in ones " +
             "after.");

    // 4. Clear forgets the issuer's entries and keeps the built-in ones.
    await driver.findElement(By.id("vci_clear_button")).click();
    await driver.wait(async function () {
      var t = await driver.findElement(
        By.id("vci_signed_metadata_status")).getText();
      return /Cleared/.test(t);
    }, waitTime, "Clear should finish and say so");
    chooser = await readChooser(driver);
    assert.strictEqual(issuerGroup(chooser), null,
      "Clear removes the issuer's entries");
    assertEveryBuiltIn(chooser, "after Clear");
    log.info("PASS Clear keeps every built-in entry.");
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("vci_configuration_chooser")
  .description("The Credential to request chooser on vc-issuance-1.html: " +
      "the issuer's entries and a built-in one per format.")
  .addOption(new Option("-u, --url <url>",
      "base url of the client under test"))
  .parse(process.argv);
const cliOptions = program.opts();
if (cliOptions.url) baseUrl = String(cliOptions.url).replace(/\/$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
