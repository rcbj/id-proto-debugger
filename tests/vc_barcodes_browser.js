// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_browser.js
//
// ---------------------------------------------------------------------------
// vc-barcodes.html in Chrome (#480): VC Barcodes v1.0 read, verified and
// issued in the page.
//
//   1. The specification's two Utopia examples, loaded by their links,
//      verify: the employment authorization document (QR text + MRZ) and
//      the driver's licence (the whole PDF417 text).
//   2. The same QR barcode against a CHANGED MRZ is invalid — the point of
//      ecdsa-xi-2023.
//   3. Issue an MRZ credential with a key generated in the page; the QR code
//      the page DRAWS is saved as an image, read back through the page's own
//      image reader, and verified — so the drawn symbol, not only the text,
//      carries the credential.
//   4. Issue an AAMVA credential protecting three fields; the PDF417 text
//      with the ZZ subfile the page added verifies.
//   5. Nothing the page did is in localStorage or sessionStorage.
//
// Needs only the client. Byte-level interoperability is
// tests/vc_barcodes_engine.js, against Digital Bazaar's released library.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
// The user guide's pictures (docs/vc/). Inert unless DOC_SCREENSHOT_DIR is
// set, so an ordinary run takes none.
const docShots = require("./doc_screenshots.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_barcodes_browser",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  var e = await driver.wait(until.elementLocated(By.id(id)), stepWait);
  await driver.executeScript("arguments[0].scrollIntoView({block:" +
                             "'center'}); arguments[0].click();", e);
  log.debug("Leaving click().");
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript("var e = document.getElementById(arguments[0]);" +
    " e.value = arguments[1]; e.dispatchEvent(new Event('change'));",
    id, value);
  log.debug("Leaving setField().");
}

async function readStatus(driver, label, pattern) {
  log.debug("Entering readStatus(). " + label);
  var status = await waitForStatus(driver, "vcb_read_status", function (s) {
    return /^(VALID|INVALID|Could not)/.test(s);
  }, label + ": the page should finish verifying", stepWait);
  status = await driver.executeScript("return document.getElementById(" +
    "'vcb_read_status').textContent;");
  assert.ok(pattern.test(status), label + ": " + status);
  log.debug("Leaving readStatus().");
  return status;
}

async function test() {
  log.debug("Entering test().");
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vcb-"));
  try {
    await loadUrl(driver, baseUrl + "/vc-barcodes.html");
    await waitForContent.waitForPageBundle(driver, "vc-barcodes.html");
    await driver.executeScript("localStorage.clear(); " +
                               "sessionStorage.clear();");

    // 1 and 2: the specification's examples.
    docShots.setPrefix("vc-barcodes");
    await click(driver, "vcb_example_ead");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the QR + MRZ example", /^VALID .*optical data/);
    await docShots.snap(driver, "01-verify-qr-mrz", { ids: ["pane_vcb_read"] });
    log.info("PASS the specification's QR + MRZ example verifies.");
    var mrz = await driver.executeScript("return document.getElementById(" +
      "'vcb_mrz').value;");
    await setField(driver, "vcb_mrz", mrz.replace("JOHN", "JANE"));
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the same QR under a changed MRZ", /^INVALID/);
    await docShots.snap(driver, "02-changed-mrz-invalid",
                        { ids: ["pane_vcb_read"] });
    log.info("PASS the same barcode beside a different MRZ is INVALID.");
    await click(driver, "vcb_example_dl");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the driver's licence example", /^VALID/);
    var rows = await driver.executeScript("return document.getElementById(" +
      "'vcb_read_result').textContent;");
    assert.ok(/DAC, DAQ, DCS/.test(rows), "the protected fields are named");
    assert.ok(/registry entry 100 \(VC Barcodes\)/.test(rows),
              "the CBOR-LD registry entry is named");
    log.info("PASS the specification's driver's licence (PDF417) example " +
             "verifies, naming DAC, DAQ and DCS as protected.");

    // 3: issue an MRZ credential, and read the DRAWN QR code back.
    await setField(driver, "vcb_subject_type", "MachineReadableZone");
    await driver.executeScript("vcbarcodespage.onSubjectType();");
    await setField(driver, "vcb_curve", "P-384");
    await click(driver, "vcb_generate_button");
    await waitForValue(driver, "vcb_issuer", function (v) {
      return /^did:key:z82/.test(v);
    }, "Generate should fill in a P-384 did:key", stepWait);
    await click(driver, "vcb_issue_button");
    await waitForStatus(driver, "vcb_issue_status", function (s) {
      return /^Issued|^Not issued/.test(s);
    }, "Issue should finish", stepWait);
    var issuedStatus = await driver.executeScript("return document." +
      "getElementById('vcb_issue_status').textContent;");
    // A key Generate made for this run alone, so the private JWK in the
    // picture protects nothing.
    await docShots.snap(driver, "03-issue-mrz", { ids: ["pane_vcb_issue"] });
    assert.ok(/^Issued/.test(issuedStatus), issuedStatus);
    var issued = await driver.executeScript("return document." +
      "getElementById('vcb_issue_output').value;");
    assert.ok(/^VC1-R[0-9A-Z $%*+\-./:]+$/.test(issued), "a QR text in the " +
              "alphanumeric set: " + issued.slice(0, 40));
    var svg = await driver.executeScript("var s = document.querySelector(" +
      "'#vcb_qr svg'); return s ? s.outerHTML : '';");
    assert.ok(svg, "the page draws the QR code");
    var svgPath = path.join(tmp, "issued.svg");
    fs.writeFileSync(svgPath, svg.indexOf("xmlns=") === -1 ?
      svg.replace("<svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"") : svg);
    await setField(driver, "vcb_barcode", "");
    await driver.findElement(By.id("vcb_image")).sendKeys(svgPath);
    var scanned = await waitForValue(driver, "vcb_barcode", function (v) {
      return v.length > 10;
    }, "the page should read the drawn QR code back", stepWait);
    assert.strictEqual(scanned, issued, "the drawn QR code carries exactly " +
                       "the issued text");
    var issueMrz = await driver.executeScript("return document." +
      "getElementById('vcb_issue_mrz').value;");
    await setField(driver, "vcb_mrz", issueMrz);
    await setField(driver, "vcb_aamva", "");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the issued QR read from its image",
                     /^VALID .*optical data/);
    log.info("PASS issued an MRZ barcode on P-384; the QR code the page " +
             "drew reads back to the same text and verifies.");

    // 4: issue an AAMVA credential.
    await setField(driver, "vcb_subject_type",
                   "AamvaDriversLicenseScannableInformation");
    await driver.executeScript("vcbarcodespage.onSubjectType();" +
      "document.getElementById('vcb_protect_DBB').checked = true;");
    await click(driver, "vcb_issue_button");
    await waitForStatus(driver, "vcb_issue_status", function (s) {
      return /^Issued.*ZZA|^Not issued/.test(s);
    }, "Issue (AAMVA) should finish", stepWait);
    await click(driver, "vcb_read_issued_button");
    await readStatus(driver, "the issued PDF417", /^VALID/);
    rows = await driver.executeScript("return document.getElementById(" +
      "'vcb_read_result').textContent;");
    assert.ok(/DAC, DAQ, DBB, DCS/.test(rows), "the four chosen fields are " +
              "the protected ones");
    log.info("PASS issued an AAMVA barcode protecting DAC, DAQ, DBB and DCS; " +
             "the PDF417 text with its ZZ subfile verifies.");

    // 5: nothing stored.
    var stored = await driver.executeScript("return localStorage.length + " +
                                            "sessionStorage.length;");
    assert.strictEqual(stored, 0, "the page stores nothing (the issuer's " +
                       "private key least of all)");
    log.info("PASS nothing is in localStorage or sessionStorage.");
    log.info("vc_barcodes_browser: all checks passed.");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                             "base url of the debugger's client"));
program.addOption(new Option("-h, --headless <headless>",
                             "run Chrome headless (default true)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) {
  baseUrl = opts.url;
  log.info("Setting url to " + baseUrl);
}
if (opts.headless === "false") headless = false;

test().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
