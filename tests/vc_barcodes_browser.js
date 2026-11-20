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
//   4. Issue an AAMVA credential protecting four fields; the page DRAWS the
//      licence's PDF417 symbol (bwip-js), which is saved as an image, read
//      back through the page's image reader (@zxing/library) to the same
//      text, and verified.
//   5. The specification's own example PDF417 text, drawn by the page as a
//      symbol and read back the same way, still verifies.
//   6. ISO licences (Appendix B): the page's ISO example verifies naming
//      DG1, DG2 and DG10; a changed DG2 is invalid; one issued in the page
//      verifies from its data groups.
//   7. Status: an MRZ barcode issued with a terse status entry; Verify
//      expands it, and Fetch and Check fetches the BitstringStatusList-
//      Credential from a server this test runs (CORS), made with Digital
//      Bazaar's @digitalbazaar/vc-bitstring-status-list and signed with
//      its ecdsa-rdfc-2019 suite: REVOKED. The same list pasted, for an
//      entry that is clear: NOT REVOKED. Pasted with its bitstring changed
//      after signing: UNVERIFIED.
//   8. Nothing the page did is in localStorage or sessionStorage.
//
// Needs only the client (the status server is this process). Byte-level
// interoperability is tests/vc_barcodes_engine.js, against Digital Bazaar's
// released libraries.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
// The user guide's pictures (docs/v0.9.6/vc/). Inert unless DOC_SCREENSHOT_DIR
// is set, so an ordinary run takes none.
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

// The SVG an element holds, saved as a file the page's image input can
// read back.
async function saveSvg(driver, selector, file) {
  log.debug("Entering saveSvg(). " + selector);
  var svg = await driver.executeScript("var s = document.querySelector(" +
    "arguments[0]); return s ? s.outerHTML : '';", selector);
  assert.ok(svg, "the page draws a symbol in " + selector);
  fs.writeFileSync(file, svg.indexOf("xmlns=") === -1 ?
    svg.replace("<svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"") : svg);
  log.debug("Leaving saveSvg().");
  return file;
}

// The image read back through the page's own file input.
async function scanImage(driver, file, label) {
  log.debug("Entering scanImage(). " + label);
  await setField(driver, "vcb_barcode", "");
  await driver.executeScript("document.getElementById('vcb_image').value " +
                             "= '';");
  await driver.findElement(By.id("vcb_image")).sendKeys(file);
  var scanned = await waitForValue(driver, "vcb_barcode", function (v) {
    return v.length > 10;
  }, label + ": the page should read the drawn symbol back", stepWait);
  log.debug("Leaving scanImage().");
  return scanned;
}

async function issueAndWait(driver, label, pattern) {
  log.debug("Entering issueAndWait(). " + label);
  await click(driver, "vcb_issue_button");
  await waitForStatus(driver, "vcb_issue_status", function (s) {
    return /^Issued|^Not issued/.test(s);
  }, label + ": Issue should finish", stepWait);
  var status = await driver.executeScript("return document." +
    "getElementById('vcb_issue_status').textContent;");
  assert.ok(pattern.test(status), label + ": " + status);
  log.debug("Leaving issueAndWait().");
  return status;
}

// ---------------------------------------------------------------------------
// The status list server: one BitstringStatusListCredential, made and
// signed with Digital Bazaar's released tooling, served with CORS.
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, "..", "client", "src");
const SRC_IMAGE = path.resolve(__dirname, "..", "source-tree", "client",
                               "src");
function clientModule(name) {
  log.debug("Entering clientModule(). " + name);
  var paths = require("./module_paths.js");
  log.debug("Leaving clientModule().");
  return paths.requireSharedModule([path.join(SRC, name),
                                    path.join(SRC_IMAGE, name)],
                                   "client/src/" + name);
}

async function statusListCredential(url, setIndex) {
  log.debug("Entering statusListCredential().");
  var contexts = clientModule("jsonld_contexts.js");
  var bsl = await import("@digitalbazaar/vc-bitstring-status-list");
  var { DataIntegrityProof } = await import("@digitalbazaar/data-integrity");
  var ecdsaRdfc = (await import(
    "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite")).cryptosuite;
  var EcdsaMultikey = await import("@digitalbazaar/ecdsa-multikey");
  var jsigs = await import("jsonld-signatures");
  jsigs = jsigs.default || jsigs;
  var key = await EcdsaMultikey.generate({ curve: "P-256" });
  var did = "did:key:" + key.publicKeyMultibase;
  key.id = did + "#" + key.publicKeyMultibase;
  key.controller = did;
  var vm = await key.export({ publicKey: true, includeContext: true });
  var loader = async function loader(u) {
    log.debug("Entering loader(). " + u);
    if (u.indexOf(did) === 0) {
      log.debug("Leaving loader(). The did:key.");
      return { documentUrl: u, document: u.indexOf("#") !== -1 ? vm : {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/multikey/v1"],
        id: did, verificationMethod: [vm], assertionMethod: [vm.id] } };
    }
    if (u === "https://www.w3.org/ns/did/v1") {
      log.debug("Leaving loader(). Minimal DID context.");
      return { documentUrl: u, document: { "@context": {
        "@protected": true, id: "@id", type: "@type",
        verificationMethod: { "@id":
          "https://w3id.org/security#verificationMethod", "@type": "@id" },
        assertionMethod: { "@id":
          "https://w3id.org/security#assertionMethod", "@type": "@id",
          "@container": "@set" } } } };
    }
    log.debug("Leaving loader(). Shipped.");
    return contexts.documentLoader(u);
  };
  var list = await bsl.createList({ length: 131072 });
  list.setStatus(setIndex, true);
  var unsigned = await bsl.createCredential({ id: url, list: list,
    statusPurpose: "revocation" });
  unsigned.issuer = did;
  var signed = await jsigs.sign(unsigned, { suite: new DataIntegrityProof({
    signer: key.signer(), cryptosuite: ecdsaRdfc }),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: loader });
  log.debug("Leaving statusListCredential().");
  return signed;
}

// Serves `documents` by path, with the CORS (and Private Network Access)
// answers a page on another origin needs.
function startStatusServer(documents) {
  log.debug("Entering startStatusServer().");
  return new Promise(function (resolve) {
    var server = http.createServer(function (req, res) {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Headers", "Accept");
      res.setHeader("Access-Control-Allow-Private-Network", "true");
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }
      var doc = documents[req.url];
      if (!doc) {
        res.writeHead(404);
        res.end();
        return;
      }
      log.info("status server: GET " + req.url);
      res.writeHead(200, { "Content-Type": "application/vc" });
      res.end(JSON.stringify(doc));
    });
    server.listen(0, "127.0.0.1", function () {
      log.debug("Leaving startStatusServer(). " + server.address().port);
      resolve(server);
    });
  });
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
    // The QR encoder loads on demand (vc_barcodes_qr bundle), so the SVG is
    // drawn a moment after Issue finishes — wait for it on content.
    await driver.wait(async function () {
      return await driver.executeScript("return !!document.querySelector(" +
        "'#vcb_qr svg');");
    }, stepWait, "the page should draw the QR code");
    var svgPath = await saveSvg(driver, "#vcb_qr svg",
                                path.join(tmp, "issued.svg"));
    var scanned = await scanImage(driver, svgPath, "the issued QR code");
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
    var issuedText = await driver.executeScript("return document." +
      "getElementById('vcb_issue_output').value;");
    assert.ok(/drawn as the PDF417 symbol/.test(await driver.executeScript(
      "return document.getElementById('vcb_issue_status').textContent;")),
      "the issue status says the symbol was drawn");
    await click(driver, "vcb_read_issued_button");
    await readStatus(driver, "the issued PDF417", /^VALID/);
    rows = await driver.executeScript("return document.getElementById(" +
      "'vcb_read_result').textContent;");
    assert.ok(/DAC, DAQ, DBB, DCS/.test(rows), "the four chosen fields are " +
              "the protected ones");
    var drawn = await saveSvg(driver, "#vcb_pdf417 svg",
                              path.join(tmp, "issued-pdf417.svg"));
    var scannedPdf = await scanImage(driver, drawn, "the issued PDF417");
    assert.strictEqual(scannedPdf, issuedText, "the drawn PDF417 symbol " +
                       "carries exactly the issued licence text, ZZ " +
                       "subfile and control characters included");
    await setField(driver, "vcb_mrz", "");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the issued PDF417 read from its image",
                     /^VALID/);
    log.info("PASS issued an AAMVA barcode protecting DAC, DAQ, DBB and DCS; " +
             "the PDF417 symbol the page drew reads back to the same text " +
             "(ZZ subfile included) and verifies.");

    // 5: the specification's example PDF417 text, drawn and read back.
    await click(driver, "vcb_example_dl");
    var exampleText = await driver.executeScript("return document." +
      "getElementById('vcb_barcode').value;");
    await click(driver, "vcb_draw_pdf417_button");
    await waitForStatus(driver, "vcb_read_status", function (s) {
      return /^Drew|^Not drawn/.test(s);
    }, "Draw as PDF417 should finish", stepWait);
    var exampleSvg = await saveSvg(driver, "#vcb_read_symbol svg",
                                   path.join(tmp, "example-pdf417.svg"));
    var scannedExample = await scanImage(driver, exampleSvg,
                                         "the example PDF417");
    assert.strictEqual(scannedExample, exampleText, "the example's symbol " +
                       "reads back to the specification's text");
    assert.ok(/PDF417 symbol/.test(await driver.executeScript("return " +
      "document.getElementById('vcb_read_status').textContent;")),
      "the page says it read a PDF417 symbol");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the example PDF417 read from its image",
                     /^VALID/);
    log.info("PASS the specification's example PDF417 text, drawn by the " +
             "page and read back from the image, verifies.");

    // 6: ISO licences (Appendix B).
    await click(driver, "vcb_example_iso");
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the ISO example", /^VALID .*optical data/);
    rows = await driver.executeScript("return document.getElementById(" +
      "'vcb_read_result').textContent;");
    assert.ok(/Protected data groups\s*DG1, DG2, DG10/.test(rows),
              "the protected data groups are named: " + rows.slice(0, 400));
    assert.ok(/ISO data group 11/.test(rows), "carried in DG11");
    var isoText = await driver.executeScript("return document." +
      "getElementById('vcb_barcode').value;");
    await setField(driver, "vcb_barcode", isoText.replace(
      "DG2: hex:fbff3ec0fe7f00ff", "DG2: hex:fbff3ec0fe7f00fe"));
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the ISO example with DG2 changed",
                     /^INVALID/);
    await setField(driver, "vcb_barcode", isoText.replace(
      "DG3: BRO", "DG3: BLU"));
    await click(driver, "vcb_verify_button");
    await readStatus(driver, "the ISO example with DG3 (unprotected) " +
                     "changed", /^VALID/);
    await setField(driver, "vcb_subject_type",
                   "IsoDrivingLicenceMachineReadableInformation");
    await driver.executeScript("vcbarcodespage.onSubjectType();" +
      "document.getElementById('vcb_iso_protect_DG3').checked = true;");
    await issueAndWait(driver, "ISO", /^Issued.*DG11/);
    await click(driver, "vcb_read_issued_button");
    await readStatus(driver, "the issued ISO licence", /^VALID/);
    rows = await driver.executeScript("return document.getElementById(" +
      "'vcb_read_result').textContent;");
    assert.ok(/DG1, DG2, DG3, DG10/.test(rows), "the four chosen groups");
    log.info("PASS ISO (Appendix B): the example verifies naming DG1, DG2 " +
             "and DG10, a changed DG2 is INVALID and a changed DG3 is not; " +
             "one issued in the page protecting DG3 too verifies.");

    // 7: status, fetched from this test's server and pasted.
    var documents = {};
    var server = await startStatusServer(documents);
    try {
      var base = "http://127.0.0.1:" + server.address().port + "/lists";
      var listUrl = base + "/revocation/0";
      var listDoc = await statusListCredential(listUrl, 7);
      documents["/lists/revocation/0"] = listDoc;
      await setField(driver, "vcb_subject_type", "MachineReadableZone");
      await driver.executeScript("vcbarcodespage.onSubjectType();");
      await setField(driver, "vcb_status_base", base);
      await setField(driver, "vcb_status_index", "7");
      await issueAndWait(driver, "MRZ with status", /^Issued/);
      await click(driver, "vcb_read_issued_button");
      await setField(driver, "vcb_list_length", "131072");
      await click(driver, "vcb_verify_button");
      await readStatus(driver, "the MRZ barcode with status", /^VALID/);
      var entry = JSON.parse(await driver.executeScript("return document." +
        "getElementById('vcb_status_entry').value;"));
      assert.strictEqual(entry.statusListCredential, listUrl);
      assert.strictEqual(entry.statusListIndex, "7");
      await click(driver, "vcb_status_fetch_button");
      var verdict = await waitForStatus(driver, "vcb_status_status",
        function (v) {
          return /^(REVOKED|NOT REVOKED|UNVERIFIED|NOT CHECKED)/.test(v);
        }, "Fetch and Check should finish", stepWait);
      assert.ok(/^REVOKED/.test(verdict), "entry 7 is set: " + verdict);
      log.info("PASS status: Fetch and Check read the library-made list " +
               "from " + listUrl + ": " + verdict);
      await setField(driver, "vcb_status_entry", JSON.stringify(
        Object.assign({}, entry, { statusListIndex: "8" })));
      await setField(driver, "vcb_status_list", JSON.stringify(listDoc));
      await click(driver, "vcb_status_paste_button");
      verdict = await waitForStatus(driver, "vcb_status_status",
        function (v) {
          return /^(REVOKED|NOT REVOKED|UNVERIFIED|NOT CHECKED)/.test(v) &&
            !/^REVOKED/.test(v);
        }, "Check Pasted should finish", stepWait);
      assert.ok(/^NOT REVOKED/.test(verdict), "entry 8 is clear: " + verdict);
      var tampered = JSON.parse(JSON.stringify(listDoc));
      var other = await statusListCredential(listUrl, 8);
      tampered.credentialSubject.encodedList =
        other.credentialSubject.encodedList;
      await setField(driver, "vcb_status_list", JSON.stringify(tampered));
      await click(driver, "vcb_status_paste_button");
      verdict = await waitForStatus(driver, "vcb_status_status",
        function (v) {
          return /^UNVERIFIED/.test(v);
        }, "a tampered list should be UNVERIFIED", stepWait);
      log.info("PASS status: the pasted list reads entry 8 as NOT REVOKED; " +
               "with its bitstring changed after signing it is " +
               "UNVERIFIED.");
    } finally {
      server.close();
    }

    // 8: nothing stored.
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
