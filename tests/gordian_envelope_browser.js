// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope_browser.js
//
// ---------------------------------------------------------------------------
// gordian-envelope.html in Chrome (#480):
//
//   1. Load bc-envelope's Certificate of Completion example, issue it, and
//      read it back: the issuer's signature verifies and the notation shows
//      the claims.
//   2. Present it with four claims disclosed: the presentation's root
//      digest is the credential's, nine claims are ELIDED, and the
//      signature verifies on the presentation read back from its UR —
//      checked again in node, by gordian_envelope.js, outside the page.
//   3. Another issuer's key does not verify it.
//   4. Issue with salted claims on Ed25519; it verifies.
//   5. Nothing is stored.
//
// Needs only the client. Byte-level conformance is
// tests/gordian_envelope_engine.js.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
// The user guide's pictures (docs/vc/). Inert unless DOC_SCREENSHOT_DIR is
// set, so an ordinary run takes none.
const docShots = require("./doc_screenshots.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus } = require("./wait_for");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "gordian_envelope_browser",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;
const ge = paths.requireSharedModule([path.join(__dirname, "..", "client",
  "src", "gordian_envelope.js")], "client/src/gordian_envelope.js");

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  var e = await driver.wait(until.elementLocated(By.id(id)), stepWait);
  await driver.executeScript("arguments[0].scrollIntoView({block:" +
                             "'center'}); arguments[0].click();", e);
  log.debug("Leaving click().");
}

async function text(driver, id) {
  log.debug("Entering text(). " + id);
  log.debug("Leaving text().");
  return driver.executeScript("var e=document.getElementById(arguments[0]);" +
    "return e ? (e.value !== undefined && e.tagName !== 'DIV' && " +
    "e.tagName !== 'PRE' ? e.value : e.textContent) : '';", id);
}

async function verified(driver, label, pattern) {
  log.debug("Entering verified(). " + label);
  await waitForStatus(driver, "ge_verify_status", function (s) {
    return /^(VALID|INVALID)/.test(s);
  }, label, stepWait);
  var s = await text(driver, "ge_verify_status");
  assert.ok(pattern.test(s), label + ": " + s);
  log.debug("Leaving verified().");
  return s;
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
  try {
    await loadUrl(driver, baseUrl + "/gordian-envelope.html");
    await waitForContent.waitForPageBundle(driver, "gordian-envelope.html");
    await driver.executeScript("localStorage.clear(); " +
                               "sessionStorage.clear();");

    // 1. Issue the example and read it back.
    docShots.setPrefix("gordian-envelope");
    await click(driver, "ge_example_link");
    await click(driver, "ge_issue_button");
    await waitForStatus(driver, "ge_issue_status", function (s) {
      return /^(Issued|Not issued)/.test(s);
    }, "Issue should finish", stepWait);
    var credential = await text(driver, "ge_issue_output");
    assert.ok(/^ur:envelope\//.test(credential), credential.slice(0, 40));
    var aliceKey = await text(driver, "ge_issuer_public_key");
    await docShots.snap(driver, "01-issue", { ids: ["pane_ge_issue"] });
    await click(driver, "ge_read_issued_button");
    await verified(driver, "the issued example", /^VALID/);
    await docShots.snap(driver, "02-read-and-verify",
                        { ids: ["pane_ge_read"] });
    var notation = await text(driver, "ge_notation");
    assert.ok(/"firstName": "James"/.test(notation) &&
              /'isA': "Certificate of Completion"/.test(notation),
              "the notation shows the claims");
    log.info("PASS issued bc-envelope's example in the page; its Schnorr " +
             "signature verifies.");

    // 2. Present four claims.
    await driver.executeScript(
      "var boxes = document.querySelectorAll('#ge_claims input');" +
      "for (var i = 0; i < boxes.length; i++) {" +
      "  var t = boxes[i].parentNode.textContent;" +
      "  boxes[i].checked = /\"firstName\"|\"lastName\"|'isA'|'issuer'/" +
      "    .test(t);" +
      "}");
    await click(driver, "ge_present_button");
    await waitForStatus(driver, "ge_present_status", function (s) {
      return /root digest/.test(s);
    }, "Present should finish", stepWait);
    var said = await text(driver, "ge_present_status");
    assert.ok(/unchanged/.test(said) && /4 claim/.test(said), said);
    var presentation = await text(driver, "ge_presentation");
    var shown = await text(driver, "ge_presentation_notation");
    await docShots.snap(driver, "03-present", { ids: ["pane_ge_read"] });
    assert.ok(/ELIDED \(8\)/.test(shown) && !/"photo"/.test(shown),
              "eight claims elided, the photo among them: " + shown);
    await click(driver, "ge_read_presentation_button");
    await verified(driver, "the presentation", /^VALID/);
    var inNode = ge.verifySignatures(ge.read(presentation),
                                     ge.readPublicKey(aliceKey));
    assert.ok(inNode.valid, "gordian_envelope.js, in node, verifies the " +
              "page's presentation too");
    assert.strictEqual(Buffer.from(ge.read(presentation).digest)
      .toString("hex"), Buffer.from(ge.read(credential).digest)
      .toString("hex"), "the presentation's root is the credential's");
    log.info("PASS presented four claims: eight elided, the same root " +
             "digest, the signature valid in the page and in node.");

    // 3. Another key.
    await click(driver, "ge_generate_button");
    var other = await text(driver, "ge_issuer_public_key");
    await driver.executeScript("document.getElementById('ge_public_key')" +
                               ".value = arguments[0];", other);
    await click(driver, "ge_verify_button");
    await verified(driver, "another issuer's key", /^INVALID/);
    log.info("PASS another issuer's key does not verify it.");

    // 4. Salted, Ed25519.
    await driver.executeScript("document.getElementById('ge_scheme')" +
      ".value = 'ed25519'; document.getElementById('ge_salt')" +
      ".checked = true;");
    await click(driver, "ge_issue_button");
    await waitForStatus(driver, "ge_issue_status", function (s) {
      return /^(Issued|Not issued)/.test(s);
    }, "Issue (salted) should finish", stepWait);
    await click(driver, "ge_read_issued_button");
    await verified(driver, "the salted Ed25519 credential", /^VALID .*ed25519/);
    var claimsText = await text(driver, "ge_claims");
    assert.ok(/salted/.test(claimsText), "the claims are shown as salted");
    log.info("PASS issued with salted claims on Ed25519; it verifies.");

    // 5. Nothing stored.
    var stored = await driver.executeScript("return localStorage.length + " +
                                            "sessionStorage.length;");
    assert.strictEqual(stored, 0, "the page stores nothing");
    log.info("PASS nothing is in localStorage or sessionStorage.");
    log.info("gordian_envelope_browser: all checks passed.");
  } finally {
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
