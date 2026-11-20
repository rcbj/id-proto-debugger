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
//   5. Encrypt the credential to a recipient made on the page and under a
//      password: the digest is unchanged, the issuer's signature still
//      verifies on the ENCRYPTED credential, the recipient's keys and the
//      password each decrypt it (in the page, and in node), and a wrong
//      password does not.
//   6. Compress it: the same digest, and it decompresses.
//   7. Split it into SSKR shares (2-of-3 and 2-of-3, both groups needed):
//      three shares from one group do not join, two from each do.
//   8. Send it as a multi-part UR and join it from the fountain parts
//      without part 1; the first pane reads the parts directly.
//   9. Issue with ML-DSA-44 and SSH Ed25519; each verifies.
//  10. Nothing is stored, and the panes collapse.
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
// The user guide's pictures (docs/v0.9.5/vc/). Inert unless DOC_SCREENSHOT_DIR
// is set, so an ordinary run takes none.
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

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript("document.getElementById(arguments[0])" +
                             ".value = arguments[1];", id, value);
  log.debug("Leaving setField().");
}

async function clickLegend(driver, paneId) {
  log.debug("Entering clickLegend(). " + paneId);
  var legend = await driver.wait(until.elementLocated(By.css("#" + paneId +
                                                             " legend")),
                                 stepWait);
  await driver.executeScript("arguments[0].scrollIntoView({block:" +
                             "'center'}); arguments[0].click();", legend);
  log.debug("Leaving clickLegend().");
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

    // 5. Encryption.
    var gc = paths.requireSharedModule([path.join(__dirname, "..", "client",
      "src", "gordian_envelope_crypto.js")],
    "client/src/gordian_envelope_crypto.js");
    await click(driver, "ge_example_link");
    await click(driver, "ge_issue_button");
    await waitForStatus(driver, "ge_issue_status", function (s) {
      return /^(Issued|Not issued)/.test(s);
    }, "Issue (again) should finish", stepWait);
    credential = await text(driver, "ge_issue_output");
    aliceKey = await text(driver, "ge_issuer_public_key");
    await clickLegend(driver, "pane_ge_encrypt");
    await setField(driver, "ge_enc_input", credential);
    await setField(driver, "ge_kp_seed", "");
    await click(driver, "ge_kp_button");
    await waitForStatus(driver, "ge_enc_status", function (s) {
      return /recipient|No keys/.test(s);
    }, "Make Keys should finish", stepWait);
    var prvkeys = await text(driver, "ge_enc_private_keys");
    assert.ok(/^ur:crypto-prvkeys\//.test(prvkeys), prvkeys.slice(0, 30));
    await driver.executeScript("document.getElementById('ge_enc_wrap')" +
                               ".checked = false;");
    await setField(driver, "ge_enc_key", "");
    await setField(driver, "ge_enc_password", "Tr0ub4dor&3");
    await driver.executeScript("document.getElementById('ge_enc_kdf')" +
                               ".value = 'pbkdf2';");
    await click(driver, "ge_encrypt_button");
    await waitForStatus(driver, "ge_enc_status", function (s) {
      return /^(Encrypted|Not encrypted)/.test(s);
    }, "Encrypt should finish", stepWait);
    var encSaid = await text(driver, "ge_enc_status");
    assert.ok(/1 recipient/.test(encSaid) && /pbkdf2/.test(encSaid) &&
              /unchanged/.test(encSaid), encSaid);
    var encrypted = await text(driver, "ge_enc_output");
    var encNotation = await text(driver, "ge_enc_notation");
    assert.ok(/^ENCRYPTED \[/.test(encNotation) &&
              /'hasRecipient': SealedMessage/.test(encNotation) &&
              /'hasSecret': EncryptedKey/.test(encNotation), encNotation);
    var encEnv = ge.read(encrypted);
    assert.ok(ge.verifySignatures(encEnv, ge.readPublicKey(aliceKey)).valid,
              "the issuer's signature verifies on the encrypted credential");
    assert.strictEqual(ge.toUr(ge.subjectOf(gc.decryptSubjectToRecipient(
      encEnv, gc.readPrivateKeys(prvkeys)))),
    ge.toUr(ge.subjectOf(ge.read(credential))), "in node, the page's " +
      "recipient keys open it");
    await setField(driver, "ge_enc_input", encrypted);
    await click(driver, "ge_decrypt_button");
    await waitForStatus(driver, "ge_enc_status", function (s) {
      return /^(Decrypted|Not decrypted)/.test(s);
    }, "Decrypt (password) should finish", stepWait);
    var decSaid = await text(driver, "ge_enc_status");
    assert.ok(/with the password/.test(decSaid), decSaid);
    var opened = await text(driver, "ge_enc_output");
    assert.strictEqual(ge.toUr(ge.subjectOf(ge.read(opened))),
                       ge.toUr(ge.subjectOf(ge.read(credential))),
                       "the password opens it");
    await setField(driver, "ge_enc_password", "wrong");
    await click(driver, "ge_decrypt_button");
    await waitForStatus(driver, "ge_enc_status", function (s) {
      return /^(Decrypted|Not decrypted)/.test(s);
    }, "Decrypt (wrong password) should finish", stepWait);
    assert.ok(/^Not decrypted/.test(await text(driver, "ge_enc_status")),
              "a wrong password does not");
    await setField(driver, "ge_enc_password", "");
    await click(driver, "ge_decrypt_button");
    await waitForStatus(driver, "ge_enc_status", function (s) {
      return /^(Decrypted|Not decrypted)/.test(s);
    }, "Decrypt (recipient) should finish", stepWait);
    assert.ok(/as a recipient/.test(await text(driver, "ge_enc_status")));
    log.info("PASS encrypted the credential to a page-made recipient and " +
             "a PBKDF2 password: same digest, the signature still valid, " +
             "opened by the keys and the password, not by a wrong one.");

    // 6. Compression.
    await clickLegend(driver, "pane_ge_compress");
    await setField(driver, "ge_comp_input", credential);
    await click(driver, "ge_compress_button");
    await waitForStatus(driver, "ge_comp_status", function (s) {
      return /^(Compressed|Not compressed)/.test(s);
    }, "Compress should finish", stepWait);
    var compSaid = await text(driver, "ge_comp_status");
    assert.ok(/^Compressed/.test(compSaid) && /unchanged/.test(compSaid),
              compSaid);
    var compressed = await text(driver, "ge_comp_output");
    assert.strictEqual(ge.read(compressed).kind, "compressed");
    await setField(driver, "ge_comp_input", compressed);
    await click(driver, "ge_decompress_button");
    await waitForStatus(driver, "ge_comp_status", function (s) {
      return /^(Decompressed|Not decompressed)/.test(s);
    }, "Decompress should finish", stepWait);
    assert.strictEqual(await text(driver, "ge_comp_output"), credential,
                       "it decompresses to the credential");
    log.info("PASS compressed and decompressed it at the same digest.");

    // 7. SSKR.
    await clickLegend(driver, "pane_ge_sskr");
    await setField(driver, "ge_sskr_input", credential);
    await setField(driver, "ge_sskr_groups", "2-of-3, 2-of-3");
    await setField(driver, "ge_sskr_threshold", "2");
    await click(driver, "ge_sskr_split_button");
    await waitForStatus(driver, "ge_sskr_status", function (s) {
      return /^(Split|Not split)/.test(s);
    }, "Split should finish", stepWait);
    var shares = (await text(driver, "ge_sskr_shares")).split("\n");
    assert.strictEqual(shares.length, 6, "six shares");
    await setField(driver, "ge_sskr_shares", shares.slice(0, 3).join("\n"));
    await click(driver, "ge_sskr_join_button");
    await waitForStatus(driver, "ge_sskr_status", function (s) {
      return /^(Joined|Not joined)/.test(s);
    }, "Join (one group) should finish", stepWait);
    assert.ok(/^Not joined/.test(await text(driver, "ge_sskr_status")),
              "one group's shares are not enough");
    await setField(driver, "ge_sskr_shares", [shares[0], shares[2],
                                              shares[3], shares[5]]
      .join("\n"));
    await click(driver, "ge_sskr_join_button");
    await waitForStatus(driver, "ge_sskr_status", function (s) {
      return /^(Joined|Not joined)/.test(s);
    }, "Join should finish", stepWait);
    assert.strictEqual(await text(driver, "ge_sskr_output"), credential,
                       "two shares of each group rejoin the credential");
    log.info("PASS split it 2-of-3 + 2-of-3: one group refused, two of " +
             "each rejoin it.");

    // 8. Multi-part UR.
    await clickLegend(driver, "pane_ge_parts");
    await setField(driver, "ge_parts_input", credential);
    await setField(driver, "ge_parts_max", "60");
    await setField(driver, "ge_parts_extra", "12");
    await click(driver, "ge_parts_encode_button");
    await waitForStatus(driver, "ge_parts_status", function (s) {
      return /fragment|No parts/.test(s);
    }, "Make Parts should finish", stepWait);
    var parts = (await text(driver, "ge_parts_list")).split("\n");
    assert.ok(parts.length > 13 && /^ur:envelope\/1-\d+\//.test(parts[0]),
              parts[0]);
    var subset = parts.slice(1).reverse().join("\n");
    await setField(driver, "ge_parts_list", subset);
    await click(driver, "ge_parts_decode_button");
    await waitForStatus(driver, "ge_parts_status", function (s) {
      return /^(Rebuilt|Not rebuilt)/.test(s);
    }, "Join Parts should finish", stepWait);
    var partsSaid = await text(driver, "ge_parts_status");
    assert.strictEqual(await text(driver, "ge_parts_output"), credential,
                       "rebuilt without part 1: " + partsSaid);
    await setField(driver, "ge_input", subset);
    await click(driver, "ge_read_button");
    await waitForStatus(driver, "ge_read_status", function (s) {
      return /^(Read|Not read)/.test(s);
    }, "Read (parts) should finish", stepWait);
    assert.ok(/multi-part/.test(await text(driver, "ge_read_status")),
              "the first pane reads the parts");
    log.info("PASS sent it as " + parts.length + " parts and rebuilt it " +
             "from the fountain parts without part 1.");

    // 9. ML-DSA-44 and SSH Ed25519.
    var schemes = [["mldsa44", /^VALID .*mldsa44/],
                   ["ssh-ed25519", /^VALID .*ssh-ed25519/]];
    for (var si = 0; si < schemes.length; si++) {
      await driver.executeScript("document.getElementById('ge_scheme')" +
        ".value = arguments[0]; gordianenvelopepage.showIssuerKey();",
      schemes[si][0]);
      await click(driver, "ge_issue_button");
      await waitForStatus(driver, "ge_issue_status", function (s) {
        return /^(Issued|Not issued)/.test(s);
      }, "Issue (" + schemes[si][0] + ") should finish", stepWait);
      await click(driver, "ge_read_issued_button");
      await verified(driver, schemes[si][0], schemes[si][1]);
    }
    log.info("PASS issued with ML-DSA-44 and with SSH Ed25519; each " +
             "verifies.");

    // 10. Nothing stored; a pane collapses.
    await clickLegend(driver, "pane_ge_parts");
    var hidden = await driver.executeScript("return getComputedStyle(" +
      "document.getElementById('ge_parts_fieldset')).display;");
    assert.strictEqual(hidden, "none", "the legend collapses the pane");
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
