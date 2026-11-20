// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: wallet_issuance.js
//
// ---------------------------------------------------------------------------
// A CREDENTIAL COLLECTED BY THE WALLET, the way the specifications have it
// collected: the person makes an offer on the issuer's own page (iya-sts's
// portal, /portal/wallet), and the DEBUGGER's issuance pages redeem it —
// vc-issuance-1's Receive pane takes the offer, step 2 redeems the
// pre-authorized code with the Transaction Code, and the Credential Request
// carries a proof by the holder key the wallet itself generated.
//
// A shared module rather than a test, so nothing schedules it; the
// presentation jobs that need a held credential require it instead of minting
// one in node and writing it into the wallet's storage, which would skip the
// half of the wallet those jobs are not about and present a credential the
// wallet never collected.
//
// Answers what the wallet STORED: the credential, the holder key pair, and
// the parsed parts a caller asserts on.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const common = require("./jwt_vc_json_common.js");
const consentScreen = require("./consent_screen.js");
const { usernameFor } = require("./random_username.js");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "wallet_issuance",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

async function clickId(driver, By, until, id, wait) {
  log.debug("Entering clickId(). " + id);
  await driver.wait(until.elementLocated(By.id(id)), wait);
  await driver.executeScript("document.getElementById(arguments[0])" +
                             ".click();", id);
  log.debug("Leaving clickId().");
}

// `opts`: { By, until, baseUrl, issuerBase, configuration, signingAlg
// (optional), label, wait, mode, viaQrImage }. Clears the wallet's storage
// first: the credential it then holds is the one this call collected and
// nothing else.
//
// `mode` is the portal's: "cross-device" (H.2, the default) or "deferred"
// (H.3), where the Credential Response carries a transaction_id and the
// wallet collects the credential from the Deferred Credential Endpoint; the
// answer then says so (`deferred`, with the transaction_id the wallet
// showed). `viaQrImage` hands the wallet the offer as the portal's QR CODE
// — an image file chosen on step 1 — rather than as the text it encodes
// (#365).
async function collect(driver, opts) {
  log.debug("Entering collect(). configuration=" + opts.configuration);
  const By = opts.By;
  const until = opts.until;
  const wait = opts.wait;
  await common.provisionWallet(opts.issuerBase,
    { why: "the wallet that collects " + opts.configuration + " through " +
           "its own issuance pages" });
  const screen = await common.offerFromThePortalWallet(driver, {
    By: By, until: until, stsBase: opts.issuerBase,
    username: usernameFor(opts.label || "wallet"),
    mode: opts.mode || "cross-device",
    configuration: opts.configuration, signingAlg: opts.signingAlg,
    wait: wait, consentScreen: consentScreen });
  await loadUrl(driver, opts.baseUrl + "/vc-issuance-1.html");
  await waitForContent.waitForPageBundle(driver, wait);
  await driver.executeScript("localStorage.clear();");
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver, wait);
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), wait);
  let readFromQr = "";
  if (opts.viaQrImage) {
    assert.ok(/^<svg/i.test(screen.qrMarkup || ""),
      "the portal drew no SVG QR code to read: " +
      String(screen.qrMarkup).slice(0, 80));
    const svg = /xmlns=/.test(screen.qrMarkup) ? screen.qrMarkup
      : screen.qrMarkup.replace(/^<svg/i,
          '<svg xmlns="http://www.w3.org/2000/svg"');
    const file = path.join(os.tmpdir(), "offer-qr-" + process.pid + "-" +
                           Date.now() + ".svg");
    fs.writeFileSync(file, svg);
    await driver.findElement(By.id("scan_offer_image")).sendKeys(file);
    await driver.wait(async function () {
      const text = await driver.executeScript(
        "return document.getElementById('scan_status').textContent;");
      return /Read the QR code|not a Credential Offer|No QR code|not an image/
        .test(text);
    }, wait, "choosing the QR image should decode it on step 1");
    const read = await driver.executeScript(
      "return { status: document.getElementById('scan_status').textContent," +
      "  text: document.getElementById('scan_offer_input').value };");
    fs.unlinkSync(file);
    assert.ok(/^Read the QR code/.test(read.status),
      "the wallet could not read the portal's QR code: " + read.status);
    assert.strictEqual(read.text, screen.offerUri,
      "the QR code decoded to something other than the offer the portal " +
      "showed beside it");
    readFromQr = read.text;
  } else {
    await driver.executeScript(
      "document.getElementById('scan_offer_input').value = arguments[0];",
      screen.offerUri);
  }
  await clickId(driver, By, until, "scan_offer_button", wait);
  await driver.wait(until.elementLocated(By.id("start_issuance_button")),
    wait, "taking the offer should offer Start Issuance");
  await driver.sleep(1000);
  await clickId(driver, By, until, "start_issuance_button", wait);
  await driver.wait(until.urlContains("vc-issuance-2.html"), wait,
    "a pre-authorized offer goes straight to the Token Request");
  await waitForContent.waitForPageBundle(driver, wait);
  await driver.wait(until.elementLocated(By.id("vc_tx_code")), wait);
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0];" +
    "vcissuance2.onTxCodeChange();", screen.txCode);
  await clickId(driver, By, until, "vc_token_request_button", wait);
  await driver.wait(async function () {
    return !!(await driver.executeScript(
      "var e = document.getElementById('vc_access_token');" +
      "return e ? (e.value || e.textContent || '').trim() : '';"));
  }, wait, "the Transaction Code should redeem the pre-authorized code");
  await clickId(driver, By, until, "vc_approve_button", wait);
  let deferredSeen = "";
  if (opts.mode === "deferred") {
    // H.3: the Credential Response is a transaction_id, step 2 opens its
    // Deferred Issuance pane and polls on its own until the issuer is ready
    // (iya-sts: oid4vci.deferredReadyMs, 4 s by default), then opens step 3.
    await driver.wait(async function () {
      return await driver.executeScript(
        "var t = document.getElementById('vc_transaction_id');" +
        "return t && t.textContent.trim() !== '' && " +
        "  t.textContent.trim() !== '\u2014' ? t.textContent.trim() : '';") ||
        (await driver.getCurrentUrl()).indexOf("vc-issuance-3.html") >= 0;
    }, wait, "a deferred offer's Credential Response should open the " +
        "Deferred Issuance pane with its transaction_id");
    if ((await driver.getCurrentUrl()).indexOf("vc-issuance-2.html") >= 0) {
      deferredSeen = await driver.executeScript(
        "return document.getElementById('vc_transaction_id')" +
        ".textContent.trim();");
    }
  }
  await driver.wait(until.urlContains("vc-issuance-3.html"),
    opts.mode === "deferred" ? wait + 20000 : wait,
    "approving should issue the credential and open step 3");
  const stored = await driver.wait(async function () {
    return await driver.executeScript(
      "var c = localStorage.getItem('sdjwtvc_credential');" +
      "var k = localStorage.getItem('sdjwtvc_holder_private_jwk');" +
      "var p = localStorage.getItem('sdjwtvc_holder_jwk');" +
      "return c && k ? { credential: c, priv: k, pub: p } : null;");
  }, wait, "the wallet should store the credential and its holder key");
  const held = { credential: stored.credential,
                 privateJwk: JSON.parse(stored.priv),
                 publicJwk: stored.pub ? JSON.parse(stored.pub) : null };
  const text = String(held.credential).trim();
  if (text.charAt(0) === "{") {
    held.document = JSON.parse(text);
    held.format = "ldp_vc";
  } else {
    const parts = text.split("~");
    held.header = common.jsonFromB64u(parts[0].split(".")[0]);
    held.payload = common.jsonFromB64u(parts[0].split(".")[1]);
    held.format = text.indexOf("~") !== -1 ? "dc+sd-jwt" : "jwt_vc_json";
  }
  held.mode = opts.mode || "cross-device";
  held.deferredTransactionId = deferredSeen;
  held.readFromQr = readFromQr;
  log.info("[wallet] collected a " + held.format + " (" +
           opts.configuration + ", " + held.mode + (readFromQr
             ? ", offer read from its QR code" : "") + ") through the " +
           "issuance pages.");
  log.debug("Leaving collect().");
  return held;
}

// Whether the credential the wallet holds is bound to the key the WALLET
// generated: cnf.jwk for the two JWT formats, the credentialSubject's
// did:jwk for ldp_vc.
function assertBoundToTheWalletsKey(held) {
  log.debug("Entering assertBoundToTheWalletsKey().");
  const pub = held.publicJwk || held.privateJwk;
  if (held.format === "ldp_vc") {
    const subject = [].concat(held.document.credentialSubject || [])[0] || {};
    const id = String(subject.id || "");
    assert.ok(/^did:jwk:/.test(id), "the ldp_vc should name its holder by " +
              "did:jwk; it names " + id);
    const jwk = JSON.parse(Buffer.from(id.slice("did:jwk:".length)
      .split("#")[0], "base64url").toString("utf8"));
    assert.ok(jwk.x === pub.x, "the ldp_vc's holder DID must be the key the " +
              "WALLET generated");
    log.debug("Leaving assertBoundToTheWalletsKey(). ldp_vc.");
    return;
  }
  let cnf = (held.payload || {}).cnf;
  if (!cnf && held.payload && held.payload.vc) {
    cnf = held.payload.cnf;
  }
  const subjectId = held.payload && (held.payload.sub ||
      ((held.payload.vc || {}).credentialSubject || {}).id);
  assert.ok((cnf && cnf.jwk && cnf.jwk.x === pub.x) ||
            (/^did:jwk:/.test(String(subjectId || "")) &&
             JSON.parse(Buffer.from(String(subjectId).slice(8).split("#")[0],
               "base64url").toString("utf8")).x === pub.x),
    "the credential must be bound to the holder key the WALLET generated");
  log.debug("Leaving assertBoundToTheWalletsKey().");
}

module.exports = {
  collect: collect,
  assertBoundToTheWalletsKey: assertBoundToTheWalletsKey
};
