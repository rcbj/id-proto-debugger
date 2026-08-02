// File: ldp_vc_presentation.js
//
// ---------------------------------------------------------------------------
// OID4VP presentation of an ldp_vc credential with a bbs-2023 derived proof,
// through the four pages, against the mock Verifier.
//
// This is the format whose presentation model is genuinely different, and the
// places it differs are what this asserts:
//
//   * the unit of disclosure is the canonical STATEMENT, not a Disclosure and
//     not a claim. The statement count will not match the claim count, and a
//     pane that implies otherwise is lying about what was signed;
//   * no holder private key is needed. The derived proof IS the holder's act,
//     so a wallet that demanded a Key Binding JWT here would refuse to build
//     for want of a key the format never uses — which it did, once;
//   * the verifier's nonce is the presentation header, bound INSIDE the proof.
//     A replay is not caught by comparing a claim; the proof itself fails;
//   * two presentations of the same credential produce different bytes. That
//     unlinkability is the reason this format exists, and neither of the other
//     two can offer it.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const browserFlags = require("./browser_flags.js");
const common = require("./jwt_vc_json_common.js");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldp_vc_presentation", level: appconfig.logLevel || "info" });

if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = function (s) { return Buffer.from(s, "binary").toString("base64"); };
  globalThis.atob = function (s) { return Buffer.from(s, "base64").toString("binary"); };
}

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var verifierBase = process.env.OID4VP_VERIFIER_URL || issuerBase;
const LDP_CONFIG_ID = process.env.OID4VCI_LDP_CONFIG_ID || "IdentityCredentialLdpVc";

const { text, waitForStatus, waitForValue } = require("./wait_for");

function severeErrors(driver) {
  const logging = require("selenium-webdriver/lib/logging");
  return driver.manage().logs().get(logging.Type.BROWSER).then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

async function freshRequest() {
  const r = await fetch(verifierBase + "/oid4vp/start?format=ldp_vc", { redirect: "manual" });
  const location = r.headers.get("location");
  assert.ok(location, "the verifier should redirect the wallet with its ldp_vc request.");
  const params = {};
  location.slice(location.indexOf("?") + 1).split("&").forEach(function (pair) {
    const eq = pair.indexOf("=");
    params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
  });
  return { params: params, query: location.split("?")[1] };
}

async function test() {
  log.info("Running ldp_vc presentation. issuer=" + issuerBase + ", verifier=" + verifierBase);
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta && (meta.credential_configurations_supported || {})[LDP_CONFIG_ID],
    "this issuer offers no ldp_vc configuration \"" + LDP_CONFIG_ID + "\".");
  const held = await common.mintJwtVcJson(issuerBase, LDP_CONFIG_ID);
  assert.strictEqual(typeof held.credential, "object", "an ldp_vc credential is a JSON object.");

  const request = await freshRequest();
  const dcql = JSON.parse(request.params.dcql_query);
  assert.strictEqual(dcql.credentials[0].format, "ldp_vc",
    "the verifier should be asking for ldp_vc.");
  assert.deepStrictEqual(dcql.credentials[0].claims[0].path.slice(0, 1), ["credentialSubject"],
    "and address its claims under credentialSubject, where a W3C VC keeps them.");

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage", "--window-size=1500,1300");
  // BBS proof derivation needs Web Crypto's getRandomValues, which requires a
  // secure context — see tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    await driver.get(baseUrl + "/vc-presentation-1.html");
    await driver.executeScript(
      "window.localStorage.clear();" +
      "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
      "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);",
      JSON.stringify(held.credential), verifierBase);
    await driver.get(baseUrl + "/vc-presentation-1.html?" + request.query);
    await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
      "step 1 should read an ldp_vc request", waitTime);
    await driver.executeScript("var b=document.getElementById('vp_continue_button'); if (b) b.click();");
    await driver.sleep(800);

    log.info("=== Step 2: selection is over canonical statements ===");
    await driver.get(baseUrl + "/vc-presentation-2.html");
    await driver.wait(until.elementLocated(By.id("vp_presentation")), waitTime);
    const envelope = await waitForValue(driver, "vp_presentation",
      function (v) { return v.trim().length > 100; },
      "step 2 should derive a bbs-2023 proof", waitTime);

    const rows = await driver.executeScript(
      "return document.querySelectorAll('#vp_disclosures_table tbody tr').length;");
    assert.ok(rows > 4,
      "the table should list the credential's canonical statements; got " + rows);
    const summary = await text(driver, "vp_selection_summary");
    assert.ok(/statement/i.test(summary) && /bbs-2023/.test(summary),
      "step 2 must say the unit of disclosure is the statement. Said: " + summary);
    assert.ok(/link/i.test(summary),
      "and that presentations are unlinkable — the reason to use this format. Said: " + summary);

    const parsed = JSON.parse(envelope);
    assert.strictEqual(parsed.cryptosuite, "bbs-2023", "the envelope names the cryptosuite.");
    assert.ok(parsed.proof && parsed.disclosedStatements.length,
      "and carries the derived proof plus the statements it discloses.");
    assert.ok(parsed.disclosedStatements.length < rows,
      "a selective disclosure should send FEWER statements than the credential has: " +
      parsed.disclosedStatements.length + " of " + rows + ". Sending all of them would mean the " +
      "selection is not working.");
    log.info("[step2] OK — " + parsed.disclosedStatements.length + " of " + rows +
             " statements chosen, proof derived without a holder key.");

    log.info("=== Step 3: the verifier's verdict ===");
    await driver.executeScript("var b=document.getElementById('vp_present_button'); if (b) b.click();");
    await driver.wait(until.urlContains("vc-presentation-3.html"), waitTime,
      "presenting should reach step 3.");
    const verdict = await waitForStatus(driver, "vp_verifier_status",
      function (s) { return /ACCEPTED|REFUSED/.test(s); }, "the verifier should reach a verdict", waitTime);
    assert.ok(/ACCEPTED/.test(verdict),
      "the verifier must accept a correctly derived bbs-2023 proof. Said: " + verdict);
    const recheck = await waitForStatus(driver, "vp_recheck_status",
      function (s) { return s.trim() !== ""; }, "the wallet should re-check what it sent", waitTime);
    assert.ok(/all pass/.test(recheck), "the wallet's own checks should pass. Said: " + recheck);
    log.info("[step3] OK — " + verdict.trim().slice(0, 90));

    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0, "the pages logged browser errors:\n" + errors.join("\n"));

    log.info("=== Unlinkability, and what the verifier refuses ===");
    // A second presentation of the SAME credential must produce different bytes.
    const second = await freshRequest();
    await driver.get(baseUrl + "/vc-presentation-1.html?" + second.query);
    await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
      "step 1 should read the second request", waitTime);
    await driver.executeScript("var b=document.getElementById('vp_continue_button'); if (b) b.click();");
    await driver.sleep(800);
    await driver.get(baseUrl + "/vc-presentation-2.html");
    await driver.wait(until.elementLocated(By.id("vp_presentation")), waitTime);
    const envelope2 = await waitForValue(driver, "vp_presentation",
      function (v) { return v.trim().length > 100; }, "the second derivation", waitTime);
    assert.notStrictEqual(JSON.parse(envelope2).proof, parsed.proof,
      "two presentations of the same credential must produce DIFFERENT proof bytes. This is the " +
      "property neither dc+sd-jwt nor jwt_vc_json can offer: they replay the issuer's signature " +
      "verbatim, so two presentations are trivially linkable.");
    log.info("[unlinkable] OK — a fresh proof per presentation.");

    // Replaying the first proof into the second session must fail: the nonce is
    // the presentation header, bound inside the proof.
    const replay = await common.httpJson(second.params.response_uri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        vp_token: JSON.stringify({ identity_credential: [envelope] }),
        state: second.params.state
      }).toString()
    });
    const result = await common.httpJson(verifierBase + "/oid4vp/result/" +
      encodeURIComponent(second.params.state));
    const v = (result.body || {}).verdict || {};
    assert.strictEqual(v.ok, false,
      "a proof derived for one request must be refused by another — the nonce is inside the proof, so " +
      "this fails the proof check itself rather than a separate comparison. HTTP " + replay.status);
    log.info("[replay] OK — a proof replayed into another session is refused.");

    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>", "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) { log.error(e.stack || e.message); process.exit(1); });
