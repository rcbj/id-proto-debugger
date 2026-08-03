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

// ---------------------------------------------------------------------------
// Getting here the way a USER does, which is a different question from whether
// the protocol works.
//
// freshRequest() below builds "/oid4vp/start?format=ldp_vc" by hand. That made
// every other assertion in this file meaningful and, on its own, proved nothing
// about reachability: for as long as this suite has passed, there was no route
// through the pages that produced that URL. Presentation step 0 linked to the
// verifier with no format at all, so the verifier asked for its default
// (dc+sd-jwt), the wallet answered with the ldp_vc it held, and the verifier
// reported a malformed presentation — "this has 1 part(s)" — because it was
// splitting a JSON object on "~". The format is the VERIFIER's choice, so the
// wallet cannot fix it after the fact; the only place it can be made is the link
// that starts the presentation.
//
// So this section constructs no URLs. It reads step 0's own links out of the
// DOM, follows them, and lets the verifier hand the request back.
// ---------------------------------------------------------------------------
async function startsFromTheWalletsOwnPages(driver, held) {
  log.info("=== Starting a presentation from the wallet's pages, not a hand-built URL ===");
  await driver.get(baseUrl + "/vc-presentation-0.html");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);",
    JSON.stringify(held.credential), verifierBase);
  await driver.get(baseUrl + "/vc-presentation-0.html");
  await driver.sleep(900);

  // Step 0 navigates from a click handler rather than an anchor, so the only
  // honest way to read where a flow goes is to take it. Each of the three must
  // name the format: a holder should not have to know that only one of the
  // buttons happens to work with the credential they hold.
  var flows = ["same-device", "same-device-signed", "cross-device"];
  for (var i = 0; i < flows.length; i++) {
    await driver.get(baseUrl + "/vc-presentation-0.html");
    await driver.sleep(700);
    var buttonId = "vp_usecase_" + flows[i];
    var exists = await driver.executeScript(
      "return !!document.getElementById(arguments[0]);", buttonId);
    assert.ok(exists, "step 0 should offer the " + flows[i] + " flow (#" + buttonId + ").");
    await driver.executeScript("document.getElementById(arguments[0]).click();", buttonId);
    // Where a flow ENDS UP differs: the same-device one stops at the verifier's
    // page, while the other two hit /oid4vp/start, which redirects straight on
    // to the wallet with the finished request. So the URL carries format= for
    // some and not others, and the question that actually matters is the same
    // for all three — did the verifier ask for ldp_vc?
    await driver.wait(async function () {
      var u = await driver.getCurrentUrl();
      return /oid4vp/.test(u) || /vc-presentation-1\.html/.test(u);
    }, waitTime, "the " + flows[i] + " flow should leave step 0.");
    var landed = await driver.getCurrentUrl();
    var askedFor = "";
    if (/[?&]format=([^&]+)/.test(landed)) {
      askedFor = decodeURIComponent(/[?&]format=([^&]+)/.exec(landed)[1]);
    } else if (/dcql_query=/.test(landed)) {
      askedFor = JSON.parse(decodeURIComponent(/[?&]dcql_query=([^&]+)/.exec(landed)[1]))
        .credentials[0].format;
    } else {
      // Landed on the wallet with the request already read (or by reference):
      // ask the page what arrived.
      await driver.sleep(1200);
      askedFor = await driver.executeScript(
        "var r = JSON.parse(window.localStorage.getItem('sdjwtvp_request') || '{}');" +
        "var q = (r.params || {}).dcql_query;" +
        "try { return q ? (JSON.parse(q).credentials[0].format || '') : ''; } catch (e) { return ''; }");
    }
    assert.strictEqual(askedFor, "ldp_vc",
      "the " + flows[i] + " flow must make the verifier ask for ldp_vc, the format this wallet holds. " +
      "Otherwise it asks for its default (dc+sd-jwt) and the wallet has nothing to answer with. " +
      "Landed on: " + landed);
    log.info("[route] OK — " + flows[i] + " → the verifier asks for " + askedFor + ".");
  }

  // Take the same-device one all the way, and let the verifier's own page decide
  // what to put in the request. Nothing below is constructed by this test.
  await driver.get(baseUrl + "/vc-presentation-0.html");
  await driver.sleep(700);
  await driver.executeScript("document.getElementById('vp_usecase_same-device').click();");
  await driver.wait(async function () {
    return /oid4vp\/verifier/.test(await driver.getCurrentUrl());
  }, waitTime, "the same-device flow should land on the verifier's page.");
  await driver.wait(until.elementLocated(By.id("present_by_value")), waitTime,
    "the verifier's page should offer to start a presentation.");
  var carried = await driver.executeScript(
    "return document.getElementById('present_by_value').getAttribute('href');");
  assert.ok(/format=ldp_vc/.test(carried),
    "the verifier page must carry the format into its own links, or clicking through drops it and the " +
    "request reverts to dc+sd-jwt. Got: " + carried);
  assert.ok(await driver.executeScript(
    "return !!document.getElementById('present_ldp_vc');"),
    "and it should offer an ldp_vc option at all — for a long time it offered dc+sd-jwt and " +
    "jwt_vc_json only, so a holder arriving directly had no way to ask for this format.");

  await driver.findElement(By.id("present_by_value")).click();
  await driver.wait(until.urlContains("vc-presentation-1.html"), waitTime,
    "the verifier should hand the request back to the wallet.");
  await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
    "step 1 should read the request it was handed", waitTime);

  // What actually arrived, read off the page rather than from anything this test
  // built. This is the assertion the old suite could not make.
  var arrived = await driver.executeScript(
    "var r = JSON.parse(window.localStorage.getItem('sdjwtvp_request') || '{}');" +
    "var q = (r.params || {}).dcql_query;" +
    "return q ? JSON.parse(q) : null;");
  assert.ok(arrived && arrived.credentials && arrived.credentials.length,
    "step 1 should have stored the DCQL query it read. Got: " + JSON.stringify(arrived));
  assert.strictEqual(arrived.credentials[0].format, "ldp_vc",
    "the request that arrived must ask for ldp_vc — the format the wallet is holding. Anything else " +
    "means the format was dropped somewhere between step 0's link and the verifier's request.");

  // And the wallet must consider itself able to answer it.
  // Step 1 reports its problems through vp_request_status, not a list element.
  var blocked = await driver.executeScript(
    "var b = document.getElementById('vp_continue_button');" +
    "var p = document.getElementById('vp_request_status');" +
    "return { disabled: b ? b.disabled : null, problems: p ? p.textContent.trim() : '' };");
  assert.strictEqual(blocked.disabled, false,
    "step 1 should let the holder continue: it holds exactly the format that was asked for. Problems " +
    "reported: " + blocked.problems);
  assert.ok(!/cannot be answered/.test(blocked.problems),
    "and must not report the request as unanswerable when it holds exactly the format asked for. " +
    "Got: " + blocked.problems);
  log.info("[route] OK — the verifier asked for ldp_vc and step 1 can answer it.");
}

// The other half of the same rule: when the formats genuinely differ, the wallet
// must say so HERE rather than build something the verifier cannot parse. Before
// this guard the presentation was sent anyway and refused with a message about
// its shape, which sends the reader looking for a serialization bug instead of at
// the credential in hand.
async function refusesAFormatItCannotAnswer(driver) {
  log.info("=== A request for a format this wallet does not hold ===");
  const sdJwt = await common.mintJwtVcJson(issuerBase, process.env.OID4VCI_CONFIG_ID || "IdentityCredential");
  assert.strictEqual(typeof sdJwt.credential, "string",
    "the control credential should be a compact-serialized one, i.e. NOT ldp_vc.");
  const request = await freshRequest();

  await driver.get(baseUrl + "/vc-presentation-1.html");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);",
    sdJwt.credential, verifierBase);
  await driver.get(baseUrl + "/vc-presentation-1.html?" + request.query);
  await driver.sleep(1200);

  var state = await driver.executeScript(
    "var b = document.getElementById('vp_continue_button');" +
    "var p = document.getElementById('vp_request_status');" +
    "return { disabled: b ? b.disabled : null, problems: p ? p.textContent.trim() : '' };");
  assert.ok(/ldp_vc/.test(state.problems) && /dc\+sd-jwt/.test(state.problems),
    "step 1 must name BOTH formats — the one asked for and the one held — because that is the whole " +
    "of the problem and neither alone identifies it. Got: " + state.problems);
  assert.strictEqual(state.disabled, true,
    "and must block: unlike a missing holder key, there is nothing the next page can do about it. A " +
    "presentation cannot convert a credential between formats.");
  log.info("[mismatch] OK — blocked at step 1, naming both formats.");
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

    // Last, because both clear localStorage and drive the pages into states the
    // sections above would not survive: one starts over from step 0, the other
    // deliberately plants the wrong credential format.
    await startsFromTheWalletsOwnPages(driver, held);
    await refusesAFormatItCannotAnswer(driver);

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
