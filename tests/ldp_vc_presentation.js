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
// The Verifier's website (iya-sts's companion on this suite's stacks), where
// the chooser on step 0 sends the browser.
const companionUrl = (process.env.COMPANION_URL || "http://localhost:9700")
    .replace(/\/+$/, "");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldp_vc_presentation",
    level: appconfig.logLevel || "info" });

if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = function (s) {
    log.debug("Entering btoa().");
    log.debug("Leaving btoa().");
    return Buffer.from(s, "binary").toString("base64");
  };
  globalThis.atob = function (s) {
    log.debug("Entering atob().");
    log.debug("Leaving atob().");
    return Buffer.from(s, "base64").toString("binary");
  };
}

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
// A STEP TRANSITION IS NOT A FIELD READ, and budgeting it as one is what broke
// this file on 2026-08-20: `waitTime` is 2000ms in tests/env/*.js — a fine
// budget for a page filling a field it already has the data for — and it was
// also carrying "click Present, derive a bbs-2023 proof in the browser, POST it
// to the verifier, load the next page of the workflow and let its bundle run".
// The BBS derivation alone is BLS12-381 arithmetic over every statement, each
// of these pages is a browserify bundle of a few megabytes, and the whole
// suite's stack is on the same machine — so on a loaded box 2 seconds went on
// the navigation alone and it failed as "presenting should reach step 3" after
// 2113ms, which reads as the wallet refusing to present. Four times the field
// budget for anything that crosses a page or derives a proof.
var stepWait = waitTime * 4;
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");
var verifierBase = process.env.OID4VP_VERIFIER_URL || issuerBase;
const LDP_CONFIG_ID = process.env.OID4VCI_LDP_CONFIG_ID ||
    "IdentityCredentialLdpVc";

const { text, waitForStatus, waitForValue } = require("./wait_for");
const waitForContent = require("./wait_for.js");

// "The page's bundle has run", which is a different question from "the page's
// markup is there" and the one that matters before pressing anything: every
// control in this application is wired with an inline onclick naming a
// browserify --standalone global, so a click that lands before the bundle has
// executed raises ReferenceError inside the page and does nothing at all out
// here. waitForPageBundle() in tests/wait_for.js reads the page's own script
// tags, so this needs no table of global names, and its note records what the
// missing wait cost.
// THE ISSUER'S JSON-LD CONTEXTS, SUPPLIED THROUGH THE PAGE. The wallet ships
// only the standard contexts and this project's own; a context an issuer
// coins is added on step 2's JSON-LD Contexts pane, which is what a person
// would do. iya-sts names its own since its #663, so this finds every
// context the held credential names that the wallet does not ship, asks
// iya-sts's OWN loader for the document, and adds it through the pane —
// neither the URL nor the document is written down in this repository.
// Answers the contexts it added.
function contextsTheWalletLacks(credential) {
  log.debug("Entering contextsTheWalletLacks().");
  const ROOT = path.join(__dirname, "..");
  const wallet = paths.requireSharedModule(
    [path.join(__dirname, "bbs2023.js"),
     path.join(ROOT, "client", "src", "bbs2023.js")],
    "the wallet's bbs-2023 cryptosuite");
  const names = [].concat((credential || {})["@context"] || [])
    .filter(function (one) {
      return typeof one === "string";
    });
  log.debug("Leaving contextsTheWalletLacks().");
  return Promise.all(names.map(function (url) {
    return wallet.documentLoader(url).then(function () {
      return null;
    }, function () {
      return url;
    });
  })).then(function (all) {
    return all.filter(Boolean);
  });
}

async function addTheIssuersContexts(driver, credential) {
  log.debug("Entering addTheIssuersContexts().");
  const lacking = await contextsTheWalletLacks(credential);
  if (!lacking.length) {
    log.info("the wallet ships every context this credential names.");
    log.debug("Leaving addTheIssuersContexts(). None needed.");
    return [];
  }
  const issuerSuite = paths.requireSharedModule(
    [paths.mockStsModule("bbs2023.js") || ""],
    "iya-sts's bbs-2023 cryptosuite, for the contexts it issues under");
  // Without the context the page must say what is missing AND where it is
  // supplied — a message naming the issuer's key would send a person to the
  // wrong service.
  await waitForStatus(driver, "vp_present_status",
    function (s) {
      return /JSON-LD Contexts/.test(s);
    },
    "with " + lacking.join(", ") + " missing, step 2 should say so and " +
        "point at the JSON-LD Contexts pane", stepWait);
  let url;
  for (url of lacking) {
    const loaded = await issuerSuite.documentLoader(url);
    await driver.executeScript(
      "document.getElementById('vp_context_url').value = arguments[0];" +
      "document.getElementById('vp_context_json').value = arguments[1];",
      url, JSON.stringify(loaded.document));
    await driver.findElement(By.id("vp_context_add_button")).click();
    await waitForStatus(driver, "vp_context_status",
      function (s) {
        return /Added/.test(s);
      }, "the page did not accept the context " + url, stepWait);
    // Adding reloads the page so the credential is canonicalized with it.
    await driver.sleep(800);
    await pageBundleReady(driver);
    const listed = await driver.findElement(By.id("vp_contexts_list"))
      .getText();
    assert.ok(listed.indexOf(url) !== -1,
      "the context just added should be listed on the pane: " + listed);
    log.info("added iya-sts's context " + url + " on the page.");
  }
  log.debug("Leaving addTheIssuersContexts().");
  return lacking;
}

async function pageBundleReady(driver) {
  log.debug("Entering pageBundleReady().");
  await waitForContent.waitForPageBundle(driver,
    "the page this test just navigated to");
  log.debug("Leaving pageBundleReady().");
}

function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  const logging = require("selenium-webdriver/lib/logging");
  log.debug("Leaving severeErrors().");
  return driver.manage().logs().get(logging.Type.BROWSER)
                       .then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      // Nor is a load the BROWSER abandoned because its own certificate or
      // network configuration changed underneath it. See browser_flags.js.
      .filter(function (e) {
        return !browserFlags.isTransientLoadError(e.message);
      })
      .map(function (e) { return e.message; });
  });
}

// ---------------------------------------------------------------------------
// Getting here the way a USER does, which is a different question from whether
// the protocol works.
//
// A request built by hand ("/oid4vp/start?format=ldp_vc", as this file once
// did) made every other assertion in this file meaningful and, on its own,
// proved nothing about reachability: for as long as this suite has passed, there was no route
// through the pages that produced that URL. Presentation step 0 linked to the
// verifier with no format at all, so the verifier asked for its default
// (dc+sd-jwt), the wallet answered with the ldp_vc it held, and the verifier
// reported a malformed presentation — "this has 1 part(s)" — because it was
// splitting a JSON object on "~". The format is the VERIFIER's choice, so the
// wallet cannot fix it after the fact; the only place it can be made is the
// link that starts the presentation.
//
// So this section constructs no URLs. It reads step 0's own links out of the
// DOM, follows them, and lets the verifier hand the request back.
// ---------------------------------------------------------------------------
async function startsFromTheWalletsOwnPages(driver, held) {
  log.debug("Entering startsFromTheWalletsOwnPages().");
  log.info("=== Starting a presentation from the wallet's pages, not a " +
           "hand-built URL ===");
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);" +
    // The Verifier's website; a deployed site defaults to none.
    "localStorage.setItem('sdjwtvp_verifier_site_url', arguments[2]);",
    JSON.stringify(held.credential), verifierBase,
    companionUrl + "/verifier");
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await driver.sleep(900);

  // Step 0 navigates from a click handler rather than an anchor, so the only
  // honest way to read where a flow goes is to take it. All three go to the
  // VERIFIER'S WEBSITE (iya-sts's companion here), and each has to say which
  // format to ask for there: the format is the Verifier's choice, made on its
  // own page, and a holder should not have to know that only one of its
  // options works with the credential they hold.
  var flows = ["same-device", "same-device-signed", "cross-device"];
  for (var i = 0; i < flows.length; i++) {
    await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
    await pageBundleReady(driver);
    await driver.sleep(700);
    var buttonId = "vp_usecase_" + flows[i];
    var exists = await driver.executeScript(
      "return !!document.getElementById(arguments[0]);", buttonId);
    assert.ok(exists, "step 0 should offer the " + flows[i] + " flow (#" +
              buttonId + ").");
    // Clicked and read in ONE script: choose() writes the status line and
    // then sets location.href, and the navigation it starts does not unload
    // the page until this script has returned.
    var said = await driver.executeScript(
      "document.getElementById(arguments[0]).click();" +
      "return document.getElementById('vp_usecase_status').textContent;",
      buttonId);
    assert.ok(/ldp_vc/.test(said),
      "the " + flows[i] + " flow must tell the reader to ask for ldp_vc, the " +
          "format this wallet holds, on the verifier's page — otherwise it " +
          "asks for its default (dc+sd-jwt) and the wallet has nothing to " +
          "answer with. Step 0 said: " + said);
    await driver.wait(until.elementLocated(By.id("start")), stepWait,
      "the " + flows[i] + " flow should land on the verifier's website.");
    var landed = await driver.getCurrentUrl();
    assert.ok(landed.indexOf(companionUrl) === 0,
      "the " + flows[i] + " flow should go to the verifier website step 0 " +
          "is configured with (" + companionUrl + "), got " + landed);
    log.info("[route] OK — " + flows[i] + " → the verifier's website, " +
             "asking for ldp_vc.");
  }

  // Take the same-device one all the way, through the verifier's own page:
  // ldp_vc, by value, a wallet on this device. Nothing below is constructed
  // by this test.
  await loadUrl(driver, baseUrl + "/vc-presentation-0.html");
  await pageBundleReady(driver);
  await driver.sleep(700);
  await driver.executeScript(
      "document.getElementById('vp_usecase_same-device').click();");
  await common.startAtTheVerifierWebsite(driver, { By: By, until: until,
    format: "ldp_vc", byReference: false, crossDevice: false,
    wait: stepWait });
  await waitForStatus(driver, "vp_request_status",
                      function (s) { return /Request read/.test(s); },
    "step 1 should read the request it was handed", stepWait);

  // What actually arrived, read off the page rather than from anything this
  // test built. This is the assertion the old suite could not make.
  var arrived = await driver.executeScript(
    "var r = JSON.parse(window.localStorage.getItem('sdjwtvp_request') " +
        "|| '{}');" +
    "var q = (r.params || {}).dcql_query;" +
    "return q ? JSON.parse(q) : null;");
  assert.ok(arrived && arrived.credentials && arrived.credentials.length,
    "step 1 should have stored the DCQL query it read. Got: " +
        JSON.stringify(arrived));
  assert.strictEqual(arrived.credentials[0].format, "ldp_vc",
    "the request that arrived must ask for ldp_vc — the format the wallet is " +
        "holding. Anything else " +
    "means the format was dropped somewhere between step 0's link and the " +
        "verifier's request.");

  // And the wallet must consider itself able to answer it.
  // Step 1 reports its problems through vp_request_status, not a list element.
  var blocked = await driver.executeScript(
    "var b = document.getElementById('vp_continue_button');" +
    "var p = document.getElementById('vp_request_status');" +
    "return { disabled: b ? b.disabled : null, problems: p ? " +
        "p.textContent.trim() : '' };");
  assert.strictEqual(blocked.disabled, false,
    "step 1 should let the holder continue: it holds exactly the format that " +
        "was asked for. Problems " +
    "reported: " + blocked.problems);
  assert.ok(!/cannot be answered/.test(blocked.problems),
    "and must not report the request as unanswerable when it holds exactly " +
        "the format asked for. " +
    "Got: " + blocked.problems);
  log.info("[route] OK — the verifier asked for ldp_vc and step 1 can " +
           "answer it.");
  log.debug("Leaving startsFromTheWalletsOwnPages().");
}

// The other half of the same rule: when the formats genuinely differ, the
// wallet must say so HERE rather than build something the verifier cannot
// parse. Before this guard the presentation was sent anyway and refused with a
// message about its shape, which sends the reader looking for a serialization
// bug instead of at the credential in hand.
async function refusesAFormatItCannotAnswer(driver) {
  log.debug("Entering refusesAFormatItCannotAnswer().");
  log.info("=== A request for a format this wallet does not hold ===");
  const sdJwt = await common.mintJwtVcJson(issuerBase,
      process.env.OID4VCI_CONFIG_ID || "IdentityCredential");
  assert.strictEqual(typeof sdJwt.credential, "string",
    "the control credential should be a compact-serialized one, i.e. " +
        "NOT ldp_vc.");
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await pageBundleReady(driver);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);",
    sdJwt.credential, verifierBase);
  // The ldp_vc request the way a person gets one: the Verifier's website.
  await common.requestThroughTheVerifierWebsite(driver, { By: By,
    until: until, siteUrl: companionUrl + "/verifier", format: "ldp_vc",
    wait: stepWait });
  await driver.sleep(1200);

  var state = await driver.executeScript(
    "var b = document.getElementById('vp_continue_button');" +
    "var p = document.getElementById('vp_request_status');" +
    "return { disabled: b ? b.disabled : null, problems: p ? " +
        "p.textContent.trim() : '' };");
  assert.ok(/ldp_vc/.test(state.problems) && /dc\+sd-jwt/.test(state.problems),
    "step 1 must name BOTH formats — the one asked for and the one held — " +
        "because that is the whole " +
    "of the problem and neither alone identifies it. Got: " + state.problems);
  assert.strictEqual(state.disabled, true,
    "and must block: unlike a missing holder key, there is nothing the next " +
        "page can do about it. A " +
    "presentation cannot convert a credential between formats.");
  log.info("[mismatch] OK — blocked at step 1, naming both formats.");
  log.debug("Leaving refusesAFormatItCannotAnswer().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running ldp_vc presentation. issuer=" + issuerBase + ", verifier=" +
           verifierBase);
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta && (meta.credential_configurations_supported ||
            {})[LDP_CONFIG_ID],
    "this issuer offers no ldp_vc configuration \"" + LDP_CONFIG_ID + "\".");

  await common.provisionWallet(issuerBase,
    { why: "the wallet whose ldp_vc credential this job presents" });
  const held = await common.mintJwtVcJson(issuerBase, LDP_CONFIG_ID);
  assert.strictEqual(typeof held.credential, "object",
                     "an ldp_vc credential is a JSON object.");


  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  // BBS proof derivation needs Web Crypto's getRandomValues, which requires a
  // secure context — see tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
    await pageBundleReady(driver);
    await driver.executeScript(
      "window.localStorage.clear();" +
      "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
      "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[1]);",
      JSON.stringify(held.credential), verifierBase);
    // The request the way a person gets one: the Verifier's website, which
    // redirects the browser to step 1 with it.
    const request = await common.requestThroughTheVerifierWebsite(driver, {
      By: By, until: until, siteUrl: companionUrl + "/verifier",
      format: "ldp_vc", wait: stepWait });
    const dcql = JSON.parse(request.params.dcql_query);
    assert.strictEqual(dcql.credentials[0].format, "ldp_vc",
      "the verifier should be asking for ldp_vc.");
    assert.deepStrictEqual(dcql.credentials[0].claims[0].path.slice(0, 1),
                           ["credentialSubject"],
      "and address its claims under credentialSubject, where a W3C VC " +
          "keeps them.");
    await waitForStatus(driver, "vp_request_status",
                        function (s) { return /Request read/.test(s); },
      "step 1 should read an ldp_vc request", stepWait);
    await driver.executeScript(
        "var b=document.getElementById('vp_continue_button'); if (b) " +
        "b.click();");
    await driver.sleep(800);

    log.info("=== Step 2: selection is over canonical statements ===");
    await loadUrl(driver, baseUrl + "/vc-presentation-2.html");
    await pageBundleReady(driver);
    await addTheIssuersContexts(driver, held.credential);
    await driver.wait(until.elementLocated(By.id("vp_presentation")), stepWait);
    const envelope = await waitForValue(driver, "vp_presentation",
      function (v) { return v.trim().length > 100; },
      "step 2 should derive a bbs-2023 proof", stepWait);

    const rows = await driver.executeScript(
      "return document.querySelectorAll('#vp_disclosures_table tbody " +
          "tr').length;");
    assert.ok(rows > 4,
      "the table should list the credential's canonical statements; got " +
          rows);
    const summary = await text(driver, "vp_selection_summary");
    assert.ok(/statement/i.test(summary) && /bbs-2023/.test(summary),
      "step 2 must say the unit of disclosure is the statement. Said: " +
          summary);
    assert.ok(/link/i.test(summary),
      "and that presentations are unlinkable — the reason to use this " +
          "format. Said: " + summary);

    const parsed = JSON.parse(envelope);
    assert.strictEqual(parsed.cryptosuite, "bbs-2023",
                       "the envelope names the cryptosuite.");
    assert.ok(parsed.proof && parsed.disclosedStatements.length,
      "and carries the derived proof plus the statements it discloses.");
    assert.ok(parsed.disclosedStatements.length < rows,
      "a selective disclosure should send FEWER statements than the " +
          "credential has: " +
      parsed.disclosedStatements.length + " of " + rows +
          ". Sending all of them would mean the " +
      "selection is not working.");
    log.info("[step2] OK — " + parsed.disclosedStatements.length + " of " +
             rows +
             " statements chosen, proof derived without a holder key.");

    log.info("=== Step 3: the verifier's verdict ===");
    await driver.executeScript(
        "var b=document.getElementById('vp_present_button'); if (b) " +
        "b.click();");
    await driver.wait(until.urlContains("vc-presentation-3.html"), stepWait,
      "presenting should reach step 3.");
    const verdict = await common.verdictOfWhatWasSent(driver, { By: By,
      until: until, wait: stepWait, verifierBase: verifierBase });
    assert.ok(verdict.ok,
      "the verifier must accept a correctly derived bbs-2023 proof. Its " +
          "verdict: " + JSON.stringify(verdict));
    const recheck = await waitForStatus(driver, "vp_recheck_status",
      function (s) { return s.trim() !== ""; },
                "the wallet should re-check what it sent", stepWait);
    assert.ok(/all pass/.test(recheck),
              "the wallet's own checks should pass. Said: " + recheck);
    log.info("[step3] OK — the Verifier accepted it, " +
             (verdict.checks || []).length + " check(s).");

    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0, "the pages logged browser errors:\n" +
                       errors.join("\n"));

    log.info("=== Unlinkability, and what the verifier refuses ===");
    // A second presentation of the SAME credential must produce different
    // bytes.
    const second = await common.requestThroughTheVerifierWebsite(driver, {
      By: By, until: until, siteUrl: companionUrl + "/verifier",
      format: "ldp_vc", wait: stepWait });
    await waitForStatus(driver, "vp_request_status",
                        function (s) { return /Request read/.test(s); },
      "step 1 should read the second request", stepWait);
    await driver.executeScript(
        "var b=document.getElementById('vp_continue_button'); if (b) " +
        "b.click();");
    await driver.sleep(800);
    await loadUrl(driver, baseUrl + "/vc-presentation-2.html");
    await pageBundleReady(driver);
    await driver.wait(until.elementLocated(By.id("vp_presentation")), stepWait);
    const envelope2 = await waitForValue(driver, "vp_presentation",
      function (v) { return v.trim().length > 100; }, "the second derivation",
                stepWait);
    assert.notStrictEqual(JSON.parse(envelope2).proof, parsed.proof,
      "two presentations of the same credential must produce DIFFERENT proof " +
          "bytes. This is the " +
      "property neither dc+sd-jwt nor jwt_vc_json can offer: they replay the " +
          "issuer's signature " +
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
    const result = await common.verificationResult(verifierBase,
      second.params.state);
    const v = (result.body || {}).verdict || {};
    assert.strictEqual(v.ok, false,
      "a proof derived for one request must be refused by another — the " +
          "nonce is inside the proof, so " +
      "this fails the proof check itself rather than a separate " +
          "comparison. HTTP " + replay.status);
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
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>",
                  "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) { log.error(e.stack ||
     e.message); process.exit(1); });
