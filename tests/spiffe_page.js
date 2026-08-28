// File: spiffe_page.js
//
// client/public/spiffe.html — the SPIFFE Protocol Debugger, driven through its
// own controls.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS WHEN spiffe_protocol.js ALREADY CALLS ALL FORTY-NINE METHODS.
//
// That test drives the api's client in process and covers the protocol far
// harder than this one does — every method, every entity, every refusal. What
// it cannot cover is the things that only exist in a page, and each of them is
// a way for this workflow to be broken while the protocol is perfect:
//
//  1. **THE PICKERS ARE BUILT FROM THE API'S CATALOGUE.** Forty-nine methods
//     reach the page as JSON from `GET /spiffe/limits`, and the whole claim
//     that this workflow "exercises every function in SPIFFE" is a claim about
//     what is in those two dropdowns. A page that offered forty-two of them
//     would look completely normal.
//  2. **THE BOOTSTRAP IS A HAND-OFF BETWEEN PANES.** `FetchX509SVID` needs no
//     credential and hands back an SVID WITH ITS PRIVATE KEY; the page keeps
//     the pair and presents it on the next surface. Nothing in the protocol
//     notices if that hand-off drops the key — the call simply becomes
//     anonymous, and an anonymous call still WORKS on the two methods that are
//     open to everybody, so the failure looks like an authorization problem on
//     a server rather than a page that lost a key.
//  3. **THE CSR BUILDER.** Five methods take a PKCS#10 request, and it is
//     built HERE, in the browser, with Web Crypto — a different implementation
//     from the node one `spiffe_engine.js` checks against OpenSSL. Without it
//     five methods on this page are unreachable in practice, which would make
//     "every method is here" a claim about a list.
//  4. **THE THREE OFFLINE READERS.** The bundle reader, the SVID inspector
//     and the SPIFFE ID checker each need no network at all, and each answers
//     a question somebody asks while holding a value and nothing else. They
//     are also the only part of this page that would work on a deployment
//     with no api — which this one is not, but they must not depend on one.
//     Two of them are panes; the bundle reader is the **Trust Bundle group**
//     inside the settings pane, folded in there on 2026-08-26 because what it
//     produces — the trust anchor — is a setting two groups below it.
//  5. **A REFUSAL IS THE INTERESTING ANSWER.** `PERMISSION_DENIED` has to
//     reach the status line as SPIFFE's answer rather than as an error, and
//     the Operations History has to tell Failure (the far end said no) from
//     Sent (the api never answered) — the two states people most often
//     confuse.
//  6. **THE KEY-MATERIAL OPT-OUT.** This page holds a PRIVATE KEY, so it
//     carries the checkbox the SAML, WS-Trust and WS-Federation panes do, and
//     clearing it must remove what is already stored rather than only stopping
//     future writes.
//  7. **THE SHAPE OF THE PAGE.** Every editable setting is in ONE pane and
//     every explanation is folded, so what is on screen for a control is its
//     tooltip. All three of those decay silently — a field added to a pane
//     below, a fold that ships open, a control with no title — and none of
//     them fails anything a protocol test asserts. Section 10.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
const waitFor = require("./wait_for.js");
const { loadPage } = require("./page_load.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "spiffe_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = process.env.BASE_URL || "http://localhost:3000";
var apiUrl = process.env.API_URL || "http://localhost:4000";
var stsUrl = process.env.STS_URL || "https://localhost:8081";
// The API's view of each surface, which on the containerized stack is a
// different name from this test's — the same distinction LDAP_URL draws, and
// its own variable for the same reason.
var workloadAddress = process.env.SPIFFE_WORKLOAD_ADDRESS || "sts:8092";
var serverAddress = process.env.SPIFFE_SERVER_ADDRESS || "sts:8181";
var bundleUrl = process.env.SPIFFE_BUNDLE_URL ||
  (process.env.API_STS_URL || "https://sts:8081") + "/spiffe/bundle";
var trustDomain = process.env.SPIFFE_TRUST_DOMAIN || "example.org";

// Longer than `waitTime` for anything that crosses a network or does crypto in
// the browser. The house multipliers are 3 / 4 / 6; a gRPC call through the api
// and an in-browser key generation are both firmly in that territory.
var waitTime = (appconfig.waitTime || 2000);
var stepWait = waitTime * 6;

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function el(driver, id) {
  return driver.findElement(By.id(id));
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (e) { e.value = arguments[1]; }", id, value);
  log.debug("Leaving setField().");
}

async function getField(driver, id) {
  log.debug("Entering getField(). " + id);
  const value = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (!e) { return null; }" +
    "return e.value !== undefined ? e.value : e.textContent;", id);
  log.debug("Leaving getField().");
  return value;
}

async function setCheckbox(driver, id, on) {
  log.debug("Entering setCheckbox(). " + id);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (e) { e.checked = !!arguments[1];" +
    "         if (e.onchange) { e.onchange(); } }", id, !!on);
  log.debug("Leaving setCheckbox().");
}

// Choosing an option and FIRING the handler. The page rebuilds the method
// picker and the request editor from `onchange`, and setting `.value` in script
// does not fire one — a select left without it looks chosen and the pane below
// still describes the previous method.
async function selectOption(driver, id, value) {
  log.debug("Entering selectOption(). " + id + "=" + value);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "e.value = arguments[1];" +
    "if (e.onchange) { e.onchange(); }", id, value);
  log.debug("Leaving selectOption().");
}

// A status line is blanked BEFORE the action that fills it, because the
// previous action's message satisfies "non-empty and not still working"
// instantly — the false pass tests/CLAUDE.md records about
// `encryption_tools.js`, arriving on a page whose every pane reports through
// one.
async function clickAndWait(driver, buttonId, statusId, timeout) {
  log.debug("Entering clickAndWait(). " + buttonId);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (e) { e.value = ''; e.className = 'spiffe-status spiffe-grow'; }",
    statusId);
  await el(driver, buttonId).click();
  // waitForStatusValue rather than wait_for.js's waitForStatus, and the
  // difference is not cosmetic: every status line on this page is an <input>,
  // so its content is its VALUE and `getText()` returns "" for ever. A poll on
  // the text waits out its whole budget and reports `(empty)` on a status the
  // page filled in immediately.
  const status = await waitForStatusValue(driver, statusId,
    function (text) {
      return !!text && !/…$/.test(String(text).trim());
    },
    "the " + buttonId + " status never settled", timeout || stepWait);
  log.debug("Leaving clickAndWait(). " + String(status).slice(0, 80));
  return status;
}

// The status line is an <input>, so its text is its VALUE and `getText()`
// returns "". wait_for.js's waitForStatus reads text; this page needs the
// value, so the poll is written here rather than there.
async function waitForStatusValue(driver, id, predicate, message, timeout) {
  log.debug("Entering waitForStatusValue(). " + id);
  let last = "";
  try {
    await driver.wait(async function () {
      last = (await getField(driver, id)) || "";
      return predicate(last);
    }, timeout || stepWait);
  } catch (e) {
    e.message = message + " (last status: " + JSON.stringify(last) + ") — " +
      e.message;
    throw e;
  }
  log.debug("Leaving waitForStatusValue().");
  return last;
}

async function open(driver) {
  log.debug("Entering open().");
  await loadPage(driver, baseUrl + "/spiffe.html", "spiffe_trust_domain",
    { timeout: stepWait });
  // A click before the browserify `--standalone` global exists is a SILENT
  // no-op: the inline handlers on this page all name `spiffe.`, the markup
  // carrying them is in the HTML from the moment it parses, and a press in
  // that gap raises a ReferenceError inside the page and looks out here like a
  // control that did nothing.
  await waitFor.waitForPageBundle(driver,
    "the spiffe bundle never finished loading", stepWait);
  await everyBoxOpensAtItsMinimum(driver);
  log.debug("Leaving open().");
}

// ---------------------------------------------------------------------------
// 0. THE PAGE OPENS COMPACT — every readout is sized to nothing, because it
//    HOLDS nothing.
//
// This page has seventeen textareas and most of them are answers: the two
// Exchange readouts, the SVID Inspector's output, the three certification
// request boxes, the held identity's two. On a page nobody has done anything
// on yet, every one of those is EMPTY — and a box that reserves ten rows for
// an answer it does not have is ten rows of white space between two panes a
// reader is trying to compare. So each declares `data-min-rows` and
// `data-max-rows` and `fitTextarea()` in the bundle sizes it to what it
// actually holds, growing when an answer arrives and shrinking again when one
// is discarded.
//
// This is checked HERE, on a freshly loaded page, because by the time the
// sections below have finished every one of those boxes has something in it —
// which is the state that hides the defect this catches. What it catches is a
// box added with a big `rows` and no ceiling, which is what all of them looked
// like before, and which nothing else on this page would ever report.
// ---------------------------------------------------------------------------
async function everyBoxOpensAtItsMinimum(driver) {
  log.debug("Entering everyBoxOpensAtItsMinimum().");
  // Runs IN THE BROWSER, so it has no bunyan and no `log` — see the repo-root
  // CLAUDE.md. What is logged is what it returns.
  const boxes = await driver.executeScript(
    "var all = document.querySelectorAll('textarea');" +
    "var undeclared = [], oversized = [], unfitted = [];" +
    "for (var i = 0; i < all.length; i++) {" +
    "  var e = all[i];" +
    "  var min = parseInt(e.getAttribute('data-min-rows') || '0', 10);" +
    "  var max = parseInt(e.getAttribute('data-max-rows') || '0', 10);" +
    "  if (!min || !max || max < min) { undeclared.push(e.id); continue; }" +
    "  if (min > 4) { oversized.push(e.id + ' opens at ' + min); }" +
    "  var lines = String(e.value || '').split('\\n').length;" +
    "  var want = Math.max(min, Math.min(max, lines));" +
    "  if (e.rows !== want) { unfitted.push(e.id + ' is ' + e.rows +" +
    "      ' rows for ' + lines + ' lines, wanted ' + want); }" +
    "}" +
    "return { total: all.length, undeclared: undeclared," +
    "         oversized: oversized, unfitted: unfitted };");

  check("every textarea declares the rows it may take — a box with no " +
    "ceiling is one that pushes the panes below it off the screen when it " +
    "is answered, and a box with no floor is one that reserves ten rows for " +
    "an answer it does not have", function () {
      assert.deepStrictEqual(boxes.undeclared, []);
      assert.ok(boxes.total >= 15,
        "only " + boxes.total + " textareas — the readouts have been " +
        "changed to something else, and this check now guards nothing");
    });

  check("and none of them opens taller than four rows, on a page where " +
    "nothing has been done yet", function () {
      assert.deepStrictEqual(boxes.oversized, []);
    });

  check("every box on a freshly loaded page is already sized to what it " +
    "holds — mountAutoFit() runs at load, so a value restored from storage " +
    "arrives in a box that fits it", function () {
      assert.deepStrictEqual(boxes.unfitted, []);
    });
  log.debug("Leaving everyBoxOpensAtItsMinimum().");
}

// ---------------------------------------------------------------------------
// 1. THE PICKERS — all forty-nine, from the api's own catalogue.
// ---------------------------------------------------------------------------
async function thePickersHoldEveryMethod(driver) {
  log.debug("Entering thePickersHoldEveryMethod().");
  await driver.wait(async function () {
    const n = await driver.executeScript(
      "var e = document.getElementById('spiffe_server_method');" +
      "return e ? e.options.length : 0;");
    return n > 0;
  }, stepWait, "the method pickers were never populated — the page builds " +
     "them from GET /spiffe/limits, so an empty one means the api did not " +
     "answer rather than that a method is missing");

  const workload = await driver.executeScript(
    "return Array.from(document.getElementById('spiffe_workload_method')" +
    ".options).map(function (o) { return o.value; });");
  check("the Workload API picker holds its seven methods, the two WIT ones " +
    "included — a surface that offered five of seven would look completely " +
    "normal", function () {
      assert.deepStrictEqual(workload.slice().sort(),
        ["FetchJWTBundles", "FetchJWTSVID", "FetchWITBundles", "FetchWITSVID",
         "FetchX509Bundles", "FetchX509SVID", "ValidateJWTSVID"].sort());
    });

  const services = await driver.executeScript(
    "return Array.from(document.getElementById('spiffe_server_service')" +
    ".options).map(function (o) { return o.value; });");
  check("the SPIRE Server API picker holds its six services", function () {
    assert.deepStrictEqual(services,
      ["entry", "agent", "bundle", "svid", "trustdomain", "debug"]);
  });

  const counts = {};
  let total = workload.length;
  for (const service of services) {
    await selectOption(driver, "spiffe_server_service", service);
    const methods = await driver.executeScript(
      "return Array.from(document.getElementById('spiffe_server_method')" +
      ".options).map(function (o) { return o.value; });");
    counts[service] = methods.length;
    total += methods.length;
  }
  check("and forty-two methods across them, which with the Workload API's " +
    "seven is all forty-nine of SPIFFE's server-side methods reachable from " +
    "this page", function () {
      assert.deepStrictEqual(counts,
        { entry: 8, agent: 9, bundle: 11, svid: 7, trustdomain: 6, debug: 1 });
      assert.strictEqual(total, 49);
    });

  await selectOption(driver, "spiffe_server_service", "entry");
  await selectOption(driver, "spiffe_server_method", "BatchCreateEntry");
  const about = await el(driver, "spiffe_server_about").getText();
  const seeded = await getField(driver, "spiffe_server_request");
  check("choosing a method describes it and seeds its request, so a person " +
    "meeting a forty-two-method surface has somewhere to start", function () {
      assert.ok(about.length > 40, "the method was not described: " + about);
      const parsed = JSON.parse(seeded);
      assert.ok(parsed.entries, "the example did not reach the editor: " +
        seeded.slice(0, 120));
    });
  log.debug("Leaving thePickersHoldEveryMethod().");
}

// ---------------------------------------------------------------------------
// 2. THE TRUST BUNDLE, fetched and then read with no network.
//
// It is a GROUP in the Configuration Parameters pane rather than a pane of its
// own — the ids did not change with the fold, which is why nothing below did.
// ---------------------------------------------------------------------------
async function theBundleGroupFetchesAndReads(driver) {
  log.debug("Entering theBundleGroupFetchesAndReads().");
  await setField(driver, "spiffe_bundle_url", bundleUrl);
  const status = await clickAndWait(driver, "btn_spiffe_fetch_bundle",
    "spiffe_bundle_status");
  check("the bundle endpoint is fetched through the api — it sends no CORS " +
    "headers, so this page cannot fetch it itself even though it is the one " +
    "SPIFFE surface that is plain HTTPS", function () {
      assert.ok(/usable key/.test(status),
        "the bundle was not read: " + status);
      assert.ok(/x509-svid/.test(status) && /jwt-svid/.test(status),
        "both uses have to be counted, because a bundle with only one of " +
        "them verifies only half of what this trust domain issues: " + status);
    });

  const document = await getField(driver, "spiffe_bundle_document");
  check("and the document itself comes back, so the reader below has " +
    "something to work on", function () {
      const parsed = JSON.parse(document);
      assert.ok(Array.isArray(parsed.keys) && parsed.keys.length >= 1);
    });

  // THE ONE DEFECT THAT MATTERS, read with no network at all. A JWK with no
  // `use` is one a consumer MUST IGNORE, so a bundle of them verifies nothing
  // — and reports no error anywhere, because the failure surfaces as an SVID
  // that will not validate.
  await setField(driver, "spiffe_bundle_document", JSON.stringify(
    { keys: [{ kty: "EC", crv: "P-256", x: "AA", y: "BB" }],
      spiffe_sequence: 1, spiffe_refresh_hint: 300 }));
  const offline = await clickAndWait(driver, "btn_spiffe_read_bundle",
    "spiffe_bundle_status", waitTime * 2);
  check("the reader works with NO NETWORK and names the one defect that " +
    "otherwise reports itself nowhere: a JWK with no `use` is ignored, so a " +
    "bundle of them verifies nothing at all", function () {
      assert.ok(/verifies nothing/.test(offline),
        "the status must say what the consequence is: " + offline);
    });
  const report = await el(driver, "spiffe_bundle_report").getText();
  check("and the report says WHICH key was discarded and why", function () {
    assert.ok(/IGNORED/.test(report), report.slice(0, 200));
    assert.ok(/MUST IGNORE/.test(report), report.slice(0, 300));
  });

  // Put the real one back and make it the trust anchor for the next pane.
  //
  // WAITING ON THE CONTENT rather than on the status, and the difference has
  // already cost a run of this file: the anchor button reads the DOCUMENT box,
  // and a status line that has settled says only that the previous call
  // finished. The failure is `no certificate reached the anchor field`, which
  // names the anchor for what is really the document still holding the
  // deliberately broken bundle from the section above.
  await clickAndWait(driver, "btn_spiffe_fetch_bundle",
    "spiffe_bundle_status");
  await driver.wait(async function () {
    const text = await getField(driver, "spiffe_bundle_document");
    try {
      const parsed = JSON.parse(text);
      return (parsed.keys || []).some(function (key) {
        return key.use === "x509-svid" && (key.x5c || []).length;
      });
    } catch (e) {
      return false;
    }
  }, stepWait, "the re-fetched bundle never reached the document box, so the " +
     "anchor button would have been reading the broken one from the section " +
     "above");
  const anchored = await clickAndWait(driver, "btn_spiffe_bundle_anchor",
    "spiffe_bundle_status", waitTime * 2);
  const anchor = await getField(driver, "spiffe_server_bundle");
  check("the x509-svid authorities become the trust anchor in the SPIRE " +
    "Server API group — and ALL of them do, because a trust domain that has " +
    "rotated publishes the old one too and dropping it is the difference " +
    "between a rotation and an outage", function () {
      assert.ok(/trust anchor/.test(anchored), anchored);
      assert.ok(/-----BEGIN CERTIFICATE-----/.test(anchor),
        "no certificate reached the anchor field. The status said: " +
        anchored + " — and the anchor field held " +
        JSON.stringify(String(anchor).slice(0, 120)));
    });
  log.debug("Leaving theBundleGroupFetchesAndReads().");
}

// ---------------------------------------------------------------------------
// 3. THE BOOTSTRAP — an identity from a surface that authenticates nobody.
// ---------------------------------------------------------------------------
async function theWorkloadApiHandsOverAnIdentity(driver) {
  log.debug("Entering theWorkloadApiHandsOverAnIdentity().");
  await setField(driver, "spiffe_trust_domain", trustDomain);
  await setField(driver, "spiffe_workload_address", workloadAddress);
  await selectOption(driver, "spiffe_workload_method", "FetchX509SVID");
  const status = await clickAndWait(driver, "btn_spiffe_call_workload",
    "spiffe_workload_status");
  check("FetchX509SVID answers with no credential of any kind — the " +
    "Workload Endpoint specification forbids requiring one, because a " +
    "workload has no root of trust until this call gives it one", function () {
      assert.ok(/^OK/.test(status), "the call did not succeed: " + status);
    });

  const heldId = await getField(driver, "spiffe_identity_id_view");
  const heldCert = await getField(driver, "spiffe_identity_cert_view");
  const holds = await el(driver, "spiffe_identity_holds_key").getText();
  check("and the page KEEPS the SVID with its private key — that hand-off " +
    "is what makes the next surface reachable as somebody, and a page that " +
    "dropped the key would simply become anonymous, which still works on the " +
    "two methods open to everybody", function () {
      assert.ok(/^spiffe:\/\//.test(heldId),
        "no identity was held: " + heldId);
      assert.ok(heldCert.length > 100, "no certificate was held");
      assert.ok(/A private key is held/.test(holds),
        "an X509-SVID without its key proves nothing: " + holds);
    });

  // The security header, which is the one check a conforming Workload API
  // makes. Clearing the box is the only way to see what a real server does to
  // a client that forgot it — a bug nothing else will ever report.
  await setCheckbox(driver, "spiffe_workload_security_header", false);
  await selectOption(driver, "spiffe_workload_method", "FetchX509Bundles");
  const refused = await clickAndWait(driver, "btn_spiffe_call_workload",
    "spiffe_workload_status");
  check("with `workload.spiffe.io: true` turned off the call is REFUSED, " +
    "which is what every conforming implementation does — it is not a " +
    "security check, it exists so a caller cannot reach the endpoint by " +
    "accident", function () {
      assert.ok(/INVALID_ARGUMENT/.test(refused),
        "expected the server's refusal and got: " + refused);
      assert.ok(/refused it/.test(refused),
        "the status has to say the server answered rather than that the " +
        "call failed: " + refused);
    });
  await setCheckbox(driver, "spiffe_workload_security_header", true);

  // A JWT-SVID, so the inspector below has one to read.
  await selectOption(driver, "spiffe_workload_method", "FetchJWTSVID");
  await setField(driver, "spiffe_workload_request",
    JSON.stringify({ audience: ["spiffe://" + trustDomain + "/page-test"] }));
  const jwt = await clickAndWait(driver, "btn_spiffe_call_workload",
    "spiffe_workload_status");
  check("FetchJWTSVID answers for the audience asked for", function () {
    assert.ok(/^OK/.test(jwt), jwt);
  });
  const answer = await getField(driver, "spiffe_exchange_response");
  const sent = await getField(driver, "spiffe_exchange_request");
  // The exchange pane pretty-prints, so the separator is `": "` and not `":"`.
  const token = (/"svid":\s*"(ey[^"]+)"/.exec(answer) || [])[1] || "";
  check("and the Exchange pane shows BOTH halves of what the api was asked " +
    "for — which is the only place the request this page composed can be " +
    "read back", function () {
      assert.ok(/^POST \/spiffe\/call/.test(sent),
        "the request half is missing: " + String(sent).slice(0, 120));
      assert.ok(/FetchJWTSVID/.test(sent),
        "the request half must name the method that was called");
      assert.ok(token,
        "no JWT-SVID could be read out of the answer half: " +
        String(answer).slice(0, 200));
    });
  log.debug("Leaving theWorkloadApiHandsOverAnIdentity().");
  return token;
}

// ---------------------------------------------------------------------------
// 4. THE SPIRE SERVER API — as the identity the page is holding.
// ---------------------------------------------------------------------------
async function theServerApiPresentsTheHeldIdentity(driver) {
  log.debug("Entering theServerApiPresentsTheHeldIdentity().");
  await setField(driver, "spiffe_server_address", serverAddress);
  await selectOption(driver, "spiffe_server_service", "bundle");
  await selectOption(driver, "spiffe_server_method", "GetBundle");
  await selectOption(driver, "spiffe_server_present", "held");
  const status = await clickAndWait(driver, "btn_spiffe_call_server",
    "spiffe_server_status");
  check("GetBundle answers over mutual TLS with the held SVID presented",
    function () {
      assert.ok(/^OK/.test(status), "the call did not succeed: " + status);
    });

  const peer = await el(driver, "spiffe_server_peer").getText();
  check("and the page reports WHO the server proved to be — its URI " +
    "subjectAltName, which is the only thing identifying it, because a SPIRE " +
    "server's certificate carries no DNS name at all", function () {
      assert.ok(peer.indexOf("spiffe://" + trustDomain + "/spire/server") >= 0,
        "the server's SPIFFE ID was not reported: " + peer);
      assert.ok(/no DNS name/.test(peer),
        "the pane has to say why hostname verification cannot apply: " + peer);
    });

  // THE INTERESTING NEGATIVE ON THIS WHOLE SURFACE. The chain verifies — it is
  // a real certificate from a trusted authority — and it names somebody else.
  await setField(driver, "spiffe_server_id",
    "spiffe://" + trustDomain + "/definitely-not-the-server");
  const mismatch = await clickAndWait(driver, "btn_spiffe_call_server",
    "spiffe_server_status");
  check("a server whose SPIFFE ID is not the expected one is refused, and " +
    "the page says the chain VERIFIED — which is what separates this from a " +
    "certificate problem and from a server that was not there", function () {
      assert.ok(/not who this call required/.test(mismatch), mismatch);
      assert.ok(/chain verified/.test(mismatch), mismatch);
    });
  await setField(driver, "spiffe_server_id", "");

  // Debug.GetInfo, refused to everything but the local socket — SPIRE's own
  // table, and the row that looks like an omission and is not.
  await selectOption(driver, "spiffe_server_service", "debug");
  await selectOption(driver, "spiffe_server_method", "GetInfo");
  const denied = await clickAndWait(driver, "btn_spiffe_call_server",
    "spiffe_server_status");
  check("Debug.GetInfo is refused over TCP however good the credential is — " +
    "it is local-only in SPIRE's own authorization table, and the page shows " +
    "the refusal as the ANSWER it is rather than as an error", function () {
      assert.ok(/PERMISSION_DENIED|UNAUTHENTICATED/.test(denied),
        "expected an authorization refusal and got: " + denied);
      assert.ok(/reached the server and the server refused it/.test(denied),
        "the status must distinguish \"SPIFFE said no\" from \"the call " +
        "failed\": " + denied);
    });

  const result = await el(driver, "spiffe_server_result").getText();
  check("and the result pane says what the server answered rather than " +
    "showing nothing", function () {
      assert.ok(/PERMISSION_DENIED|UNAUTHENTICATED/.test(result),
        result.slice(0, 200));
    });
  log.debug("Leaving theServerApiPresentsTheHeldIdentity().");
}

// ---------------------------------------------------------------------------
// 5. THE CSR BUILDER — five methods are unreachable without it.
// ---------------------------------------------------------------------------
async function theCsrBuilderMakesOneAndPlacesIt(driver) {
  log.debug("Entering theCsrBuilderMakesOneAndPlacesIt().");
  await setField(driver, "spiffe_csr_uri",
    "spiffe://" + trustDomain + "/page-minted");
  const status = await clickAndWait(driver, "btn_spiffe_build_csr",
    "spiffe_csr_status", stepWait * 2);
  const base64 = await getField(driver, "spiffe_csr_base64");
  const pem = await getField(driver, "spiffe_csr_pem");
  const key = await getField(driver, "spiffe_csr_key");
  check("a key pair and a PKCS#10 request are built IN THE BROWSER with Web " +
    "Crypto — a different implementation from the node one, and the reason " +
    "five of the forty-nine methods are reachable here at all", function () {
      assert.ok(/key pair/.test(status), status);
      assert.ok(base64.length > 100, "no base64 request");
      assert.ok(!/[^A-Za-z0-9+/=]/.test(base64),
        "a gRPC bytes field takes base64 with no PEM armour and no " +
        "whitespace, and node's base64 decoder is lenient enough to accept " +
        "something shorter and different without complaining");
      assert.ok(/^-----BEGIN CERTIFICATE REQUEST-----/.test(pem));
      assert.ok(/PRIVATE KEY/.test(key),
        "the private key stays here — that is the point of a certification " +
        "request, and it is what lets an SVID issued against this one be " +
        "presented afterwards");
    });

  // Place it, which is the part a person would otherwise do by hand between
  // two panes — and the four methods that take one put it in four different
  // places in the message.
  await selectOption(driver, "spiffe_server_service", "svid");
  await selectOption(driver, "spiffe_server_method", "MintX509SVID");
  const placed = await clickAndWait(driver, "btn_spiffe_insert_csr_server",
    "spiffe_csr_status", waitTime * 2);
  const request = await getField(driver, "spiffe_server_request");
  check("and it goes into the request editor's own csr field, wherever in " +
    "the message that method puts one", function () {
      assert.ok(/server editor/.test(placed), placed);
      assert.strictEqual(JSON.parse(request).csr, base64);
    });
  log.debug("Leaving theCsrBuilderMakesOneAndPlacesIt().");
}

// ---------------------------------------------------------------------------
// 6. THE OFFLINE PANES — no network at all.
// ---------------------------------------------------------------------------
async function theInspectorAndTheGrammarNeedNoNetwork(driver, token) {
  log.debug("Entering theInspectorAndTheGrammarNeedNoNetwork().");
  const cert = await getField(driver, "spiffe_identity_cert_view");
  await setField(driver, "spiffe_svid_input", cert);
  const x509Status = await clickAndWait(driver, "btn_spiffe_inspect_svid",
    "spiffe_svid_status", stepWait);
  check("an X509-SVID is read here, and the identity is taken from the URI " +
    "subjectAltName — the subject DN carries no meaning in SPIFFE, so a " +
    "reader who looks there is looking at the one field that never has it",
    function () {
      assert.ok(/X509-SVID for spiffe:\/\//.test(x509Status), x509Status);
      assert.ok(/trust domain/.test(x509Status), x509Status);
    });

  if (token) {
    await setField(driver, "spiffe_svid_input", token);
    const jwtStatus = await clickAndWait(driver, "btn_spiffe_inspect_svid",
      "spiffe_svid_status", stepWait);
    check("a JWT-SVID is read too, and the pane says that READING is not " +
      "VERIFYING — nothing here checks a signature, and ValidateJWTSVID is " +
      "the method that does", function () {
        assert.ok(/JWT-SVID/.test(jwtStatus), jwtStatus);
        assert.ok(/not verified|READ, not verified/.test(jwtStatus),
          "a pane that read a token and implied it had checked it would be " +
          "the most dangerous thing on this page: " + jwtStatus);
      });

    // The other half of what `open()` asserted: that box opened at two rows
    // because it was empty, and an answer has just been written into it
    // through `setVal()`. Runs IN THE BROWSER — no bunyan, no `log`.
    const grew = await driver.executeScript(
      "var e = document.getElementById('spiffe_svid_output');" +
      "return { rows: e.rows," +
      "         lines: String(e.value || '').split('\\n').length," +
      "         min: parseInt(e.getAttribute('data-min-rows'), 10)," +
      "         max: parseInt(e.getAttribute('data-max-rows'), 10) };");
    check("and the readout GREW to the answer it was given rather than " +
      "having reserved the room in advance — the page opens with this box " +
      "at two rows, and a described SVID is a dozen", function () {
        assert.ok(grew.lines > grew.min,
          "the inspector wrote " + grew.lines + " lines, which is no more " +
          "than the box already had — this check is now vacuous");
        assert.strictEqual(grew.rows,
          Math.max(grew.min, Math.min(grew.max, grew.lines)),
          "the box is " + grew.rows + " rows for " + grew.lines + " lines");
      });
  }

  // The grammar, which is stricter than a URL parser in four ways that each
  // produce an identifier looking perfectly fine in a log.
  await setField(driver, "spiffe_id_input", "spiffe://Example.org/x");
  await el(driver, "btn_spiffe_check_id").click();
  await driver.wait(async function () {
    const text = await el(driver, "spiffe_id_report").getText();
    return !!text;
  }, stepWait, "the SPIFFE ID checker never reported");
  const upper = await el(driver, "spiffe_id_report").getText();
  check("an upper-case trust domain is refused, and the page says it is not " +
    "another spelling of the lower-case one — a URL parser lower-cases the " +
    "host for you, which HIDES the defect rather than reporting it",
    function () {
      assert.ok(/lower-case/.test(upper), upper);
      assert.ok(/different identifiers/.test(upper), upper);
    });

  await setField(driver, "spiffe_id_input",
    "spiffe://" + trustDomain + "/spire/server");
  await el(driver, "btn_spiffe_check_id").click();
  await driver.wait(async function () {
    const text = await el(driver, "spiffe_id_report").getText();
    return /Valid/.test(text);
  }, stepWait, "the reserved path was not reported as valid");
  const reserved = await el(driver, "spiffe_id_report").getText();
  check("and a /spire path is valid AND flagged as reserved for the SPIFFE " +
    "implementation itself, which is why a registration entry there is " +
    "refused", function () {
      assert.ok(/RESERVED/.test(reserved), reserved);
    });

  await setField(driver, "spiffe_id_input",
    "spiffe://" + trustDomain + ".attacker.invalid/x");
  await el(driver, "btn_spiffe_check_id").click();
  await driver.wait(async function () {
    const text = await el(driver, "spiffe_id_report").getText();
    return /Valid/.test(text);
  }, stepWait, "the suffixed trust domain was not reported");
  const suffixed = await el(driver, "spiffe_id_report").getText();
  check("a suffixed trust domain is a VALID identifier that does NOT belong " +
    "— membership is a parsed comparison and never a prefix test, which is " +
    "an authorization bug in anything that federates", function () {
      assert.ok(/does NOT belong/.test(suffixed), suffixed);
      assert.ok(/prefix test/.test(suffixed), suffixed);
    });
  log.debug("Leaving theInspectorAndTheGrammarNeedNoNetwork().");
}

// ---------------------------------------------------------------------------
// 7. THE OPERATIONS HISTORY — Failure is not Sent.
// ---------------------------------------------------------------------------
async function theHistoryTellsARefusalFromNoAnswer(driver) {
  log.debug("Entering theHistoryTellsARefusalFromNoAnswer().");
  const rows = await el(driver, "spiffe_operation_history").getText();
  check("every call this page made is logged with the method, the surface " +
    "and the STATUS — so a PERMISSION_DENIED reads as an answer rather than " +
    "as a call that never happened", function () {
      assert.ok(/FetchX509SVID/.test(rows), rows.slice(0, 300));
      assert.ok(/Workload API/.test(rows), rows.slice(0, 300));
      assert.ok(/PERMISSION_DENIED|UNAUTHENTICATED/.test(rows),
        "the refusal has to be in the log with its code: " +
        rows.slice(0, 400));
      assert.ok(/Failure/.test(rows) && /Success/.test(rows),
        "both outcomes have to be distinguishable in the log");
      assert.ok(!/\bSent\b/.test(rows),
        "a row still reading Sent means the api never answered, and " +
        "everything above did answer: " + rows.slice(0, 400));
    });
  log.debug("Leaving theHistoryTellsARefusalFromNoAnswer().");
}

// ---------------------------------------------------------------------------
// 8. THE KEY-MATERIAL OPT-OUT — it must REMOVE, not merely stop writing.
// ---------------------------------------------------------------------------
async function theIdentityOptOutRemovesWhatIsStored(driver) {
  log.debug("Entering theIdentityOptOutRemovesWhatIsStored().");
  const stored = await driver.executeScript(
    "return { cert: localStorage.getItem('spiffe_identity_cert')," +
    "         key: localStorage.getItem('spiffe_identity_key') };");
  check("with the box ticked the identity is remembered, key included — " +
    "which is what makes it survive a reload, and is exactly why there is a " +
    "box", function () {
      assert.ok(stored.cert && stored.cert.length > 100,
        "nothing was stored");
      assert.ok(stored.key && stored.key.length > 20);
    });

  await setCheckbox(driver, "spiffe_save_identity", false);
  await waitForStatusValue(driver, "spiffe_identity_status",
    function (text) {
      return /removed/.test(text);
    }, "clearing the box did not report a purge");
  const after = await driver.executeScript(
    "return { cert: localStorage.getItem('spiffe_identity_cert')," +
    "         key: localStorage.getItem('spiffe_identity_key')," +
    "         pref: localStorage.getItem('spiffe_save_identity')," +
    "         other: localStorage.getItem('spiffe_trust_domain') };");
  check("clearing it REMOVES what is already stored rather than only " +
    "stopping future writes — an opt-out that left yesterday's private key " +
    "in the browser would not be one", function () {
      assert.strictEqual(after.cert, null, "the certificate is still stored");
      assert.strictEqual(after.key, null, "THE PRIVATE KEY IS STILL STORED");
      assert.strictEqual(after.pref, "0");
      assert.ok(after.other,
        "every other field on the page is still remembered — the opt-out is " +
        "about key material and nothing else");
    });

  const heldStill = await getField(driver, "spiffe_identity_id_view");
  check("and the identity is still usable in this page until it is reloaded, " +
    "because the box is about STORAGE rather than about the workflow",
    function () {
      assert.ok(/^spiffe:\/\//.test(heldStill), heldStill);
    });

  // Put it back, so a person re-driving this stack by hand finds the page in
  // the state it ships in.
  await setCheckbox(driver, "spiffe_save_identity", true);
  log.debug("Leaving theIdentityOptOutRemovesWhatIsStored().");
}

// ---------------------------------------------------------------------------
// 10. THE SHAPE OF THE PAGE — one settings pane, folded prose, and a tooltip
//     on everything.
//
// All three of these are properties a person sees at a glance and a protocol
// test cannot see at all, and each of them decays silently:
//
//   * **ONE PANE OWNS THE SETTINGS.** Every editable setting is in
//     `#pane_config`, grouped under the name of the pane it acts on. What is
//     allowed to be editable OUTSIDE it is a fixed list — the method pickers,
//     the two request editors and the two offline inputs — because those ARE
//     the operation rather than a setting for it. The **trust bundle** used
//     to be on that list and is not any more: its pane was folded into this
//     one whole on 2026-08-26, buttons and document and all, so its document
//     box is now INSIDE `#pane_config` and a copy of it left behind
//     somewhere else is what the check below would report. A new
//     field added to a pane below is what this catches, and a settings pane
//     that quietly grows a second copy of a field somewhere else is what the
//     duplicate-id check beside it catches: getElementById answers with the
//     first in document order, so the second box silently stops doing
//     anything. That is the same rule scim.js's `owns` exists to keep.
//   * **THE PROSE FOLDS, AND SHIPS CLOSED.** The explanations are why this
//     page is worth using, so they are folded rather than cut. One that
//     shipped `open` is prose back on the page, which is the state this was
//     changed away from.
//   * **EVERY FIELD AND BUTTON HAS A TOOLTIP.** With the prose folded, the
//     tooltip is the only explanation on screen for a control somebody is
//     looking straight at.
// ---------------------------------------------------------------------------
const EDITABLE_OUTSIDE_CONFIG = [
  // The expand / collapse-all switch. It is editable and it is outside the
  // settings pane, and it belongs on this list rather than in that pane: it
  // configures nothing, sends nothing and is not saved — it changes what is on
  // the screen, which is the one kind of control that must stay above the
  // panes it opens.
  "dbg_toggle_all",
  "spiffe_workload_method",
  "spiffe_workload_request",
  "spiffe_server_service",
  "spiffe_server_method",
  "spiffe_server_request",
  "spiffe_svid_input",
  "spiffe_id_input"
];

const CONFIG_GROUPS = [
  "Trust Domain",
  "Trust Bundle",
  "Workload API",
  "Held Identity",
  "SPIRE Server API",
  "Certification Request"
];

async function theSettingsAreInOnePaneAndTheProseFolds(driver) {
  log.debug("Entering theSettingsAreInOnePaneAndTheProseFolds().");
  // Everything below runs IN THE BROWSER, so it has no bunyan and no `log` —
  // see the repo-root CLAUDE.md. What is logged is what it returns.
  const shape = await driver.executeScript(
    "var conf = document.getElementById('pane_config');" +
    "var all = document.querySelectorAll('input, select, textarea');" +
    "var outside = [], untitled = [], ids = {}, dupes = [];" +
    "for (var i = 0; i < all.length; i++) {" +
    "  var e = all[i];" +
    "  if (e.id) { ids[e.id] = (ids[e.id] || 0) + 1; }" +
    "  if (!e.title || !e.title.trim()) { untitled.push(e.id || e.outerHTML" +
    "      .slice(0, 40)); }" +
    "  var editable = !e.readOnly && e.type !== 'button';" +
    "  if (editable && !(conf && conf.contains(e))) {" +
    "    outside.push(e.id || e.outerHTML.slice(0, 40));" +
    "  }" +
    "}" +
    "for (var id in ids) { if (ids[id] > 1) { dupes.push(id); } }" +
    "var folds = document.querySelectorAll('details.spiffe-more');" +
    "var openFolds = [];" +
    "for (var f = 0; f < folds.length; f++) {" +
    "  if (folds[f].open) { openFolds.push(folds[f].querySelector('summary')" +
    "      .textContent.slice(0, 40)); }" +
    "}" +
    "var titles = [];" +
    "var heads = conf ? conf.querySelectorAll('.spiffe-group-title') : [];" +
    "for (var h = 0; h < heads.length; h++) {" +
    "  titles.push(heads[h].textContent.trim());" +
    "}" +
    "var prose = document.querySelectorAll('p.spiffe-note, p.spiffe-intro');" +
    "var unfolded = [];" +
    "for (var q = 0; q < prose.length; q++) {" +
    "  if (prose[q].id) { continue; }" +
    "  if (!prose[q].closest('details.spiffe-more')) {" +
    "    unfolded.push(prose[q].textContent.trim().slice(0, 40)); }" +
    "}" +
    "var bundle = ['spiffe_bundle_ssl', 'btn_spiffe_fetch_bundle'," +
    "  'btn_spiffe_read_bundle', 'btn_spiffe_bundle_anchor'," +
    "  'spiffe_bundle_status', 'spiffe_bundle_document'," +
    "  'spiffe_bundle_report'];" +
    "var strayed = [];" +
    "for (var b = 0; b < bundle.length; b++) {" +
    "  var node = document.getElementById(bundle[b]);" +
    "  if (!node || !(conf && conf.contains(node))) {" +
    "    strayed.push(bundle[b]); }" +
    "}" +
    "return { outside: outside, untitled: untitled, dupes: dupes," +
    "         openFolds: openFolds, folds: folds.length, titles: titles," +
    "         unfolded: unfolded, strayed: strayed," +
    "         ownPane: !!document.getElementById('pane_bundle') };");

  check("every editable setting is in the Configuration Parameters pane — " +
    "what is editable outside it is the operation itself, and that list is " +
    "fixed", function () {
      assert.deepStrictEqual(shape.outside.slice().sort(),
        EDITABLE_OUTSIDE_CONFIG.slice().sort());
    });

  check("the trust bundle is in that pane WHOLE — the switch, the three " +
    "buttons, the status line, the document and the report — and has no " +
    "pane of its own left behind: a fold that moved the document and left " +
    "the buttons where they were would read as a reader with nothing to " +
    "read", function () {
      assert.deepStrictEqual(shape.strayed, []);
      assert.strictEqual(shape.ownPane, false,
        "#pane_bundle is still in the page, so the trust bundle is in two " +
        "places at once");
    });

  check("no id appears twice — a settings pane that mirrors a field instead " +
    "of owning it puts two elements under one id, and getElementById " +
    "answers with the first, so the other box silently does nothing",
    function () {
      assert.deepStrictEqual(shape.dupes, []);
    });

  check("the pane's groups are the panes the settings came from, in order, " +
    "and the Trust Bundle group is the one that is not a settings group at " +
    "all — the whole of that pane was folded in here", function () {
      assert.deepStrictEqual(shape.titles, CONFIG_GROUPS);
    });

  check("every field and button on the page carries a tooltip — with the " +
    "prose folded it is the only explanation on screen for a control " +
    "somebody is looking straight at", function () {
      assert.deepStrictEqual(shape.untitled, []);
    });

  check("every explanation on the page is inside a fold", function () {
      assert.deepStrictEqual(shape.unfolded, []);
      assert.ok(shape.folds >= 15,
        "only " + shape.folds + " folds — the prose has been cut rather " +
        "than folded");
    });

  check("and every fold ships CLOSED: one that shipped open is prose back " +
    "on the page", function () {
      assert.deepStrictEqual(shape.openFolds, []);
    });

  log.debug("Leaving theSettingsAreInOnePaneAndTheProseFolds().");
}

// ---------------------------------------------------------------------------
// 11. THE PANES COLLAPSE, and one switch does all of them.
//
// This page is long enough that the answer somebody wants is often four panes
// below the one they are working in, so every pane shuts. It uses the shared
// `.dbg-*` chrome from css/debugger.css that the rest of the tree uses rather
// than a fourth implementation of it — a `div.dbg-pane` holding a
// `.dbg-legend` title and the `fieldset` that title opens and shuts.
//
// Three properties, and each fails silently on its own:
//
//   * **THE PAIRING IS BY ID.** `x_expand_button` drives `x_fieldset`, wired
//     in `wirePanes()` rather than by an inline onclick that would spell the
//     id twice. A drifted pair is a title that does nothing at all, and the
//     only other thing that would report it is a console warning — which is
//     why section 9 asserting a clean console is part of this check rather
//     than beside it.
//   * **THE COLLAPSE IS REAL.** The triangle in the legend is a CSS `:has()`
//     rule reading the fieldset's INLINE display, so a pane can perfectly well
//     turn its triangle while staying on the screen. This asserts the height,
//     not the marker.
//   * **THE SWITCH REACHES EVERY PANE.** `setAllPanes()` discovers the
//     fieldsets off the DOM instead of holding a list, so this counts them:
//     a list would be a thing a new pane has to be remembered into, and the
//     only symptom of forgetting is the one pane the switch skips.
// ---------------------------------------------------------------------------
async function everyPaneCollapsesAndOneSwitchDoesAll(driver) {
  log.debug("Entering everyPaneCollapsesAndOneSwitchDoesAll().");
  // Runs IN THE BROWSER, so it has no bunyan and no `log` — see the repo-root
  // CLAUDE.md. What is logged is what it returns.
  const wiring = await driver.executeScript(
    "var legends = document.querySelectorAll('.dbg-legend');" +
    "var drifted = [], shut = 0;" +
    "for (var i = 0; i < legends.length; i++) {" +
    "  var id = legends[i].id || '';" +
    "  var bodyId = id.replace('_expand_button', '_fieldset');" +
    "  var body = document.getElementById(bodyId);" +
    "  if (id.indexOf('_expand_button') === -1 || !body) {" +
    "    drifted.push(id || legends[i].textContent.trim()); continue; }" +
    "  if (body.style.display === 'none') { shut += 1; }" +
    "}" +
    "return { legends: legends.length, drifted: drifted, shut: shut," +
    "         fieldsets: document.querySelectorAll('.dbg-pane > fieldset')" +
    "             .length," +
    "         toggle: !!document.getElementById('dbg_toggle_all') };");

  check("every pane title names the fieldset it opens — the pairing is " +
    "`x_expand_button` drives `x_fieldset`, and a drifted pair is a title " +
    "that does nothing with nothing in the page complaining", function () {
      assert.deepStrictEqual(wiring.drifted, []);
      assert.ok(wiring.legends >= 9,
        "only " + wiring.legends + " pane titles — a pane has stopped being " +
        "one, and this check now guards the rest of them and not it");
      assert.strictEqual(wiring.fieldsets, wiring.legends,
        wiring.fieldsets + " collapsible fieldsets for " + wiring.legends +
        " titles: a pane is either untitled or holds more than one");
      assert.ok(wiring.toggle, "there is no dbg_toggle_all on the page");
    });

  // One pane, by its own title. `spiffe_workload_fieldset` is chosen because
  // it is the pane a reader is most often in, and because it is the first one
  // BELOW the settings pane — the trust bundle used to be that pane and was
  // folded into the settings one, which is exactly the kind of move that
  // leaves a check pointing at an id nothing answers to.
  const legend = await el(driver, "spiffe_workload_expand_button");
  await legend.click();
  await driver.wait(async function () {
    const shut = await driver.executeScript(
      "return document.getElementById('spiffe_workload_fieldset')" +
      "  .offsetHeight === 0;");
    return shut === true;
  }, stepWait, "the Workload API pane never closed when its title was clicked");
  const closed = await driver.executeScript(
    "var f = document.getElementById('spiffe_workload_fieldset');" +
    "return { height: f.offsetHeight, display: f.style.display," +
    "         marker: getComputedStyle(document.getElementById(" +
    "             'spiffe_workload_expand_button'), '::before').content };");
  check("a pane's own title shuts it, and the triangle in that title turns " +
    "with it — the marker is a CSS :has() rule reading the inline display, " +
    "so it can turn over a pane that is still on the screen, which is why " +
    "the HEIGHT is what is asserted here", function () {
      assert.strictEqual(closed.height, 0);
      assert.strictEqual(closed.display, "none");
      assert.ok(/\u25b8/.test(closed.marker), "the collapsed triangle is " +
        "still " + JSON.stringify(closed.marker));
    });
  await legend.click();
  await driver.wait(async function () {
    const open = await driver.executeScript(
      "return document.getElementById('spiffe_workload_fieldset')" +
      "  .offsetHeight > 0;");
    return open === true;
  }, stepWait, "the Workload API pane never reopened");

  // And the switch, which is the control this page needs most: with every
  // pane shut it is a table of contents.
  const before = await driver.executeScript(
    "return document.documentElement.scrollHeight;");
  await driver.findElement(By.css(".dbg-toggle-slider")).click();
  await driver.wait(async function () {
    const done = await driver.executeScript(
      "var fs = document.querySelectorAll('.dbg-pane > fieldset');" +
      "for (var i = 0; i < fs.length; i++) {" +
      "  if (fs[i].style.display !== 'none') { return false; } }" +
      "return fs.length > 0;");
    return done === true;
  }, stepWait, "the collapse-all switch left at least one pane open");
  const afterCollapse = await driver.executeScript(
    "var fs = document.querySelectorAll('.dbg-pane > fieldset');" +
    "var shut = 0;" +
    "for (var i = 0; i < fs.length; i++) {" +
    "  if (fs[i].style.display === 'none') { shut += 1; } }" +
    "return { total: fs.length, shut: shut," +
    "         checked: document.getElementById('dbg_toggle_all').checked," +
    "         text: document.querySelector('.dbg-toggle-text').textContent," +
    "         height: document.documentElement.scrollHeight };");
  check("the one switch shuts EVERY pane, not a list of them — " +
    "setAllPanes() reads the fieldsets off the DOM, so a pane added later is " +
    "covered by construction rather than by somebody remembering a list",
    function () {
      assert.strictEqual(afterCollapse.shut, afterCollapse.total,
        afterCollapse.shut + " of " + afterCollapse.total + " panes shut");
      assert.ok(afterCollapse.height < before,
        "the page is still " + afterCollapse.height + "px with every pane " +
        "collapsed, against " + before + "px open — the panes turned their " +
        "markers and stayed where they were");
      assert.strictEqual(afterCollapse.checked, false);
    });

  check("and the switch's own label says what it will do NEXT rather than " +
    "what it just did — a switch reading `Collapse all panes` over a page " +
    "of collapsed panes is the one state that reads as broken", function () {
      assert.ok(/Expand all panes/.test(afterCollapse.text),
        afterCollapse.text);
    });

  await driver.findElement(By.css(".dbg-toggle-slider")).click();
  await driver.wait(async function () {
    const open = await driver.executeScript(
      "var fs = document.querySelectorAll('.dbg-pane > fieldset');" +
      "for (var i = 0; i < fs.length; i++) {" +
      "  if (fs[i].style.display === 'none') { return false; } }" +
      "return fs.length > 0;");
    return open === true;
  }, stepWait, "the switch did not put the panes back");
  log.debug("Leaving everyPaneCollapsesAndOneSwitchDoesAll().");
}

// ---------------------------------------------------------------------------
// 12. THE FIELD NAMES CARRY THE TOOLTIP TOO.
//
// Section 10 asserts that every control has one. That is half of it: a reader
// scanning a pane reads the NAMES, and on this page a name is a `<label>` with
// its own hit area beside the box rather than on it — so a tooltip that lives
// only on the control is one that is not there when the pointer is over the
// word that made somebody wonder.
//
// The two must be the SAME text, which is the part that decays: a tooltip
// improved on the control and left alone on the label is a page that explains
// one field two different ways depending on where the pointer is.
// ---------------------------------------------------------------------------
async function everyFieldNameCarriesItsTooltip(driver) {
  log.debug("Entering everyFieldNameCarriesItsTooltip().");
  // Runs IN THE BROWSER — no bunyan, no `log`.
  const labels = await driver.executeScript(
    "var all = document.querySelectorAll('label');" +
    "var untitled = [], mismatched = [], paired = 0;" +
    "for (var i = 0; i < all.length; i++) {" +
    "  var l = all[i];" +
    "  var text = l.textContent.trim().slice(0, 40);" +
    "  if (!l.title || !l.title.trim()) { untitled.push(text); continue; }" +
    "  var c = l.htmlFor ? document.getElementById(l.htmlFor) :" +
    "      l.querySelector('input, select, textarea');" +
    "  if (!c) { continue; }" +
    "  paired += 1;" +
    "  if (c.title && c.title !== l.title) {" +
    "    mismatched.push(c.id || text); } }" +
    "return { total: all.length, untitled: untitled," +
    "         mismatched: mismatched, paired: paired };");

  check("every field NAME carries a tooltip and not only the box beside it " +
    "— a label has its own hit area, and an explanation that is absent over " +
    "the word which raised the question is an explanation nobody finds",
    function () {
      assert.deepStrictEqual(labels.untitled, []);
      assert.ok(labels.total >= 30,
        "only " + labels.total + " labels on the page");
    });

  check("and the label says exactly what its control says — one field " +
    "explained two different ways depending on where the pointer is would " +
    "be worse than explaining it once", function () {
      assert.deepStrictEqual(labels.mismatched, []);
      assert.ok(labels.paired >= 30,
        "only " + labels.paired + " labels are paired with a control, so " +
        "this check compared almost nothing");
    });
  log.debug("Leaving everyFieldNameCarriesItsTooltip().");
}

// ---------------------------------------------------------------------------
// 9. THE STYLESHEET, and the console.
// ---------------------------------------------------------------------------
async function everyStyleClassIsDefined(driver) {
  log.debug("Entering everyStyleClassIsDefined().");
  // The guard tests/navigation.js makes for the pages it walks, repeated here
  // because it cannot walk to this one: a `spiffe-` class the sheet does not
  // define renders unstyled, and the link resolves so nothing 404s.
  const undefinedClasses = await driver.executeScript(
    "var used = {};" +
    "var nodes = document.querySelectorAll('[class]');" +
    "for (var i = 0; i < nodes.length; i++) {" +
    "  var names = String(nodes[i].className).split(/\\s+/);" +
    "  for (var j = 0; j < names.length; j++) {" +
    "    if (names[j].indexOf('spiffe-') === 0) { used[names[j]] = true; }" +
    "  }" +
    "}" +
    "var defined = {};" +
    "for (var s = 0; s < document.styleSheets.length; s++) {" +
    "  var rules;" +
    "  try { rules = document.styleSheets[s].cssRules; } catch (e) { continue; }" +
    "  if (!rules) { continue; }" +
    "  for (var r = 0; r < rules.length; r++) {" +
    "    var selector = rules[r].selectorText || '';" +
    "    var found = selector.match(/\\.spiffe-[A-Za-z0-9-]+/g) || [];" +
    "    for (var f = 0; f < found.length; f++) {" +
    "      defined[found[f].slice(1)] = true;" +
    "    }" +
    "  }" +
    "}" +
    "return Object.keys(used).filter(function (name) {" +
    "  return !defined[name];" +
    "});");
  check("every spiffe- class the page uses is defined in css/spiffe.css — " +
    "the WS-Federation pages once linked the wrong sheet after a rename and " +
    "rendered completely unstyled, and nothing 404'd", function () {
      assert.deepStrictEqual(undefinedClasses, []);
    });
  log.debug("Leaving everyStyleClassIsDefined().");
}

async function theConsoleIsClean(driver) {
  log.debug("Entering theConsoleIsClean().");
  const entries = await driver.manage().logs().get("browser");
  const severe = entries.filter(function (entry) {
    return entry.level && entry.level.name === "SEVERE" &&
      // A 400 or a 502 the page ASKED for is not a page defect: several of the
      // sections above drive a refusal on purpose, and Chrome logs the failed
      // fetch as SEVERE either way.
      !/the server responded with a status of (400|401|403|404|502)/
        .test(entry.message) &&
      // Nor is a load the browser abandoned because its own certificate or
      // network configuration changed under it. See browser_flags.js.
      !browserFlags.isTransientLoadError(entry.message);
  });
  check("nothing threw in the page", function () {
    assert.deepStrictEqual(severe.map(function (entry) {
      return entry.message.slice(0, 200);
    }), []);
  });
  log.debug("Leaving theConsoleIsClean().");
}

async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const response = await fetch(apiUrl + "/spiffe/limits");
    if (response.status === 404) {
      log.debug("Leaving preconditions(). 404.");
      return { ok: false, why: "the api at " + apiUrl + " answered 404 for " +
        "GET /spiffe/limits, so this build has no SPIFFE support. That is a " +
        "different thing from a SPIRE server that will not answer." };
    }
    if (!response.ok) {
      log.debug("Leaving preconditions(). Not ok.");
      return { ok: false, why: "GET /spiffe/limits answered " +
        response.status };
    }
  } catch (e) {
    log.debug("Leaving preconditions(). Unreachable.");
    return { ok: false, why: "the api at " + apiUrl + " could not be " +
      "reached (" + e.message + "). This deployment has no api behind it, " +
      "so neither of SPIFFE's gRPC surfaces exists here — which is the known " +
      "state of a static site rather than something to go looking for." };
  }
  log.debug("Leaving preconditions(). Ready.");
  return { ok: true };
}

async function test() {
  log.debug("Entering test().");
  const ready = await preconditions();
  if (!ready.ok) {
    log.warn("SKIP: " + ready.why);
    log.info("Test skipped.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("driving " + baseUrl + "/spiffe.html against the api at " + apiUrl +
    ", which will dial " + workloadAddress + " and " + serverAddress);

  // The workload the CSR pane mints an SVID for, in the applications registry,
  // before it does. The SPIFFE REGISTRATION — what decides whether an SVID is
  // issued at all — is a different register and is the SPIRE API's business;
  // this is the record of the party, under `spiffeWorkloadId`, which is the
  // identifier attribute of that family. tests/spiffe_protocol.js's copy of
  // this argues the distinction at length.
  await registry.provision(registry.baseOf(stsUrl), {
    identifier: "spiffe://" + trustDomain + "/page-minted",
    name: "SPIFFE page CSR workload",
    protocols: ["spiffe"],
    fields: { spiffeWorkloadId: ["spiffe://" + trustDomain + "/page-minted"] },
    why: "the identity the certification request pane asks MintX509SVID for"
  });

  const options = new chrome.Options();
  // --headless=new, never bare --headless, and headless is not optional: a CI
  // runner and the tests container have no display, so a windowed session
  // fails at `session not created` naming the page it was about to visit.
  options.addArguments("--headless=new", "--no-sandbox",
    "--disable-dev-shm-usage", "--window-size=1400,1800");
  // This page DOES need Web Crypto — the certification request pane generates
  // a key pair and signs with it — so the secure-context flag matters here:
  // the containerized stack serves the debugger at http://client:3000, plain
  // HTTP on a DNS name, where crypto.subtle is undefined and the failure names
  // a key pair that never arrived rather than a missing secure context.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // Ed25519 is one of the key algorithms the CSR pane offers and Chrome 121 —
  // which the tests image pins — has it behind a flag. A host run passes
  // without this, which is why only the containerized suite ever sees it.
  if (browserFlags.addWebCryptoEd25519Flags) {
    browserFlags.addWebCryptoEd25519Flags(options);
  }
  const driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).build();

  try {
    await open(driver);
    await thePickersHoldEveryMethod(driver);
    await theBundleGroupFetchesAndReads(driver);
    const token = await theWorkloadApiHandsOverAnIdentity(driver);
    await theServerApiPresentsTheHeldIdentity(driver);
    await theCsrBuilderMakesOneAndPlacesIt(driver);
    await theInspectorAndTheGrammarNeedNoNetwork(driver, token);
    await theHistoryTellsARefusalFromNoAnswer(driver);
    await theIdentityOptOutRemovesWhatIsStored(driver);
    await theSettingsAreInOnePaneAndTheProseFolds(driver);
    await everyPaneCollapsesAndOneSwitchDoesAll(driver);
    await everyFieldNameCarriesItsTooltip(driver);
    await everyStyleClassIsDefined(driver);
    await theConsoleIsClean(driver);
    log.info(checks + " checks passed.");
    assert.ok(checks >= 20,
      "Only " + checks + " checks ran. A section has stopped being called.");
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("spiffe_page")
  .description("Verify the SPIFFE Protocol Debugger page: that all " +
    "forty-nine methods reach its pickers, that an SVID fetched from a " +
    "surface which authenticates nobody is then PRESENTED on one that " +
    "requires mutual TLS, that the certification request five methods need " +
    "is built in the browser, that the three offline readers need no " +
    "network, and that the key-material opt-out removes what is already " +
    "stored.")
  .addOption(new Option("-u, --url <url>",
    "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
