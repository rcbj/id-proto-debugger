// File: ssf_page.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS DEBUGGER PAGE, IN A BROWSER, AGAINST A REAL TRANSMITTER.
//
// `ssf_engine.js` proves what this workflow COMPOSES and `ssf_protocol.js`
// proves that a real transmitter accepts it. Neither loads the page, and the
// things that only break there are the ones this file exists for:
//
//   * the bundle. A page whose `<script>` 404s does nothing at all, and every
//     other kind of test still passes;
//   * the two histories, which are the thing the workflow was asked for —
//     every set of tokens used, and every event sent or received;
//   * WHO THE AUTHENTICATED USER IS, which is read off the ID Token the
//     OAuth2 / OIDC hand-off carries. Nothing else in this suite exercises
//     the extended hand-off at all;
//   * the `callPath` row, which is the ONE control this page disables on a
//     deployment with no api — and it is disabled the way `pki.js` disables
//     its TLS pane, SWITCHED OFF rather than merely marked, because a radio
//     that only looks grey is still selectable with a keyboard;
//   * the `ssf-` classes, which `checkStylesheetsLoaded()`'s rule applies to;
//   * a clean console, which is where a handler that threw shows up and
//     nowhere else.
//
// **TWO ENVIRONMENT HAZARDS APPLY AND BOTH HAVE COST THIS SUITE A RUN
// BEFORE.** `--headless=new` and never bare `--headless`, or a runner with no
// display fails at `session not created` naming the page it was about to
// visit. And `browser_flags.js`, because this page fetches the api and the
// transmitter on loopback from whatever origin the suite is pointed at — a
// Private Network Access request Chrome blocks or preflights, whose symptom is
// a status line that never fills and a timeout naming an element rather than
// the network.
//
// **THIS PAGE GENERATES A KEY PAIR AND SIGNS.** It does it through `jws.js`,
// which is the pure-JavaScript engine and not Web Crypto, precisely so that it
// works on the containerized suite's `http://client:3000` origin where
// `crypto.subtle` does not exist at all. The transmit section is what asserts
// that, and it would be the first thing to fail if that ever changed.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ssf_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var apiUrl = process.env.API_URL || "https://localhost:4000";
// The transmitter as the BROWSER must reach it, which on the containerized
// stack is not the name this test uses and not the name the api uses. Three
// different answers to one question, and confusing them has cost this suite a
// run before — see tests/CLAUDE.md.
var stsUrl = process.env.SSF_TRANSMITTER_URL ||
    process.env.WSTRUST_STS_URL || "https://localhost:8081";

const WAIT = 20000;

let created = [];

async function fill(driver, id, value) {
  log.debug("Entering fill(). " + id);
  const field = await driver.findElement(By.id(id));
  await field.clear();
  if (value) {
    await field.sendKeys(value);
  }
  log.debug("Leaving fill().");
}

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  await driver.findElement(By.id(id)).click();
  log.debug("Leaving click().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). " + id);
  const value = await driver.findElement(By.id(id)).getText();
  log.debug("Leaving textOf().");
  return value;
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf(). " + id);
  const value = await driver.findElement(By.id(id))
      .getAttribute("value");
  log.debug("Leaving valueOf().");
  return value;
}

// WAIT ON CONTENT AND NOT ON AN ELEMENT. Every readout on this page exists in
// the markup from the first paint, so `until.elementLocated` returns
// immediately and the assertion that follows reads an empty box. The rule
// tests/CLAUDE.md states, and the reason half of this suite's flakes were
// that shape.
async function waitForValue(driver, id, what) {
  log.debug("Entering waitForValue(). " + id);
  await driver.wait(async function () {
    const value = await valueOf(driver, id);
    return value !== null && value !== "" &&
      !/^(Asking|Fetching|Generating|Signing)/.test(value);
  }, WAIT, "the " + what + " never filled in (#" + id + ")");
  const value = await valueOf(driver, id);
  log.debug("Leaving waitForValue(). " + value.slice(0, 80));
  return value;
}

async function waitForText(driver, id, what) {
  log.debug("Entering waitForText(). " + id);
  await driver.wait(async function () {
    const value = await textOf(driver, id);
    return value !== null && value.trim() !== "";
  }, WAIT, "the " + what + " never filled in (#" + id + ")");
  const value = await textOf(driver, id);
  log.debug("Leaving waitForText(). " + value.slice(0, 80));
  return value;
}

// ---------------------------------------------------------------------------
// 1. THE PAGE LOADS AND ITS BUNDLE RAN.
// ---------------------------------------------------------------------------
async function thePageLoadsAndTheBundleRan(driver) {
  log.debug("Entering thePageLoadsAndTheBundleRan().");
  log.info("=== The page and its bundle ===");
  await driver.get(baseUrl + "/ssf.html");
  await driver.wait(until.elementLocated(By.id("pane_metadata")), WAIT,
      "ssf.html did not load");
  // The bundle's global. A page whose <script> 404s renders perfectly and
  // does nothing at all, and every inline handler on it is a ReferenceError —
  // which is the failure this one line catches and no other test would.
  const wired = await driver.executeScript(
      "return typeof window.ssf === 'object' && " +
      "typeof window.ssf.discover === 'function';");
  assert.strictEqual(wired, true,
      "window.ssf is not the bundle's standalone global. Either " +
      "public/js/ssf.js 404'd or the --standalone name in client/Dockerfile " +
      "disagrees with client/build.js — in which case every onclick on this " +
      "page is a ReferenceError and nothing works.");
  // The pickers are built by onload() from the modules, so an empty one means
  // the module load failed rather than the markup being wrong.
  const counts = await driver.executeScript(
      "return { formats: document.getElementById('ssf_subject_format')" +
      "           .options.length," +
      "         types: document.getElementById('ssf_tx_type').options.length," +
      "         algs: document.getElementById('ssf_tx_alg').options.length };");
  assert.strictEqual(counts.formats, 9,
      "The subject format picker has " + counts.formats + " options. RFC " +
      "9493 defines eight formats and SSF adds the complex subject, so it " +
      "should have nine.");
  assert.strictEqual(counts.types, 2,
      "The event type picker has " + counts.types + " options. SSF 1.0 " +
      "defines two event types of its own; CAEP and RISC are later parts of " +
      "this work.");
  assert.ok(counts.algs > 20,
      "The signing algorithm picker has only " + counts.algs + " options. It " +
      "is built from jws.js's whole table, which carries the post-quantum " +
      "and composite families — a SET is the document here most worth " +
      "signing that way.");
  log.info("[page] OK — the bundle ran, and the three pickers are built " +
      "from the modules.");
  log.debug("Leaving thePageLoadsAndTheBundleRan().");
}

// ---------------------------------------------------------------------------
// 2. THE `callPath` ROW.
// ---------------------------------------------------------------------------
async function theCallPathRowReflectsWhetherThereIsAnApi(driver) {
  log.debug("Entering theCallPathRowReflectsWhetherThereIsAnApi().");
  log.info("=== The callPath row ===");
  const state = await driver.executeScript(
      "var radio = document.getElementById('ssf_cfg_callPath_api');" +
      "var row = document.getElementById('ssf_config_callpath_row');" +
      "var note = document.getElementById('ssf_callpath_note');" +
      "return { disabled: radio.disabled, checked: radio.checked," +
      "         greyed: row.className.indexOf('ssf-path-disabled') >= 0," +
      "         noteShown: note.className.indexOf('ssf-hidden') < 0," +
      "         noteText: note.textContent };");
  // WHETHER THERE IS AN api IS THE CLIENT BUILD'S ANSWER AND NOT THIS
  // TEST'S. `backendAvailable` is baked into the bundle by envify at build
  // time from `client/src/env/*.js`; this file's own configuration is the
  // TESTS' one and knows nothing about it. So the page is asked what it
  // decided, and the api is probed separately — and the two must agree,
  // which is itself the check: a build that says there is a backend and has
  // none offers a call path every request will fail on.
  const apiAnswers = await fetch(apiUrl + "/ssf/limits").then(function (r) {
    return r.ok;
  }).catch(function () {
    return false;
  });
  const backendAvailable = !state.disabled;
  assert.strictEqual(backendAvailable, apiAnswers,
      "The page " + (backendAvailable ? "offers" : "does not offer") +
      " the BackEnd call path and the api at " + apiUrl + " " +
      (apiAnswers ? "answers" : "does not answer") + ". Those have to " +
      "agree: a build that offers a path with nothing behind it produces a " +
      "fetch failure on every call, which reads as a broken transmitter.");
  if (backendAvailable) {
    assert.strictEqual(state.disabled, false,
        "This build has an api and the BackEnd call path is disabled.");
    log.info("[callPath] OK — there is an api, so both paths are offered.");
  } else {
    // SWITCHED OFF rather than merely marked, which is the distinction
    // css/pki.css records about its own disabled pane: a control that only
    // LOOKS grey is still reachable with a keyboard, and the refusal would
    // then come from a fetch to an api that is not there — which reads as a
    // broken page rather than as a build without a backend.
    assert.strictEqual(state.disabled, true,
        "This build has no api and the BackEnd radio is still selectable.");
    assert.strictEqual(state.checked, false);
    assert.strictEqual(state.greyed, true,
        "The row is not greyed, so nothing on the page says why the option " +
        "cannot be taken.");
    assert.strictEqual(state.noteShown, true);
    assert.ok(state.noteText.indexOf("PUSH") >= 0,
        "The note has to say that PUSH delivery is unavailable too — that is " +
        "the consequence a reader cannot work out for themselves, and it is " +
        "RFC 8935 rather than a limitation of this tool.");
    log.info("[callPath] OK — no api, and the row is switched off with a " +
        "reason.");
  }
  log.debug("Leaving theCallPathRowReflectsWhetherThereIsAnApi().");
}

// ---------------------------------------------------------------------------
// 3. DISCOVERY.
// ---------------------------------------------------------------------------
async function discoveryReadsEveryMember(driver) {
  log.debug("Entering discoveryReadsEveryMember().");
  log.info("=== Discovery ===");
  await fill(driver, "ssf_base_url", stsUrl);
  await click(driver, "btn_ssf_discover");
  const status = await waitForValue(driver, "ssf_discover_status",
      "discovery status");
  assert.ok(status.indexOf("Read from") === 0,
      "Discovery said: " + status);
  const table = await waitForText(driver, "ssf_metadata_table",
      "metadata table");
  ["issuer", "jwks_uri", "configuration_endpoint", "status_endpoint",
   "add_subject_endpoint", "remove_subject_endpoint",
   "verification_endpoint", "delivery_methods_supported",
   "default_subjects", "authorization_schemes"].forEach(function (member) {
    assert.ok(table.indexOf(member) >= 0,
        "The metadata table does not mention " + member + ". A reader cannot " +
        "tell a missing OPTIONAL member from a missing REQUIRED one by " +
        "looking, which is why every one is drawn whether it is there or " +
        "not.");
  });
  // The event checkbox column is built from the transmitter's own
  // events_supported, so an empty one means discovery did not reach it.
  const boxes = await driver.executeScript(
      "return document.querySelectorAll('.ssf-event-choice').length;");
  assert.ok(boxes >= 2,
      "The events_requested column has " + boxes + " boxes. It is built from " +
      "the transmitter's own events_supported.");
  log.info("[discovery] OK — every member drawn, and " + boxes +
      " event type(s) offered.");
  log.debug("Leaving discoveryReadsEveryMember().");
}

// ---------------------------------------------------------------------------
// 4. A STREAM, END TO END.
// ---------------------------------------------------------------------------
async function aStreamIsCreatedAndRead(driver) {
  log.debug("Entering aStreamIsCreatedAndRead().");
  log.info("=== The stream ===");
  // The credential. SSF 1.0 section 8 requires these endpoints to be
  // protected and this transmitter publishes what it accepts in
  // `authorization_schemes`; BASIC is chosen for the reason
  // tests/ssf_protocol.js chooses it — it is the only scheme that needs
  // nothing but a header, so an authorization server having a bad day cannot
  // make the stream sections fail and read as SSF.
  await driver.executeScript(
      "document.getElementById('ssf_auth_scheme').value = 'basic';" +
      "window.ssf.authSchemeChanged();");
  const shown = await driver.executeScript(
      "return document.getElementById('ssf_basic_row')" +
      "  .className.indexOf('ssf-hidden') < 0;");
  assert.strictEqual(shown, true,
      "The Basic credentials row stayed hidden when its scheme was chosen. " +
      "Those two fields are the one pair on this page never written to " +
      "storage, so a reader who cannot see them cannot tell that from a " +
      "field that is simply empty.");
  await fill(driver, "ssf_basic_user", "ssf-page-runner");
  await fill(driver, "ssf_basic_password", "pw");
  await fill(driver, "ssf_stream_aud",
      "https://receiver.example.com/ssf-page");
  await fill(driver, "ssf_stream_description", "ssf_page.js");
  await driver.executeScript(
      "document.getElementById('ssf_stream_delivery').value = " +
      "'urn:ietf:rfc:8936'; window.ssf.deliveryChanged();");
  await click(driver, "btn_ssf_create");
  const status = await waitForValue(driver, "ssf_stream_status_text",
      "stream status");
  assert.ok(status.indexOf("Created") === 0,
      "Creating a stream said: " + status);
  const id = await valueOf(driver, "ssf_stream_id");
  assert.ok(id.length > 0, "No stream_id came back.");
  created.push(id);
  const view = await waitForText(driver, "ssf_stream_view", "stream view");
  assert.ok(view.indexOf("events_delivered") >= 0);
  assert.ok(view.indexOf("transmitter") >= 0,
      "The stream table has to say WHOSE each member is — some are the " +
      "receiver's to set and some are the transmitter's to answer with, and " +
      "a page that let somebody type a stream_id would be offering a control " +
      "with no effect.");
  log.info("[stream] OK — created " + id + ".");
  log.debug("Leaving aStreamIsCreatedAndRead().");
}

// ---------------------------------------------------------------------------
// 5. SUBJECTS, AND THE REFUSAL THAT NAMES THE MEMBER.
// ---------------------------------------------------------------------------
async function theSubjectPaneChecksBeforeItSends(driver) {
  log.debug("Entering theSubjectPaneChecksBeforeItSends().");
  log.info("=== Subjects ===");
  await driver.executeScript(
      "document.getElementById('ssf_subject_format').value = 'email';" +
      "window.ssf.subjectFormatChanged(); window.ssf.fillSubjectExample();");
  const filled = await valueOf(driver, "ssf_subject_json");
  assert.ok(filled.indexOf('"format"') >= 0 && filled.indexOf('email') >= 0,
      "Fill with an example did not produce a specimen: " + filled);
  await click(driver, "btn_ssf_check_subject");
  const ok = await waitForText(driver, "ssf_subject_status", "subject status");
  assert.ok(ok.indexOf("Valid") === 0,
      "The specification's own specimen was called invalid: " + ok);

  // The refusal that nothing else makes: an extra member. It is the check
  // this pane exists for, because such a subject looks perfectly fine in a
  // log and every conforming receiver rejects it.
  await driver.executeScript(
      "document.getElementById('ssf_subject_json').value = " +
      "JSON.stringify({ format: 'email', email: 'a@b.c', tenant: 'acme' });");
  await click(driver, "btn_ssf_check_subject");
  await driver.wait(async function () {
    const text = await textOf(driver, "ssf_subject_status");
    return text.indexOf("problem") >= 0;
  }, WAIT, "the extra member was not refused");
  const findings = await textOf(driver, "ssf_subject_findings");
  assert.ok(findings.indexOf("tenant") >= 0,
      "The refusal does not name the member: " + findings);
  assert.ok(findings.indexOf("CLOSED") >= 0,
      "The refusal has to say WHY — a receiver that met an unrecognised " +
      "member could not tell whether it narrows the subject.");

  // And one that really goes across the wire.
  await driver.executeScript(
      "document.getElementById('ssf_subject_format').value = " +
      "'issuer_subject_id'; window.ssf.subjectFormatChanged();" +
      "window.ssf.fillSubjectExample();");
  await click(driver, "btn_ssf_add_subject");
  await driver.wait(async function () {
    const text = await textOf(driver, "ssf_subject_status");
    return text.indexOf("add subject succeeded") >= 0 ||
      text.indexOf("204") >= 0;
  }, WAIT, "Add Subject did not report a result");
  const added = await textOf(driver, "ssf_subject_status");
  assert.ok(added.indexOf("204") >= 0, "Add Subject said: " + added);
  await click(driver, "btn_ssf_remove_subject");
  await driver.wait(async function () {
    const text = await textOf(driver, "ssf_subject_status");
    return text.indexOf("IDEMPOTENT") >= 0 || text.indexOf("remove") >= 0;
  }, WAIT, "Remove Subject did not report a result");
  log.info("[subjects] OK — the specimen validates, the extra member is " +
      "refused by name, and both calls cross the wire.");
  log.debug("Leaving theSubjectPaneChecksBeforeItSends().");
}

// ---------------------------------------------------------------------------
// 6. VERIFICATION AND POLL — THE ONLY END-TO-END TEST A STREAM HAS.
// ---------------------------------------------------------------------------
async function verificationAndPollProduceAnEvent(driver) {
  log.debug("Entering verificationAndPollProduceAnEvent().");
  log.info("=== Verification and poll ===");
  await fill(driver, "ssf_verify_state", "from-ssf-page");
  await click(driver, "btn_ssf_verify");
  await driver.wait(async function () {
    const value = await valueOf(driver, "ssf_stream_status_text");
    return value.indexOf("accepted the request") >= 0 ||
      value.indexOf("could not") >= 0 || value.indexOf("400") >= 0;
  }, WAIT, "the verification request never reported a result");
  const asked = await valueOf(driver, "ssf_stream_status_text");
  assert.ok(asked.indexOf("accepted the request") >= 0,
      "The verification request said: " + asked);
  assert.ok(asked.indexOf("SEPARATE EXCHANGE") >= 0,
      "The page has to say that the EVENT is a separate exchange and has " +
      "not been seen yet — a receiver that read the 204 as the event would " +
      "believe the pipe works when nothing has crossed it.");
  await click(driver, "btn_ssf_poll");
  const polled = await waitForValue(driver, "ssf_poll_status", "poll status");
  assert.ok(/^[1-9]/.test(polled),
      "The poll returned nothing: " + polled + ". A verification event was " +
      "asked for and the pipe did not carry it, which is exactly the " +
      "failure the verification endpoint exists to reveal.");
  const messages = await waitForText(driver, "ssf_messages",
      "message history");
  assert.ok(messages.indexOf("received") >= 0);
  assert.ok(messages.indexOf("verification") >= 0,
      "The event history does not name the event type.");
  assert.ok(messages.indexOf("jti:") >= 0,
      "The event history does not show the jti, which is what an " +
      "acknowledgement names.");
  log.info("[delivery] OK — " + polled);
  log.debug("Leaving verificationAndPollProduceAnEvent().");
}

// ---------------------------------------------------------------------------
// 7. TRANSMITTING — AND THE PURE-JAVASCRIPT SIGNER.
// ---------------------------------------------------------------------------
async function thePageCanSignAndPushAnEvent(driver) {
  log.debug("Entering thePageCanSignAndPushAnEvent().");
  log.info("=== Transmitting ===");
  // ES256 in the JAVASCRIPT engine, not Web Crypto. On the containerized
  // suite's http:// origin `crypto.subtle` does not exist at all, and this
  // section is what asserts the page does not depend on it.
  await driver.executeScript(
      "document.getElementById('ssf_tx_alg').value = 'ES256';");
  await click(driver, "btn_ssf_tx_key");
  const keyStatus = await waitForValue(driver, "ssf_tx_key_status",
      "key status");
  assert.ok(keyStatus.indexOf("key pair") >= 0,
      "The key could not be generated: " + keyStatus + ". If this says " +
      "something about crypto.subtle, the page has started depending on Web " +
      "Crypto — which does not exist on this suite's http origin.");
  const priv = await valueOf(driver, "ssf_tx_private_key");
  assert.ok(priv.indexOf('"kty"') >= 0, "No private JWK: " + priv);
  await fill(driver, "ssf_tx_iss", "https://ssf-page-test.example/");
  await fill(driver, "ssf_tx_aud", "https://mock-sts.example/");
  await fill(driver, "ssf_tx_endpoint", stsUrl + "/ssf/receive");
  await driver.executeScript(
      "document.getElementById('ssf_tx_type').value = " +
      "'https://schemas.openid.net/secevent/ssf/event-type/stream-updated';" +
      "window.ssf.transmitTypeChanged();");
  await click(driver, "btn_ssf_build");
  const token = await waitForValue(driver, "ssf_tx_token", "the token");
  assert.strictEqual(token.split(".").length, 3,
      "What was built is not a compact JWS: " + token.slice(0, 80));
  const decoded = await waitForText(driver, "ssf_tx_decoded",
      "the decoded claim set");
  assert.ok(decoded.indexOf("no \"exp\"") >= 0 ||
      decoded.indexOf('"exp"') >= 0,
      "The page has to point out that there is no exp — RFC 8417 section " +
      "4.1.4 — because it is the one thing a reader will look for and not " +
      "find.");
  assert.ok(decoded.indexOf("sub_id") >= 0,
      "The page has to say the subject goes in sub_id rather than sub.");
  await click(driver, "btn_ssf_push");
  const pushed = await waitForValue(driver, "ssf_tx_status", "push status");
  assert.ok(pushed.indexOf("Delivered") === 0,
      "The push said: " + pushed);
  const messages = await textOf(driver, "ssf_messages");
  assert.ok(messages.indexOf("sent") >= 0,
      "The event history does not record what was SENT, which is half of " +
      "what it is for.");
  log.info("[transmit] OK — signed in the JavaScript engine and delivered.");
  log.debug("Leaving thePageCanSignAndPushAnEvent().");
}

// ---------------------------------------------------------------------------
// 8. THE TWO HISTORIES.
// ---------------------------------------------------------------------------
async function bothHistoriesRecordWhatTheyShould(driver) {
  log.debug("Entering bothHistoriesRecordWhatTheyShould().");
  log.info("=== The histories ===");
  // The token history, driven without a hand-off: a pasted ID Token is the
  // other way a set gets here, and it is what lets this section run with no
  // authorization server involved.
  const idToken = await driver.executeScript(
      "function b64(o) { return btoa(JSON.stringify(o))" +
      "  .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }" +
      "return b64({alg:'RS256',typ:'JWT'}) + '.' + b64({" +
      "  iss:'https://issuer.example/', sub:'alice-0001'," +
      "  aud:'ssf-page', name:'Alice Example'," +
      "  preferred_username:'alice'}) + '.sig';");
  await fill(driver, "ssf_id_token", idToken);
  await fill(driver, "ssf_access_token", "an-opaque-access-token");
  await click(driver, "btn_ssf_read_token");
  const identity = await waitForText(driver, "ssf_identity", "the identity");
  assert.ok(identity.indexOf("Alice Example") >= 0,
      "The page does not name the authenticated user: " + identity);
  assert.ok(identity.indexOf("alice-0001") >= 0,
      "The page does not show the sub.");
  assert.ok(identity.indexOf("NOT verified here") >= 0,
      "The page has to say the ID Token was NOT verified — this workflow " +
      "does not consume one, so checking its signature would be answering a " +
      "question nothing here asks, and a page that implied otherwise would " +
      "be the worst kind of wrong.");
  const tokens = await waitForText(driver, "ssf_token_history",
      "the token history");
  assert.ok(tokens.indexOf("alice") >= 0,
      "The token history does not show the subject: " + tokens);
  assert.ok(tokens.indexOf("sessionStorage") >= 0,
      "The token history has to say WHERE it is kept: a token is a " +
      "credential this workflow is using to drive somebody's control plane, " +
      "and it goes when the tab does.");

  // And that the stores really are what they say they are, which is the one
  // claim on this page a reader cannot check by looking.
  const stores = await driver.executeScript(
      "return { tokensInSession: !!sessionStorage.getItem(" +
      "           'ssf_token_history')," +
      "         tokensInLocal: !!localStorage.getItem('ssf_token_history')," +
      "         messagesInLocal: !!localStorage.getItem(" +
      "           'ssf_message_history')," +
      "         accessTokenSaved: !!localStorage.getItem(" +
      "           'ssf_access_token')," +
      "         idTokenSaved: !!localStorage.getItem('ssf_id_token')," +
      "         privateKeySaved: !!localStorage.getItem(" +
      "           'ssf_tx_private_key') };");
  assert.strictEqual(stores.tokensInSession, true,
      "The token history is not in sessionStorage.");
  assert.strictEqual(stores.tokensInLocal, false,
      "The token history is in localStorage. It holds credentials and must " +
      "not survive the tab — token_handoff.js makes the same choice for the " +
      "same reason and says so at length.");
  assert.strictEqual(stores.messagesInLocal, true,
      "The message history is not in localStorage. A Security Event Token " +
      "is EVIDENCE rather than a credential — holding one grants nothing — " +
      "and evidence is what a debugger most needs to survive a navigation.");
  assert.strictEqual(stores.accessTokenSaved, false,
      "The access token was written to localStorage. It is a credential and " +
      "is deliberately absent from REMEMBERED.");
  assert.strictEqual(stores.idTokenSaved, false,
      "The ID Token was written to localStorage.");
  assert.strictEqual(stores.privateKeySaved, false,
      "The transmitting private key was written to localStorage. A signing " +
      "key in localStorage is a signing key in every extension's reach.");
  log.info("[histories] OK — both stores are what they say, and no " +
      "credential is written down.");
  log.debug("Leaving bothHistoriesRecordWhatTheyShould().");
}

// ---------------------------------------------------------------------------
// 9. THE HAND-OFF, WITHOUT NAVIGATING.
// ---------------------------------------------------------------------------
async function theHandoffCarriesTheWholeTokenSet(driver) {
  log.debug("Entering theHandoffCarriesTheWholeTokenSet().");
  log.info("=== The OAuth2 / OIDC hand-off ===");
  // The slot is filled the way oauth2_oidc_2.js fills it and the page is
  // reloaded, which exercises the same path as the real navigation without
  // needing an authorization server. What is being asserted is the thing
  // this workflow needed and the SCIM page did not: THE WHOLE SET, because
  // an access token this service issues is opaque to a client and the
  // identity is in the ID Token.
  const idToken = await driver.executeScript(
      "function b64(o) { return btoa(JSON.stringify(o))" +
      "  .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }" +
      "var id = b64({alg:'RS256',typ:'JWT'}) + '.' + b64({" +
      "  iss:'https://issuer.example/', sub:'handed-0002'," +
      "  name:'Handed Over'}) + '.sig';" +
      "sessionStorage.setItem('token_handoff_active','1');" +
      "sessionStorage.setItem('token_handoff_return','/ssf.html');" +
      "sessionStorage.setItem('token_handoff_label','the Shared Signals " +
      "workflow');" +
      "sessionStorage.setItem('token_handoff_token','handed-access-token');" +
      "sessionStorage.setItem('token_handoff_meta', JSON.stringify(" +
      "  {source:'the token endpoint', at: Date.now()}));" +
      "sessionStorage.setItem('token_handoff_set', JSON.stringify(" +
      "  {idToken: id, refreshToken:'rt', tokenType:'Bearer'," +
      "   scope:'openid ssf:read ssf:write', expiresIn: 300}));" +
      "return id;");
  assert.ok(idToken.length > 20);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("pane_tokens")), WAIT,
      "the page did not come back");
  const access = await valueOf(driver, "ssf_access_token");
  assert.strictEqual(access, "handed-access-token",
      "The access token did not come back from the hand-off.");
  const carried = await valueOf(driver, "ssf_id_token");
  assert.strictEqual(carried, idToken,
      "The ID TOKEN did not come back. That is the addition this workflow " +
      "needed: an access token this service issues is opaque to a client, " +
      "so without it the page cannot say who is signed in.");
  const identity = await waitForText(driver, "ssf_identity", "the identity");
  assert.ok(identity.indexOf("Handed Over") >= 0,
      "The page does not name the user the hand-off carried: " + identity);
  const note = await textOf(driver, "ssf_token_handoff_note");
  assert.ok(note.indexOf("the token endpoint") >= 0,
      "The page does not say WHERE the tokens came from, which is the " +
      "question a hand-off invites.");
  // ONE SHOT. The slot is cleared by take(), so a refresh must not fill the
  // fields a second time from a hand-off that has already been collected.
  const slotAfter = await driver.executeScript(
      "return { token: sessionStorage.getItem('token_handoff_token')," +
      "         set: sessionStorage.getItem('token_handoff_set') };");
  assert.strictEqual(slotAfter.token, null,
      "The hand-off slot still holds the access token. It is one-shot — " +
      "take() clears it — or a bearer token appears in a field nobody " +
      "filled.");
  assert.strictEqual(slotAfter.set, null,
      "The hand-off slot still holds the rest of the set.");
  log.info("[handoff] OK — the whole set crossed, and the slot is empty.");
  log.debug("Leaving theHandoffCarriesTheWholeTokenSet().");
}

// ---------------------------------------------------------------------------
// 10. THE VOCABULARIES THAT ARE NOT HERE YET.
// ---------------------------------------------------------------------------
async function theAbsentVocabulariesSayTheyAreAbsent(driver) {
  log.debug("Entering theAbsentVocabulariesSayTheyAreAbsent().");
  log.info("=== CAEP and RISC ===");
  const families = await textOf(driver, "ssf_families");
  assert.ok(families.indexOf("CAEP") >= 0 && families.indexOf("RISC") >= 0,
      "The page does not mention CAEP and RISC. A workflow offering two " +
      "event types where a reader expected eighteen reads as broken rather " +
      "than as staged, so the two that are not here have to say so.");
  assert.ok(families.indexOf("NOT IMPLEMENTED") >= 0,
      "The absent vocabularies do not say they are absent.");
  log.info("[families] OK.");
  log.debug("Leaving theAbsentVocabulariesSayTheyAreAbsent().");
}

// ---------------------------------------------------------------------------
// 11. STYLES.
// ---------------------------------------------------------------------------
async function everyStyleClassIsDefined(driver) {
  log.debug("Entering everyStyleClassIsDefined().");
  log.info("=== Stylesheets ===");
  // Note the shape: this function is SERIALISED INTO THE BROWSER, so there is
  // no bunyan in it and a log line here would be `log is not defined`
  // reported as a page fault. What comes back is logged out here in node.
  const m = await driver.executeScript(
    "var links = Array.prototype.slice.call(" +
    "  document.querySelectorAll('link[rel=stylesheet]'))" +
    "  .map(function (l) { return l.getAttribute('href'); });" +
    "var empty = [];" +
    "var defined = {};" +
    "Array.prototype.slice.call(document.styleSheets).forEach(" +
    "  function (sheet) {" +
    "    var rules = null;" +
    "    try { rules = sheet.cssRules; } catch (e) { rules = null; }" +
    "    if (!rules || !rules.length) {" +
    "      if (sheet.href) empty.push(sheet.href); return; }" +
    "    Array.prototype.slice.call(rules).forEach(function collect(rule) {" +
    "      if (rule.selectorText) {" +
    "        (rule.selectorText.match(/\\.[A-Za-z0-9_-]+/g) || []).forEach(" +
    "          function (sel) { defined[sel.slice(1)] = true; });" +
    "      } else if (rule.cssRules) {" +
    "        Array.prototype.slice.call(rule.cssRules).forEach(collect);" +
    "      }" +
    "    });" +
    "  });" +
    "var used = {};" +
    "Array.prototype.slice.call(document.querySelectorAll('[class]'))" +
    "  .forEach(function (e) {" +
    "    Array.prototype.slice.call(e.classList).forEach(" +
    "      function (c) { used[c] = true; }); });" +
    "return { links: links, empty: empty," +
    "         used: Object.keys(used), defined: Object.keys(defined) };");
  assert.deepStrictEqual(m.empty, [],
    "these stylesheets loaded with no rules in them (a 404 serving an error " +
    "page, or an empty file): " + m.empty.join(", "));
  const definedSet = {};
  m.defined.forEach(function (c) {
    definedSet[c] = true;
  });
  const unstyled = m.used.filter(function (c) {
    return /^ssf-/.test(c) && !definedSet[c];
  });
  assert.deepStrictEqual(unstyled, [],
    "these `ssf-` classes are used on the page and defined in none of the " +
    "stylesheets it loads: " + unstyled.join(", ") + ". The page links: " +
    m.links.join(", ") + ". Note the Operations History pane's classes come " +
    "from op_history.js with this workflow's prefix, so css/ssf.css has to " +
    "define ssf-history-scroll, ssf-table, ssf-history, ssf-history-time " +
    "and ssf-history-empty as well as the ones written in the markup.");
  log.info("[styles] every ssf- class the page uses is defined; it links " +
      m.links.length + " stylesheet(s), all with rules.");
  log.debug("Leaving everyStyleClassIsDefined().");
}

// ---------------------------------------------------------------------------
// 12. THE CONSOLE.
// ---------------------------------------------------------------------------
async function theConsoleIsClean(driver) {
  log.debug("Entering theConsoleIsClean().");
  log.info("=== Browser console ===");
  const entries = await driver.manage().logs().get("browser");
  const severe = entries.filter(function (entry) {
    // A 404 for a favicon variant is noise from the icon set every page here
    // carries and says nothing about this workflow.
    return entry.level.name === "SEVERE" &&
      !/favicon|apple-icon|android-icon|ms-icon/.test(entry.message) &&
      // And a load the browser abandoned because its own certificate or
      // network configuration changed under it says nothing about this
      // workflow either. See browser_flags.js.
      !browserFlags.isTransientLoadError(entry.message);
  });
  assert.deepStrictEqual(severe.map(function (e) {
    return e.message;
  }), [],
    "the page must produce no severe console errors. A bundle that failed " +
    "to load, or a handler that threw, shows up here and nowhere else — the " +
    "buttons simply stop working and every wait times out naming an " +
    "element.");
  log.debug("Leaving theConsoleIsClean().");
}

// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const page = await fetch(baseUrl + "/ssf.html");
    if (!page.ok) {
      log.debug("Leaving preconditions(). No page.");
      return { ok: false, why: baseUrl + "/ssf.html answered " + page.status +
        " — this build does not carry the Shared Signals page" };
    }
    const doc = await fetch(stsUrl + "/.well-known/ssf-configuration");
    if (!doc.ok) {
      log.debug("Leaving preconditions(). No transmitter.");
      return { ok: false, why: "no SSF transmitter at " + stsUrl +
        " (/.well-known/ssf-configuration answered " + doc.status + ") — " +
        "the sts/ gitlink probably predates it" };
    }
  } catch (e) {
    log.debug("Leaving preconditions(). " + e.message);
    return { ok: false, why: "nothing answered: " + e.message };
  }
  log.debug("Leaving preconditions(). Ready.");
  return { ok: true, why: "" };
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  let id;
  for (id of created) {
    await fetch(stsUrl + "/ssf/stream", {
      method: "DELETE",
      headers: { "Content-Type": "application/json",
        Authorization: "Basic " +
          Buffer.from("ssf-page-runner:pw").toString("base64") },
      body: JSON.stringify({ stream_id: id })
    }).catch(function () {
      return null;
    });
  }
  log.debug("Leaving cleanUp(). " + created.length + " stream(s).");
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
  log.info("driving " + baseUrl + "/ssf.html against the transmitter at " +
      stsUrl + " and the api at " + apiUrl);

  const options = new chrome.Options();
  // --headless=new, never bare --headless: a CI runner and the tests
  // container have no display, and a windowed session fails at `session not
  // created` naming the page it was about to visit.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,2000");
  // The page fetches the transmitter and the api on loopback from whatever
  // origin the suite is pointed at, which is a Private Network Access request
  // Chrome blocks or preflights.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await thePageLoadsAndTheBundleRan(driver);
    await theCallPathRowReflectsWhetherThereIsAnApi(driver);
    await discoveryReadsEveryMember(driver);
    await aStreamIsCreatedAndRead(driver);
    await theSubjectPaneChecksBeforeItSends(driver);
    await verificationAndPollProduceAnEvent(driver);
    await thePageCanSignAndPushAnEvent(driver);
    await bothHistoriesRecordWhatTheyShould(driver);
    await theAbsentVocabulariesSayTheyAreAbsent(driver);
    // THE STYLE CHECK RUNS BEFORE THE HAND-OFF SECTION AND THE ORDER IS
    // LOAD-BEARING. Several of this page's `ssf-` classes are on elements the
    // bundle CREATES — the events_requested boxes are built from the
    // transmitter's own events_supported, the findings and the message rows
    // from what came back — so they are not on the page until something has
    // been fetched. The hand-off section RELOADS the page, which wipes all of
    // them, and a style check after it would pass by examining a page that no
    // longer has the classes it is meant to be checking.
    await everyStyleClassIsDefined(driver);
    await theHandoffCarriesTheWholeTokenSet(driver);
    await theConsoleIsClean(driver);
    log.info("Test completed successfully.");
  } finally {
    // driver.quit() in a FINALLY and never after a process.exit(): the
    // exit skips the finally, and one headless Chrome is about fifteen OS
    // processes of which only the first is this runner's child. See
    // tests/CLAUDE.md — a run of this suite once left 559 of them behind.
    await cleanUp();
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("ssf_page")
  .description("Verify the Shared Signals Debugger page: that its bundle " +
      "ran, that discovery draws every metadata member, that a stream is " +
      "agreed and a subject refused by name, that a verification event " +
      "arrives by poll, that the page signs and pushes one of its own in " +
      "the JavaScript engine, that both histories record what they should " +
      "and no credential is written down, and that the OAuth2 / OIDC " +
      "hand-off carries the whole token set.")
  .addOption(new Option("-u, --url <url>",
      "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
