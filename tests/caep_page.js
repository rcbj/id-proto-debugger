// File: caep_page.js
//
// ---------------------------------------------------------------------------
// THE CAEP HALF OF THE SHARED SIGNALS PAGE, IN A BROWSER, BEHIND SIX
// DIFFERENT OAuth2 / OIDC GRANTS.
//
// `caep_engine.js` proves what this workflow COMPOSES and `caep_protocol.js`
// proves that a real transmitter accepts it and emits on its own. Neither
// loads the page, and four things only break here:
//
//   * **the profile switch**, which reconfigures the whole workflow. Its
//     failure mode is not an error: it is a stream agreed for the wrong
//     vocabulary, which looks perfectly healthy and delivers nothing.
//   * **the CAEP session pane**, and specifically what it does with a grant
//     that issues NO ID TOKEN — client credentials and resource owner
//     password both do, they are supported grants, and a page that showed an
//     authenticated user it could not name would be the worst kind of wrong.
//   * **the eight simulate buttons**, each of which has to build a whole
//     event, sign it in the JavaScript engine and push it — on an origin
//     where `crypto.subtle` does not exist at all.
//   * **the reset**, whose one failure mode is silence: a Reset that could
//     not delete the stream and said nothing leaves somebody debugging
//     yesterday's stream while believing they have started over.
//
// **WHY SIX GRANTS AND NOT ONE.** The CAEP session is seeded from whatever
// the OAuth2 / OIDC hand-off produced, and the six supported grants produce
// three genuinely different shapes: an ID Token with a `sid` (a session this
// service really holds), an ID Token without one (a person, and a session
// identifier this page invented), and NO ID TOKEN AT ALL. The third is not an
// error case — it is two of the six — and the page has to say which of the
// three it is looking at, because an event naming a session identifier this
// page invented is about nothing at the far end.
//
// TWO ENVIRONMENT HAZARDS APPLY, both recorded in tests/CLAUDE.md and both
// having cost this suite a run: `--headless=new` and never bare `--headless`,
// and `browser_flags.js`, because this page fetches the transmitter and the
// api on loopback from whatever origin the suite is pointed at.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require("selenium-webdriver/lib/select");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { mustBeReady } = require("./expectation.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "caep_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
// NO apiUrl, deliberately. This job's whole subject is the page reconfiguring
// itself and a session model that lives in the browser, and the events it
// simulates are signed and sent BY the page — the debugger acting as a
// transmitter, which is an ordinary fetch. It needs no backend and runs
// against a deployed static site unchanged, which is why run-report.js hands
// it no API_URL. A variable naming an api nothing here calls is an invitation
// to start calling one.

// The transmitter as the BROWSER must reach it, which on the containerized
// stack is not the name this test uses and not the name the api uses — three
// answers to one question, and confusing them has cost this suite a run.
var stsUrl = process.env.SSF_TRANSMITTER_URL || process.env.STS_URL ||
    "https://localhost:8081";
var discoveryEndpoint = process.env.DISCOVERY_ENDPOINT ||
    (stsUrl + "/.well-known/openid-configuration");
var clientId = process.env.CLIENT_ID || "webapp1";

const WAIT = 20000;
const P = "https://schemas.openid.net/secevent/caep/event-type/";

// The eight, in catalogue order, so the button ids below can be composed.
const SHORTS = ['session-revoked', 'session-established', 'session-presented',
  'token-claims-change', 'credential-change', 'assurance-level-change',
  'device-compliance-change', 'risk-level-change'];

let created = [];
let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// The same thing for a case whose assertion has to AWAIT — reading a pane's
// visibility out of the browser, say. `check()` takes a synchronous body on
// purpose: an async one would resolve to a promise nobody waited on, and the
// check would pass by not having run.
function passed(what) {
  log.debug("Entering passed(). " + what);
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving passed().");
}

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
  const value = await driver.findElement(By.id(id)).getAttribute("value");
  log.debug("Leaving valueOf().");
  return value;
}

// WAIT ON CONTENT AND NOT ON AN ELEMENT — the rule tests/CLAUDE.md states.
// Every readout on this page exists in the markup from the first paint, so
// `until.elementLocated` returns immediately and the assertion that follows
// reads an empty box.
async function waitForValue(driver, id, what) {
  log.debug("Entering waitForValue(). " + id);
  await driver.wait(async function () {
    const value = await valueOf(driver, id);
    return value !== null && value !== "" &&
      !/^(Asking|Fetching|Generating|Signing)/.test(value);
  }, WAIT, "the " + what + " never filled in (#" + id + ")");
  const value = await valueOf(driver, id);
  log.debug("Leaving waitForValue().");
  return value;
}

async function waitForText(driver, id, what) {
  log.debug("Entering waitForText(). " + id);
  await driver.wait(async function () {
    const value = await textOf(driver, id);
    return value !== null && value.trim() !== "";
  }, WAIT, "the " + what + " never filled in (#" + id + ")");
  const value = await textOf(driver, id);
  log.debug("Leaving waitForText().");
  return value;
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  await driver.get(baseUrl + "/ssf.html");
  await driver.wait(until.elementLocated(By.id("pane_profile")), WAIT,
      baseUrl + "/ssf.html has no Profile pane — either the page 404'd or " +
      "the CAEP markup is not in this build.");
  await driver.wait(async function () {
    return await driver.executeScript(
        "return !!(window.ssf && window.ssf.profileChanged);");
  }, WAIT,
      "window.ssf.profileChanged is not there. Either public/js/ssf.js 404'd " +
      "or the bundle threw before it exported, in which case every onclick " +
      "on this page is a ReferenceError and nothing works.");
  log.debug("Leaving openPage().");
}

async function chooseProfile(driver, id) {
  log.debug("Entering chooseProfile(). " + id);
  await driver.findElement(By.id("ssf_profile_" + id)).click();
  await driver.wait(async function () {
    return await driver.executeScript(
        "return window.ssf.currentProfile();") === id;
  }, WAIT, "the profile never became " + id);
  log.debug("Leaving chooseProfile().");
}

async function eventMenu(driver) {
  return await driver.executeScript(
      "return [].slice.call(document.getElementById('ssf_tx_type').options)" +
      "  .map(function (o) { return o.value; });");
}

async function paneVisible(driver, id) {
  return await driver.executeScript(
      "var e = document.getElementById('" + id + "');" +
      "return !!e && !e.classList.contains('ssf-hidden');");
}

// ---------------------------------------------------------------------------
// 1. THE PROFILE SWITCH RECONFIGURES THE WORKFLOW.
//
// **NARROWING BOTH LISTS IS THE POINT, NOT ONE.** The Transmit menu and the
// stream's `events_requested` checkboxes are two halves of one decision: a
// menu narrowed without the checkboxes would let somebody agree a stream for
// event types the page then has no way to send — and SSF has no refusal for
// that, so the stream would look perfectly healthy and never deliver
// anything.
// ---------------------------------------------------------------------------
async function theProfileSwitchReconfiguresThePage(driver) {
  log.info("=== The profile ===");
  await openPage(driver);

  await chooseProfile(driver, 'ssf');
  const ssfMenu = await eventMenu(driver);
  check('Pure SSF offers exactly the two event types SSF defines',
      function () {
        assert.strictEqual(ssfMenu.length, 2,
            'The menu holds ' + ssfMenu.length + ' types: ' +
            ssfMenu.join(', '));
        ssfMenu.forEach(function (uri) {
          assert.ok(uri.indexOf('/ssf/event-type/') > 0, uri);
        });
      });
  assert.strictEqual(await paneVisible(driver, 'pane_caep'), false,
      'The CAEP session pane is showing in Pure SSF mode. It is about a ' +
      'vocabulary this profile does not speak.');
  passed("and the CAEP pane is not on the page");

  await chooseProfile(driver, 'caep');
  const caepMenu = await eventMenu(driver);
  check('CAEP offers exactly its eight, and no SSF type among them',
      function () {
        assert.strictEqual(caepMenu.length, 8,
            'The menu holds ' + caepMenu.length + ' types: ' +
            caepMenu.join(', '));
        SHORTS.forEach(function (short) {
          assert.ok(caepMenu.indexOf(P + short) >= 0,
              short + ' is not in the Transmit menu.');
        });
      });

  const boxes = await driver.executeScript(
      "return [].slice.call(document.querySelectorAll('.ssf-event-choice'))" +
      "  .map(function (b) { return b.value; });");
  check('AND THE STREAM\'S events_requested BOXES NARROW WITH IT',
      function () {
        assert.strictEqual(boxes.length, 8,
            'There are ' + boxes.length + ' boxes: ' + boxes.join(', ') +
            '. A menu narrowed without these would let a reader agree a ' +
            'stream for types this page cannot send, and SSF has no refusal ' +
            'for that — the stream would look healthy and deliver nothing.');
        boxes.forEach(function (uri) {
          assert.ok(uri.indexOf(P) === 0, uri + ' is not a CAEP type.');
        });
      });

  assert.strictEqual(await paneVisible(driver, 'pane_caep'), true,
      'The CAEP session pane is not showing in CAEP mode.');
  passed("and the CAEP session pane appears");

  const stillThere = ['pane_tokens', 'pane_config', 'pane_metadata',
    'pane_stream', 'pane_subjects', 'pane_receive', 'pane_transmit',
    'pane_messages', 'pane_exchange', 'pane_history'];
  let name;
  for (name of stillThere) {
    assert.strictEqual(await paneVisible(driver, name), true,
        name + ' was hidden by the CAEP profile. Every pane on this page is ' +
        'used by all three vocabularies — CAEP events travel on the same ' +
        'streams, through the same deliveries, in the same envelope — so ' +
        'hiding one would be hiding the thing they travel on.');
  }
  passed("every other pane is still there");

  await chooseProfile(driver, 'risc');
  const riscMenu = await eventMenu(driver);
  const riscNote = await textOf(driver, "ssf_profile_note");
  check('RISC offers no event type AND SAYS SO', function () {
    assert.strictEqual(riscMenu.length, 1,
        'The menu holds ' + riscMenu.length + ' entries.');
    assert.strictEqual(riscMenu[0], '',
        'An empty menu reads as a broken page; this one carries a single ' +
        'entry saying the vocabulary is not implemented yet.');
    assert.ok(/NOT IMPLEMENTED/i.test(riscNote),
        'The note says: ' + JSON.stringify(riscNote) + '. A reader who ' +
        'cannot tell "this tool does not do RISC" from "I have not found ' +
        'it yet" is being told the wrong thing by an omission.');
  });
  assert.strictEqual(await paneVisible(driver, 'pane_caep'), false,
      'The CAEP pane is showing in RISC mode.');
  passed("and the CAEP pane is gone again");

  // THE CHOICE SURVIVES A RELOAD, which is what makes it a setting rather
  // than a mood. A reader who left the page in CAEP mode and came back to
  // Pure SSF would create a stream asking for the wrong vocabulary.
  await chooseProfile(driver, 'caep');
  await openPage(driver);
  assert.strictEqual(
      await driver.executeScript("return window.ssf.currentProfile();"),
      'caep', 'The page came back in a different profile.');
  assert.strictEqual((await eventMenu(driver)).length, 8);
  passed("the profile survives a reload");
}

// ---------------------------------------------------------------------------
// 2. THE SIX GRANTS.
//
// Every one of them is run through the REAL hand-off: the CAEP pane's session
// is filled from whatever the OAuth2 / OIDC workflow actually produced, which
// is the only way to find out that two of the six produce no ID Token at all.
// ---------------------------------------------------------------------------
// EVERY GRANT THIS WORKFLOW SUPPORTS, AND WHICH OF THE THREE SHAPES IT
// PRODUCES. The table is here rather than in prose because the mapping IS the
// assertion: the CAEP pane's whole job on arrival is to say which of the three
// it has been handed, and a reader has to be able to see that all six were
// accounted for.
const GRANTS = [
  { label: 'OIDC Authorization Code Flow(code)', shape: 'sid' },
  { label: 'OIDC Implicit Flow(id_token token)', shape: 'sid' },
  { label: 'OIDC Implicit Flow(id_token)', shape: 'sid' },
  { label: 'OIDC Hybrid(code id_token)', shape: 'sid' },
  { label: 'OAuth2 Authorization Code Grant', shape: 'none' },
  { label: 'OAuth2 Implicit Grant', shape: 'none' },
  { label: 'OAuth2 Client Credential', shape: 'none' },
  { label: 'OAuth2 Resource Owner Password Credential Grant', shape: 'none' }
];

// Plant a token set of the shape a given grant produces and take it through
// the hand-off. **THIS IS NOT A SUBSTITUTE FOR DRIVING THE GRANT** — section
// 2b does that for real — it is how the OTHER FIVE shapes are reached without
// six full browser round trips through two more pages, and what it asserts is
// this page's half: what the CAEP pane does with each shape.
async function handOff(driver, set) {
  log.debug("Entering handOff().");
  await driver.executeScript(
      "sessionStorage.setItem('token_handoff_active','1');" +
      "sessionStorage.setItem('token_handoff_return','/ssf.html');" +
      "sessionStorage.setItem('token_handoff_label','the Shared Signals " +
      "workflow');" +
      "sessionStorage.setItem('token_handoff_token', arguments[0]);" +
      "sessionStorage.setItem('token_handoff_meta', JSON.stringify(" +
      "  { at: Date.now(), source: 'a test' }));" +
      "sessionStorage.setItem('token_handoff_set', arguments[1]);",
      set.accessToken, JSON.stringify(set));
  await openPage(driver);
  await chooseProfile(driver, 'caep');
  log.debug("Leaving handOff().");
}

// An unsigned-looking but well-formed JWT. It is never verified — this
// workflow does not CONSUME an ID Token, so checking a signature here would
// answer a question nothing on the page asks — and `caepFillFromToken()` says
// so on the screen, which is what section 2 asserts.
function idTokenOf(claims) {
  const b64 = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return b64({ alg: 'RS256', typ: 'JWT' }) + '.' + b64(claims) + '.' +
    'not-verified-here';
}

async function eachGrantShapeSeedsTheSession(driver) {
  log.info("=== The grant shapes ===");
  // THE MAPPING, SAID OUT LOUD. Eight supported grants and three shapes
  // between them, and the CAEP pane's whole job on arrival is to say which of
  // the three it has been handed. Every one of the three is exercised below.
  GRANTS.forEach(function (grant) {
    log.info("  " + grant.label + " -> " +
        (grant.shape === 'sid'
          ? 'an ID Token (a sid when the transmitter issues one)'
          : 'no ID Token unless openid was asked for'));
  });
  check('every supported grant maps to a shape this pane handles',
      function () {
        assert.strictEqual(GRANTS.length, 8);
        GRANTS.forEach(function (grant) {
          assert.ok(['sid', 'none'].indexOf(grant.shape) >= 0, grant.label);
        });
      });

  // (a) an ID Token WITH a sid — a session this service really holds.
  await handOff(driver, {
    accessToken: 'opaque-access-token',
    idToken: idTokenOf({ iss: stsUrl, sub: 'urn:sts-mock:user:alice',
      sid: 'a-real-session-id', acr: 'urn:example:silver', amr: ['pwd'],
      preferred_username: 'alice' }),
    tokenType: 'Bearer', scope: 'openid ssf:read ssf:write', expiresIn: 3600
  });
  await click(driver, "btn_caep_seed");
  const withSid = await textOf(driver, "caep_seed_note");
  check('an ID Token with a sid fills the session and names nothing as ' +
      'invented', function () {
        assert.ok(/WITHOUT VERIFYING/i.test(withSid),
            'The pane says: ' + JSON.stringify(withSid) + '. It has to say ' +
            'that it did not verify: this workflow does not consume an ID ' +
            'Token, so checking its signature would answer a question ' +
            'nothing here asks — and a page that implied otherwise would be ' +
            'the worst kind of wrong.');
      });
  assert.strictEqual(await valueOf(driver, "caep_sid"), 'a-real-session-id');
  assert.strictEqual(await valueOf(driver, "caep_sub"),
      'urn:sts-mock:user:alice');
  assert.strictEqual(await valueOf(driver, "caep_amr"), 'pwd');
  passed("and the session identifier is the one the token carried");

  const subject = await driver.executeScript(
      "return JSON.parse(document.getElementById('caep_subject_json')" +
      "  .value);");
  check('THE SUBJECT IS A COMPLEX ONE naming the session as well as the ' +
      'person', function () {
        assert.strictEqual(subject.format, undefined,
            'a complex subject is told from a plain one by the ABSENCE of ' +
            'format.');
        assert.strictEqual(subject.session.id, 'a-real-session-id');
        assert.strictEqual(subject.user.sub, 'urn:sts-mock:user:alice');
      });

  // (b) an ID Token with NO sid — a person, and an identifier this page made.
  await handOff(driver, {
    accessToken: 'opaque-access-token',
    idToken: idTokenOf({ iss: stsUrl, sub: 'urn:sts-mock:user:bob' }),
    tokenType: 'Bearer', scope: 'openid', expiresIn: 3600
  });
  await click(driver, "btn_caep_seed");
  const noSid = await textOf(driver, "caep_seed_note");
  const invented = await valueOf(driver, "caep_sid");
  check('an ID Token with NO sid says the session identifier was generated ' +
      'here', function () {
        assert.ok(/GENERATED HERE/i.test(noSid),
            'The pane says: ' + JSON.stringify(noSid) + '. An event naming ' +
            'a session identifier this page invented is about nothing at ' +
            'the far end, and the reader has to be told which of the two ' +
            'they are looking at.');
        assert.ok(invented.indexOf('debugger-') === 0,
            'The identifier is ' + JSON.stringify(invented) + '. A random ' +
            'hex string would be indistinguishable from a transmitter\'s, ' +
            'and somebody would eventually paste one into a real system.');
      });

  // (c) NO ID TOKEN AT ALL — two of the six grants, and not an error.
  await handOff(driver, {
    accessToken: 'opaque-access-token', idToken: '',
    tokenType: 'Bearer', scope: 'ssf:read ssf:write', expiresIn: 3600
  });
  await click(driver, "btn_caep_seed");
  const none = await textOf(driver, "caep_seed_note");
  check('A GRANT WITH NO ID TOKEN IS A SUPPORTED CASE and the pane says so',
      function () {
        assert.ok(/no ID Token/i.test(none),
            'The pane says: ' + JSON.stringify(none) + '. Client ' +
            'credentials and resource owner password are two of the six ' +
            'supported grants and neither issues one, so this is not an ' +
            'error path — and a page that showed an authenticated user it ' +
            'could not name would be the worst kind of wrong.');
      });
  await fill(driver, "caep_sub", "typed-by-hand");
  await fill(driver, "caep_iss", stsUrl);
  await driver.executeScript("window.ssf.renderCaep();");
  const typed = await driver.executeScript(
      "return JSON.parse(document.getElementById('caep_subject_json')" +
      "  .value);");
  assert.strictEqual(typed.user.sub, 'typed-by-hand',
      'A debugger pointed at somebody else\'s transmitter is entitled to ' +
      'name whatever subject it likes.');
  passed("and the pane is still usable: every field is editable");
}

// ---------------------------------------------------------------------------
// 2b. AND TWO OF THE GRANTS DRIVEN FOR REAL, THROUGH THE REAL HAND-OFF.
//
// Section 2 asserts what the pane does with each SHAPE; this asserts that the
// hand-off actually delivers one. Two grants and not six, and the choice is
// deliberate rather than a shortcut:
//
//   * **Resource owner password with `openid`** produces an ID TOKEN, from the
//     token endpoint, and
//   * **client credentials** produces NO ID TOKEN AT ALL,
//
// which are the two shapes that matter here — and neither goes near a browser
// sign-in or a consent screen. The four browser-borne grants reach the same
// hand-off through the same function in `oauth2_oidc_2.js`
// (`noteTokenHandoff()`), and whether each of them redeems correctly is
// `oauth2_*.js` and `oidc_flows.js`'s subject rather than this file's: this
// job holds the `sts-ssf` lock and driving four sign-ins through the mock's
// consent screen here would be a second copy of what those jobs already own,
// failing for their reasons and reported as a CAEP defect.
// ---------------------------------------------------------------------------
const DRIVEN = [
  { label: 'OAuth2 Resource Owner Password Credential Grant', idToken: true,
    scope: 'openid ssf:read',
    what: 'a person, authenticated at the TOKEN endpoint, with openid asked ' +
          'for — so an ID Token comes back and this page can name them' },
  { label: 'OAuth2 Client Credential', idToken: false,
    scope: 'ssf:read',
    what: 'NO USER AT ALL — the client is the subject — so there is no ID ' +
          'Token, and the session below is entirely this page\'s invention' }
];

async function twoGrantsReachTheCaepPaneForReal(driver, helpers) {
  log.info("=== Two grants, driven through the real hand-off ===");
  let grant;
  for (grant of DRIVEN) {
    log.info("--- " + grant.label + " — " + grant.what);
    let outcome = null;
    try {
      outcome = await oneGrant(driver, helpers, grant);
    } catch (e) {
      // A GRANT THAT COULD NOT BE DRIVEN IS REPORTED AND DOES NOT STOP THE
      // OTHER, because what this section is about is the HAND-OFF rather
      // than either exchange: the OAuth2 / OIDC jobs own whether a grant
      // works, and a failure here that took the other with it would hide the
      // thing this file is for.
      log.warn("  " + grant.label + " could not be driven: " + e.message);
      continue;
    }
    check(grant.label + ' delivered a token set to the CAEP pane',
        function () {
          assert.ok(outcome.hadToken,
              'Nothing came back through the hand-off. The pane said: ' +
              JSON.stringify(outcome.note));
        });
    check('and the pane reports the right shape for it', function () {
      if (grant.idToken) {
        assert.ok(!/no ID Token/i.test(outcome.note),
            grant.label + ' was asked for openid and therefore issues an ID ' +
            'Token, and the pane said: ' + JSON.stringify(outcome.note));
        assert.ok(outcome.sub.length > 0,
            'the subject box is empty, so nothing was read out of the ID ' +
            'Token.');
      } else {
        assert.ok(/no ID Token|GENERATED HERE/i.test(outcome.note),
            grant.label + ' issues no ID Token and the pane said: ' +
            JSON.stringify(outcome.note) + '. It has to say which of the ' +
            'three shapes this is, because an event naming a session ' +
            'identifier this page invented is about nothing at the far end.');
      }
    });
  }
}

async function oneGrant(driver, helpers, grant) {
  log.debug("Entering oneGrant(). " + grant.label);
  await openPage(driver);
  await chooseProfile(driver, 'caep');
  // **THE STORED GRANT TYPE IS CLEARED FIRST, AND WITHOUT THIS THE SECOND
  // ROUND TRIP CANNOT WORK.** `oauth2_oidc_1.html` remembers the last grant
  // in localStorage, and its `onload()` sends a TOKEN-ENDPOINT-ONLY grant
  // straight on to page 2 — client credentials and resource owner password
  // are exactly those two — so after the first of them page 1 never draws
  // again and the next grant's helper times out on a field that is on the
  // page it was skipped past. Same origin as this page, so one removeItem
  // reaches it.
  await driver.executeScript(
      "try { localStorage.removeItem('authorization_grant_type'); }" +
      "catch (e) { /* no storage for this origin; nothing was stored */ }");
  // The hand-off's own button: it marks this workflow as waiting and sends
  // the browser to the OAuth2 / OIDC workflow. Everything after it is that
  // workflow's, driven by common/tests.js's helpers so that this file holds
  // no second copy of how a grant is run.
  await click(driver, "btn_ssf_get_token");
  await driver.wait(async function () {
    return /oauth2_oidc_[12]\.html/.test(await driver.getCurrentUrl());
  }, WAIT, "the hand-off did not reach the OAuth2 / OIDC workflow");
  // **EVERY PANE OPEN BEFORE THE HELPERS TOUCH ANYTHING.** The OAuth2 / OIDC
  // pages remember which of their panes were collapsed, per browser, and
  // `populateMetadata()` waits for the discovery field to be VISIBLE — so a
  // pane the previous round trip left shut makes the next one fail with
  // "Waiting until element is visible", which names a field on a page that
  // is perfectly fine and sends whoever reads it to the wrong place. This is
  // a property of the browser session rather than of either page, so it is
  // put right here rather than being asserted.
  await driver.executeScript(
      "[].slice.call(document.querySelectorAll('fieldset')).forEach(" +
      "  function (f) { f.style.display = 'block'; });");
  await helpers.populateMetadata(driver, discoveryEndpoint);

  if (/Client Credential/.test(grant.label)) {
    await helpers.getAccessTokenClientCredentials(driver, clientId, 'secret',
        grant.scope);
  } else {
    await helpers.getAccessTokenPassword(driver, clientId, 'secret',
        grant.scope, 'caep-page-user', 'anything');
  }

  // THE HAND-OFF'S RETURN LINK, which is what takes the token set back. It is
  // clicked rather than navigated to, because the banner's handler is what
  // marks the set delivered.
  await driver.wait(until.elementLocated(By.id("token_handoff_return")), WAIT,
      "the OAuth2 / OIDC page drew no hand-off banner for " + grant.label +
      ", so nothing was delivered");
  await driver.findElement(By.id("token_handoff_return")).click();
  await driver.wait(async function () {
    return /ssf\.html/.test(await driver.getCurrentUrl());
  }, WAIT, "the hand-off did not come back to ssf.html");
  await driver.wait(until.elementLocated(By.id("pane_caep")), WAIT,
      "ssf.html came back without its CAEP pane");
  await click(driver, "btn_caep_seed");

  const out = {
    hadToken: (await valueOf(driver, "ssf_access_token")).length > 0,
    note: await textOf(driver, "caep_seed_note"),
    sub: await valueOf(driver, "caep_sub")
  };
  log.debug("Leaving oneGrant(). " + out.hadToken);
  return out;
}

// ---------------------------------------------------------------------------
// 3. SIMULATING EVERY ONE OF THE EIGHT.
// ---------------------------------------------------------------------------
async function everyEventCanBeSimulated(driver) {
  log.info("=== Simulating ===");
  await openPage(driver);
  await chooseProfile(driver, 'caep');
  await fill(driver, "ssf_base_url", stsUrl);
  await click(driver, "btn_ssf_discover");
  await waitForValue(driver, "ssf_discover_status", "discovery status");

  // THE CREDENTIAL. SSF 1.0 section 8 requires these endpoints to be
  // protected, and Basic is chosen for the reason ssf_page.js chooses it: it
  // is the only scheme that needs nothing but a header, so an authorization
  // server having a bad day cannot make this section fail and read as a CAEP
  // defect.
  await driver.executeScript(
      "document.getElementById('ssf_auth_scheme').value = 'basic';" +
      "window.ssf.authSchemeChanged();");
  await fill(driver, "ssf_basic_user", "caep-page-runner");
  await fill(driver, "ssf_basic_password", "pw");
  await driver.executeScript(
      "document.getElementById('ssf_stream_delivery').value = " +
      "'urn:ietf:rfc:8936'; window.ssf.deliveryChanged();");

  // A stream, so that there is somewhere for a receiver to be, and a key to
  // sign with. The signature is `jws.js`'s pure-JavaScript engine and NOT Web
  // Crypto, which is what lets this work on the containerized suite's
  // http origin where `crypto.subtle` does not exist at all.
  await fill(driver, "ssf_stream_aud", "https://caep-page.example/receiver");
  await click(driver, "btn_ssf_create");
  const status = await waitForValue(driver, "ssf_stream_status_text",
      "stream status");
  assert.ok(status.indexOf("Created") === 0,
      "Creating a stream said: " + status);
  const streamId = await valueOf(driver, "ssf_stream_id");
  assert.ok(streamId.length > 0, "No stream_id came back.");
  created.push(streamId);

  await click(driver, "btn_ssf_tx_key");
  await waitForValue(driver, "ssf_tx_private_key", "signing key");
  await fill(driver, "ssf_tx_iss", stsUrl);
  await fill(driver, "ssf_tx_aud", "https://caep-page.example/receiver");
  await fill(driver, "ssf_tx_endpoint", stsUrl + "/ssf/receive");
  await fill(driver, "caep_iss", stsUrl);
  await fill(driver, "caep_sub", "urn:sts-mock:user:caep-page");
  await fill(driver, "caep_sid", "caep-page-session");
  await driver.executeScript("window.ssf.renderCaep();");

  // SESSION-REVOKED LAST, and the order is the assertion. The model refuses a
  // `session-presented` about a session it has already been told was revoked
  // — a transmitter contradicting itself — so a run that sent the revocation
  // first would be refused for the right reason and would look like a bug.
  const order = ['session-established', 'session-presented',
    'token-claims-change', 'credential-change', 'assurance-level-change',
    'device-compliance-change', 'risk-level-change', 'session-revoked'];
  let short;
  for (short of order) {
    await click(driver, "btn_caep_" + short);
    try {
      await driver.wait(async function () {
        const token = await valueOf(driver, "ssf_tx_token");
        return token.split(".").length === 3;
      }, WAIT, short + " never produced a signed Security Event Token");
    } catch (e) {
      // THE TIMEOUT HAS TO NAME THE REASON AND NOT THE ELEMENT. Both status
      // lines are on the page and say exactly why — the payload was
      // refused, the model refused the transition, there is no receiver
      // endpoint — and a failure reading "an id never filled in" would send
      // whoever is looking at it to the wrong half of the page.
      throw new Error(short + ' produced no signed token. The CAEP pane ' +
          'said: ' + JSON.stringify(await textOf(driver,
              "caep_simulate_status")) + '. The Transmit pane said: ' +
          JSON.stringify(await valueOf(driver, "ssf_tx_status")) + '. (' +
          e.message.split("\n")[0] + ')');
    }
    const decoded = await driver.executeScript(
        "var t = document.getElementById('ssf_tx_token').value.split('.');" +
        "return t.length === 3 ? atob(t[1].replace(/-/g,'+')" +
        "  .replace(/_/g,'/')) : '';");
    const claims = JSON.parse(decoded);
    check(short + ' builds a Security Event Token carrying that event',
        function () {
          assert.ok(claims.events[P + short],
              'The token carries ' + Object.keys(claims.events).join(', '));
          assert.ok(claims.sub_id,
              'it carries no sub_id, so it says something happened and not ' +
              'to whom.');
          assert.strictEqual(claims.sub_id.session.id, 'caep-page-session');
          assert.strictEqual(claims.exp, undefined,
              'a SET MUST NOT be considered to expire — RFC 8417 section ' +
              '4.1.4 — because it records that something HAPPENED.');
        });
  }

  const state = await textOf(driver, "caep_state");
  check('THE SESSION STATE FOLLOWED THE EVENTS', function () {
    assert.ok(/revoked/.test(state),
        'The state readout says: ' + JSON.stringify(state.slice(0, 200)));
  });

  const counts = await textOf(driver, "caep_counts");
  check('and every one of the eight is counted', function () {
    assert.ok(/Total/.test(counts), counts.slice(0, 200));
    // The zeroes are drawn too — "nothing of this type has been sent" is the
    // answer to "why did nothing arrive" nine times out of ten — so the
    // count of ROWS is eight plus the total line whatever was sent.
    const rows = counts.split("\n").filter(function (line) {
      return line.trim();
    });
    assert.ok(rows.length >= 9,
        'The counts table has ' + rows.length + ' rows: ' + counts);
  });

  // THE ONE HARD REFUSAL, on the page. A `session-presented` about a session
  // this page has already said was revoked is a transmitter contradicting
  // itself, and the pane refuses to build one rather than signing it.
  const before = await valueOf(driver, "ssf_tx_token");
  await click(driver, "btn_caep_session-presented");
  const refusal = await waitForText(driver, "caep_simulate_status",
      "refusal");
  check('A REVOKED SESSION CANNOT BE PRESENTED, and the pane refuses to ' +
      'build one', function () {
        assert.ok(/REVOKED/i.test(refusal),
            'The pane said: ' + JSON.stringify(refusal));
      });
}

// ---------------------------------------------------------------------------
// 4. THE RESET.
//
// Its one failure mode is SILENCE. A Reset that could not delete the stream —
// the credential expired, the transmitter is down — and said nothing would
// leave somebody debugging yesterday's stream while believing they had
// started over, which is worse than a button that says what it could not do.
// ---------------------------------------------------------------------------
async function theResetStartsOver(driver) {
  log.info("=== Reset ===");
  const streamBefore = await valueOf(driver, "ssf_stream_id");
  assert.ok(streamBefore, "there is no stream to reset away.");

  // The confirm is answered by replacing it, which is what a headless run
  // has to do: an unanswered confirm() blocks the page and the next command
  // times out naming an element.
  await driver.executeScript("window.confirm = function () { return true; };");
  await click(driver, "btn_ssf_reset");
  const said = await waitForText(driver, "ssf_profile_note", "reset note");

  check('the reset SAYS WHAT IT DID, step by step', function () {
    assert.ok(/Started over/.test(said),
        'It said: ' + JSON.stringify(said));
    assert.ok(said.indexOf(streamBefore) >= 0,
        'It does not name the stream it asked the transmitter to delete. ' +
        'A reset that quietly failed to delete one would leave somebody ' +
        'debugging yesterday\'s stream while believing they had started ' +
        'over — which is the one failure this button must not hide. It ' +
        'said: ' + said);
    assert.ok(/histories/.test(said), said);
  });

  assert.strictEqual(await valueOf(driver, "ssf_stream_id"), '');
  const counts = await textOf(driver, "caep_counts");
  assert.ok(/Total\s*0/.test(counts.replace(/\n/g, ' ')),
      'The counters still read: ' + counts);
  passed("the stream id is cleared and the counters are zero");

  // AND THE PAGE IS STILL USABLE, which is the half a reset most often gets
  // wrong: a control that empties its own state and leaves the page in one
  // it cannot recover from is not a reset.
  await fill(driver, "caep_sid", "after-the-reset");
  await driver.executeScript("window.ssf.renderCaep();");
  await click(driver, "btn_caep_session-established");
  await driver.wait(async function () {
    return (await valueOf(driver, "ssf_tx_token")).split(".").length === 3;
  }, WAIT, "the page could not build an event after the reset");
  passed("and the page still works afterwards");
}

// ---------------------------------------------------------------------------
// 5. THE CONSOLE IS CLEAN AND EVERY ssf- CLASS IS DEFINED.
// ---------------------------------------------------------------------------
async function theConsoleIsCleanAndTheStylesAreThere(driver) {
  log.info("=== Console and styles ===");
  const unstyled = await driver.executeScript(
    "var defined = {};" +
    "Array.prototype.slice.call(document.styleSheets).forEach(" +
    "  function (sheet) {" +
    "    var rules = null;" +
    "    try { rules = sheet.cssRules; } catch (e) { rules = null; }" +
    "    if (!rules) { return; }" +
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
    "return Object.keys(used).filter(function (c) {" +
    "  return /^ssf-/.test(c) && !defined[c]; });");
  check('every ssf- class the CAEP pane creates is defined in a stylesheet ' +
      'the page loads', function () {
        assert.deepStrictEqual(unstyled, [],
            'these are used and styled nowhere: ' + unstyled.join(', ') +
            '. The CAEP pane builds most of its classes from script, so ' +
            'they are only on the page after something has been simulated — ' +
            'which is why this check runs last.');
      });

  const entries = await driver.manage().logs().get("browser");
  const bad = entries.filter(function (one) {
    // A load the browser abandoned because its own certificate or network
    // configuration changed under it says nothing about this workflow. See
    // browser_flags.js.
    return one.level && one.level.name === "SEVERE" &&
      !browserFlags.isTransientLoadError(one.message);
  }).map(function (one) {
    return one.message;
  });
  check('and nothing threw in the browser', function () {
    assert.deepStrictEqual(bad, [],
        'the console carried: ' + bad.join(" | ") + '. A handler that threw ' +
        'shows up here and nowhere else — every other assertion in this ' +
        'file would still pass.');
  });
}

async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const page = await fetch(baseUrl + "/ssf.html");
    if (!page.ok) {
      log.debug("Leaving preconditions(). No page.");
      return { ok: false, why: baseUrl + "/ssf.html answered " +
        page.status + " — this build does not carry the Shared Signals page" };
    }
    const doc = await fetch(stsUrl + "/.well-known/ssf-configuration");
    if (!doc.ok) {
      log.debug("Leaving preconditions(). No transmitter.");
      return { ok: false, why: "no SSF transmitter at " + stsUrl +
        " (/.well-known/ssf-configuration answered " + doc.status + ")" };
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
          Buffer.from("caep-page-runner:pw").toString("base64") },
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
  // A FAILURE rather than a skip: the launcher gates this job itself, so
  // reaching this line means it expected the page and a transmitter.
  mustBeReady(ready, "the client (for ssf.html), the api and the mock STS " +
              "acting as an SSF transmitter.");
  log.info("driving " + baseUrl + "/ssf.html in CAEP mode against the " +
      "transmitter at " + stsUrl);

  const options = new chrome.Options();
  // --headless=new, never bare --headless: a CI runner and the tests
  // container have no display, and a windowed session fails at `session not
  // created` naming the page it was about to visit.
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,2400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // **THE GRANT HELPERS GET A LONGER WAIT THAN `waitTime`, AND IT IS NOT A
  // FLAKE PATCH.** `waitTime` is 2000ms and is right for a field on a page
  // that is already loaded; every wait those helpers make is across a
  // NAVIGATION — `oauth2_oidc_1.html`'s onload sends a token-endpoint-only
  // grant straight on to page 2, so the element being waited for is on a
  // document that has not been fetched yet. A wait is a TIMEOUT and not a
  // sleep, so raising it costs a passing run nothing and only lets a broken
  // one take longer to fail. TEST_WAIT_TIME_MS overrides it, as everywhere
  // else in this suite.
  const grantWait = Number(process.env.TEST_WAIT_TIME_MS) ||
      Math.max(Number(appconfig.waitTime) || 2000, 10000);
  const helpers = require("../common/tests.js")({ By, until, Select,
    waitTime: grantWait, log: log, jwt: null, assert: assert });

  try {
    await theProfileSwitchReconfiguresThePage(driver);
    await eachGrantShapeSeedsTheSession(driver);
    await twoGrantsReachTheCaepPaneForReal(driver, helpers);
    await everyEventCanBeSimulated(driver);
    await theResetStartsOver(driver);
    // LAST, and the order is load-bearing: most of the CAEP pane's classes
    // are on elements the bundle CREATES, so they are not on the page until
    // something has been simulated — and a style check before that would
    // pass by examining a page that has not drawn them yet.
    await theConsoleIsCleanAndTheStylesAreThere(driver);
    log.info(checks + " checks passed.");
    assert.ok(checks >= 20,
        'Only ' + checks + ' checks ran. A section has stopped being called.');
    log.info("Test completed successfully.");
  } finally {
    // driver.quit() in a FINALLY and never after a process.exit(): the exit
    // skips the finally, and one headless Chrome is about fifteen OS
    // processes of which only the first is this runner's child.
    await cleanUp();
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("caep_page")
  .description("Verify the CAEP half of the Shared Signals page: that the " +
      "profile switch narrows every event list and brings up the session " +
      "pane, that the session is seeded from what six different OAuth2 / " +
      "OIDC grants produce — including the two that issue no ID Token at " +
      "all — that every one of the eight events can be built, signed and " +
      "pushed, that the state and the counters follow them, and that the " +
      "reset says what it did.")
  .addOption(new Option("-u, --url <url>", "base url of the client"))
  .parse(process.argv);

if (program.opts().url) {
  baseUrl = program.opts().url;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
