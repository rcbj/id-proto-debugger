// File: caep_engine.js
//
// ---------------------------------------------------------------------------
// THE CAEP VOCABULARY AND THE SESSION MODEL, DRIVEN IN NODE WITH NO
// TRANSMITTER AND NO BROWSER.
//
// `client/src/ssf_events.js` is the VOCABULARY — CAEP's eight event types are
// rows in its table, which is what that file's header promised while it had
// two. `client/src/caep_session.js` is what those rows are ABOUT: a session,
// the state CAEP believes it is in, and what has been said concerning it.
// Neither has a DOM, and that is what this file exists to take advantage of.
//
// **WHY THIS IS SEPARATE FROM `caep_protocol.js` AND `caep_page.js`.** Those
// two need the mock STS and a browser, so a failure in either can be three
// things: this client is wrong, that transmitter is wrong, or the two are fine
// and something between them is not. Here there is nothing in between. A
// failure in this file is a defect in what this workflow composes or accepts,
// asserted against CAEP 1.0's own text, and it names the member rather than
// naming a page.
//
// ---------------------------------------------------------------------------
// THE DEFECTS THIS PROFILE ACTUALLY PRODUCES ARE NEVER CRASHES, which is the
// whole argument for a file like this one:
//
//   * `reason_admin` sent as a STRING rather than as an object keyed by a
//     language tag. It is the commonest mistake in the profile and it has NO
//     SYMPTOM: a receiver indexing by language reads nothing from a string and
//     reports no error.
//   * `event_timestamp` sent as the string "1757000000". Parsed by everything,
//     compared numerically by nobody.
//   * `amr` sent as a bare string, so a session authenticated two ways reads
//     as one.
//   * a subject naming the PERSON and not the session, which asks a receiver
//     to end every session that person has — from an event that named one.
//   * a `token-claims-change` applied as a replacement rather than a merge,
//     which silently drops every claim the event did not mention.
//   * a `session-presented` about a session the transmitter has already
//     revoked, which is a transmitter contradicting itself.
//
// Every one of those produces a workflow that works perfectly against itself.
//
// SEVEN SECTIONS:
//
//   1. the eight URIs, spelled out — a typo in the shared prefix would
//      otherwise pass, because every row is built from it
//   2. the required members, and the closed enumerations
//   3. the four common claims, on every one of the eight
//   4. the open enumerations, which WARN rather than refuse
//   5. the complex subject, through the pipe's own RFC 9493 grammar
//   6. the state machine: every transition, and the two things it refuses
//   7. the counters, the ring, the suggestions and the reset
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "caep_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// requireSharedModule() is what makes a module borrowed from client/src
// resolve its own dependencies — see tests/module_paths.js. In a checkout
// these live under client/src; the tests image copies them flat beside the
// test scripts.
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const caep = paths.requireSharedModule(
  [__dirname + "/../client/src/caep_session.js",
   __dirname + "/caep_session.js"], "caep_session.js");
const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");
// The protocol table the pane's selector and both seeders read. It is here
// because the assertion this file makes about seeding is an assertion about
// the two ends AGREEING — see everySignInProtocolSeedsASession().
const sessionHandoff = paths.requireSharedModule(
  [__dirname + "/../client/src/session_handoff.js",
   __dirname + "/session_handoff.js"], "session_handoff.js");

const P = "https://schemas.openid.net/secevent/caep/event-type/";

var checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.debug("Leaving check(). " + what);
}

// A refusal has to NAME what is wrong. Asserting only `!ok` would pass against
// a validator that refused everything, which is the failure mode a permissive
// grammar most easily degrades into.
function refuses(verdict, fragment, what) {
  assert.ok(!verdict.ok, what + ': it was accepted and should not have been.');
  const joined = verdict.errors.join(' ');
  assert.ok(joined.indexOf(fragment) >= 0,
      what + ': the refusal does not mention "' + fragment + '". It said: ' +
      joined);
  checks++;
}

function warns(verdict, fragment, what) {
  assert.ok(verdict.ok, what + ': it was REFUSED and should have been ' +
      'carried. It said: ' + verdict.errors.join(' '));
  const joined = verdict.warnings.join(' ');
  assert.ok(joined.indexOf(fragment) >= 0,
      what + ': nothing warned about "' + fragment + '". It said: ' + joined);
  checks++;
}

function session() {
  return caep.newSession({ iss: 'https://sts.example.com', sub: 'u-alice',
    sid: 'sid-1', deviceId: 'dev-1', tenant: 'acme', acr: 'urn:example:silver',
    amr: ['pwd'] });
}

// ---------------------------------------------------------------------------
// 1. THE EIGHT URIs, SPELLED OUT.
//
// Written as string literals rather than built from `CAEP_PREFIX`, which is
// the whole point of the section: every row in the catalogue is built from
// that constant, so a typo in it would produce eight consistently wrong URIs
// that agree with each other perfectly and with nobody else. There is no
// "unknown event type" error in this protocol — a receiver silently ignores
// what it does not recognise — so the only way to catch that is to write the
// strings out again from the specification.
// ---------------------------------------------------------------------------
function theEightUris() {
  log.debug("Entering theEightUris().");
  log.info("1. the eight event type URIs, written out from the specification");

  const expected = [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "https://schemas.openid.net/secevent/caep/event-type/session-established",
    "https://schemas.openid.net/secevent/caep/event-type/session-presented",
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
    "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "https://schemas.openid.net/secevent/caep/event-type/" +
      "assurance-level-change",
    "https://schemas.openid.net/secevent/caep/event-type/" +
      "device-compliance-change",
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
  ];

  check("every one of CAEP's eight is in the catalogue", function () {
    expected.forEach(function (uri) {
      assert.ok(events.EVENT_BY_URI[uri],
          '"' + uri + '" is not in the catalogue. Every row is built from ' +
          'CAEP_PREFIX, so a typo there produces eight URIs that agree with ' +
          'each other and with nothing else — and this protocol has no ' +
          '"unknown event type" error, so a receiver would ignore them all ' +
          'in silence.');
    });
  });

  check("and there are exactly eight, so a ninth is deliberate", function () {
    assert.strictEqual(events.CAEP_EVENT_URIS.length, 8,
        'CAEP 1.0 defines eight event types.');
  });

  check("every one of them is family 'caep'", function () {
    expected.forEach(function (uri) {
      assert.strictEqual(events.EVENT_BY_URI[uri].family, 'caep', uri);
    });
  });

  check("familyOf() places a CAEP type this build does NOT implement as " +
      "caep rather than as unknown", function () {
    assert.strictEqual(events.familyOf(P + 'something-not-yet-invented'),
        'caep',
        '"a CAEP event this build does not implement" is a far more useful ' +
        'thing to draw than "unknown": it says the transmitter is ahead of ' +
        'this tool rather than wrong.');
  });

  check("EVERY CAEP EVENT REQUIRES A SUBJECT, and SSF's own two require " +
      "none", function () {
    events.CAEP_EVENTS.forEach(function (row) {
      assert.strictEqual(row.subject, 'required', row.uri +
          ' must carry a subject: an event that says something happened and ' +
          'not to whom is dropped at the far end with no error anybody ' +
          'sees.');
    });
    events.SSF_EVENTS.forEach(function (row) {
      assert.strictEqual(row.subject, 'none', row.uri +
          ' is about the STREAM, and a receiver that insisted on a subject ' +
          'could not be verified.');
    });
  });

  // ALL THREE ARE IMPLEMENTED SINCE 2026-09-04, and this check asserted the
  // opposite for RISC until that day. It is worth keeping in this file rather
  // than only in `risc_engine.js`: what it guards is that the three rows stay
  // HONEST about themselves, and a row claiming a vocabulary that is not
  // there is the same defect in the other direction — a reader unable to tell
  // "this tool does not do it" from "I have not found it yet".
  check("all three families say they are implemented, because they are",
      function () {
    const byId = {};
    events.FAMILIES.forEach(function (row) {
      byId[row.id] = row;
    });
    assert.strictEqual(byId.caep.implemented, true);
    assert.strictEqual(byId.risc.implemented, true,
        'RISC arrived on 2026-09-04 and the row has to say so — see ' +
        'risc_engine.js, which asserts the fourteen event types behind it.');
    assert.ok(byId.risc.what.indexOf('NOT IMPLEMENTED') < 0,
        'the RISC row still describes itself as absent.');
  });

  check("the three profiles, and what each offers", function () {
    assert.strictEqual(events.PROFILES.length, 3);
    assert.strictEqual(events.eventsForFamily('ssf').length, 2);
    assert.strictEqual(events.eventsForFamily('caep').length, 8);
    assert.strictEqual(events.eventsForFamily('risc').length, 14,
        'RISC offers fourteen event types since 2026-09-04.');
  });

  check("an unknown profile answers the pipe rather than throwing",
      function () {
    assert.strictEqual(events.profileOf('nonsense').id, 'ssf',
        'a page that failed to load because of a stored string would be the ' +
        'worst possible way to find that out.');
    assert.strictEqual(events.profileOf('').id, 'ssf');
  });

  log.debug("Leaving theEightUris().");
}

// ---------------------------------------------------------------------------
// 2. THE REQUIRED MEMBERS AND THE CLOSED ENUMERATIONS.
// ---------------------------------------------------------------------------
function requiredMembersAndClosedEnums() {
  log.debug("Entering requiredMembersAndClosedEnums().");
  log.info("2. required members, and the enumerations that are closed");

  check("token-claims-change needs `claims`, which is its whole payload",
      function () {
    refuses(events.validateEvent(P + 'token-claims-change', {}),
        'claims', 'an empty token-claims-change');
  });

  check("and `claims` must be an OBJECT — an array parses and means nothing",
      function () {
    refuses(events.validateEvent(P + 'token-claims-change',
        { claims: ['groups'] }), 'JSON object', 'claims as an array');
  });

  check("credential-change needs both its members", function () {
    refuses(events.validateEvent(P + 'credential-change',
        { credential_type: 'password' }), 'change_type',
        'a credential-change with no change_type');
    refuses(events.validateEvent(P + 'credential-change',
        { change_type: 'revoke' }), 'credential_type',
        'a credential-change with no credential_type');
  });

  check("change_type is CLOSED: those four are the whole lifecycle",
      function () {
    refuses(events.validateEvent(P + 'credential-change',
        { credential_type: 'password', change_type: 'mutate' }),
        'must be one of', 'change_type = mutate');
  });

  check("device-compliance-change needs BOTH statuses, and previous_status " +
      "is what makes a missed event visible", function () {
    refuses(events.validateEvent(P + 'device-compliance-change',
        { current_status: 'not-compliant' }), 'previous_status',
        'a compliance change with no previous_status');
  });

  check("and the hyphen is the specification's: noncompliant is refused",
      function () {
    refuses(events.validateEvent(P + 'device-compliance-change',
        { previous_status: 'compliant', current_status: 'noncompliant' }),
        'must be one of', 'current_status = noncompliant');
  });

  check("assurance-level-change needs a namespace, because the level means " +
      "nothing without one", function () {
    refuses(events.validateEvent(P + 'assurance-level-change',
        { current_level: 'aal2' }), 'namespace',
        'an assurance change with no namespace');
  });

  check("change_direction is closed to increase and decrease", function () {
    refuses(events.validateEvent(P + 'assurance-level-change',
        { namespace: 'NIST-AAL', current_level: 'aal2',
          change_direction: 'sideways' }), 'must be one of',
        'change_direction = sideways');
  });

  check("risk-level-change needs a principal AND a level, and the levels " +
      "are UPPER CASE", function () {
    refuses(events.validateEvent(P + 'risk-level-change',
        { current_level: 'HIGH' }), 'principal',
        'a risk change with no principal');
    refuses(events.validateEvent(P + 'risk-level-change',
        { principal: 'SESSION', current_level: 'high' }), 'must be one of',
        'current_level = high, in lower case');
  });

  check("session-revoked requires nothing at all, and that is not an " +
      "oversight", function () {
    const verdict = events.validateEvent(P + 'session-revoked', {});
    assert.ok(verdict.ok,
        'everything a session-revoked has to say is in the subject and the ' +
        'four common claims. There is nothing to qualify.');
  });

  check("`amr` must be an ARRAY of strings and a bare string is REFUSED",
      function () {
    refuses(events.validateEvent(P + 'session-established', { amr: 'pwd' }),
        'ARRAY of strings',
        'amr as a bare string. It is refused rather than wrapped: a session ' +
        'authenticated a second way has two values, and wrapping would hide ' +
        'a sender that can only ever say one.');
    const ok = events.validateEvent(P + 'session-established',
        { amr: ['pwd', 'hwk'] });
    assert.ok(ok.ok, ok.errors.join(' '));
  });

  log.debug("Leaving requiredMembersAndClosedEnums().");
}

// ---------------------------------------------------------------------------
// 3. THE FOUR CLAIMS CAEP GIVES EVERY EVENT.
//
// The language-map check is the one worth reading. CAEP section 2 makes
// `reason_admin` and `reason_user` objects keyed by a BCP 47 tag; a string
// there is the commonest mistake in the whole profile and has NO SYMPTOM,
// because a receiver indexing by language reads nothing from one and reports
// no error. It is refused here or nowhere.
// ---------------------------------------------------------------------------
function theFourCommonClaims() {
  log.debug("Entering theFourCommonClaims().");
  log.info("3. the four claims CAEP gives every one of its eight events");

  check("all four are accepted on EVERY one of the eight", function () {
    events.CAEP_EVENTS.forEach(function (row) {
      const payload = events.generateEvent(row.uri, {});
      payload.event_timestamp = 1788000000;
      payload.initiating_entity = 'policy';
      payload.reason_admin = { en: 'Policy 4.2 was violated' };
      payload.reason_user = { en: 'You have been signed out.' };
      const verdict = events.validateEvent(row.uri, payload);
      assert.ok(verdict.ok, row.uri + ': ' + verdict.errors.join(' '));
    });
  });

  check("and all four are OPTIONAL — an event with none of them is valid",
      function () {
    events.CAEP_EVENTS.forEach(function (row) {
      const verdict = events.validateEvent(row.uri,
          events.generateEvent(row.uri, {}));
      assert.ok(verdict.ok, row.uri + ': ' + verdict.errors.join(' '));
    });
  });

  check("reason_admin AS A STRING IS REFUSED — the mistake with no symptom",
      function () {
    refuses(events.validateEvent(P + 'session-revoked',
        { reason_admin: 'Policy 4.2 was violated' }),
        'LANGUAGE TAG',
        'reason_admin as a string. A receiver indexing by language reads ' +
        'nothing from one and reports no error, so this is caught here or ' +
        'it is not caught.');
  });

  check("and so is reason_user", function () {
    refuses(events.validateEvent(P + 'session-revoked',
        { reason_user: 'You have been signed out.' }), 'LANGUAGE TAG',
        'reason_user as a string');
  });

  check("a language map whose value is not a string is refused", function () {
    refuses(events.validateEvent(P + 'session-revoked',
        { reason_admin: { en: 42 } }), 'must be a string',
        'reason_admin.en as a number');
  });

  check("a tag that is not shaped like BCP 47 is CARRIED and warned about",
      function () {
    warns(events.validateEvent(P + 'session-revoked',
        { reason_admin: { 'not a tag': 'why' } }), 'BCP 47',
        'a reason keyed by something that is not a language tag. Nothing ' +
        'here owns that registry, so it is carried — and a receiver looking ' +
        'for "en" will not find it.');
  });

  check("event_timestamp AS A STRING IS REFUSED", function () {
    refuses(events.validateEvent(P + 'session-revoked',
        { event_timestamp: '1788000000' }), 'NUMBER',
        'a quoted timestamp. It parses everywhere and is compared ' +
        'numerically nowhere.');
  });

  check("initiating_entity is closed to CAEP's four", function () {
    refuses(events.validateEvent(P + 'session-revoked',
        { initiating_entity: 'robot' }), 'must be one of',
        'initiating_entity = robot');
    ['admin', 'user', 'policy', 'system'].forEach(function (who) {
      const verdict = events.validateEvent(P + 'session-revoked',
          { initiating_entity: who });
      assert.ok(verdict.ok, who + ': ' + verdict.errors.join(' '));
    });
  });

  check("an unrecognised member is a WARNING and not an error, which is the " +
      "opposite of the subject rule", function () {
    warns(events.validateEvent(P + 'session-revoked',
        { acme_extension: 'something' }), 'not a member',
        'a vendor extension on a CAEP event. RFC 9493 closes a SUBJECT ' +
        'identifier\'s member set because an extra member might NARROW the ' +
        'subject; an event payload has no such rule, and refusing would ' +
        'make this workflow unable to build a vendor\'s own extension.');
  });

  log.debug("Leaving theFourCommonClaims().");
}

// ---------------------------------------------------------------------------
// 4. THE OPEN ENUMERATIONS.
//
// `credential_type`, `namespace` and `principal` are lists CAEP says two
// parties may extend. Refusing a value outside them would make this workflow
// unable to mock a vendor's own type, which is exactly what a debugger is for
// — and accepting one SILENTLY would be worse, because nothing would say that
// a receiver which has not been told about it will ignore the event.
// ---------------------------------------------------------------------------
function theOpenEnumerations() {
  log.debug("Entering theOpenEnumerations().");
  log.info("4. the three open enumerations: carried, and warned about");

  check("a vendor's own credential_type is carried with a warning",
      function () {
    warns(events.validateEvent(P + 'credential-change',
        { credential_type: 'acme-smartcard', change_type: 'create' }),
        'OPEN', 'an unlisted credential type');
  });

  check("and every value CAEP does list is accepted without one", function () {
    ['password', 'pin', 'x509', 'fido2-platform', 'fido2-roaming',
     'fido-u2f', 'verifiable-credential', 'phone-voice', 'phone-sms', 'app']
      .forEach(function (type) {
        const verdict = events.validateEvent(P + 'credential-change',
            { credential_type: type, change_type: 'create' });
        assert.ok(verdict.ok, type + ': ' + verdict.errors.join(' '));
        assert.strictEqual(verdict.warnings.length, 0,
            type + ' is one of CAEP\'s own and should not warn.');
      });
  });

  check("an assurance namespace nobody has heard of is carried", function () {
    warns(events.validateEvent(P + 'assurance-level-change',
        { namespace: 'ACME-LEVELS', current_level: 'gold' }), 'OPEN',
        'an aliased assurance namespace');
  });

  check("and all six CAEP names are accepted", function () {
    ['RFC8176', 'RFC6711', 'ISO-IEC-29115', 'NIST-IAL', 'NIST-AAL',
     'NIST-FAL'].forEach(function (namespace) {
      const verdict = events.validateEvent(P + 'assurance-level-change',
          { namespace: namespace, current_level: 'aal2' });
      assert.strictEqual(verdict.warnings.length, 0, namespace);
    });
  });

  check("a risk principal outside SSF's six is carried", function () {
    warns(events.validateEvent(P + 'risk-level-change',
        { principal: 'WORKLOAD', current_level: 'HIGH' }), 'OPEN',
        'an unlisted risk principal');
  });

  check("AND THE CASE IS THE TRAP: principal is UPPER CASE here and a " +
      "complex subject's members are lower", function () {
    warns(events.validateEvent(P + 'risk-level-change',
        { principal: 'session', current_level: 'HIGH' }), 'OPEN',
        'principal = session in lower case. It is carried because the list ' +
        'is open, and it is not the value CAEP names — which catches ' +
        'everybody once, because the complex subject member IS lower case.');
  });

  log.debug("Leaving theOpenEnumerations().");
}

// ---------------------------------------------------------------------------
// 5. THE COMPLEX SUBJECT.
// ---------------------------------------------------------------------------
function theComplexSubject() {
  log.debug("Entering theComplexSubject().");
  log.info("5. the subject, through the pipe's own RFC 9493 grammar");

  check("it is a COMPLEX subject, told from a plain one by the ABSENCE of " +
      "`format`", function () {
    const subject = caep.complexSubject(session(), {});
    assert.strictEqual(subject.format, undefined,
        'that is SSF section 4\'s own discriminator. "does it have a member ' +
        'called user" is wrong for an opaque subject whose id happens to be ' +
        'spelt that way.');
    assert.strictEqual(subject.user.format, 'issuer_subject_id');
    assert.strictEqual(subject.session.format, 'opaque');
  });

  check("and it validates against ssf_client.js's grammar", function () {
    const verdict = caep.checkSubject(caep.complexSubject(session(), {}), []);
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });

  check("the device and the tenant are opt-in, because a subject naming a " +
      "device nobody asked about narrows it", function () {
    const bare = caep.complexSubject(session(), {});
    assert.strictEqual(bare.device, undefined);
    const full = caep.complexSubject(session(),
        { includeDevice: true, includeTenant: true });
    assert.strictEqual(full.device.id, 'dev-1');
    assert.strictEqual(full.tenant.id, 'acme');
    assert.ok(caep.checkSubject(full, []).ok);
  });

  check("A SUBJECT WITH NO SESSION IS STILL VALID, and that is the one this " +
      "workflow can send by mistake", function () {
    const personOnly = caep.complexSubject(session(),
        { includeSession: false });
    assert.strictEqual(personOnly.session, undefined);
    assert.ok(caep.checkSubject(personOnly, []).ok,
        'it is perfectly conforming, which is exactly why it is dangerous: ' +
        'it asks a receiver to end EVERY session that person has, from an ' +
        'event that meant one. The page says so rather than refusing, ' +
        'because it is the single most useful thing to send at a receiver ' +
        'under test.');
  });

  check("critical_subject_members is a PROMISE, and omitting a member it " +
      "names is refused", function () {
    const personOnly = caep.complexSubject(session(),
        { includeSession: false });
    const verdict = caep.checkSubject(personOnly, ['session']);
    assert.ok(!verdict.ok,
        'a transmitter publishing critical_subject_members promises that ' +
        'every complex subject carries them; sending one that does not ' +
        'would be refused at the far end, and the message is more useful on ' +
        'this side.');
  });

  check("seedFrom() says when the session identifier was GENERATED HERE",
      function () {
    const withSid = caep.seedFrom({ iss: 'https://sts.example.com',
        sub: 'u-1', sid: 'real-session' });
    assert.strictEqual(withSid.problems.length, 0);
    assert.strictEqual(withSid.session.sid, 'real-session');

    const withoutSid = caep.seedFrom({ iss: 'https://sts.example.com',
        sub: 'u-1' });
    assert.strictEqual(withoutSid.problems.length, 1);
    assert.ok(withoutSid.problems[0].indexOf('GENERATED HERE') >= 0,
        'an event naming a session identifier this page invented is about ' +
        'nothing at the far end, and the pane has to say so.');
    assert.ok(withoutSid.session.sid.indexOf('debugger-') === 0,
        'AND THE VALUE SAYS SO TOO. A random hex string would be ' +
        'indistinguishable from a transmitter\'s, and somebody would ' +
        'eventually paste one into a real system.');
  });

  check("a grant with NO ID Token is a supported case, not an error",
      function () {
    const none = caep.seedFrom({});
    assert.strictEqual(none.problems.length, 2,
        'client credentials and resource owner password both produce a ' +
        'session at the authorization server; what is missing is this ' +
        'page\'s ability to NAME it.');
    assert.ok(none.session,
        'and a session model still comes back — nothing is blocked, ' +
        'because a debugger pointed at somebody\'s transmitter is entitled ' +
        'to name whatever subject it likes.');
  });

  log.debug("Leaving theComplexSubject().");
}

// ---------------------------------------------------------------------------
// 6. THE STATE MACHINE.
// ---------------------------------------------------------------------------
function theStateMachine() {
  log.debug("Entering theStateMachine().");
  log.info("6. every transition, and the two things the model refuses");

  check("established -> presented -> revoked", function () {
    const s = session();
    assert.strictEqual(s.state, 'established');
    caep.apply(s, P + 'session-presented', {});
    assert.strictEqual(s.state, 'presented');
    caep.apply(s, P + 'session-revoked', {});
    assert.strictEqual(s.state, 'revoked');
  });

  check("A REVOKED SESSION CANNOT HAVE BEEN PRESENTED — the one hard " +
      "refusal", function () {
    const s = session();
    caep.apply(s, P + 'session-revoked', {});
    const verdict = caep.apply(s, P + 'session-presented', {});
    assert.ok(!verdict.ok,
        'that sentence says a session this transmitter has already declared ' +
        'dead was just used and honoured, which is either a transmitter ' +
        'contradicting itself or a receiver about to be told to trust ' +
        'something it was told to stop trusting.');
    assert.strictEqual(s.state, 'revoked',
        'AND THE STATE DID NOT MOVE. A refusal that still applied the ' +
        'change would be worse than none.');
  });

  check("a SECOND revocation is allowed and warned about", function () {
    const s = session();
    caep.apply(s, P + 'session-revoked', {});
    const verdict = caep.apply(s, P + 'session-revoked', {});
    assert.ok(verdict.ok,
        'a receiver should be idempotent about it, which is exactly the ' +
        'thing worth being able to test.');
    assert.ok(verdict.warnings.length > 0, 'and it is noted.');
  });

  check("re-establishing a revoked session is allowed and warned about",
      function () {
    const s = session();
    caep.apply(s, P + 'session-revoked', {});
    const verdict = caep.apply(s, P + 'session-established', {});
    assert.ok(verdict.ok);
    assert.strictEqual(s.state, 'established');
    assert.ok(verdict.warnings.length > 0,
        'a receiver that kept the revocation will ignore everything about ' +
        'it from here on, which is worth seeing happen.');
  });

  check("PREVIOUS_STATUS IS HOW A MISSED EVENT BECOMES VISIBLE, and nothing " +
      "else can see it", function () {
    const s = session();
    caep.apply(s, P + 'device-compliance-change',
        { previous_status: 'compliant', current_status: 'not-compliant' });
    assert.strictEqual(s.compliance, 'not-compliant');
    const gap = caep.apply(s, P + 'device-compliance-change',
        { previous_status: 'compliant', current_status: 'not-compliant' });
    assert.ok(gap.warnings.some(function (one) {
      return one.indexOf('INVISIBLE FROM EITHER EVENT') >= 0;
    }), 'this model holds "not-compliant" and the event says the device was ' +
        '"compliant", so one event never arrived. That gap is invisible ' +
        'from either event on its own and it is the whole reason CAEP makes ' +
        'previous_status required.');
  });

  check("and the same comparison catches a missed risk event", function () {
    const s = session();
    caep.apply(s, P + 'risk-level-change',
        { principal: 'SESSION', current_level: 'HIGH', previous_level: 'LOW' });
    assert.strictEqual(s.risk.level, 'HIGH');
    const gap = caep.apply(s, P + 'risk-level-change',
        { principal: 'SESSION', current_level: 'LOW', previous_level: 'LOW' });
    assert.ok(gap.warnings.length > 0);
  });

  check("and a missed assurance event", function () {
    const s = session();
    caep.apply(s, P + 'assurance-level-change',
        { namespace: 'NIST-AAL', current_level: 'aal2' });
    const gap = caep.apply(s, P + 'assurance-level-change',
        { namespace: 'NIST-AAL', current_level: 'aal1',
          previous_level: 'aal3' });
    assert.ok(gap.warnings.some(function (one) {
      return one.indexOf('has been missed') >= 0;
    }));
  });

  check("A DECREASE IN ASSURANCE IS CALLED OUT, because it is the direction " +
      "everybody forgets can happen with no new sign-in", function () {
    const s = session();
    const verdict = caep.apply(s, P + 'assurance-level-change',
        { namespace: 'NIST-AAL', current_level: 'aal1',
          previous_level: 'aal2', change_direction: 'decrease' });
    assert.ok(verdict.warnings.some(function (one) {
      return one.indexOf('went DOWN') >= 0;
    }));
  });

  check("TOKEN CLAIMS ARE MERGED AND NOT REPLACED", function () {
    const s = session();
    caep.apply(s, P + 'token-claims-change',
        { claims: { groups: ['staff'], department: 'ops' } });
    caep.apply(s, P + 'token-claims-change', { claims: { groups: [] } });
    assert.strictEqual(s.claims.department, 'ops',
        'a claim the second event did not mention SURVIVES. `claims` ' +
        'carries only what moved, with its new value — a receiver that ' +
        'replaced would drop every claim the event was silent about, which ' +
        'is most of them.');
    assert.strictEqual(s.claims.groups.length, 0,
        'and the one it did mention took its new value.');
  });

  check("a credential taken away leaves the session GOOD, and says so",
      function () {
    const s = session();
    const verdict = caep.apply(s, P + 'credential-change',
        { credential_type: 'fido2-platform', change_type: 'revoke' });
    assert.strictEqual(s.state, 'established',
        'losing a second factor does not invalidate the session it was used ' +
        'to establish. It is the CAEP event a receiver acts on without ' +
        'ending anything.');
    assert.ok(verdict.warnings.length > 0);
    assert.strictEqual(s.credentials[0].changeType, 'revoke');
  });

  check("an SSF event on a CAEP session changes nothing and is not an error",
      function () {
    const s = session();
    const verdict = caep.apply(s,
        'https://schemas.openid.net/secevent/ssf/event-type/verification', {});
    assert.ok(verdict.ok);
    assert.strictEqual(s.state, 'established',
        'the pipe\'s own two travel on the same stream and are about the ' +
        'stream rather than about anybody.');
  });

  log.debug("Leaving theStateMachine().");
}

// ---------------------------------------------------------------------------
// 7. THE COUNTERS, THE RING, THE SUGGESTIONS AND THE RESET.
// ---------------------------------------------------------------------------
function countersAndSuggestions() {
  log.debug("Entering countersAndSuggestions().");
  log.info("7. the counters against the ring, what the pane pre-fills, and " +
      "what a reset keeps");

  check("THE COUNTS ARE NOT THE LIST", function () {
    const s = session();
    let i;
    for (i = 0; i < caep.EVENTS_KEPT + 15; i += 1) {
      caep.record(s, P + 'session-presented', { jti: 'j' + i });
    }
    assert.strictEqual(s.counts[P + 'session-presented'],
        caep.EVENTS_KEPT + 15, 'every one was counted.');
    assert.strictEqual(s.events.length, caep.EVENTS_KEPT,
        'and the ring kept the last ' + caep.EVENTS_KEPT + '. A pane that ' +
        'answered "how many" out of this list would say ' + caep.EVENTS_KEPT +
        ' where there were ' + (caep.EVENTS_KEPT + 15) + ', which is why ' +
        'the two are separate rather than derived.');
  });

  check("describe() reports EVERY event type including the zeroes",
      function () {
    const view = caep.describe(session());
    assert.strictEqual(view.counts.length, 8,
        '"nothing of this type has been sent" is the answer to "why did ' +
        'nothing arrive" nine times out of ten, and a table that dropped ' +
        'the zeroes would hide exactly that.');
    view.counts.forEach(function (row) {
      assert.strictEqual(row.count, 0);
    });
  });

  check("and it reports what has NOT been said as such, rather than as fine",
      function () {
    const view = caep.describe(session());
    assert.strictEqual(view.compliance, '',
        'a pane showing "compliant" for a device nothing has ever reported ' +
        'on would be inventing the one fact a reader came to look up.');
    assert.strictEqual(view.risk, '');
    assert.strictEqual(view.assurance, '');
  });

  check("THE SUGGESTIONS COME FROM THE SESSION AND NOT FROM CONSTANTS",
      function () {
    const s = session();
    caep.apply(s, P + 'device-compliance-change',
        { previous_status: 'compliant', current_status: 'not-compliant' });
    const next = caep.suggest(s, P + 'device-compliance-change');
    assert.strictEqual(next.previous_status, 'not-compliant',
        'the previous status offered is the one the session is ACTUALLY in. ' +
        'A pane that pre-filled a constant would produce events that ' +
        'contradict the state it is drawing two inches away.');
    assert.strictEqual(next.current_status, 'compliant',
        'and the change offered is the one that would move it.');
  });

  check("the risk suggestion follows the session too", function () {
    const s = session();
    caep.apply(s, P + 'risk-level-change',
        { principal: 'SESSION', current_level: 'HIGH' });
    const next = caep.suggest(s, P + 'risk-level-change');
    assert.strictEqual(next.previous_level, 'HIGH');
    assert.strictEqual(next.current_level, 'MEDIUM');
  });

  check("buildPayload() adds the four common claims and can omit the " +
      "timestamp on purpose", function () {
    const s = session();
    const withStamp = caep.buildPayload(s, P + 'session-revoked', null,
        { initiatingEntity: 'admin', reasonAdmin: 'why' });
    assert.strictEqual(typeof withStamp.event_timestamp, 'number');
    assert.strictEqual(withStamp.initiating_entity, 'admin');
    assert.strictEqual(withStamp.reason_admin.en, 'why');

    const without = caep.buildPayload(s, P + 'session-revoked', null,
        { eventTimestamp: false });
    assert.strictEqual(
        Object.prototype.hasOwnProperty.call(without, 'event_timestamp'),
        false);
    assert.ok(events.validateEvent(P + 'session-revoked', without).ok,
        'AND IT IS STILL VALID. CAEP section 2 makes the member optional, ' +
        'so this is a perfectly conforming event — and it is what every ' +
        'receiver that assumes a timestamp breaks on, which is the only ' +
        'reason the page can send one.');
  });

  check("the language tag is configurable, because a receiver indexes on it",
      function () {
    const payload = caep.buildPayload(session(), P + 'session-revoked', null,
        { language: 'fr', reasonUser: 'Vous avez été déconnecté.' });
    assert.strictEqual(typeof payload.reason_user.fr, 'string');
    assert.strictEqual(payload.reason_user.en, undefined);
  });

  check("RESET KEEPS THE IDENTITY AND THROWS AWAY WHAT WAS SAID",
      function () {
    const s = session();
    caep.apply(s, P + 'session-revoked', {});
    caep.record(s, P + 'session-revoked', { jti: 'j1' });
    caep.apply(s, P + 'device-compliance-change',
        { previous_status: 'compliant', current_status: 'not-compliant' });
    caep.reset(s);
    assert.strictEqual(s.state, 'established');
    assert.strictEqual(s.total, 0);
    assert.strictEqual(s.events.length, 0);
    assert.strictEqual(s.compliance, '');
    assert.strictEqual(s.sid, 'sid-1',
        'THE IDENTIFIERS SURVIVE. A reset that regenerated them would ' +
        'silently move the subject under a stream that had already been ' +
        'told about the old one — which is the failure the button exists to ' +
        'avoid rather than cause.');
    assert.strictEqual(s.sub, 'u-alice');
  });

  check("every payload the model builds validates against the catalogue",
      function () {
    const s = session();
    events.CAEP_EVENTS.forEach(function (row) {
      const payload = caep.buildPayload(s, row.uri, null,
          { initiatingEntity: 'policy', reasonAdmin: 'a reason',
            reasonUser: 'a reason' });
      const verdict = events.validateEvent(row.uri, payload);
      assert.ok(verdict.ok, row.uri + ': ' + verdict.errors.join(' '));
      assert.strictEqual(verdict.warnings.length, 0,
          row.uri + ' warned: ' + verdict.warnings.join(' '));
    });
  });

  check("and the SET envelope takes a CAEP event with its complex subject",
      function () {
    const s = session();
    const uri = P + 'session-revoked';
    const claims = ssf.buildSetClaims({
      issuer: 'https://sts.example.com',
      audience: 'https://receiver.example.com',
      uri: uri,
      payload: caep.buildPayload(s, uri, null, { initiatingEntity: 'admin' }),
      subject: caep.complexSubject(s, {})
    });
    assert.ok(claims.sub_id, 'the subject rides in sub_id and not in sub.');
    assert.strictEqual(claims.sub, undefined,
        'RFC 8417 section 2.2 discourages `sub`, and a client that reads it ' +
        'silently reads nothing from a conforming transmitter.');
    assert.strictEqual(claims.exp, undefined,
        'a SET MUST NOT be considered to expire (section 4.1.4): it records ' +
        'that something HAPPENED, and a fact does not stop being true.');
    assert.ok(claims.events[uri],
        'the events map is keyed by the event type URI.');
  });

  log.debug("Leaving countersAndSuggestions().");
}


// ---------------------------------------------------------------------------
// EVERY SIGN-IN PROTOCOL SEEDS A SESSION, AND THREE OF THE FIVE MUST ADMIT
// THEY CANNOT NAME ONE.
//
// **CAEP IS NOT AN OAuth2 / OIDC FEATURE.** The profile is a vocabulary about
// SESSIONS, nothing in `session-revoked` names a token endpoint, and it exists
// precisely because SAML and OpenID Connect both authenticate at one instant
// and leave a session good for hours afterwards. This pane read an ID Token
// and nothing else until 2026-09-03, which made the whole workflow look like
// something it never was — and the mock proves the point from the other end,
// emitting for every browser sign-in it has through one funnel.
//
// **WHAT THIS SECTION IS REALLY ASSERTING IS THAT AN INVENTED SESSION
// IDENTIFIER IS REPORTED AS ONE.** That is the whole risk in seeding from five
// protocols instead of one, and it has no symptom anywhere else: an event
// naming a session identifier this workflow made up is well-formed, it
// validates against the catalogue two sections above, a conforming receiver
// accepts it — and it revokes a session nobody has. Nothing downstream can
// tell the two apart, so it has to be right here.
//
// It is also the section that would have caught the defect this feature
// actually shipped with for one revision: `deliver()` computed the fact under
// one member name and the seeder read another, so a REAL WS-Federation
// SessionIndex came back marked as invented. Nothing failed; the note was
// simply wrong, in the one direction that matters.
// ---------------------------------------------------------------------------
function everySignInProtocolSeedsASession() {
  log.info("=== Seeding from all five browser sign-in protocols ===");

  // The two ends of the same table. A protocol the pane offers and the seeder
  // cannot label is a selector entry that produces an unexplained session.
  const offered = sessionHandoff.protocols();
  check('the pane offers five sign-in protocols, which is every browser SSO ' +
      'profile the mock reaches through authn.startSession()', function () {
        assert.deepStrictEqual(offered.map(function (one) {
          return one.id;
        }), ['oidc', 'saml2', 'saml11', 'wsfed', 'spnego']);
      });
  offered.forEach(function (one) {
    check('"' + one.id + '" has a label and says where its session ' +
        'identifier comes from — the sentence the pane draws under the ' +
        'selector, and the only warning a reader gets', function () {
          assert.ok(one.label && one.label.length > 2, 'no label');
          assert.ok(one.where && one.where.length > 10, 'no provenance');
        });
  });

  // A session identifier that came off the wire is KEPT and reported as real.
  [['oidc', 'oidc-sid-1'], ['saml2', '_session-index-99'],
   ['wsfed', '_session-index-77']].forEach(function (pair) {
    const seeded = caep.seedFromSession({
      protocol: pair[0], iss: 'https://idp.example.com', sub: 'alice',
      sid: pair[1], sidFromTheWire: true, acr: 'urn:example:pwd', amr: ['pwd']
    }, null);
    check(pair[0] + ' keeps a session identifier the protocol really ' +
        'carried, so an event built on it names a session the far end holds',
      function () {
        assert.strictEqual(seeded.session.sid, pair[1]);
        assert.strictEqual(seeded.problems.length, 0,
          'a real session identifier must produce no warning, and produced: ' +
          seeded.problems.join(' '));
      });
  });

  // THE OTHER HALF, and the one that matters. SAML 1.1 and SPNEGO cannot
  // carry one at all; WS-Federation could not this time.
  ['saml11', 'wsfed', 'spnego'].forEach(function (protocol) {
    const seeded = caep.seedFromSession({
      protocol: protocol, iss: 'https://idp.example.com', sub: 'alice',
      sid: '', sidFromTheWire: false, acr: 'urn:example:pwd'
    }, null);
    check(protocol + ' with no session identifier on the wire generates a ' +
        'MARKED one and says so — an event naming it is well-formed, ' +
        'validates, and is about nothing at the far end', function () {
          assert.ok(/^debugger-sid-/.test(seeded.session.sid),
            'the invented identifier must say so IN THE VALUE, because a ' +
            'random hex string is indistinguishable from a transmitter\'s ' +
            'and somebody will paste it into a real system. Got: ' +
            seeded.session.sid);
          assert.ok(seeded.problems.length >= 1,
            'and it must be reported, or the pane shows an invented ' +
            'identifier with no warning at all');
        });
    check(protocol + '\'s warning names ITS OWN protocol rather than a ' +
        'missing `sid` claim, which would name a document it never carried',
      function () {
        const said = seeded.problems.join(' ');
        assert.ok(said.indexOf('sid') === -1 || said.indexOf('claim') === -1,
          'a SAML or Kerberos sign-in reported as a missing ID Token claim ' +
          'sends a reader looking for an OP that was never involved: ' + said);
      });
  });

  // THE ROUND TRIP, which is where the shipped defect lived: what `deliver()`
  // WRITES has to be what `seedFromSession()` READS. Asserting each half on
  // its own passed while the two disagreed.
  const bag = {};
  const realWindow = global.window;
  global.window = { sessionStorage: {
    getItem: function (k) {
      return (k in bag) ? bag[k] : null;
    },
    setItem: function (k, v) {
      bag[k] = String(v);
    },
    removeItem: function (k) {
      delete bag[k];
    }
  } };
  try {
    sessionHandoff.start({ returnUrl: '/ssf.html', label: 'the suite',
      protocol: 'wsfed' });
    sessionHandoff.deliver({ protocol: 'wsfed', iss: 'https://idp', sub: 'a',
      sid: '_idx77', sidFromTheWire: true }, 'the suite');
    const taken = sessionHandoff.take();
    const seeded = caep.seedFromSession(taken.session, null);
    check('a session survives the hand-off WITH the fact that its identifier ' +
        'was real — the two ends name that fact identically, and when they ' +
        'did not, a genuine WS-Federation SessionIndex was reported as ' +
        'invented with nothing failing', function () {
          assert.strictEqual(seeded.session.sid, '_idx77');
          assert.strictEqual(seeded.problems.length, 0,
            'the round trip lost it: ' + seeded.problems.join(' '));
        });
    check('and the slot is empty afterwards, because a session collected ' +
        'twice is two workflows believing they own one', function () {
          assert.strictEqual(sessionHandoff.isDelivered(), false);
        });
  } finally {
    global.window = realWindow;
  }
}

async function test() {
  log.debug("Entering test().");
  theEightUris();
  requiredMembersAndClosedEnums();
  theFourCommonClaims();
  theOpenEnumerations();
  theComplexSubject();
  theStateMachine();
  countersAndSuggestions();
  everySignInProtocolSeedsASession();

  // A FLOOR ON THE COUNT, for the reason ssf_engine.js gives: a section that
  // stops being called is a suite that quietly stops testing something, and
  // nothing else would report it.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 70,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'seventy. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("caep_engine")
  .description("Drive the CAEP vocabulary and the session model in node with " +
      "no transmitter and no browser: the eight event types written out from " +
      "the specification, every required member and closed enumeration, the " +
      "four claims CAEP gives them all — reason_admin as a LANGUAGE MAP " +
      "rather than a string, which is the mistake with no symptom — the " +
      "three open enumerations that warn rather than refuse, the complex " +
      "subject through the pipe's own RFC 9493 grammar, the state machine " +
      "and the one sentence it refuses to carry, and the counters against " +
      "the ring.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
