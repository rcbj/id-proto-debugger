// File: risc_engine.js
//
// ---------------------------------------------------------------------------
// THE RISC VOCABULARY AND THE ACCOUNT MODEL, DRIVEN IN NODE WITH NO
// TRANSMITTER AND NO BROWSER.
//
// `client/src/ssf_events.js` is the VOCABULARY — RISC's fourteen event types
// are rows in its table, which is what that file's header promised while it
// had two. `client/src/risc_account.js` is what those rows are ABOUT: an
// ACCOUNT, the three states RISC believes it is in, and what has been said
// concerning it. Neither has a DOM, and that is what this file exists to take
// advantage of.
//
// **WHY THIS IS SEPARATE FROM `risc_protocol.js` AND `risc_page.js`.** Those
// two need the mock STS and a browser, so a failure in either can be three
// things: this client is wrong, that transmitter is wrong, or the two are fine
// and something between them is not. Here there is nothing in between.
//
// ---------------------------------------------------------------------------
// THE DEFECTS THIS PROFILE PRODUCES ARE NEVER CRASHES, AND THEY ARE NOT THE
// SAME ONES CAEP PRODUCES:
//
//   * `new_value` for `new-value`. It is the only hyphenated member name in
//     any of the three vocabularies, so the underscore is what a hand types —
//     and the event validates, delivers, and tells the receiver nothing about
//     what the identifier became.
//   * an `identifier-changed` whose subject names the NEW address. The subject
//     of that event carries the OLD one, which is the reverse of every other
//     event anywhere in Shared Signals, so the mistake produces an event
//     saying that an address the receiver has never heard of has become the
//     one it already holds.
//   * `sessions-revoked` where `session-revoked` was meant. One letter, and
//     the difference between every session this person has and the one the
//     subject names.
//   * an event sent about an account that has OPTED OUT, which RISC section
//     2.8 says is not participating in event exchange.
//   * `opt-out-effective` SUPPRESSED by an over-eager opt-out gate, so a
//     receiver waits for signals that stopped without notice — which at the
//     far end is indistinguishable from a transmitter that has gone down.
//   * the four claims CAEP gives all eight of its events attached to all
//     fourteen of these, of which RISC defines three and gives them to one.
//
// Every one of those produces a workflow that works perfectly against itself.
//
// EIGHT SECTIONS:
//
//   1. the fourteen URIs, spelled out — a typo in the shared prefix would
//      otherwise pass, because every row is built from it
//   2. what is REQUIRED, which is almost nothing, and why that matters
//   3. the three common claims, on ONE event, and the absent fourth
//   4. the hyphenated member and the near miss that names it
//   5. the subject: plain, per-format, and the two rows that override it
//   6. the three state machines and the one hard refusal
//   7. the opt-out gate and the exception that makes it work
//   8. the counters, the ring, the seeding and the reset
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "risc_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const risc = paths.requireSharedModule(
  [__dirname + "/../client/src/risc_account.js",
   __dirname + "/risc_account.js"], "risc_account.js");
const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");

const P = "https://schemas.openid.net/secevent/risc/event-type/";
const C = "https://schemas.openid.net/secevent/caep/event-type/";

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

function account() {
  return risc.newAccount({ iss: 'https://sts.example.com', sub: 'u-alice',
    email: 'alice@example.com', emailVerified: true,
    phone: '+12065550100' });
}

// ---------------------------------------------------------------------------
// 1. THE FOURTEEN URIs, SPELLED OUT.
//
// Written as string literals rather than built from `RISC_PREFIX`, which is
// the whole point of the section: every row in the catalogue is built from
// that constant, so a typo in it would produce fourteen consistently wrong
// URIs that agree with each other perfectly and with nobody else. There is no
// "unknown event type" error in this protocol.
//
// **THE FOUR OPT-OUT SPELLINGS ARE THE ONES TO CHECK BY EYE.** Three of them
// begin `opt-out-` and one does not, and `opt-out-cancelled` carries the
// British double L the specification uses — a transmitter writing
// "opt-out-canceled" produces a URI a conforming receiver silently ignores.
// ---------------------------------------------------------------------------
function theFourteenUris() {
  log.debug("Entering theFourteenUris().");
  const expected = [
    'https://schemas.openid.net/secevent/risc/event-type/' +
      'account-credential-change-required',
    'https://schemas.openid.net/secevent/risc/event-type/account-purged',
    'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
    'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
    'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
    'https://schemas.openid.net/secevent/risc/event-type/identifier-recycled',
    'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
    'https://schemas.openid.net/secevent/risc/event-type/opt-in',
    'https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated',
    'https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled',
    'https://schemas.openid.net/secevent/risc/event-type/opt-out-effective',
    'https://schemas.openid.net/secevent/risc/event-type/recovery-activated',
    'https://schemas.openid.net/secevent/risc/event-type/' +
      'recovery-information-changed',
    'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked'
  ];
  check('the catalogue holds exactly fourteen RISC rows', function () {
    assert.strictEqual(events.RISC_EVENTS.length, 14,
        'RISC 1.0 defines fourteen event types.');
  });
  expected.forEach(function (uri) {
    check('the catalogue knows ' + uri.split('/').pop(), function () {
      assert.ok(events.EVENT_BY_URI[uri],
          uri + ' is not in the catalogue. There is no "unknown event type" ' +
          'error in this protocol, so a receiver would silently ignore an ' +
          'event this workflow sent under a misspelt URI.');
      assert.strictEqual(events.EVENT_BY_URI[uri].family, 'risc',
          uri + ' is not filed under the risc family.');
    });
  });
  check('every RISC row requires a subject', function () {
    events.RISC_EVENTS.forEach(function (row) {
      assert.strictEqual(row.subject, 'required',
          row.uri + ' does not require a subject. Every RISC event is about ' +
          'an account, and for eleven of the fourteen the subject is the ' +
          'ENTIRE message — so one that carries none says something ' +
          'happened and does not say to whom.');
    });
  });
  check('the RISC profile and family are both implemented', function () {
    assert.strictEqual(events.profileOf('risc').implemented, true,
        'the RISC profile still says it is not implemented.');
    const family = events.FAMILIES.filter(function (row) {
      return row.id === 'risc';
    })[0];
    assert.strictEqual(family.implemented, true,
        'the RISC family still says it is not implemented.');
  });
  check('familyOf() places a RISC URI', function () {
    assert.strictEqual(events.familyOf(P + 'account-purged'), 'risc');
  });
  log.debug("Leaving theFourteenUris().");
}

// ---------------------------------------------------------------------------
// 2. WHAT IS REQUIRED, WHICH IS ALMOST NOTHING.
//
// This is the section that separates RISC from CAEP more than any other. A
// CAEP row is mostly members; a RISC row is mostly `{}`. Eleven of the
// fourteen define no payload members at all and exactly one has a required
// member, which is what makes the SUBJECT the whole message — and a subject
// naming the wrong person a wholly wrong event with nothing else in it to
// notice by.
// ---------------------------------------------------------------------------
function whatIsRequired() {
  log.debug("Entering whatIsRequired().");
  const empty = events.RISC_EVENTS.filter(function (row) {
    return row.members.length === 0;
  });
  check('eleven of the fourteen have NO payload members at all', function () {
    assert.strictEqual(empty.length, 11,
        'Expected eleven memberless RISC event types and found ' +
        empty.length + '. If that number moved, the sentence "the subject ' +
        'is the entire message" moved with it.');
  });
  const required = events.RISC_EVENTS.filter(function (row) {
    return row.members.some(function (member) {
      return member.required;
    });
  });
  check('exactly one has a required member', function () {
    assert.strictEqual(required.length, 1,
        'Expected one RISC event type with a required member.');
    assert.strictEqual(required[0].uri, P + 'credential-compromise');
  });
  check('and it is credential_type', function () {
    const verdict = events.validateEvent(P + 'credential-compromise', {});
    refuses(verdict, 'credential_type',
        'credential-compromise with no credential_type');
  });
  check('credential_type shares CAEP\'s list BY IDENTITY', function () {
    const riscMember = events.EVENT_BY_URI[P + 'credential-compromise']
      .members.filter(function (m) { return m.name === 'credential_type'; })[0];
    const caepMember = events.EVENT_BY_URI[C + 'credential-change']
      .members.filter(function (m) { return m.name === 'credential_type'; })[0];
    assert.strictEqual(riscMember.values, caepMember.values,
        'The two lists are not the same array. RISC section 2.7 defines its ' +
        'credential_type BY REFERENCE to CAEP\'s credential-change, so they ' +
        'are one list rather than two alike ones — and two copies is a copy ' +
        'that can drift out of a relationship the specification states.');
    assert.strictEqual(riscMember.values, events.CREDENTIAL_TYPES);
  });
  check('an unlisted credential type WARNS rather than refusing', function () {
    warns(events.validateEvent(P + 'credential-compromise',
      { credential_type: 'acme-token' }), 'acme-token',
      'a vendor credential type on credential-compromise');
  });
  check('every memberless type accepts an empty payload', function () {
    empty.forEach(function (row) {
      const verdict = events.validateEvent(row.uri, {});
      assert.ok(verdict.ok, row.uri + ' refused {}: ' +
          verdict.errors.join(' ') + '. An event with nothing to say still ' +
          'carries an empty object — the event TYPE is the key in the ' +
          'events map and the payload is its value.');
    });
  });
  check('account-disabled\'s reason is an OPEN list', function () {
    assert.ok(events.validateEvent(P + 'account-disabled',
      { reason: 'hijacking' }).ok);
    warns(events.validateEvent(P + 'account-disabled',
      { reason: 'court-order' }), 'court-order',
      'a third reason on account-disabled');
  });
  log.debug("Leaving whatIsRequired().");
}

// ---------------------------------------------------------------------------
// 3. THE THREE COMMON CLAIMS, ON ONE EVENT, AND THE ABSENT FOURTH.
//
// CAEP section 2 gives four claims to every one of its eight event types. RISC
// gives THREE — there is no `initiating_entity` — and gives them to exactly
// ONE of its fourteen. Reusing CAEP's builder here would attach four members
// to fourteen rows and produce thirteen events carrying members their
// specification does not define, and nothing would fail: an unrecognised
// member is carried and ignored by a conforming receiver.
// ---------------------------------------------------------------------------
function theThreeCommonClaims() {
  log.debug("Entering theThreeCommonClaims().");
  check('RISC defines three common members, not four', function () {
    assert.strictEqual(events.RISC_COMMON_MEMBERS.length, 3);
  });
  check('and initiating_entity is not one of them', function () {
    const names = events.RISC_COMMON_MEMBERS.map(function (m) {
      return m.name;
    });
    assert.ok(names.indexOf('initiating_entity') < 0,
        'RISC gives no initiating_entity to any of its fourteen events. ' +
        'CAEP gives one to all eight of its own, which is exactly why this ' +
        'is asserted rather than assumed.');
    assert.deepStrictEqual(names.slice().sort(),
      ['event_timestamp', 'reason_admin', 'reason_user']);
  });
  check('only credential-compromise carries them', function () {
    events.RISC_EVENTS.forEach(function (row) {
      const has = row.members.some(function (member) {
        return member.name === 'reason_admin';
      });
      assert.strictEqual(has, row.uri === P + 'credential-compromise',
          row.uri + (has ? ' carries reason_admin and should not.'
            : ' does not carry reason_admin and should.'));
    });
  });
  check('buildPayload adds them ONLY where the row defines them', function () {
    const one = account();
    const withThem = risc.buildPayload(one, P + 'credential-compromise', null,
      { reasonAdmin: 'seen in a breach corpus', reasonUser: 'change it' });
    assert.strictEqual(typeof withThem.event_timestamp, 'number');
    assert.deepStrictEqual(withThem.reason_admin,
      { en: 'seen in a breach corpus' });
    const without = risc.buildPayload(one, P + 'account-purged', null,
      { reasonAdmin: 'gone', reasonUser: 'gone' });
    assert.deepStrictEqual(without, {},
        'account-purged came out carrying members RISC does not define for ' +
        'it. Nothing would fail at the far end — an unrecognised member is ' +
        'carried and ignored — which is exactly why it is checked here.');
  });
  check('reason_admin is a LANGUAGE MAP and a string is refused', function () {
    refuses(events.validateEvent(P + 'credential-compromise',
      { credential_type: 'password', reason_admin: 'a string' }),
      'LANGUAGE TAG', 'reason_admin as a bare string');
  });
  check('event_timestamp is a NUMBER and a string is refused', function () {
    refuses(events.validateEvent(P + 'credential-compromise',
      { credential_type: 'password', event_timestamp: '1757000000' }),
      'NUMBER', 'event_timestamp as a quoted number');
  });
  check('omitting event_timestamp is legal and noticed', function () {
    const one = account();
    assert.ok(events.validateEvent(P + 'credential-compromise',
      { credential_type: 'password' }).ok,
      'A credential-compromise with no event_timestamp is conforming: the ' +
      'member is optional.');
    const applied = risc.apply(one, P + 'credential-compromise',
      { credential_type: 'password' });
    assert.ok(applied.warnings.join(' ').indexOf('DISCOVERED') >= 0,
        'the model said nothing about the missing timestamp. RISC words it ' +
        'as when the compromise was DISCOVERED rather than when it ' +
        'happened, and a credential found in a breach corpus was ' +
        'compromised long before anybody noticed.');
  });
  log.debug("Leaving theThreeCommonClaims().");
}

// ---------------------------------------------------------------------------
// 4. THE HYPHENATED MEMBER, AND THE NEAR MISS THAT NAMES IT.
//
// `new-value` is the only hyphenated member name in any of the three
// vocabularies. Everything else in SSF, CAEP and RISC is snake_case, which is
// what makes `new_value` the mistake somebody makes once and never sees: the
// event validates, delivers, and says nothing.
// ---------------------------------------------------------------------------
function theHyphenatedMember() {
  log.debug("Entering theHyphenatedMember().");
  check('exactly one member name in all three vocabularies is hyphenated',
    function () {
      const found = [];
      events.EVENTS.forEach(function (row) {
        row.members.forEach(function (member) {
          if (member.name.indexOf('-') >= 0) {
            found.push(row.uri.split('/').pop() + '.' + member.name);
          }
        });
      });
      assert.deepStrictEqual(found, ['identifier-changed.new-value'],
          'The set of hyphenated member names moved. It is one, and the ' +
          'whole reason `new_value` is a trap is that it is the only one.');
    });
  check('the underscore spelling is CARRIED and NAMED', function () {
    const verdict = events.validateEvent(P + 'identifier-changed',
      { new_value: 'alice.roe@example.com' });
    warns(verdict, '"new-value"',
      'new_value on identifier-changed');
    assert.ok(verdict.warnings.join(' ').indexOf('hyphen') >= 0,
        'the warning does not say what is different about the two ' +
        'spellings. "Unknown member" alone would read as an extension ' +
        'somebody meant.');
  });
  check('and the generator does NOT silently correct it', function () {
    const built = events.generateEvent(P + 'identifier-changed',
      { new_value: 'alice.roe@example.com' });
    assert.deepStrictEqual(built, {},
        'the generator repaired `new_value` into `new-value`. This ' +
        'workflow exists so that somebody can see what is actually going on ' +
        'the wire, and silently fixing the commonest mistake in this event ' +
        'type would hide it.');
  });
  check('the correct spelling is built', function () {
    assert.deepStrictEqual(
      events.generateEvent(P + 'identifier-changed',
        { 'new-value': 'alice.roe@example.com' }),
      { 'new-value': 'alice.roe@example.com' });
  });
  check('an identifier-changed with no new-value is legal and noticed',
    function () {
      const one = account();
      assert.ok(events.validateEvent(P + 'identifier-changed', {}).ok);
      const applied = risc.apply(one, P + 'identifier-changed', {});
      assert.ok(applied.warnings.join(' ').indexOf('nearly useless') >= 0,
          'the model said nothing about an identifier-changed that does not ' +
          'say what the identifier became.');
    });
  log.debug("Leaving theHyphenatedMember().");
}

// ---------------------------------------------------------------------------
// 5. THE SUBJECT: PLAIN, PER-FORMAT, AND THE TWO ROWS THAT OVERRIDE IT.
//
// **THIS IS THE LINE OF JSON THAT SEPARATES THE TWO PROFILES.** A CAEP event
// carries a complex subject because it is about one session of one person; a
// RISC event is about the account, so the person IS the subject.
// ---------------------------------------------------------------------------
function theSubject() {
  log.debug("Entering theSubject().");
  const one = account();
  check('an ordinary RISC subject is PLAIN and issuer_subject_id by default',
    function () {
      const subject = risc.subjectFor(one, P + 'account-disabled');
      assert.strictEqual(subject.format, 'issuer_subject_id');
      assert.strictEqual(subject.sub, 'u-alice');
      const verdict = ssf.validateSubjectId(subject, { path: 'sub_id' });
      assert.ok(verdict.ok, 'the subject failed the pipe\'s own RFC 9493 ' +
          'grammar: ' + verdict.errors.join(' '));
    });
  check('every format the pane offers produces a valid subject', function () {
    ['issuer_subject_id', 'email', 'phone_number', 'opaque', 'account']
      .forEach(function (format) {
        const subject = risc.subjectFor(one, P + 'account-disabled',
          { format: format });
        assert.strictEqual(subject.format, format);
        const verdict = ssf.validateSubjectId(subject, { path: 'sub_id' });
        assert.ok(verdict.ok, format + ' produced an invalid subject: ' +
            verdict.errors.join(' '));
      });
  });
  check('THE TWO IDENTIFIER EVENTS OVERRIDE THE CHOSEN FORMAT', function () {
    [P + 'identifier-changed', P + 'identifier-recycled'].forEach(
      function (uri) {
        const subject = risc.subjectFor(one, uri,
          { format: 'issuer_subject_id' });
        assert.strictEqual(subject.format, 'email',
            uri + ' honoured issuer_subject_id. Its subject MUST be an ' +
            'address or a number, and it carries the OLD value — so an ' +
            'iss_sub subject there contains none of the message.');
        assert.strictEqual(subject.email, 'alice@example.com');
      });
  });
  check('and a wrong-format subject WARNS rather than being refused',
    function () {
      const warningsOut = events.checkSubjectFormat(P + 'identifier-changed',
        { format: 'issuer_subject_id', iss: 'https://x', sub: 'y' });
      assert.strictEqual(warningsOut.length, 1,
          'nothing was said about an iss_sub subject on identifier-changed.');
      assert.ok(warningsOut[0].indexOf('BUILT anyway') >= 0,
          'the warning does not say the event is still built. Refusing ' +
          'would remove the ability to find out what a receiver does with ' +
          'one, which is the whole point of the page.');
    });
  check('an ordinary event has no format rule at all', function () {
    assert.deepStrictEqual(
      events.checkSubjectFormat(P + 'account-purged',
        { format: 'issuer_subject_id', iss: 'https://x', sub: 'y' }), []);
  });
  check('a COMPLEX subject on an identifier event is called out',
    function () {
      const warningsOut = events.checkSubjectFormat(P + 'identifier-recycled',
        { user: { format: 'email', email: 'a@b.com' } });
      assert.ok(warningsOut.length === 1 &&
          warningsOut[0].indexOf('COMPLEX') >= 0,
          'a complex subject on an identifier event was not reported. It ' +
          'names a person and possibly a session, and this event is about ' +
          'an IDENTIFIER rather than about either.');
    });
  check('checkSubject() reports both the grammar AND the format rule',
    function () {
      const verdict = risc.checkSubject(
        { format: 'issuer_subject_id', iss: 'https://x', sub: 'y' },
        P + 'identifier-changed', []);
      assert.ok(verdict.ok, 'the subject is valid RFC 9493 and was refused.');
      assert.ok((verdict.warnings || []).join(' ').indexOf('MUST be') >= 0,
          'the per-row format rule did not reach the pane\'s findings.');
    });
  log.debug("Leaving theSubject().");
}

// ---------------------------------------------------------------------------
// 6. THE THREE STATE MACHINES AND THE ONE HARD REFUSAL.
//
// A CAEP session has ONE state because a session is alive or it is not. An
// account has a lifecycle, an opt-out state and a credential standing, and
// they move independently: an account can be opted out and perfectly healthy,
// or compromised and still enabled.
// ---------------------------------------------------------------------------
function theStateMachines() {
  log.debug("Entering theStateMachines().");
  check('a new account is active, opted in and unremarked on', function () {
    const one = account();
    assert.strictEqual(one.lifecycle, 'active');
    assert.strictEqual(one.optOut, 'opt-in');
    assert.strictEqual(one.credentialStanding, '',
        'a new account claims a credential standing. "Nothing has been ' +
        'said" and "not compromised" are different facts, and showing the ' +
        'second for the first would invent the one thing a reader came to ' +
        'look up.');
  });
  check('disable then enable moves the lifecycle both ways', function () {
    const one = account();
    risc.apply(one, P + 'account-disabled', { reason: 'hijacking' });
    assert.strictEqual(one.lifecycle, 'disabled');
    risc.apply(one, P + 'account-enabled', {});
    assert.strictEqual(one.lifecycle, 'active');
  });
  check('enabling an account nothing disabled is a WARNING', function () {
    const one = account();
    const applied = risc.apply(one, P + 'account-enabled', {});
    assert.ok(applied.ok);
    assert.ok(applied.warnings.join(' ').indexOf('nothing to enable') >= 0);
  });
  check('bulk-account is called out as a signal about the PROVIDER',
    function () {
      const one = account();
      const applied = risc.apply(one, P + 'account-disabled',
        { reason: 'bulk-account' });
      assert.ok(applied.warnings.join(' ').indexOf('PROVIDER') >= 0,
          'nothing said what bulk-account means. It asks a receiver to look ' +
          'at everything else that arrived at the same time, where ' +
          '"hijacking" is about one person.');
    });
  check('THE ONE HARD REFUSAL: account-enabled on a purged account',
    function () {
      const one = account();
      risc.apply(one, P + 'account-purged', {});
      assert.strictEqual(one.lifecycle, 'purged');
      assert.strictEqual(risc.refusals(one, P + 'account-enabled').length, 1,
          'enabling a PERMANENTLY DELETED account was allowed. That ' +
          'sentence is either a transmitter contradicting itself or a ' +
          'receiver about to be told to restore access to something that ' +
          'does not exist.');
      const applied = risc.apply(one, P + 'account-enabled', {});
      assert.ok(!applied.ok, 'apply() carried the refused event.');
      assert.strictEqual(one.lifecycle, 'purged',
          'the refused event moved the model anyway.');
    });
  check('and nothing ELSE about a purged account is refused', function () {
    const one = account();
    risc.apply(one, P + 'account-purged', {});
    assert.strictEqual(
      risc.refusals(one, P + 'credential-compromise').length, 0,
      'a compromise discovered after a deletion was refused. That is the ' +
      'ordinary case, and refusing it would remove the ability to ' +
      'reproduce it.');
    const applied = risc.apply(one, P + 'credential-compromise',
      { credential_type: 'password', event_timestamp: 1 });
    assert.ok(applied.ok);
    assert.ok(applied.warnings.join(' ').indexOf('PURGED') >= 0);
  });
  check('the pre-flight refusal and the applied one are ONE rule',
    function () {
      const one = account();
      risc.apply(one, P + 'account-purged', {});
      assert.strictEqual(risc.refusals(one, P + 'account-enabled').length,
        risc.apply(one, P + 'account-enabled', {}).errors.length,
        'two spellings of one refusal is two chances to disagree, and the ' +
        'disagreement would be invisible: the page asks the first and the ' +
        'model writes from the second.');
    });
  check('identifier-changed remembers what the address WAS', function () {
    const one = account();
    risc.apply(one, P + 'identifier-changed',
      { 'new-value': 'alice.roe@example.com' });
    assert.strictEqual(one.email, 'alice.roe@example.com');
    assert.deepStrictEqual(one.formerIdentifiers, ['alice@example.com'],
        'the model forgot the old address. An event naming the superseded ' +
        'one is still about this account, and forgetting is what makes one ' +
        'person look like two at exactly the moment their identifier ' +
        'changed.');
    assert.strictEqual(one.emailVerified, false,
        'the new address came off an event this page built, not off a ' +
        'provider, so nothing has said it is verified.');
  });
  check('identifier-recycled warns about the takeover nobody notices',
    function () {
      const one = account();
      const applied = risc.apply(one, P + 'identifier-recycled', {});
      assert.ok(applied.warnings.join(' ').indexOf('SOMEBODY ELSE') >= 0,
          'the quietest account takeover there is went unremarked: a ' +
          'receiver keyed on an address lets the new owner into the old ' +
          'owner\'s account and nothing anywhere was compromised.');
    });
  check('sessions-revoked warns on the catalogue AND in the model',
    function () {
      warns(events.validateEvent(P + 'sessions-revoked', {}), 'DEPRECATED',
        'the deprecated sessions-revoked');
      const row = events.EVENT_BY_URI[P + 'sessions-revoked'];
      assert.strictEqual(row.deprecated, C + 'session-revoked',
          'the row does not say WHAT replaces it, so a warning cannot name ' +
          'it — and the two names differ by one letter.');
      const applied = risc.apply(account(), P + 'sessions-revoked', {});
      assert.ok(applied.warnings.join(' ').indexOf('PLURAL') >= 0);
    });
  check('a CAEP event on a RISC account changes nothing and is not an error',
    function () {
      const one = account();
      const applied = risc.apply(one, C + 'session-revoked', {});
      assert.ok(applied.ok);
      assert.strictEqual(one.lifecycle, 'active',
          'a CAEP event moved the account model. All three vocabularies ' +
          'travel on the same stream and this one is about a session.');
    });
  log.debug("Leaving theStateMachines().");
}

// ---------------------------------------------------------------------------
// 7. THE OPT-OUT GATE AND THE EXCEPTION THAT MAKES IT WORK.
//
// RISC section 2.8's three states, its four transitions, and the two events
// that must never be gated — without which `opt-out-effective` could not be
// delivered and `opt-in` could not bring an account back.
// ---------------------------------------------------------------------------
function theOptOutGate() {
  log.debug("Entering theOptOutGate().");
  check('the four legal transitions', function () {
    const one = account();
    risc.apply(one, P + 'opt-out-initiated', {});
    assert.strictEqual(one.optOut, 'opt-out-initiated');
    risc.apply(one, P + 'opt-out-cancelled', {});
    assert.strictEqual(one.optOut, 'opt-in');
    risc.apply(one, P + 'opt-out-initiated', {});
    risc.apply(one, P + 'opt-out-effective', {});
    assert.strictEqual(one.optOut, 'opt-out');
    risc.apply(one, P + 'opt-in', {});
    assert.strictEqual(one.optOut, 'opt-in');
  });
  check('a move the diagram has no arrow for is APPLIED and warned about',
    function () {
      const one = account();
      const applied = risc.apply(one, P + 'opt-out-effective', {});
      assert.strictEqual(one.optOut, 'opt-out',
          'the model refused to follow a state the event DECLARED. The ' +
          'receiver will believe it, and a model that did not would be ' +
          'showing something the far end does not think.');
        assert.ok(
        applied.warnings.join(' ').indexOf('no opt-out-effective') >= 0);
      assert.ok(applied.warnings.join(' ').indexOf('hijacker') >= 0,
          'nothing said why the middle state exists: it stops a hijacker ' +
          'opting out the moment they take an account over and silencing ' +
          'the events that would report them.');
    });
  check('an opted-out account has its ordinary events suppressed',
    function () {
      const one = account();
      risc.apply(one, P + 'opt-out-initiated', {});
      assert.strictEqual(risc.gate(one, P + 'account-disabled', true).send,
        true, 'opt-out-initiated must keep exchanging — that delay is the ' +
        'whole reason the middle state exists.');
      risc.apply(one, P + 'opt-out-effective', {});
      const stopped = risc.gate(one, P + 'account-disabled', true);
      assert.strictEqual(stopped.send, false);
      assert.ok(stopped.why.indexOf('2.8') >= 0);
    });
  check('THE FOUR OPT-OUT EVENTS ARE NEVER GATED', function () {
    const one = account();
    risc.apply(one, P + 'opt-out-effective', {});
    Object.keys(risc.OPT_OUT_EVENTS).forEach(function (short) {
      assert.strictEqual(risc.gate(one, P + short, true).send, true,
          short + ' was suppressed. opt-out-effective is an event ' +
          'announcing that there will be no more events, so gating it ' +
          'enters the silent state without telling anybody — ' +
          'indistinguishable at the far end from a transmitter that has ' +
          'gone down — and opt-in is sent FROM that state by definition and ' +
          'is the only way a receiver learns the account came back.');
    });
  });
  check('and the gate can be turned off, which is the non-conforming case',
    function () {
      const one = account();
      risc.apply(one, P + 'opt-out-effective', {});
      assert.strictEqual(risc.gate(one, P + 'account-disabled', false).send,
        true, 'the gate could not be opened. Sending anyway is how a ' +
        'receiver that IGNORES an opt-out gets to be shown doing it.');
    });
  log.debug("Leaving theOptOutGate().");
}

// ---------------------------------------------------------------------------
// 8. THE COUNTERS, THE SEEDING AND THE RESET.
// ---------------------------------------------------------------------------
function countersAndSeeding() {
  log.debug("Entering countersAndSeeding().");
  check('the counters never forget and the ring does', function () {
    const one = account();
    for (var i = 0; i < risc.EVENTS_KEPT + 5; i += 1) {
      risc.record(one, P + 'account-credential-change-required', {});
    }
    assert.strictEqual(one.total, risc.EVENTS_KEPT + 5);
    assert.strictEqual(
      one.counts[P + 'account-credential-change-required'],
      risc.EVENTS_KEPT + 5);
    assert.strictEqual(one.events.length, risc.EVENTS_KEPT,
        'the ring kept everything. "How many have gone out" and "what were ' +
        'the last few" are two different questions.');
  });
  check('a suppressed event is counted APART from the total', function () {
    const one = account();
    risc.record(one, P + 'account-disabled', {});
    risc.recordSuppressed(one, P + 'account-purged');
    assert.strictEqual(one.total, 1);
    assert.strictEqual(one.suppressed, 1,
        'a suppressed event is the one count that says a receiver heard ' +
        'nothing ON PURPOSE, and nothing else can tell that from a stream ' +
        'nobody agreed.');
  });
  check('describe() draws every event type INCLUDING the zeroes',
    function () {
      const view = risc.describe(account());
      assert.strictEqual(view.counts.length, 14,
          'the zeroes are the point: "nothing of this type has been sent" ' +
          'is the answer to "why did nothing arrive" nine times out of ten.');
      const deprecated = view.counts.filter(function (row) {
        return row.deprecated;
      });
      assert.strictEqual(deprecated.length, 1,
          'the view does not carry which type its own specification ' +
          'deprecates.');
    });
  check('seedFrom() takes an address AND whether it was verified',
    function () {
      const seeded = risc.seedFrom({ iss: 'https://x', sub: 'alice',
        email: 'alice@example.com', email_verified: true });
      assert.strictEqual(seeded.account.email, 'alice@example.com');
      assert.strictEqual(seeded.account.emailVerified, true);
      assert.strictEqual(seeded.problems.length, 0,
          'a verified address from an ID Token is the clean case and ' +
          'produced a problem: ' + seeded.problems.join(' '));
    });
  check('an UNVERIFIED address is reported and not blocked', function () {
    const seeded = risc.seedFrom({ iss: 'https://x', sub: 'alice',
      email: 'alice@example.com' });
    assert.strictEqual(seeded.account.emailVerified, false);
    assert.ok(seeded.problems.join(' ').indexOf('AUTHORITATIVE') >= 0,
        'nothing said that RISC lets only the authoritative provider send ' +
        'an identifier event. An identifier-changed built from an ' +
        'unverified claim asserts an authority this workflow does not have, ' +
        'about an address that may belong to somebody else — and it is ' +
        'well-formed and undetectable at the far end.');
  });
  check('no address at all is a DIFFERENT sentence', function () {
    const seeded = risc.seedFrom({ iss: 'https://x', sub: 'alice' });
    assert.ok(seeded.account.email.indexOf('debugger-') === 0,
        'an invented address is not marked as one in the value. A plausible ' +
        'one would eventually be sent at somebody else\'s mailbox.');
    assert.ok(seeded.problems.join(' ').indexOf('GENERATED HERE') >= 0);
    assert.ok(seeded.problems.join(' ').indexOf('other twelve') >= 0,
        'nothing said that the other twelve event types are unaffected. ' +
        'Only two of the fourteen need an address at all.');
  });
  check('a grant with no ID Token seeds without an error', function () {
    const seeded = risc.seedFrom({});
    assert.ok(seeded.account, 'client credentials and resource owner ' +
        'password issue no ID Token, and both are supported grants.');
    assert.ok(seeded.problems.join(' ').indexOf('subject IS the') >= 0,
        'nothing said why a missing subject matters MORE in RISC than in ' +
        'CAEP: eleven of the fourteen carry no payload, so the subject is ' +
        'the whole message.');
  });
  check('every sign-in protocol seeds an account', function () {
    ['oidc', 'saml2', 'saml11', 'wsfed', 'spnego'].forEach(function (id) {
      const seeded = risc.seedFromSession({ protocol: id, sub: 'u-alice',
        iss: 'https://sts.example.com', email: 'alice@example.com' });
      assert.strictEqual(seeded.account.sub, 'u-alice',
          id + ' did not seed a subject. Unlike CAEP — where three of the ' +
          'five carry no session identifier — every one of the five names a ' +
          'PERSON, which is all a RISC subject needs.');
      assert.strictEqual(seeded.account.protocol, id);
    });
  });
  check('reset keeps the identity and throws away what was said',
    function () {
      const one = account();
      risc.apply(one, P + 'account-purged', {});
      risc.record(one, P + 'account-purged', {});
      risc.recordSuppressed(one, P + 'account-disabled');
      risc.reset(one);
      assert.strictEqual(one.lifecycle, 'active');
      assert.strictEqual(one.optOut, 'opt-in');
      assert.strictEqual(one.total, 0);
      assert.strictEqual(one.suppressed, 0);
      assert.strictEqual(one.sub, 'u-alice',
          'the reset threw away who the account is. What is being thrown ' +
          'away is what RISC has SAID about it.');
    });
  check('suggest() derives from the account rather than from constants',
    function () {
      const one = account();
      const values = risc.suggest(one, P + 'identifier-changed');
      assert.ok(values['new-value'].indexOf('alice') >= 0,
          'the suggested new address is unrelated to the account, which ' +
          'makes the most confusing event in the vocabulary harder to read ' +
          'rather than easier: the OLD value is in the subject and the NEW ' +
          'one is here, and a reader should be able to see they are the ' +
          'same person.');
      assert.deepStrictEqual(risc.suggest(one, P + 'account-purged'), {},
          'a memberless event type was given members to send.');
    });
  log.debug("Leaving countersAndSeeding().");
}

async function test() {
  log.debug("Entering test().");
  theFourteenUris();
  whatIsRequired();
  theThreeCommonClaims();
  theHyphenatedMember();
  theSubject();
  theStateMachines();
  theOptOutGate();
  countersAndSeeding();

  // A FLOOR ON THE COUNT, for the reason ssf_engine.js gives: a section that
  // stops being called is a suite that quietly stops testing something, and
  // nothing else would report it.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 55,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'fifty-five. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("risc_engine")
  .description("Drive the RISC vocabulary and the account model in node with " +
      "no transmitter and no browser: the fourteen event types written out " +
      "from the specification, the ONE required member and the eleven types " +
      "with no members at all, the three claims RISC gives to one event and " +
      "the fourth it does not define, the only hyphenated member name in any " +
      "of the three vocabularies and the near miss that names it, the plain " +
      "subject and the two rows that override its format, the three state " +
      "machines and the one sentence they refuse, and RISC section 2.8's " +
      "opt-out gate with the exception without which it is a trap.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
