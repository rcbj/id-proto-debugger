// File: ssf_engine.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS WORKFLOW'S ENGINES, DRIVEN IN NODE WITH NO SERVER AND NO
// BROWSER.
//
// `client/src/ssf_client.js` is the PIPE — the RFC 9493 subject grammar, the
// RFC 8417 SET envelope, stream configurations, and both deliveries.
// `client/src/ssf_events.js` is the VOCABULARY, and it is the one file CAEP
// and RISC will change. `client/src/ssf_history.js` is the two histories.
// `api/ssf_proxy.js` and `api/ssf_receiver.js` decide what the backend call
// path will forward and what the api's push inbox will accept. None of the
// five has a DOM and none of them opens a socket, which is what this file
// exists to take advantage of.
//
// **WHY THIS IS SEPARATE FROM `ssf_protocol.js` AND `ssf_page.js`.** Those two
// need a mock STS and a browser, so a failure in either can be three things:
// this client is wrong, that transmitter is wrong, or the two are fine and
// something in between is not. Here there is nothing in between. A failure in
// this file is a defect in what this workflow composes or accepts, asserted
// against the specifications' own text, and it names the member rather than
// naming a page.
//
// THE DEFECTS THIS PROTOCOL ACTUALLY PRODUCES ARE NEVER CRASHES, which is the
// whole argument for a file like this one:
//
//   * a subject identifier with an extra member — which every conforming
//     receiver MUST reject, and which looks perfectly fine in a log;
//   * an `exp` on a SET, which asks receivers to discard history (RFC 8417
//     section 4.1.4 forbids it);
//   * `events_requested` read back as `events_delivered`, so a receiver waits
//     for types nothing will ever send;
//   * a delivery method spelt `push` rather than `urn:ietf:rfc:8935`;
//   * a SET sent as `application/jwt`, which a receiver dispatching on the
//     media type drops with no error anybody sees;
//   * a `sub` claim where SSF puts `sub_id`, so a client reads nothing.
//
// Every one of those produces a workflow that works perfectly against itself.
//
// NINE SECTIONS:
//
//   1. the eight RFC 9493 formats — every valid combination, and the closed
//      member set, the required members, the value shapes and the nesting ban
//   2. complex subjects, the six members, and critical_subject_members
//   3. subject keys and descriptions
//   4. the two delivery methods and the URN-versus-shorthand trap
//   5. discovery — both well-known shapes, every metadata member, and the
//      endpoint lookup that composes nothing
//   6. stream configurations — build, check, read back, and the
//      requested-versus-delivered surprise
//   7. the SET envelope — build, sign with EVERY algorithm family, parse,
//      and every finding inspectSet() and inspectSetHeader() can produce
//   8. both deliveries, in both directions
//   9. the vocabulary table, the two histories, and the api's two modules
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ssf_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The modules under test. requireSharedModule() is what makes a module
// borrowed from client/src resolve its own dependencies — node resolves those
// relative to where the MODULE lives, and a checkout that installed only the
// tests' dependencies has no client/node_modules. See tests/module_paths.js.
// In a checkout these live under client/src and api/; the tests image copies
// them flat next to the test scripts (see tests/Dockerfile).
const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const history = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_history.js", __dirname + "/ssf_history.js"],
  "ssf_history.js");
const jws = paths.requireSharedModule(
  [__dirname + "/../client/src/jws.js", __dirname + "/jws.js"], "jws.js");
const proxy = paths.requireSharedModule(
  [__dirname + "/../api/ssf_proxy.js", __dirname + "/ssf_proxy.js"],
  "ssf_proxy.js");
const receiver = paths.requireSharedModule(
  [__dirname + "/../api/ssf_receiver.js", __dirname + "/ssf_receiver.js"],
  "ssf_receiver.js");

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

// ---------------------------------------------------------------------------
// 1. THE EIGHT FORMATS OF RFC 9493 SECTION 3.
// ---------------------------------------------------------------------------
function everyFormatIsDefinedAndValidates() {
  log.info("[subjects] All eight RFC 9493 formats, and the example of each.");
  assert.strictEqual(ssf.SUBJECT_FORMATS.length, 8,
      'RFC 9493 section 3 defines eight formats and this table has ' +
      ssf.SUBJECT_FORMATS.length + '.');
  checks++;
  ['account', 'email', 'issuer_subject_id', 'opaque', 'phone_number',
   'decentralized_identifier', 'uri', 'aliases'].forEach(function (name) {
    check('the "' + name + '" format is defined', function () {
      assert.ok(ssf.SUBJECT_FORMAT_NAMES.indexOf(name) >= 0,
          'RFC 9493 defines "' + name + '" and this build does not.');
    });
  });
  ssf.SUBJECT_FORMATS.forEach(function (row) {
    check('the "' + row.format + '" example validates', function () {
      const verdict = ssf.validateSubjectId(row.example, {});
      assert.ok(verdict.ok,
          'The specimen this build offers for "' + row.format + '" does not ' +
          'pass its own validator: ' + verdict.errors.join(' '));
      assert.strictEqual(verdict.format, row.format);
      assert.strictEqual(verdict.complex, false);
    });
    check('the "' + row.format + '" example carries only its own members',
      function () {
        Object.keys(row.example).forEach(function (name) {
          assert.ok(name === 'format' || row.members.indexOf(name) >= 0,
              'The specimen for "' + row.format + '" carries "' + name +
              '", which that format does not define.');
        });
      });
  });
  log.info("[subjects] OK — eight formats, every specimen valid.");
}

function theMemberSetIsClosed() {
  log.info("[subjects] An extra member must be REFUSED and NAMED. This is " +
      "the check nothing else makes: such a subject looks perfectly fine in " +
      "a log and every conforming receiver rejects it.");
  ssf.SUBJECT_FORMATS.forEach(function (row) {
    if (row.format === 'aliases') {
      return;
    }
    const loose = Object.assign({}, row.example, { tenant: 'acme' });
    refuses(ssf.validateSubjectId(loose, {}), 'tenant',
        'the "' + row.format + '" format with an extra member');
  });
  log.info("[subjects] OK — every format refuses an undefined member by " +
      "name.");
}

function everyRequiredMemberIsRequired() {
  log.info("[subjects] A missing required member must be refused by name.");
  ssf.SUBJECT_FORMATS.forEach(function (row) {
    row.required.forEach(function (member) {
      const short = Object.assign({}, row.example);
      delete short[member];
      refuses(ssf.validateSubjectId(short, {}), member,
          'the "' + row.format + '" format without its "' + member + '"');
    });
  });
  log.info("[subjects] OK — every required member is enforced.");
}

function theValueShapesAreChecked() {
  log.info("[subjects] The value rules that a comparison depends on.");
  refuses(ssf.validateSubjectId(
      { format: 'phone_number', phone_number: '+1 206 555 0100' }, {}),
      'E.164',
      'a phone number with spaces — a DIFFERENT subject to any receiver');
  refuses(ssf.validateSubjectId(
      { format: 'phone_number', phone_number: '2065550100' }, {}),
      'E.164', 'a phone number with no leading +');
  refuses(ssf.validateSubjectId(
      { format: 'account', uri: 'alice@example.com' }, {}),
      'acct', 'an account without the acct: scheme');
  refuses(ssf.validateSubjectId(
      { format: 'account', uri: 'mailto:alice@example.com' }, {}),
      'acct', 'an account with the wrong scheme');
  refuses(ssf.validateSubjectId({ format: 'email', email: 'alice' }, {}),
      'email address', 'an email address with no @');
  refuses(ssf.validateSubjectId(
      { format: 'decentralized_identifier', url: 'https://example.com' }, {}),
      'DID', 'a DID that is an https URL');
  refuses(ssf.validateSubjectId({ format: 'uri', uri: '/users/1' }, {}),
      'absolute URI', 'a relative URI');
  refuses(ssf.validateSubjectId(
      { format: 'issuer_subject_id', iss: 'issuer.example.com', sub: 'a' },
      {}), 'absolute URI', 'an issuer that is not a URI');
  check('an opaque id has NO shape rule, by definition', function () {
    const verdict = ssf.validateSubjectId(
        { format: 'opaque', id: '///not a uri///' }, {});
    assert.ok(verdict.ok,
        'An opaque identifier is opaque BY DEFINITION, so a check on its ' +
        'shape would be this build inventing a rule.');
  });
  check('an empty value is refused', function () {
    const verdict = ssf.validateSubjectId({ format: 'opaque', id: '' }, {});
    assert.ok(!verdict.ok);
  });
  refuses(ssf.validateSubjectId({ format: 'nonsuch', id: 'x' }, {}),
      'nonsuch', 'a format RFC 9493 does not define');
  refuses(ssf.validateSubjectId({ email: 'a@b.c' }, {}), 'format',
      'a simple identifier with no format — which is ALSO how a complex one ' +
      'is told apart, so the message has to name the format member');
  log.info("[subjects] OK — every value rule refuses by name.");
}

function aliasesMayNotNest() {
  log.info("[subjects] RFC 9493 section 3.2.8: an aliases identifier may not " +
      "contain another. It is refused rather than flattened, because " +
      "flattening builds a document a conforming receiver rejects and the " +
      "sender never finds out.");
  refuses(ssf.validateSubjectId({ format: 'aliases', identifiers: [
    { format: 'email', email: 'a@b.c' },
    { format: 'aliases', identifiers: [
      { format: 'opaque', id: 'x' }] }] }, {}),
      '3.2.8', 'a nested aliases identifier');
  refuses(ssf.validateSubjectId({ format: 'aliases', identifiers: [] }, {}),
      'empty', 'an empty aliases identifier');
  refuses(ssf.validateSubjectId({ format: 'aliases', identifiers: 'a@b.c' },
      {}), 'array', 'an aliases identifier whose identifiers is a string');
  refuses(ssf.validateSubjectId({ format: 'aliases', identifiers: [
    { format: 'email', email: 'no-at-sign' }] }, {}),
      'identifiers[0]',
      'a bad member INSIDE an aliases identifier — the path has to name it');
  check('a good aliases identifier validates', function () {
    const verdict = ssf.validateSubjectId({ format: 'aliases', identifiers: [
      { format: 'email', email: 'alice@example.com' },
      { format: 'phone_number', phone_number: '+12065550100' },
      { format: 'opaque', id: 'abc' }] }, {});
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });
  log.info("[subjects] OK — the nesting ban is enforced and the path names " +
      "the offending member.");
}

// ---------------------------------------------------------------------------
// 2. COMPLEX SUBJECTS.
// ---------------------------------------------------------------------------
function complexSubjectsAreClosedToo() {
  log.info("[complex] SSF 1.0 section 4's six members, and the fact that a " +
      "complex subject is told from a simple one by the ABSENCE of `format`.");
  assert.strictEqual(ssf.COMPLEX_SUBJECT_MEMBERS.length, 6,
      'SSF defines six complex subject members and this build has ' +
      ssf.COMPLEX_SUBJECT_MEMBERS.length + '.');
  checks++;
  ['user', 'device', 'session', 'tenant', 'org_unit', 'group']
    .forEach(function (name) {
      check('the "' + name + '" member is defined', function () {
        assert.ok(ssf.COMPLEX_SUBJECT_MEMBER_NAMES.indexOf(name) >= 0);
      });
      check('a complex subject of one "' + name + '" validates', function () {
        const subject = {};
        subject[name] = { format: 'opaque', id: 'x-' + name };
        const verdict = ssf.validateSubjectId(subject, {});
        assert.ok(verdict.ok, verdict.errors.join(' '));
        assert.strictEqual(verdict.complex, true);
      });
    });
  check('every member at once validates', function () {
    const subject = {};
    ssf.COMPLEX_SUBJECT_MEMBER_NAMES.forEach(function (name) {
      subject[name] = { format: 'opaque', id: name };
    });
    const verdict = ssf.validateSubjectId(subject, {});
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });
  refuses(ssf.validateSubjectId({ workload: { format: 'opaque', id: 'x' } },
      {}), 'workload', 'a complex member SSF does not define');
  refuses(ssf.validateSubjectId({}, {}), 'empty', 'an empty complex subject');
  refuses(ssf.validateSubjectId(
      { user: { format: 'email', email: 'nope' } }, {}), 'user.email',
      'a bad identifier inside a complex member — the path has to name it');
  check('an OPAQUE subject whose id is spelt "user" is still simple',
    function () {
      // The discriminator is `format` and NOT "does it have a member called
      // user", which is the obvious alternative and is wrong for exactly this.
      const verdict = ssf.validateSubjectId(
          { format: 'opaque', id: 'user' }, {});
      assert.ok(verdict.ok);
      assert.strictEqual(verdict.complex, false);
    });
  log.info("[complex] OK — six members, closed, and the discriminator is " +
      "`format`.");
}

function criticalSubjectMembersAreEnforced() {
  log.info("[complex] critical_subject_members is a PROMISE: a transmitter " +
      "that publishes one and omits it produces events nothing acts on.");
  refuses(ssf.validateSubjectId({ user: { format: 'opaque', id: 'a' } },
      { criticalMembers: ['session'] }), 'session',
      'a complex subject missing a critical member');
  check('a complex subject carrying it passes', function () {
    const verdict = ssf.validateSubjectId({
      user: { format: 'opaque', id: 'a' },
      session: { format: 'opaque', id: 's' } },
      { criticalMembers: ['session'] });
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });
  check('a SIMPLE subject is not held to it', function () {
    // The rule is about COMPLEX subjects: a simple identifier has no members
    // to be critical, and holding it to the list would refuse every stream
    // whose subjects are email addresses.
    const verdict = ssf.validateSubjectId({ format: 'opaque', id: 'a' },
        { criticalMembers: ['session'] });
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });
  log.info("[complex] OK.");
}

// ---------------------------------------------------------------------------
// 3. KEYS AND DESCRIPTIONS.
// ---------------------------------------------------------------------------
function subjectKeysAreStable() {
  log.info("[keys] The same subject must key the same however it was " +
      "written, and two different subjects must never collide.");
  check('member order does not change the key', function () {
    const a = ssf.subjectKey({ format: 'issuer_subject_id',
      iss: 'https://i/', sub: 'x' });
    const b = ssf.subjectKey({ sub: 'x', format: 'issuer_subject_id',
      iss: 'https://i/' });
    assert.strictEqual(a, b);
  });
  check('aliases key on their SORTED members', function () {
    const a = ssf.subjectKey({ format: 'aliases', identifiers: [
      { format: 'email', email: 'a@b.c' },
      { format: 'opaque', id: 'z' }] });
    const b = ssf.subjectKey({ format: 'aliases', identifiers: [
      { format: 'opaque', id: 'z' },
      { format: 'email', email: 'a@b.c' }] });
    assert.strictEqual(a, b,
        'The same two identifiers in the other order are ONE subject, which ' +
        'is what the aliases format means.');
  });
  check('two formats carrying the same string do not collide', function () {
    const a = ssf.subjectKey({ format: 'opaque', id: 'alice@example.com' });
    const b = ssf.subjectKey({ format: 'email', email: 'alice@example.com' });
    assert.notStrictEqual(a, b,
        'An opaque id and an email address that happen to read the same are ' +
        'DIFFERENT subjects.');
  });
  check('a complex subject keys differently from its user member',
    function () {
      const a = ssf.subjectKey({ user: { format: 'opaque', id: 'x' } });
      const b = ssf.subjectKey({ format: 'opaque', id: 'x' });
      assert.notStrictEqual(a, b);
    });
  check('describeSubject names every value', function () {
    assert.ok(ssf.describeSubject({ format: 'issuer_subject_id',
      iss: 'https://i/', sub: 'alice' }).indexOf('alice') >= 0);
    assert.ok(ssf.describeSubject({
      user: { format: 'email', email: 'a@b.c' },
      session: { format: 'opaque', id: 's1' } }).indexOf('session') >= 0);
    assert.strictEqual(ssf.describeSubject(null), '(no subject)');
  });
  log.info("[keys] OK.");
}

// ---------------------------------------------------------------------------
// 4. DELIVERY METHODS.
// ---------------------------------------------------------------------------
function deliveryMethodsAreUrns() {
  log.info("[delivery] The values on the wire are the RFC numbers as URNs. " +
      "A stream asking for \"push\" is asking for nothing SSF defines, and " +
      "that catches everybody once.");
  check('the two URNs are the RFC numbers', function () {
    assert.strictEqual(ssf.DELIVERY_PUSH, 'urn:ietf:rfc:8935');
    assert.strictEqual(ssf.DELIVERY_POLL, 'urn:ietf:rfc:8936');
  });
  check('the shorthand normalises to the URN', function () {
    assert.strictEqual(ssf.deliveryUrn('push'), ssf.DELIVERY_PUSH);
    assert.strictEqual(ssf.deliveryUrn('poll'), ssf.DELIVERY_POLL);
    assert.strictEqual(ssf.deliveryUrn(ssf.DELIVERY_PUSH), ssf.DELIVERY_PUSH);
  });
  check('an unknown method is carried through rather than guessed at',
    function () {
      // NOT mapped to a default. A caller that typed something else is
      // telling the transmitter something, and quietly substituting poll
      // would produce a stream nobody asked for.
      assert.strictEqual(ssf.deliveryUrn('carrier-pigeon'), 'carrier-pigeon');
    });
  check('only poll can be received in a browser', function () {
    const push = ssf.DELIVERY_METHODS.filter(function (row) {
      return row.method === ssf.DELIVERY_PUSH;
    })[0];
    const poll = ssf.DELIVERY_METHODS.filter(function (row) {
      return row.method === ssf.DELIVERY_POLL;
    })[0];
    assert.strictEqual(push.browserCanReceive, false,
        'A browser cannot be an HTTP server, so it cannot be the far end of ' +
        'RFC 8935. That is the specification rather than this tool.');
    assert.strictEqual(poll.browserCanReceive, true);
    assert.strictEqual(push.needsEndpoint, true);
    assert.strictEqual(poll.needsEndpoint, false);
  });
  log.info("[delivery] OK.");
}

// ---------------------------------------------------------------------------
// 5. DISCOVERY.
// ---------------------------------------------------------------------------
function bothWellKnownShapesAreTried() {
  log.info("[discovery] RFC 8414 INSERTS the well-known segment before the " +
      "issuer's path and OpenID Connect Discovery APPENDS it. A transmitter " +
      "published under a path can be either, so both are tried, insertion " +
      "first.");
  check('an origin gets one candidate', function () {
    const list = ssf.metadataCandidates('https://transmitter.example.com');
    assert.deepStrictEqual(list,
        ['https://transmitter.example.com/.well-known/ssf-configuration']);
  });
  check('a path gets both, insertion first', function () {
    const list = ssf.metadataCandidates('https://host/realm/acme');
    assert.strictEqual(list.length, 2);
    assert.strictEqual(list[0],
        'https://host/.well-known/ssf-configuration/realm/acme');
    assert.strictEqual(list[1],
        'https://host/realm/acme/.well-known/ssf-configuration');
  });
  check('a trailing slash does not produce a double one', function () {
    const list = ssf.metadataCandidates('https://host/');
    assert.strictEqual(list[0],
        'https://host/.well-known/ssf-configuration');
  });
  check('nothing in gets nothing out', function () {
    assert.deepStrictEqual(ssf.metadataCandidates(''), []);
    assert.deepStrictEqual(ssf.metadataCandidates(null), []);
  });
  log.info("[discovery] OK.");
}

function everyMetadataMemberIsDescribed() {
  log.info("[discovery] Every member SSF 1.0 section 6 defines, and which " +
      "are required — a reader cannot tell a missing OPTIONAL member from a " +
      "missing REQUIRED one by looking.");
  ['spec_version', 'issuer', 'jwks_uri', 'delivery_methods_supported',
   'configuration_endpoint', 'status_endpoint', 'add_subject_endpoint',
   'remove_subject_endpoint', 'verification_endpoint',
   'critical_subject_members', 'default_subjects', 'authorization_schemes']
    .forEach(function (name) {
      check('"' + name + '" is described', function () {
        const row = ssf.METADATA_MEMBERS.filter(function (one) {
          return one.name === name;
        })[0];
        assert.ok(row, 'SSF 1.0 defines "' + name + '" and this build does ' +
            'not describe it.');
        assert.ok(row.what.length > 20,
            '"' + name + '" has no useful description.');
      });
    });
  check('issuer and jwks_uri are the two required ones', function () {
    const required = ssf.METADATA_MEMBERS.filter(function (row) {
      return row.required;
    }).map(function (row) {
      return row.name;
    });
    assert.deepStrictEqual(required.sort(), ['issuer', 'jwks_uri']);
  });
  check('a document missing a required member is reported', function () {
    const read = ssf.readMetadata({ jwks_uri: 'https://h/jwks' });
    assert.ok(!read.ok);
    assert.deepStrictEqual(read.missing, ['issuer']);
  });
  check('an UNKNOWN member is reported and not refused', function () {
    // SSF metadata extends. A member this build does not know is a
    // transmitter doing something extra rather than something wrong.
    const read = ssf.readMetadata({ issuer: 'https://i/',
      jwks_uri: 'https://i/jwks', vendor_extension: true });
    assert.ok(read.ok);
    assert.deepStrictEqual(read.unknown, ['vendor_extension']);
  });
  check('the delivery methods are normalised on read', function () {
    const read = ssf.readMetadata({ issuer: 'https://i/',
      jwks_uri: 'https://i/jwks',
      delivery_methods_supported: ['push'] });
    assert.strictEqual(read.canPush, true);
    assert.strictEqual(read.canPoll, false);
  });
  log.info("[discovery] OK.");
}

function noEndpointIsEverComposed() {
  log.info("[discovery] SSF fixes no paths, so every endpoint comes out of " +
      "the metadata and this workflow composes none. A member the document " +
      "does not carry produces a sentence rather than a guess.");
  const doc = { issuer: 'https://i/', jwks_uri: 'https://i/jwks',
    configuration_endpoint: 'https://i/v1/streams/manage' };
  check('a published endpoint is used verbatim', function () {
    const found = ssf.endpointFor(doc, 'configuration_endpoint');
    assert.ok(found.ok);
    assert.strictEqual(found.url, 'https://i/v1/streams/manage');
  });
  check('an unpublished endpoint refuses and names the member', function () {
    const found = ssf.endpointFor(doc, 'verification_endpoint');
    assert.ok(!found.ok);
    assert.ok(found.error.indexOf('verification_endpoint') >= 0);
    assert.ok(found.error.indexOf('guess') >= 0,
        'The refusal has to say that this workflow will NOT guess a path, ' +
        'because guessing is exactly what a reader would otherwise expect.');
  });
  check('no metadata at all refuses rather than throwing', function () {
    const found = ssf.endpointFor(null, 'status_endpoint');
    assert.ok(!found.ok);
  });
  log.info("[discovery] OK.");
}

// ---------------------------------------------------------------------------
// 6. STREAM CONFIGURATIONS.
// ---------------------------------------------------------------------------
function streamConfigurationsAreBuiltAndChecked() {
  log.info("[streams] What a receiver may set, what it may not, and the " +
      "three refusals this workflow makes before anything is sent.");
  check('a poll configuration carries no endpoint_url', function () {
    const body = ssf.buildStreamConfiguration({
      aud: 'https://r/', deliveryMethod: 'poll' });
    assert.strictEqual(body.delivery.method, ssf.DELIVERY_POLL);
    assert.strictEqual(body.delivery.endpoint_url, undefined,
        'RFC 8936\'s poll endpoint is the TRANSMITTER\'s, so a ' +
        'receiver-supplied one would be a URL nothing calls.');
  });
  check('a push configuration carries one', function () {
    const body = ssf.buildStreamConfiguration({
      aud: 'https://r/', deliveryMethod: 'push',
      endpointUrl: 'https://r/events',
      authorizationHeader: 'Bearer x' });
    assert.strictEqual(body.delivery.method, ssf.DELIVERY_PUSH);
    assert.strictEqual(body.delivery.endpoint_url, 'https://r/events');
    assert.strictEqual(body.delivery.authorization_header, 'Bearer x');
  });
  check('members the TRANSMITTER owns are never sent', function () {
    const body = ssf.buildStreamConfiguration({
      aud: 'https://r/', deliveryMethod: 'poll',
      // Ignored: a create carrying either is a receiver asking for something
      // no transmitter will honour.
      iss: 'https://not-mine/', events_delivered: ['x'],
      events_supported: ['y'], min_verification_interval: 1 });
    assert.strictEqual(body.iss, undefined);
    assert.strictEqual(body.events_delivered, undefined);
    assert.strictEqual(body.events_supported, undefined);
    assert.strictEqual(body.min_verification_interval, undefined);
  });
  const meta = { issuer: 'https://i/', jwks_uri: 'https://i/jwks',
    delivery_methods_supported: [ssf.DELIVERY_POLL] };
  check('no aud is refused', function () {
    const verdict = ssf.checkStreamConfiguration(
        { delivery: { method: ssf.DELIVERY_POLL } }, meta);
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('aud') >= 0);
  });
  check('the shorthand method is refused and the URNs are named', function () {
    const verdict = ssf.checkStreamConfiguration(
        { aud: 'a', delivery: { method: 'push' } }, meta);
    assert.ok(!verdict.ok);
    const said = verdict.errors.join(' ');
    assert.ok(said.indexOf('urn:ietf:rfc:8935') >= 0 &&
        said.indexOf('urn:ietf:rfc:8936') >= 0,
        'The refusal has to NAME both URNs — that is the whole content of ' +
        'the mistake.');
  });
  check('a method the transmitter does not offer is refused', function () {
    const verdict = ssf.checkStreamConfiguration(
        { aud: 'a', delivery: { method: ssf.DELIVERY_PUSH,
          endpoint_url: 'https://r/e' } }, meta);
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('delivery_methods_supported')
        >= 0);
  });
  check('push with no endpoint is refused', function () {
    const verdict = ssf.checkStreamConfiguration(
        { aud: 'a', delivery: { method: ssf.DELIVERY_PUSH } },
        { issuer: 'i', jwks_uri: 'j',
          delivery_methods_supported: [ssf.DELIVERY_PUSH] });
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('endpoint_url') >= 0);
  });
  check('a bad format is refused and the eight are named', function () {
    const verdict = ssf.checkStreamConfiguration(
        { aud: 'a', format: 'username',
          delivery: { method: ssf.DELIVERY_POLL } }, meta);
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('issuer_subject_id') >= 0);
  });
  check('a poll stream with an endpoint WARNS rather than refusing',
    function () {
      // It is legal and pointless, which is exactly what a warning is for.
      const verdict = ssf.checkStreamConfiguration(
          { aud: 'a', delivery: { method: ssf.DELIVERY_POLL,
            endpoint_url: 'https://r/e' } }, meta);
      assert.ok(verdict.ok);
      assert.strictEqual(verdict.warnings.length, 1);
    });
  log.info("[streams] OK.");
}

function requestedVersusDeliveredIsSurfaced() {
  log.info("[streams] THE MEMBER MOST OFTEN CONFUSED. events_requested is " +
      "the ask and events_delivered is the answer; SSF has no refusal for a " +
      "type a transmitter will not agree to, so its ABSENCE is the only " +
      "notice a receiver gets.");
  const asked = { events_requested: ['a', 'b', 'c'],
    delivery: { method: ssf.DELIVERY_POLL } };
  const answered = { stream_id: 's1', iss: 'https://i/', aud: 'r',
    events_requested: ['a', 'b', 'c'], events_delivered: ['a'],
    events_supported: ['a'], delivery: { method: ssf.DELIVERY_POLL } };
  check('a dropped event type is reported', function () {
    const read = ssf.readStreamConfiguration(answered, asked);
    assert.strictEqual(read.surprises.length, 2,
        'Two of three asked-for types were not agreed and neither was ' +
        'reported.');
    assert.ok(read.surprises[0].indexOf('ONLY NOTICE') >= 0);
  });
  check('a changed delivery method is reported', function () {
    const read = ssf.readStreamConfiguration(
        { stream_id: 's', delivery: { method: ssf.DELIVERY_POLL },
          events_delivered: [] },
        { delivery: { method: ssf.DELIVERY_PUSH }, events_requested: [] });
    assert.strictEqual(read.surprises.length, 1);
    assert.ok(read.surprises[0].indexOf('Push') >= 0);
  });
  check('nothing surprising is nothing reported', function () {
    const read = ssf.readStreamConfiguration(
        { stream_id: 's', events_delivered: ['a'],
          delivery: { method: ssf.DELIVERY_POLL } },
        { events_requested: ['a'],
          delivery: { method: ssf.DELIVERY_POLL } });
    assert.strictEqual(read.surprises.length, 0);
  });
  check('the three statuses are defined and PAUSED is explained', function () {
    assert.deepStrictEqual(ssf.STREAM_STATUS_NAMES,
        ['enabled', 'paused', 'disabled']);
    const paused = ssf.STREAM_STATUSES.filter(function (row) {
      return row.status === 'paused';
    })[0];
    assert.ok(paused.what.indexOf('KEEPS QUEUEING') >= 0,
        'The difference between paused and disabled is the whole reason a ' +
        'receiver has a pause, and it has to be said.');
  });
  check('every stream member says whose it is', function () {
    assert.strictEqual(ssf.STREAM_MEMBERS.length, 10);
    ssf.STREAM_MEMBERS.forEach(function (row) {
      assert.ok(row.owner === 'transmitter' || row.owner === 'receiver',
          '"' + row.name + '" says its owner is "' + row.owner + '".');
      assert.ok(row.what.length > 20);
    });
  });
  log.info("[streams] OK.");
}

// ---------------------------------------------------------------------------
// 7. THE SET ENVELOPE.
// ---------------------------------------------------------------------------
function theSetEnvelopeIsRfc8417Shaped() {
  log.info("[set] RFC 8417: the events MAP, no exp, sub_id rather than sub, " +
      "and typ=secevent+jwt.");
  const claims = ssf.buildSetClaims({
    issuer: 'https://i/', audience: 'https://r/',
    uri: events.SSF_PREFIX + 'verification',
    payload: { state: 'hello' },
    subject: { format: 'opaque', id: 'alice' },
    txn: 'txn-1', toe: 1700000000 });
  check('the required claims are all there', function () {
    ['iss', 'jti', 'iat', 'aud', 'events'].forEach(function (name) {
      assert.ok(claims[name] !== undefined, 'no ' + name);
    });
  });
  check('there is NO exp', function () {
    assert.strictEqual(claims.exp, undefined,
        'RFC 8417 section 4.1.4: a SET MUST NOT be considered to expire. It ' +
        'records that something HAPPENED, and a fact does not stop being ' +
        'true.');
  });
  check('the subject is sub_id and there is no sub', function () {
    assert.deepStrictEqual(claims.sub_id, { format: 'opaque', id: 'alice' });
    assert.strictEqual(claims.sub, undefined);
  });
  check('events is a MAP keyed by type URI', function () {
    const keys = Object.keys(claims.events);
    assert.strictEqual(keys.length, 1);
    assert.strictEqual(keys[0], events.SSF_PREFIX + 'verification');
    assert.deepStrictEqual(claims.events[keys[0]], { state: 'hello' });
  });
  check('toe and txn are carried', function () {
    assert.strictEqual(claims.toe, 1700000000);
    assert.strictEqual(claims.txn, 'txn-1');
  });
  check('every jti is different', function () {
    const seen = {};
    let i;
    for (i = 0; i < 200; i++) {
      const jti = ssf.newJti();
      assert.ok(!seen[jti], 'newJti() repeated ' + jti + ' within 200 calls.');
      seen[jti] = true;
    }
  });
  check('the header carries typ=secevent+jwt', function () {
    const header = ssf.setHeader('ES256', { kid: 'k1' });
    assert.strictEqual(header.typ, 'secevent+jwt',
        'RFC 8417 section 2.2. A receiver that dispatches on the type drops ' +
        'a token without it with no error anybody sees.');
    assert.strictEqual(header.alg, 'ES256');
    assert.strictEqual(header.kid, 'k1');
  });
  check('the header carries the JOSE alg and NOT the selection id',
    function () {
      // jws.js identifies the two Edwards curves by selection — RFC 8037
      // registers ONE `alg` for both and puts the curve in the key — and a
      // header carrying `EdDSA-Ed25519` would name an algorithm the JOSE
      // registry does not have. No verifier on earth would accept it.
      assert.strictEqual(ssf.setHeader('EdDSA-Ed25519', {}).alg, 'EdDSA');
      assert.strictEqual(ssf.setHeader('EdDSA-Ed448', {}).alg, 'EdDSA');
    });
  log.info("[set] OK.");
}

// Signing with every family jws.js offers. It is not a check of jws.js — that
// is tests/jws_engine.js's — but of the ROUND TRIP through this workflow's own
// header and claim assembly, which is where a SET stops being a SET: a `typ`
// dropped by the builder, or a claim set re-serialized between building and
// signing, produces a token that verifies and that no receiver will dispatch.
function everySignatureFamilyRoundTrips() {
  log.info("[set] Signing and verifying with one algorithm from every " +
      "family jws.js offers, POST-QUANTUM INCLUDED — a SET is the document " +
      "here most worth signing that way, because RFC 8417 forbids it to " +
      "expire and it is therefore read long after it was written.");
  // One per family rather than all forty: the algorithms themselves are
  // tests/jws_engine.js's subject, and what is being checked here is that
  // this workflow's envelope survives each KIND of signature.
  // The alg IDs are jws.js's own, and two of them are not JOSE `alg` values:
  // RFC 8037 registers ONE `alg` for both Edwards curves and puts the curve
  // in the key, so this build's table has `EdDSA-Ed25519` and `EdDSA-Ed448`
  // as SELECTIONS while the header still says `EdDSA`. That distinction is
  // asserted below rather than assumed.
  const algs = ['HS256', 'RS256', 'PS256', 'ES256', 'ES256K',
    'EdDSA-Ed25519', 'EdDSA-Ed448', 'ML-DSA-44', 'SLH-DSA-SHA2-128s',
    'ML-DSA-44-ES256', 'ML-DSA-87-Ed448'];
  const claims = ssf.buildSetClaims({
    issuer: 'https://i/', audience: 'https://r/',
    uri: events.SSF_PREFIX + 'stream-updated',
    payload: { status: 'paused', reason: 'maintenance' } });
  return algs.reduce(function (chain, alg) {
    return chain.then(function () {
      let spec;
      try {
        spec = jws.algSpec(alg);
      } catch (e) {
        log.info("[set] " + alg + " is not in this build's table; skipped.");
        return null;
      }
      const pair = jws.generateKey(alg);
      const priv = spec.family === 'rsa' ? pair.privateKey
        : jws.privateJwk(alg, pair.privateKey, pair.publicKey);
      const pub = spec.family === 'rsa' ? pair.publicKey
        : (spec.family === 'hmac' ? priv
          : jws.publicJwk(alg, pair.publicKey));
      return ssf.signSet(claims, priv, alg, { kid: 'k-' + alg })
        .then(function (token) {
          const parsed = ssf.parseSet(token);
          assert.ok(parsed.ok, alg + ': ' + parsed.problem);
          assert.strictEqual(parsed.header.alg, spec.alg,
              alg + ': the header says "' + parsed.header.alg + '". For the ' +
              'two Edwards selections that is deliberately NOT the selection ' +
              'id — RFC 8037 registers one `alg` for both curves and puts ' +
              'the curve in the key.');
          assert.strictEqual(parsed.header.typ, 'secevent+jwt',
              alg + ': the typ did not survive signing, so a receiver that ' +
              'dispatches on it would drop this token.');
          assert.deepStrictEqual(parsed.claims, claims,
              alg + ': the claim set changed between building and signing.');
          checks++;
          return ssf.verifySet(token, pub, alg).then(function (verdict) {
            assert.ok(verdict.valid,
                alg + ': the signature this workflow made does not verify.');
            checks++;
            log.info("[set] " + alg + " round trips.");
          });
        });
    });
  }, Promise.resolve()).then(function () {
    log.info("[set] OK — every family round trips through this envelope.");
  });
}

function everyFindingIsReachable() {
  log.info("[set] The findings a debugger exists to produce. Each is a " +
      "token that verifies perfectly and that a receiver should refuse or " +
      "question.");
  const good = ssf.buildSetClaims({ issuer: 'https://i/',
    audience: 'https://r/', uri: events.SSF_PREFIX + 'verification',
    payload: {} });
  check('a clean SET has no findings', function () {
    const verdict = ssf.inspectSet(good,
        { expectedIssuer: 'https://i/', expectedAudience: 'https://r/' });
    assert.ok(verdict.ok, verdict.errors.join(' '));
    assert.strictEqual(verdict.warnings.length, 0);
  });
  check('an exp is an ERROR and cites section 4.1.4', function () {
    const verdict = ssf.inspectSet(
        Object.assign({}, good, { exp: 1800000000 }), {});
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('4.1.4') >= 0);
  });
  check('a sub claim is a WARNING and explains sub_id', function () {
    const verdict = ssf.inspectSet(
        Object.assign({}, good, { sub: 'alice' }), {});
    assert.ok(verdict.ok, 'It is discouraged rather than forbidden.');
    assert.strictEqual(verdict.warnings.length, 1);
    assert.ok(verdict.warnings[0].indexOf('sub_id') >= 0);
  });
  ['iss', 'jti', 'iat', 'aud', 'events'].forEach(function (name) {
    check('a missing ' + name + ' is an error', function () {
      const missing = Object.assign({}, good);
      delete missing[name];
      const verdict = ssf.inspectSet(missing, {});
      assert.ok(!verdict.ok);
      assert.ok(verdict.errors.join(' ').indexOf(name) >= 0);
    });
  });
  check('an empty events map is an error', function () {
    const verdict = ssf.inspectSet(
        Object.assign({}, good, { events: {} }), {});
    assert.ok(!verdict.ok);
  });
  check('an events ARRAY is an error naming the map', function () {
    const verdict = ssf.inspectSet(
        Object.assign({}, good, { events: [] }), {});
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('ARRAY') >= 0);
  });
  check('a wrong issuer is an error', function () {
    const verdict = ssf.inspectSet(good,
        { expectedIssuer: 'https://somebody-else/' });
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('did not come from') >= 0);
  });
  check('an audience this receiver is not in is an error', function () {
    const verdict = ssf.inspectSet(good,
        { expectedAudience: 'https://somebody-else/' });
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('invalid_audience') >= 0);
  });
  check('an ARRAY audience containing this receiver passes', function () {
    const verdict = ssf.inspectSet(
        Object.assign({}, good, { aud: ['https://a/', 'https://r/'] }),
        { expectedAudience: 'https://r/' });
    assert.ok(verdict.ok, verdict.errors.join(' '));
  });
  check('an invalid sub_id is reported through the subject grammar',
    function () {
      const verdict = ssf.inspectSet(Object.assign({}, good,
          { sub_id: { format: 'email', email: 'a@b.c', tenant: 'x' } }), {});
      assert.ok(!verdict.ok);
      assert.ok(verdict.errors.join(' ').indexOf('tenant') >= 0);
    });
  check('a toe after the iat is a warning about clocks', function () {
    const verdict = ssf.inspectSet(Object.assign({}, good,
        { toe: Number(good.iat) + 3600 }), {});
    assert.ok(verdict.ok);
    assert.ok(verdict.warnings.join(' ').indexOf('clocks') >= 0);
  });
  check('alg: none is an ERROR on a SET', function () {
    const verdict = ssf.inspectSetHeader({ alg: 'none', typ: 'secevent+jwt' });
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('UNSIGNED') >= 0);
  });
  check('a missing typ is a warning that says why it matters', function () {
    const verdict = ssf.inspectSetHeader({ alg: 'ES256' });
    assert.ok(verdict.ok);
    assert.ok(verdict.warnings.join(' ').indexOf('secevent+jwt') >= 0);
  });
  check('a plain JWT typ is a warning too', function () {
    const verdict = ssf.inspectSetHeader({ alg: 'ES256', typ: 'JWT' });
    assert.strictEqual(verdict.warnings.length, 1);
  });
  check('parseSet reports rather than throwing', function () {
    assert.strictEqual(ssf.parseSet('not-a-jws').ok, false);
    assert.ok(ssf.parseSet('a.b').problem.indexOf('three') >= 0);
    assert.ok(ssf.parseSet('!!!.???.###').problem.indexOf('base64url') >= 0);
    assert.strictEqual(ssf.parseSet('').ok, false);
  });
  log.info("[set] OK — every finding is reachable and each names its cause.");
}

// ---------------------------------------------------------------------------
// 8. DELIVERY, IN BOTH DIRECTIONS.
// ---------------------------------------------------------------------------
function bothDeliveriesCompose() {
  log.info("[wire] RFC 8936's poll request and RFC 8935's push, and the " +
      "three outcomes a push has rather than two.");
  check('a poll request defaults sensibly', function () {
    const body = ssf.buildPollRequest({ streamId: 's1' });
    assert.strictEqual(body.maxEvents, 10);
    assert.strictEqual(body.returnImmediately, true);
    assert.strictEqual(body.stream_id, 's1');
    assert.strictEqual(body.ack, undefined,
        'An empty ack is OMITTED rather than sent as [], which is what a ' +
        'receiver with nothing to acknowledge actually means.');
  });
  check('ack and setErrs are carried when there are any', function () {
    const body = ssf.buildPollRequest({ streamId: 's', ack: ['j1', 'j2'],
      setErrs: { j3: { err: 'invalid_key', description: 'no' } } });
    assert.deepStrictEqual(body.ack, ['j1', 'j2']);
    assert.ok(body.setErrs.j3);
  });
  check('a poll answer is read, and moreAvailable is lifted out', function () {
    const read = ssf.readPollResponse({ sets: { j1: 'tok' },
      moreAvailable: true });
    assert.deepStrictEqual(read.jtis, ['j1']);
    assert.strictEqual(read.moreAvailable, true);
    assert.strictEqual(read.problems.length, 0);
  });
  check('an answer with no sets member is reported', function () {
    const read = ssf.readPollResponse({});
    assert.strictEqual(read.problems.length, 1);
    assert.ok(read.problems[0].indexOf('2.2') >= 0);
  });
  check('a push carries the RFC 8417 media type by default', function () {
    const built = ssf.buildPushRequest('a.b.c', {});
    assert.strictEqual(built.headers['Content-Type'],
        'application/secevent+jwt');
    assert.strictEqual(built.body, 'a.b.c');
    assert.strictEqual(built.method, 'POST');
  });
  check('the wrong media type can be sent ON PURPOSE', function () {
    // The whole point of a debugger: a receiver that dispatches on the type
    // drops a token sent as application/jwt with no error anybody sees, and
    // the only way to find that out is to send one.
    const built = ssf.buildPushRequest('a.b.c',
        { mediaType: 'application/jwt' });
    assert.strictEqual(built.headers['Content-Type'], 'application/jwt');
  });
  check('an authorization header is carried when there is one', function () {
    assert.strictEqual(
        ssf.buildPushRequest('t', { authorizationHeader: 'Bearer s' })
          .headers.Authorization, 'Bearer s');
    assert.strictEqual(
        ssf.buildPushRequest('t', {}).headers.Authorization, undefined);
  });
  check('202 is accepted', function () {
    const read = ssf.readPushResponse(202, '');
    assert.strictEqual(read.accepted, true);
    assert.strictEqual(read.refused, false);
    assert.strictEqual(read.note, '');
  });
  check('200 and 204 are accepted AND noted', function () {
    [200, 204].forEach(function (status) {
      const read = ssf.readPushResponse(status, '');
      assert.strictEqual(read.accepted, true);
      assert.ok(read.note.indexOf('202') >= 0,
          'The event arrived and a stricter transmitter might not have ' +
          'treated it as delivered — both halves have to be said.');
    });
  });
  check('a 400 with err is a REFUSAL and not a failure', function () {
    const read = ssf.readPushResponse(400,
        { err: 'invalid_audience', description: 'not for me' });
    assert.strictEqual(read.accepted, false);
    assert.strictEqual(read.refused, true);
    assert.strictEqual(read.err, 'invalid_audience');
    assert.ok(read.note.indexOf('different thing from a network failure')
        >= 0);
  });
  check('a 500 with no body is neither accepted nor a refusal', function () {
    const read = ssf.readPushResponse(500, '');
    assert.strictEqual(read.accepted, false);
    assert.strictEqual(read.refused, false);
  });
  check('a JSON string body is parsed', function () {
    const read = ssf.readPushResponse(400,
        '{"err":"invalid_key","description":"x"}');
    assert.strictEqual(read.refused, true);
  });
  log.info("[wire] OK.");
}

// ---------------------------------------------------------------------------
// 9. THE VOCABULARY, THE HISTORIES AND THE api's TWO MODULES.
// ---------------------------------------------------------------------------
function theVocabularyIsSsfsTwoAndSaysWhatIsMissing() {
  log.info("[events] SSF defines TWO event types of its own, both about the " +
      "pipe. CAEP and RISC are the vocabularies over it and this build says " +
      "so rather than leaving a short list to read as broken.");
  check('exactly the two SSF types are implemented', function () {
    assert.strictEqual(events.EVENT_URIS.length, 2);
    assert.ok(events.EVENT_BY_URI[events.SSF_PREFIX + 'verification']);
    assert.ok(events.EVENT_BY_URI[events.SSF_PREFIX + 'stream-updated']);
  });
  check('both have NO subject, and that is stated', function () {
    events.EVENTS.forEach(function (row) {
      assert.strictEqual(row.subject, 'none',
          row.uri + ' is about the STREAM rather than about anybody, so a ' +
          'receiver that insisted on a subject could not be verified.');
    });
  });
  check('the three families are listed and two say they are absent',
    function () {
      assert.strictEqual(events.FAMILIES.length, 3);
      const implemented = events.FAMILIES.filter(function (row) {
        return row.implemented;
      });
      assert.deepStrictEqual(implemented.map(function (row) {
        return row.id;
      }), ['ssf']);
      events.FAMILIES.forEach(function (row) {
        assert.ok(row.what.length > 40, row.id + ' has no description.');
        if (!row.implemented) {
          assert.ok(row.what.indexOf('NOT IMPLEMENTED') >= 0,
              row.id + ' does not say it is absent, so a reader would take ' +
              'an empty list for a broken page.');
        }
      });
    });
  check('an unknown type is PLACED by prefix rather than called unknown',
    function () {
      assert.strictEqual(
          events.familyOf(events.CAEP_PREFIX + 'session-revoked'), 'caep');
      assert.strictEqual(
          events.familyOf(events.RISC_PREFIX + 'account-disabled'), 'risc');
      assert.strictEqual(events.familyOf('https://example.com/x'), '');
    });
  check('verification takes an optional state', function () {
    const uri = events.SSF_PREFIX + 'verification';
    assert.deepStrictEqual(events.generateEvent(uri, { state: 's' }),
        { state: 's' });
    assert.deepStrictEqual(events.generateEvent(uri, {}), {});
    assert.ok(events.validateEvent(uri, {}).ok,
        'The state is OPTIONAL, so an empty payload is a valid verification.');
  });
  check('stream-updated requires a status from the closed list', function () {
    const uri = events.SSF_PREFIX + 'stream-updated';
    assert.ok(events.validateEvent(uri, { status: 'paused' }).ok);
    assert.ok(!events.validateEvent(uri, {}).ok);
    assert.ok(!events.validateEvent(uri, { status: 'halted' }).ok);
    assert.deepStrictEqual(events.generateEvent(uri,
        { status: 'disabled', reason: 'why' }),
        { status: 'disabled', reason: 'why' });
  });
  check('a wrongly typed member is refused', function () {
    const uri = events.SSF_PREFIX + 'verification';
    assert.ok(!events.validateEvent(uri, { state: 42 }).ok);
  });
  check('an UNRECOGNISED member is a warning, not an error', function () {
    // The opposite of the subject rule, and the difference is the
    // specifications' own: an event vocabulary EXTENDS, and a receiver is
    // expected to ignore what it does not know.
    const uri = events.SSF_PREFIX + 'verification';
    const verdict = events.validateEvent(uri, { state: 's', vendor: 'x' });
    assert.ok(verdict.ok);
    assert.strictEqual(verdict.warnings.length, 1);
  });
  check('an unknown event type is refused and the two are named', function () {
    const verdict = events.validateEvent('https://example.com/x', {});
    assert.ok(!verdict.ok);
    assert.ok(verdict.errors.join(' ').indexOf('verification') >= 0);
  });
  check('a non-object payload is refused', function () {
    const uri = events.SSF_PREFIX + 'verification';
    assert.ok(!events.validateEvent(uri, 'a string').ok);
    assert.ok(!events.validateEvent(uri, []).ok);
  });
  check('describeEvents reads a whole events map', function () {
    const map = {};
    map[events.SSF_PREFIX + 'verification'] = { state: 's' };
    map[events.CAEP_PREFIX + 'session-revoked'] = { reason_user: 'x' };
    const rows = events.describeEvents(map);
    assert.strictEqual(rows.length, 2,
        'A SET may carry SEVERAL events — that is what the map is for — and ' +
        'a reader that showed only the first would drop events silently.');
    assert.strictEqual(rows[0].known, true);
    assert.strictEqual(rows[1].known, false);
    assert.strictEqual(rows[1].family, 'caep');
  });
  log.info("[events] OK.");
}

function theHistoriesCapAndRedact() {
  log.info("[history] The two histories: what is kept, what is redacted, and " +
      "the caps. There is no window here, so the stores are absent and every " +
      "function has to cope — which is itself the check, because a page " +
      "without storage must still work.");
  check('the redacted headers lose their WHOLE value', function () {
    const out = history.redactHeaders({
      Authorization: 'Bearer secret', 'X-Tenant': 'acme',
      Cookie: 'session=abc', DPoP: 'proof' });
    assert.strictEqual(out.Authorization, history.REDACTED);
    assert.strictEqual(out.Cookie, history.REDACTED);
    assert.strictEqual(out.DPoP, history.REDACTED);
    assert.strictEqual(out['X-Tenant'], 'acme',
        'Everything else is kept: the redaction is by NAME and only the ' +
        'credentials go, because guessing which PART of a credential is ' +
        'secret is how a redactor leaves half of one behind.');
  });
  check('redaction is case-insensitive', function () {
    const out = history.redactHeaders({ AUTHORIZATION: 'Bearer x' });
    assert.strictEqual(out.AUTHORIZATION, history.REDACTED);
  });
  check('an exchange is redacted whole and the body is capped', function () {
    const out = history.redactExchange({
      method: 'POST', url: 'https://t/ssf/stream', status: 201,
      requestHeaders: { Authorization: 'Bearer x' },
      responseHeaders: {},
      responseBody: new Array(9000).join('a') });
    assert.strictEqual(out.requestHeaders.Authorization, history.REDACTED);
    assert.ok(out.responseBody.length <= 4096);
    assert.strictEqual(history.redactExchange(null), null);
  });
  check('every store function copes with no storage at all', function () {
    // No `window` in node. A history is a convenience and a page without one
    // must still work, so nothing here may throw.
    assert.deepStrictEqual(history.tokens(), []);
    assert.deepStrictEqual(history.messages(), []);
    assert.strictEqual(history.hasMessage('j1', 'received'), false);
    history.clearTokens();
    history.clearMessages();
    assert.strictEqual(history.noteTokenUse('', 'x'), false);
    assert.ok(history.recordTokens({ source: 's' }).indexOf('tok') === 0);
    assert.ok(history.recordMessage({ direction: 'sent' }).indexOf('msg')
        === 0);
  });
  check('the cap is a thousand of each', function () {
    assert.strictEqual(history.LIMIT, 1000);
  });
  log.info("[history] OK.");
}

function theApiProxyRefusesWhatItShould() {
  log.info("[api proxy] Every refusal POST /ssf/call can produce, with no " +
      "transmitter on the other end — so a rule that stopped being enforced " +
      "fails a test naming the rule rather than timing out against a host.");
  const config = {};
  check('a relative URL is refused', function () {
    const out = proxy.describeRequest({ url: '/ssf/stream' }, config);
    assert.ok(!out.ok);
    assert.ok(out.error.indexOf('absolute') >= 0);
  });
  check('no URL at all is refused', function () {
    assert.ok(!proxy.describeRequest({}, config).ok);
  });
  check('a non-http scheme is refused', function () {
    assert.ok(!proxy.describeRequest({ url: 'file:///etc/passwd' },
        config).ok);
  });
  check('all five methods are allowed and nothing else', function () {
    assert.deepStrictEqual(proxy.METHODS,
        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
    proxy.METHODS.forEach(function (method) {
      assert.ok(proxy.describeRequest({ url: 'https://t/x', method: method },
          config).ok, method + ' was refused.');
    });
    ['HEAD', 'OPTIONS', 'TRACE', 'CONNECT'].forEach(function (method) {
      assert.ok(!proxy.describeRequest({ url: 'https://t/x', method: method },
          config).ok, method + ' was allowed.');
    });
  });
  check('the framing headers are refused BY NAME with a reason', function () {
    ['Host', 'Content-Length', 'Transfer-Encoding', 'Connection',
     'Keep-Alive', 'Upgrade', 'TE', 'Trailer', 'Proxy-Authorization']
      .forEach(function (name) {
        const headers = {};
        headers[name] = 'x';
        const out = proxy.sanitizeHeaders(headers);
        assert.ok(!out.ok, name + ' was forwarded.');
        assert.ok(out.error.indexOf(name) >= 0);
      });
  });
  check('an ordinary header is forwarded', function () {
    const out = proxy.sanitizeHeaders({ 'X-Tenant-Id': 'acme',
      'If-Match': 'W/"1"' });
    assert.ok(out.ok);
    assert.strictEqual(out.headers['X-Tenant-Id'], 'acme');
  });
  check('a header name that is not a token is refused', function () {
    assert.ok(!proxy.sanitizeHeaders({ 'not a token': 'x' }).ok);
  });
  check('CR or LF in a value is refused as injection', function () {
    const out = proxy.sanitizeHeaders({ 'X-A': 'a\r\nX-B: b' });
    assert.ok(!out.ok);
    assert.ok(out.error.indexOf('injection') >= 0);
  });
  check('a body on a GET is refused rather than dropped', function () {
    const out = proxy.encodeBody({ a: 1 }, 'GET', config);
    assert.ok(!out.ok);
    assert.ok(out.error.indexOf('silently discarded') >= 0);
  });
  check('a body on a DELETE is ALLOWED, unlike the SCIM proxy', function () {
    // SSF's stream management API is ONE PATH with five methods, and a DELETE
    // names the stream it is deleting in a JSON body. Refusing it would make
    // the delete unreachable through this endpoint.
    const out = proxy.encodeBody({ stream_id: 's1' }, 'DELETE', config);
    assert.ok(out.ok, out.error);
  });
  check('an oversized body is refused naming the setting', function () {
    const out = proxy.encodeBody(new Array(500000).join('a'), 'POST', config);
    assert.ok(!out.ok);
    assert.ok(out.error.indexOf('ssfMaxRequestBytes') >= 0);
  });
  check('the media types are DEFAULTED and not forced', function () {
    const out = proxy.describeRequest({ url: 'https://t/x', method: 'POST',
      body: { a: 1 } }, config);
    assert.strictEqual(out.headers['Content-Type'], 'application/json');
    const chosen = proxy.describeRequest({ url: 'https://t/x',
      method: 'POST', body: { a: 1 },
      headers: { 'Content-Type': 'text/plain' } }, config);
    assert.strictEqual(chosen.headers['Content-Type'], 'text/plain',
        'A debugger has to be able to send the wrong type on purpose.');
  });
  check('TLS verification is on unless explicitly turned off', function () {
    assert.strictEqual(
        proxy.describeRequest({ url: 'https://t/x' }, config).sslValidate,
        true);
    assert.strictEqual(
        proxy.describeRequest({ url: 'https://t/x', sslValidate: false },
          config).sslValidate, false);
    assert.strictEqual(
        proxy.describeRequest({ url: 'https://t/x', sslValidate: 'nonsense' },
          config).sslValidate, true,
        'Only an explicit false disables it, so a misspelled member leaves ' +
        'verification on.');
  });
  check('a 204 with no body is a SUCCESS and says so', function () {
    const read = proxy.readResponse(204, {}, '');
    assert.strictEqual(read.ok, true);
    assert.strictEqual(read.noBody, true);
  });
  check('an {err, description} refusal is read out', function () {
    const read = proxy.readResponse(400, {},
        '{"err":"access_denied","description":"needs ssf:write"}');
    assert.strictEqual(read.ok, false);
    assert.strictEqual(read.err, 'access_denied');
    assert.ok(read.description.indexOf('ssf:write') >= 0);
  });
  check('a non-JSON error names what is in front of the transmitter',
    function () {
      const read = proxy.readResponse(502, {}, '<html>Bad Gateway</html>');
      assert.ok(read.description.indexOf('in front of it') >= 0);
    });
  check('the limits document names the caps and the status rule', function () {
    const limits = proxy.limits({ ssfMaxRequestBytes: 1234 },
        { enabled: true });
    assert.strictEqual(limits.maxRequestBytes, 1234);
    assert.ok(limits.statusRule.indexOf('502') >= 0);
    assert.ok(limits.deliveryFromTheBrowser.indexOf('8935') >= 0,
        'The one asymmetry in this workflow has to be published, because a ' +
        'page cannot discover it any other way.');
    assert.ok(limits.receiver.enabled);
  });
  log.info("[api proxy] OK.");
}

function theApiReceiverIsBounded() {
  log.info("[api receiver] The push inbox: an unauthenticated endpoint that " +
      "accepts data, which is the most dangerous shape anything in the api " +
      "has. Every bound is structural rather than a gate, so every bound is " +
      "checked here.");
  receiver.reset();
  const config = { ssfReceiverEnabled: true, ssfReceiverMaxInboxes: 3,
    ssfReceiverMaxEvents: 4, ssfReceiverMaxEventBytes: 200,
    ssfReceiverTtlMs: 60000 };
  check('an inbox id is unguessable', function () {
    const made = receiver.create(config, { label: 'x' });
    assert.ok(made.ok);
    assert.ok(/^[0-9a-f]{32}$/.test(made.id),
        'The id is the whole of the access control: 16 random bytes.');
    receiver.reset();
  });
  check('the inbox cap is enforced and names the setting', function () {
    receiver.reset();
    let i;
    for (i = 0; i < 3; i++) {
      assert.ok(receiver.create(config, {}).ok);
    }
    const refused = receiver.create(config, {});
    assert.ok(!refused.ok);
    assert.ok(refused.error.indexOf('ssfReceiverMaxInboxes') >= 0);
    receiver.reset();
  });
  check('a push to an unknown inbox is a 404 with an err', function () {
    const out = receiver.deliver(config, 'deadbeef', { body: 'a.b.c' });
    assert.strictEqual(out.status, 404);
    assert.strictEqual(out.err, 'invalid_request');
  });
  check('an empty body is refused naming RFC 8935 section 2.1', function () {
    const made = receiver.create(config, {});
    const out = receiver.deliver(config, made.id, { body: '' });
    assert.strictEqual(out.status, 400);
    assert.ok(out.description.indexOf('2.1') >= 0);
    receiver.reset();
  });
  check('an oversized event is refused naming the setting', function () {
    const made = receiver.create(config, {});
    const out = receiver.deliver(config, made.id,
        { body: new Array(500).join('a') });
    assert.strictEqual(out.status, 400);
    assert.ok(out.description.indexOf('ssfReceiverMaxEventBytes') >= 0);
    receiver.reset();
  });
  check('a good push is a 202 with no body', function () {
    const made = receiver.create(config, {});
    const out = receiver.deliver(config, made.id, {
      body: token(), contentType: 'application/secevent+jwt' });
    assert.strictEqual(out.status, 202);
    assert.strictEqual(out.ok, true);
    assert.strictEqual(out.description, '',
        'RFC 8935 section 2.3 makes a success an EMPTY 202. A document here ' +
        'would be something a transmitter could depend on that no receiver ' +
        'has to send.');
    receiver.reset();
  });
  check('the WRONG media type is RECORDED and not refused', function () {
    // The finding this workflow exists to surface: a receiver that dispatches
    // on the type drops such a token with no error anybody sees, and refusing
    // it here would hide the finding behind a 400.
    const made = receiver.create(config, {});
    const out = receiver.deliver(config, made.id, {
      body: token(), contentType: 'application/jwt' });
    assert.strictEqual(out.status, 202);
    const drained = receiver.drain(config, made.id, 0);
    assert.strictEqual(drained.events[0].correctMediaType, false);
    assert.strictEqual(drained.events[0].contentType, 'application/jwt');
    receiver.reset();
  });
  check('a body that is not a compact JWS is recorded WITH its problem',
    function () {
      const made = receiver.create(config, {});
      receiver.deliver(config, made.id, { body: 'not-a-jws' });
      const drained = receiver.drain(config, made.id, 0);
      assert.ok(drained.events[0].problem.indexOf('three') >= 0);
      assert.strictEqual(drained.events[0].token, 'not-a-jws',
          'The token is kept whole either way: what arrived is the question ' +
          'being asked.');
      receiver.reset();
    });
  check('the OLDEST event is dropped when the ring fills', function () {
    const made = receiver.create(config, {});
    let i;
    for (i = 0; i < 6; i++) {
      receiver.deliver(config, made.id, { body: token(String(i)) });
    }
    const drained = receiver.drain(config, made.id, 0);
    assert.strictEqual(drained.events.length, 4);
    assert.strictEqual(drained.inbox.dropped, 2);
    assert.strictEqual(drained.inbox.pushes, 6);
    // A receiver that has stopped draining most wants what has happened
    // LATELY, and refusing new events would make a transmitter's push fail
    // because a page stopped reading.
    assert.strictEqual(drained.events[3].claims.n, '5');
    receiver.reset();
  });
  check('drain is a CURSOR rather than a destructive read', function () {
    const made = receiver.create(config, {});
    receiver.deliver(config, made.id, { body: token('1') });
    receiver.deliver(config, made.id, { body: token('2') });
    const first = receiver.drain(config, made.id, 0);
    assert.strictEqual(first.events.length, 2);
    const again = receiver.drain(config, made.id, 2);
    assert.strictEqual(again.events.length, 0);
    const all = receiver.drain(config, made.id, 0);
    assert.strictEqual(all.events.length, 2,
        'A second tab has to see everything, so the read must not empty the ' +
        'inbox.');
    receiver.reset();
  });
  check('a cursor past the end is clamped rather than failing', function () {
    const made = receiver.create(config, {});
    receiver.deliver(config, made.id, { body: token() });
    const out = receiver.drain(config, made.id, 99);
    assert.ok(out.ok);
    assert.strictEqual(out.events.length, 0);
    receiver.reset();
  });
  check('an expired inbox is swept and reports as gone', function () {
    const made = receiver.create(config, {});
    const old = { ssfReceiverEnabled: true, ssfReceiverTtlMs: 1 };
    // The sweep runs from every entry point rather than on a timer, which
    // would keep the event loop alive for a feature nobody is using.
    receiver.sweep(old, Date.now() + 1000);
    const out = receiver.drain(config, made.id, 0);
    assert.ok(!out.ok);
    assert.ok(out.error.indexOf('ssfReceiverTtlMs') >= 0);
    receiver.reset();
  });
  check('clear empties without deleting', function () {
    const made = receiver.create(config, {});
    receiver.deliver(config, made.id, { body: token() });
    const cleared = receiver.clear(config, made.id);
    assert.strictEqual(cleared.cleared, 1);
    assert.ok(receiver.get(config, made.id));
    receiver.reset();
  });
  check('the whole feature can be turned off', function () {
    const off = { ssfReceiverEnabled: false };
    assert.ok(!receiver.create(off, {}).ok);
    assert.strictEqual(receiver.enabled(off), false);
    assert.strictEqual(receiver.enabled({}), true,
        'Only an explicit false turns it off, so a missing key leaves the ' +
        'push half working rather than silently disabling it.');
  });
  check('it says it verifies NOTHING', function () {
    const limits = receiver.limits(config);
    assert.strictEqual(limits.verifies, false);
    assert.ok(limits.doesNotVerify.indexOf('no key') >= 0,
        'A receiver that refused what it could not verify would be unable ' +
        'to show anybody WHY, which is the question being asked.');
    assert.ok(limits.note.indexOf('HTTP server') >= 0);
  });
  receiver.reset();
  log.info("[api receiver] OK.");
}

// A compact JWS-shaped string with readable claims, for the receiver tests.
// It is not signed: what is being checked is the inbox's bookkeeping, and the
// signature is the PAGE's business.
function token(n) {
  const b64 = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  return b64({ alg: 'ES256', typ: 'secevent+jwt' }) + '.' +
    b64({ iss: 'https://i/', jti: 'j' + (n || '0'), iat: 1, aud: 'r',
      n: String(n || '0'), events: {} }) + '.' + 'c2ln';
}

function test() {
  log.debug("Entering test().");
  everyFormatIsDefinedAndValidates();
  theMemberSetIsClosed();
  everyRequiredMemberIsRequired();
  theValueShapesAreChecked();
  aliasesMayNotNest();
  complexSubjectsAreClosedToo();
  criticalSubjectMembersAreEnforced();
  subjectKeysAreStable();
  deliveryMethodsAreUrns();
  bothWellKnownShapesAreTried();
  everyMetadataMemberIsDescribed();
  noEndpointIsEverComposed();
  streamConfigurationsAreBuiltAndChecked();
  requestedVersusDeliveredIsSurfaced();
  theSetEnvelopeIsRfc8417Shaped();
  everyFindingIsReachable();
  bothDeliveriesCompose();
  theVocabularyIsSsfsTwoAndSaysWhatIsMissing();
  theHistoriesCapAndRedact();
  theApiProxyRefusesWhatItShould();
  theApiReceiverIsBounded();
  // The signing round trip is the only asynchronous section, so it closes.
  return everySignatureFamilyRoundTrips().then(function () {
    // A count, and it is ASSERTED rather than only printed: this file needs
    // no server and no browser, so there is no legitimate reason for it to
    // run fewer checks than it has. A sudden drop means a section stopped
    // being called, which is the way a suite quietly stops testing something.
    log.info(checks + " checks passed.");
    assert.ok(checks >= 170,
        'Only ' + checks + ' checks ran and this file defines well over a ' +
        'hundred and seventy. A section has stopped being called.');
    log.info("Test completed successfully.");
    log.debug("Leaving test().");
  });
}

const program = new Command();
program
  .name("ssf_engine")
  .description("Drive the Shared Signals workflow's engines in node with no " +
      "transmitter and no browser: all eight RFC 9493 subject formats and " +
      "the complex subject, the RFC 8417 SET envelope signed with every " +
      "algorithm family including the post-quantum ones, stream " +
      "configurations, both deliveries, the event vocabulary, the two " +
      "histories, and every refusal the api's SSF proxy and its push " +
      "receiver can produce.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
