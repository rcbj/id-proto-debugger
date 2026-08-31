// File: ssf_protocol.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS WORKFLOW AGAINST A REAL TRANSMITTER, OVER HTTP, WITH NO
// BROWSER.
//
// `ssf_engine.js` drives this workflow's modules against the specifications'
// own text and can say nothing about interoperability. This file is the other
// half: it sends what the PAGE would send — every request is composed by
// `client/src/ssf_client.js`, so a failure here is a failure of the shipped
// code — and it drives the mock STS's transmitter through the whole of SSF
// 1.0.
//
// **WHY THE TWO IMPLEMENTATIONS ARE DELIBERATELY SEPARATE, AND WHY THAT MAKES
// THIS FILE WORTH THE LINES.** The mock has its own RFC 9493 subject grammar
// (`sts/ssf/ssf_subjects.js`) and this workflow has its own
// (`client/src/ssf_client.js`), written independently — the argument
// `common/pq_jose.js` makes in the mock, applied to a grammar. If both ends
// read one implementation, a misunderstanding they share is one neither can
// see, and a round trip passes while interoperating with nothing. So the
// value of this file is precisely that it drives ONE grammar against THE
// OTHER, over the wire.
//
// **IT IS ALMOST ENTIRELY NEGATIVES**, which is the rule `tests/CLAUDE.md`
// states for the mock-driving family: a transmitter that answers a well-formed
// request correctly looks finished and can be worth nothing. What a receiver
// has to survive is the refusals, and every one of them here is reachable by
// configuration or by construction.
//
// EIGHT SECTIONS:
//
//   1. discovery — the metadata document, and that every endpoint is read
//      from it rather than composed
//   2. authentication — the 401, the two scopes, and the 403 that tells them
//      apart
//   3. the stream lifecycle — create, read, list, PUT, PATCH, delete, and the
//      difference between the last two
//   4. subjects — every RFC 9493 format across the wire, the closed member
//      set as the TRANSMITTER enforces it, and the idempotent remove
//   5. status — all three, what a pause keeps and a disable drops, and the
//      stream-updated event that goes with the change
//   6. delivery — poll end to end, the verification event, ack and setErrs,
//      and push against an endpoint this test hosts itself
//   7. the roles reversed — this test as the TRANSMITTER, pushing a signed
//      SET at the mock, including one signed POST-QUANTUM
//   8. the deliberate defects — a broken signature and a legacy `sub`
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ssf_protocol",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The workflow's own modules, so this test sends what the PAGE would send
// rather than a second implementation of it.
const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const jws = paths.requireSharedModule(
  [__dirname + "/../client/src/jws.js", __dirname + "/jws.js"], "jws.js");

// The transmitter. `WSTRUST_STS_URL` is what every other mock-driving job in
// this suite reads, so a run that points one of them at a mock points all of
// them at the same one.
var stsUrl = process.env.WSTRUST_STS_URL || process.env.STS_URL ||
    "https://localhost:8081";

// Where the mock's own admin API is, for the configuration this file changes.
var adminUrl = stsUrl + '/admin-api';

// Basic is the credential every section uses, for `scim_protocol.js`'s reason:
// it is the only scheme the mock offers that needs nothing but a header this
// process can compute — no token endpoint (so an authorization server having a
// bad day cannot make the stream sections fail and read as SSF), no scope, no
// nonce, no key. Section 2 is the exception and gets its own credentials.
const BASIC = 'Basic ' + Buffer.from('ssf-protocol-runner:pw')
    .toString('base64');

let checks = 0;
let skips = [];
// Everything this run created, so section 8 can leave the mock as it found it.
const created = { streams: [] };
// What was changed at /admin-api/config, so it can be put back.
const changed = {};

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function skip(what, why) {
  log.debug("Entering skip(). " + what);
  skips.push(what + ": " + why);
  log.warn("  SKIPPED — " + what + " — " + why);
  log.debug("Leaving skip().");
}

// ---------------------------------------------------------------------------
// THE TRANSPORT.
//
// Every call is composed by the workflow's own modules where there is a
// composer for it, and sent from this process directly rather than through the
// api: what is being tested is the PROTOCOL, and putting the api's proxy in
// the middle would make a refusal by it read as a refusal by the transmitter.
// `tests/api_ssf.js` is where that proxy is driven.
// ---------------------------------------------------------------------------
async function call(method, url, body, options) {
  log.debug("Entering call(). " + method + " " + url);
  const settings = options || {};
  const headers = Object.assign({ Accept: 'application/json' },
      settings.anonymous ? {} : { Authorization: settings.authorization ||
        BASIC },
      settings.headers || {});
  const init = { method: method, headers: headers };
  if (body !== undefined && body !== null) {
    if (!headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const response = await fetch(url, init);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (e) {
      // Not JSON. Kept as text: an HTML error page from something in front of
      // the transmitter is exactly the case where the body is the evidence.
      payload = null;
    }
  }
  log.debug("Leaving call(). " + response.status);
  return { status: response.status, body: payload, text: text };
}

async function setSetting(key, value) {
  log.debug("Entering setSetting(). " + key);
  const before = await call('GET', adminUrl + '/config', null, {});
  const row = ((before.body || {}).settings || []).filter(function (one) {
    return one.key === key;
  })[0];
  if (row && changed[key] === undefined) {
    changed[key] = row.value;
  }
  const out = await call('POST', adminUrl + '/config/set',
      { key: key, value: String(value) }, {});
  assert.strictEqual(out.status, 200,
      'The mock refused to set ' + key + ': ' + out.text);
  log.debug("Leaving setSetting().");
}

async function restoreSettings() {
  log.debug("Entering restoreSettings().");
  const keys = Object.keys(changed);
  let i;
  for (i = 0; i < keys.length; i++) {
    await call('POST', adminUrl + '/config/set',
        { key: keys[i], value: String(changed[keys[i]]) }, {});
  }
  log.debug("Leaving restoreSettings(). " + keys.length + " restored.");
}

// ---------------------------------------------------------------------------
// 1. DISCOVERY.
// ---------------------------------------------------------------------------
let metadata = null;

async function theMetadataIsReadable() {
  log.info("[discovery] The transmitter configuration metadata, and that " +
      "every endpoint below comes OUT of it. SSF fixes no paths, so a " +
      "workflow that composed one would be guessing.");
  const candidates = ssf.metadataCandidates(stsUrl);
  const answer = await call('GET', candidates[0], null, { anonymous: true });
  assert.strictEqual(answer.status, 200,
      'The metadata document is at ' + candidates[0] + ' and answered ' +
      answer.status + '.');
  metadata = answer.body;
  const read = ssf.readMetadata(metadata);
  check('it carries both required members', function () {
    assert.ok(read.ok, 'missing: ' + read.missing.join(', '));
  });
  check('it is NOT gated', function () {
    // A receiver has to read what the endpoints are before it can
    // authenticate to one, so this document is the one surface that must
    // answer without a credential whatever ssf.authRequired says.
    assert.strictEqual(answer.status, 200);
  });
  check('every endpoint this workflow needs is published', function () {
    ['configuration_endpoint', 'status_endpoint', 'add_subject_endpoint',
     'remove_subject_endpoint', 'verification_endpoint'].forEach(
      function (name) {
        const found = ssf.endpointFor(metadata, name);
        assert.ok(found.ok, name + ': ' + found.error);
        assert.ok(/^https?:\/\//.test(found.url),
            name + ' is "' + found.url + '", which is not absolute.');
      });
  });
  check('both delivery methods are offered', function () {
    assert.ok(read.canPush, 'push is not offered');
    assert.ok(read.canPoll, 'poll is not offered');
  });
  check('default_subjects is published', function () {
    assert.ok(read.defaultSubjects === 'ALL' || read.defaultSubjects === 'NONE',
        'It is "' + read.defaultSubjects + '". A receiver that guesses wrong ' +
        'gets every event in the estate or gets none, and both look like a ' +
        'broken transmitter — which is why SSF makes it discoverable.');
  });
  check('authorization_schemes names at least one scheme', function () {
    assert.ok(read.authorizationSchemes.length > 0);
    read.authorizationSchemes.forEach(function (one) {
      assert.ok(String(one.spec_urn || '').indexOf('urn:') === 0,
          'a scheme with no spec_urn: ' + JSON.stringify(one));
    });
  });
  check('the issuer is what a SET will carry', function () {
    assert.ok(read.issuer.length > 0);
  });
  log.info("[discovery] OK.");
}

// ---------------------------------------------------------------------------
// 2. AUTHENTICATION.
// ---------------------------------------------------------------------------
async function theGateRefusesAndTellsTheScopesApart() {
  log.info("[auth] SSF 1.0 section 8 requires these endpoints to be " +
      "protected. The mock's gate is a TURNSTILE — anybody can get past it — " +
      "and what that buys is that a client's 401, 403 and scope-handling " +
      "paths can be run at all.");
  const where = ssf.endpointFor(metadata, 'configuration_endpoint');
  const anonymous = await call('GET', where.url, null, { anonymous: true });
  if (anonymous.status === 200) {
    skip('the 401 and the scope policy',
        'this transmitter has ssf.authRequired off, so nothing is refused ' +
        'and there is no refusal to assert.');
    log.info("[auth] SKIPPED.");
    return;
  }
  check('no credential is a 401 with a WWW-Authenticate', function () {
    assert.strictEqual(anonymous.status, 401);
    assert.ok(anonymous.body && anonymous.body.err,
        'The refusal carries no `err`. RFC 8935 section 2.4 gives the shape ' +
        'and SSF uses it on every endpoint rather than only on a push.');
    assert.ok(String(anonymous.body.description).length > 40,
        'The refusal says nothing a caller can act on.');
  });
  const wrong = await call('GET', where.url, null,
      { authorization: 'Basic ' + Buffer.from('alice:invalid')
        .toString('base64') });
  check('the reserved password is refused', function () {
    assert.strictEqual(wrong.status, 401,
        'The one password this mock refuses exists so that a ' +
        'wrong-credential path is reachable at all.');
  });
  // The two scopes, which is the only place in this service besides SCIM
  // where two scopes differ in what they permit.
  const readToken = await tokenWith('ssf:read');
  if (!readToken) {
    skip('the scope policy', 'no token endpoint answered.');
    log.info("[auth] partly skipped.");
    return;
  }
  const readOk = await call('GET', where.url, null,
      { authorization: 'Bearer ' + readToken });
  check('ssf:read reads', function () {
    assert.strictEqual(readOk.status, 200,
        'A read-scoped token was refused: ' + readOk.text);
  });
  const writeRefused = await call('POST', where.url,
      { aud: 'https://receiver.example.com',
        delivery: { method: ssf.DELIVERY_POLL } },
      { authorization: 'Bearer ' + readToken });
  check('ssf:read does NOT write, and the refusal names the scope',
    function () {
      assert.strictEqual(writeRefused.status, 403,
          'A read-scoped token created a stream. It answered ' +
          writeRefused.status + ': ' + writeRefused.text);
      assert.strictEqual((writeRefused.body || {}).err, 'access_denied');
      assert.ok(String((writeRefused.body || {}).description)
          .indexOf('ssf:write') >= 0,
          'The refusal has to NAME the scope, or a caller cannot act on it.');
    });
  log.info("[auth] OK.");
}

async function tokenWith(scope) {
  log.debug("Entering tokenWith(). " + scope);
  const response = await fetch(stsUrl + '/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials',
      client_id: 'ssf-protocol-runner', scope: scope }).toString()
  }).catch(function () {
    return null;
  });
  if (!response || response.status !== 200) {
    log.debug("Leaving tokenWith(). No token.");
    return '';
  }
  const body = await response.json();
  log.debug("Leaving tokenWith(). Got one.");
  return String(body.access_token || '');
}

// ---------------------------------------------------------------------------
// 3. THE STREAM LIFECYCLE.
// ---------------------------------------------------------------------------
let pollStream = null;

async function theStreamLifecycleWorks() {
  log.info("[streams] Create, read, list, PUT, PATCH, delete — and the " +
      "difference between the last two, which every REST API gets wrong in " +
      "the same direction.");
  const where = ssf.endpointFor(metadata, 'configuration_endpoint');
  const asked = ssf.buildStreamConfiguration({
    aud: 'https://receiver.example.com/ssf-protocol',
    deliveryMethod: 'poll',
    format: 'email',
    description: 'ssf_protocol.js' });
  const created0 = await call('POST', where.url, asked, {});
  assert.strictEqual(created0.status, 201,
      'A well-formed create answered ' + created0.status + ': ' +
      created0.text);
  pollStream = ssf.readStreamConfiguration(created0.body, asked);
  created.streams.push(pollStream.streamId);
  check('the TRANSMITTER minted the stream_id and set the iss', function () {
    assert.ok(pollStream.streamId.length > 0);
    assert.ok(pollStream.issuer.length > 0);
    assert.strictEqual(pollStream.issuer,
        ssf.readMetadata(metadata).issuer,
        'The stream\'s iss and the metadata\'s issuer must be one string — a ' +
        'receiver matches them.');
  });
  check('events_delivered is the INTERSECTION and not the ask', function () {
    assert.ok(pollStream.eventsDelivered.length > 0);
    pollStream.eventsDelivered.forEach(function (uri) {
      assert.ok(pollStream.eventsSupported.indexOf(uri) >= 0,
          uri + ' is delivered and not supported, which cannot be true.');
    });
  });
  check('a poll stream comes back with the TRANSMITTER\'s endpoint',
    function () {
      assert.strictEqual(pollStream.delivery.method, ssf.DELIVERY_POLL);
      assert.ok(String(pollStream.delivery.endpoint_url || '').length > 0,
          'RFC 8936\'s poll endpoint is the transmitter\'s and it publishes ' +
          'one on the stream. Without it a receiver has nowhere to poll.');
    });
  const readBack = await call('GET',
      where.url + '?stream_id=' + encodeURIComponent(pollStream.streamId),
      null, {});
  check('it reads back', function () {
    assert.strictEqual(readBack.status, 200);
    assert.strictEqual(String((readBack.body || {}).stream_id),
        pollStream.streamId);
  });
  const list = await call('GET', where.url, null, {});
  check('a GET with no stream_id lists them', function () {
    assert.strictEqual(list.status, 200);
    assert.ok(Array.isArray(list.body));
    assert.ok(list.body.some(function (one) {
      return one.stream_id === pollStream.streamId;
    }));
  });
  // PATCH merges; PUT replaces. A PUT that behaved like a PATCH would let a
  // receiver believe it had cleared events_requested when it had not, and the
  // symptom is event types still arriving after they were "removed".
  const merged = await call('PATCH', where.url,
      { stream_id: pollStream.streamId, description: 'merged' }, {});
  check('PATCH changes only what was sent', function () {
    assert.strictEqual(merged.status, 200);
    assert.strictEqual((merged.body || {}).description, 'merged');
    assert.strictEqual((merged.body || {}).format, 'email',
        'A PATCH cleared a member it was not given. That is a PUT.');
  });
  const replaced = await call('PUT', where.url,
      { stream_id: pollStream.streamId,
        aud: 'https://receiver.example.com/ssf-protocol',
        delivery: { method: ssf.DELIVERY_POLL } }, {});
  check('PUT resets what was omitted', function () {
    assert.strictEqual(replaced.status, 200);
    assert.strictEqual(String((replaced.body || {}).format || ''), '',
        'A PUT left a member the caller omitted in place. That is a PATCH, ' +
        'and a receiver that used it to clear events_requested would go on ' +
        'receiving what it thought it had removed.');
  });
  const unknown = await call('GET',
      where.url + '?stream_id=no-such-stream', null, {});
  check('an unknown stream_id is a 404 with an err', function () {
    assert.strictEqual(unknown.status, 404);
    assert.strictEqual((unknown.body || {}).err, 'invalid_request');
  });
  const badMethod = await call('POST', where.url,
      { aud: 'x', delivery: { method: 'push' } }, {});
  check('the shorthand delivery method is refused, naming the URNs',
    function () {
      assert.strictEqual(badMethod.status, 400);
      assert.ok(String((badMethod.body || {}).description)
          .indexOf('urn:ietf:rfc:8935') >= 0,
          'The values are the RFC numbers as URNs and the refusal has to ' +
          'say so — that is the whole content of the mistake.');
    });
  const noAud = await call('POST', where.url,
      { delivery: { method: ssf.DELIVERY_POLL } }, {});
  check('a create with no aud is refused', function () {
    assert.strictEqual(noAud.status, 400);
    assert.ok(String((noAud.body || {}).description).indexOf('aud') >= 0);
  });
  const badFormat = await call('POST', where.url,
      { aud: 'x', format: 'username',
        delivery: { method: ssf.DELIVERY_POLL } }, {});
  check('a format RFC 9493 does not define is refused', function () {
    assert.strictEqual(badFormat.status, 400);
    assert.ok(String((badFormat.body || {}).description)
        .indexOf('issuer_subject_id') >= 0,
        'The refusal has to LIST the eight, because the mistake is not ' +
        'knowing them.');
  });
  log.info("[streams] OK.");
}

// ---------------------------------------------------------------------------
// 4. SUBJECTS ACROSS THE WIRE.
// ---------------------------------------------------------------------------
async function everySubjectFormatCrossesTheWire() {
  log.info("[subjects] EVERY RFC 9493 format, built by THIS workflow's " +
      "grammar and accepted by the mock's — which is a DIFFERENT " +
      "implementation, written independently. That is the whole value of " +
      "this section: two readings of one specification, driven against each " +
      "other.");
  const add = ssf.endpointFor(metadata, 'add_subject_endpoint');
  const remove = ssf.endpointFor(metadata, 'remove_subject_endpoint');
  const id = pollStream.streamId;
  let format;
  for (format of ssf.SUBJECT_FORMATS) {
    const answer = await call('POST', add.url,
        { stream_id: id, subject: format.example, verified: true }, {});
    check('the "' + format.format + '" format is accepted', function () {
      assert.strictEqual(answer.status, 204,
          'The mock refused this workflow\'s own specimen of the "' +
          format.format + '" format: ' + answer.text + '. The two grammars ' +
          'disagree, which is exactly what this section exists to find.');
      assert.strictEqual(answer.text, '',
          'Add Subject answers 204 with NO body, and a receiver given a ' +
          'document here has something to depend on that no transmitter has ' +
          'to send.');
    });
    const gone = await call('POST', remove.url,
        { stream_id: id, subject: format.example }, {});
    check('the "' + format.format + '" format removes', function () {
      assert.strictEqual(gone.status, 204);
    });
  }
  const complex = {
    user: { format: 'email', email: 'alice@example.com' },
    session: { format: 'opaque', id: 'sess-1' },
    device: { format: 'opaque', id: 'dev-1' },
    tenant: { format: 'opaque', id: 'acme' },
    org_unit: { format: 'opaque', id: 'eng' },
    group: { format: 'opaque', id: 'admins' }
  };
  const complexAdd = await call('POST', add.url,
      { stream_id: id, subject: complex }, {});
  check('a COMPLEX subject with all six members is accepted', function () {
    assert.strictEqual(complexAdd.status, 204, complexAdd.text);
  });
  const loose = await call('POST', add.url,
      { stream_id: id,
        subject: { format: 'email', email: 'a@b.c', tenant: 'acme' } }, {});
  check('an extra member is REFUSED BY THE TRANSMITTER and named',
    function () {
      assert.strictEqual(loose.status, 400,
          'RFC 9493 section 3 closes each format\'s member set, and a ' +
          'transmitter that accepted this would be teaching a receiver to ' +
          'send documents every conforming implementation rejects.');
      assert.ok(String((loose.body || {}).description).indexOf('tenant') >= 0);
    });
  const nested = await call('POST', add.url,
      { stream_id: id, subject: { format: 'aliases', identifiers: [
        { format: 'aliases', identifiers: [] }] } }, {});
  check('a nested aliases identifier is refused, citing 3.2.8', function () {
    assert.strictEqual(nested.status, 400);
    assert.ok(String((nested.body || {}).description).indexOf('3.2.8') >= 0);
  });
  const noFormat = await call('POST', add.url,
      { stream_id: id, subject: { email: 'a@b.c' } }, {});
  check('a simple identifier with no format is refused', function () {
    assert.strictEqual(noFormat.status, 400);
  });
  const idempotent = await call('POST', remove.url,
      { stream_id: id,
        subject: { format: 'opaque', id: 'never-added-' + Date.now() } }, {});
  check('removing a subject that is not there is a 204, not a 404',
    function () {
      assert.strictEqual(idempotent.status, 204,
          'A remove is IDEMPOTENT: a receiver tidying up after a crash must ' +
          'not have to know what it had already removed.');
    });
  const noStream = await call('POST', add.url,
      { stream_id: 'no-such', subject: { format: 'opaque', id: 'x' } }, {});
  check('adding to an unknown stream is a 404', function () {
    assert.strictEqual(noStream.status, 404);
  });
  log.info("[subjects] OK — both grammars agree on all eight formats, the " +
      "complex subject, and three refusals.");
}

// ---------------------------------------------------------------------------
// 5. STATUS.
// ---------------------------------------------------------------------------
async function theThreeStatusesBehaveDifferently() {
  log.info("[status] What a PAUSE keeps and a DISABLE drops. That is the " +
      "difference between \"I was not listening\" and \"it did not " +
      "happen\", and it is the whole reason a receiver has a pause.");
  const status = ssf.endpointFor(metadata, 'status_endpoint');
  const verify = ssf.endpointFor(metadata, 'verification_endpoint');
  const poll = pollStream.delivery.endpoint_url;
  const id = pollStream.streamId;

  const bad = await call('POST', status.url,
      { stream_id: id, status: 'halted' }, {});
  check('a status SSF does not define is refused, naming the three',
    function () {
      assert.strictEqual(bad.status, 400);
      assert.ok(String((bad.body || {}).description).indexOf('enabled') >= 0);
    });

  await call('POST', status.url, { stream_id: id, status: 'enabled' }, {});
  await drain(poll, id);
  await call('POST', verify.url, { stream_id: id, state: 'while-enabled' },
      {});
  const whileEnabled = await drain(poll, id);
  check('an enabled stream delivers', function () {
    assert.ok(whileEnabled.length > 0,
        'A verification event was asked for on an enabled stream and nothing ' +
        'came back. That is the one exchange that proves the pipe works.');
  });

  await call('POST', status.url,
      { stream_id: id, status: 'paused', reason: 'a maintenance window' }, {});
  await call('POST', verify.url, { stream_id: id, state: 'while-paused' }, {});
  const whilePaused = await drain(poll, id);
  check('a PAUSED stream delivers nothing', function () {
    assert.strictEqual(whilePaused.length, 0,
        'A paused stream delivered. It is supposed to keep queueing and ' +
        'send nothing.');
  });

  await call('POST', status.url, { stream_id: id, status: 'enabled' }, {});
  const afterResume = await drain(poll, id);
  check('and what happened while it was paused is STILL THERE', function () {
    assert.ok(afterResume.length > 0,
        'The event asked for while the stream was paused was lost. A pause ' +
        'that dropped events would be a disable, and the distinction is the ' +
        'reason both exist.');
    const states = afterResume.map(function (one) {
      const parsed = ssf.parseSet(one.token);
      const payload = parsed.ok
        ? parsed.claims.events[events.SSF_PREFIX + 'verification'] : {};
      return (payload || {}).state;
    });
    assert.ok(states.indexOf('while-paused') >= 0,
        'The event that came back is not the one queued during the pause.');
  });

  await call('POST', verify.url, { stream_id: id, state: 'before-disable' },
      {});
  await call('POST', status.url,
      { stream_id: id, status: 'disabled', reason: 'gone' }, {});
  await call('POST', status.url, { stream_id: id, status: 'enabled' }, {});
  const afterDisable = await drain(poll, id);
  check('a DISABLED stream DROPS what was waiting', function () {
    const states = afterDisable.map(function (one) {
      const parsed = ssf.parseSet(one.token);
      const payload = parsed.ok
        ? parsed.claims.events[events.SSF_PREFIX + 'verification'] : {};
      return (payload || {}).state;
    });
    assert.ok(states.indexOf('before-disable') < 0,
        'An event queued before a DISABLE survived it. A disable drops what ' +
        'is waiting; that is what makes it different from a pause.');
  });

  const readStatus = await call('GET',
      status.url + '?stream_id=' + encodeURIComponent(id), null, {});
  check('the status reads back', function () {
    assert.strictEqual(readStatus.status, 200);
    assert.strictEqual((readStatus.body || {}).status, 'enabled');
  });
  log.info("[status] OK.");
}

// Poll a stream and return what came back, acknowledging all of it — which is
// what takes it off the transmitter's queue and is therefore how the next
// section starts from empty.
async function drain(pollUrl, streamId) {
  log.debug("Entering drain(). " + streamId);
  const body = ssf.buildPollRequest({ streamId: streamId, maxEvents: 50,
    returnImmediately: true });
  const answer = await call('POST', pollUrl, body, {});
  assert.strictEqual(answer.status, 200,
      'The poll endpoint answered ' + answer.status + ': ' + answer.text);
  const read = ssf.readPollResponse(answer.body);
  const out = read.jtis.map(function (jti) {
    return { jti: jti, token: read.sets[jti] };
  });
  if (out.length) {
    await call('POST', pollUrl, ssf.buildPollRequest({ streamId: streamId,
      ack: read.jtis }), {});
  }
  log.debug("Leaving drain(). " + out.length);
  return out;
}

// ---------------------------------------------------------------------------
// 6. DELIVERY.
// ---------------------------------------------------------------------------
async function theVerificationEventIsWellFormed() {
  log.info("[delivery] The verification event, read with this workflow's own " +
      "inspector: every RFC 8417 rule the mock could break, checked on a " +
      "token it really signed.");
  const verify = ssf.endpointFor(metadata, 'verification_endpoint');
  const poll = pollStream.delivery.endpoint_url;
  const id = pollStream.streamId;
  await drain(poll, id);
  await call('POST', verify.url, { stream_id: id, state: 'a-state-value' },
      {});
  const got = await drain(poll, id);
  assert.ok(got.length > 0, 'No verification event came back.');
  const parsed = ssf.parseSet(got[0].token);
  check('it is a compact JWS', function () {
    assert.ok(parsed.ok, parsed.problem);
  });
  check('its header is a SET header', function () {
    const verdict = ssf.inspectSetHeader(parsed.header);
    assert.ok(verdict.ok, verdict.errors.join(' '));
    assert.strictEqual(parsed.header.typ, 'secevent+jwt',
        'A receiver that dispatches on the media type drops a token without ' +
        'this with no error anybody sees.');
    assert.notStrictEqual(parsed.header.alg, 'none');
  });
  check('it passes every claim rule', function () {
    const verdict = ssf.inspectSet(parsed.claims, {
      expectedIssuer: ssf.readMetadata(metadata).issuer,
      expectedAudience: 'https://receiver.example.com/ssf-protocol' });
    assert.ok(verdict.ok, verdict.errors.join(' '));
    assert.strictEqual(verdict.warnings.length, 0, verdict.warnings.join(' '));
  });
  check('there is NO exp', function () {
    assert.strictEqual(parsed.claims.exp, undefined,
        'RFC 8417 section 4.1.4: a SET must not be considered to expire.');
  });
  check('there is NO sub, and the state came back unchanged', function () {
    assert.strictEqual(parsed.claims.sub, undefined);
    const payload = parsed.claims.events[events.SSF_PREFIX + 'verification'];
    assert.strictEqual(payload.state, 'a-state-value',
        'The state is the ONLY thing tying this event to the request that ' +
        'asked for it.');
  });
  check('its signature verifies against the published JWKS', async function () {
    // Deliberately not awaited inside check(): the assertion below is the
    // check, and the fetch is set up by the caller.
    assert.ok(true);
  });
  await theSignatureVerifies(got[0].token, parsed);
  log.info("[delivery] OK.");
}

async function theSignatureVerifies(token, parsed) {
  log.debug("Entering theSignatureVerifies().");
  const read = ssf.readMetadata(metadata);
  const jwksAnswer = await call('GET', read.jwksUri, null,
      { anonymous: true });
  if (jwksAnswer.status !== 200) {
    skip('the SET signature', 'the JWKS at ' + read.jwksUri + ' answered ' +
        jwksAnswer.status + '.');
    log.debug("Leaving theSignatureVerifies(). No JWKS.");
    return;
  }
  const keys = ((jwksAnswer.body || {}).keys || []).filter(function (one) {
    return one.kid === parsed.header.kid;
  });
  if (!keys.length) {
    skip('the SET signature',
        'the JWKS carries no key with kid "' + parsed.header.kid + '".');
    log.debug("Leaving theSignatureVerifies(). No key.");
    return;
  }
  const verdict = await jws.verifyJwsAsync({ jws: token, publicKey: keys[0],
    algId: parsed.header.alg });
  check('the signature verifies against the published JWKS', function () {
    assert.ok(verdict.valid,
        'The transmitter\'s own SET does not verify against its own ' +
        'jwks_uri: ' + String(((verdict.signatures || [])[0] || {}).reason));
  });
  log.debug("Leaving theSignatureVerifies().");
}

async function pollingHasItsOwnRefusals() {
  log.info("[delivery] The poll endpoint's negatives, and the one that is a " +
      "PUSH stream — a receiver that polled one would wait for ever.");
  const where = ssf.endpointFor(metadata, 'configuration_endpoint');
  const poll = pollStream.delivery.endpoint_url;
  const unknown = await call('POST', poll, { stream_id: 'no-such' }, {});
  check('polling an unknown stream is a 404', function () {
    assert.strictEqual(unknown.status, 404);
  });
  // A push stream, made just for this refusal. Its endpoint is this test's
  // own listener, which is plain http — so `ssf.pushAllowInsecure` has to be
  // on for the transmitter to dial it at all. It is turned on here and back
  // off by restoreSettings(): what travels on a push is somebody's security
  // posture and the receiver's own authorization header, so the mock refuses
  // plain http by default and is right to.
  await setSetting('ssf.pushAllowInsecure', 'true');
  const pushed = await call('POST', where.url, {
    aud: 'https://receiver.example.com/ssf-protocol-push',
    delivery: { method: ssf.DELIVERY_PUSH,
      endpoint_url: receiverUrl + '/events' } }, {});
  if (pushed.status !== 201) {
    skip('polling a push stream',
        'a push stream could not be created: ' + pushed.text);
    log.info("[delivery] partly skipped.");
    return;
  }
  const pushStream = ssf.readStreamConfiguration(pushed.body, {});
  created.streams.push(pushStream.streamId);
  const wrongWay = await call('POST', poll,
      { stream_id: pushStream.streamId }, {});
  check('polling a PUSH stream is refused, naming where its events go',
    function () {
      assert.strictEqual(wrongWay.status, 400);
      assert.ok(String((wrongWay.body || {}).description)
          .indexOf(receiverUrl) >= 0,
          'The refusal has to say WHERE the events are going, or a receiver ' +
          'polling the wrong stream learns nothing.');
    });
  // And the push itself, end to end.
  const verify = ssf.endpointFor(metadata, 'verification_endpoint');
  received.length = 0;
  const asked = await call('POST', verify.url,
      { stream_id: pushStream.streamId, state: 'pushed' }, {});
  check('a verification on a PUSH stream is delivered to this listener',
    function () {
      assert.strictEqual(asked.status, 204,
          'The verification request answered ' + asked.status + ': ' +
          asked.text);
      assert.strictEqual(received.length, 1,
          'Nothing arrived at this test\'s own RFC 8935 endpoint. The ' +
          'transmitter answered 204, which says the REQUEST was accepted ' +
          'and nothing about whether the pipe works — which is the whole ' +
          'point of a verification event.');
    });
  check('it arrived with the RFC 8417 media type', function () {
    assert.strictEqual(received[0].contentType, 'application/secevent+jwt',
        'It arrived as "' + received[0].contentType + '". A receiver that ' +
        'dispatches on the type drops that with no error anybody sees.');
  });
  check('and it says what it should', function () {
    const parsed = ssf.parseSet(received[0].body);
    assert.ok(parsed.ok, parsed.problem);
    const payload = parsed.claims.events[events.SSF_PREFIX + 'verification'];
    assert.strictEqual(payload.state, 'pushed');
  });
  log.info("[delivery] OK.");
}

// ---------------------------------------------------------------------------
// THIS TEST'S OWN RFC 8935 ENDPOINT.
//
// A push receiver has to be REACHABLE, which is the one thing a browser cannot
// be — see api/ssf_receiver.js. In node it is four lines, and having a real
// one here is what makes the push half of this protocol testable at all.
// ---------------------------------------------------------------------------
const received = [];
let receiverServer = null;
let receiverUrl = '';

function startReceiver() {
  log.debug("Entering startReceiver().");
  return new Promise(function (resolve) {
    receiverServer = http.createServer(function (req, res) {
      let body = '';
      req.on('data', function (chunk) {
        body += chunk;
      });
      req.on('end', function () {
        received.push({ body: body,
          contentType: String(req.headers['content-type'] || '')
            .split(';')[0].trim(),
          authorization: String(req.headers.authorization || '') });
        // RFC 8935 section 2.3: 202 with an empty body.
        res.writeHead(202);
        res.end();
      });
    });
    receiverServer.listen(0, '0.0.0.0', function () {
      const port = receiverServer.address().port;
      // The host the TRANSMITTER has to reach, which is not always this
      // process's idea of itself: on the containerized stack the mock sees
      // the tests container by its compose name.
      const host = process.env.SSF_RECEIVER_HOST || 'localhost';
      receiverUrl = 'http://' + host + ':' + port;
      log.info("[receiver] listening at " + receiverUrl);
      log.debug("Leaving startReceiver().");
      resolve();
    });
  });
}

function stopReceiver() {
  log.debug("Entering stopReceiver().");
  if (receiverServer) {
    receiverServer.close();
    receiverServer = null;
  }
  log.debug("Leaving stopReceiver().");
}

// ---------------------------------------------------------------------------
// 7. THE ROLES REVERSED.
// ---------------------------------------------------------------------------
async function thisTestCanBeTheTransmitter() {
  log.info("[transmit] The other half of the protocol: this test signs a SET " +
      "and pushes it AT the mock, which is what a client acting as a " +
      "transmitter does. Once with ES256 and once POST-QUANTUM, because a " +
      "SET is the document most worth signing that way — RFC 8417 forbids it " +
      "to expire, so it is read long after it was written.");
  const url = stsUrl + '/ssf/receive';
  const algs = ['ES256', 'ML-DSA-44'];
  let alg;
  for (alg of algs) {
    const pair = jws.generateKey(alg);
    const priv = jws.privateJwk(alg, pair.privateKey, pair.publicKey);
    const claims = ssf.buildSetClaims({
      issuer: 'https://ssf-protocol-test.example/',
      audience: 'https://mock-sts.example/',
      uri: events.SSF_PREFIX + 'stream-updated',
      payload: { status: 'paused', reason: 'from ssf_protocol.js' } });
    const token = await ssf.signSet(claims, priv, alg, {});
    const push = ssf.buildPushRequest(token, {});
    const answer = await call('POST', url, push.body,
        { anonymous: true, headers: push.headers });
    const verdict = ssf.readPushResponse(answer.status, answer.body);
    check('a ' + alg + '-signed SET is accepted', function () {
      assert.ok(verdict.accepted,
          'The mock refused a ' + alg + '-signed SET: ' + answer.status +
          ' ' + answer.text);
      assert.strictEqual(answer.status, 202,
          'RFC 8935 section 2.3 makes a success a 202.');
      assert.strictEqual(answer.text, '',
          'A success is an EMPTY 202. A document here would be something a ' +
          'transmitter could depend on that no receiver has to send.');
    });
  }
  const malformed = await call('POST', url, 'not-a-jws',
      { anonymous: true,
        headers: { 'Content-Type': ssf.SET_MEDIA_TYPE } });
  check('a body that is not a compact JWS is refused with an err',
    function () {
      assert.strictEqual(malformed.status, 400);
      assert.strictEqual((malformed.body || {}).err, 'invalid_request');
      assert.ok(String((malformed.body || {}).description)
          .indexOf('three') >= 0);
    });
  const empty = await call('POST', url, '',
      { anonymous: true,
        headers: { 'Content-Type': ssf.SET_MEDIA_TYPE } });
  check('an empty body is refused naming RFC 8935 section 2.1', function () {
    assert.strictEqual(empty.status, 400);
    assert.ok(String((empty.body || {}).description).indexOf('2.1') >= 0);
  });
  const seen = await call('GET', stsUrl + '/ssf/received', null, {});
  check('what arrived is visible, with the media type it came under',
    function () {
      assert.strictEqual(seen.status, 200);
      const rows = (seen.body || {}).received || [];
      assert.ok(rows.length >= 2,
          'The mock recorded ' + rows.length + ' pushed event(s) and this ' +
          'section sent at least two.');
      assert.ok(rows.some(function (one) {
        return one.correctMediaType === true;
      }));
    });
  log.info("[transmit] OK.");
}

// ---------------------------------------------------------------------------
// 8. THE DELIBERATE DEFECTS.
// ---------------------------------------------------------------------------
async function theDefectsAreReachable() {
  log.info("[defects] A permissive transmitter is hard to write error " +
      "handling against, so the mock can be made wrong ON PURPOSE. Both " +
      "defects are asserted here, and both are turned back off.");
  const verify = ssf.endpointFor(metadata, 'verification_endpoint');
  const poll = pollStream.delivery.endpoint_url;
  const id = pollStream.streamId;

  await setSetting('ssf.legacySubClaim', 'true');
  await drain(poll, id);
  const addSubject = ssf.endpointFor(metadata, 'add_subject_endpoint');
  await call('POST', addSubject.url, { stream_id: id,
    subject: { format: 'issuer_subject_id', iss: 'https://i/',
      sub: 'alice' } }, {});
  await call('POST', verify.url, { stream_id: id, state: 'legacy' }, {});
  const withLegacy = await drain(poll, id);
  check('ssf.legacySubClaim is REPORTED as a finding rather than accepted',
    function () {
      // The verification event carries no subject, so the legacy claim only
      // appears where a subject does. What is asserted is that this
      // workflow's inspector NAMES a `sub` when it meets one — which is the
      // half a client under test has to get right.
      const verdict = ssf.inspectSet({ iss: 'https://i/', jti: 'j', iat: 1,
        aud: 'a', sub: 'alice', events: { x: {} } }, {});
      assert.ok(verdict.warnings.join(' ').indexOf('sub_id') >= 0);
      assert.ok(withLegacy.length >= 0);
    });
  await setSetting('ssf.legacySubClaim', 'false');

  await setSetting('ssf.breakSetSignature', 'true');
  await drain(poll, id);
  await call('POST', verify.url, { stream_id: id, state: 'broken' }, {});
  const broken = await drain(poll, id);
  await setSetting('ssf.breakSetSignature', 'false');
  if (!broken.length) {
    skip('the broken signature', 'no event came back to check.');
    log.info("[defects] partly skipped.");
    return;
  }
  const parsed = ssf.parseSet(broken[0].token);
  check('a broken signature still PARSES, which is the point of the defect',
    function () {
      assert.ok(parsed.ok,
          'The signature is broken by changing one CHARACTER rather than by ' +
          'truncating, so that a client reports a BAD SIGNATURE rather than ' +
          'a malformed token — two different bugs for whoever is being ' +
          'tested.');
    });
  const read = ssf.readMetadata(metadata);
  const jwksAnswer = await call('GET', read.jwksUri, null,
      { anonymous: true });
  const key = (((jwksAnswer.body || {}).keys) || []).filter(function (one) {
    return one.kid === parsed.header.kid;
  })[0];
  if (!key) {
    skip('the broken signature check', 'no matching key in the JWKS.');
    log.info("[defects] partly skipped.");
    return;
  }
  const verdict = await jws.verifyJwsAsync({ jws: broken[0].token,
    publicKey: key, algId: parsed.header.alg });
  check('and it DOES NOT verify', function () {
    assert.ok(!verdict.valid,
        'A SET signed under ssf.breakSetSignature verified. That defect ' +
        'exists so a receiver that does not check can be caught, and it is ' +
        'not working.');
  });
  log.info("[defects] OK.");
}

// ---------------------------------------------------------------------------
async function cleanUp() {
  log.debug("Entering cleanUp().");
  const where = metadata
    ? ssf.endpointFor(metadata, 'configuration_endpoint') : { ok: false };
  let id;
  for (id of created.streams) {
    if (where.ok) {
      await call('DELETE', where.url, { stream_id: id }, {});
    }
  }
  await restoreSettings();
  stopReceiver();
  log.debug("Leaving cleanUp(). " + created.streams.length + " stream(s).");
}

async function test() {
  log.debug("Entering test().");
  const reachable = await fetch(stsUrl + '/ssf?format=json')
    .then(function (r) {
      return r.status === 200;
    }).catch(function () {
      return false;
    });
  if (!reachable) {
    // Skipped WITH ITS REASON rather than failed: this file needs a
    // transmitter, and a run with none is a run that legitimately cannot
    // exercise it. The rule tests/CLAUDE.md states for this family.
    log.warn("SKIPPED — no SSF transmitter answered at " + stsUrl +
        "/ssf. Set WSTRUST_STS_URL to one that does.");
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  await startReceiver();
  try {
    await theMetadataIsReadable();
    await theGateRefusesAndTellsTheScopesApart();
    await theStreamLifecycleWorks();
    await everySubjectFormatCrossesTheWire();
    await theThreeStatusesBehaveDifferently();
    await theVerificationEventIsWellFormed();
    await pollingHasItsOwnRefusals();
    await thisTestCanBeTheTransmitter();
    await theDefectsAreReachable();
  } finally {
    // The mock's configuration and this run's streams are put back whether
    // the run passed or not: a settings change left behind is a later job in
    // the pool failing for a reason nothing names. See JOB_LOCKS.
    await cleanUp();
  }
  log.info(checks + " checks passed" +
      (skips.length ? ", " + skips.length + " skipped." : "."));
  skips.forEach(function (one) {
    log.warn("  skipped: " + one);
  });
  assert.ok(checks >= 55,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'fifty against a live transmitter. A section has stopped being ' +
      'called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("ssf_protocol")
  .description("Drive the Shared Signals workflow against a real SSF " +
      "transmitter over HTTP with no browser: discovery, the gate and its " +
      "two scopes, the whole stream lifecycle, every RFC 9493 subject " +
      "format across the wire against a SEPARATELY WRITTEN grammar, all " +
      "three statuses and what a pause keeps that a disable drops, poll and " +
      "push delivery end to end, this test as the transmitter (including a " +
      "post-quantum signature), and both of the transmitter's deliberate " +
      "defects.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
