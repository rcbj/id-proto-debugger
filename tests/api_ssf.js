// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_ssf.js
//
// ---------------------------------------------------------------------------
// THE api's SHARED SIGNALS SURFACE, OVER HTTP.
//
// `ssf_engine.js` drives `api/ssf_proxy.js` and `api/ssf_receiver.js` as
// MODULES — every refusal, every cap, every bound — and it can say nothing
// about the wiring around them. This file is the wiring, and there are four
// things in it that no module test can see:
//
//   1. **THE BODY PARSER.** A Security Event Token arrives as
//      `application/secevent+jwt` (RFC 8417 section 2.3), which neither
//      `bodyParser.json()` nor `bodyParser.urlencoded()` touches. Without the
//      text parser `api/server.js` installs for exactly that type, `req.body`
//      on `POST /ssf/receiver/:id` is an EMPTY OBJECT and every push is
//      reported as an empty body — a failure that looks like a transmitter
//      sending nothing.
//   2. **THE THREE OUTCOMES**, as HTTP statuses rather than as return values:
//      a refusal by the api is a 400, a network failure is a 502, and an SSF
//      error from the transmitter is a **200** carrying that status and its
//      `{err, description}`. The third is the one that matters — a 403 naming
//      a scope, a 400 naming the member of a subject identifier RFC 9493 does
//      not define — and an endpoint that reported those as failures would
//      throw away the most useful thing this workflow can show.
//   3. **THE ADDRESS POLICY**, which is `api/ssrf_guard.js` installed once on
//      the shared axios instance. It is NOT re-implemented in the SSF proxy
//      and this file is where "and it still applies" is asserted.
//   4. **THE RECEIVER'S ANSWER TO A TRANSMITTER**, which is RFC 8935's rather
//      than this api's usual shape: 202 with an EMPTY body on success, 400
//      with `{err, description}` on a refusal.
//
// It needs the api and nothing else — no browser, no transmitter, no mock —
// because every call either refuses before the network or is aimed at the
// api's own receiver. It SKIPS with a reason when there is no api.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
const { mustBeAbleTo } = require("./expectation.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_ssf",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const jws = paths.requireSharedModule(
  [__dirname + "/../client/src/jws.js", __dirname + "/jws.js"], "jws.js");

var apiUrl = process.env.API_URL || "https://localhost:4000";

let checks = 0;
let skips = [];
const madeInboxes = [];

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

async function json(method, path, body, headers) {
  log.debug("Entering json(). " + method + " " + path);
  const init = { method: method,
    headers: Object.assign({}, headers || {}) };
  if (body !== undefined && body !== null) {
    if (!init.headers['Content-Type']) {
      init.headers['Content-Type'] = 'application/json';
    }
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const response = await fetch(apiUrl + path, init);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (e) {
      // Not JSON. Kept as text: an HTML error page from something in front of
      // the api is exactly the case where the body is the only evidence.
      payload = null;
    }
  }
  log.debug("Leaving json(). " + response.status);
  return { status: response.status, body: payload, text: text };
}

// ---------------------------------------------------------------------------
// 1. WHAT THE api SAYS IT WILL DO.
// ---------------------------------------------------------------------------
let limits = null;

async function theLimitsDocumentIsPublished() {
  log.info("[limits] GET /ssf/limits — the page reads it to decide whether " +
      "to offer the api call path at all, and whether push delivery is " +
      "available. A static deployment gets no answer here, which is a " +
      "stronger signal than a configuration flag because it is the api " +
      "itself saying so.");
  const answer = await json('GET', '/ssf/limits');
  assert.strictEqual(answer.status, 200,
      'GET /ssf/limits answered ' + answer.status + '.');
  limits = answer.body;
  check('it names the five methods', function () {
    assert.deepStrictEqual(limits.methods,
        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
  });
  check('it names the refused headers', function () {
    assert.ok(limits.refusedHeaders.indexOf('host') >= 0);
    assert.ok(limits.refusedHeaders.indexOf('transfer-encoding') >= 0);
    Object.keys(limits.refusedHeaderReasons).forEach(function (name) {
      assert.ok(String(limits.refusedHeaderReasons[name]).length > 20,
          name + ' is refused with no reason given.');
    });
  });
  check('it states the three-outcome rule', function () {
    assert.ok(limits.statusRule.indexOf('400') >= 0);
    assert.ok(limits.statusRule.indexOf('502') >= 0);
    assert.ok(limits.statusRule.indexOf('200') >= 0);
  });
  check('it states the one asymmetry a page cannot discover', function () {
    assert.ok(limits.deliveryFromTheBrowser.indexOf('8936') >= 0);
    assert.ok(limits.deliveryFromTheBrowser.indexOf('8935') >= 0,
        'Poll delivery works from a browser and push does not, and that is ' +
        'the specifications rather than this service — so the api has to ' +
        'publish it.');
  });
  check('it says whether it will host a receiver', function () {
    assert.ok(limits.receiver);
    assert.strictEqual(typeof limits.receiver.enabled, 'boolean');
    assert.strictEqual(limits.receiver.verifies, false,
        'It holds no key of the transmitter\'s, so a receiver that refused ' +
        'what it could not verify would be unable to show anybody WHY.');
  });
  check('the caps are numbers a page can act on', function () {
    assert.ok(limits.maxRequestBytes > 0);
    assert.ok(limits.callTimeoutMs > 0);
  });
  check('it says whether the ADDRESS layers of the guard are switched on',
    function () {
      assert.strictEqual(typeof limits.addressPolicyEnabled, 'boolean',
          'A sentence describing the policy is not the same as saying ' +
          'whether it is in force, and a caller cannot tell the two apart ' +
          'from a call that went through.');
    });
  log.info("[limits] OK.");
}

// ---------------------------------------------------------------------------
// 2. THE PROXY'S REFUSALS, AS 400s.
// ---------------------------------------------------------------------------
async function theProxyRefusesBeforeTheNetwork() {
  log.info("[proxy] Every refusal is a 400 from the api and never a status " +
      "from somebody else. The module test asserts the sentences; this " +
      "asserts the STATUS, which is what a page branches on.");
  const cases = [
    ['no url', {}, 'url is required'],
    ['a relative url', { url: '/ssf/stream' }, 'absolute'],
    ['a file: url', { url: 'file:///etc/passwd' }, 'absolute'],
    ['a data: url', { url: 'data:text/plain,hello' }, 'absolute'],
    ['a method that is not one of the five',
      { url: 'https://example.invalid/x', method: 'TRACE' }, 'method'],
    ['the Host header',
      { url: 'https://example.invalid/x', headers: { Host: 'elsewhere' } },
      'Host'],
    ['the Transfer-Encoding header',
      { url: 'https://example.invalid/x',
        headers: { 'Transfer-Encoding': 'chunked' } }, 'Transfer-Encoding'],
    ['a header value carrying CRLF',
      { url: 'https://example.invalid/x',
        headers: { 'X-A': 'a\r\nX-B: b' } }, 'injection'],
    ['a body on a GET',
      { url: 'https://example.invalid/x', method: 'GET', body: { a: 1 } },
      'silently discarded']
  ];
  let one;
  for (one of cases) {
    const answer = await json('POST', '/ssf/call', one[1]);
    check(one[0] + ' is a 400 naming the reason', function () {
      assert.strictEqual(answer.status, 400,
          one[0] + ' answered ' + answer.status + ': ' + answer.text);
      assert.ok(String((answer.body || {}).error).indexOf(one[2]) >= 0,
          'The refusal does not mention "' + one[2] + '": ' + answer.text);
    });
  }
  // A DELETE with a body is ALLOWED here and refused by the SCIM proxy, and
  // the difference is the protocol: SSF's stream management API is ONE PATH
  // with five methods, and a DELETE names the stream it is deleting in a JSON
  // body. It is asserted as a NON-refusal, which means it reaches the
  // network and fails there — a 502, not a 400.
  const deleteWithBody = await json('POST', '/ssf/call', {
    url: 'https://ssf-nothing-here.invalid/stream', method: 'DELETE',
    body: { stream_id: 's1' } });
  check('a DELETE with a body is NOT refused (unlike the SCIM proxy)',
    function () {
      assert.strictEqual(deleteWithBody.status, 502,
          'It answered ' + deleteWithBody.status + '. A 400 would mean the ' +
          'api refused to send it, which would make an SSF stream delete ' +
          'unreachable through this endpoint.');
    });
  log.info("[proxy] OK.");
}

async function theAddressPolicyStillApplies() {
  log.info("[proxy] api/ssrf_guard.js is installed ONCE on the shared axios " +
      "instance and is deliberately NOT re-implemented in the SSF proxy. " +
      "This is where \"and it still covers this endpoint\" is asserted.");

  // THE ADDRESS LAYERS. Every configuration this suite runs against turns it
  // OFF — on a compose network the mock STS and the identity provider ARE
  // private addresses — so asserting a refusal here would be asserting
  // something the deployment did not ask for. It was worse than useless
  // before 2026-09-01: with the guard off, `http://127.0.0.1:1` and
  // `http://169.254.169.254` merely FAIL TO CONNECT, which is a 502, and a
  // 502 satisfied the assertion. That made both checks a test of the local
  // network rather than of the guard — and on a cloud runner it stopped even
  // being that, because 169.254.169.254 is the instance metadata service and
  // it ANSWERS: run 658 of the Selenium Tests workflow failed here with a 200
  // carrying an IIS 404 from Azure's IMDS, on a machine where nothing about
  // this repository had changed.
  //
  // So the api now publishes which state it is in, and this asserts the one
  // that is true. tests/api_ssrf_guard.js is where the refusals themselves
  // live: it drives the guard module directly, with a policy of its own, and
  // needs no network at all.
  if (!limits.addressPolicyEnabled) {
    skip('the address layers refuse loopback and cloud metadata',
        'this api has blockPrivateNetworkCalls off, because on this network ' +
        'the mock STS and the identity provider ARE private addresses. ' +
        'tests/api_ssrf_guard.js drives those layers directly.');
    check('the api SAYS the address layers are off, rather than leaving a ' +
        'caller to infer it from a call that went through', function () {
      assert.strictEqual(limits.addressPolicyEnabled, false);
      assert.ok(String(limits.addressPolicy).indexOf('ssrf_guard') >= 0,
          'and it still names the module the policy lives in.');
    });
    log.info("[proxy] OK.");
    return;
  }

  // A blocked address is a 502 and not a 400 — nothing SSF-shaped happened and
  // no response exists — so the STATUS alone cannot tell a refusal from a
  // connection that failed. The `code` can, and it is the whole assertion:
  // EBLOCKEDADDRESS is the guard, ECONNREFUSED is the network.
  const loopback = await json('POST', '/ssf/call',
      { url: 'http://127.0.0.1:1/ssf/stream', method: 'GET' });
  check('a loopback address is refused BY THE GUARD, not by the network',
    function () {
      assert.strictEqual(loopback.status, 502,
          'It answered ' + loopback.status + ': ' + loopback.text);
      assert.strictEqual((loopback.body || {}).code, 'EBLOCKEDADDRESS',
          'It answered with code ' + ((loopback.body || {}).code || '(none)') +
          '. A connection that merely failed carries ECONNREFUSED, and ' +
          'accepting either would make this a test of the local network.');
    });
  const metadata = await json('POST', '/ssf/call',
      { url: 'http://169.254.169.254/latest/meta-data/', method: 'GET' });
  check('the cloud metadata address is refused BY THE GUARD', function () {
    assert.strictEqual(metadata.status, 502,
        'It answered ' + metadata.status + ': ' + metadata.text);
    assert.strictEqual((metadata.body || {}).code, 'EBLOCKEDADDRESS',
        'It answered with code ' + ((metadata.body || {}).code || '(none)') +
        '. On a cloud runner that address ANSWERS, so anything short of a ' +
        'refusal here is the guard being absent.');
  });
  log.info("[proxy] OK.");
}

// ---------------------------------------------------------------------------
// 3. THE RECEIVER.
// ---------------------------------------------------------------------------
async function theReceiverHostsAnEndpoint() {
  log.info("[receiver] A browser cannot be an HTTP server, so it cannot be " +
      "the far end of RFC 8935. This is the api standing in — and the body " +
      "parser for application/secevent+jwt, which no module test can see.");
  if (!limits.receiver || !limits.receiver.enabled) {
    skip('the push receiver',
        'this api has ssfReceiverEnabled off, so there is nothing to drive.');
    log.info("[receiver] SKIPPED.");
    return;
  }
  const made = await json('POST', '/ssf/receiver', { label: 'api_ssf.js' });
  assert.strictEqual(made.status, 200,
      'POST /ssf/receiver answered ' + made.status + ': ' + made.text);
  madeInboxes.push(made.body.inbox.id);
  check('it hands back a delivery endpoint a transmitter can reach',
    function () {
      assert.ok(/^https?:\/\//.test(made.body.deliveryEndpoint));
      assert.ok(made.body.deliveryEndpoint.indexOf(made.body.inbox.id) > 0);
      assert.ok(made.body.note.indexOf('TRANSMITTER') >= 0,
          'The endpoint is the api\'s address AS THE CALLER REACHED IT and ' +
          'not a configured one, and that has to be said: a page on ' +
          'localhost and a page on a compose network see different hosts ' +
          'for the same api, and a stream created with the wrong one ' +
          'delivers nothing with no error anybody sees.');
    });
  const path = '/ssf/receiver/' + made.body.inbox.id;

  // A real, signed SET, built by the workflow's own modules. It is not
  // verified here — the api holds no key of a transmitter's, and says so —
  // but sending a real one is what makes the decoded readout meaningful.
  const alg = 'ES256';
  const pair = jws.generateKey(alg);
  const priv = jws.privateJwk(alg, pair.privateKey, pair.publicKey);
  const claims = ssf.buildSetClaims({
    issuer: 'https://api-ssf-test.example/',
    audience: 'https://receiver.example/',
    uri: events.SSF_PREFIX + 'verification',
    payload: { state: 'from-api-ssf' } });
  const token = await ssf.signSet(claims, priv, alg, {});

  const pushed = await json('POST', path, token,
      { 'Content-Type': ssf.SET_MEDIA_TYPE });
  check('a push is a 202 with an EMPTY body', function () {
    assert.strictEqual(pushed.status, 202,
        'It answered ' + pushed.status + ': ' + pushed.text);
    assert.strictEqual(pushed.text, '',
        'RFC 8935 section 2.3 makes a success an EMPTY 202. A document here ' +
        'would be something a transmitter could come to depend on that no ' +
        'receiver has to send.');
  });
  const drained = await json('GET', path + '/events?after=0');
  check('THE BODY PARSER IS WIRED — the token arrived whole', function () {
    // This is the check no module test can make. Without the text parser for
    // application/secevent+jwt, req.body is an empty object here and every
    // push is reported as an empty body — a failure that reads as a
    // transmitter sending nothing.
    assert.strictEqual(drained.status, 200);
    assert.strictEqual(drained.body.events.length, 1);
    assert.strictEqual(drained.body.events[0].token, token,
        'The stored token is not the one that was sent. If it is empty, the ' +
        'body parser for application/secevent+jwt is not installed.');
  });
  check('it was decoded, and the media type was noticed', function () {
    const one = drained.body.events[0];
    assert.strictEqual(one.correctMediaType, true);
    assert.strictEqual(one.header.typ, 'secevent+jwt');
    assert.strictEqual(one.claims.jti, claims.jti);
    assert.strictEqual(one.problem, '');
  });
  const wrongType = await json('POST', path, token,
      { 'Content-Type': 'application/jwt' });
  const afterWrong = await json('GET', path + '/events?after=1');
  check('the WRONG media type is accepted and REPORTED', function () {
    // The finding this workflow exists to surface. A receiver that
    // dispatches on the type drops such a token with no error anybody sees,
    // and refusing it here would hide the finding behind a 400.
    assert.strictEqual(wrongType.status, 202);
    assert.strictEqual(afterWrong.body.events.length, 1);
    assert.strictEqual(afterWrong.body.events[0].correctMediaType, false);
    assert.strictEqual(afterWrong.body.events[0].contentType,
        'application/jwt');
  });
  const malformed = await json('POST', path, 'not-a-jws',
      { 'Content-Type': ssf.SET_MEDIA_TYPE });
  check('a body that is not a compact JWS is accepted and its problem kept',
    function () {
      assert.strictEqual(malformed.status, 202,
          'What arrived IS the question being asked, so it is recorded ' +
          'rather than refused.');
    });
  const afterMalformed = await json('GET', path + '/events?after=2');
  check('and the problem says what is wrong with it', function () {
    assert.strictEqual(afterMalformed.body.events.length, 1);
    assert.ok(afterMalformed.body.events[0].problem.indexOf('three') >= 0);
    assert.strictEqual(afterMalformed.body.events[0].token, 'not-a-jws');
  });
  const empty = await json('POST', path, '',
      { 'Content-Type': ssf.SET_MEDIA_TYPE });
  check('an empty body IS refused, with an RFC 8935 err', function () {
    assert.strictEqual(empty.status, 400);
    assert.strictEqual((empty.body || {}).err, 'invalid_request');
    assert.ok(String((empty.body || {}).description).indexOf('2.1') >= 0);
  });
  const unknown = await json('POST', '/ssf/receiver/deadbeefdeadbeef', token,
      { 'Content-Type': ssf.SET_MEDIA_TYPE });
  check('a push to an unknown inbox is a 404 with an err', function () {
    assert.strictEqual(unknown.status, 404);
    assert.strictEqual((unknown.body || {}).err, 'invalid_request');
  });
  const cursor = await json('GET', path + '/events?after=0');
  check('the cursor is not destructive', function () {
    assert.strictEqual(cursor.body.events.length, 3,
        'A second reader has to see everything, so a drain must not empty ' +
        'the inbox.');
    assert.strictEqual(cursor.body.total, 3);
    assert.strictEqual(cursor.body.inbox.pushes, 3);
  });
  const cleared = await json('DELETE', path + '?clear=true');
  check('clear empties without deleting', function () {
    assert.strictEqual(cleared.status, 200);
    assert.strictEqual(cleared.body.cleared, 3);
  });
  const deleted = await json('DELETE', path);
  check('delete removes it', function () {
    assert.strictEqual(deleted.status, 200);
    assert.strictEqual(deleted.body.deleted, made.body.inbox.id);
  });
  const gone = await json('GET', path + '/events?after=0');
  check('and it is then a 404', function () {
    assert.strictEqual(gone.status, 404);
  });
  const alsoGone = await json('DELETE', path);
  check('deleting it twice is a 404 rather than a silent success',
    function () {
      assert.strictEqual(alsoGone.status, 404);
    });
  check('an inbox made with no authorization_header says it is OPEN',
    function () {
      assert.strictEqual(made.body.inbox.authenticated, false);
      assert.ok(/OPEN/.test(String(made.body.authentication || '')),
          'The answer has to say plainly that anybody with the URL can ' +
          'push: ' + JSON.stringify(made.body.authentication));
    });

  // AN INBOX THAT REQUIRES ITS STREAM'S authorization_header, over HTTP,
  // because the Authorization header reaching deliver() is server.js's
  // wiring and no module test can see it.
  const secret = 'Bearer api-ssf-' + Date.now();
  const guarded = await json('POST', '/ssf/receiver',
      { label: 'api_ssf.js guarded', authorization: secret });
  assert.strictEqual(guarded.status, 200,
      'POST /ssf/receiver answered ' + guarded.status + ': ' + guarded.text);
  madeInboxes.push(guarded.body.inbox.id);
  const guardedPath = '/ssf/receiver/' + guarded.body.inbox.id;
  const without = await json('POST', guardedPath, token,
      { 'Content-Type': ssf.SET_MEDIA_TYPE });
  const wrongSecret = await json('POST', guardedPath, token,
      { 'Content-Type': ssf.SET_MEDIA_TYPE, Authorization: secret + 'x' });
  const withSecret = await json('POST', guardedPath, token,
      { 'Content-Type': ssf.SET_MEDIA_TYPE, Authorization: secret });
  const guardedHeld = await json('GET', guardedPath + '/events?after=0');
  check('a push without the authorization_header is a 401 ' +
      'authentication_failed', function () {
    assert.strictEqual(guarded.body.inbox.authenticated, true);
    assert.ok(guarded.text.indexOf(secret) < 0,
        'The secret is never handed back.');
    assert.strictEqual(without.status, 401, without.text);
    assert.strictEqual((without.body || {}).err, 'authentication_failed');
    assert.strictEqual(wrongSecret.status, 401, wrongSecret.text);
    assert.strictEqual(withSecret.status, 202, withSecret.text);
    assert.strictEqual(guardedHeld.body.events.length, 1,
        'Only the push that carried the header was stored.');
  });
  // Gone now rather than in cleanUp(), for the per-caller cap: every job in
  // the tests container is one caller.
  await json('DELETE', guardedPath);
  await perInboxSettingsAreCeilinged();
  log.info("[receiver] OK.");
}

// What a page may ask one inbox to be: its own idle TTL, lifetime and byte
// cap, each at most the setting that is also its default. Over HTTP, because
// what reaches create() is server.js's JSON body.
async function perInboxSettingsAreCeilinged() {
  log.debug("Entering perInboxSettingsAreCeilinged().");
  const ceilings = limits.receiver;
  check('/ssf/limits publishes the three ceilings and the two counts',
    function () {
      ['ttlMs', 'idleTtlMs', 'maxInboxBytes', 'maxInboxes',
        'maxInboxesPerCaller'].forEach(function (name) {
        assert.ok(Number(ceilings[name]) > 0, name + ' is ' + ceilings[name]);
      });
      assert.ok(/CEILING/.test(String(ceilings.ceilings || '')));
    });
  const above = await json('POST', '/ssf/receiver',
      { label: 'api_ssf.js above', idleTtlMs: ceilings.idleTtlMs + 1 });
  if (above.body && above.body.inbox) {
    madeInboxes.push(above.body.inbox.id);
  }
  check('a value above its ceiling is a 400 naming the setting', function () {
    assert.strictEqual(above.status, 400, above.text);
    assert.ok(String((above.body || {}).error || '')
      .indexOf('ssfReceiverIdleTtlMs') >= 0, above.text);
  });
  const asked = { label: 'api_ssf.js within',
    idleTtlMs: Math.max(1, ceilings.idleTtlMs - 1000),
    ttlMs: Math.max(1, ceilings.ttlMs - 1000),
    maxInboxBytes: ceilings.maxInboxBytes };
  const within = await json('POST', '/ssf/receiver', asked);
  if (within.body && within.body.inbox) {
    madeInboxes.push(within.body.inbox.id);
  }
  check('a value within its ceiling is honoured and reported', function () {
    assert.strictEqual(within.status, 200, within.text);
    assert.strictEqual(within.body.inbox.idleTtlMs, asked.idleTtlMs);
    assert.strictEqual(within.body.inbox.ttlMs, asked.ttlMs);
    assert.strictEqual(within.body.inbox.maxInboxBytes, asked.maxInboxBytes);
    assert.ok(within.body.inbox.expiresAt);
  });
  const omitted = await json('POST', '/ssf/receiver',
      { label: 'api_ssf.js omitted' });
  if (omitted.body && omitted.body.inbox) {
    madeInboxes.push(omitted.body.inbox.id);
  }
  check('an omitted value gets the default', function () {
    assert.strictEqual(omitted.status, 200, omitted.text);
    assert.strictEqual(omitted.body.inbox.idleTtlMs, ceilings.idleTtlMs);
    assert.strictEqual(omitted.body.inbox.ttlMs, ceilings.ttlMs);
    assert.strictEqual(omitted.body.inbox.maxInboxBytes,
        ceilings.maxInboxBytes);
  });
  // Deleted now rather than in cleanUp(): each holds a slot against
  // ssfReceiverMaxInboxesPerCaller, and this job has opened several.
  for (const one of [within, omitted]) {
    if (one.body && one.body.inbox) {
      await json('DELETE', '/ssf/receiver/' + one.body.inbox.id);
    }
  }
  log.debug("Leaving perInboxSettingsAreCeilinged().");
}

// ---------------------------------------------------------------------------
// 4. THE THREE OUTCOMES, END TO END.
// ---------------------------------------------------------------------------
async function theThreeOutcomesAreDistinct() {
  log.info("[outcomes] A refusal by the api is a 400, a network failure is a " +
      "502, and an answer from the far end is a 200 — WHATEVER its status. " +
      "The third is the one that matters and it is the easiest to get " +
      "wrong.");
  const unreachable = await json('POST', '/ssf/call',
      { url: 'https://ssf-nothing-here.invalid/.well-known/ssf-configuration',
        method: 'GET' });
  check('an unreachable host is a 502', function () {
    assert.strictEqual(unreachable.status, 502,
        'It answered ' + unreachable.status + ': ' + unreachable.text);
    assert.ok(String((unreachable.body || {}).error)
        .indexOf('could not be reached') >= 0);
  });
  if (!limits.receiver || !limits.receiver.enabled) {
    skip('a far-end answer as a 200', 'the receiver is off, so this file has ' +
        'no endpoint of its own to aim at.');
    log.info("[outcomes] partly skipped.");
    return;
  }
  // The api's own receiver refuses an empty body with a 400 and an RFC 8935
  // `{err, description}`, which is exactly the shape of a transmitter's
  // refusal. Aiming the PROXY at it is how the third outcome is asserted
  // without a transmitter.
  const made = await json('POST', '/ssf/receiver', { label: 'outcome test' });
  madeInboxes.push(made.body.inbox.id);
  const refused = await json('POST', '/ssf/call', {
    url: made.body.deliveryEndpoint, method: 'POST',
    headers: { 'Content-Type': ssf.SET_MEDIA_TYPE },
    body: '' });
  check('a refusal by the FAR END comes back as a 200 carrying it',
    function () {
      assert.strictEqual(refused.status, 200,
          'It answered ' + refused.status + '. A far-end refusal reported ' +
          'as a failure would make this workflow unable to show the errors ' +
          'it exists to show — a 403 naming a scope, a 400 naming the ' +
          'member of a subject identifier RFC 9493 does not define.');
      assert.strictEqual(refused.body.ok, false);
      assert.strictEqual(refused.body.status, 400);
      assert.strictEqual(refused.body.err, 'invalid_request');
      assert.ok(refused.body.description.length > 20);
    });
  const accepted = await json('POST', '/ssf/call', {
    url: made.body.deliveryEndpoint, method: 'POST',
    headers: { 'Content-Type': ssf.SET_MEDIA_TYPE },
    body: 'a.b.c', http_trace: true });
  check('a 202 with no body is a SUCCESS and says so', function () {
    assert.strictEqual(accepted.status, 200);
    assert.strictEqual(accepted.body.ok, true);
    assert.strictEqual(accepted.body.status, 202);
    assert.strictEqual(accepted.body.noBody, true,
        'SSF answers 204 and 202 with nothing constantly — Add Subject, ' +
        'Remove Subject, the verification endpoint — and a page that read ' +
        '"no body" as "nothing happened" would report every one of them as ' +
        'a failure.');
  });
  check('the api returns its own trace when asked', function () {
    assert.ok(accepted.body.http_exchange,
        'Only the api can report the whole exchange — a browser withholds ' +
        'the headers it adds and CORS hides most of those that come back — ' +
        'and that is one of the three reasons this call path exists.');
    assert.strictEqual(accepted.body.http_exchange.request.method, 'POST');
  });
  log.info("[outcomes] OK.");
}

// ---------------------------------------------------------------------------
// 6. THE HOSTED TRANSMITTER (#363), driven by a receiver over HTTP.
//
// The mirror of section 4. This file plays BOTH parties the api stands
// between: the page (which creates the transmitter, signs every SET and
// hands it over) and a receiver that treats the page as a full SSF 1.0
// transmitter — it discovers it, reads its keys, creates a push stream (to
// the api's OWN inbox, so no other service is needed) and a poll stream,
// pauses and resumes, asks for verification, and polls. Each answer is SSF's
// or RFC 8935/8936's, and the push is checked by draining the inbox it
// landed in and verifying it against the published JWKS.
// ---------------------------------------------------------------------------
const madeTransmitters = [];

async function theApiHostsATransmitter() {
  log.info("[transmitter] A receiver that treats its partner as a full SSF " +
      "transmitter discovers it, creates its stream there and polls it. A " +
      "page cannot be that server; the api answers for it, and the page " +
      "signs.");
  if (!limits.transmitter || !limits.transmitter.enabled) {
    skip('the hosted transmitter',
        'this api has ssfTransmitterEnabled off, so there is nothing to ' +
        'drive.');
    log.info("[transmitter] SKIPPED.");
    return;
  }
  const alg = 'ES256';
  const pair = jws.generateKey(alg);
  const priv = jws.privateJwk(alg, pair.privateKey, pair.publicKey);
  const pub = Object.assign(jws.publicJwk(alg, pair.publicKey),
                            { kid: 'page-key-1', use: 'sig', alg: alg });
  const caep = events.CAEP_PREFIX + 'session-revoked';
  const risc = events.RISC_PREFIX + 'account-disabled';

  const leaked = await json('POST', '/ssf/transmitter', {
    jwks: { keys: [Object.assign({}, pub, { d: priv.d })] } });
  check('a JWK Set holding a PRIVATE key is refused, since it would be ' +
    'published at jwks_uri', function () {
    assert.strictEqual(leaked.status, 400);
    assert.ok(/PRIVATE/.test(leaked.body.error), leaked.text);
  });

  const made = await json('POST', '/ssf/transmitter', {
    label: 'api_ssf.js', jwks: { keys: [pub] },
    eventsSupported: [caep, risc] });
  assert.strictEqual(made.status, 200,
      'POST /ssf/transmitter answered ' + made.status + ': ' + made.text);
  const t = made.body.transmitter;
  madeTransmitters.push({ id: t.id, ownerKey: made.body.ownerKey });
  const owner = { Authorization: 'Bearer ' + made.body.ownerKey };
  const receiver = { Authorization: 'Bearer ' +
                     made.body.receiverCredential };
  const base = t.issuer.slice(apiUrl.length);
  check('the issuer is this api\'s address as the caller reached it',
    function () {
    assert.strictEqual(t.issuer.indexOf(apiUrl), 0, t.issuer);
    assert.ok(made.body.ownerKey && made.body.receiverCredential);
    assert.notStrictEqual(made.body.ownerKey, made.body.receiverCredential);
  });

  // Discovery: SSF 1.0 section 7 puts the well-known path BEFORE the
  // issuer's own path.
  const discovered = await json('GET', '/.well-known/ssf-configuration' +
                                new URL(t.issuer).pathname);
  check('the configuration metadata is at the well-known path, naming the ' +
    'issuer, jwks_uri, configuration_endpoint and both deliveries',
    function () {
      assert.strictEqual(discovered.status, 200, discovered.text);
      assert.strictEqual(discovered.body.issuer, t.issuer);
      assert.strictEqual(discovered.body.jwks_uri, t.issuer + '/jwks');
      assert.ok(discovered.body.configuration_endpoint);
      assert.deepStrictEqual(discovered.body.delivery_methods_supported,
        ['urn:ietf:rfc:8935', 'urn:ietf:rfc:8936']);
      assert.strictEqual(t.discoveryUrl, apiUrl +
        '/.well-known/ssf-configuration' + new URL(t.issuer).pathname);
    });
  const keys = await json('GET', base + '/jwks');
  check('the JWKS publishes the page\'s public key and nothing private',
    function () {
      assert.strictEqual(keys.status, 200);
      assert.strictEqual(keys.body.keys.length, 1);
      assert.strictEqual(keys.body.keys[0].kid, 'page-key-1');
      assert.strictEqual(keys.body.keys[0].d, undefined);
    });

  const anonymous = await json('POST', base + '/stream',
    { delivery: { method: 'urn:ietf:rfc:8936' } });
  const wrong = await json('POST', base + '/stream',
    { delivery: { method: 'urn:ietf:rfc:8936' } },
    { Authorization: 'Bearer not-the-credential' });
  const ownerAsReceiver = await json('POST', base + '/stream',
    { delivery: { method: 'urn:ietf:rfc:8936' } }, owner);
  check('the stream management API refuses no credential, a wrong one, and ' +
    'the OWNER key, each 401 authentication_failed', function () {
      [anonymous, wrong, ownerAsReceiver].forEach(function (r) {
        assert.strictEqual(r.status, 401, r.text);
        assert.strictEqual(r.body.err, 'authentication_failed');
      });
    });
  const noTransmitter = await json('GET', '/ssf/transmitter/' +
    '0123456789abcdef0123456789abcdef', null, owner);
  const notOwner = await json('GET', '/ssf/transmitter/' + t.id, null,
                              receiver);
  check('the page\'s own routes need the owner key, and an unknown id is a ' +
    '404', function () {
      assert.strictEqual(noTransmitter.status, 404);
      assert.strictEqual(notOwner.status, 401);
    });

  // The receiver's push inbox — the api's own — and a push stream to it.
  const inbox = await json('POST', '/ssf/receiver', {
    label: 'api_ssf.js transmitter', authorization: 'Bearer push-secret' });
  assert.strictEqual(inbox.status, 200, inbox.text);
  madeInboxes.push(inbox.body.inbox.id);
  const pushStream = await json('POST', base + '/stream', {
    delivery: { method: 'urn:ietf:rfc:8935',
      endpoint_url: inbox.body.deliveryEndpoint,
      authorization_header: 'Bearer push-secret' },
    events_requested: [caep, 'urn:example:not-offered'],
    description: 'push' }, receiver);
  check('a push stream is created: 201, Transmitter-Supplied aud, ' +
    'events_delivered the intersection, and the authorization_header never ' +
    'echoed', function () {
      assert.strictEqual(pushStream.status, 201, pushStream.text);
      assert.ok(pushStream.body.stream_id);
      assert.strictEqual(pushStream.body.iss, t.issuer);
      assert.ok(pushStream.body.aud.indexOf(t.issuer) === 0);
      assert.deepStrictEqual(pushStream.body.events_delivered, [caep]);
      assert.strictEqual(pushStream.body.delivery.authorization_header,
                         undefined);
    });
  const pollStream = await json('POST', base + '/stream', {
    delivery: { method: 'urn:ietf:rfc:8936' } }, receiver);
  check('a poll stream is created with this transmitter\'s own poll ' +
    'endpoint', function () {
      assert.strictEqual(pollStream.status, 201, pollStream.text);
      assert.ok(pollStream.body.delivery.endpoint_url.indexOf(
        t.issuer + '/poll/') === 0);
      assert.deepStrictEqual(pollStream.body.events_delivered, [caep, risc]);
    });
  const badDelivery = await json('POST', base + '/stream', {
    delivery: { method: 'push' } }, receiver);
  check('a delivery method spelt "push" is refused naming the URN',
    function () {
    assert.strictEqual(badDelivery.status, 400);
    assert.ok(badDelivery.body.description.indexOf('urn:ietf:rfc:8935') >= 0);
  });

  const sign = function (stream, uri, payload) {
    log.debug("Entering sign().");
    log.debug("Leaving sign().");
    return ssf.signSet(ssf.buildSetClaims({ issuer: t.issuer,
      audience: stream.aud, uri: uri, payload: payload,
      subject: { format: 'email', email: 'alice@example.com' } }),
      priv, alg, { kid: 'page-key-1' });
  };
  const deliver = function (stream, token) {
    log.debug("Entering deliver().");
    log.debug("Leaving deliver().");
    return json('POST', base + '/deliver', { stream_id: stream.stream_id,
      token: token, sslValidate: true }, owner);
  };

  // A push, and what landed in the inbox.
  const revoked = await sign(pushStream.body, caep,
    { event_timestamp: Math.floor(Date.now() / 1000) });
  const pushed = await deliver(pushStream.body, revoked);
  check('a SET the page signed is PUSHED to the receiver with its ' +
    'authorization_header and accepted 202', function () {
      assert.strictEqual(pushed.status, 200, pushed.text);
      assert.strictEqual(pushed.body.action, 'push');
      assert.strictEqual(pushed.body.push.status, 202,
        JSON.stringify(pushed.body.push));
      assert.deepStrictEqual(pushed.body.findings, []);
    });
  const landed = await json('GET', '/ssf/receiver/' + inbox.body.inbox.id +
                            '/events?after=0');
  const verified = await ssf.verifySet(landed.body.events[0].token,
    { jwk: keys.body.keys[0] }, alg, {});
  check('it arrived as application/secevent+jwt and verifies against the ' +
    'transmitter\'s published JWKS', function () {
      assert.strictEqual(landed.body.events.length, 1);
      assert.strictEqual(landed.body.events[0].correctMediaType, true);
      assert.strictEqual(landed.body.events[0].authorization, true);
      assert.ok(verified && verified.valid, JSON.stringify(verified));
    });
  const offList = await deliver(pushStream.body, await sign(pushStream.body,
    risc, {}));
  check('a SET outside events_delivered is still sent, with a FINDING ' +
    'naming why a receiver may drop it', function () {
      assert.strictEqual(offList.body.action, 'push');
      assert.ok(offList.body.findings.some(function (f) {
        return f.indexOf('events_delivered') >= 0;
      }), JSON.stringify(offList.body.findings));
    });

  // Paused holds; enabled releases.
  const paused = await json('POST', base + '/status',
    { stream_id: pushStream.body.stream_id, status: 'paused',
      reason: 'maintenance' }, receiver);
  const heldAnswer = await deliver(pushStream.body,
    await sign(pushStream.body, caep, {}));
  const readPaused = await json('GET', base + '/status?stream_id=' +
                                pushStream.body.stream_id, null, receiver);
  check('a paused stream HOLDS what it is given (section 8.1.2)', function () {
    assert.strictEqual(paused.status, 200, paused.text);
    assert.strictEqual(readPaused.body.status, 'paused');
    assert.strictEqual(readPaused.body.reason, 'maintenance');
    assert.strictEqual(heldAnswer.body.action, 'held');
  });
  await json('POST', base + '/status',
    { stream_id: pushStream.body.stream_id, status: 'enabled' }, receiver);
  const deadline = Date.now() + 10000;
  let after = null;
  while (Date.now() < deadline) {
    after = await json('GET', '/ssf/receiver/' + inbox.body.inbox.id +
                       '/events?after=0');
    if (after.body.events.length >= 3) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
  }
  check('enabling it again releases what was held to the receiver',
    function () {
      assert.strictEqual(after.body.events.length, 3,
        after.body.events.length + ' event(s) in the inbox');
    });

  // Poll: queued, returned until acknowledged.
  const queued = await deliver(pollStream.body,
    await sign(pollStream.body, risc, {}));
  const pollPath = new URL(pollStream.body.delivery.endpoint_url).pathname;
  const first = await json('POST', pollPath, { returnImmediately: true },
                           receiver);
  const jtis = Object.keys((first.body || {}).sets || {});
  const again = await json('POST', pollPath, { ack: jtis,
                                               returnImmediately: true },
                           receiver);
  check('a poll stream QUEUES; RFC 8936 returns it until it is acked',
    function () {
      assert.strictEqual(queued.body.action, 'queued');
      assert.strictEqual(first.status, 200, first.text);
      assert.strictEqual(jtis.length, 1);
      assert.strictEqual(queued.body.jti, jtis[0]);
      assert.deepStrictEqual(again.body.sets, {});
      assert.strictEqual(again.body.moreAvailable, false);
    });

  // Verification: queued for the page, answered by the page.
  const asked = await json('POST', base + '/verify',
    { stream_id: pollStream.body.stream_id, state: 'from-the-receiver' },
    receiver);
  const pending = await json('GET', '/ssf/transmitter/' + t.id, null, owner);
  const answer = await deliver(pollStream.body, await sign(pollStream.body,
    events.SSF_PREFIX + 'verification', { state: 'from-the-receiver' }));
  const settled = await json('GET', '/ssf/transmitter/' + t.id, null, owner);
  check('a verification request is a 204 the PAGE answers: it is pending ' +
    'until a verification SET with the same state is delivered',
    function () {
      assert.strictEqual(asked.status, 204, asked.text);
      assert.strictEqual(pending.body.transmitter.pendingVerifications
        .length, 1);
      assert.strictEqual(answer.body.action, 'queued');
      assert.strictEqual(settled.body.transmitter.pendingVerifications
        .length, 0);
    });

  // Subjects, read and delete.
  const added = await json('POST', base + '/subjects/add',
    { stream_id: pollStream.body.stream_id,
      subject: { format: 'email', email: 'alice@example.com' } }, receiver);
  const removed = await json('POST', base + '/subjects/remove',
    { stream_id: pollStream.body.stream_id,
      subject: { format: 'email', email: 'alice@example.com' } }, receiver);
  const all = await json('GET', base + '/stream', null, receiver);
  const gone = await json('DELETE', base + '/stream?stream_id=' +
                          pollStream.body.stream_id, null, receiver);
  const missing = await json('GET', base + '/stream?stream_id=' +
                             pollStream.body.stream_id, null, receiver);
  check('add subject is an empty 200, remove a 204, read all is an array, ' +
    'delete a 204, and a deleted stream is a 404', function () {
      assert.strictEqual(added.status, 200);
      assert.strictEqual(added.text, '');
      assert.strictEqual(removed.status, 204);
      assert.strictEqual(all.body.length, 2);
      assert.strictEqual(gone.status, 204);
      assert.strictEqual(missing.status, 404);
      assert.strictEqual(missing.body.err, 'not_found');
    });
  const view = await json('GET', '/ssf/transmitter/' + t.id, null, owner);
  check('the page reads every stream, its status and the log of what the ' +
    'receiver did — and never the receiver\'s push secret', function () {
      assert.strictEqual(view.body.transmitter.streams.length, 1);
      assert.strictEqual(view.body.transmitter.streams[0].pushAuthorized,
                         true);
      assert.strictEqual(view.text.indexOf('push-secret'), -1);
      assert.ok(view.body.transmitter.log.length > 5);
    });
  log.info("[transmitter] OK.");
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  let id;
  for (id of madeInboxes) {
    await json('DELETE', '/ssf/receiver/' + id).catch(function () {
      return null;
    });
  }
  let made;
  for (made of madeTransmitters) {
    await json('DELETE', '/ssf/transmitter/' + made.id, null,
      { Authorization: 'Bearer ' + made.ownerKey }).catch(function () {
        return null;
      });
  }
  log.debug("Leaving cleanUp(). " + madeInboxes.length + " inbox(es), " +
            madeTransmitters.length + " transmitter(s).");
}

async function test() {
  log.debug("Entering test().");
  const reachable = await fetch(apiUrl + '/ssf/limits').then(function (r) {
    return r.status === 200;
  }).catch(function () {
    return false;
  });
  // A FAILURE rather than a skip, and it used to log "Test completed
  // successfully (skipped)" on its way out. run-report.js gates this job
  // itself and passes API_URL, so reaching this line means the launcher
  // expected an api at that address. See tests/expectation.js.
  mustBeAbleTo(reachable, "The api this job was pointed at,", apiUrl +
    ", did not answer GET /ssf/limits. Start the stack, or set API_URL to " +
    "one that does — and note that inside the tests container the api is " +
    "https://api:4000 rather than localhost.");
  try {
    await theLimitsDocumentIsPublished();
    await theProxyRefusesBeforeTheNetwork();
    await theAddressPolicyStillApplies();
    await theReceiverHostsAnEndpoint();
    await theThreeOutcomesAreDistinct();
    await theApiHostsATransmitter();
  } finally {
    // An inbox left behind expires on its own, but it holds a slot against
    // ssfReceiverMaxInboxes meanwhile — and a later job in the pool refused
    // for that reason would fail naming a limit nothing set.
    await cleanUp();
  }
  log.info(checks + " checks passed" +
      (skips.length ? ", " + skips.length + " skipped." : "."));
  skips.forEach(function (one) {
    log.warn("  skipped: " + one);
  });
  assert.ok(checks >= 25,
      'Only ' + checks + ' checks ran and this file defines more than ' +
      'twenty-five. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_ssf")
  .description("Drive the api's Shared Signals surface over HTTP: the limits " +
      "document, every refusal POST /ssf/call makes as a 400, the address " +
      "policy still applying, the push receiver a browser cannot be — " +
      "including the body parser for application/secevent+jwt that no module " +
      "test can see — and the three outcomes as statuses.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
