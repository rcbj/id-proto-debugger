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

var apiUrl = process.env.API_URL || "http://localhost:4000";

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
  const loopback = await json('POST', '/ssf/call',
      { url: 'http://127.0.0.1:1/ssf/stream', method: 'GET' });
  check('a loopback address is refused', function () {
    assert.ok(loopback.status === 502 || loopback.status === 400,
        'It answered ' + loopback.status + ': ' + loopback.text);
    const said = String((loopback.body || {}).error || '');
    assert.ok(said.length > 0, 'The refusal says nothing.');
  });
  const metadata = await json('POST', '/ssf/call',
      { url: 'http://169.254.169.254/latest/meta-data/', method: 'GET' });
  check('the cloud metadata address is refused', function () {
    assert.ok(metadata.status === 502 || metadata.status === 400,
        'It answered ' + metadata.status + ': ' + metadata.text);
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
  log.info("[receiver] OK.");
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

async function cleanUp() {
  log.debug("Entering cleanUp().");
  let id;
  for (id of madeInboxes) {
    await json('DELETE', '/ssf/receiver/' + id).catch(function () {
      return null;
    });
  }
  log.debug("Leaving cleanUp(). " + madeInboxes.length + " inbox(es).");
}

async function test() {
  log.debug("Entering test().");
  const reachable = await fetch(apiUrl + '/ssf/limits').then(function (r) {
    return r.status === 200;
  }).catch(function () {
    return false;
  });
  if (!reachable) {
    log.warn("SKIPPED — no api answered at " + apiUrl +
        "/ssf/limits. Set API_URL to one that does.");
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  try {
    await theLimitsDocumentIsPublished();
    await theProxyRefusesBeforeTheNetwork();
    await theAddressPolicyStillApplies();
    await theReceiverHostsAnEndpoint();
    await theThreeOutcomesAreDistinct();
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
