// File: caep_protocol.js
//
// ---------------------------------------------------------------------------
// CAEP AGAINST A REAL TRANSMITTER, WITH NO BROWSER, AND THE ONE TEST IN THIS
// SUITE WHOSE SUBJECT IS SOMETHING THE FAR END DECIDED TO DO.
//
// Every other job here drives a request and reads the answer. This one signs
// somebody IN and then waits for a Security Event Token that nobody asked
// for — because that is what CAEP is, and it is the half of this feature that
// cannot be asserted from either end alone.
//
// The transmitter is the mock STS's `/ssf`, whose CAEP half is
// `sts/ssf/caep.js` and `sts/ssf/ssf_events.js`. Its reading of the
// specification was written INDEPENDENTLY of `client/src/ssf_events.js`'s —
// the argument `ssf_protocol.js` makes about RFC 9493 applied to a vocabulary
// — so this file drives one reading against the other over the wire. If both
// ends shared an implementation, a misunderstanding they shared would be one
// neither could see.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS THAT NOTHING ELSE CAN.
//
//   * that the eight types are ADVERTISED and AGREED. `events_requested` is
//     the ask and `events_delivered` is the answer, and SSF has no refusal for
//     a type a transmitter will not send — its absence from the second list is
//     the only notice a receiver ever gets.
//   * that a SIGN-IN, a SINGLE SIGN-ON and a SIGN-OUT each put an event on the
//     stream with nobody having asked.
//   * that `caep.autoEmit` off really does stop it, which is what proves the
//     setting is a setting rather than a comment.
//   * that the subject on an automatic event is SSF's COMPLEX one, naming the
//     session as well as the person — and that it arrives in `sub_id` and not
//     in `sub`.
//   * that the per-session register counts what was actually sent and outlives
//     the session it describes.
//
// THE SIGN-IN IS DRIVEN OVER HTTP AND STOPS AT THE SESSION. This file wants a
// SESSION and not a token: `startSession()` is where the session-established
// event is emitted, and it happens at the sign-in screen's POST, well before
// any code is redeemed. Driving the rest of the authorization flow would mean
// answering the consent screen — which is somebody else's test, and turning
// `oauth2.consentRequired` off here would reconfigure a setting this job does
// not hold a lock on.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "caep_protocol",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The workflow's own modules, so this test reads what the PAGE would read
// rather than a second implementation of it.
const ssf = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const caep = paths.requireSharedModule(
  [__dirname + "/../client/src/caep_session.js",
   __dirname + "/caep_session.js"], "caep_session.js");

// STS_URL and not WSTRUST_STS_URL, for the reason ssf_protocol.js records at
// length: that variable is a WS-Trust ENDPOINT carrying a `/sts` path, and SSF
// is served at the root.
var stsUrl = process.env.SSF_TRANSMITTER_URL || process.env.STS_URL ||
    "https://localhost:8081";
var adminUrl = stsUrl + '/admin-api';

const P = "https://schemas.openid.net/secevent/caep/event-type/";

// Basic, for ssf_protocol.js's reason: it is the only scheme the mock offers
// that needs nothing but a header this process can compute.
const BASIC = 'Basic ' + Buffer.from('caep-protocol-runner:pw')
    .toString('base64');

// Somebody nobody else in this suite signs in as, so that a session this file
// creates cannot be confused with one another job left behind.
const WHO = 'caep-protocol-' + Math.random().toString(16).slice(2, 8);

let checks = 0;
let skips = [];
// The subject identifier this transmitter actually uses for WHO. It derives
// one rather than using the typed name, and a receiver only ever sees the
// derived form — so section 2b reads it out of the register rather than
// guessing at the shape.
let realSub = '';
const created = { streams: [] };
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

async function call(method, url, body, options) {
  log.debug("Entering call(). " + method + " " + url);
  const settings = options || {};
  const headers = Object.assign({ Accept: 'application/json' },
      settings.anonymous ? {} : { Authorization: BASIC },
      settings.headers || {});
  const init = { method: method, headers: headers,
    redirect: settings.redirect || 'follow' };
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
      // Not JSON. Kept as text: an HTML page from the sign-in screen is
      // exactly the case where the body is the evidence.
      payload = null;
    }
  }
  log.debug("Leaving call(). " + response.status);
  return { status: response.status, body: payload, text: text,
    location: response.headers.get('location') || '',
    setCookie: response.headers.get('set-cookie') || '' };
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
// THE SIGN-IN, OVER HTTP, WITH ONE COOKIE.
//
// Three steps and it stops at the second, which is the point: the session
// exists — and `session-established` has therefore been emitted — the moment
// the sign-in screen's POST returns. Redeeming a code would mean answering the
// consent screen, and `oauth2.consentRequired` is a setting this job holds no
// lock on.
//
// The cookie is carried by hand rather than by a jar, because there is exactly
// one and node's fetch has no jar. `redirect: 'manual'` throughout: every step
// here IS a redirect, and following one would lose the `Location` this reads.
// ---------------------------------------------------------------------------
let sessionCookie = '';
let sessionId = '';

function cookieHeader() {
  return sessionCookie ? { Cookie: sessionCookie } : {};
}

function authorizeUrl() {
  return stsUrl + '/oauth2/authorize?response_type=code&client_id=webapp1' +
    '&redirect_uri=' + encodeURIComponent('https://client.example/callback') +
    '&scope=' + encodeURIComponent('openid') +
    '&state=caep-' + Math.random().toString(16).slice(2, 8);
}

async function signIn() {
  log.debug("Entering signIn().");
  const started = await call('GET', authorizeUrl(), null,
      { anonymous: true, redirect: 'manual' });
  const to = String(started.location || '');
  const match = /[?&]authn=([^&]+)/.exec(to);
  if (!match) {
    log.debug("Leaving signIn(). No sign-in screen.");
    return { ok: false, why: 'The authorization endpoint answered ' +
      started.status + ' and sent the browser to "' + to + '", which ' +
      'carries no `authn` — so there is no sign-in form to post.' };
  }
  const form = 'authn_id=' + encodeURIComponent(match[1]) +
    '&username=' + encodeURIComponent(WHO) + '&action=login';
  const posted = await call('POST', stsUrl + '/authn/login', form, {
    anonymous: true, redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  const cookie = String(posted.setCookie || '');
  const got = /sts_mock_session=([^;]+)/.exec(cookie);
  if (!got) {
    log.debug("Leaving signIn(). No session cookie.");
    return { ok: false, why: 'The sign-in screen answered ' + posted.status +
      ' and set no session cookie. It said: ' + posted.text.slice(0, 200) };
  }
  sessionCookie = "sts_mock_session=" + got[1];
  sessionId = got[1];
  log.debug("Leaving signIn(). " + sessionId);
  return { ok: true, sessionId: got[1] };
}

// Present the existing session at the authorization endpoint. TWICE is the
// interesting number: the FIRST presentation of a brand-new session is the
// sign-in's own return trip and a conforming transmitter does not report it —
// otherwise `session-presented` would arrive milliseconds after
// `session-established` on every flow and would mean nothing.
async function present() {
  log.debug("Entering present().");
  const out = await call('GET', authorizeUrl(), null,
      { anonymous: true, redirect: 'manual', headers: cookieHeader() });
  log.debug("Leaving present(). " + out.status);
  return out;
}

async function signOut() {
  log.debug("Entering signOut().");
  const out = await call('GET', stsUrl + '/oauth2/logout', null,
      { anonymous: true, redirect: 'manual', headers: cookieHeader() });
  log.debug("Leaving signOut(). " + out.status);
  return out;
}

// ---------------------------------------------------------------------------
// THE STREAM, AND THE POLL THAT DRAINS IT.
// ---------------------------------------------------------------------------
let metadata = null;
let streamId = '';
// RFC 8936's POLL ENDPOINT IS THE TRANSMITTER'S AND IS NOT IN THE METADATA.
// It comes back on the stream, in `delivery.endpoint_url` — which is the
// member that means the RECEIVER's address on a push stream and the
// TRANSMITTER's on a poll one. That reversal catches everybody once, and a
// test that looked for a `poll_endpoint` in the well-known document would
// fail naming discovery.
let pollUrl = '';

function endpoint(name) {
  const found = ssf.endpointFor(metadata, name);
  assert.ok(found.ok, name + ': ' + found.error);
  return found.url;
}

async function poll(maxEvents) {
  log.debug("Entering poll().");
  if (!pollUrl) {
    log.debug("Leaving poll(). No stream yet.");
    return [];
  }
  // `streamId` and `ack`, which are what `buildPollRequest()` actually takes.
  // The stream id is NOT an RFC 8936 member — a real poll endpoint is per
  // stream — and this transmitter publishes one URL for all of them, so it
  // has to be told which.
  const body = ssf.buildPollRequest({ maxEvents: maxEvents || 20,
    streamId: streamId, returnImmediately: true });
  const answer = await call('POST', pollUrl, body, {});
  assert.strictEqual(answer.status, 200,
      'The poll endpoint answered ' + answer.status + ': ' + answer.text);
  // RFC 8936's `sets` IS A MAP from jti to the compact JWS, not an array —
  // which is the shape that catches a client written from the section
  // heading rather than from the example.
  const read = ssf.readPollResponse(answer.body);
  const out = read.jtis.map(function (jti) {
    const token = read.sets[jti];
    const parsed = ssf.parseSet(token);
    return { jti: jti, token: token,
      claims: parsed.ok ? parsed.claims : {},
      types: parsed.ok ? Object.keys(parsed.claims.events || {}) : [] };
  });
  // Acknowledged, so the next poll in this file sees only what is new.
  if (out.length) {
    await call('POST', pollUrl,
        ssf.buildPollRequest({ maxEvents: 1, returnImmediately: true,
          streamId: streamId,
          ack: out.map(function (one) { return one.jti; }) }), {});
  }
  log.debug("Leaving poll(). " + out.length + " set(s).");
  return out;
}

function ofType(sets, short) {
  return sets.filter(function (one) {
    return one.types.indexOf(P + short) >= 0;
  });
}

// ---------------------------------------------------------------------------
// 1. THE TRANSMITTER OFFERS CAEP.
// ---------------------------------------------------------------------------
async function theEightAreOffered() {
  log.info("[caep] The eight event types, advertised and then AGREED. " +
      "events_requested is the ask and events_delivered is the answer — and " +
      "SSF has no refusal for a type a transmitter will not send, so its " +
      "absence from the second list is the only notice a receiver gets.");
  const candidates = ssf.metadataCandidates(stsUrl);
  const answer = await call('GET', candidates[0], null, { anonymous: true });
  assert.strictEqual(answer.status, 200,
      'The metadata document is at ' + candidates[0] + ' and answered ' +
      answer.status + '.');
  metadata = answer.body;

  // **`events_supported` IS A STREAM MEMBER AND NOT A METADATA ONE**, which
  // is worth knowing before looking for it in the wrong document: SSF 1.0
  // puts it on the Stream Configuration, so what a transmitter WILL send is
  // discoverable only once a stream exists. Section 2 is where it is
  // asserted. What the metadata does have to carry is every endpoint, and
  // this workflow composes none of them.
  check('every endpoint this workflow needs is published, and none is ' +
      'composed here', function () {
    ['configuration_endpoint', 'status_endpoint', 'add_subject_endpoint',
     'remove_subject_endpoint', 'verification_endpoint'].forEach(
      function (name) {
      const found = ssf.endpointFor(metadata, name);
      assert.ok(found.ok, name + ': ' + found.error);
    });
  });

  const catalogue = await call('GET', adminUrl + '/caep', null, {});
  check('the transmitter reports all eight as OFFERED', function () {
    assert.strictEqual(catalogue.status, 200, catalogue.text);
    assert.strictEqual(catalogue.body.enabled, true,
        'caep.enabled is off at this transmitter, so nothing below can ' +
        'happen. It is restored by cleanUp() if this run turned it off.');
    const offered = (catalogue.body.catalogue || []).filter(function (row) {
      return row.offered;
    }).map(function (row) {
      return row.uri;
    });
    events.CAEP_EVENT_URIS.forEach(function (uri) {
      assert.ok(offered.indexOf(uri) >= 0,
          uri + ' is not offered. This transmitter implements CAEP, and a ' +
          'type it will not agree to is one a receiver finds out about only ' +
          'by never being sent one.');
    });
  });

  check('AND ITS READING OF EACH ONE MATCHES THIS BUILD\'S', function () {
    // The two were written independently — the argument ssf_protocol.js
    // makes about RFC 9493, applied to a vocabulary — so this is the check
    // that earns that. A member one end thinks is required and the other
    // does not is a workflow that agrees with itself and interoperates with
    // nothing.
    (catalogue.body.catalogue || []).forEach(function (row) {
      const mine = events.EVENT_BY_URI[row.uri];
      assert.ok(mine, row.uri + ' is offered there and unknown here.');
      const theirs = row.required.slice().sort();
      const ours = mine.members.filter(function (member) {
        return member.required;
      }).map(function (member) {
        return member.name;
      }).sort();
      assert.deepStrictEqual(theirs, ours,
          row.uri + ': the transmitter requires [' + theirs.join(', ') +
          '] and this build requires [' + ours.join(', ') + ']. Two ' +
          'independent readings of CAEP section 3 have diverged, and the ' +
          'one that is wrong will build an event the other refuses.');
    });
  });
}

// ---------------------------------------------------------------------------
// 2. A STREAM THAT ASKS FOR ALL EIGHT.
// ---------------------------------------------------------------------------
async function aStreamAgreesThem() {
  log.info("[stream] A stream requesting the eight, and the person added to " +
      "it as a subject.");
  const body = ssf.buildStreamConfiguration({
    aud: 'https://caep-protocol.example/receiver',
    events_requested: events.CAEP_EVENT_URIS.slice()
      .concat([events.SSF_PREFIX + 'stream-updated']),
    deliveryMethod: ssf.DELIVERY_POLL,
    description: 'caep_protocol.js'
  });
  const answer = await call('POST', endpoint('configuration_endpoint'),
      body, {});
  assert.strictEqual(answer.status, 201,
      'Creating the stream answered ' + answer.status + ': ' + answer.text);
  streamId = String(answer.body.stream_id || '');
  created.streams.push(streamId);
  pollUrl = String((answer.body.delivery || {}).endpoint_url || '');
  assert.ok(pollUrl,
      'The stream came back with no delivery.endpoint_url. On a POLL stream ' +
      'that member is the TRANSMITTER\'s address rather than the ' +
      'receiver\'s, and without it there is nowhere to come and collect.');

  check('the stream reports all eight in events_supported', function () {
    const supported = answer.body.events_supported || [];
    events.CAEP_EVENT_URIS.forEach(function (uri) {
      assert.ok(supported.indexOf(uri) >= 0,
          uri + ' is not in this stream\'s events_supported.');
    });
  });

  check('every one of the eight comes back in events_delivered', function () {
    const delivered = answer.body.events_delivered || [];
    events.CAEP_EVENT_URIS.forEach(function (uri) {
      assert.ok(delivered.indexOf(uri) >= 0,
          uri + ' was requested and is NOT delivered. That absence is the ' +
          'only notice SSF gives, and a receiver reading back what it asked ' +
          'for instead would wait for ever.');
    });
  });

  // NO SUBJECT IS ADDED HERE, and that is a decision rather than an
  // omission. An EMPTY subject list means what `default_subjects` says it
  // means — `ALL` at this transmitter — so this stream is about everybody,
  // which is what section 3 needs before anybody has signed in. Section 3b
  // then adds a real one and asserts the rule that makes CAEP deliverable at
  // all.
  check('the stream is agreed with an EMPTY subject list, which means ' +
      'everybody here', function () {
    const read = ssf.readMetadata(metadata);
    assert.strictEqual(read.defaultSubjects, 'ALL',
        'default_subjects is "' + read.defaultSubjects + '". With NONE this ' +
        'stream would be about nobody until a subject was added, and a ' +
        'receiver that guessed wrong gets every event in the estate or gets ' +
        'none — which is why SSF makes it discoverable rather than leaving ' +
        'it to be inferred.');
  });
}

// ---------------------------------------------------------------------------
// 2b. A STREAM THAT NAMES THE PERSON COVERS AN EVENT ABOUT THEIR SESSION.
//
// **WITHOUT THIS RULE CAEP DELIVERS NOTHING**, and the failure is silent: a
// receiver adds the PERSON to a stream, because that is the only identifier it
// can know in advance, and every CAEP event names a COMPLEX subject whose
// `user` member is exactly that identifier. Those two are different subject
// keys, so an exact-match transmitter refuses every session event to the
// receiver that asked for the person — and a transmitter's refusal to send is
// not a message anybody receives.
// ---------------------------------------------------------------------------
async function namingThePersonCoversTheirSessions(realSub) {
  log.info("[subjects] A stream naming the PERSON has to cover an event " +
      "about a SESSION of theirs. Without it every CAEP event is refused to " +
      "the only receiver that could have asked for it.");
  const person = { format: 'issuer_subject_id',
    iss: String(metadata.issuer || ''), sub: realSub };
  const added = await call('POST', endpoint('add_subject_endpoint'),
      { stream_id: streamId, subject: person, verified: true }, {});
  check('the person is added as a plain issuer_subject_id subject',
      function () {
        assert.ok(added.status >= 200 && added.status < 300,
            'Adding the subject answered ' + added.status + ': ' +
            added.text);
      });

  await poll(50);
  const signed = await signIn();
  if (!signed.ok) {
    skip('coverage by member', signed.why);
    return;
  }
  const arrived = await poll(50);
  check('AND AN EVENT ABOUT A SESSION OF THEIRS STILL ARRIVES', function () {
    assert.ok(ofType(arrived, 'session-established').length > 0,
        'The stream now names the person EXACTLY and nothing arrived, which ' +
        'means the transmitter compares subject keys and a complex subject ' +
        'is a different key. That is the shape of the bug this rule exists ' +
        'to prevent, and it fails silently in every real deployment.');
  });
  await signOut();
  await poll(50);
}

// ---------------------------------------------------------------------------
// 3. AUTOMATIC EMISSION — THE SECTION THIS WHOLE FILE EXISTS FOR.
// ---------------------------------------------------------------------------
async function signingInEmitsAnEvent() {
  log.info("[auto] A SIGN-IN, A SINGLE SIGN-ON AND A SIGN-OUT, each putting " +
      "a Security Event Token on the stream with nobody having asked. It is " +
      "the only thing in this suite whose subject is something the far end " +
      "decided to do.");

  await poll(50);            // drain anything an earlier section left.
  const signed = await signIn();
  if (!signed.ok) {
    skip('automatic emission', signed.why);
    return;
  }

  const afterSignIn = await poll(50);
  const established = ofType(afterSignIn, 'session-established');
  // THE SUBJECT THIS SERVICE USES IS NOT THE NAME THAT WAS TYPED. It derives
  // one — `urn:sts-mock:user:<name>` here — and a receiver only ever sees
  // the derived form, so section 2b has to add THAT rather than the name.
  // Learning it from the register is the honest way round: it is what the
  // transmitter actually put in the subject.
  const report = await call('GET', adminUrl + '/caep', null, {});
  const mine = ((report.body || {}).sessions || []).filter(function (one) {
    return one.sessionId === signed.sessionId;
  })[0];
  realSub = mine ? mine.sub : WHO;
  check('signing in put a session-established on the stream', function () {
    assert.ok(established.length > 0,
        'Nothing arrived. ' + afterSignIn.length + ' set(s) were polled, ' +
        'carrying: ' + afterSignIn.map(function (one) {
          return one.types.join(',');
        }).join(' | ') + '. Either caep.autoEmit is off, or no stream both ' +
        'delivers that type and covers the subject — which is what the ' +
        'CAEP sessions page reports and is the answer nine times out of ten.');
  });

  if (!established.length) {
    return;
  }
  const claims = established[0].claims;

  check('THE SUBJECT IS A COMPLEX ONE, naming the session as well as the ' +
      'person', function () {
    assert.ok(claims.sub_id, 'there is no sub_id at all.');
    assert.strictEqual(claims.sub_id.format, undefined,
        'a complex subject is told from a plain one by the ABSENCE of ' +
        '`format`. This one carries "' + claims.sub_id.format + '", so it ' +
        'names a person and nothing else — which asks a receiver to end ' +
        'every session they have.');
    assert.ok(claims.sub_id.session,
        'there is no `session` member. The person is not revoked; one ' +
        'session of theirs is.');
    assert.strictEqual(claims.sub_id.session.id, signed.sessionId,
        'the session named is not the one that was just created.');
    assert.ok(String(claims.sub_id.user.sub).indexOf(WHO) >= 0,
        'the `user` member names "' + claims.sub_id.user.sub + '" and the ' +
        'name that was typed was "' + WHO + '". A transmitter DERIVES a ' +
        'subject identifier rather than using the typed name — this one ' +
        'makes a urn: of it — and a receiver only ever sees the derived ' +
        'form, which is why section 2b adds THAT to the stream rather than ' +
        'the name.');
    assert.ok(String(claims.sub_id.user.iss).length > 0,
        'the `user` member carries no issuer. A receiver matches that string ' +
        'against the issuer it discovered, so an event without one names ' +
        'somebody it has never heard of.');
  });

  check('and it rides in sub_id rather than in sub', function () {
    assert.strictEqual(claims.sub, undefined,
        'RFC 8417 section 2.2 discourages `sub` on a SET, and a client ' +
        'written against a transmitter that emits one silently reads ' +
        'nothing from a conforming one.');
  });

  check('there is no exp, which is RFC 8417 section 4.1.4 rather than an ' +
      'omission', function () {
    assert.strictEqual(claims.exp, undefined,
        'a SET records that something HAPPENED, and a fact does not stop ' +
        'being true.');
  });

  check('the payload validates against THIS build\'s reading of CAEP',
      function () {
    const payload = claims.events[P + 'session-established'];
    const verdict = events.validateEvent(P + 'session-established', payload);
    assert.ok(verdict.ok,
        'The transmitter\'s reading of the specification and this ' +
        'workflow\'s disagree, which is exactly what driving one against the ' +
        'other is for: ' + verdict.errors.join(' '));
  });

  check('reason_admin arrives as a LANGUAGE MAP and not as a string',
      function () {
    const payload = claims.events[P + 'session-established'];
    if (payload.reason_admin === undefined) {
      skip('reason_admin', 'this transmitter did not send one, which is ' +
          'legal — caep.includeReasons turns it off.');
      return;
    }
    assert.strictEqual(typeof payload.reason_admin, 'object',
        'It is a string. A receiver indexing by language reads nothing from ' +
        'one and reports no error, which is why this is checked over the ' +
        'wire rather than assumed.');
  });

  // SINGLE SIGN-ON. Twice, because the first presentation of a brand-new
  // session is the sign-in's own return trip.
  await present();
  await poll(50);
  await present();
  const afterSso = await poll(50);
  check('presenting the session again put a session-presented on the stream',
      function () {
        assert.ok(ofType(afterSso, 'session-presented').length > 0,
            'Nothing arrived for the second presentation. ' +
            afterSso.length + ' set(s) were polled.');
      });

  // SIGN-OUT.
  await signOut();
  const afterSignOut = await poll(50);
  check('signing out put a session-revoked on the stream', function () {
    assert.ok(ofType(afterSignOut, 'session-revoked').length > 0,
        'Nothing arrived for the sign-out. ' + afterSignOut.length +
        ' set(s) were polled.');
  });

  check('and the revocation names the same session', function () {
    const revoked = ofType(afterSignOut, 'session-revoked')[0];
    assert.strictEqual(revoked.claims.sub_id.session.id, signed.sessionId);
  });
}

// ---------------------------------------------------------------------------
// 4. THE SETTING THAT TURNS IT OFF.
// ---------------------------------------------------------------------------
async function autoEmitOffStopsIt() {
  log.info("[auto] caep.autoEmit off restores this service's older and " +
      "equally honest behaviour: every Security Event Token it sends was " +
      "asked for. Without this check the setting is a comment.");
  await setSetting('caep.autoEmit', 'false');
  await poll(50);
  const signed = await signIn();
  if (!signed.ok) {
    skip('automatic emission off', signed.why);
    await setSetting('caep.autoEmit', 'true');
    return;
  }
  const quiet = await poll(50);
  check('signing in with emission off delivers nothing', function () {
    assert.strictEqual(ofType(quiet, 'session-established').length, 0,
        quiet.length + ' set(s) arrived with caep.autoEmit off.');
  });

  const report = await call('GET', adminUrl + '/caep', null, {});
  check('AND THE SESSION IS STILL TRACKED, with a count of zero', function () {
    assert.strictEqual(report.status, 200, report.text);
    const row = (report.body.sessions || []).filter(function (one) {
      return one.sessionId === signed.sessionId;
    })[0];
    assert.ok(row,
        'A page that showed nothing here would leave "why did no event ' +
        'arrive" unanswerable. A row with a count of zero answers it.');
    assert.strictEqual(row.total, 0);
  });
  await signOut();
  await setSetting('caep.autoEmit', 'true');
}

// ---------------------------------------------------------------------------
// 5. EVERY ONE OF THE EIGHT, BY HAND.
// ---------------------------------------------------------------------------
async function everyEventEmittedByHand() {
  log.info("[emit] All eight through POST /admin-api/caep/emit. Five of them " +
      "have no act here that could cause them — no device reports " +
      "compliance to this service and no risk engine talks to it — so this " +
      "is the only way they are ever produced.");
  const signed = await signIn();
  if (!signed.ok) {
    skip('emitting by hand', signed.why);
    return;
  }
  await poll(50);

  const shorts = events.CAEP_EVENT_URIS.map(function (uri) {
    return uri.slice(P.length);
  });
  let i;
  for (i = 0; i < shorts.length; i++) {
    const short = shorts[i];
    const out = await call('POST', adminUrl + '/caep/emit',
        { session_id: signed.sessionId, type: short,
          initiating_entity: 'admin',
          reason_admin: 'emitted by caep_protocol.js' }, {});
    // `session-presented` about a session this run has not revoked is fine;
    // the ORDER matters here and revoked goes last for that reason.
    assert.strictEqual(out.status, 200,
        'Emitting ' + short + ' answered ' + out.status + ': ' + out.text);
  }

  const arrived = await poll(50);
  check('every one of the eight arrived on the stream', function () {
    shorts.forEach(function (short) {
      assert.ok(ofType(arrived, short).length > 0,
          'No ' + short + ' arrived. ' + arrived.length + ' set(s) were ' +
          'polled, carrying: ' + arrived.map(function (one) {
            return one.types.join(',');
          }).join(' | '));
    });
  });

  check('and every payload validates against this build\'s reading',
      function () {
    arrived.forEach(function (one) {
      one.types.forEach(function (uri) {
        if (uri.indexOf(P) !== 0) {
          return;
        }
        const verdict = events.validateEvent(uri, one.claims.events[uri]);
        assert.ok(verdict.ok, uri + ': ' + verdict.errors.join(' '));
      });
    });
  });

  check('THE STATE MACHINE ON THIS SIDE ACCEPTS THE WHOLE SEQUENCE',
      function () {
    // The model is the debugger's, the events are the transmitter's, and
    // this is the only place the two meet. A refusal here means the two ends
    // disagree about what may follow what — which is a real interoperability
    // finding rather than a bug in either.
    const model = caep.newSession({ iss: String(metadata.issuer || ''),
      sub: WHO, sid: signed.sessionId });
    const ordered = arrived.slice().sort(function (a, b) {
      return Number(a.claims.iat || 0) - Number(b.claims.iat || 0);
    });
    ordered.forEach(function (one) {
      one.types.forEach(function (uri) {
        if (uri.indexOf(P) !== 0) {
          return;
        }
        caep.apply(model, uri, one.claims.events[uri]);
      });
    });
    assert.ok(caep.describe(model).total >= 0);
  });

  await signOut();
}

// ---------------------------------------------------------------------------
// 6. THE DELIBERATE DEFECT THAT IS NOT A DEFECT.
// ---------------------------------------------------------------------------
async function omittingTheTimestampIsConforming() {
  log.info("[defect] caep.omitEventTimestamp. An event with no " +
      "event_timestamp is PERFECTLY CONFORMING — CAEP section 2 makes the " +
      "member optional — and it is what every receiver that assumes one " +
      "breaks on. That is the only reason the setting exists.");
  await setSetting('caep.omitEventTimestamp', 'true');
  const signed = await signIn();
  if (!signed.ok) {
    skip('the omitted timestamp', signed.why);
    await setSetting('caep.omitEventTimestamp', 'false');
    return;
  }
  await poll(50);
  const out = await call('POST', adminUrl + '/caep/emit',
      { session_id: signed.sessionId, type: 'session-revoked' }, {});
  assert.strictEqual(out.status, 200, out.text);
  const arrived = ofType(await poll(50), 'session-revoked');
  check('the event arrives with NO event_timestamp', function () {
    assert.ok(arrived.length > 0, 'nothing arrived.');
    const payload = arrived[0].claims.events[P + 'session-revoked'];
    assert.strictEqual(
        Object.prototype.hasOwnProperty.call(payload, 'event_timestamp'),
        false);
  });
  check('AND IT IS STILL VALID, which is the whole point', function () {
    const payload = arrived[0].claims.events[P + 'session-revoked'];
    assert.ok(events.validateEvent(P + 'session-revoked', payload).ok,
        'A workflow that refused it would be refusing a conforming ' +
        'transmitter, and the receiver under test would never meet the case.');
  });
  await setSetting('caep.omitEventTimestamp', 'false');
}

// ---------------------------------------------------------------------------
// 7. THE REGISTER, AND WHAT IT KNOWS THAT NOTHING ELSE DOES.
// ---------------------------------------------------------------------------
async function theRegisterOutlivesTheSession() {
  log.info("[register] The per-session register: it counts what was " +
      "actually sent, and it outlives the session it describes — which is " +
      "the only reason a revoked session is still visible anywhere.");
  const signed = await signIn();
  if (!signed.ok) {
    skip('the register', signed.why);
    return;
  }
  await poll(50);
  await call('POST', adminUrl + '/caep/emit',
      { session_id: signed.sessionId, type: 'device-compliance-change',
        payload: JSON.stringify({ previous_status: 'compliant',
          current_status: 'not-compliant' }) }, {});
  await signOut();
  await poll(50);

  const report = await call('GET', adminUrl + '/caep', null, {});
  assert.strictEqual(report.status, 200, report.text);
  const row = (report.body.sessions || []).filter(function (one) {
    return one.sessionId === signed.sessionId;
  })[0];

  check('the session is still in the register after it was signed out',
      function () {
    assert.ok(row,
        'THE SESSION STORE FORGOT IT. This row is the only remaining ' +
        'evidence that the session existed and was revoked, and nothing ' +
        'else in this service records it.');
  });
  if (!row) {
    return;
  }
  check('and its state says revoked', function () {
    assert.strictEqual(row.state, 'revoked');
  });
  check('the device compliance it was told about is on the row', function () {
    assert.strictEqual(row.compliance, 'not-compliant');
  });
  check('the counts are per event type', function () {
    assert.ok(row.counts[P + 'device-compliance-change'] >= 1,
        JSON.stringify(row.counts));
    assert.ok(row.counts[P + 'session-revoked'] >= 1,
        JSON.stringify(row.counts));
  });
  check('and the report says which streams would take a CAEP event at all',
      function () {
    const taking = (report.body.streams || []).filter(function (one) {
      return one.takes && one.takes.length;
    });
    assert.ok(taking.length > 0,
        'A session with a count of zero almost always means nobody asked ' +
        'for that type, and SSF gives a receiver no other notice of that — ' +
        'so this list is where it shows up.');
  });
}

// ---------------------------------------------------------------------------
// 8. WHAT THE TRANSMITTER REFUSES.
// ---------------------------------------------------------------------------
async function theRefusals() {
  log.info("[refusals] The two this profile adds, and both are refusals a " +
      "permissive transmitter would not make.");

  const noSubject = await call('POST', adminUrl + '/ssf/transmit',
      { stream_id: streamId, type: P + 'session-revoked', payload: '{}' }, {});
  check('a CAEP event with NO SUBJECT is refused, and the refusal says why',
      function () {
    assert.strictEqual(noSubject.status, 400,
        'It answered ' + noSubject.status + '. A session-revoked with no ' +
        'sub_id says something happened and does not say to whom, so a ' +
        'receiver drops it with no error anybody sees.');
    const said = JSON.stringify(noSubject.body || noSubject.text);
    assert.ok(/subject/i.test(said),
        'the refusal does not mention the subject: ' + said);
  });

  const bad = await call('POST', adminUrl + '/caep/emit',
      { session_id: 'no-such-session', type: 'session-revoked' }, {});
  check('emitting about a session nobody holds is refused by name',
      function () {
    assert.strictEqual(bad.status, 400, bad.text);
    assert.ok(/no-such-session/.test(bad.text), bad.text);
  });

  const unknown = await call('POST', adminUrl + '/caep/emit',
      { session_id: 'x', type: 'account-disabled' }, {});
  check('a RISC event type is refused HERE, and the eight are named',
      function () {
    assert.strictEqual(unknown.status, 400, unknown.text);
    assert.ok(/session-revoked/.test(unknown.text),
        'a refusal a caller cannot act on is worse than none: ' +
        unknown.text);
  });
}

async function cleanUp() {
  log.info("[cleanup] Leaving the mock as it was found.");
  let i;
  for (i = 0; i < created.streams.length; i++) {
    await call('POST', adminUrl + '/ssf/delete',
        { stream_id: created.streams[i] }, {});
  }
  await restoreSettings();
  // The register is this run's litter and nothing else reads it, so it goes
  // too — but only after every assertion above has read what it needed.
  await call('POST', adminUrl + '/caep/clear', {}, {});
}

async function test() {
  log.debug("Entering test().");
  let reachable = true;
  try {
    const ping = await call('GET', adminUrl + '/caep', null, {});
    reachable = ping.status === 200;
    if (reachable && ping.body && ping.body.installed === false) {
      reachable = false;
    }
  } catch (e) {
    reachable = false;
  }
  if (!reachable) {
    // A SKIP AND NOT A FAILURE, for the reason ssf_protocol.js gives: this
    // job needs a TRANSMITTER, and a run with none has proved nothing about
    // this workflow rather than found something wrong with it.
    log.warn("No CAEP transmitter at " + adminUrl + "/caep, so this job " +
        "proves nothing and skips. Point SSF_TRANSMITTER_URL at the mock " +
        "STS, or run ./local-run-tests.sh, which starts one.");
    log.info("Test completed successfully.");
    return;
  }

  try {
    await theEightAreOffered();
    await aStreamAgreesThem();
    await signingInEmitsAnEvent();
    await namingThePersonCoversTheirSessions(realSub || WHO);
    await autoEmitOffStopsIt();
    await everyEventEmittedByHand();
    await omittingTheTimestampIsConforming();
    await theRegisterOutlivesTheSession();
    await theRefusals();
  } finally {
    await cleanUp();
  }

  log.info(checks + " checks passed, " + skips.length + " skipped.");
  skips.forEach(function (one) {
    log.warn("  skipped: " + one);
  });
  assert.ok(checks >= 20,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'twenty. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("caep_protocol")
  .description("Drive CAEP against a real transmitter with no browser: the " +
      "eight types advertised and agreed on a stream, AUTOMATIC EMISSION — " +
      "a sign-in, a single sign-on and a sign-out each producing a Security " +
      "Event Token nobody asked for — the setting that turns it off, every " +
      "one of the eight emitted by hand, the deliberate defect that is not " +
      "one, and the per-session register that outlives the session it " +
      "describes.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
