// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: caep_session_protocols.js
//
// ---------------------------------------------------------------------------
// EVERY CAEP EVENT TYPE, ABOUT A SESSION ESTABLISHED OVER EVERY BROWSER
// SIGN-IN PROTOCOL, SENT BY THE MOCK AND COLLECTED BY THE DEBUGGER — BY BOTH
// DELIVERIES.
//
// **THE CLAIM UNDER TEST IS THAT CAEP IS NOT AN OAuth2 / OIDC FEATURE.** The
// profile is a vocabulary about SESSIONS: nothing in `session-revoked` names a
// token endpoint, and it exists precisely because SAML and OpenID Connect both
// authenticate at one instant and leave a session good for hours afterwards.
// Everything on both sides of this workflow was built as though only one
// protocol could produce a session, and each half was wrong on its own:
//
//   * the MOCK reached `authn.startSession()` from every browser SSO profile
//     it has, so `session-established` and `session-revoked` were already
//     protocol-independent — but `session-presented`, which is single sign-on,
//     was emitted from the OAuth2 authorization endpoint ALONE. A receiver
//     watching a SAML session therefore saw it start and end with every single
//     sign-on between the two missing, and the evidence of the gap was a count
//     of zero, which in this protocol is also what *nobody asked for that
//     type* looks like.
//   * the DEBUGGER seeded its CAEP session from an ID Token and nothing else,
//     so four of the five sign-ins here could not be the subject of an event
//     at all.
//
// Both are fixed and this is what holds them fixed. It is one job per
// protocol — `CAEP_SIGNIN_PROTOCOL` selects it and `run-report.js` schedules
// one per value — because the SIGN-IN is the expensive half and the eight
// event types over it are cheap, and because a failure then names the protocol
// in `report.xml` rather than being one row of forty.
//
// ---------------------------------------------------------------------------
// WHY THREE OF THE EIGHT ARE DRIVEN BY THE SIGN-IN, AND FIVE BY HAND.
//
// This is the one workflow in this tree where the far end SENDS SOMETHING
// NOBODY ASKED FOR. The three session events are produced here by REALLY
// DOING THE THING, so the subject is the session this job just made:
//
//   | event               | what produces it here                       |
//   |---------------------|---------------------------------------------|
//   | session-established | signing in — over the protocol under test   |
//   | session-presented   | presenting that session again: single       |
//   |                     | sign-on, at the SAME protocol's endpoint    |
//   | session-revoked     | signing out                                 |
//
// The other five are requested from the transmitter through
// `POST /admin-api/caep/emit`, still about this session. The page
// accepts the same five from any compliant transmitter.
//
// **The order is load-bearing and is not alphabetical.** `session-revoked` is
// LAST, because the model's one hard refusal is an event about a session that
// has already ended — driving it earlier would make the five that follow
// refusals rather than events, and the failure would name the state machine
// rather than the ordering.
//
// ---------------------------------------------------------------------------
// BOTH DELIVERIES, AND THEY PROVE DIFFERENT THINGS.
//
// **Poll (RFC 8936)** is the receiver coming to the transmitter, which is
// ordinary HTTPS with a JSON body — so it is what the debugger's page does
// with no api behind it at all, and the only delivery that works on the
// deployed static sites.
//
// **Push (RFC 8935)** is the transmitter coming to the receiver, and it is
// tested through `POST /ssf/receiver` on the API because **a page is not an
// HTTP server**. That is the one thing in this whole tree a browser genuinely
// cannot do — not CORS, not a certificate — and it is why `api/ssf_receiver.js`
// exists. Sending the same eight events both ways is what catches a
// transmitter that composes an event correctly for one path and not the other.
//
// ---------------------------------------------------------------------------
// AND WHAT IT ASSERTS ABOUT WHAT ARRIVED, WHICH IS THE HALF THAT MATTERS.
//
// A test that counted eight arrivals would pass against a transmitter sending
// eight malformed events, because the defects this profile produces are never
// crashes. So every collected SET is put through **the debugger's own
// engines** — `ssf_client.js`'s RFC 8417 envelope reader, `ssf_events.js`'s
// catalogue and `caep_session.js`'s state machine — which is what "received by
// the debugger workflow" means here and is a stronger statement than "a JWT
// arrived". Note the mock has its OWN reading of RFC 9493 and this side has
// its own, deliberately: one implementation driven against another is the only
// arrangement in which a misunderstanding they share surfaces as a failure
// rather than as agreement.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { spawnSync } = require("child_process");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
const { mustBeReady } = require("./expectation.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin.js");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "caep_session_protocols",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The debugger's own engines, borrowed the way every node test here borrows
// one — see module_paths.js's header for why a bare require() breaks the
// moment a client module acquires a dependency.
const events = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_events.js", __dirname + "/ssf_events.js"],
  "ssf_events.js");
const caep = paths.requireSharedModule(
  [__dirname + "/../client/src/caep_session.js",
   __dirname + "/caep_session.js"], "caep_session.js");
const ssfClient = paths.requireSharedModule(
  [__dirname + "/../client/src/ssf_client.js", __dirname + "/ssf_client.js"],
  "ssf_client.js");

var stsUrl = process.env.SSF_TRANSMITTER_URL || process.env.STS_URL ||
    "https://localhost:8081";
var apiUrl = process.env.API_URL || "https://localhost:4000";
// WHETHER THE PUSH HALF CAN RUN AT ALL ON THIS TARGET, which is a fact about
// the DEPLOYMENT and not about the transmitter. RFC 8935 has the transmitter
// come to the RECEIVER, a page is not an HTTP server, and so the debugger's
// receive half is `POST /ssf/receiver` on the api — which a deployed static
// site does not have. `run-report.js` sets this false for such a target, from
// the same fact the SCIM and SSF api jobs are gated on. Unset (every
// containerized and every local run) means the api is there, and then an api
// that does not answer is this stack being wrong rather than a capability
// this deployment never had. The POLL half needs none of it and runs
// everywhere, which is the whole reason this is a section skip rather than a
// job skip.
var pushAvailable = process.env.SSF_PUSH_AVAILABLE !== "false";
// Which sign-in this job is about. One value per job — see the header.
var protocol = process.env.CAEP_SIGNIN_PROTOCOL || "oidc";
// THE KDC, FOR THE SPNEGO JOB ONLY, as THIS PROCESS dials it — `kinit` opens
// the socket itself, so these are KRB5_TEST_* and not KRB5_KDC_HOST, for the
// reason krb5_mit_client.js gives at length: that variable is the API's view
// of the KDC (a page types it and the relay resolves it), and `sts` means
// nothing to a process on the host. run-tests-in-container.sh sets both to
// the compose name for the bridge stack.
var kdcHost = process.env.KRB5_TEST_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_TEST_KDC_PORT || "88";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
// One password for every USER account this KDC creates on first sight — a
// published test credential from its own account policy, not a secret.
var krbPassword = process.env.KRB5_PASSWORD || "password!";

const P = events.CAEP_PREFIX;
// The eight, with session-revoked LAST for the reason the header gives.
const SHORTS = ['session-established', 'session-presented',
  'token-claims-change', 'credential-change', 'assurance-level-change',
  'device-compliance-change', 'risk-level-change', 'session-revoked'];
// The three the mock produces on its own, from a real act.
const AUTOMATIC = ['session-established', 'session-presented',
  'session-revoked'];

let checks = 0;
let failures = [];
let skips = [];
let created = [];
let receiverId = '';

function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    fn();
    checks++;
    log.info("  ok — " + what);
  } catch (e) {
    failures.push(what + ": " + e.message);
    log.error("  FAILED — " + what + ": " + e.message);
  }
  log.debug("Leaving check().");
}

// A SECTION THIS TARGET CANNOT RUN, said out loud. It is not a check and does
// not count towards the floor at the bottom — a skipped section that raised
// the tally would be a test reporting work it did not do, which is the shape
// tests/expectation.js exists to forbid.
function skip(what, why) {
  log.debug("Entering skip(). " + what);
  skips.push(what + ": " + why);
  log.warn("  SKIPPED — " + what + " — " + why);
  log.debug("Leaving skip().");
}

// ---------------------------------------------------------------------------
// THE WIRE. `fetch` with the certificate this stack regenerates every start
// already trusted through NODE_EXTRA_CA_CERTS — see tests/CLAUDE.md, and note
// the deliberate absence of NODE_TLS_REJECT_UNAUTHORIZED: three tests in this
// suite exist to assert that a bad certificate is refused, and turning
// verification off here would disarm all of them.
// ---------------------------------------------------------------------------
async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const options = { method: method, redirect: 'manual',
    headers: Object.assign({}, headers || {}) };
  if (body !== null && body !== undefined) {
    options.body = typeof body === 'string' ? body : JSON.stringify(body);
    if (typeof body !== 'string') {
      options.headers['Content-Type'] = 'application/json';
    }
  }
  const answer = await fetch(url, options);
  const text = await answer.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (e) {
    json = null;
  }
  log.debug("Leaving call(). " + answer.status);
  return { status: answer.status, headers: answer.headers, text: text,
    json: json };
}

function basic(user) {
  log.debug("Entering basic().");
  const value = 'Basic ' +
      Buffer.from(String(user) + ':pw').toString('base64');
  log.debug("Leaving basic().");
  return value;
}

// ---------------------------------------------------------------------------
// THE SIGN-IN, PER PROTOCOL — and the shape is the same for all five because
// the mock funnels all five through `authn.js`: whatever the protocol, an
// unauthenticated arrival is a 303 to `/authn/login?authn=<id>`, a POST of
// that id sets `sts_session`, and the return trip completes the flow.
//
// That sameness IS the point being tested. It is what makes
// `session-established` protocol-independent at the mock, and the reason
// `session-presented` had to be made so by hand.
//
// SPNEGO takes the same path with ONE step different: the pending sign-in is
// answered at `/authn/spnego?authn=<id>` with a Kerberos ticket rather than
// POSTed with a password, and the door's 303 back to the application is the
// password screen's 303. RFC 4559 authenticates a request and has no request
// message naming a relying party, so its application is an OIDC one — which
// also makes the authorization endpoint the door its single sign-on is
// presented at, for the reason the sign-out section below gives.
// ---------------------------------------------------------------------------
function startUrlFor(who) {
  log.debug("Entering startUrlFor(). " + protocol);
  let url = '';
  // SPNEGO is reached the way a browser reaches it: an APPLICATION asks for
  // a sign-in and the person answers it with a ticket instead of a password.
  // It has no request message of its own (RFC 4559 authenticates one HTTP
  // request and names no relying party), so the application is the OIDC one.
  if (protocol === 'oidc' || protocol === 'spnego') {
    url = stsUrl + '/oauth2/authorize?response_type=code&client_id=' +
      encodeURIComponent(clientId()) + '&redirect_uri=' +
      encodeURIComponent('https://rp.example.com/cb') +
      '&scope=openid&state=caep';
  } else if (protocol === 'saml2') {
    url = stsUrl + '/saml2/sso?SAMLRequest=' + samlRequest();
  } else if (protocol === 'saml11') {
    url = stsUrl + '/saml11/sso?TARGET=' +
      encodeURIComponent('https://rp11.example.com/acs') + '&shire=' +
      encodeURIComponent('https://rp11.example.com/acs') + '&providerId=' +
      encodeURIComponent(clientId());
  } else if (protocol === 'wsfed') {
    // A `wreply` is named and registered (provisionFor()): since iya-sts
    // #592 a request with none is refused 400 where the entry has no
    // registered reply address.
    url = stsUrl + '/wsfed?wa=wsignin1.0&wtrealm=' +
      encodeURIComponent(clientId()) + '&wreply=' +
      encodeURIComponent(WSFED_REPLY);
  }
  log.debug("Leaving startUrlFor(). " + url);
  return url;
}

// Where a WS-Federation sign-in response would be posted. Nothing listens
// there; the job stops at the session.
const WSFED_REPLY = 'https://rp.example.com/wsfed';

function clientId() {
  log.debug("Entering clientId().");
  const id = (protocol === 'oidc' || protocol === 'spnego')
    ? 'webapp1' : ('urn:caep:' + protocol);
  log.debug("Leaving clientId(). " + id);
  return id;
}

// A minimal AuthnRequest, DEFLATE-compressed and base64'd as the Redirect
// binding requires. Built here rather than recorded, because a recorded string
// rots and this one is three lines.
function samlRequest() {
  log.debug("Entering samlRequest().");
  const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:' +
    'protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_caep' +
    Date.now() + '" Version="2.0" IssueInstant="' + new Date().toISOString() +
    '" AssertionConsumerServiceURL="https://rp.example.com/acs" ' +
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">' +
    '<saml:Issuer>' + clientId() + '</saml:Issuer></samlp:AuthnRequest>';
  const packed = encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64'));
  log.debug("Leaving samlRequest().");
  return packed;
}

// ---------------------------------------------------------------------------
// THE SIGN-OUT DOOR, WHICH IS NOT ONE DOOR — AND TWO PROTOCOLS HAVE NONE.
//
// `authn.dropSession()` is shared by every sign-out here, so whichever door is
// used the session ends once and emits once. What differs is whether the
// protocol HAS a door:
//
//   * SAML 2.0 has Single Logout, at /saml2/slo.
//   * WS-Federation has wsignout1.0, section 13.2.4.
//   * OAuth 2.0 / OIDC has /oauth2/logout.
//   * **SAML 1.1 has NO Single Logout at all** — that is the protocol and not
//     a gap in the mock; `docs/saml11.md` records it as one of the five
//     things switched off rather than missing.
//   * **SPNEGO has none either**: it authenticates a request and defines
//     nothing about ending anything.
//
// So the last two use the OIDC door, and that is not a workaround — it is the
// same point this whole file is about, arrived at from the other side. There
// is ONE session cookie here and every protocol shares it, which is exactly
// why a CAEP `session-revoked` is meaningful whatever signed the person in. A
// reader who signs in over SAML 1.1 and out through any door has ended the
// same session, and the event says so.
// ---------------------------------------------------------------------------
function signOutUrlFor() {
  log.debug("Entering signOutUrlFor(). " + protocol);
  let url = stsUrl + '/oauth2/logout';
  if (protocol === 'saml2') {
    url = stsUrl + '/saml2/slo';
  } else if (protocol === 'wsfed') {
    url = stsUrl + '/wsfed?wa=wsignout1.0&wtrealm=' +
      encodeURIComponent(clientId());
  }
  log.debug("Leaving signOutUrlFor(). " + url);
  return url;
}

// Through the door signOutUrlFor() names — and through RP-Initiated Logout's
// CONFIRMATION when that door is /oauth2/logout (iya-sts #124): a GET that
// carries no id_token_hint for this session is answered with a "Sign out?"
// page, and nothing ends until its form is POSTed back with `confirm=yes` and
// the `confirm_for` value only a request carrying this session's cookie was
// shown. That is the OP confirming the End-User's intent, which section 2 of
// RP-Initiated Logout 1.0 leaves to it, and it is why oidc, saml11 and spnego
// stopped emitting session-revoked on a bare GET.
async function signOut(cookie) {
  log.debug("Entering signOut(). " + protocol);
  const url = signOutUrlFor();
  const asked = await call('GET', url, null, { Cookie: cookie });
  const found = /name="confirm_for" value="([^"]*)"/.exec(asked.text || '');
  // What the door said, by its page title: "Sign out?" asks, "Signed out"
  // with no question means it found no session for this cookie to end —
  // which is the state that sends no session-revoked at all.
  const title = (/<title>([^<]*)</.exec(asked.text || '') || [])[1] || '';
  log.info("[sign-out] " + url + " answered " + asked.status +
           (title ? ' "' + title + '"' : '') +
           (found ? ", asking to confirm." : "."));
  if (!found || url.indexOf('/oauth2/logout') < 0) {
    log.debug("Leaving signOut(). No confirmation asked: " + asked.status);
    return asked;
  }
  const out = await call('POST', url,
      'confirm=yes&confirm_for=' + encodeURIComponent(found[1]),
      { Cookie: cookie,
        'Content-Type': 'application/x-www-form-urlencoded' });
  log.info("[sign-out] the confirmation was answered " + out.status + ".");
  log.debug("Leaving signOut(). Confirmed: " + out.status);
  return out;
}

function cookieOf(answer) {
  log.debug("Entering cookieOf().");
  const raw = answer.headers.getSetCookie
    ? answer.headers.getSetCookie()
    : [answer.headers.get('set-cookie') || ''];
  let value = '';
  raw.forEach(function (one) {
    // `sts_session` since iya-sts 27b81c5; it was `sts_mock_session`.
    const found = /sts_session=([^;]+)/.exec(one || '');
    if (found) {
      value = 'sts_session=' + found[1];
    }
  });
  log.debug("Leaving cookieOf(). " + (value ? 'got one' : 'none'));
  return value;
}

async function signIn(who) {
  log.debug("Entering signIn(). " + who);
  const start = startUrlFor(who);
  const first = await call('GET', start, null, {});
  const location = first.headers.get('location') || '';
  if (!/\/authn\/login/.test(location)) {
    log.debug("Leaving signIn(). No sign-in screen.");
    return { ok: false, why: 'the ' + protocol + ' endpoint answered ' +
      first.status + ' and did not send the browser to a sign-in screen (' +
      (location || 'no Location') + '). On this stack that usually means ' +
      'the endpoint is not enabled or the request was refused before ' +
      'authentication.' };
  }
  // The screen is a static surface over /authn-api since iya-sts #571, so
  // the sign-in is the page's own act, sent the way the page sends it — or,
  // for SPNEGO, the same pending sign-in answered at the Negotiate door with
  // a Kerberos ticket instead (negotiate(), above).
  const posted = protocol === 'spnego'
    ? negotiate(who, location)
    : await authnSignin.signIn(stsUrl, new URL(location, stsUrl).href,
        { action: 'login', username: who, password: 'x' });
  let cookie = posted.next === 'redirect'
    ? (posted.cookie || cookieOf(posted)) : '';
  if (!cookie) {
    log.debug("Leaving signIn(). No cookie.");
    return { ok: false, why: 'the sign-in screen answered ' + posted.status +
      ' (' + posted.next + ') and set no session cookie: ' +
      JSON.stringify(posted.errors || []) };
  }
  // THE RETURN TRIP, which is the sign-in's own presentation and must NOT be
  // reported as single sign-on — `notePresented()` spends a one-shot flag on
  // it. If this stopped being free, every flow in this suite would emit a
  // session-presented milliseconds after its session-established and the event
  // that means SINGLE SIGN-ON HAPPENED would mean nothing.
  const back = new URL(posted.location || start, stsUrl).href;
  const returned = await call('GET', back, null, { Cookie: cookie });
  // THE CONSENT SCREEN, where the application asks for one (OAuth2/OIDC on
  // this stack, and so SPNEGO, whose application is OIDC; the other three
  // draw none). Since iya-sts 2446cbe1 the
  // authorization endpoint HOLDS the session's next presentation as it sends
  // a request to that screen, so the trip back from it is the sign-in's own
  // and not a single sign-on. Left unanswered, that hold was being spent by
  // the re-presentation in run() instead — and the session-presented that
  // means SINGLE SIGN-ON HAPPENED never came, for this protocol alone. So
  // the screen is answered here the way a person answers it, and the trip
  // back is made, which leaves the session where a finished sign-in leaves
  // it: with nothing held.
  const onward = returned.headers.get('location') || '';
  if (/consent/.test(onward)) {
    const consented = await authnSignin.consentFor(
        new URL(onward, stsUrl).href, cookie);
    if (consented.next !== 'redirect' || !consented.location) {
      log.debug("Leaving signIn(). Consent not given.");
      return { ok: false, why: 'the sign-in sent the browser to the ' +
        'consent screen (' + onward + ') and answering it did not send it ' +
        'back: ' + consented.status + ' (' + consented.next + ') ' +
        JSON.stringify(consented.errors || []) };
    }
    const rotatedAtConsent = cookieOf(consented);
    if (rotatedAtConsent && rotatedAtConsent !== cookie) {
      log.info("[session] the consent screen rotated the session cookie.");
      cookie = rotatedAtConsent;
    }
    await call('GET', new URL(consented.location, stsUrl).href, null,
               { Cookie: cookie });
    log.info("[session] the sign-in asked for consent; it was given and " +
             "the trip back to the authorization endpoint was made.");
  }
  log.debug("Leaving signIn(). Signed in.");
  return { ok: true, cookie: cookie, start: start };
}

// ---------------------------------------------------------------------------
// THE STREAMS — one per delivery, both asking for all eight types.
// ---------------------------------------------------------------------------
async function agreeStream(who, delivery) {
  log.debug("Entering agreeStream(). " + delivery.method);
  // No `aud`: SSF 1.0 section 8.1.1 makes it Transmitter-Supplied, and the
  // mock addresses the stream to whoever `who` authenticated as. Naming one
  // it does not associate with that receiver is a 400 since iya-sts #144.
  const made = await call('POST', stsUrl + '/ssf/stream', {
    delivery: delivery,
    events_requested: SHORTS.map(function (short) {
      return P + short;
    })
  }, { Authorization: basic(who) });
  if (made.status >= 300 || !made.json || !made.json.stream_id) {
    log.debug("Leaving agreeStream(). Refused.");
    return null;
  }
  created.push({ id: made.json.stream_id, who: who });
  log.debug("Leaving agreeStream(). " + made.json.stream_id);
  return made.json;
}

// The api's push inbox. It exists because A PAGE IS NOT AN HTTP SERVER — the
// one thing in this tree a browser genuinely cannot do — so this is the
// debugger's receive half for RFC 8935 and there is no way to test push
// without it.
async function openApiInbox() {
  log.debug("Entering openApiInbox().");
  let made = null;
  try {
    made = await call('POST', apiUrl + '/ssf/receiver', {});
  } catch (e) {
    // CAUGHT AND REPORTED RATHER THAN THROWN, because what undici raises for
    // a connection it could not open is `TypeError: fetch failed` whose whole
    // stack is internals — it names no URL, no service and no port. The
    // assertion below says the api was not there, which is the fact; a bare
    // stack trace here would end the job before the POLL half ran, and the
    // poll half is the one that needs no api at all.
    log.error('the api at ' + apiUrl + ' could not be reached: ' + e.message);
    log.debug("Leaving openApiInbox(). Unreachable.");
    return null;
  }
  // THE FIELD NAMES ARE THE API'S OWN AND WERE GUESSED WRONG ONCE: it answers
  // `{ ok, inbox: { id, … }, deliveryEndpoint }`, not `{ id, url }`. Reading
  // the wrong ones made this return null against a perfectly healthy api, and
  // the job then reported nine push failures whose message said the api was
  // not there — which is a test blaming a service for its own mistake, the
  // worst shape a failure can have.
  const inbox = (made.json && made.json.inbox) || null;
  const endpoint = made.json ? String(made.json.deliveryEndpoint || '') : '';
  if (made.status >= 300 || !inbox || !inbox.id || !endpoint) {
    log.debug("Leaving openApiInbox(). Refused: " + made.status);
    return null;
  }
  receiverId = String(inbox.id);
  log.debug("Leaving openApiInbox(). " + endpoint);
  return { id: inbox.id, url: endpoint };
}

// EVERY SET READ SO FAR, by jti, ACKNOWLEDGED AS IT IS READ (RFC 8936
// section 2.4). The stream covers everybody, so under the pool it also holds
// every other job's events, and a poll that acknowledges nothing returns the
// same first `maxEvents` of them each time: this session's session-revoked,
// emitted last, then never comes into view however long the loop waits —
// which failed the 54395140 run with seven of the eight arrived by poll and
// all eight by push. Acknowledging what was read moves the window on.
const polledSoFar = new Map();
async function pollSets(stream, who) {
  log.debug("Entering pollSets().");
  for (let round = 0; round < 20; round++) {
    const got = await call('POST', stsUrl + '/ssf/poll', {
      stream_id: stream.stream_id, maxEvents: 200, returnImmediately: true,
      ack: Array.from(polledSoFar.keys()).filter(function (jti) {
        return polledSoFar.get(jti).acked !== true;
      })
    }, { Authorization: basic(who) });
    polledSoFar.forEach(function (one) {
      one.acked = true;
    });
    const sets = (got.json && got.json.sets) || {};
    const fresh = Object.keys(sets).filter(function (jti) {
      return !polledSoFar.has(jti);
    });
    fresh.forEach(function (jti) {
      polledSoFar.set(jti, { token: sets[jti], acked: false });
    });
    if (!fresh.length) {
      break;
    }
  }
  log.debug("Leaving pollSets(). " + polledSoFar.size + " set(s).");
  return Array.from(polledSoFar.values()).map(function (one) {
    return one.token;
  });
}

async function pushedSets() {
  log.debug("Entering pushedSets().");
  if (!receiverId) {
    log.debug("Leaving pushedSets(). No inbox.");
    return [];
  }
  const got = await call('GET',
      apiUrl + '/ssf/receiver/' + encodeURIComponent(receiverId) + '/events');
  // Each record is `{ at, token, bytes, contentType, … }` — the SET is under
  // `token`. See the note in openApiInbox() about guessing these.
  const list = (got.json && got.json.events) || [];
  const out = list.map(function (one) {
    return typeof one === 'string' ? one : String((one && one.token) || '');
  }).filter(function (one) {
    return one !== '';
  });
  log.debug("Leaving pushedSets(). " + out.length + " set(s).");
  return out;
}

// The event type a SET carries, WITHOUT verifying its signature — this test is
// about what was sent and collected, and `ssf_engine.js` is where the envelope
// rules are asserted. A SET that will not parse counts as nothing, which is
// what makes the per-type assertion below meaningful.
function typeOf(token) {
  log.debug("Entering typeOf().");
  const parsed = ssfClient.parseSet(token);
  if (!parsed.ok) {
    log.debug("Leaving typeOf(). Unparseable.");
    return { short: '', claims: null, payload: null };
  }
  const uri = Object.keys(parsed.claims.events || {})[0] || '';
  log.debug("Leaving typeOf(). " + uri);
  return { short: uri.indexOf(P) === 0 ? uri.slice(P.length) : '',
    uri: uri, claims: parsed.claims,
    payload: (parsed.claims.events || {})[uri] || null };
}

// Does a SET read by typeOf() name this session in its complex subject?
function namesSession(read, sessionId) {
  log.debug("Entering namesSession().");
  const sub = read && read.claims ? read.claims.sub_id : null;
  const out = !!(sub && sub.session &&
      String(sub.session.id || '') === String(sessionId || ''));
  log.debug("Leaving namesSession(). " + out);
  return out;
}

// ---------------------------------------------------------------------------
// DRIVING THE FIVE THAT NOTHING HERE DOES ON ITS OWN.
// ---------------------------------------------------------------------------
function specimenFor(short) {
  log.debug("Entering specimenFor(). " + short);
  const bodies = {
    'token-claims-change': { claims: { role: 'ops' } },
    'credential-change': { credential_type: 'password',
      change_type: 'update' },
    'assurance-level-change': { namespace: 'nist-aal',
      current_level: 'nist-aal2', previous_level: 'nist-aal1',
      change_direction: 'increase' },
    'device-compliance-change': { current_status: 'not-compliant',
      previous_status: 'compliant' },
    'risk-level-change': { principal: 'user', current_level: 'HIGH',
      previous_level: 'LOW', risk_reason: 'a test drove it' }
  };
  log.debug("Leaving specimenFor().");
  return bodies[short] || {};
}

async function emitByHand(sessionId, short) {
  log.debug("Entering emitByHand(). " + short);
  // `payload` is a STRING of JSON and not an object: the management API
  // mirrors the console's form, where it is a textarea, and since the
  // 2026-09-09 submodule bump the body is validated against that schema —
  // an object is refused with `"payload" must be string.`, a 400 that names
  // the member rather than the event type, on all five of the types that are
  // only ever produced this way. `caep_protocol.js` has always stringified.
  const sent = await call('POST', stsUrl + '/admin-api/caep/emit', {
    session_id: sessionId, type: short, initiating_entity: 'admin',
    payload: JSON.stringify(specimenFor(short))
  });
  log.debug("Leaving emitByHand(). " + sent.status);
  return sent;
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  try {
    const doc = await fetch(stsUrl + '/.well-known/ssf-configuration');
    if (!doc.ok) {
      log.debug("Leaving preconditions(). No transmitter.");
      return { ok: false, why: 'no SSF transmitter at ' + stsUrl +
        ' (/.well-known/ssf-configuration answered ' + doc.status + ')' };
    }
  } catch (e) {
    log.debug("Leaving preconditions(). " + e.message);
    return { ok: false, why: 'nothing answered at ' + stsUrl + ': ' +
      e.message };
  }
  log.debug("Leaving preconditions(). Ready.");
  return { ok: true, why: '' };
}

// ---------------------------------------------------------------------------
// SPNEGO, ANSWERED WITH A REAL KERBEROS TICKET.
//
// `/authn/spnego` calls `startSession()` like every other door at the mock,
// so a SPNEGO sign-in produces a CAEP session and emits. What it asks for is
// a ticket: the door answers `401 WWW-Authenticate: Negotiate`, and the only
// acceptable reply is an AP-REQ for the acceptor's principal, wrapped in
// SPNEGO. The mock is its own KDC on this stack, so the ticket comes from
// there, obtained the way any workstation obtains one:
//
//   1. `kinit <who>` — an AS exchange for a TGT. The KDC creates an account
//      for any name on first sight (its `accountPolicy`), so the person this
//      job signs in is a name generated for this run, exactly as for the
//      other four protocols, and the CAEP row is found by that name.
//   2. `curl --negotiate` at `/authn/spnego?authn=<the interrupted sign-in>`
//      — GSSAPI asks the KDC for a service ticket for `HTTP/<host>` (the TGS
//      exchange) and answers the 401 with it. The door accepts it, starts
//      the session and sends the browser back to the application with a 303,
//      which is the same shape the password screen ends in.
//
// MIT Kerberos and a GSSAPI-capable curl are what `krb5_mit_client.js` uses,
// and `tests/Dockerfile` installs both (`krb5-user`, and Ubuntu's curl, which
// is built with GSS-API). It is a client nobody here wrote, which is the right
// thing to hold the mock's acceptor to. Their ABSENCE IS A FAILURE and not a
// skip: they are a package install, not money or hardware, and a job that
// declines to run where a package is missing is a job that never runs.
//
// Everything Kerberos touches lives in a temporary directory of this run's
// own — `KRB5_CONFIG` and `KRB5CCNAME` point into it — so nothing reads or
// writes `/etc/krb5.conf` or the machine's own credential cache, and the
// directory is removed in cleanUp() whatever happened.
// ---------------------------------------------------------------------------
var krbDir = null;
var krbConfig = null;
var krbTools = { kinit: '', curl: '' };
// curl's view of the mock's certificate. Node trusts it through
// NODE_EXTRA_CA_CERTS; curl is a separate program and has to be told.
var curlTls = [];

function toolPath(name) {
  log.debug("Entering toolPath(). " + name);
  const found = spawnSync("sh", ["-c", "command -v " + name],
      { encoding: "utf8" });
  const resolved = String(found.stdout || "").trim();
  log.debug("Leaving toolPath(). " + (resolved || "(absent)"));
  return resolved;
}

// One MIT or curl command, inside this run's Kerberos directory. spawnSync
// with an argument list, so nothing is shell-quoted, and the password goes
// in on stdin, so it is on no process listing.
function krbRun(command, args, input) {
  log.debug("Entering krbRun(). " + path.basename(command));
  const result = spawnSync(command, args, {
    input: input || "",
    encoding: "utf8",
    timeout: 60000,
    env: Object.assign({}, process.env, {
      KRB5_CONFIG: krbConfig,
      KRB5CCNAME: "FILE:" + path.join(krbDir, "ccache")
    })
  });
  const answer = { status: result.status,
    stdout: String(result.stdout || ""),
    stderr: String(result.stderr || "") };
  log.debug("Leaving krbRun(). status=" + answer.status);
  return answer;
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  let host = String(url);
  try {
    host = new URL(String(url)).hostname;
  } catch (e) {
    log.debug("Leaving hostOf(). Unparseable.");
    return host;
  }
  log.debug("Leaving hostOf(). " + host);
  return host;
}

// THE CONFIGURATION, the same settings krb5_mit_client.js writes and for the
// reasons it records beside each one. The three that cost runs are the ones
// that stop MIT rewriting the HOSTNAME before it derives the SPN — forward
// and reverse canonicalization, and qualifying a short name with the
// resolver's search domain, which on the compose network turned `sts` into
// `sts.<host's domain>`: a principal the KDC does not have, a TGS refusal,
// and curl sending NO Authorization header at all — so the door's ordinary
// bare 401 is what a test then sees, naming nothing about DNS.
function writeKrb5Config() {
  log.debug("Entering writeKrb5Config().");
  krbDir = fs.mkdtempSync(path.join(os.tmpdir(),
      "caep-spnego-" + process.pid + "-"));
  krbConfig = path.join(krbDir, "krb5.conf");
  const host = hostOf(stsUrl);
  fs.writeFileSync(krbConfig, [
    "[libdefaults]",
    "    default_realm = " + realm,
    "    dns_lookup_kdc = false",
    "    dns_lookup_realm = false",
    "    dns_canonicalize_hostname = false",
    "    rdns = false",
    // The quotes are syntax: a bare `qualify_shortname =` is a parse error.
    "    qualify_shortname = \"\"",
    "    udp_preference_limit = 1",
    "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 " +
    "aes128-cts-hmac-sha1-96",
    "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 " +
    "aes128-cts-hmac-sha1-96",
    "    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
    "",
    "[realms]",
    "    " + realm + " = {",
    "        kdc = " + kdcHost + ":" + kdcPort,
    "    }",
    "",
    "[domain_realm]",
    "    " + host + " = " + realm,
    "    ." + host + " = " + realm,
    ""
  ].join("\n"), "utf8");
  log.info("[kerberos] this run's configuration is " + krbConfig +
      ", pointing at " + kdcHost + ":" + kdcPort + " for " + realm + ".");
  log.debug("Leaving writeKrb5Config().");
}

// Everything the SPNEGO sign-in needs before the door is asked, and a TGT
// for `who` at the end of it. Every way this can go wrong is a FAILURE with
// a sentence naming what was missing — see the section header for why none
// of them is a skip.
function kerberosReady(who) {
  log.debug("Entering kerberosReady(). " + who);
  krbTools.kinit = toolPath("kinit");
  krbTools.curl = toolPath("curl");
  if (!krbTools.kinit || !krbTools.curl) {
    log.debug("Leaving kerberosReady(). Tools missing.");
    return { ok: false, why: 'the SPNEGO sign-in needs MIT Kerberos\'s ' +
      'kinit and a curl built with GSS-API, and this machine has ' +
      (krbTools.kinit ? '' : 'no kinit ') + (krbTools.curl ? '' : 'no curl') +
      '. Install `krb5-user` and curl — tests/Dockerfile does, so the ' +
      'containerized suite always has them.' };
  }
  const banner = spawnSync(krbTools.curl, ["-V"], { encoding: "utf8" });
  if (!/GSS-API/.test(String(banner.stdout)) ||
      !/SPNEGO/.test(String(banner.stdout))) {
    log.debug("Leaving kerberosReady(). curl without GSS-API.");
    return { ok: false, why: 'this curl was built without GSS-API/SPNEGO, ' +
      'so --negotiate would send no Authorization header and the door ' +
      'would read it as nobody answering its challenge. Use a curl built ' +
      'with GSS-API (Ubuntu\'s is; tests/Dockerfile installs it).' };
  }
  // The bundle node verifies this job's own fetches against, so the two
  // halves of the sign-in trust the same thing; STS_CA_FILE where only that
  // is set, as krb5_mit_client.js reads it.
  const anchor = process.env.NODE_EXTRA_CA_CERTS || process.env.STS_CA_FILE;
  if (/^https:/i.test(stsUrl)) {
    if (anchor && fs.existsSync(anchor)) {
      curlTls = ["--cacert", anchor];
    } else {
      // The node half of this job verifies the mock through
      // NODE_EXTRA_CA_CERTS; with neither variable set there is no anchor to
      // hand curl, and refusing the sign-in for a TLS reason would fail a
      // job about CAEP. Said out loud, for this one hop only.
      curlTls = ["-k"];
      log.warn("[kerberos] neither NODE_EXTRA_CA_CERTS nor STS_CA_FILE " +
          "names a certificate, so curl will NOT verify the mock's TLS " +
          "certificate for the SPNEGO request.");
    }
  }
  writeKrb5Config();
  const got = krbRun(krbTools.kinit, [who + "@" + realm], krbPassword + "\n");
  if (got.status !== 0) {
    log.debug("Leaving kerberosReady(). kinit refused.");
    return { ok: false, why: 'kinit could not get a TGT for ' + who + '@' +
      realm + ' from the KDC at ' + kdcHost + ':' + kdcPort + ': ' +
      got.stderr.trim().slice(0, 300) + '. This KDC creates any account ' +
      'on first sight unless accountPolicy.anyUsernameAuthenticates is off; ' +
      'KRB5_TEST_KDC_HOST / KRB5_TEST_KDC_PORT say where it is.' };
  }
  log.info("[kerberos] kinit got a TGT for " + who + "@" + realm + ".");
  log.debug("Leaving kerberosReady(). Ready.");
  return { ok: true, why: '' };
}

// The value of one header out of curl's `-D -` block, case-insensitively, and
// every occurrence: Set-Cookie may repeat.
function headerValues(block, name) {
  log.debug("Entering headerValues(). " + name);
  const wanted = String(name).toLowerCase();
  const found = String(block).split(/\r?\n/).map(function (line) {
    const at = line.indexOf(":");
    if (at < 0 || line.slice(0, at).trim().toLowerCase() !== wanted) {
      return null;
    }
    return line.slice(at + 1).trim();
  }).filter(function (one) {
    return one !== null;
  });
  log.debug("Leaving headerValues(). " + found.length);
  return found;
}

// ANSWERING THE SIGN-IN SCREEN WITH A TICKET rather than a password. The
// screen's address carries the interrupted request (`?authn=`), and the
// SPNEGO door takes the same parameter — so the door completes the same
// pending sign-in the password screen would have, and its 303 goes back to
// the application. Returns the shape authn_signin.js's signIn() does, with
// the session cookie already read out of curl's headers.
//
// The FINAL response's headers are the ones read: curl prints every hop's
// block, and the first is the bare 401 that challenged it.
function negotiate(who, screen) {
  log.debug("Entering negotiate(). " + who);
  const ready = kerberosReady(who);
  if (!ready.ok) {
    log.debug("Leaving negotiate(). Not ready.");
    return { status: 0, next: 'error', errors: [ready.why] };
  }
  const pending = new URL(screen, stsUrl).searchParams.get('authn') || '';
  const door = stsUrl + '/authn/spnego' +
      (pending ? '?authn=' + encodeURIComponent(pending) : '');
  const result = krbRun(krbTools.curl, ["-s", "-S", "-D", "-", "-o",
    "/dev/null"].concat(curlTls).concat(["--negotiate", "-u", ":", door]));
  const blocks = result.stdout.split(/\r?\n\r?\n/).filter(function (one) {
    return /^HTTP\//.test(one);
  });
  const last = blocks[blocks.length - 1] || '';
  const status = Number((/^HTTP\/[\d.]+ (\d+)/.exec(last) || [])[1] || 0);
  const location = headerValues(last, 'location')[0] || '';
  let cookie = '';
  headerValues(last, 'set-cookie').forEach(function (one) {
    const found = /sts_session=([^;]+)/.exec(one);
    if (found) {
      cookie = 'sts_session=' + found[1];
    }
  });
  log.info("[kerberos] " + door + " answered " + status + " (" +
      blocks.length + " response(s) shown)" +
      (cookie ? ", setting a session." : "."));
  if (status !== 303 || !cookie) {
    log.debug("Leaving negotiate(). Refused.");
    return { status: status, next: 'error',
      errors: ['the SPNEGO door answered ' + status + ' (' +
        blocks.length + ' response(s) shown)' +
        (cookie ? '' : ' and set no session cookie') +
        '. A bare 401 at the end means curl sent no ' +
        'ticket at all — usually a service ticket for an SPN the KDC does ' +
        'not have (the door names the hosts it accepts in ' +
        'X-Krb5-Accepts-Spn-Hosts: ' +
        (headerValues(last, 'x-krb5-accepts-spn-hosts')[0] || 'not sent') +
        '). curl said: ' + result.stderr.trim().slice(0, 200)] };
  }
  log.debug("Leaving negotiate(). Signed in.");
  return { status: status, next: 'redirect', location: location,
    cookie: cookie };
}

// Why the push half is not being run here. It is a sentence about the TARGET
// and not about the transmitter, which is the distinction that matters when
// somebody reads this in a report: the mock composed and would have sent the
// events, and there was nowhere for them to land.
function pushNeedsAnApi() {
  log.debug("Entering pushNeedsAnApi().");
  const why = 'RFC 8935 has the TRANSMITTER come to the receiver, and a page ' +
    'is not an HTTP server — so the debugger\'s receive half is POST ' +
    '/ssf/receiver on the api, and a deployed static site has no api at all ' +
    'to host it. That is the protocol rather than a property of this build. ' +
    'The POLL half below needs none of it and is the delivery those sites ' +
    'really use, so it still runs and still says what the mock emitted. Run ' +
    'this against the containerized stack (./docker-run-tests.sh) or a local ' +
    'dev server, or set LDAP_AVAILABLE=true for a remote target that IS ' +
    'api-backed.';
  log.debug("Leaving pushNeedsAnApi().");
  return why;
}

async function run() {
  log.debug("Entering run().");
  const who = usernameFor('caep-' + protocol);
  log.info("=== " + protocol + ", as " + who + " ===");

  // Every identifier this job presents is registered first — the rule
  // tests/CLAUDE.md states, and the reason is that the mock creates an entry
  // from the SIGHTING otherwise, so what it then knows is the identifier and
  // nothing else.
  await registry.provision(registry.stsBaseFor(stsUrl), {
    identifier: clientId(),
    fields: protocol === 'wsfed' ? { wsfedReplyUrl: [WSFED_REPLY] } : {},
    why: 'the ' + protocol + ' sign-in this CAEP job drives'
  });

  // NOT EVEN ASKED FOR when this target has no api: a POST to an api that is
  // not there is a `fetch failed` in the log of a job that was never going to
  // use the answer, and it reads as the failure this skip exists to replace.
  const inbox = pushAvailable ? await openApiInbox() : null;
  const pollStream = await agreeStream(who, { method: 'urn:ietf:rfc:8936' });
  const pushStream = inbox
    ? await agreeStream(who, { method: 'urn:ietf:rfc:8935',
        endpoint_url: inbox.url })
    : null;

  check('a stream agrees all eight CAEP types for POLL delivery — and what ' +
      'comes back is events_DELIVERED, which is a receiver\'s only notice ' +
      'that a type it asked for will never arrive', function () {
        assert.ok(pollStream, 'the transmitter refused the poll stream');
        assert.strictEqual((pollStream.events_delivered || []).length, 8,
          'the transmitter delivers ' +
          (pollStream.events_delivered || []).length + ' of the eight asked ' +
          'for. A type missing here is one nothing will ever send.');
      });
  if (pushAvailable) {
    check('and a second stream agrees them for PUSH delivery, through the ' +
        'api\'s receiver — which exists for the one thing a browser ' +
        'genuinely cannot do: a page is not an HTTP server', function () {
          assert.ok(inbox, 'the api at ' + apiUrl + ' opened no push inbox. ' +
            'It is POST /ssf/receiver there, and run-report.js only ' +
            'schedules this job with SSF_PUSH_AVAILABLE unset for a target ' +
            'it believes has an api — so an api that is not there is this ' +
            'stack being wrong rather than this deployment not having the ' +
            'capability.');
          assert.ok(pushStream, 'the transmitter refused the push stream');
        });
  } else {
    skip('the PUSH half — the second stream, the api\'s RFC 8935 receiver ' +
        'and the eight arrivals through it', pushNeedsAnApi());
  }

  // --- the three that happen on their own -------------------------------
  const session = await signIn(who);
  check('a ' + protocol + ' sign-in completes at the mock — every browser ' +
      'SSO profile there reaches ONE funnel, authn.startSession(), which is ' +
      'what makes session-established protocol-independent', function () {
        assert.ok(session.ok, session.why || 'the sign-in did not complete');
      });
  if (!session.ok) {
    log.debug("Leaving run(). No session.");
    return;
  }

  // SINGLE SIGN-ON: the same session, presented again at the same protocol's
  // endpoint. Until 2026-09-03 only the OAuth2 authorization endpoint called
  // notePresented(), so for three of these five protocols this produced
  // NOTHING — silently, with a count of zero that reads exactly like a stream
  // nobody subscribed.
  //
  // A FRESH START URL rather than `session.start` again: for SAML 2.0 that
  // carries the AuthnRequest the sign-in already answered, and since the
  // 2026-09 bump the mock refuses a replayed one ("That AuthnRequest has
  // already been answered", a 400) before the session is looked at — so the
  // re-presentation emitted nothing and read as a missing session-presented.
  // The other four build the same URL either way.
  const presented = await call('GET', startUrlFor(who), null,
                               { Cookie: session.cookie });
  // A presentation may ROTATE the session's handle and send the new cookie;
  // the old one then names no live session, and the sign-out below would
  // end nothing and send no session-revoked. So the cookie is taken up the
  // way a browser takes it up.
  const rotated = cookieOf(presented);
  if (rotated && rotated !== session.cookie) {
    log.info("[session] the presentation rotated the session cookie.");
    session.cookie = rotated;
  }

  // Which session the register filed it under, so the five by-hand events can
  // name it. Read off the mock rather than guessed: the identifier is random.
  const listed = await call('GET', stsUrl + '/admin-api/caep');
  let row = null;
  ((listed.json && listed.json.sessions) || []).forEach(function (one) {
    if (String(one.username || '') === who) {
      row = one;
    }
  });
  check('the mock filed a CAEP session row for this sign-in, naming the ' +
      'protocol that made it', function () {
        assert.ok(row, 'no row on /admin-api/caep for ' + who);
      });
  if (!row) {
    log.debug("Leaving run(). No row.");
    return;
  }
  // AND FOR SPNEGO, THAT THE TICKET MADE IT. The application here is the
  // OIDC one, so a session minted by the password screen would satisfy every
  // other check in this file; the row's protocol is what tells the two apart.
  if (protocol === 'spnego') {
    check('the session was minted by the Kerberos ticket at /authn/spnego ' +
        'and not by a password screen', function () {
          assert.ok(/SPNEGO/.test(String(row.protocol || '')),
            'the CAEP row names its protocol as "' + row.protocol + '"');
        });
  }

  // --- the five this job asks the transmitter for, so the subject is
  // this session.
  const byHand = SHORTS.filter(function (short) {
    return AUTOMATIC.indexOf(short) < 0;
  });
  for (const short of byHand) {
    const sent = await emitByHand(row.sessionId, short);
    check(short + ' can be emitted by hand about a ' + protocol +
        ' session', function () {
          assert.ok(sent.status < 300, 'the mock answered ' + sent.status +
            ': ' + sent.text.slice(0, 200));
        });
  }

  // --- and the sign-out, LAST, for the reason the header gives ----------
  await signOut(session.cookie);

  // --- what arrived, by both deliveries ---------------------------------
  // An emitted event reaches the stream ASYNCHRONOUSLY: the sign-out is
  // answered before the session-revoked about it is queued, and a push is a
  // further hop. So wait — up to fifteen seconds — until the revocation of
  // THIS session has arrived by poll (and by push, where there is push),
  // rather than reading whatever had arrived the instant the answer came.
  // Nothing here acknowledges, so each read is everything so far.
  let polled = [];
  let pushed = [];
  const revokedHere = function (tokens) {
    return tokens.some(function (token) {
      const read = typeOf(token);
      return read.short === 'session-revoked' &&
             namesSession(read, row.sessionId);
    });
  };
  const deadline = Date.now() + 15000;
  for (;;) {
    polled = await pollSets(pollStream, who);
    pushed = await pushedSets();
    if ((revokedHere(polled) && (!pushAvailable || revokedHere(pushed))) ||
        Date.now() >= deadline) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  const seen = { poll: {}, push: {} };
  const model = caep.newSession({ iss: stsUrl, sub: row.sub,
    sid: row.sessionId });

  // THE STREAM COVERS EVERYBODY (an empty subject list), so it also carries
  // what every other job signing in to this mock at the same moment caused —
  // and with the suite in a pool, somebody always is. The event about THIS
  // session wins over one about somebody else's; without that, the last
  // session-established on the stream decided which session the checks
  // below read, and a neighbour's sign-in failed this job.
  [['poll', polled], ['push', pushed]].forEach(function (pair) {
    pair[1].forEach(function (token) {
      const read = typeOf(token);
      if (!read.short) {
        return;
      }
      const held = seen[pair[0]][read.short];
      if (!held || !namesSession(held, row.sessionId) ||
          namesSession(read, row.sessionId)) {
        seen[pair[0]][read.short] = read;
      }
    });
  });

  SHORTS.forEach(function (short) {
    check(short + ' reached the debugger by POLL — the delivery that needs ' +
        'no api and is the only one the deployed static sites can use',
      function () {
        assert.ok(seen.poll[short],
          'nothing of that type arrived. Collected by poll: ' +
          (Object.keys(seen.poll).join(', ') || '(nothing)') + '.' +
          (AUTOMATIC.indexOf(short) >= 0
            ? ' This is one of the three the mock emits ON ITS OWN, from a ' +
              'real act — so either the act did not reach authn.js\'s ' +
              'funnel for ' + protocol + ', or nothing calls the observer ' +
              'for it. session-presented is the one that was missing for ' +
              'every protocol but OIDC.'
            : ' This one is emitted by hand, so the emit above succeeded ' +
              'and the stream did not carry it.'));
      });
    if (pushAvailable) {
      check(short + ' reached the debugger by PUSH as well, through the ' +
          'api\'s RFC 8935 receiver', function () {
            assert.ok(seen.push[short],
              'nothing of that type arrived by push. Collected by push: ' +
              (Object.keys(seen.push).join(', ') || '(nothing)') + '. A type ' +
              'that arrives one way and not the other is a transmitter ' +
              'composing an event correctly for one path and not the other.');
          });
    }
    // AND IT IS AN EVENT THIS WORKFLOW UNDERSTANDS, which is the half a
    // count of arrivals cannot see: the defects this profile produces are
    // never crashes, and an event that validates against nothing looks
    // exactly like one that validates.
    check(short + ' is accepted by the debugger\'s OWN catalogue — the mock ' +
        'and this side read the specification separately, so agreement here ' +
        'is two readings agreeing rather than one implementation with itself',
      function () {
        const read = seen.poll[short] || seen.push[short];
        assert.ok(read, 'nothing of that type arrived at all');
        const verdict = events.validateEvent(read.uri, read.payload || {});
        assert.strictEqual(verdict.ok, true,
          'the debugger refuses what the mock sent: ' +
          (verdict.errors || []).join(' '));
      });
  });

  // The subject, which is the thing a receiver acts on and the easiest to get
  // wrong in a way nothing reports.
  check('every event names a COMPLEX subject carrying the session — a ' +
      'subject naming only the person asks a receiver to end EVERY session ' +
      'they have, which is a much larger instruction and looks perfectly ' +
      'reasonable in a log', function () {
        const missing = [];
        SHORTS.forEach(function (short) {
          const read = seen.poll[short] || seen.push[short];
          const sub = read && read.claims ? read.claims.sub_id : null;
          if (!sub || !sub.session || !sub.session.id) {
            missing.push(short);
          }
        });
        assert.deepStrictEqual(missing, []);
      });
  check('and the session it names is the one this job signed in with, so ' +
      'these events are about a session the far end really holds rather ' +
      'than an identifier somebody invented', function () {
        const read = seen.poll['session-established'] ||
            seen.push['session-established'];
        assert.ok(read, 'no session-established to read');
        assert.strictEqual(read.claims.sub_id.session.id, model.sid);
      });
  log.debug("Leaving run().");
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  if (krbDir) {
    try {
      fs.rmSync(krbDir, { recursive: true, force: true });
    } catch (e) {
      // Untidy and harmless; not worth failing a passing run over.
      log.warn("could not remove " + krbDir + ": " + e.message);
    }
  }
  for (const one of created) {
    await call('DELETE', stsUrl + '/ssf/stream',
        { stream_id: one.id }, { Authorization: basic(one.who) });
  }
  if (receiverId) {
    await call('DELETE',
        apiUrl + '/ssf/receiver/' + encodeURIComponent(receiverId));
  }
  log.debug("Leaving cleanUp().");
}

async function test() {
  log.debug("Entering test().");
  const ready = await preconditions();
  // A transmitter the launcher expected and did not get is a FAILURE and not a
  // skip — tests/CLAUDE.md's "a test that does not run is not a passing test".
  mustBeReady(ready, 'a mock STS with Shared Signals at ' + stsUrl);
  let failed = false;
  try {
    await run();
  } catch (e) {
    log.error(e.stack || e.message);
    failed = true;
  } finally {
    await cleanUp();
  }
  if (failures.length) {
    failures.forEach(function (one) {
      log.error("FAILED: " + one);
    });
    failed = true;
  }
  if (failed) {
    log.error(checks + " check(s) passed, " + failures.length + " failed.");
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.info(checks + " checks passed.");
  if (skips.length) {
    log.warn(skips.length + " section(s) skipped:");
    skips.forEach(function (why) {
      log.warn("  - " + why);
    });
  }
  // A FLOOR, for the reason ssf_engine.js gives: a section that stops being
  // called is a suite that quietly stops testing something. IT MOVES WITH THE
  // MODE rather than being set to the smaller of the two — nine of the
  // thirty-five checks here are the push half, and a floor low enough to
  // clear without them is a floor that would not notice them going missing on
  // a stack that has an api.
  const floor = pushAvailable ? 33 : 24;
  assert.ok(checks >= floor,
    'Only ' + checks + ' checks ran and this file defines at least ' + floor +
    ' for a protocol that signs in' +
    (pushAvailable ? '' : ' on a target with no api, where the push half is ' +
      'skipped') + '. A section stopped running.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("caep_session_protocols")
  .description("Every CAEP event type, about a session established over the " +
      "sign-in protocol named by CAEP_SIGNIN_PROTOCOL, sent by the mock and " +
      "collected by the debugger over BOTH deliveries — and put through the " +
      "debugger's own catalogue rather than merely counted.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test drives the transmitter and the api " +
      "directly and needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
