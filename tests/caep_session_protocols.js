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
// WHY THE THREE AUTOMATIC EVENTS ARE DRIVEN DIFFERENTLY FROM THE OTHER FIVE.
//
// This is the one workflow in this tree where the far end SENDS SOMETHING
// NOBODY ASKED FOR, and the three that do it can only be produced by REALLY
// DOING THE THING:
//
//   | event               | what produces it                            |
//   |---------------------|---------------------------------------------|
//   | session-established | signing in — over the protocol under test   |
//   | session-presented   | presenting that session again: single       |
//   |                     | sign-on, at the SAME protocol's endpoint    |
//   | session-revoked     | signing out                                 |
//
// So this job signs in, comes back, and signs out, over the protocol it was
// given — and the other five, which describe things nothing in a mock does
// (no device reports compliance to it and no risk engine talks to it), are
// emitted through `POST /admin-api/caep/emit`.
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
const zlib = require("zlib");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
const { mustBeReady, declineToRun } = require("./expectation.js");
const registry = require("./sts_applications.js");
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
// that id sets `sts_mock_session`, and the return trip completes the flow.
//
// That sameness IS the point being tested. It is what makes
// `session-established` protocol-independent at the mock, and the reason
// `session-presented` had to be made so by hand.
// ---------------------------------------------------------------------------
function startUrlFor(who) {
  log.debug("Entering startUrlFor(). " + protocol);
  let url = '';
  if (protocol === 'oidc') {
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
    url = stsUrl + '/wsfed?wa=wsignin1.0&wtrealm=' +
      encodeURIComponent(clientId());
  } else if (protocol === 'spnego') {
    url = stsUrl + '/authn/spnego';
  }
  log.debug("Leaving startUrlFor(). " + url);
  return url;
}

function clientId() {
  log.debug("Entering clientId().");
  const id = protocol === 'oidc' ? 'webapp1' : ('urn:caep:' + protocol);
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

function cookieOf(answer) {
  log.debug("Entering cookieOf().");
  const raw = answer.headers.getSetCookie
    ? answer.headers.getSetCookie()
    : [answer.headers.get('set-cookie') || ''];
  let value = '';
  raw.forEach(function (one) {
    const found = /sts_mock_session=([^;]+)/.exec(one || '');
    if (found) {
      value = 'sts_mock_session=' + found[1];
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
  const id = new URL(location, stsUrl).searchParams.get('authn');
  const form = 'authn_id=' + encodeURIComponent(id) + '&username=' +
      encodeURIComponent(who) + '&password=x';
  const posted = await call('POST', stsUrl + '/authn/login', form,
      { 'Content-Type': 'application/x-www-form-urlencoded' });
  const cookie = cookieOf(posted);
  if (!cookie) {
    log.debug("Leaving signIn(). No cookie.");
    return { ok: false, why: 'the sign-in screen accepted the form (' +
      posted.status + ') and set no session cookie' };
  }
  // THE RETURN TRIP, which is the sign-in's own presentation and must NOT be
  // reported as single sign-on — `notePresented()` spends a one-shot flag on
  // it. If this stopped being free, every flow in this suite would emit a
  // session-presented milliseconds after its session-established and the event
  // that means SINGLE SIGN-ON HAPPENED would mean nothing.
  const back = new URL(posted.headers.get('location') || start, stsUrl).href;
  await call('GET', back, null, { Cookie: cookie });
  log.debug("Leaving signIn(). Signed in.");
  return { ok: true, cookie: cookie, start: start };
}

// ---------------------------------------------------------------------------
// THE STREAMS — one per delivery, both asking for all eight types.
// ---------------------------------------------------------------------------
async function agreeStream(who, delivery) {
  log.debug("Entering agreeStream(). " + delivery.method);
  const made = await call('POST', stsUrl + '/ssf/stream', {
    delivery: delivery,
    aud: 'https://caep-protocols.example/receiver',
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

async function pollSets(stream, who) {
  log.debug("Entering pollSets().");
  const got = await call('POST', stsUrl + '/ssf/poll', {
    stream_id: stream.stream_id, maxEvents: 200, returnImmediately: true
  }, { Authorization: basic(who) });
  const sets = (got.json && got.json.sets) || {};
  log.debug("Leaving pollSets(). " + Object.keys(sets).length + " set(s).");
  return Object.keys(sets).map(function (jti) {
    return sets[jti];
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
  const sent = await call('POST', stsUrl + '/admin-api/caep/emit', {
    session_id: sessionId, type: short, initiating_entity: 'admin',
    payload: specimenFor(short)
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
// SPNEGO IS DEFERRED RATHER THAN FAKED, and this is the same deferral
// tests/CLAUDE.md already records for the federation grid's twenty-five
// missing points — for the same reason and with the same half of it now
// closed.
//
// The MOCK side is real: `/authn/spnego` calls `startSession()` like every
// other door there, so a SPNEGO sign-in DOES produce a CAEP session and DOES
// emit. What is missing is this end. `GET /authn/spnego` answers
// `401 WWW-Authenticate: Negotiate`, and answering that needs a Kerberos
// service ticket for the acceptor — which means a KDC, a keytab and a
// credential cache. `krb5_mit_client.js` is the one job here that has all
// three, because it drives MIT Kerberos itself and the image installs
// `krb5-user` for it.
//
// So this SKIPS with a reason naming exactly what it would need, rather than
// failing (which would report a defect that is not there) or asserting
// nothing (which is the "a test that does not run is not a passing test"
// failure this directory has a whole section about). `declineToRun()` makes it
// an amber SKIP with its reason in `report.xml` rather than a silent pass.
// ---------------------------------------------------------------------------
function spnegoNeedsATicket() {
  log.debug("Entering spnegoNeedsATicket().");
  const why = 'SPNEGO cannot be driven from this job yet. The mock side is ' +
    'ready — /authn/spnego calls startSession() like every other door there, ' +
    'so a SPNEGO sign-in does produce a CAEP session and does emit — but ' +
    'that endpoint answers 401 WWW-Authenticate: Negotiate, and answering it ' +
    'needs a Kerberos service ticket: a KDC, a keytab and a credential ' +
    'cache. tests/krb5_mit_client.js is the only job here that has them, ' +
    'because it drives MIT Kerberos itself and the image installs ' +
    'krb5-user for it. Giving this job the same would close it.';
  log.debug("Leaving spnegoNeedsATicket().");
  return why;
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
  if (protocol === 'spnego') {
    declineToRun(log, spnegoNeedsATicket());
    log.debug("Leaving run(). Deferred.");
    return { skipped: true };
  }
  const who = usernameFor('caep-' + protocol);
  log.info("=== " + protocol + ", as " + who + " ===");

  // Every identifier this job presents is registered first — the rule
  // tests/CLAUDE.md states, and the reason is that the mock creates an entry
  // from the SIGHTING otherwise, so what it then knows is the identifier and
  // nothing else.
  await registry.provision(registry.stsBaseFor(stsUrl), {
    identifier: clientId(),
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
  await call('GET', session.start, null, { Cookie: session.cookie });

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

  // --- the five that nothing here does on its own -----------------------
  const byHand = SHORTS.filter(function (short) {
    return AUTOMATIC.indexOf(short) < 0;
  });
  for (const short of byHand) {
    const sent = await emitByHand(row.sessionId, short);
    check(short + ' can be emitted by hand about a ' + protocol + ' session ' +
        '— five of the eight describe things nothing in a mock does, so this ' +
        'is the only way they are ever produced', function () {
          assert.ok(sent.status < 300, 'the mock answered ' + sent.status +
            ': ' + sent.text.slice(0, 200));
        });
  }

  // --- and the sign-out, LAST, for the reason the header gives ----------
  await call('GET', signOutUrlFor(), null, { Cookie: session.cookie });

  // --- what arrived, by both deliveries ---------------------------------
  const polled = await pollSets(pollStream, who);
  const pushed = await pushedSets();
  const seen = { poll: {}, push: {} };
  const model = caep.newSession({ iss: stsUrl, sub: row.sub,
    sid: row.sessionId });

  [['poll', polled], ['push', pushed]].forEach(function (pair) {
    pair[1].forEach(function (token) {
      const read = typeOf(token);
      if (read.short) {
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
  let outcome = null;
  try {
    outcome = await run();
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
  // A SKIP IS NOT A PASS AND MUST NOT PRINT ONE. Seven files in this
  // directory once wrote "Test completed successfully" on a skip path, and
  // that sentence is what made a fifth of the suite invisible — see the
  // section in tests/CLAUDE.md. declineToRun() has already set the exit code
  // and written the marker line the runner reads.
  if (outcome && outcome.skipped) {
    log.debug("Leaving test(). Skipped.");
    return;
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
