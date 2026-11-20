// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oid4vp_verifier.js
//
// ---------------------------------------------------------------------------
// THE VERIFIER'S TWO ENDPOINTS, HOSTED BY THIS SERVICE ON A PAGE'S BEHALF.
//
// When the VC Presentation workflow plays the VERIFIER (issue #364), two of
// the things OpenID4VP 1.0 asks of a Verifier are things a browser page
// cannot be:
//
//   * the `request_uri` a Wallet fetches the signed Request Object from
//     (section 5.7; a POST under request_uri_method=post, section 5.10);
//   * the `response_uri` a Wallet POSTs its answer to under `direct_post`
//     and `direct_post.jwt` (section 8.2).
//
// Both are URLs a WALLET connects to, and **a page is not an HTTP server** —
// the same reason, word for word, that api/ssf_receiver.js exists. So the
// page asks this service for a session, gets back the three URLs (the third
// is the AIA caIssuers URL the Verifier's root CA certificate is served
// from, which the suite's peer wallet fetches to build its chain), signs the
// Request Object ITSELF and hands it here to be served. **The page's signing
// key never leaves the browser**: this service stores and serves a compact
// JWS it did not make and does not verify.
//
// ---------------------------------------------------------------------------
// THREE OF THESE ROUTES ACCEPT CALLS FROM SOMEBODY ELSE'S WALLET, WHICH IS
// THE SHAPE api/ssf_receiver.js ARGUES THE BOUNDS OF. THE SAME BOUNDS HOLD:
//
// 0. **THE PAGE'S HALF IS AUTHENTICATED.** create() hands back a `secret`
//    (32 hex characters of crypto.randomBytes) and every page call after it
//    — publish, events, delete — must carry `Authorization: Bearer
//    <secret>`, compared in constant time. The Wallet's half is not and
//    cannot be: a Wallet presents no credential to a request_uri or a
//    response_uri, so those are bounded structurally, like an open SSF inbox.
// 1. **A SESSION EXISTS ONLY BECAUSE SOMEBODY ASKED FOR ONE**, and its id is
//    32 hex characters of crypto.randomBytes. Nothing can be posted to a
//    session nobody created, and nobody can guess one.
// 2. **EVERY SESSION EXPIRES** — after `oid4vpVerifierIdleTtlMs` with
//    nothing touching it, and after `oid4vpVerifierTtlMs` whatever happens —
//    and is swept whenever anything touches this module. A page may ask a
//    session for SHORTER lifetimes; the settings are ceilings as well as
//    defaults.
// 3. **THE COUNTS ARE CAPPED** — `oid4vpVerifierMaxSessions` in all and
//    `oid4vpVerifierMaxSessionsPerCaller` for one caller's address, and
//    `oid4vpVerifierMaxEvents` events in each session, oldest dropped.
// 4. **THE SIZES ARE CAPPED** — a Request Object (and the CA certificate)
//    at `oid4vpVerifierMaxRequestObjectBytes`, one Wallet answer at
//    `oid4vpVerifierMaxResponseBytes`, and everything one session holds of
//    Wallet answers at `oid4vpVerifierMaxSessionBytes`, oldest dropped
//    first — the SSF receiver's lesson that three counts multiply out to
//    more memory than anybody meant.
// 5. **IT IS OFF UNLESS THE CONFIGURATION SAYS OTHERWISE** — only an
//    explicit `oid4vpVerifierEnabled: false` turns it off, and the embedded
//    deployment does, because a Wallet cannot pass the mock STS's sign-in
//    gate in front of `/api` there (api/env/embedded.js).
//
// **NOTHING IS EXECUTED, RENDERED, FORWARDED OR VERIFIED.** What a Wallet
// posts is stored as the TEXT that arrived, field by field, and handed back
// to the page, which decrypts, verifies and judges it. A Verifier that
// refused what it could not check would be unable to show anybody WHY,
// which is the question the workflow exists to answer.
//
// ---------------------------------------------------------------------------
// LIVE SIGNING (request_uri_method=post, section 5.10). A Wallet that POSTs
// to request_uri sends `wallet_nonce` (and `wallet_metadata`), and section
// 5.10 is not optional about it: "When received, the Verifier MUST use it
// as the wallet_nonce value in the signed authorization request object."
// The key is in the page, so this service cannot sign one; a session
// created with `liveSigning: true` therefore HOLDS the Wallet's POST open,
// for at most `oid4vpVerifierLiveSignWaitMs`, and records a
// `request-fetched` event with a `signingId`. The page sees it on its next
// poll of /events, signs an object carrying that wallet_nonce, and PUTs it
// to /oid4vp/verifier/:id/request/:signingId; the held Wallet is answered
// with it and a `request-signed` event says `liveSigned: true`.
//
// **A Wallet that sent a wallet_nonce is never handed the pre-signed
// object**, which cannot carry it: section 5.10.1 has the Wallet "terminate
// request processing" on such an object, so serving it would only be a
// slower, quieter failure. When the page does not sign in time, or
// `oid4vpVerifierMaxPendingSignings` Wallets already wait on the session,
// that Wallet is answered 503 `temporarily_unavailable` — section 5.10.2:
// "If the Verifier responds with any HTTP error response, the Wallet MUST
// terminate the process" — and `request-signed` records `liveSigned:
// false`, `httpStatus: 503` and why. A POST WITHOUT a wallet_nonce has
// nothing to echo, so it still falls back to the pre-signed object. A
// session WITHOUT live signing serves the pre-signed object to every POST,
// as a debugging affordance (a Wallet that does not terminate on it is the
// finding), and the `request-fetched` event carries a `problem` saying the
// object does not carry the nonce. Every wait is a timer, and every timer
// is cleared when its session ends — deleted, expired, swept, reset or at
// shutdown() — so a session never outlives itself in the event loop.
//
// IT IS IN MEMORY AND DIES WITH THE PROCESS, for the SSF receiver's reason:
// what is held is a person's presented credentials, and this service writes
// nothing to disk anywhere else.
//
// ---------------------------------------------------------------------------
// THIS FILE HAS NO EXPRESS AND NO NETWORK. server.js registers the routes and
// calls in; every function here returns `{ ok, status, ... }` and the route
// sends it. That is what lets tests/api_oid4vp_verifier.js drive every bound
// and every refusal with no listener at all.
// ---------------------------------------------------------------------------

var crypto = require('crypto');
var bunyan = require('bunyan');

var log = bunyan.createLogger({
  name: 'oid4vp_verifier',
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// RFC 9101 section 10.2: the media type a Request Object is served as.
var REQUEST_OBJECT_MEDIA_TYPE = 'application/oauth-authz-req+jwt';

// RFC 2585 section 4.2 (and RFC 5280 section 4.2.2.1 for caIssuers): one
// DER certificate.
var CA_MEDIA_TYPE = 'application/pkix-cert';

var DEFAULTS = {
  enabled: true,
  ttlMs: 30 * 60 * 1000,
  idleTtlMs: 10 * 60 * 1000,
  maxSessions: 100,
  maxSessionsPerCaller: 10,
  maxEvents: 50,
  maxResponseBytes: 256 * 1024,
  maxRequestObjectBytes: 64 * 1024,
  maxSessionBytes: 1024 * 1024,
  liveSignWaitMs: 15000,
  maxPendingSignings: 4
};

// Text members a page may set, and the most of each it may.
var MAX_REDIRECT_URI = 4096;

// id -> { id, secret, caller, createdAt, lastUsedAt, ttlMs, idleTtlMs,
//        redirectUri, requestObject, caDer, events, total, dropped, bytes,
//        liveSigning, pending }
// `pending` is signingId -> { signingId, timer, resolve }: the Wallets held
// open under live signing.
var sessions = new Map();

// The clock, replaceable by the tests so an expiry is asserted without
// waiting for one.
var clock = Date.now;

function now() {
  log.debug('Entering now().');
  var at = clock();
  log.debug('Leaving now().');
  return at;
}

function setClock(fn) {
  log.debug('Entering setClock().');
  clock = typeof fn === 'function' ? fn : Date.now;
  log.debug('Leaving setClock().');
}

// The timers a live-signing wait runs on, replaceable by the tests the way
// the clock is, so a timeout is fired rather than waited for.
var timers = { set: setTimeout, clear: clearTimeout };

function setTimers(impl) {
  log.debug('Entering setTimers().');
  timers = impl && typeof impl.set === 'function' &&
      typeof impl.clear === 'function' ? impl
    : { set: setTimeout, clear: clearTimeout };
  log.debug('Leaving setTimers().');
}

// A Request Object answer to a Wallet.
function served(jws) {
  log.debug('Entering served().');
  var out = { ok: true, status: 200, contentType: REQUEST_OBJECT_MEDIA_TYPE,
    body: jws };
  log.debug('Leaving served().');
  return out;
}

// End a session: forget it, and release every Wallet it holds open with a
// 404 naming why — the session the Wallet would answer to is gone, so a
// Request Object now would only send it to a response_uri that 404s.
function endSession(one, why) {
  log.debug('Entering endSession(). ' + one.id);
  sessions.delete(one.id);
  var released = 0;
  one.pending.forEach(function (entry) {
    timers.clear(entry.timer);
    entry.resolve(walletError(404, why));
    released++;
  });
  one.pending.clear();
  log.debug('Leaving endSession(). ' + released + ' wait(s) released.');
  return released;
}

// How many Wallets are held open, in all or in one session: the bookkeeping
// that says no wait outlived its session.
function pendingCount(id) {
  log.debug('Entering pendingCount().');
  var count = 0;
  sessions.forEach(function (one) {
    if (id === undefined || one.id === id) {
      count += one.pending.size;
    }
  });
  log.debug('Leaving pendingCount(). ' + count);
  return count;
}

function setting(appconfig, name, fallback) {
  log.debug('Entering setting(). ' + name);
  var value = appconfig && appconfig[name];
  if (typeof value !== 'number' || !isFinite(value) || value <= 0) {
    if (value !== undefined && typeof value !== 'boolean') {
      log.warn('Ignoring ' + name + '=' + JSON.stringify(value) +
               ' — it must be a positive number. Using ' + fallback + '.');
    }
    log.debug('Leaving setting(). Default ' + fallback + '.');
    return fallback;
  }
  log.debug('Leaving setting(). ' + value);
  return value;
}

// Only an explicit `false` turns it off, so a missing or misspelt key
// leaves the feature as the configuration file intended.
function enabled(appconfig) {
  log.debug('Entering enabled().');
  var on = !(appconfig && appconfig.oid4vpVerifierEnabled === false);
  log.debug('Leaving enabled(). ' + on);
  return on;
}

// The three URLs a session is reached at, from this service's own base as
// the caller reached it (server.js's publicBaseUrl()). The Wallet must reach
// them, and the suite's peer wallet requires request_uri and response_uri
// on the same host — which building all three from one base guarantees.
function urlsFor(base, id) {
  log.debug('Entering urlsFor(). ' + id);
  var root = String(base || '').replace(/\/+$/, '') + '/oid4vp/verifier/' +
      id;
  var out = {
    requestUri: root + '/request',
    responseUri: root + '/response',
    caIssuersUrl: root + '/ca'
  };
  log.debug('Leaving urlsFor().');
  return out;
}

// AN EXTERNALLY REACHABLE BASE (#470, B5). The URLs a session hands out are
// read by a WALLET, which is often a phone that scanned a QR code — and the
// Host the page reached this service at (`localhost`, `api`) names nothing
// that phone can reach. So the base is, in order: the page's own
// `publicBaseUrl` on create, this service's `oid4vpVerifierPublicBaseUrl`,
// and only then the base the caller used (server.js's publicBaseUrl()).
//
// LETTING THE PAGE CHOOSE IT IS SAFE, and the reason is what the base is
// used for: three strings handed back to the page that asked. This service
// fetches nothing from it, redirects nobody to it and serves on its own
// host whatever it says; the page could write any request_uri it liked into
// the invocation without asking, and the Wallet reaches whatever it names.
// A base that does not lead back here simply makes a request no Wallet can
// answer. It is held to the shape a Wallet will accept — an absolute https
// URL with no query, fragment or credentials — so a typing mistake is
// refused by name rather than discovered on a phone.
var MAX_PUBLIC_BASE_URL = 2048;

function readPublicBaseUrl(value, name) {
  log.debug('Entering readPublicBaseUrl(). ' + name);
  if (value === undefined || value === null ||
      String(value).trim() === '') {
    log.debug('Leaving readPublicBaseUrl(). None.');
    return { value: '' };
  }
  var text = String(value).trim();
  if (text.length > MAX_PUBLIC_BASE_URL) {
    log.debug('Leaving readPublicBaseUrl(). Too long.');
    return { error: name + ' is ' + text.length + ' characters and this ' +
        'service takes at most ' + MAX_PUBLIC_BASE_URL + '.' };
  }
  var url;
  try {
    url = new URL(text);
  } catch (e) {
    log.debug('Leaving readPublicBaseUrl(). Not a URL.');
    return { error: name + ' must be an absolute https:// URL; ' +
        JSON.stringify(text) + ' is not a URL.' };
  }
  if (url.protocol !== 'https:') {
    log.debug('Leaving readPublicBaseUrl(). Not https.');
    return { error: name + ' must be an https:// URL: a Wallet fetches ' +
        'request_uri and posts to response_uri over TLS. It was ' +
        JSON.stringify(text) + '.' };
  }
  if (url.username || url.password || url.search || url.hash) {
    log.debug('Leaving readPublicBaseUrl(). Extra parts.');
    return { error: name + ' must be a base URL: no credentials, query ' +
        'or fragment, because the session\'s paths are appended to it. ' +
        'It was ' + JSON.stringify(text) + '.' };
  }
  log.debug('Leaving readPublicBaseUrl().');
  return { value: url.origin + url.pathname.replace(/\/+$/, '') };
}

// The configured base, '' when unset. A malformed one is logged and
// ignored, so the role keeps working on the caller's base.
function configuredPublicBaseUrl(appconfig) {
  log.debug('Entering configuredPublicBaseUrl().');
  var read = readPublicBaseUrl(appconfig &&
      appconfig.oid4vpVerifierPublicBaseUrl, 'oid4vpVerifierPublicBaseUrl');
  if (read.error) {
    log.warn('Ignoring oid4vpVerifierPublicBaseUrl: ' + read.error);
    log.debug('Leaving configuredPublicBaseUrl(). Malformed.');
    return '';
  }
  log.debug('Leaving configuredPublicBaseUrl(). ' + read.value);
  return read.value;
}

// The base a session's URLs are built from: the page's, the setting's, or
// the one the caller reached this service at.
function publicBase(appconfig, asked, callerBase) {
  log.debug('Entering publicBase().');
  var base = asked || configuredPublicBaseUrl(appconfig) ||
      String(callerBase || '');
  log.debug('Leaving publicBase(). ' + base);
  return base;
}

// Drop what has expired. From every entry point rather than on a timer,
// for the SSF receiver's reason: a timer keeps the event loop alive for a
// feature nobody is using.
function sweep(appconfig) {
  log.debug('Entering sweep().');
  var ttl = setting(appconfig, 'oid4vpVerifierTtlMs', DEFAULTS.ttlMs);
  var idle = setting(appconfig, 'oid4vpVerifierIdleTtlMs',
                     DEFAULTS.idleTtlMs);
  var at = now();
  var gone = 0;
  sessions.forEach(function (one, id) {
    if (at - one.createdAt >= Math.min(one.ttlMs, ttl) ||
        at - one.lastUsedAt >= Math.min(one.idleTtlMs, idle)) {
      endSession(one, NO_SUCH_SESSION);
      gone++;
    }
  });
  if (gone) {
    log.debug('sweep(): ' + gone + ' session(s) expired.');
  }
  log.debug('Leaving sweep(). ' + sessions.size + ' held.');
  return gone;
}

function expiresAt(one) {
  log.debug('Entering expiresAt().');
  var at = new Date(Math.min(one.createdAt + one.ttlMs,
    one.lastUsedAt + one.idleTtlMs)).toISOString();
  log.debug('Leaving expiresAt(). ' + at);
  return at;
}

// A lifetime the page asked for: absent is the setting, above the setting
// is refused naming it, anything not a positive whole number is refused.
function lifetime(appconfig, asked, member, name, fallback) {
  log.debug('Entering lifetime(). ' + member);
  var ceiling = setting(appconfig, name, fallback);
  var value = asked[member];
  if (value === undefined || value === null || value === '') {
    log.debug('Leaving lifetime(). The setting.');
    return { value: ceiling };
  }
  var number = Number(value);
  if (typeof value === 'boolean' || !isFinite(number) || number <= 0 ||
      Math.floor(number) !== number) {
    log.debug('Leaving lifetime(). Malformed.');
    return { error: member + ' must be a positive whole number of ' +
        'milliseconds; it was ' + JSON.stringify(value) + '. Leave it out ' +
        'for the default (' + name + ', ' + ceiling + ').' };
  }
  if (number > ceiling) {
    log.debug('Leaving lifetime(). Above the ceiling.');
    return { error: member + ' ' + number + ' is above this service\'s ' +
        'ceiling, ' + name + ' = ' + ceiling + '. A page may ask for less, ' +
        'never more.' };
  }
  log.debug('Leaving lifetime(). ' + number);
  return { value: number };
}

function readRedirectUri(value) {
  log.debug('Entering readRedirectUri().');
  if (value === undefined || value === null) {
    log.debug('Leaving readRedirectUri(). None.');
    return { value: '' };
  }
  var text = String(value).trim();
  if (text.length > MAX_REDIRECT_URI) {
    log.debug('Leaving readRedirectUri(). Too long.');
    return { error: 'redirectUri is ' + text.length + ' characters and ' +
        'this service holds at most ' + MAX_REDIRECT_URI + '.' };
  }
  if (/[\r\n]/.test(text)) {
    log.debug('Leaving readRedirectUri(). A line break.');
    return { error: 'redirectUri may not contain a line break.' };
  }
  log.debug('Leaving readRedirectUri().');
  return { value: text };
}

// ---------------------------------------------------------------------------
// POST /oid4vp/verifier. `options` is { redirectUri?, ttlMs?, idleTtlMs?,
// liveSigning?, publicBaseUrl? };
// `caller` is the request's address, which the per-caller cap counts.
// ---------------------------------------------------------------------------
function create(appconfig, options, caller) {
  log.debug('Entering create().');
  var asked = options || {};
  var who = String(caller || '');
  if (!enabled(appconfig)) {
    log.debug('Leaving create(). Disabled.');
    return { ok: false, status: 403, error: 'This service does not host ' +
        'Verifier sessions (oid4vpVerifierEnabled is false). The Verifier ' +
        'role needs a request_uri and a response_uri a Wallet can reach, ' +
        'and a page cannot be either.' };
  }
  sweep(appconfig);
  var max = setting(appconfig, 'oid4vpVerifierMaxSessions',
                    DEFAULTS.maxSessions);
  if (sessions.size >= max) {
    log.debug('Leaving create(). At the session limit.');
    return { ok: false, status: 400, error: 'This service is holding ' +
        sessions.size + ' Verifier session(s) and ' +
        'oid4vpVerifierMaxSessions is ' + max + '. They expire on their ' +
        'own after oid4vpVerifierTtlMs; delete one to make room now.' };
  }
  var perCaller = setting(appconfig, 'oid4vpVerifierMaxSessionsPerCaller',
                          DEFAULTS.maxSessionsPerCaller);
  var mine = 0;
  sessions.forEach(function (one) {
    if (one.caller === who) {
      mine++;
    }
  });
  if (mine >= perCaller) {
    log.debug('Leaving create(). At the per-caller limit.');
    return { ok: false, status: 400, error: 'This caller already holds ' +
        mine + ' Verifier session(s) and ' +
        'oid4vpVerifierMaxSessionsPerCaller is ' + perCaller + '. Delete ' +
        'one, or let one go idle (oid4vpVerifierIdleTtlMs).' };
  }
  var redirect = readRedirectUri(asked.redirectUri);
  if (redirect.error) {
    log.debug('Leaving create(). redirectUri refused.');
    return { ok: false, status: 400, error: redirect.error };
  }
  var ttl = lifetime(appconfig, asked, 'ttlMs', 'oid4vpVerifierTtlMs',
                     DEFAULTS.ttlMs);
  if (ttl.error) {
    log.debug('Leaving create(). ttlMs refused.');
    return { ok: false, status: 400, error: ttl.error };
  }
  var idle = lifetime(appconfig, asked, 'idleTtlMs',
                      'oid4vpVerifierIdleTtlMs', DEFAULTS.idleTtlMs);
  if (idle.error) {
    log.debug('Leaving create(). idleTtlMs refused.');
    return { ok: false, status: 400, error: idle.error };
  }
  var base = readPublicBaseUrl(asked.publicBaseUrl, 'publicBaseUrl');
  if (base.error) {
    log.debug('Leaving create(). publicBaseUrl refused.');
    return { ok: false, status: 400, error: base.error };
  }
  var live = asked.liveSigning;
  if (live !== undefined && live !== null && typeof live !== 'boolean') {
    log.debug('Leaving create(). liveSigning refused.');
    return { ok: false, status: 400, error: 'liveSigning must be true or ' +
        'false; it was ' + JSON.stringify(live) + '.' };
  }
  var at = now();
  var one = {
    id: crypto.randomBytes(16).toString('hex'),
    secret: crypto.randomBytes(16).toString('hex'),
    caller: who,
    createdAt: at,
    lastUsedAt: at,
    ttlMs: ttl.value,
    idleTtlMs: idle.value,
    redirectUri: redirect.value,
    requestObject: '',
    caDer: null,
    events: [],
    total: 0,
    dropped: 0,
    bytes: 0,
    liveSigning: live === true,
    pending: new Map()
  };
  sessions.set(one.id, one);
  log.debug('Leaving create(). ' + one.id);
  return { ok: true, status: 201, id: one.id, secret: one.secret,
    liveSigning: one.liveSigning, expiresAt: expiresAt(one),
    publicBaseUrl: base.value };
}

function find(appconfig, id) {
  log.debug('Entering find(). ' + id);
  sweep(appconfig);
  var one = sessions.get(String(id || '')) || null;
  log.debug('Leaving find(). ' + (one ? 'found' : 'not found'));
  return one;
}

var NO_SUCH_SESSION = 'There is no Verifier session with that id here. ' +
    'Either it was never created, it has been deleted, or it expired ' +
    '(oid4vpVerifierTtlMs, oid4vpVerifierIdleTtlMs).';

// Two secrets compared in constant time. Each is hashed first, so the
// comparison does not even say how long the expected one is.
function sameSecret(presented, expected) {
  log.debug('Entering sameSecret().');
  var a = crypto.createHash('sha256').update(String(presented), 'utf8')
    .digest();
  var b = crypto.createHash('sha256').update(String(expected), 'utf8')
    .digest();
  var same = crypto.timingSafeEqual(a, b) && expected !== '';
  log.debug('Leaving sameSecret(). ' + same);
  return same;
}

// The page's own session, by its id and the secret create() handed back,
// presented as `Authorization: Bearer <secret>` (the scheme in any case).
function authorized(appconfig, id, authorization) {
  log.debug('Entering authorized(). ' + id);
  var one = find(appconfig, id);
  if (!one) {
    log.debug('Leaving authorized(). No such session.');
    return { ok: false, status: 404, error: NO_SUCH_SESSION };
  }
  var match = /^\s*Bearer\s+(\S+)\s*$/i.exec(String(authorization || ''));
  if (!match || !sameSecret(match[1], one.secret)) {
    log.debug('Leaving authorized(). Refused.');
    return { ok: false, status: 401, error: 'This call needs the session\'s ' +
        'secret as `Authorization: Bearer <secret>` — the secret POST ' +
        '/oid4vp/verifier answered — and this request ' +
        (match ? 'carried a different one.' : 'carried none.') };
  }
  one.lastUsedAt = now();
  log.debug('Leaving authorized().');
  return { ok: true, session: one };
}

// A compact JWS by SHAPE only — three base64url segments, the first two
// not empty. An unsecured `alg: none` object has an empty third segment
// and is let through, since showing a Wallet refusing one is a thing this
// debugger exists to do.
var COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
// A compact JWE (RFC 7516 section 7.1): five segments, the protected header
// not empty. The encrypted key and the IV may be empty (direct, HPKE
// integrated), and the ciphertext may be. Served only as the live answer to
// one Wallet whose wallet_metadata gave a key to encrypt to (section 5.10;
// RFC 9101 section 4, signed then encrypted).
var COMPACT_JWE = new RegExp('^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]*){4}$');

// The CA certificate as base64 DER, or as PEM (the armour is stripped). It
// has to decode to a DER SEQUENCE; nothing else about it is checked.
function readCertificate(value) {
  log.debug('Entering readCertificate().');
  var text = String(value)
    .replace(/-----(BEGIN|END) [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
  if (text === '' || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(text)) {
    log.debug('Leaving readCertificate(). Not base64.');
    return { error: 'caCertificate must be the certificate\'s DER in ' +
        'base64 (or a PEM block); this is not base64.' };
  }
  var der = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'),
                        'base64');
  if (der.length < 2 || der[0] !== 0x30) {
    log.debug('Leaving readCertificate(). Not a SEQUENCE.');
    return { error: 'caCertificate decodes to ' + der.length + ' bytes ' +
        'that are not a DER SEQUENCE, so they are not a certificate.' };
  }
  log.debug('Leaving readCertificate(). ' + der.length + ' bytes.');
  return { der: der };
}

// ---------------------------------------------------------------------------
// PUT /oid4vp/verifier/:id/request — the page hands over what it signed.
// `body` is { requestObject, caCertificate?, redirectUri? }. A second PUT
// replaces the first: a page that re-signs after changing a setting serves
// the new object at the same request_uri.
// ---------------------------------------------------------------------------
// The `requestObject` member of a page's PUT, by the rules both publishes
// share: required, at most oid4vpVerifierMaxRequestObjectBytes, a compact
// JWS by shape. With `allowEncrypted` (the live answer to one Wallet,
// publishFor()), a compact JWE as well: an object pre-signed for every
// Wallet has nobody's key to be encrypted to.
function readRequestObject(appconfig, asked, allowEncrypted) {
  log.debug('Entering readRequestObject().');
  var jws = asked.requestObject === undefined || asked.requestObject === null
    ? '' : String(asked.requestObject).trim();
  if (jws === '') {
    log.debug('Leaving readRequestObject(). No request object.');
    return { error: 'requestObject is required: the signed Request ' +
        'Object, as a compact JWS, that the Wallet will fetch from ' +
        'request_uri.' };
  }
  var limit = setting(appconfig, 'oid4vpVerifierMaxRequestObjectBytes',
                      DEFAULTS.maxRequestObjectBytes);
  var size = Buffer.byteLength(jws, 'utf8');
  if (size > limit) {
    log.debug('Leaving readRequestObject(). Too large: ' + size);
    return { error: 'requestObject is ' + size + ' bytes and this service ' +
        'serves at most ' + limit + ' (oid4vpVerifierMaxRequestObjectBytes).' };
  }
  if (allowEncrypted && COMPACT_JWE.test(jws)) {
    log.debug('Leaving readRequestObject(). Encrypted: ' + size + ' bytes.');
    return { jws: jws, size: size, limit: limit, encrypted: true };
  }
  if (!COMPACT_JWS.test(jws)) {
    log.debug('Leaving readRequestObject(). Not a compact JWS.');
    return { error: 'requestObject is not a compact JWS: three base64url ' +
        'segments separated by dots, the first two not empty.' +
        (allowEncrypted ? ' Nor a compact JWE: five segments, the first ' +
          'not empty.' : ' An encrypted Request Object (five segments) is ' +
          'served only as the live answer to one Wallet, which gave the ' +
          'key in its wallet_metadata (PUT .../request/:signingId).') };
  }
  log.debug('Leaving readRequestObject(). ' + size + ' bytes.');
  return { jws: jws, size: size, limit: limit };
}

function publish(appconfig, id, authorization, body) {
  log.debug('Entering publish(). ' + id);
  var auth = authorized(appconfig, id, authorization);
  if (!auth.ok) {
    log.debug('Leaving publish(). ' + auth.status);
    return auth;
  }
  var one = auth.session;
  var asked = body || {};
  var object = readRequestObject(appconfig, asked);
  if (object.error) {
    log.debug('Leaving publish(). requestObject refused.');
    return { ok: false, status: 400, error: object.error };
  }
  var jws = object.jws;
  var size = object.size;
  var limit = object.limit;
  var der = one.caDer;
  if (asked.caCertificate !== undefined && asked.caCertificate !== null &&
      asked.caCertificate !== '') {
    var read = readCertificate(asked.caCertificate);
    if (read.error) {
      log.debug('Leaving publish(). caCertificate refused.');
      return { ok: false, status: 400, error: read.error };
    }
    if (read.der.length > limit) {
      log.debug('Leaving publish(). Certificate too large.');
      return { ok: false, status: 400, error: 'caCertificate is ' +
          read.der.length + ' bytes of DER and this service serves at ' +
          'most ' + limit + ' (oid4vpVerifierMaxRequestObjectBytes).' };
    }
    der = read.der;
  }
  var redirect = one.redirectUri;
  if (asked.redirectUri !== undefined) {
    var readUri = readRedirectUri(asked.redirectUri);
    if (readUri.error) {
      log.debug('Leaving publish(). redirectUri refused.');
      return { ok: false, status: 400, error: readUri.error };
    }
    redirect = readUri.value;
  }
  one.requestObject = jws;
  one.caDer = der;
  one.redirectUri = redirect;
  log.debug('Leaving publish(). ' + size + ' bytes.');
  return { ok: true, status: 200 };
}

// One event into a session's ring, oldest dropped by count and by the
// session's byte cap. `bytes` is what the event holds of a Wallet's text.
function record(appconfig, one, event, bytes) {
  log.debug('Entering record(). ' + event.kind);
  var maxEvents = setting(appconfig, 'oid4vpVerifierMaxEvents',
                          DEFAULTS.maxEvents);
  var maxBytes = setting(appconfig, 'oid4vpVerifierMaxSessionBytes',
                         DEFAULTS.maxSessionBytes);
  var size = bytes || 0;
  while (one.events.length &&
         (one.events.length >= maxEvents || one.bytes + size > maxBytes)) {
    one.bytes -= one.events.shift().bytes;
    one.dropped++;
  }
  var stored = Object.assign({ seq: one.total, at: new Date(now())
    .toISOString() }, event, { bytes: size });
  one.events.push(stored);
  one.bytes += size;
  one.total++;
  one.lastUsedAt = now();
  log.debug('Leaving record(). ' + one.events.length + ' held.');
  return stored;
}

// A form body read field by field, every value the text that arrived. A
// field sent twice is an array of both, in order, rather than the last one
// silently winning — which is itself a finding about a Wallet.
function readForm(text) {
  log.debug('Entering readForm().');
  var fields = {};
  new URLSearchParams(String(text || '')).forEach(function (value, name) {
    if (Object.prototype.hasOwnProperty.call(fields, name)) {
      fields[name] = [].concat(fields[name], value);
    } else {
      fields[name] = value;
    }
  });
  log.debug('Leaving readForm(). ' + Object.keys(fields).length + ' fields.');
  return fields;
}

function mediaTypeOf(contentType) {
  log.debug('Entering mediaTypeOf().');
  var type = String(contentType || '').split(';')[0].trim().toLowerCase();
  log.debug('Leaving mediaTypeOf(). ' + type);
  return type;
}

// The body a Wallet sent, as fields: from the RAW text when server.js kept
// it (so nothing is reshaped by a parser), else from what was parsed.
function fieldsOf(request) {
  log.debug('Entering fieldsOf().');
  var type = mediaTypeOf(request.contentType);
  var raw = typeof request.rawBody === 'string' ? request.rawBody : null;
  if (type === 'application/x-www-form-urlencoded') {
    var form = raw !== null ? readForm(raw)
      : Object.assign({}, request.parsed || {});
    log.debug('Leaving fieldsOf(). A form.');
    return { kind: 'form', fields: form };
  }
  if (type === 'application/json') {
    var json = request.parsed;
    if (raw !== null) {
      try {
        json = JSON.parse(raw);
      } catch (e) {
        log.debug('Leaving fieldsOf(). JSON that does not parse.');
        return { kind: 'bad', reason: 'The body is not JSON: ' + e.message };
      }
    }
    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      log.debug('Leaving fieldsOf(). JSON that is not an object.');
      return { kind: 'bad', reason: 'The body is JSON but not an object, ' +
          'so it has no fields.' };
    }
    log.debug('Leaving fieldsOf(). JSON.');
    return { kind: 'json', fields: json };
  }
  log.debug('Leaving fieldsOf(). ' + (type || 'no type'));
  return { kind: 'none' };
}

function sizeOf(request) {
  log.debug('Entering sizeOf().');
  var size;
  if (typeof request.rawBody === 'string') {
    size = Buffer.byteLength(request.rawBody, 'utf8');
  } else {
    size = Buffer.byteLength(JSON.stringify(request.parsed || {}), 'utf8');
  }
  log.debug('Leaving sizeOf(). ' + size);
  return size;
}

// A Wallet-facing refusal, in OAuth's `{error, error_description}` shape,
// since that is the one error shape a Wallet is sure to read. `code`
// overrides the error code (RFC 6749 section 4.1.2.1's
// temporarily_unavailable, for a live signature that could not be had).
function walletError(status, description, code) {
  log.debug('Entering walletError(). ' + status);
  var out = { ok: false, status: status, error: code || (status === 404
    ? 'not_found' : 'invalid_request'), error_description: description };
  log.debug('Leaving walletError().');
  return out;
}

// One more thing wrong with what arrived, added to the event's `problem`
// rather than replacing what is already there: a POST can be both the
// wrong media type and missing its Accept.
function addProblem(event, text) {
  log.debug('Entering addProblem().');
  event.problem = event.problem ? event.problem + ' ' + text : text;
  log.debug('Leaving addProblem().');
}

// Does an Accept header name this media type? Each media range is compared
// without its parameters (q=, charset), case-insensitively (RFC 9110
// section 12.5.1). A wildcard does not count: section 5.10 says the header
// is SET TO application/oauth-authz-req+jwt.
function accepts(accept, type) {
  log.debug('Entering accepts().');
  var found = String(accept || '').split(',').some(function (range) {
    return range.split(';')[0].trim().toLowerCase() === type;
  });
  log.debug('Leaving accepts(). ' + found);
  return found;
}

// The two MUSTs of OpenID4VP 1.0 section 5.10 on a request_uri POST (#469,
// D1): "The request MUST use the HTTP POST method with the https scheme,
// and the content type application/x-www-form-urlencoded and the Accept
// header set to application/oauth-authz-req+jwt." A POST that breaks either
// is still SERVED — a debugger shows what the Wallet does next — and the
// event's `problem` names the rule, so the page prints it.
function requestPostProblems(event, asked, read) {
  log.debug('Entering requestPostProblems().');
  var type = mediaTypeOf(asked.contentType);
  if (type !== 'application/x-www-form-urlencoded') {
    addProblem(event, 'The POST was sent as ' + (type ? (read.kind ===
        'json' ? 'JSON ("' + type + '")' : '"' + type + '"') :
        'no Content-Type') + '. OpenID4VP section 5.10: it MUST use ' +
        'the content type application/x-www-form-urlencoded.');
  }
  if (!accepts(asked.accept, REQUEST_OBJECT_MEDIA_TYPE)) {
    addProblem(event, 'The POST ' + (asked.accept ? 'had Accept "' +
        String(asked.accept) + '"' : 'had no Accept header') + '. ' +
        'OpenID4VP section 5.10: it MUST have the Accept header set to ' +
        REQUEST_OBJECT_MEDIA_TYPE + '.');
  }
  log.debug('Leaving requestPostProblems().');
}

// ---------------------------------------------------------------------------
// GET or POST /oid4vp/verifier/:id/request — a Wallet fetches the Request
// Object. `request` is { method, contentType, accept, rawBody, parsed,
// remoteAddress }. Under request_uri_method=post (section 5.10) the body
// carries `wallet_metadata` and `wallet_nonce`, which are recorded. Without
// live signing the object served is the one the page signed beforehand,
// which CANNOT echo a wallet_nonce it never saw, and the event's `problem`
// says so (section 5.10: the Verifier MUST use it). With it, a POST is held
// for the page to sign (waitForSigning()), and the answer is `{ ok, status,
// signingId, pending, cancel }`: `pending` is a promise of the answer, and
// `cancel()` releases the wait early (the Wallet went away).
// ---------------------------------------------------------------------------
function fetchRequest(appconfig, id, request) {
  log.debug('Entering fetchRequest(). ' + id);
  var asked = request || {};
  var one = find(appconfig, id);
  if (!one || !one.requestObject) {
    log.debug('Leaving fetchRequest(). Nothing to serve.');
    return walletError(404, one ? 'This Verifier session has no Request ' +
        'Object yet: the page has not published one.' : NO_SUCH_SESSION);
  }
  var method = String(asked.method || 'GET').toUpperCase();
  var event = { kind: 'request-fetched', method: method };
  var bytes = 0;
  var nonceSent = false;
  if (asked.remoteAddress) {
    event.remoteAddress = String(asked.remoteAddress);
  }
  if (method === 'POST') {
    var read = fieldsOf(asked);
    event.contentType = String(asked.contentType || '');
    if (asked.accept) {
      event.accept = String(asked.accept);
    }
    requestPostProblems(event, asked, read);
    if (read.fields) {
      var meta = read.fields.wallet_metadata;
      if (meta !== undefined) {
        event.walletMetadata = meta;
        if (typeof meta === 'string') {
          try {
            event.walletMetadata = JSON.parse(meta);
          } catch (e) {
            // Kept as the text that arrived: wallet_metadata that is not
            // JSON is a finding about the Wallet, not a reason to refuse.
            event.walletMetadata = meta;
          }
        }
      }
      if (read.fields.wallet_nonce !== undefined) {
        event.walletNonce = read.fields.wallet_nonce;
        nonceSent = true;
      }
    }
    bytes = sizeOf(asked);
    if (bytes > setting(appconfig, 'oid4vpVerifierMaxResponseBytes',
                        DEFAULTS.maxResponseBytes)) {
      // Too large to keep: the fetch is still answered and recorded, but
      // not what came with it.
      delete event.walletMetadata;
      delete event.walletNonce;
      addProblem(event, 'The POST body was ' + bytes + ' bytes, above ' +
          'oid4vpVerifierMaxResponseBytes, and was not kept.');
      bytes = 0;
    }
    if (one.liveSigning) {
      log.debug('Leaving fetchRequest(). Live signing.');
      return waitForSigning(appconfig, one, event, bytes, nonceSent);
    }
    if (nonceSent) {
      addProblem(event, 'The Wallet sent a wallet_nonce and this session ' +
          'has no live signing, so it was served the Request Object ' +
          'signed in advance, which does not carry it. OpenID4VP section ' +
          '5.10: the Verifier MUST use it; section 5.10.1: a Wallet given ' +
          'an object without it MUST terminate.');
    }
  }
  record(appconfig, one, event, bytes);
  log.debug('Leaving fetchRequest(). Served.');
  return served(one.requestObject);
}

// The `request-signed` event that closes a wait, and the Wallet's answer:
// the page's object when it signed one; else, for a Wallet that sent a
// wallet_nonce, a 503 (section 5.10.2), since whatever the page published
// beforehand cannot carry that nonce; else the pre-signed object (read
// NOW, so a re-publish during the wait is what is served). `gone` is a
// Wallet that closed the connection: there is nobody left to answer.
function settle(appconfig, one, signingId, jws, reason, gone) {
  log.debug('Entering settle(). ' + signingId);
  var entry = one.pending.get(signingId);
  if (!entry) {
    log.debug('Leaving settle(). Already settled.');
    return false;
  }
  one.pending.delete(signingId);
  timers.clear(entry.timer);
  var signed = { kind: 'request-signed', signingId: signingId,
    liveSigned: Boolean(jws) };
  var answer;
  if (jws) {
    answer = served(jws);
  } else if (gone) {
    signed.reason = reason;
    answer = walletError(503, reason, 'temporarily_unavailable');
  } else if (entry.nonceSent) {
    signed.reason = reason + ' The Wallet sent a wallet_nonce, which the ' +
        'Request Object signed in advance cannot carry, so it was answered ' +
        '503 (OpenID4VP section 5.10.2) rather than given an object it ' +
        'MUST refuse.';
    signed.httpStatus = 503;
    answer = walletError(503, reason + ' A Request Object carrying this ' +
        'wallet_nonce could not be signed in time.',
        'temporarily_unavailable');
  } else {
    signed.reason = reason + ' The Wallet sent no wallet_nonce, so the ' +
        'Request Object signed in advance was served.';
    answer = served(one.requestObject);
  }
  record(appconfig, one, signed, 0);
  entry.resolve(answer);
  log.debug('Leaving settle(). liveSigned=' + signed.liveSigned);
  return true;
}

// Hold a Wallet's POST for the page to sign. At the cap, answer at once: a
// 503 when the Wallet sent a wallet_nonce (section 5.10.2), else the
// pre-signed object, and say which and why.
function waitForSigning(appconfig, one, event, bytes, nonceSent) {
  log.debug('Entering waitForSigning(). ' + one.id);
  var max = setting(appconfig, 'oid4vpVerifierMaxPendingSignings',
                    DEFAULTS.maxPendingSignings);
  if (one.pending.size >= max) {
    var full = 'This session already holds ' + one.pending.size +
        ' Wallet(s) waiting for the page to sign and ' +
        'oid4vpVerifierMaxPendingSignings is ' + max + '.';
    record(appconfig, one, event, bytes);
    if (nonceSent) {
      record(appconfig, one, { kind: 'request-signed', liveSigned: false,
        httpStatus: 503, reason: full + ' The Wallet sent a wallet_nonce, ' +
          'which the Request Object signed in advance cannot carry, so it ' +
          'was answered 503 (OpenID4VP section 5.10.2) at once.' }, 0);
      log.debug('Leaving waitForSigning(). At the cap: 503.');
      return walletError(503, full + ' No Request Object carrying this ' +
          'wallet_nonce can be signed now.', 'temporarily_unavailable');
    }
    record(appconfig, one, { kind: 'request-signed', liveSigned: false,
      reason: full + ' The Wallet sent no wallet_nonce, so the ' +
        'pre-signed Request Object was served at once.' }, 0);
    log.debug('Leaving waitForSigning(). At the cap.');
    return served(one.requestObject);
  }
  var wait = setting(appconfig, 'oid4vpVerifierLiveSignWaitMs',
                     DEFAULTS.liveSignWaitMs);
  var signingId = crypto.randomBytes(16).toString('hex');
  event.signingId = signingId;
  event.waitMs = wait;
  event.signBy = new Date(now() + wait).toISOString();
  record(appconfig, one, event, bytes);
  var entry = { signingId: signingId, nonceSent: Boolean(nonceSent) };
  var pending = new Promise(function (resolve) {
    entry.resolve = resolve;
  });
  entry.timer = timers.set(function () {
    settle(appconfig, one, signingId, null, 'The page did not sign ' +
        'within oid4vpVerifierLiveSignWaitMs (' + wait + ' ms).');
  }, wait);
  // A held Wallet's socket keeps the process alive; the timer need not.
  if (entry.timer && typeof entry.timer.unref === 'function') {
    entry.timer.unref();
  }
  one.pending.set(signingId, entry);
  log.debug('Leaving waitForSigning(). ' + signingId + ', ' + wait + ' ms.');
  return { ok: true, status: 200, signingId: signingId, pending: pending,
    cancel: function () {
      settle(appconfig, one, signingId, null, 'The Wallet closed the ' +
          'connection before the page signed.', true);
    } };
}

var NO_SUCH_SIGNING = 'No Wallet is waiting on that signingId in this ' +
    'session. It was never issued, it was already answered, or its wait ' +
    '(oid4vpVerifierLiveSignWaitMs) ran out and the Wallet was answered ' +
    'without it.';

// ---------------------------------------------------------------------------
// PUT /oid4vp/verifier/:id/request/:signingId — the page answers ONE held
// Wallet with the object it signed for it. `body` is { requestObject }, by
// publish()'s rules. The session's pre-signed object is not replaced: this
// one carries one Wallet's wallet_nonce and is served to that Wallet only.
// ---------------------------------------------------------------------------
function publishFor(appconfig, id, signingId, authorization, body) {
  log.debug('Entering publishFor(). ' + id + ' ' + signingId);
  var auth = authorized(appconfig, id, authorization);
  if (!auth.ok) {
    log.debug('Leaving publishFor(). ' + auth.status);
    return auth;
  }
  var one = auth.session;
  var key = String(signingId || '');
  if (!one.pending.has(key)) {
    log.debug('Leaving publishFor(). No such wait.');
    return { ok: false, status: 404, error: NO_SUCH_SIGNING };
  }
  var object = readRequestObject(appconfig, body || {}, true);
  if (object.error) {
    log.debug('Leaving publishFor(). requestObject refused.');
    return { ok: false, status: 400, error: object.error };
  }
  settle(appconfig, one, key, object.jws);
  log.debug('Leaving publishFor(). Signed live.');
  return { ok: true, status: 200 };
}

// GET /oid4vp/verifier/:id/ca — the AIA caIssuers URL of the leaf in the
// Request Object's x5c. A Wallet that builds its chain from AIA fetches it.
function fetchCa(appconfig, id, remoteAddress) {
  log.debug('Entering fetchCa(). ' + id);
  var one = find(appconfig, id);
  if (!one || !one.caDer) {
    log.debug('Leaving fetchCa(). Nothing to serve.');
    return walletError(404, one ? 'This Verifier session has no CA ' +
        'certificate yet: the page has not published one.' : NO_SUCH_SESSION);
  }
  var event = { kind: 'ca-fetched', method: 'GET' };
  if (remoteAddress) {
    event.remoteAddress = String(remoteAddress);
  }
  record(appconfig, one, event, 0);
  log.debug('Leaving fetchCa(). ' + one.caDer.length + ' bytes.');
  return { ok: true, status: 200, contentType: CA_MEDIA_TYPE,
    body: one.caDer };
}

// The redirect_uri answered to ONE Wallet's POST, carrying a fresh,
// cryptographically random value (#468, M3). OpenID4VP 1.0 section 8.2:
// "The Verifier MUST include a fresh, cryptographically random value in
// the URL. This value is used to ensure only the receiver of the redirect
// can fetch and process the Authorization Response. ... It is RECOMMENDED
// to use a cryptographic random value of 128 bits or more." It is added as
// `response_code`, section 13.3's name for it, 128 bits in base64url, and
// a new one for every answer: the page's configured redirect_uri is the
// same for every Wallet, so on its own it is no such value.
function redirectWithCode(redirectUri) {
  log.debug('Entering redirectWithCode().');
  var code = crypto.randomBytes(16).toString('base64url');
  var uri;
  try {
    var url = new URL(redirectUri);
    url.searchParams.append('response_code', code);
    uri = url.toString();
  } catch (e) {
    // Not an absolute URL (the page may hold anything): the parameter goes
    // before any fragment, by hand.
    var hash = redirectUri.indexOf('#');
    var head = hash === -1 ? redirectUri : redirectUri.slice(0, hash);
    var tail = hash === -1 ? '' : redirectUri.slice(hash);
    uri = head + (head.indexOf('?') === -1 ? '?' :
        (/[?&]$/.test(head) ? '' : '&')) + 'response_code=' + code + tail;
  }
  log.debug('Leaving redirectWithCode().');
  return { uri: uri, code: code };
}

// ---------------------------------------------------------------------------
// POST /oid4vp/verifier/:id/response — a Wallet's answer under direct_post
// (vp_token, state, ...) or direct_post.jwt (response, the JWE). Every field
// is kept VERBATIM and nothing is checked: the page decrypts and judges.
// The answer is section 8.2's: 200 with a JSON object, carrying
// `redirect_uri` when the page set one — with a fresh `response_code` in it
// (redirectWithCode()), which the `response` event records.
//
// A JSON body is ACCEPTED and REPORTED (#469, D2): section 8.2, "The
// Authorization Response MUST be encoded in the request body using the
// format defined by the application/x-www-form-urlencoded HTTP content
// type." The fields are kept and the event carries a `problem` naming that
// MUST, which the page turns into a FAIL row of the verdict.
// ---------------------------------------------------------------------------
function respond(appconfig, id, request) {
  log.debug('Entering respond(). ' + id);
  var asked = request || {};
  var one = find(appconfig, id);
  if (!one) {
    log.debug('Leaving respond(). No such session.');
    return walletError(404, NO_SUCH_SESSION);
  }
  var limit = setting(appconfig, 'oid4vpVerifierMaxResponseBytes',
                      DEFAULTS.maxResponseBytes);
  var size = sizeOf(asked);
  var contentType = String(asked.contentType || '');
  var refusedEvent = { kind: 'response-refused', method: 'POST',
    contentType: contentType };
  if (asked.remoteAddress) {
    refusedEvent.remoteAddress = String(asked.remoteAddress);
  }
  if (size > limit) {
    refusedEvent.problem = 'The answer was ' + size + ' bytes and this ' +
        'service keeps at most ' + limit + ' (oid4vpVerifierMaxResponseBytes).';
    record(appconfig, one, refusedEvent, 0);
    log.debug('Leaving respond(). Too large: ' + size);
    return walletError(400, refusedEvent.problem);
  }
  var read = fieldsOf(asked);
  if (read.kind === 'none' || read.kind === 'bad') {
    refusedEvent.problem = read.kind === 'bad' ? read.reason
      : 'OpenID4VP 1.0 section 8.2 sends the answer as ' +
        'application/x-www-form-urlencoded, and this one was sent as ' +
        (contentType ? '"' + contentType + '"' : 'no Content-Type') + '.';
    record(appconfig, one, refusedEvent, 0);
    log.debug('Leaving respond(). Unreadable.');
    return walletError(400, refusedEvent.problem);
  }
  var event = { kind: 'response', method: 'POST', contentType: contentType,
    fields: read.fields };
  if (asked.remoteAddress) {
    event.remoteAddress = String(asked.remoteAddress);
  }
  if (read.kind === 'json') {
    event.problem = 'The answer was sent as JSON ("' +
        mediaTypeOf(contentType) + '"). OpenID4VP 1.0 section 8.2: the ' +
        'Authorization Response MUST be encoded in the request body as ' +
        'application/x-www-form-urlencoded. It was kept and is checked.';
  }
  var body = {};
  if (one.redirectUri) {
    var redirect = redirectWithCode(one.redirectUri);
    body.redirect_uri = redirect.uri;
    event.redirectUri = redirect.uri;
    event.responseCode = redirect.code;
  }
  record(appconfig, one, event, size);
  log.debug('Leaving respond(). Recorded.');
  return { ok: true, status: 200, body: body };
}

// ---------------------------------------------------------------------------
// GET /oid4vp/verifier/:id/events?after=<n> — what Wallets did. `after` is
// the `next` a previous call answered: every event numbered from it is
// handed back, and nothing is removed, so a second tab sees the same.
// ---------------------------------------------------------------------------
function events(appconfig, id, authorization, after) {
  log.debug('Entering events(). ' + id);
  var auth = authorized(appconfig, id, authorization);
  if (!auth.ok) {
    log.debug('Leaving events(). ' + auth.status);
    return auth;
  }
  var one = auth.session;
  var from = Number(after);
  if (after === undefined || after === null || after === '' ||
      !isFinite(from) || from < 0) {
    from = 0;
  }
  if (from > one.total) {
    from = one.total;
  }
  var out = one.events.filter(function (event) {
    return event.seq >= from;
  }).map(function (event) {
    var copy = Object.assign({}, event);
    delete copy.bytes;
    return copy;
  });
  log.debug('Leaving events(). ' + out.length + ' event(s).');
  return { ok: true, status: 200, events: out, next: one.total,
    dropped: one.dropped, expiresAt: expiresAt(one) };
}

// DELETE /oid4vp/verifier/:id.
function remove(appconfig, id, authorization) {
  log.debug('Entering remove(). ' + id);
  var auth = authorized(appconfig, id, authorization);
  if (!auth.ok) {
    log.debug('Leaving remove(). ' + auth.status);
    return auth;
  }
  endSession(auth.session, NO_SUCH_SESSION);
  log.debug('Leaving remove(). Deleted.');
  return { ok: true, status: 200, deleted: auth.session.id };
}

// What GET /oid4vp/verifier/limits publishes. A page reads it to learn
// whether there is an api at all — a static site answers nothing here.
function limits(appconfig) {
  log.debug('Entering limits().');
  sweep(appconfig);
  var out = {
    enabled: enabled(appconfig),
    ttlMs: setting(appconfig, 'oid4vpVerifierTtlMs', DEFAULTS.ttlMs),
    idleTtlMs: setting(appconfig, 'oid4vpVerifierIdleTtlMs',
                       DEFAULTS.idleTtlMs),
    maxSessions: setting(appconfig, 'oid4vpVerifierMaxSessions',
                         DEFAULTS.maxSessions),
    maxSessionsPerCaller: setting(appconfig,
      'oid4vpVerifierMaxSessionsPerCaller', DEFAULTS.maxSessionsPerCaller),
    maxEvents: setting(appconfig, 'oid4vpVerifierMaxEvents',
                       DEFAULTS.maxEvents),
    maxResponseBytes: setting(appconfig, 'oid4vpVerifierMaxResponseBytes',
                              DEFAULTS.maxResponseBytes),
    maxRequestObjectBytes: setting(appconfig,
      'oid4vpVerifierMaxRequestObjectBytes', DEFAULTS.maxRequestObjectBytes),
    maxSessionBytes: setting(appconfig, 'oid4vpVerifierMaxSessionBytes',
                             DEFAULTS.maxSessionBytes),
    liveSignWaitMs: setting(appconfig, 'oid4vpVerifierLiveSignWaitMs',
                            DEFAULTS.liveSignWaitMs),
    maxPendingSignings: setting(appconfig,
      'oid4vpVerifierMaxPendingSignings', DEFAULTS.maxPendingSignings),
    // '' when unset: the URLs then use the base the page reached this
    // service at, which a phone may not be able to reach (#470, B5).
    publicBaseUrl: configuredPublicBaseUrl(appconfig),
    held: sessions.size,
    requestObjectMediaType: REQUEST_OBJECT_MEDIA_TYPE,
    caMediaType: CA_MEDIA_TYPE,
    verifies: false,
    note: 'A page cannot be an HTTP server, so it cannot be the request_uri ' +
        'or the response_uri a Wallet connects to. This service hosts both ' +
        'on the page\'s behalf: the page signs the Request Object itself ' +
        'and publishes it here, and reads back what Wallets posted. ' +
        'Nothing is verified here; the page verifies.'
  };
  log.debug('Leaving limits().');
  return out;
}

// For the tests, which need a known state without a restart.
function reset() {
  log.debug('Entering reset().');
  var gone = sessions.size;
  Array.from(sessions.values()).forEach(function (one) {
    endSession(one, NO_SUCH_SESSION);
  });
  log.debug('Leaving reset(). ' + gone + ' dropped.');
  return gone;
}

// When the process stops: release every held Wallet and clear every timer,
// so a closing listener is not kept waiting on a live-signing wait.
function shutdown() {
  log.debug('Entering shutdown().');
  var released = 0;
  Array.from(sessions.values()).forEach(function (one) {
    released += endSession(one, 'This service is shutting down.');
  });
  log.debug('Leaving shutdown(). ' + released + ' wait(s) released.');
  return released;
}

module.exports = {
  REQUEST_OBJECT_MEDIA_TYPE: REQUEST_OBJECT_MEDIA_TYPE,
  CA_MEDIA_TYPE: CA_MEDIA_TYPE,
  DEFAULTS: DEFAULTS,
  enabled: enabled,
  urlsFor: urlsFor,
  readPublicBaseUrl: readPublicBaseUrl,
  configuredPublicBaseUrl: configuredPublicBaseUrl,
  publicBase: publicBase,
  create: create,
  publish: publish,
  publishFor: publishFor,
  fetchRequest: fetchRequest,
  fetchCa: fetchCa,
  respond: respond,
  events: events,
  remove: remove,
  limits: limits,
  sweep: sweep,
  sameSecret: sameSecret,
  readForm: readForm,
  setClock: setClock,
  setTimers: setTimers,
  pendingCount: pendingCount,
  reset: reset,
  shutdown: shutdown
};
