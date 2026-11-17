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
  maxSessionBytes: 1024 * 1024
};

// Text members a page may set, and the most of each it may.
var MAX_REDIRECT_URI = 4096;

// id -> { id, secret, caller, createdAt, lastUsedAt, ttlMs, idleTtlMs,
//        redirectUri, requestObject, caDer, events, total, dropped, bytes }
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
      sessions.delete(id);
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
// POST /oid4vp/verifier. `options` is { redirectUri?, ttlMs?, idleTtlMs? };
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
    bytes: 0
  };
  sessions.set(one.id, one);
  log.debug('Leaving create(). ' + one.id);
  return { ok: true, status: 201, id: one.id, secret: one.secret,
    expiresAt: expiresAt(one) };
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
function publish(appconfig, id, authorization, body) {
  log.debug('Entering publish(). ' + id);
  var auth = authorized(appconfig, id, authorization);
  if (!auth.ok) {
    log.debug('Leaving publish(). ' + auth.status);
    return auth;
  }
  var one = auth.session;
  var asked = body || {};
  var jws = asked.requestObject === undefined || asked.requestObject === null
    ? '' : String(asked.requestObject).trim();
  if (jws === '') {
    log.debug('Leaving publish(). No request object.');
    return { ok: false, status: 400, error: 'requestObject is required: ' +
        'the signed Request Object, as a compact JWS, that the Wallet ' +
        'will fetch from request_uri.' };
  }
  var limit = setting(appconfig, 'oid4vpVerifierMaxRequestObjectBytes',
                      DEFAULTS.maxRequestObjectBytes);
  var size = Buffer.byteLength(jws, 'utf8');
  if (size > limit) {
    log.debug('Leaving publish(). Too large: ' + size);
    return { ok: false, status: 400, error: 'requestObject is ' + size +
        ' bytes and this service serves at most ' + limit +
        ' (oid4vpVerifierMaxRequestObjectBytes).' };
  }
  if (!COMPACT_JWS.test(jws)) {
    log.debug('Leaving publish(). Not a compact JWS.');
    return { ok: false, status: 400, error: 'requestObject is not a ' +
        'compact JWS: three base64url segments separated by dots, the ' +
        'first two not empty. An encrypted Request Object (five segments) ' +
        'is not served here.' };
  }
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
// since that is the one error shape a Wallet is sure to read.
function walletError(status, description) {
  log.debug('Entering walletError(). ' + status);
  var out = { ok: false, status: status, error: status === 404
    ? 'not_found' : 'invalid_request', error_description: description };
  log.debug('Leaving walletError().');
  return out;
}

// ---------------------------------------------------------------------------
// GET or POST /oid4vp/verifier/:id/request — a Wallet fetches the Request
// Object. `request` is { method, contentType, rawBody, parsed,
// remoteAddress }. Under request_uri_method=post (section 5.10) the body
// carries `wallet_metadata` and `wallet_nonce`, which are recorded; the
// object served is still the one the page signed, which CANNOT echo a
// wallet_nonce it never saw — the page reports that.
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
  if (asked.remoteAddress) {
    event.remoteAddress = String(asked.remoteAddress);
  }
  if (method === 'POST') {
    var read = fieldsOf(asked);
    event.contentType = String(asked.contentType || '');
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
      }
    }
    bytes = sizeOf(asked);
    if (bytes > setting(appconfig, 'oid4vpVerifierMaxResponseBytes',
                        DEFAULTS.maxResponseBytes)) {
      // Too large to keep: the fetch is still answered and recorded, but
      // not what came with it.
      delete event.walletMetadata;
      delete event.walletNonce;
      event.problem = 'The POST body was ' + bytes + ' bytes, above ' +
          'oid4vpVerifierMaxResponseBytes, and was not kept.';
      bytes = 0;
    }
  }
  record(appconfig, one, event, bytes);
  log.debug('Leaving fetchRequest(). Served.');
  return { ok: true, status: 200, contentType: REQUEST_OBJECT_MEDIA_TYPE,
    body: one.requestObject };
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

// ---------------------------------------------------------------------------
// POST /oid4vp/verifier/:id/response — a Wallet's answer under direct_post
// (vp_token, state, ...) or direct_post.jwt (response, the JWE). Every field
// is kept VERBATIM and nothing is checked: the page decrypts and judges.
// The answer is section 8.2's: 200 with a JSON object, carrying
// `redirect_uri` when the page set one.
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
  record(appconfig, one, event, size);
  var body = one.redirectUri ? { redirect_uri: one.redirectUri } : {};
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
  sessions.delete(auth.session.id);
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
  sessions.clear();
  log.debug('Leaving reset(). ' + gone + ' dropped.');
  return gone;
}

module.exports = {
  REQUEST_OBJECT_MEDIA_TYPE: REQUEST_OBJECT_MEDIA_TYPE,
  CA_MEDIA_TYPE: CA_MEDIA_TYPE,
  DEFAULTS: DEFAULTS,
  enabled: enabled,
  urlsFor: urlsFor,
  create: create,
  publish: publish,
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
  reset: reset
};
