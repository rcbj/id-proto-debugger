// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ssf_receiver.js
//
// ---------------------------------------------------------------------------
// AN RFC 8935 PUSH ENDPOINT, HOSTED BY THIS SERVICE ON A PAGE'S BEHALF.
//
// This is the one thing in the Shared Signals workflow a browser genuinely
// cannot do, and the reason is not CORS or a certificate — it is that **a
// browser cannot be an HTTP SERVER**. RFC 8935 push delivery is the transmitter
// POSTing each Security Event Token to a URL the receiver gave it, so the
// receiver has to be reachable. A page is not.
//
// RFC 8936 poll delivery is the other way round — the receiver comes to the
// transmitter — so a page CAN be a poll receiver, with no api at all, and on
// the deployed static sites that is exactly what it is. **The split is a
// property of the two specifications and not of this service**, which is worth
// stating plainly because it is the one asymmetry in this workflow that cannot
// be designed away.
//
// So: a page asks this service for an inbox, gets back a URL, and puts that URL
// in the `delivery.endpoint_url` of the stream it creates. The transmitter
// pushes here; the page drains what arrived.
//
// ---------------------------------------------------------------------------
// THIS ENDPOINT ACCEPTS DATA FROM SOMEBODY ELSE'S TRANSMITTER, WHICH IS THE
// MOST DANGEROUS SHAPE ANYTHING IN THIS SERVICE HAS. SIX THINGS BOUND IT.
//
// The only credential in an RFC 8935 push is the `authorization_header` the
// RECEIVER chose and put in the stream's `delivery` (SSF 1.0 section 8.1.1),
// which the transmitter then sends as the Authorization header of every push.
//
// 0. **AN INBOX CREATED WITH AN AUTHORIZATION VALUE REQUIRES IT.** The page
//    passes the value it put in `delivery.authorization_header`, and every
//    push must carry exactly that Authorization header or is answered 401
//    `authentication_failed` (RFC 8935 section 2.4). An inbox created with
//    none is OPEN — anybody who has its URL can push to it — and both the
//    answer here and the page say so.
// 1. **AN INBOX EXISTS ONLY BECAUSE SOMEBODY ASKED FOR ONE**, and its id is 32
//    hex characters of `crypto.randomBytes`. There is no way to push to an
//    inbox nobody created, and no way to guess one.
// 2. **EVERY INBOX EXPIRES** — after `ssfReceiverIdleTtlMs` (default thirty
//    minutes) with no push, drain or clear, and after `ssfReceiverTtlMs`
//    (default one hour) whatever happens — and is swept when anything touches
//    this module. A page that closed its tab leaves nothing behind for long.
// 3. **THE COUNTS ARE CAPPED** — `ssfReceiverMaxInboxes` inboxes in all and
//    `ssfReceiverMaxInboxesPerCaller` for one caller's address, so one client
//    cannot hold every inbox; and `ssfReceiverMaxEvents` events in each,
//    oldest dropped. A transmitter that pushed in a loop fills one bounded
//    ring and stops.
// 4. **EACH EVENT IS SIZE-CAPPED** (`ssfReceiverMaxEventBytes`). A SET is a
//    JWS of a few hundred bytes; 64 KiB is three orders of magnitude of
//    headroom and still a bound. **AND EACH INBOX IS SIZE-CAPPED IN TOTAL**
//    (`ssfReceiverMaxInboxBytes`, default 1 MiB), oldest dropped first: the
//    three counts alone multiply out to 20 x 200 x 64 KiB, a quarter of a
//    gigabyte of text before the decoded header and claims are counted,
//    and anybody who can reach this service can create an inbox.
// 5. **IT IS OFF UNLESS THE CONFIGURATION SAYS OTHERWISE.**
//    `ssfReceiverEnabled` ships true on the local and containerized configs and
//    is false on the deployed ones, where there is no api at all — so the only
//    deployments that host an inbox are the ones somebody ran themselves.
//
// **NOTHING IS EXECUTED, RENDERED OR FORWARDED.** What arrives is stored as
// TEXT, handed back as text, and the page draws it into text nodes. This
// service does not verify the signature and does not try to: it holds no key of
// the transmitter's, and a receiver that refused what it could not verify would
// be unable to show a person WHY it could not — which is the question the
// workflow exists to answer. The page verifies, against a key the reader
// supplies or the transmitter's JWKS.
//
// ---------------------------------------------------------------------------
// IT IS IN MEMORY AND DIES WITH THE PROCESS, and that is deliberate rather than
// unfinished. What is held is a queue of security events about real people; the
// api writes nothing to disk anywhere else and this is not the feature to start
// with. A restart is a page that has to ask for a new inbox, which is the same
// thing the transmitter's own restart does to the stream.
//
// ---------------------------------------------------------------------------
// THIS FILE HAS NO EXPRESS AND NO NETWORK. `server.js` registers the routes and
// calls in; everything here is a decision about state, which is what lets
// `tests/api_ssf.js` drive the whole of it — the caps, the expiry, the sweep
// and every refusal — with no listener at all.
// ---------------------------------------------------------------------------

var crypto = require("crypto");
var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "ssf_receiver",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The media type RFC 8417 section 2.3 gives a Security Event Token. A push is
// REPORTED as carrying the wrong one rather than refused for it — see
// `deliver()` — because "your transmitter sends application/jwt" is exactly the
// kind of finding this workflow exists to make, and refusing would hide it
// behind a 400 the page could say nothing about.
var SET_MEDIA_TYPE = 'application/secevent+jwt';

var DEFAULTS = {
  enabled: true,
  ttlMs: 60 * 60 * 1000,
  idleTtlMs: 30 * 60 * 1000,
  maxInboxes: 20,
  maxInboxesPerCaller: 5,
  maxEvents: 200,
  maxEventBytes: 64 * 1024,
  maxInboxBytes: 1024 * 1024
};

// id -> { id, createdAt, lastPushAt, lastUsedAt, caller, authorization,
//        events: [...], bytes, pushes, dropped, label }
//
// `authorization` is the exact Authorization header a push must carry, or ''
// for an open inbox. It is never handed back by describe().
var inboxes = new Map();

function setting(appconfig, name, fallback) {
  log.debug("Entering setting(). " + name);
  var value = appconfig && appconfig[name];
  if (typeof value !== 'number' || !isFinite(value) || value <= 0) {
    if (value !== undefined && typeof value !== 'boolean') {
      log.warn("Ignoring " + name + "=" + JSON.stringify(value) +
               " — it must be a positive number. Using " + fallback + ".");
    }
    log.debug("Leaving setting(). Default " + fallback + ".");
    return fallback;
  }
  log.debug("Leaving setting(). " + value);
  return value;
}

// Only an explicit `false` turns it off, so a missing or misspelled key leaves
// the feature as the configuration file intended rather than silently disabling
// the one thing the push half of this workflow needs.
function enabled(appconfig) {
  log.debug("Entering enabled().");
  var value = appconfig && appconfig.ssfReceiverEnabled;
  var on = value !== false;
  log.debug("Leaving enabled(). " + on);
  return on;
}

// Drop what has expired. Called from every entry point rather than on a timer:
// a timer would keep this process's event loop alive for a feature nobody is
// using, and the cost of the sweep is one pass over at most `maxInboxes`
// entries.
function sweep(appconfig, now) {
  log.debug("Entering sweep().");
  var ttl = setting(appconfig, 'ssfReceiverTtlMs', DEFAULTS.ttlMs);
  var idle = setting(appconfig, 'ssfReceiverIdleTtlMs', DEFAULTS.idleTtlMs);
  var at = now || Date.now();
  var gone = 0;
  inboxes.forEach(function (inbox, id) {
    if (at - inbox.createdAt > ttl || at - inbox.lastUsedAt > idle) {
      inboxes.delete(id);
      gone++;
    }
  });
  if (gone) {
    log.debug("sweep(): " + gone + " inbox(es) expired.");
  }
  log.debug("Leaving sweep(). " + inboxes.size + " held.");
  return gone;
}

// ---------------------------------------------------------------------------
// Create an inbox. `label` is whatever the page calls it and is shown back
// unchanged; it is TEXT and is never interpreted. `authorization` is the
// stream's `delivery.authorization_header`, the exact Authorization header
// every push must then carry; empty makes an OPEN inbox. `caller` is who
// asked — server.js passes the request's address — and is what the
// per-caller cap counts.
// ---------------------------------------------------------------------------
function create(appconfig, options, caller) {
  log.debug("Entering create().");
  var asked = options || {};
  var who = String(caller || '');
  if (!enabled(appconfig)) {
    log.debug("Leaving create(). Disabled.");
    return { ok: false, error: 'This service does not host push receivers ' +
        '(ssfReceiverEnabled). RFC 8936 POLL delivery needs none — the ' +
        'receiver comes to the transmitter — so the workflow still works ' +
        'over that method with no api at all.' };
  }
  sweep(appconfig);
  var max = setting(appconfig, 'ssfReceiverMaxInboxes', DEFAULTS.maxInboxes);
  if (inboxes.size >= max) {
    log.debug("Leaving create(). At the inbox limit.");
    return { ok: false, error: 'This service is holding ' + inboxes.size +
        ' push receiver(s) and ssfReceiverMaxInboxes is ' + max + '. They ' +
        'expire on their own after ssfReceiverTtlMs; delete one to make ' +
        'room now.' };
  }
  var perCaller = setting(appconfig, 'ssfReceiverMaxInboxesPerCaller',
                          DEFAULTS.maxInboxesPerCaller);
  var mine = 0;
  inboxes.forEach(function (inbox) {
    if (inbox.caller === who) {
      mine++;
    }
  });
  if (mine >= perCaller) {
    log.debug("Leaving create(). At the per-caller limit.");
    return { ok: false, error: 'This caller already holds ' + mine +
        ' push receiver(s) and ssfReceiverMaxInboxesPerCaller is ' +
        perCaller + '. Delete one, or let one go idle ' +
        '(ssfReceiverIdleTtlMs).' };
  }
  var authorization = asked.authorization === undefined ||
    asked.authorization === null ? '' : String(asked.authorization).trim();
  if (authorization.length > 4096) {
    log.debug("Leaving create(). Authorization too long.");
    return { ok: false, error: 'That authorization_header is ' +
        authorization.length + ' characters; this receiver takes at most ' +
        '4096.' };
  }
  var id = crypto.randomBytes(16).toString('hex');
  var inbox = {
    id: id,
    label: String(asked.label || '').slice(0, 200),
    createdAt: Date.now(),
    lastPushAt: 0,
    lastUsedAt: Date.now(),
    caller: who,
    authorization: authorization,
    pushes: 0,
    dropped: 0,
    bytes: 0,
    events: []
  };
  inboxes.set(id, inbox);
  log.debug("Leaving create(). " + id);
  return { ok: true, id: id, inbox: describe(inbox) };
}

function get(appconfig, id) {
  log.debug("Entering get(). " + id);
  sweep(appconfig);
  var inbox = inboxes.get(String(id || '')) || null;
  log.debug("Leaving get(). " + (inbox ? "found" : "not found"));
  return inbox;
}

function remove(appconfig, id) {
  log.debug("Entering remove(). " + id);
  sweep(appconfig);
  var gone = inboxes.delete(String(id || ''));
  log.debug("Leaving remove(). " + gone);
  return gone;
}

// What an inbox is, without its events. The page polls `drain()` for those.
function describe(inbox) {
  log.debug("Entering describe().");
  var out = {
    id: inbox.id,
    label: inbox.label,
    createdAt: new Date(inbox.createdAt).toISOString(),
    lastPushAt: inbox.lastPushAt
      ? new Date(inbox.lastPushAt).toISOString() : '',
    // Whether a push must carry the stream's authorization_header. The
    // value itself is never handed back.
    authenticated: inbox.authorization !== '',
    pushes: inbox.pushes,
    dropped: inbox.dropped,
    waiting: inbox.events.length
  };
  log.debug("Leaving describe(). " + out.id);
  return out;
}

// ---------------------------------------------------------------------------
// A PUSH ARRIVES.
//
// Returns `{ ok, status, err, description }` — the RFC 8935 answer server.js
// sends back to the TRANSMITTER, which is a different audience from every other
// function in this file. Section 2.3 makes a success **202 with an empty
// body**; section 2.4 makes a failure a 400 with `{err, description}` from the
// SET Error Codes registry.
//
// **THREE THINGS ARE REPORTED RATHER THAN REFUSED**, and each is a finding this
// workflow exists to surface:
//
//   * the wrong media type — `application/jwt` instead of
//     `application/secevent+jwt` — because a receiver that dispatches on the
//     type, and several do, drops such a token with no error anybody sees;
//   * a body that is not three dot-separated parts, which is a transmitter
//     sending something that is not a compact JWS at all;
//   * a signature this service cannot check, which it never can — it holds no
//     key of the transmitter's. The PAGE verifies.
//
// What IS refused is what this service cannot store: an unknown inbox and an
// oversized body. Both are 400s naming the reason.
// ---------------------------------------------------------------------------
function deliver(appconfig, id, options) {
  log.debug("Entering deliver(). " + id);
  var asked = options || {};
  if (!enabled(appconfig)) {
    log.debug("Leaving deliver(). Disabled.");
    return { ok: false, status: 404, err: 'invalid_request',
      description: 'This service does not host push receivers ' +
        '(ssfReceiverEnabled).' };
  }
  var inbox = get(appconfig, id);
  if (!inbox) {
    log.debug("Leaving deliver(). No such inbox.");
    return { ok: false, status: 404, err: 'invalid_request',
      description: 'There is no receiver with that id here. Either it was ' +
        'never created, it has been deleted, or it expired ' +
        '(ssfReceiverTtlMs). A receiver that has gone away is a stream that ' +
        'should be deleted at the transmitter.' };
  }
  if (inbox.authorization !== '' &&
      !sameSecret(String(asked.authorization || ''), inbox.authorization)) {
    log.debug("Leaving deliver(). Authorization refused.");
    return { ok: false, status: 401, err: 'authentication_failed',
      description: 'This receiver requires the authorization_header its ' +
        'stream was created with, and this push ' +
        (asked.authorization ? 'carried a different Authorization header.'
          : 'carried no Authorization header.') };
  }
  var text = String(asked.body === undefined || asked.body === null
    ? '' : asked.body).trim();
  if (text === '') {
    log.debug("Leaving deliver(). Empty body.");
    return { ok: false, status: 400, err: 'invalid_request',
      description: 'The body is empty. RFC 8935 section 2.1 puts the ' +
        'Security Event Token in the body as application/secevent+jwt, with ' +
        'no form encoding and no JSON wrapper around it.' };
  }
  var limit = setting(appconfig, 'ssfReceiverMaxEventBytes',
                      DEFAULTS.maxEventBytes);
  var size = Buffer.byteLength(text, 'utf8');
  if (size > limit) {
    log.debug("Leaving deliver(). Too large: " + size);
    return { ok: false, status: 400, err: 'invalid_request',
      description: 'This Security Event Token is ' + size + ' bytes and ' +
        'this receiver accepts at most ' + limit +
        ' (ssfReceiverMaxEventBytes). A SET is a compact JWS of a few ' +
        'hundred bytes; something this large is not one.' };
  }
  var contentType = String(asked.contentType || '').split(';')[0]
    .trim().toLowerCase();
  var read = readCompactJws(text);
  var maxEvents = setting(appconfig, 'ssfReceiverMaxEvents',
                          DEFAULTS.maxEvents);
  // Never below one event's cap, so a single accepted event always fits.
  var maxBytes = Math.max(limit, setting(appconfig, 'ssfReceiverMaxInboxBytes',
                                         DEFAULTS.maxInboxBytes));
  // The OLDEST goes, by count and by total size. A receiver that has stopped
  // draining most wants what has happened lately, and refusing new events
  // would make a transmitter's push fail because a PAGE stopped reading.
  while (inbox.events.length &&
         (inbox.events.length >= maxEvents ||
          inbox.bytes + size > maxBytes)) {
    inbox.bytes -= inbox.events.shift().bytes;
    inbox.dropped++;
  }
  inbox.events.push({
    // The push's own number, from 0, which never moves when older events
    // are dropped. It is what `drain()`'s cursor counts.
    seq: inbox.pushes,
    at: new Date().toISOString(),
    token: text,
    bytes: size,
    contentType: contentType,
    correctMediaType: contentType === SET_MEDIA_TYPE,
    authorization: String(asked.authorization || '') !== '',
    header: read.header,
    claims: read.claims,
    problem: read.problem
  });
  inbox.bytes += size;
  inbox.pushes++;
  inbox.lastPushAt = Date.now();
  inbox.lastUsedAt = inbox.lastPushAt;
  log.debug("Leaving deliver(). Accepted, " + inbox.events.length +
      " waiting.");
  return { ok: true, status: 202, err: '', description: '' };
}

// The Authorization header a push carried against the one the inbox was
// created with, in constant time. The lengths are compared first, which says
// only how long the secret is.
function sameSecret(presented, expected) {
  log.debug("Entering sameSecret().");
  var a = Buffer.from(presented, 'utf8');
  var b = Buffer.from(expected, 'utf8');
  var same = a.length === b.length && crypto.timingSafeEqual(a, b);
  log.debug("Leaving sameSecret(). " + same);
  return same;
}

// Decode a compact JWS far enough to show it. NOT a verification and never
// will be: this service holds no key of the transmitter's, so the signature is
// the PAGE's to check. `problem` says what could not be read, and the token is
// kept whole either way — what arrived is the question being asked.
function readCompactJws(token) {
  log.debug("Entering readCompactJws().");
  var out = { header: null, claims: null, problem: '' };
  var parts = String(token).split('.');
  if (parts.length !== 3) {
    out.problem = 'This is not a compact JWS: a Security Event Token has ' +
        'three dot-separated parts and this has ' + parts.length + '.';
    log.debug("Leaving readCompactJws(). Not three parts.");
    return out;
  }
  try {
    out.header = JSON.parse(Buffer.from(parts[0], 'base64url')
        .toString('utf8'));
    out.claims = JSON.parse(Buffer.from(parts[1], 'base64url')
        .toString('utf8'));
  } catch (e) {
    // Undecodable. Reported rather than thrown, for the reason above.
    out.problem = 'The header or the payload would not decode as base64url ' +
        'JSON: ' + e.message;
  }
  log.debug("Leaving readCompactJws(). " + (out.problem || "read"));
  return out;
}

// ---------------------------------------------------------------------------
// The page collects. `after` is the number of PUSHES it has already seen —
// the `total` the previous drain answered — so a page that polls twice does
// not redraw the first lot. A cursor rather than a destructive read, because
// the events stay visible in the page's own history pane and a drain that
// emptied the inbox would make a second tab useless.
//
// It counts pushes and not positions in the ring. The caps drop the OLDEST
// event, and a cursor that was an index would then point past events the
// page has never seen: drop three, push five, and an index-based drain hands
// back two of the five.
// ---------------------------------------------------------------------------
function drain(appconfig, id, after) {
  log.debug("Entering drain(). " + id);
  var inbox = get(appconfig, id);
  if (!inbox) {
    log.debug("Leaving drain(). No such inbox.");
    return { ok: false, error: 'There is no receiver with that id here. ' +
        'Either it was never created, it has been deleted, or it expired ' +
        '(ssfReceiverTtlMs).' };
  }
  inbox.lastUsedAt = Date.now();
  var from = Number(after);
  if (!isFinite(from) || from < 0) {
    from = 0;
  }
  // A cursor from the future (a page holding a count from an inbox that has
  // since been deleted and recreated) is clamped, so the next push is seen.
  if (from > inbox.pushes) {
    from = inbox.pushes;
  }
  var out = {
    ok: true,
    inbox: describe(inbox),
    from: from,
    events: inbox.events.filter(function (one) {
      return one.seq >= from;
    }),
    total: inbox.pushes
  };
  log.debug("Leaving drain(). " + out.events.length + " new event(s).");
  return out;
}

// Empty an inbox without deleting it, for the page's Clear button.
function clear(appconfig, id) {
  log.debug("Entering clear(). " + id);
  var inbox = get(appconfig, id);
  if (!inbox) {
    log.debug("Leaving clear(). No such inbox.");
    return { ok: false, error: 'There is no receiver with that id here.' };
  }
  var gone = inbox.events.length;
  inbox.lastUsedAt = Date.now();
  inbox.events.length = 0;
  inbox.bytes = 0;
  log.debug("Leaving clear(). " + gone + " dropped.");
  return { ok: true, cleared: gone, inbox: describe(inbox) };
}

// What `GET /ssf/limits` publishes about this half, so the page can say whether
// push delivery is available BEFORE somebody creates a stream that can never be
// delivered on.
function limits(appconfig) {
  log.debug("Entering limits().");
  var out = {
    enabled: enabled(appconfig),
    ttlMs: setting(appconfig, 'ssfReceiverTtlMs', DEFAULTS.ttlMs),
    idleTtlMs: setting(appconfig, 'ssfReceiverIdleTtlMs', DEFAULTS.idleTtlMs),
    maxInboxes: setting(appconfig, 'ssfReceiverMaxInboxes',
                        DEFAULTS.maxInboxes),
    maxInboxesPerCaller: setting(appconfig, 'ssfReceiverMaxInboxesPerCaller',
                                 DEFAULTS.maxInboxesPerCaller),
    maxEvents: setting(appconfig, 'ssfReceiverMaxEvents', DEFAULTS.maxEvents),
    maxEventBytes: setting(appconfig, 'ssfReceiverMaxEventBytes',
                           DEFAULTS.maxEventBytes),
    maxInboxBytes: setting(appconfig, 'ssfReceiverMaxInboxBytes',
                           DEFAULTS.maxInboxBytes),
    held: inboxes.size,
    mediaType: SET_MEDIA_TYPE,
    verifies: false,
    note: 'A browser cannot be an HTTP server, so it cannot be the far end ' +
        'of RFC 8935 push delivery. This service hosts one on the page\'s ' +
        'behalf: ask for an inbox, put its URL in the stream\'s ' +
        'delivery.endpoint_url, and drain what arrives. RFC 8936 POLL ' +
        'delivery needs none of this — the receiver comes to the ' +
        'transmitter — which is why the deployed static sites can still ' +
        'run the whole workflow over that method.',
    doesNotVerify: 'This service does not check a signature and cannot: it ' +
        'holds no key of the transmitter\'s. A receiver that refused what ' +
        'it could not verify would be unable to show anybody WHY, which is ' +
        'the question being asked. The page verifies.'
  };
  log.debug("Leaving limits().");
  return out;
}

// For the tests, which need to start from a known state without a restart.
function reset() {
  log.debug("Entering reset().");
  var gone = inboxes.size;
  inboxes.clear();
  log.debug("Leaving reset(). " + gone + " dropped.");
  return gone;
}

module.exports = {
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  DEFAULTS: DEFAULTS,
  enabled: enabled,
  create: create,
  get: get,
  remove: remove,
  describe: describe,
  deliver: deliver,
  readCompactJws: readCompactJws,
  sameSecret: sameSecret,
  drain: drain,
  clear: clear,
  sweep: sweep,
  limits: limits,
  reset: reset
};
