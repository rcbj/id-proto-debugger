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
// THIS IS AN UNAUTHENTICATED ENDPOINT THAT ACCEPTS DATA, WHICH IS THE MOST
// DANGEROUS SHAPE ANYTHING IN THIS SERVICE HAS. FIVE THINGS BOUND IT.
//
// It has to be unauthenticated: what pushes to it is somebody else's
// transmitter, and the only credential in that exchange is the
// `authorization_header` the RECEIVER chose — which this service would have to
// be told, and which does not authenticate the transmitter to us anyway. So the
// bounds are structural rather than a gate.
//
// 1. **AN INBOX EXISTS ONLY BECAUSE SOMEBODY ASKED FOR ONE**, and its id is 32
//    hex characters of `crypto.randomBytes`. There is no way to push to an
//    inbox nobody created, and no way to guess one.
// 2. **EVERY INBOX EXPIRES** (`ssfReceiverTtlMs`, default one hour) and is
//    swept when anything touches this module. A page that closed its tab leaves
//    nothing behind for longer than that.
// 3. **THE COUNTS ARE CAPPED** — `ssfReceiverMaxInboxes` inboxes, and
//    `ssfReceiverMaxEvents` events in each, oldest dropped. A transmitter that
//    pushed in a loop fills one bounded ring and stops.
// 4. **EACH EVENT IS SIZE-CAPPED** (`ssfReceiverMaxEventBytes`). A SET is a
//    JWS of a few hundred bytes; 64 KiB is three orders of magnitude of
//    headroom and still a bound.
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
  maxInboxes: 20,
  maxEvents: 200,
  maxEventBytes: 64 * 1024
};

// id -> { id, createdAt, lastPushAt, events: [...], pushes, dropped, label }
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
  var at = now || Date.now();
  var gone = 0;
  inboxes.forEach(function (inbox, id) {
    if (at - inbox.createdAt > ttl) {
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
// unchanged; it is TEXT and is never interpreted.
// ---------------------------------------------------------------------------
function create(appconfig, options) {
  log.debug("Entering create().");
  var asked = options || {};
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
  var id = crypto.randomBytes(16).toString('hex');
  var inbox = {
    id: id,
    label: String(asked.label || '').slice(0, 200),
    createdAt: Date.now(),
    lastPushAt: 0,
    pushes: 0,
    dropped: 0,
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
  if (inbox.events.length >= maxEvents) {
    // The OLDEST goes. A receiver that has stopped draining most wants what
    // has happened lately, and refusing new events would make a transmitter's
    // push fail because a PAGE stopped reading.
    inbox.events.shift();
    inbox.dropped++;
  }
  inbox.events.push({
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
  inbox.pushes++;
  inbox.lastPushAt = Date.now();
  log.debug("Leaving deliver(). Accepted, " + inbox.events.length +
      " waiting.");
  return { ok: true, status: 202, err: '', description: '' };
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
// The page collects. `after` is the number of events it has already seen, so a
// page that polls twice does not redraw the first lot — a cursor rather than a
// destructive read, because the events stay visible in the page's own history
// pane and a drain that emptied the inbox would make a second tab useless.
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
  var from = Number(after);
  if (!isFinite(from) || from < 0) {
    from = 0;
  }
  // A cap that has been reached SHIFTS the array, so an index a page is
  // holding can point past what is there. Clamping rather than failing: the
  // page's own count is then simply behind, and the next poll catches up.
  if (from > inbox.events.length) {
    from = inbox.events.length;
  }
  var out = {
    ok: true,
    inbox: describe(inbox),
    from: from,
    events: inbox.events.slice(from),
    total: inbox.events.length
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
  inbox.events.length = 0;
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
    maxInboxes: setting(appconfig, 'ssfReceiverMaxInboxes',
                        DEFAULTS.maxInboxes),
    maxEvents: setting(appconfig, 'ssfReceiverMaxEvents', DEFAULTS.maxEvents),
    maxEventBytes: setting(appconfig, 'ssfReceiverMaxEventBytes',
                           DEFAULTS.maxEventBytes),
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
  drain: drain,
  clear: clear,
  sweep: sweep,
  limits: limits,
  reset: reset
};
