// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ssf_transmitter.js
//
// ---------------------------------------------------------------------------
// AN SSF TRANSMITTER, HOSTED BY THIS SERVICE ON A PAGE'S BEHALF (#363).
//
// The mirror image of `ssf_receiver.js`. A receiver that treats its partner
// as a real SSF 1.0 transmitter does three things a page cannot be the far
// end of:
//
//   1. it FETCHES the transmitter's configuration metadata
//      (`/.well-known/ssf-configuration` + the issuer's path, section 7) and
//      the `jwks_uri` it names;
//   2. it CREATES ITS STREAM at the transmitter's `configuration_endpoint`
//      (section 8.1.1), and for push hands the transmitter an
//      `endpoint_url` and the `authorization_header` to push with;
//   3. it may change the stream's status, add and remove subjects, ask for a
//      verification event, and — for RFC 8936 — POLL.
//
// Every one of those is a request arriving at a server, and a browser is not
// one. So the page asks this service for a transmitter, and gets back an
// issuer URL a receiver can be pointed at. The receiver talks to THIS
// service; the page reads what the receiver did, and hands this service the
// Security Event Tokens to deliver.
//
// THE PAGE SIGNS. This service holds the PUBLIC half of the page's key, which
// it publishes at `jwks_uri`, and never a private key: every SET is built and
// signed in the page, exactly as the Transmit pane always has, and arrives
// here already signed. A verification event the receiver asks for is queued
// for the page to sign and send; this service cannot make one.
//
// ---------------------------------------------------------------------------
// TWO CREDENTIALS, BECAUSE THERE ARE TWO PARTIES.
//
// * The RECEIVER CREDENTIAL is the bearer token every request to the stream
//   management API and the poll endpoint must carry (SSF 1.0 section 8 has
//   the transmitter authorize the receiver; `authorization_schemes` in the
//   metadata names RFC 6750). It is generated here unless the page supplies
//   one, and the page hands it to the receiver's operator — for iya-sts,
//   `fedSignalsBearer` on the federation relationship.
// * The OWNER KEY is what the PAGE presents to read the instance, deliver
//   and delete it. The instance id is not a secret — it is in the issuer
//   URL, which the receiver is given — so it cannot be the capability the
//   receiver inbox's id is.
//
// Both are compared in constant time and neither is ever handed back after
// creation.
//
// ---------------------------------------------------------------------------
// THE SAME BOUNDS AS THE INBOX, AND FOR THE SAME REASONS: an instance exists
// only because a page asked; every one EXPIRES (`ssfTransmitterIdleTtlMs`,
// `ssfTransmitterTtlMs`); the counts are capped (`ssfTransmitterMaxInstances`,
// `…PerCaller`, `…MaxStreams`, `…MaxQueued`); every SET is size-capped
// (`ssfTransmitterMaxEventBytes`); and it is OFF unless the configuration says
// otherwise (`ssfTransmitterEnabled`, false on the deployed sites, which have
// no api at all). It is in memory and dies with the process.
//
// THIS FILE HAS NO EXPRESS AND NO NETWORK. `server.js` registers the routes,
// performs the push, and calls in; everything here is a decision about
// state, which is what lets `tests/api_ssf.js` drive all of it with no
// listener.
// ---------------------------------------------------------------------------

var crypto = require("crypto");
var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "ssf_transmitter",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var PUSH = "urn:ietf:rfc:8935";
var POLL = "urn:ietf:rfc:8936";
var SET_MEDIA_TYPE = "application/secevent+jwt";
var VERIFICATION =
  "https://schemas.openid.net/secevent/ssf/event-type/verification";
var STREAM_UPDATED =
  "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
var STATUSES = ["enabled", "paused", "disabled"];

var DEFAULTS = {
  ttlMs: 60 * 60 * 1000,
  idleTtlMs: 30 * 60 * 1000,
  maxInstances: 10,
  maxInstancesPerCaller: 3,
  maxStreams: 5,
  maxQueued: 200,
  maxEventBytes: 64 * 1024,
  maxLog: 100
};

// The members a JWK carries only when it is PRIVATE. A key set holding one
// would publish the page's signing key at jwks_uri.
var PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

// id -> instance. See create() for the shape.
var instances = new Map();

function setting(appconfig, name, fallback) {
  log.debug("Entering setting(). " + name);
  var value = appconfig && appconfig[name];
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    if (value !== undefined && typeof value !== "boolean") {
      log.warn("Ignoring " + name + "=" + JSON.stringify(value) +
               " — it must be a positive number. Using " + fallback + ".");
    }
    log.debug("Leaving setting(). Default " + fallback + ".");
    return fallback;
  }
  log.debug("Leaving setting(). " + value);
  return value;
}

// Only an explicit `false` turns it off, as for the receiver.
function enabled(appconfig) {
  log.debug("Entering enabled().");
  var on = !(appconfig && appconfig.ssfTransmitterEnabled === false);
  log.debug("Leaving enabled(). " + on);
  return on;
}

function randomToken() {
  log.debug("Entering randomToken().");
  log.debug("Leaving randomToken().");
  return crypto.randomBytes(32).toString("base64url");
}

function sameSecret(presented, expected) {
  log.debug("Entering sameSecret().");
  var a = Buffer.from(String(presented || ""), "utf8");
  var b = Buffer.from(String(expected || ""), "utf8");
  var same = b.length > 0 && a.length === b.length &&
    crypto.timingSafeEqual(a, b);
  log.debug("Leaving sameSecret(). " + same);
  return same;
}

// The token out of an `Authorization: Bearer x` header, or "".
function bearerOf(header) {
  log.debug("Entering bearerOf().");
  var m = /^Bearer\s+(.+)$/i.exec(String(header || "").trim());
  log.debug("Leaving bearerOf(). " + !!m);
  return m ? m[1].trim() : "";
}

function sweep(appconfig, now) {
  log.debug("Entering sweep().");
  var ttl = setting(appconfig, "ssfTransmitterTtlMs", DEFAULTS.ttlMs);
  var idle = setting(appconfig, "ssfTransmitterIdleTtlMs",
                     DEFAULTS.idleTtlMs);
  var at = now || Date.now();
  var gone = 0;
  instances.forEach(function (one, id) {
    if (at - one.createdAt > Math.min(one.ttlMs, ttl) ||
        at - one.lastUsedAt > Math.min(one.idleTtlMs, idle)) {
      instances.delete(id);
      gone++;
    }
  });
  log.debug("Leaving sweep(). " + gone + " expired, " + instances.size +
            " held.");
  return gone;
}

// A positive whole number at most `ceiling`, the default when absent, or
// { error }.
function ownLimit(name, asked, ceiling) {
  log.debug("Entering ownLimit(). " + name);
  if (asked === undefined || asked === null || asked === "") {
    log.debug("Leaving ownLimit(). Default.");
    return { value: ceiling };
  }
  var n = Number(asked);
  if (typeof asked === "boolean" || !isFinite(n) || n <= 0 ||
      Math.floor(n) !== n) {
    log.debug("Leaving ownLimit(). Malformed.");
    return { error: name + " must be a positive whole number; it was " +
             JSON.stringify(asked) + "." };
  }
  if (n > ceiling) {
    log.debug("Leaving ownLimit(). Above the ceiling.");
    return { error: name + " " + n + " is above this service's ceiling, " +
             ceiling + ". A page may ask for less, never more." };
  }
  log.debug("Leaving ownLimit().");
  return { value: n };
}

// The public key set the page signs with. Every key must be a JWK with a kty
// and NO private member: what is given here is published at jwks_uri.
function checkJwks(jwks) {
  log.debug("Entering checkJwks().");
  if (!jwks || typeof jwks !== "object" || !Array.isArray(jwks.keys) ||
      !jwks.keys.length) {
    log.debug("Leaving checkJwks(). Not a key set.");
    return { error: "jwks must be a JWK Set — { \"keys\": [ … ] } — with at " +
             "least one key: the public half of the key the page signs " +
             "with. A receiver verifies every SET against it." };
  }
  if (jwks.keys.length > 10) {
    log.debug("Leaving checkJwks(). Too many.");
    return { error: "jwks holds " + jwks.keys.length + " keys; this service " +
             "publishes at most 10." };
  }
  var keys = [];
  for (var i = 0; i < jwks.keys.length; i++) {
    var k = jwks.keys[i];
    if (!k || typeof k !== "object" || typeof k.kty !== "string") {
      log.debug("Leaving checkJwks(). Key " + i + " has no kty.");
      return { error: "jwks.keys[" + i + "] is not a JWK: it has no kty." };
    }
    var leaked = PRIVATE_MEMBERS.filter(function (m) {
      return k[m] !== undefined;
    });
    if (leaked.length) {
      log.debug("Leaving checkJwks(). Private members.");
      return { error: "jwks.keys[" + i + "] carries " + leaked.join(", ") +
               ", which only a PRIVATE key has. This service publishes " +
               "what it is given at jwks_uri, so it takes the public half " +
               "only — the page keeps the private one and signs." };
    }
    keys.push(JSON.parse(JSON.stringify(k)));
  }
  log.debug("Leaving checkJwks(). " + keys.length + " key(s).");
  return { keys: keys };
}

function checkEvents(list) {
  log.debug("Entering checkEvents().");
  if (list === undefined || list === null) {
    log.debug("Leaving checkEvents(). None.");
    return { events: [] };
  }
  if (!Array.isArray(list) || list.length > 100 ||
      list.some(function (u) {
        return typeof u !== "string" || !u || u.length > 512;
      })) {
    log.debug("Leaving checkEvents(). Malformed.");
    return { error: "eventsSupported must be an array of at most 100 event " +
             "type URIs." };
  }
  var seen = {};
  var out = list.filter(function (u) {
    var fresh = !seen[u];
    seen[u] = true;
    return fresh;
  });
  log.debug("Leaving checkEvents(). " + out.length);
  return { events: out };
}

// ---------------------------------------------------------------------------
// The page asks for a transmitter. `base` is this service's address as the
// caller reached it (server.js's publicBaseUrl()), which becomes the issuer:
// it is what the receiver will be pointed at, so it is fixed now rather than
// recomputed per request — a receiver that reached the api by another name
// must still see the issuer it was configured with.
// ---------------------------------------------------------------------------
function create(appconfig, options, caller, base) {
  log.debug("Entering create().");
  var asked = options || {};
  var who = String(caller || "");
  if (!enabled(appconfig)) {
    log.debug("Leaving create(). Disabled.");
    return { ok: false, error: "This service does not host SSF " +
      "transmitters (ssfTransmitterEnabled)." };
  }
  sweep(appconfig);
  var max = setting(appconfig, "ssfTransmitterMaxInstances",
                    DEFAULTS.maxInstances);
  if (instances.size >= max) {
    log.debug("Leaving create(). At the limit.");
    return { ok: false, error: "This service is hosting " + instances.size +
      " transmitter(s) and ssfTransmitterMaxInstances is " + max + ". They " +
      "expire on their own; delete one to make room now." };
  }
  var perCaller = setting(appconfig, "ssfTransmitterMaxInstancesPerCaller",
                          DEFAULTS.maxInstancesPerCaller);
  var mine = 0;
  instances.forEach(function (one) {
    if (one.caller === who) {
      mine++;
    }
  });
  if (mine >= perCaller) {
    log.debug("Leaving create(). At the per-caller limit.");
    return { ok: false, error: "This caller already hosts " + mine +
      " transmitter(s) and ssfTransmitterMaxInstancesPerCaller is " +
      perCaller + ". Delete one first." };
  }
  var keys = checkJwks(asked.jwks);
  if (keys.error) {
    log.debug("Leaving create(). JWKS refused.");
    return { ok: false, error: keys.error };
  }
  var events = checkEvents(asked.eventsSupported);
  if (events.error) {
    log.debug("Leaving create(). Events refused.");
    return { ok: false, error: events.error };
  }
  var credential = asked.receiverCredential === undefined ||
    asked.receiverCredential === null || asked.receiverCredential === ""
    ? randomToken() : String(asked.receiverCredential);
  if (credential.length < 16 || credential.length > 512 ||
      /\s/.test(credential)) {
    log.debug("Leaving create(). Credential refused.");
    return { ok: false, error: "receiverCredential must be 16 to 512 " +
      "characters with no whitespace — it is a bearer token the receiver " +
      "presents. Leave it out and one is generated." };
  }
  var idle = ownLimit("idleTtlMs", asked.idleTtlMs,
    setting(appconfig, "ssfTransmitterIdleTtlMs", DEFAULTS.idleTtlMs));
  var ttl = ownLimit("ttlMs", asked.ttlMs,
    setting(appconfig, "ssfTransmitterTtlMs", DEFAULTS.ttlMs));
  if (idle.error || ttl.error) {
    log.debug("Leaving create(). Lifetime refused.");
    return { ok: false, error: idle.error || ttl.error };
  }
  var id = crypto.randomBytes(16).toString("hex");
  var now = Date.now();
  var one = {
    id: id,
    label: String(asked.label || "").slice(0, 200),
    issuer: String(base || "").replace(/\/+$/, "") + "/ssf/transmitter/" + id,
    createdAt: now,
    lastUsedAt: now,
    idleTtlMs: idle.value,
    ttlMs: ttl.value,
    caller: who,
    ownerKey: randomToken(),
    credential: credential,
    jwks: { keys: keys.keys },
    eventsSupported: events.events,
    streams: new Map(),
    pending: [],
    log: []
  };
  instances.set(id, one);
  log.debug("Leaving create(). " + id);
  return { ok: true, id: id, ownerKey: one.ownerKey,
           receiverCredential: credential, transmitter: describe(one) };
}

function get(appconfig, id) {
  log.debug("Entering get(). " + id);
  sweep(appconfig);
  var one = instances.get(String(id || "")) || null;
  if (one) {
    one.lastUsedAt = Date.now();
  }
  log.debug("Leaving get(). " + !!one);
  return one;
}

// The page's own requests: the instance, if the owner key is right.
// { ok, instance } or { ok: false, status, error }.
function forOwner(appconfig, id, authorization) {
  log.debug("Entering forOwner().");
  var one = get(appconfig, id);
  if (!one) {
    log.debug("Leaving forOwner(). Not found.");
    return { ok: false, status: 404, error: "There is no transmitter with " +
      "that id here. Either it was never created, it has been deleted, or " +
      "it expired (ssfTransmitterTtlMs)." };
  }
  if (!sameSecret(bearerOf(authorization), one.ownerKey)) {
    log.debug("Leaving forOwner(). Wrong owner key.");
    return { ok: false, status: 401, error: "This transmitter is read, " +
      "delivered through and deleted with the owner key it was created " +
      "with, as \"Authorization: Bearer <ownerKey>\"." };
  }
  log.debug("Leaving forOwner().");
  return { ok: true, instance: one };
}

// A RECEIVER's request to the stream management API or the poll endpoint.
// The answers are SSF's: 401 with no credential or a wrong one, 404 for an
// unknown transmitter. { ok, instance } or { ok: false, status, err,
// description }.
function forReceiver(appconfig, id, authorization) {
  log.debug("Entering forReceiver().");
  if (!enabled(appconfig)) {
    log.debug("Leaving forReceiver(). Disabled.");
    return { ok: false, status: 404, err: "not_found",
      description: "This service does not host SSF transmitters." };
  }
  var one = get(appconfig, id);
  if (!one) {
    log.debug("Leaving forReceiver(). Not found.");
    return { ok: false, status: 404, err: "not_found",
      description: "There is no transmitter with that id here; it may have " +
        "expired." };
  }
  var presented = bearerOf(authorization);
  if (!sameSecret(presented, one.credential)) {
    log.debug("Leaving forReceiver(). Credential refused.");
    note(one, { kind: "refused", detail: presented
      ? "a request carried a bearer token that is not this transmitter's " +
        "receiver credential"
      : "a request carried no bearer token" });
    return { ok: false, status: 401, err: "authentication_failed",
      description: presented ? "That bearer token is not this " +
        "transmitter's receiver credential." : "The stream management API " +
        "needs \"Authorization: Bearer <receiver credential>\" (RFC 6750)." };
  }
  log.debug("Leaving forReceiver().");
  return { ok: true, instance: one };
}

// One line in the instance's log, which the page reads. Bounded, oldest
// first out.
function note(one, row) {
  log.debug("Entering note(). " + row.kind);
  var cap = DEFAULTS.maxLog;
  one.log.push(Object.assign({ at: new Date().toISOString() }, row));
  while (one.log.length > cap) {
    one.log.shift();
  }
  log.debug("Leaving note().");
}

// ---------------------------------------------------------------------------
// SSF 1.0 section 7.1: the Transmitter Configuration Metadata.
// ---------------------------------------------------------------------------
function discoveryUrl(one) {
  log.debug("Entering discoveryUrl().");
  var u = new URL(one.issuer);
  log.debug("Leaving discoveryUrl().");
  return u.origin + "/.well-known/ssf-configuration" +
    u.pathname.replace(/\/+$/, "");
}

function metadata(one) {
  log.debug("Entering metadata().");
  var base = one.issuer;
  var out = {
    spec_version: "1_0",
    issuer: base,
    jwks_uri: base + "/jwks",
    delivery_methods_supported: [PUSH, POLL],
    configuration_endpoint: base + "/stream",
    status_endpoint: base + "/status",
    add_subject_endpoint: base + "/subjects/add",
    remove_subject_endpoint: base + "/subjects/remove",
    verification_endpoint: base + "/verify",
    authorization_schemes: [{ spec_urn: "urn:ietf:rfc:6750" }],
    default_subjects: "NONE"
  };
  log.debug("Leaving metadata().");
  return out;
}

function publicJwks(one) {
  log.debug("Entering publicJwks().");
  log.debug("Leaving publicJwks().");
  return { keys: one.jwks.keys.map(function (k) {
    return Object.assign({}, k);
  }) };
}

// The metadata and keys of an instance by id, for the two unauthenticated
// routes. null when there is none.
function published(appconfig, id) {
  log.debug("Entering published().");
  if (!enabled(appconfig)) {
    log.debug("Leaving published(). Disabled.");
    return null;
  }
  var one = get(appconfig, id);
  log.debug("Leaving published(). " + !!one);
  return one ? { metadata: metadata(one), jwks: publicJwks(one) } : null;
}

// ---------------------------------------------------------------------------
// SSF 1.0 section 8.1.1: the stream configuration.
// ---------------------------------------------------------------------------
// What a receiver sees. `authorization_header` is the RECEIVER's own secret
// and is never echoed back; `queued` and `held` are this service's own and
// say what is waiting.
function streamView(one, s) {
  log.debug("Entering streamView().");
  var out = {
    stream_id: s.stream_id,
    iss: one.issuer,
    aud: s.aud,
    events_supported: one.eventsSupported.slice(),
    events_requested: s.events_requested.slice(),
    events_delivered: s.events_delivered.slice(),
    delivery: { method: s.delivery.method,
                endpoint_url: s.delivery.endpoint_url },
    min_verification_interval: 0
  };
  if (s.description) {
    out.description = s.description;
  }
  log.debug("Leaving streamView().");
  return out;
}

// What the PAGE sees of a stream: the receiver's view plus the status, the
// subjects and what is queued — and whether the push carries a credential,
// never the credential itself.
function streamForOwner(one, s) {
  log.debug("Entering streamForOwner().");
  var out = streamView(one, s);
  out.status = s.status;
  out.reason = s.reason;
  out.subjects = s.subjects.slice();
  out.pushAuthorized = !!s.delivery.authorization_header;
  out.queued = s.queue.length;
  out.held = s.held.length;
  out.createdAt = s.createdAt;
  log.debug("Leaving streamForOwner().");
  return out;
}

// The delivery a receiver asked for, or { error }. Push needs an http(s)
// endpoint_url to push to; poll is given this transmitter's own.
function readDelivery(one, streamId, delivery) {
  log.debug("Entering readDelivery().");
  var d = delivery || {};
  if (typeof d !== "object" || Array.isArray(d)) {
    log.debug("Leaving readDelivery(). Not an object.");
    return { error: "delivery must be an object with a method." };
  }
  var method = String(d.method || "");
  if (method !== PUSH && method !== POLL) {
    log.debug("Leaving readDelivery(). Method.");
    return { error: "delivery.method must be " + PUSH + " (push) or " + POLL +
             " (poll), the two this transmitter supports; it was " +
             JSON.stringify(d.method) + "." };
  }
  if (method === POLL) {
    log.debug("Leaving readDelivery(). Poll.");
    return { delivery: { method: POLL,
      endpoint_url: one.issuer + "/poll/" + streamId,
      authorization_header: "" } };
  }
  var url = String(d.endpoint_url || "");
  var parsed = null;
  try {
    parsed = new URL(url);
  } catch (e) {
    parsed = null;
  }
  if (!parsed || (parsed.protocol !== "https:" &&
                  parsed.protocol !== "http:")) {
    log.debug("Leaving readDelivery(). Push endpoint.");
    return { error: "Push delivery needs delivery.endpoint_url, an http or " +
             "https URL this transmitter POSTs each SET to (RFC 8935)." };
  }
  var auth = d.authorization_header === undefined ||
    d.authorization_header === null ? "" : String(d.authorization_header);
  if (auth.length > 4096 || /[\r\n]/.test(auth)) {
    log.debug("Leaving readDelivery(). Authorization header.");
    return { error: "delivery.authorization_header must be one line of at " +
             "most 4096 characters." };
  }
  log.debug("Leaving readDelivery(). Push.");
  return { delivery: { method: PUSH, endpoint_url: url,
                       authorization_header: auth } };
}

function delivered(one, requested) {
  log.debug("Entering delivered().");
  var out = requested.length ? requested.filter(function (u) {
    return one.eventsSupported.indexOf(u) >= 0;
  }) : one.eventsSupported.slice();
  log.debug("Leaving delivered(). " + out.length);
  return out;
}

function readEventsRequested(value) {
  log.debug("Entering readEventsRequested().");
  if (value === undefined || value === null) {
    log.debug("Leaving readEventsRequested(). None.");
    return { events: [] };
  }
  if (!Array.isArray(value) || value.some(function (u) {
    return typeof u !== "string";
  })) {
    log.debug("Leaving readEventsRequested(). Malformed.");
    return { error: "events_requested must be an array of event type URIs." };
  }
  log.debug("Leaving readEventsRequested().");
  return { events: value.slice(0, 100) };
}

function streamOf(one, streamId) {
  log.debug("Entering streamOf().");
  log.debug("Leaving streamOf().");
  return one.streams.get(String(streamId || "")) || null;
}

function noStream(streamId) {
  log.debug("Entering noStream().");
  log.debug("Leaving noStream().");
  return { ok: false, status: 404, err: "not_found",
    description: streamId ? "There is no stream " + streamId + " at this " +
      "transmitter." : "stream_id is required." };
}

function badRequest(description) {
  log.debug("Entering badRequest().");
  log.debug("Leaving badRequest().");
  return { ok: false, status: 400, err: "invalid_request",
           description: description };
}

// POST configuration_endpoint (8.1.1.1). 201 with the stream.
function createStream(appconfig, one, body) {
  log.debug("Entering createStream().");
  var b = body || {};
  var max = setting(appconfig, "ssfTransmitterMaxStreams",
                    DEFAULTS.maxStreams);
  if (one.streams.size >= max) {
    log.debug("Leaving createStream(). At the limit.");
    return { ok: false, status: 409, err: "stream_limit",
      description: "This transmitter already has " + one.streams.size +
        " stream(s) and ssfTransmitterMaxStreams is " + max + "." };
  }
  var streamId = crypto.randomBytes(12).toString("hex");
  var d = readDelivery(one, streamId, b.delivery || { method: POLL });
  if (d.error) {
    log.debug("Leaving createStream(). Delivery.");
    return badRequest(d.error);
  }
  var requested = readEventsRequested(b.events_requested);
  if (requested.error) {
    log.debug("Leaving createStream(). Events.");
    return badRequest(requested.error);
  }
  var s = {
    stream_id: streamId,
    // Transmitter-Supplied (8.1.1). A URL naming this stream at this
    // transmitter; every SET on the stream must carry it.
    aud: one.issuer + "/streams/" + streamId,
    events_requested: requested.events,
    events_delivered: delivered(one, requested.events),
    delivery: d.delivery,
    description: typeof b.description === "string"
      ? b.description.slice(0, 500) : "",
    status: "enabled",
    reason: "",
    subjects: [],
    queue: [],
    held: [],
    createdAt: new Date().toISOString()
  };
  one.streams.set(streamId, s);
  note(one, { kind: "stream created", stream_id: streamId,
    detail: (s.delivery.method === PUSH ? "push to " +
      s.delivery.endpoint_url : "poll") + "; events_delivered: " +
      (s.events_delivered.length ? s.events_delivered.join(", ") : "none") });
  log.debug("Leaving createStream(). " + streamId);
  return { ok: true, status: 201, body: streamView(one, s) };
}

// GET configuration_endpoint (8.1.1.2): one stream, or all of them.
function readStream(one, streamId) {
  log.debug("Entering readStream().");
  if (!streamId) {
    var all = [];
    one.streams.forEach(function (s) {
      all.push(streamView(one, s));
    });
    log.debug("Leaving readStream(). All " + all.length + ".");
    return { ok: true, status: 200, body: all };
  }
  var s = streamOf(one, streamId);
  if (!s) {
    log.debug("Leaving readStream(). Not found.");
    return noStream(streamId);
  }
  log.debug("Leaving readStream().");
  return { ok: true, status: 200, body: streamView(one, s) };
}

// PATCH (8.1.1.3) merges the Receiver-Supplied members it is given; PUT
// (8.1.1.4) replaces them, so an omitted one goes back to its default.
function updateStream(one, body, replace) {
  log.debug("Entering updateStream(). replace=" + !!replace);
  var b = body || {};
  var s = streamOf(one, b.stream_id);
  if (!s) {
    log.debug("Leaving updateStream(). Not found.");
    return noStream(b.stream_id);
  }
  if (replace || b.events_requested !== undefined) {
    var requested = readEventsRequested(b.events_requested);
    if (requested.error) {
      log.debug("Leaving updateStream(). Events.");
      return badRequest(requested.error);
    }
    s.events_requested = requested.events;
    s.events_delivered = delivered(one, requested.events);
  }
  if (replace || b.delivery !== undefined) {
    var d = readDelivery(one, s.stream_id, b.delivery || { method: POLL });
    if (d.error) {
      log.debug("Leaving updateStream(). Delivery.");
      return badRequest(d.error);
    }
    s.delivery = d.delivery;
  }
  if (replace || b.description !== undefined) {
    s.description = typeof b.description === "string"
      ? b.description.slice(0, 500) : "";
  }
  note(one, { kind: replace ? "stream replaced" : "stream updated",
    stream_id: s.stream_id, detail: "events_delivered: " +
      (s.events_delivered.join(", ") || "none") });
  log.debug("Leaving updateStream().");
  return { ok: true, status: 200, body: streamView(one, s) };
}

// DELETE (8.1.1.5): 204.
function deleteStream(one, streamId) {
  log.debug("Entering deleteStream().");
  if (!one.streams.delete(String(streamId || ""))) {
    log.debug("Leaving deleteStream(). Not found.");
    return noStream(streamId);
  }
  note(one, { kind: "stream deleted", stream_id: streamId });
  log.debug("Leaving deleteStream().");
  return { ok: true, status: 204, body: null };
}

// 8.1.2: the status endpoint.
function readStatus(one, streamId) {
  log.debug("Entering readStatus().");
  var s = streamOf(one, streamId);
  if (!s) {
    log.debug("Leaving readStatus(). Not found.");
    return noStream(streamId);
  }
  var body = { stream_id: s.stream_id, status: s.status };
  if (s.reason) {
    body.reason = s.reason;
  }
  log.debug("Leaving readStatus().");
  return { ok: true, status: 200, body: body };
}

// A change of status. Leaving `paused` releases what was held: for a poll
// stream into its queue, for a push stream into `release` for server.js to
// push. Disabling drops it — section 8.1.2 has a disabled stream deliver
// nothing and keep nothing.
function updateStatus(one, body) {
  log.debug("Entering updateStatus().");
  var b = body || {};
  var s = streamOf(one, b.stream_id);
  if (!s) {
    log.debug("Leaving updateStatus(). Not found.");
    return noStream(b.stream_id);
  }
  if (STATUSES.indexOf(b.status) < 0) {
    log.debug("Leaving updateStatus(). Unknown status.");
    return badRequest("status must be one of " + STATUSES.join(", ") +
                      "; it was " + JSON.stringify(b.status) + ".");
  }
  var before = s.status;
  s.status = b.status;
  s.reason = typeof b.reason === "string" ? b.reason.slice(0, 500) : "";
  var release = [];
  if (before === "paused" && s.status === "enabled") {
    if (s.delivery.method === POLL) {
      s.held.forEach(function (row) {
        s.queue.push(row);
      });
    } else {
      release = s.held.slice();
    }
    s.held = [];
  }
  if (s.status === "disabled") {
    s.held = [];
    s.queue = [];
  }
  note(one, { kind: "status", stream_id: s.stream_id,
    detail: before + " -> " + s.status + (s.reason ? " (" + s.reason + ")"
      : "") });
  var answer = { stream_id: s.stream_id, status: s.status };
  if (s.reason) {
    answer.reason = s.reason;
  }
  log.debug("Leaving updateStatus(). " + before + " -> " + s.status);
  return { ok: true, status: 200, body: answer, release: release,
           stream: s };
}

// 8.1.3: subjects. Add answers an empty 200, remove a 204.
function changeSubject(one, body, add) {
  log.debug("Entering changeSubject(). add=" + !!add);
  var b = body || {};
  var s = streamOf(one, b.stream_id);
  if (!s) {
    log.debug("Leaving changeSubject(). Not found.");
    return noStream(b.stream_id);
  }
  var subject = b.subject;
  if (!subject || typeof subject !== "object" || Array.isArray(subject) ||
      typeof subject.format !== "string") {
    log.debug("Leaving changeSubject(). Not a subject.");
    return badRequest("subject must be a subject identifier: an object " +
                      "with a format (RFC 9493).");
  }
  var text = JSON.stringify(subject);
  var at = s.subjects.map(function (x) {
    return JSON.stringify(x);
  }).indexOf(text);
  if (add) {
    if (at < 0 && s.subjects.length < 100) {
      s.subjects.push(subject);
    }
  } else if (at < 0) {
    log.debug("Leaving changeSubject(). Not held.");
    return { ok: false, status: 404, err: "not_found",
      description: "That subject is not on stream " + s.stream_id + "." };
  } else {
    s.subjects.splice(at, 1);
  }
  note(one, { kind: add ? "subject added" : "subject removed",
              stream_id: s.stream_id, detail: text });
  log.debug("Leaving changeSubject().");
  return { ok: true, status: add ? 200 : 204, body: null };
}

// 8.1.4: the receiver asks for a verification event. The answer is 204 —
// queued — and the request goes to the PAGE, which signs the event and hands
// it back through deliver().
function requestVerification(one, body) {
  log.debug("Entering requestVerification().");
  var b = body || {};
  var s = streamOf(one, b.stream_id);
  if (!s) {
    log.debug("Leaving requestVerification(). Not found.");
    return noStream(b.stream_id);
  }
  var state = b.state === undefined || b.state === null ? ""
    : String(b.state).slice(0, 1000);
  one.pending.push({ stream_id: s.stream_id, state: state,
                     at: new Date().toISOString() });
  while (one.pending.length > 20) {
    one.pending.shift();
  }
  note(one, { kind: "verification requested", stream_id: s.stream_id,
              detail: state ? "state " + state : "no state" });
  log.debug("Leaving requestVerification().");
  return { ok: true, status: 204, body: null };
}

// ---------------------------------------------------------------------------
// THE PAGE DELIVERS A SET.
//
// Returns what server.js should do: { ok, action: "push" | "queued" |
// "held" | "dropped", url, authorization, findings } or a refusal. The SET
// is checked against the stream — iss, aud, events_delivered — and what does
// not match is a FINDING, not a refusal: sending a SET a receiver should
// refuse is how a receiver is tested, and the page says what it sent.
// ---------------------------------------------------------------------------
function readSet(token) {
  log.debug("Entering readSet().");
  var parts = String(token || "").split(".");
  if (parts.length !== 3) {
    log.debug("Leaving readSet(). Not three parts.");
    return null;
  }
  try {
    var header = JSON.parse(Buffer.from(parts[0], "base64url")
      .toString("utf8"));
    var claims = JSON.parse(Buffer.from(parts[1], "base64url")
      .toString("utf8"));
    log.debug("Leaving readSet().");
    return { header: header, claims: claims };
  } catch (e) {
    log.debug("Leaving readSet(). Undecodable: " + e.message);
    return null;
  }
}

function findingsFor(one, s, read) {
  log.debug("Entering findingsFor().");
  var out = [];
  var claims = read.claims || {};
  if (String((read.header || {}).typ || "").toLowerCase()
      .replace(/^application\//, "") !== "secevent+jwt") {
    out.push("typ is " + JSON.stringify((read.header || {}).typ) +
             ", not secevent+jwt (RFC 8417 section 2.3).");
  }
  if (claims.iss !== one.issuer) {
    out.push("iss is " + JSON.stringify(claims.iss) + ", not this " +
             "transmitter's issuer " + one.issuer + ".");
  }
  var aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (aud.indexOf(s.aud) < 0) {
    out.push("aud does not name this stream's aud, " + s.aud + ".");
  }
  Object.keys(claims.events || {}).forEach(function (uri) {
    if (uri !== VERIFICATION && uri !== STREAM_UPDATED &&
        s.events_delivered.indexOf(uri) < 0) {
      out.push(uri + " is not in this stream's events_delivered, so a " +
               "conforming receiver may drop it.");
    }
  });
  if (!claims.jti) {
    out.push("There is no jti, so a poll receiver cannot acknowledge it.");
  }
  log.debug("Leaving findingsFor(). " + out.length);
  return out;
}

function deliver(appconfig, one, body) {
  log.debug("Entering deliver().");
  var b = body || {};
  var s = streamOf(one, b.stream_id);
  if (!s) {
    log.debug("Leaving deliver(). Not found.");
    return { ok: false, status: 404, error: "There is no stream " +
      (b.stream_id || "(none given)") + " at this transmitter. A receiver " +
      "creates one at the configuration endpoint." };
  }
  var token = String(b.token || "").trim();
  var limit = setting(appconfig, "ssfTransmitterMaxEventBytes",
                      DEFAULTS.maxEventBytes);
  if (!token || Buffer.byteLength(token, "utf8") > limit) {
    log.debug("Leaving deliver(). Size.");
    return { ok: false, status: 400, error: token ? "This SET is larger " +
      "than ssfTransmitterMaxEventBytes (" + limit + ")." : "token, the " +
      "signed SET to deliver, is required." };
  }
  var read = readSet(token);
  if (!read) {
    log.debug("Leaving deliver(). Not a JWS.");
    return { ok: false, status: 400, error: "token is not a compact JWS " +
      "with a readable header and claim set; the page signs a SET and " +
      "hands it here." };
  }
  var jti = String((read.claims || {}).jti || "");
  var findings = findingsFor(one, s, read);
  var events = Object.keys((read.claims || {}).events || {});
  // A verification event answers a pending request with the same state.
  if (events.indexOf(VERIFICATION) >= 0) {
    var state = String(((read.claims.events || {})[VERIFICATION] || {})
      .state || "");
    one.pending = one.pending.filter(function (p) {
      return !(p.stream_id === s.stream_id && p.state === state);
    });
  }
  var row = { jti: jti, token: token, events: events };
  var action;
  if (s.status === "disabled") {
    action = "dropped";
  } else if (s.status === "paused") {
    s.held.push(row);
    action = "held";
  } else if (s.delivery.method === POLL) {
    var maxQueued = setting(appconfig, "ssfTransmitterMaxQueued",
                            DEFAULTS.maxQueued);
    while (s.queue.length >= maxQueued) {
      s.queue.shift();
    }
    s.queue.push(row);
    action = "queued";
  } else {
    action = "push";
  }
  note(one, { kind: "delivery", stream_id: s.stream_id, jti: jti,
    detail: action + (findings.length ? "; " + findings.length +
      " finding(s)" : "") });
  log.debug("Leaving deliver(). " + action);
  return { ok: true, action: action, stream: s, jti: jti,
    url: action === "push" ? s.delivery.endpoint_url : "",
    authorization: action === "push" ? s.delivery.authorization_header : "",
    findings: findings,
    note: action === "dropped" ? "The stream is DISABLED, so the SET was " +
      "dropped (SSF 1.0 section 8.1.2)." : (action === "held" ? "The " +
      "stream is PAUSED, so the SET is held until the receiver enables it." :
      (action === "queued" ? "Queued for the receiver's next poll " +
      "(RFC 8936)." : "")) };
}

// What a push came back with, recorded for the page.
function recordPush(one, streamId, jti, outcome) {
  log.debug("Entering recordPush().");
  note(one, Object.assign({ kind: "push", stream_id: streamId, jti: jti },
                          outcome));
  log.debug("Leaving recordPush().");
}

// ---------------------------------------------------------------------------
// RFC 8936: the receiver polls. `ack` and `setErrs` take events off the
// queue; what is returned stays queued until acknowledged (section 2.4).
// ---------------------------------------------------------------------------
function poll(one, streamId, body) {
  log.debug("Entering poll().");
  var b = body || {};
  var s = streamOf(one, streamId);
  if (!s || s.delivery.method !== POLL) {
    log.debug("Leaving poll(). No poll stream.");
    return { ok: false, status: 404, err: "not_found",
      description: "There is no poll stream " + streamId + " here." };
  }
  var done = {};
  var acked = Array.isArray(b.ack) ? b.ack.map(String) : [];
  acked.forEach(function (j) {
    done[j] = true;
  });
  var errs = b.setErrs && typeof b.setErrs === "object" ? b.setErrs : {};
  Object.keys(errs).forEach(function (j) {
    done[j] = true;
    note(one, { kind: "setErr", stream_id: s.stream_id, jti: j,
      detail: String((errs[j] || {}).err || "") + " " +
        String((errs[j] || {}).description || "") });
  });
  var before = s.queue.length;
  s.queue = s.queue.filter(function (row) {
    return !done[row.jti];
  });
  var max = Number(b.maxEvents);
  var count = isFinite(max) && max >= 0 ? Math.floor(max) : s.queue.length;
  var sets = {};
  s.queue.slice(0, count).forEach(function (row) {
    sets[row.jti || ("no-jti-" + Object.keys(sets).length)] = row.token;
  });
  if (acked.length || before !== s.queue.length || count) {
    note(one, { kind: "poll", stream_id: s.stream_id,
      detail: acked.length + " acknowledged, " + Object.keys(sets).length +
        " returned, " + s.queue.length + " still queued" });
  }
  log.debug("Leaving poll(). " + Object.keys(sets).length + " returned.");
  return { ok: true, status: 200, body: { sets: sets,
    moreAvailable: s.queue.length > count } };
}

// ---------------------------------------------------------------------------
// What the PAGE sees.
// ---------------------------------------------------------------------------
function describe(one) {
  log.debug("Entering describe().");
  var streams = [];
  one.streams.forEach(function (s) {
    streams.push(streamForOwner(one, s));
  });
  var out = {
    id: one.id,
    label: one.label,
    issuer: one.issuer,
    discoveryUrl: discoveryUrl(one),
    metadata: metadata(one),
    jwks: publicJwks(one),
    eventsSupported: one.eventsSupported.slice(),
    createdAt: new Date(one.createdAt).toISOString(),
    expiresAt: new Date(Math.min(one.createdAt + one.ttlMs,
      one.lastUsedAt + one.idleTtlMs)).toISOString(),
    streams: streams,
    pendingVerifications: one.pending.slice(),
    log: one.log.slice()
  };
  log.debug("Leaving describe(). " + streams.length + " stream(s).");
  return out;
}

function remove(appconfig, id) {
  log.debug("Entering remove().");
  var gone = instances.delete(String(id || ""));
  log.debug("Leaving remove(). " + gone);
  return gone;
}

function limits(appconfig) {
  log.debug("Entering limits().");
  var out = {
    enabled: enabled(appconfig),
    ttlMs: setting(appconfig, "ssfTransmitterTtlMs", DEFAULTS.ttlMs),
    idleTtlMs: setting(appconfig, "ssfTransmitterIdleTtlMs",
                       DEFAULTS.idleTtlMs),
    maxInstances: setting(appconfig, "ssfTransmitterMaxInstances",
                          DEFAULTS.maxInstances),
    maxInstancesPerCaller: setting(appconfig,
      "ssfTransmitterMaxInstancesPerCaller", DEFAULTS.maxInstancesPerCaller),
    maxStreams: setting(appconfig, "ssfTransmitterMaxStreams",
                        DEFAULTS.maxStreams),
    maxQueued: setting(appconfig, "ssfTransmitterMaxQueued",
                       DEFAULTS.maxQueued),
    maxEventBytes: setting(appconfig, "ssfTransmitterMaxEventBytes",
                           DEFAULTS.maxEventBytes),
    held: instances.size,
    signs: false,
    note: "A receiver that treats its partner as a full SSF transmitter " +
      "discovers it, creates its stream there and polls it — requests a " +
      "page cannot answer. This service answers them on the page's " +
      "behalf; the page signs every SET and hands it here to deliver."
  };
  log.debug("Leaving limits().");
  return out;
}

function reset() {
  log.debug("Entering reset().");
  var gone = instances.size;
  instances.clear();
  log.debug("Leaving reset(). " + gone);
  return gone;
}

module.exports = {
  PUSH: PUSH,
  POLL: POLL,
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  VERIFICATION: VERIFICATION,
  DEFAULTS: DEFAULTS,
  enabled: enabled,
  bearerOf: bearerOf,
  create: create,
  get: get,
  forOwner: forOwner,
  forReceiver: forReceiver,
  published: published,
  metadata: metadata,
  discoveryUrl: discoveryUrl,
  createStream: createStream,
  readStream: readStream,
  updateStream: updateStream,
  deleteStream: deleteStream,
  readStatus: readStatus,
  updateStatus: updateStatus,
  changeSubject: changeSubject,
  requestVerification: requestVerification,
  deliver: deliver,
  recordPush: recordPush,
  poll: poll,
  describe: describe,
  remove: remove,
  sweep: sweep,
  limits: limits,
  reset: reset
};
