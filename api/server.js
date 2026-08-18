'use strict';

var appconfig = require(process.env.CONFIG_FILE);
const express = require('express');
const expressLogging = require('express-logging');
const bunyan = require("bunyan");
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const {
  convertToOAuth2Format  } = require('./data.js');
const ssrfGuard = require('./ssrf_guard.js');
const connectTimeout = require('./connect_timeout.js');
const krb5Relay = require('./krb5_relay.js');
const tlsProbeModule = require('./tls_probe.js');

// Constants
const PORT = appconfig.port || 4000;
const HOST = appconfig.host || '0.0.0.0';
const LOG_LEVEL = appconfig.logLevel || 'debug';
const uiUrl = appconfig.uiUrl || 'http://localhost:3000';

const STATUS_200 = 200;
const STATUS_204 = 204;
const STATUS_400 = 400;
const STATUS_401 = 401;
const STATUS_403 = 403;
const STATUS_404 = 404;
const STATUS_500 = 500;

var log = bunyan.createLogger({
                                name: 'server',
                                level: LOG_LEVEL });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Outbound call timeout, in milliseconds, applied to every axios call this
// service makes (appconfig.callTimeout, set in api/env/*.js).
//
// It is needed because every one of those calls goes to a host the CALLER named
// — the token, introspection, revocation, device-authorization and userinfo
// endpoints, the SAML metadata and ArtifactResolve back-channels, the WS-Trust
// STS, the DCR endpoint — and axios has NO default timeout of its own. A host
// that completes the TCP handshake and then never answers therefore holds the
// Express request, its socket and the browser's spinner open for as long as the
// operating system's own keep-alive allows, which is minutes.
// ---------------------------------------------------------------------------
const DEFAULT_CALL_TIMEOUT = 10000;
const DEFAULT_CONNECTION_TIMEOUT = 5000;
const DEFAULT_MAX_CONTENT_LENGTH = 1048576;   // 1 MiB
const DEFAULT_MAX_REDIRECTS = 5;

/**
 * Read one positive-number limit out of the environment config.
 *
 * Shared by callTimeout, connectionTimeout and maxContentLength so they cannot
 * drift in how a missing or nonsensical value is treated.
 *
 * @param {string} name - the appconfig key, for the log message.
 * @param {*} configured - whatever the config file put there.
 * @param {number} fallback - the code default.
 * @param {string} unit - 'milliseconds' or 'bytes', for the log message.
 * @returns {number} a positive, finite number.
 */
function resolvePositiveNumber(name, configured, fallback, unit) {
  log.debug("Entering resolvePositiveNumber().");
  if (configured === undefined || configured === null) {
    log.debug("Leaving resolvePositiveNumber().");
    return fallback;
  }
  var value = Number(configured);
  // A misconfigured value must not quietly become "no limit". That is exactly
  // what axios makes of a missing timeout, and 0 is worse than useless for
  // maxContentLength — axios enforces any value > -1, so 0 would refuse every
  // response with a body in it. Name the key in the log and fall back.
  if (!Number.isFinite(value) || value <= 0) {
    log.warn("Ignoring " + name + "=" + JSON.stringify(configured) +
             ": expected a positive number of " + unit + ". Using " +
             fallback + ".");
    log.debug("Leaving resolvePositiveNumber().");
    return fallback;
  }
  log.debug("Leaving resolvePositiveNumber().");
  return value;
}

const CALL_TIMEOUT = resolvePositiveNumber(
  'callTimeout', appconfig.callTimeout, DEFAULT_CALL_TIMEOUT, 'milliseconds');

// ---------------------------------------------------------------------------
// Connection timeout, in milliseconds (appconfig.connectionTimeout): the budget
// for reaching a USABLE connection — DNS, TCP connect and, on https, the TLS
// handshake — enforced by connect_timeout.js on the agent that opens the
// socket.
//
// It is a genuinely different deadline from callTimeout, not a smaller copy of
// it. It stops counting the instant the connection is up, so the two are
// additive: a dead or firewalled address fails inside connectionTimeout, while
// a host that has answered gets the full callTimeout to produce a response.
// axios cannot express this on its own — neither its `timeout` nor an
// AbortSignal can, because both bound everything that follows.
// ---------------------------------------------------------------------------
const CONNECTION_TIMEOUT = resolvePositiveNumber(
  'connectionTimeout', appconfig.connectionTimeout, DEFAULT_CONNECTION_TIMEOUT,
  'milliseconds');

// ---------------------------------------------------------------------------
// Largest response body, in bytes, this service will accept from an outbound
// call (appconfig.maxContentLength), passed to axios as `maxContentLength`.
//
// A timeout alone does not bound a call: a host that answers promptly and then
// streams for as long as it likes is entirely within its deadline while the api
// buffers the whole body IN MEMORY to hand back to the browser. axios's default
// is -1, unlimited, so the only ceiling today is the heap. Ten concurrent
// callers pointing this service at a large file is a denial of service that
// needs no special effort.
//
// axios enforces this incrementally, destroying the response stream as soon as
// the running total passes the cap, so an oversized body is abandoned
// mid-download rather than counted after the fact. It rejects with
// ERR_BAD_RESPONSE and the message "maxContentLength size of N exceeded", which
// surfaces through the existing error handling like any other call failure.
//
// It applies to RESPONSES only. Request bodies are axios's `maxBodyLength`,
// which is not set here: what this service sends is assembled from a request
// Express has already accepted and size-limited.
// ---------------------------------------------------------------------------
const MAX_CONTENT_LENGTH = resolvePositiveNumber(
  'maxContentLength', appconfig.maxContentLength, DEFAULT_MAX_CONTENT_LENGTH,
      'bytes');

// How much of a SPNEGO-protected page's body POST /krb5/spnego hands back for
// DISPLAY. Not a transfer limit — MAX_CONTENT_LENGTH is that, and it still
// applies — but a display one: what is being debugged there is the handshake in
// the headers, and the body is a page meant for a browser. Enough to see that
// the resource really did arrive and to read a short mock's whole answer, and
// not so much that a JSON response carries a megabyte of somebody's intranet
// home page into a pane nobody will read.
const SPNEGO_BODY_CHARS = 16384;

/**
 * Read one non-negative integer setting out of the environment config.
 *
 * Deliberately separate from resolvePositiveNumber, because ZERO is meaningful
 * here and invalid there. `maxRedirects: 0` makes axios use the native transport
 * instead of follow-redirects, i.e. hand back the 3xx without following it — a
 * legitimate and stricter choice. For a timeout or a size cap, 0 means "no limit"
 * or "refuse everything", so it has to be rejected.
 *
 * @param {string} name - the appconfig key, for the log message.
 * @param {*} configured - whatever the config file put there.
 * @param {number} fallback - the code default.
 * @returns {number} a non-negative integer.
 */
function resolveNonNegativeInteger(name, configured, fallback) {
  log.debug("Entering resolveNonNegativeInteger().");
  if (configured === undefined || configured === null) {
    log.debug("Leaving resolveNonNegativeInteger().");
    return fallback;
  }
  var value = Number(configured);
  // A non-integer or negative value must not be passed through. axios gates on
  // `if (maxRedirects)`, so anything that comes out falsy-but-not-zero — NaN
  // from a non-numeric string — silently leaves follow-redirects' OWN default
  // of 21 in place, which is the opposite of having configured a limit.
  if (!Number.isInteger(value) || value < 0) {
    log.warn("Ignoring " + name + "=" + JSON.stringify(configured) +
             ": expected a non-negative whole number. Using " + fallback + ".");
    log.debug("Leaving resolveNonNegativeInteger().");
    return fallback;
  }
  log.debug("Leaving resolveNonNegativeInteger().");
  return value;
}

// ---------------------------------------------------------------------------
// How many redirects an outbound call may follow (appconfig.maxRedirects),
// passed to axios as `maxRedirects`. axios's own default is 21.
//
// Two reasons to hold it down. A redirect chain is unbounded work behind a
// single caller-supplied URL — each hop is a fresh DNS lookup and connection,
// and a loop or a long chain burns the whole callTimeout doing nothing useful.
// And a redirect is precisely how a *public* host sends this service somewhere
// private: `302 Location: http://127.0.0.1:8080/`. That address is refused by
// the SSRF guard's agent layer, which is on every hop because axios hands the
// agents to follow-redirects — but a shorter chain is less to reason about
// either way.
//
// 0 is a valid setting and means "do not follow redirects at all"; the 3xx is
// returned to the caller as the response.
// ---------------------------------------------------------------------------
const MAX_REDIRECTS = resolveNonNegativeInteger(
  'maxRedirects', appconfig.maxRedirects, DEFAULT_MAX_REDIRECTS);

// ---------------------------------------------------------------------------
// The User-Agent every outbound call sends (appconfig.userAgent).
//
// Without it axios announces itself as `axios/1.18.1`, which tells an identity
// provider's operator nothing about who is calling. This service shows up in
// other people's access logs by design — it is pointed at their token,
// introspection and metadata endpoints — so it should say what it is and which
// build, which is what makes a report like "your debugger sent us a malformed
// request on Tuesday" actionable.
//
// The setting is the whole template; `{{VERSION}}` in it is replaced with the
// build version, the same placeholder the client's footer and error pages use.
// A value with no placeholder is sent verbatim, which is a legitimate choice.
// ---------------------------------------------------------------------------
const DEFAULT_USER_AGENT = 'Identity Protocol Debugger/{{VERSION}}';

/**
 * The application version, M.N.O.
 *
 * api/Dockerfile stamps version.json into this directory at image build time and
 * copies the client's version.js beside it — one implementation of the scheme for
 * both services rather than a second that could drift. Neither is present in a
 * bare checkout (same as ./data.js), so the client's copy is tried next, and the
 * package manifest last: this must never be the thing that stops the service
 * starting.
 *
 * @returns {string} e.g. "0.9.20260731120000", or "0.9.0" from the manifest.
 */
function resolveAppVersion() {
  log.debug("Entering resolveAppVersion().");
  var candidates = ['./version.js', '../client/version.js'];
  for (var i = 0; i < candidates.length; i++) {
    try {
      var appversion = require(candidates[i]);
      // load() prefers the stamped record and computes one only if the artifact
      // was never stamped, so a built image reports its build and a checkout
      // still reports something usable.
      var record = appversion.load(__dirname);
      if (record && record.version) {
        log.debug("Leaving resolveAppVersion().");
        return record.version;
      }
    } catch (e) {
      // Not present in this layout; try the next. Logged at debug because the
      // first miss is entirely normal in a checkout.
      log.debug('resolveAppVersion: ' + candidates[i] + ' unavailable (' +
                e.code + ').');
    }
  }
  try {
    log.debug("Leaving resolveAppVersion().");
    return require('./package.json').version;
  } catch (e) {
    log.warn('Could not determine the application version: ' + e.message);
    log.debug("Leaving resolveAppVersion().");
    return '0.0.0';
  }
  log.debug("Leaving resolveAppVersion().");
}

const APP_VERSION = resolveAppVersion();

/**
 * The User-Agent template from the config, with the version substituted.
 *
 * @returns {string} never blank.
 */
function resolveUserAgent() {
  log.debug("Entering resolveUserAgent().");
  var configured = appconfig.userAgent;
  var template = DEFAULT_USER_AGENT;
  if (configured !== undefined && configured !== null) {
    // An empty or whitespace-only setting is a misconfiguration, not a request
    // to be anonymous: axios would send a User-Agent header with nothing after
    // the colon, which is worse than the default it replaced. Say so and use
    // the default, as the numeric settings do.
    if (typeof configured !== 'string' || !String(configured).trim()) {
      log.warn("Ignoring userAgent=" + JSON.stringify(configured) +
               ": expected a non-empty string. Using \"" + DEFAULT_USER_AGENT +
                   "\".");
    } else {
      template = String(configured);
    }
  }
  log.debug("Leaving resolveUserAgent().");
  return template.split('{{VERSION}}').join(APP_VERSION);
}

const USER_AGENT = resolveUserAgent();

/**
 * Read one boolean setting out of the environment config.
 *
 * A missing, null or misspelled key therefore keeps the default rather than
 * reading as false — the same rule blockPrivateNetworkCalls follows.
 *
 * @param {string} name - the appconfig key, for the log message.
 * @param {*} configured - whatever the config file put there.
 * @param {boolean} fallback - the code default.
 * @returns {boolean}
 */
/**
 * The browser origins allowed to call this api, derived from the configured URLs.
 *
 * Until now this was `origin: '*'`, which tells every site on the internet that
 * its visitors' browsers may call this api and read the replies. That is a poor
 * fit for a service whose whole job is proxying token, introspection and
 * userinfo calls — the caller supplies the endpoint AND the client secret.
 *
 * **Note which URL this is built from.** `Access-Control-Allow-Origin` names the
 * origin of the PAGE making the request, which is the debugger UI — `uiUrl`
 * (http://localhost:3000, http://client:3000, https://tools.test.idptools.io).
 * It is not `apiUrl`: that is this service's own address, and a page served from
 * it would be same-origin and would never send a CORS request at all. Allowing
 * only `apiUrl` would reject every real call. `apiUrl` is still included below
 * because it costs nothing and covers a deployment that serves the UI from this
 * origin, but `uiUrl` is the one that matters.
 *
 * A configured value may carry a path (or a trailing slash); an Origin header
 * never does, so each is reduced to scheme://host:port before comparison.
 *
 * @param {object} config - the appconfig for this environment.
 * @returns {string[]|string} the allowlist, or '*' when nothing usable is
 *   configured — a deployment missing both keys keeps working rather than
 *   refusing its own UI, with the reason logged.
 */
function resolveAllowedOrigins(config) {
  log.debug("Entering resolveAllowedOrigins().");
  var origins = [];
  [["uiUrl", config.uiUrl], ["apiUrl", config.apiUrl]].forEach(function (pair) {
    var name = pair[0];
    var configured = pair[1];
    if (configured === undefined || configured === null ||
        String(configured).trim() === "") {
      return;
    }
    var parsed;
    try {
      parsed = new URL(String(configured).trim());
    } catch (e) {
      log.warn("Ignoring " + name + "=" + JSON.stringify(configured) +
               " for CORS: it is not an absolute URL (" + e.message + ").");
      return;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      log.warn("Ignoring " + name + "=" + JSON.stringify(configured) +
               " for CORS: an origin must be http or https, not " +
                   parsed.protocol + ".");
      return;
    }
    if (origins.indexOf(parsed.origin) === -1) origins.push(parsed.origin);
  });
  if (!origins.length) {
    log.warn("Neither uiUrl nor apiUrl gives a usable origin, so CORS falls " +
             "back to '*'. " +
             "Set uiUrl to the browser origin that calls this api.");
    log.debug("Leaving resolveAllowedOrigins().");
    return "*";
  }
  log.debug("Leaving resolveAllowedOrigins().");
  return origins;
}

function resolveBoolean(name, configured, fallback) {
  log.debug("Entering resolveBoolean().");
  if (configured === undefined || configured === null) {
    log.debug("Leaving resolveBoolean().");
    return fallback;
  }
  if (typeof configured !== 'boolean') {
    // Deliberately strict: the string "false" is truthy in JavaScript, so a
    // quoted value would turn an intended off into an on without a word.
    log.warn("Ignoring " + name + "=" + JSON.stringify(configured) +
             ": expected true or false. Using " + fallback + ".");
    log.debug("Leaving resolveBoolean().");
    return fallback;
  }
  log.debug("Leaving resolveBoolean().");
  return configured;
}

// ---------------------------------------------------------------------------
// Whether outbound connections are pooled and reused (appconfig.keepAlive).
//
// On, this service stops paying for a TCP connection — and a TLS handshake,
// which is the expensive half — on every call to an identity provider it has
// just finished talking to. A debugger session is exactly that pattern: token,
// then introspection, then userinfo, all to the same host within seconds.
//
// It is what makes the agents SHARED rather than built per call, and the two
// are not separable. A keep-alive agent that is thrown away after one response
// still holds that response's socket in its free pool, and nothing closes it —
// so a per-call agent with keepAlive on leaks a file descriptor per outbound
// call, which is strictly worse than not pooling. See agentFor() below.
// ---------------------------------------------------------------------------
const KEEP_ALIVE = resolveBoolean('keepAlive', appconfig.keepAlive, true);
// The browser origins allowed to call this api. See resolveAllowedOrigins() for
// why this is built from uiUrl rather than apiUrl.
const ALLOWED_ORIGINS = resolveAllowedOrigins(appconfig);

/**
 * A headers object with this service's User-Agent on it.
 *
 * Applied at every call site rather than once on axios.defaults.headers, for the
 * same reason the agents are: a per-call `headers` object REPLACES the defaults,
 * and every one of these calls sets its own.
 *
 * Ours wins over anything already in the object. No call site sets a User-Agent
 * today, and none should be able to make this service anonymous by accident.
 *
 * @param {object} [headers] - the call's own headers.
 * @returns {object} a new object; the caller's is not modified.
 */
function withUserAgent(headers) {
  log.debug("Entering withUserAgent().");
  log.debug("Leaving withUserAgent().");
  return Object.assign({}, headers || {}, {
    'User-Agent': USER_AGENT });
}

log.info("Outbound call timeout: " + CALL_TIMEOUT +
         "ms (whole call); connection " +
         "timeout: " + CONNECTION_TIMEOUT +
             "ms (until connected); max response " +
         "size: " + MAX_CONTENT_LENGTH + " bytes; max redirects: " +
             MAX_REDIRECTS +
         (MAX_REDIRECTS === 0 ? " (redirects are not followed)." : "."));
log.info("Outbound User-Agent: " + USER_AGENT);
log.info("Outbound connection pooling (keepAlive): " + (KEEP_ALIVE ?
         "on" : "off") + ".");
log.info("CORS allowed origins: " +
         (ALLOWED_ORIGINS === "*" ?
          "* (any site) — uiUrl is not configured" : ALLOWED_ORIGINS.join(
          ", ")) + ".");

// ---------------------------------------------------------------------------
// Refuse outbound calls to loopback and private networks (see ssrf_guard.js).
//
// Installed here, once, on the axios instance every endpoint uses: this service
// fetches URLs its CALLER chooses — the token, introspection, revocation,
// device-authorization and userinfo endpoints, the SAML ArtifactResolve
// back-channel, the WS-Trust STS and the generic proxy — so without this it
// will happily probe 127.0.0.1, the deployment's private neighbours, or the
// cloud metadata service on request. One choke point rather than ten call
// sites, so anything added later is covered too.
//
// On by default; a deployment whose identity providers really are on a private
// network sets blockPrivateNetworkCalls to false in its api/env config.
// ---------------------------------------------------------------------------
const guard = ssrfGuard.createGuard(appconfig, log);
guard.install(axios);
// The Kerberos relay reuses the guard's address DECISION rather than keeping its
// own copy of the ranges — see api/krb5_relay.js. It cannot reuse the guard's
// INSTALLATION, because that is hooks on the axios agents and this transport is a
// raw socket with no axios in the path.
const krb5 = krb5Relay.createRelay(appconfig, guard, log);
// The TLS probe is in exactly the same position and for the same reason:
// `tls.connect` is a raw socket, so the guard's axios installation never sees
// it, and it therefore reuses the DECISION (blockedRangeFor) and not the
// installation. See api/tls_probe.js.
const tlsProbe = tlsProbeModule.createProbe(appconfig, guard, log);

// ---------------------------------------------------------------------------
// The agents every outbound call uses: the SSRF guard's hooks, the
// connect-phase timeout, and connection pooling.
//
// They must be built HERE rather than with a bare `new https.Agent(...)` at
// each call site, because setting httpsAgent on an axios call replaces
// axios.defaults.httpsAgent — so a hand-rolled agent silently drops the guard's
// DNS `lookup` and `createConnection` hooks, the layer that catches a redirect
// to a private literal address. Going through the guard's own factory keeps
// both concerns attached wherever an agent is needed.
//
// They are also CACHED rather than built per call, which keepAlive requires: an
// agent's pool of idle sockets lives on the agent, so a fresh one per call
// reuses nothing (pointless) while still parking that call's socket in a pool
// nobody will ever read (a leaked file descriptor per call). Sharing is safe
// because everything on these agents is stateless policy; the only thing a call
// chooses is rejectUnauthorized, so there are three agents at most and the
// cache cannot grow with traffic.
//
// One interaction worth knowing: a REUSED socket does not go through
// createConnection, so it carries no connect timeout. That is correct — it is
// already connected — and it is also why the connect timeout must not be
// thought of as a per-request guarantee once pooling is on.
// ---------------------------------------------------------------------------
const outboundAgentCache = new Map();

/**
 * The shared agent for one protocol and certificate policy.
 *
 * @param {string} protocol - 'http' or 'https'.
 * @param {boolean} [rejectUnauthorized] - https only.
 * @returns {http.Agent|https.Agent} the same instance for the same arguments.
 */
function agentFor(protocol, rejectUnauthorized) {
  log.debug("Entering agentFor().");
  var key = protocol + (protocol === 'https' ? '|' + rejectUnauthorized : '');
  var cached = outboundAgentCache.get(key);
  if (cached) {
    log.debug("Leaving agentFor().");
    return cached;
  }
  var options = {
    keepAlive: KEEP_ALIVE };
  if (protocol === 'https') {
    options.rejectUnauthorized = rejectUnauthorized;
  }
  var agent = connectTimeout.withConnectTimeout(
    guard.createAgent(protocol, options), CONNECTION_TIMEOUT, log);
  outboundAgentCache.set(key, agent);
  log.debug('Created the ' + key + ' outbound agent (keepAlive=' + KEEP_ALIVE +
            ').');
  log.debug("Leaving agentFor().");
  return agent;
}

function outboundHttpAgent() {
  log.debug("Entering outboundHttpAgent().");
  log.debug("Leaving outboundHttpAgent().");
  return agentFor('http');
}

/**
 * @param {boolean} rejectUnauthorized - whether to verify the peer's certificate.
 *   Normalised so that only an explicit `false` turns verification off, which
 *   bounds the cache to two https agents and means a missing or oddly-typed value
 *   from a request body cannot quietly stop certificates being checked.
 * @returns {https.Agent}
 */
function outboundHttpsAgent(rejectUnauthorized) {
  log.debug("Entering outboundHttpsAgent().");
  log.debug("Leaving outboundHttpsAgent().");
  return agentFor('https', rejectUnauthorized !== false);
}

// Ephemeral, in-memory store for SAML exchanges. The ACS endpoint stashes the
// (potentially large) SAMLResponse here and redirects the browser to the client
// results page with a short id; the client then fetches the XML by id. This is
// deliberate, single-instance, short-lived state (the app is otherwise
// stateless) — not for the static/backend-less deployment.
var samlExchanges = new Map();
const SAML_EXCHANGE_TTL_MS = 10 * 60 * 1000; // 10 minutes
function sweepSamlExchanges() {
  log.debug("Entering sweepSamlExchanges().");
  var now = Date.now();
  samlExchanges.forEach(function (v, k) {
    if (now - v.createdAt > SAML_EXCHANGE_TTL_MS) samlExchanges.delete(k);
  });
  log.debug("Leaving sweepSamlExchanges().");
}
function stashSamlResponse(xml, relayState) {
  log.debug("Entering stashSamlResponse().");
  sweepSamlExchanges();
  var id = crypto.randomBytes(16).toString('hex');
  samlExchanges.set(id, {
    responseXml: xml, relayState: relayState || '', createdAt: Date.now() });
  log.debug("Leaving stashSamlResponse().");
  return id;
}

// When a request asks for the artifact response binding, the SP context needed
// to resolve the artifact later (ARS URL + SP signing key) is stashed here and
// referenced by the RelayState (art:<id>) the IdP echoes back to the ACS.
var samlArtifactCtx = new Map();
function stashArtifactCtx(ctx) {
  log.debug("Entering stashArtifactCtx().");
  sweepSamlArtifactCtx();
  var id = crypto.randomBytes(16).toString('hex');
  samlArtifactCtx.set(id, Object.assign({
    createdAt: Date.now() }, ctx));
  log.debug("Leaving stashArtifactCtx().");
  return id;
}
function sweepSamlArtifactCtx() {
  log.debug("Entering sweepSamlArtifactCtx().");
  var now = Date.now();
  samlArtifactCtx.forEach(function (v, k) {
    if (now - v.createdAt > SAML_EXCHANGE_TTL_MS) samlArtifactCtx.delete(k);
  });
  log.debug("Leaving sweepSamlArtifactCtx().");
}

// jwt.xml is a local copy of https://www.iana.org/assignments/jwt/jwt.xml.
// A local copy is used to avoid latency and availability issues fetching the
// online copy from IANA, which has been an ongoing reliability problem.
var claimDescriptions = fs.readFileSync(path.join(__dirname, 'jwt.xml'),
    'utf8');
var cachedClaimDescriptions = true;

const app = express();
const expressSwagger = require('express-swagger-generator')(app);

app.use(bodyParser.json());
// SAML ACS receives application/x-www-form-urlencoded POSTs (SAMLResponse,
// RelayState, SAMLart) from the IdP; enable urlencoded parsing for those.
app.use(bodyParser.urlencoded({
  extended: true, limit: '5mb' }));
var corsOptions = {
  // See resolveAllowedOrigins(): this is uiUrl (the browser origin that calls
  // the api), not apiUrl. The cors package reflects the request's Origin when
  // it is in the list and sends no Allow-Origin at all when it is not, and it
  // adds Vary: Origin for us — which matters, because a cached response
  // carrying one allowed origin must not be served to another.
  origin: ALLOWED_ORIGINS,
  optionsSuccessStatus: STATUS_204
};
// app.use(expressLogging(logger));
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));

/**
 * @typedef HealthcheckResponse
 * @property {string} message - Status message
 */
/**
 * System healthcheck
 * @route GET /healthcheck
 * @group System - Support operations
 * @returns {HealthcheckResponse.model} 200 - Health Check Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/healthcheck', function (req, res) {
  res
  .status(STATUS_200)
  .json({
    message: 'Success' });
});

// The IANA JWT claim registry: the one outbound call in this service whose URL
// is NOT chosen by the caller. It gets the same treatment as the rest anyway —
// both timeouts, the size cap and the guarded agents — because having picked
// the URL ourselves is no reason to accept a hung or unbounded response from
// it.
const IANA_JWT_CLAIMS_URL = 'https://www.iana.org/assignments/jwt/jwt.xml';

/**
 * Retrieve Claims Description.
 * @route GET /claimdescription
 * @group Metadata - Support operations
 * @returns {HealthcheckResponse.model} 200 - Claim Description Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/claimdescription', function(req, res) {
  log.debug("Entering GET /claimdescription.");
  try {
    if(cachedClaimDescriptions) {
      log.debug("Using cached claim descriptions.");
      res
      .append('Content-Type', 'application/xml')
      .status(STATUS_200)
      .send(claimDescriptions);
    } else {
      log.debug("Pulling claim descriptions from " + IANA_JWT_CLAIMS_URL);
      axios({
        method: 'get',
        url: IANA_JWT_CLAIMS_URL,
        responseType: 'text',
        // The registry is XML. Keep axios's default response transform, which
        // tries JSON.parse on a string body, away from it.
        transformResponse: [function (d) {
          return d; }],
        timeout: CALL_TIMEOUT,
        maxContentLength: MAX_CONTENT_LENGTH,
        maxRedirects: MAX_REDIRECTS,
        httpAgent: outboundHttpAgent(),
        httpsAgent: outboundHttpsAgent(true),
        headers: withUserAgent({
          'Accept': 'application/xml, text/xml, */*' })
      })
      .then(function (response) {
        var xml = String(response.data == null ? '' : response.data);
        log.debug("Retrieved " + xml.length + " bytes of claim descriptions.");
        res
        .append('Content-Type', 'application/xml')
        .status(STATUS_200)
        .send(xml);
        // Cached only here, which means only on a 2xx: axios rejects every
        // other status, so an IANA error page can no longer be memoised and
        // served as the claim registry for the lifetime of the process. `fetch`
        // resolved on a 404, which is exactly how that could happen before.
        claimDescriptions = xml;
        cachedClaimDescriptions = true;
      })
      .catch(function (error) {
        log.error('Error from claimdescription endpoint: ' +
                  (error && error.stack ? error.stack : error));
        if(!!error.response) {
          if(!!error.response.status) {
            log.error("Error Status: " + error.response.status);
          }
          if(!!error.response.data) {
            log.error("Error Response body: " +
                      JSON.stringify(error.response.data));
          }
          if(!!error.response.headers) {
            log.error("Error Response headers: " + error.response.headers);
          }
          res.status(error.response.status ||
                     STATUS_500).json(error.response.data);
          return;
        }
        // No response at all: the call timed out, the connection never opened,
        // or the body passed maxContentLength. This branch MUST answer. The
        // previous implementation replied only when error.response was set —
        // which a network-level failure never sets, and `fetch` never set at
        // all — so every failure of this endpoint left the browser waiting for
        // a reply that was never sent, on the path of every token inspection
        // the debugger does. With the limits above in place this is the common
        // branch, not the rare one.
        res.status(STATUS_500).json({
          error: 'claim description fetch failed: ' +
                 (error && error.message ? error.message : String(error)) });
      });
   }
  } catch(e) {
    log.error("An error occurred while retrieving the claim description XML: " +
              e.stack);
    res.status(STATUS_500)
       .render('error', {
         error: 'An unexpected error occurred.' });
  }
});

/**
 * Proxy-fetch a SAML metadata document server-side.
 *
 * The SAML config page needs the IdP's metadata XML, but fetching it directly
 * from the browser is blocked by CORS (the IdP descriptor endpoint sends no
 * Access-Control-Allow-Origin). This endpoint fetches it on the server and
 * returns the XML. Like the token proxy, it fetches a caller-supplied URL, so
 * it is a dev/debugger-only tool (SSRF by design); do not expose publicly.
 *
 * The target URL is passed base64-encoded in ?url= to survive query escaping.
 * @route GET /samlmetadata
 * @group SAML - SAML support operations
 * @returns {string} 200 - The metadata XML document
 * @returns {Error.model} 400 - Missing/invalid url parameter
 * @returns {Error.model} 500 - Fetch error
 */
app.get('/samlmetadata', function (req, res) {
  log.debug('Entering GET /samlmetadata.');
  var target;
  try {
    target = Buffer.from(String(req.query.url || ''),
        'base64').toString('utf8').trim();
  } catch (e) {
    return res.status(STATUS_400).json({
      error: 'Invalid url parameter (expected base64).' });
  }
  if (!/^https?:\/\//i.test(target)) {
    return res.status(STATUS_400).json({
      error: 'url must be an absolute http(s) URL.' });
  }
  axios.get(target, {
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    httpAgent: outboundHttpAgent(),
    // Allow self-signed IdP TLS in test/dev environments.
    httpsAgent: outboundHttpsAgent(false),
    headers: withUserAgent({
      'Accept': 'application/samlmetadata+xml, application/xml, ' +
          'text/xml, */*' })
  })
  .then(function (response) {
    res.append('Content-Type',
               'application/xml').status(STATUS_200).send(response.data);
  })
  .catch(function (error) {
    log.error('Error fetching SAML metadata from ' + target + ': ' + (error &&
              error.stack ? error.stack : error));
    if (error && error.response) {
      res.status(error.response.status ||
                 STATUS_500).send(String(error.response.data ||
                 'metadata fetch failed'));
    } else {
      res.status(STATUS_500).json({
        error: 'metadata fetch failed: ' + (error && error.message ?
            error.message : String(error)) });
    }
  });
});

// ---------------------------------------------------------------------------
// SAML request signing.
//
// Signing is done server-side because the HTTP-POST binding needs an enveloped
// XML digital signature (XML-DSIG / exclusive C14N), which is impractical in
// the browser. The browser posts the unsigned AuthnRequest XML plus the SP
// private key; this returns what the browser needs to reach the IdP:
//   * redirect (and artifact response) binding: a full GET Location URL whose
//     query string (SAMLRequest DEFLATE+base64, SigAlg, Signature) is signed
//     per the SAML HTTP-Redirect binding (signature over the octet string, NOT
//     an XML signature).
//   * post binding: { location, params:{ SAMLRequest, RelayState } } for the
//     browser to auto-submit; SAMLRequest is base64 of the enveloped-signed
//     XML.
// The SP private key is transmitted to this local API; keep this dev-only.
// ---------------------------------------------------------------------------
function xmlTextEscape(s) {
  log.debug("Entering xmlTextEscape().");
  log.debug("Leaving xmlTextEscape().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function signXmlEnveloped(xml, privateKeyPem, certPem, rootLocalName) {
  log.debug("Entering signXmlEnveloped().");
  var root = rootLocalName || 'AuthnRequest';
  var xmlcrypto = require('xml-crypto');
  var SignedXml = xmlcrypto.SignedXml;
  // The root element's ID becomes the signature Reference URI (#ID).
  var m = xml.match(/\bID="([^"]+)"/);
  var id = m ? m[1] : '';
  var sig = new SignedXml({
    privateKey: privateKeyPem,
    publicCert: certPem || undefined
  });
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "/*[local-name(.)='" + root + "']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    uri: id ? ('#' + id) : ''
  });
  // Per the SAML schema the <Signature> must follow <Issuer>.
  sig.computeSignature(xml, {
    location: {
      reference: "/*[local-name(.)='" + root + "']/*[local-name(.)='Issuer']",
          action: 'after' }
  });
  log.debug("Leaving signXmlEnveloped().");
  return sig.getSignedXml();
}

/**
 * Sign a SAML AuthnRequest for the chosen binding.
 * @route POST /samlsign
 * @group SAML - SAML support operations
 */
app.post('/samlsign', function (req, res) {
  log.debug('Entering POST /samlsign.');
  try {
    var b = req.body || {
      };
    var binding = b.binding || 'redirect';
    var xml = b.xml;
    var dest = b.destination;
    var privateKeyPem = b.privateKeyPem;
    var certPem = b.certPem || '';
    var sigAlg = b.sigAlg ||
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    var relayState = b.relayState || '';
    var rootElement = b.rootElement ||
        'AuthnRequest'; // AuthnRequest | LogoutRequest
    if (!xml || !privateKeyPem) {
      return res.status(STATUS_400).json({
        error: 'xml and privateKeyPem are required.' });
    }

    if (binding === 'post') {
      var signedXml = signXmlEnveloped(xml, privateKeyPem, certPem,
          rootElement);
      var params = {
        SAMLRequest: Buffer.from(signedXml, 'utf8').toString('base64') };
      if (relayState) params.RelayState = relayState;
      // signedXml is also returned so the UI can display the enveloped-signed
      // document (e.g. the "Build Request" button).
      return res.json({
        mode: 'post', location: dest || '', params: params,
            signedXml: signedXml });
    }

    // redirect binding (also used to send the request when the response is
    // requested via the artifact binding). For artifact responses, stash the SP
    // context needed to resolve the artifact and carry its id in RelayState.
    if (binding === 'artifact') {
      var ctxId = stashArtifactCtx({
        arsUrl: b.arsUrl || '',
        privateKeyPem: privateKeyPem,
        certPem: certPem,
        spEntityId: b.spEntityId || '',
        sigAlg: sigAlg
      });
      relayState = 'art:' + ctxId;
    }
    // HTTP-Redirect binding signature (saml-bindings-2.0-os §3.4.4.1): sign the
    // octet string SAMLRequest[&RelayState]&SigAlg (URL-encoded, in that
    // order), then append &Signature. It is a detached signature over the query
    // string, NOT an XML signature in the document.
    var deflated = zlib.deflateRawSync(Buffer.from(xml, 'utf8'));
    var samlRequest = deflated.toString('base64');
    var qs = 'SAMLRequest=' + encodeURIComponent(samlRequest);
    if (relayState) qs += '&RelayState=' + encodeURIComponent(relayState);
    qs += '&SigAlg=' + encodeURIComponent(sigAlg);
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(qs);
    var signature = signer.sign(privateKeyPem, 'base64');
    qs += '&Signature=' + encodeURIComponent(signature);
    // Full GET URL when a destination is known; otherwise just the signed query
    // string (e.g. "Build Request" before metadata is loaded).
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') +
        qs) : qs;
    return res.json({
      mode: 'redirect', location: location, queryString: qs });
  } catch (e) {
    log.error('samlsign: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).json({
      error: 'sign failed: ' + (e && e.message ? e.message : String(e)) 
    });
  }
});

/**
 * Register SP context for an artifact-response flow. AuthnRequest signing now
 * happens in the browser, but resolving the artifact at the ACS is a server-side
 * SOAP back-channel that needs the SP signing key + the IdP's ARS URL. The
 * browser registers them here and gets back the RelayState (art:<id>) to carry
 * in its (browser-signed) redirect request.
 * @route POST /samlartifactctx
 * @group SAML - SAML support operations
 */
app.post('/samlartifactctx', function (req, res) {
  var b = req.body || {
    };
  if (!b.privateKeyPem || !b.arsUrl) {
    return res.status(STATUS_400).json({
      error: 'privateKeyPem and arsUrl are required.'
    });
  }
  var id = stashArtifactCtx({
    arsUrl: b.arsUrl,
    privateKeyPem: b.privateKeyPem,
    certPem: b.certPem || '',
    spEntityId: b.spEntityId || '',
    sigAlg: b.sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    // Optional WS-Addressing headers for the ArtifactResolve SOAP envelope.
    wsa: b.wsa || {}
  });
  res.json({
    relayState: 'art:' + id });
});

// Decode a SAML protocol message from a binding parameter: POST binding is raw
// base64 XML; Redirect binding is DEFLATE (raw) then base64.
function decodeSamlMessage(b64) {
  log.debug("Entering decodeSamlMessage().");
  var buf = Buffer.from(String(b64 || ''), 'base64');
  if (buf.length && buf[0] === 0x3c /* '<' */) {
    log.debug("Leaving decodeSamlMessage().");
    return buf.toString('utf8');
  }
  try {
    log.debug("Leaving decodeSamlMessage().");
    return zlib.inflateRawSync(buf).toString('utf8');
  } catch (e) {
    // Not DEFLATEd after all (a POST-binding message that did not start with
    // '<', e.g. leading whitespace): read it as plain XML.
    log.debug("Leaving decodeSamlMessage().");
    return buf.toString('utf8');
  }
  log.debug("Leaving decodeSamlMessage().");
}

// Pull the <samlp:Response> element out of a SOAP <ArtifactResponse> envelope.
function extractResponseFromArtifactResponse(soapXml) {
  log.debug("Entering extractResponseFromArtifactResponse().");
  var xmldom = require('@xmldom/xmldom');
  var xpath = require('xpath');
  var doc = new xmldom.DOMParser().parseFromString(soapXml, 'text/xml');
  var nodes = xpath.select(
    "//*[local-name(.)='Response' and " +
        "namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    doc
  );
  if (!nodes || !nodes.length) {
    log.debug("Leaving extractResponseFromArtifactResponse().");
    return '';
  }
  log.debug("Leaving extractResponseFromArtifactResponse().");
  return new xmldom.XMLSerializer().serializeToString(nodes[0]);
}

// Resolve an artifact via the SOAP back-channel: build + sign an
// ArtifactResolve with the SP context stashed at request time (looked up via
// RelayState), POST it to the IdP's Artifact Resolution Service, and return the
// embedded Response.
function resolveArtifact(artifact, relayState) {
  log.debug("Entering resolveArtifact().");
  log.debug("Leaving resolveArtifact().");
  return new Promise(function (resolve, reject) {
    var ctxId = (relayState && relayState.indexOf('art:') === 0) ?
        relayState.slice(4) : '';
    var ctx = ctxId ? samlArtifactCtx.get(ctxId) : null;
    if (!ctx || !ctx.arsUrl) {
      return reject(new Error('no artifact context / ARS URL (RelayState ' +
                    'missing or expired)'));
    }
    var id = '_' + crypto.randomBytes(16).toString('hex');
    var instant = new Date().toISOString();
    var ar = '<samlp:ArtifactResolve ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
             ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
             ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '">' +
             '<saml:Issuer>' + (ctx.spEntityId || '') + '</saml:Issuer>' +
             '<samlp:Artifact>' + artifact + '</samlp:Artifact>' +
             '</samlp:ArtifactResolve>';
    var signed;
    try {
      signed = signXmlEnveloped(ar, ctx.privateKeyPem, ctx.certPem,
          'ArtifactResolve');
    } catch (e) {
      return reject(new Error('signing ArtifactResolve failed: ' + e.message));
    }

    // Optional WS-Addressing SOAP headers. WS-Addressing is a SOAP-layer
    // mechanism (not part of the AuthnRequest); it applies only to this SOAP
    // ArtifactResolve back-channel.
    var wsa = ctx.wsa || {};
    var wsaNs = '';
    var soapHeader = '';
    if (wsa.enabled) {
      wsaNs = ' xmlns:wsa="http://www.w3.org/2005/08/addressing"';
      var to = wsa.to || ctx.arsUrl;
      var msgId = wsa.messageId || ('urn:uuid:' + crypto.randomUUID());
      var hdr = '<wsa:MessageID>' + xmlTextEscape(msgId) + '</wsa:MessageID>' +
                '<wsa:To>' + xmlTextEscape(to) + '</wsa:To>';
      if (wsa.action) hdr += '<wsa:Action>' + xmlTextEscape(wsa.action) +
          '</wsa:Action>';
      if (wsa.replyTo) hdr += '<wsa:ReplyTo><wsa:Address>' +
          xmlTextEscape(wsa.replyTo) + '</wsa:Address></wsa:ReplyTo>';
      if (wsa.from) hdr += '<wsa:From><wsa:Address>' + xmlTextEscape(wsa.from) +
          '</wsa:Address></wsa:From>';
      soapHeader = '<soap:Header>' + hdr + '</soap:Header>';
    }
    var soap = '<soap:Envelope ' +
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"' + wsaNs + '>' +
               soapHeader + '<soap:Body>' + signed +
                   '</soap:Body></soap:Envelope>';
    axios.post(ctx.arsUrl, soap, {
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      headers: withUserAgent({
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '""'
      }),
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(false),
      responseType: 'text'
    }).then(function (resp) {
      var respXml = extractResponseFromArtifactResponse(resp.data);
      if (!respXml) return reject(new Error('no <Response> found in ' +
          'ArtifactResponse'));
      resolve(respXml);
    }).catch(function (e) {
      reject(new Error('ARS SOAP call failed: ' + (e && e.message ?
             e.message : String(e))));
    });
  });
}

/**
 * SAML Assertion Consumer Service (ACS). Receives the IdP's SAMLResponse
 * (POST form field or GET query) or a SAMLart artifact, stashes the response,
 * and redirects the browser to the client results page with the stash id.
 * @route POST /samlacs
 * @route GET /samlacs
 * @group SAML - SAML support operations
 */
function handleSamlAcs(req, res) {
  log.debug("Entering handleSamlAcs().");
  log.debug('Entering ' + req.method + ' /samlacs.');
  try {
    var samlResponse = (req.body && req.body.SAMLResponse) ||
        req.query.SAMLResponse;
    var relayState = (req.body && req.body.RelayState) ||
        req.query.RelayState || '';
    if (typeof relayState !== 'string') {
      log.debug("Leaving handleSamlAcs().");
      return res.status(STATUS_400).send('ACS: invalid RelayState.');
    }
    var artifact = (req.body && req.body.SAMLart) || req.query.SAMLart;

    if (samlResponse) {
      var xml = decodeSamlMessage(samlResponse);
      var id = stashSamlResponse(xml, relayState);
      res.writeHead(302, {
        'Location': uiUrl + '/saml_response.html?id=' +
            encodeURIComponent(id) });
      log.debug("Leaving handleSamlAcs().");
      return res.end();
    }
    if (artifact) {
      log.debug("Leaving handleSamlAcs().");
      return resolveArtifact(artifact, relayState)
        .then(function (respXml) {
          var artId = stashSamlResponse(respXml, relayState);
          res.writeHead(302, {
            'Location': uiUrl + '/saml_response.html?id=' +
                encodeURIComponent(artId) });
          res.end();
        })
        .catch(function (e) {
          log.error('artifact resolve: ' + (e && e.stack ? e.stack : e));
          res.status(STATUS_500).send('Artifact resolution failed: ' + (e &&
                     e.message ? e.message : String(e)));
        });
    }
    res.status(STATUS_400).send('ACS: no SAMLResponse or SAMLart present.');
  } catch (e) {
    log.error('samlacs: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).send('ACS error: ' + (e && e.message ?
               e.message : String(e)));
  }
  log.debug("Leaving handleSamlAcs().");
}
app.post('/samlacs', handleSamlAcs);
app.get('/samlacs', handleSamlAcs);

// Single Logout service. Receives the IdP's LogoutResponse (or an IdP-initiated
// LogoutRequest) and shows it on the results page. Reuses the ACS handler,
// which decodes/stashes any SAMLResponse and redirects to the viewer.
app.post('/samlslo', handleSamlAcs);
app.get('/samlslo', handleSamlAcs);

/**
 * Fetch a stashed SAMLResponse by id (set by the ACS redirect).
 * @route GET /samlresponse
 * @group SAML - SAML support operations
 */
app.get('/samlresponse', function (req, res) {
  sweepSamlExchanges();
  var ex = samlExchanges.get(String(req.query.id || ''));
  if (!ex) return res.status(STATUS_404).json({
    error: 'not found or expired' });
  res.json({
    responseXml: ex.responseXml, relayState: ex.relayState });
});

// ---------------------------------------------------------------------------
// WS-Federation Passive Requestor Profile landing endpoint.
//
// In the passive profile the IdP authenticates the user and then auto-POSTs a
// form (wa=wsignin1.0, wresult, wctx) back to the RP's wreply URL. Point wreply
// at this endpoint (appconfig.wsfedAcsUrl) so the response is captured
// server-side and shown in the browser — the same shape as the SAML ACS.
//
// wresult is RAW XML (a WS-Trust RequestSecurityTokenResponse[Collection]
// carrying the issued SAML assertion). Unlike SAMLResponse it is NOT base64 /
// DEFLATE encoded, so it is stashed verbatim (no decode). Sign-out
// (wa=wsignout1.0 / wsignoutcleanup1.0) arrives with no wresult; redirect to
// the viewer with a signout flag. GET is registered too because
// wsignoutcleanup1.0 is delivered as a GET. Reuses the SAML exchange stash.
// ---------------------------------------------------------------------------
/**
 * WS-Federation passive sign-in landing (captures wresult).
 * @route POST /wsfed
 * @route GET /wsfed
 * @group WS-Federation - WS-Federation support operations
 */
function handleWsFedLanding(req, res) {
  log.debug("Entering handleWsFedLanding().");
  log.debug('Entering ' + req.method + ' /wsfed.');
  try {
    var wa = (req.body && req.body.wa) || req.query.wa || '';
    var wresult = (req.body && req.body.wresult) || req.query.wresult;
    var wctx = (req.body && req.body.wctx) || req.query.wctx || '';

    if (wresult) {
      // wresult is raw XML (an RSTR envelope) — stash verbatim, do NOT decode.
      var id = stashSamlResponse(wresult, wctx);
      res.writeHead(302, {
        'Location': uiUrl + '/wsfed_response.html?id=' +
            encodeURIComponent(id) });
      log.debug("Leaving handleWsFedLanding().");
      return res.end();
    }
    // Sign-out (wsignout1.0 / wsignoutcleanup1.0) carries no token.
    res.writeHead(302, {
      'Location': uiUrl + '/wsfed_response.html?signout=' +
          encodeURIComponent(wa || '1') });
    res.end();
  } catch (e) {
    log.error('wsfed: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).send('WS-Fed landing error: ' + (e && e.message ?
               e.message : String(e)));
  }
  log.debug("Leaving handleWsFedLanding().");
}
app.post('/wsfed', handleWsFedLanding);
app.get('/wsfed', handleWsFedLanding);

/**
 * Fetch a stashed wresult by id (alias of GET /samlresponse; shared stash).
 * @route GET /wsfedresponse
 * @group WS-Federation - WS-Federation support operations
 */
app.get('/wsfedresponse', function (req, res) {
  sweepSamlExchanges();
  var ex = samlExchanges.get(String(req.query.id || ''));
  if (!ex) return res.status(STATUS_404).json({
    error: 'not found or expired' });
  res.json({
    responseXml: ex.responseXml, relayState: ex.relayState });
});

// ---------------------------------------------------------------------------
// WS-Trust STS SOAP proxy.
//
// The WS-Trust workflow builds a SOAP RequestSecurityToken (RST) in the browser
// and can send it to the STS one of two ways (a radio, like the OAuth2 token
// call): directly from the browser, or through this backend proxy. The proxy
// path exists because a SOAP STS endpoint almost never sends the CORS headers a
// cross-origin browser fetch requires — the same reason the token call is
// proxied. It also allows disabling TLS validation for a self-signed STS in
// dev.
//
// The browser posts { url, soap, soapVersion, action, sslValidate }; the proxy
// forwards the SOAP body with the correct content-type/SOAPAction for the SOAP
// version and returns { status, body } (the raw RSTR envelope) for the client
// to render. Like the token / metadata proxies, it POSTs to a caller-supplied
// URL, so it is a dev/debugger-only tool (SSRF by design) — do not expose
// publicly.
// ---------------------------------------------------------------------------
/**
 * Proxy a WS-Trust RequestSecurityToken to an STS (dodges CORS).
 * @route POST /wstrust
 * @group WS-Trust - WS-Trust support operations
 * @returns {object} 200 - { status, body } from the STS
 * @returns {Error.model} 400 - Missing url/soap
 * @returns {Error.model} 500 - STS call error
 */
app.post('/wstrust', function (req, res) {
  log.debug('Entering POST /wstrust.');
  var b = req.body || {
    };
  var url = b.url;
  var soap = b.soap;
  var soapVersion = String(b.soapVersion || '1.2');
  var action = b.action || '';
  // Default to validating TLS; only skip it when the caller explicitly opts
  // out.
  var sslValidate = (b.sslValidate === false || b.sslValidate === 'false') ?
      false : true;
  if (!url || !soap) {
    return res.status(STATUS_400).json({
      error: 'url and soap are required.' });
  }
  if (!/^https?:\/\//i.test(url)) {
    return res.status(STATUS_400).json({
      error: 'url must be an absolute http(s) URL.' });
  }
  // SOAP 1.2 carries the action inside the content-type; SOAP 1.1 uses a
  // separate SOAPAction header with a text/xml body.
  var headers;
  if (soapVersion === '1.1') {
    headers = {
      'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '"' + action +
          '"' };
  } else {
    headers = {
      'Content-Type': 'application/soap+xml; charset=utf-8' + (action ?
          ('; action="' + action + '"') : '') };
  }
  axios.post(url, soap, {
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [function (d) {
      return d; }],
    // The STS may return a SOAP Fault with a 4xx/5xx status; capture the body
    // rather than throwing so the client can display the fault.
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(sslValidate),
    headers: withUserAgent(headers)
  })
  .then(function (response) {
    res.status(STATUS_200).json({
      status: response.status, body: String(response.data == null ?
          '' : response.data) });
  })
  .catch(function (error) {
    log.error('wstrust proxy error to ' + url + ': ' + (error && error.stack ?
              error.stack : error));
    res.status(STATUS_500).json({
      error: 'STS call failed: ' + (error && error.message ?
          error.message : String(error)) });
  });
});

/**
 * @typedef TokenRequest
 * @property {string} grant_type.required - The OAuth2 / OIDC Grant / Flow Type
 * @property {string} client_id.required - The OAuth2 client identifier
 * @property {string} code.required - The OAuth2 Authorization Code
 * @property {string} redirect_uri.required - The registered redirect (callback) URI for the OAuth2 application definition.
 * @property {string} scope.required - The requested OAuth2 scope.
 * @property {string} token_endpoint.required - The Token Endpoint URL for this OAuth2 Provider
 * @property {boolean} sslValidate.required - Validate the token endpoint SSL/TLS certificate
 * @property {string} resource - Resource parameter
 * @property {string} refresh_token - OAuth2 Refresh Token needed for Refresh Grant
 * @property {string} username - The username used with the OAuth2 Resource Owner Credential Grant
 * @property {string} password - The password used with the OAuth2 Resource Owner Credential Grant
 * @property {string} client_secret - The client secret for a confidential client
 * @property {object} customParams - List of key:value pairs
 * @property {string} code_verifier - PKCE RFC code_verifier parameter
 */

/**
 * @typedef TokenResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 * @property {string} refresh_token - The OAuth2 Refresh Token
 * @property {string} expires_in.required - How long the access token is valid (seconds)
 * @property {string} token_type - The OAuth2 Access Token type
 */

/**
 * @typedef Error
 * @property {boolean} status.required
 * @property {string} code.required
 */

/**
 * Wrapper around OAuth2 Token Endpoint
 * @route POST /token
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {TokenRequest.model} req.body.required - Token Endpoint Request
 * @returns {TokenResponse.model} 200 - Token Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/token', (req, res) => {
  try {
    log.info('Entering app.post for /token.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    const parameterString = convertToOAuth2Format(body);
    var headers = {
      'content-type' : 'application/x-www-form-urlencoded'
    };
    const grantType = body.grant_type;
    const clientSecret = encodeURIComponent(body.client_secret);
    const code_verifier = body.code_verifier;
    if ( typeof code_verifier != "undefined" ||
         (grantType == "refresh_token" &&
          !clientSecret)) {
      headers.origin = uiUrl;
    }
    const auth_style = body.auth_style;
    var clientId = body.client_id;
    if (!auth_style) {
      // Put client_id + client_secret in Authorization header
      headers.authorization = 'Basic ' + Buffer.from(clientId + ":" +
          clientSecret).toString('base64');
    }
    var tokenEndpoint = body.token_endpoint;
    var sslValidate = body.sslValidate; 
    log.debug("Making call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: withUserAgent(headers),
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint: ' +
                JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Token Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        res.status(error.response.status || STATUS_500);
        res.json(error.response.data);
        return;
      }
      // No response: the call timed out, the connection never opened, the body
      // passed maxContentLength, the redirect chain was too long, or the URL
      // was refused (a non-http(s) scheme, a blocked address). This branch MUST
      // answer — the 500 used to sit INSIDE the `if (error.response)` above, so
      // it could never run, and every network-level failure left the browser
      // waiting on a reply that was never sent. Those failures are exactly what
      // the outbound limits produce, so this is now the common path, not a rare
      // one.
      res.status(STATUS_500).json({
        error: 'The outbound call failed: ' +
               (error && error.message ? error.message : String(error)) });
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({
      "error": e });
  }
});

/**
 * @typedef IntrospectionRequest
 * @property {string} grant_type.required - The OAuth2 / OIDC Grant / Flow Type
 * @property {string} client_id.required - The OAuth2 client identifier
 */

/**
 * @typedef IntrospectionResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 */

/**
 * Wrapper around OAuth2 Introspection Endpoint
 * @route POST /introspection
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {IntrospectionRequest.model} req.body.required - Token Endpoint Request
 * @returns {IntrospectionResponse.model} 200 - Token Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/introspection', (req, res) => {
try {
  log.info('Entering app.post for /introspection.');
  const body = req.body;
  log.debug('body: ' + JSON.stringify(body));
  var headers = {
    "Authorization": req.headers.authorization,
    "Content-Type": "application/x-www-form-urlencoded"
  };
  var introspectionRequestMessage = {
    token: body.token,
    token_type_hint: body.token_type_hint
  }
  const parameterString = JSON.stringify(introspectionRequestMessage);
  log.debug("Method: POST");
  log.debug("URL: " + body.introspectionEndpoint);
  log.debug("headers: " + JSON.stringify(headers));
  log.debug("body: " + parameterString);
  axios({
      method: 'post',
      url: body.introspectionEndpoint,
      headers: withUserAgent(headers),
      data: introspectionRequestMessage,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(true)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Introspection Endpoint: ' +
                JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Introspection Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        res.status(error.response.status || STATUS_500);
        res.json(error.response.data);
        return;
      }
      // No response: the call timed out, the connection never opened, the body
      // passed maxContentLength, the redirect chain was too long, or the URL
      // was refused (a non-http(s) scheme, a blocked address). This branch MUST
      // answer — the 500 used to sit INSIDE the `if (error.response)` above, so
      // it could never run, and every network-level failure left the browser
      // waiting on a reply that was never sent. Those failures are exactly what
      // the outbound limits produce, so this is now the common path, not a rare
      // one.
      res.status(STATUS_500).json({
        error: 'The outbound call failed: ' +
               (error && error.message ? error.message : String(error)) });
    });
  } catch(e) {
    // `e`, not `error`: this referenced an undefined variable, so an exception
    // here raised a ReferenceError instead of being logged, and answered
    // nothing.
    log.error("Error from OAuth2 Introspection Endpoint: " + (e && e.stack ?
              e.stack : e));
    if (!res.headersSent) {
      res.status(STATUS_500).json({
        error: 'The outbound call could not be made: ' + (e && e.message ?
            e.message : String(e)) });
    }
  }
});

/**
 * @typedef RevocationRequest
 * @property {string} revocation_endpoint.required - The OAuth2 Token Revocation Endpoint URL (RFC 7009)
 * @property {string} token.required - The token (access or refresh) to revoke
 * @property {string} token_type_hint - Hint about the token type (access_token | refresh_token)
 * @property {string} client_id - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {boolean} sslValidate - Validate the revocation endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Token Revocation Endpoint (RFC 7009)
 * @route POST /revoke
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {RevocationRequest.model} req.body.required - Token Revocation Request
 * @returns {object} 200 - Token Revocation Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/revoke', (req, res) => {
  try {
    log.info('Entering app.post for /revoke.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    // auth_style truthy => send client credentials in the POST body;
    // falsy => authenticate via the HTTP Basic header (RFC 6749 Section 2.3.1).
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body. token is required;
    // token_type_hint is optional per RFC 7009 Section 2.1.
    var parameters = ['token=' + encodeURIComponent(body.token)];
    if (!!body.token_type_hint) {
      parameters.push('token_type_hint=' +
                      encodeURIComponent(body.token_type_hint));
    }
    if (auth_style) {
      // POST body authentication.
      if (!!clientId) {
        parameters.push('client_id=' + encodeURIComponent(clientId));
      }
      if (!!clientSecret) {
        parameters.push('client_secret=' + encodeURIComponent(clientSecret));
      }
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' +
                    encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client with no secret: include client_id in the request body.
      parameters.push('client_id=' + encodeURIComponent(clientId));
    }
    const parameterString = parameters.join('&');
    var revocationEndpoint = body.revocation_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making call to Revocation Endpoint.");
    log.debug("POST " + revocationEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: revocationEndpoint,
      headers: withUserAgent(headers),
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      // RFC 7009: a successful revocation returns HTTP 200 with an empty body.
      log.debug('Response from OAuth2 Revocation Endpoint: ' +
                JSON.stringify(response.data));
      res.status(response.status);
      res.json({
        message: 'Token revocation request accepted (RFC 7009).',
        status: response.status,
        statusText: response.statusText,
        data: response.data
      });
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Revocation Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({
          error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({
      "error": e });
  }
});

/**
 * @typedef TokenExchangeRequest
 * @property {string} token_endpoint.required - The OAuth2 Token Endpoint URL
 * @property {string} grant_type.required - urn:ietf:params:oauth:grant-type:token-exchange
 * @property {string} subject_token.required - The token representing the subject
 * @property {string} subject_token_type.required - The subject token type identifier (URN)
 * @property {string} actor_token - The token representing the acting party (delegation)
 * @property {string} actor_token_type - The actor token type identifier (URN)
 * @property {string} requested_token_type - The requested token type identifier (URN)
 * @property {string} resource - Target resource URI
 * @property {string} audience - Target service logical name
 * @property {string} scope - Requested scope
 * @property {string} client_id - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {boolean} sslValidate - Validate the token endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Token Endpoint for Token Exchange (RFC 8693)
 * @route POST /tokenexchange
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {TokenExchangeRequest.model} req.body.required - Token Exchange Request
 * @returns {object} 200 - Token Exchange Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/tokenexchange', (req, res) => {
  try {
    log.info('Entering app.post for /tokenexchange.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    // auth_style truthy => send client credentials in the POST body;
    // falsy => authenticate via the HTTP Basic header (RFC 6749 Section 2.3.1).
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body (RFC 8693 Section 2.1).
    var parameters = ['grant_type=' + encodeURIComponent(body.grant_type)];
    var addParam = function (key, value) {
      log.debug("Entering addParam().");
      if (!!value) {
        parameters.push(key + '=' + encodeURIComponent(value));
      }
      log.debug("Leaving addParam().");
    };
    addParam('subject_token', body.subject_token);
    addParam('subject_token_type', body.subject_token_type);
    addParam('actor_token', body.actor_token);
    addParam('actor_token_type', body.actor_token_type);
    addParam('requested_token_type', body.requested_token_type);
    addParam('resource', body.resource);
    addParam('audience', body.audience);
    addParam('scope', body.scope);
    if (auth_style) {
      // POST body authentication.
      addParam('client_id', clientId);
      addParam('client_secret', clientSecret);
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' +
                    encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client with no secret: include client_id in the request body.
      addParam('client_id', clientId);
    }
    const parameterString = parameters.join('&');
    var tokenEndpoint = body.token_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making Token Exchange call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: withUserAgent(headers),
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint (token exchange): ' +
                JSON.stringify(response.data));
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Token Endpoint (token exchange): ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({
          error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({
      "error": e });
  }
});

/**
 * @typedef DeviceAuthorizationRequest
 * @property {string} device_authorization_endpoint.required - The Device Authorization Endpoint URL (RFC 8628)
 * @property {string} client_id.required - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {string} scope - The requested scope
 * @property {boolean} sslValidate - Validate the endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Device Authorization Endpoint (RFC 8628)
 * @route POST /deviceauthorization
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {DeviceAuthorizationRequest.model} req.body.required - Device Authorization Request
 * @returns {object} 200 - Device Authorization Response (device_code, user_code, verification_uri, ...)
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/deviceauthorization', (req, res) => {
  try {
    log.info('Entering app.post for /deviceauthorization.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body (RFC 8628 Section 3.1).
    var parameters = [];
    if (!!body.scope) {
      parameters.push('scope=' + encodeURIComponent(body.scope));
    }
    if (auth_style) {
      // POST body authentication.
      if (!!clientId) {
        parameters.push('client_id=' + encodeURIComponent(clientId));
      }
      if (!!clientSecret) {
        parameters.push('client_secret=' + encodeURIComponent(clientSecret));
      }
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' +
                    encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client: include client_id in the request body.
      parameters.push('client_id=' + encodeURIComponent(clientId));
    }
    const parameterString = parameters.join('&');
    var deviceAuthorizationEndpoint = body.device_authorization_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making call to Device Authorization Endpoint.");
    log.debug("POST " + deviceAuthorizationEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: deviceAuthorizationEndpoint,
      headers: withUserAgent(headers),
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Device Authorization Endpoint: ' +
                JSON.stringify(response.data));
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Device Authorization Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({
          error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({
      "error": e
    });
  }
});

/**
 * @typedef RegistrationRequest
 * @property {string} method.required - The HTTP method to use against the registration/configuration endpoint (POST | GET | PUT | DELETE)
 * @property {string} url.required - The target URL (registration_endpoint for create, registration_client_uri for read/update/delete)
 * @property {string} bearer_token - Bearer token (initial access token for create, or registration_access_token for read/update/delete)
 * @property {object} metadata - The OIDC/RFC7591 client metadata to send (POST/PUT only)
 * @property {boolean} sslValidate - Validate the endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OIDC Dynamic Client Registration endpoints
 * (OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 / RFC 7592).
 * Proxies create (POST registration_endpoint), read (GET), update (PUT) and
 * delete (DELETE) against the client configuration endpoint so the browser is
 * not blocked by CORS.
 * @route POST /register
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {RegistrationRequest.model} req.body.required - Dynamic Client Registration Request
 * @returns {object} 200 - Registration Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/register', (req, res) => {
  try {
    log.info('Entering app.post for /register.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    // Normalize the HTTP method; create=POST, read=GET, update=PUT,
    // delete=DELETE.
    var method = (body.method || 'POST').toLowerCase();
    var url = body.url;
    var bearerToken = body.bearer_token;
    var sslValidate = body.sslValidate;
    // Client metadata is only sent on create (POST) and update (PUT).
    var payload = (method === 'post' || method === 'put') ?
        body.metadata : undefined;
    var headers = {
      'Accept': 'application/json'
    };
    if (method === 'post' || method === 'put') {
      headers['Content-Type'] = 'application/json';
    }
    // The registration access token (or an initial access token for create) is
    // presented as a Bearer token per OIDC Registration 1.0 Section 4 / RFC
    // 7592.
    if (!!bearerToken) {
      headers.authorization = 'Bearer ' + bearerToken;
    }
    log.debug("Making call to Dynamic Client Registration endpoint.");
    log.debug(method.toUpperCase() + " " + url);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + JSON.stringify(payload));
    axios({
      method: method,
      url: url,
      headers: withUserAgent(headers),
      data: payload,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from Dynamic Client Registration endpoint: ' +
                JSON.stringify(response.data));
      // A successful DELETE (RFC 7592 Section 2.3) returns HTTP 204 with no
      // body. Normalize that to 200 with a JSON summary so the browser reliably
      // receives a body (a body sent with 204 is dropped by HTTP clients).
      if (response.status === STATUS_204 || !response.data) {
        res.status(STATUS_200).json({
          message: 'Client registration request succeeded.',
          status: response.status,
          statusText: response.statusText
        });
      } else {
        res.status(response.status).json(response.data);
      }
    })
    .catch(function (error) {
      log.error('Error from Dynamic Client Registration endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({
          error: error.message
        });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({
      "error": e });
  }
});

app.post('/userinfo', (req, res) => {
  log.info('Entering app.post for /userinfo.');
  userinfo_common(req, res);
  log.debug("Leaving app.post for /userinfo.");
});

/**
 * Wrapper around OIDC UserInfo Endpoint
 * @route POST /userinfo
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {UserInfoRequest.model} req.body.required - UserInfo Endpoint Request
 * @returns {UserInfoResponse.model} 200 - UserInfo Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/userinfo', (req, res) => {
  log.info("Entering app.get for /userinfo.");
  userinfo_common(req, res);
  log.debug("Leaving app.get for /userinfo.");
});

function userinfo_common(req, res) {
  log.debug("Entering userinfo_common().");
try {
  log.info('Entering app.get for /userinfo.');
  var headers = {
    "Authorization": req.headers.authorization,
  };
  // All types of requests are converted to GET.
  log.debug("Method: GET");
  log.debug("URL: " + Buffer.from(req.query.userinfo_endpoint,
            'base64').toString('utf-8'));
  log.debug("headers: " + JSON.stringify(headers));
  axios({
      method: 'get',
      url: Buffer.from(req.query.userinfo_endpoint, 'base64').toString('utf-8'),
      headers: withUserAgent(headers),
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(true)
    })
    .then(function (response) {
      log.debug('Response from OIDC UserInfo Endpoint: ' +
                JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OIDC UserInfo Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " +
                    JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        res.status(error.response.status || STATUS_500);
        res.json(error.response.data);
        return;
      }
      // No response: the call timed out, the connection never opened, the body
      // passed maxContentLength, the redirect chain was too long, or the URL
      // was refused (a non-http(s) scheme, a blocked address). This branch MUST
      // answer — the 500 used to sit INSIDE the `if (error.response)` above, so
      // it could never run, and every network-level failure left the browser
      // waiting on a reply that was never sent. Those failures are exactly what
      // the outbound limits produce, so this is now the common path, not a rare
      // one.
      res.status(STATUS_500).json({
        error: 'The outbound call failed: ' +
               (error && error.message ? error.message : String(error)) });
    });
  } catch(e) {
    // `e`, not `error`: this referenced an undefined variable, so an exception
    // here raised a ReferenceError instead of being logged, and answered
    // nothing.
    log.error("Error from OIDC UserInfo Endpoint: " + (e && e.stack ?
              e.stack : e));
    if (!res.headersSent) {
      res.status(STATUS_500).json({
        error: 'The outbound call could not be made: ' + (e && e.message ?
            e.message : String(e)) });
    }
  }
  log.debug("Leaving userinfo_common().");
}

let options = {
    swaggerDefinition: {
        info: {
            description: 'IDPTools API',
            title: 'Swagger',
            version: '1.0.0',
        },
        host: 'localhost:4000',
        basePath: '/',
        produces: [
            "application/json",
        ],
        schemes: ['http', 'https'],
        securityDefinitions: {
        }
    },
    basedir: __dirname, //app absolute path
    files: ['server.js'] //Path to the API handle folder
};
/**
 * Relay a Kerberos v5 message to a KDC and return its reply.
 * @route POST /krb5/kdc
 * @param {string} host.body.required - the KDC's host name or address
 * @param {integer} port.body - the KDC's port; defaults to 88
 * @param {string} transport.body - "tcp" (default) or "udp"
 * @param {string} message.body.required - the request, base64
 * @returns {object} 200 - the KDC's reply, base64, with timings
 * @returns {object} 400 - the request was refused (see the reason)
 * @returns {object} 502 - the KDC could not be reached or did not answer
 */
app.post('/krb5/kdc', function (req, res) {
  log.debug('Entering POST /krb5/kdc.');
  var b = req.body || {};
  var host = b.host;
  var port = (b.port === undefined || b.port === null || b.port === '') ? 88 : b.port;
  var transport = b.transport || 'tcp';

  if (!host || !b.message) {
    log.debug('Leaving POST /krb5/kdc. Missing host or message.');
    return res.status(STATUS_400).json({
      error: 'host and message are required. message is the Kerberos request, base64-encoded.' });
  }

  // Node's base64 decoder is LENIENT: Buffer.from('!!!not base64!!!', 'base64')
  // does not throw, it silently skips the characters it does not recognise and
  // hands back whatever is left. So a caller who pasted something that is not
  // base64 at all got as far as the Kerberos pre-flight and was told "this is not
  // a Kerberos request" — true, but it names the wrong mistake and sends them
  // looking at the wrong thing. Validate the alphabet first so the diagnosis
  // matches the error.
  var raw = String(b.message).trim();
  var normalised = raw.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalised) || normalised.length % 4 === 1) {
    log.debug('Leaving POST /krb5/kdc. message is not base64.');
    return res.status(STATUS_400).json({
      error: 'message is not valid base64. It must be the Kerberos request encoded as base64 or ' +
             'base64url; note that node decodes invalid base64 silently, so this is checked here ' +
             'rather than surfacing later as "not a Kerberos request".' });
  }
  var message = Buffer.from(normalised, 'base64');
  if (!message.length) {
    log.debug('Leaving POST /krb5/kdc. message decoded to nothing.');
    return res.status(STATUS_400).json({ error: 'message decoded to zero bytes.' });
  }

  krb5.send({ host: host, port: port, transport: transport, message: message })
    .then(function (result) {
      log.debug('Leaving POST /krb5/kdc. ' + result.request.message + ' -> ' + result.replyMessage);
      return res.status(STATUS_200).json({
        reply: Buffer.from(result.reply).toString('base64'),
        replyMessage: result.replyMessage,
        request: result.request,
        target: result.target,
        timing: result.timing
      });
    })
    .catch(function (error) {
      // THE NO-RESPONSE BRANCH MUST ANSWER, and for this endpoint it is the
      // COMMON branch rather than the rare one: the whole point is aiming it at a
      // host that may not be there. api/CLAUDE.md records three handlers that
      // answered only when an error carried a `response`, so every network-level
      // failure left the browser waiting forever. This one answers on every path.
      //
      // A refusal by policy is a 400 (the caller asked for something this service
      // will not do); a network failure is a 502 (the caller asked for something
      // reasonable and the far end did not deliver). The distinction matters
      // because the page shows them differently: one is a mistake to correct, the
      // other is a fact about the KDC.
      var refusedByPolicy = ['EKRB5NOTKERBEROS', 'EKRB5PORTNOTALLOWED', 'EBLOCKEDADDRESS',
                             'EKRB5NOHOST', 'EKRB5NOPORT'].indexOf(error.code) !== -1;
      var status = refusedByPolicy ? STATUS_400 : 502;
      log.warn('POST /krb5/kdc failed [' + error.code + ']: ' + error.message);
      log.debug('Leaving POST /krb5/kdc. status=' + status);
      return res.status(status).json({ error: error.message, code: error.code });
    });
});

/**
 * Present a Kerberos AP-REQ to a service and return its answer.
 * @route POST /krb5/service
 * @param {string} host.body.required - the service's host name or address
 * @param {integer} port.body.required - the service's port
 * @param {string} message.body.required - a GSS-wrapped AP-REQ (or a bare one), base64
 * @returns {object} 200 - the service's answer, base64 (or null when it sent none)
 * @returns {object} 400 - the request was refused (see the reason)
 * @returns {object} 502 - the service could not be reached or did not answer
 */
app.post('/krb5/service', function (req, res) {
  log.debug('Entering POST /krb5/service.');
  var b = req.body || {};
  if (!b.host || !b.port || !b.message) {
    log.debug('Leaving POST /krb5/service. Missing host, port or message.');
    return res.status(STATUS_400).json({
      error: 'host, port and message are required. Unlike the KDC there is no default port: a ' +
             'Kerberos service can be on any port, so it has to be named.' });
  }
  var raw = String(b.message).trim();
  var normalised = raw.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalised) || normalised.length % 4 === 1) {
    log.debug('Leaving POST /krb5/service. message is not base64.');
    return res.status(STATUS_400).json({ error: 'message is not valid base64.' });
  }
  var message = Buffer.from(normalised, 'base64');
  if (!message.length) {
    return res.status(STATUS_400).json({ error: 'message decoded to zero bytes.' });
  }

  krb5.send({ host: b.host, port: b.port, transport: b.transport || 'tcp', message: message,
              purpose: 'service' })
    .then(function (result) {
      log.debug('Leaving POST /krb5/service. ' + result.request.message + ' -> ' +
        (result.replyMessage || 'no reply'));
      return res.status(STATUS_200).json({
        reply: result.reply && result.reply.length ? Buffer.from(result.reply).toString('base64') : null,
        replyMessage: result.replyMessage,
        request: result.request,
        target: result.target,
        timing: result.timing
      });
    })
    .catch(function (error) {
      // A service that closes cleanly WITHOUT answering is not a failure: a client
      // that did not ask for mutual authentication is not owed a reply, and reporting
      // that as an error would send somebody looking for a fault that is not there.
      if (error.code === 'EKRB5SHORTREPLY' && /closed after 0 byte/.test(error.message)) {
        log.debug('Leaving POST /krb5/service. Accepted with no reply.');
        return res.status(STATUS_200).json({
          reply: null,
          replyMessage: null,
          note: 'the service closed the connection without answering. That is not an error: a ' +
                'client that did not request mutual authentication is not owed a reply — but it ' +
                'does mean nothing has proved the service is who it claims to be.'
        });
      }
      var refusedByPolicy = ['EKRB5NOTKERBEROS', 'EKRB5PORTNOTALLOWED', 'EBLOCKEDADDRESS',
                             'EKRB5NOHOST', 'EKRB5NOPORT', 'EKRB5SERVICENOTENABLED']
        .indexOf(error.code) !== -1;
      var status = refusedByPolicy ? STATUS_400 : 502;
      log.warn('POST /krb5/service failed [' + error.code + ']: ' + error.message);
      log.debug('Leaving POST /krb5/service. status=' + status);
      return res.status(status).json({ error: error.message, code: error.code });
    });
});

// ---------------------------------------------------------------------------
// POST /krb5/spnego — the SPNEGO handshake, which is the one Kerberos exchange
// that IS an HTTP exchange.
//
// Why this is not /krb5/service, and not a browser fetch:
//
//  * It is not /krb5/service. That endpoint is a raw byte relay to a TCP port
//    and is bounded by a payload check that insists on a GSS-wrapped AP-REQ. A
//    SPNEGO exchange is an HTTP request whose Authorization header happens to
//    carry one, so the bytes are not the payload and the port is 80 or 443 —
//    neither of that endpoint's two bounds applies.
//  * It is not a fetch from the page, and that is the interesting half. A
//    cross-origin fetch can read a response header only if the server chose to
//    expose it with Access-Control-Expose-Headers — and `WWW-Authenticate` is
//    exactly the header this workflow exists to show. Worse, the browser
//    controls its own request headers, so a page cannot report what it sent.
//    This endpoint reports both sides verbatim, which is the whole product.
//
// What bounds it: the method is GET and nothing else, and the ONLY header the
// caller can influence is `Authorization`, whose value this service builds
// itself as `Negotiate <base64>` from a token it has validated the alphabet of.
// A caller cannot inject a header, a method or a body. Everything else is the
// same axios instance every other outbound call here uses, so the SSRF guard,
// the four limits and the User-Agent apply unchanged and automatically.
/**
 * Perform one step of a SPNEGO (RFC 4178) HTTP handshake and report both sides.
 * @route POST /krb5/spnego
 * @param {string} url.body.required - the protected resource, an http(s) URL
 * @param {string} token.body - the SPNEGO token, base64; omitted for the
 *                              unauthenticated first request
 * @param {boolean} sslValidate.body - verify the TLS certificate (default true)
 * @returns {object} 200 - what was sent and what came back, headers included
 * @returns {object} 400 - the request was refused (see the reason)
 * @returns {object} 502 - the resource could not be reached
 */
app.post('/krb5/spnego', function (req, res) {
  log.debug('Entering POST /krb5/spnego.');
  var b = req.body || {};
  var url = b.url;
  var sslValidate = (b.sslValidate === false || b.sslValidate === 'false') ?
      false : true;
  if (!url) {
    log.debug('Leaving POST /krb5/spnego. No url.');
    return res.status(STATUS_400).json({
      error: 'url is required. It is the SPNEGO-protected resource to fetch.' });
  }
  if (!/^https?:\/\//i.test(url)) {
    log.debug('Leaving POST /krb5/spnego. Not an http(s) url.');
    return res.status(STATUS_400).json({
      error: 'url must be an absolute http(s) URL.' });
  }
  var headers = { 'Accept': '*/*' };
  if (b.token) {
    // Validated the same way and for the same reason as the two relay
    // endpoints above: node's base64 decoder is lenient, so an unreadable
    // token would otherwise reach the far end as a shorter, different token
    // and be refused by IT — which names the wrong mistake, on somebody else's
    // machine.
    var raw = String(b.token).trim().replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 === 1) {
      log.debug('Leaving POST /krb5/spnego. token is not base64.');
      return res.status(STATUS_400).json({
        error: 'token is not valid base64. It is the SPNEGO token exactly as ' +
               'it appears after "Negotiate " in the Authorization header.' });
    }
    headers.Authorization = 'Negotiate ' + raw;
  }
  var startedAt = Date.now();
  axios.get(url, {
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [function (d) {
      return d; }],
    // A 401 is the PROTOCOL here, not a failure: the first request is supposed
    // to be refused, and the refusal carries the challenge. Throwing on it
    // would make the normal case an error path.
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(sslValidate),
    headers: withUserAgent(headers)
  })
  .then(function (response) {
    var elapsed = Date.now() - startedAt;
    var body = String(response.data == null ? '' : response.data);
    // The body is capped for DISPLAY, separately from maxContentLength which
    // caps the transfer. A protected page is HTML meant for a browser and the
    // reader wants to see that it arrived, not to read it here.
    var shown = body.slice(0, SPNEGO_BODY_CHARS);
    log.debug('Leaving POST /krb5/spnego. status=' + response.status);
    return res.status(STATUS_200).json({
      request: {
        method: 'GET',
        url: url,
        // What was actually sent, including the User-Agent this service adds,
        // so the pane shows the request rather than the caller's intent.
        headers: withUserAgent(headers)
      },
      response: {
        status: response.status,
        statusText: response.statusText || '',
        headers: response.headers && response.headers.toJSON ?
                 response.headers.toJSON() : (response.headers || {}),
        body: shown,
        bodyTruncated: body.length > shown.length,
        bodyLength: body.length
      },
      timing: { totalMs: elapsed }
    });
  })
  .catch(function (error) {
    // THE NO-RESPONSE BRANCH MUST ANSWER — see the note on POST /krb5/kdc. A
    // policy refusal (the SSRF guard, a blocked scheme) is the caller asking
    // for something this service will not do; anything else is the far end.
    var blocked = error && (error.code === 'EBLOCKEDADDRESS' ||
                            error.code === 'EPROTOCOLNOTALLOWED');
    var status = blocked ? STATUS_400 : 502;
    log.warn('POST /krb5/spnego to ' + url + ' failed [' +
      (error && error.code) + ']: ' + (error && error.message));
    log.debug('Leaving POST /krb5/spnego. status=' + status);
    return res.status(status).json({
      error: (error && error.message) ? error.message : String(error),
      code: (error && error.code) || null });
  });
});

/**
 * What the Kerberos relay will and will not do, so the page can say so before a
 * call fails. A debugger that discovers its own limits by hitting them is a
 * debugger that reports them as somebody else's fault.
 * @route GET /krb5/limits
 * @returns {object} 200 - the ports, timeouts and caps in force
 */
app.get('/krb5/limits', function (req, res) {
  log.debug('Entering GET /krb5/limits.');
  log.debug('Leaving GET /krb5/limits.');
  return res.status(STATUS_200).json({
    allowedPorts: krb5.allowedPorts,
    servicePorts: krb5.servicePorts,
    serviceEnabled: krb5.serviceEnabled,
    addressPolicyEnabled: krb5.addressPolicyEnabled,
    // SPNEGO goes over HTTP through POST /krb5/spnego rather than over a
    // socket, so it has no port list of its own and no off switch: it is the
    // same capability as every other endpoint here that fetches a caller-named
    // URL. Published all the same, because the page asks this endpoint what it
    // can do before offering a button that needs it — an older api would
    // simply not have the field.
    spnegoEnabled: true,
    spnegoBodyChars: SPNEGO_BODY_CHARS,
    limits: krb5.limits
  });
});

// ---------------------------------------------------------------------------
// LDAP. Seven operations and a limits document, all of them thin: everything
// that is protocol, policy or timing is in api/ldap_client.js, and what is here
// is the HTTP shape and the status code.
//
// LDAP is BER over a TCP socket (RFC 4511), so the browser cannot speak it at
// all — no fetch, no XHR, no WebSocket produces an LDAPMessage. That is the
// same reason the Kerberos workflow needs a relay, and the same reason the LDAP
// page is left out of the static deployments, which have no api behind them.
//
// THE THREE OUTCOMES, because collapsing them is the mistake this endpoint
// family exists to avoid. `ldapResult()` below is the whole of it:
//
//   * a refusal by THIS service — a scheme that is not ldap(s), a blocked
//     address, a port that is not allowed, an operation that is missing a DN —
//     is a 400. The caller asked for something this service will not do.
//   * a network failure — nothing listening, connection refused, a timeout — is
//     a 502. The caller asked for something reasonable and the far end did not
//     deliver.
//   * AN LDAP RESULT CODE FROM THE DIRECTORY IS A 200, with `ok: false` and the
//     code. `noSuchObject` on a DN that is not there, `invalidCredentials` on a
//     bad bind, `entryAlreadyExists` on a duplicate: the operation completed and
//     the answer was "no". Reporting those as failures of this endpoint would
//     make a debugger unable to show the single most interesting thing a
//     directory ever says, and would put the most useful half of this workflow
//     behind an error page.
// ---------------------------------------------------------------------------
const ldapClient = require('./ldap_client.js');
// The LDAP client reuses the guard's address DECISION for the same reason the
// Kerberos relay does: the guard's INSTALLATION is hooks on the axios agents,
// and this transport is a raw socket with no axios in the path. Two
// implementations of an address policy is one implementation and one hole.
const ldap = ldapClient.createLdapClient(appconfig, guard, log);

// Refusals this service made itself. Everything else that rejects is a network
// failure. Listed rather than pattern-matched on the prefix, so that adding a
// code forces a decision about which of the two it is.
const LDAP_REFUSED_BY_POLICY = [
  'ELDAPBADURL', 'ELDAPPORTNOTALLOWED', 'EBLOCKEDADDRESS', 'ELDAPNODN',
  'ELDAPNOATTRIBUTES', 'ELDAPNOCHANGES', 'ELDAPBADCHANGE', 'ELDAPBADSCOPE',
  'ELDAPREFUSED'
];

/**
 * Run one LDAP operation and answer on every path.
 *
 * Shared by all seven routes because the difference between them is one method
 * call: writing the status-code decision seven times is writing seven chances
 * to get it wrong, and the one that matters (a result code is a 200) is the one
 * a copy would most plausibly lose.
 */
function runLdapOperation(name, operation, req, res) {
  log.debug('Entering runLdapOperation(). operation=' + name);
  const body = req.body || {};
  if (!body.url) {
    log.debug('Leaving runLdapOperation(). No url.');
    return res.status(STATUS_400).json({
      error: 'url is required, and must be an ldap:// or ldaps:// URL naming ' +
             'the directory server.' });
  }
  operation(body).then(function (result) {
    log.info('POST /ldap/' + name + ' ' + result.target.url + ' -> ' +
             (result.ok ? 'success' : (result.result &&
              (result.result.name + ' (' + result.result.code + ')'))) +
             ' in ' + result.timing.totalMs + 'ms');
    log.debug('Leaving runLdapOperation(). ok=' + result.ok);
    // 200 even when ok is false: see the note above. The caller reads `ok` and
    // `result.code`, which is what a directory actually told it.
    return res.status(STATUS_200).json(result);
  }).catch(function (error) {
    // THE NO-RESPONSE BRANCH MUST ANSWER, and here — as on the Kerberos relay —
    // it is the common branch rather than the rare one, because pointing this
    // at a host that may not be there is the point.
    const refusedByPolicy =
      LDAP_REFUSED_BY_POLICY.indexOf(error && error.code) !== -1;
    const status = refusedByPolicy ? STATUS_400 : 502;
    log.warn('POST /ldap/' + name + ' failed [' +
             ((error && error.code) || 'no code') + ']: ' +
             (error && error.message));
    log.debug('Leaving runLdapOperation(). status=' + status);
    return res.status(status).json({
      error: (error && error.message) ? error.message : String(error),
      code: (error && error.code) || null });
  });
}

/**
 * Bind to a directory — the LDAP authentication exchange, on its own.
 * @route POST /ldap/bind
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN; omit or empty for an anonymous bind
 * @param {string} password.body - the simple-bind password
 * @returns {object} 200 - the result, including a REFUSED bind with its code
 * @returns {object} 400 - this service refused the request (see the reason)
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/bind', function (req, res) {
  log.debug('Entering POST /ldap/bind.');
  runLdapOperation('bind', ldap.bind, req, res);
  log.debug('Leaving POST /ldap/bind.');
});

/**
 * Search a directory.
 * @route POST /ldap/search
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} baseDn.body.required - the search base
 * @param {string} scope.body - base, one or sub (default sub)
 * @param {string} filter.body - an RFC 4515 filter (default (objectClass=*))
 * @param {array} attributes.body - the attributes to return; empty means all
 * @param {integer} sizeLimit.body - the client's own cap on entries returned
 * @returns {object} 200 - the entries, with the result code
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/search', function (req, res) {
  log.debug('Entering POST /ldap/search.');
  runLdapOperation('search', ldap.search, req, res);
  log.debug('Leaving POST /ldap/search.');
});

/**
 * Add an entry — a user, a group, a container.
 * @route POST /ldap/add
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} dn.body.required - the DN of the entry to create
 * @param {object} attributes.body.required - name to value or array of values
 * @returns {object} 200 - the result code
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/add', function (req, res) {
  log.debug('Entering POST /ldap/add.');
  runLdapOperation('add', ldap.add, req, res);
  log.debug('Leaving POST /ldap/add.');
});

/**
 * Delete an entry.
 * @route POST /ldap/delete
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} dn.body.required - the DN of the entry to remove
 * @returns {object} 200 - the result code
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/delete', function (req, res) {
  log.debug('Entering POST /ldap/delete.');
  runLdapOperation('delete', ldap.del, req, res);
  log.debug('Leaving POST /ldap/delete.');
});

/**
 * Modify an entry's attributes — which is also how group membership changes.
 * @route POST /ldap/modify
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} dn.body.required - the DN of the entry to change
 * @param {array} changes.body.required - {operation, type, values} per change
 * @returns {object} 200 - the result code
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/modify', function (req, res) {
  log.debug('Entering POST /ldap/modify.');
  runLdapOperation('modify', ldap.modify, req, res);
  log.debug('Leaving POST /ldap/modify.');
});

/**
 * Rename or move an entry.
 * @route POST /ldap/modifydn
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} dn.body.required - the DN of the entry to rename
 * @param {string} newRdn.body.required - its new relative DN
 * @param {string} newSuperior.body - a new parent DN, to move it as well
 * @returns {object} 200 - the result code
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/modifydn', function (req, res) {
  log.debug('Entering POST /ldap/modifydn.');
  runLdapOperation('modifyDN', ldap.modifyDn, req, res);
  log.debug('Leaving POST /ldap/modifydn.');
});

/**
 * Compare an attribute value without reading the entry.
 * @route POST /ldap/compare
 * @param {string} url.body.required - ldap:// or ldaps:// URL of the directory
 * @param {string} bindDn.body - the bind DN
 * @param {string} password.body - the simple-bind password
 * @param {string} dn.body.required - the DN of the entry
 * @param {string} attribute.body.required - the attribute to compare
 * @param {string} value.body - the value to compare it against
 * @returns {object} 200 - compareTrue (6) or compareFalse (5), neither an error
 * @returns {object} 400 - this service refused the request
 * @returns {object} 502 - the directory could not be reached
 */
app.post('/ldap/compare', function (req, res) {
  log.debug('Entering POST /ldap/compare.');
  runLdapOperation('compare', ldap.compare, req, res);
  log.debug('Leaving POST /ldap/compare.');
});

/**
 * What the LDAP client will and will not do, so the page can say so before a
 * call fails — the same reason GET /krb5/limits exists. It is also how the page
 * tells an older api from a broken one: a build without LDAP answers 404 here,
 * which is a different thing from a directory that will not answer.
 * @route GET /ldap/limits
 * @returns {object} 200 - the ports, timeouts, caps and vocabulary in force
 */
app.get('/ldap/limits', function (req, res) {
  log.debug('Entering GET /ldap/limits.');
  log.debug('Leaving GET /ldap/limits.');
  return res.status(STATUS_200).json({
    allowedPorts: ldap.allowedPorts,
    addressPolicyEnabled: ldap.addressPolicyEnabled,
    schemes: ['ldap', 'ldaps'],
    // Published so the page can build its dropdowns from what this service
    // will actually accept, rather than from a list typed twice.
    scopes: ldap.scopes,
    modifyOperations: ldap.modifyOperations,
    // Stated rather than left to be discovered: a referral is RECORDED and not
    // followed, because following one means opening a connection to a URL the
    // directory chose.
    followsReferrals: false,
    startTls: false,
    saslMechanisms: [],
    limits: ldap.limits
  });

// TLS / mutual TLS — POST /tls/connect, GET /tls/limits
//
// The PKI page (client/public/pki.html) issues certificates in the browser and
// then has to find out whether anything accepts them. It cannot: a page cannot
// choose which client certificate to present, cannot choose a truststore,
// cannot read the negotiated version, cipher or the server's chain, and gets a
// failed handshake as a generic network error with the alert thrown away. So
// there is deliberately NO in-browser option for this — the page always asks
// here, and api/tls_probe.js is where the socket is opened. See that file's
// header for what bounds it and why the handshake is never aborted on a
// verification failure.
// ---------------------------------------------------------------------------

/**
 * Open a TLS connection and report both sides of the handshake.
 * @route POST /tls/connect
 * @param {string} host.body.required - the server's host name or address
 * @param {integer} port.body.required - the server's port
 * @param {string} servername.body - SNI / hostname to verify; defaults to host
 * @param {string} minVersion.body - TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
 * @param {string} maxVersion.body - TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3
 * @param {string} ciphers.body - an OpenSSL cipher list
 * @param {array} alpnProtocols.body - ALPN protocols to offer
 * @param {array} trustCertificates.body - the truststore, PEM
 * @param {boolean} includeSystemRoots.body - add the platform roots as well
 * @param {string} clientCertificatePem.body - client certificate, PEM
 * @param {string} clientKeyPem.body - its private key, PEM
 * @param {boolean} mutualAuthProbe.body - also connect without the client
 *     certificate, to find out whether the server requires one
 * @param {object} httpRequest.body - {path} to GET over the connection once it
 *     is made, so the SERVER's account of it comes back too. GET only, and the
 *     path is the only part of the request a caller contributes
 * @returns {object} 200 - the handshake report (including a failed handshake)
 * @returns {object} 400 - the request was refused (see the reason)
 * @returns {object} 502 - the server could not be reached
 */
app.post('/tls/connect', function (req, res) {
  log.debug('Entering POST /tls/connect.');
  var b = req.body || {};
  if (!b.host || b.port === undefined || b.port === null || b.port === '') {
    log.debug('Leaving POST /tls/connect. Missing host or port.');
    return res.status(STATUS_400).json({
      error: 'host and port are required.' });
  }
  tlsProbe.connect({
    host: b.host,
    port: b.port,
    servername: b.servername,
    minVersion: b.minVersion,
    maxVersion: b.maxVersion,
    ciphers: b.ciphers,
    alpnProtocols: Array.isArray(b.alpnProtocols) ? b.alpnProtocols : [],
    trustCertificates: Array.isArray(b.trustCertificates)
      ? b.trustCertificates
      : (b.trustCertificates ? [b.trustCertificates] : []),
    includeSystemRoots: b.includeSystemRoots,
    clientCertificatePem: b.clientCertificatePem,
    clientKeyPem: b.clientKeyPem,
    clientKeyPassphrase: b.clientKeyPassphrase,
    mutualAuthProbe: b.mutualAuthProbe === true,
    // Optional: one GET over the connection just made, so the far end's own
    // account of it comes back beside this end's. The probe refuses anything
    // but a path — the method is GET and every header is built there — so
    // handing the caller's value straight through is the whole of this.
    httpRequest: b.httpRequest,
    // Named here rather than read from the configuration inside the probe,
    // because this is the version-stamped string every other outbound call
    // announces itself with and it is resolved once, at startup, in this file.
    userAgent: USER_AGENT
  })
    .then(function (report) {
      log.debug('Leaving POST /tls/connect. connected=' +
          report.result.connected);
      return res.status(STATUS_200).json(report);
    })
    .catch(function (error) {
      // THE NO-RESPONSE BRANCH MUST ANSWER — the same rule the Kerberos relay
      // records above, and it matters here for the same reason: aiming this at
      // a host that may not be there is the point of it. A refusal by policy is
      // a 400 (the caller asked for something this service will not do); a
      // network failure is a 502 (the far end did not deliver). Note that a
      // failed HANDSHAKE is neither — it resolves with a report, because the
      // alert is the answer.
      var refusedByPolicy = ['ETLSPORTNOTALLOWED', 'EBLOCKEDADDRESS',
                             'ETLSNOHOST', 'ETLSBADPORT', 'ETLSBADVERSION',
                             'ETLSNOCLIENTKEY', 'ETLSCLIENTMATERIAL',
                             'ETLSTRUSTTOOLARGE',
                             'ETLSBADHTTPPATH'].indexOf(error.code) !== -1;
      var status = refusedByPolicy ? STATUS_400 : 502;
      log.warn('POST /tls/connect failed [' + error.code + ']: ' +
          error.message);
      log.debug('Leaving POST /tls/connect. status=' + status);
      return res.status(status).json({ error: error.message,
                                      code: error.code });
    });
});

/**
 * What the TLS probe will and will not do, so the page can say so before a call
 * fails rather than reporting its own limits as somebody else's fault.
 * @route GET /tls/limits
 * @returns {object} 200 - the ports, timeouts and caps in force
 */
app.get('/tls/limits', function (req, res) {
  log.debug('Entering GET /tls/limits.');
  log.debug('Leaving GET /tls/limits.');
  return res.status(STATUS_200).json(tlsProbe.limits());
});

expressSwagger(options)
app.listen(PORT, HOST);
log.info(`Running on http://${HOST}:${PORT}`);

// When running under coverage (c8), exit cleanly on container stop so the V8
// coverage is flushed to NODE_V8_COVERAGE before the process is terminated.
if (process.env.COVERAGE === 'true') {
  ['SIGTERM', 'SIGINT'].forEach(function (signal) {
    process.on(signal, function () {
      log.info('Received ' + signal + '; exiting to flush coverage.');
      process.exit(0);
    });
  });
}
