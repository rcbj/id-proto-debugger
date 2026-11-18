// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// THE TWO SHARED MODULES, beside this file in the image and in common/ in a
// checkout. api/Dockerfile copies common/data.js and common/xmldsig.js in
// flat, so the image finds them here; a checkout run with `node server.js`
// (which is how the api runs natively on Windows and macOS, where a container
// cannot reach the host's smart-card service) finds them in ../common. The
// image's copy wins when both exist. No logging here: the module logger is
// created further down, after these requires.
function requireShared(name) {
  const beside = path.join(__dirname, name);
  return require(fs.existsSync(beside) ? beside :
                 path.join(__dirname, '..', 'common', name));
}
const {
  convertToOAuth2Format  } = requireShared('data.js');
const ssrfGuard = require('./ssrf_guard.js');
const connectTimeout = require('./connect_timeout.js');
const krb5Relay = require('./krb5_relay.js');
const tlsProbeModule = require('./tls_probe.js');
// The listener itself — whether this service binds TLS or plain HTTP, and with
// what certificate. In common/ because the client makes the same decision and
// the two must not disagree; see the header there. `../common/...` resolves in
// a checkout and in the image alike, which is what api/Dockerfile's staging of
// common/spiffe/ already established.
const tlsListener = require('../common/tls_listener.js');
// Whether a call verifies the far end's certificate, from the `sslValidate`
// a page sent, which is text as often as it is a boolean (#434).
const { verifiesCertificates } = require('./ssl_validate.js');

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

// THE CONFIGURATION IS HELD TO ITS MODEL BEFORE ANYTHING READS IT.
// common/model/config.schema.json's ApiConfig is generated from
// models/config/api_config.tsp and closes the object, so a misspelt key in an
// env file is refused here, by name, instead of silently leaving the setting
// at its default. Refusing to start is the same choice tls_listener.js makes
// for a missing certificate: a service that came up on a configuration other
// than the one written down is worse than one that did not come up.
const modelValidate = require('./model_validate.js');
(function checkApiConfig() {
  log.debug("Entering checkApiConfig().");
  const problems = modelValidate.checkConfig(appconfig, 'ApiConfig');
  if (problems.length) {
    problems.forEach(function (problem) {
      log.fatal('Configuration ' + process.env.CONFIG_FILE + ': ' + problem +
                '.');
    });
    log.fatal('Refusing to start: the configuration does not match ' +
              'models/config/api_config.tsp.');
    log.debug("Leaving checkApiConfig(). Refused.");
    process.exit(1);
  }
  log.debug("Leaving checkApiConfig().");
})();

// The API document, enforced: every route that names an operation is held to
// it (see model_validate.js). `validateResponses` is a test setting.
const model = modelValidate.createModel({
  validateResponses: appconfig.validateResponses === true });

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

// How much of a token endpoint's response body POST /token hands back in its
// HTTP trace, for the same reason and with the same distinction as the constant
// above: MAX_CONTENT_LENGTH bounds the TRANSFER, this bounds what is put in
// front of a reader. A token response is JSON of a few kilobytes even when it
// carries three JWTs, so this is generous; what it stops is an identity
// provider answering an HTML error page — or a login page — and that page
// arriving in a pane as a wall of markup.
const TRACE_BODY_CHARS = 16384;

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
 * The application version, M.N.P.B.
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
 * Answers with TEXT that may carry a caller's, an identity provider's or an
 * exception's words. Express's res.send(string) labels a string text/html,
 * so an error message quoting a crafted SAMLart, RelayState or upstream body
 * would be rendered as markup in the browser that was redirected here (CodeQL
 * js/xss-through-exception). text/plain plus nosniff keeps it text.
 *
 * @param {object} res - the express response.
 * @param {number} status - the HTTP status.
 * @param {string} text - what to send.
 * @returns {object} the express response.
 */
function sendPlainText(res, status, text) {
  log.debug("Entering sendPlainText(). status=" + status);
  res.status(status);
  res.type('text/plain; charset=utf-8');
  res.set('X-Content-Type-Options', 'nosniff');
  log.debug("Leaving sendPlainText().");
  return res.send(String(text));
}

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
 * @returns {string[]} the allowlist, EMPTY when nothing usable is configured
 *   — a deployment missing both keys refuses every cross-origin caller, its
 *   own UI included, with the reason logged as an error.
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
    // Fail CLOSED. This used to fall back to '*', which let any site on the
    // web drive an api that fetches URLs its caller chooses (CodeQL
    // js/cors-permissive-configuration). Every shipped configuration sets
    // uiUrl, so this is only ever a misconfiguration, and a browser refusing
    // every cross-origin call names the problem where '*' hides it.
    log.error("Neither uiUrl nor apiUrl gives a usable origin, so NO browser " +
              "origin may call this api. " +
              "Set uiUrl to the browser origin that calls this api.");
    log.debug("Leaving resolveAllowedOrigins().");
    return [];
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

// ---------------------------------------------------------------------------
// THE HTTP TRACE: what this service saw of a call it made on the caller's
// behalf.
//
// The browser cannot see any of it. When the token endpoint call is proxied —
// which is this page's default, because a great many identity providers refuse
// a browser-origin Token Request outright — the request that matters is the
// one THIS process sends, and the only thing that reaches the browser is the
// parsed token payload. So the method, the URL, the headers each way, the
// bytes on the wire and how long the far end took are all observable here and
// nowhere else, and a debugger that cannot show them is asking its user to
// take the exchange on trust.
//
// It is OPT-IN, per call, and it rides in the response body under
// `http_exchange` (see POST /token). Opt-in rather than always-on because the
// trace repeats the request verbatim, credentials included: it is a debugging
// artifact for the caller that asked for it, not a thing this service adds to
// every answer it gives.
//
// The shape is deliberately the SAME as POST /krb5/spnego's, which is the
// other endpoint here that hands an HTTP exchange back for display —
// { request: {method, url, headers, body}, response: {status, statusText,
// headers, body, bodyTruncated, bodyLength}, timing: {totalMs} }. Two shapes
// for one idea would mean two renderers in the client for no reason.
// ---------------------------------------------------------------------------

// Capture the response body as it was RECEIVED, on its way through the JSON
// parse axios would have done anyway.
//
// axios's default transformResponse parses a string body as JSON and silently
// keeps the string when it is not JSON; this does exactly that and keeps the
// raw text as well. Replacing the default is what makes the raw text reachable
// at all: by the time a handler sees `response.data` the bytes are gone, and
// re-serializing the parsed object gives a body the far end never sent —
// different whitespace, different key order, and no sign of a duplicated
// member. The sink is per-call (created in the handler), so concurrent
// requests cannot see each other's bodies.
function captureRawBody(sink) {
  log.debug("Entering captureRawBody().");
  log.debug("Leaving captureRawBody().");
  return function (data) {
    if (typeof data === 'string') {
      sink.raw = data;
      try {
        return JSON.parse(data);
      } catch (e) {
        // Not JSON. Exactly what axios's own transform does with it, and the
        // trace keeps the text either way.
        return data;
      }
    }
    sink.raw = (data === null || data === undefined) ? '' : String(data);
    return data;
  };
}

// captureRawBody()'s sibling for a response read as an arraybuffer: the
// bytes are kept as they arrived (sink.bytes) and their UTF-8 reading is
// what the trace shows (sink.raw). Nothing is parsed.
function captureRawBytes(sink) {
  log.debug("Entering captureRawBytes().");
  log.debug("Leaving captureRawBytes().");
  return function (data) {
    var bytes = Buffer.isBuffer(data) ? data :
        (data === null || data === undefined) ? Buffer.alloc(0) :
        Buffer.from(data);
    sink.bytes = bytes;
    sink.raw = bytes.toString('utf8');
    return bytes;
  };
}

// The headers of an axios response, as a plain object. axios 1.x returns an
// AxiosHeaders instance, which JSON.stringify renders as {} without toJSON().
function traceHeaders(headers) {
  log.debug("Entering traceHeaders().");
  if (!headers) {
    log.debug("Leaving traceHeaders(). None.");
    return {};
  }
  if (typeof headers.toJSON === 'function') {
    log.debug("Leaving traceHeaders(). AxiosHeaders.");
    return headers.toJSON();
  }
  log.debug("Leaving traceHeaders(). Plain object.");
  return headers;
}

/**
 * Build one HTTP trace.
 *
 * @param {object} request - {method, url, headers, body} as SENT, including
 *   whatever this service added to it, so the trace shows the request rather
 *   than the caller's intent.
 * @param {object|null} response - the axios response, or null when there was
 *   none (a timeout, a refused connection, a blocked address).
 * @param {string|null} rawBody - the response body as received.
 * @param {number} startedAt - Date.now() from immediately before the call.
 * @param {string|null} failure - the error message, when there was no response.
 * @returns {object} the trace
 */
function buildHttpTrace(request, response, rawBody, startedAt, failure) {
  log.debug("Entering buildHttpTrace().");
  var body = (rawBody === null || rawBody === undefined) ? '' : String(rawBody);
  var shown = body.slice(0, TRACE_BODY_CHARS);
  var trace = {
    request: {
      method: request.method,
      url: request.url,
      headers: request.headers || {},
      body: request.body === undefined ? '' : String(request.body)
    },
    response: response === null || response === undefined ? null : {
      status: response.status,
      statusText: response.statusText || '',
      headers: traceHeaders(response.headers),
      body: shown,
      bodyTruncated: body.length > shown.length,
      bodyLength: body.length
    },
    // Measured around the outbound call and nothing else, so it is the far
    // end's time plus the network — not this service's own handling, and not
    // the browser's round trip to this service, which the browser measures for
    // itself and shows beside this one.
    timing: {
      totalMs: Date.now() - startedAt },
    error: failure || null
  };
  log.debug("Leaving buildHttpTrace(). status=" +
            (trace.response ? trace.response.status : 'none') + " in " +
            trace.timing.totalMs + "ms.");
  return trace;
}

/**
 * Attach a trace to the payload that is about to be sent back, when the caller
 * asked for one and the payload can carry it.
 *
 * A token endpoint's response is a JSON object in every case this service is
 * built for, but nothing obliges one to be: an error page is a string and an
 * empty 204 is nothing at all. Rather than change the shape of the reply for
 * those — every existing caller reads `data.access_token` and an error
 * handler reads `responseText` — the trace is simply not attached, and the
 * client falls back to what the browser itself can see of the call. A payload
 * that already HAS an `http_exchange` member keeps its own: it is somebody
 * else's data and overwriting it would be a debugger lying about the response
 * it is showing.
 *
 * @returns {*} the payload to send, with or without the trace
 */
function withHttpTrace(payload, trace, wanted) {
  log.debug("Entering withHttpTrace(). wanted=" + !!wanted);
  if (!wanted || !trace) {
    log.debug("Leaving withHttpTrace(). Not wanted.");
    return payload;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    log.debug("Leaving withHttpTrace(). Payload cannot carry it.");
    return payload;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'http_exchange')) {
    log.warn('The token endpoint response has an http_exchange member of its ' +
             'own, so the HTTP trace was not attached.');
    log.debug("Leaving withHttpTrace(). Member taken.");
    return payload;
  }
  log.debug("Leaving withHttpTrace(). Attached.");
  return Object.assign({}, payload, {
    http_exchange: trace });
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
         (ALLOWED_ORIGINS.length === 0 ?
          "none — uiUrl is not configured" : ALLOWED_ORIGINS.join(
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
//
// AND A POOLED SOCKET HAS TO BE RETIRED BEFORE THE FAR END RETIRES IT, which
// is what the `timeout` below is for. A server closes a connection that has
// been idle for its keep-alive timeout, and a request written onto it as that
// close is in flight fails with ECONNRESET before any response — through no
// fault of either end. Node's agent is built to win that race: it reads the
// server's `Keep-Alive: timeout=N` and retires the socket a second early. But
// it only ever SHORTENS its own idle timeout to the hint (`hint < timeout` in
// Agent#keepSocketAlive), and an agent given no timeout has 0, which nothing
// is less than — so the hint is ignored, the socket is kept until the server
// closes it, and every request sent around that instant is reset. Node's own
// global agent does not have this problem because it is built with a timeout
// of 5000; these agents did not have one. Against the mock STS — a Node
// server, which advertises five seconds and closes at six — that took a
// coverage run red on 2026-09-27: GET /samlmetadata, `read ECONNRESET`,
// exactly six seconds after the previous fetch of the same document. 5000 is
// Node's own value; it is the idle limit for a server that sends no hint, and
// a server that does gets its hint less a second. It bounds only an IDLE
// socket: axios sets `callTimeout` on the socket for the life of each request.
// ---------------------------------------------------------------------------
const OUTBOUND_IDLE_SOCKET_TIMEOUT = 5000;
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
    keepAlive: KEEP_ALIVE,
    timeout: OUTBOUND_IDLE_SOCKET_TIMEOUT };
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

// ---------------------------------------------------------------------------
// EMBEDDED IN THE MOCK STS: a unix socket, and one trusted peer in front of it.
//
// DEBUGGER_LISTEN_SOCKET is set only when the mock STS forks this service as
// its embedded debugger (embedded/CLAUDE.md). The listener is then a unix
// socket — common/tls_listener.js decides that, as it decides TLS — and the
// ONLY thing that can connect to it is that service's reverse proxy, which
// terminates TLS on the debugger's public origin and strips `/api` from the
// path. So `trust proxy` is on in that mode and in no other: the proxy's
// X-Forwarded-Proto and X-Forwarded-Host are the truth about the URL a
// browser used, and without them every absolute URL built from a request
// here would say `http://` and whatever Host a unix socket was given.
// Standalone, nothing sets the variable and nothing below changes.
// ---------------------------------------------------------------------------
const LISTEN_SOCKET = tlsListener.socketPathFor({});
if (LISTEN_SOCKET) {
  app.set('trust proxy', true);
  log.info('Listening on a unix socket behind the mock STS: trust proxy on.');
}

/**
 * The prefix the embedding proxy stripped, from X-Forwarded-Prefix, or ''.
 *
 * Honoured ONLY on the socket listener, whose one peer is that proxy; on a
 * TCP listener anybody could send the header, and a URL this service hands
 * back must not be steerable by its caller. It must be a plain absolute path
 * (`/api`) — no scheme, no `//`, no query — and anything else is ignored
 * rather than repaired, so a malformed header yields the unprefixed URL.
 *
 * @param {object} req - the Express request.
 * @returns {string} e.g. "/api", or "".
 */
function forwardedPrefix(req) {
  log.debug("Entering forwardedPrefix().");
  if (!LISTEN_SOCKET) {
    log.debug("Leaving forwardedPrefix(). Not behind the embedding proxy.");
    return '';
  }
  var raw = String(req.get('X-Forwarded-Prefix') || '').trim();
  if (!/^(\/[A-Za-z0-9._~-]+)+\/?$/.test(raw)) {
    log.debug("Leaving forwardedPrefix(). Absent or not a plain path.");
    return '';
  }
  log.debug("Leaving forwardedPrefix(). " + raw.replace(/\/$/, ''));
  return raw.replace(/\/$/, '');
}

/**
 * This service's own base URL AS THE CALLER REACHED IT, for a URL handed back
 * to a browser or a transmitter.
 *
 * Standalone it is exactly the expression the SSF receiver always used —
 * `req.protocol + '://' + req.get('host')`. Behind the embedding proxy it
 * reads the forwarded host (`req.host` honours X-Forwarded-Host once trust
 * proxy is on; `req.get('host')` never does) and puts back the prefix the
 * proxy stripped, because a path that works on the socket is one segment
 * short on the public origin.
 *
 * @param {object} req - the Express request.
 * @returns {string} e.g. "https://localhost:8444/api".
 */
function publicBaseUrl(req) {
  log.debug("Entering publicBaseUrl().");
  if (!LISTEN_SOCKET) {
    log.debug("Leaving publicBaseUrl(). Standalone.");
    return req.protocol + '://' + req.get('host');
  }
  var base = req.protocol + '://' + (req.host || req.get('host')) +
      forwardedPrefix(req);
  log.debug("Leaving publicBaseUrl(). " + base);
  return base;
}

/**
 * body-parser's `verify` hook: keep the raw text of a body sent to
 * /oid4vp/verifier/<id>/..., as req.oid4vpRawBody, for the Verifier
 * session's Wallet-facing routes. Every other path is untouched.
 *
 * @param {object} req - the Express request.
 * @param {object} res - unused.
 * @param {Buffer} buf - the body as it arrived.
 */
function keepOid4vpVerifierBody(req, res, buf) {
  log.debug("Entering keepOid4vpVerifierBody().");
  if (/^\/oid4vp\/verifier\/[^/]+\/(request|response)(\?|$)/
      .test(req.url || '')) {
    req.oid4vpRawBody = buf.toString('utf8');
  }
  log.debug("Leaving keepOid4vpVerifierBody().");
}

// The JSON limit is an OUTER bound only. The caps that mean something are
// scimMaxRequestBytes (1 MiB), ssfMaxRequestBytes and gnapMaxRequestBytes
// (256 KiB each), enforced in their proxies where the answer can name the
// setting. At body-parser's default of 100 KB none of them was reachable:
// a body between 100 KB and the configured cap got body-parser's bare 413
// instead of the documented refusal. Keep this above the largest of them.
//
// The `verify` hook keeps the RAW text of a body sent to an OpenID4VP
// Verifier session (api/oid4vp_verifier.js), and only there. A Wallet's
// answer is stored field by field EXACTLY as it arrived, and the extended
// urlencoded parser reshapes a form — `a[0]=x` becomes an array, a
// repeated field collapses — before anybody could see what was sent.
app.use(bodyParser.json({ limit: '5mb', verify: keepOid4vpVerifierBody }));
// SAML ACS receives application/x-www-form-urlencoded POSTs (SAMLResponse,
// RelayState, SAMLart) from the IdP; enable urlencoded parsing for those.
app.use(bodyParser.urlencoded({
  extended: true, limit: '5mb', verify: keepOid4vpVerifierBody }));
// ---------------------------------------------------------------------------
// A Security Event Token arrives as `application/secevent+jwt` (RFC 8417
// section 2.3) — a compact JWS in the body, with no form encoding and no JSON
// wrapper around it. Neither parser above touches that type, so without this
// `req.body` on POST /ssf/receiver/:id would be an empty object and every push
// would be reported as an empty body.
//
// It is a TEXT parser and it is deliberately narrow: exactly the two types a
// SET is ever sent as, so nothing else in this service changes shape. The
// second one is not a mistake — `application/jwt` is what a transmitter that
// gets the media type wrong sends, and api/ssf_receiver.js REPORTS that rather
// than refusing it, because a receiver dispatching on the type drops such a
// token with no error anybody sees and that is a finding worth surfacing. A
// parser that refused it would hide the finding behind an empty body.
//
// The limit is above `ssfReceiverMaxEventBytes` on purpose: the CAP is that
// setting, enforced where it can name itself in the answer, and this is only
// the outer bound that keeps an absurd body out of memory.
app.use(bodyParser.text({
  type: ['application/secevent+jwt', 'application/jwt'], limit: '1mb' }));
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
// "/*splat" and not "*". Express 5 (here since the 2026-09-11 bump of
// express 4.22.2 -> 5.2.1, which came in to carry a qs advisory) resolves
// paths with path-to-regexp 8, where a wildcard MUST be named and a bare
// "*" is not a path at all. It throws at REGISTRATION rather than on a
// request -- `PathError: Missing parameter name at index 1: *` -- so the
// api exits before it listens and every call from the page dies in the
// handshake, which a browser reports as a CORS failure naming a header
// nobody changed. The name is a formality: nothing reads req.params.splat
// here, the route exists only so a preflight to any path gets the headers.
app.options("/*splat", cors(corsOptions));
app.use(cors(corsOptions));

/**
 * @typedef HealthcheckResponse
 * @property {string} message - Status message
 */
/**
 * System healthcheck
 */
app.get('/healthcheck', model.route('healthcheck'), function (req, res) {
  log.debug("Entering GET /healthcheck.");
  log.debug("Leaving GET /healthcheck.");
  res
  .status(STATUS_200)
  .json({
    message: 'Success' });
});

/**
 * The answers this process sent that its API document does not describe.
 * 404 unless validateResponses is on, which only a test configuration sets.
 */
app.get('/model/gaps', model.route('modelGaps'), function (req, res) {
  log.debug("Entering GET /model/gaps.");
  log.debug("Leaving GET /model/gaps.");
  return model.gapsHandler(req, res);
});

// The IANA JWT claim registry: the one outbound call in this service whose URL
// is NOT chosen by the caller. It gets the same treatment as the rest anyway —
// both timeouts, the size cap and the guarded agents — because having picked
// the URL ourselves is no reason to accept a hung or unbounded response from
// it.
const IANA_JWT_CLAIMS_URL = 'https://www.iana.org/assignments/jwt/jwt.xml';

/**
 * Retrieve Claims Description.
 */
app.get('/claimdescription', model.route('claimDescription'),
        function(req, res) {
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
 */
// `url` is a single string by the time this runs: models/api/saml.tsp holds
// the query to that, so a repeated ?url= is refused there rather than joined
// with a comma and decoded into a URL nobody wrote.
app.get('/samlmetadata', model.route('samlMetadata'), function (req, res) {
  log.debug('Entering GET /samlmetadata.');
  var target;
  try {
    target = Buffer.from(String(req.query.url || ''),
        'base64').toString('utf8').trim();
  } catch (e) {
    log.debug('Leaving GET /samlmetadata. Not base64.');
    return res.status(STATUS_400).json({
      error: 'Invalid url parameter (expected base64).' });
  }
  if (!/^https?:\/\//i.test(target)) {
    log.debug('Leaving GET /samlmetadata. Not http(s).');
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
      sendPlainText(res, error.response.status || STATUS_500,
                    String(error.response.data || 'metadata fetch failed'));
    } else {
      res.status(STATUS_500).json({
        error: 'metadata fetch failed: ' + (error && error.message ?
            error.message : String(error)) });
    }
  });
  log.debug('Leaving GET /samlmetadata. The fetch is under way.');
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

// THE XML SIGNATURE HERE IS THE SAME ONE THE BROWSER USES.
//
// This was the `xml-crypto` package, which made three implementations of XML
// Signature in one application: xml-crypto here, and two copies of a
// hand-written one in the browser (client/src/saml_request.js had its own and
// common/xmldsig.js had the other). A canonicalizer is a reading of a
// specification, and three readings is three chances to disagree with the
// verifier at the far end — which for SAML is an identity provider that says
// only "invalid signature".
//
// common/xmldsig.js needs the two DOM constructors, which node does not have;
// @xmldom/xmldom supplies them and was already a dependency of this file for
// the artifact SOAP handling further down.
var xmldom = require('@xmldom/xmldom');
if (!global.DOMParser) global.DOMParser = xmldom.DOMParser;
if (!global.XMLSerializer) global.XMLSerializer = xmldom.XMLSerializer;
var xmldsig = requireShared('xmldsig.js');

function signXmlEnveloped(xml, privateKeyPem, certPem, sigAlg) {
  log.debug("Entering signXmlEnveloped().");
  // The Reference URI, the enveloped-signature + exclusive-C14N transform
  // pair, the X509Data KeyInfo and the placement directly after <Issuer> are
  // all signEnveloped()'s defaults — which is not a coincidence: those
  // defaults ARE the SAML profile, which is what that function was written
  // for. `rootLocalName` is gone with the xpath that needed it; the module
  // finds the root's ID attribute itself.
  var signed = xmldsig.signEnveloped(xml, {
    privateKeyPem: privateKeyPem,
    certPem: certPem || '',
    sigAlg: sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    placement: 'after-issuer',
    includeKeyInfo: !!certPem
  });
  log.debug("Leaving signXmlEnveloped().");
  return signed;
}

/**
 * Sign a SAML AuthnRequest for the chosen binding.
 */
app.post('/samlsign', model.route('samlSign'), function (req, res) {
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
    // xml and privateKeyPem are both non-empty strings by the time this runs:
    // models/api/saml.tsp refuses either missing, empty or of another type
    // with the sentence this handler always answered ("xml and privateKeyPem
    // are required."). Every other member is a string or null there too, so
    // a numeric destination is a 400 rather than a TypeError from indexOf.
    // The api signs with RSA only (it holds no post-quantum signer), and
    // sigAlg is the caller's choice. An ECDSA, HMAC or misspelt URI is the
    // caller's error, so it is a 400 naming the methods on offer rather than
    // the 500 the signer's throw would become in the catch below.
    var refusal = xmldsig.rsaSigAlgRefusal(sigAlg, 'samlsign');
    if (refusal) {
      log.debug('Leaving POST /samlsign. ' + refusal);
      return res.status(STATUS_400).json({ error: refusal });
    }

    if (binding === 'post') {
      var signedXml = signXmlEnveloped(xml, privateKeyPem, certPem, sigAlg);
      var params = {
        SAMLRequest: Buffer.from(signedXml, 'utf8').toString('base64') };
      if (relayState) params.RelayState = relayState;
      // signedXml is also returned so the UI can display the enveloped-signed
      // document (e.g. the "Build Request" button).
      log.debug('Leaving POST /samlsign. The POST binding.');
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
    // THE DIGEST NOW FOLLOWS SigAlg. This was `crypto.createSign('RSA-SHA256')`
    // whatever the caller asked for, so a request that declared
    // SigAlg=…#rsa-sha512 was signed with SHA-256 and the query string said
    // otherwise — a document that verifies nowhere, and whose only symptom at
    // the identity provider is "invalid signature". signQueryString() reads
    // the digest out of the SigAlg it is given.
    qs += '&Signature=' + encodeURIComponent(
      xmldsig.signQueryString(qs, { privateKeyPem: privateKeyPem,
                                    sigAlg: sigAlg }));
    // Full GET URL when a destination is known; otherwise just the signed query
    // string (e.g. "Build Request" before metadata is loaded).
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') +
        qs) : qs;
    log.debug('Leaving POST /samlsign. The redirect binding.');
    return res.json({
      mode: 'redirect', location: location, queryString: qs });
  } catch (e) {
    log.error('samlsign: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).json({
      error: 'sign failed: ' + (e && e.message ? e.message : String(e))
    });
  }
  log.debug('Leaving POST /samlsign.');
});

/**
 * Register SP context for an artifact-response flow. AuthnRequest signing now
 * happens in the browser, but resolving the artifact at the ACS is a server-side
 * SOAP back-channel that needs the SP signing key + the IdP's ARS URL. The
 * browser registers them here and gets back the RelayState (art:<id>) to carry
 * in its (browser-signed) redirect request.
 */
app.post('/samlartifactctx', model.route('samlArtifactContext'),
         function (req, res) {
  log.debug('Entering POST /samlartifactctx.');
  var b = req.body || {
    };
  // THE KEY IS OPTIONAL AND THE ADDRESS IS NOT, which is a change of shape
  // rather than a relaxation. SAML 2.0 section 3.6.3 does not require the
  // <ArtifactResolve> to be signed either, and SAML 1.1 has no request document
  // to sign at all — the browser sends four unsigned query parameters. Refusing
  // without a key made "the service provider generated no key pair" fail HERE,
  // in a call whose error text names privateKeyPem and nothing else, several
  // steps before anything SAML-shaped happens. resolveArtifact() below signs
  // when there is a key and sends it unsigned when there is not.
  //
  // arsUrl is a non-empty string by the time this runs: models/api/saml.tsp
  // refuses it missing, empty or of another type with the sentence this
  // handler always answered ("arsUrl is required."). A number used to be
  // stashed, and failed only later, at the landing, as an artifact that did
  // not resolve.
  var id = stashArtifactCtx({
    arsUrl: b.arsUrl,
    privateKeyPem: b.privateKeyPem || '',
    certPem: b.certPem || '',
    spEntityId: b.spEntityId || '',
    sigAlg: b.sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    // WHICH PROTOCOL VERSION'S BACK-CHANNEL THIS IS. '1.1' means the endpoint
    // is a SAML 1.1 SAML RESPONDER (saml-bindings-1.1 section 3.1), which
    // answers a <samlp:Request> carrying an <AssertionArtifact> — NOT a SAML
    // 2.0 Artifact Resolution Service, which answers an <ArtifactResolve>. The
    // two are different messages in different namespaces returning differently
    // shaped answers, and sending one where the other is expected produces a
    // status a relying party reads as "that artifact does not resolve".
    samlVersion: b.samlVersion === '1.1' ? '1.1' : '2.0',
    // Optional WS-Addressing headers for the SOAP envelope. They apply to both
    // versions: WS-Addressing is a SOAP-layer mechanism and knows nothing about
    // what is inside the body.
    wsa: b.wsa || {}
  });
  res.json({
    relayState: 'art:' + id });
  log.debug('Leaving POST /samlartifactctx.');
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

// Pull the <samlp:Response> element out of the SOAP envelope that came back.
//
// It sits at a different DEPTH in the two versions and the difference is not
// cosmetic. A SAML 2.0 Artifact Resolution Service answers with an
// <ArtifactResponse> WRAPPING the <Response> that would otherwise have been
// POSTed — two protocol messages, each with its own status. A SAML 1.1 SAML
// responder answers with the <Response> itself, built at resolution time so it
// can carry InResponseTo naming this SOAP request. Selecting on the local name
// and the namespace finds the right element in both, and the namespace has to
// be part of it: SAML 1.1's protocol namespace ends `:1.0:protocol`, which is
// not a typo — the schemas were never renamed between 1.0 and 1.1.
function extractResponseFromArtifactResponse(soapXml) {
  log.debug("Entering extractResponseFromArtifactResponse().");
  var xmldom = require('@xmldom/xmldom');
  var xpath = require('xpath');
  var doc = new xmldom.DOMParser().parseFromString(soapXml, 'text/xml');
  var nodes = xpath.select(
    "//*[local-name(.)='Response' and " +
        "(namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol' or " +
         "namespace-uri(.)='urn:oasis:names:tc:SAML:1.0:protocol')]",
    doc
  );
  if (!nodes || !nodes.length) {
    log.debug("Leaving extractResponseFromArtifactResponse().");
    return '';
  }
  log.debug("Leaving extractResponseFromArtifactResponse().");
  return new xmldom.XMLSerializer().serializeToString(nodes[0]);
}

// The message that asks for an artifact to be resolved, in whichever version's
// spelling. Returns the XML and the id the enveloped signature must reference —
// SAML 1.1 spells that attribute `RequestID`, which is on none of the lists
// xmldsig's signEnveloped() searches, so it is passed explicitly rather than
// found. Told nothing, xml-crypto-style signers INVENT an `Id` and point the
// reference at that; it verifies, and it is not the id a SAML 1.1 responder
// looks for.
function buildArtifactResolveMessage(artifact, ctx) {
  log.debug("Entering buildArtifactResolveMessage(). version=" +
      ctx.samlVersion);
  var id = '_' + crypto.randomBytes(16).toString('hex');
  var instant = new Date().toISOString();
  if (ctx.samlVersion === '1.1') {
    // sstc-saml-bindings-1.1 section 4.1.1.6. MajorVersion/MinorVersion rather
    // than a Version attribute, RequestID rather than ID, and NO <Issuer> —
    // SAML 1.1 has no element for a requester to name itself in. The
    // responder knows whom the artifact was issued to and authenticates the
    // caller as that party, by TLS or by this message's signature (section
    // 4.1.1.6 requires one or the other); Shibboleth checks the signature
    // against the SP metadata's signing key.
    var req = '<samlp:Request ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"' +
        ' xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"' +
        ' RequestID="' + id + '" MajorVersion="1" MinorVersion="1"' +
        ' IssueInstant="' + instant + '">' +
        '<samlp:AssertionArtifact>' + xmlTextEscape(artifact) +
        '</samlp:AssertionArtifact>' +
        '</samlp:Request>';
    log.debug("Leaving buildArtifactResolveMessage(). A SAML 1.1 Request.");
    return { xml: req, id: id, refUri: '#' + id };
  }
  var ar = '<samlp:ArtifactResolve ' +
      'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
           ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
           ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '">' +
           '<saml:Issuer>' + xmlTextEscape(ctx.spEntityId || '') +
               '</saml:Issuer>' +
           '<samlp:Artifact>' + xmlTextEscape(artifact) + '</samlp:Artifact>' +
           '</samlp:ArtifactResolve>';
  log.debug("Leaving buildArtifactResolveMessage(). An ArtifactResolve.");
  return { xml: ar, id: id, refUri: '#' + id };
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
    var msg = buildArtifactResolveMessage(artifact, ctx);
    var signed = msg.xml;
    if (ctx.privateKeyPem) {
      try {
        signed = xmldsig.signEnveloped(msg.xml, {
          privateKeyPem: ctx.privateKeyPem,
          certPem: ctx.certPem || '',
          sigAlg: ctx.sigAlg ||
              'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          includeKeyInfo: !!ctx.certPem,
          // Named rather than found: SAML 1.1's id attribute is `RequestID`,
          // which signEnveloped() does not look for, and a signature that
          // referenced the wrong id verifies against the document it invented
          // instead of the one that was sent.
          refUri: msg.refUri,
          // WHERE ds:Signature GOES, and the two versions disagree. A SAML 2.0
          // <ArtifactResolve> has an <Issuer> and the signature follows it. A
          // SAML 1.1 <samlp:Request> has no Issuer at all and its schema's
          // sequence is RespondWith*, ds:Signature?, then the query or the
          // artifact — so the signature is the FIRST child, and a document that
          // put it after the <AssertionArtifact> is schema-invalid.
          placement: ctx.samlVersion === '1.1' ? 'first' : 'after-issuer'
        });
      } catch (e) {
        return reject(new Error('signing the artifact resolution request ' +
                      'failed: ' + e.message));
      }
    } else if (ctx.samlVersion === '1.1') {
      // SAML 1.1 REQUIRES the requester be authenticated here
      // (sstc-saml-bindings-1.1 section 4.1.1.6: the SOAP binding "MUST
      // provide ... bilateral authentication"), and a source site that cannot
      // tell who asked answers Success with NO assertions — which is what
      // Shibboleth does (#425). A signature over the <samlp:Request> is how
      // this API authenticates; without a key it can only send it unsigned.
      log.warn('resolveArtifact: no SP private key was registered for this ' +
               'flow, so the SAML 1.1 artifact resolution request is being ' +
               'sent UNSIGNED. sstc-saml-bindings-1.1 section 4.1.1.6 ' +
               'requires the requester to be authenticated; an identity ' +
               'provider that enforces it answers Success with no ' +
               'assertion. Load the SP key pair to sign it.');
    } else {
      log.info('resolveArtifact: no SP private key was registered for this ' +
               'flow, so the artifact resolution request is being sent ' +
               'UNSIGNED. SAML 2.0 does not require a signature here; an ' +
               'identity provider that wants one refuses with a SAML status ' +
               'rather than an HTTP error.');
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
      // SOAPAction: SAML 1.1's SOAP binding (saml-bindings-1.1 section 3.1)
      // gives requesters http://www.oasis-open.org/committees/security as
      // the value to send, and a responder must not depend on it. 2.0 keeps
      // the empty value it has always sent.
      headers: withUserAgent({
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': ctx.samlVersion === '1.1'
          ? '"http://www.oasis-open.org/committees/security"' : '""'
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
 */
function handleSamlAcs(req, res) {
  log.debug("Entering handleSamlAcs().");
  log.debug('Entering ' + req.method + ' /samlacs.');
  try {
    var samlResponse = (req.body && req.body.SAMLResponse) ||
        req.query.SAMLResponse;
    // THE RELAY STATE HAS TWO NAMES, one per protocol version. `RelayState` is
    // SAML 2.0's and did not exist before it; SAML 1.1's browser profiles
    // round-trip `TARGET`, which the profile intends as the URL of the resource
    // the person was trying to reach and which the binding guarantees comes
    // back byte for byte. That guarantee is the whole of what this endpoint
    // needs from it: the Browser/Artifact flow carries the `art:<id>` handle
    // naming the stashed SP context, and SAML 1.1 has nowhere else to put one.
    // Reading only RelayState made every 1.1 artifact resolution fail with "no
    // artifact context", which reads as an expired stash rather than as a
    // parameter this handler never looked at.
    var relayState = (req.body && req.body.RelayState) ||
        req.query.RelayState ||
        (req.body && req.body.TARGET) || req.query.TARGET || '';
    if (typeof relayState !== 'string') {
      log.debug("Leaving handleSamlAcs().");
      return sendPlainText(res, STATUS_400, 'ACS: invalid RelayState.');
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
          sendPlainText(res, STATUS_500, 'Artifact resolution failed: ' +
                        (e && e.message ? e.message : String(e)));
        });
    }
    sendPlainText(res, STATUS_400,
                  'ACS: no SAMLResponse or SAMLart present.');
  } catch (e) {
    log.error('samlacs: ' + (e && e.stack ? e.stack : e));
    sendPlainText(res, STATUS_500, 'ACS error: ' + (e && e.message ?
                  e.message : String(e)));
  }
  log.debug("Leaving handleSamlAcs().");
}
// What an identity provider sends is validated for its envelope only
// (models/api/saml.tsp): every member is optional and of any type, so a
// field nobody expected, or one sent twice, still reaches the results page.
// The relay-state check above stays here, because it answers as text/plain.
app.post('/samlacs', model.route('samlAcsPost'), handleSamlAcs);
app.get('/samlacs', model.route('samlAcsGet'), handleSamlAcs);
// SAML 1.1's Browser/Artifact consumer, at a location of its own. A SAML 1.1
// service provider picks the browser profile by which assertion consumer its
// shire names (the profile bound to that AssertionConsumerService in its
// metadata), so POST and artifact cannot share /samlacs. Same handler: what
// arrives here is a SAMLart and TARGET on a GET.
app.get('/samlacs/artifact', model.route('samlAcsArtifact'), handleSamlAcs);

// Single Logout service. Receives the IdP's LogoutResponse (or an IdP-initiated
// LogoutRequest) and shows it on the results page. Reuses the ACS handler,
// which decodes/stashes any SAMLResponse and redirects to the viewer.
app.post('/samlslo', model.route('samlSloPost'), handleSamlAcs);
app.get('/samlslo', model.route('samlSloGet'), handleSamlAcs);

/**
 * Fetch a stashed SAMLResponse by id (set by the ACS redirect).
 */
app.get('/samlresponse', model.route('samlResponse'), function (req, res) {
  log.debug('Entering GET /samlresponse.');
  sweepSamlExchanges();
  var ex = samlExchanges.get(String(req.query.id || ''));
  if (!ex) {
    log.debug('Leaving GET /samlresponse. Not found.');
    return res.status(STATUS_404).json({
      error: 'not found or expired' });
  }
  res.json({
    responseXml: ex.responseXml, relayState: ex.relayState });
  log.debug('Leaving GET /samlresponse.');
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
    sendPlainText(res, STATUS_500, 'WS-Fed landing error: ' +
                  (e && e.message ? e.message : String(e)));
  }
  log.debug("Leaving handleWsFedLanding().");
}
// The envelope only, as for the SAML landings (models/api/wsfed.tsp).
app.post('/wsfed', model.route('wsfedLandingPost'), handleWsFedLanding);
app.get('/wsfed', model.route('wsfedLandingGet'), handleWsFedLanding);

/**
 * Fetch a stashed wresult by id (alias of GET /samlresponse; shared stash).
 */
app.get('/wsfedresponse', model.route('wsfedResponse'),
        function (req, res) {
  log.debug('Entering GET /wsfedresponse.');
  sweepSamlExchanges();
  var ex = samlExchanges.get(String(req.query.id || ''));
  if (!ex) {
    log.debug('Leaving GET /wsfedresponse. Not found.');
    return res.status(STATUS_404).json({
      error: 'not found or expired' });
  }
  res.json({
    responseXml: ex.responseXml, relayState: ex.relayState });
  log.debug('Leaving GET /wsfedresponse.');
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
 */
app.post('/wstrust', model.route('wstrustProxy'), function (req, res) {
  log.debug('Entering POST /wstrust.');
  var b = req.body || {
    };
  var url = b.url;
  var soap = b.soap;
  var soapVersion = String(b.soapVersion || '1.2');
  var action = b.action || '';
  // Default to validating TLS; only skip it when the caller explicitly opts
  // out.
  var sslValidate = verifiesCertificates(b.sslValidate);
  // url and soap are both non-empty strings by the time this runs:
  // models/api/wstrust.tsp refuses either missing, empty or of another type
  // with the sentence this handler always answered ("url and soap are
  // required."). The scheme is still this handler's.
  if (!/^https?:\/\//i.test(url)) {
    log.debug('Leaving POST /wstrust. Not http(s).');
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
  log.debug('Leaving POST /wstrust. The call is under way.');
});

// ---------------------------------------------------------------------------
// THE OAUTH 2.0 / OPENID CONNECT PROXIES, held to models/api/oauth.tsp.
//
// model.route() checks each body's SHAPE before the handler runs: the
// endpoint URL the api is told to call is a non-empty string and the only
// required member, and sslValidate, auth_style and http_trace are a boolean,
// a string or null. Every protocol parameter the user typed is a string or
// null and NOTHING MORE: its content goes to the far end as typed, because a
// debugger has to be able to send a malformed request and show the
// authorization server's error. Do not add a content check here or there.
//
// None of these handlers checked anything before the model did, so there was
// no hand-written check to delete; a missing URL used to reach axios and come
// back as a 500 "Invalid URL" (tests/fixtures/api_model/oauth.json, each case
// marked `changed`). What a URL may be — http(s), and an address the policy
// allows — is still api/ssrf_guard.js's, at connect time.
// ---------------------------------------------------------------------------

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
 * @property {boolean} http_trace - Also return the HTTP exchange with the token endpoint, for display
 */

/**
 * @typedef TokenResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 * @property {string} refresh_token - The OAuth2 Refresh Token
 * @property {string} expires_in.required - How long the access token is valid (seconds)
 * @property {string} token_type - The OAuth2 Access Token type
 * @property {object} http_exchange - The HTTP exchange, when http_trace asked for it. See buildHttpTrace()
 */

/**
 * @typedef Error
 * @property {boolean} status.required
 * @property {string} code.required
 */

/**
 * Wrapper around OAuth2 Token Endpoint
 */
app.post('/token', model.route('oauthToken'), (req, res) => {
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
    var sslValidate = verifiesCertificates(body.sslValidate);
    // The HTTP trace this call is to be shown with, if the caller asked for
    // one. Opt-in per call: it repeats the request verbatim, Authorization
    // header and all, so it is built for the caller that wants to read it and
    // for nobody else. See buildHttpTrace().
    const wantsTrace = body.http_trace === true || body.http_trace === 'true';
    // Filled in by the transform below, on the way past axios's JSON parse.
    // Per call, so two requests in flight cannot see each other's bodies.
    var received = {
      raw: null };
    const sentHeaders = withUserAgent(headers);
    const sentRequest = {
      method: 'POST',
      url: tokenEndpoint,
      // What actually goes out, including the User-Agent this service adds and
      // the Authorization header it may have built — the trace shows the
      // request, not the intent behind it.
      headers: sentHeaders,
      body: parameterString };
    const startedAt = Date.now();
    log.debug("Making call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: sentHeaders,
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      transformResponse: [captureRawBody(received)],
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint: ' +
                JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(withHttpTrace(response.data,
                             buildHttpTrace(sentRequest, response,
                                            received.raw, startedAt, null),
                             wantsTrace));
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
        // A refusal is an exchange like any other, and the one a reader most
        // wants the headers and the elapsed time for.
        res.json(withHttpTrace(error.response.data,
                               buildHttpTrace(sentRequest, error.response,
                                              received.raw, startedAt, null),
                               wantsTrace));
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
      // There is no response to trace, and that IS the trace: the request that
      // went out, the reason nothing came back, and how long it took to fail
      // — which is the number that tells a timeout apart from a refused
      // connection.
      res.status(STATUS_500).json(withHttpTrace({
        error: 'The outbound call failed: ' +
               (error && error.message ? error.message : String(error)) },
        buildHttpTrace(sentRequest, null, null, startedAt,
                       (error && error.message) ? error.message :
                           String(error)),
        wantsTrace));
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
 */
app.post('/introspection', model.route('oauthIntrospection'), (req, res) => {
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
 */
app.post('/revoke', model.route('oauthRevoke'), (req, res) => {
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
    var sslValidate = verifiesCertificates(body.sslValidate);
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
 * @property {boolean} http_trace - Also return the HTTP exchange with the token endpoint, for display
 */

/**
 * Wrapper around the OAuth2 Token Endpoint for Token Exchange (RFC 8693)
 */
app.post('/tokenexchange', model.route('oauthTokenExchange'), (req, res) => {
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
    var sslValidate = verifiesCertificates(body.sslValidate);
    // The HTTP trace this call is to be shown with, if the caller asked for
    // one. Opt-in per call, exactly as POST /token's is and for the same
    // reason: the trace repeats the request verbatim, Authorization header
    // and all. See buildHttpTrace().
    const wantsTrace = body.http_trace === true || body.http_trace === 'true';
    // Filled in by the transform below, on the way past axios's JSON parse.
    // Per call, so two exchanges in flight cannot see each other's bodies.
    var received = {
      raw: null };
    const sentHeaders = withUserAgent(headers);
    const sentRequest = {
      method: 'POST',
      url: tokenEndpoint,
      // What actually goes out, including the User-Agent this service adds
      // and the Authorization header it may have built.
      headers: sentHeaders,
      body: parameterString };
    const startedAt = Date.now();
    log.debug("Making Token Exchange call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: sentHeaders,
      data: parameterString,
      timeout: CALL_TIMEOUT,
      maxContentLength: MAX_CONTENT_LENGTH,
      maxRedirects: MAX_REDIRECTS,
      transformResponse: [captureRawBody(received)],
      httpAgent: outboundHttpAgent(),
      httpsAgent: outboundHttpsAgent(sslValidate)
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint (token exchange): ' +
                JSON.stringify(response.data));
      res.status(response.status);
      res.json(withHttpTrace(response.data,
                             buildHttpTrace(sentRequest, response,
                                            received.raw, startedAt, null),
                             wantsTrace));
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
        // A refusal is an exchange like any other, and RFC 8693 section 2.2.2
        // makes it the one most worth reading: an exchange is refused for
        // what the SUBJECT token is, and the reason is in the body.
        res.json(withHttpTrace(error.response.data,
                               buildHttpTrace(sentRequest, error.response,
                                              received.raw, startedAt, null),
                               wantsTrace));
      } else {
        // No response at all: a timeout, a refused connection, a body past
        // maxContentLength, a blocked address. There is nothing to trace and
        // that IS the trace — the request that went out, why nothing came
        // back, and how long it took to fail.
        res.status(STATUS_500);
        res.json(withHttpTrace({
          error: error.message },
          buildHttpTrace(sentRequest, null, null, startedAt,
                         (error && error.message) ? error.message :
                             String(error)),
          wantsTrace));
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
 */
app.post('/deviceauthorization', model.route('oauthDeviceAuthorization'),
         (req, res) => {
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
    var sslValidate = verifiesCertificates(body.sslValidate);
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
 */
app.post('/register', model.route('oauthRegister'), (req, res) => {
  try {
    log.info('Entering app.post for /register.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    // Normalize the HTTP method; create=POST, read=GET, update=PUT,
    // delete=DELETE.
    var method = (body.method || 'POST').toLowerCase();
    var url = body.url;
    var bearerToken = body.bearer_token;
    var sslValidate = verifiesCertificates(body.sslValidate);
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

app.post('/userinfo', model.route('oauthUserInfoPost'), (req, res) => {
  log.info('Entering app.post for /userinfo.');
  userinfo_common(req, res);
  log.debug("Leaving app.post for /userinfo.");
});

/**
 * Wrapper around OIDC UserInfo Endpoint
 */
app.get('/userinfo', model.route('oauthUserInfo'), (req, res) => {
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
      // THE CONTENT TYPE IS CARRIED THROUGH, AND THAT IS THE WHOLE POINT.
      //
      // OIDC Core section 5.3.2 lets a UserInfo Response be a JWT — signed,
      // encrypted, or signed then encrypted — and then the content type is
      // `application/jwt` and the body is a compact serialization, not JSON.
      // This used to answer `res.json(response.data)` unconditionally, which
      // turned that JWT into a JSON *string*: the browser was handed
      // `"eyJhbGciOi..."` under `application/json`, quotes and all, so the page
      // could not tell an encrypted response from an OP that had returned a
      // quoted string, and the signature over the real octets was gone.
      //
      // Anything that is not JSON is therefore relayed VERBATIM under the type
      // the OP gave it. A JWT is a signature over exact bytes, so re-encoding
      // one in transit destroys the only thing it is for.
      var upstreamType = (response.headers &&
          (response.headers['content-type'] ||
           response.headers['Content-Type'])) || '';
      if (upstreamType && upstreamType.indexOf('json') === -1) {
        res.type(upstreamType);
        res.send(typeof response.data === 'string' ? response.data
                                                   : String(response.data));
        return;
      }
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

// ---------------------------------------------------------------------------
// THE API DOCUMENT, SERVED. common/model/openapi.json is generated from
// models/api/ (models/CLAUDE.md) and is the same document every route's
// validator is built from, so what a caller reads here is what a request
// meets. It replaced express-swagger-generator's Swagger 2.0, which was
// built from JSDoc comments that nothing held to the code.
//
// Its version is this build's, and its server is where this api is reached:
// embedded behind the mock STS that is the debugger's public origin under
// `/api` (taken from uiUrl, which api/env/embedded.js derives from
// DEBUGGER_UI_URL, rather than from a request: the document is built once).
// ---------------------------------------------------------------------------
const API_DOCUMENT = model.document(APP_VERSION,
  (LISTEN_SOCKET && uiUrl) ? uiUrl.replace(/\/+$/, '') + '/api' :
    (appconfig.apiUrl || null));

function escapeHtml(text) {
  log.debug("Entering escapeHtml().");
  log.debug("Leaving escapeHtml().");
  return String(text).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
             "'": '&#39;' }[c];
  });
}

// A page listing every operation, written from the document. Self-contained
// on purpose — no script, no stylesheet from anywhere — for a reader who
// wants the list rather than the explorer.
function apiDocumentIndex(doc) {
  log.debug("Entering apiDocumentIndex().");
  const rows = [];
  Object.keys(doc.paths || {}).sort().forEach(function (route) {
    Object.keys(doc.paths[route]).forEach(function (method) {
      const op = doc.paths[route][method];
      if (!op || !op.operationId) {
        return;
      }
      rows.push('<tr><td>' + escapeHtml((op.tags || [''])[0]) + '</td><td>' +
        '<code>' + escapeHtml(method.toUpperCase()) + ' ' +
        escapeHtml(route) + '</code></td><td><code>' +
        escapeHtml(op.operationId) + '</code></td><td>' +
        escapeHtml(op.description || op.summary || '') + '</td></tr>');
    });
  });
  log.debug("Leaving apiDocumentIndex(). " + rows.length);
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + escapeHtml(doc.info.title) + '</title><style>' +
    'body{font:14px/1.45 system-ui,sans-serif;margin:16px;color:#1b1b1b;' +
    'background:#fff}table{border-collapse:collapse;width:100%}' +
    'td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;' +
    'vertical-align:top}code{font-size:13px}' +
    '@media (prefers-color-scheme: dark){body{background:#151515;' +
    'color:#e8e8e8}td,th{border-color:#333}}</style></head><body>' +
    '<h1>' + escapeHtml(doc.info.title) + ' <small>' +
    escapeHtml(doc.info.version) + '</small></h1><p>The OpenAPI 3.1 ' +
    'document is <a href="../api-docs.json">api-docs.json</a>, and the ' +
    '<a href="../api-docs">explorer</a> can try it. Every route ' +
    'below is validated against it.</p><table><thead><tr><th>Family</th>' +
    '<th>Operation</th><th>operationId</th><th>What it does</th></tr>' +
    '</thead><tbody>' + rows.join('') + '</tbody></table></body></html>';
}

/**
 * The API document, OpenAPI 3.1.
 */
app.get('/api-docs.json', model.route('apiDocument'), function (req, res) {
  log.debug("Entering GET /api-docs.json.");
  log.debug("Leaving GET /api-docs.json.");
  return res.status(STATUS_200).json(API_DOCUMENT);
});

/**
 * Every operation in the API document, as a page with no script at all.
 */
app.get('/api-docs/operations', model.route('apiOperations'),
        function (req, res) {
  log.debug("Entering GET /api-docs/operations.");
  log.debug("Leaving GET /api-docs/operations.");
  return res.status(STATUS_200).type('html')
    .send(apiDocumentIndex(API_DOCUMENT));
});

// THE EXPLORER. Swagger UI, from swagger-ui-dist, served from this api's own
// node_modules rather than a CDN, so a page that shows a caller what this
// service accepts does not also send that caller to somebody else's server.
// swagger-ui-dist depends on @scarf/scarf, an install-time analytics hook;
// api/package.json sets scarfSettings.enabled false, which scarf honours,
// and api/Dockerfile sets SCARF_ANALYTICS=false as well. Every path below is
// RELATIVE, so the page works embedded behind the mock STS under /api.
const SWAGGER_UI_DIR = require('swagger-ui-dist').absolutePath();
app.use('/api-docs/assets', express.static(SWAGGER_UI_DIR, {
  index: false, fallthrough: false }));

const API_DOCS_PAGE = '<!doctype html><html lang="en"><head>' +
  '<meta charset="utf-8"><meta name="viewport" ' +
  'content="width=device-width, initial-scale=1">' +
  '<title>id-proto-debugger API</title>' +
  '<link rel="stylesheet" href="api-docs/assets/swagger-ui.css">' +
  '</head><body><div id="swagger-ui"></div>' +
  '<script src="api-docs/assets/swagger-ui-bundle.js"></script>' +
  '<script src="api-docs/init.js"></script></body></html>';

// JavaScript in a string, served to the browser: not this file's control
// flow, so the logging convention does not reach inside it.
const API_DOCS_INIT = 'window.addEventListener("load", function () {' +
  ' window.ui = SwaggerUIBundle({ url: "api-docs.json",' +
  ' dom_id: "#swagger-ui", deepLinking: true }); });\n';

/**
 * The API document in Swagger UI, which can also try an operation.
 */
app.get('/api-docs', model.route('apiDocumentIndex'), function (req, res) {
  log.debug("Entering GET /api-docs.");
  log.debug("Leaving GET /api-docs.");
  return res.status(STATUS_200).type('html').send(API_DOCS_PAGE);
});

/**
 * The explorer's initializer: where the document is and where to draw it.
 */
app.get('/api-docs/init.js', model.route('apiDocumentInit'),
        function (req, res) {
  log.debug("Entering GET /api-docs/init.js.");
  log.debug("Leaving GET /api-docs/init.js.");
  return res.status(STATUS_200).type('application/javascript')
    .send(API_DOCS_INIT);
});

/**
 * Relay a Kerberos v5 message to a KDC and return its reply.
 */
app.post('/krb5/kdc', model.route('krb5Kdc'), function (req, res) {
  log.debug('Entering POST /krb5/kdc.');
  var b = req.body || {};
  var host = b.host;
  var port = (b.port === undefined || b.port === null || b.port === '') ? 88 : b.port;
  var transport = b.transport || 'tcp';
  // host and message — present, non-empty strings — were held to
  // models/api/krb5.tsp by model.route() before this ran, with the sentence
  // this handler used to answer. What is left is about values.

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
 */
app.post('/krb5/service', model.route('krb5Service'),
    function (req, res) {
  log.debug('Entering POST /krb5/service.');
  var b = req.body || {};
  // host and message were held to models/api/krb5.tsp by model.route(),
  // with this sentence. The port stays here: absent, null, empty AND 0 are
  // all "no port", and 0 is a value, which the schema does not judge.
  if (!b.port) {
    log.debug('Leaving POST /krb5/service. Missing port.');
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
    log.debug('Leaving POST /krb5/service. message decoded to nothing.');
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
 */
app.post('/krb5/spnego', model.route('krb5Spnego'),
    function (req, res) {
  log.debug('Entering POST /krb5/spnego.');
  var b = req.body || {};
  var url = b.url;
  var sslValidate = verifiesCertificates(b.sslValidate);
  // url's presence, as a non-empty string, was held to models/api/krb5.tsp
  // by model.route() with the sentence this handler used to answer. Its
  // scheme is a value, and stays here.
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
 */
app.get('/krb5/limits', model.route('krb5Limits'), function (req, res) {
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
// The SCIM proxy's decision half. It has no axios and no network — see the top
// of that file — so requiring it here moves nothing and it cannot join a cycle.
const scimProxy = require('./scim_proxy.js');
// Shared Signals: the outbound call's rules, and the push receiver this
// service hosts on the page's behalf. Both are decision-only — no axios and no
// express in either — which is what lets tests/api_ssf.js drive every refusal
// and every cap with no listener and no transmitter.
const ssfProxy = require('./ssf_proxy.js');
// The wallet's OpenID4VP exchanges, made from here for a Verifier that sends
// no CORS headers. See oid4vp_proxy.js.
const oid4vpProxy = require('./oid4vp_proxy.js');
const ssfReceiver = require('./ssf_receiver.js');
// The Verifier role's request_uri and response_uri, hosted on a page's
// behalf because a page is not an HTTP server. See oid4vp_verifier.js.
const oid4vpVerifier = require('./oid4vp_verifier.js');
// The other half: an SSF transmitter a receiver can discover, create its
// stream at and poll, answering for a page that signs. See #363.
const ssfTransmitter = require('./ssf_transmitter.js');
// GNAP signs in the browser. This module only decides what may be
// forwarded. The private key never arrives here. See api/gnap_proxy.js.
const gnapProxy = require('./gnap_proxy.js');
// YubiCloud verification posts a form the page already signed. The
// decision half has no axios, same as the SCIM proxy.
const otpVerify = require('./otp_verify.js');
// PC/SC is optional. Requiring this file does not load the native
// library and does not stop the process when it is absent.
const smartcardReader = require('./smartcard_reader.js');
const otpHid = require('./otp_hid.js');
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
  // The body's shape — `url` present, every member the JSON type it must
  // be — was held to models/api/ldap.tsp by model.route() before this ran.
  // What is left is about values, and those are ldap_client.js's.
  const body = req.body || {};
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
 */
app.post('/ldap/bind', model.route('ldapBind'), function (req, res) {
  log.debug('Entering POST /ldap/bind.');
  runLdapOperation('bind', ldap.bind, req, res);
  log.debug('Leaving POST /ldap/bind.');
});

/**
 * Search a directory.
 */
app.post('/ldap/search', model.route('ldapSearch'), function (req, res) {
  log.debug('Entering POST /ldap/search.');
  runLdapOperation('search', ldap.search, req, res);
  log.debug('Leaving POST /ldap/search.');
});

/**
 * Add an entry — a user, a group, a container.
 */
app.post('/ldap/add', model.route('ldapAdd'), function (req, res) {
  log.debug('Entering POST /ldap/add.');
  runLdapOperation('add', ldap.add, req, res);
  log.debug('Leaving POST /ldap/add.');
});

/**
 * Delete an entry.
 */
app.post('/ldap/delete', model.route('ldapDelete'), function (req, res) {
  log.debug('Entering POST /ldap/delete.');
  runLdapOperation('delete', ldap.del, req, res);
  log.debug('Leaving POST /ldap/delete.');
});

/**
 * Modify an entry's attributes — which is also how group membership changes.
 */
app.post('/ldap/modify', model.route('ldapModify'), function (req, res) {
  log.debug('Entering POST /ldap/modify.');
  runLdapOperation('modify', ldap.modify, req, res);
  log.debug('Leaving POST /ldap/modify.');
});

/**
 * Rename or move an entry.
 */
app.post('/ldap/modifydn', model.route('ldapModifyDn'),
         function (req, res) {
  log.debug('Entering POST /ldap/modifydn.');
  runLdapOperation('modifyDN', ldap.modifyDn, req, res);
  log.debug('Leaving POST /ldap/modifydn.');
});

/**
 * Compare an attribute value without reading the entry.
 */
app.post('/ldap/compare', model.route('ldapCompare'), function (req, res) {
  log.debug('Entering POST /ldap/compare.');
  runLdapOperation('compare', ldap.compare, req, res);
  log.debug('Leaving POST /ldap/compare.');
});

/**
 * What the LDAP client will and will not do, so the page can say so before a
 * call fails — the same reason GET /krb5/limits exists. It is also how the page
 * tells an older api from a broken one: a build without LDAP answers 404 here,
 * which is a different thing from a directory that will not answer.
 */
app.get('/ldap/limits', model.route('ldapLimits'),
        function (req, res) {
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
});

// ---------------------------------------------------------------------------
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
 */
app.post('/tls/connect', model.route('tlsConnect'), function (req, res) {
  log.debug('Entering POST /tls/connect.');
  var b = req.body || {};
  // host and port — present, host a non-empty string, port an integer or
  // non-empty text — were held to models/api/tls.tsp by model.route(), with
  // the sentence this handler used to answer. Every value check is the
  // probe's.
  tlsProbe.connect({
    host: b.host,
    port: b.port,
    servername: b.servername,
    minVersion: b.minVersion,
    maxVersion: b.maxVersion,
    ciphers: b.ciphers,
    groups: b.groups,
    sigalgs: b.sigalgs,
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
      // The last three are the name lists — groups, ciphers, signature
      // algorithms — that OpenSSL refuses before a byte is sent. They join
      // the 400s rather than the 502s because nothing was dialled: the
      // caller asked for an algorithm this api's OpenSSL does not have.
      var refusedByPolicy = ['ETLSPORTNOTALLOWED', 'EBLOCKEDADDRESS',
                             'ETLSNOHOST', 'ETLSBADPORT', 'ETLSBADVERSION',
                             'ETLSNOCLIENTKEY', 'ETLSCLIENTMATERIAL',
                             'ETLSTRUSTTOOLARGE', 'ETLSBADHTTPPATH',
                             'ETLSGROUPS', 'ETLSCIPHERS',
                             'ETLSSIGALGS'].indexOf(error.code) !== -1;
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
 */
app.get('/tls/limits', model.route('tlsLimits'), function (req, res) {
  log.debug('Entering GET /tls/limits.');
  log.debug('Leaving GET /tls/limits.');
  return res.status(STATUS_200).json(tlsProbe.limits());
});

// ---------------------------------------------------------------------------
// SCIM 2.0 (RFC 7644) — the second way the SCIM workflow can make a call.
//
// Unlike LDAP and Kerberos, this endpoint is NOT here because a browser cannot
// speak the protocol: SCIM is ordinary HTTPS with a JSON body and
// `client/public/scim.html` calls it directly by default — which is what makes
// that page work on the static deployments, where there is no api at all. It
// is here for the three things the browser path cannot do: reach a server that
// sends no CORS headers (which is essentially every real SCIM endpoint), reach
// one with a self-signed certificate, and report the exchange in full, since a
// browser withholds the headers it adds and CORS withholds most of those that
// come back.
//
// The decisions — the five methods, the framing headers it will not forward,
// the request size cap, and how an answer is read — are in `api/scim_proxy.js`
// with no axios in it, so `tests/scim_protocol.js` can drive every refusal
// without a server on the other end. This handler is the call.
//
// **THE STATUS RULE IS THE ONE `POST /ldap/*` DRAWS AND IT IS THE POINT OF THE
// ENDPOINT.** A refusal by this service is a 400; a network failure is a 502;
// and a SCIM error from the far end is a **200** carrying that status and its
// `scimType`. A 409 `uniqueness`, a 404 on an id that names nothing, a 403 from
// an access control policy and the 501 on `/Me` are the server ANSWERING, and
// they are the most interesting thing a SCIM server ever says. Collapsing them
// into a failure would make a provisioning debugger unable to show the errors
// it exists to show.
// ---------------------------------------------------------------------------
/**
 * Perform one SCIM request on the caller's behalf.
 */
app.post('/scim', model.route('scimCall'), function (req, res) {
  log.debug('Entering POST /scim.');
  var described = scimProxy.describeRequest(req.body || {}, appconfig);
  if (!described.ok) {
    log.debug('Leaving POST /scim. Refused: ' + described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  var wantsTrace = (req.body || {}).http_trace === true ||
      (req.body || {}).http_trace === 'true';
  var sink = {};
  var startedAt = Date.now();
  var sentHeaders = withUserAgent(described.headers);
  axios({
    method: described.method.toLowerCase(),
    url: described.url,
    data: described.body === null ? undefined : described.body,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [captureRawBody(sink)],
    // A 4xx from a SCIM server is an ANSWER, so it must not throw. See the
    // status rule above.
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(described.sslValidate),
    headers: sentHeaders
  })
    .then(function (response) {
      var answer = scimProxy.readResponse(response.status,
          traceHeaders(response.headers), sink.raw);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          response, sink.raw, startedAt, null);
      log.debug('Leaving POST /scim. The server answered ' + answer.status +
          (answer.scimType ? ' ' + answer.scimType : '') + '.');
      return res.status(STATUS_200).json(withHttpTrace(answer, trace,
          wantsTrace));
    })
    .catch(function (error) {
      // THE NO-RESPONSE BRANCH MUST ANSWER. There is no response here at all —
      // a refused connection, a timeout, a blocked address, a body past
      // maxContentLength — so this is a 502 and NOT a SCIM status, because
      // nothing SCIM-shaped happened.
      var message = (error && error.message) ? error.message : String(error);
      log.warn('POST /scim to ' + described.url + ' failed: ' + message);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          null, sink.raw, startedAt, message);
      log.debug('Leaving POST /scim. 502.');
      return res.status(502).json(withHttpTrace({
        error: 'The SCIM server could not be reached: ' + message,
        code: (error && error.code) || '' }, trace, wantsTrace));
    });
});

/**
 * What the SCIM proxy will and will not do, so the page can say so before a
 * call fails rather than reporting its own limits as somebody else's fault.
 * It is also how the page knows there is an api at all.
 */
app.get('/scim/limits', model.route('scimLimits'),
        function (req, res) {
  log.debug('Entering GET /scim/limits.');
  log.debug('Leaving GET /scim/limits.');
  return res.status(STATUS_200).json(scimProxy.limits(appconfig));
});

// YubiCloud OTP validation. The page signs the request. This sends it
// as Validation Protocol 2.0 says, an HTTP GET with the signed
// parameters as the query string. A verifier answer, including
// BAD_OTP, is a 200. See otp_verify.js.
app.post('/otp/verify', model.route('otpVerify'), function (req, res) {
  log.debug('Entering POST /otp/verify.');
  var described = otpVerify.describeRequest(req.body || {});
  if (!described.ok) {
    log.debug('Leaving POST /otp/verify. Refused: ' + described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  var wantsTrace = (req.body || {}).http_trace === true ||
      (req.body || {}).http_trace === 'true';
  var sink = {};
  var startedAt = Date.now();
  var sentHeaders = withUserAgent({});
  var target = described.url + '?' + described.body;
  axios({
    method: 'get',
    url: target,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [captureRawBody(sink)],
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(described.sslValidate),
    headers: sentHeaders
  })
    .then(function (response) {
      var answer = otpVerify.readResponse(response.status, sink.raw);
      var trace = buildHttpTrace({ method: 'GET', url: target,
          headers: sentHeaders, body: '' },
          response, sink.raw, startedAt, null);
      log.debug('Leaving POST /otp/verify. The verifier answered ' +
          answer.status + '.');
      return res.status(STATUS_200).json(withHttpTrace(answer, trace,
          wantsTrace));
    })
    .catch(function (error) {
      var message = (error && error.message) ? error.message : String(error);
      log.warn('POST /otp/verify to ' + described.url + ' failed: ' +
          message);
      var trace = buildHttpTrace({ method: 'GET', url: target,
          headers: sentHeaders, body: '' },
          null, sink.raw, startedAt, message);
      log.debug('Leaving POST /otp/verify. 502.');
      return res.status(502).json(withHttpTrace({
        error: 'The verifier could not be reached: ' + message,
        code: (error && error.code) || '' }, trace, wantsTrace));
    });
});

app.get('/otp/limits', model.route('otpLimits'), function (req, res) {
  log.debug('Entering GET /otp/limits.');
  log.debug('Leaving GET /otp/limits.');
  return res.status(STATUS_200).json(otpVerify.limits());
});

// A sequence of APDUs on one connection, with GET RESPONSE. The reader
// is this machine, and the relay is off unless smartcardReaderEnabled
// is true (403 otherwise). A card status word is a 200. A missing
// library, reader or card is a 502.
app.get('/smartcard/limits', model.route('smartcardLimits'),
        function (req, res) {
  log.debug('Entering GET /smartcard/limits.');
  var limits = smartcardReader.limits(appconfig);
  // HID, for OTP challenge-response: a YubiKey on USB does not answer it
  // over CCID. Reported only when the relay is on, like the rest.
  limits.hid = limits.enabled ? otpHid.availability() :
      { available: false, reason: limits.reason };
  log.debug('Leaving GET /smartcard/limits.');
  return res.status(STATUS_200).json(limits);
});

// SESSIONS: one exclusive connection across several requests, for PIV's
// management-key authentication, which the page computes from the card's
// answer. Same switch as the relay; closed with a card reset. See
// smartcard_reader.js.
app.post('/smartcard/session', model.route('smartcardSessionOpen'),
         function (req, res) {
  log.debug('Entering POST /smartcard/session.');
  if (!smartcardReader.enabled(appconfig)) {
    log.debug('Leaving POST /smartcard/session. Relay off.');
    return res.status(STATUS_403).json({
      error: smartcardReader.DISABLED_MESSAGE });
  }
  var reader = smartcardReader.checkReaderName((req.body || {}).reader);
  if (!reader.ok) {
    log.debug('Leaving POST /smartcard/session. Bad reader.');
    return res.status(STATUS_400).json({ error: reader.error });
  }
  smartcardReader.openSession(reader.reader)
    .then(function (opened) {
      return res.status(STATUS_200).json(opened);
    })
    .catch(function (error) {
      log.warn('POST /smartcard/session failed: ' + error.message);
      return res.status(502).json({ error: error.message });
    });
  log.debug('Leaving POST /smartcard/session. Opening.');
});

app.post('/smartcard/session/transmit',
         model.route('smartcardSessionTransmit'), function (req, res) {
  log.debug('Entering POST /smartcard/session/transmit.');
  if (!smartcardReader.enabled(appconfig)) {
    log.debug('Leaving POST /smartcard/session/transmit. Relay off.');
    return res.status(STATUS_403).json({
      error: smartcardReader.DISABLED_MESSAGE });
  }
  // The session id (32 lower-case hex characters) is the model's check:
  // models/api/smartcard.tsp, SessionId, answers with this route's old
  // sentence. It runs before the relay switch above.
  var body = req.body || {};
  // The same APDU checks as /smartcard/transmit, with a placeholder reader.
  var described = smartcardReader.describeTransmit(
      Object.assign({}, body, { reader: 'session' }));
  if (!described.ok) {
    log.debug('Leaving POST /smartcard/session/transmit. Refused.');
    return res.status(STATUS_400).json({ error: described.error });
  }
  smartcardReader.sessionTransmit(body.id, described.apdus,
      { getResponse: described.getResponse,
        remainingIns: described.remainingIns })
    .then(function (answer) {
      return res.status(STATUS_200).json(answer);
    })
    .catch(function (error) {
      log.warn('POST /smartcard/session/transmit failed: ' + error.message);
      return res.status(502).json({ error: error.message });
    });
  log.debug('Leaving POST /smartcard/session/transmit. Sent.');
});

app.post('/smartcard/session/close',
         model.route('smartcardSessionClose'), function (req, res) {
  log.debug('Entering POST /smartcard/session/close.');
  // The session id is the model's check (models/api/smartcard.tsp,
  // SessionId), with this route's old sentence.
  var id = (req.body || {}).id;
  smartcardReader.closeSession(id).then(function (closed) {
    return res.status(STATUS_200).json({ closed: closed });
  });
  log.debug('Leaving POST /smartcard/session/close.');
});

// OTP-slot challenge-response over HID, for a browser with no WebHID. The
// same switch as the reader relay; needs a native api (see otp_hid.js). A
// key's answer is a 200, a bad request a 400, no HID or no key a 502.
app.post('/smartcard/otp/challenge',
         model.route('smartcardOtpChallenge'), function (req, res) {
  log.debug('Entering POST /smartcard/otp/challenge.');
  if (!smartcardReader.enabled(appconfig)) {
    log.debug('Leaving POST /smartcard/otp/challenge. Relay off.');
    return res.status(STATUS_403).json({
      error: smartcardReader.DISABLED_MESSAGE });
  }
  var described = otpHid.describeChallenge(req.body || {});
  if (!described.ok) {
    log.debug('Leaving POST /smartcard/otp/challenge. Refused.');
    return res.status(STATUS_400).json({ error: described.error });
  }
  otpHid.challenge(described.slot, described.challenge,
      { variable: described.variable })
    .then(function (answer) {
      return res.status(STATUS_200).json(answer);
    })
    .catch(function (error) {
      var message = (error && error.message) ? error.message :
          String(error);
      log.warn('POST /smartcard/otp/challenge failed: ' + message);
      return res.status(502).json({ error: message });
    });
  log.debug('Leaving POST /smartcard/otp/challenge. Sent.');
});

app.get('/smartcard/readers', model.route('smartcardReaders'),
        function (req, res) {
  log.debug('Entering GET /smartcard/readers.');
  if (!smartcardReader.enabled(appconfig)) {
    log.debug('Leaving GET /smartcard/readers. Disabled.');
    return res.status(STATUS_403).json({
      error: smartcardReader.DISABLED_MESSAGE });
  }
  smartcardReader.listReaders()
    .then(function (names) {
      log.debug('Leaving GET /smartcard/readers.');
      return res.status(STATUS_200).json({ readers: names });
    })
    .catch(function (error) {
      var message = (error && error.message) ? error.message :
          String(error);
      log.warn('GET /smartcard/readers failed: ' + message);
      log.debug('Leaving GET /smartcard/readers. 502.');
      return res.status(502).json({ error: message });
    });
});

app.post('/smartcard/transmit', model.route('smartcardTransmit'),
         function (req, res) {
  log.debug('Entering POST /smartcard/transmit.');
  if (!smartcardReader.enabled(appconfig)) {
    log.debug('Leaving POST /smartcard/transmit. Disabled.');
    return res.status(STATUS_403).json({
      error: smartcardReader.DISABLED_MESSAGE });
  }
  var described = smartcardReader.describeTransmit(req.body || {});
  if (!described.ok) {
    log.debug('Leaving POST /smartcard/transmit. Refused: ' +
        described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  smartcardReader.transmit(described.reader, described.apdus,
      { getResponse: described.getResponse,
        remainingIns: described.remainingIns })
    .then(function (answer) {
      log.debug('Leaving POST /smartcard/transmit. Answered ' +
          answer.status + '.');
      return res.status(STATUS_200).json(answer);
    })
    .catch(function (error) {
      var message = (error && error.message) ? error.message :
          String(error);
      log.warn('POST /smartcard/transmit failed: ' + message);
      log.debug('Leaving POST /smartcard/transmit. 502.');
      return res.status(502).json({ error: message });
    });
});

/**
 * ---------------------------------------------------------------------------
 * SHARED SIGNALS (SSF 1.0). One call to a transmitter, on the caller's behalf.
 *
 * The SCIM proxy's shape and not the LDAP relay's: SSF's management API is
 * ordinary HTTPS with a JSON body, so `client/public/ssf.html` calls a
 * transmitter DIRECTLY by default and is on the static deployments. This
 * endpoint exists for the three things a browser cannot do — CORS, a
 * self-signed certificate, and reporting the whole exchange — and
 * `api/ssf_proxy.js` argues each.
 *
 * THE THREE OUTCOMES: a refusal by this service is a 400, a network failure is
 * a 502, and **an SSF error from the transmitter is a 200** carrying that
 * status and its RFC 8935 `{err, description}`. The third matters more here
 * than anywhere else this pattern is used: a 403 naming the scope, a 400
 * naming the member of a subject identifier RFC 9493 does not define, an
 * `invalid_audience` on a stream whose `aud` is wrong — every one of those is
 * the transmitter explaining exactly what is wrong, and it is the most useful
 * thing this workflow can put on the screen.
 * ---------------------------------------------------------------------------
 */
app.post('/ssf/call', model.route('ssfCall'), function (req, res) {
  log.debug('Entering POST /ssf/call.');
  var described = ssfProxy.describeRequest(req.body || {}, appconfig);
  if (!described.ok) {
    log.debug('Leaving POST /ssf/call. Refused: ' + described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  var wantsTrace = (req.body || {}).http_trace === true ||
      (req.body || {}).http_trace === 'true';
  var sink = {};
  var startedAt = Date.now();
  var sentHeaders = withUserAgent(described.headers);
  axios({
    method: described.method.toLowerCase(),
    url: described.url,
    data: described.body === null ? undefined : described.body,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [captureRawBody(sink)],
    // A 4xx from a transmitter is an ANSWER, so it must not throw. See the
    // status rule above.
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(described.sslValidate),
    headers: sentHeaders
  })
    .then(function (response) {
      var answer = ssfProxy.readResponse(response.status,
          traceHeaders(response.headers), sink.raw);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          response, sink.raw, startedAt, null);
      log.debug('Leaving POST /ssf/call. The transmitter answered ' +
          answer.status + (answer.err ? ' ' + answer.err : '') + '.');
      return res.status(STATUS_200).json(withHttpTrace(answer, trace,
          wantsTrace));
    })
    .catch(function (error) {
      // THE NO-RESPONSE BRANCH MUST ANSWER. There is no response here at all —
      // a refused connection, a timeout, a blocked address, a body past
      // maxContentLength — so this is a 502 and NOT an SSF status, because
      // nothing SSF-shaped happened.
      var message = (error && error.message) ? error.message : String(error);
      log.warn('POST /ssf/call to ' + described.url + ' failed: ' + message);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          null, sink.raw, startedAt, message);
      log.debug('Leaving POST /ssf/call. 502.');
      return res.status(502).json(withHttpTrace({
        error: 'The transmitter could not be reached: ' + message,
        code: (error && error.code) || '' }, trace, wantsTrace));
    });
});

/**
 * What the SSF proxy will and will not do, and whether this service will host
 * a push receiver. The page reads it to decide whether to offer the api call
 * path at all, and whether push delivery is available — a static deployment
 * gets no answer here, which is a stronger signal than a configuration flag
 * because it is the api itself saying so.
 */
app.get('/ssf/limits', model.route('ssfLimits'), function (req, res) {
  log.debug('Entering GET /ssf/limits.');
  log.debug('Leaving GET /ssf/limits.');
  return res.status(STATUS_200).json(
      Object.assign(ssfProxy.limits(appconfig,
          ssfReceiver.limits(appconfig)),
        { transmitter: ssfTransmitter.limits(appconfig) }));
});

/**
 * One OpenID4VP exchange made on the WALLET's behalf: the Request Object
 * fetched from request_uri (GET, or POST under request_uri_method=post), or
 * the answer posted to response_uri. For a Verifier that sends no CORS
 * headers, which a browser-based wallet cannot otherwise use at all. See
 * api/oid4vp_proxy.js and api/CLAUDE.md, OpenID4VP.
 * @route POST /oid4vp/call
 * @param {object} request.body - url, method, headers, body (a string),
 *     sslValidate
 * @returns {object} 200 - the Verifier's answer, whatever its status
 * @returns {object} 400 - this service refused to send it
 * @returns {object} 502 - the Verifier could not be reached
 */
app.post('/oid4vp/call', model.route('oid4vpCall'), function (req, res) {
  log.debug('Entering POST /oid4vp/call.');
  var described = oid4vpProxy.describeRequest(req.body || {}, appconfig);
  if (!described.ok) {
    log.debug('Leaving POST /oid4vp/call. Refused: ' + described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  var wantsTrace = (req.body || {}).http_trace === true ||
      (req.body || {}).http_trace === 'true';
  var sink = {};
  var startedAt = Date.now();
  var sentHeaders = withUserAgent(described.headers);
  // Under responseEncoding "base64" the body is read as BYTES (a status
  // list may be a binary CWT), kept in sink.bytes, and its UTF-8 reading
  // goes to the trace (#470, B3).
  var binary = described.responseEncoding === 'base64';
  axios({
    method: described.method.toLowerCase(),
    url: described.url,
    data: described.body === null ? undefined : described.body,
    responseType: binary ? 'arraybuffer' : 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [binary ? captureRawBytes(sink) :
                        captureRawBody(sink)],
    // A Verifier's 400 is its ANSWER (invalid_request naming the check that
    // failed), so it must not throw.
    validateStatus: function () {
      return true;
    },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(described.sslValidate),
    headers: sentHeaders
  })
    .then(function (response) {
      var answer = oid4vpProxy.readResponse(response.status,
          traceHeaders(response.headers), binary ? sink.bytes : sink.raw,
          described.responseEncoding);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          response, sink.raw, startedAt, null);
      log.debug('Leaving POST /oid4vp/call. The Verifier answered ' +
          answer.status + '.');
      return res.status(STATUS_200).json(withHttpTrace(answer, trace,
          wantsTrace));
    })
    .catch(function (error) {
      // THE NO-RESPONSE BRANCH MUST ANSWER. A refusal by the address policy
      // (the SSRF guard, on the first URL or on a redirect hop) or the scheme
      // check is the caller asking for something this service will not do:
      // a 400, as POST /krb5/spnego answers it. Anything else (a refused
      // connection, a timeout, a body past maxContentLength) is the far end:
      // a 502, because nothing the Verifier said is involved.
      var message = (error && error.message) ? error.message : String(error);
      var blocked = error && (error.code === 'EBLOCKEDADDRESS' ||
                              error.code === 'EPROTOCOLNOTALLOWED');
      var status = blocked ? STATUS_400 : 502;
      log.warn('POST /oid4vp/call to ' + described.url + ' failed [' +
               (error && error.code) + ']: ' + message);
      var trace = buildHttpTrace({ method: described.method,
          url: described.url, headers: sentHeaders,
          body: described.body === null ? '' : described.body },
          null, sink.raw, startedAt, message);
      log.debug('Leaving POST /oid4vp/call. status=' + status);
      return res.status(status).json(withHttpTrace({
        error: blocked ? message :
          'The Verifier could not be reached: ' + message,
        code: (error && error.code) || '' }, trace, wantsTrace));
    });
});

/**
 * What POST /oid4vp/call will and will not do. The presentation pages read it
 * to decide whether to offer the api route at all.
 * @route GET /oid4vp/limits
 * @returns {object} 200 - the methods, refused headers, cap and status rule
 */
app.get('/oid4vp/limits', model.route('oid4vpLimits'),
    function (req, res) {
  log.debug('Entering GET /oid4vp/limits.');
  log.debug('Leaving GET /oid4vp/limits.');
  return res.status(STATUS_200).json(oid4vpProxy.limits(appconfig));
});

/**
 * One signed GNAP request, forwarded as the page built it.
 *
 * The proof covers the URL and the body. This handler sends that URL
 * and that body string. A GNAP error is a 200 carrying the status,
 * because the error code is the thing the page is here to show. A
 * refusal by this service is a 400. A network failure is a 502.
 */
/**
 * The https agent for one mtls-proved GNAP call. It is the guard's
 * agent, so the address policy is the shared one, with the connect
 * deadline every other outbound agent has.
 * @param {object} described - gnapProxy.describeRequest()'s answer
 * @returns {https.Agent} an agent to destroy after the call
 */
function gnapClientCertificateAgent(described) {
  log.debug('Entering gnapClientCertificateAgent().');
  var agent = connectTimeout.withConnectTimeout(
      guard.createAgent('https', {
        keepAlive: false,
        timeout: OUTBOUND_IDLE_SOCKET_TIMEOUT,
        rejectUnauthorized: described.sslValidate !== false,
        cert: described.clientCertificatePem,
        key: described.clientKeyPem
      }), CONNECTION_TIMEOUT, log);
  log.debug('Leaving gnapClientCertificateAgent().');
  return agent;
}

app.post('/gnap/call', model.route('gnapCall'), function (req, res) {
  log.debug('Entering POST /gnap/call.');
  var described = gnapProxy.describeRequest(req.body || {}, appconfig);
  if (!described.ok) {
    log.debug('Leaving POST /gnap/call. Refused: ' + described.error);
    return res.status(STATUS_400).json({ error: described.error });
  }
  var sink = {};
  var sentHeaders = withUserAgent(described.headers);
  // THE mtls PROOF: an agent of its own, made by the same guard and the
  // same connect deadline as the shared ones, never cached (it holds the
  // caller's private key) and never kept alive, and destroyed below.
  var clientAgent = described.clientCertificatePem
    ? gnapClientCertificateAgent(described) : null;
  // http_trace asks for this service's own account of the call — the
  // request as it left here and the raw answer — for the page's HTTP tab,
  // exactly as POST /token does. It is attached as http_exchange.
  var wantsTrace = (req.body || {}).http_trace === true ||
      (req.body || {}).http_trace === 'true';
  var startedAt = Date.now();
  var sentRequest = { method: described.method, url: described.url,
      headers: sentHeaders,
      body: described.body === null ? '' : described.body };
  axios({
    method: described.method.toLowerCase(),
    url: described.url,
    data: described.body === null ? undefined : described.body,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    // The body is the string the page signed. Leave it alone.
    transformRequest: [function (data) {
      return data;
    }],
    transformResponse: [captureRawBody(sink)],
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: clientAgent ||
        outboundHttpsAgent(described.sslValidate),
    headers: sentHeaders
  })
    .finally(function () {
      if (clientAgent) {
        clientAgent.destroy();
      }
    })
    .then(function (response) {
      var answer = gnapProxy.readResponse(response.status,
          traceHeaders(response.headers), sink.raw);
      var trace = buildHttpTrace(sentRequest, response, sink.raw, startedAt,
          null);
      log.debug('Leaving POST /gnap/call. Answered ' + answer.status +
          (answer.error ? ' ' + answer.error : '') + '.');
      return res.status(STATUS_200).json(withHttpTrace(answer, trace,
          wantsTrace));
    })
    .catch(function (error) {
      var message = (error && error.message) ? error.message
          : String(error);
      log.warn('POST /gnap/call to ' + described.url + ' failed: ' +
          message);
      var failed = buildHttpTrace(sentRequest, null, sink.raw, startedAt,
          message);
      log.debug('Leaving POST /gnap/call. 502.');
      return res.status(502).json(withHttpTrace({
        error: 'The authorization server could not be reached: ' +
            message,
        code: (error && error.code) || ''
      }, failed, wantsTrace));
    });
});

/**
 * What the GNAP relay will forward. A static deployment gets no answer
 * here, and the page then calls the authorization server itself.
 */
app.get('/gnap/limits', model.route('gnapLimits'),
        function (req, res) {
  log.debug('Entering GET /gnap/limits.');
  log.debug('Leaving GET /gnap/limits.');
  return res.status(STATUS_200).json(gnapProxy.limits(appconfig));
});

/**
 * ---------------------------------------------------------------------------
 * THE PUSH RECEIVER. A browser cannot be an HTTP server, so it cannot be the
 * far end of RFC 8935 push delivery — which is a property of the specification
 * rather than of this service. These four routes are this api standing in.
 *
 * `api/ssf_receiver.js` holds every decision and every bound; these handlers
 * are wiring. The one thing worth knowing at this layer is that
 * `POST /ssf/receiver/:id` ACCEPTS DATA from somebody else's transmitter. An
 * inbox created with an `authorization` requires exactly that Authorization
 * header on every push (401 `authentication_failed` otherwise); one created
 * without is open, bounded only structurally (an unguessable id, two
 * expiries, the caps and a configuration switch). The caller's address is
 * what `ssfReceiverMaxInboxesPerCaller` counts.
 * ---------------------------------------------------------------------------
 */
app.post('/ssf/receiver', model.route('ssfReceiverCreate'),
        function (req, res) {
  log.debug('Entering POST /ssf/receiver.');
  var made = ssfReceiver.create(appconfig, req.body || {}, req.ip);
  if (!made.ok) {
    log.debug('Leaving POST /ssf/receiver. Refused: ' + made.error);
    return res.status(STATUS_400).json({ error: made.error });
  }
  // The URL a TRANSMITTER has to be able to reach, which is this service's own
  // address as the caller reached it — not a configured one. A page on
  // localhost and a page on a compose network see different hosts for the same
  // api, and a stream created with the wrong one delivers nothing with no
  // error anybody sees until the first push. Behind the mock STS's embedding
  // proxy that address carries the `/api` the proxy stripped — see
  // publicBaseUrl().
  var base = publicBaseUrl(req);
  log.debug('Leaving POST /ssf/receiver. ' + made.id);
  return res.status(STATUS_200).json({
    ok: true,
    inbox: made.inbox,
    deliveryEndpoint: base + '/ssf/receiver/' + made.id,
    note: 'Put deliveryEndpoint in the stream\'s delivery.endpoint_url. The ' +
        'TRANSMITTER has to be able to reach it, which is why it is this ' +
        'api\'s address as you reached it rather than a configured one.',
    authentication: made.inbox.authenticated
      ? 'Every push must carry the authorization_header this inbox was ' +
        'created with, or it is answered 401 authentication_failed.'
      : 'OPEN: this inbox was created with no authorization_header, so ' +
        'anybody who has its URL can push to it.'
  });
});

/**
 * A Security Event Token arrives. The answer here goes back to the
 * TRANSMITTER, so it is RFC 8935's: 202 with an empty body on success, 400
 * with `{err, description}` on a refusal.
 */
app.post('/ssf/receiver/:id', model.route('ssfReceiverPush'),
        function (req, res) {
  log.debug('Entering POST /ssf/receiver/:id.');
  var answer = ssfReceiver.deliver(appconfig, req.params.id, {
    body: req.body,
    contentType: req.get('content-type') || '',
    authorization: req.get('authorization') || ''
  });
  if (answer.ok) {
    // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says. A
    // document here would be something a transmitter could come to depend on
    // that no receiver has to send.
    log.debug('Leaving POST /ssf/receiver/:id. Accepted.');
    return res.status(202).end();
  }
  log.debug('Leaving POST /ssf/receiver/:id. ' + answer.status + ' ' +
      answer.err);
  if (answer.status === 401) {
    // RFC 7235: a 401 names the scheme it wants. What the receiver chose is
    // opaque to it, so the challenge is the generic one.
    res.set('WWW-Authenticate', 'Bearer realm="ssf-receiver"');
  }
  return res.status(answer.status).json({ err: answer.err,
    description: answer.description });
});

/**
 * What has arrived. `after` is a CURSOR and not a destructive read: the page
 * keeps its own history and a drain that emptied the inbox would make a second
 * tab useless.
 */
app.get('/ssf/receiver/:id/events', model.route('ssfReceiverEvents'),
        function (req, res) {
  log.debug('Entering GET /ssf/receiver/:id/events.');
  var out = ssfReceiver.drain(appconfig, req.params.id, req.query.after);
  if (!out.ok) {
    log.debug('Leaving GET /ssf/receiver/:id/events. ' + out.error);
    return res.status(404).json({ error: out.error });
  }
  log.debug('Leaving GET /ssf/receiver/:id/events. ' + out.events.length +
      ' new.');
  return res.status(STATUS_200).json(out);
});

/**
 * Empty an inbox (POST with `action=clear`) or delete it outright.
 */
app.delete('/ssf/receiver/:id', model.route('ssfReceiverDelete'),
        function (req, res) {
  log.debug('Entering DELETE /ssf/receiver/:id.');
  var clearOnly = String(req.query.clear || '') === 'true';
  if (clearOnly) {
    var cleared = ssfReceiver.clear(appconfig, req.params.id);
    if (!cleared.ok) {
      log.debug('Leaving DELETE /ssf/receiver/:id. ' + cleared.error);
      return res.status(404).json({ error: cleared.error });
    }
    log.debug('Leaving DELETE /ssf/receiver/:id. Cleared.');
    return res.status(STATUS_200).json(cleared);
  }
  var gone = ssfReceiver.remove(appconfig, req.params.id);
  if (!gone) {
    log.debug('Leaving DELETE /ssf/receiver/:id. No such receiver.');
    return res.status(404).json({ error: 'There is no receiver with that id ' +
        'here. Either it was never created, it has been deleted, or it ' +
        'expired (ssfReceiverTtlMs).' });
  }
  log.debug('Leaving DELETE /ssf/receiver/:id. Deleted.');
  return res.status(STATUS_200).json({ ok: true, deleted: req.params.id });
});

/**
 * ---------------------------------------------------------------------------
 * THE VERIFIER ROLE'S request_uri AND response_uri (issue #364). When the VC
 * Presentation workflow plays the Verifier, OpenID4VP 1.0 needs a URL the
 * Wallet fetches the Request Object from and a URL it posts its answer to,
 * and a page can be neither — the SSF push receiver's reason exactly.
 *
 * `api/oid4vp_verifier.js` holds every decision and every bound; these
 * handlers are wiring. Six routes are the PAGE's (limits, create, and four
 * that carry `Authorization: Bearer <secret>`: publish, the live-signing
 * publish, events, delete), and three are a WALLET's (the
 * Request Object by GET or POST, the CA certificate, the answer), which
 * present no credential and are bounded structurally. The page signs the
 * Request Object; this service only stores and serves it, and verifies
 * nothing a Wallet sends.
 *
 * The limits route is registered first, so that `limits` is never read as
 * a session id by a route added later under /oid4vp/verifier/:id.
 * ---------------------------------------------------------------------------
 */
app.get('/oid4vp/verifier/limits', model.route('oid4vpVerifierLimits'),
        function (req, res) {
  log.debug('Entering GET /oid4vp/verifier/limits.');
  log.debug('Leaving GET /oid4vp/verifier/limits.');
  return res.status(STATUS_200).json(oid4vpVerifier.limits(appconfig));
});

app.post('/oid4vp/verifier', model.route('oid4vpVerifierCreate'),
        function (req, res) {
  log.debug('Entering POST /oid4vp/verifier.');
  var made = oid4vpVerifier.create(appconfig, req.body || {}, req.ip);
  if (!made.ok) {
    log.debug('Leaving POST /oid4vp/verifier. Refused: ' + made.error);
    return res.status(made.status).json({ error: made.error });
  }
  // The page's publicBaseUrl, else oid4vpVerifierPublicBaseUrl, else this
  // api's address AS THE CALLER REACHED IT, for the SSF receiver's reason:
  // the Wallet has to reach these URLs, and behind the embedding proxy they
  // carry the prefix it stripped. See publicBaseUrl() and, for why the
  // first two exist, publicBase() in oid4vp_verifier.js (#470, B5).
  var urls = oid4vpVerifier.urlsFor(oid4vpVerifier.publicBase(appconfig,
      made.publicBaseUrl, publicBaseUrl(req)), made.id);
  log.debug('Leaving POST /oid4vp/verifier. ' + made.id);
  return res.status(201).json({
    id: made.id,
    secret: made.secret,
    requestUri: urls.requestUri,
    responseUri: urls.responseUri,
    caIssuersUrl: urls.caIssuersUrl,
    liveSigning: made.liveSigning,
    expiresAt: made.expiresAt
  });
});

/**
 * Send a page-facing refusal: `{ error }`, with RFC 6750's challenge on a
 * 401.
 *
 * @param {object} res - the Express response.
 * @param {object} out - the module's `{ status, error }`.
 * @returns {object} the response.
 */
function oid4vpVerifierRefusal(res, out) {
  log.debug('Entering oid4vpVerifierRefusal(). ' + out.status);
  if (out.status === STATUS_401) {
    res.set('WWW-Authenticate', 'Bearer realm="oid4vp-verifier"');
  }
  log.debug('Leaving oid4vpVerifierRefusal().');
  return res.status(out.status).json({ error: out.error });
}

app.put('/oid4vp/verifier/:id/request',
        model.route('oid4vpVerifierPublish'), function (req, res) {
  log.debug('Entering PUT /oid4vp/verifier/:id/request.');
  var out = oid4vpVerifier.publish(appconfig, req.params.id,
    req.get('authorization') || '', req.body || {});
  if (!out.ok) {
    log.debug('Leaving PUT /oid4vp/verifier/:id/request. ' + out.status);
    return oid4vpVerifierRefusal(res, out);
  }
  log.debug('Leaving PUT /oid4vp/verifier/:id/request. Published.');
  return res.status(STATUS_200).json({ ok: true });
});

/**
 * LIVE SIGNING: the page answers one held Wallet POST (section 5.10) with
 * the Request Object it signed for that Wallet's wallet_nonce. See
 * waitForSigning() in api/oid4vp_verifier.js.
 */
app.put('/oid4vp/verifier/:id/request/:signingId',
        model.route('oid4vpVerifierPublishFor'), function (req, res) {
  log.debug('Entering PUT /oid4vp/verifier/:id/request/:signingId.');
  var out = oid4vpVerifier.publishFor(appconfig, req.params.id,
    req.params.signingId, req.get('authorization') || '', req.body || {});
  if (!out.ok) {
    log.debug('Leaving PUT /oid4vp/verifier/:id/request/:signingId. ' +
        out.status);
    return oid4vpVerifierRefusal(res, out);
  }
  log.debug('Leaving PUT /oid4vp/verifier/:id/request/:signingId. Signed.');
  return res.status(STATUS_200).json({ ok: true });
});

/**
 * Send a Wallet the Request Object, or a Wallet-facing refusal.
 *
 * @param {object} res - the Express response.
 * @param {object} out - the module's answer.
 * @returns {object} the response, or undefined when the Wallet has gone.
 */
function oid4vpVerifierSendRequest(res, out) {
  log.debug('Entering oid4vpVerifierSendRequest(). ' + out.status);
  if (res.destroyed || res.writableEnded) {
    log.debug('Leaving oid4vpVerifierSendRequest(). The Wallet has gone.');
    return undefined;
  }
  if (!out.ok) {
    log.debug('Leaving oid4vpVerifierSendRequest(). ' + out.status);
    return res.status(out.status).json({ error: out.error,
      error_description: out.error_description });
  }
  log.debug('Leaving oid4vpVerifierSendRequest(). Served.');
  // As a Buffer, so express adds no `; charset=utf-8` to a media type
  // (RFC 9101 section 10.2) that a Wallet may compare exactly.
  res.set('Cache-Control', 'no-store');
  return res.status(STATUS_200).type(out.contentType)
    .send(Buffer.from(out.body, 'utf8'));
}

/**
 * The Request Object, to a Wallet: by GET (section 5.7), or by POST with
 * wallet_metadata and wallet_nonce under request_uri_method=post (section
 * 5.10). Both answer the compact JWS the page published — except a POST to
 * a session created with liveSigning, which is HELD until the page signs
 * one for it or oid4vpVerifierLiveSignWaitMs runs out.
 *
 * @param {object} req - the Express request.
 * @param {object} res - the Express response.
 * @returns {object} the response.
 */
function oid4vpVerifierServeRequest(req, res) {
  log.debug('Entering oid4vpVerifierServeRequest(). ' + req.method);
  var out = oid4vpVerifier.fetchRequest(appconfig, req.params.id, {
    method: req.method,
    contentType: req.get('content-type') || '',
    accept: req.get('accept') || '',
    rawBody: req.oid4vpRawBody,
    parsed: req.body,
    remoteAddress: req.ip
  });
  if (out.pending) {
    // `close` on the RESPONSE, not the request: since Node 16 a request's
    // `close` fires once its body is read, which here is immediately.
    res.on('close', function () {
      if (!res.writableFinished) {
        out.cancel();
      }
    });
    out.pending.then(function (answer) {
      oid4vpVerifierSendRequest(res, answer);
    });
    log.debug('Leaving oid4vpVerifierServeRequest(). Held: ' +
        out.signingId);
    return undefined;
  }
  log.debug('Leaving oid4vpVerifierServeRequest().');
  return oid4vpVerifierSendRequest(res, out);
}

app.get('/oid4vp/verifier/:id/request',
        model.route('oid4vpVerifierRequestGet'), oid4vpVerifierServeRequest);
app.post('/oid4vp/verifier/:id/request',
         model.route('oid4vpVerifierRequestPost'),
         oid4vpVerifierServeRequest);

app.get('/oid4vp/verifier/:id/ca', model.route('oid4vpVerifierCa'),
        function (req, res) {
  log.debug('Entering GET /oid4vp/verifier/:id/ca.');
  var out = oid4vpVerifier.fetchCa(appconfig, req.params.id, req.ip);
  if (!out.ok) {
    log.debug('Leaving GET /oid4vp/verifier/:id/ca. ' + out.status);
    return res.status(out.status).json({ error: out.error,
      error_description: out.error_description });
  }
  log.debug('Leaving GET /oid4vp/verifier/:id/ca. Served.');
  return res.status(STATUS_200).type(out.contentType).send(out.body);
});

/**
 * A Wallet's answer (direct_post or direct_post.jwt, section 8.2). Every
 * field is kept as it arrived; the answer is 200 with `{}` or `{
 * redirect_uri }`, and a session that does not exist is a 404, so a Wallet
 * is never told an answer was received that nobody will read.
 */
app.post('/oid4vp/verifier/:id/response',
         model.route('oid4vpVerifierResponse'), function (req, res) {
  log.debug('Entering POST /oid4vp/verifier/:id/response.');
  var out = oid4vpVerifier.respond(appconfig, req.params.id, {
    contentType: req.get('content-type') || '',
    rawBody: req.oid4vpRawBody,
    parsed: req.body,
    remoteAddress: req.ip
  });
  if (!out.ok) {
    log.debug('Leaving POST /oid4vp/verifier/:id/response. ' + out.status);
    return res.status(out.status).json({ error: out.error,
      error_description: out.error_description });
  }
  log.debug('Leaving POST /oid4vp/verifier/:id/response. Recorded.');
  // Section 8.2: a Verifier's answer to the Wallet is never cached.
  res.set('Cache-Control', 'no-store');
  return res.status(STATUS_200).json(out.body);
});

app.get('/oid4vp/verifier/:id/events', model.route('oid4vpVerifierEvents'),
        function (req, res) {
  log.debug('Entering GET /oid4vp/verifier/:id/events.');
  var out = oid4vpVerifier.events(appconfig, req.params.id,
    req.get('authorization') || '', req.query.after);
  if (!out.ok) {
    log.debug('Leaving GET /oid4vp/verifier/:id/events. ' + out.status);
    return oid4vpVerifierRefusal(res, out);
  }
  log.debug('Leaving GET /oid4vp/verifier/:id/events. ' + out.events.length +
      ' event(s).');
  return res.status(STATUS_200).json({ events: out.events, next: out.next,
    dropped: out.dropped, expiresAt: out.expiresAt });
});

app.delete('/oid4vp/verifier/:id', model.route('oid4vpVerifierDelete'),
           function (req, res) {
  log.debug('Entering DELETE /oid4vp/verifier/:id.');
  var out = oid4vpVerifier.remove(appconfig, req.params.id,
    req.get('authorization') || '');
  if (!out.ok) {
    log.debug('Leaving DELETE /oid4vp/verifier/:id. ' + out.status);
    return oid4vpVerifierRefusal(res, out);
  }
  log.debug('Leaving DELETE /oid4vp/verifier/:id. Deleted.');
  return res.status(STATUS_200).json({ ok: true, deleted: out.deleted });
});

/**
 * ---------------------------------------------------------------------------
 * THE HOSTED TRANSMITTER (#363). The mirror of the push receiver above: a
 * receiver that treats its partner as a full SSF 1.0 transmitter discovers
 * it, creates its stream there, changes its status and subjects, asks for
 * verification and — for RFC 8936 — polls. Each of those is a request to a
 * server, which a page is not, so this service answers them on the page's
 * behalf.
 *
 * `api/ssf_transmitter.js` holds every decision and every bound; these
 * handlers are wiring, plus the one outbound call: the RFC 8935 push of a
 * SET the PAGE signed, to the endpoint the RECEIVER gave, carrying the
 * authorization_header the receiver gave. That push is an ordinary outbound
 * call and goes through the same agents, limits and User-Agent as every
 * other one.
 *
 * Two kinds of caller and two credentials. The page's four routes take the
 * owner key it was given at creation; the receiver's routes take the
 * receiver credential (RFC 6750). Discovery and the JWKS take neither,
 * because a receiver reads both before it has a stream at all.
 * ---------------------------------------------------------------------------
 */

// An RFC 8935 push of one SET. Never rejects: the outcome, which is recorded
// on the transmitter for the page, is the answer.
function pushSet(one, streamId, jti, delivery, token, sslValidate) {
  log.debug('Entering pushSet(). ' + delivery.url);
  var headers = withUserAgent({
    'Content-Type': ssfTransmitter.SET_MEDIA_TYPE,
    Accept: 'application/json'
  });
  if (delivery.authorization) {
    headers.Authorization = delivery.authorization;
  }
  var sink = {};
  log.debug('Leaving pushSet(). Sending.');
  return axios({
    method: 'post',
    url: delivery.url,
    data: token,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [captureRawBody(sink)],
    validateStatus: function () {
      return true;
    },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(sslValidate),
    headers: headers
  }).then(function (response) {
    var body = {};
    try {
      body = JSON.parse(sink.raw || '{}') || {};
    } catch (e) {
      body = {};
    }
    // RFC 8935 section 2.3: 202 is accepted. Section 2.4: a 400 carries
    // { err, description } from the SET Error Codes registry.
    var outcome = {
      status: response.status,
      accepted: response.status === 202,
      err: String(body.err || ''),
      description: String(body.description || '').slice(0, 500),
      detail: response.status === 202 ? 'accepted (202)'
        : 'answered ' + response.status +
          (body.err ? ' ' + body.err : '')
    };
    ssfTransmitter.recordPush(one, streamId, jti, outcome);
    log.debug('pushSet(): ' + outcome.detail);
    return outcome;
  }).catch(function (error) {
    var message = (error && error.message) ? error.message : String(error);
    log.warn('pushSet() to ' + delivery.url + ' failed: ' + message);
    var outcome = { status: 0, accepted: false, err: '',
      description: '', detail: 'not delivered: ' + message };
    ssfTransmitter.recordPush(one, streamId, jti, outcome);
    return outcome;
  });
}

// An SSF answer to a receiver: a JSON body, an empty one, or an error.
function sendTransmitterAnswer(res, answer) {
  log.debug('Entering sendTransmitterAnswer(). ' + answer.status);
  if (!answer.ok) {
    if (answer.status === 401) {
      res.set('WWW-Authenticate', 'Bearer realm="ssf-transmitter"');
    }
    log.debug('Leaving sendTransmitterAnswer(). Refused.');
    return res.status(answer.status).json({ err: answer.err,
      description: answer.description });
  }
  if (answer.body === null || answer.body === undefined) {
    log.debug('Leaving sendTransmitterAnswer(). Empty.');
    return res.status(answer.status).end();
  }
  log.debug('Leaving sendTransmitterAnswer().');
  return res.status(answer.status).json(answer.body);
}

// The receiver's routes all start the same way.
function receiverOf(req, res) {
  log.debug('Entering receiverOf().');
  var who = ssfTransmitter.forReceiver(appconfig, req.params.id,
                                       req.get('authorization') || '');
  if (!who.ok) {
    sendTransmitterAnswer(res, who);
    log.debug('Leaving receiverOf(). Refused.');
    return null;
  }
  log.debug('Leaving receiverOf().');
  return who.instance;
}

function ownerOf(req, res) {
  log.debug('Entering ownerOf().');
  var who = ssfTransmitter.forOwner(appconfig, req.params.id,
                                    req.get('authorization') || '');
  if (!who.ok) {
    if (who.status === 401) {
      res.set('WWW-Authenticate', 'Bearer realm="ssf-transmitter-owner"');
    }
    res.status(who.status).json({ error: who.error });
    log.debug('Leaving ownerOf(). Refused.');
    return null;
  }
  log.debug('Leaving ownerOf().');
  return who.instance;
}

app.post('/ssf/transmitter', model.route('ssfTransmitterCreate'),
        function (req, res) {
  log.debug('Entering POST /ssf/transmitter.');
  var made = ssfTransmitter.create(appconfig, req.body || {}, req.ip,
                                   publicBaseUrl(req));
  if (!made.ok) {
    log.debug('Leaving POST /ssf/transmitter. Refused: ' + made.error);
    return res.status(STATUS_400).json({ error: made.error });
  }
  log.debug('Leaving POST /ssf/transmitter. ' + made.id);
  return res.status(STATUS_200).json({
    ok: true,
    transmitter: made.transmitter,
    ownerKey: made.ownerKey,
    receiverCredential: made.receiverCredential,
    note: 'Point the receiver at the issuer; it discovers the rest at ' +
        'discoveryUrl. Give it receiverCredential as its bearer token for ' +
        'the stream management API. Keep ownerKey: it is how this page ' +
        'reads, delivers through and deletes this transmitter, and neither ' +
        'is shown again.'
  });
});

app.get('/ssf/transmitter/:id', model.route('ssfTransmitterRead'),
        function (req, res) {
  log.debug('Entering GET /ssf/transmitter/:id.');
  var one = ownerOf(req, res);
  if (!one) {
    log.debug('Leaving GET /ssf/transmitter/:id. Refused.');
    return undefined;
  }
  log.debug('Leaving GET /ssf/transmitter/:id.');
  return res.status(STATUS_200).json({ ok: true,
    transmitter: ssfTransmitter.describe(one) });
});

app.delete('/ssf/transmitter/:id', model.route('ssfTransmitterDelete'),
          function (req, res) {
  log.debug('Entering DELETE /ssf/transmitter/:id.');
  var one = ownerOf(req, res);
  if (!one) {
    log.debug('Leaving DELETE /ssf/transmitter/:id. Refused.');
    return undefined;
  }
  ssfTransmitter.remove(appconfig, one.id);
  log.debug('Leaving DELETE /ssf/transmitter/:id. Deleted.');
  return res.status(STATUS_200).json({ ok: true, deleted: one.id });
});

// The page hands over a SET it signed, for one stream. A push is made now
// and its outcome returned; a poll stream queues it.
app.post('/ssf/transmitter/:id/deliver',
        model.route('ssfTransmitterDeliver'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/deliver.');
  var one = ownerOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/deliver. Refused.');
    return undefined;
  }
  var body = req.body || {};
  var plan = ssfTransmitter.deliver(appconfig, one, body);
  if (!plan.ok) {
    log.debug('Leaving POST /ssf/transmitter/:id/deliver. ' + plan.error);
    return res.status(plan.status).json({ error: plan.error });
  }
  var answer = { ok: true, action: plan.action, jti: plan.jti,
    stream_id: plan.stream.stream_id, findings: plan.findings,
    note: plan.note };
  if (plan.action !== 'push') {
    log.debug('Leaving POST /ssf/transmitter/:id/deliver. ' + plan.action);
    return res.status(STATUS_200).json(answer);
  }
  return pushSet(one, plan.stream.stream_id, plan.jti,
    { url: plan.url, authorization: plan.authorization },
    String(body.token || '').trim(),
    verifiesCertificates(body.sslValidate)).then(function (outcome) {
    answer.push = outcome;
    log.debug('Leaving POST /ssf/transmitter/:id/deliver. Pushed: ' +
        outcome.detail);
    return res.status(STATUS_200).json(answer);
  });
});

// SSF 1.0 section 7: discovery is the well-known path followed by the
// issuer's own path, and it is public.
app.get('/.well-known/ssf-configuration/ssf/transmitter/:id',
       model.route('ssfTransmitterMetadata'), function (req, res) {
  log.debug('Entering GET /.well-known/ssf-configuration/…');
  var shown = ssfTransmitter.published(appconfig, req.params.id);
  if (!shown) {
    log.debug('Leaving GET /.well-known/ssf-configuration/…. Not found.');
    return res.status(404).json({ err: 'not_found',
      description: 'There is no transmitter with that id here.' });
  }
  log.debug('Leaving GET /.well-known/ssf-configuration/….');
  return res.status(STATUS_200).json(shown.metadata);
});

app.get('/ssf/transmitter/:id/jwks', model.route('ssfTransmitterJwks'),
       function (req, res) {
  log.debug('Entering GET /ssf/transmitter/:id/jwks.');
  var shown = ssfTransmitter.published(appconfig, req.params.id);
  if (!shown) {
    log.debug('Leaving GET /ssf/transmitter/:id/jwks. Not found.');
    return res.status(404).json({ err: 'not_found',
      description: 'There is no transmitter with that id here.' });
  }
  log.debug('Leaving GET /ssf/transmitter/:id/jwks.');
  return res.status(STATUS_200).set('Content-Type',
    'application/jwk-set+json').send(JSON.stringify(shown.jwks));
});

app.post('/ssf/transmitter/:id/stream',
        model.route('ssfTransmitterStreamCreate'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/stream.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/stream. Refused.');
    return undefined;
  }
  log.debug('Leaving POST /ssf/transmitter/:id/stream.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.createStream(appconfig, one, req.body));
});

app.get('/ssf/transmitter/:id/stream',
       model.route('ssfTransmitterStreamRead'), function (req, res) {
  log.debug('Entering GET /ssf/transmitter/:id/stream.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving GET /ssf/transmitter/:id/stream. Refused.');
    return undefined;
  }
  log.debug('Leaving GET /ssf/transmitter/:id/stream.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.readStream(one, req.query.stream_id));
});

app.patch('/ssf/transmitter/:id/stream',
         model.route('ssfTransmitterStreamUpdate'), function (req, res) {
  log.debug('Entering PATCH /ssf/transmitter/:id/stream.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving PATCH /ssf/transmitter/:id/stream. Refused.');
    return undefined;
  }
  log.debug('Leaving PATCH /ssf/transmitter/:id/stream.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.updateStream(one, req.body, false));
});

app.put('/ssf/transmitter/:id/stream',
       model.route('ssfTransmitterStreamReplace'), function (req, res) {
  log.debug('Entering PUT /ssf/transmitter/:id/stream.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving PUT /ssf/transmitter/:id/stream. Refused.');
    return undefined;
  }
  log.debug('Leaving PUT /ssf/transmitter/:id/stream.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.updateStream(one, req.body, true));
});

app.delete('/ssf/transmitter/:id/stream',
          model.route('ssfTransmitterStreamDelete'), function (req, res) {
  log.debug('Entering DELETE /ssf/transmitter/:id/stream.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving DELETE /ssf/transmitter/:id/stream. Refused.');
    return undefined;
  }
  log.debug('Leaving DELETE /ssf/transmitter/:id/stream.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.deleteStream(one, req.query.stream_id));
});

app.get('/ssf/transmitter/:id/status',
       model.route('ssfTransmitterStatusRead'), function (req, res) {
  log.debug('Entering GET /ssf/transmitter/:id/status.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving GET /ssf/transmitter/:id/status. Refused.');
    return undefined;
  }
  log.debug('Leaving GET /ssf/transmitter/:id/status.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.readStatus(one, req.query.stream_id));
});

// Enabling a paused push stream releases what it held; those pushes go out
// after the answer, in order, and their outcomes land on the page's log.
app.post('/ssf/transmitter/:id/status',
        model.route('ssfTransmitterStatusUpdate'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/status.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/status. Refused.');
    return undefined;
  }
  var answer = ssfTransmitter.updateStatus(one, req.body);
  sendTransmitterAnswer(res, answer);
  if (answer.ok && answer.release && answer.release.length) {
    var stream = answer.stream;
    answer.release.reduce(function (chain, row) {
      return chain.then(function () {
        return pushSet(one, stream.stream_id, row.jti,
          { url: stream.delivery.endpoint_url,
            authorization: stream.delivery.authorization_header },
          row.token, true);
      });
    }, Promise.resolve());
  }
  log.debug('Leaving POST /ssf/transmitter/:id/status.');
  return undefined;
});

app.post('/ssf/transmitter/:id/subjects/add',
        model.route('ssfTransmitterSubjectAdd'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/subjects/add.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/subjects/add. Refused.');
    return undefined;
  }
  log.debug('Leaving POST /ssf/transmitter/:id/subjects/add.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.changeSubject(one, req.body, true));
});

app.post('/ssf/transmitter/:id/subjects/remove',
        model.route('ssfTransmitterSubjectRemove'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/subjects/remove.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/subjects/remove. Refused.');
    return undefined;
  }
  log.debug('Leaving POST /ssf/transmitter/:id/subjects/remove.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.changeSubject(one, req.body, false));
});

app.post('/ssf/transmitter/:id/verify',
        model.route('ssfTransmitterVerify'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/verify.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/verify. Refused.');
    return undefined;
  }
  log.debug('Leaving POST /ssf/transmitter/:id/verify.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.requestVerification(one, req.body));
});

app.post('/ssf/transmitter/:id/poll/:streamId',
        model.route('ssfTransmitterPoll'), function (req, res) {
  log.debug('Entering POST /ssf/transmitter/:id/poll/:streamId.');
  var one = receiverOf(req, res);
  if (!one) {
    log.debug('Leaving POST /ssf/transmitter/:id/poll/:streamId. Refused.');
    return undefined;
  }
  log.debug('Leaving POST /ssf/transmitter/:id/poll/:streamId.');
  return sendTransmitterAnswer(res,
    ssfTransmitter.poll(one, req.params.streamId, req.body));
});

// ---------------------------------------------------------------------------
// SPIFFE — POST /spiffe/bundle, POST /spiffe/call, GET /spiffe/limits
//
// SPIFFE's server side is three surfaces and only ONE of them is HTTP, which is
// why two of these endpoints exist and the third is an ordinary fetch:
//
//   the bundle endpoint    plain HTTPS returning a JWK Set. POST /spiffe/bundle
//                          is an axios call like /token and /scim, so the SSRF
//                          guard installed once on the shared instance already
//                          covers it and nothing is re-implemented here. It is
//                          here at all for the three reasons the SCIM proxy is:
//                          a bundle endpoint sends no CORS headers, a staging
//                          one's certificate is self-signed, and only this side
//                          can report the whole exchange.
//   the Workload API       gRPC, and a browser cannot produce gRPC at all — no
//                          HTTP/2 stream, no trailers, no `grpc-status`, no
//                          client certificate. So POST /spiffe/call carries it.
//   the SPIRE Server API   gRPC over MUTUAL TLS. Same endpoint, same reason,
//                          plus a client certificate a page could never present.
//
// ONE endpoint for forty-nine methods rather than forty-nine endpoints, which
// is the opposite of the choice `POST /ldap/*` made and is deliberate. There,
// eight operations have eight different shapes and each route documents its
// own. Here every method is `(service, method, request)` over one wire format,
// the METHOD LIST IS DERIVED FROM THE PROTOS rather than typed, and a route per
// method would be forty-nine places for that list to drift from the protos it
// is supposed to mirror. `GET /spiffe/limits` publishes the catalogue, so the
// page builds its picker from what this service can actually call.
//
// THE THREE OUTCOMES, which is the rule POST /ldap/* and POST /scim already
// follow and which matters more on this surface than on either:
//
//   * a refusal by THIS service — an address it will not dial, a socket path
//     outside the allowlist, a method that is not on the surface — is a **400**;
//   * a network failure, and a server whose SPIFFE ID was not the one the
//     caller required, are **502**s;
//   * **a gRPC STATUS from the far end is a 200**, with `ok: false` and the
//     code. `PERMISSION_DENIED` on a method this caller's entity may not use,
//     `UNAUTHENTICATED` when it presented nothing, `UNIMPLEMENTED` with the
//     reason a server gives for declining, `INVALID_ARGUMENT` on a JWT-SVID
//     request with no audience — every one of those is SPIFFE ANSWERING, and
//     they are the most interesting thing this workflow shows. SPIRE goes to
//     the trouble of distinguishing "authenticate" from "you may not"; an api
//     that reported both as a failure would throw that away.
// ---------------------------------------------------------------------------
const spiffeClientModule = require('./spiffe_client.js');
const spiffeBundle = require('../common/spiffe/spiffe_bundle.js');
// The SPIFFE client reuses the guard's address DECISION for the reason the
// Kerberos relay and the LDAP client do: the guard's INSTALLATION is hooks on
// the axios agents, and gRPC opens a socket with no axios in the path.
const spiffe = spiffeClientModule.createSpiffeClient(appconfig, guard, log);

// Refusals this service made itself. Listed rather than matched on a prefix, so
// that adding a code forces a decision about which of the two outcomes it is —
// and note that ESPIFFESERVERIDENTITY is deliberately NOT here: a server that
// answered and turned out to be somebody else is a fact about the far end.
const SPIFFE_REFUSED_BY_POLICY = [
  'ESPIFFEBADADDRESS', 'ESPIFFEPORTNOTALLOWED', 'EBLOCKEDADDRESS',
  'ESPIFFESOCKETNOTALLOWED', 'ESPIFFESOCKETMISSING', 'ESPIFFENOTASOCKET',
  'ESPIFFESOCKETPATHTOOLONG', 'ESPIFFENOSERVICE', 'ESPIFFENOMETHOD',
  'ESPIFFEBADMETADATA', 'ESPIFFEBADMODE', 'ESPIFFENOSERVERID',
  'ESPIFFENOTRUSTDOMAIN', 'ESPIFFEBADTRUSTDOMAIN', 'ESPIFFENOTRUSTBUNDLE',
  'ESPIFFEBADTRUSTBUNDLE', 'ESPIFFEBADIDENTITY', 'ESPIFFEREFUSED'
];

/**
 * One call on either gRPC surface: the Workload API or the SPIRE Server API.
 */
app.post('/spiffe/call', model.route('spiffeCall'), function (req, res) {
  log.debug('Entering POST /spiffe/call.');
  const body = req.body || {};
  // address — present, a non-empty string — was held to
  // models/api/spiffe.tsp by model.route(), with the sentence this handler
  // used to answer (a unix: path is resolved on the machine running this
  // api, which is not the machine running your browser). Everything about
  // its value is spiffe_client.js's.
  const startedAt = Date.now();
  spiffe.call(body).then(function (answer) {
    answer.timing = { totalMs: Date.now() - startedAt };
    log.info('POST /spiffe/call ' + answer.serviceLabel + '.' + answer.method +
             ' ' + answer.target + ' -> ' + answer.status.name +
             ' in ' + answer.timing.totalMs + 'ms');
    log.debug('Leaving POST /spiffe/call. ok=' + answer.ok);
    // 200 even when ok is false: see the note above. The caller reads `ok` and
    // `status`, which is what SPIFFE actually told it.
    return res.status(STATUS_200).json(answer);
  }).catch(function (error) {
    // THE NO-RESPONSE BRANCH MUST ANSWER, and on this endpoint — as on the
    // Kerberos relay — it is a common branch rather than a rare one, because
    // pointing it at a server that may not be there is the point.
    const refusedByPolicy =
      SPIFFE_REFUSED_BY_POLICY.indexOf(error && error.code) !== -1;
    const status = refusedByPolicy ? STATUS_400 : 502;
    log.warn('POST /spiffe/call failed [' +
             ((error && error.code) || 'no code') + ']: ' +
             (error && error.message));
    log.debug('Leaving POST /spiffe/call. status=' + status);
    return res.status(status).json({
      error: (error && error.message) ? error.message : String(error),
      code: (error && error.code) || null,
      // True when a server answered, presented a certificate a trusted
      // authority had signed, and was somebody else. Separated from an
      // ordinary network failure because those are different facts and the
      // page shows them differently.
      identityMismatch: !!(error && error.identityMismatch),
      peer: (error && error.answer && error.answer.peer) || null,
      timing: { totalMs: Date.now() - startedAt } });
  });
});

/**
 * Fetch a SPIFFE bundle endpoint and say what is wrong with what came back.
 */
app.post('/spiffe/bundle', model.route('spiffeBundle'),
    function (req, res) {
  log.debug('Entering POST /spiffe/bundle.');
  const body = req.body || {};
  const url = String(body.url || '').trim();
  if (!/^https?:\/\//i.test(url)) {
    log.debug('Leaving POST /spiffe/bundle. Not an http(s) URL.');
    return res.status(STATUS_400).json({
      error: 'url is required and must be an http:// or https:// URL. A ' +
             'SPIFFE bundle endpoint is plain HTTPS — it is the ONE surface ' +
             'of SPIFFE that is, which is why this endpoint is an ordinary ' +
             'fetch and the other one is gRPC.' });
  }
  const startedAt = Date.now();
  const sink = {};
  const sentHeaders = withUserAgent({ Accept: 'application/json' });
  axios({
    method: 'get',
    url: url,
    responseType: 'text',
    timeout: CALL_TIMEOUT,
    maxContentLength: MAX_CONTENT_LENGTH,
    maxRedirects: MAX_REDIRECTS,
    transformResponse: [captureRawBody(sink)],
    // A 404 from a bundle endpoint is an ANSWER — usually the answer that the
    // path is wrong — so it must not throw.
    validateStatus: function () {
      return true; },
    httpAgent: outboundHttpAgent(),
    httpsAgent: outboundHttpsAgent(verifiesCertificates(body.sslValidate)),
    headers: sentHeaders
  })
    .then(function (response) {
      // The document is described whatever the status was, because a bundle
      // endpoint that answers 200 with an HTML error page from a proxy is the
      // case this report exists to name.
      const report = spiffeBundle.describe(sink.raw || '');
      log.info('POST /spiffe/bundle ' + url + ' -> ' + response.status + ', ' +
               report.keys.length + ' usable key(s), ' +
               report.errors.length + ' error(s)');
      log.debug('Leaving POST /spiffe/bundle. status=' + response.status);
      return res.status(STATUS_200).json({
        ok: response.status >= 200 && response.status < 300 && report.ok,
        url: url,
        httpStatus: response.status,
        headers: traceHeaders(response.headers),
        body: sink.raw || '',
        report: report,
        timing: { totalMs: Date.now() - startedAt } });
    })
    .catch(function (error) {
      const message = (error && error.message) ? error.message : String(error);
      log.warn('POST /spiffe/bundle ' + url + ' failed: ' + message);
      log.debug('Leaving POST /spiffe/bundle. 502.');
      return res.status(502).json({
        error: 'The bundle endpoint could not be reached: ' + message,
        code: (error && error.code) || '',
        timing: { totalMs: Date.now() - startedAt } });
    });
});

/**
 * What the SPIFFE client will and will not do, and every method it can call.
 *
 * The catalogue here is DERIVED from the vendored protos rather than typed, so
 * the page's method picker cannot drift from what this service can dial. It is
 * also how the page tells an older api from a broken one: a build without
 * SPIFFE answers 404 here, which is a different thing from a SPIRE server that
 * will not answer.
 */
app.get('/spiffe/limits', model.route('spiffeLimits'),
    function (req, res) {
  log.debug('Entering GET /spiffe/limits.');
  log.debug('Leaving GET /spiffe/limits.');
  return res.status(STATUS_200).json(spiffe.limits());
});


/**
 * The certificate this service is serving, as PEM, so that a caller can trust
 * it before it verifies anything.
 *
 * IT IS ON THE TLS PORT ITSELF, which looks circular and is the ordinary
 * bootstrap: fetching the PEM over a connection you cannot yet verify is the
 * same act as trusting the PEM it hands back, done one step earlier. The mock
 * STS publishes its own certificate at the same path for the same reason, and
 * common/common.sh's trustStsCertificate() is the client for both.
 *
 * 404 on a plain listener rather than an empty 200: "this service is not
 * serving TLS" and "this service is serving TLS and will not say with what"
 * are different answers and a caller acts differently on them.
 */
app.get('/tls/server-certificate',
    model.route('tlsServerCertificate'), function (req, res) {
  log.debug('Entering GET /tls/server-certificate.');
  var pem = tlsListener.serverCertificate();
  if (!pem) {
    log.debug('Leaving GET /tls/server-certificate. Plain listener.');
    return res.status(404).json({ error: 'This api is not serving TLS, so ' +
      'it has no certificate to publish.', code: 'ENOTLS' });
  }
  res.set('Content-Type', 'application/x-pem-file');
  log.debug('Leaving GET /tls/server-certificate.');
  return res.status(STATUS_200).send(pem);
});

const server = tlsListener.listen(app, appconfig,
    { name: 'api', port: PORT, host: HOST, socketPath: LISTEN_SOCKET });

// Whatever closes the listener, no live-signing wait outlives it.
server.on('close', function () {
  oid4vpVerifier.shutdown();
});

// When running under coverage (c8), exit cleanly on container stop so the V8
// coverage is flushed to NODE_V8_COVERAGE before the process is terminated.
if (process.env.COVERAGE === 'true') {
  ['SIGTERM', 'SIGINT'].forEach(function (signal) {
    process.on(signal, function () {
      log.info('Received ' + signal + '; exiting to flush coverage.');
      oid4vpVerifier.shutdown();
      process.exit(0);
    });
  });
} else if (LISTEN_SOCKET) {
  // EMBEDDED: the mock STS is this process's parent and decides its lifetime.
  // Node's default for SIGTERM is to die without closing the listener, which
  // leaves the socket file behind; closing first unlinks it, and the stale
  // unlink in tls_listener.js covers the SIGKILL case. The proxy holds
  // keep-alive connections open, so they are closed outright rather than
  // waited for, and a timer that does not keep the loop alive is the backstop
  // should close() still not call back.
  ['SIGTERM', 'SIGINT'].forEach(function (signal) {
    process.on(signal, function () {
      log.info('Received ' + signal + ' from the embedding service; closing ' +
               'the socket listener and exiting.');
      setTimeout(function () {
        process.exit(0);
      }, 2000).unref();
      // Release any Wallet held for live signing, so close() is not kept
      // waiting on it.
      oid4vpVerifier.shutdown();
      server.close(function () {
        process.exit(0);
      });
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
    });
  });
}

// An ORPHANED embedded api must not outlive the mock STS. A child forked with
// an IPC channel sees `disconnect` when its parent exits for any reason —
// including SIGKILL, which sends this process no signal at all — so that is
// the one event that is certain to arrive. Gated on the socket too, so a
// standalone api started under some IPC-speaking supervisor is unchanged.
if (LISTEN_SOCKET && typeof process.send === 'function') {
  process.on('disconnect', function () {
    log.info('The embedding service closed the IPC channel; exiting.');
    setTimeout(function () {
      process.exit(0);
    }, 2000).unref();
    server.close(function () {
      process.exit(0);
    });
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
  });
}
