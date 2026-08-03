'use strict';
//
// File: app.js
//
// ---------------------------------------------------------------------------
// The express application and everything that must be in place BEFORE a single
// route is registered: the security headers, the Private Network Access answer,
// CORS, the body parser and the call log.
//
// It is a module of its own, and the reason is the registration order. Each
// protocol module registers its endpoints as a side effect of being required
// (`const app = require('./app')` then `app.get(...)` at its top level), which
// keeps every handler exactly where it was written instead of wrapped in a
// register() function and re-indented. Express applies middleware in the order it
// was added and only to routes added AFTER it, so the middleware has to be
// installed by the time any protocol module is loaded — i.e. here, in the module
// they all require, rather than in server.js, which requires them.
//
// The consequence to remember when adding a module: server.js requires the
// protocol modules in a deliberate order, and that order is the route order.
// Nothing here has overlapping paths, so it does not currently matter — but a new
// module that registers a wildcard would matter a great deal.
// ---------------------------------------------------------------------------

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { log, headersOf, bodyOf } = require('./helpers');
// --- express app -----------------------------------------------------------
const app = express();

// Chrome Private Network Access: when a PUBLIC page calls a LOCAL (loopback)
// server — which is exactly the live-site test setup, an HTTPS page on
// idptools.com calling this mock at http://localhost:8081 — Chrome may send a
// CORS preflight carrying Access-Control-Request-Private-Network and require
// this header on the response. Answer it so the call isn't blocked. Registered
// BEFORE cors() so the header is set before the preflight response is sent;
// a no-op for the containerized suite (both sides on the same bridge network).
app.use(function (req, res, next) {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

// The response hardening that actually applies to this service.
//
// Almost everything here answers `application/json`, and the values in those
// responses are echoed from what a caller sent — an error_description quoting a
// bad grant_type, a client name from a registration request. Escaping that
// content is NOT the control: JSON.stringify already encodes it unambiguously,
// and running an HTML sanitizer over it would corrupt legitimate values while
// protecting nothing (a JSON string is not markup). The way such a body turns
// into script is a browser deciding to treat it as HTML anyway, so the control
// is to forbid that decision:
//
//   X-Content-Type-Options: nosniff   honour the declared Content-Type, never
//                                     sniff a JSON body as text/html
//   Content-Security-Policy           no script runs even if some response were
//                                     rendered as a document after all
//   X-Frame-Options: DENY             no framing of the login screen the
//                                     authorization endpoint serves
//
// The HTML this service does emit (the login screen, the credential-offer and
// verifier pages) builds its markup from server-side values, and where a
// caller-supplied value appears in it, it is escaped at that point with
// xmlEscape().
//
// The policy is as tight as these pages allow, and it is worth saying what each
// clause is for, because a stricter-looking one would break them:
//   script-src 'none'   they contain no <script> at all, inline or external —
//                       so this is the clause that makes the whole family of
//                       js/reflected-xss reports moot rather than merely
//                       unlikely: a JSON body rendered as a document still runs
//                       nothing.
//   style-src           six pages carry an inline <style> block, so
//                       'unsafe-inline' is required; extracting them to files
//                       would buy nothing here since no untrusted value reaches
//                       a style.
//   img-src data:       the two QR pages embed the code as a data: URI produced
//                       by the qrcode library server-side.
//
// NOT present, and it must not be added back: **form-action**. It looks obviously
// right here — the only form posts to /oauth2/login, which is same-origin — but
// Chrome enforces form-action against the whole REDIRECT CHAIN that follows a
// submission, not just its immediate target. This is an authorization server:
// signing in POSTs the login form and the response is a 302 to the client's
// redirect_uri, which is by definition another origin. `form-action 'self'`
// therefore blocks the browser from ever reaching the client, and the symptom is
// remote from the cause — the sign-in appears to succeed and the wallet simply
// never comes back. It cost a full SD-JWT VC issuance run to find, and
// tests/sd_jwt_vc_issuance.js is what catches it (H.1 signs in here).
// Enumerating allowed redirect origins is not a fix either: this mock accepts
// arbitrary redirect_uris on purpose.
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "frame-ancestors 'none'"
].join('; ');

app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(cors({ origin: '*' }));

app.options('*', cors({ origin: '*' }));

// Accept any content-type as raw text (SOAP arrives as text/xml or
// application/soap+xml).
app.use(bodyParser.text({ type: function () { return true; }, limit: '5mb' }));

// ---------------------------------------------------------------------------
// Record every call into every endpoint: the path, the request (headers and
// body), the response (headers, body and status), and how long it took.
//
// Registered AFTER the body parser on purpose: before that runs req.body is
// undefined, and every request would be recorded as empty.
//
// res.send / res.json / res.end are wrapped rather than hooked on 'finish',
// because by the time the response has been flushed the body is gone. Two
// entries are written per call — one when the request arrives, one when the
// answer goes out — so a request that never gets answered is still visible.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  const started = Date.now();
  const request = {
    path: req.originalUrl,
    method: req.method,
    query: req.query,
    headers: headersOf(req.headers),
    body: bodyOf(req.body)
  };
  log.debug({ request: request }, 'Request: ' + req.method + ' ' + req.originalUrl);

  let responseBody = '';
  const send = res.send;
  const json = res.json;
  const end = res.end;
  res.send = function (body) {
    responseBody = bodyOf(body);
    return send.apply(res, arguments);
  };
  res.json = function (body) {
    responseBody = bodyOf(body);
    return json.apply(res, arguments);
  };
  res.end = function (chunk) {
    if (!responseBody && chunk) responseBody = bodyOf(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk);
    return end.apply(res, arguments);
  };

  res.on('finish', function () {
    log.debug({ response: { path: req.originalUrl,
                            method: req.method,
                            status: res.statusCode,
                            durationMs: Date.now() - started,
                            headers: headersOf(res.getHeaders()),
                            body: responseBody } },
              'Response: ' + res.statusCode + ' ' + req.method + ' ' + req.originalUrl +
              ' in ' + (Date.now() - started) + 'ms');
  });
  next();
});

app.get('/healthcheck', function (req, res) {
  log.debug("Entering the healthcheck endpoint.");
  res.status(200).json({ message: 'Success' });
  log.debug("Leaving the healthcheck endpoint.");
});

module.exports = app;
