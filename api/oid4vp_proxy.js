// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oid4vp_proxy.js
//
// ---------------------------------------------------------------------------
// POST /oid4vp/call: one OpenID4VP exchange made on the WALLET's behalf.
//
// The VC Presentation workflow is a wallet that lives in a browser page, and
// two of its exchanges are cross-origin calls to the Verifier:
//
//   * fetching the Request Object from `request_uri` (a GET, or a POST
//     carrying wallet_metadata and wallet_nonce when request_uri_method=post,
//     OpenID4VP 1.0 section 5.10);
//   * posting the answer to `response_uri` (direct_post / direct_post.jwt,
//     section 8.2), or a SIOPv2 `post` to the redirect_uri.
//
// A Verifier that sends no CORS headers — most do not: a wallet is normally a
// native app, which has no CORS — therefore cannot be used from the page at
// all. The browser refuses to hand the page the Request Object, and refuses
// to show it the Verifier's reply. This endpoint makes the same call from the
// api, which no browser policy applies to, so the workflow can be the wallet
// against any compliant Verifier, not only one that happens to allow its
// origin. The page chooses: direct from the browser (the default, and the
// only route on a deployment with no api), or through here.
//
// The SSF proxy's shape and rules, for the reasons api/CLAUDE.md gives there:
//
//   * THREE OUTCOMES. A refusal by this service is a 400; a network failure
//     is a 502; and whatever the Verifier answered — a 200, a 400
//     invalid_request naming a failed check, a 404 for an expired request — is
//     a 200 here with its status inside. A Verifier's refusal is its ANSWER,
//     and the wallet's step 3 exists to show it.
//   * The address policy is not re-implemented: this is an axios call and
//     the guard installed on the shared instance covers it, redirects
//     included.
//   * Headers are refused by SHAPE, with ssf_proxy.js's own list and
//     sanitiser rather than a copy of either.
//
// Narrower than that proxy where OpenID4VP is narrower: GET and POST only (a
// Request Object is fetched, an answer is posted, and nothing else crosses),
// a form body as a string (both bodies are application/x-www-form-urlencoded
// in OpenID4VP), and the reply passed back as TEXT, because a Request Object
// is a compact JWS rather than JSON.
//
// No axios and no network here: server.js makes the call. That is what lets
// tests/api_oid4vp_proxy.js assert every refusal with no Verifier anywhere.
// ---------------------------------------------------------------------------

var bunyan = require('bunyan');
var log = bunyan.createLogger({
  name: 'oid4vp_proxy',
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

var ssfProxy = require('./ssf_proxy');

var METHODS = ['GET', 'POST'];
var DEFAULT_MAX_REQUEST_BYTES = 262144;

// The seventeenth outbound setting: a cap on the BODY this service forwards.
// An encrypted direct_post.jwt answer carrying an mdoc DeviceResponse is a few
// tens of kilobytes; nothing OpenID4VP sends approaches the default.
function maxRequestBytes(appconfig) {
  log.debug('Entering maxRequestBytes().');
  var configured = appconfig && appconfig.oid4vpMaxRequestBytes;
  if (typeof configured !== 'number' || !isFinite(configured) ||
      configured <= 0) {
    if (configured !== undefined) {
      log.warn('Ignoring oid4vpMaxRequestBytes=' +
               JSON.stringify(configured) + ' — it must be a positive ' +
               'number. Using ' + DEFAULT_MAX_REQUEST_BYTES + '.');
    }
    log.debug('Leaving maxRequestBytes(). Default.');
    return DEFAULT_MAX_REQUEST_BYTES;
  }
  log.debug('Leaving maxRequestBytes().');
  return configured;
}

function hasHeader(headers, name) {
  log.debug('Entering hasHeader(). ' + name);
  var wanted = String(name).toLowerCase();
  var found = Object.keys(headers || {}).some(function (key) {
    return key.toLowerCase() === wanted;
  });
  log.debug('Leaving hasHeader(). ' + found);
  return found;
}

// { url, method, headers, body, sslValidate } -> what server.js sends, or
// { ok: false, error } for a 400.
function describeRequest(input, appconfig) {
  log.debug('Entering describeRequest().');
  var given = input || {};
  var url = String(given.url || '').trim();
  if (url === '') {
    log.debug('Leaving describeRequest(). No url.');
    return { ok: false, error: 'url is required: the request_uri, the ' +
        'response_uri, or the redirect_uri a SIOPv2 post goes to, exactly ' +
        'as the Verifier named it.' };
  }
  if (!/^https?:\/\//i.test(url)) {
    log.debug('Leaving describeRequest(). Not http(s).');
    return { ok: false, error: 'url must be an absolute http:// or https:// ' +
        'URL. OpenID4VP names every endpoint absolutely, and a relative one ' +
        'resolved against this service would reach the api\'s own routes.' };
  }
  var method = String(given.method || 'GET').toUpperCase();
  if (METHODS.indexOf(method) < 0) {
    log.debug('Leaving describeRequest(). Method ' + method + '.');
    return { ok: false, error: 'method must be GET or POST. A wallet ' +
        'fetches a Request Object and posts an answer, and nothing else ' +
        'crosses in OpenID4VP; another method would make this endpoint ' +
        'useful for something that is not a presentation.' };
  }
  var headerResult = ssfProxy.sanitizeHeaders(given.headers);
  if (!headerResult.ok) {
    log.debug('Leaving describeRequest(). Header refused.');
    return headerResult;
  }
  var body = given.body;
  if (body === undefined || body === null || body === '') {
    body = null;
  } else if (typeof body !== 'string') {
    log.debug('Leaving describeRequest(). Body not a string.');
    return { ok: false, error: 'body must be a string: OpenID4VP\'s bodies ' +
        'are application/x-www-form-urlencoded, and the page sends them ' +
        'encoded exactly as they are to travel.' };
  }
  if (body !== null && method === 'GET') {
    log.debug('Leaving describeRequest(). Body on a GET.');
    return { ok: false, error: 'A GET carries no body. Fetching a Request ' +
        'Object by POST is request_uri_method=post, and is sent as a POST; ' +
        'a body silently dropped from a GET is how the wrong method goes ' +
        'unnoticed.' };
  }
  if (body !== null) {
    var size = Buffer.byteLength(body, 'utf8');
    var limit = maxRequestBytes(appconfig);
    if (size > limit) {
      log.debug('Leaving describeRequest(). Too large.');
      return { ok: false, error: 'This body is ' + size + ' bytes and this ' +
          'service forwards at most ' + limit + ' (oid4vpMaxRequestBytes).' };
    }
  }
  var headers = headerResult.headers;
  if (body !== null && !hasHeader(headers, 'content-type')) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }
  if (!hasHeader(headers, 'accept')) {
    headers.Accept = '*/*';
  }
  log.debug('Leaving describeRequest(). ' + method + ' ' + url);
  return { ok: true, method: method, url: url, headers: headers, body: body,
           sslValidate: !(given.sslValidate === false ||
                          given.sslValidate === 'false') };
}

// The Verifier's answer as the page reads it: the status, the headers, and
// the body as TEXT (a Request Object is a JWS, a reply may be JSON or
// nothing). `json` is the parse when it is JSON, for the page's convenience.
function readResponse(status, headers, raw) {
  log.debug('Entering readResponse(). status=' + status);
  var text = (raw === null || raw === undefined) ? '' : String(raw);
  var json = null;
  if (text !== '') {
    try {
      json = JSON.parse(text);
    } catch (e) {
      json = null;
    }
  }
  log.debug('Leaving readResponse().');
  return { status: status, ok: status >= 200 && status < 300,
           headers: headers || {}, body: text, json: json };
}

// What this endpoint does, for the page to discover that there is an api at
// all (a static deployment answers nothing here).
function limits(appconfig) {
  log.debug('Entering limits().');
  log.debug('Leaving limits().');
  return { methods: METHODS, refusedHeaders: Object.keys(
             ssfProxy.REFUSED_HEADERS), maxRequestBytes:
             maxRequestBytes(appconfig),
           statusRule: 'a 400 is this service refusing; a 502 is the ' +
             'Verifier unreachable; anything the Verifier answered is a 200 ' +
             'with its status inside.' };
}

module.exports = {
  METHODS: METHODS,
  DEFAULT_MAX_REQUEST_BYTES: DEFAULT_MAX_REQUEST_BYTES,
  maxRequestBytes: maxRequestBytes,
  describeRequest: describeRequest,
  readResponse: readResponse,
  limits: limits
};
