// File: edge_common.js
//
// ---------------------------------------------------------------------------
// Shared machinery for this deployment's Lambda@Edge landings.
//
// WHY THERE ARE LANDINGS AT ALL
//
// The hosted sites are S3 + CloudFront with no backend, and an identity
// protocol's *response* has to arrive somewhere. Most protocols here manage on
// their own — OAuth2/OIDC come back on a redirect into dist/callback/index.html
// — but two of them return their result as an HTTP POST from the IdP, and S3
// answers a POST with 403/405. The edge is the only place in a static
// deployment that can run code on the way in, so that is where the missing
// server goes:
//
//   /wsfed              wsfed_landing.js  — the WS-Federation wresult
//   /samlacs, /samlslo  saml_landing.js   — the SAML Response / LogoutResponse
//
// Both must be **Lambda@Edge**, not CloudFront Functions: Functions are never
// given the request body, so the token would be gone before any code saw it.
// The association needs include_body = true on viewer-request.
//
// WHY THE TWO LANDINGS ARE NOT THE SAME LANDING
//
// They differ in what they are handed and what the page needs back. WS-Fed's
// wresult is raw XML; SAML's SAMLResponse is base64 (and DEFLATE-compressed on
// the Redirect binding), and the response page already knows how to decode
// either, so the SAML landing passes it through untouched rather than decoding
// at the edge. What they share is everything below: parsing a form body out of a
// CloudFront event, generating a response CloudFront will accept, and handing a
// value to a same-origin page through sessionStorage.
//
// THE HAND-OFF, AND WHY IT IS sessionStorage
//
// Neither landing has anywhere to stash anything — that is the whole difficulty
// of having no server. The api's equivalents (api/server.js) stash server-side
// and pass a `?id=`; here the value must travel through the browser. It does not
// go in the URL: a signed assertion is kilobytes and would sit in the address
// bar, the history entry and any Referer. Instead the generated page writes it
// into sessionStorage (same origin as the response page, so it is shared) and
// location.replace()s — replace, so Back does not re-POST.
//
// The key names are a CONTRACT with client/src/edge_landing.js, duplicated
// because these files ship to AWS via Terraform and that one is browserified
// into the page, so they cannot import each other. CONTRACTS below is exported
// for tests/edge_landing_contract.js, which loads both and fails on drift — a
// rename on one side alone would otherwise surface only as a deployed site
// reporting that nothing arrived.
//
// LIMITS
//
// CloudFront hands a viewer-request Lambda at most 40 KB of request body
// (truncating beyond, flagged as inputTruncated) and accepts at most 40 KB of
// generated response body. Rendering a truncated token as though it were whole
// would be worse than failing, so callers refuse that case outright; and
// handoffPage() drops the no-JavaScript fallback copy before it drops the
// hand-off itself.
// ---------------------------------------------------------------------------
'use strict';

// Every generated page carries <meta name="wsfed-landing" content="..."> — the
// name is historical (this started as the WS-Federation landing) and is kept
// because remote-run-tests.sh probes for it. It means "an edge landing answered",
// not "the WS-Federation one".
var LANDING_MARKER = 'cloudfront-edge';

// Kept under CloudFront's 40 KB so headers and the multi-byte-safe measurement
// cannot push a response over.
var MAX_BODY_BYTES = 38 * 1024;

// --- The contract with client/src/edge_landing.js ---------------------------
var CONTRACTS = {
  marker: LANDING_MARKER,
  wsfed: {
    responsePage: '/wsfed_response.html',
    // "1" on a successful hand-off, "blocked" when the generated page could not
    // write sessionStorage at all.
    handoffParam: 'posted',
    wresultKey: 'wsfed_edge_wresult',
    wctxKey: 'wsfed_edge_wctx',
    waKey: 'wsfed_edge_wa'
  },
  saml: {
    responsePage: '/saml_response.html',
    handoffParam: 'posted',
    // The SAMLResponse exactly as the IdP sent it: still base64, possibly still
    // DEFLATE-compressed. decodeSamlParam() on the response page handles both,
    // and reusing it is why nothing is decoded at the edge.
    responseKey: 'saml_edge_response',
    relayStateKey: 'saml_edge_relaystate'
  }
};

function htmlEscape(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// A JavaScript string literal that is safe to sit inside a <script> element.
//
// JSON.stringify handles quoting and control characters but NOT the HTML layer:
// a "</script>" anywhere in the value — a signed assertion can carry one inside
// CDATA — ends the element early and the rest lands in the document as markup.
// Escaping < and > is what prevents that, and it is the one escape here that is
// load-bearing (a mutation test shows it really does execute otherwise).
//
// U+2028/U+2029 are belt-and-braces: newlines to a JavaScript parser but legal
// raw in JSON until ES2019 made them legal in JS strings too. Every runtime that
// can host this is well past that; two lines, so they stay.
function jsLiteral(value) {
  return JSON.stringify(String(value == null ? '' : value))
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

// Decode one application/x-www-form-urlencoded component. Malformed percent
// escapes throw in decodeURIComponent; a token is not worth losing over a stray
// '%' elsewhere in the body, so that one component falls back to its raw text.
function formDecode(text) {
  var plussed = String(text == null ? '' : text).replace(/\+/g, ' ');
  try {
    return decodeURIComponent(plussed);
  } catch (e) {
    console.log('edge-landing: undecodable form component kept verbatim (' + e.message + ').');
    return plussed;
  }
}

// Parse an urlencoded string (a query string or a form body). Later occurrences
// win, matching how Express reads req.query/req.body for a repeated name.
function parseUrlEncoded(text) {
  var out = {};
  var raw = String(text == null ? '' : text);
  if (!raw) return out;
  var pairs = raw.split('&');
  for (var i = 0; i < pairs.length; i++) {
    if (!pairs[i]) continue;
    var eq = pairs[i].indexOf('=');
    var name = eq === -1 ? pairs[i] : pairs[i].substring(0, eq);
    var value = eq === -1 ? '' : pairs[i].substring(eq + 1);
    out[formDecode(name)] = formDecode(value);
  }
  return out;
}

// The POSTed form. `include_body` must be set on the association or request.body
// is absent entirely — indistinguishable here from a genuinely empty POST, so
// say so in the log: a misconfigured association would otherwise look exactly
// like a request that legitimately carried nothing.
function readBody(request) {
  var body = request.body;
  if (!body || !body.data) {
    if (request.method === 'POST') {
      console.log('edge-landing: POST arrived with no body. If something was expected, the cache ' +
                  'behavior is missing include_body = true on the viewer-request association.');
    }
    return { params: {}, truncated: false };
  }
  var text = body.encoding === 'base64'
    ? Buffer.from(body.data, 'base64').toString('utf8')
    : String(body.data);
  return { params: parseUrlEncoded(text), truncated: body.inputTruncated === true };
}

// Merge the query string under the body, matching Express's
// (req.body && req.body.X) || req.query.X precedence in the api's routes.
function readParams(request) {
  var query = parseUrlEncoded(request.querystring || '');
  var body = readBody(request);
  var params = {};
  Object.keys(query).forEach(function (k) { params[k] = query[k]; });
  Object.keys(body.params).forEach(function (k) { params[k] = body.params[k]; });
  return { params: params, truncated: body.truncated };
}

function htmlResponse(status, description, html) {
  return {
    status: String(status),
    statusDescription: description,
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/html; charset=utf-8' }],
      // A landing that carries a security token must never be cached, by
      // CloudFront or by the browser.
      'cache-control': [{ key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' }],
      'x-content-type-options': [{ key: 'X-Content-Type-Options', value: 'nosniff' }]
    },
    body: html
  };
}

function redirectResponse(location) {
  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: location }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' }]
    }
  };
}

// Every synthetic response carries the marker, so a probe (and a human with
// curl) can recognise a landing whatever it answered.
function page(title, bodyHtml, scriptJs) {
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
    '<meta charset="utf-8">\n' +
    '<meta name="wsfed-landing" content="' + LANDING_MARKER + '">\n' +
    '<title>' + htmlEscape(title) + '</title>\n' +
    (scriptJs ? '<script>\n' + scriptJs + '\n</script>\n' : '') +
    '</head>\n<body>\n' + bodyHtml + '\n</body>\n</html>\n';
}

// The hand-off script. Defensive because a browser with sessionStorage disabled
// (or a partitioned context) throws on setItem, and silently redirecting to an
// empty response page would read as "the IdP returned nothing" — the page is
// told the hand-off failed instead, via ?<handoffParam>=blocked.
function handoffScript(values, okUrl, blockedUrl) {
  var sets = Object.keys(values).map(function (key) {
    return '    sessionStorage.setItem(' + jsLiteral(key) + ', ' + jsLiteral(values[key]) + ');\n';
  }).join('');
  return '(function () {\n' +
    '  var target = ' + jsLiteral(okUrl) + ';\n' +
    '  try {\n' + sets +
    '  } catch (e) {\n' +
    '    target = ' + jsLiteral(blockedUrl) + ';\n' +
    '  }\n' +
    '  window.location.replace(target);\n' +
    '})();';
}

// Build the whole hand-off response.
//
//   opts.values     { storageKey: value } written before the redirect
//   opts.contract   the CONTRACTS entry (responsePage + handoffParam)
//   opts.title      page title
//   opts.lead       one-line body text
//   opts.fallback   { label, value } rendered in a <noscript> textarea so the
//                   value is not simply lost without JavaScript. Dropped first
//                   when the response would exceed CloudFront's limit.
//   opts.tooLarge   extra sentence for the 413 when even one copy will not fit.
function handoffPage(opts) {
  var contract = opts.contract;
  var okUrl = contract.responsePage + '?' + contract.handoffParam + '=1';
  var blockedUrl = contract.responsePage + '?' + contract.handoffParam + '=blocked';
  var script = handoffScript(opts.values, okUrl, blockedUrl);
  var lead = '<p>' + opts.lead + '</p>\n';
  var bytesOf = function (s) { return Buffer.byteLength(s, 'utf8'); };
  console.log('Entering handoffPage(). target=' + okUrl + ' payload bytes=' +
              Object.keys(opts.values).reduce(function (n, k) { return n + bytesOf(opts.values[k]); }, 0));

  if (opts.fallback && opts.fallback.value) {
    var withFallback = page(opts.title, lead +
      '<noscript>\n<p>JavaScript is disabled, so this page cannot forward the response. Copy the ' +
      htmlEscape(opts.fallback.label) + ' below and paste it into the ' +
      '<a href="' + contract.responsePage + '">response page</a>.</p>\n' +
      '<textarea rows="20" cols="100">' + htmlEscape(opts.fallback.value) + '</textarea>\n</noscript>',
      script);
    if (bytesOf(withFallback) <= MAX_BODY_BYTES) {
      console.log('Leaving handoffPage(). Included the no-JavaScript fallback.');
      return htmlResponse(200, 'OK', withFallback);
    }
  }

  // The hand-off matters more than the fallback, so the fallback goes first.
  var lean = page(opts.title, lead, script);
  if (bytesOf(lean) <= MAX_BODY_BYTES) {
    console.log('Leaving handoffPage(). Payload too large for the no-JavaScript fallback; dropped it.');
    return htmlResponse(200, 'OK', lean);
  }

  console.log('Leaving handoffPage(). Payload exceeds the generated-response limit; refusing.');
  return htmlResponse(413, 'Payload Too Large', page('Response too large',
    '<h1>The response is too large for the edge landing</h1>\n' +
    '<p>A CloudFront Lambda@Edge viewer-request function may generate at most 40&nbsp;KB of response ' +
    'body, and this one does not fit. ' + (opts.tooLarge || '') + '</p>\n' +
    '<p>Capture the POST with the browser\'s developer tools and paste it into the ' +
    '<a href="' + contract.responsePage + '">response page</a>.</p>'));
}

// CloudFront truncated the body before this code ran, so whatever arrived is
// incomplete. Refuse rather than render a partial token as though it were whole.
function truncatedPage(what, responsePage) {
  return htmlResponse(413, 'Payload Too Large', page('Request truncated',
    '<h1>The ' + htmlEscape(what) + ' was truncated before this function saw it</h1>\n' +
    '<p>CloudFront passes a viewer-request Lambda at most 40&nbsp;KB of request body and truncates the ' +
    'rest, and it did so here — what arrived is incomplete, so it is being refused rather than rendered ' +
    'as though it were whole.</p>\n' +
    '<p>Capture the POST with the browser\'s developer tools and paste it into the ' +
    '<a href="' + responsePage + '">response page</a>.</p>'));
}

module.exports = {
  LANDING_MARKER: LANDING_MARKER,
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  CONTRACTS: CONTRACTS,
  htmlEscape: htmlEscape,
  jsLiteral: jsLiteral,
  formDecode: formDecode,
  parseUrlEncoded: parseUrlEncoded,
  readBody: readBody,
  readParams: readParams,
  htmlResponse: htmlResponse,
  redirectResponse: redirectResponse,
  page: page,
  handoffScript: handoffScript,
  handoffPage: handoffPage,
  truncatedPage: truncatedPage
};
