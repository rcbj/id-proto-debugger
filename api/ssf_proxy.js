// File: ssf_proxy.js
//
// ---------------------------------------------------------------------------
// WHAT `POST /ssf/call` WILL AND WILL NOT SEND. IT DECIDES; server.js PERFORMS.
//
// The Shared Signals workflow (`client/public/ssf.html`) can make its calls two
// ways: in the browser, or through this service. It is the SCIM arrangement
// rather than the LDAP one — SSF's management API, its status, subject,
// verification and poll endpoints are all ordinary HTTPS with a JSON body, so
// the browser path is real, is the default, and is the ONLY path on the
// deployed static sites, which have no api at all.
//
// So this endpoint exists for the three cases the browser cannot cover, which
// are SCIM's three and are worth restating because the first one bites harder
// here:
//
//   * **CORS.** A real transmitter's stream management API is a control plane —
//     it decides who gets told that somebody's session was revoked — and it
//     sends no `Access-Control-Allow-Origin`. A cross-origin `fetch` is refused
//     by the browser before the request is made, and all the page can see is
//     `TypeError: Failed to fetch`, which is indistinguishable from a DNS
//     failure, a dead host and a bad certificate.
//   * **A SELF-SIGNED CERTIFICATE**, which a browser refuses and which a
//     debugger pointed at somebody's staging transmitter meets constantly.
//   * **THE EXCHANGE ITSELF.** A browser withholds the headers it adds and CORS
//     withholds most of those that come back, so a browser-direct call can only
//     ever be reported by halves.
//
// **AND ONE THE SCIM PAGE DOES NOT HAVE**, which is the whole reason
// `api/ssf_receiver.js` exists beside this file: a browser cannot be an HTTP
// SERVER, so a page cannot be the far end of RFC 8935 push delivery. Poll
// delivery works from the browser and push does not, and that is a property of
// the specification rather than of this service. See that file.
//
// ---------------------------------------------------------------------------
// THIS FILE HAS NO NETWORK AND NO axios, ON PURPOSE.
//
// It validates and sanitises; `server.js` makes the call with the shared agents
// that carry `api/ssrf_guard.js`, the connect timeout, the size cap and the
// redirect cap. The split is `scim_proxy.js`'s and buys the same thing: every
// refusal this endpoint can produce is reachable from `tests/ssf_protocol.js`
// with no transmitter on the other end, so a rule that stopped being enforced
// fails a test naming the rule rather than timing out against a host.
//
// **THE ADDRESS POLICY IS NOT RE-IMPLEMENTED HERE AND MUST NOT BE**, for the
// reason `scim_proxy.js` gives: this is an axios call, so the guard installed
// once on the shared instance already covers it, redirects included.
//
// ---------------------------------------------------------------------------
// THE THREE OUTCOMES, WHICH ARE `POST /scim`'s AND `POST /ldap/*`'s.
//
//   * A refusal by THIS service — a relative URL, a method that is not one of
//     the five, a header this endpoint will not forward — is a **400**.
//   * A network failure — no route, refused connection, timeout, a blocked
//     address — is a **502**.
//   * **AN SSF ERROR FROM THE TRANSMITTER IS A 200**, with `ok: false` and the
//     status and the RFC 8935 `{err, description}` inside it.
//
// The third matters more here than anywhere else this pattern is used, because
// of what a Shared Signals refusal SAYS. `invalid_audience` on a stream whose
// `aud` is wrong, a 404 on a stream_id that was deleted, a 403 naming the
// scope, a 400 naming the member of a subject identifier that RFC 9493 does not
// define — every one of those is the transmitter explaining exactly what is
// wrong, in a sentence, and they are the single most useful thing this workflow
// can put on the screen. An endpoint that reported them as failures would throw
// all of it away.
//
// ---------------------------------------------------------------------------
// HEADERS: THE SAME SHAPE RULE, AND ONE ADDITION.
//
// The refused set is `scim_proxy.js`'s — framing and hop-by-hop — because the
// reasoning is about HTTP rather than about either protocol. What is added here
// is not a refusal but a DEFAULT: a request with a body gets
// `Content-Type: application/json` and every request gets `Accept:
// application/json`, unless the caller set them. Defaulted rather than forced,
// for the reason the SCIM proxy defaults its media type: a debugger has to be
// able to send the wrong one deliberately, to find out whether a transmitter
// insists.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

// The log level comes from the same configuration everything else here reads. A
// caller without one still has to be able to load this module — the tests load
// it directly to assert the refusals — so an unresolvable CONFIG_FILE falls
// back to info rather than throwing.
var log = bunyan.createLogger({
  name: "ssf_proxy",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// SSF 1.0 uses exactly these on its endpoints: POST to create, GET to read,
// PUT to replace, PATCH to merge, DELETE to remove, and POST again for status,
// subjects, verification and poll. HEAD and OPTIONS are absent deliberately —
// no SSF operation uses either, a browser sends the OPTIONS preflight itself,
// and forwarding an arbitrary method is how a proxy becomes useful for
// something other than the protocol it was written for.
var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

// See the header. Framing and hop-by-hop, not content. It is deliberately the
// same list `scim_proxy.js` carries: the reasoning is about HTTP and not about
// either protocol, so two lists that could differ would be one list with a hole
// in whichever copy nobody edited.
var REFUSED_HEADERS = {
  host: 'It would send the request to a different virtual host than the URL ' +
      'names, which is how a proxy is turned into an open one.',
  'content-length': 'The body framing is this service\'s to set — a caller ' +
      'that could set it could smuggle a second request inside the first.',
  'transfer-encoding': 'Body framing again, and the other half of the same ' +
      'smuggling pair.',
  connection: 'Hop-by-hop (RFC 7230 section 6.1). It belongs to the ' +
      'connection this service opens, not to the request being carried.',
  'keep-alive': 'Hop-by-hop (RFC 7230 section 6.1). It describes the ' +
      'connection this service opens and has nothing to say about the ' +
      'request being carried.',
  upgrade: 'Hop-by-hop, and it asks to stop speaking HTTP altogether — on a ' +
      'connection this service owns and the caller does not.',
  te: 'Hop-by-hop. It negotiates a transfer coding for THIS hop, which is ' +
      'this service\'s to choose.',
  trailer: 'Hop-by-hop, and it belongs with the framing headers above: it ' +
      'announces fields that arrive after a chunked body.',
  'proxy-authorization': 'It authenticates to a proxy rather than to the ' +
      'transmitter, so forwarding it would send this service\'s hop ' +
      'credentials somewhere they do not belong.'
};

// RFC 7230 section 3.2.6. A header name is a token; anything else is not a
// header at all and is refused before it can be interpreted as one.
var TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// The largest request body this endpoint will forward, in bytes. A SEPARATE
// number from `maxContentLength`, which bounds what comes BACK — the same split
// `scimMaxRequestBytes` makes and for a reason of its own here: an Add Subject
// carrying an `aliases` identifier with fifty members is a large request and an
// EMPTY response, since SSF answers 204 with no body.
var DEFAULT_MAX_REQUEST_BYTES = 262144;

function maxRequestBytes(appconfig) {
  log.debug("Entering maxRequestBytes().");
  var configured = appconfig && appconfig.ssfMaxRequestBytes;
  if (typeof configured !== 'number' || !isFinite(configured) ||
      configured <= 0) {
    if (configured !== undefined) {
      log.warn("Ignoring ssfMaxRequestBytes=" + JSON.stringify(configured) +
               " — it must be a positive number. Using " +
               DEFAULT_MAX_REQUEST_BYTES + ".");
    }
    log.debug("Leaving maxRequestBytes(). Default.");
    return DEFAULT_MAX_REQUEST_BYTES;
  }
  log.debug("Leaving maxRequestBytes(). " + configured);
  return configured;
}

// ---------------------------------------------------------------------------
// Validate and sanitise one request.
//
// Returns either `{ ok: false, error }` — which server.js answers as a 400 —
// or `{ ok: true, method, url, headers, body }`, which is exactly what it
// sends. Nothing here performs anything and nothing here reaches the network.
// ---------------------------------------------------------------------------
function describeRequest(input, appconfig) {
  log.debug("Entering describeRequest().");
  var given = input || {};
  var url = String(given.url || '').trim();
  if (url === '') {
    log.debug("Leaving describeRequest(). No url.");
    return { ok: false, error: 'url is required. It is the ABSOLUTE URL of ' +
        'the SSF endpoint, which the page takes from the transmitter\'s own ' +
        'configuration metadata rather than composing — SSF fixes no path, ' +
        'so every endpoint is discovered.' };
  }
  if (!/^https?:\/\//i.test(url)) {
    log.debug("Leaving describeRequest(). Not an absolute http(s) URL.");
    return { ok: false, error: 'url must be an absolute http:// or https:// ' +
        'URL. A relative one has no host for this service to resolve, and ' +
        'resolving it against this service\'s own address would make this ' +
        'endpoint a way to reach the api\'s own routes.' };
  }
  var method = String(given.method || 'GET').toUpperCase();
  if (METHODS.indexOf(method) < 0) {
    log.debug("Leaving describeRequest(). Method not allowed: " + method);
    return { ok: false, error: 'method must be one of ' + METHODS.join(', ') +
        '. SSF 1.0 uses exactly those five, and forwarding an arbitrary ' +
        'method would make this endpoint useful for something other than ' +
        'Shared Signals.' };
  }
  var headerResult = sanitizeHeaders(given.headers);
  if (!headerResult.ok) {
    log.debug("Leaving describeRequest(). Refused header.");
    return headerResult;
  }
  var bodyResult = encodeBody(given.body, method, appconfig);
  if (!bodyResult.ok) {
    log.debug("Leaving describeRequest(). Body refused.");
    return bodyResult;
  }
  var headers = headerResult.headers;
  // Defaulted, not forced. See the header.
  if (bodyResult.body !== null && !hasHeader(headers, 'content-type')) {
    headers['Content-Type'] = 'application/json';
  }
  if (!hasHeader(headers, 'accept')) {
    headers.Accept = 'application/json';
  }
  var out = {
    ok: true,
    method: method,
    url: url,
    headers: headers,
    body: bodyResult.body,
    // Default to VALIDATING TLS; only an explicit opt-out turns it off, so a
    // missing or misspelled member leaves verification on.
    sslValidate: !(given.sslValidate === false || given.sslValidate === 'false')
  };
  log.debug("Leaving describeRequest(). " + out.method + " " + out.url);
  return out;
}

function hasHeader(headers, name) {
  log.debug("Entering hasHeader(). name=" + name);
  var wanted = String(name).toLowerCase();
  var found = false;
  Object.keys(headers || {}).forEach(function (key) {
    if (key.toLowerCase() === wanted) {
      found = true;
    }
  });
  log.debug("Leaving hasHeader(). " + found);
  return found;
}

function sanitizeHeaders(given) {
  log.debug("Entering sanitizeHeaders().");
  var out = {};
  var source = given || {};
  if (typeof source !== 'object' || Array.isArray(source)) {
    log.debug("Leaving sanitizeHeaders(). Not an object.");
    return { ok: false, error: 'headers must be an object of name to value.' };
  }
  var names = Object.keys(source);
  var i;
  for (i = 0; i < names.length; i++) {
    var name = names[i];
    var lower = String(name).toLowerCase();
    if (!TOKEN.test(String(name))) {
      log.debug("Leaving sanitizeHeaders(). Name is not a token: " + name);
      return { ok: false, error: 'The header name ' + JSON.stringify(name) +
          ' is not a token (RFC 7230 section 3.2.6), so it is not a header ' +
          'name at all.' };
    }
    if (Object.prototype.hasOwnProperty.call(REFUSED_HEADERS, lower)) {
      log.debug("Leaving sanitizeHeaders(). Refused: " + lower);
      return { ok: false, error: 'This endpoint will not forward the ' + name +
          ' header. ' + REFUSED_HEADERS[lower] + ' Everything else is ' +
          'forwarded as sent — the refusals here are about the SHAPE of the ' +
          'request rather than its content.' };
    }
    var value = source[name];
    if (value === undefined || value === null) {
      continue;
    }
    var text = String(value);
    if (/[\r\n]/.test(text)) {
      log.debug("Leaving sanitizeHeaders(). CR/LF in a value.");
      return { ok: false, error: 'The value of ' + name + ' contains a ' +
          'carriage return or a line feed. That is header injection rather ' +
          'than a header value, and it is refused before it is anything ' +
          'else.' };
    }
    out[name] = text;
  }
  log.debug("Leaving sanitizeHeaders(). " + Object.keys(out).length +
      " header(s).");
  return { ok: true, headers: out };
}

// ---------------------------------------------------------------------------
// The body, serialised here rather than by axios, for `scim_proxy.js`'s two
// reasons: the size check counts BYTES ON THE WIRE, which means having the
// bytes, and the trace has to show what was actually sent rather than a
// re-serialisation with different whitespace.
//
// A body on a GET is refused rather than dropped. On a DELETE it is NOT, and
// that is the one place this differs from the SCIM proxy: SSF's stream
// management API is ONE PATH with five methods, and a DELETE names the stream
// it is deleting in a JSON body. Refusing that would make the delete
// unreachable through this endpoint.
// ---------------------------------------------------------------------------
function encodeBody(given, method, appconfig) {
  log.debug("Entering encodeBody(). method=" + method);
  if (given === undefined || given === null || given === '') {
    log.debug("Leaving encodeBody(). No body.");
    return { ok: true, body: null };
  }
  if (method === 'GET') {
    log.debug("Leaving encodeBody(). Body on a GET.");
    return { ok: false, error: 'A GET carries no body in SSF 1.0, and this ' +
        'endpoint refuses one rather than dropping it — a body that is ' +
        'silently discarded is how the wrong method goes unnoticed. Reading ' +
        'a stream takes its id in the query string.' };
  }
  var text;
  if (typeof given === 'string') {
    text = given;
  } else {
    try {
      text = JSON.stringify(given);
    } catch (e) {
      log.debug("Leaving encodeBody(). Not serialisable: " + e.message);
      return { ok: false, error: 'The body could not be serialised as JSON: ' +
          e.message };
    }
  }
  var size = Buffer.byteLength(text, 'utf8');
  var limit = maxRequestBytes(appconfig);
  if (size > limit) {
    log.debug("Leaving encodeBody(). Too large: " + size);
    return { ok: false, error: 'This request body is ' + size + ' bytes and ' +
        'this service will forward at most ' + limit + ' ' +
        '(ssfMaxRequestBytes). Nothing SSF defines is this large: a Stream ' +
        'Configuration is a few hundred bytes and the biggest ordinary ' +
        'request is an Add Subject.' };
  }
  log.debug("Leaving encodeBody(). " + size + " bytes.");
  return { ok: true, body: text };
}

// ---------------------------------------------------------------------------
// Reading the answer, which is where the three outcomes are decided.
//
// `raw` is the body as received. It is parsed here rather than left to axios so
// that a body which is NOT JSON — an HTML error page from a load balancer in
// front of the transmitter, which is a very common thing to meet — is reported
// as what it is instead of vanishing into a parse error.
//
// **A 204 WITH NO BODY IS A SUCCESS AND NOT AN EMPTY ANSWER**, which is worth
// stating because SSF uses it more than most protocols: Add Subject, Remove
// Subject and the verification endpoint all answer 204, and a page that treated
// "no body" as "nothing happened" would report every one of them as a failure.
// ---------------------------------------------------------------------------
function readResponse(status, headers, raw) {
  log.debug("Entering readResponse(). status=" + status);
  var text = (raw === null || raw === undefined) ? '' : String(raw);
  var parsed = null;
  var parseError = '';
  if (text !== '') {
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      parsed = null;
      parseError = e.message;
    }
  }
  var out = {
    status: status,
    ok: status >= 200 && status < 300,
    headers: headers || {},
    body: parsed,
    rawBody: text,
    // The RFC 8935 section 2.4 refusal shape, which SSF uses on every endpoint
    // rather than only on a push. `err` is from the SET Error Codes registry —
    // invalid_request, invalid_key, invalid_issuer, invalid_audience,
    // authentication_failed, access_denied — and `description` is the sentence
    // that is the whole value of the answer.
    err: '',
    description: '',
    noBody: text === '',
    notJson: parseError
  };
  if (parsed && typeof parsed === 'object') {
    out.err = String(parsed.err || '');
    out.description = String(parsed.description || '');
  }
  if (!out.ok && parseError && text !== '') {
    // A non-2xx whose body is not JSON is almost always something in FRONT of
    // the transmitter answering — a load balancer, a WAF, an authentication
    // gateway. Saying so is more useful than reporting a parse failure,
    // because the fix is in a different place entirely.
    out.description = 'The body of this ' + status + ' is not JSON, so it ' +
        'did not come from an SSF transmitter: something in front of it ' +
        'answered. The first bytes are ' +
        JSON.stringify(text.slice(0, 120)) + '.';
  }
  log.debug("Leaving readResponse(). ok=" + out.ok +
      (out.err ? " err=" + out.err : ""));
  return out;
}

// ---------------------------------------------------------------------------
// What `GET /ssf/limits` publishes.
//
// The same device `/scim/limits`, `/ldap/limits`, `/krb5/limits` and
// `/tls/limits` use: the page says what this service will and will not do
// BEFORE a call fails, so a refusal is a sentence rather than a surprise. It is
// also how the page knows there is an api at all — a static deployment gets no
// answer here and fixes the page's `callPath` to the browser, which is a
// stronger signal than a configuration flag because it is the api itself
// saying so.
//
// `receiver` is the half `scim/limits` has no equivalent of and is the reason
// this workflow needs an api for anything a browser could otherwise do: it
// says whether this service will host an RFC 8935 push endpoint on the page's
// behalf, and what that costs. See `api/ssf_receiver.js`.
// ---------------------------------------------------------------------------
function limits(appconfig, receiver) {
  log.debug("Entering limits().");
  var out = {
    methods: METHODS.slice(0),
    refusedHeaders: Object.keys(REFUSED_HEADERS).sort(),
    refusedHeaderReasons: REFUSED_HEADERS,
    maxRequestBytes: maxRequestBytes(appconfig),
    maxResponseBytes: (appconfig && appconfig.maxContentLength) || null,
    callTimeoutMs: (appconfig && appconfig.callTimeout) || null,
    connectionTimeoutMs: (appconfig && appconfig.connectionTimeout) || null,
    maxRedirects: (appconfig && appconfig.maxRedirects) === undefined
      ? null : appconfig.maxRedirects,
    sslValidateDefault: true,
    receiver: receiver || null,
    addressPolicy: 'The same one every outbound call from this service ' +
        'obeys: api/ssrf_guard.js, installed on the shared axios instance, ' +
        'so loopback and private ranges are refused on the request AND on ' +
        'any redirect into one. It is not re-implemented here.',
    statusRule: 'A refusal by this service is a 400; a network failure is a ' +
        '502; and an SSF error from the transmitter is a 200 carrying that ' +
        'status and its {err, description}. Those refusals are the most ' +
        'useful thing this workflow can show — a 403 naming the scope, a ' +
        '400 naming the member of a subject identifier RFC 9493 does not ' +
        'define — and reporting them as failures would throw all of it ' +
        'away.',
    deliveryFromTheBrowser: 'POLL delivery (RFC 8936) works with no api at ' +
        'all: the receiver comes to the transmitter. PUSH delivery (RFC ' +
        '8935) cannot, because a browser cannot be an HTTP server — which ' +
        'is a property of the specification rather than of this service. ' +
        'The receiver below is how this api stands in.',
    whatThisIsNot: 'Not a general HTTP proxy. Five methods, no body on a ' +
        'GET, and the framing headers are refused.'
  };
  log.debug("Leaving limits().");
  return out;
}

module.exports = {
  METHODS: METHODS,
  REFUSED_HEADERS: REFUSED_HEADERS,
  DEFAULT_MAX_REQUEST_BYTES: DEFAULT_MAX_REQUEST_BYTES,
  maxRequestBytes: maxRequestBytes,
  describeRequest: describeRequest,
  sanitizeHeaders: sanitizeHeaders,
  encodeBody: encodeBody,
  readResponse: readResponse,
  limits: limits
};
