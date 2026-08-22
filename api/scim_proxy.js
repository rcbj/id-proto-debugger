// File: scim_proxy.js
//
// ---------------------------------------------------------------------------
// WHAT `POST /scim` WILL AND WILL NOT SEND. IT DECIDES; server.js PERFORMS.
//
// The SCIM workflow (`client/public/scim.html`) can make its calls two ways: in
// the browser, or through this service. Unlike LDAP and Kerberos — where the
// api exists because a browser CANNOT speak the protocol — SCIM is ordinary
// HTTPS with a JSON body, so the browser path is real and is the default on the
// deployed static sites, which have no api at all. This endpoint exists for the
// three cases the browser cannot cover:
//
//   * **CORS.** A real SCIM endpoint is the most dangerous URL an identity
//     provider exposes and essentially none of them send
//     `Access-Control-Allow-Origin`. A cross-origin `fetch` from this page is
//     refused by the browser before the request is made, and the failure the
//     page can see says only "TypeError: Failed to fetch" — which is
//     indistinguishable from a DNS failure, a dead host and a bad certificate.
//   * **A SELF-SIGNED CERTIFICATE**, which a browser refuses and which a
//     debugger pointed at somebody's staging server meets constantly.
//   * **THE EXCHANGE ITSELF.** A browser withholds the headers it adds and CORS
//     withholds most of the ones that come back, so the page's Exchange pane
//     can only ever show half of a browser-direct call. The proxied call is
//     made here and can therefore be reported in full.
//
// ---------------------------------------------------------------------------
// THIS FILE HAS NO NETWORK AND NO axios, ON PURPOSE.
//
// It validates and sanitises; `server.js` makes the call with the shared agents
// that carry `api/ssrf_guard.js`, the connect timeout, the size cap and the
// redirect cap. That split is the one `oauth2_bcp.js` has with `oauth2.js` in
// the mock STS and it buys the thing that matters here: every refusal this
// endpoint can produce is reachable from `tests/scim_protocol.js` with no
// server on the other end, so a rule that stopped being enforced fails a test
// that names the rule rather than timing out against a host.
//
// **THE ADDRESS POLICY IS NOT RE-IMPLEMENTED HERE AND MUST NOT BE.** This is an
// axios call like `/token` and `/wstrust`, so the guard installed once on the
// shared instance already covers it — request interceptor, DNS `lookup` hook
// and wrapped `createConnection`, redirects included. That is the whole reason
// there is no `blockedRangeFor` call in this file: the two places that DO carry
// one (`ldap_client.js`, `tls_probe.js`) are raw sockets that axios never sees.
// A copy here would be a fourth implementation of one policy, which is how a
// policy comes to have a hole in one of its copies.
//
// ---------------------------------------------------------------------------
// THE THREE OUTCOMES, WHICH ARE THE SAME THREE `POST /ldap/*` DRAWS.
//
//   * A refusal by THIS service — a relative URL, a method that is not one of
//     the five, a header this endpoint will not forward — is a **400**.
//   * A network failure — no route, refused connection, timeout, a blocked
//     address — is a **502**.
//   * **A SCIM ERROR FROM THE SERVER IS A 200**, with `ok: false` and the
//     status and `scimType` inside it.
//
// The third is the one worth stating twice. A 409 `uniqueness` on a duplicate
// userName, a 404 on an id that names nothing, a 403 from an access control
// policy and a 501 on `/Me` are all the far end ANSWERING. They are the single
// most interesting thing a SCIM server ever says, and an endpoint that reported
// them as failures would make a provisioning debugger unable to show the errors
// it exists to show. `tests/scim_protocol.js` asserts the transport status on
// every negative for exactly that reason.
//
// ---------------------------------------------------------------------------
// HEADERS: AN ALLOWLIST WOULD BE WRONG AND SO WOULD ANYTHING GOES.
//
// A debugger has to be able to send the header a server it has never met asks
// for — a vendor's `X-Tenant-Id`, an `If-Match` for a server that does support
// ETags, a `DPoP` proof. So the forwarded set is not enumerated. What is
// refused instead is the set that would let a caller change the SHAPE of the
// request rather than its content:
//
//   * `Host`, which redirects the request to a different virtual host than the
//     URL says and is how a proxy is turned into an open one,
//   * `Content-Length` and `Transfer-Encoding`, which frame the body — a caller
//     that could set either could smuggle a second request inside the first,
//   * `Connection`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authorization` and
//     `Keep-Alive`, which are hop-by-hop (RFC 7230 section 6.1) and belong to
//     the connection this service owns, not to the caller's request,
//   * anything whose NAME is not a token or whose VALUE contains CR or LF,
//     which is header injection and is refused before it is anything else.
//
// Everything else goes. The list is short, it is about framing rather than
// about content, and each entry says why — an allowlist would have been shorter
// to write and would have made this endpoint useless against the third server
// somebody pointed it at.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

// The log level comes from the same configuration everything else here reads. A
// caller without one still has to be able to load this module — the tests load
// it directly to assert the refusals — so an unresolvable CONFIG_FILE falls
// back to info rather than throwing.
var log = bunyan.createLogger({
  name: "scim_proxy",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// RFC 7644 defines exactly these on its endpoints. HEAD and OPTIONS are absent
// deliberately: no SCIM operation uses either, a browser sends the OPTIONS
// preflight itself, and forwarding an arbitrary method is how a proxy becomes
// useful for something other than SCIM.
var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

// See the header. Framing and hop-by-hop, not content.
var REFUSED_HEADERS = {
  host: 'It would send the request to a different virtual host than the URL ' +
      'names, which is how a proxy is turned into an open one.',
  'content-length': 'The body framing is this service\'s to set — a caller ' +
      'that could set it could smuggle a second request inside the first.',
  'transfer-encoding': 'Body framing again, and the other half of the same ' +
      'smuggling pair.',
  connection: 'Hop-by-hop (RFC 7230 section 6.1). It belongs to the ' +
      'connection this service opens, not to the request being carried.',
  'keep-alive': 'Hop-by-hop.',
  upgrade: 'Hop-by-hop, and it asks to stop speaking HTTP.',
  te: 'Hop-by-hop.',
  trailer: 'Hop-by-hop.',
  'proxy-authorization': 'It authenticates to a proxy rather than to the ' +
      'SCIM server, so forwarding it would send this service\'s hop ' +
      'credentials somewhere they do not belong.'
};

// RFC 7230 section 3.2.6. A header name is a token; anything else is not a
// header at all and is refused before it can be interpreted as one.
var TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// The largest request body this endpoint will forward, in bytes. A SEPARATE
// number from `maxContentLength`, which bounds what comes BACK: a bulk request
// creating fifty users with every optional attribute is a large request and a
// small response, and one limit standing for both would either refuse that or
// leave the response unbounded. The ServiceProviderConfig's own
// `bulk.maxPayloadSize` is the far end's limit and is usually smaller; this one
// exists so that a caller cannot make this service buffer an unbounded body on
// its way to somewhere that would have refused it anyway.
var DEFAULT_MAX_REQUEST_BYTES = 1048576;

function maxRequestBytes(appconfig) {
  log.debug("Entering maxRequestBytes().");
  var configured = appconfig && appconfig.scimMaxRequestBytes;
  if (typeof configured !== 'number' || !isFinite(configured) ||
      configured <= 0) {
    if (configured !== undefined) {
      log.warn("Ignoring scimMaxRequestBytes=" + JSON.stringify(configured) +
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
        'the SCIM endpoint — the service root plus the path, as the page ' +
        'composes it (for example https://host/scim/v2/Users?count=10).' };
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
        '. RFC 7644 uses exactly those five, and forwarding an arbitrary ' +
        'method would make this endpoint useful for something other than ' +
        'SCIM.' };
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
  // The two headers RFC 7644 section 3.1 asks for, added only when the caller
  // did not set them. Defaulted rather than forced: a debugger has to be able
  // to send `application/json` on purpose to find out whether a server insists
  // on the SCIM media type, and forcing the right one here would make that
  // question unaskable.
  if (bodyResult.body !== null && !hasHeader(headers, 'content-type')) {
    headers['Content-Type'] = 'application/scim+json';
  }
  if (!hasHeader(headers, 'accept')) {
    headers.Accept = 'application/scim+json, application/json';
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
// The body, serialised here rather than by axios.
//
// axios would happily serialise an object, and the reason it is done here is
// the size check: `scimMaxRequestBytes` is a number of BYTES on the wire, and
// counting them means having the bytes. It also makes the trace honest — the
// Exchange pane shows what was sent, and re-serialising for display would show
// something with different whitespace from what actually went.
//
// A body on a GET or a DELETE is refused rather than dropped. Both are legal
// HTTP and neither is used by any SCIM operation, so a caller that sent one
// has almost certainly chosen the wrong method — and a proxy that silently
// discards a body is one that makes that mistake invisible.
// ---------------------------------------------------------------------------
function encodeBody(given, method, appconfig) {
  log.debug("Entering encodeBody(). method=" + method);
  if (given === undefined || given === null || given === '') {
    log.debug("Leaving encodeBody(). No body.");
    return { ok: true, body: null };
  }
  if (method === 'GET' || method === 'DELETE') {
    log.debug("Leaving encodeBody(). Body on a " + method + ".");
    return { ok: false, error: 'A ' + method + ' carries no body in RFC ' +
        '7644, and this endpoint refuses one rather than dropping it — a ' +
        'body that is silently discarded is how the wrong method goes ' +
        'unnoticed. A query by POST is what /.search is for.' };
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
        '(scimMaxRequestBytes). A bulk of this size is worth splitting ' +
        'anyway: the far end publishes its own limit as bulk.maxPayloadSize ' +
        'in its ServiceProviderConfig, and it is usually smaller than this.' };
  }
  log.debug("Leaving encodeBody(). " + size + " bytes.");
  return { ok: true, body: text };
}

// ---------------------------------------------------------------------------
// Reading the answer, which is where the three outcomes are decided.
//
// `raw` is the body as received. It is parsed here rather than left to axios so
// that a body which is NOT JSON — an HTML error page from a load balancer in
// front of the SCIM server, which is a very common thing to meet — is reported
// as what it is instead of vanishing into a parse error.
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
    scimType: '',
    detail: '',
    notJson: parseError
  };
  if (parsed && Array.isArray(parsed.schemas) &&
      parsed.schemas.indexOf(
        'urn:ietf:params:scim:api:messages:2.0:Error') >= 0) {
    out.scimType = String(parsed.scimType || '');
    out.detail = String(parsed.detail || '');
  }
  if (!out.ok && parseError && text !== '') {
    // A non-2xx whose body is not JSON is almost always something in FRONT of
    // the SCIM server answering — a load balancer, a WAF, an authentication
    // gateway. Saying so is more useful than reporting a parse failure,
    // because the fix is in a different place entirely.
    out.detail = 'The body of this ' + status + ' is not JSON, so it did not ' +
        'come from a SCIM server: something in front of it answered. The ' +
        'first bytes are ' + JSON.stringify(text.slice(0, 120)) + '.';
  }
  log.debug("Leaving readResponse(). ok=" + out.ok +
      (out.scimType ? " scimType=" + out.scimType : ""));
  return out;
}

// ---------------------------------------------------------------------------
// What `GET /scim/limits` publishes.
//
// The same device `/ldap/limits`, `/krb5/limits` and `/tls/limits` use: the
// page says what this service will and will not do BEFORE a call fails, so a
// refusal is a sentence rather than a surprise. It is also how the page knows
// there is an api at all — a static deployment gets no answer here and turns
// the backend radio off, which is a stronger signal than a configuration flag
// because it is the api itself saying so.
// ---------------------------------------------------------------------------
function limits(appconfig) {
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
    addressPolicy: 'The same one every outbound call from this service ' +
        'obeys: api/ssrf_guard.js, installed on the shared axios instance, ' +
        'so loopback and private ranges are refused on the request AND on ' +
        'any redirect into one. It is not re-implemented here.',
    statusRule: 'A refusal by this service is a 400; a network failure is a ' +
        '502; and a SCIM error from the far end is a 200 carrying that ' +
        'status and its scimType. A 409 uniqueness, a 404, a 403 and the ' +
        '501 on /Me are the server ANSWERING, and reporting them as ' +
        'failures would make this endpoint unable to show the errors it ' +
        'exists to show.',
    whatThisIsNot: 'Not a general HTTP proxy. Five methods, no body on a GET ' +
        'or a DELETE, and the framing headers are refused.'
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
