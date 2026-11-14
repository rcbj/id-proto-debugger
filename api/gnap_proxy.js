// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gnap_proxy.js
//
// ---------------------------------------------------------------------------
// WHAT `POST /gnap/call` WILL AND WILL NOT SEND. IT DECIDES; server.js
// PERFORMS.
//
// The GNAP page signs the request in the browser. The private key never
// comes here. This endpoint forwards the bytes the page already signed:
// the method, the URL, the headers and the body string. A GNAP proof
// covers those bytes (RFC 9421 `@target-uri` and `content-digest`, or a
// JWS over the same body), so a body that arrived as a string is
// forwarded unchanged. An object is JSON-encoded once, and that encoding
// is what the caller would have had to sign.
//
// This file has no axios and no network. The address policy is the one
// on the shared agents in server.js. It is not re-implemented here.
//
// MUTUAL TLS (RFC 9635 section 7.3.2) is the one proof this service
// takes part in. The key IS the TLS client certificate, and a browser
// cannot choose which certificate a fetch presents, so the page sends
// the certificate and its private key here and server.js presents them
// on a connection opened for this one call (the way POST /tls/connect
// does for the PKI page). The pair is checked here before anything is
// sent: both or neither, PEM, a bounded size, a key that belongs to the
// certificate, and an https URL. Neither is logged or kept.
//
// A refusal by this service is a 400. A network failure is a 502. A
// GNAP error from the authorization server is a 200 carrying that
// status and the error code. Those refusals are the answer the page
// is here to show.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "gnap_proxy",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// OPTIONS is discovery (RFC 9635 section 9). GET reads a discovery
// document or a key set. POST, PATCH and DELETE are the grant, the
// continuation, the modification and the revocation.
var METHODS = ["GET", "POST", "PATCH", "DELETE", "OPTIONS"];

var REFUSED_HEADERS = {
  host: "It would send the request to a different virtual host than " +
    "the URL names, which is how a proxy is turned into an open one.",
  "content-length": "The body framing is this service's to set. A " +
    "caller that could set it could smuggle a second request inside " +
    "the first.",
  "transfer-encoding": "Body framing again, and the other half of " +
    "the same smuggling pair.",
  connection: "Hop-by-hop (RFC 7230 section 6.1). It belongs to the " +
    "connection this service opens, not to the request being carried.",
  "keep-alive": "Hop-by-hop (RFC 7230 section 6.1). It describes the " +
    "connection this service opens.",
  upgrade: "Hop-by-hop, and it asks to stop speaking HTTP on a " +
    "connection this service owns.",
  te: "Hop-by-hop. It negotiates a transfer coding for this hop.",
  trailer: "Hop-by-hop. It announces fields that arrive after a " +
    "chunked body.",
  "proxy-authorization": "It authenticates to a proxy rather than to " +
    "the authorization server, so forwarding it would send this " +
    "service's hop credentials somewhere they do not belong."
};

var TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

var DEFAULT_MAX_REQUEST_BYTES = 262144;

// A certificate chain or a private key, in PEM. Large RSA keys and a
// chain of a few certificates are well under this.
var MAX_PEM_BYTES = 65536;

var nodeCrypto = require("crypto");

function maxRequestBytes(appconfig) {
  log.debug("Entering maxRequestBytes().");
  var configured = appconfig && appconfig.gnapMaxRequestBytes;
  if (typeof configured !== "number" || !isFinite(configured) ||
      configured <= 0) {
    if (configured !== undefined) {
      log.warn("Ignoring gnapMaxRequestBytes=" +
        JSON.stringify(configured) +
        " — it must be a positive number. Using " +
        DEFAULT_MAX_REQUEST_BYTES + ".");
    }
    log.debug("Leaving maxRequestBytes(). Default.");
    return DEFAULT_MAX_REQUEST_BYTES;
  }
  log.debug("Leaving maxRequestBytes(). " + configured);
  return configured;
}

function describeRequest(input, appconfig) {
  log.debug("Entering describeRequest().");
  var given = input || {};
  var url = String(given.url || "").trim();
  if (url === "") {
    log.debug("Leaving describeRequest(). No url.");
    return { ok: false, error: "url is required. It is the absolute " +
      "URL of the GNAP endpoint the page signed." };
  }
  if (!/^https?:\/\//i.test(url)) {
    log.debug("Leaving describeRequest(). Not absolute http(s).");
    return { ok: false, error: "url must be an absolute http:// or " +
      "https:// URL. A relative one has no host for this service to " +
      "resolve, and resolving it against this service's own address " +
      "would make this endpoint a way to reach the api's own routes." };
  }
  var method = String(given.method || "POST").toUpperCase();
  if (METHODS.indexOf(method) < 0) {
    log.debug("Leaving describeRequest(). Method refused.");
    return { ok: false, error: "method must be one of " +
      METHODS.join(", ") + ". RFC 9635 uses those five." };
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
  var mtls = clientCertificate(given, url);
  if (!mtls.ok) {
    log.debug("Leaving describeRequest(). Client certificate refused.");
    return mtls;
  }
  var headers = headerResult.headers;
  if (bodyResult.body !== null && !hasHeader(headers, "content-type")) {
    headers["Content-Type"] = "application/json";
  }
  var out = {
    ok: true,
    method: method,
    url: url,
    headers: headers,
    body: bodyResult.body,
    sslValidate: !(given.sslValidate === false ||
      given.sslValidate === "false"),
    clientCertificatePem: mtls.certificatePem,
    clientKeyPem: mtls.keyPem
  };
  log.debug("Leaving describeRequest(). " + out.method + " " + out.url);
  return out;
}

function clientCertificate(given, url) {
  log.debug("Entering clientCertificate().");
  var cert = given.clientCertificatePem;
  var key = given.clientKeyPem;
  var none = (cert === undefined || cert === null || cert === "") &&
    (key === undefined || key === null || key === "");
  if (none) {
    log.debug("Leaving clientCertificate(). None.");
    return { ok: true, certificatePem: null, keyPem: null };
  }
  if (typeof cert !== "string" || typeof key !== "string" || !cert ||
      !key) {
    log.debug("Leaving clientCertificate(). Half a pair.");
    return { ok: false, error: "clientCertificatePem and clientKeyPem " +
      "go together. The mtls proof (RFC 9635 section 7.3.2) is a TLS " +
      "client certificate and the key that proves it." };
  }
  if (Buffer.byteLength(cert, "utf8") > MAX_PEM_BYTES ||
      Buffer.byteLength(key, "utf8") > MAX_PEM_BYTES) {
    log.debug("Leaving clientCertificate(). Too large.");
    return { ok: false, error: "The client certificate and key are " +
      "each limited to " + MAX_PEM_BYTES + " bytes of PEM." };
  }
  if (!/^https:\/\//i.test(url)) {
    log.debug("Leaving clientCertificate(). Not https.");
    return { ok: false, error: "A client certificate is presented in " +
      "a TLS handshake, and an http:// URL has none. Use https://." };
  }
  var parsed;
  var privateKey;
  try {
    parsed = new nodeCrypto.X509Certificate(cert);
  } catch (e) {
    log.debug("Leaving clientCertificate(). Not a certificate.");
    return { ok: false, error: "clientCertificatePem is not a PEM " +
      "certificate: " + e.message };
  }
  try {
    privateKey = nodeCrypto.createPrivateKey(key);
  } catch (e) {
    log.debug("Leaving clientCertificate(). Not a key.");
    return { ok: false, error: "clientKeyPem is not an unencrypted PEM " +
      "private key: " + e.message };
  }
  if (!parsed.checkPrivateKey(privateKey)) {
    log.debug("Leaving clientCertificate(). Not a pair.");
    return { ok: false, error: "clientKeyPem is not the private key of " +
      "the certificate in clientCertificatePem." };
  }
  log.debug("Leaving clientCertificate(). A pair.");
  return { ok: true, certificatePem: cert, keyPem: key };
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
  if (typeof source !== "object" || Array.isArray(source)) {
    log.debug("Leaving sanitizeHeaders(). Not an object.");
    return { ok: false, error: "headers must be an object of name " +
      "to value." };
  }
  var names = Object.keys(source);
  var i;
  for (i = 0; i < names.length; i++) {
    var name = names[i];
    var lower = String(name).toLowerCase();
    if (!TOKEN.test(String(name))) {
      log.debug("Leaving sanitizeHeaders(). Bad name.");
      return { ok: false, error: "The header name " +
        JSON.stringify(name) + " is not a token (RFC 7230 section " +
        "3.2.6), so it is not a header name at all." };
    }
    if (Object.prototype.hasOwnProperty.call(REFUSED_HEADERS, lower)) {
      log.debug("Leaving sanitizeHeaders(). Refused " + lower);
      return { ok: false, error: "This endpoint will not forward " +
        "the " + name + " header. " + REFUSED_HEADERS[lower] };
    }
    var value = source[name];
    if (value === undefined || value === null) {
      continue;
    }
    var text = String(value);
    if (/[\r\n]/.test(text)) {
      log.debug("Leaving sanitizeHeaders(). CR/LF.");
      return { ok: false, error: "The value of " + name +
        " contains a carriage return or a line feed. That is " +
        "header injection, and it is refused." };
    }
    out[name] = text;
  }
  log.debug("Leaving sanitizeHeaders(). " + Object.keys(out).length +
    " header(s).");
  return { ok: true, headers: out };
}

function encodeBody(given, method, appconfig) {
  log.debug("Entering encodeBody(). method=" + method);
  if (given === undefined || given === null || given === "") {
    log.debug("Leaving encodeBody(). No body.");
    return { ok: true, body: null };
  }
  if (method === "GET" || method === "OPTIONS") {
    log.debug("Leaving encodeBody(). Body on " + method + ".");
    return { ok: false, error: "A " + method + " carries no body " +
      "in RFC 9635, and this endpoint refuses one rather than " +
      "dropping it. Discovery is OPTIONS on the grant endpoint, " +
      "with an empty body." };
  }
  var text;
  if (typeof given === "string") {
    text = given;
  } else {
    try {
      text = JSON.stringify(given);
    } catch (e) {
      log.debug("Leaving encodeBody(). Not serialisable.");
      return { ok: false, error: "The body could not be serialised " +
        "as JSON: " + e.message };
    }
  }
  var size = Buffer.byteLength(text, "utf8");
  var limit = maxRequestBytes(appconfig);
  if (size > limit) {
    log.debug("Leaving encodeBody(). Too large.");
    return { ok: false, error: "This request body is " + size +
      " bytes and this service will forward at most " + limit +
      " (gnapMaxRequestBytes)." };
  }
  log.debug("Leaving encodeBody(). " + size + " bytes.");
  return { ok: true, body: text };
}

function readResponse(status, headers, raw) {
  log.debug("Entering readResponse(). status=" + status);
  var text = (raw === null || raw === undefined) ? "" : String(raw);
  var parsed = null;
  var parseError = "";
  if (text !== "") {
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      parsed = null;
      parseError = e.message;
    }
  }
  var code = "";
  var description = "";
  if (parsed && typeof parsed === "object" && parsed.error) {
    if (typeof parsed.error === "string") {
      code = parsed.error;
    } else {
      code = String(parsed.error.code || "");
      description = String(parsed.error.description || "");
    }
  }
  log.debug("Leaving readResponse().");
  return {
    status: status,
    ok: status >= 200 && status < 300,
    headers: headers || {},
    body: parsed,
    rawBody: text,
    error: code,
    description: description,
    noBody: text === "",
    notJson: parseError
  };
}

function limits(appconfig) {
  log.debug("Entering limits().");
  var out = {
    methods: METHODS.slice(0),
    refusedHeaders: Object.keys(REFUSED_HEADERS).sort(),
    maxRequestBytes: maxRequestBytes(appconfig),
    maxResponseBytes: (appconfig && appconfig.maxContentLength) || null,
    callTimeoutMs: (appconfig && appconfig.callTimeout) || null,
    connectionTimeoutMs: (appconfig &&
      appconfig.connectionTimeout) || null,
    maxRedirects: (appconfig && appconfig.maxRedirects) === undefined
      ? null : appconfig.maxRedirects,
    sslValidateDefault: true,
    // Whether the address layers of api/ssrf_guard.js are on here. A
    // stack whose authorization server is a private address turns them
    // off, and a caller should be told so rather than infer it.
    addressPolicyEnabled:
      !!(appconfig && appconfig.blockPrivateNetworkCalls !== false),
    proofs: ["httpsig", "jwsd", "jws", "mtls"],
    mtls: "clientCertificatePem and clientKeyPem, presented on a " +
      "connection opened for that one call. https only. At most " +
      MAX_PEM_BYTES + " bytes each.",
    statusRule: "A refusal by this service is a 400. A network " +
      "failure is a 502. A GNAP error from the authorization server " +
      "is a 200 carrying that status and the error code."
  };
  log.debug("Leaving limits().");
  return out;
}

module.exports = {
  describeRequest: describeRequest,
  readResponse: readResponse,
  limits: limits,
  METHODS: METHODS
};
