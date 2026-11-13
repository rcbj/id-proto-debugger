// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_client.js
//
// ---------------------------------------------------------------------------
// A GNAP CLIENT INSTANCE. RFC 9635, with the proofs of sections 7.3.1,
// 7.3.2, 7.3.3 and 7.3.4, the interaction hash of section 4.2.3, RFC 9421
// signature bases, RFC 9530 content digests and RFC 8941 serialisation.
//
// This is this repository's own client. It was written from those
// documents. It shares no module with iya-sts, and nothing here is
// generated from that tree. The two evolve independently.
//
// No DOM and no network. The page and the tests decide where a
// prepared request is sent. Signing uses Web Crypto, which is the
// same API in the browser and in node, so one implementation covers
// both. A private key is a JWK. The request the caller sends is the
// string this module returns, which is the string it signed.
//
// MUTUAL TLS (section 7.3.2) signs nothing here. The key is the TLS
// client certificate, so the proof is made by whoever opens the
// connection: the api, which a page hands the certificate and its key.
// prepare() returns them beside the request as `mtls`. Section 7.3.2.1
// defines no key rotation for this method, and prepare() refuses one.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gnap_client",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var PROOFS = ["httpsig", "jwsd", "jws", "mtls"];

function webCrypto() {
  log.debug("Entering webCrypto().");
  var crypto = globalThis.crypto;
  if (!crypto || !crypto.subtle) {
    log.debug("Leaving webCrypto(). No subtle.");
    throw new Error("Web Crypto is not available in this context.");
  }
  log.debug("Leaving webCrypto().");
  return crypto;
}

function utf8(text) {
  log.debug("Entering utf8().");
  log.debug("Leaving utf8().");
  return new TextEncoder().encode(String(text));
}

function bytesToB64(bytes) {
  log.debug("Entering bytesToB64().");
  var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  var bin = "";
  var i;
  for (i = 0; i < u8.length; i++) {
    bin += String.fromCharCode(u8[i]);
  }
  log.debug("Leaving bytesToB64().");
  return btoa(bin);
}

function bytesToB64u(bytes) {
  log.debug("Entering bytesToB64u().");
  log.debug("Leaving bytesToB64u().");
  return bytesToB64(bytes).replace(/=+$/g, "").replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64uToBytes(text) {
  log.debug("Entering b64uToBytes().");
  var padded = String(text).replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) {
    padded += "=";
  }
  var bin = atob(padded);
  var out = new Uint8Array(bin.length);
  var i;
  for (i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  log.debug("Leaving b64uToBytes().");
  return out;
}

function hex(bytes) {
  log.debug("Entering hex().");
  var out = "";
  var i;
  for (i = 0; i < bytes.length; i++) {
    var one = bytes[i].toString(16);
    out += one.length === 1 ? "0" + one : one;
  }
  log.debug("Leaving hex().");
  return out;
}

function randomBytes(n) {
  log.debug("Entering randomBytes().");
  var out = new Uint8Array(n);
  webCrypto().getRandomValues(out);
  log.debug("Leaving randomBytes().");
  return out;
}

async function digest(name, bytes) {
  log.debug("Entering digest(). name=" + name);
  var algo = name === "SHA-512" ? "SHA-512" : "SHA-256";
  var hashed = await webCrypto().subtle.digest(algo, bytes);
  log.debug("Leaving digest().");
  return new Uint8Array(hashed);
}

// RFC 8941 section 4.1.6.
function sfString(value) {
  log.debug("Entering sfString().");
  log.debug("Leaving sfString().");
  return "\"" + String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") +
    "\"";
}

// RFC 9530: `sha-256=:<base64>:`.
async function contentDigest(body, alg) {
  log.debug("Entering contentDigest().");
  var name = alg || "sha-256";
  var algo = name === "sha-512" ? "SHA-512" : "SHA-256";
  if (name !== "sha-256" && name !== "sha-512") {
    log.debug("Leaving contentDigest(). Unsupported.");
    throw new Error("This client digests with sha-256 or sha-512.");
  }
  var hashed = await digest(algo, utf8(body));
  log.debug("Leaving contentDigest().");
  return name + "=:" + bytesToB64(hashed) + ":";
}

function algorithmOf(jwk) {
  log.debug("Entering algorithmOf().");
  if (jwk && jwk.alg) {
    log.debug("Leaving algorithmOf(). " + jwk.alg);
    return jwk.alg;
  }
  if (jwk && jwk.kty === "OKP") {
    log.debug("Leaving algorithmOf(). EdDSA.");
    return "EdDSA";
  }
  if (jwk && jwk.kty === "EC" && jwk.crv === "P-384") {
    log.debug("Leaving algorithmOf(). ES384.");
    return "ES384";
  }
  if (jwk && jwk.kty === "EC") {
    log.debug("Leaving algorithmOf(). ES256.");
    return "ES256";
  }
  if (jwk && jwk.kty === "oct") {
    log.debug("Leaving algorithmOf(). HS256.");
    return "HS256";
  }
  log.debug("Leaving algorithmOf(). RS256.");
  return "RS256";
}

function importParams(alg) {
  log.debug("Entering importParams(). alg=" + alg);
  var params;
  if (alg === "ES256") {
    params = { name: "ECDSA", namedCurve: "P-256" };
  } else if (alg === "ES384") {
    params = { name: "ECDSA", namedCurve: "P-384" };
  } else if (alg === "RS256") {
    params = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  } else if (alg === "PS256") {
    params = { name: "RSA-PSS", hash: "SHA-256" };
  } else if (alg === "EdDSA") {
    params = { name: "Ed25519" };
  } else if (alg === "HS256") {
    params = { name: "HMAC", hash: "SHA-256" };
  } else {
    log.debug("Leaving importParams(). Unknown.");
    throw new Error("This client signs " + alg + " with no algorithm.");
  }
  log.debug("Leaving importParams().");
  return params;
}

function signParams(alg) {
  log.debug("Entering signParams(). alg=" + alg);
  var params;
  if (alg === "ES256") {
    params = { name: "ECDSA", hash: "SHA-256" };
  } else if (alg === "ES384") {
    params = { name: "ECDSA", hash: "SHA-384" };
  } else if (alg === "PS256") {
    params = { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 };
  } else {
    params = importParams(alg);
  }
  log.debug("Leaving signParams().");
  return params;
}

function publish(jwk, alg, kid) {
  log.debug("Entering publish().");
  var out = {};
  ["kty", "crv", "x", "y", "n", "e"].forEach(function (name) {
    if (jwk[name] !== undefined) {
      out[name] = jwk[name];
    }
  });
  out.alg = alg;
  out.kid = kid;
  log.debug("Leaving publish().");
  return out;
}

async function generateKey(alg, kid) {
  log.debug("Entering generateKey(). alg=" + alg);
  var name = alg || "ES256";
  var id = kid || ("k-" + hex(randomBytes(6)));
  var params = importParams(name);
  var usages = ["sign"];
  var pair;
  if (name === "RS256" || name === "PS256") {
    pair = await webCrypto().subtle.generateKey({
      name: params.name,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    }, true, usages);
  } else if (name === "HS256") {
    var secret = await webCrypto().subtle.generateKey(
      { name: "HMAC", hash: "SHA-256", length: 256 }, true, ["sign"]);
    var secretJwk = await webCrypto().subtle.exportKey("jwk", secret);
    secretJwk.alg = "HS256";
    secretJwk.kid = id;
    log.debug("Leaving generateKey(). HMAC.");
    return {
      alg: "HS256",
      kid: id,
      privateJwk: secretJwk,
      publicJwk: null,
      reference: id
    };
  } else {
    pair = await webCrypto().subtle.generateKey(params, true, usages);
  }
  var privateJwk = await webCrypto().subtle.exportKey(
    "jwk", pair.privateKey);
  var publicJwk = await webCrypto().subtle.exportKey(
    "jwk", pair.publicKey);
  privateJwk.alg = name;
  privateJwk.kid = id;
  publicJwk = publish(publicJwk, name, id);
  log.debug("Leaving generateKey().");
  return {
    alg: name,
    kid: id,
    privateJwk: privateJwk,
    publicJwk: publicJwk,
    reference: ""
  };
}

function recordFromPrivateJwk(jwk, reference) {
  log.debug("Entering recordFromPrivateJwk().");
  if (reference) {
    log.debug("Leaving recordFromPrivateJwk(). Reference.");
    return {
      alg: "HS256",
      kid: reference,
      privateJwk: jwk || null,
      publicJwk: null,
      reference: reference
    };
  }
  var alg = algorithmOf(jwk);
  var kid = (jwk && jwk.kid) || ("k-" + hex(randomBytes(6)));
  var copy = {};
  Object.keys(jwk || {}).forEach(function (name) {
    copy[name] = jwk[name];
  });
  copy.alg = alg;
  copy.kid = kid;
  log.debug("Leaving recordFromPrivateJwk().");
  return {
    alg: alg,
    kid: kid,
    privateJwk: copy,
    publicJwk: publish(copy, alg, kid),
    reference: ""
  };
}

// The first CERTIFICATE block of a PEM text, as RFC 9635 section 7.1's
// `cert`: the DER in standard base64, which is the PEM body unwrapped.
function certificateBase64(pem) {
  log.debug("Entering certificateBase64().");
  var match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/
    .exec(String(pem || ""));
  if (!match) {
    log.debug("Leaving certificateBase64(). No certificate.");
    throw new Error("The client certificate is not a PEM certificate.");
  }
  var body = match[1].replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
    log.debug("Leaving certificateBase64(). Not base64.");
    throw new Error("The client certificate's PEM body is not base64.");
  }
  log.debug("Leaving certificateBase64().");
  return body;
}

// A client instance proved by mutual TLS. The private key is PEM and
// is only ever handed to whoever opens the connection.
function recordFromCertificate(certificatePem, privateKeyPem) {
  log.debug("Entering recordFromCertificate().");
  var cert = certificateBase64(certificatePem);
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(
      String(privateKeyPem || ""))) {
    log.debug("Leaving recordFromCertificate(). No key.");
    throw new Error("The client certificate needs its private key, " +
      "in PEM.");
  }
  log.debug("Leaving recordFromCertificate().");
  return {
    alg: "mtls",
    kid: "",
    privateJwk: null,
    publicJwk: null,
    reference: "",
    certificate: cert,
    certificatePem: String(certificatePem),
    privateKeyPem: String(privateKeyPem)
  };
}

function keyObject(record, proof) {
  log.debug("Entering keyObject().");
  if (record.reference) {
    log.debug("Leaving keyObject(). Reference.");
    return record.reference;
  }
  if (proof === "mtls" || record.certificate) {
    if (!record.certificate) {
      log.debug("Leaving keyObject(). mtls without a certificate.");
      throw new Error("The mtls proof needs a client certificate.");
    }
    log.debug("Leaving keyObject(). Certificate.");
    return { proof: "mtls", cert: record.certificate };
  }
  log.debug("Leaving keyObject().");
  return { proof: proof || "httpsig", jwk: record.publicJwk };
}

async function signRecord(record, data) {
  log.debug("Entering signRecord().");
  var alg = record.alg || algorithmOf(record.privateJwk);
  var key = await webCrypto().subtle.importKey(
    "jwk", record.privateJwk, importParams(alg), false, ["sign"]);
  var signed = await webCrypto().subtle.sign(
    signParams(alg), key, data);
  log.debug("Leaving signRecord().");
  return new Uint8Array(signed);
}

function componentValue(identifier, message) {
  log.debug("Entering componentValue().");
  var match = String(identifier).match(/^"([^"]+)"(.*)$/);
  if (!match) {
    log.debug("Leaving componentValue(). Bad identifier.");
    throw new Error("Not a signature component: " + identifier);
  }
  var name = match[1];
  var params = match[2];
  if (name === "@method") {
    log.debug("Leaving componentValue(). Method.");
    return message.method.toUpperCase();
  }
  if (name === "@target-uri") {
    log.debug("Leaving componentValue(). Target.");
    return message.url;
  }
  if (name === "@authority") {
    log.debug("Leaving componentValue(). Authority.");
    return new URL(message.url).host.toLowerCase();
  }
  var header = headerValue(message.headers, name);
  if (header === undefined) {
    log.debug("Leaving componentValue(). Missing " + name);
    throw new Error("The signature covers " + name +
      " and the request has no such field.");
  }
  var keyParam = params.match(/;key="([^"]+)"/);
  if (keyParam) {
    var members = splitDictionary(String(header));
    log.debug("Leaving componentValue(). Dictionary member.");
    return members[keyParam[1]];
  }
  log.debug("Leaving componentValue().");
  return String(header).trim();
}

function headerValue(headers, name) {
  log.debug("Entering headerValue(). name=" + name);
  var found;
  Object.keys(headers || {}).forEach(function (key) {
    if (key.toLowerCase() === name) {
      found = headers[key];
    }
  });
  log.debug("Leaving headerValue().");
  return found;
}

function splitDictionary(text) {
  log.debug("Entering splitDictionary().");
  var out = {};
  var depth = 0;
  var quoted = false;
  var start = 0;
  function push(piece) {
    log.debug("Entering push().");
    var trimmed = piece.trim();
    var eq = trimmed.indexOf("=");
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
    log.debug("Leaving push().");
  }
  var i;
  for (i = 0; i < text.length; i++) {
    var c = text[i];
    if (c === "\"" && text[i - 1] !== "\\") {
      quoted = !quoted;
    } else if (!quoted && c === "(") {
      depth++;
    } else if (!quoted && c === ")") {
      depth--;
    } else if (!quoted && depth === 0 && c === ",") {
      push(text.slice(start, i));
      start = i + 1;
    }
  }
  push(text.slice(start));
  log.debug("Leaving splitDictionary().");
  return out;
}

function signatureParams(components, params) {
  log.debug("Entering signatureParams().");
  var out = "(" + components.join(" ") + ")";
  ["created", "expires", "nonce", "keyid", "tag", "alg"].forEach(
    function (name) {
      if (params[name] === undefined) {
        return;
      }
      out += ";" + name + "=" +
        (typeof params[name] === "number" ? String(params[name])
          : sfString(params[name]));
    });
  log.debug("Leaving signatureParams().");
  return out;
}

function signatureBase(components, message, params) {
  log.debug("Entering signatureBase().");
  var lines = components.map(function (identifier) {
    return identifier + ": " + componentValue(identifier, message);
  });
  var serialised = signatureParams(components, params);
  lines.push("\"@signature-params\": " + serialised);
  log.debug("Leaving signatureBase().");
  return { base: lines.join("\n"), serialised: serialised };
}

async function httpsign(message, record, opts) {
  log.debug("Entering httpsign().");
  var options = opts || {};
  var label = options.label || "sig1";
  var components = ["\"@method\"", "\"@target-uri\""];
  if (message.body && message.body.length) {
    components.push("\"content-digest\"");
  }
  if (headerValue(message.headers, "authorization") !== undefined) {
    components.push("\"authorization\"");
  }
  (options.extraComponents || []).forEach(function (one) {
    components.push(one);
  });
  var params = {
    created: options.created !== undefined ? options.created
      : Math.floor(Date.now() / 1000),
    nonce: options.nonce === null ? undefined
      : (options.nonce || bytesToB64u(randomBytes(9))),
    keyid: options.keyid !== undefined ? options.keyid : record.kid,
    tag: options.tag === null ? undefined : (options.tag || "gnap")
  };
  if (options.alg) {
    params.alg = options.alg;
  }
  var built = signatureBase(components, message, params);
  var signature = await signRecord(record, utf8(built.base));
  var input = label + "=" + built.serialised;
  var value = label + "=:" + bytesToB64(signature) + ":";
  var existingInput = headerValue(message.headers, "signature-input");
  var existing = headerValue(message.headers, "signature");
  message.headers["Signature-Input"] = existingInput
    ? existingInput + ", " + input : input;
  message.headers.Signature = existing ? existing + ", " + value : value;
  log.debug("Leaving httpsign().");
  return { label: label, base: built.base };
}

async function jwsCompact(header, payloadBytes, record) {
  log.debug("Entering jwsCompact().");
  var h = bytesToB64u(utf8(JSON.stringify(header)));
  var p = bytesToB64u(payloadBytes);
  var signature = await signRecord(record, utf8(h + "." + p));
  log.debug("Leaving jwsCompact().");
  return h + "." + p + "." + bytesToB64u(signature);
}

async function jwsHeader(message, record, typ, token, created) {
  log.debug("Entering jwsHeader().");
  var header = {
    alg: record.alg,
    kid: record.kid,
    typ: typ,
    htm: message.method.toUpperCase(),
    uri: message.url,
    created: created || Math.floor(Date.now() / 1000)
  };
  if (token) {
    header.ath = bytesToB64u(await digest("SHA-256", utf8(token)));
  }
  log.debug("Leaving jwsHeader().");
  return header;
}

async function jwsd(message, record, token, typ) {
  log.debug("Entering jwsd().");
  var body = message.body && message.body.length
    ? await digest("SHA-256", utf8(message.body)) : new Uint8Array(0);
  var compact = await jwsCompact(
    await jwsHeader(message, record, typ || "gnap-binding-jwsd", token),
    body, record);
  log.debug("Leaving jwsd().");
  return compact;
}

// RFC 9635 section 4.2.3. The four lines are the client nonce, the
// authorization server's nonce, the interaction reference and the
// grant endpoint, joined by newlines.
async function interactionHash(clientNonce, serverNonce, interactRef,
    grantEndpoint, method) {
  log.debug("Entering interactionHash().");
  var name = method || "sha-256";
  if (name !== "sha-256" && name !== "sha-512") {
    log.debug("Leaving interactionHash(). Unsupported.");
    throw new Error("This client hashes interactions with sha-256 " +
      "or sha-512.");
  }
  var algo = name === "sha-512" ? "SHA-512" : "SHA-256";
  var lines = [clientNonce, serverNonce, interactRef, grantEndpoint]
    .join("\n");
  var hashed = await digest(algo, utf8(lines));
  log.debug("Leaving interactionHash().");
  return bytesToB64u(hashed);
}

function withClient(body, record, proof, display, classId) {
  log.debug("Entering withClient().");
  var out = JSON.parse(JSON.stringify(body || {}));
  if (typeof out.client === "string") {
    log.debug("Leaving withClient(). Instance id.");
    return out;
  }
  if (!out.client || typeof out.client !== "object") {
    out.client = {};
  }
  if (out.client.key === undefined) {
    out.client.key = keyObject(record, proof);
  }
  if (display && !out.client.display) {
    out.client.display = display;
  }
  if (classId && !out.client.class_id) {
    out.client.class_id = classId;
  }
  log.debug("Leaving withClient().");
  return out;
}

// The default sample asks for SUBJECT INFORMATION only (RFC 9635
// section 2.2), with an interaction. It is the one request iya-sts
// grants with no administrator involved: every access right it issues
// a token for must name a registered resource server (STS-GNAP-0903,
// 0904), and the one it needs no entry for, its Shared Signals
// transmitter, is a protected scope an administrator declares per
// application (STS-GNAP-0719). That second request is ssfSampleRequest().
function sampleRequest(finishUri, nonce) {
  log.debug("Entering sampleRequest().");
  log.debug("Leaving sampleRequest().");
  return {
    subject: {
      sub_id_formats: ["opaque"]
    },
    interact: {
      start: ["redirect", "user_code"],
      finish: {
        method: "redirect",
        uri: finishUri,
        nonce: nonce
      }
    }
  };
}

// An access token for iya-sts's Shared Signals transmitter (`ssf.read`),
// which is a resource server a GNAP token is presented to (GET
// /ssf/stream with the GNAP scheme). It is granted only once an
// administrator has declared ssf.read in the application's
// oauthAllowedScope.
function ssfSampleRequest(finishUri, nonce) {
  log.debug("Entering ssfSampleRequest().");
  log.debug("Leaving ssfSampleRequest().");
  return {
    access_token: {
      access: ["ssf.read"]
    },
    subject: {
      sub_id_formats: ["opaque"]
    },
    interact: {
      start: ["redirect", "user_code"],
      finish: {
        method: "redirect",
        uri: finishUri,
        nonce: nonce
      }
    }
  };
}

function errorOf(json) {
  log.debug("Entering errorOf().");
  if (!json || json.error === undefined || json.error === null) {
    log.debug("Leaving errorOf(). None.");
    return "";
  }
  if (typeof json.error === "string") {
    log.debug("Leaving errorOf(). String.");
    return json.error;
  }
  log.debug("Leaving errorOf().");
  return String(json.error.code || "");
}

function finishFromUrl(url) {
  log.debug("Entering finishFromUrl().");
  var parsed;
  try {
    parsed = new URL(url, "https://localhost/");
  } catch (e) {
    log.debug("Leaving finishFromUrl(). Not a URL.");
    return { hash: "", ref: "" };
  }
  log.debug("Leaving finishFromUrl().");
  return {
    hash: parsed.searchParams.get("hash") || "",
    ref: parsed.searchParams.get("interact_ref") || ""
  };
}

// RFC 9421 section 2.2.2: `@target-uri` is the full target URI of the
// request as it is sent. WHATWG URL serialisation is what fetch and
// node send: scheme and host lower-cased, the default port dropped, an
// empty path made "/". A fragment is never sent, so it is removed.
// prepare() sends this string, signs it, and puts it in a JWS `uri`,
// so the three cannot disagree with each other or with the wire.
function targetUri(url) {
  log.debug("Entering targetUri().");
  var parsed;
  try {
    parsed = new URL(String(url));
  } catch (e) {
    log.debug("Leaving targetUri(). Not absolute.");
    throw new Error("The request URL is not an absolute URL: " + url);
  }
  parsed.hash = "";
  log.debug("Leaving targetUri().");
  return parsed.href;
}

async function prepare(record, method, rawUrl, opts) {
  log.debug("Entering prepare().");
  var url = targetUri(rawUrl);
  var options = opts || {};
  var proof = options.proof || "httpsig";
  if (PROOFS.indexOf(proof) < 0 && options.sign !== false) {
    log.debug("Leaving prepare(). Unknown proof.");
    throw new Error("proof must be httpsig, jwsd, jws or mtls.");
  }
  if (proof === "mtls" && options.sign !== false) {
    if (!record || !record.certificate) {
      log.debug("Leaving prepare(). mtls without a certificate.");
      throw new Error("The mtls proof needs a client certificate and " +
        "its private key.");
    }
    if (options.rotateTo) {
      log.debug("Leaving prepare(). mtls rotation.");
      throw new Error("RFC 9635 section 7.3.2.1 defines no key " +
        "rotation for mtls. Rotate the certificate by deployment.");
    }
  }
  var headers = {};
  Object.keys(options.headers || {}).forEach(function (name) {
    headers[name] = options.headers[name];
  });
  var body = "";
  if (options.body !== undefined && options.body !== null) {
    body = String(options.body);
  } else if (options.json !== undefined) {
    body = typeof options.json === "string" ? options.json
      : JSON.stringify(options.json);
  }
  var message = { method: method, url: url, headers: headers, body: body };
  if (options.token) {
    headers.Authorization = (options.scheme || "GNAP") + " " +
      options.token;
  }
  var signatures = [];
  if (options.sign !== false) {
    if (proof === "httpsig") {
      if (body.length) {
        headers["Content-Type"] = headers["Content-Type"] ||
          "application/json";
        headers["Content-Digest"] = await contentDigest(
          body, options.digestAlg);
      }
      signatures.push(await httpsign(message, record, options.httpsig ||
        {}));
      if (options.rotateTo) {
        signatures.push(await httpsign(message, options.rotateTo, {
          label: "new-key",
          tag: "gnap-rotate",
          extraComponents: [
            "\"signature\";key=\"sig1\"",
            "\"signature-input\";key=\"sig1\""
          ]
        }));
      }
    } else if (proof === "jwsd") {
      if (body.length) {
        headers["Content-Type"] = "application/json";
      }
      if (options.rotateTo) {
        var inner = await jwsd(message, record, options.token,
          "gnap-binding-rotation-jwsd");
        headers["Detached-JWS"] = await jwsCompact(
          await jwsHeader(message, options.rotateTo,
            "gnap-binding-jwsd", options.token),
          utf8(inner), options.rotateTo);
      } else {
        headers["Detached-JWS"] = await jwsd(message, record,
          options.token, options.jwsTyp);
      }
    } else if (proof === "mtls") {
      // Nothing to sign. The TLS handshake is the proof.
      if (body.length) {
        headers["Content-Type"] = headers["Content-Type"] ||
          "application/json";
      }
    } else if (proof === "jws") {
      if (body.length) {
        var typ = options.rotateTo ? "gnap-binding-rotation-jws"
          : (options.jwsTyp || "gnap-binding-jws");
        var compact = await jwsCompact(
          await jwsHeader(message, record, typ, options.token),
          utf8(body), record);
        if (options.rotateTo) {
          compact = await jwsCompact(
            await jwsHeader(message, options.rotateTo,
              "gnap-binding-jws", options.token),
            utf8(compact), options.rotateTo);
        }
        body = compact;
        message.body = body;
        headers["Content-Type"] = "application/jose";
      } else {
        headers["Detached-JWS"] = await jwsd(message, record,
          options.token, "gnap-binding-jws");
      }
    }
  } else if (body.length) {
    headers["Content-Type"] = headers["Content-Type"] ||
      "application/json";
  }
  var prepared = {
    method: String(method).toUpperCase(),
    url: url,
    headers: headers,
    body: body,
    signatures: signatures
  };
  if (proof === "mtls" && options.sign !== false) {
    prepared.mtls = {
      certificatePem: record.certificatePem,
      privateKeyPem: record.privateKeyPem
    };
  }
  log.debug("Leaving prepare().");
  return prepared;
}

module.exports = {
  PROOFS: PROOFS,
  generateKey: generateKey,
  recordFromPrivateJwk: recordFromPrivateJwk,
  recordFromCertificate: recordFromCertificate,
  certificateBase64: certificateBase64,
  keyObject: keyObject,
  contentDigest: contentDigest,
  signatureBase: signatureBase,
  interactionHash: interactionHash,
  withClient: withClient,
  sampleRequest: sampleRequest,
  ssfSampleRequest: ssfSampleRequest,
  errorOf: errorOf,
  finishFromUrl: finishFromUrl,
  prepare: prepare,
  targetUri: targetUri,
  bytesToB64u: bytesToB64u,
  b64uToBytes: b64uToBytes
};
