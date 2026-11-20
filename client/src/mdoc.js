// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: mdoc.js
//
// ---------------------------------------------------------------------------
// ISO/IEC 18013-5 mdoc (`mso_mdoc`), the wallet's side: reading an issued
// credential, checking it, and presenting part of it over OpenID4VP 1.0
// (Appendix B.2).
//
// An mdoc credential, as OpenID4VCI 1.0 Appendix A.2 delivers it, is the
// base64url of a CBOR IssuerSigned:
//
//   IssuerSigned = { "nameSpaces":
//                      { ns: [ #6.24(bstr .cbor IssuerSignedItem) ] },
//                    "issuerAuth": COSE_Sign1 over #6.24(bstr .cbor MSO) }
//   IssuerSignedItem = { "digestID", "random", "elementIdentifier",
//                        "elementValue" }
//
// The Mobile Security Object (MSO) holds a digest of every item, by
// namespace and digestID, and the DEVICE KEY the holder proves possession of.
// Selective disclosure is leaving items out: what is sent is a subset of the
// tagged items, BYTE FOR BYTE as issued (their digests are over those bytes,
// so an item re-encoded "equivalently" no longer matches), and the issuerAuth
// unchanged.
//
// A presentation is a DeviceResponse whose one Document adds a deviceSigned
// part: a COSE_Sign1, detached, by the device key over
//
//   DeviceAuthenticationBytes = #6.24(bstr .cbor
//     ["DeviceAuthentication", SessionTranscript, docType,
//      DeviceNameSpacesBytes])
//
// and OpenID4VP's SessionTranscript (Appendix B.2.6.1) is
//
//   [null, null, ["OpenID4VPHandover",
//     SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]]
//
// where jwkThumbprint is the RFC 7638 thumbprint, as a byte string, of the
// Verifier's key the response is ENCRYPTED to under direct_post.jwt, and null
// otherwise. That is what makes a presentation unusable at another Verifier,
// for another request, or decrypted by anybody else: there is no nonce or aud
// field to edit, every one of them is inside the device signature.
//
// No DOM: tests/mdoc_engine.js drives it in node.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "mdoc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var cbor = require("./cbor");
var cose = require("./cose");
var bytes = require("./crypto_bytes");
var dpop = require("./dpop");
var jws = require("./jws");
// Digests and the device signature are crypto_provider.js's (#463 step 4):
// pure JS, so an mdoc is presented and checked on every deployment, plain
// HTTP included, where crypto.subtle does not exist.
var provider = require("./crypto_provider");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");

var FORMAT = "mso_mdoc";
var Tagged = cbor.Tagged;
// COSE: alg (1), x5chain (33); ES256 is -7.
var COSE_ALG = 1;
var COSE_X5CHAIN = 33;
var ES256 = -7;

// The COSE signature algorithms an issuerAuth or a deviceSignature may name
// (#469, C8), each with the jws.js row that verifies it in pure JavaScript.
// -7, -35 and -36 are the IANA COSE registry's ECDSA-with-SHA-2 values, -8
// is EdDSA; -9, -51, -52 and -19 are the FULLY SPECIFIED ones of
// draft-ietf-jose-fully-specified-algorithms (RFC 9864): ESP256 is ECDSA on
// P-256 with SHA-256, and so on. HAIP 1.0 section 7 has a Verifier support
// "COSE algorithm identifier -7 or -9, as applicable", and OpenID4VP 1.0
// Appendix B.2.2's own example advertises [-9, -50]. Until #469 this file
// verified -7 and refused every other value.
var COSE_SIGNATURE_ALGS = {
  "-7": { name: "ES256", jws: "ES256" },
  "-9": { name: "ESP256", jws: "ES256" },
  "-35": { name: "ES384", jws: "ES384" },
  "-51": { name: "ESP384", jws: "ES384" },
  "-36": { name: "ES512", jws: "ES512" },
  "-52": { name: "ESP512", jws: "ES512" },
  "-8": { name: "EdDSA", jws: "EdDSA-Ed25519" },
  "-19": { name: "Ed25519", jws: "EdDSA-Ed25519" }
};
var COSE_SIGNATURE_ALG_IDS = [-7, -9, -35, -51, -36, -52, -8, -19];

// The MSO's digestAlgorithm (ISO/IEC 18013-5 section 9.1.2.5): "SHA-256",
// "SHA-384" or "SHA-512". Pure JavaScript.
var MSO_DIGESTS = {
  "SHA-256": nobleSha256,
  "SHA-384": nobleSha512.sha384,
  "SHA-512": nobleSha512.sha512
};

// ---------------------------------------------------------------------------
// CBOR encoding (RFC 8949), deterministic as section 4.2.1 has it: shortest
// heads and map keys ordered by their encoded bytes. cbor.js only decodes.
//
// Recursive and called per item, so these carry no Entering/Leaving pair —
// the hot-path exception the code style allows, stated as it requires.
// ---------------------------------------------------------------------------
function head(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 0x100) return [major << 5 | 24, n];
  if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) {
    return [major << 5 | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff,
            (n >> 8) & 0xff, n & 0xff];
  }
  var hi = Math.floor(n / 0x100000000);
  var lo = n >>> 0;
  return [major << 5 | 27, (hi >>> 24) & 0xff, (hi >> 16) & 0xff,
          (hi >> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >> 16) & 0xff,
          (lo >> 8) & 0xff, lo & 0xff];
}

function compareBytes(a, b) {
  var n = Math.min(a.length, b.length);
  for (var i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

// A CBOR simple value other than false/true/null/undefined, which SD-CWT
// needs as a map key (simple(59), redacted_claim_keys). A class, so that a
// plain object that happens to have a "simple" member is never mistaken
// for one.
function Simple(value) {
  this.simple = value;
}

function encodeParts(v) {
  if (v === null || v === undefined) return [v === null ? 0xf6 : 0xf7];
  if (v instanceof Simple) {
    return v.simple < 24 ? [0xe0 | v.simple] : [0xf8, v.simple];
  }
  if (v === false) return [0xf4];
  if (v === true) return [0xf5];
  if (v instanceof Uint8Array) {
    return head(2, v.length).concat(Array.prototype.slice.call(v));
  }
  if (v instanceof Tagged) return head(6, v.tag).concat(encodeParts(v.value));
  if (typeof v === "number") {
    if (Number.isInteger(v)) return v >= 0 ? head(0, v) : head(1, -1 - v);
    var f = new DataView(new ArrayBuffer(9));
    f.setUint8(0, 0xfb);
    f.setFloat64(1, v);
    return Array.prototype.slice.call(new Uint8Array(f.buffer));
  }
  if (typeof v === "string") {
    var s = new TextEncoder().encode(v);
    return head(3, s.length).concat(Array.prototype.slice.call(s));
  }
  if (Array.isArray(v)) {
    var out = head(4, v.length);
    v.forEach(function (x) {
      out = out.concat(encodeParts(x));
    });
    return out;
  }
  var entries = v instanceof Map ? Array.from(v.entries()) :
      Object.keys(v).map(function (k) {
        return [k, v[k]];
      });
  var encoded = entries.map(function (e) {
    return { k: encodeParts(e[0]), v: encodeParts(e[1]) };
  }).sort(function (a, b) {
    return compareBytes(a.k, b.k);
  });
  var m = head(5, encoded.length);
  encoded.forEach(function (e) {
    m = m.concat(e.k, e.v);
  });
  return m;
}

function encode(v) {
  log.debug("Entering encode().");
  log.debug("Leaving encode().");
  return new Uint8Array(encodeParts(v));
}

// #6.24(bstr .cbor value): an item embedded as its own encoding.
function embed(value) {
  log.debug("Entering embed().");
  log.debug("Leaving embed().");
  return new Tagged(24, encode(value));
}

function sha256(data) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return Promise.resolve(provider.digest("sha256", bytes.asBytes(data)));
}

function get(map, key) {
  log.debug("Entering get(). " + key);
  log.debug("Leaving get().");
  return map instanceof Map ? map.get(key) : (map || {})[key];
}

// ---------------------------------------------------------------------------
// Reading an issued mdoc.
// ---------------------------------------------------------------------------

// Whether a stored credential is an mdoc: base64url (no dots, no tildes) of a
// CBOR map with nameSpaces and issuerAuth.
function looksLikeMdoc(serialized) {
  log.debug("Entering looksLikeMdoc().");
  var text = typeof serialized === "string" ? serialized.trim() : "";
  if (!text || /[.~{\s]/.test(text) || !/^[A-Za-z0-9_-]+$/.test(text)) {
    log.debug("Leaving looksLikeMdoc(). Not base64url.");
    return false;
  }
  try {
    var v = cbor.decode(bytes.b64uToBytes(text));
    var ok = v instanceof Map && v.has("issuerAuth") && v.has("nameSpaces");
    log.debug("Leaving looksLikeMdoc(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving looksLikeMdoc(). Not CBOR.");
    return false;
  }
}

// Whether some bytes are a DeviceResponse: base64url CBOR with documents.
function looksLikeDeviceResponse(serialized) {
  log.debug("Entering looksLikeDeviceResponse().");
  var text = typeof serialized === "string" ? serialized.trim() : "";
  if (!text || !/^[A-Za-z0-9_-]+$/.test(text)) {
    log.debug("Leaving looksLikeDeviceResponse(). Not base64url.");
    return false;
  }
  try {
    var v = cbor.decode(bytes.b64uToBytes(text));
    log.debug("Leaving looksLikeDeviceResponse().");
    return v instanceof Map && Array.isArray(v.get("documents"));
  } catch (e) {
    log.debug("Leaving looksLikeDeviceResponse(). Not CBOR.");
    return false;
  }
}

function plain(value) {
  log.debug("Entering plain().");
  log.debug("Leaving plain().");
  if (value instanceof Tagged) {
    // tdate (0) and full-date (1004) read as their text.
    return (value.tag === 0 || value.tag === 1004) ? value.value :
        cbor.toPlain(value);
  }
  return cbor.toPlain(value);
}

// The parsed mdoc: every item with the exact tagged bytes it arrived as, the
// MSO, the device key as a JWK, and the issuer's certificate chain.
function parseIssuerSigned(serialized) {
  log.debug("Entering parseIssuerSigned().");
  var raw = bytes.b64uToBytes(String(serialized).trim());
  var top = cbor.decode(raw);
  if (!(top instanceof Map) || !top.has("issuerAuth")) {
    log.debug("Leaving parseIssuerSigned(). Not IssuerSigned.");
    throw new Error("this is not an ISO mdoc IssuerSigned: no issuerAuth.");
  }
  var auth = top.get("issuerAuth");
  if (auth instanceof Tagged) auth = auth.value;
  if (!Array.isArray(auth) || auth.length !== 4) {
    log.debug("Leaving parseIssuerSigned(). Bad issuerAuth.");
    throw new Error("issuerAuth is not a COSE_Sign1 (a four-element array).");
  }
  var protectedHeader = auth[0].length ? cbor.decode(auth[0]) : new Map();
  var unprotected = auth[1] instanceof Map ? auth[1] : new Map();
  var payload = cbor.decode(auth[2]);
  var msoBytes = payload instanceof Tagged ? payload.value : auth[2];
  var mso = cbor.decode(msoBytes);
  var chain = get(unprotected, COSE_X5CHAIN) ||
      get(protectedHeader, COSE_X5CHAIN) || [];
  chain = chain instanceof Uint8Array ? [chain] : chain;
  var items = [];
  var nameSpaces = top.get("nameSpaces") || new Map();
  nameSpaces.forEach(function (list, ns) {
    (list || []).forEach(function (tagged) {
      var inner = tagged instanceof Tagged ? tagged.value : tagged;
      var item = cbor.decode(inner);
      items.push({
        namespace: ns,
        digestID: item.get("digestID"),
        elementIdentifier: item.get("elementIdentifier"),
        value: plain(item.get("elementValue")),
        tagged: inner
      });
    });
  });
  var deviceKey = get(get(mso, "deviceKeyInfo"), "deviceKey");
  var validity = get(mso, "validityInfo") || new Map();
  var out = {
    format: FORMAT,
    docType: get(mso, "docType"),
    digestAlgorithm: get(mso, "digestAlgorithm"),
    mso: mso,
    validity: {
      signed: plain(get(validity, "signed")),
      validFrom: plain(get(validity, "validFrom")),
      validUntil: plain(get(validity, "validUntil"))
    },
    items: items,
    issuerAuth: auth,
    protectedHeader: protectedHeader,
    x5chain: chain,
    alg: get(protectedHeader, COSE_ALG),
    deviceJwk: deviceKey ? cose.coseToJwk(deviceKey) : null
  };
  log.debug("Leaving parseIssuerSigned(). " + items.length + " item(s).");
  return out;
}

// The claim map a wallet shows: element identifier to value. Namespaced as
// `ns:element` only where two namespaces carry the same element.
function claimsOf(parsed) {
  log.debug("Entering claimsOf().");
  var out = {};
  var seen = {};
  parsed.items.forEach(function (it) {
    seen[it.elementIdentifier] = (seen[it.elementIdentifier] || 0) + 1;
  });
  parsed.items.forEach(function (it) {
    out[seen[it.elementIdentifier] > 1 ?
        it.namespace + ":" + it.elementIdentifier : it.elementIdentifier] =
        it.value;
  });
  log.debug("Leaving claimsOf().");
  return out;
}

// Sig_structure (RFC 9052 section 4.4) for COSE_Sign1.
function sigStructure(protectedBytes, payload) {
  log.debug("Entering sigStructure().");
  log.debug("Leaving sigStructure().");
  return encode(["Signature1", protectedBytes, new Uint8Array(0), payload]);
}

function verifyEs256(jwk, data, signature) {
  log.debug("Entering verifyEs256().");
  var key = provider.importKey({ kty: jwk.kty, crv: jwk.crv, x: jwk.x,
                                  y: jwk.y });
  log.debug("Leaving verifyEs256().");
  // COSE ECDSA is raw r || s (RFC 9053 section 2.1), the provider's default.
  return Promise.resolve(provider.verify("ecdsa-p256-sha256", key,
      bytes.asBytes(data), bytes.asBytes(signature)));
}

// A COSE signature verified in pure JavaScript (#469, C8): `alg` is the COSE
// algorithm the structure's protected header names, `key` a certificate
// (DER bytes) or { jwk }. Answers { ok, name, reason }.
function verifyCoseSignature(alg, key, data, signature) {
  log.debug("Entering verifyCoseSignature(). alg=" + alg);
  var row = COSE_SIGNATURE_ALGS[String(alg)];
  if (!row) {
    log.debug("Leaving verifyCoseSignature(). Unknown alg.");
    return { ok: false, name: String(alg), reason: "COSE algorithm " +
             JSON.stringify(alg) + " is not one this debugger verifies (" +
             COSE_SIGNATURE_ALG_IDS.join(", ") + ")." };
  }
  var input = key instanceof Uint8Array ?
      bytes.derToPem(key, "CERTIFICATE") : key;
  try {
    var spec = jws.algSpec(row.jws);
    var resolved = jws.resolveKey(spec, input, "verify");
    // EdDSA (-8) names no curve: the key's length does (RFC 8037).
    if (alg === -8 && resolved.key && resolved.key.length === 57) {
      spec = jws.algSpec("EdDSA-Ed448");
      resolved = jws.resolveKey(spec, input, "verify");
    }
    var ok = !!jws.verifyOctets(spec, resolved.key, data,
                                bytes.asBytes(signature));
    log.debug("Leaving verifyCoseSignature(). " + ok);
    return { ok: ok, name: row.name, reason: ok ? "" : "the " + row.name +
             " signature does not verify." };
  } catch (e) {
    log.debug("Leaving verifyCoseSignature(). Threw: " + e.message);
    return { ok: false, name: row.name, reason: "the key cannot verify " +
             row.name + " (" + alg + "): " + e.message };
  }
}

// What the wallet can check about what it holds: every item's digest is the
// MSO's, and issuerAuth verifies with the document signer certificate it
// carries. Whether that certificate is anybody the wallet should believe is
// the Verifier's question (its IACA trust list); this says who it is.
//
// Pure JavaScript since #469 (C8): the digests are the MSO's own
// digestAlgorithm, not always SHA-256, and issuerAuth may be any COSE
// algorithm COSE_SIGNATURE_ALGS names. Still a Promise, for its callers.
function checkIssuerSigned(parsed) {
  log.debug("Entering checkIssuerSigned().");
  var checks = [];
  var digests = get(parsed.mso, "valueDigests") || new Map();
  var digestAlg = String(parsed.digestAlgorithm || "");
  var digest = MSO_DIGESTS[digestAlg];
  if (!digest) {
    checks.push({ name: "Element digests", ok: false, detail: "the MSO's " +
      "digestAlgorithm is " + JSON.stringify(parsed.digestAlgorithm) +
      ", not one of " + Object.keys(MSO_DIGESTS).join(", ") +
      " (ISO/IEC 18013-5 section 9.1.2.5)." });
  } else {
    var bad = parsed.items.filter(function (it) {
      var expected = get(get(digests, it.namespace), it.digestID);
      return !(expected instanceof Uint8Array &&
               bytes.bytesEqual(expected,
                                digest(encode(new Tagged(24, it.tagged)))));
    });
    checks.push({ name: "Element digests", ok: bad.length === 0,
      detail: bad.length === 0 ? "every element hashes (" + digestAlg +
        ", the MSO's digestAlgorithm) to the digest the Mobile Security " +
        "Object holds for it." : bad.map(function (it) {
          return it.namespace + "/" + it.elementIdentifier;
        }).join(", ") + " do not match the MSO (" + digestAlg + ")." });
  }
  if (!parsed.x5chain.length) {
    checks.push({ name: "Issuer signature", ok: false, detail: "issuerAuth " +
      "carries no x5chain, so there is no key to check it with." });
    log.debug("Leaving checkIssuerSigned(). No x5chain.");
    return Promise.resolve(checks);
  }
  var v = verifyCoseSignature(parsed.alg, bytes.asBytes(parsed.x5chain[0]),
    sigStructure(parsed.issuerAuth[0], parsed.issuerAuth[2]),
    parsed.issuerAuth[3]);
  checks.push({ name: "Issuer signature", ok: v.ok, detail: v.ok ?
    "issuerAuth (" + v.name + ", COSE " + parsed.alg + ") verifies with " +
    "the document signer certificate in its x5chain. That certificate is " +
    "UNANCHORED: this check does not chain it to an IACA or any trust " +
    "list, so it says only that the MSO is the certificate's, not whose " +
    "the certificate is." : "issuerAuth does NOT verify with its own " +
    "document signer certificate: " + v.reason });
  log.debug("Leaving checkIssuerSigned().");
  return Promise.resolve(checks);
}

// The Document's docType against the MSO's (#469, C8). ISO/IEC 18013-5
// section 9.1.2.4 signs the docType inside the MSO; the one beside it in
// the Document is what a reader matches a request against, and nothing
// signs it — so a Document claiming another docType than its MSO is one
// whose type the issuer never vouched for.
function checkDocType(read) {
  log.debug("Entering checkDocType().");
  var docType = read.doc && read.doc.get ? read.doc.get("docType") :
      undefined;
  var msoType = read.parsed.docType;
  var ok = typeof docType === "string" && docType === msoType;
  log.debug("Leaving checkDocType(). " + ok);
  return { name: "The Document's docType is the MSO's", ok: ok,
           detail: ok ? "both are " + docType + "." : "the Document says " +
             JSON.stringify(docType) + " and the issuer-signed MSO says " +
             JSON.stringify(msoType) + "." };
}

// The device authentication of a DeviceResponse, pure JavaScript (#469,
// C8): the deviceSignature's COSE alg is the one its protected header
// names, and DeviceAuthentication is over the Document's docType. A
// deviceMac (ISO/IEC 18013-5 section 9.1.3.5) needs the reader's
// ephemeral key and an ECDH this Verifier does not hold, so it is reported
// as not performed rather than as a forgery. Answers { status: "pass" |
// "fail" | "skip", detail }.
function verifyDeviceAuthentication(read, transcript) {
  log.debug("Entering verifyDeviceAuthentication().");
  var deviceSigned = read.deviceSigned;
  var deviceAuth = get(deviceSigned, "deviceAuth");
  var sig = get(deviceAuth, "deviceSignature");
  if (!sig && get(deviceAuth, "deviceMac")) {
    log.debug("Leaving verifyDeviceAuthentication(). deviceMac.");
    return { status: "skip", detail: "the device authenticated with a " +
      "deviceMac (ISO/IEC 18013-5 section 9.1.3.5), which needs an " +
      "EMacKey agreed with the reader's ephemeral key; this Verifier holds " +
      "none and does not verify DeviceMac, so device authentication was " +
      "not performed." };
  }
  var jwk = read.parsed.deviceJwk;
  if (!Array.isArray(sig) || sig.length !== 4 || !jwk) {
    log.debug("Leaving verifyDeviceAuthentication(). Nothing to check.");
    return { status: "fail", detail: "there is no deviceSignature (or no " +
             "device key in the MSO) to check." };
  }
  var protectedHeader;
  try {
    protectedHeader = sig[0] && sig[0].length ? cbor.decode(sig[0]) :
      new Map();
  } catch (e) {
    log.debug("Leaving verifyDeviceAuthentication(). Bad header.");
    return { status: "fail", detail: "the deviceSignature's protected " +
             "header is not CBOR: " + e.message };
  }
  var alg = get(protectedHeader, COSE_ALG);
  var docType = (read.doc && read.doc.get && read.doc.get("docType")) ||
      read.parsed.docType;
  var auth = encode(embed(["DeviceAuthentication", transcript, docType,
                           get(deviceSigned, "nameSpaces")]));
  var v = verifyCoseSignature(alg, { jwk: jwk }, sigStructure(sig[0], auth),
                              sig[3]);
  log.debug("Leaving verifyDeviceAuthentication(). " + v.ok);
  return { status: v.ok ? "pass" : "fail", alg: alg, name: v.name,
           detail: v.reason };
}

// ---------------------------------------------------------------------------
// Presenting.
// ---------------------------------------------------------------------------

// OpenID4VP 1.0 Appendix B.2.6.1. `encryptionJwk` is the Verifier's key the
// response is encrypted to (direct_post.jwt), or null.
function sessionTranscript(opts) {
  log.debug("Entering sessionTranscript(). client_id=" + opts.clientId);
  var thumb = opts.encryptionJwk ?
      dpop.thumbprint(opts.encryptionJwk).then(function (t) {
        return bytes.b64uToBytes(t);
      }) : Promise.resolve(null);
  log.debug("Leaving sessionTranscript().");
  return thumb.then(function (t) {
    var info = encode([opts.clientId, opts.nonce, t, opts.responseUri]);
    return sha256(info);
  }).then(function (h) {
    return [null, null, ["OpenID4VPHandover", h]];
  });
}

// The items to send: the ones `selected` names, as "ns/element" or a bare
// element identifier.
function chosenItems(parsed, selected) {
  log.debug("Entering chosenItems().");
  var want = selected || [];
  log.debug("Leaving chosenItems().");
  return parsed.items.filter(function (it) {
    return want.indexOf(it.namespace + "/" + it.elementIdentifier) !== -1 ||
           want.indexOf(it.elementIdentifier) !== -1;
  });
}

// A DeviceResponse disclosing `selected`, device-signed over the transcript.
// Answers { deviceResponse (base64url), bytes, transcript, disclosed }.
function deviceResponse(opts) {
  log.debug("Entering deviceResponse().");
  var parsed = opts.parsed;
  var items = chosenItems(parsed, opts.selected);
  var nameSpaces = new Map();
  items.forEach(function (it) {
    if (!nameSpaces.has(it.namespace)) nameSpaces.set(it.namespace, []);
    nameSpaces.get(it.namespace).push(new Tagged(24, it.tagged));
  });
  var deviceNameSpacesBytes = embed(new Map());
  var protectedBytes = encode(new Map([[COSE_ALG, ES256]]));
  log.debug("Leaving deviceResponse().");
  return sessionTranscript(opts).then(function (transcript) {
    var auth = encode(embed(["DeviceAuthentication", transcript,
                             parsed.docType, deviceNameSpacesBytes]));
    var priv = Object.assign({}, opts.devicePrivateJwk);
    delete priv.key_ops;
    delete priv.ext;
    delete priv.alg;
    // ES256 over the COSE Sig_structure, raw r || s (RFC 9053 section 2.1).
    return Promise.resolve(provider.sign("ecdsa-p256-sha256",
        provider.importKey(priv), sigStructure(protectedBytes, auth)))
      .then(function (sig) {
        var doc = new Map([
          ["docType", parsed.docType],
          ["issuerSigned", new Map([["nameSpaces", nameSpaces],
                                    ["issuerAuth", parsed.issuerAuth]])],
          ["deviceSigned", new Map([
            ["nameSpaces", deviceNameSpacesBytes],
            ["deviceAuth", new Map([["deviceSignature",
              [protectedBytes, new Map(), null, new Uint8Array(sig)]]])]
          ])]
        ]);
        var response = encode(new Map([["version", "1.0"],
                                       ["documents", [doc]],
                                       ["status", 0]]));
        log.debug("Leaving deviceResponse(). " + items.length + " item(s).");
        return { deviceResponse: bytes.bytesToB64u(response), bytes: response,
                 transcript: transcript, disclosed: items };
      });
  });
}

// A DeviceResponse read back: the document, its disclosed items, and the
// device signature checked against the MSO's device key over the transcript
// `opts` describes — what step 3 re-checks from the bytes that went.
function readDeviceResponse(serialized) {
  log.debug("Entering readDeviceResponse().");
  var top = cbor.decode(bytes.b64uToBytes(String(serialized).trim()));
  var doc = (top.get("documents") || [])[0];
  if (!doc) {
    log.debug("Leaving readDeviceResponse(). No document.");
    throw new Error("the DeviceResponse carries no document.");
  }
  var issuerSigned = encode(doc.get("issuerSigned"));
  var parsed = parseIssuerSigned(bytes.bytesToB64u(issuerSigned));
  log.debug("Leaving readDeviceResponse().");
  return { top: top, doc: doc, parsed: parsed,
           deviceSigned: doc.get("deviceSigned") };
}

function checkDeviceSignature(read, opts) {
  log.debug("Entering checkDeviceSignature().");
  var deviceSigned = read.deviceSigned;
  var sig = get(get(deviceSigned, "deviceAuth"), "deviceSignature");
  if (!sig || !read.parsed.deviceJwk) {
    log.debug("Leaving checkDeviceSignature(). Nothing to check.");
    return Promise.resolve(false);
  }
  log.debug("Leaving checkDeviceSignature().");
  return sessionTranscript(opts).then(function (transcript) {
    var auth = encode(embed(["DeviceAuthentication", transcript,
                             read.parsed.docType,
                             get(deviceSigned, "nameSpaces")]));
    return verifyEs256(read.parsed.deviceJwk, sigStructure(sig[0], auth),
                       sig[3]);
  });
}

module.exports = {
  FORMAT: FORMAT,
  ES256: ES256,
  encode: encode,
  Simple: Simple,
  embed: embed,
  looksLikeMdoc: looksLikeMdoc,
  looksLikeDeviceResponse: looksLikeDeviceResponse,
  parseIssuerSigned: parseIssuerSigned,
  claimsOf: claimsOf,
  checkIssuerSigned: checkIssuerSigned,
  checkDocType: checkDocType,
  verifyCoseSignature: verifyCoseSignature,
  verifyDeviceAuthentication: verifyDeviceAuthentication,
  COSE_SIGNATURE_ALG_IDS: COSE_SIGNATURE_ALG_IDS,
  sessionTranscript: sessionTranscript,
  chosenItems: chosenItems,
  deviceResponse: deviceResponse,
  readDeviceResponse: readDeviceResponse,
  checkDeviceSignature: checkDeviceSignature,
  sigStructure: sigStructure
};
