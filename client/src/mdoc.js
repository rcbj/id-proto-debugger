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
var vpProtocols = require("./vp_protocols");

var FORMAT = "mso_mdoc";
var Tagged = cbor.Tagged;
// COSE: alg (1), x5chain (33); ES256 is -7.
var COSE_ALG = 1;
var COSE_X5CHAIN = 33;
var ES256 = -7;

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

function encodeParts(v) {
  if (v === null || v === undefined) return [v === null ? 0xf6 : 0xf7];
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
  return crypto.subtle.digest("SHA-256", data).then(function (d) {
    return new Uint8Array(d);
  });
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
  var key = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  log.debug("Leaving verifyEs256().");
  return crypto.subtle.importKey("jwk", key,
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    .then(function (k) {
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k,
                                  signature, data);
    });
}

// What the wallet can check about what it holds: every item's digest is the
// MSO's, and issuerAuth verifies with the document signer certificate it
// carries. Whether that certificate is anybody the wallet should believe is
// the Verifier's question (its IACA trust list); this says who it is.
function checkIssuerSigned(parsed) {
  log.debug("Entering checkIssuerSigned().");
  var checks = [];
  var digests = get(parsed.mso, "valueDigests") || new Map();
  log.debug("Leaving checkIssuerSigned().");
  return Promise.all(parsed.items.map(function (it) {
    return sha256(encode(new Tagged(24, it.tagged))).then(function (d) {
      var expected = get(get(digests, it.namespace), it.digestID);
      return expected instanceof Uint8Array &&
             bytes.bytesEqual(expected, d);
    });
  })).then(function (matches) {
    var bad = parsed.items.filter(function (it, i) {
      return !matches[i];
    });
    checks.push({ name: "Element digests", ok: bad.length === 0,
      detail: bad.length === 0 ? "every element hashes to the digest the " +
        "Mobile Security Object holds for it." : bad.map(function (it) {
          return it.namespace + "/" + it.elementIdentifier;
        }).join(", ") + " do not match the MSO." });
    if (!parsed.x5chain.length) {
      checks.push({ name: "Issuer signature", ok: false, detail: "issuerAuth " +
        "carries no x5chain, so there is no key to check it with." });
      return checks;
    }
    if (parsed.alg !== ES256) {
      checks.push({ name: "Issuer signature", ok: false, detail: "issuerAuth " +
        "is COSE algorithm " + parsed.alg + "; this wallet checks ES256 " +
        "(-7)." });
      return checks;
    }
    return vpProtocols.certificatePublicJwk(parsed.x5chain[0], "ES256")
      .then(function (jwk) {
        return verifyEs256(jwk, sigStructure(parsed.issuerAuth[0],
                                             parsed.issuerAuth[2]),
                           parsed.issuerAuth[3]);
      })
      .then(function (ok) {
        checks.push({ name: "Issuer signature", ok: ok, detail: ok ?
          "issuerAuth verifies with the document signer certificate in " +
          "its x5chain." : "issuerAuth does NOT verify with its own " +
          "document signer certificate." });
        return checks;
      });
  });
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
    return crypto.subtle.importKey("jwk", priv,
        { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
      .then(function (key) {
        return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key,
                                  sigStructure(protectedBytes, auth));
      })
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
  embed: embed,
  looksLikeMdoc: looksLikeMdoc,
  looksLikeDeviceResponse: looksLikeDeviceResponse,
  parseIssuerSigned: parseIssuerSigned,
  claimsOf: claimsOf,
  checkIssuerSigned: checkIssuerSigned,
  sessionTranscript: sessionTranscript,
  chosenItems: chosenItems,
  deviceResponse: deviceResponse,
  readDeviceResponse: readDeviceResponse,
  checkDeviceSignature: checkDeviceSignature,
  sigStructure: sigStructure
};
