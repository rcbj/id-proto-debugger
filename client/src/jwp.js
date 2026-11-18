// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jwp.js
//
// ---------------------------------------------------------------------------
// JSON Web Proofs (#478): draft-ietf-jose-json-web-proof-15, the algorithms
// of draft-ietf-jose-json-proof-algorithms-15 and the claims mapping of
// draft-ietf-jose-json-proof-token-15. DRAFTS, and every label this module
// gives the UI says so. No DOM.
//
//   * both serializations: Compact (a JPT) and CBOR (a CPT);
//   * Single Use (SU-ES256, SU-ES384, SU-ES512), MAC (MAC-H256, MAC-H384,
//     MAC-H512, MAC-H256K) and BBS (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_,
//     through bbs.js);
//   * the four interactions: issue, confirm, present and verify.
//
// Where the drafts' text and their own Appendix A disagree, the examples'
// bytes are what this follows, because they are what another
// implementation will produce:
//
//   * every signature is over the raw octets (of a header, a payload, the
//     Combined MAC Representation or the presentation internal
//     representation), not over a JWS signing input, whatever the prose
//     about "creating a JWS" suggests;
//   * MAC: the issuer signs the Combined MAC Representation (section 7.4.5;
//     7.4.8's "over the Issuer Header octets" is an erratum), and a
//     presented MAC JWP has one proof component per payload SLOT plus two
//     (7.4.7; 7.4.8's "than disclosed payloads" is an erratum);
//   * CPT payloads are CBOR values carried inline, each payload's octets
//     being its CBOR encoding; the Issuer Header's claims are at label 6,
//     where Appendix A.2 puts them (JPT's IANA section asks for 10, which
//     JWP already gives hpa).
//
// MAC-K25519 and MAC-K448 are refused by name: the draft names KMAC with
// SHAKE128/SHAKE256 and fixes neither its output length nor its
// customization string, so any choice here would be an invention.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
var cbor = require("./cbor");
var mdoc = require("./mdoc");
var bbs = require("./bbs");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "jwp",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var DRAFT = "draft-ietf-jose-json-web-proof-15";
var MEDIA_JPT = "application/jpt";

// The algorithms of JPA section 7, with their CBOR labels (section 9.1.2).
var ALGS = {
  "SU-ES256": { kind: "su", sig: "ecdsa-p256-sha256", crv: "P-256",
                cbor: 1 },
  "SU-ES384": { kind: "su", sig: "ecdsa-p384-sha384", crv: "P-384",
                cbor: 2 },
  "SU-ES512": { kind: "su", sig: "ecdsa-p521-sha512", crv: "P-521",
                cbor: 3 },
  "BBS": { kind: "bbs", crv: "BLS12381G2", cbor: 4 },
  "MAC-H256": { kind: "mac", mac: "sha256", sig: "ecdsa-p256-sha256",
                crv: "P-256", cbor: 5 },
  "MAC-H384": { kind: "mac", mac: "sha384", sig: "ecdsa-p384-sha384",
                crv: "P-384", cbor: 6 },
  "MAC-H512": { kind: "mac", mac: "sha512", sig: "ecdsa-p521-sha512",
                crv: "P-521", cbor: 7 },
  "MAC-K25519": { kind: "mac", refused: true, cbor: 8 },
  "MAC-K448": { kind: "mac", refused: true, cbor: 9 },
  "MAC-H256K": { kind: "mac", mac: "sha256", sig: "ecdsa-secp256k1-sha256",
                 crv: "secp256k1", cbor: 10 }
};
var REFUSED_KMAC = "is refused: JPA section 7.4.9 names KMAC over SHAKE " +
  "but fixes neither its output length nor its customization string, so " +
  "no two implementations can be expected to agree on its bytes.";

// Holder presentation algorithms (hpa): JOSE names and COSE labels.
var HPA_JOSE = {
  "ES256": "ecdsa-p256-sha256", "ES384": "ecdsa-p384-sha384",
  "ES512": "ecdsa-p521-sha512", "ES256K": "ecdsa-secp256k1-sha256",
  "Ed25519": "ed25519", "Ed448": "ed448", "EdDSA": "eddsa"
};
var HPA_COSE = {
  "-9": "ES256", "-51": "ES384", "-52": "ES512", "-7": "ES256",
  "-35": "ES384", "-36": "ES512", "-47": "ES256K", "-19": "Ed25519",
  "-53": "Ed448", "-8": "EdDSA"
};

// JWP section 11.1.2 CBOR labels; claims/cid from JPT (claims where
// Appendix A.2 puts it in an Issuer Header).
var LABELS = { 1: "alg", 2: "kid", 3: "typ", 4: "crit", 5: "iss",
               6: "aud", 7: "nonce", 8: "iek", 9: "hpk", 10: "hpa",
               11: "cid" };
var ISSUER_LABELS = Object.assign({}, LABELS, { 6: "claims" });

var COSE_CRV = { 1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519",
                 7: "Ed448", 8: "secp256k1" };

function b64u(data) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return bytes.bytesToB64u(data);
}

function unb64u(text) {
  log.debug("Entering unb64u().");
  log.debug("Leaving unb64u().");
  return bytes.b64uToBytes(text);
}

function utf8(text) {
  log.debug("Entering utf8().");
  log.debug("Leaving utf8().");
  return bytes.strBytes(text);
}

function concat(parts) {
  log.debug("Entering concat().");
  var n = 0;
  parts.forEach(function (p) {
    n += p.length;
  });
  var out = new Uint8Array(n);
  var at = 0;
  parts.forEach(function (p) {
    out.set(p, at);
    at += p.length;
  });
  log.debug("Leaving concat().");
  return out;
}

// An 8-byte, network-order length or count (JPA sections 7.2 and 7.4.3).
function u64(n) {
  log.debug("Entering u64().");
  var out = new Uint8Array(8);
  var v = n;
  for (var i = 7; i >= 0; i--) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  log.debug("Leaving u64().");
  return out;
}

function lengthPrefixed(data) {
  log.debug("Entering lengthPrefixed().");
  log.debug("Leaving lengthPrefixed().");
  return concat([new Uint8Array([0x5b]), u64(data.length), data]);
}

function algOf(name) {
  log.debug("Entering algOf(). " + name);
  var a = ALGS[name];
  if (!a) {
    log.debug("Leaving algOf(). Unknown.");
    throw new Error("unsupported JWP algorithm " + JSON.stringify(name) +
                    " (" + DRAFT + " registers " +
                    Object.keys(ALGS).join(", ") + ").");
  }
  if (a.refused) {
    log.debug("Leaving algOf(). Refused.");
    throw new Error(name + " " + REFUSED_KMAC);
  }
  log.debug("Leaving algOf().");
  return a;
}

function importJwk(jwk, wantPrivate) {
  log.debug("Entering importJwk().");
  var clean = {};
  ["kty", "crv", "x", "y", "d"].forEach(function (k) {
    if (jwk[k] !== undefined && (k !== "d" || wantPrivate)) clean[k] = jwk[k];
  });
  log.debug("Leaving importJwk().");
  return provider.importKey(clean, { format: "jwk" });
}

function publicJwk(jwk) {
  log.debug("Entering publicJwk().");
  var out = {};
  ["crv", "kty", "x", "y"].forEach(function (k) {
    if (jwk[k] !== undefined) out[k] = jwk[k];
  });
  log.debug("Leaving publicJwk().");
  return out;
}

// The signer id for an hpa value and the key it is used with.
function hpaSigner(hpa, jwk) {
  log.debug("Entering hpaSigner(). " + hpa);
  var name = typeof hpa === "number" ? HPA_COSE[String(hpa)] : hpa;
  var id = HPA_JOSE[name];
  if (id === "eddsa") {
    id = jwk && jwk.crv === "Ed448" ? "ed448" : "ed25519";
  }
  if (!id) {
    log.debug("Leaving hpaSigner(). Unknown.");
    throw new Error("unsupported holder presentation algorithm " +
                    JSON.stringify(hpa) + ".");
  }
  log.debug("Leaving hpaSigner(). " + id);
  return id;
}

// An hpa from the holder's key, when the issuer is not told one.
function defaultHpa(jwk) {
  log.debug("Entering defaultHpa().");
  var byCrv = { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512",
                "secp256k1": "ES256K", "Ed25519": "Ed25519",
                "Ed448": "Ed448" };
  log.debug("Leaving defaultHpa().");
  return byCrv[jwk.crv] || "ES256";
}

// ---------------------------------------------------------------------------
// The two serializations. A parsed JWP:
//   { serialization: "compact" | "cbor", form: "issued" | "presented",
//     issuerHeader: { bytes, value }, presentationHeader: { bytes, value }
//     (presented only), payloads: [Uint8Array | null] or null (detached),
//     values: [any] (CBOR only: the payloads as decoded), proof: [bytes] }
// ---------------------------------------------------------------------------
function decodeSlot(text, allowOmitted) {
  log.debug("Entering decodeSlot().");
  if (text === "") {
    if (!allowOmitted) {
      log.debug("Leaving decodeSlot(). Omitted in an issued JWP.");
      throw new Error("an issued JWP may not omit a payload.");
    }
    log.debug("Leaving decodeSlot(). Omitted.");
    return null;
  }
  log.debug("Leaving decodeSlot().");
  return text === "_" ? new Uint8Array(0) : unb64u(text);
}

function encodeSlot(data) {
  log.debug("Entering encodeSlot().");
  if (data === null || data === undefined) {
    log.debug("Leaving encodeSlot(). Omitted.");
    return "";
  }
  log.debug("Leaving encodeSlot().");
  return data.length ? b64u(data) : "_";
}

function jsonHeader(octets, what) {
  log.debug("Entering jsonHeader(). " + what);
  var value;
  try {
    value = JSON.parse(bytes.bytesToStr(octets));
  } catch (e) {
    log.debug("Leaving jsonHeader(). Not JSON.");
    throw new Error("the " + what + " is not JSON: " + e.message);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    log.debug("Leaving jsonHeader(). Not an object.");
    throw new Error("the " + what + " is not a JSON object.");
  }
  log.debug("Leaving jsonHeader().");
  return value;
}

function parseCompact(text) {
  log.debug("Entering parseCompact().");
  var parts = String(text).trim().split(".");
  if (parts.length !== 3 && parts.length !== 4) {
    log.debug("Leaving parseCompact(). " + parts.length + " parts.");
    throw new Error("a compact JWP has three parts (issued) or four " +
                    "(presented); this has " + parts.length + ".");
  }
  var presented = parts.length === 4;
  var at = presented ? 1 : 0;
  var out = { serialization: "compact",
              form: presented ? "presented" : "issued" };
  if (presented) {
    var phBytes = unb64u(parts[0]);
    out.presentationHeader = { bytes: phBytes,
      value: jsonHeader(phBytes, "Presentation Header") };
  }
  var ihBytes = unb64u(parts[at]);
  out.issuerHeader = { bytes: ihBytes,
                       value: jsonHeader(ihBytes, "Issuer Header") };
  out.payloads = parts[at + 1] === "" ? null :
    parts[at + 1].split("~").map(function (p) {
      return decodeSlot(p, presented);
    });
  out.proof = parts[at + 2].split("~").map(function (p) {
    return decodeSlot(p, false);
  });
  log.debug("Leaving parseCompact(). " + out.form);
  return out;
}

function serializeCompact(jwp) {
  log.debug("Entering serializeCompact().");
  var parts = [];
  if (jwp.form === "presented") parts.push(b64u(jwp.presentationHeader.bytes));
  parts.push(b64u(jwp.issuerHeader.bytes));
  parts.push(jwp.payloads ? jwp.payloads.map(encodeSlot).join("~") : "");
  parts.push(jwp.proof.map(encodeSlot).join("~"));
  log.debug("Leaving serializeCompact().");
  return parts.join(".");
}

// A COSE_Key, as a JWK, for iek and hpk.
function coseKeyToJwk(key) {
  log.debug("Entering coseKeyToJwk().");
  if (!(key instanceof Map)) {
    log.debug("Leaving coseKeyToJwk(). Not a map.");
    return key;
  }
  var kty = key.get(1);
  var out = { kty: kty === 2 ? "EC" : kty === 1 ? "OKP" : String(kty),
              crv: COSE_CRV[key.get(-1)] || String(key.get(-1)) };
  if (key.get(-2)) out.x = b64u(key.get(-2));
  if (key.get(-3) instanceof Uint8Array) out.y = b64u(key.get(-3));
  log.debug("Leaving coseKeyToJwk().");
  return out;
}

// A JWK as a COSE_Key (RFC 9053 section 7): EC2 or OKP, public members.
function jwkToCoseKey(jwk) {
  log.debug("Entering jwkToCoseKey().");
  var crv = Number(Object.keys(COSE_CRV).filter(function (k) {
    return COSE_CRV[k] === jwk.crv;
  })[0]);
  if (!crv) {
    log.debug("Leaving jwkToCoseKey(). Curve.");
    throw new Error("no COSE curve for " + jwk.crv + ".");
  }
  var m = new Map();
  m.set(1, jwk.kty === "OKP" ? 1 : 2);
  m.set(-1, crv);
  m.set(-2, unb64u(jwk.x));
  if (jwk.kty !== "OKP") m.set(-3, unb64u(jwk.y));
  log.debug("Leaving jwkToCoseKey().");
  return m;
}

// The Issuer Header of a CPT, in the reading this file PARSES with —
// Appendix A.2's: alg as its JPA number, claims at 6, iek/hpk as COSE_Keys,
// hpa as a fully specified COSE algorithm. JWP leaves these labels
// unsettled (see the header and docs/jwp-sd-cwt.md), so a CPT issued here
// is the A.2 reading, not a settled format.
function cborIssuerHeader(header) {
  log.debug("Entering cborIssuerHeader().");
  var labelOf = {};
  Object.keys(ISSUER_LABELS).forEach(function (k) {
    labelOf[ISSUER_LABELS[k]] = Number(k);
  });
  var hpaNumber = { ES256: -9, ES384: -51, ES512: -52, ES256K: -47,
                    Ed25519: -19, Ed448: -53, EdDSA: -8 };
  var m = new Map();
  Object.keys(header).forEach(function (name) {
    var label = labelOf[name];
    if (label === undefined) {
      throw new Error("Issuer Header parameter " + JSON.stringify(name) +
                      " has no CBOR label.");
    }
    var v = header[name];
    if (name === "alg") v = algOf(v).cbor;
    if (name === "iek" || name === "hpk") v = jwkToCoseKey(v);
    if (name === "hpa") {
      if (hpaNumber[v] === undefined) {
        throw new Error("hpa " + v + " has no COSE algorithm here.");
      }
      v = hpaNumber[v];
    }
    m.set(label, v);
  });
  log.debug("Leaving cborIssuerHeader().");
  return mdoc.encode(m);
}

function cborHeaderValue(map, labels) {
  log.debug("Entering cborHeaderValue().");
  var out = {};
  map.forEach(function (v, k) {
    var name = labels[k] || String(k);
    if (name === "iek" || name === "hpk") {
      out[name] = coseKeyToJwk(v);
    } else if (name === "alg" && typeof v === "number") {
      out.alg = Object.keys(ALGS).filter(function (a) {
        return ALGS[a].cbor === v;
      })[0] || String(v);
    } else if (name === "nonce" && v instanceof Uint8Array) {
      // A CBOR nonce is a byte string. This page writes the UTF-8 of the
      // nonce it was given (present()), so it reads back as that text when
      // it is valid UTF-8, and as base64url when it is not (the A.2
      // example's random bytes).
      try {
        out.nonce = new TextDecoder("utf-8", { fatal: true }).decode(v);
        if (/[\u0000-\u001f]/.test(out.nonce)) throw new Error("control");
      } catch (e) {
        out.nonce = b64u(v);
      }
    } else {
      out[name] = v;
    }
  });
  log.debug("Leaving cborHeaderValue().");
  return out;
}

function parseCbor(input) {
  log.debug("Entering parseCbor().");
  var item = cbor.decode(input instanceof Uint8Array ? input :
                         bytes.hexToBytes(String(input).trim()));
  if (item instanceof cbor.Tagged) item = item.value;
  if (!Array.isArray(item) || (item.length !== 3 && item.length !== 4)) {
    log.debug("Leaving parseCbor(). Not a JWP array.");
    throw new Error("a CBOR JWP is a three-element (issued) or " +
                    "four-element (presented) array.");
  }
  var presented = item.length === 4;
  var at = presented ? 1 : 0;
  var out = { serialization: "cbor",
              form: presented ? "presented" : "issued" };
  if (presented) {
    out.presentationHeader = { bytes: item[0], value: item[0].length ?
      cborHeaderValue(cbor.decode(item[0]), LABELS) : {} };
  }
  out.issuerHeader = { bytes: item[at], value: item[at].length ?
    cborHeaderValue(cbor.decode(item[at]), ISSUER_LABELS) : {} };
  out.values = item[at + 1];
  out.payloads = item[at + 1] === null ? null :
    item[at + 1].map(function (v) {
      if (v === null && !presented) {
        throw new Error("an issued JWP may not omit a payload.");
      }
      return v === null ? null : mdoc.encode(v);
    });
  out.proof = item[at + 2];
  log.debug("Leaving parseCbor(). " + out.form);
  return out;
}

function serializeCbor(jwp) {
  log.debug("Entering serializeCbor().");
  var values = jwp.values || (jwp.payloads || []).map(function (p) {
    return p === null ? null : cbor.decode(p);
  });
  var arr = [jwp.issuerHeader.bytes, jwp.payloads ? values : null,
             jwp.proof];
  if (jwp.form === "presented") arr.unshift(jwp.presentationHeader.bytes);
  log.debug("Leaving serializeCbor().");
  return mdoc.encode(arr);
}

// A JWP from either serialization: a compact string, CBOR bytes, or CBOR
// as hex.
function parse(input) {
  log.debug("Entering parse().");
  if (input instanceof Uint8Array ||
      /^[0-9a-fA-F]+$/.test(String(input).trim())) {
    log.debug("Leaving parse(). CBOR.");
    return parseCbor(input);
  }
  log.debug("Leaving parse(). Compact.");
  return parseCompact(input);
}

function serialize(jwp) {
  log.debug("Entering serialize().");
  log.debug("Leaving serialize().");
  return jwp.serialization === "cbor" ? serializeCbor(jwp) :
    serializeCompact(jwp);
}

// Whether a string is shaped like a compact JWP: three or four dot-separated
// parts of which the payload part carries tildes.
function looksLikeJwp(text) {
  log.debug("Entering looksLikeJwp().");
  var parts = String(text || "").trim().split(".");
  if (parts.length !== 3 && parts.length !== 4) {
    log.debug("Leaving looksLikeJwp(). Not 3/4 parts.");
    return false;
  }
  try {
    var h = jsonHeader(unb64u(parts[parts.length - 3]), "header");
    log.debug("Leaving looksLikeJwp().");
    return typeof h.alg === "string" && ALGS[h.alg] !== undefined;
  } catch (e) {
    log.debug("Leaving looksLikeJwp(). " + e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// The internal binary forms (JPA sections 7.2 and 7.4.3).
// ---------------------------------------------------------------------------
function presentationInternal(ph, ih, slots, proofs) {
  log.debug("Entering presentationInternal().");
  var parts = [new Uint8Array([0x84, 0x5b]), u64(ph.length), ph,
               new Uint8Array([0x5b]), u64(ih.length), ih,
               new Uint8Array([0x9b]), u64(slots.length)];
  slots.forEach(function (s) {
    parts.push(s === null ? new Uint8Array([0xf6]) : lengthPrefixed(s));
  });
  parts.push(new Uint8Array([0x9b]), u64(proofs.length));
  proofs.forEach(function (p) {
    parts.push(lengthPrefixed(p));
  });
  log.debug("Leaving presentationInternal().");
  return concat(parts);
}

var PAYLOAD_KEY_PREFIX = new Uint8Array([0x82, 0x67, 0x70, 0x61, 0x79, 0x6c,
                                         0x6f, 0x61, 0x64, 0x1b]);

function macPayloadKey(a, secret, index) {
  log.debug("Entering macPayloadKey(). " + index);
  log.debug("Leaving macPayloadKey().");
  return provider.hmac(a.mac, secret, concat([PAYLOAD_KEY_PREFIX,
                                              u64(index)]));
}

function combinedMac(ih, macs) {
  log.debug("Entering combinedMac().");
  var parts = [new Uint8Array([0x82, 0x5b]), u64(ih.length), ih,
               new Uint8Array([0x9b]), u64(macs.length)];
  macs.forEach(function (m) {
    parts.push(lengthPrefixed(m));
  });
  log.debug("Leaving combinedMac().");
  return concat(parts);
}

function bbsKeys(jwk) {
  log.debug("Entering bbsKeys().");
  if (jwk.kty !== "OKP" || jwk.crv !== "BLS12381G2") {
    log.debug("Leaving bbsKeys(). Wrong key type.");
    throw new Error("a BBS key is an OKP JWK on BLS12381G2 " +
                    "(draft-ietf-cose-bls-key-representations).");
  }
  var out = { pk: unb64u(jwk.x) };
  if (jwk.d) {
    out.sk = BigInt("0x" + bytes.bytesToHex(unb64u(jwk.d)));
  }
  log.debug("Leaving bbsKeys().");
  return out;
}

function sortedJson(value) {
  log.debug("Entering sortedJson().");
  var out = {};
  Object.keys(value).sort().forEach(function (k) {
    out[k] = value[k];
  });
  log.debug("Leaving sortedJson().");
  return JSON.stringify(out);
}

// ---------------------------------------------------------------------------
// Issue (JPA section 5.1). opts:
//   alg, header (further Issuer Header parameters, e.g. iss, kid, typ,
//   claims), payloads ([Uint8Array]), issuerKey (private JWK), holderKey
//   (public JWK; SU and MAC), hpa (defaults from the holder key),
//   ephemeralKey (SU; generated when absent), sharedSecret (MAC; random
//   when absent), serialization ("compact" | "cbor"; compact by default),
//   values (a CPT's payloads as JS values, encoded as inline CBOR).
// Returns the serialized JWP: text, or bytes for a CPT.
// ---------------------------------------------------------------------------
function issue(opts) {
  log.debug("Entering issue(). " + opts.alg);
  var a = algOf(opts.alg);
  var isCbor = opts.serialization === "cbor";
  // A CPT's payloads are CBOR values carried inline, so each payload's
  // octets are its CBOR encoding: given as values (opts.values) or as
  // octets that must decode.
  var payloads = isCbor && opts.values ? opts.values.map(function (v) {
    return mdoc.encode(v);
  }) : opts.payloads.map(function (p) {
    return p instanceof Uint8Array ? p : utf8(String(p));
  });
  if (isCbor && !opts.values) {
    payloads.forEach(function (p, i) {
      try {
        cbor.decode(p);
      } catch (e) {
        throw new Error("CPT payload " + i + " is not a CBOR value (" +
                        e.message + "); pass values instead.");
      }
    });
  }
  var header = Object.assign({}, opts.header || {}, { alg: opts.alg });
  var ephemeral = null;
  if (a.kind === "su") {
    ephemeral = opts.ephemeralKey || provider.exportKey(
      provider.generateKeyPair({ "P-256": "ec-p256", "P-384": "ec-p384",
                                 "P-521": "ec-p521" }[a.crv]), "jwk");
    header.iek = publicJwk(ephemeral);
  }
  if (a.kind !== "bbs") {
    if (!opts.holderKey) {
      log.debug("Leaving issue(). No holder key.");
      throw new Error(opts.alg + " needs the holder's presentation key.");
    }
    header.hpk = publicJwk(opts.holderKey);
    header.hpa = opts.hpa || defaultHpa(opts.holderKey);
  }
  var ih = isCbor ? cborIssuerHeader(header) : utf8(sortedJson(header));
  var proof;
  if (a.kind === "su") {
    var issuer = importJwk(opts.issuerKey, true);
    var eph = importJwk(ephemeral, true);
    proof = [provider.sign(a.sig, issuer, ih)].concat(payloads.map(
      function (p) {
        return provider.sign(a.sig, eph, p);
      }));
  } else if (a.kind === "mac") {
    var secret = opts.sharedSecret || provider.randomBytes(32);
    var macs = payloads.map(function (p, i) {
      return provider.hmac(a.mac, macPayloadKey(a, secret, i), p);
    });
    proof = [provider.sign(a.sig, importJwk(opts.issuerKey, true),
                           combinedMac(ih, macs)), secret];
  } else {
    var k = bbsKeys(opts.issuerKey);
    proof = [bbs.sign(k.sk, k.pk, ih, payloads)];
  }
  var jwp = { serialization: isCbor ? "cbor" : "compact", form: "issued",
              issuerHeader: { bytes: ih, value: header },
              payloads: payloads, proof: proof };
  log.debug("Leaving issue().");
  return isCbor ? serializeCbor(jwp) : serializeCompact(jwp);
}

// ---------------------------------------------------------------------------
// Confirm (JPA section 5.2): the holder checks an ISSUED JWP. issuerKey is
// the issuer's public JWK. Returns { valid, errors, jwp }.
// ---------------------------------------------------------------------------
function confirm(input, opts) {
  log.debug("Entering confirm().");
  var o = opts || {};
  var errors = [];
  var jwp;
  try {
    jwp = typeof input === "object" && input.proof ? input : parse(input);
  } catch (e) {
    log.debug("Leaving confirm(). Unparseable.");
    return { valid: false, errors: [e.message] };
  }
  if (jwp.form !== "issued") {
    log.debug("Leaving confirm(). Presented.");
    return { valid: false, jwp: jwp, errors: ["confirm takes an issued " +
             "JWP; this is a presented one (JPA section 5.2)."] };
  }
  if (!jwp.payloads) {
    log.debug("Leaving confirm(). Detached.");
    return { valid: false, jwp: jwp, errors: ["the payloads are detached; " +
             "they must be supplied to confirm it."] };
  }
  var h = jwp.issuerHeader.value;
  try {
    var a = algOf(h.alg);
    var ih = jwp.issuerHeader.bytes;
    if (a.kind === "su") {
      if (jwp.proof.length !== jwp.payloads.length + 1) {
        errors.push("an issued " + h.alg + " proof has one component per " +
                    "payload plus one; this has " + jwp.proof.length +
                    " for " + jwp.payloads.length + " payloads.");
      } else {
        if (!provider.verify(a.sig, importJwk(o.issuerKey), ih,
                             jwp.proof[0])) {
          errors.push("the issuer's signature over the Issuer Header does " +
                      "not verify.");
        }
        var iek = importJwk(h.iek || {});
        jwp.payloads.forEach(function (p, i) {
          if (!provider.verify(a.sig, iek, p, jwp.proof[i + 1])) {
            errors.push("payload " + i + "'s signature by the ephemeral " +
                        "key (iek) does not verify.");
          }
        });
      }
    } else if (a.kind === "mac") {
      if (jwp.proof.length !== 2) {
        errors.push("an issued MAC proof is two octet strings (signature " +
                    "and Shared Secret); this has " + jwp.proof.length + ".");
      } else {
        var macs = jwp.payloads.map(function (p, i) {
          return provider.hmac(a.mac, macPayloadKey(a, jwp.proof[1], i), p);
        });
        if (!provider.verify(a.sig, importJwk(o.issuerKey), combinedMac(ih,
                             macs), jwp.proof[0])) {
          errors.push("the issuer's signature over the Combined MAC " +
                      "Representation does not verify.");
        }
      }
    } else if (!bbs.verify(bbsKeys(o.issuerKey).pk, jwp.proof[0], ih,
                           jwp.payloads)) {
      errors.push("the BBS signature does not verify.");
    }
  } catch (e) {
    errors.push(e.message);
  }
  log.debug("Leaving confirm(). " + errors.length + " error(s).");
  return { valid: errors.length === 0, errors: errors, jwp: jwp };
}

// ---------------------------------------------------------------------------
// Present (JPA section 5.3). opts:
//   disclose ([slot index]), header (Presentation Header parameters: nonce,
//   aud, ...), holderKey (private JWK; SU and MAC).
// Returns the presented JWP in the issued one's serialization.
// ---------------------------------------------------------------------------
function present(input, opts) {
  log.debug("Entering present().");
  var jwp = typeof input === "object" && input.proof ? input : parse(input);
  if (jwp.form !== "issued") {
    log.debug("Leaving present(). Not issued.");
    throw new Error("present takes an issued JWP.");
  }
  var h = jwp.issuerHeader.value;
  var a = algOf(h.alg);
  var phValue = Object.assign({}, opts.header || {}, { alg: h.alg });
  delete phValue.hpa;
  if (phValue.nonce === undefined && phValue.aud === undefined) {
    log.debug("Leaving present(). No unique parameter.");
    throw new Error("a Presentation Header must carry a parameter unique " +
                    "to this presentation, such as nonce or aud (JWP " +
                    "section 6.2.1).");
  }
  var ph;
  if (jwp.serialization === "cbor") {
    var m = new Map();
    m.set(1, a.cbor);
    if (phValue.aud !== undefined) m.set(6, phValue.aud);
    if (phValue.nonce !== undefined) m.set(7, utf8(phValue.nonce));
    ph = mdoc.encode(m);
  } else {
    ph = utf8(sortedJson(phValue));
  }
  var show = {};
  (opts.disclose || []).forEach(function (i) {
    show[i] = true;
  });
  var slots = jwp.payloads.map(function (p, i) {
    return show[i] ? p : null;
  });
  var proof;
  if (a.kind === "su" || a.kind === "mac") {
    var components;
    if (a.kind === "su") {
      components = [jwp.proof[0]].concat(jwp.proof.slice(1).filter(
        function (_, i) {
          return show[i];
        }));
    } else {
      components = [jwp.proof[0]].concat(jwp.payloads.map(function (p, i) {
        var key = macPayloadKey(a, jwp.proof[1], i);
        return show[i] ? key : provider.hmac(a.mac, key, p);
      }));
    }
    var holder = opts.holderKey;
    if (!holder || !holder.d) {
      log.debug("Leaving present(). No holder key.");
      throw new Error(h.alg + " needs the holder's presentation PRIVATE " +
                      "key, which the Issuer Header's hpk names.");
    }
    var signer = hpaSigner(h.hpa || defaultHpa(holder), holder);
    var internal = presentationInternal(ph, jwp.issuerHeader.bytes, slots,
                                        components);
    proof = components.concat([provider.sign(signer, importJwk(holder, true),
                                             internal)]);
  } else {
    var k = bbsKeys(opts.issuerKey || {});
    var idx = Object.keys(show).map(Number).sort(function (x, y) {
      return x - y;
    });
    proof = [bbs.proofGen(k.pk, jwp.proof[0], jwp.issuerHeader.bytes, ph,
                          jwp.payloads, idx)];
  }
  var out = { serialization: jwp.serialization, form: "presented",
              presentationHeader: { bytes: ph, value: phValue },
              issuerHeader: jwp.issuerHeader, payloads: slots, proof: proof };
  if (jwp.values) {
    out.values = jwp.values.map(function (v, i) {
      return show[i] ? v : null;
    });
  }
  log.debug("Leaving present().");
  return serialize(out);
}

// ---------------------------------------------------------------------------
// Verify (JPA section 5.4): the verifier checks a PRESENTED JWP. opts:
//   issuerKey (public JWK), nonce and aud (what this Verifier expects in
//   the Presentation Header), claimNames (when the Issuer Header has no
//   claims array).
// Returns { valid, errors, warnings, jwp, disclosed: [index], claims }.
// ---------------------------------------------------------------------------
function verify(input, opts) {
  log.debug("Entering verify().");
  var o = opts || {};
  var errors = [];
  var warnings = [];
  var jwp;
  try {
    jwp = typeof input === "object" && input.proof ? input : parse(input);
  } catch (e) {
    log.debug("Leaving verify(). Unparseable.");
    return { valid: false, errors: [e.message], warnings: [] };
  }
  if (jwp.form !== "presented") {
    log.debug("Leaving verify(). Issued.");
    return { valid: false, jwp: jwp, warnings: [], errors: ["verify takes " +
             "a presented JWP; an issued one is never presented as it " +
             "stands (JWP section 6.1)."] };
  }
  var h = jwp.issuerHeader.value;
  var ph = jwp.presentationHeader.value;
  var slots = jwp.payloads || [];
  var disclosed = [];
  slots.forEach(function (s, i) {
    if (s !== null) disclosed.push(i);
  });
  try {
    var a = algOf(h.alg);
    if (ph.alg !== h.alg) {
      errors.push("the Presentation Header's alg (" + ph.alg + ") is not " +
                  "the Issuer Header's (" + h.alg + ").");
    }
    if (ph.hpa !== undefined) {
      errors.push("a Presentation Header must not carry hpa (JPA section " +
                  "7.1.8).");
    }
    if (o.nonce !== undefined && ph.nonce !== o.nonce) {
      errors.push("the Presentation Header's nonce (" + ph.nonce + ") is " +
                  "not this request's (" + o.nonce + ").");
    }
    if (o.aud !== undefined && [].concat(ph.aud || []).indexOf(o.aud) ===
        -1) {
      errors.push("the Presentation Header's aud does not name this " +
                  "Verifier (" + o.aud + ").");
    }
    var ih = jwp.issuerHeader.bytes;
    var phb = jwp.presentationHeader.bytes;
    if (a.kind === "su" || a.kind === "mac") {
      var expected = a.kind === "su" ? disclosed.length + 2 :
        slots.length + 2;
      if (jwp.proof.length !== expected) {
        errors.push("a presented " + h.alg + " proof has " + expected +
                    " components here; this has " + jwp.proof.length + ".");
      } else {
        var issuer = importJwk(o.issuerKey || {});
        if (a.kind === "su") {
          if (!provider.verify(a.sig, issuer, ih, jwp.proof[0])) {
            errors.push("the issuer's signature over the Issuer Header " +
                        "does not verify.");
          }
          var iek = importJwk(h.iek || {});
          disclosed.forEach(function (idx, n) {
            if (!provider.verify(a.sig, iek, slots[idx], jwp.proof[n + 1])) {
              errors.push("payload " + idx + "'s signature by the " +
                          "ephemeral key (iek) does not verify.");
            }
          });
        } else {
          var macs = slots.map(function (s, i) {
            var c = jwp.proof[i + 1];
            return s === null ? c : provider.hmac(a.mac, c, s);
          });
          if (!provider.verify(a.sig, issuer, combinedMac(ih, macs),
                               jwp.proof[0])) {
            errors.push("the issuer's signature over the Combined MAC " +
                        "Representation does not verify: a disclosed " +
                        "payload, its key or a withheld MAC was changed.");
          }
        }
        var hpk = h.hpk || {};
        var signer = hpaSigner(h.hpa || defaultHpa(hpk), hpk);
        var internal = presentationInternal(phb, ih, slots,
                                            jwp.proof.slice(0, -1));
        if (!provider.verify(signer, importJwk(hpk), internal,
                             jwp.proof[jwp.proof.length - 1])) {
          errors.push("the holder's signature over the presentation, by " +
                      "the Issuer Header's hpk, does not verify.");
        }
      }
    } else if (jwp.proof.length !== 1 ||
               !bbs.proofVerify(bbsKeys(o.issuerKey || {}).pk, jwp.proof[0],
                                ih, phb, disclosed.map(function (i) {
                                  return slots[i];
                                }), disclosed)) {
      errors.push("the BBS presentation proof does not verify.");
    }
  } catch (e) {
    errors.push(e.message);
  }
  var claims = null;
  try {
    claims = claimsOf(jwp, o.claimNames);
  } catch (e) {
    warnings.push(e.message);
  }
  log.debug("Leaving verify(). " + errors.length + " error(s).");
  return { valid: errors.length === 0, errors: errors, warnings: warnings,
           jwp: jwp, disclosed: disclosed, claims: claims,
           issuerHeader: h, presentationHeader: ph };
}

// ---------------------------------------------------------------------------
// JPT (draft-ietf-jose-json-proof-token-15): payload slot i is the value of
// claim claims[i], each a JSON value (a CPT's, a CBOR value). An omitted
// payload is no claim at all.
// ---------------------------------------------------------------------------
function claimNamesOf(jwp, names) {
  log.debug("Entering claimNamesOf().");
  var list = names || jwp.issuerHeader.value.claims;
  if (!Array.isArray(list)) {
    log.debug("Leaving claimNamesOf(). None.");
    throw new Error("no claim names: the Issuer Header has no claims " +
                    "array" + (jwp.issuerHeader.value.cid ? " (its cid " +
                    "names a set held elsewhere)" : "") + ".");
  }
  log.debug("Leaving claimNamesOf().");
  return list;
}

function claimsOf(jwp, names) {
  log.debug("Entering claimsOf().");
  var list = claimNamesOf(jwp, names);
  var out = {};
  (jwp.payloads || []).forEach(function (p, i) {
    if (p === null) return;
    var name = String(list[i]);
    out[name] = jwp.serialization === "cbor" ? cbor.toPlain(cbor.decode(p)) :
      JSON.parse(bytes.bytesToStr(p));
  });
  log.debug("Leaving claimsOf(). " + Object.keys(out).length + " claim(s).");
  return out;
}

// The payloads of a JPT for a claims object, in a fixed claim-name order.
function jptPayloads(claims, names) {
  log.debug("Entering jptPayloads().");
  log.debug("Leaving jptPayloads().");
  return names.map(function (n) {
    return utf8(JSON.stringify(claims[n]));
  });
}

module.exports = {
  DRAFT: DRAFT,
  MEDIA_JPT: MEDIA_JPT,
  ALGS: ALGS,
  parse: parse,
  parseCompact: parseCompact,
  parseCbor: parseCbor,
  serialize: serialize,
  looksLikeJwp: looksLikeJwp,
  presentationInternal: presentationInternal,
  combinedMac: combinedMac,
  macPayloadKey: macPayloadKey,
  issue: issue,
  confirm: confirm,
  present: present,
  verify: verify,
  claimNamesOf: claimNamesOf,
  claimsOf: claimsOf,
  jptPayloads: jptPayloads
};
