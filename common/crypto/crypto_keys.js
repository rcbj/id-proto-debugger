// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: crypto_keys.js
//
// ---------------------------------------------------------------------------
// THE ONE KEY REPRESENTATION, and every encoding of it (issue #463, step 1).
//
// crypto_provider.js is the facade every format layer calls; this is the half
// of it that is about KEYS rather than operations, split out only because one
// file holding both was past the point where it could be read. Nothing outside
// common/crypto should require this file directly — crypto_provider.js
// re-exports all of it.
//
// A key is a plain object:
//
//   { type:       "ec" | "okp" | "rsa" | "oct" | "akp" | "kem" | "hbs",
//     curve:      "P-256" | "P-384" | "P-521" | "secp256k1"      (ec)
//                 "Ed25519" | "Ed448" | "X25519" | "X448"        (okp)
//     bits:       modulus length                                 (rsa)
//     alg:        the pqc.js / hbs.js name, e.g. "ML-DSA-44"     (akp/kem/hbs)
//     publicKey:  Uint8Array
//     privateKey: Uint8Array (absent on a public key)
//     rsa:        { n, e, d, p, q, dp, dq, qi } as minimal unsigned
//                 big-endian Uint8Arrays                         (rsa) }
//
// What the two byte fields hold, per type, because "the public key" is a
// different thing in each:
//
//   ec   publicKey  = the UNCOMPRESSED point 0x04 || X || Y, each coordinate
//                    padded to the field size; privateKey = the scalar d,
//                    padded to the field size (66 bytes for P-521).
//   okp  publicKey  = the RFC 8032 / RFC 7748 encoding; privateKey = the seed
//                    (Ed*) or scalar (X*), exactly as a JWK's "d" carries it.
//   rsa  publicKey  = PKCS#1 RSAPublicKey DER; privateKey = PKCS#1
//                    RSAPrivateKey DER. The components are in `rsa` as well,
//                    because every operation wants them and none wants DER.
//   oct  privateKey = the secret; publicKey is empty. Here so an HMAC or a
//                    key-wrap key can arrive as an oct JWK like any other.
//   akp  ML-DSA / SLH-DSA / the composites, in RFC 9964's AKP sense:
//                    publicKey = "pub", privateKey = "priv" — the 32-byte SEED
//                    for ML-DSA, the full secret key for SLH-DSA.
//   kem  ML-KEM / X-Wing / composite KEMs: publicKey = the encapsulation key,
//                    privateKey = the EXPANDED decapsulation key, because that
//                    is what pk_encryption.js and pqc.js decapsulate with.
//   hbs  LMS/HSS or XMSS/XMSS^MT, as hbs.js serializes them. THE PRIVATE KEY
//                    CHANGES ON EVERY SIGNATURE — see crypto_provider.sign().
//
// THE DER IS WRITTEN HERE BY HAND, deliberately, and is required to be
// BYTE-IDENTICAL to what node's crypto (OpenSSL) exports for the same key —
// tests/crypto_provider_engine.js asserts exactly that for every classical key
// type. node-forge's asn1 would have done the writing, but its idea of a
// minimal INTEGER and of an EC PKCS#8 is not OpenSSL's, and a second reading of
// a format that disagrees with the first in one optional field is the defect
// this whole module exists to retire.
//
// PURE JS AND DOM-FREE. No Web Crypto anywhere: generation is @noble/curves,
// node-forge (RSA) and the post-quantum engines already in this directory.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var forge = require("node-forge");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var x25519 = require("@noble/curves/ed25519").x25519;
var ed448 = require("@noble/curves/ed448").ed448;
var x448 = require("@noble/curves/ed448").x448;
var mlkem = require("@noble/post-quantum/ml-kem.js");
var bytes = require("./crypto_bytes");
var hashTools = require("./hash_tools");
var pqc = require("./pqc");
var hbs = require("./hbs");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "crypto_keys",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var asBytes = bytes.asBytes;
var concatBytes = bytes.concatBytes;
var bytesToB64u = bytes.bytesToB64u;
var b64uToBytes = bytes.b64uToBytes;
var bytesToHex = bytes.bytesToHex;
var hexToBytes = bytes.hexToBytes;

// ===========================================================================
// THE CURVES
// ===========================================================================
// `cose` is the COSE Elliptic Curves registry value (RFC 9053 table 18, RFC
// 8812 for secp256k1). `size` is the field size in bytes, which is the length
// of a coordinate, of d, and of half an r||s signature.
var EC_CURVES = {
  "P-256": { noble: p256, oid: "1.2.840.10045.3.1.7", size: 32, cose: 1,
             spec: "ec-p256" },
  "P-384": { noble: p384, oid: "1.3.132.0.34", size: 48, cose: 2,
             spec: "ec-p384" },
  "P-521": { noble: p521, oid: "1.3.132.0.35", size: 66, cose: 3,
             spec: "ec-p521" },
  "secp256k1": { noble: secp256k1, oid: "1.3.132.0.10", size: 32, cose: 8,
                 spec: "ec-secp256k1" }
};

// `pub`/`priv` are the encoded lengths. `sign` says which of the two kinds
// it is: an Edwards curve signs, a Montgomery one only agrees.
var OKP_CURVES = {
  "Ed25519": { noble: ed25519, oid: "1.3.101.112", pub: 32, priv: 32,
               cose: 6, sign: true, spec: "ed25519" },
  "Ed448": { noble: ed448, oid: "1.3.101.113", pub: 57, priv: 57,
             cose: 7, sign: true, spec: "ed448" },
  "X25519": { noble: x25519, oid: "1.3.101.110", pub: 32, priv: 32,
              cose: 4, sign: false, spec: "x25519" },
  "X448": { noble: x448, oid: "1.3.101.111", pub: 56, priv: 56,
            cose: 5, sign: false, spec: "x448" }
};

var OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
var OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

// The PKIX object identifiers of the post-quantum algorithms whose
// SubjectPublicKeyInfo is just the key's bytes in the BIT STRING: RFC 9881
// (ML-DSA), RFC 9909 (SLH-DSA) and RFC 9935 (ML-KEM). The composites and
// X-Wing are deliberately absent — their PKIX bindings are drafts whose
// encodings client/src/pqc_x509.js already carries, and a second copy of a
// draft's OID table is two things to update when the draft moves.
var PQ_OIDS = {
  "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
  "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
  "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
  "SLH-DSA-SHA2-128s": "2.16.840.1.101.3.4.3.20",
  "SLH-DSA-SHA2-128f": "2.16.840.1.101.3.4.3.21",
  "SLH-DSA-SHA2-192s": "2.16.840.1.101.3.4.3.22",
  "SLH-DSA-SHA2-192f": "2.16.840.1.101.3.4.3.23",
  "SLH-DSA-SHA2-256s": "2.16.840.1.101.3.4.3.24",
  "SLH-DSA-SHA2-256f": "2.16.840.1.101.3.4.3.25",
  "SLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.26",
  "SLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.27",
  "SLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.28",
  "SLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.29",
  "SLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.30",
  "SLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.31",
  "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
  "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
  "ML-KEM-1024": "2.16.840.1.101.3.4.4.3"
};

var ML_KEM_PRIMS = {
  "ML-KEM-512": mlkem.ml_kem512,
  "ML-KEM-768": mlkem.ml_kem768,
  "ML-KEM-1024": mlkem.ml_kem1024
};

// COSE algorithm values an AKP COSE_Key must carry (RFC 9964 section 4 makes
// label 3 REQUIRED for that key type). Only the ones with a registered value.
var AKP_COSE_ALGS = { "ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50 };

var HBS_ALGS = ["HSS-LMS", "XMSS", "XMSSMT"];

// The key specs generateKeyPair() takes for the classical algorithms. The
// post-quantum and hash-based ones are resolved by name instead (pqcName()).
var KEY_SPECS = {
  "ec-p256": { type: "ec", curve: "P-256" },
  "ec-p384": { type: "ec", curve: "P-384" },
  "ec-p521": { type: "ec", curve: "P-521" },
  "ec-secp256k1": { type: "ec", curve: "secp256k1" },
  "ed25519": { type: "okp", curve: "Ed25519" },
  "ed448": { type: "okp", curve: "Ed448" },
  "x25519": { type: "okp", curve: "X25519" },
  "x448": { type: "okp", curve: "X448" },
  "rsa-2048": { type: "rsa", bits: 2048 },
  "rsa-3072": { type: "rsa", bits: 3072 },
  "rsa-4096": { type: "rsa", bits: 4096 }
};

// ===========================================================================
// DER — a writer and a reader, both small, both over Uint8Array.
// ===========================================================================
function derLength(count) {
  log.debug("Entering derLength().");
  if (count < 0x80) {
    log.debug("Leaving derLength(). Short form.");
    return new Uint8Array([count]);
  }
  var out = [];
  while (count > 0) {
    out.unshift(count & 0xff);
    count = Math.floor(count / 256);
  }
  out.unshift(0x80 | out.length);
  log.debug("Leaving derLength(). Long form.");
  return new Uint8Array(out);
}

function derTlv(tag, contents) {
  log.debug("Entering derTlv(). tag=" + tag);
  var body = asBytes(contents);
  log.debug("Leaving derTlv().");
  return concatBytes(concatBytes(new Uint8Array([tag]),
                                 derLength(body.length)), body);
}

function derSequence(parts) {
  log.debug("Entering derSequence().");
  var body = new Uint8Array(0);
  for (var i = 0; i < parts.length; i++) {
    body = concatBytes(body, parts[i]);
  }
  log.debug("Leaving derSequence().");
  return derTlv(0x30, body);
}

// An unsigned big-endian magnitude as a DER INTEGER: leading zero octets
// stripped, then ONE put back if the top bit is set, which is what makes a
// positive number not read as negative. Zero is the single octet 00.
function derUnsignedInteger(value) {
  log.debug("Entering derUnsignedInteger().");
  var v = stripLeadingZeros(asBytes(value));
  if (v.length === 0) {
    v = new Uint8Array([0]);
  } else if (v[0] & 0x80) {
    v = concatBytes(new Uint8Array([0]), v);
  }
  log.debug("Leaving derUnsignedInteger().");
  return derTlv(0x02, v);
}

function derSmallInteger(n) {
  log.debug("Entering derSmallInteger(). n=" + n);
  log.debug("Leaving derSmallInteger().");
  return derUnsignedInteger(new Uint8Array([n]));
}

function derOid(dotted) {
  log.debug("Entering derOid(). oid=" + dotted);
  var arcs = dotted.split(".").map(function (a) {
    return parseInt(a, 10);
  });
  var out = [40 * arcs[0] + arcs[1]];
  for (var i = 2; i < arcs.length; i++) {
    var arc = arcs[i];
    var chunk = [arc & 0x7f];
    arc = Math.floor(arc / 128);
    while (arc > 0) {
      chunk.unshift(0x80 | (arc & 0x7f));
      arc = Math.floor(arc / 128);
    }
    out = out.concat(chunk);
  }
  log.debug("Leaving derOid().");
  return derTlv(0x06, new Uint8Array(out));
}

function derBitString(value) {
  log.debug("Entering derBitString().");
  log.debug("Leaving derBitString().");
  return derTlv(0x03, concatBytes(new Uint8Array([0]), asBytes(value)));
}

function derOctetString(value) {
  log.debug("Entering derOctetString().");
  log.debug("Leaving derOctetString().");
  return derTlv(0x04, asBytes(value));
}

var DER_NULL = new Uint8Array([0x05, 0x00]);

// Reads ONE TLV at `offset`. Returns { tag, value, end }. Definite lengths
// only — DER has no other kind — and a length running past the buffer is an
// error rather than a short read.
function derRead(input, offset) {
  log.debug("Entering derRead().");
  var buf = asBytes(input);
  var pos = offset || 0;
  if (pos + 2 > buf.length) {
    log.debug("Leaving derRead(). Truncated header.");
    throw new Error("DER: truncated at offset " + pos + ".");
  }
  var tag = buf[pos++];
  var len = buf[pos++];
  if (len & 0x80) {
    var count = len & 0x7f;
    if (count === 0 || count > 4) {
      log.debug("Leaving derRead(). Bad length.");
      throw new Error("DER: unsupported length encoding at offset " +
                      (pos - 1) + ".");
    }
    len = 0;
    for (var i = 0; i < count; i++) {
      len = len * 256 + buf[pos++];
    }
  }
  if (pos + len > buf.length) {
    log.debug("Leaving derRead(). Truncated value.");
    throw new Error("DER: value of " + len + " bytes runs past the end.");
  }
  log.debug("Leaving derRead().");
  return { tag: tag, value: buf.subarray(pos, pos + len), end: pos + len };
}

// The children of a constructed value, in order.
function derChildren(value) {
  log.debug("Entering derChildren().");
  var out = [];
  var pos = 0;
  while (pos < value.length) {
    var node = derRead(value, pos);
    out.push(node);
    pos = node.end;
  }
  log.debug("Leaving derChildren(). count=" + out.length);
  return out;
}

function derExpect(node, tag, what) {
  log.debug("Entering derExpect(). what=" + what);
  if (!node || node.tag !== tag) {
    log.debug("Leaving derExpect(). Wrong tag.");
    throw new Error("DER: expected " + what + " (tag 0x" +
                    tag.toString(16) + "), found " +
                    (node ? "tag 0x" + node.tag.toString(16) : "nothing") +
                    ".");
  }
  log.debug("Leaving derExpect().");
  return node;
}

function derOidString(value) {
  log.debug("Entering derOidString().");
  var arcs = [Math.floor(value[0] / 40), value[0] % 40];
  var acc = 0;
  for (var i = 1; i < value.length; i++) {
    acc = acc * 128 + (value[i] & 0x7f);
    if (!(value[i] & 0x80)) {
      arcs.push(acc);
      acc = 0;
    }
  }
  log.debug("Leaving derOidString().");
  return arcs.join(".");
}

function stripLeadingZeros(value) {
  log.debug("Entering stripLeadingZeros().");
  var i = 0;
  while (i < value.length && value[i] === 0) {
    i++;
  }
  log.debug("Leaving stripLeadingZeros().");
  return value.slice(i);
}

function padTo(value, size, what) {
  log.debug("Entering padTo(). size=" + size);
  var v = stripLeadingZeros(asBytes(value));
  if (v.length > size) {
    log.debug("Leaving padTo(). Too long.");
    throw new Error((what || "Value") + " is " + v.length + " bytes; at " +
                    "most " + size + " fit.");
  }
  var out = new Uint8Array(size);
  out.set(v, size - v.length);
  log.debug("Leaving padTo().");
  return out;
}

// ===========================================================================
// RSA components <-> forge, <-> PKCS#1
// ===========================================================================
var RSA_MEMBERS = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];

function forgeBigToBytes(big) {
  log.debug("Entering forgeBigToBytes().");
  var hex = big.toString(16);
  if (hex.length % 2) {
    hex = "0" + hex;
  }
  log.debug("Leaving forgeBigToBytes().");
  return stripLeadingZeros(hexToBytes(hex));
}

function bytesToForgeBig(value) {
  log.debug("Entering bytesToForgeBig().");
  log.debug("Leaving bytesToForgeBig().");
  return new forge.jsbn.BigInteger(bytesToHex(asBytes(value)) || "0", 16);
}

function bitLength(value) {
  log.debug("Entering bitLength().");
  var v = stripLeadingZeros(asBytes(value));
  if (!v.length) {
    log.debug("Leaving bitLength(). Zero.");
    return 0;
  }
  var top = v[0], bits = 0;
  while (top) {
    bits++;
    top >>= 1;
  }
  log.debug("Leaving bitLength().");
  return (v.length - 1) * 8 + bits;
}

// Builds the key object from components; `rsa.d` absent means public.
function rsaKeyFromComponents(components) {
  log.debug("Entering rsaKeyFromComponents().");
  var rsa = {};
  for (var i = 0; i < RSA_MEMBERS.length; i++) {
    var m = RSA_MEMBERS[i];
    if (components[m] !== undefined && components[m] !== null) {
      rsa[m] = stripLeadingZeros(asBytes(components[m]));
    }
  }
  if (!rsa.n || !rsa.e) {
    log.debug("Leaving rsaKeyFromComponents(). No modulus.");
    throw new Error("An RSA key needs at least n and e.");
  }
  var key = { type: "rsa", bits: bitLength(rsa.n), rsa: rsa,
              publicKey: derSequence([derUnsignedInteger(rsa.n),
                                      derUnsignedInteger(rsa.e)]) };
  if (rsa.d) {
    for (var j = 3; j < RSA_MEMBERS.length; j++) {
      if (!rsa[RSA_MEMBERS[j]]) {
        log.debug("Leaving rsaKeyFromComponents(). No CRT members.");
        throw new Error("This RSA private key has no \"" + RSA_MEMBERS[j] +
                        "\". Keys without the CRT members (p, q, dp, dq, " +
                        "qi) are not supported.");
      }
    }
    var parts = [derSmallInteger(0)];
    for (var k = 0; k < RSA_MEMBERS.length; k++) {
      parts.push(derUnsignedInteger(rsa[RSA_MEMBERS[k]]));
    }
    key.privateKey = derSequence(parts);
  }
  log.debug("Leaving rsaKeyFromComponents().");
  return key;
}

function rsaFromPkcs1(der, isPrivate) {
  log.debug("Entering rsaFromPkcs1(). private=" + !!isPrivate);
  var seq = derExpect(derRead(der, 0), 0x30, "RSA key SEQUENCE");
  var items = derChildren(seq.value);
  var c = {};
  if (isPrivate) {
    for (var i = 0; i < RSA_MEMBERS.length; i++) {
      c[RSA_MEMBERS[i]] = derExpect(items[i + 1], 0x02, RSA_MEMBERS[i]).value;
    }
  } else {
    c.n = derExpect(items[0], 0x02, "n").value;
    c.e = derExpect(items[1], 0x02, "e").value;
  }
  log.debug("Leaving rsaFromPkcs1().");
  return rsaKeyFromComponents(c);
}

// The forge key object an RSA operation runs on. Exported for
// crypto_provider.js only.
function toForgeRsa(key, wantPrivate) {
  log.debug("Entering toForgeRsa(). private=" + !!wantPrivate);
  if (!key || key.type !== "rsa") {
    log.debug("Leaving toForgeRsa(). Not RSA.");
    throw new Error("An RSA key is required here; this one is " +
                    (key && key.type) + ".");
  }
  var r = key.rsa;
  if (!wantPrivate) {
    log.debug("Leaving toForgeRsa(). Public.");
    return forge.pki.setRsaPublicKey(bytesToForgeBig(r.n),
                                     bytesToForgeBig(r.e));
  }
  if (!r.d) {
    log.debug("Leaving toForgeRsa(). No private half.");
    throw new Error("That RSA key is a PUBLIC key — it has no private " +
                    "exponent.");
  }
  log.debug("Leaving toForgeRsa(). Private.");
  return forge.pki.setRsaPrivateKey(bytesToForgeBig(r.n),
    bytesToForgeBig(r.e), bytesToForgeBig(r.d), bytesToForgeBig(r.p),
    bytesToForgeBig(r.q), bytesToForgeBig(r.dp), bytesToForgeBig(r.dq),
    bytesToForgeBig(r.qi));
}

// ===========================================================================
// Building keys of each type from their parts
// ===========================================================================
function ecCurve(name) {
  log.debug("Entering ecCurve(). name=" + name);
  var c = EC_CURVES[name];
  if (!c) {
    log.debug("Leaving ecCurve(). Unknown.");
    throw new Error("Unknown EC curve: " + name);
  }
  log.debug("Leaving ecCurve().");
  return c;
}

function okpCurve(name) {
  log.debug("Entering okpCurve(). name=" + name);
  var c = OKP_CURVES[name];
  if (!c) {
    log.debug("Leaving okpCurve(). Unknown.");
    throw new Error("Unknown OKP curve: " + name);
  }
  log.debug("Leaving okpCurve().");
  return c;
}

// An EC key from a public point (any encoding @noble reads — uncompressed or
// compressed) and/or a private scalar. The point is VALIDATED: an off-curve
// point is refused here rather than producing a shared secret or a
// verification against something that is not a key.
function ecKey(curveName, publicPoint, privateScalar) {
  log.debug("Entering ecKey(). curve=" + curveName);
  var c = ecCurve(curveName);
  var key = { type: "ec", curve: curveName };
  if (privateScalar) {
    key.privateKey = padTo(privateScalar, c.size, "The private scalar");
    var derived = asBytes(c.noble.getPublicKey(key.privateKey, false));
    if (publicPoint) {
      var given = asBytes(c.noble.ProjectivePoint.fromHex(asBytes(publicPoint))
        .toRawBytes(false));
      if (!bytes.bytesEqual(given, derived)) {
        log.debug("Leaving ecKey(). Halves disagree.");
        throw new Error("The public point does not belong to this private " +
                        "key.");
      }
    }
    key.publicKey = derived;
  } else {
    key.publicKey = asBytes(c.noble.ProjectivePoint
      .fromHex(asBytes(publicPoint)).toRawBytes(false));
  }
  log.debug("Leaving ecKey().");
  return key;
}

function okpKey(curveName, publicBytes, privateBytes) {
  log.debug("Entering okpKey(). curve=" + curveName);
  var c = okpCurve(curveName);
  var key = { type: "okp", curve: curveName };
  if (privateBytes) {
    key.privateKey = asBytes(privateBytes).slice();
    if (key.privateKey.length !== c.priv) {
      log.debug("Leaving okpKey(). Bad private length.");
      throw new Error(curveName + " private keys are " + c.priv + " bytes; " +
                      "this one is " + key.privateKey.length + ".");
    }
    var derived = asBytes(c.noble.getPublicKey(key.privateKey));
    if (publicBytes && !bytes.bytesEqual(asBytes(publicBytes), derived)) {
      log.debug("Leaving okpKey(). Halves disagree.");
      throw new Error("The public key does not belong to this private key.");
    }
    key.publicKey = derived;
  } else {
    key.publicKey = asBytes(publicBytes).slice();
    if (key.publicKey.length !== c.pub) {
      log.debug("Leaving okpKey(). Bad public length.");
      throw new Error(curveName + " public keys are " + c.pub + " bytes; " +
                      "this one is " + key.publicKey.length + ".");
    }
  }
  log.debug("Leaving okpKey().");
  return key;
}

// The canonical name of a post-quantum or hash-based algorithm, looked up
// case-insensitively so "ml-dsa-44" and "ML-DSA-44" are one spec. Returns
// { type, alg } or null.
function pqcName(name) {
  log.debug("Entering pqcName(). name=" + name);
  var wanted = String(name || "").toLowerCase();
  var sigs = Object.keys(pqc.SIGNATURE_ALGS);
  for (var i = 0; i < sigs.length; i++) {
    if (sigs[i].toLowerCase() === wanted) {
      log.debug("Leaving pqcName(). Signature.");
      return { type: "akp", alg: sigs[i] };
    }
  }
  var kems = Object.keys(pqc.KEM_ALGS);
  for (var j = 0; j < kems.length; j++) {
    if (kems[j].toLowerCase() === wanted) {
      log.debug("Leaving pqcName(). KEM.");
      return { type: "kem", alg: kems[j] };
    }
  }
  for (var k = 0; k < HBS_ALGS.length; k++) {
    if (HBS_ALGS[k].toLowerCase() === wanted) {
      log.debug("Leaving pqcName(). Hash-based.");
      return { type: "hbs", alg: HBS_ALGS[k] };
    }
  }
  log.debug("Leaving pqcName(). Unknown.");
  return null;
}

function opaqueKey(type, alg, publicBytes, privateBytes) {
  log.debug("Entering opaqueKey(). type=" + type + " alg=" + alg);
  var key = { type: type, alg: alg, publicKey: asBytes(publicBytes).slice() };
  if (privateBytes) {
    key.privateKey = asBytes(privateBytes).slice();
  }
  log.debug("Leaving opaqueKey().");
  return key;
}

// ===========================================================================
// GENERATION
// ===========================================================================
// spec: a KEY_SPECS name ("ec-p256", "ed448", "rsa-3072", ...), a pqc.js name
// in any case ("ml-dsa-44", "SLH-DSA-SHAKE-128s", "ML-DSA-44-ES256",
// "ml-kem-768", "X-Wing"), or "HSS-LMS" / "XMSS" / "XMSSMT" with `options`
// passed through to hbs.js (levels for HSS, name for XMSS). Also accepts
// "rsa" with options.bits.
//
// RSA goes through forge SYNCHRONOUSLY: forge only reaches for Web Crypto (or
// a worker) when given a callback, and this never gives it one. In a browser
// that makes RSA-4096 a multi-second, blocking call — the price of a path that
// works outside a secure context. (In node forge quietly uses node's own
// generator, which is OpenSSL; that is forge's choice and not a Web Crypto
// one.)
function generateKeyPair(spec, options) {
  log.debug("Entering generateKeyPair(). spec=" + spec);
  var opts = options || {};
  var name = String(spec || "").toLowerCase();
  var classical = KEY_SPECS[name];
  if (name === "rsa") {
    classical = { type: "rsa", bits: opts.bits || 2048 };
  }
  if (classical && classical.type === "ec") {
    var c = ecCurve(classical.curve);
    log.debug("Leaving generateKeyPair(). EC.");
    return ecKey(classical.curve, null, c.noble.utils.randomPrivateKey());
  }
  if (classical && classical.type === "okp") {
    var o = okpCurve(classical.curve);
    log.debug("Leaving generateKeyPair(). OKP.");
    return okpKey(classical.curve, null, o.noble.utils.randomPrivateKey());
  }
  if (classical && classical.type === "rsa") {
    var pair = forge.pki.rsa.generateKeyPair({ bits: classical.bits,
                                               e: 0x10001 });
    var pk = pair.privateKey;
    log.debug("Leaving generateKeyPair(). RSA.");
    return rsaKeyFromComponents({
      n: forgeBigToBytes(pk.n), e: forgeBigToBytes(pk.e),
      d: forgeBigToBytes(pk.d), p: forgeBigToBytes(pk.p),
      q: forgeBigToBytes(pk.q), dp: forgeBigToBytes(pk.dP),
      dq: forgeBigToBytes(pk.dQ), qi: forgeBigToBytes(pk.qInv)
    });
  }
  var pq = pqcName(spec);
  if (pq && pq.type === "akp") {
    var akp = pqc.generateAkpKeyPair(pq.alg);
    log.debug("Leaving generateKeyPair(). AKP.");
    return opaqueKey("akp", pq.alg, akp.pub, akp.priv);
  }
  if (pq && pq.type === "kem") {
    var kp = pqc.kemAlg(pq.alg).keygen();
    log.debug("Leaving generateKeyPair(). KEM.");
    return opaqueKey("kem", pq.alg, kp.publicKey, kp.secretKey);
  }
  if (pq && pq.type === "hbs") {
    var made;
    var hbsAlg = pq.alg;
    if (pq.alg === "HSS-LMS") {
      made = hbs.hssKeygen({
        levels: opts.levels || [{ lms: "LMS_SHA256_M32_H5",
                                  lmots: "LMOTS_SHA256_N32_W8" }] });
    } else {
      var setName = opts.name ||
        (pq.alg === "XMSS" ? "XMSS-SHA2_10_256" : "XMSSMT-SHA2_20/4_256");
      // The parameter set decides single- or multi-tree, not the spec name,
      // because verification has to know which of the two it is reading.
      hbsAlg = hbs.resolveXmss(setName).multiTree ? "XMSSMT" : "XMSS";
      made = hbs.xmssKeygen(setName);
    }
    log.debug("Leaving generateKeyPair(). Hash-based.");
    return opaqueKey("hbs", hbsAlg, made.publicKey, made.privateKey);
  }
  log.debug("Leaving generateKeyPair(). Unknown spec.");
  throw new Error("Unknown key spec: " + spec);
}

// The public half alone, as a new object.
function publicKeyOf(key) {
  log.debug("Entering publicKeyOf().");
  var out = {};
  var names = Object.keys(key);
  for (var i = 0; i < names.length; i++) {
    if (names[i] !== "privateKey" && names[i] !== "rsa") {
      out[names[i]] = key[names[i]];
    }
  }
  if (key.type === "oct") {
    log.debug("Leaving publicKeyOf(). A secret has no public half.");
    throw new Error("A symmetric (oct) key has no public half.");
  }
  if (key.rsa) {
    out.rsa = { n: key.rsa.n, e: key.rsa.e };
  }
  log.debug("Leaving publicKeyOf().");
  return out;
}

// ===========================================================================
// SPKI / PKCS#8
// ===========================================================================
function algorithmIdentifierFor(key) {
  log.debug("Entering algorithmIdentifierFor(). type=" + key.type);
  if (key.type === "ec") {
    log.debug("Leaving algorithmIdentifierFor(). EC.");
    return derSequence([derOid(OID_EC_PUBLIC_KEY),
                        derOid(ecCurve(key.curve).oid)]);
  }
  if (key.type === "okp") {
    log.debug("Leaving algorithmIdentifierFor(). OKP.");
    return derSequence([derOid(okpCurve(key.curve).oid)]);
  }
  if (key.type === "rsa") {
    log.debug("Leaving algorithmIdentifierFor(). RSA.");
    return derSequence([derOid(OID_RSA_ENCRYPTION), DER_NULL]);
  }
  if ((key.type === "akp" || key.type === "kem") && PQ_OIDS[key.alg]) {
    log.debug("Leaving algorithmIdentifierFor(). Post-quantum.");
    return derSequence([derOid(PQ_OIDS[key.alg])]);
  }
  log.debug("Leaving algorithmIdentifierFor(). None.");
  throw new Error("No SubjectPublicKeyInfo / PKCS#8 encoding here for " +
                  (key.alg || key.type) + (key.type === "akp" ||
                  key.type === "kem" ? " — the composite and X-Wing PKIX " +
                  "bindings are in client/src/pqc_x509.js." : "."));
}

function spkiDer(key) {
  log.debug("Entering spkiDer().");
  log.debug("Leaving spkiDer().");
  return derSequence([algorithmIdentifierFor(key),
                      derBitString(key.publicKey)]);
}

// What the PKCS#8 privateKey OCTET STRING holds, per type. Each matches what
// OpenSSL 3 writes: an ECPrivateKey with the public key in [1] and WITHOUT the
// [0] parameters (they are in the AlgorithmIdentifier already); for Ed*/X*
// a CurvePrivateKey OCTET STRING (RFC 8410 section 7); for RSA the PKCS#1
// RSAPrivateKey. For ML-DSA the RFC 9881 `seed` arm ([0] IMPLICIT, the
// arm the RFC recommends), for ML-KEM the RFC 9935 `expandedKey` arm (this
// module holds ML-KEM keys expanded), and for SLH-DSA the raw secret key
// (RFC 9909 has no inner structure).
function pkcs8Inner(key) {
  log.debug("Entering pkcs8Inner(). type=" + key.type);
  if (key.type === "ec") {
    log.debug("Leaving pkcs8Inner(). EC.");
    return derSequence([derSmallInteger(1), derOctetString(key.privateKey),
                        derTlv(0xa1, derBitString(key.publicKey))]);
  }
  if (key.type === "okp") {
    log.debug("Leaving pkcs8Inner(). OKP.");
    return derOctetString(key.privateKey);
  }
  if (key.type === "rsa") {
    log.debug("Leaving pkcs8Inner(). RSA.");
    return key.privateKey;
  }
  if (/^ML-DSA-\d+$/.test(key.alg)) {
    log.debug("Leaving pkcs8Inner(). ML-DSA seed.");
    return derTlv(0x80, key.privateKey);
  }
  if (/^ML-KEM-\d+$/.test(key.alg)) {
    log.debug("Leaving pkcs8Inner(). ML-KEM expanded.");
    return derOctetString(key.privateKey);
  }
  log.debug("Leaving pkcs8Inner(). Raw.");
  return key.privateKey;
}

function pkcs8Der(key) {
  log.debug("Entering pkcs8Der().");
  if (!key.privateKey) {
    log.debug("Leaving pkcs8Der(). Public key.");
    throw new Error("PKCS#8 needs a private key; this one is public.");
  }
  var algId = algorithmIdentifierFor(key);
  log.debug("Leaving pkcs8Der().");
  return derSequence([derSmallInteger(0), algId,
                      derOctetString(pkcs8Inner(key))]);
}

function pqByOid(oid) {
  log.debug("Entering pqByOid(). oid=" + oid);
  var names = Object.keys(PQ_OIDS);
  for (var i = 0; i < names.length; i++) {
    if (PQ_OIDS[names[i]] === oid) {
      log.debug("Leaving pqByOid(). Found.");
      return names[i];
    }
  }
  log.debug("Leaving pqByOid(). Unknown.");
  return null;
}

function curveByOid(table, oid) {
  log.debug("Entering curveByOid(). oid=" + oid);
  var names = Object.keys(table);
  for (var i = 0; i < names.length; i++) {
    if (table[names[i]].oid === oid) {
      log.debug("Leaving curveByOid(). Found.");
      return names[i];
    }
  }
  log.debug("Leaving curveByOid(). Unknown.");
  return null;
}

// The AlgorithmIdentifier, read: { oid, curve? }.
function readAlgorithmIdentifier(node) {
  log.debug("Entering readAlgorithmIdentifier().");
  var parts = derChildren(derExpect(node, 0x30, "AlgorithmIdentifier").value);
  var out = { oid: derOidString(derExpect(parts[0], 0x06, "algorithm").value) };
  if (parts[1] && parts[1].tag === 0x06) {
    out.param = derOidString(parts[1].value);
  }
  log.debug("Leaving readAlgorithmIdentifier(). oid=" + out.oid);
  return out;
}

function bitStringBytes(node) {
  log.debug("Entering bitStringBytes().");
  derExpect(node, 0x03, "BIT STRING");
  if (node.value[0] !== 0) {
    log.debug("Leaving bitStringBytes(). Unused bits.");
    throw new Error("DER: a key BIT STRING with unused bits.");
  }
  log.debug("Leaving bitStringBytes().");
  return node.value.slice(1);
}

function fromSpki(der) {
  log.debug("Entering fromSpki().");
  var top = derChildren(derExpect(derRead(der, 0), 0x30, "SPKI").value);
  var alg = readAlgorithmIdentifier(top[0]);
  var pub = bitStringBytes(top[1]);
  if (alg.oid === OID_EC_PUBLIC_KEY) {
    var curve = curveByOid(EC_CURVES, alg.param);
    if (!curve) {
      log.debug("Leaving fromSpki(). Unknown curve.");
      throw new Error("Unsupported EC curve OID " + alg.param + ".");
    }
    log.debug("Leaving fromSpki(). EC.");
    return ecKey(curve, pub, null);
  }
  if (alg.oid === OID_RSA_ENCRYPTION) {
    log.debug("Leaving fromSpki(). RSA.");
    return rsaFromPkcs1(pub, false);
  }
  var okp = curveByOid(OKP_CURVES, alg.oid);
  if (okp) {
    log.debug("Leaving fromSpki(). OKP.");
    return okpKey(okp, pub, null);
  }
  var pq = pqByOid(alg.oid);
  if (pq) {
    log.debug("Leaving fromSpki(). Post-quantum.");
    return opaqueKey(/^ML-KEM/.test(pq) ? "kem" : "akp", pq, pub, null);
  }
  log.debug("Leaving fromSpki(). Unknown algorithm.");
  throw new Error("Unsupported SubjectPublicKeyInfo algorithm " + alg.oid +
                  ".");
}

function ecFromSec1(curveName, der) {
  log.debug("Entering ecFromSec1().");
  var parts = derChildren(derExpect(derRead(der, 0), 0x30,
                                    "ECPrivateKey").value);
  var d = derExpect(parts[1], 0x04, "privateKey").value;
  var pub = null;
  var curve = curveName;
  for (var i = 2; i < parts.length; i++) {
    if (parts[i].tag === 0xa0) {
      var named = derOidString(derExpect(derRead(parts[i].value, 0), 0x06,
                                         "namedCurve").value);
      curve = curve || curveByOid(EC_CURVES, named);
    } else if (parts[i].tag === 0xa1) {
      pub = bitStringBytes(derRead(parts[i].value, 0));
    }
  }
  if (!curve) {
    log.debug("Leaving ecFromSec1(). No curve.");
    throw new Error("An ECPrivateKey with no curve named anywhere.");
  }
  log.debug("Leaving ecFromSec1().");
  return ecKey(curve, pub, d);
}

function fromPkcs8(der) {
  log.debug("Entering fromPkcs8().");
  var top = derChildren(derExpect(derRead(der, 0), 0x30, "PKCS#8").value);
  var alg = readAlgorithmIdentifier(top[1]);
  var inner = derExpect(top[2], 0x04, "privateKey").value;
  if (alg.oid === OID_EC_PUBLIC_KEY) {
    var curve = curveByOid(EC_CURVES, alg.param);
    if (!curve) {
      log.debug("Leaving fromPkcs8(). Unknown curve.");
      throw new Error("Unsupported EC curve OID " + alg.param + ".");
    }
    log.debug("Leaving fromPkcs8(). EC.");
    return ecFromSec1(curve, inner);
  }
  if (alg.oid === OID_RSA_ENCRYPTION) {
    log.debug("Leaving fromPkcs8(). RSA.");
    return rsaFromPkcs1(inner, true);
  }
  var okp = curveByOid(OKP_CURVES, alg.oid);
  if (okp) {
    log.debug("Leaving fromPkcs8(). OKP.");
    return okpKey(okp, null, derExpect(derRead(inner, 0), 0x04,
                                       "CurvePrivateKey").value);
  }
  var pq = pqByOid(alg.oid);
  if (pq) {
    log.debug("Leaving fromPkcs8(). Post-quantum.");
    return pqFromPkcs8(pq, inner);
  }
  log.debug("Leaving fromPkcs8(). Unknown algorithm.");
  throw new Error("Unsupported PKCS#8 algorithm " + alg.oid + ".");
}

// The three CHOICE arms of RFC 9881 / RFC 9935 — seed [0], expandedKey
// OCTET STRING, both SEQUENCE — are all legal, and OpenSSL 3.5 writes `both`
// by default, so all three are read.
function pqFromPkcs8(alg, inner) {
  log.debug("Entering pqFromPkcs8(). alg=" + alg);
  if (/^SLH-DSA/.test(alg)) {
    var slh = pqc.signatureAlg(alg);
    var n = inner.length / 4;
    // An SLH-DSA secret key is SK.seed || SK.prf || PK.seed || PK.root, so
    // its second half IS the public key.
    log.debug("Leaving pqFromPkcs8(). SLH-DSA.");
    return opaqueKey("akp", slh.name || alg, inner.slice(2 * n), inner);
  }
  var node = derRead(inner, 0);
  var seed = null, expanded = null;
  if (node.tag === 0x80) {
    seed = node.value;
  } else if (node.tag === 0x04) {
    expanded = node.value;
  } else if (node.tag === 0x30) {
    var both = derChildren(node.value);
    seed = derExpect(both[0], 0x04, "seed").value;
    expanded = derExpect(both[1], 0x04, "expandedKey").value;
  } else {
    log.debug("Leaving pqFromPkcs8(). Unknown arm.");
    throw new Error("Unrecognised " + alg + " private key encoding (tag 0x" +
                    node.tag.toString(16) + ").");
  }
  if (/^ML-DSA/.test(alg)) {
    if (!seed) {
      log.debug("Leaving pqFromPkcs8(). ML-DSA without a seed.");
      throw new Error("This " + alg + " private key carries only the " +
                      "expanded key. The AKP representation (RFC 9964) is " +
                      "the 32-byte seed, which cannot be recovered from it.");
    }
    var kp = pqc.signatureAlg(alg).prim.keygen(seed);
    log.debug("Leaving pqFromPkcs8(). ML-DSA.");
    return opaqueKey("akp", alg, kp.publicKey, seed);
  }
  var prim = ML_KEM_PRIMS[alg];
  var sk = expanded || prim.keygen(seed).secretKey;
  // FIPS 203: the decapsulation key is dk_PKE || ek || H(ek) || z, so the
  // encapsulation key sits at 384k bytes in, and is 384k + 32 long.
  var k = (sk.length - 96) / 768;
  log.debug("Leaving pqFromPkcs8(). ML-KEM.");
  return opaqueKey("kem", alg, sk.slice(384 * k, 768 * k + 32), sk);
}

// The SubjectPublicKeyInfo inside a certificate: index 6 of the
// TBSCertificate with an explicit [0] version, 5 without.
function spkiFromCertificate(der) {
  log.debug("Entering spkiFromCertificate().");
  var cert = derChildren(derExpect(derRead(der, 0), 0x30,
                                   "Certificate").value);
  var tbs = derChildren(derExpect(cert[0], 0x30, "TBSCertificate").value);
  var index = tbs[0].tag === 0xa0 ? 6 : 5;
  var node = derExpect(tbs[index], 0x30, "subjectPublicKeyInfo");
  // Re-encoding is exact: a DER SEQUENCE is its tag, its minimal length and
  // its body, so writing it back out reproduces the input bytes.
  log.debug("Leaving spkiFromCertificate().");
  return derTlv(0x30, node.value);
}

// ===========================================================================
// JWK
// ===========================================================================
function toJwk(key, options) {
  log.debug("Entering toJwk(). type=" + key.type);
  var opts = options || {};
  var withPrivate = !!key.privateKey && !opts.publicOnly;
  var jwk;
  if (key.type === "ec") {
    var size = ecCurve(key.curve).size;
    jwk = { kty: "EC", crv: key.curve,
            x: bytesToB64u(key.publicKey.slice(1, 1 + size)),
            y: bytesToB64u(key.publicKey.slice(1 + size)) };
    if (withPrivate) {
      jwk.d = bytesToB64u(key.privateKey);
    }
  } else if (key.type === "okp") {
    jwk = { kty: "OKP", crv: key.curve, x: bytesToB64u(key.publicKey) };
    if (withPrivate) {
      jwk.d = bytesToB64u(key.privateKey);
    }
  } else if (key.type === "rsa") {
    jwk = { kty: "RSA", n: bytesToB64u(key.rsa.n),
            e: bytesToB64u(key.rsa.e) };
    if (withPrivate) {
      for (var i = 2; i < RSA_MEMBERS.length; i++) {
        jwk[RSA_MEMBERS[i]] = bytesToB64u(key.rsa[RSA_MEMBERS[i]]);
      }
    }
  } else if (key.type === "oct") {
    jwk = { kty: "oct", k: bytesToB64u(key.privateKey) };
  } else if (key.type === "akp" || key.type === "kem") {
    if (withPrivate && key.type === "kem") {
      // draft-ietf-jose-pqc-kem's AKP "priv" for ML-KEM is the 64-byte
      // SEED; this module holds the expanded key, and writing that under
      // "priv" would be a JWK no conforming reader accepts.
      log.debug("Leaving toJwk(). Expanded KEM key.");
      throw new Error("A private " + key.alg + " JWK carries the seed, " +
                      "which this key (held expanded) does not have. " +
                      "Export it as PKCS#8 or raw instead.");
    }
    jwk = withPrivate ? pqc.akpPrivateJwk(key.alg, key.publicKey,
                                           key.privateKey)
                      : pqc.akpPublicJwk(key.alg, key.publicKey);
  } else {
    log.debug("Leaving toJwk(). No JWK form.");
    throw new Error("No JWK form for a " + key.type + " key.");
  }
  if (opts.kid) {
    jwk.kid = opts.kid;
  }
  if (opts.alg && !jwk.alg) {
    jwk.alg = opts.alg;
  }
  if (opts.use) {
    jwk.use = opts.use;
  }
  log.debug("Leaving toJwk().");
  return jwk;
}

function jwkMember(jwk, name) {
  log.debug("Entering jwkMember(). name=" + name);
  if (jwk[name] === undefined || jwk[name] === null || jwk[name] === "") {
    log.debug("Leaving jwkMember(). Absent.");
    return null;
  }
  log.debug("Leaving jwkMember().");
  return b64uToBytes(jwk[name]);
}

function fromJwk(input) {
  log.debug("Entering fromJwk().");
  var jwk = input;
  if (typeof input === "string") {
    // A string that is not a PEM reaches here; say what it is not, rather
    // than leaking JSON.parse's "Unexpected token" (#463).
    try {
      jwk = JSON.parse(input);
    } catch (e) {
      log.debug("Leaving fromJwk(). Neither PEM nor JSON.");
      throw new Error("That text is neither a PEM key (-----BEGIN ...-----) " +
                      "nor a JWK (a JSON object).");
    }
  }
  if (!jwk || !jwk.kty) {
    log.debug("Leaving fromJwk(). No kty.");
    throw new Error("That is not a JWK — it has no \"kty\" member.");
  }
  if (jwk.kty === "EC") {
    var size = ecCurve(jwk.crv).size;
    var x = jwkMember(jwk, "x"), y = jwkMember(jwk, "y");
    var point = x && y ? concatBytes(new Uint8Array([4]),
      concatBytes(padTo(x, size, "x"), padTo(y, size, "y"))) : null;
    log.debug("Leaving fromJwk(). EC.");
    return ecKey(jwk.crv, point, jwkMember(jwk, "d"));
  }
  if (jwk.kty === "OKP") {
    log.debug("Leaving fromJwk(). OKP.");
    return okpKey(jwk.crv, jwkMember(jwk, "x"), jwkMember(jwk, "d"));
  }
  if (jwk.kty === "RSA") {
    var c = {};
    for (var i = 0; i < RSA_MEMBERS.length; i++) {
      c[RSA_MEMBERS[i]] = jwkMember(jwk, RSA_MEMBERS[i]);
    }
    log.debug("Leaving fromJwk(). RSA.");
    return rsaKeyFromComponents(c);
  }
  if (jwk.kty === "oct") {
    log.debug("Leaving fromJwk(). oct.");
    return { type: "oct", publicKey: new Uint8Array(0),
             privateKey: b64uToBytes(jwk.k || "") };
  }
  if (jwk.kty === "AKP") {
    var akp = pqc.akpImport(jwk);
    var named = pqcName(akp.alg);
    if (!named) {
      log.debug("Leaving fromJwk(). Unknown AKP alg.");
      throw new Error("Unknown AKP algorithm: " + akp.alg);
    }
    log.debug("Leaving fromJwk(). AKP.");
    return opaqueKey(named.type, named.alg, akp.pub, akp.priv);
  }
  log.debug("Leaving fromJwk(). Unknown kty.");
  throw new Error("Unsupported JWK kty: " + jwk.kty);
}

// RFC 7638: the REQUIRED members only, in lexicographic order, no
// whitespace, hashed. RFC 9964 section 5 gives AKP's as alg, kty, pub.
var THUMBPRINT_MEMBERS = {
  EC: ["crv", "kty", "x", "y"],
  OKP: ["crv", "kty", "x"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  AKP: ["alg", "kty", "pub"]
};

function jwkThumbprint(keyOrJwk, hash, encoding) {
  log.debug("Entering jwkThumbprint().");
  var jwk = keyOrJwk && keyOrJwk.kty ? keyOrJwk
    : toJwk(keyOrJwk, { publicOnly: keyOrJwk.type !== "oct" });
  var members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) {
    log.debug("Leaving jwkThumbprint(). Unknown kty.");
    throw new Error("No RFC 7638 member set for kty " + jwk.kty + ".");
  }
  var parts = [];
  for (var i = 0; i < members.length; i++) {
    if (typeof jwk[members[i]] !== "string") {
      log.debug("Leaving jwkThumbprint(). Missing member.");
      throw new Error("A " + jwk.kty + " JWK needs \"" + members[i] +
                      "\" for its thumbprint.");
    }
    parts.push(JSON.stringify(members[i]) + ":" +
               JSON.stringify(jwk[members[i]]));
  }
  var digest = hashTools.digest(hashName(hash || "sha256"),
                                bytes.strBytes("{" + parts.join(",") + "}"));
  log.debug("Leaving jwkThumbprint().");
  return encoding === "bytes" ? digest : bytesToB64u(digest);
}

// The provider's lower-case hash names onto hash_tools.js's ids. Shared with
// crypto_provider.js.
var HASH_NAMES = {
  "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
  "sha384": "SHA-384", "sha512": "SHA-512",
  "sha512-224": "SHA-512/224", "sha512-256": "SHA-512/256",
  "sha3-224": "SHA3-224", "sha3-256": "SHA3-256", "sha3-384": "SHA3-384",
  "sha3-512": "SHA3-512"
};

function hashName(name) {
  log.debug("Entering hashName(). name=" + name);
  var id = HASH_NAMES[String(name || "").toLowerCase()];
  if (!id) {
    if (hashTools.algorithm(name)) {
      log.debug("Leaving hashName(). Already a hash_tools id.");
      return name;
    }
    log.debug("Leaving hashName(). Unknown.");
    throw new Error("Unknown hash: " + name);
  }
  log.debug("Leaving hashName().");
  return id;
}

// ===========================================================================
// COSE_Key (RFC 9052 section 7, RFC 9053 section 7, RFC 8230 for RSA,
// RFC 9964 section 4 for AKP)
// ===========================================================================
var COSE_KTY = { OKP: 1, EC2: 2, RSA: 3, Symmetric: 4, AKP: 7 };
var COSE_RSA_LABELS = { n: -1, e: -2, d: -3, p: -4, q: -5, dp: -6, dq: -7,
                        qi: -8 };

function toCose(key, options) {
  log.debug("Entering toCose(). type=" + key.type);
  var opts = options || {};
  var withPrivate = !!key.privateKey && !opts.publicOnly;
  var m = new Map();
  if (key.type === "ec") {
    var c = ecCurve(key.curve);
    m.set(1, COSE_KTY.EC2);
    m.set(-1, c.cose);
    m.set(-2, key.publicKey.slice(1, 1 + c.size));
    m.set(-3, key.publicKey.slice(1 + c.size));
    if (withPrivate) {
      m.set(-4, key.privateKey.slice());
    }
  } else if (key.type === "okp") {
    m.set(1, COSE_KTY.OKP);
    m.set(-1, okpCurve(key.curve).cose);
    m.set(-2, key.publicKey.slice());
    if (withPrivate) {
      m.set(-4, key.privateKey.slice());
    }
  } else if (key.type === "rsa") {
    m.set(1, COSE_KTY.RSA);
    var names = withPrivate ? RSA_MEMBERS : ["n", "e"];
    for (var i = 0; i < names.length; i++) {
      m.set(COSE_RSA_LABELS[names[i]], key.rsa[names[i]].slice());
    }
  } else if (key.type === "oct") {
    m.set(1, COSE_KTY.Symmetric);
    m.set(-1, key.privateKey.slice());
  } else if (key.type === "akp") {
    var alg = opts.alg !== undefined ? opts.alg : AKP_COSE_ALGS[key.alg];
    if (alg === undefined) {
      log.debug("Leaving toCose(). AKP without a COSE alg.");
      throw new Error("An AKP COSE_Key must carry its algorithm (label 3), " +
                      "and " + key.alg + " has no registered COSE value. " +
                      "Pass options.alg.");
    }
    m.set(1, COSE_KTY.AKP);
    m.set(3, alg);
    m.set(-1, key.publicKey.slice());
    if (withPrivate) {
      m.set(-2, key.privateKey.slice());
    }
  } else {
    log.debug("Leaving toCose(). No COSE form.");
    throw new Error("No COSE_Key form for a " + key.type + " key.");
  }
  if (opts.kid !== undefined) {
    m.set(2, typeof opts.kid === "string" ? bytes.strBytes(opts.kid)
                                          : asBytes(opts.kid));
  }
  if (opts.alg !== undefined && !m.has(3)) {
    m.set(3, opts.alg);
  }
  log.debug("Leaving toCose().");
  return m;
}

function coseGet(map, label) {
  log.debug("Entering coseGet(). label=" + label);
  var v = map instanceof Map ? map.get(label) : map[String(label)];
  log.debug("Leaving coseGet().");
  return v === undefined ? null : v;
}

function byValue(table, field, value) {
  log.debug("Entering byValue().");
  var names = Object.keys(table);
  for (var i = 0; i < names.length; i++) {
    if (table[names[i]][field] === value) {
      log.debug("Leaving byValue(). Found.");
      return names[i];
    }
  }
  log.debug("Leaving byValue(). Not found.");
  return null;
}

function fromCose(map) {
  log.debug("Entering fromCose().");
  var kty = coseGet(map, 1);
  if (kty === COSE_KTY.EC2) {
    var curve = byValue(EC_CURVES, "cose", coseGet(map, -1));
    if (!curve) {
      log.debug("Leaving fromCose(). Unknown EC2 curve.");
      throw new Error("Unsupported COSE EC2 curve " + coseGet(map, -1) + ".");
    }
    var size = EC_CURVES[curve].size;
    var x = coseGet(map, -2), y = coseGet(map, -3);
    var point = null;
    if (x && y && typeof y !== "boolean") {
      point = concatBytes(new Uint8Array([4]),
        concatBytes(padTo(x, size, "x"), padTo(y, size, "y")));
    } else if (x && typeof y === "boolean") {
      // RFC 9053 section 7.1.1: y may be the SIGN BIT of a compressed point.
      point = concatBytes(new Uint8Array([y ? 3 : 2]), padTo(x, size, "x"));
    }
    log.debug("Leaving fromCose(). EC2.");
    return ecKey(curve, point, coseGet(map, -4));
  }
  if (kty === COSE_KTY.OKP) {
    var okp = byValue(OKP_CURVES, "cose", coseGet(map, -1));
    if (!okp) {
      log.debug("Leaving fromCose(). Unknown OKP curve.");
      throw new Error("Unsupported COSE OKP curve " + coseGet(map, -1) + ".");
    }
    log.debug("Leaving fromCose(). OKP.");
    return okpKey(okp, coseGet(map, -2), coseGet(map, -4));
  }
  if (kty === COSE_KTY.RSA) {
    var c = {};
    for (var i = 0; i < RSA_MEMBERS.length; i++) {
      c[RSA_MEMBERS[i]] = coseGet(map, COSE_RSA_LABELS[RSA_MEMBERS[i]]);
    }
    log.debug("Leaving fromCose(). RSA.");
    return rsaKeyFromComponents(c);
  }
  if (kty === COSE_KTY.Symmetric) {
    log.debug("Leaving fromCose(). Symmetric.");
    return { type: "oct", publicKey: new Uint8Array(0),
             privateKey: asBytes(coseGet(map, -1)) };
  }
  if (kty === COSE_KTY.AKP) {
    var alg = byValue(AKP_ALG_ROWS, "cose", coseGet(map, 3));
    if (!alg) {
      log.debug("Leaving fromCose(). Unknown AKP alg.");
      throw new Error("Unsupported AKP COSE alg " + coseGet(map, 3) + ".");
    }
    var priv = coseGet(map, -2);
    var pub = coseGet(map, -1);
    log.debug("Leaving fromCose(). AKP.");
    return opaqueKey("akp", alg, pub, priv);
  }
  log.debug("Leaving fromCose(). Unknown kty.");
  throw new Error("Unsupported COSE kty " + kty + ".");
}

var AKP_ALG_ROWS = {};
(function buildAkpAlgRows() {
  var names = Object.keys(AKP_COSE_ALGS);
  for (var i = 0; i < names.length; i++) {
    AKP_ALG_ROWS[names[i]] = { cose: AKP_COSE_ALGS[names[i]] };
  }
})();

// ===========================================================================
// RAW
// ===========================================================================
// opts.type is a spec as generateKeyPair() takes it ("ec-p256", "x448",
// "ML-DSA-44", ...) or "rsa"; opts.private says which half the bytes are.
// For RSA, raw means PKCS#1 DER.
function fromRaw(input, opts) {
  log.debug("Entering fromRaw(). type=" + (opts && opts.type));
  var o = opts || {};
  var raw = asBytes(input);
  var name = String(o.type || "").toLowerCase();
  var spec = KEY_SPECS[name];
  if (name === "rsa" || (spec && spec.type === "rsa")) {
    log.debug("Leaving fromRaw(). RSA.");
    return rsaFromPkcs1(raw, !!o.private);
  }
  if (name === "oct") {
    log.debug("Leaving fromRaw(). oct.");
    return { type: "oct", publicKey: new Uint8Array(0), privateKey: raw };
  }
  if (spec && spec.type === "ec") {
    log.debug("Leaving fromRaw(). EC.");
    return o.private ? ecKey(spec.curve, null, raw)
                     : ecKey(spec.curve, raw, null);
  }
  if (spec && spec.type === "okp") {
    log.debug("Leaving fromRaw(). OKP.");
    return o.private ? okpKey(spec.curve, null, raw)
                     : okpKey(spec.curve, raw, null);
  }
  var pq = pqcName(o.type);
  if (pq) {
    if (o.private && !o.publicKey && pq.type === "akp" &&
        pqc.signatureAlg(pq.alg).family === "ML-DSA") {
      var kp = pqc.signatureAlg(pq.alg).prim.keygen(raw);
      log.debug("Leaving fromRaw(). ML-DSA from seed.");
      return opaqueKey("akp", pq.alg, kp.publicKey, raw);
    }
    if (o.private && !o.publicKey) {
      log.debug("Leaving fromRaw(). Private without public.");
      throw new Error("A raw " + pq.alg + " private key needs " +
                      "options.publicKey beside it.");
    }
    log.debug("Leaving fromRaw(). Opaque.");
    return o.private ? opaqueKey(pq.type, pq.alg, o.publicKey, raw)
                     : opaqueKey(pq.type, pq.alg, raw, null);
  }
  log.debug("Leaving fromRaw(). Unknown type.");
  throw new Error("importKey(raw) needs options.type, e.g. \"ec-p256\"; " +
                  "got " + o.type + ".");
}

// ===========================================================================
// importKey / exportKey
// ===========================================================================
var FORMATS = ["jwk", "spki-der", "pkcs8-der", "spki-pem", "pkcs8-pem", "raw",
               "cose"];

function isCoseShape(input) {
  log.debug("Entering isCoseShape().");
  var yes = input instanceof Map ||
    (input !== null && typeof input === "object" &&
     !(input instanceof Uint8Array) && input["1"] !== undefined &&
     input.kty === undefined);
  log.debug("Leaving isCoseShape().");
  return yes;
}

function fromPem(text) {
  log.debug("Entering fromPem().");
  var label = bytes.pemLabel(text);
  var der = bytes.pemToDer(text);
  if (label === "PUBLIC KEY") {
    log.debug("Leaving fromPem(). SPKI.");
    return fromSpki(der);
  }
  if (label === "PRIVATE KEY") {
    log.debug("Leaving fromPem(). PKCS#8.");
    return fromPkcs8(der);
  }
  if (label === "RSA PRIVATE KEY") {
    log.debug("Leaving fromPem(). PKCS#1 private.");
    return rsaFromPkcs1(der, true);
  }
  if (label === "RSA PUBLIC KEY") {
    log.debug("Leaving fromPem(). PKCS#1 public.");
    return rsaFromPkcs1(der, false);
  }
  if (label === "EC PRIVATE KEY") {
    log.debug("Leaving fromPem(). SEC1.");
    return ecFromSec1(null, der);
  }
  if (label === "CERTIFICATE") {
    log.debug("Leaving fromPem(). Certificate.");
    return fromSpki(spkiFromCertificate(der));
  }
  log.debug("Leaving fromPem(). Unknown label.");
  throw new Error("Unsupported PEM block: " + label + ".");
}

// input: a JWK (object or JSON text), a PEM (any of PUBLIC KEY, PRIVATE KEY,
// RSA PRIVATE/PUBLIC KEY, EC PRIVATE KEY, CERTIFICATE), a COSE_Key (Map or
// object with integer-string keys), or bytes with options.format naming
// which of "spki-der", "pkcs8-der", "raw" (with options.type/private),
// "certificate-der" they are. options.format may also force "jwk"/"cose".
function importKey(input, options) {
  log.debug("Entering importKey(). format=" + (options && options.format));
  var opts = options || {};
  var format = opts.format;
  if (!format) {
    if (typeof input === "string" && /-----BEGIN /.test(input)) {
      format = "pem";
    } else if (typeof input === "string" ||
               (input && input.kty !== undefined)) {
      format = "jwk";
    } else if (isCoseShape(input)) {
      format = "cose";
    }
  }
  var key;
  if (format === "pem" || format === "spki-pem" || format === "pkcs8-pem") {
    key = fromPem(input);
  } else if (format === "jwk") {
    key = fromJwk(input);
  } else if (format === "cose") {
    key = fromCose(input);
  } else if (format === "spki-der") {
    key = fromSpki(asBytes(input));
  } else if (format === "pkcs8-der") {
    key = fromPkcs8(asBytes(input));
  } else if (format === "certificate-der") {
    key = fromSpki(spkiFromCertificate(asBytes(input)));
  } else if (format === "raw") {
    key = fromRaw(input, opts);
  } else {
    log.debug("Leaving importKey(). No format.");
    throw new Error("importKey: cannot tell what this input is; pass " +
                    "options.format (one of " + FORMATS.join(", ") + ").");
  }
  log.debug("Leaving importKey(). type=" + key.type);
  return key;
}

// format: one of FORMATS. options: { publicOnly, kid, alg, use } for jwk and
// cose (cose also { alg } as a COSE integer), { private } for raw.
function exportKey(key, format, options) {
  log.debug("Entering exportKey(). format=" + format);
  var opts = options || {};
  var out;
  if (format === "jwk") {
    out = toJwk(key, opts);
  } else if (format === "cose") {
    out = toCose(key, opts);
  } else if (format === "spki-der") {
    out = spkiDer(key);
  } else if (format === "pkcs8-der") {
    out = pkcs8Der(key);
  } else if (format === "spki-pem") {
    out = bytes.derToPem(spkiDer(key), "PUBLIC KEY");
  } else if (format === "pkcs8-pem") {
    out = bytes.derToPem(pkcs8Der(key), "PRIVATE KEY");
  } else if (format === "raw") {
    if (opts.private && !key.privateKey) {
      log.debug("Leaving exportKey(). No private half.");
      throw new Error("This key has no private half to export.");
    }
    out = (opts.private ? key.privateKey : key.publicKey).slice();
  } else {
    log.debug("Leaving exportKey(). Unknown format.");
    throw new Error("Unknown key format: " + format + " (one of " +
                    FORMATS.join(", ") + ").");
  }
  log.debug("Leaving exportKey().");
  return out;
}

module.exports = {
  EC_CURVES: EC_CURVES,
  OKP_CURVES: OKP_CURVES,
  KEY_SPECS: KEY_SPECS,
  PQ_OIDS: PQ_OIDS,
  HBS_ALGS: HBS_ALGS,
  FORMATS: FORMATS,
  HASH_NAMES: HASH_NAMES,
  hashName: hashName,
  generateKeyPair: generateKeyPair,
  importKey: importKey,
  exportKey: exportKey,
  publicKeyOf: publicKeyOf,
  jwkThumbprint: jwkThumbprint,
  pqcName: pqcName,
  toForgeRsa: toForgeRsa,
  ecCurve: ecCurve,
  okpCurve: okpCurve,
  // DER, for crypto_provider.js's ECDSA signature conversion
  derTlv: derTlv,
  derSequence: derSequence,
  derUnsignedInteger: derUnsignedInteger,
  derRead: derRead,
  derChildren: derChildren,
  derExpect: derExpect,
  padTo: padTo,
  stripLeadingZeros: stripLeadingZeros
};
