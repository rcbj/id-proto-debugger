// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope.js
//
// ---------------------------------------------------------------------------
// Gordian Envelope (draft-mcnally-envelope-12) over dCBOR
// (draft-mcnally-deterministic-cbor-18), as a verifiable-credential format
// (#480): decode, digest, verify, elide for a presentation, sign, and the
// ur:envelope text form. Blockchain Commons' Rust crates (bc-envelope
// 0.43.0, dcbor 0.25.2, bc-components 0.31.1, known-values 0.15.5) are the
// reference: tests/gordian_envelope_engine.js reproduces their test vectors,
// signatures included, byte for byte.
//
// AN ENVELOPE IS A MERKLE TREE OF DIGESTS, which is the whole point of it as
// a credential: any element can be ELIDED — replaced by its digest — and
// every digest above it, and therefore the issuer's signature over the root,
// stays the same. A holder presents a credential by eliding the claims a
// verifier should not see; nothing is re-signed and nobody else's key is
// needed. Salt (a 'salt' assertion) is what stops an elided "firstName":
// "John" being guessed from its digest.
//
// Ten things that cost a day each if missed are listed at the top of the
// implementation notes in docs/gordian-envelope.md; the ones that change
// bytes:
//   * a leaf's digest is SHA-256 of its dCBOR WITHOUT tag 201;
//   * a known value is a bare uint on the wire and hashed as 40000(n);
//   * tag 200 marks the top level and a WRAPPED envelope, nothing else, and
//     a UR body is the untagged form;
//   * a node's assertions are ordered by digest;
//   * a signature covers the 32 raw bytes of the subject's digest:
//     BIP-340 Schnorr and Ed25519 sign them as they are, ECDSA signs
//     SHA-256(SHA-256(them));
//   * dcbor 0.25.2 writes and reads 65-bit negative integers, which the
//     dCBOR draft forbids. The Rust encoder is what exists, so this reads
//     them.
//
// Key material from a seed (bc-components' PrivateKeyBase) is HKDF-SHA-256
// with the salt "signing". All cryptography is pure JavaScript (@noble).
//
// NO DOM.
// ---------------------------------------------------------------------------

var nobleSecp = require("@noble/curves/secp256k1");
var nobleEd = require("@noble/curves/ed25519");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha2 = require("@noble/hashes/sha512");
var nobleSha384 = nobleSha2.sha384;
var nobleSha512 = nobleSha2.sha512;
var nobleP256 = require("@noble/curves/p256");
var nobleP384 = require("@noble/curves/p384");
var nobleHkdf = require("@noble/hashes/hkdf").hkdf;
var nobleMldsa = require("@noble/post-quantum/ml-dsa.js");
var cbytes = require("./crypto_bytes");
var bcur = require("./bc_ur");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gordian_envelope",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var SPEC = "draft-mcnally-envelope-12 and draft-mcnally-deterministic-cbor-18";

var TAG = {
  DATE: 1, URI: 32, UUID: 37, ENVELOPE: 200, LEAF: 201, LEGACY_LEAF: 24,
  KNOWN_VALUE: 40000, DIGEST: 40001, ENCRYPTED: 40002, COMPRESSED: 40003,
  ARID: 40012, NONCE: 40014, PRIVATE_KEY_BASE: 40016, PUBLIC_KEYS: 40017,
  SALT: 40018, SIGNATURE: 40020, SIGNING_PRIVATE_KEY: 40021,
  SIGNING_PUBLIC_KEY: 40022, XID: 40024, X25519_PRIVATE_KEY: 40010,
  X25519_PUBLIC_KEY: 40011, PRIVATE_KEYS: 40013, SEALED_MESSAGE: 40019,
  SYMMETRIC_KEY: 40023, ENCRYPTED_KEY: 40027, MLKEM_PRIVATE_KEY: 40100,
  MLKEM_PUBLIC_KEY: 40101, MLKEM_CIPHERTEXT: 40102, MLDSA_PRIVATE_KEY: 40103,
  MLDSA_PUBLIC_KEY: 40104, MLDSA_SIGNATURE: 40105, SEED: 40300,
  SSKR_SHARE: 40309, SSKR_SHARE_V1: 309, SSH_PRIVATE_KEY: 40800,
  SSH_PUBLIC_KEY: 40801, SSH_SIGNATURE: 40802
};
var TAG_NAMES = {
  1: "Date", 32: "URI", 37: "UUID", 40000: "known-value", 40001: "Digest",
  40002: "ENCRYPTED", 40003: "COMPRESSED", 40012: "ARID", 40014: "Nonce",
  40016: "PrivateKeyBase", 40017: "PublicKeys", 40018: "Salt",
  40020: "Signature", 40021: "SigningPrivateKey", 40022: "SigningPublicKey",
  40024: "XID", 40010: "X25519PrivateKey", 40011: "X25519PublicKey",
  40013: "PrivateKeys", 40019: "SealedMessage", 40023: "SymmetricKey",
  40027: "EncryptedKey", 40100: "MLKEMPrivateKey", 40101: "MLKEMPublicKey",
  40102: "MLKEMCiphertext", 40103: "MLDSAPrivateKey",
  40104: "MLDSAPublicKey", 40105: "MLDSASignature", 40300: "Seed",
  40309: "SSKRShare", 309: "SSKRShare", 40800: "SSHPrivateKey",
  40801: "SSHPublicKey", 40802: "SSHSignature"
};

// known-values 0.15.5's registry. 25 (value) is defined there and left out
// of its formatter's store; it is named here.
var KNOWN_VALUES = {
  0: "", 1: "isA", 2: "id", 3: "signed", 4: "note", 5: "hasRecipient",
  6: "sskrShare", 7: "controller", 8: "key", 9: "dereferenceVia",
  10: "entity", 11: "name", 12: "language", 13: "issuer", 14: "holder",
  15: "salt", 16: "date", 17: "Unknown", 18: "version", 19: "hasSecret",
  20: "edits", 21: "validFrom", 22: "validUntil", 23: "position",
  24: "nickname", 25: "value", 26: "attestation", 27: "verifiableAt",
  50: "attachment", 51: "vendor", 52: "conformsTo", 60: "allow", 61: "deny",
  62: "endpoint", 63: "delegate", 64: "provenance", 65: "privateKey",
  66: "service", 67: "capability", 68: "provenanceGenerator", 70: "All",
  71: "Authorize", 72: "Sign", 73: "Encrypt", 74: "Elide", 75: "Issue",
  76: "Access", 80: "Delegate", 81: "Verify", 82: "Update", 83: "Transfer",
  84: "Elect", 85: "Burn", 86: "Revoke", 100: "body", 101: "result",
  102: "error", 103: "OK", 104: "Processing", 105: "sender",
  106: "senderContinuation", 107: "recipientContinuation", 108: "content",
  200: "Seed", 201: "PrivateKey", 202: "PublicKey", 203: "MasterKey",
  300: "asset", 301: "Bitcoin", 302: "Ethereum", 303: "Tezos",
  400: "network", 401: "MainNet", 402: "TestNet", 500: "BIP32Key",
  501: "chainCode", 502: "DerivationPath", 503: "parentPath",
  504: "childrenPath", 505: "parentFingerprint", 506: "PSBT",
  507: "OutputDescriptor", 508: "outputDescriptor", 600: "Graph",
  601: "SourceTargetGraph", 602: "ParentChildGraph", 603: "Digraph",
  604: "AcyclicGraph", 605: "Multigraph", 606: "Pseudograph",
  607: "GraphFragment", 608: "DAG", 609: "Tree", 610: "Forest",
  611: "CompoundGraph", 612: "Hypergraph", 613: "Dihypergraph", 700: "node",
  701: "edge", 702: "source", 703: "target", 704: "parent", 705: "child",
  706: "Self"
};
var KV = {};
Object.keys(KNOWN_VALUES).forEach(function (n) {
  KV[KNOWN_VALUES[n]] = Number(n);
});

// ---------------------------------------------------------------------------
// dCBOR. Values: number or BigInt, string, Uint8Array, Array, Map, boolean,
// null, Tagged. Recursive and run per item, so the encoder and decoder carry
// no Entering/Leaving pair — the hot-path exception the code style allows,
// stated as it requires; encode() and decode() log.
// ---------------------------------------------------------------------------

function Tagged(tag, value) {
  this.tag = tag;
  this.value = value;
}

var TWO64 = BigInt("18446744073709551616");

function headBig(major, n) {
  var out = [];
  if (n < BigInt(24)) {
    out.push((major << 5) | Number(n));
  } else if (n < BigInt(0x100)) {
    out.push((major << 5) | 24, Number(n));
  } else if (n < BigInt(0x10000)) {
    out.push((major << 5) | 25, Number(n >> BigInt(8)),
             Number(n & BigInt(255)));
  } else if (n < BigInt(0x100000000)) {
    out.push((major << 5) | 26);
    for (var i = 3; i >= 0; i--) {
      out.push(Number((n >> BigInt(8 * i)) & BigInt(255)));
    }
  } else {
    out.push((major << 5) | 27);
    for (var j = 7; j >= 0; j--) {
      out.push(Number((n >> BigInt(8 * j)) & BigInt(255)));
    }
  }
  return out;
}

function head(major, n) {
  return headBig(major, BigInt(n));
}

// Exactly representable as IEEE 754 binary16?
function f16Bits(x) {
  if (!isFinite(x)) return x > 0 ? 0x7c00 : 0xfc00;
  if (x === 0) return Object.is(x, -0) ? 0x8000 : 0;
  var sign = x < 0 ? 0x8000 : 0;
  var a = Math.abs(x);
  if (a > 65504) return null;
  if (a < Math.pow(2, -14)) {
    var sub = a / Math.pow(2, -24);
    return Number.isInteger(sub) ? sign | sub : null;
  }
  var e = Math.floor(Math.log2(a));
  if (Math.pow(2, e) > a) e -= 1;
  if (Math.pow(2, e + 1) <= a) e += 1;
  var m = a / Math.pow(2, e) - 1;
  var frac = m * 1024;
  if (!Number.isInteger(frac)) return null;
  return sign | ((e + 15) << 10) | frac;
}

function encodeNumber(x) {
  if (typeof x === "bigint") {
    if (x >= BigInt(0) && x < TWO64) return headBig(0, x);
    if (x < BigInt(0) && x >= -TWO64) return headBig(1, BigInt(-1) - x);
    throw new Error("an integer outside [-2^64, 2^64-1] has no dCBOR form.");
  }
  if (Number.isNaN(x)) return [0xf9, 0x7e, 0x00];
  if (Number.isInteger(x)) {
    if (x >= 0 && x < 18446744073709551616) return headBig(0, BigInt(x));
    if (x < 0 && x >= -18446744073709551616) {
      return headBig(1, BigInt(-1) - BigInt(x));
    }
  }
  var h = f16Bits(x);
  if (h !== null) return [0xf9, h >> 8, h & 0xff];
  if (Math.fround(x) === x) {
    var f = new DataView(new ArrayBuffer(4));
    f.setFloat32(0, x);
    return [0xfa].concat(Array.from(new Uint8Array(f.buffer)));
  }
  var d = new DataView(new ArrayBuffer(8));
  d.setFloat64(0, x);
  return [0xfb].concat(Array.from(new Uint8Array(d.buffer)));
}

function compareBytes(a, b) {
  var n = Math.min(a.length, b.length);
  for (var i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function encodeParts(v) {
  if (v === null) return [0xf6];
  if (v === true) return [0xf5];
  if (v === false) return [0xf4];
  if (v === undefined) throw new Error("dCBOR has no undefined.");
  if (typeof v === "number" || typeof v === "bigint") return encodeNumber(v);
  if (typeof v === "string") {
    var s = new TextEncoder().encode(v.normalize("NFC"));
    return head(3, s.length).concat(Array.from(s));
  }
  if (v instanceof Uint8Array) return head(2, v.length).concat(Array.from(v));
  if (v instanceof Tagged) return head(6, v.tag).concat(encodeParts(v.value));
  if (Array.isArray(v)) {
    var out = head(4, v.length);
    v.forEach(function (x) {
      out = out.concat(encodeParts(x));
    });
    return out;
  }
  if (v instanceof Map) {
    var entries = Array.from(v.entries()).map(function (e) {
      return { k: encodeParts(e[0]), v: encodeParts(e[1]) };
    }).sort(function (a, b) {
      return compareBytes(a.k, b.k);
    });
    for (var i = 1; i < entries.length; i++) {
      if (compareBytes(entries[i - 1].k, entries[i].k) === 0) {
        throw new Error("a dCBOR map with a duplicate key.");
      }
    }
    var m = head(5, entries.length);
    entries.forEach(function (e) {
      m = m.concat(e.k, e.v);
    });
    return m;
  }
  throw new Error("no dCBOR form for " + Object.prototype.toString.call(v));
}

function encode(v) {
  log.debug("Entering encode().");
  log.debug("Leaving encode().");
  return new Uint8Array(encodeParts(v));
}

function DcborReader(bytes) {
  this.b = bytes;
  this.i = 0;
}

DcborReader.prototype.take = function (n) {
  if (this.i + n > this.b.length) {
    throw new Error("dCBOR: the input ends inside an item.");
  }
  var out = this.b.subarray(this.i, this.i + n);
  this.i += n;
  return out;
};

DcborReader.prototype.arg = function (ai, major) {
  if (ai < 24) return { value: BigInt(ai) };
  if (ai > 27) {
    throw new Error("dCBOR: additional information " + ai + " (indefinite " +
                    "lengths and reserved values are not dCBOR).");
  }
  var n = [1, 2, 4, 8][ai - 24];
  var raw = this.take(n);
  var v = BigInt(0);
  for (var i = 0; i < raw.length; i++) v = (v << BigInt(8)) | BigInt(raw[i]);
  if (major !== 7) {
    var floor = [BigInt(24), BigInt(0x100), BigInt(0x10000),
                 BigInt(0x100000000)][ai - 24];
    if (v < floor) {
      throw new Error("dCBOR: a non-shortest argument (" + v + " in " + n +
                      " bytes).");
    }
  }
  return { value: v, raw: raw };
};

function asNumber(big) {
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
}

function readFloat(ai, raw) {
  var dv = new DataView(raw.buffer, raw.byteOffset, raw.length);
  var x;
  if (ai === 25) {
    var bits = dv.getUint16(0);
    var e = (bits >> 10) & 0x1f;
    var f = bits & 0x3ff;
    var sign = bits & 0x8000 ? -1 : 1;
    x = e === 0 ? sign * f * Math.pow(2, -24) :
        e === 31 ? (f ? NaN : sign * Infinity) :
        sign * (1 + f / 1024) * Math.pow(2, e - 15);
    if (Number.isNaN(x) && bits !== 0x7e00) {
      throw new Error("dCBOR: a NaN other than f97e00.");
    }
    if (Number.isInteger(x)) {
      throw new Error("dCBOR: an integral half-float (numeric reduction " +
                      "writes it as an integer).");
    }
    return x;
  }
  if (ai === 26) {
    x = dv.getFloat32(0);
    var sat = x >= 2147483647 ? 2147483647 : x <= -2147483648 ?
        -2147483648 : Math.trunc(x);
    if (Number.isNaN(x) || f16Bits(x) !== null || Math.fround(sat) === x) {
      throw new Error("dCBOR: a single-precision float with a shorter form.");
    }
    return x;
  }
  x = dv.getFloat64(0);
  if (Number.isNaN(x) || Math.fround(x) === x ||
      (Number.isInteger(x) && x > -9223372036854775808 &&
       x < 9223372036854775808)) {
    throw new Error("dCBOR: a double-precision float with a shorter form.");
  }
  return x;
}

function readItem(r, depth) {
  if (depth > 256) throw new Error("dCBOR: nested deeper than 256.");
  var ib = r.take(1)[0];
  var major = ib >> 5;
  var ai = ib & 0x1f;
  if (major === 7) {
    if (ai === 20) return false;
    if (ai === 21) return true;
    if (ai === 22) return null;
    if (ai >= 25 && ai <= 27) {
      return readFloat(ai, r.take([0, 2, 4, 8][ai - 24]));
    }
    throw new Error("dCBOR: simple value " + ai + " (only false, true, " +
                    "null and floats are dCBOR).");
  }
  var n = r.arg(ai, major).value;
  var i;
  switch (major) {
    case 0:
      return asNumber(n);
    case 1: {
      var neg = BigInt(-1) - n;
      return neg >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(neg) : neg;
    }
    case 2:
      return new Uint8Array(r.take(Number(n)));
    case 3: {
      var s = new TextDecoder("utf-8", { fatal: true })
        .decode(r.take(Number(n)));
      if (s !== s.normalize("NFC")) {
        throw new Error("dCBOR: text that is not in Unicode NFC.");
      }
      return s;
    }
    case 4: {
      var arr = [];
      for (i = 0; i < Number(n); i++) arr.push(readItem(r, depth + 1));
      return arr;
    }
    case 5: {
      var map = new Map();
      var prev = null;
      for (i = 0; i < Number(n); i++) {
        var start = r.i;
        var key = readItem(r, depth + 1);
        var keyBytes = r.b.subarray(start, r.i);
        if (prev) {
          var c = compareBytes(prev, keyBytes);
          if (c === 0) throw new Error("dCBOR: a duplicate map key.");
          if (c > 0) throw new Error("dCBOR: map keys out of order.");
        }
        prev = keyBytes;
        map.set(key, readItem(r, depth + 1));
      }
      return map;
    }
    default:
      return new Tagged(asNumber(n), readItem(r, depth + 1));
  }
}

function decode(bytes) {
  log.debug("Entering decode(). " + (bytes && bytes.length));
  var r = new DcborReader(cbytes.asBytes(bytes));
  var v = readItem(r, 0);
  if (r.i !== r.b.length) {
    log.debug("Leaving decode(). Trailing data.");
    throw new Error("dCBOR: " + (r.b.length - r.i) + " byte(s) after the " +
                    "item.");
  }
  log.debug("Leaving decode().");
  return v;
}

// ---------------------------------------------------------------------------
// Envelopes.
// ---------------------------------------------------------------------------

function sha256(b) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nobleSha256(b);
}

function Envelope(kind, fields, digest) {
  log.debug("Entering Envelope(). " + kind);
  this.kind = kind;
  Object.assign(this, fields);
  this.digest = digest;
  log.debug("Leaving Envelope().");
}

function isEnvelope(x) {
  log.debug("Entering isEnvelope().");
  log.debug("Leaving isEnvelope().");
  return x instanceof Envelope;
}

function leaf(value) {
  log.debug("Entering leaf().");
  log.debug("Leaving leaf().");
  return new Envelope("leaf", { value: value }, sha256(encode(value)));
}

function knownValue(n) {
  log.debug("Entering knownValue(). " + n);
  var v = typeof n === "string" ? KV[n] : n;
  if (v === undefined) {
    log.debug("Leaving knownValue(). Unknown name.");
    throw new Error("no known value is named " + JSON.stringify(n) + ".");
  }
  log.debug("Leaving knownValue().");
  return new Envelope("knownValue", { value: v },
                      sha256(encode(new Tagged(TAG.KNOWN_VALUE, v))));
}

function elided(digest) {
  log.debug("Entering elided().");
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    log.debug("Leaving elided(). Not a digest.");
    throw new Error("an elided element is a 32-byte digest.");
  }
  log.debug("Leaving elided().");
  return new Envelope("elided", {}, digest);
}

// Anything that is not already an envelope becomes a leaf.
function from(x) {
  log.debug("Entering from().");
  log.debug("Leaving from().");
  return isEnvelope(x) ? x : leaf(x);
}

function assertion(predicate, object) {
  log.debug("Entering assertion().");
  var p = from(predicate);
  var o = from(object);
  log.debug("Leaving assertion().");
  return new Envelope("assertion", { predicate: p, object: o },
                      sha256(cbytes.concatBytes(p.digest, o.digest)));
}

function wrap(e) {
  log.debug("Entering wrap().");
  var inner = from(e);
  log.debug("Leaving wrap().");
  return new Envelope("wrapped", { envelope: inner }, sha256(inner.digest));
}

function sortAssertions(list) {
  log.debug("Entering sortAssertions().");
  log.debug("Leaving sortAssertions().");
  return list.slice().sort(function (a, b) {
    return compareBytes(a.digest, b.digest);
  });
}

function node(subject, assertions) {
  log.debug("Entering node().");
  var sorted = sortAssertions(assertions);
  if (!sorted.length) {
    log.debug("Leaving node(). No assertions.");
    return subject;
  }
  log.debug("Leaving node().");
  return new Envelope("node", { subject: subject, assertions: sorted },
    sha256(cbytes.concatBytes.apply(null, [subject.digest].concat(
      sorted.map(function (a) {
        return a.digest;
      })))));
}

function subjectOf(e) {
  log.debug("Entering subjectOf().");
  log.debug("Leaving subjectOf().");
  return e.kind === "node" ? e.subject : e;
}

function assertionsOf(e) {
  log.debug("Entering assertionsOf().");
  log.debug("Leaving assertionsOf().");
  return e.kind === "node" ? e.assertions : [];
}

// Adding an assertion whose digest is already there changes nothing.
function addAssertion(e, predicate, object) {
  log.debug("Entering addAssertion().");
  var a = object === undefined && isEnvelope(predicate) &&
      (predicate.kind === "assertion" || predicate.kind === "elided" ||
       (predicate.kind === "node" && predicate.subject.kind === "assertion")) ?
      predicate : assertion(predicate, object);
  var existing = assertionsOf(e);
  var hex = cbytes.bytesToHex(a.digest);
  if (existing.some(function (x) {
    return cbytes.bytesToHex(x.digest) === hex;
  })) {
    log.debug("Leaving addAssertion(). Already there.");
    return e;
  }
  log.debug("Leaving addAssertion().");
  return node(subjectOf(e), existing.concat([a]));
}

// An assertion that carries its own salt: { p: o } [ 'salt': Salt ].
function saltedAssertion(predicate, object, salt) {
  log.debug("Entering saltedAssertion().");
  var a = assertion(predicate, object);
  log.debug("Leaving saltedAssertion().");
  return node(a, [assertion(knownValue("salt"), leaf(new Tagged(TAG.SALT,
    cbytes.asBytes(salt))))]);
}

// The untagged CBOR an envelope is written as when it is a child, and the
// body of a UR.
function toCbor(e) {
  log.debug("Entering toCbor(). " + e.kind);
  var out;
  switch (e.kind) {
    case "leaf":
      out = new Tagged(TAG.LEAF, e.value);
      break;
    case "knownValue":
      out = e.value;
      break;
    case "elided":
      out = e.digest;
      break;
    case "wrapped":
      out = new Tagged(TAG.ENVELOPE, toCbor(e.envelope));
      break;
    case "assertion":
      out = new Map([[toCbor(e.predicate), toCbor(e.object)]]);
      break;
    case "node":
      out = [toCbor(e.subject)].concat(e.assertions.map(toCbor));
      break;
    default:
      out = e.cbor;
  }
  log.debug("Leaving toCbor().");
  return out;
}

function isAssertionLike(e) {
  log.debug("Entering isAssertionLike().");
  log.debug("Leaving isAssertionLike().");
  return e.kind === "assertion" || e.kind === "elided" ||
    e.kind === "encrypted" || e.kind === "compressed" ||
    (e.kind === "node" && e.subject.kind === "assertion");
}

// From untagged envelope content. Unsorted or duplicate assertions are
// refused: the draft says MUST NOT, and the Rust encoder never writes them
// (its decoder re-sorts instead).
function fromCbor(v) {
  log.debug("Entering fromCbor().");
  var out;
  if (v instanceof Tagged) {
    if (v.tag === TAG.LEAF || v.tag === TAG.LEGACY_LEAF) {
      out = leaf(v.value);
    } else if (v.tag === TAG.ENVELOPE) {
      out = wrap(fromCbor(v.value));
    } else if (v.tag === TAG.ENCRYPTED || v.tag === TAG.COMPRESSED) {
      // The digest is element 4: 40001(digest) itself, or (an encrypted
      // message's AAD) the dCBOR of it.
      var parts = Array.isArray(v.value) ? v.value : [];
      var d = parts[3];
      if (d instanceof Uint8Array && d.length !== 32) {
        try {
          d = decode(d);
        } catch (e) {
          d = null;
        }
      }
      var digest = d instanceof Tagged && d.tag === TAG.DIGEST ? d.value :
          null;
      if (!(digest instanceof Uint8Array) || digest.length !== 32) {
        log.debug("Leaving fromCbor(). Obscured without a digest.");
        throw new Error("an " + TAG_NAMES[v.tag] + " element carries no " +
                        "digest.");
      }
      out = new Envelope(v.tag === TAG.ENCRYPTED ? "encrypted" :
                         "compressed", { cbor: v }, digest);
    } else {
      log.debug("Leaving fromCbor(). Unknown tag.");
      throw new Error("tag " + v.tag + " is not an envelope case.");
    }
  } else if (v instanceof Uint8Array) {
    out = elided(v);
  } else if (Array.isArray(v)) {
    if (v.length < 2) {
      log.debug("Leaving fromCbor(). Short node.");
      throw new Error("a node must have at least two elements.");
    }
    var subject = fromCbor(v[0]);
    var asserts = v.slice(1).map(fromCbor);
    asserts.forEach(function (a) {
      if (!isAssertionLike(a)) {
        throw new Error("a node element after the subject is not an " +
                        "assertion.");
      }
    });
    for (var i = 1; i < asserts.length; i++) {
      var c = compareBytes(asserts[i - 1].digest, asserts[i].digest);
      if (c >= 0) {
        log.debug("Leaving fromCbor(). Unsorted.");
        throw new Error(c === 0 ? "a node carries the same assertion twice." :
                        "a node's assertions are not in digest order.");
      }
    }
    out = node(subject, asserts);
  } else if (v instanceof Map) {
    if (v.size !== 1) {
      log.debug("Leaving fromCbor(). Bad assertion.");
      throw new Error("an assertion is a map with exactly one entry.");
    }
    var entry = Array.from(v.entries())[0];
    out = assertion(fromCbor(entry[0]), fromCbor(entry[1]));
  } else if ((typeof v === "number" && Number.isInteger(v) && v >= 0) ||
             (typeof v === "bigint" && v >= BigInt(0))) {
    out = knownValue(Number(v));
  } else {
    log.debug("Leaving fromCbor(). Not an envelope.");
    throw new Error("not envelope content: " + typeof v + ".");
  }
  log.debug("Leaving fromCbor().");
  return out;
}

function toBytes(e) {
  log.debug("Entering toBytes().");
  log.debug("Leaving toBytes().");
  return encode(new Tagged(TAG.ENVELOPE, toCbor(e)));
}

function fromBytes(bytes) {
  log.debug("Entering fromBytes().");
  var v = decode(bytes);
  if (!(v instanceof Tagged) || v.tag !== TAG.ENVELOPE) {
    log.debug("Leaving fromBytes(). Untagged.");
    throw new Error("an envelope's CBOR begins with tag 200.");
  }
  log.debug("Leaving fromBytes().");
  return fromCbor(v.value);
}

// ---------------------------------------------------------------------------
// UR (BCR-2020-005): ur:<type>/<bytewords minimal of body + CRC-32>, and
// the multi-part form, in bc_ur.js.
// ---------------------------------------------------------------------------

function crc32(bytes) {
  log.debug("Entering crc32().");
  log.debug("Leaving crc32().");
  return bcur.crc32(bytes);
}

function urEncode(type, body) {
  log.debug("Entering urEncode(). " + type);
  log.debug("Leaving urEncode().");
  return bcur.urEncode(type, body);
}

// One UR, or every part of a multi-part one (whitespace between them).
function urDecode(text) {
  log.debug("Entering urDecode().");
  var d = bcur.decodeAny(text);
  log.debug("Leaving urDecode(). " + d.parts + " part(s).");
  return { type: d.type, body: d.body, parts: d.parts,
           fragments: d.fragments };
}

function toUr(e) {
  log.debug("Entering toUr().");
  log.debug("Leaving toUr().");
  return urEncode("envelope", encode(toCbor(e)));
}

// The multi-part form: `count` parts (default one per fragment) of at most
// maxFragmentLength bytes each, fountain parts after the fragments.
function toUrParts(e, maxFragmentLength, count) {
  log.debug("Entering toUrParts().");
  log.debug("Leaving toUrParts().");
  return bcur.encodeParts("envelope", encode(toCbor(e)),
                          maxFragmentLength || 200, count);
}

// ur:envelope/…, hex of the tagged CBOR (d8c8…), or bytes.
function read(input) {
  log.debug("Entering read().");
  if (input instanceof Uint8Array) {
    log.debug("Leaving read(). Bytes.");
    return fromBytes(input);
  }
  var s = String(input || "").trim();
  if (/^ur:/i.test(s)) {
    var ur = urDecode(s);
    if (ur.type !== "envelope") {
      log.debug("Leaving read(). Another UR type.");
      throw new Error("ur:" + ur.type + " is not an envelope.");
    }
    log.debug("Leaving read(). UR.");
    return fromCbor(decode(ur.body));
  }
  if (/^[0-9a-fA-F\s]+$/.test(s)) {
    log.debug("Leaving read(). Hex.");
    return fromBytes(cbytes.hexToBytes(s.replace(/\s+/g, "")));
  }
  log.debug("Leaving read(). Unknown.");
  throw new Error("an envelope is read from ur:envelope/… text or the hex " +
                  "of its CBOR (d8c8…).");
}

// ---------------------------------------------------------------------------
// Keys and signatures.
// ---------------------------------------------------------------------------

var SCHEMES = ["schnorr", "ecdsa", "ed25519", "mldsa44", "mldsa65",
               "mldsa87", "ssh-ed25519", "ecdsa-sha2-nistp256",
               "ecdsa-sha2-nistp384"];

// FIPS 204 ML-DSA, as bc-components carries it: [level, bytes] under its
// own tag, the level 2, 3 or 5. The keys are FIPS 204's encodings (the
// secret key the expanded one pqcrypto writes), and the signature is the
// pure, empty-context one over the subject digest's 32 bytes.
var MLDSA = {
  mldsa44: { level: 2, impl: nobleMldsa.ml_dsa44 },
  mldsa65: { level: 3, impl: nobleMldsa.ml_dsa65 },
  mldsa87: { level: 5, impl: nobleMldsa.ml_dsa87 }
};

function mldsaScheme(level) {
  log.debug("Entering mldsaScheme(). " + level);
  var name = Object.keys(MLDSA).filter(function (k) {
    return MLDSA[k].level === level;
  })[0];
  log.debug("Leaving mldsaScheme(). " + name);
  return name || null;
}

function isMldsa(scheme) {
  log.debug("Entering isMldsa().");
  log.debug("Leaving isMldsa().");
  return Object.prototype.hasOwnProperty.call(MLDSA, scheme);
}

// A new ML-DSA key pair: { scheme, privateKey, publicKey }. `seed` (32
// bytes) makes it reproducible.
function mldsaKeyPair(scheme, seed) {
  log.debug("Entering mldsaKeyPair(). " + scheme);
  if (!isMldsa(scheme)) {
    log.debug("Leaving mldsaKeyPair(). Not ML-DSA.");
    throw new Error(scheme + " is not mldsa44, mldsa65 or mldsa87.");
  }
  var kp = MLDSA[scheme].impl.keygen(seed ? cbytes.asBytes(seed) :
                                     cbytes.randomBytes(32));
  log.debug("Leaving mldsaKeyPair().");
  return { scheme: scheme, privateKey: kp.secretKey, publicKey: kp.publicKey };
}

// bc-components PrivateKeyBase: one 32-byte signing key from a seed.
function signingKeyFromSeed(seed) {
  log.debug("Entering signingKeyFromSeed().");
  log.debug("Leaving signingKeyFromSeed().");
  return nobleHkdf(nobleSha256, cbytes.asBytes(seed),
                   cbytes.strBytes("signing"), new Uint8Array(0), 32);
}

// { scheme, privateKey (32 bytes) } -> { scheme, publicKey }.
function publicKeyOf(key) {
  log.debug("Entering publicKeyOf(). " + key.scheme);
  if (isMldsa(key.scheme)) {
    if (!key.publicKey) {
      log.debug("Leaving publicKeyOf(). No ML-DSA public key.");
      throw new Error("an ML-DSA private key does not give its public key " +
                      "here; keep the pair (ur:crypto-prvkeys does not " +
                      "carry it either).");
    }
    log.debug("Leaving publicKeyOf(). ML-DSA.");
    return { scheme: key.scheme, publicKey: key.publicKey };
  }
  if (SSH_ALGS[key.scheme]) {
    var a = SSH_ALGS[key.scheme];
    log.debug("Leaving publicKeyOf(). SSH.");
    return { scheme: key.scheme, publicKey: key.publicKey ||
             (a && a.curve ? a.impl.getPublicKey(key.privateKey, false) :
              nobleEd.ed25519.getPublicKey(key.privateKey)) };
  }
  var sk = key.privateKey;
  var pk = key.scheme === "schnorr" ? nobleSecp.schnorr.getPublicKey(sk) :
      key.scheme === "ecdsa" ? nobleSecp.secp256k1.getPublicKey(sk, true) :
      nobleEd.ed25519.getPublicKey(sk);
  log.debug("Leaving publicKeyOf().");
  return { scheme: key.scheme, publicKey: pk };
}

function publicKeyCbor(pub) {
  log.debug("Entering publicKeyCbor().");
  var inner = pub.scheme === "schnorr" ? pub.publicKey :
      SSH_ALGS[pub.scheme] ? new Tagged(TAG.SSH_PUBLIC_KEY,
                                        sshPublicKeyText(pub)) :
      isMldsa(pub.scheme) ? new Tagged(TAG.MLDSA_PUBLIC_KEY,
        [MLDSA[pub.scheme].level, pub.publicKey]) :
      [pub.scheme === "ecdsa" ? 1 : 2, pub.publicKey];
  log.debug("Leaving publicKeyCbor().");
  return new Tagged(TAG.SIGNING_PUBLIC_KEY, inner);
}

function publicKeyUr(pub) {
  log.debug("Entering publicKeyUr().");
  log.debug("Leaving publicKeyUr().");
  return urEncode("signing-public-key", encode(publicKeyCbor(pub).value));
}

// A public key from ur:signing-public-key/…, ur:crypto-pubkeys/… (its
// signing key), or hex of 32 (x-only Schnorr) or 33 (compressed ECDSA)
// bytes.
function readPublicKey(input) {
  log.debug("Entering readPublicKey().");
  var s = String(input || "").trim();
  var inner;
  if (/^ssh-|^ecdsa-sha2-/.test(s)) {
    log.debug("Leaving readPublicKey(). OpenSSH text.");
    return sshPublicKey(s);
  }
  if (/^ur:/i.test(s)) {
    var ur = urDecode(s);
    var v = decode(ur.body);
    if (ur.type === "crypto-pubkeys" && Array.isArray(v)) {
      v = v[0] instanceof Tagged ? v[0].value : v[0];
    } else if (ur.type !== "signing-public-key") {
      log.debug("Leaving readPublicKey(). Wrong UR type.");
      throw new Error("ur:" + ur.type + " is not a signing public key.");
    }
    inner = v;
  } else {
    var b = cbytes.hexToBytes(s.replace(/\s+/g, ""));
    inner = b.length === 33 ? [1, b] : b;
  }
  var out;
  if (inner instanceof Uint8Array && inner.length === 32) {
    out = { scheme: "schnorr", publicKey: inner };
  } else if (Array.isArray(inner) && inner[0] === 1 &&
             inner[1] instanceof Uint8Array && inner[1].length === 33) {
    out = { scheme: "ecdsa", publicKey: inner[1] };
  } else if (Array.isArray(inner) && inner[0] === 2 &&
             inner[1] instanceof Uint8Array && inner[1].length === 32) {
    out = { scheme: "ed25519", publicKey: inner[1] };
  } else if (inner instanceof Tagged && inner.tag === TAG.MLDSA_PUBLIC_KEY &&
             Array.isArray(inner.value) && mldsaScheme(inner.value[0]) &&
             inner.value[1] instanceof Uint8Array) {
    out = { scheme: mldsaScheme(inner.value[0]), publicKey: inner.value[1] };
  } else if (inner instanceof Tagged && inner.tag === TAG.SSH_PUBLIC_KEY &&
             typeof inner.value === "string") {
    out = sshPublicKey(inner.value);
  } else {
    log.debug("Leaving readPublicKey(). Unknown form.");
    throw new Error("not a Schnorr, ECDSA, Ed25519, ML-DSA or SSH signing " +
                    "public key.");
  }
  log.debug("Leaving readPublicKey(). " + out.scheme);
  return out;
}

// ---------------------------------------------------------------------------
// SSH signatures (bc-components' SSH variant): an SSHSIG (OpenSSH's
// PROTOCOL.sshsig) over the subject digest's 32 bytes, carried as its
// armored text under tag 40802, the key as OpenSSH text under 40801 (public)
// and 40800 (an unencrypted openssh-key-v1 private key). Ed25519 and ECDSA
// P-256 / P-384; ssh-dsa and RSA are refused by name. The namespace is
// bc-envelope-cli's default, "envelope", and the message hash SHA-256.
// ---------------------------------------------------------------------------

var SSH_ALGS = {
  "ssh-ed25519": { label: "SshEd25519" },
  "ecdsa-sha2-nistp256": { label: "SshEcdsaP256", curve: "nistp256",
                           impl: nobleP256.p256, hash: nobleSha256 },
  "ecdsa-sha2-nistp384": { label: "SshEcdsaP384", curve: "nistp384",
                           impl: nobleP384.p384, hash: nobleSha384 }
};
var SSH_NAMESPACE = "envelope";

function sshString(bytes) {
  log.debug("Entering sshString().");
  var b = typeof bytes === "string" ? cbytes.strBytes(bytes) : bytes;
  var n = b.length;
  log.debug("Leaving sshString().");
  return cbytes.concatBytes(new Uint8Array([n >>> 24, (n >>> 16) & 0xff,
                                            (n >>> 8) & 0xff, n & 0xff]), b);
}

function sshMpint(bytes) {
  log.debug("Entering sshMpint().");
  var b = cbytes.asBytes(bytes);
  var i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b.length && b[0] & 0x80) b = cbytes.concatBytes(new Uint8Array([0]), b);
  log.debug("Leaving sshMpint().");
  return sshString(b);
}

function SshReader(bytes) {
  log.debug("Entering SshReader().");
  this.b = bytes;
  this.i = 0;
  log.debug("Leaving SshReader().");
}

SshReader.prototype.u32 = function () {
  log.debug("Entering SshReader.u32().");
  if (this.i + 4 > this.b.length) {
    log.debug("Leaving SshReader.u32(). Short.");
    throw new Error("SSH: the data ends inside a number.");
  }
  var b = this.b;
  var v = ((b[this.i] << 24) | (b[this.i + 1] << 16) | (b[this.i + 2] << 8) |
           b[this.i + 3]) >>> 0;
  this.i += 4;
  log.debug("Leaving SshReader.u32().");
  return v;
};

SshReader.prototype.bytes = function () {
  log.debug("Entering SshReader.bytes().");
  var n = this.u32();
  if (this.i + n > this.b.length) {
    log.debug("Leaving SshReader.bytes(). Short.");
    throw new Error("SSH: the data ends inside a string.");
  }
  var out = this.b.slice(this.i, this.i + n);
  this.i += n;
  log.debug("Leaving SshReader.bytes().");
  return out;
};

SshReader.prototype.text = function () {
  log.debug("Entering SshReader.text().");
  log.debug("Leaving SshReader.text().");
  return cbytes.bytesToStr(this.bytes());
};

// A public key's wire form -> { scheme, publicKey }.
function sshPublicKeyFromWire(wire) {
  log.debug("Entering sshPublicKeyFromWire().");
  var r = new SshReader(wire);
  var alg = r.text();
  var out;
  if (alg === "ssh-ed25519") {
    out = { scheme: alg, publicKey: r.bytes() };
  } else if (SSH_ALGS[alg] && SSH_ALGS[alg].curve) {
    if (r.text() !== SSH_ALGS[alg].curve) {
      log.debug("Leaving sshPublicKeyFromWire(). Curve.");
      throw new Error("SSH: an " + alg + " key on another curve.");
    }
    out = { scheme: alg, publicKey: r.bytes() };
  } else {
    log.debug("Leaving sshPublicKeyFromWire(). Unsupported.");
    throw new Error("SSH key type " + JSON.stringify(alg) + " is not " +
                    "supported here (ssh-ed25519, ecdsa-sha2-nistp256 and " +
                    "ecdsa-sha2-nistp384 are).");
  }
  log.debug("Leaving sshPublicKeyFromWire(). " + alg);
  return out;
}

function sshPublicKeyWire(pub) {
  log.debug("Entering sshPublicKeyWire().");
  var a = SSH_ALGS[pub.scheme];
  log.debug("Leaving sshPublicKeyWire().");
  return a.curve ? cbytes.concatBytes(sshString(pub.scheme),
                                      sshString(a.curve),
                                      sshString(pub.publicKey)) :
    cbytes.concatBytes(sshString(pub.scheme), sshString(pub.publicKey));
}

// "ssh-ed25519 AAAA… comment" -> { scheme, publicKey }.
function sshPublicKey(text) {
  log.debug("Entering sshPublicKey().");
  var parts = String(text).trim().split(/\s+/);
  var key = sshPublicKeyFromWire(cbytes.b64ToBytes(parts[1] || ""));
  if (key.scheme !== parts[0]) {
    log.debug("Leaving sshPublicKey(). Label disagrees.");
    throw new Error("SSH: the key is labelled " + parts[0] + " and is " +
                    key.scheme + ".");
  }
  log.debug("Leaving sshPublicKey().");
  return key;
}

function sshPublicKeyText(pub) {
  log.debug("Entering sshPublicKeyText().");
  log.debug("Leaving sshPublicKeyText().");
  return pub.scheme + " " + cbytes.bytesToB64(sshPublicKeyWire(pub));
}

function armor(label, bytes) {
  log.debug("Entering armor().");
  var b64 = cbytes.bytesToB64(bytes);
  var lines = [];
  for (var i = 0; i < b64.length; i += 70) lines.push(b64.slice(i, i + 70));
  log.debug("Leaving armor().");
  return "-----BEGIN " + label + "-----\n" + lines.join("\n") +
    "\n-----END " + label + "-----\n";
}

function dearmor(label, text) {
  log.debug("Entering dearmor().");
  var m = new RegExp("-----BEGIN " + label + "-----([\\s\\S]*?)-----END " +
                     label + "-----").exec(String(text));
  if (!m) {
    log.debug("Leaving dearmor(). Not armored.");
    throw new Error("SSH: not a " + label + ".");
  }
  log.debug("Leaving dearmor().");
  return cbytes.b64ToBytes(m[1].replace(/\s+/g, ""));
}

// The bytes an SSHSIG signs: SHA-256 (or -512) of the message, framed.
function sshSignedData(namespace, hashAlg, message) {
  log.debug("Entering sshSignedData().");
  var h = hashAlg === "sha512" ? nobleSha512(message) : nobleSha256(message);
  log.debug("Leaving sshSignedData().");
  return cbytes.concatBytes(cbytes.strBytes("SSHSIG"), sshString(namespace),
                            sshString(new Uint8Array(0)), sshString(hashAlg),
                            sshString(h));
}

// The armored SSHSIG over `message` by key { scheme, privateKey,
// publicKey }.
function sshSign(key, message) {
  log.debug("Entering sshSign(). " + key.scheme);
  var a = SSH_ALGS[key.scheme];
  if (!a) {
    log.debug("Leaving sshSign(). Unsupported.");
    throw new Error("SSH signing with " + key.scheme + " is not supported " +
                    "here.");
  }
  var data = sshSignedData(SSH_NAMESPACE, "sha256", message);
  var blob;
  if (a.curve) {
    var sig = a.impl.sign(a.hash(data), key.privateKey);
    var n = a.impl.CURVE.nByteLength;
    blob = cbytes.concatBytes(sshMpint(cbytes.bigToBytes(sig.r, n)),
                              sshMpint(cbytes.bigToBytes(sig.s, n)));
  } else {
    blob = nobleEd.ed25519.sign(data, key.privateKey);
  }
  var pub = { scheme: key.scheme, publicKey: key.publicKey ||
              publicKeyOf(key).publicKey };
  var out = cbytes.concatBytes(cbytes.strBytes("SSHSIG"),
    new Uint8Array([0, 0, 0, 1]), sshString(sshPublicKeyWire(pub)),
    sshString(SSH_NAMESPACE), sshString(new Uint8Array(0)),
    sshString("sha256"), sshString(cbytes.concatBytes(sshString(key.scheme),
                                                      sshString(blob))));
  log.debug("Leaving sshSign().");
  return armor("SSH SIGNATURE", out);
}

// Armored SSHSIG -> { scheme, signature, ssh: { publicKey, namespace,
// hashAlg, blob } }.
function sshReadSignature(text) {
  log.debug("Entering sshReadSignature().");
  var b = dearmor("SSH SIGNATURE", text);
  if (cbytes.bytesToStr(b.subarray(0, 6)) !== "SSHSIG") {
    log.debug("Leaving sshReadSignature(). Magic.");
    throw new Error("SSH: not an SSHSIG.");
  }
  var r = new SshReader(b.subarray(6));
  if (r.u32() !== 1) {
    log.debug("Leaving sshReadSignature(). Version.");
    throw new Error("SSH: an SSHSIG version other than 1.");
  }
  var pub = sshPublicKeyFromWire(r.bytes());
  var namespace = r.text();
  r.bytes();
  var hashAlg = r.text();
  var sr = new SshReader(r.bytes());
  var alg = sr.text();
  var blob = sr.bytes();
  log.debug("Leaving sshReadSignature(). " + alg);
  return { scheme: alg, signature: blob,
           ssh: { publicKey: pub, namespace: namespace, hashAlg: hashAlg } };
}

function sshVerify(pub, sig, message) {
  log.debug("Entering sshVerify(). " + sig.scheme);
  var a = SSH_ALGS[sig.scheme];
  if (!a || !sig.ssh || !cbytes.bytesEqual(sig.ssh.publicKey.publicKey,
                                           pub.publicKey)) {
    log.debug("Leaving sshVerify(). Not this key.");
    return false;
  }
  var data = sshSignedData(sig.ssh.namespace, sig.ssh.hashAlg, message);
  var ok;
  if (a.curve) {
    var r = new SshReader(sig.signature);
    var rr = cbytes.bytesToBig(r.bytes());
    var ss = cbytes.bytesToBig(r.bytes());
    // OpenSSH does not normalise S, so a high-S signature is valid here.
    ok = a.impl.verify(new a.impl.Signature(rr, ss), a.hash(data),
                       pub.publicKey, { lowS: false });
  } else {
    ok = nobleEd.ed25519.verify(sig.signature, data, pub.publicKey);
  }
  log.debug("Leaving sshVerify(). " + ok);
  return ok;
}

// An unencrypted OpenSSH private key -> { scheme, privateKey, publicKey }.
function sshPrivateKey(text) {
  log.debug("Entering sshPrivateKey().");
  var b = dearmor("OPENSSH PRIVATE KEY", text);
  var magic = "openssh-key-v1\u0000";
  if (cbytes.bytesToStr(b.subarray(0, magic.length)) !== magic) {
    log.debug("Leaving sshPrivateKey(). Magic.");
    throw new Error("SSH: not an openssh-key-v1 private key.");
  }
  var r = new SshReader(b.subarray(magic.length));
  if (r.text() !== "none" || r.text() !== "none") {
    log.debug("Leaving sshPrivateKey(). Encrypted.");
    throw new Error("SSH: an encrypted private key (only unencrypted ones " +
                    "are read).");
  }
  r.bytes();
  if (r.u32() !== 1) {
    log.debug("Leaving sshPrivateKey(). Count.");
    throw new Error("SSH: a private key file holding more than one key.");
  }
  r.bytes();
  var p = new SshReader(r.bytes());
  if (p.u32() !== p.u32()) {
    log.debug("Leaving sshPrivateKey(). Check words.");
    throw new Error("SSH: the private key's check words differ.");
  }
  var alg = p.text();
  var out;
  if (alg === "ssh-ed25519") {
    var pk = p.bytes();
    out = { scheme: alg, privateKey: p.bytes().slice(0, 32), publicKey: pk };
  } else if (SSH_ALGS[alg] && SSH_ALGS[alg].curve) {
    p.text();
    var q = p.bytes();
    var d = cbytes.bytesToBig(p.bytes());
    out = { scheme: alg, publicKey: q,
            privateKey: cbytes.bigToBytes(d,
              SSH_ALGS[alg].impl.CURVE.nByteLength) };
  } else {
    log.debug("Leaving sshPrivateKey(). Unsupported.");
    throw new Error("SSH key type " + JSON.stringify(alg) + " is not " +
                    "supported here.");
  }
  log.debug("Leaving sshPrivateKey(). " + alg);
  return out;
}

// An Ed25519 SSH key from a seed as bc-components derives one: its 32 bytes
// the first page of bc-components' HKDFRng, HKDF-SHA-256(seed, salt
// "ssh-ed25519-0").
function sshEd25519FromSeed(seed) {
  log.debug("Entering sshEd25519FromSeed().");
  var sk = nobleHkdf(nobleSha256, cbytes.asBytes(seed),
                     cbytes.strBytes("ssh-ed25519-0"), new Uint8Array(0), 32);
  log.debug("Leaving sshEd25519FromSeed().");
  return { scheme: "ssh-ed25519", privateKey: sk,
           publicKey: nobleEd.ed25519.getPublicKey(sk) };
}

function signDigest(key, digest, aux) {
  log.debug("Entering signDigest(). " + key.scheme);
  var sig;
  if (key.scheme === "schnorr") {
    sig = nobleSecp.schnorr.sign(digest, key.privateKey,
                                 aux || cbytes.randomBytes(32));
  } else if (key.scheme === "ecdsa") {
    sig = nobleSecp.secp256k1.sign(sha256(sha256(digest)), key.privateKey)
      .toCompactRawBytes();
  } else if (key.scheme === "ed25519") {
    sig = nobleEd.ed25519.sign(digest, key.privateKey);
  } else if (isMldsa(key.scheme)) {
    sig = MLDSA[key.scheme].impl.sign(key.privateKey, digest);
    log.debug("Leaving signDigest(). ML-DSA.");
    return new Tagged(TAG.SIGNATURE, new Tagged(TAG.MLDSA_SIGNATURE,
      [MLDSA[key.scheme].level, sig]));
  } else if (SSH_ALGS[key.scheme]) {
    log.debug("Leaving signDigest(). SSH.");
    return new Tagged(TAG.SIGNATURE, new Tagged(TAG.SSH_SIGNATURE,
      sshSign(key, digest)));
  } else {
    log.debug("Leaving signDigest(). Unknown scheme.");
    throw new Error("signature scheme " + key.scheme + " is not one of " +
                    SCHEMES.join(", ") + ".");
  }
  log.debug("Leaving signDigest().");
  return new Tagged(TAG.SIGNATURE, key.scheme === "schnorr" ? sig :
                    [key.scheme === "ecdsa" ? 1 : 2, sig]);
}

// { scheme, signature } from a 40020 value, or null.
function readSignature(v) {
  log.debug("Entering readSignature().");
  if (!(v instanceof Tagged) || v.tag !== TAG.SIGNATURE) {
    log.debug("Leaving readSignature(). Not a signature.");
    return null;
  }
  var x = v.value;
  var out = null;
  if (x instanceof Tagged && x.tag === TAG.MLDSA_SIGNATURE &&
      Array.isArray(x.value) && mldsaScheme(x.value[0]) &&
      x.value[1] instanceof Uint8Array) {
    out = { scheme: mldsaScheme(x.value[0]), signature: x.value[1] };
  } else if (x instanceof Tagged && x.tag === TAG.SSH_SIGNATURE &&
             typeof x.value === "string") {
    try {
      out = sshReadSignature(x.value);
    } catch (e) {
      out = null;
    }
  } else if (x instanceof Uint8Array && x.length === 64) {
    out = { scheme: "schnorr", signature: x };
  } else if (Array.isArray(x) && x.length === 2 &&
             x[1] instanceof Uint8Array && x[1].length === 64) {
    out = { scheme: x[0] === 1 ? "ecdsa" : x[0] === 2 ? "ed25519" :
            "schnorr", signature: x[1] };
    if (x[0] !== 1 && x[0] !== 2 && !(x[0] instanceof Uint8Array)) {
      out = null;
    }
  }
  log.debug("Leaving readSignature(). " + (out && out.scheme));
  return out;
}

function verifyDigest(pub, sig, digest) {
  log.debug("Entering verifyDigest(). " + sig.scheme);
  if (pub.scheme !== sig.scheme) {
    log.debug("Leaving verifyDigest(). Scheme mismatch.");
    return false;
  }
  var ok = false;
  try {
    if (sig.scheme === "schnorr") {
      ok = nobleSecp.schnorr.verify(sig.signature, digest, pub.publicKey);
    } else if (sig.scheme === "ecdsa") {
      ok = nobleSecp.secp256k1.verify(sig.signature, sha256(sha256(digest)),
                                      pub.publicKey);
    } else if (isMldsa(sig.scheme)) {
      ok = MLDSA[sig.scheme].impl.verify(pub.publicKey, digest,
                                         sig.signature);
    } else if (SSH_ALGS[sig.scheme]) {
      ok = sshVerify(pub, sig, digest);
    } else {
      ok = nobleEd.ed25519.verify(sig.signature, digest, pub.publicKey);
    }
  } catch (e) {
    ok = false;
  }
  log.debug("Leaving verifyDigest(). " + ok);
  return ok;
}

function sameDigest(a, b) {
  log.debug("Entering sameDigest().");
  log.debug("Leaving sameDigest().");
  return cbytes.bytesEqual(a, b);
}

// The unelided objects of e's assertions with this predicate.
function objectsFor(e, predicate) {
  log.debug("Entering objectsFor().");
  var p = from(predicate);
  var out = assertionsOf(e).map(function (a) {
    return a.kind === "node" ? a.subject : a;
  }).filter(function (a) {
    return a.kind === "assertion" && sameDigest(a.predicate.digest, p.digest);
  }).map(function (a) {
    return a.object;
  });
  log.debug("Leaving objectsFor(). " + out.length);
  return out;
}

// e with a signature by `key` over its SUBJECT's digest. opts.aux is the
// Schnorr auxiliary randomness (tests reproduce Rust's with it).
function addSignature(e, key, opts) {
  log.debug("Entering addSignature().");
  var sig = signDigest(key, subjectOf(e).digest, opts && opts.aux);
  log.debug("Leaving addSignature().");
  return addAssertion(e, knownValue("signed"), leaf(sig));
}

// The credential pattern: wrap, then sign, so every claim is covered.
function sign(e, key, opts) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return addSignature(wrap(e), key, opts);
}

// Every 'signed' on e, checked against `pub`. Answers { valid, results,
// reason } — valid when some signature is pub's — reporting each.
function verifySignatures(e, pub) {
  log.debug("Entering verifySignatures().");
  var digest = subjectOf(e).digest;
  var results = objectsFor(e, knownValue("signed")).map(function (obj) {
    var target = subjectOf(obj);
    if (target.kind === "wrapped") {
      // Signature with metadata: the outer one over the wrapped
      // { Signature [metadata] }, the inner one over e's subject.
      var outers = objectsFor(obj, knownValue("signed"));
      var outerOk = outers.some(function (o) {
        var s = o.kind === "leaf" ? readSignature(o.value) : null;
        return s && verifyDigest(pub, s, target.digest);
      });
      var innerLeaf = subjectOf(target.envelope);
      var inner = innerLeaf.kind === "leaf" ? readSignature(innerLeaf.value) :
          null;
      return { metadata: true, scheme: inner && inner.scheme,
               valid: !!(outerOk && inner &&
                         verifyDigest(pub, inner, digest)),
               reason: inner ? "" : "the inner signature is not a " +
                 "Signature." };
    }
    var sig = target.kind === "leaf" ? readSignature(target.value) : null;
    if (!sig) {
      return { valid: false, reason: target.kind === "elided" ? "the " +
        "'signed' object is elided, so it cannot be checked." :
        "the 'signed' object is not a Signature." };
    }
    return { scheme: sig.scheme, valid: verifyDigest(pub, sig, digest) };
  });
  var valid = results.some(function (r) {
    return r.valid;
  });
  log.debug("Leaving verifySignatures(). " + valid);
  return { valid: valid, results: results, signedDigest: digest,
           reason: valid ? "" : !results.length ? "there is no 'signed' " +
             "assertion (or it is elided)." : "no signature verifies with " +
             "this " + pub.scheme + " key over the subject's digest." };
}

// ---------------------------------------------------------------------------
// Elision.
// ---------------------------------------------------------------------------

function hexOf(e) {
  log.debug("Entering hexOf().");
  log.debug("Leaving hexOf().");
  return cbytes.bytesToHex(e.digest);
}

function elide(e) {
  log.debug("Entering elide().");
  log.debug("Leaving elide().");
  return e.kind === "elided" ? e : elided(e.digest);
}

// `targets` is a Set of hex digests. Revealing keeps exactly those (an
// ancestor not in the set hides everything under it); removing elides
// exactly those.
function elideSet(e, targets, revealing) {
  log.debug("Entering elideSet(). " + e.kind);
  if (targets.has(hexOf(e)) !== revealing) {
    log.debug("Leaving elideSet(). Elided.");
    return elide(e);
  }
  var out = e;
  if (e.kind === "assertion") {
    out = assertion(elideSet(e.predicate, targets, revealing),
                    elideSet(e.object, targets, revealing));
  } else if (e.kind === "node") {
    out = node(elideSet(e.subject, targets, revealing),
               e.assertions.map(function (a) {
                 return elideSet(a, targets, revealing);
               }));
  } else if (e.kind === "wrapped") {
    out = wrap(elideSet(e.envelope, targets, revealing));
  }
  log.debug("Leaving elideSet().");
  return out;
}

function elideRevealing(e, targets) {
  log.debug("Entering elideRevealing().");
  log.debug("Leaving elideRevealing().");
  return elideSet(e, toSet(targets), true);
}

function elideRemoving(e, targets) {
  log.debug("Entering elideRemoving().");
  log.debug("Leaving elideRemoving().");
  return elideSet(e, toSet(targets), false);
}

function toSet(targets) {
  log.debug("Entering toSet().");
  var out = new Set();
  (targets instanceof Set ? Array.from(targets) : targets || [])
    .forEach(function (t) {
      out.add(t instanceof Uint8Array ? cbytes.bytesToHex(t) :
              isEnvelope(t) ? hexOf(t) : String(t).toLowerCase());
    });
  log.debug("Leaving toSet().");
  return out;
}

// bc-envelope's digests(levelLimit): each element's digest and its
// subject's, to the given depth.
function digests(e, levelLimit) {
  log.debug("Entering digests().");
  var out = new Set();
  (function walk(x, level) {
    if (level >= levelLimit) return;
    out.add(hexOf(x));
    out.add(hexOf(subjectOf(x)));
    if (x.kind === "node") {
      walk(x.subject, level + 1);
      x.assertions.forEach(function (a) {
        walk(a, level + 1);
      });
    } else if (x.kind === "assertion") {
      walk(x.predicate, level + 1);
      walk(x.object, level + 1);
    } else if (x.kind === "wrapped") {
      walk(x.envelope, level + 1);
    }
  })(e, 0);
  log.debug("Leaving digests(). " + out.size);
  return out;
}

// ---------------------------------------------------------------------------
// Reading a credential: wrapped claims under a signed outer node.
// ---------------------------------------------------------------------------

function label(e) {
  log.debug("Entering label().");
  var out;
  if (e.kind === "knownValue") {
    out = "'" + (KNOWN_VALUES[e.value] !== undefined ?
                 KNOWN_VALUES[e.value] : String(e.value)) + "'";
  } else if (e.kind === "leaf") {
    out = valueLabel(e.value);
  } else if (e.kind === "elided") {
    out = "ELIDED";
  } else if (e.kind === "wrapped") {
    out = "{ " + label(subjectOf(e.envelope)) + " … }";
  } else if (e.kind === "assertion") {
    out = label(e.predicate) + ": " + label(e.object);
  } else if (e.kind === "node") {
    out = label(e.subject) + " [" + e.assertions.length + "]";
  } else {
    out = e.kind.toUpperCase();
  }
  log.debug("Leaving label().");
  return out;
}

function dateLabel(seconds) {
  log.debug("Entering dateLabel().");
  var iso = new Date(Number(seconds) * 1000).toISOString();
  log.debug("Leaving dateLabel().");
  return /T00:00:00\.000Z$/.test(iso) ? iso.slice(0, 10) :
    iso.replace(".000Z", "Z");
}

function valueLabel(v) {
  log.debug("Entering valueLabel().");
  var out;
  if (typeof v === "string") {
    out = JSON.stringify(v);
  } else if (typeof v === "number" || typeof v === "bigint" ||
             typeof v === "boolean" || v === null) {
    out = String(v);
  } else if (v instanceof Uint8Array) {
    out = "Bytes(" + v.length + ")";
  } else if (Array.isArray(v)) {
    out = "[" + v.map(valueLabel).join(", ") + "]";
  } else if (v instanceof Map) {
    out = "{" + Array.from(v.entries()).map(function (e) {
      return valueLabel(e[0]) + ": " + valueLabel(e[1]);
    }).join(", ") + "}";
  } else if (v instanceof Tagged) {
    if (v.tag === TAG.DATE) {
      out = dateLabel(v.value);
    } else if (v.tag === TAG.ARID || v.tag === TAG.XID) {
      out = TAG_NAMES[v.tag] + "(" + cbytes.bytesToHex(v.value).slice(0, 8) +
        ")";
    } else if (v.tag === TAG.SIGNATURE) {
      var s = readSignature(v);
      out = "Signature" + (s && s.scheme !== "schnorr" ? "(" + s.scheme +
                           ")" : "");
    } else if (v.tag === TAG.SSKR_SHARE || v.tag === TAG.SSKR_SHARE_V1) {
      out = "SSKRShare";
    } else if (v.tag === TAG.SALT) {
      out = "Salt";
    } else if (v.tag === TAG.URI) {
      out = "URI(" + v.value + ")";
    } else if (TAG_NAMES[v.tag]) {
      out = TAG_NAMES[v.tag];
    } else {
      out = v.tag + "(" + valueLabel(v.value) + ")";
    }
  } else {
    out = String(v);
  }
  log.debug("Leaving valueLabel().");
  return out;
}

// Envelope notation (bc-envelope's `format`), for display.
function notation(e, indent) {
  log.debug("Entering notation().");
  var pad = indent || "";
  var out;
  if (e.kind === "node") {
    var visible = [];
    var counts = { elided: 0, encrypted: 0, compressed: 0 };
    e.assertions.forEach(function (a) {
      if (counts[a.kind] !== undefined) {
        counts[a.kind]++;
      } else {
        visible.push(notation(a, pad + "    "));
      }
    });
    visible.sort(function (a, b) {
      var ia = /^\s*'isA'/.test(a) ? 0 : 1;
      var ib = /^\s*'isA'/.test(b) ? 0 : 1;
      return ia - ib || (a < b ? -1 : a > b ? 1 : 0);
    });
    ["elided", "encrypted", "compressed"].forEach(function (k) {
      if (counts[k]) {
        visible.push(pad + "    " + k.toUpperCase() +
                     (counts[k] > 1 ? " (" + counts[k] + ")" : ""));
      }
    });
    out = notation(e.subject, pad).replace(/^\s+/, "") + " [\n" +
      visible.join("\n") + "\n" + pad + "]";
  } else if (e.kind === "wrapped") {
    out = "{\n" + pad + "    " + notation(e.envelope, pad + "    ")
      .replace(/^\s+/, "") + "\n" + pad + "}";
  } else if (e.kind === "assertion") {
    out = notation(e.predicate, pad).replace(/^\s+/, "") + ": " +
      notation(e.object, pad).replace(/^\s+/, "");
  } else {
    out = label(e);
  }
  log.debug("Leaving notation().");
  return pad + out;
}

// The tree form: every element with the first 4 bytes of its digest.
function tree(e) {
  log.debug("Entering tree().");
  var lines = [];
  (function walk(x, depth, role) {
    var name = x.kind === "node" ? "NODE" : x.kind === "wrapped" ?
        "WRAPPED" : x.kind === "assertion" ? "ASSERTION" : label(x);
    lines.push(new Array(depth + 1).join("    ") + hexOf(x).slice(0, 8) +
               (role ? " " + role : "") + " " + name);
    if (x.kind === "node") {
      walk(x.subject, depth + 1, "subj");
      x.assertions.forEach(function (a) {
        walk(a, depth + 1, "");
      });
    } else if (x.kind === "wrapped") {
      walk(x.envelope, depth + 1, "cont");
    } else if (x.kind === "assertion") {
      walk(x.predicate, depth + 1, "pred");
      walk(x.object, depth + 1, "obj");
    }
  })(e, 0, "");
  log.debug("Leaving tree().");
  return lines.join("\n");
}

// The claims of a signed credential, for a page to offer for disclosure:
// [{ digest, label, predicate, object, elided, salted, revealSet }], where
// revealSet is what elideRevealing() needs to keep that claim (its
// assertion, predicate and object, and a salt's node when salted).
function claims(e) {
  log.debug("Entering claims().");
  var outer = e;
  var wrapped = subjectOf(outer);
  if (wrapped.kind !== "wrapped") {
    log.debug("Leaving claims(). Not a wrapped credential.");
    return { claims: [], base: [], subject: null };
  }
  var content = wrapped.envelope;
  var base = [hexOf(outer), hexOf(wrapped), hexOf(content),
              hexOf(subjectOf(content))];
  assertionsOf(outer).forEach(function (a) {
    digests(a, 1e9).forEach(function (d) {
      base.push(d);
    });
  });
  var list = assertionsOf(content).map(function (a) {
    var core = a.kind === "node" ? a.subject : a;
    var reveal = [hexOf(a)];
    if (core.kind === "assertion") {
      reveal.push(hexOf(core), hexOf(core.predicate), hexOf(core.object));
    }
    if (a.kind === "node") {
      a.assertions.forEach(function (s) {
        digests(s, 1e9).forEach(function (d) {
          reveal.push(d);
        });
      });
    }
    return { digest: hexOf(a), elided: a.kind === "elided",
             salted: a.kind === "node",
             label: a.kind === "elided" ? "ELIDED " + hexOf(a).slice(0, 8) :
               label(core), revealSet: reveal };
  });
  log.debug("Leaving claims(). " + list.length);
  return { claims: list, base: base, subject: label(subjectOf(content)) };
}

// A presentation: the credential with only `keep` (claim digests, as
// claims() gives them) disclosed. The root digest — and so the issuer's
// signature — is unchanged.
function present(e, keep) {
  log.debug("Entering present().");
  var c = claims(e);
  var targets = new Set(c.base);
  var wanted = toSet(keep);
  c.claims.forEach(function (claim) {
    if (wanted.has(claim.digest)) {
      claim.revealSet.forEach(function (d) {
        targets.add(d);
      });
    }
  });
  log.debug("Leaving present().");
  return elideRevealing(e, targets);
}

module.exports = {
  SPEC: SPEC,
  TAG: TAG,
  KNOWN_VALUES: KNOWN_VALUES,
  SCHEMES: SCHEMES,
  Tagged: Tagged,
  encode: encode,
  decode: decode,
  leaf: leaf,
  knownValue: knownValue,
  elided: elided,
  assertion: assertion,
  saltedAssertion: saltedAssertion,
  wrap: wrap,
  node: node,
  addAssertion: addAssertion,
  subjectOf: subjectOf,
  assertionsOf: assertionsOf,
  objectsFor: objectsFor,
  toCbor: toCbor,
  fromCbor: fromCbor,
  toBytes: toBytes,
  fromBytes: fromBytes,
  urEncode: urEncode,
  urDecode: urDecode,
  crc32: crc32,
  toUr: toUr,
  toUrParts: toUrParts,
  read: read,
  signingKeyFromSeed: signingKeyFromSeed,
  isMldsa: isMldsa,
  mldsaKeyPair: mldsaKeyPair,
  sshPublicKey: sshPublicKey,
  sshPublicKeyText: sshPublicKeyText,
  sshPrivateKey: sshPrivateKey,
  sshEd25519FromSeed: sshEd25519FromSeed,
  publicKeyCbor: publicKeyCbor,
  publicKeyOf: publicKeyOf,
  publicKeyUr: publicKeyUr,
  readPublicKey: readPublicKey,
  signDigest: signDigest,
  verifyDigest: verifyDigest,
  readSignature: readSignature,
  addSignature: addSignature,
  sign: sign,
  verifySignatures: verifySignatures,
  elideRevealing: elideRevealing,
  elideRemoving: elideRemoving,
  digests: digests,
  claims: claims,
  present: present,
  notation: notation,
  tree: tree,
  label: label
};
