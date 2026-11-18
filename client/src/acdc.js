// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc.js
//
// ---------------------------------------------------------------------------
// ACDC — Authentic Chained Data Containers (Trust over IP KERI Suite WG
// specification) — with the parts of CESR and KERI a verifier and an issuer
// need (#480): read a CESR stream, verify the issuer's key event log, the
// registry's events and their anchors in that log, the credential itself,
// the credentials it chains to, and an IPEX grant that carries it; and issue
// all of it.
//
// AN ACDC IS VERIFIED BY ITS ISSUER'S HISTORY, NOT BY A SIGNATURE ON IT. The
// credential carries no signature at all: its SAID (a digest of its own
// bytes) is sealed into the issuer's registry by an issuance event, and that
// event is anchored by a seal in an event of the issuer's KEL, which IS
// signed. So the chain a verifier walks is
//     KEL (icp/dip, rot/drt, ixn: signatures, thresholds, next-key digests,
//          witness receipts, the delegator's approving seal)
//       -> the event whose seal names the registry event
//         -> the registry (v1 vcp, iss/rev, or bis/brv with backers;
//            v2 rip, upd/bup) -> the ACDC whose SAID it names
//           -> through the ACDC's edges, the far credentials, recursively.
//
// TWO GENERATIONS ARE ON THE WIRE, and the released libraries mix them:
// signify-ts 0.4.1 (the KERIA client vLEI uses) writes everything in
// version 1; keri-ts 2.2.9 writes its KEL in version 2 and its credentials
// and their registry in version 1. Version 2 has its own version string
// (KERICAACAAJSON….), its own attachment counter table (counts in quadlets,
// -C/-K/-L/-S/-T/-X…, ordinals as compact Numbers), its own ACDC messages
// (acm/act/acg, rd for the registry, rip/upd/bup registries) and the
// most-compact-form SAID. Both are read here, and both are issued.
//
// SAIDS ARE CHECKED OVER THE BYTES RECEIVED, never over a re-serialization:
// the issuer's JSON may format a number (Python writes 4.0) or order an
// integer-like key in a way JavaScript's JSON.stringify would not, and
// either changes the hash. Even the v2 most compact form, which is not the
// form received, is built by splicing the received bytes. Issuing uses
// JSON.stringify, as both libraries do.
//
// All cryptography is @noble, pure JavaScript: Blake3-256 (the default
// digest), Blake2b/2s, SHA3-256 and SHA-256 digests; Ed25519, Ed448,
// secp256k1 and P-256 signatures.
//
// NO DOM.
// ---------------------------------------------------------------------------

var nobleEd = require("@noble/curves/ed25519");
var nobleEd448 = require("@noble/curves/ed448");
var nobleSecp = require("@noble/curves/secp256k1");
var nobleP256 = require("@noble/curves/p256");
var blake3 = require("@noble/hashes/blake3").blake3;
var blake2b = require("@noble/hashes/blake2b").blake2b;
var blake2s = require("@noble/hashes/blake2s").blake2s;
var sha3 = require("@noble/hashes/sha3").sha3_256;
var sha256 = require("@noble/hashes/sha256").sha256;
var cbytes = require("./crypto_bytes");
var tholder = require("./acdc_threshold");
var acdcSchema = require("./acdc_schema");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var SPEC = "ToIP ACDC, CESR and KERI specifications (KERI Suite WG)";
var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// ---------------------------------------------------------------------------
// CESR primitives.
// ---------------------------------------------------------------------------

// The CESR matter code table (the CESR specification's master table for
// genus -_AAA, as cesr-ts 2.2.1 generates it): code -> hs (hard size), ss
// (soft size), xs (extra soft, pad chars inside the soft part), fs (full
// size; empty for a variable-size code) and ls (lead bytes).
var MATTER_TABLE =
  "0A:2,0,0,24,0 0B:2,0,0,88,0 0C:2,0,0,88,0 0D:2,0,0,88,0 0E:2,0,0,88,0 " +
  "0F:2,0,0,88,0 0G:2,0,0,88,0 0H:2,0,0,8,0 0I:2,0,0,88,0 0J:2,2,1,4,0 " +
  "0K:2,2,0,4,0 0L:2,6,1,8,0 0M:2,6,0,8,0 0N:2,10,1,12,0 0O:2,10,0,12,0 " +
  "1___:4,0,0,8,0 1__-:4,2,0,12,0 1AAA:4,0,0,48,0 1AAB:4,0,0,48,0 " +
  "1AAC:4,0,0,80,0 1AAD:4,0,0,80,0 1AAE:4,0,0,156,0 1AAF:4,4,0,8,0 " +
  "1AAG:4,0,0,36,0 1AAH:4,0,0,100,0 1AAI:4,0,0,48,0 1AAJ:4,0,0,48,0 " +
  "1AAK:4,0,0,4,0 1AAL:4,0,0,4,0 1AAM:4,0,0,4,0 1AAN:4,8,0,12,0 " +
  "1AAO:4,0,0,4,0 1AAP:4,0,0,4,0 2___:4,0,0,8,1 2__-:4,2,1,12,1 " +
  "3___:4,0,0,8,2 3__-:4,2,0,12,2 4A:2,2,0,,0 4B:2,2,0,,0 4C:2,2,0,,0 " +
  "4D:2,2,0,,0 4E:2,2,0,,0 4F:2,2,0,,0 4H:2,2,0,,0 5A:2,2,0,,1 5B:2,2,0,,1 " +
  "5C:2,2,0,,1 5D:2,2,0,,1 5E:2,2,0,,1 5F:2,2,0,,1 5H:2,2,0,,1 6A:2,2,0,,2 " +
  "6B:2,2,0,,2 6C:2,2,0,,2 6D:2,2,0,,2 6E:2,2,0,,2 6F:2,2,0,,2 6H:2,2,0,,2 " +
  "7AAA:4,4,0,,0 7AAB:4,4,0,,0 7AAC:4,4,0,,0 7AAD:4,4,0,,0 7AAE:4,4,0,,0 " +
  "7AAF:4,4,0,,0 7AAH:4,4,0,,0 8AAA:4,4,0,,1 8AAB:4,4,0,,1 8AAC:4,4,0,,1 " +
  "8AAD:4,4,0,,1 8AAE:4,4,0,,1 8AAF:4,4,0,,1 8AAH:4,4,0,,1 9AAA:4,4,0,,2 " +
  "9AAB:4,4,0,,2 9AAC:4,4,0,,2 9AAD:4,4,0,,2 9AAE:4,4,0,,2 9AAF:4,4,0,,2 " +
  "9AAH:4,4,0,,2 a:1,0,0,44,0 A:1,0,0,44,0 b:1,3,0,8,0 B:1,0,0,44,0 " +
  "C:1,0,0,44,0 D:1,0,0,44,0 E:1,0,0,44,0 F:1,0,0,44,0 G:1,0,0,44,0 " +
  "H:1,0,0,44,0 I:1,0,0,44,0 J:1,0,0,44,0 K:1,0,0,76,0 L:1,0,0,76,0 " +
  "M:1,0,0,4,0 N:1,0,0,12,0 O:1,0,0,44,0 P:1,0,0,124,0 Q:1,0,0,44,0 " +
  "R:1,0,0,8,0 S:1,0,0,16,0 T:1,0,0,20,0 U:1,0,0,24,0 V:1,0,0,4,1 " +
  "W:1,0,0,4,0 X:1,3,0,4,0 Y:1,7,0,8,0 Z:1,11,0,12,0";

var SIZES = {};
MATTER_TABLE.split(" ").forEach(function (entry) {
  if (!entry) {
    return;
  }
  var p = entry.split(":");
  var n = p[1].split(",");
  SIZES[p[0]] = { hs: +n[0], ss: +n[1], xs: +n[2],
                  fs: n[3] === "" ? null : +n[3], ls: +n[4] };
});

var NAMES = {
  A: "Ed25519 seed", B: "Ed25519 non-transferable key", D: "Ed25519 key",
  E: "Blake3-256 digest", F: "Blake2b-256 digest", G: "Blake2s-256 digest",
  H: "SHA3-256 digest", I: "SHA-256 digest", M: "short number",
  "0A": "salt / sequence number", "0B": "Ed25519 signature",
  "0C": "secp256k1 signature", "0I": "P-256 signature",
  "1AAA": "secp256k1 non-transferable key", "1AAB": "secp256k1 key",
  "1AAI": "P-256 non-transferable key", "1AAJ": "P-256 key",
  "1AAC": "Ed448 non-transferable key", "1AAD": "Ed448 key",
  "1AAE": "Ed448 signature", "1AAG": "date-time", "1AAP": "empty"
};

// Kept for callers that read the old fixed-size table.
var MATTER = {};
Object.keys(SIZES).forEach(function (code) {
  var s = SIZES[code];
  if (s.fs !== null && s.ss === 0) {
    MATTER[code] = { hs: s.hs, fs: s.fs, ls: s.ls,
                     raw: Math.floor((s.fs - s.hs) * 3 / 4) - s.ls,
                     name: NAMES[code] || code };
  }
});

// The digest codes a SAID may use.
var DIGESTS = {
  E: function (b) {
    return blake3(b);
  },
  F: function (b) {
    return blake2b(b, { dkLen: 32 });
  },
  G: function (b) {
    return blake2s(b, { dkLen: 32 });
  },
  H: function (b) {
    return sha3(b);
  },
  I: function (b) {
    return sha256(b);
  }
};

function hardSize(c) {
  log.debug("Entering hardSize().");
  log.debug("Leaving hardSize().");
  return /[A-Za-z]/.test(c) ? 1 : /[0456]/.test(c) ? 2 : 4;
}

function b64Encode(bytes) {
  log.debug("Entering b64Encode().");
  log.debug("Leaving b64Encode().");
  return cbytes.bytesToB64u(bytes);
}

function repeat(c, n) {
  log.debug("Entering repeat().");
  log.debug("Leaving repeat().");
  return new Array(n + 1).join(c);
}

function intToB64(n, len) {
  log.debug("Entering intToB64().");
  var s = "";
  var v = BigInt(n);
  for (var i = 0; i < len; i++) {
    s = B64.charAt(Number(v % BigInt(64))) + s;
    v = v / BigInt(64);
  }
  if (v > BigInt(0)) {
    log.debug("Leaving intToB64(). Too large.");
    throw new Error(n + " does not fit in " + len + " base-64 digits.");
  }
  log.debug("Leaving intToB64().");
  return s;
}

function b64ToInt(s) {
  log.debug("Entering b64ToInt().");
  var v = 0;
  for (var i = 0; i < s.length; i++) {
    var d = B64.indexOf(s.charAt(i));
    if (d === -1) {
      log.debug("Leaving b64ToInt(). Not base64url.");
      throw new Error("not base64url: " + JSON.stringify(s));
    }
    v = v * 64 + d;
  }
  log.debug("Leaving b64ToInt().");
  return v;
}

// raw bytes -> qb64 with a fixed-size code whose soft part is empty.
function encodeMatter(code, raw) {
  log.debug("Entering encodeMatter(). " + code);
  var m = MATTER[code];
  if (!m || raw.length !== m.raw) {
    log.debug("Leaving encodeMatter(). Bad size.");
    throw new Error("code " + code + " takes " + (m ? m.raw : "?") +
                    " bytes, not " + raw.length + ".");
  }
  var ps = code.length % 4;
  var body = b64Encode(cbytes.concatBytes(new Uint8Array(ps + m.ls), raw))
    .slice(ps);
  log.debug("Leaving encodeMatter().");
  return code + body;
}

// qb64 -> { code, raw, soft, size, qb64 } at the start of text: fixed-size
// codes, codes whose value is in the soft part (tags), and variable-size
// codes (strings, paths, bytes).
function decodeMatter(text) {
  log.debug("Entering decodeMatter().");
  var hs = hardSize(text.charAt(0));
  var code = text.slice(0, hs);
  var sz = SIZES[code];
  if (!sz) {
    log.debug("Leaving decodeMatter(). Unknown code.");
    throw new Error("CESR code " + JSON.stringify(code) + " is not in the " +
                    "CESR code table.");
  }
  var cs = hs + sz.ss;
  var soft = text.slice(hs, cs);
  var fs = sz.fs;
  if (fs === null) {
    fs = cs + b64ToInt(soft) * 4;
  }
  var q = text.slice(0, fs);
  if (q.length !== fs) {
    log.debug("Leaving decodeMatter(). Short.");
    throw new Error("a " + (NAMES[code] || code) + " is " + fs +
                    " characters; the stream ends first.");
  }
  var ps = cs % 4;
  var paw = cbytes.b64uToBytes(repeat("A", ps) + q.slice(cs));
  for (var i = 0; i < ps + sz.ls; i++) {
    if (paw[i]) {
      log.debug("Leaving decodeMatter(). Pad bits set.");
      throw new Error("non-zero pad bits in " + q.slice(0, 12) + "….");
    }
  }
  log.debug("Leaving decodeMatter().");
  return { code: code, raw: paw.slice(ps + sz.ls), soft: soft.slice(sz.xs),
           ls: sz.ls, size: fs, qb64: q };
}

// The text a string primitive carries: a tag (value in the soft part), a
// Base64 string (StrB64 / Bexter), bytes, or Empty.
var NUMBERS = [["M", 2], ["R", 5], ["N", 8], ["S", 11], ["T", 14],
               ["U", 17]];

function bextOf(m) {
  log.debug("Entering bextOf().");
  var bext = b64Encode(cbytes.concatBytes(new Uint8Array(m.ls), m.raw));
  var ws = m.ls === 0 ? (bext.charAt(0) === "A" ? 1 : 0) : (m.ls + 1) % 4;
  log.debug("Leaving bextOf().");
  return bext.slice(ws);
}

function stringOf(m) {
  log.debug("Entering stringOf(). " + m.code);
  var sel = m.code.charAt(0);
  var type = sel === "4" || sel === "5" || sel === "6" ? m.code.charAt(1) :
      sel === "7" || sel === "8" || sel === "9" ? m.code.charAt(3) : null;
  var out;
  if (m.code === "1AAP") {
    out = "";
  } else if (type === "A") {
    out = bextOf(m);
  } else if (type === "B") {
    out = cbytes.bytesToStr(m.raw);
  } else if (SIZES[m.code].ss > 0 && SIZES[m.code].fs !== null) {
    out = m.soft;
  } else {
    out = m.qb64;
  }
  log.debug("Leaving stringOf().");
  return out;
}

// A Base64 text as a StrB64 primitive (keripy's Bexter): a SAD path, or a
// weighted threshold's limen.
function encodeBexter(bext) {
  log.debug("Entering encodeBexter().");
  if (!/^[A-Za-z0-9_-]*$/.test(bext)) {
    log.debug("Leaving encodeBexter(). Not Base64.");
    throw new Error(JSON.stringify(bext) + " is not Base64 text.");
  }
  var ws = (4 - bext.length % 4) % 4;
  var full = cbytes.b64uToBytes(repeat("A", ws) + bext);
  var raw = full.slice(Math.floor(ws * 3 / 4));
  var ls = (3 - raw.length % 3) % 3;
  var size = (raw.length + ls) / 3;
  var code = (size < 4096 ? ["4A", "5A", "6A"] :
              ["7AAA", "8AAA", "9AAA"])[ls];
  var out = code + intToB64(size, size < 4096 ? 2 : 4) +
      b64Encode(cbytes.concatBytes(new Uint8Array(ls), raw));
  log.debug("Leaving encodeBexter().");
  return out;
}

// A SAD path (["e", "acdc"]) as a Pather: "-e-acdc" in a StrB64.
function encodePath(parts) {
  log.debug("Entering encodePath().");
  log.debug("Leaving encodePath().");
  return encodeBexter("-" + parts.join("-"));
}

function decodePath(m) {
  log.debug("Entering decodePath().");
  var bext = bextOf(m);
  var parts = bext.split("-");
  if (parts[0] === "") {
    parts.shift();
  }
  log.debug("Leaving decodePath().");
  return parts.length === 1 && parts[0] === "" ? [] : parts;
}

// v2 ordinals: the first Number code wide enough.
function encodeNumber(n) {
  log.debug("Entering encodeNumber().");
  var v = BigInt(n);
  for (var i = 0; i < NUMBERS.length; i++) {
    var width = NUMBERS[i][1];
    if (v < (BigInt(1) << BigInt(8 * width))) {
      var raw = new Uint8Array(width);
      var w = v;
      for (var j = width - 1; j >= 0; j--) {
        raw[j] = Number(w & BigInt(255));
        w >>= BigInt(8);
      }
      log.debug("Leaving encodeNumber().");
      return encodeMatter(NUMBERS[i][0], raw);
    }
  }
  log.debug("Leaving encodeNumber(). Too large.");
  throw new Error(n + " is too large for a CESR Number.");
}

function bigEndian(raw) {
  log.debug("Entering bigEndian().");
  var v = BigInt(0);
  for (var i = 0; i < raw.length; i++) {
    v = (v << BigInt(8)) | BigInt(raw[i]);
  }
  log.debug("Leaving bigEndian().");
  return v;
}

// An ordinal primitive: a v1 Seqner (0A), a v2 Number, or a long (0H).
function ordinalOf(m) {
  log.debug("Entering ordinalOf(). " + m.code);
  var ok = m.code === "0A" || m.code === "0H" ||
      NUMBERS.some(function (n) {
        return n[0] === m.code;
      });
  if (!ok) {
    log.debug("Leaving ordinalOf(). Not an ordinal.");
    throw new Error("expected a sequence number, found code " + m.code + ".");
  }
  var v = bigEndian(m.raw);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    log.debug("Leaving ordinalOf(). Too large.");
    throw new Error("a sequence number above 2^53 is not read here.");
  }
  log.debug("Leaving ordinalOf().");
  return Number(v);
}

// Indexed signatures: code -> { hs, ss, os, fs, alg, only }. A/B, 2A/2B
// Ed25519; C/D, 2C/2D secp256k1; E/F, 2E/2F P-256; 0A/0B, 3A/3B Ed448. The
// second of each pair is "current list only" (no ondex).
var INDEXER = {
  A: { hs: 1, ss: 1, os: 0, fs: 88, alg: "ed25519", only: false },
  B: { hs: 1, ss: 1, os: 0, fs: 88, alg: "ed25519", only: true },
  C: { hs: 1, ss: 1, os: 0, fs: 88, alg: "secp256k1", only: false },
  D: { hs: 1, ss: 1, os: 0, fs: 88, alg: "secp256k1", only: true },
  E: { hs: 1, ss: 1, os: 0, fs: 88, alg: "p256", only: false },
  F: { hs: 1, ss: 1, os: 0, fs: 88, alg: "p256", only: true },
  "0A": { hs: 2, ss: 2, os: 1, fs: 156, alg: "ed448", only: false },
  "0B": { hs: 2, ss: 2, os: 1, fs: 156, alg: "ed448", only: true },
  "2A": { hs: 2, ss: 4, os: 2, fs: 92, alg: "ed25519", only: false },
  "2B": { hs: 2, ss: 4, os: 2, fs: 92, alg: "ed25519", only: true },
  "2C": { hs: 2, ss: 4, os: 2, fs: 92, alg: "secp256k1", only: false },
  "2D": { hs: 2, ss: 4, os: 2, fs: 92, alg: "secp256k1", only: true },
  "2E": { hs: 2, ss: 4, os: 2, fs: 92, alg: "p256", only: false },
  "2F": { hs: 2, ss: 4, os: 2, fs: 92, alg: "p256", only: true },
  "3A": { hs: 2, ss: 6, os: 3, fs: 160, alg: "ed448", only: false },
  "3B": { hs: 2, ss: 6, os: 3, fs: 160, alg: "ed448", only: true }
};
var INDEXER_CODES = {
  ed25519: ["A", "B", "2A", "2B"], secp256k1: ["C", "D", "2C", "2D"],
  p256: ["E", "F", "2E", "2F"], ed448: ["0A", "0B", "3A", "3B"]
};

function decodeIndexed(text) {
  log.debug("Entering decodeIndexed().");
  var hs = /[A-Za-z]/.test(text.charAt(0)) ? 1 : 2;
  var code = text.slice(0, hs);
  var t = INDEXER[code];
  if (!t) {
    log.debug("Leaving decodeIndexed(). Unknown.");
    throw new Error("indexed signature code " + JSON.stringify(code) +
                    " is not read here.");
  }
  var q = text.slice(0, t.fs);
  if (q.length !== t.fs) {
    log.debug("Leaving decodeIndexed(). Short.");
    throw new Error("an indexed signature is " + t.fs + " characters.");
  }
  var cs = hs + t.ss;
  var index = b64ToInt(q.slice(hs, cs - t.os));
  var ondex = t.os ? b64ToInt(q.slice(cs - t.os, cs)) : index;
  var ps = cs % 4;
  var paw = cbytes.b64uToBytes(repeat("A", ps) + q.slice(cs));
  for (var i = 0; i < ps; i++) {
    if (paw[i]) {
      log.debug("Leaving decodeIndexed(). Pad bits set.");
      throw new Error("non-zero pad bits in an indexed signature.");
    }
  }
  log.debug("Leaving decodeIndexed().");
  return { code: code, alg: t.alg, index: index,
           ondex: t.only ? null : ondex, sig: paw.slice(ps), size: t.fs,
           qb64: q };
}

// sig at `index` (and `ondex` in the prior next list; null for a
// current-only signature).
function encodeIndexed(sig, index, alg, ondex) {
  log.debug("Entering encodeIndexed().");
  var codes = INDEXER_CODES[alg || "ed25519"];
  var only = ondex === null;
  var od = ondex === undefined ? index : ondex;
  var small = alg === "ed448" ? index < 64 && (only || od < 64) :
      index < 64 && (only || od === index);
  var code = codes[(small ? 0 : 2) + (only ? 1 : 0)];
  var t = INDEXER[code];
  var cs = t.hs + t.ss;
  var both = code + intToB64(index, t.ss - t.os) +
      (t.os ? intToB64(only ? 0 : od, t.os) : "");
  var ps = cs % 4;
  var out = both + b64Encode(cbytes.concatBytes(new Uint8Array(ps), sig))
    .slice(ps);
  log.debug("Leaving encodeIndexed().");
  return out;
}

function seqner(sn) {
  log.debug("Entering seqner().");
  var raw = new Uint8Array(16);
  var v = BigInt(sn);
  for (var i = 15; i >= 0; i--) {
    raw[i] = Number(v & BigInt(255));
    v >>= BigInt(8);
  }
  log.debug("Leaving seqner().");
  return encodeMatter("0A", raw);
}

// The ordinal of a generation: a v1 Seqner, a v2 Number.
function ordinal(sn, gen) {
  log.debug("Entering ordinal().");
  log.debug("Leaving ordinal().");
  return gen === 2 ? encodeNumber(sn) : seqner(sn);
}

// ---------------------------------------------------------------------------
// Counters (group codes), both generations.
// ---------------------------------------------------------------------------

// v1 counts ITEMS, except the attachment group and the pathed group, which
// count quadlets. v2 counts QUADLETS for every group.
var COUNTERS_V1 = {
  "-A": "ControllerIdxSigs", "-B": "WitnessIdxSigs",
  "-C": "NonTransReceiptCouples", "-D": "TransReceiptQuadruples",
  "-E": "FirstSeenReplayCouples", "-F": "TransIdxSigGroups",
  "-G": "SealSourceCouples", "-H": "TransLastIdxSigGroups",
  "-I": "SealSourceTriples", "-J": "SadPathSig", "-K": "SadPathSigGroup",
  "-L": "PathedMaterialCouples", "--L": "PathedMaterialCouples",
  "-T": "GenericGroup", "--T": "GenericGroup",
  "-U": "BodyWithAttachmentGroup", "--U": "BodyWithAttachmentGroup",
  "-V": "AttachmentGroup", "--V": "AttachmentGroup", "-0V": "AttachmentGroup",
  "-W": "NonNativeBodyGroup", "-Z": "ESSRPayloadGroup"
};
var COUNTERS_V2 = {
  "-A": "GenericGroup", "-B": "BodyWithAttachmentGroup",
  "-C": "AttachmentGroup", "-H": "NonNativeBodyGroup",
  "-K": "ControllerIdxSigs", "-L": "WitnessIdxSigs",
  "-M": "NonTransReceiptCouples", "-N": "TransReceiptQuadruples",
  "-O": "FirstSeenReplayCouples", "-P": "PathedMaterialCouples",
  "-Q": "DigestSealSingles", "-R": "MerkleRootSealSingles",
  "-S": "SealSourceCouples", "-T": "SealSourceTriples",
  "-U": "SealSourceLastSingles", "-V": "BackerRegistrarSealCouples",
  "-W": "TypedDigestSealCouples", "-X": "TransIdxSigGroups",
  "-Y": "TransLastIdxSigGroups", "-Z": "ESSRPayloadGroup",
  "-a": "BlindedStateQuadruples", "-b": "BoundStateSextuples"
};
var QUADLET_GROUPS_V1 = { AttachmentGroup: true, PathedMaterialCouples: true,
                          GenericGroup: true, BodyWithAttachmentGroup: true };

// A counter at the start of text: { code, name, count, size, quadlets,
// genus }. A genus-version counter (-_AAA) switches the table.
function decodeCounter(text, gen) {
  log.debug("Entering decodeCounter().");
  if (text.slice(0, 5) === "-_AAA") {
    var v = text.slice(5, 8);
    log.debug("Leaving decodeCounter(). Genus version.");
    return { code: "-_AAA", name: "KERIACDCGenusVersion",
             major: B64.indexOf(v.charAt(0)), minor: b64ToInt(v.slice(1)),
             size: 8 };
  }
  var big = text.charAt(1) === "-" || (gen !== 2 && text.charAt(1) === "0");
  var code = big ? text.slice(0, 3) : text.slice(0, 2);
  var count = big ? b64ToInt(text.slice(3, 8)) : b64ToInt(text.slice(2, 4));
  var table = gen === 2 ? COUNTERS_V2 : COUNTERS_V1;
  var name = table[code] || (big ? table["-" + code.charAt(2)] : null);
  if (!name) {
    log.debug("Leaving decodeCounter(). Unknown.");
    throw new Error("attachment group " + code + " is not a CESR version " +
                    (gen === 2 ? 2 : 1) + " counter.");
  }
  log.debug("Leaving decodeCounter(). " + name);
  return { code: code, name: name, count: count, size: big ? 8 : 4,
           quadlets: gen === 2 || !!QUADLET_GROUPS_V1[name] };
}

// The code for a group of a generation.
var CODES_V1 = {};
var CODES_V2 = {};
Object.keys(COUNTERS_V1).forEach(function (c) {
  if (c.length === 2) {
    CODES_V1[COUNTERS_V1[c]] = c;
  }
});
Object.keys(COUNTERS_V2).forEach(function (c) {
  CODES_V2[COUNTERS_V2[c]] = c;
});

// A counter for `name` over `payload`: v1 counts `items` (or quadlets for a
// quadlet group), v2 counts quadlets. Answers the counter and the payload.
function group(name, payload, items, gen) {
  log.debug("Entering group(). " + name);
  var code = (gen === 2 ? CODES_V2 : CODES_V1)[name];
  if (!code) {
    log.debug("Leaving group(). No code.");
    throw new Error("no version " + gen + " counter for " + name + ".");
  }
  var quads = gen === 2 || QUADLET_GROUPS_V1[name];
  var count = quads ? payload.length / 4 : items;
  var out = count < 4096 ? code + intToB64(count, 2) + payload :
      "-" + code + intToB64(count, 5) + payload;
  log.debug("Leaving group().");
  return out;
}

function counter(code, count) {
  log.debug("Entering counter(). " + code);
  log.debug("Leaving counter().");
  return code + intToB64(count, 2);
}

// ---------------------------------------------------------------------------
// Attachments.
// ---------------------------------------------------------------------------

function emptyAttachments() {
  log.debug("Entering emptyAttachments().");
  log.debug("Leaving emptyAttachments().");
  return { sigs: [], witnessSigs: [], receipts: [], transReceipts: [],
           firstSeen: [], sourceSeals: [], sourceTriples: [],
           transSigGroups: [], transLastSigGroups: [], pathed: [],
           blindedStates: [], backerSeals: [], digestSeals: [] };
}

// The controller signatures nested in a -F/-X (or -H/-Y) group: a v1 -A##
// (items) or a v2 -K## (quadlets).
function readNestedSigs(text, p, gen) {
  log.debug("Entering readNestedSigs().");
  var c = decodeCounter(text.slice(p), gen);
  if (c.name !== "ControllerIdxSigs") {
    log.debug("Leaving readNestedSigs(). Not signatures.");
    throw new Error("a transferable signature group's signatures are a " +
                    (gen === 2 ? "-K" : "-A") + " group, not " + c.code + ".");
  }
  var at = p + c.size;
  var sigs = [];
  var stop = c.quadlets ? at + c.count * 4 : null;
  var n = 0;
  while (stop !== null ? at < stop : n < c.count) {
    var s = decodeIndexed(text.slice(at));
    sigs.push(s);
    at += s.size;
    n++;
  }
  log.debug("Leaving readNestedSigs().");
  return { sigs: sigs, end: at };
}

// One item of a group. Answers the position after it.
function readItem(name, text, p, gen, out) {
  log.debug("Entering readItem(). " + name);
  var a;
  var b;
  var c;
  var at = p;
  if (name === "ControllerIdxSigs" || name === "WitnessIdxSigs") {
    a = decodeIndexed(text.slice(at));
    (name === "ControllerIdxSigs" ? out.sigs : out.witnessSigs).push(a);
    at += a.size;
  } else if (name === "NonTransReceiptCouples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    out.receipts.push({ verkey: a.qb64, sig: b.raw, sigCode: b.code });
    at += a.size + b.size;
  } else if (name === "TransReceiptQuadruples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    c = decodeMatter(text.slice(at + a.size + b.size));
    var sg = decodeIndexed(text.slice(at + a.size + b.size + c.size));
    out.transReceipts.push({ i: a.qb64, s: ordinalOf(b), d: c.qb64,
                             sig: sg });
    at += a.size + b.size + c.size + sg.size;
  } else if (name === "FirstSeenReplayCouples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    out.firstSeen.push({ fn: ordinalOf(a), dt: b.qb64 });
    at += a.size + b.size;
  } else if (name === "SealSourceCouples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    out.sourceSeals.push({ s: ordinalOf(a), d: b.qb64 });
    at += a.size + b.size;
  } else if (name === "SealSourceTriples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    c = decodeMatter(text.slice(at + a.size + b.size));
    out.sourceTriples.push({ i: a.qb64, s: ordinalOf(b), d: c.qb64 });
    at += a.size + b.size + c.size;
  } else if (name === "TransIdxSigGroups") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    c = decodeMatter(text.slice(at + a.size + b.size));
    var ns = readNestedSigs(text, at + a.size + b.size + c.size, gen);
    out.transSigGroups.push({ i: a.qb64, s: ordinalOf(b), d: c.qb64,
                              sigs: ns.sigs });
    at = ns.end;
  } else if (name === "TransLastIdxSigGroups") {
    a = decodeMatter(text.slice(at));
    var nl = readNestedSigs(text, at + a.size, gen);
    out.transLastSigGroups.push({ i: a.qb64, sigs: nl.sigs });
    at = nl.end;
  } else if (name === "BlindedStateQuadruples") {
    var parts = [];
    for (var i = 0; i < 4; i++) {
      var m = decodeMatter(text.slice(at));
      parts.push(m);
      at += m.size;
    }
    out.blindedStates.push({ d: parts[0].qb64, u: parts[1].qb64,
                             td: parts[2].qb64, ts: parts[3].qb64,
                             tdValue: stringOf(parts[2]),
                             tsValue: stringOf(parts[3]) });
  } else if (name === "BackerRegistrarSealCouples") {
    a = decodeMatter(text.slice(at));
    b = decodeMatter(text.slice(at + a.size));
    out.backerSeals.push({ i: a.qb64, d: b.qb64 });
    at += a.size + b.size;
  } else if (name === "DigestSealSingles") {
    a = decodeMatter(text.slice(at));
    out.digestSeals.push({ d: a.qb64 });
    at += a.size;
  } else {
    log.debug("Leaving readItem(). Not read.");
    throw new Error("attachment group " + name + " is not read here.");
  }
  log.debug("Leaving readItem().");
  return at;
}

// Read attachment groups from text[pos, end) into out. gen is the table:
// 1 or 2, switched by a genus-version counter.
function readGroups(text, pos, end, out, gen) {
  log.debug("Entering readGroups().");
  var p = pos;
  var g = gen || 1;
  while (p < end && text.charAt(p) === "-") {
    var c = decodeCounter(text.slice(p), g);
    p += c.size;
    if (c.code === "-_AAA") {
      if (c.major !== 1 && c.major !== 2) {
        log.debug("Leaving readGroups(). Genus.");
        throw new Error("genus version " + c.major + "." + c.minor +
                        " is not KERI/ACDC 1.x or 2.x.");
      }
      g = c.major;
      out.genus = g;
      continue;
    }
    var stop = c.quadlets ? p + c.count * 4 : null;
    if (stop !== null && stop > end) {
      log.debug("Leaving readGroups(). Overrun.");
      throw new Error("group " + c.code + " counts past the attachments.");
    }
    if (c.name === "AttachmentGroup" || c.name === "GenericGroup") {
      p = readGroups(text, p, stop, out, g);
      if (p !== stop) {
        log.debug("Leaving readGroups(). Group size.");
        throw new Error("attachment group " + c.code + " does not end " +
                        "where its count says.");
      }
      continue;
    }
    if (c.name === "PathedMaterialCouples") {
      var pm = decodeMatter(text.slice(p));
      var inner = emptyAttachments();
      var q = readGroups(text, p + pm.size, stop, inner, g);
      if (q !== stop) {
        log.debug("Leaving readGroups(). Pathed size.");
        throw new Error("a pathed group does not end where its count says.");
      }
      out.pathed.push({ path: decodePath(pm), att: inner });
      p = stop;
      continue;
    }
    var n = 0;
    while (stop !== null ? p < stop : n < c.count) {
      p = readItem(c.name, text, p, g, out);
      n++;
    }
    if (stop !== null && p !== stop) {
      log.debug("Leaving readGroups(). Item size.");
      throw new Error("group " + c.code + " does not end where its count " +
                      "says.");
    }
  }
  log.debug("Leaving readGroups().");
  return p;
}

// ---------------------------------------------------------------------------
// Version strings.
// ---------------------------------------------------------------------------

var V1 = /^(KERI|ACDC)([0-9a-f])([0-9a-f])(JSON|CBOR|MGPK|CESR)([0-9a-f]{6})_$/;
var V2 = new RegExp("^(KERI|ACDC)([A-Za-z0-9_-])([A-Za-z0-9_-]{2})" +
                    "([A-Za-z0-9_-])([A-Za-z0-9_-]{2})(JSON|CBOR|MGPK|CESR)" +
                    "([A-Za-z0-9_-]{4})\\.$");

// v -> { proto, gen (1 or 2), major, minor, kind, size } or null.
function parseVersion(v) {
  log.debug("Entering parseVersion().");
  var s = String(v || "");
  var m = V1.exec(s);
  if (m) {
    log.debug("Leaving parseVersion(). v1.");
    return { proto: m[1], gen: 1, major: parseInt(m[2], 16),
             minor: parseInt(m[3], 16), kind: m[4],
             size: parseInt(m[5], 16) };
  }
  m = V2.exec(s);
  if (m) {
    log.debug("Leaving parseVersion(). v2.");
    return { proto: m[1], gen: 2, major: B64.indexOf(m[2]),
             minor: b64ToInt(m[3]), gmajor: B64.indexOf(m[4]),
             gminor: b64ToInt(m[5]), kind: m[6], size: b64ToInt(m[7]) };
  }
  log.debug("Leaving parseVersion(). None.");
  return null;
}

// proto ("KERI" / "ACDC"), body size, generation (1 or 2).
function versionString(proto, size, gen) {
  log.debug("Entering versionString().");
  if (gen === 2) {
    log.debug("Leaving versionString(). v2.");
    return proto + "CAACAAJSON" + intToB64(size, 4) + ".";
  }
  log.debug("Leaving versionString().");
  return proto + "10JSON" + ("000000" + size.toString(16)).slice(-6) + "_";
}

// The v string's size must be the body's byte length.
function checkVersionSize(raw, sad) {
  log.debug("Entering checkVersionSize().");
  var v = parseVersion(sad.v);
  if (!v) {
    log.debug("Leaving checkVersionSize(). None.");
    return "no version string.";
  }
  if (v.kind !== "JSON") {
    log.debug("Leaving checkVersionSize(). Kind.");
    return "a " + v.kind + " body: only JSON bodies are read here.";
  }
  if (v.gen === 2 && v.major !== 2) {
    log.debug("Leaving checkVersionSize(). Major.");
    return "protocol version " + v.major + " in a version 2 string.";
  }
  if (v.gen === 1 && v.major !== 1) {
    log.debug("Leaving checkVersionSize(). Major 1.");
    return "protocol version " + v.major + " in a version 1 string.";
  }
  log.debug("Leaving checkVersionSize().");
  return v.size === raw.length ? "" : "the version string says " + v.size +
    " bytes and the body is " + raw.length + ".";
}

// ---------------------------------------------------------------------------
// JSON over its bytes: a tree of value spans.
// ---------------------------------------------------------------------------

// The span tree of a JSON text: each node is { type ("object", "array",
// "string", "scalar"), start, end, members (object: key -> node), keys,
// items (array) }, in character offsets. A HOT PATH: it runs once per
// character of every body, so it logs at entry and exit only.
function jsonTree(text) {
  log.debug("Entering jsonTree().");
  var stack = [];
  var root = null;
  var i = 0;
  var n = text.length;
  while (i < n) {
    var c = text.charAt(i);
    if (c === " " || c === "\n" || c === "\r" || c === "\t" || c === ":" ||
        c === ",") {
      i++;
      continue;
    }
    var parent = stack.length ? stack[stack.length - 1] : null;
    if (c === "}" || c === "]") {
      stack.pop().end = i + 1;
      i++;
      if (!stack.length) {
        break;
      }
      continue;
    }
    var node;
    if (c === "{" || c === "[") {
      node = { type: c === "{" ? "object" : "array", start: i, end: -1,
               members: {}, keys: [], items: [], awaitKey: true };
      i++;
    } else if (c === "\"") {
      var s = i;
      i++;
      while (i < n && text.charAt(i) !== "\"") {
        if (text.charAt(i) === "\\") {
          i++;
        }
        i++;
      }
      i++;
      node = { type: "string", start: s, end: i };
    } else {
      var s2 = i;
      while (i < n && ",}] \n\r\t".indexOf(text.charAt(i)) === -1) {
        i++;
      }
      node = { type: "scalar", start: s2, end: i };
    }
    if (parent && parent.type === "object") {
      if (parent.awaitKey) {
        parent.lastKey = JSON.parse(text.slice(node.start, node.end));
        parent.awaitKey = false;
        continue;
      }
      parent.members[parent.lastKey] = node;
      parent.keys.push(parent.lastKey);
      parent.awaitKey = true;
    } else if (parent) {
      parent.items.push(node);
    } else if (!root) {
      root = node;
    }
    if (node.type === "object" || node.type === "array") {
      stack.push(node);
    }
  }
  if (stack.length || !root) {
    log.debug("Leaving jsonTree(). Unterminated.");
    throw new Error("the JSON body is not terminated.");
  }
  log.debug("Leaving jsonTree().");
  return root;
}

// The text of a string node, without its quotes.
function stringValue(text, node) {
  log.debug("Entering stringValue().");
  log.debug("Leaving stringValue().");
  return node && node.type === "string" ?
    JSON.parse(text.slice(node.start, node.end)) : null;
}

// ---------------------------------------------------------------------------
// SAIDs.
// ---------------------------------------------------------------------------

function digestOf(code, bytes) {
  log.debug("Entering digestOf(). " + code);
  var f = DIGESTS[code];
  if (!f) {
    log.debug("Leaving digestOf(). Code.");
    throw new Error("digest code " + code + " is not one used here (E " +
                    "Blake3-256, F Blake2b-256, G Blake2s-256, H SHA3-256, " +
                    "I SHA-256).");
  }
  log.debug("Leaving digestOf().");
  return encodeMatter(code, f(bytes));
}

function digestQb64(text, code) {
  log.debug("Entering digestQb64().");
  log.debug("Leaving digestQb64().");
  return digestOf(code || "E", cbytes.strBytes(text));
}

var DUMMY = repeat("#", 44);

// Does next-key digest `dig` commit to the key `qb64`? (KERI: the digest of
// the key's qb64 text, in the digest's own code.)
function commitsTo(dig, qb64) {
  log.debug("Entering commitsTo().");
  var ok = false;
  try {
    ok = digestQb64(qb64, dig.charAt(0)) === dig;
  } catch (e) {
    ok = false;
  }
  log.debug("Leaving commitsTo().");
  return ok;
}

// The SAID of `sad` (an object in protocol field order), with the saidive
// labels dummied and v sized: for issuing. Answers the finished object.
function saidify(sad, labels) {
  log.debug("Entering saidify().");
  var fields = labels || ["d"];
  var tmp = Object.assign({}, sad);
  fields.forEach(function (l) {
    tmp[l] = DUMMY;
  });
  if (tmp.v !== undefined) {
    var pv = parseVersion(tmp.v);
    var proto = String(tmp.v).slice(0, 4);
    var gen = pv ? pv.gen : 1;
    tmp.v = versionString(proto, 0, gen);
    tmp.v = versionString(proto, cbytes.strBytes(JSON.stringify(tmp)).length,
                          gen);
  }
  var said = digestQb64(JSON.stringify(tmp));
  var out = Object.assign({}, tmp);
  fields.forEach(function (l) {
    out[l] = said;
  });
  log.debug("Leaving saidify().");
  return out;
}

// The text of `node` within `text` with the string values of `labels`
// (members of that object) overwritten by '#'. Answers { masked, value }.
function maskLabels(text, node, labels) {
  log.debug("Entering maskLabels().");
  var sub = text.slice(node.start, node.end);
  var value = null;
  var spans = [];
  for (var i = 0; i < labels.length; i++) {
    var m = node.members[labels[i]];
    if (!m || m.type !== "string") {
      log.debug("Leaving maskLabels(). Missing.");
      return { reason: "there is no " + labels[i] + " to check." };
    }
    var v = text.slice(m.start + 1, m.end - 1);
    if (value !== null && v !== value) {
      log.debug("Leaving maskLabels(). Disagree.");
      return { reason: labels.join(" and ") + " must carry the same SAID." };
    }
    value = v;
    spans.push({ start: m.start + 1 - node.start, end: m.end - 1 -
                 node.start });
  }
  spans.sort(function (a, b) {
    return b.start - a.start;
  }).forEach(function (sp) {
    sub = sub.slice(0, sp.start) + repeat("#", sp.end - sp.start) +
      sub.slice(sp.end);
  });
  log.debug("Leaving maskLabels().");
  return { masked: sub, value: value };
}

// Check the SAID labels of a JSON body (or of the object `node` within it)
// over its bytes. Answers { ok, said, computed, reason }.
function checkSaid(raw, labels, node) {
  log.debug("Entering checkSaid().");
  var text = typeof raw === "string" ? raw : cbytes.bytesToStr(raw);
  var tree;
  try {
    tree = node || jsonTree(text);
  } catch (e) {
    log.debug("Leaving checkSaid(). Not JSON.");
    return { ok: false, reason: e.message };
  }
  var mk = maskLabels(text, tree, labels || ["d"]);
  if (mk.reason) {
    log.debug("Leaving checkSaid(). " + mk.reason);
    return { ok: false, reason: mk.reason };
  }
  var computed;
  try {
    computed = digestQb64(mk.masked, mk.value.charAt(0));
  } catch (e) {
    log.debug("Leaving checkSaid(). Digest code.");
    return { ok: false, said: mk.value, reason: "SAID " + mk.value + ": " +
             e.message };
  }
  log.debug("Leaving checkSaid().");
  return { ok: computed === mk.value, said: mk.value, computed: computed,
           reason: computed === mk.value ? "" : "the SAID " + mk.value +
             " is not the digest of these bytes (" + computed + ")." };
}

// ---------------------------------------------------------------------------
// The CESR stream: JSON bodies, each followed by its attachments.
// ---------------------------------------------------------------------------

var VS_HEAD = /"v"\s*:\s*"([A-Z]{4}[A-Za-z0-9_.-]{11,15})"/;

// Split a CESR stream (text) into messages: { raw (bytes of the body),
// text (the body as text), sad, version, att }. A body is JSON with a
// version string of either generation; its attachments are read with its
// generation's counter table unless a genus-version counter says otherwise.
function parseStream(input) {
  log.debug("Entering parseStream().");
  var text = (typeof input === "string" ? input : cbytes.bytesToStr(input))
    .trim();
  var bytes = cbytes.strBytes(text);
  var out = [];
  var b = 0;
  var genus = null;
  while (b < bytes.length) {
    var p = cbytes.bytesToStr(bytes.slice(0, b)).length;
    if (text.slice(p, p + 5) === "-_AAA") {
      var gc = decodeCounter(text.slice(p), 1);
      genus = gc.major;
      b += 8;
      continue;
    }
    if (bytes[b] !== 0x7b) {
      log.debug("Leaving parseStream(). Not a body.");
      throw new Error("expected a JSON body at byte " + b + ", found " +
        JSON.stringify(cbytes.bytesToStr(bytes.slice(b, b + 12))) + " (only " +
        "JSON bodies are read here, not CBOR, MessagePack or native CESR).");
    }
    var head = cbytes.bytesToStr(bytes.slice(b, b + 64));
    var m = VS_HEAD.exec(head);
    var version = m ? parseVersion(m[1]) : null;
    if (!version) {
      log.debug("Leaving parseStream(). No version string.");
      throw new Error("message " + (out.length + 1) + " has no version " +
                      "string.");
    }
    if (version.kind !== "JSON") {
      log.debug("Leaving parseStream(). Kind.");
      throw new Error("message " + (out.length + 1) + " is a " +
                      version.kind + " body; only JSON bodies are read here.");
    }
    var raw = bytes.slice(b, b + version.size);
    var bodyText = cbytes.bytesToStr(raw);
    var sad;
    try {
      sad = JSON.parse(bodyText);
    } catch (e) {
      log.debug("Leaving parseStream(). Bad JSON.");
      throw new Error("message " + (out.length + 1) + ": its version " +
                      "string's size does not frame a JSON body (" +
                      e.message + ").");
    }
    b += version.size;
    p = cbytes.bytesToStr(bytes.slice(0, b)).length;
    var rest = text.slice(p);
    var nextBody = rest.search(/\{/);
    var attText = nextBody === -1 ? rest : rest.slice(0, nextBody);
    var att = emptyAttachments();
    var used;
    try {
      used = readGroups(attText, 0, attText.length, att,
                        genus || version.gen);
    } catch (e) {
      log.debug("Leaving parseStream(). Attachments.");
      throw new Error("message " + (out.length + 1) + " (" +
                      (sad.t || "acdc") + "): " + e.message);
    }
    if (used !== attText.length && attText.slice(used, used + 5) !==
        "-_AAA") {
      log.debug("Leaving parseStream(). Unread attachments.");
      throw new Error("message " + (out.length + 1) + ": attachments not " +
        "understood from " + JSON.stringify(attText.slice(used, used + 8)) +
        ".");
    }
    b += cbytes.strBytes(attText.slice(0, used)).length;
    out.push({ raw: raw, text: bodyText, sad: sad, version: version,
               gen: version.gen, att: att });
  }
  log.debug("Leaving parseStream(). " + out.length + " messages.");
  return out;
}

// ---------------------------------------------------------------------------
// Field orders, per protocol and generation.
// ---------------------------------------------------------------------------

var KERI_FIELDS = {
  icp: "v,t,d,i,s,kt,k,nt,n,bt,b,c,a",
  rot: "v,t,d,i,s,p,kt,k,nt,n,bt,br,ba,a",
  ixn: "v,t,d,i,s,p,a",
  dip: "v,t,d,i,s,kt,k,nt,n,bt,b,c,a,di",
  drt: "v,t,d,i,s,p,kt,k,nt,n,bt,br,ba,a",
  rct: "v,t,d,i,s",
  vcp: "v,t,d,i,ii,s,c,bt,b,n",
  vrt: "v,t,d,i,p,s,bt,br,ba",
  iss: "v,t,d,i,s,ri,dt",
  rev: "v,t,d,i,s,ri,p,dt",
  bis: "v,t,d,i,ii,s,ra,dt",
  brv: "v,t,d,i,s,p,ra,dt",
  exn: "v,t,d,i,rp,p,dt,r,q,a,e"
};
var KERI_FIELDS_V2 = Object.assign({}, KERI_FIELDS, {
  rot: "v,t,d,i,s,p,kt,k,nt,n,bt,br,ba,c,a",
  drt: "v,t,d,i,s,p,kt,k,nt,n,bt,br,ba,c,a",
  exn: "v,t,d,i,ri,x,p,dt,r,q,a"
});
// ACDC v2 messages with fixed fields.
var ACDC_FIXED_V2 = {
  act: "v,t,d,u,i,rd,s,a,e,r",
  acg: "v,t,d,u,i,rd,s,A,e,r",
  rip: "v,t,d,u,i,n,dt",
  bup: "v,t,d,rd,n,p,dt,b",
  upd: "v,t,d,rd,n,p,dt,td,ts",
  sch: "v,t,d,s",
  att: "v,t,d,a",
  agg: "v,t,d,A",
  edg: "v,t,d,e",
  rul: "v,t,d,r"
};
var ACDC_MAP_V1 = "v,d,u,i,ri,s,a,A,e,r";
var ACDC_MAP_V2 = "v,t,d,u,i,rd,s,a,A,e,r";

function isAcdcCredential(sad, version) {
  log.debug("Entering isAcdcCredential().");
  var ok = version && version.proto === "ACDC" &&
      (!sad.t || sad.t === "acm" || sad.t === "act" || sad.t === "acg");
  log.debug("Leaving isAcdcCredential().");
  return !!ok;
}

function exactOrder(keys, want, what) {
  log.debug("Entering exactOrder().");
  var list = want.split(",");
  var same = keys.length === list.length && keys.every(function (k, i) {
    return k === list[i];
  });
  log.debug("Leaving exactOrder().");
  return same ? "" : "a " + what + " has exactly the fields " + want +
    " in that order; this has " + keys.join(",") + ".";
}

function fieldOrder(sad, version) {
  log.debug("Entering fieldOrder().");
  var keys = Object.keys(sad);
  var v = version || parseVersion(sad.v) || { proto: "KERI", gen: 1 };
  if (v.proto === "KERI") {
    var table = v.gen === 2 ? KERI_FIELDS_V2 : KERI_FIELDS;
    if (!table[sad.t]) {
      log.debug("Leaving fieldOrder(). Unknown ilk.");
      return "KERI message type " + JSON.stringify(sad.t) + " is not read " +
        "here.";
    }
    log.debug("Leaving fieldOrder(). KERI.");
    return exactOrder(keys, table[sad.t], sad.t);
  }
  if (v.gen === 2 && ACDC_FIXED_V2[sad.t]) {
    log.debug("Leaving fieldOrder(). ACDC fixed.");
    return exactOrder(keys, ACDC_FIXED_V2[sad.t], sad.t);
  }
  if (sad.t !== undefined && (v.gen !== 2 || sad.t !== "acm")) {
    log.debug("Leaving fieldOrder(). ACDC ilk.");
    return "ACDC message type " + JSON.stringify(sad.t) + " is not read " +
      "here in version " + v.gen + ".";
  }
  var want = (v.gen === 2 ? ACDC_MAP_V2 : ACDC_MAP_V1).split(",");
  var last = -1;
  for (var i = 0; i < keys.length; i++) {
    var at = want.indexOf(keys[i]);
    if (at <= last) {
      log.debug("Leaving fieldOrder(). ACDC order.");
      return "an ACDC's fields are " + want.join(",") + " in that order " +
        "(some optional); this has " + keys.join(",") + ".";
    }
    last = at;
  }
  if (sad.a !== undefined && sad.A !== undefined) {
    log.debug("Leaving fieldOrder(). a and A.");
    return "an ACDC has an attribute section a or an aggregate A, not both.";
  }
  log.debug("Leaving fieldOrder().");
  return ["v", "d", "i", "s"].every(function (k) {
    return keys.indexOf(k) !== -1;
  }) ? "" : "an ACDC needs v, d, i and s.";
}

function hexInt(s) {
  log.debug("Entering hexInt().");
  log.debug("Leaving hexInt().");
  return /^(0|[1-9a-f][0-9a-f]*)$/.test(String(s)) ? parseInt(s, 16) : NaN;
}

// The saidive labels of a message: d, and i too for a self-addressing
// inception (icp, dip, vcp).
function saidLabels(sad) {
  log.debug("Entering saidLabels().");
  var both = (sad.t === "icp" || sad.t === "dip" || sad.t === "vcp") &&
      sad.i === sad.d;
  log.debug("Leaving saidLabels().");
  return both ? ["d", "i"] : ["d"];
}

// A message's version, field order and SAID, over its bytes (an ACDC's
// through checkAcdcSaid, the v2 most compact form). Answers "" or the
// reason.
function checkBody(m) {
  log.debug("Entering checkBody().");
  var why = checkVersionSize(m.raw, m.sad) || fieldOrder(m.sad, m.version);
  if (why) {
    log.debug("Leaving checkBody(). " + why);
    return why;
  }
  if (m.sad.t === "rct") {
    log.debug("Leaving checkBody(). Receipt.");
    return "";
  }
  if (isAcdcCredential(m.sad, m.version)) {
    var ra = checkAcdcSaid(m);
    log.debug("Leaving checkBody(). ACDC.");
    return ra.ok ? "" : ra.problems[0];
  }
  var r = checkSaid(m.text, saidLabels(m.sad));
  log.debug("Leaving checkBody().");
  return r.ok ? "" : r.reason;
}

// ---------------------------------------------------------------------------
// Keys and signatures.
// ---------------------------------------------------------------------------

var KEY_ALGS = { D: "ed25519", B: "ed25519", "1AAB": "secp256k1",
                 "1AAA": "secp256k1", "1AAJ": "p256", "1AAI": "p256",
                 "1AAD": "ed448", "1AAC": "ed448" };
var NON_TRANSFERABLE = { B: true, "1AAA": true, "1AAI": true, "1AAC": true };
var CIGAR_ALGS = { "0B": "ed25519", "0C": "secp256k1", "0I": "p256",
                   "1AAE": "ed448" };

function verifyRaw(alg, pub, sig, msg) {
  log.debug("Entering verifyRaw(). " + alg);
  var ok = false;
  try {
    if (alg === "ed25519") {
      ok = nobleEd.ed25519.verify(sig, msg, pub);
    } else if (alg === "ed448") {
      ok = nobleEd448.ed448.verify(sig, msg, pub);
    } else if (alg === "secp256k1") {
      ok = nobleSecp.secp256k1.verify(sig, sha256(msg), pub);
    } else if (alg === "p256") {
      ok = nobleP256.p256.verify(sig, sha256(msg), pub);
    }
  } catch (e) {
    ok = false;
  }
  log.debug("Leaving verifyRaw(). " + ok);
  return ok;
}

// Does the indexed or plain signature `sig` (raw) by key qb64 `key` verify
// over `msg`?
function verifyWithKey(key, sig, msg, alg) {
  log.debug("Entering verifyWithKey().");
  var k;
  try {
    k = decodeMatter(key);
  } catch (e) {
    log.debug("Leaving verifyWithKey(). Bad key.");
    return false;
  }
  var kalg = KEY_ALGS[k.code];
  if (!kalg || (alg && alg !== kalg)) {
    log.debug("Leaving verifyWithKey(). Algorithm.");
    return false;
  }
  log.debug("Leaving verifyWithKey().");
  return verifyRaw(kalg, k.raw, sig, msg);
}

// A transferable Ed25519 signing key: { seed, verkey (qb64 D…) }. A
// non-transferable one (a witness or backer) has verkey B….
function keyFromSeed(seed, transferable) {
  log.debug("Entering keyFromSeed().");
  var s = cbytes.asBytes(seed);
  log.debug("Leaving keyFromSeed().");
  return { seed: s, verkey: encodeMatter(transferable === false ? "B" : "D",
    nobleEd.ed25519.getPublicKey(s)) };
}

function newKey(transferable) {
  log.debug("Entering newKey().");
  log.debug("Leaving newKey().");
  return keyFromSeed(cbytes.randomBytes(32), transferable);
}

function sign(key, msg) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return nobleEd.ed25519.sign(msg, key.seed);
}

// Is `seal` ({i, s, d}, a member of a KEL event's a) the seal of `want`?
function sealIs(seal, want) {
  log.debug("Entering sealIs().");
  var ok = !!seal && typeof seal === "object" && seal.i === want.i &&
      seal.s === want.s && seal.d === want.d &&
      Object.keys(seal).sort().join(",") === "d,i,s";
  log.debug("Leaving sealIs().");
  return ok;
}

// ---------------------------------------------------------------------------
// Key event logs: icp/dip, rot/drt, ixn, in either generation, with
// thresholds (numeric or weighted), next-key digests, witness receipts and
// delegation.
// ---------------------------------------------------------------------------

var KEL_ILKS = { icp: true, rot: true, ixn: true, dip: true, drt: true };

function receiptKey(i, s, d) {
  log.debug("Entering receiptKey().");
  log.debug("Leaving receiptKey().");
  return i + "|" + s + "|" + d;
}

// Witness receipts carried by rct messages anywhere in the stream.
function collectReceipts(messages) {
  log.debug("Entering collectReceipts().");
  var out = {};
  messages.forEach(function (m) {
    if (m.sad.t !== "rct" || checkVersionSize(m.raw, m.sad) ||
        fieldOrder(m.sad, m.version)) {
      return;
    }
    var k = receiptKey(m.sad.i, m.sad.s, m.sad.d);
    var r = out[k] || { wigers: [], couples: [] };
    r.wigers = r.wigers.concat(m.att.witnessSigs);
    r.couples = r.couples.concat(m.att.receipts);
    out[k] = r;
  });
  log.debug("Leaving collectReceipts().");
  return out;
}

// The distinct witnesses of `wits` whose receipts on m verify: indexed
// witness signatures (-B / -L) and non-transferable receipt couples (-C /
// -M), attached to the event or to an rct for it.
function witnessReceipts(m, wits, extra) {
  log.debug("Entering witnessReceipts().");
  var seen = {};
  var wigers = m.att.witnessSigs.concat(extra ? extra.wigers : []);
  wigers.forEach(function (s) {
    var key = wits[s.index];
    if (key && verifyWithKey(key, s.sig, m.raw, s.alg)) {
      seen[key] = true;
    }
  });
  var couples = m.att.receipts.concat(extra ? extra.couples : []);
  couples.forEach(function (c) {
    if (wits.indexOf(c.verkey) !== -1 &&
        verifyWithKey(c.verkey, c.sig, m.raw, CIGAR_ALGS[c.sigCode])) {
      seen[c.verkey] = true;
    }
  });
  log.debug("Leaving witnessReceipts().");
  return Object.keys(seen);
}

function unique(list) {
  log.debug("Entering unique().");
  var seen = {};
  var ok = list.every(function (x) {
    if (seen[x]) {
      return false;
    }
    seen[x] = true;
    return true;
  });
  log.debug("Leaving unique().");
  return ok;
}

// A witness or backer threshold against its list: 0 with none, otherwise
// between 1 and the list's length.
function checkToad(toad, list, what) {
  log.debug("Entering checkToad().");
  var label = what || "bt";
  var ok = !isNaN(toad) && (list.length === 0 ? toad === 0 :
                             toad >= 1 && toad <= list.length);
  log.debug("Leaving checkToad().");
  return ok ? "" : label + " " + toad + " is not valid for " + list.length +
    " witness(es).";
}

// The witness list after a rotation's cuts (br) and adds (ba).
function rotateList(list, cuts, adds, what) {
  log.debug("Entering rotateList().");
  var label = what || "witness";
  if (!Array.isArray(cuts) || !Array.isArray(adds) || !unique(cuts) ||
      !unique(adds)) {
    log.debug("Leaving rotateList(). Lists.");
    return { reason: "the " + label + " cuts and adds are lists without " +
             "duplicates." };
  }
  var bad = cuts.filter(function (c) {
    return list.indexOf(c) === -1;
  });
  if (bad.length) {
    log.debug("Leaving rotateList(). Cut.");
    return { reason: "cuts " + label + "(es) that are not current: " +
             bad.join(", ") + "." };
  }
  var clash = adds.filter(function (a) {
    return cuts.indexOf(a) !== -1 || list.indexOf(a) !== -1;
  });
  if (clash.length) {
    log.debug("Leaving rotateList(). Add.");
    return { reason: "adds " + label + "(es) that are current or cut: " +
             clash.join(", ") + "." };
  }
  var next = list.filter(function (w) {
    return cuts.indexOf(w) === -1;
  }).concat(adds);
  log.debug("Leaving rotateList().");
  return { list: next };
}

// Apply one key event to an identifier's state. Answers "" or the reason;
// on success the state is updated and the event recorded.
function applyEvent(state, m, ctx) {
  log.debug("Entering applyEvent().");
  var sad = m.sad;
  var t = sad.t;
  var why = checkBody(m);
  if (why) {
    log.debug("Leaving applyEvent(). Body.");
    return why;
  }
  var sn = hexInt(sad.s);
  if (isNaN(sn)) {
    log.debug("Leaving applyEvent(). s.");
    return "s " + JSON.stringify(sad.s) + " is not a hex sequence number.";
  }
  var est = t !== "ixn";
  var inception = t === "icp" || t === "dip";
  if (state.sn === -1 && !inception) {
    log.debug("Leaving applyEvent(). No inception.");
    return "the first event of a KEL is its inception.";
  }
  if (sn !== state.sn + 1) {
    log.debug("Leaving applyEvent(). Sequence.");
    return "sequence number " + sad.s + " follows " + state.sn +
      " (a gap, or duplicity).";
  }
  if (inception) {
    if (sn !== 0) {
      log.debug("Leaving applyEvent(). icp s.");
      return "an inception is sequence number 0.";
    }
    var selfAddressing = sad.i === sad.d;
    if (t === "dip" && !selfAddressing) {
      log.debug("Leaving applyEvent(). dip prefix.");
      return "a delegated identifier's prefix is self-addressing (i = d).";
    }
    if (!selfAddressing && (sad.k.length !== 1 || sad.k[0] !== sad.i)) {
      log.debug("Leaving applyEvent(). Basic.");
      return "a basic prefix is its single key.";
    }
    if (NON_TRANSFERABLE[decodeMatter(sad.i).code] &&
        (sad.n.length || sad.a.length || sad.b.length)) {
      log.debug("Leaving applyEvent(). Non-transferable.");
      return "a non-transferable identifier has no next keys, witnesses " +
        "or seals.";
    }
    state.prefix = sad.i;
    state.gen = m.gen;
  } else {
    if (sad.i !== state.prefix) {
      log.debug("Leaving applyEvent(). Prefix.");
      return "not this AID's event.";
    }
    if (sad.p !== state.last) {
      log.debug("Leaving applyEvent(). Prior.");
      return "p is not the previous event's SAID.";
    }
    if (!state.next.length) {
      log.debug("Leaving applyEvent(). Abandoned.");
      return "the identifier has no next keys (non-transferable or " +
        "abandoned): no event may follow.";
    }
    if (t === "ixn" && state.cnfg.indexOf("EO") !== -1) {
      log.debug("Leaving applyEvent(). EO.");
      return "the identifier is establishment-only (EO): no ixn.";
    }
    if (t === "rot" && state.delegator) {
      log.debug("Leaving applyEvent(). rot for delegated.");
      return "a delegated identifier rotates with drt, not rot.";
    }
    if (t === "drt" && !state.delegator) {
      log.debug("Leaving applyEvent(). drt.");
      return "a drt for an identifier that is not delegated.";
    }
  }
  var keys = est ? sad.k : state.keys;
  var kt;
  var nt;
  try {
    kt = est ? tholder.parse(sad.kt) : state.kt;
    nt = est ? tholder.parse(sad.nt) : state.nt;
  } catch (e) {
    log.debug("Leaving applyEvent(). Threshold.");
    return e.message;
  }
  if (est) {
    if (!Array.isArray(keys) || !keys.length || !unique(keys)) {
      log.debug("Leaving applyEvent(). Keys.");
      return "k is a non-empty list of distinct keys.";
    }
    why = tholder.checkAgainst(kt, keys.length, "kt") ||
      tholder.checkAgainst(nt, sad.n.length, "nt");
    if (why) {
      log.debug("Leaving applyEvent(). Threshold size.");
      return why;
    }
  }
  var verified = {};
  m.att.sigs.forEach(function (s) {
    var key = keys[s.index];
    if (key && verifyWithKey(key, s.sig, m.raw, s.alg)) {
      verified[s.index] = s;
    }
  });
  var indices = Object.keys(verified).map(Number);
  if (!tholder.satisfy(kt, indices)) {
    log.debug("Leaving applyEvent(). Signatures.");
    return indices.length + " verified signature(s) of the " +
      m.att.sigs.length + " attached do not satisfy kt " + kt.text + ".";
  }
  if (t === "rot" || t === "drt") {
    var ondices = [];
    indices.forEach(function (i) {
      var s = verified[i];
      if (s.ondex !== null && state.next[s.ondex] &&
          commitsTo(state.next[s.ondex], keys[i])) {
        ondices.push(s.ondex);
      }
    });
    if (!tholder.satisfy(state.nt, ondices)) {
      log.debug("Leaving applyEvent(). Prior next.");
      return "the rotated-in keys do not satisfy the prior next threshold " +
        "(" + state.nt.text + "): their digests are not the prior event's n.";
    }
  }
  var wits = state.wits;
  var toad = state.toad;
  if (inception) {
    wits = sad.b;
    toad = hexInt(sad.bt);
    if (!Array.isArray(wits) || !unique(wits)) {
      log.debug("Leaving applyEvent(). Witnesses.");
      return "b is a list of distinct witnesses.";
    }
  } else if (est) {
    var rl = rotateList(state.wits, sad.br, sad.ba);
    if (rl.reason) {
      log.debug("Leaving applyEvent(). Witness rotation.");
      return rl.reason;
    }
    wits = rl.list;
    toad = hexInt(sad.bt);
  }
  why = checkToad(toad, wits);
  if (why) {
    log.debug("Leaving applyEvent(). Toad.");
    return why;
  }
  var receipted = witnessReceipts(m, wits,
    ctx.receipts[receiptKey(sad.i, sad.s, sad.d)]);
  if (receipted.length < toad && !ctx.opts.unwitnessed) {
    log.debug("Leaving applyEvent(). Not fully witnessed.");
    return "only " + receipted.length + " of the " + toad + " witness " +
      "receipts bt requires verify: the event is not fully witnessed.";
  }
  var delegator = t === "dip" ? sad.di : state.delegator;
  var anchor = null;
  if (t === "dip" || t === "drt") {
    var ds = ctx.kevers[delegator];
    if (!ds || !ds.ok) {
      log.debug("Leaving applyEvent(). No delegator.");
      return "the delegator " + delegator + "'s KEL is not in the stream " +
        "ahead of this event" + (ds ? " (" + ds.reason + ")" : "") + ".";
    }
    if (ds.cnfg.indexOf("DND") !== -1) {
      log.debug("Leaving applyEvent(). DND.");
      return "the delegator " + delegator + " is do-not-delegate (DND).";
    }
    var want = { i: sad.i, s: sad.s, d: sad.d };
    var src = m.att.sourceSeals[0];
    var cands = ds.events.filter(function (e) {
      return !src || (e.sn === src.s && e.said === src.d);
    });
    cands.some(function (e) {
      if ((e.a || []).some(function (seal) {
        return sealIs(seal, want);
      })) {
        anchor = { sn: e.sn, said: e.said };
      }
      return !!anchor;
    });
    if (!anchor) {
      log.debug("Leaving applyEvent(). Not approved.");
      return "the delegator " + delegator + " has not anchored (approved) " +
        "this event" + (src ? ": its event " + src.s + " " + src.d +
        " carries no seal of it." : ".");
    }
  }
  if (est) {
    state.keys = keys;
    state.kt = kt;
    state.next = sad.n;
    state.nt = nt;
    state.cnfg = inception ? sad.c || [] : (sad.c || state.cnfg);
    state.estSn = sn;
    state.estSaid = sad.d;
  }
  state.wits = wits;
  state.toad = toad;
  state.delegator = delegator || null;
  state.sn = sn;
  state.last = sad.d;
  state.events.push({ sn: sn, said: sad.d, t: t, a: sad.a || [],
                      gen: m.gen, keys: keys, kt: kt, estSn: state.estSn,
                      wits: wits, toad: toad, verified: indices.length,
                      receipts: receipted.length, anchor: anchor });
  log.debug("Leaving applyEvent().");
  return "";
}

function newState() {
  log.debug("Entering newState().");
  log.debug("Leaving newState().");
  return { ok: false, prefix: null, events: [], keys: null, next: [],
           kt: null, nt: null, sn: -1, last: null, wits: [], toad: 0,
           cnfg: [], delegator: null, gen: null };
}

// One identifier's KEL messages, in order.
function processKel(msgs, ctx) {
  log.debug("Entering processKel().");
  var state = newState();
  for (var i = 0; i < msgs.length; i++) {
    var m = msgs[i];
    var prior = state.events[hexInt(m.sad.s)];
    if (prior && prior.said === m.sad.d) {
      continue;
    }
    if (prior) {
      state.reason = "KEL event " + m.sad.t + " " + m.sad.s + ": duplicity " +
        "— two different events at sequence number " + m.sad.s + ".";
      log.debug("Leaving processKel(). Duplicity.");
      return state;
    }
    var why;
    try {
      why = applyEvent(state, m, ctx);
    } catch (e) {
      why = e.message;
    }
    if (why) {
      state.reason = "KEL event " + m.sad.t + " " + m.sad.s + ": " + why;
      log.debug("Leaving processKel(). " + state.reason);
      return state;
    }
  }
  state.ok = !!state.prefix;
  if (!state.ok) {
    state.reason = "no inception event.";
  }
  log.debug("Leaving processKel(). " + state.ok);
  return state;
}

// Every KEL in the stream, delegators before their delegates. Answers
// { prefix: state }.
function processKels(messages, opts) {
  log.debug("Entering processKels().");
  var groups = {};
  var order = [];
  messages.forEach(function (m) {
    if (!KEL_ILKS[m.sad.t] || !m.version || m.version.proto !== "KERI") {
      return;
    }
    if (!groups[m.sad.i]) {
      groups[m.sad.i] = [];
      order.push(m.sad.i);
    }
    groups[m.sad.i].push(m);
  });
  var ctx = { kevers: {}, receipts: collectReceipts(messages),
              opts: opts || {} };
  var pending = order.slice();
  while (pending.length) {
    var progressed = false;
    for (var i = 0; i < pending.length; i++) {
      var pre = pending[i];
      var first = groups[pre][0].sad;
      var waits = first.t === "dip" && groups[first.di] &&
          !ctx.kevers[first.di];
      if (waits && pending.indexOf(first.di) !== -1) {
        continue;
      }
      ctx.kevers[pre] = processKel(groups[pre], ctx);
      pending.splice(i, 1);
      i--;
      progressed = true;
    }
    if (!progressed) {
      pending.forEach(function (p) {
        ctx.kevers[p] = processKel(groups[p], ctx);
      });
      pending = [];
    }
  }
  log.debug("Leaving processKels(). " + order.length + " identifiers.");
  return ctx.kevers;
}

// The issuer's KEL alone, as the old interface had it.
function verifyKel(messages, opts) {
  log.debug("Entering verifyKel().");
  var kevers = processKels(messages, opts);
  var first = messages.filter(function (m) {
    return KEL_ILKS[m.sad.t];
  })[0];
  var state = first ? kevers[first.sad.i] : null;
  log.debug("Leaving verifyKel().");
  return state || Object.assign(newState(), { reason: "no inception event." });
}

// The key state an identifier's KEL had at establishment event sn with SAID
// said: { keys, kt } or null.
function establishmentAt(kever, sn, said) {
  log.debug("Entering establishmentAt().");
  var e = kever && kever.events[sn];
  log.debug("Leaving establishmentAt().");
  return e && e.said === said && e.t !== "ixn" ? e : null;
}

// Signatures by an identifier's keys at one of its establishment events:
// a -F/-X group { i, s, d, sigs } (or a -H/-Y group, latest keys) over msg.
// Answers "" or the reason.
function checkTransSigs(kevers, groupSig, msg, last) {
  log.debug("Entering checkTransSigs().");
  var kever = kevers[groupSig.i];
  if (!kever || !kever.ok) {
    log.debug("Leaving checkTransSigs(). No KEL.");
    return "the signer " + groupSig.i + "'s KEL is not in the stream" +
      (kever ? " (" + kever.reason + ")" : "") + ".";
  }
  var est = last ? kever.events[kever.estSn] :
      establishmentAt(kever, groupSig.s, groupSig.d);
  if (!est) {
    log.debug("Leaving checkTransSigs(). No event.");
    return "the signer's establishment event " + groupSig.s + " " +
      groupSig.d + " is not in its verified KEL.";
  }
  var ok = [];
  groupSig.sigs.forEach(function (s) {
    if (est.keys[s.index] && verifyWithKey(est.keys[s.index], s.sig, msg,
                                           s.alg)) {
      ok.push(s.index);
    }
  });
  log.debug("Leaving checkTransSigs().");
  return tholder.satisfy(est.kt, ok) ? "" : ok.length + " verified " +
    "signature(s) do not satisfy the signer's threshold " + est.kt.text + ".";
}

// ---------------------------------------------------------------------------
// ACDC SAIDs: nested blocks, the aggregate, the most compact form.
// ---------------------------------------------------------------------------

// Does object node `node` have a SAID label at any depth (objects only)?
function hasSaidNode(node, label) {
  log.debug("Entering hasSaidNode().");
  var found = node.type === "object" && (!!node.members[label] ||
    node.keys.some(function (k) {
      return node.members[k].type === "object" &&
        hasSaidNode(node.members[k], label);
    }));
  log.debug("Leaving hasSaidNode().");
  return found;
}

// The block-level compact text of object node `node`: every nested block
// that has its own d is replaced by its SAID (computed over ITS compact
// text, recursively), blocks without one stay expanded with their own
// SAIDed children compacted. Built by splicing the received text. Answers
// { text, said (null when the block has no `label`) }; every block whose
// received SAID is not the one computed is pushed onto problems.
function compactNode(text, node, label, problems, path) {
  log.debug("Entering compactNode(). " + path);
  var out = "";
  var cursor = node.start;
  node.keys.forEach(function (k) {
    var child = node.members[k];
    if (child.type === "object" && hasSaidNode(child, "d")) {
      var r = compactNode(text, child, "d", problems, path + "." + k);
      out += text.slice(cursor, child.start) +
        (r.said !== null ? JSON.stringify(r.said) : r.text);
      cursor = child.end;
    }
  });
  out += text.slice(cursor, node.end);
  var said = null;
  if (node.members[label] && node.members[label].type === "string") {
    var received = stringValue(text, node.members[label]);
    var mk = maskLabels(out, jsonTree(out), [label]);
    try {
      said = digestQb64(mk.masked, received.charAt(0));
    } catch (e) {
      said = digestQb64(mk.masked, "E");
    }
    if (said !== received) {
      problems.push(path + "." + label + " " + received + " is not the " +
                    "SAID of that block (" + said + ")");
    }
  }
  log.debug("Leaving compactNode().");
  return { text: out, said: said };
}

// The AGID of an aggregate A = [AGID, block or block SAID, …]: the digest
// of the JSON list of the blocks' SAIDs with its own slot dummied. Each
// disclosed block is checked against its SAID over its bytes.
function aggregateId(text, arr, problems, path) {
  log.debug("Entering aggregateId().");
  if (arr.type !== "array" || !arr.items.length ||
      arr.items[0].type !== "string") {
    log.debug("Leaving aggregateId(). Shape.");
    problems.push(path + " is not a list whose first element is its AGID");
    return null;
  }
  var agid = stringValue(text, arr.items[0]);
  var saids = [repeat("#", agid.length)];
  for (var i = 1; i < arr.items.length; i++) {
    var item = arr.items[i];
    if (item.type === "string") {
      saids.push(stringValue(text, item));
    } else if (item.type === "object") {
      var r = checkSaid(text, ["d"], item);
      if (!r.ok) {
        problems.push(path + "[" + i + "]: " + r.reason);
      }
      saids.push(r.computed || r.said);
    } else {
      problems.push(path + "[" + i + "] is neither a block nor its SAID");
      saids.push("");
    }
  }
  var computed;
  try {
    computed = digestQb64(JSON.stringify(saids), agid.charAt(0));
  } catch (e) {
    computed = digestQb64(JSON.stringify(saids), "E");
  }
  if (computed !== agid) {
    problems.push(path + "[0], the AGID " + agid + ", is not the digest of " +
                  "its blocks' SAIDs (" + computed + ")");
  }
  log.debug("Leaving aggregateId().");
  return computed;
}

// Every nested block of a version 1 section that has a d, each over its own
// full bytes (version 1 does not compact).
function checkNestedV1(text, node, problems, path) {
  log.debug("Entering checkNestedV1(). " + path);
  if (node.type !== "object") {
    log.debug("Leaving checkNestedV1(). Not a block.");
    return;
  }
  if (node.members.d && node.members.d.type === "string") {
    var r = checkSaid(text, ["d"], node);
    if (!r.ok) {
      problems.push(path + ".d: " + r.reason);
    }
  }
  node.keys.forEach(function (k) {
    checkNestedV1(text, node.members[k], problems, path + "." + k);
  });
  log.debug("Leaving checkNestedV1().");
}

var SECTIONS = ["s", "a", "A", "e", "r"];

// The ACDC's top-level SAID and its sections' SAIDs, over the received
// bytes. Version 1: d over the full body as received, each nested block
// over its own bytes. Version 2: d over the MOST COMPACT FORM, which is
// spliced from the received bytes (each section replaced by its SAID, or
// the aggregate by its AGID; v re-sized for that form). Answers
// { ok, problems, compact, computed }.
function checkAcdcSaid(m) {
  log.debug("Entering checkAcdcSaid().");
  var problems = [];
  var tree = jsonTree(m.text);
  if (m.gen !== 2) {
    var top = checkSaid(m.text, ["d"], tree);
    if (!top.ok) {
      problems.push(top.reason);
    }
    SECTIONS.forEach(function (sec) {
      var node = tree.members[sec];
      if (!node) {
        return;
      }
      if (sec === "A") {
        aggregateId(m.text, node, problems, "A");
      } else if (sec === "s" && node.type === "object") {
        var rs = checkSaid(m.text, ["$id"], node);
        if (!rs.ok) {
          problems.push("s: " + rs.reason);
        }
      } else {
        checkNestedV1(m.text, node, problems, sec);
      }
    });
    log.debug("Leaving checkAcdcSaid(). v1.");
    return { ok: !problems.length, problems: problems,
             computed: top.computed };
  }
  var out = "";
  var cursor = tree.start;
  SECTIONS.forEach(function (sec) {
    var node = tree.members[sec];
    if (!node || node.type === "string") {
      return;
    }
    var repl;
    if (sec === "A") {
      var agid = aggregateId(m.text, node, problems, "A");
      repl = agid ? JSON.stringify(agid) : m.text.slice(node.start, node.end);
    } else if (sec === "s" && node.type === "object" && node.members.$id) {
      var rs = checkSaid(m.text, ["$id"], node);
      if (!rs.ok) {
        problems.push("s: " + rs.reason);
      }
      repl = JSON.stringify(rs.computed || rs.said);
    } else if (node.type === "object") {
      var r = compactNode(m.text, node, "d", problems, sec);
      repl = r.said !== null ? JSON.stringify(r.said) : r.text;
    } else {
      repl = m.text.slice(node.start, node.end);
    }
    out += m.text.slice(cursor, node.start) + repl;
    cursor = node.end;
  });
  out += m.text.slice(cursor, tree.end);
  var ctree = jsonTree(out);
  var vnode = ctree.members.v;
  var pv = parseVersion(m.sad.v);
  var sized = versionString(pv.proto, cbytes.strBytes(out).length, 2);
  out = out.slice(0, vnode.start + 1) + sized + out.slice(vnode.end - 1);
  var cs = checkSaid(out, ["d"]);
  if (!cs.ok) {
    problems.push("the top-level SAID over the most compact form: " +
                  cs.reason);
  }
  log.debug("Leaving checkAcdcSaid(). v2.");
  return { ok: !problems.length, problems: problems, compact: out,
           computed: cs.computed };
}

// ---------------------------------------------------------------------------
// Anchors: the seal of a TEL event in its issuer's KEL.
// ---------------------------------------------------------------------------

// Is a v1 registry event anchored, per its -G seal source couple, by an
// issuer KEL event whose a is EXACTLY ONE seal {i, s, d} of it, as keri-ts
// and keripy require? Answers "" or the reason.
function anchored(kel, message) {
  log.debug("Entering anchored().");
  var src = message.att.sourceSeals[0];
  if (!src) {
    log.debug("Leaving anchored(). No couple.");
    return "it carries no seal source couple (-G) naming its anchor.";
  }
  var ev = kel.events[src.s];
  if (!ev || ev.said !== src.d) {
    log.debug("Leaving anchored(). No such event.");
    return "its anchor, KEL event " + src.s + " " + src.d + ", is not in " +
      "the issuer's verified KEL.";
  }
  var sad = message.sad;
  var seals = ev.a || [];
  if (seals.length !== 1 || !sealIs(seals[0], { i: sad.i, s: sad.s,
                                                 d: sad.d })) {
    log.debug("Leaving anchored(). Seal.");
    return "KEL event " + src.s + "'s a is not exactly one seal {i, s, d} " +
      "of it (keri-ts and keripy require exactly one).";
  }
  log.debug("Leaving anchored().");
  return "";
}

// A v2 registry event's anchor: an issuer KEL event carrying the seal
// {i: the registry, s: its n, d: its SAID} (keri-ts matchesRegistrySeal),
// at the event its -S/-G couple names if it has one. Answers the event or
// null.
function registryAnchor(kel, message, regid) {
  log.debug("Entering registryAnchor().");
  var want = { i: regid, s: message.sad.n, d: message.sad.d };
  var src = message.att.sourceSeals[0];
  var found = null;
  kel.events.some(function (e) {
    if (src && (e.sn !== src.s || e.said !== src.d)) {
      return false;
    }
    if (e.a.some(function (seal) {
      return sealIs(seal, want);
    })) {
      found = e;
    }
    return !!found;
  });
  log.debug("Leaving registryAnchor().");
  return found;
}

// A credential issued without a registry: its SAID sealed directly in an
// issuer KEL event (a digest seal {d}, or an event seal naming it).
function directAnchor(kel, said) {
  log.debug("Entering directAnchor().");
  var found = null;
  kel.events.some(function (e) {
    if (e.a.some(function (seal) {
      return seal === said || (!!seal && typeof seal === "object" &&
                               seal.d === said);
    })) {
      found = e;
    }
    return !!found;
  });
  log.debug("Leaving directAnchor().");
  return found;
}

// Backer receipts (-B indexed signatures against the backer list) on a
// registry event: the distinct backers whose signatures verify.
function backerReceipts(m, baks) {
  log.debug("Entering backerReceipts().");
  log.debug("Leaving backerReceipts().");
  return witnessReceipts(m, baks, null);
}

// ---------------------------------------------------------------------------
// Registries (TELs).
// ---------------------------------------------------------------------------

// A version 1 registry (vcp, with its vrt rotations) and the credential's
// events in it: iss/rev in a no-backer (NB) registry, bis/brv in a backer
// registry. add(name, ok, detail) records each check. Answers { ok, revoked,
// reason }.
function verifyTelV1(ctx, acdcMsg, kel, add) {
  log.debug("Entering verifyTelV1().");
  var acdc = acdcMsg.sad;
  var fail = function (reason) {
    log.debug("Entering fail().");
    log.debug("Leaving fail(). Leaving verifyTelV1(). " + reason);
    return { ok: false, revoked: false, reason: reason };
  };
  var vcpMsg = ctx.messages.filter(function (m) {
    return m.sad.t === "vcp" && m.sad.i === acdc.ri;
  })[0];
  if (!vcpMsg) {
    add("the registry inception (vcp) is in the stream", false, "the " +
        "registry " + acdc.ri + " (vcp) is not in the stream.");
    return fail("the registry " + acdc.ri + " (vcp) is not in the stream.");
  }
  var vsad = vcpMsg.sad;
  var nb = Array.isArray(vsad.c) && vsad.c.indexOf("NB") !== -1;
  var why = checkBody(vcpMsg) || (vsad.ii !== acdc.i ? "ii is not the " +
    "ACDC's issuer." : "") || (vsad.s !== "0" ? "s is not 0." : "") ||
    (vsad.i !== vsad.d ? "i is not its SAID d." : "");
  var baks = Array.isArray(vsad.b) ? vsad.b : [];
  var toad = hexInt(vsad.bt);
  if (!why && nb && (baks.length || toad !== 0)) {
    why = "a no-backer (NB) registry has no backers and bt 0.";
  }
  if (!why && !nb) {
    why = (!unique(baks) ? "its backers repeat." : "") ||
      checkToad(toad, baks, "bt");
  }
  if (!add("the registry inception (vcp): SAID, issuer ii, s 0, " +
           (nb ? "no backers" : baks.length + " backers, bt " + vsad.bt),
           !why, why || acdc.ri)) {
    return fail("the registry inception does not verify: " + why);
  }
  var va = anchored(kel, vcpMsg);
  if (!add("the vcp is anchored in the issuer's KEL", !va, va)) {
    return fail(va);
  }
  // The registry's backer state at each of its events.
  var states = {};
  states["0|" + vsad.d] = { baks: baks, toad: toad };
  if (!nb) {
    var got = backerReceipts(vcpMsg, baks);
    if (!add("the vcp's backer receipts satisfy bt", got.length >= toad,
             got.length + " of " + toad)) {
      return fail("the vcp has " + got.length + " of the " + toad +
                  " backer receipts bt requires.");
    }
    var prior = vsad.d;
    var cur = { baks: baks, toad: toad };
    var vrts = ctx.messages.filter(function (m) {
      return m.sad.t === "vrt" && m.sad.i === acdc.ri;
    });
    for (var j = 0; j < vrts.length; j++) {
      var vr = vrts[j];
      var rl = rotateList(cur.baks, vr.sad.br, vr.sad.ba, "backer");
      var vt = hexInt(vr.sad.bt);
      var vwhy = checkBody(vr) || (vr.sad.p !== prior ? "p is not the " +
        "prior registry event." : "") || (hexInt(vr.sad.s) !== j + 1 ?
        "s is out of sequence." : "") || rl.reason ||
        checkToad(vt, rl.list || [], "bt") || anchored(kel, vr);
      var vgot = vwhy ? [] : backerReceipts(vr, rl.list);
      if (!vwhy && vgot.length < vt) {
        vwhy = vgot.length + " of the " + vt + " backer receipts.";
      }
      if (!add("registry rotation (vrt) " + vr.sad.s, !vwhy, vwhy)) {
        return fail("registry rotation " + vr.sad.s + ": " + vwhy);
      }
      cur = { baks: rl.list, toad: vt };
      states[hexInt(vr.sad.s) + "|" + vr.sad.d] = cur;
      prior = vr.sad.d;
    }
  }
  var tel = ctx.messages.filter(function (m) {
    return ["iss", "rev", "bis", "brv"].indexOf(m.sad.t) !== -1 &&
      m.sad.i === acdc.d;
  });
  var issIlk = nb ? "iss" : "bis";
  var revIlk = nb ? "rev" : "brv";
  var wrong = tel.filter(function (m) {
    return m.sad.t !== issIlk && m.sad.t !== revIlk;
  })[0];
  if (wrong) {
    add("the credential's events match the registry type", false, "a " +
        wrong.sad.t + " in a " + (nb ? "no-backer" : "backer") +
        " registry.");
    return fail("a " + wrong.sad.t + " is invalid in a " +
                (nb ? "no-backer" : "backer") + " registry.");
  }
  // The backer state a bis/brv names in its ra seal, and its receipts.
  var backed = function (m) {
    log.debug("Entering backed().");
    var ra = m.sad.ra || {};
    var st = states[hexInt(ra.s) + "|" + ra.d];
    if (ra.i !== acdc.ri || !st) {
      log.debug("Leaving backed(). No registry event.");
      return "its ra does not name an event of registry " + acdc.ri + ".";
    }
    var g = backerReceipts(m, st.baks);
    log.debug("Leaving backed().");
    return g.length >= st.toad ? "" : g.length + " of the " + st.toad +
      " backer receipts.";
  };
  var iss = tel.filter(function (m) {
    return m.sad.t === issIlk;
  })[0];
  if (!iss) {
    add("an issuance (" + issIlk + ") for the credential", false, "no " +
        issIlk + " for " + acdc.d + " in the stream.");
    return fail("no " + issIlk + " for " + acdc.d + " in the stream.");
  }
  var iwhy = checkBody(iss) || (iss.sad.s !== "0" ? "s is not 0." : "") ||
      (nb ? (iss.sad.ri !== acdc.ri ? "ri is not the ACDC's." : "") :
       (iss.sad.ii !== acdc.ri ? "ii is not the ACDC's registry." : "") ||
       backed(iss));
  if (!add("the issuance event (" + issIlk + "): SAID, s 0, registry" +
           (nb ? "" : ", backers"), !iwhy, iwhy || iss.sad.d)) {
    return fail("the issuance event does not verify: " + iwhy);
  }
  var ia = anchored(kel, iss);
  if (!add("the " + issIlk + " is anchored in the issuer's KEL", !ia, ia)) {
    return fail(ia);
  }
  var triple = acdcMsg.att.sourceTriples[0];
  var tok = !!triple && triple.i === acdc.d && triple.s === 0 &&
      triple.d === iss.sad.d;
  add("the ACDC's -I seal source triple names this " + issIlk, tok,
      tok ? "" : "the ACDC's attached triple does not name (its SAID, 0, " +
      "the " + issIlk + " SAID).");
  var rev = tel.filter(function (m) {
    return m.sad.t === revIlk;
  })[0];
  var revoked = false;
  if (rev) {
    var rwhy = checkBody(rev) || (rev.sad.p !== iss.sad.d ? "p is not the " +
      "issuance." : "") || (rev.sad.s !== "1" ? "s is not 1." : "") ||
      (nb ? (rev.sad.ri !== acdc.ri ? "ri is not the ACDC's." : "") :
       backed(rev)) || anchored(kel, rev);
    add("a revocation (" + revIlk + "), anchored", !rwhy, rwhy ?
        "a " + revIlk + " is present and does not verify: " + rwhy :
        "the credential is REVOKED");
    revoked = !rwhy;
  }
  log.debug("Leaving verifyTelV1().");
  return { ok: tok, revoked: revoked, reason: tok ? "" : "the -I triple." };
}

// The BLID of a blinded state block: the digest of its four CESR fields
// with its own SAID dummied (ACDC specification, blindable updates).
function blindedStateId(bs) {
  log.debug("Entering blindedStateId().");
  var code = bs.d.charAt(0);
  log.debug("Leaving blindedStateId().");
  return digestQb64(repeat("#", bs.d.length) + bs.u + bs.td + bs.ts, code);
}

// A version 2 registry (rip) and its updates (upd, bup), each anchored in
// the issuer's KEL by a seal {i: registry, s: n, d}. The credential's state
// is the last update that names it: an upd with td = its SAID, or a bup
// whose blinded state is disclosed in the stream. Answers { ok, revoked,
// state, reason }.
function verifyTelV2(ctx, acdcMsg, kel, add) {
  log.debug("Entering verifyTelV2().");
  var acdc = acdcMsg.sad;
  var fail = function (reason) {
    log.debug("Entering fail().");
    log.debug("Leaving fail(). Leaving verifyTelV2(). " + reason);
    return { ok: false, revoked: false, reason: reason };
  };
  var rip = ctx.messages.filter(function (m) {
    return m.sad.t === "rip" && m.sad.d === acdc.rd;
  })[0];
  if (!rip) {
    add("the registry inception (rip) is in the stream", false, "the " +
        "registry " + acdc.rd + " (rip) is not in the stream.");
    return fail("the registry " + acdc.rd + " (rip) is not in the stream.");
  }
  var why = checkBody(rip) || (rip.sad.i !== acdc.i ? "i is not the ACDC's " +
    "issuer." : "") || (rip.sad.n !== "0" ? "n is not 0." : "");
  if (!add("the registry inception (rip): SAID, issuer i, n 0", !why,
           why || acdc.rd)) {
    return fail("the registry inception does not verify: " + why);
  }
  var ra = registryAnchor(kel, rip, acdc.rd);
  if (!add("the rip is anchored in the issuer's KEL", !!ra, ra ? "event " +
           ra.sn : "no issuer KEL event carries the seal {i, s, d} of it.")) {
    return fail("the rip is not anchored.");
  }
  var blinded = [];
  ctx.messages.forEach(function (m) {
    blinded = blinded.concat(m.att.blindedStates);
  });
  var updates = ctx.messages.filter(function (m) {
    return (m.sad.t === "upd" || m.sad.t === "bup") && m.sad.rd === acdc.rd;
  }).sort(function (a, b) {
    return hexInt(a.sad.n) - hexInt(b.sad.n);
  });
  var prior = rip.sad.d;
  var state = null;
  for (var i = 0; i < updates.length; i++) {
    var u = updates[i];
    var uwhy = checkBody(u) || (hexInt(u.sad.n) !== i + 1 ? "n " + u.sad.n +
      " is out of sequence." : "") || (u.sad.p !== prior ? "p is not the " +
      "prior registry event." : "") || (registryAnchor(kel, u, acdc.rd) ?
      "" : "no issuer KEL event carries the seal {i, s, d} of it.");
    if (!add("registry update (" + u.sad.t + ") " + u.sad.n, !uwhy, uwhy ||
             (u.sad.t === "upd" ? u.sad.ts + " " + u.sad.td : "blinded " +
              u.sad.b))) {
      return fail("registry update " + u.sad.n + ": " + uwhy);
    }
    prior = u.sad.d;
    if (u.sad.t === "upd" && u.sad.td === acdc.d) {
      state = u.sad.ts;
    } else if (u.sad.t === "bup") {
      var bs = blinded.filter(function (x) {
        return x.d === u.sad.b;
      })[0];
      if (bs) {
        var ok = blindedStateId(bs) === bs.d;
        add("the blinded state of bup " + u.sad.n + " is disclosed", ok,
            ok ? (bs.tsValue || "(empty)") + " " + (bs.tdValue || "(empty)") :
            "its BLID " + bs.d + " is not the digest of its fields.");
        if (ok && bs.tdValue === acdc.d) {
          state = bs.tsValue;
        }
      }
    }
  }
  if (!add("the registry names this credential", state !== null, state ?
           "state " + state : "no update in registry " + acdc.rd +
           " names " + acdc.d + " (nor discloses a blinded state for it).")) {
    return fail("no registry update names the credential.");
  }
  var revoked = state === "revoked";
  if (!revoked && state !== "issued") {
    add("the credential's registry state", false, "state " + state +
        " is neither issued nor revoked.");
    return fail("registry state " + state + ".");
  }
  if (revoked) {
    add("a revocation in the registry", true, "the credential is REVOKED");
  }
  log.debug("Leaving verifyTelV2().");
  return { ok: true, revoked: revoked, state: state, reason: "" };
}

// ---------------------------------------------------------------------------
// Schemas.
// ---------------------------------------------------------------------------

// A schema as given: an object, or its JSON text (whose $id is then checked
// over its bytes). Answers { obj, text } or throws.
function readSchema(s) {
  log.debug("Entering readSchema().");
  if (typeof s === "string") {
    log.debug("Leaving readSchema(). Text.");
    return { obj: JSON.parse(s), text: s.trim() };
  }
  log.debug("Leaving readSchema(). Object.");
  return { obj: s, text: JSON.stringify(s) };
}

// The schema an ACDC's s names (a SAID, or the schema section itself in a
// v2 ACDC), checked: its $id is its own SAID, and the credential as
// presented validates against it.
function checkSchema(acdc, schemas, add) {
  log.debug("Entering checkSchema().");
  var want = typeof acdc.s === "string" ? acdc.s :
      (acdc.s && acdc.s.$id) || null;
  var found = null;
  schemas.forEach(function (s) {
    if (!found && s.obj && s.obj.$id === want) {
      found = s;
    }
  });
  if (!found && acdc.s && typeof acdc.s === "object") {
    found = { obj: acdc.s, text: JSON.stringify(acdc.s) };
  }
  if (!found) {
    if (schemas.length) {
      add("the ACDC names a schema given", false, "s is " + want + "; no " +
          "schema given has that $id.");
    }
    log.debug("Leaving checkSchema(). None.");
    return;
  }
  var r = checkSaid(found.text, ["$id"]);
  add("the schema's $id is its SAID", r.ok, r.ok ? r.said : r.reason);
  var v = acdcSchema.validate(found.obj, acdc);
  add("the credential validates against its schema (JSON Schema " +
      (v.dialect === "2020-12" ? "2020-12" : "draft-07") + ")", v.valid,
      v.reason);
  log.debug("Leaving checkSchema().");
}

// ---------------------------------------------------------------------------
// Edges: chained credentials.
// ---------------------------------------------------------------------------

var EDGE_RESERVED = ["d", "u", "n", "s", "o", "w"];
var MAX_DEPTH = 8;

// The issuee of an ACDC (a.i), or null; "?" when the attribute section is
// not disclosed.
function issueeOf(acdc) {
  log.debug("Entering issueeOf().");
  var out = acdc.a && typeof acdc.a === "object" ? acdc.a.i || null :
      typeof acdc.a === "string" ? "?" : null;
  log.debug("Leaving issueeOf().");
  return out;
}

// Is `aid` delegated (directly or through a chain) by `by`?
function delegatedBy(kevers, aid, by) {
  log.debug("Entering delegatedBy().");
  var seen = {};
  var k = kevers[aid];
  while (k && k.delegator && !seen[k.prefix]) {
    seen[k.prefix] = true;
    if (k.delegator === by) {
      log.debug("Leaving delegatedBy(). Yes.");
      return true;
    }
    k = kevers[k.delegator];
  }
  log.debug("Leaving delegatedBy(). No.");
  return false;
}

// One edge: its far node, verified recursively, under its unary operators.
// Answers { valid, detail }.
function evalEdge(ctx, near, label, edge, depth, seen) {
  log.debug("Entering evalEdge(). " + label);
  var e = typeof edge === "string" ? { n: edge } : edge;
  var farMsg = ctx.acdcs[e.n];
  if (!farMsg) {
    log.debug("Leaving evalEdge(). No far node.");
    return { valid: false, detail: label + ": the far node " + e.n +
             " is not in the stream" + (typeof edge === "string" ?
             " (a compact edge whose block is not disclosed, or a simple " +
             "compact edge to a credential that is not presented)" : "") };
  }
  var far = farMsg.sad;
  var ops = e.o === undefined ? [] : Array.isArray(e.o) ? e.o : [e.o];
  var issuerOp = null;
  var not = false;
  for (var i = 0; i < ops.length; i++) {
    if (ops[i] === "I2I" || ops[i] === "NI2I" || ops[i] === "DI2I") {
      issuerOp = ops[i];
    } else if (ops[i] === "NOT") {
      not = true;
    } else {
      log.debug("Leaving evalEdge(). Operator.");
      return { valid: false, detail: label + ": unary operator " +
               JSON.stringify(ops[i]) + " is not an edge operator (I2I, " +
               "NI2I, DI2I, NOT)." };
    }
  }
  var issuee = issueeOf(far);
  if (!issuerOp) {
    issuerOp = issuee ? "I2I" : "NI2I";
  }
  var r = verifyCredential(ctx, farMsg, depth + 1, seen);
  var farValid = r.valid;
  var why = r.valid ? "" : (r.revoked ? "REVOKED" : r.reason);
  var schemaOk = !e.s || e.s === (typeof far.s === "string" ? far.s :
                                   far.s && far.s.$id);
  var issuerOk = true;
  var iwhy = "";
  if (issuerOp === "I2I" || issuerOp === "DI2I") {
    if (!issuee) {
      issuerOk = false;
      iwhy = issuerOp + " needs a targeted far node, and it has no issuee";
    } else if (issuee === "?") {
      issuerOk = false;
      iwhy = issuerOp + ": the far node's attributes are not disclosed";
    } else if (issuee !== near.i && !(issuerOp === "DI2I" &&
               delegatedBy(ctx.kevers, near.i, issuee))) {
      issuerOk = false;
      iwhy = issuerOp + ": this credential's issuer " + near.i + " is not " +
        "the far node's issuee " + issuee + (issuerOp === "DI2I" ?
        " nor delegated by it" : "");
    }
  }
  var nodeValid = not ? !farValid : farValid;
  var valid = nodeValid && schemaOk && issuerOk;
  var detail = label + " -> " + e.n + " (" + issuerOp + (not ? ", NOT" :
    "") + "): far node " + (farValid ? "valid" : "invalid (" + why + ")") +
    (schemaOk ? "" : "; its schema " + far.s + " is not the edge's s " +
     e.s) + (iwhy ? "; " + iwhy : "");
  log.debug("Leaving evalEdge(). " + valid);
  return { valid: valid, detail: detail, far: r };
}

// An edge-group (the e section, or a group nested in it) under its m-ary
// operator: AND (the default), OR, NAND, NOR. Answers { valid, details }.
function evalGroup(ctx, near, group, depth, seen, path) {
  log.debug("Entering evalGroup(). " + path);
  var op = group.o === undefined ? "AND" : group.o;
  if (["AND", "OR", "NAND", "NOR"].indexOf(op) === -1) {
    log.debug("Leaving evalGroup(). Operator.");
    return { valid: false, details: [path + ": edge-group operator " +
             JSON.stringify(op) + (op === "AVG" || op === "WAVG" ?
             " averages a property its schema or governance framework " +
             "defines; it is not a validity operator, so it is not " +
             "evaluated here." : " is not an edge-group operator.")] };
  }
  var details = [];
  var results = [];
  Object.keys(group).forEach(function (label) {
    if (EDGE_RESERVED.indexOf(label) !== -1) {
      return;
    }
    var v = group[label];
    var r;
    if (v && typeof v === "object" && v.n === undefined) {
      r = evalGroup(ctx, near, v, depth, seen, path + "." + label);
      details = details.concat(r.details);
    } else {
      r = evalEdge(ctx, near, path + "." + label, v, depth, seen);
      details.push((r.valid ? "valid: " : "INVALID: ") + r.detail);
    }
    results.push(r.valid);
  });
  var all = results.every(Boolean);
  var any = results.some(Boolean);
  var valid = op === "AND" ? all : op === "OR" ? any : op === "NAND" ?
      !all : !any;
  if (!results.length) {
    valid = true;
  }
  log.debug("Leaving evalGroup(). " + valid);
  return { valid: valid, details: details, op: op };
}

// ---------------------------------------------------------------------------
// Verification of a credential and of a presentation.
// ---------------------------------------------------------------------------

// Verify one ACDC message of the stream against the stream's KELs and
// registries, recursively through its edges. Answers { valid, revoked,
// reason, checks, acdc, edges }.
function verifyCredential(ctx, acdcMsg, depth, seen) {
  log.debug("Entering verifyCredential().");
  var checks = [];
  var add = function (name, ok, detail) {
    log.debug("Entering add(). " + name);
    checks.push({ name: name, ok: ok, detail: detail || "" });
    log.debug("Leaving add(). " + ok);
    return ok;
  };
  var acdc = acdcMsg.sad;
  var out = { valid: false, revoked: false, checks: checks, acdc: acdc,
              gen: acdcMsg.gen };
  var finish = function (reason) {
    log.debug("Entering finish().");
    out.reason = reason;
    log.debug("Leaving finish(). Leaving verifyCredential(). " + reason);
    return out;
  };
  if (seen[acdc.d]) {
    return finish("a cycle of edges returns to " + acdc.d + ".");
  }
  if (depth > MAX_DEPTH) {
    return finish("the chain of edges is deeper than " + MAX_DEPTH + ".");
  }
  var seenHere = Object.assign({}, seen);
  seenHere[acdc.d] = true;
  var kel = ctx.kevers[acdc.i];
  if (!add("the issuer's KEL verifies (signatures, thresholds, chaining, " +
           "witnesses, delegation)", !!kel && kel.ok, kel ? (kel.ok ?
           kel.events.length + " events, prefix " + kel.prefix +
           (kel.delegator ? ", delegated by " + kel.delegator : "") :
           kel.reason) : "the issuer " + acdc.i + "'s KEL is not in the " +
           "stream.")) {
    return finish(kel ? kel.reason : "the issuer's KEL is not in the " +
                  "stream.");
  }
  var why = checkVersionSize(acdcMsg.raw, acdc) ||
      fieldOrder(acdc, acdcMsg.version);
  if (!add("the ACDC's version string and field order (version " +
           acdcMsg.gen + (acdc.t ? ", " + acdc.t : "") + ")", !why, why)) {
    return finish(why);
  }
  var said = checkAcdcSaid(acdcMsg);
  if (!add(acdcMsg.gen === 2 ? "the ACDC's SAID is the digest of its most " +
           "compact form, and its sections' SAIDs" : "the ACDC's SAID is " +
           "its bytes' digest, and its sections' SAIDs", said.ok,
           said.ok ? acdc.d : said.problems.join("; "))) {
    return finish(said.problems[0]);
  }
  if (acdc.A !== undefined) {
    var disclosed = Array.isArray(acdc.A) ? acdc.A.slice(1).filter(
      function (x) {
        return x && typeof x === "object";
      }).length : 0;
    add("the aggregate (A): AGID over its blocks", true,
        Array.isArray(acdc.A) ? disclosed + " of " + (acdc.A.length - 1) +
        " blocks disclosed" : "compact: " + acdc.A);
  }
  var reg = acdcMsg.gen === 2 ? acdc.rd : acdc.ri;
  var tel;
  if (reg) {
    tel = acdcMsg.gen === 2 ? verifyTelV2(ctx, acdcMsg, kel, add) :
      verifyTelV1(ctx, acdcMsg, kel, add);
  } else {
    var da = directAnchor(kel, acdc.d);
    add("issued directly: the issuer's KEL seals the ACDC's SAID", !!da,
        da ? "event " + da.sn : "no registry, and no issuer KEL event " +
        "carries a seal of " + acdc.d + ".");
    tel = { ok: !!da, revoked: false };
  }
  out.revoked = !!tel.revoked;
  checkSchema(acdc, ctx.schemas, add);
  if (acdc.e !== undefined) {
    if (typeof acdc.e === "string") {
      add("the edges (e)", false, "the edge section is compact (" + acdc.e +
          "): its far nodes cannot be verified until it is disclosed.");
    } else {
      var eg = evalGroup(ctx, acdc, acdc.e, depth, seenHere, "e");
      out.edges = eg;
      add("the edges (e" + (eg.op && eg.op !== "AND" ? ", " + eg.op : "") +
          "): every far node verified, operators applied", eg.valid,
          eg.details.join(" | "));
    }
  }
  out.valid = checks.every(function (c) {
    return c.ok;
  }) && tel.ok && !out.revoked;
  out.reason = out.valid ? "" : out.revoked ? "the credential is revoked." :
      (checks.filter(function (c) {
        return !c.ok;
      }).map(function (c) {
        return c.name + ": " + c.detail;
      })[0] || tel.reason);
  log.debug("Leaving verifyCredential(). " + out.valid);
  return out;
}

// The verification context of a parsed stream.
function makeContext(messages, opts) {
  log.debug("Entering makeContext().");
  var o = opts || {};
  var acdcs = {};
  messages.forEach(function (m) {
    if (isAcdcCredential(m.sad, m.version) && m.sad.d) {
      acdcs[m.sad.d] = m;
    }
  });
  var schemas = [];
  (o.schemas || []).concat(o.schema ? [o.schema] : []).forEach(function (s) {
    try {
      schemas.push(readSchema(s));
    } catch (e) {
      schemas.push({ obj: null, text: "", error: e.message });
    }
  });
  log.debug("Leaving makeContext().");
  return { messages: messages, kevers: processKels(messages, o),
           acdcs: acdcs, schemas: schemas, opts: o };
}

// A whole presentation stream: the KELs (the issuer's, its delegators',
// those of chained credentials' issuers), registries, the credential and
// any credentials its edges chain to. opts: { said (which ACDC; the last
// one otherwise), schema / schemas (objects or JSON texts), unwitnessed
// (accept events short of their witness threshold) }. Answers { valid,
// revoked, reason, checks: [{ name, ok, detail }], acdc, issuer, kel,
// kevers, edges }.
function verifyPresentation(input, opts) {
  log.debug("Entering verifyPresentation().");
  var o = opts || {};
  var out = { valid: false, revoked: false, checks: [] };
  var messages;
  try {
    messages = typeof input === "string" || input instanceof Uint8Array ?
      parseStream(input) : input;
  } catch (e) {
    out.checks.push({ name: "the CESR stream parses", ok: false,
                      detail: e.message });
    out.reason = e.message;
    log.debug("Leaving verifyPresentation(). Unparseable.");
    return out;
  }
  var ctx = makeContext(messages, o);
  var credentials = messages.filter(function (m) {
    return isAcdcCredential(m.sad, m.version);
  });
  var target = o.said ? ctx.acdcs[o.said] : credentials[credentials.length -
                                                        1];
  var parsed = { name: "the CESR stream parses", ok: true,
                 detail: messages.length + " messages" };
  if (!target) {
    out.checks.push(parsed);
    out.reason = o.said ? "the stream carries no ACDC " + o.said + "." :
      "the stream carries no ACDC.";
    log.debug("Leaving verifyPresentation(). No ACDC.");
    return out;
  }
  var r = verifyCredential(ctx, target, 0, {});
  r.checks.unshift(parsed);
  r.issuer = target.sad.i;
  r.kel = ctx.kevers[target.sad.i] || null;
  r.kevers = ctx.kevers;
  log.debug("Leaving verifyPresentation(). " + r.valid);
  return r;
}

// ---------------------------------------------------------------------------
// IPEX: exchange (exn) messages — a grant carrying a credential.
// ---------------------------------------------------------------------------

// A message made from an embed's span within an exn body: its own bytes,
// with the attachments of the pathed group whose path names it.
function embedMessage(exnMsg, node, path) {
  log.debug("Entering embedMessage(). " + path.join("."));
  var text = exnMsg.text.slice(node.start, node.end);
  var sad = JSON.parse(text);
  var pathed = exnMsg.att.pathed.filter(function (p) {
    return p.path.join(".") === path.join(".");
  })[0];
  var version = parseVersion(sad.v);
  log.debug("Leaving embedMessage().");
  return { raw: cbytes.strBytes(text), text: text, sad: sad,
           version: version, gen: version ? version.gen : 1,
           att: pathed ? pathed.att : emptyAttachments(), embedded: true };
}

// Verify an exchange message — by default the last IPEX grant in the
// stream: its SAID, the sender's signature against the sender's KEL (which
// must be in the stream), its embeds' SAIDs (e.d over the e block), and the
// credential it grants, verified from the embeds and the rest of the
// stream exactly as a presentation is. opts as verifyPresentation, plus
// { said (which exn) }. Answers { valid, reason, checks, exn, credential }.
function verifyExchange(input, opts) {
  log.debug("Entering verifyExchange().");
  var o = opts || {};
  var checks = [];
  var add = function (name, ok, detail) {
    log.debug("Entering add(). " + name);
    checks.push({ name: name, ok: ok, detail: detail || "" });
    log.debug("Leaving add(). " + ok);
    return ok;
  };
  var out = { valid: false, checks: checks };
  var finish = function (reason) {
    log.debug("Entering finish().");
    out.reason = reason;
    log.debug("Leaving finish(). Leaving verifyExchange(). " + reason);
    return out;
  };
  var messages;
  try {
    messages = parseStream(input);
  } catch (e) {
    add("the CESR stream parses", false, e.message);
    return finish(e.message);
  }
  add("the CESR stream parses", true, messages.length + " messages");
  var exns = messages.filter(function (m) {
    return m.sad.t === "exn" && (o.said ? m.sad.d === o.said :
                                 m.sad.r === "/ipex/grant");
  });
  var exn = exns[exns.length - 1];
  if (!exn) {
    return finish("the stream carries no " + (o.said ? "exn " + o.said :
                  "IPEX grant (an exn with r /ipex/grant)") + ".");
  }
  out.exn = exn.sad;
  var why = checkBody(exn);
  if (!add("the exn's version string, field order and SAID (version " +
           exn.gen + ", route " + exn.sad.r + ")", !why, why || exn.sad.d)) {
    return finish(why);
  }
  var kevers = processKels(messages, o);
  var tsg = exn.att.transSigGroups[0] || exn.att.transLastSigGroups[0];
  var swhy = !tsg ? "it carries no transferable signature group (-F / -X)." :
      tsg.i !== exn.sad.i ? "the signature group is " + tsg.i + "'s, not " +
      "the sender's." : checkTransSigs(kevers, tsg, exn.raw,
                                       !exn.att.transSigGroups[0]);
  if (!add("the sender " + exn.sad.i + "'s signature, against its KEL",
           !swhy, swhy)) {
    return finish(swhy);
  }
  var tree = jsonTree(exn.text);
  var eNode = exn.gen === 2 ? (tree.members.a && tree.members.a.members.e) :
      tree.members.e;
  var embeds = [];
  if (eNode && eNode.type === "object" && eNode.keys.length) {
    var es = checkSaid(exn.text, ["d"], eNode);
    if (!add("the embeds' SAID (e.d over the e block)", es.ok, es.ok ?
             es.said : es.reason)) {
      return finish(es.reason);
    }
    var base = exn.gen === 2 ? ["a", "e"] : ["e"];
    eNode.keys.forEach(function (k) {
      if (k !== "d" && eNode.members[k].type === "object") {
        embeds.push({ label: k, msg: embedMessage(exn, eNode.members[k],
                                                  base.concat([k])) });
      }
    });
    embeds.forEach(function (em) {
      var b = isAcdcCredential(em.msg.sad, em.msg.version) ?
          (checkVersionSize(em.msg.raw, em.msg.sad) ||
           fieldOrder(em.msg.sad, em.msg.version)) : checkBody(em.msg);
      add("embed e." + em.label + " (" + (em.msg.sad.t || "acdc") + ")",
          !b, b || em.msg.sad.d);
    });
  }
  var recipient = exn.gen === 2 ? exn.sad.ri ||
      (exn.sad.a && exn.sad.a.i) : (exn.sad.a && exn.sad.a.i) || exn.sad.rp;
  var acdcEmbed = embeds.filter(function (em) {
    return em.label === "acdc";
  })[0];
  if (exn.sad.r === "/ipex/grant" && !acdcEmbed) {
    add("the grant embeds a credential (e.acdc)", false, "no e.acdc.");
    return finish("the grant embeds no credential.");
  }
  if (exn.sad.r === "/ipex/admit" || exn.sad.r === "/ipex/agree") {
    var prior = messages.filter(function (m) {
      return m.sad.t === "exn" && m.sad.d === exn.sad.p;
    })[0];
    add("it answers the exchange its p names", !!prior, prior ? prior.sad.r +
        " " + prior.sad.d : "p " + exn.sad.p + " is not in the stream.");
  }
  if (acdcEmbed) {
    var issuee = issueeOf(acdcEmbed.msg.sad);
    if (issuee && issuee !== "?") {
      add("the grant's recipient is the credential's issuee",
          issuee === recipient, "recipient " + recipient + ", issuee " +
          issuee);
    }
    var rest = messages.filter(function (m) {
      return m !== exn;
    });
    var order = ["anc", "iss", "acdc"];
    embeds.slice().sort(function (a, b) {
      return order.indexOf(a.label) - order.indexOf(b.label);
    }).forEach(function (em) {
      rest.push(em.msg);
    });
    var cred = verifyPresentation(rest, Object.assign({}, o,
      { said: acdcEmbed.msg.sad.d }));
    out.credential = cred;
    add("the granted credential verifies", cred.valid, cred.valid ?
        acdcEmbed.msg.sad.d : (cred.revoked ? "REVOKED: " : "") + cred.reason);
  }
  out.valid = checks.every(function (c) {
    return c.ok;
  });
  out.reason = out.valid ? "" : checks.filter(function (c) {
    return !c.ok;
  }).map(function (c) {
    return c.name + ": " + c.detail;
  })[0];
  log.debug("Leaving verifyExchange(). " + out.valid);
  return out;
}

// ---------------------------------------------------------------------------
// Issuing: controllers (KELs), registries, credentials, presentations.
// ---------------------------------------------------------------------------

function dateTime(when) {
  log.debug("Entering dateTime().");
  log.debug("Leaving dateTime().");
  return new Date(when === undefined ? Date.now() : when).toISOString()
    .replace("Z", "000+00:00");
}

function salt() {
  log.debug("Entering salt().");
  log.debug("Leaving salt().");
  return encodeMatter("0A", cbytes.randomBytes(16));
}

function isPlainMap(v) {
  log.debug("Entering isPlainMap().");
  log.debug("Leaving isPlainMap().");
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function hasSaidObj(obj) {
  log.debug("Entering hasSaidObj().");
  var found = isPlainMap(obj) && (obj.d !== undefined ||
    Object.keys(obj).some(function (k) {
      return hasSaidObj(obj[k]);
    }));
  log.debug("Leaving hasSaidObj().");
  return found;
}

// Version 1 nested SAIDs: every block with a d is saidified over its FULL
// content, innermost first.
function saidifyDeep(obj) {
  log.debug("Entering saidifyDeep().");
  var out = {};
  Object.keys(obj).forEach(function (k) {
    out[k] = isPlainMap(obj[k]) && hasSaidObj(obj[k]) ?
      saidifyDeep(obj[k]) : obj[k];
  });
  log.debug("Leaving saidifyDeep().");
  return out.d !== undefined ? saidify(out) : out;
}

// Version 2 nested SAIDs: the most compact form. Answers { full (every d
// filled), said (or null), compact (the block-level compact form) }.
function compactObject(obj, label) {
  log.debug("Entering compactObject().");
  var full = {};
  var compact = {};
  Object.keys(obj).forEach(function (k) {
    var v = obj[k];
    if (isPlainMap(v) && hasSaidObj(v)) {
      var r = compactObject(v, "d");
      full[k] = r.full;
      compact[k] = r.said !== null ? r.said : r.compact;
    } else {
      full[k] = v;
      compact[k] = v;
    }
  });
  var said = null;
  if (obj[label] !== undefined) {
    said = saidify(compact, [label])[label];
    full[label] = said;
    compact[label] = said;
  }
  log.debug("Leaving compactObject().");
  return { full: full, said: said, compact: compact };
}

// An aggregate A from blocks: each block given a u (blinding) and its d,
// the AGID over their SAIDs in slot 0.
function makeAggregate(blocks) {
  log.debug("Entering makeAggregate().");
  var made = blocks.map(function (b) {
    return saidify(Object.assign({ d: "", u: salt() }, b));
  });
  var agid = digestQb64(JSON.stringify([DUMMY].concat(made.map(function (b) {
    return b.d;
  }))));
  log.debug("Leaving makeAggregate().");
  return [agid].concat(made);
}

// An ACDC with its SAIDs: version 1 over the full form, version 2 over
// the most compact form (the full form returned carries that SAID and its
// own v size). Answers { acdc (full), compact }.
function sealAcdc(sad, gen) {
  log.debug("Entering sealAcdc(). v" + gen);
  if (gen !== 2) {
    var v1 = {};
    Object.keys(sad).forEach(function (k) {
      v1[k] = isPlainMap(sad[k]) && hasSaidObj(sad[k]) && k !== "s" ?
        saidifyDeep(sad[k]) : sad[k];
    });
    var done = saidify(v1);
    log.debug("Leaving sealAcdc(). v1.");
    return { acdc: done, compact: null };
  }
  var full = {};
  var compact = {};
  Object.keys(sad).forEach(function (k) {
    var v = sad[k];
    if (k === "A" && Array.isArray(v)) {
      full[k] = v;
      compact[k] = v[0];
    } else if (k === "s" && isPlainMap(v)) {
      full[k] = v;
      compact[k] = v.$id;
    } else if (SECTIONS.indexOf(k) !== -1 && isPlainMap(v) &&
               hasSaidObj(v)) {
      var r = compactObject(v, "d");
      full[k] = r.full;
      compact[k] = r.said !== null ? r.said : r.compact;
    } else {
      full[k] = v;
      compact[k] = v;
    }
  });
  var sealed = saidify(compact);
  full.d = sealed.d;
  var tmp = Object.assign({}, full, { v: versionString("ACDC", 0, 2) });
  full.v = versionString("ACDC", cbytes.strBytes(JSON.stringify(tmp)).length,
                         2);
  log.debug("Leaving sealAcdc(). v2.");
  return { acdc: full, compact: sealed };
}

function hexThreshold(n) {
  log.debug("Entering hexThreshold().");
  log.debug("Leaving hexThreshold().");
  return Math.max(1, Math.ceil(n / 2)).toString(16);
}

// The attachments of a key event: controller signatures, witness
// receipts (the controller here also runs its witnesses), and the
// delegator's seal source couple; v1 counters, or v2 inside -C.
function eventAttachments(ctl, raw, keys, extraCouple) {
  log.debug("Entering eventAttachments().");
  var msg = cbytes.strBytes(raw);
  var gen = ctl.gen;
  var sigs = keys.map(function (k, i) {
    return encodeIndexed(sign(k, msg), i, "ed25519");
  }).join("");
  var body = group("ControllerIdxSigs", sigs, keys.length, gen);
  if (ctl.wits.length) {
    var wsigs = ctl.wits.map(function (w, i) {
      return encodeIndexed(sign(w, msg), i, "ed25519");
    }).join("");
    body += group("WitnessIdxSigs", wsigs, ctl.wits.length, gen);
  }
  if (extraCouple) {
    body += group("SealSourceCouples", ordinal(extraCouple.sn, gen) +
                  extraCouple.said, 1, gen);
  }
  var out = gen === 2 ? group("AttachmentGroup", body, 0, 2) : body;
  log.debug("Leaving eventAttachments().");
  return out;
}

// A key event controller: its keys, next keys, witnesses and KEL. opts:
// { gen (1 or 2), signers (count), kt / nt (thresholds; a list for a
// weighted one), witnesses (count), toad, delegator (a controller),
// keys, nextKeys }.
function makeController(opts) {
  log.debug("Entering makeController().");
  var o = opts || {};
  var gen = o.gen === 2 ? 2 : 1;
  var count = o.signers || (o.keys ? o.keys.length : 1);
  var keys = o.keys || Array.from({ length: count }, function () {
    return newKey();
  });
  var next = o.nextKeys || Array.from({ length: count }, function () {
    return newKey();
  });
  var wits = Array.from({ length: o.witnesses || 0 }, function () {
    return newKey(false);
  });
  var toad = o.toad !== undefined ? o.toad : wits.length;
  var ctl = { gen: gen, keys: keys, next: next, wits: wits, toad: toad,
              kt: o.kt || (count === 1 ? "1" : hexThreshold(count)),
              nt: o.nt || (count === 1 ? "1" : hexThreshold(count)),
              delegator: o.delegator || null, events: [], stream: "",
              sn: -1 };
  var sad = { v: versionString("KERI", 0, gen),
              t: ctl.delegator ? "dip" : "icp", d: "", i: "", s: "0",
              kt: ctl.kt, k: keys.map(function (k) {
                return k.verkey;
              }), nt: ctl.nt, n: next.map(function (k) {
                return digestQb64(k.verkey);
              }), bt: toad.toString(16), b: wits.map(function (w) {
                return w.verkey;
              }), c: [], a: [] };
  if (ctl.delegator) {
    sad.di = ctl.delegator.prefix;
  }
  var icp = saidify(sad, ["d", "i"]);
  ctl.prefix = icp.i;
  ctl.icp = icp;
  appendEvent(ctl, icp, keys);
  log.debug("Leaving makeController(). " + ctl.prefix);
  return ctl;
}

// Record and serialize a key event; a delegated event is first anchored by
// its delegator's interaction event, whose couple it carries.
function appendEvent(ctl, sad, keys) {
  log.debug("Entering appendEvent(). " + sad.t + " " + sad.s);
  var couple = null;
  if (sad.t === "dip" || sad.t === "drt") {
    var ev = interact(ctl.delegator, [{ i: sad.i, s: sad.s, d: sad.d }]);
    couple = { sn: hexInt(ev.s), said: ev.d };
  }
  var raw = JSON.stringify(sad);
  var text = raw + eventAttachments(ctl, raw, keys, couple);
  ctl.events.push({ sad: sad, text: text });
  ctl.stream += text;
  ctl.sn = hexInt(sad.s);
  ctl.last = sad.d;
  if (sad.t !== "ixn") {
    ctl.estSn = ctl.sn;
    ctl.estSaid = sad.d;
  }
  log.debug("Leaving appendEvent().");
  return sad;
}

// An interaction event anchoring `seals`.
function interact(ctl, seals) {
  log.debug("Entering interact().");
  var ixn = saidify({ v: versionString("KERI", 0, ctl.gen), t: "ixn", d: "",
                      i: ctl.prefix, s: (ctl.sn + 1).toString(16),
                      p: ctl.last, a: seals });
  appendEvent(ctl, ixn, ctl.keys);
  log.debug("Leaving interact().");
  return ixn;
}

// A rotation to the pre-committed next keys (drt for a delegated
// controller), with fresh next keys.
function rotate(ctl) {
  log.debug("Entering rotate().");
  var keys = ctl.next;
  var next = keys.map(function () {
    return newKey();
  });
  var sad = { v: versionString("KERI", 0, ctl.gen),
              t: ctl.delegator ? "drt" : "rot", d: "", i: ctl.prefix,
              s: (ctl.sn + 1).toString(16), p: ctl.last, kt: ctl.kt,
              k: keys.map(function (k) {
                return k.verkey;
              }), nt: ctl.nt, n: next.map(function (k) {
                return digestQb64(k.verkey);
              }), bt: ctl.toad.toString(16), br: [], ba: [] };
  if (ctl.gen === 2) {
    sad.c = [];
  }
  sad.a = [];
  var rot = saidify(sad);
  ctl.keys = keys;
  ctl.next = next;
  appendEvent(ctl, rot, keys);
  log.debug("Leaving rotate().");
  return rot;
}

// The full stream of a controller, its delegators' first.
function kelStream(ctl) {
  log.debug("Entering kelStream().");
  log.debug("Leaving kelStream().");
  return (ctl.delegator ? kelStream(ctl.delegator) : "") + ctl.stream;
}

// A v1 TEL event's attachments: backer receipts, then the seal source
// couple of its anchor, in one -V group.
function telAttachments(raw, backers, sn, said) {
  log.debug("Entering telAttachments().");
  var msg = cbytes.strBytes(raw);
  var body = "";
  if (backers && backers.length) {
    body += group("WitnessIdxSigs", backers.map(function (b, i) {
      return encodeIndexed(sign(b, msg), i, "ed25519");
    }).join(""), backers.length, 1);
  }
  body += group("SealSourceCouples", seqner(sn) + said, 1, 1);
  log.debug("Leaving telAttachments().");
  return group("AttachmentGroup", body, 0, 1);
}

// A v2 registry event's attachments: its anchor's seal source couple.
function telAttachmentsV2(sn, said) {
  log.debug("Entering telAttachmentsV2().");
  log.debug("Leaving telAttachmentsV2().");
  return group("AttachmentGroup", group("SealSourceCouples",
    encodeNumber(sn) + said, 1, 2), 0, 2);
}

// A schema for a credential's attributes: $id its SAID, the dialect the
// generation's libraries use (draft-07 for v1, 2020-12 for v2).
function defaultSchema(attrs, gen, opts) {
  log.debug("Entering defaultSchema().");
  var o = opts || {};
  var types = {};
  Object.keys(attrs).forEach(function (k) {
    var v = attrs[k];
    types[k] = { type: Array.isArray(v) ? "array" : v === null ? "null" :
                 typeof v === "number" ? "number" : typeof v };
  });
  var props = Object.assign({ d: { type: "string" }, u: { type: "string" },
                              i: { type: "string" },
                              dt: { type: "string", format: "date-time" } },
                            types);
  var section = function (detail) {
    log.debug("Entering section().");
    log.debug("Leaving section().");
    return { oneOf: [{ type: "string" }, detail || { type: "object" }] };
  };
  var top = { v: { type: "string" } };
  if (gen === 2) {
    top.t = { type: "string" };
  }
  top.d = { type: "string" };
  top.u = { type: "string" };
  top.i = { type: "string" };
  top[gen === 2 ? "rd" : "ri"] = { type: "string" };
  top.s = section();
  top.a = section({ type: "object", properties: props,
                    required: ["d"].concat(Object.keys(types)),
                    additionalProperties: false });
  top.A = { oneOf: [{ type: "string" }, { type: "array" }] };
  top.e = section();
  top.r = section();
  var schema = { $id: "", $schema: gen === 2 ?
                 "https://json-schema.org/draft/2020-12/schema" :
                 "http://json-schema.org/draft-07/schema#",
                 title: o.title || "Debugger ACDC",
                 description: "An ACDC issued by the id-proto-debugger.",
                 type: "object",
                 credentialType: o.credentialType || "IdProtoDebuggerExample",
                 version: "1.0.0", properties: top,
                 required: ["v", "d", "i", "s"],
                 additionalProperties: false };
  log.debug("Leaving defaultSchema().");
  return saidify(schema, ["$id"]);
}

// A whole issuance, and the presentation stream a verifier receives. opts:
//   version      1 (default: what signify-ts and KERIA issue) or 2
//   signers, kt, nt, witnesses, toad   the issuer's keys (a weighted kt is
//                a list) and its witnesses
//   delegated    the issuer is a delegated identifier (dip) of a fresh
//                delegator, which anchors it
//   backers, backerToad   a v1 backer registry (bis/brv) instead of NB
//   attributes   object; dt is added
//   recipient    a.i (targeted)
//   aggregate    a list of blocks: an A section (selective disclosure)
//                instead of a
//   edges        { label: { n, s, o } } or { label: issued } (another
//                issuance; its ACDC and schema are named)
//   rules        an r section (object; given a d)
//   private      a top-level u (a private ACDC)
//   direct       no registry: the issuer's KEL seals the SAID itself
//   schema, when, issuer (a controller to issue with)
// Answers { stream, acdc, compact, schema, icp, vcp / rip, iss / upd, ixns,
// ctl, key, nextKey, gen }.
function issue(opts) {
  log.debug("Entering issue().");
  var o = opts || {};
  var gen = o.version === 2 ? 2 : 1;
  var dt = dateTime(o.when);
  var delegator = o.delegated && !o.issuer ?
      makeController({ gen: gen }) : null;
  var ctl = o.issuer || makeController({
    gen: gen, signers: o.signers, kt: o.kt, nt: o.nt,
    witnesses: o.witnesses, toad: o.toad, delegator: delegator,
    keys: o.key ? [o.key] : undefined,
    nextKeys: o.nextKey ? [o.nextKey] : undefined });
  var startLen = ctl.stream.length;
  var aid = ctl.prefix;
  var attrs = Object.assign({}, o.attributes || {});
  var schema = o.schema ? Object.assign({ $id: "" }, o.schema) :
      defaultSchema(o.aggregate ? {} : attrs, gen);
  if (!schema.$id) {
    schema = saidify(schema, ["$id"]);
  }
  var out = { gen: gen, ctl: ctl, schema: schema, ixns: [], delegator:
              delegator };
  var registryKey = gen === 2 ? "rd" : "ri";
  var regid = null;
  var telText = "";
  if (!o.direct && gen === 1) {
    var backers = Array.from({ length: o.backers || 0 }, function () {
      return newKey(false);
    });
    var vtoad = o.backerToad !== undefined ? o.backerToad : backers.length;
    var vcp = saidify({ v: versionString("KERI", 0, 1), t: "vcp", d: "",
      i: "", ii: aid, s: "0", c: backers.length ? [] : ["NB"],
      bt: vtoad.toString(16), b: backers.map(function (b) {
        return b.verkey;
      }), n: encodeMatter("A", cbytes.randomBytes(32)) }, ["d", "i"]);
    var vixn = interact(ctl, [{ i: vcp.i, s: "0", d: vcp.d }]);
    out.ixns.push(vixn);
    telText += JSON.stringify(vcp) + telAttachments(JSON.stringify(vcp),
      backers, hexInt(vixn.s), vixn.d);
    out.vcp = vcp;
    out.backers = backers;
    regid = vcp.i;
  } else if (!o.direct) {
    var rip = saidify({ v: versionString("ACDC", 0, 2), t: "rip", d: "",
                        u: salt(), i: aid, n: "0", dt: dt });
    var rixn = interact(ctl, [{ i: rip.d, s: "0", d: rip.d }]);
    out.ixns.push(rixn);
    telText += JSON.stringify(rip) + telAttachmentsV2(hexInt(rixn.s),
                                                      rixn.d);
    out.rip = rip;
    regid = rip.d;
  }
  var a = null;
  if (!o.aggregate) {
    a = Object.assign({ d: "" }, gen === 2 ? { u: salt() } : {},
                      o.recipient ? { i: o.recipient } : {}, attrs,
                      { dt: attrs.dt || dt });
  }
  var sad = { v: versionString("ACDC", 0, gen) };
  if (gen === 2) {
    sad.t = "acm";
  }
  sad.d = "";
  if (o.private) {
    sad.u = salt();
  }
  sad.i = aid;
  if (regid) {
    sad[registryKey] = regid;
  }
  sad.s = schema.$id;
  if (a) {
    sad.a = a;
  } else {
    sad.A = makeAggregate(o.aggregate);
  }
  if (o.edges) {
    var e = { d: "" };
    Object.keys(o.edges).forEach(function (label) {
      var edge = o.edges[label];
      e[label] = edge && edge.acdc ? { d: "", n: edge.acdc.d,
        s: edge.schema.$id } : Object.assign({ d: "" }, edge);
    });
    sad.e = e;
  }
  if (o.rules) {
    sad.r = Object.assign({ d: "" }, o.rules);
  }
  var sealed = sealAcdc(sad, gen);
  var acdc = sealed.acdc;
  out.acdc = acdc;
  out.compact = sealed.compact;
  var credText = JSON.stringify(acdc);
  if (o.direct) {
    var dixn = interact(ctl, [{ i: acdc.d, s: "0", d: acdc.d }]);
    out.ixns.push(dixn);
  } else if (gen === 1) {
    var bk = out.backers.length > 0;
    var iss = saidify(bk ? { v: versionString("KERI", 0, 1), t: "bis", d: "",
      i: acdc.d, ii: regid, s: "0", ra: { i: regid, s: "0",
      d: out.vcp.d }, dt: dt } : { v: versionString("KERI", 0, 1),
      t: "iss", d: "", i: acdc.d, s: "0", ri: regid, dt: dt });
    var iixn = interact(ctl, [{ i: acdc.d, s: "0", d: iss.d }]);
    out.ixns.push(iixn);
    out.iss = iss;
    out.issAnchor = iixn;
    telText += JSON.stringify(iss) + telAttachments(JSON.stringify(iss),
      out.backers, hexInt(iixn.s), iixn.d);
    credText += counter("-I", 1) + acdc.d + seqner(0) + iss.d;
  } else {
    var upd = saidify({ v: versionString("ACDC", 0, 2), t: "upd", d: "",
                        rd: regid, n: "1", p: out.rip.d, dt: dt,
                        td: acdc.d, ts: "issued" });
    var uixn = interact(ctl, [{ i: regid, s: "1", d: upd.d }]);
    out.ixns.push(uixn);
    out.upd = upd;
    telText += JSON.stringify(upd) + telAttachmentsV2(hexInt(uixn.s),
                                                      uixn.d);
  }
  out.icp = ctl.icp;
  out.key = ctl.keys[0];
  out.nextKey = ctl.next[0];
  out.kel = ctl.stream.slice(startLen);
  out.tel = telText;
  out.credentialText = credText;
  out.stream = kelStream(ctl) + telText + credText;
  log.debug("Leaving issue().");
  return out;
}

// Revoke: a rev (or brv) in a v1 registry, an upd with ts revoked in a v2
// one, anchored by a further ixn. Answers the stream with both appended.
function revoke(issued, when) {
  log.debug("Entering revoke().");
  var ctl = issued.ctl;
  var dt = dateTime(when);
  var text;
  if (issued.gen === 2) {
    var upd = saidify({ v: versionString("ACDC", 0, 2), t: "upd", d: "",
                        rd: issued.rip.d, n: "2", p: issued.upd.d, dt: dt,
                        td: issued.acdc.d, ts: "revoked" });
    var ixn = interact(ctl, [{ i: issued.rip.d, s: "2", d: upd.d }]);
    text = ctl.events[ctl.events.length - 1].text + JSON.stringify(upd) +
      telAttachmentsV2(hexInt(ixn.s), ixn.d);
  } else {
    var bk = issued.backers && issued.backers.length > 0;
    var rev = saidify(bk ? { v: versionString("KERI", 0, 1), t: "brv",
      d: "", i: issued.acdc.d, s: "1", p: issued.iss.d, ra: { i: issued.vcp.i,
      s: "0", d: issued.vcp.d }, dt: dt } : { v: versionString("KERI", 0, 1),
      t: "rev", d: "", i: issued.acdc.d, s: "1", ri: issued.vcp.i,
      p: issued.iss.d, dt: dt });
    var rixn = interact(ctl, [{ i: rev.i, s: "1", d: rev.d }]);
    text = ctl.events[ctl.events.length - 1].text + JSON.stringify(rev) +
      telAttachments(JSON.stringify(rev), issued.backers, hexInt(rixn.s),
                     rixn.d);
  }
  log.debug("Leaving revoke().");
  return issued.stream + text;
}

// A chain: an issuer issues a credential to a holder, and the holder, as
// issuer, issues a second credential whose edge points to the first (I2I
// by default). opts: { version, parent (issue options), child (issue
// options), operator (the edge's o) }. Answers { stream, parent, child,
// holder }.
function issueChain(opts) {
  log.debug("Entering issueChain().");
  var o = opts || {};
  var gen = o.version === 2 ? 2 : 1;
  var holder = makeController({ gen: gen });
  var parent = issue(Object.assign({ version: gen, attributes:
    { role: "parent" }, recipient: holder.prefix }, o.parent || {}));
  var edge = { acdc: parent.acdc, schema: parent.schema };
  var edges = { parent: o.operator ? { n: parent.acdc.d,
    s: parent.schema.$id, o: o.operator } : edge };
  var child = issue(Object.assign({ version: gen, attributes:
    { role: "child" }, issuer: holder, edges: edges }, o.child || {}));
  log.debug("Leaving issueChain().");
  return { stream: parent.stream + child.stream, parent: parent,
           child: child, holder: holder };
}

// Selective disclosure of an aggregate: the ACDC with only the blocks at
// `indices` (1-based, as in A) expanded, the others replaced by their
// SAIDs. Its d is unchanged (in version 2 the SAID is over the most compact
// form); its v is re-sized. Answers the new body text.
function discloseAggregate(acdc, indices) {
  log.debug("Entering discloseAggregate().");
  if (!Array.isArray(acdc.A)) {
    log.debug("Leaving discloseAggregate(). No A.");
    throw new Error("the ACDC has no aggregate (A) to disclose from.");
  }
  var A = acdc.A.map(function (b, i) {
    return i === 0 || indices.indexOf(i) !== -1 || typeof b === "string" ?
      b : b.d;
  });
  var pv = parseVersion(acdc.v);
  var sad = Object.assign({}, acdc, { A: A, v: versionString("ACDC", 0,
                                                              pv.gen) });
  sad.v = versionString("ACDC", cbytes.strBytes(JSON.stringify(sad)).length,
                        pv.gen);
  log.debug("Leaving discloseAggregate().");
  return JSON.stringify(sad);
}

// The stream of an issuance with its ACDC body replaced (a disclosed or
// compact variant of the same credential).
function withAcdcText(issued, text) {
  log.debug("Entering withAcdcText().");
  var plain = JSON.stringify(issued.acdc);
  log.debug("Leaving withAcdcText().");
  return issued.stream.replace(plain, text);
}

// An IPEX grant (/ipex/grant) of an issued credential to its issuee, as
// signify-ts builds one: a version 1 exn whose e embeds the ACDC, its iss
// and the anchoring ixn (e.d last), signed by the issuer with a -F
// transferable signature group, each embed's attachments in a -L pathed
// group. opts: { recipient, message, when }. Answers { exn, text, stream
// (the issuance stream with the grant appended) }.
function grant(issued, opts) {
  log.debug("Entering grant().");
  var o = opts || {};
  if (issued.gen === 2 || !issued.iss) {
    log.debug("Leaving grant(). Not v1.");
    throw new Error("a grant here carries a version 1 credential with its " +
                    "iss, as signify-ts and keri-ts exchange them.");
  }
  var ctl = issued.ctl;
  var recipient = o.recipient || (issued.acdc.a && issued.acdc.a.i) || "";
  var anc = issued.issAnchor;
  var ancEvent = ctl.events.filter(function (e) {
    return e.sad.d === anc.d;
  })[0];
  var ancAtc = ancEvent.text.slice(JSON.stringify(anc).length);
  var issAtc = telAttachments(JSON.stringify(issued.iss), issued.backers,
                              hexInt(anc.s), anc.d);
  var acdcAtc = counter("-I", 1) + issued.acdc.d + seqner(0) +
      issued.iss.d;
  var e = saidify({ acdc: issued.acdc, iss: issued.iss, anc: anc, d: "" });
  var exn = saidify({ v: versionString("KERI", 0, 1), t: "exn", d: "",
                      i: ctl.prefix, rp: recipient, p: "",
                      dt: dateTime(o.when), r: "/ipex/grant", q: {},
                      a: { i: recipient, m: o.message || "" }, e: e });
  var raw = JSON.stringify(exn);
  var msg = cbytes.strBytes(raw);
  var sigs = ctl.keys.map(function (k, i) {
    return encodeIndexed(sign(k, msg), i, "ed25519");
  }).join("");
  var atc = counter("-F", 1) + ctl.prefix + seqner(ctl.estSn) +
      ctl.estSaid + group("ControllerIdxSigs", sigs, ctl.keys.length, 1);
  [["acdc", acdcAtc], ["iss", issAtc], ["anc", ancAtc]].forEach(
    function (pair) {
      atc += group("PathedMaterialCouples", encodePath(["e", pair[0]]) +
                   pair[1], 0, 1);
    });
  log.debug("Leaving grant().");
  return { exn: exn, text: raw + atc, stream: issued.stream + raw + atc };
}

module.exports = {
  SPEC: SPEC,
  MATTER: MATTER,
  SIZES: SIZES,
  encodeMatter: encodeMatter,
  decodeMatter: decodeMatter,
  encodeIndexed: encodeIndexed,
  decodeIndexed: decodeIndexed,
  encodeNumber: encodeNumber,
  encodePath: encodePath,
  decodePath: decodePath,
  encodeBexter: encodeBexter,
  decodeCounter: decodeCounter,
  group: group,
  seqner: seqner,
  intToB64: intToB64,
  b64ToInt: b64ToInt,
  digestQb64: digestQb64,
  versionString: versionString,
  parseVersion: parseVersion,
  saidify: saidify,
  checkSaid: checkSaid,
  checkAcdcSaid: checkAcdcSaid,
  blindedStateId: blindedStateId,
  keyFromSeed: keyFromSeed,
  newKey: newKey,
  parseStream: parseStream,
  checkBody: checkBody,
  processKels: processKels,
  verifyKel: verifyKel,
  verifyPresentation: verifyPresentation,
  verifyExchange: verifyExchange,
  makeController: makeController,
  interact: interact,
  rotate: rotate,
  kelStream: kelStream,
  defaultSchema: defaultSchema,
  sealAcdc: sealAcdc,
  makeAggregate: makeAggregate,
  discloseAggregate: discloseAggregate,
  withAcdcText: withAcdcText,
  issue: issue,
  issueChain: issueChain,
  revoke: revoke,
  grant: grant,
  dateTime: dateTime,
  incept: function (key, nextKey) {
    log.debug("Entering incept().");
    log.debug("Leaving incept().");
    return makeController({ keys: [key], nextKeys: [nextKey] }).icp;
  }
};
