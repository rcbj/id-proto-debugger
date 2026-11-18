// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc.js
//
// ---------------------------------------------------------------------------
// ACDC — Authentic Chained Data Containers (Trust over IP KERI Suite WG
// specification) — with the parts of CESR and KERI a verifier and an issuer
// need (#480): read a CESR stream, verify the issuer's key event log, the
// registry's issuance and revocation events and their anchors in that log,
// and the credential itself; and issue all of it.
//
// AN ACDC IS VERIFIED BY ITS ISSUER'S HISTORY, NOT BY A SIGNATURE ON IT. The
// credential carries no signature at all: its SAID (a digest of its own
// bytes) is sealed into the issuer's registry by an `iss` event, and that
// event is anchored by a seal in an event of the issuer's KEL, which IS
// signed. So the chain a verifier walks is
//     KEL (icp, rot, ixn: signatures, thresholds, next-key digests)
//       -> the ixn whose one seal is {i, s, d} of the registry event
//         -> vcp (the registry) and iss (this credential) / rev
//           -> the ACDC whose SAID iss names.
//
// WHAT IS ON THE WIRE, per the released libraries (signify-ts 0.4.1, the
// KERIA client vLEI uses; keri-ts 2.2.9): version 1 everywhere for the
// credential and its registry (ACDC10JSON…, vcp/iss/rev), and a v1 KEL from
// signify. keri-ts writes its KEL in v2 by default; that generation's CESR
// tables are not implemented here yet and a v2 event is refused by name.
//
// SAIDS ARE CHECKED OVER THE BYTES RECEIVED, never over a re-serialization:
// the issuer's JSON may format a number (4.0) or order an integer-like key
// in a way JavaScript's JSON.stringify would not, and either changes the
// hash. Issuing uses JSON.stringify, as both libraries do.
//
// Blake3-256 is the default digest (code E). All cryptography is @noble,
// pure JavaScript.
//
// NO DOM.
// ---------------------------------------------------------------------------

var nobleEd = require("@noble/curves/ed25519");
var nobleSecp = require("@noble/curves/secp256k1");
var nobleP256 = require("@noble/curves/p256");
var blake3 = require("@noble/hashes/blake3").blake3;
var sha256 = require("@noble/hashes/sha256").sha256;
var cbytes = require("./crypto_bytes");

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

// code -> { hs, ss, fs, ls, raw } for the fixed-size codes used here.
var MATTER = {
  A: { hs: 1, fs: 44, raw: 32, name: "Ed25519 seed" },
  B: { hs: 1, fs: 44, raw: 32, name: "Ed25519 non-transferable key" },
  D: { hs: 1, fs: 44, raw: 32, name: "Ed25519 key" },
  E: { hs: 1, fs: 44, raw: 32, name: "Blake3-256 digest" },
  H: { hs: 1, fs: 44, raw: 32, name: "SHA3-256 digest" },
  I: { hs: 1, fs: 44, raw: 32, name: "SHA-256 digest" },
  M: { hs: 1, fs: 4, raw: 2, name: "short number" },
  "0A": { hs: 2, fs: 24, raw: 16, name: "salt / sequence number" },
  "0B": { hs: 2, fs: 88, raw: 64, name: "Ed25519 signature" },
  "0C": { hs: 2, fs: 88, raw: 64, name: "secp256k1 signature" },
  "0I": { hs: 2, fs: 88, raw: 64, name: "P-256 signature" },
  "1AAA": { hs: 4, fs: 48, raw: 33, name: "secp256k1 non-transferable key" },
  "1AAB": { hs: 4, fs: 48, raw: 33, name: "secp256k1 key" },
  "1AAI": { hs: 4, fs: 48, raw: 33, name: "P-256 non-transferable key" },
  "1AAJ": { hs: 4, fs: 48, raw: 33, name: "P-256 key" },
  "1AAG": { hs: 4, fs: 36, raw: 24, name: "date-time" }
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
    if (d === -1) throw new Error("not base64url: " + JSON.stringify(s));
    v = v * 64 + d;
  }
  log.debug("Leaving b64ToInt().");
  return v;
}

// raw bytes -> qb64 with a fixed-size code.
function encodeMatter(code, raw) {
  log.debug("Entering encodeMatter(). " + code);
  var m = MATTER[code];
  if (!m || raw.length !== m.raw) {
    log.debug("Leaving encodeMatter(). Bad size.");
    throw new Error("code " + code + " takes " + (m ? m.raw : "?") +
                    " bytes, not " + raw.length + ".");
  }
  var ps = code.length % 4;
  var body = b64Encode(cbytes.concatBytes(new Uint8Array(ps), raw)).slice(ps);
  log.debug("Leaving encodeMatter().");
  return code + body;
}

// qb64 -> { code, raw, size } at the start of text.
function decodeMatter(text) {
  log.debug("Entering decodeMatter().");
  var hs = hardSize(text.charAt(0));
  var code = text.slice(0, hs);
  var m = MATTER[code];
  if (!m) {
    log.debug("Leaving decodeMatter(). Unknown code.");
    throw new Error("CESR code " + JSON.stringify(code) + " is not one this " +
                    "debugger reads.");
  }
  var q = text.slice(0, m.fs);
  if (q.length !== m.fs) {
    log.debug("Leaving decodeMatter(). Short.");
    throw new Error("a " + m.name + " is " + m.fs + " characters.");
  }
  var ps = code.length % 4;
  var paw = cbytes.b64uToBytes(new Array(ps + 1).join("A") + q.slice(hs));
  for (var i = 0; i < ps; i++) {
    if (paw[i]) {
      log.debug("Leaving decodeMatter(). Pad bits set.");
      throw new Error("non-zero pad bits in " + q.slice(0, 12) + "….");
    }
  }
  log.debug("Leaving decodeMatter().");
  return { code: code, raw: paw.slice(ps), size: m.fs, qb64: q };
}

// Indexed signatures: A/B (Ed25519), C/D (secp256k1), E/F (P-256), and the
// big forms 2A-2F.
var INDEXER = { A: "ed25519", B: "ed25519", C: "secp256k1", D: "secp256k1",
                E: "p256", F: "p256", "2A": "ed25519", "2B": "ed25519",
                "2C": "secp256k1", "2D": "secp256k1", "2E": "p256",
                "2F": "p256" };

function decodeIndexed(text) {
  log.debug("Entering decodeIndexed().");
  var big = text.charAt(0) === "2";
  var code = text.slice(0, big ? 2 : 1);
  if (!INDEXER[code]) {
    log.debug("Leaving decodeIndexed(). Unknown.");
    throw new Error("indexed signature code " + JSON.stringify(code) +
                    " is not read here.");
  }
  var fs = big ? 92 : 88;
  var q = text.slice(0, fs);
  var index = b64ToInt(big ? q.slice(2, 4) : q.slice(1, 2));
  var ondex = big ? b64ToInt(q.slice(4, 6)) : index;
  var cs = big ? 6 : 2;
  var paw = cbytes.b64uToBytes(new Array(cs % 4 + 1).join("A") + q.slice(cs));
  var only = code === "B" || code === "D" || code === "F" ||
      code === "2B" || code === "2D" || code === "2F";
  log.debug("Leaving decodeIndexed().");
  return { code: code, alg: INDEXER[code], index: index,
           ondex: only ? null : ondex, sig: paw.slice(cs % 4), size: fs,
           qb64: q };
}

function encodeIndexed(sig, index, alg) {
  log.debug("Entering encodeIndexed().");
  var codes = { ed25519: ["A", "2A"], secp256k1: ["C", "2C"],
                p256: ["E", "2E"] }[alg || "ed25519"];
  var out;
  if (index <= 63) {
    out = codes[0] + B64.charAt(index) +
      b64Encode(cbytes.concatBytes(new Uint8Array(2), sig)).slice(2);
  } else {
    out = codes[1] + intToB64(index, 2) + intToB64(index, 2) +
      b64Encode(cbytes.concatBytes(new Uint8Array(2), sig)).slice(2);
  }
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

function seqnerValue(raw) {
  log.debug("Entering seqnerValue().");
  var v = BigInt(0);
  for (var i = 0; i < raw.length; i++) v = (v << BigInt(8)) | BigInt(raw[i]);
  log.debug("Leaving seqnerValue().");
  return Number(v);
}

function counter(code, count) {
  log.debug("Entering counter(). " + code);
  log.debug("Leaving counter().");
  return code + intToB64(count, 2);
}

// ---------------------------------------------------------------------------
// Keys.
// ---------------------------------------------------------------------------

var KEY_ALGS = { D: "ed25519", B: "ed25519", "1AAB": "secp256k1",
                 "1AAA": "secp256k1", "1AAJ": "p256", "1AAI": "p256" };

function verifyRaw(alg, pub, sig, msg) {
  log.debug("Entering verifyRaw(). " + alg);
  var ok = false;
  try {
    if (alg === "ed25519") {
      ok = nobleEd.ed25519.verify(sig, msg, pub);
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

// A transferable Ed25519 signing key: { seed, verkey (qb64 D…) }.
function keyFromSeed(seed) {
  log.debug("Entering keyFromSeed().");
  var s = cbytes.asBytes(seed);
  log.debug("Leaving keyFromSeed().");
  return { seed: s, verkey: encodeMatter("D",
    nobleEd.ed25519.getPublicKey(s)) };
}

function newKey() {
  log.debug("Entering newKey().");
  log.debug("Leaving newKey().");
  return keyFromSeed(cbytes.randomBytes(32));
}

function sign(key, msg) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return nobleEd.ed25519.sign(msg, key.seed);
}

function digestQb64(text) {
  log.debug("Entering digestQb64().");
  log.debug("Leaving digestQb64().");
  return encodeMatter("E", blake3(cbytes.strBytes(text)));
}

// ---------------------------------------------------------------------------
// Version strings and SAIDs.
// ---------------------------------------------------------------------------

var V1 = /^(KERI|ACDC)10JSON([0-9a-f]{6})_$/;
var V2 = /^(KERI|ACDC)[A-Za-z0-9_-]{3}[A-Za-z0-9_-]{3}JSON[A-Za-z0-9_-]{4}\.$/;

function versionString(proto, size) {
  log.debug("Entering versionString().");
  log.debug("Leaving versionString().");
  return proto + "10JSON" + ("000000" + size.toString(16)).slice(-6) + "_";
}

var DUMMY = new Array(45).join("#");

// The SAID of `sad` (an object in protocol field order), with the saidive
// labels dummied and `v` sized: for issuing. Answers the finished object.
function saidify(sad, labels) {
  log.debug("Entering saidify().");
  var fields = labels || ["d"];
  var tmp = Object.assign({}, sad);
  fields.forEach(function (l) {
    tmp[l] = DUMMY;
  });
  if (tmp.v !== undefined) {
    var proto = String(tmp.v).slice(0, 4);
    tmp.v = versionString(proto, 0);
    tmp.v = versionString(proto, cbytes.strBytes(JSON.stringify(tmp)).length);
  }
  var said = digestQb64(JSON.stringify(tmp));
  var out = Object.assign({}, tmp);
  fields.forEach(function (l) {
    out[l] = said;
  });
  log.debug("Leaving saidify().");
  return out;
}

// A tokenizer that records the byte span of the string value of each
// member of the top-level object, so a SAID is checked over the received
// bytes with only its own value overwritten.
function memberSpans(text) {
  log.debug("Entering memberSpans().");
  var spans = {};
  var depth = 0;
  var i = 0;
  var expectKey = false;
  var key = null;
  var n = text.length;
  while (i < n) {
    var c = text.charAt(i);
    if (c === "\"") {
      var start = i;
      i++;
      while (i < n && text.charAt(i) !== "\"") {
        if (text.charAt(i) === "\\") i++;
        i++;
      }
      var str = text.slice(start + 1, i);
      i++;
      if (depth === 1 && expectKey) {
        key = JSON.parse("\"" + str + "\"");
        expectKey = false;
      } else if (depth === 1 && key !== null) {
        spans[key] = { start: start + 1, end: i - 1 };
        key = null;
      }
      continue;
    }
    if (c === "{" || c === "[") {
      depth++;
      if (depth === 1) expectKey = true;
      if (depth === 2) key = null;
    } else if (c === "}" || c === "]") {
      depth--;
    } else if (c === "," && depth === 1) {
      expectKey = true;
      key = null;
    }
    i++;
  }
  log.debug("Leaving memberSpans().");
  return spans;
}

// Check the SAID labels of a received JSON body over its bytes. Answers
// { ok, said, computed, reason }.
function checkSaid(raw, labels) {
  log.debug("Entering checkSaid().");
  var text = typeof raw === "string" ? raw : cbytes.bytesToStr(raw);
  var spans = memberSpans(text);
  var fields = labels || ["d"];
  var value = null;
  var masked = text;
  for (var i = 0; i < fields.length; i++) {
    var sp = spans[fields[i]];
    if (!sp) {
      log.debug("Leaving checkSaid(). Missing.");
      return { ok: false, reason: "there is no " + fields[i] + " to check." };
    }
    var v = text.slice(sp.start, sp.end);
    if (value !== null && v !== value) {
      log.debug("Leaving checkSaid(). Disagree.");
      return { ok: false, reason: fields.join(" and ") + " must carry the " +
               "same SAID." };
    }
    value = v;
  }
  // Overwrite from the end so the earlier spans stay valid.
  fields.map(function (f) {
    return spans[f];
  }).sort(function (a, b) {
    return b.start - a.start;
  }).forEach(function (sp) {
    masked = masked.slice(0, sp.start) +
      new Array(sp.end - sp.start + 1).join("#") + masked.slice(sp.end);
  });
  var code = value.charAt(0);
  var digest = code === "E" ? blake3(cbytes.strBytes(masked)) :
      code === "I" ? sha256(cbytes.strBytes(masked)) : null;
  if (!digest) {
    log.debug("Leaving checkSaid(). Digest code.");
    return { ok: false, said: value, reason: "SAID code " + code + " is not " +
             "one checked here (E Blake3-256, I SHA-256)." };
  }
  var computed = encodeMatter(code, digest);
  log.debug("Leaving checkSaid().");
  return { ok: computed === value, said: value, computed: computed,
           reason: computed === value ? "" : "the SAID " + value + " is not " +
             "the digest of these bytes (" + computed + ")." };
}

// The v string's size must be the body's byte length.
function checkVersionSize(raw, sad) {
  log.debug("Entering checkVersionSize().");
  var m = V1.exec(String(sad.v || ""));
  if (!m) {
    log.debug("Leaving checkVersionSize(). Not v1.");
    return V2.test(String(sad.v || "")) ? "a version 2 message (" + sad.v +
      "): this debugger reads the version 1 KERI and ACDC generation the " +
      "released libraries issue credentials in, not v2 yet." :
      "no version string.";
  }
  var size = parseInt(m[2], 16);
  log.debug("Leaving checkVersionSize().");
  return size === raw.length ? "" : "the version string says " + size +
    " bytes and the body is " + raw.length + ".";
}

// ---------------------------------------------------------------------------
// The CESR stream: JSON bodies, each followed by its attachments.
// ---------------------------------------------------------------------------

// v1 counters: code -> how its items are read.
function readGroups(text, pos, end, out) {
  log.debug("Entering readGroups().");
  var p = pos;
  while (p < end) {
    var code = text.slice(p, p + 2);
    if (text.charAt(p) !== "-") break;
    var count = b64ToInt(text.slice(p + 2, p + 4));
    p += 4;
    var i;
    if (code === "-V") {
      var stop = p + count * 4;
      p = readGroups(text, p, stop, out);
      continue;
    }
    if (code === "-_") {
      p += 4;
      continue;
    }
    if (code === "-A" || code === "-B") {
      for (i = 0; i < count; i++) {
        var s = decodeIndexed(text.slice(p));
        (code === "-A" ? out.sigs : out.witnessSigs).push(s);
        p += s.size;
      }
    } else if (code === "-G") {
      for (i = 0; i < count; i++) {
        var sq = decodeMatter(text.slice(p));
        var dg = decodeMatter(text.slice(p + sq.size));
        out.sourceSeals.push({ s: seqnerValue(sq.raw), d: dg.qb64 });
        p += sq.size + dg.size;
      }
    } else if (code === "-I") {
      for (i = 0; i < count; i++) {
        var pre = decodeMatter(text.slice(p));
        var sq2 = decodeMatter(text.slice(p + pre.size));
        var dg2 = decodeMatter(text.slice(p + pre.size + sq2.size));
        out.sourceTriples.push({ i: pre.qb64, s: seqnerValue(sq2.raw),
                                 d: dg2.qb64 });
        p += pre.size + sq2.size + dg2.size;
      }
    } else if (code === "-E") {
      for (i = 0; i < count; i++) {
        var fn = decodeMatter(text.slice(p));
        var dt = decodeMatter(text.slice(p + fn.size));
        out.firstSeen.push({ fn: seqnerValue(fn.raw), dt: dt.qb64 });
        p += fn.size + dt.size;
      }
    } else if (code === "-C") {
      for (i = 0; i < count; i++) {
        var vk = decodeMatter(text.slice(p));
        var cig = decodeMatter(text.slice(p + vk.size));
        out.receipts.push({ verkey: vk.qb64, sig: cig.raw });
        p += vk.size + cig.size;
      }
    } else if (code === "-F") {
      for (i = 0; i < count; i++) {
        var fp = decodeMatter(text.slice(p));
        var fs = decodeMatter(text.slice(p + fp.size));
        var fd = decodeMatter(text.slice(p + fp.size + fs.size));
        p += fp.size + fs.size + fd.size;
        var group = { i: fp.qb64, s: seqnerValue(fs.raw), d: fd.qb64,
                      sigs: [] };
        if (text.slice(p, p + 2) !== "-A") {
          throw new Error("a -F group's signatures are a -A group.");
        }
        var n = b64ToInt(text.slice(p + 2, p + 4));
        p += 4;
        for (var j = 0; j < n; j++) {
          var gs = decodeIndexed(text.slice(p));
          group.sigs.push(gs);
          p += gs.size;
        }
        out.transSigGroups.push(group);
      }
    } else {
      log.debug("Leaving readGroups(). Unknown counter.");
      throw new Error("attachment group " + code + " is not read here.");
    }
  }
  log.debug("Leaving readGroups().");
  return p;
}

// Split a CESR stream (text) into messages: { raw (bytes of the body),
// sad, attachments }. Bodies are JSON with a version string; anything else
// is refused by name.
function parseStream(input) {
  log.debug("Entering parseStream().");
  var text = typeof input === "string" ? input : cbytes.bytesToStr(input);
  var bytes = cbytes.strBytes(text);
  if (bytes.length !== text.length) {
    // Non-ASCII content: work in bytes for the body sizes.
    log.debug("parseStream(): non-ASCII stream.");
  }
  var out = [];
  var p = 0;
  var b = 0;
  text = text.trim();
  bytes = cbytes.strBytes(text);
  while (b < bytes.length) {
    if (bytes[b] !== 0x7b) {
      log.debug("Leaving parseStream(). Not a body.");
      throw new Error("expected a JSON body at byte " + b + ", found " +
        JSON.stringify(cbytes.bytesToStr(bytes.slice(b, b + 12))) + " (only " +
        "JSON bodies are read here, not CBOR or MessagePack).");
    }
    var head = cbytes.bytesToStr(bytes.slice(b, b + 40));
    var m = /"v":"([A-Z]{4}10JSON([0-9a-f]{6})_)"/.exec(head);
    if (!m) {
      var m2 = /"v":"([A-Z]{4}[A-Za-z0-9_-]{6}JSON[A-Za-z0-9_-]{4}\.)"/
        .exec(head);
      log.debug("Leaving parseStream(). No v1 version string.");
      throw new Error(m2 ? "message " + (out.length + 1) + " is CESR " +
        "version 2 (" + m2[1] + "); this debugger reads version 1, which " +
        "signify-ts and both libraries' credentials use." : "message " +
        (out.length + 1) + " has no version string.");
    }
    var size = parseInt(m[2], 16);
    var raw = bytes.slice(b, b + size);
    var sad = JSON.parse(cbytes.bytesToStr(raw));
    b += size;
    p = cbytes.bytesToStr(bytes.slice(0, b)).length;
    var att = { sigs: [], witnessSigs: [], sourceSeals: [],
                sourceTriples: [], firstSeen: [], receipts: [],
                transSigGroups: [] };
    var rest = text.slice(p);
    var nextBody = rest.indexOf("{");
    var attText = nextBody === -1 ? rest : rest.slice(0, nextBody);
    var used = readGroups(attText, 0, attText.length, att);
    if (used !== attText.length) {
      log.debug("Leaving parseStream(). Unread attachments.");
      throw new Error("message " + (out.length + 1) + ": attachments not " +
        "understood from " + JSON.stringify(attText.slice(used, used + 8)) +
        ".");
    }
    b += cbytes.strBytes(attText).length;
    out.push({ raw: raw, sad: sad, att: att });
  }
  log.debug("Leaving parseStream(). " + out.length + " messages.");
  return out;
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

var FIELDS = {
  icp: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  rot: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba",
        "a"],
  ixn: ["v", "t", "d", "i", "s", "p", "a"],
  vcp: ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
  iss: ["v", "t", "d", "i", "s", "ri", "dt"],
  rev: ["v", "t", "d", "i", "s", "ri", "p", "dt"]
};
var ACDC_FIELDS = ["v", "d", "u", "i", "ri", "s", "a", "A", "e", "r"];

function fieldOrder(sad) {
  log.debug("Entering fieldOrder().");
  var keys = Object.keys(sad);
  var want = sad.t ? FIELDS[sad.t] : ACDC_FIELDS;
  if (!want) {
    log.debug("Leaving fieldOrder(). Unknown ilk.");
    return "message type " + JSON.stringify(sad.t) + " is not read here.";
  }
  if (sad.t) {
    var same = keys.length === want.length && keys.every(function (k, i) {
      return k === want[i];
    });
    log.debug("Leaving fieldOrder().");
    return same ? "" : "a " + sad.t + " has exactly the fields " +
      want.join(",") + " in that order; this has " + keys.join(",") + ".";
  }
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
  log.debug("Leaving fieldOrder().");
  return ["v", "d", "i", "s"].every(function (k) {
    return keys.indexOf(k) !== -1;
  }) ? "" : "an ACDC needs v, d, i and s.";
}

function hexInt(s) {
  log.debug("Entering hexInt().");
  log.debug("Leaving hexInt().");
  return /^[0-9a-f]+$/.test(String(s)) ? parseInt(s, 16) : NaN;
}

// Numeric thresholds only; a weighted one is refused by name.
function threshold(kt) {
  log.debug("Entering threshold().");
  if (Array.isArray(kt)) {
    log.debug("Leaving threshold(). Weighted.");
    throw new Error("weighted (fractional) signing thresholds are not " +
                    "checked here yet.");
  }
  log.debug("Leaving threshold().");
  return hexInt(kt);
}

// The issuer's key state from its KEL messages, in order. Answers
// { ok, reason, prefix, events: [{ sn, said, t, raw, a }], keys,
// establishment }.
function verifyKel(messages) {
  log.debug("Entering verifyKel().");
  var state = { ok: false, prefix: null, events: [], keys: null, next: null,
                nt: 0, kt: 0, sn: -1, last: null };
  var fail = function (m, why) {
    state.reason = "KEL event " + (m ? m.sad.t + " " + m.sad.s : "") + ": " +
      why;
    return state;
  };
  for (var i = 0; i < messages.length; i++) {
    var m = messages[i];
    var sad = m.sad;
    var why = checkVersionSize(m.raw, sad) || fieldOrder(sad);
    if (why) return fail(m, why);
    var said = checkSaid(m.raw, sad.t === "icp" && sad.i === sad.d ?
                         ["d", "i"] : ["d"]);
    if (!said.ok) return fail(m, said.reason);
    var sn = hexInt(sad.s);
    if (sn !== state.sn + 1) {
      return fail(m, "sequence number " + sad.s + " follows " + state.sn +
                  " (a gap, or duplicity).");
    }
    if (sad.t === "icp") {
      if (sn !== 0) return fail(m, "an icp is sequence number 0.");
      var basic = sad.i !== sad.d;
      if (basic && (sad.k.length !== 1 || sad.k[0] !== sad.i)) {
        return fail(m, "a basic prefix is its single key.");
      }
      state.prefix = sad.i;
    } else {
      if (sad.i !== state.prefix) return fail(m, "not this AID's event.");
      if (sad.p !== state.last) {
        return fail(m, "p is not the previous event's SAID.");
      }
    }
    var keys = sad.t === "ixn" ? state.keys : sad.k;
    var kt;
    try {
      kt = sad.t === "ixn" ? state.kt : threshold(sad.kt);
    } catch (e) {
      return fail(m, e.message);
    }
    var verified = {};
    var nextOk = {};
    m.att.sigs.forEach(function (s) {
      var key = keys[s.index];
      if (!key) return;
      var k = decodeMatter(key);
      if (!verifyRaw(KEY_ALGS[k.code], k.raw, s.sig, m.raw)) return;
      verified[s.index] = true;
      if (sad.t === "rot" && s.ondex !== null && state.next &&
          state.next[s.ondex] === digestQb64(key)) {
        nextOk[s.ondex] = true;
      }
    });
    var count = Object.keys(verified).length;
    if (count < kt) {
      return fail(m, count + " verified signature(s) of the " + kt +
                  " the threshold needs.");
    }
    if (sad.t === "rot" && Object.keys(nextOk).length < state.nt) {
      return fail(m, "the rotated-in keys do not satisfy the prior next " +
                  "threshold (" + state.nt + "): their digests are not the " +
                  "prior event's n.");
    }
    if (sad.t !== "ixn") {
      state.keys = sad.k;
      state.kt = kt;
      state.next = sad.n;
      state.nt = hexInt(sad.nt);
    }
    state.sn = sn;
    state.last = sad.d;
    state.events.push({ sn: sn, said: sad.d, t: sad.t, a: sad.a,
                        verified: count });
  }
  state.ok = !!state.prefix;
  if (!state.ok) state.reason = "no inception event.";
  log.debug("Leaving verifyKel(). " + state.ok);
  return state;
}

// Is `event` (a registry event) anchored, per its -G seal source couple, by
// an issuer KEL event whose a is exactly [{i, s, d}] of it?
function anchored(kel, message) {
  log.debug("Entering anchored().");
  var src = message.att.sourceSeals[0];
  if (!src) {
    log.debug("Leaving anchored(). No couple.");
    return "it carries no seal source couple (-G) naming its anchor.";
  }
  var ev = kel.events.filter(function (e) {
    return e.sn === src.s;
  })[0];
  if (!ev || ev.said !== src.d) {
    log.debug("Leaving anchored(). No such event.");
    return "its anchor, KEL event " + src.s + " " + src.d + ", is not in " +
      "the issuer's verified KEL.";
  }
  var seals = ev.a || [];
  var sad = message.sad;
  var seal = seals[0] || {};
  if (seals.length !== 1 || seal.i !== sad.i || seal.s !== sad.s ||
      seal.d !== sad.d) {
    log.debug("Leaving anchored(). Seal.");
    return "KEL event " + src.s + "'s a is not exactly one seal {i, s, d} " +
      "of it (keri-ts and keripy require exactly one).";
  }
  log.debug("Leaving anchored().");
  return "";
}

// A whole presentation stream: the issuer's KEL, its registry (vcp), the
// credential's TEL (iss, rev?) and the ACDC with its -I triple. opts:
// { schema (object, optional: its $id is checked and the s matched) }.
// Answers { valid, revoked, reason, checks: [{ name, ok, detail }], acdc,
// issuer, kel }.
function verifyPresentation(input, opts) {
  log.debug("Entering verifyPresentation().");
  var o = opts || {};
  var checks = [];
  var add = function (name, ok, detail) {
    checks.push({ name: name, ok: ok, detail: detail || "" });
    return ok;
  };
  var out = { valid: false, revoked: false, checks: checks };
  var messages;
  try {
    messages = parseStream(input);
  } catch (e) {
    add("the CESR stream parses", false, e.message);
    out.reason = e.message;
    log.debug("Leaving verifyPresentation(). Unparseable.");
    return out;
  }
  add("the CESR stream parses", true, messages.length + " messages");
  var kelMsgs = messages.filter(function (m) {
    return FIELDS[m.sad.t] && ["icp", "rot", "ixn"].indexOf(m.sad.t) !== -1;
  });
  var acdcs = messages.filter(function (m) {
    return !m.sad.t && /^ACDC/.test(String(m.sad.v));
  });
  var acdcMsg = acdcs[acdcs.length - 1];
  var finish = function (reason) {
    out.reason = reason;
    log.debug("Leaving verifyPresentation(). " + reason);
    return out;
  };
  if (!acdcMsg) return finish("the stream carries no ACDC.");
  var acdc = acdcMsg.sad;
  out.acdc = acdc;
  out.issuer = acdc.i;
  var kel = verifyKel(kelMsgs.filter(function (m) {
    return m.sad.i === acdc.i;
  }));
  out.kel = kel;
  if (!add("the issuer's KEL verifies (signatures, thresholds, chaining)",
           kel.ok, kel.ok ? kel.events.length + " events, prefix " +
           kel.prefix : kel.reason)) {
    return finish(kel.reason);
  }
  var why = checkVersionSize(acdcMsg.raw, acdc) || fieldOrder(acdc);
  if (!add("the ACDC's version string and field order", !why, why)) {
    return finish(why);
  }
  var top = checkSaid(acdcMsg.raw, ["d"]);
  if (!add("the ACDC's SAID is its bytes' digest", top.ok, top.reason)) {
    return finish(top.reason);
  }
  ["a", "e", "r"].forEach(function (sec) {
    if (acdc[sec] && typeof acdc[sec] === "object" && acdc[sec].d) {
      var r = checkSaid(JSON.stringify(acdc[sec]), ["d"]);
      add("section " + sec + "'s SAID", r.ok, r.ok ? r.said :
          r.reason + " (re-serialized: a section is checked over " +
          "JSON.stringify of it)");
    }
  });
  var vcpMsg = messages.filter(function (m) {
    return m.sad.t === "vcp" && m.sad.i === acdc.ri;
  })[0];
  if (!vcpMsg) return finish("the registry " + acdc.ri + " (vcp) is not in " +
                             "the stream.");
  var vsaid = checkSaid(vcpMsg.raw, ["d", "i"]);
  var vok = vsaid.ok && !fieldOrder(vcpMsg.sad) &&
      vcpMsg.sad.ii === acdc.i && vcpMsg.sad.s === "0";
  if (!add("the registry inception (vcp): SAID, issuer ii, s 0", vok,
           vok ? acdc.ri : vsaid.reason || "ii is not the ACDC's issuer, " +
           "or s is not 0.")) {
    return finish("the registry inception does not verify.");
  }
  var va = anchored(kel, vcpMsg);
  if (!add("the vcp is anchored in the issuer's KEL", !va, va)) {
    return finish(va);
  }
  var tel = messages.filter(function (m) {
    return (m.sad.t === "iss" || m.sad.t === "rev") && m.sad.i === acdc.d;
  });
  var iss = tel.filter(function (m) {
    return m.sad.t === "iss";
  })[0];
  if (!iss) return finish("no iss for " + acdc.d + " in the stream.");
  var isaid = checkSaid(iss.raw, ["d"]);
  var iok = isaid.ok && !fieldOrder(iss.sad) && iss.sad.s === "0" &&
      iss.sad.ri === acdc.ri;
  if (!add("the issuance event (iss): SAID, s 0, ri", iok, iok ? iss.sad.d :
           isaid.reason || "s is not 0 or ri is not the ACDC's.")) {
    return finish("the issuance event does not verify.");
  }
  var ia = anchored(kel, iss);
  if (!add("the iss is anchored in the issuer's KEL", !ia, ia)) {
    return finish(ia);
  }
  var triple = acdcMsg.att.sourceTriples[0];
  var tok = !!triple && triple.i === acdc.d && triple.s === 0 &&
      triple.d === iss.sad.d;
  add("the ACDC's -I seal source triple names this iss", tok, tok ? "" :
      "the ACDC's attached triple does not name (its SAID, 0, the iss " +
      "SAID).");
  if (o.schema) {
    var sid = o.schema.$id;
    var tmp = Object.assign({}, o.schema, { $id: DUMMY });
    var computed = digestQb64(JSON.stringify(tmp));
    add("the schema's $id is its SAID", computed === sid, computed === sid ?
        sid : "the schema's $id " + sid + " is not its digest " + computed +
        ".");
    add("the ACDC names this schema", acdc.s === sid, acdc.s === sid ? "" :
        "s is " + acdc.s + ".");
  }
  var rev = tel.filter(function (m) {
    return m.sad.t === "rev";
  })[0];
  if (rev) {
    var rsaid = checkSaid(rev.raw, ["d"]);
    var rok = rsaid.ok && rev.sad.p === iss.sad.d && rev.sad.s === "1" &&
        !anchored(kel, rev);
    add("a revocation (rev), anchored", rok, rok ? "the credential is " +
        "REVOKED" : "a rev is present and does not verify: " +
        (rsaid.reason || anchored(kel, rev) || "p or s"));
    out.revoked = rok;
  }
  out.valid = checks.every(function (c) {
    return c.ok;
  }) && !out.revoked;
  out.reason = out.valid ? "" : out.revoked ? "the credential is revoked." :
      checks.filter(function (c) {
        return !c.ok;
      }).map(function (c) {
        return c.name + ": " + c.detail;
      })[0];
  log.debug("Leaving verifyPresentation(). " + out.valid);
  return out;
}

// ---------------------------------------------------------------------------
// Issuing.
// ---------------------------------------------------------------------------

function dateTime(when) {
  log.debug("Entering dateTime().");
  log.debug("Leaving dateTime().");
  return new Date(when === undefined ? Date.now() : when).toISOString()
    .replace("Z", "000+00:00");
}

function signed(raw, keys) {
  log.debug("Entering signed().");
  var sigs = keys.map(function (k, i) {
    return encodeIndexed(sign(k, cbytes.strBytes(raw)), i);
  });
  log.debug("Leaving signed().");
  return raw + counter("-A", sigs.length) + sigs.join("");
}

// A single-key, self-addressing, transferable issuer: its icp, signed.
function incept(key, nextKey) {
  log.debug("Entering incept().");
  var icp = saidify({ v: "KERI10JSON000000_", t: "icp", d: "", i: "",
    s: "0", kt: "1", k: [key.verkey], nt: "1",
    n: [digestQb64(nextKey.verkey)], bt: "0", b: [], c: [], a: [] },
    ["d", "i"]);
  log.debug("Leaving incept().");
  return icp;
}

function interact(prefix, sn, prior, seals) {
  log.debug("Entering interact().");
  log.debug("Leaving interact().");
  return saidify({ v: "KERI10JSON000000_", t: "ixn", d: "", i: prefix,
                   s: sn.toString(16), p: prior, a: seals });
}

// A whole issuance, as signify-ts / KERIA produce it, and the presentation
// stream a verifier receives. opts: { key, nextKey (the issuer's; new ones
// otherwise), schema ($id is computed when it is "" or absent), attributes
// (object; dt is added), recipient (a.i, optional), when }. Answers
// { stream, acdc, icp, vcp, iss, schema, key, nextKey }.
function issue(opts) {
  log.debug("Entering issue().");
  var o = opts || {};
  var key = o.key || newKey();
  var nextKey = o.nextKey || newKey();
  var dt = dateTime(o.when);
  var schema = Object.assign({ $id: "" }, o.schema || {
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "Debugger ACDC", type: "object",
    credentialType: "IdProtoDebuggerExample", version: "1.0.0" });
  schema = (function () {
    var t = Object.assign({}, schema, { $id: DUMMY });
    var said = digestQb64(JSON.stringify(t));
    return Object.assign({}, t, { $id: said });
  })();
  var icp = incept(key, nextKey);
  var aid = icp.i;
  var vcp = saidify({ v: "KERI10JSON000000_", t: "vcp", d: "", i: "",
    ii: aid, s: "0", c: ["NB"], bt: "0", b: [],
    n: encodeMatter("A", cbytes.randomBytes(32)) }, ["d", "i"]);
  var attrs = Object.assign({ d: "" }, o.recipient ? { i: o.recipient } : {},
                            o.attributes || {}, { dt: dt });
  var a = saidify(attrs);
  var acdc = saidify({ v: "ACDC10JSON000000_", d: "", i: aid, ri: vcp.i,
                       s: schema.$id, a: a });
  var iss = saidify({ v: "KERI10JSON000000_", t: "iss", d: "", i: acdc.d,
                      s: "0", ri: vcp.i, dt: dt });
  var ixn1 = interact(aid, 1, icp.d, [{ i: vcp.i, s: "0", d: vcp.d }]);
  var ixn2 = interact(aid, 2, ixn1.d, [{ i: acdc.d, s: "0", d: iss.d }]);
  var telCouple = function (sn, said) {
    var body = counter("-G", 1) + seqner(sn) + said;
    return counter("-V", body.length / 4) + body;
  };
  var stream = [icp, ixn1, ixn2].map(function (e) {
    return signed(JSON.stringify(e), [key]);
  }).join("") +
    JSON.stringify(vcp) + telCouple(1, ixn1.d) +
    JSON.stringify(iss) + telCouple(2, ixn2.d) +
    JSON.stringify(acdc) + counter("-I", 1) + acdc.d + seqner(0) + iss.d;
  log.debug("Leaving issue().");
  return { stream: stream, acdc: acdc, icp: icp, vcp: vcp, iss: iss,
           ixns: [ixn1, ixn2], schema: schema, key: key, nextKey: nextKey };
}

// Revoke: a rev in the TEL, anchored by a further ixn. Answers the stream
// with both appended.
function revoke(issued, when) {
  log.debug("Entering revoke().");
  var rev = saidify({ v: "KERI10JSON000000_", t: "rev", d: "",
    i: issued.acdc.d, s: "1", ri: issued.vcp.i, p: issued.iss.d,
    dt: dateTime(when) });
  var last = issued.ixns[issued.ixns.length - 1];
  var ixn3 = interact(issued.icp.i, issued.ixns.length + 1, last.d,
                      [{ i: rev.i, s: "1", d: rev.d }]);
  var body = counter("-G", 1) + seqner(issued.ixns.length + 1) + ixn3.d;
  log.debug("Leaving revoke().");
  return issued.stream + signed(JSON.stringify(ixn3), [issued.key]) +
    JSON.stringify(rev) + counter("-V", body.length / 4) + body;
}

module.exports = {
  SPEC: SPEC,
  MATTER: MATTER,
  encodeMatter: encodeMatter,
  decodeMatter: decodeMatter,
  encodeIndexed: encodeIndexed,
  decodeIndexed: decodeIndexed,
  seqner: seqner,
  intToB64: intToB64,
  b64ToInt: b64ToInt,
  digestQb64: digestQb64,
  saidify: saidify,
  checkSaid: checkSaid,
  keyFromSeed: keyFromSeed,
  newKey: newKey,
  parseStream: parseStream,
  verifyKel: verifyKel,
  verifyPresentation: verifyPresentation,
  incept: incept,
  issue: issue,
  revoke: revoke,
  dateTime: dateTime
};
