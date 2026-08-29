// File: hbs.js
//
// ---------------------------------------------------------------------------
// STATEFUL HASH-BASED SIGNATURES — the two schemes NIST SP 800-208 approves,
// and the only signatures in this application whose PRIVATE KEY CHANGES EVERY
// TIME YOU USE IT.
//
//   * LMS and HSS      — RFC 8554, plus the SHA-256/192 and SHAKE256
//                        parameter sets of RFC 9858
//   * XMSS and XMSS^MT — RFC 8391, plus the SHA-256/192 and SHAKE256
//                        parameter sets of SP 800-208 section 5
//
// WHY THEY ARE HERE, BESIDE SLH-DSA RATHER THAN INSTEAD OF IT. FIPS 205's
// SLH-DSA and these two are the same idea — a Merkle tree over one-time
// signatures, secure if the hash function is — and they differ in the one
// place that decides whether you can deploy them: SLH-DSA is STATELESS and
// picks its one-time key at random from a space large enough that a collision
// is negligible, while these are STATEFUL and the signer must remember which
// one-time keys it has spent. That is a smaller, faster, older design (LMS
// signatures are a few kilobytes where SLH-DSA's are 8 to 50), and it is why
// NIST approved them years before FIPS 205 and restricted them, in SP
// 800-208 section 1, to applications where the state can be guaranteed —
// firmware and software signing above all.
//
// THE STATE IS THE WHOLE SUBJECT, so this module is built around it rather
// than hiding it. Every private key here carries its own index (`q` for LMS,
// `idx` for XMSS); `sign()` REFUSES to run without being handed the updated
// key back, `remaining()` says how many signatures are left, and an exhausted
// key is an error rather than a wrap-around. Reusing one index for two
// different messages does not merely weaken these schemes — it hands an
// attacker the material to forge a signature on a THIRD message, which is why
// RFC 8554 section 5.4.1 requires the incremented index to reach non-volatile
// storage BEFORE the signature is released, and why `signTwiceFromOneIndex()`
// exists in this module: a debugger that can only demonstrate the safe path
// cannot show what the rule is for.
//
// WHAT A BROWSER CAN AND CANNOT DO, WHICH IS NOT A LIMITATION OF THIS CODE.
// Key generation walks every leaf of the top tree, and each leaf is a full
// one-time key pair — for LMS_*_H20 that is 1,048,576 of them, tens of
// billions of hash compressions, hours in any language. VERIFICATION is
// unaffected: it hashes one authentication path, h nodes, whatever h is. So
// this module verifies, parses and describes EVERY parameter set both
// registries define, and generates keys only for the ones whose top tree is
// small enough — `keygenCost()` returns the number of leaves and `canKeygen()`
// the verdict, so a caller refuses with a number rather than hanging. That
// division is also the best possible motivation for the multi-tree variants:
// HSS with L=2 and XMSS^MT with d=2 reach 2^20 signatures while generating
// only a 2^10 tree, and this is the one place you can watch that happen.
//
// NO DOM AND NO STORAGE — like jws.js, the encryption engines and hash_tools.js
// — which is what lets tests/hbs_signatures.js drive all of it in node against
// RFC 8554's own test cases, RFC 9858's, and signatures and keys produced by
// OTHER implementations. That last part matters more here than anywhere else
// in this tree: hash-based signatures are simple enough to implement and
// unforgiving enough to get subtly wrong, and every one of the mistakes worth
// making — a domain separator dropped, a padding length of n where the
// 192-bit parameter sets want 4, an authentication path applied in the wrong
// order — produces a scheme that signs and verifies against itself perfectly
// and interoperates with nothing.
//
// THE PRIVATE KEY FORMAT HERE IS THIS TOOL'S OWN, AND IT HAS TO BE. Both
// specifications define the public key and the signature down to the byte and
// deliberately leave the private key to the implementation (RFC 8554 section
// 5.2: "an internal matter to the implementation"; RFC 8391 section 4.1.3
// likewise), because nothing interoperable depends on it. What this module
// stores is the seed the key is derived from plus the index — see
// `serializePrivateKey()`, which names its own magic so a reader is never
// misled into thinking it is standard.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// A node consumer (tests/hbs_signatures.js loads this module directly) may
// have no CONFIG_FILE, so fall back to info rather than failing to load — the
// block crypto_bytes.js carries, for the same reason.
var log = bunyan.createLogger({
  name: "hbs",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512").sha512;
var nobleSha3 = require("@noble/hashes/sha3");
var bytesLib = require("./crypto_bytes");

var bytesEqual = bytesLib.bytesEqual;
var randomBytes = bytesLib.randomBytes;

// CONCATENATION IS DELIBERATELY NOT `crypto_bytes`'s HERE, and it is a
// hot-path decision rather than a stylistic one. That module's version logs
// on entry and exit and calls `asBytes()` — which logs twice more — on each
// argument, which is exactly right for a page that joins a handful of buffers
// per click and ruinous five times per Winternitz step, a million steps per
// key. `client/src/env/local.js` and `docker-tests.js` both set logLevel
// "debug", so on both test stacks that would be tens of millions of
// serialized records for one key generation. Everything in this module that
// runs once per operation still uses the shared helpers.
function cat() {
  var total = 0;
  var i;
  for (i = 0; i < arguments.length; i++) {
    total += arguments[i].length;
  }
  var out = new Uint8Array(total);
  var offset = 0;
  for (i = 0; i < arguments.length; i++) {
    out.set(arguments[i], offset);
    offset += arguments[i].length;
  }
  return out;
}

// BigInt literals are a syntax error to the bundler's parser — see the "No
// BigInt literals in client/src" section of client/CLAUDE.md. The XMSS tree
// address is 64 bits wide and an XMSS^MT index can be 60, so the arithmetic
// that splits an index into a tree address and a leaf address is done in
// BigInt and these are its constants.
var _B0 = BigInt(0);
var _B1 = BigInt(1);
var _B32 = BigInt(32);
var _BMASK32 = BigInt(0xffffffff);

// ===========================================================================
// Hash functions
//
// Six of them across the two schemes, and three are TRUNCATIONS rather than
// distinct functions: RFC 9858 section 2 defines SHA-256/192 as SHA-256 with
// the last 64 bits dropped ("we use the same initial hash value as the
// untruncated SHA-256, rather than defining a distinct one, so that we can
// use a standard SHA-256 implementation without modification"), and
// SHAKE256/256 and SHAKE256/192 as the first 256 and 192 bits of SHAKE256's
// output. SP 800-208 does the same for the XMSS 192-bit parameter sets.
// ===========================================================================
function sha256Trunc(bytes, outLen) {
  var full = nobleSha256(bytes);
  return outLen === full.length ? full : full.slice(0, outLen);
}

var HASHES = {
  // name: function (bytes, outLen) -> Uint8Array of outLen bytes
  sha256: function (bytes, outLen) { return sha256Trunc(bytes, outLen); },
  sha512: function (bytes, outLen) {
    var full = nobleSha512(bytes);
    return outLen === full.length ? full : full.slice(0, outLen);
  },
  shake128: function (bytes, outLen) {
    return nobleSha3.shake128(bytes, { dkLen: outLen });
  },
  shake256: function (bytes, outLen) {
    return nobleSha3.shake256(bytes, { dkLen: outLen });
  }
};

// ===========================================================================
// Byte helpers. u32str/u16str/u8str are RFC 8554's names; toByte is RFC
// 8391's. They are the same operation and both names are kept, because the
// algorithms below are transcriptions of two documents and a reader checking
// one against the other should not have to translate.
// ===========================================================================
function u32str(value) {
  var out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

function u16str(value) {
  var out = new Uint8Array(2);
  out[0] = (value >>> 8) & 0xff;
  out[1] = value & 0xff;
  return out;
}

function u8str(value) {
  var out = new Uint8Array(1);
  out[0] = value & 0xff;
  return out;
}

// toByte(x, y) from RFC 8391 section 2.4: y bytes, big-endian.
//
// THE NUMBER PATH IS NOT AN OPTIMISATION THAT CAN BE SKIPPED. `value` may be
// a BigInt, because an XMSS^MT index does not fit in a Number once h passes
// 53 — but the overwhelmingly common call is a padding constant of 0 to 4,
// three times per Winternitz step, three million times per key generation.
// Doing that in BigInt took XMSS-SHA2_10_256 key generation from four
// seconds to six and a half.
function toByte(value, length) {
  var out = new Uint8Array(length);
  var i;
  if (typeof value === "number" && value <= Number.MAX_SAFE_INTEGER) {
    var v = value;
    for (i = length - 1; i >= 0; i--) {
      out[i] = v % 256;
      v = Math.floor(v / 256);
    }
    return out;
  }
  var big = typeof value === "bigint" ? value : BigInt(value);
  for (i = length - 1; i >= 0; i--) {
    out[i] = Number(big & BigInt(0xff));
    big = big >> BigInt(8);
  }
  return out;
}

function strTou32(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
          (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function bytesToBig(bytes) {
  var v = _B0;
  for (var i = 0; i < bytes.length; i++) {
    v = (v << BigInt(8)) | BigInt(bytes[i]);
  }
  return v;
}

// ===========================================================================
// LM-OTS and LMS parameter sets (RFC 8554 Table 1 and Table 2, RFC 9858
// Tables 1 and 2). The identifiers are the IANA registry's and appear in the
// wire format, so they are the key here rather than the name.
//
// `p` and `ls` are COMPUTED by RFC 8554 Appendix B rather than transcribed,
// because the two documents publish the same four-line algorithm and eight
// tabulated rows and only one of those can be wrong in a way a test would
// catch. tests/hbs_signatures.js asserts the computation against every
// published row.
// ===========================================================================
function lmotsInternals(n, w) {
  var u = Math.ceil(8 * n / w);
  var v = Math.ceil((Math.floor(Math.log2((Math.pow(2, w) - 1) * u)) + 1) / w);
  return { u: u, v: v, ls: 16 - (v * w), p: u + v };
}

function lmotsSet(id, name, hash, n, w) {
  var internals = lmotsInternals(n, w);
  return { id: id, name: name, hash: hash, n: n, w: w,
           p: internals.p, ls: internals.ls,
           sigLen: 4 + n * (internals.p + 1) };
}

var LMOTS = [
  lmotsSet(1, "LMOTS_SHA256_N32_W1", "sha256", 32, 1),
  lmotsSet(2, "LMOTS_SHA256_N32_W2", "sha256", 32, 2),
  lmotsSet(3, "LMOTS_SHA256_N32_W4", "sha256", 32, 4),
  lmotsSet(4, "LMOTS_SHA256_N32_W8", "sha256", 32, 8),
  lmotsSet(5, "LMOTS_SHA256_N24_W1", "sha256", 24, 1),
  lmotsSet(6, "LMOTS_SHA256_N24_W2", "sha256", 24, 2),
  lmotsSet(7, "LMOTS_SHA256_N24_W4", "sha256", 24, 4),
  lmotsSet(8, "LMOTS_SHA256_N24_W8", "sha256", 24, 8),
  lmotsSet(9, "LMOTS_SHAKE_N32_W1", "shake256", 32, 1),
  lmotsSet(10, "LMOTS_SHAKE_N32_W2", "shake256", 32, 2),
  lmotsSet(11, "LMOTS_SHAKE_N32_W4", "shake256", 32, 4),
  lmotsSet(12, "LMOTS_SHAKE_N32_W8", "shake256", 32, 8),
  lmotsSet(13, "LMOTS_SHAKE_N24_W1", "shake256", 24, 1),
  lmotsSet(14, "LMOTS_SHAKE_N24_W2", "shake256", 24, 2),
  lmotsSet(15, "LMOTS_SHAKE_N24_W4", "shake256", 24, 4),
  lmotsSet(16, "LMOTS_SHAKE_N24_W8", "shake256", 24, 8)
];

function lmsSet(id, name, hash, m, h) {
  return { id: id, name: name, hash: hash, m: m, h: h };
}

var LMS = [
  lmsSet(5, "LMS_SHA256_M32_H5", "sha256", 32, 5),
  lmsSet(6, "LMS_SHA256_M32_H10", "sha256", 32, 10),
  lmsSet(7, "LMS_SHA256_M32_H15", "sha256", 32, 15),
  lmsSet(8, "LMS_SHA256_M32_H20", "sha256", 32, 20),
  lmsSet(9, "LMS_SHA256_M32_H25", "sha256", 32, 25),
  lmsSet(10, "LMS_SHA256_M24_H5", "sha256", 24, 5),
  lmsSet(11, "LMS_SHA256_M24_H10", "sha256", 24, 10),
  lmsSet(12, "LMS_SHA256_M24_H15", "sha256", 24, 15),
  lmsSet(13, "LMS_SHA256_M24_H20", "sha256", 24, 20),
  lmsSet(14, "LMS_SHA256_M24_H25", "sha256", 24, 25),
  lmsSet(15, "LMS_SHAKE_M32_H5", "shake256", 32, 5),
  lmsSet(16, "LMS_SHAKE_M32_H10", "shake256", 32, 10),
  lmsSet(17, "LMS_SHAKE_M32_H15", "shake256", 32, 15),
  lmsSet(18, "LMS_SHAKE_M32_H20", "shake256", 32, 20),
  lmsSet(19, "LMS_SHAKE_M32_H25", "shake256", 32, 25),
  lmsSet(20, "LMS_SHAKE_M24_H5", "shake256", 24, 5),
  lmsSet(21, "LMS_SHAKE_M24_H10", "shake256", 24, 10),
  lmsSet(22, "LMS_SHAKE_M24_H15", "shake256", 24, 15),
  lmsSet(23, "LMS_SHAKE_M24_H20", "shake256", 24, 20),
  lmsSet(24, "LMS_SHAKE_M24_H25", "shake256", 24, 25)
];

// ===========================================================================
// XMSS and XMSS^MT parameter sets.
//
// The hash family and n come from the NAME, and `padding` is the one value
// that cannot: SP 800-208 gives the 192-bit parameter sets a FOUR-byte
// function padding where RFC 8391's own sets use n bytes. Nothing about the
// name says so, both choices produce a working scheme, and the two do not
// interoperate — so it is a field here rather than a rule.
// ===========================================================================
function xmssHashOf(name) {
  if (name.indexOf("SHAKE256") >= 0) {
    return "shake256";
  }
  if (name.indexOf("SHAKE") >= 0) {
    // RFC 8391 section 5.1: the SHAKE sets use SHAKE128 at n = 32 and
    // SHAKE256 at n = 64. SP 800-208's "SHAKE256_" sets are caught above.
    return name.indexOf("_512") >= 0 ? "shake256" : "shake128";
  }
  return name.indexOf("_512") >= 0 ? "sha512" : "sha256";
}

function xmssSet(id, name, n, h, d) {
  return { id: id, name: name, hash: xmssHashOf(name), n: n, w: 16, h: h,
           d: d, padding: n === 24 ? 4 : n,
           multiTree: d > 1 };
}

var XMSS = [
  xmssSet(1, "XMSS-SHA2_10_256", 32, 10, 1),
  xmssSet(2, "XMSS-SHA2_16_256", 32, 16, 1),
  xmssSet(3, "XMSS-SHA2_20_256", 32, 20, 1),
  xmssSet(4, "XMSS-SHA2_10_512", 64, 10, 1),
  xmssSet(5, "XMSS-SHA2_16_512", 64, 16, 1),
  xmssSet(6, "XMSS-SHA2_20_512", 64, 20, 1),
  xmssSet(7, "XMSS-SHAKE_10_256", 32, 10, 1),
  xmssSet(8, "XMSS-SHAKE_16_256", 32, 16, 1),
  xmssSet(9, "XMSS-SHAKE_20_256", 32, 20, 1),
  xmssSet(10, "XMSS-SHAKE_10_512", 64, 10, 1),
  xmssSet(11, "XMSS-SHAKE_16_512", 64, 16, 1),
  xmssSet(12, "XMSS-SHAKE_20_512", 64, 20, 1),
  xmssSet(13, "XMSS-SHA2_10_192", 24, 10, 1),
  xmssSet(14, "XMSS-SHA2_16_192", 24, 16, 1),
  xmssSet(15, "XMSS-SHA2_20_192", 24, 20, 1),
  xmssSet(16, "XMSS-SHAKE256_10_256", 32, 10, 1),
  xmssSet(17, "XMSS-SHAKE256_16_256", 32, 16, 1),
  xmssSet(18, "XMSS-SHAKE256_20_256", 32, 20, 1),
  xmssSet(19, "XMSS-SHAKE256_10_192", 24, 10, 1),
  xmssSet(20, "XMSS-SHAKE256_16_192", 24, 16, 1),
  xmssSet(21, "XMSS-SHAKE256_20_192", 24, 20, 1)
];

// The XMSS^MT registry, built from the (h, d) grid each family publishes
// rather than typed out 56 times — the identifiers are consecutive within
// each family and the test asserts every name and number against the IANA
// registry, which is what makes generating them safe.
var XMSSMT_SHAPES = [[20, 2], [20, 4], [40, 2], [40, 4], [40, 8],
                     [60, 3], [60, 6], [60, 12]];

var XMSSMT = (function () {
  var families = [
    { prefix: "XMSSMT-SHA2_", suffix: "_256", n: 32 },
    { prefix: "XMSSMT-SHA2_", suffix: "_512", n: 64 },
    { prefix: "XMSSMT-SHAKE_", suffix: "_256", n: 32 },
    { prefix: "XMSSMT-SHAKE_", suffix: "_512", n: 64 },
    { prefix: "XMSSMT-SHA2_", suffix: "_192", n: 24 },
    { prefix: "XMSSMT-SHAKE256_", suffix: "_256", n: 32 },
    { prefix: "XMSSMT-SHAKE256_", suffix: "_192", n: 24 }
  ];
  var out = [];
  var id = 1;
  for (var f = 0; f < families.length; f++) {
    for (var s = 0; s < XMSSMT_SHAPES.length; s++) {
      var h = XMSSMT_SHAPES[s][0];
      var d = XMSSMT_SHAPES[s][1];
      var name = families[f].prefix + h + "/" + d + families[f].suffix;
      out.push(xmssSet(id, name, families[f].n, h, d));
      id++;
    }
  }
  return out;
})();

function indexBy(list, key) {
  var map = {};
  for (var i = 0; i < list.length; i++) {
    map[list[i][key]] = list[i];
  }
  return map;
}

var LMOTS_BY_ID = indexBy(LMOTS, "id");
var LMOTS_BY_NAME = indexBy(LMOTS, "name");
var LMS_BY_ID = indexBy(LMS, "id");
var LMS_BY_NAME = indexBy(LMS, "name");
var XMSS_BY_ID = indexBy(XMSS, "id");
var XMSS_BY_NAME = indexBy(XMSS, "name");
var XMSSMT_BY_ID = indexBy(XMSSMT, "id");
var XMSSMT_BY_NAME = indexBy(XMSSMT, "name");

// ===========================================================================
// LM-OTS (RFC 8554 section 4)
//
// THE FUNCTIONS BELOW ARE A HOT PATH AND DO NOT LOG. Generating one LMS
// public key at H10/W8 is 1024 leaves times 8,671 hash computations, and a
// `log.debug` pair inside `coef()` or the Winternitz loop would be the entire
// log and most of the runtime — the failure recorded against saml_tools.js in
// the repo-root CLAUDE.md, one order of magnitude worse. The entry points
// (keygen, sign, verify, parse) log; everything they call does not.
// ===========================================================================

// The fixed domain separators. Every hash in this system is prefixed by one
// of them, which is what stops a value computed for one purpose being
// accepted as a value of another — the property RFC 8554 section 7.1 calls
// the security string.
var D_PBLC = 0x8080;
var D_MESG = 0x8181;
var D_LEAF = 0x8282;
var D_INTR = 0x8383;

function coef(S, i, w) {
  var shift = 8 - (w * (i % (8 / w)) + w);
  return (Math.pow(2, w) - 1) & (S[Math.floor(i * w / 8)] >> shift);
}

// Algorithm 2. `sum` is a 16-bit unsigned integer and the left shift by ls is
// what moves the bits that matter into the digits the signature will carry;
// dropping it produces a checksum that is always zero in the digits used,
// which is a scheme with no checksum at all and still round-trips.
function cksm(otsParams, S) {
  var sum = 0;
  var limit = otsParams.n * 8 / otsParams.w;
  var max = Math.pow(2, otsParams.w) - 1;
  for (var i = 0; i < limit; i++) {
    sum = sum + max - coef(S, i, otsParams.w);
  }
  return u16str((sum << otsParams.ls) & 0xffff);
}

function lmotsHash(otsParams, parts) {
  return HASHES[otsParams.hash](cat.apply(null, parts),
                                otsParams.n);
}

// Appendix A: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
// The 0xff is the whole of what separates this from a Winternitz step, whose
// index reaches 254 at most.
function lmotsPrivateElement(otsParams, I, q, i, seed) {
  return lmotsHash(otsParams,
      [I, u32str(q), u16str(i), u8str(0xff), seed]);
}

// Algorithm 1, returning only K — the caller already knows I and q.
function lmotsPublicKeyHash(otsParams, I, q, seed) {
  var max = Math.pow(2, otsParams.w) - 1;
  var parts = [I, u32str(q), u16str(D_PBLC)];
  for (var i = 0; i < otsParams.p; i++) {
    var tmp = lmotsPrivateElement(otsParams, I, q, i, seed);
    for (var j = 0; j < max; j++) {
      tmp = lmotsHash(otsParams, [I, u32str(q), u16str(i), u8str(j), tmp]);
    }
    parts.push(tmp);
  }
  return lmotsHash(otsParams, parts);
}

// Algorithm 3. `C` is the randomizer; it is an argument rather than generated
// here so that a caller can reproduce a published test case.
function lmotsSign(otsParams, I, q, seed, message, C) {
  var Q = lmotsHash(otsParams, [I, u32str(q), u16str(D_MESG), C, message]);
  var QC = cat(Q, cksm(otsParams, Q));
  var parts = [u32str(otsParams.id), C];
  for (var i = 0; i < otsParams.p; i++) {
    var a = coef(QC, i, otsParams.w);
    var tmp = lmotsPrivateElement(otsParams, I, q, i, seed);
    for (var j = 0; j < a; j++) {
      tmp = lmotsHash(otsParams, [I, u32str(q), u16str(i), u8str(j), tmp]);
    }
    parts.push(tmp);
  }
  return cat.apply(null, parts);
}

// Algorithm 4b — the candidate public key Kc. Verification is this plus one
// comparison, and every LMS and HSS verification below goes through it.
function lmotsPublicKeyCandidate(otsParams, I, q, signature, message) {
  var n = otsParams.n;
  var expected = 4 + n * (otsParams.p + 1);
  if (signature.length !== expected) {
    throw new Error("LM-OTS signature is " + signature.length +
                    " bytes; " + otsParams.name + " signatures are " +
                    expected + ".");
  }
  var sigType = strTou32(signature, 0);
  if (sigType !== otsParams.id) {
    throw new Error("LM-OTS signature names type " + sigType +
                    " and the public key names " + otsParams.id + ".");
  }
  var C = signature.subarray(4, 4 + n);
  var Q = lmotsHash(otsParams, [I, u32str(q), u16str(D_MESG), C, message]);
  var QC = cat(Q, cksm(otsParams, Q));
  var max = Math.pow(2, otsParams.w) - 1;
  var parts = [I, u32str(q), u16str(D_PBLC)];
  for (var i = 0; i < otsParams.p; i++) {
    var a = coef(QC, i, otsParams.w);
    var offset = 4 + n * (i + 1);
    var tmp = signature.subarray(offset, offset + n);
    for (var j = a; j < max; j++) {
      tmp = lmotsHash(otsParams, [I, u32str(q), u16str(i), u8str(j), tmp]);
    }
    parts.push(tmp);
  }
  return lmotsHash(otsParams, parts);
}

// ===========================================================================
// LMS (RFC 8554 section 5)
// ===========================================================================
function lmsHash(lmsParams, parts) {
  return HASHES[lmsParams.hash](cat.apply(null, parts),
                                lmsParams.m);
}

// Every node of one LMS tree, indexed 1 .. 2^(h+1)-1 exactly as section 5.3
// numbers them, so an authentication path is a lookup rather than a second
// traversal. It is the memory-hungry option of the two RFC 8554 section 5.4.1
// offers, and it is the right one here: the trees this can generate at all
// are small, and the alternative recomputes the whole tree once per level.
function lmsTree(lmsParams, otsParams, I, seed) {
  var leaves = Math.pow(2, lmsParams.h);
  var nodes = new Array(2 * leaves);
  for (var q = 0; q < leaves; q++) {
    var K = lmotsPublicKeyHash(otsParams, I, q, seed);
    nodes[leaves + q] = lmsHash(lmsParams,
        [I, u32str(leaves + q), u16str(D_LEAF), K]);
  }
  for (var r = leaves - 1; r >= 1; r--) {
    nodes[r] = lmsHash(lmsParams,
        [I, u32str(r), u16str(D_INTR), nodes[2 * r], nodes[2 * r + 1]]);
  }
  return nodes;
}

function lmsPublicKeyBytes(lmsParams, otsParams, I, root) {
  return cat(u32str(lmsParams.id), u32str(otsParams.id), I, root);
}

function lmsAuthPath(lmsParams, nodes, q) {
  var leaves = Math.pow(2, lmsParams.h);
  var path = [];
  var node = leaves + q;
  while (node > 1) {
    path.push(nodes[node ^ 1]);
    node = node >> 1;
  }
  return path;
}

function lmsSignWithTree(lmsParams, otsParams, I, seed, nodes, q, message,
                         C) {
  var otsSig = lmotsSign(otsParams, I, q, seed, message, C);
  var path = lmsAuthPath(lmsParams, nodes, q);
  return cat.apply(null,
      [u32str(q), otsSig, u32str(lmsParams.id)].concat(path));
}

// Algorithm 6a, and the shape of it is the reason this scheme works at all:
// the verifier recomputes the ROOT from a leaf it derived itself, so the only
// thing the signer has to be trusted about is which leaf.
function lmsRootFromSignature(lmsParams, otsParams, I, signature, message) {
  var parsed = parseLmsSignature(signature, otsParams, lmsParams);
  var Kc = lmotsPublicKeyCandidate(otsParams, I, parsed.q, parsed.otsSignature,
                                   message);
  var nodeNum = Math.pow(2, lmsParams.h) + parsed.q;
  var tmp = lmsHash(lmsParams, [I, u32str(nodeNum), u16str(D_LEAF), Kc]);
  for (var i = 0; i < lmsParams.h; i++) {
    var half = Math.floor(nodeNum / 2);
    if (nodeNum % 2 === 1) {
      tmp = lmsHash(lmsParams,
          [I, u32str(half), u16str(D_INTR), parsed.path[i], tmp]);
    } else {
      tmp = lmsHash(lmsParams,
          [I, u32str(half), u16str(D_INTR), tmp, parsed.path[i]]);
    }
    nodeNum = half;
  }
  return tmp;
}

// ===========================================================================
// Parsing — the half of this module a debugger is actually for.
//
// Every length rule in Algorithm 6a is a length rule HERE, and each one is
// reported as a sentence naming the field rather than as "invalid", because a
// signature that fails to parse and a signature that parses and does not
// verify are completely different problems with completely different causes.
// ===========================================================================
function parseLmsPublicKey(bytes) {
  log.debug("Entering parseLmsPublicKey().");
  if (bytes.length < 8) {
    log.debug("Leaving parseLmsPublicKey(). Too short.");
    throw new Error("An LMS public key is at least 8 bytes; this is " +
                    bytes.length + ".");
  }
  var lmsParams = LMS_BY_ID[strTou32(bytes, 0)];
  if (!lmsParams) {
    log.debug("Leaving parseLmsPublicKey(). Unknown LMS type.");
    throw new Error("Unknown LMS typecode 0x" +
                    strTou32(bytes, 0).toString(16) + ".");
  }
  var otsParams = LMOTS_BY_ID[strTou32(bytes, 4)];
  if (!otsParams) {
    log.debug("Leaving parseLmsPublicKey(). Unknown LM-OTS type.");
    throw new Error("Unknown LM-OTS typecode 0x" +
                    strTou32(bytes, 4).toString(16) + ".");
  }
  if (bytes.length !== 24 + lmsParams.m) {
    log.debug("Leaving parseLmsPublicKey(). Wrong length.");
    throw new Error("An " + lmsParams.name + " public key is " +
                    (24 + lmsParams.m) + " bytes; this is " + bytes.length +
                    ".");
  }
  log.debug("Leaving parseLmsPublicKey().");
  return { lmsParams: lmsParams, otsParams: otsParams,
           I: bytes.subarray(8, 24), root: bytes.subarray(24),
           bytes: bytes };
}

// `otsParams` and `lmsParams` come from the PUBLIC KEY, not from the
// signature, and the typecodes inside the signature are then checked against
// them — RFC 8554 Algorithm 6a steps 2c and 2g. A parser that believed the
// signature's own typecodes would let a forger choose the parameter set, and
// would still round-trip perfectly against itself.
// `allowTrailing` is RFC 8554 section 6.3's requirement rather than a
// convenience: inside an HSS signature an LMS signature is followed by the
// public key it signed and by the next signature, so the parser must be able
// to consume one from the front of a longer string and report how many bytes
// it took. On its own an LMS signature must be exactly its own length, and
// trailing bytes there are a malformed signature rather than a longer one.
function parseLmsSignature(bytes, otsParams, lmsParams, allowTrailing) {
  if (bytes.length < 8) {
    throw new Error("An LMS signature is at least 8 bytes; this is " +
                    bytes.length + ".");
  }
  var q = strTou32(bytes, 0);
  var otsType = strTou32(bytes, 4);
  if (otsType !== otsParams.id) {
    throw new Error("The signature's LM-OTS typecode is " + otsType +
                    " and the public key's is " + otsParams.id + ".");
  }
  var otsLen = 4 + otsParams.n * (otsParams.p + 1);
  if (bytes.length < 8 + otsLen - 4) {
    throw new Error("The signature is too short to hold an " +
                    otsParams.name + " signature.");
  }
  var otsSignature = bytes.subarray(4, 4 + otsLen);
  var lmsTypeOffset = 4 + otsLen;
  var lmsType = strTou32(bytes, lmsTypeOffset);
  if (lmsType !== lmsParams.id) {
    throw new Error("The signature's LMS typecode is " + lmsType +
                    " and the public key's is " + lmsParams.id + ".");
  }
  if (q >= Math.pow(2, lmsParams.h)) {
    throw new Error("The signature's leaf index q = " + q +
                    " is outside a height-" + lmsParams.h + " tree.");
  }
  var expected = 12 + otsParams.n * (otsParams.p + 1) +
      lmsParams.m * lmsParams.h;
  if (allowTrailing ? bytes.length < expected : bytes.length !== expected) {
    throw new Error("An " + lmsParams.name + " / " + otsParams.name +
                    " signature is " + expected + " bytes; this is " +
                    bytes.length + ".");
  }
  var path = [];
  var offset = lmsTypeOffset + 4;
  for (var i = 0; i < lmsParams.h; i++) {
    path.push(bytes.subarray(offset, offset + lmsParams.m));
    offset += lmsParams.m;
  }
  return { q: q, otsSignature: otsSignature, path: path, length: expected,
           otsParams: otsParams, lmsParams: lmsParams };
}

// ===========================================================================
// HSS (RFC 8554 section 6) — a tree of LMS trees, and the reason a 2^20 key
// can be generated at all: only the top tree exists before the first
// signature.
// ===========================================================================
function parseHssPublicKey(bytes) {
  log.debug("Entering parseHssPublicKey().");
  if (bytes.length < 4) {
    log.debug("Leaving parseHssPublicKey(). Too short.");
    throw new Error("An HSS public key is at least 4 bytes; this is " +
                    bytes.length + ".");
  }
  var levels = strTou32(bytes, 0);
  if (levels < 1 || levels > 8) {
    log.debug("Leaving parseHssPublicKey(). Bad level count.");
    throw new Error("An HSS public key names " + levels + " levels; RFC " +
                    "8554 section 6 allows 1 to 8.");
  }
  var lms = parseLmsPublicKey(bytes.subarray(4));
  log.debug("Leaving parseHssPublicKey().");
  return { levels: levels, top: lms, bytes: bytes };
}

// Section 6.3. The signature carries Nspk signed public keys and Nspk+1
// signatures, and each level's public key is verified by the level above
// before it is trusted to verify the next one.
function parseHssSignature(bytes, pub) {
  log.debug("Entering parseHssSignature().");
  if (bytes.length < 4) {
    log.debug("Leaving parseHssSignature(). Too short.");
    throw new Error("An HSS signature is at least 4 bytes; this is " +
                    bytes.length + ".");
  }
  var nspk = strTou32(bytes, 0);
  if (nspk + 1 !== pub.levels) {
    log.debug("Leaving parseHssSignature(). Level mismatch.");
    throw new Error("The signature carries " + nspk + " signed public " +
                    "key(s), so it is an L = " + (nspk + 1) + " signature, " +
                    "and the public key names L = " + pub.levels + ".");
  }
  var offset = 4;
  var levels = [];
  var key = pub.top;
  for (var i = 0; i < nspk; i++) {
    var sig = parseLmsSignature(bytes.subarray(offset),
                                key.otsParams, key.lmsParams, true);
    var sigBytes = bytes.subarray(offset, offset + sig.length);
    offset += sig.length;
    var childBytes = bytes.subarray(offset);
    var child = parseLmsPublicKey(
        childBytes.subarray(0, 8 + 16 + lmsMOf(childBytes)));
    offset += child.bytes.length;
    levels.push({ signature: sig, signatureBytes: sigBytes, key: key,
                  signedKey: child });
    key = child;
  }
  var last = parseLmsSignature(bytes.subarray(offset), key.otsParams,
                               key.lmsParams, true);
  if (offset + last.length !== bytes.length) {
    log.debug("Leaving parseHssSignature(). Trailing bytes.");
    throw new Error("The HSS signature has " +
                    (bytes.length - offset - last.length) +
                    " trailing byte(s).");
  }
  log.debug("Leaving parseHssSignature().");
  return { nspk: nspk, levels: levels, finalKey: key,
           finalSignature: last,
           finalSignatureBytes: bytes.subarray(offset) };
}

// An LMS public key's length depends on the m of the parameter set it names,
// which is inside it — so a nested key inside an HSS signature cannot be
// skipped over without reading its typecode first.
function lmsMOf(bytes) {
  if (bytes.length < 8) {
    throw new Error("A nested LMS public key is truncated.");
  }
  var lmsParams = LMS_BY_ID[strTou32(bytes, 0)];
  if (!lmsParams) {
    throw new Error("A nested LMS public key names unknown typecode 0x" +
                    strTou32(bytes, 0).toString(16) + ".");
  }
  return lmsParams.m;
}

// ===========================================================================
// What a browser can afford.
//
// Key generation walks every leaf of a tree and each leaf is a full one-time
// key pair, so the cost is 2^h * (p * (2^w - 1) + 1) hash computations — a
// number that ranges from 8,500 (H5/W1) to about 9 * 10^12 (H25/W8). Callers
// ask BEFORE starting, and refuse with the number rather than freezing the
// tab. Verification is not affected by any of this and is never gated: it
// hashes one authentication path, h nodes deep, whatever h is.
// ===========================================================================
var MAX_KEYGEN_HASHES = 8000000;

function lmsKeygenCost(lmsParams, otsParams) {
  var leaves = Math.pow(2, lmsParams.h);
  return leaves * (otsParams.p * (Math.pow(2, otsParams.w) - 1) + 1) +
      2 * leaves;
}

function canKeygen(cost) {
  return cost <= MAX_KEYGEN_HASHES;
}

// The HSS private key. RFC 8554 section 5.2 leaves this format entirely to
// the implementation, so it IS ours and the magic says so — a reader must
// never be able to mistake it for something another tool will read. What it
// holds is a master seed and, per level, the two typecodes, a generation
// counter and the leaf index q. Everything else is derived: I and SEED for a
// level come from the master seed and that level's generation counter, which
// is what lets an exhausted lower tree be replaced (section 6.2) without
// storing a fresh random value anywhere.
var LMS_KEY_MAGIC = [0x4c, 0x4d, 0x53, 0x4b];

function deriveLevelIdentity(master, level, generation, lmsParams,
                             otsParams) {
  var I = HASHES[lmsParams.hash](
      cat(master, u8str(level), u32str(generation), u8str(0)), 16);
  var seed = HASHES[otsParams.hash](
      cat(master, u8str(level), u32str(generation), u8str(1)),
      otsParams.n);
  return { I: I, seed: seed };
}

function serializeLmsPrivateKey(key) {
  log.debug("Entering serializeLmsPrivateKey().");
  var parts = [new Uint8Array(LMS_KEY_MAGIC), u8str(1),
               u8str(key.levels.length), key.master];
  for (var i = 0; i < key.levels.length; i++) {
    var level = key.levels[i];
    parts.push(u32str(level.lmsParams.id), u32str(level.otsParams.id),
               u32str(level.generation), u32str(level.q));
  }
  log.debug("Leaving serializeLmsPrivateKey().");
  return cat.apply(null, parts);
}

function parseLmsPrivateKey(bytes) {
  log.debug("Entering parseLmsPrivateKey().");
  if (bytes.length < 38 || bytes[0] !== LMS_KEY_MAGIC[0] ||
      bytes[1] !== LMS_KEY_MAGIC[1] || bytes[2] !== LMS_KEY_MAGIC[2] ||
      bytes[3] !== LMS_KEY_MAGIC[3]) {
    log.debug("Leaving parseLmsPrivateKey(). Not an LMSK blob.");
    throw new Error("This is not an HSS/LMS private key from this tool " +
                    "(it does not start with LMSK).");
  }
  if (bytes[4] !== 1) {
    log.debug("Leaving parseLmsPrivateKey(). Bad version.");
    throw new Error("Unsupported HSS/LMS private key version " + bytes[4] +
                    ".");
  }
  var levelCount = bytes[5];
  var master = bytes.subarray(6, 38);
  var levels = [];
  var offset = 38;
  for (var i = 0; i < levelCount; i++) {
    if (offset + 16 > bytes.length) {
      log.debug("Leaving parseLmsPrivateKey(). Truncated.");
      throw new Error("The private key is truncated at level " + i + ".");
    }
    var lmsParams = LMS_BY_ID[strTou32(bytes, offset)];
    var otsParams = LMOTS_BY_ID[strTou32(bytes, offset + 4)];
    if (!lmsParams || !otsParams) {
      log.debug("Leaving parseLmsPrivateKey(). Unknown typecode.");
      throw new Error("The private key names an unknown typecode at level " +
                      i + ".");
    }
    levels.push({ lmsParams: lmsParams, otsParams: otsParams,
                  generation: strTou32(bytes, offset + 8),
                  q: strTou32(bytes, offset + 12) });
    offset += 16;
  }
  log.debug("Leaving parseLmsPrivateKey().");
  return { master: master, levels: levels };
}

// The public key of an HSS key: u32str(L) || the top LMS public key. Only the
// TOP tree has to exist for this, which is the whole point of HSS and the
// only reason a 2^20-signature key is reachable from a browser at all.
function hssKeygen(spec) {
  log.debug("Entering hssKeygen(). levels=" + spec.levels.length);
  var master = spec.master || randomBytes(32);
  var levels = [];
  var total = 0;
  for (var i = 0; i < spec.levels.length; i++) {
    var lmsParams = resolveLms(spec.levels[i].lms);
    var otsParams = resolveLmots(spec.levels[i].lmots);
    total += lmsKeygenCost(lmsParams, otsParams);
    levels.push({ lmsParams: lmsParams, otsParams: otsParams,
                  generation: 0, q: 0 });
  }
  if (!canKeygen(total)) {
    log.debug("Leaving hssKeygen(). Too expensive.");
    throw new Error("Generating this key would take about " +
                    Math.round(total / 1000000) + " million hash " +
                    "computations, past this tool's limit of " +
                    Math.round(MAX_KEYGEN_HASHES / 1000000) + " million. " +
                    "Use a smaller h, a smaller w, or more HSS levels — " +
                    "only the top tree is built here.");
  }
  var key = { master: master, levels: levels };
  var top = levels[0];
  var identity = deriveLevelIdentity(master, 0, 0, top.lmsParams,
                                     top.otsParams);
  var nodes = lmsTree(top.lmsParams, top.otsParams, identity.I,
                      identity.seed);
  var publicKey = cat(u32str(levels.length),
      lmsPublicKeyBytes(top.lmsParams, top.otsParams, identity.I, nodes[1]));
  log.debug("Leaving hssKeygen().");
  return { privateKey: serializeLmsPrivateKey(key), publicKey: publicKey,
           key: key };
}

// Section 6.2, and the state handling is the point rather than a detail: this
// returns the UPDATED private key beside the signature and the caller has to
// store it. An index is spent whether or not the caller keeps the result,
// which is exactly the property that makes these schemes dangerous to
// operate and is why SP 800-208 section 1 restricts where they may be used.
function hssSign(privateKeyBytes, message, options) {
  log.debug("Entering hssSign().");
  var key = parseLmsPrivateKey(privateKeyBytes);
  var opts = options || {};
  var L = key.levels.length;
  // Find the lowest level with an unused leaf; every level below it is
  // regenerated with a fresh identity, as section 6.2 requires.
  var d = L;
  while (d > 0 && key.levels[d - 1].q >=
         Math.pow(2, key.levels[d - 1].lmsParams.h)) {
    d = d - 1;
  }
  if (d === 0) {
    log.debug("Leaving hssSign(). Exhausted.");
    throw new Error("This HSS key is exhausted: every leaf of every level " +
                    "has been used. It cannot sign again, and reusing one " +
                    "would let an attacker forge.");
  }
  for (var r = d; r < L; r++) {
    key.levels[r].generation += 1;
    key.levels[r].q = 0;
  }
  // Build every level's tree, sign each level's public key with its parent,
  // and sign the message with the bottom one.
  var trees = [];
  for (var i = 0; i < L; i++) {
    var level = key.levels[i];
    var identity = deriveLevelIdentity(key.master, i, level.generation,
                                       level.lmsParams, level.otsParams);
    trees.push({ identity: identity,
                 nodes: lmsTree(level.lmsParams, level.otsParams,
                                identity.I, identity.seed) });
  }
  var parts = [u32str(L - 1)];
  for (var j = 0; j < L - 1; j++) {
    var childPub = lmsPublicKeyBytes(key.levels[j + 1].lmsParams,
        key.levels[j + 1].otsParams, trees[j + 1].identity.I,
        trees[j + 1].nodes[1]);
    var parent = key.levels[j];
    parts.push(lmsSignWithTree(parent.lmsParams, parent.otsParams,
        trees[j].identity.I, trees[j].identity.seed, trees[j].nodes,
        parent.q, childPub, randomizerFor(parent.otsParams, opts)));
    parts.push(childPub);
  }
  var bottom = key.levels[L - 1];
  var q = bottom.q;
  parts.push(lmsSignWithTree(bottom.lmsParams, bottom.otsParams,
      trees[L - 1].identity.I, trees[L - 1].identity.seed,
      trees[L - 1].nodes, q, message,
      randomizerFor(bottom.otsParams, opts)));
  if (!opts.reuseIndex) {
    key.levels[L - 1].q = q + 1;
  }
  log.debug("Leaving hssSign(). q=" + q);
  return { signature: cat.apply(null, parts),
           privateKey: serializeLmsPrivateKey(key), q: q };
}

// C, the LM-OTS message randomizer. It is an argument so that a caller
// reproducing a published test case can supply the one that case used;
// everywhere else it is fresh randomness, which is what stops two signatures
// of one message under one key from being identical.
function randomizerFor(otsParams, opts) {
  if (opts && opts.C) {
    return opts.C;
  }
  return randomBytes(otsParams.n);
}

function hssVerify(publicKeyBytes, message, signatureBytes) {
  log.debug("Entering hssVerify().");
  var pub = parseHssPublicKey(publicKeyBytes);
  var parsed = parseHssSignature(signatureBytes, pub);
  var key = pub.top;
  for (var i = 0; i < parsed.levels.length; i++) {
    var level = parsed.levels[i];
    var root = lmsRootFromSignature(key.lmsParams, key.otsParams, key.I,
                                    level.signatureBytes,
                                    level.signedKey.bytes);
    if (!bytesEqual(root, key.root)) {
      log.debug("Leaving hssVerify(). Level " + i + " failed.");
      return { valid: false,
               reason: "The signature over the level " + (i + 1) +
                   " public key does not verify under the level " + i +
                   " key." };
    }
    key = level.signedKey;
  }
  var finalRoot = lmsRootFromSignature(key.lmsParams, key.otsParams, key.I,
                                       parsed.finalSignatureBytes, message);
  if (!bytesEqual(finalRoot, key.root)) {
    log.debug("Leaving hssVerify(). Message signature failed.");
    return { valid: false,
             reason: "The signature over the message does not verify: the " +
                 "root computed from it is not the one in the public key." };
  }
  log.debug("Leaving hssVerify(). Valid.");
  return { valid: true, levels: parsed.levels.length + 1 };
}

function resolveLmots(nameOrId) {
  var found = typeof nameOrId === "number" ? LMOTS_BY_ID[nameOrId] :
      LMOTS_BY_NAME[nameOrId];
  if (!found) {
    throw new Error("Unknown LM-OTS parameter set: " + nameOrId);
  }
  return found;
}

function resolveLms(nameOrId) {
  var found = typeof nameOrId === "number" ? LMS_BY_ID[nameOrId] :
      LMS_BY_NAME[nameOrId];
  if (!found) {
    throw new Error("Unknown LMS parameter set: " + nameOrId);
  }
  return found;
}

// ===========================================================================
// XMSS and XMSS^MT (RFC 8391, and SP 800-208 sections 5 to 7)
//
// EVERYTHING BELOW IS ALSO A HOT PATH AND DOES NOT LOG, for the reason given
// above the LM-OTS section. One XMSS-SHA2_10_256 key is 1,024 leaves times 67
// chains times 15 steps, and each step is three hash calls.
//
// The four keyed functions are RFC 8391 section 5.1's, with SP 800-208's
// padding length: the first argument of every one of them is toByte(x, pad)
// where x is 0 for F, 1 for H, 2 for H_msg, 3 for PRF — and 4 for the
// PRF_keygen that SP 800-208 section 6.2 adds, which RFC 8391 does not have.
// `pad` is n for the 256- and 512-bit parameter sets and FOUR for the 192-bit
// ones. That last value is the single most consequential thing on this page
// that no name anywhere reveals: a 192-bit implementation that pads to n
// signs, verifies and round-trips perfectly and agrees with nothing.
// ===========================================================================
var PAD_F = 0;
var PAD_H = 1;
var PAD_HASH = 2;
var PAD_PRF = 3;
var PAD_PRF_KEYGEN = 4;

function coreHash(params, bytes) {
  return HASHES[params.hash](bytes, params.n);
}

// The five function-separation prefixes, computed once per parameter set
// rather than on every hash. They are constants of the parameter set —
// toByte(0..4, padding) — and building them per call is three allocations and
// three loops inside the innermost loop of the whole scheme.
function padBytes(params, which) {
  if (!params.pads) {
    params.pads = [toByte(0, params.padding), toByte(1, params.padding),
                   toByte(2, params.padding), toByte(3, params.padding),
                   toByte(4, params.padding)];
  }
  return params.pads[which];
}

// An address is eight 32-bit words. It is passed around as a Uint32Array and
// serialized big-endian only when it reaches a hash.
function newAddress() {
  return new Uint32Array(8);
}

function addressBytes(adrs) {
  var out = new Uint8Array(32);
  for (var i = 0; i < 8; i++) {
    out[i * 4] = (adrs[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (adrs[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (adrs[i] >>> 8) & 0xff;
    out[i * 4 + 3] = adrs[i] & 0xff;
  }
  return out;
}

// RFC 8391 section 2.5: "we furthermore assume that the setType() method sets
// the four words following the type word to zero". Leaving them alone is a
// working scheme whose addresses collide across types.
function setType(adrs, type) {
  adrs[3] = type;
  adrs[4] = 0;
  adrs[5] = 0;
  adrs[6] = 0;
  adrs[7] = 0;
}

function setTreeAddress(adrs, value) {
  var v = typeof value === "bigint" ? value : BigInt(value);
  adrs[1] = Number((v >> _B32) & _BMASK32);
  adrs[2] = Number(v & _BMASK32);
}

function prf(params, key, inBytes32) {
  return coreHash(params, cat(padBytes(params, PAD_PRF), key,
                                      inBytes32));
}

// SP 800-208 section 6.2. The WOTS+ private key elements are derived from the
// secret seed AND the public seed AND the address, rather than from an index
// alone as RFC 8391 section 3.1.7 suggests — which is what makes one seed
// safe to use across the whole hypertree.
function prfKeygen(params, key, inBytes) {
  return coreHash(params, cat(
      padBytes(params, PAD_PRF_KEYGEN), key, inBytes));
}

function hashMessage(params, R, root, idx, message) {
  return coreHash(params, cat(
      padBytes(params, PAD_HASH), R, root,
      toByte(idx, params.n), message));
}

function xorBytesInto(a, b) {
  var out = new Uint8Array(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function thashF(params, input, pubSeed, adrs) {
  adrs[7] = 0;
  var key = prf(params, pubSeed, addressBytes(adrs));
  adrs[7] = 1;
  var bm = prf(params, pubSeed, addressBytes(adrs));
  return coreHash(params, cat(padBytes(params, PAD_F), key,
                                      xorBytesInto(input, bm)));
}

function thashH(params, left, right, pubSeed, adrs) {
  adrs[7] = 0;
  var key = prf(params, pubSeed, addressBytes(adrs));
  adrs[7] = 1;
  var bm0 = prf(params, pubSeed, addressBytes(adrs));
  adrs[7] = 2;
  var bm1 = prf(params, pubSeed, addressBytes(adrs));
  return coreHash(params, cat(padBytes(params, PAD_H), key,
      xorBytesInto(left, bm0), xorBytesInto(right, bm1)));
}

// ---------------------------------------------------------------------------
// WOTS+ (RFC 8391 section 3.1)
// ---------------------------------------------------------------------------
function wotsLen(params) {
  var lgw = Math.log2(params.w);
  var len1 = Math.ceil(8 * params.n / lgw);
  var len2 = Math.floor(Math.log2(len1 * (params.w - 1)) / lgw) + 1;
  return { len1: len1, len2: len2, len: len1 + len2, lgw: lgw };
}

function baseW(X, w, outLen) {
  var out = new Array(outLen);
  var lgw = Math.log2(w);
  var inPos = 0;
  var total = 0;
  var bits = 0;
  for (var consumed = 0; consumed < outLen; consumed++) {
    if (bits === 0) {
      total = X[inPos];
      inPos++;
      bits += 8;
    }
    bits -= lgw;
    out[consumed] = (total >> bits) & (w - 1);
  }
  return out;
}

// The message digits followed by the checksum digits — the array both signing
// and verification walk. The checksum is what stops an attacker advancing
// every chain: increasing any message digit decreases the checksum, and a
// chain can only be advanced.
function wotsDigits(params, message) {
  var lens = wotsLen(params);
  var msg = baseW(message, params.w, lens.len1);
  var csum = 0;
  for (var i = 0; i < lens.len1; i++) {
    csum = csum + params.w - 1 - msg[i];
  }
  csum = csum << (8 - ((lens.len2 * lens.lgw) % 8));
  var csumBytes = Math.ceil((lens.len2 * lens.lgw) / 8);
  return msg.concat(baseW(toByte(csum, csumBytes), params.w, lens.len2));
}

// Algorithm 2. Word 6 is the HASH address — the step within this chain —
// while word 5 is the chain address and word 4 is the leaf this WOTS+ key
// belongs to. RFC 8391 section 3.1.4 is explicit that a WOTS+ algorithm "MUST
// NOT manipulate any parts of ADRS except for the last three 32-bit words",
// which is words 5, 6 and 7; touching word 4 would overwrite the leaf index
// the caller set and produce a tree that is perfectly self-consistent and
// verifies against no other implementation.
function wotsChain(params, X, start, steps, pubSeed, adrs) {
  var tmp = X;
  for (var i = start; i < start + steps && i < params.w; i++) {
    adrs[6] = i;
    tmp = thashF(params, tmp, pubSeed, adrs);
  }
  return tmp;
}

function wotsPrivateKey(params, skSeed, pubSeed, adrs) {
  var lens = wotsLen(params);
  var sk = new Array(lens.len);
  adrs[6] = 0;
  adrs[7] = 0;
  for (var i = 0; i < lens.len; i++) {
    adrs[5] = i;
    sk[i] = prfKeygen(params, skSeed, cat(pubSeed,
                                                  addressBytes(adrs)));
  }
  return sk;
}

function wotsPublicKey(params, sk, pubSeed, adrs) {
  var out = new Array(sk.length);
  for (var i = 0; i < sk.length; i++) {
    adrs[5] = i;
    out[i] = wotsChain(params, sk[i], 0, params.w - 1, pubSeed, adrs);
  }
  return out;
}

function wotsSign(params, message, sk, pubSeed, adrs) {
  var digits = wotsDigits(params, message);
  var sig = new Array(sk.length);
  for (var i = 0; i < sk.length; i++) {
    adrs[5] = i;
    sig[i] = wotsChain(params, sk[i], 0, digits[i], pubSeed, adrs);
  }
  return sig;
}

function wotsPkFromSig(params, message, sig, pubSeed, adrs) {
  var digits = wotsDigits(params, message);
  var out = new Array(sig.length);
  for (var i = 0; i < sig.length; i++) {
    adrs[5] = i;
    out[i] = wotsChain(params, sig[i], digits[i],
                       params.w - 1 - digits[i], pubSeed, adrs);
  }
  return out;
}

// ---------------------------------------------------------------------------
// L-trees and hash trees (RFC 8391 sections 4.1.4 and 4.1.5)
// ---------------------------------------------------------------------------
function ltree(params, pk, pubSeed, adrs) {
  var nodes = pk.slice();
  var lenPrime = nodes.length;
  adrs[5] = 0;
  while (lenPrime > 1) {
    for (var i = 0; i < Math.floor(lenPrime / 2); i++) {
      adrs[6] = i;
      nodes[i] = thashH(params, nodes[2 * i], nodes[2 * i + 1], pubSeed,
                        adrs);
    }
    if (lenPrime % 2 === 1) {
      nodes[Math.floor(lenPrime / 2)] = nodes[lenPrime - 1];
    }
    lenPrime = Math.ceil(lenPrime / 2);
    adrs[5] = adrs[5] + 1;
  }
  return nodes[0];
}

// One whole tree: every leaf and every internal node, so an authentication
// path is a lookup. `nodes[k][j]` is the j-th node at height k, leaves at
// height 0 — the numbering RFC 8391's algorithms use, rather than RFC 8554's
// one-based node numbers, because these two documents genuinely differ here
// and translating between them in code is how a path ends up reversed.
function xmssTree(params, skSeed, pubSeed, layer, treeAddress) {
  var height = params.h / params.d;
  var leafCount = Math.pow(2, height);
  var levels = [new Array(leafCount)];
  for (var i = 0; i < leafCount; i++) {
    var adrs = newAddress();
    adrs[0] = layer;
    setTreeAddress(adrs, treeAddress);
    setType(adrs, 0);
    adrs[4] = i;
    var sk = wotsPrivateKey(params, skSeed, pubSeed, adrs);
    setType(adrs, 0);
    adrs[4] = i;
    var pk = wotsPublicKey(params, sk, pubSeed, adrs);
    setType(adrs, 1);
    adrs[4] = i;
    levels[0][i] = ltree(params, pk, pubSeed, adrs);
  }
  for (var k = 1; k <= height; k++) {
    var prev = levels[k - 1];
    var row = new Array(prev.length / 2);
    for (var j = 0; j < row.length; j++) {
      var a = newAddress();
      a[0] = layer;
      setTreeAddress(a, treeAddress);
      setType(a, 2);
      a[5] = k - 1;
      a[6] = j;
      row[j] = thashH(params, prev[2 * j], prev[2 * j + 1], pubSeed, a);
    }
    levels.push(row);
  }
  return { levels: levels, root: levels[height][0], height: height };
}

function xmssAuthPath(tree, leafIndex) {
  var path = [];
  var index = leafIndex;
  for (var k = 0; k < tree.height; k++) {
    path.push(tree.levels[k][index ^ 1]);
    index = index >> 1;
  }
  return path;
}

// Algorithm 13. The verifier's whole job: turn a one-time signature and an
// authentication path back into a root, and compare.
function xmssRootFromSig(params, leafIndex, otsSig, auth, message, pubSeed,
                         layer, treeAddress) {
  var adrs = newAddress();
  adrs[0] = layer;
  setTreeAddress(adrs, treeAddress);
  setType(adrs, 0);
  adrs[4] = leafIndex;
  var pk = wotsPkFromSig(params, message, otsSig, pubSeed, adrs);
  setType(adrs, 1);
  adrs[4] = leafIndex;
  var node = ltree(params, pk, pubSeed, adrs);
  setType(adrs, 2);
  adrs[6] = leafIndex;
  for (var k = 0; k < params.h / params.d; k++) {
    adrs[5] = k;
    if (Math.floor(leafIndex / Math.pow(2, k)) % 2 === 0) {
      adrs[6] = Math.floor(adrs[6] / 2);
      node = thashH(params, node, auth[k], pubSeed, adrs);
    } else {
      adrs[6] = Math.floor((adrs[6] - 1) / 2);
      node = thashH(params, auth[k], node, pubSeed, adrs);
    }
  }
  return node;
}

// ---------------------------------------------------------------------------
// XMSS and XMSS^MT — keys, signatures, and the state.
//
// The private key format is this tool's, for the reason RFC 8391 section
// 4.1.3 gives: nothing interoperable depends on it. It holds the two secret
// seeds, the public seed, the root and the index — SP 800-208 section 7.2.1's
// "SK_SEED, SK_PRF, SEED, root, idx" — and the magic says whose it is.
// ---------------------------------------------------------------------------
var XMSS_KEY_MAGIC = [0x58, 0x4d, 0x53, 0x4b];

// One tree: 2^(h/d) leaves, each len chains of (w-1) steps, three hash
// computations per step (a key, a bitmask and F itself).
function xmssTreeCost(params) {
  var lens = wotsLen(params);
  var leaves = Math.pow(2, params.h / params.d);
  return leaves * lens.len * (params.w - 1) * 3;
}

// KEY GENERATION BUILDS ONE TREE AND SIGNING BUILDS d OF THEM, so the cost
// that decides whether a parameter set is usable here is the SIGNING one — a
// key that can be generated and never used is a worse outcome than a refusal
// naming the number. It is also the clearest possible statement of what the
// multi-tree variants buy: XMSSMT-SHA2_20/4_256 signs 1,048,576 messages
// with trees of 32 leaves, while XMSS-SHA2_20_256 needs 1,048,576 leaves in
// one tree and cannot be generated here at all.
function xmssKeyCost(params) {
  return xmssTreeCost(params) * params.d;
}

function xmssIdxBytes(params) {
  return Math.ceil(params.h / 8);
}

function serializeXmssPrivateKey(key) {
  log.debug("Entering serializeXmssPrivateKey().");
  var out = cat(new Uint8Array(XMSS_KEY_MAGIC), u8str(1),
      u8str(key.params.multiTree ? 1 : 0), u32str(key.params.id),
      key.skSeed, key.skPrf, key.pubSeed, key.root, toByte(key.idx, 8));
  log.debug("Leaving serializeXmssPrivateKey().");
  return out;
}

function parseXmssPrivateKey(bytes) {
  log.debug("Entering parseXmssPrivateKey().");
  if (bytes.length < 10 || bytes[0] !== XMSS_KEY_MAGIC[0] ||
      bytes[1] !== XMSS_KEY_MAGIC[1] || bytes[2] !== XMSS_KEY_MAGIC[2] ||
      bytes[3] !== XMSS_KEY_MAGIC[3]) {
    log.debug("Leaving parseXmssPrivateKey(). Not an XMSK blob.");
    throw new Error("This is not an XMSS private key from this tool (it " +
                    "does not start with XMSK).");
  }
  if (bytes[4] !== 1) {
    log.debug("Leaving parseXmssPrivateKey(). Bad version.");
    throw new Error("Unsupported XMSS private key version " + bytes[4] + ".");
  }
  var multi = bytes[5] === 1;
  var id = strTou32(bytes, 6);
  var params = multi ? XMSSMT_BY_ID[id] : XMSS_BY_ID[id];
  if (!params) {
    log.debug("Leaving parseXmssPrivateKey(). Unknown OID.");
    throw new Error("Unknown " + (multi ? "XMSS^MT" : "XMSS") +
                    " algorithm identifier " + id + ".");
  }
  var n = params.n;
  var expected = 10 + 4 * n + 8;
  if (bytes.length !== expected) {
    log.debug("Leaving parseXmssPrivateKey(). Wrong length.");
    throw new Error("An " + params.name + " private key from this tool is " +
                    expected + " bytes; this is " + bytes.length + ".");
  }
  log.debug("Leaving parseXmssPrivateKey().");
  return { params: params,
           skSeed: bytes.subarray(10, 10 + n),
           skPrf: bytes.subarray(10 + n, 10 + 2 * n),
           pubSeed: bytes.subarray(10 + 2 * n, 10 + 3 * n),
           root: bytes.subarray(10 + 3 * n, 10 + 4 * n),
           idx: Number(bytesToBig(bytes.subarray(10 + 4 * n))) };
}

// The public key IS interoperable and is exactly RFC 8391's: the algorithm
// identifier, the root and the public seed.
function xmssPublicKeyBytes(params, root, pubSeed) {
  return cat(u32str(params.id), root, pubSeed);
}

function parseXmssPublicKey(bytes, multiTree) {
  log.debug("Entering parseXmssPublicKey().");
  if (bytes.length < 4) {
    log.debug("Leaving parseXmssPublicKey(). Too short.");
    throw new Error("An XMSS public key is at least 4 bytes; this is " +
                    bytes.length + ".");
  }
  var id = strTou32(bytes, 0);
  var params = multiTree ? XMSSMT_BY_ID[id] : XMSS_BY_ID[id];
  if (!params) {
    log.debug("Leaving parseXmssPublicKey(). Unknown OID.");
    throw new Error("Unknown " + (multiTree ? "XMSS^MT" : "XMSS") +
                    " algorithm identifier 0x" + id.toString(16) +
                    ". The identifier is the first four bytes and the two " +
                    "registries are separate: 0x" + id.toString(16) +
                    " means different things in each.");
  }
  if (bytes.length !== 4 + 2 * params.n) {
    log.debug("Leaving parseXmssPublicKey(). Wrong length.");
    throw new Error("An " + params.name + " public key is " +
                    (4 + 2 * params.n) + " bytes; this is " + bytes.length +
                    ".");
  }
  log.debug("Leaving parseXmssPublicKey().");
  return { params: params, root: bytes.subarray(4, 4 + params.n),
           pubSeed: bytes.subarray(4 + params.n), bytes: bytes };
}

// RFC 8391 section 4.1.8 (single tree) and 4.2.3 (multi-tree). The index is
// four bytes for XMSS and ceil(h/8) for XMSS^MT — which is 3 bytes at h = 20
// and 8 at h = 60, so a parser that assumes four is wrong in both directions.
function parseXmssSignature(bytes, params) {
  log.debug("Entering parseXmssSignature().");
  var n = params.n;
  var lens = wotsLen(params);
  var perTree = (params.h / params.d + lens.len) * n;
  var idxLen = params.multiTree ? xmssIdxBytes(params) : 4;
  var expected = idxLen + n + params.d * perTree;
  if (bytes.length !== expected) {
    log.debug("Leaving parseXmssSignature(). Wrong length.");
    throw new Error("An " + params.name + " signature is " + expected +
                    " bytes; this is " + bytes.length + ".");
  }
  var idx = Number(bytesToBig(bytes.subarray(0, idxLen)));
  if (idx >= Math.pow(2, params.h)) {
    log.debug("Leaving parseXmssSignature(). Index out of range.");
    throw new Error("The signature's index " + idx + " is outside a " +
                    "height-" + params.h + " hypertree.");
  }
  var offset = idxLen;
  var r = bytes.subarray(offset, offset + n);
  offset += n;
  var trees = [];
  for (var layer = 0; layer < params.d; layer++) {
    var otsSig = [];
    for (var i = 0; i < lens.len; i++) {
      otsSig.push(bytes.subarray(offset, offset + n));
      offset += n;
    }
    var auth = [];
    for (var k = 0; k < params.h / params.d; k++) {
      auth.push(bytes.subarray(offset, offset + n));
      offset += n;
    }
    trees.push({ otsSignature: otsSig, auth: auth });
  }
  log.debug("Leaving parseXmssSignature(). idx=" + idx);
  return { idx: idx, r: r, trees: trees, params: params, length: expected };
}

function xmssKeygen(name, options) {
  log.debug("Entering xmssKeygen(). name=" + name);
  var params = resolveXmss(name);
  var cost = xmssKeyCost(params);
  if (!canKeygen(cost)) {
    log.debug("Leaving xmssKeygen(). Too expensive.");
    throw new Error("Generating this key would take about " +
                    Math.round(cost / 1000000) + " million hash " +
                    "computations, past this tool's limit of " +
                    Math.round(MAX_KEYGEN_HASHES / 1000000) + " million. " +
                    "Only the TOP tree is built, so a multi-tree parameter " +
                    "set of the same total height costs far less.");
  }
  var opts = options || {};
  var skSeed = opts.skSeed || randomBytes(params.n);
  var skPrf = opts.skPrf || randomBytes(params.n);
  var pubSeed = opts.pubSeed || randomBytes(params.n);
  // The top layer is d-1; for single-tree XMSS that is layer 0.
  var tree = xmssTree(params, skSeed, pubSeed, params.d - 1, 0);
  var key = { params: params, skSeed: skSeed, skPrf: skPrf,
              pubSeed: pubSeed, root: tree.root, idx: 0 };
  log.debug("Leaving xmssKeygen().");
  return { privateKey: serializeXmssPrivateKey(key),
           publicKey: xmssPublicKeyBytes(params, tree.root, pubSeed),
           key: key };
}

// Algorithms 12 and 16. One code path for both, because XMSS is XMSS^MT with
// d = 1 — the multi-tree loop simply does not run — and writing them twice is
// how the two drift.
function xmssSign(privateKeyBytes, message, options) {
  log.debug("Entering xmssSign().");
  var key = parseXmssPrivateKey(privateKeyBytes);
  var params = key.params;
  var opts = options || {};
  var total = Math.pow(2, params.h);
  if (key.idx >= total) {
    log.debug("Leaving xmssSign(). Exhausted.");
    throw new Error("This " + params.name + " key is exhausted: all " +
                    total + " one-time keys have been used. Signing again " +
                    "would reuse one, which is what lets an attacker forge.");
  }
  var idx = key.idx;
  var idxLen = params.multiTree ? xmssIdxBytes(params) : 4;
  var r = prf(params, key.skPrf, toByte(idx, 32));
  var mPrime = hashMessage(params, r, key.root, idx, message);
  var perTreeHeight = params.h / params.d;
  var parts = [toByte(idx, idxLen), r];
  var idxTree = BigInt(idx) >> BigInt(perTreeHeight);
  var idxLeaf = idx % Math.pow(2, perTreeHeight);
  var signed = mPrime;
  for (var layer = 0; layer < params.d; layer++) {
    var tree = xmssTree(params, key.skSeed, key.pubSeed, layer, idxTree);
    var adrs = newAddress();
    adrs[0] = layer;
    setTreeAddress(adrs, idxTree);
    setType(adrs, 0);
    adrs[4] = idxLeaf;
    var sk = wotsPrivateKey(params, key.skSeed, key.pubSeed, adrs);
    setType(adrs, 0);
    adrs[4] = idxLeaf;
    var otsSig = wotsSign(params, signed, sk, key.pubSeed, adrs);
    parts = parts.concat(otsSig, xmssAuthPath(tree, idxLeaf));
    signed = tree.root;
    idxLeaf = Number(idxTree % BigInt(Math.pow(2, perTreeHeight)));
    idxTree = idxTree >> BigInt(perTreeHeight);
  }
  if (!opts.reuseIndex) {
    key.idx = idx + 1;
  }
  log.debug("Leaving xmssSign(). idx=" + idx);
  return { signature: cat.apply(null, parts),
           privateKey: serializeXmssPrivateKey(key), idx: idx };
}

// Algorithms 14 and 17, again as one path.
function xmssVerify(publicKeyBytes, message, signatureBytes, multiTree) {
  log.debug("Entering xmssVerify().");
  var pub = parseXmssPublicKey(publicKeyBytes, multiTree);
  var params = pub.params;
  var parsed = parseXmssSignature(signatureBytes, params);
  var perTreeHeight = params.h / params.d;
  var mPrime = hashMessage(params, parsed.r, pub.root, parsed.idx, message);
  var idxTree = BigInt(parsed.idx) >> BigInt(perTreeHeight);
  var idxLeaf = parsed.idx % Math.pow(2, perTreeHeight);
  var node = mPrime;
  for (var layer = 0; layer < params.d; layer++) {
    node = xmssRootFromSig(params, idxLeaf, parsed.trees[layer].otsSignature,
                           parsed.trees[layer].auth, node, pub.pubSeed,
                           layer, idxTree);
    idxLeaf = Number(idxTree % BigInt(Math.pow(2, perTreeHeight)));
    idxTree = idxTree >> BigInt(perTreeHeight);
  }
  if (!bytesEqual(node, pub.root)) {
    log.debug("Leaving xmssVerify(). Root mismatch.");
    return { valid: false,
             reason: "The root computed from the signature is not the root " +
                 "in the public key." };
  }
  log.debug("Leaving xmssVerify(). Valid.");
  return { valid: true, idx: parsed.idx, layers: params.d };
}

function resolveXmss(nameOrId) {
  if (typeof nameOrId === "string") {
    var byName = XMSS_BY_NAME[nameOrId] || XMSSMT_BY_NAME[nameOrId];
    if (!byName) {
      throw new Error("Unknown XMSS parameter set: " + nameOrId);
    }
    return byName;
  }
  throw new Error("An XMSS parameter set must be named: the two registries " +
                  "assign the same numbers to different things.");
}

// ===========================================================================
// Describing what is on the wire.
//
// This is the half of the module a DEBUGGER is for, and it is deliberately
// separate from verification: a signature that will not verify still has
// fields, and the fields are where the answer is. A wrong parameter set, a
// leaf index past the end of the tree, an authentication path of the wrong
// depth and a public key from a different key pair all fail verification
// identically and look completely different here.
// ===========================================================================
function bytesToHexShort(bytes, limit) {
  var hex = bytesLib.bytesToHex(bytes);
  if (!limit || hex.length <= limit * 2) {
    return hex;
  }
  return hex.slice(0, limit * 2) + "… (" + bytes.length + " bytes)";
}

function describeHss(publicKeyBytes, signatureBytes) {
  log.debug("Entering describeHss().");
  var lines = [];
  var pub = parseHssPublicKey(publicKeyBytes);
  lines.push("HSS public key — " + pub.levels + " level(s), " +
             publicKeyBytes.length + " bytes.");
  lines.push("  Top LMS type:    " + pub.top.lmsParams.name + " (0x" +
             pub.top.lmsParams.id.toString(16) + "), h = " +
             pub.top.lmsParams.h + ", m = " + pub.top.lmsParams.m);
  lines.push("  Top LM-OTS type: " + pub.top.otsParams.name + " (0x" +
             pub.top.otsParams.id.toString(16) + "), w = " +
             pub.top.otsParams.w + ", p = " + pub.top.otsParams.p +
             ", n = " + pub.top.otsParams.n);
  lines.push("  I (key id):      " + bytesToHexShort(pub.top.I));
  lines.push("  T[1] (root):     " + bytesToHexShort(pub.top.root, 16));
  if (!signatureBytes || !signatureBytes.length) {
    log.debug("Leaving describeHss(). No signature.");
    return lines.join("\n");
  }
  var sig = parseHssSignature(signatureBytes, pub);
  lines.push("");
  lines.push("HSS signature — " + signatureBytes.length + " bytes, Nspk = " +
             sig.nspk + " (so L = " + (sig.nspk + 1) + ").");
  for (var i = 0; i < sig.levels.length; i++) {
    var level = sig.levels[i];
    lines.push("  Level " + i + ": leaf q = " + level.signature.q +
               " of 2^" + level.signature.lmsParams.h + ", " +
               level.signature.length + " bytes, signing the level " +
               (i + 1) + " public key");
    lines.push("           signed key: " + level.signedKey.lmsParams.name +
               " / " + level.signedKey.otsParams.name);
  }
  lines.push("  Level " + sig.levels.length + ": leaf q = " +
             sig.finalSignature.q + " of 2^" +
             sig.finalSignature.lmsParams.h + ", " +
             sig.finalSignature.length + " bytes, signing the MESSAGE");
  lines.push("  Randomizer C:    " +
             bytesToHexShort(sig.finalSignature.otsSignature.subarray(
                 4, 4 + sig.finalSignature.otsParams.n), 16));
  lines.push("  Auth path:       " + sig.finalSignature.path.length +
             " node(s) of " + sig.finalSignature.lmsParams.m + " bytes");
  log.debug("Leaving describeHss().");
  return lines.join("\n");
}

function describeXmss(publicKeyBytes, signatureBytes, multiTree) {
  log.debug("Entering describeXmss().");
  var lines = [];
  var pub = parseXmssPublicKey(publicKeyBytes, multiTree);
  var params = pub.params;
  var lens = wotsLen(params);
  lines.push((params.multiTree ? "XMSS^MT" : "XMSS") + " public key — " +
             publicKeyBytes.length + " bytes.");
  lines.push("  Parameter set:   " + params.name + " (OID 0x" +
             params.id.toString(16) + ")");
  lines.push("  Functions:       " + params.hash + ", n = " + params.n +
             ", padding = " + params.padding + " byte(s)" +
             (params.padding === 4 ? "  <- SP 800-208's 192-bit rule" : ""));
  lines.push("  Tree:            h = " + params.h + ", d = " + params.d +
             " layer(s) of height " + (params.h / params.d) + ", w = " +
             params.w + ", len = " + lens.len);
  lines.push("  Capacity:        2^" + params.h + " signatures");
  lines.push("  Root:            " + bytesToHexShort(pub.root, 16));
  lines.push("  SEED (public):   " + bytesToHexShort(pub.pubSeed, 16));
  if (!signatureBytes || !signatureBytes.length) {
    log.debug("Leaving describeXmss(). No signature.");
    return lines.join("\n");
  }
  var sig = parseXmssSignature(signatureBytes, params);
  lines.push("");
  lines.push((params.multiTree ? "XMSS^MT" : "XMSS") + " signature — " +
             signatureBytes.length + " bytes.");
  lines.push("  Index idx_sig:   " + sig.idx + " (" +
             (params.multiTree ? xmssIdxBytes(params) : 4) +
             "-byte field; " + (Math.pow(2, params.h) - sig.idx - 1) +
             " one-time key(s) would remain)");
  lines.push("  Randomness r:    " + bytesToHexShort(sig.r, 16));
  for (var i = 0; i < sig.trees.length; i++) {
    lines.push("  Layer " + i + ": WOTS+ signature of " +
               sig.trees[i].otsSignature.length + " x " + params.n +
               " bytes, auth path of " + sig.trees[i].auth.length +
               " node(s)");
  }
  log.debug("Leaving describeXmss().");
  return lines.join("\n");
}

// How many one-time keys a private key has left. The number a pane shows
// beside the key, and the thing that makes these schemes different from
// every other signature on this page.
function remaining(privateKeyBytes) {
  log.debug("Entering remaining().");
  if (privateKeyBytes.length > 4 && privateKeyBytes[0] === XMSS_KEY_MAGIC[0] &&
      privateKeyBytes[1] === XMSS_KEY_MAGIC[1]) {
    var xk = parseXmssPrivateKey(privateKeyBytes);
    log.debug("Leaving remaining(). XMSS.");
    return { used: xk.idx, total: Math.pow(2, xk.params.h),
             left: Math.pow(2, xk.params.h) - xk.idx, name: xk.params.name };
  }
  var lk = parseLmsPrivateKey(privateKeyBytes);
  var total = 1;
  var used = 0;
  for (var i = 0; i < lk.levels.length; i++) {
    total = total * Math.pow(2, lk.levels[i].lmsParams.h);
  }
  // Only the bottom level's index is a count of MESSAGES; the levels above
  // are spent one per regeneration of the level below.
  var bottom = lk.levels[lk.levels.length - 1];
  used = bottom.q;
  log.debug("Leaving remaining(). HSS.");
  return { used: used, total: total,
           left: Math.pow(2, bottom.lmsParams.h) - bottom.q,
           bottomOnly: true,
           name: lk.levels.map(function (l) { return l.lmsParams.name; })
               .join(" / ") };
}

// ===========================================================================
// The demonstration this module exists to be able to make.
//
// SP 800-208 section 1 restricts these schemes to applications where the
// signer can guarantee it never reuses a one-time key, and RFC 8554 section
// 5.4.1 requires the incremented index to be committed to storage BEFORE the
// signature leaves the signer. Both sentences are easy to read and hard to
// feel. This signs two DIFFERENT messages from the same index and hands back
// both signatures: both verify, which is exactly the point — nothing about
// either one is detectably wrong, and what an attacker now has is two
// Winternitz chains revealed at two different heights, which is the material
// a forgery on a third message is built from.
//
// It is not a way to sign twice. It is the failure, on demand, on a key you
// just made, so that the rule is about something you have seen.
// ===========================================================================
function signTwiceFromOneIndex(scheme, privateKeyBytes, messageA, messageB) {
  log.debug("Entering signTwiceFromOneIndex(). scheme=" + scheme);
  var signer = scheme === "xmss" ? xmssSign : hssSign;
  var first = signer(privateKeyBytes, messageA, { reuseIndex: true });
  var second = signer(privateKeyBytes, messageB, { reuseIndex: true });
  log.debug("Leaving signTwiceFromOneIndex().");
  return { first: first.signature, second: second.signature,
           index: scheme === "xmss" ? first.idx : first.q };
}

module.exports = {
  LMOTS: LMOTS,
  LMS: LMS,
  XMSS: XMSS,
  XMSSMT: XMSSMT,
  MAX_KEYGEN_HASHES: MAX_KEYGEN_HASHES,
  lmotsInternals: lmotsInternals,
  lmotsPublicKeyHash: lmotsPublicKeyHash,
  lmsKeygenCost: lmsKeygenCost,
  xmssKeyCost: xmssKeyCost,
  xmssTreeCost: xmssTreeCost,
  canKeygen: canKeygen,
  resolveLmots: resolveLmots,
  resolveLms: resolveLms,
  resolveXmss: resolveXmss,
  wotsLen: wotsLen,
  hssKeygen: hssKeygen,
  hssSign: hssSign,
  hssVerify: hssVerify,
  parseHssPublicKey: parseHssPublicKey,
  parseHssSignature: parseHssSignature,
  parseLmsPublicKey: parseLmsPublicKey,
  parseLmsSignature: parseLmsSignature,
  parseLmsPrivateKey: parseLmsPrivateKey,
  xmssKeygen: xmssKeygen,
  xmssSign: xmssSign,
  xmssVerify: xmssVerify,
  parseXmssPublicKey: parseXmssPublicKey,
  parseXmssSignature: parseXmssSignature,
  parseXmssPrivateKey: parseXmssPrivateKey,
  describeHss: describeHss,
  describeXmss: describeXmss,
  remaining: remaining,
  signTwiceFromOneIndex: signTwiceFromOneIndex
};
