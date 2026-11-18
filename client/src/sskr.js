// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: sskr.js
//
// ---------------------------------------------------------------------------
// Sharded Secret Key Reconstruction (#480): Blockchain Commons' SSKR
// (BCR-2020-011), over Shamir's Secret Sharing in GF(2^8) as bc-shamir
// 0.13.0 does it, with the two-level group scheme and the five-byte share
// header of the released sskr 0.12.0 crate. A Gordian Envelope uses it to
// split the key an encrypted subject is locked with into 'sskrShare'
// assertions (gordian_envelope_crypto.js).
//
// What has to be exactly bc-shamir's for shares to interoperate:
//   * the field is GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11b, AES's);
//   * a threshold-t split of a secret evaluates, at x = 0 .. count-1, the
//     polynomial through t-2 random shares at x = 0 .. t-3, a DIGEST share
//     at x = 254 (four bytes of HMAC-SHA-256(key = the other bytes, message
//     = the secret), then those random bytes) and the secret at x = 255;
//   * a threshold of 1 is no Shamir at all: every share is the secret;
//   * a share is [id(2) | gt-1,gc-1 | gi,mt-1 | 0,mi] || value, each pair
//     a nibble;
//   * the random bytes are drawn in bc-shamir's order (the t-2 random
//     shares, then the digest's tail), so a test RNG reproduces the crate's
//     shares byte for byte. tests/gordian_envelope_engine.js holds this to
//     the sskr crate's own tests' output.
//
// NO DOM.
// ---------------------------------------------------------------------------

var nobleHmac = require("@noble/hashes/hmac").hmac;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "sskr",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var MIN_SECRET_LEN = 16;
var MAX_SECRET_LEN = 32;
var MAX_SHARE_COUNT = 16;
var METADATA_SIZE = 5;
var SECRET_INDEX = 255;
var DIGEST_INDEX = 254;

// GF(2^8) by log and antilog tables over the generator 3.
var EXP = new Array(510);
var LOG = new Array(256);
(function () {
  var x = 1;
  for (var i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    var x2 = x << 1;
    if (x2 & 0x100) x2 ^= 0x11b;
    x = x2 ^ x;
  }
  for (var j = 255; j < 510; j++) EXP[j] = EXP[j - 255];
})();

// Field arithmetic runs per byte of every share; gfMul and gfDiv carry no
// Entering/Leaving pair (the hot-path exception the code style allows).
// interpolate() logs.
function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a, b) {
  if (b === 0) throw new Error("GF(256): division by zero.");
  if (a === 0) return 0;
  return EXP[LOG[a] + 255 - LOG[b]];
}

// The value at x of the polynomial through (xs[i], ys[i]): Lagrange, byte
// by byte.
function interpolate(xs, ys, x) {
  log.debug("Entering interpolate(). x=" + x);
  var len = ys[0].length;
  var out = new Uint8Array(len);
  for (var i = 0; i < xs.length; i++) {
    var num = 1;
    var den = 1;
    for (var j = 0; j < xs.length; j++) {
      if (j === i) continue;
      num = gfMul(num, x ^ xs[j]);
      den = gfMul(den, xs[i] ^ xs[j]);
    }
    var basis = gfDiv(num, den);
    for (var k = 0; k < len; k++) out[k] ^= gfMul(basis, ys[i][k]);
  }
  log.debug("Leaving interpolate().");
  return out;
}

function validate(threshold, count, length) {
  log.debug("Entering validate().");
  var problem = count > MAX_SHARE_COUNT ? "more than " + MAX_SHARE_COUNT +
      " shares" : threshold < 1 || threshold > count ? "a threshold of " +
      threshold + " for " + count + " shares" : length > MAX_SECRET_LEN ?
      "a secret longer than " + MAX_SECRET_LEN + " bytes" :
      length < MIN_SECRET_LEN ? "a secret shorter than " + MIN_SECRET_LEN +
      " bytes" : length & 1 ? "a secret of odd length" : "";
  if (problem) {
    log.debug("Leaving validate(). " + problem);
    throw new Error("Shamir: " + problem + ".");
  }
  log.debug("Leaving validate().");
}

function digestOf(randomTail, secret) {
  log.debug("Entering digestOf().");
  log.debug("Leaving digestOf().");
  return nobleHmac(nobleSha256, randomTail, secret);
}

// bc-shamir's split_secret. rng(n) -> n random bytes.
function splitSecret(threshold, count, secret, rng) {
  log.debug("Entering splitSecret(). " + threshold + "-of-" + count);
  var s = cbytes.asBytes(secret);
  validate(threshold, count, s.length);
  var random = rng || cbytes.randomBytes;
  var out = [];
  var i;
  if (threshold === 1) {
    for (i = 0; i < count; i++) out.push(s.slice());
    log.debug("Leaving splitSecret(). Threshold 1.");
    return out;
  }
  var xs = [];
  var ys = [];
  for (i = 0; i < threshold - 2; i++) {
    var r = cbytes.asBytes(random(s.length));
    out.push(r);
    xs.push(i);
    ys.push(r);
  }
  var digest = new Uint8Array(s.length);
  digest.set(cbytes.asBytes(random(s.length - 4)), 4);
  digest.set(digestOf(digest.subarray(4), s).subarray(0, 4), 0);
  xs.push(DIGEST_INDEX, SECRET_INDEX);
  ys.push(digest, s);
  for (i = threshold - 2; i < count; i++) out.push(interpolate(xs, ys, i));
  log.debug("Leaving splitSecret().");
  return out;
}

// bc-shamir's recover_secret: the shares at `indexes`, checked against the
// digest share.
function recoverSecret(indexes, shares) {
  log.debug("Entering recoverSecret(). " + shares.length);
  var t = shares.length;
  if (!t || indexes.length !== t) {
    log.debug("Leaving recoverSecret(). Bad threshold.");
    throw new Error("Shamir: one index per share, and at least one share.");
  }
  var len = shares[0].length;
  validate(t, t, len);
  if (shares.some(function (x) {
    return x.length !== len;
  })) {
    log.debug("Leaving recoverSecret(). Unequal.");
    throw new Error("Shamir: shares of unequal length.");
  }
  if (t === 1) {
    log.debug("Leaving recoverSecret(). Threshold 1.");
    return cbytes.asBytes(shares[0]).slice();
  }
  var digest = interpolate(indexes, shares, DIGEST_INDEX);
  var secret = interpolate(indexes, shares, SECRET_INDEX);
  var check = digestOf(digest.subarray(4), secret);
  if (!cbytes.bytesEqual(check.subarray(0, 4), digest.subarray(0, 4))) {
    log.debug("Leaving recoverSecret(). Checksum.");
    throw new Error("Shamir: the shares' checksum fails (wrong shares, or " +
                    "too few).");
  }
  log.debug("Leaving recoverSecret().");
  return secret;
}

// "2-of-3" -> [2, 3].
function parseGroup(text) {
  log.debug("Entering parseGroup().");
  var m = /^\s*(\d{1,2})\s*-?\s*of\s*-?\s*(\d{1,2})\s*$/i.exec(String(text));
  if (!m) {
    log.debug("Leaving parseGroup(). Not m-of-n.");
    throw new Error("a group is \"m-of-n\" (2-of-3): " + JSON.stringify(text));
  }
  log.debug("Leaving parseGroup().");
  return [Number(m[1]), Number(m[2])];
}

// { groupThreshold, groups: [[m, n], ...] }, checked as sskr's Spec is.
function spec(groupThreshold, groups) {
  log.debug("Entering spec().");
  var gs = groups.map(function (g) {
    return Array.isArray(g) ? g : parseGroup(g);
  });
  if (!(groupThreshold >= 1) || groupThreshold > gs.length) {
    log.debug("Leaving spec(). Group threshold.");
    throw new Error("SSKR: a group threshold of " + groupThreshold + " for " +
                    gs.length + " group(s).");
  }
  if (gs.length > MAX_SHARE_COUNT) {
    log.debug("Leaving spec(). Groups.");
    throw new Error("SSKR: at most " + MAX_SHARE_COUNT + " groups.");
  }
  gs.forEach(function (g) {
    if (g[1] < 1 || g[1] > MAX_SHARE_COUNT || g[0] > g[1]) {
      throw new Error("SSKR: a group of " + g[0] + "-of-" + g[1] + ".");
    }
  });
  log.debug("Leaving spec().");
  return { groupThreshold: groupThreshold, groups: gs };
}

function serializeShare(sh) {
  log.debug("Entering serializeShare().");
  var head = new Uint8Array([sh.id >> 8, sh.id & 0xff,
    (((sh.groupThreshold - 1) & 0xf) << 4) | ((sh.groupCount - 1) & 0xf),
    ((sh.groupIndex & 0xf) << 4) | ((sh.memberThreshold - 1) & 0xf),
    sh.memberIndex & 0xf]);
  log.debug("Leaving serializeShare().");
  return cbytes.concatBytes(head, sh.value);
}

// A share's bytes -> its fields.
function parseShare(bytes) {
  log.debug("Entering parseShare().");
  var b = cbytes.asBytes(bytes);
  if (b.length < METADATA_SIZE + MIN_SECRET_LEN) {
    log.debug("Leaving parseShare(). Short.");
    throw new Error("SSKR: a share is five bytes of metadata and at least " +
                    MIN_SECRET_LEN + " of value.");
  }
  var out = { id: (b[0] << 8) | b[1], groupThreshold: (b[2] >> 4) + 1,
              groupCount: (b[2] & 0xf) + 1, groupIndex: b[3] >> 4,
              memberThreshold: (b[3] & 0xf) + 1, memberIndex: b[4] & 0xf,
              value: b.slice(METADATA_SIZE) };
  if (out.groupThreshold > out.groupCount) {
    log.debug("Leaving parseShare(). Group threshold.");
    throw new Error("SSKR: a share whose group threshold exceeds its group " +
                    "count.");
  }
  if (b[4] >> 4) {
    log.debug("Leaving parseShare(). Reserved bits.");
    throw new Error("SSKR: a share's reserved bits are not zero.");
  }
  log.debug("Leaving parseShare().");
  return out;
}

// sskr_generate_using: [[share bytes, ...] per group].
function generate(sp, secret, rng) {
  log.debug("Entering generate().");
  var s = cbytes.asBytes(secret);
  var random = rng || cbytes.randomBytes;
  var idBytes = cbytes.asBytes(random(2));
  var id = (idBytes[0] << 8) | idBytes[1];
  var groupSecrets = splitSecret(sp.groupThreshold, sp.groups.length, s,
                                 random);
  var out = sp.groups.map(function (g, gi) {
    return splitSecret(g[0], g[1], groupSecrets[gi], random)
      .map(function (value, mi) {
        return serializeShare({ id: id, groupIndex: gi,
                                groupThreshold: sp.groupThreshold,
                                groupCount: sp.groups.length,
                                memberIndex: mi, memberThreshold: g[0],
                                value: value });
      });
  });
  log.debug("Leaving generate(). " + out.length + " group(s).");
  return out;
}

// sskr_combine: the secret from enough shares of one split.
function combine(shareBytes) {
  log.debug("Entering combine(). " + shareBytes.length);
  if (!shareBytes.length) {
    log.debug("Leaving combine(). None.");
    throw new Error("SSKR: no shares.");
  }
  var shares = shareBytes.map(parseShare);
  var first = shares[0];
  var groups = [];
  shares.forEach(function (sh) {
    if (sh.id !== first.id || sh.groupThreshold !== first.groupThreshold ||
        sh.groupCount !== first.groupCount ||
        sh.value.length !== first.value.length) {
      throw new Error("SSKR: shares from different splits.");
    }
    var g = groups.filter(function (x) {
      return x.index === sh.groupIndex;
    })[0];
    if (!g) {
      groups.push({ index: sh.groupIndex, threshold: sh.memberThreshold,
                    indexes: [sh.memberIndex], values: [sh.value] });
      return;
    }
    if (g.threshold !== sh.memberThreshold) {
      throw new Error("SSKR: two member thresholds in one group.");
    }
    if (g.indexes.indexOf(sh.memberIndex) !== -1) {
      throw new Error("SSKR: the same member's share twice.");
    }
    if (g.indexes.length < g.threshold) {
      g.indexes.push(sh.memberIndex);
      g.values.push(sh.value);
    }
  });
  if (groups.length < first.groupThreshold) {
    log.debug("Leaving combine(). Not enough groups.");
    throw new Error("SSKR: shares from " + groups.length + " group(s); " +
                    first.groupThreshold + " are needed.");
  }
  var masterIndexes = [];
  var masterShares = [];
  for (var i = 0; i < groups.length; i++) {
    var g = groups[i];
    if (g.indexes.length < g.threshold) continue;
    try {
      masterShares.push(recoverSecret(g.indexes, g.values));
      masterIndexes.push(g.index);
    } catch (e) {
      log.debug("combine(): group " + g.index + " did not recover.");
    }
    if (masterIndexes.length === first.groupThreshold) break;
  }
  if (masterIndexes.length < first.groupThreshold) {
    log.debug("Leaving combine(). Not enough complete groups.");
    throw new Error("SSKR: " + masterIndexes.length + " group(s) met their " +
                    "threshold; " + first.groupThreshold + " are needed.");
  }
  log.debug("Leaving combine().");
  return recoverSecret(masterIndexes, masterShares);
}

module.exports = {
  MIN_SECRET_LEN: MIN_SECRET_LEN,
  MAX_SECRET_LEN: MAX_SECRET_LEN,
  MAX_SHARE_COUNT: MAX_SHARE_COUNT,
  splitSecret: splitSecret,
  recoverSecret: recoverSecret,
  parseGroup: parseGroup,
  spec: spec,
  parseShare: parseShare,
  generate: generate,
  combine: combine
};
