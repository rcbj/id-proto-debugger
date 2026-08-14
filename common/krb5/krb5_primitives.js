// File: krb5_primitives.js
//
// ---------------------------------------------------------------------------
// The pieces of Kerberos v5's cryptography that no runtime gives you.
//
// Everything else this codec needs — AES-CBC, HMAC-SHA-1/256/384, PBKDF2 — is
// in Web Crypto, in the browser and in node alike, and lives in krb5_crypto.js.
// What is here is what Web Crypto does NOT have and what node's `crypto` will
// not hand over either. Measured on node 22.13, which is what this repository
// runs:
//
//     cts ciphers: []            <- no CBC ciphertext-stealing mode
//     rc4:         []            <- OpenSSL 3 moved it to the legacy provider
//     md4:         unsupported   <- likewise
//     md5:         OK in node's crypto, ABSENT from Web Crypto
//
// The last line is the one that surprises people. `crypto.subtle` supports
// exactly SHA-1, SHA-256, SHA-384 and SHA-512, so MD5 has to be written out
// even though node has it — this module is bundled into the browser, where the
// node implementation does not exist, and a module that behaves differently in
// the two places is worse than one that is slower in both.
//
// **This file must not `require("crypto")`.** It is staged into client/src and
// bundled by browserify, which substitutes a bare `require("crypto")` with the
// whole crypto-browserify shim — and that shim contains `elliptic`, which
// carries GHSA-848j-6mx2-7j84 with no patched version in existence. See
// "Keeping elliptic out of the bundles" in client/CLAUDE.md;
// tests/jwk_pem_encoding.js fails the build if this rule is broken.
//
// MD4 and RC4 are here because etype 23 (arcfour-hmac-md5) needs them, and
// etype 23 is here because it is what the estates that actually need debugging
// are still running. Microsoft is retiring it — the Windows Server 2025
// security baseline disables it — so it is implemented, exercised and clearly
// labelled as legacy rather than left out.
//
// Nothing in this file is a general-purpose cryptographic offering. MD4, MD5
// and RC4 are all broken and are present only because a wire protocol this
// tool has to speak still uses them.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly,
// or the mock KDC) may not have one, so fall back to info rather than failing
// to load.
var log = bunyan.createLogger({
  name: "krb5_primitives",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      // A missing log level must not stop the module loading.
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// Bytes.
//
// One representation throughout: Uint8Array. Buffer is a Uint8Array so it
// arrives here unconverted, and a caller in the browser has no Buffer at all.
// ---------------------------------------------------------------------------

function toBytes(value) {
  if (value === null || value === undefined) return new Uint8Array(0);
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new Error("krb5: expected bytes, got " + (typeof value));
}

// UTF-8, written out rather than taken from TextEncoder so that the module has
// the same behaviour wherever it runs. Kerberos principal names and passwords
// are not ASCII-only in general.
function utf8(text) {
  var s = String(text);
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      // A surrogate pair is one code point, and encoding the halves separately
      // (CESU-8) produces bytes a KDC will hash to something else.
      var lo = s.charCodeAt(i + 1);
      var cp = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
               0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      i++;
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(out);
}

// UTF-16 little-endian: the encoding the NT hash is taken over, and the reason
// etype 23 keys are what they are. No surrogate handling is needed because
// JavaScript strings are already UTF-16 code units.
function utf16le(text) {
  var s = String(text);
  var out = new Uint8Array(s.length * 2);
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = (c >> 8) & 0xff;
  }
  return out;
}

function concat(list) {
  var total = 0, i;
  for (i = 0; i < list.length; i++) total += list[i].length;
  var out = new Uint8Array(total);
  var at = 0;
  for (i = 0; i < list.length; i++) { out.set(list[i], at); at += list[i].length; }
  return out;
}

function xor(a, b) {
  var n = Math.min(a.length, b.length);
  var out = new Uint8Array(n);
  for (var i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}

function toHex(bytes) {
  var b = toBytes(bytes), s = "";
  for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
  return s;
}

function fromHex(text) {
  var s = String(text).replace(/[\s:]/g, "");
  if (s.length % 2) throw new Error("krb5: hex string has an odd length");
  var out = new Uint8Array(s.length / 2);
  for (var i = 0; i < out.length; i++) {
    var byte = parseInt(s.substr(i * 2, 2), 16);
    if (isNaN(byte)) throw new Error("krb5: not hex at offset " + (i * 2));
    out[i] = byte;
  }
  return out;
}

// Constant-time comparison. Every checksum verification in this codec goes
// through it: a Kerberos integrity check that leaks its answer through timing
// is exactly the thing an attacker with a forged ticket would measure, and
// early-exit is the natural way to write the loop.
function equalConstantTime(a, b) {
  var x = toBytes(a), y = toBytes(b);
  if (x.length !== y.length) return false;
  var diff = 0;
  for (var i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// n-fold (RFC 3961 section 5.1).
//
// A length-changing fold: replicate the input until it is a whole number of
// output-sized chunks, rotating right by 13 bits on each repetition, then add
// the chunks together with end-around carry. It is used to stretch a constant
// to a cipher block ("kerberos" to 16 bytes) and to compress a key-usage
// constant, so getting it wrong makes every derived key wrong and nothing else
// says so.
//
// This is a port of the reference implementation, kept in its original shape
// on purpose: the index arithmetic below is not obvious, and a version
// rewritten to read better is a version whose disagreement with the RFC's
// published vectors nobody can localise. Those vectors are in
// tests/krb5_crypto.js.
//
// No logging inside: it is called for every key derivation.
// ---------------------------------------------------------------------------
function nfold(input, outBits) {
  var inBytes = toBytes(input);
  var inLen = inBytes.length;
  var outLen = outBits >> 3;
  if (outLen <= 0) throw new Error("krb5: nfold output size must be positive");
  if (inLen === 0) throw new Error("krb5: nfold input must not be empty");

  // lcm(outLen, inLen)
  var a = outLen, b = inLen, c;
  while (b !== 0) { c = b; b = a % b; a = c; }
  var lcm = (outLen * inLen) / a;

  var out = new Uint8Array(outLen);
  var byte = 0;
  for (var i = lcm - 1; i >= 0; i--) {
    // The most significant bit of the input that lands in this output byte.
    var msbit = (((inLen << 3) - 1) +
                 (((inLen << 3) + 13) * Math.floor(i / inLen)) +
                 ((inLen - (i % inLen)) << 3)) % (inLen << 3);
    byte += (((inBytes[(((inLen - 1) - (msbit >> 3)) % inLen + inLen) % inLen] << 8) |
              (inBytes[((inLen - (msbit >> 3)) % inLen + inLen) % inLen])) >>> ((msbit & 7) + 1)) & 0xff;
    byte += out[i % outLen];
    out[i % outLen] = byte & 0xff;
    byte >>= 8;                       // carry
  }
  if (byte) {                         // end-around carry
    for (var j = outLen - 1; j >= 0; j--) {
      byte += out[j];
      out[j] = byte & 0xff;
      byte >>= 8;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// MD4 (RFC 1320) and MD5 (RFC 1321).
//
// Both are here for etype 23 alone: MD4 is the NT hash (the string-to-key for
// arcfour-hmac-md5 is MD4 of the UTF-16LE password, unsalted), and MD5 is
// underneath its HMAC. Neither is used anywhere else in this codec, and
// neither should be.
//
// The two share their padding and their little-endian word order, so the
// message schedule below is common to both.
// ---------------------------------------------------------------------------

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

// Length-pad to a multiple of 64 bytes with the bit length appended as a
// little-endian 64-bit value: identical for MD4 and MD5.
function padMdInput(bytes) {
  var len = bytes.length;
  var withOne = len + 1;
  var padded = new Uint8Array(withOne + ((56 - (withOne % 64)) + 64) % 64 + 8);
  padded.set(bytes);
  padded[len] = 0x80;
  var bitsLo = (len << 3) >>> 0;
  var bitsHi = Math.floor(len / 0x20000000) >>> 0;
  var at = padded.length - 8;
  padded[at] = bitsLo & 0xff;
  padded[at + 1] = (bitsLo >>> 8) & 0xff;
  padded[at + 2] = (bitsLo >>> 16) & 0xff;
  padded[at + 3] = (bitsLo >>> 24) & 0xff;
  padded[at + 4] = bitsHi & 0xff;
  padded[at + 5] = (bitsHi >>> 8) & 0xff;
  padded[at + 6] = (bitsHi >>> 16) & 0xff;
  padded[at + 7] = (bitsHi >>> 24) & 0xff;
  return padded;
}

function wordsOfBlock(padded, offset) {
  var X = new Array(16);
  for (var i = 0; i < 16; i++) {
    var j = offset + i * 4;
    X[i] = (padded[j] | (padded[j + 1] << 8) | (padded[j + 2] << 16) | (padded[j + 3] << 24)) >>> 0;
  }
  return X;
}

function digestToBytes(state) {
  var out = new Uint8Array(state.length * 4);
  for (var i = 0; i < state.length; i++) {
    out[i * 4] = state[i] & 0xff;
    out[i * 4 + 1] = (state[i] >>> 8) & 0xff;
    out[i * 4 + 2] = (state[i] >>> 16) & 0xff;
    out[i * 4 + 3] = (state[i] >>> 24) & 0xff;
  }
  return out;
}

// Round 3 visits the message words out of order; rounds 1 and 2 are expressible
// as arithmetic on the loop index, so only this one needs a table.
var MD4_R3_ORDER = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

function md4(input) {
  var padded = padMdInput(toBytes(input));
  var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  var F = function (x, y, z) { return ((x & y) | (~x & z)) >>> 0; };
  var G = function (x, y, z) { return ((x & y) | (x & z) | (y & z)) >>> 0; };
  var H = function (x, y, z) { return (x ^ y ^ z) >>> 0; };
  for (var off = 0; off < padded.length; off += 64) {
    var X = wordsOfBlock(padded, off);
    var a = h[0], b = h[1], c = h[2], d = h[3], i;
    // Written as the RFC writes it — four operations per group, registers named
    // in the [abcd] [dabc] [cdab] [bcda] rotation — rather than as a loop over a
    // shift table. The compact form is one transposition away from being wrong
    // in a way only the published vectors would catch.
    for (i = 0; i < 16; i += 4) {                                    // round 1
      a = rotl((a + F(b, c, d) + X[i]) >>> 0, 3);
      d = rotl((d + F(a, b, c) + X[i + 1]) >>> 0, 7);
      c = rotl((c + F(d, a, b) + X[i + 2]) >>> 0, 11);
      b = rotl((b + F(c, d, a) + X[i + 3]) >>> 0, 19);
    }
    for (i = 0; i < 4; i++) {                                        // round 2
      a = rotl((a + G(b, c, d) + X[i] + 0x5a827999) >>> 0, 3);
      d = rotl((d + G(a, b, c) + X[i + 4] + 0x5a827999) >>> 0, 5);
      c = rotl((c + G(d, a, b) + X[i + 8] + 0x5a827999) >>> 0, 9);
      b = rotl((b + G(c, d, a) + X[i + 12] + 0x5a827999) >>> 0, 13);
    }
    for (i = 0; i < 16; i += 4) {                                    // round 3
      a = rotl((a + H(b, c, d) + X[MD4_R3_ORDER[i]] + 0x6ed9eba1) >>> 0, 3);
      d = rotl((d + H(a, b, c) + X[MD4_R3_ORDER[i + 1]] + 0x6ed9eba1) >>> 0, 9);
      c = rotl((c + H(d, a, b) + X[MD4_R3_ORDER[i + 2]] + 0x6ed9eba1) >>> 0, 11);
      b = rotl((b + H(c, d, a) + X[MD4_R3_ORDER[i + 3]] + 0x6ed9eba1) >>> 0, 15);
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
  }
  return digestToBytes(h);
}

var MD5_K = (function () {
  var k = new Array(64);
  for (var i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  return k;
})();
var MD5_SHIFT = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

function md5(input) {
  var padded = padMdInput(toBytes(input));
  var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  for (var off = 0; off < padded.length; off += 64) {
    var X = wordsOfBlock(padded, off);
    var a = h[0], b = h[1], c = h[2], d = h[3];
    for (var i = 0; i < 64; i++) {
      var f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      var tmp = d;
      d = c; c = b;
      b = (b + rotl((a + (f >>> 0) + MD5_K[i] + X[g]) >>> 0, MD5_SHIFT[i])) >>> 0;
      a = tmp;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
  }
  return digestToBytes(h);
}

// HMAC-MD5 (RFC 2104), needed because Web Crypto will not do HMAC over a hash
// it does not implement. Block size 64 bytes, same as the SHA-2 family below it.
function hmacMd5(key, message) {
  var k = toBytes(key);
  if (k.length > 64) k = md5(k);
  var ipad = new Uint8Array(64), opad = new Uint8Array(64);
  ipad.set(k); opad.set(k);
  for (var i = 0; i < 64; i++) { ipad[i] ^= 0x36; opad[i] ^= 0x5c; }
  return md5(concat([opad, md5(concat([ipad, toBytes(message)]))]));
}

// ---------------------------------------------------------------------------
// RC4 (etype 23's cipher).
//
// Symmetric: the same call encrypts and decrypts.
// ---------------------------------------------------------------------------
function rc4(key, data) {
  var k = toBytes(key), input = toBytes(data);
  var s = new Uint8Array(256), i, j = 0, t;
  for (i = 0; i < 256; i++) s[i] = i;
  for (i = 0; i < 256; i++) {
    j = (j + s[i] + k[i % k.length]) & 0xff;
    t = s[i]; s[i] = s[j]; s[j] = t;
  }
  var out = new Uint8Array(input.length);
  i = 0; j = 0;
  for (var n = 0; n < input.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    t = s[i]; s[i] = s[j]; s[j] = t;
    out[n] = input[n] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

module.exports = {
  toBytes: toBytes,
  utf8: utf8,
  utf16le: utf16le,
  concat: concat,
  xor: xor,
  toHex: toHex,
  fromHex: fromHex,
  equalConstantTime: equalConstantTime,
  nfold: nfold,
  md4: md4,
  md5: md5,
  hmacMd5: hmacMd5,
  rc4: rc4
};
