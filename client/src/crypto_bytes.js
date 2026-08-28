// File: crypto_bytes.js
//
// ---------------------------------------------------------------------------
// Bytes, and the four ways this project writes them down.
//
// Every page that does cryptography needs the same dozen conversions —
// UTF-8 <-> bytes, base64, base64url, hex, PEM framing, a constant-time
// compare, a random buffer — and until this module existed three files carried
// their own copy of them: jose_jwe.js (base64url and PEM, for JWE),
// digital_signature.js (all of them, for five signature schemes and three MAC
// families) and key_material.js (which took jose_jwe's rather than writing a
// third set, and was the only one that did).
//
// They are here now, once, because a copy of a conversion is not a copy of a
// decision: base64 and base64url differ by two characters and a padding rule,
// `atob` throws on whitespace a textarea puts there for free, and a PEM parser
// that keeps the header line produces bytes that are wrong in a way nothing
// notices until somebody else's tool reads them. Those are exactly the choices
// that drift when they are made twice.
//
// NO DOM AND NO CRYPTOGRAPHY. Everything here is a pure function of its
// arguments except randomBytes(), which is the one line that needs a Web Crypto
// global — so the whole module loads in node, which is what lets
// tests/crypto_engines.js drive it and everything built on it with no browser.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "crypto_bytes",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------
function strBytes(str) {
  log.debug("Entering strBytes().");
  log.debug("Leaving strBytes().");
  return new TextEncoder().encode(String(str === undefined ? '' : str));
}

function bytesToStr(bytes) {
  log.debug("Entering bytesToStr().");
  log.debug("Leaving bytesToStr().");
  return new TextDecoder().decode(asBytes(bytes));
}

// Anything byte-shaped as a Uint8Array. ArrayBuffer, a typed-array view over a
// larger buffer, or an ordinary array all arrive here from somewhere — Web
// Crypto returns ArrayBuffers, @noble returns Uint8Arrays, forge returns
// binary strings that a caller has already decoded.
function asBytes(input) {
  log.debug("Entering asBytes().");
  if (input instanceof Uint8Array) {
    log.debug("Leaving asBytes(). Already a Uint8Array.");
    return input;
  }
  log.debug("Leaving asBytes().");
  return new Uint8Array(input || []);
}

// ---------------------------------------------------------------------------
// base64 and base64url
//
// The whitespace strip on the way IN is not tidiness: every one of these is
// fed from a <textarea>, which wraps long values, and `atob` throws on a
// newline rather than ignoring it.
// ---------------------------------------------------------------------------
function bytesToB64(input) {
  log.debug("Entering bytesToB64().");
  var bytes = asBytes(input);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  log.debug("Leaving bytesToB64().");
  return btoa(bin);
}

function b64ToBytes(b64) {
  log.debug("Entering b64ToBytes().");
  var bin = atob(String(b64).replace(/\s+/g, ''));
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  log.debug("Leaving b64ToBytes().");
  return bytes;
}

function bytesToB64u(input) {
  log.debug("Entering bytesToB64u().");
  log.debug("Leaving bytesToB64u().");
  return bytesToB64(input).replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=+$/, '');
}

function strToB64u(str) {
  log.debug("Entering strToB64u().");
  log.debug("Leaving strToB64u().");
  return bytesToB64u(strBytes(str));
}

function b64uToBytes(b64u) {
  log.debug("Entering b64uToBytes().");
  var s = String(b64u).replace(/\s+/g, '').replace(/-/g, '+')
      .replace(/_/g, '/');
  var pad = '==='.slice(0, (4 - s.length % 4) % 4);
  log.debug("Leaving b64uToBytes().");
  return b64ToBytes(s + pad);
}

function b64uToStr(b64u) {
  log.debug("Entering b64uToStr().");
  log.debug("Leaving b64uToStr().");
  return bytesToStr(b64uToBytes(b64u));
}

// ---------------------------------------------------------------------------
// hex
// ---------------------------------------------------------------------------
function bytesToHex(input) {
  log.debug("Entering bytesToHex().");
  var bytes = asBytes(input);
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += ('0' + bytes[i].toString(16)).slice(-2);
  }
  log.debug("Leaving bytesToHex().");
  return out;
}

// Refuses a non-hex character rather than reading it as 0, which is what
// parseInt does: a key field holding "0x1234" or a pasted "de ad be ef!" would
// otherwise encrypt under a key that is not the one on the screen, and the
// only symptom is a decryption that fails on the other side.
function hexToBytes(hex) {
  log.debug("Entering hexToBytes().");
  var text = String(hex).replace(/\s+/g, '');
  if (text.length % 2) {
    log.debug("Leaving hexToBytes(). Odd length.");
    throw new Error('Hex value has an odd number of digits (' + text.length +
                    ').');
  }
  if (text.length && !/^[0-9a-fA-F]+$/.test(text)) {
    log.debug("Leaving hexToBytes(). Not hex.");
    throw new Error('Value is not hexadecimal.');
  }
  var out = new Uint8Array(text.length >> 1);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(text.substr(i * 2, 2), 16);
  }
  log.debug("Leaving hexToBytes().");
  return out;
}

// ---------------------------------------------------------------------------
// Buffers
// ---------------------------------------------------------------------------
function concatBytes() {
  log.debug("Entering concatBytes().");
  var total = 0, i;
  for (i = 0; i < arguments.length; i++) {
    total += asBytes(arguments[i]).length;
  }
  var out = new Uint8Array(total), offset = 0;
  for (i = 0; i < arguments.length; i++) {
    var part = asBytes(arguments[i]);
    out.set(part, offset);
    offset += part.length;
  }
  log.debug("Leaving concatBytes().");
  return out;
}

// Constant time in the length it compares. The early return on a length
// mismatch leaks the length and nothing else, which is what every comparison
// of this shape does — a tag's length is public.
function bytesEqual(a, b) {
  log.debug("Entering bytesEqual().");
  var left = asBytes(a), right = asBytes(b);
  if (left.length !== right.length) {
    log.debug("Leaving bytesEqual(). Different lengths.");
    return false;
  }
  var diff = 0;
  for (var i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  log.debug("Leaving bytesEqual().");
  return diff === 0;
}

function randomBytes(count) {
  log.debug("Entering randomBytes(). count=" + count);
  var out = new Uint8Array(count);
  crypto.getRandomValues(out);
  log.debug("Leaving randomBytes().");
  return out;
}

function xorBytes(a, b) {
  log.debug("Entering xorBytes().");
  var left = asBytes(a), right = asBytes(b);
  var out = new Uint8Array(Math.min(left.length, right.length));
  for (var i = 0; i < out.length; i++) out[i] = left[i] ^ right[i];
  log.debug("Leaving xorBytes().");
  return out;
}

// A big-endian 32-bit counter, which is what every KDF in this tree prefixes
// its rounds with.
function uint32be(value) {
  log.debug("Entering uint32be().");
  var out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  log.debug("Leaving uint32be().");
  return out;
}

// A native BigInt as fixed-length big-endian bytes — an affine coordinate for
// a JWK, a finite-field element for ElGamal.
function bigToBytes(value, length) {
  log.debug("Entering bigToBytes().");
  var hex = value.toString(16);
  if (hex.length > length * 2) {
    log.debug("Leaving bigToBytes(). Too large.");
    throw new Error('Value does not fit in ' + length + ' bytes.');
  }
  while (hex.length < length * 2) hex = '0' + hex;
  log.debug("Leaving bigToBytes().");
  return hexToBytes(hex);
}

function bytesToBig(input) {
  log.debug("Entering bytesToBig().");
  var hex = bytesToHex(input);
  log.debug("Leaving bytesToBig().");
  return hex ? BigInt('0x' + hex) : BigInt(0);
}

// ---------------------------------------------------------------------------
// PEM
//
// Two pairs, and they are not interchangeable. derToPem/pemToDer carry DER —
// a PKCS#8 or SubjectPublicKeyInfo structure — and are what key_material.js
// and jose_jwe.js pass to Web Crypto. rawToPem/pemToRaw carry OPAQUE BYTES in
// PEM framing, which is what a scheme with no standard ASN.1 encoding gets
// (SLH-DSA, ML-DSA and ML-KEM keys are byte strings, not structures).
// ---------------------------------------------------------------------------
function derToPem(der, label) {
  log.debug("Entering derToPem(). label=" + label);
  var b64 = bytesToB64(der);
  var lines = b64.match(/.{1,64}/g) || [''];
  log.debug("Leaving derToPem().");
  return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
         '\n-----END ' + label + '-----\n';
}

// THE LABEL MAY CONTAIN HYPHENS, and the obvious regex does not allow for it.
//
// `-----[^-]+-----` reads `-----BEGIN PRIVATE KEY-----` and stops dead at
// `-----BEGIN SLH-DSA PRIVATE KEY-----`, because `[^-]+` cannot cross the
// hyphen in the algorithm's name. The header then survives the strip, reaches
// atob, and throws `Invalid character` — a message about base64, from a
// function that was handed a perfectly good PEM.
//
// That is not hypothetical: it is what this module did when jose_jwe.js's
// version of this function (which had only ever seen `PRIVATE KEY` and
// `PUBLIC KEY`) became the shared one. Every SLH-DSA and ML-DSA operation on
// the Digital Signature page failed at once, reporting "signature was not
// produced" — a sentence about signing, on a page whose signing was fine.
// ML-KEM keys on the Encryption page are framed the same way.
function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  var body = String(pem)
    .replace(/-----(?:BEGIN|END)[^\n]*?-----/g, '')
    .replace(/\s+/g, '');
  log.debug("Leaving pemToDer().");
  return b64ToBytes(body);
}

var rawToPem = derToPem;
var pemToRaw = pemToDer;

// Both readers take ONE block. base64 padding is only valid at the end of a
// string, so two padded bodies concatenated are not one base64 value and atob
// refuses them — a file holding a public and a private block (which is what
// the raw-key downloads write) has to be split on its BEGIN lines first.
// Every caller in this tree passes a single block.

// The label of the first PEM block in a text, or null when there is none.
// Used to tell a caller what it actually pasted — "that is a CERTIFICATE, not
// a private key" is a better message than a Web Crypto DataError.
// Same hyphen trap as pemToDer() above, and it was here too: `([^-]+)` cannot
// match `SLH-DSA PRIVATE KEY`, so this returned null for exactly the labels a
// reader most needs named.
function pemLabel(pem) {
  log.debug("Entering pemLabel().");
  var match = /-----BEGIN ([^\n]*?)-----/.exec(String(pem || ''));
  log.debug("Leaving pemLabel().");
  return match ? match[1].trim() : null;
}

module.exports = {
  // text
  strBytes: strBytes,
  bytesToStr: bytesToStr,
  asBytes: asBytes,
  // base64 / base64url
  bytesToB64: bytesToB64,
  b64ToBytes: b64ToBytes,
  bytesToB64u: bytesToB64u,
  strToB64u: strToB64u,
  b64uToBytes: b64uToBytes,
  b64uToStr: b64uToStr,
  // hex
  bytesToHex: bytesToHex,
  hexToBytes: hexToBytes,
  // buffers
  concatBytes: concatBytes,
  bytesEqual: bytesEqual,
  randomBytes: randomBytes,
  xorBytes: xorBytes,
  uint32be: uint32be,
  bigToBytes: bigToBytes,
  bytesToBig: bytesToBig,
  // PEM
  derToPem: derToPem,
  pemToDer: pemToDer,
  rawToPem: rawToPem,
  pemToRaw: pemToRaw,
  pemLabel: pemLabel
};
