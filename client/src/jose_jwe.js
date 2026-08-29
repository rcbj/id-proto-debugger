// File: jose_jwe.js
//
// ---------------------------------------------------------------------------
// JWE in the browser — compact serialization, RFC 7516 / RFC 7518.
//
// Extracted from jwt_tools.js so that more than one page can encrypt and
// decrypt with the same code. OID4VCI section 10 has a Credential Issuer and a
// Wallet encrypting to each other, and the last thing that should exist twice
// is the Concat KDF: two independent readings of RFC 7518 section 4.6 can agree
// with each other perfectly and still be wrong, and nothing would notice until
// something else tried to decrypt the result.
//
// What it does:
//
//   alg   RSA-OAEP, RSA-OAEP-256          key wrapping with the recipient's key
//         ECDH-ES                         direct key agreement (the agreed key
//                                         IS the content encryption key)
//         ECDH-ES+A128KW / +A192KW /      key agreement, then AES-KW wrapping of
//         +A256KW                         a fresh random CEK
//   enc   A128GCM, A192GCM, A256GCM          AEAD in one primitive
//         A128CBC-HS256, A192CBC-HS384,     AES-CBC then HMAC, RFC 7518
//         A256CBC-HS512                     section 5.2
//
// The CBC-HMAC family is here because it is the DEFAULT content encryption for
// an encrypted OpenID Connect response: a client that registers
// `userinfo_encrypted_response_alg` and says nothing about `enc` has asked for
// A128CBC-HS256, so a JWE reader that speaks only AES-GCM cannot read the
// commonest encrypted UserInfo response there is.
//
// Their CEK is TWICE the AES key size and is split in half — the FIRST half is
// the MAC key and the SECOND is the encryption key. Getting that order the
// wrong way round produces a JWE that this code reads back perfectly and that
// no other implementation can open, which is why ENC_KEY_BYTES below is the
// whole CEK length and the halves are taken in one place.
//
// ECDH-ES is limited to P-256 when encrypting (which is what the wallets and
// issuers this project talks to use); when decrypting, the curve is taken from
// the incoming epk header, so P-384 and P-521 are read as well.
//
// Keys may be given in whatever form the caller has:
//
//   * a CryptoKey                 already imported
//   * a JWK object                as it comes out of a JWKS
//   * a JWK string                as a page's text field holds it
//   * a PEM string                SPKI (public) or PKCS#8 (private)
//
// which is the difference between reusable and "reusable if you reformat
// first": jwt_tools has PEM/JWK text in a textarea, the OID4VCI panes have a
// JWK object from a metadata document.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "jose_jwe",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// Bytes and base64url — one implementation, in crypto_bytes.js.
//
// These eight lived here, and digital_signature.js had its own copy of most of
// them, and key_material.js took THESE rather than writing a third set. They
// are now all one set, for the reason that module's header gives: base64 and
// base64url differ by two characters and a padding rule, and a conversion
// written twice is a decision made twice.
//
// They are still re-exported from here, because a caller that has this module
// for JWE should not need a second require to read the value it just got back.
// ---------------------------------------------------------------------------
var bytes = require("./crypto_bytes");

var bytesToB64u = bytes.bytesToB64u;
var strToB64u = bytes.strToB64u;
var b64uToBytes = bytes.b64uToBytes;
var b64uToStr = bytes.b64uToStr;
var derToPem = bytes.derToPem;
var concatBytes = bytes.concatBytes;
var uint32be = bytes.uint32be;

// The one that is NOT a straight re-export. Every caller here hands the result
// to crypto.subtle.importKey(), which takes a BufferSource — but this has
// returned an ArrayBuffer since it was written, and something reading
// `.byteLength` off it would keep working while something reading `.length`
// would silently see undefined. Preserved rather than "tidied".
function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  log.debug("Leaving pemToDer().");
  return bytes.pemToDer(pem).buffer;
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------
// JWE content-encryption key sizes (bytes).
// The FULL content-encryption key length in bytes. For AES-GCM that is the AES
// key; for the CBC-HMAC family it is the MAC key and the AES key together, and
// RFC 7518 section 5.2.2 defines the CEK that way — so ECDH-ES's Concat KDF and
// every random-CEK path below ask for the right number of bytes without
// knowing which family they are serving.
var ENC_KEY_BYTES = {
  A128GCM: 16, A192GCM: 24, A256GCM: 32,
  'A128CBC-HS256': 32, 'A192CBC-HS384': 48, 'A256CBC-HS512': 64
};

// RFC 7518 section 5.2.2: for each CBC-HMAC enc, the size of EACH half of the
// CEK, the HMAC hash, and how much of the HMAC output becomes the tag — which
// is the first half of it, not all of it. A verifier that compares the whole
// HMAC output against a 16-byte tag rejects every valid token.
var CBC_HMAC = {
  'A128CBC-HS256': { halfBytes: 16, hash: 'SHA-256', tagBytes: 16 },
  'A192CBC-HS384': { halfBytes: 24, hash: 'SHA-384', tagBytes: 24 },
  'A256CBC-HS512': { halfBytes: 32, hash: 'SHA-512', tagBytes: 32 }
};

// The hash each RSA-OAEP variant uses.
var JWE_RSA_HASH = { 'RSA-OAEP': 'SHA-1', 'RSA-OAEP-256': 'SHA-256' };

// ECDH-ES key-agreement key-wrap variants (RFC 7518 section 4.6) -> AES
// key-wrap size in bytes. Plain "ECDH-ES" (direct key agreement) is handled
// separately.
var ECDH_KW_BYTES = { 'ECDH-ES+A128KW': 16, 'ECDH-ES+A192KW': 24,
    'ECDH-ES+A256KW': 32 };

// The curve used when THIS side chooses: P-256. Decryption follows the epk.
var ECDH_CURVE = 'P-256';
var ECDH_CURVE_BITS = 256;
var CURVE_BITS = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };

function isEcdh(alg) {
  log.debug("Entering isEcdh().");
  log.debug("Leaving isEcdh().");
  return alg === 'ECDH-ES' || ECDH_KW_BYTES[alg] !== undefined;
}
// ---------------------------------------------------------------------------
// WHAT THIS FILE DOES WHEN WEB CRYPTO WILL NOT.
//
// Chrome implements AES at 128 and 256 and REFUSES 192 — for GCM, for CBC and
// for key wrapping alike (measured; node's Web Crypto does support them, which
// is a good way to be misled by a unit test). That takes three registered JOSE
// algorithms off the table in the one place they are most likely to be met: a
// browser. A192GCM, A192CBC-HS384 and ECDH-ES+A192KW are not exotic — they are
// simply the middle size.
//
// So the AES-192 operations are performed HERE, in JavaScript, on the same
// node-forge engine `symmetric_crypto.js` already uses for the Encryption
// page's ciphers and the Digital Signature page's block-cipher MACs — an
// engine `tests/crypto_engines.js` drives against the RFCs' own vectors and
// against OpenSSL. This is the same trade `jws.js` makes for secp256k1 and
// Ed448, and for the same reason: an algorithm the tool cannot perform is a
// case it cannot debug.
//
// THE RULE IS BY KEY SIZE AND NOT BY A CAPABILITY PROBE, deliberately: 192
// always goes through the JavaScript path and 128/256 always go through Web
// Crypto. A probe would make the code path depend on the browser, so a defect
// in the JavaScript path would be invisible in node (where Web Crypto does 192)
// and appear only in Chrome. This way both paths are exercised everywhere, and
// `tests/jose_jwe_encryption.js` checks the two against each other.
// ---------------------------------------------------------------------------
var symmetric = require("./symmetric_crypto");

// Web Crypto is used for these key sizes; anything else is done in JavaScript.
// AES-192 is the size every browser-grade Web Crypto refuses, so it is decided
// here by a FIXED RULE rather than by the probe — see the block above.
function webCryptoDoesAes(keyBytes) {
  log.debug("Entering webCryptoDoesAes().");
  log.debug("Leaving webCryptoDoesAes().");
  return keyBytes === 16 || keyBytes === 32;
}

// ---------------------------------------------------------------------------
// THE ONE PLACE THAT ASKS "CAN WEB CRYPTO DO THIS", AND WHAT THE ANSWER IS FOR.
//
// It chooses an ENGINE. It never decides whether an algorithm is available,
// and nothing downstream of it may: this module implements every algorithm it
// offers in JavaScript as well, so a browser that refuses one changes which
// code runs and nothing else. A runtime's gaps are that runtime's business —
// a debugger that inherited them would refuse to reproduce exactly the case
// somebody came here with, and would report the refusal as if the ALGORITHM
// were unavailable rather than one implementation of it.
//
// The fixed rule above covers AES-192, which is the known case. This adds the
// unknown ones: any size or family a particular runtime turns out to refuse
// falls through to the JavaScript engine instead of failing.
// ---------------------------------------------------------------------------
async function webCryptoCanDo(family, keyBytes) {
  log.debug("Entering webCryptoCanDo(). " + family + "/" + (keyBytes * 8));
  if (!webCryptoDoesAes(keyBytes)) {
    log.debug("Leaving webCryptoCanDo(). AES-192 always goes to JavaScript.");
    return false;
  }
  var support = await probeAesSupport();
  var ok = !(support && support[family] &&
             support[family][keyBytes * 8] === false);
  log.debug("Leaving webCryptoCanDo(). " + ok);
  return ok;
}

// RFC 3394 key wrapping, on the raw AES block. Web Crypto has this as 'AES-KW'
// at 128 and 256; this is the same construction for the size it has not.
var AES_KW_IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6,
                                0xa6, 0xa6, 0xa6, 0xa6]);

function aesKwWrapJs(kek, plaintextKey) {
  log.debug("Entering aesKwWrapJs().");
  var n = plaintextKey.length / 8;
  var a = AES_KW_IV.slice(0);
  var r = [];
  var i;
  for (i = 0; i < n; i++) {
    r.push(plaintextKey.slice(i * 8, i * 8 + 8));
  }
  for (var j = 0; j < 6; j++) {
    for (i = 1; i <= n; i++) {
      var b = symmetric.aesBlock(kek, concatBytes(a, r[i - 1]));
      a = b.slice(0, 8);
      // XOR the round counter t = n*j + i into the low-order end of A. It is
      // written over the last four octets because t cannot exceed 6n and n is
      // small; the octets above them are always zero.
      var t = n * j + i;
      a[7] ^= t & 0xff;
      a[6] ^= (t >>> 8) & 0xff;
      a[5] ^= (t >>> 16) & 0xff;
      a[4] ^= (t >>> 24) & 0xff;
      r[i - 1] = b.slice(8, 16);
    }
  }
  var out = new Uint8Array(8 * (n + 1));
  out.set(a, 0);
  for (i = 0; i < n; i++) {
    out.set(r[i], 8 * (i + 1));
  }
  log.debug("Leaving aesKwWrapJs().");
  return out;
}

function aesKwUnwrapJs(kek, wrapped) {
  log.debug("Entering aesKwUnwrapJs().");
  var n = wrapped.length / 8 - 1;
  var a = wrapped.slice(0, 8);
  var r = [];
  var i;
  for (i = 0; i < n; i++) {
    r.push(wrapped.slice(8 * (i + 1), 8 * (i + 2)));
  }
  for (var j = 5; j >= 0; j--) {
    for (i = n; i >= 1; i--) {
      var t = n * j + i;
      var av = a.slice(0);
      av[7] ^= t & 0xff;
      av[6] ^= (t >>> 8) & 0xff;
      av[5] ^= (t >>> 16) & 0xff;
      av[4] ^= (t >>> 24) & 0xff;
      var b = symmetric.aesBlockDecrypt(kek, concatBytes(av, r[i - 1]));
      a = b.slice(0, 8);
      r[i - 1] = b.slice(8, 16);
    }
  }
  // The integrity check RFC 3394 section 2.2.2 defines, and the only thing that
  // distinguishes a wrong key-encryption key from a right one here: A must have
  // come back as the constant it started as.
  var ok = a.length === AES_KW_IV.length;
  var diff = 0;
  for (i = 0; i < AES_KW_IV.length; i++) {
    diff |= a[i] ^ AES_KW_IV[i];
  }
  if (!ok || diff !== 0) {
    log.debug("Leaving aesKwUnwrapJs(). The integrity check failed.");
    throw new Error('the wrapped key did not unwrap: its RFC 3394 integrity ' +
        'check failed, which means the key-encryption key is not the one it ' +
        'was wrapped with.');
  }
  var out = new Uint8Array(8 * n);
  for (i = 0; i < n; i++) {
    out.set(r[i], 8 * i);
  }
  log.debug("Leaving aesKwUnwrapJs().");
  return out;
}

function isCbcHmac(enc) {
  log.debug("Entering isCbcHmac().");
  log.debug("Leaving isCbcHmac().");
  return CBC_HMAC[enc] !== undefined;
}
function isRsa(alg) {
  log.debug("Entering isRsa().");
  log.debug("Leaving isRsa().");
  return JWE_RSA_HASH[alg] !== undefined;
}
function supportedAlgs() {
  log.debug("Entering supportedAlgs().");
  log.debug("Leaving supportedAlgs().");
  return ['RSA-OAEP', 'RSA-OAEP-256',
          'ECDH-ES'].concat(Object.keys(ECDH_KW_BYTES));
}
function supportedEncs() {
  log.debug("Entering supportedEncs().");
  log.debug("Leaving supportedEncs().");
  return Object.keys(ENC_KEY_BYTES);
}

// ---------------------------------------------------------------------------
// What this browser's Web Crypto will actually do.
//
// RFC 7518 defines AES-128, AES-192 and AES-256 for both key wrapping and
// content encryption. Chrome's Web Crypto implements 128 and 256 and REJECTS
// 192 — so ECDH-ES+A192KW and A192GCM cannot be performed there however
// correctly they are coded. Node's Web Crypto does support them, which is a
// good way to be misled by a unit test.
//
// So the algorithms are probed rather than assumed, once, and a caller can say
// "not supported by this browser" instead of surfacing an OperationError from
// somewhere deep in a key import.
// ---------------------------------------------------------------------------
var aesSupportProbe = null;

function probeAesSupport() {
  log.debug("Entering probeAesSupport().");
  if (aesSupportProbe) {
    log.debug("Leaving probeAesSupport(). Cached.");
    return aesSupportProbe;
  }
  aesSupportProbe = (async function () {
    var support = { 'AES-GCM': {}, 'AES-KW': {}, 'AES-CBC': {} };
    // AES-CBC is probed at the same three sizes, which are the HALF-CEK sizes
    // the CBC-HMAC family actually uses — so the loop needs no special case
    // and only the reason string in encUnsupportedReason() does.
    var names = ['AES-GCM', 'AES-KW', 'AES-CBC'];
    var sizes = [128, 192, 256];
    for (var n = 0; n < names.length; n++) {
      for (var b = 0; b < sizes.length; b++) {
        var usages = names[n] === 'AES-KW' ? ['wrapKey'] : ['encrypt'];
        try {
          await crypto.subtle.importKey('raw', new Uint8Array(sizes[b] / 8),
            { name: names[n] }, false, usages);
          support[names[n]][sizes[b]] = true;
        } catch (e) {
          support[names[n]][sizes[b]] = false;
        }
      }
    }
    log.debug("probeAesSupport(): AES-GCM " +
              JSON.stringify(support['AES-GCM']) +
              ", AES-KW " + JSON.stringify(support['AES-KW']) +
              ", AES-CBC " + JSON.stringify(support['AES-CBC']));
    return support;
  })();
  log.debug("Leaving probeAesSupport(). Probing.");
  return aesSupportProbe;
}

// ---------------------------------------------------------------------------
// "" WHEN USABLE HERE — AND SINCE 2026-08-28 THAT IS ALWAYS, FOR EVERY
// ALGORITHM THIS MODULE OFFERS.
//
// These two functions are what a page calls to decide whether to grey an option
// out, and they now have exactly one honest answer: nothing here is unavailable
// because of the browser. Every `alg` in supportedAlgs() and every `enc` in
// supportedEncs() has a JavaScript implementation in this file or in
// symmetric_crypto.js, so a runtime that refuses one changes which engine runs
// (webCryptoCanDo() above) and nothing a user can see.
//
// THEY ARE KEPT RATHER THAN DELETED, and the reason is the callers: three pages
// call them per option to build their dropdowns, and a page that stopped asking
// would be a page with nowhere to put the answer when there IS one. The day an
// algorithm is added that genuinely cannot be performed — one needing a
// primitive nothing here implements — this is where it says so, and the pages
// need no change to show it.
//
// What must NOT come back is the old behaviour: reporting AES-192 as unusable
// because Chrome's Web Crypto refuses it. That greyed out three registered JOSE
// algorithms this module can perfectly well perform, and greyed them out in the
// one place they were most likely to be needed. An algorithm this file can do
// is never reported as unavailable.
// ---------------------------------------------------------------------------
function algUnsupportedReason(alg, support) {
  log.debug("Entering algUnsupportedReason(). alg=" + alg);
  if (supportedAlgs().indexOf(alg) === -1) {
    log.debug("Leaving algUnsupportedReason(). Not offered at all.");
    return "this module does not implement " + alg;
  }
  log.debug("Leaving algUnsupportedReason(). Usable.");
  return "";
}

function encUnsupportedReason(enc, support) {
  log.debug("Entering encUnsupportedReason(). enc=" + enc);
  if (!ENC_KEY_BYTES[enc]) {
    log.debug("Leaving encUnsupportedReason(). Unknown.");
    return "unknown content encryption algorithm";
  }
  log.debug("Leaving encUnsupportedReason(). Usable.");
  return "";
}

// ---------------------------------------------------------------------------
// Key input
// ---------------------------------------------------------------------------
function isCryptoKey(key) {
  log.debug("Entering isCryptoKey().");
  log.debug("Leaving isCryptoKey().");
  return !!key && typeof key === "object" &&
      typeof key.algorithm === "object" && "type" in key;
}

function asJwk(key) {
  log.debug("Entering asJwk().");
  if (!key) {
    log.debug("Leaving asJwk().");
    return null;
  }
  if (typeof key === "object" && !isCryptoKey(key)) {
    log.debug("Leaving asJwk().");
    return key;
  }
  if (typeof key === "string" && key.trim().charAt(0) === "{") {
    try {
      log.debug("Leaving asJwk().");
      return JSON.parse(key);
    } catch (e) {
      // Not JSON after all: treat it as PEM and let the import say so.
      log.debug("asJwk(): the text starts with { but is not JSON: " +
                e.message);
      log.debug("Leaving asJwk().");
      return null;
    }
  }
  log.debug("Leaving asJwk().");
  return null;
}

// alg/use/key_ops/ext are metadata about a key, not part of it, and Web Crypto
// rejects a JWK whose key_ops disagree with the usages asked for.
function stripJwkForImport(jwk) {
  log.debug("Entering stripJwkForImport().");
  var out = {};
  Object.keys(jwk).forEach(function (k) {
    if (['alg', 'use', 'key_ops', 'ext', 'kid', 'x5c', 'x5t', 'x5t#S256',
        'x5u'].indexOf(k) === -1) {
      out[k] = jwk[k];
    }
  });
  log.debug("Leaving stripJwkForImport().");
  return out;
}

// Import a key in any of the accepted forms. `format` is the PEM's DER format
// ("spki" for a public key, "pkcs8" for a private one).
function importKey(key, format, params, usages) {
  log.debug("Entering importKey(). format=" + format);
  if (isCryptoKey(key)) {
    log.debug("Leaving importKey(). It was already a CryptoKey.");
    return Promise.resolve(key);
  }
  var jwk = asJwk(key);
  if (jwk) {
    log.debug("Leaving importKey(). Importing a JWK.");
    return crypto.subtle.importKey('jwk', stripJwkForImport(jwk), params, false,
                                   usages);
  }
  log.debug("Leaving importKey(). Importing PEM as " + format + ".");
  return crypto.subtle.importKey(format, pemToDer(String(key)), params, false,
                                 usages);
}

// The curve a key names, so ECDH import parameters can be built for it. A JWK
// says so directly; a PEM does not, so P-256 is assumed — which is what this
// project's issuers and wallets use, and what encryption chooses anyway.
function curveOf(key, fallback) {
  log.debug("Entering curveOf().");
  var jwk = asJwk(key);
  if (jwk && jwk.crv) {
    log.debug("Leaving curveOf().");
    return jwk.crv;
  }
  log.debug("Leaving curveOf().");
  return fallback || ECDH_CURVE;
}

// ---------------------------------------------------------------------------
// The Concat KDF — NIST SP 800-56A as RFC 7518 section 4.6 uses it.
//
// This is the part worth having exactly once. The agreed secret is not the key:
// it is hashed together with the algorithm identifier and the key length, each
// length-prefixed, and a single wrong prefix produces a key that is wrong in a
// way that only shows up as "decryption failed" somewhere else entirely.
//
//   AlgorithmID   the "enc" value for direct ECDH-ES, the full "alg" for the
//                 +A*KW variants
//   PartyUInfo    empty here (no apu header)
//   PartyVInfo    empty here (no apv header)
//   SuppPubInfo   the key length in BITS
// ---------------------------------------------------------------------------
async function concatKdf(z, keyBytes, algId) {
  log.debug("Entering concatKdf(). algId=" + algId + ", keyBytes=" + keyBytes);
  var algBytes = new TextEncoder().encode(algId);
  var otherInfo = concatBytes(
    uint32be(algBytes.length), algBytes,   // AlgorithmID
    uint32be(0),                           // PartyUInfo (empty)
    uint32be(0),                           // PartyVInfo (empty)
    uint32be(keyBytes * 8)                 // SuppPubInfo = keydatalen in bits
  );                                       // SuppPrivInfo omitted
  // NIST SP 800-56A Concat KDF, and it REPEATS. One SHA-256 round yields 32
  // bytes, which covered every key size this file used to need — A128/A192/
  // A256GCM and every AES-KW size are all 32 bytes or fewer, so the loop below
  // ran once and the counter never mattered.
  //
  // A192CBC-HS384 and A256CBC-HS512 need 48 and 64 bytes, and a single round
  // cannot produce them. Before this loop existed, ECDH-ES direct agreement
  // with either of those returned 32 bytes and the CEK split then threw — the
  // failure was at least loud, but a KDF that silently stopped early would
  // have been worse: the two sides would agree on a short key and interoperate
  // with nothing that implements the whole of section 5.8.1.
  var rounds = Math.ceil(keyBytes / 32);
  var derived = new Uint8Array(rounds * 32);
  for (var counter = 1; counter <= rounds; counter++) {
    var input = concatBytes(uint32be(counter), new Uint8Array(z), otherInfo);
    var round = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    derived.set(round, (counter - 1) * 32);
  }
  log.debug("Leaving concatKdf(). " + rounds + " round(s).");
  return derived.slice(0, keyBytes);
}

// ---------------------------------------------------------------------------
// Content encryption key: produced for encryption, recovered for decryption.
//
// `protectedHeader` is written into for the ECDH-ES variants, which have to
// publish the ephemeral public key they agreed with (epk).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AES_CBC_HMAC_SHA2 — RFC 7518 section 5.2.
//
// The composite AEAD the JOSE algorithms predating widespread AES-GCM use, and
// the one an OpenID Connect client gets by default. Encrypt-then-MAC, with
// four details that each produce a token nothing else can read:
//
//   * THE CEK SPLITS MAC-KEY FIRST, ENC-KEY SECOND (section 5.2.2.1 steps 1-3).
//   * THE MAC COVERS AAD || IV || CIPHERTEXT || AL, in that order, where AL is
//     the AAD length IN BITS as a 64-bit big-endian integer — bits, not bytes,
//     and of the AAD alone.
//   * THE TAG IS THE FIRST HALF of the HMAC output, not the whole of it.
//   * The tag is compared in CONSTANT TIME on the way back, because a JWE tag
//     check that returns early is a padding oracle with extra steps.
//
// Web Crypto gives us AES-CBC with PKCS#7 padding, which is exactly what
// section 5.2.2.1 step 4 asks for, so the padding is not done by hand.
// ---------------------------------------------------------------------------

// The AAD bit length as the 8-byte big-endian AL block. Split into two 32-bit
// halves because a JavaScript number stops being exact past 2^53 and a bitwise
// shift stops working past 2^31 — neither matters at any real AAD size, and
// writing it correctly costs one line.
function alBlock(aadByteLength) {
  log.debug("Entering alBlock().");
  var bits = aadByteLength * 8;
  var out = new Uint8Array(8);
  var high = Math.floor(bits / 4294967296);
  var low = bits >>> 0;
  out.set(uint32be(high), 0);
  out.set(uint32be(low), 4);
  log.debug("Leaving alBlock().");
  return out;
}

function cbcHalves(enc, cekBytes) {
  log.debug("Entering cbcHalves(). enc=" + enc);
  var spec = CBC_HMAC[enc];
  if (!spec) {
    log.debug("Leaving cbcHalves(). Not a CBC-HMAC enc.");
    throw new Error('not an AES-CBC-HMAC content encryption: ' + enc);
  }
  if (cekBytes.length !== spec.halfBytes * 2) {
    log.debug("Leaving cbcHalves(). Wrong CEK length.");
    throw new Error(enc + ' needs a ' + (spec.halfBytes * 2) +
        '-byte content encryption key; this one is ' + cekBytes.length +
        ' bytes.');
  }
  log.debug("Leaving cbcHalves().");
  return {
    spec: spec,
    macKey: cekBytes.slice(0, spec.halfBytes),
    encKey: cekBytes.slice(spec.halfBytes)
  };
}

async function cbcHmacTag(halves, iv, aad, ciphertext) {
  log.debug("Entering cbcHmacTag().");
  var mac = await crypto.subtle.importKey('raw', halves.macKey,
      { name: 'HMAC', hash: halves.spec.hash }, false, ['sign']);
  var signed = new Uint8Array(await crypto.subtle.sign('HMAC', mac,
      concatBytes(aad, iv, ciphertext, alBlock(aad.length))));
  log.debug("Leaving cbcHmacTag().");
  return signed.slice(0, halves.spec.tagBytes);
}

async function cbcHmacEncrypt(cekBytes, enc, iv, aad, plaintext) {
  log.debug("Entering cbcHmacEncrypt(). enc=" + enc);
  var halves = cbcHalves(enc, cekBytes);
  var ciphertext = await aesCbcSeal(halves.encKey, iv, plaintext);
  var tag = await cbcHmacTag(halves, iv, aad, ciphertext);
  log.debug("Leaving cbcHmacEncrypt().");
  return { ciphertext: ciphertext, tag: tag };
}

async function cbcHmacDecrypt(cekBytes, enc, iv, aad, ciphertext, tag) {
  log.debug("Entering cbcHmacDecrypt(). enc=" + enc);
  var halves = cbcHalves(enc, cekBytes);
  var expected = await cbcHmacTag(halves, iv, aad, ciphertext);
  // Constant time, and the length is checked first because comparing arrays of
  // different lengths cannot be done in constant time anyway.
  var ok = expected.length === tag.length;
  var diff = 0;
  for (var i = 0; i < expected.length; i++) {
    diff |= expected[i] ^ (tag[i] === undefined ? ~expected[i] : tag[i]);
  }
  if (!ok || diff !== 0) {
    log.debug("Leaving cbcHmacDecrypt(). The authentication tag is wrong.");
    throw new Error('the authentication tag does not verify — this JWE was ' +
        'not produced with this key, or it has been altered.');
  }
  var plaintext = await aesCbcOpen(halves.encKey, iv, ciphertext);
  log.debug("Leaving cbcHmacDecrypt().");
  return plaintext;
}

// ---------------------------------------------------------------------------
// THE CONTENT ENCRYPTION KEY, AS RAW BYTES.
//
// Both directions produce or recover the CEK as plain octets rather than as an
// imported CryptoKey, because the two content-encryption families want it in
// different shapes: AES-GCM wants one AES key, AES-CBC-HMAC wants the octets
// split into a MAC key and an AES key. Handing back a CryptoKey would force
// this layer to know which family it is serving, and would make a 48-byte
// A192CBC-HS384 CEK unrepresentable — there is no 48-byte AES key to import it
// as.
//
// `deriveCek()` / `unwrapCek()` below are the older CryptoKey-shaped entry
// points, kept because jwt_tools.js has called them since before this file
// existed. They are AES-GCM only and say so.
// ---------------------------------------------------------------------------
async function deriveCekBytes(alg, enc, protectedHeader, recipientPublicKey) {
  log.debug("Entering deriveCekBytes(). alg=" + alg + ", enc=" + enc);
  var keyBytes = ENC_KEY_BYTES[enc];
  if (!keyBytes) throw new Error('unsupported content encryption: ' + enc);

  if (isEcdh(alg)) {
    var curve = curveOf(recipientPublicKey, ECDH_CURVE);
    var recipientPub = await importKey(recipientPublicKey, 'spki',
      { name: 'ECDH', namedCurve: curve }, []);
    var ephemeral = await crypto.subtle.generateKey({ name: 'ECDH',
        namedCurve: curve },
      true, ['deriveBits']);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH',
        public: recipientPub },
      ephemeral.privateKey, CURVE_BITS[curve] || ECDH_CURVE_BITS);
    var epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
    protectedHeader.epk = { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y };

    if (alg === 'ECDH-ES') {
      // Direct: the agreed key IS the CEK and encrypted_key is empty. The
      // Concat KDF AlgorithmID is the content-encryption "enc" value, and the
      // key data length is the WHOLE CEK — which for a CBC-HMAC enc is both
      // halves, exactly as RFC 7518 section 5.2.2 defines it.
      var direct = await concatKdf(z, keyBytes, enc);
      log.debug("Leaving deriveCekBytes(). ECDH-ES direct.");
      return { cekBytes: asCekBytes(direct), encryptedKey: '' };
    }
    // ECDH-ES+A*KW: derive a key-wrapping key (AlgorithmID is the full "alg",
    // keydatalen is the AES-KW size), then wrap a fresh random CEK with it.
    var kekBytes = await concatKdf(z, ECDH_KW_BYTES[alg], alg);
    var random = randomCekBytes(keyBytes);
    log.debug("Leaving deriveCekBytes(). " + alg + ".");
    return { cekBytes: random,
             encryptedKey: bytesToB64u(await wrapRawBytes(random, kekBytes)) };
  }

  if (!isRsa(alg)) throw new Error('unsupported key management algorithm: ' +
      alg);
  // RSA-OAEP / RSA-OAEP-256: a random CEK wrapped with the recipient's key.
  var cek = randomCekBytes(keyBytes);
  var rsaPub = await importKey(recipientPublicKey, 'spki',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['encrypt']);
  var wrappedCek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPub,
      cek);
  log.debug("Leaving deriveCekBytes(). " + alg + ".");
  return { cekBytes: cek, encryptedKey: bytesToB64u(wrappedCek) };
}

function randomCekBytes(keyBytes) {
  log.debug("Entering randomCekBytes().");
  var out = new Uint8Array(keyBytes);
  crypto.getRandomValues(out);
  log.debug("Leaving randomCekBytes().");
  return out;
}

function asCekBytes(value) {
  log.debug("Entering asCekBytes().");
  log.debug("Leaving asCekBytes().");
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

// AES-KW wraps a KEY, not a buffer, and Web Crypto will not import 48 octets as
// an AES key — so the CEK is carried through the wrap as an HMAC key, which
// accepts any length. The hash named here is never used for anything: nothing
// signs with this key, it exists to be exported straight back out as raw bytes.
async function wrapRawBytes(rawBytes, kekBytes) {
  log.debug("Entering wrapRawBytes().");
  if (!(await webCryptoCanDo('AES-KW', kekBytes.length))) {
    log.debug("Leaving wrapRawBytes(). JavaScript.");
    return aesKwWrapJs(kekBytes, rawBytes);
  }
  var kek = await crypto.subtle.importKey('raw', kekBytes, { name: 'AES-KW' },
      false, ['wrapKey']);
  var carrier = await crypto.subtle.importKey('raw', rawBytes,
      { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  var wrapped = await crypto.subtle.wrapKey('raw', carrier, kek, 'AES-KW');
  log.debug("Leaving wrapRawBytes(). Web Crypto.");
  return new Uint8Array(wrapped);
}

async function unwrapRawBytes(wrappedBytes, kekBytes) {
  log.debug("Entering unwrapRawBytes().");
  if (!(await webCryptoCanDo('AES-KW', kekBytes.length))) {
    log.debug("Leaving unwrapRawBytes(). JavaScript.");
    return aesKwUnwrapJs(kekBytes, wrappedBytes);
  }
  var kek = await crypto.subtle.importKey('raw', kekBytes, { name: 'AES-KW' },
      false, ['unwrapKey']);
  var carrier = await crypto.subtle.unwrapKey('raw', wrappedBytes, kek,
      'AES-KW', { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  var raw = await crypto.subtle.exportKey('raw', carrier);
  log.debug("Leaving unwrapRawBytes(). Web Crypto.");
  return new Uint8Array(raw);
}

// ---------------------------------------------------------------------------
// AES-GCM and AES-CBC, through Web Crypto or through JavaScript depending only
// on the key size. Both return and take the ciphertext and the tag SEPARATELY,
// which is what JWE's five segments want — Web Crypto concatenates them and
// node-forge keeps them apart, so the difference is absorbed here.
// ---------------------------------------------------------------------------
async function aesGcmSeal(cekBytes, iv, aad, plaintext) {
  log.debug("Entering aesGcmSeal().");
  if (!(await webCryptoCanDo('AES-GCM', cekBytes.length))) {
    var out = symmetric.encrypt({ id: 'AES-' + (cekBytes.length * 8) + '-GCM',
      key: cekBytes, iv: iv, plaintext: plaintext, aad: aad });
    log.debug("Leaving aesGcmSeal(). JavaScript.");
    return { ciphertext: out.ciphertext, tag: out.tag };
  }
  var key = await crypto.subtle.importKey('raw', cekBytes,
      { name: 'AES-GCM' }, false, ['encrypt']);
  var full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 },
    key, plaintext));
  log.debug("Leaving aesGcmSeal(). Web Crypto.");
  return { ciphertext: full.slice(0, full.length - 16),
           tag: full.slice(full.length - 16) };
}

async function aesGcmOpen(cekBytes, iv, aad, ciphertext, tag) {
  log.debug("Entering aesGcmOpen().");
  if (!(await webCryptoCanDo('AES-GCM', cekBytes.length))) {
    // symmetric.decrypt() returns the plaintext BYTES, not an object around
    // them — unlike encrypt(), which returns { ciphertext, tag, iv }. The
    // asymmetry is that module's and is easy to get wrong in exactly one
    // direction: reading `.plaintext` off a Uint8Array is `undefined`, which
    // then compares unequal to the input and reads as a cipher that does not
    // round-trip rather than as a property that does not exist.
    var plain = symmetric.decrypt({
      id: 'AES-' + (cekBytes.length * 8) + '-GCM',
      key: cekBytes, iv: iv, ciphertext: ciphertext, tag: tag, aad: aad });
    log.debug("Leaving aesGcmOpen(). JavaScript.");
    return plain;
  }
  var key = await crypto.subtle.importKey('raw', cekBytes,
      { name: 'AES-GCM' }, false, ['decrypt']);
  var plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 }, key,
    concatBytes(ciphertext, tag));
  log.debug("Leaving aesGcmOpen(). Web Crypto.");
  return new Uint8Array(plain);
}

async function aesCbcSeal(encKey, iv, plaintext) {
  log.debug("Entering aesCbcSeal().");
  if (!(await webCryptoCanDo('AES-CBC', encKey.length))) {
    var out = symmetric.encrypt({ id: 'AES-' + (encKey.length * 8) + '-CBC',
      key: encKey, iv: iv, plaintext: plaintext });
    log.debug("Leaving aesCbcSeal(). JavaScript.");
    return out.ciphertext;
  }
  var key = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' },
      false, ['encrypt']);
  log.debug("Leaving aesCbcSeal(). Web Crypto.");
  return new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv }, key, plaintext));
}

async function aesCbcOpen(encKey, iv, ciphertext) {
  log.debug("Entering aesCbcOpen().");
  if (!(await webCryptoCanDo('AES-CBC', encKey.length))) {
    var plain = symmetric.decrypt({
      id: 'AES-' + (encKey.length * 8) + '-CBC',
      key: encKey, iv: iv, ciphertext: ciphertext });
    log.debug("Leaving aesCbcOpen(). JavaScript.");
    return plain;
  }
  var key = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' },
      false, ['decrypt']);
  log.debug("Leaving aesCbcOpen(). Web Crypto.");
  return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: iv }, key, ciphertext));
}

async function unwrapCekBytes(alg, enc, protectedHeader, encryptedKey,
                              recipientPrivateKey) {
  log.debug("Entering unwrapCekBytes(). alg=" + alg + ", enc=" + enc);
  var keyBytes = ENC_KEY_BYTES[enc];
  if (!keyBytes) throw new Error('unsupported content encryption: ' + enc);

  if (isEcdh(alg)) {
    if (!protectedHeader.epk) throw new Error('an ECDH-ES JWE must carry an ' +
        '"epk" header.');
    var curve = protectedHeader.epk.crv || ECDH_CURVE;
    var recipientPriv = await importKey(recipientPrivateKey, 'pkcs8',
      { name: 'ECDH', namedCurve: curve }, ['deriveBits']);
    var epk = await crypto.subtle.importKey('jwk', protectedHeader.epk,
      { name: 'ECDH', namedCurve: curve }, false, []);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH', public: epk },
        recipientPriv,
      CURVE_BITS[curve] || ECDH_CURVE_BITS);
    if (alg === 'ECDH-ES') {
      var direct = await concatKdf(z, keyBytes, enc);
      log.debug("Leaving unwrapCekBytes(). ECDH-ES direct.");
      return asCekBytes(direct);
    }
    var kekBytes = await concatKdf(z, ECDH_KW_BYTES[alg], alg);
    log.debug("Leaving unwrapCekBytes(). " + alg + ".");
    return unwrapRawBytes(b64uToBytes(encryptedKey), kekBytes);
  }

  if (!isRsa(alg)) throw new Error('unsupported key management algorithm: ' +
      alg);
  var rsaPriv = await importKey(recipientPrivateKey, 'pkcs8',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['decrypt']);
  var cek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPriv,
      b64uToBytes(encryptedKey));
  log.debug("Leaving unwrapCekBytes(). " + alg + ".");
  return new Uint8Array(cek);
}

// The CryptoKey-shaped entry points. AES-GCM only — a CBC-HMAC CEK is not one
// AES key and cannot be returned this way, so it is refused by name rather than
// truncated into something that would encrypt and never decrypt.
function refuseCbcHmacHere(enc, where) {
  log.debug("Entering refuseCbcHmacHere().");
  if (!isCbcHmac(enc)) {
    log.debug("Leaving refuseCbcHmacHere().");
    return;
  }
  log.debug("Leaving refuseCbcHmacHere(). Refused.");
  throw new Error(where + '() returns one AES-GCM key and ' + enc + ' needs ' +
      'a MAC key and an AES key. Use encryptCompact()/decryptCompact(), or ' +
      where + 'Bytes().');
}

// The CryptoKey-shaped entry points hand back a Web Crypto key, so they cannot
// serve a size Web Crypto refuses to import however well this file can perform
// it in JavaScript. encryptCompact()/decryptCompact() have no such limit.
function refuseUnimportableSize(enc, where) {
  log.debug("Entering refuseUnimportableSize().");
  if (webCryptoDoesAes(ENC_KEY_BYTES[enc])) {
    log.debug("Leaving refuseUnimportableSize().");
    return;
  }
  log.debug("Leaving refuseUnimportableSize(). Refused.");
  throw new Error(where + '() returns a Web Crypto key and this browser will ' +
      'not import an AES-' + (ENC_KEY_BYTES[enc] * 8) + ' one. ' +
      'encryptCompact()/decryptCompact() perform ' + enc + ' in JavaScript ' +
      'instead — use those.');
}

async function deriveCek(alg, enc, protectedHeader, recipientPublicKey) {
  log.debug("Entering deriveCek(). alg=" + alg + ", enc=" + enc);
  refuseCbcHmacHere(enc, 'deriveCek');
  refuseUnimportableSize(enc, 'deriveCek');
  var derived = await deriveCekBytes(alg, enc, protectedHeader,
      recipientPublicKey);
  var cek = await crypto.subtle.importKey('raw', derived.cekBytes,
      { name: 'AES-GCM' }, false, ['encrypt']);
  log.debug("Leaving deriveCek().");
  return { cek: cek, encryptedKey: derived.encryptedKey };
}

async function unwrapCek(alg, enc, protectedHeader, encryptedKey,
                         recipientPrivateKey) {
  log.debug("Entering unwrapCek(). alg=" + alg + ", enc=" + enc);
  refuseCbcHmacHere(enc, 'unwrapCek');
  refuseUnimportableSize(enc, 'unwrapCek');
  var cekBytes = await unwrapCekBytes(alg, enc, protectedHeader, encryptedKey,
      recipientPrivateKey);
  log.debug("Leaving unwrapCek().");
  return crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false,
      ['decrypt']);
}

// ---------------------------------------------------------------------------
// Compact serialization
// ---------------------------------------------------------------------------
// { alg, enc, plaintext, key, header } -> the five-part compact JWE.
//
// `header` adds parameters to the protected header (kid, cty, typ, apu/apv…);
// alg and enc are set from the arguments and cannot be overridden by it, since
// they describe what this function is actually doing.
async function encryptCompact(options) {
  log.debug("Entering encryptCompact(). alg=" + options.alg + ", enc=" +
            options.enc);
  var alg = options.alg;
  var enc = options.enc;
  if (!ENC_KEY_BYTES[enc]) throw new Error('unsupported content encryption: ' +
      enc);

  var protectedHeader = {};
  Object.keys(options.header || {}).forEach(function (k) {
    protectedHeader[k] = options.header[k];
  });
  protectedHeader.alg = alg;
  protectedHeader.enc = enc;

  var derived = await deriveCekBytes(alg, enc, protectedHeader, options.key);
  var protectedB64 = strToB64u(JSON.stringify(protectedHeader));
  // RFC 7516: the AAD is ASCII(BASE64URL(protected header)).
  var aad = new TextEncoder().encode(protectedB64);

  // Twelve octets for GCM, sixteen — one AES block — for CBC. A CBC-HMAC JWE
  // built with a 12-byte IV is refused by every other implementation and by
  // this one on the way back, so the length comes off the enc rather than
  // being a constant.
  var iv = new Uint8Array(isCbcHmac(enc) ? 16 : 12);
  crypto.getRandomValues(iv);
  var plaintextBytes = typeof options.plaintext === "string"
    ? new TextEncoder().encode(options.plaintext)
    : options.plaintext;

  var sealed;
  if (isCbcHmac(enc)) {
    sealed = await cbcHmacEncrypt(derived.cekBytes, enc, iv, aad,
        plaintextBytes);
  } else {
    sealed = await aesGcmSeal(derived.cekBytes, iv, aad, plaintextBytes);
  }

  var compact = [protectedB64, derived.encryptedKey, bytesToB64u(iv),
                 bytesToB64u(sealed.ciphertext),
                 bytesToB64u(sealed.tag)].join('.');
  log.debug("Leaving encryptCompact(). " + compact.length + " characters.");
  return { jwe: compact, header: protectedHeader };
}

// The protected header of a compact JWE, without decrypting anything — enough
// to decide whether this recipient can open it, and to find the kid it names.
function parseCompact(jwe) {
  log.debug("Entering parseCompact().");
  var parts = String(jwe).trim().split('.');
  if (parts.length !== 5) {
    log.debug("Leaving parseCompact(). " + parts.length + " parts, not five.");
    throw new Error('not a JWE in compact serialization: expected five ' +
                    'segments, got ' + parts.length + '.');
  }
  var header;
  try {
    header = JSON.parse(b64uToStr(parts[0]));
  } catch (e) {
    log.debug("Leaving parseCompact(). The header is not readable JSON.");
    throw new Error('the JWE protected header is not readable JSON: ' +
                    e.message);
  }
  log.debug("Leaving parseCompact(). alg=" + header.alg + ", enc=" +
            header.enc);
  return { header: header, parts: parts };
}

// { jwe, key } -> { plaintext, header }. The algorithms come from the JWE's own
// protected header, which is authenticated as the AAD: an attacker cannot
// change them without the tag failing.
async function decryptCompact(options) {
  log.debug("Entering decryptCompact().");
  var parsed = parseCompact(options.jwe);
  var header = parsed.header;
  var parts = parsed.parts;
  if (!ENC_KEY_BYTES[header.enc]) throw new Error('unsupported content ' +
      'encryption: ' + header.enc);

  var cekBytes = await unwrapCekBytes(header.alg, header.enc, header, parts[1],
      options.key);
  var aad = new TextEncoder().encode(parts[0]);
  var iv = b64uToBytes(parts[2]);
  var plaintext;
  if (isCbcHmac(header.enc)) {
    plaintext = await cbcHmacDecrypt(cekBytes, header.enc, iv, aad,
        b64uToBytes(parts[3]), b64uToBytes(parts[4]));
  } else {
    plaintext = await aesGcmOpen(cekBytes, iv, aad, b64uToBytes(parts[3]),
        b64uToBytes(parts[4]));
  }

  log.debug("Leaving decryptCompact().");
  return { plaintext: new TextDecoder().decode(plaintext), header: header };
}

// ---------------------------------------------------------------------------
// PBES2 — a password instead of a key (RFC 7518 section 4.8).
//
// The one JWE `alg` in this file that wraps with something derived from a
// PASSWORD rather than from a key pair, and the reason it is here rather than
// beside the code that calls it: it is what password-protects a downloaded
// JWK set, and THREE places wanted that — jwt_tools and the PKI page through
// key_material.js, and both key-pair panes on the Digital Signature and
// Encryption pages. It was written twice before it was written here.
//
// PBES2-HS256+A128KW over A256GCM, 100,000 iterations. Note the salt Web
// Crypto is given is not p2s: RFC 7518 says the PBKDF2 salt is the alg name,
// a zero octet, and then p2s — get that wrong and the output is a JWE that
// only this code can open.
// ---------------------------------------------------------------------------
async function pbes2JweEncrypt(plaintext, password) {
  log.debug("Entering pbes2JweEncrypt().");
  var alg = 'PBES2-HS256+A128KW', enc = 'A256GCM';
  var p2s = crypto.getRandomValues(new Uint8Array(16));
  var p2c = 100000;
  var pwKey = await crypto.subtle.importKey('raw',
      bytes.strBytes(password), 'PBKDF2', false, ['deriveKey']);
  var saltInput = concatBytes(bytes.strBytes(alg), new Uint8Array([0]), p2s);
  var wrapKey = await crypto.subtle.deriveKey({ name: 'PBKDF2',
      salt: saltInput, iterations: p2c, hash: 'SHA-256' },
    pwKey, { name: 'AES-KW', length: 128 }, false, ['wrapKey']);
  var cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 },
      true, ['encrypt']);
  var wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', cek, wrapKey,
      'AES-KW'));
  var protectedHeader = { alg: alg, enc: enc, p2s: bytesToB64u(p2s), p2c: p2c };
  var phB64 = strToB64u(JSON.stringify(protectedHeader));
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: bytes.strBytes(phB64),
     tagLength: 128 },
    cek, bytes.strBytes(plaintext)));
  var ct = full.slice(0, full.length - 16);
  var tag = full.slice(full.length - 16);
  log.debug("Leaving pbes2JweEncrypt().");
  return [phB64, bytesToB64u(wrapped), bytesToB64u(iv), bytesToB64u(ct),
          bytesToB64u(tag)].join('.');
}

module.exports = {
  // bytes / base64url, exported so callers do not keep their own copies
  bytesToB64u: bytesToB64u,
  strToB64u: strToB64u,
  b64uToBytes: b64uToBytes,
  b64uToStr: b64uToStr,
  derToPem: derToPem,
  pemToDer: pemToDer,
  concatBytes: concatBytes,
  uint32be: uint32be,
  // algorithms
  ENC_KEY_BYTES: ENC_KEY_BYTES,
  JWE_RSA_HASH: JWE_RSA_HASH,
  ECDH_KW_BYTES: ECDH_KW_BYTES,
  ECDH_CURVE: ECDH_CURVE,
  ECDH_CURVE_BITS: ECDH_CURVE_BITS,
  isEcdh: isEcdh,
  isRsa: isRsa,
  supportedAlgs: supportedAlgs,
  supportedEncs: supportedEncs,
  probeAesSupport: probeAesSupport,
  algUnsupportedReason: algUnsupportedReason,
  encUnsupportedReason: encUnsupportedReason,
  // keys
  importKey: importKey,
  stripJwkForImport: stripJwkForImport,
  curveOf: curveOf,
  // the pieces
  concatKdf: concatKdf,
  deriveCek: deriveCek,
  unwrapCek: unwrapCek,
  deriveCekBytes: deriveCekBytes,
  unwrapCekBytes: unwrapCekBytes,
  isCbcHmac: isCbcHmac,
  // The JavaScript AES paths, exported so tests/jose_jwe_encryption.js can
  // check them against Web Crypto directly rather than only through a JWE.
  webCryptoDoesAes: webCryptoDoesAes,
  aesKwWrapJs: aesKwWrapJs,
  aesKwUnwrapJs: aesKwUnwrapJs,
  CBC_HMAC: CBC_HMAC,
  cbcHmacEncrypt: cbcHmacEncrypt,
  cbcHmacDecrypt: cbcHmacDecrypt,
  // password-based key wrapping
  pbes2JweEncrypt: pbes2JweEncrypt,
  // and the whole thing
  encryptCompact: encryptCompact,
  parseCompact: parseCompact,
  decryptCompact: decryptCompact
};
