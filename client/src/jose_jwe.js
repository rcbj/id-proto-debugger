// File: jose_jwe.js
//
// ---------------------------------------------------------------------------
// JWE in the browser — compact serialization, RFC 7516 / RFC 7518.
//
// Extracted from jwt_tools.js so that more than one page can encrypt and
// decrypt with the same code. OID4VCI section 10 has a Credential Issuer and a
// Wallet encrypting to each other, and the last thing that should exist twice is
// the Concat KDF: two independent readings of RFC 7518 section 4.6 can agree
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
//   enc   A128GCM, A192GCM, A256GCM
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
// which is the difference between reusable and "reusable if you reformat first":
// jwt_tools has PEM/JWK text in a textarea, the OID4VCI panes have a JWK object
// from a metadata document.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// A node consumer (the tests load this module directly) may have no CONFIG_FILE,
// so fall back to info rather than failing to load.
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
// Bytes and base64url
// ---------------------------------------------------------------------------
function bytesToB64u(input) {
  var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function strToB64u(str) {
  return bytesToB64u(new TextEncoder().encode(str));
}

function b64uToBytes(b64u) {
  var s = String(b64u).replace(/-/g, '+').replace(/_/g, '/');
  var pad = '==='.slice(0, (4 - s.length % 4) % 4);
  var bin = atob(s + pad);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64uToStr(b64u) {
  return new TextDecoder().decode(b64uToBytes(b64u));
}

function derToPem(der, label) {
  var bytes = new Uint8Array(der);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  var b64 = btoa(bin);
  var lines = b64.match(/.{1,64}/g).join('\n');
  return '-----BEGIN ' + label + '-----\n' + lines + '\n-----END ' + label + '-----\n';
}

function pemToDer(pem) {
  var b64 = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function concatBytes() {
  var total = 0, i;
  for (i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total);
  var offset = 0;
  for (i = 0; i < arguments.length; i++) {
    out.set(arguments[i], offset);
    offset += arguments[i].length;
  }
  return out;
}

function uint32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------
// JWE content-encryption key sizes (bytes).
var ENC_KEY_BYTES = { A128GCM: 16, A192GCM: 24, A256GCM: 32 };

// The hash each RSA-OAEP variant uses.
var JWE_RSA_HASH = { 'RSA-OAEP': 'SHA-1', 'RSA-OAEP-256': 'SHA-256' };

// ECDH-ES key-agreement key-wrap variants (RFC 7518 section 4.6) -> AES key-wrap
// size in bytes. Plain "ECDH-ES" (direct key agreement) is handled separately.
var ECDH_KW_BYTES = { 'ECDH-ES+A128KW': 16, 'ECDH-ES+A192KW': 24, 'ECDH-ES+A256KW': 32 };

// The curve used when THIS side chooses: P-256. Decryption follows the epk.
var ECDH_CURVE = 'P-256';
var ECDH_CURVE_BITS = 256;
var CURVE_BITS = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };

function isEcdh(alg) { return alg === 'ECDH-ES' || ECDH_KW_BYTES[alg] !== undefined; }
function isRsa(alg) { return JWE_RSA_HASH[alg] !== undefined; }
function supportedAlgs() { return ['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES'].concat(Object.keys(ECDH_KW_BYTES)); }
function supportedEncs() { return Object.keys(ENC_KEY_BYTES); }

// ---------------------------------------------------------------------------
// What this browser's Web Crypto will actually do.
//
// RFC 7518 defines AES-128, AES-192 and AES-256 for both key wrapping and
// content encryption. Chrome's Web Crypto implements 128 and 256 and REJECTS
// 192 — so ECDH-ES+A192KW and A192GCM cannot be performed there however
// correctly they are coded. Node's Web Crypto does support them, which is a good
// way to be misled by a unit test.
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
    var support = { 'AES-GCM': {}, 'AES-KW': {} };
    var names = ['AES-GCM', 'AES-KW'];
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
    log.debug("probeAesSupport(): AES-GCM " + JSON.stringify(support['AES-GCM']) +
              ", AES-KW " + JSON.stringify(support['AES-KW']));
    return support;
  })();
  log.debug("Leaving probeAesSupport(). Probing.");
  return aesSupportProbe;
}

// "" when usable here, otherwise why not.
function algUnsupportedReason(alg, support) {
  var kwBytes = ECDH_KW_BYTES[alg];
  if (!kwBytes) return "";
  if (support && support['AES-KW'] && support['AES-KW'][kwBytes * 8] === false) {
    return "this browser's Web Crypto does not implement AES-" + (kwBytes * 8) + " key wrapping";
  }
  return "";
}

function encUnsupportedReason(enc, support) {
  var keyBytes = ENC_KEY_BYTES[enc];
  if (!keyBytes) return "unknown content encryption algorithm";
  if (support && support['AES-GCM'] && support['AES-GCM'][keyBytes * 8] === false) {
    return "this browser's Web Crypto does not implement AES-" + (keyBytes * 8) + "-GCM";
  }
  return "";
}

// ---------------------------------------------------------------------------
// Key input
// ---------------------------------------------------------------------------
function isCryptoKey(key) {
  return !!key && typeof key === "object" && typeof key.algorithm === "object" && "type" in key;
}

function asJwk(key) {
  if (!key) return null;
  if (typeof key === "object" && !isCryptoKey(key)) return key;
  if (typeof key === "string" && key.trim().charAt(0) === "{") {
    try {
      return JSON.parse(key);
    } catch (e) {
      // Not JSON after all: treat it as PEM and let the import say so.
      log.debug("asJwk(): the text starts with { but is not JSON: " + e.message);
      return null;
    }
  }
  return null;
}

// alg/use/key_ops/ext are metadata about a key, not part of it, and Web Crypto
// rejects a JWK whose key_ops disagree with the usages asked for.
function stripJwkForImport(jwk) {
  var out = {};
  Object.keys(jwk).forEach(function (k) {
    if (['alg', 'use', 'key_ops', 'ext', 'kid', 'x5c', 'x5t', 'x5t#S256', 'x5u'].indexOf(k) === -1) {
      out[k] = jwk[k];
    }
  });
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
    return crypto.subtle.importKey('jwk', stripJwkForImport(jwk), params, false, usages);
  }
  log.debug("Leaving importKey(). Importing PEM as " + format + ".");
  return crypto.subtle.importKey(format, pemToDer(String(key)), params, false, usages);
}

// The curve a key names, so ECDH import parameters can be built for it. A JWK
// says so directly; a PEM does not, so P-256 is assumed — which is what this
// project's issuers and wallets use, and what encryption chooses anyway.
function curveOf(key, fallback) {
  var jwk = asJwk(key);
  if (jwk && jwk.crv) return jwk.crv;
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
  // One SHA-256 round covers up to 32 bytes, enough for A128/A192/A256GCM and
  // for every AES-KW size.
  var input = concatBytes(uint32be(1), new Uint8Array(z), otherInfo);
  var hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  log.debug("Leaving concatKdf().");
  return hash.slice(0, keyBytes);
}

// ---------------------------------------------------------------------------
// Content encryption key: produced for encryption, recovered for decryption.
//
// `protectedHeader` is written into for the ECDH-ES variants, which have to
// publish the ephemeral public key they agreed with (epk).
// ---------------------------------------------------------------------------
async function deriveCek(alg, enc, protectedHeader, recipientPublicKey) {
  log.debug("Entering deriveCek(). alg=" + alg + ", enc=" + enc);
  var keyBytes = ENC_KEY_BYTES[enc];
  if (!keyBytes) throw new Error('unsupported content encryption: ' + enc);

  if (isEcdh(alg)) {
    var curve = curveOf(recipientPublicKey, ECDH_CURVE);
    var recipientPub = await importKey(recipientPublicKey, 'spki',
      { name: 'ECDH', namedCurve: curve }, []);
    var ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve },
      true, ['deriveBits']);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPub },
      ephemeral.privateKey, CURVE_BITS[curve] || ECDH_CURVE_BITS);
    var epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
    protectedHeader.epk = { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y };

    if (alg === 'ECDH-ES') {
      // Direct: the agreed key IS the CEK and encrypted_key is empty. The Concat
      // KDF AlgorithmID is the content-encryption "enc" value.
      var cekBytes = await concatKdf(z, keyBytes, enc);
      var cek = await crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['encrypt']);
      log.debug("Leaving deriveCek(). ECDH-ES direct.");
      return { cek: cek, encryptedKey: '' };
    }
    // ECDH-ES+A*KW: derive a key-wrapping key (AlgorithmID is the full "alg",
    // keydatalen is the AES-KW size), then wrap a fresh random CEK with it.
    var kekBytes = await concatKdf(z, ECDH_KW_BYTES[alg], alg);
    var kek = await crypto.subtle.importKey('raw', kekBytes, { name: 'AES-KW' }, false, ['wrapKey']);
    var cekKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: keyBytes * 8 },
      true, ['encrypt']);
    var wrapped = await crypto.subtle.wrapKey('raw', cekKey, kek, 'AES-KW');
    log.debug("Leaving deriveCek(). " + alg + ".");
    return { cek: cekKey, encryptedKey: bytesToB64u(wrapped) };
  }

  if (!isRsa(alg)) throw new Error('unsupported key management algorithm: ' + alg);
  // RSA-OAEP / RSA-OAEP-256: a random CEK wrapped with the recipient's key.
  var randomCek = new Uint8Array(keyBytes);
  crypto.getRandomValues(randomCek);
  var rsaPub = await importKey(recipientPublicKey, 'spki',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['encrypt']);
  var wrappedCek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPub, randomCek);
  var imported = await crypto.subtle.importKey('raw', randomCek, { name: 'AES-GCM' }, false, ['encrypt']);
  log.debug("Leaving deriveCek(). " + alg + ".");
  return { cek: imported, encryptedKey: bytesToB64u(wrappedCek) };
}

async function unwrapCek(alg, enc, protectedHeader, encryptedKey, recipientPrivateKey) {
  log.debug("Entering unwrapCek(). alg=" + alg + ", enc=" + enc);
  var keyBytes = ENC_KEY_BYTES[enc];
  if (!keyBytes) throw new Error('unsupported content encryption: ' + enc);

  if (isEcdh(alg)) {
    if (!protectedHeader.epk) throw new Error('an ECDH-ES JWE must carry an "epk" header.');
    var curve = protectedHeader.epk.crv || ECDH_CURVE;
    var recipientPriv = await importKey(recipientPrivateKey, 'pkcs8',
      { name: 'ECDH', namedCurve: curve }, ['deriveBits']);
    var epk = await crypto.subtle.importKey('jwk', protectedHeader.epk,
      { name: 'ECDH', namedCurve: curve }, false, []);
    var z = await crypto.subtle.deriveBits({ name: 'ECDH', public: epk }, recipientPriv,
      CURVE_BITS[curve] || ECDH_CURVE_BITS);
    if (alg === 'ECDH-ES') {
      var cekBytes = await concatKdf(z, keyBytes, enc);
      log.debug("Leaving unwrapCek(). ECDH-ES direct.");
      return crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    }
    var kekBytes = await concatKdf(z, ECDH_KW_BYTES[alg], alg);
    var kek = await crypto.subtle.importKey('raw', kekBytes, { name: 'AES-KW' }, false, ['unwrapKey']);
    log.debug("Leaving unwrapCek(). " + alg + ".");
    return crypto.subtle.unwrapKey('raw', b64uToBytes(encryptedKey), kek, 'AES-KW',
      { name: 'AES-GCM' }, false, ['decrypt']);
  }

  if (!isRsa(alg)) throw new Error('unsupported key management algorithm: ' + alg);
  var rsaPriv = await importKey(recipientPrivateKey, 'pkcs8',
    { name: 'RSA-OAEP', hash: JWE_RSA_HASH[alg] }, ['decrypt']);
  var cek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPriv, b64uToBytes(encryptedKey));
  log.debug("Leaving unwrapCek(). " + alg + ".");
  return crypto.subtle.importKey('raw', new Uint8Array(cek), { name: 'AES-GCM' }, false, ['decrypt']);
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
  log.debug("Entering encryptCompact(). alg=" + options.alg + ", enc=" + options.enc);
  var alg = options.alg;
  var enc = options.enc;
  if (!ENC_KEY_BYTES[enc]) throw new Error('unsupported content encryption: ' + enc);

  var protectedHeader = {};
  Object.keys(options.header || {}).forEach(function (k) {
    protectedHeader[k] = options.header[k];
  });
  protectedHeader.alg = alg;
  protectedHeader.enc = enc;

  var derived = await deriveCek(alg, enc, protectedHeader, options.key);
  var protectedB64 = strToB64u(JSON.stringify(protectedHeader));
  // RFC 7516: the AAD is ASCII(BASE64URL(protected header)).
  var aad = new TextEncoder().encode(protectedB64);

  var iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  var plaintextBytes = typeof options.plaintext === "string"
    ? new TextEncoder().encode(options.plaintext)
    : options.plaintext;
  var full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 },
    derived.cek, plaintextBytes));

  // Web Crypto appends the 16-byte authentication tag; JWE keeps the ciphertext
  // and the tag in separate segments.
  var ciphertext = full.slice(0, full.length - 16);
  var tag = full.slice(full.length - 16);

  var compact = [protectedB64, derived.encryptedKey, bytesToB64u(iv),
                 bytesToB64u(ciphertext), bytesToB64u(tag)].join('.');
  log.debug("Leaving encryptCompact(). " + compact.length + " characters.");
  return { jwe: compact, header: protectedHeader };
}

// The protected header of a compact JWE, without decrypting anything — enough to
// decide whether this recipient can open it, and to find the kid it names.
function parseCompact(jwe) {
  log.debug("Entering parseCompact().");
  var parts = String(jwe).trim().split('.');
  if (parts.length !== 5) {
    log.debug("Leaving parseCompact(). " + parts.length + " parts, not five.");
    throw new Error('not a JWE in compact serialization: expected five segments, got ' + parts.length + '.');
  }
  var header;
  try {
    header = JSON.parse(b64uToStr(parts[0]));
  } catch (e) {
    log.debug("Leaving parseCompact(). The header is not readable JSON.");
    throw new Error('the JWE protected header is not readable JSON: ' + e.message);
  }
  log.debug("Leaving parseCompact(). alg=" + header.alg + ", enc=" + header.enc);
  return { header: header, parts: parts };
}

// { jwe, key } -> { plaintext, header }. The algorithms come from the JWE's own
// protected header, which is authenticated as the AAD: an attacker cannot change
// them without the tag failing.
async function decryptCompact(options) {
  log.debug("Entering decryptCompact().");
  var parsed = parseCompact(options.jwe);
  var header = parsed.header;
  var parts = parsed.parts;
  if (!ENC_KEY_BYTES[header.enc]) throw new Error('unsupported content encryption: ' + header.enc);

  var cek = await unwrapCek(header.alg, header.enc, header, parts[1], options.key);
  var plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: b64uToBytes(parts[2]),
    additionalData: new TextEncoder().encode(parts[0]),
    tagLength: 128
  }, cek, concatBytes(b64uToBytes(parts[3]), b64uToBytes(parts[4])));

  log.debug("Leaving decryptCompact().");
  return { plaintext: new TextDecoder().decode(plaintext), header: header };
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
  // and the whole thing
  encryptCompact: encryptCompact,
  parseCompact: parseCompact,
  decryptCompact: decryptCompact
};
