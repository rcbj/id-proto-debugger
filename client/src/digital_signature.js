// File: digital_signature.js
// Author: Robert C. Broeckelmann Jr.
// Notes:
//
// Standalone Digital Signature tool. Asymmetric panes:
//   #1 SLH-DSA (FIPS 205, post-quantum)      — @noble/post-quantum
//   #2 RSA (PKCS#1 v1.5 / PSS) + any hash     — node-forge (keygen) +
//   pure-JS padding
//   #3 ECC (ECDSA over P-256/P-384/P-521/secp256k1, EdDSA) + any hash —
//   @noble/curves
//   #4 ML-DSA (FIPS 204, post-quantum)        — @noble/post-quantum
//   #5 BBS over BLS12-381, both ciphersuites  — ./bbs, shared with bbs-2023
// followed by the symmetric MAC panes, which are labelled separately because a
// MAC is not a digital signature.
//
// The RSA and ECC panes deliberately DO NOT use the Web Crypto API:
// crypto.subtle only supports the SHA family, whereas these panes support a
// wide range of hash algorithms (SHA-2, SHA-3, RIPEMD-160, BLAKE2b, and the
// legacy/broken SHA-1 and MD5). Everything runs in the browser; no key material
// is ever persisted.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var slh = require("@noble/post-quantum/slh-dsa.js");
var mldsa = require("@noble/post-quantum/ml-dsa.js");
var forge = require("node-forge");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;
var schnorr = require("@noble/curves/secp256k1").schnorr;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var ed448 = require("@noble/curves/ed448").ed448;
var bls12_381 = require("@noble/curves/bls12-381").bls12_381;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");
var nobleSha1 = require("@noble/hashes/sha1").sha1;
var nobleSha3 = require("@noble/hashes/sha3");
var nobleRipemd160 = require("@noble/hashes/ripemd160").ripemd160;
var nobleBlake2b = require("@noble/hashes/blake2b").blake2b;
var nobleBlake2s = require("@noble/hashes/blake2s").blake2s;
var nobleBlake3 = require("@noble/hashes/blake3").blake3;
var nobleHmac = require("@noble/hashes/hmac").hmac;
var nobleKmac128 = require("@noble/hashes/sha3-addons").kmac128;
var nobleKmac256 = require("@noble/hashes/sha3-addons").kmac256;
// Pane #5's BBS is NOT a fifth implementation: it is the module the SD-JWT VC
// workflow already signs bbs-2023 credentials with. Anything this pane needs
// that it did not have — the second ciphersuite, KeyGen — belongs there rather
// than here, so both callers get it and tests/bbs_crypto.js checks it.
var bbs = require("./bbs");
// Panes #6 and #7. Both are engines with NO DOM, for the reason the header of
// each one gives: a JWS and an XML Signature are wire formats somebody else's
// library has to read, so the bytes are asserted in node against OpenSSL and
// against xml-crypto rather than against a round trip through this page, which
// would agree with itself whatever the implementation did.
var jws = require("./jws");
var xmldsig = require("./xmldsig");
var log = bunyan.createLogger({ name: 'digital_signature',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// SLH-DSA parameter sets (FIPS 205). Keyed by the label shown in the dropdown.
// ---------------------------------------------------------------------------
var PARAM_SETS = {
  'SLH-DSA-SHA2-128s': slh.slh_dsa_sha2_128s,
  'SLH-DSA-SHA2-128f': slh.slh_dsa_sha2_128f,
  'SLH-DSA-SHA2-192s': slh.slh_dsa_sha2_192s,
  'SLH-DSA-SHA2-192f': slh.slh_dsa_sha2_192f,
  'SLH-DSA-SHA2-256s': slh.slh_dsa_sha2_256s,
  'SLH-DSA-SHA2-256f': slh.slh_dsa_sha2_256f,
  'SLH-DSA-SHAKE-128s': slh.slh_dsa_shake_128s,
  'SLH-DSA-SHAKE-128f': slh.slh_dsa_shake_128f,
  'SLH-DSA-SHAKE-192s': slh.slh_dsa_shake_192s,
  'SLH-DSA-SHAKE-192f': slh.slh_dsa_shake_192f,
  'SLH-DSA-SHAKE-256s': slh.slh_dsa_shake_256s,
  'SLH-DSA-SHAKE-256f': slh.slh_dsa_shake_256f
};

// ---------------------------------------------------------------------------
// ML-DSA parameter sets (FIPS 204, formerly CRYSTALS-Dilithium).
// ---------------------------------------------------------------------------
var ML_PARAM_SETS = {
  'ML-DSA-44': mldsa.ml_dsa44,
  'ML-DSA-65': mldsa.ml_dsa65,
  'ML-DSA-87': mldsa.ml_dsa87
};

// ---------------------------------------------------------------------------
// THE HELPERS THIS PAGE USED TO OWN NOW LIVE IN THREE SHARED MODULES.
//
// The byte, base64, hex and PEM-framing conversions are crypto_bytes.js; the
// DOM accessors, the clipboard, the collapse/expand behaviour and the download
// are tool_panes.js; the AES/Poly1305/SipHash MAC primitives are
// symmetric_crypto.js. Each of them was written here first and then wanted by
// the Encryption / Decryption page, which is the same page with different
// cryptography in it — see the header of each module for what a second copy
// would have cost.
//
// They are aliased to their old local names rather than rewritten at every
// call site: this file has about two hundred of them, and a rename touching
// all two hundred is a diff nobody can review against a 967-line Selenium test
// that already passes.
//
// ONE BEHAVIOURAL CHANGE, and it is an improvement the MAC panes already cope
// with: crypto_bytes' hexToBytes() REFUSES a non-hex character or an odd digit
// count instead of reading it as zero. macCompute() and macVerify() wrap their
// work in a try/catch and report the message, so a mistyped key field now says
// "Value is not hexadecimal" where it used to compute a tag under a key that
// was not the one on the screen.
// ---------------------------------------------------------------------------
var bytesLib = require("./crypto_bytes");
var symmetric = require("./symmetric_crypto");
var panes = require("./tool_panes");
var jose = require("./jose_jwe");
var keyMaterial = require("./key_material");
var pkEncryption = require("./pk_encryption");
var x509 = require("./x509");

var val = panes.val;
var setVal = panes.setVal;
var triggerDownload = panes.triggerDownload;
var defer = panes.defer;

var strBytes = bytesLib.strBytes;
var bytesToB64 = bytesLib.bytesToB64;
var b64ToBytes = bytesLib.b64ToBytes;
var bytesToHex = bytesLib.bytesToHex;
var hexToBytes = bytesLib.hexToBytes;
var concatBytes = bytesLib.concatBytes;
var bytesEqual = bytesLib.bytesEqual;
var randomBytes = bytesLib.randomBytes;
var rawToPem = bytesLib.rawToPem;
var pemToRaw = bytesLib.pemToRaw;
var b64u = bytesLib.bytesToB64u;
var bigToBytes = bytesLib.bigToBytes;

// ---------------------------------------------------------------------------
// Hash registry (shared by the RSA and ECC panes). `oid` is the DER-encoded
// DigestInfo prefix required by RSA PKCS#1 v1.5 (null => v1.5 not available for
// that hash — use PSS). `security` flags legacy/broken hashes for the UI.
// ---------------------------------------------------------------------------
function md5Digest(bytes) {
  log.debug("Entering md5Digest().");
  var md = forge.md.md5.create();
  md.update(forge.util.binary.raw.encode(bytes));
  log.debug("Leaving md5Digest().");
  return forge.util.binary.raw.decode(md.digest().getBytes());
}
var HASHES = {
  'SHA-256':     { fn: nobleSha256,
                  oid: '3031300d060960864801650304020105000420' },
  'SHA-384':     { fn: nobleSha512.sha384,
                  oid: '3041300d060960864801650304020205000430' },
  'SHA-512':     { fn: nobleSha512.sha512,
                  oid: '3051300d060960864801650304020305000440' },
  'SHA3-256':    { fn: nobleSha3.sha3_256,
                  oid: '3031300d060960864801650304020805000420' },
  'SHA3-384':    { fn: nobleSha3.sha3_384,
                  oid: '3041300d060960864801650304020905000430' },
  'SHA3-512':    { fn: nobleSha3.sha3_512,
                  oid: '3051300d060960864801650304020a05000440' },
  'BLAKE2b-512': { fn: nobleBlake2b,         oid: null },
  'BLAKE3-256':  { fn: nobleBlake3,          oid: null },
  'RIPEMD-160':  { fn: nobleRipemd160,
                  oid: '3021300906052b2403020105000414' },
  'SHA-1':       { fn: nobleSha1,
                  oid: '3021300906052b0e03021a05000414' },
  'MD5':         { fn: md5Digest,
                  oid: '3020300c06082a864886f70d020505000410' }
};
function digestOf(hashName, bytes) {
  log.debug("Entering digestOf().");
  var h = HASHES[hashName];
  if (!h) throw new Error('Unknown hash: ' + hashName);
  log.debug("Leaving digestOf().");
  return h.fn(bytes);
}

// ---------------------------------------------------------------------------
// ECC curves (pane #3). ECDSA curves take a selectable hash; EdDSA curves have
// their hash fixed by the scheme (Ed25519 -> SHA-512, Ed448 -> SHAKE256).
// ---------------------------------------------------------------------------
var CURVES = {
  'P-256':     { kind: 'ecdsa', curve: p256,      jwkCrv: 'P-256',
                fieldBytes: 32 },
  'P-384':     { kind: 'ecdsa', curve: p384,      jwkCrv: 'P-384',
                fieldBytes: 48 },
  'P-521':     { kind: 'ecdsa', curve: p521,      jwkCrv: 'P-521',
                fieldBytes: 66 },
  'secp256k1': { kind: 'ecdsa', curve: secp256k1, jwkCrv: 'secp256k1',
                fieldBytes: 32 },
  'Ed25519':   { kind: 'eddsa', curve: ed25519,   jwkCrv: 'Ed25519' },
  'Ed448':     { kind: 'eddsa', curve: ed448,     jwkCrv: 'Ed448' },
  // Schnorr (BIP-340 over secp256k1) and BLS (BLS12-381) hash the message
  // themselves, so the Hash selection does not apply to them.
  'secp256k1-schnorr': { kind: 'schnorr', curve: schnorr },
  'bls12-381':         { kind: 'bls',     curve: bls12_381 }
};

// ===========================================================================
// Pane #1 — SLH-DSA (post-quantum)
// ===========================================================================
function currentAlg() {
  log.debug("Entering currentAlg().");
  var name = val('ds_param');
  var alg = PARAM_SETS[name];
  if (!alg) throw new Error('Unknown parameter set: ' + name);
  log.debug("Leaving currentAlg().");
  return alg;
}

function generateKeys() {
  log.debug("Entering generateKeys().");
  var name = val('ds_param');
  setVal('ds_status', 'Generating ' + name + ' key pair…');
  defer(function () {
    try {
      var alg = currentAlg();
      var kp = alg.keygen();
      setVal('ds_private_key', rawToPem(kp.secretKey, 'SLH-DSA PRIVATE KEY'));
      setVal('ds_public_key', rawToPem(kp.publicKey, 'SLH-DSA PUBLIC KEY'));
      setVal('ds_status', 'Generated ' + name + ' key pair (public ' +
        kp.publicKey.length + ' B, secret ' + kp.secretKey.length + ' B).');
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setVal('ds_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving generateKeys().");
  return false;
}

// ---------------------------------------------------------------------------
// Keystore download helpers (shared by all three panes).
//
// Formats: PEM, DER, JWK, PKCS#12. An optional password encrypts the private
// material (encrypted PKCS#8 for PEM/DER, a PBES2 JWE for JWK, native for
// PKCS#12). Not every key type supports every format — unsupported combinations
// report a clear status message rather than emit a broken file.
//
// PBES2 (JWK password protection) uses the Web Crypto API. That is unrelated to
// the panes' deliberate avoidance of crypto.subtle for *signing* (which exists
// only to allow non-SHA hashes); PBES2 here is standard and hash-agnostic.
// ---------------------------------------------------------------------------
// Password-protecting a JWK set is jose_jwe.js's PBES2 and tool_panes.js's
// download — the same two functions the Encryption / Decryption page's key
// panes call, so a .jwe written by either page is the same artifact.
var downloadJwkSet = panes.downloadJwkSet;

// ---------------------------------------------------------------------------
// Pane #1 SLH-DSA download: PEM (raw, unencrypted) and JWK (+password) are
// supported; DER and PKCS#12 have no standard SLH-DSA representation.
// ---------------------------------------------------------------------------
async function downloadKeys() {
  log.debug("Entering downloadKeys().");
  var fmt = val('ds_slh_ks_format') || 'pem', pw = val('ds_slh_ks_password');
  var priv = val('ds_private_key'), pub = val('ds_public_key');
  if (!priv && !pub) {
    setVal('ds_status', 'Nothing to download — generate a key pair first.');
    log.debug("Leaving downloadKeys().");
    return false;
  }
  try {
    if (fmt === 'pem') {
      if (pw) {
        setVal('ds_status', 'Password protection for SLH-DSA is only ' +
               'available in JWK format. Choose JWK.');
        log.debug("Leaving downloadKeys().");
        return false;
      }
      triggerDownload('slh-dsa-keys.pem', pub + '\n' + priv,
                      'application/x-pem-file');
      setVal('ds_status', 'Downloaded key pair (slh-dsa-keys.pem).');
    } else if (fmt === 'jwk') {
      var alg = val('ds_param');
      var pubJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), use: 'sig' };
      var privJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)),
          d: b64u(pemToRaw(priv)), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'slh-dsa-keys', 'ds_status');
    } else {
      setVal('ds_status', fmt.toUpperCase() +
             ' export is not supported for SLH-DSA keys. Use PEM or JWK.');
    }
  } catch (e) {
    log.error('downloadKeys: ' + e.message);
    setVal('ds_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving downloadKeys().");
  return false;
}

function sign() {
  log.debug("Entering sign().");
  var name = val('ds_param');
  setVal('ds_status', 'Signing with ' + name + '…');
  defer(function () {
    try {
      var alg = currentAlg();
      var sk = pemToRaw(val('ds_private_key'));
      var sig = alg.sign(sk, strBytes(val('ds_value')));
      setVal('ds_signature', bytesToB64(sig));
      setVal('ds_status', 'Signed (' + name + ') — signature is ' + sig.length +
             ' bytes.');
    } catch (e) {
      log.error('sign: ' + e.message);
      setVal('ds_status', 'Sign error: ' + e.message +
             ' (does the parameter set match the key pair?)');
    }
  });
  log.debug("Leaving sign().");
  return false;
}

function validate() {
  log.debug("Entering validate().");
  var name = val('ds_param');
  setVal('ds_status', 'Validating signature with ' + name + '…');
  defer(function () {
    try {
      var alg = currentAlg();
      var ok = alg.verify(pemToRaw(val('ds_public_key')),
          strBytes(val('ds_value')), b64ToBytes(val('ds_signature')));
      setVal('ds_status', ok
        ? 'Signature VALID ✓ — the signature matches the value and public key.'
        : 'Signature INVALID ✗ — the signature does not verify.');
    } catch (e) {
      log.error('validate: ' + e.message);
      setVal('ds_status', 'Validation error: ' + e.message +
             ' (does the parameter set match the key pair?)');
    }
  });
  log.debug("Leaving validate().");
  return false;
}

// ===========================================================================
// Pane #4 — ML-DSA (FIPS 204, post-quantum)
// ===========================================================================
function currentMldsaAlg() {
  log.debug("Entering currentMldsaAlg().");
  var name = val('ds_ml_param');
  var alg = ML_PARAM_SETS[name];
  if (!alg) throw new Error('Unknown ML-DSA parameter set: ' + name);
  log.debug("Leaving currentMldsaAlg().");
  return alg;
}

function mldsaGenerateKeys() {
  log.debug("Entering mldsaGenerateKeys().");
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Generating ' + name + ' key pair…');
  defer(function () {
    try {
      var kp = currentMldsaAlg().keygen();
      setVal('ds_ml_private_key', rawToPem(kp.secretKey, 'ML-DSA PRIVATE KEY'));
      setVal('ds_ml_public_key', rawToPem(kp.publicKey, 'ML-DSA PUBLIC KEY'));
      setVal('ds_ml_status', 'Generated ' + name + ' key pair (public ' +
        kp.publicKey.length + ' B, secret ' + kp.secretKey.length + ' B).');
    } catch (e) {
      log.error('mldsaGenerateKeys: ' + e.message);
      setVal('ds_ml_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving mldsaGenerateKeys().");
  return false;
}

function mldsaSign() {
  log.debug("Entering mldsaSign().");
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Signing with ' + name + '…');
  defer(function () {
    try {
      var sig = currentMldsaAlg().sign(pemToRaw(val('ds_ml_private_key')),
          strBytes(val('ds_ml_value')));
      setVal('ds_ml_signature', bytesToB64(sig));
      setVal('ds_ml_status', 'Signed (' + name + ') — signature is ' +
             sig.length + ' bytes.');
    } catch (e) {
      log.error('mldsaSign: ' + e.message);
      setVal('ds_ml_status', 'Sign error: ' + e.message +
             ' (does the parameter set match the key pair?)');
    }
  });
  log.debug("Leaving mldsaSign().");
  return false;
}

function mldsaValidate() {
  log.debug("Entering mldsaValidate().");
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Validating signature with ' + name + '…');
  defer(function () {
    try {
      var ok = currentMldsaAlg().verify(pemToRaw(val('ds_ml_public_key')),
          strBytes(val('ds_ml_value')), b64ToBytes(val('ds_ml_signature')));
      setVal('ds_ml_status', ok
        ? 'Signature VALID ✓ — the signature matches the value and public key.'
        : 'Signature INVALID ✗ — the signature does not verify.');
    } catch (e) {
      log.error('mldsaValidate: ' + e.message);
      setVal('ds_ml_status', 'Validation error: ' + e.message +
             ' (does the parameter set match the key pair?)');
    }
  });
  log.debug("Leaving mldsaValidate().");
  return false;
}

// PEM (raw, unencrypted) and JWK (+password) supported; DER/PKCS#12 have no
// standard ML-DSA representation.
async function mldsaDownloadKeys() {
  log.debug("Entering mldsaDownloadKeys().");
  var fmt = val('ds_ml_ks_format') || 'pem', pw = val('ds_ml_ks_password');
  var priv = val('ds_ml_private_key'), pub = val('ds_ml_public_key');
  if (!priv && !pub) {
    setVal('ds_ml_status', 'Nothing to download — generate a key pair first.');
    log.debug("Leaving mldsaDownloadKeys().");
    return false;
  }
  try {
    if (fmt === 'pem') {
      if (pw) {
        setVal('ds_ml_status', 'Password protection for ML-DSA is only ' +
               'available in JWK format. Choose JWK.');
        log.debug("Leaving mldsaDownloadKeys().");
        return false;
      }
      triggerDownload('ml-dsa-keys.pem', pub + '\n' + priv,
                      'application/x-pem-file');
      setVal('ds_ml_status', 'Downloaded key pair (ml-dsa-keys.pem).');
    } else if (fmt === 'jwk') {
      var alg = val('ds_ml_param');
      var pubJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), use: 'sig' };
      var privJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)),
          d: b64u(pemToRaw(priv)), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'ml-dsa-keys',
                           'ds_ml_status');
    } else {
      setVal('ds_ml_status', fmt.toUpperCase() +
             ' export is not supported for ML-DSA keys. Use PEM or JWK.');
    }
  } catch (e) {
    log.error('mldsaDownloadKeys: ' + e.message);
    setVal('ds_ml_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving mldsaDownloadKeys().");
  return false;
}

// ===========================================================================
// Pane #2 — RSA (PKCS#1 v1.5 / PSS) with a selectable hash (pure JS)
// ===========================================================================
// RSA primitives on native BigInt (this is a debugging tool, not a hardened
// constant-time implementation). BigInt constants written as BigInt(...) rather
// than 0n/1n literals: browserify's insert-module-globals lexes this file (it
// references `process`) with an esprima build that predates BigInt literals.
var _B0 = BigInt(0), _B1 = BigInt(1), _B8 = BigInt(8), _B255 = BigInt(255);
function forgeToBig(fbn) {
  log.debug("Entering forgeToBig().");
  log.debug("Leaving forgeToBig().");
  return BigInt('0x' + fbn.toString(16));
}
function os2ip(bytes) {
  log.debug("Entering os2ip().");
  var x = _B0;
  for (var i = 0; i < bytes.length; i++) x = (x << _B8) | BigInt(bytes[i]);
  log.debug("Leaving os2ip().");
  return x;
}
function i2osp(x, len) {
  log.debug("Entering i2osp().");
  var o = new Uint8Array(len);
  for (var i = len - 1; i >= 0; i--) { o[i] = Number(x & _B255); x >>= _B8; }
  log.debug("Leaving i2osp().");
  return o;
}
function modpow(b, e, m) {
  log.debug("Entering modpow().");
  var r = _B1;
  b %= m;
  while (e > _B0) { if (e & _B1) r = r * b % m; e >>= _B1; b = b * b % m; }
  log.debug("Leaving modpow().");
  return r;
}

// EMSA-PKCS1-v1_5 (RFC 8017 §9.2): 0x00 01 FF..FF 00 || DigestInfo(hash) || H
function emsaPkcs1v15(msg, hashName, emLen) {
  log.debug("Entering emsaPkcs1v15().");
  var h = HASHES[hashName];
  if (!h.oid) throw new Error('PKCS#1 v1.5 has no DigestInfo OID for ' +
      hashName + '. Choose PSS padding instead.');
  var T = concatBytes(hexToBytes(h.oid), digestOf(hashName, msg));
  if (emLen < T.length + 11) throw new Error('Modulus too short for ' +
      hashName + '.');
  var psLen = emLen - T.length - 3;
  var em = new Uint8Array(emLen);
  em[0] = 0x00; em[1] = 0x01;
  for (var i = 0; i < psLen; i++) em[2 + i] = 0xff;
  em[2 + psLen] = 0x00;
  em.set(T, 3 + psLen);
  log.debug("Leaving emsaPkcs1v15().");
  return em;
}

// MGF1 (RFC 8017 §B.2.1) using the same hash as the signature.
function mgf1(seed, len, hashName) {
  log.debug("Entering mgf1().");
  var t = new Uint8Array(0), counter = 0;
  while (t.length < len) {
    t = concatBytes(t, digestOf(hashName, concatBytes(seed,
        i2osp(BigInt(counter), 4))));
    counter++;
  }
  log.debug("Leaving mgf1().");
  return t.slice(0, len);
}

// EMSA-PSS-ENCODE (RFC 8017 §9.1.1); salt length = digest length.
function emsaPssEncode(msg, hashName, emBits) {
  log.debug("Entering emsaPssEncode().");
  var mHash = digestOf(hashName, msg), hLen = mHash.length, sLen = hLen;
  var emLen = Math.ceil(emBits / 8);
  if (emLen < hLen + sLen +
      2) throw new Error('Modulus too short for PSS with ' + hashName + '.');
  var salt = randomBytes(sLen);
  var H = digestOf(hashName, concatBytes(new Uint8Array(8), mHash, salt));
  var DB = concatBytes(new Uint8Array(emLen - sLen - hLen - 2),
      new Uint8Array([0x01]), salt);
  var dbMask = mgf1(H, emLen - hLen - 1, hashName);
  var maskedDB = DB.map(function (b, i) { return b ^ dbMask[i]; });
  maskedDB[0] &= (0xff >> (8 * emLen - emBits));
  log.debug("Leaving emsaPssEncode().");
  return concatBytes(maskedDB, H, new Uint8Array([0xbc]));
}
function emsaPssVerify(msg, em, hashName, emBits) {
  log.debug("Entering emsaPssVerify().");
  var mHash = digestOf(hashName, msg), hLen = mHash.length, sLen = hLen;
  var emLen = Math.ceil(emBits / 8);
  if (em.length !== emLen || em[em.length - 1] !== 0xbc) {
    log.debug("Leaving emsaPssVerify().");
    return false;
  }
  var maskedDB = em.slice(0, emLen - hLen - 1), H = em.slice(emLen - hLen - 1,
      emLen - 1);
  var DB = maskedDB.map(function (b, i) { return b ^ mgf1(H, emLen - hLen - 1,
      hashName)[i]; });
  DB[0] &= (0xff >> (8 * emLen - emBits));
  for (var i = 0; i < emLen - sLen - hLen - 2; i++) if (DB[i] !== 0) {
    log.debug("Leaving emsaPssVerify().");
    return false;
  }
  if (DB[emLen - sLen - hLen - 2] !== 0x01) {
    log.debug("Leaving emsaPssVerify().");
    return false;
  }
  var salt = DB.slice(DB.length - sLen);
  var H2 = digestOf(hashName, concatBytes(new Uint8Array(8), mHash, salt));
  log.debug("Leaving emsaPssVerify().");
  return bytesEqual(H, H2);
}

function rsaPaddingLabel(p) {
  log.debug("Entering rsaPaddingLabel().");
  log.debug("Leaving rsaPaddingLabel().");
  return p === 'pss' ? 'PSS' : 'PKCS#1 v1.5';
}

// An RSA key pair, through pk_encryption.js — the same function the Encryption
// / Decryption page's RSA pane calls, and the reason it is shared rather than
// repeated is the PRIVATE KEY'S ENCODING. forge's privateKeyToPem() emits
// PKCS#1 (`BEGIN RSA PRIVATE KEY`); key_material.js, jose_jwe.js and Web
// Crypto's importKey('pkcs8', …) all want PKCS#8, so the keystore matrix below
// refuses a PKCS#1 key with a bare `DataError` and no message. That defect was
// found on the other page and fixed in one place.
function rsaGenerateKeys() {
  log.debug("Entering rsaGenerateKeys().");
  var bits = parseInt(val('ds_rsa_bits'), 10) || 2048;
  setVal('ds_rsa_status', 'Generating RSA ' + bits +
         '-bit key pair — pure JS, so larger sizes take longer…');
  defer(function () {
    try {
      var pair = pkEncryption.rsaGenerateKeyPair(bits);
      setVal('ds_rsa_private_key', pair.privatePem);
      setVal('ds_rsa_public_key', pair.publicPem);
      setVal('ds_rsa_status', 'Generated RSA ' + bits + '-bit key pair.');
    } catch (e) {
      log.error('rsaGenerateKeys: ' + e.message);
      setVal('ds_rsa_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving rsaGenerateKeys().");
  return false;
}

// The throwaway certificate a PKCS#12 wraps the key in, and the one View
// certificate shows. x509.js's, shared with jwt_tools and the Encryption /
// Decryption page — a certificate profile written three times is three sets of
// extensions to get wrong, and this tree already records five defects that
// produced certificates which parse, display plausibly and are then refused.
async function rsaSelfSignedCertPem() {
  log.debug("Entering rsaSelfSignedCertPem().");
  var pem = await x509.selfSignedCertPem({
    subject: 'CN=digital-signature-tool',
    privatePem: val('ds_rsa_private_key'),
    publicPem: val('ds_rsa_public_key'),
    desc: { kind: 'rsa', hash: 'SHA-256' }
  });
  log.debug("Leaving rsaSelfSignedCertPem().");
  return pem;
}

// Build a self-signed X.509 cert from the current RSA key pair and open the
// certificate-details page (saml_cert.html) to inspect it. The cert is handed
// over via localStorage ('saml_cert_view') and shown in a new tab.
function viewRsaCert() {
  log.debug("Entering viewRsaCert().");
  var privPem = val('ds_rsa_private_key'), pubPem = val('ds_rsa_public_key');
  if (!privPem.trim() || !pubPem.trim()) {
    setVal('ds_rsa_status', 'Generate an RSA key pair first.');
    log.debug("Leaving viewRsaCert().");
    return false;
  }
  rsaSelfSignedCertPem().then(function (pem) {
    if (window.localStorage) localStorage.setItem('saml_cert_view', pem);
    window.open('/saml_cert.html?from=digital_signature.html', '_blank');
  }).catch(function (e) {
    log.error('viewRsaCert: ' + e.message);
    setVal('ds_rsa_status', 'Certificate error: ' + e.message);
  });
  log.debug("Leaving viewRsaCert().");
  return false;
}

// THE KEYSTORE MATRIX IS key_material.js's, NOT THIS FILE'S.
//
// This pane had its own node-forge implementation of PEM / DER / JWK /
// PKCS#12 — a second reading of four wire formats, which is exactly what
// key_material.js's own header says must not exist twice: these encodings are
// read by OpenSSL, keytool and somebody else's TLS stack, and two
// implementations can agree with each other and both be wrong. It is now the
// one the PKI page, JWT Tools and the Encryption / Decryption page all use,
// and tests/pki_key_formats.js checks all 49 cells of it against OpenSSL in
// node.
//
// The only thing this function still decides is the CERTIFICATE a PKCS#12
// wraps the key in, which key_material deliberately does not mint.
async function rsaDownloadKeys() {
  log.debug("Entering rsaDownloadKeys().");
  var format = val('ds_rsa_ks_format') || 'pem';
  var password = val('ds_rsa_ks_password');
  var privatePem = val('ds_rsa_private_key');
  var publicPem = val('ds_rsa_public_key');
  if (!privatePem.trim() || !publicPem.trim()) {
    setVal('ds_rsa_status',
           'No key pair to export. Generate a key pair first.');
    log.debug("Leaving rsaDownloadKeys(). Nothing to export.");
    return false;
  }
  try {
    var descriptor = { kind: 'rsa', hash: 'SHA-256' };
    var certs = format === 'pkcs12' ? [await rsaSelfSignedCertPem()] : [];
    var result = await keyMaterial.exportKeyPair({
      privatePem: privatePem,
      publicPem: publicPem,
      desc: descriptor,
      format: format,
      password: password,
      friendlyName: 'digital-signature-tool',
      use: 'sig',
      certs: certs,
      baseName: 'rsa-keys'
    });
    keyMaterial.downloadFiles(result.files);
    setVal('ds_rsa_status', result.status);
  } catch (e) {
    log.error('rsaDownloadKeys: ' + e.message);
    setVal('ds_rsa_status', e.message);
  }
  log.debug("Leaving rsaDownloadKeys().");
  return false;
}

function rsaSign() {
  log.debug("Entering rsaSign().");
  var padding = val('ds_rsa_padding'), hashName = val('ds_rsa_hash');
  setVal('ds_rsa_status', 'Signing with RSA ' + rsaPaddingLabel(padding) +
         ' / ' + hashName + '…');
  try {
    var key = forge.pki.privateKeyFromPem(val('ds_rsa_private_key'));
    var n = forgeToBig(key.n), d = forgeToBig(key.d);
    var modBits = n.toString(2).length, k = Math.ceil(modBits / 8);
    var msg = strBytes(val('ds_rsa_value'));
    var em = padding === 'pss' ? emsaPssEncode(msg, hashName, modBits -
        1) : emsaPkcs1v15(msg, hashName, k);
    var sig = i2osp(modpow(os2ip(em), d, n), k);
    setVal('ds_rsa_signature', bytesToB64(sig));
    setVal('ds_rsa_status', 'Signed (RSA ' + rsaPaddingLabel(padding) + ' / ' +
           hashName + ') — ' + sig.length + ' bytes.');
  } catch (e) {
    log.error('rsaSign: ' + e.message);
    setVal('ds_rsa_status', 'Sign error: ' + e.message);
  }
  log.debug("Leaving rsaSign().");
  return false;
}

function rsaValidate() {
  log.debug("Entering rsaValidate().");
  var padding = val('ds_rsa_padding'), hashName = val('ds_rsa_hash');
  setVal('ds_rsa_status', 'Validating RSA ' + rsaPaddingLabel(padding) + ' / ' +
         hashName + '…');
  try {
    var key = forge.pki.publicKeyFromPem(val('ds_rsa_public_key'));
    var n = forgeToBig(key.n), e = forgeToBig(key.e);
    var modBits = n.toString(2).length, k = Math.ceil(modBits / 8);
    var msg = strBytes(val('ds_rsa_value'));
    var m = modpow(os2ip(b64ToBytes(val('ds_rsa_signature'))), e, n);
    var em = i2osp(m, k);
    var ok = padding === 'pss'
      ? emsaPssVerify(msg, em, hashName, modBits - 1)
      : bytesEqual(em, emsaPkcs1v15(msg, hashName, k));
    setVal('ds_rsa_status', ok
      ? 'Signature VALID ✓ — the signature matches the value and public key.'
      : 'Signature INVALID ✗ — the signature does not verify.');
  } catch (e) {
    log.error('rsaValidate: ' + e.message);
    setVal('ds_rsa_status', 'Validation error: ' + e.message);
  }
  log.debug("Leaving rsaValidate().");
  return false;
}

// ===========================================================================
// Pane #3 — ECC (ECDSA / EdDSA) with a selectable hash (@noble/curves)
// ===========================================================================
function eccCurve() {
  log.debug("Entering eccCurve().");
  var name = val('ds_ecc_curve');
  var c = CURVES[name];
  if (!c) throw new Error('Unknown curve: ' + name);
  log.debug("Leaving eccCurve().");
  return c;
}

function eccGenerateKeys() {
  log.debug("Entering eccGenerateKeys().");
  var name = val('ds_ecc_curve');
  setVal('ds_ecc_status', 'Generating ' + name + ' key pair…');
  try {
    var c = eccCurve();
    var priv = c.curve.utils.randomPrivateKey();
    var pub = c.curve.getPublicKey(priv);
    setVal('ds_ecc_private_key', bytesToHex(priv));
    setVal('ds_ecc_public_key', bytesToHex(pub));
    setVal('ds_ecc_status', 'Generated ' + name + ' key pair (private ' +
           priv.length + ' B, public ' + pub.length + ' B).');
  } catch (e) {
    log.error('eccGenerateKeys: ' + e.message);
    setVal('ds_ecc_status', 'Key generation error: ' + e.message);
  }
  log.debug("Leaving eccGenerateKeys().");
  return false;
}

// Build a JWK pair for the current ECC keys (EC for ECDSA curves, OKP for
// EdDSA).
function eccJwkSet() {
  log.debug("Entering eccJwkSet().");
  var c = eccCurve();
  var priv = hexToBytes(val('ds_ecc_private_key')), pubHex =
      val('ds_ecc_public_key');
  if (c.kind === 'eddsa') {
    var pub = hexToBytes(pubHex);
    log.debug("Leaving eccJwkSet().");
    return [
      { kty: 'OKP', crv: c.jwkCrv, x: b64u(pub), use: 'sig' },
      { kty: 'OKP', crv: c.jwkCrv, x: b64u(pub), d: b64u(priv), use: 'sig' }
    ];
  }
  var pt = c.curve.ProjectivePoint.fromHex(pubHex).toAffine();
  var x = b64u(bigToBytes(pt.x, c.fieldBytes)), y = b64u(bigToBytes(pt.y,
      c.fieldBytes));
  log.debug("Leaving eccJwkSet().");
  return [
    { kty: 'EC', crv: c.jwkCrv, x: x, y: y, use: 'sig' },
    { kty: 'EC', crv: c.jwkCrv, x: x, y: y, d: b64u(priv), use: 'sig' }
  ];
}

async function eccDownloadKeys() {
  log.debug("Entering eccDownloadKeys().");
  var fmt = val('ds_ecc_ks_format') || 'jwk', pw = val('ds_ecc_ks_password');
  var priv = val('ds_ecc_private_key'), pub = val('ds_ecc_public_key');
  if (!priv && !pub) {
    setVal('ds_ecc_status', 'Nothing to download — generate a key pair first.');
    log.debug("Leaving eccDownloadKeys().");
    return false;
  }
  try {
    var c = eccCurve();
    if (fmt === 'jwk' && (c.kind === 'schnorr' || c.kind === 'bls')) {
      setVal('ds_ecc_status', 'JWK is not defined for ' + val('ds_ecc_curve') +
             '. Copy the hex from the key fields.');
    } else if (fmt === 'jwk') {
      await downloadJwkSet(eccJwkSet(), pw, 'ecc-keys', 'ds_ecc_status');
    } else {
      setVal('ds_ecc_status', fmt.toUpperCase() + ' export is not supported ' +
             'for these raw ECC keys. Use JWK (or copy the hex from the ' +
             'key fields).');
    }
  } catch (e) {
    log.error('eccDownloadKeys: ' + e.message);
    setVal('ds_ecc_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving eccDownloadKeys().");
  return false;
}

function eccSign() {
  log.debug("Entering eccSign().");
  var name = val('ds_ecc_curve'), hashName = val('ds_ecc_hash');
  setVal('ds_ecc_status', 'Signing with ' + name + '…');
  try {
    var c = eccCurve();
    var priv = hexToBytes(val('ds_ecc_private_key'));
    var msg = strBytes(val('ds_ecc_value'));
    var sig, detail;
    if (c.kind === 'ecdsa') {
      sig = c.curve.sign(digestOf(hashName, msg), priv).toCompactRawBytes();
      detail = name + ' / ' + hashName;
    } else {
      // EdDSA, Schnorr (BIP-340), and BLS all hash the message internally.
      sig = c.curve.sign(msg, priv);
      detail = name;
    }
    setVal('ds_ecc_signature', bytesToB64(sig));
    setVal('ds_ecc_status', 'Signed (' + detail + ') — signature is ' +
           sig.length + ' bytes.');
  } catch (e) {
    log.error('eccSign: ' + e.message);
    setVal('ds_ecc_status', 'Sign error: ' + e.message +
           ' (does the curve match the key pair?)');
  }
  log.debug("Leaving eccSign().");
  return false;
}

function eccValidate() {
  log.debug("Entering eccValidate().");
  var name = val('ds_ecc_curve'), hashName = val('ds_ecc_hash');
  setVal('ds_ecc_status', 'Validating signature with ' + name + '…');
  try {
    var c = eccCurve();
    var pub = hexToBytes(val('ds_ecc_public_key'));
    var sig = b64ToBytes(val('ds_ecc_signature'));
    var msg = strBytes(val('ds_ecc_value'));
    var ok = c.kind === 'ecdsa'
      ? c.curve.verify(sig, digestOf(hashName, msg), pub)
      : c.curve.verify(sig, msg, pub);
    setVal('ds_ecc_status', ok
      ? 'Signature VALID ✓ — the signature matches the value and public key.'
      : 'Signature INVALID ✗ — the signature does not verify.');
  } catch (e) {
    log.error('eccValidate: ' + e.message);
    setVal('ds_ecc_status', 'Validation error: ' + e.message +
           ' (does the curve/hash match the signature?)');
  }
  log.debug("Leaving eccValidate().");
  return false;
}

// ===========================================================================
// Pane #5 — BBS over BLS12-381 (draft-irtf-cfrg-bbs-signatures)
//
// The one pane whose signature is not over a single value: BBS signs an
// ORDERED LIST of messages, and its point is what comes next — the holder
// turns that signature into a derived proof revealing only the messages they
// choose, freshly randomised each time and therefore unlinkable.
//
// The maths is in ./bbs, shared with the SD-JWT VC workflow's bbs-2023
// cryptosuite, so what lives here is only the pane: reading its fields,
// choosing a ciphersuite, and reporting. Every octet-string field is read as
// UTF-8 text or as hex according to one selector, which is what lets a reader
// paste the draft's own test vectors in and get the draft's own bytes out.
// ===========================================================================
function bbsOctetsOf(text) {
  log.debug("Entering bbsOctetsOf().");
  if (val('ds_bbs_encoding') !== 'hex') {
    log.debug("Leaving bbsOctetsOf(). Text.");
    return strBytes(text);
  }
  var h = String(text).replace(/\s+/g, '');
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) {
    throw new Error('"' + text + '" is not hex. Either fix it or set Input ' +
                    'encoding to UTF-8 text.');
  }
  log.debug("Leaving bbsOctetsOf(). Hex.");
  return hexToBytes(h);
}
function bbsOctets(id) {
  log.debug("Entering bbsOctets().");
  log.debug("Leaving bbsOctets().");
  return bbsOctetsOf(val(id));
}

// One message per line, read the way a text file's lines are read: ONE
// trailing newline is the line terminator and not an extra message, and
// everything else is a message — including an empty line.
//
// That distinction is not pedantry. BBS signs zero-length messages happily and
// binds every message to its own generator by index, so an empty message that
// is dropped changes the whole signature; the draft's own multi-message test
// vector ends with exactly that, an empty tenth message. Dropping every
// trailing blank line (the obvious rule) makes that vector unreproducible
// here, and keeping every one of them makes the ordinary textarea's trailing
// newline into a phantom message. So: a user who wants a trailing empty
// message types one more newline than they otherwise would.
function bbsMessages() {
  log.debug("Entering bbsMessages().");
  var text = val('ds_bbs_messages').replace(/\r?\n$/, '');
  if (text === '') {
    log.debug("Leaving bbsMessages(). No messages.");
    return [];
  }
  log.debug("Leaving bbsMessages().");
  return text.split(/\r?\n/).map(function (line) {
    return bbsOctetsOf(line);
  });
}

// Zero-based indexes into the message list. An EMPTY list is legal and means
// "disclose nothing", which is a real BBS proof and not a mistake.
function bbsDisclosedIndexes(count) {
  log.debug("Entering bbsDisclosedIndexes().");
  var raw = val('ds_bbs_disclosed').trim();
  if (!raw) {
    log.debug("Leaving bbsDisclosedIndexes(). None disclosed.");
    return [];
  }
  var out = [];
  raw.split(/[\s,]+/).forEach(function (part) {
    var n = parseInt(part, 10);
    if (isNaN(n) || String(n) !== part || n < 0 || n >= count) {
      throw new Error('Disclosed index "' + part + '" is not a message ' +
                      'index (0…' + (count - 1) + ').');
    }
    if (out.indexOf(n) === -1) out.push(n);
  });
  out.sort(function (a, b) { return a - b; });
  log.debug("Leaving bbsDisclosedIndexes().");
  return out;
}

function bbsSecretKey() {
  log.debug("Entering bbsSecretKey().");
  var h = val('ds_bbs_private_key').replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error('The BBS private key must be a 32-byte scalar in hex ' +
                    '(64 characters). Generate a key pair first.');
  }
  log.debug("Leaving bbsSecretKey().");
  return BigInt('0x' + h);
}
function bbsPublicKey() {
  log.debug("Entering bbsPublicKey().");
  var h = val('ds_bbs_public_key').replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]{192}$/.test(h)) {
    throw new Error('The BBS public key must be a compressed 96-byte G2 ' +
                    'point in hex (192 characters).');
  }
  log.debug("Leaving bbsPublicKey().");
  return hexToBytes(h);
}

// KeyGen (section 3.4.1) rather than a random scalar, so the pair on screen is
// reproducible from the key material beside it. An empty material field means
// "make me 32 random bytes and show them", which keeps that property without
// asking the user to invent an IKM.
function bbsGenerateKeys() {
  log.debug("Entering bbsGenerateKeys().");
  var suite = val('ds_bbs_suite');
  setVal('ds_bbs_status', 'Deriving ' + suite + ' key pair…');
  defer(function () {
    try {
      var hex = val('ds_bbs_key_material').replace(/\s+/g, '');
      if (!hex) {
        hex = bytesToHex(randomBytes(32));
        setVal('ds_bbs_key_material', hex);
      }
      if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
        throw new Error('Key material must be hex.');
      }
      var sk = bbs.keyGen(hexToBytes(hex), bbsOctets('ds_bbs_key_info'),
                          bbsOctets('ds_bbs_key_dst'), suite);
      var pk = bbs.secretKeyToPublicKey(sk);
      setVal('ds_bbs_private_key', bytesToHex(bbs.i2osp(sk,
             bbs.OCTET_SCALAR_LENGTH)));
      setVal('ds_bbs_public_key', bytesToHex(pk));
      setVal('ds_bbs_status', 'Derived ' + suite + ' key pair (secret ' +
        bbs.OCTET_SCALAR_LENGTH + ' B, public ' + pk.length + ' B). KeyGen ' +
        'is deterministic: the same key material and key info always give ' +
        'this key.');
    } catch (e) {
      log.error('bbsGenerateKeys: ' + e.message);
      setVal('ds_bbs_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving bbsGenerateKeys().");
  return false;
}

function bbsSign() {
  log.debug("Entering bbsSign().");
  var suite = val('ds_bbs_suite');
  setVal('ds_bbs_status', 'Signing with BBS ' + suite + '…');
  defer(function () {
    try {
      var messages = bbsMessages();
      if (!messages.length) throw new Error('Enter at least one message.');
      var sig = bbs.sign(bbsSecretKey(), bbsPublicKey(),
          bbsOctets('ds_bbs_header'), messages, suite);
      setVal('ds_bbs_signature', bytesToB64(sig));
      setVal('ds_bbs_status', 'Signed (' + suite + ') over ' +
             messages.length + ' message(s) — signature is ' + sig.length +
             ' bytes.');
    } catch (e) {
      log.error('bbsSign: ' + e.message);
      setVal('ds_bbs_status', 'Sign error: ' + e.message);
    }
  });
  log.debug("Leaving bbsSign().");
  return false;
}

function bbsValidate() {
  log.debug("Entering bbsValidate().");
  var suite = val('ds_bbs_suite');
  setVal('ds_bbs_status', 'Validating BBS signature (' + suite + ')…');
  defer(function () {
    try {
      var ok = bbs.verify(bbsPublicKey(), b64ToBytes(val('ds_bbs_signature')),
          bbsOctets('ds_bbs_header'), bbsMessages(), suite);
      setVal('ds_bbs_status', ok
        ? 'Signature VALID ✓ — the signature matches this message list, ' +
          'header and public key.'
        : 'Signature INVALID ✗ — the signature does not verify. Message ' +
          'order and count are bound in, as is the header.');
    } catch (e) {
      log.error('bbsValidate: ' + e.message);
      setVal('ds_bbs_status', 'Validation error: ' + e.message +
             ' (does the ciphersuite match the key pair?)');
    }
  });
  log.debug("Leaving bbsValidate().");
  return false;
}

function bbsProofGen() {
  log.debug("Entering bbsProofGen().");
  var suite = val('ds_bbs_suite');
  setVal('ds_bbs_status', 'Deriving a BBS proof (' + suite + ')…');
  defer(function () {
    try {
      var messages = bbsMessages();
      if (!messages.length) throw new Error('Enter at least one message.');
      var disclosed = bbsDisclosedIndexes(messages.length);
      var proof = bbs.proofGen(bbsPublicKey(),
          b64ToBytes(val('ds_bbs_signature')), bbsOctets('ds_bbs_header'),
          bbsOctets('ds_bbs_ph'), messages, disclosed, suite);
      setVal('ds_bbs_proof', bytesToB64(proof));
      setVal('ds_bbs_status', 'Derived a proof disclosing ' +
        disclosed.length + ' of ' + messages.length + ' message(s) — ' +
        proof.length + ' bytes. Derive again and the bytes differ: BBS ' +
        'proofs are unlinkable.');
    } catch (e) {
      log.error('bbsProofGen: ' + e.message);
      setVal('ds_bbs_status', 'Proof error: ' + e.message +
             ' (is the signature the one over these messages?)');
    }
  });
  log.debug("Leaving bbsProofGen().");
  return false;
}

function bbsProofVerify() {
  log.debug("Entering bbsProofVerify().");
  var suite = val('ds_bbs_suite');
  setVal('ds_bbs_status', 'Verifying the BBS proof (' + suite + ')…');
  defer(function () {
    try {
      var messages = bbsMessages();
      var disclosed = bbsDisclosedIndexes(messages.length);
      var shown = disclosed.map(function (i) { return messages[i]; });
      var ok = bbs.proofVerify(bbsPublicKey(), b64ToBytes(val('ds_bbs_proof')),
          bbsOctets('ds_bbs_header'), bbsOctets('ds_bbs_ph'), shown,
          disclosed, suite);
      setVal('ds_bbs_status', ok
        ? 'Proof VALID ✓ — a signature exists over all ' + messages.length +
          ' message(s), and these ' + disclosed.length + ' are as claimed. ' +
          'The undisclosed ones stay hidden.'
        : 'Proof INVALID ✗ — the proof does not verify against these ' +
          'disclosed messages, indexes, header and presentation header.');
    } catch (e) {
      log.error('bbsProofVerify: ' + e.message);
      setVal('ds_bbs_status', 'Proof validation error: ' + e.message);
    }
  });
  log.debug("Leaving bbsProofVerify().");
  return false;
}

// BBS keys export as a JWK (OKP / Bls12381G2, per the COSE/JOSE BLS key
// representations draft) with an optional PBES2 password, like the ECC pane.
// PEM, DER and PKCS#12 have no standard BBS representation, so they say so
// rather than emitting something nothing else can read.
async function bbsDownloadKeys() {
  log.debug("Entering bbsDownloadKeys().");
  var fmt = val('ds_bbs_ks_format') || 'jwk', pw = val('ds_bbs_ks_password');
  var priv = val('ds_bbs_private_key').replace(/\s+/g, '');
  var pub = val('ds_bbs_public_key').replace(/\s+/g, '');
  if (!priv && !pub) {
    setVal('ds_bbs_status',
           'Nothing to download — generate a key pair first.');
    log.debug("Leaving bbsDownloadKeys().");
    return false;
  }
  try {
    if (fmt === 'jwk') {
      var pubJwk = { kty: 'OKP', crv: 'Bls12381G2', x: b64u(hexToBytes(pub)),
          use: 'sig' };
      var privJwk = { kty: 'OKP', crv: 'Bls12381G2', x: b64u(hexToBytes(pub)),
          d: b64u(hexToBytes(priv)), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'bbs-keys', 'ds_bbs_status');
    } else {
      setVal('ds_bbs_status', fmt.toUpperCase() + ' export is not supported ' +
             'for BBS keys. Use JWK (or copy the hex from the key fields).');
    }
  } catch (e) {
    log.error('bbsDownloadKeys: ' + e.message);
    setVal('ds_bbs_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving bbsDownloadKeys().");
  return false;
}

// ===========================================================================
// Symmetric MACs (NOT digital signatures — a MAC uses one shared secret, so it
// gives integrity + origin but no non-repudiation / public verifiability).
// Grouped into panes by family: keyed-hash, block-cipher, universal-hash.
// ===========================================================================

// The five primitives these three panes are built on are symmetric_crypto.js's
// now. Poly1305 is the one that forced the move: ChaCha20-Poly1305 on the
// Encryption page needs the same RFC 8439 section 2.5 implementation, and two
// readings of that section can agree with each other and be wrong together.
var aesCmac = symmetric.aesCmac;
var aesCbcMac = symmetric.aesCbcMac;
var aesGmac = symmetric.aesGmac;
var poly1305 = symmetric.poly1305;
var siphash24 = symmetric.siphash24;

// MAC registry. fn(keyBytes, msgBytes) -> tag bytes; keyBytes = length to
// generate with "Generate Key".
var MACS = {
  // Keyed-hash family
  'HMAC-SHA256':  { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha256, k, m);
  },        keyBytes: 32 },
  'HMAC-SHA384':  { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha512.sha384, k, m);
  }, keyBytes: 48 },
  'HMAC-SHA512':  { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha512.sha512, k, m);
  }, keyBytes: 64 },
  'HMAC-SHA3-256':{ fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha3.sha3_256, k, m);
  }, keyBytes: 32 },
  'HMAC-SHA3-512':{ fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha3.sha3_512, k, m);
  }, keyBytes: 64 },
  'HMAC-SHA1':    { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleHmac(nobleSha1, k, m);
  },          keyBytes: 20 }, // insecure
  'KMAC128':      { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleKmac128(k, m, { dkLen: 32 });
  },   keyBytes: 32 },
  'KMAC256':      { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleKmac256(k, m, { dkLen: 64 });
  },   keyBytes: 32 },
  'BLAKE2b':      { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleBlake2b(m, { key: k });
  },         keyBytes: 32 },
  'BLAKE2s':      { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleBlake2s(m, { key: k });
  },         keyBytes: 32 },
  'BLAKE3':       { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return nobleBlake3(m, { key: k });
  },          keyBytes: 32 }, // key must be 32B
  // Block-cipher family (AES)
  'AES-CMAC':     { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return aesCmac(k, m);
  },                       keyBytes: 32 },
  'AES-CBC-MAC':  { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return aesCbcMac(k, m);
  },                     keyBytes: 32 }, // legacy
  'AES-GMAC':     { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return aesGmac(k, m);
  },                       keyBytes: 32 },
  // Universal-hash family
  'Poly1305':     { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return poly1305(k, m);
  },                      keyBytes: 32 }, // one-time key
  'SipHash-2-4':  { fn: function (k, m) {
    log.debug("Entering fn().");
    log.debug("Leaving fn().");
    return siphash24(k, m);
  },                     keyBytes: 16 }
};

// Pane handlers — one set, parameterized by pane prefix (khmac/bcmac/uhmac).
function macGenerateKey(prefix) {
  log.debug("Entering macGenerateKey().");
  var alg = val('ds_' + prefix + '_alg'), mac = MACS[alg];
  if (!mac) {
    setVal('ds_' + prefix + '_status', 'Unknown MAC: ' + alg);
    log.debug("Leaving macGenerateKey().");
    return false;
  }
  setVal('ds_' + prefix + '_key', bytesToHex(randomBytes(mac.keyBytes)));
  setVal('ds_' + prefix + '_status', 'Generated ' + (mac.keyBytes * 8) +
         '-bit key for ' + alg + '.');
  log.debug("Leaving macGenerateKey().");
  return false;
}
function macCompute(prefix) {
  log.debug("Entering macCompute().");
  var alg = val('ds_' + prefix + '_alg');
  try {
    var mac = MACS[alg];
    if (!mac) throw new Error('Unknown MAC: ' + alg);
    var tag = mac.fn(hexToBytes(val('ds_' + prefix + '_key')),
        strBytes(val('ds_' + prefix + '_value')));
    setVal('ds_' + prefix + '_mac', bytesToB64(tag));
    setVal('ds_' + prefix + '_status', 'Computed ' + alg + ' — ' + tag.length +
           '-byte tag.');
  } catch (e) {
    log.error('macCompute: ' + e.message);
    setVal('ds_' + prefix + '_status', 'MAC error: ' + e.message +
           ' (check the key length for this algorithm).');
  }
  log.debug("Leaving macCompute().");
  return false;
}
function macVerify(prefix) {
  log.debug("Entering macVerify().");
  var alg = val('ds_' + prefix + '_alg');
  try {
    var mac = MACS[alg];
    if (!mac) throw new Error('Unknown MAC: ' + alg);
    var tag = mac.fn(hexToBytes(val('ds_' + prefix + '_key')),
        strBytes(val('ds_' + prefix + '_value')));
    var ok = bytesEqual(tag, b64ToBytes(val('ds_' + prefix + '_mac')));
    setVal('ds_' + prefix + '_status', ok
      ? 'MAC VALID ✓ — recomputed tag matches the value and key.'
      : 'MAC INVALID ✗ — the tag does not match.');
  } catch (e) {
    log.error('macVerify: ' + e.message);
    setVal('ds_' + prefix + '_status', 'Verify error: ' + e.message);
  }
  log.debug("Leaving macVerify().");
  return false;
}

// ===========================================================================
// Pane #6 — JWS (JSON Web Signature, RFC 7515)
//
// The pane that is about a SERIALIZATION rather than about a primitive. Every
// algorithm here is one the panes above already have — HMAC, RSA in both
// paddings, ECDSA, EdDSA — and what this one adds is the envelope they travel
// in: which octets are signed (RFC 7515 section 5.1, and it is NOT the JSON,
// it is the base64url of the JSON, with a period in the middle), how the three
// parts are packed, and what the header says about all of it.
//
// The cryptography and the serialization are in ./jws. What lives here is the
// pane: reading its fields, choosing a key representation, and reporting.
// ===========================================================================

// The key fields hold what the pane above them holds: RSA is a PEM, an
// elliptic-curve key is raw hex, and an HMAC secret is whatever the encoding
// selector says. That selector exists because a shared secret is the one piece
// of key material people paste from somewhere else — a JWK's `k` is base64url,
// a config file's is usually text, and a test vector's is hex, and reading one
// as another produces a valid signature under a key that is not the one on the
// screen.
function jwsSecretBytes(text) {
  log.debug("Entering jwsSecretBytes().");
  var encoding = val('ds_jws_secret_encoding') || 'hex';
  var raw = (text || '').trim();
  if (encoding === 'text') {
    log.debug("Leaving jwsSecretBytes(). UTF-8.");
    return strBytes(raw);
  }
  if (encoding === 'b64u') {
    log.debug("Leaving jwsSecretBytes(). base64url.");
    return bytesLib.b64uToBytes(raw);
  }
  log.debug("Leaving jwsSecretBytes(). Hex.");
  return hexToBytes(raw);
}

function jwsKeyFor(algId, which) {
  log.debug("Entering jwsKeyFor().");
  var spec = jws.algSpec(algId);
  var text = val(which === 'private' ? 'ds_jws_private_key'
                                     : 'ds_jws_public_key');
  if (spec.family === 'none') {
    log.debug("Leaving jwsKeyFor(). Unsecured.");
    return null;
  }
  if (spec.family === 'rsa') {
    log.debug("Leaving jwsKeyFor(). PEM.");
    return text;
  }
  if (spec.family === 'hmac') {
    log.debug("Leaving jwsKeyFor(). Secret.");
    return jwsSecretBytes(text);
  }
  log.debug("Leaving jwsKeyFor(). Raw hex.");
  return hexToBytes(text);
}

function jwsShowKeys(algId, pair) {
  log.debug("Entering jwsShowKeys().");
  var spec = jws.algSpec(algId);
  if (spec.family === 'rsa') {
    setVal('ds_jws_private_key', pair.privateKey);
    setVal('ds_jws_public_key', pair.publicKey);
  } else if (spec.family === 'hmac') {
    var encoding = val('ds_jws_secret_encoding') || 'hex';
    var shown;
    if (encoding === 'b64u') {
      shown = bytesLib.bytesToB64u(pair.privateKey);
    } else {
      // Random bytes are not text. Rather than emit mojibake that the "UTF-8
      // text" selector would then read back as different bytes, the generator
      // switches the pane to hex — a key that changes when it is displayed is
      // worse than a selector that moved.
      if (encoding === 'text') setVal('ds_jws_secret_encoding', 'hex');
      shown = bytesToHex(pair.privateKey);
    }
    setVal('ds_jws_private_key', shown);
    setVal('ds_jws_public_key', shown);
  } else {
    setVal('ds_jws_private_key', bytesToHex(pair.privateKey));
    setVal('ds_jws_public_key', bytesToHex(pair.publicKey));
  }
  log.debug("Leaving jwsShowKeys().");
}

function jwsGenerateKeys() {
  log.debug("Entering jwsGenerateKeys().");
  var algId = val('ds_jws_alg');
  var spec = jws.algSpec(algId);
  if (spec.family === 'none') {
    setVal('ds_jws_private_key', '');
    setVal('ds_jws_public_key', '');
    setVal('ds_jws_status', 'alg=none has no key. That is the whole point of ' +
           'it, and the reason a relying party that accepts one is broken.');
    log.debug("Leaving jwsGenerateKeys(). Unsecured.");
    return false;
  }
  var bits = parseInt(val('ds_jws_rsa_bits'), 10) || 2048;
  setVal('ds_jws_status', 'Generating a ' + algId + ' key' +
         (spec.family === 'rsa' ? ' pair (RSA ' + bits +
          '-bit, pure JS — larger sizes take longer)' : '') + '…');
  defer(function () {
    try {
      jwsShowKeys(algId, jws.generateKey(algId, { bits: bits }));
      setVal('ds_jws_status', 'Generated ' + algId + ' key material (' +
             spec.spec + ', ' + spec.req.toLowerCase() + ' to implement).');
    } catch (e) {
      log.error('jwsGenerateKeys: ' + e.message);
      setVal('ds_jws_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving jwsGenerateKeys().");
  return false;
}

// The payload check the pane exists to make. RFC 7515 lets a payload be any
// octet sequence; this pane requires JSON, so Sign refuses a payload that is
// not — and this button says the same thing without signing anything.
function jwsValidatePayload() {
  log.debug("Entering jwsValidatePayload().");
  var checked = jws.validateJson(val('ds_jws_payload'));
  if (!checked.valid) {
    setVal('ds_jws_status', 'Payload is NOT valid JSON ✗ — ' + checked.error);
    log.debug("Leaving jwsValidatePayload(). Invalid.");
    return false;
  }
  setVal('ds_jws_status', 'Payload is valid JSON ✓ — a JSON ' + checked.kind +
         (checked.members === null ? '' : ' with ' + checked.members +
          ' member(s)') + '.');
  log.debug("Leaving jwsValidatePayload().");
  return false;
}

// Re-indent the payload. Deliberately a BUTTON rather than something Sign
// does: reformatting changes the octets under the signature, so it is the
// user's decision and it happens before signing, visibly, in the field they
// are looking at.
function jwsFormatPayload() {
  log.debug("Entering jwsFormatPayload().");
  var checked = jws.validateJson(val('ds_jws_payload'));
  if (!checked.valid) {
    setVal('ds_jws_status', 'Cannot format — ' + checked.error);
    log.debug("Leaving jwsFormatPayload(). Invalid.");
    return false;
  }
  setVal('ds_jws_payload', JSON.stringify(checked.value, null, 2));
  setVal('ds_jws_status', 'Payload re-indented. The signature covers these ' +
         'octets, so sign again.');
  log.debug("Leaving jwsFormatPayload().");
  return false;
}

function jwsHeaderObject(id, label) {
  log.debug("Entering jwsHeaderObject().");
  var raw = (val(id) || '').trim();
  if (!raw) {
    log.debug("Leaving jwsHeaderObject(). Empty.");
    return {};
  }
  var parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(label + ' is not well-formed JSON: ' + e.message);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(label + ' must be a JSON object.');
  }
  log.debug("Leaving jwsHeaderObject().");
  return parsed;
}

function jwsSign() {
  log.debug("Entering jwsSign().");
  var algId = val('ds_jws_alg');
  setVal('ds_jws_status', 'Signing with ' + algId + '…');
  try {
    var checked = jws.validateJson(val('ds_jws_payload'));
    if (!checked.valid) {
      setVal('ds_jws_status', 'Refusing to sign — ' + checked.error);
      log.debug("Leaving jwsSign(). Payload is not JSON.");
      return false;
    }
    var payload = panes.isChecked('ds_jws_compact_payload')
      ? JSON.stringify(checked.value) : val('ds_jws_payload');
    var result = jws.signJws({
      algId: algId,
      payload: payload,
      privateKey: jwsKeyFor(algId, 'private'),
      publicKey: jwsKeyFor(algId, 'public'),
      serialization: val('ds_jws_serialization') || 'compact',
      typ: val('ds_jws_typ'),
      cty: val('ds_jws_cty'),
      kid: val('ds_jws_kid'),
      header: jwsHeaderObject('ds_jws_header_extra',
          'The extra protected header'),
      unprotected: jwsHeaderObject('ds_jws_unprotected',
          'The unprotected header'),
      // The checkbox says "unencoded", not "encoded": a missing element (an
      // older cached page) then means b64 stays ON, which is RFC 7515's
      // behaviour rather than RFC 7797's.
      b64: panes.isChecked('ds_jws_unencoded') ? false : true,
      detached: panes.isChecked('ds_jws_detached'),
      embedJwk: panes.isChecked('ds_jws_embed_jwk')
    });
    if (panes.isChecked('ds_jws_compact_payload')) {
      setVal('ds_jws_payload', payload);
    }
    setVal('ds_jws_signature', result.serialized);
    setVal('ds_jws_decoded', 'Protected header:\n' +
           JSON.stringify(result.header, null, 2) +
           '\n\nSigning input (RFC 7515 §5.1):\n' + result.signingInput);
    setVal('ds_jws_status', 'Signed — ' + result.alg + ', ' +
           result.serialization + ' serialization' +
           (result.detached ? ', detached payload' : '') +
           (result.b64 === false ? ', unencoded payload (RFC 7797)' : '') +
           '. Signature is ' +
           bytesLib.b64uToBytes(result.signature).length + ' bytes.');
  } catch (e) {
    log.error('jwsSign: ' + e.message);
    setVal('ds_jws_status', 'Sign error: ' + e.message);
  }
  log.debug("Leaving jwsSign().");
  return false;
}

function jwsValidate() {
  log.debug("Entering jwsValidate().");
  var algId = val('ds_jws_alg');
  setVal('ds_jws_status', 'Validating…');
  try {
    var fromHeader = panes.isChecked('ds_jws_trust_header');
    var result = jws.verifyJws({
      jws: val('ds_jws_signature'),
      publicKey: jwsKeyFor(algId, 'public'),
      algId: fromHeader ? null : algId,
      detachedPayload: val('ds_jws_payload')
    });
    var first = result.signatures[0] || {};
    setVal('ds_jws_decoded', 'Protected header:\n' +
           JSON.stringify(first.header || {}, null, 2) +
           (first.unprotected ? '\n\nUnprotected header:\n' +
            JSON.stringify(first.unprotected, null, 2) : '') +
           '\n\nPayload:\n' + (first.payload === undefined ? '(detached)'
                                : first.payload));
    if (result.unsecured && result.valid) {
      setVal('ds_jws_status', 'Unsecured JWS (alg=none) — well-formed, and ' +
             'NOTHING about it is authenticated. RFC 7515 §6.');
    } else if (result.valid) {
      setVal('ds_jws_status', 'Signature VALID ✓ — ' +
             (first.header ? first.header.alg : algId) + ', ' +
             result.serialization + ' serialization' +
             (result.detached ? ', detached payload' : '') + '.');
    } else {
      setVal('ds_jws_status', 'Signature INVALID ✗ — ' +
             (first.reason || 'the signature does not verify.'));
    }
  } catch (e) {
    log.error('jwsValidate: ' + e.message);
    setVal('ds_jws_status', 'Validation error: ' + e.message);
  }
  log.debug("Leaving jwsValidate().");
  return false;
}

async function jwsDownloadKeys() {
  log.debug("Entering jwsDownloadKeys().");
  var algId = val('ds_jws_alg');
  var spec = jws.algSpec(algId);
  var fmt = val('ds_jws_ks_format') || 'jwk', pw = val('ds_jws_ks_password');
  var priv = val('ds_jws_private_key'), pub = val('ds_jws_public_key');
  if (!priv && !pub) {
    setVal('ds_jws_status', 'Nothing to download — generate a key first.');
    log.debug("Leaving jwsDownloadKeys(). Nothing to export.");
    return false;
  }
  try {
    if (spec.family === 'none') {
      setVal('ds_jws_status', 'alg=none has no key to export.');
    } else if (spec.family === 'rsa') {
      // The shared keystore matrix, exactly as the RSA pane uses it —
      // key_material.js's, checked against OpenSSL in node.
      var certs = fmt === 'pkcs12' ? [await x509.selfSignedCertPem({
        subject: 'CN=jws-signing-key', privatePem: priv, publicPem: pub,
        desc: { kind: 'rsa', hash: 'SHA-256' } })] : [];
      var out = await keyMaterial.exportKeyPair({
        privatePem: priv, publicPem: pub,
        desc: { kind: 'rsa', hash: 'SHA-256' },
        format: fmt, password: pw, friendlyName: 'jws-signing-key',
        use: 'sig', certs: certs, baseName: 'jws-keys'
      });
      keyMaterial.downloadFiles(out.files);
      setVal('ds_jws_status', out.status);
    } else if (fmt === 'jwk') {
      var kid = val('ds_jws_kid');
      var set;
      if (spec.family === 'hmac') {
        // ONE key, not two. An `oct` JWK is the whole of a shared secret —
        // there is no public half to publish beside it, and a set carrying
        // the same key twice invites somebody to hand the first one out.
        set = [jws.publicJwk(algId, jwsSecretBytes(priv), kid)];
      } else {
        set = [jws.publicJwk(algId, hexToBytes(pub), kid),
               jws.privateJwk(algId, hexToBytes(priv), hexToBytes(pub), kid)];
      }
      await downloadJwkSet(set, pw, 'jws-keys', 'ds_jws_status');
    } else {
      setVal('ds_jws_status', fmt.toUpperCase() + ' export is not supported ' +
             'for a raw ' + algId + ' key. Use JWK, which is the form JOSE ' +
             'defines for it.');
    }
  } catch (e) {
    log.error('jwsDownloadKeys: ' + e.message);
    setVal('ds_jws_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving jwsDownloadKeys().");
  return false;
}

// ===========================================================================
// Pane #7 — XML Digital Signature (W3C XMLDSIG, RFC 3275)
//
// The other pane about an envelope rather than a primitive, and the one with
// the most ways to produce a signature that is cryptographically perfect and
// verifies nowhere: the canonicalization is a choice, the transforms are an
// ORDERED LIST whose output feeds the next one, the Reference names what is
// covered, and every one of those is written into the document a verifier
// reads back. So they are all on the screen.
//
// The engine is ./xmldsig, shared with the SAML, WS-Trust and WS-Federation
// pages — a canonicalizer is a reading of a specification, and two readings
// of C14N agree with each other and interoperate with nobody. What that module
// does NOT carry is elliptic-curve and HMAC cryptography, deliberately (it
// would land in three bundles that sign nothing with a curve), so this pane
// hands it a signer built from the curves the ECC pane above already loaded.
// ===========================================================================

var XML_CURVES = {
  'P-256': { curve: p256, fieldBytes: 32,
             oid: 'urn:oid:1.2.840.10045.3.1.7' },
  'P-384': { curve: p384, fieldBytes: 48, oid: 'urn:oid:1.3.132.0.34' },
  'P-521': { curve: p521, fieldBytes: 66, oid: 'urn:oid:1.3.132.0.35' },
  'secp256k1': { curve: secp256k1, fieldBytes: 32,
                 oid: 'urn:oid:1.3.132.0.10' }
};

// The XMLDSIG hash names are lower-case and unhyphenated where this page's
// hash registry spells them SHA-256; mapping rather than renaming, because the
// registry above is shared with the RSA and ECC panes and their dropdowns.
var XML_HASHES = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384',
                   sha512: 'SHA-512' };

function xmlCurve() {
  log.debug("Entering xmlCurve().");
  var name = val('ds_xml_curve') || 'P-256';
  var c = XML_CURVES[name];
  if (!c) throw new Error('Unknown curve: ' + name);
  log.debug("Leaving xmlCurve().");
  return c;
}

// A signer/verifier pair for the families xmldsig.js deliberately does not
// implement. `octets` is a forge binary string on the way in and out — that is
// the engine's currency, and converting at this boundary keeps every byte
// conversion in one place.
function xmlSigner() {
  log.debug("Entering xmlSigner().");
  log.debug("Leaving xmlSigner().");
  return function (octets, spec) {
    var bytes = forge.util.binary.raw.decode(octets);
    if (spec.family === 'hmac') {
      var key = hexToBytes(val('ds_xml_private_key'));
      return forge.util.binary.raw.encode(
          nobleHmac(HASHES[XML_HASHES[spec.hash]].fn, key, bytes));
    }
    var c = xmlCurve();
    var priv = hexToBytes(val('ds_xml_private_key'));
    var sig = c.curve.sign(digestOf(XML_HASHES[spec.hash], bytes), priv);
    return forge.util.binary.raw.encode(sig.toCompactRawBytes());
  };
}

function xmlVerifier() {
  log.debug("Entering xmlVerifier().");
  log.debug("Leaving xmlVerifier().");
  return function (octets, signature, spec) {
    var bytes = forge.util.binary.raw.decode(octets);
    var sig = forge.util.binary.raw.decode(signature);
    if (spec.family === 'hmac') {
      var key = hexToBytes(val('ds_xml_public_key') ||
                           val('ds_xml_private_key'));
      var tag = nobleHmac(HASHES[XML_HASHES[spec.hash]].fn, key, bytes);
      return bytesEqual(tag, sig);
    }
    var c = xmlCurve();
    var pub = hexToBytes(val('ds_xml_public_key'));
    // lowS:false on VERIFICATION only. @noble refuses a high-S secp256k1
    // signature by default — a Bitcoin malleability rule that XMLDSIG does
    // not have — so a perfectly good signature from OpenSSL would be reported
    // as a bad one. Signing keeps the default, which is always acceptable.
    return c.curve.verify(sig, digestOf(XML_HASHES[spec.hash], bytes), pub,
                          { lowS: false });
  };
}

function xmlGenerateKeys() {
  log.debug("Entering xmlGenerateKeys().");
  var spec;
  try {
    spec = xmldsig.sigMethod(val('ds_xml_sigalg'));
  } catch (e) {
    setVal('ds_xml_status', e.message);
    log.debug("Leaving xmlGenerateKeys(). Unknown method.");
    return false;
  }
  if (spec.family === 'hmac') {
    var secret = randomBytes(32);
    setVal('ds_xml_private_key', bytesToHex(secret));
    setVal('ds_xml_public_key', bytesToHex(secret));
    setVal('ds_xml_cert', '');
    setVal('ds_xml_status', 'Generated a 256-bit shared secret. An HMAC ' +
           'SignatureMethod is a MAC: it proves integrity, it gives no ' +
           'non-repudiation, and both parties hold this one key.');
    log.debug("Leaving xmlGenerateKeys(). HMAC.");
    return false;
  }
  if (spec.family === 'ecdsa') {
    try {
      var c = xmlCurve();
      var priv = c.curve.utils.randomPrivateKey();
      setVal('ds_xml_private_key', bytesToHex(priv));
      setVal('ds_xml_public_key', bytesToHex(c.curve.getPublicKey(priv,
          false)));
      setVal('ds_xml_cert', '');
      setVal('ds_xml_status', 'Generated an ECDSA ' + val('ds_xml_curve') +
             ' key pair. KeyInfo for it is a dsig11:ECKeyValue — no X.509 ' +
             'certificate is minted for a curve here.');
    } catch (e) {
      log.error('xmlGenerateKeys: ' + e.message);
      setVal('ds_xml_status', 'Key generation error: ' + e.message);
    }
    log.debug("Leaving xmlGenerateKeys(). ECDSA.");
    return false;
  }
  var bits = parseInt(val('ds_xml_rsa_bits'), 10) || 2048;
  setVal('ds_xml_status', 'Generating an RSA ' + bits + '-bit key pair and a ' +
         'self-signed certificate — pure JS, so this takes a moment…');
  defer(function () {
    try {
      // The SHARED generator, so the private key is PKCS#8 and the keystore
      // matrix below can export it; the certificate comes from xmldsig.js,
      // which is where forge certificate minting for XML signing already
      // lives.
      var pair = pkEncryption.rsaGenerateKeyPair(bits);
      setVal('ds_xml_private_key', pair.privatePem);
      setVal('ds_xml_public_key', pair.publicPem);
      setVal('ds_xml_cert', xmldsig.selfSignedCertFor(pair.privatePem,
          pair.publicPem, 'xml-signature-tool'));
      setVal('ds_xml_status', 'Generated an RSA ' + bits + '-bit key pair ' +
             'and a self-signed certificate for KeyInfo.');
    } catch (e) {
      log.error('xmlGenerateKeys: ' + e.message);
      setVal('ds_xml_status', 'Key generation error: ' + e.message);
    }
  });
  log.debug("Leaving xmlGenerateKeys(). RSA.");
  return false;
}

// The transform CHAIN, in the order XMLDSIG applies it: remove the signature,
// then filter, then decode, then canonicalize. The order is not a preference —
// each transform's output is the next one's input, and a canonicalization
// anywhere but last ends the chain (the engine says so by name).
function xmlTransforms() {
  log.debug("Entering xmlTransforms().");
  var list = [];
  if (panes.isChecked('ds_xml_t_enveloped')) {
    list.push({ algorithm: xmldsig.TRANSFORM_ENVELOPED });
  }
  var kind = val('ds_xml_t_xpath_kind') || 'none';
  var expr = (val('ds_xml_t_xpath') || '').trim();
  if (kind === 'xpath' && expr) {
    list.push({ algorithm: xmldsig.TRANSFORM_XPATH, xpath: expr });
  } else if (kind === 'filter2' && expr) {
    list.push({ algorithm: xmldsig.TRANSFORM_XPATH_FILTER2,
                filters: [{ filter: val('ds_xml_t_filter') || 'intersect',
                            xpath: expr }] });
  }
  var base64 = panes.isChecked('ds_xml_t_base64');
  if (base64) list.push({ algorithm: xmldsig.TRANSFORM_BASE64 });
  var c14n = val('ds_xml_t_c14n');
  var notes = [];
  if (c14n && base64) {
    // The base64 transform already produces OCTETS, and a canonicalization
    // takes a node-set — so the two cannot both be on the chain and the
    // engine refuses the pair by name. Dropping the canonicalization is the
    // only reading of "base64 and this c14n" that means anything, and it is
    // said out loud rather than done quietly: a transform silently missing
    // from a Reference is the class of defect this whole pane is for.
    notes.push('The base64 transform ends the chain — it produces octets, ' +
        'and a canonicalization needs a node-set. The Reference ' +
        'canonicalization was left off.');
  } else if (c14n) {
    list.push({ algorithm: c14n, prefixList: val('ds_xml_t_prefixes') });
  }
  log.debug("Leaving xmlTransforms().");
  return { list: list, notes: notes };
}

// The check the pane exists to make, and the mirror of the JWS pane's JSON
// one. XMLDSIG signs the exact octets that get canonicalized, so nothing here
// "cleans" the input — a document that is not well-formed is refused, by name,
// before anything is signed.
function xmlValidateDocument() {
  log.debug("Entering xmlValidateDocument().");
  try {
    var doc = xmldsig.parseXmlStrict(val('ds_xml_value'), 'the XML');
    var root = doc.documentElement;
    setVal('ds_xml_status', 'The XML is well-formed ✓ — root <' +
           root.nodeName + '>' +
           (root.namespaceURI ? ' in ' + root.namespaceURI : '') +
           ', ' + doc.getElementsByTagName('*').length + ' element(s).');
  } catch (e) {
    setVal('ds_xml_status', 'The XML is NOT well-formed ✗ — ' + e.message);
  }
  log.debug("Leaving xmlValidateDocument().");
  return false;
}

function xmlSignOptions(spec, paneTransforms) {
  log.debug("Entering xmlSignOptions().");
  var keyInfo = val('ds_xml_keyinfo') || 'x509';
  var opts = {
    mode: val('ds_xml_mode') || 'enveloped',
    sigAlg: val('ds_xml_sigalg'),
    digestUri: val('ds_xml_digest'),
    c14nAlg: val('ds_xml_c14n'),
    c14nPrefixList: val('ds_xml_c14n_prefixes'),
    transforms: paneTransforms.list,
    refUri: val('ds_xml_ref_uri'),
    placement: val('ds_xml_placement'),
    objectId: val('ds_xml_object_id'),
    signatureId: val('ds_xml_sig_id'),
    keyInfo: keyInfo,
    keyName: val('ds_xml_keyname'),
    certPem: val('ds_xml_cert'),
    publicKeyPem: spec.family === 'rsa' ? val('ds_xml_public_key') : ''
  };
  if (spec.family === 'ecdsa') {
    var c = xmlCurve();
    opts.ecNamedCurve = c.oid;
    opts.ecPublicPoint = hexToBytes(val('ds_xml_public_key'));
  }
  if (spec.family === 'rsa') opts.privateKeyPem = val('ds_xml_private_key');
  else opts.signer = xmlSigner();
  log.debug("Leaving xmlSignOptions().");
  return opts;
}

function xmlSign() {
  log.debug("Entering xmlSign().");
  var alg = val('ds_xml_sigalg');
  setVal('ds_xml_status', 'Signing…');
  try {
    var spec = xmldsig.sigMethod(alg);
    if (spec.family !== 'rsa' && val('ds_xml_keyinfo') === 'x509') {
      setVal('ds_xml_status', 'A ' + spec.label + ' signature has no X.509 ' +
             'certificate here. Choose KeyValue (ECDSA) or KeyName / none ' +
             '(HMAC) for KeyInfo.');
      log.debug("Leaving xmlSign(). KeyInfo does not fit the key.");
      return false;
    }
    var paneTransforms = xmlTransforms();
    var result = xmldsig.signXml(val('ds_xml_value'),
        xmlSignOptions(spec, paneTransforms));
    var notes = paneTransforms.notes.concat(result.notes);
    setVal('ds_xml_signature', result.xml);
    if (result.referencedXml) setVal('ds_xml_value', result.referencedXml);
    setVal('ds_xml_report',
      'SignedInfo (canonicalized — these are the signed octets):\n' +
      result.signedInfo + '\n\nReference URI: ' +
      (result.referenceUri || '(empty — the whole document)') +
      '\nTransforms: ' + (result.transforms.join('\n            ') ||
       '(none)') +
      '\nDigestValue: ' + result.digestValue +
      '\nSignatureValue: ' + result.signatureValue +
      (notes.length ? '\n\nNotes:\n- ' + notes.join('\n- ') : ''));
    setVal('ds_xml_status', 'Signed — ' + spec.label + ', ' +
           xmldsig.c14nMethod(result.canonicalization).label + ', ' +
           result.mode + (notes.length ? '. ' + notes[0] : '.'));
  } catch (e) {
    log.error('xmlSign: ' + e.message);
    setVal('ds_xml_status', 'Sign error: ' + e.message);
  }
  log.debug("Leaving xmlSign().");
  return false;
}

function xmlValidate() {
  log.debug("Entering xmlValidate().");
  setVal('ds_xml_status', 'Validating…');
  try {
    var mode = val('ds_xml_mode') || 'enveloped';
    var spec = xmldsig.sigMethod(val('ds_xml_sigalg'));
    var opts = {
      certPem: val('ds_xml_cert'),
      publicKeyPem: spec.family === 'rsa' ? val('ds_xml_public_key') : '',
      referencedXml: mode === 'detached' ? val('ds_xml_value') : null
    };
    if (spec.family !== 'rsa') opts.verifier = xmlVerifier();
    var result = xmldsig.verifyXml(val('ds_xml_signature'), opts);
    if (result.error) {
      setVal('ds_xml_status', 'Validation error: ' + result.error);
      log.debug("Leaving xmlValidate(). Engine reported an error.");
      return false;
    }
    var lines = ['SignatureMethod: ' + result.signatureMethod,
                 'CanonicalizationMethod: ' + result.canonicalization,
                 'SignatureValue over SignedInfo: ' +
                 (result.signatureValid ? 'VALID' : 'INVALID' +
                  (result.signatureError ? ' (' + result.signatureError + ')'
                                         : '')),
                 'KeyInfo: ' + result.keyInfo +
                 (result.signerSubject ? ' (CN=' + result.signerSubject + ')'
                                       : '')];
    result.references.forEach(function (r, n) {
      lines.push('Reference ' + (n + 1) + ' URI="' + r.uri + '": ' +
        (r.ok ? 'digest matches' : 'FAILED — ' + (r.reason || 'unknown')) +
        (r.declared ? '\n  declared ' + r.declared + '\n  computed ' +
         r.computed : ''));
    });
    setVal('ds_xml_report', lines.join('\n'));
    setVal('ds_xml_status', result.valid
      ? 'Signature VALID ✓ — the SignatureValue and every Reference digest ' +
        'check out.'
      : 'Signature INVALID ✗ — ' + (!result.signatureValid
          ? 'the SignatureValue does not verify over SignedInfo.'
          : 'a Reference digest does not match; the signed content changed.'));
  } catch (e) {
    log.error('xmlValidate: ' + e.message);
    setVal('ds_xml_status', 'Validation error: ' + e.message);
  }
  log.debug("Leaving xmlValidate().");
  return false;
}

async function xmlDownloadKeys() {
  log.debug("Entering xmlDownloadKeys().");
  var fmt = val('ds_xml_ks_format') || 'pem', pw = val('ds_xml_ks_password');
  var priv = val('ds_xml_private_key'), pub = val('ds_xml_public_key');
  if (!priv && !pub) {
    setVal('ds_xml_status', 'Nothing to download — generate a key first.');
    log.debug("Leaving xmlDownloadKeys(). Nothing to export.");
    return false;
  }
  try {
    var spec = xmldsig.sigMethod(val('ds_xml_sigalg'));
    if (spec.family === 'rsa') {
      var certPem = val('ds_xml_cert');
      var out = await keyMaterial.exportKeyPair({
        privatePem: priv, publicPem: pub,
        desc: { kind: 'rsa', hash: 'SHA-256' },
        format: fmt, password: pw, friendlyName: 'xml-signature-tool',
        use: 'sig', certs: fmt === 'pkcs12' && certPem ? [certPem] : [],
        baseName: 'xmldsig-keys'
      });
      keyMaterial.downloadFiles(out.files);
      setVal('ds_xml_status', out.status);
    } else if (spec.family === 'ecdsa' && fmt === 'jwk') {
      var c = xmlCurve();
      var pt = c.curve.ProjectivePoint.fromHex(pub).toAffine();
      var x = b64u(bigToBytes(pt.x, c.fieldBytes));
      var y = b64u(bigToBytes(pt.y, c.fieldBytes));
      await downloadJwkSet([
        { kty: 'EC', crv: val('ds_xml_curve'), x: x, y: y, use: 'sig' },
        { kty: 'EC', crv: val('ds_xml_curve'), x: x, y: y,
          d: b64u(hexToBytes(priv)), use: 'sig' }
      ], pw, 'xmldsig-keys', 'ds_xml_status');
    } else if (spec.family === 'hmac') {
      setVal('ds_xml_status', 'A shared secret has no keystore format here. ' +
             'Copy the hex from the key field.');
    } else {
      setVal('ds_xml_status', fmt.toUpperCase() + ' export is not supported ' +
             'for a raw ECDSA key. Use JWK.');
    }
  } catch (e) {
    log.error('xmlDownloadKeys: ' + e.message);
    setVal('ds_xml_status', 'Download error: ' + e.message);
  }
  log.debug("Leaving xmlDownloadKeys().");
  return false;
}

// ---------------------------------------------------------------------------
// Page chrome — collapse/expand, the clipboard, and the "Return to" link.
// All three are tool_panes.js's, shared with the Encryption / Decryption page.
// ---------------------------------------------------------------------------
function expandAll() {
  log.debug("Entering expandAll().");
  log.debug("Leaving expandAll().");
  return panes.expandAll();
}

function collapseAll() {
  log.debug("Entering collapseAll().");
  log.debug("Leaving collapseAll().");
  return panes.collapseAll();
}

function copyField(elementId) {
  log.debug("Entering copyField().");
  log.debug("Leaving copyField().");
  return panes.copyField(elementId);
}

// The pages that may send you here. A whitelist rather than a redirect — see
// the note on setReturnLink() in tool_panes.js.
var RETURN_TARGETS = {
  'oauth2_oidc_1.html': { href: '/oauth2_oidc_1.html' },
  'oauth2_oidc_2.html': { href: '/oauth2_oidc_2.html' },
  'encryption_tools.html': { href: '/encryption_tools.html',
                             label: 'Encryption / Decryption' }
};

function setReturnLink() {
  log.debug("Entering setReturnLink().");
  panes.setReturnLink(RETURN_TARGETS, '/oauth2_oidc_1.html');
  log.debug("Leaving setReturnLink().");
}

window.onload = function () {
  log.debug("Entering onload().");
  log.debug('Entering onload function.');
  setReturnLink();
  setVal('ds_value', 'Sign me with SLH-DSA!');
  setVal('ds_rsa_value', 'Sign me with RSA!');
  setVal('ds_ecc_value', 'Sign me with ECC!');
  setVal('ds_ml_value', 'Sign me with ML-DSA!');
  // BBS signs a LIST, so its pane is seeded with one — plus the two octet
  // strings the draft binds in (header, presentation header) and a disclosure
  // selection, so "Derive Proof" does something meaningful on first use.
  setVal('ds_bbs_messages', 'given_name:Alice\nfamily_name:Smith\n' +
         'birthdate:1980-01-01\ncountry:US');
  setVal('ds_bbs_header', 'BBS demo header');
  setVal('ds_bbs_ph', 'verifier nonce 12345');
  setVal('ds_bbs_disclosed', '0, 2');
  // The JWS pane signs JSON and nothing else, so its seed is JSON — and it is
  // indented, which is the point: a JWS payload is base64url of the octets as
  // they stand, so the whitespace is inside the signature.
  setVal('ds_jws_payload', JSON.stringify({
    iss: 'https://as.example.com',
    sub: 'alice',
    aud: 'https://api.example.com',
    scope: 'read write'
  }, null, 2));
  // The XML pane's seed carries a comment and a namespace on purpose: the
  // comment is what tells the two halves of each canonicalization method
  // apart, and the namespace is what exclusive C14N is about.
  setVal('ds_xml_value',
    '<Order xmlns="urn:example:order" ID="order-1">\n' +
    '  <!-- exclusive vs inclusive C14N shows up here -->\n' +
    '  <Item sku="A1">Widget</Item>\n' +
    '  <Total currency="USD">42.00</Total>\n' +
    '</Order>');
  // Symmetric MAC panes: seed a value and an initial random key.
  setVal('ds_khmac_value',
         'MAC me with a keyed hash!'); macGenerateKey('khmac');
  setVal('ds_bcmac_value',
         'MAC me with a block cipher!'); macGenerateKey('bcmac');
  setVal('ds_uhmac_value',
         'MAC me with a universal hash!'); macGenerateKey('uhmac');

  // Make each pane collapsible: clicking its legend toggles the fieldset.
  panes.wireCollapsibleLegends();

  // Default to all panes minimized on load; the user expands the ones they need
  // (or clicks "Expand all"). Clicking a pane's title toggles it individually.
  collapseAll();
  log.debug("Leaving onload().");
};

module.exports = {
  generateKeys,
  downloadKeys,
  sign,
  validate,
  rsaGenerateKeys,
  rsaDownloadKeys,
  rsaSign,
  rsaValidate,
  eccGenerateKeys,
  eccDownloadKeys,
  eccSign,
  eccValidate,
  mldsaGenerateKeys,
  mldsaDownloadKeys,
  mldsaSign,
  mldsaValidate,
  bbsGenerateKeys,
  bbsDownloadKeys,
  bbsSign,
  bbsValidate,
  bbsProofGen,
  bbsProofVerify,
  macGenerateKey,
  macCompute,
  macVerify,
  jwsGenerateKeys,
  jwsValidatePayload,
  jwsFormatPayload,
  jwsSign,
  jwsValidate,
  jwsDownloadKeys,
  xmlGenerateKeys,
  xmlValidateDocument,
  xmlSign,
  xmlValidate,
  xmlDownloadKeys,
  viewRsaCert,
  expandAll,
  collapseAll,
  copyField
};
