// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: crypto_provider.js
//
// ---------------------------------------------------------------------------
// THE CRYPTOGRAPHY FACADE (issue #463). One API that every format layer calls:
// JOSE (jws.js, jose_jwe.js), XML Signature / Encryption (common/xmldsig.js)
// and COSE (mdoc.js, webauthn.js, CWT). Each of those maps ITS identifiers —
// a JOSE `alg`, an XML algorithm URI, a COSE integer — onto the canonical ids
// in ALGORITHMS below and holds no cryptography of its own. In step 1 nothing
// calls this yet; it exists, is complete for the classical algorithms, and
// tests/crypto_provider_engine.js holds it against node's own crypto
// (OpenSSL), which shares no code with @noble or node-forge.
//
// WHAT IS NEW HERE AND WHAT IS NOT. Wherever an engine in this directory
// already implements a primitive, this file calls it:
//
//   digests, KMAC        -> hash_tools.js
//   AES-GCM, AES-CBC (PKCS#7), ChaCha20-Poly1305, the raw AES block
//                        -> symmetric_crypto.js
//   RSA-OAEP / PKCS#1 v1.5 encryption
//                        -> pk_encryption.js
//   ML-DSA, SLH-DSA, composites, ML-KEM, X-Wing
//                        -> pqc.js
//   LMS/HSS, XMSS/XMSS^MT
//                        -> hbs.js
//   the key representation and every key encoding
//                        -> crypto_keys.js (new; re-exported from here)
//
// and what is implemented HERE, once, because nothing had it: ECDSA, RSA
// PKCS#1 v1.5 and PSS signatures, EdDSA (from jws.js's js backend, which keeps
// its copy until step 2 moves it onto this), ECDH / X25519 / X448, HMAC, HKDF,
// PBKDF2 (over @noble/hashes with hash_tools.js's hash functions), NIST SP
// 800-56A Concat KDF, RFC 3394 AES Key Wrap, unpadded AES-CBC (for XML
// Encryption's ISO 10126 padding, which a PKCS#7 unpad refuses), and DER <->
// raw ECDSA signature conversion.
//
// SYNCHRONOUS WHERE THE PRIMITIVE IS. Every function returns its result
// directly. A webcrypto backend, when one exists, will be the async one.
//
// BACKENDS. `js` is the only backend in step 1 and is always present.
// `webcrypto` is reserved: a later step may add it as an OPTIONAL second
// backend, chosen per call or per page, and it must then produce output
// byte-identical to `js` wherever the operation is deterministic (ECDSA is the
// trap: the `js` backend signs RFC 6979 deterministically, Web Crypto signs
// with fresh randomness, so for ECDSA "identical" can only mean "each
// verifies the other's"). THIS FILE NEVER TOUCHES WEB CRYPTO — the test
// asserts its text does not even name it — so it works outside a secure
// context, which is the point of the whole issue.
//
// NO DOM. Bytes in, bytes out.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var forge = require("node-forge");
var nobleHmac = require("@noble/hashes/hmac").hmac;
var nobleHkdf = require("@noble/hashes/hkdf").hkdf;
var noblePbkdf2 = require("@noble/hashes/pbkdf2").pbkdf2;
var bytes = require("./crypto_bytes");
var hashTools = require("./hash_tools");
var symmetric = require("./symmetric_crypto");
var pkEncryption = require("./pk_encryption");
var pqc = require("./pqc");
var hbs = require("./hbs");
var keys = require("./crypto_keys");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "crypto_provider",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// crypto_bytes.asBytes() turns a STRING into an empty array (new
// Uint8Array("abc") has length 0), which would make digest("sha256", "abc")
// the hash of nothing and an HMAC over any text verify against any other. At
// this API a string is UTF-8 text, everywhere.
function asBytes(input) {
  log.debug("Entering asBytes().");
  if (typeof input === "string") {
    log.debug("Leaving asBytes(). UTF-8 text.");
    return bytes.strBytes(input);
  }
  log.debug("Leaving asBytes().");
  return bytes.asBytes(input);
}

var concatBytes = bytes.concatBytes;

// ===========================================================================
// BACKENDS
// ===========================================================================
var BACKENDS = ["js", "webcrypto"];
var currentBackend = "js";

function backend() {
  log.debug("Entering backend().");
  log.debug("Leaving backend().");
  return currentBackend;
}

// Refuses "webcrypto" in step 1 rather than accepting it and quietly running
// `js` anyway: a backend switch that switches nothing would make every
// "both backends agree" check pass vacuously.
function setBackend(name) {
  log.debug("Entering setBackend(). name=" + name);
  if (BACKENDS.indexOf(name) < 0) {
    log.debug("Leaving setBackend(). Unknown.");
    throw new Error("Unknown crypto backend: " + name + " (one of " +
                    BACKENDS.join(", ") + ").");
  }
  if (name !== "js") {
    log.debug("Leaving setBackend(). Not implemented.");
    throw new Error("The " + name + " backend has no implementations yet " +
                    "(issue #463 adds it after the format layers move); " +
                    "every operation runs on js.");
  }
  currentBackend = name;
  log.debug("Leaving setBackend().");
  return currentBackend;
}

// Whether a Web Crypto backend COULD run here. It reads the interface object
// rather than the property on `crypto`: SubtleCrypto is [SecureContext], so a
// browser does not expose the interface at all on an insecure origin, and
// testing for it touches no Web Crypto method.
function webcryptoAvailable() {
  log.debug("Entering webcryptoAvailable().");
  var g = typeof globalThis !== "undefined" ? globalThis : {};
  var yes = typeof g.SubtleCrypto === "function" &&
            g.isSecureContext !== false;
  log.debug("Leaving webcryptoAvailable(). " + yes);
  return yes;
}

// ===========================================================================
// THE CANONICAL ALGORITHM TABLE
// ===========================================================================
// One row per primitive. `kind` is digest | mac | kdf | signature |
// key-agreement | cipher | key-wrap | asym-encryption | kem. `keyType` is the
// key `type` an operation needs (null for keyless ones). `deterministic` says
// whether the same inputs always give the same output on the js backend —
// what decides whether a second backend can be held to identical bytes.
var ALGORITHMS = {};

function addAlgorithm(id, row) {
  log.debug("Entering addAlgorithm(). id=" + id);
  row.id = id;
  ALGORITHMS[id] = row;
  log.debug("Leaving addAlgorithm().");
}

var SIGNERS = {
  "ecdsa-p256-sha256": { family: "ecdsa", curve: "P-256", hash: "sha256" },
  "ecdsa-p384-sha384": { family: "ecdsa", curve: "P-384", hash: "sha384" },
  "ecdsa-p521-sha512": { family: "ecdsa", curve: "P-521", hash: "sha512" },
  "ecdsa-secp256k1-sha256": { family: "ecdsa", curve: "secp256k1",
                              hash: "sha256" },
  "rsa-pkcs1-sha1": { family: "rsa-pkcs1", hash: "sha1", legacy: true },
  "rsa-pkcs1-sha256": { family: "rsa-pkcs1", hash: "sha256" },
  "rsa-pkcs1-sha384": { family: "rsa-pkcs1", hash: "sha384" },
  "rsa-pkcs1-sha512": { family: "rsa-pkcs1", hash: "sha512" },
  "rsa-pss-sha256": { family: "rsa-pss", hash: "sha256" },
  "rsa-pss-sha384": { family: "rsa-pss", hash: "sha384" },
  "rsa-pss-sha512": { family: "rsa-pss", hash: "sha512" },
  "ed25519": { family: "eddsa", curve: "Ed25519" },
  "ed448": { family: "eddsa", curve: "Ed448" }
};

(function buildAlgorithms() {
  var hashes = Object.keys(keys.HASH_NAMES);
  for (var h = 0; h < hashes.length; h++) {
    addAlgorithm(hashes[h], { kind: "digest", family: "hash", keyType: null,
                              deterministic: true,
                              engine: "hash_tools.js",
                              engineId: keys.HASH_NAMES[hashes[h]] });
    addAlgorithm("hmac-" + hashes[h], { kind: "mac", family: "hmac",
                                        keyType: "oct", hash: hashes[h],
                                        deterministic: true });
  }
  addAlgorithm("kmac128", { kind: "mac", family: "kmac", keyType: "oct",
                            deterministic: true, engine: "hash_tools.js" });
  addAlgorithm("kmac256", { kind: "mac", family: "kmac", keyType: "oct",
                            deterministic: true, engine: "hash_tools.js" });
  addAlgorithm("hkdf", { kind: "kdf", family: "hkdf", keyType: null,
                         deterministic: true });
  addAlgorithm("pbkdf2", { kind: "kdf", family: "pbkdf2", keyType: null,
                           deterministic: true });
  addAlgorithm("concat-kdf", { kind: "kdf", family: "concat-kdf",
                               keyType: null, deterministic: true });

  var signers = Object.keys(SIGNERS);
  for (var i = 0; i < signers.length; i++) {
    var s = SIGNERS[signers[i]];
    addAlgorithm(signers[i], {
      kind: "signature", family: s.family,
      keyType: s.family === "ecdsa" ? "ec"
             : s.family === "eddsa" ? "okp" : "rsa",
      curve: s.curve || null, hash: s.hash || null,
      // RFC 6979 makes the js backend's ECDSA deterministic; PSS salts.
      deterministic: s.family !== "rsa-pss"
    });
  }
  var pq = Object.keys(pqc.SIGNATURE_ALGS);
  for (var j = 0; j < pq.length; j++) {
    addAlgorithm(pq[j], { kind: "signature",
                          family: pqc.SIGNATURE_ALGS[pq[j]].family ||
                                  "composite",
                          keyType: "akp", deterministic: false,
                          engine: "pqc.js" });
  }
  // An LMS signature's per-message randomizer C is fresh; XMSS's r is a PRF
  // of the index, so XMSS is deterministic GIVEN THE STATE — and the state is
  // the private key, which changes on every call.
  addAlgorithm("HSS-LMS", { kind: "signature", family: "hbs", keyType: "hbs",
                            deterministic: false, stateful: true,
                            engine: "hbs.js" });
  addAlgorithm("XMSS", { kind: "signature", family: "hbs", keyType: "hbs",
                         deterministic: true, stateful: true,
                         engine: "hbs.js" });
  addAlgorithm("XMSSMT", { kind: "signature", family: "hbs", keyType: "hbs",
                           deterministic: true, stateful: true,
                           engine: "hbs.js" });

  var curves = ["P-256", "P-384", "P-521", "secp256k1"];
  for (var c = 0; c < curves.length; c++) {
    addAlgorithm("ecdh-" + curves[c].toLowerCase(),
                 { kind: "key-agreement", family: "ecdh", keyType: "ec",
                   curve: curves[c], deterministic: true });
  }
  addAlgorithm("x25519", { kind: "key-agreement", family: "ecdh",
                           keyType: "okp", curve: "X25519",
                           deterministic: true });
  addAlgorithm("x448", { kind: "key-agreement", family: "ecdh",
                         keyType: "okp", curve: "X448", deterministic: true });

  addAlgorithm("aes-gcm", { kind: "cipher", family: "aes", keyType: "oct",
                            keyBytes: [16, 24, 32], ivBytes: 12,
                            deterministic: true,
                            engine: "symmetric_crypto.js" });
  addAlgorithm("aes-cbc", { kind: "cipher", family: "aes", keyType: "oct",
                            keyBytes: [16, 24, 32], ivBytes: 16,
                            deterministic: true,
                            engine: "symmetric_crypto.js" });
  addAlgorithm("chacha20-poly1305", { kind: "cipher", family: "chacha",
                                      keyType: "oct", keyBytes: [32],
                                      ivBytes: 12, deterministic: true,
                                      engine: "symmetric_crypto.js" });
  addAlgorithm("aes-kw", { kind: "key-wrap", family: "aes", keyType: "oct",
                           keyBytes: [16, 24, 32], deterministic: true });
  addAlgorithm("rsa-oaep-sha1", { kind: "asym-encryption", family: "rsa",
                                  keyType: "rsa", hash: "sha1",
                                  deterministic: false,
                                  engine: "pk_encryption.js" });
  addAlgorithm("rsa-oaep-sha256", { kind: "asym-encryption", family: "rsa",
                                    keyType: "rsa", hash: "sha256",
                                    deterministic: false,
                                    engine: "pk_encryption.js" });
  addAlgorithm("rsa-pkcs1v15-enc", { kind: "asym-encryption", family: "rsa",
                                     keyType: "rsa", legacy: true,
                                     deterministic: false,
                                     engine: "pk_encryption.js" });
  var kems = Object.keys(pqc.KEM_ALGS);
  for (var k = 0; k < kems.length; k++) {
    addAlgorithm(kems[k], { kind: "kem", family: "kem", keyType: "kem",
                            deterministic: false, engine: "pqc.js" });
  }
})();

function algorithmInfo(id) {
  log.debug("Entering algorithmInfo(). id=" + id);
  var row = ALGORITHMS[id];
  if (!row) {
    log.debug("Leaving algorithmInfo(). Unknown.");
    throw new Error("Unknown algorithm: " + id);
  }
  log.debug("Leaving algorithmInfo().");
  return row;
}

// ===========================================================================
// DIGEST / MAC / KDF
// ===========================================================================
function digest(alg, data) {
  log.debug("Entering digest(). alg=" + alg);
  var out = hashTools.digest(keys.hashName(alg), asBytes(data));
  log.debug("Leaving digest().");
  return out;
}

// The @noble CHash for a provider hash name — hash_tools.js's own function,
// so HMAC, HKDF and PBKDF2 run over exactly the digest `digest()` computes.
function chash(alg) {
  log.debug("Entering chash(). alg=" + alg);
  var row = hashTools.algorithm(keys.hashName(alg));
  if (!row || !row.hash) {
    log.debug("Leaving chash(). Not a fixed-output hash.");
    throw new Error(alg + " is not a fixed-output hash.");
  }
  log.debug("Leaving chash().");
  return row.hash;
}

// A secret given as bytes, a string (UTF-8) or an oct key.
function secretBytes(key) {
  log.debug("Entering secretBytes().");
  if (key && key.type === "oct") {
    log.debug("Leaving secretBytes(). oct key.");
    return key.privateKey;
  }
  if (typeof key === "string") {
    log.debug("Leaving secretBytes(). String.");
    return bytes.strBytes(key);
  }
  log.debug("Leaving secretBytes().");
  return asBytes(key);
}

function hmac(alg, key, data) {
  log.debug("Entering hmac(). alg=" + alg);
  var name = String(alg).replace(/^hmac-/, "");
  var out = nobleHmac(chash(name), secretBytes(key), asBytes(data));
  log.debug("Leaving hmac().");
  return out;
}

// HMAC verification in constant time over the tag's length.
function hmacVerify(alg, key, data, tag) {
  log.debug("Entering hmacVerify(). alg=" + alg);
  var ok = bytes.bytesEqual(hmac(alg, key, data), asBytes(tag));
  log.debug("Leaving hmacVerify().");
  return ok;
}

// SP 800-185 KMAC. variant: "kmac128" | "kmac256" (or the XOF forms
// hash_tools.js names). opts: { customization, outputBits }.
function kmac(variant, key, data, opts) {
  log.debug("Entering kmac(). variant=" + variant);
  var o = opts || {};
  var id = String(variant).toUpperCase();
  var out = hashTools.derive(id, {
    key: secretBytes(key), message: asBytes(data),
    customization: o.customization || "",
    outputBits: o.outputBits || (/256/.test(id) ? 512 : 256)
  });
  log.debug("Leaving kmac().");
  return out;
}

// RFC 5869. `length` in bytes. An absent salt is HashLen zero octets, which
// is what @noble does with an undefined one.
function hkdf(hash, ikm, salt, info, length) {
  log.debug("Entering hkdf(). hash=" + hash + " length=" + length);
  var out = nobleHkdf(chash(hash), secretBytes(ikm),
                      salt === undefined || salt === null ? undefined
                                                         : asBytes(salt),
                      info === undefined || info === null ? undefined
                                                         : asBytes(info),
                      length);
  log.debug("Leaving hkdf().");
  return out;
}

// RFC 8018 PBKDF2-HMAC. `length` in bytes.
function pbkdf2(hash, password, salt, iterations, length) {
  log.debug("Entering pbkdf2(). hash=" + hash + " c=" + iterations);
  var out = noblePbkdf2(chash(hash), secretBytes(password), asBytes(salt),
                        { c: iterations, dkLen: length });
  log.debug("Leaving pbkdf2().");
  return out;
}

// NIST SP 800-56A rev. 3 section 5.8.2.1.1, the one-step "Concat KDF" with a
// hash: K = H(1 || Z || OtherInfo) || H(2 || Z || OtherInfo) || ..., the
// counter a 32-bit big-endian integer, truncated to `length` BYTES. OtherInfo
// is the caller's: JOSE ECDH-ES (RFC 7518 section 4.6.2) builds AlgorithmID ||
// PartyUInfo || PartyVInfo || SuppPubInfo, and that composition belongs in
// the JOSE layer, not here.
function concatKdf(hash, z, length, otherInfo) {
  log.debug("Entering concatKdf(). hash=" + hash + " length=" + length);
  var secret = asBytes(z);
  var other = asBytes(otherInfo || new Uint8Array(0));
  var out = new Uint8Array(0);
  for (var counter = 1; out.length < length; counter++) {
    out = concatBytes(out, digest(hash, concatBytes(bytes.uint32be(counter),
                                  concatBytes(secret, other))));
  }
  log.debug("Leaving concatKdf().");
  return out.slice(0, length);
}

// ===========================================================================
// ECDSA SIGNATURE ENCODINGS
// ===========================================================================
// Written here rather than taken from @noble because @noble/curves 1.4.0's
// DER writer (DER.hexFromSig) only emits SHORT-FORM lengths, so a P-521
// signature — whose SEQUENCE is up to 139 bytes — comes out as invalid DER.
// PR #388 upgrades @noble; this does not depend on it either way.

// raw r || s (each half the same length) -> DER Ecdsa-Sig-Value.
function rawToDerEcdsa(raw) {
  log.debug("Entering rawToDerEcdsa().");
  var sig = asBytes(raw);
  if (sig.length === 0 || sig.length % 2) {
    log.debug("Leaving rawToDerEcdsa(). Odd length.");
    throw new Error("A raw ECDSA signature is r || s of equal halves; this " +
                    "one is " + sig.length + " bytes.");
  }
  var half = sig.length / 2;
  log.debug("Leaving rawToDerEcdsa().");
  return keys.derSequence([keys.derUnsignedInteger(sig.slice(0, half)),
                           keys.derUnsignedInteger(sig.slice(half))]);
}

// DER Ecdsa-Sig-Value -> raw r || s, each padded to `size` bytes (the curve's
// field size: 32, 48, 66). Refuses trailing bytes and negative integers.
function derToRawEcdsa(der, size) {
  log.debug("Entering derToRawEcdsa(). size=" + size);
  var input = asBytes(der);
  var seq = keys.derExpect(keys.derRead(input, 0), 0x30, "Ecdsa-Sig-Value");
  if (seq.end !== input.length) {
    log.debug("Leaving derToRawEcdsa(). Trailing bytes.");
    throw new Error("DER ECDSA signature has trailing bytes.");
  }
  var parts = keys.derChildren(seq.value);
  if (parts.length !== 2) {
    log.debug("Leaving derToRawEcdsa(). Not two integers.");
    throw new Error("DER ECDSA signature must hold exactly r and s.");
  }
  var r = keys.derExpect(parts[0], 0x02, "r").value;
  var s = keys.derExpect(parts[1], 0x02, "s").value;
  if ((r[0] & 0x80) || (s[0] & 0x80)) {
    log.debug("Leaving derToRawEcdsa(). Negative.");
    throw new Error("DER ECDSA signature has a negative integer.");
  }
  log.debug("Leaving derToRawEcdsa().");
  return concatBytes(keys.padTo(r, size, "r"), keys.padTo(s, size, "s"));
}

// ===========================================================================
// SIGNATURES
// ===========================================================================
function signerFor(alg) {
  log.debug("Entering signerFor(). alg=" + alg);
  var s = SIGNERS[alg];
  if (s) {
    log.debug("Leaving signerFor(). Classical.");
    return s;
  }
  if (pqc.SIGNATURE_ALGS[alg]) {
    log.debug("Leaving signerFor(). Post-quantum.");
    return { family: "pqc", name: alg };
  }
  if (keys.HBS_ALGS.indexOf(alg) >= 0) {
    log.debug("Leaving signerFor(). Hash-based.");
    return { family: "hbs", name: alg };
  }
  log.debug("Leaving signerFor(). Unknown.");
  throw new Error("Unknown signature algorithm: " + alg);
}

function requireKey(key, signer, alg, wantPrivate) {
  log.debug("Entering requireKey(). alg=" + alg);
  var wantType = { ecdsa: "ec", eddsa: "okp", "rsa-pkcs1": "rsa",
                   "rsa-pss": "rsa", pqc: "akp", hbs: "hbs" }[signer.family];
  if (!key || key.type !== wantType) {
    log.debug("Leaving requireKey(). Wrong type.");
    throw new Error(alg + " needs a " + wantType + " key; this one is " +
                    (key && key.type) + ".");
  }
  if (signer.curve && key.curve !== signer.curve) {
    log.debug("Leaving requireKey(). Wrong curve.");
    throw new Error(alg + " needs a " + signer.curve + " key; this one is " +
                    key.curve + ".");
  }
  if (signer.name && key.alg !== signer.name) {
    log.debug("Leaving requireKey(). Wrong algorithm.");
    throw new Error(alg + " needs a " + signer.name + " key; this one is " +
                    key.alg + ".");
  }
  if (wantPrivate && !key.privateKey) {
    log.debug("Leaving requireKey(). Public key.");
    throw new Error("That is a PUBLIC key — nothing can be signed with it (" +
                    alg + ").");
  }
  log.debug("Leaving requireKey().");
}

function forgeMd(hash) {
  log.debug("Entering forgeMd(). hash=" + hash);
  var factory = forge.md[hash];
  if (!factory) {
    log.debug("Leaving forgeMd(). Unknown.");
    throw new Error("No RSA signature hash " + hash + ".");
  }
  log.debug("Leaving forgeMd().");
  return factory.create();
}

// RFC 8017 section 9.1 with MGF1 over the SAME hash and a salt of the hash's
// length — what RFC 7518 section 3.5 fixes for PS256/384/512, and what
// XML DSig's RSA-PSS URIs and COSE's PS* default to.
function pssParams(hash) {
  log.debug("Entering pssParams(). hash=" + hash);
  var md = forgeMd(hash);
  log.debug("Leaving pssParams().");
  return forge.pss.create({ md: md, mgf: forge.mgf.mgf1.create(forgeMd(hash)),
                            saltLength: md.digestLength });
}

// ---------------------------------------------------------------------------
// RSA PRIVATE-KEY SIGNING ON OPENSSL WHERE THERE IS ONE (#463 step 3, keeping
// issue #302). forge's RSA private-key operation is JavaScript: its blinding
// comes from forge.random and its modPow has no side-channel hardening. Under
// node (the api signing SAML and JOSE, and the tests) the same octets are
// signed by node's crypto instead. In a browser nothing changes: this is
// never reached, and every RSA signature is forge's, as before.
//
// NO ALGORITHM IS LOST (rcbj, 2026-11-18). This is used only for RSA
// PKCS#1 v1.5 and PSS signing, and ONLY when node's crypto does that exact
// hash. Anything it cannot do, or any error it raises, falls through to the
// forge path, which handles every algorithm it handled before. PKCS#1 v1.5
// is deterministic, so both paths give the same bytes (tests assert it);
// PSS uses MGF1 over the message hash and a hash-length salt on both.
//
// THE MODULE NAME IS HELD IN A VARIABLE because this file is browserified:
// a literal require of the crypto module would pull crypto-browserify (and
// elliptic) into every bundle, which tests/jwk_pem_encoding.js refuses. The
// call is made only when `process.versions.node` says this is node.
// opts.forceJs skips it, for the test that compares the two.
// ---------------------------------------------------------------------------
var NODE_CRYPTO_MODULE = "crypto";
var nodeCryptoCache;
function nodeCrypto() {
  log.debug("Entering nodeCrypto().");
  if (nodeCryptoCache !== undefined) {
    log.debug("Leaving nodeCrypto(). Cached.");
    return nodeCryptoCache;
  }
  nodeCryptoCache = null;
  if (typeof process === "undefined" || !process.versions ||
      !process.versions.node || typeof require !== "function") {
    log.debug("Leaving nodeCrypto(). Not node.");
    return null;
  }
  try {
    var c = require(NODE_CRYPTO_MODULE);
    if (c && typeof c.sign === "function" &&
        typeof c.createPrivateKey === "function" &&
        typeof c.getHashes === "function") {
      nodeCryptoCache = c;
    }
  } catch (e) {
    log.debug("nodeCrypto(): no crypto module: " + e.message);
  }
  log.debug("Leaving nodeCrypto().");
  return nodeCryptoCache;
}

// The signature by node's crypto, or null when it does not do this one (the
// caller then uses forge).
function nodeRsaSign(signer, key, msg) {
  log.debug("Entering nodeRsaSign(). hash=" + signer.hash);
  var c = nodeCrypto();
  if (!c || c.getHashes().indexOf(signer.hash) === -1) {
    log.debug("Leaving nodeRsaSign(). Not available.");
    return null;
  }
  try {
    var k = c.createPrivateKey({ key: keys.exportKey(key, "pkcs8-pem"),
                                 format: "pem" });
    var params = { key: k };
    if (signer.family === "rsa-pss") {
      params.padding = c.constants.RSA_PKCS1_PSS_PADDING;
      params.saltLength = forgeMd(signer.hash).digestLength;
    } else {
      params.padding = c.constants.RSA_PKCS1_PADDING;
    }
    var sig = new Uint8Array(c.sign(signer.hash, msg, params));
    log.debug("Leaving nodeRsaSign(). OpenSSL.");
    return sig;
  } catch (e) {
    log.debug("Leaving nodeRsaSign(). Falling back: " + e.message);
    return null;
  }
}

// Which path an RSA signature takes here: "node" or "forge". For tests.
function rsaSignBackend() {
  log.debug("Entering rsaSignBackend().");
  log.debug("Leaving rsaSignBackend().");
  return nodeCrypto() ? "node" : "forge";
}

// sign(alg, key, data, opts) -> signature bytes.
//
//   ECDSA: opts.encoding "raw" (r || s, the default — JOSE and COSE) or
//          "der" (XML DSig's ECDSA URIs say raw too; X.509 and CMS use DER).
//          Deterministic RFC 6979 nonces, low-S on secp256k1 and not on the
//          NIST curves — exactly what jws.js's js backend emits today.
//   HSS-LMS / XMSS / XMSSMT: THE KEY IS MUTATED. key.privateKey is replaced
//          by the advanced state hbs.js returns, and the caller MUST persist
//          it before using the signature; signing again from a stale copy
//          reuses a one-time key. opts passes through to hbs.js.
//   post-quantum (pqc.js names): opts passes through (context, etc.).
function sign(alg, key, data, opts) {
  log.debug("Entering sign(). alg=" + alg);
  var o = opts || {};
  var signer = signerFor(alg);
  requireKey(key, signer, alg, true);
  var msg = asBytes(data);
  if (signer.family === "ecdsa") {
    var c = keys.ecCurve(signer.curve);
    var sig = c.noble.sign(digest(signer.hash, msg), key.privateKey);
    var raw = concatBytes(bytes.bigToBytes(sig.r, c.size),
                          bytes.bigToBytes(sig.s, c.size));
    log.debug("Leaving sign(). ECDSA.");
    return o.encoding === "der" ? rawToDerEcdsa(raw) : raw;
  }
  if (signer.family === "eddsa") {
    log.debug("Leaving sign(). EdDSA.");
    return asBytes(keys.okpCurve(signer.curve).noble
      .sign(msg, key.privateKey));
  }
  if (signer.family === "rsa-pkcs1" || signer.family === "rsa-pss") {
    var viaNode = o.forceJs ? null : nodeRsaSign(signer, key, msg);
    if (viaNode) {
      log.debug("Leaving sign(). RSA, OpenSSL.");
      return viaNode;
    }
    var priv = keys.toForgeRsa(key, true);
    var md = forgeMd(signer.hash);
    md.update(forge.util.binary.raw.encode(msg));
    var out = signer.family === "rsa-pss"
      ? priv.sign(md, pssParams(signer.hash))
      : priv.sign(md);
    log.debug("Leaving sign(). RSA.");
    return forge.util.binary.raw.decode(out);
  }
  if (signer.family === "pqc") {
    log.debug("Leaving sign(). Post-quantum.");
    return pqc.signWithPriv(alg, msg, key.privateKey,
                            o.context ? o : undefined);
  }
  var result = alg === "HSS-LMS" ? hbs.hssSign(key.privateKey, msg, o)
                                 : hbs.xmssSign(key.privateKey, msg, o);
  key.privateKey = result.privateKey;
  log.debug("Leaving sign(). Hash-based; private key advanced.");
  return result.signature;
}

// verify(alg, key, data, signature, opts) -> boolean. NEVER throws on a bad
// signature: a malformed, wrong-length or out-of-range signature is `false`,
// because a verifier that throws makes a forgery look like a bug in the
// tool. It does throw on a key of the wrong type, which is the caller's bug.
//
// ECDSA: opts.encoding as for sign(). HIGH-S IS ACCEPTED on every curve,
// secp256k1 included — @noble refuses it there by default (a Bitcoin
// malleability rule) and no JOSE, COSE or XML specification has that rule,
// so OpenSSL's perfectly valid high-S signatures would read as forgeries.
function verify(alg, key, data, signature, opts) {
  log.debug("Entering verify(). alg=" + alg);
  var o = opts || {};
  var signer = signerFor(alg);
  requireKey(key, signer, alg, false);
  var msg = asBytes(data);
  var sigBytes = asBytes(signature);
  var ok = false;
  try {
    ok = verifyInner(alg, signer, key, msg, sigBytes, o);
  } catch (e) {
    log.debug("verify(): malformed input: " + e.message);
    ok = false;
  }
  log.debug("Leaving verify(). " + ok);
  return ok;
}

function verifyInner(alg, signer, key, msg, sigBytes, o) {
  log.debug("Entering verifyInner(). family=" + signer.family);
  if (signer.family === "ecdsa") {
    var c = keys.ecCurve(signer.curve);
    var raw = o.encoding === "der" ? derToRawEcdsa(sigBytes, c.size)
                                   : sigBytes;
    if (raw.length !== 2 * c.size) {
      log.debug("Leaving verifyInner(). Wrong length.");
      return false;
    }
    // An {r, s} object rather than bytes: handed bytes, @noble 1.4.0 tries
    // DER FIRST and only then compact, so a raw r || s that happens to parse
    // as DER would be read as something else.
    var rs = { r: bytes.bytesToBig(raw.slice(0, c.size)),
               s: bytes.bytesToBig(raw.slice(c.size)) };
    var good = c.noble.verify(rs, digest(signer.hash, msg), key.publicKey,
                              { lowS: false });
    log.debug("Leaving verifyInner(). ECDSA.");
    return good;
  }
  if (signer.family === "eddsa") {
    log.debug("Leaving verifyInner(). EdDSA.");
    return keys.okpCurve(signer.curve).noble.verify(sigBytes, msg,
                                                    key.publicKey);
  }
  if (signer.family === "rsa-pkcs1" || signer.family === "rsa-pss") {
    var pub = keys.toForgeRsa(key, false);
    if (sigBytes.length !== Math.ceil(key.bits / 8)) {
      log.debug("Leaving verifyInner(). Wrong RSA length.");
      return false;
    }
    var md = forgeMd(signer.hash);
    md.update(forge.util.binary.raw.encode(msg));
    var sigRaw = forge.util.binary.raw.encode(sigBytes);
    var rsaOk = signer.family === "rsa-pss"
      ? pub.verify(md.digest().getBytes(), sigRaw, pssParams(signer.hash))
      : pub.verify(md.digest().getBytes(), sigRaw);
    log.debug("Leaving verifyInner(). RSA.");
    return rsaOk;
  }
  if (signer.family === "pqc") {
    log.debug("Leaving verifyInner(). Post-quantum.");
    return pqc.verifyWithPub(alg, sigBytes, msg, key.publicKey,
                             o.context ? o : undefined);
  }
  var verdict = alg === "HSS-LMS"
    ? hbs.hssVerify(key.publicKey, msg, sigBytes)
    : hbs.xmssVerify(key.publicKey, msg, sigBytes, alg === "XMSSMT");
  log.debug("Leaving verifyInner(). Hash-based.");
  return !!verdict.valid;
}

// ===========================================================================
// KEY AGREEMENT
// ===========================================================================
// ECDH on P-256/384/521/secp256k1 returns the x-coordinate of the shared
// point, field-size padded (SEC 1 section 3.3.1, and what JOSE ECDH-ES and
// node's diffieHellman() call Z). X25519/X448 return the RFC 7748 output.
// An all-zero X25519/X448 result (a small-order peer key) is REFUSED, as RFC
// 7748 section 6.1 permits and RFC 9180 / JOSE require.
function ecdh(privateKey, publicKey) {
  log.debug("Entering ecdh().");
  if (!privateKey || !privateKey.privateKey) {
    log.debug("Leaving ecdh(). No private key.");
    throw new Error("ECDH needs a private key on our side.");
  }
  if (!publicKey || publicKey.type !== privateKey.type ||
      publicKey.curve !== privateKey.curve) {
    log.debug("Leaving ecdh(). Mismatched keys.");
    throw new Error("ECDH needs both keys on the same curve (" +
                    privateKey.curve + " vs " +
                    (publicKey && publicKey.curve) + ").");
  }
  if (privateKey.type === "ec") {
    var c = keys.ecCurve(privateKey.curve);
    var point = asBytes(c.noble.getSharedSecret(privateKey.privateKey,
                                                publicKey.publicKey, true));
    log.debug("Leaving ecdh(). EC.");
    return point.slice(1);
  }
  var o = keys.okpCurve(privateKey.curve);
  if (privateKey.type !== "okp" || o.sign) {
    log.debug("Leaving ecdh(). Not an agreement key.");
    throw new Error(privateKey.curve + " is a signature curve; key " +
                    "agreement is X25519 or X448.");
  }
  var z = asBytes(o.noble.getSharedSecret(privateKey.privateKey,
                                          publicKey.publicKey));
  var any = 0;
  for (var i = 0; i < z.length; i++) {
    any |= z[i];
  }
  if (!any) {
    log.debug("Leaving ecdh(). All-zero output.");
    throw new Error(privateKey.curve + " produced the all-zero value: the " +
                    "peer's public key is of small order.");
  }
  log.debug("Leaving ecdh(). Montgomery.");
  return z;
}

// ===========================================================================
// SYMMETRIC
// ===========================================================================
function aesId(mode, key) {
  log.debug("Entering aesId(). mode=" + mode);
  var len = asBytes(key).length;
  if ([16, 24, 32].indexOf(len) < 0) {
    log.debug("Leaving aesId(). Bad key length.");
    throw new Error("AES keys are 16, 24 or 32 bytes; this one is " + len +
                    ".");
  }
  log.debug("Leaving aesId().");
  return "AES-" + (len * 8) + "-" + mode;
}

// AES-GCM with a 128-bit tag, kept SEPARATE from the ciphertext (JWE carries
// it in its own segment; XML Encryption and COSE append it — the format
// layer concatenates).
function aesGcmEncrypt(key, iv, plaintext, aad) {
  log.debug("Entering aesGcmEncrypt().");
  var k = secretBytes(key);
  var out = symmetric.encrypt({ id: aesId("GCM", k), key: k, iv: iv,
                                plaintext: plaintext, aad: aad });
  log.debug("Leaving aesGcmEncrypt().");
  return { ciphertext: out.ciphertext, tag: out.tag };
}

// Throws on an authentication failure.
function aesGcmDecrypt(key, iv, ciphertext, tag, aad) {
  log.debug("Entering aesGcmDecrypt().");
  var k = secretBytes(key);
  var out = symmetric.decrypt({ id: aesId("GCM", k), key: k, iv: iv,
                                ciphertext: ciphertext, tag: tag, aad: aad });
  log.debug("Leaving aesGcmDecrypt().");
  return out;
}

// padding: "pkcs7" (default; symmetric_crypto.js) or "none" (whole blocks
// only, no padding added or removed — XML Encryption's ISO 10126 padding is
// random bytes that a PKCS#7 unpad would refuse, so that layer strips it
// itself). The "none" path is CBC chaining over symmetric_crypto.js's raw
// AES block.
function aesCbcEncrypt(key, iv, plaintext, opts) {
  log.debug("Entering aesCbcEncrypt().");
  var k = secretBytes(key);
  var padding = (opts && opts.padding) || "pkcs7";
  if (padding === "pkcs7") {
    var out = symmetric.encrypt({ id: aesId("CBC", k), key: k, iv: iv,
                                  plaintext: plaintext });
    log.debug("Leaving aesCbcEncrypt(). PKCS#7.");
    return out.ciphertext;
  }
  var pt = asBytes(plaintext);
  checkCbcRaw(k, iv, pt);
  var prev = asBytes(iv);
  var ct = new Uint8Array(pt.length);
  for (var i = 0; i < pt.length; i += 16) {
    prev = symmetric.aesBlock(k, bytes.xorBytes(pt.slice(i, i + 16), prev));
    ct.set(prev, i);
  }
  log.debug("Leaving aesCbcEncrypt(). Unpadded.");
  return ct;
}

function aesCbcDecrypt(key, iv, ciphertext, opts) {
  log.debug("Entering aesCbcDecrypt().");
  var k = secretBytes(key);
  var padding = (opts && opts.padding) || "pkcs7";
  if (padding === "pkcs7") {
    var out = symmetric.decrypt({ id: aesId("CBC", k), key: k, iv: iv,
                                  ciphertext: ciphertext });
    log.debug("Leaving aesCbcDecrypt(). PKCS#7.");
    return out;
  }
  var ct = asBytes(ciphertext);
  checkCbcRaw(k, iv, ct);
  var prev = asBytes(iv);
  var pt = new Uint8Array(ct.length);
  for (var i = 0; i < ct.length; i += 16) {
    var block = ct.slice(i, i + 16);
    pt.set(bytes.xorBytes(symmetric.aesBlockDecrypt(k, block), prev), i);
    prev = block;
  }
  log.debug("Leaving aesCbcDecrypt(). Unpadded.");
  return pt;
}

function checkCbcRaw(key, iv, data) {
  log.debug("Entering checkCbcRaw().");
  aesId("CBC", key);
  if (asBytes(iv).length !== 16) {
    log.debug("Leaving checkCbcRaw(). Bad IV.");
    throw new Error("AES-CBC needs a 16-byte IV.");
  }
  if (data.length % 16) {
    log.debug("Leaving checkCbcRaw(). Partial block.");
    throw new Error("Unpadded AES-CBC needs whole 16-byte blocks; this is " +
                    data.length + " bytes.");
  }
  log.debug("Leaving checkCbcRaw().");
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
  log.debug("Entering chacha20Poly1305Encrypt().");
  var out = symmetric.encrypt({ id: "CHACHA20-POLY1305",
                                key: secretBytes(key), iv: nonce,
                                plaintext: plaintext, aad: aad });
  log.debug("Leaving chacha20Poly1305Encrypt().");
  return { ciphertext: out.ciphertext, tag: out.tag };
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
  log.debug("Entering chacha20Poly1305Decrypt().");
  var out = symmetric.decrypt({ id: "CHACHA20-POLY1305",
                                key: secretBytes(key), iv: nonce,
                                ciphertext: ciphertext, tag: tag, aad: aad });
  log.debug("Leaving chacha20Poly1305Decrypt().");
  return out;
}

// RFC 3394 AES Key Wrap with the default IV A6A6A6A6A6A6A6A6 — JWE's
// A128KW/A192KW/A256KW, XML Encryption's kw-aes*, COSE's A*KW. Section 2.2.1
// (index-based), over symmetric_crypto.js's raw AES block.
var KW_IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

function kwXorCounter(a, t) {
  log.debug("Entering kwXorCounter().");
  var out = a.slice();
  var tt = t;
  for (var i = 7; i >= 0 && tt > 0; i--) {
    out[i] ^= tt & 0xff;
    tt = Math.floor(tt / 256);
  }
  log.debug("Leaving kwXorCounter().");
  return out;
}

function aesKwWrap(kek, keyData) {
  log.debug("Entering aesKwWrap().");
  var k = secretBytes(kek);
  aesId("KW", k);
  var p = asBytes(keyData);
  if (p.length < 16 || p.length % 8) {
    log.debug("Leaving aesKwWrap(). Bad length.");
    throw new Error("AES Key Wrap takes a multiple of 8 bytes, at least 16; " +
                    "this is " + p.length + ".");
  }
  var n = p.length / 8;
  var a = KW_IV.slice();
  var r = [];
  for (var i = 0; i < n; i++) {
    r.push(p.slice(8 * i, 8 * i + 8));
  }
  for (var j = 0; j <= 5; j++) {
    for (var m = 0; m < n; m++) {
      var b = symmetric.aesBlock(k, concatBytes(a, r[m]));
      a = kwXorCounter(b.slice(0, 8), n * j + m + 1);
      r[m] = b.slice(8, 16);
    }
  }
  var out = a;
  for (var q = 0; q < n; q++) {
    out = concatBytes(out, r[q]);
  }
  log.debug("Leaving aesKwWrap().");
  return out;
}

// Throws when the integrity check fails — i.e. a wrong KEK or a modified
// wrapped key — and compares the IV in constant time.
function aesKwUnwrap(kek, wrapped) {
  log.debug("Entering aesKwUnwrap().");
  var k = secretBytes(kek);
  aesId("KW", k);
  var c = asBytes(wrapped);
  if (c.length < 24 || c.length % 8) {
    log.debug("Leaving aesKwUnwrap(). Bad length.");
    throw new Error("An AES-wrapped key is a multiple of 8 bytes, at least " +
                    "24; this is " + c.length + ".");
  }
  var n = c.length / 8 - 1;
  var a = c.slice(0, 8);
  var r = [];
  for (var i = 0; i < n; i++) {
    r.push(c.slice(8 * (i + 1), 8 * (i + 2)));
  }
  for (var j = 5; j >= 0; j--) {
    for (var m = n - 1; m >= 0; m--) {
      var b = symmetric.aesBlockDecrypt(k,
        concatBytes(kwXorCounter(a, n * j + m + 1), r[m]));
      a = b.slice(0, 8);
      r[m] = b.slice(8, 16);
    }
  }
  if (!bytes.bytesEqual(a, KW_IV)) {
    log.debug("Leaving aesKwUnwrap(). Integrity check failed.");
    throw new Error("AES Key Unwrap failed its integrity check: wrong key " +
                    "or modified data.");
  }
  var out = new Uint8Array(0);
  for (var q = 0; q < n; q++) {
    out = concatBytes(out, r[q]);
  }
  log.debug("Leaving aesKwUnwrap().");
  return out;
}

// ===========================================================================
// RSA ENCRYPTION, KEMs
// ===========================================================================
var RSA_ENC = {
  "rsa-oaep-sha1": { padding: "oaep", hash: "SHA-1" },
  "rsa-oaep-sha256": { padding: "oaep", hash: "SHA-256" },
  "rsa-pkcs1v15-enc": { padding: "v1_5" }
};

function rsaEncScheme(alg) {
  log.debug("Entering rsaEncScheme(). alg=" + alg);
  var s = RSA_ENC[alg];
  if (!s) {
    log.debug("Leaving rsaEncScheme(). Unknown.");
    throw new Error("Unknown RSA encryption scheme: " + alg);
  }
  log.debug("Leaving rsaEncScheme().");
  return s;
}

// OAEP uses MGF1 over the SAME hash as the label hash (RFC 8017 / JWE's
// RSA-OAEP and RSA-OAEP-256; XML Encryption's rsa-oaep-mgf1p is SHA-1 both).
function rsaEncrypt(alg, publicKey, plaintext) {
  log.debug("Entering rsaEncrypt(). alg=" + alg);
  var s = rsaEncScheme(alg);
  var out = pkEncryption.rsaEncrypt({
    publicPem: keys.exportKey(keys.publicKeyOf(publicKey), "spki-pem"),
    padding: s.padding, hash: s.hash, plaintext: plaintext });
  log.debug("Leaving rsaEncrypt().");
  return out.ciphertext;
}

function rsaDecrypt(alg, privateKey, ciphertext) {
  log.debug("Entering rsaDecrypt(). alg=" + alg);
  var s = rsaEncScheme(alg);
  var out = pkEncryption.rsaDecrypt({
    privatePem: keys.exportKey(privateKey, "pkcs8-pem"),
    padding: s.padding, hash: s.hash, ciphertext: ciphertext });
  log.debug("Leaving rsaDecrypt().");
  return out;
}

// ML-KEM, X-Wing and the composite KEMs, by pqc.js name.
function kemEncapsulate(publicKey) {
  log.debug("Entering kemEncapsulate(). alg=" + (publicKey && publicKey.alg));
  if (!publicKey || publicKey.type !== "kem") {
    log.debug("Leaving kemEncapsulate(). Not a KEM key.");
    throw new Error("KEM encapsulation needs a kem key.");
  }
  var r = pqc.kemAlg(publicKey.alg).encapsulate(publicKey.publicKey);
  log.debug("Leaving kemEncapsulate().");
  return { ciphertext: asBytes(r.cipherText || r.ciphertext),
           sharedSecret: asBytes(r.sharedSecret) };
}

function kemDecapsulate(privateKey, ciphertext) {
  log.debug("Entering kemDecapsulate().");
  if (!privateKey || privateKey.type !== "kem" || !privateKey.privateKey) {
    log.debug("Leaving kemDecapsulate(). Not a private KEM key.");
    throw new Error("KEM decapsulation needs a private kem key.");
  }
  var out = asBytes(pqc.kemAlg(privateKey.alg)
    .decapsulate(asBytes(ciphertext), privateKey.privateKey));
  log.debug("Leaving kemDecapsulate().");
  return out;
}

function randomBytes(count) {
  log.debug("Entering randomBytes(). count=" + count);
  log.debug("Leaving randomBytes().");
  return bytes.randomBytes(count);
}

module.exports = {
  // backends
  BACKENDS: BACKENDS,
  backend: backend,
  setBackend: setBackend,
  webcryptoAvailable: webcryptoAvailable,
  // the table
  ALGORITHMS: ALGORITHMS,
  algorithmInfo: algorithmInfo,
  // keys (crypto_keys.js)
  KEY_SPECS: keys.KEY_SPECS,
  KEY_FORMATS: keys.FORMATS,
  EC_CURVES: keys.EC_CURVES,
  OKP_CURVES: keys.OKP_CURVES,
  generateKeyPair: keys.generateKeyPair,
  importKey: keys.importKey,
  exportKey: keys.exportKey,
  publicKeyOf: keys.publicKeyOf,
  jwkThumbprint: keys.jwkThumbprint,
  // digest / MAC / KDF
  digest: digest,
  hmac: hmac,
  hmacVerify: hmacVerify,
  kmac: kmac,
  hkdf: hkdf,
  pbkdf2: pbkdf2,
  concatKdf: concatKdf,
  // signatures
  sign: sign,
  verify: verify,
  rsaSignBackend: rsaSignBackend,
  rawToDerEcdsa: rawToDerEcdsa,
  derToRawEcdsa: derToRawEcdsa,
  // key agreement
  ecdh: ecdh,
  // symmetric
  aesGcmEncrypt: aesGcmEncrypt,
  aesGcmDecrypt: aesGcmDecrypt,
  aesCbcEncrypt: aesCbcEncrypt,
  aesCbcDecrypt: aesCbcDecrypt,
  chacha20Poly1305Encrypt: chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt: chacha20Poly1305Decrypt,
  aesKwWrap: aesKwWrap,
  aesKwUnwrap: aesKwUnwrap,
  // asymmetric encryption / KEM
  rsaEncrypt: rsaEncrypt,
  rsaDecrypt: rsaDecrypt,
  kemEncapsulate: kemEncapsulate,
  kemDecapsulate: kemDecapsulate,
  randomBytes: randomBytes
};
