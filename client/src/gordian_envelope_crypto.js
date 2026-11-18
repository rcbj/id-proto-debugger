// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope_crypto.js
//
// ---------------------------------------------------------------------------
// The OBSCURING half of Gordian Envelope (#480), over gordian_envelope.js:
// ENCRYPTED elements (tag 40002), COMPRESSED elements (tag 40003), public-
// key recipients ('hasRecipient' with a SealedMessage) and SSKR shares
// ('sskrShare'). Each, like elision, leaves the element's digest where it
// was — so a signature over a tree stays valid while parts of the tree are
// encrypted, compressed or split. bc-envelope 0.43.0 and bc-components
// 0.31.1 are the reference; tests/gordian_envelope_engine.js holds this to
// their test vectors and to bc-envelope-cli 0.35.0 in both directions.
//
// The bytes that have to be theirs:
//
//   * An EncryptedMessage is 40002([ciphertext, nonce(12), tag(16), aad]),
//     ChaCha20-Poly1305 (RFC 8439), its AAD the dCBOR of 40001(digest) —
//     the digest of what was encrypted, which is how an encrypted element
//     keeps its place in the tree. The plaintext is the TAGGED envelope,
//     200(...): for a node only its subject is encrypted and its assertions
//     stay outside.
//   * A Compressed is 40003([crc32, size, data, 40001(digest)]), the data
//     raw DEFLATE (RFC 1951) of the tagged envelope at level 6 — or the
//     bytes themselves when DEFLATE would not make them smaller. The
//     compressed bytes need not be miniz's: the digest does not cover them.
//   * A recipient is 'hasRecipient': 40019([40002(...), encapsulation]),
//     the content key (40023(key), dCBOR) sealed to an X25519 key — an
//     ephemeral key pair, the shared secret HKDF-SHA-256(X25519, salt
//     "agreement") — or to an ML-KEM key (FIPS 203), whose shared secret is
//     the key. A private key from a seed is HKDF-SHA-256(seed, salt
//     "agreement"), as bc-components' PrivateKeyBase derives it.
//   * A secret is 'hasSecret': 40027(EncryptedMessage), the content key
//     locked with a key derived from a password (HKDF, PBKDF2, scrypt or
//     Argon2id, with bc-components' parameters).
//   * An SSKR share is 'sskrShare': 40309(share), the share of the content
//     key in sskr.js's format; every share envelope carries the same
//     encrypted subject.
//
// Keys live only in the caller's memory. NO DOM.
// ---------------------------------------------------------------------------

var nobleX25519 = require("@noble/curves/ed25519").x25519;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512").sha512;
var nobleHkdf = require("@noble/hashes/hkdf").hkdf;
var noblePbkdf2 = require("@noble/hashes/pbkdf2").pbkdf2;
var nobleScrypt = require("@noble/hashes/scrypt").scrypt;
var nobleArgon2id = require("@noble/hashes/argon2").argon2id;
var nobleMlkem = require("@noble/post-quantum/ml-kem.js");
var fflate = require("fflate");
var ge = require("./gordian_envelope");
var sskr = require("./sskr");
var sym = require("./symmetric_crypto");
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gordian_envelope_crypto",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var T = ge.Tagged;
var TAG = ge.TAG;

// FIPS 203 ML-KEM as bc-components labels it: [level, bytes], the level
// 512, 768 or 1024.
var MLKEM = {
  512: { scheme: "mlkem512", impl: nobleMlkem.ml_kem512 },
  768: { scheme: "mlkem768", impl: nobleMlkem.ml_kem768 },
  1024: { scheme: "mlkem1024", impl: nobleMlkem.ml_kem1024 }
};

function mlkemLevel(scheme) {
  log.debug("Entering mlkemLevel(). " + scheme);
  var level = Object.keys(MLKEM).filter(function (k) {
    return MLKEM[k].scheme === scheme;
  })[0];
  log.debug("Leaving mlkemLevel().");
  return level ? Number(level) : null;
}

function digestCbor(digest) {
  log.debug("Entering digestCbor().");
  log.debug("Leaving digestCbor().");
  return new T(TAG.DIGEST, digest);
}

// ---------------------------------------------------------------------------
// Symmetric keys and EncryptedMessage.
// ---------------------------------------------------------------------------

function generateKey() {
  log.debug("Entering generateKey().");
  log.debug("Leaving generateKey().");
  return cbytes.randomBytes(32);
}

function keyUr(key) {
  log.debug("Entering keyUr().");
  log.debug("Leaving keyUr().");
  return ge.urEncode("crypto-key", ge.encode(cbytes.asBytes(key)));
}

// ur:crypto-key/…, or 64 hex digits.
function readKey(input) {
  log.debug("Entering readKey().");
  var s = String(input || "").trim();
  var key;
  if (/^ur:/i.test(s)) {
    var ur = ge.urDecode(s);
    if (ur.type !== "crypto-key") {
      log.debug("Leaving readKey(). Wrong UR type.");
      throw new Error("ur:" + ur.type + " is not a symmetric key " +
                      "(ur:crypto-key).");
    }
    key = ge.decode(ur.body);
    if (key instanceof T && key.tag === TAG.SYMMETRIC_KEY) key = key.value;
  } else {
    key = cbytes.hexToBytes(s.replace(/\s+/g, ""));
  }
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    log.debug("Leaving readKey(). Not 32 bytes.");
    throw new Error("a symmetric key is 32 bytes.");
  }
  log.debug("Leaving readKey().");
  return key;
}

// -> the EncryptedMessage's CBOR, 40002([ct, nonce, tag, aad?]).
function encryptMessage(key, plaintext, aad, nonce) {
  log.debug("Entering encryptMessage().");
  var n = nonce ? cbytes.asBytes(nonce) : cbytes.randomBytes(12);
  var a = aad ? cbytes.asBytes(aad) : new Uint8Array(0);
  var r = sym.chacha20Poly1305Encrypt(cbytes.asBytes(key), n,
                                      cbytes.asBytes(plaintext), a);
  var parts = [r.ciphertext, n, r.tag];
  if (a.length) parts.push(a);
  log.debug("Leaving encryptMessage().");
  return new T(TAG.ENCRYPTED, parts);
}

// { ciphertext, nonce, tag, aad } of a 40002 value.
function readMessage(v) {
  log.debug("Entering readMessage().");
  var p = v instanceof T && v.tag === TAG.ENCRYPTED ? v.value : null;
  if (!Array.isArray(p) || p.length < 3 || p.length > 4 ||
      !p.every(function (x) {
        return x instanceof Uint8Array;
      }) || p[1].length !== 12 || p[2].length !== 16) {
    log.debug("Leaving readMessage(). Not an EncryptedMessage.");
    throw new Error("an EncryptedMessage is 40002([ciphertext, nonce(12), " +
                    "tag(16), aad]).");
  }
  log.debug("Leaving readMessage().");
  return { ciphertext: p[0], nonce: p[1], tag: p[2],
           aad: p[3] || new Uint8Array(0) };
}

function decryptMessage(key, v) {
  log.debug("Entering decryptMessage().");
  var m = readMessage(v);
  var out;
  try {
    out = sym.chacha20Poly1305Decrypt(cbytes.asBytes(key), m.nonce,
                                      m.ciphertext, m.aad, m.tag);
  } catch (e) {
    log.debug("Leaving decryptMessage(). Tag.");
    throw new Error("the key does not open this EncryptedMessage (its " +
                    "Poly1305 tag fails).");
  }
  log.debug("Leaving decryptMessage().");
  return out;
}

// ---------------------------------------------------------------------------
// Encrypting an envelope's subject.
// ---------------------------------------------------------------------------

function encryptedElement(cbor) {
  log.debug("Entering encryptedElement().");
  log.debug("Leaving encryptedElement().");
  return ge.fromCbor(cbor);
}

// bc-envelope's encrypt_subject: the subject (the whole envelope unless it
// is a node) becomes ENCRYPTED; the digest of the result is unchanged.
function encryptSubject(e, key, nonce) {
  log.debug("Entering encryptSubject(). " + e.kind);
  var target = e.kind === "node" ? e.subject : e;
  if (target.kind === "encrypted") {
    log.debug("Leaving encryptSubject(). Already encrypted.");
    throw new Error("the subject is already encrypted.");
  }
  if (target.kind === "elided") {
    log.debug("Leaving encryptSubject(). Elided.");
    throw new Error("an elided subject cannot be encrypted.");
  }
  var msg = encryptMessage(key, ge.toBytes(target),
                           ge.encode(digestCbor(target.digest)), nonce);
  var enc = encryptedElement(msg);
  var out = e.kind === "node" ? ge.node(enc, e.assertions) : enc;
  if (!cbytes.bytesEqual(out.digest, e.digest)) {
    log.debug("Leaving encryptSubject(). Digest changed.");
    throw new Error("encryption changed the digest; this should not happen.");
  }
  log.debug("Leaving encryptSubject().");
  return out;
}

// bc-envelope's decrypt_subject.
function decryptSubject(e, key) {
  log.debug("Entering decryptSubject().");
  var target = ge.subjectOf(e);
  if (target.kind !== "encrypted") {
    log.debug("Leaving decryptSubject(). Not encrypted.");
    throw new Error("the subject is not encrypted.");
  }
  var plain = decryptMessage(key, target.cbor);
  var inner = ge.fromBytes(plain);
  if (!cbytes.bytesEqual(inner.digest, target.digest)) {
    log.debug("Leaving decryptSubject(). Digest.");
    throw new Error("the decrypted subject's digest is not the one its " +
                    "EncryptedMessage names.");
  }
  var out = e.kind === "node" ? ge.node(inner, e.assertions) : inner;
  if (!cbytes.bytesEqual(out.digest, e.digest)) {
    log.debug("Leaving decryptSubject(). Envelope digest.");
    throw new Error("the decrypted envelope's digest changed.");
  }
  log.debug("Leaving decryptSubject().");
  return out;
}

function unwrap(e) {
  log.debug("Entering unwrap().");
  var s = ge.subjectOf(e);
  if (s.kind !== "wrapped") {
    log.debug("Leaving unwrap(). Not wrapped.");
    throw new Error("the subject is not a wrapped envelope.");
  }
  log.debug("Leaving unwrap().");
  return s.envelope;
}

// Wrap then encrypt, so the assertions are hidden too.
function encrypt(e, key, nonce) {
  log.debug("Entering encrypt().");
  log.debug("Leaving encrypt().");
  return encryptSubject(ge.wrap(e), key, nonce);
}

function decrypt(e, key) {
  log.debug("Entering decrypt().");
  log.debug("Leaving decrypt().");
  return unwrap(decryptSubject(e, key));
}

// ---------------------------------------------------------------------------
// Compression.
// ---------------------------------------------------------------------------

// bc-envelope's compress: the whole envelope becomes COMPRESSED.
function compress(e) {
  log.debug("Entering compress(). " + e.kind);
  if (e.kind === "compressed") {
    log.debug("Leaving compress(). Already compressed.");
    return e;
  }
  if (e.kind === "encrypted" || e.kind === "elided") {
    log.debug("Leaving compress(). Obscured.");
    throw new Error("an " + e.kind + " envelope cannot be compressed.");
  }
  var data = ge.toBytes(e);
  var deflated = fflate.deflateSync(data, { level: 6 });
  var body = deflated.length && deflated.length < data.length ? deflated :
      data;
  var out = ge.fromCbor(new T(TAG.COMPRESSED, [ge.crc32(data), data.length,
    body, digestCbor(e.digest)]));
  log.debug("Leaving compress(). " + body.length + "/" + data.length);
  return out;
}

function readCompressed(v) {
  log.debug("Entering readCompressed().");
  var p = v instanceof T && v.tag === TAG.COMPRESSED ? v.value : null;
  if (!Array.isArray(p) || p.length !== 4 || typeof p[0] !== "number" ||
      typeof p[1] !== "number" || !(p[2] instanceof Uint8Array)) {
    log.debug("Leaving readCompressed(). Not a Compressed.");
    throw new Error("a compressed element is 40003([crc32, size, data, " +
                    "digest]).");
  }
  if (p[2].length > p[1]) {
    log.debug("Leaving readCompressed(). Larger.");
    throw new Error("the compressed data is larger than its stated size.");
  }
  log.debug("Leaving readCompressed().");
  return { checksum: p[0] >>> 0, size: p[1], data: p[2] };
}

function decompress(e) {
  log.debug("Entering decompress().");
  if (e.kind !== "compressed") {
    log.debug("Leaving decompress(). Not compressed.");
    throw new Error("the envelope is not compressed.");
  }
  var c = readCompressed(e.cbor);
  var data;
  if (c.data.length >= c.size) {
    data = c.data;
  } else {
    try {
      data = fflate.inflateSync(c.data, { out: new Uint8Array(c.size) });
    } catch (err) {
      log.debug("Leaving decompress(). Corrupt.");
      throw new Error("the compressed data is not valid DEFLATE: " +
                      err.message);
    }
  }
  if (data.length !== c.size || ge.crc32(data) !== c.checksum) {
    log.debug("Leaving decompress(). Checksum.");
    throw new Error("the decompressed data's size or CRC-32 is not the one " +
                    "the element states.");
  }
  var out = ge.fromBytes(data);
  if (!cbytes.bytesEqual(out.digest, e.digest)) {
    log.debug("Leaving decompress(). Digest.");
    throw new Error("the decompressed envelope's digest is not the one the " +
                    "element states.");
  }
  log.debug("Leaving decompress().");
  return out;
}

function replaceSubject(e, subject) {
  log.debug("Entering replaceSubject().");
  log.debug("Leaving replaceSubject().");
  return e.kind === "node" ? ge.node(subject, e.assertions) : subject;
}

function compressSubject(e) {
  log.debug("Entering compressSubject().");
  log.debug("Leaving compressSubject().");
  return replaceSubject(e, compress(ge.subjectOf(e)));
}

function decompressSubject(e) {
  log.debug("Entering decompressSubject().");
  var s = ge.subjectOf(e);
  log.debug("Leaving decompressSubject().");
  return s.kind === "compressed" ? replaceSubject(e, decompress(s)) : e;
}

// ---------------------------------------------------------------------------
// Key pairs: PrivateKeys / PublicKeys (a signing key and an encapsulation
// key), from a seed, ur:crypto-prvkey-base, ur:seed or ur:crypto-prvkeys.
// ---------------------------------------------------------------------------

function hkdf(material, salt) {
  log.debug("Entering hkdf(). " + salt);
  log.debug("Leaving hkdf().");
  return nobleHkdf(nobleSha256, cbytes.asBytes(material),
                   cbytes.strBytes(salt), new Uint8Array(0), 32);
}

function x25519FromSeed(seed) {
  log.debug("Entering x25519FromSeed().");
  log.debug("Leaving x25519FromSeed().");
  return { scheme: "x25519", privateKey: hkdf(seed, "agreement") };
}

// An ML-KEM key pair { scheme, privateKey, publicKey }.
function mlkemKeyPair(scheme, seed) {
  log.debug("Entering mlkemKeyPair(). " + scheme);
  var level = mlkemLevel(scheme);
  if (!level) {
    log.debug("Leaving mlkemKeyPair(). Unknown.");
    throw new Error(scheme + " is not mlkem512, mlkem768 or mlkem1024.");
  }
  var kp = MLKEM[level].impl.keygen(seed ? cbytes.asBytes(seed) :
                                    cbytes.randomBytes(64));
  log.debug("Leaving mlkemKeyPair().");
  return { scheme: scheme, privateKey: kp.secretKey, publicKey: kp.publicKey };
}

function encapsulationPublicKey(priv) {
  log.debug("Entering encapsulationPublicKey(). " + priv.scheme);
  if (priv.scheme === "x25519") {
    log.debug("Leaving encapsulationPublicKey(). X25519.");
    return { scheme: "x25519",
             publicKey: nobleX25519.getPublicKey(priv.privateKey) };
  }
  if (!priv.publicKey) {
    log.debug("Leaving encapsulationPublicKey(). No ML-KEM public key.");
    throw new Error("an ML-KEM private key does not give its public key " +
                    "here.");
  }
  log.debug("Leaving encapsulationPublicKey().");
  return { scheme: priv.scheme, publicKey: priv.publicKey };
}

// { signing, encapsulation } private keys from a seed, as bc-components'
// PrivateKeyBase gives them (signing: schnorr unless `scheme` says).
function privateKeysFromSeed(seed, scheme) {
  log.debug("Entering privateKeysFromSeed(). " + scheme);
  var s = scheme || "schnorr";
  var signing = s === "ssh-ed25519" ? ge.sshEd25519FromSeed(seed) :
      { scheme: s, privateKey: ge.signingKeyFromSeed(seed) };
  if (ge.isMldsa(s)) {
    log.debug("Leaving privateKeysFromSeed(). ML-DSA.");
    throw new Error("an ML-DSA key is not derived from a seed by " +
                    "bc-components; generate one.");
  }
  log.debug("Leaving privateKeysFromSeed().");
  return { signing: signing, encapsulation: x25519FromSeed(seed) };
}

function signingPrivateKeyFromCbor(v) {
  log.debug("Entering signingPrivateKeyFromCbor().");
  var x = v instanceof T && v.tag === TAG.SIGNING_PRIVATE_KEY ? v.value : v;
  var out;
  if (x instanceof Uint8Array && x.length === 32) {
    out = { scheme: "schnorr", privateKey: x };
  } else if (Array.isArray(x) && (x[0] === 1 || x[0] === 2) &&
             x[1] instanceof Uint8Array && x[1].length === 32) {
    out = { scheme: x[0] === 1 ? "ecdsa" : "ed25519", privateKey: x[1] };
  } else if (x instanceof T && x.tag === TAG.MLDSA_PRIVATE_KEY &&
             Array.isArray(x.value)) {
    var name = { 2: "mldsa44", 3: "mldsa65", 5: "mldsa87" }[x.value[0]];
    if (!name) {
      log.debug("Leaving signingPrivateKeyFromCbor(). ML-DSA level.");
      throw new Error("an ML-DSA private key of unknown level.");
    }
    out = { scheme: name, privateKey: x.value[1] };
  } else if (x instanceof T && x.tag === TAG.SSH_PRIVATE_KEY &&
             typeof x.value === "string") {
    out = ge.sshPrivateKey(x.value);
  } else {
    log.debug("Leaving signingPrivateKeyFromCbor(). Unknown.");
    throw new Error("not a signing private key this page reads.");
  }
  log.debug("Leaving signingPrivateKeyFromCbor(). " + out.scheme);
  return out;
}

function encapsulationPrivateKeyFromCbor(v) {
  log.debug("Entering encapsulationPrivateKeyFromCbor().");
  var out;
  if (v instanceof T && v.tag === TAG.X25519_PRIVATE_KEY &&
      v.value instanceof Uint8Array && v.value.length === 32) {
    out = { scheme: "x25519", privateKey: v.value };
  } else if (v instanceof T && v.tag === TAG.MLKEM_PRIVATE_KEY &&
             Array.isArray(v.value) && MLKEM[v.value[0]]) {
    out = { scheme: MLKEM[v.value[0]].scheme, privateKey: v.value[1] };
  } else {
    log.debug("Leaving encapsulationPrivateKeyFromCbor(). Unknown.");
    throw new Error("not an X25519 or ML-KEM private key.");
  }
  log.debug("Leaving encapsulationPrivateKeyFromCbor(). " + out.scheme);
  return out;
}

function encapsulationPublicKeyFromCbor(v) {
  log.debug("Entering encapsulationPublicKeyFromCbor().");
  var out;
  if (v instanceof T && v.tag === TAG.X25519_PUBLIC_KEY &&
      v.value instanceof Uint8Array && v.value.length === 32) {
    out = { scheme: "x25519", publicKey: v.value };
  } else if (v instanceof T && v.tag === TAG.MLKEM_PUBLIC_KEY &&
             Array.isArray(v.value) && MLKEM[v.value[0]]) {
    out = { scheme: MLKEM[v.value[0]].scheme, publicKey: v.value[1] };
  } else {
    log.debug("Leaving encapsulationPublicKeyFromCbor(). Unknown.");
    throw new Error("not an X25519 or ML-KEM public key.");
  }
  log.debug("Leaving encapsulationPublicKeyFromCbor(). " + out.scheme);
  return out;
}

function encapsulationPublicKeyCbor(pub) {
  log.debug("Entering encapsulationPublicKeyCbor().");
  log.debug("Leaving encapsulationPublicKeyCbor().");
  return pub.scheme === "x25519" ? new T(TAG.X25519_PUBLIC_KEY,
                                         pub.publicKey) :
    new T(TAG.MLKEM_PUBLIC_KEY, [mlkemLevel(pub.scheme), pub.publicKey]);
}

function encapsulationPrivateKeyCbor(priv) {
  log.debug("Entering encapsulationPrivateKeyCbor().");
  log.debug("Leaving encapsulationPrivateKeyCbor().");
  return priv.scheme === "x25519" ? new T(TAG.X25519_PRIVATE_KEY,
                                          priv.privateKey) :
    new T(TAG.MLKEM_PRIVATE_KEY, [mlkemLevel(priv.scheme), priv.privateKey]);
}

function signingPrivateKeyCbor(key) {
  log.debug("Entering signingPrivateKeyCbor(). " + key.scheme);
  var inner;
  if (key.scheme === "schnorr") {
    inner = key.privateKey;
  } else if (key.scheme === "ecdsa" || key.scheme === "ed25519") {
    inner = [key.scheme === "ecdsa" ? 1 : 2, key.privateKey];
  } else if (ge.isMldsa(key.scheme)) {
    inner = new T(TAG.MLDSA_PRIVATE_KEY, [{ mldsa44: 2, mldsa65: 3,
      mldsa87: 5 }[key.scheme], key.privateKey]);
  } else {
    log.debug("Leaving signingPrivateKeyCbor(). Unsupported.");
    throw new Error("writing a " + key.scheme + " private key is not " +
                    "supported here.");
  }
  log.debug("Leaving signingPrivateKeyCbor().");
  return new T(TAG.SIGNING_PRIVATE_KEY, inner);
}

// The private keys from any of: ur:crypto-prvkeys, ur:crypto-prvkey-base,
// ur:seed, or the hex of a seed. -> { signing, encapsulation }.
function readPrivateKeys(input, scheme) {
  log.debug("Entering readPrivateKeys().");
  var s = String(input || "").trim();
  var out;
  if (/^ur:/i.test(s)) {
    var ur = ge.urDecode(s);
    var v = ge.decode(ur.body);
    if (ur.type === "crypto-prvkeys" && Array.isArray(v) && v.length === 2) {
      out = { signing: signingPrivateKeyFromCbor(v[0]),
              encapsulation: encapsulationPrivateKeyFromCbor(v[1]) };
    } else if (ur.type === "crypto-prvkey-base" && v instanceof Uint8Array) {
      out = privateKeysFromSeed(v, scheme);
    } else if (ur.type === "seed" && v instanceof Map &&
               v.get(1) instanceof Uint8Array) {
      out = privateKeysFromSeed(v.get(1), scheme);
    } else {
      log.debug("Leaving readPrivateKeys(). Wrong UR.");
      throw new Error("ur:" + ur.type + " is not ur:crypto-prvkeys, " +
                      "ur:crypto-prvkey-base or ur:seed.");
    }
  } else {
    var seed = cbytes.hexToBytes(s.replace(/\s+/g, ""));
    if (seed.length < 16) {
      log.debug("Leaving readPrivateKeys(). Short seed.");
      throw new Error("a seed is at least 16 bytes of hex.");
    }
    out = privateKeysFromSeed(seed, scheme);
  }
  log.debug("Leaving readPrivateKeys().");
  return out;
}

function privateKeysUr(keys) {
  log.debug("Entering privateKeysUr().");
  log.debug("Leaving privateKeysUr().");
  return ge.urEncode("crypto-prvkeys", ge.encode([
    signingPrivateKeyCbor(keys.signing),
    encapsulationPrivateKeyCbor(keys.encapsulation)]));
}

function publicKeysOf(keys) {
  log.debug("Entering publicKeysOf().");
  log.debug("Leaving publicKeysOf().");
  return { signing: keys.signing ? ge.publicKeyOf(keys.signing) : null,
           encapsulation: encapsulationPublicKey(keys.encapsulation) };
}

function publicKeysUr(pubs) {
  log.debug("Entering publicKeysUr().");
  log.debug("Leaving publicKeysUr().");
  return ge.urEncode("crypto-pubkeys", ge.encode([
    ge.publicKeyCbor(pubs.signing),
    encapsulationPublicKeyCbor(pubs.encapsulation)]));
}

// ur:crypto-pubkeys/… -> { signing, encapsulation }.
function readPublicKeys(input) {
  log.debug("Entering readPublicKeys().");
  var ur = ge.urDecode(String(input || "").trim());
  var v = ge.decode(ur.body);
  if (ur.type !== "crypto-pubkeys" || !Array.isArray(v) || v.length !== 2) {
    log.debug("Leaving readPublicKeys(). Wrong UR.");
    throw new Error("a recipient is ur:crypto-pubkeys/… (a signing key and " +
                    "an encapsulation key).");
  }
  var signing = null;
  try {
    signing = ge.readPublicKey(ge.urEncode("signing-public-key",
      ge.encode(v[0] instanceof T ? v[0].value : v[0])));
  } catch (e) {
    signing = null;
  }
  log.debug("Leaving readPublicKeys().");
  return { signing: signing,
           encapsulation: encapsulationPublicKeyFromCbor(v[1]) };
}

// ---------------------------------------------------------------------------
// SealedMessage and recipients.
// ---------------------------------------------------------------------------

function agreementKey(privateKey, publicKey) {
  log.debug("Entering agreementKey().");
  log.debug("Leaving agreementKey().");
  return hkdf(nobleX25519.getSharedSecret(privateKey, publicKey),
              "agreement");
}

// plaintext sealed to an encapsulation public key -> 40019([msg, enc]).
// opts.ephemeral (an X25519 private key) and opts.nonce reproduce a test.
function seal(plaintext, recipient, opts) {
  log.debug("Entering seal(). " + recipient.scheme);
  var o = opts || {};
  var key;
  var encapsulated;
  if (recipient.scheme === "x25519") {
    var eph = o.ephemeral || hkdf(cbytes.randomBytes(32), "agreement");
    key = agreementKey(eph, recipient.publicKey);
    encapsulated = new T(TAG.X25519_PUBLIC_KEY,
                         nobleX25519.getPublicKey(eph));
  } else {
    var level = mlkemLevel(recipient.scheme);
    if (!level) {
      log.debug("Leaving seal(). Unknown scheme.");
      throw new Error("no encapsulation scheme " + recipient.scheme + ".");
    }
    var kem = MLKEM[level].impl.encapsulate(recipient.publicKey);
    key = kem.sharedSecret;
    encapsulated = new T(TAG.MLKEM_CIPHERTEXT, [level, kem.cipherText]);
  }
  log.debug("Leaving seal().");
  return new T(TAG.SEALED_MESSAGE, [encryptMessage(key, plaintext,
    o.aad, o.nonce), encapsulated]);
}

function unseal(v, priv) {
  log.debug("Entering unseal(). " + priv.scheme);
  var p = v instanceof T && v.tag === TAG.SEALED_MESSAGE ? v.value : null;
  if (!Array.isArray(p) || p.length !== 2 || !(p[1] instanceof T)) {
    log.debug("Leaving unseal(). Not a SealedMessage.");
    throw new Error("a SealedMessage is 40019([EncryptedMessage, " +
                    "encapsulation]).");
  }
  var key;
  if (p[1].tag === TAG.X25519_PUBLIC_KEY) {
    if (priv.scheme !== "x25519") {
      log.debug("Leaving unseal(). Scheme.");
      throw new Error("sealed to an X25519 key, not " + priv.scheme + ".");
    }
    key = agreementKey(priv.privateKey, p[1].value);
  } else if (p[1].tag === TAG.MLKEM_CIPHERTEXT && Array.isArray(p[1].value)) {
    var level = p[1].value[0];
    if (!MLKEM[level] || MLKEM[level].scheme !== priv.scheme) {
      log.debug("Leaving unseal(). ML-KEM level.");
      throw new Error("sealed to ML-KEM-" + level + ", not " + priv.scheme +
                      ".");
    }
    key = MLKEM[level].impl.decapsulate(p[1].value[1], priv.privateKey);
  } else {
    log.debug("Leaving unseal(). Unknown encapsulation.");
    throw new Error("an encapsulation this page does not know.");
  }
  log.debug("Leaving unseal().");
  return decryptMessage(key, p[0]);
}

function hasRecipient(recipient, contentKey, opts) {
  log.debug("Entering hasRecipient().");
  log.debug("Leaving hasRecipient().");
  return ge.assertion(ge.knownValue("hasRecipient"), ge.leaf(seal(
    ge.encode(new T(TAG.SYMMETRIC_KEY, cbytes.asBytes(contentKey))),
    recipient.encapsulation || recipient, opts)));
}

function addRecipient(e, recipient, contentKey, opts) {
  log.debug("Entering addRecipient().");
  log.debug("Leaving addRecipient().");
  return ge.addAssertion(e, hasRecipient(recipient, contentKey, opts));
}

// The subject encrypted with a new content key, sealed to each recipient.
function encryptSubjectToRecipients(e, recipients, contentKey) {
  log.debug("Entering encryptSubjectToRecipients(). " + recipients.length);
  var key = contentKey || generateKey();
  var out = encryptSubject(e, key);
  recipients.forEach(function (r) {
    out = addRecipient(out, r, key);
  });
  log.debug("Leaving encryptSubjectToRecipients().");
  return out;
}

// The SealedMessages of e's unobscured 'hasRecipient' assertions.
function recipients(e) {
  log.debug("Entering recipients().");
  var out = ge.objectsFor(e, ge.knownValue("hasRecipient"))
    .filter(function (o) {
      return o.kind === "leaf" && o.value instanceof T &&
        o.value.tag === TAG.SEALED_MESSAGE;
    }).map(function (o) {
      return o.value;
    });
  log.debug("Leaving recipients(). " + out.length);
  return out;
}

// The content key from the first SealedMessage `keys` opens.
function contentKeyFor(e, keys) {
  log.debug("Entering contentKeyFor().");
  var priv = keys.encapsulation || keys;
  var sealed = recipients(e);
  for (var i = 0; i < sealed.length; i++) {
    try {
      var k = ge.decode(unseal(sealed[i], priv));
      if (k instanceof T && k.tag === TAG.SYMMETRIC_KEY &&
          k.value instanceof Uint8Array && k.value.length === 32) {
        log.debug("Leaving contentKeyFor(). Recipient " + i + ".");
        return k.value;
      }
    } catch (err) {
      log.debug("contentKeyFor(): recipient " + i + " is not this key.");
    }
  }
  log.debug("Leaving contentKeyFor(). None.");
  throw new Error(sealed.length ? "none of the " + sealed.length +
                  " recipient(s) is this key." :
                  "the envelope has no 'hasRecipient' assertion.");
}

function decryptSubjectToRecipient(e, keys) {
  log.debug("Entering decryptSubjectToRecipient().");
  log.debug("Leaving decryptSubjectToRecipient().");
  return decryptSubject(e, contentKeyFor(e, keys));
}

// ---------------------------------------------------------------------------
// Secrets ('hasSecret'): the content key locked with a password, as
// bc-components' EncryptedKey does it. 40027(40002([ct, nonce, tag, aad])),
// the plaintext the content key's 32 raw bytes, the AAD the dCBOR of the
// derivation's parameters — [0, salt, hash] HKDF, [1, salt, iterations,
// hash] PBKDF2, [2, salt, log2 N, r, p] scrypt, [3, salt] Argon2id
// (Argon2id v19, m = 19456 KiB, t = 2, p = 1: the argon2 crate's
// defaults) — the salt 40018(16 bytes), the hash 0 for SHA-256 and 1 for
// SHA-512. bc-envelope-cli's defaults are what lockSubject() writes.
// ---------------------------------------------------------------------------

var KDF = { hkdf: 0, pbkdf2: 1, scrypt: 2, argon2id: 3 };
var KDF_NAMES = ["HKDF", "PBKDF2", "Scrypt", "Argon2id"];

function deriveKey(params, secret) {
  log.debug("Entering deriveKey(). " + params[0]);
  var salt = params[1] instanceof T ? params[1].value : params[1];
  if (!(salt instanceof Uint8Array)) {
    log.debug("Leaving deriveKey(). No salt.");
    throw new Error("the key derivation parameters carry no salt.");
  }
  var pw = cbytes.asBytes(secret);
  var out;
  if (params[0] === KDF.hkdf) {
    out = nobleHkdf(params[2] === 1 ? nobleSha512 : nobleSha256, pw, salt,
                    new Uint8Array(0), 32);
  } else if (params[0] === KDF.pbkdf2) {
    out = noblePbkdf2(params[3] === 1 ? nobleSha512 : nobleSha256, pw, salt,
                      { c: params[2], dkLen: 32 });
  } else if (params[0] === KDF.scrypt) {
    out = nobleScrypt(pw, salt, { N: Math.pow(2, params[2]), r: params[3],
                                  p: params[4], dkLen: 32,
                                  maxmem: 1024 * 1024 * 1024 });
  } else if (params[0] === KDF.argon2id) {
    out = nobleArgon2id(pw, salt, { t: 2, m: 19456, p: 1, dkLen: 32,
                                    version: 0x13 });
  } else {
    log.debug("Leaving deriveKey(). Unknown method.");
    throw new Error("key derivation method " + params[0] + " is not one " +
                    "this page knows (SSH-agent locks need an agent).");
  }
  log.debug("Leaving deriveKey().");
  return out;
}

// The EncryptedKey's parameters as dCBOR values.
function kdfParams(method, opts) {
  log.debug("Entering kdfParams(). " + method);
  var o = opts || {};
  var salt = new T(TAG.SALT, o.salt ? cbytes.asBytes(o.salt) :
                   cbytes.randomBytes(16));
  var out;
  if (method === "hkdf") {
    out = [KDF.hkdf, salt, 0];
  } else if (method === "pbkdf2") {
    out = [KDF.pbkdf2, salt, o.iterations || 100000, 0];
  } else if (method === "scrypt") {
    out = [KDF.scrypt, salt, 15, 8, 1];
  } else if (method === "argon2id") {
    out = [KDF.argon2id, salt];
  } else {
    log.debug("Leaving kdfParams(). Unknown.");
    throw new Error("no key derivation " + JSON.stringify(method) + " (hkdf, " +
                    "pbkdf2, scrypt or argon2id).");
  }
  log.debug("Leaving kdfParams().");
  return out;
}

function lockKey(method, secret, contentKey, opts) {
  log.debug("Entering lockKey(). " + method);
  var params = kdfParams(method, opts);
  var derived = deriveKey(params, secret);
  log.debug("Leaving lockKey().");
  return new T(TAG.ENCRYPTED_KEY, encryptMessage(derived,
    cbytes.asBytes(contentKey), ge.encode(params), opts && opts.nonce));
}

function unlockKey(v, secret) {
  log.debug("Entering unlockKey().");
  if (!(v instanceof T) || v.tag !== TAG.ENCRYPTED_KEY) {
    log.debug("Leaving unlockKey(). Not an EncryptedKey.");
    throw new Error("not an EncryptedKey (40027).");
  }
  var params = ge.decode(readMessage(v.value).aad);
  if (!Array.isArray(params)) {
    log.debug("Leaving unlockKey(). Parameters.");
    throw new Error("an EncryptedKey whose AAD is not its parameters.");
  }
  var key = decryptMessage(deriveKey(params, secret), v.value);
  if (key.length !== 32) {
    log.debug("Leaving unlockKey(). Not a key.");
    throw new Error("the EncryptedKey does not hold a 32-byte key.");
  }
  log.debug("Leaving unlockKey().");
  return key;
}

// "EncryptedKey(Argon2id)", "EncryptedKey(PBKDF2(SHA256))", as bc-envelope
// prints one.
function describeSecret(v) {
  log.debug("Entering describeSecret().");
  var out = "EncryptedKey";
  try {
    var p = ge.decode(readMessage(v.value).aad);
    var name = KDF_NAMES[p[0]] || "method " + p[0];
    var hashed = p[0] === KDF.hkdf ? p[2] : p[0] === KDF.pbkdf2 ? p[3] :
        null;
    out += "(" + name + (hashed === null ? "" : "(" + (hashed === 1 ?
      "SHA512" : "SHA256") + ")") + ")";
  } catch (e) {
    out += "(?)";
  }
  log.debug("Leaving describeSecret().");
  return out;
}

function addSecret(e, method, secret, contentKey, opts) {
  log.debug("Entering addSecret(). " + method);
  log.debug("Leaving addSecret().");
  return ge.addAssertion(e, ge.knownValue("hasSecret"),
                         ge.leaf(lockKey(method, secret, contentKey, opts)));
}

// bc-envelope's lock_subject: encrypt with a new content key, locked with
// the password.
function lockSubject(e, method, secret, opts) {
  log.debug("Entering lockSubject().");
  var key = (opts && opts.contentKey) || generateKey();
  log.debug("Leaving lockSubject().");
  return addSecret(encryptSubject(e, key), method, secret, key, opts);
}

function unlockSubject(e, secret) {
  log.debug("Entering unlockSubject().");
  var locks = ge.objectsFor(e, ge.knownValue("hasSecret"))
    .filter(function (o) {
      return o.kind === "leaf";
    });
  for (var i = 0; i < locks.length; i++) {
    try {
      var key = unlockKey(locks[i].value, secret);
      log.debug("Leaving unlockSubject(). Lock " + i + ".");
      return decryptSubject(e, key);
    } catch (err) {
      log.debug("unlockSubject(): lock " + i + ": " + err.message);
    }
  }
  log.debug("Leaving unlockSubject(). None.");
  throw new Error(locks.length ? "the password opens none of the " +
                  locks.length + " 'hasSecret' lock(s)." :
                  "the envelope has no 'hasSecret' assertion.");
}

// ---------------------------------------------------------------------------
// SSKR.
// ---------------------------------------------------------------------------

// bc-envelope's sskr_split: e (already encrypted with contentKey) once per
// share, each with its 'sskrShare'. -> [[envelope, ...] per group].
function sskrSplit(e, sp, contentKey, rng) {
  log.debug("Entering sskrSplit().");
  var groups = sskr.generate(sp, contentKey, rng);
  var out = groups.map(function (g) {
    return g.map(function (share) {
      return ge.addAssertion(e, ge.knownValue("sskrShare"),
                             ge.leaf(new T(TAG.SSKR_SHARE, share)));
    });
  });
  log.debug("Leaving sskrSplit().");
  return out;
}

function sharesIn(e) {
  log.debug("Entering sharesIn().");
  var out = ge.objectsFor(e, ge.knownValue("sskrShare"))
    .filter(function (o) {
      return o.kind === "leaf" && o.value instanceof T &&
        (o.value.tag === TAG.SSKR_SHARE ||
         o.value.tag === TAG.SSKR_SHARE_V1) &&
        o.value.value instanceof Uint8Array;
    }).map(function (o) {
      return o.value.value;
    });
  log.debug("Leaving sharesIn(). " + out.length);
  return out;
}

// bc-envelope's sskr_join: the decrypted SUBJECT of the share envelopes.
function sskrJoin(envelopes) {
  log.debug("Entering sskrJoin(). " + envelopes.length);
  if (!envelopes.length) {
    log.debug("Leaving sskrJoin(). None.");
    throw new Error("no share envelopes.");
  }
  var byId = {};
  envelopes.forEach(function (e) {
    sharesIn(e).forEach(function (s) {
      var id = cbytes.bytesToHex(s.subarray(0, 2));
      (byId[id] = byId[id] || []).push(s);
    });
  });
  var problems = [];
  var ids = Object.keys(byId);
  for (var i = 0; i < ids.length; i++) {
    try {
      var key = sskr.combine(byId[ids[i]]);
      var opened = decryptSubject(envelopes[0], key);
      log.debug("Leaving sskrJoin(). Split " + ids[i] + ".");
      return ge.subjectOf(opened);
    } catch (err) {
      problems.push(ids[i] + ": " + err.message);
    }
  }
  log.debug("Leaving sskrJoin(). Failed.");
  throw new Error(ids.length ? "the shares do not recover the content key (" +
                  problems.join("; ") + ")." : "the envelopes carry no " +
                  "'sskrShare' assertion.");
}

// bc-envelope-cli's `sskr split`: wrap, encrypt, split. -> { shares:
// [envelope, ...] flattened, groups, contentKey }.
function splitEnvelope(e, groupThreshold, groups, contentKey, rng) {
  log.debug("Entering splitEnvelope().");
  var key = contentKey || generateKey();
  var sp = sskr.spec(groupThreshold, groups);
  var nested = sskrSplit(encryptSubject(ge.wrap(e), key), sp, key, rng);
  var flat = [];
  nested.forEach(function (g) {
    flat = flat.concat(g);
  });
  log.debug("Leaving splitEnvelope(). " + flat.length + " shares.");
  return { shares: flat, groups: nested, contentKey: key };
}

// bc-envelope-cli's `sskr join`: the original envelope.
function joinEnvelope(envelopes) {
  log.debug("Entering joinEnvelope().");
  log.debug("Leaving joinEnvelope().");
  return unwrap(sskrJoin(envelopes));
}

// What a share envelope's share says about itself.
function describeShares(e) {
  log.debug("Entering describeShares().");
  var out = sharesIn(e).map(function (s) {
    var p = sskr.parseShare(s);
    return { id: cbytes.bytesToHex(s.subarray(0, 2)), group: p.groupIndex + 1,
             groups: p.groupCount, groupThreshold: p.groupThreshold,
             member: p.memberIndex + 1, memberThreshold: p.memberThreshold };
  });
  log.debug("Leaving describeShares(). " + out.length);
  return out;
}

module.exports = {
  generateKey: generateKey,
  keyUr: keyUr,
  readKey: readKey,
  encryptMessage: encryptMessage,
  decryptMessage: decryptMessage,
  encryptSubject: encryptSubject,
  decryptSubject: decryptSubject,
  encrypt: encrypt,
  decrypt: decrypt,
  unwrap: unwrap,
  compress: compress,
  decompress: decompress,
  compressSubject: compressSubject,
  decompressSubject: decompressSubject,
  readCompressed: readCompressed,
  x25519FromSeed: x25519FromSeed,
  mlkemKeyPair: mlkemKeyPair,
  privateKeysFromSeed: privateKeysFromSeed,
  readPrivateKeys: readPrivateKeys,
  privateKeysUr: privateKeysUr,
  publicKeysOf: publicKeysOf,
  publicKeysUr: publicKeysUr,
  readPublicKeys: readPublicKeys,
  seal: seal,
  unseal: unseal,
  addRecipient: addRecipient,
  encryptSubjectToRecipients: encryptSubjectToRecipients,
  recipients: recipients,
  contentKeyFor: contentKeyFor,
  decryptSubjectToRecipient: decryptSubjectToRecipient,
  KDF_METHODS: Object.keys(KDF),
  lockKey: lockKey,
  unlockKey: unlockKey,
  describeSecret: describeSecret,
  addSecret: addSecret,
  lockSubject: lockSubject,
  unlockSubject: unlockSubject,
  sskrSplit: sskrSplit,
  sskrJoin: sskrJoin,
  splitEnvelope: splitEnvelope,
  joinEnvelope: joinEnvelope,
  describeShares: describeShares
};
