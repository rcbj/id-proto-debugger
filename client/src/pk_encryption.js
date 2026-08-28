// File: pk_encryption.js
//
// ---------------------------------------------------------------------------
// Public-key ENCRYPTION — the four families, and the one thing they all have
// in common.
//
//   RSA        RSA-OAEP (SHA-1/256/384/512) and RSAES-PKCS#1 v1.5
//   ECC        ECIES: ephemeral ECDH -> HKDF -> an AEAD
//   ML-KEM     FIPS 203 (formerly CRYSTALS-Kyber), the post-quantum one,
//              on its own or hybridised with X25519
//   FFC        the finite-field family DSA belongs to: textbook ElGamal, and
//              DHIES over the same group
//
// THE THING THEY HAVE IN COMMON is worth stating at the top, because it is the
// single most misunderstood fact about this page: **only RSA encrypts a
// message directly, and even RSA only encrypts a very short one.** Everything
// else here is a KEY ENCAPSULATION MECHANISM — it produces a shared secret,
// and the message is then encrypted symmetrically under a key derived from it.
// That is not a simplification this page invented to make the code shorter; it
// is what ECIES, HPKE, JWE's ECDH-ES, TLS and every real deployment of any of
// these actually do. So the asymmetric panes all emit the same four fields —
// an encapsulation, an IV, a ciphertext and a tag — and the pane says which
// part of that its own algorithm produced.
//
// ABOUT DSA. There is no such thing as DSA encryption, and no honest way to
// add one: DSA is a signature algorithm and its private key operation produces
// a signature, not a decryption. What CAN be done with a DSA key is what the
// finite-field family has always done — Diffie-Hellman over the same (p, q, g)
// group, and ElGamal, which is the encryption scheme DSA's own key structure
// comes from. Both are here, under their own names, over the standard MODP
// groups of RFC 3526. See docs/encryption.md.
//
// NO DOM. Bytes and strings in, bytes and strings out, so
// tests/crypto_engines.js drives every path in node with no browser.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var forge = require("node-forge");
var mlkem = require("@noble/post-quantum/ml-kem.js");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;
var x25519 = require("@noble/curves/ed25519").x25519;
var nobleHkdf = require("@noble/hashes/hkdf").hkdf;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var bytes = require("./crypto_bytes");
var symmetric = require("./symmetric_crypto");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "pk_encryption",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var asBytes = bytes.asBytes;
var concatBytes = bytes.concatBytes;
var randomBytes = bytes.randomBytes;
var hexToBytes = bytes.hexToBytes;
var bytesToHex = bytes.bytesToHex;

// The AEAD every hybrid mode here wraps the message in, unless the caller names
// another. AES-256-GCM rather than a choice, because the point of the pane is
// the ASYMMETRIC half; the symmetric panes are where the modes are compared.
var DEFAULT_CIPHER = 'AES-256-GCM';

// ---------------------------------------------------------------------------
// The KDF every hybrid mode here shares.
//
// HKDF-SHA256 (RFC 5869) with the shared secret as the input keying material
// and a caller-supplied `info` string binding the context. `info` is not
// decoration: two protocols deriving keys from the same ECDH secret must not
// derive the SAME key, and the info string is what separates them. The page
// exposes it, and each pane defaults it to its own name.
// ---------------------------------------------------------------------------
function deriveKey(sharedSecret, info, lengthBytes) {
  log.debug("Entering deriveKey(). info=" + info);
  var out = nobleHkdf(nobleSha256, asBytes(sharedSecret), new Uint8Array(0),
                      bytes.strBytes(info || ''), lengthBytes || 32);
  log.debug("Leaving deriveKey().");
  return asBytes(out);
}

// Wrap a plaintext under a derived key, and unwrap it. Every asymmetric family
// below finishes here, which is what makes their outputs the same shape.
function sealWith(sharedSecret, options) {
  log.debug("Entering sealWith().");
  var opts = options || {};
  var cipherId = opts.cipherId || DEFAULT_CIPHER;
  var spec = symmetric.describe(cipherId);
  var key = deriveKey(sharedSecret, opts.info, spec.keyBytes);
  var iv = symmetric.generateIv(cipherId);
  var sealed = symmetric.encrypt({ id: cipherId, key: key, iv: iv,
                                   aad: opts.aad,
                                   plaintext: opts.plaintext });
  log.debug("Leaving sealWith().");
  return { iv: sealed.iv, ciphertext: sealed.ciphertext, tag: sealed.tag,
           cipherId: cipherId };
}

function openWith(sharedSecret, options) {
  log.debug("Entering openWith().");
  var opts = options || {};
  var cipherId = opts.cipherId || DEFAULT_CIPHER;
  var spec = symmetric.describe(cipherId);
  var key = deriveKey(sharedSecret, opts.info, spec.keyBytes);
  var plain = symmetric.decrypt({ id: cipherId, key: key, iv: opts.iv,
                                  aad: opts.aad,
                                  ciphertext: opts.ciphertext,
                                  tag: opts.tag });
  log.debug("Leaving openWith().");
  return plain;
}

// ===========================================================================
// RSA
// ===========================================================================
// The hashes RSA-OAEP may use. SHA-1 is OAEP's default in PKCS#1 v2.2 and is
// what a great deal of deployed software still sends, which is why it is here;
// it is the MGF1 hash as well, since OAEP uses one hash for both unless told
// otherwise and nothing in the wild says otherwise.
var OAEP_HASHES = {
  'SHA-1': forge.md.sha1,
  'SHA-256': forge.md.sha256,
  'SHA-384': forge.md.sha384,
  'SHA-512': forge.md.sha512
};

var RSA_PADDINGS = {
  'oaep': { forgeScheme: 'RSA-OAEP', label: 'RSA-OAEP (PKCS#1 v2.2)' },
  'v1_5': { forgeScheme: 'RSAES-PKCS1-V1_5',
            label: 'RSAES-PKCS#1 v1.5 (legacy)', security: 'legacy' }
};

function rsaPadding(id) {
  log.debug("Entering rsaPadding(). id=" + id);
  var found = RSA_PADDINGS[String(id || 'oaep')];
  if (!found) {
    log.debug("Leaving rsaPadding(). Unknown.");
    throw new Error('Unknown RSA padding: ' + id);
  }
  log.debug("Leaving rsaPadding().");
  return found;
}

function oaepOptions(hashName) {
  log.debug("Entering oaepOptions(). hash=" + hashName);
  var factory = OAEP_HASHES[hashName || 'SHA-256'];
  if (!factory) {
    log.debug("Leaving oaepOptions(). Unknown hash.");
    throw new Error('Unknown OAEP hash: ' + hashName);
  }
  log.debug("Leaving oaepOptions().");
  return { md: factory.create(), mgf1: { md: factory.create() } };
}

// PKCS#8 for the private half, NOT forge's default PKCS#1.
//
// forge.pki.privateKeyToPem() emits `BEGIN RSA PRIVATE KEY` — PKCS#1, the bare
// RSAPrivateKey structure — and everything else in this tree speaks PKCS#8
// (`BEGIN PRIVATE KEY`): key_material.js's whole keystore matrix, jose_jwe.js's
// key import, and Web Crypto's importKey('pkcs8', …), which is what both of
// those end in. The Download Keys button's JWK format therefore failed with a
// bare `DataError` — no message, because that is what Web Crypto raises when
// the DER is not the structure it was told to expect. forge reads PKCS#8 back
// perfectly well, so nothing here loses anything by emitting it.
//
// The public half is already SPKI (`BEGIN PUBLIC KEY`), which is what
// publicKeyToPem() produces and what every reader here wants.
function rsaGenerateKeyPair(bits) {
  log.debug("Entering rsaGenerateKeyPair(). bits=" + bits);
  var pair = forge.pki.rsa.generateKeyPair({ bits: bits || 2048, e: 0x10001 });
  var pkcs8 = forge.pki.privateKeyInfoToPem(
    forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(pair.privateKey)));
  log.debug("Leaving rsaGenerateKeyPair().");
  return {
    privatePem: pkcs8.trim() + '\n',
    publicPem: forge.pki.publicKeyToPem(pair.publicKey).trim() + '\n'
  };
}

function rsaModulusBytes(publicKey) {
  log.debug("Entering rsaModulusBytes().");
  log.debug("Leaving rsaModulusBytes().");
  return Math.ceil(publicKey.n.bitLength() / 8);
}

// How long a message this key and padding can carry DIRECTLY. Reported by the
// page before the button is pressed, because "the message is too long" is the
// first thing anybody meets here and the number depends on three things at
// once: the modulus, the padding, and — for OAEP — the hash.
function rsaMaxDirectBytes(options) {
  log.debug("Entering rsaMaxDirectBytes().");
  var opts = options || {};
  var publicKey = forge.pki.publicKeyFromPem(opts.publicPem);
  var k = rsaModulusBytes(publicKey);
  var padding = rsaPadding(opts.padding);
  var max;
  if (padding.forgeScheme === 'RSA-OAEP') {
    // k - 2*hLen - 2, PKCS#1 v2.2 section 7.1.1.
    var hLen = OAEP_HASHES[opts.hash || 'SHA-256'].create().digestLength;
    max = k - 2 * hLen - 2;
  } else {
    // k - 11, PKCS#1 v1.5 section 7.2.1.
    max = k - 11;
  }
  log.debug("Leaving rsaMaxDirectBytes(). max=" + max);
  return max;
}

function rsaEncrypt(options) {
  log.debug("Entering rsaEncrypt().");
  var opts = options || {};
  var publicKey = forge.pki.publicKeyFromPem(opts.publicPem);
  var padding = rsaPadding(opts.padding);
  var plaintext = asBytes(opts.plaintext);
  var max = rsaMaxDirectBytes(opts);
  if (plaintext.length > max) {
    log.debug("Leaving rsaEncrypt(). Too long.");
    throw new Error('RSA encrypts at most ' + max + ' bytes directly with ' +
                    'this key and padding, and this message is ' +
                    plaintext.length + '. That is not a limit to work around ' +
                    'by splitting it: use Hybrid, which is what every real ' +
                    'protocol does — RSA wraps a fresh symmetric key and the ' +
                    'message is encrypted under that.');
  }
  var raw = forge.util.binary.raw.encode(plaintext);
  var out = padding.forgeScheme === 'RSA-OAEP'
    ? publicKey.encrypt(raw, 'RSA-OAEP', oaepOptions(opts.hash))
    : publicKey.encrypt(raw, 'RSAES-PKCS1-V1_5');
  log.debug("Leaving rsaEncrypt().");
  return { ciphertext: forge.util.binary.raw.decode(out) };
}

function rsaDecrypt(options) {
  log.debug("Entering rsaDecrypt().");
  var opts = options || {};
  var privateKey = forge.pki.privateKeyFromPem(opts.privatePem);
  var padding = rsaPadding(opts.padding);
  var raw = forge.util.binary.raw.encode(asBytes(opts.ciphertext));
  var out = padding.forgeScheme === 'RSA-OAEP'
    ? privateKey.decrypt(raw, 'RSA-OAEP', oaepOptions(opts.hash))
    : privateKey.decrypt(raw, 'RSAES-PKCS1-V1_5');
  log.debug("Leaving rsaDecrypt().");
  return forge.util.binary.raw.decode(out);
}

// The hybrid form: a fresh symmetric key, wrapped with RSA. This is what
// S/MIME, CMS, JWE's RSA-OAEP and every TLS cipher suite that ever used RSA
// key transport do, and it is the only one of the two that takes a message of
// any length.
function rsaHybridEncrypt(options) {
  log.debug("Entering rsaHybridEncrypt().");
  var opts = options || {};
  var cipherId = opts.cipherId || DEFAULT_CIPHER;
  var spec = symmetric.describe(cipherId);
  var cek = randomBytes(spec.keyBytes);
  var wrapped = rsaEncrypt({ publicPem: opts.publicPem, padding: opts.padding,
                             hash: opts.hash, plaintext: cek });
  var iv = symmetric.generateIv(cipherId);
  var sealed = symmetric.encrypt({ id: cipherId, key: cek, iv: iv,
                                   aad: opts.aad,
                                   plaintext: opts.plaintext });
  log.debug("Leaving rsaHybridEncrypt().");
  return { encapsulation: wrapped.ciphertext, iv: sealed.iv,
           ciphertext: sealed.ciphertext, tag: sealed.tag,
           cipherId: cipherId };
}

function rsaHybridDecrypt(options) {
  log.debug("Entering rsaHybridDecrypt().");
  var opts = options || {};
  var cipherId = opts.cipherId || DEFAULT_CIPHER;
  var cek = rsaDecrypt({ privatePem: opts.privatePem, padding: opts.padding,
                         hash: opts.hash, ciphertext: opts.encapsulation });
  var plain = symmetric.decrypt({ id: cipherId, key: cek, iv: opts.iv,
                                  aad: opts.aad,
                                  ciphertext: opts.ciphertext,
                                  tag: opts.tag });
  log.debug("Leaving rsaHybridDecrypt().");
  return plain;
}

// ===========================================================================
// ECC — ECIES
// ===========================================================================
// X25519 is in this list and is NOT a signature curve: it exists only for
// key agreement, which is exactly what this pane does, and it is the one the
// Digital Signature page's ECC pane cannot offer for the mirror-image reason.
var ECIES_CURVES = {
  'P-256': { curve: p256, label: 'P-256 (secp256r1)', montgomery: false },
  'P-384': { curve: p384, label: 'P-384 (secp384r1)', montgomery: false },
  'P-521': { curve: p521, label: 'P-521 (secp521r1)', montgomery: false },
  'secp256k1': { curve: secp256k1, label: 'secp256k1', montgomery: false },
  'X25519': { curve: x25519, label: 'X25519 (key agreement only)',
              montgomery: true }
};

var ECIES_CURVE_ORDER = ['P-256', 'P-384', 'P-521', 'secp256k1', 'X25519'];

function eciesCurveIds() {
  log.debug("Entering eciesCurveIds().");
  log.debug("Leaving eciesCurveIds().");
  return ECIES_CURVE_ORDER.slice();
}

function eciesCurve(id) {
  log.debug("Entering eciesCurve(). id=" + id);
  var found = ECIES_CURVES[id];
  if (!found) {
    log.debug("Leaving eciesCurve(). Unknown.");
    throw new Error('Unknown curve: ' + id);
  }
  log.debug("Leaving eciesCurve().");
  return found;
}

function eciesGenerateKeyPair(curveId) {
  log.debug("Entering eciesGenerateKeyPair(). curve=" + curveId);
  var descriptor = eciesCurve(curveId);
  var priv = descriptor.montgomery
    ? x25519.utils.randomPrivateKey()
    : descriptor.curve.utils.randomPrivateKey();
  var pub = descriptor.curve.getPublicKey(priv);
  log.debug("Leaving eciesGenerateKeyPair().");
  return { privateKeyHex: bytesToHex(priv), publicKeyHex: bytesToHex(pub) };
}

// The agreed secret. For the Weierstrass curves @noble returns the compressed
// POINT, whose first byte is the sign of y — the x coordinate alone is the
// shared secret (SEC 1's ECDH primitive), so that prefix is dropped. Feeding
// the whole point to the KDF would still "work" between two copies of this
// code and interoperate with nothing.
function eciesSharedSecret(descriptor, privateKey, publicKey) {
  log.debug("Entering eciesSharedSecret().");
  if (descriptor.montgomery) {
    log.debug("Leaving eciesSharedSecret(). X25519.");
    return asBytes(x25519.getSharedSecret(privateKey, publicKey));
  }
  var point = asBytes(descriptor.curve.getSharedSecret(privateKey, publicKey));
  log.debug("Leaving eciesSharedSecret(). Weierstrass, x coordinate only.");
  return point.slice(1);
}

function eciesEncrypt(options) {
  log.debug("Entering eciesEncrypt().");
  var opts = options || {};
  var descriptor = eciesCurve(opts.curve);
  var recipient = hexToBytes(opts.publicKeyHex);
  // Ephemeral-static: a fresh key pair per message, which is what makes two
  // encryptions of the same plaintext to the same recipient differ, and what
  // the "E" in ECIES is.
  var ephemeral = eciesGenerateKeyPair(opts.curve);
  var secret = eciesSharedSecret(descriptor,
      hexToBytes(ephemeral.privateKeyHex), recipient);
  var sealed = sealWith(secret, { info: opts.info, aad: opts.aad,
                                  cipherId: opts.cipherId,
                                  plaintext: opts.plaintext });
  log.debug("Leaving eciesEncrypt().");
  return { encapsulation: hexToBytes(ephemeral.publicKeyHex), iv: sealed.iv,
           ciphertext: sealed.ciphertext, tag: sealed.tag,
           cipherId: sealed.cipherId };
}

function eciesDecrypt(options) {
  log.debug("Entering eciesDecrypt().");
  var opts = options || {};
  var descriptor = eciesCurve(opts.curve);
  var secret = eciesSharedSecret(descriptor, hexToBytes(opts.privateKeyHex),
                                 asBytes(opts.encapsulation));
  var plain = openWith(secret, { info: opts.info, aad: opts.aad,
                                 cipherId: opts.cipherId, iv: opts.iv,
                                 ciphertext: opts.ciphertext, tag: opts.tag });
  log.debug("Leaving eciesDecrypt().");
  return plain;
}

// ===========================================================================
// ML-KEM — FIPS 203, the post-quantum one
// ===========================================================================
// A KEM does not take a message at all: encapsulate() takes only the
// recipient's public key and returns a ciphertext AND a fresh shared secret,
// which is then the key. That is why this pane cannot have a "direct" mode the
// way RSA does — there is nothing to put a message into.
var ML_KEM_SETS = {
  'ML-KEM-512': { kem: mlkem.ml_kem512, label: 'ML-KEM-512 (category 1)' },
  'ML-KEM-768': { kem: mlkem.ml_kem768, label: 'ML-KEM-768 (category 3)' },
  'ML-KEM-1024': { kem: mlkem.ml_kem1024, label: 'ML-KEM-1024 (category 5)' }
};

var ML_KEM_ORDER = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];

function mlkemSetIds() {
  log.debug("Entering mlkemSetIds().");
  log.debug("Leaving mlkemSetIds().");
  return ML_KEM_ORDER.slice();
}

function mlkemSet(id) {
  log.debug("Entering mlkemSet(). id=" + id);
  var found = ML_KEM_SETS[id];
  if (!found) {
    log.debug("Leaving mlkemSet(). Unknown.");
    throw new Error('Unknown ML-KEM parameter set: ' + id);
  }
  log.debug("Leaving mlkemSet().");
  return found;
}

// The hybrid. Its shared secret is the ML-KEM secret CONCATENATED with an
// X25519 one, and the reason is the whole argument for hybrids: the result is
// no weaker than the stronger of the two, so a break of either leaves the
// other holding. This is the shape TLS's X25519MLKEM768 uses. `hybrid` on the
// descriptor is what tells the page to emit two encapsulations.
function mlkemGenerateKeyPair(setId, hybrid) {
  log.debug("Entering mlkemGenerateKeyPair(). set=" + setId);
  var pair = mlkemSet(setId).kem.keygen();
  var result = { privateKeyHex: bytesToHex(pair.secretKey),
                 publicKeyHex: bytesToHex(pair.publicKey) };
  if (hybrid) {
    var classical = eciesGenerateKeyPair('X25519');
    result.privateKeyHex += ':' + classical.privateKeyHex;
    result.publicKeyHex += ':' + classical.publicKeyHex;
  }
  log.debug("Leaving mlkemGenerateKeyPair().");
  return result;
}

// A hybrid key is written "<ml-kem hex>:<x25519 hex>" in the page's key
// fields, because one field holding two keys is easier to carry around than
// two fields that must not be mismatched.
function splitHybridKey(hex, hybrid) {
  log.debug("Entering splitHybridKey().");
  var parts = String(hex || '').split(':');
  if (!hybrid) {
    log.debug("Leaving splitHybridKey(). Not hybrid.");
    return { pq: hexToBytes(parts[0] || ''), classical: null };
  }
  if (parts.length !== 2) {
    log.debug("Leaving splitHybridKey(). Malformed.");
    throw new Error('A hybrid key is two keys separated by a colon ' +
                    '("<ML-KEM hex>:<X25519 hex>"). This value has ' +
                    parts.length + ' part(s) — it is probably a plain ML-KEM ' +
                    'key, generated before Hybrid was selected.');
  }
  log.debug("Leaving splitHybridKey(). Hybrid.");
  return { pq: hexToBytes(parts[0]), classical: hexToBytes(parts[1]) };
}

function mlkemEncrypt(options) {
  log.debug("Entering mlkemEncrypt().");
  var opts = options || {};
  var set = mlkemSet(opts.paramSet);
  var keys = splitHybridKey(opts.publicKeyHex, opts.hybrid);
  var encapsulated = set.kem.encapsulate(keys.pq);
  var secret = asBytes(encapsulated.sharedSecret);
  var encapsulation = bytesToHex(encapsulated.cipherText);
  if (opts.hybrid) {
    var ephemeral = eciesGenerateKeyPair('X25519');
    secret = concatBytes(secret,
      eciesSharedSecret(eciesCurve('X25519'),
                        hexToBytes(ephemeral.privateKeyHex), keys.classical));
    encapsulation += ':' + ephemeral.publicKeyHex;
  }
  var sealed = sealWith(secret, { info: opts.info, aad: opts.aad,
                                  cipherId: opts.cipherId,
                                  plaintext: opts.plaintext });
  log.debug("Leaving mlkemEncrypt().");
  return { encapsulationHex: encapsulation, iv: sealed.iv,
           ciphertext: sealed.ciphertext, tag: sealed.tag,
           cipherId: sealed.cipherId };
}

function mlkemDecrypt(options) {
  log.debug("Entering mlkemDecrypt().");
  var opts = options || {};
  var set = mlkemSet(opts.paramSet);
  var keys = splitHybridKey(opts.privateKeyHex, opts.hybrid);
  var parts = String(opts.encapsulationHex || '').split(':');
  if (opts.hybrid && parts.length !== 2) {
    log.debug("Leaving mlkemDecrypt(). Malformed encapsulation.");
    throw new Error('A hybrid encapsulation is two values separated by a ' +
                    'colon. This one has ' + parts.length + ' part(s).');
  }
  var secret = asBytes(set.kem.decapsulate(hexToBytes(parts[0]), keys.pq));
  if (opts.hybrid) {
    secret = concatBytes(secret,
      eciesSharedSecret(eciesCurve('X25519'), keys.classical,
                        hexToBytes(parts[1])));
  }
  var plain = openWith(secret, { info: opts.info, aad: opts.aad,
                                 cipherId: opts.cipherId, iv: opts.iv,
                                 ciphertext: opts.ciphertext, tag: opts.tag });
  log.debug("Leaving mlkemDecrypt().");
  return plain;
}

// ===========================================================================
// FFC — the finite-field family (this is where DSA's group lives)
// ===========================================================================
// The MODP groups of RFC 3526, which are the ones IKE, SSH and TLS's
// finite-field Diffie-Hellman use. Generating a fresh safe prime in a browser
// is minutes of work for no benefit — a DH group is public and shared by
// design, which is the whole reason these are published as named groups.
var _FFC_PREFIX =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AA';

var FFC_GROUPS = {
  'modp-2048': {
    label: 'RFC 3526 group 14 (2048-bit MODP)',
    g: '2',
    p: _FFC_PREFIX + 'CAA68FFFFFFFFFFFFFFFF'
  },
  'modp-3072': {
    label: 'RFC 3526 group 15 (3072-bit MODP)',
    g: '2',
    p: _FFC_PREFIX + 'AC42DAD33170D04507A33A85521ABDF1CBA64' +
       'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
       'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
       'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
       'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
       '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
  }
};

var FFC_GROUP_ORDER = ['modp-2048', 'modp-3072'];

function ffcGroupIds() {
  log.debug("Entering ffcGroupIds().");
  log.debug("Leaving ffcGroupIds().");
  return FFC_GROUP_ORDER.slice();
}

function ffcGroup(id) {
  log.debug("Entering ffcGroup(). id=" + id);
  var found = FFC_GROUPS[id];
  if (!found) {
    log.debug("Leaving ffcGroup(). Unknown.");
    throw new Error('Unknown MODP group: ' + id);
  }
  log.debug("Leaving ffcGroup().");
  return {
    id: id,
    label: found.label,
    p: new forge.jsbn.BigInteger(found.p, 16),
    g: new forge.jsbn.BigInteger(found.g, 10),
    bytes: Math.ceil(found.p.length * 4 / 8)
  };
}

// A private exponent. 256 bits rather than the full length of p: with a group
// this size the discrete log is bounded by the square root of the exponent
// space, so 256 bits gives 128-bit security and every modPow below is eight
// times faster than it would otherwise be. This is what RFC 3526 section 8
// says to do.
function ffcGenerateKeyPair(groupId) {
  log.debug("Entering ffcGenerateKeyPair(). group=" + groupId);
  var group = ffcGroup(groupId);
  var x = new forge.jsbn.BigInteger(bytesToHex(randomBytes(32)), 16);
  var y = group.g.modPow(x, group.p);
  log.debug("Leaving ffcGenerateKeyPair().");
  return { privateKeyHex: x.toString(16), publicKeyHex: y.toString(16) };
}

function ffcSharedSecret(group, exponentHex, baseHex) {
  log.debug("Entering ffcSharedSecret().");
  var exponent = new forge.jsbn.BigInteger(exponentHex, 16);
  var base = new forge.jsbn.BigInteger(baseHex, 16);
  var z = base.modPow(exponent, group.p);
  // Left-padded to the size of p, per RFC 5114 / SP 800-56A: an agreed value
  // that happens to start with a zero byte must still be the same number of
  // bytes on both sides, or the two ends derive different keys about one time
  // in 256 and it looks like an intermittent fault.
  log.debug("Leaving ffcSharedSecret().");
  return hexToBytes(padHex(z.toString(16), group.bytes * 2));
}

function padHex(hex, length) {
  log.debug("Entering padHex().");
  var out = String(hex);
  while (out.length < length) out = '0' + out;
  log.debug("Leaving padHex().");
  return out;
}

// --- Textbook ElGamal -------------------------------------------------------
// c1 = g^k, c2 = m * y^k mod p. This is the encryption scheme DSA's key
// structure comes from, and it is offered because "what does a DSA-shaped key
// do when it encrypts" has a real answer worth seeing.
//
// It is TEXTBOOK, which the pane says: no padding, so it is malleable —
// multiplying c2 by any t multiplies the plaintext by t, and the recipient
// cannot tell. The message is length-limited to the group, exactly like RSA's
// direct mode, and for the same reason. Use the hybrid for anything real.
function elgamalMaxBytes(groupId) {
  log.debug("Entering elgamalMaxBytes().");
  var group = ffcGroup(groupId);
  log.debug("Leaving elgamalMaxBytes().");
  return group.bytes - 2;
}

// A 0x01 marker in front of the message, so that a plaintext with leading zero
// bytes survives the trip through an integer and back.
function elgamalEncrypt(options) {
  log.debug("Entering elgamalEncrypt().");
  var opts = options || {};
  var group = ffcGroup(opts.group);
  var plaintext = asBytes(opts.plaintext);
  var max = elgamalMaxBytes(opts.group);
  if (plaintext.length > max) {
    log.debug("Leaving elgamalEncrypt(). Too long.");
    throw new Error('Textbook ElGamal over this group encrypts at most ' +
                    max + ' bytes, and this message is ' + plaintext.length +
                    '. Use Hybrid (DHIES) for a message of any length.');
  }
  var m = new forge.jsbn.BigInteger(
      '01' + bytesToHex(plaintext), 16);
  var k = new forge.jsbn.BigInteger(bytesToHex(randomBytes(32)), 16);
  var y = new forge.jsbn.BigInteger(opts.publicKeyHex, 16);
  var c1 = group.g.modPow(k, group.p);
  var c2 = m.multiply(y.modPow(k, group.p)).mod(group.p);
  log.debug("Leaving elgamalEncrypt().");
  return { c1Hex: padHex(c1.toString(16), group.bytes * 2),
           c2Hex: padHex(c2.toString(16), group.bytes * 2) };
}

function elgamalDecrypt(options) {
  log.debug("Entering elgamalDecrypt().");
  var opts = options || {};
  var group = ffcGroup(opts.group);
  var x = new forge.jsbn.BigInteger(opts.privateKeyHex, 16);
  var c1 = new forge.jsbn.BigInteger(opts.c1Hex, 16);
  var c2 = new forge.jsbn.BigInteger(opts.c2Hex, 16);
  var s = c1.modPow(x, group.p);
  var m = c2.multiply(s.modInverse(group.p)).mod(group.p);
  var hex = m.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (hex.slice(0, 2) !== '01') {
    log.debug("Leaving elgamalDecrypt(). No marker.");
    throw new Error('This did not decrypt to a message produced here: the ' +
                    'recovered value has no 0x01 length marker. The private ' +
                    'key, the group, or one of the two ciphertext halves is ' +
                    'not the right one. Note that textbook ElGamal is ' +
                    'unauthenticated, so a modified ciphertext usually ' +
                    'decrypts to something rather than failing.');
  }
  log.debug("Leaving elgamalDecrypt().");
  return hexToBytes(hex.slice(2));
}

// --- DHIES over the same group ---------------------------------------------
// The hybrid: an ephemeral DH key pair, the agreed secret through HKDF, and an
// AEAD over the message. Same shape as ECIES, different group.
function ffcHybridEncrypt(options) {
  log.debug("Entering ffcHybridEncrypt().");
  var opts = options || {};
  var group = ffcGroup(opts.group);
  var ephemeral = ffcGenerateKeyPair(opts.group);
  var secret = ffcSharedSecret(group, ephemeral.privateKeyHex,
                               opts.publicKeyHex);
  var sealed = sealWith(secret, { info: opts.info, aad: opts.aad,
                                  cipherId: opts.cipherId,
                                  plaintext: opts.plaintext });
  log.debug("Leaving ffcHybridEncrypt().");
  return { encapsulationHex: padHex(ephemeral.publicKeyHex, group.bytes * 2),
           iv: sealed.iv, ciphertext: sealed.ciphertext, tag: sealed.tag,
           cipherId: sealed.cipherId };
}

function ffcHybridDecrypt(options) {
  log.debug("Entering ffcHybridDecrypt().");
  var opts = options || {};
  var group = ffcGroup(opts.group);
  var secret = ffcSharedSecret(group, opts.privateKeyHex,
                               opts.encapsulationHex);
  var plain = openWith(secret, { info: opts.info, aad: opts.aad,
                                 cipherId: opts.cipherId, iv: opts.iv,
                                 ciphertext: opts.ciphertext, tag: opts.tag });
  log.debug("Leaving ffcHybridDecrypt().");
  return plain;
}

module.exports = {
  DEFAULT_CIPHER: DEFAULT_CIPHER,
  deriveKey: deriveKey,
  // RSA
  OAEP_HASHES: OAEP_HASHES,
  RSA_PADDINGS: RSA_PADDINGS,
  rsaGenerateKeyPair: rsaGenerateKeyPair,
  rsaMaxDirectBytes: rsaMaxDirectBytes,
  rsaEncrypt: rsaEncrypt,
  rsaDecrypt: rsaDecrypt,
  rsaHybridEncrypt: rsaHybridEncrypt,
  rsaHybridDecrypt: rsaHybridDecrypt,
  // ECIES
  ECIES_CURVES: ECIES_CURVES,
  eciesCurveIds: eciesCurveIds,
  eciesCurve: eciesCurve,
  eciesGenerateKeyPair: eciesGenerateKeyPair,
  eciesSharedSecret: eciesSharedSecret,
  eciesEncrypt: eciesEncrypt,
  eciesDecrypt: eciesDecrypt,
  // ML-KEM
  ML_KEM_SETS: ML_KEM_SETS,
  mlkemSetIds: mlkemSetIds,
  mlkemSet: mlkemSet,
  mlkemGenerateKeyPair: mlkemGenerateKeyPair,
  mlkemEncrypt: mlkemEncrypt,
  mlkemDecrypt: mlkemDecrypt,
  // FFC / DSA-family
  FFC_GROUPS: FFC_GROUPS,
  ffcGroupIds: ffcGroupIds,
  ffcGroup: ffcGroup,
  ffcGenerateKeyPair: ffcGenerateKeyPair,
  ffcSharedSecret: ffcSharedSecret,
  elgamalMaxBytes: elgamalMaxBytes,
  elgamalEncrypt: elgamalEncrypt,
  elgamalDecrypt: elgamalDecrypt,
  ffcHybridEncrypt: ffcHybridEncrypt,
  ffcHybridDecrypt: ffcHybridDecrypt
};
