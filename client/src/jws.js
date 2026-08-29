// File: jws.js
// Author: Robert C. Broeckelmann Jr.
//
// ---------------------------------------------------------------------------
// JSON Web Signature (RFC 7515), with the algorithms of RFC 7518 section 3.1,
// the Edwards curves of RFC 8037, the secp256k1 of RFC 8812, and the
// unencoded payload of RFC 7797.
//
// It has NO DOM. That is the whole point of it being a module rather than a
// handful of functions inside digital_signature.js: a JWS is a wire format
// somebody else's library has to read, so `tests/jws_engine.js` drives every
// algorithm and every serialization in node and hands the result to node's own
// OpenSSL and to `jsonwebtoken` — the only kind of check that catches a
// signature which is self-consistent and interoperates with nothing. Three
// defects that class produces and a round trip through this file cannot see:
// an ECDSA signature left in DER instead of the R||S concatenation JOSE
// requires (section 3.4), a PSS salt length that is not the hash length
// (section 3.5), and a payload re-serialized between signing and encoding, so
// that the octets signed are not the octets sent.
//
// IT HAS TWO CRYPTO BACKENDS, and the caller chooses. The `js` backend is
// node-forge and @noble, and it is the default: crypto.subtle has no secp256k1
// and no Ed448 — both registered JOSE algorithms — and it does not exist
// outside a secure context, which the containerized test origin is not. The
// `webcrypto` backend is crypto.subtle, and it exists because four workflows
// were already signing with it when this module absorbed them: DPoP proofs,
// OID4VCI credential proofs, SD-JWT VC Key Binding JWTs and the JWT Tools Sign
// pane. Routing those through here makes the JOSE half single-sourced — one
// algorithm table, one signing input, one serialization, one place that knows
// Web Crypto returns ECDSA as the raw R||S pair JWS already wants — WITHOUT
// changing a byte of what those four produce, which is the part no test in
// this repository could have caught if it had changed.
//
// KEY MATERIAL ARRIVES IN WHATEVER FORM THE CALLER HAS. A PEM (PKCS#8, SPKI or
// a CERTIFICATE), a JWK, a whole JWK Set, raw bytes, an HMAC secret in text /
// hex / base64url, or a Web Crypto CryptoKey. That flexibility is not a
// convenience: it is what let five pages stop each carrying their own reading
// of "the user pasted something". Two of those readings were wrong in the same
// way and neither page knew — see spkiFromCertificatePem() below.
//
// WHAT IS DELIBERATELY NOT HERE: JWE (that is jose_jwe.js), and the JWT claim
// semantics (that is jwt_tools.js). This file signs and verifies octets. The
// PAYLOAD IS SIGNED EXACTLY AS GIVEN — it is never reformatted, because
// re-serializing a JSON payload between validating it and signing it changes
// the bytes under the signature and produces a JWS whose payload no longer
// matches what the caller saw. `validateJson()` therefore reports on a string
// and returns it unchanged; a caller that WANTS the compact form asks for it
// before signing, with compactJson().
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "jws",
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

var forge = require("node-forge");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var ed448 = require("@noble/curves/ed448").ed448;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");
var nobleHmac = require("@noble/hashes/hmac").hmac;
var bytesLib = require("./crypto_bytes");
var pkEncryption = require("./pk_encryption");
var pqc = require("./pqc");

var strBytes = bytesLib.strBytes;
var bytesToStr = bytesLib.bytesToStr;
var bytesToB64u = bytesLib.bytesToB64u;
var b64uToBytes = bytesLib.b64uToBytes;
var strToB64u = bytesLib.strToB64u;
var concatBytes = bytesLib.concatBytes;
var bigToBytes = bytesLib.bigToBytes;

// ---------------------------------------------------------------------------
// The hashes JOSE uses. Only the SHA-2 family appears in any registered JWS
// algorithm, which is why this table is three lines rather than the eleven the
// RSA and ECC panes carry: those panes exist to pair a signature with a hash
// nobody standardised, and a JWS header value is a registered name.
// ---------------------------------------------------------------------------
var HASHES = {
  'SHA-256': { noble: nobleSha256, forge: forge.md.sha256, bytes: 32 },
  'SHA-384': { noble: nobleSha512.sha384, forge: forge.md.sha384, bytes: 48 },
  'SHA-512': { noble: nobleSha512.sha512, forge: forge.md.sha512, bytes: 64 }
};

function hashOf(hashName, bytes) {
  log.debug("Entering hashOf().");
  var h = HASHES[hashName];
  if (!h) throw new Error('Unknown hash: ' + hashName);
  log.debug("Leaving hashOf().");
  return h.noble(bytes);
}

function forgeMd(hashName) {
  log.debug("Entering forgeMd().");
  var h = HASHES[hashName];
  if (!h) throw new Error('Unknown hash: ' + hashName);
  log.debug("Leaving forgeMd().");
  return h.forge.create();
}

// ---------------------------------------------------------------------------
// The algorithm table — RFC 7518 section 3.1 in full, plus the two extensions
// that add a registered `alg` value rather than a new kind of key.
//
// `req` is the specification's OWN implementation requirement, carried here so
// the page can show it rather than assert it: RFC 7518 makes exactly one
// algorithm Required (HS256), two Recommended (RS256, ES256 — ES256 at
// "Recommended+"), and everything else Optional. It matters because "supported"
// and "required" are different claims and a debugger that blurs them teaches
// the wrong thing about what a peer must accept.
//
// THE KEY OF THIS TABLE IS NOT ALWAYS THE HEADER VALUE. `alg` is what goes in
// the protected header; EdDSA is one registered `alg` covering two curves
// (RFC 8037 section 3.1 — the curve is in the KEY, not the header), so the two
// are separate rows with one `alg` between them, and verification tells them
// apart by the length of the public key rather than by anything in the JWS.
// ---------------------------------------------------------------------------
var ALGS = {
  HS256: { alg: 'HS256', family: 'hmac', hash: 'SHA-256',
           req: 'Required', spec: 'RFC 7518 §3.2',
           label: 'HS256 — HMAC-SHA-256 (required)' },
  HS384: { alg: 'HS384', family: 'hmac', hash: 'SHA-384',
           req: 'Optional', spec: 'RFC 7518 §3.2',
           label: 'HS384 — HMAC-SHA-384' },
  HS512: { alg: 'HS512', family: 'hmac', hash: 'SHA-512',
           req: 'Optional', spec: 'RFC 7518 §3.2',
           label: 'HS512 — HMAC-SHA-512' },
  RS256: { alg: 'RS256', family: 'rsa', pad: 'v1_5', hash: 'SHA-256',
           req: 'Recommended', spec: 'RFC 7518 §3.3',
           label: 'RS256 — RSASSA-PKCS1-v1_5 SHA-256 (recommended)' },
  RS384: { alg: 'RS384', family: 'rsa', pad: 'v1_5', hash: 'SHA-384',
           req: 'Optional', spec: 'RFC 7518 §3.3',
           label: 'RS384 — RSASSA-PKCS1-v1_5 SHA-384' },
  RS512: { alg: 'RS512', family: 'rsa', pad: 'v1_5', hash: 'SHA-512',
           req: 'Optional', spec: 'RFC 7518 §3.3',
           label: 'RS512 — RSASSA-PKCS1-v1_5 SHA-512' },
  ES256: { alg: 'ES256', family: 'ec', curve: p256, crv: 'P-256',
           hash: 'SHA-256', fieldBytes: 32,
           req: 'Recommended+', spec: 'RFC 7518 §3.4',
           label: 'ES256 — ECDSA P-256 SHA-256 (recommended+)' },
  ES384: { alg: 'ES384', family: 'ec', curve: p384, crv: 'P-384',
           hash: 'SHA-384', fieldBytes: 48,
           req: 'Optional', spec: 'RFC 7518 §3.4',
           label: 'ES384 — ECDSA P-384 SHA-384' },
  ES512: { alg: 'ES512', family: 'ec', curve: p521, crv: 'P-521',
           hash: 'SHA-512', fieldBytes: 66,
           req: 'Optional', spec: 'RFC 7518 §3.4',
           label: 'ES512 — ECDSA P-521 SHA-512' },
  PS256: { alg: 'PS256', family: 'rsa', pad: 'pss', hash: 'SHA-256',
           req: 'Optional', spec: 'RFC 7518 §3.5',
           label: 'PS256 — RSASSA-PSS SHA-256 / MGF1-SHA-256' },
  PS384: { alg: 'PS384', family: 'rsa', pad: 'pss', hash: 'SHA-384',
           req: 'Optional', spec: 'RFC 7518 §3.5',
           label: 'PS384 — RSASSA-PSS SHA-384 / MGF1-SHA-384' },
  PS512: { alg: 'PS512', family: 'rsa', pad: 'pss', hash: 'SHA-512',
           req: 'Optional', spec: 'RFC 7518 §3.5',
           label: 'PS512 — RSASSA-PSS SHA-512 / MGF1-SHA-512' },
  // RFC 8037: one `alg` value, two curves. The curve lives in the key.
  'EdDSA-Ed25519': { alg: 'EdDSA', family: 'okp', curve: ed25519,
                     crv: 'Ed25519', pubBytes: 32,
                     req: 'Optional', spec: 'RFC 8037 §3.1',
                     label: 'EdDSA — Ed25519' },
  'EdDSA-Ed448': { alg: 'EdDSA', family: 'okp', curve: ed448,
                   crv: 'Ed448', pubBytes: 57,
                   req: 'Optional', spec: 'RFC 8037 §3.1',
                   label: 'EdDSA — Ed448' },
  // RFC 8812 §3.2. The curve name in a JWK is "secp256k1"; the `alg` is its
  // own registered value rather than an ES256 over a different curve.
  ES256K: { alg: 'ES256K', family: 'ec', curve: secp256k1, crv: 'secp256k1',
            hash: 'SHA-256', fieldBytes: 32,
            req: 'Optional', spec: 'RFC 8812 §3.2',
            label: 'ES256K — ECDSA secp256k1 SHA-256' },
  // -------------------------------------------------------------------
  // POST-QUANTUM. One family, four specifications, and only ONE of them is
  // published — which is why every row carries `pqSpec` into pqc.js's SPECS
  // table and the pane renders a draft warning from it. See pqc.js.
  //
  // The `alg` value IS the table key for all of these, unlike EdDSA: each
  // parameter set has its own registered name, so nothing has to be guessed
  // from a key length.
  //
  // FN-DSA IS ALSO NOT HERE, and for a different reason from the SLH-DSA
  // parameter sets below: draft-ietf-cose-falcon-04 DOES register
  // `FN-DSA-512` and `FN-DSA-1024`, so the identifiers exist. What is missing
  // is an implementation this bundle can load — see the header of pqc.js and
  // its MISSING table. Adding the rows without a signer would produce an
  // `alg` the page offers and cannot honour, which is worse than an absence.
  //
  // WHAT IS NOT HERE: the other ten SLH-DSA parameter sets. FIPS 205 defines
  // twelve and this page's raw SLH-DSA pane offers all twelve, but
  // draft-ietf-cose-sphincs-plus-10 registers exactly two — one NIST
  // category 1 "small" set per hash family — and says so deliberately, to
  // keep early implementations interoperable. A JWS `alg` of
  // "SLH-DSA-SHA2-256f" would be this project's invention, so it does not
  // exist here.
  'ML-DSA-44': { alg: 'ML-DSA-44', family: 'pq', pqName: 'ML-DSA-44',
                 pqSpec: 'RFC.9964', req: 'Optional', spec: 'RFC 9964 §2',
                 label: 'ML-DSA-44 — FIPS 204 (RFC 9964)' },
  'ML-DSA-65': { alg: 'ML-DSA-65', family: 'pq', pqName: 'ML-DSA-65',
                 pqSpec: 'RFC.9964', req: 'Optional', spec: 'RFC 9964 §2',
                 label: 'ML-DSA-65 — FIPS 204 (RFC 9964)' },
  'ML-DSA-87': { alg: 'ML-DSA-87', family: 'pq', pqName: 'ML-DSA-87',
                 pqSpec: 'RFC.9964', req: 'Optional', spec: 'RFC 9964 §2',
                 label: 'ML-DSA-87 — FIPS 204 (RFC 9964)' },
  'SLH-DSA-SHA2-128s': { alg: 'SLH-DSA-SHA2-128s', family: 'pq',
                 pqName: 'SLH-DSA-SHA2-128s',
                 pqSpec: 'I-D.cose-sphincs-plus', req: 'Optional',
                 spec: 'draft-ietf-cose-sphincs-plus-10',
                 label: 'SLH-DSA-SHA2-128s — FIPS 205 (draft)' },
  'SLH-DSA-SHAKE-128s': { alg: 'SLH-DSA-SHAKE-128s', family: 'pq',
                 pqName: 'SLH-DSA-SHAKE-128s',
                 pqSpec: 'I-D.cose-sphincs-plus', req: 'Optional',
                 spec: 'draft-ietf-cose-sphincs-plus-10',
                 label: 'SLH-DSA-SHAKE-128s — FIPS 205 (draft)' },
  'ML-DSA-44-ES256': { alg: 'ML-DSA-44-ES256', family: 'pq',
                 pqName: 'ML-DSA-44-ES256',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-44-ES256 — composite PQ/T (draft)' },
  'ML-DSA-65-ES256': { alg: 'ML-DSA-65-ES256', family: 'pq',
                 pqName: 'ML-DSA-65-ES256',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-65-ES256 — composite PQ/T (draft)' },
  'ML-DSA-87-ES384': { alg: 'ML-DSA-87-ES384', family: 'pq',
                 pqName: 'ML-DSA-87-ES384',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-87-ES384 — composite PQ/T (draft)' },
  'ML-DSA-44-Ed25519': { alg: 'ML-DSA-44-Ed25519', family: 'pq',
                 pqName: 'ML-DSA-44-Ed25519',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-44-Ed25519 — composite PQ/T (draft)' },
  'ML-DSA-65-Ed25519': { alg: 'ML-DSA-65-Ed25519', family: 'pq',
                 pqName: 'ML-DSA-65-Ed25519',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-65-Ed25519 — composite PQ/T (draft)' },
  'ML-DSA-87-Ed448': { alg: 'ML-DSA-87-Ed448', family: 'pq',
                 pqName: 'ML-DSA-87-Ed448',
                 pqSpec: 'I-D.jose-pq-composite-sigs', req: 'Optional',
                 spec: 'draft-ietf-jose-pq-composite-sigs-03',
                 label: 'ML-DSA-87-Ed448 — composite PQ/T (draft)' },
  // RFC 7515 §6 / RFC 7518 §3.6. It is in the registry, it is Optional, and
  // it authenticates nothing — which is the reason to be able to produce one:
  // a relying party that accepts it has a critical defect, and this is how you
  // demonstrate that to them.
  none: { alg: 'none', family: 'none',
          req: 'Optional', spec: 'RFC 7518 §3.6',
          label: 'none — Unsecured JWS (NO signature)' }
};

function algIds() {
  log.debug("Entering algIds().");
  log.debug("Leaving algIds().");
  return Object.keys(ALGS);
}

function algSpec(algId) {
  log.debug("Entering algSpec().");
  var a = ALGS[algId];
  if (!a) throw new Error('Unknown JWS algorithm: ' + algId);
  log.debug("Leaving algSpec().");
  return a;
}

// Resolve a HEADER `alg` value back to a row of the table. Everything but
// EdDSA is one-to-one; EdDSA is decided by the length of the key in hand,
// because RFC 8037 puts the curve in the JWK and not in the header — so a
// verifier with the wrong-length key gets "Ed448 key with an Ed25519
// signature" rather than a bare curve error from deep inside @noble.
function algForHeader(headerAlg, keyBytes) {
  log.debug("Entering algForHeader().");
  if (headerAlg !== 'EdDSA') {
    var direct = ALGS[headerAlg];
    if (!direct) throw new Error('Unsupported "alg" header value: ' +
        headerAlg);
    log.debug("Leaving algForHeader().");
    return direct;
  }
  var len = keyBytes ? keyBytes.length : 0;
  if (len === 57 || len === 114) {
    log.debug("Leaving algForHeader(). Ed448.");
    return ALGS['EdDSA-Ed448'];
  }
  if (len === 32 || len === 64) {
    log.debug("Leaving algForHeader(). Ed25519.");
    return ALGS['EdDSA-Ed25519'];
  }
  throw new Error('EdDSA key length ' + len + ' is neither Ed25519 (32) ' +
      'nor Ed448 (57) — RFC 8037 puts the curve in the key, so the key is ' +
      'the only thing that can say which one this is.');
}

// ---------------------------------------------------------------------------
// The signing primitives. One function per family, each taking and returning
// bytes, so signJws()/verifyJws() below are about the SERIALIZATION and
// nothing else.
// ---------------------------------------------------------------------------
function rsaPssParams(hashName) {
  log.debug("Entering rsaPssParams().");
  // RFC 7518 §3.5: MGF1 with the SAME hash, and a salt of the hash's own
  // length. Both are fixed by the specification; neither is a choice, and a
  // salt of some other length verifies against nothing else on earth.
  var pss = forge.pss.create({
    md: forgeMd(hashName),
    mgf: forge.mgf.mgf1.create(forgeMd(hashName)),
    saltLength: HASHES[hashName].bytes
  });
  log.debug("Leaving rsaPssParams().");
  return pss;
}

function signOctets(spec, key, octets) {
  log.debug("Entering signOctets(). alg=" + spec.alg);
  if (spec.family === 'none') {
    log.debug("Leaving signOctets(). Unsecured.");
    return new Uint8Array(0);
  }
  if (spec.family === 'hmac') {
    log.debug("Leaving signOctets(). HMAC.");
    return nobleHmac(HASHES[spec.hash].noble, key, octets);
  }
  if (spec.family === 'rsa') {
    var priv = forge.pki.privateKeyFromPem(key);
    var md = forgeMd(spec.hash);
    md.update(forge.util.binary.raw.encode(octets));
    var raw = spec.pad === 'pss' ? priv.sign(md, rsaPssParams(spec.hash))
                                 : priv.sign(md);
    log.debug("Leaving signOctets(). RSA.");
    return forge.util.binary.raw.decode(raw);
  }
  if (spec.family === 'ec') {
    // RFC 7518 §3.4: the JWS signature is R || S, each left-padded to the
    // coordinate size — NOT the DER SEQUENCE every other API hands you.
    var sig = spec.curve.sign(hashOf(spec.hash, octets), key);
    log.debug("Leaving signOctets(). ECDSA.");
    return sig.toCompactRawBytes();
  }
  if (spec.family === 'okp') {
    log.debug("Leaving signOctets(). EdDSA.");
    return spec.curve.sign(octets, key);
  }
  if (spec.family === 'pq') {
    // `key` here is the AKP `priv` value, not necessarily the signing key —
    // pqc.signWithPriv() is what knows the difference, and it is the reason
    // this branch is one line rather than a per-family switch.
    log.debug("Leaving signOctets(). Post-quantum.");
    return pqc.signWithPriv(spec.pqName, octets, key);
  }
  throw new Error('Unsupported algorithm family: ' + spec.family);
}

function verifyOctets(spec, key, octets, signature) {
  log.debug("Entering verifyOctets(). alg=" + spec.alg);
  if (spec.family === 'none') {
    // RFC 7515 §6: the signature of an Unsecured JWS is the empty octet
    // sequence. Anything else is not an Unsecured JWS, and saying "valid"
    // about a non-empty one would be a lie about a token that authenticates
    // nothing either way.
    log.debug("Leaving verifyOctets(). Unsecured.");
    return signature.length === 0;
  }
  if (spec.family === 'hmac') {
    var tag = nobleHmac(HASHES[spec.hash].noble, key, octets);
    log.debug("Leaving verifyOctets(). HMAC.");
    return bytesLib.bytesEqual(tag, signature);
  }
  if (spec.family === 'rsa') {
    var pub = forge.pki.publicKeyFromPem(key);
    var md = forgeMd(spec.hash);
    md.update(forge.util.binary.raw.encode(octets));
    var raw = forge.util.binary.raw.encode(signature);
    var ok = spec.pad === 'pss'
      ? pub.verify(md.digest().getBytes(), raw, rsaPssParams(spec.hash))
      : pub.verify(md.digest().getBytes(), raw);
    log.debug("Leaving verifyOctets(). RSA.");
    return ok;
  }
  if (spec.family === 'ec') {
    // lowS:false on VERIFICATION only. @noble refuses a high-S secp256k1
    // signature by default (a Bitcoin malleability rule), and JOSE has no such
    // rule — so a perfectly valid ES256K signature from OpenSSL would be
    // reported invalid. Signing keeps the default, which is always acceptable.
    log.debug("Leaving verifyOctets(). ECDSA.");
    return spec.curve.verify(signature, hashOf(spec.hash, octets), key,
                             { lowS: false });
  }
  if (spec.family === 'okp') {
    log.debug("Leaving verifyOctets(). EdDSA.");
    return spec.curve.verify(signature, octets, key);
  }
  if (spec.family === 'pq') {
    // A wrong-length signature or key is a FAILED verification here rather
    // than an exception, matching every other branch above: @noble throws on
    // a malformed input, and a JWS verifier that throws where it should
    // return false makes a forged token look like a bug in the tool.
    try {
      var pqOk = pqc.verifyWithPub(spec.pqName, signature, octets, key);
      log.debug("Leaving verifyOctets(). Post-quantum.");
      return pqOk;
    } catch (e) {
      log.debug("Leaving verifyOctets(). Post-quantum, malformed: " +
                e.message);
      return false;
    }
  }
  throw new Error('Unsupported algorithm family: ' + spec.family);
}

// ---------------------------------------------------------------------------
// KEY FORMS
//
// Everything below turns whatever a caller has into what a backend needs.
// It is deliberately here rather than in five pages, because "the user pasted
// something" is a reading of a format, and this file already records what a
// second reading of a format costs.
// ---------------------------------------------------------------------------

// A certificate is not a public key, and two pages in this tree spent a long
// time not knowing it.
//
// Both the JWT Tools and Token Detail verification panes offer "X.509
// Certificate (PEM)" and both handed the PEM's bytes to
// importKey('spki', …) — which is a SubjectPublicKeyInfo, not a Certificate.
// A real certificate pasted into either field failed with a bare Web Crypto
// DataError naming nothing; the only thing that ever worked there was a
// `BEGIN PUBLIC KEY` PEM, which is what the page's own auto-fill happened to
// put in it. So the label was true of nothing the code accepted.
//
// This walks the Certificate to its subjectPublicKeyInfo and returns that as a
// PEM. It is node-forge's ASN.1 rather than pkijs on purpose: forge is already
// a dependency of this file, pkijs is not a dependency of every page that
// verifies a JWS, and the walk is ten lines —
//   Certificate      ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
//   TBSCertificate   ::= SEQUENCE { [0] version OPTIONAL, serialNumber,
//                                   signature, issuer, validity, subject,
//                                   subjectPublicKeyInfo, … }
// so the index of the SPKI is 6 with an explicit version and 5 without, which
// is the only thing there is to get right. Unlike forge's own
// certificateFromPem() this does not care what algorithm the key is: it copies
// the SPKI out whole, so an EC or Ed25519 certificate works exactly as an RSA
// one does.
function spkiFromCertificatePem(pem) {
  log.debug("Entering spkiFromCertificatePem().");
  var der = bytesLib.pemToDer(pem);
  var cert = forge.asn1.fromDer(forge.util.binary.raw.encode(der));
  var tbs = cert.value[0];
  var versioned = tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC;
  var spki = tbs.value[versioned ? 6 : 5];
  if (!spki) {
    throw new Error('This certificate has no subjectPublicKeyInfo where one ' +
        'belongs — it may not be an X.509 certificate.');
  }
  log.debug("Leaving spkiFromCertificatePem().");
  return bytesLib.derToPem(
    forge.util.binary.raw.decode(forge.asn1.toDer(spki).getBytes()),
    'PUBLIC KEY');
}

// The BIT STRING at the end of a SubjectPublicKeyInfo, which for an EC key is
// the uncompressed point and for an Ed key is the public key itself. (For RSA
// it is a DER RSAPublicKey, which forge reads for us, so this is not used
// there.) The leading octet of a DER BIT STRING is the count of unused bits
// and is not part of the key — dropping it is the whole of the encoding, and
// keeping it produces a point that is off the curve by one byte.
function spkiPublicBits(pem) {
  log.debug("Entering spkiPublicBits().");
  var der = bytesLib.pemToDer(pem);
  var spki = forge.asn1.fromDer(forge.util.binary.raw.encode(der));
  var bits = spki.value[1];
  var raw = bits.value;
  var out = forge.util.binary.raw.decode(
    raw.charCodeAt(0) === 0 ? raw.slice(1) : raw);
  log.debug("Leaving spkiPublicBits().");
  return out;
}

// The private scalar out of a PKCS#8 PrivateKeyInfo, for the two families
// whose JS backend wants raw bytes.
//
//   EC  (RFC 5915)  privateKey OCTET STRING wraps
//                   ECPrivateKey ::= SEQUENCE { version, privateKey OCTET
//                                               STRING, … }
//   OKP (RFC 8410)  privateKey OCTET STRING wraps a CurvePrivateKey, which is
//                   itself an OCTET STRING of the raw key
//
// Both are "an OCTET STRING inside the OCTET STRING", which is the detail that
// catches people: reading the outer one gives you DER where a scalar was
// expected, and every signature made with it is wrong in a way that looks like
// a wrong key rather than a wrong parse.
function pkcs8PrivateBits(spec, pem) {
  log.debug("Entering pkcs8PrivateBits().");
  var der = bytesLib.pemToDer(pem);
  var pki = forge.asn1.fromDer(forge.util.binary.raw.encode(der));
  var inner = forge.asn1.fromDer(pki.value[2].value);
  var raw;
  if (spec.family === 'okp') {
    raw = inner.value;
  } else {
    raw = inner.value[1].value;
  }
  log.debug("Leaving pkcs8PrivateBits().");
  return forge.util.binary.raw.decode(raw);
}

// A JWK, in either direction, for every family this module signs with. RSA
// goes back through forge's own key builders rather than being re-encoded by
// hand: `setRsaPublicKey` and `setRsaPrivateKey` take the same members a JWK
// carries, under different names, and the renaming is the whole conversion.
function jwkBig(value) {
  log.debug("Entering jwkBig().");
  var bytes = b64uToBytes(value);
  log.debug("Leaving jwkBig().");
  return new forge.jsbn.BigInteger(bytesLib.bytesToHex(bytes) || '0', 16);
}

// A public JWK handed to a signer is a mistake worth naming. Without this the
// missing `d` reads as an empty octet string, which becomes a private scalar
// of zero — an operation that does not throw, produces a signature, and
// verifies against nothing.
function requirePrivateMember(jwk, spec) {
  log.debug("Entering requirePrivateMember().");
  if (jwk.d === undefined || jwk.d === '') {
    throw new Error('That ' + jwk.kty + ' JWK is a PUBLIC key — it has no ' +
        '"d" member, so nothing can be signed with it (alg=' + spec.alg +
        ').');
  }
  log.debug("Leaving requirePrivateMember().");
}

function jwkToKey(spec, jwk, wantPrivate) {
  log.debug("Entering jwkToKey(). kty=" + (jwk && jwk.kty));
  if (!jwk || !jwk.kty) throw new Error('That is not a JWK — it has no ' +
      '"kty" member.');
  if (spec.family === 'hmac') {
    if (jwk.kty !== 'oct') throw new Error('alg=' + spec.alg + ' needs an ' +
        'oct JWK; this one is ' + jwk.kty + '.');
    log.debug("Leaving jwkToKey(). oct.");
    return b64uToBytes(jwk.k || '');
  }
  if (spec.family === 'rsa') {
    if (jwk.kty !== 'RSA') throw new Error('alg=' + spec.alg + ' needs an ' +
        'RSA JWK; this one is ' + jwk.kty + '.');
    if (!wantPrivate) {
      log.debug("Leaving jwkToKey(). RSA public.");
      return forge.pki.publicKeyToPem(
        forge.pki.setRsaPublicKey(jwkBig(jwk.n), jwkBig(jwk.e)));
    }
    if (jwk.d === undefined) throw new Error('That RSA JWK is a PUBLIC key — ' +
        'it has no "d" member, so nothing can be signed with it.');
    var key = forge.pki.setRsaPrivateKey(jwkBig(jwk.n), jwkBig(jwk.e),
      jwkBig(jwk.d), jwkBig(jwk.p), jwkBig(jwk.q), jwkBig(jwk.dp),
      jwkBig(jwk.dq), jwkBig(jwk.qi));
    log.debug("Leaving jwkToKey(). RSA private.");
    return forge.pki.privateKeyInfoToPem(
      forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(key)));
  }
  if (spec.family === 'okp') {
    if (jwk.kty !== 'OKP') throw new Error('alg=' + spec.alg + ' needs an ' +
        'OKP JWK; this one is ' + jwk.kty + '.');
    if (wantPrivate) requirePrivateMember(jwk, spec);
    log.debug("Leaving jwkToKey(). OKP.");
    return b64uToBytes(wantPrivate ? jwk.d : (jwk.x || ''));
  }
  if (spec.family === 'ec') {
    if (jwk.kty !== 'EC') throw new Error('alg=' + spec.alg + ' needs an EC ' +
        'JWK; this one is ' + jwk.kty + '.');
    if (wantPrivate) {
      requirePrivateMember(jwk, spec);
      log.debug("Leaving jwkToKey(). EC private.");
      return b64uToBytes(jwk.d);
    }
    // The uncompressed point: 0x04 || X || Y, each coordinate padded to the
    // field size. A JWK that trimmed a leading zero from either — which a
    // conforming publisher may do — must still give the same point, which is
    // what the padding here is for.
    log.debug("Leaving jwkToKey(). EC public.");
    return concatBytes(new Uint8Array([4]),
      concatBytes(pad(b64uToBytes(jwk.x || ''), spec.fieldBytes),
                  pad(b64uToBytes(jwk.y || ''), spec.fieldBytes)));
  }
  if (spec.family === 'pq') {
    // RFC 9964 section 3: the key type is AKP, the parameters are `pub` and
    // `priv`, and `alg` is REQUIRED. pqc.akpImport() enforces all three plus
    // the seed-length rule, so the errors a person sees name the section
    // they broke rather than a byte length from inside a lattice.
    var akp = pqc.akpImport(jwk);
    if (wantPrivate && !akp.priv) {
      throw new Error('That AKP JWK is a PUBLIC key — it has no "priv" ' +
          'member, so nothing can be signed with it (alg=' + spec.alg + ').');
    }
    if (akp.alg !== spec.alg) {
      throw new Error('alg=' + spec.alg + ' needs an AKP JWK whose "alg" is ' +
          spec.alg + '; this one says ' + akp.alg + '. RFC 9964 makes that ' +
          'member REQUIRED precisely because "pub" and "priv" are opaque ' +
          'octets that cannot say which algorithm they belong to.');
    }
    log.debug("Leaving jwkToKey(). AKP.");
    return wantPrivate ? akp.priv : akp.pub;
  }
  throw new Error('No JWK form for alg=' + spec.alg + '.');
}

function pad(bytes, size) {
  log.debug("Entering pad().");
  if (bytes.length >= size) {
    log.debug("Leaving pad(). Already long enough.");
    return bytes;
  }
  var out = new Uint8Array(size);
  out.set(bytes, size - bytes.length);
  log.debug("Leaving pad().");
  return out;
}

// Choose a key out of a JWK Set the way a relying party does: by `kid` when
// the header names one, and otherwise by what the key is FOR. A set with one
// usable key and no kid is the common case for a small issuer and must work;
// a set with several and no kid is genuinely ambiguous and says so.
function selectFromJwks(jwks, header, spec) {
  log.debug("Entering selectFromJwks().");
  var keys = (jwks && jwks.keys) || [];
  if (!keys.length) throw new Error('That JWK Set has no keys.');
  if (header && header.kid) {
    var byKid = keys.filter(function (k) { return k.kid === header.kid; });
    if (!byKid.length) {
      throw new Error('No key in the set has kid "' + header.kid + '", which ' +
          'is the one the JWS header names.');
    }
    log.debug("Leaving selectFromJwks(). By kid.");
    return byKid[0];
  }
  var wanted = { hmac: 'oct', rsa: 'RSA', ec: 'EC', okp: 'OKP' }[spec.family];
  var usable = keys.filter(function (k) {
    return k.kty === wanted && (!k.use || k.use === 'sig') &&
      (!k.alg || k.alg === spec.alg);
  });
  if (!usable.length) {
    throw new Error('No key in the set can verify an ' + spec.alg +
        ' signature (looking for kty=' + wanted + ').');
  }
  if (usable.length > 1) {
    throw new Error('The JWS header has no "kid" and the set has ' +
        usable.length + ' keys that could verify it. Which one is meant is ' +
        'not knowable from the JWS.');
  }
  log.debug("Leaving selectFromJwks(). Only candidate.");
  return usable[0];
}

// Is this a JWK Set? `.keys` must be an ARRAY, and that word is doing real
// work: every Uint8Array, Array and Map has a `keys` METHOD, so a truthiness
// test here reads an HMAC secret as a JWK Set with no keys in it — which
// reports "That JWK Set has no keys" about a perfectly good secret, and names
// nothing a caller would recognise.
function asJwkSet(input) {
  log.debug("Entering asJwkSet().");
  if (!input || typeof input !== 'object') {
    log.debug("Leaving asJwkSet(). Not an object.");
    return null;
  }
  if (input.jwks && Array.isArray(input.jwks.keys)) {
    log.debug("Leaving asJwkSet(). Wrapped.");
    return input.jwks;
  }
  if (Array.isArray(input.keys)) {
    log.debug("Leaving asJwkSet(). Bare.");
    return input;
  }
  log.debug("Leaving asJwkSet(). No.");
  return null;
}

// A JWK Set narrowed to the one key the header points at, leaving every other
// key form untouched. Callers hand a whole set straight from a jwks_uri, and
// both backends want a single key.
function narrowToOneKey(input, header, spec) {
  log.debug("Entering narrowToOneKey().");
  var jwks = asJwkSet(input);
  if (!jwks) {
    log.debug("Leaving narrowToOneKey(). Not a set.");
    return input;
  }
  log.debug("Leaving narrowToOneKey(). Narrowed.");
  return { jwk: selectFromJwks(jwks, header, spec) };
}

// The one entry point every caller's key goes through.
//
// `input` may be: a CryptoKey; { cryptoKey }; a Uint8Array; a JWK object;
// { jwk }; { jwks } or a JWK Set; { secret, encoding }; or a PEM string
// (PKCS#8, SPKI, or a CERTIFICATE, which is unwrapped to its SPKI first).
// `usage` is 'sign' or 'verify'; `header` is the JWS header when there is one,
// because that is what picks a key out of a set.
function resolveKey(spec, input, usage, header) {
  log.debug("Entering resolveKey(). usage=" + usage);
  var wantPrivate = usage === 'sign';
  if (input == null || input === '') {
    if (spec.family === 'none') {
      log.debug("Leaving resolveKey(). Unsecured needs none.");
      return { backend: 'js', key: null };
    }
    throw new Error('No key was supplied for alg=' + spec.alg + '.');
  }
  if (typeof CryptoKey !== 'undefined' && input instanceof CryptoKey) {
    log.debug("Leaving resolveKey(). CryptoKey.");
    return { backend: 'webcrypto', key: input };
  }
  if (input.cryptoKey) {
    log.debug("Leaving resolveKey(). Wrapped CryptoKey.");
    return { backend: 'webcrypto', key: input.cryptoKey };
  }
  if (input instanceof Uint8Array) {
    log.debug("Leaving resolveKey(). Raw bytes.");
    return { backend: 'js', key: input };
  }
  if (input.secret !== undefined) {
    log.debug("Leaving resolveKey(). Secret.");
    return { backend: 'js', key: secretBytes(input.secret, input.encoding) };
  }
  var jwks = asJwkSet(input);
  if (jwks) {
    log.debug("Leaving resolveKey(). From a JWK Set.");
    return { backend: 'js',
             key: jwkToKey(spec, selectFromJwks(jwks, header, spec),
                           wantPrivate),
             jwk: selectFromJwks(jwks, header, spec) };
  }
  var jwk = input.jwk || (input.kty ? input : null);
  if (jwk) {
    log.debug("Leaving resolveKey(). JWK.");
    return { backend: 'js', key: jwkToKey(spec, jwk, wantPrivate), jwk: jwk };
  }
  if (typeof input === 'string') {
    var label = bytesLib.pemLabel(input) || '';
    var pem = /CERTIFICATE/.test(label) ? spkiFromCertificatePem(input)
                                        : input;
    if (spec.family === 'rsa') {
      log.debug("Leaving resolveKey(). RSA PEM.");
      return { backend: 'js', key: pem };
    }
    if (spec.family === 'hmac') {
      throw new Error('alg=' + spec.alg + ' is a MAC — it takes a shared ' +
          'secret, not a PEM.');
    }
    log.debug("Leaving resolveKey(). Curve PEM.");
    return { backend: 'js',
             key: wantPrivate ? pkcs8PrivateBits(spec, pem)
                              : spkiPublicBits(pem) };
  }
  throw new Error('Unrecognised key material for alg=' + spec.alg + '.');
}

// A shared secret, in whichever of the three ways it was written down. This
// matters more than it looks: the JWT Tools pane reads its secret as base64url
// (a JWK's `k`) and the Token Detail pane read the SAME field as UTF-8 text,
// so the two pages disagreed about what a given secret WAS. Neither was wrong
// — they were answering different questions — which is exactly why the choice
// is now a parameter instead of a convention.
function secretBytes(secret, encoding) {
  log.debug("Entering secretBytes(). encoding=" + encoding);
  if (secret instanceof Uint8Array) {
    log.debug("Leaving secretBytes(). Already bytes.");
    return secret;
  }
  var text = String(secret == null ? '' : secret).trim();
  if (encoding === 'hex') {
    log.debug("Leaving secretBytes(). Hex.");
    return bytesLib.hexToBytes(text);
  }
  if (encoding === 'text') {
    log.debug("Leaving secretBytes(). UTF-8 text.");
    return strBytes(text);
  }
  log.debug("Leaving secretBytes(). base64url.");
  return b64uToBytes(text);
}

// ---------------------------------------------------------------------------
// THE WEB CRYPTO BACKEND
//
// One table drives it, and that table is ALGS above. Every one of the four
// call sites this replaced carried its own two-line map from `alg` to an
// importKey algorithm and a sign algorithm — four copies of the same fact,
// and the reason it was copied four times is that getting it wrong produces a
// Web Crypto DataError naming neither the algorithm nor the key.
// ---------------------------------------------------------------------------
var WEBCRYPTO_HASH = { 'SHA-256': 'SHA-256', 'SHA-384': 'SHA-384',
                       'SHA-512': 'SHA-512' };

// ---------------------------------------------------------------------------
// WHETHER WEB CRYPTO CAN REPRESENT THIS ALGORITHM AT ALL — which is a property
// of the ALGORITHM and not of the runtime, so it is a fixed rule rather than a
// probe.
//
// `crypto.subtle` has no identifier for secp256k1 and none for Ed448, in any
// browser and in node: they are not missing from one implementation, they are
// absent from the specification's registry of names. Asking for either gets
// "Unrecognized namedCurve" out of an import, several frames from anything that
// names the algorithm.
//
// This module implements both in JavaScript, so a caller that asked for the
// webcrypto backend gets the JavaScript one for these two and a correct answer
// either way. A BACKEND IS AN IMPLEMENTATION CHOICE AND MUST NEVER DECIDE
// WHETHER AN ALGORITHM WORKS — the same rule jose_jwe.js follows for the
// AES-192 sizes Chrome refuses. Before this existed, verifying an ES256K token
// against a JWKS failed outright wherever the caller had asked for Web Crypto,
// which on the UserInfo page is every time.
// ---------------------------------------------------------------------------
function webCryptoKnowsAlg(spec) {
  log.debug("Entering webCryptoKnowsAlg().");
  if (!spec || spec.family === 'none') {
    log.debug("Leaving webCryptoKnowsAlg(). Unsecured.");
    return false;
  }
  if (spec.family === 'ec' && spec.crv === 'secp256k1') {
    log.debug("Leaving webCryptoKnowsAlg(). No secp256k1 in Web Crypto.");
    return false;
  }
  if (spec.family === 'okp' && spec.crv === 'Ed448') {
    log.debug("Leaving webCryptoKnowsAlg(). No Ed448 in Web Crypto.");
    return false;
  }
  if (spec.family === 'pq') {
    // The post-quantum and hybrid signatures. Web Crypto has no name for any
    // of them in any runtime — webCryptoImportParams() throws "has no Web
    // Crypto equivalent" — and this module implements every one of them, so a
    // caller that asked for the webcrypto backend gets the JavaScript one and
    // a correct answer rather than a refusal.
    log.debug("Leaving webCryptoKnowsAlg(). Post-quantum.");
    return false;
  }
  log.debug("Leaving webCryptoKnowsAlg().");
  return true;
}

function webCryptoImportParams(spec) {
  log.debug("Entering webCryptoImportParams().");
  if (spec.family === 'hmac') {
    log.debug("Leaving webCryptoImportParams(). HMAC.");
    return { name: 'HMAC', hash: { name: WEBCRYPTO_HASH[spec.hash] } };
  }
  if (spec.family === 'rsa') {
    log.debug("Leaving webCryptoImportParams(). RSA.");
    return { name: spec.pad === 'pss' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
             hash: { name: WEBCRYPTO_HASH[spec.hash] } };
  }
  if (spec.family === 'ec') {
    log.debug("Leaving webCryptoImportParams(). ECDSA.");
    return { name: 'ECDSA', namedCurve: spec.crv };
  }
  if (spec.family === 'okp') {
    log.debug("Leaving webCryptoImportParams(). EdDSA.");
    return { name: spec.crv };
  }
  throw new Error('alg=' + spec.alg + ' has no Web Crypto equivalent.');
}

function webCryptoSignParams(spec) {
  log.debug("Entering webCryptoSignParams().");
  if (spec.family === 'hmac') {
    log.debug("Leaving webCryptoSignParams(). HMAC.");
    return { name: 'HMAC' };
  }
  if (spec.family === 'rsa') {
    log.debug("Leaving webCryptoSignParams(). RSA.");
    return spec.pad === 'pss'
      ? { name: 'RSA-PSS', saltLength: HASHES[spec.hash].bytes }
      : { name: 'RSASSA-PKCS1-v1_5' };
  }
  if (spec.family === 'ec') {
    log.debug("Leaving webCryptoSignParams(). ECDSA.");
    return { name: 'ECDSA', hash: { name: WEBCRYPTO_HASH[spec.hash] } };
  }
  if (spec.family === 'okp') {
    log.debug("Leaving webCryptoSignParams(). EdDSA.");
    return { name: spec.crv };
  }
  throw new Error('alg=' + spec.alg + ' has no Web Crypto equivalent.');
}

// Import whatever the caller gave into a CryptoKey. A CryptoKey passes
// straight through — a non-extractable key generated by the page is the whole
// reason this backend exists.
function webCryptoImport(spec, input, usage) {
  log.debug("Entering webCryptoImport(). usage=" + usage);
  var usages = [usage];
  if (typeof CryptoKey !== 'undefined' && input instanceof CryptoKey) {
    log.debug("Leaving webCryptoImport(). Already a CryptoKey.");
    return Promise.resolve(input);
  }
  if (input && input.cryptoKey) {
    log.debug("Leaving webCryptoImport(). Wrapped CryptoKey.");
    return Promise.resolve(input.cryptoKey);
  }
  var params = webCryptoImportParams(spec);
  var jwk = input && (input.jwk || (input.kty ? input : null));
  if (jwk) {
    log.debug("Leaving webCryptoImport(). From a JWK.");
    return crypto.subtle.importKey('jwk', jwk, params, false, usages);
  }
  if (input && input.secret !== undefined) {
    log.debug("Leaving webCryptoImport(). From a secret.");
    return crypto.subtle.importKey('raw',
      secretBytes(input.secret, input.encoding), params, false, usages);
  }
  if (input instanceof Uint8Array) {
    log.debug("Leaving webCryptoImport(). Raw.");
    return crypto.subtle.importKey('raw', input, params, false, usages);
  }
  if (typeof input === 'string') {
    var label = bytesLib.pemLabel(input) || '';
    var pem = /CERTIFICATE/.test(label) ? spkiFromCertificatePem(input)
                                        : input;
    var form = usage === 'sign' ? 'pkcs8' : 'spki';
    log.debug("Leaving webCryptoImport(). From a PEM as " + form + ".");
    return crypto.subtle.importKey(form, bytesLib.pemToDer(pem), params, false,
                                   usages);
  }
  return Promise.reject(new Error('Unrecognised key material for alg=' +
      spec.alg + '.'));
}

// ---------------------------------------------------------------------------
// Key material. The engine's contract: RSA keys are PEM strings, EC and OKP
// keys are RAW bytes (the private scalar, the encoded public point), and an
// HMAC key is the secret's bytes. The page converts whatever its fields hold
// into that; the tests hand it bytes directly.
// ---------------------------------------------------------------------------
function generateKey(algId, options) {
  log.debug("Entering generateKey(). alg=" + algId);
  var spec = algSpec(algId);
  var opts = options || {};
  if (spec.family === 'none') {
    log.debug("Leaving generateKey(). Unsecured needs no key.");
    return { kind: 'none', privateKey: null, publicKey: null };
  }
  if (spec.family === 'hmac') {
    // RFC 7518 §3.2: a key of at least the hash output's size. Shorter is a
    // MUST NOT, so the generated one is exactly that size rather than a
    // convenient round number.
    var secret = bytesLib.randomBytes(HASHES[spec.hash].bytes);
    log.debug("Leaving generateKey(). HMAC.");
    return { kind: 'hmac', privateKey: secret, publicKey: secret };
  }
  if (spec.family === 'rsa') {
    var pair = pkEncryption.rsaGenerateKeyPair(opts.bits || 2048);
    log.debug("Leaving generateKey(). RSA.");
    return { kind: 'rsa', privateKey: pair.privatePem,
             publicKey: pair.publicPem };
  }
  if (spec.family === 'pq') {
    // privateKey is the AKP `priv` representation throughout — the 32-byte
    // seed for ML-DSA, the raw private key for SLH-DSA and FN-DSA, and
    // seed || traditional key for a composite. One representation, so the
    // pane, the JWK download and signJws() never disagree.
    var akpPair = pqc.generateAkpKeyPair(spec.pqName);
    log.debug("Leaving generateKey(). Post-quantum.");
    return { kind: 'pq', privateKey: akpPair.priv, publicKey: akpPair.pub };
  }
  var priv = spec.curve.utils.randomPrivateKey();
  var pub = spec.curve.getPublicKey(priv);
  log.debug("Leaving generateKey(). " + spec.family);
  return { kind: spec.family, privateKey: priv, publicKey: pub };
}

// The PUBLIC key as a JWK — for the optional `jwk` header member, and for the
// pane's JWK download. Built here rather than through key_material.js because
// that module's conversions are Web Crypto and therefore async and
// secure-context-only, and this whole file exists to work where crypto.subtle
// does not.
function publicJwk(algId, publicKey, kid) {
  log.debug("Entering publicJwk(). alg=" + algId);
  var spec = algSpec(algId);
  var jwk;
  if (spec.family === 'rsa') {
    var pub = forge.pki.publicKeyFromPem(publicKey);
    jwk = {
      kty: 'RSA',
      n: bytesToB64u(bigToBytes(BigInt(pub.n.toString()),
                                Math.ceil(pub.n.bitLength() / 8))),
      e: bytesToB64u(bigToBytes(BigInt(pub.e.toString()),
                                Math.ceil(pub.e.bitLength() / 8)))
    };
  } else if (spec.family === 'okp') {
    jwk = { kty: 'OKP', crv: spec.crv, x: bytesToB64u(publicKey) };
  } else if (spec.family === 'ec') {
    var pt = spec.curve.ProjectivePoint.fromHex(
        bytesLib.bytesToHex(publicKey)).toAffine();
    jwk = { kty: 'EC', crv: spec.crv,
            x: bytesToB64u(bigToBytes(pt.x, spec.fieldBytes)),
            y: bytesToB64u(bigToBytes(pt.y, spec.fieldBytes)) };
  } else if (spec.family === 'hmac') {
    jwk = { kty: 'oct', k: bytesToB64u(publicKey) };
  } else if (spec.family === 'pq') {
    jwk = pqc.akpPublicJwk(spec.alg, publicKey);
  } else {
    throw new Error('No JWK representation for alg=' + algId + '.');
  }
  jwk.alg = spec.alg;
  jwk.use = 'sig';
  if (kid) jwk.kid = kid;
  log.debug("Leaving publicJwk().");
  return jwk;
}

// The PRIVATE key as a JWK, for the pane's JWK set download. RSA is left out
// deliberately: a private RSA JWK is eight members derived from a PKCS#8 blob,
// key_material.js already produces one through the shared keystore matrix that
// tests/pki_key_formats.js checks against OpenSSL, and a second reading of
// those members here is exactly the duplication that module exists to prevent.
function privateJwk(algId, privateKey, publicKey, kid) {
  log.debug("Entering privateJwk(). alg=" + algId);
  var spec = algSpec(algId);
  if (spec.family === 'rsa' || spec.family === 'none') {
    throw new Error('No raw private JWK for alg=' + algId + '.');
  }
  var jwk = publicJwk(algId, publicKey, kid);
  if (spec.family === 'hmac') {
    log.debug("Leaving privateJwk(). Symmetric.");
    return jwk;
  }
  if (spec.family === 'pq') {
    // NOT `d`. RFC 9964 names the AKP private parameter `priv`, and an AKP
    // JWK carrying `d` is what this project used to emit — readable by this
    // page and by nothing else.
    jwk.priv = bytesToB64u(privateKey);
    log.debug("Leaving privateJwk(). AKP.");
    return jwk;
  }
  jwk.d = bytesToB64u(privateKey);
  log.debug("Leaving privateJwk().");
  return jwk;
}

// ---------------------------------------------------------------------------
// The payload. RFC 7515 allows ANY octet sequence, and this page's pane
// requires JSON — so the check is here, reported rather than enforced, and it
// NEVER rewrites what it was given (see the file header).
// ---------------------------------------------------------------------------
function validateJson(text) {
  log.debug("Entering validateJson().");
  if (typeof text !== 'string' || text.trim() === '') {
    log.debug("Leaving validateJson(). Empty.");
    return { valid: false, error: 'The payload is empty — it must be a JSON ' +
             'document.' };
  }
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving validateJson(). Not JSON.");
    return { valid: false, error: 'The payload is not well-formed JSON: ' +
             e.message };
  }
  var kind = parsed === null ? 'null'
    : Array.isArray(parsed) ? 'array' : typeof parsed;
  log.debug("Leaving validateJson().");
  return { valid: true, value: parsed, kind: kind,
           members: (kind === 'object') ? Object.keys(parsed).length : null };
}

function compactJson(text) {
  log.debug("Entering compactJson().");
  var checked = validateJson(text);
  if (!checked.valid) throw new Error(checked.error);
  log.debug("Leaving compactJson().");
  return JSON.stringify(checked.value);
}

// ---------------------------------------------------------------------------
// Signing.
//
// opts: {
//   algId, payload (string), privateKey,
//   serialization: 'compact' | 'flattened' | 'general',
//   header: {}          extra PROTECTED header members
//   unprotected: {}     JSON serializations only (RFC 7515 §7.2)
//   kid, typ, cty, crit: []
//   b64: true|false     RFC 7797 — false signs the payload unencoded
//   detached: bool      RFC 7515 App. F — the payload is left out
//   embedJwk: bool      put the public key in the header as `jwk`
// }
// ---------------------------------------------------------------------------
function buildProtectedHeader(opts) {
  log.debug("Entering buildProtectedHeader().");
  var spec = algSpec(opts.algId);
  var header = {};
  // `alg` first, and every other member after it: a header is a JSON object
  // and member order carries no meaning, but a reader looking at the decoded
  // header of a token wants the algorithm on the first line.
  header.alg = spec.alg;
  if (opts.typ) header.typ = opts.typ;
  if (opts.cty) header.cty = opts.cty;
  if (opts.kid) header.kid = opts.kid;
  var extra = opts.header || {};
  Object.keys(extra).forEach(function (k) { header[k] = extra[k]; });
  if (opts.embedJwk && spec.family !== 'none' && spec.family !== 'hmac') {
    header.jwk = publicJwk(opts.algId, opts.publicKey, opts.kid);
  }
  var crit = (opts.crit || []).slice();
  if (opts.b64 === false) {
    // RFC 7797 §3: `b64` MUST be integrity-protected, so it goes in the
    // protected header, and it MUST be listed in `crit` — a recipient that
    // does not implement RFC 7797 has to reject the JWS rather than verify it
    // against the base64url of a payload that was never base64url'd.
    header.b64 = false;
    if (crit.indexOf('b64') < 0) crit.push('b64');
  }
  if (crit.length) header.crit = crit;
  log.debug("Leaving buildProtectedHeader().");
  return header;
}

function signingInput(protectedB64u, payload, b64) {
  log.debug("Entering signingInput().");
  var head = strBytes(protectedB64u + '.');
  var tail = b64 === false ? strBytes(payload)
                           : strBytes(strToB64u(payload));
  log.debug("Leaving signingInput().");
  return concatBytes(head, tail);
}

// Which backend signs. A CryptoKey can only be used by Web Crypto — that is
// the whole reason a page holds one — and everything else defaults to the
// pure-JS path, which is the one that works over plain HTTP and covers the two
// algorithms crypto.subtle does not have.
function backendFor(requested, keyInput) {
  log.debug("Entering backendFor().");
  if (requested) {
    log.debug("Leaving backendFor(). Requested " + requested + ".");
    return requested;
  }
  if (typeof CryptoKey !== 'undefined' && keyInput instanceof CryptoKey) {
    log.debug("Leaving backendFor(). CryptoKey implies webcrypto.");
    return 'webcrypto';
  }
  if (keyInput && keyInput.cryptoKey) {
    log.debug("Leaving backendFor(). Wrapped CryptoKey implies webcrypto.");
    return 'webcrypto';
  }
  log.debug("Leaving backendFor(). Default js.");
  return 'js';
}

// The payload as octets-to-be. An object is serialized compactly, which is
// what every JWT-shaped caller wants; a string is used EXACTLY as given, which
// is what the Digital Signature pane needs, because a payload reformatted
// between validation and signing is signed as something the user never saw.
function payloadText(payload) {
  log.debug("Entering payloadText().");
  if (payload == null) {
    log.debug("Leaving payloadText(). Empty.");
    return '';
  }
  if (typeof payload === 'string') {
    log.debug("Leaving payloadText(). Verbatim.");
    return payload;
  }
  log.debug("Leaving payloadText(). Serialized.");
  return JSON.stringify(payload);
}

// ---------------------------------------------------------------------------
// SIGNING, in three pieces and two entry points.
//
// The two entry points exist because the callers genuinely differ: the
// Digital Signature pane and the node engine test sign with pure JS and want
// the answer, while the DPoP, OID4VCI, SD-JWT VC and JWT Tools panes hold a
// Web Crypto key and can only be given a promise. What they must NOT differ
// in is any of the JOSE — so prepareSign() and assembleSign() are the whole
// of it, and each entry point is four lines around the signature itself.
// ---------------------------------------------------------------------------
function prepareSign(options) {
  log.debug("Entering prepareSign().");
  var spec = algSpec(options.algId);
  var payload = payloadText(options.payload);
  var b64 = options.b64 === false ? false : true;
  var serialization = options.serialization || 'compact';

  if (b64 === false && serialization === 'compact' &&
      payload.indexOf('.') >= 0) {
    // RFC 7797 section 5.2: an unencoded payload in the compact serialization
    // cannot contain a period, because the period is the compact
    // serialization's own delimiter. A JSON payload hits this constantly —
    // any decimal number, any hostname in a string — so it is worth naming
    // rather than producing a token that reads as having four parts.
    throw new Error('RFC 7797: an unencoded (b64=false) payload cannot ' +
        'contain "." in the COMPACT serialization — it is the delimiter. ' +
        'Use a JSON serialization, or leave b64 on.');
  }
  if (serialization === 'compact' && options.unprotected &&
      Object.keys(options.unprotected).length) {
    throw new Error('The compact serialization has no place for an ' +
        'unprotected header (RFC 7515 §7.1) — use a JSON serialization.');
  }
  if (serialization !== 'compact' && serialization !== 'flattened' &&
      serialization !== 'general') {
    throw new Error('Unknown serialization: ' + serialization);
  }

  var header;
  if (options.protectedHeader) {
    // USED VERBATIM, member order included. Four workflows were signing their
    // own hand-built headers before this module absorbed them, and a JWS is
    // the base64url of those exact bytes — so re-ordering the members here,
    // however harmlessly a parser would read it, would change every DPoP
    // proof and every credential proof this application produces. Nothing in
    // this repository could have caught that.
    header = options.protectedHeader;
    if (header.alg !== undefined && header.alg !== spec.alg) {
      throw new Error('The supplied header says alg=' + header.alg +
          ' but ' + spec.alg + ' was selected.');
    }
  } else {
    header = buildProtectedHeader({
      algId: options.algId, typ: options.typ, cty: options.cty,
      kid: options.kid, crit: options.crit, header: options.header,
      b64: b64, embedJwk: options.embedJwk, publicKey: options.publicKey
    });
  }
  var protectedB64u = strToB64u(JSON.stringify(header));
  log.debug("Leaving prepareSign().");
  return {
    spec: spec, header: header, payload: payload, b64: b64,
    serialization: serialization, protected: protectedB64u,
    input: signingInput(protectedB64u, payload, b64)
  };
}

function assembleSign(prep, signature, options, backend) {
  log.debug("Entering assembleSign().");
  var signatureB64u = bytesToB64u(signature);
  var result = {
    alg: prep.spec.alg,
    algId: options.algId,
    backend: backend,
    header: prep.header,
    payload: prep.payload,
    protected: prep.protected,
    signature: signatureB64u,
    signingInput: bytesToStr(prep.input),
    payloadEncoded: prep.b64 === false ? prep.payload
                                       : strToB64u(prep.payload),
    detached: !!options.detached,
    b64: prep.b64,
    serialization: prep.serialization
  };
  if (prep.serialization === 'compact') {
    result.serialized = prep.protected + '.' +
      (options.detached ? '' : result.payloadEncoded) + '.' + signatureB64u;
    log.debug("Leaving assembleSign(). Compact.");
    return result;
  }
  var entry = { protected: prep.protected, signature: signatureB64u };
  if (options.unprotected && Object.keys(options.unprotected).length) {
    entry.header = options.unprotected;
  }
  var doc = {};
  if (prep.serialization === 'flattened') {
    if (!options.detached) doc.payload = result.payloadEncoded;
    doc.protected = entry.protected;
    if (entry.header) doc.header = entry.header;
    doc.signature = entry.signature;
  } else {
    if (!options.detached) doc.payload = result.payloadEncoded;
    doc.signatures = [entry];
  }
  result.serialized = JSON.stringify(doc, null, 2);
  // `json`, not `document` — this module must not contain that identifier at
  // all, because tests/jws_engine.js proves it has no DOM by looking for it,
  // and a member of that name would be a false positive that gets the check
  // weakened rather than the module fixed.
  result.json = doc;
  log.debug("Leaving assembleSign(). JSON serialization.");
  return result;
}

// Which backend signs. A CryptoKey can only be used by Web Crypto — that is
// the whole reason a page holds one — and everything else defaults to the
// pure-JS path, which is the one that works over plain HTTP and covers the two
// algorithms crypto.subtle does not have.
function backendFor(requested, keyInput) {
  log.debug("Entering backendFor().");
  if (requested) {
    log.debug("Leaving backendFor(). Requested " + requested + ".");
    return requested;
  }
  if (typeof CryptoKey !== 'undefined' && keyInput instanceof CryptoKey) {
    log.debug("Leaving backendFor(). CryptoKey implies webcrypto.");
    return 'webcrypto';
  }
  if (keyInput && keyInput.cryptoKey) {
    log.debug("Leaving backendFor(). Wrapped CryptoKey implies webcrypto.");
    return 'webcrypto';
  }
  log.debug("Leaving backendFor(). Default js.");
  return 'js';
}

// The payload as octets-to-be. An object is serialized compactly, which is
// what every JWT-shaped caller wants; a string is used EXACTLY as given, which
// is what the Digital Signature pane needs, because a payload reformatted
// between validation and signing is signed as something the user never saw.
function payloadText(payload) {
  log.debug("Entering payloadText().");
  if (payload == null) {
    log.debug("Leaving payloadText(). Empty.");
    return '';
  }
  if (typeof payload === 'string') {
    log.debug("Leaving payloadText(). Verbatim.");
    return payload;
  }
  log.debug("Leaving payloadText(). Serialized.");
  return JSON.stringify(payload);
}

// The synchronous entry point: pure JS only, and it says so rather than
// silently doing something else if handed a Web Crypto key.
function signJws(opts) {
  log.debug("Entering signJws().");
  var options = opts || {};
  var backend = backendFor(options.backend, options.privateKey);
  if (backend !== 'js') {
    throw new Error('signJws() is synchronous and the ' + backend +
        ' backend is not. Use signJwsAsync().');
  }
  var prep = prepareSign(options);
  var resolved = resolveKey(prep.spec, options.privateKey, 'sign', prep.header);
  var signature = signOctets(prep.spec, resolved.key, prep.input);
  log.debug("Leaving signJws().");
  return assembleSign(prep, signature, options, backend);
}

// The asynchronous entry point, which is the same thing with the signature
// awaited. Either backend; a caller that does not care passes a key and gets
// whichever one that key implies.
function signJwsAsync(opts) {
  log.debug("Entering signJwsAsync().");
  var options = opts || {};
  var backend = backendFor(options.backend, options.privateKey);
  var prep, signing;
  try {
    prep = prepareSign(options);
    if (backend === 'webcrypto' && !webCryptoKnowsAlg(prep.spec)) {
      // Asked for Web Crypto, and Web Crypto has no name for this algorithm.
      // The JavaScript engine does it instead — see webCryptoKnowsAlg().
      backend = 'js';
    }
    if (backend === 'webcrypto') {
      signing = webCryptoImport(prep.spec, options.privateKey, 'sign')
        .then(function (key) {
          return crypto.subtle.sign(webCryptoSignParams(prep.spec), key,
                                    prep.input);
        })
        .then(function (sig) {
          // Web Crypto returns an ECDSA signature as the raw R||S pair, which
          // is already the JWS encoding of RFC 7518 section 3.4 — there is no
          // DER to unwrap. Every call site this module absorbed carried that
          // sentence as a comment; now one place knows it.
          return new Uint8Array(sig);
        });
    } else {
      var resolved = resolveKey(prep.spec, options.privateKey, 'sign',
                                prep.header);
      signing = Promise.resolve(signOctets(prep.spec, resolved.key,
                                           prep.input));
    }
  } catch (e) {
    log.debug("Leaving signJwsAsync(). Refused: " + e.message);
    return Promise.reject(e);
  }
  log.debug("Leaving signJwsAsync().");
  return signing.then(function (signature) {
    return assembleSign(prep, signature, options, backend);
  });
}

// ---------------------------------------------------------------------------
// Parsing. Accepts either serialization, so a reader can paste whatever they
// have. Returns a normalized shape: a payload (possibly absent, when the JWS
// is detached) and a list of signature entries.
// ---------------------------------------------------------------------------
function parseJws(text) {
  log.debug("Entering parseJws().");
  var raw = (text || '').trim();
  if (!raw) throw new Error('There is no JWS to read.');
  if (raw.charAt(0) === '{') {
    var doc;
    try {
      doc = JSON.parse(raw);
    } catch (e) {
      throw new Error('This looks like a JSON serialization but is not ' +
          'well-formed JSON: ' + e.message);
    }
    var entries;
    if (Array.isArray(doc.signatures)) {
      entries = doc.signatures;
      var serialization = 'general';
    } else if (doc.signature !== undefined) {
      entries = [{ protected: doc.protected, header: doc.header,
                   signature: doc.signature }];
      serialization = 'flattened';
    } else {
      throw new Error('A JSON-serialized JWS needs either "signatures" ' +
          '(general) or "signature" (flattened) — RFC 7515 §7.2.');
    }
    log.debug("Leaving parseJws(). JSON serialization.");
    return { serialization: serialization, payload: doc.payload,
             detached: doc.payload === undefined, entries: entries };
  }
  var parts = raw.split('.');
  if (parts.length !== 3) {
    throw new Error('A compact JWS has exactly three parts separated by ' +
        'periods; this has ' + parts.length + '.');
  }
  log.debug("Leaving parseJws(). Compact.");
  return { serialization: 'compact', payload: parts[1],
           detached: parts[1] === '',
           entries: [{ protected: parts[0], signature: parts[2] }] };
}

// The `crit` check of RFC 7515 §4.1.11, which is a MUST and is the one header
// rule a verifier is most often missing: an extension the producer marked
// critical and this code does not implement means the JWS is REJECTED, not
// verified with the member ignored.
var UNDERSTOOD_CRIT = { b64: true };

function critProblem(header) {
  log.debug("Entering critProblem().");
  var crit = header.crit;
  if (crit === undefined) {
    log.debug("Leaving critProblem(). None.");
    return null;
  }
  if (!Array.isArray(crit) || crit.length === 0) {
    log.debug("Leaving critProblem(). Malformed.");
    return '"crit" must be a non-empty array of header names ' +
        '(RFC 7515 §4.1.11).';
  }
  for (var i = 0; i < crit.length; i++) {
    var name = crit[i];
    if (typeof name !== 'string') {
      log.debug("Leaving critProblem(). Non-string.");
      return '"crit" must contain only strings (RFC 7515 §4.1.11).';
    }
    if (!UNDERSTOOD_CRIT[name]) {
      log.debug("Leaving critProblem(). Unsupported extension.");
      return 'The producer marked "' + name + '" critical and this verifier ' +
          'does not implement it, so RFC 7515 §4.1.11 says the JWS MUST be ' +
          'rejected.';
    }
    if (header[name] === undefined) {
      log.debug("Leaving critProblem(). Missing member.");
      return '"crit" names "' + name + '" but the protected header has no ' +
          'such member (RFC 7515 §4.1.11).';
    }
  }
  log.debug("Leaving critProblem(). Understood.");
  return null;
}

// VERIFICATION, the same shape: one preparation, two entry points.
//
// prepareVerify() does everything that is not the signature check — reading
// the header, the crit MUST of RFC 7515 §4.1.11, the algorithm the verifier
// chose versus the one the token names, and rebuilding the signing input —
// and returns, for each signature in the JWS, either a finished verdict or
// the work still to do.
//
// opts: {
//   jws,                the serialized JWS, in any of the three forms
//   publicKey,          any key form resolveKey() accepts, or a CryptoKey
//   algId,              the algorithm the VERIFIER chose; omit to take the
//                       header's, which RFC 8725 §3.1 says not to do
//   detachedPayload,    the payload, for a JWS that carries none
//   backend,            'js' (default) or 'webcrypto'
//   secretEncoding      how to read an HMAC secret given as a string
// }
function prepareVerify(options) {
  log.debug("Entering prepareVerify().");
  var parsed = parseJws(options.jws);
  if (parsed.detached && options.detachedPayload == null) {
    throw new Error('This JWS carries no payload (it is detached — RFC 7515 ' +
        'App. F). Supply the payload it was signed over.');
  }
  var keyInput = withSecretEncoding(options.publicKey, options.secretEncoding);
  var entries = parsed.entries.map(function (entry, index) {
    var one = { index: index };
    try {
      var header = JSON.parse(bytesToStr(b64uToBytes(entry.protected || '')));
      one.header = header;
      one.unprotected = entry.header || null;
      var b64 = header.b64 === false ? false : true;
      one.b64 = b64;
      one.alg = header.alg;
      var spec = options.algId ? algSpec(options.algId)
        : algForHeader(header.alg, keyLengthHint(keyInput, header));
      if (options.algId && spec.alg !== header.alg) {
        // A verifier that trusts the header's `alg` over its own expectation
        // is the algorithm-confusion bug, so the caller's choice wins and the
        // mismatch is REPORTED rather than quietly accommodated.
        one.valid = false;
        one.reason = 'The header says alg=' + header.alg + ' but ' +
            spec.alg + ' was selected. RFC 8725 §3.1: the verifier decides ' +
            'the algorithm, not the token.';
        return { verdict: one };
      }
      var crit = critProblem(header);
      if (crit) {
        one.valid = false;
        one.reason = crit;
        return { verdict: one };
      }
      one.payload = parsed.detached ? options.detachedPayload
        : (b64 === false ? parsed.payload
                         : bytesToStr(b64uToBytes(parsed.payload)));
      return {
        verdict: one,
        spec: spec,
        input: signingInput(entry.protected || '', one.payload, b64),
        signature: b64uToBytes(entry.signature || ''),
        header: header,
        // A JWK Set is narrowed to ONE key here, before either backend sees
        // it, because which key is meant depends on the header and neither
        // backend knows about headers. Doing it per entry is not pedantry: a
        // general-serialization JWS may carry two signatures under different
        // kids, and picking one key for the whole document would verify one
        // of them against the other's key.
        keyInput: narrowToOneKey(keyInput, header, spec)
      };
    } catch (e) {
      one.valid = false;
      one.reason = e.message;
      return { verdict: one };
    }
  });
  log.debug("Leaving prepareVerify().");
  return { parsed: parsed, keyInput: keyInput, entries: entries };
}

function assembleVerify(prep) {
  log.debug("Entering assembleVerify().");
  var results = prep.entries.map(function (e) { return e.verdict; });
  var allValid = results.length > 0 && results.every(function (r) {
    return r.valid;
  });
  log.debug("Leaving assembleVerify().");
  return {
    valid: allValid,
    serialization: prep.parsed.serialization,
    detached: prep.parsed.detached,
    signatures: results,
    payload: results.length ? results[0].payload : undefined,
    header: results.length ? results[0].header : undefined,
    unsecured: results.length ? !!results[0].unsecured : false
  };
}

// The synchronous entry point: pure JS only.
function verifyJws(opts) {
  log.debug("Entering verifyJws().");
  var options = opts || {};
  var backend = backendFor(options.backend, options.publicKey);
  if (backend !== 'js') {
    throw new Error('verifyJws() is synchronous and the ' + backend +
        ' backend is not. Use verifyJwsAsync().');
  }
  var prep = prepareVerify(options);
  prep.entries.forEach(function (e) {
    if (e.verdict.valid !== undefined) return;
    try {
      var resolved = resolveKey(e.spec, e.keyInput, 'verify', e.header);
      e.verdict.backend = 'js';
      e.verdict.valid = verifyOctets(e.spec, resolved.key, e.input,
                                     e.signature);
      e.verdict.unsecured = e.spec.family === 'none';
      if (!e.verdict.valid) e.verdict.reason = 'The signature does not verify.';
    } catch (err) {
      e.verdict.valid = false;
      e.verdict.reason = err.message;
    }
  });
  log.debug("Leaving verifyJws().");
  return assembleVerify(prep);
}

// The asynchronous entry point. Either backend.
function verifyJwsAsync(opts) {
  log.debug("Entering verifyJwsAsync().");
  var options = opts || {};
  var prep;
  try {
    prep = prepareVerify(options);
  } catch (e) {
    log.debug("Leaving verifyJwsAsync(). Unreadable.");
    return Promise.reject(e);
  }
  var backend = backendFor(options.backend, prep.keyInput);
  var checks = prep.entries.map(function (e) {
    if (e.verdict.valid !== undefined) return Promise.resolve();
    // Reported per ENTRY rather than per call, because a general-serialization
    // JWS may carry two signatures whose algorithms do not take the same
    // engine — an ES256K one falls back to JavaScript while an RS256 one
    // beside it stays on Web Crypto.
    e.verdict.backend = webCryptoKnowsAlg(e.spec) ? backend : 'js';
    var work;
    try {
      if (backend === 'webcrypto' && webCryptoKnowsAlg(e.spec)) {
        work = webCryptoImport(e.spec, e.keyInput, 'verify')
          .then(function (key) {
            return crypto.subtle.verify(webCryptoSignParams(e.spec), key,
                                        e.signature, e.input);
          });
      } else {
        var resolved = resolveKey(e.spec, e.keyInput, 'verify', e.header);
        work = Promise.resolve(verifyOctets(e.spec, resolved.key, e.input,
                                            e.signature));
      }
    } catch (err) {
      e.verdict.valid = false;
      e.verdict.reason = err.message;
      return Promise.resolve();
    }
    return work.then(function (ok) {
      e.verdict.valid = !!ok;
      e.verdict.unsecured = e.spec.family === 'none';
      if (!e.verdict.valid) {
        e.verdict.reason = 'The signature does not verify.';
      }
    }, function (err) {
      e.verdict.valid = false;
      e.verdict.reason = err.message;
    });
  });
  log.debug("Leaving verifyJwsAsync().");
  return Promise.all(checks).then(function () {
    return assembleVerify(prep);
  });
}

// A string key that is really a shared secret has to say how it is written
// down. Callers pass `secretEncoding` beside the key rather than wrapping it,
// because the key comes out of a text field and the encoding out of a
// dropdown, and threading them separately is what the pages actually have.
function withSecretEncoding(key, encoding) {
  log.debug("Entering withSecretEncoding().");
  if (!encoding || typeof key !== 'string') {
    log.debug("Leaving withSecretEncoding(). Unchanged.");
    return key;
  }
  log.debug("Leaving withSecretEncoding(). Wrapped.");
  return { secret: key, encoding: encoding };
}

// EdDSA's curve lives in the key and nowhere in the header, so the LENGTH of
// the key is the only thing that can tell Ed25519 from Ed448. This reaches
// through the forms a key may arrive in to find that length, and returns
// nothing when it cannot — in which case algForHeader() says so by name.
// The `header` argument is only ever used for one thing, and it is the reason
// this function takes one at all: **EdDSA against a JWK SET**.
//
// RFC 8037 puts the curve in the KEY and not in the `alg` header, so `EdDSA`
// alone does not say whether a signature is Ed25519 or Ed448 — algForHeader()
// decides from the length of the key in hand. That worked for a bare JWK, for
// bytes and for a PEM, and could never work for a JWK Set: the set was measured
// before narrowToOneKey() had picked anything out of it, so the hint was null,
// the length was 0, and every EdDSA verification against a JWKS failed with
// "EdDSA key length 0 is neither Ed25519 (32) nor Ed448 (57)" — a message about
// the key that is really about the lookup, and one no caller could act on.
//
// Nothing here had noticed because the only EdDSA verifications in this tree
// took a pasted key. It surfaced the moment an identity provider published an
// OKP key in its JWKS and signed a UserInfo response with it.
function keyLengthHint(input, header) {
  log.debug("Entering keyLengthHint().");
  if (input instanceof Uint8Array) {
    log.debug("Leaving keyLengthHint(). Bytes.");
    return input;
  }
  var jwk = input && (input.jwk || (input.kty ? input : null));
  if (jwk && jwk.x) {
    log.debug("Leaving keyLengthHint(). From a JWK.");
    return b64uToBytes(jwk.x);
  }
  var set = asJwkSet(input);
  if (set) {
    // By `kid` when the header names one, which is what a JWKS-published key
    // almost always carries. Otherwise the only OKP key in the set, and only if
    // there is exactly one — guessing between two would pick the wrong curve
    // silently, which is worse than the error this replaces.
    var candidates = (set.keys || []).filter(function (k) {
      return header && header.kid ? k.kid === header.kid : k.kty === 'OKP';
    });
    if (candidates.length === 1 && candidates[0].x) {
      log.debug("Leaving keyLengthHint(). From a JWK Set.");
      return b64uToBytes(candidates[0].x);
    }
    log.debug("Leaving keyLengthHint(). The set names no single usable key.");
    return null;
  }
  if (typeof input === 'string' && /BEGIN/.test(input)) {
    try {
      var label = bytesLib.pemLabel(input) || '';
      var pem = /CERTIFICATE/.test(label) ? spkiFromCertificatePem(input)
                                          : input;
      log.debug("Leaving keyLengthHint(). From a PEM.");
      return spkiPublicBits(pem);
    } catch (e) {
      log.debug("Leaving keyLengthHint(). PEM unreadable.");
      return null;
    }
  }
  log.debug("Leaving keyLengthHint(). None.");
  return null;
}

module.exports = {
  ALGS: ALGS,
  HASHES: HASHES,
  algIds: algIds,
  algSpec: algSpec,
  algForHeader: algForHeader,
  generateKey: generateKey,
  publicJwk: publicJwk,
  privateJwk: privateJwk,
  validateJson: validateJson,
  compactJson: compactJson,
  buildProtectedHeader: buildProtectedHeader,
  signingInput: signingInput,
  signOctets: signOctets,
  verifyOctets: verifyOctets,
  signJws: signJws,
  signJwsAsync: signJwsAsync,
  parseJws: parseJws,
  verifyJws: verifyJws,
  verifyJwsAsync: verifyJwsAsync,
  // Key forms, exported because the pages that offer a key FIELD need to say
  // what they will accept, and because tests/jws_engine.js checks each
  // conversion against node's own crypto.
  spkiFromCertificatePem: spkiFromCertificatePem,
  spkiPublicBits: spkiPublicBits,
  pkcs8PrivateBits: pkcs8PrivateBits,
  jwkToKey: jwkToKey,
  selectFromJwks: selectFromJwks,
  narrowToOneKey: narrowToOneKey,
  resolveKey: resolveKey,
  secretBytes: secretBytes,
  webCryptoKnowsAlg: webCryptoKnowsAlg,
  webCryptoImportParams: webCryptoImportParams,
  webCryptoSignParams: webCryptoSignParams,
  webCryptoImport: webCryptoImport,
  payloadText: payloadText
};
