// File: openssl35.js
//
// ---------------------------------------------------------------------------
// THE POST-QUANTUM ORACLE, AND WHY IT IS NODE RATHER THAN THE `openssl`
// COMMAND EVERY OTHER PKI TEST USES.
//
// tests/pki_x509.js makes its assertions by handing certificates to OpenSSL,
// because a round trip through the implementation that wrote them cannot catch
// an encoding that is wrong and self-consistent. That argument applies with
// MORE force to ML-DSA, SLH-DSA and ML-KEM — nothing in this project has ever
// interoperated with another implementation of them — and it runs straight
// into a version wall:
//
//   * the `openssl` BINARY is whatever is on the PATH, and NOTHING HERE PINS
//     IT. ubuntu:latest ships 3.5 today and shipped 3.0 a release ago; an
//     Ubuntu 22.04 development host has 3.0.2. On 3.0 there are no
//     post-quantum algorithms at all: `openssl x509 -text` on an ML-DSA
//     certificate prints `Unable to load Public Key` and `openssl verify`
//     fails with `X509_PUBKEY_get0:decode error`, neither of which is a
//     statement about the certificate. A test that asserted through the
//     binary would therefore pass or fail on the base image's release date.
//   * node's OpenSSL moves with the NODE version, and every image here pins
//     that: 24.16 is linked against OpenSSL 3.5.6, the release that added
//     ML-KEM, ML-DSA and SLH-DSA. `crypto.createPublicKey()` reads their
//     SubjectPublicKeyInfo, `crypto.createPrivateKey()` reads all three arms
//     of their PKCS#8, and `crypto.verify(null, ...)` verifies their
//     signatures — identically on every machine that runs this suite.
//
// So the oracle for the post-quantum families is the SAME OpenSSL, reached
// through a different door. It is a genuinely independent implementation of
// the encodings and of the algorithms — the certificates under test are built
// by pkijs/asn1js and signed by @noble/post-quantum, and nothing about either
// is involved in the answers this module returns.
//
// WHAT IT CANNOT DO, and the tests say so rather than skipping quietly:
// OpenSSL 3.5 has no composite ML-DSA (the draft is not implemented by any
// released OpenSSL) and does not VERIFY the alternative-signature extensions,
// though 3.5 does print them. A composite certificate is therefore checked by
// this project's own verifier and by the arithmetic of its two halves; the
// hybrid certificates are checked by the `openssl` BINARY, which is the whole
// point of them — a validator that does not enforce those extensions must
// still accept the certificate.
// ---------------------------------------------------------------------------
const crypto = require("crypto");
const asn1js = require("asn1js");

var bunyan = require("bunyan");
var appconfig = require(process.env.CONFIG_FILE);
var log = bunyan.createLogger({ name: "openssl35",
    level: appconfig.LOG_LEVEL || "info" });

var probed = null;

// Whether this node's OpenSSL knows the post-quantum algorithms. Probed once
// by actually generating a key rather than by reading a version string: the
// algorithms can be compiled out, and a version comparison would say yes.
function available() {
  log.debug("Entering available().");
  if (probed === null) {
    try {
      crypto.generateKeyPairSync("ml-dsa-44");
      probed = true;
    } catch (e) {
      log.warn("openssl35: no post-quantum support in node's OpenSSL (" +
          process.versions.openssl + "): " + e.message);
      probed = false;
    }
  }
  log.debug("Leaving available(). " + probed);
  return probed;
}

// The sentence a test prints when it has to go on without the oracle. One
// place, so every skip says the same thing and names the fix.
function unavailableReason() {
  log.debug("Entering unavailableReason().");
  log.debug("Leaving unavailableReason().");
  return "node's OpenSSL is " + process.versions.openssl + ", which has no " +
      "ML-DSA/SLH-DSA/ML-KEM. The cross-checks against another " +
      "implementation are skipped; the images pin node 24.16 (OpenSSL 3.5), " +
      "so this only happens on a development machine running an older node.";
}

function publicKey(pem) {
  log.debug("Entering publicKey().");
  var key = crypto.createPublicKey(pem);
  log.debug("Leaving publicKey(). type=" + key.asymmetricKeyType);
  return key;
}

function privateKey(pem) {
  log.debug("Entering privateKey().");
  var key = crypto.createPrivateKey(pem);
  log.debug("Leaving privateKey(). type=" + key.asymmetricKeyType);
  return key;
}

// The algorithm name OpenSSL reads out of a key, which is the answer to "did
// the OID and the wrapping we wrote mean what we thought". Returns null when
// OpenSSL cannot read the key at all.
function keyTypeOf(pem) {
  log.debug("Entering keyTypeOf().");
  var type = null;
  try {
    type = crypto.createPublicKey(pem).asymmetricKeyType;
  } catch (e) {
    log.debug("keyTypeOf(): OpenSSL refused the key: " + e.message);
    type = null;
  }
  log.debug("Leaving keyTypeOf(). " + type);
  return type;
}

// A one-shot signature verification: `null` as the algorithm is how node asks
// for the key's own built-in hashing, which is what ML-DSA and SLH-DSA (and
// Ed25519) do.
function verify(data, pem, signature) {
  log.debug("Entering verify().");
  var ok = crypto.verify(null, Buffer.from(data),
      crypto.createPublicKey(pem), Buffer.from(signature));
  log.debug("Leaving verify(). " + ok);
  return ok;
}

function sign(data, pem) {
  log.debug("Entering sign().");
  var out = crypto.sign(null, Buffer.from(data), crypto.createPrivateKey(pem));
  log.debug("Leaving sign(). " + out.length + " bytes.");
  return new Uint8Array(out);
}

// The three fields of a Certificate that a signature check needs, taken apart
// with asn1js because there is nothing else in reach that can read a
// certificate whose algorithms OpenSSL 3.0 does not know. This is DER
// surgery on the outermost SEQUENCE only — tbsCertificate, signatureAlgorithm,
// signatureValue — and it makes no claim about anything inside them.
function certificateParts(der) {
  log.debug("Entering certificateParts().");
  var input = new Uint8Array(der);
  var parsed = asn1js.fromBER(input.slice().buffer);
  if (parsed.offset === -1) {
    log.debug("Leaving certificateParts(). Unparseable.");
    throw new Error("this is not a DER Certificate");
  }
  var items = parsed.result.valueBlock.value;
  var oidBlock = items[1].valueBlock.value[0];
  var out = {
    tbs: new Uint8Array(items[0].toBER(false)),
    signatureAlgorithmOid: oidBlock.valueBlock.toString(),
    signature: new Uint8Array(items[2].valueBlock.valueHexView)
  };
  log.debug("Leaving certificateParts().");
  return out;
}

// Verify a certificate's signature with the ISSUER's public key, as OpenSSL
// reads both. This is the check `openssl verify` would make if it knew the
// algorithm: same library, same key, same bytes.
function verifyCertificate(certDer, issuerPublicPem) {
  log.debug("Entering verifyCertificate().");
  var parts = certificateParts(certDer);
  var ok = verify(parts.tbs, issuerPublicPem, parts.signature);
  log.debug("Leaving verifyCertificate(). " + ok);
  return ok;
}

// The public half of a private key, derived by OpenSSL. This is what
// `openssl pkey -pubout` does for the classical families, and it is the check
// that catches a pane showing two unrelated keys.
function publicFromPrivate(pem) {
  log.debug("Entering publicFromPrivate().");
  var out = crypto.createPublicKey(crypto.createPrivateKey(pem))
      .export({ type: "spki", format: "pem" });
  log.debug("Leaving publicFromPrivate().");
  return out;
}

// The public key out of a certificate, as PEM, so that a chain can be checked
// link by link without this project's own parser being involved.
function publicKeyFromCertificate(certPem) {
  log.debug("Entering publicKeyFromCertificate().");
  var pem = crypto.createPublicKey(certPem)
      .export({ type: "spki", format: "pem" });
  log.debug("Leaving publicKeyFromCertificate().");
  return pem;
}

module.exports = {
  available: available,
  unavailableReason: unavailableReason,
  publicKey: publicKey,
  privateKey: privateKey,
  keyTypeOf: keyTypeOf,
  verify: verify,
  sign: sign,
  publicFromPrivate: publicFromPrivate,
  certificateParts: certificateParts,
  verifyCertificate: verifyCertificate,
  publicKeyFromCertificate: publicKeyFromCertificate
};
