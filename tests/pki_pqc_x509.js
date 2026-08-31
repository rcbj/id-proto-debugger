// File: pki_pqc_x509.js
//
// The POST-QUANTUM half of the PKI workflow: client/src/pqc_x509.js, the
// post-quantum entries in client/src/key_material.js and client/src/x509.js,
// and the three ways a certificate here can carry post-quantum cryptography.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A SECOND FILE RATHER THAN MORE ROWS IN pki_x509.js
//
// pki_x509.js is a cross product: every signature algorithm against every
// subject key algorithm, ~240 certificates, all of them handed to the `openssl`
// binary. Adding thirty-four post-quantum algorithms to that matrix would do
// two things, and both are wrong:
//
//   * it would multiply the matrix by six and cost minutes per run for cells
//     that say nothing new — an ML-DSA-87 CA over each of forty subject keys
//     tests the subject key encodings forty times and ML-DSA-87 once;
//   * every one of those cells would be checked by an ORACLE THAT CANNOT READ
//     THEM. The `openssl` binary in these images is 3.0 and has no
//     post-quantum algorithms at all: it reports an ML-DSA certificate as
//     `X509_PUBKEY_get0:decode error`, which is a statement about OpenSSL 3.0
//     and not about the certificate.
//
// So pki_x509.js keeps its matrix over the classical algorithms and this file
// takes the post-quantum ones, with tests/openssl35.js as the oracle — the
// same OpenSSL, version 3.5.6, reached through node's crypto module instead of
// through the command line. See the header of that file.
//
// ---------------------------------------------------------------------------
// THE THREE WAYS, AND WHAT CAN CHECK EACH ONE
//
//   1. PURE — an ML-DSA or SLH-DSA key with an ML-DSA or SLH-DSA signature
//      (RFC 9881, RFC 9909), and an ML-KEM key as a SUBJECT (RFC 9935).
//      OpenSSL 3.5 knows all of these, so every one of them is checked by an
//      implementation this project did not write.
//   2. COMPOSITE — one OID naming an ML-DSA key and a traditional key at once
//      (draft-ietf-lamps-pq-composite-sigs-19). NO released OpenSSL implements
//      it, so the checks here are this project's own verifier plus the
//      arithmetic that has to hold either way: the two halves split at the
//      lengths FIPS 204 fixes, each half verifies on its own against the
//      component key, and tampering with EITHER half must fail — which is the
//      property a composite exists for and the one an implementation that
//      checks only the post-quantum half would pass without.
//   3. HYBRID — a classical certificate carrying a second key and a second
//      signature in the X.509 (2019) alternative extensions. Here the oracle
//      is the OLD `openssl` binary, deliberately: the whole claim of a hybrid
//      certificate is that a validator which has never heard of any of this
//      still accepts it, and OpenSSL 3.0 is exactly such a validator.
//
// ---------------------------------------------------------------------------
// ONE PERFORMANCE DECISION IS VISIBLE IN THE ASSERTIONS AND IS WRITTEN DOWN
// HERE SO IT IS NOT MISTAKEN FOR AN OVERSIGHT.
//
// SLH-DSA's six "s" (small signature) parameter sets are slow to sign in
// JavaScript — measured on this tree, SLH-DSA-SHAKE-256s takes 18 seconds for
// ONE signature, against 0.9 seconds for the same operation in OpenSSL's C.
// Issuing a CA and a leaf with each of the six would add about three minutes
// to every run of this suite.
//
// So the six slow sets are covered in the direction that costs nothing:
// OPENSSL SIGNS AND THIS CODE VERIFIES, over the identical encodings, which
// exercises the SubjectPublicKeyInfo, the PKCS#8 and the verify path. The
// seven fast sets (the six "f" sets and SLH-DSA-SHA2-128s) additionally issue
// real certificates, which is where the signing path is exercised. Setting
// PQC_SLOW=1 issues certificates with all twelve and takes the three minutes.
//
// Node only — no browser, no services, no network — so it never skips, except
// for the post-quantum cross-checks when node's own OpenSSL is older than 3.5,
// which the images make impossible and a development machine can still do.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "pki_pqc_x509",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const paths = require("./module_paths.js");
function clientModule(name) {
  log.debug("Entering clientModule(). name=" + name);
  const found = paths.requireSharedModule(
    [path.join(__dirname, "..", "client", "src", name),
     path.join(__dirname, name)],
    "client/src/" + name);
  log.debug("Leaving clientModule().");
  return found;
}

const keys = clientModule("key_material.js");
const x509 = clientModule("x509.js");
const pqx = clientModule("pqc_x509.js");
const oracle = require("./openssl35.js");

const SLOW_SETS = ["slh-dsa-sha2-192s", "slh-dsa-sha2-256s",
                   "slh-dsa-shake-128s", "slh-dsa-shake-192s",
                   "slh-dsa-shake-256s"];

var workDir = null;
var keyCache = {};
var crossChecks = 0;

function tempDir() {
  log.debug("Entering tempDir().");
  if (!workDir) {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-pqc-"));
  }
  log.debug("Leaving tempDir().");
  return workDir;
}

async function keyFor(algId) {
  log.debug("Entering keyFor(). alg=" + algId);
  if (!keyCache[algId]) {
    keyCache[algId] = await keys.generateKeyPair(algId);
  }
  log.debug("Leaving keyFor().");
  return keyCache[algId];
}

function postQuantumAlgIds() {
  log.debug("Entering postQuantumAlgIds().");
  const out = keys.keyAlgIds().filter(function (id) {
    return keys.keyAlg(id).kind === "pqc";
  });
  log.debug("Leaving postQuantumAlgIds(). " + out.length + " of them.");
  return out;
}

function familyOf(algId) {
  log.debug("Entering familyOf(). alg=" + algId);
  const family = pqx.alg(algId).family;
  log.debug("Leaving familyOf().");
  return family;
}

// A certificate signed with this algorithm, self-signed unless an issuer is
// given. Kept here rather than inline so that every case below issues its
// certificates the same way and a failure names the algorithm.
async function issue(algId, subject, options) {
  log.debug("Entering issue(). alg=" + algId);
  const opts = options || {};
  const key = opts.subjectKey || await keyFor(algId);
  const signerKey = opts.signerKey || key;
  const spec = {
    profile: opts.profile || "root-ca",
    subject: subject,
    subjectPublicKey: key.publicPem,
    signatureAlg: opts.signatureAlg || algId,
    extensions: x509.defaultExtensions(opts.profile || "root-ca")
  };
  if (opts.issuerCertPem) {
    spec.issuer = { certificatePem: opts.issuerCertPem,
                   privateKeyPem: signerKey.privatePem,
                   keyAlg: opts.signerAlg };
  } else {
    spec.issuerPrivateKey = signerKey.privatePem;
  }
  if (opts.subjectAltPublicKey) {
    spec.subjectAltPublicKey = opts.subjectAltPublicKey;
  }
  if (opts.altSignature) spec.altSignature = opts.altSignature;
  const cert = await x509.issueCertificate(spec);
  log.debug("Leaving issue().");
  return cert;
}

// ---------------------------------------------------------------------------
// 1. The registry says what the standards say.
//
// Every fact in it is a transcription — an OID, a length, a label — and a
// transcription is the error class that produces bytes which are wrong and
// self-consistent. These are the values written out of RFC 9881 section 5,
// RFC 9909 section 5, RFC 9935 section 6 and section 6 of the composite draft
// BY HAND HERE, so that agreeing with the module means agreeing with two
// independent readings rather than with itself.
// ---------------------------------------------------------------------------
function theRegistryMatchesTheStandards() {
  log.debug("Entering theRegistryMatchesTheStandards().");
  const expected = {
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
    "SLH-DSA-SHA2-128s": "2.16.840.1.101.3.4.3.20",
    "SLH-DSA-SHA2-128f": "2.16.840.1.101.3.4.3.21",
    "SLH-DSA-SHA2-192s": "2.16.840.1.101.3.4.3.22",
    "SLH-DSA-SHA2-192f": "2.16.840.1.101.3.4.3.23",
    "SLH-DSA-SHA2-256s": "2.16.840.1.101.3.4.3.24",
    "SLH-DSA-SHA2-256f": "2.16.840.1.101.3.4.3.25",
    "SLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.26",
    "SLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.27",
    "SLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.28",
    "SLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.29",
    "SLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.30",
    "SLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.31",
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "mldsa44-rsa2048-pss-sha256": "1.3.6.1.5.5.7.6.37",
    "mldsa44-rsa2048-pkcs15-sha256": "1.3.6.1.5.5.7.6.38",
    "mldsa44-ed25519-sha512": "1.3.6.1.5.5.7.6.39",
    "mldsa44-ecdsa-p256-sha256": "1.3.6.1.5.5.7.6.40",
    "mldsa65-rsa3072-pss-sha512": "1.3.6.1.5.5.7.6.41",
    "mldsa65-rsa3072-pkcs15-sha512": "1.3.6.1.5.5.7.6.42",
    "mldsa65-rsa4096-pss-sha512": "1.3.6.1.5.5.7.6.43",
    "mldsa65-rsa4096-pkcs15-sha512": "1.3.6.1.5.5.7.6.44",
    "mldsa65-ecdsa-p256-sha512": "1.3.6.1.5.5.7.6.45",
    "mldsa65-ecdsa-p384-sha512": "1.3.6.1.5.5.7.6.46",
    "mldsa65-ed25519-sha512": "1.3.6.1.5.5.7.6.48",
    "mldsa87-ecdsa-p384-sha512": "1.3.6.1.5.5.7.6.49",
    "mldsa87-ed448-shake256": "1.3.6.1.5.5.7.6.51",
    "mldsa87-rsa3072-pss-sha512": "1.3.6.1.5.5.7.6.52",
    "mldsa87-rsa4096-pss-sha512": "1.3.6.1.5.5.7.6.53",
    "mldsa87-ecdsa-p521-sha512": "1.3.6.1.5.5.7.6.54"
  };
  const ids = pqx.algIds();
  assert.deepStrictEqual(ids.slice().sort(), Object.keys(expected).sort(),
    "the post-quantum registry and this test's transcription of the " +
    "standards have diverged — an algorithm nothing here names is an " +
    "algorithm nothing here checks");
  ids.forEach(function (id) {
    assert.strictEqual(pqx.alg(id).oid, expected[id],
      id + ": the OID in the registry is not the one the standard assigns");
    assert.strictEqual(pqx.algForOid(expected[id]).id, id,
      id + ": the OID does not map back to the algorithm");
  });
  // The two composite algorithms that are absent are absent ON PURPOSE, and
  // the record of why is part of the module rather than of somebody's memory.
  const missing = Object.keys(pqx.COMPOSITE_MISSING);
  assert.strictEqual(missing.length, 2,
    "the brainpool composites are the two the draft defines and this build " +
    "does not implement; if that has changed, this test should say so");
  missing.forEach(function (name) {
    assert.ok(/brainpool/i.test(pqx.COMPOSITE_MISSING[name].why),
      name + ": the reason for its absence no longer names the curve");
  });
  // The domain-separation prefix, byte for byte, from section 2.2.
  assert.strictEqual(Buffer.from(pqx.COMPOSITE_PREFIX).toString("hex"),
    "436f6d706f73697465416c676f726974686d5369676e61747572657332303235",
    "the composite prefix is not the ASCII of " +
    "CompositeAlgorithmSignatures2025");
  log.info("Checked " + ids.length + " algorithm identifiers against the " +
      "standards.");
  log.debug("Leaving theRegistryMatchesTheStandards().");
}

// ---------------------------------------------------------------------------
// 2. Every key encodes the way the RFCs say, and OpenSSL reads it back.
//
// This is the test that catches an SPKI with the public key wrapped in an
// OCTET STRING inside the BIT STRING (one extra layer, parses perfectly,
// verifies nothing), a PKCS#8 whose seed is EXPLICIT [0] rather than IMPLICIT
// (two extra bytes), and an AlgorithmIdentifier carrying a NULL where the RFC
// says the parameters are absent.
// ---------------------------------------------------------------------------
async function everyKeyEncodesAsTheRfcsSayAndOpensslAgrees() {
  log.debug("Entering everyKeyEncodesAsTheRfcsSayAndOpensslAgrees().");
  // OpenSSL's own name for each of these is exactly the lower-cased
  // algorithm id — ml-dsa-44, slh-dsa-shake-256f, ml-kem-1024 — which is
  // convenient and is also a check: if a name here ever stopped matching,
  // the key would be read as something else rather than refused.
  for (const algId of postQuantumAlgIds()) {
    const pair = await keyFor(algId);
    assert.ok(/^-----BEGIN PRIVATE KEY-----/.test(pair.privatePem),
      algId + ": the private key is not a PKCS#8 PEM");
    assert.ok(/^-----BEGIN PUBLIC KEY-----/.test(pair.publicPem),
      algId + ": the public key is not a SubjectPublicKeyInfo PEM");

    // This build reads back what it wrote, in both directions.
    // The registry spells ML-DSA-44 the way the standard does and
    // key_material.js lower-cases every id it holds, so the comparison is
    // case-insensitive here rather than one of the two being "right".
    const spki = pqx.decodeSpki(pemBytes(pair.publicPem));
    assert.ok(spki && spki.alg.toLowerCase() === algId,
      algId + ": decodeSpki() did not recognise this build's own SPKI");
    const p8 = pqx.decodePkcs8(pemBytes(pair.privatePem));
    assert.ok(p8 && p8.alg.toLowerCase() === algId,
      algId + ": decodePkcs8() did not recognise this build's own PKCS#8");
    assert.strictEqual(p8.form, familyOf(algId) === "ML-DSA" ||
        familyOf(algId) === "ML-KEM" ? "seed" : "raw",
      algId + ": the private key was written in an unexpected CHOICE arm");
    assert.strictEqual(
      Buffer.from(pqx.publicFromPrivate(algId, p8.priv)).toString("hex"),
      Buffer.from(spki.pub).toString("hex"),
      algId + ": the public key does not belong to the private key");

    if (!oracle.available()) continue;
    // And OpenSSL reads it too, which is the half that matters.
    const name = familyOf(algId) === "Composite ML-DSA" ? null : algId;
    if (name) {
      assert.strictEqual(oracle.keyTypeOf(pair.publicPem), name,
        algId + ": OpenSSL 3.5 does not read this SubjectPublicKeyInfo as " +
        name);
      assert.strictEqual(
        oracle.privateKey(pair.privatePem).asymmetricKeyType, name,
        algId + ": OpenSSL 3.5 does not read this PKCS#8 as " + name);
      crossChecks += 2;
    } else {
      // The composites: no released OpenSSL knows the OID, and it must say so
      // rather than silently read the key as something else.
      assert.strictEqual(oracle.keyTypeOf(pair.publicPem), null,
        algId + ": OpenSSL claims to know a composite algorithm — if a " +
        "release has implemented the draft, this test should start using it");
    }
  }
  log.debug("Leaving everyKeyEncodesAsTheRfcsSayAndOpensslAgrees().");
}

function pemBytes(pem) {
  log.debug("Entering pemBytes().");
  const out = new Uint8Array(Buffer.from(
      String(pem).replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
      "base64"));
  log.debug("Leaving pemBytes().");
  return out;
}

// ---------------------------------------------------------------------------
// 3. All three arms of the ML-DSA and ML-KEM private key CHOICE.
//
// RFC 9881 section 6 defines seed, expandedKey and both; the RFC recommends
// the first and OpenSSL 3.5 writes the third, so a build that can only produce
// or only consume one of them interoperates with half the world.
// ---------------------------------------------------------------------------
async function allThreePrivateKeyArmsRoundTrip() {
  log.debug("Entering allThreePrivateKeyArmsRoundTrip().");
  const seeded = postQuantumAlgIds().filter(function (id) {
    return familyOf(id) === "ML-DSA" || familyOf(id) === "ML-KEM";
  });
  assert.ok(seeded.length === 6,
    "the seeded families are ML-DSA's three parameter sets and ML-KEM's " +
    "three; this test found " + seeded.length);
  for (const algId of seeded) {
    const pair = await keyFor(algId);
    const seed = pqx.decodePkcs8(pemBytes(pair.privatePem)).priv;
    for (const form of ["seed", "expandedKey", "both"]) {
      const pem = pqx.privatePem(algId, seed, { form: form });
      const read = pqx.decodePkcs8(pemBytes(pem));
      assert.strictEqual(read.form, form,
        algId + ": a " + form + " private key read back as " + read.form);
      if (form === "expandedKey") {
        assert.strictEqual(read.priv, null,
          algId + ": the expandedKey arm carries no seed and must not " +
          "invent one — the derivation is one-way");
        assert.strictEqual(read.expanded.length,
          pqx.expandPrivate(pqx.alg(algId), seed).length,
          algId + ": the expanded key is the wrong length");
      } else {
        assert.strictEqual(Buffer.from(read.priv).toString("hex"),
          Buffer.from(seed).toString("hex"),
          algId + ": the seed did not survive the " + form + " arm");
      }
      if (!oracle.available()) continue;
      assert.ok(oracle.privateKey(pem).asymmetricKeyType,
        algId + ": OpenSSL 3.5 refused the " + form + " arm");
      crossChecks += 1;
    }
  }
  log.debug("Leaving allThreePrivateKeyArmsRoundTrip().");
}

// ---------------------------------------------------------------------------
// 4. Pure post-quantum certificates, verified by OpenSSL 3.5.
// ---------------------------------------------------------------------------
async function pureCertificatesVerifyAgainstOpenssl() {
  log.debug("Entering pureCertificatesVerifyAgainstOpenssl().");
  const slow = process.env.PQC_SLOW === "1";
  const signing = postQuantumAlgIds().filter(function (id) {
    if (pqx.alg(id).use !== "sig") return false;
    if (familyOf(id) === "Composite ML-DSA") return false;
    return slow || SLOW_SETS.indexOf(id) < 0;
  });
  let issued = 0;
  for (const algId of signing) {
    const key = await keyFor(algId);
    const ca = await issue(algId, "CN=" + algId + " Root,O=idptools");
    assert.strictEqual(ca.signatureAlg, algId,
      algId + ": the certificate reports a different signature algorithm");
    // A leaf over an ML-KEM key, because a post-quantum CA certifying a
    // post-quantum KEM key is the shape an encryption certificate has.
    const kemKey = await keyFor("ml-kem-768");
    const leaf = await issue(algId, "CN=kem-leaf.example,O=idptools", {
      profile: "tls-server", subjectKey: kemKey, signerKey: key,
      signerAlg: algId, issuerCertPem: ca.pem, signatureAlg: algId
    });
    const chain = await x509.verifyChain([leaf.pem, ca.pem]);
    assert.ok(chain[0].signatureValid && chain[1].signatureValid,
      algId + ": this build does not accept its own chain");
    issued += 2;
    if (!oracle.available()) continue;
    assert.ok(oracle.verifyCertificate(ca.der, pemOf(ca)),
      algId + ": OpenSSL 3.5 refused the self-signature on the CA");
    assert.ok(oracle.verifyCertificate(leaf.der, pemOf(ca)),
      algId + ": OpenSSL 3.5 refused the leaf's signature");
    // The subject key of the leaf is the KEM key, and OpenSSL must read it as
    // one — a certificate is the only place an ML-KEM public key appears.
    assert.strictEqual(
      oracle.keyTypeOf(oracle.publicKeyFromCertificate(leaf.pem)),
      "ml-kem-768",
      algId + ": OpenSSL does not read the leaf's subject key as ML-KEM-768");
    crossChecks += 3;
  }
  log.info("Issued " + issued + " pure post-quantum certificates over " +
      signing.length + " algorithms.");
  assert.ok(issued >= 16,
    "only " + issued + " pure post-quantum certificates were issued");
  log.debug("Leaving pureCertificatesVerifyAgainstOpenssl().");
}

// The issuer's public key as PEM, taken out of its own certificate by OpenSSL
// rather than by this codebase.
function pemOf(cert) {
  log.debug("Entering pemOf().");
  const pem = oracle.available()
    ? oracle.publicKeyFromCertificate(cert.pem)
    : null;
  log.debug("Leaving pemOf().");
  return pem;
}

// ---------------------------------------------------------------------------
// 5. The six slow SLH-DSA parameter sets, in the direction that is cheap.
//
// OpenSSL signs (in C, in under a second) and this build verifies, over the
// encodings this build produced. What that does not exercise is the signing
// path for those six sets — which is the same code as the six fast ones with a
// different parameter object — and PQC_SLOW=1 covers it at a cost of about
// three minutes.
// ---------------------------------------------------------------------------
async function theSlowParameterSetsVerifyWhatOpensslSigns() {
  log.debug("Entering theSlowParameterSetsVerifyWhatOpensslSigns().");
  if (!oracle.available()) {
    log.warn("Skipping: " + oracle.unavailableReason());
    log.debug("Leaving theSlowParameterSetsVerifyWhatOpensslSigns().");
    return;
  }
  const message = Buffer.from("a message signed by OpenSSL, verified here");
  for (const algId of SLOW_SETS) {
    const pair = await keyFor(algId);
    const signature = oracle.sign(message, pair.privatePem);
    const pub = pqx.decodeSpki(pemBytes(pair.publicPem)).pub;
    assert.ok(await pqx.verify(algId, signature, message, pub),
      algId + ": this build cannot verify a signature OpenSSL 3.5 made with " +
      "the key this build generated — the two disagree about the algorithm, " +
      "the key encoding, or both");
    const tampered = Uint8Array.from(signature);
    tampered[10] ^= 0x01;
    assert.strictEqual(await pqx.verify(algId, tampered, message, pub), false,
      algId + ": a tampered signature verified");
    crossChecks += 1;
  }
  log.debug("Leaving theSlowParameterSetsVerifyWhatOpensslSigns().");
}

// ---------------------------------------------------------------------------
// 6. Composite ML-DSA: both halves, and both halves failing.
// ---------------------------------------------------------------------------
async function compositeCertificatesNeedBothHalves() {
  log.debug("Entering compositeCertificatesNeedBothHalves().");
  const composites = postQuantumAlgIds().filter(function (id) {
    return familyOf(id) === "Composite ML-DSA";
  });
  assert.strictEqual(composites.length, 16,
    "sixteen of the draft's eighteen composite algorithms are implemented " +
    "here; this run found " + composites.length);
  for (const algId of composites) {
    const key = await keyFor(algId);
    const ca = await issue(algId, "CN=" + algId + ",O=idptools");
    const chain = await x509.verifyChain([ca.pem]);
    assert.strictEqual(chain[0].signatureValid, true,
      algId + ": the composite self-signature does not verify");

    // The lengths the draft fixes, which is what makes deserialization
    // possible at all: the ML-DSA half is fixed-width and the traditional half
    // is whatever remains.
    const cfg = pqx.alg(algId).composite;
    const pub = pqx.decodeSpki(pemBytes(key.publicPem)).pub;
    const halves = pqx.splitCompositePublic(cfg, pub);
    assert.strictEqual(halves.mldsa.length,
      { "ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592 }[cfg.mldsa],
      algId + ": the ML-DSA half of the public key is the wrong length");

    // Tampering with either half must be refused. A verifier that checks only
    // the post-quantum half passes every other test in this file.
    const message = Buffer.from("composite tamper check");
    const priv = pqx.decodePkcs8(pemBytes(key.privatePem)).priv;
    const signature = await pqx.sign(algId, message, priv);
    assert.ok(await pqx.verify(algId, signature, message, pub),
      algId + ": a fresh composite signature does not verify");
    const sigHalves = pqx.splitCompositeSignature(cfg, signature);
    const breakMlDsa = Uint8Array.from(signature);
    breakMlDsa[7] ^= 0x01;
    assert.strictEqual(await pqx.verify(algId, breakMlDsa, message, pub),
      false, algId + ": a broken ML-DSA half verified");
    const breakTrad = Uint8Array.from(signature);
    breakTrad[sigHalves.mldsa.length + 8] ^= 0x01;
    assert.strictEqual(await pqx.verify(algId, breakTrad, message, pub), false,
      algId + ": a broken traditional half verified — this is the check a " +
      "composite exists for");
    // And the domain separation: the same key over the same message under a
    // DIFFERENT composite algorithm must not verify, which is what the label
    // in M' and in the ML-DSA context is there to guarantee.
    const other = composites.filter(function (id) {
      return pqx.alg(id).composite.mldsa === cfg.mldsa && id !== algId;
    })[0];
    if (other) {
      assert.strictEqual(
        await pqx.verify(algId, await pqx.sign(other, message,
            await borrowedPrivate(other, algId, priv)), message, pub),
        false, algId + ": a signature made under " + other + " verified");
    }
  }
  log.info("Checked " + composites.length + " composite algorithms.");
  log.debug("Leaving compositeCertificatesNeedBothHalves().");
}

// The same key material presented as another composite algorithm, where the
// two share an ML-DSA parameter set and a traditional shape. Returns the
// private key unchanged when they do not, in which case the cross-algorithm
// check below is skipped rather than made against a key of the wrong size.
async function borrowedPrivate(otherId, algId, priv) {
  log.debug("Entering borrowedPrivate().");
  const mine = pqx.alg(algId).composite;
  const theirs = pqx.alg(otherId).composite;
  if (mine.trad.kind !== theirs.trad.kind ||
      mine.trad.curve !== theirs.trad.curve ||
      mine.trad.bits !== theirs.trad.bits) {
    const own = await keyFor(otherId);
    log.debug("Leaving borrowedPrivate(). Different shape.");
    return pqx.decodePkcs8(pemBytes(own.privatePem)).priv;
  }
  log.debug("Leaving borrowedPrivate(). Same shape.");
  return priv;
}

// ---------------------------------------------------------------------------
// 7. Mixed chains: a classical CA over a post-quantum leaf and the reverse.
//
// This is the case an organisation actually has during a migration, and it is
// the one where an implementation that assumes both ends of a link are the
// same family falls over.
// ---------------------------------------------------------------------------
async function mixedChainsVerifyEndToEnd() {
  log.debug("Entering mixedChainsVerifyEndToEnd().");
  const roots = ["rsa-2048", "ec-p384", "ed25519", "ml-dsa-65",
                 "slh-dsa-sha2-128f", "mldsa44-ecdsa-p256-sha256"];
  const leaves = ["rsa-2048", "ec-p256", "ed25519", "ml-dsa-44",
                  "slh-dsa-shake-128f", "ml-kem-1024",
                  "mldsa65-ed25519-sha512"];
  let links = 0;
  for (const rootAlg of roots) {
    const rootKey = await keyFor(rootAlg);
    const rootSig = x509.signatureAlgorithmsFor(keys.keyAlg(rootAlg))[0];
    const root = await issue(rootAlg, "CN=Mixed Root " + rootAlg, {
      signatureAlg: rootSig });
    // An intermediate whose key is deliberately of the OTHER kind from the
    // root's, so every chain here crosses the boundary at least once.
    const midAlg = pqx.alg(rootAlg) ? "ec-p256" : "ml-dsa-44";
    const midKey = await keyFor(midAlg);
    const midSig = x509.signatureAlgorithmsFor(keys.keyAlg(midAlg))[0];
    const mid = await issue(rootAlg, "CN=Mixed Intermediate " + midAlg, {
      profile: "intermediate-ca", subjectKey: midKey, signerKey: rootKey,
      signerAlg: rootAlg, issuerCertPem: root.pem, signatureAlg: rootSig });
    for (const leafAlg of leaves) {
      const leafKey = await keyFor(leafAlg);
      const leaf = await issue(midAlg, "CN=leaf-" + leafAlg + ".example", {
        profile: "tls-server", subjectKey: leafKey, signerKey: midKey,
        signerAlg: midAlg, issuerCertPem: mid.pem, signatureAlg: midSig });
      const chain = await x509.verifyChain([leaf.pem, mid.pem, root.pem]);
      chain.forEach(function (link, i) {
        assert.strictEqual(link.signatureValid, true,
          "link " + i + " of " + rootAlg + " -> " + midAlg + " -> " +
          leafAlg + " does not verify: " + (link.error || ""));
        assert.strictEqual(link.namesMatch, true,
          "link " + i + " of " + rootAlg + " -> " + midAlg + " -> " +
          leafAlg + " does not chain by name");
      });
      links += chain.length;
    }
  }
  log.info("Verified " + links + " links across mixed classical/" +
      "post-quantum chains.");
  assert.ok(links >= 100,
    "the mixed-chain matrix has shrunk to " + links + " links");
  log.debug("Leaving mixedChainsVerifyEndToEnd().");
}

// ---------------------------------------------------------------------------
// 8. The hybrid certificate, and the promise it makes to OLD software.
// ---------------------------------------------------------------------------
async function hybridCertificatesCarryTwoSignatures() {
  log.debug("Entering hybridCertificatesCarryTwoSignatures().");
  const pairs = [
    { classical: "ec-p256", classicalSig: "sha256-ecdsa", alt: "ml-dsa-44" },
    { classical: "rsa-2048", classicalSig: "sha256-rsa", alt: "ml-dsa-65" },
    { classical: "ed25519", classicalSig: "ed25519",
      alt: "slh-dsa-sha2-128f" },
    { classical: "ec-p384", classicalSig: "sha384-rsapss",
      alt: "mldsa44-ed25519-sha512", classicalKey: "rsa-3072" }
  ];
  for (const combo of pairs) {
    const classicalAlg = combo.classicalKey || combo.classical;
    const caKey = await keyFor(classicalAlg);
    const caAltKey = await keyFor(combo.alt);
    const ca = await issue(classicalAlg, "CN=Hybrid Root " + combo.alt, {
      signatureAlg: combo.classicalSig,
      subjectAltPublicKey: caAltKey.publicPem,
      altSignature: { signatureAlg: combo.alt,
                     privateKeyPem: caAltKey.privatePem }
    });
    const leafKey = await keyFor("ec-p256");
    const leafAltKey = await keyFor(combo.alt);
    const leaf = await issue(classicalAlg, "CN=hybrid-leaf.example", {
      profile: "tls-server", subjectKey: leafKey, signerKey: caKey,
      signerAlg: classicalAlg, issuerCertPem: ca.pem,
      signatureAlg: combo.classicalSig,
      subjectAltPublicKey: leafAltKey.publicPem,
      altSignature: { signatureAlg: combo.alt,
                     privateKeyPem: caAltKey.privatePem }
    });

    const chain = await x509.verifyChain([leaf.pem, ca.pem]);
    chain.forEach(function (link, i) {
      assert.strictEqual(link.signatureValid, true,
        combo.alt + ": the conventional signature on link " + i + " fails");
      assert.ok(link.alternative && link.alternative.present,
        combo.alt + ": link " + i + " reports no alternative signature");
      assert.strictEqual(link.alternative.valid, true,
        combo.alt + ": the alternative signature on link " + i +
        " does not verify: " + (link.alternative.reason || ""));
    });

    // THE POINT OF THE WHOLE EXERCISE: OpenSSL 3.0 — which has never heard of
    // ML-DSA, of the composite draft, or of clause 9.8 — must verify this
    // chain as an ordinary one and ignore the three extensions.
    const caFile = writePem("hybrid-ca.pem", ca.pem);
    const leafFile = writePem("hybrid-leaf.pem", leaf.pem);
    const verdict = execFileSync("openssl",
        ["verify", "-CAfile", caFile, leafFile], { encoding: "utf8" });
    assert.ok(/OK/.test(verdict),
      combo.alt + ": OpenSSL 3.0 refused a hybrid certificate, which defeats " +
      "the entire purpose of putting the second key in an extension: " +
      verdict);
    const text = execFileSync("openssl",
        ["x509", "-in", leafFile, "-noout", "-text"], { encoding: "utf8" });
    ["2.5.29.72", "2.5.29.73", "2.5.29.74"].forEach(function (oid) {
      assert.ok(text.indexOf(oid) >= 0,
        combo.alt + ": OpenSSL does not report extension " + oid + ", so it " +
        "is not in the certificate");
    });

    // A hybrid certificate whose alternative signature is tampered with must
    // be reported as invalid — and its conventional signature must still be
    // fine, because the two are independent.
    const broken = await breakAlternativeSignature(leaf.pem);
    const brokenChain = await x509.verifyChain([broken, ca.pem]);
    assert.strictEqual(brokenChain[0].alternative.valid, false,
      combo.alt + ": a tampered alternative signature was accepted");
  }
  log.debug("Leaving hybridCertificatesCarryTwoSignatures().");
}

// Flip one bit inside the altSignatureValue extension, leaving every other
// byte — and the conventional signature's own validity over the TBS — alone.
// The certificate is re-assembled by hand because this is the one operation no
// legitimate code path performs.
async function breakAlternativeSignature(certPem) {
  log.debug("Entering breakAlternativeSignature().");
  const der = Buffer.from(pemBytes(certPem));
  // 2.5.29.74 as DER: OID tag, length 3, then 55 1d 4a.
  const marker = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x4a]);
  const at = der.indexOf(marker);
  assert.ok(at > 0, "this certificate carries no altSignatureValue extension");
  // Somewhere well inside the extension's value; the exact offset does not
  // matter as long as it is a signature byte rather than a length.
  der[at + 40] = der[at + 40] ^ 0x01;
  const pem = "-----BEGIN CERTIFICATE-----\n" +
      (der.toString("base64").match(/.{1,64}/g) || []).join("\n") +
      "\n-----END CERTIFICATE-----\n";
  log.debug("Leaving breakAlternativeSignature().");
  return pem;
}

// ---------------------------------------------------------------------------
// 9. The preTBSCertificate rules, checked directly.
//
// Two removals, both easy to get wrong in a way that only shows up as "the
// other implementation says my signature is invalid".
// ---------------------------------------------------------------------------
async function thePreTbsIsTheTbsMinusTwoThings() {
  log.debug("Entering thePreTbsIsTheTbsMinusTwoThings().");
  const caKey = await keyFor("ec-p256");
  const altKey = await keyFor("ml-dsa-44");
  const cert = await issue("ec-p256", "CN=preTBS check", {
    signatureAlg: "sha256-ecdsa",
    subjectAltPublicKey: altKey.publicPem,
    altSignature: { signatureAlg: "ml-dsa-44",
                   privateKeyPem: altKey.privatePem }
  });
  const pkijs = require("pkijs");
  const parsed = pkijs.Certificate.fromBER(pemBytes(cert.pem));
  const tbs = new Uint8Array(parsed.tbsView);
  const preTbs = x509.preTbsFromTbs(tbs);
  assert.ok(preTbs.length < tbs.length,
    "the preTBSCertificate is the TBSCertificate with the signature field " +
    "and the altSignatureValue extension removed, so it cannot be longer");
  const asHex = Buffer.from(preTbs).toString("hex");
  assert.strictEqual(asHex.indexOf("06035" + "51d4a"), -1,
    "the altSignatureValue extension is still in the preTBSCertificate, so " +
    "the CA signed a document that includes the signature it was computing");
  // The signature FIELD is the AlgorithmIdentifier of the conventional
  // algorithm; ecdsa-with-SHA256 is 1.2.840.10045.4.3.2, whose DER is
  // 06 08 2a 86 48 ce 3d 04 03 02. It appears once in the TBSCertificate (the
  // signature field) and must appear zero times in the preTBSCertificate.
  const ecdsaOid = "06082a8648ce3d040302";
  assert.ok(Buffer.from(tbs).toString("hex").indexOf(ecdsaOid) >= 0,
    "the TBSCertificate does not carry the signature field this test " +
    "expects, so the check below would pass for the wrong reason");
  assert.strictEqual(asHex.indexOf(ecdsaOid), -1,
    "the signature field is still in the preTBSCertificate — the " +
    "alternative signature would then cover the conventional algorithm, " +
    "which is exactly what clause 9.8 removes");
  log.debug("Leaving thePreTbsIsTheTbsMinusTwoThings().");
}

// ---------------------------------------------------------------------------
// 10. Certification requests: the proof of possession, post-quantum.
// ---------------------------------------------------------------------------
async function certificationRequestsProvePossession() {
  log.debug("Entering certificationRequestsProvePossession().");
  const algs = ["ml-dsa-44", "ml-dsa-87", "slh-dsa-sha2-128f",
                "mldsa44-ecdsa-p256-sha256", "mldsa65-rsa3072-pss-sha512"];
  for (const algId of algs) {
    const key = await keyFor(algId);
    const csr = await x509.certificationRequest({
      subject: "CN=csr." + algId + ".example,O=SPIRE,C=US",
      publicKeyPem: key.publicPem,
      privateKeyPem: key.privatePem,
      signatureAlg: algId,
      subjectAltName: [{ kind: "uri", value: "spiffe://example.org/w" }]
    });
    assert.ok(/^-----BEGIN CERTIFICATE REQUEST-----/.test(csr.pem),
      algId + ": that is not a PKCS#10 PEM");
    assert.strictEqual(csr.signatureAlg, algId,
      algId + ": the request names a different signature algorithm");
    // The proof of possession has to be checkable by somebody else. For the
    // pure algorithms that is OpenSSL 3.5; for the composites it is this
    // build, since no release implements the draft.
    const der = Buffer.from(csr.der);
    const parts = requestParts(der);
    const pub = pqx.decodeSpki(pemBytes(key.publicPem)).pub;
    assert.ok(await pqx.verify(algId, parts.signature, parts.info, pub),
      algId + ": the request's own signature does not verify");
    if (oracle.available() && familyOf(algId) !== "Composite ML-DSA") {
      assert.ok(oracle.verify(parts.info, key.publicPem, parts.signature),
        algId + ": OpenSSL 3.5 refused the proof of possession");
      crossChecks += 1;
    }
  }
  log.debug("Leaving certificationRequestsProvePossession().");
}

// The CertificationRequestInfo and the signature out of a PKCS#10, the same
// DER surgery openssl35.js does for a certificate and for the same reason.
function requestParts(der) {
  log.debug("Entering requestParts().");
  const asn1js = require("asn1js");
  const input = new Uint8Array(der);
  const parsed = asn1js.fromBER(input.slice().buffer);
  const items = parsed.result.valueBlock.value;
  const out = {
    info: new Uint8Array(items[0].toBER(false)),
    signature: new Uint8Array(items[2].valueBlock.valueHexView)
  };
  log.debug("Leaving requestParts().");
  return out;
}

// ---------------------------------------------------------------------------
// 10b. EVERY PROFILE TAKES A POST-QUANTUM KEY.
//
// The page's fourteen profiles are the roles a certificate plays — three CA
// levels, a TLS server, a TLS client, both at once, digital signature, key
// encipherment, code signing, S/MIME, OCSP responder, time stamping, smartcard
// logon and a Kerberos KDC — and "post-quantum works" is only true if it is
// true for all of them. They differ in their extensions rather than in their
// cryptography, so the failure this catches is not a signature: it is a
// profile whose default `keyUsage` or `extendedKeyUsage` makes the encoder or
// the describer take a path the post-quantum keys never reach.
//
// THE KEY-ENCIPHERMENT PROFILE IS THE INTERESTING ONE, and it is the reason
// ML-KEM is in this loop as a subject key. That is the encryption certificate
// — the one a KEM key is FOR — and it cannot be self-signed at any point, so
// it is issued by an ML-DSA CA here exactly as it would be anywhere else.
// What this test does NOT assert is that the keyUsage bits are the ones RFC
// 9935 section 4 requires of an ML-KEM certificate (keyEncipherment alone):
// this is a debugger, every bit is editable on purpose, and issuing the
// certificate that is wrong in exactly one way is the point of the page.
// ---------------------------------------------------------------------------
async function everyProfileTakesAPostQuantumKey() {
  log.debug("Entering everyProfileTakesAPostQuantumKey().");
  const caKey = await keyFor("ml-dsa-65");
  const ca = await issue("ml-dsa-65", "CN=Profile CA,O=idptools");
  const profiles = x509.profileIds();
  assert.ok(profiles.length >= 14,
    "the profile list has shrunk to " + profiles.length + ", so this sweep " +
    "covers less than the page offers");
  let issued = 0;
  for (const profileId of profiles) {
    const p = x509.profile(profileId);
    // A CA profile signs with its OWN key, so it gets a signing algorithm; a
    // leaf profile may hold a KEM key, which signs nothing. Both are covered:
    // the subject key rotates through the three families.
    const subjectAlg = p.ca
      ? "ml-dsa-44"
      : (profileId === "key-encipherment" ? "ml-kem-768"
        : (issued % 2 ? "slh-dsa-sha2-128f" : "ml-dsa-87"));
    const subjectKey = await keyFor(subjectAlg);
    const cert = await issue("ml-dsa-65", "CN=" + profileId + ".example," +
        "O=idptools", {
      profile: profileId, subjectKey: subjectKey, signerKey: caKey,
      signerAlg: "ml-dsa-65", issuerCertPem: ca.pem, signatureAlg: "ml-dsa-65"
    });
    const described = await x509.describeCertificate(cert.pem);
    assert.strictEqual(described.signatureAlgorithm, "ML-DSA-65",
      profileId + ": the describer does not name the signature algorithm");
    const chain = await x509.verifyChain([cert.pem, ca.pem]);
    assert.strictEqual(chain[0].signatureValid, true,
      profileId + ": a " + subjectAlg + " certificate under this profile " +
      "does not verify");
    if (oracle.available()) {
      assert.ok(oracle.verifyCertificate(cert.der, pemOf(ca)),
        profileId + ": OpenSSL 3.5 refused the signature on a " + subjectAlg +
        " certificate issued under this profile");
      crossChecks += 1;
    }
    issued += 1;
  }
  log.info("Issued " + issued + " post-quantum certificates, one per " +
      "profile.");
  log.debug("Leaving everyProfileTakesAPostQuantumKey().");
}

// ---------------------------------------------------------------------------
// 11. The refusals, and whether they name what is actually wrong.
// ---------------------------------------------------------------------------
async function badInputIsRefusedByName() {
  log.debug("Entering badInputIsRefusedByName().");
  const kem = await keyFor("ml-kem-768");
  await refuses(function () {
    return x509.issueCertificate({
      profile: "root-ca", subject: "CN=impossible",
      subjectPublicKey: kem.publicPem, issuerPrivateKey: kem.privatePem,
      signatureAlg: "ml-kem-768",
      extensions: x509.defaultExtensions("root-ca")
    });
  }, /key-encapsulation/i, "a self-signed ML-KEM certificate");

  await refuses(function () {
    return x509.certificationRequest({
      subject: "CN=impossible", publicKeyPem: kem.publicPem,
      privateKeyPem: kem.privatePem, signatureAlg: "ml-kem-768"
    });
  }, /proof of possession/i, "a certification request for an ML-KEM key");

  const mldsa = await keyFor("ml-dsa-44");
  const other = await keyFor("ml-dsa-65");
  await refuses(function () {
    return x509.issueCertificate({
      profile: "root-ca", subject: "CN=mismatch",
      subjectPublicKey: mldsa.publicPem, issuerPrivateKey: other.privatePem,
      signatureAlg: "ml-dsa-44",
      extensions: x509.defaultExtensions("root-ca")
    });
  }, /ML-DSA-65 private key/i, "signing ML-DSA-44 with an ML-DSA-65 key");

  const seed = pqx.decodePkcs8(pemBytes(mldsa.privatePem)).priv;
  const expandedOnly = pqx.privatePem("ML-DSA-44", seed,
      { form: "expandedKey" });
  await refuses(function () {
    return x509.issueCertificate({
      profile: "root-ca", subject: "CN=expanded",
      subjectPublicKey: mldsa.publicPem, issuerPrivateKey: expandedOnly,
      signatureAlg: "ml-dsa-44",
      extensions: x509.defaultExtensions("root-ca")
    });
  }, /expandedKey arm/i, "signing from a key with no seed");

  // The composite JWK refusal, which is about two encodings of the same key
  // rather than about anything being broken.
  const composite = await keyFor("mldsa44-ecdsa-p256-sha256");
  await refuses(function () {
    return keys.pubToJwk(composite.publicPem,
        keys.keyAlg("mldsa44-ecdsa-p256-sha256"));
  }, /JOSE/i, "a composite key as a JWK");

  // An alternative signature with no alternative private key.
  const classical = await keyFor("ec-p256");
  await refuses(function () {
    return x509.issueCertificate({
      profile: "root-ca", subject: "CN=no alt key",
      subjectPublicKey: classical.publicPem,
      issuerPrivateKey: classical.privatePem, signatureAlg: "sha256-ecdsa",
      extensions: x509.defaultExtensions("root-ca"),
      altSignature: { signatureAlg: "ml-dsa-44" }
    });
  }, /alternative private key/i, "a hybrid certificate with no second key");
  log.debug("Leaving badInputIsRefusedByName().");
}

async function refuses(fn, pattern, what) {
  log.debug("Entering refuses(). what=" + what);
  let message = null;
  try {
    await fn();
  } catch (e) {
    message = e.message;
  }
  assert.ok(message, what + " was accepted, and it cannot be");
  assert.ok(pattern.test(message),
    what + " was refused with a message that does not say why: " + message);
  log.debug("Leaving refuses().");
}

// ---------------------------------------------------------------------------
// 12. The menus a page draws are the registries, filtered.
// ---------------------------------------------------------------------------
async function theMenusOfferOnlyWhatEachKeyCanDo() {
  log.debug("Entering theMenusOfferOnlyWhatEachKeyCanDo().");
  for (const algId of postQuantumAlgIds()) {
    const desc = keys.keyAlg(algId);
    const offered = x509.signatureAlgorithmsFor(desc);
    if (pqx.alg(algId).use === "kem") {
      assert.deepStrictEqual(offered, [],
        algId + ": a key-encapsulation key was offered a signature algorithm");
      continue;
    }
    assert.deepStrictEqual(offered, [algId],
      algId + ": a post-quantum key can produce exactly one signature " +
      "algorithm, and the menu offered " + offered.join(", "));
    assert.strictEqual(x509.defaultSignatureAlgorithm(desc), algId,
      algId + ": the default signature algorithm is not the key's own");
    assert.ok(x509.SIG_ALGS[algId],
      algId + ": there is no signature algorithm entry for this key");
    assert.strictEqual(x509.SIG_ALGS[algId].oid, pqx.alg(algId).oid,
      algId + ": the signature algorithm's OID and the key's disagree");
  }
  // A classical key must not be offered a post-quantum algorithm, which is the
  // same rule in the other direction and the one a generated menu can break.
  ["rsa-2048", "ec-p256", "ed25519"].forEach(function (algId) {
    x509.signatureAlgorithmsFor(keys.keyAlg(algId)).forEach(function (sig) {
      assert.strictEqual(x509.SIG_ALGS[sig].kind !== "pqc", true,
        algId + " was offered the post-quantum algorithm " + sig);
    });
  });
  log.debug("Leaving theMenusOfferOnlyWhatEachKeyCanDo().");
}

function writePem(name, pem) {
  log.debug("Entering writePem().");
  const file = path.join(tempDir(), name);
  fs.writeFileSync(file, pem);
  log.debug("Leaving writePem().");
  return file;
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Post-quantum X.509 against OpenSSL " +
      process.versions.openssl + ".");
  try {
    execFileSync("openssl", ["version"], { encoding: "utf8" });
  } catch (e) {
    throw new Error("openssl is not on the PATH. The hybrid cases assert " +
      "that a validator with no post-quantum support accepts the " +
      "certificate, and that validator is the openssl binary.");
  }
  if (!oracle.available()) {
    log.warn(oracle.unavailableReason());
  }
  theRegistryMatchesTheStandards();
  await theMenusOfferOnlyWhatEachKeyCanDo();
  await everyKeyEncodesAsTheRfcsSayAndOpensslAgrees();
  await allThreePrivateKeyArmsRoundTrip();
  await thePreTbsIsTheTbsMinusTwoThings();
  await badInputIsRefusedByName();
  await certificationRequestsProvePossession();
  await everyProfileTakesAPostQuantumKey();
  await hybridCertificatesCarryTwoSignatures();
  await theSlowParameterSetsVerifyWhatOpensslSigns();
  await compositeCertificatesNeedBothHalves();
  await mixedChainsVerifyEndToEnd();
  await pureCertificatesVerifyAgainstOpenssl();
  log.info("Cross-checked " + crossChecks + " facts against OpenSSL " +
      process.versions.openssl + ".");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("pki_pqc_x509")
  .description("Verify post-quantum certificate authoring — pure, composite " +
      "and hybrid — against OpenSSL 3.5 and against OpenSSL 3.0.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
}).catch(function (e) {
  log.error(e.stack || e.message);
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  process.exit(1);
});
