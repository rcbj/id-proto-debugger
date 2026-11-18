// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ecdsa_sd_2023_engine.js
//
// ---------------------------------------------------------------------------
// The ecdsa-sd-2023 cryptosuite (client/src/ecdsa_sd_2023.js, over
// di_selective.js; #476), held to the specification's own test vectors and
// to Digital Bazaar's released implementation, which shares no code with it.
//
// The W3C vectors (tests/fixtures/vc_di_ecdsa_sd_vectors.json, with the
// commit they came from) fix the HMAC key, so everything up to the
// signatures is deterministic and is compared exactly, for both of the
// specification's examples:
//
//   * the HMAC-relabelled canonical statements of the credential, the proof
//     hash and the mandatory hash;
//   * the signed base credential verifies (the issuer key read from its
//     did:key, the one-time key from the proof);
//   * deriving from it with the example's selective pointers yields the
//     specification's reveal document AND, byte for byte, its derived
//     proofValue — nothing in a derivation is random;
//   * the specification's derived credential verifies, its relabelled
//     statements are the vectors' verifyNQuads, and a changed disclosure
//     does not verify.
//
// Signatures themselves are ECDSA with a random nonce, so the interop half
// is where they are checked: Digital Bazaar's base proof verified here, its
// derived proof verified here, ours derived from its base and from ours
// verified there, and it deriving from our base. No browser, no services.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "ecdsa_sd_2023_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
const paths = require("./module_paths.js");
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
const di = load("data_integrity_rdfc.js");
const sd = load("ecdsa_sd_2023.js");
const selective = load("di_selective.js");
const contexts = load("jsonld_contexts.js");

const FIXTURE = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures", "vc_di_ecdsa_sd_vectors.json"), "utf8"));

function hexBytes(hex) {
  log.debug("Entering hexBytes().");
  log.debug("Leaving hexBytes().");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function hex(bytes) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(bytes).toString("hex");
}

// The examples' vocabulary, handed to the wallet's loader the way a person
// adds an issuer's context; the wallet does not ship it.
function supplyContexts() {
  log.debug("Entering supplyContexts().");
  Object.keys(FIXTURE.contexts).forEach(function (url) {
    contexts.addContext(url, FIXTURE.contexts[url]);
  });
  log.debug("Leaving supplyContexts().");
}

async function specificationVectors() {
  log.debug("Entering specificationVectors().");
  var hmacKey = hexBytes(FIXTURE.keyMaterial.hmacKeyString);
  for (const name of Object.keys(FIXTURE.examples)) {
    var x = FIXTURE.examples[name];

    var grouped = await selective.canonicalizeAndGroup(x.unsigned,
      selective.hmacIdLabels(hmacKey), { mandatory: x.mandatoryPointers });
    assert.deepStrictEqual(grouped.statements, x.hmacCanon,
      name + ": the HMAC-relabelled canonical statements are the vectors'");
    var proof = Object.assign({}, x.proofConfig);
    delete proof["@context"];
    assert.strictEqual(hex(await selective.proofHash(x.unsigned, proof)),
                       x.hashData.proofHash, name + ": proofHash");
    var mandatory = Array.from(grouped.groups.mandatory.matching.values());
    assert.strictEqual(hex(selective.sha256(Buffer.from(mandatory.join(""),
      "utf8"))), x.hashData.mandatoryHash, name + ": mandatoryHash");

    var base = await di.verifyProof(x.signedBase);
    assert.ok(base.valid, name + ": the specification's base credential " +
              "verifies: " + base.reason);

    var derived = await sd.deriveProof(x.signedBase,
      { selectivePointers: x.selectivePointers });
    var reveal = Object.assign({}, derived.document);
    delete reveal.proof;
    assert.deepStrictEqual(reveal, x.unsignedReveal,
                           name + ": the reveal document is the vectors'");
    assert.strictEqual(derived.document.proof.proofValue,
                       x.derived.proof.proofValue,
                       name + ": the derived proofValue, byte for byte");

    var r = await di.verifyProof(x.derived);
    assert.ok(r.valid, name + ": the specification's derived credential " +
              "verifies: " + r.reason);
    assert.deepStrictEqual(r.proofs[0].disclosedStatements.slice().sort(),
                           x.verifyNQuads.slice().sort(),
                           name + ": the verifier's statements are the " +
                           "vectors' verifyNQuads");
    var forged = JSON.parse(JSON.stringify(x.derived));
    forged.validUntil = "2099-01-01T00:00:00Z";
    assert.ok(!(await di.verifyProof(forged)).valid,
              name + ": a changed mandatory claim does not verify");
    log.info("PASS " + name + ": canonical statements, hashes and the " +
             "derived proofValue are the specification's; its base and " +
             "derived credentials verify, a forged one does not.");
  }
  log.debug("Leaving specificationVectors().");
}

const docs = {};
async function loader(url) {
  log.debug("Entering loader(). " + url);
  var bare = url.split("#")[0];
  if (docs[url] || docs[bare]) {
    log.debug("Leaving loader(). Published.");
    return { contextUrl: null, documentUrl: url,
             document: docs[url] || docs[bare] };
  }
  log.debug("Leaving loader(). Shipped context.");
  return contexts.documentLoader(url);
}

async function digitalBazaar() {
  log.debug("Entering digitalBazaar().");
  var jsigs = require("jsonld-signatures");
  var DataIntegrityProof = (await import("@digitalbazaar/data-integrity"))
    .DataIntegrityProof;
  var dbsd = await import("@digitalbazaar/ecdsa-sd-2023-cryptosuite");
  var EcdsaMultikey = await import("@digitalbazaar/ecdsa-multikey");
  var C = "https://issuer.example/sd";
  var kp = await EcdsaMultikey.generate({ curve: "P-256", controller: C });
  var pub = await kp.export({ publicKey: true });
  docs[pub.id] = Object.assign(
    { "@context": "https://w3id.org/security/multikey/v1" }, pub);
  docs[C] = { "@context": [{ "@version": 1.1, id: "@id",
    assertionMethod: { "@id": "https://w3id.org/security#assertionMethod",
                       "@type": "@id", "@container": "@set" } }],
    id: C, assertionMethod: [pub.id] };
  var publicJwk = await EcdsaMultikey.toJwk({ keyPair: kp });
  var privateJwk = await EcdsaMultikey.toJwk({ keyPair: kp,
                                               secretKey: true });
  var resolveKey = async function () {
    return publicJwk;
  };
  var credential = { "@context": ["https://www.w3.org/ns/credentials/v2",
    { given_name: "https://schema.org/givenName",
      family_name: "https://schema.org/familyName" }],
    type: ["VerifiableCredential"], issuer: C,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:alice", given_name: "Alice",
                         family_name: "Liddell" } };
  var mandatory = ["/issuer", "/validFrom"];
  var chosen = ["/credentialSubject/given_name"];
  var purpose = new jsigs.purposes.AssertionProofPurpose();
  var verifyThere = function (doc) {
    return jsigs.verify(doc, { suite: new DataIntegrityProof({
      cryptosuite: dbsd.createVerifyCryptosuite() }), purpose: purpose,
      documentLoader: loader });
  };
  var deriveThere = function (doc) {
    return jsigs.derive(doc, { suite: new DataIntegrityProof({
      cryptosuite: dbsd.createDiscloseCryptosuite({
        selectivePointers: chosen }) }), purpose: purpose,
      documentLoader: loader });
  };
  var errorOf = function (v) {
    return v.error ? String(((v.error.errors || [v.error])[0] || {})
      .message) : "";
  };

  var theirBase = await jsigs.sign(credential, { suite:
    new DataIntegrityProof({ signer: kp.signer(), cryptosuite:
      dbsd.createSignCryptosuite({ mandatoryPointers: mandatory }) }),
    purpose: purpose, documentLoader: loader });
  var r = await di.verifyProof(theirBase, { resolveKey: resolveKey });
  assert.ok(r.valid, "their base proof verifies here: " + r.reason);
  var theirDerived = await deriveThere(theirBase);
  r = await di.verifyProof(theirDerived, { resolveKey: resolveKey });
  assert.ok(r.valid, "their derived proof verifies here: " + r.reason);
  var mine = await sd.deriveProof(theirBase,
                                  { selectivePointers: chosen });
  var v = await verifyThere(mine.document);
  assert.ok(v.verified, "ours, derived from their base, verifies there: " +
            errorOf(v));
  var myBase = await sd.createBaseProof(credential, { privateJwk: privateJwk,
    verificationMethod: pub.id, mandatoryPointers: mandatory });
  r = await di.verifyProof(myBase, { resolveKey: resolveKey });
  assert.ok(r.valid, "our base proof verifies here: " + r.reason);
  v = await verifyThere(await deriveThere(myBase));
  assert.ok(v.verified, "they derive from our base and verify it: " +
            errorOf(v));
  v = await verifyThere((await sd.deriveProof(myBase,
    { selectivePointers: chosen })).document);
  assert.ok(v.verified, "ours, derived from our base, verifies there: " +
            errorOf(v));
  assert.ok(!("family_name" in mine.document.credentialSubject),
            "the claim nobody chose is not disclosed");
  await assert.rejects(sd.createBaseProof(credential, { privateJwk:
    { kty: "EC", crv: "P-384", x: "x", y: "y", d: "d" },
    verificationMethod: pub.id }), /P-256/,
    "a P-384 issuer key is refused, naming section 3.5.8's P-256");
  log.info("PASS ecdsa-sd-2023 against Digital Bazaar: base and derived " +
           "proofs in every direction; a P-384 issuer key is refused.");
  log.debug("Leaving digitalBazaar().");
}

async function main() {
  log.debug("Entering main().");
  supplyContexts();
  await specificationVectors();
  await digitalBazaar();
  log.info("ecdsa_sd_2023_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
