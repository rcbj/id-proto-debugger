// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bbs2023_cryptosuite.js
//
// ---------------------------------------------------------------------------
// The bbs-2023 cryptosuite (client/src/bbs2023.js) against W3C "Data
// Integrity BBS Cryptosuites v1.0" — checked by two things that are not this
// tree's own code:
//
//   * the SPECIFICATION'S TEST VECTORS (Appendix A.1 and A.2), vendored in
//     tests/fixtures/vc_di_bbs_vectors.json with the commit they came from.
//     BBS Sign is deterministic and the vectors fix the HMAC key, so a base
//     proof made here must equal the published one BYTE FOR BYTE. A derived
//     proof draws fresh randomness, so the published one is VERIFIED, and a
//     derivation from the published base proof must reproduce the published
//     reveal document and every derived-proof component but the BBS proof;
//   * an INDEPENDENT IMPLEMENTATION, @digitalbazaar/bbs-2023-cryptosuite
//     2.0.1 (with its own BBS, canonicalizer and CBOR), in both directions:
//     its base proofs derived and verified here, and what is derived here
//     verified by it.
//
// Then what a verifier must refuse: a tampered reveal document, another
// presentation header, a base proof shown to a verifier, an unsupported
// feature option, and the pre-W3C non-standard envelope this tree used to
// send.
//
// No browser and no services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "bbs2023_cryptosuite",
    level: appconfig.logLevel || "info" });

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
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
const suite = load("bbs2023.js");
const bbs = load("bbs.js");

const FIXTURE = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures", "vc_di_bbs_vectors.json"), "utf8"));
const VECTORS = FIXTURE.vectors;

var assertions = 0;
function ok(value, message) {
  log.debug("Entering ok().");
  assertions++;
  assert.ok(value, message);
  log.debug("Leaving ok().");
}
function eq(actual, expected, message) {
  log.debug("Entering eq().");
  assertions++;
  assert.deepStrictEqual(actual, expected, message);
  log.debug("Leaving eq().");
}

function hex(text) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Uint8Array.from(Buffer.from(text, "hex"));
}
function toHex(data) {
  log.debug("Entering toHex().");
  log.debug("Leaving toHex().");
  return Buffer.from(data).toString("hex");
}
function copy(value) {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(value));
}
function withoutProof(doc) {
  log.debug("Entering withoutProof().");
  var out = copy(doc);
  delete out.proof;
  log.debug("Leaving withoutProof().");
  return out;
}

const KEYS = VECTORS["BBSKeyMaterial.json"];
const SECRET_KEY = BigInt("0x" + KEYS.privateKeyHex);
const PUBLIC_KEY = hex(KEYS.publicKeyHex);
const HMAC_KEY = hex(KEYS.hmacKeyString);
const PRESENTATION_HEADER =
    hex(VECTORS["BBSDeriveMaterial.json"].presentationHeaderHex);

// The derived-proof components that do not depend on ProofGen's randomness.
function deterministicPart(proofValue) {
  log.debug("Entering deterministicPart().");
  var p = suite.parseDerivedProofValue(proofValue);
  log.debug("Leaving deterministicPart().");
  return { labelMap: Array.from(p.labelMap.entries()),
           mandatoryIndexes: p.mandatoryIndexes,
           selectiveIndexes: p.selectiveIndexes,
           presentationHeader: toHex(p.presentationHeader) };
}

// One Appendix example: the base proof reproduced exactly, the published
// derived proof verified, a derivation from the published base proof
// matching it in everything but the BBS proof, and both proof values
// re-serializing to the published bytes.
async function appendixExample(name, files) {
  log.debug("Entering appendixExample(). " + name);
  const signed = VECTORS[files.signed];
  const hashes = VECTORS[files.hashData];
  const made = await suite.createBaseProof(withoutProof(signed),
    VECTORS[files.proofConfig], { secretKey: SECRET_KEY,
      publicKey: PUBLIC_KEY, hmacKey: HMAC_KEY,
      mandatoryPointers: VECTORS[files.mandatory] });
  eq(toHex(made.proofHash), hashes.proofHash, name + ": proofHash");
  eq(toHex(made.mandatoryHash), hashes.mandatoryHash,
     name + ": mandatoryHash");
  eq(made.credential.proof.proofValue, signed.proof.proofValue,
     name + ": the base proof must equal the published one byte for byte " +
     "(BBS Sign is deterministic and the HMAC key is fixed)");
  eq(suite.serializeBaseProofValue(suite.parseBaseProofValue(
     signed.proof.proofValue)), signed.proof.proofValue,
     name + ": the published base proofValue re-serializes to itself");
  ok(!("created" in made.credential.proof) ||
     "created" in VECTORS[files.proofConfig],
     name + ": nothing is added to the proof options");

  const published = VECTORS[files.revealed];
  const verified = await suite.verifyDerivedProof(published, PUBLIC_KEY);
  eq(verified.verified, true, name + ": the published derived proof " +
     "verifies: " + verified.reason);
  eq(toHex(verified.presentationHeader), toHex(PRESENTATION_HEADER),
     name + ": its presentation header is the published one");
  eq(suite.serializeDerivedProofValue(suite.parseDerivedProofValue(
     published.proof.proofValue)), published.proof.proofValue,
     name + ": the published derived proofValue re-serializes to itself " +
     "(compressed label map and index lists included)");

  const derived = await suite.deriveProof(signed, {
    selectivePointers: VECTORS[files.selective],
    presentationHeader: PRESENTATION_HEADER });
  eq(withoutProof(derived.document), withoutProof(published),
     name + ": the reveal document is the published one");
  eq(deterministicPart(derived.document.proof.proofValue),
     deterministicPart(published.proof.proofValue),
     name + ": label map, mandatory and selective indexes and " +
     "presentation header are the published ones");
  const ours = await suite.verifyDerivedProof(derived.document, PUBLIC_KEY);
  eq(ours.verified, true, name + ": the derivation made here verifies");
  ok(derived.document.proof.proofValue !== published.proof.proofValue,
     name + ": and its BBS proof is fresh, not the published bytes");
  log.info("[spec " + name + "] base proof byte-exact, published derived " +
           "proof verified, derivation matches it.");
  log.debug("Leaving appendixExample().");
}

async function specVectors() {
  log.debug("Entering specVectors().");
  const vm = VECTORS["addProofConfig.json"].verificationMethod;
  eq(vm.split("#")[1], suite.publicKeyToMultikey(PUBLIC_KEY),
     "the key material's Multikey is the one the vectors' did:key names");
  eq(toHex(suite.multikeyToPublicKey(vm.split("#")[1])), KEYS.publicKeyHex,
     "and decodes back to the key");
  await appendixExample("A.2 (windsurf)", {
    signed: "addSignedSDBase.json", hashData: "addHashData.json",
    proofConfig: "addProofConfig.json", mandatory: "windMandatory.json",
    selective: "windSelective.json",
    revealed: "derivedRevealDocument.json" });
  Object.keys(FIXTURE.contexts).forEach(function (url) {
    suite.addContext(url, FIXTURE.contexts[url]);
  });
  await appendixExample("A.1 (permanent resident card)", {
    signed: "prc/addSignedSDBase.json", hashData: "prc/addHashData.json",
    proofConfig: "prc/addProofConfig.json",
    mandatory: "prCredMandatory.json", selective: "prCredSelective.json",
    revealed: "prc/derivedRevealDocument.json" });
  log.debug("Leaving specVectors().");
}

// ---------------------------------------------------------------------------
// Digital Bazaar's implementation (ESM, so imported dynamically).
// ---------------------------------------------------------------------------
async function digitalBazaar() {
  log.debug("Entering digitalBazaar().");
  const cryptosuite = await import("@digitalbazaar/bbs-2023-cryptosuite");
  const multikeyPath = require.resolve("@digitalbazaar/bls12-381-multikey",
    { paths: [path.dirname(require.resolve(
      "@digitalbazaar/bbs-2023-cryptosuite"))] });
  const multikey = await import(multikeyPath);
  log.debug("Leaving digitalBazaar().");
  return { suite: cryptosuite, multikey: multikey };
}

async function dbVerify(db, revealed, publicKey) {
  log.debug("Entering dbVerify().");
  const verify = db.suite.createVerifyCryptosuite();
  const data = await verify.createVerifyData({ cryptosuite: verify,
    document: withoutProof(revealed), proof: copy(revealed.proof),
    documentLoader: suite.documentLoader });
  if (data === false) {
    log.debug("Leaving dbVerify(). Refused before verifying.");
    return false;
  }
  const verifier = await verify.createVerifier({ verificationMethod: {
    type: "Multikey", id: revealed.proof.verificationMethod,
    controller: revealed.proof.verificationMethod.split("#")[0],
    publicKeyMultibase: suite.publicKeyToMultikey(publicKey) } });
  const result = await verifier.verify({ data: data });
  log.debug("Leaving dbVerify(). " + result);
  return result;
}

async function independentImplementation() {
  log.debug("Entering independentImplementation().");
  const db = await digitalBazaar();
  const doc = withoutProof(VECTORS["windDoc.json"]);
  const multibase = suite.publicKeyToMultikey(PUBLIC_KEY);
  const options = { type: "DataIntegrityProof", cryptosuite: "bbs-2023",
    verificationMethod: "did:key:" + multibase + "#" + multibase,
    proofPurpose: "assertionMethod" };

  // Theirs signs; this derives; both verify.
  const keyPair = await db.multikey.fromRaw({
    algorithm: db.multikey.ALGORITHMS.BBS_BLS12381_SHA256,
    secretKey: hex(KEYS.privateKeyHex), publicKey: PUBLIC_KEY });
  const signing = db.suite.createSignCryptosuite({
    mandatoryPointers: ["/issuer", "/credentialSubject/sailNumber",
                        "/credentialSubject/sails/1"] });
  const verifyData = await signing.createVerifyData({ cryptosuite: signing,
    document: copy(doc), proof: copy(options),
    documentLoader: suite.documentLoader });
  const theirBase = Object.assign(copy(doc), { proof: Object.assign(
    copy(options), { proofValue: await signing.createProofValue({
      verifyData: verifyData,
      dataIntegrityProof: { signer: keyPair.signer() } }) }) });
  const fromTheirs = await suite.deriveProof(theirBase, {
    selectivePointers: ["/credentialSubject/boards/1",
                        "/credentialSubject/sails/3/size"],
    presentationHeader: "nonce-from-a-verifier" });
  const here = await suite.verifyDerivedProof(fromTheirs.document,
                                              PUBLIC_KEY);
  eq(here.verified, true, "a proof derived here from Digital Bazaar's base " +
     "proof verifies here: " + here.reason);
  eq(await dbVerify(db, fromTheirs.document, PUBLIC_KEY), true,
     "and Digital Bazaar verifies it");
  ok(!("boards" in fromTheirs.document.credentialSubject) ||
     fromTheirs.document.credentialSubject.boards.length === 1,
     "only the chosen board is revealed");

  // This signs; theirs derives; both verify.
  const ours = await suite.createBaseProof(doc, options, {
    secretKey: SECRET_KEY, publicKey: PUBLIC_KEY,
    mandatoryPointers: ["/issuer", "/credentialSubject/sails/0"] });
  const disclose = db.suite.createDiscloseCryptosuite({
    selectivePointers: ["/credentialSubject/boards/0/brand"],
    presentationHeader: new TextEncoder().encode("abc") });
  const theirRevealed = await disclose.derive({ cryptosuite: disclose,
    document: withoutProof(ours.credential),
    purpose: { term: "assertionMethod" }, proofSet: [ours.credential.proof],
    documentLoader: suite.documentLoader,
    dataIntegrityProof: { matchProof: async function matchProof() {
      log.debug("Entering matchProof().");
      log.debug("Leaving matchProof().");
      return true;
    } } });
  const theirs = await suite.verifyDerivedProof(theirRevealed, PUBLIC_KEY);
  eq(theirs.verified, true, "Digital Bazaar's proof derived from a base " +
     "proof made here verifies here: " + theirs.reason);
  eq(await dbVerify(db, theirRevealed, PUBLIC_KEY), true,
     "and verifies there");
  const sameChoice = await suite.deriveProof(ours.credential, {
    selectivePointers: ["/credentialSubject/boards/0/brand"],
    presentationHeader: "abc" });
  eq(withoutProof(sameChoice.document), withoutProof(theirRevealed),
     "the same pointers give both implementations the same reveal document");
  eq(deterministicPart(sameChoice.document.proof.proofValue),
     deterministicPart(theirRevealed.proof.proofValue),
     "and the same label map and indexes");

  // The published vectors, to the other implementation.
  eq(await dbVerify(db, VECTORS["derivedRevealDocument.json"], PUBLIC_KEY),
     true, "Digital Bazaar verifies the specification's A.2 derived proof");
  // And a derivation of the published base proof made here.
  const fromVector = await suite.deriveProof(VECTORS["addSignedSDBase.json"],
    { selectivePointers: VECTORS["windSelective.json"],
      presentationHeader: PRESENTATION_HEADER });
  eq(await dbVerify(db, fromVector.document, PUBLIC_KEY), true,
     "Digital Bazaar verifies a derivation of the published base proof " +
     "made here");
  const tampered = copy(fromTheirs.document);
  tampered.credentialSubject.sailNumber = "Mars101";
  eq(await dbVerify(db, tampered, PUBLIC_KEY), false,
     "the control: Digital Bazaar refuses a tampered reveal document, so " +
     "its acceptances above mean something");
  log.info("[independent] Digital Bazaar's base proofs derive and verify " +
           "here; what is derived here verifies there.");
  log.debug("Leaving independentImplementation().");
}

// ---------------------------------------------------------------------------
// What a verifier must refuse.
// ---------------------------------------------------------------------------
async function refusals() {
  log.debug("Entering refusals().");
  const signed = VECTORS["addSignedSDBase.json"];
  const derived = await suite.deriveProof(signed, {
    selectivePointers: VECTORS["windSelective.json"],
    presentationHeader: "the-request-nonce" });
  const control = await suite.verifyDerivedProof(derived.document,
                                                 PUBLIC_KEY);
  eq(control.verified, true, "the control verifies");
  eq(Buffer.from(control.presentationHeader).toString(),
     "the-request-nonce", "and reports its presentation header, for the " +
     "caller to compare with its nonce");

  const again = await suite.deriveProof(signed, {
    selectivePointers: VECTORS["windSelective.json"],
    presentationHeader: "the-request-nonce" });
  ok(again.document.proof.proofValue !== derived.document.proof.proofValue,
     "two derivations of one credential differ (unlinkability)");
  eq((await suite.verifyDerivedProof(again.document, PUBLIC_KEY)).verified,
     true, "and both verify");

  const tampered = copy(derived.document);
  tampered.credentialSubject.sails[0].year = 1999;
  eq((await suite.verifyDerivedProof(tampered, PUBLIC_KEY)).verified, false,
     "an altered selectively disclosed value is refused");
  const tamperedMandatory = copy(derived.document);
  tamperedMandatory.issuer = "https://vc.example/somebody-else";
  eq((await suite.verifyDerivedProof(tamperedMandatory, PUBLIC_KEY))
     .verified, false, "an altered mandatory value is refused");
  const added = copy(derived.document);
  added.credentialSubject.sails.push({ size: 9, sailName: "X", year: 2024 });
  eq((await suite.verifyDerivedProof(added, PUBLIC_KEY)).verified, false,
     "a statement added to the reveal document is refused");

  const parts = suite.parseDerivedProofValue(
    derived.document.proof.proofValue);
  parts.presentationHeader = new TextEncoder().encode("another-nonce");
  const replayed = copy(derived.document);
  replayed.proof.proofValue = suite.serializeDerivedProofValue(parts);
  eq((await suite.verifyDerivedProof(replayed, PUBLIC_KEY)).verified, false,
     "a derived proof with its presentation header changed is refused");

  const otherKey = bbs.secretKeyToPublicKey(SECRET_KEY + BigInt(1));
  eq((await suite.verifyDerivedProof(derived.document, otherKey)).verified,
     false, "another issuer key does not verify it");

  const envelope = { cryptosuite: "bbs-2023", proof: "AAAA",
    disclosedIndexes: [0], disclosedStatements: ["_:b0 <x:y> \"z\" .\n"],
    proofOptions: { verificationMethod: "https://issuer.example/k" } };
  ok(suite.isPreW3cEnvelope(envelope), "the old envelope is recognised");
  const old = await suite.verifyDerivedProof(envelope, PUBLIC_KEY);
  eq(old.verified, false, "and refused");
  ok(/pre-W3C non-standard bbs-2023 envelope/.test(old.reason), old.reason);
  ok(!suite.isPreW3cEnvelope(derived.document),
     "a W3C reveal document is not mistaken for one");

  const base = await suite.verifyDerivedProof(signed, PUBLIC_KEY);
  eq(base.verified, false, "a base proof shown to a verifier is refused");
  ok(/BASE proof/.test(base.reason), base.reason);

  const feature = copy(derived.document);
  const raw = Buffer.from(feature.proof.proofValue.slice(1), "base64url");
  raw[2] = 0x07;
  feature.proof.proofValue = "u" + raw.toString("base64url");
  const pseudonym = await suite.verifyDerivedProof(feature, PUBLIC_KEY);
  eq(pseudonym.verified, false, "a feature option is refused");
  ok(/pseudonym/.test(pseudonym.reason), pseudonym.reason);

  const oldBase = copy(signed);
  oldBase.proof.proofValue = "u" + Buffer.from(
    suite.parseBaseProofValue(signed.proof.proofValue).bbsSignature)
    .toString("base64url");
  await assert.rejects(suite.deriveProof(oldBase,
    { selectivePointers: [] }), /pre-W3C non-standard base proof/,
    "a bare BBS signature as the base proof (the pre-W3C issuer shape) " +
    "is refused by the holder, by name");
  assertions++;
  assert.throws(function () {
    suite.multikeyToPublicKey("u" + Buffer.from(PUBLIC_KEY)
      .toString("base64url"));
  }, /pre-W3C/, "a raw base64url BBS key is not a Multikey");
  assertions++;

  const altered = copy(signed);
  altered.credentialSubject.sailNumber = "Mars101";
  await assert.rejects(suite.deriveProof(altered,
    { selectivePointers: [] }), /base proof does not verify/,
    "the holder refuses to derive from a base proof whose MANDATORY " +
    "statements were altered (the header no longer matches)");
  assertions++;
  const alteredSelective = copy(signed);
  alteredSelective.credentialSubject.boards[1].brand = "Naish";
  await assert.rejects(suite.deriveProof(alteredSelective,
    { selectivePointers: [] }), /base proof does not verify/,
    "and one whose selectively disclosable statements were (the signature " +
    "no longer verifies)");
  assertions++;
  log.info("[refusals] tampering, replay, another key, a base proof, a " +
           "feature option and the pre-W3C envelope are all refused.");
  log.debug("Leaving refusals().");
}

// The wallet's pointer helpers: what a DCQL claims path selects.
function pointerHelpers() {
  log.debug("Entering pointerHelpers().");
  const doc = VECTORS["windDoc.json"];
  eq(suite.claimPointers(doc, ["credentialSubject", "sailNumber"]),
     ["/credentialSubject/sailNumber"], "a member path");
  eq(suite.claimPointers(doc, ["credentialSubject", "boards", null,
                               "year"]),
     ["/credentialSubject/boards/0/year", "/credentialSubject/boards/1/year"],
     "null selects every array element");
  eq(suite.claimPointers(doc, ["credentialSubject", "nothing"]), [],
     "a path that leads nowhere selects nothing");
  ok(suite.leafPointers(doc).some(function (leaf) {
    return leaf.pointer === "/credentialSubject/sails/3/size" &&
      leaf.value === 7.8;
  }), "every leaf is offered with its value");
  ok(suite.pointerWithin("/credentialSubject/sails/1/size",
                         "/credentialSubject/sails/1") &&
     !suite.pointerWithin("/credentialSubject/sails/10",
                          "/credentialSubject/sails/1"),
     "pointerWithin compares path segments, not prefixes");
  log.debug("Leaving pointerHelpers().");
}

async function test() {
  log.debug("Entering test().");
  await specVectors();
  await independentImplementation();
  await refusals();
  pointerHelpers();
  log.info("Test completed successfully. " + assertions + " assertions.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
