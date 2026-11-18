// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: holder_key_algs.js
//
// ---------------------------------------------------------------------------
// The holder key is whatever kind the issuer accepts (#475), and every
// signature the wallet makes with it uses the algorithm that key signs.
//
// Until #475 the wallet made a P-256 key through Web Crypto and signed
// everything ES256, so an issuer whose proof_signing_alg_values_supported
// named only EdDSA, ES384 or ES256K could not be asked for a credential at
// all. Now vc_formats.holderKeyAlgFor() picks from the issuer's list, within
// what the credential's format can use afterwards (an mdoc's device key is
// ES256 here), and vci_wallet.generateHolderKeyPair() makes the key in pure
// JS. For each algorithm this test:
//
//   * makes the key, and signs the OpenID4VCI key proof, the SD-JWT Key
//     Binding JWT and the jwt_vc_json VP JWT with it — each verified by
//     node's own crypto (OpenSSL), with the header naming the algorithm;
//   * wraps an ldp_vc in the holder's VerifiablePresentation, in the suite
//     that key signs (vc_formats.holderSuiteFor()), and verifies it;
//
// and it pins the choices: the issuer's order is not the wallet's, an mdoc
// gets ES256 whatever else the issuer offers, and an issuer offering nothing
// the wallet can make gets no key rather than a wrong one. No browser and
// no services.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "holder_key_algs",
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
const wallet = load("vci_wallet.js");
const sdJwtVp = load("sd_jwt_vp.js");
const vpProtocols = load("vp_protocols.js");
const formats = load("vc_formats.js");
const di = load("data_integrity_rdfc.js");

// A compact JWS verified by OpenSSL against the public JWK.
function verifyJwt(jwt, publicJwk) {
  log.debug("Entering verifyJwt().");
  var parts = jwt.split(".");
  var alg = JSON.parse(Buffer.from(parts[0], "base64url")).alg;
  var key = nodeCrypto.createPublicKey({ key: publicJwk, format: "jwk" });
  var data = Buffer.from(parts[0] + "." + parts[1]);
  var sig = Buffer.from(parts[2], "base64url");
  var ok;
  if (alg === "EdDSA" || alg === "Ed25519") {
    ok = nodeCrypto.verify(null, data, key, sig);
  } else if (/^ES/.test(alg)) {
    ok = nodeCrypto.verify({ ES256: "sha256", ES384: "sha384",
      ES512: "sha512", ES256K: "sha256" }[alg], data,
      { key: key, dsaEncoding: "ieee-p1363" }, sig);
  } else if (/^PS/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data, { key: key,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: Number(alg.slice(2)) / 8 }, sig);
  } else {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data, key, sig);
  }
  log.debug("Leaving verifyJwt(). " + alg + " " + ok);
  return { alg: alg, ok: ok };
}

function didJwk(jwk) {
  log.debug("Entering didJwk().");
  log.debug("Leaving didJwk().");
  return "did:jwk:" + Buffer.from(JSON.stringify(jwk)).toString("base64url");
}

async function everyAlgorithm() {
  log.debug("Entering everyAlgorithm().");
  for (const alg of formats.HOLDER_KEY_ALGS) {
    var key = await wallet.generateHolderKeyPair(alg);
    assert.deepStrictEqual(formats.publicJwkOf(key.privateJwk),
                           key.publicJwk, alg + ": public half matches");
    var proofs = await wallet.signProofs([key], {
      credentialIssuer: "https://issuer.example", nonce: "c-nonce",
      proofAlgs: [alg] });
    var kb = await sdJwtVp.signKbJwt({ aud: "x509_hash:verifier",
      nonce: "n", sdHash: "h", holderPrivateJwk: key.privateJwk });
    var vpJwt = await sdJwtVp.signVpJwt({ aud: "verifier", nonce: "n",
      credential: "c", holderPrivateJwk: key.privateJwk });
    [["key proof", proofs[0]], ["KB-JWT", kb.jwt], ["VP JWT", vpJwt.jwt]]
      .forEach(function (pair) {
        var r = verifyJwt(pair[1], key.publicJwk);
        assert.strictEqual(r.alg, alg, alg + ": the " + pair[0] +
                           " header names " + alg);
        assert.ok(r.ok, alg + ": the " + pair[0] + " verifies in OpenSSL");
      });
    var holder = didJwk(key.publicJwk);
    var vp = await vpProtocols.ldpVerifiablePresentation({
      credential: { "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"] },
      holder: holder, privateJwk: key.privateJwk, nonce: "n", aud: "v" });
    var suite = formats.ldpSuiteOf(vp.proof);
    assert.strictEqual(suite, formats.holderSuiteFor(key.publicJwk).suite,
                       alg + ": the VP is signed in the key's suite");
    var checked = await di.verifyProof(vp);
    assert.ok(checked.valid, alg + ": the " + suite + " holder VP " +
              "verifies: " + checked.reason);
    log.info("PASS " + alg + ": key proof, KB-JWT and VP JWT verify in " +
             "OpenSSL; the ldp_vc holder VP is " + suite + ".");
  }
  log.debug("Leaving everyAlgorithm().");
}

function choices() {
  log.debug("Entering choices().");
  assert.strictEqual(formats.holderKeyAlgFor(""), "ES256",
                     "no list: ES256");
  assert.strictEqual(formats.holderKeyAlgFor("ES384, EdDSA"), "EdDSA",
                     "the wallet's preference among what the issuer takes");
  assert.strictEqual(formats.holderKeyAlgFor(["ES256K"], "ldp_vc"),
                     "ES256K", "secp256k1 when that is all there is");
  assert.strictEqual(formats.holderKeyAlgFor("EdDSA, ES256", "mso_mdoc"),
                     "ES256", "an mdoc's device key is ES256");
  assert.strictEqual(formats.holderKeyAlgFor("EdDSA", "mso_mdoc"), "",
                     "an mdoc issuer without ES256 gets no key");
  assert.strictEqual(formats.holderKeyAlgFor("Ed25519"), "Ed25519",
                     "an issuer taking only RFC 9864's Ed25519 gets one");
  assert.strictEqual(formats.jwsFor({ kty: "OKP", crv: "Ed25519", x: "x" },
                     ["Ed25519"]).headerAlg, "Ed25519",
                     "and the key signs under that name for it");
  assert.strictEqual(formats.holderKeyAlgFor("HS256"), "",
                     "a list of nothing the wallet can make gets no key");
  var p256 = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  assert.ok(formats.holderKeyFits(p256, "ES256, ES384", "dc+sd-jwt"),
            "a P-256 key fits an ES256 issuer");
  assert.ok(!formats.holderKeyFits(p256, "EdDSA", "dc+sd-jwt"),
            "a P-256 key does not fit an EdDSA-only issuer");
  log.info("PASS the holder key algorithm follows the issuer's list and the " +
           "format.");
  log.debug("Leaving choices().");
}

// transaction_data (OpenID4VP 1.0 section 8.4; Appendix B.3.3.1 for
// SD-JWT VC). The Verifier encodes each object as base64url JSON and the
// wallet hashes that exact string into the KB-JWT. node's crypto is the
// reference the wallet's pure-JS digest is held to.
async function transactionData() {
  log.debug("Entering transactionData().");
  function encode(obj) {
    return Buffer.from(JSON.stringify(obj)).toString("base64url");
  }
  function b64uHash(name, str) {
    return nodeCrypto.createHash(name).update(Buffer.from(str, "ascii"))
      .digest("base64url");
  }
  // Default algorithm: sha-256, and no alg member in the KB-JWT.
  const strDefault = encode({ type: "payment", credential_ids: ["cred1"] });
  const r1 = await sdJwtVp.transactionDataHashes(
    { transaction_data: [strDefault] }, "cred1");
  assert.deepStrictEqual(r1.hashes, [b64uHash("sha256", strDefault)],
    "the hash is sha-256 of the base64url string as received");
  assert.strictEqual(r1.alg, null,
    "no alg member when the entry lists no transaction_data_hashes_alg");
  // A choice of algorithms: the wallet prefers sha-256 and names it.
  const strChoice = encode({ type: "payment", credential_ids: ["cred1"],
    transaction_data_hashes_alg: ["sha-512", "sha-256"] });
  const r2 = await sdJwtVp.transactionDataHashes(
    { transaction_data: [strChoice] }, "cred1");
  assert.strictEqual(r2.alg, "sha-256",
    "the wallet prefers sha-256 among the offered algorithms");
  assert.deepStrictEqual(r2.hashes, [b64uHash("sha256", strChoice)]);
  // Only sha-512 offered: the wallet uses and names it.
  const str512 = encode({ type: "payment", credential_ids: ["cred1"],
    transaction_data_hashes_alg: ["sha-512"] });
  const r3 = await sdJwtVp.transactionDataHashes(
    { transaction_data: [str512] }, "cred1");
  assert.strictEqual(r3.alg, "sha-512");
  assert.deepStrictEqual(r3.hashes, [b64uHash("sha512", str512)]);
  // Only the entry naming this credential query is bound.
  const forOther = encode({ type: "x", credential_ids: ["other"] });
  const forMine = encode({ type: "y", credential_ids: ["cred1"] });
  const r4 = await sdJwtVp.transactionDataHashes(
    { transaction_data: [forOther, forMine] }, "cred1");
  assert.deepStrictEqual(r4.hashes, [b64uHash("sha256", forMine)],
    "only the entry naming this query is hashed");
  // No transaction_data: null, so the KB-JWT is left unchanged.
  assert.strictEqual(
    await sdJwtVp.transactionDataHashes({}, "cred1"), null);
  // The KB-JWT carries the members when they are passed, and neither when not.
  const key = await wallet.generateHolderKeyPair("ES256");
  const kb = await sdJwtVp.signKbJwt({ aud: "x509_hash:v", nonce: "n",
    sdHash: "h", holderPrivateJwk: key.privateJwk,
    transactionDataHashes: r2.hashes, transactionDataHashesAlg: r2.alg });
  const kbPayload = JSON.parse(
    Buffer.from(kb.jwt.split(".")[1], "base64url").toString());
  assert.deepStrictEqual(kbPayload.transaction_data_hashes, r2.hashes,
    "the KB-JWT carries transaction_data_hashes");
  assert.strictEqual(kbPayload.transaction_data_hashes_alg, "sha-256",
    "and names the algorithm when the Verifier offered a choice");
  const kb2 = await sdJwtVp.signKbJwt({ aud: "v", nonce: "n", sdHash: "h",
    holderPrivateJwk: key.privateJwk });
  const kb2Payload = JSON.parse(
    Buffer.from(kb2.jwt.split(".")[1], "base64url").toString());
  assert.ok(!("transaction_data_hashes" in kb2Payload),
    "no member in a KB-JWT without transaction_data");
  log.info("PASS transaction_data_hashes: section 8.4 / Appendix B.3.3.1.");
  log.debug("Leaving transactionData().");
}

// The key proof TYPES of a Credential Request (OpenID4VCI 1.0 section 8.2.1):
// `jwt` (the default, one proof of possession per key) and `attestation` (one
// Key Attestation JWT vouching for the holder keys). node's crypto is the
// reference the attestation signature is held to.
async function keyProofTypes() {
  log.debug("Entering keyProofTypes().");
  // buildRequestBody keys body.proofs by the proof type, defaulting to jwt.
  const jwtBody = wallet.buildRequestBody({ credentialConfigurationId: "c",
    proofs: ["a.b.c"] });
  assert.deepStrictEqual(Object.keys(jwtBody.proofs), ["jwt"],
    "the default proof type is jwt");
  assert.deepStrictEqual(jwtBody.proofs.jwt, ["a.b.c"]);
  const attBody = wallet.buildRequestBody({ credentialConfigurationId: "c",
    proofs: ["x.y.z"], proofType: "attestation" });
  assert.deepStrictEqual(Object.keys(attBody.proofs), ["attestation"],
    "proofType attestation keys body.proofs by it");
  const bogusBody = wallet.buildRequestBody({ credentialConfigurationId: "c",
    proofs: ["x"], proofType: "cwt" });
  assert.deepStrictEqual(Object.keys(bogusBody.proofs), ["jwt"],
    "an unsupported proof type falls back to jwt");

  // A Key Attestation JWT: typ keyattestation+jwt, the attester's key in the
  // header, attested_keys the holder public JWKs, and the c_nonce as nonce.
  const k1 = await wallet.generateHolderKeyPair("ES256");
  const k2 = await wallet.generateHolderKeyPair("EdDSA");
  const made = await wallet.signAttestationProof([k1, k2],
    { nonce: "c-nonce-123" });
  assert.strictEqual(made.proofs.length, 1,
    "one Key Attestation JWT covers every holder key");
  const att = made.proofs[0];
  const header = JSON.parse(Buffer.from(att.split(".")[0], "base64url"));
  const payload = JSON.parse(Buffer.from(att.split(".")[1], "base64url"));
  assert.strictEqual(header.typ, wallet.KEY_ATTESTATION_TYP,
    "typ is keyattestation+jwt");
  assert.deepStrictEqual(header.jwk, made.attesterKey.publicJwk,
    "the header carries the attester's public key");
  assert.deepStrictEqual(payload.attested_keys, [k1.publicJwk, k2.publicJwk],
    "attested_keys are the holder public JWKs");
  assert.strictEqual(payload.nonce, "c-nonce-123",
    "the c_nonce travels as the attestation's nonce");
  assert.ok(typeof payload.iat === "number", "iat is present");
  // The attestation verifies against the attester key in OpenSSL.
  const r = verifyJwt(att, made.attesterKey.publicJwk);
  assert.ok(r.ok, "the Key Attestation JWT verifies: " + r.alg);
  log.info("PASS the key proof types: jwt (default) and attestation.");
  log.debug("Leaving keyProofTypes().");
}

// The built-in credential configurations issuance step 1 offers beside the
// issuer's own: one per format an OpenID4VCI Credential Request can name, and
// each a combination that format defines. AnonCreds has none: a CL
// credential is issued against a blinded link secret, which a Credential
// Request has no member for.
function builtInConfigurations() {
  log.debug("Entering builtInConfigurations().");
  var ids = formats.builtInFormatIds();
  formats.formatIds().forEach(function (f) {
    assert.strictEqual(ids.indexOf(f) !== -1, f !== "anoncreds",
      f + (f === "anoncreds" ? " has no" : " has a") +
      " built-in configuration");
  });
  ids.forEach(function (f) {
    var row = formats.format(f);
    var cfg = formats.builtInConfiguration(f);
    assert.strictEqual(cfg.format, f);
    assert.strictEqual(formats.builtInFormatOf(cfg.id), f,
      "the id names its format: " + cfg.id);
    cfg.credential_signing_alg_values_supported.forEach(function (a) {
      assert.ok(formats.isSigningAlgFor(f, a),
        f + ": " + a + " is a signing algorithm the format defines");
    });
    assert.ok(cfg.credential_signing_alg_values_supported.length,
      f + ": at least one signing algorithm");
    cfg.cryptographic_binding_methods_supported.forEach(function (b) {
      assert.ok(row.bindingMethods.indexOf(b) !== -1,
        f + ": binding " + b + " is one the format defines");
    });
    cfg.proof_types_supported.forEach(function (t) {
      assert.ok(row.proofTypes.indexOf(t) !== -1,
        f + ": proof type " + t + " is one the format defines");
    });
  });
  // The members each OpenID4VCI 1.0 format profile REQUIRES.
  assert.ok(formats.builtInConfiguration("dc+sd-jwt").vct,
    "dc+sd-jwt carries a vct (Appendix A.3)");
  assert.ok(formats.builtInConfiguration("mso_mdoc").doctype,
    "mso_mdoc carries a doctype (Appendix A.2)");
  ["jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"].forEach(function (f) {
    var def = formats.builtInConfiguration(f).credential_definition;
    assert.ok(def && Array.isArray(def.type) &&
              def.type.indexOf("VerifiableCredential") !== -1,
      f + ": credential_definition.type (Appendix A.1)");
    assert.strictEqual(Array.isArray(def["@context"]), f !== "jwt_vc_json",
      f + ": @context " + (f === "jwt_vc_json" ? "absent (A.1.1)" :
                           "present (A.1.2, A.1.3)"));
  });
  assert.strictEqual(formats.builtInConfiguration("anoncreds"), null);
  assert.strictEqual(formats.builtInFormatOf("IdentityCredential"), "",
    "an issuer's own id is not a built-in one");
  // Proof types follow the format in the pane's defaults too.
  assert.strictEqual(formats.metadataDefaults("sd-cwt").proof_types_supported,
    "cwt");
  log.info("PASS built-in credential configurations: " + ids.length +
           " formats, each a valid combination.");
  log.debug("Leaving builtInConfigurations().");
}

async function main() {
  log.debug("Entering main().");
  choices();
  await everyAlgorithm();
  await transactionData();
  await keyProofTypes();
  builtInConfigurations();
  log.info("holder_key_algs: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
