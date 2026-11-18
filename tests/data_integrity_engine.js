// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: data_integrity_engine.js
//
// ---------------------------------------------------------------------------
// client/src/data_integrity.js in node, held to implementations it shares no
// code with (#475). Every suite is checked in BOTH directions — their proof
// verified here, ours verified there — and a tampered credential must fail.
//
//   eddsa-rdfc-2022, eddsa-jcs-2022       Digital Bazaar's cryptosuites over
//   ecdsa-rdfc-2019, ecdsa-jcs-2019       @digitalbazaar/data-integrity and
//     (P-256 and P-384)                   jsonld-signatures
//   Ed25519Signature2020 / 2018           @digitalbazaar/ed25519-signature-*
//   JsonWebSignature2020                  assembled from mainstream parts:
//     (EdDSA, ES256, ES384, ES512,        `jose` for the RFC 7797 detached
//      PS256, RS256; ES256K)              JWS, node's crypto (OpenSSL) for
//                                         ES256K, which jose 6 lacks, and
//                                         jsonld for RDFC-1.0. No released
//                                         implementation of the whole suite
//                                         is usable (Transmute's has no
//                                         working release).
//   EcdsaSecp256k1Signature2019           @blockcerts/ecdsa-secp256k1-
//                                         signature-2019's own test vector
//
// Two of those are BYTE-FOR-BYTE checks, possible because Ed25519 and
// RFC 6979 ECDSA are deterministic: the eddsa-rdfc-2022 example in Digital
// Bazaar's README and the signature Blockcerts' own test expects. The rest
// are interoperability checks, since ECDSA with a random nonce has no single
// right answer.
//
// It also pins a reading the specifications do NOT allow, which the module
// REFUSES and diagnoses: a JCS proof whose signer hashed the document's
// @context but did not write it into the proof (this wallet's own
// ecdsa-jcs-2019 holder proof did exactly that until #475). The debugger
// implements the specification; tolerating such a signer is not its job,
// naming its defect is.
//
// Every implementation used here is a RELEASED version, pinned in
// tests/package.json. No browser and no services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "data_integrity_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

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
const di = load("data_integrity_rdfc.js");
const contexts = load("jsonld_contexts.js");
const didLib = load("did.js");

const CONTROLLER = "https://issuer.example/issuers/1";

// What the outside implementations resolve: verification method documents
// and the controller document that authorises them. Everything else is a
// context this debugger ships.
const docs = {};
async function loader(url) {
  log.debug("Entering loader(). " + url);
  if (docs[url]) {
    log.debug("Leaving loader(). Published.");
    return { contextUrl: null, documentUrl: url, document: docs[url] };
  }
  log.debug("Leaving loader(). Shipped context.");
  return contexts.documentLoader(url);
}

// A controller document needs only `assertionMethod` defined; an inline
// context does that without shipping the DID Core context to the tests.
function controllerDocument() {
  log.debug("Entering controllerDocument().");
  if (!docs[CONTROLLER]) {
    docs[CONTROLLER] = {
      "@context": [{ "@version": 1.1, id: "@id",
        assertionMethod: { "@id": "https://w3id.org/security#assertionMethod",
                           "@type": "@id", "@container": "@set" } }],
      id: CONTROLLER, assertionMethod: [] };
  }
  log.debug("Leaving controllerDocument().");
  return docs[CONTROLLER];
}

// Ours resolves keys through the caller, never by fetching.
const jwks = {};
async function resolveKey(vm) {
  log.debug("Entering resolveKey(). " + vm);
  if (!jwks[vm]) {
    log.debug("Leaving resolveKey(). Unknown.");
    throw new Error("no key published for " + vm);
  }
  log.debug("Leaving resolveKey().");
  return jwks[vm];
}

function publish(method, jwk, ctx) {
  log.debug("Entering publish(). " + method.id);
  docs[method.id] = Object.assign({ "@context": ctx }, method);
  controllerDocument().assertionMethod.push(method.id);
  jwks[method.id] = jwk;
  log.debug("Leaving publish().");
}

function credential(v2, issuer) {
  log.debug("Entering credential().");
  var base = v2 ? {
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 { given_name: "https://schema.org/givenName" }],
    type: ["VerifiableCredential"], issuer: issuer || CONTROLLER,
    validFrom: "2026-01-01T00:00:00Z"
  } : {
    "@context": ["https://www.w3.org/2018/credentials/v1",
                 { given_name: "https://schema.org/givenName" }],
    type: ["VerifiableCredential"], issuer: issuer || CONTROLLER,
    issuanceDate: "2026-01-01T00:00:00Z"
  };
  base.credentialSubject = { id: "did:example:alice", given_name: "Alice" };
  log.debug("Leaving credential().");
  return base;
}

function tampered(doc) {
  log.debug("Entering tampered().");
  var t = JSON.parse(JSON.stringify(doc));
  t.credentialSubject.given_name = "Mallory";
  log.debug("Leaving tampered().");
  return t;
}

function firstError(result) {
  log.debug("Entering firstError().");
  var e = result && result.error;
  log.debug("Leaving firstError().");
  return e ? String(((e.errors || [e])[0] || {}).message || e) : "";
}

let jsigs;
let AssertionProofPurpose;

// Theirs -> ours and ours -> theirs through jsonld-signatures.
async function both(name, makeSuite, ours, privateJwk, vm, v2) {
  log.debug("Entering both(). " + name);
  var label = name + " (" + (v2 ? "VCDM 2.0" : "VCDM 1.1") + ")";
  var signed = await jsigs.sign(credential(v2), { suite: makeSuite(false),
    purpose: new AssertionProofPurpose(), documentLoader: loader });
  var r = await di.verifyProof(signed, { resolveKey: resolveKey });
  assert.ok(r.valid, label + ": theirs must verify here: " + r.reason);
  assert.ok(!(await di.verifyProof(tampered(signed),
    { resolveKey: resolveKey })).valid, label + ": tampered theirs fails");
  var mine = await di.createProof(credential(v2), { suite: ours,
    privateJwk: privateJwk, verificationMethod: vm });
  var v = await jsigs.verify(mine, { suite: makeSuite(true),
    purpose: new AssertionProofPurpose(), documentLoader: loader });
  assert.ok(v.verified, label + ": ours must verify there: " +
            firstError(v));
  log.info("PASS " + label + ": both directions, tamper rejected.");
  log.debug("Leaving both().");
}

// Digital Bazaar's README example: a fixed key, a fixed `created`, and an
// Ed25519 signature, so there is exactly one right proofValue.
async function readmeVector(Ed25519Multikey) {
  log.debug("Entering readmeVector().");
  var kp = await Ed25519Multikey.from({
    "@context": "https://w3id.org/security/multikey/v1", type: "Multikey",
    controller: "https://example.edu/issuers/565049",
    id: "https://example.edu/issuers/565049#" +
      "z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT",
    publicKeyMultibase: "z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT",
    secretKeyMultibase: "zrv3rbPamVDGvrm7LkYPLWYJ35P9audujKKsWn3x29EUiGw" +
      "whdZQd1iHhrsmZidtVALBQmhX3j9E5Fvx6Kr29DPt6LH" });
  var priv = await Ed25519Multikey.toJwk({ keyPair: kp, secretKey: true });
  var out = await di.createProof({
    "@context": ["https://www.w3.org/2018/credentials/v1",
      { AlumniCredential: "https://schema.org#AlumniCredential",
        alumniOf: "https://schema.org#alumniOf" }],
    id: "http://example.edu/credentials/1872",
    type: ["VerifiableCredential", "AlumniCredential"],
    issuer: "https://example.edu/issuers/565049",
    issuanceDate: "2010-01-01T19:23:24Z",
    credentialSubject: { id: "https://example.edu/students/alice",
                         alumniOf: "Example University" }
  }, { suite: "eddsa-rdfc-2022", privateJwk: priv,
       verificationMethod: kp.id,
       created: Date.parse("2022-09-06T21:29:24Z") });
  assert.deepStrictEqual(out["@context"].slice(-1),
    ["https://w3id.org/security/data-integrity/v2"],
    "a VCDM 1.1 document gains data-integrity/v2");
  assert.strictEqual(out.proof.proofValue,
    "z4uwHCobmxKqQfZb7i8QRnNR9J4TR6u4Wkm4DB3ms337gfSpL4UwhTD7KKdPjyAaVJQ4y" +
    "896FEnB1Vz3uEz14jWoC", "Digital Bazaar's published proofValue");
  log.info("PASS eddsa-rdfc-2022: Digital Bazaar's README example, byte " +
           "for byte.");
  log.debug("Leaving readmeVector().");
}

async function dataIntegritySuites() {
  log.debug("Entering dataIntegritySuites().");
  const { DataIntegrityProof } = await import("@digitalbazaar/data-integrity");
  const eddsaRdfc = (await import(
    "@digitalbazaar/eddsa-rdfc-2022-cryptosuite")).cryptosuite;
  const ecdsaRdfc = (await import(
    "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite")).cryptosuite;
  const eddsaJcs = await import("@digitalbazaar/eddsa-jcs-2022-cryptosuite");
  const ecdsaJcs = await import("@digitalbazaar/ecdsa-jcs-2019-cryptosuite");
  const Ed25519Multikey = await import("@digitalbazaar/ed25519-multikey");
  const EcdsaMultikey = await import("@digitalbazaar/ecdsa-multikey");
  await readmeVector(Ed25519Multikey);

  function dip(signer, signSuite, verifySuite) {
    log.debug("Entering dip().");
    log.debug("Leaving dip().");
    return function (verifying) {
      return new DataIntegrityProof(verifying ? { cryptosuite: verifySuite } :
        { signer: signer, cryptosuite: signSuite });
    };
  }
  var ed = await Ed25519Multikey.generate({ controller: CONTROLLER });
  publish(await ed.export({ publicKey: true }),
          await Ed25519Multikey.toJwk({ keyPair: ed }),
          "https://w3id.org/security/multikey/v1");
  var edPriv = await Ed25519Multikey.toJwk({ keyPair: ed, secretKey: true });
  for (const v2 of [false, true]) {
    await both("eddsa-rdfc-2022", dip(ed.signer(), eddsaRdfc, eddsaRdfc),
               "eddsa-rdfc-2022", edPriv, ed.id, v2);
    await both("eddsa-jcs-2022", dip(ed.signer(),
      eddsaJcs.createSignCryptosuite(), eddsaJcs.createVerifyCryptosuite()),
      "eddsa-jcs-2022", edPriv, ed.id, v2);
  }
  for (const curve of ["P-256", "P-384"]) {
    var ec = await EcdsaMultikey.generate({ curve: curve,
                                            controller: CONTROLLER });
    publish(await ec.export({ publicKey: true }),
            await EcdsaMultikey.toJwk({ keyPair: ec }),
            "https://w3id.org/security/multikey/v1");
    var ecPriv = await EcdsaMultikey.toJwk({ keyPair: ec, secretKey: true });
    for (const v2 of [false, true]) {
      await both("ecdsa-rdfc-2019 " + curve, dip(ec.signer(), ecdsaRdfc,
        ecdsaRdfc), "ecdsa-rdfc-2019", ecPriv, ec.id, v2);
      await both("ecdsa-jcs-2019 " + curve, dip(ec.signer(),
        ecdsaJcs.createSignCryptosuite(), ecdsaJcs.createVerifyCryptosuite()),
        "ecdsa-jcs-2019", ecPriv, ec.id, v2);
    }
  }
  log.debug("Leaving dataIntegritySuites().");
}

async function ed25519Legacy() {
  log.debug("Entering ed25519Legacy().");
  const Ed25519Multikey = await import("@digitalbazaar/ed25519-multikey");
  const { Ed25519Signature2020 } =
    await import("@digitalbazaar/ed25519-signature-2020");
  const { Ed25519VerificationKey2020 } =
    await import("@digitalbazaar/ed25519-verification-key-2020");
  const { Ed25519Signature2018 } =
    await import("@digitalbazaar/ed25519-signature-2018");
  const { Ed25519VerificationKey2018 } =
    await import("@digitalbazaar/ed25519-verification-key-2018");
  // One seed, so the four key classes are the same key.
  var seed = nodeCrypto.randomBytes(32);
  var mk = await Ed25519Multikey.generate({ seed: seed });
  var priv = await Ed25519Multikey.toJwk({ keyPair: mk, secretKey: true });
  var pub = await Ed25519Multikey.toJwk({ keyPair: mk });
  var k20 = await Ed25519VerificationKey2020.generate({ seed: seed,
    controller: CONTROLLER });
  k20.id = CONTROLLER + "#ed25519-2020";
  publish(k20.export({ publicKey: true }), pub,
          "https://w3id.org/security/suites/ed25519-2020/v1");
  var k18 = await Ed25519VerificationKey2018.generate({ seed: seed,
    controller: CONTROLLER });
  k18.id = CONTROLLER + "#ed25519-2018";
  var m18 = k18.export({ publicKey: true });
  publish(m18, pub, "https://w3id.org/security/suites/ed25519-2018/v1");
  assert.strictEqual(di.methodToJwk(m18).x, pub.x,
    "an Ed25519VerificationKey2018's publicKeyBase58 reads as its JWK");
  await both("Ed25519Signature2020", function (verifying) {
    return new Ed25519Signature2020(verifying ? {} : { key: k20 });
  }, "Ed25519Signature2020", priv, k20.id, false);
  await both("Ed25519Signature2018", function (verifying) {
    return new Ed25519Signature2018(verifying ? {} : { key: k18 });
  }, "Ed25519Signature2018", priv, k18.id, false);
  log.debug("Leaving ed25519Legacy().");
}

// Blockcerts' own test: a fixed secp256k1 key, a fixed `created`, RFC 6979
// nonces, so one right JWS.
async function secp256k1Vector() {
  log.debug("Entering secp256k1Vector().");
  var pkg = path.dirname(require.resolve(
    "@blockcerts/ecdsa-secp256k1-signature-2019"));
  var fx = path.join(pkg, "..", "src", "__tests__", "__fixtures__");
  var fxContexts = {
    "http://schema.org": JSON.parse(fs.readFileSync(
      path.join(fx, "contexts", "schema.json"))),
    // A context whose host no longer answers (ns.did.ai); a wallet is handed
    // such a context rather than shipping it, and so is this test.
    "https://ns.did.ai/suites/secp256k1-2019/v1": JSON.parse(fs.readFileSync(
      path.join(fx, "contexts", "secp256k1-2019-v1.json")))
  };
  var fxLoader = async function (u) {
    return fxContexts[u] ? { contextUrl: null, documentUrl: u,
      document: fxContexts[u] } : contexts.documentLoader(u);
  };
  var kp = JSON.parse(fs.readFileSync(path.join(fx, "keyPair.json")))
    .private;
  var pubJwk = di.methodToJwk(kp);
  var d = Buffer.from(didLib.base58Decode(kp.privateKeyBase58))
    .toString("base64url");
  var doc = { "@context": ["http://schema.org",
    "https://ns.did.ai/suites/secp256k1-2019/v1"], "@type": "Person",
    name: "Bob Belcher" };
  var want = "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ.." +
    "g1hW0hlWm_eSlqFRDouZhpqSq7dl0TzzD2hjJDOWKlE6f8UIkFOWTMll9rBNCh-likdO" +
    "wfRiWJedB9DXUndLAA";
  var out = await di.createProof(doc, {
    suite: "EcdsaSecp256k1Signature2019",
    privateJwk: Object.assign({ d: d }, pubJwk), verificationMethod: kp.id,
    created: Date.parse("2021-04-20T00:00:00Z"), documentLoader: fxLoader,
    addContext: false, deterministic: true });
  assert.strictEqual(out.proof.jws, want, "Blockcerts' expected JWS");
  var r = await di.verifyProof(out, { resolveKey: async function () {
    return pubJwk;
  }, documentLoader: fxLoader });
  assert.ok(r.valid, "Blockcerts' vector verifies here: " + r.reason);
  log.info("PASS EcdsaSecp256k1Signature2019: Blockcerts' test vector, " +
           "byte for byte.");
  log.debug("Leaving secp256k1Vector().");
}

// JsonWebSignature2020 (W3C CCG): RDFC-1.0 of the proof options (under the
// document's @context, without `jws`) and of the document, SHA-256 of each,
// concatenated, and signed as an RFC 7797 detached JWS with "b64": false.
// The canonicalization is jsonld's, the hashes node's, and the JWS jose's —
// or node's own ECDSA for ES256K, which jose 6 (Web Crypto) does not do.
async function jws2020VerifyData(doc, proof) {
  log.debug("Entering jws2020VerifyData().");
  var jsonld = require("jsonld");
  var options = Object.assign({ "@context": doc["@context"] }, proof);
  delete options.jws;
  var unsecured = Object.assign({}, doc);
  delete unsecured.proof;
  var canon = function (d) {
    log.debug("Entering canon().");
    log.debug("Leaving canon().");
    return jsonld.canonize(d, { algorithm: "RDFC-1.0", format:
      "application/n-quads", base: null, safe: true,
      documentLoader: loader });
  };
  var texts = await Promise.all([canon(options), canon(unsecured)]);
  var sha = function (t) {
    log.debug("Entering sha().");
    log.debug("Leaving sha().");
    return nodeCrypto.createHash("sha256").update(t, "utf8").digest();
  };
  log.debug("Leaving jws2020VerifyData().");
  return new Uint8Array(Buffer.concat([sha(texts[0]), sha(texts[1])]));
}

function JWS_HEADER(alg) {
  log.debug("Entering JWS_HEADER().");
  log.debug("Leaving JWS_HEADER().");
  return { alg: alg, b64: false, crit: ["b64"] };
}

// Sign the verify data as a detached JWS: jose's FlattenedSign, or node's
// crypto for ES256K.
async function jws2020Sign(jose, alg, keys, data) {
  log.debug("Entering jws2020Sign(). " + alg);
  if (alg === "ES256K") {
    var head = Buffer.from(JSON.stringify(JWS_HEADER(alg)))
      .toString("base64url");
    var sig = nodeCrypto.sign("sha256", Buffer.concat([
      Buffer.from(head + "."), Buffer.from(data)]),
      { key: keys.privateKey, dsaEncoding: "ieee-p1363" });
    log.debug("Leaving jws2020Sign(). node.");
    return head + ".." + sig.toString("base64url");
  }
  var flat = await new jose.FlattenedSign(data)
    .setProtectedHeader(JWS_HEADER(alg)).sign(keys.privateKey);
  log.debug("Leaving jws2020Sign(). jose.");
  return flat.protected + ".." + flat.signature;
}

async function jws2020Verify(jose, alg, keys, data, jws) {
  log.debug("Entering jws2020Verify(). " + alg);
  var parts = String(jws).split(".");
  if (alg === "ES256K") {
    var ok = nodeCrypto.verify("sha256", Buffer.concat([
      Buffer.from(parts[0] + "."), Buffer.from(data)]),
      { key: keys.publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(parts[2], "base64url"));
    log.debug("Leaving jws2020Verify(). node " + ok);
    return ok;
  }
  try {
    var r = await jose.flattenedVerify({ protected: parts[0], payload: data,
      signature: parts[2] }, keys.publicKey);
    log.debug("Leaving jws2020Verify(). jose.");
    return r.protectedHeader.alg === alg && r.protectedHeader.b64 === false;
  } catch (e) {
    log.debug("Leaving jws2020Verify(). jose refused: " + e.message);
    return false;
  }
}

async function jsonWebSignature2020() {
  log.debug("Entering jsonWebSignature2020().");
  var jose = await import("jose");
  var algs = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256",
              "ES256K"];
  for (const alg of algs) {
    var keys;
    var priv;
    var pub;
    if (alg === "ES256K") {
      var pair = nodeCrypto.generateKeyPairSync("ec",
        { namedCurve: "secp256k1" });
      keys = pair;
      priv = pair.privateKey.export({ format: "jwk" });
      pub = pair.publicKey.export({ format: "jwk" });
    } else {
      keys = await jose.generateKeyPair(alg === "EdDSA" ? "Ed25519" : alg,
                                        { extractable: true });
      priv = await jose.exportJWK(keys.privateKey);
      pub = await jose.exportJWK(keys.publicKey);
    }
    var vm = CONTROLLER + "#jws-" + alg.toLowerCase();
    jwks[vm] = pub;
    var doc = credential(false);
    doc["@context"].push("https://w3id.org/security/suites/jws-2020/v1");
    var label = "JsonWebSignature2020 " + alg;

    var proof = { type: "JsonWebSignature2020",
                  created: "2026-11-17T00:00:00Z", verificationMethod: vm,
                  proofPurpose: "assertionMethod" };
    proof.jws = await jws2020Sign(jose, alg, keys,
                                  await jws2020VerifyData(doc, proof));
    var theirs = Object.assign({}, doc, { proof: proof });
    var r = await di.verifyProof(theirs, { resolveKey: resolveKey });
    assert.ok(r.valid, label + ": theirs must verify here: " + r.reason);
    assert.ok(!(await di.verifyProof(tampered(theirs),
      { resolveKey: resolveKey })).valid, label + ": tampered theirs fails");

    var mine = await di.createProof(doc, { suite: "JsonWebSignature2020",
      privateJwk: priv, verificationMethod: vm, jwsAlg: alg });
    var data = await jws2020VerifyData(mine, mine.proof);
    assert.ok(await jws2020Verify(jose, alg, keys, data, mine.proof.jws),
              label + ": ours must verify there");
    var otherData = await jws2020VerifyData(tampered(mine), mine.proof);
    assert.ok(!(await jws2020Verify(jose, alg, keys, otherData,
              mine.proof.jws)), label + ": ours over a tampered document " +
              "must fail there");
    log.info("PASS " + label + ": both directions, tamper rejected.");
  }
  log.debug("Leaving jsonWebSignature2020().");
}

// Everything this module signs, verified by itself with every key it signs
// with — the one place secp256k1 under JsonWebSignature2020 and P-521 are
// exercised — and each refusal naming its cause.
async function ownRoundTrips() {
  log.debug("Entering ownRoundTrips().");
  var provider = paths.requireCryptoModule("crypto_provider.js");
  var specs = { "Ed25519": "ed25519", "P-256": "ec-p256",
                "P-384": "ec-p384", "P-521": "ec-p521",
                "secp256k1": "ec-secp256k1", "RSA": "rsa-2048" };
  var count = 0;
  for (const id of Object.keys(di.SUITES)) {
    for (const k of di.SUITES[id].keys) {
      var kp = provider.generateKeyPair(specs[k]);
      var priv = provider.exportKey(kp, "jwk");
      var pub = provider.exportKey(kp, "jwk", { publicOnly: true });
      var vm = "did:example:own#" + id + "-" + k;
      jwks[vm] = pub;
      var signed = await di.createProof(credential(false), { suite: id,
        privateJwk: priv, verificationMethod: vm });
      var r = await di.verifyProof(signed, { resolveKey: resolveKey });
      assert.ok(r.valid, id + " " + k + ": " + r.reason);
      assert.ok(!(await di.verifyProof(tampered(signed),
        { resolveKey: resolveKey })).valid, id + " " + k + ": tamper");
      count++;
    }
  }
  log.info("PASS " + count + " suite/key combinations sign and verify, and " +
           "reject a tampered document.");

  // A did:key for secp256k1, which did.js cannot decompress on its own.
  var k1 = provider.exportKey(provider.generateKeyPair("ec-secp256k1"),
                              "jwk", { publicOnly: true });
  var k1Did = didLib.jwkToDidKey(k1);
  assert.deepStrictEqual(di.didKeyJwk(k1Did), { kty: "EC", crv: "secp256k1",
    x: k1.x, y: k1.y }, "a secp256k1 did:key decodes");

  // A key of the wrong type is named, not reported as a bad signature.
  var ed = provider.generateKeyPair("ed25519");
  await assert.rejects(di.createProof(credential(false), {
    suite: "ecdsa-rdfc-2019", privateJwk: provider.exportKey(ed, "jwk"),
    verificationMethod: "did:example:x#1" }), /P-256 or P-384/);
  log.info("PASS a secp256k1 did:key decodes; a wrong key type is named.");
  log.debug("Leaving ownRoundTrips().");
}

// The @context rules, and a forbidden reading refused with its defect named.
async function contextRules() {
  log.debug("Entering contextRules().");
  var provider = paths.requireCryptoModule("crypto_provider.js");
  var kp = provider.generateKeyPair("ec-p256");
  var priv = provider.exportKey(kp, "jwk");
  var vm = "did:example:nc#p256";
  jwks[vm] = provider.exportKey(kp, "jwk", { publicOnly: true });

  // A JCS proof must carry the @context it was hashed with.
  var jcsSigned = await di.createProof(credential(true), {
    suite: "ecdsa-jcs-2019", privateJwk: priv, verificationMethod: vm });
  assert.deepStrictEqual(jcsSigned.proof["@context"],
    jcsSigned["@context"], "an ecdsa-jcs-2019 proof carries the @context");
  var stripped = JSON.parse(JSON.stringify(jcsSigned));
  delete stripped.proof["@context"];
  var r = await di.verifyProof(stripped, { resolveKey: resolveKey });
  assert.ok(!r.valid && /WOULD verify had the document's @context/.test(
            r.proofs[0].diagnosis || ""),
            "a JCS proof that dropped its @context is refused, and the " +
            "reason names the defect: " + r.reason);

  // A JCS proof's @context must be a PREFIX of the document's.
  var other = JSON.parse(JSON.stringify(jcsSigned));
  other.proof["@context"] = ["https://www.w3.org/2018/credentials/v1"];
  r = await di.verifyProof(other, { resolveKey: resolveKey });
  assert.ok(!r.valid && /does not begin with/.test(r.reason),
            "a JCS proof under a foreign @context is refused: " + r.reason);

  // An RDFC DataIntegrityProof's own @context must EQUAL the document's.
  var rdfcSigned = await di.createProof(credential(true), {
    suite: "ecdsa-rdfc-2019", privateJwk: priv, verificationMethod: vm });
  var withCtx = JSON.parse(JSON.stringify(rdfcSigned));
  withCtx.proof["@context"] = [withCtx["@context"][0]];
  r = await di.verifyProof(withCtx, { resolveKey: resolveKey });
  assert.ok(!r.valid && /not the document's/.test(r.reason),
            "an RDFC proof under a different @context is refused");
  log.info("PASS JCS context rules: carried, prefix-checked, and a dropped " +
           "one refused with its defect named; RDFC context must be equal.");
  log.debug("Leaving contextRules().");
}

async function main() {
  log.debug("Entering main().");
  jsigs = require("jsonld-signatures");
  AssertionProofPurpose = jsigs.purposes.AssertionProofPurpose;
  await ownRoundTrips();
  await contextRules();
  await dataIntegritySuites();
  await ed25519Legacy();
  await secp256k1Vector();
  await jsonWebSignature2020();
  log.info("data_integrity_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
