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

async function main() {
  log.debug("Entering main().");
  choices();
  await everyAlgorithm();
  log.info("holder_key_algs: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
