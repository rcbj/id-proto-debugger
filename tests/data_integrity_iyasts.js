// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: data_integrity_iyasts.js
//
// ---------------------------------------------------------------------------
// client/src/data_integrity.js against iya-sts's own Data Integrity module
// (oid4vc/vc_data_integrity.js, loaded in process from the image the stack
// runs, #475). iya-sts is the Verifier and the issuer the suite's ldp_vc jobs
// talk to, so the questions worth asking it are the ones those jobs depend on:
//
//   * a credential iya-sts signs in each cryptosuite it signs (ecdsa-jcs-2019
//     on P-256 and P-384, eddsa-jcs-2022, ecdsa-rdfc-2019, eddsa-rdfc-2022)
//     verifies here, and a tampered one does not;
//   * a credential signed here in each of those suites verifies there;
//   * the wallet's holder Verifiable Presentation — vp_protocols.js's
//     ldpVerifiablePresentation(), whose proof carries the @context it
//     signs, as the JCS suites require — verifies with iya-sts's verifier,
//     for a P-256 holder key (ecdsa-jcs-2019) and an Ed25519 one
//     (eddsa-jcs-2022), with the request's nonce and Client Identifier as
//     challenge and domain, and fails under another nonce.
//
// The outside implementations in data_integrity_engine.js are the
// specification's witnesses; this is the peer's. Neither shares code with
// the module under test. No browser and no services: it needs only iya-sts's
// tree (module_paths.js's mockStsModule()), and FAILS naming the image when
// that cannot be had, like every job that loads iya-sts's code.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "data_integrity_iyasts",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

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

function iyaSts() {
  log.debug("Entering iyaSts().");
  var found = paths.mockStsModule("vc_data_integrity.js", function (m) {
    log.warn(m);
  });
  if (!found) {
    log.debug("Leaving iyaSts(). Not found.");
    throw new Error("iya-sts's vc_data_integrity.js is not in its tree (" +
                    paths.iyaStsImage() + ").");
  }
  log.debug("Leaving iyaSts(). " + found);
  return require(found);
}

// What iya-sts signs with: a node KeyObject and the public JWK.
function keyPair(spec) {
  log.debug("Entering keyPair(). " + spec);
  var pair = spec === "Ed25519" ?
    nodeCrypto.generateKeyPairSync("ed25519") :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: spec });
  var pub = pair.publicKey.export({ format: "jwk" });
  var priv = pair.privateKey.export({ format: "jwk" });
  log.debug("Leaving keyPair().");
  return { keyObject: pair.privateKey, publicJwk: pub, privateJwk: priv };
}

function didJwk(jwk) {
  log.debug("Entering didJwk().");
  log.debug("Leaving didJwk().");
  return "did:jwk:" + Buffer.from(JSON.stringify(jwk)).toString("base64url");
}

function credential(issuer) {
  log.debug("Entering credential().");
  log.debug("Leaving credential().");
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 { given_name: "https://schema.org/givenName" }],
    type: ["VerifiableCredential"], issuer: issuer,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:alice", given_name: "Alice" }
  };
}

function failed(result) {
  log.debug("Entering failed().");
  log.debug("Leaving failed().");
  return (result.checks || []).filter(function (c) {
    return !c.ok;
  }).map(function (c) {
    return c.name + ": " + c.detail;
  }).join("; ");
}

const SUITES = [["ecdsa-jcs-2019", "P-256"], ["ecdsa-jcs-2019", "P-384"],
                ["eddsa-jcs-2022", "Ed25519"],
                ["ecdsa-rdfc-2019", "P-256"], ["ecdsa-rdfc-2019", "P-384"],
                ["eddsa-rdfc-2022", "Ed25519"]];

async function credentialsBothWays(sts, di) {
  log.debug("Entering credentialsBothWays().");
  var all = sts.ALL_CRYPTOSUITES || Object.keys(sts.SUITES || {});
  for (const [suite, curve] of SUITES) {
    var k = keyPair(curve);
    var did = didJwk(k.publicJwk);
    var vm = did + "#0";
    var theirs = await sts.signDocument(credential(did), {
      cryptosuite: suite, publicJwk: k.publicJwk, privateKey: k.keyObject,
      verificationMethod: vm, proofPurpose: "assertionMethod" });
    var r = await di.verifyProof(theirs);
    assert.ok(r.valid, suite + " " + curve + ": iya-sts's verifies here: " +
              r.reason);
    var bad = JSON.parse(JSON.stringify(theirs));
    bad.credentialSubject.given_name = "Mallory";
    assert.ok(!(await di.verifyProof(bad)).valid,
              suite + " " + curve + ": a tampered one does not");
    var mine = await di.createProof(credential(did), { suite: suite,
      privateJwk: k.privateJwk, verificationMethod: vm });
    var v = await sts.verifyProof(mine, { allowedCryptosuites: all,
      expectedPurpose: "assertionMethod", expectedChallenge: null,
      expectedDomain: null });
    assert.ok(v.ok, suite + " " + curve + ": ours verifies in iya-sts: " +
              failed(v));
    log.info("PASS " + suite + " " + curve + ": both directions, tamper " +
             "rejected.");
  }
  log.debug("Leaving credentialsBothWays().");
}

// The wallet's holder VP, verified as iya-sts's Verifier verifies one.
async function holderPresentations(sts, di) {
  log.debug("Entering holderPresentations().");
  var vp = load("vp_protocols.js");
  var issuer = keyPair("Ed25519");
  var issuerDid = didJwk(issuer.publicJwk);
  for (const [curve, expected] of [["P-256", "ecdsa-jcs-2019"],
                                   ["Ed25519", "eddsa-jcs-2022"]]) {
    var holder = keyPair(curve);
    var holderDid = didJwk(holder.publicJwk);
    var unsigned = credential(issuerDid);
    unsigned.credentialSubject.id = holderDid;
    var signed = await di.createProof(unsigned, { suite: "eddsa-rdfc-2022",
      privateJwk: issuer.privateJwk, verificationMethod: issuerDid + "#0" });
    var nonce = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var aud = "x509_hash:verifier-" + curve;
    var wrapped = await vp.ldpVerifiablePresentation({ credential: signed,
      holder: holderDid, privateJwk: holder.privateJwk, nonce: nonce,
      aud: aud });
    assert.strictEqual(wrapped.proof.cryptosuite, expected,
                       "a " + curve + " holder key signs " + expected);
    assert.deepStrictEqual(wrapped.proof["@context"], wrapped["@context"],
                           "the JCS holder proof carries the @context");
    var v = await sts.verifyProof(wrapped, { expectedChallenge: nonce,
      expectedDomain: aud });
    assert.ok(v.ok, curve + " holder VP verifies in iya-sts: " + failed(v));
    var replay = await sts.verifyProof(wrapped, {
      expectedChallenge: "another", expectedDomain: aud });
    assert.ok(!replay.ok, curve + " holder VP under another nonce fails");
    var mine = await di.verifyProof(wrapped);
    assert.ok(mine.valid, curve + " holder VP verifies here: " + mine.reason);
    log.info("PASS the wallet's " + expected + " holder VP (" + curve +
             ") verifies in iya-sts, and fails under another nonce.");
  }
  log.debug("Leaving holderPresentations().");
}

async function main() {
  log.debug("Entering main().");
  log.info("iya-sts image: " + paths.iyaStsImage());
  var sts = iyaSts();
  var di = load("data_integrity_rdfc.js");
  await credentialsBothWays(sts, di);
  await holderPresentations(sts, di);
  log.info("data_integrity_iyasts: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
