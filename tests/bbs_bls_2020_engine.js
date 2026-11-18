// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bbs_bls_2020_engine.js
//
// ---------------------------------------------------------------------------
// BbsBlsSignature2020 and BbsBlsSignatureProof2020 (#475), held to MATTR's
// released implementation, which defines the suite in practice:
// @mattrglobal/bbs-signatures 1.2.0 (the Rust `bbs` crate 0.4.1 compiled to
// WASM) and @mattrglobal/jsonld-signatures-bbs 1.2.0. Neither shares a line
// with client/src/bbs_plus_2020.js or bbs_bls_2020.js.
//
// The signature scheme alone (bbs_plus_2020.js), for 1, 3, 9 and 17
// messages: their signature verifies here and a changed message does not;
// their proof verifies here and not under another nonce; our proof verifies
// in their library and not under another nonce. That covers the generator
// derivation — an older hash-to-curve draft whose sgn0 is not RFC 9380's,
// which a straight RFC 9380 map gets wrong about half the time — the
// message hash, the proof's Fiat-Shamir transcript and its wire format.
//
// The suite (bbs_bls_2020.js, through data_integrity.js's verifyProof()):
// a credential MATTR signs verifies here and a tampered one does not; a
// presentation MATTR derives verifies here; and presentations derived here,
// for two different reveal frames, verify in MATTR's verifier.
//
// Released versions only, pinned in tests/package.json. No browser and no
// services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bbs_bls_2020_engine",
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
const bbsPlus = load("bbs_plus_2020.js");
const bbsLd = load("bbs_bls_2020.js");
const contexts = load("jsonld_contexts.js");
const didLib = load("did.js");

const mattrBbs = require("@mattrglobal/bbs-signatures");
const mattrLd = require("@mattrglobal/jsonld-signatures-bbs");
// The jsonld-signatures release MATTR's suite is written against (7.0.0),
// which it carries nested; the top-level one is a later major.
const jsigs = require(require.resolve("jsonld-signatures", { paths:
  [path.dirname(require.resolve("@mattrglobal/jsonld-signatures-bbs"))] }));

function enc(s) {
  log.debug("Entering enc().");
  log.debug("Leaving enc().");
  return Uint8Array.from(Buffer.from(s));
}

async function signatureScheme() {
  log.debug("Entering signatureScheme().");
  for (const n of [1, 3, 9, 17]) {
    var kp = await mattrBbs.generateBls12381G2KeyPair();
    var msgs = [];
    for (var i = 0; i < n; i++) {
      msgs.push(enc("message " + i + " of " + n));
    }
    var sig = await mattrBbs.blsSign({ keyPair: kp, messages: msgs });
    assert.ok(bbsPlus.verifySignature(kp.publicKey, sig, msgs),
              n + ": their signature verifies here");
    var changed = msgs.slice();
    changed[n - 1] = enc("changed");
    assert.ok(!bbsPlus.verifySignature(kp.publicKey, sig, changed),
              n + ": a changed message does not");
    var revealed = msgs.map(function (m, k) {
      return k;
    }).filter(function (k) {
      return k % 2 === 0;
    });
    var shown = revealed.map(function (k) {
      return msgs[k];
    });
    var nonce = enc("nonce-" + n);
    var theirs = await mattrBbs.blsCreateProof({ signature: sig,
      publicKey: kp.publicKey, messages: msgs, nonce: nonce,
      revealed: revealed });
    assert.ok(bbsPlus.verifyProof(kp.publicKey, theirs, shown, nonce),
              n + ": their proof verifies here");
    assert.ok(!bbsPlus.verifyProof(kp.publicKey, theirs, shown,
              enc("other")), n + ": their proof under another nonce fails");
    var mine = bbsPlus.createProof(kp.publicKey, sig, msgs, revealed, nonce);
    assert.ok((await mattrBbs.blsVerifyProof({ proof: mine,
      publicKey: kp.publicKey, messages: shown, nonce: nonce })).verified,
      n + ": our proof verifies in MATTR's library");
    assert.ok(!(await mattrBbs.blsVerifyProof({ proof: mine,
      publicKey: kp.publicKey, messages: shown, nonce: enc("other") }))
      .verified, n + ": our proof under another nonce fails there");
    log.info("PASS BBS+ 2020, " + n + " message(s): signatures and proofs " +
             "in both directions, nonce bound.");
  }
  log.debug("Leaving signatureScheme().");
}

// The controller document and contexts MATTR's suite resolves; the DID
// context is inline so the tests ship no copy of DID Core's.
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

async function suite() {
  log.debug("Entering suite().");
  var C = "did:example:bbs-issuer";
  var kp = await mattrLd.Bls12381G2KeyPair.generate({ id: C + "#key-1",
                                                      controller: C });
  docs[C] = {
    "@context": [{ "@version": 1.1, id: "@id", assertionMethod: {
      "@id": "https://w3id.org/security#assertionMethod", "@type": "@id",
      "@container": "@set" } }, "https://w3id.org/security/bbs/v1"],
    id: C,
    assertionMethod: [{ id: C + "#key-1", type: "Bls12381G2Key2020",
                        controller: C, publicKeyBase58: kp.publicKey }]
  };
  var key = didLib.base58Decode(kp.publicKey);
  var opts = { resolveBbsKey: async function () {
    return key;
  } };
  var ctx = ["https://www.w3.org/2018/credentials/v1", bbsLd.BBS_CONTEXT,
    { given_name: "https://schema.org/givenName",
      family_name: "https://schema.org/familyName",
      address: "https://schema.org/address",
      locality: "https://schema.org/addressLocality" }];
  var signed = await jsigs.sign({ "@context": ctx,
    type: ["VerifiableCredential"], issuer: C,
    issuanceDate: "2026-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:alice", given_name: "Alice",
      family_name: "Liddell", address: { locality: "Oxford" } } }, {
    suite: new mattrLd.BbsBlsSignature2020({ key: kp }),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: loader });
  var r = await di.verifyProof(signed, opts);
  assert.ok(r.valid, "MATTR's BbsBlsSignature2020 verifies here: " +
            r.reason);
  var tampered = JSON.parse(JSON.stringify(signed));
  tampered.credentialSubject.given_name = "Mallory";
  assert.ok(!(await di.verifyProof(tampered, opts)).valid,
            "a tampered BbsBlsSignature2020 credential does not");
  log.info("PASS BbsBlsSignature2020: MATTR's credential verifies here (" +
           r.proofs[0].statementCount + " statements), tamper rejected.");

  var frames = [
    { "@context": ctx, type: ["VerifiableCredential"],
      credentialSubject: { "@explicit": true, given_name: {} } },
    { "@context": ctx, type: ["VerifiableCredential"],
      credentialSubject: { "@explicit": true, family_name: {},
                           address: { "@explicit": true, locality: {} } } }
  ];
  var theirs = await mattrLd.deriveProof(signed, frames[0], {
    suite: new mattrLd.BbsBlsSignatureProof2020(), documentLoader: loader });
  r = await di.verifyProof(theirs, opts);
  assert.ok(r.valid, "MATTR's derived proof verifies here: " + r.reason);
  var forged = JSON.parse(JSON.stringify(theirs));
  forged.credentialSubject.given_name = "Mallory";
  assert.ok(!(await di.verifyProof(forged, opts)).valid,
            "a changed disclosure in MATTR's derived proof does not");
  for (const frame of frames) {
    var mine = await bbsLd.deriveProof(signed, frame,
      Object.assign({ documentLoader: loader }, opts));
    var v = await jsigs.verify(mine.document, {
      suite: new mattrLd.BbsBlsSignatureProof2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: loader });
    assert.ok(v.verified, "our derived proof verifies in MATTR's " +
      "verifier: " + (v.error ? String(v.error.errors || v.error) : ""));
    r = await di.verifyProof(mine.document, opts);
    assert.ok(r.valid, "our derived proof verifies here: " + r.reason);
    log.info("PASS BbsBlsSignatureProof2020: ours, disclosing " +
             mine.disclosedStatements.length + " of " + mine.statementCount +
             " statements, verifies in MATTR's verifier and here.");
  }
  log.info("PASS BbsBlsSignatureProof2020: MATTR's derived proof " +
           "verifies here, and a changed disclosure does not.");
  log.debug("Leaving suite().");
}

async function main() {
  log.debug("Entering main().");
  await signatureScheme();
  await suite();
  log.info("bbs_bls_2020_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
