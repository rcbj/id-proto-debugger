// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jwp_engine.js
//
// ---------------------------------------------------------------------------
// JSON Web Proofs (client/src/jwp.js; #478), held to the drafts' own bytes
// and to implementations that share no code with it. No browser, no
// services.
//
// tests/fixtures/jwp_jpa15_vectors.json is Appendix A of
// draft-ietf-jose-json-proof-algorithms-15 as the working group's CI
// rendered it (the IETF archive's text omits the figures; the file names
// the commit). Its keys are given, so:
//
//   * the SU-ES256 JPT, the SU-ES256 CPT, the BBS JPT and the MAC-H256 JPT
//     each confirm as issued and verify as presented, under the request's
//     nonce and aud, with the claims the claims array names;
//   * the MAC example's derived payload keys and MAC values are reproduced
//     byte for byte from its shared secret;
//   * presenting the issued SU and MAC examples with the example's own
//     Presentation Header reproduces every proof component but the
//     holder's (ECDSA is randomized), and the result verifies.
//
// Then round trips for every offered algorithm (SU-ES256/384/512,
// MAC-H256/384/512, MAC-H256K, BBS), each checked by an implementation
// written apart from the engine: node's own crypto over the internal
// representations rebuilt below from JPA's text, and Digital Bazaar's
// released @digitalbazaar/bbs-signatures for BBS (its verifyProof on our
// presentation, our verify on its deriveProof). And what must fail: a
// changed disclosed payload, a substituted withheld MAC, a dropped proof
// component, another nonce or audience, an issued JWP handed to verify,
// a presented one to confirm, and the two KMAC algorithms the draft leaves
// unspecified.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "jwp_engine",
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
const cborLib = paths.requireSharedModule([path.join(SRC, "cbor.js")],
                                          "client/src/cbor.js");
const jwp = paths.requireSharedModule([path.join(SRC, "jwp.js")],
                                      "client/src/jwp.js");
const FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures",
  "jwp_jpa15_vectors.json"), "utf8"));

function b(s) {
  log.debug("Entering b().");
  log.debug("Leaving b().");
  return s === "_" ? Buffer.alloc(0) : Buffer.from(s, "base64url");
}

function pubOf(jwk) {
  log.debug("Entering pubOf().");
  var j = Object.assign({}, jwk);
  delete j.d;
  delete j.use;
  log.debug("Leaving pubOf().");
  return j;
}

// --- the witness: JPA's binary forms rebuilt here, node's crypto --------
function u64(n) {
  log.debug("Entering u64().");
  var x = Buffer.alloc(8);
  x.writeBigUInt64BE(BigInt(n));
  log.debug("Leaving u64().");
  return x;
}

function internalRep(ph, ih, slots, proofs) {
  log.debug("Entering internalRep().");
  var p = [Buffer.from([0x84, 0x5b]), u64(ph.length), ph,
           Buffer.from([0x5b]), u64(ih.length), ih,
           Buffer.from([0x9b]), u64(slots.length)];
  slots.forEach(function (s) {
    if (s === null) {
      p.push(Buffer.from([0xf6]));
    } else {
      p.push(Buffer.from([0x5b]), u64(s.length), s);
    }
  });
  p.push(Buffer.from([0x9b]), u64(proofs.length));
  proofs.forEach(function (q) {
    p.push(Buffer.from([0x5b]), u64(q.length), q);
  });
  log.debug("Leaving internalRep().");
  return Buffer.concat(p);
}

const NODE_HASH = { "P-256": "sha256", "P-384": "sha384", "P-521": "sha512",
                    "secp256k1": "sha256" };

function nodeVerify(jwk, data, sig) {
  log.debug("Entering nodeVerify(). " + jwk.crv);
  var key = nodeCrypto.createPublicKey({ key: pubOf(jwk), format: "jwk" });
  var ok = /^Ed/.test(jwk.crv) ? nodeCrypto.verify(null, data, key, sig) :
    nodeCrypto.verify(NODE_HASH[jwk.crv], data,
                      { key: key, dsaEncoding: "ieee-p1363" }, sig);
  log.debug("Leaving nodeVerify(). " + ok);
  return ok;
}

// A compact presented SU or MAC JWP checked by the witness alone.
function witnessVerify(text, issuerJwk) {
  log.debug("Entering witnessVerify().");
  var P = text.split(".");
  var ph = b(P[0]);
  var ih = b(P[1]);
  var h = JSON.parse(ih.toString());
  var slots = P[2].split("~").map(function (s) {
    return s === "" ? null : b(s);
  });
  var pr = P[3].split("~").map(b);
  var holderOk = nodeVerify(h.hpk, internalRep(ph, ih, slots,
                            pr.slice(0, -1)), pr[pr.length - 1]);
  var issuerOk;
  if (/^SU-/.test(h.alg)) {
    var shown = slots.filter(function (s) {
      return s !== null;
    });
    issuerOk = nodeVerify(issuerJwk, ih, pr[0]) && shown.every(
      function (s, n) {
        return nodeVerify(h.iek, s, pr[n + 1]);
      });
  } else {
    var mac = h.alg === "MAC-H384" ? "sha384" : h.alg === "MAC-H512" ?
      "sha512" : "sha256";
    var macs = slots.map(function (s, i) {
      return s === null ? pr[i + 1] :
        nodeCrypto.createHmac(mac, pr[i + 1]).update(s).digest();
    });
    var comb = Buffer.concat([Buffer.from([0x82, 0x5b]), u64(ih.length), ih,
      Buffer.from([0x9b]), u64(macs.length)].concat(macs.map(function (m) {
        return Buffer.concat([Buffer.from([0x5b]), u64(m.length), m]);
      })));
    issuerOk = nodeVerify(issuerJwk, comb, pr[0]);
  }
  log.debug("Leaving witnessVerify().");
  return holderOk && issuerOk;
}

function keyPair(crv) {
  log.debug("Entering keyPair(). " + crv);
  var pair = /^Ed/.test(crv) ?
    nodeCrypto.generateKeyPairSync(crv.toLowerCase()) :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv });
  log.debug("Leaving keyPair().");
  return pair.privateKey.export({ format: "jwk" });
}

const PH = { aud: "https://recipient.example.com", nonce: "n-0S6_WzA2Mj" };

// --- the specification's own examples -----------------------------------
function specificationVectors() {
  log.debug("Entering specificationVectors().");
  var su = FX.su;
  var c = jwp.confirm(su.issued, { issuerKey: pubOf(su.issuerKey) });
  assert.ok(c.valid, "SU-ES256 example confirms: " + c.errors.join("; "));
  var v = jwp.verify(su.presented, { issuerKey: pubOf(su.issuerKey),
    nonce: su.presentationHeader.nonce, aud: su.presentationHeader.aud });
  assert.ok(v.valid, "SU-ES256 example verifies: " + v.errors.join("; "));
  assert.deepStrictEqual(v.disclosed, su.disclosed, "its disclosed slots");
  assert.deepStrictEqual(v.claims, { iat: 1714521600, exp: 1717199999,
    given_name: "Jay", age_over_21: true }, "its claims, by name");
  var mine = jwp.present(su.issued, { disclose: su.disclosed,
    header: su.presentationHeader, holderKey: su.holderKey });
  var mp = mine.split(".");
  var sp = su.presented.split(".");
  assert.strictEqual(mp[0], sp[0], "our Presentation Header octets are " +
                     "the example's");
  assert.strictEqual(mp.slice(1, 3).join("."), sp.slice(1, 3).join("."),
                     "and so are the headers and slots");
  assert.deepStrictEqual(mp[3].split("~").slice(0, -1),
                         sp[3].split("~").slice(0, -1),
                         "every proof component but the holder's");
  assert.ok(witnessVerify(mine, su.issuerKey), "the witness verifies ours");

  c = jwp.confirm(FX.cpt.issued, { issuerKey: pubOf(su.issuerKey) });
  assert.ok(c.valid, "SU-ES256 CPT example confirms: " +
            c.errors.join("; "));
  v = jwp.verify(FX.cpt.presented, { issuerKey: pubOf(su.issuerKey),
                                     aud: "https://recipient.example.com" });
  assert.ok(v.valid, "SU-ES256 CPT example verifies: " + v.errors.join("; "));
  assert.strictEqual(v.claims["171"], "Jay", "CPT claim 171 (given_name)");

  var bk = FX.bbs.issuerKey;
  c = jwp.confirm(FX.bbs.issued, { issuerKey: bk });
  assert.ok(c.valid, "BBS example confirms: " + c.errors.join("; "));
  v = jwp.verify(FX.bbs.presented, { issuerKey: pubOf(bk),
    nonce: FX.bbs.presentationHeader.nonce, claimNames: ["iat", "exp",
    "family_name", "given_name", "email", "address", "age_over_21"] });
  assert.ok(v.valid, "BBS example verifies: " + v.errors.join("; "));
  assert.deepStrictEqual(v.disclosed, [0, 1, 2, 3], "BBS disclosed slots");

  var mac = FX.mac;
  var secret = b(mac.sharedSecret);
  var a = jwp.ALGS["MAC-H256"];
  mac.payloads.forEach(function (p, i) {
    var key = jwp.macPayloadKey(a, secret, i);
    assert.strictEqual(Buffer.from(key).toString("base64url"),
                       mac.derivedKeys[i], "MAC derived key " + i);
  });
  c = jwp.confirm(mac.issued, { issuerKey: pubOf(mac.issuerKey) });
  assert.ok(c.valid, "MAC-H256 example confirms: " + c.errors.join("; "));
  v = jwp.verify(mac.presented, { issuerKey: pubOf(mac.issuerKey),
    nonce: mac.presentationHeader.nonce, aud: mac.presentationHeader.aud });
  assert.ok(v.valid, "MAC-H256 example verifies: " + v.errors.join("; "));
  mine = jwp.present(mac.issued, { disclose: [0, 1, 2, 3],
    header: mac.presentationHeader, holderKey: mac.holderKey });
  assert.deepStrictEqual(mine.split(".")[3].split("~").slice(0, -1),
    mac.presented.split(".")[3].split("~").slice(0, -1),
    "MAC: every presented component but the holder's is the example's");
  assert.ok(witnessVerify(mine, mac.issuerKey), "the witness verifies ours");
  log.info("PASS the drafts' Appendix A: SU-ES256 (JPT and CPT), BBS and " +
           "MAC-H256 confirm and verify; our presentations reproduce every " +
           "deterministic byte.");
  log.debug("Leaving specificationVectors().");
}

// --- round trips, every offered algorithm -------------------------------
const CLAIMS = { iss: "https://issuer.example", given_name: "Alice",
                 family_name: "Liddell", age_over_18: true };
const NAMES = Object.keys(CLAIMS);

function roundTrips() {
  log.debug("Entering roundTrips().");
  var cases = [["SU-ES256", "P-256", "P-256"], ["SU-ES384", "P-384", "P-384"],
               ["SU-ES512", "P-521", "Ed25519"],
               ["MAC-H256", "P-256", "P-256"], ["MAC-H384", "P-384", "P-384"],
               ["MAC-H512", "P-521", "P-521"],
               ["MAC-H256K", "secp256k1", "Ed448"]];
  cases.forEach(function (t) {
    var issuer = keyPair(t[1]);
    var holder = keyPair(t[2]);
    var issued = jwp.issue({ alg: t[0], header: { claims: NAMES, typ: "JPT" },
      payloads: jwp.jptPayloads(CLAIMS, NAMES), issuerKey: issuer,
      holderKey: holder });
    var c = jwp.confirm(issued, { issuerKey: pubOf(issuer) });
    assert.ok(c.valid, t[0] + ": ours confirms: " + c.errors.join("; "));
    var shown = jwp.present(issued, { disclose: [0, 1, 3], header: PH,
                                      holderKey: holder });
    var v = jwp.verify(shown, { issuerKey: pubOf(issuer), nonce: PH.nonce,
                                aud: PH.aud });
    assert.ok(v.valid, t[0] + ": ours verifies: " + v.errors.join("; "));
    assert.deepStrictEqual(v.claims, { iss: CLAIMS.iss, given_name: "Alice",
      age_over_18: true }, t[0] + ": exactly the disclosed claims");
    assert.ok(witnessVerify(shown, issuer), t[0] + ": node's crypto, over " +
              "JPA's binary forms rebuilt in this test, verifies it");
    negatives(t[0], shown, issued, issuer);
  });
  log.info("PASS SU-ES256/384/512, MAC-H256/384/512 and MAC-H256K: issue, " +
           "confirm, present, verify, each checked by node's crypto.");
  log.debug("Leaving roundTrips().");
}

function negatives(alg, shown, issued, issuer) {
  log.debug("Entering negatives(). " + alg);
  var o = { issuerKey: pubOf(issuer), nonce: PH.nonce, aud: PH.aud };
  var P = shown.split(".");
  var slots = P[2].split("~");
  slots[0] = Buffer.from(JSON.stringify("https://evil.example"))
    .toString("base64url");
  assert.ok(!jwp.verify([P[0], P[1], slots.join("~"), P[3]].join("."), o)
    .valid, alg + ": a changed disclosed payload fails");
  var proofs = P[3].split("~");
  assert.ok(!jwp.verify([P[0], P[1], P[2], proofs.slice(1).join("~")]
    .join("."), o).valid, alg + ": a dropped proof component fails");
  if (/^MAC/.test(alg)) {
    proofs[3] = Buffer.alloc(32, 7).toString("base64url");
    assert.ok(!jwp.verify([P[0], P[1], P[2], proofs.join("~")].join("."), o)
      .valid, alg + ": a substituted withheld MAC fails");
  }
  assert.ok(!jwp.verify(shown, Object.assign({}, o, { nonce: "other" }))
    .valid, alg + ": another nonce fails");
  assert.ok(!jwp.verify(shown, Object.assign({}, o, { aud: "https://x" }))
    .valid, alg + ": another audience fails");
  assert.ok(!jwp.verify(issued, o).valid, alg + ": an issued JWP is not " +
            "verified as a presentation");
  assert.ok(!jwp.confirm(shown, o).valid, alg + ": a presented JWP is not " +
            "confirmed as issued");
  log.debug("Leaving negatives().");
}

async function bbsAgainstDigitalBazaar() {
  log.debug("Entering bbsAgainstDigitalBazaar().");
  var theirs = await import("@digitalbazaar/bbs-signatures");
  var suite = theirs.CIPHERSUITES.BLS12381_SHA256;
  var kp = await theirs.generateKeyPair({ ciphersuite: suite });
  var jwk = { kty: "OKP", crv: "BLS12381G2",
    x: Buffer.from(kp.publicKey).toString("base64url"),
    d: Buffer.from(kp.secretKey).toString("base64url") };
  var issued = jwp.issue({ alg: "BBS", header: { claims: NAMES },
    payloads: jwp.jptPayloads(CLAIMS, NAMES), issuerKey: jwk });
  var P = issued.split(".");
  var ih = b(P[0]);
  var msgs = P[1].split("~").map(b);
  assert.ok(await theirs.verifySignature({ publicKey: kp.publicKey,
    signature: b(P[2]), header: ih, messages: msgs, ciphersuite: suite }),
    "BBS: Digital Bazaar verifies our issuer signature");
  var shown = jwp.present(issued, { disclose: [1, 3], header: PH,
                                    issuerKey: pubOf(jwk) });
  var S = shown.split(".");
  assert.ok(await theirs.verifyProof({ publicKey: kp.publicKey,
    proof: b(S[3]), header: ih, presentationHeader: b(S[0]),
    disclosedMessages: [msgs[1], msgs[3]], disclosedMessageIndexes: [1, 3],
    ciphersuite: suite }), "BBS: Digital Bazaar verifies our presentation");
  var theirProof = await theirs.deriveProof({ publicKey: kp.publicKey,
    signature: b(P[2]), header: ih, presentationHeader: b(S[0]),
    messages: msgs, disclosedMessageIndexes: [1, 3], ciphersuite: suite });
  var theirShown = [S[0], S[1], S[2],
                    Buffer.from(theirProof).toString("base64url")].join(".");
  var v = jwp.verify(theirShown, { issuerKey: pubOf(jwk), nonce: PH.nonce });
  assert.ok(v.valid, "BBS: we verify Digital Bazaar's derivation: " +
            v.errors.join("; "));
  assert.deepStrictEqual(v.claims, { given_name: "Alice",
                                     age_over_18: true }, "BBS: its claims");
  var again = jwp.present(issued, { disclose: [1, 3], header: PH,
                                    issuerKey: pubOf(jwk) });
  assert.notStrictEqual(again.split(".")[3], S[3],
                        "BBS: two presentations of one JWP differ");
  assert.ok(!jwp.verify(shown, { issuerKey: pubOf(jwk), nonce: "other" })
    .valid, "BBS: another nonce fails");
  var forged = S.slice();
  forged[2] = forged[2].replace(/^[^~]*~[^~]*/, "~" + Buffer.from(
    JSON.stringify("Mallory")).toString("base64url"));
  assert.ok(!jwp.verify(forged.join("."), { issuerKey: pubOf(jwk) }).valid,
            "BBS: a changed disclosed payload fails");
  log.info("PASS BBS against Digital Bazaar's released bbs-signatures: our " +
           "issuance and presentation verify there, its derivation here; " +
           "presentations are unlinkable.");
  log.debug("Leaving bbsAgainstDigitalBazaar().");
}

// CPT issuance (the CBOR serialization), in the Appendix A.2 reading the
// parser uses: claims at 6, iek/hpk as COSE_Keys, hpa a COSE algorithm.
function cptRoundTrips() {
  log.debug("Entering cptRoundTrips().");
  var cases = [["SU-ES256", "P-256", "P-256", -9],
               ["SU-ES384", "P-384", "P-384", -51],
               ["MAC-H256", "P-256", "Ed25519", -19]];
  cases.forEach(function (t) {
    var issuer = keyPair(t[1]);
    var holder = keyPair(t[2]);
    var values = NAMES.map(function (n) {
      return CLAIMS[n];
    });
    var issued = jwp.issue({ alg: t[0], serialization: "cbor",
      header: { claims: NAMES, typ: 20 }, values: values, issuerKey: issuer,
      holderKey: holder });
    assert.ok(issued instanceof Uint8Array, t[0] + ": a CPT is bytes");
    var top = cborLib.decode(issued);
    var ih = cborLib.decode(top[0]);
    assert.deepStrictEqual(Array.from(ih.keys()).sort(function (a, b) {
      return a - b;
    }), t[0].indexOf("SU") === 0 ? [1, 3, 6, 8, 9, 10] : [1, 3, 6, 9, 10],
      t[0] + ": the header's labels are Appendix A.2's");
    assert.strictEqual(ih.get(10), t[3], t[0] + ": hpa is the COSE " +
                       "algorithm of the holder's key");
    assert.deepStrictEqual(top[1], values, t[0] + ": payloads are inline " +
                           "CBOR values");
    if (t[0].indexOf("SU") === 0) {
      assert.ok(nodeVerify(issuer, top[0], top[2][0]), t[0] + ": node's " +
                "crypto verifies the issuer's signature over the CBOR " +
                "Issuer Header");
    }
    var c = jwp.confirm(issued, { issuerKey: pubOf(issuer) });
    assert.ok(c.valid, t[0] + " CPT: confirms: " + c.errors.join("; "));
    var shown = jwp.present(issued, { disclose: [0, 1, 3], header: PH,
                                      holderKey: holder });
    var v = jwp.verify(shown, { issuerKey: pubOf(issuer), nonce: PH.nonce,
                                aud: PH.aud });
    assert.ok(v.valid, t[0] + " CPT: verifies: " + v.errors.join("; "));
  });
  assert.throws(function () {
    jwp.issue({ alg: "SU-ES256", serialization: "cbor", payloads: ["x"],
                issuerKey: keyPair("P-256"), holderKey: keyPair("P-256") });
  }, /not a CBOR value/, "a CPT payload that is not CBOR is refused");
  log.info("PASS CPT issuance (SU-ES256, SU-ES384, MAC-H256): the header " +
           "in Appendix A.2's labels, hpa a COSE algorithm, inline CBOR " +
           "payloads, the issuer's signature checked by node; confirmed, " +
           "presented, verified.");
  log.debug("Leaving cptRoundTrips().");
}

function refusals() {
  log.debug("Entering refusals().");
  ["MAC-K25519", "MAC-K448"].forEach(function (alg) {
    assert.throws(function () {
      jwp.issue({ alg: alg, payloads: ["1"], issuerKey: keyPair("Ed25519"),
                  holderKey: keyPair("Ed25519") });
    }, /KMAC/, alg + " is refused, naming why");
  });
  assert.throws(function () {
    jwp.present(FX.su.issued, { disclose: [0], header: {},
                                holderKey: FX.su.holderKey });
  }, /nonce or aud/, "a Presentation Header with nothing unique is refused");
  log.info("PASS MAC-K25519 and MAC-K448 refused by name; a Presentation " +
           "Header with no unique parameter refused.");
  log.debug("Leaving refusals().");
}

async function main() {
  log.debug("Entering main().");
  specificationVectors();
  roundTrips();
  await bbsAgainstDigitalBazaar();
  cptRoundTrips();
  refusals();
  log.info("jwp_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
