// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope_engine.js
//
// ---------------------------------------------------------------------------
// client/src/gordian_envelope.js in node (#480), held to the test vectors
// of draft-mcnally-envelope-12, draft-mcnally-deterministic-cbor-18 and
// Blockchain Commons' released Rust crates (bc-envelope 0.43.0, dcbor
// 0.25.2, bc-components 0.31.1) — their own tests' expected outputs,
// signatures included:
//
//   1. dCBOR: dcbor's encode table (numeric reduction, shortest floats,
//      65-bit negatives as Rust writes them), and every refusal its
//      decoder makes.
//   2. The draft's digest tree: leaves, assertions, nodes, wrapping, known
//      values, elision.
//   3. Keys and signatures: bc-components' HKDF key derivation, its
//      fake RNG, the BIP-340 Schnorr "Hello." signature and the
//      double-SHA-256 ECDSA one, reproduced byte for byte.
//   4. The "Certificate of Completion" credential of bc-envelope's tests:
//      every digest in its tree, the issuer's signature, the holder's
//      redaction (seven claims elided, the signature still good) and the
//      employer's countersignature — the root digest of each Rust's.
//   5. UR: BCR-2020-012's CRC and bytewords vector, ur:envelope/axgrbdrnem.
//   6. What must fail: tampering, a wrong key, an elided signature, a
//      reordered node.
//   7. Blockchain Commons' released bc-envelope-cli 0.35.0 itself
//      (tests/gordian_witness.js): it computes our credentials' digests and
//      verifies our Schnorr, ECDSA and Ed25519 signatures; we verify what it
//      signs, and what it elides, at the same digest.
//
// No browser and no services. The witness is native (tests may use native
// code) and comes from the private mirror; when it cannot be had the job
// FAILS naming the image. The TypeScript port is a prerelease, so it is not
// used.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gordian_envelope_engine",
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

const paths = require("./module_paths.js");
const ge = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "gordian_envelope.js")], "client/src/gordian_envelope.js");
const T = ge.Tagged;

const hex = function (b) {
  return Buffer.from(b).toString("hex");
};
const H = function (s) {
  return new Uint8Array(Buffer.from(s, "hex"));
};
const p8 = function (e) {
  return hex(e.digest).slice(0, 8);
};

// bc-rand's fake RNG: Xoshiro256** from a fixed seed, one byte (the low
// one) per 64-bit output. Rust's tests sign with it, so its first 32 bytes
// are the Schnorr auxiliary randomness of every expected signature.
function fakeRng() {
  log.debug("Entering fakeRng().");
  var s = ["17295166580085024720", "422929670265678780",
           "5577237070365765850", "7953171132032326923"].map(BigInt);
  var M = (BigInt(1) << BigInt(64)) - BigInt(1);
  var rotl = function (x, k) {
    return ((x << BigInt(k)) | (x >> BigInt(64 - k))) & M;
  };
  log.debug("Leaving fakeRng().");
  return function (n) {
    var out = [];
    for (var i = 0; i < n; i++) {
      var r = (rotl((s[1] * BigInt(5)) & M, 7) * BigInt(9)) & M;
      var t = (s[1] << BigInt(17)) & M;
      s[2] ^= s[0];
      s[3] ^= s[1];
      s[1] ^= s[2];
      s[0] ^= s[3];
      s[2] ^= t;
      s[3] = rotl(s[3], 45);
      out.push(Number(r & BigInt(255)));
    }
    return new Uint8Array(out);
  };
}

function key(seedHex, scheme) {
  log.debug("Entering key().");
  log.debug("Leaving key().");
  return { scheme: scheme || "schnorr",
           privateKey: ge.signingKeyFromSeed(H(seedHex)) };
}
const ALICE = "82f32c855d3d542256180810797e0073";
const BOB = "187a5973c64d359c836eba466a44db7b";

// ---------------------------------------------------------------------------

function dcbor() {
  log.debug("Entering dcbor().");
  // dcbor tests/encode.rs, which draft-18 Appendix A agrees with except
  // where Rust writes a 65-bit negative.
  var table = [
    [1.5, "f93e00"], [2345678.25, "fa4a0f2b39"],
    [1.2, "fb3ff3333333333333"], [42.0, "182a"], [2345678.0, "1a0023cace"],
    [-2345678.0, "3a0023cacd"], [-0.0, "00"],
    [5.960464477539063e-8, "f90001"], [1.401298464324817e-45, "fa00000001"],
    [5e-324, "fb0000000000000001"],
    [2.2250738585072014e-308, "fb0010000000000000"],
    [6.103515625e-5, "f90400"], [65504.0, "19ffe0"],
    [33554430.0, "1a01fffffe"],
    [-9223372036854774784.0, "3b7ffffffffffffbff"],
    [BigInt("-9223372036854775807"), "3b7ffffffffffffffe"],
    [18446744073709550000.0, "1bfffffffffffff800"],
    [18446744073709552000.0, "fa5f800000"],
    [-9223372036854777856.0, "3b80000000000007ff"],
    [-18446744073709549568.0, "3bfffffffffffff7ff"],
    [-18446744073709551616.0, "3bffffffffffffffff"],
    [-18446744073709555712.0, "fbc3f0000000000001"],
    [3.4028234663852886e38, "fa7f7fffff"],
    [3.402823466385289e38, "fb47efffffe0000001"],
    [1.7976931348623157e308, "fb7fefffffffffffff"],
    [Infinity, "f97c00"], [-Infinity, "f9fc00"], [NaN, "f97e00"]];
  table.forEach(function (row) {
    assert.strictEqual(hex(ge.encode(row[0])), row[1],
                       "dCBOR of " + String(row[0]));
  });
  // NFC at encode, refused at decode; key order; and the header rules.
  assert.strictEqual(hex(ge.encode("é")), hex(ge.encode("é")),
                     "text is NFC-normalised when written");
  var refuse = [["6365cc81", /NFC/, "non-NFC text"],
                ["a2026161016161", /order/, "misordered map keys"],
                ["a2016161016162", /duplicate/,
                 "duplicate map keys"],
                ["1817", /non-shortest/, "a non-shortest argument"],
                ["9f00ff", /indefinite/, "indefinite length"],
                ["f7", /simple value/, "undefined"],
                ["f93c00", /integral half/, "an integral float"],
                ["f97e01", /NaN/, "a non-canonical NaN"],
                ["fa3fc00000", /shorter form/, "a float with a shorter form"],
                ["0000", /after the item/, "trailing data"],
                ["62ff", /ends inside|utf-8|encoded data/i, "bad UTF-8"]];
  refuse.forEach(function (r) {
    assert.throws(function () {
      ge.decode(H(r[0]));
    }, r[1], "dCBOR refuses " + r[2]);
  });
  assert.strictEqual(ge.decode(H("3bffffffffffffffff")),
                     BigInt("-18446744073709551616"),
                     "a 65-bit negative, as Rust writes it, is read");
  log.info("PASS dCBOR: dcbor 0.25.2's encode table (" + table.length +
           " values), NFC, and " + refuse.length + " refusals.");
  log.debug("Leaving dcbor().");
}

function digestTree() {
  log.debug("Entering digestTree().");
  assert.strictEqual(hex(ge.leaf("Hello").digest), "4d303dac9eed63573f6190" +
                     "e9c4191be619e03a7b3c21e9bb3d27ac1a55971e6b",
                     "draft 4.1: the leaf digest leaves out tag 201");
  assert.strictEqual(hex(ge.elided(ge.leaf("Hello").digest).digest),
                     hex(ge.leaf("Hello").digest), "draft 4.2");
  assert.strictEqual(hex(ge.wrap("Hello").digest), "743a86a9f411b1441215fb" +
                     "bd3ece3de5206810e8a3dd8239182e123802677bd7", "draft 4.5");
  assert.strictEqual(hex(ge.assertion("knows", "Bob").digest), "78d666eb8f4" +
                     "c0977a0425ab6aa21ea16934a6bc97c6f0c3abaefac951c1714a2",
                     "draft 4.4");
  var alice = ge.addAssertion(ge.leaf("Alice"), "knows", "Bob");
  assert.strictEqual(hex(ge.toBytes(alice)), "d8c882d8c965416c696365a1d8c9" +
                     "656b6e6f7773d8c963426f62", "a node's CBOR");
  ["Carol", "Edward"].forEach(function (n) {
    alice = ge.addAssertion(alice, "knows", n);
  });
  assert.strictEqual(hex(alice.digest), "6255e3b67ad935caf07b5dce5105d913dc" +
                     "fb82f0392d4d302f6d406e85ab4769", "draft 4.3");
  assert.strictEqual(ge.tree(alice).split("\n")[2].trim(), "4012caf2 " +
                     "ASSERTION", "assertions in digest order (Carol first)");
  assert.strictEqual(p8(ge.knownValue("signed")), "d0e39e78", "known values " +
                     "are hashed as 40000(n)");
  assert.strictEqual(ge.toUr(ge.knownValue("signed")),
                     "ur:envelope/axgrbdrnem", "and written as a bare uint");
  assert.strictEqual(p8(ge.leaf(42)), "7f83f7bd");
  assert.strictEqual(p8(ge.leaf(-42)), "9e0ad272");
  assert.strictEqual(p8(ge.fromBytes(H("d8c8d818182a"))), "7f83f7bd",
                     "the legacy leaf tag 24 reads as 201");
  var salted = ge.addAssertion(ge.leaf("Hello."), ge.knownValue("salt"),
    ge.leaf(new T(ge.TAG.SALT, H("b559bbbf6cce2632"))));
  assert.strictEqual(p8(salted), "4f0f2d55", "a salted envelope");
  log.info("PASS the digest tree: the draft's section 4 vectors, known " +
           "values, the legacy leaf tag and salt.");
  log.debug("Leaving digestTree().");
}

function keysAndSignatures() {
  log.debug("Entering keysAndSignatures().");
  assert.strictEqual(hex(ge.signingKeyFromSeed(H("59f2293a5bce7d4de59e71b4" +
    "207ac5d2"))), "9505a44aaf385ce633cf0e2bc49e65cc88794213bdfbf8caf04150" +
    "b9c4905f5a", "PrivateKeyBase: HKDF-SHA-256, salt \"signing\"");
  assert.strictEqual(hex(fakeRng()(100)), "7eb559bbbf6cce2632cf9f194aeb5094" +
    "3de7e1cbad54dcfab27a42759f5e2fed518684c556472008a67932f7c682125b50cb72" +
    "e8216f6906358fdaf28d3545532daee0c5bb5023f50cd8e71ec14901ac746c576c481b" +
    "893be6656b80622b3a564e59b4e2", "bc-rand's fake RNG");
  var hello = ge.addSignature(ge.leaf("Hello."), key(ALICE),
                              { aux: fakeRng()(32) });
  assert.strictEqual(p8(hello), "949a991e", "the signed Hello. of " +
                     "format_tests.rs");
  var sig = ge.objectsFor(hello, ge.knownValue("signed"))[0].value.value;
  assert.strictEqual(hex(sig), "d0f6b2577edb3f4b0f533e21577bc12a58aaca2604" +
    "bc71e84bd4e2c81421900bca361a1a8de3b7dbfe1cb5c16e34cb8c9a78fe6f7a387e95" +
    "9bbb15f6f3d898d3", "BIP-340 over the subject's 32-byte digest, as is");
  var ecdsa = ge.signDigest({ scheme: "ecdsa", privateKey: H("322b5c1dd5a1" +
    "7c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36") },
    new TextEncoder().encode("Wolf McNally"));
  assert.strictEqual(hex(ecdsa.value[1]), "1458d0f3d97e25109b38fd965782b43" +
    "213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fb" +
    "a4dc355cd89b47213e855cf6d23", "ECDSA signs SHA-256(SHA-256(message))");
  ["schnorr", "ecdsa", "ed25519"].forEach(function (scheme) {
    var k = key(ALICE, scheme);
    var signed = ge.sign(ge.leaf("credential"), k);
    var pub = ge.publicKeyOf(k);
    assert.ok(ge.verifySignatures(signed, pub).valid, scheme + " verifies");
    assert.ok(ge.verifySignatures(ge.read(ge.toUr(signed)),
      ge.readPublicKey(ge.publicKeyUr(pub))).valid, scheme + " survives " +
      "the UR forms of the envelope and the key");
    assert.ok(!ge.verifySignatures(signed, ge.publicKeyOf(key(BOB,
      scheme))).valid, scheme + ": another key does not verify");
  });
  log.info("PASS keys and signatures: HKDF, the fake RNG, the Schnorr " +
           "Hello. and the ECDSA vector reproduced; Schnorr, ECDSA and " +
           "Ed25519 through the UR forms; another key refused.");
  log.debug("Leaving keysAndSignatures().");
}

function certificate() {
  log.debug("Entering certificate().");
  var cred = ge.leaf(new T(ge.TAG.ARID, H("4676635a6e6068c2ef3ffd8ff726dd40" +
                                         "1fd341036e920f136a1d8af5e829496d")));
  [[ge.knownValue("isA"), "Certificate of Completion"],
   [ge.knownValue("issuer"), "Example Electrical Engineering Board"],
   [ge.knownValue("controller"), "Example Electrical Engineering Board"],
   ["firstName", "James"], ["lastName", "Maxwell"],
   ["issueDate", new T(1, 1577836800)],
   ["expirationDate", new T(1, 1830297600)],
   ["photo", "This is James Maxwell's photo."],
   ["certificateNumber", "123-456-789"],
   ["subject", "RF and Microwave Engineering"],
   ["continuingEducationUnits", 1], ["professionalDevelopmentHours", 15],
   ["topics", ["Subject 1", "Subject 2"]]].forEach(function (a) {
    cred = ge.addAssertion(cred, a[0], a[1]);
  });
  var signed = ge.addAssertion(ge.sign(cred, key(ALICE),
    { aux: fakeRng()(32) }), ge.knownValue("note"),
    "Signed by Example Electrical Engineering Board");
  // format_tests.rs: the whole tree, first four bytes of each digest.
  var expected = ["0b721f78", "397a2d4c", "8122ffa9", "10d3de01", "1f9ff098",
    "9e3bff3a", "21c21808", "36c254d0", "6e5d379f", "639ae9bf", "3c114201",
    "5f82a16a", "fe4d5230", "4a9b2e4d", "222afe69", "cb67f31d", "4d67bba0",
    "2be2d79b", "051beee6", "5171cbaf", "3976ef74", "231b8527", "54b3e1e7",
    "f13aa855", "dc0e9c36", "5dc6d4e3", "4395643b", "d6d0b768", "68895d8e",
    "e6bf4dd3", "543fcc09", "8ec5e912", "2b191589", "4bf5122f", "9b3d4785",
    "af10ee92", "f8489ac1", "caf5ced3", "8e4e62eb", "202c10ef", "d3e0cc15",
    "6dd16ba3", "f8489ac1", "46a02aaf", "d0e39e78", "34c14941", "e6d7fca0",
    "0fcd6a39", "f106bad1"];
  var got = ge.tree(signed).split("\n").map(function (l) {
    return l.trim().slice(0, 8);
  });
  assert.deepStrictEqual(got, expected, "every digest of the signed " +
                         "credential is Rust's");
  var alice = ge.publicKeyOf(key(ALICE));
  assert.ok(ge.verifySignatures(signed, alice).valid, "the issuer's " +
            "signature verifies");
  // test_data.rs: the holder reveals six claims.
  var c = ge.claims(signed);
  var keep = c.claims.filter(function (x) {
    return /^("firstName"|"lastName"|'isA'|'issuer'|"subject"|"expiration)/
      .test(x.label);
  }).map(function (x) {
    return x.digest;
  });
  assert.strictEqual(keep.length, 6);
  var redacted = ge.present(signed, keep);
  assert.strictEqual(p8(redacted), "0b721f78", "the redaction keeps the " +
                     "root digest");
  assert.deepStrictEqual(ge.assertionsOf(ge.subjectOf(redacted).envelope)
    .filter(function (a) {
      return a.kind === "elided";
    }).map(p8).sort(), ["1f9ff098", "4a9b2e4d", "5171cbaf", "54b3e1e7",
                        "68895d8e", "8ec5e912", "9b3d4785"],
    "exactly the seven claims Rust's redaction elides");
  assert.ok(ge.verifySignatures(ge.read(ge.toUr(redacted)), alice).valid,
            "the issuer's signature verifies on the redacted credential, " +
            "read back from its UR");
  // format_tests.rs: the employer re-wraps and countersigns.
  var employer = ge.addSignature(ge.addAssertion(ge.wrap(ge.addAssertion(
    ge.addAssertion(ge.wrap(redacted), "employeeHiredDate",
                    new T(1, 1640995200)), "employeeStatus", "active")),
    ge.knownValue("note"), "Signed by Employer Corp."), key(BOB),
    { aux: fakeRng()(32) });
  assert.strictEqual(p8(employer), "7ab3e6b1", "the countersigned " +
                     "credential's root is Rust's");
  log.info("PASS the Certificate of Completion: all " + expected.length +
           " digests, the issuer's signature, the six-claim redaction and " +
           "the employer's countersignature are bc-envelope's.");
  log.debug("Leaving certificate().");
  return { signed: signed, alice: alice };
}

function urAndRefusals(c) {
  log.debug("Entering urAndRefusals().");
  var body = H("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
  assert.strictEqual(ge.crc32(body).toString(16), "c904f40b");
  assert.strictEqual(ge.urEncode("crypto-seed", body).split("/")[1],
    "tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd",
    "BCR-2020-012's bytewords");
  var ur = ge.toUr(c.signed);
  assert.throws(function () {
    ge.read(ur.slice(0, -2) + (ur.slice(-2) === "ae" ? "ad" : "ae"));
  }, /CRC/, "a UR whose checksum fails");
  // Swap two assertions of the outer node: same tree, wrong order.
  var cb = ge.toCbor(c.signed);
  var swapped = [cb[0], cb[2], cb[1]];
  assert.throws(function () {
    ge.fromCbor(swapped);
  }, /digest order/, "a node whose assertions are out of order");
  var forged = ge.addAssertion(ge.subjectOf(c.signed).envelope, "firstName",
                               "Jane");
  var resigned = ge.node(ge.wrap(forged), ge.assertionsOf(c.signed));
  assert.ok(!ge.verifySignatures(resigned, c.alice).valid, "a claim added " +
            "under the issuer's signature breaks it");
  var sigAssertion = ge.assertionsOf(c.signed).filter(function (a) {
    return /signed/.test(ge.label(a));
  })[0];
  var hidden = ge.elideRemoving(c.signed, [sigAssertion.object]);
  var r = ge.verifySignatures(hidden, c.alice);
  assert.ok(!r.valid && /elided/.test(r.results[0].reason), "an elided " +
            "signature cannot be checked, and says so");
  log.info("PASS UR: BCR-2020-012's vector, a bad checksum refused; " +
           "refusals: reordered node, a claim added under the signature, " +
           "an elided signature.");
  log.debug("Leaving urAndRefusals().");
}

function againstTheCli() {
  log.debug("Entering againstTheCli().");
  var run = require("./gordian_witness.js").runner();
  var seed = H(ALICE);
  var cred = ge.leaf(new T(ge.TAG.ARID, new Uint8Array(32).fill(7)));
  cred = ge.addAssertion(cred, ge.knownValue("isA"), "Certificate");
  cred = ge.addAssertion(cred, "firstName", "James");
  cred = ge.addAssertion(cred, ge.saltedAssertion("lastName", "Maxwell",
                                                  new Uint8Array(8).fill(1)));
  ["schnorr", "ecdsa", "ed25519"].forEach(function (scheme) {
    var k = { scheme: scheme, privateKey: ge.signingKeyFromSeed(seed) };
    var signed = ge.sign(cred, k);
    var ur = ge.toUr(signed);
    assert.strictEqual(run("digest", "--hex", ur), hex(signed.digest),
                       scheme + ": the CLI computes our digest");
    run("verify", "--verifier", ge.publicKeyUr(ge.publicKeyOf(k)), ur);
  });
  var prv = run("generate", "prvkeys");
  var pub = ge.readPublicKey(run("generate", "pubkeys", prv));
  var theirs = run("subject", "type", "string", "Alice");
  theirs = run("assertion", "add", "pred-obj", "string", "knows", "string",
               "Bob", theirs);
  theirs = run("sign", "--signer", prv, run("subject", "type", "wrapped",
                                            theirs));
  var env = ge.read(theirs);
  assert.strictEqual(hex(env.digest), run("digest", "--hex", theirs),
                     "our digest of the CLI's envelope is the CLI's");
  assert.ok(ge.verifySignatures(env, pub).valid, "we verify the CLI's " +
            "signature");
  var elided = ge.read(run("elide", "removing", run("digest",
    ge.toUr(ge.assertion("knows", "Bob"))), theirs));
  assert.strictEqual(hex(elided.digest), hex(env.digest), "the CLI's " +
                     "elision keeps the root digest, read here");
  assert.ok(ge.verifySignatures(elided, pub).valid, "and its signature " +
            "still verifies here");
  log.info("PASS bc-envelope-cli 0.35.0: it computes our digests and " +
           "verifies our Schnorr, ECDSA and Ed25519 signatures; we verify " +
           "what it signs and what it elides.");
  log.debug("Leaving againstTheCli().");
}

function main() {
  log.debug("Entering main().");
  dcbor();
  digestTree();
  keysAndSignatures();
  urAndRefusals(certificate());
  againstTheCli();
  log.info("gordian_envelope_engine: all checks passed.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
}
