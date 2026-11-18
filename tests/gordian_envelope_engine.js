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
//   8. The obscuring cases against the crates' vectors: bc-components'
//      RFC 8439 EncryptedMessage (its CBOR and its ur:encrypted), its four
//      Compressed checksums, bc-envelope's compression and encryption
//      tests (the compressed-subject tree, digests unchanged), the sskr
//      crate's shares for its three splits (printed by its own tests,
//      which use a counting RNG reproduced here) and bc-shamir's recovery
//      example, and the ur crate's single-part and twenty-part vectors
//      (fountain parts included) and its 32767-byte round trip.
//   9. The same against bc-envelope-cli, both ways: encryption with a
//      symmetric key (seven envelope shapes), compression, recipients
//      (X25519 from a seed — the CLI derives the same keys — and
//      ML-KEM-512/768/1024), password locks (PBKDF2, scrypt, Argon2id;
//      HKDF, which the CLI does not count as a password, round trip
//      only), SSKR split and join (two groups), ML-DSA-44/65/87
//      signatures, and SSH signatures (Ed25519 byte for byte; ECDSA P-256
//      and P-384).
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
const gc = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "gordian_envelope_crypto.js")], "client/src/gordian_envelope_crypto.js");
const sskr = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "sskr.js")], "client/src/sskr.js");
const bcur = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "bc_ur.js")], "client/src/bc_ur.js");
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

// bc-components' and bc-envelope's own obscuring tests.
function obscuringVectors() {
  log.debug("Entering obscuringVectors().");
  // bc-components symmetric/mod.rs: RFC 8439 section 2.8.2 as an
  // EncryptedMessage.
  var msg = gc.encryptMessage(H("808182838485868788898a8b8c8d8e8f909192939" +
    "495969798999a9b9c9d9e9f"), new TextEncoder().encode("Ladies and " +
    "Gentlemen of the class of '99: If I could offer you only one tip for " +
    "the future, sunscreen would be it."), H("50515253c0c1c2c3c4c5c6c7"),
    H("070000004041424344454647"));
  var msgHex = "d99c42845872d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08" +
    "fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905" +
    "d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67594558580" +
    "8b4831d7bc3ff4def08e4b7a9de576d26586cec64b61164c07000000404142434445" +
    "4647501ae10b594f09e26a7e902ecbd06006914c50515253c0c1c2c3c4c5c6c7";
  assert.strictEqual(hex(ge.encode(msg)), msgHex, "bc-components' RFC 8439 " +
                     "EncryptedMessage, byte for byte");
  assert.strictEqual(ge.urEncode("encrypted", ge.encode(msg.value)),
    "ur:encrypted/lrhdjptecylgeeiemnhnuykglnperfguwskbsaoxpmwegydtjtayzept" +
    "voreosenwyidtbfsrnoxhylkptiobglfzszointnmojplucyjsuebknnambddtahtbon" +
    "rpkbsnfrenmoutrylbdpktlulkmkaxplvldeascwhdzsqddkvezstbkpmwgolplalufd" +
    "ehtsrffhwkuewtmngrknntvwkotdihlntoswgrhscmgsataeaeaefzfpfwfxfyfefgfl" +
    "gdcyvybdhkgwasvoimkbmhdmsbtihnammegsgdgygmgurtsesasrssskswstcfnbpdct",
    "and its ur:encrypted");
  // bc-envelope encrypted_tests.rs: every shape keeps its digest.
  var symKey = H("38900719dea655e9a1bc1682aaccf0bfcd79a7239db672d39216e4ac" +
                 "dd660dc0");
  var nonce = H("4d785658f36c22fb5aed3ac0");
  var single = ge.addAssertion(ge.leaf("Alice"), "knows", "Bob");
  var shapes = [ge.leaf("Hello."), ge.wrap(ge.leaf("Hello.")),
                ge.wrap(ge.wrap(ge.leaf("Hello."))), ge.knownValue("note"),
                ge.assertion("knows", "Bob"), single,
                ge.addAssertion(single, "knows", "Carol")];
  shapes.forEach(function (e, i) {
    var enc = ge.read(ge.toUr(gc.encryptSubject(e, symKey, nonce)));
    assert.strictEqual(hex(enc.digest), hex(e.digest), "shape " + i +
                       ": the encrypted envelope keeps its digest");
    assert.strictEqual(ge.subjectOf(enc).kind, "encrypted");
    assert.strictEqual(ge.toUr(gc.decryptSubject(enc, symKey)), ge.toUr(e),
                       "shape " + i + " decrypts to itself");
    assert.throws(function () {
      gc.decryptSubject(enc, H("00".repeat(32)));
    }, /Poly1305/, "shape " + i + ": another key does not open it");
  });
  // bc-components compressed.rs: the checksums, and the sizes that are
  // not DEFLATE's choice.
  var LOREM = "Lorem ipsum dolor sit amet consectetur adipiscing elit mi " +
    "nibh ornare proin blandit diam ridiculus, faucibus mus dui eu " +
    "vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. " +
    "Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet " +
    "velit ullamcorper porttitor, lobortis dapibus hac purus aliquam " +
    "natoque iaculis blandit montes nunc pretium.";
  [[LOREM, "3eeb10a0", 364], [LOREM.slice(0, 49), "29db1793", 49],
   ["Lorem", "44989b39", 5], ["", "00000000", 0]].forEach(function (c) {
    var b = new TextEncoder().encode(c[0]);
    assert.strictEqual(ge.crc32(b).toString(16).padStart(8, "0"), c[1],
                       "the Compressed checksum of " + c[2] + " bytes");
  });
  var original = ge.leaf(LOREM);
  assert.strictEqual(ge.toBytes(original).length, 371, "compression_tests: " +
                     "371 bytes");
  var compressed = ge.read(ge.toUr(gc.compress(original)));
  assert.strictEqual(compressed.kind, "compressed");
  assert.strictEqual(hex(compressed.digest), hex(original.digest));
  assert.ok(ge.toBytes(compressed).length < 300, "and smaller (" +
            ge.toBytes(compressed).length + " here; miniz's 283)");
  assert.strictEqual(ge.toUr(gc.decompress(compressed)), ge.toUr(original));
  var tiny = gc.compress(ge.leaf("Hi"));
  assert.strictEqual(gc.readCompressed(tiny.cbor).data.length,
                     gc.readCompressed(tiny.cbor).size, "data DEFLATE " +
                     "would not shrink is stored as it is");
  assert.strictEqual(ge.toUr(gc.decompress(tiny)), ge.toUr(ge.leaf("Hi")));
  // compression_tests.rs test_compress_subject: the signed tree, then its
  // subject compressed, at the same digests.
  var signed = ge.addSignature(ge.wrap(ge.addAssertion(ge.leaf("Alice"),
    ge.knownValue("note"), LOREM)), key(ALICE), { aux: fakeRng()(32) });
  assert.deepStrictEqual(ge.tree(signed).split("\n").map(function (l) {
    return l.trim().slice(0, 8);
  }), ["ec608f27", "d7183f04", "7f35e345", "13941b48", "9fb69539",
       "0fcd6a39", "e343c9b4", "0db2ee20", "d0e39e78", "f0d3ce4c"],
  "test_compress_subject's tree");
  var cs = ge.read(ge.toUr(gc.compressSubject(signed)));
  assert.deepStrictEqual(ge.tree(cs).split("\n").map(function (l) {
    return l.trim();
  }).slice(0, 2), ["ec608f27 NODE", "d7183f04 subj COMPRESSED"],
  "the compressed subject keeps both digests");
  assert.ok(ge.verifySignatures(cs, ge.publicKeyOf(key(ALICE))).valid,
            "the signature still verifies over the compressed subject");
  assert.strictEqual(ge.toUr(gc.decompressSubject(cs)), ge.toUr(signed));
  log.info("PASS obscuring vectors: bc-components' EncryptedMessage (CBOR " +
           "and UR), seven encrypted shapes at their digests, the " +
           "Compressed checksums, and test_compress_subject's tree (" +
           "signature still valid).");
  log.debug("Leaving obscuringVectors().");
}

// The sskr crate's tests' RNG: each fill restarts at 0 and adds 17.
function countingRng(n) {
  log.debug("Entering countingRng().");
  var out = new Uint8Array(n);
  for (var i = 0, b = 0; i < n; i++, b = (b + 17) & 255) out[i] = b;
  log.debug("Leaving countingRng().");
  return out;
}

function sskrVectors() {
  log.debug("Entering sskrVectors().");
  var cases = [
    [1, ["3-of-5"], "0ff784df000c4380a5ed683f7e6e3dcf", [1, 2, 4], [
      "001100020000112233445566778899aabbccddeeff",
      "0011000201d43099fe444807c46921a4f33a2a798b",
      "0011000202d9ad4e3bec2e1a7485698823abf05d36",
      "00110002030d8cf5f6ec337bc764d1866b5d07ca42",
      "00110002041aa7fe3199bc5092ef3816b074cabdf2"]],
    [1, ["2-of-7"], "204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3" +
     "efabc184b1a", [3, 4], [
      "00110001002dcd14c2252dc8489af3985030e74d5a48e8eff1478ab86e65b43869b" +
      "f39d556",
      "0011000101a1dfdd798388aada635b9974472b4fc59a32ae520c42c9f6a0af70149" +
      "b882487",
      "00110001022ee99daf727c0c7773b89a18de64497ff7476dacd1015a45f482a893f" +
      "7402cef",
      "0011000103a2fb5414d4d96ee58a109b3ca9a84be0259d2c0f9ac92bdd3199e0eed" +
      "3f1dd3e",
      "00110001042b851d188b8f5b3653659cc0f7fa45102dadf04b708767385cd803862" +
      "fcb3c3f",
      "0011000105a797d4a32d2a39a4aacd9de48036478fff77b1e83b4f16a099c34bfb0" +
      "b7acdee",
      "001100010628a19475dcde9f09ba2e9e881979413592027216e60c8513cdee937c6" +
      "7b2c586"]],
    [2, ["2-of-3", "2-of-3"], "204188bfa6b440a1bdfd6753ff55a8241e07af5c5be9" +
     "43db917e3efabc184b1a", [0, 1, 3, 5], [
      "0011110100ce5cce1ad9fe9cefa4707449576e8eadfc7d107c5a9e812b21f80aeca" +
      "635cacd",
      "001111010184190ee2fcc276947ad68a6eef10694c784811720d350b06102944028" +
      "1a5a550",
      "00111101025ad655f193865319032793073c925b74ef171260f4d38e714341962be" +
      "80e14ec",
      "00111111004d741d38fcc276947ad68a6eef10694c784811720d350b06102944028" +
      "1a5a550",
      "0011111101b39fde657f5bfe7d5dd8756d20a28c322ea751df1156f0b3e4e342918" +
      "2843b1c",
      "0011111102aab98082e1eb7d5d34ca6f686a6fb8b0d48d913335f3e677e3a6483f8" +
      "7e782c8"]]];
  cases.forEach(function (c) {
    var flat = [];
    sskr.generate(sskr.spec(c[0], c[1]), H(c[2]), countingRng)
      .forEach(function (g) {
        flat = flat.concat(g.map(hex));
      });
    assert.deepStrictEqual(flat, c[4], c[1].join(" + ") + ": the sskr " +
                           "crate's shares, byte for byte");
    assert.strictEqual(hex(sskr.combine(c[3].map(function (i) {
      return H(flat[i]);
    }))), c[2], c[1].join(" + ") + ": recovered from shares " + c[3]);
  });
  assert.throws(function () {
    sskr.combine([H(cases[0][4][0]), H(cases[0][4][1])]);
  }, /checksum|group/, "two shares of a 3-of-5 do not recover it");
  assert.strictEqual(new TextDecoder().decode(sskr.recoverSecret([0, 2], [
    new Uint8Array([47, 165, 102, 232, 218, 99, 6, 94, 39, 6, 253, 215, 12,
                    88, 64, 32, 105, 40, 222, 146, 93, 197, 48, 129]),
    new Uint8Array([221, 174, 116, 201, 90, 99, 136, 33, 64, 215, 60, 84,
                    207, 28, 74, 10, 111, 243, 43, 224, 48, 64, 199,
                    172])])), "my secret belongs to me.",
  "bc-shamir's recovery example");
  // bc-envelope sskr_tests.rs: the share envelope's notation, and 2-of-3.
  var e = ge.addAssertion(ge.leaf("Secret message"), "metadata",
                          "This is a test");
  var split = gc.splitEnvelope(e, 1, ["2-of-3"]);
  assert.strictEqual(ge.notation(split.shares[0]), "ENCRYPTED [\n    " +
                     "'sskrShare': SSKRShare\n]", "sskr_tests' notation");
  var back = split.shares.slice(1).map(function (x) {
    return ge.read(ge.toUr(x));
  });
  assert.strictEqual(ge.toUr(gc.joinEnvelope(back)), ge.toUr(e),
                     "two of three shares rejoin it");
  assert.throws(function () {
    gc.joinEnvelope([back[0]]);
  }, /recover/, "one share does not");
  log.info("PASS SSKR: the sskr crate's shares for 3-of-5, 2-of-7 and two " +
           "2-of-3 groups, byte for byte, and their recovery; " +
           "bc-shamir's example; bc-envelope's share notation and 2-of-3 " +
           "join.");
  log.debug("Leaving sskrVectors().");
}

function multipartVectors() {
  log.debug("Entering multipartVectors().");
  // ur 0.4.1's make_message: Xoshiro256** from SHA-256("Wolf"), a byte per
  // next_int(0, 255).
  var message = function (n) {
    var rng = new bcur.Xoshiro(new TextEncoder().encode("Wolf"));
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = rng.nextInt(0, 255);
    return ge.encode(out);
  };
  var rng = new bcur.Xoshiro(new TextEncoder().encode("Wolf"));
  var first = [];
  for (var i = 0; i < 10; i++) first.push(Number(rng.next() % BigInt(100)));
  assert.deepStrictEqual(first, [42, 81, 85, 8, 82, 84, 76, 73, 70, 88],
                         "test_rng_1");
  assert.strictEqual(bcur.urEncode("bytes", message(50)), "ur:bytes/hdeymej" +
    "tswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuef" +
    "ywkdplrsrjynbvygabwjldapfcsdwkbrkch", "test_single_part_ur");
  var expected = ["lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsno" +
    "yoyaxaedsuttydmmhhpktpmsrjtdkgslpgh", "lpaoascfadaxcywenbpljkhdcagwdpf" +
    "nsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
    "lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeyk" +
    "ssjykklronvsjksopdzmol", "lpaaascfadaxcywenbpljkhdcasotkhemthydawydtax" +
    "neurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas", "lpahascfadaxcywenb" +
    "pljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejo" +
    "kbwf", "lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpa" +
    "vyrolkzczcpkmwidmwoxkilghdsowp", "lpatascfadaxcywenbpljkhdcavszmwnjkwt" +
    "clrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy", "lpayascfad" +
    "axcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttoro" +
    "dklubbuyaetk", "lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmln" +
    "wmadspaxrkytbztpbauotbgtgtaeaevtgavtny", "lpbkascfadaxcywenbpljkhdcahk" +
    "adaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
    "lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeyk" +
    "ssjykklronvsjkvetiiapk", "lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospey" +
    "iefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs", "lpbtascfadaxcywenb" +
    "pljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziach" +
    "rfgd", "lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydk" +
    "bkdslgjkbbkortbelomueekgvstegt", "lpbsascfadaxcywenbpljkhdcaynmhpddpzm" +
    "versbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt", "lpbeascfad" +
    "axcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmuki" +
    "rlrsbtamjtpd", "lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnyty" +
    "isincxmhtbceaykolduortotiaiaiafhiaoyce", "lpbgascfadaxcywenbpljkhdcahk" +
    "adaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
    "lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbn" +
    "cxgslgftvtsrjtksplcpeo", "lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrt" +
    "rdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot"].map(function (w, k) {
    return "ur:bytes/" + (k + 1) + "-9/" + w;
  });
  var parts = bcur.encodeParts("bytes", message(256), 30, 20);
  assert.deepStrictEqual(parts, expected, "test_ur_encoder: all twenty " +
                         "parts, the eleven fountain parts included");
  var dec = bcur.decodeAny(parts.slice(1).join(" "));
  assert.strictEqual(hex(dec.body), hex(message(256)), "decoded without " +
                     "part 1, from simple and mixed parts");
  assert.throws(function () {
    bcur.decodeAny(parts.slice(9).join(" "));
  }, /more parts/, "parts 10-20 alone span eight of the nine fragments, " +
  "and the decoder says it needs more");
  var big = message(32767);
  var enc = new bcur.MultipartEncoder("bytes", big, 1000);
  var d = new bcur.MultipartDecoder();
  while (!d.isComplete()) d.receive(enc.nextPart());
  assert.strictEqual(hex(d.message().body), hex(big), "test_multipart_ur: " +
                     "32767 bytes in 1000-byte fragments");
  assert.throws(function () {
    var other = bcur.encodeParts("bytes", message(255), 30, 2);
    bcur.decodeAny(parts[0] + " " + other[1]);
  }, /same message/, "a part of another message is refused");
  // An envelope as parts, read back by gordian_envelope.read().
  var cred = ge.leaf("x");
  for (var j = 0; j < 30; j++) cred = ge.addAssertion(cred, "claim" + j, j);
  var eparts = ge.toUrParts(cred, 80, 40);
  assert.ok(/^ur:envelope\/1-\d+\//.test(eparts[0]), eparts[0].slice(0, 20));
  assert.strictEqual(ge.toUr(ge.read(eparts.filter(function (p, k) {
    return k % 4 !== 1;
  }).join("\n"))), ge.toUr(cred), "an envelope from shuffled mixed parts");
  log.info("PASS multi-part URs: the ur crate's RNG, single-part and " +
           "twenty-part vectors byte for byte, decoding from mixed parts, " +
           "its 32767-byte round trip, and an envelope read from parts.");
  log.debug("Leaving multipartVectors().");
}

function obscuringAgainstTheCli() {
  log.debug("Entering obscuringAgainstTheCli().");
  var run = require("./gordian_witness.js").runner();
  var alice = ge.addAssertion(ge.leaf("Alice"), "knows", "Bob");
  var wrapped = ge.wrap(alice);
  // Symmetric encryption, seven shapes, both ways.
  var k = gc.generateKey();
  var kur = gc.keyUr(k);
  [ge.leaf("Hello."), ge.knownValue("note"), ge.assertion("knows", "Bob"),
   alice, wrapped, ge.wrap(wrapped), ge.addAssertion(alice, "knows",
                                                     "Carol")]
    .forEach(function (e, i) {
      assert.strictEqual(run("decrypt", "--key", kur,
                             ge.toUr(gc.encryptSubject(e, k))), ge.toUr(e),
                         "shape " + i + ": the CLI decrypts ours");
      assert.strictEqual(ge.toUr(gc.decryptSubject(ge.read(run("encrypt",
        "--key", kur, ge.toUr(e))), k)), ge.toUr(e), "shape " + i +
        ": we decrypt the CLI's");
    });
  // Compression, both ways.
  var long = ge.leaf("Lorem ipsum ".repeat(40));
  assert.strictEqual(run("decompress", ge.toUr(gc.compress(long))),
                     ge.toUr(long), "the CLI decompresses ours");
  var theirs = ge.read(run("compress", ge.toUr(long)));
  assert.strictEqual(theirs.kind, "compressed");
  assert.strictEqual(ge.toUr(gc.decompress(theirs)), ge.toUr(long),
                     "we decompress the CLI's");
  var signed = ge.sign(alice, key(ALICE));
  assert.strictEqual(run("decompress", "--subject", ge.toUr(
    gc.compressSubject(signed))), ge.toUr(signed), "and a compressed " +
    "subject under a signature");
  // Recipients: X25519 from a seed, and ML-KEM.
  var seed = H("0102030405060708090a0b0c0d0e0f10");
  var mine = gc.readPrivateKeys(hex(seed));
  var base = ge.urEncode("crypto-prvkey-base", ge.encode(seed));
  assert.strictEqual(run("generate", "prvkeys", base), gc.privateKeysUr(mine),
                     "the CLI derives our private keys from the seed");
  var minePub = gc.publicKeysUr(gc.publicKeysOf(mine));
  assert.strictEqual(run("generate", "pubkeys", run("generate", "prvkeys",
                                                   base)), minePub,
                     "and our public keys");
  var prv = run("generate", "prvkeys");
  var pub = run("generate", "pubkeys", prv);
  var toThem = gc.encryptSubjectToRecipients(wrapped,
    [gc.readPublicKeys(pub), gc.readPublicKeys(minePub)]);
  assert.strictEqual(ge.toUr(ge.subjectOf(ge.read(run("decrypt",
    "--recipient", prv, ge.toUr(toThem))))), ge.toUr(wrapped),
  "the CLI opens our X25519 SealedMessage");
  assert.strictEqual(ge.toUr(ge.subjectOf(gc.decryptSubjectToRecipient(
    ge.read(run("encrypt", "--recipient", minePub, ge.toUr(wrapped))),
    mine))), ge.toUr(wrapped), "we open the CLI's");
  ["mlkem512", "mlkem768", "mlkem1024"].forEach(function (level) {
    var pair = run("generate", "keypairs", "--encryption", level)
      .split(/\s+/);
    var ours = gc.encryptSubjectToRecipients(wrapped,
                                             [gc.readPublicKeys(pair[1])]);
    assert.strictEqual(ge.toUr(ge.subjectOf(ge.read(run("decrypt",
      "--recipient", pair[0], ge.toUr(ours))))), ge.toUr(wrapped),
    level + ": the CLI opens ours");
    assert.strictEqual(ge.toUr(ge.subjectOf(gc.decryptSubjectToRecipient(
      ge.read(run("encrypt", "--recipient", pair[1], ge.toUr(wrapped))),
      gc.readPrivateKeys(pair[0])))), ge.toUr(wrapped), level +
      ": we open the CLI's");
  });
  // Password locks.
  var pw = new TextEncoder().encode("correct horse");
  // An HKDF lock is not a PASSWORD lock to the CLI (is_password_based()),
  // so it is only round-tripped here.
  gc.KDF_METHODS.forEach(function (m) {
    var locked = gc.lockSubject(wrapped, m, pw);
    assert.strictEqual(ge.toUr(ge.subjectOf(gc.unlockSubject(ge.read(
      ge.toUr(locked)), pw))), ge.toUr(wrapped), m + ": ours unlocks here");
    if (m !== "hkdf") {
      assert.strictEqual(ge.toUr(ge.subjectOf(ge.read(run("decrypt",
        "--password", "correct horse", ge.toUr(locked))))), ge.toUr(wrapped),
      m + ": the CLI unlocks ours");
      assert.strictEqual(ge.toUr(ge.subjectOf(gc.unlockSubject(ge.read(
        run("encrypt", "--password", "correct horse", "-d", m,
            ge.toUr(wrapped))), pw))), ge.toUr(wrapped), m +
        ": we unlock the CLI's");
    }
  });
  assert.throws(function () {
    gc.unlockSubject(gc.lockSubject(wrapped, "pbkdf2", pw),
                     new TextEncoder().encode("wrong"));
  }, /opens none/, "a wrong password opens nothing");
  // SSKR.
  var split = gc.splitEnvelope(alice, 2, ["2-of-3", "2-of-3"]);
  var urs = split.shares.map(ge.toUr);
  assert.strictEqual(run("sskr", "join", urs[0], urs[2], urs[3], urs[5]),
                     ge.toUr(alice), "the CLI joins our shares");
  var cs = run("sskr", "split", "-t", "2", "-g", "2-of-3", "-g", "3-of-5",
               ge.toUr(alice)).split(/\s+/);
  assert.strictEqual(cs.length, 8);
  assert.strictEqual(ge.toUr(gc.joinEnvelope([cs[1], cs[2], cs[3], cs[5],
    cs[7]].map(function (x) {
    return ge.read(x);
  }))), ge.toUr(alice), "we join the CLI's");
  assert.deepStrictEqual(gc.describeShares(ge.read(cs[4])).map(function (d) {
    return [d.group, d.groups, d.groupThreshold, d.member,
            d.memberThreshold];
  }), [[2, 2, 2, 2, 3]], "a CLI share describes itself");
  // ML-DSA.
  ["mldsa44", "mldsa65", "mldsa87"].forEach(function (scheme) {
    var kp = ge.mldsaKeyPair(scheme);
    run("verify", "--verifier", ge.publicKeyUr(ge.publicKeyOf(kp)),
        ge.toUr(ge.sign(alice, kp)));
    var keys = { signing: kp, encapsulation: gc.x25519FromSeed(seed) };
    var their = run("sign", "--signer", gc.privateKeysUr(keys),
                    ge.toUr(wrapped));
    assert.ok(ge.verifySignatures(ge.read(their), ge.publicKeyOf(kp)).valid,
              scheme + ": we verify what the CLI signs with our key");
    var pair = run("generate", "keypairs", "--signing", scheme).split(/\s+/);
    assert.ok(ge.verifySignatures(ge.read(run("sign", "--signer", pair[0],
      ge.toUr(wrapped))), ge.readPublicKey(pair[1])).valid, scheme +
      ": and with its own");
  });
  // SSH.
  var sshSeed = new Uint8Array(16).fill(9);
  var sshBase = ge.urEncode("crypto-prvkey-base", ge.encode(sshSeed));
  ["ssh-ed25519", "ssh-ecdsa-p256", "ssh-ecdsa-p384"].forEach(function (a) {
    var sprv = run("generate", "prvkeys", "--signing", a, sshBase);
    var spub = run("generate", "pubkeys", sprv);
    var verifier = gc.readPublicKeys(spub).signing;
    var theirSigned = run("sign", "--signer", sprv, ge.toUr(wrapped));
    assert.ok(ge.verifySignatures(ge.read(theirSigned), verifier).valid,
              a + ": we verify the CLI's SSHSIG");
    var ourSigned = ge.sign(alice, gc.readPrivateKeys(sprv).signing);
    run("verify", "--verifier", spub, ge.toUr(ourSigned));
    if (a === "ssh-ed25519") {
      var derived = ge.sshEd25519FromSeed(sshSeed);
      assert.strictEqual(hex(derived.publicKey), hex(verifier.publicKey),
                         "the Ed25519 SSH key from the seed is the CLI's");
      assert.strictEqual(ge.toUr(ge.addSignature(wrapped, derived)),
                         theirSigned, "and its SSHSIG is byte for byte");
    }
  });
  log.info("PASS bc-envelope-cli 0.35.0, both ways: symmetric encryption " +
           "(seven shapes), compression, X25519 and ML-KEM-512/768/1024 " +
           "recipients (seed derivation identical), PBKDF2/scrypt/Argon2id " +
           "password locks, SSKR split and join, ML-DSA-44/65/87, and SSH " +
           "Ed25519 (byte for byte) and ECDSA P-256/P-384 signatures.");
  log.debug("Leaving obscuringAgainstTheCli().");
}

function main() {
  log.debug("Entering main().");
  dcbor();
  digestTree();
  keysAndSignatures();
  urAndRefusals(certificate());
  obscuringVectors();
  sskrVectors();
  multipartVectors();
  againstTheCli();
  obscuringAgainstTheCli();
  log.info("gordian_envelope_engine: all checks passed.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
}
