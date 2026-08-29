// File: hbs_signatures.js
//
// ---------------------------------------------------------------------------
// STATEFUL HASH-BASED SIGNATURES — LMS/HSS (RFC 8554, RFC 9858) and
// XMSS/XMSS^MT (RFC 8391, SP 800-208) — driven in NODE with no browser,
// because client/src/hbs.js has no DOM.
//
// WHY THIS FILE MATTERS MORE THAN MOST. Every other signature scheme in this
// application is somebody else's implementation with a thin layer over it:
// ML-DSA, SLH-DSA and the elliptic curves are @noble's, RSA is node-forge's.
// There is no LMS or XMSS in this dependency tree — none in @noble, none in
// Web Crypto, none in node — so `hbs.js` is an implementation of two
// specifications written from the specifications, and that is a completely
// different risk. Hash-based signatures are simple enough to write in an
// afternoon and unforgiving enough that every interesting mistake produces a
// scheme that signs and verifies against ITSELF perfectly and interoperates
// with nothing:
//
//   * a domain separator dropped (D_PBLC, D_MESG, D_LEAF, D_INTR)
//   * the WOTS+ chain address written into the word the LEAF index lives in
//     (words 4, 5 and 6 of an OTS address are the leaf, the chain and the
//     step — this one was real, and it cost every XMSS key generated here
//     until the reference vectors said so)
//   * SP 800-208's FOUR-byte function padding for the 192-bit parameter sets,
//     where RFC 8391's own sets pad to n
//   * an authentication path applied left-for-right
//   * the Winternitz checksum left unshifted by ls, which makes it always
//     zero in the digits that are actually signed
//
// Not one of those is visible from a round trip. So the vectors are the whole
// point of this job, and every one of them comes from OUTSIDE this tree:
//
//   * RFC 8554 Appendix F's two HSS test cases and RFC 9858 Appendix A's
//     three, which between them cover W4 and W8, H5 and H10, L = 1 and L = 2,
//     and all four LMS hash functions including both truncations.
//   * cisco/hash-sigs's LM-OTS vectors, which give I, q and SEED, so they
//     exercise RFC 8554 Appendix A key generation directly rather than only
//     verification.
//   * ONE VERIFICATION VECTOR FOR EVERY ONE OF THE 21 XMSS PARAMETER SETS in
//     the IANA registry, produced by Botan.
//   * The XMSS REFERENCE IMPLEMENTATION's own key generation and XMSS^MT
//     vectors. Nothing publishes an XMSS^MT test vector — Botan does not
//     implement it and that repository ships no KAT files — so these are
//     generated from it deterministically, and they are the only thing that
//     can pin SP 800-208 section 6.2's PRF_keygen and the 192-bit padding
//     rule, because both are invisible to a verifier.
//   * Signatures that MUST NOT verify, from both invalid-signature files.
//
// and then the properties no vector can express: that the parameter tables
// this module COMPUTES agree with the ones the RFCs print, that the two IANA
// registries are reproduced exactly, that a spent index cannot be spent
// twice, that an exhausted key refuses, and that key generation refuses a
// parameter set it cannot finish rather than hanging a browser tab.
//
// AND THAT ALL OF THAT IS NOT VACUOUS. everyRuleIsLoadBearing() breaks the
// module seven ways on purpose and requires the vector each mutation is
// aimed at to notice — because every check here is of the form "this vector
// reproduces", and none of them says that any PARTICULAR line is carrying
// weight. Two of the seven earned their place on the first run: see the
// comment above that section.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it
// has not been told about. This job parses no arguments at all — it drives a
// module in process — so node ignores the pair. Do not add commander here
// without also declaring `--url`; see tests/CLAUDE.md.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'hbs_signatures',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The module under test is read from the client TREE rather than from a flat
// copy beside this script — `COPY client/src /usr/src/client/src` in
// tests/Dockerfile puts it there — through module_paths.js, so that its own
// `require("@noble/hashes/sha256")` resolves against tests/node_modules.
const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");
const hbs = paths.requireSharedModule([path.join(SRC, "hbs.js")],
                                      "client/src/hbs.js");

const VECTORS = JSON.parse(
    fs.readFileSync(path.join(__dirname, "hbs_vectors.json"), "utf8"));

function b64(text) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(text || "", "base64");
}

function hex(bytes) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(bytes).toString("hex");
}

// ===========================================================================
// 1. The parameter tables, against the ones the documents print.
//
// `p` and `ls` are computed by RFC 8554 Appendix B rather than transcribed,
// so the computation is what has to be checked — a wrong `p` is a signature
// of the wrong length, and a wrong `ls` is a checksum that contributes
// nothing while every round trip still passes.
// ===========================================================================
const RFC8554_TABLE_1 = {
  "LMOTS_SHA256_N32_W1": { p: 265, ls: 7, sigLen: 8516 },
  "LMOTS_SHA256_N32_W2": { p: 133, ls: 6, sigLen: 4292 },
  "LMOTS_SHA256_N32_W4": { p: 67, ls: 4, sigLen: 2180 },
  "LMOTS_SHA256_N32_W8": { p: 34, ls: 0, sigLen: 1124 }
};

// RFC 9858 Table 1.
const RFC9858_TABLE_1 = {
  "LMOTS_SHA256_N24_W1": { p: 200, ls: 8 },
  "LMOTS_SHA256_N24_W2": { p: 101, ls: 6 },
  "LMOTS_SHA256_N24_W4": { p: 51, ls: 4 },
  "LMOTS_SHA256_N24_W8": { p: 26, ls: 0 },
  "LMOTS_SHAKE_N32_W1": { p: 265, ls: 7 },
  "LMOTS_SHAKE_N32_W2": { p: 133, ls: 6 },
  "LMOTS_SHAKE_N32_W4": { p: 67, ls: 4 },
  "LMOTS_SHAKE_N32_W8": { p: 34, ls: 0 },
  "LMOTS_SHAKE_N24_W1": { p: 200, ls: 8 },
  "LMOTS_SHAKE_N24_W2": { p: 101, ls: 6 },
  "LMOTS_SHAKE_N24_W4": { p: 51, ls: 4 },
  "LMOTS_SHAKE_N24_W8": { p: 26, ls: 0 }
};

// RFC 8391 Tables 1 and 2 — len is len_1 + len_2 and is likewise computed.
const RFC8391_LEN = { 32: 67, 64: 131, 24: 51 };

function parameterTablesMatchTheDocuments() {
  log.debug("Entering parameterTablesMatchTheDocuments().");
  var checked = 0;
  var published = Object.assign({}, RFC8554_TABLE_1, RFC9858_TABLE_1);
  for (var i = 0; i < hbs.LMOTS.length; i++) {
    var set = hbs.LMOTS[i];
    var row = published[set.name];
    assert.ok(row, "hbs.js has an LM-OTS set the documents do not: " +
              set.name + ".");
    assert.strictEqual(set.p, row.p,
        set.name + " has p = " + set.p + "; the table says " + row.p + ".");
    assert.strictEqual(set.ls, row.ls,
        set.name + " has ls = " + set.ls + "; the table says " + row.ls +
        ".");
    if (row.sigLen) {
      assert.strictEqual(set.sigLen, row.sigLen,
          set.name + " signatures are " + set.sigLen + " bytes; RFC 8554 " +
          "Table 1 says " + row.sigLen + ".");
    }
    checked++;
  }
  assert.strictEqual(checked, 16,
      "There are 16 LM-OTS parameter sets in the IANA registry; this build " +
      "has " + checked + ".");
  for (var j = 0; j < hbs.XMSS.length; j++) {
    var x = hbs.XMSS[j];
    assert.strictEqual(hbs.wotsLen(x).len, RFC8391_LEN[x.n],
        x.name + " computes len = " + hbs.wotsLen(x).len + "; RFC 8391 " +
        "Table 2 says " + RFC8391_LEN[x.n] + " for n = " + x.n + ".");
  }
  log.info("OK — every computed p, ls, sigLen and len matches the table " +
           "printed in RFC 8554, RFC 9858 or RFC 8391.");
  log.debug("Leaving parameterTablesMatchTheDocuments().");
}

// The two registries, reproduced. An identifier is what appears ON THE WIRE,
// so a wrong one is not a naming mistake — it is a public key nobody else can
// read, and a signature this tool would reject.
const IANA_LMS_IDS = {
  1: "LMOTS_SHA256_N32_W1", 4: "LMOTS_SHA256_N32_W8",
  5: "LMOTS_SHA256_N24_W1", 8: "LMOTS_SHA256_N24_W8",
  9: "LMOTS_SHAKE_N32_W1", 12: "LMOTS_SHAKE_N32_W8",
  13: "LMOTS_SHAKE_N24_W1", 16: "LMOTS_SHAKE_N24_W8"
};
const IANA_LMS_SIG_IDS = {
  5: "LMS_SHA256_M32_H5", 9: "LMS_SHA256_M32_H25",
  10: "LMS_SHA256_M24_H5", 14: "LMS_SHA256_M24_H25",
  15: "LMS_SHAKE_M32_H5", 19: "LMS_SHAKE_M32_H25",
  20: "LMS_SHAKE_M24_H5", 24: "LMS_SHAKE_M24_H25"
};
const IANA_XMSS_IDS = {
  1: "XMSS-SHA2_10_256", 3: "XMSS-SHA2_20_256", 4: "XMSS-SHA2_10_512",
  7: "XMSS-SHAKE_10_256", 12: "XMSS-SHAKE_20_512", 13: "XMSS-SHA2_10_192",
  15: "XMSS-SHA2_20_192", 16: "XMSS-SHAKE256_10_256",
  18: "XMSS-SHAKE256_20_256", 19: "XMSS-SHAKE256_10_192",
  21: "XMSS-SHAKE256_20_192"
};
const IANA_XMSSMT_IDS = {
  1: "XMSSMT-SHA2_20/2_256", 8: "XMSSMT-SHA2_60/12_256",
  9: "XMSSMT-SHA2_20/2_512", 16: "XMSSMT-SHA2_60/12_512",
  17: "XMSSMT-SHAKE_20/2_256", 24: "XMSSMT-SHAKE_60/12_256",
  25: "XMSSMT-SHAKE_20/2_512", 32: "XMSSMT-SHAKE_60/12_512",
  33: "XMSSMT-SHA2_20/2_192", 40: "XMSSMT-SHA2_60/12_192",
  41: "XMSSMT-SHAKE256_20/2_256", 48: "XMSSMT-SHAKE256_60/12_256",
  49: "XMSSMT-SHAKE256_20/2_192", 56: "XMSSMT-SHAKE256_60/12_192"
};

function registriesAreReproducedExactly() {
  log.debug("Entering registriesAreReproducedExactly().");
  function check(list, expected, what) {
    log.debug("Entering check(). what=" + what);
    var byId = {};
    for (var i = 0; i < list.length; i++) {
      assert.ok(!byId[list[i].id],
          what + " assigns identifier " + list[i].id + " twice.");
      byId[list[i].id] = list[i].name;
    }
    for (var id in expected) {
      if (!expected.hasOwnProperty(id)) continue;
      assert.strictEqual(byId[id], expected[id],
          what + " identifier " + id + " is " + byId[id] + " here and " +
          expected[id] + " in the IANA registry.");
    }
    log.debug("Leaving check().");
  }
  check(hbs.LMOTS, IANA_LMS_IDS, "The LM-OTS registry");
  check(hbs.LMS, IANA_LMS_SIG_IDS, "The LMS registry");
  check(hbs.XMSS, IANA_XMSS_IDS, "The XMSS registry");
  check(hbs.XMSSMT, IANA_XMSSMT_IDS, "The XMSS^MT registry");
  assert.strictEqual(hbs.LMS.length, 20,
      "The IANA LMS registry has 20 parameter sets; this build has " +
      hbs.LMS.length + ".");
  assert.strictEqual(hbs.XMSS.length, 21,
      "The IANA XMSS registry has 21 parameter sets; this build has " +
      hbs.XMSS.length + ".");
  assert.strictEqual(hbs.XMSSMT.length, 56,
      "The IANA XMSS^MT registry has 56 parameter sets; this build has " +
      hbs.XMSSMT.length + ".");
  // The 192-bit sets and only they carry SP 800-208's four-byte padding.
  var all = hbs.XMSS.concat(hbs.XMSSMT);
  for (var k = 0; k < all.length; k++) {
    var expectedPad = all[k].n === 24 ? 4 : all[k].n;
    assert.strictEqual(all[k].padding, expectedPad,
        all[k].name + " pads its function separator to " + all[k].padding +
        " bytes; SP 800-208 says " + expectedPad + ".");
  }
  log.info("OK — all 16 LM-OTS, 20 LMS, 21 XMSS and 56 XMSS^MT parameter " +
           "sets carry the IANA registry's identifiers, and the 192-bit " +
           "sets alone pad to four bytes.");
  log.debug("Leaving registriesAreReproducedExactly().");
}

// ===========================================================================
// 2. LM-OTS key generation, against cisco/hash-sigs.
// ===========================================================================
function lmotsKeyGenerationMatchesAnotherImplementation() {
  log.debug("Entering lmotsKeyGenerationMatchesAnotherImplementation().");
  var cases = VECTORS.lmotsKeygen;
  assert.ok(cases.length >= 4, "The LM-OTS vector set is empty.");
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var params = hbs.resolveLmots(c.type);
    var K = hbs.lmotsPublicKeyHash(params, b64(c.I), c.q, b64(c.seed));
    assert.strictEqual(hex(K), hex(b64(c.publicKey)),
        c.name + ": the LM-OTS public key computed from I, q and SEED does " +
        "not match the published one, so RFC 8554 Appendix A key " +
        "generation or Algorithm 1 is wrong.");
  }
  log.info("OK — " + cases.length + " LM-OTS public keys reproduce from I, " +
           "q and SEED.");
  log.debug("Leaving lmotsKeyGenerationMatchesAnotherImplementation().");
}

// ===========================================================================
// 3. The published HSS/LMS signatures.
// ===========================================================================
function publishedLmsSignaturesVerify() {
  log.debug("Entering publishedLmsSignaturesVerify().");
  var cases = VECTORS.lmsVerify;
  assert.ok(cases.length >= 5, "The LMS vector set is short.");
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var result = hbs.hssVerify(b64(c.publicKey), b64(c.message),
                               b64(c.signature));
    assert.ok(result.valid, c.name + " does not verify: " + result.reason);
    // ...and the same signature must fail against a message it did not sign,
    // which is what says the check is doing work at all.
    var flipped = Buffer.concat([b64(c.message), Buffer.from([0])]);
    var negative = hbs.hssVerify(b64(c.publicKey), flipped,
                                 b64(c.signature));
    assert.ok(!negative.valid,
        c.name + " verifies against a message it did not sign.");
  }
  log.info("OK — all " + cases.length + " published HSS/LMS test cases " +
           "verify, and none of them verifies the wrong message.");
  log.debug("Leaving publishedLmsSignaturesVerify().");
}

// ===========================================================================
// 4. Every XMSS parameter set, against another implementation's signatures.
// ===========================================================================
function everyXmssParameterSetVerifies() {
  log.debug("Entering everyXmssParameterSetVerifies().");
  var cases = VECTORS.xmssVerify;
  var seen = {};
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var result = hbs.xmssVerify(b64(c.publicKey), b64(c.message),
                                b64(c.signature), false);
    assert.ok(result.valid,
        c.params + " does not verify: " + result.reason);
    seen[c.params] = true;
  }
  for (var j = 0; j < hbs.XMSS.length; j++) {
    assert.ok(seen[hbs.XMSS[j].name],
        "There is no verification vector for " + hbs.XMSS[j].name +
        ", so this build offers a parameter set nothing has checked.");
  }
  log.info("OK — one third-party signature verifies under each of the " +
           cases.length + " XMSS parameter sets, with none missing.");
  log.debug("Leaving everyXmssParameterSetVerifies().");
}

// ===========================================================================
// 4b. XMSS^MT, against the reference implementation that accompanies RFC 8391.
//
// NOTHING PUBLISHES AN XMSS^MT TEST VECTOR. Botan does not implement the
// multi-tree variant, the reference implementation ships no KAT files, and
// RFC 8391's appendices are XDR formats rather than examples — so for a
// while this build's XMSS^MT was checked only by round trips, which is the
// state every comment in this tree warns about. These vectors close that:
// they are produced by the reference implementation itself, deterministically
// from a fixed seed, so they are reproducible by anybody who repeats the
// procedure in `_source` and in docs/hbs.md.
//
// What they cover that the single-tree vectors cannot is the multi-tree loop:
// splitting one index into a tree address and a leaf address at each layer,
// the layer address in ADRS, the ceil(h/8)-byte index field (three bytes at
// h = 20 and five at h = 40, where a parser that assumed four would be wrong
// in both directions), and the chaining of each tree's root into the layer
// above as the message the next WOTS+ key signs.
// ===========================================================================
function xmssMtMatchesTheReferenceImplementation() {
  log.debug("Entering xmssMtMatchesTheReferenceImplementation().");
  var keygen = VECTORS.xmssmtKeygen || [];
  var verify = VECTORS.xmssmtVerify || [];
  assert.ok(keygen.length >= 7,
      "The XMSS^MT key generation vectors are missing or short (" +
      keygen.length + "); every hash family this build offers needs one, " +
      "because these are the cheap ones and the flagged single-tree " +
      "vectors must not be the only cover for a rule.");
  assert.ok(verify.length >= 4,
      "The XMSS^MT verification vectors are missing or short.");

  var families = {};
  var paddings = {};
  for (var i = 0; i < keygen.length; i++) {
    var c = keygen[i];
    var params = hbs.resolveXmss(c.params);
    assert.ok(params.multiTree,
        c.params + " is in the XMSS^MT vector set and is not multi-tree.");
    var generated = hbs.xmssKeygen(c.params, {
      skSeed: b64(c.secretSeed), skPrf: b64(c.secretPrf),
      pubSeed: b64(c.publicSeed) });
    assert.strictEqual(hex(generated.publicKey), hex(b64(c.publicKey)),
        c.params + ": the public key generated from the reference " +
        "implementation's own seeds is not the one it produced. Only the " +
        "TOP tree is built for a key, so this is the layer d-1 path, " +
        "PRF_keygen and the padding length.");
    families[params.hash] = true;
    paddings[params.padding] = true;
  }
  // THE POINT OF THE CHEAP VECTORS: every hash function and every padding
  // length this build implements is checked at key generation on EVERY run,
  // rather than only when a flag is set. If this ever stops being true the
  // flagged vectors below have become load-bearing, and that is exactly the
  // arrangement tests/CLAUDE.md warns about.
  assert.strictEqual(Object.keys(families).length, 4,
      "The always-on key generation vectors cover " +
      Object.keys(families).join(", ") + "; all four of sha256, sha512, " +
      "shake128 and shake256 must be among them.");
  // Numerically, not as strings: Object.keys sorts "32" before "4".
  var padList = Object.keys(paddings).map(Number).sort(function (a, b) {
    return a - b;
  });
  assert.strictEqual(padList.join(","), "4,32,64",
      "The always-on key generation vectors cover padding lengths " +
      padList.join(", ") + "; SP 800-208 has three — 4 for the 192-bit " +
      "sets, and n itself (32 or 64) for the rest.");
  // Depth is deliberately NOT asserted here: key generation builds only the
  // top tree whatever d is, so d = 2 and d = 12 are the same code path. The
  // verification vectors below are where the hypertree depth is exercised,
  // and they assert it.

  var verifiedLayers = {};
  for (var j = 0; j < verify.length; j++) {
    var v = verify[j];
    var vp = hbs.resolveXmss(v.params);
    var result = hbs.xmssVerify(b64(v.publicKey), b64(v.message),
                                b64(v.signature), true);
    assert.ok(result.valid, v.params + " does not verify: " + result.reason);
    assert.strictEqual(result.layers, vp.d,
        v.params + " verified through " + result.layers + " layer(s) and " +
        "has d = " + vp.d + ".");
    // ...and the same signature must be refused for the wrong message, or
    // the check above is satisfied by a verifier that always agrees.
    var wrong = hbs.xmssVerify(b64(v.publicKey),
        Buffer.concat([b64(v.message), Buffer.from([0])]),
        b64(v.signature), true);
    assert.ok(!wrong.valid,
        v.params + " verified a message it did not sign.");
    verifiedLayers[vp.d] = true;
  }
  assert.ok(Object.keys(verifiedLayers).length >= 3,
      "The XMSS^MT verification vectors exercise only " +
      Object.keys(verifiedLayers).length + " distinct hypertree depths; the " +
      "index splitting is what these are for.");
  log.info("OK — " + keygen.length + " XMSS^MT keys and " + verify.length +
           " XMSS^MT signatures match the RFC 8391 reference " +
           "implementation, across " + Object.keys(families).length +
           " hash functions, " + Object.keys(paddings).length +
           " padding lengths and depths " +
           Object.keys(verifiedLayers).sort().join(", ") + ".");
  log.debug("Leaving xmssMtMatchesTheReferenceImplementation().");
}

// ===========================================================================
// 5. XMSS key generation, against the reference implementation.
//
// THIS IS THE ONLY CHECK THAT CAN SEE SP 800-208 SECTION 6.2. A verifier
// never touches PRF_keygen, so an implementation that derives its WOTS+
// private elements any other way produces keys that verify perfectly and are
// not the keys the seeds define — which matters the moment anybody restores a
// key from its seed with somebody else's tool.
//
// It is the slowest section here by a wide margin: each of these builds 1,024
// leaves, and the SHAKE parameter sets are three times the work of the SHA-2
// ones. That is the real cost of a hash-based key and it is the reason the
// page refuses h = 16.
// ===========================================================================
// THE FLAG BEHIND THESE NO LONGER GATES ANY RULE, and that is the point of
// the section above.
//
// A SINGLE-TREE key generation vector is 1,024 leaves — five seconds for
// SHA-2 and up to seventy-eight for SHAKE — and reproducing all seven took
// 168 seconds, which would have made this the second-longest job in the
// suite. It was also, for a while, the only cover for SP 800-208 section
// 6.2's PRF_keygen and the four-byte padding rule, so the flag WAS load
// bearing and this comment used to argue about which two to keep.
//
// It is not any more. The XMSS^MT vectors above generate keys from trees of
// 32 leaves, cover all four hash functions and all three padding lengths in
// about two seconds, and run on every job — and the section asserts that
// coverage rather than assuming it. What is left here is the SINGLE-TREE
// path at a real tree size, which is worth having and is worth five seconds
// rather than a hundred and sixty: XMSS-SHA2_10_256, the parameter set RFC
// 8391 section 5.1 makes mandatory, plus its 192-bit sibling. The remaining
// five re-test rules that are already covered, on a bigger tree, and
// `HBS_ALL_KEYGEN=1` runs them.
var ALWAYS_KEYGEN = ["XMSS-SHA2_10_256", "XMSS-SHA2_10_192"];

function xmssKeyGenerationMatchesTheReferenceImplementation() {
  log.debug("Entering xmssKeyGenerationMatchesTheReferenceImplementation().");
  var cases = VECTORS.xmssKeygen;
  var all = process.env.HBS_ALL_KEYGEN === "1";
  var ran = 0;
  var deferred = [];
  var families = {};
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var params = hbs.resolveXmss(c.params);
    if (!all && ALWAYS_KEYGEN.indexOf(c.params) < 0) {
      deferred.push(c.params);
      continue;
    }
    if (!hbs.canKeygen(hbs.xmssKeyCost(params))) {
      log.info("SKIPPED " + c.params + " — " +
               Math.round(hbs.xmssKeyCost(params) / 1000000) + " million " +
               "hash computations is past this build's own limit, which is " +
               "the property tested in refusesWhatItCannotFinish().");
      continue;
    }
    var started = Date.now();
    var generated = hbs.xmssKeygen(c.params, {
      skSeed: b64(c.secretSeed), skPrf: b64(c.secretPrf),
      pubSeed: b64(c.publicSeed) });
    assert.strictEqual(hex(generated.publicKey), hex(b64(c.publicKey)),
        c.params + ": the public key generated from the reference " +
        "implementation's own seeds is not the one it produced. The " +
        "likeliest causes are SP 800-208 section 6.2's PRF_keygen and the " +
        "function padding length.");
    families[params.hash + "/" + params.padding] = true;
    ran++;
    log.info(c.params + " key generation reproduces (" +
             (Date.now() - started) + "ms).");
  }
  assert.ok(ran >= 2,
      "Only " + ran + " key generation vectors ran; at least the two " +
      "padding rules must be covered.");
  var paddings = {};
  for (var key in families) {
    if (families.hasOwnProperty(key)) {
      paddings[key.split("/")[1]] = true;
    }
  }
  assert.ok(Object.keys(paddings).length >= 2,
      "The key generation vectors that ran cover only " +
      Object.keys(paddings).length + " padding length(s); SP 800-208's " +
      "four-byte rule for the 192-bit sets is the one a name never reveals.");
  if (deferred.length) {
    log.info("Deferred " + deferred.length + " single-tree key generation " +
             "vector(s): " + deferred.join(", ") + ". They take about 160 " +
             "seconds between them and gate NO rule — every hash function " +
             "and every padding length is checked on this run by the " +
             "XMSS^MT vectors, which the section above asserts. " +
             "HBS_ALL_KEYGEN=1 runs them on a full-size tree as well.");
  }
  log.info("OK — " + ran + " XMSS public key(s) reproduce byte for byte " +
           "from the reference implementation's seeds, across " +
           Object.keys(paddings).length + " padding rule(s).");
  log.debug("Leaving xmssKeyGenerationMatchesTheReferenceImplementation().");
}

// ===========================================================================
// 6. Signatures that must NOT verify.
//
// Every check above is a positive, and a verifier that returns true
// unconditionally passes all of them. These are the other half: mutations
// another implementation made on purpose — a swapped byte in the
// authentication path, a swapped byte in the one-time signature, a truncated
// signature, a prefixed one — each of which must be refused.
// ===========================================================================
function forgeriesAreRefused() {
  log.debug("Entering forgeriesAreRefused().");
  var refused = 0;
  var xmss = VECTORS.xmssNegative || [];
  for (var i = 0; i < xmss.length; i++) {
    var c = xmss[i];
    var result;
    try {
      result = hbs.xmssVerify(b64(c.publicKey), b64(c.message),
                              b64(c.signature), false);
    } catch (e) {
      // A length or index rule refusing the signature outright is a refusal
      // and counts; what must never happen is `valid: true`.
      result = { valid: false, reason: e.message };
    }
    assert.ok(!result.valid,
        "An XMSS signature mutated on purpose (" + c.why + ") verified.");
    refused++;
  }
  var lms = VECTORS.lmsNegative || [];
  for (var j = 0; j < lms.length; j++) {
    var l = lms[j];
    var out;
    try {
      out = hbs.hssVerify(b64(l.publicKey), b64(l.message),
                          b64(l.signature));
    } catch (e2) {
      out = { valid: false, reason: e2.message };
    }
    assert.ok(!out.valid,
        "An HSS signature that must be refused (" + l.why + ") verified.");
    refused++;
  }
  assert.ok(refused >= 6,
      "Only " + refused + " negative vectors ran; the positives above are " +
      "satisfied by a verifier that always returns true.");
  log.info("OK — " + refused + " deliberately invalid signatures were all " +
           "refused.");
  log.debug("Leaving forgeriesAreRefused().");
}

// And the mutations this file makes itself, on a signature this build just
// produced — because the vendored negatives are all XMSS-SHA2_10_256 and
// HSS/SHA-256, and a scheme can be right there and wrong elsewhere.
function everyByteOfASignatureMatters() {
  log.debug("Entering everyByteOfASignatureMatters().");
  var message = Buffer.from("stateful hash-based signatures", "utf8");
  var pair = hbs.hssKeygen({ levels: [
      { lms: "LMS_SHA256_M32_H5", lmots: "LMOTS_SHA256_N32_W8" }] });
  var signed = hbs.hssSign(pair.privateKey, message);
  assert.ok(hbs.hssVerify(pair.publicKey, message, signed.signature).valid,
      "A signature this build just made does not verify under its own key.");
  // One flipped bit in each region of the signature: the leaf index, the
  // randomizer C, a Winternitz chain, and the authentication path.
  var regions = { "leaf index q": 2, "LM-OTS typecode": 6,
                  "randomizer C": 12, "a Winternitz chain": 400,
                  "the authentication path": signed.signature.length - 20 };
  for (var where in regions) {
    if (!regions.hasOwnProperty(where)) continue;
    var mutated = Buffer.from(signed.signature);
    mutated[regions[where]] ^= 0x01;
    var result;
    try {
      result = hbs.hssVerify(pair.publicKey, message, mutated);
    } catch (e) {
      result = { valid: false };
    }
    assert.ok(!result.valid,
        "Flipping one bit in " + where + " left the signature valid.");
  }
  var other = hbs.hssKeygen({ levels: [
      { lms: "LMS_SHA256_M32_H5", lmots: "LMOTS_SHA256_N32_W8" }] });
  assert.ok(!hbs.hssVerify(other.publicKey, message, signed.signature).valid,
      "A signature verified under a DIFFERENT key pair's public key.");
  log.info("OK — a bit flipped anywhere in a signature, and a signature " +
           "offered under another key, are both refused.");
  log.debug("Leaving everyByteOfASignatureMatters().");
}

// ===========================================================================
// 7. Round trips across the shapes, including the multi-tree variants.
//
// Verification is pinned by the vectors above, so signing is checked against
// a verifier that is known to be right rather than against itself — which is
// the strongest statement available for an operation nobody publishes
// reproducible vectors for (both specifications leave the private key format
// and the randomizer to the implementation).
// ===========================================================================
function signingRoundTripsUnderAVerifiedVerifier() {
  log.debug("Entering signingRoundTripsUnderAVerifiedVerifier().");
  var message = Buffer.from("firmware image v2.1", "utf8");
  var hssShapes = [
    { label: "L=1 SHA-256 W8", levels: [
        { lms: "LMS_SHA256_M32_H5", lmots: "LMOTS_SHA256_N32_W8" }] },
    { label: "L=2 SHA-256/192 W4", levels: [
        { lms: "LMS_SHA256_M24_H5", lmots: "LMOTS_SHA256_N24_W4" },
        { lms: "LMS_SHA256_M24_H5", lmots: "LMOTS_SHA256_N24_W4" }] },
    { label: "L=2 SHAKE256/256 W2", levels: [
        { lms: "LMS_SHAKE_M32_H5", lmots: "LMOTS_SHAKE_N32_W2" },
        { lms: "LMS_SHAKE_M32_H5", lmots: "LMOTS_SHAKE_N32_W2" }] },
    { label: "L=3 SHAKE256/192 W1", levels: [
        { lms: "LMS_SHAKE_M24_H5", lmots: "LMOTS_SHAKE_N24_W1" },
        { lms: "LMS_SHAKE_M24_H5", lmots: "LMOTS_SHAKE_N24_W1" },
        { lms: "LMS_SHAKE_M24_H5", lmots: "LMOTS_SHAKE_N24_W1" }] }
  ];
  for (var i = 0; i < hssShapes.length; i++) {
    var pair = hbs.hssKeygen(hssShapes[i]);
    var signed = hbs.hssSign(pair.privateKey, message);
    var result = hbs.hssVerify(pair.publicKey, message, signed.signature);
    assert.ok(result.valid, hssShapes[i].label + " does not round-trip: " +
              result.reason);
    assert.strictEqual(result.levels, hssShapes[i].levels.length,
        hssShapes[i].label + " verified as " + result.levels + " levels.");
  }

  var xmssShapes = ["XMSS-SHA2_10_192", "XMSSMT-SHA2_20/4_256",
                    "XMSSMT-SHAKE256_40/8_192", "XMSSMT-SHA2_60/12_256"];
  for (var j = 0; j < xmssShapes.length; j++) {
    var params = hbs.resolveXmss(xmssShapes[j]);
    var generated = hbs.xmssKeygen(xmssShapes[j]);
    var sig = hbs.xmssSign(generated.privateKey, message);
    var verdict = hbs.xmssVerify(generated.publicKey, message, sig.signature,
                                 params.multiTree);
    assert.ok(verdict.valid, xmssShapes[j] + " does not round-trip: " +
              verdict.reason);
    assert.strictEqual(verdict.layers, params.d,
        xmssShapes[j] + " verified through " + verdict.layers +
        " layer(s) and has d = " + params.d + ".");
    // The signature length is a published function of the parameters, and
    // getting it wrong is how an implementation ends up with an
    // authentication path of the wrong depth that still verifies against
    // itself.
    var expected = (params.multiTree ? Math.ceil(params.h / 8) : 4) +
        params.n + params.d *
        (params.h / params.d + hbs.wotsLen(params).len) * params.n;
    assert.strictEqual(sig.signature.length, expected,
        xmssShapes[j] + " signatures are " + sig.signature.length +
        " bytes; RFC 8391 section 4.2.3 says " + expected + ".");
  }
  log.info("OK — " + (hssShapes.length + xmssShapes.length) + " key shapes " +
           "sign and verify, including a 2^60-signature hypertree.");
  log.debug("Leaving signingRoundTripsUnderAVerifiedVerifier().");
}

// ===========================================================================
// 8. THE STATE — the whole reason SP 800-208 exists, and the only property
// on this page that a signature scheme has and the others do not.
// ===========================================================================
function theIndexAdvancesAndTheKeyRunsOut() {
  log.debug("Entering theIndexAdvancesAndTheKeyRunsOut().");
  var message = Buffer.from("one", "utf8");
  // XMSS: the smallest tree this can generate is 2^10, which is too many
  // signatures to exhaust in a test — so exhaustion is checked on HSS, whose
  // H5 tree is 32, and advancement is checked on both.
  var xmss = hbs.xmssKeygen("XMSSMT-SHA2_20/4_256");
  var first = hbs.xmssSign(xmss.privateKey, message);
  var second = hbs.xmssSign(first.privateKey, message);
  assert.strictEqual(first.idx, 0, "The first XMSS signature used index " +
      first.idx + " rather than 0.");
  assert.strictEqual(second.idx, 1,
      "The second XMSS signature used index " + second.idx +
      "; the index must advance or the one-time key is reused.");
  assert.notStrictEqual(hex(first.signature), hex(second.signature),
      "Two signatures of the SAME message came out identical, so the index " +
      "did not reach the signature.");
  // Signing with the ORIGINAL key blob again re-spends index 0: the state
  // lives in the key the caller stored, which is exactly the operational
  // hazard, and this build makes it visible rather than preventing it.
  var replayed = hbs.xmssSign(xmss.privateKey, message);
  assert.strictEqual(replayed.idx, 0,
      "Signing again with the un-updated key blob did not re-spend index 0, " +
      "so this build is hiding the property SP 800-208 is about.");
  var left = hbs.remaining(second.privateKey);
  assert.strictEqual(left.used, 2,
      "After two signatures the key reports " + left.used + " used.");
  assert.strictEqual(left.total, Math.pow(2, 20),
      "An h = 20 hypertree reports " + left.total + " total signatures.");

  // HSS, exhausted for real: 32 leaves at the bottom of a one-level key.
  // W1 rather than W8, and it matters to the clock rather than to the check:
  // this signs 32 times and each signature rebuilds the tree, so the
  // Winternitz width is the difference between 8,500 hash computations per
  // tree and 277,000. What is being proved is about the INDEX, and the index
  // does not know what w is.
  var hss = hbs.hssKeygen({ levels: [
      { lms: "LMS_SHA256_M32_H5", lmots: "LMOTS_SHA256_N32_W1" }] });
  var key = hss.privateKey;
  var used = [];
  for (var i = 0; i < 32; i++) {
    var out = hbs.hssSign(key, message);
    assert.ok(hbs.hssVerify(hss.publicKey, message, out.signature).valid,
        "Signature " + i + " of an H5 key does not verify.");
    used.push(out.q);
    key = out.privateKey;
  }
  for (var j = 0; j < 32; j++) {
    assert.strictEqual(used[j], j,
        "The " + j + "th signature used leaf " + used[j] + ".");
  }
  var threw = null;
  try {
    hbs.hssSign(key, message);
  } catch (e) {
    threw = e.message;
  }
  assert.ok(threw && /exhausted/i.test(threw),
      "A key with all 32 leaves spent signed a 33rd message" +
      (threw ? " (refused with: " + threw + ")" : "") + ".");
  log.info("OK — the index advances, the state lives in the stored key, and " +
           "an exhausted key refuses to sign rather than wrapping around.");
  log.debug("Leaving theIndexAdvancesAndTheKeyRunsOut().");
}

// The failure mode itself. Both signatures verify — that is the point, and
// it is why the rule is about the SIGNER's storage rather than about
// anything a verifier could check.
function reuseIsUndetectableToAVerifier() {
  log.debug("Entering reuseIsUndetectableToAVerifier().");
  var pair = hbs.hssKeygen({ levels: [
      { lms: "LMS_SHA256_M32_H5", lmots: "LMOTS_SHA256_N32_W8" }] });
  var a = Buffer.from("transfer 10 units", "utf8");
  var b = Buffer.from("transfer 10000 units", "utf8");
  var both = hbs.signTwiceFromOneIndex("hss", pair.privateKey, a, b);
  assert.strictEqual(both.index, 0,
      "The reuse demonstration did not use one index twice.");
  assert.ok(hbs.hssVerify(pair.publicKey, a, both.first).valid,
      "The first of the two reused-index signatures does not verify.");
  assert.ok(hbs.hssVerify(pair.publicKey, b, both.second).valid,
      "The second of the two reused-index signatures does not verify — " +
      "which would make the demonstration a lie: the danger is precisely " +
      "that BOTH are accepted.");
  assert.notStrictEqual(hex(both.first), hex(both.second),
      "The two signatures are identical, so nothing was demonstrated.");
  log.info("OK — two different messages signed from one index both verify, " +
           "which is the failure SP 800-208 section 1 exists to prevent.");
  log.debug("Leaving reuseIsUndetectableToAVerifier().");
}

// ===========================================================================
// 9. Refusals: what this build will not attempt, and what it will not read.
// ===========================================================================
function refusesWhatItCannotFinish() {
  log.debug("Entering refusesWhatItCannotFinish().");
  var threw = null;
  try {
    hbs.xmssKeygen("XMSS-SHA2_16_256");
  } catch (e) {
    threw = e.message;
  }
  assert.ok(threw && /million hash/.test(threw),
      "Generating an h = 16 XMSS key was attempted rather than refused with " +
      "the number of hash computations it would take.");
  var lmsThrew = null;
  try {
    hbs.hssKeygen({ levels: [
        { lms: "LMS_SHA256_M32_H20", lmots: "LMOTS_SHA256_N32_W8" }] });
  } catch (e2) {
    lmsThrew = e2.message;
  }
  assert.ok(lmsThrew && /million hash/.test(lmsThrew),
      "Generating an H20 LMS key was attempted rather than refused.");
  // ...and the multi-tree parameter sets of the SAME total height are not
  // refused, which is the entire argument for their existence.
  var mt = hbs.resolveXmss("XMSSMT-SHA2_20/4_256");
  assert.ok(hbs.canKeygen(hbs.xmssKeyCost(mt)),
      "XMSSMT-SHA2_20/4_256 reaches 2^20 signatures with 32-leaf trees and " +
      "is refused, which would leave nothing on this page able to show why " +
      "the multi-tree variants exist.");
  log.info("OK — h = 16 and H20 single trees are refused by the number, " +
           "while a 2^20 hypertree of 32-leaf trees is not.");
  log.debug("Leaving refusesWhatItCannotFinish().");
}

function malformedInputIsNamedRatherThanGuessed() {
  log.debug("Entering malformedInputIsNamedRatherThanGuessed().");
  var cases = [
    { what: "an LMS public key with an unknown typecode",
      run: function () {
        hbs.parseLmsPublicKey(Buffer.from("ffffffff00000004" +
            "00".repeat(48), "hex"));
      }, expect: /Unknown LMS typecode/ },
    { what: "an LMS public key of the wrong length",
      run: function () {
        hbs.parseLmsPublicKey(Buffer.from("0000000500000004" +
            "00".repeat(20), "hex"));
      }, expect: /public key is 56 bytes/ },
    { what: "an HSS public key claiming nine levels",
      run: function () {
        hbs.parseHssPublicKey(Buffer.from("00000009" +
            "0000000500000004" + "00".repeat(48), "hex"));
      }, expect: /1 to 8/ },
    { what: "an XMSS public key with an unknown OID",
      run: function () {
        hbs.parseXmssPublicKey(Buffer.from("000000ff" + "00".repeat(64),
                                           "hex"), false);
      }, expect: /Unknown XMSS algorithm identifier/ },
    { what: "an XMSS parameter set given by number",
      run: function () { hbs.resolveXmss(1); },
      expect: /must be named/ },
    { what: "a private key blob that is not ours",
      run: function () {
        hbs.parseLmsPrivateKey(Buffer.from("00".repeat(64), "hex"));
      }, expect: /does not start with LMSK/ }
  ];
  for (var i = 0; i < cases.length; i++) {
    var message = null;
    try {
      cases[i].run();
    } catch (e) {
      message = e.message;
    }
    assert.ok(message, cases[i].what + " was accepted.");
    assert.ok(cases[i].expect.test(message),
        cases[i].what + " was refused with \"" + message +
        "\", which does not name the problem.");
  }
  log.info("OK — " + cases.length + " malformed inputs are each refused by " +
           "a sentence naming the field.");
  log.debug("Leaving malformedInputIsNamedRatherThanGuessed().");
}

// ===========================================================================
// 9b. MUTATION TESTING — the section that says the sections above are not
// vacuous.
//
// Every check in this file is of the form "this vector reproduces". A
// verifier that returned true unconditionally would fail the negatives, but
// nothing so far proves that any PARTICULAR line of hbs.js is load bearing —
// and in a hash-based signature the lines that matter most are the ones whose
// removal produces a scheme that still round-trips. So this section breaks
// the module on purpose, one line at a time, and requires the named vector to
// notice.
//
// It loads a MUTATED COPY rather than monkey-patching: the copy goes to a
// temp directory with its one relative require rewritten to an absolute path,
// so nothing is ever written into client/src, where a leftover file would be
// swept up by the client-source checks in jwk_pem_encoding.js and could reach
// a bundle. Each mutation asserts its target text was PRESENT before
// substituting — a mutation that silently fails to apply would make the check
// it anchors pass for the wrong reason, which is the exact failure this
// section exists to rule out.
//
// The last case is the one worth reading: moving PRF_keygen's domain
// separator from 4 to 3 breaks key generation and leaves VERIFICATION
// working, because a verifier never touches it. That is why the reference
// implementation's key generation vectors had to be obtained at all.
// ===========================================================================
var MUTANTS = [
  {
    why: "SP 800-208's four-byte function padding for the 192-bit sets, " +
         "changed to n",
    from: "d: d, padding: n === 24 ? 4 : n,",
    to: "d: d, padding: n,",
    breaks: "xmssmtKeygen"
  },
  {
    why: "the WOTS+ HASH address written to ADRS word 5, the CHAIN address",
    from: "  for (var i = start; i < start + steps && i < params.w; i++) {\n" +
          "    adrs[6] = i;",
    to: "  for (var i = start; i < start + steps && i < params.w; i++) {\n" +
        "    adrs[5] = i;",
    breaks: "xmssVerify"
  },
  {
    why: "the WOTS+ CHAIN address written to ADRS word 4, where the LEAF " +
         "index lives — the defect this module actually shipped with",
    from: "  var out = new Array(sig.length);\n" +
          "  for (var i = 0; i < sig.length; i++) {\n" +
          "    adrs[5] = i;",
    to: "  var out = new Array(sig.length);\n" +
        "  for (var i = 0; i < sig.length; i++) {\n" +
        "    adrs[4] = i;",
    breaks: "xmssVerify"
  },
  {
    why: "LMS's D_LEAF domain separator replaced by D_INTR",
    from: "var D_LEAF = 0x8282;",
    to: "var D_LEAF = 0x8383;",
    breaks: "lmsVerify"
  },
  {
    // AIMED AT A SHIFTED PARAMETER SET ON PURPOSE. `ls` is 0 for every w = 8
    // set, so against RFC 8554's Test Case 1 this mutation is a no-op and
    // survives — which is what the first draft of this section did, and what
    // caught it. `lmsVerifyShifted` finds a vector whose LM-OTS set actually
    // has a shift, and fails if the vector set no longer contains one.
    why: "the LM-OTS checksum left unshifted by ls, which puts the checksum " +
         "in bits the signature never encodes",
    from: "  return u16str((sum << otsParams.ls) & 0xffff);",
    to: "  return u16str(sum & 0xffff);",
    breaks: "lmsVerifyShifted"
  },
  {
    why: "LM-OTS key generation's 0xff separator changed to 0xfe, which " +
         "collides with a Winternitz step at w = 8",
    from: "      [I, u32str(q), u16str(i), u8str(0xff), seed]);",
    to: "      [I, u32str(q), u16str(i), u8str(0xfe), seed]);",
    breaks: "lmotsKeygen"
  },
  {
    why: "SP 800-208 section 6.2's PRF_keygen separator changed from 4 to " +
         "PRF's own 3",
    from: "      padBytes(params, PAD_PRF_KEYGEN), key, inBytes));",
    to: "      padBytes(params, PAD_PRF), key, inBytes));",
    breaks: "xmssmtKeygen",
    stillVerifies: true
  }
];

function loadMutant(index, mutant) {
  log.debug("Entering loadMutant(). index=" + index);
  var source = fs.readFileSync(path.join(SRC, "hbs.js"), "utf8");
  assert.ok(source.indexOf(mutant.from) >= 0,
      "The mutation \"" + mutant.why + "\" no longer matches hbs.js. It " +
      "has to be re-aimed: a mutation that does not apply makes the check " +
      "it anchors pass for the wrong reason.");
  var mutated = source.replace(mutant.from, mutant.to);
  assert.notStrictEqual(mutated, source, "The mutation changed nothing.");
  // The one relative require, made absolute so the copy can live outside
  // client/src — see the note above about never writing into that directory.
  mutated = mutated.replace('require("./crypto_bytes")',
      JSON.stringify(path.join(SRC, "crypto_bytes.js")).replace(/^/, "require(")
          .replace(/$/, ")"));
  var file = path.join(os.tmpdir(),
      "hbs-mutant-" + process.pid + "-" + index + ".js");
  fs.writeFileSync(file, mutated);
  log.debug("Leaving loadMutant().");
  return { module: require(file), file: file };
}

// The first published LMS case whose LM-OTS parameter set has a NON-ZERO left
// shift. Every w = 8 set has ls = 0, so the checksum shift is invisible in
// four of the five published cases; this finds the one where it is not, and
// fails loudly rather than quietly aiming a mutation at nothing.
function shiftedLmsCase() {
  log.debug("Entering shiftedLmsCase().");
  for (var i = 0; i < VECTORS.lmsVerify.length; i++) {
    var pub = hbs.parseHssPublicKey(b64(VECTORS.lmsVerify[i].publicKey));
    if (pub.top.otsParams.ls > 0) {
      log.debug("Leaving shiftedLmsCase(). " + pub.top.otsParams.name);
      return VECTORS.lmsVerify[i];
    }
  }
  throw new Error("No published LMS vector uses an LM-OTS parameter set " +
                  "with ls > 0, so the checksum shift is exercised by " +
                  "nothing here.");
}

// Run one vector of the named kind through a module, and say whether it
// reproduced. Never throws: a mutant that crashes has still noticed.
function vectorHolds(module, kind) {
  log.debug("Entering vectorHolds(). kind=" + kind);
  try {
    if (kind === "lmsVerify" || kind === "lmsVerifyShifted") {
      var l = kind === "lmsVerify" ? VECTORS.lmsVerify[0] : shiftedLmsCase();
      log.debug("Leaving vectorHolds().");
      return module.hssVerify(b64(l.publicKey), b64(l.message),
                              b64(l.signature)).valid;
    }
    if (kind === "xmssVerify") {
      var x = VECTORS.xmssVerify[0];
      log.debug("Leaving vectorHolds().");
      return module.xmssVerify(b64(x.publicKey), b64(x.message),
                               b64(x.signature), false).valid;
    }
    if (kind === "lmotsKeygen") {
      var o = VECTORS.lmotsKeygen[0];
      var K = module.lmotsPublicKeyHash(module.resolveLmots(o.type),
                                        b64(o.I), o.q, b64(o.seed));
      log.debug("Leaving vectorHolds().");
      return hex(K) === hex(b64(o.publicKey));
    }
    // xmssmtKeygen — the cheapest key generation vector there is, 32 leaves.
    var k = VECTORS.xmssmtKeygen[4];
    var generated = module.xmssKeygen(k.params, {
      skSeed: b64(k.secretSeed), skPrf: b64(k.secretPrf),
      pubSeed: b64(k.publicSeed) });
    log.debug("Leaving vectorHolds().");
    return hex(generated.publicKey) === hex(b64(k.publicKey));
  } catch (e) {
    log.debug("Leaving vectorHolds(). Threw: " + e.message);
    return false;
  }
}

function everyRuleIsLoadBearing() {
  log.debug("Entering everyRuleIsLoadBearing().");
  // The unmutated module must reproduce each kind first, or "the mutant
  // fails" would mean nothing.
  var kinds = ["lmsVerify", "lmsVerifyShifted", "xmssVerify", "lmotsKeygen",
               "xmssmtKeygen"];
  for (var k = 0; k < kinds.length; k++) {
    assert.ok(vectorHolds(hbs, kinds[k]),
        "The UNMUTATED module does not reproduce the " + kinds[k] +
        " vector, so this section can prove nothing.");
  }
  for (var i = 0; i < MUTANTS.length; i++) {
    var mutant = MUTANTS[i];
    var loaded = loadMutant(i, mutant);
    try {
      assert.ok(!vectorHolds(loaded.module, mutant.breaks),
          "MUTATION SURVIVED: with " + mutant.why + ", the " +
          mutant.breaks + " vector still reproduces. That check is not " +
          "testing what it claims to.");
      if (mutant.stillVerifies) {
        assert.ok(vectorHolds(loaded.module, "xmssVerify"),
            "The PRF_keygen mutation broke verification too. It is in this " +
            "list precisely because it does NOT — which is the whole " +
            "argument for obtaining key generation vectors, and if that has " +
            "stopped being true the argument needs rewriting.");
      }
    } finally {
      delete require.cache[require.resolve(loaded.file)];
      fs.unlinkSync(loaded.file);
    }
  }
  log.info("OK — all " + MUTANTS.length + " mutations were caught by the " +
           "vector each is aimed at, and the PRF_keygen one broke key " +
           "generation while leaving verification working.");
  log.debug("Leaving everyRuleIsLoadBearing().");
}

// ===========================================================================
// 10. The division of labour, and the page.
// ===========================================================================
function theEngineReachesNoDom() {
  log.debug("Entering theEngineReachesNoDom().");
  var source = fs.readFileSync(path.join(SRC, "hbs.js"), "utf8");
  var code = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  var forbidden = ["document", "window", "localStorage", "crypto.subtle"];
  for (var i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/hbs.js reaches " + forbidden[i] + " — this whole job " +
        "exists because it does not.");
  }
  // The hot-path rule from the repo-root CLAUDE.md, enforced rather than
  // hoped for: a log line inside the Winternitz chain or the tree hash would
  // be tens of millions of records for one key, and at the debug level both
  // test stacks configure it would make the page unusable rather than slow.
  var hotPaths = ["function wotsChain", "function coef", "function lmotsHash",
                  "function thashF", "function thashH", "function prf",
                  "function cat"];
  for (var j = 0; j < hotPaths.length; j++) {
    var start = code.indexOf(hotPaths[j]);
    assert.ok(start > 0, "hbs.js no longer has " + hotPaths[j] + "().");
    var body = code.slice(start, code.indexOf("\n}", start));
    assert.ok(body.indexOf("log.debug") < 0,
        hotPaths[j] + "() logs. It is called millions of times per key " +
        "generation; see the hot-path exception in the repo-root CLAUDE.md.");
  }
  log.info("OK — the engine has no DOM, and none of the seven hot-path " +
           "functions logs.");
  log.debug("Leaving theEngineReachesNoDom().");
}

function thePageAndTheEngineAgree() {
  log.debug("Entering thePageAndTheEngineAgree().");
  var html = fs.readFileSync(path.join(PUBLIC, "digital_signature.html"),
                             "utf8");
  var bundle = fs.readFileSync(path.join(SRC, "digital_signature.js"),
                               "utf8");
  function optionsOf(selectId) {
    log.debug("Entering optionsOf(). selectId=" + selectId);
    var start = html.indexOf('id="' + selectId + '"');
    assert.ok(start > 0, "The page has no <select id=\"" + selectId + "\">.");
    var slice = html.slice(start, html.indexOf("</select>", start));
    var values = [];
    var re = /<option value="([^"]*)"/g;
    var m = re.exec(slice);
    while (m) {
      values.push(m[1]);
      m = re.exec(slice);
    }
    log.debug("Leaving optionsOf().");
    return values;
  }
  var lmots = optionsOf("ds_hbs_lmots");
  for (var i = 0; i < lmots.length; i++) {
    hbs.resolveLmots(lmots[i]);
  }
  assert.strictEqual(lmots.length, hbs.LMOTS.length,
      "The page offers " + lmots.length + " LM-OTS parameter sets and the " +
      "registry has " + hbs.LMOTS.length + ".");
  var lms = optionsOf("ds_hbs_lms");
  assert.strictEqual(lms.length, hbs.LMS.length,
      "The page offers " + lms.length + " LMS parameter sets and the " +
      "registry has " + hbs.LMS.length + ".");
  for (var j = 0; j < lms.length; j++) {
    hbs.resolveLms(lms[j]);
  }
  var xmss = optionsOf("ds_hbs_xmss");
  assert.strictEqual(xmss.length, hbs.XMSS.length + hbs.XMSSMT.length,
      "The page offers " + xmss.length + " XMSS parameter sets and the two " +
      "registries have " + (hbs.XMSS.length + hbs.XMSSMT.length) + ".");
  for (var k = 0; k < xmss.length; k++) {
    hbs.resolveXmss(xmss[k]);
  }
  var called = {};
  var re = /digital_signature\.(hbs[A-Za-z0-9_]*)\(/g;
  var m = re.exec(html);
  while (m) {
    called[m[1]] = true;
    m = re.exec(html);
  }
  assert.ok(Object.keys(called).length >= 4,
      "The page calls only " + Object.keys(called).length +
      " hbs* handlers; the pane needs at least generate, sign, validate and " +
      "describe.");
  var exported = bundle.slice(bundle.lastIndexOf("module.exports"));
  for (var name in called) {
    if (!called.hasOwnProperty(name)) continue;
    assert.ok(new RegExp("\\b" + name + "\\b").test(exported),
        "digital_signature.html calls digital_signature." + name +
        "() and the bundle does not export it — every click on that " +
        "control would be a ReferenceError.");
  }
  log.info("OK — the pane offers all " + lmots.length + " LM-OTS, " +
           lms.length + " LMS and " + xmss.length + " XMSS parameter sets, " +
           "and every handler it calls is exported.");
  log.debug("Leaving thePageAndTheEngineAgree().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  parameterTablesMatchTheDocuments();
  registriesAreReproducedExactly();
  lmotsKeyGenerationMatchesAnotherImplementation();
  publishedLmsSignaturesVerify();
  everyXmssParameterSetVerifies();
  xmssMtMatchesTheReferenceImplementation();
  forgeriesAreRefused();
  everyByteOfASignatureMatters();
  signingRoundTripsUnderAVerifiedVerifier();
  theIndexAdvancesAndTheKeyRunsOut();
  reuseIsUndetectableToAVerifier();
  refusesWhatItCannotFinish();
  malformedInputIsNamedRatherThanGuessed();
  everyRuleIsLoadBearing();
  xmssKeyGenerationMatchesTheReferenceImplementation();
  theEngineReachesNoDom();
  thePageAndTheEngineAgree();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
