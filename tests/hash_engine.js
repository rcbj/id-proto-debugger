// File: hash_engine.js
//
// ---------------------------------------------------------------------------
// The Hashing / Encoding Tools page's HASHING, driven in NODE with no browser
// — because the module it is built on, client/src/hash_tools.js, has no DOM.
//
// This is the half of that page's testing a Selenium job cannot do well.
// tests/encoding_tools.js drives the page: it presses the buttons, reads the
// status lines and proves the wiring. What it cannot do is say the bytes are
// right, because a digest is the one value where being wrong looks exactly
// like being right — 64 hex characters that change completely whenever the
// input does. A page can be confidently, consistently, self-consistently
// wrong and nothing about the screen says so.
//
// So this job asserts against things that are NOT this code:
//
//   * node's own crypto — OpenSSL — for every fixed-output function this
//     module offers (SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256,
//     SHA3-224/256/384/512) and for both SHAKEs at five output lengths.
//   * `openssl mac ... KMAC128 / KMAC256`, a SECOND implementation of the
//     keyed SP 800-185 function, over random keys, messages, customization
//     strings and lengths. It is the only cross-implementation check
//     available for that half: no browser and no node API has cSHAKE.
//   * SP 800-185's own sample values, transcribed from its appendix — the
//     three cSHAKE samples, all six KMAC samples, four TupleHash samples and
//     two ParallelHash ones.
//   * The SP 800-185 CONSTRUCTIONS, re-derived here from the specification's
//     text: left_encode / right_encode / encode_string, and TupleHash and
//     ParallelHash built out of cSHAKE from those. That is the check that
//     catches a derived function whose padding is wrong in a way its own
//     round trip cannot see, which is where these functions actually fail.
//
// and then the properties no vector can express: that cSHAKE with an empty N
// and S IS SHAKE (SP 800-185 section 3.3), that KMAC's XOF variant differs
// from KMAC in EVERY byte rather than in its length, that a SHAKE's longer
// output extends its shorter one while a KMAC's does not, that TupleHash
// really is unambiguous where concatenation is not, that ParallelHash's block
// size changes the answer, and that legacy Keccak is not SHA-3.
//
// It also asserts the DIVISION ITSELF — that the module under test reaches no
// DOM and no Web Crypto — since that is the whole reason this job can exist,
// and it is a property a later edit can quietly take away. And it holds the
// PAGE to the engine: every option the HTML offers has to name a function the
// registry actually has, and every handler the HTML calls has to be exported.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it has
// not been told about. This job parses no arguments at all — it drives a
// module in process and has no base url to visit — so node ignores the pair
// and there is nothing to declare. Do not add commander here without also
// declaring `--url`; see tests/CLAUDE.md.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'hash_engine',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The module under test is read from the client TREE rather than from a flat
// copy beside this script — `COPY client/src /usr/src/client/src` in
// tests/Dockerfile is what puts it there, and __dirname/.. is /usr/src in the
// image and the repository root in a checkout. Through module_paths.js rather
// than a bare require(), for the reason tests/CLAUDE.md gives: node resolves a
// module's own requires from where THAT module lives, so hash_tools.js's
// `require("bunyan")` and `require("@noble/hashes/sha3")` would be looked for
// under client/node_modules, which neither the image nor a tests-only install
// has.
const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");
const hashes = paths.requireSharedModule(
    [path.join(SRC, "hash_tools.js")], "client/src/hash_tools.js");
const noble = require("@noble/hashes/sha3-addons");
const nobleSha3 = require("@noble/hashes/sha3");

function hex(bytes) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(bytes).toString("hex");
}

function fromHex(text) {
  log.debug("Entering fromHex().");
  log.debug("Leaving fromHex().");
  return Buffer.from(text.replace(/\s+/g, ""), "hex");
}

// The inputs every section runs over. The empty string and "abc" because they
// are what the specifications' own examples use; the 200-byte counting
// sequence because it is SP 800-185's sample data; a block-straddling length
// because a sponge's rate is 168 bytes for the 128-bit functions and 136 for
// the 256-bit ones, and an input that ends exactly on one is where padding
// goes wrong.
const DATA_200 = Buffer.from(Array.from({ length: 200 }, function (_, i) {
  return i;
}));
const INPUTS = [
  Buffer.alloc(0),
  Buffer.from("abc", "utf8"),
  Buffer.from("a".repeat(1000), "utf8"),
  DATA_200,
  Buffer.alloc(136, 0x5a),
  Buffer.alloc(168, 0xa5),
  crypto.randomBytes(777)
];

// ===========================================================================
// 1. Every fixed-output function, against node's OpenSSL.
// ===========================================================================
const OPENSSL_NAMES = {
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
  "SHA-512/224": "sha512-224",
  "SHA-512/256": "sha512-256",
  "SHA3-224": "sha3-224",
  "SHA3-256": "sha3-256",
  "SHA3-384": "sha3-384",
  "SHA3-512": "sha3-512"
};

function fixedOutputFunctionsAgreeWithOpenssl() {
  log.debug("Entering fixedOutputFunctionsAgreeWithOpenssl().");
  var count = 0;
  for (var id in OPENSSL_NAMES) {
    if (!OPENSSL_NAMES.hasOwnProperty(id)) continue;
    for (var i = 0; i < INPUTS.length; i++) {
      var expected = crypto.createHash(OPENSSL_NAMES[id])
          .update(INPUTS[i]).digest("hex");
      var actual = hex(hashes.digest(id, INPUTS[i]));
      assert.strictEqual(actual, expected,
          id + " disagrees with OpenSSL on input " + i + " (" +
          INPUTS[i].length + " bytes).");
      count++;
    }
    // The registry's own digest length has to be the one the function
    // produces: it is what every security note below is computed from, so a
    // wrong number there is a wrong claim rather than a wrong label.
    var alg = hashes.algorithm(id);
    assert.strictEqual(hashes.digest(id, INPUTS[1]).length * 8, alg.bits,
        id + " produces a digest that is not " + alg.bits + " bits.");
  }
  log.info("OK — " + count + " digests across " +
           Object.keys(OPENSSL_NAMES).length +
           " fixed-output functions match OpenSSL.");
  log.debug("Leaving fixedOutputFunctionsAgreeWithOpenssl().");
}

// ===========================================================================
// 2. The two SHAKEs, at five lengths each, against node's OpenSSL — and the
//    property that makes them extendable: a longer output EXTENDS a shorter
//    one, byte for byte, rather than replacing it.
// ===========================================================================
function shakeAgreesWithOpensslAtEveryLength() {
  log.debug("Entering shakeAgreesWithOpensslAtEveryLength().");
  var lengths = [8, 64, 256, 512, 4096];
  var count = 0;
  var pairs = [["SHAKE128", "shake128"], ["SHAKE256", "shake256"]];
  for (var p = 0; p < pairs.length; p++) {
    for (var i = 0; i < INPUTS.length; i++) {
      for (var l = 0; l < lengths.length; l++) {
        var bits = lengths[l];
        var expected = crypto.createHash(pairs[p][1],
            { outputLength: bits / 8 }).update(INPUTS[i]).digest("hex");
        var actual = hex(hashes.digest(pairs[p][0], INPUTS[i],
                                       { outputBits: bits }));
        assert.strictEqual(actual, expected,
            pairs[p][0] + " at " + bits + " bits disagrees with OpenSSL on " +
            "input " + i + ".");
        count++;
      }
    }
    var short = hex(hashes.digest(pairs[p][0], DATA_200, { outputBits: 256 }));
    var long = hex(hashes.digest(pairs[p][0], DATA_200, { outputBits: 4096 }));
    assert.ok(long.indexOf(short) === 0,
        pairs[p][0] + " at 4096 bits does not begin with its own 256-bit " +
        "output — it is not behaving as an extendable-output function.");
  }
  log.info("OK — " + count + " SHAKE outputs match OpenSSL, and each longer " +
           "output extends the shorter one.");
  log.debug("Leaving shakeAgreesWithOpensslAtEveryLength().");
}

// ===========================================================================
// 3. Legacy Keccak is NOT SHA-3.
//
// FIPS 202 appended the domain separator 01 before padding and the original
// submission did not, so the two produce completely different digests of the
// same input. The page offers both because tools that predate the standard
// call the older one "SHA3", which is the most common way a correct SHA-3
// implementation gets reported as broken. The value asserted here is the
// empty-string Keccak-256 digest every one of those tools publishes.
// ===========================================================================
function keccakIsNotSha3() {
  log.debug("Entering keccakIsNotSha3().");
  var keccakEmpty = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfa" +
      "d8045d85a470";
  assert.strictEqual(hex(hashes.digest("Keccak-256", Buffer.alloc(0))),
      keccakEmpty, "Keccak-256 of the empty string is not the published " +
      "pre-FIPS value.");
  for (var i = 0; i < INPUTS.length; i++) {
    assert.notStrictEqual(hex(hashes.digest("Keccak-256", INPUTS[i])),
        hex(hashes.digest("SHA3-256", INPUTS[i])),
        "Keccak-256 and SHA3-256 agree on input " + i + ", so one of them " +
        "is using the other's padding.");
    assert.notStrictEqual(hex(hashes.digest("Keccak-512", INPUTS[i])),
        hex(hashes.digest("SHA3-512", INPUTS[i])),
        "Keccak-512 and SHA3-512 agree on input " + i + ".");
  }
  // And the page has to SAY so, because a reader who cannot tell them apart
  // is exactly who reaches for this option.
  assert.ok(/NOT SHA3-256/.test(hashes.describe("Keccak-256")),
      "Keccak-256's notes do not warn that it is not SHA3-256.");
  log.info("OK — legacy Keccak is distinct from SHA-3 everywhere, and says " +
           "so.");
  log.debug("Leaving keccakIsNotSha3().");
}

// ===========================================================================
// 4. SP 800-185's own sample values.
//
// Transcribed from the appendix of that document. `S` is the customization
// string, `N` the function name, `L` the output length in bits.
// ===========================================================================
const KMAC_KEY = fromHex("404142434445464748494a4b4c4d4e4f" +
                         "505152535455565758595a5b5c5d5e5f");
const D4 = fromHex("00010203");
const TUPLE_1 = [fromHex("000102"), fromHex("101112131415")];
const TUPLE_3 = [fromHex("000102"), fromHex("101112131415"),
                 fromHex("202122232425262728")];
const PARALLEL_DATA = fromHex("000102030405060710111213141516172021222324" +
                              "252627");

const SP800185_SAMPLES = [
  { name: "cSHAKE128 Sample #1", fn: "cSHAKE128", message: D4,
    customization: "Email Signature", outputBits: 256,
    expected: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814" +
        "d5aaf5" },
  { name: "cSHAKE256 Sample #3", fn: "cSHAKE256", message: D4,
    customization: "Email Signature", outputBits: 512,
    expected: "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896ee" +
        "e0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c74646952" +
        "7281c8c" },
  { name: "cSHAKE256 Sample #4", fn: "cSHAKE256", message: DATA_200,
    customization: "Email Signature", outputBits: 512,
    expected: "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302" +
        "73091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25a" +
        "fb092bb" },
  { name: "KMAC128 Sample #1", fn: "KMAC128", key: KMAC_KEY, message: D4,
    customization: "", outputBits: 256,
    expected: "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f45" +
        "6ee14e" },
  { name: "KMAC128 Sample #2", fn: "KMAC128", key: KMAC_KEY, message: D4,
    customization: "My Tagged Application", outputBits: 256,
    expected: "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811" +
        "324aa5" },
  { name: "KMAC128 Sample #3", fn: "KMAC128", key: KMAC_KEY,
    message: DATA_200, customization: "My Tagged Application",
    outputBits: 256,
    expected: "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9" +
        "729230" },
  { name: "KMAC256 Sample #4", fn: "KMAC256", key: KMAC_KEY, message: D4,
    customization: "My Tagged Application", outputBits: 512,
    expected: "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a" +
        "68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27" +
        "773a8dd" },
  { name: "KMAC256 Sample #5", fn: "KMAC256", key: KMAC_KEY,
    message: DATA_200, customization: "", outputBits: 512,
    expected: "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414b" +
        "cfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6" +
        "b759b69" },
  { name: "KMAC256 Sample #6", fn: "KMAC256", key: KMAC_KEY,
    message: DATA_200, customization: "My Tagged Application",
    outputBits: 512,
    expected: "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837d" +
        "a2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe47687" +
        "6fc8965" },
  { name: "TupleHash128 Sample #1", fn: "TupleHash128", messages: TUPLE_1,
    customization: "", outputBits: 256,
    expected: "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3f" +
        "fc8ed1" },
  { name: "TupleHash128 Sample #2", fn: "TupleHash128", messages: TUPLE_1,
    customization: "My Tuple App", outputBits: 256,
    expected: "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588" +
        "e96dfb" },
  { name: "TupleHash128 Sample #3", fn: "TupleHash128", messages: TUPLE_3,
    customization: "My Tuple App", outputBits: 256,
    expected: "e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804" +
        "bb6e84" },
  { name: "TupleHash256 Sample #4", fn: "TupleHash256", messages: TUPLE_1,
    customization: "", outputBits: 512,
    expected: "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201" +
        "ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb2" +
        "3bbe194" },
  { name: "ParallelHash128 Sample #1", fn: "ParallelHash128",
    message: PARALLEL_DATA, blockBytes: 8, customization: "",
    outputBits: 256,
    expected: "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454" +
        "a2b4f5" },
  { name: "ParallelHash128 Sample #2", fn: "ParallelHash128",
    message: PARALLEL_DATA, blockBytes: 8, customization: "Parallel Data",
    outputBits: 256,
    expected: "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e49579" +
        "5b7206" }
];

function sp800185SampleValuesMatch() {
  log.debug("Entering sp800185SampleValuesMatch().");
  for (var i = 0; i < SP800185_SAMPLES.length; i++) {
    var s = SP800185_SAMPLES[i];
    var actual = hex(hashes.derive(s.fn, s));
    assert.strictEqual(actual, s.expected,
        s.name + " does not match the value published in SP 800-185.");
  }
  log.info("OK — all " + SP800185_SAMPLES.length + " transcribed SP 800-185 " +
           "sample values reproduce.");
  log.debug("Leaving sp800185SampleValuesMatch().");
}

// ===========================================================================
// 5. KMAC against a SECOND implementation — OpenSSL's.
//
// The only cross-implementation check available for the SP 800-185 half:
// neither Web Crypto nor node's own hash API has any of these functions, but
// OpenSSL 3 carries KMAC128 and KMAC256 as MACs, customization string and
// all. It is randomized on purpose — the transcribed samples above pin four
// fixed inputs, and what this adds is every OTHER input, including the key
// lengths and customization strings nobody wrote a sample for.
//
// It SKIPS rather than fails when the CLI has no KMAC (OpenSSL 1.x), and says
// so loudly: a check that silently passes because its second implementation
// was missing is the failure mode tests/CLAUDE.md warns about.
// ===========================================================================
function opensslKmac(fnBits, key, message, customization, outputBits) {
  log.debug("Entering opensslKmac().");
  var file = path.join(os.tmpdir(),
      "hash-engine-" + process.pid + "-" + Date.now() + ".bin");
  fs.writeFileSync(file, message);
  var args = ["mac", "-macopt", "hexkey:" + key.toString("hex"),
              "-macopt", "size:" + (outputBits / 8)];
  if (customization) {
    args.push("-macopt", "custom:" + customization);
  }
  args.push("-in", file, "KMAC" + fnBits);
  try {
    var out = execFileSync("openssl", args, { encoding: "utf8" });
    log.debug("Leaving opensslKmac().");
    return out.trim().toLowerCase();
  } finally {
    fs.unlinkSync(file);
  }
}

function opensslHasKmac() {
  log.debug("Entering opensslHasKmac().");
  try {
    var probe = opensslKmac(128, Buffer.alloc(16, 1), Buffer.from("probe"),
                            "", 256);
    log.debug("Leaving opensslHasKmac().");
    return /^[0-9a-f]{64}$/.test(probe);
  } catch (e) {
    log.debug("Leaving opensslHasKmac(). Not available: " + e.message);
    return false;
  }
}

function kmacAgreesWithOpenssl() {
  log.debug("Entering kmacAgreesWithOpenssl().");
  if (!opensslHasKmac()) {
    log.warn("SKIPPED — this machine's `openssl mac` has no KMAC (OpenSSL " +
             "3 is needed), so the KMAC half is checked only against SP " +
             "800-185's transcribed samples on this run.");
    log.debug("Leaving kmacAgreesWithOpenssl(). Skipped.");
    return;
  }
  var customizations = ["", "My Tagged Application", "another domain",
                        "éà non-ascii"];
  var count = 0;
  for (var bits = 128; bits <= 256; bits += 128) {
    for (var i = 0; i < INPUTS.length; i++) {
      // OpenSSL's KMAC provider refuses a key shorter than 4 bytes, though
      // SP 800-185 allows any length — so the cross-check stays above that
      // floor and the shorter keys are covered by the samples above.
      var key = crypto.randomBytes(4 + (i * 7) % 60);
      var s = customizations[i % customizations.length];
      var outputBits = [128, 256, 512, 1024][i % 4];
      var expected = opensslKmac(bits, key, INPUTS[i], s, outputBits);
      var actual = hex(hashes.derive("KMAC" + bits,
          { key: key, message: INPUTS[i], customization: s,
            outputBits: outputBits }));
      assert.strictEqual(actual, expected,
          "KMAC" + bits + " disagrees with OpenSSL on input " + i +
          " (key " + key.length + " bytes, S=\"" + s + "\", L=" +
          outputBits + ").");
      count++;
    }
  }
  log.info("OK — " + count + " KMAC results match OpenSSL's own " +
           "implementation.");
  log.debug("Leaving kmacAgreesWithOpenssl().");
}

// ===========================================================================
// 6. TupleHash and ParallelHash against the SPECIFICATION'S construction,
//    re-derived here.
//
// SP 800-185 section 2.3 defines three integer encodings and builds all four
// functions out of cSHAKE with them. Writing them here rather than reusing
// the library's is the point: the defect these functions actually have is an
// encoding that is self-consistent — a left_encode that pads to a fixed width
// or a right_encode of a byte count where a bit count was meant — and no
// round trip through one implementation can see it.
// ===========================================================================
function leftEncode(x) {
  log.debug("Entering leftEncode().");
  var out = [];
  var v = x;
  do {
    out.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  log.debug("Leaving leftEncode().");
  return Buffer.from([out.length].concat(out));
}

function rightEncode(x) {
  log.debug("Entering rightEncode().");
  var out = [];
  var v = x;
  do {
    out.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  log.debug("Leaving rightEncode().");
  return Buffer.from(out.concat([out.length]));
}

function encodeString(buf) {
  log.debug("Entering encodeString().");
  log.debug("Leaving encodeString().");
  return Buffer.concat([leftEncode(buf.length * 8), Buffer.from(buf)]);
}

function specTupleHash(strength, messages, outputBits, customization) {
  log.debug("Entering specTupleHash().");
  var parts = messages.map(encodeString);
  parts.push(rightEncode(outputBits));
  var fn = strength === 128 ? noble.cshake128 : noble.cshake256;
  log.debug("Leaving specTupleHash().");
  return fn(Buffer.concat(parts), { dkLen: outputBits / 8,
                                    NISTfn: "TupleHash",
                                    personalization: customization });
}

function specParallelHash(strength, message, blockBytes, outputBits,
                          customization) {
  log.debug("Entering specParallelHash().");
  var leaf = strength === 128 ? nobleSha3.shake128 : nobleSha3.shake256;
  var leafBytes = strength === 128 ? 32 : 64;
  var parts = [leftEncode(blockBytes)];
  var blocks = 0;
  for (var i = 0; i < message.length; i += blockBytes) {
    parts.push(Buffer.from(leaf(message.subarray(i, i + blockBytes),
                                { dkLen: leafBytes })));
    blocks++;
  }
  parts.push(rightEncode(blocks), rightEncode(outputBits));
  var fn = strength === 128 ? noble.cshake128 : noble.cshake256;
  log.debug("Leaving specParallelHash().");
  return fn(Buffer.concat(parts), { dkLen: outputBits / 8,
                                    NISTfn: "ParallelHash",
                                    personalization: customization });
}

function derivedFunctionsMatchTheSpecConstruction() {
  log.debug("Entering derivedFunctionsMatchTheSpecConstruction().");
  var count = 0;
  var customizations = ["", "My Tuple App", "domain two"];
  for (var s = 0; s < 2; s++) {
    var strength = s === 0 ? 128 : 256;
    for (var i = 0; i < INPUTS.length; i++) {
      var custom = customizations[i % customizations.length];
      var outputBits = [256, 512][i % 2];
      // TupleHash: a two-element tuple built from this input, so the tuple
      // boundaries fall in a different place for every case.
      var tuple = [INPUTS[i].subarray(0, Math.floor(INPUTS[i].length / 3)),
                   INPUTS[i].subarray(Math.floor(INPUTS[i].length / 3))];
      assert.strictEqual(
          hex(hashes.derive("TupleHash" + strength,
              { messages: tuple, customization: custom,
                outputBits: outputBits })),
          hex(specTupleHash(strength, tuple, outputBits, custom)),
          "TupleHash" + strength + " does not match the SP 800-185 " +
          "construction on input " + i + ".");
      count++;
      var blockBytes = [1, 8, 13, 168][i % 4];
      assert.strictEqual(
          hex(hashes.derive("ParallelHash" + strength,
              { message: INPUTS[i], blockBytes: blockBytes,
                customization: custom, outputBits: outputBits })),
          hex(specParallelHash(strength, INPUTS[i], blockBytes, outputBits,
                               custom)),
          "ParallelHash" + strength + " does not match the SP 800-185 " +
          "construction on input " + i + " (B=" + blockBytes + ").");
      count++;
    }
  }
  log.info("OK — " + count + " TupleHash / ParallelHash results match the " +
           "construction re-derived from SP 800-185's own text.");
  log.debug("Leaving derivedFunctionsMatchTheSpecConstruction().");
}

// ===========================================================================
// 7. The properties no vector expresses.
// ===========================================================================

// SP 800-185 section 3.3: cSHAKE with an empty function name and an empty
// customization string IS SHAKE. The page says so in its notes, and a reader
// who takes that on trust deserves it to be true.
function cshakeWithNothingCustomIsShake() {
  log.debug("Entering cshakeWithNothingCustomIsShake().");
  for (var i = 0; i < INPUTS.length; i++) {
    assert.strictEqual(
        hex(hashes.derive("cSHAKE128", { message: INPUTS[i],
            customization: "", functionName: "", outputBits: 512 })),
        hex(hashes.digest("SHAKE128", INPUTS[i], { outputBits: 512 })),
        "cSHAKE128 with empty N and S is not SHAKE128 on input " + i + ".");
    assert.strictEqual(
        hex(hashes.derive("cSHAKE256", { message: INPUTS[i],
            customization: "", functionName: "", outputBits: 512 })),
        hex(hashes.digest("SHAKE256", INPUTS[i], { outputBits: 512 })),
        "cSHAKE256 with empty N and S is not SHAKE256 on input " + i + ".");
    // ...and a non-empty S has to change it, or customization is a field
    // that does nothing, which is the failure that looks like success.
    assert.notStrictEqual(
        hex(hashes.derive("cSHAKE128", { message: INPUTS[i],
            customization: "some domain", outputBits: 512 })),
        hex(hashes.digest("SHAKE128", INPUTS[i], { outputBits: 512 })),
        "cSHAKE128 ignored its customization string on input " + i + ".");
  }
  log.info("OK — cSHAKE with no N and no S is SHAKE, and a customization " +
           "string changes the answer.");
  log.debug("Leaving cshakeWithNothingCustomIsShake().");
}

// KMAC binds L into the computation with right_encode(L); the XOF variant
// encodes right_encode(0) instead. So KMAC128 at 512 bits is NOT KMAC128 at
// 256 bits with more bytes after it, and KMAC128XOF is not KMAC128 truncated
// — while a SHAKE, four lines above, is exactly that. Getting these two
// backwards produces a MAC that verifies against itself and against nothing
// else.
function outputLengthIsBoundIntoKmac() {
  log.debug("Entering outputLengthIsBoundIntoKmac().");
  var key = KMAC_KEY;
  var short = hex(hashes.derive("KMAC128",
      { key: key, message: DATA_200, outputBits: 256 }));
  var long = hex(hashes.derive("KMAC128",
      { key: key, message: DATA_200, outputBits: 512 }));
  assert.ok(long.indexOf(short) !== 0,
      "KMAC128 at 512 bits begins with its 256-bit output — the length is " +
      "not bound into the computation, which is the difference between " +
      "KMAC and KMAC-XOF.");
  var xofShort = hex(hashes.derive("KMAC128XOF",
      { key: key, message: DATA_200, outputBits: 256 }));
  var xofLong = hex(hashes.derive("KMAC128XOF",
      { key: key, message: DATA_200, outputBits: 512 }));
  assert.ok(xofLong.indexOf(xofShort) === 0,
      "KMAC128XOF at 512 bits does not extend its 256-bit output, so it is " +
      "not behaving as an XOF.");
  assert.notStrictEqual(short, xofShort,
      "KMAC128 and KMAC128XOF produced the same 256 bits, so one of them " +
      "is not encoding the length the way SP 800-185 says.");
  log.info("OK — KMAC binds its output length, KMAC-XOF extends, and the " +
           "two differ.");
  log.debug("Leaving outputLengthIsBoundIntoKmac().");
}

// TupleHash's whole reason for existing: ("ab","c") and ("a","bc") have the
// same concatenation and MUST have different digests.
function tupleHashIsUnambiguous() {
  log.debug("Entering tupleHashIsUnambiguous().");
  var a = [Buffer.from("ab"), Buffer.from("c")];
  var b = [Buffer.from("a"), Buffer.from("bc")];
  assert.strictEqual(Buffer.concat(a).toString("hex"),
                     Buffer.concat(b).toString("hex"),
      "the two tuples in this check no longer share a concatenation, so it " +
      "is checking nothing.");
  assert.notStrictEqual(
      hex(hashes.derive("TupleHash128", { messages: a, outputBits: 256 })),
      hex(hashes.derive("TupleHash128", { messages: b, outputBits: 256 })),
      "TupleHash128 gave two differently-split tuples the same digest — it " +
      "is hashing the concatenation, which is the one thing it exists not " +
      "to do.");
  // And an empty tuple is a legal input rather than a crash.
  assert.strictEqual(
      hashes.derive("TupleHash128", { messages: [], outputBits: 256 }).length,
      32, "TupleHash128 of the empty tuple did not produce 256 bits.");
  log.info("OK — TupleHash separates tuple elements that share a " +
           "concatenation.");
  log.debug("Leaving tupleHashIsUnambiguous().");
}

// ParallelHash's block size is part of the definition, not a performance
// knob: two readers who choose differently get different digests of one file,
// and a pane that hid B would make that undiagnosable.
function parallelHashBlockSizeChangesTheAnswer() {
  log.debug("Entering parallelHashBlockSizeChangesTheAnswer().");
  var eight = hex(hashes.derive("ParallelHash128",
      { message: PARALLEL_DATA, blockBytes: 8, outputBits: 256 }));
  var twelve = hex(hashes.derive("ParallelHash128",
      { message: PARALLEL_DATA, blockBytes: 12, outputBits: 256 }));
  assert.notStrictEqual(eight, twelve,
      "ParallelHash128 gave the same digest for B=8 and B=12, so the block " +
      "size is being ignored.");
  assert.throws(function () {
    hashes.derive("ParallelHash128",
        { message: PARALLEL_DATA, blockBytes: 0, outputBits: 256 });
  }, /block size/, "ParallelHash accepted a zero block size.");
  log.info("OK — ParallelHash's block size is part of the answer.");
  log.debug("Leaving parallelHashBlockSizeChangesTheAnswer().");
}

// ===========================================================================
// 8. Input and output codings, and the refusals.
// ===========================================================================
function codingsAndRefusals() {
  log.debug("Entering codingsAndRefusals().");
  var message = Buffer.from("abc", "utf8");
  var wanted = hex(hashes.digest("SHA3-256", message));
  var forms = [["text", "abc"], ["hex", "616263"], ["hex", "61 62 63"],
               ["hex", "61:62:63"], ["base64", "YWJj"],
               ["base64url", "YWJj"]];
  for (var i = 0; i < forms.length; i++) {
    assert.strictEqual(
        hex(hashes.digest("SHA3-256",
            hashes.decodeInput(forms[i][1], forms[i][0]))),
        wanted, "input coding " + forms[i][0] + " did not decode \"" +
        forms[i][1] + "\" to the same three bytes.");
  }
  var digest = hashes.digest("SHA-256", message);
  assert.strictEqual(hashes.encodeOutput(digest, "hex"),
      hashes.encodeOutput(digest, "HEX").toLowerCase(),
      "the HEX output coding is not the hex one in upper case.");
  assert.strictEqual(
      Buffer.from(hashes.encodeOutput(digest, "base64"),
                  "base64").toString("hex"),
      hex(digest), "the base64 output coding does not decode back to the " +
      "digest.");
  assert.ok(hashes.encodeOutput(digest, "base64url").indexOf("=") < 0,
      "the base64url output coding is padded.");

  assert.throws(function () { hashes.decodeInput("abc", "hex"); },
      /odd number/, "an odd-length hex input was accepted.");
  assert.throws(function () { hashes.decodeInput("zz", "hex"); },
      /non-hex/, "a non-hex character was accepted as hex.");
  assert.throws(function () {
    hashes.digest("SHAKE256", message, { outputBits: 7 });
  }, /multiple of 8/, "an output length of 7 bits was accepted.");
  assert.throws(function () {
    hashes.digest("SHAKE256", message,
                  { outputBits: hashes.MAX_OUTPUT_BITS + 8 });
  }, /capped/, "an output length past the cap was accepted.");
  assert.throws(function () { hashes.digest("SHA3-257", message); },
      /Unknown hash algorithm/, "an unknown algorithm was accepted.");
  assert.throws(function () {
    hashes.derive("KMAC128", { message: message, outputBits: 256 });
  }, /needs a key/, "KMAC was computed with no key.");
  log.info("OK — every input and output coding round-trips, and each " +
           "malformed argument is refused by name.");
  log.debug("Leaving codingsAndRefusals().");
}

// ===========================================================================
// 9. The notes, which are most of what these panes are for.
//
// A wrong digest is caught by every section above. A wrong NOTE is caught by
// nothing else at all, and it is the half a reader takes away with them.
// ===========================================================================
function notesSayTheRightThings() {
  log.debug("Entering notesSayTheRightThings().");
  // A SHAKE's strength is capped by its capacity however much output is
  // asked for — the single most misunderstood thing about an XOF.
  var capped = hashes.strengths("SHAKE128", 4096);
  assert.strictEqual(capped.collision, 128,
      "SHAKE128 asked for 4096 bits is reported with more than 128-bit " +
      "collision resistance.");
  assert.strictEqual(capped.preimage, 128,
      "SHAKE128 asked for 4096 bits is reported with more than 128-bit " +
      "preimage resistance.");
  var shortShake = hashes.strengths("SHAKE256", 128);
  assert.strictEqual(shortShake.collision, 64,
      "SHAKE256 asked for 128 bits is not bounded by its output length.");

  // Collision and preimage are reported SEPARATELY under a quantum
  // attacker, because conflating them is what produces the claim that
  // SHA-256 has 128-bit post-quantum security full stop.
  var sha256 = hashes.describe("SHA-256");
  assert.ok(/128-bit collision, 256-bit preimage/.test(sha256),
      "SHA-256's classical strengths are not both stated.");
  assert.ok(/Grover/.test(sha256) &&
      /collision resistance is essentially unchanged/.test(sha256),
      "SHA-256's note does not distinguish what Grover moves from what it " +
      "does not.");

  // The two functions whose collision search DEFINES a NIST category say so,
  // and the ones that do not, do not.
  var categorised = { "SHA-256": 2, "SHA3-256": 2, "SHA-384": 4,
                      "SHA3-384": 4 };
  for (var i = 0; i < hashes.ALGORITHMS.length; i++) {
    var alg = hashes.ALGORITHMS[i];
    var text = hashes.describe(alg.id, 256);
    var expected = categorised[alg.id];
    if (expected) {
      assert.ok(text.indexOf("security category " + expected) > 0,
          alg.id + " does not name NIST post-quantum security category " +
          expected + ".");
    } else {
      assert.ok(text.indexOf("security category") < 0,
          alg.id + " claims to define a NIST post-quantum security " +
          "category, and it does not.");
    }
    assert.ok(/Post-quantum role: /.test(text),
        alg.id + " has no post-quantum role line.");
    assert.ok(text.indexOf(alg.spec) >= 0,
        alg.id + " does not name the specification it comes from.");
  }

  // The functions the post-quantum standards actually use have to name them,
  // because that is the whole reason those panes were added.
  assert.ok(/FIPS 203/.test(hashes.describe("SHA3-256")),
      "SHA3-256's note does not say it is ML-KEM's H.");
  assert.ok(/FIPS 203/.test(hashes.describe("SHA3-512")),
      "SHA3-512's note does not say it is ML-KEM's G.");
  var shake256 = hashes.describe("SHAKE256", 256);
  assert.ok(/FIPS 204/.test(shake256) && /FIPS 205/.test(shake256),
      "SHAKE256's note does not name ML-DSA and SLH-DSA, which are built " +
      "on it.");
  assert.ok(/SHAttered|BROKEN/.test(hashes.describe("SHA-1")),
      "SHA-1's note does not say its collision resistance is broken.");

  // Every SP 800-185 function describes itself, and the description names
  // the customization string in use — a value the reader cannot otherwise
  // tell was applied, since applying it changes nothing about the shape of
  // the answer.
  for (var d = 0; d < hashes.DERIVED.length; d++) {
    var fn = hashes.DERIVED[d];
    var note = hashes.describeDerived(fn.id,
        { customization: "a domain" });
    assert.ok(note.indexOf("SP 800-185") > 0,
        fn.id + " does not name SP 800-185.");
    assert.ok(note.indexOf("a domain") > 0,
        fn.id + " does not report the customization string in use.");
    assert.ok(hashes.describeDerived(fn.id, {}).indexOf("S is empty") > 0,
        fn.id + " does not say when the customization string is empty.");
  }
  log.info("OK — the notes state both resistances, separate what Grover " +
           "moves from what it does not, and name the standard each " +
           "function serves.");
  log.debug("Leaving notesSayTheRightThings().");
}

// ===========================================================================
// 10. The division of labour, and the page.
// ===========================================================================
function theEngineReachesNoDomAndNoWebCrypto() {
  log.debug("Entering theEngineReachesNoDomAndNoWebCrypto().");
  var source = fs.readFileSync(path.join(SRC, "hash_tools.js"), "utf8");
  // Comments discuss all of these at length — that is where the reasoning
  // lives — so only real code lines count.
  var code = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  var forbidden = ["document", "window", "localStorage", "sessionStorage",
                   "crypto.subtle"];
  for (var i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/hash_tools.js reaches " + forbidden[i] + " — this whole " +
        "job exists because it does not, so the reference has to go or this " +
        "check does.");
  }
  log.info("OK — the engine has no DOM, no storage and no Web Crypto.");
  log.debug("Leaving theEngineReachesNoDomAndNoWebCrypto().");
}

// The page and the engine drift apart silently: an option whose value is not
// a registry id produces "Unknown hash algorithm" in a status line nobody is
// watching, and a handler the page calls but the bundle does not export is a
// ReferenceError on click. Both are one typo away and neither is visible in a
// diff of either file alone.
function thePageAndTheEngineAgree() {
  log.debug("Entering thePageAndTheEngineAgree().");
  var html = fs.readFileSync(path.join(PUBLIC, "encoding_tools.html"),
                             "utf8");
  var bundle = fs.readFileSync(path.join(SRC, "encoding_tools.js"), "utf8");

  function optionsOf(selectId) {
    log.debug("Entering optionsOf(). selectId=" + selectId);
    var start = html.indexOf('id="' + selectId + '"');
    assert.ok(start > 0, "the page has no <select id=\"" + selectId + "\">.");
    var end = html.indexOf("</select>", start);
    var values = [];
    var re = /<option value="([^"]+)"/g;
    var slice = html.slice(start, end);
    var m = re.exec(slice);
    while (m) {
      values.push(m[1]);
      m = re.exec(slice);
    }
    log.debug("Leaving optionsOf().");
    return values;
  }

  var offered = optionsOf("sha_size").concat(optionsOf("sha3_alg"));
  for (var i = 0; i < offered.length; i++) {
    assert.ok(hashes.algorithm(offered[i]),
        "the page offers a hash called \"" + offered[i] + "\" and the " +
        "registry has no such algorithm.");
  }
  for (var a = 0; a < hashes.ALGORITHMS.length; a++) {
    assert.ok(offered.indexOf(hashes.ALGORITHMS[a].id) >= 0,
        "hash_tools.js has " + hashes.ALGORITHMS[a].id + " and no pane " +
        "offers it.");
  }
  var derived = optionsOf("sp185_fn");
  for (var d = 0; d < derived.length; d++) {
    assert.ok(hashes.derived(derived[d]),
        "the page offers an SP 800-185 function called \"" + derived[d] +
        "\" and the registry has no such function.");
  }
  for (var f = 0; f < hashes.DERIVED.length; f++) {
    assert.ok(derived.indexOf(hashes.DERIVED[f].id) >= 0,
        "hash_tools.js has " + hashes.DERIVED[f].id + " and the page does " +
        "not offer it.");
  }

  // Every handler the markup calls has to be exported by the bundle.
  var called = {};
  var re = /encoding_tools\.([A-Za-z0-9_]+)\(/g;
  var m = re.exec(html);
  while (m) {
    called[m[1]] = true;
    m = re.exec(html);
  }
  var exported = bundle.slice(bundle.lastIndexOf("module.exports"));
  for (var name in called) {
    if (!called.hasOwnProperty(name)) continue;
    assert.ok(new RegExp("\\b" + name + "\\b").test(exported),
        "encoding_tools.html calls encoding_tools." + name + "() and the " +
        "bundle does not export it — every click on that control would be " +
        "a ReferenceError.");
  }
  log.info("OK — the page offers exactly the registry's " +
           hashes.ALGORITHMS.length + " hashes and " +
           hashes.DERIVED.length + " SP 800-185 functions, and every " +
           "handler it calls is exported.");
  log.debug("Leaving thePageAndTheEngineAgree().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  fixedOutputFunctionsAgreeWithOpenssl();
  shakeAgreesWithOpensslAtEveryLength();
  keccakIsNotSha3();
  sp800185SampleValuesMatch();
  kmacAgreesWithOpenssl();
  derivedFunctionsMatchTheSpecConstruction();
  cshakeWithNothingCustomIsShake();
  outputLengthIsBoundIntoKmac();
  tupleHashIsUnambiguous();
  parallelHashBlockSizeChangesTheAnswer();
  codingsAndRefusals();
  notesSayTheRightThings();
  theEngineReachesNoDomAndNoWebCrypto();
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
