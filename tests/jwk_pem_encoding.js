// File: jwk_pem.js
//
// client/src/jwk_pem.js — a JWK public key encoded as a SubjectPublicKeyInfo PEM,
// which is what the JWKS page displays under "PEM Format".
//
// Why this module exists at all, and therefore why this test does: the page used
// to get that encoding from the `jwk-to-pem` package, which builds the EC point
// through `elliptic`. browserify bundles what a page requires, so `elliptic`
// shipped to the browser — and `elliptic` carries GHSA-848j-6mx2-7j84 (ECDSA
// signatures with a leading-zero `k` are computed with a truncated byte length,
// which can expose the private key) with NO patched version in existence: the
// advisory's range is `<=6.6.1` and 6.6.1 is the latest release. There is
// nothing to upgrade to, so the fix was to stop needing the package.
//
// That trade only holds if the replacement is exactly as correct as what it
// replaced. A PEM is a wire format other tools have to parse, and a
// wrong-by-one-byte encoding is the kind of thing that shows up as somebody
// else's tool rejecting a key rather than as a failure here. So this test does
// not check "looks like a PEM":
//
//   * a round trip through node's own SPKI parser (crypto.createPublicKey),
//     which shares no code with either implementation — it parses the DER this
//     module emitted and must recover the JWK it started from. This is a
//     stronger oracle than matching `jwk-to-pem`'s bytes would have been, and it
//     does not need that package installed to run: agreeing with a second
//     encoder proves only that two encoders agree, whereas a parser recovering
//     the original key proves the encoding says what it should;
//   * the encoding rules that are easy to get wrong and silent when wrong: the
//     DER INTEGER sign byte on an RSA modulus, multi-byte lengths, and EC
//     coordinates that a publisher trimmed a leading zero from;
//   * the refusals, because the JWKS page depends on a throw to mark ONE key
//     unrenderable without losing the rest of the table.
//
// It also guards the reason the module exists: client/src is read for any
// require of `jwk-to-pem`, `jsonwebtoken` or a bare `crypto`, each of which
// puts `elliptic` back into a bundle. That check is the only thing here that
// would catch a NEW page reintroducing it.
//
// No browser and no services: node only, so it never skips.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwk_pem",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the module is at client/src/jwk_pem.js; the tests image copies it
// flat next to the test scripts (see tests/Dockerfile).
var jwkToPem = paths.requireSharedModule(
  [__dirname + "/../client/src/jwk_pem.js", __dirname + "/jwk_pem.js"], "jwk_pem.js");

// The module uses atob/btoa (browser globals). Node has had both since 16, but
// assert it rather than discover a ReferenceError three functions deep.
assert.strictEqual(typeof atob, "function", "this node has no global atob()");
assert.strictEqual(typeof btoa, "function", "this node has no global btoa()");


// --- the oracles ------------------------------------------------------------

function derOf(pem) {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

// The outer SEQUENCE must declare exactly the bytes that follow it — no more, no
// fewer. This is checked on EVERY key rather than a sample because node's SPKI
// parser TOLERATES TRAILING BYTES: a DER with junk appended parses fine and
// recovers the right key, so the round trip alone cannot see it. A mutation that
// appended a byte to the encoding survived until this check was hoisted here.
function assertOuterLengthConsistent(pem, label) {
  log.debug("Entering assertOuterLengthConsistent().");
  const der = derOf(pem);
  assert.strictEqual(der[0], 0x30, label + ": SPKI does not start with a SEQUENCE tag");
  let declared;
  let headerBytes;
  if (der[1] < 0x80) {
    declared = der[1];
    headerBytes = 2;
  } else {
    const lengthOfLength = der[1] & 0x7f;
    declared = 0;
    for (let i = 0; i < lengthOfLength; i++) {
      declared = declared * 256 + der[2 + i];
    }
    headerBytes = 2 + lengthOfLength;
  }
  assert.strictEqual(declared, der.length - headerBytes,
    label + ": the SEQUENCE declares " + declared + " content bytes but the encoding carries " +
    (der.length - headerBytes) + " — trailing or missing bytes");
  log.debug("Leaving assertOuterLengthConsistent().");
}

// Independent of both implementations: parse the PEM this module produced with
// node's own SPKI reader and recover the JWK. If the DER is malformed node
// throws; if it is well-formed but wrong, the recovered JWK differs.
function roundTripsThroughNode(jwk, label) {
  log.debug("Entering roundTripsThroughNode().");
  const pem = jwkToPem(jwk);
  assertOuterLengthConsistent(pem, label);
  let recovered;
  try {
    recovered = crypto.createPublicKey({ key: pem, format: "pem", type: "spki" })
                      .export({ format: "jwk" });
  } catch (e) {
    assert.fail(label + ": node could not parse the SPKI this module produced: " + e.message);
  }
  const interesting = (j) => {
    const out = {};
    Object.keys(j).sort().forEach(function (k) {
      if (k === "key_ops" || k === "ext" || k === "alg" || k === "use" || k === "kid") return;
      out[k] = j[k];
    });
    return out;
  };
  assert.deepStrictEqual(interesting(recovered), interesting(jwk),
    label + ": the key node recovered from the PEM is not the key that went in");
  log.debug("Leaving roundTripsThroughNode().");
  return pem;
}

function generatedJwk(type, options) {
  return crypto.generateKeyPairSync(type, options).publicKey.export({ format: "jwk" });
}


// --- the checks -------------------------------------------------------------

function rsaKeys() {
  log.debug("Entering rsaKeys().");
  log.info("[rsa] Encoding RSA public keys and reading them back with node's SPKI parser.");
  // Several sizes, and enough 2048 samples that both DER-INTEGER cases (high bit
  // set, needing the 0x00 sign byte, and not set) are certain to be covered.
  [1024, 2048, 3072, 4096].forEach(function (bits) {
    const jwk = generatedJwk("rsa", { modulusLength: bits });
    const pem = roundTripsThroughNode(jwk, "RSA " + bits);
    assert.ok(/^-----BEGIN PUBLIC KEY-----\n/.test(pem), "RSA " + bits + ": missing PEM header");
    assert.ok(/-----END PUBLIC KEY-----\n$/.test(pem), "RSA " + bits + ": missing PEM footer");
    pem.split("\n").slice(1, -2).forEach(function (line) {
      assert.ok(line.length <= 64, "RSA " + bits + ": base64 line longer than 64 characters");
    });
  });

  for (let i = 0; i < 12; i++) {
    roundTripsThroughNode(generatedJwk("rsa", { modulusLength: 2048 }), "RSA 2048 sample " + i);
  }
  log.info("[rsa] OK — four key sizes and 12 further 2048-bit keys all parsed back to the key " +
           "they came from, with well-formed PEM framing.");
  log.debug("Leaving rsaKeys().");
}

// The DER INTEGER rules, exercised deliberately rather than hoped for.
//
// A generated RSA modulus cannot cover them: a modulus of exactly 2048 bits
// always has its top bit set, so real keys only ever take the sign-byte branch
// (an earlier version of this test asserted otherwise and was simply wrong). The
// other branches are reached with crafted moduli. They matter because the failure
// mode is silent — a modulus encoded without its sign byte reads as a NEGATIVE
// integer, which is a different number, so the key is wrong rather than rejected.
function derIntegerRules() {
  log.debug("Entering derIntegerRules().");
  log.info("[integer] Checking DER INTEGER minimal encoding and the sign byte.");

  function modulusEncodedAs(nBytes) {
    const pem = jwkToPem({
      kty: "RSA",
      n: Buffer.from(nBytes).toString("base64url"),
      e: "AQAB"
    });
    return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  }

  // Each case: the modulus bytes going in, and the INTEGER *contents* that must
  // come out. Trailing bytes are arbitrary padding to keep the values distinct.
  const tail = [0x11, 0x22, 0x33, 0x44];
  const cases = [
    { what: "high bit set — needs a 0x00 sign byte so it does not read as negative",
      input: [0xff].concat(tail), expected: [0x00, 0xff].concat(tail) },
    { what: "high bit clear — must NOT gain a sign byte",
      input: [0x7f].concat(tail), expected: [0x7f].concat(tail) },
    { what: "leading zero, then a high bit — zero stripped, sign byte re-added",
      input: [0x00, 0x80].concat(tail), expected: [0x00, 0x80].concat(tail) },
    { what: "leading zeros, then a low byte — zeros stripped, no sign byte",
      input: [0x00, 0x00, 0x7f].concat(tail), expected: [0x7f].concat(tail) }
  ];

  cases.forEach(function (testCase) {
    const der = modulusEncodedAs(testCase.input);
    const wanted = Buffer.concat([
      Buffer.from([0x02, testCase.expected.length]),
      Buffer.from(testCase.expected)
    ]);
    assert.ok(der.includes(wanted),
      "[integer] " + testCase.what + ": expected the DER to contain INTEGER " +
      wanted.toString("hex") + " but it does not — full DER " + der.toString("hex"));
    // And the un-normalised form must NOT be there, or "contains the right bytes"
    // could pass while the wrong encoding sits beside it.
    if (testCase.expected.length !== testCase.input.length) {
      const naive = Buffer.concat([
        Buffer.from([0x02, testCase.input.length]),
        Buffer.from(testCase.input)
      ]);
      assert.ok(!der.includes(naive),
        "[integer] " + testCase.what + ": the un-normalised INTEGER " +
        naive.toString("hex") + " is still present");
    }
  });

  // The public exponent is the one INTEGER in a real key that takes the
  // no-sign-byte branch: AQAB is 0x010001, whose leading byte is below 0x80.
  const realKey = jwkToPem(generatedJwk("rsa", { modulusLength: 2048 }));
  const realDer = Buffer.from(realKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  assert.ok(realDer.includes(Buffer.from([0x02, 0x03, 0x01, 0x00, 0x01])),
    "the public exponent 65537 should encode as INTEGER 02 03 01 00 01, with no sign byte");
  assert.ok(!realDer.includes(Buffer.from([0x02, 0x04, 0x00, 0x01, 0x00, 0x01])),
    "the public exponent gained a sign byte it does not need");

  log.info("[integer] OK — " + cases.length + " crafted moduli plus the real exponent all encode " +
           "minimally, with the sign byte exactly where it belongs.");
  log.debug("Leaving derIntegerRules().");
}

function ecKeys() {
  log.debug("Entering ecKeys().");
  log.info("[ec] Encoding EC public keys on every supported curve.");
  assert.deepStrictEqual(jwkToPem.SUPPORTED_CURVES.slice().sort(), ["P-256", "P-384", "P-521"],
    "the supported curve list changed — jwk-to-pem covered exactly these three");
  jwkToPem.SUPPORTED_CURVES.forEach(function (crv) {
    for (let i = 0; i < 10; i++) {
      roundTripsThroughNode(generatedJwk("ec", { namedCurve: crv }), crv + " sample " + i);
    }
  });
  log.info("[ec] OK — P-256, P-384 and P-521 all round-trip.");
  log.debug("Leaving ecKeys().");
}

// RFC 7518 sections 6.2.1.2/6.2.1.3: a coordinate is the full field size,
// zero-padded on the LEFT. Publishers do sometimes trim a leading zero, and an
// unpadded coordinate is a DIFFERENT POINT — so the failure is a key that is
// quietly wrong, not a key that is rejected. Forge the case rather than wait for
// it: take a key whose x starts with 0x00 and strip it, as a careless publisher
// would, then require the recovered x to be the original.
function trimmedCoordinateIsRepadded() {
  log.debug("Entering trimmedCoordinateIsRepadded().");
  log.info("[padding] A publisher that trimmed a leading zero from a coordinate must still " +
           "produce the original point.");
  let tested = 0;
  for (let attempt = 0; attempt < 6000 && tested < 3; attempt++) {
    const jwk = generatedJwk("ec", { namedCurve: "P-256" });
    const xBytes = Buffer.from(jwk.x, "base64url");
    if (xBytes[0] !== 0x00) continue;
    const trimmed = Object.assign({}, jwk, { x: xBytes.subarray(1).toString("base64url") });
    const recovered = crypto.createPublicKey({ key: jwkToPem(trimmed), format: "pem", type: "spki" })
                            .export({ format: "jwk" });
    assert.strictEqual(recovered.x, jwk.x,
      "a coordinate missing its leading zero was not re-padded, so the encoded point is wrong");
    assert.strictEqual(recovered.y, jwk.y, "y changed while re-padding x");
    tested++;
  }
  if (tested === 0) {
    // Not a pass and not a failure of the module: P-256 x values start with 0x00
    // about 1 in 256 times, so 6000 tries missing it means something is off with
    // key generation, and silently reporting OK would hide that.
    assert.fail("no P-256 key with a leading-zero x coordinate turned up in 6000 tries");
  }
  log.info("[padding] OK — " + tested + " trimmed coordinates were re-padded to the correct point.");
  log.debug("Leaving trimmedCoordinateIsRepadded().");
}

// Both DER length forms, named explicitly. The single-byte form covers content
// under 128 bytes (a P-256 key) and the long form 0x82 xx xx appears above 255 (a
// 4096-bit modulus), so a length encoder broken in only one of the two would
// otherwise slip through whichever key sizes happened to be sampled.
function derLengthsAreWellFormed() {
  log.debug("Entering derLengthsAreWellFormed().");
  log.info("[der] Checking both DER length forms — short and long.");
  const shortForm = jwkToPem(generatedJwk("ec", { namedCurve: "P-256" }));
  const longForm = jwkToPem(generatedJwk("rsa", { modulusLength: 4096 }));
  assert.ok(derOf(shortForm)[1] < 0x80,
    "a P-256 SPKI should use the short length form");
  assert.strictEqual(derOf(longForm)[1], 0x82,
    "a 4096-bit RSA SPKI should use the two-byte long length form");
  assertOuterLengthConsistent(shortForm, "P-256");
  assertOuterLengthConsistent(longForm, "RSA 4096");
  log.info("[der] OK — declared lengths match the content, in both the short and long forms.");
  log.debug("Leaving derLengthsAreWellFormed().");
}

// The JWKS page catches a throw to mark one key unrenderable and keep the rest of
// the table. That only works if unsupported input throws rather than returning
// something PEM-shaped, and the message has to name the type for the page to say
// anything useful.
function refusals() {
  log.debug("Entering refusals().");
  log.info("[refusals] Unsupported and malformed keys must throw, naming the cause.");
  const cases = [
    [{ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
     /Unsupported key type "OKP"/],
    [{ kty: "oct", k: "AAAA" }, /Unsupported key type "oct"/],
    [{ kty: "EC", crv: "secp256k1", x: "AAAA", y: "AAAA" }, /Unsupported curve "secp256k1"/],
    [{ kty: "RSA", e: "AQAB" }, /missing or non-string "n"/],
    [{ kty: "RSA", n: "AQAB" }, /missing or non-string "e"/],
    [{ kty: "EC", crv: "P-256", y: "AAAA" }, /missing or non-string "x"/],
    [{}, /Unsupported key type "undefined"/],
    [null, /expected an object/],
    ["not a jwk", /expected an object/]
  ];
  cases.forEach(function (pair) {
    assert.throws(function () { jwkToPem(pair[0]); }, pair[1],
      "expected " + JSON.stringify(pair[0]) + " to be refused with " + pair[1]);
  });

  // A coordinate too long for its curve is a different key, not a paddable one.
  assert.throws(function () {
    const jwk = generatedJwk("ec", { namedCurve: "P-256" });
    jwkToPem(Object.assign({}, jwk, {
      x: Buffer.concat([Buffer.from([1]), Buffer.from(jwk.x, "base64url")]).toString("base64url")
    }));
  }, /too long for P-256/, "an over-long coordinate should be refused, not truncated");
  log.info("[refusals] OK — " + (cases.length + 1) + " bad inputs all throw with a named cause.");
  log.debug("Leaving refusals().");
}

// A private JWK is not an error at the call site — the JWKS page shows keys an
// identity provider published — but `d` must be IGNORED rather than encoded, or
// a page whose job is displaying public keys would render a private one.
function privateMembersAreIgnored() {
  log.debug("Entering privateMembersAreIgnored().");
  log.info("[private] A JWK carrying `d` must still encode as the PUBLIC key.");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  assert.ok(privateJwk.d, "the generated private JWK should carry d");
  const pem = jwkToPem(privateJwk);
  assert.ok(/BEGIN PUBLIC KEY/.test(pem) && !/PRIVATE/.test(pem),
    "a private JWK produced something other than a public-key PEM");
  assertOuterLengthConsistent(pem, "EC private JWK encoded as public");
  // The encoding must be byte-identical to the one the public half alone gives:
  // anything else means `d` left a trace, which node's trailing-byte-tolerant
  // parser would not report.
  const publicOnly = jwkToPem(pair.publicKey.export({ format: "jwk" }));
  assert.strictEqual(pem, publicOnly,
    "encoding a private JWK differed from encoding its public half — d leaked into the output");
  const recovered = crypto.createPublicKey({ key: pem, format: "pem", type: "spki" })
                          .export({ format: "jwk" });
  assert.ok(!recovered.d, "the encoded key still carries the private component");
  assert.strictEqual(recovered.x, privateJwk.x, "public x does not match");
  assert.strictEqual(recovered.y, privateJwk.y, "public y does not match");
  log.info("[private] OK — d is dropped and the public point survives.");
  log.debug("Leaving privateMembersAreIgnored().");
}

// The point of the exercise. `elliptic` reaches a browser bundle through any of
// these requires, and there is no patched version to fall back on, so the only
// defence is not requiring them. This is the check that catches a NEW page.
function ellipticStaysOutOfTheBundles() {
  log.debug("Entering ellipticStaysOutOfTheBundles().");
  log.info("[bundles] Reading client/src for the requires that pull `elliptic` into a bundle.");
  const srcDir = path.join(__dirname, "..", "client", "src");
  if (!fs.existsSync(srcDir)) {
    // The tests image copies individual modules flat and has no client/src, so
    // there is nothing to read. Say so rather than reporting a silent pass.
    log.info("[bundles] SKIPPED — no client/src in this layout (running from the tests image).");
    return;
  }
  // common/krb5 is scanned as well, and for exactly the same reason: those
  // modules are STAGED INTO client/src at build time (the way common/data.js
  // already is, see client/Dockerfile and client/build.js), so browserify treats
  // them as bundle source even though they do not live under client/src. A
  // `require("crypto")` there would put `elliptic` into the Kerberos bundle with
  // nothing in this repository noticing — the Kerberos crypto reaches Web Crypto
  // through globalThis specifically to avoid it, and this is what holds it to
  // that.
  const extraDirs = [path.join(__dirname, "..", "common", "krb5")]
    .filter(function (d) { return fs.existsSync(d); });
  const banned = [
    { pattern: /require\(\s*['"]jwk-to-pem['"]\s*\)/, name: "jwk-to-pem",
      why: "builds its EC point through elliptic; use ./jwk_pem instead" },
    { pattern: /require\(\s*['"]jsonwebtoken['"]\s*\)/, name: "jsonwebtoken",
      why: "reaches elliptic via jwa -> crypto -> crypto-browserify; decoding a JWT needs no crypto" },
    { pattern: /require\(\s*['"]crypto['"]\s*\)/, name: "crypto",
      why: "browserify substitutes the whole crypto-browserify shim, which contains elliptic; " +
           "use create-hash for a digest, or Web Crypto" },
    { pattern: /require\(\s*['"]@fidm\/x509['"]\s*\)/, name: "@fidm/x509",
      why: "requires 'crypto', so it drags crypto-browserify and elliptic in with it" }
  ];
  const offences = [];
  // Recursive: client/src has subdirectories (env, vendor_claims), and a bundle
  // reaches whatever any of its requires reach, at any depth.
  const files = [];
  (function walk(dir, label) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, label);
      } else if (/\.js$/.test(entry.name)) {
        files.push({ path: full, label: label + "/" + path.relative(dir, full) });
      }
    });
  })(srcDir, "client/src");
  extraDirs.forEach(function (dir) {
    walkExtra(dir, path.relative(path.join(__dirname, ".."), dir));
  });
  function walkExtra(dir, label) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walkExtra(full, label + "/" + entry.name);
      else if (/\.js$/.test(entry.name)) files.push({ path: full, label: label + "/" + entry.name });
    });
  }
  assert.ok(files.length > 0, "found no .js files in client/src");
  // The staged directories must actually have been read, or this check reports a
  // pass over files it never opened — the silent-no-op failure mode.
  extraDirs.forEach(function (dir) {
    const rel = path.relative(path.join(__dirname, ".."), dir);
    assert.ok(files.some(function (f) { return f.label.indexOf(rel) === 0; }),
      "found no .js files under " + rel + ", which is staged into a bundle and must be scanned");
  });
  files.forEach(function (file) {
    const text = fs.readFileSync(file.path, "utf8");
    text.split("\n").forEach(function (line, index) {
      // Comments in these files discuss the banned requires on purpose (that is
      // where the reasoning lives), so a commented line is not an offence.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      banned.forEach(function (rule) {
        if (rule.pattern.test(line)) {
          offences.push(file.label + ":" + (index + 1) + " requires " + rule.name +
                        " — " + rule.why);
        }
      });
    });
  });
  assert.deepStrictEqual(offences, [],
    "these requires put elliptic (GHSA-848j-6mx2-7j84, no patched version exists) back into a " +
    "browser bundle:\n  " + offences.join("\n  "));

  // And the packages themselves are gone from client/package.json, so a future
  // `npm install` cannot quietly restore the option.
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "client", "package.json"), "utf8"));
  const declared = Object.assign({}, manifest.dependencies, manifest.devDependencies);
  ["jwk-to-pem", "jsonwebtoken", "@fidm/x509"].forEach(function (name) {
    assert.ok(!declared[name],
      "client/package.json still declares " + name + ", which reaches elliptic; it was removed " +
      "deliberately and nothing in client/src requires it");
  });
  assert.ok(declared["create-hash"],
    "client/package.json must declare create-hash — debugger.js requires it for the PKCE " +
    "code_challenge, and it is currently only present as a transitive dependency of browserify");
  log.info("[bundles] OK — " + files.length + " files in client/src plus the staged directories (" +
    extraDirs.map(function (d) { return path.relative(path.join(__dirname, ".."), d); }).join(", ") +
    "), none requiring a package that " +
           "reaches elliptic, and none of those packages declared.");
  log.debug("Leaving ellipticStaysOutOfTheBundles().");
}


async function test() {
  log.debug("Entering test().");
  rsaKeys();
  derIntegerRules();
  ecKeys();
  trimmedCoordinateIsRepadded();
  derLengthsAreWellFormed();
  refusals();
  privateMembersAreIgnored();
  ellipticStaysOutOfTheBundles();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("jwk_pem")
  .description("Verify client/src/jwk_pem.js encodes JWK public keys as correct SPKI PEMs.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
