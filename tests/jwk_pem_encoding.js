// File: jwk_pem.js
//
// client/src/jwk_pem.js — a JWK public key encoded as a SubjectPublicKeyInfo
// PEM, which is what the JWKS page displays under "PEM Format".
//
// Why this module exists at all, and therefore why this test does: the page
// used to get that encoding from the `jwk-to-pem` package, which builds the EC
// point through `elliptic`. browserify bundles what a page requires, so
// `elliptic` shipped to the browser — and `elliptic` carries
// GHSA-848j-6mx2-7j84 (ECDSA signatures with a leading-zero `k` are computed
// with a truncated byte length, which can expose the private key) with NO
// patched version in existence: the advisory's range is `<=6.6.1` and 6.6.1 is
// the latest release. There is nothing to upgrade to, so the fix was to stop
// needing the package.
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
//     stronger oracle than matching `jwk-to-pem`'s bytes would have been, and
//     it does not need that package installed to run: agreeing with a second
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

// The two source sweeps below read the WHOLE of client/src, so "that directory
// exists" is not the question they need answered — "is this a checkout" is. The
// tests image stages most borrowed modules FLAT beside these scripts, but it
// also mirrors eleven Kerberos bundles into /usr/src/client/src, because the
// two Kerberos pane tests resolve their files as ../client/src (see
// tests/Dockerfile). A guard on the directory therefore stopped skipping the
// moment that mirror appeared, and the elliptic sweep ran over eleven files it
// had never been meant to judge before dying on client/package.json, which no
// mirror carries — a failure naming a manifest for what is really a layout.
//
// That manifest is the discriminator precisely because it sits OUTSIDE
// client/src: no mirror of that directory can ever contain it, and a checkout
// cannot lack it. Returns the directory to sweep, or undefined in the image.
function checkoutSrcDir() {
  log.debug("Entering checkoutSrcDir().");
  const manifest = path.join(__dirname, "..", "client", "package.json");
  if (!fs.existsSync(manifest)) {
    log.debug("Leaving checkoutSrcDir(). No " + manifest + ".");
    return undefined;
  }
  const dir = path.join(__dirname, "..", "client", "src");
  log.debug("Leaving checkoutSrcDir(). " + dir);
  return dir;
}

// In a checkout the module is at client/src/jwk_pem.js; the tests image copies
// it flat next to the test scripts (see tests/Dockerfile).
var jwkToPem = paths.requireSharedModule(
  [__dirname + "/../client/src/jwk_pem.js", __dirname + "/jwk_pem.js"],
   "jwk_pem.js");

// The module uses atob/btoa (browser globals). Node has had both since 16, but
// assert it rather than discover a ReferenceError three functions deep.
assert.strictEqual(typeof atob, "function", "this node has no global atob()");
assert.strictEqual(typeof btoa, "function", "this node has no global btoa()");


// --- the oracles ------------------------------------------------------------

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
                     "base64");
}

// The outer SEQUENCE must declare exactly the bytes that follow it — no more,
// no fewer. This is checked on EVERY key rather than a sample because node's
// SPKI parser TOLERATES TRAILING BYTES: a DER with junk appended parses fine
// and recovers the right key, so the round trip alone cannot see it. A mutation
// that appended a byte to the encoding survived until this check was hoisted
// here.
function assertOuterLengthConsistent(pem, label) {
  log.debug("Entering assertOuterLengthConsistent().");
  const der = derOf(pem);
  assert.strictEqual(der[0], 0x30, label +
                     ": SPKI does not start with a SEQUENCE tag");
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
    label + ": the SEQUENCE declares " + declared +
        " content bytes but the encoding carries " +
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
    recovered = crypto.createPublicKey({ key: pem, format: "pem",
        type: "spki" })
                      .export({ format: "jwk" });
  } catch (e) {
    assert.fail(label +
                ": node could not parse the SPKI this module produced: " +
                e.message);
  }
  const interesting = (j) => {
    log.debug("Entering interesting().");
    const out = {};
    Object.keys(j).sort().forEach(function (k) {
      if (k === "key_ops" || k === "ext" || k === "alg" || k === "use" ||
          k === "kid") return;
      out[k] = j[k];
    });
    log.debug("Leaving interesting().");
    return out;
  };
  assert.deepStrictEqual(interesting(recovered), interesting(jwk),
    label +
        ": the key node recovered from the PEM is not the key that went in");
  log.debug("Leaving roundTripsThroughNode().");
  return pem;
}

function generatedJwk(type, options) {
  log.debug("Entering generatedJwk().");
  log.debug("Leaving generatedJwk().");
  return crypto.generateKeyPairSync(type,
      options).publicKey.export({ format: "jwk" });
}


// --- the checks -------------------------------------------------------------

function rsaKeys() {
  log.debug("Entering rsaKeys().");
  log.info("[rsa] Encoding RSA public keys and reading them back with node's " +
           "SPKI parser.");
  // Several sizes, and enough 2048 samples that both DER-INTEGER cases (high
  // bit set, needing the 0x00 sign byte, and not set) are certain to be
  // covered.
  [1024, 2048, 3072, 4096].forEach(function (bits) {
    const jwk = generatedJwk("rsa", { modulusLength: bits });
    const pem = roundTripsThroughNode(jwk, "RSA " + bits);
    assert.ok(/^-----BEGIN PUBLIC KEY-----\n/.test(pem), "RSA " + bits +
              ": missing PEM header");
    assert.ok(/-----END PUBLIC KEY-----\n$/.test(pem), "RSA " + bits +
              ": missing PEM footer");
    pem.split("\n").slice(1, -2).forEach(function (line) {
      assert.ok(line.length <= 64, "RSA " + bits +
                ": base64 line longer than 64 characters");
    });
  });

  for (let i = 0; i < 12; i++) {
    roundTripsThroughNode(generatedJwk("rsa", { modulusLength: 2048 }),
                          "RSA 2048 sample " + i);
  }
  log.info("[rsa] OK — four key sizes and 12 further 2048-bit keys all " +
           "parsed back to the key " +
           "they came from, with well-formed PEM framing.");
  log.debug("Leaving rsaKeys().");
}

// The DER INTEGER rules, exercised deliberately rather than hoped for.
//
// A generated RSA modulus cannot cover them: a modulus of exactly 2048 bits
// always has its top bit set, so real keys only ever take the sign-byte branch
// (an earlier version of this test asserted otherwise and was simply wrong).
// The other branches are reached with crafted moduli. They matter because the
// failure mode is silent — a modulus encoded without its sign byte reads as a
// NEGATIVE integer, which is a different number, so the key is wrong rather
// than rejected.
function derIntegerRules() {
  log.debug("Entering derIntegerRules().");
  log.info("[integer] Checking DER INTEGER minimal encoding and the " +
           "sign byte.");

  function modulusEncodedAs(nBytes) {
    log.debug("Entering modulusEncodedAs().");
    const pem = jwkToPem({
      kty: "RSA",
      n: Buffer.from(nBytes).toString("base64url"),
      e: "AQAB"
    });
    log.debug("Leaving modulusEncodedAs().");
    return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
                       "base64");
  }

  // Each case: the modulus bytes going in, and the INTEGER *contents* that must
  // come out. Trailing bytes are arbitrary padding to keep the values distinct.
  const tail = [0x11, 0x22, 0x33, 0x44];
  const cases = [
    { what: "high bit set — needs a 0x00 sign byte so it does not read " +
     "as negative",
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
      wanted.toString("hex") + " but it does not — full DER " +
                      der.toString("hex"));
    // And the un-normalised form must NOT be there, or "contains the right
    // bytes" could pass while the wrong encoding sits beside it.
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
  const realDer = Buffer.from(realKey.replace(/-----[^-]+-----/g,
      "").replace(/\s+/g, ""), "base64");
  assert.ok(realDer.includes(Buffer.from([0x02, 0x03, 0x01, 0x00, 0x01])),
    "the public exponent 65537 should encode as INTEGER 02 03 01 00 01, with " +
        "no sign byte");
  assert.ok(!realDer.includes(Buffer.from([0x02, 0x04, 0x00, 0x01, 0x00,
            0x01])),
    "the public exponent gained a sign byte it does not need");

  log.info("[integer] OK — " + cases.length +
           " crafted moduli plus the real exponent all encode " +
           "minimally, with the sign byte exactly where it belongs.");
  log.debug("Leaving derIntegerRules().");
}

function ecKeys() {
  log.debug("Entering ecKeys().");
  log.info("[ec] Encoding EC public keys on every supported curve.");
  assert.deepStrictEqual(jwkToPem.SUPPORTED_CURVES.slice().sort(), ["P-256",
                         "P-384", "P-521"],
    "the supported curve list changed — jwk-to-pem covered exactly " +
        "these three");
  jwkToPem.SUPPORTED_CURVES.forEach(function (crv) {
    for (let i = 0; i < 10; i++) {
      roundTripsThroughNode(generatedJwk("ec", { namedCurve: crv }), crv +
                            " sample " + i);
    }
  });
  log.info("[ec] OK — P-256, P-384 and P-521 all round-trip.");
  log.debug("Leaving ecKeys().");
}

// RFC 7518 sections 6.2.1.2/6.2.1.3: a coordinate is the full field size,
// zero-padded on the LEFT. Publishers do sometimes trim a leading zero, and an
// unpadded coordinate is a DIFFERENT POINT — so the failure is a key that is
// quietly wrong, not a key that is rejected. Forge the case rather than wait
// for it: take a key whose x starts with 0x00 and strip it, as a careless
// publisher would, then require the recovered x to be the original.
function trimmedCoordinateIsRepadded() {
  log.debug("Entering trimmedCoordinateIsRepadded().");
  log.info("[padding] A publisher that trimmed a leading zero from a " +
           "coordinate must still " +
           "produce the original point.");
  let tested = 0;
  for (let attempt = 0; attempt < 6000 && tested < 3; attempt++) {
    const jwk = generatedJwk("ec", { namedCurve: "P-256" });
    const xBytes = Buffer.from(jwk.x, "base64url");
    if (xBytes[0] !== 0x00) continue;
    const trimmed = Object.assign({}, jwk,
        { x: xBytes.subarray(1).toString("base64url") });
    const recovered = crypto.createPublicKey({ key: jwkToPem(trimmed),
        format: "pem", type: "spki" })
                            .export({ format: "jwk" });
    assert.strictEqual(recovered.x, jwk.x,
      "a coordinate missing its leading zero was not re-padded, so the " +
          "encoded point is wrong");
    assert.strictEqual(recovered.y, jwk.y, "y changed while re-padding x");
    tested++;
  }
  if (tested === 0) {
    // Not a pass and not a failure of the module: P-256 x values start with
    // 0x00 about 1 in 256 times, so 6000 tries missing it means something is
    // off with key generation, and silently reporting OK would hide that.
    assert.fail("no P-256 key with a leading-zero x coordinate turned up in " +
                "6000 tries");
  }
  log.info("[padding] OK — " + tested +
           " trimmed coordinates were re-padded to the correct point.");
  log.debug("Leaving trimmedCoordinateIsRepadded().");
}

// Both DER length forms, named explicitly. The single-byte form covers content
// under 128 bytes (a P-256 key) and the long form 0x82 xx xx appears above 255
// (a 4096-bit modulus), so a length encoder broken in only one of the two would
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
  log.info("[der] OK — declared lengths match the content, in both the short " +
           "and long forms.");
  log.debug("Leaving derLengthsAreWellFormed().");
}

// The JWKS page catches a throw to mark one key unrenderable and keep the rest
// of the table. That only works if unsupported input throws rather than
// returning something PEM-shaped, and the message has to name the type for the
// page to say anything useful.
function refusals() {
  log.debug("Entering refusals().");
  log.info("[refusals] Unsupported and malformed keys must throw, naming " +
           "the cause.");
  const cases = [
    [{ kty: "OKP", crv: "Ed25519",
     x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
     /Unsupported key type "OKP"/],
    [{ kty: "oct", k: "AAAA" }, /Unsupported key type "oct"/],
    [{ kty: "EC", crv: "secp256k1", x: "AAAA", y: "AAAA" },
     /Unsupported curve "secp256k1"/],
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
      x: Buffer.concat([Buffer.from([1]), Buffer.from(jwk.x,
                       "base64url")]).toString("base64url")
    }));
  }, /too long for P-256/,
      "an over-long coordinate should be refused, not truncated");
  log.info("[refusals] OK — " + (cases.length + 1) +
           " bad inputs all throw with a named cause.");
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
    "encoding a private JWK differed from encoding its public half — d " +
        "leaked into the output");
  const recovered = crypto.createPublicKey({ key: pem, format: "pem",
      type: "spki" })
                          .export({ format: "jwk" });
  assert.ok(!recovered.d,
            "the encoded key still carries the private component");
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
  log.info("[bundles] Reading client/src for the requires that pull " +
           "`elliptic` into a bundle.");
  const srcDir = checkoutSrcDir();
  if (!srcDir) {
    // The tests image copies individual modules flat and carries only a partial
    // mirror of client/src, so there is nothing here worth reading. Say so
    // rather than reporting a pass over eleven Kerberos bundles.
    log.info("[bundles] SKIPPED — no client/package.json in this layout, so " +
             "this is the tests image (which carries only a partial mirror " +
             "of client/src) rather than a checkout.");
    log.debug("Leaving ellipticStaysOutOfTheBundles().");
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
  //
  // common/spiffe and common/xmldsig.js are staged the same way and are read
  // here for the same reason. xmldsig.js is the one that would otherwise have
  // slipped out of this check entirely: it USED to live in client/src and was
  // moved to common/ when api/server.js started signing with it, and a scan
  // that only reads client/src would have gone on reporting a pass over a
  // module it no longer looks at — while that module is still browserified
  // into nine bundles.
  const extraDirs = [path.join(__dirname, "..", "common", "krb5"),
                     path.join(__dirname, "..", "common", "spiffe")]
    .filter(function (d) { return fs.existsSync(d); });
  const extraFiles = [path.join(__dirname, "..", "common", "xmldsig.js")]
    .filter(function (f) { return fs.existsSync(f); });
  const banned = [
    { pattern: /require\(\s*['"]jwk-to-pem['"]\s*\)/, name: "jwk-to-pem",
      why: "builds its EC point through elliptic; use ./jwk_pem instead" },
    { pattern: /require\(\s*['"]jsonwebtoken['"]\s*\)/, name: "jsonwebtoken",
      why: "reaches elliptic via jwa -> crypto -> crypto-browserify; " +
          "decoding a JWT needs no crypto" },
    { pattern: /require\(\s*['"]crypto['"]\s*\)/, name: "crypto",
      why: "browserify substitutes the whole crypto-browserify shim, which " +
          "contains elliptic; " +
           "use create-hash for a digest, or Web Crypto" },
    { pattern: /require\(\s*['"]@fidm\/x509['"]\s*\)/, name: "@fidm/x509",
      why: "requires 'crypto', so it drags crypto-browserify and elliptic " +
          "in with it" }
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
  extraFiles.forEach(function (file) {
    files.push({ path: file,
                 label: path.relative(path.join(__dirname, ".."), file) });
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
  // The same non-vacuity check for the single staged FILES, and it matters
  // more for them: a directory that vanishes is obvious, whereas a file that
  // moves again leaves this list quietly naming nothing.
  extraFiles.forEach(function (file) {
    const rel = path.relative(path.join(__dirname, ".."), file);
    assert.ok(files.some(function (f) { return f.label === rel; }),
      "found no " + rel + ", which is staged into nine bundles and must " +
      "be scanned");
  });
  files.forEach(function (file) {
    const text = fs.readFileSync(file.path, "utf8");
    text.split("\n").forEach(function (line, index) {
      // Comments in these files discuss the banned requires on purpose (that is
      // where the reasoning lives), so a commented line is not an offence.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      banned.forEach(function (rule) {
        if (rule.pattern.test(line)) {
          offences.push(file.label + ":" + (index + 1) +
                        " requires " + rule.name +
                        " — " + rule.why);
        }
      });
    });
  });
  assert.deepStrictEqual(offences, [],
    "these requires put elliptic (GHSA-848j-6mx2-7j84, no patched version " +
        "exists) back into a " +
    "browser bundle:\n  " + offences.join("\n  "));

  // And the packages themselves are gone from client/package.json, so a future
  // `npm install` cannot quietly restore the option.
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..",
      "client", "package.json"), "utf8"));
  const declared = Object.assign({}, manifest.dependencies,
      manifest.devDependencies);
  ["jwk-to-pem", "jsonwebtoken", "@fidm/x509"].forEach(function (name) {
    assert.ok(!declared[name],
      "client/package.json still declares " + name +
          ", which reaches elliptic; it was removed " +
      "deliberately and nothing in client/src requires it");
  });
  assert.ok(declared["create-hash"],
    "client/package.json must declare create-hash — oauth2_oidc_1.js " +
            "requires it for the PKCE " +
    "code_challenge, and it is currently only present as a transitive " +
            "dependency of browserify");
  var stagedNames = extraDirs.concat(extraFiles).map(function (p) {
    return path.relative(path.join(__dirname, ".."), p);
  });
  log.info("[bundles] OK — " + files.length + " files in client/src plus " +
           "the staged " + stagedNames.join(", ") + ", none requiring a " +
           "package that reaches elliptic, and none of those packages " +
           "declared.");
  log.debug("Leaving ellipticStaysOutOfTheBundles().");
}


// A BigInt LITERAL — 0n, 8n, 0xffn — anywhere in client/src is a client image
// that will not build, and the failure names neither the literal nor the change
// that exposed it.
//
// browserify runs the envify transform over every file in a bundle that
// references `process.env`, and envify parses with an esprima build old enough
// to predate BigInt literals: it rejects one as "Line NNN: Unexpected token
// ILLEGAL". So the literal is harmless right up until the file acquires a
// `process.env` reference, or is required by something that has one — at which
// point the build fails with a syntax error against a file nobody touched, in
// the bundle of whichever page happens to reach it.
//
// That is not hypothetical. bbs.js carried `0n`/`8n`/`0xffn` for months while
// nothing in it mentioned `process`; giving it a log level broke
// `browserify src/vc_presentation_2.js` — three requires away — on line 104 of
// bbs.js. digital_signature.js had already been through the same thing and
// carries the same fix.
//
// So the rule is stated as "none in client/src" rather than "none in a file that
// mentions process.env": the trigger is not a property of the file, and a rule
// that depends on it is a rule that passes until the day it matters. The fix is
// always the same and costs nothing — `var _B0 = BigInt(0)` once, and use it.
function bigIntLiteralsStayOutOfTheBundles() {
  log.debug("Entering bigIntLiteralsStayOutOfTheBundles().");
  log.info("[bigint] Reading client/src for BigInt literals, which envify's " +
           "esprima cannot parse.");
  const srcDir = checkoutSrcDir();
  if (!srcDir) {
    log.info("[bigint] SKIPPED — no client/package.json in this layout, so " +
             "this is the tests image (which carries only a partial mirror " +
             "of client/src) rather than a checkout.");
    log.debug("Leaving bigIntLiteralsStayOutOfTheBundles().");
    return;
  }
  // `0xffn` / `8n`, but not an identifier ending in n, a property, or a decimal.
  const BIGINT = /(^|[^\w$.])(0[xX][0-9a-fA-F]+|\d+)n(?![\w$])/;
  const files = [];
  (function walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.js$/.test(entry.name)) {
        files.push(path.relative(srcDir, full));
      }
    });
  })(srcDir);
  assert.ok(files.length > 0, "found no .js files in client/src");
  const offences = [];
  files.forEach(function (file) {
    const text = fs.readFileSync(path.join(srcDir, file), "utf8");
    text.split("\n").forEach(function (line, index) {
      // As above: the two files that carry the fix explain it in prose, and
      // naming `0n` while telling you not to write it is not writing it.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      if (BIGINT.test(line)) {
        offences.push("client/src/" + file + ":" + (index + 1) + "  " +
                      line.trim().slice(0, 90));
      }
    });
  });
  assert.deepStrictEqual(offences, [],
    "these BigInt literals will fail `browserify` with \"Unexpected token " +
        "ILLEGAL\" as soon as\n" +
    "anything in their bundle references process.env. Write BigInt(0) " +
        "instead:\n  " +
    offences.join("\n  "));
  log.info("[bigint] OK — " + files.length +
           " files in client/src, no BigInt literals.");
  log.debug("Leaving bigIntLiteralsStayOutOfTheBundles().");
}


// client/src/coverage_beacon.js is the one file here that is NOT browserified.
// The Dockerfile's coverage step appends it to each finished bundle with
//   cat src/coverage_beacon.js >> public/js/${src_name}.js
// so it never passes through browserify or envify at all: in the browser it is
// raw script text, where `require` and `process` do not exist. A `require` in
// it is therefore not a module import but an uncaught ReferenceError on every
// instrumented page.
//
// That is not hypothetical either. The 2026-08-14 style sweep gave it the
// standard bunyan logger, and `require("bunyan")` at its top level threw before
// setInterval() was ever reached — so `./run-coverage.sh` shipped NO frontend
// coverage (an empty coverage/frontend/.nyc_output, a 0-byte lcov.info) and
// failed the 12 tests that assert the browser console is clean. None of those
// 12 named the beacon, coverage, or a require; they named a page.
//
// This check lives in the ordinary suite rather than in the coverage build
// because that is the whole problem: the plain launchers never append this
// file, so nothing outside `./run-coverage.sh` can see the breakage, and that
// is not what anybody runs after an edit. Console-backed `log` shim only — see
// the note in the file itself and the list in the repo-root CLAUDE.md.
function appendedBeaconNeedsNoModuleSystem() {
  log.debug("Entering appendedBeaconNeedsNoModuleSystem().");
  log.info("[beacon] Reading client/src/coverage_beacon.js, which is " +
           "appended to bundles raw, for module-system references.");
  const beacon = path.join(__dirname, "..", "client", "src",
      "coverage_beacon.js");
  if (!fs.existsSync(beacon)) {
    // Same reason as the two checks above: the tests image copies individual
    // modules flat and does not carry this one. Say so rather than pass
    // quietly.
    log.info("[beacon] SKIPPED — no client/src/coverage_beacon.js in this " +
             "layout (running from the tests image).");
    log.debug("Leaving appendedBeaconNeedsNoModuleSystem().");
    return;
  }
  // Comments in this file name `require("bunyan")` and `process` on purpose —
  // that is where the reasoning lives — so strip the comments rather than
  // skipping whole lines: the point of the file is a shim whose explanation
  // quotes the very thing it must not do.
  const text = fs.readFileSync(beacon, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^[ \t]*\/\/.*$/gm, "")
    .replace(/[ \t]+\/\/.*$/gm, "");
  const banned = [
    { pattern: /\brequire\s*\(/, name: "require(",
      why: "browserify never sees this file, so `require` is undefined in " +
          "the browser" },
    { pattern: /\bprocess\s*\./, name: "process.",
      why: "envify never sees this file either, so `process` is undefined in " +
          "the browser" },
    { pattern: /\bmodule\s*\.\s*exports\b/, name: "module.exports",
      why: "there is no module wrapper around this file once it is appended" }
  ];
  const offences = [];
  banned.forEach(function (rule) {
    if (rule.pattern.test(text)) {
      offences.push(rule.name + " — " + rule.why);
    }
  });
  assert.deepStrictEqual(offences, [],
    "client/src/coverage_beacon.js is APPENDED to already-browserified " +
        "bundles (see the\n" +
    "COVERAGE block in client/Dockerfile), so each of these is an uncaught " +
        "ReferenceError\n" +
    "on every instrumented page — which empties the frontend coverage " +
        "report and fails\n" +
    "every test that asserts a clean browser console:\n  " +
    offences.join("\n  "));
  // And it must still have a logger of the shape the convention expects, or the
  // next sweep will "fix" its absence by adding bunyan back.
  assert.ok(/var\s+log\s*=\s*\{/.test(text),
    "client/src/coverage_beacon.js has no console-backed `log` shim; the " +
        "logging convention " +
    "cannot reach bunyan from a file appended raw to a bundle, so the shim " +
        "is what keeps " +
    "somebody from adding one");
  log.info("[beacon] OK — no require/process/module.exports, and the " +
           "console-backed log shim is present.");
  log.debug("Leaving appendedBeaconNeedsNoModuleSystem().");
}


// ---------------------------------------------------------------------------
// No two files may land on the same path in the tests image.
//
// tests/Dockerfile copies test scripts AND the modules they exercise FLAT into one
// directory. Two files sharing a basename therefore overwrite each other, and which one
// survives depends only on which COPY ran last. Both outcomes are bad and one of them is
// silent:
//
//   * the MODULE wins  — `node <name>.js` loads a module, prints nothing, exits 0, and
//     run-report records a PASS. The test has not run. This is the dangerous one, and it
//     had happened three times over: dpop.js, jose_jwe.js and url_safety.js were each
//     reporting green in ~30ms while executing a module. Renamed, they take 231ms, 709ms
//     and 46ms and assert thousands of things.
//   * the TEST wins    — the module is replaced by a test script, so everything that
//     requires it gets a file with no exports. krb5_pac.js did this and took five other
//     Kerberos jobs down with it, because krb5_describe.js requires it.
//
// The convention that avoids it is to give the TEST a distinguishing name — the module
// keeps its own, since other code imports it: jwk_pem.js is tested by jwk_pem_encoding.js,
// krb5_crypto.js by krb5_crypto_vectors.js, krb5_pac.js by krb5_pac_layout.js. The
// Dockerfile has said so in a comment for a long time; a comment is not a check, and this
// is the check.
//
// Runs in a checkout, where tests/Dockerfile is readable; skipped with a reason in the
// image, where it is not.
// ---------------------------------------------------------------------------
function testsImageHasNoCollidingFilenames() {
  log.debug("Entering testsImageHasNoCollidingFilenames().");
  const dockerfile = path.join(__dirname, "Dockerfile");
  if (!fs.existsSync(dockerfile)) {
    log.info("[collisions] skipped: tests/Dockerfile is not present, so this is the tests image " +
      "rather than a checkout.");
    log.debug("Leaving testsImageHasNoCollidingFilenames().");
    return;
  }
  const flat = {};
  fs.readFileSync(dockerfile, "utf8").split("\n").forEach(function (line) {
    const text = line.trim();
    if (text.indexOf("COPY ") !== 0) return;
    const parts = text.slice(5).split(/\s+/).filter(Boolean);
    if (parts.length < 2) return;
    const dest = parts[parts.length - 1];
    // Only the flat destination collides; "./sts/" and "./contexts" are directories of
    // their own and a basename may legitimately repeat across them.
    if (dest !== "./" && dest !== ".") return;
    parts.slice(0, -1).forEach(function (src) {
      if (!/\.js$/.test(src)) return;
      const base = src.split("/").pop();
      if (!flat[base]) flat[base] = [];
      flat[base].push(src);
    });
  });

  const collisions = Object.keys(flat).filter(function (base) { return flat[base].length > 1; })
    .map(function (base) { return base + " <- " + flat[base].join(" and "); });
  assert.deepStrictEqual(collisions, [],
    "these files are copied FLAT into the tests image under the same name, so the last COPY " +
    "silently overwrites the earlier one: " + collisions.join(" | ") +
    ". Give the TEST a distinguishing name (jwk_pem.js is tested by jwk_pem_encoding.js, " +
    "krb5_crypto.js by krb5_crypto_vectors.js) — the module keeps its own name because other " +
    "code requires it. If the module wins, the test silently passes in ~30ms without running; " +
    "if the test wins, everything requiring that module breaks.");

  // ...and every script run-report names must actually REACH the image. A job whose
  // script was never COPYd fails with MODULE_NOT_FOUND in 0.0s, which reads as a broken
  // test rather than a missing line in a Dockerfile — krb5_as_exchange.js was in the
  // suite for four phases and in the image for none of them, passing on every host run.
  const report = path.join(__dirname, "run-report.js");
  if (fs.existsSync(report)) {
    const copied = {};
    Object.keys(flat).forEach(function (base) { copied[base] = true; });
    // The image also copies whole globs (tests/oauth2_*, tests/oidc_*); expand them the
    // same way Docker does, by prefix.
    const globs = [];
    fs.readFileSync(dockerfile, "utf8").replace(/COPY\s+([^\n]+)/g, function (_, rest) {
      rest.split(/\s+/).forEach(function (src) {
        if (src.indexOf("tests/") === 0 && src.indexOf("*") !== -1) {
          globs.push(src.slice("tests/".length).replace("*", ""));
        }
      });
      return _;
    });
    const scripts = [];
    fs.readFileSync(report, "utf8").replace(/script:\s*"([^"]+)"/g, function (_, name) {
      if (scripts.indexOf(name) === -1) scripts.push(name);
      return _;
    });
    const absent = scripts.filter(function (name) {
      if (copied[name]) return false;
      return !globs.some(function (prefix) { return name.indexOf(prefix) === 0; });
    });
    assert.deepStrictEqual(absent, [],
      "run-report.js schedules these scripts and tests/Dockerfile never copies them into the " +
      "image, so each fails there with MODULE_NOT_FOUND in 0.0s while passing on every host " +
      "run: " + absent.join(", "));
  }

  const total = Object.keys(flat).length;
  log.info("[collisions] OK — " + total + " files are copied flat into the tests image, every " +
    "one has a unique name, and every script run-report schedules is among them.");
  stsModuleClosureIsCopied(dockerfile);
  flatCopiedModulesHaveTheirPackages(dockerfile);
  log.debug("Leaving testsImageHasNoCollidingFilenames().");
}

// ---------------------------------------------------------------------------
// EVERY sts/*.js THIS IMAGE COPIES MUST BRING ITS OWN REQUIRES WITH IT.
//
// Four tests load modules out of the mock STS submodule in process rather than
// over HTTP — the mock-KDC jobs — so tests/Dockerfile copies a hand-picked set
// of sts/*.js into ./sts/. A hand-picked set is exactly what goes stale, and it
// goes stale WITHOUT THIS FILE OR THAT ONE CHANGING: the closure moves when the
// sts/ GITLINK moves, because the mock gave a module it already had a new
// `require`. It has happened four times, and tests/Dockerfile carries a
// paragraph for each — admin_stats.js, config.js, audit.js, and then the RFC
// 9700 bump, which gave app.js a require on ./oauth2_bcp and three others one
// on ./applications.
//
// Every one of those failed the same way and none of them named the fix:
// "Cannot find module './applications'" thrown at require time from inside a
// file the image HAS, before a single test ran, while every host run stayed
// green because a checkout has the whole submodule.
//
// So this walks it instead of listing it. Seed with what the Dockerfile copies,
// follow each relative require, and require the result to be a subset of what
// is copied. It reads the Dockerfile as STATEMENTS rather than lines for the
// reason the file header gives: a check a reformat can silence is a check that
// will be silenced.
//
// **AND IT FOLLOWS `../` AS WELL AS `./`, WHICH IT DID NOT USED TO NEED TO.**
// Every module in that repository sat in its root until mock-sts 0f986b3
// ("Reorganizing source code."), so every intra-mock require was `./x` and a
// walker that only understood `./` saw the whole graph. After the move, the
// cross-directory ones are `../common/app` — and a `./`-only walker would have
// followed NOTHING between directories, reported "OK, every require resolves"
// over a set it never traversed, and let exactly the failure it exists for
// through. That is this project's recurring defect (a check that quietly does
// nothing) hiding inside the check written to prevent another one, so the
// names below are kept as PATHS relative to the mock's root and resolved the
// way node resolves them.
// ---------------------------------------------------------------------------
function stsModuleClosureIsCopied(dockerfile) {
  log.debug("Entering stsModuleClosureIsCopied().");
  const stsDir = path.join(__dirname, "..", "sts");
  if (!fs.existsSync(stsDir)) {
    log.info("[sts-closure] skipped: sts/ is not checked out here.");
    log.debug("Leaving stsModuleClosureIsCopied().");
    return;
  }
  // What the image copies out of sts/, whatever the destination — ./sts/ for
  // most of them, but bbs2023.js lands flat as sts_bbs2023.js and is required
  // by that name, so the SOURCE is what matters here, not where it lands.
  const copied = {};
  // ANCHORED AT THE START OF A LINE, and that is not tidiness. An unanchored
  // /COPY\s+/ also matches the word COPY inside a COMMENT — and this file is
  // full of comments quoting the build error a missing COPY produces — so a
  // sentence like `so \`COPY sts/krb5_kdc.js … ./sts/\` put a file next to` was
  // read as an instruction and reported as a copied module that the submodule
  // does not have. Docker requires the instruction at the start of a line and
  // no COPY here uses a backslash continuation, so this is also the correct
  // reading of the file.
  const copyLine = /^COPY\s+([^\n]+)/gm;
  fs.readFileSync(dockerfile, "utf8").replace(copyLine, function (_, rest) {
    rest.split(/\s+/).forEach(function (src) {
      if (src.indexOf("sts/") === 0 && /\.js$/.test(src)) {
        copied[src.slice("sts/".length)] = true;
      }
    });
    return _;
  });
  const seen = {};
  const queue = Object.keys(copied);
  const missing = [];
  while (queue.length) {
    const name = queue.shift();
    if (seen[name]) {
      continue;
    }
    seen[name] = true;
    const file = path.join(stsDir, name);
    if (!fs.existsSync(file)) {
      // A COPY naming a file the submodule does not have is the OTHER failure
      // in this family: the image build itself stops, rather than a test.
      missing.push(name + " (copied, but absent from the sts/ checkout)");
      continue;
    }
    // COMMENT LINES ARE DROPPED, for the reason the banned-require scan above
    // gives about the files it reads: the mock's comments discuss requires on
    // purpose. `common/worker_pool.js` explains how to reproduce a hang with
    // `node -e "require('./common/crypto')"`, and read as code that is a
    // dependency on `common/common/crypto.js`, which exists nowhere and which
    // no COPY could satisfy.
    const src = fs.readFileSync(file, "utf8").split("\n")
      .filter(function (line) {
        return !/^\s*(\/\/|\*|\/\*)/.test(line);
      }).join("\n");
    // Both `./x` and `../dir/x`, resolved against the requiring file's own
    // directory and normalised back to a path relative to the mock's root —
    // which is the form the COPY sources above are in.
    const re = /require\((['"])(\.\.?\/[A-Za-z0-9_.\/-]+)\1\)/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      let dep = path.posix.normalize(
        path.posix.join(path.posix.dirname(name), m[2]));
      if (!/\.js$/.test(dep)) {
        dep = dep + ".js";
      }
      if (dep.indexOf("..") === 0) {
        // A require reaching outside the mock's own tree. There is none today
        // and one would not be copyable at all, so it is reported rather than
        // silently normalised away.
        missing.push(dep + " (required by sts/" + name + ", and it points " +
          "outside the mock's own tree)");
        continue;
      }
      if (!copied[dep]) {
        missing.push(dep + " (required by sts/" + name + ")");
        continue;
      }
      if (!seen[dep]) {
        queue.push(dep);
      }
    }
  }
  const unique = missing.filter(function (v, i) {
    return missing.indexOf(v) === i;
  });
  assert.deepStrictEqual(unique, [],
    "tests/Dockerfile copies sts modules whose own requires it does " +
    "not copy, so the in-process mock-KDC jobs die at load with " +
    "\"Cannot find module\" naming a file this image HAS. This set moves " +
    "when the sts/ GITLINK moves, not when a line here changes — add a " +
    "COPY sts/<dir>/<name> ./sts/<dir>/ for each (the destination has to " +
    "MIRROR the mock's own folder, or a require of ../common/x lands " +
    "outside the image's sts/ tree): " + unique.join(", "));
  log.info("[sts-closure] OK — " + Object.keys(seen).length + " sts " +
    "modules are copied and every relative require among them resolves " +
    "inside the image.");
  log.debug("Leaving stsModuleClosureIsCopied().");
}

// ---------------------------------------------------------------------------
// EVERY MODULE COPIED FLAT MUST HAVE ITS PACKAGES IN tests/package.json.
//
// The check above walks RELATIVE requires; this one walks the other kind, and
// it is a different failure with the same shape. A module copied out of
// client/src or common/ lands beside the test scripts, where the ONLY
// resolution root is tests/node_modules — client/node_modules is not in the
// image at all. So a package the client declares and this package does not is
// a `Cannot find module` at require time, thrown from inside a file the image
// HAS, while every host run stays green because there the module is loaded
// from client/src and resolves against client/node_modules.
//
// That is exactly how `@noble/post-quantum` cost a run on 2026-08-22:
// pk_encryption.js requires `@noble/post-quantum/ml-kem.js` for ML-KEM,
// client/package.json has it, tests/package.json did not, and
// crypto_engines.js — 14 sections of RFC vectors — died before the first one
// with a message naming a package rather than a package.json.
//
// The set moves when a COPIED MODULE GAINS A require, not when a line here
// changes, which is why this walks rather than lists. Only sources from
// OUTSIDE tests/ are checked: a test script's own optional dependency is a
// deliberate thing, whereas a module has no such fallback and no say in where
// it is loaded from. (url_safety_schemes.js used to be the example here; its
// dompurify/jsdom pair is declared now, because "optional" had turned into a
// section that logged SKIPPED on every run and measured nothing.)
// ---------------------------------------------------------------------------
function flatCopiedModulesHaveTheirPackages(dockerfile) {
  log.debug("Entering flatCopiedModulesHaveTheirPackages().");
  const manifest = path.join(__dirname, "package.json");
  if (!fs.existsSync(manifest)) {
    log.info("[deps] skipped: tests/package.json is not present, so this is " +
      "the tests image rather than a checkout.");
    log.debug("Leaving flatCopiedModulesHaveTheirPackages().");
    return;
  }
  const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
  const declared = {};
  ["dependencies", "optionalDependencies"].forEach(function (section) {
    Object.keys(pkg[section] || {}).forEach(function (name) {
      declared[name] = true;
    });
  });
  const builtins = {};
  require("module").builtinModules.forEach(function (name) {
    builtins[name] = true;
  });

  // Only the FLAT destination: a module landing in ./sts/ or
  // /usr/src/client/src resolves from a directory of its own, and
  // client/server.js — copied there to be RUN rather than required — brings
  // the client's own node_modules question with it.
  const sources = [];
  fs.readFileSync(dockerfile, "utf8").split("\n").forEach(function (line) {
    const text = line.trim();
    if (text.indexOf("COPY ") !== 0) {
      return;
    }
    const parts = text.slice(5).split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
      return;
    }
    const dest = parts[parts.length - 1];
    if (dest !== "./" && dest !== ".") {
      return;
    }
    parts.slice(0, -1).forEach(function (src) {
      if (!/\.js$/.test(src)) {
        return;
      }
      if (src.indexOf("tests/") === 0) {
        return;
      }
      if (sources.indexOf(src) === -1) {
        sources.push(src);
      }
    });
  });

  const missing = [];
  const repo = path.join(__dirname, "..");
  sources.forEach(function (src) {
    const file = path.join(repo, src);
    if (!fs.existsSync(file)) {
      // A COPY naming a file this repository has not got stops the image
      // build itself, which is loud; say so here anyway rather than reading
      // it as "no requires".
      missing.push(src + " is copied but absent from this checkout");
      return;
    }
    const text = fs.readFileSync(file, "utf8");
    const re = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const id = m[1];
      if (id.charAt(0) === "." || id.charAt(0) === "/") {
        continue;
      }
      if (builtins[id] || builtins[id.replace(/^node:/, "")]) {
        continue;
      }
      // The package, not the subpath: `@noble/post-quantum/ml-kem.js` is
      // declared as `@noble/post-quantum`.
      const segments = id.split("/");
      const name = id.charAt(0) === "@"
        ? segments.slice(0, 2).join("/") : segments[0];
      if (declared[name]) {
        continue;
      }
      const entry = name + " (required by " + src + ")";
      if (missing.indexOf(entry) === -1) {
        missing.push(entry);
      }
    }
  });
  assert.deepStrictEqual(missing, [],
    "tests/Dockerfile copies these modules FLAT into the image, where the " +
    "only place node can resolve a package is tests/node_modules — and " +
    "tests/package.json does not declare them, so the jobs that load those " +
    "modules die at require with \"Cannot find module\" naming a package. " +
    "A host run cannot see it: there the same module comes from client/src " +
    "and resolves against client/node_modules. Add each to " +
    "tests/package.json with the SAME specifier the owning package.json " +
    "uses, so the image runs the code the browser bundle does: " +
    missing.join(", "));
  log.info("[deps] OK — " + sources.length + " modules are copied flat into " +
    "the tests image and every package they require is declared in " +
    "tests/package.json.");
  log.debug("Leaving flatCopiedModulesHaveTheirPackages().");
}

// ---------------------------------------------------------------------------
// EVERY BUNDLE MUST BE IN ALL THREE LISTS, AND THE THIRD ONE FAILS SILENTLY.
//
// A page's bundle is named in three places that are not near each other:
//
//   1. the `BUNDLES` array in `client/build.js`   — the static deployments,
//   2. a `RUN browserify` line in `client/Dockerfile` — the container image,
//   3. the `for entry in "src:standalone"` loop in that same Dockerfile's
//      COVERAGE block — `./run-coverage.sh`, and nothing else.
//
// Miss (1) and the deployed static site is fine while the containerized page's
// <script> 404s. Miss (2) and the reverse. Both of those are loud: a page that
// does nothing fails its own suite immediately.
//
// **MISS (3) AND NOTHING ANYWHERE FAILS.** The page builds, ships, works and
// passes every test it has; it simply reports no coverage. The only symptom is
// a number in a report nobody diffs, and the plain launchers never execute that
// block at all — so an ordinary run cannot see the gap even in principle.
//
// That is not hypothetical. On 2026-08-22 SEVEN bundles were missing from it —
// all six Kerberos pages plus `pki` — and the Dockerfile had carried a comment
// SAYING six of them were missing for months. A comment is not a check, which
// is the whole reason this function exists rather than a longer comment.
//
// It reads the loop as a STATEMENT rather than as a line, for the reason
// tests/CLAUDE.md records about source-inspection tests: a regex written
// against one line stops seeing the thing it checks the moment somebody wraps
// it, and it then fails by naming the property rather than the formatting.
// ---------------------------------------------------------------------------
function coverageListCoversEveryBundle() {
  log.debug("Entering coverageListCoversEveryBundle().");
  log.info("[bundle lists] Comparing client/build.js's BUNDLES, the " +
           "RUN browserify lines and the coverage loop.");
  const dockerfile = path.join(__dirname, "..", "client", "Dockerfile");
  const buildJs = path.join(__dirname, "..", "client", "build.js");
  if (!fs.existsSync(dockerfile) || !fs.existsSync(buildJs)) {
    // The tests image copies client/Dockerfile in as `client_Dockerfile` and
    // does not carry build.js, so this cannot run there. Say so rather than
    // pass quietly — a check that skips silently is the defect this file is
    // full of notes about.
    log.info("[bundle lists] SKIPPED — client/Dockerfile and/or " +
             "client/build.js are not both present in this layout (running " +
             "from the tests image).");
    log.debug("Leaving coverageListCoversEveryBundle().");
    return;
  }
  const docker = fs.readFileSync(dockerfile, "utf8");
  const build = fs.readFileSync(buildJs, "utf8");

  // (2) The plain build. One RUN per bundle, each naming its source file and
  // its --standalone global.
  const plain = {};
  // Built from a string rather than written as a literal only so it fits in
  // eighty columns; a regex literal cannot be broken across lines.
  const runLine = new RegExp(
    "^RUN browserify src\\/([A-Za-z0-9_]+)\\.js" +
    "[^\\n]*?--standalone ([A-Za-z0-9_]+)", "gm");
  let match = runLine.exec(docker);
  while (match !== null) {
    plain[match[1]] = match[2];
    match = runLine.exec(docker);
  }
  assert.ok(Object.keys(plain).length > 20,
    "Only " + Object.keys(plain).length + " RUN browserify lines were found " +
    "in client/Dockerfile, which cannot be right — this check's own regex " +
    "has probably stopped matching, which would make it pass while testing " +
    "nothing.");

  // (3) The coverage loop, read as a statement: everything between
  // `for entry in` and the `;` that closes it, however it is wrapped.
  const loop = docker.match(/for entry in([\s\S]*?);\s*do/);
  assert.ok(loop,
    "The COVERAGE block's `for entry in ... ; do` loop was not found in " +
    "client/Dockerfile at all. Either it has been removed — in which case " +
    "./run-coverage.sh now instruments nothing — or this check can no longer " +
    "see it.");
  const coverage = {};
  (loop[1].match(/"([^"]+)"/g) || []).forEach(function (quoted) {
    const parts = quoted.slice(1, -1).split(":");
    coverage[parts[0]] = parts[1];
  });

  // (1) build.js's BUNDLES.
  const bundlesBlock = build.match(/const BUNDLES = \[([\s\S]*?)\n\];/);
  assert.ok(bundlesBlock,
    "The BUNDLES array was not found in client/build.js.");
  const bundles = {};
  (bundlesBlock[1].match(/\['([^']+)',\s*'([^']+)'\]/g) || [])
    .forEach(function (entry) {
      const parts = entry.match(/\['([^']+)',\s*'([^']+)'\]/);
      bundles[parts[1]] = parts[2];
    });

  const problems = [];
  Object.keys(plain).forEach(function (name) {
    if (coverage[name] === undefined) {
      problems.push("`" + name + "` is built by client/Dockerfile and is NOT " +
        "in the COVERAGE loop, so ./run-coverage.sh reports nothing for that " +
        "page — silently, because the page still builds and still works.");
    }
    if (bundles[name] === undefined) {
      problems.push("`" + name + "` is built by client/Dockerfile and is NOT " +
        "in client/build.js's BUNDLES, so the static deployments ship a page " +
        "whose <script> 404s.");
    }
  });
  Object.keys(bundles).forEach(function (name) {
    if (plain[name] === undefined) {
      problems.push("`" + name + "` is in client/build.js's BUNDLES and has " +
        "no RUN browserify line in client/Dockerfile, so the containerized " +
        "page's <script> 404s while the static site is fine.");
    }
  });
  Object.keys(coverage).forEach(function (name) {
    if (plain[name] === undefined) {
      problems.push("`" + name + "` is in the COVERAGE loop and is not built " +
        "by any RUN browserify line, so ./run-coverage.sh fails building it.");
    } else if (coverage[name] !== plain[name]) {
      // The --standalone name IS the global the page's inline onclick
      // handlers call, so a disagreement means every click on that page is a
      // silent no-op under coverage and works everywhere else.
      problems.push("`" + name + "` is built --standalone " + plain[name] +
        " normally and --standalone " + coverage[name] + " under coverage. " +
        "That global is what every inline onclick on the page calls, so " +
        "under ./run-coverage.sh every click there is a ReferenceError.");
    }
  });
  assert.deepStrictEqual(problems, [],
    "A page's bundle has to be named in THREE places — client/build.js's " +
        "BUNDLES,\n" +
    "a RUN browserify line in client/Dockerfile, and that file's COVERAGE " +
        "loop.\n" +
    "The third fails SILENTLY, which is why this check exists:\n  " +
    problems.join("\n  "));
  log.info("[bundle lists] OK — " + Object.keys(plain).length +
           " bundle(s), all three lists agree.");
  log.debug("Leaving coverageListCoversEveryBundle().");
}

// ---------------------------------------------------------------------------
// EVERY SCHEDULED JOB MUST DECLARE `--url`, OR IT DIES BEFORE ITS FIRST LINE.
//
// run-report.js spawns each job as `node <script>.js --url <BASE_URL>`, and
// commander exit(1)s on an option it was not told about. A test that has no use
// for a base url — it reads source, or drives modules in process — still has to
// ACCEPT one, or the report carries a job that failed in 0.06s with
// `error: unknown option '--url'` and not one line of the test's own output.
// That reads as a broken runner rather than as a missing option, and it has now
// cost two runs: page_load_retry.js on 2026-08-20, then both SCIM node jobs on
// 2026-08-22. tests/CLAUDE.md has said so since the first one, which is exactly
// why this is a check rather than another paragraph.
//
// A job that parses no arguments at all is fine and is why this looks for
// commander rather than for the option alone: node ignores the pair when
// nothing reads it (crypto_engines.js relies on that, and says so).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A SHARED MODULE IN common/ IS STAGED INTO client/src BY A LIST, AND A LIST
// GOES STALE.
//
// common/xmldsig.js is copied into client/src at build time so the eight
// bundles that `require("./xmldsig")` can resolve it — client/build.js names
// them in XMLDSIG_BUNDLES. Add a ninth consumer and nothing here notices: the
// bundle builds locally (a developer usually has a staged copy lying around)
// and fails in the image with `Cannot find module './xmldsig'`, a message
// naming a file that exists, two directories away. That is precisely how the
// Kerberos list failed when spnego.js was added — the comment above
// KRB5_BUNDLES in build.js records it — so the list gets a check this time
// rather than a comment.
function stagedSharedModuleListsAreComplete() {
  log.debug("Entering stagedSharedModuleListsAreComplete().");
  const srcDir = path.join(__dirname, "..", "client", "src");
  const buildJs = path.join(__dirname, "..", "client", "build.js");
  if (!fs.existsSync(srcDir) || !fs.existsSync(buildJs)) {
    log.info("[staged lists] SKIPPED — this is the tests image, which has no " +
             "client/src tree or build.js to compare.");
    log.debug("Leaving stagedSharedModuleListsAreComplete().");
    return;
  }
  const build = fs.readFileSync(buildJs, "utf8");
  // Every staged module that a bundle reaches by a bare relative require, and
  // the build.js list that is supposed to name its consumers.
  const staged = [
    { module: "xmldsig", list: "XMLDSIG_BUNDLES" },
    { module: "spiffe_id", list: "SPIFFE_BUNDLES" }
  ];
  let checked = 0;
  staged.forEach(function (entry) {
    const m = new RegExp("const " + entry.list +
      "\\s*=\\s*\\[([^\\]]*)\\]").exec(build);
    assert.ok(m, "client/build.js no longer declares " + entry.list +
      ", which is what stages common/" + entry.module + ".js into client/src");
    const declared = (m[1].match(/'[^']+'/g) || [])
      .map(function (q) { return q.slice(1, -1); }).sort();
    // Who actually requires it, read from the source rather than from a list.
    const requires = new RegExp("require\\(\\s*[\"']\\./" +
      entry.module + "(\\.js)?[\"']\\s*\\)");
    const consumers = fs.readdirSync(srcDir)
      .filter(function (f) { return /\.js$/.test(f); })
      .filter(function (f) {
        return requires.test(fs.readFileSync(path.join(srcDir, f), "utf8"));
      })
      .map(function (f) { return f.replace(/\.js$/, ""); });
    // A consumer that is not itself a bundle entry point is reached THROUGH
    // one, and the bundle that reaches it is what has to be in the list — so
    // only compare the ones that are bundles.
    const bundles = new Set((build.match(/\['([a-z0-9_]+)',\s*'[^']*'\]/g) ||
      []).map(function (b) { return /\['([a-z0-9_]+)'/.exec(b)[1]; }));
    const direct = consumers.filter(function (c) { return bundles.has(c); })
      .sort();
    direct.forEach(function (c) {
      assert.ok(declared.indexOf(c) >= 0,
        "client/src/" + c + ".js requires ./" + entry.module + " but " +
        entry.list + " in client/build.js does not name it, so common/" +
        entry.module + ".js will not be staged for that bundle and the image " +
        "build fails with \"Cannot find module './" + entry.module + "'\".");
    });
    // ...and the other way, so the list cannot quietly name a bundle that
    // stopped needing it and go on looking maintained.
    declared.forEach(function (d) {
      assert.ok(consumers.indexOf(d) >= 0,
        entry.list + " in client/build.js names " + d + ", which no longer " +
        "requires ./" + entry.module + ".");
    });
    checked += direct.length;
  });
  log.info("[staged lists] OK — " + checked + " bundle(s) that require a " +
           "module staged out of common/ are named by the list that stages " +
           "it, and no list names a bundle that does not.");
  log.debug("Leaving stagedSharedModuleListsAreComplete().");
}

function everyJobDeclaresTheUrlOption() {
  log.debug("Entering everyJobDeclaresTheUrlOption().");
  const report = path.join(__dirname, "run-report.js");
  if (!fs.existsSync(report)) {
    log.info("[--url] skipped: no run-report.js beside this test.");
    log.debug("Leaving everyJobDeclaresTheUrlOption().");
    return;
  }
  const scripts = [];
  fs.readFileSync(report, "utf8").replace(/script:\s*"([^"]+)"/g,
      function (_, name) {
        if (scripts.indexOf(name) === -1) scripts.push(name);
        return _;
      });
  // The first argument of `.option(...)` / `new Option(...)` is the flag spec,
  // and it is read as a STATEMENT rather than a line: these declarations wrap
  // at 80 columns, and a check a reformat can silence is a check that will be
  // silenced.
  const SPEC = /(?:\.option|new\s+Option)\s*\(\s*(["'])((?:\\.|(?!\1).)*)\1/g;
  const undeclared = [];
  scripts.forEach(function (name) {
    const file = path.join(__dirname, name);
    if (!fs.existsSync(file)) {
      // Absence is somebody else's check — testsImageHasNoCollidingFilenames()
      // asserts every scheduled script reaches the image.
      return;
    }
    const src = fs.readFileSync(file, "utf8");
    if (!/require\(\s*["']commander["']\s*\)/.test(src)) {
      return;
    }
    var takesUrl = false;
    var m;
    SPEC.lastIndex = 0;
    while ((m = SPEC.exec(src)) !== null) {
      if (m[2].split(/[\s,|]+/).indexOf("--url") !== -1) {
        takesUrl = true;
      }
    }
    if (!takesUrl) {
      undeclared.push(name);
    }
  });
  assert.deepStrictEqual(undeclared, [],
    "run-report.js hands every job `--url <BASE_URL>` and these scripts use " +
    "commander without declaring it, so each exits 1 in ~0.06s with " +
    "`error: unknown option '--url'` before running a single check: " +
    undeclared.join(", ") + ". Add the option and say it is ignored:\n" +
    '  // Accepted and ignored: run-report.js passes --url to every job.\n' +
    '  .addOption(new Option("-u, --url <url>",\n' +
    '      "base url (unused: this test needs no browser)"))');
  log.info("[--url] OK — " + scripts.length + " scheduled script(s), every " +
    "one that parses arguments accepts --url.");
  log.debug("Leaving everyJobDeclaresTheUrlOption().");
}

// ---------------------------------------------------------------------------
// A BROWSER RECONFIGURING ITSELF MUST NOT COUNT AS A PAGE ERROR — AND MUST
// NOT BECOME A LICENCE TO IGNORE FAILED LOADS.
//
// Chrome abandons a request whose certificate-verifier or network
// configuration is replaced while it is in flight, and reports it with a code
// of its own: net::ERR_CERT_VERIFIER_CHANGED, net::ERR_NETWORK_CHANGED. The
// server was never asked and no certificate was rejected on its merits, so
// neither is a verdict on the page — but the console line looks like every
// other failed load, and the twenty-odd tests here that assert a clean console
// read it as one. That is the single failure of 270 jobs on the
// ./remote-run-tests.sh run of 2026-08-28: a stylesheet on a job whose every
// functional assertion had already passed. browser_flags.js drops exactly
// those two codes and logs every drop.
//
// Two properties, because each is silent when it breaks:
//
//   A. The filter still passes REAL failures through. Widening it to
//      `Failed to load resource` would swallow every 404, every refused
//      connection and every certificate this suite deliberately makes a
//      browser reject — and those tests would keep passing while testing
//      nothing.
//   B. Every test that asserts a clean console actually applies it. A new
//      browser test is written by copying the nearest one, and the copy that
//      misses this reintroduces a flake that reproduces on nobody's machine.
//
// A file that only LOGS severe entries on its way to failing has nothing to
// filter and is listed as an exception here rather than edited.
//
// Node only, no browser, no network: never skipped.
// ---------------------------------------------------------------------------
function transientLoadErrorsAreFilteredNotSwallowed() {
  log.debug("Entering transientLoadErrorsAreFilteredNotSwallowed().");
  const browserFlags = require("./browser_flags.js");

  // (A) What it drops, and — the half that matters — what it does not.
  const DROPPED = [
    "https://test.idptools.com/css/bootstrap.css - Failed to load resource: " +
        "net::ERR_CERT_VERIFIER_CHANGED",
    "https://example.test/js/app.js - Failed to load resource: " +
        "net::ERR_NETWORK_CHANGED"
  ];
  const KEPT = [
    // A certificate that WAS verified and found wanting.
    "https://sts.test/token - Failed to load resource: " +
        "net::ERR_CERT_AUTHORITY_INVALID",
    "https://sts.test/token - Failed to load resource: " +
        "net::ERR_CERT_COMMON_NAME_INVALID",
    // A service that is not there.
    "http://localhost:4000/claimdescription - Failed to load resource: " +
        "net::ERR_CONNECTION_REFUSED",
    // A status the page asked for and got.
    "https://idp.test/metadata - Failed to load resource: the server " +
        "responded with a status of 404 (Not Found)",
    // The thing every one of these assertions exists to catch.
    "https://idptools.com/js/saml_tools.js 12:3 Uncaught ReferenceError: " +
        "samlToolsInit is not defined"
  ];
  DROPPED.forEach(function (message) {
    assert.strictEqual(browserFlags.isTransientLoadError(message), true,
      "browser_flags.isTransientLoadError() must drop the browser's own " +
      "configuration change, and did not for:\n  " + message);
  });
  KEPT.forEach(function (message) {
    assert.strictEqual(browserFlags.isTransientLoadError(message), false,
      "browser_flags.isTransientLoadError() must keep a real failure, and " +
      "dropped this one — which would make every console assertion in this " +
      "suite decorative:\n  " + message);
  });
  assert.deepStrictEqual(
    browserFlags.withoutTransientLoadErrors(DROPPED.concat(KEPT)), KEPT,
    "withoutTransientLoadErrors() must remove exactly the transient codes " +
    "and preserve the rest, in order.");
  // Neither an empty log nor a missing one is an error.
  assert.deepStrictEqual(browserFlags.withoutTransientLoadErrors([]), []);
  assert.deepStrictEqual(browserFlags.withoutTransientLoadErrors(null), []);
  assert.strictEqual(browserFlags.isTransientLoadError(undefined), false);

  // (B) Every test that JUDGES severe console entries applies it.
  //
  // The candidates are the files that compare a log entry's level against
  // SEVERE. A file is satisfied by calling the helper, or by already dropping
  // every failed load — `Failed to load resource` — which is a wider filter
  // this cannot make wider.
  const SATISFIED = new RegExp("isTransientLoadError|" +
      "withoutTransientLoadErrors|Failed to load resource");
  // Files that only PRINT severe entries while reporting a failure of their
  // own. There is no assertion to protect, and filtering the diagnostic would
  // remove the line that explains the failure.
  const LOG_ONLY = ["kerberos_spnego_signin.js", "rfc9700_flows.js"];
  const self = path.basename(__filename);
  const missing = [];
  var candidates = 0;
  fs.readdirSync(__dirname).filter(function (name) {
    return /\.js$/.test(name) && name !== self;
  }).forEach(function (name) {
    const src = fs.readFileSync(path.join(__dirname, name), "utf8");
    if (!/name\s*[!=]==\s*(["'])SEVERE\1/.test(src)) {
      return;
    }
    candidates++;
    if (LOG_ONLY.indexOf(name) !== -1) {
      return;
    }
    if (!SATISFIED.test(src)) {
      missing.push(name);
    }
  });
  assert.deepStrictEqual(missing, [],
    "these tests assert on SEVERE browser console entries without filtering " +
    "the browser's own configuration changes, so each carries the flake that " +
    "cost the remote run of 2026-08-28: " + missing.join(", ") + ". Add\n" +
    '  .filter(function (e) {\n' +
    '    return !browserFlags.isTransientLoadError(e.message);\n' +
    '  })\n' +
    "to the filter, or list the file in LOG_ONLY here if it only logs them.");
  log.info("[console noise] OK — the two configuration-change codes are " +
    "dropped, five real failures are not, and all " + candidates +
    " console-judging test(s) filter them.");
  log.debug("Leaving transientLoadErrorsAreFilteredNotSwallowed().");
}

// ---------------------------------------------------------------------------
// NO DOCKERFILE STAGE MAY OUTGROW DOCKER'S LAYER LIMIT.
//
// Docker's layer store refuses a chain deeper than 125 layers (`maxDepth` in
// moby's layer package) and every RUN, COPY and ADD adds one. tests/Dockerfile
// is almost entirely COPY — one line per test script, per borrowed module and
// per vendored directory — so it grows with every protocol this suite learns,
// and on 2026-08-25 it reached 126 and the build died with
//
//   Step 132/136 : RUN ls
//   ...
//   max depth exceeded
//
// naming no instruction, no file and no limit, three lines after that step's
// own output. It reads as the `ls` failing. The fix was to split the COPYs
// into two staging stages the final image copies /usr/src out of, which is
// documented at the top of tests/Dockerfile — and a split is exactly the kind
// of headroom that gets used up again without anybody noticing, because
// nothing about adding one more COPY line looks different from the last
// hundred.
//
// So this counts. It fails at a BUDGET well below the real ceiling, on
// purpose: a check that fires at 125 fires only once the build is already
// broken, which is the situation it exists to replace. At 100 there is room
// for the base image's own layers (which count too — a `node:` base is about
// eight) and enough warning to add a stage deliberately rather than under a
// build failure.
//
// It reads every Dockerfile in the tree, not only this one: client/Dockerfile
// is the next closest and has the same shape (one COPY per bundle). Runs in a
// checkout; the tests image has no repository to walk and says so.
// ---------------------------------------------------------------------------
function everyDockerfileStaysUnderTheLayerLimit() {
  log.debug("Entering everyDockerfileStaysUnderTheLayerLimit().");
  // 125 is docker's; 100 is ours, and the gap is the base image plus warning.
  const DOCKER_MAX_DEPTH = 125;
  const BUDGET = 100;
  const repo = path.join(__dirname, "..");
  // `client/` IS NOT THE MARKER, AND THAT COST THE CONTAINERIZED RUN OF
  // 2026-08-27. The tests image stages client/src at /usr/src/client/src (see
  // tests/Dockerfile) precisely so the Kerberos and SPIFFE jobs can require
  // their modules by the path a checkout uses — so this directory exists in
  // the image, the guard did not fire, and the walk below found NO Dockerfile
  // at all. The failure was the summary's `counted.reduce()` on an empty array
  // — "Reduce of empty array with no initial value", naming Array.reduce and
  // nothing about docker, layers or the missing tree. What the image does not
  // carry is a Dockerfile, so that is what is asked about, and the walk's own
  // result is checked below as well: this function is about Dockerfiles, and
  // "none found" is the one condition it can never usefully assert on.
  if (!fs.existsSync(path.join(repo, "tests", "Dockerfile"))) {
    log.info("[layers] skipped: no tests/Dockerfile here, so this is the " +
      "tests image rather than a checkout.");
    log.debug("Leaving everyDockerfileStaysUnderTheLayerLimit().");
    return;
  }
  // The submodules' own Dockerfiles ARE walked — sts/Dockerfile builds in
  // this stack and a gitlink bump is exactly the kind of change that could
  // push one over. node_modules and .git are not.
  const skip = /(^|\/)(node_modules|\.git)(\/|$)/;
  const found = [];
  const walk = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (skip.test(full)) {
        return;
      }
      if (entry.isDirectory()) {
        walk(full);
        return;
      }
      if (entry.name === "Dockerfile" || /^Dockerfile\./.test(entry.name)) {
        found.push(full);
      }
    });
  };
  walk(repo);
  if (found.length === 0) {
    log.info("[layers] skipped: the tree at " + repo + " holds no Dockerfile " +
      "to walk.");
    log.debug("Leaving everyDockerfileStaysUnderTheLayerLimit().");
    return;
  }

  const over = [];
  const counted = [];
  found.forEach(function (file) {
    const lines = fs.readFileSync(file, "utf8").split("\n");
    // Per STAGE, because each FROM starts a fresh chain — that is what makes
    // the split in tests/Dockerfile work at all.
    let stage = "(before any FROM)";
    let layers = 0;
    let continued = false;
    const report = function () {
      if (layers === 0 && stage === "(before any FROM)") {
        // Nothing between the top of the file and its first FROM; a stage
        // with no layers of its own is not worth naming in the summary.
        return;
      }
      const rel = path.relative(repo, file);
      counted.push(rel + " [" + stage + "]: " + layers);
      if (layers > BUDGET) {
        over.push(rel + " stage " + stage + " has " + layers + " layer " +
          "instructions");
      }
    };
    lines.forEach(function (line) {
      const wasContinued = continued;
      continued = /\\\s*$/.test(line);
      if (wasContinued) {
        return;
      }
      const text = line.trim();
      if (text.charAt(0) === "#" || text === "") {
        return;
      }
      if (/^FROM\s/i.test(text)) {
        report();
        stage = text.replace(/^FROM\s+/i, "");
        layers = 0;
        return;
      }
      if (/^(RUN|COPY|ADD)\s/i.test(text)) {
        layers++;
      }
    });
    report();
  });

  assert.deepStrictEqual(over, [],
    "docker refuses a layer chain deeper than " + DOCKER_MAX_DEPTH + " and " +
    "every RUN/COPY/ADD adds one; these stages are past this suite's budget " +
    "of " + BUDGET + ": " + over.join(" | ") + ". Split the stage the way " +
    "tests/Dockerfile is split — a staging stage the image copies /usr/src " +
    "out of — rather than merging COPY lines, whose comments are attached to " +
    "the lines they explain. Left alone, the build fails with `max depth " +
    "exceeded`, which names no instruction and no file.");

  log.info("[layers] OK — " + found.length + " Dockerfile(s), " +
    counted.length + " stage(s), the deepest at " +
    counted.reduce(function (a, b) {
      return Number(a.split(": ").pop()) > Number(b.split(": ").pop()) ? a : b;
    }) + " layer instructions, budget " + BUDGET + " of docker's " +
    DOCKER_MAX_DEPTH + ".");
  log.debug("Leaving everyDockerfileStaysUnderTheLayerLimit().");
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
  bigIntLiteralsStayOutOfTheBundles();
  appendedBeaconNeedsNoModuleSystem();
  coverageListCoversEveryBundle();
  testsImageHasNoCollidingFilenames();
  everyDockerfileStaysUnderTheLayerLimit();
  stagedSharedModuleListsAreComplete();
  everyJobDeclaresTheUrlOption();
  transientLoadErrorsAreFilteredNotSwallowed();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("jwk_pem")
  .description("Verify client/src/jwk_pem.js encodes JWK public keys as " +
      "correct SPKI PEMs.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
