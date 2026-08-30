// File: frodokem_vectors.js
//
// ===========================================================================
// FrodoKEM AND eFrodoKEM AGAINST THE REFERENCE IMPLEMENTATION'S OWN KATs.
//
// `client/src/frodokem.js` is the only cryptographic primitive in this project
// with NO LIBRARY BEHIND IT. @noble has ML-KEM and no FrodoKEM; npm has no
// FrodoKEM at all; the one credible open implementation
// (microsoft/PQCrypto-LWEKE) is C plus a Python reference. So it was written
// from the specification, and a lattice KEM written from a specification is
// exactly the thing that must not be trusted on a round trip: a subtly wrong
// one encapsulates and decapsulates against ITSELF perfectly, agrees with
// itself about every byte, and interoperates with nothing.
//
// **THAT IS NOT HYPOTHETICAL HERE. This file caught it.** The first run
// matched eight of the twelve parameter sets and failed the SHAKE generator at
// 976 and 1344 — because specification algorithm 8 is named "Frodo.Gen using
// SHAKE128" and MEANS IT: those two parameter sets hash with SHAKE256
// everywhere else in the scheme and with SHAKE128 for the matrix A. Nothing
// else could have found that. Both halves round-tripped, both halves agreed,
// and four of the twelve were wrong.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHY IT IS THE STRONGEST FORM AVAILABLE.
//
// The `.rsp` files are the NIST Known Answer Test format: a seed, and the
// public key, secret key, ciphertext and shared secret that a correct
// implementation produces FROM that seed. Reproducing them needs the same
// deterministic randomness the KAT generator used — NIST's AES-256-CTR-DRBG,
// which every PQC reference implementation ships as `rng.c` and which is
// implemented below because it is a test fixture and not a thing this project
// does.
//
// So this is not "our encapsulation decapsulates". It is: seed the DRBG with
// the published seed, generate a key pair, encapsulate, and require all four
// published values back, byte for byte, for every one of the TWELVE
// identifiers draft-eastlake-rfc9231bis-xmlsec-uris section 3.6.10 defines.
//
// **eFrodoKEM IS NOT "FrodoKEM WITHOUT THE SALT"**, which is the other thing
// these vectors are here to hold: it is the original pre-2023 scheme, and
// every length derived from `CRYPTO_BYTES` — s, seedSE, k, pkh and the shared
// secret — is half what the salted variant uses. Stripping the salt and
// changing nothing else produces six more KEMs that round-trip and match
// nothing.
//
// The vectors are in `frodokem_vectors.json`, as the seed and the shared
// secret verbatim plus SHA-256 and a length for the three large values — the
// twelve verbatim records are 1.5MB of hex, and a digest of a published value
// is exactly as strong while staying a file somebody can read. That file says
// how to reproduce it from the upstream `.rsp`.
//
// Node only: no browser, no network, no service. It takes a `--url` it
// ignores, for the reason every node-only job here does.
// ===========================================================================

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bunyan = require("bunyan");
const { program } = require("commander");

program.option("--url <url>", "ignored; this test needs no server").parse();

const log = bunyan.createLogger({
  name: "frodokem_vectors",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const { requireSharedModule } = require("./module_paths.js");
const frodo = requireSharedModule([
  path.join(__dirname, "frodokem.js"),
  path.join(__dirname, "..", "client", "src", "frodokem.js"),
], "client/src/frodokem.js");

const VECTORS = JSON.parse(fs.readFileSync(
    path.join(__dirname, "frodokem_vectors.json"), "utf8"));

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) {
    pass++;
    log.info("  PASS  " + name + (detail ? "  -> " + detail : ""));
  } else {
    fail++;
    log.error("  FAIL  " + name + (detail ? "  -> " + detail : ""));
  }
  return !!ok;
}

// ---------------------------------------------------------------------------
// NIST's AES-256-CTR-DRBG, as `rng.c` in every PQC reference implementation.
// It is HERE and not in client/src because nothing this project does needs a
// deterministic RNG — it exists only to reproduce published vectors, and a
// deterministic RNG that escaped into the application would be the worst
// possible thing to find there.
//
// `V` is a 16-byte big-endian counter. The update after every draw is what
// makes the sequence match: an implementation that skipped it would produce
// the right FIRST value and diverge from the second.
// ---------------------------------------------------------------------------
function makeDrbg(entropy48) {
  log.debug("Entering makeDrbg().");
  let key = Buffer.alloc(32);
  let v = Buffer.alloc(16);
  function ecb(k, block) {
    const cipher = crypto.createCipheriv("aes-256-ecb", k, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(block), cipher.final()]);
  }
  function bump() {
    for (let i = 15; i >= 0; i--) {
      v[i] = (v[i] + 1) & 0xff;
      if (v[i] !== 0) {
        break;
      }
    }
  }
  function update(provided) {
    const temp = Buffer.alloc(48);
    for (let i = 0; i < 3; i++) {
      bump();
      ecb(key, v).copy(temp, 16 * i);
    }
    if (provided) {
      for (let i = 0; i < 48; i++) {
        temp[i] ^= provided[i];
      }
    }
    key = Buffer.from(temp.subarray(0, 32));
    v = Buffer.from(temp.subarray(32, 48));
  }
  update(Buffer.from(entropy48));
  log.debug("Leaving makeDrbg().");
  return function randombytes(n) {
    const out = Buffer.alloc(n);
    let at = 0;
    while (at < n) {
      bump();
      ecb(key, v).copy(out, at, 0, Math.min(16, n - at));
      at += 16;
    }
    update(null);
    return new Uint8Array(out);
  };
}

function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(Buffer.from(bytes))
    .digest("hex").toUpperCase();
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex").toUpperCase();
}

// ---------------------------------------------------------------------------
function everyParameterSetReproducesItsVector() {
  log.info("A. the twelve published Known Answer Tests");
  check("the module offers exactly the twelve identifiers the draft defines",
        frodo.VARIANTS.length === 12, frodo.VARIANTS.join(", "));
  frodo.VARIANTS.forEach(function (variant) {
    const want = VECTORS.vectors[variant];
    if (!check(variant + ": a published vector is on file", !!want)) {
      return;
    }
    const randombytes = makeDrbg(Buffer.from(want.seed, "hex"));
    const pair = frodo.keygen(variant, randombytes);
    const encapsulated = frodo.encapsulate(variant, pair.publicKey,
                                           randombytes);
    // All four published values, from the published seed.
    check(variant + ": the public key is the published one",
          pair.publicKey.length === want.pkBytes &&
          sha256Hex(pair.publicKey) === want.pkSha256,
          pair.publicKey.length + " bytes");
    check(variant + ": the secret key is the published one",
          pair.secretKey.length === want.skBytes &&
          sha256Hex(pair.secretKey) === want.skSha256,
          pair.secretKey.length + " bytes");
    check(variant + ": the ciphertext is the published one",
          encapsulated.ciphertext.length === want.ctBytes &&
          sha256Hex(encapsulated.ciphertext) === want.ctSha256,
          encapsulated.ciphertext.length + " bytes");
    check(variant + ": the shared secret is the published one",
          hex(encapsulated.sharedSecret) === want.ss,
          hex(encapsulated.sharedSecret));
    // And decapsulation recovers it, which the KAT format asserts implicitly.
    const recovered = frodo.decapsulate(variant, pair.secretKey,
                                        encapsulated.ciphertext);
    check(variant + ": decapsulation recovers it", hex(recovered) === want.ss);
  });
}

// ---------------------------------------------------------------------------
function theFujisakiOkamotoTransformDoesItsJob() {
  log.info("B. a wrong key and a tampered ciphertext");
  // One parameter set is enough here: the FO transform is the same code for
  // all twelve and the KATs above have already established that code is right.
  const variant = "FrodoKEM-640-AES";
  const randombytes = function (n) {
    return new Uint8Array(crypto.randomBytes(n));
  };
  const a = frodo.keygen(variant, randombytes);
  const b = frodo.keygen(variant, randombytes);
  const encapsulated = frodo.encapsulate(variant, a.publicKey, randombytes);

  // **A WRONG KEY DOES NOT FAIL. THAT IS FIPS-STYLE IMPLICIT REJECTION AND IT
  // IS THE POINT OF THE TRANSFORM.** Returning an error would leak, through
  // its timing, which part of the decryption went wrong — the attack of Guo,
  // Johansson and Nilsson (CRYPTO 2020) against exactly this construction. So
  // decapsulation with the wrong key returns a well-formed shared secret
  // derived from that key's own `s`, which is simply a different one.
  const wrongKey = frodo.decapsulate(variant, b.secretKey,
                                     encapsulated.ciphertext);
  check("a wrong secret key returns a well-formed shared secret rather than " +
        "an error — implicit rejection, and the reason a caller finds out at " +
        "an AEAD tag",
        wrongKey.length === encapsulated.sharedSecret.length);
  check("and it is NOT the right one",
        hex(wrongKey) !== hex(encapsulated.sharedSecret));

  // A tampered ciphertext, same story: the re-encryption inside decapsulation
  // disagrees, so `s` is used instead of `k'`.
  const tampered = Uint8Array.from(encapsulated.ciphertext);
  tampered[0] ^= 0x01;
  const fromTampered = frodo.decapsulate(variant, a.secretKey, tampered);
  check("a tampered ciphertext also returns a well-formed shared secret",
        fromTampered.length === encapsulated.sharedSecret.length);
  check("and it too is not the right one",
        hex(fromTampered) !== hex(encapsulated.sharedSecret));

  // Lengths that cannot be right are refused BY NAME, because those are
  // mistakes in a caller rather than facts about a ciphertext.
  let refusal = "";
  try {
    frodo.decapsulate(variant, a.secretKey, new Uint8Array(10));
  } catch (e) {
    refusal = e.message;
  }
  check("a ciphertext of the wrong length is refused, with both lengths in " +
        "the sentence", /9752/.test(refusal) && /10/.test(refusal), refusal);
  let badVariant = "";
  try {
    frodo.resolve("FrodoKEM-999-AES");
  } catch (e) {
    badVariant = e.message;
  }
  check("an unknown parameter set is refused, naming the twelve",
        /640,976,1344/.test(badVariant), badVariant);
}

// ---------------------------------------------------------------------------
function theParametersMatchTheSpecification() {
  log.info("C. the parameter tables, against the published sizes");
  // Specification tables 4 and 5, and eFrodoKEM's api_efrodo*.h. Written out
  // here rather than read from the module, which would assert that the module
  // agrees with itself.
  const EXPECTED = {
    "FrodoKEM-640-AES": [640, 32768, 15, 2, 9616, 19888, 9752, 16],
    "FrodoKEM-976-AES": [976, 65536, 16, 3, 15632, 31296, 15792, 24],
    "FrodoKEM-1344-AES": [1344, 65536, 16, 4, 21520, 43088, 21696, 32],
    "eFrodoKEM-640-AES": [640, 32768, 15, 2, 9616, 19888, 9720, 16],
    "eFrodoKEM-976-AES": [976, 65536, 16, 3, 15632, 31296, 15744, 24],
    "eFrodoKEM-1344-AES": [1344, 65536, 16, 4, 21520, 43088, 21632, 32]
  };
  Object.keys(EXPECTED).forEach(function (variant) {
    const want = EXPECTED[variant];
    const p = frodo.resolve(variant);
    check(variant + ": n, q, D, B, and the four lengths",
          p.n === want[0] && p.q === want[1] && p.D === want[2] &&
          p.B === want[3] && p.pkBytes === want[4] && p.skBytes === want[5] &&
          p.ctBytes === want[6] && p.lenSs === want[7],
          [p.n, p.q, p.D, p.B, p.pkBytes, p.skBytes, p.ctBytes,
           p.lenSs].join("/"));
  });
  // THE DIFFERENCE THAT IS NOT THE SALT. eFrodoKEM's seedSE is half the
  // salted variant's, and a reader who assumes otherwise writes six broken
  // parameter sets that round-trip perfectly.
  const salted = frodo.resolve("FrodoKEM-640-AES");
  const ephemeral = frodo.resolve("eFrodoKEM-640-AES");
  check("the ephemeral variant carries no salt", ephemeral.lenSalt === 0);
  check("the salted one does", salted.lenSalt === 32);
  check("AND their seedSE lengths differ, which is the half that is not the " +
        "salt", ephemeral.lenSeedSE === 16 && salted.lenSeedSE === 32,
        ephemeral.lenSeedSE + " against " + salted.lenSeedSE);
}

function main() {
  log.info("Starting Test run. FrodoKEM and eFrodoKEM against the reference " +
           "implementation's Known Answer Tests.");
  theParametersMatchTheSpecification();
  everyParameterSetReproducesItsVector();
  theFujisakiOkamotoTransformDoesItsJob();
  log.info("---------------------------------------------------------------");
  log.info(pass + " passed, " + fail + " failed.");
  process.exit(fail ? 1 : 0);
}

main();
