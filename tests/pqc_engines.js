// File: pqc_engines.js
//
// ---------------------------------------------------------------------------
// The post-quantum cryptography, driven in NODE with no browser.
//
// Same division as tests/crypto_engines.js, and for the same reason: the
// Selenium jobs press the buttons and prove the wiring, and they check every
// signature against the code that made it — which agrees with itself whatever
// the implementation does. For post-quantum work that self-agreement is the
// dangerous case rather than a theoretical one, because almost nothing else in
// the world can read these bytes yet. A pane that signs and verifies its own
// ML-DSA is exactly as convincing when the domain separation is wrong.
//
// So this job asserts against things that are NOT this code:
//
//   * draft-connolly-cfrg-xwing-kem-07's OWN test vectors, all three, for
//     key generation, derandomized encapsulation and decapsulation. This is
//     the strongest statement in the file: a published vector that a fresh
//     implementation cannot accidentally satisfy.
//   * The domain-separation labels of draft-ietf-jose-pq-composite-sigs-03
//     and draft-ietf-lamps-pq-composite-kem-08, compared against the
//     HEXADECIMAL those drafts print beside them. A label that is one
//     character out still signs and verifies against itself and interoperates
//     with nobody, and it is the single most likely thing to be wrong.
//   * The key, signature and ciphertext sizes in FIPS 203/204/205, which
//     pqc.js has to TRANSCRIBE because @noble/post-quantum 0.4.1 exposes no
//     metadata at all — and which the composite constructions then use to
//     split a concatenated key. A mistyped digit there gives a splitter that
//     works between two copies of this code and interoperates with nothing,
//     so every row is checked against a key the library actually generated.
//   * RFC 9964's rules about the AKP key type, which this project got wrong
//     for months: `pub`/`priv` rather than `x`/`d`, `alg` required, and an
//     ML-DSA `priv` that MUST be the 32-byte seed.
//
// and then, separately, the properties no vector can express: that a tampered
// payload is refused, that a wrong context string is refused, that a
// pre-hashed signature does not verify as a pure one, and that a composite
// signature with one half replaced is refused — which is the entire point of
// a composite and the one failure that would otherwise look like success.
// ---------------------------------------------------------------------------

// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it has
// not been told about. This job parses no arguments at all — it drives modules
// in process and has no base url to visit — so node ignores the pair and there
// is nothing to declare. Do not add commander here without also declaring
// `--url`; see tests/CLAUDE.md.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'pqc_engines',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The modules under test live next to this script in the tests image and in
// client/src in a checkout — see the note in tests/module_paths.js, and the
// tests/Dockerfile COPY that puts them here.
const paths = require("./module_paths.js");
const SRC = path.resolve(__dirname, "..", "client", "src");

function shared(name) {
  log.debug("Entering shared(). name=" + name);
  const found = paths.requireSharedModule(
    [path.join(__dirname, name), path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving shared().");
  return found;
}

const bytes = shared("crypto_bytes.js");
const pqc = shared("pqc.js");
const jws = shared("jws.js");

function hex(value) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return bytes.bytesToHex(value);
}

function utf8(text) {
  log.debug("Entering utf8().");
  log.debug("Leaving utf8().");
  return bytes.strBytes(text);
}

// ---------------------------------------------------------------------------
// 1. The division this job depends on: no DOM anywhere in the engine.
// ---------------------------------------------------------------------------
function checkNoDom() {
  log.debug("Entering checkNoDom().");
  // Same shape and the same reasoning as tests/crypto_engines.js: comments
  // are where the reasoning lives, so only real code counts.
  const forbidden = /\b(document|window|localStorage|sessionStorage)\s*\./;
  const candidates = [path.join(__dirname, "pqc.js"), path.join(SRC, "pqc.js")];
  const file = candidates.filter(function (one) {
    return fs.existsSync(one);
  })[0];
  assert.ok(file, "could not locate pqc.js to read");
  fs.readFileSync(file, "utf8").split(/\r?\n/).forEach(function (line, i) {
    const code = line.replace(/^\s*(\/\/|\*).*$/, '');
    assert.ok(!forbidden.test(code),
      "pqc.js line " + (i + 1) + " touches the DOM: " + line.trim() +
      "\nThis whole job depends on the module being drivable in node; the " +
      "moment it reads a field it can only be tested through a browser.");
  });
  log.info("[no-dom] OK — pqc.js reaches no DOM.");
  log.debug("Leaving checkNoDom().");
}

// ---------------------------------------------------------------------------
// 2. X-Wing, against draft-connolly-cfrg-xwing-kem-07 Appendix C.
// ---------------------------------------------------------------------------
// The vectors are transcribed into tests/xwing_vectors.json rather than
// recomputed, which is the point: they came out of the draft, so agreeing
// with them is evidence about the IMPLEMENTATION rather than about the
// transcription.
function checkXWingVectors() {
  log.debug("Entering checkXWingVectors().");
  const fixture = JSON.parse(fs.readFileSync(
    path.join(__dirname, "xwing_vectors.json"), "utf8"));
  const xwing = pqc.kemAlg('X-Wing');
  assert.ok(fixture.vectors.length >= 3,
    "the X-Wing fixture should carry all three of the draft's vectors.");

  fixture.vectors.forEach(function (v, i) {
    const label = "X-Wing vector " + (i + 1) + ": ";
    const pair = xwing.keygen(bytes.hexToBytes(v.seed));
    assert.strictEqual(hex(pair.publicKey), v.pk,
      label + "the public key derived from the seed does not match the " +
      "draft. Key generation expands the 32-byte seed, so this is the " +
      "assertion that catches a wrong expansion function.");

    // Derandomized encapsulation: the 64-byte eseed is what makes the
    // ciphertext reproducible, and without it a vector could only ever check
    // decapsulation.
    const enc = xwing.encapsulate(bytes.hexToBytes(v.pk),
                                  bytes.hexToBytes(v.eseed));
    assert.strictEqual(hex(enc.cipherText), v.ct,
      label + "the ciphertext does not match the draft.");
    assert.strictEqual(hex(enc.sharedSecret), v.ss,
      label + "the shared secret does not match the draft — the combiner " +
      "is wrong, which is invisible to a round trip.");

    const back = xwing.decapsulate(bytes.hexToBytes(v.ct), pair.secretKey);
    assert.strictEqual(hex(back), v.ss,
      label + "decapsulation does not recover the draft's shared secret.");
  });
  log.debug("Leaving checkXWingVectors().");
}

// ---------------------------------------------------------------------------
// 3. The domain-separation labels, against the drafts' own hexadecimal.
// ---------------------------------------------------------------------------
// Every one of these is a string this project could have transcribed wrongly,
// and every one of them is invisible to a round trip. The drafts print the
// hex precisely because the strings are hard to read.
function checkCompositeLabels() {
  log.debug("Entering checkCompositeLabels().");

  // draft-ietf-jose-pq-composite-sigs-03, section 4.2 and Table 4.
  assert.strictEqual(hex(pqc.COMPOSITE_PREFIX).toLowerCase(),
    "436f6d706f73697465416c676f726974686d5369676e61747572657332303235",
    "the composite signature Prefix must be the byte encoding of " +
    "\"CompositeAlgorithmSignatures2025\".");

  const sigLabels = {
    'ML-DSA-44-ES256':
      "434f4d505349472d4d4c44534134342d45434453412d503235362d534841323536",
    'ML-DSA-65-ES256':
      "434f4d505349472d4d4c44534136352d45434453412d503235362d534841353132",
    'ML-DSA-87-ES384':
      "434f4d505349472d4d4c44534138372d45434453412d503338342d534841353132",
    'ML-DSA-44-Ed25519':
      "434f4d505349472d4d4c44534134342d456432353531392d534841353132",
    'ML-DSA-65-Ed25519':
      "434f4d505349472d4d4c44534136352d456432353531392d534841353132",
    'ML-DSA-87-Ed448':
      "434f4d505349472d4d4c44534138372d45643434382d5348414b45323536"
  };
  Object.keys(sigLabels).forEach(function (name) {
    const cfg = pqc.COMPOSITE_ALGS[name];
    assert.ok(cfg, "composite signature algorithm " + name + " is missing.");
    assert.strictEqual(hex(utf8(cfg.label)).toLowerCase(), sigLabels[name],
      name + "'s Label does not match Table 4 of " +
      "draft-ietf-jose-pq-composite-sigs-03.");
  });

  // draft-ietf-lamps-pq-composite-kem-08, section 7. Only two hexes are
  // printed in that document; those two are the ones asserted, because an
  // assertion against a hex this project computed itself would prove nothing.
  assert.strictEqual(hex(utf8(pqc.COMPOSITE_KEMS['MLKEM768-X25519'].label))
      .toLowerCase(), "5c2e2f2f5e5c",
    "MLKEM768-X25519's Label must be the six bytes 5c2e2f2f5e5c — the " +
    "same label X-Wing uses. It is backslash, dot, slash, slash, caret, " +
    "backslash, and JavaScript string escaping is exactly how it gets " +
    "silently shortened.");
  assert.strictEqual(hex(utf8(pqc.COMPOSITE_KEMS['MLKEM768-ECDH-P256'].label))
      .toLowerCase(),
    "5153462d4d4c4b454d3736382d503235362d53484133323536",
    "MLKEM768-ECDH-P256's Label does not match the hex in section 7.");

  log.debug("Leaving checkCompositeLabels().");
}

// ---------------------------------------------------------------------------
// 4. Key and signature sizes, against the specifications' own tables.
// ---------------------------------------------------------------------------
// The Falcon rows are the reason this function exists. @noble's default
// Falcon signature is VARIABLE length (roughly 650-666 bytes for falcon-512),
// and draft-ietf-cose-falcon-04 Table 1 gives a single number — the PADDED
// size. Signing with the unpadded variant produces something that verifies
// here and is the wrong length for anybody reading the draft, and because
// most unpadded signatures happen to be shorter, the bug is intermittent.
function checkSizes() {
  log.debug("Entering checkSizes().");
  const message = utf8("size check");

  // EVERY transcribed size row, against what the library actually produces.
  // This is the assertion that makes the tables trustworthy; the composite
  // splitters depend on them and would fail silently and self-consistently.
  Object.keys(pqc.SIGNATURE_ALGS).forEach(function (name) {
    const entry = pqc.SIGNATURE_ALGS[name];
    if (entry.family === 'SLH-DSA' && !/-128s$/.test(name)) {
      // Generating a key for the large SLH-DSA sets is cheap but signing is
      // not, so only the sizes that do not need a signature are checked for
      // the other ten. Saying so beats quietly checking less.
      const pair = entry.keygen();
      assert.strictEqual(pair.publicKey.length, entry.lengths.publicKey,
        name + " public key size must match the FIPS 205 table.");
      assert.strictEqual(pair.secretKey.length, entry.lengths.secretKey,
        name + " private key size must match the FIPS 205 table.");
      return;
    }
    const pair = pqc.generateAkpKeyPair(name);
    assert.strictEqual(pair.pub.length, entry.lengths.publicKey,
      name + " public key size must match its transcribed table row.");
    assert.strictEqual(
      pqc.signWithPriv(name, message, pair.priv).length,
      entry.lengths.signature,
      name + " signature size must match its transcribed table row.");
  });

  Object.keys(pqc.KEM_ALGS).forEach(function (name) {
    const kem = pqc.kemAlg(name);
    const pair = kem.keygen();
    const enc = kem.encapsulate(pair.publicKey);
    assert.strictEqual(pair.publicKey.length, kem.lengths.publicKey,
      name + " public key size must match its transcribed table row.");
    assert.strictEqual(enc.cipherText.length, kem.lengths.cipherText,
      name + " ciphertext size must match its transcribed table row.");
  });

  // FIPS 204 Table 1, as reproduced in the composite draft.
  const mldsaTable = {
    'ML-DSA-44': { sig: 2420, pub: 1312, seed: 32 },
    'ML-DSA-65': { sig: 3309, pub: 1952, seed: 32 },
    'ML-DSA-87': { sig: 4627, pub: 2592, seed: 32 }
  };
  Object.keys(mldsaTable).forEach(function (name) {
    const want = mldsaTable[name];
    const pair = pqc.generateAkpKeyPair(name);
    assert.strictEqual(pair.pub.length, want.pub,
      name + " public key size must match FIPS 204.");
    assert.strictEqual(pair.priv.length, want.seed,
      name + " AKP priv must be the 32-byte seed, not the expanded key.");
    assert.strictEqual(pqc.signWithPriv(name, message, pair.priv).length,
      want.sig, name + " signature size must match FIPS 204.");
  });

  // The composite sizes are the two components added, and the draft says so;
  // asserting it is what makes DeserializeSignatureValue unambiguous.
  Object.keys(pqc.COMPOSITE_ALGS).forEach(function (name) {
    const entry = pqc.signatureAlg(name);
    const cfg = pqc.COMPOSITE_ALGS[name];
    const trad = pqc.TRAD[cfg.trad];
    const mldsa = mldsaTable[cfg.mldsa];
    assert.strictEqual(entry.lengths.signature, mldsa.sig + trad.sigLen,
      name + " signature must be the ML-DSA signature followed by the " +
      trad.sigLen + "-byte " + cfg.trad + " one.");
    assert.strictEqual(entry.lengths.secretKey, 32 + trad.privLen,
      name + " private key must be a 32-byte ML-DSA seed followed by the " +
      "traditional key — the draft requires the seed form.");
  });

  log.debug("Leaving checkSizes().");
}

// ---------------------------------------------------------------------------
// 5. The pre-hash mapping.
// ---------------------------------------------------------------------------
// pqc.js does NOT encode the pre-hash OIDs: @noble/post-quantum 0.4.1 carries
// its own table, with the OIDs from NIST's registry and with SHAKE-128 at a
// 256-bit output and SHAKE-256 at 512-bit — the lengths FIPS 204 §5.4
// requires rather than the libraries' defaults. So the only thing that can be
// wrong on this path is the NAME MAPPING, and that is what is checked: every
// name the page offers must resolve to one the library accepts, and an
// unknown one must throw rather than silently signing something else.
function checkPrehashMapping() {
  log.debug("Entering checkPrehashMapping().");
  const names = pqc.prehashNames();
  assert.ok(names.length >= 7,
    "the seven FIPS 204 section 5.4 pre-hash functions should be offered.");
  const pair = pqc.generateAkpKeyPair('ML-DSA-44');
  const message = utf8("mapping check");
  names.forEach(function (name) {
    const mapped = pqc.prehash(name);
    assert.ok(typeof mapped === 'string' && mapped.length > 0,
      name + " must map to a hash name the library knows.");
    // The mapping is only proved correct by the library ACCEPTING it — an
    // unknown name throws inside @noble, which is why this signs rather than
    // merely comparing strings.
    const sig = pqc.signWithPriv('ML-DSA-44', message, pair.priv,
                                 { prehash: mapped });
    assert.ok(pqc.verifyWithPub('ML-DSA-44', sig, message, pair.pub,
                                { prehash: mapped }),
      name + " must produce a verifiable HashML-DSA signature.");
  });
  assert.throws(function () { pqc.prehash('SHA-999'); }, /Unknown pre-hash/,
    "an unknown pre-hash name must be refused by name, not passed through.");
  log.debug("Leaving checkPrehashMapping().");
}

// ---------------------------------------------------------------------------
// 6. RFC 9964's AKP rules — the ones this project got wrong.
// ---------------------------------------------------------------------------
function checkAkpJwk() {
  log.debug("Entering checkAkpJwk().");
  const pair = pqc.generateAkpKeyPair('ML-DSA-44');
  const pub = pqc.akpPublicJwk('ML-DSA-44', pair.pub);
  const priv = pqc.akpPrivateJwk('ML-DSA-44', pair.pub, pair.priv);

  assert.strictEqual(pub.kty, 'AKP', "the key type is AKP.");
  assert.ok(pub.pub, "RFC 9964 section 3 names the public parameter `pub`.");
  assert.ok(priv.priv,
    "RFC 9964 section 3 names the private parameter `priv`.");
  assert.strictEqual(pub.x, undefined,
    "`x` is OKP's parameter name. An AKP JWK carrying it is what this " +
    "project used to emit and no conforming implementation reads.");
  assert.strictEqual(priv.d, undefined,
    "`d` is likewise not an AKP parameter.");
  assert.strictEqual(pub.alg, 'ML-DSA-44',
    "`alg` is REQUIRED on an AKP key — `pub` and `priv` are opaque octets " +
    "that cannot say which algorithm they belong to.");
  assert.strictEqual(bytes.b64uToBytes(priv.priv).length, 32,
    "RFC 9964 section 3.2: the ML-DSA `priv` MUST be the 32-byte seed.");

  // An AKP JWK with no `alg` must be refused rather than guessed at.
  assert.throws(function () {
    pqc.akpImport({ kty: 'AKP', pub: pub.pub });
  }, /alg/i, "an AKP JWK without `alg` must be refused.");

  // The expanded-key mistake, named rather than left to fail deep inside the
  // lattice code.
  assert.throws(function () {
    pqc.akpImport({ kty: 'AKP', alg: 'ML-DSA-44', pub: pub.pub,
                    priv: bytes.bytesToB64u(new Uint8Array(2560)) });
  }, /seed/i,
    "a 2560-byte ML-DSA `priv` is the expanded key and must be refused " +
    "with a message that says so.");

  // ...but a COMPOSITE `priv` is legitimately seed + traditional key and must
  // NOT be caught by that rule. The first version of the check tested the
  // algorithm NAME with /^ML-DSA-/, which matches every composite too and
  // rejected six valid key types.
  Object.keys(pqc.COMPOSITE_ALGS).forEach(function (name) {
    const cpair = pqc.generateAkpKeyPair(name);
    const cjwk = pqc.akpPrivateJwk(name, cpair.pub, cpair.priv);
    const back = pqc.akpImport(cjwk);
    assert.strictEqual(back.priv.length, cpair.priv.length,
      name + "'s private key must survive an AKP round trip — it is a seed " +
      "PLUS a traditional key and is never 32 bytes.");
  });

  log.debug("Leaving checkAkpJwk().");
}

// ---------------------------------------------------------------------------
// 7. Signatures: round trips, and the refusals that matter more.
// ---------------------------------------------------------------------------
function checkSignatures() {
  log.debug("Entering checkSignatures().");
  const message = utf8("the quick brown fox");
  const other = utf8("the quick brown fix");

  Object.keys(pqc.SIGNATURE_ALGS).forEach(function (name) {
    const entry = pqc.SIGNATURE_ALGS[name];
    // The slow SLH-DSA parameter sets take tens of seconds each to sign in
    // pure JS. Two of them are exercised in full; the rest are checked for
    // their registry shape only, which is what a test that has to finish can
    // honestly do. tests/CLAUDE.md's rule about saying so rather than
    // quietly narrowing applies here.
    if (entry.family === 'SLH-DSA' && !/-128s$/.test(name)) {
      assert.ok(typeof entry.sign === 'function' &&
                typeof entry.verify === 'function',
        name + " must still expose the common signer shape.");
      return;
    }
    const pair = pqc.generateAkpKeyPair(name);
    const sig = pqc.signWithPriv(name, message, pair.priv);
    assert.ok(pqc.verifyWithPub(name, sig, message, pair.pub),
      name + " must verify its own signature.");
    assert.ok(!pqc.verifyWithPub(name, sig, other, pair.pub),
      name + " must refuse a signature over a different message.");

    const stranger = pqc.generateAkpKeyPair(name);
    assert.ok(!pqc.verifyWithPub(name, sig, message, stranger.pub),
      name + " must refuse a signature made under a different key.");
  });

  log.debug("Leaving checkSignatures().");
}

// ---------------------------------------------------------------------------
// 8. The context string and the pre-hash are ALGORITHM CHANGES, not options.
// ---------------------------------------------------------------------------
function checkContextAndPrehash() {
  log.debug("Entering checkContextAndPrehash().");
  const message = utf8("context matters");
  const pair = pqc.generateAkpKeyPair('ML-DSA-44');

  const ctxA = { context: utf8("application-A") };
  const ctxB = { context: utf8("application-B") };
  const signed = pqc.signWithPriv('ML-DSA-44', message, pair.priv, ctxA);
  assert.ok(pqc.verifyWithPub('ML-DSA-44', signed, message, pair.pub, ctxA),
    "a context-bound signature verifies under the same context.");
  assert.ok(!pqc.verifyWithPub('ML-DSA-44', signed, message, pair.pub, ctxB),
    "a signature made for one context MUST NOT verify under another — that " +
    "separation is the whole reason FIPS 204 section 5.2 has a context.");
  assert.ok(!pqc.verifyWithPub('ML-DSA-44', signed, message, pair.pub, {}),
    "nor as a pure signature with no context at all.");

  // HashML-DSA is a different algorithm from ML-DSA, and a different one for
  // each hash. Both directions are asserted because a verifier that ignored
  // the pre-hash would pass the first check alone.
  const preSha256 = { prehash: pqc.prehash('SHA-256') };
  const preSha512 = { prehash: pqc.prehash('SHA-512') };
  const hashed = pqc.signWithPriv('ML-DSA-44', message, pair.priv, preSha256);
  assert.ok(pqc.verifyWithPub('ML-DSA-44', hashed, message, pair.pub,
                              preSha256),
    "a pre-hashed signature verifies under the same pre-hash.");
  assert.ok(!pqc.verifyWithPub('ML-DSA-44', hashed, message, pair.pub,
                               preSha512),
    "HashML-DSA with SHA-512 must not accept a SHA-256 signature — the " +
    "hash OID is inside the signed message.");
  assert.ok(!pqc.verifyWithPub('ML-DSA-44', hashed, message, pair.pub, {}),
    "and pure ML-DSA must not accept a pre-hashed signature.");

  log.debug("Leaving checkContextAndPrehash().");
}

// ---------------------------------------------------------------------------
// 9. A composite signature must need BOTH halves.
// ---------------------------------------------------------------------------
// This is the assertion the whole composite idea rests on. A composite that
// verified when only its ML-DSA half was right would be strictly worse than
// plain ML-DSA — it would carry a traditional signature that nothing checks,
// which is exactly the false assurance the construction exists to prevent.
function checkCompositeHalves() {
  log.debug("Entering checkCompositeHalves().");
  const message = utf8("both halves or nothing");

  Object.keys(pqc.COMPOSITE_ALGS).forEach(function (name) {
    const entry = pqc.signatureAlg(name);
    const cfg = pqc.COMPOSITE_ALGS[name];
    const trad = pqc.TRAD[cfg.trad];
    const mlSigLen = entry.lengths.signature - trad.sigLen;

    const pair = pqc.generateAkpKeyPair(name);
    const sig = pqc.signWithPriv(name, message, pair.priv);
    assert.ok(pqc.verifyWithPub(name, sig, message, pair.pub),
      name + " must verify a well-formed composite signature.");

    // Replace the traditional half with one from a different key pair. The
    // ML-DSA half is untouched and still correct.
    const stranger = pqc.generateAkpKeyPair(name);
    const strangerSig = pqc.signWithPriv(name, message, stranger.priv);
    const frankenstein = bytes.concatBytes(sig.slice(0, mlSigLen),
                                           strangerSig.slice(mlSigLen));
    assert.ok(!pqc.verifyWithPub(name, frankenstein, message, pair.pub),
      name + " must refuse a signature whose traditional half was replaced.");

    // And the mirror: a correct traditional half with a foreign ML-DSA half.
    const mirrored = bytes.concatBytes(strangerSig.slice(0, mlSigLen),
                                       sig.slice(mlSigLen));
    assert.ok(!pqc.verifyWithPub(name, mirrored, message, pair.pub),
      name + " must refuse a signature whose ML-DSA half was replaced.");

    // components() is what the pane uses to say WHICH half failed, and a
    // status line that said the wrong one would be worse than none.
    const verdict = entry.components(frankenstein, message, pair.pub);
    assert.strictEqual(verdict.mldsa, true,
      name + ": the untouched ML-DSA half should report valid.");
    assert.strictEqual(verdict.trad, false,
      name + ": the replaced traditional half should report invalid.");

    // A truncated signature is malformed, not "invalid but well-formed".
    const truncated = sig.slice(0, sig.length - 1);
    assert.ok(!pqc.verifyWithPub(name, truncated, message, pair.pub),
      name + " must refuse a truncated composite signature.");
    assert.strictEqual(entry.components(truncated, message, pair.pub)
      .wellFormed, false,
      name + ": a truncated signature must be reported as malformed.");
  });

  log.debug("Leaving checkCompositeHalves().");
}

// ---------------------------------------------------------------------------
// 10. KEMs: round trips, refusals, and the combiner's inputs.
// ---------------------------------------------------------------------------
function checkKems() {
  log.debug("Entering checkKems().");
  Object.keys(pqc.KEM_ALGS).forEach(function (name) {
    const kem = pqc.kemAlg(name);
    const pair = kem.keygen();
    const enc = kem.encapsulate(pair.publicKey);
    const back = kem.decapsulate(enc.cipherText, pair.secretKey);
    assert.strictEqual(hex(back), hex(enc.sharedSecret),
      name + " must decapsulate to the secret it encapsulated.");
    assert.strictEqual(enc.sharedSecret.length, 32,
      name + " produces a 256-bit shared secret.");

    // A ciphertext for somebody else must not yield the same secret. ML-KEM
    // is implicitly rejecting — it returns a pseudo-random secret rather than
    // an error — so "different" is the correct assertion, not "throws".
    const stranger = kem.keygen();
    const strangerEnc = kem.encapsulate(stranger.publicKey);
    const wrong = kem.decapsulate(strangerEnc.cipherText, pair.secretKey);
    assert.notStrictEqual(hex(wrong), hex(strangerEnc.sharedSecret),
      name + " must not recover another recipient's shared secret.");
  });

  // The composite combiner is SHA3-256(mlkemSS || tradSS || tradCT ||
  // tradPK || Label) — asserted here against a hash computed from the parts,
  // so that a reordering of those five inputs is caught. A round trip cannot
  // see it: both ends would reorder identically.
  const sample = {
    mlkemSS: bytes.hexToBytes("00".repeat(32)),
    tradSS: bytes.hexToBytes("11".repeat(32)),
    tradCT: bytes.hexToBytes("22".repeat(65)),
    tradPK: bytes.hexToBytes("33".repeat(65))
  };
  const label = pqc.COMPOSITE_KEMS['MLKEM768-ECDH-P256'].label;
  const expected = require("crypto").createHash("sha3-256")
    .update(Buffer.from(bytes.concatBytes(sample.mlkemSS, sample.tradSS,
                                          sample.tradCT, sample.tradPK,
                                          utf8(label))))
    .digest("hex");
  assert.strictEqual(hex(pqc.kemCombiner(sample.mlkemSS, sample.tradSS,
                                         sample.tradCT, sample.tradPK, label)),
    expected,
    "the KEM combiner must be SHA3-256 over mlkemSS || tradSS || tradCT || " +
    "tradPK || Label, in that order — node's own SHA3 is the second " +
    "implementation here.");

  log.debug("Leaving checkKems().");
}

// ---------------------------------------------------------------------------
// 11. JWS: every post-quantum algorithm end to end, and what is NOT offered.
// ---------------------------------------------------------------------------
function checkJws() {
  log.debug("Entering checkJws().");
  const payload = JSON.stringify({ iss: "debugger", sub: "pq" });
  const pqAlgs = jws.algIds().filter(function (id) {
    return jws.ALGS[id].family === 'pq';
  });
  assert.strictEqual(pqAlgs.length, 11,
    "eleven post-quantum JOSE algorithms are wired up: 3 ML-DSA (RFC 9964), " +
    "2 SLH-DSA and 6 composite (drafts). FN-DSA's identifiers are registered " +
    "by draft-ietf-cose-falcon-04 but there is no signer this bundle can " +
    "load, and pqc.js's MISSING table records that — an `alg` the page " +
    "offers and cannot honour would be worse than the absence.");

  pqAlgs.forEach(function (algId) {
    const key = jws.generateKey(algId);
    const privJwk = jws.privateJwk(algId, key.privateKey, key.publicKey, 'k1');
    const pubJwk = jws.publicJwk(algId, key.publicKey, 'k1');
    assert.strictEqual(pubJwk.kty, 'AKP',
      algId + " must publish an AKP JWK.");

    const token = jws.signJws({ algId: algId, payload: payload,
                                privateKey: privJwk });
    const compact = typeof token === 'string' ? token
      : (token.jws || token.serialized || token.compact || token.token);
    const parts = String(compact).split('.');
    assert.strictEqual(parts.length, 3,
      algId + " must produce a three-part compact JWS.");

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    assert.strictEqual(header.alg, algId,
      algId + " must appear verbatim in the protected header.");

    const good = jws.verifyJws({ jws: compact, publicKey: pubJwk });
    const verdict = good.entries ? good.entries[0].verdict : good;
    assert.strictEqual(verdict.valid, true,
      algId + " must verify a JWS it signed.");

    // The negative that matters: a swapped payload.
    const tampered = parts[0] + '.' +
      Buffer.from(JSON.stringify({ iss: "attacker" })).toString('base64url') +
      '.' + parts[2];
    const bad = jws.verifyJws({ jws: tampered, publicKey: pubJwk });
    const badVerdict = bad.entries ? bad.entries[0].verdict : bad;
    assert.strictEqual(badVerdict.valid, false,
      algId + " must refuse a JWS whose payload was replaced.");
  });

  // Only two SLH-DSA parameter sets have a JOSE name, and the raw pane's
  // other ten must NOT have leaked into the JWS table. Registering
  // "SLH-DSA-SHA2-256f" as an `alg` would be this project's invention.
  const slhInJws = pqAlgs.filter(function (id) { return /^SLH-DSA/.test(id); });
  assert.deepStrictEqual(slhInJws.sort(),
    ['SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s'],
    "draft-ietf-cose-sphincs-plus-10 registers exactly two SLH-DSA " +
    "algorithms — one NIST category 1 'small' set per hash family. The " +
    "other ten FIPS 205 parameter sets have no JOSE `alg` and must not be " +
    "offered as one.");

  // ...while the raw registry still carries all twelve, because the
  // PRIMITIVE is standardised even where the envelope binding is not.
  const slhInRegistry = Object.keys(pqc.SIGNATURE_ALGS).filter(function (n) {
    return pqc.SIGNATURE_ALGS[n].family === 'SLH-DSA';
  });
  assert.strictEqual(slhInRegistry.length, 12,
    "all twelve FIPS 205 parameter sets remain available as primitives.");

  // The absence of FN-DSA must be RECORDED, not merely true. This is the
  // assertion that stops it being silently forgotten if the bundler ever
  // changes and the algorithm becomes available.
  assert.ok(pqc.MISSING.some(function (m) { return /FN-DSA/.test(m.name); }),
    "FN-DSA is absent for an implementation reason rather than a " +
    "specification one, and MISSING must say so.");

  log.debug("Leaving checkJws().");
}

// ---------------------------------------------------------------------------
// 12. Every algorithm says which standard it is, and drafts say they are.
// ---------------------------------------------------------------------------
// The rule this enforces is the one the whole module was written around: a
// debugger may implement a draft, but it must never present one as settled.
function checkStandardsMetadata() {
  log.debug("Entering checkStandardsMetadata().");
  const everything = Object.keys(pqc.SIGNATURE_ALGS)
    .map(function (n) { return pqc.SIGNATURE_ALGS[n]; })
    .concat(Object.keys(pqc.KEM_ALGS)
      .map(function (n) { return pqc.KEM_ALGS[n]; }));

  everything.forEach(function (entry) {
    assert.ok(entry.spec, entry.name + " must name the specification it " +
      "implements.");
    assert.ok(pqc.SPECS[entry.spec],
      entry.name + " cites an unknown specification id: " + entry.spec);
    const spec = pqc.SPECS[entry.spec];
    assert.ok(spec.status === 'rfc' || spec.status === 'draft',
      entry.name + "'s specification must be marked published or draft.");
    if (spec.status === 'draft') {
      assert.ok(spec.note && spec.note.length > 20,
        entry.name + " cites a draft, so that draft MUST carry the note the " +
        "pages render beside it. A draft presented without one is the " +
        "failure this whole module exists to prevent.");
      assert.ok(/draft-/.test(spec.note),
        entry.name + "'s draft note must name the draft revision — " +
        "\"implements the draft\" without a revision is the claim that " +
        "ages worst.");
    }
  });

  // specNote() is what the panes call; it must be empty for a published
  // standard and non-empty for a draft, with no third case.
  assert.strictEqual(pqc.specNote('RFC.9964'), '',
    "a published RFC gets no draft warning.");
  assert.ok(pqc.specNote('I-D.cose-falcon').length > 0,
    "a draft gets one.");
  assert.strictEqual(pqc.isDraft('FIPS.204'), false);
  assert.strictEqual(pqc.isDraft('I-D.jose-pqc-kem'), true);

  // And the algorithms that are deliberately absent are recorded as such,
  // with a reason — so an absent pane reads as a decision.
  assert.ok(pqc.MISSING.length >= 1, "the omissions must be recorded.");
  pqc.MISSING.forEach(function (m) {
    assert.ok(m.name && m.reason && m.reason.length > 40,
      "each omitted algorithm must say why it is omitted.");
  });
  assert.ok(pqc.MISSING.some(function (m) { return m.name === 'HQC'; }),
    "HQC is selected by NIST but has no implementable specification, and " +
    "that must be written down rather than left as a silent gap.");

  log.debug("Leaving checkStandardsMetadata().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The post-quantum engines, in node.");
  checkNoDom();
  checkXWingVectors();
  checkCompositeLabels();
  checkSizes();
  checkPrehashMapping();
  checkAkpJwk();
  checkSignatures();
  checkContextAndPrehash();
  checkCompositeHalves();
  checkKems();
  checkJws();
  checkStandardsMetadata();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (error) {
  log.error(error.stack || error.message);
  process.exit(1);
});
