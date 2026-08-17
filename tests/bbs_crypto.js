// File: bbs_crypto.js
//
// ---------------------------------------------------------------------------
// The BBS signatures the debugger produces, checked by an implementation that
// is not ours.
//
// This is the foundation the bbs-2023 cryptosuite stands on, and it is the one
// piece where "it works" cannot be established by testing the code against
// itself. BBS has several places where a signer and a verifier can share the
// same mistake and agree perfectly with each other while agreeing with nobody
// else in the world — the ciphersuite's fixed P1 point, the API id the domain
// separation tags are built from, the generator derivation. The first draft of
// client/src/bbs.js got two of those wrong and its own round trip passed.
//
// So the oracle is @digitalbazaar/bbs-signatures: a different BBS
// implementation, used here and by the STS. It is ESM-only, which is why the
// browser cannot use it (browserify consumes CommonJS) and therefore why there
// are two implementations at all. Be precise about how independent that is: the
// two share @noble/curves for field and curve arithmetic, so what is
// cross-checked is the BBS PROTOCOL layer — generators, domain, the signature
// equation — not the underlying maths.
//
// The strongest assertion here is byte-identity. BBS signing is deterministic
// for a given key, header and message set, so two correct implementations do
// not merely accept each other's signatures, they produce the same bytes.
// Anything less than that would mean one of them is doing something the other
// tolerates.
//
// SINCE 2026-08-17 THERE IS A SECOND ORACLE, and it is the stronger one: the
// draft's own published test vectors, vendored as tests/bbs_vectors.json. They
// are here because the module grew what the Digital Signature page's BBS pane
// needed — KeyGen, and the second ciphersuite, BLS12-381-SHAKE-256 — and the
// independent implementation cannot settle either one. It has no exported
// KeyGen taking key_info and key_dst, and at 3.1.0 it does not reproduce the
// draft's SHAKE-256 vectors at all (its @noble/curves 2.x hashes to G1
// differently under XOF), while this module reproduces them byte for byte. So
// each oracle is used for what it can actually settle, and the disagreement is
// re-checked on every run rather than written in as an expectation: if a later
// release starts matching the draft, the cross-implementation check for that
// suite starts running by itself.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "bbs_crypto", level: appconfig.logLevel ||
    "info" });

var bbs = paths.requireSharedModule(
  [path.join(__dirname, "bbs.js"),
   path.join(__dirname, "..", "client", "src", "bbs.js")],
  "the BBS module");

const SK = 0x2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079n;
const hex = function (u8) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(u8).toString("hex");
};

// The draft's own published test vectors, vendored beside this file. They are
// the oracle for anything the independent implementation cannot answer for —
// which since 2026-08-17 includes the whole BLS12-381-SHAKE-256 ciphersuite:
// @digitalbazaar/bbs-signatures 3.1.0 does not reproduce the draft's SHAKE
// vectors (its @noble/curves 2.x hashes to G1 differently under XOF), while
// this repository's module reproduces them byte for byte. So the two oracles
// are used for what each can actually settle, and the disagreement is checked
// rather than assumed — see independentImplementationOnShake() below.
const VECTORS = require("./bbs_vectors.json");
const bytes = function (hexText) {
  log.debug("Entering bytes().");
  log.debug("Leaving bytes().");
  return Uint8Array.from(Buffer.from(hexText, "hex"));
};

async function crossCheckSha256(theirs) {
  log.debug("Entering crossCheckSha256().");
  const suite = theirs.CIPHERSUITES.BLS12381_SHA256;

  log.info("=== Key derivation ===");
  const pk = bbs.secretKeyToPublicKey(SK);
  const skBytes = bbs.i2osp(SK, 32);
  const theirPk = await theirs.secretKeyToPublicKey({ secretKey: skBytes,
      ciphersuite: suite });
  assert.strictEqual(hex(pk), hex(theirPk),
    "the same secret key must give the same public key in both " +
        "implementations.");
  assert.strictEqual(pk.length, 96,
                     "a BLS12-381 G2 public key is 96 compressed bytes.");
  log.info("[keys] OK — identical 96-byte public key from the same secret.");

  const messages = ["given_name:Alice", "family_name:Smith",
      "birthdate:1980-01-01", "country:US"]
    .map(function (m) { return bbs.te(m); });
  const header = bbs.te("bbs-2023 test header");

  log.info("=== Signing, both directions ===");
  const ourSig = bbs.sign(SK, pk, header, messages);
  assert.strictEqual(ourSig.length, 80,
                     "a BBS signature is 80 bytes (48-byte A, 32-byte e).");

  const theyAccept = await theirs.verifySignature(
    { publicKey: pk, signature: ourSig, header, messages, ciphersuite: suite });
  assert.strictEqual(theyAccept, true,
    "an independent implementation must accept the signature the debugger " +
        "produced. This is the " +
    "assertion the whole bbs-2023 feature rests on: if it fails, the " +
        "debugger is emitting something " +
    "only it believes.");

  const theirSig = await theirs.sign(
    { secretKey: skBytes, publicKey: theirPk, header, messages,
     ciphersuite: suite });
  assert.strictEqual(bbs.verify(pk, theirSig, header, messages), true,
    "and the debugger must accept theirs.");

  assert.strictEqual(hex(ourSig), hex(theirSig),
    "BBS signing is deterministic, so two correct implementations produce " +
        "the SAME BYTES. Merely " +
    "accepting each other would leave room for one of them to be doing " +
        "something the other tolerates.");
  log.info("[sign] OK — byte-identical 80-byte signatures, each accepted by " +
           "the other.");

  log.info("=== A tampered message is refused by both ===");
  const tampered = ["given_name:Mallory", "family_name:Smith",
      "birthdate:1980-01-01", "country:US"]
    .map(function (m) { return bbs.te(m); });
  assert.strictEqual(bbs.verify(pk, ourSig, header, tampered), false,
    "the debugger must refuse a signature over different messages.");
  const theirVerdict = await theirs.verifySignature(
    { publicKey: pk, signature: ourSig, header, messages: tampered,
     ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(theirVerdict, false,
                     "and so must the independent implementation.");
  log.info("[tamper] OK — a changed claim is refused by both.");

  log.info("=== A changed header is refused ===");
  assert.strictEqual(bbs.verify(pk, ourSig, bbs.te("a different header"),
                     messages), false,
    "the header is signed over, so changing it must invalidate the signature.");
  log.info("[header] OK — the header is bound into the signature.");

  log.info("=== Message count and order both matter ===");
  const reordered = [messages[1], messages[0], messages[2], messages[3]];
  assert.strictEqual(bbs.verify(pk, ourSig, header, reordered), false,
    "each message is bound to its own generator, so reordering must " +
        "invalidate the signature — this " +
    "is what stops a holder shuffling claims between fields.");
  assert.strictEqual(bbs.verify(pk, ourSig, header, messages.slice(0, 3)),
                     false,
    "and dropping one must too.");
  log.info("[binding] OK — order and count are both bound.");

  log.info("=== Derived proofs: selective disclosure, cross-checked ===");
  const ph = bbs.te("verifier nonce 12345");
  const disclosed = [0, 2];
  const disclosedMessages = disclosed.map(function (i) { return messages[i]; });

  const ourProof = bbs.proofGen(pk, ourSig, header, ph, messages, disclosed);
  assert.strictEqual(ourProof.length, 336,
    "a BBS proof disclosing 2 of 4 messages is 336 bytes (3 points + 6 " +
        "scalars).");

  const theyAcceptProof = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header, presentationHeader: ph,
    disclosedMessages, disclosedMessageIndexes: disclosed,
        ciphersuite: suite });
  assert.strictEqual(theyAcceptProof, true,
    "an independent implementation must accept the derived proof the wallet " +
        "produced. This is what " +
    "bbs-2023 selective disclosure rests on.");

  const theirProof = await theirs.deriveProof({
    publicKey: pk, signature: ourSig, header, presentationHeader: ph,
    messages, disclosedMessageIndexes: disclosed, ciphersuite: suite });
  assert.strictEqual(bbs.proofVerify(pk, theirProof, header, ph,
                     disclosedMessages, disclosed), true,
    "and the debugger must accept theirs.");
  log.info("[proof] OK — 336-byte proofs, each implementation accepting " +
           "the other's.");

  log.info("=== Unlinkability ===");
  const secondProof = bbs.proofGen(pk, ourSig, header, ph, messages, disclosed);
  assert.notStrictEqual(hex(ourProof), hex(secondProof),
    "two derivations of the SAME credential must differ. This is the " +
        "property an SD-JWT cannot offer: " +
    "there the issuer signature is reused verbatim, so two presentations are " +
        "trivially linkable.");
  assert.strictEqual(await theirs.verifyProof({
    publicKey: pk, proof: secondProof, header, presentationHeader: ph,
    disclosedMessages, disclosedMessageIndexes: disclosed,
        ciphersuite: suite }), true,
    "and both must verify.");
  log.info("[unlinkable] OK — fresh randomness per derivation, both " +
           "proofs valid.");

  log.info("=== What a derived proof must refuse ===");
  const substituted = [messages[0], bbs.te("country:FR")];
  const forged = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header, presentationHeader: ph,
    disclosedMessages: substituted, disclosedMessageIndexes: disclosed,
        ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(forged, false,
    "claiming a different value for a disclosed message must be refused.");

  const replayed = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header,
        presentationHeader: bbs.te("a different nonce"),
    disclosedMessages, disclosedMessageIndexes: disclosed, ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(replayed, false,
    "the presentation header is the verifier's nonce, so a proof replayed " +
        "into another session must " +
    "be refused — otherwise the nonce buys nothing.");

  assert.strictEqual(
    bbs.proofVerify(pk, ourProof, header, ph, disclosedMessages, disclosed),
                    true,
    "the control: the same proof, checked properly, still verifies — so the " +
        "refusals above are about " +
    "the defects and not about the verifier.");
  log.info("[proof-negative] OK — substituted disclosure and replay both " +
           "refused; control verifies.");
  log.debug("Leaving crossCheckSha256().");
}

// Both ciphersuites, against the draft's fixtures. KeyGen first, because the
// fixtures hand it every input the algorithm takes — key material, key info
// and an explicit key DST — which is the only way to pin a derivation that is
// otherwise reproducible only against itself.
async function draftTestVectors() {
  log.debug("Entering draftTestVectors().");
  log.info("=== The draft's own test vectors, both ciphersuites ===");
  const names = Object.keys(VECTORS.suites);
  assert.strictEqual(names.length, 2,
    "tests/bbs_vectors.json must carry both ciphersuites; found: " +
        names.join(", "));
  for (const name of names) {
    const suite = VECTORS.suites[name];
    const kp = suite.keypair;
    const sk = bbs.keyGen(bytes(kp.keyMaterial), bytes(kp.keyInfo),
        bytes(kp.keyDst), name);
    assert.strictEqual(hex(bbs.i2osp(sk, bbs.OCTET_SCALAR_LENGTH)),
        kp.secretKey,
      name + ": KeyGen did not reproduce the draft's secret key. Three " +
          "things diverge silently here: the default DST is built from the " +
          "BARE ciphersuite id, key_info is length-prefixed with two " +
          "octets, and the expansion differs per suite.");
    assert.strictEqual(hex(bbs.secretKeyToPublicKey(sk)), kp.publicKey,
      name + ": the draft's public key was not derived from its secret key.");
    log.info("[" + name + " KeyGen] OK — the draft's key pair, derived.");

    for (const v of suite.signatures) {
      const messages = v.messages.map(bytes);
      assert.strictEqual(
        bbs.verify(bytes(v.publicKey), bytes(v.signature), bytes(v.header),
                   messages, name),
        v.valid,
        name + " / " + v.name + ": " + v.caseName + " — expected " +
            (v.valid ? "valid" : "invalid" + " (" + v.reason + ")") + ".");
      if (!v.valid) continue;
      assert.strictEqual(
        hex(bbs.sign(BigInt("0x" + v.secretKey), bytes(v.publicKey),
                     bytes(v.header), messages, name)),
        v.signature,
        name + " / " + v.name + ": BBS signing is deterministic, so this " +
            "must be the draft's exact bytes rather than merely something " +
            "the draft's verifier accepts.");
    }
    log.info("[" + name + " signatures] OK — " + suite.signatures.length +
             " vectors, valid ones byte-identical.");

    for (const p of suite.proofs) {
      const disclosed = p.disclosedIndexes.map(function (i) {
        return bytes(p.messages[i]);
      });
      assert.strictEqual(
        bbs.proofVerify(bytes(p.publicKey), bytes(p.proof), bytes(p.header),
                        bytes(p.presentationHeader), disclosed,
                        p.disclosedIndexes, name),
        p.valid,
        name + " / " + p.name + ": " + p.caseName + " did not get the " +
            "draft's verdict.");
    }
    log.info("[" + name + " proofs] OK — " + suite.proofs.length +
             " derived-proof vectors.");
  }
  log.debug("Leaving draftTestVectors().");
}

// The SHAKE-256 suite end to end in this implementation: sign, verify, refuse
// a tampered list, derive proofs, refuse a replay, and stay unlinkable. The
// vectors above prove the constants; this proves the operations compose.
async function shakeSuiteRoundTrip() {
  log.debug("Entering shakeSuiteRoundTrip().");
  const name = "BLS12-381-SHAKE-256";
  log.info("=== " + name + " round trip ===");
  const sk = bbs.keyGen(bytes("00".repeat(32)), bbs.te("digital signature " +
      "page"), undefined, name);
  const pk = bbs.secretKeyToPublicKey(sk);
  const messages = ["given_name:Alice", "family_name:Smith",
      "birthdate:1980-01-01", "country:US"].map(function (m) {
    return bbs.te(m);
  });
  const header = bbs.te("BBS test header");
  const ph = bbs.te("verifier nonce 12345");
  const disclosed = [0, 2];
  const disclosedMessages = disclosed.map(function (i) { return messages[i]; });

  const sig = bbs.sign(sk, pk, header, messages, name);
  assert.strictEqual(sig.length, 80,
                     "a BBS signature is 80 bytes in either ciphersuite.");
  assert.strictEqual(bbs.verify(pk, sig, header, messages, name), true,
                     name + ": the signature must verify.");
  assert.strictEqual(
    bbs.verify(pk, sig, header, [bbs.te("given_name:Mallory")].concat(
        messages.slice(1)), name), false,
    name + ": a changed message must be refused.");
  assert.strictEqual(bbs.verify(pk, sig, bbs.te("other"), messages, name),
                     false, name + ": the header is bound into the signature.");

  const proof = bbs.proofGen(pk, sig, header, ph, messages, disclosed, name);
  assert.strictEqual(
    bbs.proofVerify(pk, proof, header, ph, disclosedMessages, disclosed, name),
    true, name + ": the derived proof must verify.");
  assert.strictEqual(
    bbs.proofVerify(pk, proof, header, bbs.te("another nonce"),
                    disclosedMessages, disclosed, name),
    false, name + ": a proof replayed into another session must be refused.");
  const second = bbs.proofGen(pk, sig, header, ph, messages, disclosed, name);
  assert.notStrictEqual(hex(second), hex(proof),
    name + ": two derivations of one signature must differ — otherwise the " +
        "presentations are linkable and BBS buys nothing over an SD-JWT.");
  assert.strictEqual(
    bbs.proofVerify(pk, second, header, ph, disclosedMessages, disclosed,
                    name), true, name + ": and both must verify.");
  log.info("[" + name + "] OK — sign/verify, proofs, replay refused, " +
           "unlinkable.");
  log.debug("Leaving shakeSuiteRoundTrip().");
}

// A key or a signature belongs to ONE ciphersuite, and nothing in either byte
// string says which. So the separation has to be checked: each suite's own
// generators, domain and P1 must make the other's signature unverifiable
// rather than merely unlikely to verify.
async function ciphersuiteSeparation() {
  log.debug("Entering ciphersuiteSeparation().");
  log.info("=== The two ciphersuites do not interoperate ===");
  const material = bytes("11".repeat(32));
  const messages = [bbs.te("a"), bbs.te("b")];
  const header = bbs.te("h");
  const both = ["BLS12-381-SHA-256", "BLS12-381-SHAKE-256"];
  for (const name of both) {
    const other = both[1 - both.indexOf(name)];
    const sk = bbs.keyGen(material, undefined, undefined, name);
    const pk = bbs.secretKeyToPublicKey(sk);
    const sig = bbs.sign(sk, pk, header, messages, name);
    assert.strictEqual(bbs.verify(pk, sig, header, messages, name), true,
                       name + ": the control must verify under its own suite.");
    let accepted;
    try {
      accepted = bbs.verify(pk, sig, header, messages, other);
    } catch (e) {
      accepted = false;
    }
    assert.strictEqual(accepted, false,
      "a " + name + " signature verified under " + other + ".");
    const otherSk = bbs.keyGen(material, undefined, undefined, other);
    assert.notStrictEqual(otherSk.toString(16), sk.toString(16),
      "the same key material gave the same key in both suites — KeyGen's " +
          "DST is suite-specific and must differ.");
  }
  log.info("[separation] OK — neither suite accepts the other's signature, " +
           "and KeyGen differs per suite.");
  log.debug("Leaving ciphersuiteSeparation().");
}

// What the independent implementation says about the SHAKE-256 suite. It is
// checked, not assumed: today @digitalbazaar/bbs-signatures 3.1.0 disagrees
// with the draft's own vectors here (ours agrees), so its verdict is reported
// rather than asserted. If a later release starts reproducing the vectors, the
// full byte-identity cross-check runs automatically — which is the point of
// deciding this at run time instead of writing the disagreement in as an
// expectation nobody revisits.
async function independentImplementationOnShake(theirs) {
  log.debug("Entering independentImplementationOnShake().");
  const name = "BLS12-381-SHAKE-256";
  const suite = theirs.CIPHERSUITES.BLS12381_SHAKE256;
  const v = VECTORS.suites[name].signatures.find(function (s) {
    return s.valid;
  });
  const messages = v.messages.map(bytes);
  let theirSig = null;
  try {
    theirSig = await theirs.sign({ secretKey: bytes(v.secretKey),
      publicKey: bytes(v.publicKey), header: bytes(v.header), messages,
      ciphersuite: suite });
  } catch (e) {
    log.warn("[shake cross-impl] the independent implementation could not " +
             "sign under " + name + ": " + e.message);
    log.debug("Leaving independentImplementationOnShake(). Could not sign.");
    return;
  }
  if (hex(theirSig) !== v.signature) {
    log.warn("[shake cross-impl] @digitalbazaar/bbs-signatures does not " +
             "reproduce the draft's " + name + " vector, so it is not an " +
             "oracle for this suite; tests/bbs_vectors.json is. Ours " +
             "matches the draft, which draftTestVectors() asserts.");
    log.debug("Leaving independentImplementationOnShake(). They diverge.");
    return;
  }
  assert.strictEqual(
    hex(bbs.sign(BigInt("0x" + v.secretKey), bytes(v.publicKey),
                 bytes(v.header), messages, name)),
    hex(theirSig),
    name + ": both implementations now reproduce the draft, so their bytes " +
        "must be identical.");
  assert.strictEqual(await theirs.verifySignature({
    publicKey: bytes(v.publicKey), signature: bytes(v.signature),
    header: bytes(v.header), messages, ciphersuite: suite }), true,
    name + ": the independent implementation must accept the draft's own " +
        "signature.");
  log.info("[shake cross-impl] OK — the independent implementation now " +
           "agrees with the draft on " + name + " too.");
  log.debug("Leaving independentImplementationOnShake().");
}

async function test() {
  log.debug("Entering test().");
  // ESM-only, so it is imported dynamically from this CommonJS test.
  const theirs = await import("@digitalbazaar/bbs-signatures");
  await crossCheckSha256(theirs);
  await draftTestVectors();
  await shakeSuiteRoundTrip();
  await ciphersuiteSeparation();
  await independentImplementationOnShake(theirs);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "unused; accepted so the runner can pass it"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
