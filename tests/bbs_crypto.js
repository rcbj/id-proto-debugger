// File: bbs_crypto.js
//
// ---------------------------------------------------------------------------
// The BBS signatures the debugger produces, checked by an implementation that is
// not ours.
//
// This is the foundation the bbs-2023 cryptosuite stands on, and it is the one
// piece where "it works" cannot be established by testing the code against
// itself. BBS has several places where a signer and a verifier can share the
// same mistake and agree perfectly with each other while agreeing with nobody
// else in the world — the ciphersuite's fixed P1 point, the API id the domain
// separation tags are built from, the generator derivation. The first draft of
// client/src/bbs.js got two of those wrong and its own round trip passed.
//
// So the oracle is @digitalbazaar/bbs-signatures: a different BBS implementation,
// used here and by the STS. It is ESM-only, which is why the browser cannot use
// it (browserify consumes CommonJS) and therefore why there are two
// implementations at all. Be precise about how independent that is: the two
// share @noble/curves for field and curve arithmetic, so what is cross-checked is
// the BBS PROTOCOL layer — generators, domain, the signature equation — not the
// underlying maths.
//
// The strongest assertion here is byte-identity. BBS signing is deterministic
// for a given key, header and message set, so two correct implementations do not
// merely accept each other's signatures, they produce the same bytes. Anything
// less than that would mean one of them is doing something the other tolerates.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "bbs_crypto", level: appconfig.logLevel || "info" });

var bbs = paths.requireSharedModule(
  [path.join(__dirname, "bbs.js"),
   path.join(__dirname, "..", "client", "src", "bbs.js")],
  "the BBS module");

const SK = 0x2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079n;
const hex = function (u8) { return Buffer.from(u8).toString("hex"); };

async function test() {
  // ESM-only, so it is imported dynamically from this CommonJS test.
  const theirs = await import("@digitalbazaar/bbs-signatures");
  const suite = theirs.CIPHERSUITES.BLS12381_SHA256;

  log.info("=== Key derivation ===");
  const pk = bbs.secretKeyToPublicKey(SK);
  const skBytes = bbs.i2osp(SK, 32);
  const theirPk = await theirs.secretKeyToPublicKey({ secretKey: skBytes, ciphersuite: suite });
  assert.strictEqual(hex(pk), hex(theirPk),
    "the same secret key must give the same public key in both implementations.");
  assert.strictEqual(pk.length, 96, "a BLS12-381 G2 public key is 96 compressed bytes.");
  log.info("[keys] OK — identical 96-byte public key from the same secret.");

  const messages = ["given_name:Alice", "family_name:Smith", "birthdate:1980-01-01", "country:US"]
    .map(function (m) { return bbs.te(m); });
  const header = bbs.te("bbs-2023 test header");

  log.info("=== Signing, both directions ===");
  const ourSig = bbs.sign(SK, pk, header, messages);
  assert.strictEqual(ourSig.length, 80, "a BBS signature is 80 bytes (48-byte A, 32-byte e).");

  const theyAccept = await theirs.verifySignature(
    { publicKey: pk, signature: ourSig, header, messages, ciphersuite: suite });
  assert.strictEqual(theyAccept, true,
    "an independent implementation must accept the signature the debugger produced. This is the " +
    "assertion the whole bbs-2023 feature rests on: if it fails, the debugger is emitting something " +
    "only it believes.");

  const theirSig = await theirs.sign(
    { secretKey: skBytes, publicKey: theirPk, header, messages, ciphersuite: suite });
  assert.strictEqual(bbs.verify(pk, theirSig, header, messages), true,
    "and the debugger must accept theirs.");

  assert.strictEqual(hex(ourSig), hex(theirSig),
    "BBS signing is deterministic, so two correct implementations produce the SAME BYTES. Merely " +
    "accepting each other would leave room for one of them to be doing something the other tolerates.");
  log.info("[sign] OK — byte-identical 80-byte signatures, each accepted by the other.");

  log.info("=== A tampered message is refused by both ===");
  const tampered = ["given_name:Mallory", "family_name:Smith", "birthdate:1980-01-01", "country:US"]
    .map(function (m) { return bbs.te(m); });
  assert.strictEqual(bbs.verify(pk, ourSig, header, tampered), false,
    "the debugger must refuse a signature over different messages.");
  const theirVerdict = await theirs.verifySignature(
    { publicKey: pk, signature: ourSig, header, messages: tampered, ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(theirVerdict, false, "and so must the independent implementation.");
  log.info("[tamper] OK — a changed claim is refused by both.");

  log.info("=== A changed header is refused ===");
  assert.strictEqual(bbs.verify(pk, ourSig, bbs.te("a different header"), messages), false,
    "the header is signed over, so changing it must invalidate the signature.");
  log.info("[header] OK — the header is bound into the signature.");

  log.info("=== Message count and order both matter ===");
  const reordered = [messages[1], messages[0], messages[2], messages[3]];
  assert.strictEqual(bbs.verify(pk, ourSig, header, reordered), false,
    "each message is bound to its own generator, so reordering must invalidate the signature — this " +
    "is what stops a holder shuffling claims between fields.");
  assert.strictEqual(bbs.verify(pk, ourSig, header, messages.slice(0, 3)), false,
    "and dropping one must too.");
  log.info("[binding] OK — order and count are both bound.");

  log.info("=== Derived proofs: selective disclosure, cross-checked ===");
  const ph = bbs.te("verifier nonce 12345");
  const disclosed = [0, 2];
  const disclosedMessages = disclosed.map(function (i) { return messages[i]; });

  const ourProof = bbs.proofGen(pk, ourSig, header, ph, messages, disclosed);
  assert.strictEqual(ourProof.length, 336,
    "a BBS proof disclosing 2 of 4 messages is 336 bytes (3 points + 6 scalars).");

  const theyAcceptProof = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header, presentationHeader: ph,
    disclosedMessages, disclosedMessageIndexes: disclosed, ciphersuite: suite });
  assert.strictEqual(theyAcceptProof, true,
    "an independent implementation must accept the derived proof the wallet produced. This is what " +
    "bbs-2023 selective disclosure rests on.");

  const theirProof = await theirs.deriveProof({
    publicKey: pk, signature: ourSig, header, presentationHeader: ph,
    messages, disclosedMessageIndexes: disclosed, ciphersuite: suite });
  assert.strictEqual(bbs.proofVerify(pk, theirProof, header, ph, disclosedMessages, disclosed), true,
    "and the debugger must accept theirs.");
  log.info("[proof] OK — 336-byte proofs, each implementation accepting the other's.");

  log.info("=== Unlinkability ===");
  const secondProof = bbs.proofGen(pk, ourSig, header, ph, messages, disclosed);
  assert.notStrictEqual(hex(ourProof), hex(secondProof),
    "two derivations of the SAME credential must differ. This is the property an SD-JWT cannot offer: " +
    "there the issuer signature is reused verbatim, so two presentations are trivially linkable.");
  assert.strictEqual(await theirs.verifyProof({
    publicKey: pk, proof: secondProof, header, presentationHeader: ph,
    disclosedMessages, disclosedMessageIndexes: disclosed, ciphersuite: suite }), true,
    "and both must verify.");
  log.info("[unlinkable] OK — fresh randomness per derivation, both proofs valid.");

  log.info("=== What a derived proof must refuse ===");
  const substituted = [messages[0], bbs.te("country:FR")];
  const forged = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header, presentationHeader: ph,
    disclosedMessages: substituted, disclosedMessageIndexes: disclosed, ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(forged, false,
    "claiming a different value for a disclosed message must be refused.");

  const replayed = await theirs.verifyProof({
    publicKey: pk, proof: ourProof, header, presentationHeader: bbs.te("a different nonce"),
    disclosedMessages, disclosedMessageIndexes: disclosed, ciphersuite: suite })
    .catch(function () { return false; });
  assert.strictEqual(replayed, false,
    "the presentation header is the verifier's nonce, so a proof replayed into another session must " +
    "be refused — otherwise the nonce buys nothing.");

  assert.strictEqual(
    bbs.proofVerify(pk, ourProof, header, ph, disclosedMessages, disclosed), true,
    "the control: the same proof, checked properly, still verifies — so the refusals above are about " +
    "the defects and not about the verifier.");
  log.info("[proof-negative] OK — substituted disclosure and replay both refused; control verifies.");

  log.info("Test completed successfully.");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused; accepted so the runner can pass it"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
