// File: bbs2023_cryptosuite.js
//
// ---------------------------------------------------------------------------
// The bbs-2023 cryptosuite end to end, across two implementations.
//
// tests/bbs_crypto.js proves the BBS primitive. This proves the layer above it:
// turning a JSON-LD credential into the canonical statements BBS signs, and
// back. That layer has its own way of being silently wrong — a different
// context, a dropped term, a stray newline — and it fails looking exactly like a
// broken signature.
//
// The exchange deliberately crosses implementations at every step:
//
//   the STS issues        with @digitalbazaar/bbs-signatures (sts/bbs2023.js)
//   the wallet derives    with our own BBS      (client/src/bbs2023.js)
//   the STS verifies      the wallet's proof
//
// So neither side is marking its own homework. What the two MUST share is the
// canonical form, and that is asserted directly rather than assumed.
//
// No browser and no services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "bbs2023_cryptosuite", level: appconfig.logLevel || "info" });

// The browser module uses btoa/atob; node has them on Buffer.
if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = function (s) { return Buffer.from(s, "binary").toString("base64"); };
  globalThis.atob = function (s) { return Buffer.from(s, "base64").toString("binary"); };
}

// Two layouts: a checkout (separate trees) and the tests image (everything flat,
// with the STS's copy renamed because it shares a basename with the wallet's).
const paths = require("./module_paths.js");
const ROOT = path.join(__dirname, "..");
const walletSuite = paths.requireSharedModule(
  [path.join(__dirname, "bbs2023.js"), path.join(ROOT, "client", "src", "bbs2023.js")],
  "the wallet's bbs-2023 cryptosuite");
const stsSuite = paths.requireSharedModule(
  [path.join(__dirname, "sts_bbs2023.js"), path.join(ROOT, "sts", "bbs2023.js")],
  "the STS's bbs-2023 cryptosuite");

const enc = function (s) { return new TextEncoder().encode(s); };

async function test() {
  log.info("=== The STS issues an ldp_vc credential with a bbs-2023 base proof ===");
  const keys = await stsSuite.generateKeyPair();
  const unsecured = {
    "@context": ["https://www.w3.org/ns/credentials/v2", stsSuite.IDENTITY_CONTEXT_URL],
    type: ["VerifiableCredential", "IdentityCredential"],
    issuer: "http://localhost:8081",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder",
      given_name: "Alice", family_name: "Smith",
      email: "alice@example.com", birthDate: "1980-01-01"
    }
  };
  const issued = await stsSuite.issue(unsecured,
    { verificationMethod: "http://localhost:8081/bbs/keys/1", created: "2026-08-02T00:00:00Z" },
    keys.secretKey, keys.publicKey);

  assert.strictEqual(issued.credential.proof.type, "DataIntegrityProof",
    "a bbs-2023 credential carries an EMBEDDED proof — that is the whole reason this format can hold " +
    "BBS at all, where a JWS-secured one cannot.");
  assert.strictEqual(issued.credential.proof.cryptosuite, "bbs-2023", "and names the cryptosuite.");
  assert.ok(/^u/.test(issued.credential.proof.proofValue),
    "proofValue is multibase base64url, so it begins with 'u'.");
  assert.ok(issued.statements.length > 4,
    "the credential should canonicalize to several statements; got " + issued.statements.length);
  log.info("[issue] OK — " + issued.statements.length + " canonical statements, base proof attached.");

  const selfCheck = await stsSuite.verifyBase(issued.credential, keys.publicKey);
  assert.strictEqual(selfCheck.ok, true, "the STS must verify the base proof it just produced.");
  log.info("[issue] OK — the STS verifies its own base proof.");

  log.info("=== The two implementations agree on the canonical form ===");
  const ph = enc("verifier-nonce-xyz");
  const stmts = issued.statements;
  const chosen = [];
  stmts.forEach(function (s, i) { if (/givenName|birthDate/.test(s)) chosen.push(i); });
  assert.ok(chosen.length >= 2, "the fixture should offer at least two disclosable claims.");

  const derived = await walletSuite.deriveProof(issued.credential, keys.publicKey, chosen, ph);
  assert.deepStrictEqual(derived.statements, stmts,
    "the wallet and the issuer must canonicalize to byte-identical statements. If they do not, every " +
    "signature fails and it looks like a crypto bug rather than a canonicalization one.");
  log.info("[canonical] OK — identical statements from both implementations.");

  log.info("=== Selective disclosure, verified by the other side ===");
  const ok = await stsSuite.verifyDerived(keys.publicKey, derived.proof, derived.header, ph,
    derived.disclosedStatements, derived.disclosedIndexes);
  assert.strictEqual(ok, true,
    "the STS must accept the derived proof the WALLET produced. This is the assertion the whole " +
    "ldp_vc + bbs-2023 feature rests on.");
  assert.strictEqual(derived.disclosedIndexes.length, chosen.length,
    "only the chosen statements should be disclosed.");
  assert.ok(derived.disclosedStatements.every(function (s) { return !/email|familyName/.test(s); }),
    "and the withheld claims must genuinely not be in the disclosed set — this is the point of the " +
    "format, not a display choice.");
  log.info("[derive] OK — disclosed " + derived.disclosedIndexes.length + " of " + stmts.length +
           ", accepted by the issuer's implementation, withheld claims absent.");

  log.info("=== Unlinkability ===");
  const again = await walletSuite.deriveProof(issued.credential, keys.publicKey, chosen, ph);
  assert.notStrictEqual(Buffer.from(derived.proof).toString("hex"),
                        Buffer.from(again.proof).toString("hex"),
    "two derivations of the same credential must differ — the property an SD-JWT cannot offer.");
  assert.strictEqual(await stsSuite.verifyDerived(keys.publicKey, again.proof, again.header, ph,
    again.disclosedStatements, again.disclosedIndexes), true, "and both must verify.");
  log.info("[unlinkable] OK — fresh proof each derivation, both valid.");

  log.info("=== What the verifier must refuse ===");
  const replayed = await stsSuite.verifyDerived(keys.publicKey, derived.proof, derived.header,
    enc("a different nonce"), derived.disclosedStatements, derived.disclosedIndexes);
  assert.strictEqual(replayed, false,
    "a proof replayed into another session must be refused, or the verifier's nonce buys nothing.");

  const substituted = derived.disclosedStatements.slice();
  substituted[0] = substituted[0].replace(/"[^"]*"/, '"Mallory"');
  const forged = await stsSuite.verifyDerived(keys.publicKey, derived.proof, derived.header, ph,
    substituted, derived.disclosedIndexes);
  assert.strictEqual(forged, false, "claiming a different value for a disclosed statement must be refused.");

  const tampered = JSON.parse(JSON.stringify(issued.credential));
  tampered.credentialSubject.given_name = "Mallory";
  const tamperedCheck = await stsSuite.verifyBase(tampered, keys.publicKey);
  assert.strictEqual(tamperedCheck.ok, false, "an edited credential must fail its base proof.");

  assert.strictEqual(await stsSuite.verifyDerived(keys.publicKey, derived.proof, derived.header, ph,
    derived.disclosedStatements, derived.disclosedIndexes), true,
    "the control: the same proof checked properly still verifies, so the refusals above are about the " +
    "defects and not about the verifier.");
  log.info("[negative] OK — replay, substitution and an edited credential all refused; control verifies.");

  log.info("Test completed successfully.");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
