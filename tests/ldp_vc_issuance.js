// File: ldp_vc_issuance.js
//
// ---------------------------------------------------------------------------
// OID4VCI issuance in the ldp_vc format, secured by a bbs-2023 Data Integrity
// proof, against the mock Credential Issuer the STS hosts.
//
// The third format, and the one that is structurally different from the other
// two. dc+sd-jwt and jwt_vc_json are both JWS-secured strings; this is a JSON-LD
// document with an EMBEDDED proof, and that is exactly why it can carry BBS at
// all — a BBS signature has no home in a JWS, because there is no BBS `alg` in
// JOSE.
//
// What this asserts is the shape of that difference:
//
//   * the issuer advertises a CRYPTOSUITE where the other two advertise a JOSE
//     alg — that member is the visible sign of a different securing mechanism;
//   * what comes back is an object with proof.type DataIntegrityProof, not a
//     compact-serialized string;
//   * the issuer publishes the BBS key its proofs are made with, and the
//     credential points at it;
//   * the base proof actually verifies, and an edited credential does not.
//
// tests/bbs2023_cryptosuite.js covers the cryptosuite across two
// implementations; this covers the ISSUER endpoint and what it advertises.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "ldp_vc_issuance", level: appconfig.logLevel || "info" });

if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = function (s) { return Buffer.from(s, "binary").toString("base64"); };
  globalThis.atob = function (s) { return Buffer.from(s, "base64").toString("binary"); };
}

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
const ROOT = path.join(__dirname, "..");
const paths = require("./module_paths.js");
const stsSuite = paths.requireSharedModule(
  [path.join(__dirname, "sts_bbs2023.js"), path.join(ROOT, "sts", "bbs2023.js")],
  "the STS's bbs-2023 cryptosuite");
// The wallet's own half of the exchange, loaded so this test covers what the
// PAGE does with the response and not only what the issuer sends. Both are
// copied flat into the tests image, hence the two candidate paths.
const wallet = paths.requireSharedModule(
  [path.join(__dirname, "vci_wallet.js"), path.join(ROOT, "client", "src", "vci_wallet.js")],
  "the wallet's Credential Request/Response module");
const sdJwtVc = paths.requireSharedModule(
  [path.join(__dirname, "sd_jwt_vc.js"), path.join(ROOT, "client", "src", "sd_jwt_vc.js")],
  "the wallet's credential parsing module");

const LDP_CONFIG_ID = process.env.OID4VCI_LDP_CONFIG_ID || "IdentityCredentialLdpVc";

async function test() {
  log.info("Running ldp_vc issuance against " + issuerBase);
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta, "no credential issuer metadata at " + issuerBase + ". Start the STS mock.");
  const configs = meta.credential_configurations_supported || {};
  const entry = configs[LDP_CONFIG_ID];
  assert.ok(entry, "this issuer offers no ldp_vc configuration \"" + LDP_CONFIG_ID + "\". Offered: " +
    Object.keys(configs).join(", "));

  log.info("=== What the issuer advertises ===");
  assert.strictEqual(entry.format, "ldp_vc", "the configuration should name the format.");
  assert.deepStrictEqual(entry.credential_signing_alg_values_supported, ["bbs-2023"],
    "for ldp_vc this member holds a CRYPTOSUITE, not a JOSE alg — that is the visible sign that the " +
    "credential is secured by an embedded Data Integrity proof rather than by a JWS. Got: " +
    JSON.stringify(entry.credential_signing_alg_values_supported));
  assert.ok(entry.credential_definition && Array.isArray(entry.credential_definition.type),
    "a W3C credential is identified by its type array.");
  assert.ok(!entry.vct, "and carries no vct: that names an SD-JWT VC.");
  log.info("[metadata] OK — " + LDP_CONFIG_ID + " offers " +
    entry.credential_definition.type.join("/") + " as ldp_vc/bbs-2023.");

  log.info("=== What the credential endpoint returns ===");
  const held = await common.mintJwtVcJson(issuerBase, LDP_CONFIG_ID);
  const cred = held.credential;
  assert.strictEqual(typeof cred, "object",
    "an ldp_vc credential is a JSON OBJECT, not a compact-serialized string — the other two formats " +
    "are strings, and a string here would mean the wrong thing was issued.");
  assert.strictEqual((cred.proof || {}).type, "DataIntegrityProof",
    "the proof is EMBEDDED in the credential.");
  assert.strictEqual(cred.proof.cryptosuite, "bbs-2023", "and names the cryptosuite.");
  assert.ok(/^u/.test(cred.proof.proofValue), "proofValue is multibase base64url ('u').");
  assert.ok(cred.proof.verificationMethod, "and says where its key is.");
  assert.ok(cred.credentialSubject && cred.credentialSubject.id,
    "the subject is named — for this format by id, not by a cnf key.");
  log.info("[issue] OK — a " + [].concat(cred.type).join("/") + " with an embedded bbs-2023 proof.");

  log.info("=== The published key, and the proof it made ===");
  const km = (await common.httpJson(cred.proof.verificationMethod)).body;
  assert.ok(km && km.publicKeyMultibase,
    "the verificationMethod should resolve to a key. Got: " + JSON.stringify(km).slice(0, 160));
  assert.strictEqual(km.cryptosuite, "bbs-2023", "and name the cryptosuite it is for.");
    assert.ok(/^u/.test(km.publicKeyMultibase),
    "the key should be multibase base64url, which begins with 'u'.");
  const pk = stsSuite.multibaseToBytes(km.publicKeyMultibase);
  assert.strictEqual(pk.length, 96,
    "a BLS12-381 G2 public key is 96 compressed bytes. A short key here means the multibase prefix " +
    "was stripped twice — a decoder that also strips it, plus a caller that strips it, eats a data " +
    "character whenever the payload starts with 'u'. That is intermittent: it passes for most keys.");

  const verdict = await stsSuite.verifyBase(cred, pk);
  assert.strictEqual(verdict.ok, true,
    "the base proof must verify against the key the credential points at. If this fails the issuer is " +
    "publishing a key it did not sign with.");
  assert.ok(verdict.statements.length > 4,
    "the credential should canonicalize to several statements; got " + verdict.statements.length);
  log.info("[verify] OK — the base proof verifies over " + verdict.statements.length + " statements.");

  log.info("=== What the WALLET makes of that response ===");
  // The section above proves the ISSUER is right. That is not the same as the
  // workflow working, and the gap between the two is where this format failed:
  // step 2 showed "the response carries no credential" against an issuer whose
  // response this file had already asserted was correct. extractCredential()
  // recognized a credential only when it was a string, and an ldp_vc is an
  // object — so the one assertion above (typeof cred === "object") was exactly
  // the fact that broke the page, made without ever running the page.
  //
  // Asserted against held.responseBody — the bytes the issuer actually sent —
  // rather than a body rebuilt here, which would only re-assert this file's own
  // belief about the shape.
  assert.ok(held.responseBody, "the mint helper should hand back the Credential Response it received.");
  const stored = wallet.extractCredential(held.responseBody);
  assert.strictEqual(typeof stored, "string",
    "the wallet stores credentials as strings — localStorage takes a string, and an object reaches it " +
    "as the literal \"[object Object]\". An ldp_vc must therefore be serialized, not passed through.");
  assert.ok(stored,
    "extractCredential() returned nothing for an ldp_vc Credential Response. This is the step 2 failure: " +
    "the issuer answered 200 with a credential and the wallet reported \"the response carries no " +
    "credential\". Response was: " + JSON.stringify(held.responseBody).slice(0, 300));

  // The envelope trap: {credential: {...}} is itself an object, so a serializer
  // applied one level too high stores the wrapper AROUND the credential. That
  // is non-empty and a string, so both assertions above pass while what was
  // stored is unusable.
  const back = JSON.parse(stored);
  assert.ok(back.proof, "what was stored should BE the credential.");
  assert.ok(!back.credential,
    "what was stored is the {credential: …} envelope, not the credential inside it.");
  assert.deepStrictEqual(back, cred, "and should round-trip to exactly what the issuer sent.");

  // The batch member has to agree with the single one, or step 3's picker shows
  // something different from what step 2 kept. They disagreed before this fix:
  // allCredentials() passed the object through while extractCredential() did not.
  const all = wallet.allCredentials(held.responseBody);
  assert.strictEqual(all.length, 1, "one proof was sent, so one credential comes back.");
  assert.strictEqual(all[0], stored,
    "allCredentials() and extractCredential() must produce the SAME representation of the same " +
    "credential — step 2 stores the first under CREDENTIAL and the array under CREDENTIALS, and step 3 " +
    "reads both.");
  log.info("[wallet] OK — the response reads as a " + stored.length + "-character string.");

  // And that string has to survive the trip to step 3, which is the page that
  // renders it. It is stored as JSON text precisely because credentialFormat()
  // identifies an ldp_vc by a leading brace.
  const parsed = sdJwtVc.parseCredential(stored);
  assert.strictEqual(parsed.format, "ldp_vc",
    "step 3 must recognize the stored form as ldp_vc, not fail to parse it.");
  assert.strictEqual(parsed.selectivelyDisclosable, true,
    "ldp_vc IS selectively disclosable — over canonical statements rather than Disclosures.");
  assert.deepStrictEqual(parsed.disclosures, [], "and carries no Disclosures.");
  assert.ok(parsed.claims && parsed.claims.given_name,
    "the claims should be readable for the step 3 table. Got: " + JSON.stringify(parsed.claims));
  assert.strictEqual(parsed.subject, cred.credentialSubject.id,
    "the holder is named by credentialSubject.id for this format, not by a cnf key.");
  log.info("[wallet] OK — step 3 parses it as ldp_vc with " +
    Object.keys(parsed.claims).length + " claim(s), 0 Disclosures.");

  // The control. Without it "extraction works" could just mean the reader
  // returns something for anything it is handed — including the deferred
  // response, whose whole point is that it carries no credential yet.
  assert.strictEqual(wallet.extractCredential({ transaction_id: "t-1" }), "",
    "a deferred response carries no credential, and step 2 routes on exactly that emptiness — if this " +
    "returns a value, the deferred pane never opens.");
  assert.strictEqual(wallet.extractCredential({ credentials: [] }), "", "nor does an empty array.");
  assert.strictEqual(wallet.extractCredential(null), "", "nor a missing body.");
  log.info("[wallet] OK — and still reports nothing for a deferred/empty response.");

  log.info("=== An edited credential must not verify ===");
  const tampered = JSON.parse(JSON.stringify(cred));
  tampered.credentialSubject.given_name = "Mallory";
  const tamperedVerdict = await stsSuite.verifyBase(tampered, pk);
  assert.strictEqual(tamperedVerdict.ok, false,
    "changing a claim must break the base proof — the control below shows the check is not simply " +
    "always-false.");
  const control = await stsSuite.verifyBase(cred, pk);
  assert.strictEqual(control.ok, true, "the control: the untouched credential still verifies.");
  log.info("[tamper] OK — an edited claim is refused; the control still verifies.");

  log.info("Test completed successfully.");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) { log.error(e.stack || e.message); process.exit(1); });
