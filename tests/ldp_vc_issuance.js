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
  const pk = stsSuite.b64uToBytes(String(km.publicKeyMultibase).replace(/^u/, ""));

  const verdict = await stsSuite.verifyBase(cred, pk);
  assert.strictEqual(verdict.ok, true,
    "the base proof must verify against the key the credential points at. If this fails the issuer is " +
    "publishing a key it did not sign with.");
  assert.ok(verdict.statements.length > 4,
    "the credential should canonicalize to several statements; got " + verdict.statements.length);
  log.info("[verify] OK — the base proof verifies over " + verdict.statements.length + " statements.");

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
