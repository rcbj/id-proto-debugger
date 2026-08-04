// File: jwt_vc_json_issuance_waltid.js
//
// ---------------------------------------------------------------------------
// OID4VCI issuance in the jwt_vc_json format, against walt.id's issuer-api2.
//
// The interoperability half of jwt_vc_json_issuance.js: same format, same
// assertions about what a VC-JWT has to be, someone else's implementation
// producing it. What differs is what may be ASSUMED. The mock issuer binds a
// jwt_vc_json holder with cnf.jwk; walt.id's own profiles bind with a subject
// DID (mapping.credentialSubject.id = "<subjectDid>"). Neither is wrong, so this
// test reports which it got and fails only when there is no binding at all —
// asserting our mock's choice here would be asserting that walt.id agrees with
// us, which is not what an interoperability test is for.
//
// Skipped, not failed, when walt.id offers no jwt_vc_json configuration. That is
// the state of a checkout whose walt.id container has not been restarted onto
// the configuration in waltid/config/credential-issuer-metadata.conf.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const common = require("./jwt_vc_json_common.js");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwt_vc_json_issuance_waltid",
                                level: appconfig.logLevel || "info" });

// walt.id's Credential Issuer Identifier has a PATH. WALTID_ISSUER_URL is the
// bare base (http://localhost:7005) — the identifier is that plus /openid4vci,
// and its metadata therefore lives at
// /.well-known/openid-credential-issuer/openid4vci, because RFC 8414 INSERTS the
// well-known segment before the path rather than appending it. Passing the bare
// base looks for the document one path short and finds a 404, which reads as
// "walt.id offers no jwt_vc_json" when in fact nothing was ever asked.
// sd_jwt_vc_waltid.js does the same thing for the same reason.
var WALTID_PATH = process.env.WALTID_ISSUER_PATH || "/openid4vci";
// walt.id's issuance profile that carries the jwt_vc_json configuration. It is
// what the pre-authorized offer is created from, and therefore how a real access
// token is obtained without driving a browser through Keycloak.
var WALTID_PROFILE_ID = process.env.WALTID_JWT_VC_PROFILE_ID || "identityCredentialJwtVcJson";

var issuerBase = process.env.WALTID_ISSUER_URL
  ? String(process.env.WALTID_ISSUER_URL).replace(/\/+$/, "") + WALTID_PATH
  : "";

async function test() {
  log.debug("Entering test().");
  // Every one of these is a FAILURE rather than a skip: this job is the only
  // thing that proves jwt_vc_json interoperates, and a run where it quietly did
  // nothing reports success for a format nobody tested.
  assert.ok(issuerBase,
    "WALTID_ISSUER_URL is not set, so walt.id's issuer was never asked for a jwt_vc_json credential.");
  log.info("Running jwt_vc_json issuance against walt.id at " + issuerBase);

  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.meta, "no credential issuer metadata at " + issuerBase + ".");
  assert.ok(found.id,
    "walt.id offers no jwt_vc_json credential configuration, so this interoperability check did not run. " +
    "Offered: " + Object.keys(found.meta.credential_configurations_supported || {}).join(", ") +
    ". The configuration is in waltid/config/credential-issuer-metadata.conf with a matching profile in " +
    "issuer2-profiles.conf — restart waltid-issuer-api to load it.");

  // --- what it advertises ---------------------------------------------------
  const entry = found.entry;
  assert.strictEqual(entry.format, common.FORMAT, "the configuration should name the format.");
  assert.ok(entry.credential_definition && Array.isArray(entry.credential_definition.type),
    "a jwt_vc_json configuration identifies its credential with credential_definition.type. Got: " +
    JSON.stringify(entry.credential_definition));
  log.info("[metadata] walt.id offers " + found.id + " -> " +
           entry.credential_definition.type.join("/") + ".");

  // --- what it issues -------------------------------------------------------
  // A REAL token: walt.id refuses anything that is not a JWS, unlike our mock.
  const accessToken = await common.preAuthorizedAccessToken(issuerBase, WALTID_PROFILE_ID);
  assert.ok(accessToken,
    "could not obtain an access token from walt.id with the pre-authorized code grant for profile \"" +
    WALTID_PROFILE_ID + "\". Without one the credential endpoint answers 401 and nothing about " +
    "jwt_vc_json gets tested.");
  // "did": walt.id resolves the subject DID from the proof for this format.
  const held = await common.mintJwtVcJson(issuerBase, found.id, accessToken, "did");
  const parsed = common.assertIsJwtVcJson(held.credential, "walt.id");

  const claimCount = Object.keys(parsed.credentialSubject).filter(function (k) { return k !== "id"; }).length;
  assert.ok(claimCount > 0, "walt.id should assert something about the subject.");

  // --- holder binding: reported, not dictated -------------------------------
  const binding = common.holderBindingOf(parsed.payload);
  assert.notStrictEqual(binding.kind, "none",
    "an issued credential must say who may present it — cnf.jwk or a subject DID in credentialSubject.id. " +
    "walt.id's credential carries neither, which would make it unpresentable by anyone.");
  if (binding.kind === "cnf.jwk") {
    assert.strictEqual(binding.jwk.x, held.publicJwk.x,
      "a cnf.jwk binding should name the key the proof of possession presented.");
    log.info("[binding] walt.id bound this credential with cnf.jwk, the same way our mock does.");
  } else {
    log.info("[binding] walt.id bound this credential by SUBJECT DID (" + binding.subjectId + "), where our " +
             "mock uses cnf.jwk. Both are legitimate; it means a wallet has to sign the presentation with " +
             "the key behind that DID, which is what the presentation job reports on.");
  }

  log.info("[issuance] OK — walt.id issued a " + parsed.types.join("/") + " with " + claimCount +
           " claim(s), bound by " + binding.kind + ".");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>", "run headless (true/false)"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
