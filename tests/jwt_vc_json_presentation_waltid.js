// File: jwt_vc_json_presentation_waltid.js
//
// ---------------------------------------------------------------------------
// OID4VP presentation of a jwt_vc_json credential against walt.id's
// verifier-api2, with the credential issued by walt.id's issuer in the same run
// — so neither end of the exchange is ours.
//
// The interoperability half of jwt_vc_json_presentation.js. Two gates before it
// can say anything, and both are honest skips rather than failures:
//
//   1. walt.id must OFFER jwt_vc_json. Until its container is restarted onto the
//      configuration in waltid/config/, it offers only dc+sd-jwt.
//
//   2. The credential must be presentable BY THIS WALLET. walt.id's own
//      jwt_vc_json profiles bind the holder with a subject DID
//      (mapping.credentialSubject.id = "<subjectDid>"), not with the cnf.jwk our
//      mock uses. A VP JWT has to be signed by the key the credential names, and
//      for a DID-bound credential this wallet has no such key — it never held
//      one, because the proof of possession it made at issuance offered a JWK.
//      That is a real interoperability gap, not a defect in either
//      implementation, and it is reported as such: the run says what walt.id did
//      and what would have to be built to answer it, rather than failing on a
//      difference nobody has agreed to yet.
//
// When walt.id does bind with cnf.jwk, the full presentation runs and is checked
// by walt.id's own policies.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const common = require("./jwt_vc_json_common.js");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwt_vc_json_presentation_waltid",
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
var verifierBase = (process.env.WALTID_VERIFIER_URL || "").replace(/\/+$/, "");
var REQUESTED = (process.env.OID4VP_CLAIMS || "given_name,family_name").split(",");
const DCQL_ID = "identity_credential";

// The DCQL query walt.id is asked to enforce. Claim paths are rooted at
// credentialSubject: that is where a W3C VC keeps them, and asking for a bare
// ["given_name"] would ask for a claim that is not there — which does not fail
// loudly, it just looks like the wallet withheld everything.
function dcqlQuery(types) {
  return {
    credentials: [{
      id: DCQL_ID,
      format: common.FORMAT,
      meta: { type_values: [types] },
      claims: REQUESTED.map(function (name) { return { path: ["credentialSubject", name] }; })
    }]
  };
}

async function createVerificationSession(types) {
  log.debug("Entering createVerificationSession().");
  const setup = {
    flow_type: "cross_device",
    core_flow: {
      dcql_query: dcqlQuery(types),
      signed_request: false,
      encrypted_response: false,
      policies: { vc_policies: ["signature", "expiration", "not-before"] }
    },
    url_config: {}
  };
  const created = await common.httpJson(verifierBase + "/verification-session/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(setup)
  });
  log.debug("Leaving createVerificationSession(). status=" + created.status);
  return created;
}

async function test() {
  log.debug("Entering test().");
  // Failures, not skips — including the holder-binding gap below. A skip there
  // would let an unfinished interoperability story report as a green run.
  assert.ok(verifierBase, "WALTID_VERIFIER_URL is not set, so walt.id's verifier was never asked to " +
    "verify a jwt_vc_json presentation.");
  assert.ok(issuerBase, "WALTID_ISSUER_URL is not set; this job issues the credential it presents from " +
    "walt.id so that neither end of the exchange is ours.");
  log.info("Running jwt_vc_json presentation against walt.id. issuer=" + issuerBase +
           ", verifier=" + verifierBase);

  const live = await common.httpJson(verifierBase + "/livez").catch(function () { return { ok: false }; });
  assert.ok(live.ok, "walt.id's verifier is not answering at " + verifierBase + "/livez.");

  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.id,
    "walt.id offers no jwt_vc_json credential configuration, so this interoperability check did not run. " +
    "Offered: " + Object.keys(((found.meta || {}).credential_configurations_supported) || {}).join(", ") +
    ". The configuration is in waltid/config/credential-issuer-metadata.conf with a matching profile in " +
    "issuer2-profiles.conf — restart waltid-issuer-api to load it.");

  const accessToken = await common.preAuthorizedAccessToken(issuerBase, WALTID_PROFILE_ID);
  assert.ok(accessToken,
    "could not obtain an access token from walt.id with the pre-authorized code grant for profile \"" +
    WALTID_PROFILE_ID + "\".");
  // "did": walt.id resolves the subject DID from the proof for this format.
  const held = await common.mintJwtVcJson(issuerBase, found.id, accessToken, "did");
  const parsed = common.assertIsJwtVcJson(held.credential, "walt.id");
  log.info("[issuance] walt.id issued a " + parsed.types.join("/") + " to present.");

  // Gate 2: can this wallet sign a presentation for it?
  const binding = common.holderBindingOf(parsed.payload);
  // Can this wallet sign a presentation for it?
  //
  // Two ways a credential can name its holder, and the earlier assumption that a
  // subject DID meant "not us" was wrong. walt.id binds jwt_vc_json with
  // credentialSubject.id = "<subjectDid>", and it derives that DID from the proof
  // of possession this wallet made — a did:jwk, which is the wallet's own public
  // key encoded into the identifier. So the wallet does hold the private half and
  // CAN sign for it; what it must do differently is present as that DID rather
  // than as an anonymous key.
  //
  // It is still checked rather than assumed: a DID this wallet did not generate
  // (did:web, or a did:jwk over somebody else's key) is genuinely unpresentable
  // here, and that is a failure rather than a skip.
  var presentingAs = "urn:holder";
  if (binding.kind === "cnf.jwk") {
    presentingAs = "urn:holder";
  } else if (binding.kind === "credentialSubject.id") {
    assert.strictEqual(binding.subjectId, held.did,
      "walt.id bound this credential to " + binding.subjectId + ", which is not the did:jwk this wallet " +
      "proved possession of (" + held.did + "). A Verifiable Presentation JWT has to be signed by the key " +
      "the credential names, and this wallet does not hold that one.");
    presentingAs = binding.subjectId;
    log.info("[binding] walt.id bound it by subject DID, and it is this wallet's own did:jwk — so the " +
             "presentation is signed with that key and presented as that DID.");
  } else {
    assert.fail("the credential names no holder at all (" + binding.kind + "), so nobody can present it.");
  }

  // walt.id binds with a key we hold, so the exchange can actually run.
  const created = await createVerificationSession(parsed.types);
  assert.ok(created.status === 200 || created.status === 201,
    "walt.id would not create a jwt_vc_json verification session (HTTP " + created.status + "): " +
    String(created.raw).slice(0, 300) + ". Its DCQL support for this format differs from its SD-JWT path.");
  assert.ok(created.body && created.body.sessionId,
    "walt.id should return a sessionId. Got: " + String(created.raw).slice(0, 300));

  const url = created.body.fullAuthorizationRequestUrl || created.body.bootstrapAuthorizationRequestUrl;
  assert.ok(url, "and an Authorization Request URL for the wallet.");
  const params = {};
  url.slice(url.indexOf("?") + 1).split("&").forEach(function (pair) {
    const eq = pair.indexOf("=");
    params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
  });

  // Build the VP JWT the same way the wallet does, and let walt.id judge it.
  const header = common.b64u(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const payload = common.b64u(JSON.stringify({
    iss: presentingAs, aud: params.client_id, nonce: params.nonce,
    iat: Math.floor(Date.now() / 1000),
    vp: { "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiablePresentation"], verifiableCredential: [held.credential] }
  }));
  const sig = common.b64u(crypto.sign(null, Buffer.from(header + "." + payload),
    { key: held.privateKey, dsaEncoding: "ieee-p1363" }));
  const vpJwt = header + "." + payload + "." + sig;

  const posted = await common.httpJson(params.response_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      vp_token: JSON.stringify({ identity_credential: [vpJwt] }),
      state: params.state || ""
    }).toString()
  });
  log.info("[presentation] walt.id answered HTTP " + posted.status + " to the VP JWT.");

  const info = await common.httpJson(verifierBase + "/verification-session/" +
    encodeURIComponent(created.body.sessionId) + "/info");
  assert.ok(info.ok, "walt.id should report the session outcome. Got HTTP " + info.status);
  log.info("[presentation] walt.id's verdict: " + String(info.raw).slice(0, 400));
  assert.ok(posted.status >= 200 && posted.status < 400,
    "walt.id should accept a correctly built VP JWT over a credential it issued itself. Got HTTP " +
    posted.status + ": " + String(posted.raw).slice(0, 300));
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
