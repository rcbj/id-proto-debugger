// File: vc_did.js
//
// The issuer named by a DECENTRALIZED IDENTIFIER, end to end, for both formats
// that can carry one — and the documents that make that DID discoverable and
// believable rather than merely asserted.
//
// What is being tested is a chain, and every link of it is somewhere a credential
// could look fine and verify against nothing:
//
//   1. the issuer ADVERTISES the DID (credential issuer metadata, and the
//      jwt-vc-issuer document that SD-JWT VC's own key resolution uses), and says
//      per credential configuration which identifier its credentials will carry.
//      Without this a wallet learns the DID only from the credential itself,
//      which is the one source that cannot corroborate it;
//   2. the DID RESOLVES to a document publishing the issuer's keys;
//   3. the origin and the DID are proved to be the SAME ENTITY by a Domain
//      Linkage Credential (DIF Well Known DID Configuration). For did:web this is
//      the link that is not circular: resolving did:web:host means fetching host,
//      so the DID document alone cannot establish that host's controller and the
//      DID's controller are one party;
//   4. the credentials issued from the DID configurations actually name the DID —
//      dc+sd-jwt in iss, ldp_vc in issuer and in its proof's verificationMethod;
//   5. and the key resolved from the DID document VERIFIES those credentials. A
//      DID that resolves to the wrong key is the failure that looks like success
//      right up to the last step.
//
// Two things asserted here that are about not breaking anything:
//
//   * the plain configurations still name the issuer by https URL. dc+sd-jwt's
//     DID route is an extension — draft-ietf-oauth-sd-jwt-vc defines no DID-based
//     issuer signature mechanism — so the specification's own route must go on
//     being the one the plain configuration exercises. A test suite where every
//     credential had switched to DIDs would have stopped testing the spec;
//   * a DID configuration differs from its sibling in NOTHING but the issuer's
//     own name. They are clones in the metadata, and the credentials they mint
//     must assert the same claims.
//
// Needs the STS mock and nothing else — no browser, no Keycloak, no walt.id.
const assert = require("assert");
const crypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_did",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const ROOT = path.join(__dirname, "..");
// The wallet's own DID module: this test verifies with the SAME code the pages
// use, so a page that cannot resolve the issuer's DID fails here too.
const did = paths.requireSharedModule(
  [path.join(__dirname, "did.js"), path.join(ROOT, "client", "src", "did.js")],
  "the wallet's DID module");
const metadataClient = paths.requireSharedModule(
  [path.join(__dirname, "metadata_client.js"), path.join(ROOT, "client", "src", "metadata_client.js")],
  "the wallet's metadata/JWS module");
const stsSuite = paths.requireSharedModule(
  [path.join(__dirname, "sts_bbs2023.js"), path.join(ROOT, "sts", "bbs2023.js")],
  "the STS's bbs-2023 cryptosuite");

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");

// The two configurations that name the issuer by DID, and the plain ones they are
// clones of. The pairing is the point: each DID case is checked against its
// sibling, so "the DID variant works" cannot be true by accident of it being
// different in some other way.
const PAIRS = [
  { did: "IdentityCredentialDid", plain: "IdentityCredential", format: "dc+sd-jwt" },
  { did: "IdentityCredentialLdpVcDid", plain: "IdentityCredentialLdpVc", format: "ldp_vc" }
];

// http, because these stacks have no TLS. did:web mandates https and this is the
// same deviation the pages take (allowHttp), not a shortcut peculiar to the test.
const RESOLVE = { allowHttp: true };

function issuerOrigin() {
  return new URL(issuerBase).origin;
}

// --- 1. what the issuer advertises ------------------------------------------
async function metadataAdvertisesTheDid() {
  log.info("=== What the issuer advertises ===");
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta, "no credential issuer metadata at " + issuerBase + ". Start the STS mock.");

  assert.ok(meta.issuer_did,
    "the credential issuer metadata should name this issuer's DID. Without it a wallet that receives " +
    "a credential whose iss is a did:web has been told about that DID by nothing it fetched — it has " +
    "to take the credential's word for who issued it, which is the one thing a credential cannot " +
    "establish about itself.");
  assert.ok(did.isDid(meta.issuer_did), 'issuer_did should be a DID; got "' + meta.issuer_did + '".');
  assert.strictEqual(did.parse(meta.issuer_did).method, "web",
    "this issuer's DID should be did:web — the only method with a document to serve. did:jwk and " +
    "did:key resolve from the identifier itself, which would make the endpoint pointless.");
  log.info("[metadata] OK — issuer_did is " + meta.issuer_did + ".");

  const configs = meta.credential_configurations_supported || {};
  for (const pair of PAIRS) {
    const didEntry = configs[pair.did];
    const plainEntry = configs[pair.plain];
    assert.ok(didEntry, 'this issuer offers no "' + pair.did + '" configuration. Offered: ' +
      Object.keys(configs).join(", "));
    assert.ok(plainEntry, 'this issuer offers no "' + pair.plain + '" configuration to compare it with.');
    assert.strictEqual(didEntry.format, pair.format,
      pair.did + " should be " + pair.format + ", the same format as its sibling.");

    // The per-configuration advertisement: what the credential will actually
    // carry. This is the member a wallet can act on BEFORE requesting anything.
    assert.strictEqual(didEntry.issuer_identifier, meta.issuer_did,
      pair.did + " should advertise that its credentials name the issuer by DID.");
    assert.strictEqual(plainEntry.issuer_identifier, meta.credential_issuer,
      pair.plain + " should advertise the https identifier it has always used — if this has become " +
      "a DID, the whole issuer has been switched over and the specification's own key-resolution " +
      "route is no longer being exercised by anything.");

    // Clones apart from the three things that must differ. A claim added to one
    // and not the other would make the pair incomparable, which is the only
    // reason the pair is interesting.
    const strip = function (entry) {
      const copy = JSON.parse(JSON.stringify(entry));
      delete copy.scope;
      delete copy.display;
      delete copy.issuer_identifier;
      return copy;
    };
    assert.deepStrictEqual(strip(didEntry), strip(plainEntry),
      pair.did + " should differ from " + pair.plain + " in NOTHING but its scope, its display name " +
      "and the issuer identifier it advertises. Anything else and the two are not comparable.");
    assert.notStrictEqual(didEntry.scope, plainEntry.scope,
      "the two configurations need distinct scopes, or a wallet asking by scope cannot choose.");
  }
  log.info("[metadata] OK — both DID configurations advertise the DID and are clones of their siblings.");

  // SD-JWT VC's own key-resolution document. Its `issuer` must stay the https
  // identifier — the specification has a verifier insert the well-known path into
  // the credential's iss and require that this document's issuer equals what it
  // started from, and a DID cannot be the subject of that rule. The DID is named
  // BESIDE it, which is what connects the two identifiers at all.
  const jwtVcIssuer = await common.httpJson(issuerBase + "/.well-known/jwt-vc-issuer");
  assert.ok(jwtVcIssuer.ok, "the jwt-vc-issuer document should be served: HTTP " + jwtVcIssuer.status);
  assert.strictEqual(jwtVcIssuer.body.issuer, meta.credential_issuer,
    "the jwt-vc-issuer document's issuer must remain the https identifier this document is FOUND by.");
  assert.ok(jwtVcIssuer.body.jwks_uri, "and it should still publish a jwks_uri.");
  assert.strictEqual(jwtVcIssuer.body.issuer_did, meta.issuer_did,
    "and it should name the same DID the credential issuer metadata does. Two documents disagreeing " +
    "about which DID this issuer answers to is worse than neither of them saying.");
  log.info("[metadata] OK — jwt-vc-issuer keeps its https issuer and names the DID beside it.");
  return meta;
}

// --- 2 and 3. the DID resolves, and the origin proves it owns it -------------
async function theDidResolvesAndTheOriginProvesIt(meta) {
  log.info("=== The DID document ===");
  const resolved = await did.resolve(meta.issuer_did, RESOLVE);
  assert.strictEqual(resolved.document.id, meta.issuer_did,
    "a resolved document's id MUST be the DID resolved (DID Core).");
  const methods = did.verificationMethods(resolved.document);
  assert.ok(methods.length >= 2,
    "this issuer signs two quite different things and should publish a key for each: RS256 JWTs and " +
    "bbs-2023 Data Integrity proofs. Got " + methods.length + " method(s).");

  const jose = methods.filter(function (m) { return m.jwk; });
  const multibase = methods.filter(function (m) { return m.publicKeyMultibase; });
  assert.ok(jose.length >= 1, "at least one key must be expressible as a JWK, or no JWS can be verified.");
  assert.ok(multibase.length >= 1,
    "the BBS key must appear as a publicKeyMultibase. A BLS12-381 key has no registered JOSE kty, so " +
    "forcing it into a publicKeyJwk would be inventing one.");
  const converted = did.assertionJwks(resolved.document);
  assert.ok(converted.jwks.keys.length >= 1, "the document should offer a usable assertion key.");
  assert.ok(converted.unusable.length >= 1,
    "and should report the BBS key as one it cannot express as a JWK, by name, rather than dropping " +
    "it silently: " + JSON.stringify(converted.unusable));
  log.info("[did:web] OK — " + methods.length + " verification methods, " +
           converted.jwks.keys.length + " usable as JWKs, " + converted.unusable.length + " not.");

  log.info("=== Well Known DID Configuration ===");
  const linkage = await did.verifyOriginLinkage(issuerOrigin(), meta.issuer_did, RESOLVE);
  assert.ok(linkage.matched.length >= 1,
    "the origin's DID Configuration should carry a Domain Linkage Credential for the DID this issuer " +
    "advertises. Found entries for: " +
    linkage.results.map(function (r) { return r.did || "(none)"; }).join(", "));
  const failed = linkage.matched[0].checks.filter(function (c) { return !c.ok; });
  assert.deepStrictEqual(failed.map(function (c) { return c.name + ": " + c.detail; }), [],
    "every check on the Domain Linkage Credential should pass.");
  assert.strictEqual(linkage.linked, true,
    "and the verdict should be that this origin and this DID are the same entity.");
  assert.strictEqual(linkage.matched[0].origin, issuerOrigin(),
    "the credential should name the origin it was served from, or it belongs to a different site.");
  log.info("[linkage] OK — " + issuerOrigin() + " and " + meta.issuer_did +
           " are proved one entity by " + linkage.url + ".");

  // The check that makes the one above mean something: this document must not
  // vouch for a DID it does not carry. Otherwise "linked" would be a property of
  // the file existing rather than of what it says.
  const impostor = await did.verifyOriginLinkage(issuerOrigin(), "did:web:somebody.else", RESOLVE);
  assert.strictEqual(impostor.linked, false,
    "an origin that links its OWN DID must not read as vouching for anybody else's.");
  log.info("[linkage] OK — and it vouches for no other DID.");
}

// --- 4 and 5. the credentials, and the keys that verify them -----------------
async function sdJwtVcNamesTheDidAndVerifies(meta) {
  log.info("=== dc+sd-jwt issued by a DID-named issuer ===");
  const held = await common.mintJwtVcJson(issuerBase, "IdentityCredentialDid");
  const issuerJwt = String(held.credential).split("~")[0];
  const payload = common.jsonFromB64u(issuerJwt.split(".")[1]);

  assert.strictEqual(payload.iss, meta.issuer_did,
    "the credential's iss should be the DID the metadata advertised. If these differ, a wallet that " +
    "believed the metadata is resolving the wrong identifier.");
  assert.ok(payload.cnf && payload.cnf.jwk,
    "holder binding must still be cnf.jwk (RFC 7800). A DID here would be nobody's convention — " +
    "the DID names the ISSUER, and that is the whole of what this extension changes.");

  // The link that matters: resolve the identifier the credential names, and let
  // the key that comes back verify the signature. This is the path issuance
  // step 3 takes, using the same modules.
  const resolved = await did.resolve(payload.iss, RESOLVE);
  const converted = did.assertionJwks(resolved.document);
  const verdict = await metadataClient.verifyJwsWithJwks(issuerJwt, converted.jwks, "the credential");
  assert.strictEqual(verdict.valid, true,
    "the credential must verify against a key the DID document authorises to ASSERT. A DID that " +
    "resolves to the wrong key looks like success until exactly here.");
  log.info("[dc+sd-jwt] OK — iss is " + payload.iss + " and the resolved key verifies it (kid " +
           verdict.kid + ").");

  // A key the document does NOT publish must not verify it. Without this, the
  // assertion above would also pass for a verifier that ignored the key.
  const strangerJwks = { keys: [{ kty: "RSA", kid: "stranger", e: "AQAB",
    n: crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
         .publicKey.export({ format: "jwk" }).n }] };
  const strangerVerdict = await metadataClient.verifyJwsWithJwks(issuerJwt, strangerJwks, "the credential");
  assert.strictEqual(strangerVerdict.valid, false,
    "a key this DID does not publish must NOT verify the credential.");
  log.info("[dc+sd-jwt] OK — and an unrelated key does not verify it.");

  // The non-regression: the plain configuration must still be resolvable the way
  // the specification says, by inserting the well-known path into its iss.
  const plain = await common.mintJwtVcJson(issuerBase, "IdentityCredential");
  const plainPayload = common.jsonFromB64u(String(plain.credential).split("~")[0].split(".")[1]);
  assert.strictEqual(plainPayload.iss, meta.credential_issuer,
    "the PLAIN configuration must still name the issuer by its https identifier, so that " +
    "/.well-known/jwt-vc-issuer — the mechanism draft-ietf-oauth-sd-jwt-vc actually defines — goes " +
    "on being exercised. The DID route is an extension and must not quietly replace it.");
  assert.ok(!did.isDid(plainPayload.iss), "and that identifier must not be a DID.");

  // Same claims from both: they are the same credential from the same issuer, and
  // only the issuer's own name differs.
  const claimNames = function (credential) {
    return String(credential).split("~").slice(1).filter(Boolean).map(function (disclosure) {
      return common.jsonFromB64u(disclosure)[1];
    }).sort();
  };
  assert.deepStrictEqual(claimNames(held.credential), claimNames(plain.credential),
    "the DID configuration should assert the same claims as its sibling — it is the same credential " +
    "with the issuer named differently, not a different credential.");
  log.info("[dc+sd-jwt] OK — the plain sibling keeps its https iss and asserts the same claims.");
}

async function ldpVcNamesTheDidAndVerifies(meta) {
  log.info("=== ldp_vc issued by a DID-named issuer ===");
  const held = await common.mintJwtVcJson(issuerBase, "IdentityCredentialLdpVcDid");
  const credential = held.credential;
  assert.strictEqual(typeof credential, "object", "an ldp_vc credential is a JSON object.");
  assert.strictEqual(credential.issuer, meta.issuer_did,
    "the credential's issuer should be the DID. VC Data Model 2.0 is DID-native, so unlike " +
    "dc+sd-jwt this is ordinary rather than an extension.");

  const vm = credential.proof.verificationMethod;
  assert.ok(did.isDid(vm),
    "the proof's verificationMethod should be a DID URL into this issuer's document, not an https " +
    'URL. Got "' + vm + '".');
  assert.strictEqual(did.parse(vm).did, meta.issuer_did,
    "and it should be a URL into the SAME DID the credential names as issuer.");
  assert.ok(did.parse(vm).fragment,
    "a DID URL naming a key needs a fragment, or it names the document rather than a key in it.");

  // The wallet's route to the issuer's BBS key. This is where the DID variant
  // would have been unusable: presentation step 2 used to fetch() whatever the
  // proof named, and a DID URL is not fetchable — the symptom was the issuer's
  // key reported unreachable, which reads as a broken issuer.
  const resolved = await did.resolveVerificationMethod(vm, RESOLVE);
  assert.ok(resolved.method.publicKeyMultibase,
    "the verificationMethod must resolve to a key with a publicKeyMultibase: " +
    JSON.stringify(resolved.method).slice(0, 200));
  const pk = stsSuite.multibaseToBytes(resolved.method.publicKeyMultibase);
  assert.strictEqual(pk.length, 96,
    "a BLS12-381 G2 public key is 96 compressed bytes; got " + pk.length + ". A short key here means " +
    "the multibase prefix was stripped twice.");

  const verdict = await stsSuite.verifyBase(credential, pk);
  assert.strictEqual(verdict.ok, true,
    "the embedded bbs-2023 proof must verify against the key resolved FROM THE DID DOCUMENT. This is " +
    "the whole chain for this format: the credential names a DID, the DID resolves to a document, the " +
    "document names the key, and the key verifies the proof.");
  log.info("[ldp_vc] OK — issuer " + credential.issuer + ", verificationMethod " + vm +
           ", proof verifies over " + verdict.statements.length + " statements.");

  // Non-regression: the plain ldp_vc configuration keeps the dereferenceable
  // https verificationMethod that tests/ldp_vc_issuance.js fetches directly.
  const plain = await common.mintJwtVcJson(issuerBase, "IdentityCredentialLdpVc");
  assert.strictEqual(plain.credential.issuer, meta.credential_issuer,
    "the plain ldp_vc configuration must still name the https issuer.");
  assert.ok(!did.isDid(plain.credential.proof.verificationMethod),
    "and must keep an https verificationMethod, which tests/ldp_vc_issuance.js dereferences with a " +
    'plain GET. Got "' + plain.credential.proof.verificationMethod + '".');
  const plainResolved = await did.resolveVerificationMethod(plain.credential.proof.verificationMethod,
                                                            RESOLVE);
  assert.ok(plainResolved.method.publicKeyMultibase,
    "and that URL must still dereference to a key — the same helper must handle both forms.");
  log.info("[ldp_vc] OK — the plain sibling keeps its https issuer and dereferenceable key URL.");

  const claimsOf = function (c) { return Object.keys(c.credentialSubject).sort().join(","); };
  assert.strictEqual(claimsOf(credential), claimsOf(plain.credential),
    "and both configurations should assert the same claims about the subject.");
  log.info("[ldp_vc] OK — the same claims from both.");
}

async function test() {
  log.info("Running the DID-named issuer checks against " + issuerBase);
  const meta = await metadataAdvertisesTheDid();
  await theDidResolvesAndTheOriginProvesIt(meta);
  await sdJwtVcNamesTheDidAndVerifies(meta);
  await ldpVcNamesTheDidAndVerifies(meta);
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("vc_did")
  .description("Verify the issuer named by DID: advertisement, resolution, domain linkage, both formats.")
  // Accepted and ignored: run-report.js passes --url to every job. This test
  // drives the ISSUER, not the pages, so it needs no browser.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
