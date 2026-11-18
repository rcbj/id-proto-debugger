// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_verifier_engine.js
//
// ---------------------------------------------------------------------------
// The debugger as an OpenID4VP 1.0 VERIFIER (client/src/vp_verifier.js), in
// node, with no browser and no network (issue #364, PRs 1 and 3).
//
// Named vp_verifier_engine.js and not vp_verifier.js because the tests image
// is one flat directory: a test named after a module would replace it.
//
// What it holds the module to, each against something the module did not
// write:
//
//   * the Verifier identity: node's own X509Certificate reads the leaf's SAN
//     and AIA caIssuers and verifies the chain, and x509Hash agrees with
//     vp_protocols.x509Hash() and with node's SHA-256;
//   * the signed Request Object is checked by the WALLET's reading of the
//     same rules (vp_protocols.verifyX509Request), for x509_hash and
//     x509_san_dns;
//   * a dc+sd-jwt presentation from an issuer written HERE (node's ECDSA,
//     node's SHA-256) and a KB-JWT from sd_jwt_vp's signer passes every check
//     over direct_post and direct_post.jwt — and each of fifteen defects
//     fails EXACTLY the check it targets and no other;
//   * mso_mdoc against tests/mdoc_test_issuer.js, jwt_vc_json with a VC JWT
//     signed here, and ldp_vc bbs-2023 (W3C reveal documents, bare and in
//     an ecdsa-jcs-2019 VP, and the pre-W3C envelope refused);
//   * PR 3: the decentralized_identifier, verifier_attestation and
//     pre-registered Request Objects decoded here and verified with node
//     against the key did.js resolves / the attestation's cnf.jwk / the
//     registered JWKS; openid_federation refused; wallet_nonce;
//   * the Digital Credentials API: unsigned and signed requests, dc_api and
//     dc_api.jwt answers held to an origin: audience, and an mdoc signed
//     here over the OpenID4VPDCAPIHandover transcript written from the text;
//   * Token Status Lists (node's zlib, entries packed LSB first) and
//     Bitstring Status Lists (node's gzip, MSB first), with the bit orders
//     chosen so that reading either one the wrong way gives a wrong answer;
//     draft-ietf-oauth-status-list-21's own vectors (sections 4.1/4.2 and
//     Appendix C.1 and C.3) and Bitstring Status List v1.0's Examples 1-3;
//     an HTML page and binary in the list's place; and the
//     Status List Token's signer linked to the credential's issuer by each
//     of section 11.3's routes (certificates from x509.js, keys and
//     thumbprints from node), and the ways it is NOT;
//   * CWT Status List Tokens (section 5.2, #471 E5) assembled byte by byte
//     here and signed by node's ECDSA: VALID, INVALID, SUSPENDED, a bad
//     signature, a sub mismatch and each structural MUST, by kid, x5chain
//     and x5t; plus the draft's own section 5.2 CWT and its section 4.3 and
//     Appendix C.1/C.2 CBOR StatusLists;
//   * Data Integrity: the W3C's own eddsa-jcs-2022 vector, and credentials,
//     VPs and status list credentials signed here in five suite/curve
//     combinations (JCS written here, RDFC by jsonld).
//   * #469: what a conformant Wallet or Issuer may send — a bare VC JWT,
//     a VP JWT with no iat, aud arrays, exp/nbf, DID holders and cnf.kid /
//     cnf.jku, DID documents naming keys every way DID Core allows,
//     SD-JWT VC -27's aka_vcts and extends examples (Figures 4, 16, 17),
//     OpenID4VP 1.0 Appendix B.1.1's type_values examples expanded as
//     IRIs, mdocs signed here with -9, -35, SHA-384/512 digests and
//     DeviceMac, and the Data Integrity proof @context rules; plus issuer
//     keys that cannot be had reported as a SKIP (B2/B3).
//
// Which checks are the SPECIFICATIONS' own vectors, byte for byte or value
// for value (#471, T1), as opposed to inputs built here from their text:
//
//   * OpenID4VP 1.0 Appendix B.2.6.1 and B.2.6.2: the example JWK's
//     thumbprint, the two HandoverInfo, Handover and SessionTranscript hex
//     strings, rebuilt by the Verifier and by the wallet
//     (openid4vpSpecVectors());
//   * OpenID4VP 1.0 Appendix B.3.2: the example SD-JWT VC's _sd array, its
//     three Disclosures and their printed SHA-256 hashes (ibid.);
//   * draft-ietf-oauth-status-list-21 sections 4.1/4.2 and Appendix C.1 and
//     C.3 (tokenStatusSpecVectors()); its section 5.2 example CWT and the
//     CBOR StatusLists of section 4.3 and Appendix C.1 and C.2
//     (cwtStatusLists());
//   * Bitstring Status List v1.0 Examples 1-3 (bitstringStatusLists());
//   * the W3C eddsa-jcs-2022 test vector (cryptosuites()).
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const jsonld = require("jsonld");
const mdocIssuer = require("./mdoc_test_issuer.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_verifier_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
const paths = require("./module_paths.js");
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
const verifier = load("vp_verifier.js");
const vp = load("vp_protocols.js");
const x509 = load("x509.js");
const sdJwtVp = load("sd_jwt_vp.js");
const bbs2023 = load("bbs2023.js");
// ecdsa-sd-2023 (#476): the Verifier verifies it through data_integrity.js.
const ecdsaSd = load("ecdsa_sd_2023.js");
const bbs = load("bbs.js");
const didLib = load("did.js");
const joseJwe = load("jose_jwe.js");

// Every assertion goes through here, so the run can say how many it made
// and refuse to call a run that made too few a pass.
let assertions = 0;
function ok(cond, message) {
  log.debug("Entering ok().");
  assertions++;
  assert.ok(cond, message);
  log.debug("Leaving ok().");
}

function eq(actual, expected, message) {
  log.debug("Entering eq().");
  assertions++;
  assert.deepStrictEqual(actual, expected, message);
  log.debug("Leaving eq().");
}

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function sha256b64u(text) {
  log.debug("Entering sha256b64u().");
  log.debug("Leaving sha256b64u().");
  return b64u(nodeCrypto.createHash("sha256").update(text).digest());
}

function ecPair() {
  log.debug("Entering ecPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving ecPair().");
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicJwk: pair.publicKey.export({ format: "jwk" }),
    privateJwk: pair.privateKey.export({ format: "jwk" })
  };
}

function didJwk(publicJwk) {
  log.debug("Entering didJwk().");
  log.debug("Leaving didJwk().");
  return "did:jwk:" + b64u(JSON.stringify({ kty: publicJwk.kty,
    crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }));
}

// A compact ES256 JWS signed by node's own crypto.
function nodeJws(header, payload, key) {
  log.debug("Entering nodeJws().");
  const input = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving nodeJws().");
  return input + "." + b64u(sig);
}

function failedIds(result) {
  log.debug("Entering failedIds().");
  log.debug("Leaving failedIds().");
  return result.checks.filter(function (c) {
    return c.status === "fail";
  }).map(function (c) {
    return c.id;
  }).sort();
}

function checkById(result, id) {
  log.debug("Entering checkById(). " + id);
  log.debug("Leaving checkById().");
  return result.checks.filter(function (c) {
    return c.id === id;
  })[0];
}

function allPass(result, what) {
  log.debug("Entering allPass(). " + what);
  eq(failedIds(result), [], what + ": a correct response failed: " +
     JSON.stringify(result.checks.filter(function (c) {
       return c.status === "fail";
     }), null, 2));
  ok(result.ok, what + ": ok must be true when nothing failed: " +
     JSON.stringify(result.checks.filter(function (c) {
       return c.essential && c.status === "skip";
     }), null, 2));
  eq(result.verdict, "pass", what + ": the verdict of a full pass");
  log.debug("Leaving allPass().");
}

function failsOnly(result, ids, what) {
  log.debug("Entering failsOnly(). " + what);
  eq(failedIds(result), ids.slice().sort(), what + ": expected exactly " +
     JSON.stringify(ids) + " to fail; " + JSON.stringify(result.checks
       .filter(function (c) {
         return c.status === "fail";
       }), null, 2));
  ok(!result.ok, what + ": ok must be false when a check failed");
  eq(result.verdict, "fail", what + ": the verdict when a check failed");
  log.debug("Leaving failsOnly().");
}

// Nothing failed, and the essential checks `ids` were NOT performed: the
// verdict is "incomplete" (#467 S4), which is what a key that could not be
// had produces (#469 B2) — never a pass, and not a forgery either.
function incompleteOnly(result, ids, what) {
  log.debug("Entering incompleteOnly(). " + what);
  eq(failedIds(result), [], what + ": nothing may fail: " +
     JSON.stringify(result.checks.filter(function (c) {
       return c.status === "fail";
     }), null, 2));
  eq(result.verdict, "incomplete", what + ": the verdict is incomplete");
  ok(!result.ok, what + ": ok is false");
  ids.forEach(function (id) {
    const c = checkById(result, id);
    ok(c && c.status === "skip" && c.essential, what + ": " + id +
       " is an essential skip: " + JSON.stringify(c));
  });
  log.debug("Leaving incompleteOnly().");
}

let checksSeen = 0;
async function run(opts) {
  log.debug("Entering run().");
  const r = await verifier.verifyResponse(opts);
  checksSeen += r.checks.length;
  log.debug("Leaving run().");
  return r;
}

// ---------------------------------------------------------------------------
function randomTokens() {
  log.debug("Entering randomTokens().");
  const a = verifier.randomToken();
  const b = verifier.randomToken();
  ok(/^[A-Za-z0-9_-]{22}$/.test(a), "16 bytes is 22 base64url characters");
  ok(a !== b, "two tokens must differ");
  eq(Buffer.from(verifier.randomToken(32), "base64url").length, 32,
     "randomToken(32) is 32 bytes");
  log.info("PASS randomToken.");
  log.debug("Leaving randomTokens().");
}

function dcqlBuilder() {
  log.debug("Entering dcqlBuilder().");
  eq(verifier.FORMATS.slice().sort(),
     ["dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"]);
  const dcql = verifier.buildDcql({ queries: [
    { id: "pid", format: "dc+sd-jwt", vct: "urn:eudi:pid:1",
      claims: [["given_name"], ["address", "street_address"]] },
    { id: "mdl", format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL",
      claims: [["org.iso.18013.5.1", "family_name"]],
      requireBinding: false },
    { id: "w3c", format: "jwt_vc_json",
      types: ["VerifiableCredential", "IdentityCredential"],
      claims: [["credentialSubject", "given_name"]] },
    { id: "ld", format: "ldp_vc", types: [["VerifiableCredential"]] }
  ], credentialSets: [{ options: [["pid"], ["mdl"]] },
                      { options: [["w3c", "ld"]], required: false }] });
  eq(dcql.credentials[0], { id: "pid", format: "dc+sd-jwt",
    meta: { vct_values: ["urn:eudi:pid:1"] },
    claims: [{ path: ["given_name"] },
             { path: ["address", "street_address"] }] });
  eq(dcql.credentials[1].meta, { doctype_value: "org.iso.18013.5.1.mDL" });
  eq(dcql.credentials[1].require_cryptographic_holder_binding, false);
  ok(!("require_cryptographic_holder_binding" in dcql.credentials[0]),
     "the default (true) is not written out");
  eq(dcql.credentials[2].meta, { type_values: [["VerifiableCredential",
    "IdentityCredential"]] }, "a flat types list is one alternative");
  eq(dcql.credentials[3].meta, { type_values: [["VerifiableCredential"]] });
  ok(!dcql.credentials[3].claims, "no claims means no claims member");
  eq(dcql.credential_sets, [{ options: [["pid"], ["mdl"]] },
     { options: [["w3c", "ld"]], required: false }]);
  const V = "urn:x";
  const D = "org.iso.18013.5.1.mDL";
  [[{ queries: [] }, /at least one/],
   [{ queries: [{ format: "dc+sd-jwt", vct: V }] }, /no id/],
   [{ queries: [{ id: "a b", format: "dc+sd-jwt", vct: V }] },
    /alphanumeric/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: V },
                { id: "a", format: "mso_mdoc", doctype: D }] }, /twice/],
   [{ queries: [{ id: "a", format: "vc+sd-jwt" }] }, /unknown format/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: V, claims: [[]] }] },
    /non-empty/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: V, claims: [[""]] }] },
    /segment/],
   [{ queries: [{ id: "a", format: "mso_mdoc", doctype: D,
                  claims: [["ns"]] }] }, /namespace, element/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: V }],
      credentialSets: [{ options: [["b"]] }] }, /no credential query/],
   // #468, M4: each format's REQUIRED meta member, never empty. Appendix
   // B.3.5 vct_values "REQUIRED. A non-empty array of strings"; B.2.3
   // doctype_value REQUIRED; B.1.1 type_values "REQUIRED. A non-empty
   // array of string arrays", each inner array non-empty.
   [{ queries: [{ id: "a", format: "dc+sd-jwt" }] }, /B\.3\.5/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: [] }] }, /B\.3\.5/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: "" }] }, /B\.3\.5/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", vct: [V, ""] }] },
    /B\.3\.5/],
   [{ queries: [{ id: "a", format: "mso_mdoc" }] }, /B\.2\.3/],
   [{ queries: [{ id: "a", format: "mso_mdoc", doctype: "" }] }, /B\.2\.3/],
   [{ queries: [{ id: "a", format: "mso_mdoc", doctype: "  " }] },
    /B\.2\.3/],
   [{ queries: [{ id: "a", format: "jwt_vc_json" }] }, /B\.1\.1/],
   [{ queries: [{ id: "a", format: "jwt_vc_json", types: [] }] },
    /B\.1\.1/],
   [{ queries: [{ id: "a", format: "ldp_vc", types: [[]] }] }, /B\.1\.1/],
   [{ queries: [{ id: "a", format: "ldp_vc",
                  types: [["VerifiableCredential"], []] }] }, /B\.1\.1/],
   [{ queries: [{ id: "a", format: "jwt_vc_json", types: [""] }] },
    /B\.1\.1/]
  ].forEach(function (c) {
    assertions++;
    assert.throws(function () {
      verifier.buildDcql(c[0]);
    }, c[1], "buildDcql must refuse " + JSON.stringify(c[0]));
  });
  // The spec's own examples come back unchanged: section 6.4.1's first
  // query and B.1.3.1.4's W3C one.
  eq(verifier.buildDcql({ queries: [{ id: "my_credential",
    format: "dc+sd-jwt",
    vct: ["https://credentials.example.com/identity_credential"],
    claims: [["last_name"], ["first_name"], ["address", "street_address"]]
  }] }).credentials[0].meta, { vct_values:
    ["https://credentials.example.com/identity_credential"] });
  eq(verifier.buildDcql({ queries: [{ id: "example_jwt_vc",
    format: "jwt_vc_json", types: [["IDCredential"]] }] })
    .credentials[0].meta, { type_values: [["IDCredential"]] });
  log.info("PASS buildDcql, and each refusal by name.");
  log.debug("Leaving dcqlBuilder().");
  return dcql;
}

async function identityAndRequest() {
  log.debug("Entering identityAndRequest().");
  const aia = "https://verifier.example/ca/root.der";
  const id = await verifier.makeVerifierIdentity({
    dnsName: "verifier.example", caIssuersUrl: aia });
  const leaf = new nodeCrypto.X509Certificate(id.leafPem);
  const root = new nodeCrypto.X509Certificate(id.rootPem);
  ok(/DNS:verifier\.example/.test(leaf.subjectAltName || ""),
     "the leaf's SAN must be dNSName verifier.example: " +
     leaf.subjectAltName);
  ok(String(leaf.infoAccess || "").indexOf("CA Issuers - URI:" + aia) !== -1,
     "the leaf's AIA caIssuers must be " + aia + ": " + leaf.infoAccess);
  ok(leaf.verify(root.publicKey), "the leaf must verify with the root key");
  ok(root.verify(root.publicKey), "the root must be self-signed");
  ok(leaf.checkIssued(root), "the root must be the leaf's issuer");
  ok(root.ca && !leaf.ca, "root is a CA, leaf is not");
  eq(Buffer.from(id.leafDer).equals(leaf.raw), true, "leafDer is the leaf");
  eq(Buffer.from(id.rootDer).equals(root.raw), true, "rootDer is the root");
  eq(id.x5c, [leaf.raw.toString("base64")],
     "x5c is the LEAF ONLY, in base64 (not base64url)");
  eq(id.x509Hash, b64u(nodeCrypto.createHash("sha256").update(leaf.raw)
     .digest()), "x509Hash is the SHA-256 of the leaf DER");
  eq(id.x509Hash, await vp.x509Hash(id.leafDer),
     "x509Hash disagrees with the wallet's vp_protocols.x509Hash");
  ok(!!id.privateJwk.d && id.publicJwk.d === undefined,
     "privateJwk carries d and publicJwk does not");
  const noAia = await verifier.makeVerifierIdentity({ dnsName: "v2.example" });
  ok(!new nodeCrypto.X509Certificate(noAia.leafPem).infoAccess,
     "without caIssuersUrl the leaf has no AIA");

  eq(verifier.clientIdFor("x509_hash", id), "x509_hash:" + id.x509Hash);
  eq(verifier.clientIdFor("x509_san_dns", id,
     { dnsName: "verifier.example" }), "x509_san_dns:verifier.example");
  eq(verifier.clientIdFor("redirect_uri", null,
     { redirectUri: "https://v.example/cb" }),
     "redirect_uri:https://v.example/cb");
  assertions++;
  assert.throws(function () {
    verifier.clientIdFor("nonsense", id, {});
  }, /not a Client Identifier prefix/, "an unknown prefix is refused");

  const enc = await verifier.responseEncryptionKey();
  eq([enc.publicJwk.kty, enc.publicJwk.crv, enc.publicJwk.use,
      enc.publicJwk.alg], ["EC", "P-256", "enc", "ECDH-ES"]);
  ok(enc.publicJwk.kid && !enc.publicJwk.d && enc.privateJwk.d,
     "the public key has a kid and no d; the private key has d");
  nodeCrypto.createPublicKey({ key: enc.publicJwk, format: "jwk" });
  assertions++;

  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"]] }] });
  for (const prefix of ["x509_hash", "x509_san_dns"]) {
    const clientId = verifier.clientIdFor(prefix, id,
      { dnsName: "verifier.example" });
    const claims = verifier.requestObjectClaims({ clientId: clientId,
      responseUri: "https://verifier.example/response",
      responseMode: "direct_post.jwt", nonce: "n-1", state: "s-1",
      dcql: dcql, encryptionJwk: enc.privateJwk, now: 1800000000 });
    eq([claims.iss, claims.client_id, claims.aud, claims.response_type,
        claims.response_mode, claims.iat, claims.exp],
       [clientId, clientId, "https://self-issued.me/v2", "vp_token",
        "direct_post.jwt", 1800000000, 1800000600]);
    eq(claims.client_metadata.jwks.keys.length, 1);
    ok(!claims.client_metadata.jwks.keys[0].d,
       "the private half must never reach client_metadata");
    eq(claims.client_metadata.encrypted_response_enc_values_supported,
       ["A128GCM", "A256GCM"]);
    eq(Object.keys(claims.client_metadata.vp_formats_supported).sort(),
       ["dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"]);
    const compact = await verifier.signRequestObject({ claims: claims,
      identity: id });
    const header = JSON.parse(Buffer.from(compact.split(".")[0],
      "base64url"));
    eq(header, { alg: "ES256", typ: "oauth-authz-req+jwt", x5c: id.x5c });
    const r = await vp.verifyX509Request({ compact: compact,
      clientId: clientId, trustAnchorPem: id.rootPem,
      verifyChain: x509.verifyChain,
      responseTarget: claims.response_uri });
    r.checks.forEach(function (c) {
      ok(c.ok, prefix + ": the wallet's check '" + c.name + "' failed: " +
         c.detail);
    });
    ok(r.checks.length >= 4, prefix + ": the wallet made too few checks");
  }
  const plain = verifier.requestObjectClaims({
    clientId: "redirect_uri:https://v.example/response",
    responseUri: "https://v.example/response", responseMode: "direct_post",
    nonce: "n", dcql: dcql });
  ok(!("iss" in plain), "a redirect_uri request carries no iss");
  ok(!plain.client_metadata.jwks, "direct_post needs no encryption key");
  assertions++;
  assert.throws(function () {
    verifier.requestObjectClaims({ clientId: "x", responseMode: "fragment",
      dcql: dcql });
  }, /response_mode/);
  log.info("PASS the Verifier identity and the Request Object, read by " +
           "the wallet's own rules.");
  log.debug("Leaving identityAndRequest().");
  return { identity: id, enc: enc };
}

// THE IDENTITY ACROSS RUNS (#470, B4): one root, two requests. Each request
// gets a new leaf and both chain to the same root, which node's own
// X509Certificate checks, and a wallet CONFIGURED with that root as its
// anchor (vp_protocols.verifyX509Request with trustAnchorPem, no AIA) takes
// both. Then the identity file round-trips, and a tampered one is refused.
async function persistentIdentity() {
  log.debug("Entering persistentIdentity().");
  const root = await verifier.makeVerifierRoot();
  const rootCert = new nodeCrypto.X509Certificate(root.certificatePem);
  ok(rootCert.ca && rootCert.verify(rootCert.publicKey),
     "the root is a self-signed CA");
  const fromCert = rootCert.publicKey.export({ format: "jwk" });
  eq([fromCert.x, fromCert.y], [root.privateJwk.x, root.privateJwk.y],
     "the root's private JWK is the key node reads out of its certificate");
  eq(Buffer.from(verifier.p256PointOfCertificate(rootCert.raw))
     .toString("base64url"), Buffer.concat([Buffer.from([4]),
       Buffer.from(fromCert.x, "base64url"),
       Buffer.from(fromCert.y, "base64url")]).toString("base64url"),
     "p256PointOfCertificate() finds the point node finds");
  const a = await verifier.makeVerifierIdentity({ dnsName: "a.example",
    caIssuersUrl: "https://a.example/ca", root: root });
  const b = await verifier.makeVerifierIdentity({ dnsName: "b.example",
    root: root });
  eq(a.rootPem, root.certificatePem, "request 1 names the kept root");
  eq(b.rootPem, root.certificatePem, "request 2 names the same root");
  ok(Buffer.from(a.rootDer).equals(rootCert.raw) &&
     Buffer.from(b.rootDer).equals(rootCert.raw), "rootDer is that root");
  ok(!Buffer.from(a.leafDer).equals(Buffer.from(b.leafDer)),
     "each request has a new leaf");
  ok(a.x509Hash !== b.x509Hash, "so a new x509_hash");
  for (const one of [a, b]) {
    const leaf = new nodeCrypto.X509Certificate(one.leafPem);
    ok(leaf.verify(rootCert.publicKey) && leaf.checkIssued(rootCert),
       one.dnsName + "'s leaf chains to the kept root (node)");
    const clientId = verifier.clientIdFor("x509_hash", one);
    const claims = verifier.requestObjectClaims({ clientId: clientId,
      responseUri: "https://" + one.dnsName + "/response",
      responseMode: "direct_post", nonce: "n", state: "s",
      dcql: verifier.buildDcql({ queries: [{ id: "pid",
        format: "dc+sd-jwt", vct: VCT }] }) });
    const compact = await verifier.signRequestObject({ claims: claims,
      identity: one });
    const r = await vp.verifyX509Request({ compact: compact,
      clientId: clientId, trustAnchorPem: root.certificatePem,
      verifyChain: x509.verifyChain,
      responseTarget: claims.response_uri });
    r.checks.forEach(function (c) {
      ok(c.ok, one.dnsName + ": a wallet anchored on the kept root: '" +
         c.name + "' failed: " + c.detail);
    });
  }

  const requestKey = verifier.makeRequestKey();
  const attester = verifier.makeAttester();
  const file = JSON.stringify(verifier.verifierIdentityFile({ root: root,
    attester: attester, requestKey: requestKey }));
  ok(file.indexOf("BEGIN PRIVATE KEY") === -1 && file.indexOf("privatePem")
     === -1, "the file holds the root's key as a JWK only");
  const back = verifier.readVerifierIdentityFile(file);
  eq(back.root.certificatePem.trim(), root.certificatePem.trim(),
     "the root certificate round-trips");
  eq(back.root.privateJwk, root.privateJwk, "the root key round-trips");
  eq(back.attester.iss, attester.iss, "the attester keeps its iss");
  eq(back.attester.jwks, attester.jwks, "and the JWKS a wallet trusts");
  eq(verifier.clientIdFor("decentralized_identifier", back.requestKey,
       { didMethod: "jwk" }),
     verifier.clientIdFor("decentralized_identifier", requestKey,
       { didMethod: "jwk" }), "the request key keeps its DID");
  eq(verifier.preRegisteredJwks(back.requestKey),
     verifier.preRegisteredJwks(requestKey),
     "and the JWKS a pre-registered client_id was registered with");
  const c = await verifier.makeVerifierIdentity({ dnsName: "c.example",
    root: back.root });
  ok(new nodeCrypto.X509Certificate(c.leafPem).verify(rootCert.publicKey),
     "a leaf issued under the IMPORTED root chains to the same root");
  const attestation = await verifier.verifierAttestation({
    attester: back.attester, sub: "c.example", identity: back.requestKey });
  ok(nodeVerifyJws(attestation, attester.jwks.keys[0]),
     "the imported attester signs what the original's JWKS verifies (node)");

  const doc = JSON.parse(file);
  throws(function () {
    verifier.readVerifierIdentityFile("{");
  }, /is JSON/, "a file that is not JSON");
  throws(function () {
    verifier.readVerifierIdentityFile(Object.assign({}, doc,
      { type: "something-else" }));
  }, /not a Verifier identity file/, "the wrong type");
  throws(function () {
    verifier.readVerifierIdentityFile(Object.assign({}, doc,
      { version: 2 }));
  }, /version 2/, "an unknown version");
  throws(function () {
    verifier.readVerifierIdentityFile(Object.assign({}, doc, { root: {
      certificatePem: doc.root.certificatePem,
      privateJwk: requestKey.privateJwk } }));
  }, /is not the key in root\.certificatePem/,
  "a root key that is not the certificate's");
  throws(function () {
    verifier.readVerifierIdentityFile(Object.assign({}, doc, { requestKey: {
      privateJwk: Object.assign({}, requestKey.privateJwk,
        { x: attester.privateJwk.x }) } }));
  }, /not the public key of its d/, "a JWK whose x is not its d's");
  throws(function () {
    verifier.readVerifierIdentityFile(Object.assign({}, doc,
      { attester: { privateJwk: { kty: "OKP", crv: "Ed25519", d: "AA" } } }));
  }, /P-256 private JWK/, "an attester key that is not P-256");
  log.info("PASS the Verifier's identity outlives a request: one root, a " +
           "new leaf each time, the file round-trips and is checked.");
  log.debug("Leaving persistentIdentity().");
}

// AN IP ADDRESS IS NOT A dNSName (#470, B5; RFC 5280 section 4.2.1.6).
// When the api is reached by an address, x509_san_dns is refused by name
// and x509_hash's leaf carries the address as an iPAddress SAN — read here
// by node's own X509Certificate, which prints the decoded octets.
async function ipHosts() {
  log.debug("Entering ipHosts().");
  const root = await verifier.makeVerifierRoot();
  for (const one of [["192.0.2.10", "192.0.2.10"],
                     ["[2001:db8::1]", "2001:DB8:0:0:0:0:0:1"]]) {
    const id = await verifier.makeVerifierIdentity({ dnsName: one[0],
      root: root });
    const leaf = new nodeCrypto.X509Certificate(id.leafPem);
    const san = leaf.subjectAltName || "";
    ok(new RegExp("^IP Address:" + one[1].replace(/\./g, "\\.") + "$", "i")
       .test(san), one[0] + ": the SAN must be one iPAddress and no " +
       "dNSName; node read " + JSON.stringify(san));
    eq(id.ipAddress, one[0].replace(/^\[|\]$/g, ""),
       one[0] + ": the identity says its SAN is an address");
    ok(leaf.checkIP(one[0].replace(/^\[|\]$/g, "")) !== undefined,
       one[0] + ": node's checkIP() matches the leaf");
    eq(verifier.clientIdFor("x509_hash", id), "x509_hash:" + id.x509Hash,
       one[0] + ": x509_hash is still available");
    throws(function () {
      verifier.clientIdFor("x509_san_dns", id, { dnsName: one[0] });
    }, /it is an IP address[\s\S]*Use x509_hash/,
    one[0] + ": x509_san_dns is refused, naming x509_hash");
  }
  throws(function () {
    verifier.clientIdFor("x509_san_dns", null, { dnsName: "10.1.2.3" });
  }, /dNSName SAN/, "the refusal needs no certificate");
  const named = await verifier.makeVerifierIdentity({
    dnsName: "verifier.example", root: root });
  eq(new nodeCrypto.X509Certificate(named.leafPem).subjectAltName,
     "DNS:verifier.example", "a host name is still a dNSName");
  eq(named.ipAddress, "", "and the identity says so");
  eq(verifier.clientIdFor("x509_san_dns", named, {}),
     "x509_san_dns:verifier.example", "and x509_san_dns works for it");
  log.info("PASS an IP host: an iPAddress SAN for x509_hash, x509_san_dns " +
           "refused by name.");
  log.debug("Leaving ipHosts().");
}

function requestUris() {
  log.debug("Entering requestUris().");
  const byRef = verifier.authorizationRequestUri({
    clientId: "x509_hash:abc+/=", requestUri: "https://v.example/req/1?x=1&y",
    requestUriMethod: "post" });
  ok(byRef.indexOf("openid4vp://?") === 0, "default scheme: " + byRef);
  let u = new URL(byRef);
  eq([u.searchParams.get("client_id"), u.searchParams.get("request_uri"),
      u.searchParams.get("request_uri_method")],
     ["x509_hash:abc+/=", "https://v.example/req/1?x=1&y", "post"]);
  const byValue = verifier.authorizationRequestUri({ clientId: "c",
    requestObject: "a.b.c", scheme: "haip-vp://" });
  u = new URL(byValue);
  eq([u.protocol, u.searchParams.get("request")], ["haip-vp:", "a.b.c"]);
  const dcql = { credentials: [{ id: "q", format: "dc+sd-jwt",
    meta: { vct_values: ["urn:x"] } }] };
  const unsigned = verifier.authorizationRequestUri({
    clientId: "redirect_uri:https://v.example/r",
    scheme: "https://wallet.example/authorize?lang=en",
    params: { response_type: "vp_token", nonce: "n&=?", dcql_query: dcql,
              response_mode: "direct_post",
              response_uri: "https://v.example/r" } });
  u = new URL(unsigned);
  eq(u.searchParams.get("lang"), "en", "an existing query is kept");
  eq(JSON.parse(u.searchParams.get("dcql_query")), dcql,
     "an object parameter travels as its JSON");
  eq(u.searchParams.get("nonce"), "n&=?", "values are percent-encoded");
  log.info("PASS authorizationRequestUri round-trips through URL parsing.");
  log.debug("Leaving requestUris().");
}

// ---------------------------------------------------------------------------
// A compact JWE written HERE with node's crypto, for #468 M6: ECDH-ES
// (direct key agreement) on P-256, RFC 7518 section 4.6's Concat KDF with
// empty PartyUInfo and PartyVInfo, then AES-GCM with the protected header's
// base64url as the AAD (RFC 7516 section 5.1). Nothing from client/src
// touches it, so the Verifier's reading of a header has to agree with
// OpenSSL's AES-GCM and a KDF written from the RFC.
// ---------------------------------------------------------------------------
const GCM_BITS = { A128GCM: 128, A192GCM: 192, A256GCM: 256 };

function concatKdf(z, enc, bits) {
  log.debug("Entering concatKdf(). " + enc);
  const u32 = function u32(n) {
    log.debug("Entering u32().");
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug("Leaving u32().");
    return b;
  };
  const algId = Buffer.from(enc, "ascii");
  const out = nodeCrypto.createHash("sha256").update(Buffer.concat([
    u32(1), z, u32(algId.length), algId, u32(0), u32(0), u32(bits)
  ])).digest().subarray(0, bits / 8);
  log.debug("Leaving concatKdf().");
  return out;
}

function nodeJwe(header, plaintext, recipientPublicJwk) {
  log.debug("Entering nodeJwe(). " + header.enc);
  const bits = GCM_BITS[header.enc];
  const eph = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const epk = eph.publicKey.export({ format: "jwk" });
  const full = Object.assign({}, header,
    { epk: { kty: "EC", crv: "P-256", x: epk.x, y: epk.y } });
  const z = nodeCrypto.diffieHellman({ privateKey: eph.privateKey,
    publicKey: nodeCrypto.createPublicKey({ key: { kty: "EC",
      crv: "P-256", x: recipientPublicJwk.x, y: recipientPublicJwk.y },
    format: "jwk" }) });
  const cek = concatKdf(z, header.enc, bits);
  const protectedB64 = b64u(JSON.stringify(full));
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv("aes-" + bits + "-gcm", cek, iv);
  cipher.setAAD(Buffer.from(protectedB64, "ascii"));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  log.debug("Leaving nodeJwe().");
  return [protectedB64, "", b64u(iv), b64u(ct), b64u(tag)].join(".");
}

// OpenID4VP 1.0 section 8.3 and RFC 7516's header rules on a direct_post.jwt
// answer (#468, M6), and section 8.2's form encoding (#469, D2). Every
// defect fails EXACTLY its own row and the answer is still opened.
async function jweHeaderRules(env, jwtSession, form, fetchJson, fields) {
  log.debug("Entering jweHeaderRules().");
  const pub = env.enc.publicJwk;
  const plain = Buffer.from(JSON.stringify(fields));
  const send = async function send(jwe, sessionOverride, contentType) {
    log.debug("Entering send().");
    const res = await run({ fields: vp.formEncode({ response: jwe }),
      session: Object.assign({}, jwtSession, sessionOverride || {}),
      fetchJson: fetchJson, contentType: contentType });
    log.debug("Leaving send().");
    return res;
  };
  const right = { alg: "ECDH-ES", enc: "A128GCM", kid: pub.kid };
  let r = await send(nodeJwe(right, plain, pub));
  allPass(r, "a JWE written with node's crypto");
  ["response.jwe.kid", "response.jwe.alg", "response.jwe.enc",
   "response.jwe.crit", "response.decrypt"].forEach(function (id) {
    eq((checkById(r, id) || {}).status, "pass", id + " on a correct JWE");
  });
  ok(!checkById(r, "response.jwe.zip"), "no zip, no zip row");
  ok(!checkById(r, "response.encoding"), "no contentType, no encoding row");
  r = await send(nodeJwe(right, plain, pub), {}, "application/x-www-form-" +
                 "urlencoded; charset=UTF-8");
  allPass(r, "posted as a form");
  eq(checkById(r, "response.encoding").status, "pass");
  r = await send(nodeJwe(Object.assign({}, right, { enc: "A256GCM" }), plain,
                 pub));
  allPass(r, "A256GCM, the other value this Verifier offers");

  r = await send(nodeJwe(Object.assign({}, right, { kid: "other" }), plain,
                 pub));
  failsOnly(r, ["response.jwe.kid"], "kid names another key (section 8.3)");
  ok(/MUST include the same value/.test(checkById(r,
     "response.jwe.kid").detail), "the row quotes section 8.3");
  eq(checkById(r, "response.decrypt").status, "pass",
     "a wrong kid is reported, and the answer still opens");
  const noKid = Object.assign({}, right);
  delete noKid.kid;
  r = await send(nodeJwe(noKid, plain, pub));
  failsOnly(r, ["response.jwe.kid"], "no kid when the key has one");
  const keyNoKid = Object.assign({}, env.enc.privateJwk);
  delete keyNoKid.kid;
  r = await send(nodeJwe(noKid, plain, pub), { decryptionJwk: keyNoKid });
  allPass(r, "no kid when the key has none");
  eq(checkById(r, "response.jwe.kid").status, "skip");

  r = await send(nodeJwe(Object.assign({}, right, { enc: "A192GCM" }), plain,
                 pub));
  failsOnly(r, ["response.jwe.enc"], "an enc the request did not offer");
  eq(checkById(r, "response.decrypt").status, "pass");
  // Section 8.3's own client_metadata example offers A128CBC-HS256.
  const cbc = await joseJwe.encryptCompact({ alg: "ECDH-ES",
    enc: "A128CBC-HS256", plaintext: plain.toString(), key: pub,
    header: { kid: pub.kid } });
  r = await send(cbc.jwe);
  failsOnly(r, ["response.jwe.enc"], "A128CBC-HS256 when it was not offered");
  r = await send(cbc.jwe, { encValuesSupported: ["A128GCM",
                                                 "A128CBC-HS256"] });
  allPass(r, "A128CBC-HS256 when the request offered it (section 8.3's " +
          "example)");

  const kw = await joseJwe.encryptCompact({ alg: "ECDH-ES+A128KW",
    enc: "A128GCM", plaintext: plain.toString(), key: pub,
    header: { kid: pub.kid } });
  r = await send(kw.jwe);
  failsOnly(r, ["response.jwe.alg"], "ECDH-ES+A128KW to an ECDH-ES key " +
            "(section 8.3: alg MUST equal the chosen jwk's alg)");
  eq(checkById(r, "response.decrypt").status, "pass");

  // RFC 7515 section 4.1.11's own example extension, "exp".
  r = await send(nodeJwe(Object.assign({}, right, { crit: ["exp"],
    exp: 1363284000 }), plain, pub));
  failsOnly(r, ["response.jwe.crit"], "crit names an extension this " +
            "Verifier does not understand");
  r = await send(nodeJwe(Object.assign({}, right, { crit: [] }), plain, pub));
  failsOnly(r, ["response.jwe.crit"], "crit is the empty list");
  ok(/empty list/.test(checkById(r, "response.jwe.crit").detail));

  // RFC 7516 section 4.1.3: "DEF" is DEFLATE (RFC 1951), node's raw deflate.
  r = await send(nodeJwe(Object.assign({}, right, { zip: "DEF" }),
                 zlib.deflateRawSync(plain), pub));
  allPass(r, "a zip DEF answer is inflated and checked");
  eq(checkById(r, "response.jwe.zip").status, "pass");
  r = await send(nodeJwe(Object.assign({}, right, { zip: "BR" }), plain,
                 pub));
  failsOnly(r, ["response.jwe.zip"], "a zip value nothing here undoes");
  r = await send(nodeJwe(Object.assign({}, right, { zip: "DEF" }), plain,
                 pub));
  failsOnly(r, ["response.jwe.zip"], "zip DEF over bytes that are not " +
            "DEFLATE");

  // Section 8.2: the answer MUST be form-encoded. JSON is opened, checked,
  // and FAILs its own row.
  r = await send(nodeJwe(right, plain, pub), {}, "application/json");
  failsOnly(r, ["response.encoding"], "a JSON answer (section 8.2)");
  eq(checkById(r, "response.decrypt").status, "pass");
  r = await run({ fields: form, session: Object.assign({}, jwtSession,
    { responseMode: "direct_post", decryptionJwk: undefined }),
    fetchJson: fetchJson, contentType: "text/plain" });
  failsOnly(r, ["response.encoding"], "a plain answer as text/plain");
  log.info("PASS #468 M6 and #469 D2: the JWE's kid, alg, enc, crit and " +
           "zip, and the form encoding, each its own row.");
  log.debug("Leaving jweHeaderRules().");
}

// ---------------------------------------------------------------------------
// dc+sd-jwt: an issuer written here.
// ---------------------------------------------------------------------------
const ISSUER = "https://issuer.example/tenant";
const VCT = "urn:eudi:pid:1";

function disclosure(salt, name, value) {
  log.debug("Entering disclosure().");
  const arr = name === null ? [salt, value] : [salt, name, value];
  log.debug("Leaving disclosure().");
  return b64u(JSON.stringify(arr));
}

function makeIssuer() {
  log.debug("Entering makeIssuer().");
  const key = ecPair();
  const jwk = Object.assign({ kid: "iss-1", alg: "ES256", use: "sig" },
                            key.publicJwk);
  const docs = {};
  docs["https://issuer.example/.well-known/jwt-vc-issuer/tenant"] =
    { issuer: ISSUER, jwks_uri: "https://issuer.example/jwks" };
  docs["https://issuer.example/jwks"] = { keys: [jwk] };
  log.debug("Leaving makeIssuer().");
  return { key: key, docs: docs };
}

// The SD-JWT VC, with given_name and family_name disclosable at the top, a
// street_address disclosable INSIDE a disclosable address, a nationality as
// a disclosable ARRAY element, and a birthdate nobody asks for.
function issueSdJwt(issuer, holderJwk, opts) {
  log.debug("Entering issueSdJwt().");
  const o = opts || {};
  const now = Math.floor(Date.now() / 1000);
  const d = {
    given_name: disclosure("s1", "given_name", "Erika"),
    family_name: disclosure("s2", "family_name", "Mustermann"),
    birthdate: disclosure("s3", "birthdate", "1963-08-12"),
    street: disclosure("s4", "street_address", "Heidestrasse 17"),
    nat: disclosure("s6", null, "DE")
  };
  d.address = disclosure("s5", "address",
    { locality: "Koeln", _sd: [sha256b64u(d.street)] });
  const payload = Object.assign({
    iss: ISSUER, iat: now - 60, nbf: now - 60, exp: now + 86400,
    vct: VCT, _sd_alg: "sha-256",
    _sd: [d.given_name, d.family_name, d.birthdate, d.address]
      .map(sha256b64u).concat([sha256b64u("decoy")]),
    nationalities: [{ "...": sha256b64u(d.nat) }],
    cnf: { jwk: holderJwk }
  }, o.payload || {});
  const header = Object.assign({ alg: "ES256", typ: o.typ || "dc+sd-jwt",
    kid: "iss-1" }, o.header || {});
  const jwt = nodeJws(header, payload, o.signer || issuer.key);
  log.debug("Leaving issueSdJwt().");
  return { jwt: jwt, d: d };
}

// A presentation assembled here: the issuer JWT, the Disclosures given, and
// a KB-JWT whose every member can be set wrong on purpose.
function presentSdJwt(jwt, discs, kb) {
  log.debug("Entering presentSdJwt().");
  const prefix = [jwt].concat(discs).join("~") + "~";
  if (!kb) {
    log.debug("Leaving presentSdJwt(). No KB-JWT.");
    return prefix;
  }
  const payload = { iat: kb.iat !== undefined ? kb.iat :
                      Math.floor(Date.now() / 1000),
                    aud: kb.aud, nonce: kb.nonce,
                    sd_hash: kb.sdHash || sha256b64u(prefix) };
  Object.assign(payload, kb.extra || {});
  log.debug("Leaving presentSdJwt().");
  return prefix + nodeJws({ alg: "ES256", typ: kb.typ || "kb+jwt" },
                          payload, kb.key);
}

async function sdJwtRoundTrip(env) {
  log.debug("Entering sdJwtRoundTrip().");
  const issuer = makeIssuer();
  const fetched = [];
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    fetched.push(url);
    if (!issuer.docs[url]) {
      log.debug("Leaving fetchJson(). Not found.");
      return Promise.reject(new Error("no such document: " + url));
    }
    log.debug("Leaving fetchJson().");
    return Promise.resolve(JSON.parse(JSON.stringify(issuer.docs[url])));
  };
  const holder = ecPair();
  const cred = issueSdJwt(issuer, holder.publicJwk);
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"],
    ["family_name"], ["address", "street_address"],
    ["nationalities", null]] }] });
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    state: verifier.randomToken(), responseMode: "direct_post",
    responseUri: "https://verifier.example/response", dcql: dcql };
  const wanted = [cred.d.given_name, cred.d.family_name, cred.d.address,
                  cred.d.street, cred.d.nat];

  // The KB-JWT by the wallet's own signer.
  const built = await sdJwtVp.buildPresentation({
    credential: cred.jwt + "~" + wanted.join("~") + "~",
    selected: wanted, holderPrivateJwk: holder.privateJwk,
    aud: clientId, nonce: session.nonce, keyBinding: true });
  const form = vp.formEncode(vp.responseFields({
    vpToken: { pid: [built.presentation] }, state: session.state }));
  let r = await run({ fields: form, session: session, fetchJson: fetchJson });
  allPass(r, "dc+sd-jwt over direct_post");
  ok(fetched.indexOf("https://issuer.example/.well-known/jwt-vc-issuer/" +
     "tenant") !== -1, "the issuer key must come from jwt-vc-issuer " +
     "metadata inserted before the issuer's path");
  [["response.mode", "pass"], ["response.state", "pass"],
   ["response.queries", "pass"], ["pid[0].issuer.signature", "pass"],
   ["pid[0].disclosures", "pass"], ["pid[0].kb.sd_hash", "pass"],
   ["pid[0].kb.signature", "pass"], ["pid[0].claims", "pass"],
   ["status", "skip"]].forEach(function (pair) {
    const c = checkById(r, pair[0]);
    ok(c && c.status === pair[1], pair[0] + " must be " + pair[1] + ": " +
       JSON.stringify(c));
  });
  eq(r.presentations.length, 1);
  eq(r.presentations[0].claims.address, { locality: "Koeln",
     street_address: "Heidestrasse 17" }, "a nested Disclosure is put back");
  eq(r.presentations[0].claims.nationalities, ["DE"],
     "an array-element Disclosure is put back");
  ok(!("birthdate" in r.presentations[0].claims),
     "an undisclosed claim stays hidden");
  ok(r.checks.every(function (c) {
    return c.id && c.group && c.label && ["pass", "fail", "skip"]
      .indexOf(c.status) !== -1 && typeof c.detail === "string";
  }), "every check has id, group, label, status and detail");
  eq(r.checks.map(function (c) {
    return c.id;
  }).length, new Set(r.checks.map(function (c) {
    return c.id;
  })).size, "check ids are unique");

  // The same, as a URLSearchParams and as an object of fields.
  r = await run({ fields: new URLSearchParams(form), session: session,
                  fetchJson: fetchJson });
  allPass(r, "dc+sd-jwt as URLSearchParams");
  const parsed = verifier.parseResponse(form);
  eq(parsed.vpToken, { pid: [built.presentation] },
     "vp_token is parsed from its JSON");
  eq(parsed.state, session.state);

  // direct_post.jwt: encrypted with the WALLET's encryptResponse.
  const jwtSession = Object.assign({}, session, {
    responseMode: "direct_post.jwt", decryptionJwk: env.enc.privateJwk });
  const claims = verifier.requestObjectClaims({ clientId: clientId,
    responseUri: session.responseUri, responseMode: "direct_post.jwt",
    nonce: session.nonce, state: session.state, dcql: dcql,
    encryptionJwk: env.enc.publicJwk });
  for (const encName of ["A128GCM", "A256GCM"]) {
    const sealed = await vp.encryptResponse({ fields: vp.responseFields({
      vpToken: { pid: [built.presentation] }, state: session.state }),
      clientMetadata: claims.client_metadata, enc: encName });
    eq(sealed.header.kid, env.enc.publicJwk.kid);
    r = await run({ fields: vp.formEncode({ response: sealed.jwe }),
                    session: jwtSession, fetchJson: fetchJson });
    allPass(r, "dc+sd-jwt over direct_post.jwt " + encName);
    ok(checkById(r, "response.decrypt").status === "pass",
       "response.decrypt must be reported");
  }
  // The mode the request asked for, and the one that arrived.
  r = await run({ fields: form, session: jwtSession, fetchJson: fetchJson });
  failsOnly(r, ["response.mode"], "a plain form under direct_post.jwt");
  r = await run({ fields: { response: "a.b.c.d.e" }, session: session,
                  fetchJson: fetchJson });
  failsOnly(r, ["response.mode"], "a JWE under direct_post");
  const otherKey = await verifier.responseEncryptionKey();
  const sealedElsewhere = await vp.encryptResponse({ fields: {
    vp_token: { pid: [built.presentation] }, state: session.state },
    clientMetadata: { jwks: { keys: [otherKey.publicJwk] } } });
  r = await run({ fields: { response: sealedElsewhere.jwe },
                  session: jwtSession, fetchJson: fetchJson });
  // Section 8.3: a JWE to another key names that key's kid, which is not
  // the one this Verifier offered.
  failsOnly(r, ["response.decrypt", "response.jwe.kid"],
            "a JWE to another Verifier's key");
  await jweHeaderRules(env, jwtSession, form, fetchJson, {
    vp_token: { pid: [built.presentation] }, state: session.state });

  // --- one defect each, each failing exactly its own check ---------------
  const good = { aud: clientId, nonce: session.nonce, key: holder };
  async function one(name, presentation, expect, sessionOverride, vpToken) {
    log.debug("Entering one(). " + name);
    const s = Object.assign({}, session, sessionOverride || {});
    const fields = vp.formEncode(vp.responseFields({
      vpToken: vpToken || { pid: [presentation] },
      state: (sessionOverride || {}).sentState || session.state }));
    const res = await run({ fields: fields, session: s,
                            fetchJson: fetchJson });
    failsOnly(res, expect, name);
    log.debug("Leaving one().");
    return res;
  }
  const P = function P(kbChanges, discs, jwt) {
    log.debug("Entering P().");
    log.debug("Leaving P().");
    return presentSdJwt(jwt || cred.jwt, discs || wanted,
                        Object.assign({}, good, kbChanges));
  };
  allPass(await run({ fields: vp.formEncode({ vp_token: { pid: [P({})] },
    state: session.state }), session: session, fetchJson: fetchJson }),
    "the test's own presentation builder");

  await one("wrong nonce", P({ nonce: "another" }), ["pid[0].kb.nonce"]);
  await one("wrong aud", P({ aud: "x509_hash:somebody-else" }),
            ["pid[0].kb.aud"]);
  await one("stale iat", P({ iat: Math.floor(Date.now() / 1000) - 3600 }),
            ["pid[0].kb.iat"]);
  await one("iat in the future", P({ iat: Math.floor(Date.now() / 1000) +
            3600 }), ["pid[0].kb.iat"]);
  const tampered = disclosure("s3", "birthdate", "1999-01-01");
  await one("tampered Disclosure", P({}, wanted.concat([tampered])),
            ["pid[0].disclosures"]);
  await one("requested claim withheld", P({}, wanted.slice(1)),
            ["pid[0].claims"]);
  await one("wrong sd_hash", P({ sdHash: sha256b64u("something else") }),
            ["pid[0].kb.sd_hash"]);
  await one("KB-JWT signed by another key", P({ key: ecPair() }),
            ["pid[0].kb.signature"]);
  await one("KB-JWT typ JWT", P({ typ: "JWT" }), ["pid[0].kb.header"]);
  const forged = issueSdJwt(issuer, holder.publicJwk,
                            { signer: ecPair() });
  await one("bad issuer signature", P({}, null, forged.jwt),
            ["pid[0].issuer.signature"]);
  const legacy = issueSdJwt(issuer, holder.publicJwk, { typ: "vc+sd-jwt" });
  const legacyResult = await one("legacy typ", P({}, null, legacy.jwt),
                                 ["pid[0].issuer.typ"]);
  ok(/legacy/i.test(checkById(legacyResult, "pid[0].issuer.typ").detail),
     "the vc+sd-jwt failure must say it is the legacy name");
  const otherVct = issueSdJwt(issuer, holder.publicJwk,
                              { payload: { vct: "urn:other" } });
  await one("wrong vct", P({}, null, otherVct.jwt), ["pid[0].vct"]);
  const now = Math.floor(Date.now() / 1000);
  const expired = issueSdJwt(issuer, holder.publicJwk,
    { payload: { exp: now - 7200, iat: now - 90000, nbf: now - 90000 } });
  await one("expired credential", P({}, null, expired.jwt),
            ["pid[0].validity"]);
  const noKb = await one("no KB-JWT where binding is required",
    presentSdJwt(cred.jwt, wanted, null), ["pid[0].kb.present"]);
  ok(checkById(noKb, "pid[0].kb.nonce").status === "skip",
     "with no KB-JWT its checks are skipped, not passed");
  await one("wrong state", P({}), ["response.state"],
            { sentState: "not-the-state" });
  await one("missing query", P({}), ["response.queries"], null, {});
  await one("unknown query id", P({}), ["response.queries"], null,
            { pid: [P({})], other: ["x"] });
  await one("a bare string where an array belongs", P({}),
            ["response.queries"], null, { pid: P({}) });

  // Holder binding not required: no KB-JWT is fine then.
  const unbound = Object.assign({}, session, { dcql: verifier.buildDcql({
    queries: [{ id: "pid", format: "dc+sd-jwt", requireBinding: false,
                vct: VCT, claims: [["given_name"]] }] }) });
  allPass(await run({ fields: vp.formEncode({ vp_token: { pid: [
    presentSdJwt(cred.jwt, wanted, null)] }, state: session.state }),
    session: unbound, fetchJson: fetchJson }), "no binding required");

  // An error answer is reported as such, and nothing else is checked.
  r = await run({ fields: "error=access_denied&error_description=no&state=" +
                  session.state, session: session, fetchJson: fetchJson });
  failsOnly(r, ["response.error"], "an error answer");
  eq(r.checks.length, 1, "an error answer is one check");
  log.info("PASS dc+sd-jwt: a full round trip in both response modes, and " +
           "every defect failing exactly its own check.");
  // #471 E3b: transaction_data (section 8.4, Appendix B.3.3.1). The hash
  // is node's, over the base64url STRING as sent.
  const tdObjects = [{ type: "example_type", credential_ids: ["pid"] },
                     { type: "payment", credential_ids: ["pid"],
                       transaction_data_hashes_alg: ["sha-384"] }];
  const tdStrings = verifier.encodeTransactionData(tdObjects, dcql);
  eq(JSON.parse(Buffer.from(tdStrings[0], "base64url")), tdObjects[0],
     "E3b: base64url JSON objects");
  const tdHash = function tdHash(alg, str) {
    log.debug("Entering tdHash().");
    log.debug("Leaving tdHash().");
    return nodeCrypto.createHash(alg).update(str, "utf8").digest("base64url");
  };
  const tdSession = Object.assign({}, session, { transactionData: tdStrings });
  const tdRun = async function tdRun(extra) {
    log.debug("Entering tdRun().");
    const res = await run({ fields: vp.formEncode({ vp_token: { pid: [
      P({ extra: extra })] }, state: session.state }), session: tdSession,
      fetchJson: fetchJson });
    log.debug("Leaving tdRun().");
    return res;
  };
  // The second asks for sha-384, so the KB-JWT must name it and hash both
  // with it; the first then fails, being sha-256 by default.
  let tr = await tdRun({ transaction_data_hashes: [
    tdHash("sha256", tdStrings[0])] });
  eq([checkById(tr, "pid[0].kb.transaction_data[0]").status,
      checkById(tr, "response.transaction_data[0]").status],
     ["pass", "pass"], "E3b: sha-256 by default binds transaction 0");
  ok(/MUST name the one it used/.test(
     checkById(tr, "pid[0].kb.transaction_data[1]").detail),
     "E3b: a listed alg the KB-JWT does not name fails");
  tr = await tdRun({ transaction_data_hashes_alg: "sha-384",
    transaction_data_hashes: [tdHash("sha384", tdStrings[1])] });
  eq([checkById(tr, "pid[0].kb.transaction_data[0]").status,
      checkById(tr, "pid[0].kb.transaction_data[1]").status],
     ["fail", "pass"], "E3b: sha-384 for the one that lists it");
  tr = await tdRun({ transaction_data_hashes: [tdHash("sha256",
    Buffer.from(tdStrings[0], "base64url").toString())] });
  ok(/not decoded first/.test(checkById(tr,
     "pid[0].kb.transaction_data[0]").detail),
     "E3b: a hash of the DECODED object is not the binding");
  tr = await tdRun({});
  eq([checkById(tr, "pid[0].kb.transaction_data[0]").status,
      checkById(tr, "response.transaction_data[0]").status, tr.verdict],
     ["skip", "skip", "pass"], "E3b: no hashes is reported (another " +
     "representation may be the type's), not failed");
  for (const bad of [[], [{ credential_ids: ["pid"] }],
                     [{ type: "t", credential_ids: ["nope"] }],
                     [{ type: "t", credential_ids: ["pid"],
                        transaction_data_hashes_alg: [] }]]) {
    let why = "";
    try {
      verifier.encodeTransactionData(bad, dcql);
    } catch (e) {
      why = e.message;
    }
    ok(/transaction_data/.test(why), "E3b: refused " + JSON.stringify(bad));
  }
  let tdUnbound = "";
  try {
    verifier.encodeTransactionData([{ type: "t", credential_ids: ["p"] }],
      verifier.buildDcql({ queries: [{ id: "p", format: "dc+sd-jwt",
        vct: VCT, requireBinding: false }] }));
  } catch (e) {
    tdUnbound = e.message;
  }
  ok(/B\.3\.3/.test(tdUnbound), "E3b: a transaction on an tdUnbound query");
  const tdClaims = verifier.requestObjectClaims({ clientId: clientId,
    responseUri: session.responseUri, responseMode: "direct_post",
    nonce: "n", state: "s", dcql: dcql, transactionData: tdStrings });
  eq(tdClaims.transaction_data, tdStrings, "E3b: carried in the request");
  log.debug("Leaving sdJwtRoundTrip().");
}

// ---------------------------------------------------------------------------
async function mdocRoundTrip(env) {
  log.debug("Entering mdocRoundTrip().");
  const auth = await mdocIssuer.authority("vp verifier");
  const device = ecPair();
  const credential = mdocIssuer.issue(auth, device.publicJwk, {
    given_name: "Erika", family_name: "Mustermann", age_over_18: true });
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const NS = mdocIssuer.NS;
  const dcql = verifier.buildDcql({ queries: [{ id: "mdl",
    format: "mso_mdoc", doctype: mdocIssuer.DOCTYPE,
    claims: [[NS, "given_name"], [NS, "family_name"]] }] });
  const unanchored = { clientId: clientId, nonce: verifier.randomToken(),
    state: "st", responseMode: "direct_post.jwt",
    responseUri: "https://verifier.example/response", dcql: dcql,
    decryptionJwk: env.enc.privateJwk };
  // The IACA is the trust anchor; with it the x5chain is anchored.
  const session = Object.assign({}, unanchored,
                                { trustAnchors: [auth.iacaPem] });
  const built = await sdJwtVp.buildMdocPresentation({ credential: credential,
    selected: [NS + "/given_name", NS + "/family_name"],
    holderPrivateJwk: device.privateJwk, aud: clientId,
    nonce: session.nonce, responseUri: session.responseUri,
    encryptionJwk: env.enc.publicJwk });
  const metadata = { jwks: { keys: [env.enc.publicJwk] } };
  async function send(s, presentation) {
    log.debug("Entering send().");
    const sealed = await vp.encryptResponse({ fields: { vp_token: {
      mdl: [presentation] }, state: "st" }, clientMetadata: metadata });
    log.debug("Leaving send().");
    return run({ fields: { response: sealed.jwe }, session: s });
  }
  // #467 S3/S4: with no trust anchor the document signer certificate is
  // UNANCHORED — nothing fails, and the verdict is not a pass.
  let r = await send(unanchored, built.presentation);
  eq(failedIds(r), [], "mdoc, unanchored: nothing fails");
  eq([r.verdict, r.ok, r.incomplete], ["incomplete", false, 1],
     "mdoc, unanchored: the verdict is incomplete, one essential check");
  eq(checkById(r, "mdl[0].mdoc.issuer-trust").status, "skip",
     "mdoc, unanchored: the issuer trust row is a skip");
  ok(/NOT anchored/.test(checkById(r, "mdl[0].mdoc.issuer-trust").detail),
     "mdoc, unanchored: the row says so");
  ok(/UNANCHORED/.test(checkById(r, "mdl[0].mdoc.issuer-signature")
     .detail), "mdoc.js's issuer signature text says it is unanchored");
  r = await send(session, built.presentation);
  allPass(r, "mso_mdoc over direct_post.jwt");
  ok(/anchored at the supplied trust anchor/.test(checkById(r,
     "mdl[0].mdoc.issuer-trust").detail), "mdoc, anchored at the IACA");
  ["mdl[0].mdoc.element-digests", "mdl[0].mdoc.issuer-signature",
   "mdl[0].mdoc.issuer-trust",
   "mdl[0].mdoc.device-signature", "mdl[0].mdoc.doctype",
   "mdl[0].validity", "mdl[0].claims"].forEach(function (id) {
    ok(checkById(r, id) && checkById(r, id).status === "pass",
       id + " must pass: " + JSON.stringify(checkById(r, id)));
  });
  eq(r.presentations[0].claims[NS], { given_name: "Erika",
     family_name: "Mustermann" });
  r = await send(Object.assign({}, session, { nonce: "another" }),
                 built.presentation);
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc, another nonce");
  r = await send(Object.assign({}, session, {
    responseUri: "https://elsewhere.example/r" }), built.presentation);
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc, another " +
            "response_uri");
  const wantsMore = verifier.buildDcql({ queries: [{ id: "mdl",
    format: "mso_mdoc", doctype: mdocIssuer.DOCTYPE,
    claims: [[NS, "given_name"], [NS, "age_over_18"]] }] });
  r = await send(Object.assign({}, session, { dcql: wantsMore }),
                 built.presentation);
  failsOnly(r, ["mdl[0].claims"], "mdoc, a requested element withheld");
  const otherDoc = verifier.buildDcql({ queries: [{ id: "mdl",
    format: "mso_mdoc", doctype: "org.example.other",
    claims: [[NS, "given_name"]] }] });
  r = await send(Object.assign({}, session, { dcql: otherDoc }),
                 built.presentation);
  failsOnly(r, ["mdl[0].mdoc.doctype"], "mdoc, another docType");
  log.info("PASS mso_mdoc: DeviceResponse, issuerSigned and the device " +
           "signature over the OpenID4VPHandover transcript.");
  log.debug("Leaving mdocRoundTrip().");
}

// ---------------------------------------------------------------------------
async function jwtVcJsonRoundTrip(env) {
  log.debug("Entering jwtVcJsonRoundTrip().");
  const issuer = ecPair();
  const issuerDid = didJwk(issuer.publicJwk);
  const holder = ecPair();
  const holderDid = didJwk(holder.publicJwk);
  const now = Math.floor(Date.now() / 1000);
  const vc = nodeJws({ alg: "ES256", typ: "JWT", kid: issuerDid + "#0" }, {
    iss: issuerDid, sub: holderDid, iat: now - 60, nbf: now - 60,
    exp: now + 86400, cnf: { jwk: holder.publicJwk },
    vc: { "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiableCredential", "IdentityCredential"],
          credentialSubject: { id: holderDid, given_name: "Erika",
                               family_name: "Mustermann" } }
  }, issuer);
  const clientId = verifier.clientIdFor("x509_san_dns", env.identity,
    { dnsName: "verifier.example" });
  const dcql = verifier.buildDcql({ queries: [{ id: "w3c",
    format: "jwt_vc_json", types: ["VerifiableCredential",
    "IdentityCredential"], claims: [["credentialSubject", "given_name"]]
  }] });
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    state: "st", responseMode: "direct_post",
    responseUri: "https://verifier.example/response", dcql: dcql };
  async function send(s, presentation) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return run({ fields: vp.formEncode({ vp_token: { w3c: [presentation] },
                 state: "st" }), session: s });
  }
  const signed = await sdJwtVp.signVpJwt({ credential: vc,
    holderPrivateJwk: holder.privateJwk, holderId: holderDid,
    aud: clientId, nonce: session.nonce });
  let r = await send(session, signed.jwt);
  allPass(r, "jwt_vc_json");
  ["w3c[0].vp.signature", "w3c[0].vp.binding", "w3c[0].vc.signature",
   "w3c[0].types", "w3c[0].claims"].forEach(function (id) {
    ok(checkById(r, id) && checkById(r, id).status === "pass",
       id + " must pass: " + JSON.stringify(checkById(r, id)));
  });
  r = await send(Object.assign({}, session, { nonce: "other" }), signed.jwt);
  failsOnly(r, ["w3c[0].vp.nonce"], "jwt_vc_json, another nonce");
  r = await send(Object.assign({}, session, { clientId: "x509_san_dns:x" }),
                 signed.jwt);
  failsOnly(r, ["w3c[0].vp.aud"], "jwt_vc_json, another Verifier");
  const thief = ecPair();
  const stolen = await sdJwtVp.signVpJwt({ credential: vc,
    holderPrivateJwk: thief.privateJwk, holderId: holderDid,
    aud: clientId, nonce: session.nonce });
  r = await send(session, stolen.jwt);
  failsOnly(r, ["w3c[0].vp.signature"], "jwt_vc_json, a VP claiming the " +
            "holder's DID and signed by somebody else");
  const own = await sdJwtVp.signVpJwt({ credential: vc,
    holderPrivateJwk: thief.privateJwk, holderId: didJwk(thief.publicJwk),
    aud: clientId, nonce: session.nonce });
  r = await send(session, own.jwt);
  failsOnly(r, ["w3c[0].vp.binding"], "jwt_vc_json, a VP by a key the " +
            "credential is not bound to");
  const parts = vc.split(".");
  const badVc = parts[0] + "." + parts[1] + "." + b64u(Buffer.alloc(64, 1));
  const badVp = await sdJwtVp.signVpJwt({ credential: badVc,
    holderPrivateJwk: holder.privateJwk, holderId: holderDid,
    aud: clientId, nonce: session.nonce });
  r = await send(session, badVp.jwt);
  failsOnly(r, ["w3c[0].vc.signature"], "jwt_vc_json, a forged VC");
  log.info("PASS jwt_vc_json: the VP JWT, its holder binding and the " +
           "embedded VC.");
  log.debug("Leaving jwtVcJsonRoundTrip().");
}

// ---------------------------------------------------------------------------
// ldp_vc with bbs-2023 as W3C Data Integrity BBS Cryptosuites v1.0 has it
// (#470 B1): a reveal document with a derived proof, bare or inside an
// ecdsa-jcs-2019 VP, verified from the document itself.
async function ldpVcRoundTrip(env) {
  log.debug("Entering ldpVcRoundTrip().");
  const sk = bbs.keyGen(nodeCrypto.randomBytes(32));
  const pk = bbs.secretKeyToPublicKey(sk);
  const vm = "https://issuer.example/bbs/keys/1";
  const docs = {};
  docs[vm] = { id: vm, type: "Multikey", controller: "https://issuer.example",
               publicKeyMultibase: bbs2023.publicKeyToMultikey(pk) };
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    if (!docs[url]) {
      log.debug("Leaving fetchJson(). Not found.");
      return Promise.reject(new Error("no such document: " + url));
    }
    log.debug("Leaving fetchJson().");
    return Promise.resolve(docs[url]);
  };
  const holder = ecPair();
  const holderDid = didJwk(holder.publicJwk);
  const unsecured = {
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 bbs2023.IDENTITY_CONTEXT_URL],
    type: ["VerifiableCredential", "IdentityCredential"],
    issuer: "https://issuer.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: holderDid, given_name: "Erika",
                         family_name: "Mustermann" }
  };
  const issued = await bbs2023.createBaseProof(unsecured,
    { verificationMethod: vm }, { secretKey: sk, publicKey: pk });
  eq(issued.mandatoryPointers, ["/issuer", "/type", "/validFrom"],
     "the default mandatory pointers the credential has");
  ok(!("created" in issued.credential.proof), "no created in the proof");
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const nonce = verifier.randomToken();
  async function revealFor(credential, ph) {
    log.debug("Entering revealFor().");
    const derived = await bbs2023.deriveProof(credential, {
      selectivePointers: ["/credentialSubject/given_name"],
      presentationHeader: ph });
    log.debug("Leaving revealFor().");
    return derived.document;
  }
  async function inVp(credential) {
    log.debug("Entering inVp().");
    log.debug("Leaving inVp().");
    return vp.ldpVerifiablePresentation({ credential: credential,
      holder: holderDid, privateJwk: holder.privateJwk, nonce: nonce,
      aud: clientId });
  }
  // type_values are compared as expanded IRIs (OpenID4VP 1.0 B.1.1).
  const dcql = verifier.buildDcql({ queries: [{ id: "ld", format: "ldp_vc",
    types: ["https://www.w3.org/2018/credentials#VerifiableCredential",
            "https://idptools.com/contexts/identity#IdentityCredential"],
    claims: [["credentialSubject", "given_name"]] }] });
  const session = { clientId: clientId, nonce: nonce, state: "st",
    responseMode: "direct_post", dcql: dcql,
    responseUri: "https://verifier.example/response" };
  async function send(s, element, fetcher) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return run({ fields: vp.formEncode({ vp_token: { ld: [element] },
                 state: "st" }), session: s,
                 fetchJson: fetcher || fetchJson });
  }
  const revealed = await revealFor(issued.credential, nonce);
  ok(!("family_name" in revealed.credentialSubject),
     "the withheld claim is not in the reveal document");
  eq(revealed.credentialSubject.id, holderDid,
     "the subject's id travels with any claim of it");
  const wrapped = await inVp(revealed);
  let r = await send(session, wrapped);
  allPass(r, "ldp_vc bbs-2023 reveal document in an ecdsa-jcs-2019 VP");
  ["ld[0].vp.proof", "ld[0].vp.challenge", "ld[0].vp.domain",
   "ld[0].vc.proof", "ld[0].bbs.ph", "ld[0].vc.validity", "ld[0].types",
   "ld[0].vp.binding", "ld[0].claims"].forEach(function (id) {
    ok(checkById(r, id) && checkById(r, id).status === "pass",
       id + " must pass: " + JSON.stringify(checkById(r, id)));
  });
  ok(/bbs-2023 by https:\/\/issuer\.example\/bbs\/keys\/1/.test(
     checkById(r, "ld[0].vc.proof").detail),
     checkById(r, "ld[0].vc.proof").detail);
  r = await send(session, await inVp(await revealFor(issued.credential,
                                                     "")));
  allPass(r, "ldp_vc in a VP, presentation header empty");
  ok(/empty/.test(checkById(r, "ld[0].bbs.ph").detail),
     checkById(r, "ld[0].bbs.ph").detail);
  r = await send(Object.assign({}, session, { nonce: "other" }), wrapped);
  failsOnly(r, ["ld[0].bbs.ph", "ld[0].vp.challenge"],
            "ldp_vc, another nonce (both the BBS presentation header and " +
            "the VP challenge carry it)");
  r = await send(Object.assign({}, session, { clientId: "x509_hash:x" }),
                 wrapped);
  failsOnly(r, ["ld[0].vp.domain"], "ldp_vc, another Verifier");

  // A tampered reveal document. Re-wrapped, so the holder's proof is good
  // and only the issuer's derived proof can catch it.
  const tampered = JSON.parse(JSON.stringify(revealed));
  tampered.credentialSubject.given_name = "Mallory";
  r = await send(session, await inVp(tampered));
  failsOnly(r, ["ld[0].vc.proof"], "ldp_vc, a tampered reveal document " +
            "re-wrapped by the holder");
  const forgedVp = JSON.parse(JSON.stringify(wrapped));
  forgedVp.verifiableCredential[0].credentialSubject.given_name = "Mallory";
  r = await send(session, forgedVp);
  failsOnly(r, ["ld[0].vc.proof", "ld[0].vp.proof", "ld[0].vp.binding"],
            "ldp_vc, a reveal document altered inside a signed VP");

  // Bare: the presentation header is the binding.
  r = await send(session, revealed);
  allPass(r, "ldp_vc, a bare reveal document whose presentation header " +
          "is the nonce");
  eq(checkById(r, "ld[0].vp.proof").status, "skip",
     "a bare reveal document has no VP proof to check");
  ok(checkById(r, "ld[0].bbs.ph").essential, "and its presentation header " +
     "is then an essential check");
  r = await send(session, await revealFor(issued.credential, "other"));
  failsOnly(r, ["ld[0].bbs.ph"], "ldp_vc, a bare reveal document derived " +
            "for another nonce");
  r = await send(session, await revealFor(issued.credential, ""));
  failsOnly(r, ["ld[0].bbs.ph"], "ldp_vc, a bare reveal document with no " +
            "presentation header");

  // The pre-W3C envelope this tree's wallet used to send.
  const envelope = { cryptosuite: "bbs-2023", proof: b64u(Buffer.alloc(272)),
    disclosedIndexes: [0], disclosedStatements: ["_:b0 <x:y> \"z\" .\n"],
    proofOptions: { verificationMethod: vm } };
  r = await send(session, envelope);
  ok(failedIds(r).indexOf("ld[0].vc.proof") !== -1 && !r.ok,
     "the pre-W3C envelope fails: " + JSON.stringify(failedIds(r)));
  ok(/pre-W3C non-standard bbs-2023 envelope/.test(
     checkById(r, "ld[0].vc.proof").detail),
     checkById(r, "ld[0].vc.proof").detail);
  r = await send(session, await inVp(envelope));
  ok(/pre-W3C non-standard/.test(checkById(r, "ld[0].vc.proof").detail) &&
     !r.ok, "and inside a VP too");

  // S2: an https issuer and a derived proof by a key it does not control.
  const thiefSk = bbs.keyGen(nodeCrypto.randomBytes(32));
  const thiefPk = bbs.secretKeyToPublicKey(thiefSk);
  const thiefKey = bbs2023.publicKeyToMultikey(thiefPk);
  const foreign = await bbs2023.createBaseProof(unsecured,
    { verificationMethod: "did:key:" + thiefKey + "#" + thiefKey },
    { secretKey: thiefSk, publicKey: thiefPk });
  r = await send(session, await inVp(await revealFor(foreign.credential,
                                                     nonce)));
  failsOnly(r, ["ld[0].vc.proof"], "ldp_vc, an https issuer with a foreign " +
            "did:key Multikey");
  ok(/not authorised by the issuer/.test(
     checkById(r, "ld[0].vc.proof").detail),
     checkById(r, "ld[0].vc.proof").detail);
  // The issuer's own key URL, serving somebody else's key.
  const swapped = {};
  swapped[vm] = Object.assign({}, docs[vm], { publicKeyMultibase: thiefKey });
  r = await send(session, wrapped, function swappedJson(url) {
    log.debug("Entering swappedJson().");
    log.debug("Leaving swappedJson().");
    return Promise.resolve(swapped[url]);
  });
  failsOnly(r, ["ld[0].vc.proof"], "ldp_vc, the verification method " +
            "serves another key");
  // A key that cannot be had is a SKIP, not a forgery (#470 B2).
  r = await send(session, wrapped, function nothing() {
    log.debug("Entering nothing().");
    log.debug("Leaving nothing().");
    return Promise.reject(new Error("unreachable"));
  });
  incompleteOnly(r, ["ld[0].vc.proof"], "ldp_vc, the issuer's BBS key " +
                 "cannot be fetched");
  // A raw base64url key where a Multikey belongs.
  const raw = {};
  raw[vm] = Object.assign({}, docs[vm], { publicKeyMultibase: "u" +
    b64u(Buffer.from(pk)) });
  r = await send(session, wrapped, function rawJson(url) {
    log.debug("Entering rawJson().");
    log.debug("Leaving rawJson().");
    return Promise.resolve(raw[url]);
  });
  failsOnly(r, ["ld[0].vc.proof"], "ldp_vc, a raw base64url BBS key");
  ok(/pre-W3C/.test(checkById(r, "ld[0].vc.proof").detail),
     checkById(r, "ld[0].vc.proof").detail);

  // Validity, which the default mandatory pointers always reveal.
  const expired = await bbs2023.createBaseProof(Object.assign({}, unsecured,
    { validUntil: "2026-02-01T00:00:00Z" }), { verificationMethod: vm },
    { secretKey: sk, publicKey: pk });
  r = await send(session, await inVp(await revealFor(expired.credential,
                                                     nonce)));
  failsOnly(r, ["ld[0].vc.validity"], "ldp_vc, an expired credential");

  const otherSuite = JSON.parse(JSON.stringify(wrapped));
  otherSuite.proof.cryptosuite = "eddsa-rdfc-2022";
  r = await send(session, otherSuite);
  failsOnly(r, ["ld[0].vp.proof", "ld[0].vp.binding"], "a P-256 proof " +
            "relabelled eddsa-rdfc-2022 (that suite needs an Ed25519 key)");
  ok(/Ed25519/.test(checkById(r, "ld[0].vp.proof").detail),
     checkById(r, "ld[0].vp.proof").detail);
  // A P-256 ecdsa-jcs-2019 proof relabelled ecdsa-sd-2023: that suite is
  // verified now (#476), and this proofValue is not one of its own.
  const sdSuite = JSON.parse(JSON.stringify(wrapped));
  sdSuite.proof.cryptosuite = "ecdsa-sd-2023";
  r = await send(session, sdSuite);
  eq(checkById(r, "ld[0].vp.proof").status, "fail",
     "an ecdsa-jcs-2019 proof relabelled ecdsa-sd-2023 fails");

  // A genuine ecdsa-sd-2023 credential: an issuer base proof by a did:key
  // P-256 key, derived to one claim by the holder and wrapped in the
  // holder's VP. Then the same with the disclosed claim changed.
  const sdIssuer = ecPair();
  const sdDid = didLib.jwkToDidKey(sdIssuer.publicJwk);
  const sdBase = await ecdsaSd.createBaseProof(Object.assign({}, unsecured,
    { issuer: sdDid }), { privateJwk: sdIssuer.privateJwk,
    verificationMethod: sdDid + "#" + sdDid.slice("did:key:".length),
    mandatoryPointers: ["/issuer", "/type", "/validFrom"] });
  const sdDerived = (await ecdsaSd.deriveProof(sdBase,
    { selectivePointers: ["/credentialSubject/given_name"] })).document;
  ok(!("family_name" in sdDerived.credentialSubject),
     "ecdsa-sd-2023: the withheld claim is not disclosed");
  r = await send(session, await inVp(sdDerived));
  allPass(r, "ldp_vc ecdsa-sd-2023 derived credential in an " +
          "ecdsa-jcs-2019 VP");
  ok(/ecdsa-sd-2023/.test(checkById(r, "ld[0].vc.proof").detail),
     checkById(r, "ld[0].vc.proof").detail);
  const sdTampered = JSON.parse(JSON.stringify(sdDerived));
  sdTampered.credentialSubject.given_name = "Mallory";
  r = await send(session, await inVp(sdTampered));
  failsOnly(r, ["ld[0].vc.proof"], "ldp_vc, a tampered ecdsa-sd-2023 " +
            "disclosure re-wrapped by the holder");
  ok(verifier.vpFormatsSupported().ldp_vc.cryptosuite_values
     .indexOf("bbs-2023") !== -1, "bbs-2023 is advertised");
  log.info("PASS ldp_vc: W3C bbs-2023 reveal documents, bare and in an " +
           "ecdsa-jcs-2019 VP, and the pre-W3C envelope refused.");
  log.debug("Leaving ldpVcRoundTrip().");
}

// ---------------------------------------------------------------------------
// PR 3: helpers the new sections share.
// ---------------------------------------------------------------------------

// RFC 8785 JSON Canonicalization, written here rather than taken from
// vp_protocols.jcs() so that the Data Integrity tests do not check the
// engine's JCS with itself. ECMAScript's JSON.stringify already serializes
// strings and numbers as RFC 8785 section 3.2.2 requires; what JCS adds is
// object members sorted by their UTF-16 code units, which is what the
// default sort compares.
function canonicalizeJson(value) {
  log.debug("Entering canonicalizeJson().");
  let out;
  if (Array.isArray(value)) {
    out = "[" + value.map(canonicalizeJson).join(",") + "]";
  } else if (value && typeof value === "object") {
    out = "{" + Object.keys(value).filter(function (k) {
      return value[k] !== undefined;
    }).sort().map(function (k) {
      return JSON.stringify(k) + ":" + canonicalizeJson(value[k]);
    }).join(",") + "}";
  } else {
    out = JSON.stringify(value);
  }
  log.debug("Leaving canonicalizeJson().");
  return out;
}

// A compact JWS verified by node's crypto against a JWK (ES256 or ES384).
function nodeVerifyJws(compact, jwk) {
  log.debug("Entering nodeVerifyJws().");
  const parts = compact.split(".");
  const header = JSON.parse(Buffer.from(parts[0], "base64url"));
  const key = nodeCrypto.createPublicKey({ key: { kty: jwk.kty,
    crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
  log.debug("Leaving nodeVerifyJws().");
  return nodeCrypto.verify(header.alg === "ES384" ? "sha384" : "sha256",
    Buffer.from(parts[0] + "." + parts[1]),
    { key: key, dsaEncoding: "ieee-p1363" },
    Buffer.from(parts[2], "base64url"));
}

function decodeCompact(compact) {
  log.debug("Entering decodeCompact().");
  const parts = compact.split(".");
  log.debug("Leaving decodeCompact().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url")),
           payload: JSON.parse(Buffer.from(parts[1], "base64url")) };
}

function thumbprintOf(jwk) {
  log.debug("Entering thumbprintOf().");
  log.debug("Leaving thumbprintOf().");
  return b64u(nodeCrypto.createHash("sha256").update(JSON.stringify(
    { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest());
}

async function rejects(promiseFn, re, message) {
  log.debug("Entering rejects().");
  assertions++;
  await assert.rejects(promiseFn, re, message);
  log.debug("Leaving rejects().");
}

function throws(fn, re, message) {
  log.debug("Entering throws().");
  assertions++;
  assert.throws(fn, re, message);
  log.debug("Leaving throws().");
}

// ---------------------------------------------------------------------------
// The remaining Client Identifier prefixes, and wallet_nonce.
// ---------------------------------------------------------------------------
async function prefixesAndWalletNonce(env) {
  log.debug("Entering prefixesAndWalletNonce().");
  const key = verifier.makeRequestKey();
  eq([key.publicJwk.kty, key.publicJwk.crv, key.publicJwk.alg],
     ["EC", "P-256", "ES256"]);
  ok(!key.publicJwk.d && key.privateJwk.d, "makeRequestKey: d only private");
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"]] }] });
  const base = { responseUri: "https://verifier.example/response",
    responseMode: "direct_post", nonce: "n-1", state: "s-1", dcql: dcql };

  // decentralized_identifier with did:jwk and did:key, each resolved by
  // did.js and the signature checked by node.
  for (const method of ["jwk", "key"]) {
    const cid = verifier.clientIdFor("decentralized_identifier", key,
                                     { didMethod: method });
    ok(cid.indexOf("decentralized_identifier:did:" + method + ":") === 0,
       cid);
    const did = cid.slice("decentralized_identifier:".length);
    const claims = verifier.requestObjectClaims(Object.assign({}, base,
      { clientId: cid }));
    const compact = await verifier.signRequestObject({ claims: claims,
      identity: key });
    const d = decodeCompact(compact);
    ok(!("x5c" in d.header), method + ": a DID-signed request has no x5c");
    eq(d.header.typ, "oauth-authz-req+jwt");
    eq(d.header.kid, method === "jwk" ? did + "#0" :
       did + "#" + did.slice("did:key:".length),
       method + ": kid is a DID URL naming the key");
    eq(d.payload.client_id, cid);
    ok(!("iss" in d.payload), "only the x509 prefixes carry iss");
    const resolved = await didLib.resolve(did);
    const vmJwk = didLib.verificationMethods(resolved.document)[0].jwk;
    ok(nodeVerifyJws(compact, vmJwk), method + ": the request verifies " +
       "with the key did.js resolves the DID to");
    ok(!nodeVerifyJws(compact, ecPair().publicJwk),
       method + ": and not with another key");
  }
  const strangerDid = "decentralized_identifier:" +
    verifier.didForKey(verifier.makeRequestKey().publicJwk, "jwk");
  await rejects(function () {
    return verifier.signRequestObject({ claims: verifier.requestObjectClaims(
      Object.assign({}, base, { clientId: strangerDid })), identity: key });
  }, /another key/, "signing as a DID of another key is refused");

  // verifier_attestation.
  const attester = verifier.makeAttester();
  ok(/^did:jwk:/.test(attester.iss), "the attester's iss is its did:jwk");
  eq(attester.jwks.keys.length, 1);
  ok(!attester.jwks.keys[0].d, "the attester's published key has no d");
  const vaCid = verifier.clientIdFor("verifier_attestation", null,
                                     { value: "verifier.example" });
  eq(vaCid, "verifier_attestation:verifier.example");
  const vaClaims = verifier.requestObjectClaims(Object.assign({}, base,
    { clientId: vaCid }));
  const vaCompact = await verifier.signRequestObject({ claims: vaClaims,
    identity: key, attester: attester });
  const va = decodeCompact(vaCompact);
  ok(!("x5c" in va.header), "an attested request carries no x5c");
  ok(typeof va.header.jwt === "string", "the attestation is the jwt header");
  const att = decodeCompact(va.header.jwt);
  eq(att.header.typ, "verifier-attestation+jwt");
  eq(att.payload.sub, "verifier.example",
     "the attestation's sub is the Client Identifier's value");
  eq(att.payload.iss, attester.iss);
  ok(att.payload.exp > att.payload.iat, "the attestation expires");
  ok(nodeVerifyJws(va.header.jwt, attester.jwks.keys[0]),
     "the attestation verifies with the attester's published key");
  const attIssKey = (await didLib.resolve(att.payload.iss)).document;
  ok(nodeVerifyJws(va.header.jwt,
     didLib.verificationMethods(attIssKey)[0].jwk),
     "and with the key its iss (a did:jwk) resolves to");
  eq(thumbprintOf(att.payload.cnf.jwk), thumbprintOf(key.publicJwk),
     "cnf.jwk is the request key");
  ok(nodeVerifyJws(vaCompact, att.payload.cnf.jwk),
     "the request verifies with the attestation's cnf.jwk");
  await rejects(function () {
    return verifier.signRequestObject({ claims: vaClaims, identity: key });
  }, /attester/, "verifier_attestation without an attester is refused");

  // Pre-registered: no prefix, a kid the wallet's JWKS has, no x5c.
  eq(verifier.clientIdFor("pre-registered", null,
     { clientId: "my-verifier-123" }), "my-verifier-123");
  throws(function () {
    verifier.clientIdFor("pre-registered", null,
                         { clientId: "x509_hash:abc" });
  }, /prefix/, "a typed id with a prefix is not pre-registered");
  throws(function () {
    verifier.clientIdFor("pre-registered", null, {});
  }, /client_id/, "a pre-registered client needs a typed id");
  const prClaims = verifier.requestObjectClaims(Object.assign({}, base,
    { clientId: "my-verifier-123" }));
  const prCompact = await verifier.signRequestObject({ claims: prClaims,
    identity: key });
  const pr = decodeCompact(prCompact);
  const jwks = verifier.preRegisteredJwks(key);
  ok(!("x5c" in pr.header) && !("jwt" in pr.header),
     "a pre-registered request carries neither x5c nor jwt");
  eq(pr.header.kid, jwks.keys[0].kid, "kid names the pre-registered key");
  ok(!jwks.keys[0].d, "the pre-registered JWKS is public");
  ok(nodeVerifyJws(prCompact, jwks.keys[0]),
     "the request verifies with the JWKS a wallet would have registered");

  // openid_federation is refused everywhere, citing the roadmap.
  throws(function () {
    verifier.clientIdFor("openid_federation", null, {});
  }, /Federation 1\.0.*spec-roadmap/);
  throws(function () {
    verifier.requestObjectClaims(Object.assign({}, base,
      { clientId: "openid_federation:https://v.example" }));
  }, /trust chain/);
  await rejects(function () {
    return verifier.signRequestObject({ claims: Object.assign({}, prClaims,
      { client_id: "openid_federation:https://v.example" }), identity: key });
  }, /trust chain/);

  // origin: only the DC API's, never typed into a direct_post request.
  eq(verifier.clientIdFor("origin", null,
     { origin: "https://verifier.example" }),
     "origin:https://verifier.example");
  throws(function () {
    verifier.requestObjectClaims(Object.assign({}, base,
      { clientId: "origin:https://verifier.example" }));
  }, /Digital Credentials API/);

  // wallet_nonce (section 5.10).
  const withNonce = verifier.requestObjectClaims(Object.assign({}, base, {
    clientId: verifier.clientIdFor("x509_hash", env.identity),
    walletNonce: "wallet-nonce-1" }));
  eq(withNonce.wallet_nonce, "wallet-nonce-1", "wallet_nonce is included");
  const signedNonce = await verifier.signRequestObject({ claims: withNonce,
    identity: env.identity });
  eq(decodeCompact(signedNonce).payload.wallet_nonce, "wallet-nonce-1",
     "and signed");
  ok(!("wallet_nonce" in prClaims), "and absent when none was given");
  log.info("PASS the Client Identifier prefixes (DID, attestation, " +
           "pre-registered, origin, federation refused) and wallet_nonce.");
  log.debug("Leaving prefixesAndWalletNonce().");
}

// ---------------------------------------------------------------------------
// mdoc: an issuer and a DeviceResponse written here, so the MSO can carry a
// status and the transcript can be the DC API's.
// ---------------------------------------------------------------------------
function coseSigStructure(protectedBytes, payload) {
  log.debug("Entering coseSigStructure().");
  log.debug("Leaving coseSigStructure().");
  return mdocIssuer.cbor(["Signature1", protectedBytes, Buffer.alloc(0),
                          payload]);
}

// `opts` (#469, C8): alg (the issuerAuth COSE alg, -7), hash (node's name
// for the digest, "sha256"), digestAlgorithm (what the MSO SAYS, which a
// test may make disagree with `hash`), msoDocType, deviceCrv (the COSE
// curve of the device key: 1 P-256, 2 P-384).
function issueMdocHere(auth, devicePublicJwk, elements, status, opts) {
  log.debug("Entering issueMdocHere().");
  const o = opts || {};
  const hashName = o.hash || "sha256";
  const Tag = mdocIssuer.Tag;
  const cbor = mdocIssuer.cbor;
  const tdate = function tdate(d) {
    log.debug("Entering tdate().");
    log.debug("Leaving tdate().");
    return new Tag(0, d.toISOString().replace(/\.\d{3}Z$/, "Z"));
  };
  const now = new Date();
  const items = Object.keys(elements).map(function (name, i) {
    return { digestID: i, bytes: cbor({ digestID: i,
      random: nodeCrypto.randomBytes(16), elementIdentifier: name,
      elementValue: elements[name] }) };
  });
  const digests = new Map();
  items.forEach(function (it) {
    digests.set(it.digestID, nodeCrypto.createHash(hashName)
      .update(cbor(new Tag(24, it.bytes))).digest());
  });
  const mso = {
    version: "1.0", digestAlgorithm: o.digestAlgorithm || "SHA-256",
    valueDigests: new Map([[mdocIssuer.NS, digests]]),
    deviceKeyInfo: { deviceKey: new Map([[1, 2], [-1, o.deviceCrv || 1],
      [-2, Buffer.from(devicePublicJwk.x, "base64url")],
      [-3, Buffer.from(devicePublicJwk.y, "base64url")]]) },
    docType: o.msoDocType || mdocIssuer.DOCTYPE,
    validityInfo: { signed: tdate(now), validFrom: tdate(now),
      validUntil: tdate(new Date(now.getTime() + 30 * 86400000)) }
  };
  if (status) mso.status = status.raw || { status_list: status };
  const payload = cbor(new Tag(24, cbor(mso)));
  const protectedBytes = cbor(new Map([[1, o.alg || -7]]));
  const signature = nodeCrypto.sign("sha256",
    coseSigStructure(protectedBytes, payload),
    { key: auth.dsKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving issueMdocHere().");
  return { items: items, docType: mdocIssuer.DOCTYPE,
           issuerAuth: [protectedBytes, new Map([[33, auth.dsDer]]), payload,
                        signature] };
}

// OpenID4VP 1.0 Appendix B.2.6.2, from the text: [null, null,
// ["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce,
// jwkThumbprint]))]], the origin WITHOUT "origin:".
function dcTranscript(origin, nonce, encryptionJwk) {
  log.debug("Entering dcTranscript().");
  const thumb = encryptionJwk ? Buffer.from(thumbprintOf(encryptionJwk),
                                            "base64url") : null;
  const info = mdocIssuer.cbor([origin, nonce, thumb]);
  log.debug("Leaving dcTranscript().");
  return [null, null, ["OpenID4VPDCAPIHandover",
    nodeCrypto.createHash("sha256").update(info).digest()]];
}

// `opts` (#469, C8): docType (the DOCUMENT's, which DeviceAuthentication
// signs, ISO/IEC 18013-5 section 9.1.3.4), alg and hash (the device
// signature's COSE alg and node's digest), deviceMac (a MAC in place of
// the signature).
function deviceResponseHere(cred, device, transcript, opts) {
  log.debug("Entering deviceResponseHere().");
  const o = opts || {};
  const Tag = mdocIssuer.Tag;
  const cbor = mdocIssuer.cbor;
  const nsBytes = cbor(new Map());
  const docType = o.docType || cred.docType;
  const auth = cbor(new Tag(24, cbor(["DeviceAuthentication", transcript,
    docType, new Tag(24, nsBytes)])));
  const protectedBytes = cbor(new Map([[1, o.alg || -7]]));
  const sig = nodeCrypto.sign(o.hash || "sha256",
    coseSigStructure(protectedBytes, auth),
    { key: device.privateKey, dsaEncoding: "ieee-p1363" });
  const deviceAuth = o.deviceMac ? new Map([["deviceMac",
    [cbor(new Map([[1, 5]])), new Map(), null, Buffer.alloc(32, 7)]]]) :
    new Map([["deviceSignature", [protectedBytes, new Map(), null, sig]]]);
  const doc = new Map([
    ["docType", docType],
    ["issuerSigned", new Map([
      ["nameSpaces", new Map([[mdocIssuer.NS, cred.items.map(function (it) {
        return new Tag(24, it.bytes);
      })]])],
      ["issuerAuth", cred.issuerAuth]])],
    ["deviceSigned", new Map([
      ["nameSpaces", new Tag(24, nsBytes)],
      ["deviceAuth", deviceAuth]])]
  ]);
  log.debug("Leaving deviceResponseHere().");
  return b64u(cbor(new Map([["version", "1.0"], ["documents", [doc]],
                            ["status", 0]])));
}

// ---------------------------------------------------------------------------
// The Digital Credentials API (OpenID4VP 1.0 Appendix A).
// ---------------------------------------------------------------------------
const ORIGIN = "https://verifier.example";

async function dcApi(env) {
  log.debug("Entering dcApi().");
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"]] }] });
  const nonce = verifier.randomToken();
  const clientId = verifier.clientIdFor("x509_hash", env.identity);

  // The request: unsigned and signed.
  const unsignedClaims = verifier.requestObjectClaims({
    responseMode: "dc_api", nonce: nonce, dcql: dcql, state: "ignored",
    responseUri: "https://ignored.example/r" });
  ["client_id", "response_uri", "state", "iat", "exp", "aud",
   "expected_origins"].forEach(function (k) {
    ok(!(k in unsignedClaims), "an unsigned DC API request has no " + k);
  });
  eq([unsignedClaims.response_type, unsignedClaims.response_mode,
      unsignedClaims.nonce], ["vp_token", "dc_api", nonce]);
  const unsignedReq = await verifier.dcApiRequest({ signed: false,
    claims: unsignedClaims, origin: ORIGIN });
  eq(unsignedReq.protocol, "openid4vp-v1-unsigned");
  eq(Object.keys(unsignedReq).sort(), ["data", "protocol"],
     "the request is exactly { protocol, data }");
  eq(unsignedReq.data.dcql_query, dcql);
  throws(function () {
    verifier.requestObjectClaims({ clientId: clientId,
      responseMode: "dc_api", nonce: nonce, dcql: dcql });
  }, /expected_origins/, "a signed DC API request needs expected_origins");
  const signedClaims = verifier.requestObjectClaims({ clientId: clientId,
    responseMode: "dc_api.jwt", nonce: nonce, dcql: dcql,
    expectedOrigins: [ORIGIN], encryptionJwk: env.enc.publicJwk });
  eq(signedClaims.expected_origins, [ORIGIN]);
  ok(!("response_uri" in signedClaims) && !("state" in signedClaims),
     "a signed DC API request has no response_uri or state either");
  eq(signedClaims.client_metadata.jwks.keys[0].kid, env.enc.publicJwk.kid);
  const signedReq = await verifier.dcApiRequest({ signed: true,
    claims: signedClaims, identity: env.identity, origin: ORIGIN });
  eq(signedReq.protocol, "openid4vp-v1-signed");
  eq(Object.keys(signedReq.data), ["request"]);
  const sr = decodeCompact(signedReq.data.request);
  eq(sr.header.x5c, env.identity.x5c);
  eq(sr.payload.expected_origins, [ORIGIN]);
  ok(nodeVerifyJws(signedReq.data.request, env.identity.publicJwk),
     "the signed DC API request verifies with the leaf key");
  await rejects(function () {
    return verifier.dcApiRequest({ signed: true, claims: signedClaims,
      identity: env.identity, origin: "https://elsewhere.example" });
  }, /expected_origins/, "an origin outside expected_origins is refused");
  // #471, E6: an Origin has no trailing slash (OpenID4VP 1.0 section 2;
  // the HTML Standard's serialization, window.location.origin).
  await rejects(function () {
    return verifier.dcApiRequest({ signed: true, claims: signedClaims,
      identity: env.identity, origin: ORIGIN + "/" });
  }, /is not an origin/, "an origin with a trailing slash is a URL");
  // #471 E3c: openid4vp-v1-multisigned (Appendix A.3.2.2). One payload,
  // one signature per Client Identifier, client_id only in each protected
  // header. jose's generalVerify checks each signature against its own key.
  await rejects(function () {
    return verifier.dcApiRequest({ multisigned: true, claims: signedClaims,
      signers: [{ identity: env.identity, clientId: clientId }] });
  }, /at least two signers/);
  const didKey = verifier.makeRequestKey();
  const didCid = verifier.clientIdFor("decentralized_identifier", didKey,
                                      { didMethod: "jwk" });
  const info = [{ format: "jwt", data: "eyJhbGciOiJFUzI1NiJ9.e30.sig" }];
  const multi = await verifier.dcApiRequest({ multisigned: true,
    claims: signedClaims, origin: ORIGIN, signers: [
      { identity: env.identity, clientId: clientId },
      { identity: didKey, clientId: didCid, verifierInfo: info }] });
  eq([multi.protocol, Object.keys(multi.data.request).sort()],
     ["openid4vp-v1-multisigned", ["payload", "signatures"]]);
  const mPayload = JSON.parse(Buffer.from(multi.data.request.payload,
                                          "base64url"));
  ok(!("client_id" in mPayload) && !("iss" in mPayload) &&
     !("verifier_info" in mPayload) && mPayload.nonce === nonce &&
     mPayload.expected_origins[0] === ORIGIN, "E3c: the payload carries " +
     "everything but client_id, iss and verifier_info");
  const headers = multi.data.request.signatures.map(function (sig) {
    return JSON.parse(Buffer.from(sig.protected, "base64url"));
  });
  eq(headers.map(function (h) {
    return h.client_id;
  }), [clientId, didCid], "E3c: each header names its client_id");
  eq([headers[0].x5c, headers[1].verifier_info], [env.identity.x5c, info],
     "E3c: x5c and verifier_info where they belong");
  const jose = await import("jose");
  const keys = [await jose.importJWK(Object.assign({},
    env.identity.publicJwk, { alg: "ES256" })),
                await jose.importJWK(Object.assign({}, didKey.publicJwk,
    { alg: "ES256" }))];
  for (let k = 0; k < 2; k++) {
    const one = { payload: multi.data.request.payload,
                  signatures: [multi.data.request.signatures[k]] };
    const v = await jose.generalVerify(one, keys[k]);
    eq(v.protectedHeader.client_id, k === 0 ? clientId : didCid,
       "E3c: jose verifies signature " + k + " with its own key");
  }
  await rejects(function () {
    return verifier.dcApiRequest({ claims: verifier.requestObjectClaims({
      clientId: clientId, responseUri: "https://v.example/r", nonce: nonce,
      dcql: dcql }) });
  }, /dc_api/, "a direct_post request is not a DC API request");

  // dc+sd-jwt over dc_api (unsigned) and dc_api.jwt (signed).
  const issuer = makeIssuer();
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return issuer.docs[url] ? Promise.resolve(issuer.docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const holder = ecPair();
  const cred = issueSdJwt(issuer, holder.publicJwk);
  const unsignedSession = { nonce: nonce, responseMode: "dc_api",
    dcql: dcql, origin: ORIGIN };
  const pres = function pres(aud) {
    log.debug("Entering pres().");
    log.debug("Leaving pres().");
    return presentSdJwt(cred.jwt, [cred.d.given_name],
                        { aud: aud, nonce: nonce, key: holder });
  };
  let r = await run({ fields: { vp_token: { pid: [pres("origin:" +
    ORIGIN)] } }, session: unsignedSession, fetchJson: fetchJson });
  allPass(r, "dc+sd-jwt over dc_api");
  eq(checkById(r, "response.state").status, "skip",
     "state is a skip over the DC API");
  eq(checkById(r, "response.origin").status, "pass");
  eq(checkById(r, "pid[0].kb.aud").status, "pass");
  r = await run({ fields: JSON.stringify({ vp_token: { pid: [pres(
    "origin:" + ORIGIN)] } }), session: unsignedSession,
    fetchJson: fetchJson });
  allPass(r, "the DC API data object as JSON text");
  r = await run({ fields: { vp_token: { pid: [pres(ORIGIN)] } },
                  session: unsignedSession, fetchJson: fetchJson });
  failsOnly(r, ["pid[0].kb.aud"], "aud without the origin: prefix");
  // #471, E6: Appendix A.4's example audience has a slash; the Origin
  // (section 2, B.2.6.2's hashed "https://example.com") has none. The
  // audience stays exact, and the mismatch is explained.
  r = await run({ fields: { vp_token: { pid: [pres("origin:" + ORIGIN +
    "/")] } }, session: unsignedSession, fetchJson: fetchJson });
  failsOnly(r, ["pid[0].kb.aud"], "aud with a trailing slash");
  ok(/trailing slash, which is a URL and not an Origin.*section 2/.test(
    checkById(r, "pid[0].kb.aud").detail),
     checkById(r, "pid[0].kb.aud").detail);
  r = await run({ fields: { vp_token: { pid: [pres("origin:" + ORIGIN +
    "/")] } }, session: Object.assign({}, unsignedSession,
    { origin: ORIGIN + "/" }), fetchJson: fetchJson });
  failsOnly(r, ["response.origin"], "a session origin with a path");
  ok(/a URL with a path, not an Origin/.test(
    checkById(r, "response.origin").detail),
     checkById(r, "response.origin").detail);
  eq(checkById(r, "pid[0].kb.aud").detail.indexOf("trailing slash"), -1,
     "no slash hint where the audience is what the session says");
  r = await run({ fields: { vp_token: { pid: [pres("origin:" +
    ORIGIN)] } }, session: Object.assign({}, unsignedSession,
    { origin: undefined }), fetchJson: fetchJson });
  failsOnly(r, ["response.origin", "pid[0].kb.aud"],
            "no session origin: nothing to hold the audience to");
  const signedSession = { clientId: clientId, nonce: nonce,
    responseMode: "dc_api.jwt", dcql: dcql, origin: ORIGIN,
    decryptionJwk: env.enc.privateJwk };
  const sealed = async function sealed(presentation) {
    log.debug("Entering sealed().");
    const out = await vp.encryptResponse({ fields: { vp_token: {
      pid: [presentation] } }, clientMetadata: signedClaims.client_metadata });
    log.debug("Leaving sealed().");
    return { response: out.jwe };
  };
  r = await run({ fields: await sealed(pres("origin:" + ORIGIN)),
                  session: signedSession, fetchJson: fetchJson });
  allPass(r, "dc+sd-jwt over dc_api.jwt with a signed request");
  eq(checkById(r, "response.decrypt").status, "pass");
  r = await run({ fields: await sealed(pres(clientId)),
                  session: signedSession, fetchJson: fetchJson });
  failsOnly(r, ["pid[0].kb.aud"], "aud = the client_id: under the DC API " +
            "the audience is the origin even for a signed request");
  r = await run({ fields: { vp_token: { pid: [pres("origin:" + ORIGIN)] } },
                  session: signedSession, fetchJson: fetchJson });
  failsOnly(r, ["response.mode"], "a plain vp_token under dc_api.jwt");

  // mso_mdoc with the OpenID4VPDCAPIHandover transcript.
  const auth = await mdocIssuer.authority("dc api");
  const device = ecPair();
  const mcred = issueMdocHere(auth, device.publicJwk,
                              { given_name: "Erika", family_name: "M" });
  const NS = mdocIssuer.NS;
  const mdql = verifier.buildDcql({ queries: [{ id: "mdl",
    format: "mso_mdoc", doctype: mdocIssuer.DOCTYPE,
    claims: [[NS, "given_name"]] }] });
  const mSession = { nonce: nonce, responseMode: "dc_api", dcql: mdql,
                     origin: ORIGIN, trustAnchors: [auth.iacaPem] };
  const plainDr = deviceResponseHere(mcred, device,
                                     dcTranscript(ORIGIN, nonce, null));
  r = await run({ fields: { vp_token: { mdl: [plainDr] } },
                  session: mSession });
  allPass(r, "mso_mdoc over dc_api");
  ok(/OpenID4VPDCAPIHandover/.test(checkById(r,
     "mdl[0].mdoc.device-signature").detail), "the DC API handover is named");
  r = await run({ fields: { vp_token: { mdl: [plainDr] } },
    session: Object.assign({}, mSession, { origin: "https://other.example" })
  });
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc, another origin");
  r = await run({ fields: { vp_token: { mdl: [plainDr] } },
                  session: Object.assign({}, mSession, { origin: "" }) });
  failsOnly(r, ["response.origin", "mdl[0].mdoc.device-signature"],
            "mdoc, no origin");
  const prefixed = deviceResponseHere(mcred, device,
    dcTranscript("origin:" + ORIGIN, nonce, null));
  r = await run({ fields: { vp_token: { mdl: [prefixed] } },
                  session: mSession });
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc, a transcript " +
            "with the origin: prefix (B.2.6.2 says it MUST NOT have it)");
  const redirectStyle = deviceResponseHere(mcred, device,
    mdocIssuer.transcript(clientId, nonce, null, "https://v.example/r"));
  r = await run({ fields: { vp_token: { mdl: [redirectStyle] } },
                  session: mSession });
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc, the " +
            "OpenID4VPHandover transcript where the DC API one belongs");
  const mSigned = Object.assign({}, mSession, { clientId: clientId,
    responseMode: "dc_api.jwt", decryptionJwk: env.enc.privateJwk });
  const encDr = deviceResponseHere(mcred, device,
    dcTranscript(ORIGIN, nonce, env.enc.publicJwk));
  const mSealed = await vp.encryptResponse({ fields: { vp_token: {
    mdl: [encDr] } }, clientMetadata: signedClaims.client_metadata });
  r = await run({ fields: { response: mSealed.jwe }, session: mSigned });
  allPass(r, "mso_mdoc over dc_api.jwt");
  const mSealedPlain = await vp.encryptResponse({ fields: { vp_token: {
    mdl: [plainDr] } }, clientMetadata: signedClaims.client_metadata });
  r = await run({ fields: { response: mSealedPlain.jwe },
                  session: mSigned });
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "mdoc under dc_api.jwt " +
            "signed over a transcript with no key thumbprint");
  log.info("PASS the Digital Credentials API: unsigned and signed " +
           "requests, origin: audiences, and the DC API mdoc handover.");
  log.debug("Leaving dcApi().");
}

// ---------------------------------------------------------------------------
// Status lists, built here with node's zlib and this file's own bit packing.
// ---------------------------------------------------------------------------

// draft-ietf-oauth-status-list section 4.1: entry 0 in the LEAST significant
// bits of byte 0. zlib DEFLATE, base64url.
function tokenStatusLst(values, bits) {
  log.debug("Entering tokenStatusLst().");
  const buf = Buffer.alloc(Math.ceil(values.length * bits / 8));
  values.forEach(function (v, i) {
    const bit = i * bits;
    buf[bit >> 3] |= v << (bit & 7);
  });
  log.debug("Leaving tokenStatusLst().");
  return b64u(zlib.deflateSync(buf));
}

// W3C Bitstring Status List v1.0 section 3.2: bit 0 the MOST significant
// bit of byte 0. GZIP, multibase base64url ("u"). 16 KiB, the spec's
// minimum.
function bitstringEncodedList(setBits, size, values) {
  log.debug("Entering bitstringEncodedList().");
  const buf = Buffer.alloc(16384);
  const width = size || 1;
  const put = function put(index, value) {
    log.debug("Entering put().");
    for (let j = 0; j < width; j++) {
      const k = index * width + j;
      if ((value >> (width - 1 - j)) & 1) buf[k >> 3] |= 0x80 >> (k & 7);
    }
    log.debug("Leaving put().");
  };
  (setBits || []).forEach(function (i) {
    put(i, 1);
  });
  Object.keys(values || {}).forEach(function (i) {
    put(Number(i), values[i]);
  });
  log.debug("Leaving bitstringEncodedList().");
  return "u" + b64u(zlib.gzipSync(buf));
}

function textFetcher(docs, seen) {
  log.debug("Entering textFetcher().");
  log.debug("Leaving textFetcher().");
  return function fetchText(url, opts) {
    log.debug("Entering fetchText(). " + url);
    if (seen) seen.push({ url: url, accept: (opts || {}).accept });
    if (!(url in docs)) {
      log.debug("Leaving fetchText(). Not found.");
      return Promise.reject(new Error("404 " + url));
    }
    log.debug("Leaving fetchText().");
    return Promise.resolve(docs[url]);
  };
}

async function tokenStatusLists(env) {
  log.debug("Entering tokenStatusLists().");
  const issuer = makeIssuer();
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return issuer.docs[url] ? Promise.resolve(issuer.docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const now = Math.floor(Date.now() / 1000);
  // idx: 0 1 2 3 4 5 6 7 — idx 3 is VALID only when read LSB first.
  const lst = tokenStatusLst([1, 1, 1, 0, 2, 1, 1, 3], 2);
  const URI = "https://issuer.example/statuslists/1";
  const listToken = function listToken(changes, signer) {
    log.debug("Entering listToken().");
    const c = changes || {};
    log.debug("Leaving listToken().");
    return nodeJws(Object.assign({ alg: "ES256", typ: "statuslist+jwt",
      kid: "iss-1" }, c.header || {}), Object.assign({ sub: URI,
      iat: now - 60, exp: now + 3600, ttl: 300,
      status_list: { bits: 2, lst: lst } }, c.payload || {}),
      signer || issuer.key);
  };
  const docs = {};
  docs[URI] = listToken();
  docs[URI + "/forged"] = listToken({ payload: { sub: URI + "/forged" } },
                                    ecPair());
  docs[URI + "/wrongsub"] = listToken();
  docs[URI + "/typ"] = listToken({ header: { typ: "JWT" },
                                   payload: { sub: URI + "/typ" } });
  docs[URI + "/expired"] = listToken({ payload: { sub: URI + "/expired",
    iat: now - 7200, exp: now - 3600 } });
  // A COSE_Sign1 in CWT tag 61 (RFC 8392 section 6), as BYTES, which
  // section 5.2 forbids, with no type and a signature that is not one: read
  // as a CWT and failed for each (cwtStatusLists() has the correct ones).
  docs[URI + "/cwt"] = new Uint8Array(mdocIssuer.cbor(new mdocIssuer.Tag(61,
    new mdocIssuer.Tag(18, [mdocIssuer.cbor(new Map([[1, -7]])), new Map(),
      mdocIssuer.cbor(new Map([[2, URI + "/cwt"]])),
      Buffer.alloc(64, 1)]))));
  // The same CWT read as hex TEXT is not a CWT: no "CWT recognised" for
  // what is merely text.
  docs[URI + "/hex"] = Buffer.from(docs[URI + "/cwt"]).toString("hex");
  docs[URI + "/html"] = { body: Buffer.from("<!DOCTYPE html><html><body>" +
    "<h1>Sign in</h1></body></html>"), contentType: "text/html" };
  docs[URI + "/binary"] = { body: Buffer.from([0xff, 0xfe, 0x00, 0x9c]),
    contentType: "application/octet-stream" };
  docs[URI + "/apptyp"] = listToken({ header: { typ:
    "application/statuslist+jwt" }, payload: { sub: URI + "/apptyp" } });
  docs[URI + "/uptyp"] = listToken({ header: { typ: "StatusList+JWT" },
    payload: { sub: URI + "/uptyp" } });
  const seen = [];
  const fetchText = textFetcher(docs, seen);
  const holder = ecPair();
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"]] }] });
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", dcql: dcql,
    responseUri: "https://verifier.example/response" };
  async function at(ref, opts) {
    log.debug("Entering at().");
    const o = opts || {};
    const cred = issueSdJwt(issuer, holder.publicJwk, ref === null ? {} :
      { payload: { status: { status_list: ref } } });
    const presentation = presentSdJwt(cred.jwt, [cred.d.given_name],
      { aud: clientId, nonce: session.nonce, key: holder });
    const r = await run({ fields: { vp_token: { pid: [presentation] } },
      session: session, fetchJson: fetchJson,
      fetchText: o.noFetch ? undefined : fetchText });
    log.debug("Leaving at().");
    return r;
  }
  let r = await at({ idx: 3, uri: URI });
  allPass(r, "Token Status List, VALID");
  eq([checkById(r, "pid[0].status").status,
      checkById(r, "pid[0].status.list").status,
      checkById(r, "status").status], ["pass", "pass", "pass"]);
  ok(/VALID/.test(checkById(r, "pid[0].status").detail));
  ok(/ttl 300s/.test(checkById(r, "pid[0].status.list").detail),
     "the ttl is reported: " + checkById(r, "pid[0].status.list").detail);
  eq(seen.length && seen[0].accept, "application/statuslist+jwt, " +
     "application/statuslist+cwt", "both of section 8.1's media types are " +
     "asked for, the CWT form being verified too (#471, E5)");
  eq(checkById(r, "pid[0].status.signer").status, "pass");
  ok(/the same key.*kid "iss-1"/.test(
    checkById(r, "pid[0].status.signer").detail),
     checkById(r, "pid[0].status.signer").detail);
  r = await at({ idx: 5, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "Token Status List, INVALID");
  ok(/INVALID.*revoked/.test(checkById(r, "pid[0].status").detail));
  r = await at({ idx: 4, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "Token Status List, SUSPENDED");
  ok(/SUSPENDED.*suspended/.test(checkById(r, "pid[0].status").detail));
  r = await at({ idx: 7, uri: URI });
  allPass(r, "an application-specific value is reported, not judged");
  eq(checkById(r, "pid[0].status").status, "skip");
  ok(/0x03, reserved as application-specific/.test(
    checkById(r, "pid[0].status").detail),
     checkById(r, "pid[0].status").detail);
  r = await at({ idx: 40, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "idx past the end of the list");
  r = await at({ idx: 3, uri: URI + "/forged" });
  failsOnly(r, ["pid[0].status.list", "status"],
            "a Status List Token signed by somebody else");
  eq(checkById(r, "pid[0].status").status, "skip",
     "a value from an unverified list is not relied on");
  eq(checkById(r, "pid[0].status.signer").status, "skip",
     "an unverified list's signer is linked to nothing");
  ok(/does NOT verify/.test(checkById(r, "pid[0].status.list").detail));
  r = await at({ idx: 3, uri: URI + "/wrongsub" });
  failsOnly(r, ["pid[0].status.list", "status"], "sub is not the uri");
  r = await at({ idx: 3, uri: URI + "/typ" });
  failsOnly(r, ["pid[0].status.list", "status"], "typ is not statuslist+jwt");
  r = await at({ idx: 3, uri: URI + "/expired" });
  failsOnly(r, ["pid[0].status.list", "status"], "an expired list");
  // A list that could not be fetched is a check NOT PERFORMED (#470 B3):
  // nothing fails, and the row says what could not be fetched.
  r = await at({ idx: 3, uri: URI + "/missing" });
  eq(failedIds(r), [], "a list that will not load: nothing fails");
  eq(checkById(r, "pid[0].status.list").status, "skip",
     "a list that will not load is a skip");
  ok(/could not fetch .*\/missing/.test(
    checkById(r, "pid[0].status.list").detail),
     checkById(r, "pid[0].status.list").detail);
  r = await at({ idx: 3, uri: URI + "/cwt" });
  failsOnly(r, ["pid[0].status.list", "status"],
            "a CWT in tag 61 with no type and a signature of 0x01s");
  ok(/CWT tag \(61\).*MUST NOT.*no type \(16\).*does NOT verify/.test(
    checkById(r, "pid[0].status.list").detail),
     checkById(r, "pid[0].status.list").detail);
  r = await at({ idx: 3, uri: URI + "/hex" });
  failsOnly(r, ["pid[0].status.list", "status"], "hex text is not a CWT");
  ok(/text that is not a compact JWS/.test(
    checkById(r, "pid[0].status.list").detail));
  ok(!/CWT form/.test(checkById(r, "pid[0].status.list").detail));
  r = await at({ idx: 3, uri: URI + "/html" });
  failsOnly(r, ["pid[0].status.list", "status"], "an HTML error page");
  ok(/an HTML page \(served as text\/html\)/.test(
    checkById(r, "pid[0].status.list").detail),
     checkById(r, "pid[0].status.list").detail);
  r = await at({ idx: 3, uri: URI + "/binary" });
  failsOnly(r, ["pid[0].status.list", "status"], "binary, not CBOR");
  ok(/4 bytes of binary data, and not a COSE_Sign1/.test(
    checkById(r, "pid[0].status.list").detail),
     checkById(r, "pid[0].status.list").detail);
  // RFC 7515 section 4.1.9: typ compares as a media type.
  r = await at({ idx: 3, uri: URI + "/apptyp" });
  allPass(r, "typ application/statuslist+jwt");
  r = await at({ idx: 3, uri: URI + "/uptyp" });
  allPass(r, "typ StatusList+JWT");
  ok(/RFC 7515 section 4\.1\.9/.test(
    checkById(r, "pid[0].status.list").detail));
  r = await at({ idx: 3, uri: URI }, { noFetch: true });
  allPass(r, "no fetchText");
  eq([checkById(r, "pid[0].status").status, checkById(r, "status").status],
     ["skip", "skip"]);
  ok(/no fetchText/.test(checkById(r, "pid[0].status").detail));
  r = await at(null);
  allPass(r, "no status at all");
  eq(checkById(r, "pid[0].status").status, "skip",
     "a credential with no status is a skip, not a pass");
  r = await at({ idx: -1, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "a malformed reference");

  // mso_mdoc: the reference is in the MSO, the list's key in its x5c.
  const auth = await mdocIssuer.authority("status");
  const mdocUri = "https://issuer.example/statuslists/mdoc";
  const x5cList = function x5cList(signerKey) {
    log.debug("Entering x5cList().");
    const input = b64u(JSON.stringify({ alg: "ES256", typ: "statuslist+jwt",
      x5c: [Buffer.from(auth.dsDer).toString("base64")] })) + "." +
      b64u(JSON.stringify({ sub: mdocUri, iat: now, exp: now + 600,
        status_list: { bits: 1, lst: b64u(zlib.deflateSync(
          Buffer.from([0x02]))) } }));
    log.debug("Leaving x5cList().");
    return input + "." + b64u(nodeCrypto.sign("sha256", Buffer.from(input),
      { key: signerKey, dsaEncoding: "ieee-p1363" }));
  };
  const mdocDocs = {};
  mdocDocs[mdocUri] = x5cList(auth.dsKey);
  mdocDocs[mdocUri + "/forged"] = x5cList(ecPair().privateKey);
  const device = ecPair();
  const nonce = verifier.randomToken();
  const NS = mdocIssuer.NS;
  const mSession = { nonce: nonce, responseMode: "dc_api", origin: ORIGIN,
    trustAnchors: [auth.iacaPem],
    dcql: verifier.buildDcql({ queries: [{ id: "mdl", format: "mso_mdoc",
      doctype: mdocIssuer.DOCTYPE, claims: [[NS, "given_name"]] }] }) };
  async function mdocAt(status) {
    log.debug("Entering mdocAt().");
    const cred = issueMdocHere(auth, device.publicJwk,
                               { given_name: "Erika" }, status);
    const dr = deviceResponseHere(cred, device,
                                  dcTranscript(ORIGIN, nonce, null));
    const res = await run({ fields: { vp_token: { mdl: [dr] } },
      session: mSession, fetchText: textFetcher(mdocDocs) });
    log.debug("Leaving mdocAt().");
    return res;
  }
  r = await mdocAt({ idx: 0, uri: mdocUri });
  allPass(r, "mdoc, VALID (bit 0 of 0x02)");
  eq(checkById(r, "mdl[0].status").status, "pass");
  eq(checkById(r, "mdl[0].status.signer").status, "pass");
  ok(/the same key.*the same x5c/.test(
    checkById(r, "mdl[0].status.signer").detail),
     checkById(r, "mdl[0].status.signer").detail);
  r = await mdocAt({ idx: 1, uri: mdocUri });
  failsOnly(r, ["mdl[0].status", "status"], "mdoc, INVALID (bit 1 of 0x02)");
  r = await mdocAt({ idx: 0, uri: mdocUri + "/forged" });
  failsOnly(r, ["mdl[0].status.list", "status"],
            "mdoc, a list not signed by the x5c's key");
  r = await mdocAt(null);
  eq(checkById(r, "mdl[0].status").status, "skip", "mdoc, no status");
  ok(/names no status/.test(checkById(r, "mdl[0].status").detail));
  // ISO/IEC 18013-5's identifier_list is a status mechanism, not the
  // absence of one.
  r = await mdocAt({ raw: { identifier_list: { id: Buffer.from([1, 2]),
    uri: "https://issuer.example/identifiers/1" } } });
  allPass(r, "mdoc, an identifier_list");
  eq(checkById(r, "mdl[0].status.identifier-list").status, "skip");
  ok(/identifier_list.*does not read/.test(
    checkById(r, "mdl[0].status.identifier-list").detail));
  ok(!checkById(r, "mdl[0].status") ||
     !/names no status/.test(checkById(r, "mdl[0].status").detail),
     "an identifier_list is not reported as no status");
  log.info("PASS the IETF Token Status List: VALID, INVALID, SUSPENDED, " +
           "and every defect of the list, for dc+sd-jwt and mso_mdoc.");
  log.debug("Leaving tokenStatusLists().");
}

// ---------------------------------------------------------------------------
// draft-ietf-oauth-status-list-21's own vectors: the two worked examples of
// sections 4.1 and 4.2 (16 one-bit and 12 two-bit entries) and Appendix C's
// one-bit and four-bit lists of 2^20 entries, each lst copied from the
// draft. node's zlib checks the draft's own claims about them first, so a
// transcription error says so; then each is served in a Status List Token
// signed here and read through the Verifier, entry by entry.
// ---------------------------------------------------------------------------
const TSL_C1_LST =
    "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAA" +
    "AAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpL" +
    "AAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAA" +
    "AACAZC8L2AEb";
const TSL_C3_LST =
    "eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li1EjoOQGabAgAAAAAA" +
    "AAAAAAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAADoxaEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAIIoCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
    "AAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAAAAjsA9xMBMA";

async function tokenStatusSpecVectors(env) {
  log.debug("Entering tokenStatusSpecVectors().");
  const inflated = function inflated(lst) {
    log.debug("Entering inflated().");
    log.debug("Leaving inflated().");
    return zlib.inflateSync(Buffer.from(lst, "base64url"));
  };
  // Section 4.1: "compressed array (hex): 78dadbb918000217015d", the bytes
  // 0xB9 0xA3; section 4.2 encodes them as "eNrbuRgAAhcBXQ".
  eq(Buffer.from("eNrbuRgAAhcBXQ", "base64url").toString("hex"),
     "78dadbb918000217015d", "section 4.1's compressed bytes");
  eq(Array.from(inflated("eNrbuRgAAhcBXQ")), [0xb9, 0xa3],
     "section 4.1's byte array");
  eq(Buffer.from("eNo76fITAAPfAgc", "base64url").toString("hex"),
     "78da3be9f2130003df0207", "section 4.1's two-bit compressed bytes");
  eq(Array.from(inflated("eNo76fITAAPfAgc")), [0xc9, 0x44, 0xf9],
     "section 4.1's two-bit byte array");
  eq(inflated(TSL_C1_LST).length, 131072, "Appendix C.1: 2^20 one-bit");
  eq(inflated(TSL_C3_LST).length, 524288, "Appendix C.3: 2^20 four-bit");

  const issuer = makeIssuer();
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return issuer.docs[url] ? Promise.resolve(issuer.docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const now = Math.floor(Date.now() / 1000);
  const BASE = "https://issuer.example/statuslists/draft/";
  const docs = {};
  const lists = { s41: [1, "eNrbuRgAAhcBXQ"], s42: [2, "eNo76fITAAPfAgc"],
                  c1: [1, TSL_C1_LST], c3: [4, TSL_C3_LST] };
  Object.keys(lists).forEach(function (name) {
    docs[BASE + name] = nodeJws({ alg: "ES256", typ: "statuslist+jwt",
      kid: "iss-1" }, { sub: BASE + name, iat: now - 60, exp: now + 3600,
      status_list: { bits: lists[name][0], lst: lists[name][1] } },
      issuer.key);
  });
  const holder = ecPair();
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", responseUri: "https://verifier.example/r",
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: VCT, claims: [["given_name"]] }] }) };
  async function entry(name, idx) {
    log.debug("Entering entry(). " + name + " " + idx);
    const cred = issueSdJwt(issuer, holder.publicJwk, { payload: { status:
      { status_list: { idx: idx, uri: BASE + name } } } });
    const r = await run({ fields: { vp_token: { pid: [presentSdJwt(cred.jwt,
      [cred.d.given_name], { aud: clientId, nonce: session.nonce,
        key: holder })] } }, session: session, fetchJson: fetchJson,
      fetchText: textFetcher(docs) });
    log.debug("Leaving entry().");
    return checkById(r, "pid[0].status");
  }
  // [list, idx, the draft's value, the row status, what the row says]
  const cases = [
    ["s41", 0, 1, "fail", /INVALID/], ["s41", 1, 0, "pass", /VALID/],
    ["s41", 3, 1, "fail", /INVALID/], ["s41", 6, 0, "pass", /VALID/],
    ["s41", 13, 1, "fail", /INVALID/], ["s41", 14, 0, "pass", /VALID/],
    ["s41", 15, 1, "fail", /INVALID/], ["s41", 16, null, "fail", /beyond/],
    ["s42", 0, 1, "fail", /INVALID/], ["s42", 1, 2, "fail", /SUSPENDED/],
    ["s42", 2, 0, "pass", /VALID/],
    ["s42", 3, 3, "skip", /0x03, reserved as application-specific/],
    ["s42", 9, 2, "fail", /SUSPENDED/],
    ["s42", 11, 3, "skip", /application-specific/],
    ["c1", 0, 1, "fail", /INVALID/], ["c1", 1993, 1, "fail", /INVALID/],
    ["c1", 1994, 0, "pass", /VALID/], ["c1", 1000345, 1, "fail", /INVALID/],
    ["c1", 1048575, 0, "pass", /VALID/],
    ["c1", 1048576, null, "fail", /beyond/],
    ["c3", 0, 1, "fail", /INVALID/], ["c3", 1993, 2, "fail", /SUSPENDED/],
    ["c3", 35460, 3, "skip", /0x03, reserved as application-specific/],
    ["c3", 459495, 4, "skip", /0x04, reserved for future registration/],
    ["c3", 923232, 8, "skip", /0x08, reserved for future registration/],
    ["c3", 1000345, 12, "skip", /0x0C, reserved as application-specific/],
    ["c3", 1030203, 13, "skip", /0x0D, reserved as application-specific/],
    ["c3", 1030205, 15, "skip", /0x0F, reserved as application-specific/],
    ["c3", 25460, 0, "pass", /VALID/]
  ];
  for (const c of cases) {
    const row = await entry(c[0], c[1]);
    const what = c[0] + "[" + c[1] + "]";
    eq(row.status, c[3], what + ": " + row.detail);
    ok(c[4].test(row.detail), what + ": " + row.detail);
    if (c[2] !== null) {
      ok(row.detail.indexOf(" is " + c[2] + " (") !== -1,
         what + " is " + c[2] + " in the draft: " + row.detail);
    }
  }
  log.info("PASS draft-ietf-oauth-status-list-21's own vectors: sections " +
           "4.1/4.2 and Appendix C.1 and C.3, " + cases.length + " entries.");
  log.debug("Leaving tokenStatusSpecVectors().");
}

// ---------------------------------------------------------------------------
// Who signed the Status List Token, and is that the credential's issuer?
// draft-ietf-oauth-status-list-21 section 11.3's cases, each built here:
// the same key (the same x5c, an x5t or x5t#S256 naming the credential's
// leaf, the credential's kid), the same web-based key resolution, a
// different key under the same CA with id-kp-oauthStatusSigning (section
// 10), and the cases that are NOT a link. Certificates are issued by
// x509.js; keys, signatures and thumbprints are node's.
// ---------------------------------------------------------------------------
// id-kp-oauthStatusSigning is "1.3.6.1.5.5.7.3.TBD" in the draft (section
// 14.9), so the test names an OID of its own, the way a PKI would.
const STATUS_EKU = "1.3.6.1.4.1.55555.7.3.1";

function pemB64(pem) {
  log.debug("Entering pemB64().");
  log.debug("Leaving pemB64().");
  return pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
}

async function testPki() {
  log.debug("Entering testPki().");
  const pair = function pair() {
    log.debug("Entering pair().");
    const k = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    log.debug("Leaving pair().");
    return { privateKey: k.privateKey,
      publicPem: k.publicKey.export({ type: "spki", format: "pem" }),
      privatePem: k.privateKey.export({ type: "pkcs8", format: "pem" }) };
  };
  const root = async function root(cn) {
    log.debug("Entering root(). " + cn);
    const key = pair();
    const cert = await x509.issueCertificate({ subject: "CN=" + cn,
      subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
      signatureAlg: "sha256-ecdsa",
      extensions: x509.defaultExtensions("root-ca") });
    log.debug("Leaving root().");
    return { key: key, b64: pemB64(cert.pem), pem: cert.pem };
  };
  const leaf = async function leaf(ca, cn, ekus, dnsName) {
    log.debug("Entering leaf(). " + cn);
    const key = pair();
    const ext = x509.defaultExtensions("tls-server");
    ext.keyUsage.usages = ["digitalSignature"];
    // SD-JWT VC section 2.5: the iss is bound to the end-entity
    // certificate by a dNSName (or URI) in its subjectAltName.
    ext.subjectAltName = dnsName ?
      { present: true, names: [{ kind: "dns", value: dnsName }] } :
      { present: false, names: [] };
    ext.extKeyUsage = { present: !!ekus, usages: ekus || [],
                        critical: false };
    const cert = await x509.issueCertificate({ subject: "CN=" + cn,
      subjectPublicKey: key.publicPem,
      issuer: { certificatePem: ca.pem, privateKeyPem: ca.key.privatePem,
                keyAlg: "ec-p256" },
      signatureAlg: "sha256-ecdsa", extensions: ext });
    log.debug("Leaving leaf().");
    return { key: key, b64: pemB64(cert.pem) };
  };
  const ca = await root("Status Test CA");
  const otherCa = await root("Somebody Else's CA");
  const out = { ca: ca, otherCa: otherCa,
    issuer: await leaf(ca, "Credential Issuer", null,
                       new URL(ISSUER).hostname),
    statusEku: await leaf(ca, "Status Issuer", [STATUS_EKU]),
    statusPlain: await leaf(ca, "Status Issuer Without EKU"),
    other: await leaf(otherCa, "Unrelated Status Issuer", [STATUS_EKU]) };
  log.debug("Leaving testPki().");
  return out;
}

async function statusSignerLinks(env) {
  log.debug("Entering statusSignerLinks().");
  const pki = await testPki();
  const issuer = makeIssuer();
  const second = ecPair();
  const statusKey = ecPair();
  issuer.docs["https://issuer.example/jwks"].keys.push(Object.assign(
    { kid: "iss-2", alg: "ES256", use: "sig" }, second.publicJwk));
  issuer.docs["https://status.example/.well-known/jwt-vc-issuer"] = {
    issuer: "https://status.example", jwks: { keys: [Object.assign(
      { kid: "st-1", alg: "ES256", use: "sig" }, statusKey.publicJwk)] } };
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return issuer.docs[url] ? Promise.resolve(issuer.docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const now = Math.floor(Date.now() / 1000);
  const BASE = "https://issuer.example/statuslists/link/";
  const leafDer = Buffer.from(pki.issuer.b64, "base64");
  const docs = {};
  const list = function list(name, header, signer, payload) {
    log.debug("Entering list(). " + name);
    docs[BASE + name] = nodeJws(Object.assign({ alg: "ES256",
      typ: "statuslist+jwt" }, header), Object.assign({ sub: BASE + name,
      iat: now - 60, exp: now + 3600,
      status_list: { bits: 1, lst: b64u(zlib.deflateSync(Buffer.from(
        [0x00]))) } }, payload || {}), signer);
    log.debug("Leaving list().");
  };
  // The credential's x5c carries the end-entity certificate only: HAIP 1.0
  // section 6.1.1 says the trust anchor MUST NOT be in it. The CA reaches
  // the Verifier as a trust anchor instead (#467 S3).
  const x5c = [pki.issuer.b64];
  list("eku", { x5c: [pki.statusEku.b64, pki.ca.b64] }, pki.statusEku.key);
  list("noeku", { x5c: [pki.statusPlain.b64, pki.ca.b64] },
       pki.statusPlain.key);
  list("other", { x5c: [pki.other.b64, pki.otherCa.b64] }, pki.other.key);
  list("samex5c", { x5c: x5c }, pki.issuer.key);
  list("x5ts256", { "x5t#S256": b64u(nodeCrypto.createHash("sha256")
    .update(leafDer).digest()) }, pki.issuer.key);
  list("x5t", { x5t: b64u(nodeCrypto.createHash("sha1").update(leafDer)
    .digest()) }, pki.issuer.key);
  list("x5tforged", { "x5t#S256": b64u(nodeCrypto.createHash("sha256")
    .update(leafDer).digest()) }, ecPair());
  // C10: an https iss whose metadata does not answer, signed with the
  // credential's own key — section 11.3's same-key case.
  list("fallback", {}, issuer.key, { iss: "https://nowhere.example" });
  list("samekid", { kid: "iss-1" }, issuer.key, { iss: ISSUER });
  list("samejwks", { kid: "iss-2" }, second, { iss: ISSUER });
  list("stranger", { kid: "st-1" }, statusKey,
       { iss: "https://status.example" });

  const holder = ecPair();
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", responseUri: "https://verifier.example/r",
    trustAnchors: [pki.ca.pem],
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: VCT, claims: [["given_name"]] }] }) };
  async function at(name, opts) {
    log.debug("Entering at(). " + name);
    const o = opts || {};
    const cred = issueSdJwt(issuer, holder.publicJwk, Object.assign({
      payload: { status: { status_list: { idx: 0, uri: BASE + name } } } },
      o.certified ? { header: { x5c: x5c }, signer: pki.issuer.key } : {}));
    const r = await run({ fields: { vp_token: { pid: [presentSdJwt(cred.jwt,
      [cred.d.given_name], { aud: clientId, nonce: session.nonce,
        key: holder })] } }, session: session, fetchJson: fetchJson,
      fetchText: textFetcher(docs), statusSigningEku: o.eku });
    log.debug("Leaving at().");
    return r;
  }
  const signer = function signer(r) {
    log.debug("Entering signer().");
    log.debug("Leaving signer().");
    return checkById(r, "pid[0].status.signer");
  };
  // [list, options, the signer row's status, what it says]
  const linked = [
    ["eku", { certified: true, eku: STATUS_EKU }, "pass",
     /the same chain.*Status Test CA.*1\.3\.6\.1\.4\.1\.55555\.7\.3\.1/],
    ["eku", { certified: true, eku: [STATUS_EKU, "1.2.3"] }, "pass",
     /the same chain/],
    ["eku", { certified: true }, "skip",
     /NOT linked.*does not carry id-kp-oauthStatusSigning.*TBD/],
    ["noeku", { certified: true, eku: STATUS_EKU }, "skip",
     /NOT linked.*Status Test CA.*does not carry/],
    ["other", { certified: true, eku: STATUS_EKU }, "skip",
     /NOT linked: the list verifies with the x5c leaf/],
    ["samex5c", { certified: true }, "pass", /the same key.*same x5c/],
    ["x5ts256", { certified: true }, "pass", /the same key.*x5t#S256/],
    ["x5t", { certified: true }, "pass", /the same key.*an x5t that/],
    ["fallback", {}, "pass", /the same key/],
    ["samekid", {}, "pass", /the same key.*kid "iss-1"/],
    ["samejwks", {}, "pass", /the same web-based key resolution/],
    ["stranger", {}, "skip", /NOT linked.*status\.example/]
  ];
  for (const c of linked) {
    const r = await at(c[0], c[1]);
    allPass(r, "signer link, " + c[0]);
    eq(checkById(r, "pid[0].status").status, "pass", c[0]);
    eq(signer(r).status, c[2], c[0] + ": " + signer(r).detail);
    ok(c[3].test(signer(r).detail), c[0] + ": " + signer(r).detail);
    if (c[2] !== "pass") {
      ok(/not shown to be the credential's issuer/.test(
        checkById(r, "pid[0].status").detail),
         "an unlinked signer is named on the value row too");
    }
  }
  let r = await at("fallback");
  ok(/the credential issuer's key.*its own key: .*nowhere\.example/.test(
    checkById(r, "pid[0].status.list").detail),
     "the fallback says why: " + checkById(r, "pid[0].status.list").detail);
  r = await at("x5tforged", { certified: true });
  failsOnly(r, ["pid[0].status.list", "status"],
            "an x5t#S256 naming the issuer's leaf, signed by another key");
  eq(signer(r).status, "skip");
  log.info("PASS the Status List Token's signer: the same key (x5c, x5t, " +
           "x5t#S256, kid), the same key resolution, the same CA with " +
           "id-kp-oauthStatusSigning, and the three ways of NOT being " +
           "linked.");
  log.debug("Leaving statusSignerLinks().");
}

async function bitstringStatusLists(env) {
  log.debug("Entering bitstringStatusLists().");
  const issuer = ecPair();
  const issuerDid = didJwk(issuer.publicJwk);
  const holder = ecPair();
  const holderDid = didJwk(holder.publicJwk);
  const now = Math.floor(Date.now() / 1000);
  const LIST = "https://issuer.example/bsl/";
  const listVc = function listVc(name, purpose, encodedList, signer,
                                  extra) {
    log.debug("Entering listVc().");
    const x = extra || {};
    const did = x.did || issuerDid;
    log.debug("Leaving listVc().");
    return nodeJws({ alg: "ES256", typ: "vc+jwt", kid: did + "#0" }, {
      iss: did, iat: now - 60, exp: now + 3600,
      vc: Object.assign({ "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: LIST + name, type: ["VerifiableCredential",
          "BitstringStatusListCredential"], issuer: did,
        credentialSubject: { id: LIST + name + "#list",
          type: "BitstringStatusList", statusPurpose: purpose,
          encodedList: encodedList } }, x.vc || {}) }, signer || issuer);
  };
  const docs = {};
  // Revoked: 0 and 42. Index 7 is NOT revoked, read MSB first.
  docs[LIST + "rev"] = listVc("rev", "revocation",
                              bitstringEncodedList([0, 42]));
  docs[LIST + "sus"] = listVc("sus", "suspension",
                              bitstringEncodedList([9]));
  docs[LIST + "msg"] = listVc("msg", "message",
                              bitstringEncodedList([], 2, { 3: 2 }));
  docs[LIST + "forged"] = listVc("forged", "revocation",
                                 bitstringEncodedList([]), ecPair());
  docs[LIST + "ref"] = listVc("ref", "refresh", bitstringEncodedList([4]));
  docs[LIST + "msg1"] = listVc("msg1", "message", bitstringEncodedList([5]));
  // Bitstring Status List v1.0 section 2.2: the list's issuer "MAY be
  // different" from the credential's.
  const otherIssuer = ecPair();
  docs[LIST + "elsewhere"] = listVc("elsewhere", "revocation",
    bitstringEncodedList([]), otherIssuer,
    { did: didJwk(otherIssuer.publicJwk) });
  // A VC-JWT whose JWT exp is in the future and whose credential's own
  // validUntil is past.
  docs[LIST + "lapsed"] = listVc("lapsed", "revocation",
    bitstringEncodedList([]), null, { vc: { validFrom:
      "2020-01-01T00:00:00Z", validUntil: "2021-01-01T00:00:00Z" } });
  docs[LIST + "notyet"] = listVc("notyet", "revocation",
    bitstringEncodedList([]), null, { vc: { validFrom:
      "2999-01-01T00:00:00Z" } });
  // The specification's own Example 3 encodedList: GZIP of 16 KiB of
  // zeros, the minimum list, 131,072 entries none of them set.
  const SPEC_ENCODED =
    "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3" +
    "AYbSVKsAQAAA";
  const specBits = zlib.gunzipSync(Buffer.from(SPEC_ENCODED.slice(1),
                                               "base64url"));
  eq(specBits.length, 16384, "Example 3's list is 16 KiB");
  ok(specBits.every(function (b) {
    return b === 0;
  }), "and no entry of it is set");
  docs[LIST + "spec"] = listVc("spec", "revocation", SPEC_ENCODED);
  docs[LIST + "html"] = { body: Buffer.from("<html><body>502 Bad Gateway" +
    "</body></html>"), contentType: "text/html; charset=utf-8" };
  const entry = function entry(name, purpose, index, extra) {
    log.debug("Entering entry().");
    log.debug("Leaving entry().");
    return Object.assign({ id: LIST + name + "#" + index,
      type: "BitstringStatusListEntry", statusPurpose: purpose,
      statusListIndex: String(index), statusListCredential: LIST + name },
      extra || {});
  };
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const dcql = verifier.buildDcql({ queries: [{ id: "w3c",
    format: "jwt_vc_json", types: ["VerifiableCredential"],
    claims: [["credentialSubject", "given_name"]] }] });
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", dcql: dcql };
  const seen = [];
  async function at(status) {
    log.debug("Entering at().");
    const vc = nodeJws({ alg: "ES256", typ: "JWT", kid: issuerDid + "#0" }, {
      iss: issuerDid, sub: holderDid, iat: now - 60, nbf: now - 60,
      exp: now + 86400, cnf: { jwk: holder.publicJwk },
      vc: { "@context": ["https://www.w3.org/ns/credentials/v2"],
            type: ["VerifiableCredential"], credentialStatus: status,
            credentialSubject: { id: holderDid, given_name: "Erika" } }
    }, issuer);
    const signed = await sdJwtVp.signVpJwt({ credential: vc,
      holderPrivateJwk: holder.privateJwk, holderId: holderDid,
      aud: clientId, nonce: session.nonce });
    const res = await run({ fields: { vp_token: { w3c: [signed.jwt] } },
      session: session, fetchText: textFetcher(docs, seen) });
    log.debug("Leaving at().");
    return res;
  }
  let r = await at([entry("rev", "revocation", 7),
                    entry("sus", "suspension", 7)]);
  allPass(r, "Bitstring Status List: neither revoked nor suspended");
  ["w3c[0].vc.status.revocation", "w3c[0].vc.status.revocation.list",
   "w3c[0].vc.status.suspension", "w3c[0].vc.status.suspension.list",
   "status"].forEach(function (id) {
    eq(checkById(r, id) && checkById(r, id).status, "pass", id);
  });
  r = await at([entry("rev", "revocation", 42),
                entry("sus", "suspension", 7)]);
  failsOnly(r, ["w3c[0].vc.status.revocation", "status"], "revoked");
  ok(/revoked/.test(checkById(r, "w3c[0].vc.status.revocation").detail));
  r = await at([entry("rev", "revocation", 0)]);
  failsOnly(r, ["w3c[0].vc.status.revocation", "status"], "index 0 " +
            "revoked (the most significant bit of byte 0)");
  r = await at([entry("rev", "revocation", 7),
                entry("sus", "suspension", 9)]);
  failsOnly(r, ["w3c[0].vc.status.suspension", "status"], "suspended");
  ok(/(^|, )application\/vc(, |;|$)/.test(seen[0].accept),
     "section 4: application/vc is asked for: " + seen[0].accept);
  // Section 2.1's Example 2, whose four messages are "0x0".."0x3"; the
  // entry here writes 0x2 as "0x02", the same status as a number.
  const fourMessages = [{ status: "0x0", message: "pending_review" },
    { status: "0x1", message: "accepted" },
    { status: "0x02", message: "rejected" },
    { status: "0x3", message: "undefined" }];
  r = await at(entry("msg", "message", 3, { statusSize: 2,
    statusMessage: fourMessages }));
  allPass(r, "a message entry");
  ok(/\(0x2\): "rejected"/.test(
    checkById(r, "w3c[0].vc.status.message").detail),
     checkById(r, "w3c[0].vc.status.message").detail);
  r = await at(entry("msg", "message", 3, { statusSize: 2,
    statusMessage: fourMessages.slice(0, 2) }));
  failsOnly(r, ["w3c[0].vc.status.message.entry", "status"],
            "statusMessage shorter than 2^statusSize");
  ok(/array of 4 element\(s\).*array of 2/.test(
    checkById(r, "w3c[0].vc.status.message.entry").detail));
  r = await at(entry("msg", "message", 3, { statusSize: 2 }));
  failsOnly(r, ["w3c[0].vc.status.message.entry", "status"],
            "statusSize 2 and no statusMessage");
  ok(/statusSize is 2 and there is no statusMessage.*MUST be present/.test(
    checkById(r, "w3c[0].vc.status.message.entry").detail));
  eq(checkById(r, "w3c[0].vc.status.message").status, "pass",
     "the value is still read and reported");
  r = await at(entry("msg1", "message", 5));
  allPass(r, "a one-bit message entry with no statusMessage");
  ok(/: "set" \(no statusMessage/.test(
    checkById(r, "w3c[0].vc.status.message").detail),
     checkById(r, "w3c[0].vc.status.message").detail);
  r = await at(entry("msg1", "message", 4));
  ok(/: "unset"/.test(checkById(r, "w3c[0].vc.status.message").detail));
  r = await at(entry("ref", "refresh", 4));
  allPass(r, "refresh set");
  eq(checkById(r, "w3c[0].vc.status.refresh").status, "pass");
  ok(/updated credential is available.*does not invalidate/.test(
    checkById(r, "w3c[0].vc.status.refresh").detail),
     checkById(r, "w3c[0].vc.status.refresh").detail);
  r = await at(entry("ref", "refresh", 3));
  ok(/no refresh is pending/.test(
    checkById(r, "w3c[0].vc.status.refresh").detail));
  r = await at(entry("elsewhere", "revocation", 7));
  allPass(r, "a list issued by somebody else (section 2.2: MAY)");
  ok(/is not the credential's issuer .*section 2\.2 allows/.test(
    checkById(r, "w3c[0].vc.status.revocation.list").detail),
     checkById(r, "w3c[0].vc.status.revocation.list").detail);
  r = await at(entry("lapsed", "revocation", 7));
  failsOnly(r, ["w3c[0].vc.status.revocation.list", "status"],
            "a VC-JWT list past its validUntil");
  ok(/validUntil/.test(
    checkById(r, "w3c[0].vc.status.revocation.list").detail),
     checkById(r, "w3c[0].vc.status.revocation.list").detail);
  r = await at(entry("notyet", "revocation", 7));
  failsOnly(r, ["w3c[0].vc.status.revocation.list", "status"],
            "a VC-JWT list before its validFrom");
  r = await at(entry("spec", "revocation", 94567));
  allPass(r, "Example 1's index 94567 in Example 3's list");
  ok(/entry 94567 of .* is 0: not revoked/.test(
    checkById(r, "w3c[0].vc.status.revocation").detail),
     checkById(r, "w3c[0].vc.status.revocation").detail);
  r = await at(entry("html", "revocation", 7));
  failsOnly(r, ["w3c[0].vc.status.revocation.list", "status"],
            "an HTML page in the list's place");
  ok(/an HTML page \(served as text\/html\)/.test(
    checkById(r, "w3c[0].vc.status.revocation.list").detail),
     checkById(r, "w3c[0].vc.status.revocation.list").detail);
  r = await at(entry("forged", "revocation", 7));
  failsOnly(r, ["w3c[0].vc.status.revocation.list", "status"],
            "a list signed by another key");
  r = await at(entry("sus", "revocation", 7));
  failsOnly(r, ["w3c[0].vc.status.revocation.list", "status"],
            "an entry whose purpose is not the list's");
  r = await at(entry("rev", "revocation", 200000));
  failsOnly(r, ["w3c[0].vc.status.revocation", "status"], "index too big");
  r = await at({ type: "SomethingElse2099", statusPurpose: "revocation" });
  allPass(r, "an unknown status type");
  eq(checkById(r, "w3c[0].vc.status.revocation").status, "skip");
  r = await at(undefined);
  eq(checkById(r, "w3c[0].vc.status").status, "skip", "no credentialStatus");
  log.info("PASS the W3C Bitstring Status List: revocation, suspension, " +
           "message, most-significant-bit first, and a forged list.");
  log.debug("Leaving bitstringStatusLists().");
}

// ---------------------------------------------------------------------------
// Data Integrity cryptosuites, signed here: JCS by this file's own
// canonicalizeJson(), RDFC-1.0 by jsonld with the contexts bbs2023.js
// ships, hashes and signatures by node.
// ---------------------------------------------------------------------------
const SUITE_KEYS = {
  "eddsa-rdfc-2022": ["ed25519"], "eddsa-jcs-2022": ["ed25519"],
  "ecdsa-rdfc-2019": ["P-256", "P-384"], "ecdsa-jcs-2019": ["P-384"]
};

function suiteKey(kind) {
  log.debug("Entering suiteKey(). " + kind);
  const pair = kind === "ed25519" ? nodeCrypto.generateKeyPairSync("ed25519")
    : nodeCrypto.generateKeyPairSync("ec", { namedCurve: kind });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  const did = didLib.jwkToDidKey(publicJwk);
  log.debug("Leaving suiteKey().");
  return { kind: kind, privateKey: pair.privateKey, publicJwk: publicJwk,
           did: did, vm: did + "#" + did.slice("did:key:".length) };
}

async function diSign(doc, suite, key, purpose, extra) {
  log.debug("Entering diSign(). " + suite);
  const proof = Object.assign({ type: "DataIntegrityProof",
    cryptosuite: suite, created: "2026-01-01T00:00:00Z",
    verificationMethod: key.vm, proofPurpose: purpose }, extra || {});
  // A JCS suite hashes the proof options exactly as received, so the
  // proof carries the @context it is signed with (the W3C vectors do); an
  // RDFC one expands its configuration under the document's @context
  // (VC Data Integrity, Verify Proof step 4). `extra.omitContext` signs
  // the non-conformant JCS shape: @context hashed, then left out.
  const jcsSuite = /-jcs-/.test(suite);
  if (jcsSuite && doc["@context"] && !(extra && extra.omitContext) &&
      !("@context" in proof)) {
    proof["@context"] = doc["@context"];
  }
  delete proof.omitContext;
  const config = Object.assign({ "@context": doc["@context"] }, proof);
  const unsecured = Object.assign({}, doc);
  delete unsecured.proof;
  const canon = async function canon(x) {
    log.debug("Entering canon().");
    if (/-jcs-/.test(suite)) {
      log.debug("Leaving canon(). JCS.");
      return canonicalizeJson(x);
    }
    log.debug("Leaving canon(). RDFC-1.0.");
    return jsonld.canonize(x, { algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader: bbs2023.documentLoader, safe: true });
  };
  const hashName = key.kind === "P-384" ? "sha384" : "sha256";
  const h = function h(text) {
    log.debug("Entering h().");
    log.debug("Leaving h().");
    return nodeCrypto.createHash(hashName).update(text).digest();
  };
  const data = Buffer.concat([h(await canon(config)),
                              h(await canon(unsecured))]);
  const sig = key.kind === "ed25519" ?
    nodeCrypto.sign(null, data, key.privateKey) :
    nodeCrypto.sign(hashName, data, { key: key.privateKey,
                                      dsaEncoding: "ieee-p1363" });
  proof.proofValue = "z" + didLib.base58Encode(new Uint8Array(sig));
  log.debug("Leaving diSign().");
  return Object.assign({}, doc, { proof: proof });
}

async function cryptosuites(env) {
  log.debug("Entering cryptosuites().");
  // The W3C's own test vector (vc-di-eddsa, Appendix B.3, eddsa-jcs-2022):
  // JCS loads no context, so it verifies offline. The two intermediate
  // hashes are the spec's, checked first so a transcription error says so.
  const pk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
  const ctx = ["https://www.w3.org/ns/credentials/v2",
               "https://www.w3.org/ns/credentials/examples/v2"];
  const vector = { "@context": ctx,
    id: "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    type: ["VerifiableCredential", "AlumniCredential"],
    name: "Alumni Credential",
    description: "A minimum viable example of an Alumni Credential.",
    issuer: "https://vc.example/issuers/5678",
    validFrom: "2023-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:abcdefgh",
                         alumniOf: "The School of Examples" } };
  const vectorProof = { type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022", created: "2023-02-24T23:36:38Z",
    verificationMethod: "did:key:" + pk + "#" + pk,
    proofPurpose: "assertionMethod", "@context": ctx };
  const hex = function hex(x) {
    log.debug("Entering hex().");
    log.debug("Leaving hex().");
    return nodeCrypto.createHash("sha256").update(canonicalizeJson(x))
      .digest("hex");
  };
  eq(hex(vector), "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03" +
     "abc92f19", "the spec's hash of the canonical credential");
  eq(hex(vectorProof), "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a" +
     "097cabe539a1db", "the spec's hash of the canonical proof options");
  const signedVector = Object.assign({}, vector, { proof: Object.assign({},
    vectorProof, { proofValue: "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1e" +
    "HXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX" }) });
  let v = await verifier.verifyDataIntegrity(signedVector,
                                             { purpose: "assertionMethod" });
  ok(v.valid, "the W3C eddsa-jcs-2022 vector verifies: " + v.reason);
  const tamperedVector = JSON.parse(JSON.stringify(signedVector));
  tamperedVector.credentialSubject.alumniOf = "Another School";
  v = await verifier.verifyDataIntegrity(tamperedVector);
  ok(!v.valid && !v.unsupported, "and fails once altered");
  v = await verifier.verifyDataIntegrity(signedVector,
                                         { purpose: "authentication" });
  ok(!v.valid && /proofPurpose/.test(v.reason),
     "an assertionMethod proof is not an authentication proof");

  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const nonce = verifier.randomToken();
  const dcql = verifier.buildDcql({ queries: [{ id: "ld", format: "ldp_vc",
    types: [["VerifiableCredential"]],
    claims: [["credentialSubject", "given_name"]] }] });
  const session = { clientId: clientId, nonce: nonce,
                    responseMode: "direct_post", dcql: dcql };
  let rounds = 0;
  for (const suite of Object.keys(SUITE_KEYS)) {
    for (const kind of SUITE_KEYS[suite]) {
      const what = suite + " (" + kind + ")";
      const issuerKey = suiteKey(kind);
      const holderKey = suiteKey(kind);
      const LIST = "https://issuer.example/ld/" + suite + "/" + kind;
      const listCred = await diSign({
        "@context": ["https://www.w3.org/ns/credentials/v2"], id: LIST,
        type: ["VerifiableCredential", "BitstringStatusListCredential"],
        issuer: issuerKey.did, validFrom: "2026-01-01T00:00:00Z",
        credentialSubject: { id: LIST + "#list", type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList: bitstringEncodedList([5]) } },
        suite, issuerKey, "assertionMethod");
      const docs = {};
      docs[LIST] = JSON.stringify(listCred);
      const vcFor = async function vcFor(index, signer) {
        log.debug("Entering vcFor().");
        const vc = await diSign({
          "@context": ["https://www.w3.org/ns/credentials/v2",
                       bbs2023.IDENTITY_CONTEXT_URL],
          type: ["VerifiableCredential", "IdentityCredential"],
          issuer: issuerKey.did, validFrom: "2026-01-01T00:00:00Z",
          credentialStatus: { id: LIST + "#" + index,
            type: "BitstringStatusListEntry", statusPurpose: "revocation",
            statusListIndex: String(index), statusListCredential: LIST },
          credentialSubject: { id: holderKey.did, given_name: "Erika" } },
          suite, signer || issuerKey, "assertionMethod");
        log.debug("Leaving vcFor().");
        return vc;
      };
      const vpFor = async function vpFor(vc, opts) {
        log.debug("Entering vpFor().");
        const o = opts || {};
        const out = await diSign({
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiablePresentation"], holder: holderKey.did,
          verifiableCredential: [vc] }, suite, o.signer || holderKey,
          "authentication", { challenge: o.challenge || nonce,
                              domain: clientId });
        log.debug("Leaving vpFor().");
        return out;
      };
      const send = async function send(element) {
        log.debug("Entering send().");
        log.debug("Leaving send().");
        return run({ fields: { vp_token: { ld: [element] } },
                     session: session, fetchText: textFetcher(docs) });
      };
      const goodVc = await vcFor(4);
      let r = await send(await vpFor(goodVc));
      allPass(r, what);
      ["ld[0].vp.proof", "ld[0].vc.proof", "ld[0].vp.binding",
       "ld[0].vc.validity", "ld[0].vc.status.revocation",
       "ld[0].vc.status.revocation.list", "ld[0].claims"].forEach(
        function (id) {
          eq(checkById(r, id) && checkById(r, id).status, "pass",
             what + ": " + id + " " + JSON.stringify(checkById(r, id)));
        });
      ok(checkById(r, "ld[0].vp.proof").detail.indexOf(suite) !== -1,
         "the suite is named");
      r = await send(await vpFor(await vcFor(5)));
      failsOnly(r, ["ld[0].vc.status.revocation", "status"],
                what + ", revoked in a " + suite + "-signed list");
      const altered = JSON.parse(JSON.stringify(goodVc));
      altered.credentialSubject.given_name = "Mallory";
      r = await send(await vpFor(altered));
      failsOnly(r, ["ld[0].vc.proof"], what + ", an altered credential " +
                "inside a correctly signed VP");
      r = await send(await vpFor(goodVc, { signer: Object.assign({},
        suiteKey(kind), { vm: holderKey.vm }) }));
      failsOnly(r, ["ld[0].vp.proof", "ld[0].vp.binding"],
                what + ", a VP signed by another key under the holder's " +
                "verificationMethod");
      r = await send(await vpFor(await vcFor(4, holderKey)));
      failsOnly(r, ["ld[0].vc.proof"], what + ", a credential signed by " +
                "a key that is not its issuer's");
      r = await send(await vpFor(goodVc, { challenge: "other" }));
      failsOnly(r, ["ld[0].vp.challenge"], what + ", another challenge");
      rounds++;
    }
  }
  eq(rounds, 5, "five suite/curve combinations");
  log.info("PASS Data Integrity: the W3C eddsa-jcs-2022 vector, and " +
           "eddsa-rdfc-2022, eddsa-jcs-2022, ecdsa-rdfc-2019 (P-256, " +
           "P-384) and ecdsa-jcs-2019 (P-384) on VPs, credentials and " +
           "status list credentials.");
  log.debug("Leaving cryptosuites().");
}

// ---------------------------------------------------------------------------
// #467: the security findings S1-S4. Every key and signature here is node's
// own crypto; the certificates are x509.js's encoder over node keys, and
// each chain is cross-checked with node's X509Certificate before the
// Verifier is asked about it.
// ---------------------------------------------------------------------------
function nodePemPair(kind) {
  log.debug("Entering nodePemPair(). " + kind);
  const pair = kind === "rsa" ?
    nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }) :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving nodePemPair().");
  return {
    kind: kind, privateKey: pair.privateKey,
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    keyAlg: kind === "rsa" ? "rsa-2048" : "ec-p256",
    sigAlg: kind === "rsa" ? "sha256-rsa" : "sha256-ecdsa"
  };
}

// One certificate. `issuer` is { cert, key } or absent (self-signed).
async function testCert(o) {
  log.debug("Entering testCert(). " + o.cn);
  const nowMs = Date.now();
  const ext = x509.defaultExtensions(o.profile);
  if (o.sans) {
    ext.subjectAltName = { present: true, critical: false, names: o.sans };
  }
  const signer = o.issuer ? o.issuer.key : o.key;
  const spec = {
    profile: o.profile, subject: "CN=" + o.cn + ",O=idptools test",
    subjectPublicKey: o.key.publicPem,
    signatureAlg: signer.sigAlg,
    notBefore: o.notBefore || new Date(nowMs - 3600000),
    notAfter: o.notAfter || new Date(nowMs + 30 * 86400000),
    extensions: ext
  };
  if (o.issuer) {
    spec.issuer = { certificatePem: o.issuer.cert.pem,
                    privateKeyPem: signer.privatePem,
                    keyAlg: signer.keyAlg };
  } else {
    spec.issuerPrivateKey = o.key.privatePem;
  }
  const issued = await x509.issueCertificate(spec);
  const node = new nodeCrypto.X509Certificate(issued.pem);
  log.debug("Leaving testCert().");
  return { pem: issued.pem, node: node, b64: node.raw.toString("base64") };
}

async function securityFindings(env) {
  log.debug("Entering securityFindings().");
  const now = Math.floor(Date.now() / 1000);
  const GOV = "https://gov.example";
  const noNet = function noNet(url) {
    log.debug("Entering noNet(). " + url);
    log.debug("Leaving noNet().");
    return Promise.reject(new Error("no network: " + url));
  };
  const sdDcql = verifier.buildDcql({ queries: [{ id: "p",
    format: "dc+sd-jwt", vct: VCT, requireBinding: false }] });
  const sdSession = { clientId: verifier.clientIdFor("x509_hash",
    env.identity), nonce: verifier.randomToken(), state: "s",
    responseMode: "direct_post", dcql: sdDcql };
  const sendSd = function sendSd(jwt, extra) {
    log.debug("Entering sendSd().");
    const x = extra || {};
    log.debug("Leaving sendSd().");
    return run({ fields: vp.formEncode({ vp_token: { p: [jwt + "~"] },
                 state: "s" }),
                 session: Object.assign({}, sdSession, x.session || {}),
                 fetchJson: x.fetchJson || noNet });
  };
  const sdPayload = function sdPayload(iss) {
    log.debug("Entering sdPayload().");
    log.debug("Leaving sdPayload().");
    return { iss: iss, vct: VCT, iat: now - 60, given_name: "X" };
  };

  // --- S1: a DID in kid never chooses the issuer. ----------------------
  // The forgery reproduced in the review (probe/forge.js): iss is an https
  // URL, the attacker signs with a key of its own and names it as a did:jwk
  // in kid, and the query does not require holder binding.
  const attacker = ecPair();
  const attackerDid = didJwk(attacker.publicJwk);
  const forged = nodeJws({ alg: "ES256", typ: "dc+sd-jwt",
                           kid: attackerDid + "#0" }, sdPayload(GOV),
                         attacker);
  // With no network the issuer's key cannot be had (#469 B3): an
  // incomplete verdict naming the URL — still never a pass.
  let r = await sendSd(forged);
  incompleteOnly(r, ["p[0].issuer.signature"], "S1: https iss, an " +
                 "attacker's did:jwk in kid, no network");
  ok(/could not fetch https:\/\/gov\.example\/\.well-known\/jwt-vc-issuer/
     .test(checkById(r, "p[0].issuer.signature").detail),
     "S1, no network: the row names the URL: " +
     checkById(r, "p[0].issuer.signature").detail);
  // With the real issuer's metadata on hand the forgery still fails, and
  // the row says the DID in kid was not used.
  const gov = ecPair();
  const govDocs = {};
  govDocs[GOV + "/.well-known/jwt-vc-issuer"] = { issuer: GOV,
    jwks: { keys: [Object.assign({ kid: "g1" }, gov.publicJwk)] } };
  const govFetch = function govFetch(url) {
    log.debug("Entering govFetch(). " + url);
    log.debug("Leaving govFetch().");
    return govDocs[url] ? Promise.resolve(govDocs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  r = await sendSd(forged, { fetchJson: govFetch });
  failsOnly(r, ["p[0].issuer.signature"], "S1: the forgery against the " +
            "issuer's real metadata");
  ok(/was not used/.test(checkById(r, "p[0].issuer.signature").detail),
     "S1: the row says the DID in kid was not used: " +
     checkById(r, "p[0].issuer.signature").detail);
  // The genuine credential from that issuer passes.
  r = await sendSd(nodeJws({ alg: "ES256", typ: "dc+sd-jwt", kid: "g1" },
                           sdPayload(GOV), gov), { fetchJson: govFetch });
  allPass(r, "S1: the issuer's own credential, from its metadata");
  // An iss that is neither a DID nor https, with a DID kid.
  r = await sendSd(nodeJws({ alg: "ES256", typ: "dc+sd-jwt",
                             kid: attackerDid + "#0" },
                           sdPayload("urn:example:gov"), attacker));
  incompleteOnly(r, ["p[0].issuer.signature"], "S1: a urn iss with a DID " +
                 "kid: no route leads to the issuer's key");
  ok(/only when iss IS that DID/.test(checkById(r,
     "p[0].issuer.signature").detail), "S1: the urn case says why");
  // A DID iss whose kid names ANOTHER DID.
  const real = ecPair();
  r = await sendSd(nodeJws({ alg: "ES256", typ: "dc+sd-jwt",
                             kid: attackerDid + "#0" },
                           sdPayload(didJwk(real.publicJwk)), attacker));
  failsOnly(r, ["p[0].issuer.signature"], "S1: a DID iss, another DID kid");
  // The legitimate DID case: iss IS the DID kid names.
  r = await sendSd(nodeJws({ alg: "ES256", typ: "dc+sd-jwt",
                             kid: attackerDid + "#0" },
                           sdPayload(attackerDid), attacker));
  allPass(r, "S1: iss is the DID kid names");

  // jwt_vc_json takes the same route. The VP JWT is built here with node.
  const vcDcql = verifier.buildDcql({ queries: [{ id: "w",
    format: "jwt_vc_json", types: ["VerifiableCredential"],
    requireBinding: false }] });
  const sendVc = async function sendVc(vcJwt, fetchJson) {
    log.debug("Entering sendVc().");
    const vpJwt = nodeJws({ alg: "ES256", typ: "JWT",
                            kid: attackerDid + "#0" },
      { iss: attackerDid, aud: sdSession.clientId, nonce: sdSession.nonce,
        iat: now, vp: { "@context": ["https://www.w3.org/2018/" +
          "credentials/v1"], type: ["VerifiablePresentation"],
          holder: attackerDid, verifiableCredential: [vcJwt] } }, attacker);
    log.debug("Leaving sendVc().");
    return run({ fields: vp.formEncode({ vp_token: { w: [vpJwt] },
                 state: "s" }),
                 session: Object.assign({}, sdSession, { dcql: vcDcql }),
                 fetchJson: fetchJson || noNet });
  };
  const vcBody = { "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential"], credentialSubject: { name: "X" } };
  r = await sendVc(nodeJws({ alg: "ES256", typ: "JWT",
                             kid: attackerDid + "#0" },
                           { iss: GOV, iat: now - 60, vc: vcBody },
                           attacker), govFetch);
  failsOnly(r, ["w[0].vc.signature"], "S1: jwt_vc_json, https iss and an " +
            "attacker's DID kid");
  r = await sendVc(nodeJws({ alg: "ES256", typ: "JWT", kid: "g1" },
                           { iss: GOV, iat: now - 60, vc: vcBody }, gov),
                   govFetch);
  allPass(r, "S1: jwt_vc_json from the issuer's metadata");

  // --- S2: a URL issuer's proof must be by a method it controls. --------
  // The W3C vc-di-eddsa Appendix B.3 example: issuer
  // https://vc.example/issuers/5678, proof by a did:key — the signature is
  // the spec's own and verifies, and nothing ties that did:key to the URL.
  const vecCtx = ["https://www.w3.org/ns/credentials/v2",
                  "https://www.w3.org/ns/credentials/examples/v2"];
  const vecPk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
  const w3cVector = { "@context": vecCtx,
    id: "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    type: ["VerifiableCredential", "AlumniCredential"],
    name: "Alumni Credential",
    description: "A minimum viable example of an Alumni Credential.",
    issuer: "https://vc.example/issuers/5678",
    validFrom: "2023-01-01T00:00:00Z",
    credentialSubject: { id: "did:example:abcdefgh",
                         alumniOf: "The School of Examples" },
    proof: { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022",
      created: "2023-02-24T23:36:38Z",
      verificationMethod: "did:key:" + vecPk + "#" + vecPk,
      proofPurpose: "assertionMethod", "@context": vecCtx,
      proofValue: "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93F" +
        "CzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX" } };
  const ldDcql = verifier.buildDcql({ queries: [{ id: "u",
    format: "ldp_vc", types: [["VerifiableCredential"]],
    requireBinding: false }] });
  const UNI = "https://university.example";
  const uniKey = suiteKey("P-384");
  const uniDid = "did:web:university.example";
  const uniDocs = {};
  uniDocs[UNI + "/.well-known/did.json"] = {
    "@context": ["https://www.w3.org/ns/did/v1"], id: uniDid,
    verificationMethod: [{ id: uniDid + "#k1", type: "JsonWebKey2020",
      controller: uniDid, publicKeyJwk: uniKey.publicJwk }],
    assertionMethod: [uniDid + "#k1"] };
  const uniFetch = function uniFetch(url) {
    log.debug("Entering uniFetch(). " + url);
    log.debug("Leaving uniFetch().");
    return uniDocs[url] ? Promise.resolve(uniDocs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const uniSigner = Object.assign({}, uniKey, { vm: uniDid + "#k1" });
  const listDocs = {};
  const sendLd = function sendLd(cred) {
    log.debug("Entering sendLd().");
    log.debug("Leaving sendLd().");
    return run({ fields: { vp_token: { u: [cred] }, state: "s" },
                 session: Object.assign({}, sdSession, { dcql: ldDcql }),
                 fetchJson: uniFetch, fetchText: textFetcher(listDocs) });
  };
  r = await sendLd(w3cVector);
  failsOnly(r, ["u[0].vc.proof"], "S2: the W3C example, a URL issuer and " +
            "a did:key proof");
  ok(/not authorised by the issuer/.test(checkById(r, "u[0].vc.proof")
     .detail), "S2: the row names the reason");
  const uniCred = function uniCred(issuer, extra) {
    log.debug("Entering uniCred().");
    log.debug("Leaving uniCred().");
    return Object.assign({ "@context": ["https://www.w3.org/ns/" +
      "credentials/v2"], type: ["VerifiableCredential"], issuer: issuer,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { name: "Erika" } }, extra || {});
  };
  r = await sendLd(await diSign(uniCred(UNI), "ecdsa-jcs-2019", uniSigner,
                                "assertionMethod"));
  allPass(r, "S2: a URL issuer, proof by its own did:web");
  r = await sendLd(await diSign(uniCred(UNI), "ecdsa-jcs-2019", uniKey,
                                "assertionMethod"));
  failsOnly(r, ["u[0].vc.proof"], "S2: a URL issuer, proof by a did:key");
  r = await sendLd(await diSign(uniCred(UNI + "/registrar"),
                                "ecdsa-jcs-2019", uniSigner,
                                "assertionMethod"));
  failsOnly(r, ["u[0].vc.proof"], "S2: an issuer path the did:web's " +
            "document is not under");
  r = await sendLd(await diSign(uniCred("https://evil.example"),
                                "ecdsa-jcs-2019", uniSigner,
                                "assertionMethod"));
  failsOnly(r, ["u[0].vc.proof"], "S2: another origin's did:web");
  // A status list credential obeys the same rule.
  const LISTS = UNI + "/lists/";
  const listCred = async function listCred(name, signer) {
    log.debug("Entering listCred().");
    const out = await diSign({ "@context": ["https://www.w3.org/ns/" +
      "credentials/v2"], id: LISTS + name,
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: UNI, validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: LISTS + name + "#list",
        type: "BitstringStatusList", statusPurpose: "revocation",
        encodedList: bitstringEncodedList([]) } },
      "ecdsa-jcs-2019", signer, "assertionMethod");
    log.debug("Leaving listCred().");
    return JSON.stringify(out);
  };
  listDocs[LISTS + "own"] = await listCred("own", uniSigner);
  listDocs[LISTS + "foreign"] = await listCred("foreign", uniKey);
  const withStatus = async function withStatus(name) {
    log.debug("Entering withStatus().");
    log.debug("Leaving withStatus().");
    return diSign(uniCred(UNI, { credentialStatus: { id: LISTS + name +
      "#3", type: "BitstringStatusListEntry", statusPurpose: "revocation",
      statusListIndex: "3", statusListCredential: LISTS + name } }),
      "ecdsa-jcs-2019", uniSigner, "assertionMethod");
  };
  r = await sendLd(await withStatus("own"));
  allPass(r, "S2: a status list credential signed by its URL issuer's " +
          "did:web");
  r = await sendLd(await withStatus("foreign"));
  failsOnly(r, ["u[0].vc.status.revocation.list", "status"], "S2: a status " +
            "list credential with a URL issuer and a did:key proof");
  ok(/not authorised by the issuer/.test(checkById(r,
     "u[0].vc.status.revocation.list").detail), "S2: the list row says why");

  // --- S4: an unsupported cryptosuite is not a pass. --------------------
  // (It was ecdsa-sd-2023 until #476 made that suite verifiable; a name no
  // registry has keeps the case about an UNSUPPORTED suite.)
  const sdSuite = await diSign(uniCred(UNI), "ecdsa-jcs-2019", uniSigner,
                               "assertionMethod");
  sdSuite.proof.cryptosuite = "example-unsupported-2099";
  r = await sendLd(sdSuite);
  eq(failedIds(r), [], "S4: an unsupported cryptosuite fails nothing");
  eq([r.verdict, r.ok, r.incomplete], ["incomplete", false, 1],
     "S4: an unsupported cryptosuite leaves the verdict incomplete");
  ok(checkById(r, "u[0].vc.proof").essential &&
     checkById(r, "u[0].vc.proof").status === "skip",
     "S4: the issuer proof is an essential skip");

  // --- S3 (and S4): an x5c chain is reported, never trusted on sight. ----
  const rootKey = nodePemPair("rsa");
  const interKey = nodePemPair("ec");
  const leafKey = nodePemPair("ec");
  const root = await testCert({ profile: "root-ca", cn: "Test Root",
                                key: rootKey });
  const inter = await testCert({ profile: "issuing-ca", cn: "Test Issuing",
    key: interKey, issuer: { cert: root, key: rootKey } });
  const govSans = [{ kind: "dns", value: "gov.example" }];
  const leaf = await testCert({ profile: "tls-server", cn: "gov.example",
    key: leafKey, issuer: { cert: inter, key: interKey }, sans: govSans });
  ok(leaf.node.verify(inter.node.publicKey) &&
     inter.node.verify(root.node.publicKey) &&
     root.node.verify(root.node.publicKey), "node: the chain is sound");
  const x5cJwt = function x5cJwt(chain, iss, signer) {
    log.debug("Entering x5cJwt().");
    log.debug("Leaving x5cJwt().");
    return nodeJws({ alg: "ES256", typ: "dc+sd-jwt",
                     x5c: chain.map(function (c) {
                       return c.b64;
                     }) }, sdPayload(iss), { privateKey:
                     (signer || leafKey).privateKey });
  };
  const anchors = { session: { trustAnchors: [root.pem] } };
  const trustOf = function trustOf(res) {
    log.debug("Entering trustOf().");
    log.debug("Leaving trustOf().");
    return checkById(res, "p[0].issuer.trust");
  };
  // Unanchored: nothing fails, the trust row is an essential skip, and the
  // verdict is incomplete.
  r = await sendSd(x5cJwt([leaf, inter], GOV));
  eq(failedIds(r), [], "S3: a sound chain, unanchored, fails nothing");
  eq(checkById(r, "p[0].issuer.signature").status, "pass",
     "S3: the signature row still says the JWT verifies with the leaf");
  eq([trustOf(r).status, trustOf(r).essential], ["skip", true],
     "S3: with no anchor the trust row is an essential skip");
  eq([r.verdict, r.ok, r.incomplete], ["incomplete", false, 1],
     "S4: an unanchored x5c is an incomplete verdict, not a pass");
  ok(/NOT anchored/.test(trustOf(r).detail) &&
     /each certificate is signed by the next/.test(trustOf(r).detail),
     "S3: the unanchored row reports the chain: " + trustOf(r).detail);
  // The iss binding is a row of its own (SD-JWT VC -27 section 2.5).
  ok(checkById(r, "p[0].issuer.iss").status === "pass" &&
     /bound to the end-entity certificate by the dNSName/.test(
       checkById(r, "p[0].issuer.iss").detail),
     "S3: a bound iss is a pass on issuer.iss: " +
     JSON.stringify(checkById(r, "p[0].issuer.iss")));
  // The same chain, anchored at the supplied root (an RSA root over an EC
  // chain, so both signature families are checked).
  r = await sendSd(x5cJwt([leaf, inter], GOV), anchors);
  allPass(r, "S3: a sound chain anchored at a supplied root");
  ok(/anchored at the supplied trust anchor "Test Root"/.test(
     trustOf(r).detail), trustOf(r).detail);
  // The anchor included in x5c: reported (HAIP 1.0 section 6.1.1).
  r = await sendSd(x5cJwt([leaf, inter, root], GOV));
  eq(trustOf(r).status, "skip", "S3: an included anchor is not trusted " +
     "because it is there");
  // Reported on a row of its own, never a failure (rcbj, 2026-11-17).
  const included = checkById(r, "p[0].issuer.anchor-included");
  ok(included && included.status === "skip" && !included.essential &&
     /INCLUDED in x5c.*HAIP 1\.0 section 6\.1\.1/.test(included.detail),
     "S3: the included anchor is reported: " + JSON.stringify(included));
  r = await sendSd(x5cJwt([leaf, inter, root], GOV), anchors);
  allPass(r, "S3: an included anchor that IS a supplied anchor");
  ok(checkById(r, "p[0].issuer.anchor-included").status === "skip",
     "S3: and it is still reported");
  // A self-signed leaf.
  const selfKey = nodePemPair("ec");
  const selfLeaf = await testCert({ profile: "tls-server",
    cn: "gov.example", key: selfKey, sans: govSans });
  ok(selfLeaf.node.verify(selfLeaf.node.publicKey), "node: self-signed");
  r = await sendSd(x5cJwt([selfLeaf], GOV, selfKey));
  eq(trustOf(r).status, "skip", "S3: a self-signed leaf, no anchors");
  const selfRow = checkById(r, "p[0].issuer.self-signed");
  ok(selfRow && selfRow.status === "skip" && !selfRow.essential &&
     /SELF-SIGNED.*HAIP 1\.0 section 6\.1\.1/.test(selfRow.detail),
     "S3: a self-signed signer is reported: " + JSON.stringify(selfRow));
  eq(checkById(r, "p[0].issuer.signature").status, "pass",
     "S3: and the signature itself still verifies");
  r = await sendSd(x5cJwt([selfLeaf], GOV, selfKey), anchors);
  failsOnly(r, ["p[0].issuer.trust"], "S3: a self-signed leaf against a " +
            "supplied anchor");
  ok(/none of the 1 supplied trust anchor/.test(trustOf(r).detail),
     trustOf(r).detail);
  // An expired leaf.
  const oldLeaf = await testCert({ profile: "tls-server", cn: "gov.example",
    key: leafKey, issuer: { cert: inter, key: interKey }, sans: govSans,
    notBefore: new Date(Date.now() - 3 * 86400000),
    notAfter: new Date(Date.now() - 86400000) });
  r = await sendSd(x5cJwt([oldLeaf, inter], GOV), anchors);
  failsOnly(r, ["p[0].issuer.trust"], "S3: an expired leaf");
  ok(/EXPIRED/.test(trustOf(r).detail), trustOf(r).detail);
  // A broken link: an intermediate with the right NAME and another key.
  const imposterKey = nodePemPair("ec");
  const imposter = await testCert({ profile: "issuing-ca",
    cn: "Test Issuing", key: imposterKey,
    issuer: { cert: root, key: rootKey } });
  ok(!leaf.node.verify(imposter.node.publicKey) &&
     leaf.node.issuer === imposter.node.subject, "node: the names match " +
     "and the signature does not");
  r = await sendSd(x5cJwt([leaf, imposter], GOV), anchors);
  failsOnly(r, ["p[0].issuer.trust"], "S3: a broken link");
  ok(/BROKEN/.test(trustOf(r).detail), trustOf(r).detail);
  r = await sendSd(x5cJwt([leaf, imposter], GOV));
  failsOnly(r, ["p[0].issuer.trust"], "S3: a broken link fails even " +
            "with no anchors");
  // iss not in the end-entity certificate's SAN. SD-JWT VC -27 section
  // 2.5: a recipient MAY reject it, and rcbj's rule is that the debugger
  // REPORTS it and never fails because of it: a SKIP that is not
  // essential, saying iss is unauthenticated and the issuer is the
  // certificate's subject. The chain itself is still trusted.
  r = await sendSd(x5cJwt([leaf, inter], "https://other.example"),
                   anchors);
  eq(failedIds(r), [], "S3: an unbound iss fails nothing");
  eq(trustOf(r).status, "pass", "S3: the chain is still anchored");
  const unbound = checkById(r, "p[0].issuer.iss");
  ok(unbound && unbound.status === "skip" && !unbound.essential &&
     /NOT bound.*NOT authenticated.*issuer is the certificate's subject.*SHOULD NOT include an iss claim/
       .test(unbound.detail), "S3: the unbound iss row: " +
     JSON.stringify(unbound));
  eq(r.verdict, "pass", "S3: an unbound iss does not change the verdict");
  // The configured mapping section 2.5 allows: by the leaf's SHA-256, and
  // by its common name. Each makes the binding a pass.
  const leafHash = nodeCrypto.createHash("sha256")
    .update(Buffer.from(leaf.b64, "base64")).digest("hex");
  r = await sendSd(x5cJwt([leaf, inter], "https://other.example"),
                   { session: Object.assign({}, anchors.session, {
                     issuerBindings: [{ iss: "https://other.example",
                                        sha256: leafHash }] }) });
  ok(checkById(r, "p[0].issuer.iss").status === "pass" &&
     /configured mapping/.test(checkById(r, "p[0].issuer.iss").detail),
     "S3: a configured sha256 mapping binds iss: " +
     JSON.stringify(checkById(r, "p[0].issuer.iss")));
  // #471 E2: DCQL trusted_authorities (OpenID4VP 1.0 section 6.1.1). The
  // aki values the page asks for are the anchors' SubjectKeyIdentifiers,
  // read here by OpenSSL, not by this tree.
  const opensslSki = function opensslSki(pem) {
    log.debug("Entering opensslSki().");
    const out = require("child_process").execFileSync("openssl",
      ["x509", "-noout", "-ext", "subjectKeyIdentifier"], { input: pem })
      .toString();
    const hex = (/([0-9A-F]{2}(:[0-9A-F]{2})+)/.exec(out) || [""])[0]
      .replace(/:/g, "");
    log.debug("Leaving opensslSki().");
    return Buffer.from(hex, "hex").toString("base64url");
  };
  const rootAki = opensslSki(root.pem);
  const interAki = opensslSki(inter.pem);
  eq(verifier.akiValuesFromAnchors([root.pem, inter.pem]).values,
     [rootAki, interAki], "E2: aki values are the anchors' SKIs");
  const taDcql = function taDcql(entries) {
    log.debug("Entering taDcql().");
    log.debug("Leaving taDcql().");
    return verifier.buildDcql({ queries: [{ id: "p", format: "dc+sd-jwt",
      vct: VCT, requireBinding: false, trustedAuthorities: entries }] });
  };
  eq(taDcql([{ type: "aki", values: [rootAki] }]).credentials[0]
     .trusted_authorities, [{ type: "aki", values: [rootAki] }]);
  let taRefused = "";
  try {
    taDcql([{ type: "aki", values: [] }]);
  } catch (e) {
    taRefused = e.message;
  }
  ok(/non-empty array of strings/.test(taRefused), "E2: empty values");
  const taRun = function taRun(entries) {
    log.debug("Entering taRun().");
    log.debug("Leaving taRun().");
    return sendSd(x5cJwt([leaf, inter], GOV), { session: Object.assign({},
      anchors.session, { dcql: taDcql(entries) }) });
  };
  // The leaf's AKI is the intermediate's SKI; the intermediate's is the
  // root's, so either value matches somewhere in the chain.
  for (const v of [interAki, rootAki]) {
    r = await taRun([{ type: "aki", values: [v] }]);
    ok(checkById(r, "p[0].issuer.trusted-authorities").status === "pass",
       "E2: aki " + v + " matches: " +
       JSON.stringify(checkById(r, "p[0].issuer.trusted-authorities")));
  }
  r = await taRun([{ type: "aki", values: ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] },
                   { type: "etsi_tl", values: ["https://lotl.example.com"] }]);
  const taMiss = checkById(r, "p[0].issuer.trusted-authorities");
  ok(taMiss.status === "skip" && !taMiss.essential &&
     /no certificate in its chain of 2.*etsi_tl.*SHOULD/.test(taMiss.detail),
     "E2: section 6.1.1.1's example value matches nothing, reported: " +
     JSON.stringify(taMiss));
  eq(failedIds(r), [], "E2: a credential outside trusted_authorities " +
     "fails nothing (the wallet SHOULD, the trust rows decide)");
  // #471 E1: the HAIP 1.0 Verifier mode. A HAIP violation is REPORTED on
  // a "haip." row and every other check still runs (rcbj, 2026-11-17); the
  // validity verdict leaves those rows out and `profile` counts them.
  const haipSession = function haipSession(extra) {
    log.debug("Entering haipSession().");
    log.debug("Leaving haipSession().");
    return { session: Object.assign({}, anchors.session, { profile: "haip" },
                                    extra || {}) };
  };
  r = await sendSd(x5cJwt([leaf, inter], GOV), haipSession());
  eq(r.verdict, "pass", "E1: a sound chain is still a pass under HAIP");
  ok(r.profile && r.profile.name === "HAIP 1.0", "E1: profile reported");
  eq(r.checks.filter(function (c) {
    return c.profile === "haip" && c.status === "fail";
  }).map(function (c) {
    return c.id;
  }), ["response.haip.encrypted"], "E1: the only violation of a sound x5c " +
     "credential sent by direct_post is the unencrypted answer");
  ok(/VIOLATES HAIP 1\.0.*direct_post\.jwt or dc_api\.jwt/.test(
     checkById(r, "response.haip.encrypted").detail), "E1: says which rule");
  for (const id of ["p[0].haip.format", "p[0].haip.issuer.x5c",
                    "p[0].haip.issuer.not-self-signed",
                    "p[0].haip.issuer.no-anchor-in-chain",
                    "p[0].haip.kb.present"]) {
    eq(checkById(r, id).status, "pass", "E1: " + id);
  }
  // The anchor carried in x5c: a HAIP violation, reported, and the chain
  // still anchored and the signature still checked.
  r = await sendSd(x5cJwt([leaf, inter, root], GOV), haipSession());
  eq(checkById(r, "p[0].haip.issuer.no-anchor-in-chain").status, "fail",
     "E1: an included anchor violates HAIP 6.1.1");
  eq([checkById(r, "p[0].issuer.signature").status, trustOf(r).status,
      r.verdict], ["pass", "pass", "pass"], "E1: and validation goes on");
  eq(r.profile.violations, 2, "E1: two violations counted");
  // No x5c, a cnf with no KB-JWT, and a status with no status_list: three
  // violations of HAIP 6.1, each reported; the issuer key is then looked
  // for the non-HAIP way, and the checks that can still run do.
  const noX5c = nodeJws({ alg: "ES256", typ: "dc+sd-jwt" }, Object.assign(
    sdPayload(GOV), { cnf: { jwk: { kty: "EC", crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" } },
      status: { identifier_list: { id: "1", uri: "https://x.example" } } }),
    { privateKey: leafKey.privateKey });
  r = await sendSd(noX5c, haipSession());
  eq(["p[0].haip.issuer.x5c", "p[0].haip.kb.present",
      "p[0].haip.status.status_list"].map(function (id) {
    return checkById(r, id).status;
  }), ["fail", "fail", "fail"], "E1: three HAIP 6.1 violations reported");
  ok(checkById(r, "p[0].issuer.signature") && checkById(r, "p[0].vct"),
     "E1: and the issuer key and vct were still checked");
  // Outside HAIP mode there are no haip rows at all.
  r = await sendSd(x5cJwt([leaf, inter, root], GOV), anchors);
  ok(!r.profile && !r.checks.some(function (c) {
    return /\.haip\./.test(c.id) || c.profile;
  }), "E1: plain OpenID4VP has no HAIP rows");
  // The request side.
  const haipReq = function haipReq(over) {
    log.debug("Entering haipReq().");
    log.debug("Leaving haipReq().");
    return verifier.haipRequestProblems(Object.assign({ dcApi: false,
      prefix: "x509_hash", delivery: "reference-get",
      responseMode: "direct_post.jwt", formats: ["dc+sd-jwt"],
      redirectUri: "https://verifier.example/done" }, over || {}));
  };
  eq(haipReq(), { refused: [], advised: [] }, "E1: a HAIP request");
  eq(haipReq({ prefix: "x509_san_dns" }).refused.length, 1);
  eq(haipReq({ delivery: "value" }).refused.length, 1);
  eq(haipReq({ responseMode: "direct_post" }).refused.length, 1);
  eq(haipReq({ formats: ["ldp_vc", "mso_mdoc"] }).refused.length, 1);
  eq(haipReq({ encValues: ["A256GCM"] }).refused.length, 1);
  eq(haipReq({ redirectUri: "" }).advised.length, 1, "E1: same-device " +
     "is advised, not required");
  eq(haipReq({ dcApi: true, responseMode: "dc_api.jwt", signed: false,
               prefix: "redirect_uri" }).refused, [],
     "E1: an unsigned DC API request names no prefix");
  eq(haipReq({ dcApi: true, responseMode: "dc_api", signed: true,
               prefix: "decentralized_identifier" }).refused.length, 2);
  // A chain anchored at some OTHER root.
  const otherRootKey = nodePemPair("ec");
  const otherRoot = await testCert({ profile: "root-ca", cn: "Other Root",
                                     key: otherRootKey });
  r = await sendSd(x5cJwt([leaf, inter], GOV),
                   { session: { trustAnchors: [otherRoot.pem] } });
  failsOnly(r, ["p[0].issuer.trust"], "S3: anchors that did not issue it");
  log.info("PASS #467: a kid never chooses the issuer (S1), a URL " +
           "issuer's proof is by a method it controls (S2), an x5c chain " +
           "is reported and anchored or not (S3), and a check not " +
           "performed is not a pass (S4).");
  log.debug("Leaving securityFindings().");
}

// ---------------------------------------------------------------------------
// #469: what a conformant Wallet or Issuer may send, and this Verifier used
// to refuse — each case built from the specifications' own examples or
// with node's crypto, never with this tree's wallet.
// ---------------------------------------------------------------------------
function didKeyOf(pair) {
  log.debug("Entering didKeyOf().");
  const did = didLib.jwkToDidKey(pair.publicJwk);
  log.debug("Leaving didKeyOf().");
  return { did: did, kid: did + "#" + did.slice("did:key:".length) };
}

function docFetcher(docs) {
  log.debug("Entering docFetcher().");
  log.debug("Leaving docFetcher().");
  return function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return docs[url] !== undefined ? Promise.resolve(docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
}

function jwtVcSession(env, dcql) {
  log.debug("Entering jwtVcSession().");
  log.debug("Leaving jwtVcSession().");
  return { clientId: verifier.clientIdFor("x509_hash", env.identity),
           nonce: verifier.randomToken(), state: "s",
           responseMode: "direct_post", dcql: dcql };
}

async function sendOne(session, id, presentation, extra) {
  log.debug("Entering sendOne().");
  const vpToken = {};
  vpToken[id] = [presentation];
  log.debug("Leaving sendOne().");
  return run(Object.assign({ fields: vp.formEncode({ vp_token: vpToken,
    state: "s" }), session: session }, extra || {}));
}

// OpenID4VP 1.0 Appendix B.1.3.1.2's example credential, with a DID issuer
// whose key node holds. `over` replaces members of the payload.
function exampleVc(issuer, over) {
  log.debug("Entering exampleVc().");
  const payload = Object.assign({
    iss: issuer.did, nbf: 1262304000,
    jti: "http://example.gov/credentials/3732",
    sub: "did:example:ebfeb1f712ebc6f1c276e12ec21",
    vc: { "@context": ["https://www.w3.org/2018/credentials/v1",
                       "https://www.w3.org/2018/credentials/examples/v1"],
          type: ["VerifiableCredential", "IDCredential"],
          credentialSubject: { given_name: "Max",
            family_name: "Mustermann", birthdate: "1998-01-11",
            address: { street_address: "Sandanger 25",
              locality: "Musterstadt", postal_code: "123456",
              country: "DE" } } } }, over || {});
  log.debug("Leaving exampleVc().");
  return nodeJws({ alg: "ES256", typ: "JWT", kid: issuer.kid }, payload,
                 issuer.pair);
}

// The VP JWT of Appendix B.1.3.1.5, signed by node; `over` replaces or (as
// undefined) removes members.
function exampleVp(holder, session, vcs, over, header) {
  log.debug("Entering exampleVp().");
  const now = Math.floor(Date.now() / 1000);
  const payload = Object.assign({ iss: holder.did,
    jti: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    aud: session.clientId, nbf: now - 10, iat: now - 10, exp: now + 600,
    nonce: session.nonce,
    vp: { "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiablePresentation"], verifiableCredential: vcs } },
    over || {});
  Object.keys(payload).forEach(function (k) {
    if (payload[k] === undefined) delete payload[k];
  });
  log.debug("Leaving exampleVp().");
  return nodeJws(Object.assign({ alg: "ES256", typ: "JWT",
                                 kid: holder.kid }, header || {}),
                 payload, holder.pair);
}

function exampleContexts() {
  log.debug("Entering exampleContexts().");
  // The two example contexts the specifications' examples name, as much of
  // them as these cases use: both put undefined terms under @vocab.
  [["https://www.w3.org/2018/credentials/examples/v1",
    "https://example.org/examples#"],
   ["https://www.w3.org/ns/credentials/examples/v2",
    "https://www.w3.org/ns/credentials/examples#"]].forEach(function (c) {
    try {
      bbs2023.addContext(c[0], { "@context": { "@vocab": c[1] } });
    } catch (e) {
      log.debug("exampleContexts(): " + c[0] + ": " + e.message);
    }
  });
  log.debug("Leaving exampleContexts().");
}

async function jwtVcJsonFindings(env) {
  log.debug("Entering jwtVcJsonFindings().");
  exampleContexts();
  const issuerPair = ecPair();
  const issuer = Object.assign({ pair: issuerPair }, didKeyOf(issuerPair));
  const holderPair = ecPair();
  const holder = Object.assign({ pair: holderPair }, didKeyOf(holderPair));
  // Appendix B.1.3.1.4's own query, holder binding not required.
  const unbound = { credentials: [{ id: "example_jwt_vc",
    format: "jwt_vc_json", require_cryptographic_holder_binding: false,
    meta: { type_values: [["IDCredential"]] },
    claims: [{ path: ["credentialSubject", "family_name"] },
             { path: ["credentialSubject", "given_name"] }] }] };
  const session = jwtVcSession(env, unbound);
  const vc = exampleVc(issuer);

  // C1: a bare VC is the answer B.1 REQUIRES when binding is not.
  let r = await sendOne(session, "example_jwt_vc", vc);
  allPass(r, "C1: a bare VC JWT, binding not required");
  eq(checkById(r, "example_jwt_vc[0].vp.signature").status, "skip",
     "C1: there is no VP to verify");
  ok(/bare VC JWT/.test(checkById(r, "example_jwt_vc[0].format").detail),
     "C1: the format row says it is a bare VC");
  const bound = JSON.parse(JSON.stringify(unbound));
  delete bound.credentials[0].require_cryptographic_holder_binding;
  r = await sendOne(jwtVcSession(env, bound), "example_jwt_vc", vc);
  failsOnly(r, ["example_jwt_vc[0].vp.signature"], "C1: a bare VC when " +
            "binding IS required");

  // C6: the spec's [["IDCredential"]] against a type under an @vocab
  // context: as written it matches, expanded it does not, and the row
  // says which.
  ok(/matched only as WRITTEN/.test(checkById(allPassOf(await sendOne(
     session, "example_jwt_vc", vc)), "example_jwt_vc[0].types").detail),
     "C6: a compact type_values value is reported as such");

  // B2: an https issuer with no route to its key.
  const httpsVc = exampleVc(issuer, { iss: "https://example.gov/issuers/" +
                                      "565049" });
  r = await sendOne(session, "example_jwt_vc", httpsVc,
                    { fetchJson: docFetcher({}) });
  incompleteOnly(r, ["example_jwt_vc[0].vc.signature"], "B2: jwt_vc_json, " +
                 "an https issuer with no key route");
  ok(new RegExp("could not resolve the issuer's key: could not fetch " +
     "https://example\\.gov/\\.well-known/jwt-vc-issuer/issuers/565049")
     .test(checkById(r, "example_jwt_vc[0].vc.signature").detail),
     "B2: the row names the URL and says no jwt_vc_json spec defines it: " +
     checkById(r, "example_jwt_vc[0].vc.signature").detail);
  ok(/no jwt_vc_json specification defines it/.test(checkById(r,
     "example_jwt_vc[0].vc.signature").detail), "B2: and says why");
  r = await sendOne(session, "example_jwt_vc", httpsVc);
  incompleteOnly(r, ["example_jwt_vc[0].vc.signature"], "B2: no fetchJson");
  // Metadata naming another issuer is, for jwt_vc_json, a route that did
  // not lead anywhere — not a forgery.
  const wrongMeta = {};
  wrongMeta["https://example.gov/.well-known/jwt-vc-issuer/issuers/565049"] =
    { issuer: "https://elsewhere.example", jwks: { keys: [] } };
  r = await sendOne(session, "example_jwt_vc", httpsVc,
                    { fetchJson: docFetcher(wrongMeta) });
  incompleteOnly(r, ["example_jwt_vc[0].vc.signature"], "B2: metadata " +
                 "for another issuer");
  // And for dc+sd-jwt the same metadata is a MUST broken: a FAIL.
  const sdIssuer = ecPair();
  const sdDcql = { credentials: [{ id: "p", format: "dc+sd-jwt",
    require_cryptographic_holder_binding: false,
    meta: { vct_values: [VCT] } }] };
  const sdSession = jwtVcSession(env, sdDcql);
  const sdJwt = nodeJws({ alg: "ES256", typ: "dc+sd-jwt" },
    { iss: "https://example.gov/issuers/565049", vct: VCT,
      iat: Math.floor(Date.now() / 1000) - 60 }, sdIssuer);
  r = await sendOne(sdSession, "p", sdJwt + "~",
                    { fetchJson: docFetcher(wrongMeta) });
  failsOnly(r, ["p[0].issuer.signature"], "B2: dc+sd-jwt metadata naming " +
            "another issuer is a FAIL (SD-JWT VC section 4.3)");
  // B3's reporting half for dc+sd-jwt: a jwks_uri that cannot be fetched.
  const brokenUri = {};
  brokenUri["https://example.gov/.well-known/jwt-vc-issuer/issuers/565049"] =
    { issuer: "https://example.gov/issuers/565049",
      jwks_uri: "https://example.gov/jwks" };
  r = await sendOne(sdSession, "p", sdJwt + "~",
                    { fetchJson: docFetcher(brokenUri) });
  incompleteOnly(r, ["p[0].issuer.signature"], "B3: a jwks_uri that " +
                 "cannot be fetched");
  ok(/could not fetch https:\/\/example\.gov\/jwks/.test(checkById(r,
     "p[0].issuer.signature").detail), "B3: the row names the jwks_uri");

  // C2, C15, C16 on a VP JWT signed by node, binding required, the holder
  // a did:key that is the credential's sub (C3).
  const subjectVc = exampleVc(issuer, { sub: holder.did });
  const bSession = jwtVcSession(env, bound);
  const send = function send(jwt, extra) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return sendOne(bSession, "example_jwt_vc", jwt, extra);
  };
  r = await send(exampleVp(holder, bSession, [subjectVc]));
  allPass(r, "C3: a did:key holder that is the credential's sub");
  ok(/which is the credential's sub/.test(checkById(r,
     "example_jwt_vc[0].vp.binding").detail), "C3: bound by DID");
  r = await send(exampleVp(holder, bSession, [subjectVc],
                           { iat: undefined }));
  allPass(r, "C2: a VP JWT with no iat");
  eq(checkById(r, "example_jwt_vc[0].vp.iat").status, "skip",
     "C2: no iat is a skip");
  ok(/B\.1\.3\.1\.5/.test(checkById(r, "example_jwt_vc[0].vp.iat").detail),
     "C2: the skip cites B.1.3.1.5");
  const old = Math.floor(Date.now() / 1000) - 3600;
  r = await send(exampleVp(holder, bSession, [subjectVc], { iat: old }));
  failsOnly(r, ["example_jwt_vc[0].vp.iat"], "C2: an hour-old VP JWT");
  ok(/this debugger's freshness policy/.test(checkById(r,
     "example_jwt_vc[0].vp.iat").detail), "C2: the policy is labelled");
  r = await send(exampleVp(holder, bSession, [subjectVc], { iat: old }),
                 { maxAgeSeconds: 7200 });
  allPass(r, "C2: the policy raised to two hours");
  r = await sendOne(Object.assign({}, bSession, { maxAgeSeconds: 0 }),
                    "example_jwt_vc",
                    exampleVp(holder, bSession, [subjectVc], { iat: old }));
  allPass(r, "C2: maxAgeSeconds 0 sets no age limit");
  r = await send(exampleVp(holder, bSession, [subjectVc],
                           { aud: ["https://other.example",
                                   bSession.clientId] }));
  allPass(r, "C15: aud an array containing the client_id");
  r = await send(exampleVp(holder, bSession, [subjectVc],
                           { aud: ["https://other.example"] }));
  failsOnly(r, ["example_jwt_vc[0].vp.aud"], "C15: an array without it");
  const now = Math.floor(Date.now() / 1000);
  r = await send(exampleVp(holder, bSession, [subjectVc],
                           { exp: now - 3600 }));
  failsOnly(r, ["example_jwt_vc[0].vp.validity"], "C16: an expired VP");
  r = await send(exampleVp(holder, bSession, [subjectVc],
                           { nbf: now + 3600 }));
  failsOnly(r, ["example_jwt_vc[0].vp.validity"], "C16: a VP not yet valid");

  // C3: a VP by another did:key is not the subject's.
  const otherPair = ecPair();
  const other = Object.assign({ pair: otherPair }, didKeyOf(otherPair));
  r = await send(exampleVp(other, bSession, [subjectVc]));
  failsOnly(r, ["example_jwt_vc[0].vp.binding"], "C3: another did:key");
  // C3: a did:web holder, resolved through fetchJson.
  const webDid = "did:web:holder.example";
  const webDocs = {};
  webDocs["https://holder.example/.well-known/did.json"] = { id: webDid,
    verificationMethod: [{ id: "#k1", type: "JsonWebKey2020",
      controller: webDid, publicKeyJwk: holderPair.publicJwk }],
    authentication: ["#k1"] };
  const webHolder = { pair: holderPair, did: webDid, kid: webDid + "#k1" };
  r = await send(exampleVp(webHolder, bSession, [exampleVc(issuer,
    { sub: webDid })]), { fetchJson: docFetcher(webDocs) });
  allPass(r, "C3: a did:web holder that is the credential's sub");
  // C3: the VP's key in its header, the subject a did:key of that key.
  r = await send(exampleVp(holder, bSession, [subjectVc], {},
    { kid: undefined, jwk: holderPair.publicJwk }));
  allPass(r, "C3: a header jwk that is a key of the subject's did:key");
  // C4 for jwt_vc_json: cnf.kid, a DID URL, resolved.
  r = await send(exampleVp(holder, bSession, [exampleVc(issuer,
    { cnf: { kid: holder.kid } })], {},
    { kid: undefined, jwk: holderPair.publicJwk }));
  allPass(r, "C4: jwt_vc_json bound by cnf.kid");
  ok(/cnf\.kid/.test(checkById(r, "example_jwt_vc[0].vp.binding").detail),
     "C4: the binding row names cnf.kid");
  log.info("PASS #469 jwt_vc_json: a bare VC (C1), iat optional and the " +
           "freshness window a policy (C2), DID holders (C3), cnf.kid " +
           "(C4), aud arrays (C15), exp/nbf (C16), and issuer key routes " +
           "that fail as a SKIP (B2/B3).");
  log.debug("Leaving jwtVcJsonFindings().");
}

function allPassOf(result) {
  log.debug("Entering allPassOf().");
  allPass(result, "a passing response");
  log.debug("Leaving allPassOf().");
  return result;
}

// C7: a did:web issuer whose document names its keys the ways DID Core
// allows — a RELATIVE id, an absolute one, a publicKeyJwk with a kid of
// its own — and credentials with and without a kid.
async function didIssuerKeys(env) {
  log.debug("Entering didIssuerKeys().");
  const did = "did:web:issuer.example:tenant";
  const k1 = ecPair();
  const k2 = ecPair();
  const docs = {};
  docs["https://issuer.example/tenant/did.json"] = { id: did,
    verificationMethod: [
      { id: "#key-1", type: "JsonWebKey2020", controller: did,
        publicKeyJwk: k1.publicJwk },
      { id: did + "#key-2", type: "JsonWebKey2020", controller: did,
        publicKeyJwk: Object.assign({ kid: "own-kid" }, k2.publicJwk) }],
    assertionMethod: ["#key-1", did + "#key-2"] };
  const fetchJson = docFetcher(docs);
  const dcql = { credentials: [{ id: "w", format: "jwt_vc_json",
    require_cryptographic_holder_binding: false,
    meta: { type_values: [["VerifiableCredential"]] } }] };
  const session = jwtVcSession(env, dcql);
  const vcBy = function vcBy(key, kid) {
    log.debug("Entering vcBy().");
    const header = { alg: "ES256", typ: "JWT" };
    if (kid !== undefined) header.kid = kid;
    log.debug("Leaving vcBy().");
    return nodeJws(header, { iss: did, iat: Math.floor(Date.now() / 1000),
      vc: { "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential"],
            credentialSubject: { name: "X" } } }, key);
  };
  let r = await sendOne(session, "w", vcBy(k1, did + "#key-1"),
                        { fetchJson: fetchJson });
  allPass(r, "C7: kid names a RELATIVE verification method id");
  r = await sendOne(session, "w", vcBy(k1, "#key-1"),
                    { fetchJson: fetchJson });
  allPass(r, "C7: a relative kid");
  r = await sendOne(session, "w", vcBy(k2, "own-kid"),
                    { fetchJson: fetchJson });
  allPass(r, "C7: kid names the publicKeyJwk's own kid");
  r = await sendOne(session, "w", vcBy(k2, did + "#key-2"),
                    { fetchJson: fetchJson });
  allPass(r, "C7: kid names the absolute id of a key that has its own kid");
  r = await sendOne(session, "w", vcBy(k2), { fetchJson: fetchJson });
  allPass(r, "C7: no kid, two keys, each tried (SD-JWT VC section 4.2)");
  ok(/each of 2 keys was tried/.test(checkById(r, "w[0].vc.signature")
     .detail), "C7: the row says each key was tried: " +
     checkById(r, "w[0].vc.signature").detail);
  r = await sendOne(session, "w", vcBy(k2, did + "#key-1"),
                    { fetchJson: fetchJson });
  failsOnly(r, ["w[0].vc.signature"], "C7: kid names key-1, signed by 2");
  r = await sendOne(session, "w", vcBy(k1, did + "#nope"),
                    { fetchJson: fetchJson });
  failsOnly(r, ["w[0].vc.signature"], "C7: a kid no key answers to");
  ok(/no key has kid/.test(checkById(r, "w[0].vc.signature").detail),
     "C7: and says so");
  r = await sendOne(session, "w", vcBy(ecPair()), { fetchJson: fetchJson });
  failsOnly(r, ["w[0].vc.signature"], "C7: no kid, signed by neither key");
  r = await sendOne(session, "w", vcBy(k1, did + "#key-1"));
  incompleteOnly(r, ["w[0].vc.signature"], "B2: a did:web that cannot be " +
                 "resolved");
  log.info("PASS #469 C7: DID issuer keys by relative id, absolute id, " +
           "their own kid, and with no kid at all.");
  log.debug("Leaving didIssuerKeys().");
}

// C4 and C5 on dc+sd-jwt: the Key Binding JWT's key from cnf.kid and
// cnf.jku, and SD-JWT VC -27's own type examples.
async function sdJwtFindings(env) {
  log.debug("Entering sdJwtFindings().");
  const issuer = makeIssuer();
  const holder = ecPair();
  const hk = didKeyOf(holder);
  const docs = Object.assign({}, issuer.docs);
  docs["https://holder.example/jwks"] = { keys: [
    Object.assign({ kid: "h0" }, ecPair().publicJwk),
    Object.assign({ kid: "h1" }, holder.publicJwk)] };
  const fetchJson = docFetcher(docs);
  const dcql = { credentials: [{ id: "p", format: "dc+sd-jwt",
    meta: { vct_values: [VCT] } }] };
  const session = jwtVcSession(env, dcql);
  const present = function present(payload, kb) {
    log.debug("Entering present().");
    const jwt = issueSdJwt(issuer, holder.publicJwk,
                           { payload: payload }).jwt;
    log.debug("Leaving present().");
    return presentSdJwt(jwt, [], Object.assign({ aud: session.clientId,
      nonce: session.nonce, key: holder }, kb || {}));
  };
  let r = await sendOne(session, "p", present({ cnf: { kid: hk.kid } }),
                        { fetchJson: fetchJson });
  allPass(r, "C4: a KB-JWT whose key is cnf.kid, a did:key URL");
  ok(/cnf\.kid/.test(checkById(r, "p[0].kb.signature").detail),
     "C4: the row names cnf.kid");
  r = await sendOne(session, "p", present({ cnf: {
    jku: "https://holder.example/jwks", kid: "h1" } }),
    { fetchJson: fetchJson });
  allPass(r, "C4: cnf.jku narrowed by cnf.kid");
  r = await sendOne(session, "p", present({ cnf: {
    jku: "https://holder.example/jwks" } }), { fetchJson: fetchJson });
  allPass(r, "C4: cnf.jku alone, each key tried");
  r = await sendOne(session, "p", present({ cnf: {
    jku: "https://holder.example/missing" } }), { fetchJson: fetchJson });
  incompleteOnly(r, ["p[0].kb.signature"], "C4: a cnf.jku that cannot be " +
                 "fetched");
  r = await sendOne(session, "p", present({ cnf: { kid: "opaque-1" } }),
                    { fetchJson: fetchJson });
  incompleteOnly(r, ["p[0].kb.signature"], "C4: an opaque cnf.kid");
  r = await sendOne(session, "p", present({ cnf: { kid: hk.kid } },
                                          { key: ecPair() }),
                    { fetchJson: fetchJson });
  failsOnly(r, ["p[0].kb.signature"], "C4: a KB-JWT by another key");
  r = await sendOne(session, "p", present({}, { iat: null }),
                    { fetchJson: fetchJson });
  failsOnly(r, ["p[0].kb.iat"], "C2: a KB-JWT's iat stays REQUIRED " +
            "(RFC 9901 section 4.3)");

  // C5: SD-JWT VC -27 Figure 4, the PID with aka_vcts, against a query for
  // the general type.
  const pidQuery = { credentials: [{ id: "p", format: "dc+sd-jwt",
    meta: { vct_values: ["urn:example:eudi:pid"] } }] };
  const pidSession = jwtVcSession(env, pidQuery);
  const pid = function pid(payload) {
    log.debug("Entering pid().");
    const jwt = issueSdJwt(issuer, holder.publicJwk,
                           { payload: payload }).jwt;
    log.debug("Leaving pid().");
    return presentSdJwt(jwt, [], { aud: pidSession.clientId,
      nonce: pidSession.nonce, key: holder });
  };
  r = await sendOne(pidSession, "p", pid({
    vct: "urn:example:eudi:pid:aendgard:1",
    aka_vcts: ["urn:example:eudi:pid"] }), { fetchJson: fetchJson });
  allPass(r, "C5: SD-JWT VC -27 Figure 4, aka_vcts");
  ok(/through aka_vcts/.test(checkById(r, "p[0].vct").detail),
     "C5: the row says aka_vcts matched");
  r = await sendOne(pidSession, "p", pid({
    vct: "urn:example:eudi:pid:aendgard:1",
    aka_vcts: ["urn:example:eudi:pid", "urn:example:eudi:pid:aendgard:1"] }),
    { fetchJson: fetchJson });
  failsOnly(r, ["p[0].vct"], "C5: aka_vcts containing the vct itself");
  r = await sendOne(pidSession, "p", pid({
    vct: "urn:example:eudi:pid:aendgard:1",
    aka_vcts: ["urn:example:eudi:other"] }), { fetchJson: fetchJson });
  failsOnly(r, ["p[0].vct"], "C5: aka_vcts naming another type");
  // SD-JWT VC -27 Figures 16 and 17: v42 extends the galactic type.
  const V42 = "https://betelgeuse.example.com/education_credential/v42";
  const GALAXY = "https://galaxy.example.com/galactic-education-credential/v2";
  const typeDocs = Object.assign({}, docs);
  typeDocs[V42] = { vct: V42,
    name: "Betelgeuse Education Credential - Version 42",
    description: "This is our education credential. Don't panic.",
    extends: GALAXY };
  typeDocs[GALAXY] = { vct: GALAXY, name: "Galactic Education" };
  const eduSession = jwtVcSession(env, { credentials: [{ id: "p",
    format: "dc+sd-jwt", meta: { vct_values: [GALAXY] } }] });
  const edu = function edu() {
    log.debug("Entering edu().");
    const jwt = issueSdJwt(issuer, holder.publicJwk,
                           { payload: { vct: V42 } }).jwt;
    log.debug("Leaving edu().");
    return presentSdJwt(jwt, [], { aud: eduSession.clientId,
      nonce: eduSession.nonce, key: holder });
  };
  r = await sendOne(eduSession, "p", edu(),
                    { fetchJson: docFetcher(typeDocs) });
  allPass(r, "C5: a vct that extends the requested type (B.3.5)");
  ok(/extends chain/.test(checkById(r, "p[0].vct").detail),
     "C5: the row says the extends chain matched");
  const loop = Object.assign({}, typeDocs);
  loop[GALAXY] = { vct: GALAXY, extends: V42 };
  const loopSession = jwtVcSession(env, { credentials: [{ id: "p",
    format: "dc+sd-jwt", meta: { vct_values: ["urn:example:none"] } }] });
  const loopJwt = issueSdJwt(issuer, holder.publicJwk,
                             { payload: { vct: V42 } }).jwt;
  r = await sendOne(loopSession, "p", presentSdJwt(loopJwt, [],
    { aud: loopSession.clientId, nonce: loopSession.nonce, key: holder }),
    { fetchJson: docFetcher(loop) });
  failsOnly(r, ["p[0].vct"], "C5: a circular extends (section 7.4)");
  ok(/circular/.test(checkById(r, "p[0].vct").detail), "C5: named");
  r = await sendOne(eduSession, "p", edu(), { fetchJson: fetchJson });
  eq(checkById(r, "p[0].vct").status, "skip", "C5: Type Metadata that " +
     "cannot be fetched leaves inheritance unknown");
  log.info("PASS #469 dc+sd-jwt: KB-JWT keys from cnf.kid and cnf.jku " +
           "(C4), aka_vcts and extends (C5).");
  log.debug("Leaving sdJwtFindings().");
}

// C6: OpenID4VP 1.0 Appendix B.1.1's own type_values and the three
// credentials it says match them, for both W3C formats.
async function typeValueFindings(env) {
  log.debug("Entering typeValueFindings().");
  exampleContexts();
  const typeValues = [
    ["https://www.w3.org/2018/credentials#VerifiableCredential",
     "https://example.org/examples#AlumniCredential",
     "https://example.org/examples#BachelorDegree"],
    ["https://www.w3.org/2018/credentials#VerifiableCredential",
     "https://example.org/examples#UniversityDegreeCredential"],
    ["IdentityCredential"]];
  const examples = [
    [["https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"],
     ["VerifiableCredential", "UniversityDegreeCredential"]],
    [["https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"],
     ["VerifiableCredential", "BachelorDegree", "AlumniCredential"]],
    [["https://www.w3.org/2018/credentials/v1"],
     ["VerifiableCredential", "IdentityCredential"]]];
  const key = suiteKey("ed25519");
  const issuerPair = ecPair();
  const issuer = Object.assign({ pair: issuerPair }, didKeyOf(issuerPair));
  for (const format of ["jwt_vc_json", "ldp_vc"]) {
    const session = jwtVcSession(env, { credentials: [{ id: "c",
      format: format, require_cryptographic_holder_binding: false,
      meta: { type_values: typeValues } }] });
    const make = async function make(ctx, types) {
      log.debug("Entering make().");
      const body = { "@context": ctx, type: types,
        issuer: format === "ldp_vc" ? key.did : issuer.did,
        issuanceDate: "2026-01-01T00:00:00Z",
        credentialSubject: { id: "did:example:abc" } };
      const out = format === "ldp_vc" ?
        JSON.stringify(await diSign(body, "eddsa-jcs-2022", key,
                                    "assertionMethod")) :
        exampleVc(issuer, { vc: body });
      log.debug("Leaving make().");
      return out;
    };
    for (let i = 0; i < examples.length; i++) {
      const r = await sendOne(session, "c", await make(examples[i][0],
                                                       examples[i][1]));
      allPass(r, "C6: " + format + ", Appendix B.1.1 example " + (i + 1));
      ok(/after JSON-LD expansion/.test(checkById(r, "c[0].types").detail),
         "C6: " + format + " example " + (i + 1) + " matched as IRIs: " +
         checkById(r, "c[0].types").detail);
    }
    const r = await sendOne(session, "c", await make(examples[0][0],
      ["VerifiableCredential", "AlumniCredential"]));
    failsOnly(r, ["c[0].types"], "C6: " + format + ", AlumniCredential " +
              "without BachelorDegree matches no alternative");
  }
  log.info("PASS #469 C6: type_values compared as expanded IRIs, for " +
           "jwt_vc_json and (now at all) ldp_vc.");
  log.debug("Leaving typeValueFindings().");
}

// C8: mdocs signed here with the algorithms and digests ISO/IEC 18013-5
// and HAIP 1.0 allow, and a Document whose docType is not its MSO's.
async function mdocFindings(env) {
  log.debug("Entering mdocFindings().");
  const auth = await mdocIssuer.authority("issue 469");
  const NS = mdocIssuer.NS;
  const device = ecPair();
  const dcql = { credentials: [{ id: "mdl", format: "mso_mdoc",
    meta: { doctype_value: mdocIssuer.DOCTYPE },
    claims: [{ path: [NS, "given_name"] }] }] };
  const session = Object.assign(jwtVcSession(env, dcql), {
    responseUri: "https://verifier.example/response",
    trustAnchors: [auth.iacaPem] });
  const transcript = mdocIssuer.transcript(session.clientId, session.nonce,
                                           null, session.responseUri);
  const send = function send(cred, dev, opts) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return sendOne(session, "mdl", deviceResponseHere(cred, dev || device,
                                                      transcript, opts));
  };
  const elements = { given_name: "Erika" };
  let r = await send(issueMdocHere(auth, device.publicJwk, elements));
  allPass(r, "C8: the baseline mdoc, -7");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
                               { alg: -9 }));
  allPass(r, "C8: issuerAuth -9 (ESP256, HAIP 1.0 section 7)");
  ok(/ESP256/.test(checkById(r, "mdl[0].mdoc.issuer-signature").detail),
     "C8: the row names ESP256");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
                               { alg: -999 }));
  failsOnly(r, ["mdl[0].mdoc.issuer-signature"], "C8: an unknown COSE alg");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
    { hash: "sha384", digestAlgorithm: "SHA-384" }));
  allPass(r, "C8: SHA-384 element digests");
  ok(/SHA-384/.test(checkById(r, "mdl[0].mdoc.element-digests").detail),
     "C8: the row names SHA-384");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
    { hash: "sha512", digestAlgorithm: "SHA-512" }));
  allPass(r, "C8: SHA-512 element digests");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
    { hash: "sha384", digestAlgorithm: "SHA-256" }));
  failsOnly(r, ["mdl[0].mdoc.element-digests"], "C8: SHA-384 digests in " +
            "an MSO that says SHA-256");
  r = await send(issueMdocHere(auth, device.publicJwk, elements, null,
                               { msoDocType: "org.example.other" }),
                 null, { docType: mdocIssuer.DOCTYPE });
  failsOnly(r, ["mdl[0].mdoc.mso-doctype", "mdl[0].mdoc.doctype"],
            "C8: a Document claiming mDL over an MSO that says otherwise");
  // The device signature in its own COSE alg: a P-384 device key, -35.
  const p384 = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "P-384" });
  const dev384 = { privateKey: p384.privateKey,
                   publicJwk: p384.publicKey.export({ format: "jwk" }) };
  r = await send(issueMdocHere(auth, dev384.publicJwk, elements, null,
                               { deviceCrv: 2 }), dev384,
                 { alg: -35, hash: "sha384" });
  allPass(r, "C8: a P-384 device key signing ES384 (-35)");
  r = await send(issueMdocHere(auth, device.publicJwk, elements), device,
                 { alg: -35 });
  failsOnly(r, ["mdl[0].mdoc.device-signature"], "C8: a header alg the " +
            "device key cannot have made");
  r = await send(issueMdocHere(auth, device.publicJwk, elements), device,
                 { deviceMac: true });
  incompleteOnly(r, ["mdl[0].mdoc.device-signature"], "C8: DeviceMac is " +
                 "not performed, not a forgery");
  ok(/DeviceMac/.test(checkById(r, "mdl[0].mdoc.device-signature").detail),
     "C8: and says DeviceMac");
  const formats = verifier.vpFormatsSupported().mso_mdoc;
  ok(formats.issuerauth_alg_values.indexOf(-7) !== -1 &&
     formats.issuerauth_alg_values.indexOf(-9) !== -1 &&
     formats.deviceauth_alg_values.indexOf(-9) !== -1,
     "C8: -7 and -9 are advertised: " + JSON.stringify(formats));
  log.info("PASS #469 C8: mdoc issuerAuth -7/-9/-35, the MSO's " +
           "digestAlgorithm, its docType, the device alg, and DeviceMac.");
  log.debug("Leaving mdocFindings().");
}

// C14: the proof's @context, by the cryptosuites' Verify Proof step 4. A
// JCS proof is hashed exactly as received and its @context must be a
// PREFIX of the document's; an RDFC proof's must be the document's.
async function proofContexts(env) {
  log.debug("Entering proofContexts().");
  const key = suiteKey("ed25519");
  const A = "https://www.w3.org/ns/credentials/v2";
  const B = "https://www.w3.org/ns/credentials/examples/v2";
  const body = function body(ctx) {
    log.debug("Entering body().");
    log.debug("Leaving body().");
    return { "@context": ctx, type: ["VerifiableCredential"],
             issuer: key.did, credentialSubject: { id: "did:example:x" } };
  };
  // Signed over [A]; the document then grows a second context. Verify
  // Proof hashes the document with the PROOF's @context.
  const grown = await diSign(body([A]), "eddsa-jcs-2022", key,
                             "assertionMethod");
  grown["@context"] = [A, B];
  let v = await verifier.verifyDataIntegrity(grown);
  ok(v.valid, "C14: a JCS proof whose @context is a " +
     "strict prefix: " + v.reason);
  const notPrefix = await diSign(body([A, B]), "eddsa-jcs-2022", key,
                                 "assertionMethod", { "@context": [B] });
  v = await verifier.verifyDataIntegrity(notPrefix);
  // The reasons are data_integrity.js's wording since the Verifier moved
  // onto it (#475): the same rules, read once in this tree.
  ok(!v.valid && /does not begin with the proof's @context/.test(v.reason),
     "C14: a JCS proof @context " +
     "that is not a prefix: " + v.reason);
  const omitted = await diSign(body([A]), "eddsa-jcs-2022", key,
                               "assertionMethod", { omitContext: true });
  ok(!("@context" in omitted.proof), "the omitted shape has no @context");
  v = await verifier.verifyDataIntegrity(omitted);
  ok(!v.valid && /WOULD verify had the document's @context been added/
       .test(v.reason) && !!v.diagnosis,
     "C14: the old shape FAILS, and says why: " + v.reason);
  const dcql = { credentials: [{ id: "c", format: "ldp_vc",
    require_cryptographic_holder_binding: false }] };
  const r = await sendOne(jwtVcSession(env, dcql), "c",
                          JSON.stringify(omitted));
  failsOnly(r, ["c[0].vc.proof"], "C14: the issuer proof row fails");
  eq(checkById(r, "c[0].vc.proof").essential, true,
     "C14: and it is essential");
  const rdfcSame = await diSign(body([A]), "eddsa-rdfc-2022", key,
                                "assertionMethod", { "@context": [A] });
  v = await verifier.verifyDataIntegrity(rdfcSame);
  ok(v.valid, "C14: an RDFC proof naming the document's @context: " +
     v.reason);
  const rdfcPrefix = await diSign(body([A]), "eddsa-rdfc-2022", key,
                                  "assertionMethod", { "@context": [A] });
  rdfcPrefix["@context"] = [A, B];
  v = await verifier.verifyDataIntegrity(rdfcPrefix);
  ok(!v.valid && /not the document's/.test(v.reason), "C14: an RDFC " +
     "proof @context that is only a prefix: " + v.reason);
  // Moved onto data_integrity.js (#475), the Verifier also verifies the
  // Linked Data proof types that preceded Data Integrity. Signed here by
  // that module, and a tampered copy fails.
  const di = load("data_integrity_rdfc.js");
  const legacy = await di.createProof(body([A]), { suite:
    "Ed25519Signature2020", privateJwk: Object.assign({},
      key.privateKey.export({ format: "jwk" })),
    verificationMethod: key.vm, proofPurpose: "assertionMethod" });
  v = await verifier.verifyDataIntegrity(legacy, {
    purpose: "assertionMethod" });
  ok(v.valid, "an Ed25519Signature2020 proof verifies: " + v.reason);
  const legacyBad = JSON.parse(JSON.stringify(legacy));
  legacyBad.credentialSubject = { id: "did:example:someone-else" };
  v = await verifier.verifyDataIntegrity(legacyBad);
  ok(!v.valid, "and a tampered one does not: " + v.reason);
  log.info("PASS #469 C14: JCS proof options hashed as received under the " +
           "prefix rule, RDFC under equality, the old shape a FAIL.");
  log.debug("Leaving proofContexts().");
}

// ONE DECLARATION PER NAME in vp_verifier.js. Two branches once each added a
// certSignedBy() and a CERT_SIG_ALGS of different shapes; in JavaScript the
// second declaration silently replaces the first, and the merged engine
// failed a correct mdoc answer with no hint why. A source check names it.
// ---------------------------------------------------------------------------
// #468 and #469: the request side's findings, each against something this
// tree did not write.
// ---------------------------------------------------------------------------
function nodeEdJws(header, payload, privateKey) {
  log.debug("Entering nodeEdJws().");
  const input = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  log.debug("Leaving nodeEdJws().");
  return input + "." + b64u(nodeCrypto.sign(null, Buffer.from(input),
                                            privateKey));
}

// RFC 5280 section 4.2.1.3's KeyUsage, read from a certificate's DER.
const KU_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment",
  "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
  "encipherOnly", "decipherOnly"];

function keyUsageOf(der) {
  log.debug("Entering keyUsageOf().");
  const forgeLib = require("node-forge");
  const asn1 = forgeLib.asn1;
  const cert = asn1.fromDer(Buffer.from(der).toString("binary"));
  const tbs = cert.value[0];
  const wrapped = tbs.value.filter(function (n) {
    return n.tagClass === asn1.Class.CONTEXT_SPECIFIC && n.type === 3;
  })[0];
  const exts = wrapped.value[0].value;
  for (const ext of exts) {
    if (asn1.derToOid(ext.value[0].value) !== "2.5.29.15") {
      continue;
    }
    const critical = ext.value.length === 3 &&
      ext.value[1].value.charCodeAt(0) !== 0;
    const octets = ext.value[ext.value.length - 1].value;
    const bits = asn1.fromDer(octets).value;
    const raw = typeof bits === "string" ? bits : "";
    const names = [];
    for (let i = 1; i < raw.length; i++) {
      for (let b = 0; b < 8; b++) {
        if (raw.charCodeAt(i) & (0x80 >> b)) {
          names.push(KU_BITS[(i - 1) * 8 + b]);
        }
      }
    }
    log.debug("Leaving keyUsageOf().");
    return { critical: critical, names: names };
  }
  log.debug("Leaving keyUsageOf(). None.");
  return { critical: false, names: [] };
}

async function requestSideFindings(env) {
  log.debug("Entering requestSideFindings().");
  // M5. RFC 5480 section 3: an id-ecPublicKey end-entity certificate may
  // assert digitalSignature, nonRepudiation and/or keyAgreement, never
  // keyEncipherment. The KeyUsage BIT STRING is read straight out of the
  // DER (node-forge's ASN.1 reader and RFC 5280 section 4.2.1.3's bit
  // numbering written here), not through x509.js.
  const leafKu = keyUsageOf(env.identity.leafDer);
  ok(leafKu.critical, "the leaf carries a critical KeyUsage");
  eq(leafKu.names, ["digitalSignature"],
     "the P-256 leaf asserts digitalSignature only (RFC 5480 section 3)");
  const rootKu = keyUsageOf(env.identity.rootDer);
  ok(rootKu.names.indexOf("keyCertSign") !== -1 &&
     rootKu.names.indexOf("keyEncipherment") === -1,
     "the root signs certificates and asserts no keyEncipherment either: " +
     rootKu.names.join(", "));
  const nodeLeaf = new nodeCrypto.X509Certificate(env.identity.leafPem);
  eq(nodeLeaf.publicKey.asymmetricKeyDetails.namedCurve, "prime256v1",
     "node reads the leaf key as P-256");

  // M7. Appendix B.3.4: fully-specified identifiers, so Ed25519.
  const formats = verifier.vpFormatsSupported();
  eq(formats["dc+sd-jwt"]["sd-jwt_alg_values"], ["ES256", "ES384",
     "Ed25519"]);
  eq(formats["dc+sd-jwt"]["kb-jwt_alg_values"], ["ES256", "ES384",
     "Ed25519"]);
  ok(formats["dc+sd-jwt"]["sd-jwt_alg_values"].indexOf("EdDSA") === -1 &&
     formats["dc+sd-jwt"]["kb-jwt_alg_values"].indexOf("EdDSA") === -1,
     "EdDSA is not fully specified and is not advertised for SD-JWT VC");
  // ...and an SD-JWT VC whose issuer JWT AND KB-JWT both say "Ed25519",
  // signed by node, verifies end to end.
  const issuerKey = nodeCrypto.generateKeyPairSync("ed25519");
  const holderKey = nodeCrypto.generateKeyPairSync("ed25519");
  const issuerJwk = Object.assign({ kid: "iss-ed", alg: "Ed25519",
    use: "sig" }, issuerKey.publicKey.export({ format: "jwk" }));
  const holderJwk = holderKey.publicKey.export({ format: "jwk" });
  const docs = {};
  docs["https://issuer.example/.well-known/jwt-vc-issuer/tenant"] =
    { issuer: ISSUER, jwks_uri: "https://issuer.example/jwks-ed" };
  docs["https://issuer.example/jwks-ed"] = { keys: [issuerJwk] };
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return docs[url] ? Promise.resolve(JSON.parse(JSON.stringify(docs[url])))
      : Promise.reject(new Error("no such document: " + url));
  };
  const now = Math.floor(Date.now() / 1000);
  const given = disclosure("e1", "given_name", "Erika");
  const jwt = nodeEdJws({ alg: "Ed25519", typ: "dc+sd-jwt", kid: "iss-ed" },
    { iss: ISSUER, iat: now - 60, exp: now + 3600, vct: VCT,
      _sd_alg: "sha-256", _sd: [sha256b64u(given)],
      cnf: { jwk: holderJwk } }, issuerKey.privateKey);
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    state: "st-ed", responseMode: "direct_post",
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: VCT, claims: [["given_name"]] }] }) };
  const prefix = jwt + "~" + given + "~";
  const kb = nodeEdJws({ alg: "Ed25519", typ: "kb+jwt" },
    { iat: now, aud: clientId, nonce: session.nonce,
      sd_hash: sha256b64u(prefix) }, holderKey.privateKey);
  const fields = vp.formEncode({ vp_token: { pid: [prefix + kb] },
                                 state: session.state });
  let r = await run({ fields: fields, session: session,
                      fetchJson: fetchJson });
  allPass(r, "an SD-JWT VC and KB-JWT whose headers say Ed25519");
  eq([checkById(r, "pid[0].issuer.signature").status,
      checkById(r, "pid[0].kb.signature").status], ["pass", "pass"],
     "both Ed25519 signatures were verified, not skipped");
  const forged = prefix + kb.slice(0, -6) + (kb.slice(-6) === "AAAAAA" ?
    "BBBBBB" : "AAAAAA");
  r = await run({ fields: vp.formEncode({ vp_token: { pid: [forged] },
    state: session.state }), session: session, fetchJson: fetchJson });
  ok(checkById(r, "pid[0].kb.signature").status === "fail",
     "a damaged Ed25519 KB-JWT signature fails");

  // C17. Section 5.9.3: "Requests using the redirect_uri Client Identifier
  // Prefix cannot be signed".
  const plain = verifier.requestObjectClaims({
    clientId: "redirect_uri:https://v.example/response",
    responseUri: "https://v.example/response", responseMode: "direct_post",
    nonce: "n", dcql: session.dcql });
  await rejects(function () {
    return verifier.signRequestObject({ claims: plain,
                                        identity: env.identity });
  }, /redirect_uri.*never signed.*cannot be signed/,
  "signRequestObject must refuse a redirect_uri: request even with an x5c");
  await rejects(function () {
    return verifier.signRequestObject({ claims: plain,
      identity: verifier.makeRequestKey() });
  }, /5\.9\.3/, "and with a bare key");
  eq(verifier.clientIdFor("redirect_uri", {},
     { redirectUri: "https://v.example/response" }),
     "redirect_uri:https://v.example/response",
     "a redirect_uri Client Identifier needs no identity at all");

  // C18. "pre-registered" is a client_id_prefixes_supported value (section
  // 10.1), not a prefix: "pre-registered:x" is a Client Identifier of its
  // own and signs as a pre-registered client.
  const typed = verifier.clientIdFor("pre-registered", null,
    { clientId: "pre-registered:x" });
  eq(typed, "pre-registered:x");
  const key = verifier.makeRequestKey();
  const pre = await verifier.signRequestObject({ identity: key,
    claims: verifier.requestObjectClaims({ clientId: typed,
      responseUri: "https://v.example/response", responseMode: "direct_post",
      nonce: "n", dcql: session.dcql }) });
  eq(decodeCompact(pre).header.kid, key.publicJwk.kid,
     "pre-registered:x is signed as a pre-registered client (kid)");

  // M8. Section 5.1: with request_uri_method=post the Verifier SHOULD send
  // client_metadata beside request_uri.
  const md = { vp_formats_supported: formats };
  let u = new URL(verifier.authorizationRequestUri({ clientId: "c",
    requestUri: "https://v.example/req", requestUriMethod: "post",
    clientMetadata: md }));
  eq(u.searchParams.get("request_uri_method"), "post");
  eq(JSON.parse(u.searchParams.get("client_metadata")), md,
     "client_metadata travels beside request_uri under post");
  u = new URL(verifier.authorizationRequestUri({ clientId: "c",
    requestUri: "https://v.example/req", clientMetadata: md }));
  ok(!u.searchParams.has("client_metadata"),
     "under get the Request Object carries it, and nothing else does");
  log.info("PASS #468 M5 (KeyUsage read from the DER), M7 (Ed25519 " +
           "signed by node) and M8; #469 C17 and C18.");
  log.debug("Leaving requestSideFindings().");
}

function oneDeclarationPerName() {
  log.debug("Entering oneDeclarationPerName().");
  const text = fs.readFileSync(path.join(SRC, "vp_verifier.js"), "utf8");
  const names = (text.match(
      /^(?:async\s+)?(?:function|var|const|let)\s+[A-Za-z0-9_$]+/gm) || [])
    .map(function (one) {
      return one.split(/\s+/).pop();
    });
  const seen = {};
  const twice = names.filter(function (one) {
    const again = !!seen[one];
    seen[one] = true;
    return again;
  });
  eq(twice, [], "vp_verifier.js declares these top-level names more than " +
     "once, and the later one silently wins");
  log.debug("Leaving oneDeclarationPerName().");
}

// ---------------------------------------------------------------------------
// OpenID4VP 1.0's own worked examples (#471, T1), as bytes the specification
// prints. Nothing here is this tree's wallet: each input and each expected
// value is copied from the text, and the spec's own hex is checked against
// node's SHA-256 first, so a transcription error says so rather than
// passing or failing the code for the wrong reason.
//
//   B.2.6.1  the input JWK's RFC 7638 thumbprint, OpenID4VPHandoverInfo,
//            OpenID4VPHandover and the SessionTranscript, rebuilt from
//            client_id, nonce, that JWK and response_uri;
//   B.2.6.2  the same for OpenID4VPDCAPIHandoverInfo / OpenID4VPDCAPI-
//            Handover, from the origin "https://example.com", nonce and JWK;
//   B.3.2    the example SD-JWT VC's _sd array and its three Disclosures:
//            the Verifier must find each printed digest for each printed
//            Disclosure and put back John, Doe and 1940-01-01.
//
// Both transcripts are rebuilt twice, by the Verifier
// (vp_verifier.mdocSessionTranscript) and by the wallet (mdoc.js
// sessionTranscript), and must be the spec's bytes exactly.
// ---------------------------------------------------------------------------
const OID4VP_B26_JWK = { kty: "EC", crv: "P-256",
  x: "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
  y: "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
  use: "enc", alg: "ECDH-ES", kid: "1" };
const OID4VP_B26_NONCE = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
const OID4VP_B261_INFO =
    "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767" +
    "426b786a7831726463397564527276654b7653734a4971383061766c58654c486847" +
    "7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6" +
    "bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365";
const OID4VP_B261_HANDOVER =
    "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c" +
    "efdd9d95240d254b046b11b68013722aad38ac";
const OID4VP_B261_TRANSCRIPT =
    "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e" +
    "ed494cefdd9d95240d254b046b11b68013722aad38ac";
const OID4VP_B262_INFO =
    "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831" +
    "726463397564527276654b7653734a4971383061766c58654c486847777174415820" +
    "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047";
const OID4VP_B262_HANDOVER =
    "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f97" +
    "62c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a";
const OID4VP_B262_TRANSCRIPT =
    "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4" +
    "212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a";

function hexOf(b) {
  log.debug("Entering hexOf().");
  log.debug("Leaving hexOf().");
  return Buffer.from(b).toString("hex");
}

function sha256Hex(hex) {
  log.debug("Entering sha256Hex().");
  log.debug("Leaving sha256Hex().");
  return nodeCrypto.createHash("sha256").update(Buffer.from(hex, "hex"))
    .digest("hex");
}

async function openid4vpSpecVectors(env) {
  log.debug("Entering openid4vpSpecVectors().");
  const mdoc = load("mdoc.js");
  // The spec against itself, with node: each Handover's hash is SHA-256 of
  // its Info, each SessionTranscript is [null, null, Handover], and the
  // Info's third element is the JWK's thumbprint (node's SHA-256 of RFC
  // 7638's member order).
  const thumbHex = Buffer.from(thumbprintOf(OID4VP_B26_JWK), "base64url")
    .toString("hex");
  ok(OID4VP_B261_INFO.indexOf("5820" + thumbHex) !== -1,
     "B.2.6.1: the Info's third element is the JWK's RFC 7638 thumbprint");
  ok(OID4VP_B262_INFO.indexOf("5820" + thumbHex) !== -1,
     "B.2.6.2: the Info's third element is the JWK's RFC 7638 thumbprint");
  eq(OID4VP_B261_HANDOVER.slice(-64), sha256Hex(OID4VP_B261_INFO),
     "B.2.6.1: the Handover hashes the Info (node's SHA-256)");
  eq(OID4VP_B262_HANDOVER.slice(-64), sha256Hex(OID4VP_B262_INFO),
     "B.2.6.2: the Handover hashes the Info (node's SHA-256)");
  eq(OID4VP_B261_TRANSCRIPT, "83f6f6" + OID4VP_B261_HANDOVER,
     "B.2.6.1: the SessionTranscript wraps the Handover");
  eq(OID4VP_B262_TRANSCRIPT, "83f6f6" + OID4VP_B262_HANDOVER,
     "B.2.6.2: the SessionTranscript wraps the Handover");

  // The Verifier's thumbprint of the spec's JWK.
  eq(Buffer.from(verifier.jwkThumbprint(OID4VP_B26_JWK), "base64url")
    .toString("hex"), thumbHex, "B.2.6.1: jwkThumbprint() of the JWK");

  // B.2.6.1, redirects: x509_san_dns:example.com, an encrypted response.
  const redirect = { responseMode: "direct_post.jwt",
    decryptionJwk: OID4VP_B26_JWK, clientId: "x509_san_dns:example.com",
    nonce: OID4VP_B26_NONCE, responseUri: "https://example.com/response" };
  eq(hexOf(mdoc.encode([redirect.clientId, redirect.nonce,
    Buffer.from(thumbHex, "hex"), redirect.responseUri])), OID4VP_B261_INFO,
     "B.2.6.1: OpenID4VPHandoverInfo, byte for byte");
  let t = verifier.mdocSessionTranscript(redirect);
  eq(hexOf(mdoc.encode(t.transcript[2])), OID4VP_B261_HANDOVER,
     "B.2.6.1: the Verifier's OpenID4VPHandover, byte for byte");
  eq(hexOf(mdoc.encode(t.transcript)), OID4VP_B261_TRANSCRIPT,
     "B.2.6.1: the Verifier's SessionTranscript, byte for byte");
  ok(t.encrypted, "B.2.6.1: direct_post.jwt carries the thumbprint");
  const walletRedirect = await mdoc.sessionTranscript({
    clientId: redirect.clientId, nonce: redirect.nonce,
    encryptionJwk: OID4VP_B26_JWK, responseUri: redirect.responseUri });
  eq(hexOf(mdoc.encode(walletRedirect)), OID4VP_B261_TRANSCRIPT,
     "B.2.6.1: the wallet's SessionTranscript, byte for byte");

  // B.2.6.2, the Digital Credentials API: origin https://example.com
  // WITHOUT "origin:" and without a trailing slash, dc_api.jwt.
  const dc = { responseMode: "dc_api.jwt", decryptionJwk: OID4VP_B26_JWK,
    origin: "https://example.com", nonce: OID4VP_B26_NONCE };
  eq(hexOf(mdoc.encode([dc.origin, dc.nonce,
    Buffer.from(thumbHex, "hex")])), OID4VP_B262_INFO,
     "B.2.6.2: OpenID4VPDCAPIHandoverInfo, byte for byte");
  t = verifier.mdocSessionTranscript(dc);
  eq(hexOf(mdoc.encode(t.transcript[2])), OID4VP_B262_HANDOVER,
     "B.2.6.2: the Verifier's OpenID4VPDCAPIHandover, byte for byte");
  eq(hexOf(mdoc.encode(t.transcript)), OID4VP_B262_TRANSCRIPT,
     "B.2.6.2: the Verifier's SessionTranscript, byte for byte");
  // The same request answered under dc_api (unencrypted) must NOT be the
  // spec's bytes: its third element is null (B.2.6.2).
  t = verifier.mdocSessionTranscript(Object.assign({}, dc,
    { responseMode: "dc_api" }));
  ok(hexOf(mdoc.encode(t.transcript)) !== OID4VP_B262_TRANSCRIPT &&
     !t.encrypted, "B.2.6.2: dc_api's jwkThumbprint is null");

  // B.3.2: the example SD-JWT VC, its _sd array and Disclosures as
  // printed. Only cnf is replaced (by a holder key that can sign a
  // KB-JWT); no digest covers it. The issuer, https://example.com/issuer,
  // publishes a key made here in its jwt-vc-issuer metadata.
  const B32_VCT = "https://credentials.example.com/identity_credential";
  const B32_ISS = "https://example.com/issuer";
  const disclosures = {
    given_name: "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAi" +
      "Sm9obiJd",
    family_name: "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiw" +
      "gIkRvZSJd",
    birthdate: "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImJpcnRoZGF0ZSIsICIx" +
      "OTQwLTAxLTAxIl0"
  };
  const printed = { given_name: "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
    family_name: "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
    birthdate: "tiTngp9_jhC389UP8_k67MXqoSfiHq3iK6o9un4we_Y" };
  Object.keys(printed).forEach(function (name) {
    eq(sha256b64u(disclosures[name]), printed[name],
       "B.3.2: node's SHA-256 of the " + name + " Disclosure is the " +
       "printed hash");
  });
  const signer = ecPair();
  const holder = ecPair();
  const docs = {};
  docs["https://example.com/.well-known/jwt-vc-issuer/issuer"] =
    { issuer: B32_ISS, jwks: { keys: [Object.assign({ kid: "b32",
      alg: "ES256" }, signer.publicJwk)] } };
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return docs[url] ? Promise.resolve(docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const jwt = nodeJws({ alg: "ES256", typ: "dc+sd-jwt", kid: "b32" }, {
    _sd: ["3oUCnaKt7wqDKuyh-LgQozzfhgb8gO5Ni-RCWsWW2vA",
          "8z8z9X9jUtb99gjejCwFAGz4aqlHf-sCqQ6eM_qmpUQ",
          "Cxq4872UXXngGULT_kl8fdwVFkyK6AJfPZLy7L5_0kI",
          "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
          "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
          "sFcViHN-JG3eTUyBmU4fkwusy5I1SLBhe1jNvKxP5xM",
          "tiTngp9_jhC389UP8_k67MXqoSfiHq3iK6o9un4we_Y",
          "xsKkGJXD1-e3I9zj0YyKNv-lU5YqhsEAF9NhOr8xga4"],
    iss: B32_ISS, iat: 1683000000, exp: 1883000000, vct: B32_VCT,
    _sd_alg: "sha-256", cnf: { jwk: holder.publicJwk } }, signer);
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", responseUri: "https://verifier.example/r",
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: B32_VCT, claims: [["given_name"], ["family_name"],
                             ["birthdate"]] }] }) };
  const r = await run({ fields: { vp_token: { pid: [presentSdJwt(jwt,
    [disclosures.given_name, disclosures.family_name, disclosures.birthdate],
    { aud: clientId, nonce: session.nonce, key: holder })] } },
    session: session, fetchJson: fetchJson });
  allPass(r, "B.3.2: the example SD-JWT VC");
  eq(checkById(r, "pid[0].disclosures").status, "pass");
  eq([r.presentations[0].claims.given_name,
      r.presentations[0].claims.family_name,
      r.presentations[0].claims.birthdate], ["John", "Doe", "1940-01-01"],
     "B.3.2: each printed Disclosure is found by its printed digest");
  log.info("PASS OpenID4VP 1.0's own vectors: Appendix B.2.6.1 and " +
           "B.2.6.2 (thumbprint, Info, Handover, SessionTranscript, by the " +
           "Verifier and the wallet) and B.3.2's Disclosures.");
  log.debug("Leaving openid4vpSpecVectors().");
}

// ---------------------------------------------------------------------------
// Status List Tokens in CWT form (draft-ietf-oauth-status-list-21 section
// 5.2, #471 E5), each assembled HERE byte by byte with tests/
// mdoc_test_issuer.js's CBOR encoder and signed by node's ECDSA over RFC
// 9052 section 4.4's Sig_structure: COSE_Sign1_Tagged (18), type (16)
// application/statuslist+cwt in the protected header, the kid (4), x5chain
// (33) or x5t (34) naming the key, and the Claims Set 2/6/4/65534/65533.
// Then the draft's own bytes: section 5.2's example CWT (signed by a key the
// draft does not publish, so it must be read and NOT relied on), and the
// CBOR StatusList encodings of section 4.3 and Appendix C.1 and C.2,
// carried verbatim as claim 65533.
// ---------------------------------------------------------------------------
// Section 5.2's example, hex as printed.
const TSL_52_CWT =
    "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b63" +
    "7774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f73" +
    "74617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2" +
    "646269747301636c73744a78dadbb918000217015d584093fa4d01032b18c35e2fe1" +
    "101b77fd6cc9440022caa4694450c4e4e9feab4e99d1fa6d9772ce2bf3a12e0323de" +
    "d7c982c5e101a5e67f0cbc1e2b6f57ce99c279";
// Section 4.3's StatusList in CBOR: [0xb9, 0xa3], one bit each.
const TSL_43_CBOR = "a2646269747301636c73744a78dadbb918000217015d";
// Appendix C.1 (1-bit) and C.2 (2-bit), CBOR encoding, as printed.
const TSL_C1_CBOR =
    "a2646269747301636c737458bd78daeddc010dc0200c0041a88249400ad2903e0f4b" +
    "ba00bd93f002beb7a2a2010000a91e09000000000000000000000000000000807296" +
    "04000000000000000000000000000000000000000000000000000000000000000000" +
    "000000000000005c6f4800000000000000fc2c240000000000000000000000be1b12" +
    "000000000000000000ecaa4b000000000000000000000000000000009b0b09000000" +
    "00000000000038de9400000000000000002a30cc010000000080642f0bd8011b";
const TSL_C2_CBOR =
    "a2646269747302636c737459013d78daeddb310d00211000412ea1a04004fe5520ed" +
    "357c28c81d3312b6df68bc65480000000000406e2101000000000000000000000000" +
    "0000000000000000000000000000000000000040795b020000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000" +
    "0080f4ba0400000000000000000000000000406d764a000000000000000000000000" +
    "000000000000000000e0922101000000000000000000000000000000000000fc1312" +
    "00000000000000000000000000000000000000000000000000000000000000c0912e" +
    "01000000000000000000000000000000000000c07d4b020000000000000000000000" +
    "00000000a8614a0000000000000000000000406a1fcd60010c";

// A CWT Status List Token. `o`: claims (a Map of overrides; a value of
// undefined removes the claim), statusListRaw (CBOR bytes spliced in as
// claim 65533 verbatim), prot / unprot (Maps merged over the defaults),
// tags (default [18]), signer (a node private key), mac (a COSE_Mac0).
function cwtStatusList(sub, signer, o) {
  log.debug("Entering cwtStatusList().");
  const opts = o || {};
  const cbor = mdocIssuer.cbor;
  const now = Math.floor(Date.now() / 1000);
  const prot = new Map([[1, -7], [16, "application/statuslist+cwt"]]);
  (opts.prot || new Map()).forEach(function (v, k) {
    if (v === undefined) {
      prot.delete(k);
    } else {
      prot.set(k, v);
    }
  });
  const unprot = new Map([[4, Buffer.from("iss-1")]]);
  (opts.unprot || new Map()).forEach(function (v, k) {
    if (v === undefined) {
      unprot.delete(k);
    } else {
      unprot.set(k, v);
    }
  });
  const claims = new Map([[2, sub], [6, now - 60], [4, now + 3600],
    [65534, 300], [65533, new Map([["bits", 2], ["lst", Buffer.from(
      tokenStatusLst([1, 1, 1, 0, 2, 1, 1, 3], 2), "base64url")]])]]);
  (opts.claims || new Map()).forEach(function (v, k) {
    if (v === undefined) {
      claims.delete(k);
    } else {
      claims.set(k, v);
    }
  });
  let payload;
  if (opts.statusListRaw) {
    claims.delete(65533);
    const entries = [];
    claims.forEach(function (v, k) {
      entries.push(cbor(k), cbor(v));
    });
    payload = Buffer.concat([Buffer.from([0xa0 + claims.size + 1])]
      .concat(entries, [cbor(65533), opts.statusListRaw]));
  } else {
    payload = cbor(claims);
  }
  const protectedBytes = cbor(prot);
  const sig = opts.mac ? Buffer.alloc(32, 9) : nodeCrypto.sign("sha256",
    coseSigStructure(protectedBytes, payload),
    { key: signer, dsaEncoding: "ieee-p1363" });
  let out = [protectedBytes, unprot, payload, sig];
  (opts.tags || (opts.mac ? [17] : [18])).slice().reverse()
    .forEach(function (t) {
      out = new mdocIssuer.Tag(t, out);
    });
  log.debug("Leaving cwtStatusList().");
  return new Uint8Array(cbor(out));
}

async function cwtStatusLists(env) {
  log.debug("Entering cwtStatusLists().");
  const issuer = makeIssuer();
  const fetchJson = function fetchJson(url) {
    log.debug("Entering fetchJson(). " + url);
    log.debug("Leaving fetchJson().");
    return issuer.docs[url] ? Promise.resolve(issuer.docs[url]) :
      Promise.reject(new Error("no such document: " + url));
  };
  const now = Math.floor(Date.now() / 1000);
  const URI = "https://issuer.example/statuslists/cwt";
  const key = issuer.key.privateKey;
  const docs = {};
  const add = function add(name, o, signer) {
    log.debug("Entering add(). " + name);
    docs[URI + name] = cwtStatusList(URI + name, signer || key, o);
    log.debug("Leaving add().");
  };
  add("");
  add("/forged", null, ecPair().privateKey);
  add("/wrongsub", { claims: new Map([[2, URI + "/elsewhere"]]) });
  add("/expired", { claims: new Map([[6, now - 7200], [4, now - 3600]]) });
  add("/noiat", { claims: new Map([[6, undefined]]) });
  add("/tag61", { tags: [61, 18] });
  add("/untagged", { tags: [] });
  add("/notype", { prot: new Map([[16, undefined]]) });
  add("/unprottype", { prot: new Map([[16, undefined]]),
    unprot: new Map([[16, "application/statuslist+cwt"]]) });
  add("/jwttype", { prot: new Map([[16, "application/statuslist+jwt"]]) });
  add("/textlst", { claims: new Map([[65533, new Map([["bits", 2],
    ["lst", tokenStatusLst([0], 2)]])]]) });
  add("/badttl", { claims: new Map([[65534, 0]]) });
  add("/mac", { mac: true });
  add("/agg", { claims: new Map([[65533, new Map([["bits", 2],
    ["lst", Buffer.from(tokenStatusLst([1, 1, 1, 0], 2), "base64url")],
    ["aggregation_uri", "https://issuer.example/aggregation"]])]]) });
  docs[URI + "/served"] = { body: cwtStatusList(URI + "/served", key),
    contentType: "application/statuslist+cwt" };
  docs[URI + "/served-wrong"] = { body: cwtStatusList(URI + "/served-wrong",
    key), contentType: "application/octet-stream" };
  // Section 4.3 and Appendix C.1/C.2's own CBOR, verbatim as claim 65533.
  [["/s43", TSL_43_CBOR], ["/c1", TSL_C1_CBOR], ["/c2", TSL_C2_CBOR]]
    .forEach(function (pair) {
      add(pair[0], { statusListRaw: Buffer.from(pair[1], "hex") });
    });
  // Section 5.2's example: sub https://example.com/statuslists/1, kid
  // "12", a key the draft never publishes.
  const SPEC_URI = "https://example.com/statuslists/1";
  docs[SPEC_URI] = new Uint8Array(Buffer.from(TSL_52_CWT, "hex"));
  const seen = [];
  const fetchText = textFetcher(docs, seen);
  const holder = ecPair();
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", responseUri: "https://verifier.example/r",
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: VCT, claims: [["given_name"]] }] }) };
  async function at(idx, uri) {
    log.debug("Entering at(). " + uri + " " + idx);
    const cred = issueSdJwt(issuer, holder.publicJwk, { payload: { status:
      { status_list: { idx: idx, uri: uri } } } });
    const r = await run({ fields: { vp_token: { pid: [presentSdJwt(cred.jwt,
      [cred.d.given_name], { aud: clientId, nonce: session.nonce,
        key: holder })] } }, session: session, fetchJson: fetchJson,
      fetchText: fetchText });
    log.debug("Leaving at().");
    return r;
  }
  const row = function row(r, id) {
    log.debug("Entering row(). " + id);
    log.debug("Leaving row().");
    return checkById(r, "pid[0].status" + id);
  };
  // idx 3 is VALID, 4 SUSPENDED, 5 INVALID (LSB first).
  let r = await at(3, URI);
  allPass(r, "CWT: VALID");
  eq([row(r, "").status, row(r, ".list").status, row(r, ".signer").status],
     ["pass", "pass", "pass"]);
  ok(row(r, ".list").detail.indexOf("a CWT (COSE_Sign1_Tagged, type " +
     "application/statuslist+cwt), sub (2) is the credential's uri, " +
     "signed (ES256, COSE -7)") === 0, row(r, ".list").detail);
  ok(/ttl 300s/.test(row(r, ".list").detail), row(r, ".list").detail);
  ok(/the same key.*kid "iss-1"/.test(row(r, ".signer").detail),
     "the COSE kid (4) names the credential's key: " +
     row(r, ".signer").detail);
  eq(seen[0].accept, "application/statuslist+jwt, " +
     "application/statuslist+cwt", "both forms are asked for (section 8.1)");
  r = await at(5, URI);
  failsOnly(r, ["pid[0].status", "status"], "CWT: INVALID");
  ok(/is 1 \(INVALID\).*revoked/.test(row(r, "").detail), row(r, "").detail);
  r = await at(4, URI);
  failsOnly(r, ["pid[0].status", "status"], "CWT: SUSPENDED");
  ok(/is 2 \(SUSPENDED\)/.test(row(r, "").detail), row(r, "").detail);
  r = await at(40, URI);
  failsOnly(r, ["pid[0].status", "status"], "CWT: idx past the end");
  r = await at(3, URI + "/forged");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: a bad signature");
  ok(/does NOT verify/.test(row(r, ".list").detail), row(r, ".list").detail);
  eq([row(r, "").status, row(r, ".signer").status], ["skip", "skip"],
     "CWT: an unverified list is neither relied on nor linked");
  r = await at(3, URI + "/wrongsub");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: sub mismatch");
  ok(row(r, ".list").detail.indexOf("sub (2) is \"" + URI +
     "/elsewhere\", not the uri") !== -1, row(r, ".list").detail);
  eq(row(r, "").status, "skip");
  r = await at(3, URI + "/expired");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: expired (4)");
  ok(/expired at/.test(row(r, ".list").detail));
  r = await at(3, URI + "/noiat");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: no iat (6)");
  r = await at(3, URI + "/tag61");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: in the CWT tag");
  ok(/CWT tag \(61\), which section 5\.2 says it MUST NOT be/.test(
    row(r, ".list").detail), row(r, ".list").detail);
  r = await at(3, URI + "/untagged");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: untagged");
  ok(/not tagged COSE_Sign1_Tagged \(18\)/.test(row(r, ".list").detail));
  r = await at(3, URI + "/notype");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: no type (16)");
  r = await at(3, URI + "/unprottype");
  failsOnly(r, ["pid[0].status.list", "status"],
            "CWT: type (16) unprotected");
  ok(/unprotected header/.test(row(r, ".list").detail));
  r = await at(3, URI + "/jwttype");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: the JWT's type");
  r = await at(0, URI + "/textlst");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: lst as text");
  ok(/byte string/.test(row(r, ".list").detail));
  eq(row(r, "").status, "skip");
  r = await at(3, URI + "/badttl");
  failsOnly(r, ["pid[0].status.list", "status"], "CWT: ttl 0");
  r = await at(3, URI + "/agg");
  allPass(r, "CWT: an aggregation_uri");
  ok(/aggregation_uri is https:\/\/issuer\.example\/aggregation/.test(
    row(r, ".list").detail), row(r, ".list").detail);
  r = await at(3, URI + "/mac");
  allPass(r, "CWT: COSE_Mac0 is reported, not judged");
  eq([row(r, ".list").status, row(r, "").status], ["skip", "skip"]);
  ok(/COSE_Mac0/.test(row(r, ".list").detail), row(r, ".list").detail);
  r = await at(3, URI + "/served");
  allPass(r, "CWT: served as application/statuslist+cwt");
  ok(!/served as/.test(row(r, ".list").detail));
  r = await at(3, URI + "/served-wrong");
  allPass(r, "CWT: served under another media type, reported");
  ok(/served as application\/octet-stream, not application\/statuslist\+cwt/
    .test(row(r, ".list").detail), row(r, ".list").detail);

  // The draft's own CBOR StatusLists, as claim 65533.
  const cases = [
    ["/s43", 0, 1, "fail"], ["/s43", 1, 0, "pass"], ["/s43", 15, 1, "fail"],
    ["/c1", 0, 1, "fail"], ["/c1", 1, 0, "pass"], ["/c1", 1993, 1, "fail"],
    ["/c1", 25460, 1, "fail"], ["/c1", 1000345, 1, "fail"],
    ["/c1", 1048575, 0, "pass"],
    ["/c2", 0, 1, "fail"], ["/c2", 1993, 2, "fail"], ["/c2", 2, 0, "pass"],
    ["/c2", 159495, 3, "skip"], ["/c2", 1000345, 3, "skip"],
    ["/c2", 645645, 2, "fail"]
  ];
  for (const c of cases) {
    r = await at(c[1], URI + c[0]);
    const what = "CWT " + c[0] + "[" + c[1] + "]";
    eq(row(r, ".list").status, "pass", what + ": " + row(r, ".list").detail);
    eq(row(r, "").status, c[3], what + ": " + row(r, "").detail);
    ok(row(r, "").detail.indexOf(" is " + c[2] + " (") !== -1,
       what + " is " + c[2] + " in the draft: " + row(r, "").detail);
  }

  // Section 5.2's example, read as printed. Everything but the signature
  // checks out (it expires in 2042); the key behind kid "12" is not
  // published, so the value is reported and not relied on.
  r = await at(0, SPEC_URI);
  failsOnly(r, ["pid[0].status.list", "status"],
            "section 5.2's example: no published key");
  ok(/^the CWT Status List Token: the signature does NOT verify with /.test(
    row(r, ".list").detail) && !/sub|type|tag|iat|ttl/.test(
    row(r, ".list").detail.split("verify with")[0]), row(r, ".list").detail);
  eq(row(r, "").status, "skip");
  ok(row(r, "").detail.indexOf("idx 0 of " + SPEC_URI + " is 1 " +
     "(INVALID), but the Status List Token did not verify") === 0,
     row(r, "").detail);

  // mso_mdoc: the CWT names the credential's document signer by x5chain
  // (33), and by x5t (34) over SHA-256 (-16) — section 11.3's COSE routes.
  const auth = await mdocIssuer.authority("cwt");
  const mdocUri = "https://issuer.example/statuslists/mdoc-cwt";
  const one = function one(name, o, signer) {
    log.debug("Entering one(). " + name);
    log.debug("Leaving one().");
    return cwtStatusList(mdocUri + name, signer || auth.dsKey,
      Object.assign({ unprot: new Map([[4, undefined]]) }, o));
  };
  const mdocDocs = {};
  mdocDocs[mdocUri] = one("", { prot: new Map([[33, auth.dsDer]]) });
  mdocDocs[mdocUri + "/x5t"] = one("/x5t", { prot: new Map([[34, [-16,
    nodeCrypto.createHash("sha256").update(auth.dsDer).digest()]]]) });
  mdocDocs[mdocUri + "/forged"] = one("/forged",
    { prot: new Map([[33, auth.dsDer]]) }, ecPair().privateKey);
  const device = ecPair();
  const nonce = verifier.randomToken();
  const mSession = { nonce: nonce, responseMode: "dc_api", origin: ORIGIN,
    trustAnchors: [auth.iacaPem],
    dcql: verifier.buildDcql({ queries: [{ id: "mdl", format: "mso_mdoc",
      doctype: mdocIssuer.DOCTYPE, claims: [[mdocIssuer.NS,
                                             "given_name"]] }] }) };
  async function mdocAt(status) {
    log.debug("Entering mdocAt().");
    const cred = issueMdocHere(auth, device.publicJwk,
                               { given_name: "Erika" }, status);
    const res = await run({ fields: { vp_token: { mdl: [deviceResponseHere(
      cred, device, dcTranscript(ORIGIN, nonce, null))] } },
      session: mSession, fetchText: textFetcher(mdocDocs) });
    log.debug("Leaving mdocAt().");
    return res;
  }
  r = await mdocAt({ idx: 3, uri: mdocUri });
  allPass(r, "mdoc, a CWT list by x5chain, VALID");
  eq(checkById(r, "mdl[0].status").status, "pass");
  ok(/the same key.*the same x5c/.test(
    checkById(r, "mdl[0].status.signer").detail),
     checkById(r, "mdl[0].status.signer").detail);
  r = await mdocAt({ idx: 5, uri: mdocUri });
  failsOnly(r, ["mdl[0].status", "status"], "mdoc, a CWT list, INVALID");
  r = await mdocAt({ idx: 3, uri: mdocUri + "/x5t" });
  allPass(r, "mdoc, a CWT list by x5t (SHA-256)");
  ok(/x5t#S256 that is the credential's leaf/.test(
    checkById(r, "mdl[0].status.signer").detail),
     checkById(r, "mdl[0].status.signer").detail);
  r = await mdocAt({ idx: 3, uri: mdocUri + "/forged" });
  failsOnly(r, ["mdl[0].status.list", "status"],
            "mdoc, a CWT list not signed by its x5chain's key");
  log.info("PASS CWT Status List Tokens (section 5.2): VALID, INVALID, " +
           "SUSPENDED, every defect of the CWT, a COSE_Mac0, section " +
           "5.2's example and the CBOR vectors of section 4.3 and " +
           "Appendix C.1/C.2, for dc+sd-jwt and mso_mdoc.");
  log.debug("Leaving cwtStatusLists().");
}

// #471 E4: wallet_metadata from a request_uri POST (OpenID4VP 1.0 section
// 5.10) is honoured where this Verifier can, and reported where it cannot.
// The encrypted Request Object is opened by the `jose` library, which
// shares no code with this tree.
async function walletMetadataHonoured(env) {
  log.debug("Entering walletMetadataHonoured().");
  const id = env.identity;
  const base = { keyJwk: id.privateJwk, prefix: "x509_hash",
                 responseMode: "direct_post", formats: ["dc+sd-jwt"] };
  // Section 5.10's own example, exactly as it travels: form-decoded, it is
  // a JSON string listing ES256 for dc+sd-jwt.
  const example = decodeURIComponent(
    "%7B%22vp_formats_supported%22%3A%7B%22dc%2Bsd-jwt%22%3A%7B%22sd-jwt_a" +
    "lg_values%22%3A%20%5B%22ES256%22%5D%2C%22kb-jwt_alg_values%22%3A%20%5B" +
    "%22ES256%22%5D%7D%7D%7D");
  let plan = verifier.planForWalletMetadata(example, base);
  eq([plan.signAlg, plan.encryptTo, plan.findings], ["ES256", null, []],
     "E4: section 5.10's example asks nothing this request does not do");
  plan = verifier.planForWalletMetadata(example, Object.assign({}, base,
    { formats: ["mso_mdoc"] }));
  ok(plan.findings.length === 1 && /mso_mdoc.*not in the wallet's vp_formats_supported/
       .test(plan.findings[0].text), "E4: a format the wallet lacks: " +
     JSON.stringify(plan.findings));
  plan = verifier.planForWalletMetadata("{not json", base);
  ok(/not JSON/.test(plan.findings[0].text), "E4: unreadable metadata");
  eq(verifier.planForWalletMetadata(undefined, base).findings, [],
     "E4: no wallet_metadata, nothing to say");
  // request_object_signing_alg_values_supported.
  plan = verifier.planForWalletMetadata({
    request_object_signing_alg_values_supported: ["ES384", "ES256"] }, base);
  eq(plan.signAlg, "ES256", "E4: the key's alg the wallet lists");
  plan = verifier.planForWalletMetadata({
    request_object_signing_alg_values_supported: ["PS256"] }, base);
  ok(plan.signAlg === "ES256" && plan.findings[0].level === "warn" &&
     /signs only ES256; signed with ES256 anyway/.test(plan.findings[0].text),
     "E4: no common signing alg is reported: " +
     JSON.stringify(plan.findings));
  eq(verifier.signingAlgsFor({ crv: "Ed25519" }), ["Ed25519", "EdDSA"]);
  // client_id_prefixes_supported.
  plan = verifier.planForWalletMetadata({
    client_id_prefixes_supported: ["x509_san_dns"] }, base);
  ok(/does not include x509_hash/.test(plan.findings[0].text),
     "E4: a prefix the wallet lacks: " + JSON.stringify(plan.findings));
  // authorization_encryption_*: the offer is narrowed to what both do.
  const jwt = Object.assign({}, base, { responseMode: "direct_post.jwt",
                                        responseAlg: "ECDH-ES" });
  plan = verifier.planForWalletMetadata({
    authorization_encryption_alg_values_supported: ["ECDH-ES"],
    authorization_encryption_enc_values_supported: ["A256GCM"] }, jwt);
  eq(plan.encValues, ["A256GCM"], "E4: enc narrowed to both sides'");
  plan = verifier.planForWalletMetadata({
    authorization_encryption_alg_values_supported: ["RSA-OAEP-256"],
    authorization_encryption_enc_values_supported: ["A192GCM"] }, jwt);
  eq(plan.encValues, ["A128GCM", "A256GCM"], "E4: nothing shared, " +
     "offered unchanged");
  eq(plan.findings.map(function (f) {
    return f.level;
  }), ["warn", "warn"], "E4: both mismatches reported");
  // jwks: the Request Object is signed, then encrypted to the wallet's key.
  const walletKey = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "P-256" });
  const walletPub = Object.assign(walletKey.publicKey.export(
    { format: "jwk" }), { kid: "wallet-enc-1", use: "enc" });
  const sigOnly = Object.assign({}, walletPub, { kid: "wallet-sig",
                                                 use: "sig" });
  plan = verifier.planForWalletMetadata({ jwks: { keys: [sigOnly,
    walletPub] } }, base);
  eq([plan.encryptTo && plan.encryptTo.kid, plan.requestEncAlg,
      plan.requestEnc], ["wallet-enc-1", "ECDH-ES", "A256GCM"],
     "E4: the first key not for signing, ECDH-ES / A256GCM");
  const claims = verifier.requestObjectClaims({
    clientId: verifier.clientIdFor("x509_hash", id, {}),
    responseUri: "https://verifier.example/response",
    responseMode: "direct_post", nonce: "n-e4", state: "s-e4",
    walletNonce: "wn-e4",
    dcql: verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
      vct: VCT, claims: [["given_name"]] }] }) });
  const signed = await verifier.signRequestObject({ claims: claims,
    identity: id, algId: plan.signAlg });
  const sealed = await verifier.encryptRequestObject(signed, plan);
  eq(sealed.split(".").length, 5, "E4: a compact JWE");
  const jose = await import("jose");
  const opened = await jose.compactDecrypt(sealed,
    await jose.importJWK(walletKey.privateKey.export({ format: "jwk" }),
                         "ECDH-ES"));
  eq([opened.protectedHeader.alg, opened.protectedHeader.enc,
      opened.protectedHeader.cty, opened.protectedHeader.kid],
     ["ECDH-ES", "A256GCM", "JWT", "wallet-enc-1"],
     "E4: jose reads the header RFC 9101 section 4 and RFC 7519 5.2 ask for");
  eq(new TextDecoder().decode(opened.plaintext), signed,
     "E4: jose opens it to the signed Request Object");
  const inner = await jose.compactVerify(signed, await jose.importX509(
    "-----BEGIN CERTIFICATE-----\n" + id.x5c[0] +
    "\n-----END CERTIFICATE-----", "ES256"));
  eq(JSON.parse(new TextDecoder().decode(inner.payload)).wallet_nonce,
     "wn-e4", "E4: and the signature inside verifies, carrying wallet_nonce");
  // A key nothing here encrypts to, and enc values nothing here does.
  plan = verifier.planForWalletMetadata({ jwks: { keys: [{ kty: "oct",
    k: "AAAA" }] } }, base);
  ok(!plan.encryptTo && /none is one this Verifier can encrypt to/.test(
     plan.findings[0].text), "E4: no usable key: " +
     JSON.stringify(plan.findings));
  plan = verifier.planForWalletMetadata({ jwks: { keys: [walletPub] },
    request_object_encryption_enc_values_supported: ["XC20P"] }, base);
  ok(!plan.encryptTo && /names no content encryption/.test(
     plan.findings[0].text), "E4: no usable enc");
  let refused = "";
  try {
    await verifier.signRequestObject({ claims: claims, identity: id,
                                       algId: "ES384" });
  } catch (e) {
    refused = e.message;
  }
  ok(/cannot sign ES384/.test(refused), "E4: an alg the key cannot make " +
     "is refused, not mislabelled: " + refused);
  log.debug("Leaving walletMetadataHonoured().");
}

// #471 E3a: the request options OpenID4VP 1.0 defines and the page now
// offers. Signatures over the new request keys are checked by jose.
async function requestOptions(env) {
  log.debug("Entering requestOptions().");
  const jose = await import("jose");
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", vct: VCT, claims: [["given_name"]] }] });
  for (const [keyAlg, alg] of [["ec-p384", "ES384"], ["ed25519", "EdDSA"]]) {
    const id = await verifier.makeVerifierIdentity({
      dnsName: "verifier.example", keyAlg: keyAlg });
    const claims = verifier.requestObjectClaims({
      clientId: verifier.clientIdFor("x509_hash", id, {}),
      responseUri: "https://verifier.example/response",
      responseMode: "direct_post", nonce: "n-k", state: "s-k", dcql: dcql });
    const compact = await verifier.signRequestObject({ claims: claims,
                                                       identity: id });
    const header = JSON.parse(Buffer.from(compact.split(".")[0],
                                          "base64url"));
    eq(header.alg, alg, "E3: a " + keyAlg + " request key signs " + alg);
    const leafKey = new nodeCrypto.X509Certificate(id.leafPem).publicKey;
    const checked = await jose.compactVerify(compact, leafKey);
    eq(JSON.parse(new TextDecoder().decode(checked.payload)).nonce, "n-k",
       "E3: jose verifies the " + keyAlg + " Request Object against its " +
       "certificate");
  }
  let refused = "";
  try {
    await verifier.makeVerifierIdentity({ dnsName: "v.example",
                                          keyAlg: "rsa-2048" });
  } catch (e) {
    refused = e.message;
  }
  ok(/ec-p256, ec-p384 or ed25519/.test(refused), "E3: other keys refused");
  // scope instead of dcql_query (section 5.1: one, never both).
  const id = env.identity;
  const base = { clientId: verifier.clientIdFor("x509_hash", id, {}),
    responseUri: "https://verifier.example/response",
    responseMode: "direct_post", nonce: "n", state: "s", dcql: dcql };
  let claims = verifier.requestObjectClaims(Object.assign({}, base,
    { scope: "com.example.healthCardCredential_presentation" }));
  ok(claims.scope === "com.example.healthCardCredential_presentation" &&
     !("dcql_query" in claims), "E3: scope replaces dcql_query");
  // verifier_info, section 5.1's own example.
  const info = [{ format: "jwt", data: "eyJhbGciOiJFUzI1...EF0RBtvPClL71TW" +
    "HlIQ", credential_ids: ["pid"] }];
  claims = verifier.requestObjectClaims(Object.assign({}, base,
    { verifierInfo: info }));
  eq(claims.verifier_info, info, "E3: verifier_info is carried");
  for (const bad of [[], [{ data: "x" }], [{ format: "jwt" }],
                     [{ format: "jwt", data: "x", credential_ids: ["no"] }]]) {
    let why = "";
    try {
      verifier.requestObjectClaims(Object.assign({}, base,
        { verifierInfo: bad }));
    } catch (e) {
      why = e.message;
    }
    ok(/verifier_info/.test(why), "E3: refused " + JSON.stringify(bad));
  }
  // values, claim ids and claim_sets (section 6.4.1's example shape) and
  // intent_to_retain (Appendix B.2.4).
  const q = verifier.buildDcql({ queries: [{ id: "pid", format: "dc+sd-jwt",
    vct: VCT, claims: [{ id: "a", path: ["last_name"] },
                       { id: "b", path: ["postal_code"],
                         values: ["90210", "90211"] },
                       { id: "c", path: ["address", "street_address"] }],
    claimSets: [["a", "c"], ["b"]] }] }).credentials[0];
  eq([q.claims[1].values, q.claim_sets], [["90210", "90211"],
     [["a", "c"], ["b"]]], "E3: values and claim_sets");
  for (const spec of [
    { claims: [{ path: ["x"] }], claimSets: [["x"]] },
    { claims: [{ id: "a", path: ["x"] }], claimSets: [["z"]] },
    { claims: [{ id: "a", path: ["x"], values: [] }] },
    { claims: [{ id: "a", path: ["x"], values: [1.5] }] },
    { claims: [{ id: "a", path: ["x"], intentToRetain: true }] }]) {
    let why = "";
    try {
      verifier.buildDcql({ queries: [Object.assign({ id: "pid",
        format: "dc+sd-jwt", vct: VCT }, spec)] });
    } catch (e) {
      why = e.message;
    }
    ok(why.length > 0, "E3: refused " + JSON.stringify(spec));
  }
  const m = verifier.buildDcql({ queries: [{ id: "mdl", format: "mso_mdoc",
    doctype: "org.iso.18013.5.1.mDL",
    claims: [{ path: ["org.iso.18013.5.1", "family_name"],
               intentToRetain: false }] }] }).credentials[0];
  eq(m.claims[0].intent_to_retain, false, "E3: intent_to_retain on mdoc");
  log.debug("Leaving requestOptions().");
}

async function main() {
  log.debug("Entering main().");
  randomTokens();
  dcqlBuilder();
  const env = await identityAndRequest();
  await persistentIdentity();
  await ipHosts();
  requestUris();
  oneDeclarationPerName();
  await sdJwtRoundTrip(env);
  await mdocRoundTrip(env);
  await jwtVcJsonRoundTrip(env);
  await ldpVcRoundTrip(env);
  await prefixesAndWalletNonce(env);
  await dcApi(env);
  await openid4vpSpecVectors(env);
  await tokenStatusLists(env);
  await tokenStatusSpecVectors(env);
  await cwtStatusLists(env);
  await statusSignerLinks(env);
  await bitstringStatusLists(env);
  await cryptosuites(env);
  await securityFindings(env);
  await jwtVcJsonFindings(env);
  await didIssuerKeys(env);
  await sdJwtFindings(env);
  await typeValueFindings(env);
  await mdocFindings(env);
  await proofContexts(env);
  await requestSideFindings(env);
  await walletMetadataHonoured(env);
  await requestOptions(env);
  log.info("vp_verifier_engine: " + assertions + " assertions, " +
           checksSeen + " Verifier checks examined.");
  // A floor, so a refactor that silently stops running a section cannot
  // pass by checking less.
  assert.ok(assertions >= 1440, "only " + assertions + " assertions ran; " +
            "expected at least 1440");
  assert.ok(checksSeen >= 5700, "only " + checksSeen + " Verifier checks " +
            "were examined; expected at least 5700");
  log.info("vp_verifier_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("vp_verifier_engine FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
