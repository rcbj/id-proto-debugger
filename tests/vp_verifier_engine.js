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
//     signed here, and ldp_vc bbs-2023 inside an ecdsa-jcs-2019 VP;
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
//   * Data Integrity: the W3C's own eddsa-jcs-2022 vector, and credentials,
//     VPs and status list credentials signed here in five suite/curve
//     combinations (JCS written here, RDFC by jsonld).
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
const bbs = load("bbs.js");
const didLib = load("did.js");

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
  ok(result.ok, what + ": ok must be true when nothing failed");
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
  log.debug("Leaving failsOnly().");
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
  [[{ queries: [] }, /at least one/],
   [{ queries: [{ format: "dc+sd-jwt" }] }, /no id/],
   [{ queries: [{ id: "a b", format: "dc+sd-jwt" }] }, /alphanumeric/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt" },
                { id: "a", format: "mso_mdoc" }] }, /twice/],
   [{ queries: [{ id: "a", format: "vc+sd-jwt" }] }, /unknown format/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", claims: [[]] }] },
    /non-empty/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt", claims: [[""]] }] },
    /segment/],
   [{ queries: [{ id: "a", format: "mso_mdoc", claims: [["ns"]] }] },
    /namespace, element/],
   [{ queries: [{ id: "a", format: "dc+sd-jwt" }],
      credentialSets: [{ options: [["b"]] }] }, /no credential query/]
  ].forEach(function (c) {
    assertions++;
    assert.throws(function () {
      verifier.buildDcql(c[0]);
    }, c[1], "buildDcql must refuse " + JSON.stringify(c[0]));
  });
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
    format: "dc+sd-jwt", claims: [["given_name"]] }] });
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
  const header = { alg: "ES256", typ: o.typ || "dc+sd-jwt", kid: "iss-1" };
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
  failsOnly(r, ["response.decrypt"], "a JWE to another Verifier's key");

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
                claims: [["given_name"]] }] }) });
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
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    state: "st", responseMode: "direct_post.jwt",
    responseUri: "https://verifier.example/response", dcql: dcql,
    decryptionJwk: env.enc.privateJwk };
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
  let r = await send(session, built.presentation);
  allPass(r, "mso_mdoc over direct_post.jwt");
  ["mdl[0].mdoc.element-digests", "mdl[0].mdoc.issuer-signature",
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
async function ldpVcRoundTrip(env) {
  log.debug("Entering ldpVcRoundTrip().");
  const sk = bbs.keyGen(nodeCrypto.randomBytes(32));
  const pk = bbs.secretKeyToPublicKey(sk);
  const vm = "https://issuer.example/bbs/keys/1";
  const docs = {};
  docs[vm] = { id: vm, type: "Multikey", controller: "https://issuer.example",
               publicKeyMultibase: "u" + b64u(pk) };
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
    { verificationMethod: vm, created: "2026-01-01T00:00:00Z" }, sk, pk);
  const clientId = verifier.clientIdFor("x509_hash", env.identity);
  const nonce = verifier.randomToken();
  async function envelopeFor(n, indexes) {
    log.debug("Entering envelopeFor().");
    const derived = await bbs2023.deriveProof(issued.credential, pk, indexes,
                                              new TextEncoder().encode(n));
    const proofOptions = Object.assign({ "@context":
      issued.credential["@context"] }, issued.credential.proof);
    delete proofOptions.proofValue;
    log.debug("Leaving envelopeFor().");
    return { cryptosuite: "bbs-2023", proof: bbs2023.bytesToB64u(
      derived.proof), disclosedIndexes: derived.disclosedIndexes,
      disclosedStatements: derived.disclosedStatements,
      proofOptions: proofOptions };
  }
  const all = issued.statements.map(function (s, i) {
    return i;
  });
  const dcql = verifier.buildDcql({ queries: [{ id: "ld", format: "ldp_vc",
    claims: [["credentialSubject", "given_name"]] }] });
  const session = { clientId: clientId, nonce: nonce, state: "st",
    responseMode: "direct_post", dcql: dcql,
    responseUri: "https://verifier.example/response" };
  async function send(s, element) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return run({ fields: vp.formEncode({ vp_token: { ld: [element] },
                 state: "st" }), session: s, fetchJson: fetchJson });
  }
  const wrapped = await vp.ldpVerifiablePresentation({
    credential: await envelopeFor(nonce, all), holder: holderDid,
    privateJwk: holder.privateJwk, nonce: nonce, aud: clientId });
  let r = await send(session, wrapped);
  allPass(r, "ldp_vc bbs-2023 in an ecdsa-jcs-2019 VP");
  ["ld[0].vp.proof", "ld[0].vp.challenge", "ld[0].vp.domain",
   "ld[0].bbs.proof", "ld[0].vp.binding", "ld[0].claims"].forEach(
    function (id) {
      ok(checkById(r, id) && checkById(r, id).status === "pass",
         id + " must pass: " + JSON.stringify(checkById(r, id)));
    });
  r = await send(Object.assign({}, session, { nonce: "other" }), wrapped);
  failsOnly(r, ["ld[0].bbs.proof", "ld[0].vp.challenge"],
            "ldp_vc, another nonce (both the BBS presentation header and " +
            "the VP challenge carry it)");
  r = await send(Object.assign({}, session, { clientId: "x509_hash:x" }),
                 wrapped);
  failsOnly(r, ["ld[0].vp.domain"], "ldp_vc, another Verifier");
  const forgedVp = JSON.parse(JSON.stringify(wrapped));
  forgedVp.holder = holderDid;
  const sts = forgedVp.verifiableCredential[0].disclosedStatements;
  const at = sts.findIndex(function (st) {
    return st.indexOf('"Erika"') !== -1;
  });
  ok(at !== -1, "a disclosed statement carries the given name");
  sts[at] = sts[at].replace('"Erika"', '"Mallory"');
  r = await send(session, forgedVp);
  ok(failedIds(r).indexOf("ld[0].bbs.proof") !== -1 &&
     failedIds(r).indexOf("ld[0].vp.proof") !== -1,
     "an altered statement must fail the BBS proof and the holder proof " +
     "over it: " + JSON.stringify(failedIds(r)));
  const bare = await envelopeFor(nonce, all);
  r = await send(session, bare);
  failsOnly(r, ["ld[0].vp.proof"], "ldp_vc, a bare envelope where holder " +
            "binding is required");
  const otherSuite = JSON.parse(JSON.stringify(wrapped));
  otherSuite.proof.cryptosuite = "eddsa-rdfc-2022";
  r = await send(session, otherSuite);
  failsOnly(r, ["ld[0].vp.proof", "ld[0].vp.binding"], "a P-256 proof " +
            "relabelled eddsa-rdfc-2022 (that suite needs an Ed25519 key)");
  ok(/Ed25519/.test(checkById(r, "ld[0].vp.proof").detail),
     checkById(r, "ld[0].vp.proof").detail);
  const sdSuite = JSON.parse(JSON.stringify(wrapped));
  sdSuite.proof.cryptosuite = "ecdsa-sd-2023";
  r = await send(session, sdSuite);
  eq(checkById(r, "ld[0].vp.proof").status, "skip",
     "ecdsa-sd-2023 is a skip that says why");
  ok(/ecdsa-sd-2023 is not verified/.test(
     checkById(r, "ld[0].vp.proof").detail));
  log.info("PASS ldp_vc: bbs-2023 derived proof and ecdsa-jcs-2019 holder " +
           "proof.");
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
    format: "dc+sd-jwt", claims: [["given_name"]] }] });
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

function issueMdocHere(auth, devicePublicJwk, elements, status) {
  log.debug("Entering issueMdocHere().");
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
    digests.set(it.digestID, nodeCrypto.createHash("sha256")
      .update(cbor(new Tag(24, it.bytes))).digest());
  });
  const mso = {
    version: "1.0", digestAlgorithm: "SHA-256",
    valueDigests: new Map([[mdocIssuer.NS, digests]]),
    deviceKeyInfo: { deviceKey: new Map([[1, 2], [-1, 1],
      [-2, Buffer.from(devicePublicJwk.x, "base64url")],
      [-3, Buffer.from(devicePublicJwk.y, "base64url")]]) },
    docType: mdocIssuer.DOCTYPE,
    validityInfo: { signed: tdate(now), validFrom: tdate(now),
      validUntil: tdate(new Date(now.getTime() + 30 * 86400000)) }
  };
  if (status) mso.status = { status_list: status };
  const payload = cbor(new Tag(24, cbor(mso)));
  const protectedBytes = cbor(new Map([[1, -7]]));
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

function deviceResponseHere(cred, device, transcript) {
  log.debug("Entering deviceResponseHere().");
  const Tag = mdocIssuer.Tag;
  const cbor = mdocIssuer.cbor;
  const nsBytes = cbor(new Map());
  const auth = cbor(new Tag(24, cbor(["DeviceAuthentication", transcript,
    cred.docType, new Tag(24, nsBytes)])));
  const protectedBytes = cbor(new Map([[1, -7]]));
  const sig = nodeCrypto.sign("sha256", coseSigStructure(protectedBytes,
    auth), { key: device.privateKey, dsaEncoding: "ieee-p1363" });
  const doc = new Map([
    ["docType", cred.docType],
    ["issuerSigned", new Map([
      ["nameSpaces", new Map([[mdocIssuer.NS, cred.items.map(function (it) {
        return new Tag(24, it.bytes);
      })]])],
      ["issuerAuth", cred.issuerAuth]])],
    ["deviceSigned", new Map([
      ["nameSpaces", new Tag(24, nsBytes)],
      ["deviceAuth", new Map([["deviceSignature",
        [protectedBytes, new Map(), null, sig]]])]])]
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
  await rejects(function () {
    return verifier.dcApiRequest({ multisigned: true, claims: signedClaims,
      identity: env.identity });
  }, /multisigned/);
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
                     origin: ORIGIN };
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
  docs[URI + "/cwt"] = "d2845843a1012618";
  const seen = [];
  const fetchText = textFetcher(docs, seen);
  const holder = ecPair();
  const dcql = verifier.buildDcql({ queries: [{ id: "pid",
    format: "dc+sd-jwt", claims: [["given_name"]] }] });
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
  ok(seen.length && /statuslist\+jwt/.test(seen[0].accept),
     "the list is asked for as application/statuslist+jwt");
  r = await at({ idx: 5, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "Token Status List, INVALID");
  ok(/INVALID.*revoked/.test(checkById(r, "pid[0].status").detail));
  r = await at({ idx: 4, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "Token Status List, SUSPENDED");
  ok(/SUSPENDED.*suspended/.test(checkById(r, "pid[0].status").detail));
  r = await at({ idx: 7, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "an application-specific value");
  ok(/application-specific/.test(checkById(r, "pid[0].status").detail));
  r = await at({ idx: 40, uri: URI });
  failsOnly(r, ["pid[0].status", "status"], "idx past the end of the list");
  r = await at({ idx: 3, uri: URI + "/forged" });
  failsOnly(r, ["pid[0].status.list", "status"],
            "a Status List Token signed by somebody else");
  eq(checkById(r, "pid[0].status").status, "skip",
     "a value from an unverified list is not relied on");
  ok(/does NOT verify/.test(checkById(r, "pid[0].status.list").detail));
  r = await at({ idx: 3, uri: URI + "/wrongsub" });
  failsOnly(r, ["pid[0].status.list", "status"], "sub is not the uri");
  r = await at({ idx: 3, uri: URI + "/typ" });
  failsOnly(r, ["pid[0].status.list", "status"], "typ is not statuslist+jwt");
  r = await at({ idx: 3, uri: URI + "/expired" });
  failsOnly(r, ["pid[0].status.list", "status"], "an expired list");
  r = await at({ idx: 3, uri: URI + "/missing" });
  failsOnly(r, ["pid[0].status.list", "status"], "a list that will not load");
  r = await at({ idx: 3, uri: URI + "/cwt" });
  allPass(r, "a CWT Status List Token");
  eq(checkById(r, "pid[0].status.list").status, "skip");
  ok(/CWT/.test(checkById(r, "pid[0].status.list").detail));
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
    dcql: verifier.buildDcql({ queries: [{ id: "mdl", format: "mso_mdoc",
      claims: [[NS, "given_name"]] }] }) };
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
  r = await mdocAt({ idx: 1, uri: mdocUri });
  failsOnly(r, ["mdl[0].status", "status"], "mdoc, INVALID (bit 1 of 0x02)");
  r = await mdocAt({ idx: 0, uri: mdocUri + "/forged" });
  failsOnly(r, ["mdl[0].status.list", "status"],
            "mdoc, a list not signed by the x5c's key");
  r = await mdocAt(null);
  eq(checkById(r, "mdl[0].status").status, "skip", "mdoc, no status");
  log.info("PASS the IETF Token Status List: VALID, INVALID, SUSPENDED, " +
           "and every defect of the list, for dc+sd-jwt and mso_mdoc.");
  log.debug("Leaving tokenStatusLists().");
}

async function bitstringStatusLists(env) {
  log.debug("Entering bitstringStatusLists().");
  const issuer = ecPair();
  const issuerDid = didJwk(issuer.publicJwk);
  const holder = ecPair();
  const holderDid = didJwk(holder.publicJwk);
  const now = Math.floor(Date.now() / 1000);
  const LIST = "https://issuer.example/bsl/";
  const listVc = function listVc(name, purpose, encodedList, signer) {
    log.debug("Entering listVc().");
    log.debug("Leaving listVc().");
    return nodeJws({ alg: "ES256", typ: "vc+jwt", kid: issuerDid + "#0" }, {
      iss: issuerDid, iat: now - 60, exp: now + 3600,
      vc: { "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: LIST + name, type: ["VerifiableCredential",
          "BitstringStatusListCredential"], issuer: issuerDid,
        credentialSubject: { id: LIST + name + "#list",
          type: "BitstringStatusList", statusPurpose: purpose,
          encodedList: encodedList } } }, signer || issuer);
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
    format: "jwt_vc_json", claims: [["credentialSubject", "given_name"]] }] });
  const session = { clientId: clientId, nonce: verifier.randomToken(),
    responseMode: "direct_post", dcql: dcql };
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
      session: session, fetchText: textFetcher(docs) });
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
  r = await at(entry("msg", "message", 3, { statusSize: 2,
    statusMessage: [{ status: "0x0", message: "pending" },
                    { status: "0x2", message: "under review" }] }));
  allPass(r, "a message entry");
  ok(/under review/.test(checkById(r, "w3c[0].vc.status.message").detail),
     checkById(r, "w3c[0].vc.status.message").detail);
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

async function main() {
  log.debug("Entering main().");
  randomTokens();
  dcqlBuilder();
  const env = await identityAndRequest();
  requestUris();
  await sdJwtRoundTrip(env);
  await mdocRoundTrip(env);
  await jwtVcJsonRoundTrip(env);
  await ldpVcRoundTrip(env);
  await prefixesAndWalletNonce(env);
  await dcApi(env);
  await tokenStatusLists(env);
  await bitstringStatusLists(env);
  await cryptosuites(env);
  log.info("vp_verifier_engine: " + assertions + " assertions, " +
           checksSeen + " Verifier checks examined.");
  // A floor, so a refactor that silently stops running a section cannot
  // pass by checking less.
  assert.ok(assertions >= 450, "only " + assertions + " assertions ran; " +
            "expected at least 450");
  assert.ok(checksSeen >= 1600, "only " + checksSeen + " Verifier checks " +
            "were examined; expected at least 1600");
  log.info("vp_verifier_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("vp_verifier_engine FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
