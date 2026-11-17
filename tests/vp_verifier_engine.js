// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_verifier_engine.js
//
// ---------------------------------------------------------------------------
// The debugger as an OpenID4VP 1.0 VERIFIER (client/src/vp_verifier.js), in
// node, with no browser and no network (issue #364, PR 1).
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
//     signed here, and ldp_vc bbs-2023 inside an ecdsa-jcs-2019 VP.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
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
  ["decentralized_identifier", "verifier_attestation", "nonsense"].forEach(
    function (p) {
      assertions++;
      assert.throws(function () {
        verifier.clientIdFor(p, id, {});
      }, /not built|PR 3/, p + " must be refused in PR 1");
    });

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
  eq(checkById(r, "ld[0].vp.proof").status, "skip",
     "another cryptosuite is a skip naming PR 3");
  ok(/PR 3/.test(checkById(r, "ld[0].vp.proof").detail));
  log.info("PASS ldp_vc: bbs-2023 derived proof and ecdsa-jcs-2019 holder " +
           "proof.");
  log.debug("Leaving ldpVcRoundTrip().");
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
  log.info("vp_verifier_engine: " + assertions + " assertions, " +
           checksSeen + " Verifier checks examined.");
  // A floor, so a refactor that silently stops running a section cannot
  // pass by checking less.
  assert.ok(assertions >= 200, "only " + assertions + " assertions ran; " +
            "expected at least 200");
  assert.ok(checksSeen >= 500, "only " + checksSeen + " Verifier checks " +
            "were examined; expected at least 500");
  log.info("vp_verifier_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("vp_verifier_engine FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
