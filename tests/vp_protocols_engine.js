// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_protocols_engine.js
//
// ---------------------------------------------------------------------------
// The presentation workflow's PROTOCOLS — OpenID4VP 1.0, OpenID4VC HAIP 1.0
// and SIOPv2 — in node, with no browser and no Verifier (client/src/
// vp_protocols.js).
//
// It is called vp_protocols_engine.js and not vp_protocols.js because the
// tests image is one flat directory: a test named after a module would
// replace it.
//
// What it holds the engine to, each against something the engine did not
// write:
//
//   * x509_hash is the base64url SHA-256 of the leaf DER, checked against
//     node's own X509Certificate; a request signed by another key, a hash
//     naming another certificate, and a chain with no anchor each fail by
//     name;
//   * the direct_post.jwt response opens with the Verifier's private key
//     through jose_jwe.js's decrypt, carries the Verifier key's kid, and its
//     plaintext is the JSON of the response parameters;
//   * a self-issued ID Token in each of the three subject syntaxes verifies
//     with node's crypto against the key its sub names, with iss equal to
//     sub;
//   * JCS against RFC 8785's own examples, and the ecdsa-jcs-2019 proof
//     verified by node's crypto over the hashes the cryptosuite defines;
//   * every protocol's rules: what HAIP refuses (by value, plaintext,
//     pre-registered), what OpenID4VP refuses for a redirect_uri identifier
//     whose answer goes elsewhere, and SIOPv2's subject syntax negotiation —
//     and the delivery and refusal each response_mode gets.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_protocols_engine",
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
const vp = load("vp_protocols.js");
const x509 = load("x509.js");
const joseJwe = load("jose_jwe.js");
const jws = load("jws.js");

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function jsonPart(jwt, i) {
  log.debug("Entering jsonPart().");
  log.debug("Leaving jsonPart().");
  return JSON.parse(Buffer.from(jwt.split(".")[i], "base64url").toString());
}

function ecPair() {
  log.debug("Entering ecPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving ecPair().");
  return {
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    publicJwk: pair.publicKey.export({ format: "jwk" }),
    privateJwk: pair.privateKey.export({ format: "jwk" }),
    keyObject: pair.publicKey
  };
}

// A Verifier with a Root, and a leaf naming verifier.example under it: what
// an x509 Client Identifier is made from.
async function verifierPki() {
  log.debug("Entering verifierPki().");
  const rootKey = ecPair();
  const leafKey = ecPair();
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Test Verifier Root,O=idptools",
    subjectPublicKey: rootKey.publicPem, issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha256-ecdsa", extensions: x509.defaultExtensions("root-ca")
  });
  const ext = x509.defaultExtensions("tls-server");
  ext.subjectAltName = { present: true, critical: false,
    names: [{ kind: "dns", value: "verifier.example" }] };
  const leaf = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=verifier.example,O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
              keyAlg: "es256" },
    signatureAlg: "sha256-ecdsa", extensions: ext
  });
  const der = new nodeCrypto.X509Certificate(leaf.pem).raw;
  log.debug("Leaving verifierPki().");
  return { root: root, leaf: leaf, leafKey: leafKey, leafDer: der,
           hash: b64u(nodeCrypto.createHash("sha256").update(der).digest()) };
}

async function signRequest(pki, payload, key) {
  log.debug("Entering signRequest().");
  const signed = await jws.signJwsAsync({
    algId: "ES256",
    protectedHeader: { alg: "ES256", typ: "oauth-authz-req+jwt",
                       x5c: [pki.leafDer.toString("base64")] },
    payload: payload,
    privateKey: { jwk: (key || pki.leafKey).privateJwk },
    backend: "webcrypto"
  });
  log.debug("Leaving signRequest().");
  return signed.serialized;
}

function check(result, name) {
  log.debug("Entering check(). " + name);
  log.debug("Leaving check().");
  return result.checks.filter(function (c) { return c.name === name; })[0];
}

async function x509ClientIdentifiers() {
  log.debug("Entering x509ClientIdentifiers().");
  const pki = await verifierPki();
  assert.strictEqual(await vp.x509Hash(pki.leafDer), pki.hash,
    "x509Hash() disagrees with node's SHA-256 of the leaf DER");
  assert.deepStrictEqual(vp.certificateParts(pki.leafDer).dnsNames,
    ["verifier.example"], "the dNSName was not read from the SAN");
  const clientId = "x509_hash:" + pki.hash;
  const good = await signRequest(pki, { client_id: clientId });
  let r = await vp.verifyX509Request({ compact: good, clientId: clientId,
    trustAnchorPem: pki.root.pem, verifyChain: x509.verifyChain });
  ["x5c", "x509_hash", "signature", "trust anchor"].forEach(function (n) {
    assert.ok(check(r, n) && check(r, n).ok, "a correct x509_hash request " +
      "failed '" + n + "': " + JSON.stringify(r.checks));
  });
  r = await vp.verifyX509Request({ compact: good, clientId: clientId,
    verifyChain: x509.verifyChain });
  assert.strictEqual(check(r, "trust anchor").ok, false,
    "a chain with no configured anchor must be reported UNTRUSTED");
  r = await vp.verifyX509Request({ compact: good,
    clientId: "x509_hash:" + b64u(Buffer.alloc(32)),
    verifyChain: x509.verifyChain });
  assert.strictEqual(check(r, "x509_hash").ok, false,
    "a Client Identifier naming another certificate must fail x509_hash");
  const forged = await signRequest(pki, { client_id: clientId }, ecPair());
  r = await vp.verifyX509Request({ compact: forged, clientId: clientId });
  assert.strictEqual(check(r, "signature").ok, false,
    "a request signed by a key other than the certificate's must fail");
  r = await vp.verifyX509Request({ compact: good,
    clientId: "x509_san_dns:verifier.example",
    responseTarget: "https://elsewhere.example/response" });
  assert.strictEqual(check(r, "x509_san_dns").ok, true,
    "the certified DNS name was not matched");
  assert.strictEqual(check(r, "response host").ok, false,
    "an x509_san_dns answer going to another host must fail");
  log.info("PASS x509_hash and x509_san_dns Client Identifiers.");
  log.debug("Leaving x509ClientIdentifiers().");
}

async function encryptedResponse() {
  log.debug("Entering encryptedResponse().");
  const verifierKey = ecPair();
  const pub = Object.assign({ use: "enc", alg: "ECDH-ES", kid: "resp-1" },
                            verifierKey.publicJwk);
  const metadata = { jwks: { keys: [{ kty: "AKP", alg: "HPKE-10-KE",
                                      kid: "pq", pub: "AA" }, pub] },
    encrypted_response_enc_values_supported: ["A256GCM", "A128GCM"] };
  const fields = vp.responseFields({ vpToken: { q: ["presentation"] },
    idToken: "a.b.c", state: "st-1" });
  for (const enc of ["A256GCM", "A128GCM"]) {
    const sealed = await vp.encryptResponse({ fields: fields,
      clientMetadata: metadata, enc: enc });
    assert.strictEqual(sealed.header.kid, "resp-1",
      "the JWE must name the Verifier key it was encrypted to");
    assert.strictEqual(sealed.header.alg, "ECDH-ES");
    assert.strictEqual(sealed.header.enc, enc);
    const opened = await joseJwe.decryptCompact({ jwe: sealed.jwe,
      key: verifierKey.privateJwk });
    const text = typeof opened.plaintext === "string" ? opened.plaintext :
        Buffer.from(opened.plaintext).toString();
    assert.deepStrictEqual(JSON.parse(text), fields,
      "the decrypted response is not the JSON of the response parameters");
    const d = vp.deliveryFor({ response_mode: "direct_post.jwt",
      response_uri: "https://v.example/r" }, fields, sealed);
    assert.deepStrictEqual(Object.keys(d.fields), ["response"],
      "direct_post.jwt posts exactly one field, response");
  }
  await assert.rejects(vp.encryptResponse({ fields: fields,
    clientMetadata: { jwks: { keys: [] } } }), /no ECDH-ES/,
    "with no key to encrypt to, encryption must refuse");
  log.info("PASS direct_post.jwt encryption, both enc values.");
  log.debug("Leaving encryptedResponse().");
}

async function selfIssuedIdTokens() {
  log.debug("Entering selfIssuedIdTokens().");
  const holder = ecPair();
  for (const syntax of vp.SUBJECT_SYNTAXES) {
    const t = await vp.selfIssuedIdToken({ privateJwk: holder.privateJwk,
      syntax: syntax, aud: "x509_hash:abc", nonce: "n-1" });
    const p = t.payload;
    assert.strictEqual(p.iss, p.sub, syntax + ": iss must equal sub");
    assert.strictEqual(p.aud, "x509_hash:abc");
    assert.strictEqual(p.nonce, "n-1");
    assert.ok(p.exp > p.iat, syntax + ": exp must follow iat");
    const parts = t.jwt.split(".");
    const ok = nodeCrypto.verify("sha256",
      Buffer.from(parts[0] + "." + parts[1]),
      { key: holder.keyObject, dsaEncoding: "ieee-p1363" },
      Buffer.from(parts[2], "base64url"));
    assert.ok(ok, syntax + ": the ID Token does not verify with the key");
    if (syntax === vp.SUBJECT_JWK_THUMBPRINT) {
      const j = holder.publicJwk;
      const tp = b64u(nodeCrypto.createHash("sha256").update(
        JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y })).digest());
      assert.strictEqual(p.sub, tp, "sub must be the RFC 7638 thumbprint");
      assert.ok(p.sub_jwk && !p.sub_jwk.d, "sub_jwk must be the PUBLIC key");
    } else {
      assert.ok(p.sub.indexOf(syntax + ":") === 0, "sub is not a " + syntax);
      assert.ok(jsonPart(t.jwt, 0).kid.indexOf(p.sub + "#") === 0,
        syntax + ": the header must name the subject's verification method");
    }
  }
  assert.strictEqual(vp.chooseSubjectSyntax({
    subject_syntax_types_supported: ["did:web"] }, ""), null,
    "no common subject syntax must be null, not a guess");
  assert.strictEqual(vp.chooseSubjectSyntax(null, ""),
    vp.SUBJECT_JWK_THUMBPRINT, "the SIOPv2 default is the JWK Thumbprint");
  log.info("PASS self-issued ID Tokens in all three subject syntaxes.");
  log.debug("Leaving selfIssuedIdTokens().");
}

async function jcsAndDataIntegrity() {
  log.debug("Entering jcsAndDataIntegrity().");
  // RFC 8785 section 3.2.2's example, and its key-ordering one (section
  // 3.2.3), written with escapes so the file stays ASCII.
  assert.strictEqual(vp.jcs({ numbers: [333333333.33333329, 1E30, 4.50,
    2e-3, 0.000000000000000000000000001],
    string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/",
    literals: [null, true, false] }),
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,' +
    '0.002,1e-27],"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  assert.strictEqual(vp.jcs({ "\u20ac": 1, "\r": 2, "\ud83d\ude00": 3,
    "1": 4, "\u00f6": 5 }),
    '{"\\r":2,"1":4,"\u00f6":5,"\u20ac":1,"\ud83d\ude00":3}');
  const holder = ecPair();
  const doc = { "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"], holder: "did:jwk:x" };
  const proof = await vp.ecdsaJcs2019Proof({ document: doc,
    privateJwk: holder.privateJwk, verificationMethod: "did:jwk:x#0",
    challenge: "n-2", domain: "x509_hash:abc" });
  assert.strictEqual(proof.cryptosuite, "ecdsa-jcs-2019");
  assert.strictEqual(proof.challenge, "n-2");
  assert.strictEqual(proof.domain, "x509_hash:abc");
  const config = Object.assign({}, proof, { "@context": doc["@context"] });
  delete config.proofValue;
  const hash = function (v) {
    return nodeCrypto.createHash("sha256").update(vp.jcs(v)).digest();
  };
  const data = Buffer.concat([hash(config), hash(doc)]);
  const did = load("did.js");
  const sig = Buffer.from(did.base58Decode(proof.proofValue.slice(1)));
  assert.ok(nodeCrypto.verify("sha256", data,
    { key: holder.keyObject, dsaEncoding: "ieee-p1363" }, sig),
    "the ecdsa-jcs-2019 proof does not verify over the cryptosuite's hashes");
  log.info("PASS RFC 8785 JCS and the ecdsa-jcs-2019 holder proof.");
  log.debug("Leaving jcsAndDataIntegrity().");
}

function blockedIds(rules) {
  log.debug("Entering blockedIds().");
  log.debug("Leaving blockedIds().");
  return vp.blockingRules(rules).map(function (r) { return r.id; });
}

function protocolRules() {
  log.debug("Entering protocolRules().");
  const dcql = { credentials: [{ id: "q", format: "dc+sd-jwt" }] };
  const encMeta = { jwks: { keys: [{ kty: "EC", crv: "P-256", x: "x",
    y: "y", kid: "k", use: "enc", alg: "ECDH-ES" }] } };
  const haipRequest = {
    params: { client_id: "x509_hash:abc", response_type: "vp_token",
      response_mode: "direct_post.jwt", response_uri: "https://v/r",
      nonce: "n" },
    source: "request_uri (signed Request Object)", signed: true,
    requestObject: "a.b.c", requestObjectHeader: { alg: "ES256",
      typ: "oauth-authz-req+jwt" }, requestObjectPayload: {
      client_id: "x509_hash:abc" }, outerClientId: "x509_hash:abc",
    dcql: dcql, clientMetadata: encMeta };
  const x509ok = { checks: ["x509_hash", "signature", "trust anchor"].map(
    function (n) { return { name: n, ok: true }; }) };
  let rules = vp.requestRules(vp.PROTOCOL_HAIP, { request: haipRequest,
    x509: x509ok, requestedFormat: "dc+sd-jwt" });
  assert.deepStrictEqual(blockedIds(rules), [],
    "a conformant HAIP request was refused: " + JSON.stringify(rules));
  // The same request, in the clear: HAIP refuses, plain OpenID4VP does not.
  const plain = JSON.parse(JSON.stringify(haipRequest));
  plain.params.response_mode = "direct_post";
  assert.ok(blockedIds(vp.requestRules(vp.PROTOCOL_HAIP, { request: plain,
    x509: x509ok })).indexOf("HAIP: direct_post.jwt") !== -1,
    "HAIP must refuse a plaintext answer");
  assert.deepStrictEqual(blockedIds(vp.requestRules(vp.PROTOCOL_OID4VP,
    { request: plain, x509: x509ok })), [],
    "OpenID4VP alone must accept direct_post");
  // By value, redirect_uri: HAIP refuses three ways.
  const byValue = { params: { client_id: "redirect_uri:https://v/r",
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: "https://v/r", nonce: "n" }, source: "redirect (by value)",
    signed: false, dcql: dcql };
  const haipBlocked = blockedIds(vp.requestRules(vp.PROTOCOL_HAIP,
    { request: byValue }));
  ["HAIP: request_uri", "HAIP: signed", "HAIP: x509_hash"].forEach(
    function (id) {
      assert.ok(haipBlocked.indexOf(id) !== -1, "HAIP did not refuse " + id);
    });
  // redirect_uri whose answer goes elsewhere.
  const elsewhere = JSON.parse(JSON.stringify(byValue));
  elsewhere.params.response_uri = "https://attacker/r";
  assert.ok(blockedIds(vp.requestRules(vp.PROTOCOL_OID4VP,
    { request: elsewhere })).indexOf("redirect_uri target") !== -1,
    "a redirect_uri Client Identifier answering elsewhere must be refused");
  // SIOPv2.
  const siop = { params: { client_id: "redirect_uri:https://v/cb",
    response_type: "id_token", scope: "openid", nonce: "n",
    redirect_uri: "https://v/cb" }, signed: false,
    clientMetadata: { subject_syntax_types_supported: ["did:jwk"] } };
  assert.deepStrictEqual(blockedIds(vp.requestRules(vp.PROTOCOL_SIOPV2,
    { request: siop })), [], "a plain SIOPv2 request was refused");
  assert.ok(blockedIds(vp.requestRules(vp.PROTOCOL_OID4VP,
    { request: siop })).indexOf("response_type") !== -1,
    "OpenID4VP must not answer an ID Token request");
  siop.clientMetadata.subject_syntax_types_supported = ["did:web"];
  assert.ok(blockedIds(vp.requestRules(vp.PROTOCOL_SIOPV2,
    { request: siop })).indexOf("SIOPv2: subject syntax") !== -1,
    "no common subject syntax must be refused");
  log.info("PASS the rules of OpenID4VP, HAIP and SIOPv2.");
  log.debug("Leaving protocolRules().");
}

function deliveries() {
  log.debug("Entering deliveries().");
  const fields = { id_token: "a.b.c", state: "s" };
  const frag = vp.deliveryFor({ redirect_uri: "https://v/cb" }, fields);
  assert.strictEqual(frag.kind, "redirect");
  assert.strictEqual(frag.url, "https://v/cb#id_token=a.b.c&state=s",
    "fragment is the default response mode for an ID Token");
  const q = vp.deliveryFor({ response_mode: "query",
    redirect_uri: "https://v/cb?x=1" }, fields);
  assert.strictEqual(q.url, "https://v/cb?x=1&id_token=a.b.c&state=s");
  assert.strictEqual(vp.deliveryFor({ response_mode: "form_post",
    redirect_uri: "https://v/cb" }, fields).kind, "form");
  assert.strictEqual(vp.deliveryFor({ response_mode: "post",
    redirect_uri: "https://v/cb" }, fields).kind, "post");
  const vpt = vp.formEncode({ vp_token: { q: ["x"] } });
  assert.strictEqual(vpt, "vp_token=" + encodeURIComponent('{"q":["x"]}'),
    "an object-valued parameter is form-encoded as its JSON");
  assert.strictEqual(vp.refusalFields({ response_type: "id_token" }).error,
    "user_cancelled", "SIOPv2 declines with user_cancelled");
  assert.strictEqual(vp.refusalFields({ response_type: "vp_token" }).error,
    "access_denied", "OpenID4VP declines with access_denied");
  assert.strictEqual(vp.refusalFields({ response_type: "id_token" },
    "subject_syntax").error, "subject_syntax_types_not_supported");
  log.info("PASS deliveries and refusals for every response_mode.");
  log.debug("Leaving deliveries().");
}

async function main() {
  log.debug("Entering main().");
  await x509ClientIdentifiers();
  await encryptedResponse();
  await selfIssuedIdTokens();
  await jcsAndDataIntegrity();
  protocolRules();
  deliveries();
  log.info("vp_protocols_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
