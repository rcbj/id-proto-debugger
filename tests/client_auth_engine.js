// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: client_auth_engine.js
//
// ---------------------------------------------------------------------------
// OAuth 2.0 client authentication at the token endpoint
// (client/src/client_auth.js), each method's wire form held to the text that
// defines it, every signature checked by node's own crypto. No browser, no
// services.
//
//   * client_secret_basic: RFC 6749 section 2.3.1's own example header, and
//     Appendix B's form-urlencoding of a client_id and secret that need it
//     (space as "+", ":" and "&" escaped) — Basic over the RAW strings is
//     the classic defect, and it works until somebody's secret has a colon;
//   * client_secret_post: client_id and client_secret in the body;
//   * client_secret_jwt and private_key_jwt (RFC 7523 section 2.2 and
//     draft-ietf-oauth-rfc7523bis-11): client_assertion_type, iss = sub =
//     client_id, aud the issuer identifier as the SOLE value (or the token
//     endpoint when that is chosen), jti, iat, exp, typ
//     client-authentication+jwt; HS256, ES256, EdDSA and PS256 verified by
//     node;
//   * attest_jwt_client_auth (draft-ietf-oauth-attestation-based-client-auth
//     -12): the attestation's typ, sub and cnf; the PoP's typ, aud, jti, iat
//     and challenge, signed by the key the attestation's cnf names;
//   * what must not happen: a secret method with no secret, private_key_jwt
//     with no private key, an assertion with no issuer to name, and the
//     secret appearing in what a page SHOWS.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "client_auth_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

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

const paths = require("./module_paths.js");
const ca = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "client_auth.js")], "client/src/client_auth.js");

const ISSUER = "https://as.example";
const TOKEN = "https://as.example/oauth2/token";

function part(jwt, i) {
  log.debug("Entering part().");
  log.debug("Leaving part().");
  return JSON.parse(Buffer.from(jwt.split(".")[i], "base64url").toString());
}

function verifies(jwt, publicKey, alg) {
  log.debug("Entering verifies(). " + alg);
  var p = jwt.split(".");
  var data = Buffer.from(p[0] + "." + p[1]);
  var sig = Buffer.from(p[2], "base64url");
  var ok;
  if (/^ES/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data,
      { key: publicKey, dsaEncoding: "ieee-p1363" }, sig);
  } else if (/^PS/.test(alg)) {
    ok = nodeCrypto.verify("sha" + alg.slice(2), data, { key: publicKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST }, sig);
  } else {
    ok = nodeCrypto.verify(null, data, publicKey, sig);
  }
  log.debug("Leaving verifies(). " + ok);
  return ok;
}

async function secretMethods() {
  log.debug("Entering secretMethods().");
  var r = await ca.apply({ method: "client_secret_basic",
                           clientId: "s6BhdRkqt3", secret: "gX1fBat3bV" });
  assert.strictEqual(r.headers.Authorization,
                     "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW",
                     "RFC 6749 section 2.3.1's own example");
  assert.deepStrictEqual(r.params, {}, "nothing in the body for Basic");
  r = await ca.apply({ method: "client_secret_basic", clientId: "my app:1",
                       secret: "p&ss w%rd" });
  assert.strictEqual(Buffer.from(r.headers.Authorization.slice(6), "base64")
    .toString(), "my+app%3A1:p%26ss+w%25rd",
    "Appendix B: both halves form-urlencoded before Basic");
  assert.ok(!/p&ss/.test(r.shownHeaders.Authorization) &&
            /<client_secret>/.test(r.shownHeaders.Authorization),
            "what is shown has no secret in it");
  r = await ca.apply({ method: "client_secret_post", clientId: "c1",
                       secret: "s3cr3t" });
  assert.deepStrictEqual(r.params, { client_id: "c1", client_secret: "s3cr3t" },
                         "client_secret_post: both in the body");
  assert.strictEqual(r.shownParams.client_secret, "<client_secret>",
                     "and the shown body hides it");
  var text = ca.describe("client_secret_post", TOKEN, { grant_type: "x" }, r);
  assert.ok(!/s3cr3t/.test(text), "describe() never prints the secret");
  r = await ca.apply({ method: "none", clientId: "public-1" });
  assert.deepStrictEqual(r.params, { client_id: "public-1" }, "none");
  log.info("PASS client_secret_basic (RFC 6749 2.3.1 and Appendix B), " +
           "client_secret_post and none; the secret is never shown.");
  log.debug("Leaving secretMethods().");
}

function checkAssertion(params, clientId, aud) {
  log.debug("Entering checkAssertion().");
  assert.strictEqual(params.client_assertion_type,
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion_type (RFC 7523 section 2.2)");
  var h = part(params.client_assertion, 0);
  var c = part(params.client_assertion, 1);
  assert.strictEqual(h.typ, "client-authentication+jwt",
                     "typ (draft-ietf-oauth-rfc7523bis-11)");
  assert.strictEqual(c.iss, clientId, "iss is the client_id");
  assert.strictEqual(c.sub, clientId, "sub is the client_id");
  assert.strictEqual(c.aud, aud, "aud, a single string");
  assert.ok(c.jti && c.iat && c.exp > c.iat, "jti, iat and exp");
  log.debug("Leaving checkAssertion().");
  return h;
}

async function assertionMethods() {
  log.debug("Entering assertionMethods().");
  var r = await ca.apply({ method: "client_secret_jwt", clientId: "c1",
                           secret: "shared-secret", issuer: ISSUER });
  var h = checkAssertion(r.params, "c1", ISSUER);
  assert.strictEqual(h.alg, "HS256", "client_secret_jwt defaults to HS256");
  var p = r.params.client_assertion.split(".");
  assert.strictEqual(nodeCrypto.createHmac("sha256", "shared-secret")
    .update(p[0] + "." + p[1]).digest("base64url"), p[2],
    "the HMAC is keyed by the secret");
  var cases = [["ES256", nodeCrypto.generateKeyPairSync("ec",
                 { namedCurve: "P-256" })],
               ["EdDSA", nodeCrypto.generateKeyPairSync("ed25519")],
               ["PS256", nodeCrypto.generateKeyPairSync("rsa",
                 { modulusLength: 2048 })]];
  for (const [alg, pair] of cases) {
    r = await ca.apply({ method: "private_key_jwt", clientId: "c2",
      issuer: ISSUER, signingKey: pair.privateKey.export({ format: "jwk" }),
      alg: alg, kid: "k-" + alg });
    h = checkAssertion(r.params, "c2", ISSUER);
    assert.strictEqual(h.alg, alg, alg + ": the chosen alg");
    assert.strictEqual(h.kid, "k-" + alg, alg + ": kid");
    assert.ok(verifies(r.params.client_assertion, pair.publicKey, alg),
              alg + ": node verifies the assertion");
  }
  r = await ca.apply({ method: "private_key_jwt", clientId: "c2",
    issuer: ISSUER, tokenEndpoint: TOKEN, audienceChoice: "token_endpoint",
    signingKey: cases[0][1].privateKey.export({ format: "jwk" }) });
  checkAssertion(r.params, "c2", TOKEN);
  assert.ok(/rfc7523bis/.test(r.notes.join(" ")), "the token endpoint " +
            "audience is noted as RFC 7523's, not the update's");
  log.info("PASS client_secret_jwt (HS256) and private_key_jwt (ES256, " +
           "EdDSA, PS256): RFC 7523 / 7523bis-11 claims, typ and aud, " +
           "verified by node.");
  log.debug("Leaving assertionMethods().");
}

async function attestation() {
  log.debug("Entering attestation().");
  var attester = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instance = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var instanceJwk = instance.privateKey.export({ format: "jwk" });
  var att = await ca.makeAttestation({ attesterKey: attester.privateKey
    .export({ format: "jwk" }), kid: "a1", clientId: "wallet-1",
    instanceKey: instanceJwk });
  assert.strictEqual(part(att, 0).typ, "oauth-client-attestation+jwt",
                     "the attestation's typ (section 4)");
  var ac = part(att, 1);
  assert.strictEqual(ac.sub, "wallet-1", "its sub is the client_id");
  assert.ok(ac.iat && ac.exp > ac.iat, "iat and exp");
  assert.strictEqual(ac.cnf.jwk.d, undefined, "cnf carries no private key");
  assert.strictEqual(ac.cnf.jwk.x, instanceJwk.x, "cnf is the instance key");
  assert.ok(verifies(att, attester.publicKey, "ES256"), "signed by the " +
            "attester");
  var r = await ca.apply({ method: "attest_jwt_client_auth",
    clientId: "wallet-1", issuer: ISSUER, attestation: att,
    instanceKey: instanceJwk, challenge: "AYjcyMzY3ZDhiNmJkNTZ" });
  assert.strictEqual(r.headers["OAuth-Client-Attestation"], att,
                     "the attestation in OAuth-Client-Attestation");
  var pop = r.headers["OAuth-Client-Attestation-PoP"];
  assert.strictEqual(part(pop, 0).typ, "oauth-client-attestation-pop+jwt",
                     "the PoP's typ (section 5.1)");
  var pc = part(pop, 1);
  assert.strictEqual(pc.aud, ISSUER, "the PoP's aud is the issuer");
  assert.ok(pc.jti && pc.iat, "jti and iat");
  assert.strictEqual(pc.challenge, "AYjcyMzY3ZDhiNmJkNTZ",
                     "the server's challenge (section 6)");
  assert.ok(verifies(pop, instance.publicKey, "ES256"), "the PoP is signed " +
            "by the key the attestation's cnf names");
  var other = await ca.apply({ method: "attest_jwt_client_auth",
    clientId: "someone-else", issuer: ISSUER, attestation: att,
    instanceKey: instanceJwk });
  assert.ok(/sub/.test(other.notes.join(" ")), "a client_id that is not " +
            "the attestation's sub is noted (section 7.5)");
  assert.strictEqual(ca.challengeOf({ "oauth-client-attestation-challenge":
    "c-2" }), "c-2", "a response's challenge is read");
  log.info("PASS attest_jwt_client_auth (draft -12): the attestation's " +
           "typ, sub and cnf; the PoP's typ, aud, jti, iat and challenge, " +
           "signed by the cnf key.");
  log.debug("Leaving attestation().");
}

async function refusals() {
  log.debug("Entering refusals().");
  for (const m of ["client_secret_basic", "client_secret_post",
                   "client_secret_jwt"]) {
    await assert.rejects(ca.apply({ method: m, clientId: "c", secret: "",
      issuer: ISSUER }), /never stored/, m + " with no secret is refused");
  }
  await assert.rejects(ca.apply({ method: "private_key_jwt", clientId: "c",
    issuer: ISSUER }), /private key/, "private_key_jwt with no key");
  await assert.rejects(ca.apply({ method: "private_key_jwt", clientId: "c",
    signingKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" } }),
    /issuer identifier/, "an assertion with no issuer to name");
  await assert.rejects(ca.apply({ method: "attest_jwt_client_auth",
    clientId: "c", issuer: ISSUER }), /Client Attestation/,
    "attestation with nothing to attest");
  assert.strictEqual(ca.defaultMethod(["tls_client_auth", "private_key_jwt",
    "client_secret_basic"]), "private_key_jwt", "the default is the " +
    "server's first method this implements, in its order");
  assert.strictEqual(ca.defaultMethod(undefined), "none", "and none when " +
                     "the server says nothing");
  log.info("PASS refusals, and the default method from the server's list.");
  log.debug("Leaving refusals().");
}

async function main() {
  log.debug("Entering main().");
  await secretMethods();
  await assertionMethods();
  await attestation();
  await refusals();
  log.info("client_auth_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
