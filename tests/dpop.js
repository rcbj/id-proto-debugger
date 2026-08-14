// File: dpop.js
//
// client/src/dpop.js — DPoP, RFC 9449, the wallet's half.
//
// Everything here is checkable without a browser or a service, and every part
// of it fails SILENTLY when it is wrong: a wrong thumbprint, a wrong `htu` or a
// wrong `ath` all produce a perfectly well-formed proof that simply matches
// nothing, and the server's refusal reads as "your key is wrong" rather than
// "your encoding is wrong".
//
// The oracle for the part that matters most is not a second implementation but
// the RFCs' own published values:
//
//   * RFC 9449's worked example prints a DPoP proof whose header carries an EC
//     public key, and prints the same key's JWK Thumbprint as the `jkt`
//     confirmation value of the access token bound to it. Those two figures are
//     an input and its expected output, written down by the people who defined
//     the mechanism.
//   * RFC 7638 section 3.1 does the same for an RSA key.
//
// The three ways a thumbprint goes wrong are each tested directly, because all
// three are things a reasonable implementation does by accident: including a
// member the specification excludes (a `kid` or an `alg` — Web Crypto exports
// `key_ops` and `ext`), ordering the members as the object happens to hold them
// rather than lexicographically, and pretty-printing the JSON.
//
// Signatures are verified with node's own crypto, which shares no code with the
// Web Crypto path the module uses — so a proof that only this module can check
// is not a passing proof.
//
// No browser and no services: node only, so it never skips.
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "dpop",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the module is at client/src/dpop.js; the tests image copies it
// flat next to the test scripts (see tests/Dockerfile).
var dpop = paths.requireSharedModule(
  [__dirname + "/../client/src/dpop.js", __dirname + "/dpop.js"], "dpop.js");

// The module signs through Web Crypto, as it does in the browser. Assert it
// rather than discover a TypeError six functions deep.
assert.strictEqual(typeof crypto.webcrypto.subtle, "object",
                   "this node has no Web Crypto");

function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function jsonFromB64u(s) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(b64uDecode(s).toString("utf8"));
}

// ---------------------------------------------------------------------------
// The published vectors.
// ---------------------------------------------------------------------------
// RFC 9449, the EC public key carried in the example DPoP proof's `jwk` header.
const RFC9449_JWK = {
  kty: "EC",
  x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
  y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
  crv: "P-256"
};
// ...and the `cnf.jkt` the same document shows for the token bound to it.
const RFC9449_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

// RFC 7638 section 3.1.
const RFC7638_JWK = {
  e: "AQAB",
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aP" +
     "FFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl9" +
     "3lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdA" +
     "ZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3" +
     "XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
};
const RFC7638_JKT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// --- the thumbprint, against the specifications' own numbers ----------------
async function thumbprintMatchesPublishedVectors() {
  log.debug("Entering thumbprintMatchesPublishedVectors().");
  log.info("=== The JWK Thumbprint (RFC 7638), against published vectors ===");

  var ec = await dpop.thumbprint(RFC9449_JWK);
  assert.strictEqual(ec, RFC9449_JKT,
    "the EC key from RFC 9449's own worked example must hash to the jkt that " +
        "same document " +
    "prints for the token bound to it. Got " + ec + ", expected " +
        RFC9449_JKT + ".");
  var rsa = await dpop.thumbprint(RFC7638_JWK);
  assert.strictEqual(rsa, RFC7638_JKT,
    "the RSA key from RFC 7638 section 3.1 must hash to the thumbprint " +
        "printed beside it. " +
    "Got " + rsa + ", expected " + RFC7638_JKT + ".");
  log.info("[thumbprint] OK — the RFC 9449 EC vector and the RFC 7638 RSA " +
           "vector both match.");

  // The canonical form itself, so a failure above says WHICH of the three rules
  // broke rather than only that the digest differs.
  var canonical = dpop.canonicalJwk(RFC9449_JWK);
  assert.strictEqual(canonical,
    '{"crv":"P-256","kty":"EC",' +
        '"x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",' +
    '"y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}',
    "the thumbprint input must be the required members, lexicographic, with " +
        "no whitespace.");
  assert.ok(canonical.indexOf(" ") === -1 && canonical.indexOf("\n") === -1,
    "the thumbprint input must carry no whitespace at all; got: " + canonical);
  log.info("[thumbprint] OK — the canonical input is exact.");

  log.debug("Leaving thumbprintMatchesPublishedVectors().");
}

// The three silent ways to get it wrong.
async function thumbprintIgnoresEverythingItShould() {
  log.debug("Entering thumbprintIgnoresEverythingItShould().");
  log.info("=== The thumbprint excludes what RFC 7638 excludes ===");

  // 1. Extra members must not change the answer. This is the one that bites in
  //    practice: Web Crypto exports key_ops and ext, and a key that later gains
  //    a kid would otherwise stop matching its own access token.
  var decorated = Object.assign({}, RFC9449_JWK, {
    kid: "some-key-id", alg: "ES256", use: "sig", key_ops: ["verify"], ext: true
  });
  assert.strictEqual(await dpop.thumbprint(decorated), RFC9449_JKT,
    "kid/alg/use/key_ops/ext are NOT thumbprint input — a key that gains any " +
        "of them must " +
    "still match the token bound to it. This is what Web Crypto's own export " +
        "produces.");

  // 2. The member order in the object must not change the answer.
  var shuffled = { y: RFC9449_JWK.y, kty: RFC9449_JWK.kty, crv: RFC9449_JWK.crv,
                   x: RFC9449_JWK.x };
  assert.strictEqual(await dpop.thumbprint(shuffled), RFC9449_JKT,
    "the members are ordered lexicographically by the specification, not by " +
        "the order the " +
    "key object happens to hold them in.");

  // 3. A DIFFERENT key must give a different answer — the control that stops
  //    the two assertions above from passing on a constant.
  var other = Object.assign({}, RFC9449_JWK,
      { x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFt" });
  assert.notStrictEqual(await dpop.thumbprint(other), RFC9449_JKT,
    "a key with a different x must not produce the same thumbprint.");
  log.info("[thumbprint] OK — extras and ordering ignored, a changed " +
           "coordinate is not.");

  // A key type with no defined required-member list, and a key missing one, are
  // refused rather than hashed into something meaningless.
  assert.throws(function () { dpop.canonicalJwk({ kty: "NOPE", x: "a" }); },
                /kty NOPE/,
    "an unknown kty must be refused, not hashed.");
  assert.throws(function () { dpop.canonicalJwk({ kty: "EC", crv: "P-256",
                x: "a" }); }, /missing y/,
    "a key missing a required member must be refused, naming the member.");
  assert.throws(function () { dpop.canonicalJwk(null); }, /kty/,
    "no key at all must be refused.");
  log.info("[thumbprint] OK — an unusable key is refused, naming what " +
           "is wrong.");

  log.debug("Leaving thumbprintIgnoresEverythingItShould().");
}

// --- htu: RFC 9449 section 4.2 + the normalization section 4.3 asks for -----
function htuDropsQueryAndNormalizes() {
  log.debug("Entering htuDropsQueryAndNormalizes().");
  log.info("=== htu (RFC 9449 section 4.2/4.3) ===");
  var cases = [
    // [input, expected, why it is in the list]
    ["https://issuer.example/oid4vci/credential?foo=1&bar=2",
     "https://issuer.example/oid4vci/credential", "the query is excluded"],
    ["https://issuer.example/oid4vci/credential#frag",
     "https://issuer.example/oid4vci/credential", "the fragment is excluded"],
    ["https://issuer.example:443/oid4vci/credential",
     "https://issuer.example/oid4vci/credential",
         "a default https port is normalized away"],
    ["http://localhost:80/oauth2/token",
     "http://localhost/oauth2/token", "a default http port is normalized away"],
    ["http://localhost:8081/oauth2/token",
     "http://localhost:8081/oauth2/token", "a non-default port is kept"],
    ["HTTPS://Issuer.EXAMPLE/oid4vci/credential",
     "https://issuer.example/oid4vci/credential",
         "scheme and host are case-insensitive"],
    ["https://issuer.example", "https://issuer.example/", "an empty path is /"]
  ];
  cases.forEach(function (c) {
    assert.strictEqual(dpop.htuFor(c[0]), c[1],
      "htu: " + c[2] + ". " + c[0] + " -> " + dpop.htuFor(c[0]) +
          ", expected " + c[1]);
  });
  log.info("[htu] OK — " + cases.length +
           " cases, query/fragment dropped and RFC 3986 " +
           "normalization applied.");

  // The port normalization is not decoration: without it a server comparing
  // byte-for-byte refuses a proof for the very endpoint it is serving, and the
  // refusal is indistinguishable from an attack.
  assert.strictEqual(dpop.htuFor("https://a.example:443/x"),
                     dpop.htuFor("https://a.example/x"),
    "the same endpoint written with and without its default port must " +
        "produce ONE htu, or a " +
    "correct client is refused for a reason nobody can see.");
  log.debug("Leaving htuDropsQueryAndNormalizes().");
}

// --- ath: RFC 9449 section 4.2 ---------------------------------------------
async function athIsTheHashOfTheToken() {
  log.debug("Entering athIsTheHashOfTheToken().");
  log.info("=== ath (RFC 9449 section 4.2) ===");
  var token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
  var expected = crypto.createHash("sha256").update(token,
      "ascii").digest("base64url");
  assert.strictEqual(await dpop.athFor(token), expected,
    "ath must be base64url(SHA-256(ASCII(token))). This is the claim that " +
        "stops a proof " +
    "captured with one token being replayed with another.");
  // A one-character change must change it, or it is not binding anything.
  assert.notStrictEqual(await dpop.athFor(token + "x"), expected,
    "a different token must produce a different ath.");
  log.info("[ath] OK — matches node's own digest, and changes with the token.");
  log.debug("Leaving athIsTheHashOfTheToken().");
}

// --- jti -------------------------------------------------------------------
function jtiIsUnpredictableAndLongEnough() {
  log.debug("Entering jtiIsUnpredictableAndLongEnough().");
  log.info("=== jti (RFC 9449 section 4.2) ===");
  var seen = {};
  var shortest = Infinity;
  for (var i = 0; i < 500; i++) {
    var id = dpop.newJti();
    assert.ok(!seen[id], "newJti() repeated a value within 500 calls: " + id);
    seen[id] = true;
    shortest = Math.min(shortest, b64uDecode(id).length * 8);
  }
  assert.ok(shortest >= 96,
    "RFC 9449 asks for at least 96 bits of pseudorandom data in jti so the " +
        "server can detect " +
    "a replay; the shortest of 500 was " + shortest + " bits.");
  log.info("[jti] OK — 500 distinct values, at least " + shortest +
           " bits each.");
  log.debug("Leaving jtiIsUnpredictableAndLongEnough().");
}

// --- the proof, verified by node rather than by this module -----------------
async function proofIsWellFormedAndVerifies() {
  log.debug("Entering proofIsWellFormedAndVerifies().");
  log.info("=== The DPoP proof (RFC 9449 section 4.2), verified by node ===");

  for (const alg of dpop.ALGS) {
    var key = await dpop.generateKeyPair(alg);
    assert.strictEqual(key.alg, alg, "generateKeyPair(" + alg +
                       ") reported alg " + key.alg);
    assert.ok(key.publicJwk && !key.publicJwk.d,
      "the public half must carry no private material — it travels in every " +
          "proof header.");
    // RFC 9449 section 4.3 check 7: the jwk header MUST NOT contain a private
    // key. Web Crypto's export includes key_ops/ext, so this is a real filter.
    ["d", "p", "q", "dp", "dq", "qi", "key_ops", "ext"].forEach(function (m) {
      assert.strictEqual(key.publicJwk[m], undefined,
        "the public JWK must not carry " + m +
            "; it would travel in every proof.");
    });

    var made = await dpop.proof({
      key: key,
      htm: "post",
      htu: "https://issuer.example/oid4vci/credential?ignored=1",
      accessToken: "an-access-token",
      nonce: "server-supplied-nonce"
    });

    var parts = made.proof.split(".");
    assert.strictEqual(parts.length, 3,
                       "a DPoP proof is a compact JWS with three parts.");
    var header = jsonFromB64u(parts[0]);
    var payload = jsonFromB64u(parts[1]);

    // Section 4.2's required header parameters, and section 4.3's checks on
    // them.
    assert.strictEqual(header.typ, "dpop+jwt",
      "the proof must be explicitly typed dpop+jwt (RFC 8725 section 3.11). " +
          "Without it a " +
      "receiver may accept some other JWT the client signed with the " +
          "same key.");
    assert.strictEqual(header.alg, alg,
                       "the header must name the signing algorithm.");
    assert.notStrictEqual(header.alg, "none", "alg must not be none.");
    assert.ok(header.jwk && header.jwk.kty,
              "the header must carry the public key as a JWK.");
    assert.strictEqual(header.jwk.d, undefined,
                       "the header's jwk must not contain a private key.");
    assert.strictEqual(header.kid, undefined,
      "a kid in the header would be pointless here — the key itself is " +
          "present — and would " +
      "change nothing about the thumbprint.");

    // Section 4.2's required claims.
    ["jti", "htm", "htu", "iat"].forEach(function (c) {
      assert.ok(payload[c] !== undefined, "the payload must contain " + c +
                ".");
    });
    assert.strictEqual(payload.htm, "POST",
      "htm is the HTTP method, upper case as RFC 9110 writes it — a " +
          "lower-case method fails " +
      "a byte comparison at the server.");
    assert.strictEqual(payload.htu, "https://issuer.example/oid4vci/credential",
      "htu must drop the query. Got " + payload.htu);
    assert.strictEqual(payload.nonce, "server-supplied-nonce",
      "a server-supplied nonce must reach the payload.");
    assert.strictEqual(payload.ath, await dpop.athFor("an-access-token"),
      "ath must be present and correct when the proof accompanies an " +
          "access token.");
    assert.ok(Math.abs(payload.iat - Math.floor(Date.now() / 1000)) < 120,
      "iat must be now, not a stale or absent timestamp.");

    // The signature, checked by node — a different implementation entirely.
    var publicKey = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
    var signingInput = Buffer.from(parts[0] + "." + parts[1], "ascii");
    var signature = b64uDecode(parts[2]);
    var ok;
    if (alg === "ES256") {
      // JWS carries ECDSA as raw r||s; node's verifier wants to be told that.
      ok = crypto.verify("sha256", signingInput, { key: publicKey,
          dsaEncoding: "ieee-p1363" },
                         signature);
      assert.strictEqual(signature.length, 64,
        "an ES256 JWS signature is the 64-byte r||s pair, not DER. Got " +
            signature.length +
        " bytes, which is what a DER signature would be.");
    } else {
      ok = crypto.verify("sha256", signingInput, publicKey, signature);
    }
    assert.ok(ok, alg +
        ": the proof's signature does not verify against the key in its own " +
                  "header, checked with node rather than with the module " +
                      "that made it.");

    // And the key in the header is the key the token would be bound to.
    var jkt = await dpop.thumbprint(header.jwk);
    assert.strictEqual(jkt, await dpop.thumbprint(key.publicJwk),
      "the thumbprint of the header's jwk must equal the thumbprint of the " +
          "wallet's own key — " +
      "that equality is the whole binding.");

    // Tampering must break it. A JWS whose payload can be edited proves
    // nothing.
    var tampered = parts[0] + "." +
      Buffer.from(JSON.stringify(Object.assign({}, payload, { htm: "GET" })))
        .toString("base64url") + "." + parts[2];
    var tparts = tampered.split(".");
    var tinput = Buffer.from(tparts[0] + "." + tparts[1], "ascii");
    var stillOk = alg === "ES256"
      ? crypto.verify("sha256", tinput, { key: publicKey,
          dsaEncoding: "ieee-p1363" },
                      b64uDecode(tparts[2]))
      : crypto.verify("sha256", tinput, publicKey, b64uDecode(tparts[2]));
    assert.strictEqual(stillOk, false,
      alg + ": changing htm from POST to GET must invalidate the signature.");

    log.info("[proof] OK — " + alg +
             ": typed, all required claims, verifies under node, and " +
             "does not survive tampering.");
  }

  // No access token means no ath. Sending one anyway would be a claim about a
  // token that is not there.
  var key2 = await dpop.generateKeyPair("ES256");
  var atTokenEndpoint = await dpop.proof({
    key: key2, htm: "POST", htu: "http://localhost:8081/oauth2/token"
  });
  assert.strictEqual(jsonFromB64u(atTokenEndpoint.proof.split(".")[1]).ath,
                     undefined,
    "the proof for a Token Request carries no ath: there is no access token " +
        "yet. RFC 9449 " +
    "requires ath only when the proof accompanies one.");
  assert.strictEqual(jsonFromB64u(atTokenEndpoint.proof.split(".")[1]).nonce,
                     undefined,
    "and no nonce until the server has asked for one.");
  log.info("[proof] OK — a Token Request proof carries neither ath nor nonce.");

  // Two proofs for the same request must differ: a reusable proof is a
  // replayable one.
  var again = await dpop.proof({ key: key2, htm: "POST",
      htu: "http://localhost:8081/oauth2/token" });
  assert.notStrictEqual(atTokenEndpoint.proof, again.proof,
    "two proofs for the same method and URI must differ — each carries its " +
        "own jti, which is " +
    "what lets the server refuse a replay.");
  log.info("[proof] OK — proofs are single-use.");

  log.debug("Leaving proofIsWellFormedAndVerifies().");
}

// --- what the wallet does with the server's answers ------------------------
function nonceHandshakeIsRecognised() {
  log.debug("Entering nonceHandshakeIsRecognised().");
  log.info("=== The DPoP-Nonce handshake (RFC 9449 sections 8 and 9) ===");

  // An authorization server asks with a 400 and an error in the body.
  var fromAs = dpop.nonceRequested(400, { error: "use_dpop_nonce" },
                                   { "dpop-nonce": "eyJ7S_zG" });
  assert.strictEqual(fromAs.wanted, true,
                     "a 400 use_dpop_nonce body must be recognised.");
  assert.strictEqual(fromAs.nonce, "eyJ7S_zG",
                     "and the nonce must be read from the header.");

  // A resource server asks with a 401 and the error in WWW-Authenticate — a
  // DIFFERENT shape for the same request, which is why both are handled.
  var fromRs = dpop.nonceRequested(401, null, {
    "www-authenticate": 'DPoP error="use_dpop_nonce", ' +
        'error_description="Resource server ' +
                        'requires nonce in DPoP proof"',
    "dpop-nonce": "eyJ7S_zG-rs"
  });
  assert.strictEqual(fromRs.wanted, true,
    "a 401 with use_dpop_nonce in WWW-Authenticate must be recognised — a " +
        "resource server " +
    "asks that way, not with a JSON body.");
  assert.strictEqual(fromRs.nonce, "eyJ7S_zG-rs", "and its nonce read too.");

  // Anything else is not a nonce request, and must not be treated as one: a
  // wallet that retried on every error would loop on a real failure.
  assert.strictEqual(dpop.nonceRequested(400, { error: "invalid_grant" },
                     {}).wanted, false,
    "an unrelated error must NOT look like a nonce request, or the wallet " +
        "retries forever " +
    "on a genuine failure.");
  assert.strictEqual(dpop.nonceRequested(401, null, {
    "www-authenticate": 'DPoP error="invalid_token"' }).wanted, false,
    "nor must an invalid_token challenge.");
  log.info("[nonce] OK — both request shapes recognised, unrelated " +
           "errors are not.");

  // Header case: a Headers object is case-insensitive, a plain object is not,
  // and both reach this code.
  assert.strictEqual(dpop.nonceFromResponse({ headers: { "DPoP-Nonce": "x" } }),
                     "x",
    "a plain header object spelled as the RFC spells it must be read.");
  assert.strictEqual(dpop.nonceFromResponse({
    headers: { get: function (n) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return n === "DPoP-Nonce" ? "y" : null;
    } } }), "y",
    "a fetch() Headers object must be read through get().");
  assert.strictEqual(dpop.nonceFromResponse(null), "",
                     "and no response is no nonce.");
  log.info("[nonce] OK — read from either header representation.");

  log.debug("Leaving nonceHandshakeIsRecognised().");
}

function tokenIsPresentedAsDpopNotBearer() {
  log.debug("Entering tokenIsPresentedAsDpopNotBearer().");
  log.info("=== The authentication scheme (RFC 9449 section 7.1) ===");
  assert.strictEqual(dpop.authorizationHeader("abc"), "DPoP abc",
    "a DPoP-bound token is presented with the DPoP scheme. Presenting it as " +
        "Bearer is a " +
    "protocol error even though the bytes are identical, and a resource " +
        "server that accepts " +
    "either has thrown the binding away.");
  assert.ok(dpop.authorizationHeader("abc").indexOf("Bearer") === -1,
            "and never as Bearer.");
  log.info("[scheme] OK — Authorization: DPoP <token>.");
  log.debug("Leaving tokenIsPresentedAsDpopNotBearer().");
}

// A symmetric key must not be usable. RFC 9449 forbids a MAC, and there is a
// concrete reason beyond conformance: the verifier would hold the same secret
// and could mint proofs itself, so the signature would prove nothing.
async function symmetricKeysAreRefused() {
  log.debug("Entering symmetricKeysAreRefused().");
  log.info("=== No MACs (RFC 9449 section 4.2) ===");
  assert.strictEqual(dpop.algOfJwk({ kty: "oct", k: "c2VjcmV0" }), "",
    "an oct key must map to no DPoP algorithm.");
  assert.strictEqual(dpop.algOfJwk({ kty: "EC", crv: "P-384", x: "a", y: "b" }),
                     "",
    "a curve this wallet cannot sign with must map to no algorithm rather " +
        "than to ES256, " +
    "which would sign with the wrong hash.");
  assert.strictEqual(dpop.algOfJwk({ kty: "EC", crv: "P-256", x: "a", y: "b" }),
                     "ES256");
  assert.strictEqual(dpop.algOfJwk({ kty: "RSA", n: "a", e: "AQAB" }), "RS256");
  await assert.rejects(
    dpop.proof({ key: { alg: "HS256", publicJwk: { kty: "oct" },
               privateJwk: {} },
                 htm: "POST", htu: "https://x.example/y" }),
    /not an algorithm this wallet can sign with/,
    "asking for a MAC must be refused by name, not attempted.");
  log.info("[algs] OK — MACs and unsupported curves refused.");
  log.debug("Leaving symmetricKeysAreRefused().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying client/src/dpop.js against RFC 9449 " +
           "and RFC 7638.");
  await thumbprintMatchesPublishedVectors();
  await thumbprintIgnoresEverythingItShould();
  htuDropsQueryAndNormalizes();
  await athIsTheHashOfTheToken();
  jtiIsUnpredictableAndLongEnough();
  await proofIsWellFormedAndVerifies();
  nonceHandshakeIsRecognised();
  tokenIsPresentedAsDpopNotBearer();
  await symmetricKeysAreRefused();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("dpop")
  .description("Verify client/src/dpop.js: RFC 9449 proofs, RFC 7638 " +
      "thumbprints, htu/ath/jti.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
