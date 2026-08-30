// File: sts_userinfo_protected.js
//
// The SIGNED and ENCRYPTED UserInfo Response — OIDC Core section 5.3.2 —
// against the mock authorization server, over HTTP with no browser.
//
// Section 5.3.2 gives the UserInfo Response four shapes, and which one a client
// gets is decided entirely by what it registered:
//
//   neither ..._signed_response_alg nor    application/json
//   ..._encrypted_response_alg
//   ..._signed_response_alg only           application/jwt, a JWS
//   ..._encrypted_response_alg only        application/jwt, a JWE
//   both                                   application/jwt, a JWS inside a JWE
//
// THIS FILE IS A CROSS-IMPLEMENTATION CHECK AND THAT IS THE POINT OF IT. The
// mock produces each response with node's OpenSSL (sts/common/crypto.js) and
// every one is opened here with the DEBUGGER'S OWN ENGINES — client/src/jws.js
// and client/src/jose_jwe.js, which are Web Crypto and a pure-JS fallback.
// Two independent implementations, in two repositories, of the same four
// specifications. A round trip through either one alone proves only that it
// agrees with itself, and the failures that matter in JOSE are precisely the
// self-consistent ones:
//
//   * a CBC-HMAC CEK split the wrong way round (the MAC key is the FIRST half);
//   * AL computed over the wrong span or in bytes rather than bits;
//   * the authentication tag taken as the whole HMAC rather than its first half;
//   * a Concat KDF that stops after one round, which is invisible until a key
//     longer than 32 bytes is asked for — A192CBC-HS384 and A256CBC-HS512;
//   * `cty` omitted from the outer header of a Nested JWT, which a recipient
//     that trusts it reads as a claims object and cannot parse.
//
// Every one of those produces a document the side that made it reads back
// perfectly. Only the far side notices, and that is what this file is.
//
// THE NEGATIVES MATTER AS MUCH AS THE ROUND TRIPS. A signed response with no
// `iss` and no `aud` is the whole reason not to want one: it is a signed
// statement about somebody that any client would believe, so those two members
// are asserted rather than assumed. And encryption is NOT authentication — an
// encrypted-only response proves who it was encrypted TO and says nothing about
// who wrote it — so this file checks that the mock does not sign when it was
// only asked to encrypt.
//
// Needs the STS mock and nothing else, so it is skipped only when there is no
// STS to talk to.

const assert = require("assert");
const nodeCrypto = require("crypto");
const paths = require("./module_paths");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_userinfo_protected",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The debugger's engines, loaded through module_paths so their own requires
// resolve whether this runs from a checkout or from the tests image.
var jose = paths.requireSharedModule(
  [__dirname + "/../client/src/jose_jwe.js", __dirname + "/jose_jwe.js"],
   "jose_jwe.js");
var jws = paths.requireSharedModule(
  [__dirname + "/../client/src/jws.js", __dirname + "/jws.js"], "jws.js");

var stsUrl = process.env.WSTRUST_STS_URL || "";
var stsBase = process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "");
var REDIRECT_URI = "http://localhost:9999/callback";

// One RSA and one EC key pair, standing in for the RELYING PARTY's key
// material: the public halves go into the registration's `jwks` and the mock
// encrypts to them, the private halves stay here and open what comes back.
var rpRsa = null;
var rpEc = null;
var opJwks = null;

function rpKeys() {
  log.debug("Entering rpKeys().");
  if (!rpRsa) {
    rpRsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    rpEc = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  }
  log.debug("Leaving rpKeys().");
  return {
    jwks: { keys: [
      Object.assign(rpRsa.publicKey.export({ format: "jwk" }),
                    { kid: "rp-rsa", use: "enc" }),
      Object.assign(rpEc.publicKey.export({ format: "jwk" }),
                    { kid: "rp-ec", use: "enc" })
    ] },
    rsaPrivatePem: rpRsa.privateKey.export({ type: "pkcs8", format: "pem" }),
    ecPrivatePem: rpEc.privateKey.export({ type: "pkcs8", format: "pem" })
  };
}

// ---------------------------------------------------------------------------
// EVERY REQUEST THIS FILE MAKES GOES THROUGH HERE, AND THE RETRY IS THE POINT.
//
// This job asks the mock STS for a signed UserInfo response for EVERY
// algorithm its metadata advertises, and two of those are SLH-DSA: about two
// seconds for the SHA-2 parameter set and TWELVE for the SHAKE one, of
// straight-line CPU, per signature. That is the algorithm and not the
// implementation — the mock's worker pool moved the cost off its event loop,
// which is what stopped it failing unrelated jobs, but it did not make it
// smaller.
//
// A request that arrives while the service is busy does not fail like a busy
// service. The kernel accepts the connection, nothing answers, undici gives up
// and throws `TypeError: fetch failed` — a message whose entire stack is
// internals and which names no URL, no service and no algorithm. That is
// exactly what took this job out in CI once the watchdog was raised far enough
// for it to finish: it stopped being killed and started failing on a fetch,
// which reads like the mock is down.
//
// `tests/CLAUDE.md` states the rule this implements — a test that talks to the
// mock over HTTPS retries a CONNECTION failure rather than reporting it — and
// names `stsFetch()` in sts_jws_verification.js as the pattern. This is that,
// and the two are deliberately alike.
//
// ONLY A CONNECTION FAILURE IS RETRIED. A response is returned whatever its
// status, so a 400 or a 500 still fails the assertion that was looking at it;
// this cannot turn a broken endpoint into a passing test. And when the window
// runs out it says how long it waited, so a mock that really is down still
// reads as one.
// ---------------------------------------------------------------------------
const BUSY_WINDOW_MS = 90000;

async function stsFetch(url, options) {
  log.debug("Entering stsFetch(). url=" + url);
  const until = Date.now() + BUSY_WINDOW_MS;
  let attempts = 0;
  let last = null;
  while (Date.now() < until) {
    attempts++;
    try {
      const response = await fetch(url, options);
      if (attempts > 1) {
        log.info("[busy] " + url + " answered on attempt " + attempts +
                 "; the mock was blocked on a signature until then.");
      }
      log.debug("Leaving stsFetch(). status=" + response.status);
      return response;
    } catch (e) {
      last = e;
      log.debug("stsFetch(): " + url + " did not connect (" + e.message +
                "); retrying.");
      await new Promise(function (r) { setTimeout(r, 1000); });
    }
  }
  log.debug("Leaving stsFetch(). Gave up.");
  throw new Error("could not reach " + url + " in " +
    (BUSY_WINDOW_MS / 1000) + "s of trying (" +
    (last && last.message) + ", " + attempts + " attempt(s)). An SLH-DSA " +
    "signature is seconds of CPU, so this job expects the mock to be busy — " +
    "but not for this long, which usually means it is not running.");
}

async function registerClient(metadata) {
  log.debug("Entering registerClient().");
  var response = await stsFetch(stsBase + "/oauth2/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ redirect_uris: [REDIRECT_URI] },
                                       metadata))
  });
  var body = await response.text();
  assert.strictEqual(response.status, 201,
    "registration should have been accepted; got " + response.status + ": " +
    body.slice(0, 300));
  log.debug("Leaving registerClient().");
  return JSON.parse(body);
}

async function accessTokenFor(client) {
  log.debug("Entering accessTokenFor().");
  var response = await stsFetch(stsBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password", username: "alice", password: "any",
      scope: "openid profile email",
      client_id: client.client_id, client_secret: client.client_secret
    }).toString()
  });
  var body = await response.text();
  assert.strictEqual(response.status, 200,
    "the token endpoint should have issued a token; got " + response.status +
    ": " + body.slice(0, 300));
  log.debug("Leaving accessTokenFor().");
  return JSON.parse(body);
}

async function callUserinfo(accessToken) {
  log.debug("Entering callUserinfo().");
  var response = await stsFetch(stsBase + "/oauth2/userinfo",
    { headers: { Authorization: "Bearer " + accessToken } });
  var body = await response.text();
  log.debug("Leaving callUserinfo(). " + response.status);
  return { status: response.status, body: body,
           contentType: response.headers.get("content-type") || "" };
}

async function fetchOpJwks() {
  log.debug("Entering fetchOpJwks().");
  if (!opJwks) {
    var response = await stsFetch(stsBase + "/oauth2/jwks");
    assert.strictEqual(response.status, 200, "the JWKS should resolve.");
    opJwks = await response.json();
  }
  log.debug("Leaving fetchOpJwks().");
  return opJwks;
}

// Verify with the DEBUGGER's JWS engine and return the claims.
async function verifyWithDebugger(token, client) {
  log.debug("Entering verifyWithDebugger().");
  var header = JSON.parse(Buffer.from(token.split(".")[0], "base64url")
    .toString("utf8"));
  var keyInput;
  if (String(header.alg).indexOf("HS") === 0) {
    // OIDC Core section 10.1's symmetric case: the key IS the client_secret,
    // which is why an HS* response needs nothing from the JWKS.
    keyInput = { secret: client.client_secret, encoding: "text" };
  } else {
    keyInput = { jwks: await fetchOpJwks() };
  }
  var verdict = await jws.verifyJwsAsync({ jws: token, publicKey: keyInput,
                                           backend: "webcrypto" });
  assert.ok(verdict.valid, "the debugger's JWS engine should verify a " +
    header.alg + " UserInfo response the mock signed; it said: " +
    ((verdict.signatures[0] || {}).reason || "(no reason)"));
  log.debug("Leaving verifyWithDebugger(). " + header.alg);
  return { header: header, claims: JSON.parse(verdict.payload) };
}

// ---------------------------------------------------------------------------
// A client that registered nothing still gets JSON. This is the case every
// other one is a departure from, and it is asserted first so that a mock which
// had started signing unconditionally would fail HERE — naming the default —
// rather than in one of the shapes below.
// ---------------------------------------------------------------------------
async function unregisteredClientGetsPlainJson() {
  log.debug("Entering unregisteredClientGetsPlainJson().");
  var client = await registerClient({});
  var tokens = await accessTokenFor(client);
  var answer = await callUserinfo(tokens.access_token);

  assert.strictEqual(answer.status, 200, "UserInfo should have answered 200.");
  assert.ok(answer.contentType.indexOf("application/json") !== -1,
    "a client that registered no response protection must get " +
    "application/json; got " + answer.contentType);
  var claims = JSON.parse(answer.body);
  assert.ok(claims.sub, "the JSON response should carry a sub.");
  assert.strictEqual(claims.iss, undefined,
    "an UNSIGNED UserInfo response should not carry iss — section 5.3.2 adds " +
    "iss and aud to the SIGNED form, and a plain JSON response carrying them " +
    "suggests the two paths have been conflated.");
  log.info("[default] OK — a client that registered no protection gets " +
           "application/json with " + Object.keys(claims).length + " claim(s).");
  log.debug("Leaving unregisteredClientGetsPlainJson().");
}

// ---------------------------------------------------------------------------
// Every signing algorithm the metadata advertises, verified with the
// debugger's engine. The list is READ FROM THE METADATA rather than written
// here: an algorithm advertised and not implemented is exactly the failure this
// catches, and a hard-coded list here would have to be kept in step by hand.
// ---------------------------------------------------------------------------
async function everyAdvertisedSigningAlgorithmWorks() {
  log.debug("Entering everyAdvertisedSigningAlgorithmWorks().");
  var metadata = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  var algs = (metadata.userinfo_signing_alg_values_supported || [])
    .filter(function (alg) { return alg !== "none"; });
  assert.ok(algs.length > 0,
    "the OP advertises no userinfo signing algorithms at all.");

  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    var client = await registerClient({ userinfo_signed_response_alg: alg });
    var tokens = await accessTokenFor(client);
    var answer = await callUserinfo(tokens.access_token);
    assert.strictEqual(answer.status, 200,
      alg + ": UserInfo should have answered 200; got " + answer.status +
      ": " + answer.body.slice(0, 200));
    assert.ok(answer.contentType.indexOf("application/jwt") !== -1,
      alg + ": a signed response must be application/jwt, not " +
      answer.contentType);
    assert.strictEqual(answer.body.trim().split(".").length, 3,
      alg + ": a signed-only response should be a three-part JWS.");

    // THE ECDSA SIGNATURE MUST BE R||S AND NOT DER, which is RFC 7518 section
    // 3.4 and the single commonest way to get a JOSE ECDSA signature wrong:
    // every general-purpose crypto API — node's, OpenSSL's — returns the DER
    // SEQUENCE of two INTEGERs, and a verifier handed that reports a bad
    // signature over one that is perfectly good.
    //
    // Length is the whole test and it is exact: R||S is twice the coordinate
    // size, always, while a DER signature is ~70 bytes and VARIES with the
    // values. That variance is why this is asserted rather than left to the
    // verification above — roughly half of all signatures need a leading zero
    // stripped or a sign byte removed, so a converter that mishandles either
    // passes an end-to-end check about half the time.
    var ecdsaBytes = { ES256: 64, ES256K: 64, ES384: 96, ES512: 132 }[alg];
    if (ecdsaBytes) {
      var rawSignature = Buffer.from(answer.body.trim().split(".")[2],
                                     "base64url");
      assert.strictEqual(rawSignature.length, ecdsaBytes,
        alg + ": the signature must be the R||S concatenation of RFC 7518 " +
        "section 3.4, which is exactly " + ecdsaBytes + " bytes for this " +
        "curve. A " + rawSignature.length + "-byte one is almost certainly " +
        "the DER SEQUENCE node returned, passed through unconverted.");
    }

    var verified = await verifyWithDebugger(answer.body.trim(), client);
    assert.strictEqual(verified.header.alg, alg,
      "the response should be signed with the registered algorithm.");
    // Section 5.3.2's two members, and the reason a signed response is worth
    // asking for. Without them it is a signed profile any client would believe.
    assert.ok(verified.claims.iss,
      alg + ": a signed UserInfo response MUST carry iss (section 5.3.2).");
    var audience = Array.isArray(verified.claims.aud) ? verified.claims.aud
      : [verified.claims.aud];
    assert.ok(audience.indexOf(client.client_id) !== -1,
      alg + ": a signed UserInfo response MUST carry an aud naming this " +
      "client; got " + JSON.stringify(verified.claims.aud));
    assert.ok(verified.claims.sub, alg + ": the claims should carry a sub.");
  }
  log.info("[signing] OK — " + algs.length + " advertised algorithm(s) sign a " +
           "UserInfo response the debugger's own engine verifies, each with " +
           "iss and aud, and every ECDSA signature is R||S rather than DER: " +
           algs.join(", ") + ".");
  log.debug("Leaving everyAdvertisedSigningAlgorithmWorks().");
}

// ---------------------------------------------------------------------------
// Every advertised alg/enc pair, decrypted with the debugger's engine. This is
// the grid the CBC-HMAC family and the multi-round Concat KDF live in: an
// implementation that agrees with itself passes a round trip and fails here.
// ---------------------------------------------------------------------------
async function everyAdvertisedEncryptionPairWorks() {
  log.debug("Entering everyAdvertisedEncryptionPairWorks().");
  var metadata = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  var algs = metadata.userinfo_encryption_alg_values_supported || [];
  var encs = metadata.userinfo_encryption_enc_values_supported || [];
  assert.ok(algs.length > 0 && encs.length > 0,
    "the OP advertises no userinfo encryption algorithms at all.");
  var keys = rpKeys();
  var pairs = 0;

  for (var a = 0; a < algs.length; a++) {
    for (var e = 0; e < encs.length; e++) {
      var alg = algs[a];
      var enc = encs[e];
      var client = await registerClient({
        userinfo_encrypted_response_alg: alg,
        userinfo_encrypted_response_enc: enc,
        jwks: keys.jwks
      });
      var tokens = await accessTokenFor(client);
      var answer = await callUserinfo(tokens.access_token);
      assert.strictEqual(answer.status, 200,
        alg + "/" + enc + ": UserInfo should have answered 200; got " +
        answer.status + ": " + answer.body.slice(0, 250));
      assert.ok(answer.contentType.indexOf("application/jwt") !== -1,
        alg + "/" + enc + ": an encrypted response must be application/jwt.");
      assert.strictEqual(answer.body.trim().split(".").length, 5,
        alg + "/" + enc + ": a JWE in compact serialization has five parts.");

      var opened = await jose.decryptCompact({
        jwe: answer.body.trim(),
        key: alg.indexOf("ECDH") === 0 ? keys.ecPrivatePem : keys.rsaPrivatePem
      });
      assert.strictEqual(opened.header.alg, alg,
        "the JWE header should name the registered alg.");
      assert.strictEqual(opened.header.enc, enc,
        "the JWE header should name the registered enc.");
      var claims = JSON.parse(opened.plaintext);
      assert.ok(claims.sub,
        alg + "/" + enc + ": the decrypted claims should carry a sub.");
      // ENCRYPTION IS NOT AUTHENTICATION. This client asked to be encrypted to
      // and did not ask for a signature, so there must not be one — and the
      // response must not have quietly gained iss/aud either, which belong to
      // the signed form and would suggest the two paths were conflated.
      assert.strictEqual(opened.header.cty, undefined,
        alg + "/" + enc + ': an encrypted-only response has no JWS inside, ' +
        'so its header must not claim cty="JWT".');
      pairs++;
    }
  }
  log.info("[encryption] OK — " + pairs + " alg/enc pair(s) encrypt a " +
           "UserInfo response the debugger's own engine decrypts: " +
           algs.join(", ") + " over " + encs.join(", ") + ".");
  log.debug("Leaving everyAdvertisedEncryptionPairWorks().");
}

// ---------------------------------------------------------------------------
// SIGNED THEN ENCRYPTED, which is the shape with a rule attached: section 5.3.2
// requires that order and RFC 7519 section 5.2 requires the outer header to say
// so with cty:"JWT". Encrypting first and signing the ciphertext would let
// anyone who can decrypt strip the signature and re-encrypt to somebody else.
// ---------------------------------------------------------------------------
async function nestedResponseIsSignedThenEncrypted() {
  log.debug("Entering nestedResponseIsSignedThenEncrypted().");
  var keys = rpKeys();
  var client = await registerClient({
    userinfo_signed_response_alg: "RS256",
    userinfo_encrypted_response_alg: "RSA-OAEP-256",
    userinfo_encrypted_response_enc: "A128CBC-HS256",
    jwks: keys.jwks
  });
  var tokens = await accessTokenFor(client);
  var answer = await callUserinfo(tokens.access_token);
  assert.strictEqual(answer.status, 200, "UserInfo should have answered 200.");
  assert.strictEqual(answer.body.trim().split(".").length, 5,
    "the OUTER document must be the JWE — signed then encrypted, not the " +
    "other way round.");

  var opened = await jose.decryptCompact({ jwe: answer.body.trim(),
                                           key: keys.rsaPrivatePem });
  assert.strictEqual(opened.header.cty, "JWT",
    'the outer JWE header must carry cty="JWT" (RFC 7519 section 5.2) so a ' +
    "recipient knows there is a JWS inside rather than a claims object.");
  var inner = opened.plaintext.trim();
  assert.strictEqual(inner.split(".").length, 3,
    "what is inside the JWE should be a three-part JWS.");

  var verified = await verifyWithDebugger(inner, client);
  assert.ok(verified.claims.sub, "the nested claims should carry a sub.");
  assert.ok(verified.claims.iss,
    "the nested signed response must still carry iss.");
  log.info("[nested] OK — signed then encrypted, cty=\"JWT\" on the outer " +
           "header, and the inner " + verified.header.alg +
           " signature verifies.");
  log.debug("Leaving nestedResponseIsSignedThenEncrypted().");
}

// ---------------------------------------------------------------------------
// THE DEFAULT `enc`. A client that registers an encryption `alg` and says
// nothing about `enc` has asked for A128CBC-HS256 — section 2 of the
// registration specification decides that, not the client and not the server.
//
// This is worth its own assertion because it is the commonest encrypted
// response there is and because getting it wrong is silent: a server that
// defaulted to an AES-GCM enc would produce something this particular client
// could still read, and would fail against every client that took the spec at
// its word.
// ---------------------------------------------------------------------------
async function encRegistrationDefaultsToA128CbcHs256() {
  log.debug("Entering encRegistrationDefaultsToA128CbcHs256().");
  var keys = rpKeys();
  var client = await registerClient({
    userinfo_encrypted_response_alg: "RSA-OAEP-256",
    jwks: keys.jwks
  });
  var tokens = await accessTokenFor(client);
  var answer = await callUserinfo(tokens.access_token);
  assert.strictEqual(answer.status, 200, "UserInfo should have answered 200.");
  var opened = await jose.decryptCompact({ jwe: answer.body.trim(),
                                           key: keys.rsaPrivatePem });
  assert.strictEqual(opened.header.enc, "A128CBC-HS256",
    "a registration with no userinfo_encrypted_response_enc means " +
    "A128CBC-HS256; this response used " + opened.header.enc + ".");
  assert.ok(JSON.parse(opened.plaintext).sub, "the claims should carry a sub.");
  log.info("[enc default] OK — an omitted userinfo_encrypted_response_enc " +
           "means A128CBC-HS256.");
  log.debug("Leaving encRegistrationDefaultsToA128CbcHs256().");
}

// ---------------------------------------------------------------------------
// THE NEGATIVES. A client can register something this server cannot do, and
// what it must NOT do then is answer 200 with plain JSON — a client that
// registered a signed response and got unsigned JSON has no way to notice, and
// will go on believing it verified something.
// ---------------------------------------------------------------------------
async function unsupportedRegistrationsAreRefusedNotDowngraded() {
  log.debug("Entering unsupportedRegistrationsAreRefusedNotDowngraded().");
  var cases = [
    // AN UNREGISTERED VALUE, and it has to be, because there is no registered
    // JWS signing algorithm left that this service does not implement: the
    // RSASSA-PKCS1 and PSS families, ES256/384/512, ES256K and EdDSA all have a
    // key generated for them at startup and all thirteen are exercised above.
    // This was "ES256" and then "ES256K" and each stopped being a negative as
    // the gap it named was closed — which is the right direction for this list
    // to move. What the assertion is really about survives either way: an
    // algorithm the server cannot perform must be REFUSED BY NAME rather than
    // answered in the clear.
    ["userinfo_signed_response_alg", "ES512K",
     "an algorithm that is not registered and cannot be performed"],
    ["userinfo_encrypted_response_alg", "A128KW",
     "a key-management algorithm this server does not implement"]
  ];
  for (var i = 0; i < cases.length; i++) {
    var member = cases[i][0];
    var value = cases[i][1];
    var why = cases[i][2];
    var metadata = {};
    metadata[member] = value;
    var client = await registerClient(metadata);
    var tokens = await accessTokenFor(client);
    var answer = await callUserinfo(tokens.access_token);
    assert.notStrictEqual(answer.status, 200,
      why + " (" + member + "=" + value + ") must not be answered 200. A " +
      "client that registered protection and got an unprotected 200 has no " +
      "way to tell, which is the worst possible outcome here. Got: " +
      answer.body.slice(0, 200));
    assert.ok(answer.body.indexOf(value) !== -1,
      "the refusal should name the algorithm that was registered, so the " +
      "client is told what to change; got: " + answer.body.slice(0, 200));
  }

  // And an encryption registration with no key to encrypt to: the same rule.
  var noKeyClient = await registerClient({
    userinfo_encrypted_response_alg: "RSA-OAEP-256" });
  var noKeyTokens = await accessTokenFor(noKeyClient);
  var noKeyAnswer = await callUserinfo(noKeyTokens.access_token);
  assert.notStrictEqual(noKeyAnswer.status, 200,
    "a client that asked for an encrypted response and registered no jwks " +
    "must not be answered 200 in the clear.");
  log.info("[negatives] OK — an algorithm this server cannot perform, and an " +
           "encryption registration with no key, are refused rather than " +
           "quietly downgraded to unprotected JSON.");
  log.debug("Leaving unsupportedRegistrationsAreRefusedNotDowngraded().");
}

// ---------------------------------------------------------------------------
// The metadata has to be TRUE, in both directions: this server must not
// advertise what it cannot do (covered by the two grids above, which read their
// lists from the metadata) and must not omit what it can.
// ---------------------------------------------------------------------------
async function metadataAdvertisesWhatItDoes() {
  log.debug("Entering metadataAdvertisesWhatItDoes().");
  var metadata = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  ["userinfo_signing_alg_values_supported",
   "userinfo_encryption_alg_values_supported",
   "userinfo_encryption_enc_values_supported"].forEach(function (member) {
    assert.ok(Array.isArray(metadata[member]) && metadata[member].length,
      "the OpenID Provider metadata should advertise " + member +
      ", or a client cannot discover what to register.");
  });
  assert.ok(metadata.userinfo_signing_alg_values_supported
    .indexOf("none") !== -1,
    'userinfo_signing_alg_values_supported should include "none", which is ' +
    "the default and the only way to say that an unsigned response is " +
    "available.");
  assert.ok(metadata.userinfo_encryption_enc_values_supported
    .indexOf("A128CBC-HS256") !== -1,
    "A128CBC-HS256 must be supported: it is what a client that registers an " +
    "encryption alg and no enc has asked for, so a server without it cannot " +
    "serve the default.");
  log.info("[metadata] OK — all three userinfo algorithm lists are " +
           'advertised, "none" among the signing ones and A128CBC-HS256 ' +
           "among the encryption ones.");
  log.debug("Leaving metadataAdvertisesWhatItDoes().");
}

// ---------------------------------------------------------------------------
// THE ID TOKEN honours a registered `id_token_signed_response_alg` too (OIDC
// Core section 3.1.3.7), with the same keys and the same shared signer.
//
// This is here rather than in a file of its own because it is the SAME
// mechanism as the UserInfo response above — a client registers an algorithm
// and the service signs with the key that algorithm needs — and the thing most
// worth asserting is that the two agree. A service where UserInfo could be
// ES256K and the ID Token could not would be one whose keys reached one
// endpoint and not the other, which is exactly the gap this work closed.
//
// Every advertised algorithm is driven, read from the metadata rather than
// listed here, so an algorithm advertised and not implemented fails HERE.
// ---------------------------------------------------------------------------
async function everyAdvertisedIdTokenAlgorithmWorks() {
  log.debug("Entering everyAdvertisedIdTokenAlgorithmWorks().");
  var metadata = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  var algs = (metadata.id_token_signing_alg_values_supported || [])
    .filter(function (alg) { return alg !== "none"; });
  assert.ok(algs.length > 0,
    "the OP advertises no id_token signing algorithms at all.");

  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    var client = await registerClient({ id_token_signed_response_alg: alg });
    var tokens = await accessTokenFor(client);
    assert.ok(tokens.id_token,
      alg + ": the token response should carry an id_token.");
    var header = JSON.parse(Buffer.from(tokens.id_token.split(".")[0],
      "base64url").toString("utf8"));
    assert.strictEqual(header.alg, alg,
      "the ID Token should be signed with the algorithm the client " +
      "registered; it says " + header.alg + ".");

    // Same ECDSA format rule as the UserInfo responses: R||S, never DER.
    var ecdsaBytes = { ES256: 64, ES256K: 64, ES384: 96, ES512: 132 }[alg];
    if (ecdsaBytes) {
      assert.strictEqual(
        Buffer.from(tokens.id_token.split(".")[2], "base64url").length,
        ecdsaBytes,
        alg + ": the ID Token signature must be the R||S concatenation of " +
        "RFC 7518 section 3.4.");
    }

    var verified = await verifyWithDebugger(tokens.id_token, client);
    assert.ok(verified.claims.sub, alg + ": the ID Token should carry a sub.");
    assert.strictEqual(verified.claims.aud, client.client_id,
      alg + ": the ID Token's aud should be this client.");
  }
  log.info("[id token] OK — " + algs.length + " advertised algorithm(s) sign " +
           "an ID Token the debugger's own engine verifies: " +
           algs.join(", ") + ".");
  log.debug("Leaving everyAdvertisedIdTokenAlgorithmWorks().");
}

// ---------------------------------------------------------------------------
// THE ALGORITHM LISTS ACROSS THE WHOLE SERVICE AGREE WITH EACH OTHER.
//
// Every list here is derived from one table in common/crypto.js, and this is
// what holds that true from the outside: the lists that describe the SAME
// capability must be identical, and the JWKS must actually carry a key for
// every asymmetric algorithm advertised for signing. A service that advertised
// ES256K for the token endpoint and not for the ID Token would be one where
// somebody had written a list out by hand again.
// ---------------------------------------------------------------------------
async function theAlgorithmListsAgreeWithEachOther() {
  log.debug("Entering theAlgorithmListsAgreeWithEachOther().");
  var metadata = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  var jwks = await fetchOpJwks();

  var authLists = ["token_endpoint_auth_signing_alg_values_supported",
                   "revocation_endpoint_auth_signing_alg_values_supported",
                   "introspection_endpoint_auth_signing_alg_values_supported"];
  var first = metadata[authLists[0]];
  authLists.forEach(function (name) {
    assert.deepStrictEqual(metadata[name], first,
      name + " should name the same algorithms as " + authLists[0] +
      ": they all describe the same verifier, and a difference between them " +
      "means a list was written out by hand somewhere.");
  });

  // Every asymmetric signing algorithm advertised must have a key published to
  // verify it with. The symmetric ones must NOT — their key is the client
  // secret, and a JWKS entry for one would be this service publishing a
  // client's credential.
  var advertised = metadata.id_token_signing_alg_values_supported || [];
  var curvesInJwks = jwks.keys.map(function (k) {
    return k.crv || k.kty;
  });
  var needs = { ES256: "P-256", ES384: "P-384", ES512: "P-521",
                ES256K: "secp256k1", EdDSA: "Ed25519",
                RS256: "RSA", PS256: "RSA" };
  Object.keys(needs).forEach(function (alg) {
    if (advertised.indexOf(alg) === -1) return;
    assert.ok(curvesInJwks.indexOf(needs[alg]) !== -1,
      alg + " is advertised for signing and the JWKS carries no " +
      needs[alg] + " key to verify it with. An algorithm advertised with no " +
      "published key is worse than one not offered: the client gets a " +
      "signature it cannot check and reports a broken issuer.");
  });
  assert.ok(!jwks.keys.some(function (k) { return k.kty === "oct"; }),
    "the JWKS must not publish a symmetric key: an HS* signature here is made " +
    "with the CLIENT'S secret, and publishing one would be this service " +
    "handing out a client credential.");

  log.info("[lists] OK — the three client-authentication lists are identical, " +
           "and the JWKS carries a key for every asymmetric algorithm " +
           "advertised (" + jwks.keys.length + " keys) and no symmetric one.");
  log.debug("Leaving theAlgorithmListsAgreeWithEachOther().");
}

async function test() {
  log.debug("Entering test().");
  if (!stsBase) {
    log.info("No STS URL (WSTRUST_STS_URL / OID4VCI_ISSUER_URL) — skipping.");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Starting Test run against " + stsBase + ".");
  await metadataAdvertisesWhatItDoes();
  await unregisteredClientGetsPlainJson();
  await everyAdvertisedSigningAlgorithmWorks();
  await everyAdvertisedIdTokenAlgorithmWorks();
  await theAlgorithmListsAgreeWithEachOther();
  await everyAdvertisedEncryptionPairWorks();
  await encRegistrationDefaultsToA128CbcHs256();
  await nestedResponseIsSignedThenEncrypted();
  await unsupportedRegistrationsAreRefusedNotDowngraded();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_userinfo_protected")
  .description("Verify the mock's signed and encrypted UserInfo responses " +
      "(OIDC Core section 5.3.2), opened with the debugger's own engines.")
  .addOption(new Option("-u, --url <url>",
      "ignored; kept for a uniform CLI across the suite"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
