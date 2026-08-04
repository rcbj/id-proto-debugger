// File: sts_dpop.js
//
// DPoP end to end against the mock authorization server and the OID4VCI issuer
// it hosts — RFC 9449, driven over HTTP with no browser.
//
// The point of this file is the NEGATIVES. A DPoP implementation that issues
// bound tokens and accepts valid proofs looks finished and can still be worth
// nothing, because the value is entirely in what it REFUSES. Every one of the
// following omissions leaves a server that passes a happy-path test:
//
//   * not checking the signature — any client claims any key;
//   * not checking htm/htu — one captured proof works at every endpoint,
//     including the token endpoint's proof replayed at the credential endpoint;
//   * not checking ath — a proof captured with one token is presented with
//     another, which is the theft DPoP exists to stop;
//   * not comparing the token's cnf.jkt with the proof's key — the token is
//     bound to nothing and the client's own key is simply believed;
//   * not checking typ — some other JWT the client signed with the same key is
//     accepted, and this workflow signs one: the OID4VCI proof of possession;
//   * accepting a bound token presented as Bearer — the single most likely way
//     to implement DPoP and gain nothing at all;
//   * not remembering jti — a captured proof is reusable for its whole window.
//
// So each is asserted directly, and each assertion names the check it is about
// rather than only that the request failed. A server that refused everything
// would pass a test that only looked at the status code, which is why the happy
// paths are interleaved rather than run once at the start.
//
// Needs the STS mock and nothing else — no browser, no Keycloak — so it is
// skipped only when there is no STS to talk to.

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_dpop",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var stsBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var TOKEN_ENDPOINT = stsBase + "/oauth2/token";
var CREDENTIAL_ENDPOINT = stsBase + "/oid4vci/credential";
var NONCE_ENDPOINT = stsBase + "/oid4vci/nonce";
var NOTIFICATION_ENDPOINT = stsBase + "/oid4vci/notification";
var CLIENT_ID = "dpop-test-client";

function b64u(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString("utf8")); }
function claimsOf(token) { return jsonFromB64u(String(token).split(".")[1]); }

// ---------------------------------------------------------------------------
// A DPoP client, written here rather than borrowed from client/src/dpop.js ON
// PURPOSE. If both sides of this exchange came from the same implementation, a
// shared misunderstanding — the thumbprint's member order, say — would make the
// test pass and interoperate with nobody. tests/dpop.js checks that module
// against the RFCs' own vectors; this file checks the SERVER against an
// independent client.
// ---------------------------------------------------------------------------
function newKey(type) {
  log.debug("Entering newKey(). type=" + type);
  var pair = type === "rsa"
    ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    : crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });
  log.debug("Leaving newKey().");
  return {
    alg: type === "rsa" ? "RS256" : "ES256",
    privateKey: pair.privateKey,
    publicJwk: type === "rsa"
      ? { kty: jwk.kty, n: jwk.n, e: jwk.e }
      : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
  };
}

function jkt(key) {
  var j = key.publicJwk;
  var canonical = j.kty === "RSA"
    ? JSON.stringify({ e: j.e, kty: j.kty, n: j.n })
    : JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y });
  return crypto.createHash("sha256").update(canonical, "utf8").digest("base64url");
}

function athOf(token) {
  return crypto.createHash("sha256").update(String(token), "ascii").digest("base64url");
}

// `over` lets a negative case override any part of the proof — the whole point
// of the file, so it is a first-class parameter rather than a special case.
function makeProof(key, opts) {
  var over = opts.over || {};
  var header = Object.assign({ typ: "dpop+jwt", alg: key.alg, jwk: key.publicJwk },
                             over.header || {});
  var payload = Object.assign({
    jti: b64u(crypto.randomBytes(16)),
    htm: String(opts.htm || "POST").toUpperCase(),
    htu: String(opts.htu).split("?")[0].split("#")[0],
    iat: Math.floor(Date.now() / 1000)
  }, opts.accessToken ? { ath: athOf(opts.accessToken) } : {},
     opts.nonce ? { nonce: opts.nonce } : {},
     over.payload || {});
  // A negative may need a claim ABSENT, which Object.assign cannot express.
  (over.remove || []).forEach(function (c) { delete payload[c]; });
  (over.removeHeader || []).forEach(function (h) { delete header[h]; });

  var signingInput = b64u(JSON.stringify(header)) + "." + b64u(JSON.stringify(payload));
  var signature;
  if (over.badSignature) {
    signature = crypto.randomBytes(key.alg === "RS256" ? 256 : 64);
  } else if (key.alg === "RS256") {
    signature = crypto.sign("sha256", Buffer.from(signingInput, "ascii"), key.privateKey);
  } else {
    signature = crypto.sign("sha256", Buffer.from(signingInput, "ascii"),
                            { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  }
  return signingInput + "." + b64u(signature);
}

async function post(url, opts) {
  var options = opts || {};
  var headers = Object.assign({}, options.headers || {});
  var body;
  if (options.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(options.form).toString();
  } else if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  }
  var r = await fetch(url, { method: "POST", headers: headers, body: body, redirect: "manual" });
  var text = await r.text();
  var parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    // Not JSON. That is itself information for a caller checking an error shape,
    // so it is reported rather than thrown.
    parsed = null;
  }
  return {
    status: r.status, body: parsed, text: text,
    headers: r.headers,
    dpopNonce: r.headers.get("DPoP-Nonce") || "",
    authenticate: r.headers.get("WWW-Authenticate") || ""
  };
}

// A Bearer token and a DPoP-bound token, both by client_credentials — the
// shortest grant that needs no browser.
async function bearerToken() {
  var r = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "client_credentials", client_id: CLIENT_ID, scope: "openid" }
  });
  assert.strictEqual(r.status, 200, "could not get a Bearer token: " + r.text.slice(0, 200));
  return r.body;
}

async function boundToken(key, extra) {
  var proof = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT, nonce: (extra || {}).nonce });
  var r = await post(TOKEN_ENDPOINT, {
    form: Object.assign({ grant_type: "client_credentials", client_id: CLIENT_ID, scope: "openid" },
                        (extra || {}).form || {}),
    headers: { DPoP: proof }
  });
  return r;
}

// ---------------------------------------------------------------------------
async function serverAdvertisesDpop() {
  log.debug("Entering serverAdvertisesDpop().");
  log.info("=== The authorization server advertises DPoP (RFC 9449 section 5.1) ===");
  var r = await fetch(stsBase + "/.well-known/oauth-authorization-server");
  assert.strictEqual(r.status, 200, "the RFC 8414 metadata did not load.");
  var meta = await r.json();
  var algs = meta.dpop_signing_alg_values_supported;
  assert.ok(Array.isArray(algs) && algs.length,
    "dpop_signing_alg_values_supported must be advertised: it is the ONLY signal a wallet has " +
    "that DPoP is on offer, so a server that supports it silently will never be asked.");
  assert.ok(algs.indexOf("ES256") >= 0, "ES256 must be among them; got " + algs.join(", "));
  assert.strictEqual(algs.indexOf("none"), -1, "none must never be advertised.");
  assert.strictEqual(algs.indexOf("HS256"), -1,
    "no MAC may be advertised — the server would hold the same secret and could mint proofs.");
  log.info("[metadata] OK — " + algs.length + " algorithms, all asymmetric.");
  log.debug("Leaving serverAdvertisesDpop().");
}

async function bearerStillWorks() {
  log.debug("Entering bearerStillWorks().");
  log.info("=== A request with no DPoP proof is still a Bearer request ===");
  var token = await bearerToken();
  assert.strictEqual(token.token_type, "Bearer",
    "a Token Request with no DPoP header must yield a Bearer token — adding DPoP must not " +
    "break the Bearer clients this server also exists to exercise.");
  assert.strictEqual(claimsOf(token.access_token).cnf, undefined,
    "and that token must carry no cnf: there is nothing to confirm.");
  log.info("[bearer] OK — unbound, and announced as Bearer.");
  log.debug("Leaving bearerStillWorks().");
}

async function tokenIsBoundToTheProofKey() {
  log.debug("Entering tokenIsBoundToTheProofKey().");
  log.info("=== The Token Request binds the token (RFC 9449 sections 5, 6.1) ===");
  var key = newKey("ec");
  var r = await boundToken(key);
  assert.strictEqual(r.status, 200, "a valid DPoP proof was refused: " + r.text.slice(0, 300));
  assert.strictEqual(r.body.token_type, "DPoP",
    "token_type must be DPoP, not Bearer: it is how the wallet learns it must send a proof on " +
    "every later call. Got " + r.body.token_type);
  var claims = claimsOf(r.body.access_token);
  assert.ok(claims.cnf && claims.cnf.jkt,
    "the access token must carry cnf.jkt — inside the signed token, so a resource server can " +
    "check the binding without asking anybody.");
  assert.strictEqual(claims.cnf.jkt, jkt(key),
    "cnf.jkt must be the RFC 7638 thumbprint of the key that signed the proof, computed here " +
    "by an independent implementation. Got " + claims.cnf.jkt + ", expected " + jkt(key));
  log.info("[token] OK — token_type DPoP and cnf.jkt is this client's own thumbprint.");

  // An RSA proof must work too, or the advertised algorithm list is a lie.
  var rsa = newKey("rsa");
  var r2 = await boundToken(rsa);
  assert.strictEqual(r2.status, 200, "an RS256 DPoP proof was refused: " + r2.text.slice(0, 200));
  assert.strictEqual(claimsOf(r2.body.access_token).cnf.jkt, jkt(rsa),
    "an RSA key's thumbprint uses e/kty/n — a different member list from an EC key's, and a " +
    "server that hard-coded the EC list would fail exactly here.");
  log.info("[token] OK — RS256 accepted and its RSA thumbprint is right.");

  log.debug("Leaving tokenIsBoundToTheProofKey().");
  return { key: key, token: r.body };
}

async function tokenEndpointRefusesBadProofs() {
  log.debug("Entering tokenEndpointRefusesBadProofs().");
  log.info("=== The token endpoint's proof checks (RFC 9449 section 4.3) ===");
  var key = newKey("ec");
  var cases = [
    ["check 4: typ", { header: { typ: "JWT" } },
     "some other JWT the client signed with the same key would be accepted as a proof — and " +
     "this very workflow signs one, the OID4VCI openid4vci-proof+jwt"],
    ["check 5: alg none", { header: { alg: "none" } }, "an unsigned proof proves nothing"],
    ["check 5: a MAC", { header: { alg: "HS256" } },
     "the server would hold the same secret and could mint proofs itself"],
    ["check 6: the signature", { badSignature: true },
     "without this check any client can claim any key"],
    ["check 7: private key in the header", { header: { jwk: Object.assign({ d: "AAAA" },
       key.publicJwk) } }, "RFC 9449 forbids private material in the jwk header"],
    ["check 3: no jti", { remove: ["jti"] }, "replay detection has nothing to work with"],
    ["check 3: no htm", { remove: ["htm"] }, "the proof is not tied to a method"],
    ["check 3: no htu", { remove: ["htu"] }, "the proof is not tied to an endpoint"],
    ["check 3: no iat", { remove: ["iat"] }, "the proof never goes stale"],
    ["check 8: the wrong htm", { payload: { htm: "GET" } },
     "a proof made for one method must not work for another"],
    ["check 9: the wrong htu", { payload: { htu: stsBase + "/oid4vci/credential" } },
     "THE credential endpoint's proof must not be usable at the token endpoint"],
    ["check 11: a stale iat", { payload: { iat: Math.floor(Date.now() / 1000) - 4000 } },
     "an old proof stays usable forever"],
    ["check 11: an iat in the future", { payload: { iat: Math.floor(Date.now() / 1000) + 4000 } },
     "a proof can be minted for later use"],
    ["check 2: not a JWT", { notAJwt: true }, "a malformed proof must be refused, not crash"]
  ];

  for (const [label, over, why] of cases) {
    var proof = over.notAJwt ? "this-is-not-a-jwt"
                             : makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT, over: over });
    var r = await post(TOKEN_ENDPOINT, {
      form: { grant_type: "client_credentials", client_id: CLIENT_ID, scope: "openid" },
      headers: { DPoP: proof }
    });
    assert.strictEqual(r.status, 400,
      label + ": this proof must be REFUSED (400), got " + r.status + ". Otherwise " + why + ".");
    assert.strictEqual(r.body && r.body.error, "invalid_dpop_proof",
      label + ": the error must be invalid_dpop_proof, got " +
      JSON.stringify(r.body && r.body.error) + ".");
    log.debug("  refused as it should be: " + label);
  }
  log.info("[token] OK — " + cases.length + " bad proofs each refused with invalid_dpop_proof.");

  // Two DPoP header fields (check 1). Express joins them with a comma, and a
  // compact JWS contains none, so accepting "either of them" would let an
  // attacker append their own proof to a captured request.
  var good = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT });
  var alsoGood = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT });
  var doubled = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "client_credentials", client_id: CLIENT_ID, scope: "openid" },
    headers: { DPoP: good + ", " + alsoGood }
  });
  assert.strictEqual(doubled.status, 400,
    "check 1: two DPoP header fields must be refused; accepting either would let an attacker " +
    "append their own proof to a captured request.");
  log.info("[token] OK — a doubled DPoP header is refused.");

  // And the control: a good proof still works after all that, so the refusals
  // above are not a server that simply stopped answering.
  var stillFine = await boundToken(newKey("ec"));
  assert.strictEqual(stillFine.status, 200,
    "after all those refusals a VALID proof must still be accepted — otherwise this section " +
    "proves only that the server says no.");
  log.info("[token] OK — a valid proof still works afterwards.");

  log.debug("Leaving tokenEndpointRefusesBadProofs().");
}

async function proofsAreSingleUse() {
  log.debug("Entering proofsAreSingleUse().");
  log.info("=== Replay (RFC 9449 section 11.1) ===");
  var key = newKey("ec");
  var proof = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT });
  var form = { grant_type: "client_credentials", client_id: CLIENT_ID, scope: "openid" };
  var first = await post(TOKEN_ENDPOINT, { form: form, headers: { DPoP: proof } });
  assert.strictEqual(first.status, 200, "the first use of a proof must work.");
  var second = await post(TOKEN_ENDPOINT, { form: form, headers: { DPoP: proof } });
  assert.strictEqual(second.status, 400,
    "the SAME proof must not work twice — without jti replay detection a captured proof stays " +
    "usable for its whole iat window, which is the difference between a proof of possession " +
    "and a password.");
  assert.ok(/already been used|jti/i.test(JSON.stringify(second.body)),
    "and the refusal should say it was a replay. Got: " + second.text.slice(0, 200));
  log.info("[replay] OK — a proof works once.");
  log.debug("Leaving proofsAreSingleUse().");
}

async function boundTokenIsUsableAtTheCredentialEndpoint(bound) {
  log.debug("Entering boundTokenIsUsableAtTheCredentialEndpoint().");
  log.info("=== The Credential Endpoint accepts the binding (RFC 9449 section 7) ===");
  var key = bound.key;
  var accessToken = bound.token.access_token;

  // The happy path. A 400 about the credential request's own contents is a PASS
  // here: it means authentication and the binding were accepted and the handler
  // went on to read the body. What must not happen is 401.
  var proof = makeProof(key, {
    htm: "POST", htu: CREDENTIAL_ENDPOINT, accessToken: accessToken
  });
  var ok = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: proof }
  });
  assert.notStrictEqual(ok.status, 401,
    "a correct DPoP presentation was rejected as unauthorized: " + ok.text.slice(0, 300));
  log.info("[resource] OK — accepted (status " + ok.status + ", not 401).");

  // The single most likely way to implement DPoP and gain nothing: accept the
  // bound token as a Bearer token. The bytes are identical, so only an explicit
  // check catches it.
  var asBearer = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "Bearer " + accessToken }
  });
  assert.strictEqual(asBearer.status, 401,
    "a DPoP-BOUND token presented as a Bearer token must be refused. The bytes are the same, " +
    "so a server that accepts either has thrown the binding away entirely and DPoP has bought " +
    "it nothing.");
  assert.ok(/DPoP/.test(asBearer.authenticate),
    "and the challenge must name DPoP so the client knows what to do. Got: " + asBearer.authenticate);
  log.info("[resource] OK — the bound token is refused when presented as Bearer.");

  // ath: a proof made for this token must not work with another one.
  var otherKey = newKey("ec");
  var otherBound = await boundToken(otherKey);
  var wrongAth = makeProof(key, {
    htm: "POST", htu: CREDENTIAL_ENDPOINT,
    accessToken: otherBound.body.access_token       // ath over the WRONG token
  });
  var athFail = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: wrongAth }
  });
  assert.strictEqual(athFail.status, 401,
    "check 12: a proof whose ath hashes a DIFFERENT token must be refused. Without this a " +
    "proof captured alongside one token can be presented with a stolen one, which is exactly " +
    "the theft DPoP exists to prevent.");
  log.info("[resource] OK — a proof with the wrong ath is refused.");

  // A missing ath entirely.
  var noAth = makeProof(key, {
    htm: "POST", htu: CREDENTIAL_ENDPOINT, accessToken: accessToken, over: { remove: ["ath"] }
  });
  var noAthResult = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: noAth }
  });
  assert.strictEqual(noAthResult.status, 401,
    "check 12: ath is REQUIRED when the proof accompanies an access token, so a proof without " +
    "one must be refused rather than treated as an older client.");
  log.info("[resource] OK — a proof with no ath at all is refused.");

  // cnf.jkt: the client's own key must not be believed over the token's binding.
  var attackerProof = makeProof(otherKey, {
    htm: "POST", htu: CREDENTIAL_ENDPOINT, accessToken: accessToken
  });
  var wrongKey = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: attackerProof }
  });
  assert.strictEqual(wrongKey.status, 401,
    "check 12: the proof key must match the token's cnf.jkt. This is the assertion that says " +
    "the token is bound to SOMETHING — without it a thief signs with their own key and is " +
    "believed, and every other check still passes.");
  log.info("[resource] OK — a proof from the wrong key is refused (cnf.jkt enforced).");

  // htu: the token endpoint's proof must not be reusable here.
  var wrongEndpoint = makeProof(key, {
    htm: "POST", htu: TOKEN_ENDPOINT, accessToken: accessToken
  });
  var htuFail = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: wrongEndpoint }
  });
  assert.strictEqual(htuFail.status, 401,
    "check 9: a proof made for the token endpoint must not be accepted at the credential " +
    "endpoint.");
  log.info("[resource] OK — a proof for another endpoint is refused.");

  // And an unbound token still works as a Bearer token at the same endpoint, so
  // none of the above is the endpoint simply refusing everything.
  var plain = await bearerToken();
  var bearerOk = await post(CREDENTIAL_ENDPOINT, {
    json: { credential_configuration_id: "IdentityCredential" },
    headers: { Authorization: "Bearer " + plain.access_token }
  });
  assert.notStrictEqual(bearerOk.status, 401,
    "an UNBOUND token must still be accepted as Bearer — the endpoint has not simply started " +
    "refusing everything. Got " + bearerOk.status + ": " + bearerOk.text.slice(0, 200));
  log.info("[resource] OK — a plain Bearer token is still accepted (status " +
           bearerOk.status + ").");

  log.debug("Leaving boundTokenIsUsableAtTheCredentialEndpoint().");
}

async function notificationEndpointIsProtectedToo() {
  log.debug("Entering notificationEndpointIsProtectedToo().");
  log.info("=== Every protected endpoint, not just the interesting one ===");
  var key = newKey("ec");
  var bound = await boundToken(key);
  var accessToken = bound.body.access_token;
  // The three protected endpoints shared one Bearer-only check before this work
  // and now share one that also does DPoP. The reason to test more than one is
  // that a per-endpoint copy is exactly how one of three ends up not demanding
  // the proof — and the one that forgot is the one an attacker would use.
  var asBearer = await post(NOTIFICATION_ENDPOINT, {
    json: { notification_id: "whatever", event: "credential_accepted" },
    headers: { Authorization: "Bearer " + accessToken }
  });
  assert.strictEqual(asBearer.status, 401,
    "the notification endpoint must refuse a bound token presented as Bearer, the same way the " +
    "credential endpoint does.");
  var proof = makeProof(key, {
    htm: "POST", htu: NOTIFICATION_ENDPOINT, accessToken: accessToken
  });
  var withProof = await post(NOTIFICATION_ENDPOINT, {
    json: { notification_id: "whatever", event: "credential_accepted" },
    headers: { Authorization: "DPoP " + accessToken, DPoP: proof }
  });
  assert.notStrictEqual(withProof.status, 401,
    "and must accept it with a valid proof: " + withProof.text.slice(0, 200));
  log.info("[resource] OK — the notification endpoint enforces the same rule (401 as Bearer, " +
           withProof.status + " with a proof).");
  log.debug("Leaving notificationEndpointIsProtectedToo().");
}

async function refreshTokenCarriesTheBinding() {
  log.debug("Entering refreshTokenCarriesTheBinding().");
  log.info("=== The refresh token is bound too (RFC 9449 section 5) ===");
  // A grant that issues a refresh token: password, which this mock accepts for
  // any password but "invalid".
  var key = newKey("ec");
  var proof = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT });
  var issued = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "password", username: "dpop-user", password: "anything",
            client_id: CLIENT_ID, scope: "openid" },
    headers: { DPoP: proof }
  });
  assert.strictEqual(issued.status, 200, "the password grant with a proof failed: " +
                     issued.text.slice(0, 200));
  assert.ok(issued.body.refresh_token, "this grant should have issued a refresh token.");
  var refreshClaims = claimsOf(issued.body.refresh_token);
  assert.ok(refreshClaims.cnf && refreshClaims.cnf.jkt === jkt(key),
    "a refresh token issued alongside a bound access token must itself be bound: a wallet is a " +
    "public client, so an unbound refresh token would be a bearer credential that mints bound " +
    "access tokens for whoever holds it — worse than not binding, because token_type would " +
    "claim a guarantee nothing checked.");
  log.info("[refresh] OK — the refresh token carries the same cnf.jkt.");

  // Redeeming it needs the key.
  var withoutProof = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "refresh_token", refresh_token: issued.body.refresh_token,
            client_id: CLIENT_ID }
  });
  assert.strictEqual(withoutProof.status, 400,
    "a bound refresh token must not be redeemable without a proof.");
  var wrongKeyProof = makeProof(newKey("ec"), { htm: "POST", htu: TOKEN_ENDPOINT });
  var withWrongKey = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "refresh_token", refresh_token: issued.body.refresh_token,
            client_id: CLIENT_ID },
    headers: { DPoP: wrongKeyProof }
  });
  assert.strictEqual(withWrongKey.status, 400,
    "nor by a different key — otherwise a stolen refresh token is laundered into one bound to " +
    "the thief's key, and the binding is decorative.");
  var rightKeyProof = makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT });
  var refreshed = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "refresh_token", refresh_token: issued.body.refresh_token,
            client_id: CLIENT_ID },
    headers: { DPoP: rightKeyProof }
  });
  assert.strictEqual(refreshed.status, 200, "the right key must be able to refresh: " +
                     refreshed.text.slice(0, 200));
  assert.strictEqual(claimsOf(refreshed.body.access_token).cnf.jkt, jkt(key),
    "and the new access token keeps the binding.");
  log.info("[refresh] OK — redeemable only by its own key, and the binding survives.");
  log.debug("Leaving refreshTokenCarriesTheBinding().");
}

async function nonceHandshakeWorks() {
  log.debug("Entering nonceHandshakeWorks().");
  log.info("=== The DPoP-Nonce handshake (RFC 9449 sections 8 and 9) ===");
  // Nonce mode is a server setting and this test drives the server over HTTP, so
  // it is turned on through the non-spec control endpoint the mock publishes for
  // exactly this purpose (and which /sts-metadata lists as non-spec).
  var on = await post(stsBase + "/dpop/nonce-mode", { json: { required: true } });
  if (on.status === 404) {
    log.warn("[nonce] SKIPPED — this STS has no /dpop/nonce-mode control endpoint.");
    return;
  }
  assert.strictEqual(on.status, 200, "could not turn nonce mode on: " + on.text.slice(0, 200));
  try {
    var key = newKey("ec");
    // First attempt, no nonce: the server must ASK rather than simply refuse, or
    // a conforming client has no way forward.
    var asked = await boundToken(key);
    assert.strictEqual(asked.status, 400,
      "with nonce mode on, a proof with no nonce must not be accepted.");
    assert.strictEqual(asked.body.error, "use_dpop_nonce",
      "the error must be use_dpop_nonce — a plain invalid_dpop_proof leaves a correct client " +
      "stuck. Got " + JSON.stringify(asked.body.error));
    assert.ok(asked.dpopNonce,
      "and the response must carry a DPoP-Nonce header for the retry.");
    log.info("[nonce] OK — the server asks, with a nonce to retry with.");

    // The retry.
    var retried = await boundToken(key, { nonce: asked.dpopNonce });
    assert.strictEqual(retried.status, 200,
      "the retry carrying the server's nonce must succeed: " + retried.text.slice(0, 200));
    log.info("[nonce] OK — the retry is accepted.");

    // An invented nonce must not do.
    var invented = await boundToken(newKey("ec"), { nonce: "a-nonce-nobody-issued" });
    assert.strictEqual(invented.status, 400,
      "a nonce the server never issued must be refused, or the claim checks nothing.");
    assert.strictEqual(invented.body.error, "use_dpop_nonce",
      "and the server should ask again rather than refuse outright.");
    log.info("[nonce] OK — an invented nonce is refused.");

    // OID4VCI's own mention of DPoP: the Nonce Endpoint may hand out a DPoP
    // nonce alongside the c_nonce, saving the 401 round trip.
    var nonceResponse = await post(NONCE_ENDPOINT, {});
    assert.strictEqual(nonceResponse.status, 200, "the OID4VCI nonce endpoint did not answer.");
    assert.ok(nonceResponse.body.c_nonce, "it must still return a c_nonce.");
    assert.ok(nonceResponse.dpopNonce,
      "and with nonce mode on it should also carry DPoP-Nonce — this is the one thing OID4VCI " +
      "says about DPoP by name, and the only place in the flow where the 401 handshake can be " +
      "skipped, since the wallet is already making this call for its c_nonce.");
    log.info("[nonce] OK — the OID4VCI Nonce Response carries a DPoP-Nonce.");

    // A resource server asks differently from an authorization server: 401 with
    // use_dpop_nonce in WWW-Authenticate, not a 400 JSON body. A client that
    // handles only one shape gets stuck on the other.
    var bound = await boundToken(key, { nonce: nonceResponse.dpopNonce });
    assert.strictEqual(bound.status, 200, "could not get a bound token for the resource test.");
    var noNonceProof = makeProof(key, {
      htm: "POST", htu: CREDENTIAL_ENDPOINT, accessToken: bound.body.access_token
    });
    var rs = await post(CREDENTIAL_ENDPOINT, {
      json: { credential_configuration_id: "IdentityCredential" },
      headers: { Authorization: "DPoP " + bound.body.access_token, DPoP: noNonceProof }
    });
    assert.strictEqual(rs.status, 401,
      "a resource server requiring a nonce answers 401, not 400. Got " + rs.status);
    assert.ok(/use_dpop_nonce/.test(rs.authenticate),
      "and says use_dpop_nonce in WWW-Authenticate rather than in a JSON body. Got: " +
      rs.authenticate);
    assert.ok(rs.dpopNonce, "with a nonce to retry with.");
    var rsRetry = await post(CREDENTIAL_ENDPOINT, {
      json: { credential_configuration_id: "IdentityCredential" },
      headers: {
        Authorization: "DPoP " + bound.body.access_token,
        DPoP: makeProof(key, { htm: "POST", htu: CREDENTIAL_ENDPOINT,
                               accessToken: bound.body.access_token, nonce: rs.dpopNonce })
      }
    });
    assert.notStrictEqual(rsRetry.status, 401,
      "and the retry must be accepted: " + rsRetry.text.slice(0, 200));
    log.info("[nonce] OK — the resource server's 401/WWW-Authenticate shape works too.");
  } finally {
    // Always back off, or every later section in this process — and any other
    // test sharing this STS — starts failing for a reason it cannot see.
    var off = await post(stsBase + "/dpop/nonce-mode", { json: { required: false } });
    assert.strictEqual(off.status, 200, "could not turn nonce mode back off.");
    log.debug("nonce mode turned back off.");
  }
  log.debug("Leaving nonceHandshakeWorks().");
}

async function authorizationCodeCanBeBoundToTheKey() {
  log.debug("Entering authorizationCodeCanBeBoundToTheKey().");
  log.info("=== dpop_jkt binds the authorization code (RFC 9449 section 10) ===");
  // The authorization endpoint needs a signed-in session, so this drives its
  // login screen the way oauth2_sts_endpoints.js does: post the form, read the
  // redirect, take the code out of it.
  var key = newKey("ec");
  var redirectUri = "http://localhost:9999/callback";
  var authorize = stsBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: redirectUri,
    scope: "openid", state: "dpop-state", dpop_jkt: jkt(key)
  }).toString();

  // The authorization endpoint shows a login screen first, so this drives it the
  // way a browser would and the way oauth2_sts_endpoints.js does: GET authorize,
  // post the form's own login_id back, then follow to the authorization response.
  var form1 = await fetch(authorize, { redirect: "manual" });
  assert.strictEqual(form1.status, 200, "expected the login screen, got " + form1.status);
  var page = await form1.text();
  var loginId = (page.match(/name="login_id" value="([^"]+)"/) || [])[1];
  assert.ok(loginId, "the login screen carries no login_id to post back.");
  var loggedIn = await fetch(stsBase + "/oauth2/login", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ login_id: loginId, username: "dpop-user",
                                password: "any-password", action: "login" }).toString()
  });
  assert.strictEqual(loggedIn.status, 302, "the login form should redirect, got " + loggedIn.status);
  var cookie = String(loggedIn.headers.get("set-cookie") || "").split(";")[0];
  assert.ok(cookie, "signing in should establish a session.");

  // Every code below comes from re-GETting the same authorization URL with that
  // session, which is what a browser would do on a second visit.
  var codeFor = async function (what) {
    var r = await fetch(authorize, { headers: { Cookie: cookie }, redirect: "manual" });
    var location = r.headers.get("location") || "";
    assert.ok(/[?&]code=/.test(location),
      "no code for " + what + ". status=" + r.status + " location=" + location.slice(0, 200));
    return new URL(location).searchParams.get("code");
  };

  // Redeeming it without a proof must fail, even though PKCE was not used: the
  // code is bound to the key now.
  var noProof = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "authorization_code", code: await codeFor("the no-proof case"),
            redirect_uri: redirectUri, client_id: CLIENT_ID }
  });
  assert.strictEqual(noProof.status, 400,
    "a code bound with dpop_jkt must not be redeemable without a DPoP proof. This is the window " +
    "PKCE does not close: a thief with the code AND the code_verifier still cannot sign for the " +
    "key. Got " + noProof.status + ": " + noProof.text.slice(0, 200));
  assert.strictEqual(noProof.body.error, "invalid_grant",
    "and it is the GRANT that is bad, not the proof (there is none): got " +
    JSON.stringify(noProof.body.error));
  log.info("[dpop_jkt] OK — a bound code is refused without a proof.");

  var wrong = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "authorization_code", code: await codeFor("the wrong-key case"),
            redirect_uri: redirectUri, client_id: CLIENT_ID },
    headers: { DPoP: makeProof(newKey("ec"), { htm: "POST", htu: TOKEN_ENDPOINT }) }
  });
  assert.strictEqual(wrong.status, 400,
    "a code bound to one key must not be redeemable by another. Got " + wrong.status);
  log.info("[dpop_jkt] OK — the wrong key is refused.");

  var right = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "authorization_code", code: await codeFor("the right-key case"),
            redirect_uri: redirectUri, client_id: CLIENT_ID },
    headers: { DPoP: makeProof(key, { htm: "POST", htu: TOKEN_ENDPOINT }) }
  });
  assert.strictEqual(right.status, 200,
    "the nominated key must be able to redeem it: " + right.text.slice(0, 250));
  assert.strictEqual(claimsOf(right.body.access_token).cnf.jkt, jkt(key),
    "and the token it issues is bound to that same key.");

  // The control: WITHOUT dpop_jkt the same flow still works with no proof at
  // all, so none of the above is the authorization endpoint simply breaking.
  var unbound = stsBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: redirectUri,
    scope: "openid", state: "dpop-state"
  }).toString();
  var plainRedirect = await fetch(unbound, { headers: { Cookie: cookie }, redirect: "manual" });
  var plainCode = new URL(plainRedirect.headers.get("location")).searchParams.get("code");
  var plain = await post(TOKEN_ENDPOINT, {
    form: { grant_type: "authorization_code", code: plainCode, redirect_uri: redirectUri,
            client_id: CLIENT_ID }
  });
  assert.strictEqual(plain.status, 200,
    "an authorization request WITHOUT dpop_jkt must still redeem with no proof — otherwise the " +
    "refusals above are just a broken endpoint. Got " + plain.status + ": " +
    plain.text.slice(0, 200));
  assert.strictEqual(plain.body.token_type, "Bearer",
    "and that one is an ordinary Bearer token.");
  log.info("[dpop_jkt] OK — the nominated key redeems it and the token is bound.");
  log.debug("Leaving authorizationCodeCanBeBoundToTheKey().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. sts=" + stsBase);
  var reachable = await fetch(stsBase + "/.well-known/oauth-authorization-server")
    .then(function (r) { return r.ok; })
    .catch(function () { return false; });
  if (!reachable) {
    log.warn("SKIPPED — no STS mock at " + stsBase + ". Set WSTRUST_STS_URL or " +
             "OID4VCI_ISSUER_URL, or start the sts service.");
    return;
  }
  await serverAdvertisesDpop();
  await bearerStillWorks();
  var bound = await tokenIsBoundToTheProofKey();
  await tokenEndpointRefusesBadProofs();
  await proofsAreSingleUse();
  await boundTokenIsUsableAtTheCredentialEndpoint(bound);
  await notificationEndpointIsProtectedToo();
  await refreshTokenCarriesTheBinding();
  await authorizationCodeCanBeBoundToTheKey();
  await nonceHandshakeWorks();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_dpop")
  .description("Verify the STS mock's DPoP support (RFC 9449) at the token and protected endpoints.")
  .addOption(new Option("-u, --url <url>", "ignored; kept for a uniform CLI across the suite"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
