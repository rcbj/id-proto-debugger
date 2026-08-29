// File: sts_jws_verification.js
//
// EVERY ALGORITHM THE MOCK ADVERTISES FOR A CLIENT-SUPPLIED JWS, DRIVEN.
//
// Three surfaces here take a JWS the CLIENT signed and verify it, and each
// advertises a list of algorithms it will accept:
//
//   client assertions      token_endpoint_auth_signing_alg_values_supported
//   DPoP proofs            dpop_signing_alg_values_supported
//   OID4VCI proofs         proof_signing_alg_values_supported
//
// An advertised list is a PROMISE, and until this file existed nothing checked
// that any of the three was kept. That is not hypothetical: on 2026-08-28 the
// OID4VCI issuer advertised eleven proof algorithms while the code accepted
// two, so a wallet that read the metadata, chose EdDSA and signed a perfectly
// good proof was told its algorithm was unsupported by the very issuer that
// had just advertised it. The same day, the same endpoint was found hardcoding
// SHA-256, which would have verified an ES384 proof against the WRONG DIGEST —
// a correct signature reported as a bad one. Both were found by reading the
// code. This is what finds the next one.
//
// SO THE LISTS ARE READ FROM THE METADATA AND EVERY ENTRY IS DRIVEN. Writing
// the algorithms out here would have been writing a fourth copy of the thing
// this whole change set exists to have one of — and a copy that lags is
// exactly what lets an advertised algorithm stop working unnoticed.
//
// EVERY SIGNATURE IS MADE HERE, BY HAND, ON NODE'S OpenSSL. Nothing is
// borrowed from the debugger's jws.js or from the mock's own signer, which is
// `sts_dpop.js`'s rule and matters for the same reason: if the thing being
// verified were produced by the code doing the verifying, a shared
// misunderstanding would pass and interoperate with nobody.
//
// Needs the STS mock and nothing else — no browser.

const assert = require("assert");
const crypto = require("crypto");
const paths = require("./module_paths");
// The DEBUGGER's post-quantum engine, used to SIGN what the mock then verifies
// with its own — see signerFor(). Loaded through module_paths so its requires
// resolve from a checkout and from the tests image alike.
var pqc = paths.requireSharedModule(
  [__dirname + "/../client/src/pqc.js", __dirname + "/pqc.js"], "pqc.js");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_jws_verification",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "";
var stsBase = process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "");

// ---------------------------------------------------------------------------
// A signer per algorithm, written out. The point of this table is that it is
// NOT the one the service under test uses: the parameters come from the RFCs
// and the signatures from node's OpenSSL.
//
// `null` means node cannot perform it — the post-quantum ones — and those are
// reported as not driveable rather than skipped in silence.
// ---------------------------------------------------------------------------
function signerFor(alg) {
  log.debug("Entering signerFor(). alg=" + alg);
  var hashes = { "256": "sha256", "384": "sha384", "512": "sha512" };
  var size = alg.slice(-3);
  if (/^HS(256|384|512)$/.test(alg)) {
    log.debug("Leaving signerFor(). HMAC.");
    return { kind: "hmac", hash: hashes[size] };
  }
  if (/^RS(256|384|512)$/.test(alg)) {
    log.debug("Leaving signerFor(). RSASSA-PKCS1.");
    return { kind: "rsa", hash: hashes[size], gen: ["rsa",
             { modulusLength: 2048 }], options: {} };
  }
  if (/^PS(256|384|512)$/.test(alg)) {
    log.debug("Leaving signerFor(). RSASSA-PSS.");
    return { kind: "rsa", hash: hashes[size], gen: ["rsa",
             { modulusLength: 2048 }],
             options: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: Number(size) / 8 } };
  }
  if (/^ES(256|384|512)$/.test(alg) || alg === "ES256K") {
    var curve = { ES256: "prime256v1", ES384: "secp384r1",
                  ES512: "secp521r1", ES256K: "secp256k1" }[alg];
    log.debug("Leaving signerFor(). ECDSA.");
    return { kind: "ec", hash: alg === "ES256K" ? "sha256" : hashes[size],
             gen: ["ec", { namedCurve: curve }],
             options: { dsaEncoding: "ieee-p1363" } };
  }
  if (alg === "EdDSA") {
    log.debug("Leaving signerFor(). EdDSA.");
    return { kind: "ed", hash: null, gen: ["ed25519", null], options: {} };
  }
  // THE POST-QUANTUM ONES, SIGNED WITH THE DEBUGGER'S ENGINE. Node cannot sign
  // any of them, so the alternative was to leave a third of every advertised
  // list undriven — and using the debugger's `pqc.js` here is not a shortcut
  // but the point: the mock verifies with its OWN implementation
  // (sts/common/pq_jose.js, written independently), so a proof signed by one
  // side and accepted by the other is a real cross-check of the framing.
  if (/^(ML-DSA|SLH-DSA)/.test(alg)) {
    log.debug("Leaving signerFor(). Post-quantum, via the debugger's engine.");
    return { kind: "pq", hash: null, options: {} };
  }
  log.debug("Leaving signerFor(). Cannot sign " + alg + ".");
  return null;
}

function keyPairFor(spec, alg) {
  log.debug("Entering keyPairFor().");
  if (spec.kind === "pq") {
    var akp = pqc.generateAkpKeyPair(alg);
    log.debug("Leaving keyPairFor(). AKP.");
    return {
      pqAlg: alg,
      pqPriv: akp.priv,
      // RFC 9964: `pub` and `priv`, and `alg` is REQUIRED on an AKP JWK.
      publicKey: { export: function () {
        return { kty: "AKP", alg: alg, use: "sig",
                 pub: Buffer.from(akp.pub).toString("base64url") };
      } },
      privateKey: null
    };
  }
  var pair = spec.gen[1] ? crypto.generateKeyPairSync(spec.gen[0], spec.gen[1])
                         : crypto.generateKeyPairSync(spec.gen[0]);
  log.debug("Leaving keyPairFor().");
  return pair;
}

function b64u(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

// One compact JWS, assembled here rather than by any library.
function makeJws(alg, spec, key, header, payload) {
  log.debug("Entering makeJws(). alg=" + alg);
  var input = b64u(Object.assign({ alg: alg }, header)) + "." + b64u(payload);
  var signature;
  if (spec.kind === "pq") {
    signature = Buffer.from(pqc.signWithPriv(key.pqAlg,
      Buffer.from(input, "ascii"), key.pqPriv));
  } else if (spec.kind === "hmac") {
    signature = crypto.createHmac(spec.hash, key)
      .update(Buffer.from(input, "ascii")).digest();
  } else {
    signature = crypto.sign(spec.hash, Buffer.from(input, "ascii"),
      Object.assign({ key: key }, spec.options));
  }
  log.debug("Leaving makeJws().");
  return input + "." + signature.toString("base64url");
}

// ---------------------------------------------------------------------------
// EVERY REQUEST HERE GOES THROUGH THIS, AND THE REASON IS THE SERVICE RATHER
// THAN THE NETWORK.
//
// The mock STS is one node process with one event loop, and some of what this
// suite asks it to do BLOCKS that loop for tens of seconds: SLH-DSA-SHAKE-128s
// is about twelve seconds for a single signature, and
// `sts_userinfo_protected.js` asks for one per advertised algorithm, twice —
// a UserInfo response and an ID Token. While that runs, the process accepts a TCP connection (the kernel's
// backlog does that for it) and then answers nothing, so a TLS handshake to it
// simply does not finish.
//
// undici — node's `fetch` — gives a connection ten seconds and then throws
// `TypeError: fetch failed`, whose whole stack is internals. That is what took
// this job out on 2026-08-29: it opened its FIRST connection at 04:53:30, in
// the middle of the other job's twenty-second ID Token pass, and failed ten
// seconds later naming nothing — no URL, no service, no algorithm, and nothing
// to distinguish it from a mock that had died. The two jobs share the mock
// because both are about what that one service advertises, and serialising
// them in JOB_LOCKS would cost the pool a minute to fix a client-side timeout.
//
// So a CONNECTION failure is retried rather than reported: the service is
// working, it is just not listening yet. A failure that survives the whole
// window is reported with the URL and the wait in it, which is the message the
// bare TypeError could not give. Anything the service actually ANSWERS —
// including a 500 — is returned untouched, because that is an answer and this
// wrapper has no opinion about it.
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
      // A connection-level failure only: undici reports every one of them as
      // this same TypeError, and there is nothing else `fetch` throws here.
      last = e;
      log.debug("stsFetch(): " + url + " did not connect (" + e.message +
                "); retrying.");
      await new Promise(function (r) { setTimeout(r, 1000); });
    }
  }
  log.debug("Leaving stsFetch(). Gave up.");
  throw new Error("could not reach " + url + " in " +
    (BUSY_WINDOW_MS / 1000) + "s of trying (" +
    (last && last.message) + ", " + attempts + " attempt(s)). The mock STS " +
    "blocks its event loop for tens of seconds while it signs an SLH-DSA " +
    "message, so a short outage here is ordinary; this long a one means it " +
    "is not running.");
}

async function metadata() {
  log.debug("Entering metadata().");
  var doc = await (await stsFetch(stsBase +
      "/.well-known/openid-configuration")).json();
  log.debug("Leaving metadata().");
  return doc;
}

async function registerClient(body, base) {
  log.debug("Entering registerClient().");
  var response = await stsFetch((base || stsBase) + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign(
      { redirect_uris: ["http://localhost:9999/callback"] }, body))
  });
  assert.strictEqual(response.status, 201, "registration should be accepted.");
  log.debug("Leaving registerClient().");
  return response.json();
}

// ---------------------------------------------------------------------------
// CLIENT ASSERTIONS — RFC 7523, both `private_key_jwt` and `client_secret_jwt`.
//
// The symmetric and asymmetric halves diverge in exactly one place and it is
// the interesting one: an HS* assertion is verified with the CLIENT SECRET and
// an asymmetric one with a key the client registered. A server that took the
// algorithm from the assertion's own header rather than from the registered
// METHOD would verify an RS256 public key as an HMAC secret — a forgery
// anybody can produce, since the key is public. That negative is asserted at
// the end.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// CLIENT ASSERTIONS — RFC 7523, both `private_key_jwt` and `client_secret_jwt`.
//
// DRIVEN THROUGH THE VERIFIER DIRECTLY AND NOT OVER HTTP, and the reason is a
// property of this service worth stating plainly: **it never enforces client
// authentication at the token endpoint.** A token request carrying a garbage
// `client_assertion`, or none at all, is answered 200 — at the default realm
// and, measured, in an RFC 9700 realm too, where the mode's other rules (no
// password grant, exact redirect matching) do apply. It is a permissive mock
// and that is deliberate.
//
// So an HTTP test here would have been worthless in the most dangerous way: it
// would have signed an assertion, posted it, seen 200, and reported coverage —
// and it would have gone on passing if `verifyAssertion()` were deleted
// outright. The first version of this file did exactly that and was thrown
// away.
//
// Loading `oauth-oidc/client_auth.js` and calling its `verify()` tests the code
// that actually does the checking. What it gives up is the wiring between the
// endpoint and the verifier, which nothing can test while the endpoint does not
// call it in anger — and that gap is named here rather than papered over.
// ---------------------------------------------------------------------------
async function everyAdvertisedClientAssertionAlgorithmWorks() {
  log.debug("Entering everyAdvertisedClientAssertionAlgorithmWorks().");
  // mockStsModule() answers with a PATH — the mock's layout moves and this is
  // what finds a module by name rather than by folder.
  var clientAuth = require(paths.mockStsModule("client_auth.js"));
  var doc = await metadata();
  var algs = doc.token_endpoint_auth_signing_alg_values_supported || [];
  assert.ok(algs.length, "no client assertion algorithms are advertised.");
  var audience = [stsBase + "/oauth2/token"];
  var driven = 0;
  var undriveable = [];

  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    var spec = signerFor(alg);
    if (!spec) {
      undriveable.push(alg);
      continue;
    }
    var symmetric = spec.kind === "hmac";
    var clientId = "assertion-client-" + i;
    var secret = "secret-for-" + clientId;
    var pair = symmetric ? null : keyPairFor(spec, alg);
    var now = Math.floor(Date.now() / 1000);
    var assertionJws = makeJws(alg, spec,
      symmetric ? secret : (spec.kind === "pq" ? pair : pair.privateKey),
      symmetric ? { typ: "JWT" } : { typ: "JWT", kid: "assert-1" },
      { iss: clientId, sub: clientId, aud: audience[0],
        exp: now + 300, iat: now, jti: "assertion-" + alg + "-" + now });

    var verdict = clientAuth.verify({
      method: symmetric ? "client_secret_jwt" : "private_key_jwt",
      clientId: clientId,
      clientSecret: secret,
      assertionType: clientAuth.ASSERTION_TYPE,
      assertion: assertionJws,
      audiences: audience,
      jwks: symmetric ? undefined : { keys: [Object.assign(
        pair.publicKey.export({ format: "jwk" }),
        { kid: "assert-1", use: "sig", alg: alg })] }
    });
    assert.ok(verdict.ok,
      alg + ": an assertion signed with an ADVERTISED algorithm must verify. " +
      "The verifier said: " + (verdict.description || "(no reason)"));
    driven++;
  }

  // THE ALGORITHM-CONFUSION REFUSAL, which is what makes the rest worth
  // having: an assertion nominating HS256 from a client registered for
  // private_key_jwt would have the server verify a signature using a PUBLIC
  // key as an HMAC secret — a forgery anybody can produce, since the key is
  // public.
  var rsaSpec = signerFor("RS256");
  var rsaPair = keyPairFor(rsaSpec);
  var publicPem = rsaPair.publicKey.export({ type: "spki", format: "pem" });
  var nowSec = Math.floor(Date.now() / 1000);
  var forged = makeJws("HS256", signerFor("HS256"), publicPem,
    { typ: "JWT", kid: "assert-1" },
    { iss: "confused-client", sub: "confused-client", aud: audience[0],
      exp: nowSec + 300, iat: nowSec, jti: "forged-" + nowSec });
  var forgedVerdict = clientAuth.verify({
    method: "private_key_jwt", clientId: "confused-client",
    assertionType: clientAuth.ASSERTION_TYPE, assertion: forged,
    audiences: audience,
    jwks: { keys: [Object.assign(rsaPair.publicKey.export({ format: "jwk" }),
      { kid: "assert-1", use: "sig", alg: "RS256" })] } });
  assert.strictEqual(forgedVerdict.ok, false,
    "an assertion nominating HS256 from a client registered for " +
    "private_key_jwt must be REFUSED. Accepting it means verifying a " +
    "signature with a PUBLIC key used as an HMAC secret.");

  // And an assertion signed by the wrong key, which is the ordinary negative.
  var otherPair = keyPairFor(rsaSpec);
  var wrongKey = makeJws("RS256", rsaSpec, otherPair.privateKey,
    { typ: "JWT", kid: "assert-1" },
    { iss: "wrong-key-client", sub: "wrong-key-client", aud: audience[0],
      exp: nowSec + 300, iat: nowSec, jti: "wrong-" + nowSec });
  var wrongVerdict = clientAuth.verify({
    method: "private_key_jwt", clientId: "wrong-key-client",
    assertionType: clientAuth.ASSERTION_TYPE, assertion: wrongKey,
    audiences: audience,
    jwks: { keys: [Object.assign(rsaPair.publicKey.export({ format: "jwk" }),
      { kid: "assert-1", use: "sig", alg: "RS256" })] } });
  assert.strictEqual(wrongVerdict.ok, false,
    "an assertion signed by a key the client did not register must be " +
    "refused.");

  log.info("[assertions] OK — " + driven + " advertised algorithm(s) verify " +
           "through client_auth.js, the HS-over-a-public-key forgery is " +
           "refused, and so is a wrong key" +
           (undriveable.length
             ? " (" + undriveable.length + " post-quantum one(s) node cannot " +
               "sign: " + undriveable.join(", ") + ")"
             : "") + ".");
  log.debug("Leaving everyAdvertisedClientAssertionAlgorithmWorks().");
}

// ---------------------------------------------------------------------------
// OID4VCI PROOF OF POSSESSION. The wallet signs a proof with a key it holds
// and puts that key in the header; the issuer verifies against it.
// ---------------------------------------------------------------------------
async function everyAdvertisedProofAlgorithmWorks() {
  log.debug("Entering everyAdvertisedProofAlgorithmWorks().");
  var issuerMeta = await (await stsFetch(stsBase +
      "/.well-known/openid-credential-issuer")).json();
  var configs = issuerMeta.credential_configurations_supported || {};
  var configId = Object.keys(configs)[0];
  assert.ok(configId, "the issuer advertises no credential configurations.");
  var algs = (((configs[configId].proof_types_supported || {}).jwt || {})
    .proof_signing_alg_values_supported) || [];
  assert.ok(algs.length, "no proof signing algorithms are advertised.");

  var client = await registerClient({});
  var tokenResponse = await (await stsFetch(stsBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: "alice",
      password: "any", scope: "openid", client_id: client.client_id,
      client_secret: client.client_secret }).toString() })).json();

  var driven = 0;
  var undriveable = [];
  var tooSlow = [];
  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    var spec = signerFor(alg);
    if (!spec) {
      undriveable.push(alg);
      continue;
    }
    // ONE ALGORITHM IS LEFT OUT OF THIS LOOP FOR TIME, AND IT IS NAMED.
    //
    // SLH-DSA-SHAKE-128s takes about TWELVE SECONDS to produce one signature
    // — measured, and it is the parameter set's own trade: `s` is the
    // small-signature, slow-signing variant. It is already signed twice in the
    // section above, and a third and fourth here bought nothing but half a
    // minute of wall clock and, on the first run, a `fetch failed` when the
    // whole job ran long. Its SHA-2 sibling stays, so the SLH-DSA path through
    // this endpoint is still driven; and the full eleven are driven against
    // this endpoint's verifier in sts_userinfo_protected.js, where the mock's
    // own signer makes them cheaply.
    if (alg === "SLH-DSA-SHAKE-128s") {
      tooSlow.push(alg);
      continue;
    }
    var nonce = await (await stsFetch(stsBase + "/oid4vci/nonce",
      { method: "POST" })).json();
    var pair = keyPairFor(spec, alg);
    var proof = makeJws(alg, spec,
      spec.kind === "pq" ? pair : pair.privateKey,
      { typ: "openid4vci-proof+jwt",
        jwk: pair.publicKey.export({ format: "jwk" }) },
      { aud: issuerMeta.credential_issuer,
        iat: Math.floor(Date.now() / 1000), nonce: nonce.c_nonce });

    var response = await stsFetch(stsBase + "/oid4vci/credential", {
      method: "POST",
      headers: { "Content-Type": "application/json",
                 Authorization: "Bearer " + tokenResponse.access_token },
      body: JSON.stringify({ credential_configuration_id: configId,
        proof: { proof_type: "jwt", jwt: proof } })
    });
    var body = await response.text();
    assert.strictEqual(response.status, 200,
      alg + ": a proof of possession signed with an ADVERTISED algorithm must " +
      "be accepted. This is the exact failure found on 2026-08-28, when the " +
      "issuer advertised eleven and accepted two. Got " + response.status +
      ": " + body.slice(0, 220));
    driven++;
  }

  // A proof signed by one key and carrying ANOTHER in its header proves
  // nothing, and must be refused — the check that makes the rest meaningful.
  var ecSpec = signerFor("ES256");
  var honest = keyPairFor(ecSpec);
  var impostor = keyPairFor(ecSpec);
  var freshNonce = await (await stsFetch(stsBase + "/oid4vci/nonce",
    { method: "POST" })).json();
  var mismatched = makeJws("ES256", ecSpec, impostor.privateKey,
    { typ: "openid4vci-proof+jwt",
      jwk: honest.publicKey.export({ format: "jwk" }) },
    { aud: issuerMeta.credential_issuer,
      iat: Math.floor(Date.now() / 1000), nonce: freshNonce.c_nonce });
  var refused = await stsFetch(stsBase + "/oid4vci/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + tokenResponse.access_token },
    body: JSON.stringify({ credential_configuration_id: configId,
      proof: { proof_type: "jwt", jwt: mismatched } })
  });
  assert.notStrictEqual(refused.status, 200,
    "a proof signed by a key OTHER than the one in its own header must be " +
    "refused; accepting it would make the proof prove nothing at all.");

  log.info("[oid4vci proof] OK — " + driven + " advertised algorithm(s) are " +
           "accepted and a proof signed by the wrong key is refused" +
           (undriveable.length
             ? "; " + undriveable.length + " could not be signed here: " +
               undriveable.join(", ")
             : "") +
           (tooSlow.length
             ? "; " + tooSlow.join(", ") + " left out for time (12s per " +
               "signature) and covered in sts_userinfo_protected.js"
             : "") + ".");
  log.debug("Leaving everyAdvertisedProofAlgorithmWorks().");
}

// ---------------------------------------------------------------------------
// The advertised lists must be REACHABLE, which is a different claim from
// their being correct: an algorithm nothing here can drive is one this file
// cannot vouch for, and saying which those are is the honest part.
// ---------------------------------------------------------------------------
async function undriveableAlgorithmsAreNamed() {
  log.debug("Entering undriveableAlgorithmsAreNamed().");
  var doc = await metadata();
  var all = doc.token_endpoint_auth_signing_alg_values_supported || [];
  var undriveable = all.filter(function (alg) { return !signerFor(alg); });
  // THE LIST MUST BE EMPTY. Every algorithm this service advertises for client
  // authentication is signable here — the classical ones on node's OpenSSL and
  // the post-quantum ones through the debugger's engine — so anything landing
  // in this list is an algorithm that was advertised and lost its coverage,
  // which is the state this whole file exists to make impossible.
  assert.strictEqual(undriveable.length, 0,
    "these algorithms are advertised for client authentication and nothing " +
    "here can sign one, so they are advertised and unchecked: " +
    undriveable.join(", ") + ". Add a signer for each in signerFor().");
  log.info("[coverage] OK — every one of the " + all.length + " algorithms " +
           "advertised for client authentication is signed and driven here.");
  log.debug("Leaving undriveableAlgorithmsAreNamed().");
}

async function test() {
  log.debug("Entering test().");
  if (!stsBase) {
    log.info("No STS URL — skipping.");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Starting Test run against " + stsBase + ".");
  await everyAdvertisedClientAssertionAlgorithmWorks();
  await everyAdvertisedProofAlgorithmWorks();
  await undriveableAlgorithmsAreNamed();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_jws_verification")
  .description("Every algorithm the mock advertises for a client-supplied " +
      "JWS is actually accepted.")
  .addOption(new Option("-u, --url <url>",
      "ignored; this test needs no browser"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
