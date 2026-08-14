// File: oid4vci_request_encryption.js
//
// ---------------------------------------------------------------------------
// Credential REQUEST encryption — OID4VCI 1.0 section 10, "Encrypted Credential
// Requests and Responses", in the direction the suite did not already cover.
//
// Response encryption was already implemented: the WALLET generates a key,
// sends it in the request, and gets a JWE back. This is the mirror, and the
// asymmetry is the reason it needs its own tests rather than a copy of the
// response ones. Three differences are normative:
//
//   * the ISSUER publishes the keys, in credential_request_encryption.jwks,
//     and "Each JWK in the set MUST have a kid (Key ID) parameter that uniquely
//     identifies the key";
//   * there is NO alg_values_supported for requests. "The alg parameter MUST be
//     present. The JWE alg algorithm used MUST be equal to the alg value of the
//     chosen JWK" — the algorithm is a property of the key. A wallet that reads
//     the response side's member list here finds nothing and cannot encrypt;
//   * "If the selected public key contains a kid parameter, the JWE MUST
//     include the same value in the kid JWE Header Parameter", which is what
//     makes issuer key rotation detectable instead of an opaque failure.
//
// Both sides are the real implementations: the wallet half is
// client/src/vci_wallet.js, the same module issuance steps 2 and 4 use, and the
// issuer half is the STS mock. Neither is a stand-in written for the test.
//
// Section 10 applies identically to the Deferred Credential Request, which is
// the easy half to forget, so it is exercised too.
//
// Needs only the STS mock. walt.id is NOT covered here: its issuer metadata
// advertises neither credential_request_encryption nor
// credential_response_encryption, so there is no key to encrypt to and nothing
// to interoperate with. assertWaltidStillDoesNotOffer() below records that as a
// checked fact rather than an assumption, so the day walt.id adds it, this says
// so instead of staying quietly unwritten.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "oid4vci_request_encryption", level: appconfig.logLevel || "info"
});

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");
const ROOT = path.join(__dirname, "..");
const paths = require("./module_paths.js");
const wallet = paths.requireSharedModule(
  [path.join(__dirname, "vci_wallet.js"), path.join(ROOT, "client", "src",
   "vci_wallet.js")],
  "the wallet's Credential Request/Response module");
const schema = paths.requireSharedModule(
  [path.join(__dirname, "metadata_schema.js"), path.join(ROOT, "client", "src",
   "metadata_schema.js")],
  "the metadata schema checker");

const CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
const CLIENT_ID = common.WALLET_CLIENT_ID;

// Build a Credential Request with the wallet's own module, so what is encrypted
// is a request the issuer would otherwise accept in the clear. Encrypting a
// hand-rolled body would leave "the issuer rejected it" ambiguous between the
// encryption and the contents.
async function freshRequestBody(meta, holderKey) {
  log.debug("Entering freshRequestBody().");
  const nonce = await wallet.fetchNonce(meta.nonce_endpoint || "");
  const proof = await wallet.signProof(holderKey, {
    clientId: CLIENT_ID, credentialIssuer: meta.credential_issuer,
        nonce: nonce.nonce
  });
  log.debug("Leaving freshRequestBody().");
  return wallet.buildRequestBody({ credentialConfigurationId: CONFIG_ID,
                                 proofs: [proof] });
}

async function postJwe(endpoint, jwe, accessToken) {
  log.debug("Entering postJwe().");
  const r = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/jwt", "Authorization": "Bearer " +
              (accessToken || "tok") },
    body: jwe
  });
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    /* an encrypted response is not JSON */
  }
  log.debug("Leaving postJwe().");
  return { status: r.status, body: body, raw: text,
          contentType: r.headers.get("content-type") || "" };
}

// A JWE with a deliberately wrong protected header — a request no correct
// wallet would send, built here to prove the ISSUER checks what section 10 says
// it must.
//
// Built with node crypto rather than through wallet.encryptRequestBody(),
// because that function will not produce these: it takes alg from the chosen
// key and never emits zip, which is correct behaviour. Routing these through it
// silently produced a VALID request — the override was ignored, the issuer
// answered 200, and the case tested nothing. Forging the header is the only way
// to exercise the refusal.
//
// It must also be a real encryption rather than a mutated finished JWE: the
// protected header is the AAD, so editing it afterwards breaks the
// authentication tag and every case would fail as tampering instead of as the
// specific refusal under test.
function forgeJwe(body, jwk, overrides) {
  log.debug("Entering forgeJwe().");
  const crypto = require("crypto");
  const header = Object.assign(
    { alg: "RSA-OAEP-256", enc: "A256GCM", typ: "JWT", kid: jwk.kid },
     overrides || {});
  const bits = header.enc === "A128GCM" ? 128 : 256;
  // A192GCM is a legal JOSE value this issuer does not advertise; node can
  // produce it, which is what makes it a usable negative.
  const keyBytes = header.enc === "A192GCM" ? 24 : bits / 8;
  const cek = crypto.randomBytes(keyBytes);
  const iv = crypto.randomBytes(12);
  const b64 = function (b) {
    log.debug("Entering b64().");
    log.debug("Leaving b64().");
    return Buffer.from(b).toString("base64url");
  };
  const headerB64 = b64(Buffer.from(JSON.stringify(header), "utf8"));
  const encryptedKey = crypto.publicEncrypt({
    key: crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e },
                                format: "jwk" }),
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256"
  }, cek);
  const cipher = crypto.createCipheriv("aes-" + (keyBytes * 8) + "-gcm", cek,
      iv);
  cipher.setAAD(Buffer.from(headerB64, "ascii"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(body), "utf8")), cipher.final()
  ]);
  log.debug("Leaving forgeJwe().");
  return [headerB64, b64(encryptedKey), b64(iv), b64(ciphertext),
          b64(cipher.getAuthTag())].join(".");
}

async function assertWaltidStillDoesNotOffer() {
  log.debug("Entering assertWaltidStillDoesNotOffer().");
  const waltid = process.env.WALTID_ISSUER_URL;
  if (!waltid) {
    log.info("[walt.id] WALTID_ISSUER_URL is unset, so walt.id's support was " +
             "not re-checked.");
    log.debug("Leaving assertWaltidStillDoesNotOffer().");
    return;
  }
  let meta = null;
  try {
    meta = await common.issuerMetadata(waltid.replace(/\/+$/, ""));
  } catch (e) {
    log.info("[walt.id] its metadata could not be read (" + e.message +
             "); support not re-checked.");
    log.debug("Leaving assertWaltidStillDoesNotOffer().");
    return;
  }
  if (!meta) {
    log.info("[walt.id] no metadata returned; support not re-checked.");
    log.debug("Leaving assertWaltidStillDoesNotOffer().");
    return;
  }
  if (meta.credential_request_encryption) {
    // Not a failure: walt.id gaining this is good news. But it must not pass
    // silently, because the interoperability test it enables is the whole
    // reason to know.
    log.warn("[walt.id] NOW ADVERTISES credential_request_encryption: " +
      JSON.stringify(meta.credential_request_encryption).slice(0, 200) +
      " — an interoperability test against it is now possible and should " +
          "be written.");
  } else {
    log.info("[walt.id] still advertises no credential_request_encryption, " +
             "so there is no " +
      "interoperability test to run: a wallet cannot encrypt to an issuer " +
          "that publishes no key.");
  }
  log.debug("Leaving assertWaltidStillDoesNotOffer().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running OID4VCI section 10 request encryption against " +
           issuerBase);
  const meta = await common.issuerMetadata(issuerBase);
  assert.ok(meta && meta.credential_endpoint,
    "no credential issuer metadata at " + issuerBase + ". Start the STS mock.");

  // --- what the issuer advertises -------------------------------------------
  log.info("=== The metadata (section 12.2.3) ===");
  const offered = meta.credential_request_encryption;
  assert.ok(offered,
    "the issuer should advertise credential_request_encryption. Without it a " +
        "wallet has no key and " +
    "MUST NOT encrypt, so every assertion below would be untestable.");
  assert.ok(offered.jwks && Array.isArray(offered.jwks.keys) &&
            offered.jwks.keys.length,
    "jwks is REQUIRED and must carry at least one key.");
  offered.jwks.keys.forEach(function (k, i) {
    assert.ok(k.kid, "key " + i +
              " has no kid, and \"Each JWK in the set MUST have a kid\".");
    assert.ok(k.alg, "key " + i +
        " has no alg. For REQUESTS the alg comes from the key — there is no " +
      "alg_values_supported to fall back on — so a key without one cannot be " +
          "used at all.");
  });
  assert.ok(Array.isArray(offered.enc_values_supported) &&
            offered.enc_values_supported.length,
    "enc_values_supported is REQUIRED and non-empty.");
  assert.strictEqual(typeof offered.encryption_required, "boolean",
    "encryption_required is REQUIRED and a boolean.");
  assert.strictEqual(offered.alg_values_supported, undefined,
    "credential_request_encryption must NOT carry alg_values_supported — " +
        "that member belongs to the " +
    "RESPONSE side. Copying the response object's shape here is the likely " +
        "mistake, and it produces " +
    "metadata that looks complete while telling the wallet to read the " +
        "algorithm from the wrong place.");
  log.info("[metadata] OK — " + offered.jwks.keys.length + " key(s), enc " +
    offered.enc_values_supported.join("/") + ", required=" +
                                      offered.encryption_required + ".");

  // The document must also pass the wallet's own schema checker, which is what
  // step 1 shows a user. A rule that only this test knows is a rule the pane
  // does not enforce.
  const verdict = schema.validateVciMetadata(meta);
  const relevant = (verdict.errors || []).filter(function (e) {
    return String(e.cite ||
                  "").indexOf("credential_request_encryption") !== -1 ||
           String(e.member ||
                  "").indexOf("credential_request_encryption") !== -1;
  });
  assert.deepStrictEqual(relevant, [],
    "the issuer's own metadata must satisfy the schema rules the debugger " +
        "applies to it: " +
    JSON.stringify(relevant));
  log.info("[schema] OK — the advertised object passes the debugger's " +
           "own checker.");

  // --- what the wallet decides ----------------------------------------------
  log.info("=== The wallet's key selection (section 10) ===");
  const offer = wallet.requestEncryptionOffer(meta);
  assert.strictEqual(offer.offered, true, "the wallet should see the offer.");
  assert.strictEqual(offer.usable, true, "and be able to use it: " +
                     offer.reason);
  assert.strictEqual(offer.alg, offer.jwk.alg,
    "the JWE alg MUST equal the alg of the chosen JWK — that is the rule " +
        "that replaces " +
    "alg_values_supported for requests.");
  assert.ok(offered.enc_values_supported.indexOf(offer.enc) !== -1,
    "and the enc must be one the issuer said it can decode; the wallet chose " +
        offer.enc + ".");
  assert.strictEqual(offer.kid, offer.jwk.kid,
                     "and it must remember which key it picked.");
  log.info("[select] OK — " + offer.reason);

  // The negative half of the selection logic, which the live issuer cannot
  // produce: a wallet must decline rather than guess.
  const noAlg = wallet.requestEncryptionOffer({
    credential_request_encryption: {
      jwks: { keys: [{ kty: "RSA", n: "a", e: "AQAB", kid: "k1" }] },
      enc_values_supported: ["A128GCM"], encryption_required: false
    }
  });
  assert.strictEqual(noAlg.usable, false,
    "a key with no alg is not usable: section 10 requires the alg to be " +
        "present, and defaulting one " +
    "would encrypt with an algorithm the issuer never claimed to support.");
  const noCommonEnc = wallet.requestEncryptionOffer({
    credential_request_encryption: {
      jwks: { keys: [{ kty: "RSA", n: "a", e: "AQAB", kid: "k1",
             alg: "RSA-OAEP-256" }] },
      enc_values_supported: ["A128CBC-HS256"], encryption_required: true
    }
  });
  assert.strictEqual(noCommonEnc.usable, false,
    "no shared enc means no encryption, even when the issuer requires it.");
  assert.strictEqual(noCommonEnc.required, true,
    "and the wallet must still report that it was REQUIRED — that " +
        "combination is the one a pane has " +
    "to explain, because it means the endpoint cannot be used at all.");
  const notOffered = wallet.requestEncryptionOffer({});
  assert.strictEqual(notOffered.offered, false,
                     "an issuer that says nothing is offering nothing,");
  assert.strictEqual(notOffered.required, false, "and requiring nothing.");
  log.info("[select] OK — declines a key with no alg, an incompatible enc, " +
           "and an absent offer.");

  // --- the encrypted request round trip -------------------------------------
  log.info("=== An encrypted Credential Request ===");
  const holderKey = await wallet.generateHolderKeyPair();
  const body = await freshRequestBody(meta, holderKey);
  const jwe = await wallet.encryptRequestBody(body, offer);
  const parts = jwe.split(".");
  assert.strictEqual(parts.length, 5,
    "a JWE in compact serialization has five parts; got " + parts.length + ".");
  const header = JSON.parse(Buffer.from(parts[0],
      "base64url").toString("utf8"));
  assert.strictEqual(header.alg, offer.jwk.alg,
                     "the header alg is the chosen key's alg.");
  assert.strictEqual(header.enc, offer.enc, "and the negotiated enc.");
  assert.strictEqual(header.kid, offer.jwk.kid,
    "and the kid MUST be echoed: \"If the selected public key contains a kid " +
        "parameter, the JWE MUST " +
    "include the same value in the kid JWE Header Parameter.\" Omitting it " +
        "leaves an issuer with " +
    "several keys guessing.");
  assert.ok(!header.zip,
    "no zip: this issuer advertises no zip_values_supported, and \"If absent " +
        "then no compression " +
    "algorithms are supported\".");
  assert.ok(jwe.indexOf(CONFIG_ID) === -1,
    "the configuration id must not appear in the JWE as plaintext — if it " +
        "does, nothing was encrypted.");

  const sent = await postJwe(meta.credential_endpoint, jwe);
  assert.strictEqual(sent.status, 200,
    "the issuer should decrypt and honour the request: HTTP " + sent.status +
        " " +
    String(sent.raw).slice(0, 240));
  const credential = wallet.extractCredential(sent.body);
  assert.ok(credential,
    "and return a credential. Got: " + JSON.stringify(sent.body).slice(0, 200));
  log.info("[round trip] OK — an encrypted request produced a credential.");

  // Every enc the issuer advertises must actually work, or the metadata
  // overstates what the endpoint can decode.
  for (const enc of offered.enc_values_supported) {
    if (wallet.REQUEST_ENC_PREFERENCE.indexOf(enc) === -1) {
      log.info("[enc] " + enc +
          " is advertised but this wallet does not perform it; not exercised.");
      continue;
    }
    const b = await freshRequestBody(meta, holderKey);
    const j = await wallet.encryptRequestBody(b, Object.assign({}, offer,
        { enc: enc }));
    const r = await postJwe(meta.credential_endpoint, j);
    assert.strictEqual(r.status, 200,
      "the issuer advertises enc " + enc + ", so it must decode it: HTTP " +
          r.status + " " +
      String(r.raw).slice(0, 200));
    log.info("[enc] OK — " + enc + " round-trips.");
  }

  // --- what the issuer must refuse ------------------------------------------
  log.info("=== Refusals ===");
  const refusals = [
    {
      what: "a kid naming a key the issuer never published",
      jwe: forgeJwe(await freshRequestBody(meta, holderKey), offer.jwk,
        { kid: "sts-mock-req-enc-STALE" }),
      why: "this is what a wallet holding cached metadata sends after the " +
          "issuer rotates its key. " +
           "Ignoring the kid would turn that into an unexplainable " +
               "decryption failure."
    },
    {
      what: "an enc the issuer did not advertise",
      jwe: forgeJwe(await freshRequestBody(meta, holderKey), offer.jwk,
                    { enc: "A192GCM" }),
      why: "accepting an unadvertised algorithm makes enc_values_supported " +
          "meaningless.",
      // The refusal must be a POLICY decision taken from enc_values_supported
      // before any crypto is attempted, not a lucky side effect of the key
      // length. Removing the allow-list still produces a 400 here — A192GCM
      // needs a 24-byte CEK and the code would reach for 32 — so asserting only
      // the status code passes against an issuer that checks nothing. This is
      // the assertion that fails when the allow-list is deleted.
      mentions: "supports enc"
    },
    {
      what: "a compressed request when no zip is advertised",
      jwe: forgeJwe(await freshRequestBody(meta, holderKey), offer.jwk,
                    { zip: "DEF" }),
      why: "\"If absent then no compression algorithms are supported.\""
    },
    {
      what: "an alg other than the chosen key's",
      jwe: forgeJwe(await freshRequestBody(meta, holderKey), offer.jwk,
                    { alg: "RSA-OAEP" }),
      why: "\"The JWE alg algorithm used MUST be equal to the alg value of " +
          "the chosen JWK\", and " +
           "RSA-OAEP (SHA-1) is not RSA-OAEP-256 however similar the " +
               "name looks."
    },
    {
      what: "something that is not a JWE at all",
      jwe: "this.is.not.a.jwe",
      why: "an application/jwt body that cannot be parsed must be refused, " +
          "not treated as JSON."
    }
  ];
  for (const c of refusals) {
    const r = await postJwe(meta.credential_endpoint, c.jwe);
    assert.strictEqual(r.status, 400, c.what + " must be refused with 400 — " +
                       c.why +
      " Got HTTP " + r.status + " " + String(r.raw).slice(0, 160));
    assert.ok(r.body && r.body.error, "and a JSON error object. Got: " +
              String(r.raw).slice(0, 160));
    if (c.mentions) {
      assert.ok(String(r.body.error_description ||
                "").indexOf(c.mentions) !== -1,
        "the refusal must say why in terms of the advertised policy " +
            "(expected the description to " +
        "contain \"" + c.mentions +
            "\"), not fail incidentally somewhere deeper. Got: " +
        JSON.stringify(r.body.error_description || "").slice(0, 200));
    }
    log.info("[refuse] OK — " + c.what + " → " + r.body.error);
  }

  // Tampering is its own case: the protected header is the AAD, so altering the
  // ciphertext must fail the authentication tag rather than decrypt to garbage.
  const good = await wallet.encryptRequestBody(await freshRequestBody(meta,
      holderKey), offer);
  const bits = good.split(".");
  bits[3] = bits[3].slice(0, -4) + (bits[3].slice(-4) === "AAAA" ?
       "BBBB" : "AAAA");
  const tampered = await postJwe(meta.credential_endpoint, bits.join("."));
  assert.strictEqual(tampered.status, 400,
    "altered ciphertext must fail the GCM authentication tag.");
  log.info("[refuse] OK — tampered ciphertext → " + (tampered.body ||
           {}).error);

  // The control: the very same body, unaltered, still works. Without it every
  // refusal above could be an endpoint that simply rejects everything.
  const control = await postJwe(meta.credential_endpoint,
    await wallet.encryptRequestBody(await freshRequestBody(meta, holderKey),
                                    offer));
  assert.strictEqual(control.status, 200,
    "the control: an untampered encrypted request still succeeds, so the " +
        "refusals above are " +
    "discriminating rather than blanket.");
  log.info("[refuse] OK — the control still succeeds, so the refusals are " +
           "discriminating.");

  // --- the deferred endpoint, same rule -------------------------------------
  log.info("=== The Deferred Credential Request (section 10 applies " +
           "identically) ===");
  if (!meta.deferred_credential_endpoint) {
    log.info("[deferred] this issuer advertises no " +
             "deferred_credential_endpoint; not exercised.");
  } else {
    // A transaction id this issuer never made: the point is that the request is
    // DECRYPTED and then judged on its contents, not refused as unreadable.
    const deferredJwe = await wallet.encryptRequestBody({
        transaction_id: "no-such-transaction" }, offer);
    const d = await postJwe(meta.deferred_credential_endpoint, deferredJwe);
    assert.ok(d.body && d.body.error,
      "the deferred endpoint should answer with a JSON error: " +
          String(d.raw).slice(0, 200));
    assert.notStrictEqual(d.body.error, "invalid_encryption_parameters",
      "the encrypted deferred request must be DECRYPTED — an encryption " +
          "error here means section 10 " +
      "was implemented on the credential endpoint only, which is the half " +
          "that gets forgotten. Got: " +
      JSON.stringify(d.body).slice(0, 200));
    assert.strictEqual(d.body.error, "invalid_transaction_id",
      "and then judged on its contents: this transaction does not exist.");
    log.info("[deferred] OK — decrypted, then refused on its contents (" +
             d.body.error + ").");
  }

  // --- unencrypted is still allowed while encryption_required is false ------
  log.info("=== encryption_required ===");
  if (offered.encryption_required === false) {
    const plain = await fetch(meta.credential_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                "Authorization": "Bearer tok" },
      body: JSON.stringify(await freshRequestBody(meta, holderKey))
    });
    assert.strictEqual(plain.status, 200,
      "with encryption_required = false the Wallet MAY choose, so an " +
          "unencrypted request must still " +
      "be honoured. HTTP " + plain.status);
    log.info("[required=false] OK — an unencrypted request is still accepted.");
    log.info("[required=true] not exercised here: it is a start-up setting " +
      "(OID4VCI_REQUEST_ENCRYPTION_REQUIRED=true) and this issuer is running " +
          "with it off. The " +
      "refusal it produces is asserted by the STS's own unit coverage.");
  } else {
    const plain = await fetch(meta.credential_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                "Authorization": "Bearer tok" },
      body: JSON.stringify(await freshRequestBody(meta, holderKey))
    });
    assert.strictEqual(plain.status, 400,
      "with encryption_required = true an unencrypted request SHOULD be " +
          "rejected.");
    log.info("[required=true] OK — an unencrypted request is refused.");
  }

  await assertWaltidStillDoesNotOffer();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "unused"));
program.addOption(new Option("-h, --headless <headless>", "unused"));
program.parse(process.argv);

test().catch(function (e) { log.error(e.stack ||
     e.message); process.exit(1); });
