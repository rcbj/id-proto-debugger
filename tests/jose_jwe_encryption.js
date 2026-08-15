// File: jose_jwe.js
//
// The shared in-browser JWE implementation (client/src/jose_jwe.js), tested
// directly — no browser, no page, just the crypto.
//
// It is worth testing on its own because it is now shared: the JWT Tools page
// encrypts and decrypts with it, and OID4VCI section 10 has a Credential Issuer
// and a Wallet encrypting to each other with it. A round trip against itself is
// the weakest possible check of a key derivation — two sides of the same
// mistake agree perfectly — so the Concat KDF (RFC 7518 section 4.6) is also
// checked against an implementation written here, from the RFC text, that
// shares no code with the module.
//
// What the browser suite adds on top of this is what only a browser can say:
// which algorithms Chrome's Web Crypto actually implements (it rejects AES-192,
// which node happily performs — see tests/jwt_tools.js).
//
// Needs no services: node's Web Crypto is enough.

const assert = require("assert");
const nodeCrypto = require("crypto");
const paths = require("./module_paths");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'jose_jwe_test',
                                level: appconfig.LOG_LEVEL || 'info' });

// The module is browser code: it expects btoa/atob and Web Crypto, all of which
// node provides as globals. It is loaded through module_paths so its own
// requires resolve whether it is run from a checkout or from the tests image.
var jose = paths.requireSharedModule(
  [__dirname + "/../client/src/jose_jwe.js", __dirname + "/jose_jwe.js"],
   "jose_jwe.js");

// ---------------------------------------------------------------------------
// An independent Concat KDF, written from RFC 7518 section 4.6:
//
//   Hash( round=1 || Z || AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo )
//
// with each Info field length-prefixed as a 32-bit big-endian count, and
// SuppPubInfo carrying the key length in BITS. Deliberately built with node's
// Buffer and hash APIs rather than anything the module uses, so that agreement
// between the two means something.
// ---------------------------------------------------------------------------
function independentConcatKdf(z, keyBytes, algId) {
  log.debug("Entering independentConcatKdf().");
  function uint32(n) {
    log.debug("Entering uint32().");
    var b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug("Leaving uint32().");
    return b;
  }
  var alg = Buffer.from(algId, "utf8");
  var input = Buffer.concat([
    uint32(1), Buffer.from(z),
    uint32(alg.length), alg,
    uint32(0),
    uint32(0),
    uint32(keyBytes * 8)
  ]);
  log.debug("Leaving independentConcatKdf().");
  return nodeCrypto.createHash("sha256").update(input).digest().subarray(0,
                               keyBytes);
}

async function keyDerivationMatchesTheRfc() {
  log.debug("Entering keyDerivationMatchesTheRfc().");
  log.info("=== The Concat KDF, against an independent implementation ===");
  var z = nodeCrypto.randomBytes(32);
  // Both uses of the KDF: direct ECDH-ES (AlgorithmID is the "enc" value) and
  // the key-wrap variants (AlgorithmID is the full "alg").
  var cases = [
    ["A128GCM", 16], ["A192GCM", 24], ["A256GCM", 32],
    ["ECDH-ES+A128KW", 16], ["ECDH-ES+A192KW", 24], ["ECDH-ES+A256KW", 32]
  ];
  for (var i = 0; i < cases.length; i++) {
    var mine = Buffer.from(await jose.concatKdf(z, cases[i][1], cases[i][0]));
    var independent = independentConcatKdf(z, cases[i][1], cases[i][0]);
    assert.ok(mine.equals(independent),
      "the derived key for " + cases[i][0] +
          " differs from an independent reading of RFC 7518 " +
      "section 4.6:\n  module:      " + mine.toString("hex") +
      "\n  independent: " + independent.toString("hex"));
  }
  // A different secret must produce a different key, or the comparison above
  // could be comparing two constants.
  var other = Buffer.from(await jose.concatKdf(nodeCrypto.randomBytes(32), 32,
      "A256GCM"));
  var same = Buffer.from(await jose.concatKdf(z, 32, "A256GCM"));
  assert.ok(!other.equals(same),
            "a different agreed secret must derive a different key.");
  // As must a different AlgorithmID, which is the whole point of binding it in.
  var byEnc = Buffer.from(await jose.concatKdf(z, 32, "A256GCM"));
  var byAlg = Buffer.from(await jose.concatKdf(z, 32, "ECDH-ES+A256KW"));
  assert.ok(!byEnc.equals(byAlg),
    "the AlgorithmID must change the derived key, otherwise it is not " +
        "bound in.");
  log.info("[kdf] OK — " + cases.length +
           " derivations match, and the inputs demonstrably matter.");
  log.debug("Leaving keyDerivationMatchesTheRfc().");
}

async function everyAlgorithmRoundTrips() {
  log.debug("Entering everyAlgorithmRoundTrips().");
  log.info("=== Every algorithm pair round-trips ===");
  var rsaSha256 = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,
     0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]);
  var rsaSha1 = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,
     0, 1]), hash: "SHA-1" },
    true, ["encrypt", "decrypt"]);
  var ec = await crypto.subtle.generateKey({ name: "ECDH",
      namedCurve: "P-256" }, true, ["deriveBits"]);

  // A realistic payload: an OID4VCI Credential Request is what this will carry.
  var plaintext = JSON.stringify({
    credential_configuration_id: "IdentityCredential",
    proofs: { jwt: ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.e30.sig"] }
  });

  var keyPairs = {
    "RSA-OAEP": rsaSha1,
    "RSA-OAEP-256": rsaSha256,
    "ECDH-ES": ec,
    "ECDH-ES+A128KW": ec,
    "ECDH-ES+A192KW": ec,
    "ECDH-ES+A256KW": ec
  };
  var pairs = 0;
  var algs = jose.supportedAlgs();
  var encs = jose.supportedEncs();
  for (var a = 0; a < algs.length; a++) {
    for (var e = 0; e < encs.length; e++) {
      var alg = algs[a];
      var enc = encs[e];
      var pair = keyPairs[alg];
      assert.ok(pair, "no key pair for " + alg +
                " — the module offers an algorithm this test does not cover.");

      var produced = await jose.encryptCompact({
        alg: alg, enc: enc, plaintext: plaintext, key: pair.publicKey,
        header: { kid: "test-key-1", cty: "JWT" }
      });
      var parts = produced.jwe.split(".");
      assert.strictEqual(parts.length, 5,
        alg + " / " + enc +
            ": compact serialization must have five segments, got " +
            parts.length);
      assert.strictEqual(produced.header.alg, alg,
                         "the protected header must name the alg used.");
      assert.strictEqual(produced.header.enc, enc, "and the enc.");
      assert.strictEqual(produced.header.kid, "test-key-1",
        "caller-supplied header parameters must survive.");
      assert.strictEqual(produced.header.cty, "JWT", "including cty.");

      if (jose.isEcdh(alg)) {
        assert.ok(produced.header.epk && produced.header.epk.crv === "P-256",
          alg + " must publish the ephemeral public key it agreed with. Got: " +
          JSON.stringify(produced.header.epk));
        assert.ok(!produced.header.epk.d,
          "and the epk must be the PUBLIC half only. Got members: " +
          Object.keys(produced.header.epk).join(", "));
      }
      if (alg === "ECDH-ES") {
        assert.strictEqual(parts[1], "",
          "ECDH-ES is direct key agreement: encrypted_key must be empty. Got " +
              parts[1].length +
          " characters.");
      } else {
        assert.ok(parts[1].length > 0,
          alg + " wraps a content encryption key, so encrypted_key must not " +
              "be empty.");
      }

      var back = await jose.decryptCompact({ jwe: produced.jwe,
          key: pair.privateKey });
      assert.strictEqual(back.plaintext, plaintext,
        alg + " / " + enc + " did not round-trip.");
      assert.strictEqual(back.header.alg, alg,
          "the decrypted header should be the one that was sent.");
      pairs++;
    }
  }
  log.info("[round trip] OK — " + pairs +
           " alg/enc pairs encrypt and decrypt: " +
           algs.join(", ") + " over " + encs.join(", ") + ".");
  log.debug("Leaving everyAlgorithmRoundTrips().");
}

async function keysInEveryForm() {
  log.debug("Entering keysInEveryForm().");
  log.info("=== Keys in every form a caller might have ===");
  var rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,
     0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]);
  var pubJwk = await crypto.subtle.exportKey("jwk", rsa.publicKey);
  var privJwk = await crypto.subtle.exportKey("jwk", rsa.privateKey);
  var pubPem = jose.derToPem(await crypto.subtle.exportKey("spki",
      rsa.publicKey), "PUBLIC KEY");
  var privPem = jose.derToPem(await crypto.subtle.exportKey("pkcs8",
      rsa.privateKey), "PRIVATE KEY");

  // A JWK as it comes out of a JWKS — with the metadata members a strict Web
  // Crypto import rejects, which is why they have to be stripped.
  var fromJwks = { kty: pubJwk.kty, n: pubJwk.n, e: pubJwk.e,
      alg: "RSA-OAEP-256", use: "enc", kid: "issuer-enc-1" };
  var forms = [
    ["a CryptoKey", rsa.publicKey, rsa.privateKey],
    ["a JWK object from a JWKS", fromJwks, privJwk],
    ["JWK text, as a page field holds it", JSON.stringify(pubJwk),
     JSON.stringify(privJwk)],
    ["PEM", pubPem, privPem]
  ];
  for (var i = 0; i < forms.length; i++) {
    var produced = await jose.encryptCompact({
      alg: "RSA-OAEP-256", enc: "A256GCM", plaintext: "the same either way",
          key: forms[i][1]
    });
    var back = await jose.decryptCompact({ jwe: produced.jwe,
        key: forms[i][2] });
    assert.strictEqual(back.plaintext, "the same either way",
      "encrypting with " + forms[i][0] +
          " should work — that is what makes the module reusable.");
  }
  log.info("[keys] OK — " + forms.length + " key forms accepted: " +
           forms.map(function (f) { return f[0]; }).join("; ") + ".");
  log.debug("Leaving keysInEveryForm().");
}

async function tamperingAndBadInputAreRefused() {
  log.debug("Entering tamperingAndBadInputAreRefused().");
  log.info("=== Tampering and malformed input ===");
  var rsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,
     0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]);
  var ec = await crypto.subtle.generateKey({ name: "ECDH",
      namedCurve: "P-256" }, true, ["deriveBits"]);
  var produced = await jose.encryptCompact({
    alg: "RSA-OAEP-256", enc: "A256GCM", plaintext: "secret", key: rsa.publicKey
  });

  // The protected header is the AAD, so editing it must break the tag. This is
  // what stops an attacker downgrading enc or swapping the epk.
  var parts = produced.jwe.split(".");
  var header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  header.enc = "A128GCM";
  var edited = [Buffer.from(JSON.stringify(header)).toString("base64url")]
      .concat(parts.slice(1)).join(".");
  await assert.rejects(
    jose.decryptCompact({ jwe: edited, key: rsa.privateKey }),
    "editing the protected header must fail: it is the additional " +
        "authenticated data.");

  // A flipped bit in the ciphertext, likewise.
  var ciphertext = Buffer.from(parts[3], "base64url");
  ciphertext[0] ^= 0x01;
  var flipped = parts.slice(0, 3).concat([ciphertext.toString("base64url"),
      parts[4]]).join(".");
  await assert.rejects(
    jose.decryptCompact({ jwe: flipped, key: rsa.privateKey }),
    "a modified ciphertext must fail authentication.");

  // The wrong key.
  var otherRsa = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,
     0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]);
  await assert.rejects(
    jose.decryptCompact({ jwe: produced.jwe, key: otherRsa.privateKey }),
    "another recipient's key must not open it.");

  // Shapes that are not JWEs at all, with messages that say what is wrong.
  assert.throws(function () { jose.parseCompact("one.two.three"); },
                /five segments/,
    "a three-part token is a JWS, not a JWE, and should be named as such.");
  assert.throws(function () { jose.parseCompact("!!!!.b.c.d.e"); },
                /readable JSON/,
    "an unreadable protected header should say so.");

  // An ECDH-ES JWE with no epk cannot be opened, and the reason should say why
  // rather than surfacing a Web Crypto error.
  var ecdh = await jose.encryptCompact({
    alg: "ECDH-ES", enc: "A256GCM", plaintext: "secret", key: ec.publicKey
  });
  var ecdhParts = ecdh.jwe.split(".");
  var noEpk = JSON.parse(Buffer.from(ecdhParts[0],
      "base64url").toString("utf8"));
  delete noEpk.epk;
  var stripped = [Buffer.from(JSON.stringify(noEpk)).toString("base64url")]
    .concat(ecdhParts.slice(1)).join(".");
  await assert.rejects(
    jose.decryptCompact({ jwe: stripped, key: ec.privateKey }),
    /epk/,
    "an ECDH-ES JWE without an epk header should be refused by name.");

  // Algorithms the module does not implement must be refused, not guessed at.
  await assert.rejects(
    jose.encryptCompact({ alg: "A256KW", enc: "A256GCM", plaintext: "x",
                        key: rsa.publicKey }),
    /unsupported key management algorithm/,
    "a key-management algorithm this module does not implement should " +
        "be named.");
  await assert.rejects(
    jose.encryptCompact({ alg: "RSA-OAEP-256", enc: "A256CBC-HS512",
                        plaintext: "x", key: rsa.publicKey }),
    /unsupported content encryption/,
    "so should an unimplemented content encryption algorithm.");
  log.info("[negatives] OK — header edits, bit flips, the wrong key, " +
           "malformed input and unimplemented " +
           "algorithms are all refused.");
  log.debug("Leaving tamperingAndBadInputAreRefused().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Testing client/src/jose_jwe.js directly.");
  await keyDerivationMatchesTheRfc();
  await everyAlgorithmRoundTrips();
  await keysInEveryForm();
  await tamperingAndBadInputAreRefused();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
