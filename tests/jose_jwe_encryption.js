// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
function independentConcatKdf(z, keyBytes, algId, apu, apv) {
  log.debug("Entering independentConcatKdf().");
  function uint32(n) {
    log.debug("Entering uint32().");
    var b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug("Leaving uint32().");
    return b;
  }
  var alg = Buffer.from(algId, "utf8");
  var u = Buffer.from(apu || []);
  var v = Buffer.from(apv || []);
  var otherInfo = Buffer.concat([
    uint32(alg.length), alg,
    uint32(u.length), u,
    uint32(v.length), v,
    uint32(keyBytes * 8)
  ]);
  var out = [];
  for (var round = 1; (round - 1) * 32 < keyBytes; round++) {
    out.push(nodeCrypto.createHash("sha256")
      .update(Buffer.concat([uint32(round), Buffer.from(z), otherInfo]))
      .digest());
  }
  log.debug("Leaving independentConcatKdf().");
  return Buffer.concat(out).subarray(0, keyBytes);
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

// ---------------------------------------------------------------------------
// apu / apv (#472). RFC 7518 section 4.6.2 makes the base64url-decoded "apu"
// and "apv" header values the PartyUInfo and PartyVInfo of the Concat KDF.
// The module ignored them, which round-trips against itself perfectly and
// fails against every implementation that sets them — so both directions are
// checked against a JWE built and opened by hand with node's own crypto
// (ECDH, the KDF above, AES key wrap and AES-GCM), sharing no code with it.
// X25519 is absent because the module implements ECDH-ES on the NIST curves
// only (CURVE_BITS in jose_jwe.js).
// ---------------------------------------------------------------------------
var KW_BYTES = { "ECDH-ES+A128KW": 16, "ECDH-ES+A192KW": 24,
                 "ECDH-ES+A256KW": 32 };
var KW_IV = Buffer.from("A6A6A6A6A6A6A6A6", "hex");
var NODE_CURVES = { "P-256": "prime256v1", "P-384": "secp384r1",
                    "P-521": "secp521r1" };

// The key the KDF derives from the agreed secret, for either side.
function independentAgreement(alg, enc, header, privateKey, publicKey) {
  log.debug("Entering independentAgreement().");
  var z = nodeCrypto.diffieHellman({ privateKey: privateKey,
                                     publicKey: publicKey });
  var apu = header.apu === undefined ? null :
    Buffer.from(header.apu, "base64url");
  var apv = header.apv === undefined ? null :
    Buffer.from(header.apv, "base64url");
  var direct = alg === "ECDH-ES";
  var key = independentConcatKdf(z, direct ? 32 : KW_BYTES[alg],
                                 direct ? enc : alg, apu, apv);
  log.debug("Leaving independentAgreement().");
  return key;
}

// A compact JWE built entirely with node's crypto. enc is always A256GCM.
function independentEncrypt(alg, crv, recipientPublic, extraHeader,
                            plaintext) {
  log.debug("Entering independentEncrypt().");
  var eph = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: NODE_CURVES[crv] });
  var epk = eph.publicKey.export({ format: "jwk" });
  var header = Object.assign({ alg: alg, enc: "A256GCM",
    epk: { kty: "EC", crv: crv, x: epk.x, y: epk.y } }, extraHeader);
  var derived = independentAgreement(alg, "A256GCM", header, eph.privateKey,
                                     recipientPublic);
  var cek = derived;
  var encryptedKey = Buffer.alloc(0);
  if (alg !== "ECDH-ES") {
    cek = nodeCrypto.randomBytes(32);
    var wrap = nodeCrypto.createCipheriv("id-aes" + (derived.length * 8) +
        "-wrap", derived, KW_IV);
    encryptedKey = Buffer.concat([wrap.update(cek), wrap.final()]);
  }
  var protectedB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  var iv = nodeCrypto.randomBytes(12);
  var gcm = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  gcm.setAAD(Buffer.from(protectedB64, "ascii"));
  var ct = Buffer.concat([gcm.update(plaintext, "utf8"), gcm.final()]);
  log.debug("Leaving independentEncrypt().");
  return [protectedB64, encryptedKey.toString("base64url"),
          iv.toString("base64url"), ct.toString("base64url"),
          gcm.getAuthTag().toString("base64url")].join(".");
}

// Open a compact A256GCM JWE with node's crypto alone.
function independentDecrypt(jwe, recipientPrivate) {
  log.debug("Entering independentDecrypt().");
  var parts = jwe.split(".");
  var header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  assert.strictEqual(header.enc, "A256GCM");
  var epk = nodeCrypto.createPublicKey({ key: header.epk, format: "jwk" });
  var derived = independentAgreement(header.alg, header.enc, header,
                                     recipientPrivate, epk);
  var cek = derived;
  if (header.alg !== "ECDH-ES") {
    var unwrap = nodeCrypto.createDecipheriv("id-aes" +
        (derived.length * 8) + "-wrap", derived, KW_IV);
    cek = Buffer.concat([unwrap.update(Buffer.from(parts[1], "base64url")),
                         unwrap.final()]);
  }
  var gcm = nodeCrypto.createDecipheriv("aes-256-gcm", cek,
                                        Buffer.from(parts[2], "base64url"));
  gcm.setAAD(Buffer.from(parts[0], "ascii"));
  gcm.setAuthTag(Buffer.from(parts[4], "base64url"));
  var plain = Buffer.concat([gcm.update(Buffer.from(parts[3], "base64url")),
                             gcm.final()]).toString("utf8");
  log.debug("Leaving independentDecrypt().");
  return plain;
}

// Replace one member of a compact JWE's protected header, leaving the other
// four segments as they were.
function withHeaderMember(jwe, name, value) {
  log.debug("Entering withHeaderMember().");
  var parts = jwe.split(".");
  var header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  header[name] = value;
  log.debug("Leaving withHeaderMember().");
  return [Buffer.from(JSON.stringify(header)).toString("base64url")]
    .concat(parts.slice(1)).join(".");
}

async function apuApvMatchAnIndependentImplementation() {
  log.debug("Entering apuApvMatchAnIndependentImplementation().");
  log.info("=== apu / apv in the Concat KDF, against node's own crypto ===");
  var plaintext = JSON.stringify({ vp_token: { q: ["eyJ.e30.sig~"] } });
  // What OpenID4VP wallets send: apu a nonce of the wallet's, apv the
  // verifier's nonce. Arbitrary octets, so a zero and a 0xff are included.
  var partyHeaders = [
    ["without apu/apv", {}],
    ["with apu and apv", {
      apu: Buffer.from([0, 1, 2, 0xff, 0x41]).toString("base64url"),
      apv: Buffer.from("verifier-nonce-n-0S6_WzA2Mj").toString("base64url")
    }],
    ["with apu only", { apu: Buffer.from("Alice").toString("base64url") }],
    ["with apv only", { apv: Buffer.from("Bob").toString("base64url") }],
    ["with empty apu and apv", { apu: "", apv: "" }]
  ];
  var algs = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
              "ECDH-ES+A256KW"];
  var checked = 0;
  for (var crv of Object.keys(NODE_CURVES)) {
    var recipient = nodeCrypto.generateKeyPairSync("ec",
      { namedCurve: NODE_CURVES[crv] });
    var publicJwk = recipient.publicKey.export({ format: "jwk" });
    var privateJwk = recipient.privateKey.export({ format: "jwk" });
    for (var alg of algs) {
      for (var ph of partyHeaders) {
        var label = alg + " on " + crv + " " + ph[0];
        // 1. node's JWE, opened by the module.
        var theirs = independentEncrypt(alg, crv, recipient.publicKey, ph[1],
                                        plaintext);
        var opened = await jose.decryptCompact({ jwe: theirs,
                                                 key: privateJwk });
        assert.strictEqual(opened.plaintext, plaintext,
          label + ": the module did not open node's JWE.");
        // 2. the module's JWE, apu/apv placed by the caller, opened by node.
        var mine = await jose.encryptCompact({ alg: alg, enc: "A256GCM",
          plaintext: plaintext, key: publicJwk, header: ph[1] });
        assert.strictEqual(mine.header.apu, ph[1].apu,
          label + ": apu must be carried as given, never invented.");
        assert.strictEqual(mine.header.apv, ph[1].apv,
          label + ": apv must be carried as given, never invented.");
        assert.strictEqual(independentDecrypt(mine.jwe, recipient.privateKey),
          plaintext, label + ": node could not open the module's JWE.");
        // 3. an apu altered after encryption must not open.
        var altered = withHeaderMember(theirs, "apu",
          Buffer.from("Mallory").toString("base64url"));
        await assert.rejects(
          jose.decryptCompact({ jwe: altered, key: privateJwk }),
          label + ": a JWE whose apu was altered must not decrypt.");
        checked++;
      }
    }
  }

  // The KDF on its own, since a header edit also breaks the AAD and so cannot
  // show by itself that apu reached the derivation.
  var z = nodeCrypto.randomBytes(32);
  var withApu = Buffer.from(await jose.concatKdf(z, 32, "A256GCM",
    new Uint8Array([1, 2, 3]), new Uint8Array(0)));
  var plain = Buffer.from(await jose.concatKdf(z, 32, "A256GCM"));
  assert.ok(!withApu.equals(plain), "apu must change the derived key.");
  assert.ok(withApu.equals(independentConcatKdf(z, 32, "A256GCM",
    [1, 2, 3], null)), "the module's KDF with apu disagrees with RFC 7518.");
  var withApv = Buffer.from(await jose.concatKdf(z, 32, "A256GCM",
    null, new Uint8Array([1, 2, 3])));
  assert.ok(!withApv.equals(withApu),
    "apu and apv must occupy different fields of OtherInfo.");
  // Multi-round output (A256CBC-HS512 needs 64 octets) with apu and apv.
  var long = Buffer.from(await jose.concatKdf(z, 64, "A256CBC-HS512",
    new Uint8Array([9]), new Uint8Array([8, 7])));
  assert.ok(long.equals(independentConcatKdf(z, 64, "A256CBC-HS512",
    [9], [8, 7])), "a two-round derivation with apu/apv disagrees.");

  // apu/apv that are not base64url are refused by name, both ways.
  var bad = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" });
  for (var value of ["not base64url!", "abc+/", "a", 42]) {
    await assert.rejects(
      jose.encryptCompact({ alg: "ECDH-ES", enc: "A256GCM", plaintext: "x",
        key: bad.publicKey.export({ format: "jwk" }),
        header: { apu: value } }),
      /"apu" header parameter must be a base64url string/,
      "an apu of " + JSON.stringify(value) + " should be refused by name.");
  }
  var good = independentEncrypt("ECDH-ES", "P-256", bad.publicKey,
    { apv: "AAAA" }, "x");
  await assert.rejects(
    jose.decryptCompact({ jwe: withHeaderMember(good, "apv", "AA=="),
      key: bad.privateKey.export({ format: "jwk" }) }),
    /"apv" header parameter must be a base64url string/,
    "a padded apv is base64, not base64url, and should be refused by name.");

  log.info("[apu/apv] OK — " + checked + " cases interoperate with node's " +
           "crypto in both directions, and an altered apu does not open.");
  log.debug("Leaving apuApvMatchAnIndependentImplementation().");
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
  // ML-KEM and HPKE (#312) take JWKs, one key per alg; tests/hpke_jwe_engine.js
  // holds them to the drafts' vectors, and this checks they serialize like
  // every other alg here.
  jose.supportedAlgs().filter(jose.isKemAlg).forEach(function (a) {
    var kp = jose.generateKemKeyPair(a);
    keyPairs[a] = { publicKey: kp.publicJwk, privateKey: kp.privateJwk };
  });
  var pairs = 0;
  var algs = jose.supportedAlgs();
  var encs = jose.supportedEncs();
  for (var a = 0; a < algs.length; a++) {
    for (var e = 0; e < encs.length; e++) {
      var alg = algs[a];
      var enc = encs[e];
      // HPKE Integrated Encryption has no enc, so one pass covers it.
      if (jose.isIntegrated(alg) && e > 0) {
        continue;
      }
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
      assert.strictEqual(produced.header.enc,
                         jose.isIntegrated(alg) ? undefined : enc,
                         "and the enc — none for HPKE Integrated Encryption.");
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
      if (alg === "ECDH-ES" || /^ML-KEM-[0-9]+$/.test(alg)) {
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

// ---------------------------------------------------------------------------
// RFC 7518 Appendix B.1 — the specification's OWN vector for
// AES_128_CBC_HMAC_SHA_256, and an independent AES-CBC + HMAC built on node's
// OpenSSL for the two sizes the appendix does not publish in the same form.
//
// This is the check a round trip cannot make. The CBC-HMAC construction has
// four places where a reading of section 5.2.2 can be self-consistent and
// wrong, and every one of them round-trips perfectly against itself:
//
//   * the CEK halves taken the wrong way round (MAC key is the FIRST half);
//   * AL computed in bytes rather than bits, or over the wrong span;
//   * the MAC input assembled in another order;
//   * the whole HMAC output used as the tag instead of its first half.
//
// Each produces a JWE this module reads back happily and no other
// implementation can open — which for an encrypted UserInfo response is a
// client reporting that the identity provider sent it something corrupt.
// ---------------------------------------------------------------------------
async function cbcHmacMatchesTheRfcVector() {
  log.debug("Entering cbcHmacMatchesTheRfcVector().");
  var hex = function (text) {
    return Uint8Array.from(Buffer.from(text.replace(/\s+/g, ""), "hex"));
  };
  var ascii = function (text) {
    return Uint8Array.from(Buffer.from(text, "ascii"));
  };
  var toHex = function (bytes) {
    return Buffer.from(bytes).toString("hex");
  };

  var K = hex("000102030405060708090a0b0c0d0e0f" +
              "101112131415161718191a1b1c1d1e1f");
  var IV = hex("1af38c2dc2b96ffdd86694092341bc04");
  var A = ascii("The second principle of Auguste Kerckhoffs");
  var P = ascii("A cipher system must not be required to be secret, and it " +
                "must be able to fall into the hands of the enemy without " +
                "inconvenience");
  var EXPECTED_TAG = "652c3fa36b0a7c5b3219fab3a30bc1c4";

  var sealed = await jose.cbcHmacEncrypt(K, "A128CBC-HS256", IV, A, P);
  assert.strictEqual(toHex(sealed.tag), EXPECTED_TAG,
    "the RFC 7518 B.1 authentication tag must come out exactly. A tag that " +
    "is wrong here is a tag that is wrong everywhere, and the round-trip " +
    "test above cannot see it.");

  var back = await jose.cbcHmacDecrypt(K, "A128CBC-HS256", IV, A,
      sealed.ciphertext, sealed.tag);
  assert.strictEqual(Buffer.from(back).toString("ascii"),
    Buffer.from(P).toString("ascii"),
    "the B.1 vector must decrypt back to its own plaintext.");

  // The other two sizes against node's OpenSSL, which is a genuinely separate
  // implementation of the same construction.
  var sizes = { "A128CBC-HS256": ["aes-128-cbc", "sha256", 16],
                "A192CBC-HS384": ["aes-192-cbc", "sha384", 24],
                "A256CBC-HS512": ["aes-256-cbc", "sha512", 32] };
  var names = Object.keys(sizes);
  for (var i = 0; i < names.length; i++) {
    var enc = names[i];
    var spec = sizes[enc];
    var cek = Uint8Array.from(nodeCrypto.randomBytes(spec[2] * 2));
    var iv = Uint8Array.from(nodeCrypto.randomBytes(16));
    var aad = Uint8Array.from(nodeCrypto.randomBytes(37));
    var plaintext = Uint8Array.from(nodeCrypto.randomBytes(200));

    var mine = await jose.cbcHmacEncrypt(cek, enc, iv, aad, plaintext);

    var cipher = nodeCrypto.createCipheriv(spec[0],
        Buffer.from(cek.slice(spec[2])), Buffer.from(iv));
    var reference = Buffer.concat([cipher.update(Buffer.from(plaintext)),
                                   cipher.final()]);
    var al = Buffer.alloc(8);
    al.writeBigUInt64BE(BigInt(aad.length * 8));
    var mac = nodeCrypto.createHmac(spec[1], Buffer.from(cek.slice(0, spec[2])))
      .update(Buffer.concat([Buffer.from(aad), Buffer.from(iv), reference, al]))
      .digest().subarray(0, spec[2]);

    assert.strictEqual(toHex(mine.ciphertext), reference.toString("hex"),
      enc + ": the ciphertext must match OpenSSL's byte for byte.");
    assert.strictEqual(toHex(mine.tag), mac.toString("hex"),
      enc + ": the authentication tag must match an independent reading of " +
      "section 5.2.2 — key halves, AL in bits, and the tag truncated to the " +
      "first half of the HMAC output.");

    // A flipped ciphertext bit must be caught by the MAC, not by CBC padding:
    // a padding error that escapes the tag check is the classic oracle.
    var mauled = Uint8Array.from(mine.ciphertext);
    mauled[5] ^= 1;
    await assert.rejects(
      jose.cbcHmacDecrypt(cek, enc, iv, aad, mauled, mine.tag),
      /authentication tag/,
      enc + ": a mauled ciphertext must be refused by the tag check.");
  }
  log.info("[cbc-hmac] OK — RFC 7518 B.1 reproduces exactly, and all three " +
           "sizes agree with OpenSSL on ciphertext and tag.");
  log.debug("Leaving cbcHmacMatchesTheRfcVector().");
}

// ---------------------------------------------------------------------------
// THE JAVASCRIPT AES PATH — what this module does where Web Crypto will not.
//
// Chrome implements AES at 128 and 256 and refuses 192, for GCM, for CBC and
// for key wrapping alike. That would take A192GCM, A192CBC-HS384 and
// ECDH-ES+A192KW — three registered JOSE algorithms — off the table in a
// browser, so jose_jwe.js performs them itself on node-forge.
//
// TWO THINGS HERE CANNOT BE CHECKED BY A ROUND TRIP, which is why this function
// exists beside the grid above. The first is that the JavaScript key wrap is
// the RFC's key wrap and not merely self-consistent: it is checked against RFC
// 3394's own published vectors AND against node's Web Crypto, which implements
// AES-KW at all three sizes. The second is the routing rule itself — 192 must
// take the JavaScript path and 128/256 must not — because a module that quietly
// routed everything through JavaScript would still pass every round trip while
// abandoning the browser's audited implementation for the sizes it has.
// ---------------------------------------------------------------------------
async function theJavaScriptAesPathMatchesWebCrypto() {
  log.debug("Entering theJavaScriptAesPathMatchesWebCrypto().");
  var hex = function (text) {
    return Uint8Array.from(Buffer.from(text.replace(/\s+/g, ""), "hex"));
  };
  var toHex = function (bytes) {
    return Buffer.from(bytes).toString("hex");
  };

  // The routing rule. 192 is the size Web Crypto refuses; the other two must
  // keep using it.
  assert.strictEqual(jose.webCryptoDoesAes(24), false,
    "AES-192 must take the JavaScript path — it is the size Chrome refuses.");
  assert.strictEqual(jose.webCryptoDoesAes(16), true,
    "AES-128 must keep using Web Crypto.");
  assert.strictEqual(jose.webCryptoDoesAes(32), true,
    "AES-256 must keep using Web Crypto.");

  // RFC 3394 section 4's published vectors, all three KEK sizes.
  var vectors = [
    ["4.1", "000102030405060708090A0B0C0D0E0F",
     "00112233445566778899AABBCCDDEEFF",
     "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"],
    ["4.2", "000102030405060708090A0B0C0D0E0F1011121314151617",
     "00112233445566778899AABBCCDDEEFF",
     "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"],
    ["4.3",
     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF",
     "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"]
  ];
  vectors.forEach(function (v) {
    var wrapped = jose.aesKwWrapJs(hex(v[1]), hex(v[2]));
    assert.strictEqual(toHex(wrapped), v[3],
      "RFC 3394 section " + v[0] + " must reproduce exactly; a key wrap that " +
      "is wrong here is wrong everywhere and the round trip cannot see it.");
    assert.strictEqual(toHex(jose.aesKwUnwrapJs(hex(v[1]), wrapped)),
      hex(v[2]) && toHex(hex(v[2])),
      "RFC 3394 section " + v[0] + " must unwrap back to its own key.");
  });

  // And against node's Web Crypto, which does implement AES-KW at 192.
  for (var bits = 128; bits <= 256; bits += 64) {
    var kek = Uint8Array.from(nodeCrypto.randomBytes(bits / 8));
    var cek = Uint8Array.from(nodeCrypto.randomBytes(32));
    var mine = jose.aesKwWrapJs(kek, cek);
    var kekKey = await crypto.subtle.importKey("raw", kek, { name: "AES-KW" },
      false, ["wrapKey"]);
    var carrier = await crypto.subtle.importKey("raw", cek,
      { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
    var reference = new Uint8Array(await crypto.subtle.wrapKey("raw", carrier,
      kekKey, "AES-KW"));
    assert.strictEqual(toHex(mine), toHex(reference),
      "AES-" + bits + "-KW in JavaScript must agree with Web Crypto's, byte " +
      "for byte.");
  }

  // The integrity check is the only thing that tells a wrong key-encryption
  // key from a right one, so an unwrap with the wrong KEK must throw rather
  // than hand back plausible rubbish.
  await assert.rejects(
    (async function () {
      var wrapped = jose.aesKwWrapJs(
        Uint8Array.from(nodeCrypto.randomBytes(24)),
        Uint8Array.from(nodeCrypto.randomBytes(32)));
      jose.aesKwUnwrapJs(Uint8Array.from(nodeCrypto.randomBytes(24)), wrapped);
    })(),
    /integrity/,
    "unwrapping with the wrong KEK must fail RFC 3394's integrity check by " +
    "name, not return rubbish.");

  // NOTHING THIS MODULE OFFERS MAY BE REPORTED AS UNAVAILABLE. Not the three
  // AES-192 algorithms Chrome refuses, and not anything else: every alg and
  // enc here has a JavaScript implementation, so what a runtime cannot do
  // changes which engine runs and never what a user is allowed to choose.
  //
  // This is asserted over the WHOLE catalogue rather than over the three
  // known cases, because the failure it guards against is a future algorithm
  // being greyed out for the same bad reason.
  var support = await jose.probeAesSupport();
  jose.supportedEncs().forEach(function (enc) {
    assert.strictEqual(jose.encUnsupportedReason(enc, support), "",
      enc + " must never be reported unavailable: this module implements it, " +
      "in JavaScript where the runtime will not.");
  });
  jose.supportedAlgs().forEach(function (alg) {
    assert.strictEqual(jose.algUnsupportedReason(alg, support), "",
      alg + " must never be reported unavailable, for the same reason.");
  });
  // An algorithm that genuinely is not implemented must still be named, or
  // the two functions above would be answering "" to everything.
  assert.ok(/unknown/.test(jose.encUnsupportedReason("A999GCM", support)),
    "an enc this module does not implement must still be named as such.");
  log.info("[js aes] OK — RFC 3394 reproduces at all three sizes and agrees " +
           "with Web Crypto; AES-192 routes to JavaScript and 128/256 do " +
           "not; and the three AES-192 algorithms report as usable.");
  log.debug("Leaving theJavaScriptAesPathMatchesWebCrypto().");
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
  // THIS USED TO BE "A256CBC-HS512", and it stopped being a negative on
  // 2026-08-28 when the CBC-HMAC family was implemented. RFC 7518 section 5.1
  // registers exactly six `enc` values and the module now does all six, so
  // there is no registered-but-unimplemented one left to name here — an
  // unregistered value is what is left, and it still proves the point the
  // assertion was making: an `enc` this module does not know is REFUSED rather
  // than guessed at. Do not "fix" this back to a real algorithm.
  await assert.rejects(
    jose.encryptCompact({ alg: "RSA-OAEP-256", enc: "A256CBC-HS999",
                        plaintext: "x", key: rsa.publicKey }),
    /unsupported content encryption/,
    "an unregistered content encryption algorithm should be named.");
  log.info("[negatives] OK — header edits, bit flips, the wrong key, " +
           "malformed input and unimplemented " +
           "algorithms are all refused.");
  log.debug("Leaving tamperingAndBadInputAreRefused().");
}

// WITH NO WEB CRYPTO AT ALL (#463, step 2). A page served over plain HTTP
// has no crypto.subtle, and every primitive here is crypto_provider.js's
// now, so every key management algorithm and every content encryption must
// still encrypt and decrypt. crypto.subtle is removed for the duration
// (getRandomValues stays: it exists outside a secure context). Each JWE is
// then opened by the `jose` library, which shares no code with this tree.
async function worksWithNoWebCrypto() {
  log.debug("Entering worksWithNoWebCrypto().");
  log.info("=== Every algorithm with no crypto.subtle ===");
  var ecPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var xPair = nodeCrypto.generateKeyPairSync("x25519");
  var rsaPair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var jwkOf = function jwkOf(k) {
    log.debug("Entering jwkOf().");
    log.debug("Leaving jwkOf().");
    return k.export({ format: "jwk" });
  };
  var cases = [];
  ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
    .forEach(function (alg) {
      cases.push({ alg: alg, pair: ecPair });
    });
  cases.push({ alg: "ECDH-ES", pair: xPair });
  cases.push({ alg: "RSA-OAEP", pair: rsaPair });
  cases.push({ alg: "RSA-OAEP-256", pair: rsaPair });
  var encs = ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
              "A192CBC-HS384", "A256CBC-HS512"];
  var made = [];
  var descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  var real = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", { configurable: true,
    writable: true, value: { getRandomValues: function (a) {
      return real.getRandomValues(a);
    } } });
  try {
    assert.strictEqual(typeof crypto.subtle, "undefined");
    for (var i = 0; i < cases.length; i++) {
      for (var j = 0; j < encs.length; j++) {
        var c = cases[i];
        var text = "no web crypto: " + c.alg + " / " + encs[j];
        var sealed = await jose.encryptCompact({ alg: c.alg, enc: encs[j],
          plaintext: text, key: jwkOf(c.pair.publicKey) });
        var opened = await jose.decryptCompact({ jwe: sealed.jwe,
          key: jwkOf(c.pair.privateKey) });
        assert.strictEqual(opened.plaintext, text, text);
        made.push({ jwe: sealed.jwe, key: c.pair.privateKey, text: text });
      }
    }
    var pw = await jose.pbes2JweEncrypt("secret set", "a password");
    assert.strictEqual(pw.split(".").length, 5, "PBES2 with no Web Crypto");
    made.push({ jwe: pw, password: "a password", text: "secret set" });
  } finally {
    Object.defineProperty(globalThis, "crypto", descriptor);
  }
  var lib = await import("jose");
  for (var k = 0; k < made.length; k++) {
    var m = made[k];
    var out = m.password
      ? await lib.compactDecrypt(m.jwe, new TextEncoder().encode(m.password),
                                 { keyManagementAlgorithms: [
                                   "PBES2-HS256+A128KW"],
                                   // jose's default cap is 10,000; this
                                   // module uses 100,000 iterations.
                                   maxPBES2Count: 100000 })
      : await lib.compactDecrypt(m.jwe, m.key);
    assert.strictEqual(new TextDecoder().decode(out.plaintext), m.text,
                       "jose opens: " + m.text);
  }
  log.info("[no web crypto] OK — " + (made.length - 1) + " alg/enc pairs " +
           "and PBES2 encrypt and decrypt with crypto.subtle absent, and " +
           "the jose library opens every one.");
  log.debug("Leaving worksWithNoWebCrypto().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Testing client/src/jose_jwe.js directly.");
  await keyDerivationMatchesTheRfc();
  await apuApvMatchAnIndependentImplementation();
  await everyAlgorithmRoundTrips();
  await cbcHmacMatchesTheRfcVector();
  await theJavaScriptAesPathMatchesWebCrypto();
  await keysInEveryForm();
  await tamperingAndBadInputAreRefused();
  await worksWithNoWebCrypto();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
