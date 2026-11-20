// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: hpke_jwe_engine.js
//
// ===========================================================================
// POST-QUANTUM AND HPKE KEY ESTABLISHMENT IN JWE (#312), in node.
//
// client/src/hpke.js (the HPKE engine), client/src/jwe_kem.js (the JOSE
// bindings) and client/src/jose_jwe.js (the five segments), held to answers
// that are not their own:
//
//   A. draft-ietf-hpke-pq-05's published vectors — every suite in the file
//      (ML-KEM-512/768/1024, the three PQ/T hybrids with X-Wing among them,
//      and the DHKEMs; HKDF, SHAKE and TurboSHAKE; AES-GCM and
//      ChaCha20-Poly1305): DeriveKeyPair, Encap reproduced from the vector's
//      ikmE, Decap of the vector's enc, the key schedule, every encryption
//      in both directions and every export.
//   B. draft-irtf-cfrg-concrete-hybrid-kems' vectors: key expansion from the
//      seed, the derandomized encapsulation and the decapsulation.
//   C. The JOSE working group's HPKE JWEs (draft-ietf-jose-hpke-encrypt-22's
//      repository): every compact JWE opened with the vector's key through
//      decryptCompact(). HPKE-4-KE and HPKE-6-KE, which -22 removed, must be
//      REFUSED as unknown algorithms.
//   D. draft-ietf-jose-pqc-kem-05's KMAC256 derivation, which no draft
//      publishes a vector for, rebuilt here from section 5.1's text with
//      Buffer and computed by OpenSSL's `openssl mac KMAC256` — and then a
//      whole ML-KEM JWE opened WITHOUT jose_jwe.js: the KEM decapsulated, the
//      CEK derived by OpenSSL and the content decrypted by node's AES-GCM.
//   E. X-Wing twice: hpke.js's MLKEM768-X25519 against pqc.js's X-Wing,
//      which tests/pqc_engines.js holds to the X-Wing draft's own vectors.
//   F. Every ML-KEM and HPKE alg against every enc through encryptCompact()
//      and decryptCompact(), with the header shape each draft requires, and
//      the PSK mode.
//   G. The refusals a wrong key, a wrong header or an altered JWE gets.
//
// THE VECTORS ARE COMMITTED, byte for byte as published, each checked
// against the SHA-256 below on load (a vector file that changed is a
// different test). They are the IETF's, under BCP 78 and the IETF Trust
// Legal Provisions, from each document's own repository at the commit its
// pinned revision was cut from:
//
//   tests/hpke_pq_vectors.json      hpkewg/hpke-pq
//       6433c8fce0b8b749dfc86c1095081a88698ccfab  test-vectors.json
//   tests/hybrid_kem_vectors.json   cfrg/draft-irtf-cfrg-concrete-hybrid-kems
//       e76e1939fb5bec71d3d6c206de20ca2c008f1f80  test-vectors.json
//   tests/jose_hpke_vectors.json    ietf-wg-jose/draft-ietf-jose-hpke-encrypt
//       2fa0c6b2b6d82013aa87a6d83c121de6f2fec3f0  examples/jose-vectors.json
//
// They carry test keys published in those documents, and nothing else.
//
// Needs no services and no browser.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const nodeCrypto = require("crypto");
const { execFileSync } = require("child_process");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "hpke_jwe_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The modules are read from the client TREE: `COPY client/src
// /usr/src/client/src` in tests/Dockerfile puts it at ../client/src in the
// image, and it is ../client/src in a checkout. Through module_paths.js so
// their own requires (bunyan, @noble/*) resolve from this install.
const SRC = path.join(path.resolve(__dirname, ".."), "client", "src");
const paths = require("./module_paths.js");
const hpke = paths.requireSharedModule([path.join(SRC, "hpke.js")],
                                       "client/src/hpke.js");
const kem = paths.requireSharedModule([path.join(SRC, "jwe_kem.js")],
                                      "client/src/jwe_kem.js");
const jose = paths.requireSharedModule([path.join(SRC, "jose_jwe.js")],
                                       "client/src/jose_jwe.js");
const pqc = paths.requireCryptoModule("pqc.js");
const mlkem = require("@noble/post-quantum/ml-kem.js");

const VECTORS = {
  "hpke_pq_vectors.json":
    "35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c",
  "hybrid_kem_vectors.json":
    "08b47d9fe5c827f7ceb20dd10a59bc853a949d6eaf0ad835405e86d833f92bad",
  "jose_hpke_vectors.json":
    "235fade8057e5e114d3e6b6e39c7187509178f148e0518a4117e8a3d3c1c3884"
};

function loadVectors(name) {
  log.debug("Entering loadVectors(). " + name);
  var file = path.join(__dirname, name);
  var raw = fs.readFileSync(file);
  var sum = nodeCrypto.createHash("sha256").update(raw).digest("hex");
  assert.strictEqual(sum, VECTORS[name], name + " is not the file that " +
      "was published (SHA-256 " + sum + "); a changed vector file is a " +
      "different test.");
  log.debug("Leaving loadVectors().");
  return JSON.parse(raw.toString("utf8"));
}

// hex() is a hot path — every vector field passes through it — so it logs
// nothing.
function hex(s) {
  return Uint8Array.from(Buffer.from(String(s || ""), "hex"));
}

function same(a, b) {
  log.debug("Entering same().");
  log.debug("Leaving same().");
  return Buffer.from(a).equals(Buffer.from(b));
}

function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString("base64url");
}

// ===========================================================================
// A. draft-ietf-hpke-pq-05
// ===========================================================================
function hpkePqVectors() {
  log.debug("Entering hpkePqVectors().");
  log.info("=== A. draft-ietf-hpke-pq-05's vectors ===");
  var vectors = loadVectors("hpke_pq_vectors.json");
  var suites = [];
  vectors.forEach(function (v) {
    var tag = "kem 0x" + v.kem_id.toString(16) + " kdf 0x" +
              v.kdf_id.toString(16) + " aead 0x" + v.aead_id.toString(16);
    assert.strictEqual(v.mode, 0, tag + ": only base-mode vectors are " +
                       "published here");
    var suite = { kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id };
    var kp = hpke.deriveKeyPair(v.kem_id, hex(v.ikmR));
    assert.ok(same(kp.sk, hex(v.skRm)), tag + ": DeriveKeyPair sk");
    assert.ok(same(kp.pk, hex(v.pkRm)), tag + ": DeriveKeyPair pk");
    var s = hpke.setupSender(suite, kp.pk, { info: hex(v.info),
                                             ikmE: hex(v.ikmE) });
    assert.ok(same(s.enc, hex(v.enc)), tag + ": Encap from ikmE");
    var r = hpke.setupReceiver(suite, hex(v.enc), kp.sk,
                               { info: hex(v.info) });
    assert.ok(same(r.sharedSecret, hex(v.shared_secret)),
              tag + ": shared_secret");
    assert.ok(same(s.context.sharedSecret, hex(v.shared_secret)),
              tag + ": the sender's shared_secret");
    assert.ok(same(r.key, hex(v.key)), tag + ": key");
    assert.ok(same(r.baseNonce, hex(v.base_nonce)), tag + ": base_nonce");
    assert.ok(same(r.exporterSecret, hex(v.exporter_secret)),
              tag + ": exporter_secret");
    v.encryptions.forEach(function (e, i) {
      assert.ok(same(s.context.seal(hex(e.aad), hex(e.pt)), hex(e.ct)),
                tag + ": Seal #" + i);
      assert.ok(same(r.open(hex(e.aad), hex(e.ct)), hex(e.pt)),
                tag + ": Open #" + i);
    });
    v.exports.forEach(function (x, i) {
      assert.ok(same(r.exportSecret(hex(x.exporter_context), x.L),
                     hex(x.exported_value)), tag + ": Export #" + i);
    });
    suites.push(tag);
  });
  log.info("OK — " + suites.length + " suites, every value: " +
           suites.join("; "));
  log.debug("Leaving hpkePqVectors().");
}

// ===========================================================================
// B. draft-irtf-cfrg-concrete-hybrid-kems
// ===========================================================================
function concreteHybridVectors() {
  log.debug("Entering concreteHybridVectors().");
  log.info("=== B. The concrete hybrid KEM vectors ===");
  var all = loadVectors("hybrid_kem_vectors.json");
  var names = { mlkem768_p256: "MLKEM768-P256",
                mlkem768_x25519: "MLKEM768-X25519",
                mlkem1024_p384: "MLKEM1024-P384" };
  Object.keys(names).forEach(function (k) {
    assert.ok(Array.isArray(all[k]) && all[k].length > 0,
              "the vector file has no " + k + " group");
    var h = hpke.HYBRIDS[names[k]];
    all[k].forEach(function (v, i) {
      var tag = names[k] + " #" + i;
      var x = hpke.cgExpand(h, hex(v.seed));
      assert.ok(same(x.ek, hex(v.encapsulation_key)), tag + ": ek");
      var e = hpke.cgEncaps(h, x.ek, hex(v.randomness));
      assert.ok(same(e.ct, hex(v.ciphertext)), tag + ": ciphertext");
      assert.ok(same(e.ss, hex(v.shared_secret)), tag + ": Encaps ss");
      assert.ok(same(hpke.cgDecaps(h, hex(v.seed), hex(v.ciphertext)),
                     hex(v.shared_secret)), tag + ": Decaps ss");
    });
    log.info("OK — " + names[k] + ": " + all[k].length + " vectors.");
  });
  log.debug("Leaving concreteHybridVectors().");
}

// ===========================================================================
// C. The JOSE working group's HPKE JWEs
// ===========================================================================
async function joseHpkeVectors() {
  log.debug("Entering joseHpkeVectors().");
  log.info("=== C. draft-ietf-jose-hpke-encrypt-22's JWEs ===");
  var vectors = loadVectors("jose_hpke_vectors.json");
  var removed = ["HPKE-4-KE", "HPKE-6-KE"];
  var opened = [];
  for (var i = 0; i < vectors.length; i++) {
    var v = vectors[i];
    if (removed.indexOf(v.alg) !== -1) {
      assert.strictEqual(kem.isKemAlg(v.alg), false, v.alg + " was " +
                         "removed by -22 and must not be offered");
      await assert.rejects(jose.decryptCompact({ jwe: v.compact,
                                                 key: v.jwk }),
                           /unsupported key management algorithm/,
                           v.alg + " must be refused");
      continue;
    }
    var r = await jose.decryptCompact({ jwe: v.compact, key: v.jwk });
    assert.ok(r.plaintext.length > 0, v.alg + ": no plaintext");
    // And back the other way, to the vector's own public key.
    var pub = Object.assign({}, v.jwk);
    delete pub.d;
    var again = await jose.encryptCompact({ alg: v.alg, enc: "A128GCM",
                                            plaintext: r.plaintext,
                                            key: pub });
    var back = await jose.decryptCompact({ jwe: again.jwe, key: v.jwk });
    assert.strictEqual(back.plaintext, r.plaintext, v.alg + ": re-encrypt");
    opened.push(v.alg);
  }
  assert.strictEqual(opened.length, vectors.length - removed.length);
  log.info("OK — opened and re-encrypted " + opened.length + " compact " +
           "JWEs (" + opened.join(", ") + "); " + removed.join(" and ") +
           " refused, as -22 removed them.");
  log.debug("Leaving joseHpkeVectors().");
}

// ===========================================================================
// D. pqc-kem-05's KMAC256 KDF, independently
// ===========================================================================
// Section 5.1, from the text: X = AlgorithmID || SuppPubInfo, AlgorithmID a
// 32-bit big-endian length and the ASCII name, SuppPubInfo the key length in
// BITS as 32-bit big-endian, PartyUInfo and PartyVInfo omitted, S empty, L
// in bits. Built with Buffer and handed to OpenSSL.
function opensslPqcKemKdf(ss, algorithmId, keyBytes) {
  log.debug("Entering opensslPqcKemKdf(). " + algorithmId);
  var id = Buffer.from(algorithmId, "ascii");
  var len = Buffer.alloc(4);
  len.writeUInt32BE(id.length);
  var bits = Buffer.alloc(4);
  bits.writeUInt32BE(keyBytes * 8);
  var x = Buffer.concat([len, id, bits]);
  var file = path.join(os.tmpdir(), "hpke-jwe-engine-" + process.pid + "-" +
                       Date.now() + ".bin");
  fs.writeFileSync(file, x);
  try {
    var out = execFileSync("openssl", ["mac", "-macopt",
      "hexkey:" + Buffer.from(ss).toString("hex"), "-macopt",
      "size:" + keyBytes, "-in", file, "KMAC256"], { encoding: "utf8" });
    log.debug("Leaving opensslPqcKemKdf().");
    return Buffer.from(out.trim(), "hex");
  } finally {
    fs.unlinkSync(file);
  }
}

async function pqcKemKdfIsTheDraftsText() {
  log.debug("Entering pqcKemKdfIsTheDraftsText().");
  log.info("=== D. pqc-kem-05's KMAC256 KDF, against OpenSSL ===");
  var cases = [["A128GCM", 16], ["A192GCM", 24], ["A256GCM", 32],
               ["A128CBC-HS256", 32], ["A192CBC-HS384", 48],
               ["A256CBC-HS512", 64], ["ML-KEM-512+A128KW", 16],
               ["ML-KEM-768+A192KW", 24], ["ML-KEM-1024+A256KW", 32]];
  cases.forEach(function (c) {
    var ss = nodeCrypto.randomBytes(32);
    assert.ok(same(kem.pqcKemKdf(ss, c[0], c[1]),
                   opensslPqcKemKdf(ss, c[0], c[1])),
              "the KMAC256 KDF disagrees with OpenSSL for " + c[0]);
  });
  log.info("OK — " + cases.length + " AlgorithmID/length pairs agree " +
           "with `openssl mac KMAC256`.");

  // A whole ML-KEM JWE, opened without jose_jwe.js.
  var opened = 0;
  var algs = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
  var encs = { A128GCM: 16, A256GCM: 32 };
  for (var i = 0; i < algs.length; i++) {
    for (var enc in encs) {
      if (!Object.prototype.hasOwnProperty.call(encs, enc)) continue;
      var kp = kem.generateKeyPair(algs[i]);
      var jwe = (await jose.encryptCompact({ alg: algs[i], enc: enc,
        plaintext: "independent " + algs[i], key: kp.publicJwk })).jwe;
      var parts = jwe.split(".");
      var header = JSON.parse(Buffer.from(parts[0], "base64url"));
      assert.strictEqual(parts[1], "", algs[i] + ": direct key agreement " +
                         "has an empty JWE Encrypted Key");
      var prim = { "ML-KEM-512": mlkem.ml_kem512,
                   "ML-KEM-768": mlkem.ml_kem768,
                   "ML-KEM-1024": mlkem.ml_kem1024 }[algs[i]];
      var seed = Buffer.from(kp.privateJwk.priv, "base64url");
      assert.strictEqual(seed.length, 64, "the AKP priv is the 64-byte seed");
      var ss = prim.decapsulate(Buffer.from(header.ek, "base64url"),
                                prim.keygen(seed).secretKey);
      var cek = opensslPqcKemKdf(ss, enc, encs[enc]);
      var d = nodeCrypto.createDecipheriv("aes-" + (encs[enc] * 8) + "-gcm",
                                          cek, Buffer.from(parts[2],
                                                           "base64url"));
      d.setAAD(Buffer.from(parts[0], "ascii"));
      d.setAuthTag(Buffer.from(parts[4], "base64url"));
      var pt = Buffer.concat([d.update(Buffer.from(parts[3], "base64url")),
                              d.final()]).toString("utf8");
      assert.strictEqual(pt, "independent " + algs[i]);
      opened++;
    }
  }
  log.info("OK — " + opened + " ML-KEM JWEs opened by noble's ML-KEM, " +
           "OpenSSL's KMAC256 and node's AES-GCM, with no jose_jwe.js.");
  log.debug("Leaving pqcKemKdfIsTheDraftsText().");
}

// ===========================================================================
// E. X-Wing, two ways
// ===========================================================================
function xwingTwoWays() {
  log.debug("Entering xwingTwoWays().");
  log.info("=== E. hpke.js's MLKEM768-X25519 against pqc.js's X-Wing ===");
  var xw = pqc.kemAlg("X-Wing");
  var h = hpke.HYBRIDS["MLKEM768-X25519"];
  for (var i = 0; i < 8; i++) {
    var seed = nodeCrypto.randomBytes(32);
    var kp = xw.keygen(seed);
    assert.ok(same(hpke.cgExpand(h, seed).ek, kp.publicKey),
              "X-Wing public keys differ");
    var e = xw.encapsulate(kp.publicKey);
    assert.ok(same(hpke.cgDecaps(h, seed, e.cipherText), e.sharedSecret),
              "hpke.js does not decapsulate pqc.js's X-Wing ciphertext");
    var f = hpke.cgEncaps(h, kp.publicKey);
    assert.ok(same(xw.decapsulate(f.ct, seed), f.ss),
              "pqc.js does not decapsulate hpke.js's X-Wing ciphertext");
  }
  log.info("OK — 8 key pairs, both directions.");
  log.debug("Leaving xwingTwoWays().");
}

// ===========================================================================
// F. Every alg, every enc, and the header each draft requires
// ===========================================================================
async function everyAlgEveryEnc() {
  log.debug("Entering everyAlgEveryEnc().");
  log.info("=== F. Every ML-KEM and HPKE alg against every enc ===");
  var algs = kem.algNames();
  assert.strictEqual(algs.length, 6 + 17 + 15, "6 ML-KEM algs, 17 " +
                     "Integrated HPKE algs and 15 Key Encryption ones");
  algs.forEach(function (a) {
    assert.ok(jose.supportedAlgs().indexOf(a) !== -1,
              "supportedAlgs() does not offer " + a);
  });
  var count = 0;
  for (var i = 0; i < algs.length; i++) {
    var alg = algs[i];
    var kp = jose.generateKemKeyPair(alg, "kid-" + alg);
    assert.strictEqual(kp.publicJwk.alg, alg);
    assert.strictEqual(kp.publicJwk.use, "enc");
    assert.ok(!kp.publicJwk.priv && !kp.publicJwk.d,
              alg + ": the public JWK carries private material");
    var encs = jose.isIntegrated(alg) ? ["A256GCM"] : jose.supportedEncs();
    for (var j = 0; j < encs.length; j++) {
      var text = "for " + alg + " / " + encs[j];
      var out = await jose.encryptCompact({ alg: alg, enc: encs[j],
                                            plaintext: text,
                                            key: kp.publicJwk,
                                            header: {
                                              kid: kp.publicJwk.kid } });
      var parts = out.jwe.split(".");
      var header = JSON.parse(Buffer.from(parts[0], "base64url"));
      if (jose.isIntegrated(alg)) {
        assert.strictEqual(header.enc, undefined, alg + ": Integrated " +
                           "Encryption writes no enc");
        assert.strictEqual(header.ek, undefined, alg + ": no ek");
        assert.strictEqual(parts[2], "", alg + ": empty IV");
        assert.strictEqual(parts[4], "", alg + ": empty tag");
        assert.ok(parts[1].length > 0, alg + ": the encapsulated secret");
      } else {
        assert.strictEqual(header.enc, encs[j]);
        assert.ok(typeof header.ek === "string" && header.ek.length > 0,
                  alg + ": the ek header");
        if (kem.isMlKemAlg(alg) && !kem.mlkemKwBytes(alg)) {
          assert.strictEqual(parts[1], "", alg + ": direct agreement has " +
                             "an empty JWE Encrypted Key");
        } else {
          assert.ok(parts[1].length > 0, alg + ": an encrypted key");
        }
      }
      var back = await jose.decryptCompact({ jwe: out.jwe,
                                             key: kp.privateJwk });
      assert.strictEqual(back.plaintext, text);
      count++;
    }
  }
  log.info("OK — " + count + " round trips over " + algs.length + " algs.");

  // PSK mode, both management modes, and the header that says so.
  var psk = nodeCrypto.randomBytes(32);
  var pskId = Buffer.from("psk-1", "utf8");
  var cases = ["HPKE-0", "HPKE-3-KE", "HPKE-5", "HPKE-7-KE"];
  for (var p = 0; p < cases.length; p++) {
    var pkp = kem.generateKeyPair(cases[p]);
    var sealed = await jose.encryptCompact({ alg: cases[p], enc: "A128GCM",
                                             plaintext: "psk", psk: psk,
                                             pskId: pskId,
                                             key: pkp.publicJwk });
    assert.strictEqual(sealed.header.psk_id, b64u(pskId),
                       cases[p] + ": psk_id is the base64url of the id");
    var opened = await jose.decryptCompact({ jwe: sealed.jwe,
                                             key: pkp.privateJwk, psk: psk });
    assert.strictEqual(opened.plaintext, "psk");
    await assert.rejects(jose.decryptCompact({ jwe: sealed.jwe,
                                               key: pkp.privateJwk }),
                         /pre-shared key is needed/, cases[p] +
                         ": a PSK JWE without the PSK");
    await assert.rejects(jose.decryptCompact({ jwe: sealed.jwe,
      key: pkp.privateJwk, psk: nodeCrypto.randomBytes(32) }), /OpenError/,
      cases[p] + ": the wrong PSK");
  }
  log.info("OK — PSK mode for " + cases.join(", ") + ".");
  log.debug("Leaving everyAlgEveryEnc().");
}

// ===========================================================================
// G. Refusals
// ===========================================================================
async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== G. Refusals ===");
  var kp = kem.generateKeyPair("ML-KEM-768");
  var other = Object.assign({}, kp.publicJwk, { alg: "ML-KEM-768+A192KW" });
  await assert.rejects(jose.encryptCompact({ alg: "ML-KEM-768",
    enc: "A128GCM", plaintext: "x", key: other }), /names exactly one/,
    "an AKP key for another alg");
  var short = Object.assign({}, kp.privateJwk,
    { priv: b64u(nodeCrypto.randomBytes(32)) });
  var jwe = (await jose.encryptCompact({ alg: "ML-KEM-768", enc: "A128GCM",
    plaintext: "x", key: kp.publicJwk })).jwe;
  await assert.rejects(jose.decryptCompact({ jwe: jwe, key: short }),
                       /64-byte d \|\| z/, "a 32-byte ML-KEM priv");
  var wrong = kem.generateKeyPair("ML-KEM-768");
  var opened = await jose.decryptCompact({ jwe: jwe, key: wrong.privateJwk })
    .then(function () {
      return true;
    }, function () {
      return false;
    });
  assert.strictEqual(opened, false, "the wrong ML-KEM key opened a JWE");
  await assert.rejects(jose.encryptCompact({ alg: "ML-KEM-768",
    enc: "A128GCM", plaintext: "x",
    key: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----" }),
    /as a JWK/, "a PEM for a KEM alg");

  var xw = kem.generateKeyPair("HPKE-10");
  var integrated = (await jose.encryptCompact({ alg: "HPKE-10",
    enc: "A256GCM", plaintext: "x", key: xw.publicJwk })).jwe;
  var p = integrated.split(".");
  var withEnc = Buffer.from(JSON.stringify({ alg: "HPKE-10",
    enc: "A256GCM" })).toString("base64url");
  await assert.rejects(jose.decryptCompact({ jwe: [withEnc].concat(
    p.slice(1)).join("."), key: xw.privateJwk }), /MUST NOT carry an "enc"/,
    "Integrated Encryption with an enc header");
  await assert.rejects(jose.decryptCompact({ jwe: [p[0], p[1], "AAAA", p[3],
    p[4]].join("."), key: xw.privateJwk }), /MUST be empty/,
    "Integrated Encryption with an IV");
  var tampered = Buffer.from(p[3], "base64url");
  tampered[0] ^= 1;
  await assert.rejects(jose.decryptCompact({ jwe: [p[0], p[1], p[2],
    tampered.toString("base64url"), p[4]].join("."), key: xw.privateJwk }),
    /OpenError/, "an altered Integrated ciphertext");
  var otherHeader = Buffer.from(JSON.stringify({ alg: "HPKE-10",
    kid: "x" })).toString("base64url");
  await assert.rejects(jose.decryptCompact({ jwe: [otherHeader].concat(
    p.slice(1)).join("."), key: xw.privateJwk }), /OpenError/,
    "a protected header changed after sealing (it is the HPKE aad)");
  await assert.rejects(jose.encryptCompact({ alg: "HPKE-10-KE",
    enc: "A128GCM", plaintext: "x", key: xw.publicJwk }), /names exactly/,
    "an HPKE-10 key for HPKE-10-KE");
  var xwKe = kem.generateKeyPair("HPKE-10-KE");
  await assert.rejects(jose.encryptCompact({ alg: "HPKE-10-KE",
    enc: "A128GCM", plaintext: "x", key: xwKe.publicJwk,
    psk: nodeCrypto.randomBytes(32), pskId: Buffer.from("id") }),
    /only HPKE's base mode/, "a PSK with a PQ/T hybrid");

  var ec = kem.generateKeyPair("HPKE-1");
  await assert.rejects(jose.encryptCompact({ alg: "HPKE-0",
    enc: "A128GCM", plaintext: "x", key: ec.publicJwk }), /P-256 key/,
    "a P-384 key for HPKE-0");
  var ke = (await jose.encryptCompact({ alg: "HPKE-0-KE", enc: "A128GCM",
    plaintext: "x", key: kem.generateKeyPair("HPKE-0-KE").publicJwk })).jwe;
  var kp2 = ke.split(".");
  var hdr = JSON.parse(Buffer.from(kp2[0], "base64url"));
  delete hdr.ek;
  await assert.rejects(jose.decryptCompact({ jwe: [Buffer.from(
    JSON.stringify(hdr)).toString("base64url")].concat(kp2.slice(1))
    .join("."), key: kem.generateKeyPair("HPKE-0-KE").privateJwk }),
    /"ek" header/, "Key Encryption without ek");
  log.info("OK — every refusal names its reason.");
  log.debug("Leaving refusals().");
}

// The engines reach no DOM and no Web Crypto: both are synchronous and both
// run on a plain-HTTP origin.
function enginesAreSelfContained() {
  log.debug("Entering enginesAreSelfContained().");
  ["hpke.js", "jwe_kem.js"].forEach(function (f) {
    var text = fs.readFileSync(path.join(SRC, f), "utf8");
    assert.ok(!/\bdocument\.|\bwindow\.|crypto\.subtle/.test(text),
              f + " reaches the DOM or Web Crypto");
  });
  log.info("OK — hpke.js and jwe_kem.js touch no DOM and no Web Crypto.");
  log.debug("Leaving enginesAreSelfContained().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  hpkePqVectors();
  concreteHybridVectors();
  await joseHpkeVectors();
  await pqcKemKdfIsTheDraftsText();
  xwingTwoWays();
  await everyAlgEveryEnc();
  await refusals();
  enginesAreSelfContained();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
