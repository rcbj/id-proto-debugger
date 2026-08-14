// File: krb5_crypto_vectors.js
//
// common/krb5/krb5_primitives.js and krb5_crypto.js — the RFC 3961 encryption
// framework and every encryption type this debugger performs.
//
// ---------------------------------------------------------------------------
// Why this test is the most important one in the Kerberos workflow.
//
// Every failure mode of this code produces the SAME symptom: one opaque
// integrity error, at the far end, with no indication of which layer was wrong.
// A wrong n-fold, a wrong key usage number, a MAC over the ciphertext where the
// specification says plaintext, a confounder of the wrong length, a CTS block
// swap omitted for the exact-multiple case — all of them yield a perfectly
// well-formed message that a KDC rejects with KRB_AP_ERR_BAD_INTEGRITY, which
// is also what it says for a wrong password.
//
// So the oracle cannot be this codec's own mock KDC. Two implementations written
// from the same misreading agree with each other perfectly, and the disagreement
// only surfaces against a real domain controller, weeks later, as a bug that
// looks like a configuration problem. The oracle has to be values written down
// by the people who defined the algorithms:
//
//   * RFC 1320 appendix A       MD4 (the NT hash under etype 23)
//   * RFC 1321 appendix A       MD5 (under etype 23's HMAC)
//   * RFC 2202                  HMAC-MD5
//   * RFC 3961 appendix A.1     n-fold, at five different output sizes
//   * RFC 3962 appendix B       AES string-to-key, and CBC ciphertext stealing
//   * RFC 8009 appendix A       the SHA-2 KDF, string-to-key, and encryption
//
// Each layer is tested SEPARATELY as well as end to end, because an end-to-end
// encryption that round-trips proves only that this file agrees with itself: two
// compensating errors (a wrong Ke together with a wrong Ki) round-trip happily.
//
// The negative half matters as much. An implementation that never refuses
// anything is not an implementation of an authentication protocol, and "it
// decrypted" is not the same claim as "it rejected what it should".
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_crypto_vectors",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the modules are under common/krb5/; the tests image copies them
// flat next to the test scripts (see tests/Dockerfile). They are named
// krb5_*.js rather than asn1.js / crypto.js precisely because of that flat
// copy: a file called crypto.js landing beside the tests is an accident waiting
// to happen.
//
// **This test is called krb5_crypto_VECTORS.js for the same reason**, following
// tests/jwk_pem_encoding.js: the module it exercises is krb5_crypto.js, and two
// files of that name copied flat into one directory means whichever COPY ran
// last wins. The test would then be loading itself, and the failure would be
// silent.
var prim = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_primitives.js", __dirname + "/krb5_primitives.js"],
  "krb5_primitives.js");
var kcrypto = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_crypto.js", __dirname + "/krb5_crypto.js"],
  "krb5_crypto.js");

// The module reaches Web Crypto through globalThis rather than require("crypto"),
// which is what keeps `elliptic` out of the browser bundles. Assert it rather
// than discover a TypeError six functions deep.
assert.strictEqual(typeof globalThis.crypto.subtle, "object", "this node has no Web Crypto");

const hex = (b) => prim.toHex(b);
const unhex = (s) => prim.fromHex(s);
const ascii = (s) => prim.utf8(s);

function eq(label, got, want) {
  const g = typeof got === "string" ? got : hex(got);
  const w = String(want).replace(/[\s]/g, "").toLowerCase();
  assert.strictEqual(g, w, label + "\n  got  " + g + "\n  want " + w);
  log.debug("ok: " + label);
}

// ---------------------------------------------------------------------------
// The hash and cipher primitives Web Crypto does not have.
//
// These are not incidental: MD4 IS the string-to-key for etype 23 (the NT hash),
// so an MD4 that is wrong in the last round produces a key that is wrong for
// every RC4 exchange and right for nothing.
// ---------------------------------------------------------------------------
function primitivesMatchTheirOwnRfcs() {
  log.debug("Entering primitivesMatchTheirOwnRfcs().");

  // RFC 1320 appendix A.5
  eq("MD4(\"\")", prim.md4(ascii("")), "31d6cfe0d16ae931b73c59d7e0c089c0");
  eq("MD4(\"a\")", prim.md4(ascii("a")), "bde52cb31de33e46245e05fbdbd6fb24");
  eq("MD4(\"abc\")", prim.md4(ascii("abc")), "a448017aaf21d8525fc10ae87aa6729d");
  eq("MD4(\"message digest\")", prim.md4(ascii("message digest")), "d9130a8164549fe818874806e1c7014b");
  eq("MD4(a..z)", prim.md4(ascii("abcdefghijklmnopqrstuvwxyz")), "d79e1c308aa5bbcdeea8ed63df412da9");
  eq("MD4(alnum)", prim.md4(ascii("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
     "043f8582f241db351ce627e153e7f0e4");
  // Multi-block, which is where a wrong padding length shows up.
  eq("MD4(80 digits)", prim.md4(ascii("1234567890".repeat(8))), "e33b4ddc9c38f2199c3e7b164fcc0536");

  // RFC 1321 appendix A.5
  eq("MD5(\"\")", prim.md5(ascii("")), "d41d8cd98f00b204e9800998ecf8427e");
  eq("MD5(\"abc\")", prim.md5(ascii("abc")), "900150983cd24fb0d6963f7d28e17f72");
  eq("MD5(alnum)", prim.md5(ascii("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
     "d174ab98d277d9f5a5611c2c9f419d9f");

  // RFC 2202 sections 2 and 3 — the second case has a key SHORTER than the
  // block size, which is where a missing zero-pad shows up.
  eq("HMAC-MD5 case 1", prim.hmacMd5(new Uint8Array(16).fill(0x0b), ascii("Hi There")),
     "9294727a3638bb1c13f48ef8158bfc9d");
  eq("HMAC-MD5 case 2", prim.hmacMd5(ascii("Jefe"), ascii("what do ya want for nothing?")),
     "750c783e6ab0b503eaa86e310a5db738");

  eq("RC4(\"Key\")", prim.rc4(ascii("Key"), ascii("Plaintext")), "bbf316e8d940af0ad3");
  eq("RC4(\"Wiki\")", prim.rc4(ascii("Wiki"), ascii("pedia")), "1021bf0420");
  eq("RC4(\"Secret\")", prim.rc4(ascii("Secret"), ascii("Attack at dawn")), "45a01f645fc35b383552544b9bf5");

  // The NT hash of a known password: MD4 over UTF-16LE. This is the value every
  // Windows administrator has seen, and it is etype 23's whole string-to-key.
  eq("NT hash of \"password\"", prim.md4(prim.utf16le("password")), "8846f7eaee8fb117ad06bdd830b7586c");

  log.debug("Leaving primitivesMatchTheirOwnRfcs().");
}

// ---------------------------------------------------------------------------
// n-fold, RFC 3961 appendix A.1.
//
// Five output sizes and inputs shorter, equal to and longer than the output,
// because the replication-and-rotate arithmetic differs in each case. The
// "kerberos" folds are the ones the AES string-to-key depends on directly.
// ---------------------------------------------------------------------------
function nfoldMatchesRfc3961() {
  log.debug("Entering nfoldMatchesRfc3961().");
  eq("64-fold(\"012345\")", prim.nfold(ascii("012345"), 64), "be072631276b1955");
  eq("56-fold(\"password\")", prim.nfold(ascii("password"), 56), "78a07b6caf85fa");
  eq("64-fold(\"Rough Consensus…\")", prim.nfold(ascii("Rough Consensus, and Running Code"), 64),
     "bb6ed30870b7f0e0");
  eq("168-fold(\"password\")", prim.nfold(ascii("password"), 168),
     "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
  eq("192-fold(\"MASSACHVSETTS…\")", prim.nfold(ascii("MASSACHVSETTS INSTITVTE OF TECHNOLOGY"), 192),
     "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b");
  // A one-byte input folded to 21 bytes: the pathological replication case.
  eq("168-fold(\"Q\")", prim.nfold(ascii("Q"), 168), "518a54a215a8452a518a54a215a8452a518a54a215");
  eq("168-fold(\"ba\")", prim.nfold(ascii("ba"), 168), "fb25d531ae8974499f52fd92ea9857c4ba24cf297e");
  eq("64-fold(\"kerberos\")", prim.nfold(ascii("kerberos"), 64), "6b65726265726f73");
  eq("128-fold(\"kerberos\")", prim.nfold(ascii("kerberos"), 128), "6b65726265726f737b9b5b2b93132b93");
  eq("168-fold(\"kerberos\")", prim.nfold(ascii("kerberos"), 168),
     "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4");
  eq("256-fold(\"kerberos\")", prim.nfold(ascii("kerberos"), 256),
     "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4");
  log.debug("Leaving nfoldMatchesRfc3961().");
}

// ---------------------------------------------------------------------------
// CBC with ciphertext stealing, RFC 3962 appendix B.
//
// The two cases that catch a wrong implementation are both here:
//
//  * 17 bytes — one full block plus one byte. The output is the SECOND
//    ciphertext block followed by one byte of the FIRST. An implementation that
//    does not swap produces the right length and the wrong bytes.
//  * 32 bytes — an exact multiple of the block size, which still swaps. Reading
//    "ciphertext stealing" as "only needed when there is a partial block" gives
//    plain CBC here, and plain CBC is wrong.
//
// The 16-byte case is the other boundary: one block does NOT swap.
// ---------------------------------------------------------------------------
async function ctsMatchesRfc3962() {
  log.debug("Entering ctsMatchesRfc3962().");
  const key = ascii("chicken teriyaki");
  const iv = new Uint8Array(16);
  const input = ascii("I would like the General Gau's Chicken, please, and wonton soup.");

  // Transcribed by extracting the hex dumps from the RFC's own text rather than
  // by hand. The first attempt at this table was retyped and carried a
  // one-nibble error in the 32-byte case, which the implementation then
  // correctly failed — an hour spent suspecting the CTS code for a typo in its
  // oracle. If these ever need revisiting, re-extract; do not retype.
  const cases = [
    [17, "c6353568f2bf8cb4d8a580362da7ff7f97"],
    [31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"],
    [32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"],
    [47, "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e" +
         "39312523a78662d5be7fcbcc98ebf5"],
    [48, "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd8" +
         "39312523a78662d5be7fcbcc98ebf5a8"],
    [64, "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8" +
         "4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"]
  ];

  for (const [len, expected] of cases) {
    const pt = input.slice(0, len);
    const ct = await kcrypto.ctsEncrypt(key, iv, pt);
    eq("CTS encrypt " + len + " bytes", ct, expected);
    assert.strictEqual(ct.length, len, "CTS must not change the length (" + len + ")");
    // Decrypt is a separate code path — it has to recover the truncated block
    // rather than produce it — so it is checked rather than assumed.
    const back = await kcrypto.ctsDecrypt(key, iv, ct);
    eq("CTS decrypt " + len + " bytes", back, hex(pt));
  }
  log.debug("Leaving ctsMatchesRfc3962().");
}

// ---------------------------------------------------------------------------
// AES string-to-key, RFC 3962 appendix B — all seven published cases, at both
// key sizes.
//
// The last case is the one worth having: the pass phrase is a single non-BMP
// character (U+1D11E, the g-clef, as the four UTF-8 bytes f0 9d 84 9e). It is
// there to catch an implementation that encodes a surrogate pair as two
// three-byte sequences (CESU-8) instead of one four-byte one — which produces a
// different key and no other symptom.
// ---------------------------------------------------------------------------
async function stringToKeyMatchesRfc3962() {
  log.debug("Entering stringToKeyMatchesRfc3962().");
  const aes128 = kcrypto.etypeById(17);
  const aes256 = kcrypto.etypeById(18);
  const iterParam = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

  const cases = [
    { iter: 1, pass: "password", salt: ascii("ATHENA.MIT.EDUraeburn"),
      k128: "42263c6e89f4fc28b8df68ee09799f15",
      k256: "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161" },
    { iter: 2, pass: "password", salt: ascii("ATHENA.MIT.EDUraeburn"),
      k128: "c651bf29e2300ac27fa469d693bdda13",
      k256: "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff" },
    { iter: 1200, pass: "password", salt: ascii("ATHENA.MIT.EDUraeburn"),
      k128: "4c01cd46d632d01e6dbe230a01ed642a",
      k256: "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a" },
    // A salt that is not text at all.
    { iter: 5, pass: "password", salt: unhex("1234567878563412"),
      k128: "e9b23d52273747dd5c35cb55be619d8e",
      k256: "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31" },
    // Pass phrase exactly the HMAC block size, then one byte over: the two
      // cases either side of the key-shortening boundary in HMAC.
    { iter: 1200, pass: "X".repeat(64), salt: ascii("pass phrase equals block size"),
      k128: "59d1bb789a828b1aa54ef9c2883f69ed",
      k256: "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34" },
    { iter: 1200, pass: "X".repeat(65), salt: ascii("pass phrase exceeds block size"),
      k128: "cb8005dc5f90179a7f02104c0018751d",
      k256: "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b" },
    // The g-clef: one code point outside the BMP.
    { iter: 50, pass: "\u{1D11E}", salt: ascii("EXAMPLE.COMpianist"),
      k128: "f149c1f2e154a73452d43e7fe62a56e5",
      k256: "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e" }
  ];

  for (const c of cases) {
    const label = "s2k iter=" + c.iter + " pass=" + JSON.stringify(c.pass).slice(0, 18);
    eq(label + " aes128", await aes128.stringToKey(c.pass, c.salt, iterParam(c.iter)), c.k128);
    eq(label + " aes256", await aes256.stringToKey(c.pass, c.salt, iterParam(c.iter)), c.k256);
  }

  // The g-clef case again, but proving the encoding rather than the key: if
  // utf8() emitted CESU-8 the byte string below would be six bytes.
  eq("UTF-8 of U+1D11E", prim.utf8("\u{1D11E}"), "f09d849e");

  log.debug("Leaving stringToKeyMatchesRfc3962().");
}

// ---------------------------------------------------------------------------
// RFC 8009: the SHA-2 KDF, string-to-key, and encryption.
//
// The single most valuable assertion in this function is the aes256 Ke/Kc/Ki
// triple. For aes256-cts-hmac-sha384-192 the RFC derives Ke at 256 bits but Kc
// and Ki at 192, and nothing except these published values catches an
// implementation that uses one length for all three — it produces keys that are
// correct for encryption and wrong for integrity, which is an integrity error
// with a working cipher underneath it.
// ---------------------------------------------------------------------------
async function rfc8009MatchesItsVectors() {
  log.debug("Entering rfc8009MatchesItsVectors().");
  const aes128 = kcrypto.etypeById(19);
  const aes256 = kcrypto.etypeById(20);

  // --- key derivation, key usage 2 ---
  const base128 = unhex("3705D96080C17728A0E800EAB6E0D23C");
  eq("aes128-sha256 Kc usage 2", await aes128.checksumKey(base128, 2), "b31a018a48f54776f403e9a396325dc3");
  eq("aes128-sha256 Ke usage 2", await aes128.encryptionKey(base128, 2), "9b197dd1e8c5609d6e67c3e37c62c72e");
  eq("aes128-sha256 Ki usage 2", await aes128.integrityKey(base128, 2), "9fda0e56ab2d85e1569a688696c26a6c");

  const base256 = unhex("6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52");
  eq("aes256-sha384 Kc usage 2", await aes256.checksumKey(base256, 2),
     "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d");
  eq("aes256-sha384 Ke usage 2 (256 bits, not 192)", await aes256.encryptionKey(base256, 2),
     "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49");
  eq("aes256-sha384 Ki usage 2", await aes256.integrityKey(base256, 2),
     "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f");

  // --- string-to-key. The RFC's saltp embeds sixteen random bytes between the
  // enctype name and the realm-and-principal salt, so the salt passed here is
  // those bytes followed by "ATHENA.MIT.EDUraeburn"; the module prepends the
  // enctype name and the NUL itself, which is the part being tested.
  const salt8009 = prim.concat([unhex("10DF9DD783E5BC8ACEA1730E74355F61"), ascii("ATHENA.MIT.EDUraeburn")]);
  const iter32768 = new Uint8Array([0x00, 0x00, 0x80, 0x00]);
  eq("aes128-sha256 s2k", await aes128.stringToKey("password", salt8009, iter32768),
     "089bca48b105ea6ea77ca5d2f39dc5e7");
  eq("aes256-sha384 s2k", await aes256.stringToKey("password", salt8009, iter32768),
     "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467");

  // --- sample encryptions, key usage 2, with the RFC's own confounders. The
  // four plaintext lengths are chosen by the RFC to cross every CTS boundary:
  // empty (one block total), shorter than a block, exactly a block, longer.
  const enc128 = [
    { pt: "", conf: "7E5895EAF2672435BAD817F545A37148",
      ct: "EF85FB890BB8472F4DAB20394DCA781D" + "AD877EDA39D50C870C0D5A0A8E48C718" },
    { pt: "000102030405", conf: "7BCA285E2FD4130FB55B1A5C83BC5B24",
      ct: "84D7F30754ED987BAB0BF3506BEB09CFB55402CEF7E6" + "877CE99E247E52D16ED4421DFDF8976C" },
    { pt: "000102030405060708090A0B0C0D0E0F", conf: "56AB21713FF62C0A1457200F6FA9948F",
      ct: "3517D640F50DDC8AD3628722B3569D2AE07493FA8263254080EA65C1008E8FC2" +
          "95FB4852E7D83E1E7C48C37EEBE6B0D3" },
    { pt: "000102030405060708090A0B0C0D0E0F1011121314", conf: "A7A4E29A4728CE10664FB64E49AD3FAC",
      ct: "720F73B18D9859CD6CCB4346115CD336C70F58EDC0C4437C5573544C31C813BCE1E6D072C1" +
          "86B39A413C2F92CA9B8334A287FFCBFC" }
  ];
  for (let i = 0; i < enc128.length; i++) {
    const c = enc128[i];
    const out = await aes128.encrypt(base128, 2, unhex(c.pt), unhex(c.conf));
    eq("aes128-sha256 encrypt case " + (i + 1) + " (" + (c.pt.length / 2) + "-byte plaintext)", out, c.ct);
    // And back, through the verifying path.
    eq("aes128-sha256 decrypt case " + (i + 1), await aes128.decrypt(base128, 2, unhex(c.ct)), c.pt.toLowerCase());
  }

  log.debug("Leaving rfc8009MatchesItsVectors().");
}

// ---------------------------------------------------------------------------
// The AES-SHA1 etypes (17 and 18) — the ones Active Directory actually uses.
//
// RFC 3962 publishes string-to-key vectors (above) but NO full sample
// encryption, and that absence is a real hole rather than a footnote. It was
// measured: applying the classic spec misreading — MAC the ciphertext instead of
// the plaintext — to BOTH encrypt and decrypt leaves every round-trip in this
// function passing, because the two sides agree with each other. An
// implementation wrong in exactly that way interoperates with nothing and no
// round-trip test can see it.
//
// So the MAC input is pinned white-box, against the normative text rather than
// against a published ciphertext. RFC 3961 section 5.3's simplified profile
// states the encryption function as:
//
//      H1 = HMAC(Ki, conf | plaintext | pad)
//
// — the PLAINTEXT, confounder included, not the ciphertext. (RFC 8009 is the
// other way round, MACing IV | C, which is why the two profiles are separate
// objects in the module.) The assertion below recomputes that HMAC from the
// module's own Ki and the recovered plaintext and requires it to equal the
// trailing bytes of the ciphertext, which the mutation above fails.
//
// This is still not proof of interoperability — that arrives with the MIT krb5
// and Samba AD exchanges in phase 4 — but it is no longer merely self-consistent.
// ---------------------------------------------------------------------------
async function aesSha1RoundTripsAtEveryBoundary() {
  log.debug("Entering aesSha1RoundTripsAtEveryBoundary().");
  for (const id of [17, 18]) {
    const e = kcrypto.etypeById(id);
    const key = await e.stringToKey("hunter2", ascii("EXAMPLE.COMalice"), null);
    assert.strictEqual(key.length, e.keyBytes, e.name + " key length");

    // 0 crosses no boundary; 1 and 15 make a partial second block; 16 makes the
    // total an exact multiple; 17 and 100 go past it.
    for (const len of [0, 1, 15, 16, 17, 100]) {
      const pt = new Uint8Array(len).map((_, i) => (i * 31) & 255);
      const ct = await e.encrypt(key, kcrypto.KEY_USAGE.AS_REP_ENCPART, pt);
      // Confounder plus plaintext plus a 12-byte MAC, and CTS does not pad.
      assert.strictEqual(ct.length, 16 + len + 12,
        e.name + " ciphertext length for " + len + " bytes of plaintext");
      const back = await e.decrypt(key, kcrypto.KEY_USAGE.AS_REP_ENCPART, ct);
      eq(e.name + " round trip " + len + " bytes", back, hex(pt));

      // The MAC covers conf | plaintext (RFC 3961 section 5.3), NOT the
      // ciphertext. Recomputed here from the module's own integrity key and the
      // recovered plaintext, because a round trip cannot tell the two apart.
      const ki = await e.integrityKey(key, kcrypto.KEY_USAGE.AS_REP_ENCPART);
      const confAndPlain = await kcrypto.ctsDecrypt(
        await e.encryptionKey(key, kcrypto.KEY_USAGE.AS_REP_ENCPART),
        new Uint8Array(16), ct.slice(0, ct.length - e.checksumBytes));
      const expectedMac = (await kcrypto.hmac("SHA-1", ki, confAndPlain)).slice(0, e.checksumBytes);
      eq(e.name + " MAC covers conf|plaintext, " + len + " bytes",
         ct.slice(ct.length - e.checksumBytes), hex(expectedMac));
    }

    // Two different usages must produce different encryption keys, or the usage
    // number is not being folded in at all — which round-trips perfectly and
    // interoperates with nothing.
    const k1 = hex(await e.encryptionKey(key, 2));
    const k2 = hex(await e.encryptionKey(key, 3));
    const c1 = hex(await e.checksumKey(key, 2));
    assert.notStrictEqual(k1, k2, e.name + " usage 2 and 3 derived the SAME encryption key");
    assert.notStrictEqual(k1, c1, e.name + " Ke and Kc are the same key");
    log.debug(e.name + ": Ke(2)=" + k1.slice(0, 16) + "… Ke(3)=" + k2.slice(0, 16) + "…");
  }
  log.debug("Leaving aesSha1RoundTripsAtEveryBoundary().");
}

// ---------------------------------------------------------------------------
// etype 23, arcfour-hmac-md5.
//
// Its two peculiarities are asserted directly because both are load-bearing and
// neither resembles the AES etypes:
//
//  * the string-to-key ignores the salt entirely (it is the NT hash), which is
//    why AD's salt discovery matters only for AES; and
//  * three key usage numbers are TRANSLATED before use (3 and 9 both become 8,
//    23 becomes 13). Skip that and the AS-REP enc-part decrypts to nothing.
// ---------------------------------------------------------------------------
async function arcfourBehavesLikeRfc4757() {
  log.debug("Entering arcfourBehavesLikeRfc4757().");
  const e = kcrypto.etypeById(23);
  assert.strictEqual(e.legacy, true, "etype 23 must be marked legacy");

  eq("arcfour s2k is the NT hash", await e.stringToKey("password"), "8846f7eaee8fb117ad06bdd830b7586c");
  // Salted and unsalted must agree, because the salt is not an input.
  const withSalt = hex(await e.stringToKey("password", ascii("EXAMPLE.COMbob"), null));
  eq("arcfour s2k ignores the salt", withSalt, "8846f7eaee8fb117ad06bdd830b7586c");

  assert.strictEqual(kcrypto.translateArcfourUsage(3), 8, "usage 3 must translate to 8");
  assert.strictEqual(kcrypto.translateArcfourUsage(9), 8, "usage 9 must translate to 8");
  assert.strictEqual(kcrypto.translateArcfourUsage(23), 13, "usage 23 must translate to 13");
  assert.strictEqual(kcrypto.translateArcfourUsage(11), 11, "usage 11 must pass through");

  const key = await e.stringToKey("password");
  for (const len of [0, 1, 16, 63]) {
    const pt = new Uint8Array(len).map((_, i) => (i * 17) & 255);
    const ct = await e.encrypt(key, kcrypto.KEY_USAGE.AP_REQ_AUTH, pt);
    // A 16-byte checksum, an 8-byte confounder, and a stream cipher: no padding.
    assert.strictEqual(ct.length, 16 + 8 + len, "arcfour ciphertext length for " + len);
    eq("arcfour round trip " + len + " bytes",
       await e.decrypt(key, kcrypto.KEY_USAGE.AP_REQ_AUTH, ct), hex(pt));
  }

  // Usages 3 and 9 translate to the same number, so — uniquely — they must
  // produce interchangeable ciphertext. This is the assertion that proves the
  // translation is actually applied rather than merely present.
  const ct3 = await e.encrypt(key, 3, ascii("same"), unhex("0011223344556677"));
  const ct9 = await e.encrypt(key, 9, ascii("same"), unhex("0011223344556677"));
  eq("arcfour usage 3 and 9 are the same key stream", ct3, hex(ct9));
  eq("arcfour cross-usage decrypt (3 encrypted, 9 decrypts)", await e.decrypt(key, 9, ct3), hex(ascii("same")));

  log.debug("Leaving arcfourBehavesLikeRfc4757().");
}

// ---------------------------------------------------------------------------
// Checksums.
// ---------------------------------------------------------------------------
async function checksumsAreKeyedAndVerified() {
  log.debug("Entering checksumsAreKeyedAndVerified().");
  for (const id of [17, 18, 19, 20, 23]) {
    const e = kcrypto.etypeById(id);
    const key = await e.stringToKey("hunter2", ascii("EXAMPLE.COMalice"), null);
    const msg = ascii("the quick brown fox");
    const c = await e.checksum(key, kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, msg);
    assert.strictEqual(c.length, e.checksumBytes, e.name + " checksum length");
    assert.strictEqual(await e.verifyChecksum(key, kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, msg, c), true,
      e.name + " must verify its own checksum");
    // A different usage must not verify: the usage is part of the key.
    assert.strictEqual(await e.verifyChecksum(key, kcrypto.KEY_USAGE.AP_REP_ENCPART, msg, c), false,
      e.name + " verified a checksum computed under a DIFFERENT key usage");
    // One flipped bit in the message must not verify.
    const tampered = ascii("the quick brown foy");
    assert.strictEqual(await e.verifyChecksum(key, kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, tampered, c), false,
      e.name + " verified a checksum over a MODIFIED message");
  }
  log.debug("Leaving checksumsAreKeyedAndVerified().");
}

// ---------------------------------------------------------------------------
// The negative half.
//
// Every case here is something a real deployment produces, and an
// implementation that accepts any of them is not doing authentication:
// the wrong password, a downgraded etype, a truncated reply, a flipped bit in a
// ticket, a ciphertext replayed under a different key usage.
// ---------------------------------------------------------------------------
async function refusesWhatItMustRefuse() {
  log.debug("Entering refusesWhatItMustRefuse().");

  async function mustThrow(what, fn, matching) {
    let threw = null;
    try {
      await fn();
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, "expected a refusal: " + what);
    if (matching) {
      assert.ok(matching.test(threw.message),
        what + ": refused, but the message does not say why (" + threw.message + ")");
    }
    log.debug("refused as it should: " + what + " (" + threw.message + ")");
  }

  for (const id of [17, 18, 19, 20, 23]) {
    const e = kcrypto.etypeById(id);
    const key = await e.stringToKey("correct horse", ascii("EXAMPLE.COMalice"), null);
    const wrongKey = await e.stringToKey("correct horsf", ascii("EXAMPLE.COMalice"), null);
    const usage = kcrypto.KEY_USAGE.AS_REP_ENCPART;
    const ct = await e.encrypt(key, usage, ascii("the session key goes here"));

    await mustThrow(e.name + ": wrong key", () => e.decrypt(wrongKey, usage, ct), /integrity check failed/);
    await mustThrow(e.name + ": wrong key usage", () => e.decrypt(key, usage + 1, ct), /integrity check failed/);

    // A flipped bit in the ciphertext body.
    const bitFlipped = ct.slice();
    bitFlipped[4] ^= 0x01;
    await mustThrow(e.name + ": one flipped ciphertext bit", () => e.decrypt(key, usage, bitFlipped),
      /integrity check failed/);

    // A flipped bit in the MAC itself.
    const macFlipped = ct.slice();
    macFlipped[macFlipped.length - 1] ^= 0x80;
    await mustThrow(e.name + ": one flipped MAC bit", () => e.decrypt(key, usage, macFlipped),
      /integrity check failed/);

    // Truncated: a short read on a KDC reply must not be mistaken for a short
    // message.
    await mustThrow(e.name + ": truncated ciphertext", () => e.decrypt(key, usage, ct.slice(0, 8)),
      /too short/);
    await mustThrow(e.name + ": empty ciphertext", () => e.decrypt(key, usage, new Uint8Array(0)),
      /too short/);
  }

  // DES is decode-only and must be refused by name rather than by a generic
  // "unknown etype", because a KDC offering it is a finding in itself.
  await mustThrow("etype 3 (des-cbc-md5) refused by name", async () => kcrypto.etypeById(3),
    /des-cbc-md5.*not implemented|not implemented.*des-cbc-md5/);
  await mustThrow("etype 1 mentions the Windows removal", async () => kcrypto.etypeById(1),
    /Windows Server 2025/);
  await mustThrow("an unknown etype", async () => kcrypto.etypeById(9999), /unknown/);
  assert.strictEqual(kcrypto.etypeName(3), "des-cbc-md5", "a refused etype must still have a NAME to display");
  assert.strictEqual(kcrypto.etypeName(4242), "etype-4242", "an unknown etype must render as something");

  // CTS cannot operate on less than a block; the confounder guarantees this
  // never happens in the protocol, so a caller hitting it has a bug and should
  // hear about it rather than get silence.
  await mustThrow("CTS on 15 bytes", () => kcrypto.ctsEncrypt(new Uint8Array(16), new Uint8Array(16),
    new Uint8Array(15)), /at least one block/);

  // A KDC that asks for 2^32 PBKDF2 iterations is either broken or hostile; RFC
  // 3962 encodes that as an all-zero s2kparams. Attempting it would hang the
  // browser for hours, which is a denial of service delivered by a reply.
  await mustThrow("s2kparams of 2^32 iterations", () => kcrypto.etypeById(18)
    .stringToKey("password", ascii("EXAMPLE.COMalice"), new Uint8Array([0, 0, 0, 0])), /2\^32/);

  log.debug("Leaving refusesWhatItMustRefuse().");
}

// ---------------------------------------------------------------------------
// The key usage table itself.
//
// These numbers are protocol constants: getting one wrong is a wire
// incompatibility, not a local bug, so the ones this codec depends on are
// pinned against RFC 4120 section 7.5.1 rather than left to whatever the
// implementation happens to pass.
// ---------------------------------------------------------------------------
function keyUsageNumbersArePinned() {
  log.debug("Entering keyUsageNumbersArePinned().");
  const U = kcrypto.KEY_USAGE;
  const expected = {
    AS_REQ_PA_ENC_TIMESTAMP: 1, KDC_REP_TICKET: 2, AS_REP_ENCPART: 3,
    TGS_REQ_AUTH_CKSUM: 6, TGS_REQ_AUTH: 7,
    TGS_REP_ENCPART_SESSKEY: 8, TGS_REP_ENCPART_SUBKEY: 9,
    AP_REQ_AUTH_CKSUM: 10, AP_REQ_AUTH: 11, AP_REP_ENCPART: 12,
    KRB_CRED_ENCPART: 14, PA_FOR_USER_CKSUM: 17,
    GSS_ACCEPTOR_SEAL: 22, GSS_ACCEPTOR_SIGN: 23,
    GSS_INITIATOR_SEAL: 24, GSS_INITIATOR_SIGN: 25
  };
  Object.keys(expected).forEach(function (name) {
    assert.strictEqual(U[name], expected[name],
      "key usage " + name + " must be " + expected[name] + " (RFC 4120 section 7.5.1)");
  });

  // The derivation constant is the usage as four big-endian octets and then the
  // purpose byte. A little-endian mistake here is invisible for usage 0 and
  // wrong for every other one.
  eq("usage constant for 2 / 0xAA", kcrypto.usageConstant(2, 0xaa), "00000002aa");
  eq("usage constant for 258 / 0x55", kcrypto.usageConstant(258, 0x55), "0000010255");

  // The default preference must lead with an AES etype and must not lead with
  // the legacy one — the order is what a KDC picks from.
  const pref = kcrypto.DEFAULT_ETYPE_PREFERENCE;
  assert.ok(pref.length >= 2, "there must be a preference order to offer");
  assert.strictEqual(kcrypto.etypeById(pref[0]).legacy, false,
    "the FIRST etype offered must not be the legacy one");
  assert.strictEqual(pref[pref.length - 1], 23, "arcfour-hmac-md5 must be offered last if at all");
  log.debug("Leaving keyUsageNumbersArePinned().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying common/krb5 crypto against RFC 1320, 1321, 2202, 3961, 3962, 8009.");
  primitivesMatchTheirOwnRfcs();
  nfoldMatchesRfc3961();
  await ctsMatchesRfc3962();
  await stringToKeyMatchesRfc3962();
  await rfc8009MatchesItsVectors();
  await aesSha1RoundTripsAtEveryBoundary();
  await arcfourBehavesLikeRfc4757();
  await checksumsAreKeyedAndVerified();
  await refusesWhatItMustRefuse();
  keyUsageNumbersArePinned();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_crypto_vectors")
  .description("Verify the Kerberos v5 encryption framework against the RFCs' own published vectors.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
