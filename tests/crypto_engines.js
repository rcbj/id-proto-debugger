// File: crypto_engines.js
//
// ---------------------------------------------------------------------------
// The Encryption / Decryption page's cryptography, driven in NODE with no
// browser — because the modules it is built on have no DOM.
//
// This is the half of that page's testing that a Selenium job cannot do well.
// tests/encryption_tools.js drives the page: it presses the buttons, reads the
// status lines, and proves the wiring. What it CANNOT do is tell you that the
// bytes are right, because everything it checks it checks against this same
// code — encrypt then decrypt agrees with itself whatever the implementation
// does, and the class of defect that matters most here is exactly the one that
// is self-consistent and interoperates with nothing.
//
// So this job asserts against things that are NOT this code:
//
//   * RFC 8439's own vectors for ChaCha20, Poly1305 and the AEAD.
//   * RFC 4493's vectors for AES-CMAC.
//   * The SipHash-2-4 reference vectors.
//   * NIST SP 800-38A's vectors for AES-CBC, CTR, CFB, OFB and ECB.
//   * RFC 3526's primes, checked for primality and safe-primality rather than
//     trusted as transcribed — a mistyped digit gives a group that still
//     "works" between two copies of this code and is not the standard one.
//   * node's own crypto for AES-GCM, 3DES and DES, which is OpenSSL: a second
//     implementation of the same ciphers, present on every machine that runs
//     this suite.
//
// and then, separately, the properties that no vector can express: that a
// modified ciphertext is refused, that a changed AAD is refused, that two
// encryptions of one message differ, and that an ECIES context string actually
// separates contexts.
//
// It also asserts the DIVISION ITSELF — that no module under test reaches for
// a DOM — since the whole reason this job can exist is that the cryptography
// was kept out of the page bundle, and that is a property a later edit can
// quietly take away.
// ---------------------------------------------------------------------------

// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it has
// not been told about. This job parses no arguments at all — it drives modules
// in process and has no base url to visit — so node ignores the pair and there
// is nothing to declare. Do not add commander here without also declaring
// `--url`; see tests/CLAUDE.md.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'crypto_engines',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The modules under test live next to this script in the tests image and in
// client/src in a checkout — see the note in tests/module_paths.js, and the
// tests/Dockerfile COPY that puts them here.
const paths = require("./module_paths.js");
const SRC = path.resolve(__dirname, "..", "client", "src");

function shared(name) {
  log.debug("Entering shared(). name=" + name);
  const found = paths.requireSharedModule(
    [path.join(__dirname, name), path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving shared().");
  return found;
}

const bytes = shared("crypto_bytes.js");
const symmetric = shared("symmetric_crypto.js");
const pk = shared("pk_encryption.js");

function hex(value) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return bytes.bytesToHex(value);
}

// ---------------------------------------------------------------------------
// 1. crypto_bytes.js — the conversions three modules now share.
// ---------------------------------------------------------------------------
function checkByteHelpers() {
  log.debug("Entering checkByteHelpers().");
  const sample = bytes.strBytes("hello ✓ world");
  assert.strictEqual(bytes.bytesToStr(bytes.b64ToBytes(
    bytes.bytesToB64(sample))), "hello ✓ world");
  assert.strictEqual(bytes.bytesToStr(bytes.b64uToBytes(
    bytes.bytesToB64u(sample))), "hello ✓ world");
  assert.strictEqual(bytes.bytesToStr(bytes.hexToBytes(
    bytes.bytesToHex(sample))), "hello ✓ world");

  // base64url is base64 with two characters swapped and no padding. A value
  // containing both is what says so — this is the difference that goes
  // unnoticed until somebody else's parser sees it.
  const awkward = bytes.hexToBytes("fbff00");
  assert.strictEqual(bytes.bytesToB64(awkward), "+/8A");
  assert.strictEqual(bytes.bytesToB64u(awkward), "-_8A");

  // A textarea wraps what it holds, and atob throws on a newline rather than
  // ignoring it. Every one of these is read out of a textarea.
  assert.strictEqual(hex(bytes.b64ToBytes("aGVs\n bG8=")), "68656c6c6f");
  assert.strictEqual(hex(bytes.hexToBytes("de ad\nbe ef")), "deadbeef");

  // Refusing bad hex rather than reading it as zero is the one behavioural
  // change the Digital Signature page's refactor made, and it is asserted
  // because the old behaviour was to encrypt under a key that was not the one
  // on the screen.
  assert.throws(function () { bytes.hexToBytes("zz"); },
                /not hexadecimal/i);
  assert.throws(function () { bytes.hexToBytes("abc"); },
                /odd number/i);

  // PEM framing round-trips and reports its label — INCLUDING a label with a
  // hyphen in it, which is the case that broke.
  //
  // The obvious strip regex is `-----[^-]+-----`, and it reads
  // `-----BEGIN PRIVATE KEY-----` and stops dead at
  // `-----BEGIN SLH-DSA PRIVATE KEY-----`, because the character class cannot
  // cross the hyphen in the algorithm's name. The header then survives into
  // atob, which throws `Invalid character` — a complaint about base64 from a
  // function handed a perfectly good PEM. It took out every SLH-DSA and ML-DSA
  // operation on the Digital Signature page the moment jose_jwe.js's version
  // of this function (which had only ever seen `PRIVATE KEY`) became the
  // shared one, and it reported "signature was not produced" on a page whose
  // signing was fine.
  ["TEST KEY", "PRIVATE KEY", "PUBLIC KEY", "RSA PRIVATE KEY",
   "SLH-DSA PRIVATE KEY", "ML-DSA-65 PRIVATE KEY", "ML-KEM-KEYS PUBLIC KEY",
   "CERTIFICATE"].forEach(function (label) {
    const framed = bytes.derToPem(sample, label);
    assert.strictEqual(bytes.pemLabel(framed), label,
      "pemLabel() misread the label " + label);
    assert.strictEqual(hex(bytes.pemToDer(framed)), hex(sample),
      "a PEM labelled " + label + " did not survive the round trip. A label " +
      "containing a hyphen is the case a `[^-]+` strip regex cannot handle.");
    assert.ok(framed.split("\n").every(function (line) {
      return line.length <= 64 || line.indexOf("-----") === 0;
    }), "PEM body lines must wrap at 64 characters");
  });
  // ONE BLOCK. pemToDer() strips the framing and decodes what is left, so a
  // file holding TWO blocks — which is what a raw-key download writes — is not
  // something to hand it: base64 padding is only valid at the end, so two
  // padded bodies concatenated are not one base64 string and atob refuses
  // them. Every caller in this tree passes a single block; a caller with a
  // two-block file splits it on the BEGIN lines first. Asserted so the
  // boundary is written down rather than discovered.
  const twoBlocks = bytes.derToPem(bytes.hexToBytes("aabb"),
                                   "SLH-DSA PUBLIC KEY") +
                    bytes.derToPem(bytes.hexToBytes("ccdd"),
                                   "SLH-DSA PRIVATE KEY");
  assert.throws(function () { bytes.pemToDer(twoBlocks); },
    /Invalid character/,
    "pemToDer() is a single-block reader and this test records that. If it " +
    "has grown multi-block support, assert the new behaviour here.");
  assert.strictEqual(bytes.pemLabel(twoBlocks), "SLH-DSA PUBLIC KEY",
    "pemLabel() reports the FIRST block's label");

  assert.strictEqual(bytes.bytesEqual(sample, sample), true);
  assert.strictEqual(bytes.bytesEqual(sample, bytes.strBytes("x")), false);
  assert.strictEqual(hex(bytes.bigToBytes(BigInt(258), 4)), "00000102");
  assert.throws(function () { bytes.bigToBytes(BigInt(65536), 2); },
                /does not fit/);
  log.info("[bytes] OK — base64/base64url/hex round-trip, PEM survives a " +
           "hyphenated label, whitespace is tolerated, and bad hex is " +
           "refused rather than read as zero.");
  log.debug("Leaving checkByteHelpers().");
}

// ---------------------------------------------------------------------------
// 2. RFC 8439 — ChaCha20, Poly1305, and the AEAD.
//
// The AEAD tag is the assertion that matters most in this file. Encrypt-then-
// decrypt agrees with itself no matter what the MAC covers, so a construction
// that forgot the AAD padding or the two length counters passes every
// round-trip test ever written and interoperates with nothing. Only the RFC's
// own tag catches it.
// ---------------------------------------------------------------------------
const RFC8439_PLAINTEXT =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one " +
  "tip for the future, sunscreen would be it.";

function checkChaCha20() {
  log.debug("Entering checkChaCha20().");
  const key = bytes.hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const nonce = bytes.hexToBytes("000000000000004a00000000");
  const out = symmetric.chacha20(key, nonce,
                                 bytes.strBytes(RFC8439_PLAINTEXT), 1);
  assert.strictEqual(hex(out),
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
    "5af90bbf74a35be6b40b8eedf2785e42874d",
    "RFC 8439 section 2.4.2 — the ChaCha20 keystream is wrong");

  // Poly1305, RFC 8439 section 2.5.2.
  const polyKey = bytes.hexToBytes(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  assert.strictEqual(
    hex(symmetric.poly1305(polyKey,
        bytes.strBytes("Cryptographic Forum Research Group"))),
    "a8061dc1305136c6c22b8baf0c0127a9",
    "RFC 8439 section 2.5.2 — the Poly1305 tag is wrong");

  // The AEAD, RFC 8439 section 2.8.2.
  const aeadKey = bytes.hexToBytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const aeadNonce = bytes.hexToBytes("070000004041424344454647");
  const aad = bytes.hexToBytes("50515253c0c1c2c3c4c5c6c7");
  const sealed = symmetric.chacha20Poly1305Encrypt(
    aeadKey, aeadNonce, bytes.strBytes(RFC8439_PLAINTEXT), aad);
  assert.strictEqual(hex(sealed.ciphertext).slice(0, 32),
    "d31a8d34648e60db7b86afbc53ef7ec2",
    "RFC 8439 section 2.8.2 — the AEAD ciphertext is wrong");
  assert.strictEqual(hex(sealed.tag), "1ae10b594f09e26a7e902ecbd0600691",
    "RFC 8439 section 2.8.2 — the AEAD tag is wrong. This is the check that " +
    "catches a MAC input built without the AAD padding or the two length " +
    "counters, which round-trips against itself perfectly.");
  assert.strictEqual(
    bytes.bytesToStr(symmetric.chacha20Poly1305Decrypt(
      aeadKey, aeadNonce, sealed.ciphertext, aad, sealed.tag)),
    RFC8439_PLAINTEXT);
  log.info("[rfc8439] OK — ChaCha20, Poly1305 and the AEAD match the RFC's " +
           "own vectors, tag included.");
  log.debug("Leaving checkChaCha20().");
}

// ---------------------------------------------------------------------------
// 3. RFC 4493 (AES-CMAC) and the SipHash-2-4 reference vectors.
//
// These two are on the DIGITAL SIGNATURE page's MAC panes, and they are
// asserted here because they moved into symmetric_crypto.js when
// ChaCha20-Poly1305 needed the Poly1305 beside them. A move is exactly when a
// vector earns its keep.
// ---------------------------------------------------------------------------
function checkBlockCipherMacs() {
  log.debug("Entering checkBlockCipherMacs().");
  const key = bytes.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
  const vectors = [
    ["", "bb1d6929e95937287fa37d129b756746"],
    ["6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"],
    ["6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
     "30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"],
    ["6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
     "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
     "51f0bebf7e3b9d92fc49741779363cfe"]
  ];
  vectors.forEach(function (pair) {
    assert.strictEqual(hex(symmetric.aesCmac(key,
        bytes.hexToBytes(pair[0]))), pair[1],
      "RFC 4493 — AES-CMAC over a " + (pair[0].length / 2) +
      "-byte message is wrong");
  });

  // SipHash-2-4, the reference implementation's vectors for key
  // 000102…0f over messages 00, 0001, 000102, …
  const sipKey = bytes.hexToBytes("000102030405060708090a0b0c0d0e0f");
  const sipVectors = ["310e0edd47db6f72", "fd67dc93c539f874",
                      "5a4fa9d909806c0d", "2d7efbd796666785",
                      "b7877127e09427cf", "8da699cd64557618"];
  sipVectors.forEach(function (want, length) {
    const message = new Uint8Array(length);
    for (var i = 0; i < length; i++) message[i] = i;
    assert.strictEqual(hex(symmetric.siphash24(sipKey, message)), want,
      "SipHash-2-4 over a " + length + "-byte message is wrong. Note the " +
      "tail is the last (len % 8) bytes with the length in the top byte — " +
      "which is what makes the short messages the interesting ones.");
  });
  log.info("[macs] OK — AES-CMAC matches RFC 4493 and SipHash-2-4 matches " +
           "the reference vectors at every tail length.");
  log.debug("Leaving checkBlockCipherMacs().");
}

// ---------------------------------------------------------------------------
// 4. NIST SP 800-38A — the AES modes, against the standard's own vectors.
//
// One block of each, which is enough: what these catch is a mode wired to the
// wrong primitive or an IV used as a counter, and that is wrong on the first
// block or never.
// ---------------------------------------------------------------------------
const SP800_38A_KEY =
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const SP800_38A_IV = "000102030405060708090a0b0c0d0e0f";
const SP800_38A_BLOCK = "6bc1bee22e409f96e93d7e117393172a";

function checkAesModes() {
  log.debug("Entering checkAesModes().");
  // Each entry: [cipher id, iv, expected first ciphertext block]. The values
  // are SP 800-38A's F.1.5 (ECB), F.2.5 (CBC), F.3.13 (CFB128), F.4.5 (OFB)
  // and F.5.5 (CTR) for AES-256.
  const cases = [
    ['AES-256-ECB', '', 'f3eed1bdb5d2a03c064b5a7e3db181f8'],
    ['AES-256-CBC', SP800_38A_IV, 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'],
    ['AES-256-CFB', SP800_38A_IV, 'dc7e84bfda79164b7ecd8486985d3860'],
    ['AES-256-OFB', SP800_38A_IV, 'dc7e84bfda79164b7ecd8486985d3860'],
    ['AES-256-CTR', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
     '601ec313775789a5b7a7f504bbf3d228']
  ];
  cases.forEach(function (one) {
    const out = symmetric.encrypt({
      id: one[0],
      key: bytes.hexToBytes(SP800_38A_KEY),
      iv: bytes.hexToBytes(one[1]),
      plaintext: bytes.hexToBytes(SP800_38A_BLOCK)
    });
    assert.strictEqual(hex(out.ciphertext).slice(0, 32), one[2],
      "NIST SP 800-38A — " + one[0] + " produced the wrong first block");
  });
  log.info("[sp800-38a] OK — ECB, CBC, CFB, OFB and CTR match the " +
           "standard's AES-256 vectors.");
  log.debug("Leaving checkAesModes().");
}

// ---------------------------------------------------------------------------
// 5. A SECOND IMPLEMENTATION: node's own crypto, which is OpenSSL.
//
// Everything above is a vector; this is a live cross-check, and it covers the
// ciphers whose published vectors are least convenient — GCM at three key
// sizes, 3DES in both keying options, and single DES. Ours encrypts, OpenSSL
// decrypts, and then the other way round: one direction alone would miss a
// padding convention that is wrong symmetrically.
// ---------------------------------------------------------------------------
const OPENSSL_NAMES = {
  'AES-128-GCM': 'aes-128-gcm',
  'AES-192-GCM': 'aes-192-gcm',
  'AES-256-GCM': 'aes-256-gcm',
  'AES-128-CBC': 'aes-128-cbc',
  'AES-192-CBC': 'aes-192-cbc',
  'AES-256-CBC': 'aes-256-cbc',
  'AES-256-CTR': 'aes-256-ctr',
  'AES-256-OFB': 'aes-256-ofb',
  'AES-256-ECB': 'aes-256-ecb',
  '3DES-192-CBC': 'des-ede3-cbc',
  '3DES-192-ECB': 'des-ede3',
  'DES-CBC': 'des-cbc',
  'DES-ECB': 'des-ecb',
  'CHACHA20-POLY1305': 'chacha20-poly1305'
};

function opensslDecrypt(id, key, iv, ciphertext, tag, aad) {
  log.debug("Entering opensslDecrypt(). id=" + id);
  const spec = symmetric.cipher(id);
  const name = OPENSSL_NAMES[id];
  const decipher = spec.ivBytes
    ? crypto.createDecipheriv(name, Buffer.from(key), Buffer.from(iv))
    : crypto.createDecipheriv(name, Buffer.from(key), null);
  if (spec.aead) {
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(tag));
  }
  if (!spec.padded) {
    decipher.setAutoPadding(false);
  }
  const out = Buffer.concat([decipher.update(Buffer.from(ciphertext)),
                             decipher.final()]);
  log.debug("Leaving opensslDecrypt().");
  return new Uint8Array(out);
}

function opensslEncrypt(id, key, iv, plaintext, aad) {
  log.debug("Entering opensslEncrypt(). id=" + id);
  const spec = symmetric.cipher(id);
  const name = OPENSSL_NAMES[id];
  const cipher = spec.ivBytes
    ? crypto.createCipheriv(name, Buffer.from(key), Buffer.from(iv))
    : crypto.createCipheriv(name, Buffer.from(key), null);
  if (spec.aead) {
    cipher.setAAD(Buffer.from(aad));
  }
  if (!spec.padded) {
    cipher.setAutoPadding(false);
  }
  const out = Buffer.concat([cipher.update(Buffer.from(plaintext)),
                             cipher.final()]);
  log.debug("Leaving opensslEncrypt().");
  return { ciphertext: new Uint8Array(out),
           tag: spec.aead ? new Uint8Array(cipher.getAuthTag())
                          : new Uint8Array(0) };
}

// Whether this node's OpenSSL will provide a cipher at all. OpenSSL 3 moved
// single DES into the legacy provider, which is not loaded by default, so
// `des-cbc` answers `digital envelope routines::unsupported` on every modern
// node. That is a fact about the checking tool rather than about the code
// under test, so those two are skipped HERE and covered by a published vector
// in checkDesVectors() instead — a skip that silently checked nothing would be
// the worst of both.
function opensslProvides(id) {
  log.debug("Entering opensslProvides(). id=" + id);
  const spec = symmetric.cipher(id);
  try {
    const probe = spec.ivBytes
      ? crypto.createCipheriv(OPENSSL_NAMES[id],
          Buffer.alloc(symmetric.expandDesKey(spec,
            new Uint8Array(spec.keyBytes)).length),
          Buffer.alloc(spec.ivBytes))
      : crypto.createCipheriv(OPENSSL_NAMES[id],
          Buffer.alloc(symmetric.expandDesKey(spec,
            new Uint8Array(spec.keyBytes)).length), null);
    probe.final();
    log.debug("Leaving opensslProvides(). Yes.");
    return true;
  } catch (e) {
    log.debug("Leaving opensslProvides(). No: " + e.message);
    return false;
  }
}

// The cross-check must not be allowed to quietly shrink to nothing. These are
// the ciphers it MUST have covered for the job to mean anything; if one of
// them starts being skipped, that is a finding rather than a smaller run.
const OPENSSL_REQUIRED = ['AES-128-GCM', 'AES-192-GCM', 'AES-256-GCM',
                          'AES-256-CBC', 'AES-256-CTR', 'AES-256-OFB',
                          'AES-256-ECB', '3DES-192-CBC', '3DES-192-ECB',
                          'CHACHA20-POLY1305'];

function checkAgainstOpenssl() {
  log.debug("Entering checkAgainstOpenssl().");
  const message = bytes.strBytes(
    "Sixty-four bytes exactly, so every block boundary is crossed twice..");
  var checked = 0;
  const covered = [], skipped = [];
  Object.keys(OPENSSL_NAMES).forEach(function (id) {
    const spec = symmetric.cipher(id);
    if (!opensslProvides(id)) {
      skipped.push(id);
      return;
    }
    // Two-key 3DES has no distinct OpenSSL name — it IS des-ede3 with a
    // repeated subkey, which expandDesKey() is what asserts below.
    const key = symmetric.generateKey(id);
    const iv = symmetric.generateIv(id);
    const aad = spec.aead ? bytes.strBytes("cross-checked") : new Uint8Array(0);

    // Ours out, OpenSSL in.
    const ours = symmetric.encrypt({ id: id, key: key, iv: iv, aad: aad,
                                     plaintext: message });
    assert.strictEqual(
      hex(opensslDecrypt(id, key, iv, ours.ciphertext, ours.tag, aad)),
      hex(message),
      "OpenSSL could not decrypt what " + id + " produced");

    // OpenSSL out, ours in.
    const theirs = opensslEncrypt(id, key, iv, message, aad);
    assert.strictEqual(hex(theirs.ciphertext), hex(ours.ciphertext),
      id + " and OpenSSL produced different ciphertext for the same key, " +
      "IV and message");
    assert.strictEqual(
      hex(symmetric.decrypt({ id: id, key: key, iv: iv, aad: aad,
                              ciphertext: theirs.ciphertext,
                              tag: theirs.tag })),
      hex(message),
      id + " could not decrypt what OpenSSL produced");
    checked++;
    covered.push(id);
  });
  if (skipped.length) {
    log.info("[openssl] SKIPPED (this node's OpenSSL " +
             process.versions.openssl + " does not provide them; covered by " +
             "published vectors instead): " + skipped.join(", "));
  }
  OPENSSL_REQUIRED.forEach(function (id) {
    assert.ok(covered.indexOf(id) >= 0,
      id + " was not cross-checked against OpenSSL. It is on the required " +
      "list, so this is a finding rather than a smaller run — either the " +
      "cipher was removed from the catalogue or this node stopped " +
      "providing it.");
  });

  // Two-key 3DES: the same algorithm with K3 = K1, which is what lets a
  // 16-byte legacy key be used at all. OpenSSL is asked for the three-key
  // cipher with the expanded key, which is the claim being made.
  const twoKey = symmetric.generateKey('3DES-128-CBC');
  const iv = symmetric.generateIv('3DES-128-CBC');
  const ours = symmetric.encrypt({ id: '3DES-128-CBC', key: twoKey, iv: iv,
                                   plaintext: message });
  const expanded = symmetric.expandDesKey(symmetric.cipher('3DES-128-CBC'),
                                          twoKey);
  assert.strictEqual(hex(expanded), hex(twoKey) + hex(twoKey.slice(0, 8)),
    "Two-key 3DES must expand to K1 K2 K1");
  assert.strictEqual(
    hex(opensslDecrypt('3DES-192-CBC', expanded, iv, ours.ciphertext,
                       null, null)),
    hex(message),
    "OpenSSL could not decrypt two-key 3DES as des-ede3-cbc with the " +
    "expanded key — which is what two-key 3DES IS");
  checked++;
  log.info("[openssl] OK — " + checked + " ciphers agree byte-for-byte with " +
           "node's OpenSSL in both directions.");
  log.debug("Leaving checkAgainstOpenssl().");
}

// ---------------------------------------------------------------------------
// 5b. Single DES, against a published vector rather than OpenSSL.
//
// OpenSSL 3 will not do single DES without the legacy provider, so the cross
// check above skips it — and a cipher covered by nothing at all would be
// exactly the "test that quietly does nothing" this suite keeps finding. The
// canonical FIPS 81 vector covers it instead, and 3DES with all three subkeys
// equal must produce the same block, which is what says the EDE wiring is the
// right way round.
// ---------------------------------------------------------------------------
function checkDesVectors() {
  log.debug("Entering checkDesVectors().");
  const key = bytes.hexToBytes("133457799BBCDFF1");
  const block = bytes.hexToBytes("0123456789ABCDEF");
  const single = symmetric.encrypt({ id: 'DES-ECB', key: key,
                                     iv: new Uint8Array(0),
                                     plaintext: block });
  assert.strictEqual(hex(single.ciphertext).slice(0, 16), "85e813540f0ab405",
    "the canonical single-DES vector is wrong");
  // 3DES with K1 = K2 = K3 is single DES by construction (encrypt, decrypt
  // with the same key, encrypt). If this differs, the middle operation is
  // running the wrong way.
  const triple = symmetric.encrypt({
    id: '3DES-192-ECB',
    key: bytes.concatBytes(key, key, key),
    iv: new Uint8Array(0),
    plaintext: block
  });
  assert.strictEqual(hex(triple.ciphertext).slice(0, 16),
                     hex(single.ciphertext).slice(0, 16),
    "3DES with three identical subkeys must equal single DES — it does not, " +
    "so the E-D-E ordering is wrong");
  // And the round trip, since nothing else exercises single DES end to end.
  const text = bytes.strBytes("legacy interop");
  const iv = symmetric.generateIv('DES-CBC');
  const sealed = symmetric.encrypt({ id: 'DES-CBC', key: key, iv: iv,
                                     plaintext: text });
  assert.strictEqual(hex(symmetric.decrypt({ id: 'DES-CBC', key: key, iv: iv,
    ciphertext: sealed.ciphertext, tag: new Uint8Array(0) })), hex(text));
  log.info("[des] OK — the FIPS 81 vector, 3DES(K,K,K) == DES, and a " +
           "DES-CBC round trip. OpenSSL 3 cannot check these itself.");
  log.debug("Leaving checkDesVectors().");
}

// ---------------------------------------------------------------------------
// 6. The properties no vector expresses.
// ---------------------------------------------------------------------------
function checkRefusals() {
  log.debug("Entering checkRefusals().");
  const message = bytes.strBytes("refuse me");
  symmetric.cipherIds().forEach(function (id) {
    const spec = symmetric.cipher(id);
    if (!spec.aead) {
      return;
    }
    const key = symmetric.generateKey(id), iv = symmetric.generateIv(id);
    const aad = bytes.strBytes("bound");
    const out = symmetric.encrypt({ id: id, key: key, iv: iv, aad: aad,
                                    plaintext: message });
    // A flipped bit in the ciphertext.
    const flipped = out.ciphertext.slice();
    flipped[0] ^= 0x01;
    assert.throws(function () {
      symmetric.decrypt({ id: id, key: key, iv: iv, aad: aad,
                          ciphertext: flipped, tag: out.tag });
    }, /did not verify/i, id + " accepted a modified ciphertext");
    // A changed AAD — the half that is authenticated and not encrypted, and
    // the one a round-trip test never exercises because it never changes it.
    assert.throws(function () {
      symmetric.decrypt({ id: id, key: key, iv: iv,
                          aad: bytes.strBytes("other"),
                          ciphertext: out.ciphertext, tag: out.tag });
    }, /did not verify/i, id + " accepted changed additional authenticated " +
       "data, which means the AAD is not covered by the tag at all");
    // A truncated tag.
    assert.throws(function () {
      symmetric.decrypt({ id: id, key: key, iv: iv, aad: aad,
                          ciphertext: out.ciphertext,
                          tag: out.tag.slice(0, 8) });
    }, /16-byte tag/, id + " accepted a truncated tag");
  });

  // Key and IV lengths are named, with the field and the number, before forge
  // is reached — a range error from inside a buffer names neither.
  assert.throws(function () {
    symmetric.encrypt({ id: 'AES-256-GCM', key: new Uint8Array(16),
                        iv: new Uint8Array(12),
                        plaintext: new Uint8Array(1) });
  }, /needs a 32-byte key/);
  assert.throws(function () {
    symmetric.encrypt({ id: 'AES-256-GCM', key: new Uint8Array(32),
                        iv: new Uint8Array(16),
                        plaintext: new Uint8Array(1) });
  }, /needs a 12-byte nonce/);
  assert.throws(function () {
    symmetric.encrypt({ id: 'AES-256-ECB', key: new Uint8Array(32),
                        iv: new Uint8Array(16),
                        plaintext: new Uint8Array(1) });
  }, /takes no IV/);
  assert.throws(function () {
    symmetric.encrypt({ id: 'AES-256-CBC', key: new Uint8Array(32),
                        iv: new Uint8Array(16), aad: bytes.strBytes("x"),
                        plaintext: new Uint8Array(1) });
  }, /nowhere to put/, "an unauthenticated cipher must refuse AAD rather " +
     "than accept it and silently drop it, which would look like it was " +
     "protected");

  // ECB is the pane's own demonstration: identical plaintext blocks must
  // produce identical ciphertext blocks. If this ever stops being true the
  // page is no longer showing what it claims to show.
  const ecbKey = symmetric.generateKey('AES-256-ECB');
  const repeated = symmetric.encrypt({
    id: 'AES-256-ECB', key: ecbKey, iv: new Uint8Array(0),
    plaintext: bytes.hexToBytes(SP800_38A_BLOCK + SP800_38A_BLOCK)
  });
  assert.strictEqual(hex(repeated.ciphertext).slice(0, 32),
                     hex(repeated.ciphertext).slice(32, 64),
    "ECB must map identical plaintext blocks to identical ciphertext blocks " +
    "— that is the property the pane exists to show");
  log.info("[refusals] OK — every AEAD refuses a flipped bit, a changed AAD " +
           "and a truncated tag; lengths are named; ECB still leaks " +
           "structure.");
  log.debug("Leaving checkRefusals().");
}

// ---------------------------------------------------------------------------
// 7. RFC 3526's groups, checked rather than trusted.
//
// A mistyped digit in a 617-digit prime gives a group in which ElGamal and
// DHIES both still work — between two copies of this code. Nothing downstream
// notices, and the value is no longer the standard group anybody else uses.
// ---------------------------------------------------------------------------
function checkModpGroups() {
  log.debug("Entering checkModpGroups().");
  pk.ffcGroupIds().forEach(function (id) {
    const group = pk.ffcGroup(id);
    const p = BigInt('0x' + pk.FFC_GROUPS[id].p);
    const expectedBits = id === 'modp-2048' ? 2048 : 3072;
    assert.strictEqual(p.toString(2).length, expectedBits,
      id + " is not " + expectedBits + " bits");
    // RFC 3526's groups are safe primes: p and (p-1)/2 are both prime.
    assert.ok(isProbablePrime(p), id + "'s p is not prime");
    assert.ok(isProbablePrime((p - BigInt(1)) / BigInt(2)),
      id + " is not a SAFE prime — (p-1)/2 is composite, so the group has " +
      "small subgroups an attacker can confine a shared secret to");
    // Every RFC 3526 group begins and ends with the same 64 bits.
    assert.ok(/^FFFFFFFFFFFFFFFFC90FDAA2/.test(pk.FFC_GROUPS[id].p),
      id + " does not start with RFC 3526's fixed prefix");
    assert.ok(/FFFFFFFFFFFFFFFF$/.test(pk.FFC_GROUPS[id].p),
      id + " does not end with RFC 3526's fixed suffix");
    assert.strictEqual(group.g.toString(10), '2');
  });
  log.info("[modp] OK — both RFC 3526 groups are safe primes of the right " +
           "size, with the standard's own prefix and suffix.");
  log.debug("Leaving checkModpGroups().");
}

// Miller-Rabin, deterministic enough for this purpose with fixed bases. It is
// written out rather than taken from a library on purpose: the point is to
// check the transcription with something that is not the transcription.
function isProbablePrime(n) {
  log.debug("Entering isProbablePrime().");
  const one = BigInt(1), two = BigInt(2);
  if (n < two) {
    log.debug("Leaving isProbablePrime(). Below two.");
    return false;
  }
  var d = n - one, r = 0;
  while (d % two === BigInt(0)) {
    d /= two;
    r++;
  }
  const bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
  for (const base of bases) {
    var x = modPow(BigInt(base), d, n);
    if (x === one || x === n - one) {
      continue;
    }
    var witness = true;
    for (var i = 0; i < r - 1; i++) {
      x = (x * x) % n;
      if (x === n - one) {
        witness = false;
        break;
      }
    }
    if (witness) {
      log.debug("Leaving isProbablePrime(). Composite.");
      return false;
    }
  }
  log.debug("Leaving isProbablePrime(). Probably prime.");
  return true;
}

function modPow(base, exponent, modulus) {
  log.debug("Entering modPow().");
  var result = BigInt(1), b = base % modulus, e = exponent;
  while (e > BigInt(0)) {
    if (e % BigInt(2) === BigInt(1)) {
      result = (result * b) % modulus;
    }
    e /= BigInt(2);
    b = (b * b) % modulus;
  }
  log.debug("Leaving modPow().");
  return result;
}

// ---------------------------------------------------------------------------
// 8. The public-key mechanisms.
// ---------------------------------------------------------------------------
const PK_MESSAGE = "Attack at dawn. ✓ Trailing spaces survive:   ";

function checkRsa() {
  log.debug("Entering checkRsa().");
  const pair = pk.rsaGenerateKeyPair(2048);
  ['oaep', 'v1_5'].forEach(function (padding) {
    const hashes = padding === 'oaep'
      ? ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] : ['SHA-256'];
    hashes.forEach(function (hash) {
      const max = pk.rsaMaxDirectBytes({ publicPem: pair.publicPem,
                                         padding: padding, hash: hash });
      // The published formulae: k - 2*hLen - 2 for OAEP, k - 11 for v1.5.
      const expected = padding === 'oaep'
        ? 256 - 2 * ({ 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48,
                       'SHA-512': 64 })[hash] - 2
        : 256 - 11;
      assert.strictEqual(max, expected,
        "PKCS#1's own size formula disagrees for " + padding + "/" + hash);

      // Exactly at the limit works; one over is refused by name.
      const atLimit = new Uint8Array(max);
      atLimit.fill(0x41);
      const sealed = pk.rsaEncrypt({ publicPem: pair.publicPem,
                                     padding: padding, hash: hash,
                                     plaintext: atLimit });
      assert.strictEqual(sealed.ciphertext.length, 256,
        "an RSA ciphertext is one modulus wide whatever the message length");
      assert.strictEqual(
        hex(pk.rsaDecrypt({ privatePem: pair.privatePem, padding: padding,
                            hash: hash, ciphertext: sealed.ciphertext })),
        hex(atLimit));
      assert.throws(function () {
        pk.rsaEncrypt({ publicPem: pair.publicPem, padding: padding,
                        hash: hash, plaintext: new Uint8Array(max + 1) });
      }, /at most/, padding + "/" + hash + " accepted an over-long message");
    });
  });

  // RSA-OAEP-SHA-256 against node's own crypto, which is OpenSSL: the padding
  // is where an RSA implementation goes wrong, and it is not visible from a
  // round trip against itself.
  const theirs = crypto.publicEncrypt({
    key: pair.publicPem,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from("interop"));
  assert.strictEqual(
    bytes.bytesToStr(pk.rsaDecrypt({ privatePem: pair.privatePem,
                                     padding: 'oaep', hash: 'SHA-256',
                                     ciphertext: new Uint8Array(theirs) })),
    "interop",
    "could not decrypt what OpenSSL's RSA-OAEP-SHA-256 produced");
  const ours = pk.rsaEncrypt({ publicPem: pair.publicPem, padding: 'oaep',
                               hash: 'SHA-256',
                               plaintext: bytes.strBytes("interop") });
  assert.strictEqual(crypto.privateDecrypt({
    key: pair.privatePem,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from(ours.ciphertext)).toString(), "interop",
    "OpenSSL could not decrypt what our RSA-OAEP-SHA-256 produced");

  // The hybrid, which is what the page defaults to and what any real protocol
  // does. A message far longer than the modulus is the point.
  const long = bytes.strBytes(PK_MESSAGE.repeat(50));
  const hybrid = pk.rsaHybridEncrypt({ publicPem: pair.publicPem,
                                       padding: 'oaep', hash: 'SHA-256',
                                       aad: bytes.strBytes("ctx"),
                                       plaintext: long });
  assert.ok(long.length > 256, "the hybrid test message must exceed the " +
            "modulus, or it is not testing the hybrid");
  assert.strictEqual(
    hex(pk.rsaHybridDecrypt({ privatePem: pair.privatePem, padding: 'oaep',
                              hash: 'SHA-256', aad: bytes.strBytes("ctx"),
                              encapsulation: hybrid.encapsulation,
                              iv: hybrid.iv, ciphertext: hybrid.ciphertext,
                              tag: hybrid.tag })), hex(long));
  assert.throws(function () {
    pk.rsaHybridDecrypt({ privatePem: pair.privatePem, padding: 'oaep',
                          hash: 'SHA-256', aad: bytes.strBytes("other"),
                          encapsulation: hybrid.encapsulation, iv: hybrid.iv,
                          ciphertext: hybrid.ciphertext, tag: hybrid.tag });
  }, /did not verify/i, "the hybrid accepted changed AAD");
  log.info("[rsa] OK — both paddings at every hash, the size limits are " +
           "PKCS#1's own, OpenSSL reads our OAEP and we read its, and the " +
           "hybrid carries a message longer than the modulus.");
  log.debug("Leaving checkRsa().");
}

function checkEcies() {
  log.debug("Entering checkEcies().");
  pk.eciesCurveIds().forEach(function (curve) {
    const pair = pk.eciesGenerateKeyPair(curve);
    const sealed = pk.eciesEncrypt({ curve: curve,
                                     publicKeyHex: pair.publicKeyHex,
                                     info: 'ecies-test',
                                     plaintext: bytes.strBytes(PK_MESSAGE) });
    assert.strictEqual(
      bytes.bytesToStr(pk.eciesDecrypt({ curve: curve,
        privateKeyHex: pair.privateKeyHex, info: 'ecies-test',
        encapsulation: sealed.encapsulation, iv: sealed.iv,
        ciphertext: sealed.ciphertext, tag: sealed.tag })), PK_MESSAGE);

    // Ephemeral means ephemeral: two encryptions of one message to one
    // recipient must differ. If they stop differing the ephemeral key is
    // being reused, which is the whole security of the scheme.
    const again = pk.eciesEncrypt({ curve: curve,
                                    publicKeyHex: pair.publicKeyHex,
                                    info: 'ecies-test',
                                    plaintext: bytes.strBytes(PK_MESSAGE) });
    assert.notStrictEqual(hex(again.encapsulation), hex(sealed.encapsulation),
      curve + " reused its ephemeral key");
    assert.notStrictEqual(hex(again.ciphertext), hex(sealed.ciphertext));

    // The context string separates contexts. A pane that accepted any info
    // would be deriving one key for every protocol that ever agreed this
    // secret.
    assert.throws(function () {
      pk.eciesDecrypt({ curve: curve, privateKeyHex: pair.privateKeyHex,
                        info: 'another-protocol',
                        encapsulation: sealed.encapsulation, iv: sealed.iv,
                        ciphertext: sealed.ciphertext, tag: sealed.tag });
    }, /did not verify/i, curve + " ignored the KDF info string");

    // Somebody else's private key must not open it.
    const other = pk.eciesGenerateKeyPair(curve);
    assert.throws(function () {
      pk.eciesDecrypt({ curve: curve, privateKeyHex: other.privateKeyHex,
                        info: 'ecies-test',
                        encapsulation: sealed.encapsulation, iv: sealed.iv,
                        ciphertext: sealed.ciphertext, tag: sealed.tag });
    }, /did not verify/i, curve + " decrypted under the wrong key");
  });

  // The agreed secret on a Weierstrass curve is the x COORDINATE, not the
  // compressed point @noble hands back — SEC 1's ECDH primitive. Feeding the
  // whole point to the KDF works perfectly between two copies of this code and
  // interoperates with nothing, so it is asserted directly. node's ECDH is the
  // second implementation.
  const nodeEcdh = crypto.createECDH('prime256v1');
  nodeEcdh.generateKeys();
  const ours = pk.eciesGenerateKeyPair('P-256');
  const theirSecret = nodeEcdh.computeSecret(
    Buffer.from(ours.publicKeyHex, 'hex'));
  const ourSecret = pk.eciesSharedSecret(pk.eciesCurve('P-256'),
    bytes.hexToBytes(ours.privateKeyHex),
    new Uint8Array(nodeEcdh.getPublicKey()));
  assert.strictEqual(hex(ourSecret), theirSecret.toString('hex'),
    "our P-256 ECDH secret is not the x coordinate node computes — which is " +
    "what SEC 1 says it is, and what every other implementation will assume");
  assert.strictEqual(ourSecret.length, 32,
    "a P-256 shared secret is 32 bytes; 33 means the compressed point's " +
    "sign byte is still on the front");
  log.info("[ecies] OK — five curves round-trip, the ephemeral key is fresh " +
           "each time, the info string separates contexts, and the P-256 " +
           "agreed secret matches node's ECDH exactly.");
  log.debug("Leaving checkEcies().");
}

function checkMlKem() {
  log.debug("Entering checkMlKem().");
  [false, true].forEach(function (hybrid) {
    pk.mlkemSetIds().forEach(function (set) {
      const pair = pk.mlkemGenerateKeyPair(set, hybrid);
      const sealed = pk.mlkemEncrypt({ paramSet: set, hybrid: hybrid,
        publicKeyHex: pair.publicKeyHex, info: 'kem-test',
        plaintext: bytes.strBytes(PK_MESSAGE) });
      assert.strictEqual(
        bytes.bytesToStr(pk.mlkemDecrypt({ paramSet: set, hybrid: hybrid,
          privateKeyHex: pair.privateKeyHex, info: 'kem-test',
          encapsulationHex: sealed.encapsulationHex, iv: sealed.iv,
          ciphertext: sealed.ciphertext, tag: sealed.tag })), PK_MESSAGE,
        set + (hybrid ? " hybrid" : "") + " did not round-trip");

      // The FIPS 203 sizes, which are what says the parameter set selected is
      // the one that ran.
      const sizes = { 'ML-KEM-512': [800, 1632, 768],
                      'ML-KEM-768': [1184, 2400, 1088],
                      'ML-KEM-1024': [1568, 3168, 1568] }[set];
      const pqPublic = pair.publicKeyHex.split(':')[0];
      const pqPrivate = pair.privateKeyHex.split(':')[0];
      const pqCipher = sealed.encapsulationHex.split(':')[0];
      assert.strictEqual(pqPublic.length / 2, sizes[0],
        set + "'s public key is the wrong size for FIPS 203");
      assert.strictEqual(pqPrivate.length / 2, sizes[1],
        set + "'s private key is the wrong size for FIPS 203");
      assert.strictEqual(pqCipher.length / 2, sizes[2],
        set + "'s encapsulation is the wrong size for FIPS 203");

      // A hybrid must carry BOTH halves, and dropping the classical one must
      // not still decrypt — otherwise "hybrid" is a label rather than a fact.
      if (hybrid) {
        assert.strictEqual(pair.publicKeyHex.split(':').length, 2);
        assert.strictEqual(sealed.encapsulationHex.split(':').length, 2);
        assert.throws(function () {
          pk.mlkemDecrypt({ paramSet: set, hybrid: false,
            privateKeyHex: pair.privateKeyHex.split(':')[0],
            info: 'kem-test',
            encapsulationHex: sealed.encapsulationHex.split(':')[0],
            iv: sealed.iv, ciphertext: sealed.ciphertext, tag: sealed.tag });
        }, /did not verify/i,
          set + " hybrid decrypted from the post-quantum half alone, so the " +
          "X25519 secret is not actually mixed into the key");
      }
    });
  });
  // A plain key used as a hybrid one is named rather than throwing from inside
  // a library.
  const plain = pk.mlkemGenerateKeyPair('ML-KEM-768', false);
  assert.throws(function () {
    pk.mlkemEncrypt({ paramSet: 'ML-KEM-768', hybrid: true,
                      publicKeyHex: plain.publicKeyHex,
                      plaintext: bytes.strBytes("x") });
  }, /two keys separated by a colon/);
  log.info("[ml-kem] OK — three parameter sets at FIPS 203's key sizes, " +
           "alone and hybridised, and the hybrid genuinely needs both " +
           "halves.");
  log.debug("Leaving checkMlKem().");
}

function checkFiniteField() {
  log.debug("Entering checkFiniteField().");
  pk.ffcGroupIds().forEach(function (id) {
    const pair = pk.ffcGenerateKeyPair(id);
    const group = pk.ffcGroup(id);

    // ElGamal, including the case a round trip of ordinary text never
    // produces: leading zero bytes, which an integer drops unless something
    // marks the length.
    const sealed = pk.elgamalEncrypt({ group: id,
      publicKeyHex: pair.publicKeyHex,
      plaintext: bytes.strBytes(PK_MESSAGE) });
    assert.strictEqual(bytes.bytesToStr(pk.elgamalDecrypt({ group: id,
      privateKeyHex: pair.privateKeyHex, c1Hex: sealed.c1Hex,
      c2Hex: sealed.c2Hex })), PK_MESSAGE);
    const zeros = new Uint8Array([0, 0, 0, 65, 66]);
    const zeroSealed = pk.elgamalEncrypt({ group: id,
      publicKeyHex: pair.publicKeyHex, plaintext: zeros });
    assert.strictEqual(hex(pk.elgamalDecrypt({ group: id,
      privateKeyHex: pair.privateKeyHex, c1Hex: zeroSealed.c1Hex,
      c2Hex: zeroSealed.c2Hex })), "0000004142",
      "ElGamal lost the message's leading zero bytes");
    assert.throws(function () {
      pk.elgamalEncrypt({ group: id, publicKeyHex: pair.publicKeyHex,
                          plaintext: new Uint8Array(
                            pk.elgamalMaxBytes(id) + 1) });
    }, /at most/);

    // ElGamal IS malleable — multiplying c2 by t multiplies the plaintext by
    // t, and no part of the scheme objects. The pane says so, and this is
    // what stops that sentence from quietly becoming untrue.
    //
    // What is asserted is precisely what is true here, and the distinction
    // cost this test a first draft: the recovered value is changed, and this
    // page's 0x01 length marker then usually NOTICES, so decryption refuses
    // rather than returning altered bytes. That marker is a sanity check on an
    // encoding, not authentication — it catches an arbitrary mauling and would
    // not stop one chosen to preserve it. So the assertion is "never the
    // original plaintext", by either route, and the pane's wording says the
    // same thing rather than claiming the mauling goes unnoticed here.
    const c2 = BigInt('0x' + sealed.c2Hex);
    const modulus = BigInt('0x' + pk.FFC_GROUPS[id].p);
    const doubled = ((c2 * BigInt(2)) % modulus).toString(16);
    var recovered = null;
    try {
      recovered = pk.elgamalDecrypt({ group: id,
        privateKeyHex: pair.privateKeyHex, c1Hex: sealed.c1Hex,
        c2Hex: doubled.length % 2 ? '0' + doubled : doubled });
    } catch (e) {
      assert.ok(/length marker/.test(e.message),
        "a mauled ElGamal ciphertext must be refused for the reason the " +
        "encoding gives, not by something failing underneath: " + e.message);
    }
    assert.ok(recovered === null ||
              hex(recovered) !== hex(bytes.strBytes(PK_MESSAGE)),
      "multiplying c2 by two returned the ORIGINAL plaintext, which would " +
      "mean the ciphertext half is not being used at all");

    // DHIES over the same group.
    const dh = pk.ffcHybridEncrypt({ group: id,
      publicKeyHex: pair.publicKeyHex, info: 'dhies-test',
      plaintext: bytes.strBytes(PK_MESSAGE) });
    assert.strictEqual(bytes.bytesToStr(pk.ffcHybridDecrypt({ group: id,
      privateKeyHex: pair.privateKeyHex, info: 'dhies-test',
      encapsulationHex: dh.encapsulationHex, iv: dh.iv,
      ciphertext: dh.ciphertext, tag: dh.tag })), PK_MESSAGE);

    // The agreed secret must be symmetric AND fixed-length. A secret that
    // happens to start with a zero byte, left unpadded, makes the two ends
    // derive different keys about one time in 256 — which reads as an
    // intermittent fault rather than a bug.
    for (var round = 0; round < 40; round++) {
      const a = pk.ffcGenerateKeyPair(id), b = pk.ffcGenerateKeyPair(id);
      const left = pk.ffcSharedSecret(group, a.privateKeyHex, b.publicKeyHex);
      const right = pk.ffcSharedSecret(group, b.privateKeyHex, a.publicKeyHex);
      assert.strictEqual(hex(left), hex(right),
        id + " Diffie-Hellman is not symmetric");
      assert.strictEqual(left.length, group.bytes,
        id + " agreed a secret that is not padded to the size of p");
    }
  });
  log.info("[ffc] OK — ElGamal and DHIES over both RFC 3526 groups, leading " +
           "zeros survive, ElGamal is demonstrably malleable, and the " +
           "agreed secret is symmetric and fixed-length over 80 exchanges.");
  log.debug("Leaving checkFiniteField().");
}

// ---------------------------------------------------------------------------
// 9. The division of labour itself.
//
// Every check above is possible only because these modules have no DOM. That
// is a property an ordinary-looking edit can remove — one call to
// document.getElementById for convenience — and the symptom would be this
// whole job failing to load
// with a message about `document`, three releases later. Asserted here, where
// it reads as a rule rather than as an accident.
// ---------------------------------------------------------------------------
const DOM_FREE = ['crypto_bytes.js', 'symmetric_crypto.js',
                  'pk_encryption.js'];

function checkNoDom() {
  log.debug("Entering checkNoDom().");
  const forbidden = /\b(document|window|localStorage|sessionStorage)\s*\./;
  var checked = 0;
  DOM_FREE.forEach(function (name) {
    const candidates = [path.join(__dirname, name), path.join(SRC, name)];
    const file = candidates.filter(function (one) {
      return fs.existsSync(one);
    })[0];
    assert.ok(file, "could not locate " + name + " to read");
    const source = fs.readFileSync(file, "utf8");
    source.split(/\r?\n/).forEach(function (line, index) {
      // Comments are where the reasoning lives, so only real code counts.
      const code = line.replace(/^\s*(\/\/|\*).*$/, '');
      assert.ok(!forbidden.test(code),
        name + " line " + (index + 1) + " touches the DOM: " + line.trim() +
        "\nThese three modules are what tests/crypto_engines.js drives in " +
        "node. The DOM belongs in tool_panes.js and the page bundles.");
    });
    checked++;
  });
  log.info("[no-dom] OK — " + checked + " modules under test reach no DOM, " +
           "which is what lets this job run without a browser.");
  log.debug("Leaving checkNoDom().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Encryption / Decryption page's engines, " +
           "in node.");
  checkNoDom();
  checkByteHelpers();
  checkChaCha20();
  checkBlockCipherMacs();
  checkAesModes();
  checkAgainstOpenssl();
  checkDesVectors();
  checkRefusals();
  checkModpGroups();
  checkRsa();
  checkEcies();
  checkMlKem();
  checkFiniteField();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (error) {
  log.error(error.stack || error.message);
  process.exit(1);
});
