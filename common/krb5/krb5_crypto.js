// File: krb5_crypto.js
//
// ---------------------------------------------------------------------------
// The RFC 3961 encryption framework and the encryption types Kerberos v5
// actually meets in 2026.
//
//   17  aes128-cts-hmac-sha1-96      RFC 3962   the AD workhorse
//   18  aes256-cts-hmac-sha1-96      RFC 3962   the AD workhorse
//   19  aes128-cts-hmac-sha256-128   RFC 8009   MIT/Heimdal; Windows Server 2025
//   20  aes256-cts-hmac-sha384-192   RFC 8009   defines the bits but is reported
//                                               not to negotiate them yet
//   23  arcfour-hmac-md5             RFC 4757   legacy, being retired, still the
//                                               thing you have to debug
//
// DES is deliberately absent. Windows Server 2025 removed it and it is not
// coming back; a capture containing it decodes (the codec names the etype) but
// nothing here will produce or accept one.
//
// EVERYTHING IN THIS FILE IS ASYNC, and that is not a style choice. Web Crypto
// is promise-based, and this module runs in the browser as well as in node —
// `globalThis.crypto.subtle` in both, so there is one code path rather than two.
// It must not `require("crypto")`: browserify would substitute crypto-browserify
// and ship `elliptic` (GHSA-848j-6mx2-7j84, no patched version) into the bundle.
// See client/CLAUDE.md.
//
// Three things here are the ones that go wrong, and each fails as an opaque
// integrity error rather than as anything that names itself:
//
//  * **The key usage number.** Every encryption is keyed by a usage constant
//    folded into the derivation. The right key, the right cipher and the wrong
//    usage produce a checksum mismatch and no other symptom. They are in
//    KEY_USAGE below with their RFC 4120 section, and no call site passes a
//    bare integer.
//  * **The confounder.** Every etype prepends random bytes to the plaintext.
//    Forget it and you decrypt to garbage of exactly the right length.
//  * **Which bytes the MAC covers.** RFC 3962 MACs the PLAINTEXT (conf|data);
//    RFC 8009 MACs the CIPHERTEXT with the IV in front (IV|C). Reading one and
//    implementing the other gives an implementation that talks only to itself.
//
// The oracle for all of it is the RFCs' own published vectors, in
// tests/krb5_crypto.js: RFC 3961 appendix A (n-fold, DR/DK), RFC 3962
// appendix B (string-to-key, CTS), RFC 8009 appendix A (KDF, encryption). A
// Kerberos implementation tested only against its own mock KDC is
// self-consistently wrong, which is indistinguishable from correct until it
// meets a domain controller.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_crypto",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var toBytes = prim.toBytes;
var concat = prim.concat;

// ---------------------------------------------------------------------------
// Web Crypto, reached the same way in both runtimes.
// ---------------------------------------------------------------------------
function subtle() {
  if (typeof globalThis !== "undefined" && globalThis.crypto && 
      globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("krb5: no Web Crypto here. In the browser this means the " +
      "page " +
    "is not a secure context (https or localhost); Kerberos cannot be done " +
        "over " +
    "plain http on a non-local origin.");
}

function randomBytes(n) {
  var out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

// ---------------------------------------------------------------------------
// Unpadded CBC on top of Web Crypto, which only offers the padded kind.
//
// Web Crypto's AES-CBC always applies PKCS#7 on encrypt and always validates it
// on decrypt. Kerberos needs neither: its plaintexts are already block-aligned
// by the confounder-and-CTS construction, and a stray padding block would be
// sixteen bytes of ciphertext no KDC expects.
//
//  * Encrypt: encrypt, then drop the trailing all-padding block.
//  * Decrypt: append a block chosen so that the final plaintext block IS exact
//    PKCS#7 padding, so the validation passes and can be discarded. That block
//    is E(0x10 x16 XOR C_last), and E of a single block is itself an encrypt
//    with a zero IV.
//
// Two extra AES operations per decryption. The alternative was shipping an AES
// implementation, which is a much worse trade.
// ---------------------------------------------------------------------------
async function importAesKey(keyBytes) {
  return subtle().importKey("raw", toBytes(keyBytes), { name: "AES-CBC" }, 
      false, ["encrypt", "decrypt"]);
}

async function cbcEncryptRaw(aesKey, iv, data) {
  log.debug("Entering cbcEncryptRaw().");
  var input = toBytes(data);
  if (input.length % 16 !== 0) {
    log.debug("Leaving cbcEncryptRaw().");
    throw new Error("krb5: raw CBC needs a whole number of blocks");
  }
  var full = new Uint8Array(await subtle().encrypt({
    name: "AES-CBC",
    iv: toBytes(iv)
  }, aesKey, input));
  log.debug("Leaving cbcEncryptRaw().");
  return full.slice(0, input.length);
}

async function cbcDecryptRaw(aesKey, iv, data) {
  log.debug("Entering cbcDecryptRaw().");
  var input = toBytes(data);
  if (input.length === 0) {
    log.debug("Leaving cbcDecryptRaw().");
    return new Uint8Array(0);
  }
  if (input.length % 16 !== 0) {
    log.debug("Leaving cbcDecryptRaw().");
    throw new Error("krb5: raw CBC needs a whole number of blocks");
  }
  var last = input.slice(input.length - 16);
  var padBlock = new Uint8Array(16).fill(16);
  var synthetic = await cbcEncryptRaw(aesKey, new Uint8Array(16), 
      prim.xor(padBlock, last));
  var glued = concat([input, synthetic]);
  var out = new Uint8Array(await subtle().decrypt({
    name: "AES-CBC",
    iv: toBytes(iv)
  }, aesKey, glued));
  log.debug("Leaving cbcDecryptRaw().");
  return out.slice(0, input.length);
}

// A single-block ECB decryption, which CTS needs to recover the truncated
// block. D(block) is a CBC decryption under a zero IV.
async function ecbDecryptBlock(aesKey, block) {
  return cbcDecryptRaw(aesKey, new Uint8Array(16), toBytes(block));
}

// ---------------------------------------------------------------------------
// CBC with ciphertext stealing, as Kerberos uses it (CBC-CS3).
//
// The last two ciphertext blocks are exchanged and the final one truncated to
// the length of the trailing partial plaintext. Two cases are where
// implementations go wrong, and both have published vectors:
//
//  * A plaintext that is an EXACT multiple of the block size still swaps the
//    last two blocks. It is not plain CBC.
//  * A plaintext of one block or less does NOT swap and is plain CBC.
// ---------------------------------------------------------------------------
async function ctsEncrypt(keyBytes, iv, plaintext) {
  log.debug("Entering ctsEncrypt(). bytes=" + toBytes(plaintext).length);
  var data = toBytes(plaintext);
  if (data.length < 16) {
    throw new Error("krb5: CTS needs at least one block; got " + data.length);
  }
  var aesKey = await importAesKey(keyBytes);
  if (data.length === 16) {
    log.debug("Leaving ctsEncrypt(). Single block, plain CBC.");
    return cbcEncryptRaw(aesKey, iv, data);
  }
  var m = data.length % 16 || 16;
  // Zero-pad the trailing partial block up to the block size. When m is 16 this
  // is a no-op and the swap below is what makes an exact multiple differ from
  // plain CBC.
  var c = await cbcEncryptRaw(aesKey, iv, concat([data, 
      new Uint8Array((16 - m) % 16)]));
  var n = c.length / 16;
  var cLast = c.slice((n - 1) * 16, n * 16);
  var cPrev = c.slice((n - 2) * 16, (n - 1) * 16);
  var out = concat([c.slice(0, (n - 2) * 16), cLast, cPrev.slice(0, m)]);
  log.debug("Leaving ctsEncrypt(). blocks=" + n + ", tail=" + m);
  return out;
}

async function ctsDecrypt(keyBytes, iv, ciphertext) {
  log.debug("Entering ctsDecrypt(). bytes=" + toBytes(ciphertext).length);
  var data = toBytes(ciphertext);
  if (data.length < 16) {
    throw new Error("krb5: CTS ciphertext shorter than a block");
  }
  var aesKey = await importAesKey(keyBytes);
  if (data.length === 16) {
    log.debug("Leaving ctsDecrypt(). Single block, plain CBC.");
    return cbcDecryptRaw(aesKey, iv, data);
  }
  var m = data.length % 16 || 16;
  var head = data.slice(0, data.length - 16 - m);     // C_1 .. C_{n-2}
  var cLast = data.slice(data.length - 16 - m, data.length - m);  // C_n, full
  var truncated = data.slice(data.length - m);        // C_{n-1}, first m bytes

  // D(C_n) is (P_n | zeros) XOR C_{n-1}, so the bytes of C_{n-1} that were
  // dropped on the wire are exactly the tail of D(C_n).
  var z = await ecbDecryptBlock(aesKey, cLast);
  var cPrev = concat([truncated, z.slice(m)]);
  var pLast = prim.xor(z, cPrev).slice(0, m);

  var rest = await cbcDecryptRaw(aesKey, iv, concat([head, cPrev]));
  log.debug("Leaving ctsDecrypt(). recovered=" + (rest.length + pLast.length));
  return concat([rest, pLast]);
}

// ---------------------------------------------------------------------------
// HMAC and PBKDF2 through Web Crypto, with MD5 falling back to the pure
// implementation because `crypto.subtle` does not know that hash.
// ---------------------------------------------------------------------------
async function hmac(hashName, keyBytes, message) {
  if (hashName === "MD5") {
    return prim.hmacMd5(keyBytes, message);
  }
  var key = await subtle().importKey("raw", toBytes(keyBytes), {
    name: "HMAC",
    hash: hashName
  }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", key, toBytes(message)));
}

async function pbkdf2(hashName, password, salt, iterations, outBits) {
  log.debug("Entering pbkdf2().");
  var key = await subtle().importKey("raw", toBytes(password), "PBKDF2", false, 
      ["deriveBits"]);
  var bits = await subtle().deriveBits(
    {
      name: "PBKDF2",
      salt: toBytes(salt),
      iterations: iterations,
      hash: hashName
    }, key, outBits);
  log.debug("Leaving pbkdf2().");
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// RFC 3961 section 5.1: DR (derive random) and DK (derive key).
//
// DR encrypts the folded constant in CBC under the base key, feeding each block
// back in, until enough bytes exist. random-to-key is the identity for AES, so
// DK is DR truncated.
// ---------------------------------------------------------------------------
async function deriveRandom(baseKey, constant, outBytes) {
  log.debug("Entering deriveRandom().");
  var c = toBytes(constant);
  if (c.length !== 16) c = prim.nfold(c, 128);
  var aesKey = await importAesKey(baseKey);
  var out = new Uint8Array(0);
  var block = c;
  while (out.length < outBytes) {
    block = await cbcEncryptRaw(aesKey, new Uint8Array(16), block);
    out = concat([out, block]);
  }
  log.debug("Leaving deriveRandom().");
  return out.slice(0, outBytes);
}

// The derivation constant: the usage as a four-byte big-endian value followed
// by the purpose byte — 0x99 for a checksum key, 0xAA for encryption, 0x55 for
// integrity.
function usageConstant(usage, purposeByte) {
  return new Uint8Array([
    (usage >>> 24) & 0xff, (usage >>> 16) & 0xff, (usage >>> 8) & 0xff, 
        usage & 0xff,
    purposeByte
  ]);
}

async function deriveKeyAes(baseKey, usage, purposeByte, keyBytes) {
  return deriveRandom(baseKey, usageConstant(usage, purposeByte), keyBytes);
}

// ---------------------------------------------------------------------------
// RFC 8009 section 3: KDF-HMAC-SHA2, an SP800-108 counter-mode KDF.
//
//   K1 = HMAC-SHA-256/384(key, 0x00000001 | label | 0x00 | k)   (k in bits, BE32)
//
// Note the asymmetry that is easy to get wrong and that the RFC's own vectors
// are the only thing that catches: for aes256-cts-hmac-sha384-192, **Ke is 256
// bits while Kc and Ki are 192**. Using one length for all three produces keys
// that are wrong for two of the three purposes.
// ---------------------------------------------------------------------------
async function kdfHmacSha2(hashName, key, label, outBits) {
  var input = concat([
    new Uint8Array([0, 0, 0, 1]),
    toBytes(label),
    new Uint8Array([0]),
    new Uint8Array([(outBits >>> 24) & 0xff, (outBits >>> 16) & 0xff, 
        (outBits >>> 8) & 0xff, outBits & 0xff])
  ]);
  var mac = await hmac(hashName, key, input);
  return mac.slice(0, outBits / 8);
}

// ---------------------------------------------------------------------------
// Key usage numbers, RFC 4120 section 7.5.1 (and RFC 4121 for the GSS ones).
//
// Named rather than inlined because a wrong one is invisible: it produces a
// well-formed message that fails integrity at the far end, and the error a KDC
// returns for it is the same one it returns for a wrong password.
// ---------------------------------------------------------------------------
var KEY_USAGE = {
  AS_REQ_PA_ENC_TIMESTAMP: 1,        // PA-ENC-TIMESTAMP, client long-term key
  KDC_REP_TICKET: 2,                 // AS-REP/TGS-REP ticket enc-part, service key
  AS_REP_ENCPART: 3,                 // AS-REP enc-part, client long-term key
  TGS_REQ_AD_SESSKEY: 4,
  TGS_REQ_AD_SUBKEY: 5,
  TGS_REQ_AUTH_CKSUM: 6,             // PA-TGS-REQ Authenticator checksum
  TGS_REQ_AUTH: 7,                   // PA-TGS-REQ Authenticator, TGT session key
  TGS_REP_ENCPART_SESSKEY: 8,        // TGS-REP enc-part under the TGT session key
  TGS_REP_ENCPART_SUBKEY: 9,         // ... or under the Authenticator subkey
  AP_REQ_AUTH_CKSUM: 10,             // AP-REQ Authenticator checksum
  AP_REQ_AUTH: 11,                   // AP-REQ Authenticator, service session key
  AP_REP_ENCPART: 12,                // AP-REP enc-part
  KRB_PRIV_ENCPART: 13,
  KRB_CRED_ENCPART: 14,              // delegated credentials
  KRB_SAFE_CKSUM: 15,
  KDC_REP_TICKET_ENCPART_ALT: 16,
  PA_FOR_USER_CKSUM: 17,             // S4U2Self PA-FOR-USER checksum
  KRB_ERROR_CKSUM: 18,
  AD_KDCISSUED_CKSUM: 19,
  AD_MTE: 20,
  AD_ITE: 21,
  GSS_ACCEPTOR_SEAL: 22,             // RFC 4121 per-message tokens
  GSS_ACCEPTOR_SIGN: 23,
  GSS_INITIATOR_SEAL: 24,
  GSS_INITIATOR_SIGN: 25
};

// ---------------------------------------------------------------------------
// The AES families.
// ---------------------------------------------------------------------------

function aesSha1Profile(id, name, keyBytes) {
  log.debug("Entering aesSha1Profile().");
  var CHECKSUM_BYTES = 12;                       // hmac-sha1-96
  log.debug("Leaving aesSha1Profile().");
  return {
    id: id,
    name: name,
    keyBytes: keyBytes,
    blockBytes: 16,
    confounderBytes: 16,
    checksumBytes: CHECKSUM_BYTES,
    checksumType: (keyBytes === 16) ? 15 : 
        16,   // hmac-sha1-96-aes128 / -aes256
    defaultIterations: 4096,
    rfc: "RFC 3962",
    legacy: false,

    // RFC 3962 section 4. The salt is NOT guessable and must come from the
    // KDC's ETYPE-INFO2 — Active Directory's default is the realm followed by
    // the sAMAccountName for a user, but a host-shaped string for a computer
    // account. Guessing works until the first machine account.
    async stringToKey(password, salt, params) {
      log.debug("Entering stringToKey(). etype=" + name);
      var iterations = this.defaultIterations;
      if (params && toBytes(params).length === 4) {
        var p = toBytes(params);
        iterations = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
        // RFC 3962: all-zero means 2^32, which no sane KDC sends and which
        // would hang the browser for hours. Refuse rather than attempt it.
        if (iterations === 0) {
          throw new Error("krb5: s2kparams asks for 2^32 iterations");
        }
      }
      var tkey = await pbkdf2("SHA-1", prim.utf8(password), toBytes(salt), 
          iterations, keyBytes * 8);
      var key = await deriveRandom(tkey, prim.utf8("kerberos"), keyBytes);
      log.debug("Leaving stringToKey(). iterations=" + iterations);
      return key;
    },

    async encryptionKey(baseKey, usage) { return deriveKeyAes(baseKey, usage, 
        0xAA, keyBytes); },
    async integrityKey(baseKey, usage) { return deriveKeyAes(baseKey, usage, 
        0x55, keyBytes); },
    async checksumKey(baseKey, usage) { return deriveKeyAes(baseKey, usage, 
        0x99, keyBytes); },

    // RFC 3961 section 5.3 simplified profile: the MAC is over the PLAINTEXT
    // (confounder included), not over the ciphertext. RFC 8009 is the other way
    // round; implementing one while reading the other is the classic error.
    async encrypt(baseKey, usage, plaintext, confounderForTest) {
      log.debug("Entering encrypt(). etype=" + name + ", usage=" + usage);
      var ke = await this.encryptionKey(baseKey, usage);
      var ki = await this.integrityKey(baseKey, usage);
      var conf = confounderForTest ? toBytes(confounderForTest) : 
          randomBytes(16);
      var plain = concat([conf, toBytes(plaintext)]);
      var c = await ctsEncrypt(ke, new Uint8Array(16), plain);
      var h = (await hmac("SHA-1", ki, plain)).slice(0, CHECKSUM_BYTES);
      log.debug("Leaving encrypt(). bytes=" + (c.length + h.length));
      return concat([c, h]);
    },

    async decrypt(baseKey, usage, ciphertext) {
      log.debug("Entering decrypt(). etype=" + name + ", usage=" + usage);
      var data = toBytes(ciphertext);
      if (data.length < 16 + CHECKSUM_BYTES) {
        throw new Error("krb5: ciphertext too short for " + name);
      }
      var ke = await this.encryptionKey(baseKey, usage);
      var ki = await this.integrityKey(baseKey, usage);
      var c = data.slice(0, data.length - CHECKSUM_BYTES);
      var h = data.slice(data.length - CHECKSUM_BYTES);
      var plain = await ctsDecrypt(ke, new Uint8Array(16), c);
      var expect = (await hmac("SHA-1", ki, plain)).slice(0, CHECKSUM_BYTES);
      if (!prim.equalConstantTime(h, expect)) {
        throw new Error("krb5: integrity check failed (" + name + ", usage " + 
            usage + ")");
      }
      log.debug("Leaving decrypt(). plaintext=" + (plain.length - 16));
      return plain.slice(16);
    },

    async checksum(baseKey, usage, message) {
      var kc = await this.checksumKey(baseKey, usage);
      return (await hmac("SHA-1", kc, message)).slice(0, CHECKSUM_BYTES);
    },

    async verifyChecksum(baseKey, usage, message, given) {
      return prim.equalConstantTime(await this.checksum(baseKey, usage, 
          message), given);
    }
  };
}

function aesSha2Profile(id, name, keyBytes, hashName, macBytes) {
  log.debug("Entering aesSha2Profile().");
  var kiBits = macBytes * 8;
  log.debug("Leaving aesSha2Profile().");
  return {
    id: id,
    name: name,
    keyBytes: keyBytes,
    blockBytes: 16,
    confounderBytes: 16,
    checksumBytes: macBytes,
    checksumType: (keyBytes === 16) ? 19 : 
        20,   // hmac-sha256-128-aes128 / hmac-sha384-192-aes256
    defaultIterations: 32768,                    // RFC 8009, not 3962's 4096
    rfc: "RFC 8009",
    legacy: false,

    async stringToKey(password, salt, params) {
      log.debug("Entering stringToKey(). etype=" + name);
      var iterations = this.defaultIterations;
      if (params && toBytes(params).length === 4) {
        var p = toBytes(params);
        iterations = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
        if (iterations === 0) {
          throw new Error("krb5: s2kparams asks for 2^32 iterations");
        }
      }
      // saltp puts the enctype name in front of the salt, so the same password
      // and salt produce different keys for the two RFC 8009 etypes.
      var saltp = concat([prim.utf8(name), new Uint8Array([0]), toBytes(salt)]);
      var tkey = await pbkdf2(hashName, prim.utf8(password), saltp, iterations, 
          keyBytes * 8);
      var key = await kdfHmacSha2(hashName, tkey, prim.utf8("kerberos"), 
          keyBytes * 8);
      log.debug("Leaving stringToKey(). iterations=" + iterations);
      return key;
    },

    // Ke is the FULL key length; Kc and Ki are the MAC length. For
    // aes256-cts-hmac-sha384-192 that means 256 bits against 192, and using one
    // number for all three is wrong for two of them.
    async encryptionKey(baseKey, usage) {
      return kdfHmacSha2(hashName, baseKey, usageConstant(usage, 0xAA), 
          keyBytes * 8);
    },
    async integrityKey(baseKey, usage) {
      return kdfHmacSha2(hashName, baseKey, usageConstant(usage, 0x55), kiBits);
    },
    async checksumKey(baseKey, usage) {
      return kdfHmacSha2(hashName, baseKey, usageConstant(usage, 0x99), kiBits);
    },

    // Encrypt-then-MAC, and the MAC covers IV | ciphertext — the opposite of
    // RFC 3962 above.
    async encrypt(baseKey, usage, plaintext, confounderForTest) {
      log.debug("Entering encrypt(). etype=" + name + ", usage=" + usage);
      var ke = await this.encryptionKey(baseKey, usage);
      var ki = await this.integrityKey(baseKey, usage);
      var iv = new Uint8Array(16);
      var conf = confounderForTest ? toBytes(confounderForTest) : 
          randomBytes(16);
      var c = await ctsEncrypt(ke, iv, concat([conf, toBytes(plaintext)]));
      var h = (await hmac(hashName, ki, concat([iv, c]))).slice(0, macBytes);
      log.debug("Leaving encrypt(). bytes=" + (c.length + h.length));
      return concat([c, h]);
    },

    async decrypt(baseKey, usage, ciphertext) {
      log.debug("Entering decrypt(). etype=" + name + ", usage=" + usage);
      var data = toBytes(ciphertext);
      if (data.length < 16 + macBytes) {
        throw new Error("krb5: ciphertext too short for " + name);
      }
      var ke = await this.encryptionKey(baseKey, usage);
      var ki = await this.integrityKey(baseKey, usage);
      var iv = new Uint8Array(16);
      var c = data.slice(0, data.length - macBytes);
      var h = data.slice(data.length - macBytes);
      // Verified BEFORE decrypting, which is what encrypt-then-MAC is for.
      var expect = (await hmac(hashName, ki, concat([iv, c]))).slice(0, 
          macBytes);
      if (!prim.equalConstantTime(h, expect)) {
        throw new Error("krb5: integrity check failed (" + name + ", usage " + 
            usage + ")");
      }
      var plain = await ctsDecrypt(ke, iv, c);
      log.debug("Leaving decrypt(). plaintext=" + (plain.length - 16));
      return plain.slice(16);
    },

    async checksum(baseKey, usage, message) {
      var kc = await this.checksumKey(baseKey, usage);
      return (await hmac(hashName, kc, message)).slice(0, macBytes);
    },

    async verifyChecksum(baseKey, usage, message, given) {
      return prim.equalConstantTime(await this.checksum(baseKey, usage, 
          message), given);
    }
  };
}

// ---------------------------------------------------------------------------
// etype 23, arcfour-hmac-md5 (RFC 4757).
//
// Legacy, and marked so. It is here because it is what the estates that need
// debugging are still running, and because its differences are instructive:
// the string-to-key is UNSALTED (MD4 of the UTF-16LE password — the NT hash),
// which is why AD's salt discovery matters only for AES, and why this etype
// behaves so differently under offline attack.
//
// Its key usage numbers are also not the protocol's: three of them are
// translated before use, a wart carried from an earlier draft.
// ---------------------------------------------------------------------------
function translateArcfourUsage(usage) {
  log.debug("Entering translateArcfourUsage().");
  if (usage === 3) {
    log.debug("Leaving translateArcfourUsage().");
    return 8;
  }
  if (usage === 9) {
    log.debug("Leaving translateArcfourUsage().");
    return 8;
  }
  if (usage === 23) {
    log.debug("Leaving translateArcfourUsage().");
    return 13;
  }
  log.debug("Leaving translateArcfourUsage().");
  return usage;
}

function le32(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, 
      (n >>> 24) & 0xff]);
}

var ARCFOUR = {
  id: 23,
  name: "arcfour-hmac-md5",
  keyBytes: 16,
  blockBytes: 1,
  confounderBytes: 8,
  checksumBytes: 16,
  checksumType: -138,                 // hmac-md5
  defaultIterations: 0,
  rfc: "RFC 4757",
  legacy: true,

  // No salt, no iteration count: the key is the NT hash of the password.
  async stringToKey(password) {
    log.debug("Entering stringToKey(). etype=arcfour-hmac-md5 (unsalted)");
    return prim.md4(prim.utf16le(password));
  },

  async encrypt(baseKey, usage, plaintext, confounderForTest) {
    log.debug("Entering encrypt(). etype=arcfour-hmac-md5, usage=" + usage);
    var t = le32(translateArcfourUsage(usage));
    var k1 = await hmac("MD5", baseKey, t);
    var k2 = k1;
    var conf = confounderForTest ? toBytes(confounderForTest) : randomBytes(8);
    var data = concat([conf, toBytes(plaintext)]);
    var cksum = await hmac("MD5", k2, data);
    var k3 = await hmac("MD5", k1, cksum);
    log.debug("Leaving encrypt().");
    return concat([cksum, prim.rc4(k3, data)]);
  },

  async decrypt(baseKey, usage, ciphertext) {
    log.debug("Entering decrypt(). etype=arcfour-hmac-md5, usage=" + usage);
    var data = toBytes(ciphertext);
    if (data.length < 16 + 8) {
      throw new Error("krb5: ciphertext too short for arcfour-hmac-md5");
    }
    var t = le32(translateArcfourUsage(usage));
    var k1 = await hmac("MD5", baseKey, t);
    var k2 = k1;
    var cksum = data.slice(0, 16);
    var k3 = await hmac("MD5", k1, cksum);
    var plain = prim.rc4(k3, data.slice(16));
    var expect = await hmac("MD5", k2, plain);
    if (!prim.equalConstantTime(cksum, expect)) {
      throw new Error("krb5: integrity check failed (arcfour-hmac-md5, usage " + 
          usage + ")");
    }
    log.debug("Leaving decrypt(). plaintext=" + (plain.length - 8));
    return plain.slice(8);
  },

  // RFC 4757 section 4: a signature key derived from a fixed string, then MD5
  // over the usage and the message, then HMAC of that.
  async checksum(baseKey, usage, message) {
    var ksign = await hmac("MD5", baseKey, concat([prim.utf8("signaturekey"), 
        new Uint8Array([0])]));
    var tmp = prim.md5(concat([le32(translateArcfourUsage(usage)), 
        toBytes(message)]));
    return hmac("MD5", ksign, tmp);
  },

  async verifyChecksum(baseKey, usage, message, given) {
    return prim.equalConstantTime(await this.checksum(baseKey, usage, message), 
        given);
  }
};

var ETYPES = {
  17: aesSha1Profile(17, "aes128-cts-hmac-sha1-96", 16),
  18: aesSha1Profile(18, "aes256-cts-hmac-sha1-96", 32),
  19: aesSha2Profile(19, "aes128-cts-hmac-sha256-128", 16, "SHA-256", 16),
  20: aesSha2Profile(20, "aes256-cts-hmac-sha384-192", 32, "SHA-384", 24),
  23: ARCFOUR
};

// Names for etypes this codec will DECODE but not perform, so that a capture
// or a KDC's advertised list renders honestly instead of showing a bare number.
var ETYPE_NAMES_UNSUPPORTED = {
  1: "des-cbc-crc",
  2: "des-cbc-md4",
  3: "des-cbc-md5",
  5: "des3-cbc-md5",
  7: "des3-cbc-sha1",
  16: "des3-cbc-sha1-kd",
  24: "arcfour-hmac-exp",
  25: "camellia128-cts-cmac",
  26: "camellia256-cts-cmac"
};

function etypeById(id) {
  var e = ETYPES[id];
  if (!e) {
    var known = ETYPE_NAMES_UNSUPPORTED[id];
    throw new Error("krb5: encryption type " + id +
      (known ? " (" + known + ") is not implemented here" : " is unknown") +
      (id >= 1 && id <= 7 ? " — DES was removed from Windows Server 2025 and " +
          "is decode-only here" : ""));
  }
  return e;
}

function etypeByName(name) {
  var ids = Object.keys(ETYPES);
  for (var i = 0; i < ids.length; i++) {
    if (ETYPES[ids[i]].name === name) {
      return ETYPES[ids[i]];
    }
  }
  throw new Error("krb5: no encryption type named " + name);
}

function etypeName(id) {
  return (ETYPES[id] && ETYPES[id].name) || ETYPE_NAMES_UNSUPPORTED[id] || (
      "etype-" + id);
}

// Preference order offered in an AS-REQ by default: the strongest first, with
// the legacy one last so a KDC that supports anything better chooses it.
var DEFAULT_ETYPE_PREFERENCE = [18, 17, 20, 19, 23];

module.exports = {
  ETYPES: ETYPES,
  KEY_USAGE: KEY_USAGE,
  DEFAULT_ETYPE_PREFERENCE: DEFAULT_ETYPE_PREFERENCE,
  etypeById: etypeById,
  etypeByName: etypeByName,
  etypeName: etypeName,
  isSupportedEtype: function (id) { return Object.prototype.hasOwnProperty.call(ETYPES, 
      id); },
  // Exposed for the vector tests, which have to reach the layers individually:
  // a passing end-to-end encryption can hide two compensating errors.
  ctsEncrypt: ctsEncrypt,
  ctsDecrypt: ctsDecrypt,
  cbcEncryptRaw: cbcEncryptRaw,
  cbcDecryptRaw: cbcDecryptRaw,
  deriveRandom: deriveRandom,
  kdfHmacSha2: kdfHmacSha2,
  usageConstant: usageConstant,
  hmac: hmac,
  pbkdf2: pbkdf2,
  randomBytes: randomBytes,
  translateArcfourUsage: translateArcfourUsage
};
