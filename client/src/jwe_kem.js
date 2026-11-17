// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jwe_kem.js
//
// ---------------------------------------------------------------------------
// KEM-BASED JWE KEY ESTABLISHMENT: ML-KEM, AND HPKE OVER DHKEM, ML-KEM AND
// THE PQ/T HYBRIDS (X-Wing among them).
//
// Every algorithm here is from an Internet-Draft, and the drafts disagree
// about which revision still has a JOSE binding, so the revisions are named:
//
//   ML-KEM-512, -768, -1024             draft-ietf-jose-pqc-kem-05
//   ML-KEM-512+A128KW, -768+A192KW,     (direct key agreement, and key
//   -1024+A256KW                        agreement with AES key wrap)
//
//   HPKE-0 … HPKE-7, and the -KE forms  draft-ietf-jose-hpke-encrypt-22
//   (no HPKE-4-KE or HPKE-6-KE: -22     (HPKE over the classical DHKEMs)
//   removed them)
//
//   HPKE-8 … HPKE-16, and the -KE forms draft-reddy-cose-jose-pqc-hybrid-
//                                       hpke-11 (HPKE over ML-KEM and the
//                                       three PQ/T hybrids; HPKE-10/11 are
//                                       X-Wing)
//
// WHY -05 OF pqc-kem. Revision -06 (July 2026) removed every JOSE section and
// is COSE-only; -05 is the last revision that defines a JWE algorithm, an
// `ek` header for the KEM ciphertext, and a KDF. ONE PLACE DEPARTS FROM -05,
// knowingly: -05 section 10 says an AKP `priv` is "the 32-byte seed", which
// cannot generate an ML-KEM key at all (FIPS 203's KeyGen_internal takes
// d AND z, 64 bytes). -06 corrected it to the 64-byte d || z seed, and
// draft-ietf-hpke-pq-05 uses the same 64-byte form, so that is what is read
// and written here. A 32-byte ML-KEM `priv` is refused by name.
//
// THE pqc-kem-05 KDF IS THE MOST LIKELY PLACE FOR TWO IMPLEMENTATIONS TO
// DISAGREE, because no draft publishes a vector for it. Section 5.1:
//
//   KMAC256(K = SS', X = AlgorithmID || SuppPubInfo, L, S = "")
//
// with AlgorithmID and SuppPubInfo exactly as RFC 7518 section 4.6.2 defines
// them — a 32-bit big-endian length followed by the ASCII name, and the key
// length in BITS as a 32-bit big-endian integer — and PartyUInfo and
// PartyVInfo OMITTED (not empty-with-a-length: absent). AlgorithmID is the
// `enc` value for direct key agreement and the `alg` value for key wrap,
// exactly as for ECDH-ES. L is in bits. tests/hpke_jwe_engine.js rebuilds
// this from that text with node's own SP 800-185 KMAC, sharing no code.
//
// HPKE IN JWE, AND THE ONE STRUCTURE THAT IS JOSE'S OWN. Key Encryption
// (`HPKE-n-KE`) seals the CEK with HPKE's single-shot API, with
//
//   info = "JOSE-HPKE rcpt" || 0xFF || enc || 0xFF || recipient_extra_info
//
// (the Recipient_structure, -22 section 6.1) and an EMPTY aad, and puts the
// encapsulated secret in the `ek` header. Integrated Encryption (`HPKE-n`)
// seals the PLAINTEXT with an EMPTY info and aad = ASCII(BASE64URL(protected
// header)); it has no `enc` and no `ek`, its JWE Encrypted Key IS the
// encapsulated secret, and its IV and tag segments are empty.
//
// PSK MODE. -22 allows HPKE's mode_psk for HPKE-0..7, selected by a
// `psk_id` header (the base64url of the identifier). draft-reddy-…-11
// section 5 allows only the base mode for HPKE-8..16, so a PSK given with one
// of those is refused.
//
// KEYS. Every ML-KEM and HPKE-8..16 key is a `kty: "AKP"` JWK whose `alg`
// names EXACTLY ONE of these algorithms — a key for ML-KEM-768 does not work
// for ML-KEM-768+A192KW or for HPKE-15, and that strictness is the drafts'
// (pqc-kem-05 section 10, -11 section 6). HPKE-0..7 use ordinary `EC` and
// `OKP` JWKs on the curve the suite names (-22 section 9). Keys are JWKs
// only: there is no PEM form of an X-Wing key in any specification.
//
// jose_jwe.js calls in here and does the rest: the AES key wrap, the content
// encryption and the five segments. NO DOM, and synchronous — nothing in
// here touches Web Crypto.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var sha3Addons = require("@noble/hashes/sha3-addons");
var hpke = require("./hpke");
var bytes = require("./crypto_bytes");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "jwe_kem",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var asBytes = bytes.asBytes;
var concatBytes = bytes.concatBytes;
var strBytes = bytes.strBytes;
var bytesToB64u = bytes.bytesToB64u;
var b64uToBytes = bytes.b64uToBytes;

var SPEC_PQC_KEM = "draft-ietf-jose-pqc-kem-05";
var SPEC_HPKE = "draft-ietf-jose-hpke-encrypt-22";
var SPEC_HYBRID = "draft-reddy-cose-jose-pqc-hybrid-hpke-11";

// ---------------------------------------------------------------------------
// THE ALGORITHMS
// ---------------------------------------------------------------------------
// ML-KEM (pqc-kem-05 section 8). `kwBytes` is the AES key wrap size for the
// key-wrap forms and null for direct key agreement.
var ML_KEM_ALGS = {
  "ML-KEM-512": { kem: "ML-KEM-512", kwBytes: null },
  "ML-KEM-768": { kem: "ML-KEM-768", kwBytes: null },
  "ML-KEM-1024": { kem: "ML-KEM-1024", kwBytes: null },
  "ML-KEM-512+A128KW": { kem: "ML-KEM-512", kwBytes: 16 },
  "ML-KEM-768+A192KW": { kem: "ML-KEM-768", kwBytes: 24 },
  "ML-KEM-1024+A256KW": { kem: "ML-KEM-1024", kwBytes: 32 }
};

// HPKE. kem / kdf / aead are the HPKE registry code points. `kty`/`crv` say
// what key the suite takes (-22 Table 3 for 0..7; AKP for 8..16).
var HPKE_SUITES = {
  "0": { kem: 0x0010, kdf: 0x0001, aead: 0x0001, kty: "EC", crv: "P-256",
         spec: SPEC_HPKE, ke: true },
  "1": { kem: 0x0011, kdf: 0x0002, aead: 0x0002, kty: "EC", crv: "P-384",
         spec: SPEC_HPKE, ke: true },
  "2": { kem: 0x0012, kdf: 0x0003, aead: 0x0002, kty: "EC", crv: "P-521",
         spec: SPEC_HPKE, ke: true },
  "3": { kem: 0x0020, kdf: 0x0001, aead: 0x0001, kty: "OKP", crv: "X25519",
         spec: SPEC_HPKE, ke: true },
  "4": { kem: 0x0020, kdf: 0x0001, aead: 0x0003, kty: "OKP", crv: "X25519",
         spec: SPEC_HPKE, ke: false },
  "5": { kem: 0x0021, kdf: 0x0003, aead: 0x0002, kty: "OKP", crv: "X448",
         spec: SPEC_HPKE, ke: true },
  "6": { kem: 0x0021, kdf: 0x0003, aead: 0x0003, kty: "OKP", crv: "X448",
         spec: SPEC_HPKE, ke: false },
  "7": { kem: 0x0010, kdf: 0x0001, aead: 0x0002, kty: "EC", crv: "P-256",
         spec: SPEC_HPKE, ke: true },
  "8": { kem: 0x0050, kdf: 0x0011, aead: 0x0002, kty: "AKP",
         spec: SPEC_HYBRID, ke: true },
  "9": { kem: 0x0050, kdf: 0x0011, aead: 0x0003, kty: "AKP",
         spec: SPEC_HYBRID, ke: true },
  "10": { kem: 0x647a, kdf: 0x0011, aead: 0x0002, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "11": { kem: 0x647a, kdf: 0x0011, aead: 0x0003, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "12": { kem: 0x0051, kdf: 0x0011, aead: 0x0002, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "13": { kem: 0x0051, kdf: 0x0011, aead: 0x0003, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "14": { kem: 0x0040, kdf: 0x0011, aead: 0x0001, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "15": { kem: 0x0041, kdf: 0x0011, aead: 0x0002, kty: "AKP",
          spec: SPEC_HYBRID, ke: true },
  "16": { kem: 0x0042, kdf: 0x0011, aead: 0x0002, kty: "AKP",
          spec: SPEC_HYBRID, ke: true }
};

var HPKE_ALGS = {};
(function buildHpkeAlgs() {
  Object.keys(HPKE_SUITES).forEach(function (n) {
    var s = HPKE_SUITES[n];
    var base = { kem: s.kem, kdf: s.kdf, aead: s.aead, kty: s.kty,
                 crv: s.crv, spec: s.spec };
    HPKE_ALGS["HPKE-" + n] = Object.assign({ integrated: true }, base);
    if (s.ke) {
      HPKE_ALGS["HPKE-" + n + "-KE"] = Object.assign({ integrated: false },
                                                      base);
    }
  });
})();

// The order the menus list them in: ML-KEM first, then HPKE by number with
// each suite's Integrated form before its Key Encryption form.
function algNames() {
  log.debug("Entering algNames().");
  var out = Object.keys(ML_KEM_ALGS);
  Object.keys(HPKE_SUITES).forEach(function (n) {
    out.push("HPKE-" + n);
    if (HPKE_SUITES[n].ke) {
      out.push("HPKE-" + n + "-KE");
    }
  });
  log.debug("Leaving algNames().");
  return out;
}

function isMlKemAlg(alg) {
  log.debug("Entering isMlKemAlg().");
  log.debug("Leaving isMlKemAlg().");
  return Object.prototype.hasOwnProperty.call(ML_KEM_ALGS, alg);
}

function isHpkeAlg(alg) {
  log.debug("Entering isHpkeAlg().");
  log.debug("Leaving isHpkeAlg().");
  return Object.prototype.hasOwnProperty.call(HPKE_ALGS, alg);
}

function isKemAlg(alg) {
  log.debug("Entering isKemAlg().");
  log.debug("Leaving isKemAlg().");
  return isMlKemAlg(alg) || isHpkeAlg(alg);
}

// Integrated Encryption: the JWE has no `enc`, and nothing else in JWE is
// like that.
function isIntegrated(alg) {
  log.debug("Entering isIntegrated().");
  log.debug("Leaving isIntegrated().");
  return isHpkeAlg(alg) && HPKE_ALGS[alg].integrated;
}

// What a page shows beside the algorithm: which draft, and what it is.
function describeAlg(alg) {
  log.debug("Entering describeAlg(). alg=" + alg);
  var out;
  if (isMlKemAlg(alg)) {
    var m = ML_KEM_ALGS[alg];
    out = { alg: alg, spec: SPEC_PQC_KEM, kty: "AKP",
            summary: m.kem + (m.kwBytes ? ", then A" + (m.kwBytes * 8) +
                     "KW of a random CEK" : " direct key agreement") +
                     "; KMAC256 KDF" };
  } else if (isHpkeAlg(alg)) {
    var h = HPKE_ALGS[alg];
    out = { alg: alg, spec: h.spec, kty: h.kty, crv: h.crv,
            summary: hpke.KEMS[h.kem].name + ", " + hpke.KDFS[h.kdf].name +
                     ", " + hpke.AEADS[h.aead].name + " — " +
                     (h.integrated ? "Integrated Encryption (no enc)" :
                      "Key Encryption of the CEK") };
  } else {
    log.debug("Leaving describeAlg(). Not a KEM alg.");
    return null;
  }
  log.debug("Leaving describeAlg().");
  return out;
}

// ---------------------------------------------------------------------------
// KEYS
// ---------------------------------------------------------------------------
function asJwkObject(key) {
  log.debug("Entering asJwkObject().");
  if (key && typeof key === "object") {
    log.debug("Leaving asJwkObject(). Object.");
    return key;
  }
  var text = String(key || "").trim();
  if (text.charAt(0) !== "{") {
    log.debug("Leaving asJwkObject(). Not JSON.");
    throw new Error("a KEM-based JWE algorithm takes its key as a JWK — " +
                    "there is no PEM form of an AKP KEM key in any " +
                    "specification.");
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving asJwkObject().");
    return parsed;
  } catch (e) {
    log.debug("Leaving asJwkObject(). Not parseable.");
    throw new Error("the key is not a readable JWK: " + e.message);
  }
}

function pad(b, len) {
  log.debug("Entering pad().");
  if (b.length >= len) {
    log.debug("Leaving pad().");
    return b;
  }
  var out = new Uint8Array(len);
  out.set(b, len - b.length);
  log.debug("Leaving pad().");
  return out;
}

// The KEM a JWE alg uses, and its key sizes.
function kemIdFor(alg) {
  log.debug("Entering kemIdFor(). alg=" + alg);
  if (isHpkeAlg(alg)) {
    log.debug("Leaving kemIdFor(). HPKE.");
    return HPKE_ALGS[alg].kem;
  }
  var byName = { "ML-KEM-512": 0x0040, "ML-KEM-768": 0x0041,
                 "ML-KEM-1024": 0x0042 };
  log.debug("Leaving kemIdFor(). ML-KEM.");
  return byName[ML_KEM_ALGS[alg].kem];
}

// A JWK -> { pub, priv } as the KEM's serialized bytes, refusing the shapes
// that would otherwise fail much later with a length error from inside a
// primitive. `needPrivate` says which half the caller is about to use.
function readKey(alg, key, needPrivate) {
  log.debug("Entering readKey(). alg=" + alg);
  var jwk = asJwkObject(key);
  var kemId = kemIdFor(alg);
  var kem = hpke.KEMS[kemId];
  var wantKty = isHpkeAlg(alg) ? HPKE_ALGS[alg].kty : "AKP";
  if (jwk.kty !== wantKty) {
    log.debug("Leaving readKey(). Wrong kty.");
    throw new Error(alg + " takes a kty \"" + wantKty + "\" key" +
                    (wantKty === "AKP" ? "" : " on " + HPKE_ALGS[alg].crv) +
                    "; this one is kty \"" + (jwk.kty || "(absent)") + "\".");
  }
  var out = { pub: null, priv: null, kid: jwk.kid };
  if (wantKty === "AKP") {
    // pqc-kem-05 section 10 and -11 section 6: the key names exactly one
    // algorithm, and that is the one it may be used with.
    if (jwk.alg !== alg) {
      log.debug("Leaving readKey(). AKP alg mismatch.");
      throw new Error("this AKP key is for \"" + (jwk.alg || "(no alg)") +
                      "\" and the JWE is " + alg + ". An AKP key names " +
                      "exactly one algorithm, so it is not used for " +
                      "another.");
    }
    if (jwk.pub) {
      out.pub = b64uToBytes(jwk.pub);
    }
    if (jwk.priv) {
      out.priv = b64uToBytes(jwk.priv);
    }
  } else if (wantKty === "EC") {
    if (jwk.crv !== HPKE_ALGS[alg].crv) {
      log.debug("Leaving readKey(). Wrong curve.");
      throw new Error(alg + " takes a " + HPKE_ALGS[alg].crv + " key; this " +
                      "one is on " + (jwk.crv || "(no crv)") + ".");
    }
    var coord = (kem.Npk - 1) / 2;
    if (jwk.x && jwk.y) {
      out.pub = concatBytes(new Uint8Array([0x04]),
                            pad(b64uToBytes(jwk.x), coord),
                            pad(b64uToBytes(jwk.y), coord));
    }
    if (jwk.d) {
      out.priv = pad(b64uToBytes(jwk.d), kem.Nsk);
    }
  } else {
    if (jwk.crv !== HPKE_ALGS[alg].crv) {
      log.debug("Leaving readKey(). Wrong curve.");
      throw new Error(alg + " takes an " + HPKE_ALGS[alg].crv + " key; " +
                      "this one is on " + (jwk.crv || "(no crv)") + ".");
    }
    if (jwk.x) {
      out.pub = b64uToBytes(jwk.x);
    }
    if (jwk.d) {
      out.priv = b64uToBytes(jwk.d);
    }
  }
  if (needPrivate) {
    if (!out.priv) {
      log.debug("Leaving readKey(). No private half.");
      throw new Error("decrypting " + alg + " needs the PRIVATE key; this " +
                      "JWK has only the public half.");
    }
    if (out.priv.length !== kem.Nsk) {
      log.debug("Leaving readKey(). Wrong private length.");
      throw new Error("a " + kem.name + " private key is " + kem.Nsk +
                      " bytes; this one is " + out.priv.length + "." +
                      (kem.Nsk === 64 && out.priv.length === 32 ?
                       " pqc-kem-05 section 10 says a 32-byte seed, which " +
                       "cannot generate an ML-KEM key; the 64-byte d || z " +
                       "seed (-06, and draft-ietf-hpke-pq-05) is required."
                       : ""));
    }
  } else {
    if (!out.pub && out.priv) {
      out.pub = hpke.publicKeyOf(kemId, out.priv);
    }
    if (!out.pub) {
      log.debug("Leaving readKey(). No public half.");
      throw new Error("encrypting with " + alg + " needs the recipient's " +
                      "public key; this JWK has none.");
    }
    if (out.pub.length !== kem.Npk) {
      log.debug("Leaving readKey(). Wrong public length.");
      throw new Error("a " + kem.name + " public key is " + kem.Npk +
                      " bytes; this one is " + out.pub.length + ".");
    }
  }
  log.debug("Leaving readKey().");
  return out;
}

// A fresh key pair for `alg`, as { publicJwk, privateJwk }. AKP for ML-KEM
// and HPKE-8..16; EC or OKP for HPKE-0..7. `use` and `alg` are set on both,
// so the public half can go straight into a JWKS.
function generateKeyPair(alg, kid) {
  log.debug("Entering generateKeyPair(). alg=" + alg);
  if (!isKemAlg(alg)) {
    log.debug("Leaving generateKeyPair(). Not a KEM alg.");
    throw new Error(alg + " is not a KEM-based JWE algorithm.");
  }
  var kemId = kemIdFor(alg);
  var kp = hpke.generateKeyPair(kemId);
  var kty = isHpkeAlg(alg) ? HPKE_ALGS[alg].kty : "AKP";
  var pub;
  var priv;
  if (kty === "AKP") {
    pub = { kty: "AKP", alg: alg, use: "enc", pub: bytesToB64u(kp.pk) };
    priv = Object.assign({}, pub, { priv: bytesToB64u(kp.sk) });
  } else if (kty === "EC") {
    var coord = (kp.pk.length - 1) / 2;
    pub = { kty: "EC", crv: HPKE_ALGS[alg].crv,
            x: bytesToB64u(kp.pk.slice(1, 1 + coord)),
            y: bytesToB64u(kp.pk.slice(1 + coord)), use: "enc", alg: alg };
    priv = Object.assign({}, pub, { d: bytesToB64u(kp.sk) });
  } else {
    pub = { kty: "OKP", crv: HPKE_ALGS[alg].crv, x: bytesToB64u(kp.pk),
            use: "enc", alg: alg };
    priv = Object.assign({}, pub, { d: bytesToB64u(kp.sk) });
  }
  if (kid) {
    pub.kid = kid;
    priv.kid = kid;
  }
  log.debug("Leaving generateKeyPair().");
  return { publicJwk: pub, privateJwk: priv };
}

// ---------------------------------------------------------------------------
// ML-KEM (pqc-kem-05)
// ---------------------------------------------------------------------------
// The section 5.1 KDF. `algorithmId` is `enc` (direct) or `alg` (key wrap);
// `keyBytes` is the length of the key wanted, which SuppPubInfo and L both
// carry in BITS.
function pqcKemKdf(sharedSecret, algorithmId, keyBytes) {
  log.debug("Entering pqcKemKdf(). algorithmId=" + algorithmId +
            ", keyBytes=" + keyBytes);
  var id = strBytes(algorithmId);
  var x = concatBytes(bytes.uint32be(id.length), id,
                      bytes.uint32be(keyBytes * 8));
  var out = sha3Addons.kmac256(asBytes(sharedSecret), x,
                               { dkLen: keyBytes,
                                 personalization: new Uint8Array(0) });
  log.debug("Leaving pqcKemKdf().");
  return out;
}

// Encrypting: { key, ek } where `key` is the CEK (direct) or the AES key
// wrapping key (key wrap) and `ek` the KEM ciphertext for the header.
// `cekBytes` is the CEK length the `enc` needs.
function mlkemAgree(alg, enc, recipientKey, cekBytes) {
  log.debug("Entering mlkemAgree(). alg=" + alg);
  var spec = ML_KEM_ALGS[alg];
  var k = readKey(alg, recipientKey, false);
  var r = hpke.mlkemEncaps(spec.kem, k.pub);
  var key = spec.kwBytes ? pqcKemKdf(r.ss, alg, spec.kwBytes)
                         : pqcKemKdf(r.ss, enc, cekBytes);
  log.debug("Leaving mlkemAgree().");
  return { key: key, ek: r.ct, kid: k.kid };
}

// Decrypting: the same key, from the `ek` header and the private seed.
function mlkemAgreeBack(alg, enc, ekB64u, recipientKey, cekBytes) {
  log.debug("Entering mlkemAgreeBack(). alg=" + alg);
  var spec = ML_KEM_ALGS[alg];
  if (typeof ekB64u !== "string" || !ekB64u) {
    log.debug("Leaving mlkemAgreeBack(). No ek.");
    throw new Error("an " + alg + " JWE must carry the KEM ciphertext in " +
                    "an \"ek\" header (pqc-kem-05 section 6).");
  }
  var k = readKey(alg, recipientKey, true);
  var dk = hpke.mlkemExpand(spec.kem, k.priv).dk;
  var ss = hpke.mlkemDecaps(spec.kem, dk, b64uToBytes(ekB64u));
  var key = spec.kwBytes ? pqcKemKdf(ss, alg, spec.kwBytes)
                         : pqcKemKdf(ss, enc, cekBytes);
  log.debug("Leaving mlkemAgreeBack().");
  return key;
}

function mlkemKwBytes(alg) {
  log.debug("Entering mlkemKwBytes().");
  log.debug("Leaving mlkemKwBytes().");
  return isMlKemAlg(alg) ? ML_KEM_ALGS[alg].kwBytes : null;
}

// ---------------------------------------------------------------------------
// HPKE (jose-hpke-encrypt-22, reddy-11)
// ---------------------------------------------------------------------------
function suiteOf(alg) {
  log.debug("Entering suiteOf().");
  var h = HPKE_ALGS[alg];
  log.debug("Leaving suiteOf().");
  return { kem: h.kem, kdf: h.kdf, aead: h.aead };
}

// -22 section 6.1.
function recipientStructure(enc, extraInfo) {
  log.debug("Entering recipientStructure(). enc=" + enc);
  var out = concatBytes(strBytes("JOSE-HPKE rcpt"), new Uint8Array([0xff]),
                        strBytes(enc), new Uint8Array([0xff]),
                        asBytes(extraInfo || new Uint8Array(0)));
  log.debug("Leaving recipientStructure().");
  return out;
}

// PSK options for HPKE: { psk, pskId } as bytes, or {} for the base mode.
// The header carries psk_id; reddy-11 allows only the base mode.
function pskOptions(alg, opts) {
  log.debug("Entering pskOptions().");
  var o = opts || {};
  if (!o.psk || !asBytes(o.psk).length) {
    log.debug("Leaving pskOptions(). Base mode.");
    return {};
  }
  if (HPKE_ALGS[alg].spec === SPEC_HYBRID) {
    log.debug("Leaving pskOptions(). PSK refused.");
    throw new Error(alg + ": " + SPEC_HYBRID + " section 5 allows only " +
                    "HPKE's base mode with ML-KEM and the hybrids, so no " +
                    "PSK.");
  }
  var pskId = asBytes(o.pskId || new Uint8Array(0));
  if (!pskId.length) {
    log.debug("Leaving pskOptions(). PSK without an id.");
    throw new Error("an HPKE PSK needs a psk_id to go with it.");
  }
  if (asBytes(o.psk).length < 32) {
    log.debug("Leaving pskOptions(). Short PSK.");
    throw new Error("an HPKE PSK MUST have at least 32 bytes of entropy " +
                    "(draft-ietf-hpke-hpke section 5.1.2); this one is " +
                    asBytes(o.psk).length + " bytes.");
  }
  log.debug("Leaving pskOptions(). PSK mode.");
  return { psk: asBytes(o.psk), pskId: pskId };
}

// Key Encryption, sending: the CEK sealed to the recipient.
function hpkeEncryptCek(alg, enc, cek, recipientKey, opts) {
  log.debug("Entering hpkeEncryptCek(). alg=" + alg);
  var k = readKey(alg, recipientKey, false);
  var psk = pskOptions(alg, opts);
  var sealed = hpke.seal(suiteOf(alg), k.pub, recipientStructure(enc),
                         new Uint8Array(0), cek, psk);
  log.debug("Leaving hpkeEncryptCek().");
  return { ek: sealed.enc, encryptedKey: sealed.ct, kid: k.kid,
           pskId: psk.pskId };
}

// Key Encryption, receiving.
function hpkeDecryptCek(alg, header, encryptedKey, recipientKey, opts) {
  log.debug("Entering hpkeDecryptCek(). alg=" + alg);
  if (typeof header.ek !== "string" || !header.ek) {
    log.debug("Leaving hpkeDecryptCek(). No ek.");
    throw new Error(alg + " is HPKE Key Encryption, which carries the " +
                    "encapsulated secret in an \"ek\" header; this JWE has " +
                    "none.");
  }
  var k = readKey(alg, recipientKey, true);
  var psk = pskFromHeader(alg, header, opts);
  var cek = hpke.open(suiteOf(alg), b64uToBytes(header.ek), k.priv,
                      recipientStructure(header.enc), new Uint8Array(0),
                      asBytes(encryptedKey), psk);
  log.debug("Leaving hpkeDecryptCek().");
  return cek;
}

function pskFromHeader(alg, header, opts) {
  log.debug("Entering pskFromHeader().");
  var o = opts || {};
  if (header.psk_id === undefined) {
    log.debug("Leaving pskFromHeader(). Base mode.");
    return {};
  }
  if (!o.psk) {
    log.debug("Leaving pskFromHeader(). No PSK supplied.");
    throw new Error("this JWE names psk_id \"" + header.psk_id + "\", so " +
                    "HPKE ran in PSK mode and the pre-shared key is needed " +
                    "to open it.");
  }
  log.debug("Leaving pskFromHeader().");
  return pskOptions(alg, { psk: o.psk, pskId: b64uToBytes(header.psk_id) });
}

// Integrated Encryption, sending. `protectedB64` is the ENCODED protected
// header (which must already carry psk_id if a PSK is used), whose ASCII is
// the HPKE aad. Returns the JWE Encrypted Key (the encapsulated secret) and
// the JWE Ciphertext (HPKE's ciphertext, tag included).
function hpkeIntegratedSeal(alg, protectedB64, plaintext, recipientKey,
                            opts) {
  log.debug("Entering hpkeIntegratedSeal(). alg=" + alg);
  var k = readKey(alg, recipientKey, false);
  var psk = pskOptions(alg, opts);
  var sealed = hpke.seal(suiteOf(alg), k.pub, new Uint8Array(0),
                         strBytes(protectedB64), asBytes(plaintext), psk);
  log.debug("Leaving hpkeIntegratedSeal().");
  return { encryptedKey: sealed.enc, ciphertext: sealed.ct };
}

function hpkeIntegratedOpen(alg, header, protectedB64, encryptedKey,
                            ciphertext, recipientKey, opts) {
  log.debug("Entering hpkeIntegratedOpen(). alg=" + alg);
  var k = readKey(alg, recipientKey, true);
  var psk = pskFromHeader(alg, header, opts);
  var pt = hpke.open(suiteOf(alg), asBytes(encryptedKey), k.priv,
                     new Uint8Array(0), strBytes(protectedB64),
                     asBytes(ciphertext), psk);
  log.debug("Leaving hpkeIntegratedOpen().");
  return pt;
}

// The private key a page holds, checked against a JWK's public half — so a
// pane can say "this is not the key the JWE was made for" before HPKE says
// only "OpenError".
function keyNames(alg) {
  log.debug("Entering keyNames().");
  var kty = isHpkeAlg(alg) ? HPKE_ALGS[alg].kty : "AKP";
  log.debug("Leaving keyNames().");
  return kty === "AKP" ? "an AKP JWK with alg \"" + alg + "\"" :
    "a " + kty + " JWK on " + HPKE_ALGS[alg].crv;
}

module.exports = {
  SPEC_PQC_KEM: SPEC_PQC_KEM,
  SPEC_HPKE: SPEC_HPKE,
  SPEC_HYBRID: SPEC_HYBRID,
  ML_KEM_ALGS: ML_KEM_ALGS,
  HPKE_ALGS: HPKE_ALGS,
  algNames: algNames,
  isMlKemAlg: isMlKemAlg,
  isHpkeAlg: isHpkeAlg,
  isKemAlg: isKemAlg,
  isIntegrated: isIntegrated,
  describeAlg: describeAlg,
  keyNames: keyNames,
  readKey: readKey,
  generateKeyPair: generateKeyPair,
  pqcKemKdf: pqcKemKdf,
  mlkemAgree: mlkemAgree,
  mlkemAgreeBack: mlkemAgreeBack,
  mlkemKwBytes: mlkemKwBytes,
  recipientStructure: recipientStructure,
  hpkeEncryptCek: hpkeEncryptCek,
  hpkeDecryptCek: hpkeDecryptCek,
  hpkeIntegratedSeal: hpkeIntegratedSeal,
  hpkeIntegratedOpen: hpkeIntegratedOpen
};
