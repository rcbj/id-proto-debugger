// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: hpke.js
//
// ---------------------------------------------------------------------------
// HYBRID PUBLIC KEY ENCRYPTION — the engine under the HPKE JWE algorithms.
//
// Three documents, read together, and none of them an RFC yet:
//
//   draft-ietf-hpke-hpke-02   HPKE itself (RFC 9180's successor): the
//                             DHKEMs, the two-stage HKDF key schedule, the
//                             ONE-STAGE key schedule a XOF uses, the
//                             base and PSK modes, Seal/Open and Export.
//   draft-ietf-hpke-pq-05     ML-KEM-512/768/1024 as HPKE KEMs, the three
//                             PQ/T hybrids as HPKE KEMs, and SHAKE128,
//                             SHAKE256, TurboSHAKE128 and TurboSHAKE256 as
//                             one-stage KDFs.
//   draft-irtf-cfrg-concrete-hybrid-kems-02 (over draft-irtf-cfrg-hybrid-
//                             kems-08)   what those three hybrids ARE: the
//                             CG framework — ML-KEM plus a "nominal group",
//                             a SHAKE256 seed expansion, and the C2PRI
//                             combiner SHA3-256(ss_PQ || ss_T || ct_T ||
//                             ek_T || label). MLKEM768-X25519 is X-Wing.
//
// jwe_kem.js is the JOSE half: it names the JWE algorithms
// (draft-ietf-jose-hpke-encrypt-22's HPKE-0..7 and
// draft-reddy-cose-jose-pqc-hybrid-hpke-11's HPKE-8..16) and builds the
// Recipient_structure. Nothing in THIS file knows JOSE exists.
//
// WHY IT IS WRITTEN HERE AND NOT TAKEN FROM A LIBRARY. The library that
// carries HPKE and the hybrids (@noble/post-quantum 0.5+, @hpke/*) is ESM
// only, and browserify cannot load it — the module header of pqc.js records
// that constraint. What this file DOES take from libraries is every
// primitive: ML-KEM from @noble/post-quantum 0.4.1, the curves, HKDF, SHAKE,
// TurboSHAKE and SHA3 from @noble, and the AEADs from symmetric_crypto.js.
// The part written here is the composition, which is exactly the part a
// published test vector checks: tests/hpke_jwe_engine.js holds every function
// below to draft-ietf-hpke-pq-05's own vectors (DeriveKeyPair, Encap from the
// vector's ikmE, the key schedule, every encryption and every export) and to
// the concrete hybrid KEM draft's.
//
// EVERYTHING IS SYNCHRONOUS. Nothing here touches Web Crypto, so it works on
// a plain-HTTP origin and in node, and a JWE pane can call it without an
// await chain.
//
// NO DOM.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var mlkem = require("@noble/post-quantum/ml-kem.js");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var x25519 = require("@noble/curves/ed25519").x25519;
var x448 = require("@noble/curves/ed448").x448;
var hkdf = require("@noble/hashes/hkdf");
var sha256 = require("@noble/hashes/sha256").sha256;
var sha2 = require("@noble/hashes/sha512");
var sha3 = require("@noble/hashes/sha3");
var sha3Addons = require("@noble/hashes/sha3-addons");
var bytes = require("./crypto_bytes");
var symmetric = require("./symmetric_crypto");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "hpke",
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

var MODE_BASE = 0x00;
var MODE_PSK = 0x01;
var HPKE_V1 = strBytes("HPKE-v1");

// I2OSP(n, w): n as a w-byte big-endian integer.
function i2osp(n, w) {
  log.debug("Entering i2osp().");
  var out = new Uint8Array(w);
  var v = n;
  for (var i = w - 1; i >= 0; i--) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  log.debug("Leaving i2osp().");
  return out;
}

// lengthPrefixed(x) = I2OSP(len(x), 2) || x. A one-stage KDF prefixes
// every variable-length input, which is the whole of its domain separation.
function lengthPrefixed(x) {
  log.debug("Entering lengthPrefixed().");
  var b = asBytes(x);
  if (b.length > 65535) {
    log.debug("Leaving lengthPrefixed(). Too long.");
    throw new Error("HPKE: an input to a one-stage KDF is limited to " +
                    "65535 bytes; this one is " + b.length + ".");
  }
  log.debug("Leaving lengthPrefixed().");
  return concatBytes(i2osp(b.length, 2), b);
}

function bigFromBytes(b) {
  log.debug("Entering bigFromBytes().");
  var n = BigInt(0);
  for (var i = 0; i < b.length; i++) {
    n = (n << BigInt(8)) | BigInt(b[i]);
  }
  log.debug("Leaving bigFromBytes().");
  return n;
}

// ---------------------------------------------------------------------------
// KDFs
// ---------------------------------------------------------------------------
// A two-stage KDF is HKDF (Extract, then Expand); a one-stage KDF is a XOF
// that takes the whole labelled input at once (Derive). The key schedule,
// the DHKEM's ExtractAndExpand and DeriveKeyPair, and Export all differ by
// which kind the suite has, so each KDF says which it is.
var KDFS = {
  0x0001: { name: "HKDF-SHA256", twoStage: true, hash: sha256, Nh: 32 },
  0x0002: { name: "HKDF-SHA384", twoStage: true, hash: sha2.sha384, Nh: 48 },
  0x0003: { name: "HKDF-SHA512", twoStage: true, hash: sha2.sha512, Nh: 64 },
  0x0010: { name: "SHAKE128", twoStage: false, Nh: 32,
            derive: function (ikm, L) {
              log.debug("Entering shake128 derive(). L=" + L);
              var out = sha3.shake128(ikm, { dkLen: L });
              log.debug("Leaving shake128 derive().");
              return out;
            } },
  0x0011: { name: "SHAKE256", twoStage: false, Nh: 64,
            derive: function (ikm, L) {
              log.debug("Entering shake256 derive(). L=" + L);
              var out = sha3.shake256(ikm, { dkLen: L });
              log.debug("Leaving shake256 derive().");
              return out;
            } },
  // TurboSHAKE with the domain separation byte 0x1f, which is TurboSHAKE's
  // own default and what draft-ietf-hpke-pq-05 section 5 names.
  0x0012: { name: "TurboSHAKE128", twoStage: false, Nh: 32,
            derive: function (ikm, L) {
              log.debug("Entering turboshake128 derive(). L=" + L);
              var out = sha3Addons.turboshake128(ikm, { dkLen: L, D: 0x1f });
              log.debug("Leaving turboshake128 derive().");
              return out;
            } },
  0x0013: { name: "TurboSHAKE256", twoStage: false, Nh: 64,
            derive: function (ikm, L) {
              log.debug("Entering turboshake256 derive(). L=" + L);
              var out = sha3Addons.turboshake256(ikm, { dkLen: L, D: 0x1f });
              log.debug("Leaving turboshake256 derive().");
              return out;
            } }
};

function kdfOf(id) {
  log.debug("Entering kdfOf(). id=" + id);
  var kdf = KDFS[id];
  if (!kdf) {
    log.debug("Leaving kdfOf(). Unknown.");
    throw new Error("HPKE: KDF 0x" + Number(id).toString(16) +
                    " is not one this implementation has.");
  }
  log.debug("Leaving kdfOf().");
  return kdf;
}

// LabeledExtract / LabeledExpand (two-stage) and LabeledDerive (one-stage).
// suite_id is passed explicitly here rather than being "implicit from the
// implementation": the same functions serve the KEM ("KEM" || kem_id) and
// the rest of HPKE ("HPKE" || kem_id || kdf_id || aead_id).
function labeledExtract(kdf, suiteId, salt, label, ikm) {
  log.debug("Entering labeledExtract(). label=" + label);
  var labeled = concatBytes(HPKE_V1, suiteId, strBytes(label), asBytes(ikm));
  var out = hkdf.extract(kdf.hash, labeled, asBytes(salt));
  log.debug("Leaving labeledExtract().");
  return out;
}

function labeledExpand(kdf, suiteId, prk, label, info, L) {
  log.debug("Entering labeledExpand(). label=" + label + ", L=" + L);
  var labeled = concatBytes(i2osp(L, 2), HPKE_V1, suiteId, strBytes(label),
                            asBytes(info));
  var out = hkdf.expand(kdf.hash, prk, labeled, L);
  log.debug("Leaving labeledExpand().");
  return out;
}

function labeledDerive(kdf, suiteId, ikm, label, context, L) {
  log.debug("Entering labeledDerive(). label=" + label + ", L=" + L);
  var labeled = concatBytes(asBytes(ikm), HPKE_V1, suiteId,
                            lengthPrefixed(strBytes(label)), i2osp(L, 2),
                            asBytes(context));
  var out = kdf.derive(labeled, L);
  log.debug("Leaving labeledDerive().");
  return out;
}

// ---------------------------------------------------------------------------
// AEADs — symmetric_crypto.js, which tests/crypto_engines.js holds to the
// RFCs' own vectors. HPKE wants the tag APPENDED to the ciphertext; that
// module keeps it apart, so the difference is absorbed here.
// ---------------------------------------------------------------------------
var AEADS = {
  0x0001: { name: "AES-128-GCM", cipher: "AES-128-GCM", Nk: 16, Nn: 12,
            Nt: 16 },
  0x0002: { name: "AES-256-GCM", cipher: "AES-256-GCM", Nk: 32, Nn: 12,
            Nt: 16 },
  0x0003: { name: "ChaCha20Poly1305", cipher: "CHACHA20-POLY1305", Nk: 32,
            Nn: 12, Nt: 16 }
};

function aeadOf(id) {
  log.debug("Entering aeadOf(). id=" + id);
  var aead = AEADS[id];
  if (!aead) {
    log.debug("Leaving aeadOf(). Unknown.");
    throw new Error("HPKE: AEAD 0x" + Number(id).toString(16) +
                    " is not one this implementation has.");
  }
  log.debug("Leaving aeadOf().");
  return aead;
}

function aeadSeal(aead, key, nonce, aad, pt) {
  log.debug("Entering aeadSeal(). " + aead.name);
  var out = symmetric.encrypt({ id: aead.cipher, key: key, iv: nonce,
                                aad: asBytes(aad), plaintext: asBytes(pt) });
  log.debug("Leaving aeadSeal().");
  return concatBytes(out.ciphertext, out.tag);
}

function aeadOpen(aead, key, nonce, aad, ct) {
  log.debug("Entering aeadOpen(). " + aead.name);
  var c = asBytes(ct);
  if (c.length < aead.Nt) {
    log.debug("Leaving aeadOpen(). Shorter than the tag.");
    throw new Error("HPKE OpenError: the ciphertext is shorter than the " +
                    aead.Nt + "-byte tag.");
  }
  var plain;
  try {
    plain = symmetric.decrypt({ id: aead.cipher, key: key, iv: nonce,
                                aad: asBytes(aad),
                                ciphertext: c.slice(0, c.length - aead.Nt),
                                tag: c.slice(c.length - aead.Nt) });
  } catch (e) {
    log.debug("Leaving aeadOpen(). The tag does not verify.");
    throw new Error("HPKE OpenError: the " + aead.name + " tag did not " +
                    "verify — the wrong key, or an altered message (" +
                    e.message + ")");
  }
  log.debug("Leaving aeadOpen().");
  return plain;
}

// ---------------------------------------------------------------------------
// DH GROUPS — for the DHKEMs and for the traditional half of a hybrid.
// ---------------------------------------------------------------------------
// `Ndh` is the size of the shared secret: the x-coordinate for the NIST
// curves, the whole output for X25519/X448. `Nscalar` is the scalar length
// RandomScalar reads, and `order` is what the rejection sampling of both
// DeriveKeyPair (DHKEM) and RandomScalar (the CG framework) compares
// against.
var GROUPS = {
  "P-256": { curve: p256, nist: true, Ndh: 32, Npk: 65, Nsk: 32,
             bitmask: 0xff },
  "P-384": { curve: p384, nist: true, Ndh: 48, Npk: 97, Nsk: 48,
             bitmask: 0xff },
  "P-521": { curve: p521, nist: true, Ndh: 66, Npk: 133, Nsk: 66,
             bitmask: 0x01 },
  "X25519": { curve: x25519, nist: false, Ndh: 32, Npk: 32, Nsk: 32 },
  "X448": { curve: x448, nist: false, Ndh: 56, Npk: 56, Nsk: 56 }
};

function groupPublicKey(group, sk) {
  log.debug("Entering groupPublicKey().");
  var g = GROUPS[group];
  var pk = g.nist ? g.curve.getPublicKey(asBytes(sk), false)
                  : g.curve.getPublicKey(asBytes(sk));
  log.debug("Leaving groupPublicKey().");
  return asBytes(pk);
}

// DH(sk, pk). For the NIST curves the public key is validated (it must be an
// uncompressed point on the curve — noble's fromHex checks both) and the
// result is the x-coordinate. For X25519/X448 an all-zero output is the
// ValidationError of draft-ietf-hpke-hpke-02 section 7.1.4 when `checkZero`
// is set; X-Wing (and so the CG framework) deliberately omits that check.
function groupDh(group, sk, pk, checkZero) {
  log.debug("Entering groupDh(). " + group);
  var g = GROUPS[group];
  var pkBytes = asBytes(pk);
  if (pkBytes.length !== g.Npk) {
    log.debug("Leaving groupDh(). Wrong public key length.");
    throw new Error("HPKE ValidationError: a " + group + " public key is " +
                    g.Npk + " bytes; this one is " + pkBytes.length + ".");
  }
  var out;
  if (g.nist) {
    if (pkBytes[0] !== 0x04) {
      log.debug("Leaving groupDh(). Not uncompressed.");
      throw new Error("HPKE ValidationError: a " + group + " public key " +
                      "must be an uncompressed point (0x04 || x || y).");
    }
    try {
      g.curve.ProjectivePoint.fromHex(pkBytes).assertValidity();
    } catch (e) {
      log.debug("Leaving groupDh(). Not on the curve.");
      throw new Error("HPKE ValidationError: the " + group + " public key " +
                      "is not a point on the curve (" + e.message + ").");
    }
    var shared = asBytes(g.curve.getSharedSecret(asBytes(sk), pkBytes, true));
    out = shared.slice(1, 1 + g.Ndh);
  } else {
    out = asBytes(g.curve.getSharedSecret(asBytes(sk), pkBytes));
    if (checkZero && out.every(function (b) {
      return b === 0;
    })) {
      log.debug("Leaving groupDh(). All-zero output.");
      throw new Error("HPKE ValidationError: the " + group + " shared " +
                      "secret is all zero — a low-order public key.");
    }
  }
  log.debug("Leaving groupDh().");
  return out;
}

// ---------------------------------------------------------------------------
// KEMs
// ---------------------------------------------------------------------------
var ML_KEM = {
  "ML-KEM-512": { prim: mlkem.ml_kem512, k: 2, Npk: 800, Nct: 768 },
  "ML-KEM-768": { prim: mlkem.ml_kem768, k: 3, Npk: 1184, Nct: 1088 },
  "ML-KEM-1024": { prim: mlkem.ml_kem1024, k: 4, Npk: 1568, Nct: 1568 }
};

// FIPS 203 section 7.2's encapsulation key check: every 12-bit coefficient of
// the encoded vector t is reduced modulo q = 3329, i.e. ByteEncode(
// ByteDecode(ek)) == ek. noble 0.4.1 does not perform it, and
// draft-ietf-hpke-pq-05 section 3 makes a failure an EncapError.
function mlkemCheckEncapsulationKey(name, ek) {
  log.debug("Entering mlkemCheckEncapsulationKey(). " + name);
  var p = ML_KEM[name];
  if (ek.length !== p.Npk) {
    log.debug("Leaving mlkemCheckEncapsulationKey(). Wrong length.");
    throw new Error("HPKE EncapError: an " + name + " encapsulation key is " +
                    p.Npk + " bytes; this one is " + ek.length + ".");
  }
  var n = 384 * p.k;
  for (var i = 0; i < n; i += 3) {
    var a = ek[i] | ((ek[i + 1] & 0x0f) << 8);
    var b = (ek[i + 1] >> 4) | (ek[i + 2] << 4);
    if (a >= 3329 || b >= 3329) {
      log.debug("Leaving mlkemCheckEncapsulationKey(). Not reduced.");
      throw new Error("HPKE EncapError: the " + name + " encapsulation " +
                      "key fails FIPS 203's modulus check.");
    }
  }
  log.debug("Leaving mlkemCheckEncapsulationKey().");
}

// A 64-byte seed d || z -> { ek, dkExpanded }. ML-KEM.KeyGen_internal(d, z)
// is what noble's keygen() performs on a 64-byte seed.
function mlkemExpand(name, seed) {
  log.debug("Entering mlkemExpand(). " + name);
  var s = asBytes(seed);
  if (s.length !== 64) {
    log.debug("Leaving mlkemExpand(). Wrong seed length.");
    throw new Error("An " + name + " private key is the 64-byte seed d || " +
                    "z; this one is " + s.length + " bytes.");
  }
  var kp = ML_KEM[name].prim.keygen(s);
  log.debug("Leaving mlkemExpand().");
  return { ek: asBytes(kp.publicKey), dk: asBytes(kp.secretKey) };
}

function mlkemEncaps(name, ek, m) {
  log.debug("Entering mlkemEncaps(). " + name);
  var ekBytes = asBytes(ek);
  mlkemCheckEncapsulationKey(name, ekBytes);
  var r = ML_KEM[name].prim.encapsulate(ekBytes,
                                        m ? asBytes(m) : undefined);
  log.debug("Leaving mlkemEncaps().");
  return { ss: asBytes(r.sharedSecret), ct: asBytes(r.cipherText) };
}

function mlkemDecaps(name, dkExpanded, ct) {
  log.debug("Entering mlkemDecaps(). " + name);
  var c = asBytes(ct);
  if (c.length !== ML_KEM[name].Nct) {
    log.debug("Leaving mlkemDecaps(). Wrong ciphertext length.");
    throw new Error("HPKE DecapError: an " + name + " ciphertext is " +
                    ML_KEM[name].Nct + " bytes; this one is " + c.length +
                    ".");
  }
  var ss = asBytes(ML_KEM[name].prim.decapsulate(c, dkExpanded));
  log.debug("Leaving mlkemDecaps().");
  return ss;
}

// THE CG FRAMEWORK'S NOMINAL GROUPS (concrete-hybrid-kems section 3.1).
// Nseed is how much of the expanded seed the traditional half consumes:
// RandomScalar reads Nscalar bytes at a time and moves on past a rejected
// one, so P-256's 128 bytes are four candidates and P-384's 48 are one.
var NOMINAL = {
  "P-256": { group: "P-256", Nseed: 128, Nscalar: 32, Nelem: 65, Nss: 32 },
  "P-384": { group: "P-384", Nseed: 48, Nscalar: 48, Nelem: 97, Nss: 48 },
  "X25519": { group: "X25519", Nseed: 32, Nscalar: 32, Nelem: 32, Nss: 32 }
};

// RandomScalar(seed) -> the scalar as bytes. For X25519 it is the seed
// itself (32 bytes, clamped inside X25519); for the NIST curves, rejection
// sampling over consecutive Nscalar-byte windows.
function randomScalar(nominal, seed) {
  log.debug("Entering randomScalar(). " + nominal.group);
  var s = asBytes(seed);
  if (nominal.group === "X25519") {
    log.debug("Leaving randomScalar(). X25519.");
    return s.slice(0, 32);
  }
  var order = GROUPS[nominal.group].curve.CURVE.n;
  for (var start = 0; start + nominal.Nscalar <= s.length;
       start += nominal.Nscalar) {
    var candidate = s.slice(start, start + nominal.Nscalar);
    var k = bigFromBytes(candidate);
    if (k !== BigInt(0) && k < order) {
      log.debug("Leaving randomScalar(). Window " +
                (start / nominal.Nscalar) + ".");
      return candidate;
    }
  }
  log.debug("Leaving randomScalar(). Rejection sampling failed.");
  throw new Error("RandomScalar: rejection sampling failed for " +
                  nominal.group + " (cryptographically negligible unless " +
                  "the seed is not random).");
}

function nominalExp(nominal, point, scalar) {
  log.debug("Entering nominalExp(). " + nominal.group);
  var out;
  if (nominal.group === "X25519") {
    out = asBytes(x25519.getSharedSecret(asBytes(scalar), asBytes(point)));
  } else {
    var g = GROUPS[nominal.group];
    var pkBytes = asBytes(point);
    if (pkBytes.length !== nominal.Nelem || pkBytes[0] !== 0x04) {
      log.debug("Leaving nominalExp(). Not an uncompressed point.");
      throw new Error(nominal.group + ": the element must be an " +
                      nominal.Nelem + "-byte uncompressed point.");
    }
    g.curve.ProjectivePoint.fromHex(pkBytes).assertValidity();
    // ElementToSharedSecret: the x-coordinate, Nss bytes.
    out = asBytes(g.curve.getSharedSecret(asBytes(scalar), pkBytes, true))
      .slice(1, 1 + nominal.Nss);
  }
  log.debug("Leaving nominalExp().");
  return out;
}

function nominalBase(nominal, scalar) {
  log.debug("Entering nominalBase(). " + nominal.group);
  var out = nominal.group === "X25519"
    ? asBytes(x25519.getPublicKey(asBytes(scalar)))
    : asBytes(GROUPS[nominal.group].curve.getPublicKey(asBytes(scalar),
                                                       false));
  log.debug("Leaving nominalBase().");
  return out;
}

// The hybrid KEM's own interface (concrete-hybrid-kems section 4, CG
// framework of hybrid-kems section 5.5). `dk` is the 32-byte seed; the
// component keys are re-derived from it on every use.
function cgExpand(h, seed) {
  log.debug("Entering cgExpand(). " + h.label);
  var s = asBytes(seed);
  if (s.length !== 32) {
    log.debug("Leaving cgExpand(). Wrong seed length.");
    throw new Error("A " + h.name + " private key is the 32-byte seed; " +
                    "this one is " + s.length + " bytes.");
  }
  var nominal = NOMINAL[h.group];
  var full = sha3.shake256(s, { dkLen: 64 + nominal.Nseed });
  var pq = mlkemExpand(h.pq, full.slice(0, 64));
  var dkT = randomScalar(nominal, full.slice(64));
  var ekT = nominalBase(nominal, dkT);
  log.debug("Leaving cgExpand().");
  return { ekPq: pq.ek, dkPq: pq.dk, ekT: ekT, dkT: dkT,
           ek: concatBytes(pq.ek, ekT) };
}

function cgCombine(h, ssPq, ssT, ctT, ekT) {
  log.debug("Entering cgCombine(). " + h.name);
  var out = sha3.sha3_256(concatBytes(ssPq, ssT, ctT, ekT, h.labelBytes));
  log.debug("Leaving cgCombine().");
  return out;
}

// `randomness` (optional) is what the test vectors call it: 32 bytes of ML-KEM
// encapsulation randomness followed by the group's Nseed bytes for the
// ephemeral scalar. Ordinary callers omit it.
function cgEncaps(h, ek, randomness) {
  log.debug("Entering cgEncaps(). " + h.name);
  var nominal = NOMINAL[h.group];
  var ekBytes = asBytes(ek);
  var npk = ML_KEM[h.pq].Npk;
  if (ekBytes.length !== npk + nominal.Nelem) {
    log.debug("Leaving cgEncaps(). Wrong key length.");
    throw new Error("HPKE EncapError: a " + h.name + " encapsulation key " +
                    "is " + (npk + nominal.Nelem) + " bytes; this one is " +
                    ekBytes.length + ".");
  }
  var rnd = randomness ? asBytes(randomness)
                       : bytes.randomBytes(32 + nominal.Nseed);
  var ekPq = ekBytes.slice(0, npk);
  var ekT = ekBytes.slice(npk);
  var pq = mlkemEncaps(h.pq, ekPq, rnd.slice(0, 32));
  var skE = randomScalar(nominal, rnd.slice(32));
  var ctT = nominalBase(nominal, skE);
  var ssT = nominalExp(nominal, ekT, skE);
  log.debug("Leaving cgEncaps().");
  return { ss: cgCombine(h, pq.ss, ssT, ctT, ekT),
           ct: concatBytes(pq.ct, ctT) };
}

function cgDecaps(h, seed, ct) {
  log.debug("Entering cgDecaps(). " + h.name);
  var nominal = NOMINAL[h.group];
  var c = asBytes(ct);
  var nct = ML_KEM[h.pq].Nct;
  if (c.length !== nct + nominal.Nelem) {
    log.debug("Leaving cgDecaps(). Wrong ciphertext length.");
    throw new Error("HPKE DecapError: a " + h.name + " ciphertext is " +
                    (nct + nominal.Nelem) + " bytes; this one is " +
                    c.length + ".");
  }
  var keys = cgExpand(h, seed);
  var ctT = c.slice(nct);
  var ssPq = mlkemDecaps(h.pq, keys.dkPq, c.slice(0, nct));
  var ssT = nominalExp(nominal, ctT, keys.dkT);
  log.debug("Leaving cgDecaps().");
  return cgCombine(h, ssPq, ssT, ctT, keys.ekT);
}

// The concrete hybrids. `labelBytes` is ASCII except X-Wing's, which is the
// six bytes 5c 2e 2f 2f 5e 5c — `\.//^\` — written as bytes because every
// backslash in a string literal is a chance to shorten it silently.
var HYBRIDS = {
  "MLKEM768-P256": { name: "MLKEM768-P256", pq: "ML-KEM-768",
                     group: "P-256", label: "MLKEM768-P256",
                     labelBytes: strBytes("MLKEM768-P256") },
  "MLKEM768-X25519": { name: "MLKEM768-X25519", pq: "ML-KEM-768",
                       group: "X25519", label: "X-Wing",
                       labelBytes: new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f,
                                                   0x5e, 0x5c]) },
  "MLKEM1024-P384": { name: "MLKEM1024-P384", pq: "ML-KEM-1024",
                      group: "P-384", label: "MLKEM1024-P384",
                      labelBytes: strBytes("MLKEM1024-P384") }
};

// The HPKE KEM registry this module implements. `kdf` on a DHKEM is the
// KEM's OWN KDF, which is used for its ExtractAndExpand and DeriveKeyPair
// whatever the suite's KDF is.
var KEMS = {
  0x0010: { name: "DHKEM(P-256, HKDF-SHA256)", kind: "dh", group: "P-256",
            kdf: 0x0001, Nsecret: 32, Nenc: 65, Npk: 65, Nsk: 32 },
  0x0011: { name: "DHKEM(P-384, HKDF-SHA384)", kind: "dh", group: "P-384",
            kdf: 0x0002, Nsecret: 48, Nenc: 97, Npk: 97, Nsk: 48 },
  0x0012: { name: "DHKEM(P-521, HKDF-SHA512)", kind: "dh", group: "P-521",
            kdf: 0x0003, Nsecret: 64, Nenc: 133, Npk: 133, Nsk: 66 },
  0x0020: { name: "DHKEM(X25519, HKDF-SHA256)", kind: "dh", group: "X25519",
            kdf: 0x0001, Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32 },
  0x0021: { name: "DHKEM(X448, HKDF-SHA512)", kind: "dh", group: "X448",
            kdf: 0x0003, Nsecret: 64, Nenc: 56, Npk: 56, Nsk: 56 },
  0x0040: { name: "ML-KEM-512", kind: "mlkem", pq: "ML-KEM-512",
            Nsecret: 32, Nenc: 768, Npk: 800, Nsk: 64 },
  0x0041: { name: "ML-KEM-768", kind: "mlkem", pq: "ML-KEM-768",
            Nsecret: 32, Nenc: 1088, Npk: 1184, Nsk: 64 },
  0x0042: { name: "ML-KEM-1024", kind: "mlkem", pq: "ML-KEM-1024",
            Nsecret: 32, Nenc: 1568, Npk: 1568, Nsk: 64 },
  0x0050: { name: "MLKEM768-P256", kind: "hybrid", hybrid: "MLKEM768-P256",
            Nsecret: 32, Nenc: 1153, Npk: 1249, Nsk: 32 },
  0x0051: { name: "MLKEM1024-P384", kind: "hybrid",
            hybrid: "MLKEM1024-P384", Nsecret: 32, Nenc: 1665, Npk: 1665,
            Nsk: 32 },
  0x647a: { name: "MLKEM768-X25519 (X-Wing)", kind: "hybrid",
            hybrid: "MLKEM768-X25519", Nsecret: 32, Nenc: 1120, Npk: 1216,
            Nsk: 32 }
};

function kemOf(id) {
  log.debug("Entering kemOf(). id=" + id);
  var kem = KEMS[id];
  if (!kem) {
    log.debug("Leaving kemOf(). Unknown.");
    throw new Error("HPKE: KEM 0x" + Number(id).toString(16) +
                    " is not one this implementation has.");
  }
  log.debug("Leaving kemOf().");
  return kem;
}

function kemSuiteId(kemId) {
  log.debug("Entering kemSuiteId().");
  log.debug("Leaving kemSuiteId().");
  return concatBytes(strBytes("KEM"), i2osp(kemId, 2));
}

// The DHKEM's ExtractAndExpand, always with the KEM's own two-stage HKDF.
function dhkemExtractAndExpand(kemId, dh, kemContext) {
  log.debug("Entering dhkemExtractAndExpand().");
  var kem = KEMS[kemId];
  var kdf = KDFS[kem.kdf];
  var sid = kemSuiteId(kemId);
  var prk = labeledExtract(kdf, sid, new Uint8Array(0), "eae_prk", dh);
  var out = labeledExpand(kdf, sid, prk, "shared_secret", kemContext,
                          kem.Nsecret);
  log.debug("Leaving dhkemExtractAndExpand().");
  return out;
}

// DeriveKeyPair(ikm) -> { sk, pk }, serialized. The DHKEMs follow
// draft-ietf-hpke-hpke-02 section 7.1.3 with their own HKDF; the ML-KEM and
// hybrid KEMs follow draft-ietf-hpke-pq-05 sections 3 and 4, which use the
// SHAKE256 one-stage KDF and the label "DeriveKeyPair".
function deriveKeyPair(kemId, ikm) {
  log.debug("Entering deriveKeyPair(). kem=0x" + kemId.toString(16));
  var kem = kemOf(kemId);
  var sid = kemSuiteId(kemId);
  var out;
  if (kem.kind === "dh") {
    var g = GROUPS[kem.group];
    var kdf = KDFS[kem.kdf];
    var prk = labeledExtract(kdf, sid, new Uint8Array(0), "dkp_prk", ikm);
    if (!g.nist) {
      var skX = labeledExpand(kdf, sid, prk, "sk", new Uint8Array(0),
                              kem.Nsk);
      out = { sk: skX, pk: groupPublicKey(kem.group, skX) };
      log.debug("Leaving deriveKeyPair(). Montgomery.");
      return out;
    }
    var order = g.curve.CURVE.n;
    for (var counter = 0; counter <= 255; counter++) {
      var candidate = labeledExpand(kdf, sid, prk, "candidate",
                                    i2osp(counter, 1), kem.Nsk);
      candidate[0] = candidate[0] & g.bitmask;
      var n = bigFromBytes(candidate);
      if (n !== BigInt(0) && n < order) {
        out = { sk: candidate, pk: groupPublicKey(kem.group, candidate) };
        log.debug("Leaving deriveKeyPair(). NIST curve, counter " +
                  counter + ".");
        return out;
      }
    }
    log.debug("Leaving deriveKeyPair(). DeriveKeyPairError.");
    throw new Error("HPKE DeriveKeyPairError: no valid scalar in 256 " +
                    "candidates.");
  }
  var shake = KDFS[0x0011];
  if (kem.kind === "mlkem") {
    var dk = labeledDerive(shake, sid, ikm, "DeriveKeyPair",
                           new Uint8Array(0), 64);
    out = { sk: dk, pk: mlkemExpand(kem.pq, dk).ek };
    log.debug("Leaving deriveKeyPair(). ML-KEM.");
    return out;
  }
  var seed = labeledDerive(shake, sid, ikm, "DeriveKeyPair",
                           new Uint8Array(0), 32);
  out = { sk: seed, pk: cgExpand(HYBRIDS[kem.hybrid], seed).ek };
  log.debug("Leaving deriveKeyPair(). Hybrid.");
  return out;
}

// GenerateKeyPair() = DeriveKeyPair(random(Nsk)) for a DHKEM; for ML-KEM and
// the hybrids it is the seed format directly (hpke-pq-05 sections 3 and 4).
function generateKeyPair(kemId) {
  log.debug("Entering generateKeyPair(). kem=0x" + kemId.toString(16));
  var kem = kemOf(kemId);
  var out;
  if (kem.kind === "dh") {
    out = deriveKeyPair(kemId, bytes.randomBytes(kem.Nsk));
  } else if (kem.kind === "mlkem") {
    var dk = bytes.randomBytes(64);
    out = { sk: dk, pk: mlkemExpand(kem.pq, dk).ek };
  } else {
    var seed = bytes.randomBytes(32);
    out = { sk: seed, pk: cgExpand(HYBRIDS[kem.hybrid], seed).ek };
  }
  log.debug("Leaving generateKeyPair().");
  return out;
}

// The public key a private key belongs to — what a JWK's `pub` (or x/y) must
// agree with, and what the DHKEM's kem_context needs on the receiving side.
function publicKeyOf(kemId, sk) {
  log.debug("Entering publicKeyOf(). kem=0x" + kemId.toString(16));
  var kem = kemOf(kemId);
  var out;
  if (kem.kind === "dh") {
    out = groupPublicKey(kem.group, sk);
  } else if (kem.kind === "mlkem") {
    out = mlkemExpand(kem.pq, sk).ek;
  } else {
    out = cgExpand(HYBRIDS[kem.hybrid], sk).ek;
  }
  log.debug("Leaving publicKeyOf().");
  return out;
}

// Encap(pkR) -> { sharedSecret, enc }. `ikmE` (optional) makes it
// deterministic, exactly as the test vectors use it: for a DHKEM it is
// DeriveKeyPair's input for the ephemeral key; for ML-KEM it is the 32-byte
// encapsulation randomness m; for a hybrid it is m followed by the ephemeral
// scalar's seed.
function encap(kemId, pkR, ikmE) {
  log.debug("Entering encap(). kem=0x" + kemId.toString(16));
  var kem = kemOf(kemId);
  var pk = asBytes(pkR);
  if (pk.length !== kem.Npk) {
    log.debug("Leaving encap(). Wrong key length.");
    throw new Error("HPKE EncapError: a " + kem.name + " public key is " +
                    kem.Npk + " bytes; this one is " + pk.length + ".");
  }
  var out;
  if (kem.kind === "dh") {
    var eph = ikmE ? deriveKeyPair(kemId, ikmE) : generateKeyPair(kemId);
    var dh = groupDh(kem.group, eph.sk, pk, true);
    var kemContext = concatBytes(eph.pk, pk);
    out = { sharedSecret: dhkemExtractAndExpand(kemId, dh, kemContext),
            enc: eph.pk };
    log.debug("Leaving encap(). DHKEM.");
    return out;
  }
  if (kem.kind === "mlkem") {
    var r = mlkemEncaps(kem.pq, pk, ikmE);
    out = { sharedSecret: r.ss, enc: r.ct };
    log.debug("Leaving encap(). ML-KEM.");
    return out;
  }
  var h = cgEncaps(HYBRIDS[kem.hybrid], pk, ikmE);
  out = { sharedSecret: h.ss, enc: h.ct };
  log.debug("Leaving encap(). Hybrid.");
  return out;
}

function decap(kemId, enc, skR) {
  log.debug("Entering decap(). kem=0x" + kemId.toString(16));
  var kem = kemOf(kemId);
  var e = asBytes(enc);
  var sk = asBytes(skR);
  if (sk.length !== kem.Nsk) {
    log.debug("Leaving decap(). Wrong private key length.");
    throw new Error("HPKE DeserializeError: a " + kem.name + " private key " +
                    "is " + kem.Nsk + " bytes; this one is " + sk.length +
                    ".");
  }
  if (e.length !== kem.Nenc) {
    log.debug("Leaving decap(). Wrong enc length.");
    throw new Error("HPKE DecapError: a " + kem.name + " encapsulated " +
                    "secret is " + kem.Nenc + " bytes; this one is " +
                    e.length + ".");
  }
  var out;
  if (kem.kind === "dh") {
    var dh = groupDh(kem.group, sk, e, true);
    var kemContext = concatBytes(e, groupPublicKey(kem.group, sk));
    out = dhkemExtractAndExpand(kemId, dh, kemContext);
    log.debug("Leaving decap(). DHKEM.");
    return out;
  }
  if (kem.kind === "mlkem") {
    out = mlkemDecaps(kem.pq, mlkemExpand(kem.pq, sk).dk, e);
    log.debug("Leaving decap(). ML-KEM.");
    return out;
  }
  out = cgDecaps(HYBRIDS[kem.hybrid], sk, e);
  log.debug("Leaving decap(). Hybrid.");
  return out;
}

// ---------------------------------------------------------------------------
// THE KEY SCHEDULE AND THE CONTEXT
// ---------------------------------------------------------------------------
function hpkeSuiteId(suite) {
  log.debug("Entering hpkeSuiteId().");
  log.debug("Leaving hpkeSuiteId().");
  return concatBytes(strBytes("HPKE"), i2osp(suite.kem, 2),
                     i2osp(suite.kdf, 2), i2osp(suite.aead, 2));
}

// suite = { kem, kdf, aead }; opts = { info, psk, pskId }.
function keySchedule(suite, sharedSecret, opts) {
  log.debug("Entering keySchedule().");
  var o = opts || {};
  var info = asBytes(o.info || new Uint8Array(0));
  var psk = asBytes(o.psk || new Uint8Array(0));
  var pskId = asBytes(o.pskId || new Uint8Array(0));
  // VerifyPSKInputs: the two go together or not at all, and their presence
  // IS the mode.
  if ((psk.length > 0) !== (pskId.length > 0)) {
    log.debug("Leaving keySchedule(). Inconsistent PSK inputs.");
    throw new Error("HPKE: psk and psk_id must be given together or not " +
                    "at all.");
  }
  var mode = psk.length ? MODE_PSK : MODE_BASE;
  var kdf = kdfOf(suite.kdf);
  var aead = aeadOf(suite.aead);
  var sid = hpkeSuiteId(suite);
  var key, baseNonce, exporterSecret;
  if (kdf.twoStage) {
    var empty = new Uint8Array(0);
    var pskIdHash = labeledExtract(kdf, sid, empty, "psk_id_hash", pskId);
    var infoHash = labeledExtract(kdf, sid, empty, "info_hash", info);
    var ctx = concatBytes(new Uint8Array([mode]), pskIdHash, infoHash);
    var secret = labeledExtract(kdf, sid, sharedSecret, "secret", psk);
    key = labeledExpand(kdf, sid, secret, "key", ctx, aead.Nk);
    baseNonce = labeledExpand(kdf, sid, secret, "base_nonce", ctx, aead.Nn);
    exporterSecret = labeledExpand(kdf, sid, secret, "exp", ctx, kdf.Nh);
  } else {
    var secrets = concatBytes(lengthPrefixed(psk),
                              lengthPrefixed(sharedSecret));
    var context = concatBytes(new Uint8Array([mode]), lengthPrefixed(pskId),
                              lengthPrefixed(info));
    var all = labeledDerive(kdf, sid, secrets, "secret", context,
                            aead.Nk + aead.Nn + kdf.Nh);
    key = all.slice(0, aead.Nk);
    baseNonce = all.slice(aead.Nk, aead.Nk + aead.Nn);
    exporterSecret = all.slice(aead.Nk + aead.Nn);
  }
  log.debug("Leaving keySchedule(). mode=" + mode);
  return makeContext(suite, kdf, aead, sid, key, baseNonce, exporterSecret);
}

function makeContext(suite, kdf, aead, sid, key, baseNonce, exporterSecret) {
  log.debug("Entering makeContext().");
  var seq = 0;
  function nonceFor(n) {
    log.debug("Entering nonceFor().");
    var out = bytes.xorBytes(baseNonce, i2osp(n, aead.Nn));
    log.debug("Leaving nonceFor().");
    return out;
  }
  var ctx = {
    suite: suite,
    key: key,
    baseNonce: baseNonce,
    exporterSecret: exporterSecret,
    seal: function (aad, pt) {
      log.debug("Entering context seal(). seq=" + seq);
      var ct = aeadSeal(aead, key, nonceFor(seq), aad, pt);
      seq = seq + 1;
      log.debug("Leaving context seal().");
      return ct;
    },
    open: function (aad, ct) {
      log.debug("Entering context open(). seq=" + seq);
      var pt = aeadOpen(aead, key, nonceFor(seq), aad, ct);
      seq = seq + 1;
      log.debug("Leaving context open().");
      return pt;
    },
    exportSecret: function (exporterContext, L) {
      log.debug("Entering context exportSecret(). L=" + L);
      var out = kdf.twoStage
        ? labeledExpand(kdf, sid, exporterSecret, "sec", exporterContext, L)
        : labeledDerive(kdf, sid, exporterSecret, "sec", exporterContext, L);
      log.debug("Leaving context exportSecret().");
      return out;
    }
  };
  log.debug("Leaving makeContext().");
  return ctx;
}

// SetupS / SetupR, for base or PSK mode according to whether a psk is given.
function setupSender(suite, pkR, opts) {
  log.debug("Entering setupSender().");
  var o = opts || {};
  var e = encap(suite.kem, pkR, o.ikmE);
  var ctx = keySchedule(suite, e.sharedSecret, o);
  ctx.sharedSecret = e.sharedSecret;
  log.debug("Leaving setupSender().");
  return { enc: e.enc, context: ctx };
}

function setupReceiver(suite, enc, skR, opts) {
  log.debug("Entering setupReceiver().");
  var ss = decap(suite.kem, enc, skR);
  var ctx = keySchedule(suite, ss, opts || {});
  ctx.sharedSecret = ss;
  log.debug("Leaving setupReceiver().");
  return ctx;
}

// The single-shot API (draft-ietf-hpke-hpke-02 section 6.1).
function seal(suite, pkR, info, aad, pt, opts) {
  log.debug("Entering seal().");
  var o = Object.assign({}, opts || {}, { info: info });
  var s = setupSender(suite, pkR, o);
  var ct = s.context.seal(aad, pt);
  log.debug("Leaving seal().");
  return { enc: s.enc, ct: ct };
}

function open(suite, enc, skR, info, aad, ct, opts) {
  log.debug("Entering open().");
  var o = Object.assign({}, opts || {}, { info: info });
  var ctx = setupReceiver(suite, enc, skR, o);
  var pt = ctx.open(aad, ct);
  log.debug("Leaving open().");
  return pt;
}

module.exports = {
  MODE_BASE: MODE_BASE,
  MODE_PSK: MODE_PSK,
  KEMS: KEMS,
  KDFS: KDFS,
  AEADS: AEADS,
  HYBRIDS: HYBRIDS,
  ML_KEM: ML_KEM,
  deriveKeyPair: deriveKeyPair,
  generateKeyPair: generateKeyPair,
  publicKeyOf: publicKeyOf,
  encap: encap,
  decap: decap,
  keySchedule: keySchedule,
  setupSender: setupSender,
  setupReceiver: setupReceiver,
  seal: seal,
  open: open,
  // The pieces the JOSE ML-KEM binding (pqc-kem-05) uses directly: it is
  // ML-KEM WITHOUT HPKE, so it needs the bare KEM and nothing above it.
  mlkemExpand: mlkemExpand,
  mlkemEncaps: mlkemEncaps,
  mlkemDecaps: mlkemDecaps,
  // Exported for tests/hpke_jwe_engine.js, which checks the hybrid KEMs
  // against draft-irtf-cfrg-concrete-hybrid-kems' own vectors.
  cgExpand: cgExpand,
  cgEncaps: cgEncaps,
  cgDecaps: cgDecaps
};
