// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bbs_plus_2020.js
//
// ---------------------------------------------------------------------------
// BBS+ AS BbsBlsSignature2020 USES IT (#475): the 2020 signature scheme of
// the Rust `bbs` crate 0.4.1, which MATTR's @mattrglobal/bbs-signatures 1.x
// compiles to WASM and which @mattrglobal/jsonld-signatures-bbs signs every
// BbsBlsSignature2020 credential with. It is NOT the IETF BBS of bbs.js
// (draft-irtf-cfrg-bbs-signatures, which bbs-2023 uses): a different
// signature (A, e, s rather than A, e), different generators, a different
// message-to-scalar map and a different proof. Neither can verify the other.
//
// What it is, read from the crate rather than from a paper, because a
// credential in the wild is whatever that crate produced:
//
//   public key   w = g2^x, 96 bytes compressed. The message generators are
//                derived from it: h_i = H2C(w_uncompressed || 0x00 ||
//                I2OSP(i, 4) || 0x00 || I2OSP(count, 4)), i = 0 for h0.
//   H2C          hash_to_curve to G1 with expand_message_xmd over BLAKE2b
//                and the DST "BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES
//                :1_0_0" — from a DRAFT of RFC 9380 whose sgn0 is "greater
//                than (p-1)/2" rather than RFC 9380's parity. That one
//                difference decides the sign of each mapped point, so the
//                RFC's map gives the right point about half the time and its
//                negation or something else otherwise. mapToG1Old() below is
//                the RFC's simplified SWU with the draft's sign rule, then
//                the RFC's 11-isogeny (RFC 9380 Appendix E.2 constants).
//   message      m = OS2IP(BLAKE2b-384(bytes)) mod r
//   signature    A || e || s: a compressed G1 point and two 32-byte
//                big-endian scalars, 112 bytes. Valid when
//                e(A, w * g2^e) = e(g1 * h0^s * PROD h_i^m_i, g2).
//   proof        the crate's PoKOfSignatureProof (A', A-bar, d and two
//                Schnorr proofs of knowledge, Fiat-Shamir over the
//                uncompressed points and BLAKE2b), wrapped as MATTR wraps it:
//                I2OSP(message count, 2) || a little-endian-by-bit bit vector
//                of the revealed indices, byte-reversed || the proof.
//                The nonce is hashed to a scalar like a message.
//
// Pure JS on @noble/curves and @noble/hashes, like everything that runs in
// the browser here. NO DOM.
// ---------------------------------------------------------------------------

var nobleBls = require("@noble/curves/bls12-381").bls12_381;
var htc = require("@noble/curves/abstract/hash-to-curve");
var weierstrass = require("@noble/curves/abstract/weierstrass");
var blake2b = require("@noble/hashes/blake2b").blake2b;
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bbs_plus_2020",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var Fp = nobleBls.fields.Fp;
var Fr = nobleBls.fields.Fr;
var Fp12 = nobleBls.fields.Fp12;
var G1 = nobleBls.G1.ProjectivePoint;
var G2 = nobleBls.G2.ProjectivePoint;
var DST_G1 = "BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0";
var SIGNATURE_LENGTH = 112;
var PUBLIC_KEY_LENGTH = 96;

// RFC 9380 Appendix E.2: the 11-isogeny from E' to BLS12-381 G1, and E'.
// Copied from @noble/curves 1.4.0, which carries the RFC's values.
var ISO_G1 = [
  // xNum
  [
    "0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56" +
      "cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
    "0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c" +
      "70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
    "0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501e" +
      "c68e25c958c3e3d2a09729fe0179f9dac9edcb0",
    "0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289" +
      "f1b330835336e25ce3107193c5b388641d9b6861",
    "0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb659" +
      "82fac18985a286f301e77c451154ce9ac8895d9",
    "0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab90" +
      "97e68f90a0870d2dcae73d19cd13c1c66f652983",
    "0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f" +
      "9c86b2a8da25128c1052ecaddd7f225a139ed84",
    "0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62e" +
      "f0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
    "0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c92" +
      "8c5d1de4fa295f296b74e956d71986a8497e317",
    "0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314ba" +
      "f4bb1b7fa3190b2edc0327797f241067be390c9e",
    "0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af360" +
      "03b14866f69b771f8c285decca67df3f1605fb7b",
    "0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc" +
      "24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"
  ],
  // xDen
  [
    "0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617" +
      "fc8ac62b558d681be343df8993cf9fa40d21b1c",
    "0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c258" +
      "8c48bf5713daa8846cb026e9e5c8276ec82b3bff",
    "0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b" +
      "11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
    "0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc" +
      "28d6fd04976d5243eecf5c4130de8938dc62cd8",
    "0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e8" +
      "33b306da9bd29ba81f35781d539d395b3532a21e",
    "0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef2" +
      "4b8982f7400d24bc4228f11c02df9a29f6304a5",
    "0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e07306" +
      "2aede9cea73b3538f0de06cec2574496ee84a3a",
    "0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cd" +
      "f9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
    "0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67" +
      "f39883503826692abba43704776ec3a79a1d641",
    "0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df53397" +
      "8f31c1593174e4b4b7865002d6384d168ecdd0a",
    "0x00000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000001"
  ],
  // yNum
  [
    "0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c9" +
      "56543d3cd0c7aee9b3ba3c2be9845719707bb33",
    "0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343" +
      "eb67ad34d6c56711962fa8bfe097e75a2e41c696",
    "0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91" +
      "400da7d26d521628b00523b8dfe240c72de1f6",
    "0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec0" +
      "3251cf9de405aba9ec61deca6355c77b0e5f4cb",
    "0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd22" +
      "1351adc2ee7f8dc099040a841b6daecf2e8fedb",
    "0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d" +
      "3ad5544e203f6326c95a807299b23ab13633a5f0",
    "0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4" +
      "d634f3747a87ac2460f415ec961f8855fe9d6f2",
    "0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c" +
      "26c842642f64550fedfe935a15e4ca31870fb29",
    "0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1" +
      "f20cabe69d65201c78607a360370e577bdba587",
    "0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed" +
      "1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
    "0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e41" +
      "6389e61031bf3a5cce3fbafce813711ad011c132",
    "0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f" +
      "911f643249d9cdf41b44d606ce07c8a4d0074d8e",
    "0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e80" +
      "7b4633f06c851c1919211f20d4c04f00b971ef8",
    "0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3" +
      "c40659cc6cf90ad1c232a6442d9d3f5db980133",
    "0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d3" +
      "96a7ce46ba1049b6579afb7866b1e715475224b",
    "0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa" +
      "95af01b2b665027efec01c7704b456be69c8b604"
  ],
  // yDen
  [
    "0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b" +
      "5be72e7a07f3688ef60c206d01479253b03663c1",
    "0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356" +
      "f453e01f78a4260763529e3532f6102c2e49a03d",
    "0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd2" +
      "79cd2eca6757cd636f96f891e2538b53dbf67f2",
    "0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489" +
      "e726af41727364f2c28297ada8d26d98445f5416",
    "0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc" +
      "9dec916a20b15dc0fd2ededda39142311a5001d",
    "0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6" +
      "f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
    "0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc" +
      "400a0051d5fa9c01a58b1fb93d1a1399126a775c",
    "0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd2" +
      "06357132b920f5b00801dee460ee415a15812ed9",
    "0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c" +
      "4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
    "0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e" +
      "7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
    "0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e" +
      "636a5c871a5c29f4f83060400f8b49cba8f6aa8",
    "0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88c" +
      "ea7913516f968986f7ebbea9684b529e2561092",
    "0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a" +
      "00d9b8693000763e3b90ac11e99b138573345cc",
    "0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27" +
      "942480e420517bd8714cc80d1fadc1326ed06f7",
    "0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd63" +
      "56caa205ca2f570f13497804415473a1d634b8f",
    "0x00000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000001"
  ]
];
var SWU_A = BigInt(
  "0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aef" +
  "d881ac98936f8da0e0f97f5cf428082d584c1d");
var SWU_B = BigInt(
  "0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14f" +
  "cef35ef55a23215a316ceaa5d1cc48e98e172be0");

var isoMapG1 = htc.isogenyMap(Fp, ISO_G1.map(function (row) {
  return row.map(function (h) {
    return BigInt(h);
  });
}));
var swuG1 = weierstrass.mapToCurveSimpleSWU(Fp, {
  A: Fp.create(SWU_A), B: Fp.create(SWU_B), Z: Fp.create(BigInt(11))
});
var HALF_P = (Fp.ORDER - BigInt(1)) / BigInt(2);

// HOT PATH, and deliberately not logged: draftNegative(), mapToG1Old(),
// hashToG1(), os2ip(), i2osp(), hashToScalar(), asBytes(), randomScalar()
// and mod() run per generator, per message and per scalar — a credential of
// forty statements is hundreds of calls for one proof. The functions that
// call them log, which is where a trace of a verification lives.
//
// The draft's sgn0: "negative" when greater than (p - 1) / 2.
function draftNegative(v) {
  return Fp.create(v) > HALF_P;
}

// One field element to E' and through the isogeny, with the draft's sign.
function mapToG1Old(u) {
  var p = swuG1(u);
  var y = draftNegative(p.y) !== draftNegative(u) ? Fp.neg(p.y) : p.y;
  return isoMapG1(p.x, y);
}

function hashToG1(msg) {
  var u = htc.hash_to_field(msg, 2, { DST: DST_G1, p: Fp.ORDER, m: 1,
    k: 128, expand: "xmd", hash: blake2b });
  return G1.fromAffine(mapToG1Old(u[0][0]))
    .add(G1.fromAffine(mapToG1Old(u[1][0]))).clearCofactor();
}

function os2ip(b) {
  var x = BigInt(0);
  for (var i = 0; i < b.length; i++) {
    x = (x << BigInt(8)) | BigInt(b[i]);
  }
  return x;
}

function i2osp(x, len) {
  var out = new Uint8Array(len);
  var v = BigInt(x);
  for (var i = len - 1; i >= 0; i--) {
    out[i] = Number(v & BigInt(255));
    v = v >> BigInt(8);
  }
  return out;
}

// A message (or a nonce) as a scalar: BLAKE2b with a 48-byte output, read
// big-endian and reduced mod r (the crate's hash_to_fr / Fr::from_okm).
function hashToScalar(bytes) {
  return Fr.create(os2ip(blake2b(asBytes(bytes), { dkLen: 48 })));
}

function asBytes(v) {
  return typeof v === "string" ? cbytes.strBytes(v) : v;
}

function randomScalar() {
  return Fr.create(os2ip(cbytes.randomBytes(48)));
}

// The BBS+ public key for `count` messages: w and its generators.
function publicKeyFor(publicKey, count) {
  log.debug("Entering publicKeyFor(). count=" + count);
  if (!publicKey || publicKey.length !== PUBLIC_KEY_LENGTH) {
    log.debug("Leaving publicKeyFor(). Wrong length.");
    throw new Error("a BbsBlsSignature2020 public key is a 96-byte " +
                    "compressed G2 point.");
  }
  if (!(count > 0)) {
    log.debug("Leaving publicKeyFor(). No messages.");
    throw new Error("a BBS+ key needs at least one message.");
  }
  var w = G2.fromHex(publicKey);
  var wb = w.toRawBytes(false);
  var h = [];
  for (var i = 0; i <= count; i++) {
    h.push(hashToG1(cbytes.concatBytes(wb, new Uint8Array([0]), i2osp(i, 4),
                                       new Uint8Array([0]),
                                       i2osp(count, 4))));
  }
  log.debug("Leaving publicKeyFor().");
  return { w: w, h0: h[0], h: h.slice(1) };
}

function readSignature(signature) {
  log.debug("Entering readSignature().");
  if (!signature || signature.length !== SIGNATURE_LENGTH) {
    log.debug("Leaving readSignature(). Wrong length.");
    throw new Error("a BbsBlsSignature2020 signature is " +
                    SIGNATURE_LENGTH + " bytes (A, e, s).");
  }
  log.debug("Leaving readSignature().");
  return { A: G1.fromHex(signature.slice(0, 48)),
           e: Fr.create(os2ip(signature.slice(48, 80))),
           s: Fr.create(os2ip(signature.slice(80, 112))) };
}

// g1 * h0^s * PROD h_i^m_i
function computeB(pk, s, scalars) {
  log.debug("Entering computeB().");
  var b = G1.BASE.add(pk.h0.multiply(s));
  scalars.forEach(function (m, i) {
    if (m !== BigInt(0)) {
      b = b.add(pk.h[i].multiply(m));
    }
  });
  log.debug("Leaving computeB().");
  return b;
}

function pairingsEqual(p1, q1, p2, q2) {
  log.debug("Entering pairingsEqual().");
  log.debug("Leaving pairingsEqual().");
  return Fp12.eql(nobleBls.pairing(p1, q1), nobleBls.pairing(p2, q2));
}

// Whether `signature` signs exactly `messages` (byte arrays or strings, in
// order) under the 96-byte public key.
function verifySignature(publicKey, signature, messages) {
  log.debug("Entering verifySignature(). " + messages.length + " message(s).");
  var pk = publicKeyFor(publicKey, messages.length);
  var sig;
  try {
    sig = readSignature(signature);
  } catch (e) {
    log.debug("Leaving verifySignature(). " + e.message);
    return false;
  }
  var b = computeB(pk, sig.s, messages.map(hashToScalar));
  var ok = pairingsEqual(sig.A, pk.w.add(G2.BASE.multiply(sig.e)),
                         b, G2.BASE);
  log.debug("Leaving verifySignature(). " + ok);
  return ok;
}

function mod(x) {
  return Fr.create(x);
}

function serializeProof(p) {
  log.debug("Entering serializeProof().");
  var proof1 = cbytes.concatBytes(p.c1.toRawBytes(true),
    i2osp(p.resp1.length, 4),
    cbytes.concatBytes.apply(null, p.resp1.map(function (r) {
      return i2osp(r, 32);
    })));
  var proof2 = cbytes.concatBytes(p.c2.toRawBytes(true),
    i2osp(p.resp2.length, 4),
    cbytes.concatBytes.apply(null, p.resp2.map(function (r) {
      return i2osp(r, 32);
    })));
  log.debug("Leaving serializeProof().");
  return cbytes.concatBytes(p.aPrime.toRawBytes(true),
    p.aBar.toRawBytes(true), p.d.toRawBytes(true),
    i2osp(proof1.length, 4), proof1, proof2);
}

function readProofG1(bytes) {
  log.debug("Entering readProofG1().");
  var c = G1.fromHex(bytes.slice(0, 48));
  var n = Number(os2ip(bytes.slice(48, 52)));
  if (bytes.length !== 52 + 32 * n) {
    log.debug("Leaving readProofG1(). Bad length.");
    throw new Error("a proof of knowledge's response list does not match " +
                    "its length.");
  }
  var resp = [];
  for (var i = 0; i < n; i++) {
    resp.push(Fr.create(os2ip(bytes.slice(52 + 32 * i, 84 + 32 * i))));
  }
  log.debug("Leaving readProofG1().");
  return { c: c, resp: resp };
}

function bitVector(total, revealed) {
  log.debug("Entering bitVector().");
  var bytes = new Uint8Array(Math.floor(total / 8) + 1);
  revealed.forEach(function (r) {
    bytes[Math.floor(r / 8)] |= 1 << (r % 8);
  });
  log.debug("Leaving bitVector().");
  return bytes.reverse();
}

function revealedFromBits(bits) {
  log.debug("Entering revealedFromBits().");
  var out = [];
  var scalar = 0;
  for (var i = bits.length - 1; i >= 0; i--) {
    for (var bit = 0; bit < 8; bit++) {
      if ((bits[i] >> bit) & 1) {
        out.push(scalar);
      }
      scalar++;
    }
  }
  log.debug("Leaving revealedFromBits(). " + out.length);
  return out;
}

// The bytes the challenge is computed over: A-bar, then each committed
// vector's bases and commitment, uncompressed (the crate's to_bytes()).
function challengeBytes(aBar, bases1, c1, bases2, c2, nonce) {
  log.debug("Entering challengeBytes().");
  var parts = [aBar.toRawBytes(false)];
  bases1.forEach(function (p) {
    parts.push(p.toRawBytes(false));
  });
  parts.push(c1.toRawBytes(false));
  bases2.forEach(function (p) {
    parts.push(p.toRawBytes(false));
  });
  parts.push(c2.toRawBytes(false));
  parts.push(i2osp(hashToScalar(nonce), 32));
  log.debug("Leaving challengeBytes().");
  return cbytes.concatBytes.apply(null, parts);
}

// A proof that discloses messages[i] for every i in `revealed` and proves
// knowledge of a signature on all of them, bound to `nonce`. Answers the
// proof bytes as MATTR's blsCreateProof() writes them.
function createProof(publicKey, signature, messages, revealed, nonce) {
  log.debug("Entering createProof(). " + revealed.length + " of " +
            messages.length + " revealed.");
  var pk = publicKeyFor(publicKey, messages.length);
  var sig = readSignature(signature);
  var m = messages.map(hashToScalar);
  var shown = {};
  revealed.forEach(function (i) {
    if (!(i >= 0 && i < messages.length)) {
      throw new Error("revealed index " + i + " is out of range.");
    }
    shown[i] = true;
  });
  var b = computeB(pk, sig.s, m);
  if (!pairingsEqual(sig.A, pk.w.add(G2.BASE.multiply(sig.e)), b,
                     G2.BASE)) {
    log.debug("Leaving createProof(). Signature does not verify.");
    throw new Error("the signature does not verify over these messages, " +
                    "so no proof can be made from it.");
  }
  var r1 = randomScalar();
  var r2 = randomScalar();
  var aPrime = sig.A.multiply(r1);
  var aBar = b.multiply(r1).subtract(aPrime.multiply(sig.e));
  var d = b.multiply(r1).add(pk.h0.multiply(mod(-r2)));
  var r3 = Fr.inv(r1);
  var sPrime = mod(sig.s - mod(r2 * r3));
  var bases1 = [aPrime, pk.h0];
  var secrets1 = [mod(-sig.e), r2];
  var bases2 = [d, pk.h0];
  var secrets2 = [mod(-r3), sPrime];
  for (var i = 0; i < messages.length; i++) {
    if (!shown[i]) {
      bases2.push(pk.h[i]);
      secrets2.push(m[i]);
    }
  }
  var blind1 = bases1.map(randomScalar);
  var blind2 = bases2.map(randomScalar);
  var commit = function (bases, blinds) {
    return bases.reduce(function (acc, p, k) {
      return acc.add(p.multiply(blinds[k]));
    }, G1.ZERO);
  };
  var c1 = commit(bases1, blind1);
  var c2 = commit(bases2, blind2);
  var c = hashToScalar(challengeBytes(aBar, bases1, c1, bases2, c2, nonce));
  var respond = function (blinds, secrets) {
    return blinds.map(function (bl, k) {
      return mod(bl - mod(c * secrets[k]));
    });
  };
  var proof = serializeProof({ aPrime: aPrime, aBar: aBar, d: d, c1: c1,
    resp1: respond(blind1, secrets1), c2: c2,
    resp2: respond(blind2, secrets2) });
  var sorted = revealed.slice().sort(function (x, y) {
    return x - y;
  });
  log.debug("Leaving createProof().");
  return cbytes.concatBytes(i2osp(messages.length, 2),
                            bitVector(messages.length, sorted), proof);
}

// The message indices a proof reveals, ascending.
function revealedIndicesOf(proof) {
  log.debug("Entering revealedIndicesOf().");
  var count = Number(os2ip(proof.slice(0, 2)));
  log.debug("Leaving revealedIndicesOf().");
  return revealedFromBits(proof.slice(2, 2 + Math.floor(count / 8) + 1));
}

// Whether `proof` (as createProof() or MATTR writes it) proves knowledge of
// a signature under `publicKey` on a message list whose revealed members are
// `revealedMessages`, in index order, bound to `nonce`.
function verifyProof(publicKey, proof, revealedMessages, nonce) {
  log.debug("Entering verifyProof().");
  try {
    var count = Number(os2ip(proof.slice(0, 2)));
    var bitLen = Math.floor(count / 8) + 1;
    var revealed = revealedFromBits(proof.slice(2, 2 + bitLen));
    if (revealed.length !== revealedMessages.length) {
      log.debug("Leaving verifyProof(). Count mismatch.");
      return false;
    }
    var body = proof.slice(2 + bitLen);
    var pk = publicKeyFor(publicKey, count);
    var aPrime = G1.fromHex(body.slice(0, 48));
    var aBar = G1.fromHex(body.slice(48, 96));
    var d = G1.fromHex(body.slice(96, 144));
    var len1 = Number(os2ip(body.slice(144, 148)));
    var p1 = readProofG1(body.slice(148, 148 + len1));
    var p2 = readProofG1(body.slice(148 + len1));
    if (aPrime.equals(G1.ZERO)) {
      log.debug("Leaving verifyProof(). A' is zero.");
      return false;
    }
    if (!pairingsEqual(aPrime, pk.w, aBar, G2.BASE)) {
      log.debug("Leaving verifyProof(). Pairing.");
      return false;
    }
    var shown = {};
    revealed.forEach(function (idx, k) {
      shown[idx] = hashToScalar(revealedMessages[k]);
    });
    var bases1 = [aPrime, pk.h0];
    var bases2 = [d, pk.h0];
    var disclosed = G1.BASE;
    for (var i = 0; i < count; i++) {
      if (Object.prototype.hasOwnProperty.call(shown, i)) {
        disclosed = disclosed.add(pk.h[i].multiply(shown[i]));
      } else {
        bases2.push(pk.h[i]);
      }
    }
    if (p1.resp.length !== bases1.length ||
        p2.resp.length !== bases2.length) {
      log.debug("Leaving verifyProof(). Response count.");
      return false;
    }
    var c = hashToScalar(challengeBytes(aBar, bases1, p1.c, bases2, p2.c,
                                        nonce));
    var check = function (bases, resp, target, commitment) {
      var acc = target.multiply(c);
      bases.forEach(function (p, k) {
        if (resp[k] !== BigInt(0)) {
          acc = acc.add(p.multiply(resp[k]));
        }
      });
      return acc.equals(commitment);
    };
    var ok = check(bases1, p1.resp, aBar.subtract(d), p1.c) &&
      check(bases2, p2.resp, disclosed.negate(), p2.c);
    log.debug("Leaving verifyProof(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving verifyProof(). Malformed: " + e.message);
    return false;
  }
}

module.exports = {
  SIGNATURE_LENGTH: SIGNATURE_LENGTH,
  PUBLIC_KEY_LENGTH: PUBLIC_KEY_LENGTH,
  hashToScalar: hashToScalar,
  publicKeyFor: publicKeyFor,
  verifySignature: verifySignature,
  createProof: createProof,
  verifyProof: verifyProof,
  revealedIndicesOf: revealedIndicesOf
};
