// File: bbs.js
//
// ---------------------------------------------------------------------------
// BBS signatures over BLS12-381 (draft-irtf-cfrg-bbs-signatures), ciphersuite
// BLS12-381-SHA-256, in the browser.
//
// This is what makes the `bbs-2023` Data Integrity cryptosuite possible here,
// and it is the reason bbs-2023 cannot live in the other two credential formats
// this workflow supports: an SD-JWT VC and a jwt_vc_json are secured by a JWS,
// whose `alg` must be a registered JOSE algorithm, and BBS is not one. BBS
// needs a pairing-friendly curve and produces a signature that a verifier can
// turn into a *derived proof* over a chosen subset of the signed messages —
// which is a different shape from a signature entirely.
//
// What BBS buys, and why it is worth this much code: with an SD-JWT the holder
// withholds a Disclosure but the issuer's signature is unchanged, so two
// presentations of the same credential are trivially linkable by that
// signature. With BBS the holder derives a FRESH proof each time, disclosing
// only the statements asked for, and the proofs are unlinkable to each other.
// That is selective disclosure plus unlinkability, which neither of the other
// formats offers.
//
// WHY THIS IS WRITTEN OUT RATHER THAN INSTALLED. @digitalbazaar/bbs-signatures
// is a good implementation and this project does use it — on the STS and in the
// tests. It cannot be used here: it is ESM-only ("type": "module", no CJS
// entry), and browserify cannot consume that. That accident turns out to be
// useful, because it means the browser's proofs are produced by one
// implementation and checked by a different one. The two share @noble/curves
// for field and curve arithmetic, so the independence is at the BBS PROTOCOL
// layer, not all the way down — worth being precise about rather than
// overclaiming.
//
// Reference: draft-irtf-cfrg-bbs-signatures-08, sections 3.5 (Sign/Verify),
// 3.6 (ProofGen/ProofVerify) and 4.1 (the BLS12-381-SHA-256 ciphersuite).
// ---------------------------------------------------------------------------

var noble = require("@noble/curves/bls12-381");
var hashToCurve = require("@noble/curves/abstract/hash-to-curve");
var nobleUtils = require("@noble/curves/abstract/utils");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bbs",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var bls = noble.bls12_381;
var G1 = bls.G1.ProjectivePoint;
var G2 = bls.G2.ProjectivePoint;
var Fr = bls.fields.Fr;

// BigInt constants written as BigInt(...) rather than 0n/8n/0xffn literals, for
// the same reason as in digital_signature.js: an esprima build that predates
// BigInt literals lexes any file in a bundle that references `process`, and
// rejects them as "Unexpected token ILLEGAL".
//
// This file only acquired such a reference when it acquired a log level, so the
// literals sat here harmless for as long as nothing in it mentioned `process` —
// which is precisely what makes the failure hard to read: adding a logger broke
// the build with a syntax error on a line the change never touched, in the
// bundle of a page (vc_presentation_2) three requires away. Keep the constants
// here and the literals out of the code below. See client/CLAUDE.md.
var _B0 = BigInt(0), _B8 = BigInt(8), _B255 = BigInt(255);

// --- ciphersuite BLS12-381-SHA-256 (section 4.1) ----------------------------
//
// Two constants that are easy to get wrong, and both were, in the first draft
// of this file — with a self-test that passed anyway, because sign() and
// verify() shared the mistake. Only cross-checking against a different
// implementation found them.
//
//   CIPHERSUITE_ID is the bare suite id. The DSTs are built from the API id,
//   which is that plus "H2G_HM2S_" — keeping them separate matters because the
//   blind and pseudonym APIs use different suffixes over the same suite.
//
//   P1 is a FIXED point defined by the ciphersuite, not the G1 base point.
//   B = P1 + Q1*domain + ... , and using the generator instead produces
//   signatures that verify perfectly against your own verifier and against
//   nobody else's.
var CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
var API_ID = CIPHERSUITE_ID + "H2G_HM2S_";
var P1_HEX = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd" +
             "225e7c59698588e70d11406d161b4e28c9";
var EXPAND_LEN = 48;            // octets of uniform bytes per scalar
var OCTET_SCALAR_LENGTH = 32;
var OCTET_POINT_LENGTH = 48;    // compressed G1

function te(s) {
  log.debug("Entering te().");
  log.debug("Leaving te().");
  return new TextEncoder().encode(s);
}
function concatBytes() {
  log.debug("Entering concatBytes().");
  var parts = Array.prototype.slice.call(arguments);
  var total = parts.reduce(function (n, p) { return n + p.length; }, 0);
  var out = new Uint8Array(total);
  var at = 0;
  parts.forEach(function (p) { out.set(p, at); at += p.length; });
  log.debug("Leaving concatBytes().");
  return out;
}
function i2osp(value, length) {
  log.debug("Entering i2osp().");
  var out = new Uint8Array(length);
  var v = BigInt(value);
  for (var i = length - 1; i >= 0; i--) {
    out[i] = Number(v & _B255);
    v >>= _B8;
  }
  log.debug("Leaving i2osp().");
  return out;
}

// hash_to_scalar (section 4.3.1): expand to 48 octets and reduce mod r.
// Reducing 48 octets rather than 32 is what keeps the result statistically
// uniform in Fr; taking 32 and reducing would bias the low end.
function hashToScalar(message, dst) {
  log.debug("Entering hashToScalar().");
  var uniform = hashToCurve.expand_message_xmd(message, dst, EXPAND_LEN,
      sha256Fn());
  log.debug("Leaving hashToScalar().");
  return Fr.create(nobleUtils.bytesToNumberBE(uniform));
}

// @noble exposes sha256 through its hashes package; resolved once and kept, so
// a missing export fails at load with a clear message rather than inside a
// signing operation.
var sha256Impl = null;
function sha256Fn() {
  log.debug("Entering sha256Fn().");
  if (sha256Impl) {
    log.debug("Leaving sha256Fn().");
    return sha256Impl;
  }
  try {
    sha256Impl = require("@noble/hashes/sha256").sha256;
  } catch (e) {
    throw new Error("BBS needs SHA-256 from @noble/hashes: " + e.message);
  }
  log.debug("Leaving sha256Fn().");
  return sha256Impl;
}

// create_generators (section 4.2): a deterministic list of G1 points, derived
// from the ciphersuite alone, so a verifier reconstructs exactly the generators
// the signer used without them being transmitted.
var generatorCache = [];
function createGenerators(count) {
  log.debug("Entering createGenerators().");
  if (generatorCache.length >= count) {
    log.debug("Leaving createGenerators().");
    return generatorCache.slice(0, count);
  }
  var seedDst = te(API_ID + "SIG_GENERATOR_SEED_");
  var generateDst = te(API_ID + "SIG_GENERATOR_DST_");
  var seedLen = EXPAND_LEN;
  var v = hashToCurve.expand_message_xmd(te(API_ID + "MESSAGE_GENERATOR_SEED"),
                                         seedDst, seedLen, sha256Fn());
  var out = [];
  for (var i = 1; i <= count; i++) {
    v = hashToCurve.expand_message_xmd(concatBytes(v, i2osp(i, 8)), seedDst,
        seedLen, sha256Fn());
    var p = bls.G1.hashToCurve(v, { DST: generateDst });
    out.push(G1.fromAffine(p.toAffine()));
  }
  generatorCache = out;
  log.debug("Leaving createGenerators().");
  return out;
}

function messagesToScalars(messages) {
  log.debug("Entering messagesToScalars().");
  var dst = te(API_ID + "MAP_MSG_TO_SCALAR_AS_HASH_");
  log.debug("Leaving messagesToScalars().");
  return messages.map(function (m) { return hashToScalar(m, dst); });
}

// --- keys -------------------------------------------------------------------
function secretKeyToPublicKey(sk) {
  log.debug("Entering secretKeyToPublicKey().");
  log.debug("Leaving secretKeyToPublicKey().");
  return G2.BASE.multiply(sk).toRawBytes(true);
}

// --- Sign / Verify (section 3.5) -------------------------------------------
//
// B = P1 + Q1*domain + H_1*msg_1 + ... + H_L*msg_L
// A = B * (1/(sk + e))
// signature = (A, e)
function calculateDomain(pk, q1, generators, header) {
  log.debug("Entering calculateDomain().");
  var dom = concatBytes(
    i2osp(generators.length, 8),
    q1.toRawBytes(true),
    concatBytes.apply(null,
        generators.map(function (g) { return g.toRawBytes(true); })),
    te(API_ID),
    i2osp(header.length, 8), header);
  log.debug("Leaving calculateDomain().");
  return hashToScalar(concatBytes(pk, dom), te(API_ID + "H2S_"));
}

var p1Cache = null;
function P1() {
  log.debug("Entering P1().");
  if (!p1Cache) p1Cache = G1.fromHex(P1_HEX);
  log.debug("Leaving P1().");
  return p1Cache;
}

function computeB(domain, msgScalars, q1, generators) {
  log.debug("Entering computeB().");
  var b = P1().add(q1.multiply(domain));
  msgScalars.forEach(function (m, i) {
    if (m !== _B0) b = b.add(generators[i].multiply(m));
  });
  log.debug("Leaving computeB().");
  return b;
}

function sign(sk, pk, header, messages) {
  log.debug("Entering sign().");
  var msgScalars = messagesToScalars(messages);
  var all = createGenerators(msgScalars.length + 1);
  var q1 = all[0];
  var generators = all.slice(1);
  var domain = calculateDomain(pk, q1, generators, header);
  var e = hashToScalar(
    concatBytes(i2osp(sk, OCTET_SCALAR_LENGTH),
                concatBytes.apply(null, msgScalars.map(function (m) {
                  return i2osp(m, OCTET_SCALAR_LENGTH);
                })),
                i2osp(domain, OCTET_SCALAR_LENGTH)),
    te(API_ID + "H2S_"));
  var b = computeB(domain, msgScalars, q1, generators);
  var a = b.multiply(Fr.inv(Fr.add(sk, e)));
  log.debug("Leaving sign().");
  return concatBytes(a.toRawBytes(true), i2osp(e, OCTET_SCALAR_LENGTH));
}

function verify(pk, signature, header, messages) {
  log.debug("Entering verify().");
  var a = G1.fromHex(signature.slice(0, OCTET_POINT_LENGTH));
  var e = Fr.create(nobleUtils.bytesToNumberBE(signature.slice(
      OCTET_POINT_LENGTH)));
  var msgScalars = messagesToScalars(messages);
  var all = createGenerators(msgScalars.length + 1);
  var q1 = all[0];
  var generators = all.slice(1);
  var domain = calculateDomain(pk, q1, generators, header);
  var b = computeB(domain, msgScalars, q1, generators);
  var w = G2.fromHex(pk);
  // e(A, W + G2*e) == e(B, G2)
  var lhs = bls.pairing(a, w.add(G2.BASE.multiply(e)));
  var rhs = bls.pairing(b, G2.BASE);
  log.debug("Leaving verify().");
  return bls.fields.Fp12.eql(lhs, rhs);
}


// serialize (section 4.4.4): the draft's canonical encoding of a mixed array —
// G1 points compressed, scalars and lengths as fixed-width big-endian integers.
// The challenge is a hash over this, so a single wrong width makes every proof
// unverifiable by anyone else while remaining perfectly self-consistent.
function serializeArray(items) {
  log.debug("Entering serializeArray().");
  var parts = items.map(function (item) {
    if (typeof item === "bigint") return i2osp(item, OCTET_SCALAR_LENGTH);
    if (typeof item === "number") return i2osp(item, 8);
    return item.toRawBytes(true);      // a G1 point
  });
  log.debug("Leaving serializeArray().");
  return concatBytes.apply(null, parts);
}

function randomScalar() {
  log.debug("Entering randomScalar().");
  // Web Crypto's getRandomValues ONLY. A bare require("crypto") here would make
  // browserify substitute the whole crypto-browserify shim, which contains
  // browserify-sign and create-ecdh and therefore `elliptic` — carrying
  // GHSA-848j-6mx2-7j84, for which no patched version exists, into every bundle
  // that loads this module. Measured: it added 40 elliptic references and ~1
  // MB. See the "Keeping elliptic out of the bundles" note in CLAUDE.md.
  var webcrypto = (typeof globalThis !== "undefined" && globalThis.crypto) ||
                  (typeof window !== "undefined" && window.crypto);
  if (!webcrypto || !webcrypto.getRandomValues) {
    throw new Error("BBS proof generation needs Web Crypto's " +
                    "getRandomValues, which this context " +
      "does not provide. In the containerized suite the page must be on a " +
          "secure origin — see " +
      "tests/browser_flags.js.");
  }
  var bytes = new Uint8Array(EXPAND_LEN);
  webcrypto.getRandomValues(bytes);
  log.debug("Leaving randomScalar().");
  return Fr.create(nobleUtils.bytesToNumberBE(bytes));
}

// --- ProofGen / ProofVerify (section 3.6) -----------------------------------
//
// This is what BBS is FOR. The holder turns the issuer's signature into a fresh
// zero-knowledge proof over a chosen subset of the messages: the verifier
// learns the disclosed messages and that a valid signature exists over all of
// them, and nothing else. Because the randomness is fresh each time, two proofs
// from the same credential are unlinkable — which is the property an SD-JWT
// cannot offer, since there the issuer's signature is reused verbatim every
// time.
function proofChallenge(initRes, disclosedIndexes, disclosedScalars, ph) {
  log.debug("Entering proofChallenge().");
  var zipped = [];
  disclosedIndexes.forEach(function (idx, i) {
    zipped.push(idx);
    zipped.push(disclosedScalars[i]);
  });
  var arr = [disclosedIndexes.length].concat(zipped, [
    initRes.Abar, initRes.Bbar, initRes.D, initRes.T1, initRes.T2,
        initRes.domain]);
  log.debug("Leaving proofChallenge().");
  return hashToScalar(concatBytes(serializeArray(arr), i2osp(ph.length, 8), ph),
                      te(API_ID + "H2S_"));
}

function proofGen(pk, signature, header, ph, messages, disclosedIndexes) {
  log.debug("Entering proofGen().");
  var a = G1.fromHex(signature.slice(0, OCTET_POINT_LENGTH));
  var e = Fr.create(nobleUtils.bytesToNumberBE(signature.slice(
      OCTET_POINT_LENGTH)));
  var msgScalars = messagesToScalars(messages);
  var L = msgScalars.length;
  var all = createGenerators(L + 1);
  var q1 = all[0];
  var H = all.slice(1);
  var disclosed = disclosedIndexes.slice().sort(function (x, y) { return x -
      y; });
  var undisclosed = [];
  for (var i =
       0; i < L; i++) if (disclosed.indexOf(i) === -1) undisclosed.push(i);

  var domain = calculateDomain(pk, q1, H, header);
  var b = computeB(domain, msgScalars, q1, H);

  var rs = [];
  for (var k = 0; k < undisclosed.length + 5; k++) rs.push(randomScalar());
  var r1 = rs[0], r2 = rs[1], eTilde = rs[2], r1Tilde = rs[3], r3Tilde = rs[4];
  var mTilde = rs.slice(5);

  var D = b.multiply(r2);
  var Abar = a.multiply(Fr.mul(r1, r2));
  var Bbar = D.multiply(r1).subtract(Abar.multiply(e));
  var T1 = Abar.multiply(eTilde).add(D.multiply(r1Tilde));
  var T2 = D.multiply(r3Tilde);
  undisclosed.forEach(function (j, idx) { T2 =
                      T2.add(H[j].multiply(mTilde[idx])); });

  var initRes = { Abar: Abar, Bbar: Bbar, D: D, T1: T1, T2: T2,
      domain: domain };
  var challenge = proofChallenge(initRes, disclosed,
    disclosed.map(function (j) { return msgScalars[j]; }), ph);

  var r3 = Fr.inv(r2);
  var eHat = Fr.add(eTilde, Fr.mul(e, challenge));
  var r1Hat = Fr.sub(r1Tilde, Fr.mul(r1, challenge));
  var r3Hat = Fr.sub(r3Tilde, Fr.mul(r3, challenge));
  var mHat = undisclosed.map(function (j, idx) {
    return Fr.add(mTilde[idx], Fr.mul(msgScalars[j], challenge));
  });

  log.debug("Leaving proofGen().");
  return serializeArray([Abar, Bbar, D, eHat, r1Hat, r3Hat].concat(mHat,
                        [challenge]));
}

function parseProof(proof) {
  log.debug("Entering parseProof().");
  var at = 0;
  var take = function (n) {
    log.debug("Entering take().");
    var out = proof.slice(at, at + n);
    at += n;
    log.debug("Leaving take().");
    return out;
  };
  var Abar = G1.fromHex(take(OCTET_POINT_LENGTH));
  var Bbar = G1.fromHex(take(OCTET_POINT_LENGTH));
  var D = G1.fromHex(take(OCTET_POINT_LENGTH));
  var scalars = [];
  while (at < proof.length) scalars.push(Fr.create(nobleUtils.bytesToNumberBE(
         take(OCTET_SCALAR_LENGTH))));
  var challenge = scalars.pop();
  var eHat = scalars.shift(), r1Hat = scalars.shift(), r3Hat = scalars.shift();
  log.debug("Leaving parseProof().");
  return { Abar: Abar, Bbar: Bbar, D: D, eHat: eHat, r1Hat: r1Hat, r3Hat: r3Hat,
           mHat: scalars, challenge: challenge };
}

function proofVerify(pk, proof, header, ph, disclosedMessages,
                     disclosedIndexes) {
  log.debug("Entering proofVerify().");
  var p = parseProof(proof);
  var disclosed = disclosedIndexes.slice().sort(function (x, y) { return x -
      y; });
  var U = p.mHat.length;
  var R = disclosed.length;
  var L = R + U;
  var all = createGenerators(L + 1);
  var q1 = all[0];
  var H = all.slice(1);
  var undisclosed = [];
  for (var i =
       0; i < L; i++) if (disclosed.indexOf(i) === -1) undisclosed.push(i);

  var domain = calculateDomain(pk, q1, H, header);
  var disclosedScalars = messagesToScalars(disclosedMessages);

  var T1 = p.Bbar.multiply(p.challenge).add(p.Abar.multiply(p.eHat))
      .add(p.D.multiply(p.r1Hat));
  var Bv = P1().add(q1.multiply(domain));
  disclosedScalars.forEach(function (m, idx) { Bv =
                           Bv.add(H[disclosed[idx]].multiply(m)); });
  var T2 = Bv.multiply(p.challenge).add(p.D.multiply(p.r3Hat));
  undisclosed.forEach(function (j, idx) { T2 =
                      T2.add(H[j].multiply(p.mHat[idx])); });

  var initRes = { Abar: p.Abar, Bbar: p.Bbar, D: p.D, T1: T1, T2: T2,
      domain: domain };
  var expected = proofChallenge(initRes, disclosed, disclosedScalars, ph);
  if (!Fr.eql(expected, p.challenge)) {
    log.debug("Leaving proofVerify().");
    return false;
  }

  // e(Abar, W) == e(Bbar, G2): the pairing check that ties the proof back to
  // the issuer's key.
  var w = G2.fromHex(pk);
  log.debug("Leaving proofVerify().");
  return bls.fields.Fp12.eql(bls.pairing(p.Abar, w), bls.pairing(p.Bbar,
                             G2.BASE));
}

module.exports = {
  CIPHERSUITE_ID: CIPHERSUITE_ID,
  API_ID: API_ID,
  P1: P1,
  OCTET_SCALAR_LENGTH: OCTET_SCALAR_LENGTH,
  OCTET_POINT_LENGTH: OCTET_POINT_LENGTH,
  te: te,
  concatBytes: concatBytes,
  i2osp: i2osp,
  hashToScalar: hashToScalar,
  createGenerators: createGenerators,
  messagesToScalars: messagesToScalars,
  secretKeyToPublicKey: secretKeyToPublicKey,
  calculateDomain: calculateDomain,
  computeB: computeB,
  sign: sign,
  verify: verify,
  proofGen: proofGen,
  proofVerify: proofVerify,
  serializeArray: serializeArray
};
