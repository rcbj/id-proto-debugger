// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: amcl_bn254.js
//
// ---------------------------------------------------------------------------
// The pairing-friendly curve AnonCreds revocation is built on (#479), as
// anoncreds-clsignatures uses it through Apache Milagro (amcl) "BN254".
// Pure JS (BigInt, over @noble/curves 1.9's field tower); no DOM.
//
// It is NOT the alt_bn128 curve @noble/curves calls bn254. It is Nogami's
// Barreto-Naehrig curve:
//
//   x = -(2^62 + 2^55 + 1);  p = 36x^4+36x^3+24x^2+6x+1;  r = ... +18x^2+...
//   G1: y^2 = x^3 + 2 over Fp, generator (-1, 1);
//   Fp2 = Fp[i]/(i^2 + 1); xi = 1 + i; G2 on the D-type twist
//   y^2 = x^3 + 2/xi = x^3 + (1 - i).
//
// The pairing is the optimal ate pairing, written plainly in Fp12 rather
// than with sparse line tricks: the Miller loop over |6x+2| (negative here,
// so its value is inverted and the point negated), the two Frobenius
// lines, and the EXACT final exponentiation f^((p^12-1)/r). Exactness
// matters because pairing values are hashed into the non-revocation
// proof's challenge: a pairing that is amcl's raised to some power
// verifies its own proofs and interoperates with nothing.
//
// amcl's encodings, which anoncreds-rs's JSON carries:
//
//   * a field element as "xes HEX", HEX its Montgomery residue v*R mod p
//     (R = 2^280, R mod p = 095E45DD...), possibly unreduced; xes ignored;
//   * G1 "X Y Z", G2 "Xa Xb Ya Yb Za Zb" (homogeneous projective), GT the 12
//     Fp coefficients A.a.a A.a.b A.b.a ... C.b.b;
//   * a group-order element as 64 hex digits;
//   * bytes (what the challenge hashes): G1 04||x||y then 63 zero bytes,
//     G2 x.a||x.b||y.a||y.b, GT the 12 coefficients then 128 zero bytes,
//     each 32 bytes big-endian, affine and fully reduced.
//
// The tower is noble's (Fp6 = Fp2[v]/(v^3 - xi), Fp12 = Fp6[w]/(w^2 - v));
// amcl's FP12 = A + B*w + C*w^2 over FP4 = a + b*s (s^2 = xi, w^3 = s) maps
// onto it as amcl (A.a, A.b, B.a, B.b, C.a, C.b) = noble (c0.c0, c1.c1,
// c1.c0, c0.c2, c0.c1, c1.c2).
// ---------------------------------------------------------------------------

var tower = require("@noble/curves-v1.9/abstract/tower.js");
var bytes = require("./crypto_bytes");
var provider = require("./crypto_provider");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "amcl_bn254",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var ZERO = BigInt(0);
var ONE = BigInt(1);
var TWO = BigInt(2);
var THREE = BigInt(3);

var X = -(BigInt(1) << BigInt(62)) - (BigInt(1) << BigInt(55)) - ONE;
var P = BigInt("0x2523648240000001BA344D80000000086121000000000013A700000000" +
               "000013");
var R = BigInt("0x2523648240000001BA344D8000000007FF9F800000000010A100000000" +
               "00000D");
var RMODP = BigInt("0x095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFF" +
                   "FF7D07A8A8");
var FINAL_EXP = (P ** BigInt(12) - ONE) / R;

var TWIST_B = null;
var T = tower.tower12({
  ORDER: P,
  X_LEN: 64,
  FP2_NONRESIDUE: [ONE, ONE],
  Fp2mulByB: function (n) {
    return T.Fp2.mul(n, TWIST_B);
  },
  Fp12finalExponentiate: function (f) {
    return T.Fp12.pow(f, FINAL_EXP);
  }
});
var Fp = T.Fp;
var Fp2 = T.Fp2;
var Fp6 = T.Fp6;
var Fp12 = T.Fp12;
TWIST_B = Fp2.fromBigTuple([ONE, P - ONE]);
var G1_B = BigInt(2);
var RMODP_INV = Fp.inv(RMODP);

// --- generic short-Weierstrass arithmetic, y^2 = x^3 + b, affine ----------
// The helpers below run inside scalar multiplications and the Miller loop,
// so they carry no entry/exit logging; the functions that call them do.
function curve(F, b) {
  var inf = { inf: true };
  var isInf = function (Pt) {
    return !!Pt.inf;
  };
  var neg = function (Pt) {
    return isInf(Pt) ? Pt : { x: Pt.x, y: F.neg(Pt.y) };
  };
  var dbl = function (Pt) {
    if (isInf(Pt) || F.is0(Pt.y)) return inf;
    var l = F.div(F.mul(F.sqr(Pt.x), THREE), F.add(Pt.y, Pt.y));
    var x3 = F.sub(F.sqr(l), F.add(Pt.x, Pt.x));
    return { x: x3, y: F.sub(F.mul(l, F.sub(Pt.x, x3)), Pt.y) };
  };
  var add = function (A, B) {
    if (isInf(A)) return B;
    if (isInf(B)) return A;
    if (F.eql(A.x, B.x)) return F.eql(A.y, B.y) ? dbl(A) : inf;
    var l = F.div(F.sub(B.y, A.y), F.sub(B.x, A.x));
    var x3 = F.sub(F.sub(F.sqr(l), A.x), B.x);
    return { x: x3, y: F.sub(F.mul(l, F.sub(A.x, x3)), A.y) };
  };
  var mul = function (Pt, k) {
    var n = ((k % R) + R) % R;
    var acc = inf;
    var base = Pt;
    while (n > ZERO) {
      if (n & ONE) acc = add(acc, base);
      base = dbl(base);
      n >>= ONE;
    }
    return acc;
  };
  var onCurve = function (Pt) {
    return isInf(Pt) || F.eql(F.sqr(Pt.y),
                              F.add(F.mul(F.sqr(Pt.x), Pt.x), b));
  };
  var eq = function (A, B) {
    if (isInf(A) || isInf(B)) return isInf(A) && isInf(B);
    return F.eql(A.x, B.x) && F.eql(A.y, B.y);
  };
  return { inf: inf, isInf: isInf, neg: neg, dbl: dbl, add: add, mul: mul,
           onCurve: onCurve, eq: eq };
}

var G1 = curve(Fp, G1_B);
var G2 = curve(Fp2, TWIST_B);
var G1_GEN = { x: P - ONE, y: ONE };

// --- the pairing -------------------------------------------------------------
var FP12_ZERO6 = Fp6.ZERO;

function fp12(c0, c1) {
  return Fp12.create ? Fp12.create({ c0: c0, c1: c1 }) : { c0: c0, c1: c1 };
}

function fp6(c0, c1, c2) {
  return Fp6.create ? Fp6.create({ c0: c0, c1: c1, c2: c2 }) :
    { c0: c0, c1: c1, c2: c2 };
}

// psi: the D-type untwist, (x', y') -> (x' w^2, y' w^3) in E(Fp12).
function untwist(Q) {
  return { x: fp12(fp6(Fp2.ZERO, Q.x, Fp2.ZERO), FP12_ZERO6),
           y: fp12(FP12_ZERO6, fp6(Fp2.ZERO, Q.y, Fp2.ZERO)) };
}

function fromFp(v) {
  return fp12(fp6(Fp2.fromBigTuple([v, ZERO]), Fp2.ZERO, Fp2.ZERO),
              FP12_ZERO6);
}

var E12 = curve(Fp12, fromFp(G1_B));

// The line through A and B (tangent when equal), evaluated at P (all in
// E(Fp12)); with A + B returned.
function line(A, B, Pt) {
  var l;
  if (Fp12.eql(A.x, B.x) && Fp12.eql(A.y, B.y)) {
    l = Fp12.div(Fp12.mul(Fp12.sqr(A.x), fromFp(THREE)),
                 Fp12.add(A.y, A.y));
  } else if (Fp12.eql(A.x, B.x)) {
    return { value: Fp12.sub(Pt.x, A.x), sum: E12.inf };
  } else {
    l = Fp12.div(Fp12.sub(B.y, A.y), Fp12.sub(B.x, A.x));
  }
  var value = Fp12.sub(Fp12.sub(Pt.y, A.y), Fp12.mul(l, Fp12.sub(Pt.x,
                                                                  A.x)));
  return { value: value, sum: E12.add(A, B) };
}

function frobenius(Pt, k) {
  return { x: Fp12.frobeniusMap(Pt.x, k), y: Fp12.frobeniusMap(Pt.y, k) };
}

var LOOP = -(BigInt(6) * X + TWO);
var LOOP_BITS = LOOP.toString(2);

// The Miller loop of the optimal ate pairing, before the final
// exponentiation.
function miller(Pg1, Qg2) {
  log.debug("Entering miller().");
  var Pt = { x: fromFp(Pg1.x), y: fromFp(Pg1.y) };
  var Q = untwist(Qg2);
  var f = Fp12.ONE;
  var Tp = Q;
  for (var i = 1; i < LOOP_BITS.length; i++) {
    var d = line(Tp, Tp, Pt);
    f = Fp12.mul(Fp12.sqr(f), d.value);
    Tp = d.sum;
    if (LOOP_BITS[i] === "1") {
      var a = line(Tp, Q, Pt);
      f = Fp12.mul(f, a.value);
      Tp = a.sum;
    }
  }
  // 6x+2 < 0: f_{-n,Q} = 1 / f_{n,Q} (verticals vanish in the final
  // exponentiation) and [6x+2]Q = -[n]Q.
  f = Fp12.inv(f);
  Tp = E12.neg(Tp);
  var q1 = frobenius(Q, 1);
  var q2 = E12.neg(frobenius(Q, 2));
  var l1 = line(Tp, q1, Pt);
  f = Fp12.mul(f, l1.value);
  var l2 = line(l1.sum, q2, Pt);
  f = Fp12.mul(f, l2.value);
  log.debug("Leaving miller().");
  return f;
}

function pairing(Pg1, Qg2) {
  log.debug("Entering pairing().");
  if (G1.isInf(Pg1) || G2.isInf(Qg2)) {
    log.debug("Leaving pairing(). Infinity.");
    return Fp12.ONE;
  }
  var out = Fp12.pow(miller(Pg1, Qg2), FINAL_EXP);
  log.debug("Leaving pairing().");
  return out;
}

// e(P1,Q1) * e(P2,Q2), one final exponentiation.
function pairing2(P1, Q1, P2, Q2) {
  log.debug("Entering pairing2().");
  var f = Fp12.ONE;
  if (!G1.isInf(P1) && !G2.isInf(Q1)) f = Fp12.mul(f, miller(P1, Q1));
  if (!G1.isInf(P2) && !G2.isInf(Q2)) f = Fp12.mul(f, miller(P2, Q2));
  log.debug("Leaving pairing2().");
  return Fp12.pow(f, FINAL_EXP);
}

// --- encodings -----------------------------------------------------------
function hex64(v) {
  return v.toString(16).toUpperCase().padStart(64, "0");
}

function fpFromMont(hex) {
  return Fp.mul(Fp.create(BigInt("0x" + hex) % P), RMODP_INV);
}

function fpToMont(v) {
  return Fp.mul(v, RMODP);
}

function tokens(str, n, what) {
  var t = String(str).trim().split(/\s+/);
  if (t.length !== 2 * n) {
    throw new Error(what + " has " + t.length + " tokens, not " + 2 * n +
                    ".");
  }
  var out = [];
  for (var i = 0; i < n; i++) {
    if (!/^\d+$/.test(t[2 * i]) || Number(t[2 * i]) === 0 ||
        !/^[0-9a-fA-F]+$/.test(t[2 * i + 1])) {
      throw new Error(what + " is not amcl's \"xes HEX\" form.");
    }
    out.push(fpFromMont(t[2 * i + 1]));
  }
  return out;
}

function g1FromString(str) {
  log.debug("Entering g1FromString().");
  var v = tokens(str, 3, "a G1 point");
  if (Fp.is0(v[2])) {
    log.debug("Leaving g1FromString(). Infinity.");
    return G1.inf;
  }
  var zi = Fp.inv(v[2]);
  var pt = { x: Fp.mul(v[0], zi), y: Fp.mul(v[1], zi) };
  if (!G1.onCurve(pt)) {
    log.debug("Leaving g1FromString(). Off the curve.");
    throw new Error("a G1 point is not on y^2 = x^3 + 2.");
  }
  log.debug("Leaving g1FromString().");
  return pt;
}

function g2FromString(str) {
  log.debug("Entering g2FromString().");
  var v = tokens(str, 6, "a G2 point");
  var Z = Fp2.fromBigTuple([v[4], v[5]]);
  if (Fp2.is0(Z)) {
    log.debug("Leaving g2FromString(). Infinity.");
    return G2.inf;
  }
  var zi = Fp2.inv(Z);
  var pt = { x: Fp2.mul(Fp2.fromBigTuple([v[0], v[1]]), zi),
             y: Fp2.mul(Fp2.fromBigTuple([v[2], v[3]]), zi) };
  if (!G2.onCurve(pt)) {
    log.debug("Leaving g2FromString(). Off the twist.");
    throw new Error("a G2 point is not on the twist.");
  }
  log.debug("Leaving g2FromString().");
  return pt;
}

function g1ToString(pt) {
  log.debug("Entering g1ToString().");
  log.debug("Leaving g1ToString().");
  if (G1.isInf(pt)) {
    return "1 " + hex64(ZERO) + " 2 " + hex64(RMODP) + " 1 " + hex64(ZERO);
  }
  return "1 " + hex64(fpToMont(pt.x)) + " 1 " + hex64(fpToMont(pt.y)) +
    " 2 " + hex64(RMODP);
}

function g2ToString(pt) {
  log.debug("Entering g2ToString().");
  var z = hex64(ZERO);
  log.debug("Leaving g2ToString().");
  if (G2.isInf(pt)) {
    return ["1 " + z, "1 " + z, "2 " + hex64(RMODP), "1 " + z, "1 " + z,
            "1 " + z].join(" ");
  }
  return ["1 " + hex64(fpToMont(pt.x.c0)), "1 " + hex64(fpToMont(pt.x.c1)),
          "1 " + hex64(fpToMont(pt.y.c0)), "1 " + hex64(fpToMont(pt.y.c1)),
          "2 " + hex64(RMODP), "1 " + z].join(" ");
}

// The 12 Fp coefficients of an Fp12 in amcl's order.
function gtCoefficients(f) {
  var pairs = [f.c0.c0, f.c1.c1, f.c1.c0, f.c0.c2, f.c0.c1, f.c1.c2];
  var out = [];
  pairs.forEach(function (e) {
    out.push(e.c0, e.c1);
  });
  return out;
}

function gtFromCoefficients(c) {
  var e = function (i) {
    return Fp2.fromBigTuple([c[2 * i], c[2 * i + 1]]);
  };
  return fp12(fp6(e(0), e(4), e(3)), fp6(e(2), e(1), e(5)));
}

function gtFromString(str) {
  log.debug("Entering gtFromString().");
  log.debug("Leaving gtFromString().");
  return gtFromCoefficients(tokens(str, 12, "a pairing value"));
}

function gtToString(f) {
  log.debug("Entering gtToString().");
  log.debug("Leaving gtToString().");
  return gtCoefficients(f).map(function (v) {
    return "1 " + hex64(fpToMont(v));
  }).join(" ");
}

function be32(v) {
  return bytes.hexToBytes(v.toString(16).padStart(64, "0"));
}

function cat(list) {
  var n = 0;
  list.forEach(function (b) {
    n += b.length;
  });
  var out = new Uint8Array(n);
  var at = 0;
  list.forEach(function (b) {
    out.set(b, at);
    at += b.length;
  });
  return out;
}

function g1ToBytes(pt) {
  log.debug("Entering g1ToBytes().");
  var x = G1.isInf(pt) ? ZERO : pt.x;
  var y = G1.isInf(pt) ? ONE : pt.y;
  log.debug("Leaving g1ToBytes().");
  return cat([new Uint8Array([4]), be32(x), be32(y), new Uint8Array(63)]);
}

function g2ToBytes(pt) {
  log.debug("Entering g2ToBytes().");
  if (G2.isInf(pt)) {
    log.debug("Leaving g2ToBytes(). Infinity.");
    return new Uint8Array(128);
  }
  log.debug("Leaving g2ToBytes().");
  return cat([be32(pt.x.c0), be32(pt.x.c1), be32(pt.y.c0), be32(pt.y.c1)]);
}

function g2FromBytes(b) {
  log.debug("Entering g2FromBytes().");
  var n = function (i) {
    return BigInt("0x" + bytes.bytesToHex(b.slice(32 * i, 32 * i + 32)));
  };
  var pt = { x: Fp2.fromBigTuple([n(0), n(1)]),
             y: Fp2.fromBigTuple([n(2), n(3)]) };
  log.debug("Leaving g2FromBytes().");
  return G2.onCurve(pt) ? pt : G2.inf;
}

function gtToBytes(f) {
  log.debug("Entering gtToBytes().");
  log.debug("Leaving gtToBytes().");
  return cat(gtCoefficients(f).map(be32).concat([new Uint8Array(128)]));
}

// --- group-order elements ------------------------------------------------
function goeFromString(str) {
  log.debug("Entering goeFromString().");
  log.debug("Leaving goeFromString().");
  return BigInt("0x" + String(str).trim()) % R;
}

function goeToString(v) {
  log.debug("Entering goeToString().");
  log.debug("Leaving goeToString().");
  return hex64(((v % R) + R) % R);
}

function goeToBytes(v) {
  log.debug("Entering goeToBytes().");
  log.debug("Leaving goeToBytes().");
  return be32(((v % R) + R) % R);
}

function randomGoe() {
  log.debug("Entering randomGoe().");
  var b = provider.randomBytes(64);
  log.debug("Leaving randomGoe().");
  return BigInt("0x" + bytes.bytesToHex(b)) % R;
}

module.exports = {
  P: P, R: R, X: X, RMODP: RMODP,
  Fp: Fp, Fp2: Fp2, Fp12: Fp12,
  G1: G1, G2: G2, G1_GEN: G1_GEN,
  pairing: pairing, pairing2: pairing2,
  gtMul: function (a, b) {
    return Fp12.mul(a, b);
  },
  gtPow: function (a, k) {
    return Fp12.pow(a, ((k % R) + R) % R);
  },
  gtInv: function (a) {
    return Fp12.inv(a);
  },
  gtEq: function (a, b) {
    return Fp12.eql(a, b);
  },
  g1FromString: g1FromString, g1ToString: g1ToString, g1ToBytes: g1ToBytes,
  g2FromString: g2FromString, g2ToString: g2ToString, g2ToBytes: g2ToBytes,
  g2FromBytes: g2FromBytes,
  gtFromString: gtFromString, gtToString: gtToString, gtToBytes: gtToBytes,
  goeFromString: goeFromString, goeToString: goeToString,
  goeToBytes: goeToBytes, randomGoe: randomGoe
};
