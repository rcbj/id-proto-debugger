// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_revocation.js
//
// ---------------------------------------------------------------------------
// AnonCreds REVOCATION (#479): the CKS accumulator and the non-revocation
// proof, holder and verifier, over amcl_bn254.js's pairing. No DOM. Written
// from anoncreds-clsignatures 0.3.2 / anoncreds-rs v0.2.3, which
// tests/anoncreds_engine.js holds it to.
//
//   * the credential request blinds vr' as ur = vr'*h2;
//   * processing sets vr = vr' + vr'' and checks the three pairing
//     equations the issuer's data must satisfy (the first,
//     e(g_i, V) * e(-g, omega) = z, is the one that fails when the pairing
//     is not bit-identical to amcl's);
//   * the revocation state comes from the TAILS file (00 02 then 2L+1 G2
//     points; its name, tailsHash, is base58 of its SHA-256, checked here
//     although anoncreds-rs does not) and the status list: the witness is
//     the sum of tail[L+1-j+i] over the issued j other than i;
//   * the non-revocation proof's seven commitments and eight tau values go
//     AHEAD of the sub-proof's primary items in the challenge, the
//     responses are tilde + c*value mod r, and the verifier recomputes the
//     taus under r - c with the PRIMARY proof's m2 response reduced mod r,
//     which is what ties the two proofs to one credential.
// ---------------------------------------------------------------------------

var bn = require("./amcl_bn254");
var bytes = require("./crypto_bytes");
var provider = require("./crypto_provider");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds_revocation",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var R = bn.R;
var G1 = bn.G1;
var G2 = bn.G2;
var NAMES = ["rho", "r", "r_prime", "r_prime_prime", "r_prime_prime_prime",
             "o", "o_prime", "m", "m_prime", "t", "t_prime", "s", "c"];

function md(a) {
  return ((a % R) + R) % R;
}

// The credential definition's revocation public key, parsed.
function revocationKey(credentialDefinition) {
  log.debug("Entering revocationKey().");
  var k = ((credentialDefinition || {}).value || {}).revocation;
  if (!k) {
    log.debug("Leaving revocationKey(). None.");
    return null;
  }
  var out = {};
  ["g", "h", "h0", "h1", "h2", "htilde", "pk"].forEach(function (n) {
    out[n] = bn.g1FromString(k[n]);
  });
  ["g_dash", "h_cap", "u", "y"].forEach(function (n) {
    out[n] = bn.g2FromString(k[n]);
  });
  log.debug("Leaving revocationKey().");
  return out;
}

// The request's ur = vr'*h2, and vr' for the metadata.
function blind(rk) {
  log.debug("Entering blind().");
  var vrPrime = bn.randomGoe();
  log.debug("Leaving blind().");
  return { ur: bn.g1ToString(G1.mul(rk.h2, vrPrime)),
           vrPrime: bn.goeToString(vrPrime) };
}

function accumKeyZ(rrd) {
  log.debug("Entering accumKeyZ().");
  log.debug("Leaving accumKeyZ().");
  return bn.gtFromString(rrd.value.publicKeys.accumKey.z);
}

// processCredential's revocation half: returns the r_credential with
// vr_prime_prime = vr' + vr'' mod r, after the three checks.
function processRevocation(credential, vrPrimeHex, credentialDefinition,
                           rrd) {
  log.debug("Entering processRevocation().");
  var rc = credential.signature.r_credential;
  var rk = revocationKey(credentialDefinition);
  if (!rk || !rrd || !credential.rev_reg || !credential.witness ||
      !vrPrimeHex) {
    log.debug("Leaving processRevocation(). Missing inputs.");
    throw new Error("a revocable credential needs the credential " +
      "definition's revocation key, the revocation registry definition, " +
      "the credential's rev_reg and witness, and the request's vr_prime.");
  }
  if (!rc.i) {
    log.debug("Leaving processRevocation(). Index 0.");
    throw new Error("the credential's revocation index is 0.");
  }
  var vr = md(bn.goeFromString(vrPrimeHex) +
              bn.goeFromString(rc.vr_prime_prime));
  var ws = rc.witness_signature;
  var gi = bn.g1FromString(ws.g_i);
  var V = bn.g2FromString(credential.rev_reg.accum);
  var omega = bn.g2FromString(credential.witness.omega);
  var z = accumKeyZ(rrd);
  if (!bn.gtEq(bn.pairing2(gi, V, G1.neg(rk.g), omega), z)) {
    log.debug("Leaving processRevocation(). Witness check.");
    throw new Error("the issuer's witness does not verify against the " +
      "accumulator: e(g_i, V) * e(-g, omega) is not accumKey.z.");
  }
  var sigmaI = bn.g2FromString(ws.sigma_i);
  if (!bn.gtEq(bn.pairing2(G1.add(rk.pk, gi), sigmaI, G1.neg(rk.g),
                           rk.g_dash), bn.Fp12.ONE)) {
    log.debug("Leaving processRevocation(). sigma_i check.");
    throw new Error("the witness signature sigma_i does not verify.");
  }
  var sigma = bn.g1FromString(rc.sigma);
  var c = bn.goeFromString(rc.c);
  var m2 = bn.goeFromString(rc.m2);
  var giR = bn.g1FromString(rc.g_i);
  var rhs = G1.add(G1.add(rk.h0, G1.mul(rk.h1, m2)),
                   G1.add(G1.mul(rk.h2, vr), giR));
  if (!bn.gtEq(bn.pairing2(sigma, G2.add(rk.y, G2.mul(rk.h_cap, c)),
                           G1.neg(rhs), rk.h_cap), bn.Fp12.ONE)) {
    log.debug("Leaving processRevocation(). sigma check.");
    throw new Error("the non-revocation signature sigma does not verify.");
  }
  var out = JSON.parse(JSON.stringify(rc));
  out.vr_prime_prime = bn.goeToString(vr);
  log.debug("Leaving processRevocation().");
  return out;
}

// --- tails --------------------------------------------------------------
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(b) {
  log.debug("Entering base58().");
  var n = BigInt("0x" + (bytes.bytesToHex(b) || "0"));
  var s = "";
  while (n > BigInt(0)) {
    s = B58[Number(n % BigInt(58))] + s;
    n /= BigInt(58);
  }
  for (var i = 0; i < b.length && b[i] === 0; i++) s = "1" + s;
  log.debug("Leaving base58().");
  return s;
}

function tailsHash(tailsBytes) {
  log.debug("Entering tailsHash().");
  log.debug("Leaving tailsHash().");
  return base58(provider.digest("sha256", tailsBytes));
}

function tail(tailsBytes, k) {
  log.debug("Entering tail(). " + k);
  var at = 2 + 128 * k;
  log.debug("Leaving tail().");
  return bn.g2FromBytes(tailsBytes.slice(at, at + 128));
}

// The revocation state of credential index i under a status list:
// { witness: { omega }, rev_reg: { accum }, timestamp }. The witness is
// checked against the list's accumulator (e(g_i, V) * e(-g, omega) = z);
// anoncreds-rs's own holder always counts index L as issued, which is
// right for an issuance-by-default registry and wrong otherwise, so both
// readings are tried and the one that verifies kept.
function revocationState(opts) {
  log.debug("Entering revocationState().");
  var rrd = opts.revocationRegistryDefinition;
  var list = opts.revocationStatusList;
  var tb = opts.tailsBytes;
  if (rrd.value.tailsHash && tailsHash(tb) !== rrd.value.tailsHash) {
    log.debug("Leaving revocationState(). Tails hash.");
    throw new Error("the tails file is not the one the registry names: " +
                    "its SHA-256 is " + tailsHash(tb) + ", not " +
                    rrd.value.tailsHash + ".");
  }
  var L = rrd.value.maxCredNum;
  var rc = opts.credential.signature.r_credential;
  var i = rc.i;
  var bits = list.revocationList || [];
  var base = G2.inf;
  for (var j = 1; j < L; j++) {
    if (j !== i && bits[j] === 0) base = G2.add(base, tail(tb, L + 1 - j + i));
  }
  var withLast = j !== i ? G2.add(base, tail(tb, 1 + i)) : base;
  var V = bn.g2FromString(list.currentAccumulator);
  var rk = revocationKey(opts.credentialDefinition);
  var gi = bn.g1FromString(rc.witness_signature.g_i);
  var z = accumKeyZ(rrd);
  var holds = function (omega) {
    return bn.gtEq(bn.pairing2(gi, V, G1.neg(rk.g), omega), z);
  };
  var omega = holds(withLast) ? withLast : holds(base) ? base : null;
  if (!omega) {
    log.debug("Leaving revocationState(). Revoked or inconsistent.");
    throw new Error("no witness for index " + i + " verifies against this " +
      "status list's accumulator: the credential is revoked under it, or " +
      "the list and tails do not belong together.");
  }
  log.debug("Leaving revocationState().");
  return { witness: { omega: bn.g2ToString(omega) },
           rev_reg: { accum: list.currentAccumulator },
           timestamp: list.timestamp };
}

// --- the proof ------------------------------------------------------------
function tau(rk, p, m2, V, cl) {
  log.debug("Entering tau().");
  var ht = rk.htilde;
  var T1 = G1.add(G1.mul(rk.h, p.rho), G1.mul(ht, p.o));
  var T2 = G1.add(G1.mul(cl.E, p.c), G1.neg(G1.add(G1.mul(rk.h, p.m),
                                                    G1.mul(ht, p.t))));
  var a3 = G1.add(G1.add(G1.mul(cl.A, p.c), G1.mul(ht, md(p.r - p.m))),
                  G1.neg(G1.add(G1.mul(rk.h1, m2), G1.mul(rk.h2, p.s))));
  var T3 = bn.pairing2(a3, rk.h_cap, G1.neg(G1.mul(ht, p.rho)), rk.y);
  var T4 = bn.pairing2(G1.mul(ht, p.r), V, G1.neg(G1.mul(rk.g, p.r_prime)),
                       rk.h_cap);
  var T5 = G1.add(G1.mul(rk.g, p.r), G1.mul(ht, p.o_prime));
  var T6 = G1.add(G1.mul(cl.D, p.r_prime_prime),
                  G1.neg(G1.add(G1.mul(rk.g, p.m_prime),
                                G1.mul(ht, p.t_prime))));
  var T7 = bn.pairing2(G1.add(G1.mul(G1.add(rk.pk, cl.G), p.r_prime_prime),
                              G1.neg(G1.mul(ht, p.m_prime))), rk.h_cap,
                       G1.mul(ht, p.r), cl.S);
  var T8 = bn.pairing2(G1.mul(ht, p.r), rk.u,
                       G1.neg(G1.mul(rk.g, p.r_prime_prime_prime)), rk.h_cap);
  log.debug("Leaving tau().");
  return { g1: [T1, T2, T5, T6], gt: [T3, T4, T7, T8] };
}

function tauBytes(t) {
  log.debug("Entering tauBytes().");
  log.debug("Leaving tauBytes().");
  return [bn.g1ToBytes(t.g1[0]), bn.g1ToBytes(t.g1[1]), bn.gtToBytes(t.gt[0]),
          bn.gtToBytes(t.gt[1]), bn.g1ToBytes(t.g1[2]), bn.g1ToBytes(t.g1[3]),
          bn.gtToBytes(t.gt[2]), bn.gtToBytes(t.gt[3])];
}

function cListBytes(cl) {
  log.debug("Entering cListBytes().");
  log.debug("Leaving cListBytes().");
  return [bn.g1ToBytes(cl.E), bn.g1ToBytes(cl.D), bn.g1ToBytes(cl.A),
          bn.g1ToBytes(cl.G), bn.g2ToBytes(cl.W), bn.g2ToBytes(cl.S),
          bn.g2ToBytes(cl.U)];
}

// The prover's half before the challenge. m2Tilde is the PRIMARY proof's
// m~2 (an integer), shared. Returns { cBytes, tauBytes, finalize(c) }.
function proverInit(credential, state, credentialDefinition, m2Tilde) {
  log.debug("Entering proverInit().");
  var rk = revocationKey(credentialDefinition);
  var rc = credential.signature.r_credential;
  var x = {};
  ["rho", "r", "r_prime", "r_prime_prime", "r_prime_prime_prime", "o",
   "o_prime"].forEach(function (n) {
    x[n] = bn.randomGoe();
  });
  x.c = bn.goeFromString(rc.c);
  x.s = bn.goeFromString(rc.vr_prime_prime);
  x.m = md(x.rho * x.c);
  x.m_prime = md(x.r * x.r_prime_prime);
  x.t = md(x.o * x.c);
  x.t_prime = md(x.o_prime * x.r_prime_prime);
  var ht = rk.htilde;
  var omega = bn.g2FromString(state.witness.omega);
  var V = bn.g2FromString(state.rev_reg.accum);
  var ws = rc.witness_signature;
  var cl = {
    E: G1.add(G1.mul(rk.h, x.rho), G1.mul(ht, x.o)),
    D: G1.add(G1.mul(rk.g, x.r), G1.mul(ht, x.o_prime)),
    A: G1.add(bn.g1FromString(rc.sigma), G1.mul(ht, x.rho)),
    G: G1.add(bn.g1FromString(rc.g_i), G1.mul(ht, x.r)),
    W: G2.add(omega, G2.mul(rk.h_cap, x.r_prime)),
    S: G2.add(bn.g2FromString(ws.sigma_i), G2.mul(rk.h_cap,
                                                  x.r_prime_prime)),
    U: G2.add(bn.g2FromString(ws.u_i), G2.mul(rk.h_cap,
                                              x.r_prime_prime_prime))
  };
  var tilde = {};
  NAMES.forEach(function (n) {
    tilde[n] = bn.randomGoe();
  });
  var t = tau(rk, tilde, md(m2Tilde), V, cl);
  log.debug("Leaving proverInit().");
  return {
    cBytes: cListBytes(cl),
    tauBytes: tauBytes(t),
    finalize: function (cHash) {
      var ch = md(cHash);
      var xl = {};
      NAMES.forEach(function (n) {
        xl[n] = bn.goeToString(md(tilde[n] + ch * x[n]));
      });
      return { x_list: xl, c_list: {
        e: bn.g1ToString(cl.E), d: bn.g1ToString(cl.D),
        a: bn.g1ToString(cl.A), g: bn.g1ToString(cl.G),
        w: bn.g2ToString(cl.W), s: bn.g2ToString(cl.S),
        u: bn.g2ToString(cl.U) } };
    }
  };
}

// The verifier's tau items for one sub-proof's non-revocation proof, and
// the c_list bytes its points must have: { tauBytes, cBytes }.
function verifierTau(nrp, credentialDefinition, rrd, accumString, cHash,
                     m2Response) {
  log.debug("Entering verifierTau().");
  var rk = revocationKey(credentialDefinition);
  var z = accumKeyZ(rrd);
  var V = bn.g2FromString(accumString);
  var c = nrp.c_list;
  var cl = { E: bn.g1FromString(c.e), D: bn.g1FromString(c.d),
             A: bn.g1FromString(c.a), G: bn.g1FromString(c.g),
             W: bn.g2FromString(c.w), S: bn.g2FromString(c.s),
             U: bn.g2FromString(c.u) };
  var hat = {};
  NAMES.forEach(function (n) {
    hat[n] = bn.goeFromString(nrp.x_list[n]);
  });
  var neg = md(-md(cHash));
  var calc = tau(rk, hat, md(m2Response), V, cl);
  var T3e = bn.pairing2(G1.add(rk.h0, cl.G), rk.h_cap, G1.neg(cl.A), rk.y);
  var T4e = bn.gtMul(bn.pairing2(cl.G, V, G1.neg(rk.g), cl.W),
                     bn.gtInv(z));
  var T7e = bn.pairing2(G1.add(rk.pk, cl.G), cl.S, G1.neg(rk.g), rk.g_dash);
  var T8e = bn.pairing2(cl.G, rk.u, G1.neg(rk.g), cl.U);
  var g1 = [G1.add(G1.mul(cl.E, neg), calc.g1[0]), calc.g1[1],
            G1.add(G1.mul(cl.D, neg), calc.g1[2]), calc.g1[3]];
  var gt = [T3e, T4e, T7e, T8e].map(function (e, k) {
    return bn.gtMul(bn.gtPow(e, neg), calc.gt[k]);
  });
  log.debug("Leaving verifierTau().");
  return { tauBytes: tauBytes({ g1: g1, gt: gt }), cBytes: cListBytes(cl) };
}

// The non-revocation interval a sub-proof is asked for (R7.6): the most
// stringent of its revealed attributes' and predicates' own intervals,
// else the request's.
function intervalFor(request, attrRefs, predRefs) {
  log.debug("Entering intervalFor().");
  var local = null;
  var merge = function (iv) {
    if (!iv) return;
    if (!local) {
      local = { from: iv.from, to: iv.to };
      return;
    }
    if (iv.from !== undefined && (local.from === undefined ||
                                  iv.from > local.from)) local.from = iv.from;
    if (iv.to !== undefined && (local.to === undefined || iv.to < local.to)) {
      local.to = iv.to;
    }
  };
  attrRefs.forEach(function (r) {
    merge(((request.requested_attributes || {})[r] || {}).non_revoked);
  });
  predRefs.forEach(function (r) {
    merge(((request.requested_predicates || {})[r] || {}).non_revoked);
  });
  log.debug("Leaving intervalFor().");
  return local || request.non_revoked || null;
}

module.exports = {
  revocationKey: revocationKey,
  blind: blind,
  processRevocation: processRevocation,
  tailsHash: tailsHash,
  revocationState: revocationState,
  proverInit: proverInit,
  verifierTau: verifierTau,
  intervalFor: intervalFor
};
