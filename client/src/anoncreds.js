// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds.js
//
// ---------------------------------------------------------------------------
// AnonCreds 1.0 (#479), the HOLDER and the VERIFIER, CL signatures, no
// revocation. Pure JS (BigInt); no DOM. Written from the AnonCreds
// specification and the byte-level behaviour of anoncreds-rs v0.2.3 /
// anoncreds-clsignatures 0.3.2, which is what every AnonCreds deployment
// runs — the specification publishes no test vectors, so tests/
// anoncreds_engine.js holds this to anoncreds-rs itself, in both
// directions.
//
// The API mirrors anoncreds-rs's (createCredentialRequest,
// processCredential, createPresentation, verifyPresentation) over the same
// JSON objects, so a test can swap one for the other at any step.
//
// What decides interoperability, each point checked against anoncreds-rs:
//
//   * every hash is SHA-256 over the plain concatenation of each number's
//     minimal big-endian bytes, sign dropped, zero as no bytes at all, and
//     the digest read as an unsigned big-endian integer;
//   * the presentation challenge is over every sub-proof's tau items, then
//     every c_list item, then the request's nonce — revealed values, m2 and
//     the public key are not in it;
//   * the e response is offset by 2^596 and the verifier puts it back;
//   * attribute names inside CL are spaces removed then lower-cased, and the
//     link secret is the hidden attribute "master_secret", one random
//     witness for it shared by every sub-proof;
//   * an attribute that parses as an i32 is encoded as that integer, any
//     other value as SHA-256 of its UTF-8 bytes read big-endian;
//   * the key correctness proof is hashed in the order the issuer sent
//     xr_cap, which is whatever order its HashMap had.
//
// The verifier checks three things anoncreds-rs 0.2.3 does not: that each
// predicate in the proof is the one the request asked for, that c_list is
// the A' and T values the sub-proofs carry, and that a revealed raw value
// encodes to its encoded value.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
// Revocation: the CKS accumulator and the non-revocation proof.
var rev = require("./anoncreds_revocation");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// anoncreds-clsignatures 0.3.2 constants.rs.
var C = {
  LINK_SECRET: 256, E_START: 596, VPRIME: 2128, MVECT: 592, ETILDE: 456,
  VTILDE: 3060, UTILDE: 592, MTILDE: 593, M2TILDE: 2432, VPRIME_TILDE: 673,
  RTILDE: 672, NONCE: 80, ALPHATILDE: 2787
};
var E_START_VALUE = BigInt(1) << BigInt(C.E_START);
var LINK_SECRET_ATTR = "master_secret";
var P_TYPES = { ">=": "GE", "<=": "LE", ">": "GT", "<": "LT" };
var P_ORDER = { GE: 0, LE: 1, GT: 2, LT: 3 };

// --- arithmetic --------------------------------------------------------------
// The helpers below run thousands of times per presentation (every modPow
// is a loop over thousands of bits), so they carry no entry/exit logging;
// the functions that call them do.

var ZERO = BigInt(0);
var ONE = BigInt(1);
var TWO = BigInt(2);

function big(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  var s = String(v).trim();
  if (!/^-?\d+$/.test(s)) {
    throw new Error("not a decimal integer: " + JSON.stringify(s).slice(0, 40));
  }
  return BigInt(s);
}

function dec(v) {
  return v.toString(10);
}

function mod(a, n) {
  var r = a % n;
  return r < ZERO ? r + n : r;
}

function inverse(a, n) {
  var t = ZERO;
  var newT = ONE;
  var r = n;
  var newR = mod(a, n);
  while (newR !== ZERO) {
    var q = r / newR;
    var tmp = t - q * newT;
    t = newT;
    newT = tmp;
    tmp = r - q * newR;
    r = newR;
    newR = tmp;
  }
  if (r !== ONE) throw new Error("no modular inverse");
  return mod(t, n);
}

// base^exp mod n; a negative exponent is the inverse's power, as
// anoncreds-clsignatures' mod_exp has it.
function modPow(base, exp, n) {
  var b = mod(base, n);
  var e = exp;
  if (e < ZERO) {
    b = inverse(b, n);
    e = -e;
  }
  var result = ONE;
  while (e > ZERO) {
    if (e & ONE) result = (result * b) % n;
    e >>= ONE;
    if (e > ZERO) b = (b * b) % n;
  }
  return result;
}

// B(x): minimal big-endian magnitude, sign dropped, zero as no bytes.
function toBytes(x) {
  var v = x < ZERO ? -x : x;
  if (v === ZERO) return new Uint8Array(0);
  var h = v.toString(16);
  if (h.length & 1) h = "0" + h;
  return bytes.hexToBytes(h);
}

function fromBytes(b) {
  if (!b.length) return ZERO;
  return BigInt("0x" + bytes.bytesToHex(b));
}

function concat(list) {
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

// uint_be(SHA256(B(x1) || B(x2) || ...)).
function hashInts(list) {
  return fromBytes(provider.digest("sha256", concat(list.map(function (x) {
    return x instanceof Uint8Array ? x : toBytes(x);
  }))));
}

// A uniform integer in [0, 2^bits).
function rand(bits) {
  var n = Math.ceil(bits / 8);
  var b = provider.randomBytes(n);
  var extra = n * 8 - bits;
  if (extra) b[0] &= 0xff >> extra;
  return fromBytes(b);
}

// Miller-Rabin; the holder checks only that e is prime.
function isProbablePrime(n) {
  log.debug("Entering isProbablePrime().");
  if (n < TWO) {
    log.debug("Leaving isProbablePrime(). < 2.");
    return false;
  }
  var small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
  for (var i = 0; i < small.length; i++) {
    var p = BigInt(small[i]);
    if (n === p) {
      log.debug("Leaving isProbablePrime(). Small prime.");
      return true;
    }
    if (n % p === ZERO) {
      log.debug("Leaving isProbablePrime(). Small factor.");
      return false;
    }
  }
  var d = n - ONE;
  var s = 0;
  while ((d & ONE) === ZERO) {
    d >>= ONE;
    s++;
  }
  var bits = n.toString(2).length;
  for (var round = 0; round < 40; round++) {
    var a = mod(rand(bits), n - BigInt(4)) + TWO;
    var x = modPow(a, d, n);
    if (x === ONE || x === n - ONE) continue;
    var composite = true;
    for (var r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x === n - ONE) {
        composite = false;
        break;
      }
    }
    if (composite) {
      log.debug("Leaving isProbablePrime(). Composite.");
      return false;
    }
  }
  log.debug("Leaving isProbablePrime(). Probably prime.");
  return true;
}

// --- names and values --------------------------------------------------------
function attrCommonView(name) {
  log.debug("Entering attrCommonView().");
  log.debug("Leaving attrCommonView().");
  return String(name).replace(/ /g, "").toLowerCase();
}

// Rust's str::parse::<i32>: an optional sign, ASCII digits, in range.
function parseI32(raw) {
  log.debug("Entering parseI32().");
  var s = String(raw);
  if (!/^[+-]?\d+$/.test(s)) {
    log.debug("Leaving parseI32(). Not digits.");
    return null;
  }
  var v = BigInt(s.charAt(0) === "+" ? s.slice(1) : s);
  if (v < BigInt(-2147483648) || v > BigInt(2147483647)) {
    log.debug("Leaving parseI32(). Out of range.");
    return null;
  }
  log.debug("Leaving parseI32().");
  return Number(v);
}

function encodeAttribute(raw) {
  log.debug("Entering encodeAttribute().");
  var i = parseI32(raw);
  if (i !== null) {
    log.debug("Leaving encodeAttribute(). i32.");
    return String(i);
  }
  log.debug("Leaving encodeAttribute(). SHA-256.");
  return dec(fromBytes(provider.digest("sha256", bytes.strBytes(String(raw)))));
}

function createLinkSecret() {
  log.debug("Entering createLinkSecret().");
  log.debug("Leaving createLinkSecret().");
  return dec(rand(C.LINK_SECRET));
}

function createNonce() {
  log.debug("Entering createNonce().");
  log.debug("Leaving createNonce().");
  return dec(rand(C.NONCE));
}

// The numbers of a credential definition's primary public key.
function primaryKey(credentialDefinition) {
  log.debug("Entering primaryKey().");
  var cd = credentialDefinition;
  var p = ((cd || {}).value || {}).primary;
  if (!p) {
    log.debug("Leaving primaryKey(). None.");
    throw new Error("the credential definition has no value.primary key.");
  }
  if ((cd.type || "CL") !== "CL") {
    log.debug("Leaving primaryKey(). Not CL.");
    throw new Error("signature type " + cd.type + " is not CL.");
  }
  var r = {};
  Object.keys(p.r || {}).forEach(function (k) {
    r[k] = big(p.r[k]);
  });
  if (p.rms !== undefined && r[LINK_SECRET_ATTR] === undefined) {
    r[LINK_SECRET_ATTR] = big(p.rms);
  }
  log.debug("Leaving primaryKey().");
  return { n: big(p.n), s: big(p.s), z: big(p.z), rctxt: big(p.rctxt), r: r,
           revocable: !!cd.value.revocation };
}

// --- the credential offer's key correctness proof (spec 4.2) -----------------
function verifyKeyCorrectnessProof(pk, kcp) {
  log.debug("Entering verifyKeyCorrectnessProof().");
  var pairs = (kcp && kcp.xr_cap) || [];
  var listed = {};
  pairs.forEach(function (p) {
    listed[p[0]] = true;
  });
  var missing = Object.keys(pk.r).filter(function (k) {
    return !listed[k] && k !== LINK_SECRET_ATTR;
  });
  var extra = Object.keys(listed).filter(function (k) {
    return pk.r[k] === undefined;
  });
  if (missing.length || extra.length) {
    log.debug("Leaving verifyKeyCorrectnessProof(). Key sets differ.");
    return "the key correctness proof does not cover the key's attributes " +
      "(missing " + missing.join(", ") + "; extra " + extra.join(", ") + ").";
  }
  var c = big(kcp.c);
  var zCap = (modPow(pk.z, -c, pk.n) * modPow(pk.s, big(kcp.xz_cap), pk.n)) %
    pk.n;
  var rs = [];
  var rCaps = [];
  pairs.forEach(function (p) {
    var rk = pk.r[p[0]];
    rs.push(rk);
    rCaps.push((modPow(rk, -c, pk.n) * modPow(pk.s, big(p[1]), pk.n)) % pk.n);
  });
  var cPrime = hashInts([pk.z].concat(rs, [zCap], rCaps));
  log.debug("Leaving verifyKeyCorrectnessProof(). " + (cPrime === c));
  return cPrime === c ? null : "the issuer's key correctness proof does not " +
    "verify (the credential definition's key is not well formed).";
}

// --- credential request (spec 5.2) -------------------------------------------
// opts: credentialOffer, credentialDefinition, linkSecret (decimal string),
// linkSecretId, entropy (a string; random when absent), proverDid.
function createCredentialRequest(opts) {
  log.debug("Entering createCredentialRequest().");
  var offer = opts.credentialOffer;
  var pk = primaryKey(opts.credentialDefinition);
  var bad = verifyKeyCorrectnessProof(pk, offer.key_correctness_proof);
  if (bad) {
    log.debug("Leaving createCredentialRequest(). KCP.");
    throw new Error(bad);
  }
  if (pk.r[LINK_SECRET_ATTR] === undefined) {
    log.debug("Leaving createCredentialRequest(). No master_secret.");
    throw new Error("the credential definition has no master_secret key.");
  }
  var ms = big(opts.linkSecret);
  var vPrime = rand(C.VPRIME);
  var u = (modPow(pk.s, vPrime, pk.n) *
           modPow(pk.r[LINK_SECRET_ATTR], ms, pk.n)) % pk.n;
  var vTilde = rand(C.VPRIME_TILDE);
  var mTilde = rand(C.MTILDE);
  var uTilde = (modPow(pk.s, vTilde, pk.n) *
                modPow(pk.r[LINK_SECRET_ATTR], mTilde, pk.n)) % pk.n;
  var c = hashInts([u, uTilde, big(offer.nonce)]);
  var nonce = createNonce();
  var request = {};
  if (opts.proverDid && !opts.entropy) {
    request.prover_did = opts.proverDid;
  } else {
    request.entropy = opts.entropy || dec(rand(80));
  }
  request.cred_def_id = offer.cred_def_id;
  // A revocable credential definition: blind vr' as ur = vr'*h2 too.
  var rk = rev.revocationKey(opts.credentialDefinition);
  var blinding = rk ? rev.blind(rk) : null;
  request.blinded_ms = { u: dec(u), ur: blinding ? blinding.ur : null,
                         hidden_attributes: [LINK_SECRET_ATTR],
                         committed_attributes: {} };
  request.blinded_ms_correctness_proof = {
    c: dec(c), v_dash_cap: dec(c * vPrime + vTilde),
    m_caps: { master_secret: dec(mTilde + c * ms) }, r_caps: {} };
  request.nonce = nonce;
  log.debug("Leaving createCredentialRequest().");
  return { credentialRequest: request,
           credentialRequestMetadata: {
             link_secret_blinding_data: { v_prime: dec(vPrime),
               vr_prime: blinding ? blinding.vrPrime : null },
             nonce: nonce, link_secret_name: opts.linkSecretId || "" } };
}

// The CL values of a credential: normalised name -> encoded integer, plus
// the link secret.
function credentialValues(credential, linkSecret) {
  log.debug("Entering credentialValues().");
  var out = {};
  Object.keys(credential.values || {}).forEach(function (k) {
    out[attrCommonView(k)] = big(credential.values[k].encoded);
  });
  if (linkSecret !== undefined) out[LINK_SECRET_ATTR] = big(linkSecret);
  log.debug("Leaving credentialValues().");
  return out;
}

// --- processing the issued credential (spec 5.3) -----------------------------
// Returns the credential with v = v' + v'', after every check the holder
// makes; throws naming the one that failed.
function processCredential(credential, opts) {
  log.debug("Entering processCredential().");
  var pk = primaryKey(opts.credentialDefinition);
  var sig = credential.signature.p_credential;
  var vPrime = big(opts.credentialRequestMetadata.link_secret_blinding_data
    .v_prime);
  var v = vPrime + big(sig.v);
  var e = big(sig.e);
  if (!isProbablePrime(e)) {
    log.debug("Leaving processCredential(). e composite.");
    throw new Error("the signature's e is not prime.");
  }
  var values = credentialValues(credential, opts.linkSecret);
  var keys = Object.keys(pk.r);
  var missing = keys.filter(function (k) {
    return values[k] === undefined;
  });
  var unknown = Object.keys(values).filter(function (k) {
    return pk.r[k] === undefined;
  });
  if (missing.length || unknown.length) {
    log.debug("Leaving processCredential(). Value set.");
    throw new Error("the credential's values are not the credential " +
      "definition's attributes (missing " + missing.join(", ") +
      "; unknown " + unknown.join(", ") + ").");
  }
  var rx = (modPow(pk.s, v, pk.n) * modPow(pk.rctxt, big(sig.m_2), pk.n)) %
    pk.n;
  keys.forEach(function (k) {
    rx = (rx * modPow(pk.r[k], values[k], pk.n)) % pk.n;
  });
  var q = (pk.z * inverse(rx, pk.n)) % pk.n;
  var a = big(sig.a);
  if (modPow(a, e, pk.n) !== q) {
    log.debug("Leaving processCredential(). A^e != Q.");
    throw new Error("the CL signature does not verify (A^e is not Q).");
  }
  var scp = credential.signature_correctness_proof;
  var c = big(scp.c);
  var aCap = modPow(a, c + big(scp.se) * e, pk.n);
  if (hashInts([q, a, aCap, big(opts.credentialRequestMetadata.nonce)]) !==
      c) {
    log.debug("Leaving processCredential(). SCP.");
    throw new Error("the issuer's signature correctness proof does not " +
                    "verify.");
  }
  var out = JSON.parse(JSON.stringify(credential));
  out.signature.p_credential.v = dec(v);
  // A revocable credential: vr = vr' + vr'', after the three checks.
  if (credential.signature.r_credential) {
    out.signature.r_credential = rev.processRevocation(credential,
      opts.credentialRequestMetadata.link_secret_blinding_data.vr_prime,
      opts.credentialDefinition, opts.revocationRegistryDefinition);
  }
  log.debug("Leaving processCredential().");
  return out;
}

// A held (processed) credential's CL signature, re-checked with the link
// secret: A^e = Q. Returns null, or why not.
function verifyCredentialSignature(credential, credentialDefinition,
                                   linkSecret) {
  log.debug("Entering verifyCredentialSignature().");
  try {
    var pk = primaryKey(credentialDefinition);
    var sig = credential.signature.p_credential;
    var values = credentialValues(credential, linkSecret);
    var rx = (modPow(pk.s, big(sig.v), pk.n) *
              modPow(pk.rctxt, big(sig.m_2), pk.n)) % pk.n;
    Object.keys(pk.r).forEach(function (k) {
      if (values[k] === undefined) throw new Error("no value for " + k);
      rx = (rx * modPow(pk.r[k], values[k], pk.n)) % pk.n;
    });
    var q = (pk.z * inverse(rx, pk.n)) % pk.n;
    var ok = modPow(big(sig.a), big(sig.e), pk.n) === q;
    log.debug("Leaving verifyCredentialSignature(). " + ok);
    return ok ? null : "the CL signature does not verify under this link " +
      "secret (A^e is not Q).";
  } catch (e) {
    log.debug("Leaving verifyCredentialSignature(). " + e.message);
    return e.message;
  }
}

// --- presentation (spec 6) ---------------------------------------------------
function schemaAttrs(schema) {
  log.debug("Entering schemaAttrs().");
  log.debug("Leaving schemaAttrs().");
  return (schema.attrNames || schema.attr_names || []).map(attrCommonView);
}

function deltaOf(m, p) {
  log.debug("Entering deltaOf(). " + p.p_type);
  log.debug("Leaving deltaOf().");
  return p.p_type === "GE" ? m - p.value : p.p_type === "GT" ?
    m - p.value - 1 : p.p_type === "LE" ? p.value - m : p.value - m - 1;
}

function deltaPrime(p) {
  log.debug("Entering deltaPrime().");
  log.debug("Leaving deltaPrime().");
  return p.p_type === "GT" ? p.value + 1 : p.p_type === "LT" ? p.value - 1 :
    p.value;
}

// Lagrange: any four squares summing to delta (the verifier never sees them).
function fourSquares(delta) {
  log.debug("Entering fourSquares(). " + delta);
  var isq = function (x) {
    return Math.floor(Math.sqrt(x));
  };
  for (var a = isq(delta); a >= 0; a--) {
    var r1 = delta - a * a;
    for (var b = Math.min(a, isq(r1)); b >= 0; b--) {
      var r2 = r1 - b * b;
      for (var c = Math.min(b, isq(r2)); c >= 0; c--) {
        var r3 = r2 - c * c;
        var d = isq(r3);
        if (d * d === r3 && d <= c) {
          log.debug("Leaving fourSquares().");
          return [a, b, c, d].map(BigInt);
        }
      }
    }
  }
  log.debug("Leaving fourSquares(). None found.");
  throw new Error("no four-square decomposition of " + delta);
}

function predicateCompare(a, b) {
  log.debug("Entering predicateCompare().");
  var x = a.attr_name < b.attr_name ? -1 : a.attr_name > b.attr_name ? 1 :
    P_ORDER[a.p_type] - P_ORDER[b.p_type] || a.value - b.value;
  log.debug("Leaving predicateCompare().");
  return x;
}

// T for the equality proof (calc_teq).
function calcTeq(pk, aPrime, eExp, vExp, m2Exp, mExps) {
  log.debug("Entering calcTeq().");
  var t = modPow(aPrime, eExp, pk.n);
  Object.keys(mExps).forEach(function (k) {
    t = (t * modPow(pk.r[k], mExps[k], pk.n)) % pk.n;
  });
  t = (t * modPow(pk.s, vExp, pk.n)) % pk.n;
  t = (t * modPow(pk.rctxt, m2Exp, pk.n)) % pk.n;
  log.debug("Leaving calcTeq().");
  return t;
}

// The predicate tau items (calc_tne): [T0..T3, TDelta, Q].
function calcTne(pk, u, r, mj, alpha, t, isLess) {
  log.debug("Entering calcTne().");
  var out = [];
  for (var i = 0; i < 4; i++) {
    out.push((modPow(pk.z, u[i], pk.n) * modPow(pk.s, r[i], pk.n)) % pk.n);
  }
  out.push((modPow(pk.z, mj, pk.n) *
            modPow(pk.s, isLess ? -r.DELTA : r.DELTA, pk.n)) % pk.n);
  var q = modPow(pk.s, alpha, pk.n);
  for (var j = 0; j < 4; j++) {
    q = (q * modPow(t[j], u[j], pk.n)) % pk.n;
  }
  out.push(q);
  log.debug("Leaving calcTne().");
  return out;
}

// opts as anoncreds-rs's Presentation.create: presentationRequest,
// credentials [{credential}], credentialsProve [{entryIndex, referent,
// isPredicate, reveal}], selfAttest {referent: value}, linkSecret,
// schemas {id: schema}, credentialDefinitions {id: creddef}.
function createPresentation(opts) {
  log.debug("Entering createPresentation().");
  var req = opts.presentationRequest;
  var ms = big(opts.linkSecret);
  var mTildeMs = rand(C.MVECT);
  var used = [];
  var byEntry = {};
  (opts.credentialsProve || []).forEach(function (p) {
    if (!byEntry[p.entryIndex]) {
      byEntry[p.entryIndex] = [];
      used.push(p.entryIndex);
    }
    byEntry[p.entryIndex].push(p);
  });
  used.sort(function (a, b) {
    return a - b;
  });
  var requested = { revealed_attrs: {}, self_attested_attrs:
    Object.assign({}, opts.selfAttest || {}), unrevealed_attrs: {},
    predicates: {} };
  var groups = {};
  var tauList = [];
  var cList = [];
  var states = [];
  var identifiers = [];
  used.forEach(function (entry, subIndex) {
    var cred = opts.credentials[entry].credential;
    var schema = opts.schemas[cred.schema_id];
    var cd = opts.credentialDefinitions[cred.cred_def_id];
    if (!schema || !cd) {
      throw new Error("the schema or credential definition of credential " +
                      entry + " was not supplied.");
    }
    var pk = primaryKey(cd);
    var values = credentialValues(cred, ms);
    var revealed = {};
    var predicates = [];
    var revealedRefs = [];
    var predicateRefs = [];
    byEntry[entry].forEach(function (p) {
      if (p.isPredicate) {
        predicateRefs.push(p.referent);
        var pi = (req.requested_predicates || {})[p.referent];
        if (!pi) throw new Error("no requested predicate " + p.referent);
        predicates.push({ attr_name: attrCommonView(pi.name),
                          p_type: P_TYPES[pi.p_type] || pi.p_type,
                          value: pi.p_value });
        requested.predicates[p.referent] = { sub_proof_index: subIndex };
        return;
      }
      var ai = (req.requested_attributes || {})[p.referent];
      if (!ai) throw new Error("no requested attribute " + p.referent);
      if (!p.reveal) {
        requested.unrevealed_attrs[p.referent] = { sub_proof_index: subIndex };
        return;
      }
      revealedRefs.push(p.referent);
      var names = ai.names || [ai.name];
      var found = {};
      names.forEach(function (nm) {
        revealed[attrCommonView(nm)] = true;
        var key = Object.keys(cred.values).filter(function (k) {
          return attrCommonView(k) === attrCommonView(nm);
        })[0];
        if (key === undefined) {
          throw new Error("credential " + entry + " has no attribute " + nm);
        }
        found[nm] = { raw: cred.values[key].raw,
                      encoded: cred.values[key].encoded };
      });
      if (ai.names) {
        groups[p.referent] = { sub_proof_index: subIndex, values: found };
      } else {
        requested.revealed_attrs[p.referent] = { sub_proof_index: subIndex,
          raw: found[ai.name].raw, encoded: found[ai.name].encoded };
      }
    });
    predicates.sort(predicateCompare);
    // CL refuses an attribute both revealed and predicated
    // (anoncreds-clsignatures prover.rs, _check_add_sub_proof_request_params).
    predicates.forEach(function (p) {
      if (revealed[p.attr_name]) {
        throw new Error("attribute " + p.attr_name + " is both revealed and " +
                        "the subject of a predicate in credential " + entry +
                        "; a CL proof cannot do both.");
      }
    });
    var attrs = schemaAttrs(schema).concat([LINK_SECRET_ATTR]);
    var sig = cred.signature.p_credential;
    var m2 = big(sig.m_2);
    var m2Tilde = rand(C.M2TILDE);
    var r = rand(C.VPRIME);
    var eTilde = rand(C.ETILDE);
    var vTilde = rand(C.VTILDE);
    var unrevealed = attrs.filter(function (a) {
      return !revealed[a];
    });
    var mTilde = {};
    unrevealed.forEach(function (a) {
      mTilde[a] = a === LINK_SECRET_ATTR ? mTildeMs : rand(C.MVECT);
    });
    var aPrime = (modPow(pk.s, r, pk.n) * big(sig.a)) % pk.n;
    var e = big(sig.e);
    var vPrime = big(sig.v) - e * r;
    var tEq = calcTeq(pk, aPrime, eTilde, vTilde, m2Tilde, mTilde);
    var subC = [toBytes(aPrime)];
    var subTau = [toBytes(tEq)];
    var preds = predicates.map(function (p) {
      var mj = parseI32(dec(values[p.attr_name]));
      if (mj === null) {
        throw new Error("predicate attribute " + p.attr_name + " is not an " +
                        "integer credential value.");
      }
      var delta = deltaOf(mj, p);
      if (delta < 0) {
        throw new Error("the credential does not satisfy " + p.attr_name +
                        " " + p.p_type + " " + p.value + ".");
      }
      var u = fourSquares(delta);
      var ri = [rand(C.VPRIME), rand(C.VPRIME), rand(C.VPRIME),
                rand(C.VPRIME)];
      var rDelta = rand(C.VPRIME);
      var t = u.map(function (ui, i) {
        return (modPow(pk.z, ui, pk.n) * modPow(pk.s, ri[i], pk.n)) % pk.n;
      });
      t.push((modPow(pk.z, BigInt(delta), pk.n) *
              modPow(pk.s, rDelta, pk.n)) % pk.n);
      var uTilde = [rand(C.UTILDE), rand(C.UTILDE), rand(C.UTILDE),
                    rand(C.UTILDE)];
      var rTilde = [rand(C.RTILDE), rand(C.RTILDE), rand(C.RTILDE),
                    rand(C.RTILDE)];
      rTilde.DELTA = rand(C.RTILDE);
      var alphaTilde = rand(C.ALPHATILDE);
      var tau = calcTne(pk, uTilde, rTilde, mTilde[p.attr_name], alphaTilde,
                        t, p.p_type === "LE" || p.p_type === "LT");
      t.forEach(function (x) {
        subC.push(toBytes(x));
      });
      tau.forEach(function (x) {
        subTau.push(toBytes(x));
      });
      return { p: p, u: u, ri: ri, rDelta: rDelta, t: t, uTilde: uTilde,
               rTilde: rTilde, alphaTilde: alphaTilde };
    });
    // Revocation: a non-revocation proof when the request asks for an
    // interval and a revocation state was given; its items go AHEAD of the
    // primary ones, and it shares the primary m~2.
    var entryOpts = opts.credentials[entry];
    var interval = cred.rev_reg_id ? rev.intervalFor(req, revealedRefs,
                                                     predicateRefs) : null;
    var nrp = null;
    if (interval && entryOpts.revocationState) {
      nrp = rev.proverInit(cred, entryOpts.revocationState, cd, m2Tilde);
      subC = nrp.cBytes.concat(subC);
      subTau = nrp.tauBytes.concat(subTau);
    }
    tauList = tauList.concat(subTau);
    cList = cList.concat(subC);
    states.push({ pk: pk, values: values, revealed: revealed,
                  unrevealed: unrevealed, mTilde: mTilde, m2: m2,
                  m2Tilde: m2Tilde, e: e, eTilde: eTilde, vPrime: vPrime,
                  vTilde: vTilde, aPrime: aPrime, preds: preds, nrp: nrp });
    identifiers.push({ schema_id: cred.schema_id, cred_def_id:
                       cred.cred_def_id, rev_reg_id: cred.rev_reg_id || null,
                       timestamp: entryOpts.timestamp !== undefined ?
                         entryOpts.timestamp : null });
  });
  var c = hashInts(tauList.concat(cList, [toBytes(big(req.nonce))]));
  var proofs = states.map(function (st) {
    var revealedAttrs = {};
    Object.keys(st.revealed).sort().forEach(function (a) {
      revealedAttrs[a] = dec(st.values[a]);
    });
    var m = {};
    st.unrevealed.forEach(function (a) {
      m[a] = dec(st.mTilde[a] + c * st.values[a]);
    });
    return {
      primary_proof: {
        eq_proof: { revealed_attrs: revealedAttrs, a_prime: dec(st.aPrime),
          e: dec(c * (st.e - E_START_VALUE) + st.eTilde),
          v: dec(c * st.vPrime + st.vTilde), m: m,
          m2: dec(st.m2Tilde + c * st.m2) },
        ge_proofs: st.preds.map(function (pp) {
          var u = {};
          var rr = {};
          var tt = {};
          var sumUr = ZERO;
          for (var i = 0; i < 4; i++) {
            u[String(i)] = dec(c * pp.u[i] + pp.uTilde[i]);
            rr[String(i)] = dec(c * pp.ri[i] + pp.rTilde[i]);
            tt[String(i)] = dec(pp.t[i]);
            sumUr += pp.u[i] * pp.ri[i];
          }
          rr.DELTA = dec(c * pp.rDelta + pp.rTilde.DELTA);
          tt.DELTA = dec(pp.t[4]);
          return { u: u, r: rr, mj: m[pp.p.attr_name],
                   alpha: dec(c * (pp.rDelta - sumUr) + pp.alphaTilde),
                   t: tt, predicate: pp.p };
        })
      },
      non_revoc_proof: st.nrp ? st.nrp.finalize(c) : null
    };
  });
  if (Object.keys(groups).length) requested.revealed_attr_groups = groups;
  log.debug("Leaving createPresentation(). " + proofs.length +
            " sub-proof(s).");
  return { proof: { proofs: proofs, aggregated_proof: {
             c_hash: dec(c), c_list: cList.map(function (b) {
               return Array.prototype.slice.call(b);
             }) } },
           requested_proof: requested, identifiers: identifiers };
}

// --- verification (spec 7) ---------------------------------------------------
function restrictionTags(presentation, idx, schemas, cds, subProofRaw) {
  log.debug("Entering restrictionTags().");
  var id = presentation.identifiers[idx] || {};
  var schema = schemas[id.schema_id] || {};
  var cd = cds[id.cred_def_id] || {};
  log.debug("Leaving restrictionTags().");
  return { schema_id: id.schema_id, cred_def_id: id.cred_def_id,
           schema_issuer_id: schema.issuerId, schema_issuer_did:
           schema.issuerId, schema_name: schema.name,
           schema_version: schema.version, issuer_id: cd.issuerId,
           issuer_did: cd.issuerId, raw: subProofRaw || {} };
}

// WQL: $eq (a plain value), $neq, $in, $and, $or, $not, implicit $and;
// an array of objects is their $or.
function matchQuery(q, tags) {
  log.debug("Entering matchQuery().");
  if (q === null || q === undefined) {
    log.debug("Leaving matchQuery(). None.");
    return true;
  }
  if (Array.isArray(q)) {
    var list = q.filter(function (x) {
      return x !== null;
    });
    log.debug("Leaving matchQuery(). Legacy $or.");
    return !list.length || list.some(function (x) {
      return matchQuery(x, tags);
    });
  }
  var ok = Object.keys(q).every(function (k) {
    var v = q[k];
    if (k === "$and") {
      return v.every(function (x) {
        return matchQuery(x, tags);
      });
    }
    if (k === "$or") {
      return !v.length || v.some(function (x) {
        return matchQuery(x, tags);
      });
    }
    if (k === "$not") return !matchQuery(v, tags);
    var m = /^attr::(.+)::(value|marker)$/.exec(k);
    var actual = m ? tags.raw[attrCommonView(m[1])] : tags[k];
    if (!m && !(k in tags)) {
      throw new Error("unsupported restriction tag " + k + ".");
    }
    if (m && actual === undefined) return true;
    if (v !== null && typeof v === "object") {
      if (v.$neq !== undefined) return actual !== v.$neq;
      if (v.$in !== undefined) return v.$in.indexOf(actual) !== -1;
      if (v.$eq !== undefined) return actual === v.$eq;
      throw new Error("unsupported restriction operator in " + k + ".");
    }
    return actual === v;
  });
  log.debug("Leaving matchQuery(). " + ok);
  return ok;
}

// opts as anoncreds-rs's Presentation.verify: presentationRequest, schemas,
// credentialDefinitions. Returns { valid, errors, warnings, revealed }.
function verifyPresentation(presentation, opts) {
  log.debug("Entering verifyPresentation().");
  var errors = [];
  var warnings = [];
  var req = opts.presentationRequest;
  try {
    var rp = presentation.requested_proof || {};
    var proofs = presentation.proof.proofs;
    var ids = presentation.identifiers || [];
    if (proofs.length !== ids.length) {
      errors.push("there are " + proofs.length + " sub-proofs and " +
                  ids.length + " identifiers.");
    }
    // Referent coverage.
    var answered = Object.keys(rp.revealed_attrs || {}).concat(
      Object.keys(rp.revealed_attr_groups || {}),
      Object.keys(rp.unrevealed_attrs || {}),
      Object.keys(rp.self_attested_attrs || {})).sort();
    var asked = Object.keys(req.requested_attributes || {}).sort();
    if (JSON.stringify(answered) !== JSON.stringify(asked)) {
      errors.push("the attribute referents answered (" + answered.join(", ") +
                  ") are not those requested (" + asked.join(", ") + ").");
    }
    var askedP = Object.keys(req.requested_predicates || {}).sort();
    if (JSON.stringify(Object.keys(rp.predicates || {}).sort()) !==
        JSON.stringify(askedP)) {
      errors.push("the predicate referents answered are not those " +
                  "requested.");
    }
    var raws = proofs.map(function () {
      return {};
    });
    var revealed = {};
    // Revealed values: request name(s), encoded == the proof's, raw.
    var checkRevealed = function (ref, idx, name, val) {
      var eq = (proofs[idx] || {}).primary_proof.eq_proof;
      var inProof = eq.revealed_attrs[attrCommonView(name)];
      var norm = parseI32(val.encoded);
      if (inProof === undefined) {
        errors.push(ref + ": " + name + " is not revealed in sub-proof " +
                    idx + ".");
      } else if ((norm !== null ? String(norm) : val.encoded) !==
                 dec(big(inProof))) {
        errors.push(ref + ": the encoded value of " + name + " is not the " +
                    "one the proof reveals.");
      }
      if (encodeAttribute(val.raw) !== (norm !== null ? String(norm) :
                                        val.encoded)) {
        warnings.push(ref + ": raw " + JSON.stringify(val.raw) + " does " +
                      "not encode to its encoded value, so the raw value " +
                      "is the issuer's word alone.");
      }
      raws[idx][attrCommonView(name)] = val.raw;
      revealed[ref + (name !== undefined ? "/" + name : "")] = val.raw;
    };
    Object.keys(rp.revealed_attrs || {}).forEach(function (ref) {
      var ai = (req.requested_attributes || {})[ref] || {};
      var v = rp.revealed_attrs[ref];
      if (!ai.name) {
        errors.push(ref + " is answered as one attribute but was asked " +
                    "as a group.");
        return;
      }
      checkRevealed(ref, v.sub_proof_index, ai.name, v);
    });
    Object.keys(rp.revealed_attr_groups || {}).forEach(function (ref) {
      var ai = (req.requested_attributes || {})[ref] || {};
      var g = rp.revealed_attr_groups[ref];
      if (!ai.names || JSON.stringify(Object.keys(g.values).sort()) !==
          JSON.stringify(ai.names.slice().sort())) {
        errors.push(ref + ": the group's names are not those requested.");
        return;
      }
      ai.names.forEach(function (nm) {
        checkRevealed(ref, g.sub_proof_index, nm, g.values[nm]);
      });
    });
    // Restrictions.
    var restricted = function (ref, info, idx) {
      if (!info.restrictions) return;
      if (!matchQuery(info.restrictions, restrictionTags(presentation, idx,
          opts.schemas, opts.credentialDefinitions, raws[idx]))) {
        errors.push(ref + ": the credential does not meet the request's " +
                    "restrictions.");
      }
    };
    Object.keys(req.requested_attributes || {}).forEach(function (ref) {
      var info = req.requested_attributes[ref];
      var at = (rp.revealed_attrs || {})[ref] ||
        (rp.revealed_attr_groups || {})[ref] ||
        (rp.unrevealed_attrs || {})[ref];
      if (at) {
        restricted(ref, info, at.sub_proof_index);
      } else if (info.restrictions && (Array.isArray(info.restrictions) ?
                 info.restrictions.length : Object.keys(info.restrictions)
                   .length)) {
        errors.push(ref + " is restricted, so it cannot be self-attested.");
      }
    });
    // Predicates: the proof's must be the request's (anoncreds-rs 0.2.3 does
    // not compare them).
    Object.keys(rp.predicates || {}).forEach(function (ref) {
      var pi = req.requested_predicates[ref] || {};
      var idx = rp.predicates[ref].sub_proof_index;
      var want = { attr_name: attrCommonView(pi.name), p_type:
                   P_TYPES[pi.p_type] || pi.p_type, value: pi.p_value };
      var ge = ((proofs[idx] || {}).primary_proof || {}).ge_proofs || [];
      if (!ge.some(function (g) {
        return predicateCompare(g.predicate, want) === 0;
      })) {
        errors.push(ref + ": no sub-proof proves " + pi.name + " " +
                    pi.p_type + " " + pi.p_value + ".");
      }
      restricted(ref, pi, idx);
    });
    // The CL proof.
    var tau = [];
    var cExpected = [];
    var msResponse = null;
    proofs.forEach(function (sp, idx) {
      var id = ids[idx] || {};
      var schema = opts.schemas[id.schema_id];
      var cd = opts.credentialDefinitions[id.cred_def_id];
      if (!schema || !cd) {
        throw new Error("the schema or credential definition of sub-proof " +
                        idx + " was not supplied.");
      }
      var pk = primaryKey(cd);
      var eq = sp.primary_proof.eq_proof;
      var c = big(presentation.proof.aggregated_proof.c_hash);
      // Revocation (anoncreds-rs verifier.rs check_non_revoked_interval and
      // get_revocation_registry): the interval this sub-proof is asked
      // for, its timestamp inside it, the status list for exactly that
      // (rev_reg_id, timestamp), and the non-revocation proof's taus AHEAD
      // of the primary ones. Stricter than anoncreds-rs 0.2.3, which
      // verifies a sub-proof with no non-revocation proof as if none had
      // been asked for: one is REQUIRED when an interval applies.
      if (pk.revocable) {
        var refsOf = function (map) {
          return Object.keys(map || {}).filter(function (ref) {
            return map[ref].sub_proof_index === idx;
          });
        };
        var interval = rev.intervalFor(req, refsOf(rp.revealed_attrs).concat(
          refsOf(rp.revealed_attr_groups)), refsOf(rp.predicates));
        if (interval && !id.rev_reg_id) interval = null;
        if (interval) {
          if (id.timestamp === null || id.timestamp === undefined) {
            throw new Error("sub-proof " + idx + " is asked for a " +
              "non-revocation interval and names no timestamp.");
          }
          if ((interval.from !== undefined && id.timestamp < interval.from) ||
              (interval.to !== undefined && id.timestamp > interval.to)) {
            throw new Error("sub-proof " + idx + "'s timestamp " +
              id.timestamp + " is outside the interval asked for.");
          }
          if (!sp.non_revoc_proof) {
            errors.push("sub-proof " + idx + " is asked to prove it is not " +
              "revoked and carries no non-revocation proof.");
          }
        }
        if (sp.non_revoc_proof) {
          var rrd = (opts.revocationRegistryDefinitions || {})[id.rev_reg_id];
          var list = (opts.revocationStatusLists || []).filter(function (l) {
            return l.revRegDefId === id.rev_reg_id &&
              l.timestamp === id.timestamp;
          })[0];
          if (!rrd || !list) {
            throw new Error("sub-proof " + idx + "'s non-revocation proof " +
              "needs the revocation registry definition " + id.rev_reg_id +
              " and its status list at timestamp " + id.timestamp + ".");
          }
          var nr = rev.verifierTau(sp.non_revoc_proof, cd, rrd,
                                   list.currentAccumulator, c, big(eq.m2));
          tau = tau.concat(nr.tauBytes);
          cExpected = cExpected.concat(nr.cBytes);
        }
      }
      var attrs = schemaAttrs(schema).concat([LINK_SECRET_ATTR]);
      var unrevealed = attrs.filter(function (a) {
        return eq.revealed_attrs[a] === undefined;
      });
      Object.keys(eq.revealed_attrs).forEach(function (a) {
        if (attrs.indexOf(a) === -1) {
          throw new Error("sub-proof " + idx + " reveals " + a + ", which " +
                          "the schema does not have.");
        }
      });
      if (eq.m[LINK_SECRET_ATTR] === undefined) {
        throw new Error("sub-proof " + idx + " proves no link secret.");
      }
      if (msResponse === null) msResponse = eq.m[LINK_SECRET_ATTR];
      if (eq.m[LINK_SECRET_ATTR] !== msResponse) {
        errors.push("sub-proof " + idx + " is under a different link " +
                    "secret from sub-proof 0.");
      }
      var mHat = {};
      unrevealed.forEach(function (a) {
        if (eq.m[a] === undefined) {
          throw new Error("sub-proof " + idx + " has no response for " + a +
                          ".");
        }
        mHat[a] = big(eq.m[a]);
      });
      var aPrime = big(eq.a_prime);
      var t1 = calcTeq(pk, aPrime, big(eq.e), big(eq.v), big(eq.m2), mHat);
      var rar = modPow(aPrime, E_START_VALUE, pk.n);
      Object.keys(eq.revealed_attrs).forEach(function (a) {
        rar = (rar * modPow(pk.r[a], big(eq.revealed_attrs[a]), pk.n)) % pk.n;
      });
      var t2 = modPow((pk.z * inverse(rar, pk.n)) % pk.n, -c, pk.n);
      tau.push(toBytes((t1 * t2) % pk.n));
      cExpected.push(toBytes(aPrime));
      sp.primary_proof.ge_proofs.forEach(function (g) {
        var p = g.predicate;
        var isLess = p.p_type === "LE" || p.p_type === "LT";
        var u = [0, 1, 2, 3].map(function (i) {
          return big(g.u[String(i)]);
        });
        var r = [0, 1, 2, 3].map(function (i) {
          return big(g.r[String(i)]);
        });
        r.DELTA = big(g.r.DELTA);
        var t = [0, 1, 2, 3].map(function (i) {
          return big(g.t[String(i)]);
        });
        var tDelta = big(g.t.DELTA);
        if (g.mj !== eq.m[p.attr_name]) {
          errors.push("sub-proof " + idx + "'s predicate on " + p.attr_name +
                      " is not about the attribute its equality proof " +
                      "covers.");
        }
        var tn = calcTne(pk, u, r, big(g.mj), big(g.alpha), t, isLess);
        for (var i = 0; i < 4; i++) {
          tn[i] = (modPow(t[i], -c, pk.n) * tn[i]) % pk.n;
        }
        var d = isLess ? inverse(tDelta, pk.n) : tDelta;
        tn[4] = (modPow((modPow(pk.z, BigInt(deltaPrime(p)), pk.n) * d) %
                        pk.n, -c, pk.n) * tn[4]) % pk.n;
        tn[5] = (modPow(tDelta, -c, pk.n) * tn[5]) % pk.n;
        tn.forEach(function (x) {
          tau.push(toBytes(x));
        });
        t.concat([tDelta]).forEach(function (x) {
          cExpected.push(toBytes(x));
        });
      });
    });
    var given = presentation.proof.aggregated_proof.c_list.map(function (b) {
      return Uint8Array.from(b);
    });
    if (JSON.stringify(given.map(bytes.bytesToHex)) !==
        JSON.stringify(cExpected.map(bytes.bytesToHex))) {
      errors.push("the aggregated proof's c_list is not the A' and T " +
                  "values the sub-proofs carry.");
    }
    var cHash = hashInts(tau.concat(given, [toBytes(big(req.nonce))]));
    if (cHash !== big(presentation.proof.aggregated_proof.c_hash)) {
      errors.push("the CL proof does not verify: the recomputed challenge " +
                  "is not c_hash (a value, a response or the nonce " +
                  "differs).");
    }
    log.debug("Leaving verifyPresentation(). " + errors.length +
              " error(s).");
    return { valid: errors.length === 0, errors: errors, warnings: warnings,
             revealed: revealed };
  } catch (e) {
    errors.push(e.message);
    log.debug("Leaving verifyPresentation(). " + e.message);
    return { valid: false, errors: errors, warnings: warnings, revealed: {} };
  }
}

module.exports = {
  CONSTANTS: C,
  LINK_SECRET_ATTR: LINK_SECRET_ATTR,
  attrCommonView: attrCommonView,
  encodeAttribute: encodeAttribute,
  createLinkSecret: createLinkSecret,
  createNonce: createNonce,
  primaryKey: primaryKey,
  verifyKeyCorrectnessProof: verifyKeyCorrectnessProof,
  createCredentialRequest: createCredentialRequest,
  processCredential: processCredential,
  verifyCredentialSignature: verifyCredentialSignature,
  createPresentation: createPresentation,
  verifyPresentation: verifyPresentation,
  // the arithmetic, for the tests
  hashInts: hashInts,
  toBytes: toBytes,
  fourSquares: fourSquares,
  isProbablePrime: isProbablePrime
};
