'use strict';
//
// File: frodokem.js
//
// ===========================================================================
// FrodoKEM AND eFrodoKEM, WRITTEN FROM THE SPECIFICATION.
//
// This is the only key-encapsulation mechanism in this project with no library
// behind it. @noble has ML-KEM and no FrodoKEM; npm has no FrodoKEM at all;
// the one credible open implementation (microsoft/PQCrypto-LWEKE) is C and a
// Python reference. So it is written out here, and
// `tests/frodokem_vectors.js` holds it to the reference implementation's OWN
// Known Answer Test files — the `.rsp` vectors published with it — for every
// parameter set. That is not a nicety: a lattice KEM that is subtly wrong
// encapsulates and decapsulates against ITSELF perfectly and interoperates
// with nothing, which is exactly the failure mode this project keeps
// recording.
//
// draft-eastlake-rfc9231bis-xmlsec-uris section 3.6.10 gives it twelve XML
// identifiers: three security levels, two ways of generating the matrix A
// (AES-128 or SHAKE128), and the standard variant against the EPHEMERAL one.
// `common/xmldsig.js` holds those identifiers; this file is the mechanism.
//
// ---------------------------------------------------------------------------
// WHAT MAKES FrodoKEM DIFFERENT FROM ML-KEM, AND WHY IT IS SLOW.
//
// ML-KEM is structured: its lattice is a polynomial ring, so a key operation
// is a handful of NTTs. FrodoKEM is deliberately UNSTRUCTURED — plain
// Learning With Errors over generic lattices, which is the conservative
// choice and the reason [EUCC-ACM] names it beside ML-KEM. The price is
// arithmetic: the public matrix A is n x n with n up to 1344, so a single
// operation GENERATES 1.8 MILLION 16-bit entries and multiplies them.
// FrodoKEM-1344 is roughly two hundred times the work of ML-KEM-1024 and
// there is no clever way around it — that is the scheme, not this
// implementation.
//
// Two consequences are written into the callers rather than hidden here: the
// mock STS runs it in a worker process (common/worker.js), and the browser
// panes say what a parameter set costs before you press the button.
//
// A IS NEVER MATERIALISED IN FULL. The reference implementation builds the
// whole n x n matrix and then multiplies; at n=1344 that is 3.6 MB of
// Int32Array before anything else. Here each ROW of A is generated and
// consumed in turn, which is the same arithmetic in a 5 KB buffer, and it is
// the one place this file deliberately does not mirror the reference's shape.
//
// ---------------------------------------------------------------------------
// THE TWO BIT ORDERS, WHICH ARE NOT THE SAME AND ARE THE EASIEST THING HERE TO
// GET WRONG.
//
// `pack` / `unpack` (specification algorithms 3 and 4) write each D-bit
// element MOST SIGNIFICANT BIT FIRST into a big-endian bit stream — bit index
// 0 is the top bit of byte 0.
//
// `encode` / `decode` (algorithms 1 and 2) read the message's bits LEAST
// SIGNIFICANT FIRST WITHIN EACH BYTE — bit t of the message is bit (t & 7) of
// byte (t >> 3).
//
// Swapping them produces a KEM that is entirely self-consistent: it
// encapsulates, it decapsulates, the shared secrets match, and every byte on
// the wire differs from what the specification says. Only the KAT files catch
// it, which is why they are not optional here.
// ===========================================================================

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "frodokem",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var forge = require("node-forge");
var sha3 = require("@noble/hashes/sha3");

// ---------------------------------------------------------------------------
// The parameter sets, specification tables 3, 4 and 5. Every number is the
// table's; `tests/frodokem_vectors.js` checks the derived lengths against the
// KAT files' own, which is what catches a transposed digit here.
//
// `chi` is the error distribution as multiples of 2^16; `T_chi` is the
// zero-centred CDF built from it (section 2.2.4), which is what `sample()`
// compares against.
// ---------------------------------------------------------------------------
var SETS = {
  640: {
    chi: [9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1],
    D: 15, q: 32768, n: 640, nbar: 8, mbar: 8, B: 2,
    lenSeedA: 16, lenZ: 16, lenMu: 16, lenSeedSE: 32, lenSalt: 32,
    lenS: 16, lenK: 16, lenPkh: 16, lenSs: 16,
    shake: 'shake128',
    skBytes: 19888, pkBytes: 9616, ctBytes: 9752
  },
  976: {
    chi: [11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1],
    D: 16, q: 65536, n: 976, nbar: 8, mbar: 8, B: 3,
    lenSeedA: 16, lenZ: 16, lenMu: 24, lenSeedSE: 48, lenSalt: 48,
    lenS: 24, lenK: 24, lenPkh: 24, lenSs: 24,
    shake: 'shake256',
    skBytes: 31296, pkBytes: 15632, ctBytes: 15792
  },
  1344: {
    chi: [18286, 14320, 6876, 2023, 364, 40, 2],
    D: 16, q: 65536, n: 1344, nbar: 8, mbar: 8, B: 4,
    lenSeedA: 16, lenZ: 16, lenMu: 32, lenSeedSE: 64, lenSalt: 64,
    lenS: 32, lenK: 32, lenPkh: 32, lenSs: 32,
    shake: 'shake256',
    skBytes: 43088, pkBytes: 21520, ctBytes: 21696
  }
};

// Section 2.2.4: T_chi(0) = chi(0)/2 - 1, T_chi(z) = T_chi(0) + sum chi(1..z).
function cdfOf(chi) {
  log.debug("Entering cdfOf().");
  var t = [Math.floor(chi[0] / 2) - 1];
  var running = 0;
  for (var z = 1; z < chi.length; z++) {
    running += chi[z];
    t.push(t[0] + running);
  }
  log.debug("Leaving cdfOf(). " + t.length + " entries.");
  return t;
}

// "FrodoKEM-640-AES" and its eleven siblings, resolved to a parameter set plus
// the two switches: which generator makes A, and whether the ciphertext
// carries a salt. eFrodoKEM is the EPHEMERAL variant — the salt exists to give
// multi-ciphertext security when one key pair answers many encapsulations, and
// an ephemeral key pair answers one.
function resolve(variant) {
  log.debug("Entering resolve(). variant=" + variant);
  var m = /^(e?)FrodoKEM-(640|976|1344)-(AES|SHAKE)$/.exec(String(variant));
  if (!m) {
    log.debug("Leaving resolve(). Unknown variant.");
    throw new Error('frodokem: "' + variant + '" is not a FrodoKEM parameter ' +
        'set. They are {e,}FrodoKEM-{640,976,1344}-{AES,SHAKE}.');
  }
  var base = SETS[m[2]];
  var out = {};
  Object.keys(base).forEach(function (k) { out[k] = base[k]; });
  out.variant = variant;
  out.ephemeral = m[1] === 'e';
  out.genAes = m[3] === 'AES';
  out.T_chi = cdfOf(base.chi);
  // ---------------------------------------------------------------------
  // eFrodoKEM IS NOT "FrodoKEM WITHOUT THE SALT", AND ASSUMING IT WAS IS THE
  // MISTAKE THIS COMMENT EXISTS TO STOP.
  //
  // It is the ORIGINAL (pre-2023) scheme, and the salt was added to the
  // standard variant along with a widening of the seed: FrodoKEM-640 draws a
  // 32-byte seedSE and a 32-byte salt, while eFrodoKEM-640 draws a 16-byte
  // seedSE and no salt at all. Every length that the reference derives from
  // `CRYPTO_BYTES` — s, seedSE, k, pkh and the shared secret — is HALF what
  // the salted variant uses, and `mu` is B*nbar*nbar/8 rather than a table
  // entry.
  //
  // Stripping the salt and changing nothing else produces a KEM that
  // round-trips against itself and matches none of the published vectors,
  // which is precisely the failure this whole file is tested against. The
  // numbers below are eFrodoKEM/src/api_efrodo{640,976,1344}.h's own.
  //
  // The salt exists for multi-ciphertext security when one key pair answers
  // many encapsulations; an EPHEMERAL key pair answers one, which is what the
  // `e` means and why the variant is still offered.
  // ---------------------------------------------------------------------
  if (out.ephemeral) {
    var cryptoBytes = { 640: 16, 976: 24, 1344: 32 }[out.n];
    out.lenS = cryptoBytes;
    out.lenSeedSE = cryptoBytes;
    out.lenK = cryptoBytes;
    out.lenPkh = cryptoBytes;
    out.lenSs = cryptoBytes;
    out.lenZ = out.lenSeedA;
    out.lenMu = (out.B * out.nbar * out.nbar) / 8;
    out.lenSalt = 0;
    out.ctBytes = ((out.D * out.n * out.nbar) / 8) +
                  ((out.D * out.nbar * out.nbar) / 8);
  }
  log.debug("Leaving resolve(). n=" + out.n + ", ephemeral=" + out.ephemeral);
  return out;
}

function shakeOf(p, message, outBytes) {
  log.debug("Entering shakeOf(). " + outBytes + " bytes.");
  var fn = p.shake === 'shake128' ? sha3.shake128 : sha3.shake256;
  log.debug("Leaving shakeOf().");
  return fn(message, { dkLen: outBytes });
}

function concatBytes() {
  var total = 0;
  var i;
  for (i = 0; i < arguments.length; i++) {
    total += arguments[i].length;
  }
  var out = new Uint8Array(total);
  var at = 0;
  for (i = 0; i < arguments.length; i++) {
    out.set(arguments[i], at);
    at += arguments[i].length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Algorithm 5. `r` is a 16-bit integer; the low bit is the sign and the rest
// indexes the CDF. The loop runs to len(T_chi) - 1, not len(T_chi), which is
// the specification's `s` and is off by one from what a reader expects.
// ---------------------------------------------------------------------------
function sample(p, r) {
  var t = r >>> 1;
  var e = 0;
  for (var z = 0; z < p.T_chi.length - 1; z++) {
    if (t > p.T_chi[z]) {
      e++;
    }
  }
  return (r & 1) ? -e : e;
}

// Algorithm 6, into a flat Int32Array of n1 * n2.
function sampleMatrix(p, r, offset, n1, n2) {
  log.debug("Entering sampleMatrix(). " + n1 + "x" + n2);
  var out = new Int32Array(n1 * n2);
  for (var i = 0; i < n1 * n2; i++) {
    out[i] = sample(p, r[offset + i]);
  }
  log.debug("Leaving sampleMatrix().");
  return out;
}

// The 2*k 16-bit little-endian integers SHAKE produces for the noise.
function noiseWords(p, prefix, seedSE, count) {
  log.debug("Entering noiseWords(). " + count + " words.");
  var bytes = shakeOf(p, concatBytes(new Uint8Array([prefix]), seedSE),
                      count * 2);
  var out = new Uint16Array(count);
  for (var i = 0; i < count; i++) {
    out[i] = bytes[2 * i] | (bytes[2 * i + 1] << 8);
  }
  log.debug("Leaving noiseWords().");
  return out;
}

// ---------------------------------------------------------------------------
// A, ONE ROW AT A TIME. Algorithms 7 and 8.
//
// The reference builds the whole n x n matrix; this yields row i into a
// reusable buffer, because at n=1344 the full matrix is 1.8 million entries
// and every caller consumes it row by row anyway. The arithmetic is identical.
//
// The AES generator encrypts one block per EIGHT columns, with the row and
// column indices as two 16-bit little-endian integers in an otherwise zero
// block; a whole row is therefore n/8 blocks, encrypted in one call because a
// cipher object per block is most of the cost.
// ---------------------------------------------------------------------------
function rowGenerator(p, seedA) {
  log.debug("Entering rowGenerator(). aes=" + p.genAes);
  var n = p.n;
  var row = new Int32Array(n);
  if (!p.genAes) {
    var prefix = new Uint8Array(2 + seedA.length);
    prefix.set(seedA, 2);
    log.debug("Leaving rowGenerator(). SHAKE.");
    return function (i) {
      prefix[0] = i & 0xff;
      prefix[1] = (i >>> 8) & 0xff;
      // **ALWAYS SHAKE128, WHATEVER THE PARAMETER SET HASHES WITH ELSEWHERE.**
      // Specification algorithm 8 is named "Frodo.Gen using SHAKE128" and
      // means it: FrodoKEM-976 and -1344 use SHAKE256 for every other hash in
      // the scheme and SHAKE128 for this one. Using the set's own function
      // here produces a KEM that round-trips against itself perfectly and
      // matches none of the published vectors — which is exactly what it did,
      // on four of the twelve, until the KAT files said so.
      var c = sha3.shake128(prefix, { dkLen: 2 * n });
      for (var j = 0; j < n; j++) {
        row[j] = (c[2 * j] | (c[2 * j + 1] << 8)) % p.q;
      }
      return row;
    };
  }
  // AES-128-ECB, through forge because Web Crypto has no ECB mode at all and
  // this file has to run in a browser as well as in node.
  var key = forge.util.createBuffer(
      forge.util.binary.raw.encode(seedA)).getBytes();
  var blocks = new Uint8Array(2 * n);
  log.debug("Leaving rowGenerator(). AES-128.");
  return function (i) {
    var j;
    for (j = 0; j < n; j += 8) {
      var at = 2 * j;
      blocks[at] = i & 0xff;
      blocks[at + 1] = (i >>> 8) & 0xff;
      blocks[at + 2] = j & 0xff;
      blocks[at + 3] = (j >>> 8) & 0xff;
      for (var z = 4; z < 16; z++) {
        blocks[at + z] = 0;
      }
    }
    var cipher = forge.cipher.createCipher('AES-ECB', key);
    cipher.start();
    cipher.update(forge.util.createBuffer(
        forge.util.binary.raw.encode(blocks)));
    cipher.finish(function () { return true; });
    var out = cipher.output.getBytes();
    for (j = 0; j < n; j++) {
      row[j] = ((out.charCodeAt(2 * j) & 0xff) |
                ((out.charCodeAt(2 * j + 1) & 0xff) << 8)) % p.q;
    }
    return row;
  };
}

// ---------------------------------------------------------------------------
// The three products this scheme needs, each written against A's ROWS so the
// matrix is never held whole.
//
// Every accumulation stays exact in a double: the largest is n * (q-1) * 12,
// which at n=1344 is about 1.06e9 — far inside 2^53 — so the modulus is taken
// once per output element exactly as the reference does. A `% q` per term
// would be slower and no more correct.
// ---------------------------------------------------------------------------
function mod(x, q) {
  var r = x % q;
  return r < 0 ? r + q : r;
}

// B = A S + E, with A generated row by row. S is n x nbar.
function aTimesSPlusE(p, nextRow, S, E) {
  log.debug("Entering aTimesSPlusE().");
  var n = p.n;
  var nbar = p.nbar;
  var out = new Int32Array(n * nbar);
  for (var i = 0; i < n; i++) {
    var row = nextRow(i);
    for (var k = 0; k < nbar; k++) {
      var sum = 0;
      for (var j = 0; j < n; j++) {
        sum += row[j] * S[j * nbar + k];
      }
      out[i * nbar + k] = mod(sum + E[i * nbar + k], p.q);
    }
  }
  log.debug("Leaving aTimesSPlusE().");
  return out;
}

// B' = S' A + E', with A generated row by row. S' is mbar x n, so A's row i
// contributes to every output column: this accumulates rather than finishing
// an element at a time, which is why the modulus is taken at the end.
function sTimesAPlusE(p, nextRow, Sprime, Eprime) {
  log.debug("Entering sTimesAPlusE().");
  var n = p.n;
  var mbar = p.mbar;
  var acc = new Float64Array(mbar * n);
  for (var i = 0; i < n; i++) {
    var row = nextRow(i);
    for (var r = 0; r < mbar; r++) {
      var s = Sprime[r * n + i];
      if (s === 0) {
        continue;
      }
      var base = r * n;
      for (var j = 0; j < n; j++) {
        acc[base + j] += s * row[j];
      }
    }
  }
  var out = new Int32Array(mbar * n);
  for (var t = 0; t < mbar * n; t++) {
    out[t] = mod(acc[t] + Eprime[t], p.q);
  }
  log.debug("Leaving sTimesAPlusE().");
  return out;
}

function addMatrices(p, X, Y) {
  var out = new Int32Array(X.length);
  for (var i = 0; i < X.length; i++) {
    out[i] = mod(X[i] + Y[i], p.q);
  }
  return out;
}

// A plain X (r1 x c) * Y (c x c2) + Z, for the small products.
function mulAdd(p, X, r1, c, Y, c2, Z, subtract) {
  log.debug("Entering mulAdd(). " + r1 + "x" + c + " * " + c + "x" + c2);
  var out = new Int32Array(r1 * c2);
  for (var i = 0; i < r1; i++) {
    for (var j = 0; j < c2; j++) {
      var sum = 0;
      for (var k = 0; k < c; k++) {
        sum += X[i * c + k] * Y[k * c2 + j];
      }
      var z = Z ? Z[i * c2 + j] : 0;
      out[i * c2 + j] = mod(subtract ? z - sum : sum + z, p.q);
    }
  }
  log.debug("Leaving mulAdd().");
  return out;
}

// ---------------------------------------------------------------------------
// Algorithms 3 and 4 — pack and unpack, MSB-FIRST per D-bit element into a
// big-endian bit stream. See the header on the other bit order.
// ---------------------------------------------------------------------------
function pack(p, C, n1, n2) {
  log.debug("Entering pack(). " + n1 + "x" + n2);
  var D = p.D;
  var out = new Uint8Array((D * n1 * n2) / 8);
  var bit = 0;
  for (var i = 0; i < n1 * n2; i++) {
    var v = C[i];
    for (var l = D - 1; l >= 0; l--) {
      if ((v >>> l) & 1) {
        out[bit >>> 3] |= 0x80 >>> (bit & 7);
      }
      bit++;
    }
  }
  log.debug("Leaving pack(). " + out.length + " bytes.");
  return out;
}

function unpack(p, b, n1, n2) {
  log.debug("Entering unpack(). " + n1 + "x" + n2);
  var D = p.D;
  var out = new Int32Array(n1 * n2);
  var bit = 0;
  for (var i = 0; i < n1 * n2; i++) {
    var v = 0;
    for (var l = 0; l < D; l++) {
      if (b[bit >>> 3] & (0x80 >>> (bit & 7))) {
        v |= 1 << (D - 1 - l);
      }
      bit++;
    }
    out[i] = v;
  }
  log.debug("Leaving unpack().");
  return out;
}

// ---------------------------------------------------------------------------
// Algorithms 1 and 2 — encode and decode, LSB-FIRST within each byte of the
// message. See the header.
// ---------------------------------------------------------------------------
function encode(p, mu) {
  log.debug("Entering encode().");
  var out = new Int32Array(p.mbar * p.nbar);
  var scale = p.q / Math.pow(2, p.B);
  for (var i = 0; i < p.mbar * p.nbar; i++) {
    var tmp = 0;
    for (var l = 0; l < p.B; l++) {
      var t = i * p.B + l;
      if (mu[t >>> 3] & (1 << (t & 7))) {
        tmp += Math.pow(2, l);
      }
    }
    out[i] = tmp * scale;
  }
  log.debug("Leaving encode().");
  return out;
}

function decode(p, K) {
  log.debug("Entering decode().");
  var out = new Uint8Array((p.B * p.mbar * p.nbar) / 8);
  var twoB = Math.pow(2, p.B);
  for (var i = 0; i < p.mbar * p.nbar; i++) {
    // round(K * 2^B / q) mod 2^B, as floor(x + 1/2) — NOT the language's
    // round(), which is banker's rounding on a tie and would decode a
    // half-integer to the wrong bit.
    var tmp = Math.floor(K[i] * twoB / p.q + 0.5) % twoB;
    for (var l = 0; l < p.B; l++) {
      if ((tmp >>> l) & 1) {
        var t = i * p.B + l;
        out[t >>> 3] |= 1 << (t & 7);
      }
    }
  }
  log.debug("Leaving decode().");
  return out;
}

// S^T in the secret key: nbar * n SIGNED 16-bit little-endian integers. Signed
// because the sampled values are, and reading them back unsigned produces a
// secret key that decapsulates to noise.
function packSigned(values) {
  log.debug("Entering packSigned().");
  var out = new Uint8Array(values.length * 2);
  for (var i = 0; i < values.length; i++) {
    var v = values[i] & 0xffff;
    out[2 * i] = v & 0xff;
    out[2 * i + 1] = (v >>> 8) & 0xff;
  }
  log.debug("Leaving packSigned().");
  return out;
}

function unpackSigned(bytes, count) {
  log.debug("Entering unpackSigned().");
  var out = new Int32Array(count);
  for (var i = 0; i < count; i++) {
    var v = bytes[2 * i] | (bytes[2 * i + 1] << 8);
    out[i] = v >= 0x8000 ? v - 0x10000 : v;
  }
  log.debug("Leaving unpackSigned().");
  return out;
}

function transpose(X, rows, cols) {
  var out = new Int32Array(rows * cols);
  for (var i = 0; i < rows; i++) {
    for (var j = 0; j < cols; j++) {
      out[j * rows + i] = X[i * cols + j];
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Algorithm 12 — key generation. `randomBytes(k)` is the caller's, so the KAT
// harness can supply NIST's DRBG and reproduce the published vectors byte for
// byte; everything else uses real randomness.
// ---------------------------------------------------------------------------
function keygen(variant, randomBytes) {
  log.debug("Entering keygen(). variant=" + variant);
  var p = resolve(variant);
  var seed = randomBytes(p.lenS + p.lenSeedSE + p.lenZ);
  var s = seed.subarray(0, p.lenS);
  var seedSE = seed.subarray(p.lenS, p.lenS + p.lenSeedSE);
  var z = seed.subarray(p.lenS + p.lenSeedSE);

  var seedA = shakeOf(p, z, p.lenSeedA);
  var r = noiseWords(p, 0x5f, seedSE, 2 * p.n * p.nbar);
  var Stransposed = sampleMatrix(p, r, 0, p.nbar, p.n);
  var S = transpose(Stransposed, p.nbar, p.n);
  var E = sampleMatrix(p, r, p.n * p.nbar, p.n, p.nbar);
  var B = aTimesSPlusE(p, rowGenerator(p, seedA), S, E);
  var b = pack(p, B, p.n, p.nbar);
  var pkh = shakeOf(p, concatBytes(seedA, b), p.lenPkh);

  var pk = concatBytes(seedA, b);
  var sk = concatBytes(s, seedA, b, packSigned(Stransposed), pkh);
  if (pk.length !== p.pkBytes || sk.length !== p.skBytes) {
    log.debug("Leaving keygen(). Length disagreement.");
    throw new Error('frodokem: ' + variant + ' produced a ' + pk.length +
        '-byte public key and a ' + sk.length + '-byte secret key; the ' +
        'specification says ' + p.pkBytes + ' and ' + p.skBytes +
        '. That is a defect in this file, not in the caller.');
  }
  log.debug("Leaving keygen().");
  return { publicKey: pk, secretKey: sk };
}

// Algorithm 13 — encapsulation.
function encapsulate(variant, pk, randomBytes) {
  log.debug("Entering encapsulate(). variant=" + variant);
  var p = resolve(variant);
  if (pk.length !== p.pkBytes) {
    log.debug("Leaving encapsulate(). Wrong public key length.");
    throw new Error('frodokem: a ' + variant + ' public key is ' + p.pkBytes +
        ' bytes; this one is ' + pk.length + '.');
  }
  var seedA = pk.subarray(0, p.lenSeedA);
  var b = pk.subarray(p.lenSeedA);

  var random = randomBytes(p.lenMu + p.lenSalt);
  var mu = random.subarray(0, p.lenMu);
  var salt = random.subarray(p.lenMu);
  var pkh = shakeOf(p, pk, p.lenPkh);
  var seedSEk = shakeOf(p, concatBytes(pkh, mu, salt),
                        p.lenSeedSE + p.lenK);
  var seedSE = seedSEk.subarray(0, p.lenSeedSE);
  var k = seedSEk.subarray(p.lenSeedSE);

  var r = noiseWords(p, 0x96, seedSE,
                     2 * p.mbar * p.n + p.mbar * p.nbar);
  var Sprime = sampleMatrix(p, r, 0, p.mbar, p.n);
  var Eprime = sampleMatrix(p, r, p.mbar * p.n, p.mbar, p.n);
  var Bprime = sTimesAPlusE(p, rowGenerator(p, seedA), Sprime, Eprime);
  var c1 = pack(p, Bprime, p.mbar, p.n);

  var Epp = sampleMatrix(p, r, 2 * p.mbar * p.n, p.mbar, p.nbar);
  var B = unpack(p, b, p.n, p.nbar);
  var V = mulAdd(p, Sprime, p.mbar, p.n, B, p.nbar, Epp, false);
  var C = addMatrices(p, V, encode(p, mu));
  var c2 = pack(p, C, p.mbar, p.nbar);

  var ct = concatBytes(c1, c2, salt);
  var ss = shakeOf(p, concatBytes(c1, c2, salt, k), p.lenSs);
  if (ct.length !== p.ctBytes) {
    log.debug("Leaving encapsulate(). Length disagreement.");
    throw new Error('frodokem: ' + variant + ' produced a ' + ct.length +
        '-byte ciphertext; the specification says ' + p.ctBytes + '.');
  }
  log.debug("Leaving encapsulate().");
  return { ciphertext: ct, sharedSecret: ss };
}

// ---------------------------------------------------------------------------
// Algorithm 14 — decapsulation, including the Fujisaki-Okamoto re-encryption
// and the constant-time choice between k' and s.
//
// STEP 16 IS WHY THIS IS NOT SIMPLY "DECRYPT". A KEM that returned an error
// for a malformed ciphertext would leak, through the timing of that error,
// which part of the decryption failed — the attack of Guo, Johansson and
// Nilsson (CRYPTO 2020) against exactly this construction. So the ciphertext
// is RE-ENCRYPTED from the recovered message and compared; a mismatch returns
// a shared secret derived from the secret key's own `s` instead, which is
// well-formed, wrong, and indistinguishable from a good one to the caller.
// That is why a wrong key here produces a plausible secret rather than a
// failure, and why the XML layer's refusal comes from the AEAD tag.
// ---------------------------------------------------------------------------
function decapsulate(variant, sk, ct) {
  log.debug("Entering decapsulate(). variant=" + variant);
  var p = resolve(variant);
  if (sk.length !== p.skBytes) {
    log.debug("Leaving decapsulate(). Wrong secret key length.");
    throw new Error('frodokem: a ' + variant + ' secret key is ' + p.skBytes +
        ' bytes; this one is ' + sk.length + '.');
  }
  if (ct.length !== p.ctBytes) {
    log.debug("Leaving decapsulate(). Wrong ciphertext length.");
    throw new Error('frodokem: a ' + variant + ' ciphertext is ' + p.ctBytes +
        ' bytes; this one is ' + ct.length + '.');
  }
  var c1Len = (p.mbar * p.n * p.D) / 8;
  var c2Len = (p.mbar * p.nbar * p.D) / 8;
  var c1 = ct.subarray(0, c1Len);
  var c2 = ct.subarray(c1Len, c1Len + c2Len);
  var salt = ct.subarray(c1Len + c2Len);

  var at = 0;
  var s = sk.subarray(at, at + p.lenS); at += p.lenS;
  var seedA = sk.subarray(at, at + p.lenSeedA); at += p.lenSeedA;
  var bLen = (p.D * p.n * p.nbar) / 8;
  var b = sk.subarray(at, at + bLen); at += bLen;
  var sLen = p.n * p.nbar * 2;
  var Stransposed = unpackSigned(sk.subarray(at, at + sLen), p.n * p.nbar);
  at += sLen;
  var pkh = sk.subarray(at, at + p.lenPkh);
  var S = transpose(Stransposed, p.nbar, p.n);

  var Bprime = unpack(p, c1, p.mbar, p.n);
  var C = unpack(p, c2, p.mbar, p.nbar);
  var M = mulAdd(p, Bprime, p.mbar, p.n, S, p.nbar, C, true);
  var muPrime = decode(p, M);

  var seedSEk = shakeOf(p, concatBytes(pkh, muPrime, salt),
                        p.lenSeedSE + p.lenK);
  var seedSEprime = seedSEk.subarray(0, p.lenSeedSE);
  var kPrime = seedSEk.subarray(p.lenSeedSE);

  var r = noiseWords(p, 0x96, seedSEprime,
                     2 * p.mbar * p.n + p.mbar * p.nbar);
  var Sprime = sampleMatrix(p, r, 0, p.mbar, p.n);
  var Eprime = sampleMatrix(p, r, p.mbar * p.n, p.mbar, p.n);
  var Bpp = sTimesAPlusE(p, rowGenerator(p, seedA), Sprime, Eprime);
  var Epp = sampleMatrix(p, r, 2 * p.mbar * p.n, p.mbar, p.nbar);
  var B = unpack(p, b, p.n, p.nbar);
  var V = mulAdd(p, Sprime, p.mbar, p.n, B, p.nbar, Epp, false);
  var Cprime = addMatrices(p, V, encode(p, muPrime));

  var equal = constantTimeEqual(Bprime, Bpp) && constantTimeEqual(C, Cprime);
  var kbar = constantTimeSelect(kPrime, s, equal);
  var ss = shakeOf(p, concatBytes(c1, c2, salt, kbar), p.lenSs);
  log.debug("Leaving decapsulate(). reencryption matched=" + equal);
  return ss;
}

// Written without an early return, which is the whole point: a comparison that
// stopped at the first differing element would tell an attacker WHERE the
// ciphertext went wrong. JavaScript gives no real timing guarantees, so this
// is the shape rather than the promise, and the file says so.
function constantTimeEqual(a, b) {
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function constantTimeSelect(a, b, useA) {
  var mask = useA ? 0xff : 0x00;
  var out = new Uint8Array(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = (a[i] & mask) | (b[i] & ~mask & 0xff);
  }
  return out;
}

// The twelve the draft names, in its order.
var VARIANTS = [];
['', 'e'].forEach(function (prefix) {
  [640, 976, 1344].forEach(function (n) {
    ['AES', 'SHAKE'].forEach(function (gen) {
      VARIANTS.push(prefix + 'FrodoKEM-' + n + '-' + gen);
    });
  });
});

module.exports = {
  VARIANTS: VARIANTS,
  resolve: resolve,
  keygen: keygen,
  encapsulate: encapsulate,
  decapsulate: decapsulate,
  // Exported for the vector test, which drives the algorithms individually
  // before driving the whole thing.
  pack: pack,
  unpack: unpack,
  encode: encode,
  decode: decode,
  sample: sample,
  cdfOf: cdfOf
};
