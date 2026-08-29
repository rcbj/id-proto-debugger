// File: hash_tools.js
//
// ---------------------------------------------------------------------------
// Every hash function the Hashing / Encoding Tools page offers, plus the note
// that says what each one is FOR.
//
// It is a module rather than four more functions inside encoding_tools.js for
// the reason the encryption engines, jws.js and scim_client.js are modules:
// it has NO DOM, so tests/hash_engine.js drives all of it in node against
// numbers that are NOT this code — FIPS 202's and SP 800-185's own sample
// values, and node's OpenSSL for both SHA families — rather than against a
// round trip through the page, which agrees with itself whatever the
// implementation does. A digest is exactly the kind of value where that
// distinction decides everything: a wrong one is still 64 hex characters that
// change completely when the input does, so a page can be confidently,
// consistently wrong and look perfect.
//
// WHY THE SHA-3 SIDE IS HERE AT ALL — the post-quantum part.
//
// The page had SHA-1 and the three SHA-2 sizes, over `crypto.subtle`, and
// nothing else. That is the FIPS 180-4 half of NIST's hashing, and it leaves
// out the half the three post-quantum standards are actually built from:
//
//   * FIPS 202 (2015) — SHA3-224/256/384/512 and the two extendable-output
//     functions, SHAKE128 and SHAKE256. Web Crypto has NONE of them, in any
//     browser, which is why this file is pure JavaScript (@noble/hashes) and
//     not `crypto.subtle`. That also means the whole page now works over
//     plain HTTP: `crypto.subtle` does not exist outside a secure context,
//     and the containerized suite's origin is not one — see tests/CLAUDE.md.
//   * SP 800-185 (2016) — cSHAKE, KMAC, TupleHash and ParallelHash, the four
//     functions DERIVED from cSHAKE. They are not variants of SHA-3: each
//     prefixes the input with an encoded function name and customization
//     string, so two uses of one hash with different customizations are
//     different functions, which is the property domain separation is.
//
// Those are what FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
// hash with — every one of them, exclusively, in the SHAKE parameter sets.
// A debugger that can sign with ML-DSA and SLH-DSA (the Digital Signature
// page does) but cannot compute the SHAKE256 those schemes are made of is
// missing the primitive underneath, which is where the interoperability
// arguments actually happen: `role` below records which function each
// standard uses each hash AS, because "SHA3-256" and "ML-KEM's H" are the
// same call and only one of them is findable in FIPS 203.
//
// WHAT THE QUANTUM NOTES SAY, AND WHY THEY ARE NOT n/2 EVERYWHERE. Grover's
// algorithm searches an n-bit preimage in about 2^(n/2) evaluations, so
// preimage resistance halves. Collision resistance does NOT: the birthday
// bound already puts a classical attacker at 2^(n/2), and the quantum
// improvement on that (BHT, 2^(n/3)) needs quantum-accessible memory on the
// same order, which is why NIST's own security categories are defined by
// COLLISION search on SHA-256/SHA3-256 (category 2) and SHA-384/SHA3-384
// (category 4) and treat those as unmoved. Reporting one number for both
// resistances is the mistake this pane exists to stop: it is what makes
// people believe SHA-256 has "128-bit post-quantum security", which is true
// of its preimage resistance and false of the property they were relying on.
//
// NO DOM AND NO STORAGE. Everything here is a pure function of its arguments.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// A node consumer (tests/hash_engine.js loads this module directly) may have
// no CONFIG_FILE, so fall back to info rather than failing to load — the same
// block crypto_bytes.js carries, and for the same reason.
var log = bunyan.createLogger({
  name: "hash_tools",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var nobleSha1 = require("@noble/hashes/sha1");
var nobleSha256 = require("@noble/hashes/sha256");
var nobleSha512 = require("@noble/hashes/sha512");
var nobleSha3 = require("@noble/hashes/sha3");
var nobleAddons = require("@noble/hashes/sha3-addons");
var bytesLib = require("./crypto_bytes");

// The largest output this module will produce, in bits. An XOF has no length
// of its own — SHAKE256 will hand back a gigabyte as happily as 32 bytes — so
// the cap is here rather than at the caller, where each new call site would
// get to invent its own.
var MAX_OUTPUT_BITS = 65536;

// ---------------------------------------------------------------------------
// The fixed-output and extendable-output hash functions (FIPS 180-4, 202).
//
// `hash` is the noble function for a fixed-length digest; `xof` is the noble
// function for an extendable-output one, and exactly one of the two is set.
// `capacity` is the SHAKE security parameter in bits (FIPS 202 Table 4): a
// SHAKE's strength is bounded by it however long the output is asked to be,
// which is the one thing about an XOF that surprises everybody — asking
// SHAKE128 for 512 bits does not give 256-bit collision resistance.
// ---------------------------------------------------------------------------
var ALGORITHMS = [
  { id: "SHA-256", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha256.sha256, bits: 256, category: 2,
    role: "SLH-DSA-SHA2's F and PRF (FIPS 205); the PKCE, JWS and " +
        "X.509 workhorse" },
  { id: "SHA-1", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha1.sha1, bits: 160, category: null,
    broken: "Collision resistance is BROKEN in practice — SHAttered (2017) " +
        "produced a colliding pair at about 2^63 work, and a chosen-prefix " +
        "collision followed in 2020. Present for reading old artifacts, " +
        "never for new ones.",
    role: "none — no post-quantum standard uses it" },
  { id: "SHA-224", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha256.sha224, bits: 224, category: null,
    role: "none — no post-quantum standard uses it" },
  { id: "SHA-384", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha512.sha384, bits: 384, category: 4,
    role: "none directly — but see the category line above" },
  { id: "SHA-512", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha512.sha512, bits: 512, category: null,
    role: "SLH-DSA-SHA2 at categories 3 and 5 hashes the message with it " +
        "(FIPS 205)" },
  { id: "SHA-512/224", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha512.sha512_224, bits: 224, category: null,
    role: "none — truncated SHA-512, so no length-extension" },
  { id: "SHA-512/256", group: "SHA-2 (FIPS 180-4)", spec: "FIPS 180-4",
    hash: nobleSha512.sha512_256, bits: 256, category: null,
    role: "none — truncated SHA-512, so no length-extension, and faster " +
        "than SHA-256 on 64-bit hardware" },

  { id: "SHA3-224", group: "SHA-3 (FIPS 202)", spec: "FIPS 202",
    hash: nobleSha3.sha3_224, bits: 224, category: null,
    role: "none directly — the sponge, at the smallest standard size" },
  { id: "SHA3-256", group: "SHA-3 (FIPS 202)", spec: "FIPS 202",
    hash: nobleSha3.sha3_256, bits: 256, category: 2,
    role: "ML-KEM's H (FIPS 203 section 4.1)" },
  { id: "SHA3-384", group: "SHA-3 (FIPS 202)", spec: "FIPS 202",
    hash: nobleSha3.sha3_384, bits: 384, category: 4,
    role: "none directly — but see the category line above" },
  { id: "SHA3-512", group: "SHA-3 (FIPS 202)", spec: "FIPS 202",
    hash: nobleSha3.sha3_512, bits: 512, category: null,
    role: "ML-KEM's G (FIPS 203 section 4.1)" },

  { id: "SHAKE128", group: "SHAKE — extendable output (FIPS 202)",
    spec: "FIPS 202", xof: nobleSha3.shake128, bits: null, capacity: 128,
    category: null,
    role: "ML-KEM's XOF, which expands the seed into the matrix A (FIPS " +
        "203); ML-DSA's ExpandA (FIPS 204)" },
  { id: "SHAKE256", group: "SHAKE — extendable output (FIPS 202)",
    spec: "FIPS 202", xof: nobleSha3.shake256, bits: null, capacity: 256,
    category: null,
    role: "ML-KEM's PRF and J (FIPS 203); nearly every hash in ML-DSA " +
        "(FIPS 204); ALL SIX of SLH-DSA-SHAKE's functions (FIPS 205); and " +
        "Ed448's internal hash (RFC 8032)" },

  { id: "Keccak-256", group: "Legacy Keccak (NOT FIPS 202)",
    spec: "Keccak submission (pre-FIPS padding)",
    hash: nobleSha3.keccak_256, bits: 256, category: null,
    caution: "This is NOT SHA3-256. FIPS 202 appended the two-bit domain " +
        "separator 01 to the message before padding; the original Keccak " +
        "submission did not, so the two produce completely different " +
        "digests of the same input. It is here because Ethereum and " +
        "several older tools standardized on the pre-FIPS version and " +
        "call it 'SHA3', which is the single most common way a correct " +
        "SHA-3 implementation gets reported as broken.",
    role: "none — pre-standard padding" },
  { id: "Keccak-512", group: "Legacy Keccak (NOT FIPS 202)",
    spec: "Keccak submission (pre-FIPS padding)",
    hash: nobleSha3.keccak_512, bits: 512, category: null,
    caution: "Pre-FIPS padding — see Keccak-256. Not SHA3-512.",
    role: "none — pre-standard padding" }
];

var BY_ID = (function () {
  var map = {};
  for (var i = 0; i < ALGORITHMS.length; i++) {
    map[ALGORITHMS[i].id] = ALGORITHMS[i];
  }
  return map;
})();

// ---------------------------------------------------------------------------
// The SP 800-185 functions derived from cSHAKE.
//
// `kind` decides which arguments mean anything, and the page dims the rest:
// only KMAC takes a key, only TupleHash takes a LIST of strings, only
// ParallelHash takes a block size. `xof` marks the four variants whose final
// length encoding is right_encode(0) rather than right_encode(L) — which is
// the whole difference between KMAC128 and KMAC128XOF, and it changes every
// byte of the output rather than just its length.
// ---------------------------------------------------------------------------
var DERIVED = [
  { id: "cSHAKE128", kind: "cshake", fn: nobleAddons.cshake128,
    strength: 128,
    about: "SHAKE128 with a function name N and a customization string S " +
        "prefixed in. With both empty it IS SHAKE128, bit for bit — SP " +
        "800-185 section 3.3 says so, and this pane will show it." },
  { id: "cSHAKE256", kind: "cshake", fn: nobleAddons.cshake256,
    strength: 256,
    about: "SHAKE256 with a function name N and a customization string S " +
        "prefixed in. With both empty it IS SHAKE256, bit for bit." },
  { id: "KMAC128", kind: "kmac", fn: nobleAddons.kmac128, strength: 128,
    about: "A keyed MAC built on cSHAKE128. Unlike HMAC it needs no nested " +
        "construction — the sponge is not vulnerable to length extension — " +
        "and the requested output length L is bound INTO the computation." },
  { id: "KMAC256", kind: "kmac", fn: nobleAddons.kmac256, strength: 256,
    about: "A keyed MAC built on cSHAKE256, otherwise as KMAC128." },
  { id: "KMAC128XOF", kind: "kmac", fn: nobleAddons.kmac128xof, xof: true,
    strength: 128,
    about: "KMAC128 with the length encoded as right_encode(0) instead of " +
        "right_encode(L), which makes the output a stream you may take any " +
        "amount of — and makes it differ from KMAC128 in every byte." },
  { id: "KMAC256XOF", kind: "kmac", fn: nobleAddons.kmac256xof, xof: true,
    strength: 256,
    about: "KMAC256 as an extendable-output function — see KMAC128XOF." },
  { id: "TupleHash128", kind: "tuple", fn: nobleAddons.tuplehash128,
    strength: 128,
    about: "Hashes a LIST of strings unambiguously: each element is length-" +
        "prefixed, so ('ab','c') and ('a','bc') have different digests. " +
        "That is the property plain concatenation does not have, and it is " +
        "why one string per line here is not the same as one long line." },
  { id: "TupleHash256", kind: "tuple", fn: nobleAddons.tuplehash256,
    strength: 256,
    about: "TupleHash at the 256-bit security strength." },
  { id: "TupleHash128XOF", kind: "tuple", fn: nobleAddons.tuplehash128xof,
    xof: true, strength: 128,
    about: "TupleHash128 as an extendable-output function." },
  { id: "TupleHash256XOF", kind: "tuple", fn: nobleAddons.tuplehash256xof,
    xof: true, strength: 256,
    about: "TupleHash256 as an extendable-output function." },
  { id: "ParallelHash128", kind: "parallel", fn: nobleAddons.parallelhash128,
    strength: 128,
    about: "Splits the input into B-byte blocks, hashes each independently " +
        "and hashes the concatenated results — so B is part of the " +
        "definition and two readers who pick different block sizes get " +
        "different digests of the same file." },
  { id: "ParallelHash256", kind: "parallel", fn: nobleAddons.parallelhash256,
    strength: 256,
    about: "ParallelHash at the 256-bit security strength." },
  { id: "ParallelHash128XOF", kind: "parallel",
    fn: nobleAddons.parallelhash128xof, xof: true, strength: 128,
    about: "ParallelHash128 as an extendable-output function." },
  { id: "ParallelHash256XOF", kind: "parallel",
    fn: nobleAddons.parallelhash256xof, xof: true, strength: 256,
    about: "ParallelHash256 as an extendable-output function." }
];

var DERIVED_BY_ID = (function () {
  var map = {};
  for (var i = 0; i < DERIVED.length; i++) {
    map[DERIVED[i].id] = DERIVED[i];
  }
  return map;
})();

// ---------------------------------------------------------------------------
// Input / output codings.
//
// A hash pane that can only take UTF-8 text cannot check a published test
// vector, because every specification writes its inputs in hex — which is
// the first thing anybody does with a tool like this.
// ---------------------------------------------------------------------------
function decodeInput(text, encoding) {
  log.debug("Entering decodeInput(). encoding=" + encoding);
  var value = text || "";
  if (encoding === "hex") {
    var cleaned = value.replace(/[\s:]+/g, "");
    if (cleaned.length % 2 !== 0) {
      log.debug("Leaving decodeInput(). Odd hex length.");
      throw new Error("Hex input has an odd number of digits.");
    }
    if (cleaned.length && !/^[0-9a-fA-F]+$/.test(cleaned)) {
      log.debug("Leaving decodeInput(). Not hex.");
      throw new Error("Hex input contains a non-hex character.");
    }
    log.debug("Leaving decodeInput().");
    return cleaned.length ? bytesLib.hexToBytes(cleaned) : new Uint8Array(0);
  }
  if (encoding === "base64") {
    log.debug("Leaving decodeInput().");
    return bytesLib.b64ToBytes(value.replace(/\s+/g, ""));
  }
  if (encoding === "base64url") {
    log.debug("Leaving decodeInput().");
    return bytesLib.b64uToBytes(value.replace(/\s+/g, ""));
  }
  log.debug("Leaving decodeInput().");
  return bytesLib.strBytes(value);
}

function encodeOutput(bytes, format) {
  log.debug("Entering encodeOutput(). format=" + format);
  if (format === "HEX") {
    log.debug("Leaving encodeOutput().");
    return bytesLib.bytesToHex(bytes).toUpperCase();
  }
  if (format === "base64") {
    log.debug("Leaving encodeOutput().");
    return bytesLib.bytesToB64(bytes);
  }
  if (format === "base64url") {
    log.debug("Leaving encodeOutput().");
    return bytesLib.bytesToB64u(bytes);
  }
  log.debug("Leaving encodeOutput().");
  return bytesLib.bytesToHex(bytes);
}

// A requested output length, checked. SP 800-185 allows any number of BITS;
// this module is byte-oriented, so a length that is not a whole number of
// bytes is refused by name rather than silently rounded — a digest that is
// almost the one the specification asked for is the worst answer available.
function outputBytes(bits) {
  log.debug("Entering outputBytes(). bits=" + bits);
  var n = parseInt(bits, 10);
  if (!isFinite(n) || n <= 0) {
    log.debug("Leaving outputBytes(). Not a length.");
    throw new Error("Output length must be a positive number of bits.");
  }
  if (n % 8 !== 0) {
    log.debug("Leaving outputBytes(). Not whole bytes.");
    throw new Error("Output length must be a multiple of 8 bits.");
  }
  if (n > MAX_OUTPUT_BITS) {
    log.debug("Leaving outputBytes(). Too long.");
    throw new Error("Output length is capped at " + MAX_OUTPUT_BITS +
                    " bits here.");
  }
  log.debug("Leaving outputBytes().");
  return n / 8;
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------
function digest(id, message, opts) {
  log.debug("Entering digest(). id=" + id);
  var alg = BY_ID[id];
  if (!alg) {
    log.debug("Leaving digest(). Unknown algorithm.");
    throw new Error("Unknown hash algorithm: " + id);
  }
  if (alg.xof) {
    var dkLen = outputBytes((opts && opts.outputBits) || 256);
    log.debug("Leaving digest(). XOF.");
    return alg.xof(message, { dkLen: dkLen });
  }
  log.debug("Leaving digest().");
  return alg.hash(message);
}

// The SP 800-185 functions. `opts` carries whatever the chosen function
// takes: message (bytes) or messages (an array of byte arrays for TupleHash),
// key (bytes, KMAC only), customization (the string S), functionName (the
// string N, cSHAKE only — the others fix it), blockBytes (ParallelHash's B)
// and outputBits (L).
function derive(id, opts) {
  log.debug("Entering derive(). id=" + id);
  var fn = DERIVED_BY_ID[id];
  if (!fn) {
    log.debug("Leaving derive(). Unknown function.");
    throw new Error("Unknown SP 800-185 function: " + id);
  }
  var options = opts || {};
  var params = { dkLen: outputBytes(options.outputBits || 256) };
  if (options.customization) {
    params.personalization = options.customization;
  }
  if (fn.kind === "cshake") {
    // N is reserved by SP 800-185 section 3.2 for functions NIST itself
    // defines; the other three fix it ("KMAC", "TupleHash", "ParallelHash"),
    // so it is only an argument here.
    params.NISTfn = options.functionName || "";
    log.debug("Leaving derive(). cSHAKE.");
    return fn.fn(options.message || new Uint8Array(0), params);
  }
  if (fn.kind === "kmac") {
    if (!options.key) {
      log.debug("Leaving derive(). No key.");
      throw new Error(id + " needs a key.");
    }
    log.debug("Leaving derive(). KMAC.");
    return fn.fn(options.key, options.message || new Uint8Array(0), params);
  }
  if (fn.kind === "tuple") {
    log.debug("Leaving derive(). TupleHash.");
    return fn.fn(options.messages || [], params);
  }
  if (fn.kind === "parallel") {
    var b = parseInt(options.blockBytes, 10);
    if (!isFinite(b) || b <= 0) {
      log.debug("Leaving derive(). Bad block size.");
      throw new Error("ParallelHash needs a block size B of at least 1 " +
                      "byte.");
    }
    params.blockLen = b;
    log.debug("Leaving derive(). ParallelHash.");
    return fn.fn(options.message || new Uint8Array(0), params);
  }
  log.debug("Leaving derive(). Unhandled kind.");
  throw new Error("Unhandled SP 800-185 kind: " + fn.kind);
}

// ---------------------------------------------------------------------------
// The notes. These are the reason the panes are worth having rather than a
// `sha3sum` shell alias, so they are computed here — where a test can read
// them — instead of typed into the HTML, where the numbers would go stale
// against the algorithm list beside them.
// ---------------------------------------------------------------------------

// FIPS 202 Table 4: an XOF's resistances are bounded BOTH by the output
// length d and by the capacity (128 or 256). A fixed-output hash gets d/2 and
// d, which is the classical statement of it.
function strengths(id, outputBits) {
  log.debug("Entering strengths(). id=" + id);
  var alg = BY_ID[id];
  if (!alg) {
    log.debug("Leaving strengths(). Unknown algorithm.");
    throw new Error("Unknown hash algorithm: " + id);
  }
  var d = alg.bits || parseInt(outputBits, 10) || 0;
  if (!alg.xof) {
    log.debug("Leaving strengths().");
    return { output: d, collision: d / 2, preimage: d };
  }
  log.debug("Leaving strengths(). XOF.");
  return { output: d,
           collision: Math.min(d / 2, alg.capacity),
           preimage: Math.min(d, alg.capacity) };
}

function describe(id, outputBits) {
  log.debug("Entering describe(). id=" + id);
  var alg = BY_ID[id];
  if (!alg) {
    log.debug("Leaving describe(). Unknown algorithm.");
    throw new Error("Unknown hash algorithm: " + id);
  }
  var s = strengths(id, outputBits);
  var lines = [];
  lines.push(alg.id + " — " + alg.spec + ", " + s.output + "-bit output" +
             (alg.xof ? " (extendable; capacity " + alg.capacity +
              " bits)" : ""));
  lines.push("Classical: " + s.collision + "-bit collision, " + s.preimage +
             "-bit preimage resistance.");
  lines.push("Quantum: preimage falls to about " +
             Math.round(s.preimage / 2) + " bits under Grover; collision " +
             "resistance is essentially unchanged at " + s.collision +
             " bits, because the classical birthday bound already applies " +
             "and the quantum improvement on it needs comparable quantum " +
             "memory.");
  if (alg.category) {
    lines.push("Collision search on this function DEFINES NIST " +
               "post-quantum security category " + alg.category + ".");
  }
  lines.push("Post-quantum role: " + alg.role + ".");
  if (alg.caution) {
    lines.push("CAUTION: " + alg.caution);
  }
  if (alg.broken) {
    lines.push("BROKEN: " + alg.broken);
  }
  log.debug("Leaving describe().");
  return lines.join("\n");
}

function describeDerived(id, opts) {
  log.debug("Entering describeDerived(). id=" + id);
  var fn = DERIVED_BY_ID[id];
  if (!fn) {
    log.debug("Leaving describeDerived(). Unknown function.");
    throw new Error("Unknown SP 800-185 function: " + id);
  }
  var options = opts || {};
  var lines = [];
  lines.push(fn.id + " — NIST SP 800-185, " + fn.strength +
             "-bit security strength" + (fn.xof ? ", extendable output" :
             "") + ".");
  lines.push(fn.about);
  lines.push("Customization S separates domains: the same key and the same " +
             "message under a different S is a different function, and " +
             "that is what S is for.");
  if (options.customization) {
    lines.push("S in use: \"" + options.customization + "\".");
  } else {
    lines.push("S is empty on this computation.");
  }
  log.debug("Leaving describeDerived().");
  return lines.join("\n");
}

// Lookups, as functions rather than as the two maps, so a caller cannot add
// an algorithm to the registry from outside it.
function algorithm(id) {
  log.debug("Entering algorithm(). id=" + id);
  log.debug("Leaving algorithm().");
  return BY_ID[id];
}

function derivedFunction(id) {
  log.debug("Entering derivedFunction(). id=" + id);
  log.debug("Leaving derivedFunction().");
  return DERIVED_BY_ID[id];
}

module.exports = {
  ALGORITHMS: ALGORITHMS,
  DERIVED: DERIVED,
  MAX_OUTPUT_BITS: MAX_OUTPUT_BITS,
  algorithm: algorithm,
  derived: derivedFunction,
  decodeInput: decodeInput,
  encodeOutput: encodeOutput,
  outputBytes: outputBytes,
  digest: digest,
  derive: derive,
  strengths: strengths,
  describe: describe,
  describeDerived: describeDerived
};
