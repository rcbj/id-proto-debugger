// File: pqc.js
//
// ---------------------------------------------------------------------------
// POST-QUANTUM CRYPTOGRAPHY — the algorithms, and WHICH STANDARD EACH ONE IS.
//
// This module exists for a reason that is not "the panes needed somewhere to
// put the ML-DSA call". Post-quantum cryptography is, right now, a mixture of
// three quite different things:
//
//   * published standards a client can be held to     (FIPS 203/204/205,
//     RFC 9964, RFC 8554, RFC 8391)
//   * Internet-Drafts that are stable enough to build against but WILL still
//     change their algorithm names, their key encodings, or their KDF
//     (draft-ietf-jose-pqc-kem, draft-ietf-cose-falcon, the two composite
//     drafts, draft-connolly-cfrg-xwing-kem)
//   * algorithms that have been SELECTED but have no specification anybody can
//     implement yet (HQC — see THE ONE THING THIS MODULE DELIBERATELY OMITS,
//     below)
//
// A debugger that presents all three as if they were the same kind of fact is
// worse than useless, because the whole point of the tool is to tell somebody
// what the wire is supposed to look like. So EVERY algorithm here carries a
// `spec` pointing into the SPECS table, every SPECS entry carries a `status`
// of 'rfc' or 'draft', and every draft entry carries the `note` that the UI is
// required to render beside it. `specNote()` is the one function that produces
// that sentence, so a pane cannot forget to say it and two panes cannot
// disagree about what it says.
//
// THE ONE THING THIS MODULE DELIBERATELY OMITS IS HQC. NIST selected it in
// March 2025 as the backup KEM, and that is the entire extent of what exists:
// there is no published FIPS, no draft FIPS, no IETF draft binding it to JOSE
// or COSE, and no implementation in this dependency tree or any vetted JS
// one. Implementing it from the round-4 submission would mean inventing the
// encoding and the algorithm identifier, which is precisely the thing a
// debugger must never do — a made-up wire format that looks authoritative is a
// worse outcome than an absent pane. When the draft FIPS lands, HQC belongs
// here, and `MISSING` below records why it is not here yet so the next reader
// does not have to re-derive it.
//
// ONE CONSTRAINT SHAPES WHAT IS IN HERE AND IT IS NOT A CRYPTOGRAPHIC ONE.
// This client is bundled with browserify, which is a CommonJS bundler, and
// `@noble/post-quantum` became ESM-ONLY at version 0.5.0 ("type": "module",
// no CJS build, no esm/ + cjs/ pair). 0.4.1 is therefore the last version
// this build can consume, and `esmify` does not rescue it: the transform gets
// as far as the nested `@noble/hashes` 1.8.0 and browserify's parser rejects
// that file's syntax outright. So everything below is built on 0.4.1, which
// carries ML-KEM, ML-DSA and SLH-DSA — including their context strings and
// their pre-hash variants with the correct OIDs — and does NOT carry Falcon
// or any hybrid preset. What that costs is recorded in MISSING and the two
// gaps are filled differently: X-Wing is implemented here from the draft's
// own pseudocode (and checked against its three published test vectors), and
// FN-DSA is absent rather than pulled from an unmaintained third-party WASM
// wrapper. Moving to a newer library means changing the bundler, which is a
// larger decision than this module gets to make on its own.
//
// NO DOM. Bytes in, bytes out, so tests/pqc_engines.js drives every path in
// node with no browser — the same rule pk_encryption.js and jws.js follow.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var mldsa = require("@noble/post-quantum/ml-dsa.js");
var slh = require("@noble/post-quantum/slh-dsa.js");
var mlkem = require("@noble/post-quantum/ml-kem.js");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var ed448 = require("@noble/curves/ed448").ed448;
var x25519 = require("@noble/curves/ed25519").x25519;
var x448 = require("@noble/curves/ed448").x448;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha384 = require("@noble/hashes/sha512").sha384;
var nobleSha512 = require("@noble/hashes/sha512").sha512;
var nobleShake256 = require("@noble/hashes/sha3").shake256;
var nobleSha3_256 = require("@noble/hashes/sha3").sha3_256;
var nobleSha3_512 = require("@noble/hashes/sha3").sha3_512;
var nobleShake128 = require("@noble/hashes/sha3").shake128;
var bytes = require("./crypto_bytes");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "pqc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var EMPTY_CTX = new Uint8Array(0);

var asBytes = bytes.asBytes;
var concatBytes = bytes.concatBytes;
var strBytes = bytes.strBytes;
var bytesToB64u = bytes.bytesToB64u;
var b64uToBytes = bytes.b64uToBytes;

// ===========================================================================
// THE STANDARDS TABLE
// ===========================================================================
// `status` is the only field the UI branches on: 'rfc' means a published,
// citable document whose bytes will not move under a caller, and 'draft' means
// an Internet-Draft that can and does change between revisions. The `note` on
// a draft is the sentence rendered beside every algorithm that cites it — it
// names the revision, because "implements the draft" without a revision number
// is the claim that ages worst.
var SPECS = {
  'FIPS.203': {
    title: 'FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism',
    status: 'rfc',
    ref: 'https://doi.org/10.6028/NIST.FIPS.203'
  },
  'FIPS.204': {
    title: 'FIPS 204 — Module-Lattice-Based Digital Signature Standard',
    status: 'rfc',
    ref: 'https://doi.org/10.6028/NIST.FIPS.204'
  },
  'FIPS.205': {
    title: 'FIPS 205 — Stateless Hash-Based Digital Signature Standard',
    status: 'rfc',
    ref: 'https://doi.org/10.6028/NIST.FIPS.205'
  },
  'RFC.9964': {
    title: 'RFC 9964 — ML-DSA for JOSE and COSE',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc9964.html'
  },
  'RFC.8554': {
    title: 'RFC 8554 — Leighton-Micali Hash-Based Signatures',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc8554.html'
  },
  'RFC.8391': {
    title: 'RFC 8391 — XMSS: eXtended Merkle Signature Scheme',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc8391.html'
  },
  'RFC.9881': {
    title: 'RFC 9881 — Algorithm Identifiers for ML-DSA in X.509',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc9881.html'
  },
  'RFC.9909': {
    title: 'RFC 9909 — Algorithm Identifiers for SLH-DSA in X.509',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc9909.html'
  },
  'RFC.9935': {
    title: 'RFC 9935 — Algorithm Identifiers for ML-KEM in X.509',
    status: 'rfc',
    ref: 'https://www.rfc-editor.org/rfc/rfc9935.html'
  },
  'SP.800-208': {
    title: 'NIST SP 800-208 — Recommendation for Stateful Hash-Based ' +
           'Signature Schemes',
    status: 'rfc',
    ref: 'https://doi.org/10.6028/NIST.SP.800-208'
  },
  // ---- drafts ----
  'I-D.cose-sphincs-plus': {
    title: 'draft-ietf-cose-sphincs-plus-10 — SLH-DSA for JOSE and COSE',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/',
    note: 'DRAFT STANDARD — draft-ietf-cose-sphincs-plus-10, submitted to ' +
          'the IESG. The algorithm names are stable but not yet an RFC, and ' +
          'only the two NIST category 1 "small" parameter sets are ' +
          'registered for JOSE, one per hash family.'
  },
  'I-D.cose-falcon': {
    title: 'draft-ietf-cose-falcon-04 — FN-DSA for JOSE and COSE',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-cose-falcon/',
    note: 'DRAFT STANDARD — draft-ietf-cose-falcon-04, and the underlying ' +
          'FIPS 206 is itself still in development. Both the algorithm ' +
          'identifiers and the final FN-DSA parameters may change; what is ' +
          'implemented here is Falcon as submitted to the NIST process.'
  },
  'I-D.jose-pq-composite-sigs': {
    title: 'draft-ietf-jose-pq-composite-sigs-03 — PQ/T Hybrid Composite ' +
           'Signatures for JOSE and COSE',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/',
    note: 'DRAFT STANDARD — draft-ietf-jose-pq-composite-sigs-03. The ' +
          'combiner and the domain-separation labels are taken verbatim ' +
          'from that revision; the JOSE algorithm names have no IANA ' +
          'assignment yet.'
  },
  'I-D.jose-pqc-kem': {
    title: 'draft-ietf-jose-pqc-kem-06 — Post-Quantum Key Encapsulation ' +
           'Mechanisms for JOSE and COSE',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/',
    note: 'DRAFT STANDARD — draft-ietf-jose-pqc-kem-06. The COSE algorithm ' +
          'codepoints are still TBD, and the KMAC256 key-derivation inputs ' +
          'are specified by reference to RFC 9053 rather than written out, ' +
          'so a future revision may change the bytes on the wire.'
  },
  'I-D.lamps-composite-kem': {
    title: 'draft-ietf-lamps-pq-composite-kem-08 — Composite ML-KEM for use ' +
           'in X.509 Public Key Infrastructure and CMS',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/',
    note: 'DRAFT STANDARD — draft-ietf-lamps-pq-composite-kem-08. The ' +
          'combiner and the per-algorithm labels are taken verbatim from ' +
          'that revision. The OIDs it lists are PROTOTYPING OIDs in an ' +
          'Entrust arc and the draft says they will be replaced by IANA, ' +
          'so do not burn them into anything.'
  },
  'I-D.xwing': {
    title: 'draft-connolly-cfrg-xwing-kem — X-Wing: general-purpose hybrid ' +
           'post-quantum KEM',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/',
    note: 'DRAFT STANDARD — draft-connolly-cfrg-xwing-kem (CFRG). The ' +
          'combiner is frozen and has test vectors, but the document is not ' +
          'yet an RFC.'
  },
  'I-D.lamps-composite-sigs': {
    title: 'draft-ietf-lamps-pq-composite-sigs-19 — Composite ML-DSA for ' +
           'use in X.509 Public Key Infrastructure and CMS',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/',
    note: 'DRAFT STANDARD — draft-ietf-lamps-pq-composite-sigs-19, in the ' +
          'RFC Editor queue. Unlike its JOSE sibling this revision has real ' +
          'IANA OIDs (1.3.6.1.5.5.7.6.37 to .54) rather than prototyping ' +
          'ones, and the construction is frozen; what is not yet frozen is ' +
          'the document, so a certificate issued with these identifiers is ' +
          'a test artifact rather than something to deploy.'
  },
  'X.509-2019': {
    title: 'ITU-T X.509 (2019) clause 9.8 — alternative public key and ' +
           'signature extensions',
    status: 'draft',
    ref: 'https://www.itu.int/rec/T-REC-X.509',
    note: 'PUBLISHED BY ITU-T, NOT BY THE IETF, and that is the caveat ' +
          'rather than a draft number: the three extensions (2.5.29.72, ' +
          '.73, .74) are in the 2019 edition of X.509, but the IETF profile ' +
          'that would say how a PKIX validator treats them — ' +
          'draft-truskovsky-lamps-pq-hybrid-x509 — expired without ' +
          'progressing. Implementations agree on the encoding and differ on ' +
          'what a failed alternative signature means.'
  },
  'I-D.cfrg-hybrid-kems': {
    title: 'draft-irtf-cfrg-hybrid-kems — Hybrid PQ/T Key Encapsulation ' +
           'Mechanisms',
    status: 'draft',
    ref: 'https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/',
    note: 'DRAFT STANDARD — draft-irtf-cfrg-hybrid-kems (CFRG). These are ' +
          'the generic QSF constructions, not the LAMPS composite KEM ' +
          'encodings used in X.509; the two are different byte layouts for ' +
          'the same idea.'
  }
};

// What is NOT here, and why. Rendered by the pages so that an absent algorithm
// reads as a decision rather than an oversight — and so that nobody adds one
// by writing the wire format themselves.
var MISSING = [
  {
    name: 'FN-DSA (Falcon)',
    reason: 'NIST selected it and draft-ietf-cose-falcon-04 registers ' +
            'FN-DSA-512 and FN-DSA-1024 for JOSE, so unlike HQC there IS a ' +
            'specification to implement. What is missing is an ' +
            'implementation this build can load: @noble/post-quantum ships ' +
            'Falcon only from 0.5.0, which is ESM-only, and this client is ' +
            'bundled with browserify (CommonJS). The alternative on npm is ' +
            'an unmaintained 2021 WASM wrapper, which is not a dependency ' +
            'worth adding to a security tool for an algorithm whose FIPS ' +
            '206 is still unpublished. It belongs here when the bundler ' +
            'moves.'
  },
  {
    name: 'HQC',
    reason: 'Selected by NIST in March 2025 as the backup KEM, but there is ' +
            'no draft FIPS, no IETF draft binding it to JOSE or COSE, and ' +
            'no vetted JavaScript implementation. Implementing it now would ' +
            'mean inventing an encoding and an algorithm identifier.'
  }
];

function spec(id) {
  log.debug("Entering spec(). id=" + id);
  var found = SPECS[id];
  if (!found) {
    log.debug("Leaving spec(). Unknown.");
    throw new Error('Unknown specification id: ' + id);
  }
  log.debug("Leaving spec().");
  return found;
}

// The one place a "this is a draft" sentence is produced. Returns '' for a
// published standard, so a caller can concatenate it unconditionally.
function specNote(id) {
  log.debug("Entering specNote(). id=" + id);
  var found = SPECS[id];
  if (!found || found.status !== 'draft') {
    log.debug("Leaving specNote(). Not a draft.");
    return '';
  }
  log.debug("Leaving specNote().");
  return found.note;
}

function isDraft(id) {
  log.debug("Entering isDraft(). id=" + id);
  var found = SPECS[id];
  log.debug("Leaving isDraft().");
  return !!found && found.status === 'draft';
}

// ===========================================================================
// AKP — the JWK key type every post-quantum algorithm here shares (RFC 9964)
// ===========================================================================
// RFC 9964 section 3 defines "AKP" (Algorithm Key Pair) with exactly two key
// parameters, `pub` and `priv`, both base64url, and makes `alg` REQUIRED —
// because unlike an EC key, an AKP key's parameters are opaque octets that
// carry nothing to identify the algorithm from. That is why this function
// takes the algorithm name and refuses to build a key without one.
//
// THIS REPLACED A WRONG EXPORT. Both post-quantum panes used to write
// `{ kty: 'AKP', x: ..., d: ... }`, borrowing OKP's parameter names, which
// predates RFC 9964 and no conforming implementation reads. `x`/`d` are gone
// rather than kept as an alias: the whole value of the pane is that what it
// hands you is what the standard says.
//
// AND `priv` IS THE SEED, NOT THE EXPANDED KEY. RFC 9964 section 3.2 requires
// that for ML-DSA the `priv` parameter be the 32-byte seed. The expanded
// secret key (2560/4032/4896 bytes) is what the signing primitive wants, so
// callers re-derive it with keygen(seed) — see `akpImportSigning()`. Writing
// the expanded key into `priv` produces a JWK that this page could read back
// and nothing else could.
function akpPublicJwk(algName, pub, extra) {
  log.debug("Entering akpPublicJwk(). alg=" + algName);
  if (!algName) {
    log.debug("Leaving akpPublicJwk(). No alg.");
    throw new Error('An AKP JWK requires "alg" (RFC 9964 section 3).');
  }
  var jwk = { kty: 'AKP', alg: algName, pub: bytesToB64u(asBytes(pub)) };
  var keys = Object.keys(extra || {});
  for (var i = 0; i < keys.length; i++) {
    jwk[keys[i]] = extra[keys[i]];
  }
  log.debug("Leaving akpPublicJwk().");
  return jwk;
}

function akpPrivateJwk(algName, pub, priv, extra) {
  log.debug("Entering akpPrivateJwk(). alg=" + algName);
  var jwk = akpPublicJwk(algName, pub, extra);
  jwk.priv = bytesToB64u(asBytes(priv));
  log.debug("Leaving akpPrivateJwk().");
  return jwk;
}

// Reads an AKP JWK back into bytes, refusing the shapes that would otherwise
// fail much later with an unhelpful length error from the primitive.
function akpImport(jwk) {
  log.debug("Entering akpImport().");
  if (!jwk || jwk.kty !== 'AKP') {
    log.debug("Leaving akpImport(). Not AKP.");
    throw new Error('Not an AKP JWK: kty is ' +
                    (jwk && jwk.kty ? jwk.kty : '(absent)') + '.');
  }
  if (!jwk.alg) {
    log.debug("Leaving akpImport(). No alg.");
    throw new Error('An AKP JWK MUST carry "alg" (RFC 9964 section 3).');
  }
  if (!jwk.pub) {
    log.debug("Leaving akpImport(). No pub.");
    throw new Error('An AKP JWK MUST carry "pub".');
  }
  var out = { alg: jwk.alg, pub: b64uToBytes(jwk.pub), priv: null };
  if (jwk.priv) {
    out.priv = b64uToBytes(jwk.priv);
  }
  // The mistake this catches is the one the old export made: an ML-DSA JWK
  // whose private half is the expanded key rather than the seed. It is
  // detectable purely from the length, and saying so here is far kinder than
  // letting keygen() reject a 2560-byte "seed".
  //
  // THE FAMILY IS READ FROM THE REGISTRY AND NOT FROM THE NAME, and that is
  // not fastidiousness — the first version of this check tested
  // /^ML-DSA-/ against `alg`, which also matches every COMPOSITE algorithm
  // ("ML-DSA-44-Ed25519" and friends), whose `priv` is legitimately a seed
  // PLUS a traditional key and therefore never 32 bytes. It rejected six
  // valid key types.
  var known = SIGNATURE_ALGS[jwk.alg];
  if (out.priv && known && known.family === 'ML-DSA' &&
      out.priv.length !== 32) {
    log.debug("Leaving akpImport(). Expanded ML-DSA private key.");
    throw new Error('RFC 9964 section 3.2 requires the ML-DSA "priv" ' +
        'parameter to be the 32-byte seed; this one is ' + out.priv.length +
        ' bytes, which is the expanded private key. Re-export the key.');
  }
  log.debug("Leaving akpImport().");
  return out;
}

// ===========================================================================
// SIGNATURES
// ===========================================================================
// Every entry exposes the same four things — keygen/sign/verify/lengths — so
// the panes, jws.js and the tests all drive one shape. `jose` is the JOSE
// "alg" name where one is registered and null where the algorithm has a
// primitive but no envelope binding (the ten SLH-DSA parameter sets JOSE does
// not register are the whole of that case).
//
// `seeded` says whether keygen accepts a 32-byte seed, which is what makes an
// RFC 9964 `priv` round-trip possible. ML-DSA and the composites are seeded;
// SLH-DSA and Falcon are not, so their AKP `priv` is the raw secret key —
// which is what draft-ietf-cose-sphincs-plus and draft-ietf-cose-falcon
// each specify for their own algorithms.

// ---------------------------------------------------------------------------
// THE SIZE TABLES, AND WHY THEY ARE WRITTEN OUT HERE
// ---------------------------------------------------------------------------
// @noble/post-quantum 0.4.1 exposes almost no metadata — no `lengths` on any
// algorithm — so the sizes the composite constructions need in order to SPLIT
// a concatenated key or signature have to come from somewhere. They come from
// the standards, transcribed, because that is what the composite drafts
// themselves do: "since the key or signature sizes are fixed as defined in
// [FIPS.204], it is unambiguous to encode or decode a composite key".
//
// A transcription is exactly the kind of thing that is wrong silently — a
// mistyped digit gives a splitter that works between two copies of this code
// and interoperates with nothing — so tests/pqc_engines.js checks every one
// of these against a key the library actually generates and a signature it
// actually produces, rather than trusting the table.
var ML_DSA_SIZES = {
  'ML-DSA-44': { publicKey: 1312, secretKey: 2560, signature: 2420, seed: 32 },
  'ML-DSA-65': { publicKey: 1952, secretKey: 4032, signature: 3309, seed: 32 },
  'ML-DSA-87': { publicKey: 2592, secretKey: 4896, signature: 4627, seed: 32 }
};

var ML_KEM_SIZES = {
  'ML-KEM-512': { publicKey: 800, secretKey: 1632, cipherText: 768,
                  sharedSecret: 32 },
  'ML-KEM-768': { publicKey: 1184, secretKey: 2400, cipherText: 1088,
                  sharedSecret: 32 },
  'ML-KEM-1024': { publicKey: 1568, secretKey: 3168, cipherText: 1568,
                   sharedSecret: 32 }
};

// FIPS 205 Table 2. The SHA2 and SHAKE families of one parameter set have
// identical sizes — the hash function changes, the geometry does not.
var SLH_DSA_SIZES = {
  '128s': { publicKey: 32, secretKey: 64, signature: 7856 },
  '128f': { publicKey: 32, secretKey: 64, signature: 17088 },
  '192s': { publicKey: 48, secretKey: 96, signature: 16224 },
  '192f': { publicKey: 48, secretKey: 96, signature: 35664 },
  '256s': { publicKey: 64, secretKey: 128, signature: 29792 },
  '256f': { publicKey: 64, secretKey: 128, signature: 49856 }
};

function slhSizesFor(name) {
  log.debug("Entering slhSizesFor(). name=" + name);
  var suffix = name.slice(name.lastIndexOf('-') + 1);
  var found = SLH_DSA_SIZES[suffix];
  if (!found) {
    log.debug("Leaving slhSizesFor(). Unknown.");
    throw new Error('No FIPS 205 size row for ' + name + '.');
  }
  log.debug("Leaving slhSizesFor().");
  return found;
}

function mldsaEntry(name, prim) {
  return {
    name: name,
    family: 'ML-DSA',
    jose: name,
    spec: 'FIPS.204',
    joseSpec: 'RFC.9964',
    seeded: true,
    prim: prim,
    keygen: function (seed) {
      log.debug("Entering ML-DSA keygen().");
      var kp = seed ? prim.keygen(asBytes(seed)) : prim.keygen();
      log.debug("Leaving ML-DSA keygen().");
      return { publicKey: kp.publicKey, secretKey: kp.secretKey,
               seed: seed ? asBytes(seed) : null };
    },
    // THE ARGUMENT ORDER HERE IS THE LIBRARY'S, AND IT IS THE REVERSE OF THE
    // ONE THIS MODULE PRESENTS. @noble/post-quantum 0.4.1 takes
    // (key, message) and this registry exposes (message, key), matching the
    // order every other signer in this project uses and the order the
    // library itself moved to in 0.5.0. Normalising here is the whole reason
    // the panes and jws.js do not care which version is installed.
    sign: function (msg, sk, opts) {
      log.debug("Entering ML-DSA sign().");
      var o = opts || {};
      var signer = o.prehash ? prim.prehash(o.prehash) : prim;
      var sig = signer.sign(asBytes(sk), asBytes(msg),
                            o.context ? asBytes(o.context) : EMPTY_CTX);
      log.debug("Leaving ML-DSA sign().");
      return sig;
    },
    verify: function (sig, msg, pk, opts) {
      log.debug("Entering ML-DSA verify().");
      var o = opts || {};
      var signer = o.prehash ? prim.prehash(o.prehash) : prim;
      var ok = signer.verify(asBytes(pk), asBytes(msg), asBytes(sig),
                             o.context ? asBytes(o.context) : EMPTY_CTX);
      log.debug("Leaving ML-DSA verify().");
      return ok;
    },
    lengths: ML_DSA_SIZES[name]
  };
}

function slhEntry(name, prim, joseName) {
  return {
    name: name,
    family: 'SLH-DSA',
    jose: joseName || null,
    spec: 'FIPS.205',
    joseSpec: joseName ? 'I-D.cose-sphincs-plus' : null,
    seeded: false,
    prim: prim,
    keygen: function () {
      log.debug("Entering SLH-DSA keygen().");
      var kp = prim.keygen();
      log.debug("Leaving SLH-DSA keygen().");
      return { publicKey: kp.publicKey, secretKey: kp.secretKey, seed: null };
    },
    // Same reversal as ML-DSA above, for the same reason.
    sign: function (msg, sk, opts) {
      log.debug("Entering SLH-DSA sign().");
      var o = opts || {};
      var signer = o.prehash ? prim.prehash(o.prehash) : prim;
      var sig = signer.sign(asBytes(sk), asBytes(msg),
                            o.context ? asBytes(o.context) : EMPTY_CTX);
      log.debug("Leaving SLH-DSA sign().");
      return sig;
    },
    verify: function (sig, msg, pk, opts) {
      log.debug("Entering SLH-DSA verify().");
      var o = opts || {};
      var signer = o.prehash ? prim.prehash(o.prehash) : prim;
      var ok = signer.verify(asBytes(pk), asBytes(msg), asBytes(sig),
                             o.context ? asBytes(o.context) : EMPTY_CTX);
      log.debug("Leaving SLH-DSA verify().");
      return ok;
    },
    lengths: slhSizesFor(name)
  };
}

// ---------------------------------------------------------------------------
// COMPOSITE ML-DSA  (draft-ietf-jose-pq-composite-sigs-03)
// ---------------------------------------------------------------------------
// The construction, from section 4.2 of that draft, is:
//
//     M'      = Prefix || Label || 0x00 || PH(M)
//     mldsaSig = ML-DSA.Sign(mldsaSK, M', ctx = Label)
//     tradSig  = Trad.Sign(tradSK, M')
//     signature = mldsaSig || tradSig
//
// Three details in there are easy to get wrong and each is worth naming:
//
//  1. THE LABEL IS USED TWICE. It goes into M' as domain separation AND is
//     passed down as the ML-DSA `ctx`. That is deliberate in the draft — the
//     second use binds the component signature to the composite algorithm, so
//     a component signature lifted out of a composite cannot be replayed as a
//     standalone ML-DSA signature.
//  2. THE 0x00 IS A LENGTH, NOT A TERMINATOR. The draft's combiner allows an
//     application context; JOSE requires it to be empty, and the byte encodes
//     that emptiness as a length of zero. It is not a C string ending.
//  3. THE PRE-HASH IS NOT HashML-DSA. Pre-hashing happens at the COMPOSITE
//     level, and the underlying component is therefore PURE ML-DSA. Signing
//     the composite with `prehash` would be a different algorithm.
//
// ONE AMBIGUITY, AND THIS IS WHERE IT IS RECORDED. The draft says the ECDSA
// component uses "the raw fixed-length encodings already defined for ECDSA in
// JOSE (Section 3.4 of [RFC7518] and Section 6.2.1.1 of [RFC7518])", which
// pins the SIGNATURE to R || S but leaves the PUBLIC KEY to be read out of the
// JWK parameter definitions. This implements it as the uncompressed point
// BODY, x || y, with no 0x04 prefix — that being what §6.2.1.1/§6.2.1.2
// define as the two fixed-length parameters. The LAMPS sibling draft uses a
// SEC1 point WITH the prefix, so this is one byte per key of genuine
// divergence between the two documents. If a future revision settles it the
// other way, `tradPublicKey()` is the only function that changes.
var COMPOSITE_PREFIX = strBytes('CompositeAlgorithmSignatures2025');

function shake256_64(msg) {
  log.debug("Entering shake256_64().");
  var out = nobleShake256(asBytes(msg), { dkLen: 64 });
  log.debug("Leaving shake256_64().");
  return out;
}

// The traditional halves, each described by what the composite needs of it:
// the fixed byte lengths (so a concatenated key or signature can be split
// again) and how to sign M'.
var TRAD = {
  'ES256': {
    curve: p256, kind: 'ec', hash: nobleSha256,
    pubLen: 64, privLen: 32, sigLen: 64
  },
  'ES384': {
    curve: p384, kind: 'ec', hash: nobleSha384,
    pubLen: 96, privLen: 48, sigLen: 96
  },
  'Ed25519': {
    curve: ed25519, kind: 'eddsa',
    pubLen: 32, privLen: 32, sigLen: 64
  },
  'Ed448': {
    curve: ed448, kind: 'eddsa',
    pubLen: 57, privLen: 57, sigLen: 114
  }
};

function tradPublicKey(t, priv) {
  log.debug("Entering tradPublicKey().");
  if (t.kind === 'ec') {
    // false = uncompressed, which is 0x04 || x || y. The composite carries
    // x || y, so the prefix comes off — see the ambiguity note above.
    var uncompressed = asBytes(t.curve.getPublicKey(asBytes(priv), false));
    log.debug("Leaving tradPublicKey(). EC.");
    return uncompressed.slice(1);
  }
  log.debug("Leaving tradPublicKey(). EdDSA.");
  return asBytes(t.curve.getPublicKey(asBytes(priv)));
}

function tradSign(t, priv, mPrime) {
  log.debug("Entering tradSign().");
  if (t.kind === 'ec') {
    var sig = t.curve.sign(t.hash(asBytes(mPrime)), asBytes(priv));
    log.debug("Leaving tradSign(). EC.");
    return asBytes(sig.toCompactRawBytes());
  }
  log.debug("Leaving tradSign(). EdDSA.");
  return asBytes(t.curve.sign(asBytes(mPrime), asBytes(priv)));
}

function tradVerify(t, pub, mPrime, sig) {
  log.debug("Entering tradVerify().");
  var ok;
  if (t.kind === 'ec') {
    // Put the 0x04 back on: noble wants a point, and what the composite
    // carries is the body of one.
    var point = concatBytes(new Uint8Array([0x04]), asBytes(pub));
    ok = t.curve.verify(asBytes(sig), t.hash(asBytes(mPrime)), point);
    log.debug("Leaving tradVerify(). EC.");
    return ok;
  }
  ok = t.curve.verify(asBytes(sig), asBytes(mPrime), asBytes(pub));
  log.debug("Leaving tradVerify(). EdDSA.");
  return ok;
}

// Table 2 (pre-hash) and Table 4 (label) of the draft, joined. The label is
// ASCII and is hashed nowhere — it goes into M' as bytes and into ML-DSA as
// the context, both verbatim.
var COMPOSITE_ALGS = {
  'ML-DSA-44-ES256': {
    mldsa: 'ML-DSA-44', trad: 'ES256', ph: nobleSha256,
    label: 'COMPSIG-MLDSA44-ECDSA-P256-SHA256'
  },
  'ML-DSA-65-ES256': {
    mldsa: 'ML-DSA-65', trad: 'ES256', ph: nobleSha512,
    label: 'COMPSIG-MLDSA65-ECDSA-P256-SHA512'
  },
  'ML-DSA-87-ES384': {
    mldsa: 'ML-DSA-87', trad: 'ES384', ph: nobleSha512,
    label: 'COMPSIG-MLDSA87-ECDSA-P384-SHA512'
  },
  'ML-DSA-44-Ed25519': {
    mldsa: 'ML-DSA-44', trad: 'Ed25519', ph: nobleSha512,
    label: 'COMPSIG-MLDSA44-Ed25519-SHA512'
  },
  'ML-DSA-65-Ed25519': {
    mldsa: 'ML-DSA-65', trad: 'Ed25519', ph: nobleSha512,
    label: 'COMPSIG-MLDSA65-Ed25519-SHA512'
  },
  'ML-DSA-87-Ed448': {
    mldsa: 'ML-DSA-87', trad: 'Ed448', ph: shake256_64,
    label: 'COMPSIG-MLDSA87-Ed448-SHAKE256'
  }
};

function compositeMessage(cfg, msg) {
  log.debug("Entering compositeMessage().");
  var out = concatBytes(COMPOSITE_PREFIX, strBytes(cfg.label),
                        new Uint8Array([0x00]), asBytes(cfg.ph(asBytes(msg))));
  log.debug("Leaving compositeMessage().");
  return out;
}

function compositeEntry(name, cfg) {
  var mlPrim = ML_PRIMS[cfg.mldsa];
  var mlSizes = ML_DSA_SIZES[cfg.mldsa];
  var t = TRAD[cfg.trad];
  return {
    name: name,
    family: 'Composite ML-DSA',
    jose: name,
    spec: 'I-D.jose-pq-composite-sigs',
    joseSpec: 'I-D.jose-pq-composite-sigs',
    seeded: true,
    composite: cfg,
    // The composite public key is mldsaPK || tradPK and the private key is
    // the 32-byte ML-DSA SEED || tradSK. The seed rather than the expanded
    // key is what makes the composite private key small, and the draft
    // requires it: "the ML-DSA private key MUST be a 32-bytes seed".
    keygen: function () {
      log.debug("Entering composite keygen().");
      var seed = bytes.randomBytes(32);
      var mlKp = mlPrim.keygen(seed);
      var tradPriv = asBytes(t.curve.utils.randomPrivateKey());
      var tradPub = tradPublicKey(t, tradPriv);
      log.debug("Leaving composite keygen().");
      return {
        publicKey: concatBytes(mlKp.publicKey, tradPub),
        secretKey: concatBytes(seed, tradPriv),
        seed: seed
      };
    },
    sign: function (msg, sk) {
      log.debug("Entering composite sign().");
      var skBytes = asBytes(sk);
      if (skBytes.length !== 32 + t.privLen) {
        log.debug("Leaving composite sign(). Bad key length.");
        throw new Error('A ' + name + ' private key is ' + (32 + t.privLen) +
            ' bytes (a 32-byte ML-DSA seed followed by a ' + t.privLen +
            '-byte ' + cfg.trad + ' key); this one is ' + skBytes.length +
            '.');
      }
      var seed = skBytes.slice(0, 32);
      var tradPriv = skBytes.slice(32);
      var mPrime = compositeMessage(cfg, msg);
      var mlKp = mlPrim.keygen(seed);
      var mlSig = mlPrim.sign(mlKp.secretKey, mPrime, strBytes(cfg.label));
      var tSig = tradSign(t, tradPriv, mPrime);
      log.debug("Leaving composite sign().");
      return concatBytes(mlSig, tSig);
    },
    verify: function (sig, msg, pk) {
      log.debug("Entering composite verify().");
      var sigBytes = asBytes(sig);
      var pkBytes = asBytes(pk);
      var mlSigLen = mlSizes.signature;
      var mlPubLen = mlSizes.publicKey;
      if (sigBytes.length !== mlSigLen + t.sigLen) {
        log.debug("Leaving composite verify(). Bad signature length.");
        return false;
      }
      if (pkBytes.length !== mlPubLen + t.pubLen) {
        log.debug("Leaving composite verify(). Bad key length.");
        return false;
      }
      var mPrime = compositeMessage(cfg, msg);
      // BOTH halves must verify. Returning on the first failure would be
      // correct but would also make the two components' failures
      // indistinguishable in the log, which is the one thing somebody
      // debugging a composite signature actually wants to know.
      var mlOk = mlPrim.verify(pkBytes.slice(0, mlPubLen), mPrime,
                               sigBytes.slice(0, mlSigLen),
                               strBytes(cfg.label));
      var tOk = tradVerify(t, pkBytes.slice(mlPubLen),
                           mPrime, sigBytes.slice(mlSigLen));
      log.debug("Leaving composite verify(). ml=" + mlOk + " trad=" + tOk);
      return mlOk && tOk;
    },
    // Which half failed. The panes call this after a failed verify so the
    // status line can say "the ML-DSA half verified and the ECDSA half did
    // not", which is the difference between a stripped signature and a
    // corrupt one.
    components: function (sig, msg, pk) {
      log.debug("Entering composite components().");
      var sigBytes = asBytes(sig);
      var pkBytes = asBytes(pk);
      var mlSigLen = mlSizes.signature;
      var mlPubLen = mlSizes.publicKey;
      var out = { mldsa: false, trad: false, wellFormed: false };
      if (sigBytes.length !== mlSigLen + t.sigLen ||
          pkBytes.length !== mlPubLen + t.pubLen) {
        log.debug("Leaving composite components(). Malformed.");
        return out;
      }
      out.wellFormed = true;
      var mPrime = compositeMessage(cfg, msg);
      try {
        out.mldsa = mlPrim.verify(pkBytes.slice(0, mlPubLen), mPrime,
                                  sigBytes.slice(0, mlSigLen),
                                  strBytes(cfg.label));
      } catch (e) {
        // A malformed component is a failed component, not an exception the
        // caller has to handle: the whole point of this function is to say
        // which half is bad.
        out.mldsa = false;
      }
      try {
        out.trad = tradVerify(t, pkBytes.slice(mlPubLen), mPrime,
                              sigBytes.slice(mlSigLen));
      } catch (e) {
        // Same reasoning as the ML-DSA half above.
        out.trad = false;
      }
      log.debug("Leaving composite components().");
      return out;
    },
    lengths: {
      publicKey: mlSizes.publicKey + t.pubLen,
      secretKey: 32 + t.privLen,
      signature: mlSizes.signature + t.sigLen,
      seed: 32
    }
  };
}

var ML_PRIMS = {
  'ML-DSA-44': mldsa.ml_dsa44,
  'ML-DSA-65': mldsa.ml_dsa65,
  'ML-DSA-87': mldsa.ml_dsa87
};

// ---------------------------------------------------------------------------
// The registry the panes, jws.js and the tests all read.
// ---------------------------------------------------------------------------
var SIGNATURE_ALGS = {};

(function buildSignatureAlgs() {
  SIGNATURE_ALGS['ML-DSA-44'] = mldsaEntry('ML-DSA-44', mldsa.ml_dsa44);
  SIGNATURE_ALGS['ML-DSA-65'] = mldsaEntry('ML-DSA-65', mldsa.ml_dsa65);
  SIGNATURE_ALGS['ML-DSA-87'] = mldsaEntry('ML-DSA-87', mldsa.ml_dsa87);

  // Only two SLH-DSA parameter sets carry a JOSE name. The other ten are
  // real FIPS 205 algorithms with no envelope binding, and they are in the
  // registry with `jose: null` so the raw pane can offer all twelve while
  // the JWS pane offers exactly the two the draft registers.
  var slhSets = [
    ['SLH-DSA-SHA2-128s', slh.slh_dsa_sha2_128s, 'SLH-DSA-SHA2-128s'],
    ['SLH-DSA-SHA2-128f', slh.slh_dsa_sha2_128f, null],
    ['SLH-DSA-SHA2-192s', slh.slh_dsa_sha2_192s, null],
    ['SLH-DSA-SHA2-192f', slh.slh_dsa_sha2_192f, null],
    ['SLH-DSA-SHA2-256s', slh.slh_dsa_sha2_256s, null],
    ['SLH-DSA-SHA2-256f', slh.slh_dsa_sha2_256f, null],
    ['SLH-DSA-SHAKE-128s', slh.slh_dsa_shake_128s, 'SLH-DSA-SHAKE-128s'],
    ['SLH-DSA-SHAKE-128f', slh.slh_dsa_shake_128f, null],
    ['SLH-DSA-SHAKE-192s', slh.slh_dsa_shake_192s, null],
    ['SLH-DSA-SHAKE-192f', slh.slh_dsa_shake_192f, null],
    ['SLH-DSA-SHAKE-256s', slh.slh_dsa_shake_256s, null],
    ['SLH-DSA-SHAKE-256f', slh.slh_dsa_shake_256f, null]
  ];
  for (var i = 0; i < slhSets.length; i++) {
    SIGNATURE_ALGS[slhSets[i][0]] =
      slhEntry(slhSets[i][0], slhSets[i][1], slhSets[i][2]);
  }

  var compNames = Object.keys(COMPOSITE_ALGS);
  for (var j = 0; j < compNames.length; j++) {
    SIGNATURE_ALGS[compNames[j]] =
      compositeEntry(compNames[j], COMPOSITE_ALGS[compNames[j]]);
  }
})();

function signatureAlg(name) {
  log.debug("Entering signatureAlg(). name=" + name);
  var found = SIGNATURE_ALGS[name];
  if (!found) {
    log.debug("Leaving signatureAlg(). Unknown.");
    throw new Error('Unknown post-quantum signature algorithm: ' + name);
  }
  log.debug("Leaving signatureAlg().");
  return found;
}

// The JOSE-registered subset, in the order the dropdowns show them.
function joseSignatureAlgs() {
  log.debug("Entering joseSignatureAlgs().");
  var names = Object.keys(SIGNATURE_ALGS);
  var out = [];
  for (var i = 0; i < names.length; i++) {
    if (SIGNATURE_ALGS[names[i]].jose) {
      out.push(names[i]);
    }
  }
  log.debug("Leaving joseSignatureAlgs().");
  return out;
}


// ===========================================================================
// KEY ENCAPSULATION
// ===========================================================================
// Three kinds live here and the difference between them is the whole reason
// the registry carries a `spec`:
//
//   * ML-KEM itself — FIPS 203, a published standard.
//   * X-Wing — draft-connolly-cfrg-xwing-kem, a CFRG draft with published
//     TEST VECTORS, which tests/pqc_engines.js checks this implementation
//     against. A hybrid whose combiner is frozen.
//   * Composite ML-KEM — draft-ietf-lamps-pq-composite-kem-08, which defines
//     concrete pairings with a concrete combiner and a per-algorithm label.
//
// WHAT IS NOT HERE, AND WHY, because it is the case that looks most like an
// oversight: the "QSF" presets that ship in @noble/post-quantum
// (`QSF_ml_kem768_p256` and friends) are NOT used, even though they are
// exactly the pairing somebody would reach for. draft-irtf-cfrg-hybrid-kems
// defines the QSF *frameworks* but its "Hybrid KEM Labels" registry is
// explicitly created EMPTY — there is not one registered concrete
// instantiation in it — so the label those presets hash
// (`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)`) is the library's
// own invention rather than anybody's wire format. Two implementations
// following that draft would not interoperate, because the draft does not yet
// say what to put in the hash. The ML-KEM + P-256 pairing IS available here —
// under Composite ML-KEM, where a draft does name the label.
//
// THERE IS NO ML-KEM BINDING FOR JWE, AND THAT IS A FACT ABOUT THE DRAFTS
// RATHER THAN A GAP HERE. draft-ietf-jose-pqc-kem-06 is named for the JOSE
// working group and its running header reads "PQ KEM for COSE": every binding
// section in it (§6 "Post-Quantum KEM in COSE", §7 "COSE Ciphersuite
// Registration", §8 "Use of AKP Key Type for PQC KEM Keys in COSE", and the
// whole of its IANA section) registers COSE codepoints, and the words "JOSE"
// appear in it three times — twice in its own filename and once in a citation
// of RFC 9964's title. Its KDF section reads "The key derivation for COSE is
// performed using KMAC". So there is currently no specified `alg` value, no
// specified header parameter and no specified KDF context for ML-KEM in a
// JWE, and this module deliberately does not invent one. jose_jwe.js says so
// on the page instead.

var mlkemCurves = {
  'P-256': { curve: p256, kind: 'ec', ssLen: 32 },
  'P-384': { curve: p384, kind: 'ec', ssLen: 48 },
  'P-521': { curve: p521, kind: 'ec', ssLen: 66 },
  'X25519': { curve: x25519, kind: 'montgomery', ssLen: 32 },
  'X448': { curve: x448, kind: 'montgomery', ssLen: 56 }
};

// The traditional half, promoted from a key agreement into a KEM exactly as
// section 3.2 of the composite draft does it: the sender makes an ephemeral
// key pair, the ciphertext IS the ephemeral public key, and the shared secret
// is the raw Diffie-Hellman output. Note this is the SIMPLIFIED DHKEM the
// draft specifies — RFC 9180's real DHKEM runs the result through
// ExtractAndExpand, and this one does not, because the composite combiner
// does the hashing.
function tradKemEncap(c, recipientPub) {
  log.debug("Entering tradKemEncap().");
  var out;
  if (c.kind === 'ec') {
    var eph = c.curve.utils.randomPrivateKey();
    // getSharedSecret returns a point; the DH output for these curves is the
    // x-coordinate alone, which is what SEC 1 and SP 800-56A call Z. The
    // leading byte is the point-format prefix, so it comes off.
    var shared = asBytes(c.curve.getSharedSecret(eph, asBytes(recipientPub)));
    out = {
      sharedSecret: shared.slice(1, 1 + c.ssLen),
      cipherText: asBytes(c.curve.getPublicKey(eph, false))
    };
    log.debug("Leaving tradKemEncap(). EC.");
    return out;
  }
  // X25519/X448 private keys are just random bytes of the curve's length.
  var ephM = bytes.randomBytes(c.ssLen);
  out = {
    sharedSecret: asBytes(c.curve.getSharedSecret(ephM, asBytes(recipientPub))),
    cipherText: asBytes(c.curve.getPublicKey(ephM))
  };
  log.debug("Leaving tradKemEncap(). Montgomery.");
  return out;
}

function tradKemDecap(c, cipherText, recipientPriv) {
  log.debug("Entering tradKemDecap().");
  var shared;
  if (c.kind === 'ec') {
    shared = asBytes(c.curve.getSharedSecret(asBytes(recipientPriv),
                                             asBytes(cipherText)));
    log.debug("Leaving tradKemDecap(). EC.");
    return shared.slice(1, 1 + c.ssLen);
  }
  shared = asBytes(c.curve.getSharedSecret(asBytes(recipientPriv),
                                           asBytes(cipherText)));
  log.debug("Leaving tradKemDecap(). Montgomery.");
  return shared;
}

// Section 4.4: ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label).
// The label is what stops two different composite algorithms deriving the same
// secret from the same inputs, which is why it is per-algorithm and not a
// constant.
function kemCombiner(mlkemSS, tradSS, tradCT, tradPK, label) {
  log.debug("Entering kemCombiner().");
  var out = nobleSha3_256(concatBytes(asBytes(mlkemSS), asBytes(tradSS),
                                      asBytes(tradCT), asBytes(tradPK),
                                      strBytes(label)));
  log.debug("Leaving kemCombiner().");
  return out;
}

// The concrete algorithms of section 7. Every one of these carries the LABEL
// the draft assigns it; nothing here is named by this project.
var COMPOSITE_KEMS = {
  'MLKEM768-ECDH-P256': {
    mlkem: mlkem.ml_kem768, mlkemName: 'ML-KEM-768', curve: 'P-256',
    label: 'QSF-MLKEM768-P256-SHA3256',
    oid: '2.16.840.1.114027.80.5.2.66'
  },
  'MLKEM768-ECDH-P384': {
    mlkem: mlkem.ml_kem768, mlkemName: 'ML-KEM-768', curve: 'P-384',
    label: 'QSF-MLKEM768-P384-SHA3256',
    oid: '2.16.840.1.114027.80.5.2.67'
  },
  'MLKEM768-X25519': {
    mlkem: mlkem.ml_kem768, mlkemName: 'ML-KEM-768', curve: 'X25519',
    // Six bytes, 5c 2e 2f 2f 5e 5c. The draft gives the hex because the
    // string is almost impossible to read: backslash, dot, slash, slash,
    // caret, backslash. It is X-Wing's label, deliberately — this composite
    // algorithm and X-Wing derive their shared secret identically.
    label: '\\.//^\\',
    oid: '2.16.840.1.114027.80.5.2.65'
  },
  'MLKEM1024-ECDH-P384': {
    mlkem: mlkem.ml_kem1024, mlkemName: 'ML-KEM-1024', curve: 'P-384',
    label: 'QSF-MLKEM1024-P384-SHA3256',
    oid: '2.16.840.1.114027.80.5.2.69'
  },
  'MLKEM1024-ECDH-P521': {
    mlkem: mlkem.ml_kem1024, mlkemName: 'ML-KEM-1024', curve: 'P-521',
    label: 'QSF-MLKEM1024-P521-SHA3256',
    oid: '2.16.840.1.114027.80.5.2.72'
  },
  'MLKEM1024-X448': {
    mlkem: mlkem.ml_kem1024, mlkemName: 'ML-KEM-1024', curve: 'X448',
    label: 'QSF-MLKEM1024-X448-SHA3256',
    oid: '2.16.840.1.114027.80.5.2.71'
  }
};

function compositeKemEntry(name, cfg) {
  var c = mlkemCurves[cfg.curve];
  var mlSizes = ML_KEM_SIZES[cfg.mlkemName];
  var tradPubLen = c.kind === 'ec'
    ? 1 + 2 * (cfg.curve === 'P-256' ? 32 : cfg.curve === 'P-384' ? 48 : 66)
    : c.ssLen;
  var tradPrivLen = c.ssLen;
  return {
    name: name,
    family: 'Composite ML-KEM',
    spec: 'I-D.lamps-composite-kem',
    hybrid: true,
    label: cfg.label,
    oid: cfg.oid,
    keygen: function () {
      log.debug("Entering composite KEM keygen().");
      var mlKp = cfg.mlkem.keygen();
      var tradPriv = c.kind === 'ec'
        ? asBytes(c.curve.utils.randomPrivateKey())
        : bytes.randomBytes(c.ssLen);
      var tradPub = c.kind === 'ec'
        ? asBytes(c.curve.getPublicKey(tradPriv, false))
        : asBytes(c.curve.getPublicKey(tradPriv));
      log.debug("Leaving composite KEM keygen().");
      return {
        publicKey: concatBytes(mlKp.publicKey, tradPub),
        secretKey: concatBytes(mlKp.secretKey, tradPriv)
      };
    },
    encapsulate: function (pk) {
      log.debug("Entering composite KEM encapsulate().");
      var pkBytes = asBytes(pk);
      var mlPubLen = mlSizes.publicKey;
      if (pkBytes.length !== mlPubLen + tradPubLen) {
        log.debug("Leaving composite KEM encapsulate(). Bad key length.");
        throw new Error('A ' + name + ' public key is ' +
            (mlPubLen + tradPubLen) + ' bytes; this one is ' +
            pkBytes.length + '.');
      }
      var mlPub = pkBytes.slice(0, mlPubLen);
      var tradPub = pkBytes.slice(mlPubLen);
      var mlEnc = cfg.mlkem.encapsulate(mlPub);
      var tradEnc = tradKemEncap(c, tradPub);
      log.debug("Leaving composite KEM encapsulate().");
      return {
        cipherText: concatBytes(mlEnc.cipherText, tradEnc.cipherText),
        sharedSecret: kemCombiner(mlEnc.sharedSecret, tradEnc.sharedSecret,
                                  tradEnc.cipherText, tradPub, cfg.label)
      };
    },
    decapsulate: function (ct, sk) {
      log.debug("Entering composite KEM decapsulate().");
      var ctBytes = asBytes(ct);
      var skBytes = asBytes(sk);
      var mlCtLen = mlSizes.cipherText;
      var mlSkLen = mlSizes.secretKey;
      if (ctBytes.length !== mlCtLen + tradPubLen) {
        log.debug("Leaving composite KEM decapsulate(). Bad ciphertext.");
        throw new Error('A ' + name + ' ciphertext is ' +
            (mlCtLen + tradPubLen) + ' bytes; this one is ' +
            ctBytes.length + '.');
      }
      if (skBytes.length !== mlSkLen + tradPrivLen) {
        log.debug("Leaving composite KEM decapsulate(). Bad key length.");
        throw new Error('A ' + name + ' private key is ' +
            (mlSkLen + tradPrivLen) + ' bytes; this one is ' +
            skBytes.length + '.');
      }
      var mlSs = cfg.mlkem.decapsulate(ctBytes.slice(0, mlCtLen),
                                       skBytes.slice(0, mlSkLen));
      var tradCt = ctBytes.slice(mlCtLen);
      var tradPriv = skBytes.slice(mlSkLen);
      var tradSs = tradKemDecap(c, tradCt, tradPriv);
      // The combiner needs the RECIPIENT's traditional public key, which the
      // decapsulator holds only as a private key — so it is re-derived here.
      // Getting this wrong is the classic composite-KEM bug: the two sides
      // hash different `tradPK` and the secrets silently disagree.
      var tradPub = c.kind === 'ec'
        ? asBytes(c.curve.getPublicKey(tradPriv, false))
        : asBytes(c.curve.getPublicKey(tradPriv));
      log.debug("Leaving composite KEM decapsulate().");
      return kemCombiner(mlSs, tradSs, tradCt, tradPub, cfg.label);
    },
    lengths: {
      publicKey: mlSizes.publicKey + tradPubLen,
      secretKey: mlSizes.secretKey + tradPrivLen,
      cipherText: mlSizes.cipherText + tradPubLen,
      sharedSecret: 32
    }
  };
}

// ---------------------------------------------------------------------------
// X-WING  (draft-connolly-cfrg-xwing-kem)
// ---------------------------------------------------------------------------
// Implemented here from the draft's own pseudocode rather than taken from a
// library preset, because the library that ships one is ESM-only and this
// build cannot load it (see the module header). That would normally be a
// reason for caution — a hand-rolled KEM is exactly the thing to distrust —
// except that this one is checked against ALL THREE of the draft's published
// test vectors, in tests/pqc_engines.js, for the public key, the ciphertext
// and the shared secret. A vector match is a stronger statement about
// correctness than "it came from a package", and it is the reason this is
// acceptable where inventing HQC would not be: the answer is written down.
//
// The construction, from sections 5 and 6 of the draft:
//
//   expandDecapsulationKey(sk):
//     expanded = SHAKE256(sk, 96)
//     (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
//     sk_X = expanded[64:96];  pk_X = X25519(sk_X, base)
//
//   Combiner(ss_M, ss_X, ct_X, pk_X) =
//     SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
//
// TWO DETAILS ARE EASY TO GET WRONG AND BOTH ARE INVISIBLE TO A ROUND TRIP.
// The expansion is SHAKE**256**, not SHAKE128 — an early reading of this got
// that backwards and produced a perfectly self-consistent KEM that agreed
// with nothing. And the label is SIX BYTES of almost pure punctuation,
// 5c 2e 2f 2f 5e 5c, which is `\.//^\` — in a JavaScript string literal each
// backslash has to be doubled, and getting that wrong silently shortens the
// label rather than failing.
//
// The 32-byte secret key IS the seed: X-Wing expands it on every use rather
// than storing the component keys, which is what makes its private key so
// much smaller than the composite KEMs' below.
var XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
var XWING_CT_ML = 1088;

function xwingExpand(seed) {
  log.debug("Entering xwingExpand().");
  var seedBytes = asBytes(seed);
  if (seedBytes.length !== 32) {
    log.debug("Leaving xwingExpand(). Bad seed length.");
    throw new Error('An X-Wing private key is the 32-byte seed; this one is ' +
                    seedBytes.length + ' bytes.');
  }
  var expanded = nobleShake256(seedBytes, { dkLen: 96 });
  // ML-KEM's KeyGen_internal takes d || z, which is exactly the first 64
  // bytes — noble's keygen() accepts that pair as one 64-byte seed.
  var mlKp = mlkem.ml_kem768.keygen(expanded.slice(0, 64));
  var skX = expanded.slice(64, 96);
  log.debug("Leaving xwingExpand().");
  return { skM: mlKp.secretKey, pkM: mlKp.publicKey,
           skX: skX, pkX: asBytes(x25519.getPublicKey(skX)) };
}

function xwingCombiner(ssM, ssX, ctX, pkX) {
  log.debug("Entering xwingCombiner().");
  var out = nobleSha3_256(concatBytes(asBytes(ssM), asBytes(ssX),
                                      asBytes(ctX), asBytes(pkX),
                                      XWING_LABEL));
  log.debug("Leaving xwingCombiner().");
  return out;
}

var xwing = {
  name: 'X-Wing', family: 'X-Wing', spec: 'I-D.xwing', hybrid: true,
  seeded: true,
  keygen: function (seed) {
    log.debug("Entering X-Wing keygen().");
    var sk = seed ? asBytes(seed) : bytes.randomBytes(32);
    var parts = xwingExpand(sk);
    log.debug("Leaving X-Wing keygen().");
    return { secretKey: sk, publicKey: concatBytes(parts.pkM, parts.pkX) };
  },
  // `eseed` is the 64-byte encapsulation seed the draft's EncapsulateDerand
  // takes. It exists so the test vectors can be reproduced; ordinary callers
  // omit it and get fresh randomness.
  encapsulate: function (pk, eseed) {
    log.debug("Entering X-Wing encapsulate().");
    var pkBytes = asBytes(pk);
    var mlPubLen = ML_KEM_SIZES['ML-KEM-768'].publicKey;
    if (pkBytes.length !== mlPubLen + 32) {
      log.debug("Leaving X-Wing encapsulate(). Bad key length.");
      throw new Error('An X-Wing public key is ' + (mlPubLen + 32) +
                      ' bytes; this one is ' + pkBytes.length + '.');
    }
    var pkM = pkBytes.slice(0, mlPubLen);
    var pkX = pkBytes.slice(mlPubLen);
    var seedBytes = eseed ? asBytes(eseed) : bytes.randomBytes(64);
    if (seedBytes.length !== 64) {
      log.debug("Leaving X-Wing encapsulate(). Bad eseed length.");
      throw new Error('An X-Wing encapsulation seed is 64 bytes; this one ' +
                      'is ' + seedBytes.length + '.');
    }
    var ekX = seedBytes.slice(32, 64);
    var ctX = asBytes(x25519.getPublicKey(ekX));
    var ssX = asBytes(x25519.getSharedSecret(ekX, pkX));
    var enc = mlkem.ml_kem768.encapsulate(pkM, seedBytes.slice(0, 32));
    log.debug("Leaving X-Wing encapsulate().");
    return {
      cipherText: concatBytes(asBytes(enc.cipherText), ctX),
      sharedSecret: xwingCombiner(enc.sharedSecret, ssX, ctX, pkX)
    };
  },
  decapsulate: function (ct, sk) {
    log.debug("Entering X-Wing decapsulate().");
    var ctBytes = asBytes(ct);
    if (ctBytes.length !== XWING_CT_ML + 32) {
      log.debug("Leaving X-Wing decapsulate(). Bad ciphertext length.");
      throw new Error('An X-Wing ciphertext is ' + (XWING_CT_ML + 32) +
                      ' bytes; this one is ' + ctBytes.length + '.');
    }
    var parts = xwingExpand(sk);
    var ctM = ctBytes.slice(0, XWING_CT_ML);
    var ctX = ctBytes.slice(XWING_CT_ML);
    var ssM = asBytes(mlkem.ml_kem768.decapsulate(ctM, parts.skM));
    var ssX = asBytes(x25519.getSharedSecret(parts.skX, ctX));
    log.debug("Leaving X-Wing decapsulate().");
    return xwingCombiner(ssM, ssX, ctX, parts.pkX);
  },
  lengths: { seed: 32, secretKey: 32,
             publicKey: ML_KEM_SIZES['ML-KEM-768'].publicKey + 32,
             cipherText: XWING_CT_ML + 32, sharedSecret: 32 }
};

var KEM_ALGS = {};

(function buildKems() {
  KEM_ALGS['ML-KEM-512'] = {
    name: 'ML-KEM-512', family: 'ML-KEM', spec: 'FIPS.203', hybrid: false,
    keygen: function () { return mlkem.ml_kem512.keygen(); },
    encapsulate: function (pk) { return mlkem.ml_kem512.encapsulate(asBytes(pk)); },
    decapsulate: function (ct, sk) {
      return mlkem.ml_kem512.decapsulate(asBytes(ct), asBytes(sk));
    },
    lengths: ML_KEM_SIZES['ML-KEM-512']
  };
  KEM_ALGS['ML-KEM-768'] = {
    name: 'ML-KEM-768', family: 'ML-KEM', spec: 'FIPS.203', hybrid: false,
    keygen: function () { return mlkem.ml_kem768.keygen(); },
    encapsulate: function (pk) { return mlkem.ml_kem768.encapsulate(asBytes(pk)); },
    decapsulate: function (ct, sk) {
      return mlkem.ml_kem768.decapsulate(asBytes(ct), asBytes(sk));
    },
    lengths: ML_KEM_SIZES['ML-KEM-768']
  };
  KEM_ALGS['ML-KEM-1024'] = {
    name: 'ML-KEM-1024', family: 'ML-KEM', spec: 'FIPS.203', hybrid: false,
    keygen: function () { return mlkem.ml_kem1024.keygen(); },
    encapsulate: function (pk) { return mlkem.ml_kem1024.encapsulate(asBytes(pk)); },
    decapsulate: function (ct, sk) {
      return mlkem.ml_kem1024.decapsulate(asBytes(ct), asBytes(sk));
    },
    lengths: ML_KEM_SIZES['ML-KEM-1024']
  };

  KEM_ALGS['X-Wing'] = xwing;

  var compNames = Object.keys(COMPOSITE_KEMS);
  for (var i = 0; i < compNames.length; i++) {
    KEM_ALGS[compNames[i]] =
      compositeKemEntry(compNames[i], COMPOSITE_KEMS[compNames[i]]);
  }
})();

function kemAlg(name) {
  log.debug("Entering kemAlg(). name=" + name);
  var found = KEM_ALGS[name];
  if (!found) {
    log.debug("Leaving kemAlg(). Unknown.");
    throw new Error('Unknown post-quantum KEM: ' + name);
  }
  log.debug("Leaving kemAlg().");
  return found;
}



// ---------------------------------------------------------------------------
// PRE-HASH (HashML-DSA, FIPS 204 §5.4 — and HashSLH-DSA, FIPS 205 §10.2.2)
// ---------------------------------------------------------------------------
// The pre-hash variants sign H(M) rather than M, and FIPS 204 §5.4 puts the
// hash function's DER-encoded OID into the formatted message M' so that two
// different pre-hashes can never produce the same signed bytes.
//
// THE LIBRARY OWNS THOSE OIDs, which is worth saying because an earlier draft
// of this module encoded them by hand. @noble/post-quantum 0.4.1 carries its
// own table keyed by hash name — with the OIDs from NIST's algorithm
// registry, and with SHAKE-128 at a 256-bit output and SHAKE-256 at 512-bit,
// which are the lengths FIPS 204 §5.4 requires and NOT the libraries'
// defaults. So this table maps the names this page shows onto the names that
// library uses, and encodes nothing itself. The mapping is the only thing
// that can be wrong here, and it is wrong loudly: an unknown name throws.
var PREHASHES = {
  'SHA-256': 'SHA2-256',
  'SHA-384': 'SHA2-384',
  'SHA-512': 'SHA2-512',
  'SHA3-256': 'SHA3-256',
  'SHA3-512': 'SHA3-512',
  'SHAKE128': 'SHAKE-128',
  'SHAKE256': 'SHAKE-256'
};

function prehashNames() {
  log.debug("Entering prehashNames().");
  log.debug("Leaving prehashNames().");
  return Object.keys(PREHASHES);
}

// Returns the library's own name for the hash, which is what the signer
// wants. It is deliberately not a hash FUNCTION: on this version the caller
// never hashes anything itself, because doing so would lose the OID.
function prehash(name) {
  log.debug("Entering prehash(). name=" + name);
  var found = PREHASHES[name];
  if (!found) {
    log.debug("Leaving prehash(). Unknown.");
    throw new Error('Unknown pre-hash algorithm: ' + name + '. Known: ' +
                    Object.keys(PREHASHES).join(', ') + '.');
  }
  log.debug("Leaving prehash().");
  return found;
}

// ---------------------------------------------------------------------------
// SIGNING FROM AN AKP `priv`, WHICH IS NOT ALWAYS THE SIGNING KEY
// ---------------------------------------------------------------------------
// These two functions exist so that every caller — the panes, jws.js, the
// tests — can hold ONE private-key representation: exactly the bytes that go
// into an AKP JWK's `priv` parameter. That is not the same thing as the bytes
// the signing primitive wants, and the difference is per family:
//
//   ML-DSA     `priv` is the 32-byte SEED (RFC 9964 §3.2 makes that a MUST).
//              The primitive wants the 2560/4032/4896-byte expanded key, so
//              it is re-derived with keygen(seed) on every call. That costs
//              well under a millisecond and it is the only way a JWK this
//              page emits can be read by anything else.
//   Composite  `priv` is seed || tradSK, and the composite signer already
//              splits it — the same reasoning, one level up.
//   SLH-DSA    `priv` IS the private key; FIPS 205 has no separate seed to
//              carry, so there is nothing to re-derive.
//   FN-DSA     the same.
//
// Getting this wrong is silent in one direction and loud in the other: an
// expanded ML-DSA key written into `priv` produces a JWK that this page can
// read back and no conforming implementation can, which is precisely the bug
// the old `x`/`d` export had.
function signWithPriv(algName, msg, priv, opts) {
  log.debug("Entering signWithPriv(). alg=" + algName);
  var entry = signatureAlg(algName);
  var privBytes = asBytes(priv);
  if (entry.family === 'ML-DSA') {
    if (privBytes.length !== 32) {
      log.debug("Leaving signWithPriv(). Bad seed length.");
      throw new Error('An ML-DSA "priv" is the 32-byte seed (RFC 9964 ' +
          'section 3.2); this one is ' + privBytes.length + ' bytes.');
    }
    var kp = entry.prim.keygen(privBytes);
    var sig = entry.sign(msg, kp.secretKey, opts);
    log.debug("Leaving signWithPriv(). ML-DSA.");
    return sig;
  }
  log.debug("Leaving signWithPriv().");
  return entry.sign(msg, privBytes, opts);
}

// The public half needs no such treatment — `pub` is the public key for every
// family here — but this wrapper keeps the two calls symmetrical at the call
// sites, which is worth more than the one line it saves.
function verifyWithPub(algName, sig, msg, pub, opts) {
  log.debug("Entering verifyWithPub(). alg=" + algName);
  var ok = signatureAlg(algName).verify(sig, msg, asBytes(pub), opts);
  log.debug("Leaving verifyWithPub().");
  return ok;
}

// Generate a key pair in the AKP representation: `pub` is the public key and
// `priv` is whatever that algorithm's AKP `priv` parameter holds.
function generateAkpKeyPair(algName) {
  log.debug("Entering generateAkpKeyPair(). alg=" + algName);
  var entry = signatureAlg(algName);
  var kp;
  if (entry.family === 'ML-DSA') {
    var seed = bytes.randomBytes(32);
    kp = entry.prim.keygen(seed);
    log.debug("Leaving generateAkpKeyPair(). ML-DSA.");
    return { pub: kp.publicKey, priv: seed };
  }
  kp = entry.keygen();
  log.debug("Leaving generateAkpKeyPair().");
  return { pub: kp.publicKey, priv: kp.secretKey };
}

module.exports = {
  SPECS: SPECS,
  MISSING: MISSING,
  spec: spec,
  specNote: specNote,
  isDraft: isDraft,
  akpPublicJwk: akpPublicJwk,
  akpPrivateJwk: akpPrivateJwk,
  akpImport: akpImport,
  SIGNATURE_ALGS: SIGNATURE_ALGS,
  signatureAlg: signatureAlg,
  signWithPriv: signWithPriv,
  verifyWithPub: verifyWithPub,
  generateAkpKeyPair: generateAkpKeyPair,
  PREHASHES: PREHASHES,
  prehashNames: prehashNames,
  prehash: prehash,
  joseSignatureAlgs: joseSignatureAlgs,
  COMPOSITE_ALGS: COMPOSITE_ALGS,
  KEM_ALGS: KEM_ALGS,
  kemAlg: kemAlg,
  COMPOSITE_KEMS: COMPOSITE_KEMS,
  kemCombiner: kemCombiner,
  compositeMessage: compositeMessage,
  COMPOSITE_PREFIX: COMPOSITE_PREFIX,
  TRAD: TRAD
};
