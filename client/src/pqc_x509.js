// File: pqc_x509.js
//
// ---------------------------------------------------------------------------
// POST-QUANTUM KEYS AND SIGNATURES *AS X.509 SEES THEM*.
//
// `pqc.js` is the algorithms; this is the PKIX binding of them, and the two
// are separate files because the same algorithm is a different set of BYTES in
// the two worlds. A JOSE ML-DSA key is an AKP JWK whose `pub` is base64url; an
// X.509 one is a SubjectPublicKeyInfo whose BIT STRING is the same octets with
// no wrapping at all. Nothing about ML-DSA changes between them, and every
// byte around it does.
//
// FOUR DOCUMENTS DEFINE WHAT IS IN HERE, AND THREE OF THEM ARE PUBLISHED:
//
//   * RFC 9881 — ML-DSA in X.509. Three signature algorithms, three public key
//     algorithms, one private key CHOICE with three arms (below).
//   * RFC 9909 — SLH-DSA in X.509. Twelve parameter sets, and both halves of
//     the key are raw octets: "-- KEY no ASN.1 wrapping --".
//   * RFC 9935 — ML-KEM in X.509. A KEM has no signature, so these appear here
//     only as a SUBJECT key: a certificate that certifies a key-establishment
//     key, which is what a post-quantum encryption certificate is.
//   * draft-ietf-lamps-pq-composite-sigs-19 — Composite ML-DSA. STILL A DRAFT,
//     in the RFC Editor queue at the time of writing, and every label this
//     module produces for one says so with the revision number, because
//     "implements the composite draft" without a revision is the claim that
//     ages worst.
//
// ---------------------------------------------------------------------------
// THE PRIVATE KEY IS A CHOICE, AND WHICH ARM YOU WRITE IS INTEROPERABILITY
//
// RFC 9881 section 6 gives ML-DSA private keys three encodings inside the
// OneAsymmetricKey `privateKey` OCTET STRING:
//
//     ML-DSA-44-PrivateKey ::= CHOICE {
//       seed [0] OCTET STRING (SIZE (32)),
//       expandedKey OCTET STRING (SIZE (2560)),
//       both SEQUENCE { seed OCTET STRING (SIZE (32)),
//                       expandedKey OCTET STRING (SIZE (2560)) } }
//
// The RFC RECOMMENDS `seed`, and OpenSSL 3.5 writes `both`. This module writes
// `seed` by default and READS ALL THREE, which is the only combination that is
// both conformant and able to open what the most widely deployed producer
// emits. `encodePkcs8()` takes the arm as an option so the page can show what
// each one looks like — that difference is the sort of thing a debugger exists
// to make visible. ML-KEM (RFC 9935) has the identical CHOICE with a 64-byte
// seed; SLH-DSA has no CHOICE at all, only raw octets.
//
// ---------------------------------------------------------------------------
// COMPOSITE: THE SAME CONSTRUCTION AS pqc.js, THREE DIFFERENT ENCODINGS
//
// The message representative is identical — M' = Prefix || Label || len(ctx)
// || ctx || PH(M), with the Label passed down as the ML-DSA context — and the
// labels in this table are the same strings pqc.js carries. What differs is
// how the TRADITIONAL component is written down, and all three differences are
// one-line changes that produce a signature nothing else will verify:
//
//   1. the ECDSA public key keeps its 0x04 uncompressed prefix here and loses
//      it in JOSE (section 4 of the draft against RFC 7518 section 6.2.1);
//   2. the ECDSA signature is a DER Ecdsa-Sig-Value here and fixed-width
//      r || s in JOSE;
//   3. the RSA components exist here and not in JOSE at all.
//
// So this module implements the composite from the draft directly rather than
// calling pqc.js's version, and tests/pki_pqc_x509.js holds the two apart by
// asserting that a composite certificate verifies with OpenSSL 3.5 while the
// JOSE encoding of the same key does not appear anywhere in it.
//
// TWO COMPOSITE ALGORITHMS ARE DELIBERATELY ABSENT and it is the same rule the
// rest of this tree follows: id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 and
// id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 need the brainpool curves, which are
// in no library in this dependency tree and in no browser. Implementing them
// from the parameters would mean writing a curve, and a curve that is wrong is
// wrong silently. The other sixteen are all here.
//
// NO DOM, and no Web Crypto except where an RSA composite forces it — which is
// why every pure post-quantum path in this file works on a plain-HTTP origin
// where `crypto.subtle` does not exist. tests/pki_pqc_x509.js drives all of it
// in node and hands the result to OpenSSL 3.5 through node's own crypto, which
// is the only implementation in reach that knows these algorithms.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var asn1js = require("asn1js");
var pqc = require("./pqc");
var bytes = require("./crypto_bytes");
var mlkem = require("@noble/post-quantum/ml-kem.js");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var ed448 = require("@noble/curves/ed448").ed448;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha384 = require("@noble/hashes/sha512").sha384;
var nobleSha512 = require("@noble/hashes/sha512").sha512;
var nobleShake256 = require("@noble/hashes/sha3").shake256;

var log = bunyan.createLogger({
  name: "pqc_x509",
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

// ---------------------------------------------------------------------------
// The OIDs.
//
// ML-DSA and SLH-DSA use ONE identifier for the key and for the signature —
// there is no hash to name beside it, which is the whole point of a signature
// scheme that does its own hashing — so a single table serves both fields.
// ML-KEM's identifiers can only ever appear in a SubjectPublicKeyInfo.
// ---------------------------------------------------------------------------
var SIG_OIDS = {
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
  'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
  'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
  'SLH-DSA-SHA2-128s': '2.16.840.1.101.3.4.3.20',
  'SLH-DSA-SHA2-128f': '2.16.840.1.101.3.4.3.21',
  'SLH-DSA-SHA2-192s': '2.16.840.1.101.3.4.3.22',
  'SLH-DSA-SHA2-192f': '2.16.840.1.101.3.4.3.23',
  'SLH-DSA-SHA2-256s': '2.16.840.1.101.3.4.3.24',
  'SLH-DSA-SHA2-256f': '2.16.840.1.101.3.4.3.25',
  'SLH-DSA-SHAKE-128s': '2.16.840.1.101.3.4.3.26',
  'SLH-DSA-SHAKE-128f': '2.16.840.1.101.3.4.3.27',
  'SLH-DSA-SHAKE-192s': '2.16.840.1.101.3.4.3.28',
  'SLH-DSA-SHAKE-192f': '2.16.840.1.101.3.4.3.29',
  'SLH-DSA-SHAKE-256s': '2.16.840.1.101.3.4.3.30',
  'SLH-DSA-SHAKE-256f': '2.16.840.1.101.3.4.3.31'
};

var KEM_OIDS = {
  'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
  'ML-KEM-768': '2.16.840.1.101.3.4.4.2',
  'ML-KEM-1024': '2.16.840.1.101.3.4.4.3'
};

// FIPS 203 Table 3, the two lengths this module has to know: the public key,
// so a SubjectPublicKeyInfo can be checked rather than trusted, and the seed,
// which is the (d || z) pair RFC 9935's `seed` arm carries.
var KEM_SIZES = {
  'ML-KEM-512': { publicKey: 800, secretKey: 1632, seed: 64,
                 prim: mlkem.ml_kem512 },
  'ML-KEM-768': { publicKey: 1184, secretKey: 2400, seed: 64,
                 prim: mlkem.ml_kem768 },
  'ML-KEM-1024': { publicKey: 1568, secretKey: 3168, seed: 64,
                  prim: mlkem.ml_kem1024 }
};

// ---------------------------------------------------------------------------
// The traditional halves of a composite, in their X.509 spellings.
//
// `sigHash` is NOT always the pre-hash: id-MLDSA65-RSA3072-PSS-SHA512
// pre-hashes with SHA-512 and instantiates RSASSA-PSS with SHA-256, because
// the draft fixes the PSS parameters per RSA SIZE (its Table 2 and Table 3)
// and the pre-hash per ALGORITHM. Reading one value off the algorithm name
// gives the wrong signature for four of the sixteen entries below, so both are
// written out per entry rather than derived.
// ---------------------------------------------------------------------------
var EC_CURVE_OIDS = {
  'P-256': '1.2.840.10045.3.1.7',
  'P-384': '1.3.132.0.34',
  'P-521': '1.3.132.0.35'
};

var TRAD_EC = {
  'P-256': { curve: p256, oid: EC_CURVE_OIDS['P-256'], fieldLen: 32 },
  'P-384': { curve: p384, oid: EC_CURVE_OIDS['P-384'], fieldLen: 48 },
  'P-521': { curve: p521, oid: EC_CURVE_OIDS['P-521'], fieldLen: 66 }
};

var ED25519_OID = '1.3.101.112';
var ED448_OID = '1.3.101.113';
var RSA_OID = '1.2.840.113549.1.1.1';

var HASHES = {
  'SHA-256': nobleSha256,
  'SHA-384': nobleSha384,
  'SHA-512': nobleSha512,
  'SHAKE256/64': function shake256_64(msg) {
    return nobleShake256(asBytes(msg), { dkLen: 64 });
  }
};

function hashFn(name) {
  log.debug("Entering hashFn(). name=" + name);
  var found = HASHES[name];
  if (!found) {
    log.debug("Leaving hashFn(). Unknown.");
    throw new Error('No hash function named ' + name + ' in this build.');
  }
  log.debug("Leaving hashFn().");
  return found;
}

// Section 6 of the composite draft, transcribed one entry at a time. `id` is
// this project's own lower-case handle; `name` is the draft's.
var COMPOSITE_ALGS = {
  'mldsa44-rsa2048-pss-sha256': {
    name: 'id-MLDSA44-RSA2048-PSS-SHA256',
    oid: '1.3.6.1.5.5.7.6.37',
    label: 'COMPSIG-MLDSA44-RSA2048-PSS-SHA256',
    mldsa: 'ML-DSA-44', ph: 'SHA-256',
    trad: { kind: 'rsa', bits: 2048, pss: true, sigHash: 'SHA-256',
           saltLength: 32 }
  },
  'mldsa44-rsa2048-pkcs15-sha256': {
    name: 'id-MLDSA44-RSA2048-PKCS15-SHA256',
    oid: '1.3.6.1.5.5.7.6.38',
    label: 'COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256',
    mldsa: 'ML-DSA-44', ph: 'SHA-256',
    trad: { kind: 'rsa', bits: 2048, pss: false, sigHash: 'SHA-256' }
  },
  'mldsa44-ed25519-sha512': {
    name: 'id-MLDSA44-Ed25519-SHA512',
    oid: '1.3.6.1.5.5.7.6.39',
    label: 'COMPSIG-MLDSA44-Ed25519-SHA512',
    mldsa: 'ML-DSA-44', ph: 'SHA-512',
    trad: { kind: 'ed', name: 'Ed25519' }
  },
  'mldsa44-ecdsa-p256-sha256': {
    name: 'id-MLDSA44-ECDSA-P256-SHA256',
    oid: '1.3.6.1.5.5.7.6.40',
    label: 'COMPSIG-MLDSA44-ECDSA-P256-SHA256',
    mldsa: 'ML-DSA-44', ph: 'SHA-256',
    trad: { kind: 'ec', curve: 'P-256', sigHash: 'SHA-256' }
  },
  'mldsa65-rsa3072-pss-sha512': {
    name: 'id-MLDSA65-RSA3072-PSS-SHA512',
    oid: '1.3.6.1.5.5.7.6.41',
    label: 'COMPSIG-MLDSA65-RSA3072-PSS-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 3072, pss: true, sigHash: 'SHA-256',
           saltLength: 32 }
  },
  'mldsa65-rsa3072-pkcs15-sha512': {
    name: 'id-MLDSA65-RSA3072-PKCS15-SHA512',
    oid: '1.3.6.1.5.5.7.6.42',
    label: 'COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 3072, pss: false, sigHash: 'SHA-256' }
  },
  'mldsa65-rsa4096-pss-sha512': {
    name: 'id-MLDSA65-RSA4096-PSS-SHA512',
    oid: '1.3.6.1.5.5.7.6.43',
    label: 'COMPSIG-MLDSA65-RSA4096-PSS-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 4096, pss: true, sigHash: 'SHA-384',
           saltLength: 48 }
  },
  'mldsa65-rsa4096-pkcs15-sha512': {
    name: 'id-MLDSA65-RSA4096-PKCS15-SHA512',
    oid: '1.3.6.1.5.5.7.6.44',
    label: 'COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 4096, pss: false, sigHash: 'SHA-384' }
  },
  'mldsa65-ecdsa-p256-sha512': {
    name: 'id-MLDSA65-ECDSA-P256-SHA512',
    oid: '1.3.6.1.5.5.7.6.45',
    label: 'COMPSIG-MLDSA65-ECDSA-P256-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'ec', curve: 'P-256', sigHash: 'SHA-256' }
  },
  'mldsa65-ecdsa-p384-sha512': {
    name: 'id-MLDSA65-ECDSA-P384-SHA512',
    oid: '1.3.6.1.5.5.7.6.46',
    label: 'COMPSIG-MLDSA65-ECDSA-P384-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'ec', curve: 'P-384', sigHash: 'SHA-384' }
  },
  'mldsa65-ed25519-sha512': {
    name: 'id-MLDSA65-Ed25519-SHA512',
    oid: '1.3.6.1.5.5.7.6.48',
    label: 'COMPSIG-MLDSA65-Ed25519-SHA512',
    mldsa: 'ML-DSA-65', ph: 'SHA-512',
    trad: { kind: 'ed', name: 'Ed25519' }
  },
  'mldsa87-ecdsa-p384-sha512': {
    name: 'id-MLDSA87-ECDSA-P384-SHA512',
    oid: '1.3.6.1.5.5.7.6.49',
    label: 'COMPSIG-MLDSA87-ECDSA-P384-SHA512',
    mldsa: 'ML-DSA-87', ph: 'SHA-512',
    trad: { kind: 'ec', curve: 'P-384', sigHash: 'SHA-384' }
  },
  'mldsa87-ed448-shake256': {
    name: 'id-MLDSA87-Ed448-SHAKE256',
    oid: '1.3.6.1.5.5.7.6.51',
    label: 'COMPSIG-MLDSA87-Ed448-SHAKE256',
    mldsa: 'ML-DSA-87', ph: 'SHAKE256/64',
    trad: { kind: 'ed', name: 'Ed448' }
  },
  'mldsa87-rsa3072-pss-sha512': {
    name: 'id-MLDSA87-RSA3072-PSS-SHA512',
    oid: '1.3.6.1.5.5.7.6.52',
    label: 'COMPSIG-MLDSA87-RSA3072-PSS-SHA512',
    mldsa: 'ML-DSA-87', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 3072, pss: true, sigHash: 'SHA-256',
           saltLength: 32 }
  },
  'mldsa87-rsa4096-pss-sha512': {
    name: 'id-MLDSA87-RSA4096-PSS-SHA512',
    oid: '1.3.6.1.5.5.7.6.53',
    label: 'COMPSIG-MLDSA87-RSA4096-PSS-SHA512',
    mldsa: 'ML-DSA-87', ph: 'SHA-512',
    trad: { kind: 'rsa', bits: 4096, pss: true, sigHash: 'SHA-384',
           saltLength: 48 }
  },
  'mldsa87-ecdsa-p521-sha512': {
    name: 'id-MLDSA87-ECDSA-P521-SHA512',
    oid: '1.3.6.1.5.5.7.6.54',
    label: 'COMPSIG-MLDSA87-ECDSA-P521-SHA512',
    mldsa: 'ML-DSA-87', ph: 'SHA-512',
    trad: { kind: 'ec', curve: 'P-521', sigHash: 'SHA-512' }
  }
};

// The two the draft defines and this build does not implement, recorded the
// way pqc.js records HQC: absent WITH A REASON is a fact a reader can act on,
// and a silently missing algorithm is one they have to rediscover.
var COMPOSITE_MISSING = {
  'id-MLDSA65-ECDSA-brainpoolP256r1-SHA512': {
    oid: '1.3.6.1.5.5.7.6.47',
    why: 'brainpoolP256r1 is in no library in this dependency tree and in ' +
         'no browser. Writing the curve here to fill the gap would be ' +
         'inventing cryptography, which this project does not do.'
  },
  'id-MLDSA87-ECDSA-brainpoolP384r1-SHA512': {
    oid: '1.3.6.1.5.5.7.6.50',
    why: 'brainpoolP384r1, for the same reason as brainpoolP256r1 above.'
  }
};

var COMPOSITE_PREFIX = strBytes('CompositeAlgorithmSignatures2025');

// ---------------------------------------------------------------------------
// The registry every caller reads: one entry per algorithm, whatever family.
// ---------------------------------------------------------------------------
var ALGS = {};

(function buildAlgs() {
  Object.keys(SIG_OIDS).forEach(function (name) {
    ALGS[name] = {
      id: name,
      name: name,
      family: name.indexOf('ML-DSA') === 0 ? 'ML-DSA' : 'SLH-DSA',
      use: 'sig',
      oid: SIG_OIDS[name],
      spec: name.indexOf('ML-DSA') === 0 ? 'RFC.9881' : 'RFC.9909'
    };
  });
  Object.keys(KEM_OIDS).forEach(function (name) {
    ALGS[name] = {
      id: name,
      name: name,
      family: 'ML-KEM',
      use: 'kem',
      oid: KEM_OIDS[name],
      spec: 'RFC.9935'
    };
  });
  Object.keys(COMPOSITE_ALGS).forEach(function (id) {
    var cfg = COMPOSITE_ALGS[id];
    ALGS[id] = {
      id: id,
      name: cfg.name,
      family: 'Composite ML-DSA',
      use: 'sig',
      oid: cfg.oid,
      spec: 'I-D.lamps-composite-sigs',
      composite: cfg
    };
  });
})();

var ALG_BY_OID = (function buildAlgByOid() {
  var out = {};
  Object.keys(ALGS).forEach(function (id) {
    out[ALGS[id].oid] = ALGS[id];
  });
  return out;
})();

// The lower-case index, because the two registries that read this one spell
// their ids differently: pqc.js and the standards use 'ML-DSA-44', and
// key_material.js/x509.js lower-case every id they hold (the classical ones
// have always been 'ec-p256'). Rather than make every caller remember which
// spelling it has, every lookup here accepts either.
var ALG_BY_LOWER = (function buildAlgByLower() {
  var out = {};
  Object.keys(ALGS).forEach(function (id) {
    out[id.toLowerCase()] = ALGS[id];
  });
  return out;
})();

// The descriptor for an algorithm id, or null. Null rather than a throw for
// the same reason key_material.js's keyAlg() returns null: a stored object
// written by a newer build must be reportable as "this build does not know
// that algorithm" rather than crash the page that lists it.
function alg(id) {
  log.debug("Entering alg(). id=" + id);
  var found = ALGS[id] || ALG_BY_LOWER[String(id || '').toLowerCase()] || null;
  log.debug("Leaving alg().");
  return found;
}

function algForOid(oid) {
  log.debug("Entering algForOid(). oid=" + oid);
  var found = ALG_BY_OID[String(oid)] || null;
  log.debug("Leaving algForOid().");
  return found;
}

function isPqc(id) {
  log.debug("Entering isPqc(). id=" + id);
  var yes = !!alg(id);
  log.debug("Leaving isPqc(). " + yes);
  return yes;
}

function algIds(use) {
  log.debug("Entering algIds(). use=" + use);
  var out = Object.keys(ALGS).filter(function (id) {
    return !use || ALGS[id].use === use;
  });
  log.debug("Leaving algIds(). " + out.length + " of them.");
  return out;
}

// ---------------------------------------------------------------------------
// ASN.1 helpers — the four shapes this module builds, and nothing else.
// ---------------------------------------------------------------------------
function bufferOf(view) {
  log.debug("Entering bufferOf().");
  var out = asBytes(view);
  log.debug("Leaving bufferOf().");
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
}

function algorithmIdentifier(oid) {
  log.debug("Entering algorithmIdentifier(). oid=" + oid);
  // PARAMS ARE absent for every algorithm in this file. RFC 9881 section 3
  // and RFC 9909 section 4 both say the parameters field MUST be absent, and
  // an explicit NULL there — which is what an RSA AlgorithmIdentifier carries
  // and what a copied builder therefore tends to emit — makes a certificate
  // that OpenSSL 3.5 refuses to load with "unsupported algorithm".
  var out = new asn1js.Sequence({
    value: [new asn1js.ObjectIdentifier({ value: oid })]
  });
  log.debug("Leaving algorithmIdentifier().");
  return out;
}

function derOf(schema) {
  log.debug("Entering derOf().");
  var out = new Uint8Array(schema.toBER(false));
  log.debug("Leaving derOf().");
  return out;
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo
// ---------------------------------------------------------------------------
function encodeSpki(algId, pub) {
  log.debug("Entering encodeSpki(). alg=" + algId);
  var entry = alg(algId);
  if (!entry) {
    log.debug("Leaving encodeSpki(). Unknown algorithm.");
    throw new Error('Not a post-quantum algorithm this build knows: ' + algId);
  }
  var out = derOf(new asn1js.Sequence({
    value: [
      algorithmIdentifier(entry.oid),
      new asn1js.BitString({ valueHex: bufferOf(pub) })
    ]
  }));
  log.debug("Leaving encodeSpki(). " + out.length + " bytes.");
  return out;
}

// Reads a SubjectPublicKeyInfo and returns {alg, pub} if its algorithm is one
// of ours, and null if it is not — so a caller can try this first and fall
// back to Web Crypto for the classical families without catching anything.
function decodeSpki(der) {
  log.debug("Entering decodeSpki().");
  var parsed = asn1js.fromBER(bufferOf(asBytes(der)));
  if (parsed.offset === -1 || !parsed.result.valueBlock ||
      !parsed.result.valueBlock.value ||
      parsed.result.valueBlock.value.length < 2) {
    log.debug("Leaving decodeSpki(). Not a SubjectPublicKeyInfo.");
    return null;
  }
  var algSeq = parsed.result.valueBlock.value[0];
  var bitString = parsed.result.valueBlock.value[1];
  var oidBlock = algSeq.valueBlock && algSeq.valueBlock.value
    ? algSeq.valueBlock.value[0]
    : null;
  if (!oidBlock || !oidBlock.valueBlock ||
      typeof oidBlock.valueBlock.toString !== 'function') {
    log.debug("Leaving decodeSpki(). No algorithm OID.");
    return null;
  }
  var entry = algForOid(oidBlock.valueBlock.toString());
  if (!entry) {
    log.debug("Leaving decodeSpki(). Not a post-quantum algorithm.");
    return null;
  }
  var pub = new Uint8Array(bitString.valueBlock.valueHexView);
  log.debug("Leaving decodeSpki(). alg=" + entry.id);
  return { alg: entry.id, entry: entry, pub: pub };
}

// ---------------------------------------------------------------------------
// PKCS#8 / OneAsymmetricKey
//
// `form` selects the CHOICE arm for the two families that have one:
// 'seed' (the default, and what RFC 9881 section 6 and RFC 9935 section 5
// RECOMMEND), 'expandedKey', or 'both' (what OpenSSL 3.5 writes). SLH-DSA and
// the composites have no CHOICE and ignore it.
// ---------------------------------------------------------------------------
function seedArm(seed) {
  log.debug("Entering seedArm().");
  // [0] IMPLICIT OCTET STRING: a primitive context-tagged value carrying the
  // seed octets directly. Encoding it as an EXPLICIT [0] wrapping an OCTET
  // STRING adds two bytes that every conforming reader rejects, and asn1js
  // will happily build either.
  var out = new asn1js.Primitive({
    idBlock: { tagClass: 3, tagNumber: 0 },
    valueHex: bufferOf(seed)
  });
  log.debug("Leaving seedArm().");
  return out;
}

function privateKeyContent(entry, priv, form) {
  log.debug("Entering privateKeyContent(). alg=" + entry.id +
      " form=" + form);
  if (entry.family === 'SLH-DSA' || entry.family === 'Composite ML-DSA') {
    // "-- PRIVATE-KEY no ASN.1 wrapping --" for SLH-DSA (RFC 9909 section 4),
    // and section 5.1 of the composite draft for the composite: the OCTET
    // STRING holds the raw serialization and nothing more.
    log.debug("Leaving privateKeyContent(). Raw.");
    return asBytes(priv);
  }
  var sizes = entry.family === 'ML-KEM'
    ? KEM_SIZES[entry.id]
    : { seed: 32 };
  var chosen = form || 'seed';
  if (chosen === 'seed') {
    if (asBytes(priv).length !== sizes.seed) {
      log.debug("Leaving privateKeyContent(). Wrong seed length.");
      throw new Error('The seed arm of ' + entry.id + ' is ' + sizes.seed +
          ' bytes; this key is ' + asBytes(priv).length + '. Pass the seed, ' +
          'not the expanded key.');
    }
    log.debug("Leaving privateKeyContent(). Seed arm.");
    return derOf(seedArm(priv));
  }
  var expanded = expandPrivate(entry, priv);
  if (chosen === 'expandedKey') {
    log.debug("Leaving privateKeyContent(). expandedKey arm.");
    return derOf(new asn1js.OctetString({ valueHex: bufferOf(expanded) }));
  }
  if (chosen === 'both') {
    log.debug("Leaving privateKeyContent(). both arm.");
    return derOf(new asn1js.Sequence({
      value: [
        new asn1js.OctetString({ valueHex: bufferOf(priv) }),
        new asn1js.OctetString({ valueHex: bufferOf(expanded) })
      ]
    }));
  }
  log.debug("Leaving privateKeyContent(). Unknown form.");
  throw new Error('Unknown private key form: ' + chosen + '. RFC 9881 ' +
      'section 6 defines seed, expandedKey and both.');
}

// The expanded secret key derived from a seed, which is what the CHOICE's
// other two arms carry. Deriving it rather than storing it is what makes the
// seed arm lossless: FIPS 204 algorithm 6 and FIPS 203 algorithm 16 are both
// deterministic in the seed.
function expandPrivate(entry, seed) {
  log.debug("Entering expandPrivate(). alg=" + entry.id);
  if (entry.family === 'ML-KEM') {
    var kem = KEM_SIZES[entry.id].prim.keygen(asBytes(seed));
    log.debug("Leaving expandPrivate(). ML-KEM.");
    return asBytes(kem.secretKey);
  }
  var kp = pqc.signatureAlg(entry.id).prim.keygen(asBytes(seed));
  log.debug("Leaving expandPrivate(). ML-DSA.");
  return asBytes(kp.secretKey);
}

function encodePkcs8(algId, priv, options) {
  log.debug("Entering encodePkcs8(). alg=" + algId);
  var entry = alg(algId);
  if (!entry) {
    log.debug("Leaving encodePkcs8(). Unknown algorithm.");
    throw new Error('Not a post-quantum algorithm this build knows: ' + algId);
  }
  var opts = options || {};
  var content = privateKeyContent(entry, priv, opts.form);
  var out = derOf(new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      algorithmIdentifier(entry.oid),
      new asn1js.OctetString({ valueHex: bufferOf(content) })
    ]
  }));
  log.debug("Leaving encodePkcs8(). " + out.length + " bytes.");
  return out;
}

// Reads any of the three arms back, and returns the key in the ONE form the
// rest of this module signs with: `priv` is the seed for ML-DSA and ML-KEM,
// the raw secret key for SLH-DSA, and the composite serialization for a
// composite. `expanded` is filled in when the file carried one.
function decodePkcs8(der) {
  log.debug("Entering decodePkcs8().");
  var parsed = asn1js.fromBER(bufferOf(asBytes(der)));
  if (parsed.offset === -1 || !parsed.result.valueBlock ||
      !parsed.result.valueBlock.value ||
      parsed.result.valueBlock.value.length < 3) {
    log.debug("Leaving decodePkcs8(). Not a OneAsymmetricKey.");
    return null;
  }
  var algSeq = parsed.result.valueBlock.value[1];
  var oidBlock = algSeq.valueBlock && algSeq.valueBlock.value
    ? algSeq.valueBlock.value[0]
    : null;
  if (!oidBlock || !oidBlock.valueBlock ||
      typeof oidBlock.valueBlock.toString !== 'function') {
    log.debug("Leaving decodePkcs8(). No algorithm OID.");
    return null;
  }
  var entry = algForOid(oidBlock.valueBlock.toString());
  if (!entry) {
    log.debug("Leaving decodePkcs8(). Not a post-quantum algorithm.");
    return null;
  }
  var content = new Uint8Array(
      parsed.result.valueBlock.value[2].valueBlock.valueHexView);
  if (entry.family === 'SLH-DSA' || entry.family === 'Composite ML-DSA') {
    log.debug("Leaving decodePkcs8(). Raw private key.");
    return { alg: entry.id, entry: entry, priv: content, expanded: null,
             form: 'raw' };
  }
  var inner = asn1js.fromBER(bufferOf(content));
  if (inner.offset === -1) {
    log.debug("Leaving decodePkcs8(). Unparseable private key.");
    throw new Error('The privateKey octets of this ' + entry.id + ' key are ' +
        'not one of the three CHOICE arms RFC 9881 section 6 defines.');
  }
  var block = inner.result;
  var tag = block.idBlock;
  if (tag.tagClass === 3 && tag.tagNumber === 0) {
    log.debug("Leaving decodePkcs8(). seed arm.");
    return { alg: entry.id, entry: entry,
             priv: new Uint8Array(block.valueBlock.valueHexView),
             expanded: null, form: 'seed' };
  }
  if (tag.tagClass === 1 && tag.tagNumber === 4) {
    // expandedKey. There is no seed to recover — the derivation is one-way —
    // so `priv` is the expanded key and every signer below has to cope with
    // that. This is the arm that costs a caller the ability to re-export in
    // the compact form, which is worth saying out loud somewhere.
    log.debug("Leaving decodePkcs8(). expandedKey arm.");
    return { alg: entry.id, entry: entry, priv: null,
             expanded: new Uint8Array(block.valueBlock.valueHexView),
             form: 'expandedKey' };
  }
  if (tag.tagClass === 1 && tag.tagNumber === 16) {
    var parts = block.valueBlock.value || [];
    if (parts.length !== 2) {
      log.debug("Leaving decodePkcs8(). Malformed both arm.");
      throw new Error('The "both" arm of an ' + entry.id + ' private key is ' +
          'a SEQUENCE of exactly two OCTET STRINGs.');
    }
    log.debug("Leaving decodePkcs8(). both arm.");
    return { alg: entry.id, entry: entry,
             priv: new Uint8Array(parts[0].valueBlock.valueHexView),
             expanded: new Uint8Array(parts[1].valueBlock.valueHexView),
             form: 'both' };
  }
  log.debug("Leaving decodePkcs8(). Unrecognised CHOICE arm.");
  throw new Error('Unrecognised private key CHOICE arm for ' + entry.id + '.');
}

// ---------------------------------------------------------------------------
// The traditional component of a composite, in the encodings section 4 of the
// draft pins. Every one of these five functions exists because the draft names
// a DIFFERENT encoding from the one the same key has in JOSE, in a JWK, or in
// the PKCS#8 file a browser would hand you.
// ---------------------------------------------------------------------------

// ECPrivateKey (RFC 5915) WITHOUT the optional publicKey field, which the
// draft explicitly excludes. Web Crypto's PKCS#8 export always includes it, so
// a composite built by lifting bytes out of an exported key would carry an
// extra 70-odd octets and split wrongly at the far end.
function ecPrivateKeyDer(trad, scalar) {
  log.debug("Entering ecPrivateKeyDer(). curve=" + trad.curve);
  var info = TRAD_EC[trad.curve];
  var out = derOf(new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }),
      new asn1js.OctetString({ valueHex: bufferOf(scalar) }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.ObjectIdentifier({ value: info.oid })]
      })
    ]
  }));
  log.debug("Leaving ecPrivateKeyDer().");
  return out;
}

function ecScalarFromDer(trad, der) {
  log.debug("Entering ecScalarFromDer().");
  var parsed = asn1js.fromBER(bufferOf(asBytes(der)));
  if (parsed.offset === -1) {
    log.debug("Leaving ecScalarFromDer(). Unparseable.");
    throw new Error('The ECDSA half of this composite private key is not an ' +
        'ECPrivateKey.');
  }
  var parts = parsed.result.valueBlock.value || [];
  if (parts.length < 2) {
    log.debug("Leaving ecScalarFromDer(). Too few fields.");
    throw new Error('An ECPrivateKey has at least a version and a key.');
  }
  var raw = new Uint8Array(parts[1].valueBlock.valueHexView);
  var want = TRAD_EC[trad.curve].fieldLen;
  // RFC 5915 fixes the OCTET STRING at ceil(log2(n)/8) octets, so a short
  // value is a producer that stripped a leading zero rather than a different
  // key. Left-padding is the reading every other implementation takes.
  if (raw.length < want) {
    var padded = new Uint8Array(want);
    padded.set(raw, want - raw.length);
    raw = padded;
  }
  log.debug("Leaving ecScalarFromDer().");
  return raw;
}

// The RSA halves are lifted straight out of the standard containers: an SPKI's
// BIT STRING already IS an RSAPublicKey, and a PKCS#8's privateKey OCTET
// STRING already IS an RSAPrivateKey. Both directions are therefore a wrap or
// an unwrap rather than a re-encoding, which is what keeps the CRT parameters
// intact — a composite carrying a two-prime key rebuilt from (n, d) would
// verify perfectly and be several times slower to sign with.
function rsaSpkiFromPublicKeyDer(rsaPub) {
  log.debug("Entering rsaSpkiFromPublicKeyDer().");
  var out = derOf(new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: RSA_OID }),
                new asn1js.Null()]
      }),
      new asn1js.BitString({ valueHex: bufferOf(rsaPub) })
    ]
  }));
  log.debug("Leaving rsaSpkiFromPublicKeyDer().");
  return out;
}

function rsaPkcs8FromPrivateKeyDer(rsaPriv) {
  log.debug("Entering rsaPkcs8FromPrivateKeyDer().");
  var out = derOf(new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: RSA_OID }),
                new asn1js.Null()]
      }),
      new asn1js.OctetString({ valueHex: bufferOf(rsaPriv) })
    ]
  }));
  log.debug("Leaving rsaPkcs8FromPrivateKeyDer().");
  return out;
}

function innerOctets(der, index) {
  log.debug("Entering innerOctets(). index=" + index);
  var parsed = asn1js.fromBER(bufferOf(asBytes(der)));
  var part = parsed.result.valueBlock.value[index];
  var out = new Uint8Array(part.valueBlock.valueHexView);
  log.debug("Leaving innerOctets().");
  return out;
}

function rsaWebCryptoParams(trad, forSigning) {
  log.debug("Entering rsaWebCryptoParams().");
  var name = trad.pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
  var out = forSigning && trad.pss
    ? { name: name, saltLength: trad.saltLength }
    : { name: name, hash: trad.sigHash };
  log.debug("Leaving rsaWebCryptoParams().");
  return out;
}

// ---------------------------------------------------------------------------
// Composite key generation, signing and verification.
// ---------------------------------------------------------------------------
async function generateCompositeKeyPair(cfg) {
  log.debug("Entering generateCompositeKeyPair(). alg=" + cfg.name);
  var seed = bytes.randomBytes(32);
  var mldsaPub = pqc.signatureAlg(cfg.mldsa).prim.keygen(seed).publicKey;
  var tradPub;
  var tradSk;
  if (cfg.trad.kind === 'ec') {
    var info = TRAD_EC[cfg.trad.curve];
    var scalar = info.curve.utils.randomPrivateKey();
    tradSk = ecPrivateKeyDer(cfg.trad, scalar);
    tradPub = asBytes(info.curve.getPublicKey(scalar, false));
  } else if (cfg.trad.kind === 'ed') {
    var edCurve = cfg.trad.name === 'Ed448' ? ed448 : ed25519;
    var edPriv = edCurve.utils.randomPrivateKey();
    tradSk = asBytes(edPriv);
    tradPub = asBytes(edCurve.getPublicKey(edPriv));
  } else {
    var pair = await crypto.subtle.generateKey({
      name: cfg.trad.pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
      modulusLength: cfg.trad.bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: cfg.trad.sigHash
    }, true, ['sign', 'verify']);
    var pkcs8 = new Uint8Array(
        await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    var spki = new Uint8Array(
        await crypto.subtle.exportKey('spki', pair.publicKey));
    tradSk = innerOctets(pkcs8, 2);
    tradPub = new Uint8Array(
        asn1js.fromBER(bufferOf(spki)).result.valueBlock.value[1]
            .valueBlock.valueHexView);
  }
  log.debug("Leaving generateCompositeKeyPair().");
  return {
    pub: concatBytes(asBytes(mldsaPub), tradPub),
    priv: concatBytes(seed, asBytes(tradSk))
  };
}

function splitCompositePublic(cfg, pub) {
  log.debug("Entering splitCompositePublic().");
  var mldsaLen = pqc.SIGNATURE_ALGS[cfg.mldsa].lengths.publicKey;
  var all = asBytes(pub);
  if (all.length <= mldsaLen) {
    log.debug("Leaving splitCompositePublic(). Too short.");
    throw new Error('A ' + cfg.name + ' public key is ' + mldsaLen +
        ' bytes of ML-DSA followed by the traditional key; this one is ' +
        all.length + ' bytes in total.');
  }
  log.debug("Leaving splitCompositePublic().");
  return { mldsa: all.slice(0, mldsaLen), trad: all.slice(mldsaLen) };
}

function splitCompositePrivate(cfg, priv) {
  log.debug("Entering splitCompositePrivate().");
  var all = asBytes(priv);
  if (all.length <= 32) {
    log.debug("Leaving splitCompositePrivate(). Too short.");
    throw new Error('A ' + cfg.name + ' private key is a 32-byte ML-DSA ' +
        'seed followed by the traditional key; this one is ' + all.length +
        ' bytes in total.');
  }
  log.debug("Leaving splitCompositePrivate().");
  return { seed: all.slice(0, 32), trad: all.slice(32) };
}

function splitCompositeSignature(cfg, sig) {
  log.debug("Entering splitCompositeSignature().");
  var mldsaLen = pqc.SIGNATURE_ALGS[cfg.mldsa].lengths.signature;
  var all = asBytes(sig);
  if (all.length <= mldsaLen) {
    log.debug("Leaving splitCompositeSignature(). Too short.");
    throw new Error('A ' + cfg.name + ' signature is ' + mldsaLen +
        ' bytes of ML-DSA followed by the traditional signature; this one ' +
        'is ' + all.length + ' bytes in total.');
  }
  log.debug("Leaving splitCompositeSignature().");
  return { mldsa: all.slice(0, mldsaLen), trad: all.slice(mldsaLen) };
}

// M' — section 2.2. The 0x00 is len(ctx) for the empty application context
// X.509 uses; it is a LENGTH and not a terminator, which is the detail that
// makes a hand-written implementation of this disagree with a correct one by
// exactly one byte and no error message anywhere.
function compositeMessage(cfg, message) {
  log.debug("Entering compositeMessage(). alg=" + cfg.name);
  var out = concatBytes(COMPOSITE_PREFIX, strBytes(cfg.label),
      new Uint8Array([0x00]), asBytes(hashFn(cfg.ph)(asBytes(message))));
  log.debug("Leaving compositeMessage(). " + out.length + " bytes.");
  return out;
}

async function signComposite(cfg, message, priv) {
  log.debug("Entering signComposite(). alg=" + cfg.name);
  var halves = splitCompositePrivate(cfg, priv);
  var mPrime = compositeMessage(cfg, message);
  var entry = pqc.signatureAlg(cfg.mldsa);
  var mldsaSk = entry.prim.keygen(halves.seed).secretKey;
  // The Label is the ML-DSA context as well as part of M'. Signing with an
  // empty context here produces a composite that verifies against nothing and
  // whose ML-DSA half can be lifted out and replayed on its own, which is the
  // attack the second use of the label exists to stop.
  var mldsaSig = entry.sign(mPrime, mldsaSk, { context: strBytes(cfg.label) });
  var tradSig;
  if (cfg.trad.kind === 'ec') {
    var info = TRAD_EC[cfg.trad.curve];
    var digest = hashFn(cfg.trad.sigHash)(mPrime);
    tradSig = asBytes(info.curve
        .sign(digest, ecScalarFromDer(cfg.trad, halves.trad))
        .toDERRawBytes());
  } else if (cfg.trad.kind === 'ed') {
    var edCurve = cfg.trad.name === 'Ed448' ? ed448 : ed25519;
    tradSig = asBytes(edCurve.sign(mPrime, halves.trad));
  } else {
    var key = await crypto.subtle.importKey('pkcs8',
        bufferOf(rsaPkcs8FromPrivateKeyDer(halves.trad)),
        { name: cfg.trad.pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
          hash: cfg.trad.sigHash }, false, ['sign']);
    tradSig = new Uint8Array(await crypto.subtle.sign(
        rsaWebCryptoParams(cfg.trad, true), key, bufferOf(mPrime)));
  }
  log.debug("Leaving signComposite().");
  return concatBytes(asBytes(mldsaSig), tradSig);
}

async function verifyComposite(cfg, sig, message, pub) {
  log.debug("Entering verifyComposite(). alg=" + cfg.name);
  var pubHalves;
  var sigHalves;
  try {
    pubHalves = splitCompositePublic(cfg, pub);
    sigHalves = splitCompositeSignature(cfg, sig);
  } catch (e) {
    log.debug("Leaving verifyComposite(). Not splittable: " + e.message);
    return false;
  }
  var mPrime = compositeMessage(cfg, message);
  var entry = pqc.signatureAlg(cfg.mldsa);
  var mldsaOk = entry.verify(sigHalves.mldsa, mPrime, pubHalves.mldsa,
      { context: strBytes(cfg.label) });
  // BOTH halves, always, and the draft says so: "Compliant applications MUST
  // output Valid signature (true) if and only if all component signatures
  // were successfully validated." A verifier that stops at the first success
  // is a verifier that accepts a forged post-quantum half.
  var tradOk = false;
  if (cfg.trad.kind === 'ec') {
    var info = TRAD_EC[cfg.trad.curve];
    var digest = hashFn(cfg.trad.sigHash)(mPrime);
    try {
      tradOk = info.curve.verify(sigHalves.trad, digest, pubHalves.trad);
    } catch (e) {
      log.debug("verifyComposite(): ECDSA half refused: " + e.message);
      tradOk = false;
    }
  } else if (cfg.trad.kind === 'ed') {
    var edCurve = cfg.trad.name === 'Ed448' ? ed448 : ed25519;
    try {
      tradOk = edCurve.verify(sigHalves.trad, mPrime, pubHalves.trad);
    } catch (e) {
      log.debug("verifyComposite(): EdDSA half refused: " + e.message);
      tradOk = false;
    }
  } else {
    var key = await crypto.subtle.importKey('spki',
        bufferOf(rsaSpkiFromPublicKeyDer(pubHalves.trad)),
        { name: cfg.trad.pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
          hash: cfg.trad.sigHash }, false, ['verify']);
    tradOk = await crypto.subtle.verify(rsaWebCryptoParams(cfg.trad, true),
        key, bufferOf(sigHalves.trad), bufferOf(mPrime));
  }
  log.debug("Leaving verifyComposite(). mldsa=" + mldsaOk +
      " trad=" + tradOk);
  return !!mldsaOk && !!tradOk;
}

// ---------------------------------------------------------------------------
// The public API: one keygen, one sign, one verify, whatever the family.
// ---------------------------------------------------------------------------
async function generateKeyPair(algId) {
  log.debug("Entering generateKeyPair(). alg=" + algId);
  var entry = alg(algId);
  if (!entry) {
    log.debug("Leaving generateKeyPair(). Unknown algorithm.");
    throw new Error('Not a post-quantum algorithm this build knows: ' + algId);
  }
  if (entry.family === 'Composite ML-DSA') {
    var composite = await generateCompositeKeyPair(entry.composite);
    log.debug("Leaving generateKeyPair(). Composite.");
    return { alg: algId, pub: composite.pub, priv: composite.priv };
  }
  if (entry.family === 'ML-KEM') {
    var seed = bytes.randomBytes(KEM_SIZES[entry.id].seed);
    var kem = KEM_SIZES[entry.id].prim.keygen(seed);
    log.debug("Leaving generateKeyPair(). ML-KEM.");
    return { alg: algId, pub: asBytes(kem.publicKey), priv: seed };
  }
  var pair = pqc.generateAkpKeyPair(entry.id);
  log.debug("Leaving generateKeyPair(). " + entry.family + ".");
  return { alg: algId, pub: asBytes(pair.pub), priv: asBytes(pair.priv) };
}

// The public key that goes with a private one — needed because a PKCS#8 file
// carries no public half for any of these algorithms, and a certificate
// cannot be checked against the key that signed it without one.
function publicFromPrivate(algId, priv) {
  log.debug("Entering publicFromPrivate(). alg=" + algId);
  var entry = alg(algId);
  if (!entry) {
    log.debug("Leaving publicFromPrivate(). Unknown algorithm.");
    throw new Error('Not a post-quantum algorithm this build knows: ' + algId);
  }
  if (entry.family === 'ML-KEM') {
    log.debug("Leaving publicFromPrivate(). ML-KEM.");
    return asBytes(KEM_SIZES[entry.id].prim.keygen(asBytes(priv)).publicKey);
  }
  if (entry.family === 'SLH-DSA') {
    // FIPS 205 section 9.1: the public key is the second half of the private
    // key (PK.seed || PK.root), so no derivation is needed or possible.
    var all = asBytes(priv);
    log.debug("Leaving publicFromPrivate(). SLH-DSA.");
    return all.slice(all.length / 2);
  }
  if (entry.family === 'ML-DSA') {
    log.debug("Leaving publicFromPrivate(). ML-DSA.");
    return asBytes(pqc.signatureAlg(entry.id).prim.keygen(asBytes(priv))
        .publicKey);
  }
  var cfg = entry.composite;
  var halves = splitCompositePrivate(cfg, priv);
  var mldsaPub = pqc.signatureAlg(cfg.mldsa).prim.keygen(halves.seed)
      .publicKey;
  var tradPub;
  if (cfg.trad.kind === 'ec') {
    var info = TRAD_EC[cfg.trad.curve];
    tradPub = asBytes(info.curve.getPublicKey(
        ecScalarFromDer(cfg.trad, halves.trad), false));
  } else if (cfg.trad.kind === 'ed') {
    var edCurve = cfg.trad.name === 'Ed448' ? ed448 : ed25519;
    tradPub = asBytes(edCurve.getPublicKey(halves.trad));
  } else {
    // An RSAPrivateKey carries the modulus and the public exponent as its
    // second and third fields, which is the whole of an RSAPublicKey — so the
    // public half is a re-encoding rather than a computation.
    var parsed = asn1js.fromBER(bufferOf(asBytes(halves.trad)));
    var parts = parsed.result.valueBlock.value;
    tradPub = derOf(new asn1js.Sequence({ value: [parts[1], parts[2]] }));
  }
  log.debug("Leaving publicFromPrivate(). Composite.");
  return concatBytes(asBytes(mldsaPub), tradPub);
}

async function sign(algId, message, priv) {
  log.debug("Entering sign(). alg=" + algId);
  var entry = alg(algId);
  if (!entry || entry.use !== 'sig') {
    log.debug("Leaving sign(). Not a signature algorithm.");
    throw new Error(algId + ' is not a post-quantum signature algorithm ' +
        'this build can sign with.');
  }
  if (entry.family === 'Composite ML-DSA') {
    var composite = await signComposite(entry.composite, message, priv);
    log.debug("Leaving sign(). Composite.");
    return composite;
  }
  if (entry.family === 'ML-DSA') {
    var sig = pqc.signWithPriv(entry.id, asBytes(message),
        asBytes(priv));
    log.debug("Leaving sign(). ML-DSA.");
    return asBytes(sig);
  }
  var slh = pqc.signatureAlg(entry.id).sign(asBytes(message),
      asBytes(priv));
  log.debug("Leaving sign(). SLH-DSA.");
  return asBytes(slh);
}

async function verify(algId, sig, message, pub) {
  log.debug("Entering verify(). alg=" + algId);
  var entry = alg(algId);
  if (!entry || entry.use !== 'sig') {
    log.debug("Leaving verify(). Not a signature algorithm.");
    throw new Error(algId + ' is not a post-quantum signature algorithm ' +
        'this build can verify with.');
  }
  if (entry.family === 'Composite ML-DSA') {
    var ok = await verifyComposite(entry.composite, sig, message, pub);
    log.debug("Leaving verify(). Composite.");
    return ok;
  }
  var pure = pqc.verifyWithPub(entry.id, asBytes(sig), asBytes(message),
      asBytes(pub));
  log.debug("Leaving verify(). " + entry.family + ".");
  return !!pure;
}

// ---------------------------------------------------------------------------
// PEM, and the labels a page shows.
// ---------------------------------------------------------------------------
function publicPem(algId, pub) {
  log.debug("Entering publicPem(). alg=" + algId);
  var pem = bytes.derToPem(encodeSpki(algId, pub), 'PUBLIC KEY');
  log.debug("Leaving publicPem().");
  return pem;
}

function privatePem(algId, priv, options) {
  log.debug("Entering privatePem(). alg=" + algId);
  var pem = bytes.derToPem(encodePkcs8(algId, priv, options), 'PRIVATE KEY');
  log.debug("Leaving privatePem().");
  return pem;
}

var FAMILY_SPECS = {
  'ML-DSA': 'RFC.9881',
  'SLH-DSA': 'RFC.9909',
  'ML-KEM': 'RFC.9935',
  'Composite ML-DSA': 'I-D.lamps-composite-sigs'
};

// The sentence a pane renders beside a draft algorithm, from pqc.js's one
// SPECS table so that two pages cannot disagree about what the caveat says.
function specNote(algId) {
  log.debug("Entering specNote(). alg=" + algId);
  var entry = alg(algId);
  var note = entry ? pqc.specNote(entry.spec) : null;
  log.debug("Leaving specNote().");
  return note;
}

function labelFor(algId) {
  log.debug("Entering labelFor(). alg=" + algId);
  var entry = alg(algId);
  if (!entry) {
    log.debug("Leaving labelFor(). Unknown.");
    return String(algId);
  }
  var label;
  if (entry.family === 'Composite ML-DSA') {
    label = entry.composite.name.replace(/^id-/, '') + ' (composite, draft)';
  } else if (entry.family === 'ML-KEM') {
    label = entry.name + ' (key establishment)';
  } else {
    label = entry.name;
  }
  log.debug("Leaving labelFor().");
  return label;
}

module.exports = {
  // the registry
  ALGS: ALGS,
  SIG_OIDS: SIG_OIDS,
  KEM_OIDS: KEM_OIDS,
  KEM_SIZES: KEM_SIZES,
  COMPOSITE_ALGS: COMPOSITE_ALGS,
  COMPOSITE_MISSING: COMPOSITE_MISSING,
  COMPOSITE_PREFIX: COMPOSITE_PREFIX,
  alg: alg,
  algForOid: algForOid,
  algIds: algIds,
  isPqc: isPqc,
  labelFor: labelFor,
  specNote: specNote,
  FAMILY_SPECS: FAMILY_SPECS,
  // encodings
  encodeSpki: encodeSpki,
  decodeSpki: decodeSpki,
  encodePkcs8: encodePkcs8,
  decodePkcs8: decodePkcs8,
  publicPem: publicPem,
  privatePem: privatePem,
  algorithmIdentifier: algorithmIdentifier,
  // keys and signatures
  generateKeyPair: generateKeyPair,
  publicFromPrivate: publicFromPrivate,
  sign: sign,
  verify: verify,
  // exported for tests/pki_pqc_x509.js, which asserts the composite splits
  // and the message representative against the draft's own definitions
  compositeMessage: compositeMessage,
  splitCompositePublic: splitCompositePublic,
  splitCompositePrivate: splitCompositePrivate,
  splitCompositeSignature: splitCompositeSignature,
  expandPrivate: expandPrivate
};
