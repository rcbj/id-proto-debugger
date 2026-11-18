// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: data_integrity.js
//
// ---------------------------------------------------------------------------
// Data Integrity and Linked Data proofs on a JSON-LD credential or
// presentation: CREATE one and VERIFY one, for every proof type an `ldp_vc`
// arrives with except the selective-disclosure ones (bbs-2023 lives in
// bbs2023.js; ecdsa-sd-2023 in ecdsa_sd_2023.js, #476).
//
//   W3C VC Data Integrity EdDSA Cryptosuites v1.0
//     eddsa-rdfc-2022     RDFC-1.0, SHA-256, Ed25519
//     eddsa-jcs-2022      JCS (RFC 8785), SHA-256, Ed25519
//   W3C VC Data Integrity ECDSA Cryptosuites v1.0
//     ecdsa-rdfc-2019     RDFC-1.0, P-256/SHA-256 or P-384/SHA-384
//     ecdsa-jcs-2019      JCS, likewise
//   W3C Verifiable Credential Barcodes v1.0 (Working Draft)
//     ecdsa-xi-2023       ecdsa-rdfc-2019 plus a hash of "extra information"
//                         from outside the document (a barcode's optical
//                         data); SHA-256 on both curves (#480)
//   The Linked Data Signatures proof types that preceded Data Integrity, and
//   that a great many deployed credentials still carry:
//     Ed25519Signature2018          detached JWS, EdDSA
//     Ed25519Signature2020          proofValue, Ed25519
//     JsonWebSignature2020          detached JWS, any of EdDSA, ES256K, ES256,
//                                   ES384, ES512, PS256
//     EcdsaSecp256k1Signature2019   detached JWS, ES256K
//
// EVERY ONE IS THE SAME THREE STEPS, which is why they are one table and not
// eight modules: canonicalize the proof's options and the document without
// its proof, hash each, and sign hash(options) || hash(document). What varies
// is the canonicalization (RDFC-1.0 or JCS), the hash (SHA-384 only for the
// ECDSA suites on P-384), the @context the options are canonicalized under,
// and how the signature is written down (a multibase proofValue or a detached
// RFC 7797 JWS). Each of those is a column of SUITES below.
//
// The one difference that is NOT a column, and that costs everybody once:
// a DataIntegrityProof's options are canonicalized under the DOCUMENT's
// @context (and a proof that carries its own @context must carry exactly
// that one — compared for equality, not as a prefix; the JCS suites instead
// keep the @context in the proof and check the document's begins with it),
// while the legacy types follow jsonld-signatures, which lets a proof's own
// @context win and falls back to https://w3id.org/security/v2 when the
// document names none. Some pre-2020 signers ALWAYS used security/v2. Such a
// proof is INVALID here — the debugger implements the specification — and
// the reason says that it would have verified under that reading.
//
// WHAT THIS DOES NOT DECIDE. It verifies that the key the verificationMethod
// names made this signature over this document. Whether that key may speak
// for the credential's issuer, whether the proofPurpose is the one a caller
// wanted, whether `challenge` and `domain` are this request's — those are the
// caller's, and the result carries everything needed to decide them.
// `resolveKey` is the caller's too: this module never fetches anything.
//
// All cryptography is common/crypto/crypto_provider.js: pure JS, synchronous,
// and the same in a page served over plain HTTP as anywhere else. Only RDFC
// canonicalization is asynchronous (jsonld), so the API is promises.
//
// RDFC-1.0 IS REGISTERED, NOT REQUIRED. jsonld and rdf-canonize are most of a
// bundle, and this module is reached from vp_protocols.js, which nearly every
// VC page loads for reasons that have nothing to do with JSON-LD. So the JCS
// suites work everywhere, and the RDFC suites and legacy types work wherever
// data_integrity_rdfc.js has been loaded, which registers the canonicalizer
// here. A page that does not load it gets an error naming the module.
//
// NO DOM.
// ---------------------------------------------------------------------------

var provider = require("./crypto_provider");
var cbytes = require("./crypto_bytes");
var jsonldContexts = require("./jsonld_contexts");
var didLib = require("./did");
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "data_integrity",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var DATA_INTEGRITY_PROOF = "DataIntegrityProof";

// The key curves each family signs with, as JWK crv (or kty for RSA).
var EDDSA_CURVES = ["Ed25519"];
var ECDSA_CURVES = ["P-256", "P-384"];
var JWS_2020_CURVES = ["Ed25519", "secp256k1", "P-256", "P-384", "P-521",
                     "RSA"];

// One row per proof type. `id` is what a caller names it by: the cryptosuite
// for a DataIntegrityProof, the proof `type` for a legacy one.
//   canon     "rdfc" | "jcs"
//   encoding  "proofValue" (multibase base58btc) | "jws" (detached, b64=false)
//   keys      the JWK crv values (or "RSA") the suite signs with
//   context   the suite's own context, which a signed document must name
//   vmType    the verification method type the suite's documents use
//   legacy    true for the Linked Data Signatures types (see the header)
//   spec      where the algorithm is written down
var SUITES = {
  "eddsa-rdfc-2022": {
    proofType: DATA_INTEGRITY_PROOF, cryptosuite: "eddsa-rdfc-2022",
    canon: "rdfc", encoding: "proofValue", keys: EDDSA_CURVES,
    vmType: "Multikey",
    spec: "W3C VC Data Integrity EdDSA Cryptosuites v1.0, section 3.2"
  },
  "eddsa-jcs-2022": {
    proofType: DATA_INTEGRITY_PROOF, cryptosuite: "eddsa-jcs-2022",
    canon: "jcs", encoding: "proofValue", keys: EDDSA_CURVES,
    vmType: "Multikey",
    spec: "W3C VC Data Integrity EdDSA Cryptosuites v1.0, section 3.3"
  },
  "ecdsa-rdfc-2019": {
    proofType: DATA_INTEGRITY_PROOF, cryptosuite: "ecdsa-rdfc-2019",
    canon: "rdfc", encoding: "proofValue", keys: ECDSA_CURVES,
    vmType: "Multikey",
    spec: "W3C VC Data Integrity ECDSA Cryptosuites v1.0, section 3.2"
  },
  "ecdsa-jcs-2019": {
    proofType: DATA_INTEGRITY_PROOF, cryptosuite: "ecdsa-jcs-2019",
    canon: "jcs", encoding: "proofValue", keys: ECDSA_CURVES,
    vmType: "Multikey",
    spec: "W3C VC Data Integrity ECDSA Cryptosuites v1.0, section 3.3"
  },
  // ecdsa-rdfc-2019 with a THIRD hash appended: of the optical data printed
  // on the document the barcode is on (vc_barcodes.js computes it), passed
  // as `extraInformation`. SHA-256 for all three hashes on either curve —
  // the TR says ecdsa-rdfc-2019's hash, which on P-384 is SHA-384, and
  // Digital Bazaar's ecdsa-xi-2023-cryptosuite (every published barcode)
  // uses SHA-256; the published barcodes decide [#480].
  "ecdsa-xi-2023": {
    proofType: DATA_INTEGRITY_PROOF, cryptosuite: "ecdsa-xi-2023",
    canon: "rdfc", encoding: "proofValue", keys: ECDSA_CURVES,
    vmType: "Multikey", hash: "sha256", extraInformation: true,
    spec: "W3C Verifiable Credential Barcodes v1.0 (Working Draft), " +
      "section 3.2.4"
  },
  "Ed25519Signature2018": {
    proofType: "Ed25519Signature2018", canon: "rdfc", encoding: "jws",
    keys: EDDSA_CURVES, legacy: true,
    context: "https://w3id.org/security/suites/ed25519-2018/v1",
    vmType: "Ed25519VerificationKey2018",
    spec: "W3C CCG Ed25519 Signature 2018"
  },
  "Ed25519Signature2020": {
    proofType: "Ed25519Signature2020", canon: "rdfc",
    encoding: "proofValue", keys: EDDSA_CURVES, legacy: true,
    context: "https://w3id.org/security/suites/ed25519-2020/v1",
    vmType: "Ed25519VerificationKey2020",
    spec: "W3C CCG Ed25519 Signature 2020"
  },
  "JsonWebSignature2020": {
    proofType: "JsonWebSignature2020", canon: "rdfc", encoding: "jws",
    keys: JWS_2020_CURVES, legacy: true,
    context: "https://w3id.org/security/suites/jws-2020/v1",
    vmType: "JsonWebKey2020",
    spec: "W3C CCG JSON Web Signature 2020"
  },
  "EcdsaSecp256k1Signature2019": {
    proofType: "EcdsaSecp256k1Signature2019", canon: "rdfc",
    encoding: "jws", keys: ["secp256k1"], legacy: true,
    context: "https://w3id.org/security/suites/secp256k1-2019/v1",
    vmType: "EcdsaSecp256k1VerificationKey2019",
    spec: "W3C CCG Ecdsa Secp256k1 Signature 2019"
  }
};

// Proof types and cryptosuites that are recognised but verified elsewhere or
// not at all, with the reason a caller can print.
var VERIFIED_ELSEWHERE = {
  "bbs-2023": "bbs-2023 is selective disclosure: its derived proofs are " +
    "verified by bbs2023.js.",
  "ecdsa-sd-2023": "ecdsa-sd-2023 is selective disclosure: its base and " +
    "derived proofs are verified by ecdsa_sd_2023.js.",
  "BbsBlsSignature2020": "BbsBlsSignature2020 is verified by " +
    "bbs_bls_2020.js, which this page does not load.",
  "BbsBlsSignatureProof2020": "BbsBlsSignatureProof2020 is verified by " +
    "bbs_bls_2020.js, which this page does not load."
};

// The suite id a proof object is an instance of: its cryptosuite when it is a
// DataIntegrityProof, its type otherwise.
function suiteIdOf(proof) {
  log.debug("Entering suiteIdOf().");
  var p = proof || {};
  var id = p.type === DATA_INTEGRITY_PROOF ? String(p.cryptosuite || "") :
      String(p.type || "");
  log.debug("Leaving suiteIdOf(). " + id);
  return id;
}

function suite(id) {
  log.debug("Entering suite(). " + id);
  var row = SUITES[id] || null;
  log.debug("Leaving suite().");
  return row;
}

// Every proof type an ldp_vc may arrive with, whether or not this module is
// the one that verifies it. sd_jwt_vc.js recognises the format by these.
function isRecognisedProof(proof) {
  log.debug("Entering isRecognisedProof().");
  var id = suiteIdOf(proof);
  var ok = !!(SUITES[id] || VERIFIED_ELSEWHERE[id]);
  log.debug("Leaving isRecognisedProof(). " + ok);
  return ok;
}

// The suites a key can sign with, best first. A caller that holds an Ed25519
// key gets the EdDSA suites, a P-256 one the ECDSA suites; JWS 2020 signs
// with anything and is listed last because it is the oldest.
function suitesForKey(jwk) {
  log.debug("Entering suitesForKey().");
  var name = keyName(jwk);
  // A suite that also signs data from outside the document (ecdsa-xi-2023,
  // the optical data of a barcode) is for the caller that has that data,
  // and is not offered for an ordinary credential.
  var out = Object.keys(SUITES).filter(function (id) {
    return SUITES[id].keys.indexOf(name) !== -1 &&
      !SUITES[id].extraInformation;
  });
  log.debug("Leaving suitesForKey(). " + out.join(", "));
  return out;
}

function keyName(jwk) {
  log.debug("Entering keyName().");
  var k = jwk || {};
  log.debug("Leaving keyName().");
  return k.kty === "RSA" ? "RSA" : String(k.crv || "");
}

// ---------------------------------------------------------------------------
// Canonicalization.
// ---------------------------------------------------------------------------

// RFC 8785 JSON Canonicalization Scheme. Member names sort by UTF-16 code
// units, which is what JavaScript's default string comparison is; numbers
// and strings serialise exactly as ECMAScript's JSON.stringify does, which is
// what the RFC adopts.
function jcs(value) {
  log.debug("Entering jcs().");
  var out;
  if (value === null || typeof value !== "object") {
    out = JSON.stringify(value);
  } else if (Array.isArray(value)) {
    out = "[" + value.map(function (v) {
      return jcs(v);
    }).join(",") + "]";
  } else {
    out = "{" + Object.keys(value).filter(function (k) {
      return value[k] !== undefined;
    }).sort().map(function (k) {
      return JSON.stringify(k) + ":" + jcs(value[k]);
    }).join(",") + "}";
  }
  log.debug("Leaving jcs().");
  return out;
}

// RDFC-1.0 to N-Quads, in safe mode (a term that expands to nothing is an
// error, not a silently unsigned claim), with no base IRI, through the
// offline loader. These are jsonld-signatures' own options.
var rdfcCanonize = null;
var jsonldLibrary = null;

// data_integrity_rdfc.js hands in jsonld.canonize — and, for the suites that
// also need to frame and read RDF back (BbsBlsSignatureProof2020), the jsonld
// library itself.
function registerRdfc(canonize, library) {
  log.debug("Entering registerRdfc().");
  rdfcCanonize = canonize;
  jsonldLibrary = library || null;
  log.debug("Leaving registerRdfc().");
}

function jsonldLib() {
  log.debug("Entering jsonldLib().");
  if (!jsonldLibrary) {
    log.debug("Leaving jsonldLib(). Not registered.");
    throw new Error("jsonld is not loaded on this page " +
                    "(data_integrity_rdfc.js registers it).");
  }
  log.debug("Leaving jsonldLib().");
  return jsonldLibrary;
}

// Proof types implemented by a module of their own, registered here when it
// is loaded (bbs_bls_2020.js), so verifyProof() answers for them too and the
// pages that never load them do not carry their curve.
var EXTERNAL_SUITES = {};

function registerSuite(id, impl) {
  log.debug("Entering registerSuite(). " + id);
  EXTERNAL_SUITES[id] = impl;
  log.debug("Leaving registerSuite().");
}

function rdfcAvailable() {
  log.debug("Entering rdfcAvailable().");
  log.debug("Leaving rdfcAvailable().");
  return typeof rdfcCanonize === "function";
}

function rdfc(doc, loader) {
  log.debug("Entering rdfc().");
  if (!rdfcAvailable()) {
    log.debug("Leaving rdfc(). Not registered.");
    return Promise.reject(new Error("RDFC-1.0 canonicalization is not " +
      "loaded on this page (data_integrity_rdfc.js registers it); only the " +
      "JCS cryptosuites are available here."));
  }
  log.debug("Leaving rdfc().");
  return rdfcCanonize(doc, {
    algorithm: "RDFC-1.0",
    format: "application/n-quads",
    base: null,
    safe: true,
    documentLoader: loader || jsonldContexts.documentLoader
  });
}

function canonicalize(row, doc, loader) {
  log.debug("Entering canonicalize(). " + row.canon);
  if (row.canon === "jcs") {
    log.debug("Leaving canonicalize(). JCS.");
    return Promise.resolve(jcs(doc));
  }
  log.debug("Leaving canonicalize(). RDFC.");
  return rdfc(doc, loader);
}

// The hash both halves are digested with: SHA-384 only for an ECDSA suite on
// P-384; every legacy type and every other key is SHA-256.
function hashFor(row, jwk) {
  log.debug("Entering hashFor().");
  if (row.hash) {
    log.debug("Leaving hashFor(). Fixed by the suite.");
    return row.hash;
  }
  var big = !row.legacy && row.keys === ECDSA_CURVES &&
      keyName(jwk) === "P-384";
  log.debug("Leaving hashFor().");
  return big ? "sha384" : "sha256";
}

// ---------------------------------------------------------------------------
// The signature primitive behind a key, and its JWS name.
// ---------------------------------------------------------------------------
var PRIMITIVES = {
  "Ed25519": { alg: "ed25519", jws: "EdDSA" },
  "P-256": { alg: "ecdsa-p256-sha256", jws: "ES256" },
  "P-384": { alg: "ecdsa-p384-sha384", jws: "ES384" },
  "P-521": { alg: "ecdsa-p521-sha512", jws: "ES512" },
  "secp256k1": { alg: "ecdsa-secp256k1-sha256", jws: "ES256K" },
  "RSA": { alg: "rsa-pss-sha256", jws: "PS256" }
};

// An RSA key under JsonWebSignature2020 may sign with any of the RFC 7518
// RSA algorithms; PS256 is what this writes unless told otherwise.
var RSA_JWS = {
  "RS256": "rsa-pkcs1-sha256", "RS384": "rsa-pkcs1-sha384",
  "RS512": "rsa-pkcs1-sha512", "PS256": "rsa-pss-sha256",
  "PS384": "rsa-pss-sha384", "PS512": "rsa-pss-sha512"
};

// The primitive a key signs with under a suite. `jwsAlg` chooses among the
// RSA algorithms; for every other key the curve decides, and a jwsAlg that
// disagrees with it is refused.
function primitiveFor(row, jwk, jwsAlg) {
  log.debug("Entering primitiveFor().");
  var name = keyName(jwk);
  if (row.keys.indexOf(name) === -1) {
    log.debug("Leaving primitiveFor(). Wrong key.");
    throw new Error(suiteIdOfRow(row) + " signs with " +
        row.keys.join(" or ") + " keys; this key is " + (name || "unknown") +
        ".");
  }
  if (name === "RSA" && jwsAlg) {
    if (!RSA_JWS[jwsAlg]) {
      log.debug("Leaving primitiveFor(). Not an RSA alg.");
      throw new Error(jwsAlg + " is not an RSA JWS algorithm (" +
          Object.keys(RSA_JWS).join(", ") + ").");
    }
    log.debug("Leaving primitiveFor(). RSA " + jwsAlg + ".");
    return { alg: RSA_JWS[jwsAlg], jws: jwsAlg };
  }
  if (jwsAlg && jwsAlg !== PRIMITIVES[name].jws) {
    log.debug("Leaving primitiveFor(). alg disagrees with key.");
    throw new Error("a " + name + " key signs " + PRIMITIVES[name].jws +
        ", not " + jwsAlg + ".");
  }
  log.debug("Leaving primitiveFor().");
  return PRIMITIVES[name];
}

function suiteIdOfRow(row) {
  log.debug("Entering suiteIdOfRow().");
  log.debug("Leaving suiteIdOfRow().");
  return row.cryptosuite || row.proofType;
}

function importJwk(jwk) {
  log.debug("Entering importJwk().");
  var clean = Object.assign({}, jwk);
  delete clean.key_ops;
  delete clean.ext;
  // An Ed25519 `d` of 64 bytes is the NaCl secret key (seed || public key),
  // which some libraries export where RFC 8037 says the 32-byte seed. It is
  // read as the seed when its second half really is this key's `x`.
  if (clean.kty === "OKP" && clean.crv === "Ed25519" && clean.d) {
    var d = cbytes.b64uToBytes(clean.d);
    if (d.length === 64 && clean.x &&
        cbytes.bytesToB64u(d.slice(32)) === clean.x) {
      log.debug("importJwk(): 64-byte Ed25519 d read as seed || public.");
      clean.d = cbytes.bytesToB64u(d.slice(0, 32));
    }
  }
  log.debug("Leaving importJwk().");
  return provider.importKey(clean, { format: "jwk" });
}

// ---------------------------------------------------------------------------
// The data that is signed.
// ---------------------------------------------------------------------------

function contextsEqual(a, b) {
  log.debug("Entering contextsEqual().");
  log.debug("Leaving contextsEqual().");
  return jcs(a === undefined ? null : a) === jcs(b === undefined ? null : b);
}

// The proof options as they are canonicalized. `variant` is "document" (the
// rule for each type) or "security-v2" (the pre-2020 legacy reading).
function proofOptions(row, proof, unsecured, variant) {
  log.debug("Entering proofOptions(). " + variant);
  var opts = Object.assign({}, proof);
  delete opts.proofValue;
  delete opts.jws;
  delete opts.signatureValue;
  if (!row.legacy && row.canon === "jcs") {
    // The JCS suites hash the options EXACTLY as the proof carries them: the
    // signer put the document's @context into the proof, and it stays there.
    // "implicit-context" is the non-conformant reading in which a signer
    // hashed that @context and then left it out of the proof it wrote.
    if (variant === "implicit-context" &&
        unsecured["@context"] !== undefined) {
      opts["@context"] = unsecured["@context"];
    }
  } else if (!row.legacy) {
    if (unsecured["@context"] !== undefined) {
      opts["@context"] = unsecured["@context"];
    } else {
      delete opts["@context"];
    }
  } else if (variant === "security-v2") {
    opts["@context"] = jsonldContexts.SECURITY_V2_URL;
  } else if (opts["@context"] === undefined) {
    opts["@context"] = unsecured["@context"] !== undefined ?
        unsecured["@context"] : jsonldContexts.SECURITY_V2_URL;
  }
  log.debug("Leaving proofOptions().");
  return opts;
}

// hash(canonical options) || hash(canonical document), and for a suite that
// takes extra information, || hash(extra).
async function verifyData(row, proof, unsecured, jwk, variant, loader,
                          extra) {
  log.debug("Entering verifyData().");
  var hash = hashFor(row, jwk);
  var options = proofOptions(row, proof, unsecured, variant);
  var texts = await Promise.all([canonicalize(row, options, loader),
                                 canonicalize(row, unsecured, loader)]);
  var parts = [provider.digest(hash, cbytes.strBytes(texts[0])),
               provider.digest(hash, cbytes.strBytes(texts[1]))];
  if (row.extraInformation) {
    parts.push(provider.digest(hash, cbytes.asBytes(extra)));
  }
  log.debug("Leaving verifyData().");
  return {
    data: cbytes.concatBytes.apply(null, parts),
    canonicalOptions: texts[0],
    canonicalDocument: texts[1],
    hash: hash
  };
}

// The RFC 7797 detached-payload JWS header these suites write.
function jwsHeader(alg) {
  log.debug("Entering jwsHeader().");
  log.debug("Leaving jwsHeader().");
  return { alg: alg, b64: false, crit: ["b64"] };
}

function jwsSigningInput(encodedHeader, data) {
  log.debug("Entering jwsSigningInput().");
  log.debug("Leaving jwsSigningInput().");
  return cbytes.concatBytes(cbytes.strBytes(encodedHeader + "."), data);
}

function unsecuredOf(doc) {
  log.debug("Entering unsecuredOf().");
  var out = Object.assign({}, doc);
  delete out.proof;
  log.debug("Leaving unsecuredOf().");
  return out;
}

function toArray(v) {
  log.debug("Entering toArray().");
  log.debug("Leaving toArray().");
  return v === undefined || v === null ? [] : [].concat(v);
}

// ---------------------------------------------------------------------------
// Creating a proof.
// ---------------------------------------------------------------------------

// Whether one of the document's contexts that this debugger ships already
// defines `term`. credentials/v1 defines Ed25519Signature2018 and
// EcdsaSecp256k1Signature2019 itself, as PROTECTED terms, so adding the
// suite's own context to such a document is a JSON-LD error rather than a
// harmless repeat; credentials/v2 defines DataIntegrityProof.
function contextDefines(contexts, term) {
  log.debug("Entering contextDefines(). " + term);
  var found = contexts.some(function (c) {
    var shipped = typeof c === "string" ? jsonldContexts.CONTEXTS[c] : null;
    var defs = shipped ? toArray(shipped["@context"]) : [c];
    return defs.some(function (d) {
      return d && typeof d === "object" &&
        Object.prototype.hasOwnProperty.call(d, term);
    });
  });
  log.debug("Leaving contextDefines(). " + found);
  return found;
}

// The @context a document must carry to be signed with `id`: one that
// defines the proof type, adding the suite's own context (or, for a
// DataIntegrityProof, data-integrity/v2) when none does. Answers a NEW
// document; the input is not changed.
function withSuiteContext(doc, id) {
  log.debug("Entering withSuiteContext(). " + id);
  var row = suite(id);
  var ctx = toArray(doc["@context"]);
  if (contextDefines(ctx, row.proofType)) {
    log.debug("Leaving withSuiteContext(). Already defined.");
    return doc;
  }
  var need = row.legacy ? row.context : jsonldContexts.DATA_INTEGRITY_V2_URL;
  var out = Object.assign({}, doc);
  out["@context"] = ctx.concat([need]);
  log.debug("Leaving withSuiteContext(). Added " + need + ".");
  return out;
}

function xsdDateTime(when) {
  log.debug("Entering xsdDateTime().");
  log.debug("Leaving xsdDateTime().");
  return new Date(when === undefined ? Date.now() : when).toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

// opts: { suite, privateJwk, verificationMethod, jwsAlg (an RSA key's
// algorithm under JsonWebSignature2020), proofPurpose ("assertionMethod"
// by default), created (a Date, a millisecond count, or false for none),
// challenge, domain, expires, nonce, addContext (default true),
// documentLoader, extraInformation (bytes; ecdsa-xi-2023 only) }. Answers
// the secured document: a NEW object with the
// suite's context added when it was missing and `proof` set (appended to an
// existing proof as a proof set).
async function createProof(doc, opts) {
  log.debug("Entering createProof(). " + (opts && opts.suite));
  var o = opts || {};
  var row = suite(o.suite);
  if (!row) {
    log.debug("Leaving createProof(). Unknown suite.");
    throw new Error("No proof type or cryptosuite " +
        JSON.stringify(o.suite) + " here; known: " +
        Object.keys(SUITES).join(", ") + ".");
  }
  if (!o.privateJwk || !o.verificationMethod) {
    log.debug("Leaving createProof(). Missing key or method.");
    throw new Error("A proof needs a private key and a verificationMethod.");
  }
  if (row.extraInformation && !o.extraInformation) {
    log.debug("Leaving createProof(). No extra information.");
    throw new Error(o.suite + " also signs data from outside the document " +
        "(extraInformation), and none was given.");
  }
  var prim = primitiveFor(row, o.privateJwk,
                          row.encoding === "jws" ? o.jwsAlg : undefined);
  var base = o.addContext === false ? doc : withSuiteContext(doc, o.suite);
  var unsecured = unsecuredOf(base);
  var proof = { type: row.proofType };
  if (row.cryptosuite) proof.cryptosuite = row.cryptosuite;
  if (o.created !== false) proof.created = xsdDateTime(o.created);
  if (o.expires) proof.expires = xsdDateTime(o.expires);
  proof.verificationMethod = o.verificationMethod;
  proof.proofPurpose = o.proofPurpose || "assertionMethod";
  if (o.challenge !== undefined) proof.challenge = o.challenge;
  if (o.domain !== undefined) proof.domain = o.domain;
  if (o.nonce !== undefined) proof.nonce = o.nonce;
  // eddsa-jcs-2022 / ecdsa-jcs-2019, Proof Configuration step 2: the
  // document's @context goes into the proof, and is part of what is signed
  // AND of what is sent.
  if (row.canon === "jcs" && unsecured["@context"] !== undefined) {
    proof["@context"] = unsecured["@context"];
  }
  var vd = await verifyData(row, proof, unsecured, o.privateJwk, "document",
                            o.documentLoader, o.extraInformation);
  var key = importJwk(o.privateJwk);
  // ECDSA is hedged by default (crypto_provider.js); opts.deterministic
  // asks for plain RFC 6979, which only a known-answer test needs.
  var signOpts = { deterministic: !!o.deterministic };
  if (row.encoding === "jws") {
    var encoded = cbytes.bytesToB64u(cbytes.strBytes(
        JSON.stringify(jwsHeader(prim.jws))));
    var sig = provider.sign(prim.alg, key, jwsSigningInput(encoded, vd.data),
                            signOpts);
    proof.jws = encoded + ".." + cbytes.bytesToB64u(sig);
  } else {
    proof.proofValue = "z" + didLib.base58Encode(
        provider.sign(prim.alg, key, vd.data, signOpts));
  }
  var out = Object.assign({}, base);
  var existing = toArray(doc.proof);
  out.proof = existing.length ? existing.concat([proof]) : proof;
  log.debug("Leaving createProof().");
  return out;
}

// ---------------------------------------------------------------------------
// Verifying.
// ---------------------------------------------------------------------------

// The key a verification method document carries, as a JWK, whichever of the
// spellings a legacy method type uses.
function methodToJwk(method) {
  log.debug("Entering methodToJwk().");
  var m = method || {};
  if (m.publicKeyJwk) {
    log.debug("Leaving methodToJwk(). publicKeyJwk.");
    return m.publicKeyJwk;
  }
  if (m.jwk) {
    log.debug("Leaving methodToJwk(). Normalized by did.js.");
    return m.jwk;
  }
  if (m.publicKeyMultibase) {
    log.debug("Leaving methodToJwk(). publicKeyMultibase.");
    return didKeyJwk("did:key:" + m.publicKeyMultibase);
  }
  if (m.publicKeyBase58) {
    var raw = didLib.base58Decode(m.publicKeyBase58);
    if (m.type === "Ed25519VerificationKey2018" && raw.length === 32) {
      log.debug("Leaving methodToJwk(). Ed25519 base58.");
      return { kty: "OKP", crv: "Ed25519", x: cbytes.bytesToB64u(raw) };
    }
    if (m.type === "EcdsaSecp256k1VerificationKey2019" && raw.length === 33) {
      log.debug("Leaving methodToJwk(). secp256k1 base58.");
      return secp256k1Jwk(raw);
    }
  }
  log.debug("Leaving methodToJwk(). No key.");
  return null;
}

// A compressed secp256k1 point as a JWK. did.js decompresses the NIST curves
// and has no secp256k1 parameters, so @noble's curve does it here.
function secp256k1Jwk(compressed) {
  log.debug("Entering secp256k1Jwk().");
  var full = secp256k1.ProjectivePoint.fromHex(cbytes.bytesToHex(compressed))
    .toRawBytes(false);
  log.debug("Leaving secp256k1Jwk().");
  return { kty: "EC", crv: "secp256k1",
           x: cbytes.bytesToB64u(full.slice(1, 33)),
           y: cbytes.bytesToB64u(full.slice(33, 65)) };
}

// A did:key, including the secp256k1 multicodec (0xe7) did.js cannot
// decompress.
function didKeyJwk(did) {
  log.debug("Entering didKeyJwk().");
  var id = did.slice("did:key:".length);
  if (id.charAt(0) === "z") {
    var raw = didLib.base58Decode(id.slice(1));
    if (raw[0] === 0xe7 && raw[1] === 0x01 && raw.length === 35) {
      log.debug("Leaving didKeyJwk(). secp256k1.");
      return secp256k1Jwk(raw.slice(2));
    }
  }
  log.debug("Leaving didKeyJwk().");
  return didLib.didKeyToJwk(did);
}

// A resolver for callers that have no policy of their own: did:key and
// did:jwk read in place, other DIDs and https URLs through did.js with the
// caller's fetch. The Verifier passes its own instead.
// options.allowHttp lets did:web fall back to plain http, for the stacks
// here that serve a DID document without TLS (did.js tries https first).
function defaultResolveKey(fetchImpl, options) {
  log.debug("Entering defaultResolveKey().");
  var allowHttp = !!(options && options.allowHttp);
  log.debug("Leaving defaultResolveKey().");
  return function resolveKey(vm) {
    log.debug("Entering resolveKey(). " + String(vm).slice(0, 80));
    var url = String(vm || "");
    var did = url.split("#")[0];
    try {
      if (/^did:key:/.test(did)) {
        log.debug("Leaving resolveKey(). did:key.");
        return Promise.resolve(didKeyJwk(did));
      }
      if (/^did:jwk:/.test(did)) {
        log.debug("Leaving resolveKey(). did:jwk.");
        return Promise.resolve(didLib.didJwkToJwk(did));
      }
    } catch (e) {
      log.debug("Leaving resolveKey(). Undecodable DID.");
      return Promise.reject(e);
    }
    log.debug("Leaving resolveKey(). Resolving.");
    return didLib.resolveVerificationMethod(url, { allowHttp: allowHttp,
      fetch: fetchImpl }).then(function (r) {
      return methodToJwk(r.method);
    });
  };
}

function verifySignature(row, prim, jwk, proof, data) {
  log.debug("Entering verifySignature().");
  var key = importJwk(jwk);
  if (row.encoding === "jws") {
    var parts = String(proof.jws || "").split(".");
    if (parts.length !== 3 || parts[1] !== "") {
      log.debug("Leaving verifySignature(). Not detached.");
      return { valid: false, reason: "jws is not a detached JWS " +
               "(header..signature)." };
    }
    var header;
    try {
      header = JSON.parse(cbytes.bytesToStr(cbytes.b64uToBytes(parts[0])));
    } catch (e) {
      log.debug("Leaving verifySignature(). Bad header.");
      return { valid: false, reason: "the JWS header is not JSON." };
    }
    if (header.b64 !== false || toArray(header.crit).indexOf("b64") === -1) {
      log.debug("Leaving verifySignature(). b64.");
      return { valid: false, reason: "the JWS header must carry " +
               "\"b64\": false and name it in \"crit\" (RFC 7797)." };
    }
    if (keyName(jwk) === "RSA" && RSA_JWS[header.alg]) {
      prim = { alg: RSA_JWS[header.alg], jws: header.alg };
    }
    if (header.alg !== prim.jws) {
      log.debug("Leaving verifySignature(). alg.");
      return { valid: false, reason: "the JWS alg is " +
               JSON.stringify(header.alg) + " and the key is " +
               keyName(jwk) + ", which signs " + prim.jws + "." };
    }
    var ok = provider.verify(prim.alg, key, jwsSigningInput(parts[0], data),
                             cbytes.b64uToBytes(parts[2]));
    log.debug("Leaving verifySignature(). JWS " + ok);
    return { valid: ok, alg: header.alg };
  }
  var pv = String(proof.proofValue || "");
  if (pv.charAt(0) !== "z") {
    log.debug("Leaving verifySignature(). Not base58btc.");
    return { valid: false, reason: "proofValue is not multibase base58btc " +
             "(it must begin \"z\")." };
  }
  var sig;
  try {
    sig = didLib.base58Decode(pv.slice(1));
  } catch (e) {
    log.debug("Leaving verifySignature(). Bad base58.");
    return { valid: false, reason: "proofValue: " + e.message };
  }
  var good = provider.verify(prim.alg, key, data, sig);
  log.debug("Leaving verifySignature(). " + good);
  return { valid: good, alg: prim.jws };
}

// What a signature that verifies only under a non-conformant reading says
// about its signer.
var DIAGNOSES = {
  "implicit-context": function (id) {
    log.debug("Entering DIAGNOSES.implicit-context().");
    log.debug("Leaving DIAGNOSES.implicit-context().");
    return "the signature does not verify as " + id + " defines it, and " +
      "WOULD verify had the document's @context been added to proof " +
      "options that do not carry it: the signer hashed an @context it did " +
      "not write into the proof (" + id + " Proof Configuration step 2 " +
      "requires the proof to carry it).";
  },
  "security-v2": function (id) {
    log.debug("Entering DIAGNOSES.security-v2().");
    log.debug("Leaving DIAGNOSES.security-v2().");
    return "the signature does not verify with the proof options read " +
      "under the document's @context, and WOULD verify read under " +
      "https://w3id.org/security/v2: the signer used the pre-2020 " +
      "jsonld-signatures canonicalization of " + id + "'s options.";
  }
};

// Canonicalize, hash and check the signature under one reading.
async function readSignature(row, prim, jwk, proof, unsecured, variant,
                             loader, extra) {
  log.debug("Entering readSignature(). " + variant);
  var vd;
  try {
    vd = await verifyData(row, proof, unsecured, jwk, variant, loader,
                          extra);
  } catch (e) {
    log.debug("Leaving readSignature(). Canonicalization failed.");
    return { valid: false, reason: "canonicalization failed (every " +
      "@context must be one this debugger ships or was given, and every " +
      "term defined): " + e.message };
  }
  var r = verifySignature(row, prim, jwk, proof, vd.data);
  log.debug("Leaving readSignature(). " + r.valid);
  return r;
}

// One proof on one document. opts: { resolveKey(vm) -> Promise<JWK>,
// documentLoader, fetch (for the default resolver), extraInformation
// (ecdsa-xi-2023) }. Answers
//   { valid, unsupported, reason, suite, proofType, verificationMethod,
//     proofPurpose, challenge, domain, created, expires, jwk, alg,
//     diagnosis, spec }
// `diagnosis` is set on an INVALID proof that would have verified under a
// reading the specification does not allow, and names that defect.
// and never throws for a bad proof: a reason is the answer.
async function verifyOneProof(doc, proof, opts) {
  log.debug("Entering verifyOneProof().");
  var o = opts || {};
  var p = proof || {};
  var id = suiteIdOf(p);
  var row = suite(id);
  var out = { valid: false, suite: id, proofType: String(p.type || ""),
              verificationMethod: String(p.verificationMethod || ""),
              proofPurpose: p.proofPurpose, challenge: p.challenge,
              domain: p.domain, created: p.created, expires: p.expires };
  if (!row && EXTERNAL_SUITES[id]) {
    var ext = await EXTERNAL_SUITES[id].verify(doc, p, o);
    log.debug("Leaving verifyOneProof(). " + id + " " + !!ext.valid);
    return Object.assign(out, ext);
  }
  if (!row) {
    log.debug("Leaving verifyOneProof(). Unsupported.");
    return Object.assign(out, { unsupported: true,
      reason: VERIFIED_ELSEWHERE[id] || "proof " + JSON.stringify(id) +
        " is not a type this debugger knows (" +
        Object.keys(SUITES).join(", ") + ")." });
  }
  out.spec = row.spec;
  if (row.extraInformation && !o.extraInformation) {
    log.debug("Leaving verifyOneProof(). No extra information.");
    return Object.assign(out, { reason: id + " also signs data from " +
      "outside the credential (for VC Barcodes, the optical data printed " +
      "on the document), and none was given to check it against." });
  }
  if (row.proofType !== p.type) {
    log.debug("Leaving verifyOneProof(). Type/suite mismatch.");
    return Object.assign(out, { reason: id + " is a " + row.proofType +
                                ", not a " + p.type + "." });
  }
  var unsecured = unsecuredOf(doc);
  if (!row.legacy && row.canon === "jcs" && p["@context"] !== undefined) {
    // Verify Proof (JCS suites) step 4: the document's @context must START
    // WITH the proof's, in order, and the unsecured document is then read
    // under the proof's.
    var pc = toArray(p["@context"]);
    var dc = toArray(unsecured["@context"]);
    var prefix = pc.every(function (c, i) {
      return contextsEqual(c, dc[i]);
    });
    if (!prefix) {
      log.debug("Leaving verifyOneProof(). JCS context not a prefix.");
      return Object.assign(out, { reason: "the document's @context does " +
        "not begin with the proof's @context (" + id + " requires it to)." });
    }
    unsecured["@context"] = p["@context"];
  } else if (!row.legacy && p["@context"] !== undefined &&
      !contextsEqual(p["@context"], unsecured["@context"])) {
    log.debug("Leaving verifyOneProof(). Context mismatch.");
    return Object.assign(out, { reason: "the proof carries an @context " +
      "that is not the document's (a DataIntegrityProof's must be equal " +
      "to it)." });
  }
  var resolveKey = o.resolveKey || defaultResolveKey(o.fetch);
  var jwk;
  try {
    jwk = await resolveKey(out.verificationMethod);
  } catch (e) {
    log.debug("Leaving verifyOneProof(). Key unresolved.");
    return Object.assign(out, { reason: "verificationMethod " +
      out.verificationMethod + " could not be resolved: " + e.message });
  }
  if (!jwk) {
    log.debug("Leaving verifyOneProof(). No key.");
    return Object.assign(out, { reason: "verificationMethod " +
      out.verificationMethod + " resolves to no key." });
  }
  out.jwk = jwk;
  var prim;
  try {
    prim = primitiveFor(row, jwk);
  } catch (e) {
    log.debug("Leaving verifyOneProof(). Wrong key type.");
    return Object.assign(out, { reason: e.message });
  }
  // The specification's reading decides. When it fails, the readings a
  // non-conformant signer is known to use are tried ONLY to say what went
  // wrong: a proof that verifies under one of them is still invalid, and the
  // reason names the defect (#475; the debugger implements the spec, and
  // compatibility with such signers is not its job).
  var spec = await readSignature(row, prim, jwk, p, unsecured, "document",
                                 o.documentLoader, o.extraInformation);
  Object.assign(out, spec);
  if (!out.valid) {
    var alternatives = row.legacy ? ["security-v2"] :
        (row.canon === "jcs" && p["@context"] === undefined ?
         ["implicit-context"] : []);
    for (var i = 0; i < alternatives.length; i++) {
      var alt = await readSignature(row, prim, jwk, p, unsecured,
                                    alternatives[i], o.documentLoader);
      if (alt.valid) {
        out.diagnosis = DIAGNOSES[alternatives[i]](id);
        out.reason = out.diagnosis;
        break;
      }
    }
  }
  if (!out.valid && !out.reason) {
    out.reason = "the signature does not verify with " +
      out.verificationMethod + " over this document.";
  }
  log.debug("Leaving verifyOneProof(). " + out.valid);
  return out;
}

// Every proof on a document (a proof set is several). `valid` is true when
// there is at least one proof and every proof verified.
async function verifyProof(doc, opts) {
  log.debug("Entering verifyProof().");
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    log.debug("Leaving verifyProof(). Not an object.");
    return { valid: false, proofs: [], reason: "not a JSON object." };
  }
  var proofs = toArray(doc.proof);
  if (!proofs.length) {
    log.debug("Leaving verifyProof(). No proof.");
    return { valid: false, proofs: [], reason: "there is no proof." };
  }
  var results = [];
  for (var i = 0; i < proofs.length; i++) {
    results.push(await verifyOneProof(doc, proofs[i], opts));
  }
  var valid = results.every(function (r) {
    return r.valid;
  });
  log.debug("Leaving verifyProof(). " + valid);
  return { valid: valid, proofs: results,
           reason: valid ? "" : (results.filter(function (r) {
             return !r.valid;
           })[0] || {}).reason };
}

module.exports = {
  DATA_INTEGRITY_PROOF: DATA_INTEGRITY_PROOF,
  SUITES: SUITES,
  VERIFIED_ELSEWHERE: VERIFIED_ELSEWHERE,
  PRIMITIVES: PRIMITIVES,
  RSA_JWS: RSA_JWS,
  suite: suite,
  suiteIdOf: suiteIdOf,
  isRecognisedProof: isRecognisedProof,
  suitesForKey: suitesForKey,
  jcs: jcs,
  rdfc: rdfc,
  registerRdfc: registerRdfc,
  jsonldLib: jsonldLib,
  registerSuite: registerSuite,
  rdfcAvailable: rdfcAvailable,
  withSuiteContext: withSuiteContext,
  methodToJwk: methodToJwk,
  didKeyJwk: didKeyJwk,
  defaultResolveKey: defaultResolveKey,
  createProof: createProof,
  verifyProof: verifyProof,
  verifyOneProof: verifyOneProof
};
