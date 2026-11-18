// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ecdsa_sd_2023.js
//
// ---------------------------------------------------------------------------
// The `ecdsa-sd-2023` Data Integrity cryptosuite (W3C VC Data Integrity
// ECDSA Cryptosuites v1.0, sections 3.4 to 3.6): selective disclosure with
// ordinary ECDSA signatures, over the selective-disclosure functions of VC
// Data Integrity 1.1 in di_selective.js (#476).
//
// What makes it different from bbs-2023, which shares those functions:
//
//   * there is no zero-knowledge proof. The ISSUER signs every non-mandatory
//     statement separately with a one-time P-256 key made for this proof,
//     and signs with its own key only proofHash || that one-time public key
//     || mandatoryHash. A holder discloses a statement by handing over its
//     signature, so two presentations of one credential are LINKABLE — the
//     same signatures appear in both — which bbs-2023 exists to avoid;
//   * blank nodes are relabelled with the HMAC of their canonical label,
//     "u" + base64url, NOT sorted into b0, b1... (hmacIdLabels());
//   * the proof values are CBOR tagged 0xd95d00 (base: [baseSignature,
//     publicKey, hmacKey, signatures, mandatoryPointers]) and 0xd95d01
//     (derived: [baseSignature, publicKey, signatures, compressed label map
//     c14nN -> HMAC bytes, mandatoryIndexes]).
//
// The issuer's key is P-256: section 3.5.8 (parseDerivedProofValue)
// requires the base signature to be "a byte array of length 64", which only
// a P-256 signature is, and Digital Bazaar's and iya-sts's implementations
// both enforce it. The one-time key is P-256 too, and the proof hash and
// mandatory hash are SHA-256. (The same sentence gives the public key's
// length as 36; a P-256 Multikey is 35 bytes, 0x8024 and a compressed point,
// which is what every implementation, this one included, writes and reads.)
// All cryptography is crypto_provider.js, pure JS.
//
// Loading this module registers the cryptosuite with data_integrity.js, so
// its verifyProof() answers for a base proof and for a derived one.
// NO DOM.
// ---------------------------------------------------------------------------

var di = require("./di_selective");
var dataIntegrity = require("./data_integrity");
var provider = require("./crypto_provider");
var bytes = require("./crypto_bytes");
var cbor = require("./cbor");
// The deterministic CBOR ENCODER; cbor.js only decodes.
var mdoc = require("./mdoc");
var didLib = require("./did");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "ecdsa_sd_2023",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var CRYPTOSUITE = "ecdsa-sd-2023";
var PROOF_TYPE = "DataIntegrityProof";
var BASE_HEADER = [0xd9, 0x5d, 0x00];
var DERIVED_HEADER = [0xd9, 0x5d, 0x01];
// The Multikey prefix of a compressed P-256 public key (multicodec 0x1200).
var P256_MULTIKEY = [0x80, 0x24];
var HMAC_KEY_LENGTH = 32;
var SPEC = "W3C VC Data Integrity ECDSA Cryptosuites v1.0, sections " +
  "3.4-3.6 (ecdsa-sd-2023)";

function startsWith(data, prefix) {
  log.debug("Entering startsWith().");
  var ok = prefix.every(function (b, i) {
    return data[i] === b;
  });
  log.debug("Leaving startsWith(). " + ok);
  return ok;
}

function decodeProofValue(proofValue) {
  log.debug("Entering decodeProofValue().");
  var text = String(proofValue || "");
  if (text.charAt(0) !== "u") {
    log.debug("Leaving decodeProofValue(). Not base64url.");
    throw new Error("an ecdsa-sd-2023 proofValue is multibase " +
                    "base64url-no-pad (it must begin with \"u\").");
  }
  log.debug("Leaving decodeProofValue().");
  return bytes.b64uToBytes(text.slice(1));
}

function encodeProofValue(header, items) {
  log.debug("Entering encodeProofValue().");
  log.debug("Leaving encodeProofValue().");
  return "u" + bytes.bytesToB64u(bytes.concatBytes(new Uint8Array(header),
                                                   mdoc.encode(items)));
}

function isBytes(v, length) {
  log.debug("Entering isBytes().");
  log.debug("Leaving isBytes().");
  return v instanceof Uint8Array && (length === undefined ||
                                     v.length === length);
}

// Which proof value it is: "base", "derived", or "" for neither.
function proofValueKind(proofValue) {
  log.debug("Entering proofValueKind().");
  var data;
  try {
    data = decodeProofValue(proofValue);
  } catch (e) {
    log.debug("Leaving proofValueKind(). Undecodable.");
    return "";
  }
  var kind = startsWith(data, BASE_HEADER) ? "base" :
    startsWith(data, DERIVED_HEADER) ? "derived" : "";
  log.debug("Leaving proofValueKind(). " + kind);
  return kind;
}

function serializeBaseProofValue(c) {
  log.debug("Entering serializeBaseProofValue().");
  log.debug("Leaving serializeBaseProofValue().");
  return encodeProofValue(BASE_HEADER, [c.baseSignature, c.publicKey,
    c.hmacKey, c.signatures, c.mandatoryPointers]);
}

function parseBaseProofValue(proofValue) {
  log.debug("Entering parseBaseProofValue().");
  var data = decodeProofValue(proofValue);
  if (!startsWith(data, BASE_HEADER)) {
    log.debug("Leaving parseBaseProofValue(). Wrong header.");
    throw new Error("not an ecdsa-sd-2023 base proof (the CBOR does not " +
                    "begin 0xd95d00).");
  }
  var items = cbor.decode(data.slice(BASE_HEADER.length));
  if (!Array.isArray(items) || items.length !== 5 || !isBytes(items[0]) ||
      !isBytes(items[1], 35) || !isBytes(items[2], HMAC_KEY_LENGTH) ||
      !Array.isArray(items[3]) || !items[3].every(function (s) {
        return isBytes(s, 64);
      }) || !Array.isArray(items[4])) {
    log.debug("Leaving parseBaseProofValue(). Malformed.");
    throw new Error("malformed ecdsa-sd-2023 base proof: expected " +
      "[baseSignature, 35-byte publicKey, 32-byte hmacKey, 64-byte " +
      "signatures, mandatoryPointers].");
  }
  log.debug("Leaving parseBaseProofValue().");
  return { baseSignature: items[0], publicKey: items[1], hmacKey: items[2],
           signatures: items[3], mandatoryPointers: items[4] };
}

// c14nN -> "u" + base64url(HMAC) becomes N -> HMAC bytes, and back.
function compressLabelMap(labelMap) {
  log.debug("Entering compressLabelMap().");
  var out = new Map();
  labelMap.forEach(function (to, from) {
    out.set(parseInt(String(from).replace(/^c14n/, ""), 10),
            bytes.b64uToBytes(String(to).slice(1)));
  });
  log.debug("Leaving compressLabelMap().");
  return out;
}

function decompressLabelMap(compressed) {
  log.debug("Entering decompressLabelMap().");
  if (!(compressed instanceof Map)) {
    log.debug("Leaving decompressLabelMap(). Not a map.");
    throw new Error("malformed ecdsa-sd-2023 derived proof: the label map " +
                    "is not a CBOR map.");
  }
  var out = new Map();
  compressed.forEach(function (to, from) {
    if (!Number.isInteger(from) || from < 0 || !isBytes(to)) {
      throw new Error("malformed ecdsa-sd-2023 derived proof: a label map " +
                      "entry is not an integer and bytes.");
    }
    out.set("c14n" + from, "u" + bytes.bytesToB64u(to));
  });
  log.debug("Leaving decompressLabelMap().");
  return out;
}

function serializeDerivedProofValue(c) {
  log.debug("Entering serializeDerivedProofValue().");
  log.debug("Leaving serializeDerivedProofValue().");
  return encodeProofValue(DERIVED_HEADER, [c.baseSignature, c.publicKey,
    c.signatures, compressLabelMap(c.labelMap), c.mandatoryIndexes]);
}

function parseDerivedProofValue(proofValue) {
  log.debug("Entering parseDerivedProofValue().");
  var data = decodeProofValue(proofValue);
  if (!startsWith(data, DERIVED_HEADER)) {
    log.debug("Leaving parseDerivedProofValue(). Wrong header.");
    throw new Error("not an ecdsa-sd-2023 derived proof (the CBOR does not " +
                    "begin 0xd95d01).");
  }
  var items = cbor.decode(data.slice(DERIVED_HEADER.length));
  if (!Array.isArray(items) || items.length !== 5 || !isBytes(items[0]) ||
      !isBytes(items[1], 35) || !Array.isArray(items[2]) ||
      !items[2].every(function (s) {
        return isBytes(s, 64);
      }) || !Array.isArray(items[4]) || !items[4].every(Number.isInteger)) {
    log.debug("Leaving parseDerivedProofValue(). Malformed.");
    throw new Error("malformed ecdsa-sd-2023 derived proof: expected " +
      "[baseSignature, 35-byte publicKey, 64-byte signatures, label map, " +
      "mandatoryIndexes].");
  }
  log.debug("Leaving parseDerivedProofValue().");
  return { baseSignature: items[0], publicKey: items[1],
           signatures: items[2], labelMap: decompressLabelMap(items[3]),
           mandatoryIndexes: items[4] };
}

// The one-time P-256 key, as the 35-byte Multikey the proof carries, and
// back as a JWK.
function multikeyBytes(publicJwk) {
  log.debug("Entering multikeyBytes().");
  var compressed = didLib.compressPoint("P-256",
    bytes.b64uToBytes(publicJwk.x), bytes.b64uToBytes(publicJwk.y));
  log.debug("Leaving multikeyBytes().");
  return bytes.concatBytes(new Uint8Array(P256_MULTIKEY), compressed);
}

function multikeyJwk(publicKey) {
  log.debug("Entering multikeyJwk().");
  if (!startsWith(publicKey, P256_MULTIKEY)) {
    log.debug("Leaving multikeyJwk(). Not P-256.");
    throw new Error("the proof's one-time public key is not a P-256 " +
                    "Multikey (0x8024).");
  }
  log.debug("Leaving multikeyJwk().");
  return didLib.didKeyToJwk("did:key:z" + didLib.base58Encode(publicKey));
}

// The issuer key's ECDSA: P-256/SHA-256, the only curve whose signature
// is the 64 bytes section 3.5.8 requires.
function issuerAlg(jwk) {
  log.debug("Entering issuerAlg().");
  var crv = String((jwk || {}).crv || "");
  var alg = crv === "P-256" ? "ecdsa-p256-sha256" : "";
  if (!alg) {
    log.debug("Leaving issuerAlg(). Wrong key.");
    throw new Error("ecdsa-sd-2023's base signature is 64 bytes " +
                    "(section 3.5.8), so its issuer key is P-256; this key " +
                    "is " + (crv || (jwk || {}).kty) + ".");
  }
  log.debug("Leaving issuerAlg(). " + alg);
  return alg;
}

function importJwk(jwk) {
  log.debug("Entering importJwk().");
  var clean = Object.assign({}, jwk);
  delete clean.key_ops;
  delete clean.ext;
  delete clean.alg;
  log.debug("Leaving importJwk().");
  return provider.importKey(clean, { format: "jwk" });
}

function mandatoryHash(statements) {
  log.debug("Entering mandatoryHash().");
  log.debug("Leaving mandatoryHash().");
  return di.sha256(bytes.strBytes(statements.join("")));
}

function theProof(secured) {
  log.debug("Entering theProof().");
  var p = [].concat((secured && secured.proof) || []).filter(function (x) {
    return x && x.type === PROOF_TYPE && x.cryptosuite === CRYPTOSUITE;
  })[0];
  if (!p) {
    log.debug("Leaving theProof(). None.");
    throw new Error("the document carries no ecdsa-sd-2023 proof.");
  }
  log.debug("Leaving theProof().");
  return p;
}

// ---------------------------------------------------------------------------
// The issuer's base proof (section 3.5). opts: { privateJwk (P-256
// only), verificationMethod, mandatoryPointers, proofPurpose, created,
// hmacKey }. Answers the secured credential.
// ---------------------------------------------------------------------------
async function createBaseProof(unsecured, opts) {
  log.debug("Entering createBaseProof().");
  var o = opts || {};
  var alg = issuerAlg(o.privateJwk);
  var document = di.withoutProof(unsecured);
  var proof = { type: PROOF_TYPE, cryptosuite: CRYPTOSUITE };
  if (o.created !== false) {
    proof.created = new Date(o.created === undefined ? Date.now() :
                             o.created).toISOString()
      .replace(/\.\d{3}Z$/, "Z");
  }
  proof.verificationMethod = o.verificationMethod;
  proof.proofPurpose = o.proofPurpose || "assertionMethod";
  var mandatoryPointers = (o.mandatoryPointers || []).slice();
  var hmacKey = o.hmacKey || bytes.randomBytes(HMAC_KEY_LENGTH);
  var proofHash = await di.proofHash(document, proof);
  var grouped = await di.canonicalizeAndGroup(document,
    di.hmacIdLabels(hmacKey), { mandatory: mandatoryPointers });
  var mandatory = Array.from(grouped.groups.mandatory.matching.values());
  var nonMandatory = Array.from(
    grouped.groups.mandatory.nonMatching.values());
  var oneTime = provider.generateKeyPair("ec-p256");
  var signatures = nonMandatory.map(function (statement) {
    return provider.sign("ecdsa-p256-sha256", oneTime,
                         bytes.strBytes(statement));
  });
  var publicKey = multikeyBytes(provider.exportKey(oneTime, "jwk",
                                                   { publicOnly: true }));
  var toSign = bytes.concatBytes(proofHash, publicKey,
                                 mandatoryHash(mandatory));
  var baseSignature = provider.sign(alg, importJwk(o.privateJwk), toSign);
  proof.proofValue = serializeBaseProofValue({ baseSignature: baseSignature,
    publicKey: publicKey, hmacKey: hmacKey, signatures: signatures,
    mandatoryPointers: mandatoryPointers });
  log.debug("Leaving createBaseProof(). " + mandatory.length +
            " mandatory, " + nonMandatory.length + " selective.");
  return Object.assign({}, document, { proof: proof });
}

// ---------------------------------------------------------------------------
// The holder's derived proof (section 3.6.6, createDisclosureData). opts:
// { selectivePointers }. Answers { document: the reveal document with its
// derived proof, mandatoryCount, selectiveCount, statementCount }.
// ---------------------------------------------------------------------------
async function deriveProof(secured, opts) {
  log.debug("Entering deriveProof().");
  var o = opts || {};
  var proof = theProof(secured);
  var base = parseBaseProofValue(proof.proofValue);
  var selective = (o.selectivePointers || []).slice();
  if (!base.mandatoryPointers.length && !selective.length) {
    log.debug("Leaving deriveProof(). Nothing selected.");
    throw new Error("nothing is selected for disclosure: the base proof " +
                    "has no mandatory pointers and none were chosen.");
  }
  var document = di.withoutProof(secured);
  var combined = base.mandatoryPointers.concat(selective);
  var grouped = await di.canonicalizeAndGroup(document,
    di.hmacIdLabels(base.hmacKey), { mandatory: base.mandatoryPointers,
      selective: selective, combined: combined });
  var g = grouped.groups;
  var mandatoryIndexes = [];
  var relative = 0;
  g.combined.matching.forEach(function (statement, index) {
    if (g.mandatory.matching.has(index)) mandatoryIndexes.push(relative);
    relative++;
  });
  // The base proof's signatures are in non-mandatory order; keep those
  // whose statement the selection names.
  var nonMandatoryIndexes = Array.from(g.mandatory.nonMatching.keys());
  if (nonMandatoryIndexes.length !== base.signatures.length) {
    log.debug("Leaving deriveProof(). Signature count.");
    throw new Error("the base proof carries " + base.signatures.length +
      " signatures and the credential has " + nonMandatoryIndexes.length +
      " non-mandatory statements: it is not the credential that was " +
      "signed.");
  }
  var signatures = base.signatures.filter(function (sig, i) {
    return g.selective.matching.has(nonMandatoryIndexes[i]);
  });
  var revealDocument = di.selectJsonLd(document, combined);
  var revealIds = new Map();
  await di.canonize(g.combined.deskolemized.join(""), revealIds);
  var labelMap = new Map();
  revealIds.forEach(function (c14n, from) {
    labelMap.set(di.withoutPrefix(c14n),
                 grouped.labelMap.get(di.withoutPrefix(from)));
  });
  var derived = Object.assign({}, proof);
  delete derived["@context"];
  derived.proofValue = serializeDerivedProofValue({
    baseSignature: base.baseSignature, publicKey: base.publicKey,
    signatures: signatures, labelMap: labelMap,
    mandatoryIndexes: mandatoryIndexes });
  revealDocument.proof = derived;
  log.debug("Leaving deriveProof(). " + signatures.length + " of " +
            base.signatures.length + " selective statement(s) disclosed.");
  return { document: revealDocument, mandatoryCount: mandatoryIndexes.length,
           selectiveCount: signatures.length,
           statementCount: base.signatures.length };
}

// The issuer's key, through the caller's resolver or data_integrity.js's.
function resolveIssuerKey(opts, vm) {
  log.debug("Entering resolveIssuerKey().");
  var o = opts || {};
  var fn = o.resolveKey || dataIntegrity.defaultResolveKey(o.fetch,
    { allowHttp: !!o.allowHttp });
  log.debug("Leaving resolveIssuerKey().");
  return Promise.resolve(fn(vm));
}

function verifySignatures(issuerJwk, oneTimeKey, signatures, toVerify,
                          nonMandatory, baseSignature) {
  log.debug("Entering verifySignatures().");
  if (signatures.length !== nonMandatory.length) {
    log.debug("Leaving verifySignatures(). Count.");
    return "the proof carries " + signatures.length + " statement " +
      "signature(s) for " + nonMandatory.length + " non-mandatory " +
      "statement(s).";
  }
  if (!provider.verify(issuerAlg(issuerJwk), importJwk(issuerJwk), toVerify,
                       baseSignature)) {
    log.debug("Leaving verifySignatures(). Base signature.");
    return "the issuer's base signature does not verify over the proof " +
      "options, the one-time key and the mandatory statements.";
  }
  var bad = -1;
  nonMandatory.some(function (statement, i) {
    if (!provider.verify("ecdsa-p256-sha256", oneTimeKey,
                         bytes.strBytes(statement), signatures[i])) {
      bad = i;
      return true;
    }
    return false;
  });
  if (bad >= 0) {
    log.debug("Leaving verifySignatures(). Statement " + bad + ".");
    return "the signature on non-mandatory statement " + bad + " does not " +
      "verify: " + nonMandatory[bad].trim();
  }
  log.debug("Leaving verifySignatures(). All verify.");
  return "";
}

// A derived proof (section 3.6.7, createVerifyData, and 3.6.2). The result
// is data_integrity.js's shape.
async function verifyDerivedProof(secured, proof, opts) {
  log.debug("Entering verifyDerivedProof().");
  var out = { valid: false, derived: true, spec: SPEC };
  try {
    var parsed = parseDerivedProofValue(proof.proofValue);
    var document = di.withoutProof(secured);
    var proofHash = await di.proofHash(document, proof);
    var relabelled = await di.relabelledCanonicalStatements(document,
      di.labelsFromMap(parsed.labelMap));
    var mandatory = [];
    var nonMandatory = [];
    relabelled.statements.forEach(function (statement, i) {
      (parsed.mandatoryIndexes.indexOf(i) >= 0 ? mandatory : nonMandatory)
        .push(statement);
    });
    var issuerJwk = await resolveIssuerKey(opts, proof.verificationMethod);
    if (!issuerJwk) {
      throw new Error("verificationMethod " + proof.verificationMethod +
                      " resolves to no key.");
    }
    out.jwk = issuerJwk;
    var problem = verifySignatures(issuerJwk,
      importJwk(multikeyJwk(parsed.publicKey)), parsed.signatures,
      bytes.concatBytes(proofHash, parsed.publicKey,
                        mandatoryHash(mandatory)),
      nonMandatory, parsed.baseSignature);
    out.valid = !problem;
    out.disclosedStatements = mandatory.concat(nonMandatory);
    out.mandatoryCount = mandatory.length;
    if (problem) out.reason = problem;
  } catch (e) {
    out.reason = e.message;
  }
  log.debug("Leaving verifyDerivedProof(). " + out.valid);
  return out;
}

// A base proof, as its holder checks it before deriving from it (the
// issuance pages): every statement, the hmacKey in hand.
async function verifyBaseProof(secured, proof, opts) {
  log.debug("Entering verifyBaseProof().");
  var out = { valid: false, base: true, spec: SPEC };
  try {
    var base = parseBaseProofValue(proof.proofValue);
    var document = di.withoutProof(secured);
    var proofHash = await di.proofHash(document, proof);
    var grouped = await di.canonicalizeAndGroup(document,
      di.hmacIdLabels(base.hmacKey), { mandatory: base.mandatoryPointers });
    var mandatory = Array.from(grouped.groups.mandatory.matching.values());
    var nonMandatory = Array.from(
      grouped.groups.mandatory.nonMatching.values());
    var issuerJwk = await resolveIssuerKey(opts, proof.verificationMethod);
    if (!issuerJwk) {
      throw new Error("verificationMethod " + proof.verificationMethod +
                      " resolves to no key.");
    }
    out.jwk = issuerJwk;
    var problem = verifySignatures(issuerJwk,
      importJwk(multikeyJwk(base.publicKey)), base.signatures,
      bytes.concatBytes(proofHash, base.publicKey,
                        mandatoryHash(mandatory)),
      nonMandatory, base.baseSignature);
    out.valid = !problem;
    out.statementCount = mandatory.length + nonMandatory.length;
    out.mandatoryCount = mandatory.length;
    if (problem) out.reason = problem;
  } catch (e) {
    out.reason = e.message;
  }
  log.debug("Leaving verifyBaseProof(). " + out.valid);
  return out;
}

dataIntegrity.registerSuite(CRYPTOSUITE, {
  verify: function verify(doc, proof, opts) {
    log.debug("Entering verify().");
    log.debug("Leaving verify().");
    return proofValueKind(proof.proofValue) === "base" ?
      verifyBaseProof(doc, proof, opts) : verifyDerivedProof(doc, proof, opts);
  }
});

module.exports = {
  CRYPTOSUITE: CRYPTOSUITE,
  proofValueKind: proofValueKind,
  serializeBaseProofValue: serializeBaseProofValue,
  parseBaseProofValue: parseBaseProofValue,
  serializeDerivedProofValue: serializeDerivedProofValue,
  parseDerivedProofValue: parseDerivedProofValue,
  createBaseProof: createBaseProof,
  deriveProof: deriveProof,
  verifyDerivedProof: verifyDerivedProof,
  verifyBaseProof: verifyBaseProof
};
