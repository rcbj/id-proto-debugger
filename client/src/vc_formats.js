// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_formats.js
//
// ---------------------------------------------------------------------------
// What each credential format ALLOWS: which signature algorithms (or Data
// Integrity cryptosuites, or COSE algorithms) may secure it, how a credential
// in it is bound to its holder, how the holder proves possession when asking
// for one, and how the holder proves possession when presenting one (#474).
//
// It exists so that nobody has to work out a valid combination by hand. Every
// page that offers a choice reads its menu and its default from here:
// issuance step 1's placeholder metadata, the holder proof a presentation is
// signed with, and the Verifier's vp_formats_supported. A combination this
// table does not list is one the format's specification does not define, and
// a page that offers it is offering something no conformant peer will accept.
//
// The identifiers are each format's OWN, because OpenID4VCI 1.0 Appendix A
// and OpenID4VP 1.0 Appendix B say so: JOSE `alg` names for the JWT formats,
// cryptosuite and proof type names for ldp_vc, and COSE algorithm NUMBERS for
// mso_mdoc.
//
// NO DOM and no cryptography: a table and the functions that read it, small
// enough for every bundle to include.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_formats",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// JOSE signature algorithms a JWT-secured credential may name (RFC 7518,
// RFC 8037, RFC 8812, the fully-specified Ed25519 of RFC 9864, and ML-DSA
// from draft-ietf-cose-dilithium as JOSE carries it). Best default first.
var JOSE_ALGS = ["ES256", "ES384", "ES512", "EdDSA", "Ed25519", "ES256K",
                 "PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
                 "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

// COSE algorithm identifiers an mdoc's issuerAuth may carry (ISO/IEC
// 18013-5 section 9.1.3.6, and OpenID4VCI 1.0 Appendix A.2.2, which names
// them by number): ES256, ES384, ES512, EdDSA, and the fully-specified
// ESP256/ESP384/Ed25519 of RFC 9864.
var COSE_ALGS = [-7, -35, -36, -8, -9, -51, -19];
var COSE_ALG_NAMES = { "-7": "ES256", "-35": "ES384", "-36": "ES512",
  "-8": "EdDSA", "-9": "ESP256", "-51": "ESP384", "-19": "Ed25519" };

// The proofs an ldp_vc may arrive with. `kind` is "di" for a
// DataIntegrityProof cryptosuite and "ld" for a legacy Linked Data proof
// type; `selective` marks the suites a holder DERIVES a presentation from
// rather than presenting whole; `curves` are the key curves (JWK crv, or
// "RSA", or "BLS12-381") each signs with.
var LDP_SUITES = {
  "eddsa-rdfc-2022": { kind: "di", curves: ["Ed25519"] },
  "eddsa-jcs-2022": { kind: "di", curves: ["Ed25519"] },
  "ecdsa-rdfc-2019": { kind: "di", curves: ["P-256", "P-384"] },
  "ecdsa-jcs-2019": { kind: "di", curves: ["P-256", "P-384"] },
  "ecdsa-sd-2023": { kind: "di", curves: ["P-256", "P-384"],
                     selective: true },
  "bbs-2023": { kind: "di", curves: ["BLS12-381"], selective: true },
  "Ed25519Signature2020": { kind: "ld", curves: ["Ed25519"] },
  "Ed25519Signature2018": { kind: "ld", curves: ["Ed25519"] },
  "JsonWebSignature2020": { kind: "ld", curves: ["Ed25519", "secp256k1",
    "P-256", "P-384", "P-521", "RSA"] },
  "EcdsaSecp256k1Signature2019": { kind: "ld", curves: ["secp256k1"] },
  "BbsBlsSignature2020": { kind: "ld", curves: ["BLS12-381"],
                           selective: true }
};

// The proof a HOLDER signs a Verifiable Presentation with, for each key
// curve, best first. The JCS suites lead because they need no JSON-LD
// context to be fetched or shipped at either end; the legacy types come
// last, for the Verifiers that accept nothing newer.
var LDP_HOLDER_SUITES = {
  "Ed25519": ["eddsa-jcs-2022", "eddsa-rdfc-2022", "Ed25519Signature2020",
              "JsonWebSignature2020", "Ed25519Signature2018"],
  "P-256": ["ecdsa-jcs-2019", "ecdsa-rdfc-2019", "JsonWebSignature2020"],
  "P-384": ["ecdsa-jcs-2019", "ecdsa-rdfc-2019", "JsonWebSignature2020"],
  "P-521": ["JsonWebSignature2020"],
  "secp256k1": ["EcdsaSecp256k1Signature2019", "JsonWebSignature2020"],
  "RSA": ["JsonWebSignature2020"]
};

// One row per format identifier.
//   signingAlgs    what credential_signing_alg_values_supported may hold
//   defaultSigningAlgs   what step 1 shows before an issuer says otherwise
//   bindingMethods / defaultBinding   cryptographic_binding_methods_supported
//   proofTypes     the key proof types a Credential Request may carry
//   holderBinding  how a presentation proves possession
//   selective      whether the holder chooses what to disclose
var FORMATS = {
  "dc+sd-jwt": {
    name: "SD-JWT VC", spec: "draft-ietf-oauth-sd-jwt-vc; OpenID4VCI 1.0 " +
      "Appendix A.3",
    signingAlgs: JOSE_ALGS, defaultSigningAlgs: ["ES256"],
    bindingMethods: ["jwk"], defaultBinding: "jwk",
    proofTypes: ["jwt", "attestation"], holderBinding: "Key Binding JWT",
    selective: true, typeMember: "vct"
  },
  "jwt_vc_json": {
    name: "W3C VC secured as a JWT (no JSON-LD)",
    spec: "OpenID4VCI 1.0 Appendix A.1.1",
    signingAlgs: JOSE_ALGS, defaultSigningAlgs: ["ES256"],
    bindingMethods: ["jwk", "did:jwk", "did:key"], defaultBinding: "jwk",
    proofTypes: ["jwt", "attestation"],
    holderBinding: "a Verifiable Presentation JWT", selective: false,
    typeMember: "credential_definition.type"
  },
  "jwt_vc_json-ld": {
    name: "W3C VC secured as a JWT (JSON-LD)",
    spec: "OpenID4VCI 1.0 Appendix A.1.2",
    signingAlgs: JOSE_ALGS, defaultSigningAlgs: ["ES256"],
    bindingMethods: ["jwk", "did:jwk", "did:key"], defaultBinding: "jwk",
    proofTypes: ["jwt", "attestation"],
    holderBinding: "a Verifiable Presentation JWT", selective: false,
    typeMember: "credential_definition.type"
  },
  "ldp_vc": {
    name: "W3C VC secured with a Data Integrity proof",
    spec: "OpenID4VCI 1.0 Appendix A.1.3",
    signingAlgs: Object.keys(LDP_SUITES),
    defaultSigningAlgs: ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"],
    bindingMethods: ["did:jwk", "did:key"], defaultBinding: "did:jwk",
    proofTypes: ["jwt", "di_vp", "attestation"],
    holderBinding: "a Verifiable Presentation with the holder's Data " +
      "Integrity proof", selective: "by cryptosuite",
    typeMember: "credential_definition.type"
  },
  "mso_mdoc": {
    name: "ISO/IEC 18013-5 mdoc", spec: "OpenID4VCI 1.0 Appendix A.2",
    signingAlgs: COSE_ALGS, defaultSigningAlgs: [-7],
    bindingMethods: ["cose_key"], defaultBinding: "cose_key",
    proofTypes: ["jwt", "attestation"],
    holderBinding: "the mdoc's DeviceAuth signature", selective: true,
    typeMember: "doctype"
  }
};

// The key proof a wallet signs a Credential Request with: the JOSE algs it
// can generate a holder key for, best first.
var HOLDER_KEY_ALGS = ["ES256", "EdDSA", "Ed25519", "ES384", "ES256K",
                       "ES512", "PS256", "RS256"];

function format(id) {
  log.debug("Entering format(). " + id);
  var row = FORMATS[id] || null;
  log.debug("Leaving format().");
  return row;
}

function formatIds() {
  log.debug("Entering formatIds().");
  log.debug("Leaving formatIds().");
  return Object.keys(FORMATS);
}

// Whether `value` is a credential signing algorithm the format defines.
function isSigningAlgFor(formatId, value) {
  log.debug("Entering isSigningAlgFor(). " + formatId);
  var row = FORMATS[formatId];
  var ok = !!row && row.signingAlgs.some(function (a) {
    return String(a) === String(value);
  });
  log.debug("Leaving isSigningAlgFor(). " + ok);
  return ok;
}

// The placeholder values issuance step 1 shows for a format before an
// issuer's metadata has been read, as field strings.
function metadataDefaults(formatId) {
  log.debug("Entering metadataDefaults(). " + formatId);
  var row = FORMATS[formatId];
  if (!row) {
    log.debug("Leaving metadataDefaults(). Unknown format.");
    return null;
  }
  log.debug("Leaving metadataDefaults().");
  return {
    credential_signing_alg_values_supported:
      row.defaultSigningAlgs.join(", "),
    cryptographic_binding_methods_supported: row.defaultBinding,
    proof_signing_alg_values_supported: "ES256"
  };
}

// The ldp_vc proof type or cryptosuite a proof object is: its cryptosuite
// when it is a DataIntegrityProof, its type otherwise.
function ldpSuiteOf(proof) {
  log.debug("Entering ldpSuiteOf().");
  var p = proof || {};
  var id = p.type === "DataIntegrityProof" ? String(p.cryptosuite || "") :
      String(p.type || "");
  log.debug("Leaving ldpSuiteOf(). " + id);
  return id;
}

// Whether a JSON object carries a proof this table recognises: what makes
// it an ldp_vc rather than any JSON at all.
function isLdpSecured(doc) {
  log.debug("Entering isLdpSecured().");
  var proofs = [].concat((doc && doc.proof) || []);
  var ok = proofs.some(function (p) {
    return !!LDP_SUITES[ldpSuiteOf(p)];
  });
  log.debug("Leaving isLdpSecured(). " + ok);
  return ok;
}

function isSelectiveLdpSuite(id) {
  log.debug("Entering isSelectiveLdpSuite(). " + id);
  var row = LDP_SUITES[id];
  log.debug("Leaving isSelectiveLdpSuite().");
  return !!(row && row.selective);
}

function curveOf(jwk) {
  log.debug("Entering curveOf().");
  var k = jwk || {};
  log.debug("Leaving curveOf().");
  return k.kty === "RSA" ? "RSA" : String(k.crv || "");
}

// The suite a holder signs a VP with, given its key and what the Verifier
// said it accepts — the ldp_vc entry of vp_formats_supported, or a DCQL
// credential query's meta, either of which may carry `cryptosuite_values`
// and `proof_type_values`. With no constraint, the key's best suite.
// Answers { suite, candidates, reason } with suite "" when none fits.
function holderSuiteFor(jwk, accepts) {
  log.debug("Entering holderSuiteFor().");
  var curve = curveOf(jwk);
  var candidates = LDP_HOLDER_SUITES[curve] || [];
  var a = accepts || {};
  var suites = a.cryptosuite_values ? [].concat(a.cryptosuite_values) : null;
  var types = a.proof_type_values ? [].concat(a.proof_type_values) : null;
  var allowed = candidates.filter(function (id) {
    var row = LDP_SUITES[id];
    var proofType = row.kind === "di" ? "DataIntegrityProof" : id;
    if (types && types.indexOf(proofType) === -1) return false;
    if (row.kind === "di" && suites && suites.indexOf(id) === -1) {
      return false;
    }
    return true;
  });
  var out = { suite: allowed[0] || "", candidates: allowed };
  if (!out.suite) {
    out.reason = candidates.length ?
      "the Verifier accepts " + JSON.stringify({ cryptosuite_values: suites,
        proof_type_values: types }) + " and a " + curve + " holder key " +
      "signs only " + candidates.join(", ") + "." :
      "no Data Integrity or Linked Data proof signs with a " +
      (curve || "key of this type") + ".";
  }
  log.debug("Leaving holderSuiteFor(). " + (out.suite || "none"));
  return out;
}

// The holder key algorithm a wallet should generate for an issuer that
// accepts `issuerAlgs` on its key proof (proof_signing_alg_values_supported).
// With no list, ES256, which every issuer here and most in the wild accept.
function holderKeyAlgFor(issuerAlgs) {
  log.debug("Entering holderKeyAlgFor().");
  var offered = [].concat(issuerAlgs || []).map(String);
  if (!offered.length) {
    log.debug("Leaving holderKeyAlgFor(). Default.");
    return "ES256";
  }
  var alg = HOLDER_KEY_ALGS.filter(function (x) {
    return offered.indexOf(x) !== -1;
  })[0] || "";
  log.debug("Leaving holderKeyAlgFor(). " + (alg || "none"));
  return alg;
}

// vp_formats_supported, as a Verifier states it (OpenID4VP 1.0 section
// 11.1 and Appendix B): everything this debugger can verify, per format.
function vpFormatsSupported() {
  log.debug("Entering vpFormatsSupported().");
  var ldpDi = Object.keys(LDP_SUITES).filter(function (id) {
    return LDP_SUITES[id].kind === "di";
  });
  var ldpTypes = ["DataIntegrityProof"].concat(Object.keys(LDP_SUITES)
    .filter(function (id) {
      return LDP_SUITES[id].kind === "ld";
    }));
  var jose = JOSE_ALGS.slice();
  log.debug("Leaving vpFormatsSupported().");
  return {
    "dc+sd-jwt": { "sd-jwt_alg_values": jose, "kb-jwt_alg_values": jose },
    "jwt_vc_json": { alg_values: jose },
    "ldp_vc": { proof_type_values: ldpTypes, cryptosuite_values: ldpDi },
    "mso_mdoc": { issuerauth_alg_values: COSE_ALGS.slice(),
                  deviceauth_alg_values: COSE_ALGS.slice() }
  };
}

module.exports = {
  FORMATS: FORMATS,
  JOSE_ALGS: JOSE_ALGS,
  COSE_ALGS: COSE_ALGS,
  COSE_ALG_NAMES: COSE_ALG_NAMES,
  LDP_SUITES: LDP_SUITES,
  LDP_HOLDER_SUITES: LDP_HOLDER_SUITES,
  HOLDER_KEY_ALGS: HOLDER_KEY_ALGS,
  format: format,
  formatIds: formatIds,
  isSigningAlgFor: isSigningAlgFor,
  metadataDefaults: metadataDefaults,
  ldpSuiteOf: ldpSuiteOf,
  isLdpSecured: isLdpSecured,
  isSelectiveLdpSuite: isSelectiveLdpSuite,
  holderSuiteFor: holderSuiteFor,
  holderKeyAlgFor: holderKeyAlgFor,
  vpFormatsSupported: vpFormatsSupported
};
