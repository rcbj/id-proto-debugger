// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vci_metadata.js
//
// ---------------------------------------------------------------------------
// Credential Issuer Metadata — OpenID for Verifiable Credential Issuance
// (OID4VCI) 1.0, "Credential Issuer Metadata".
//
// The same idea as op_metadata.js, for the other metadata document the SD-JWT
// VC issuance page can load. Two groups:
//
//   VCI_METADATA         top-level members of the issuer metadata document
//   VCI_CONFIG_METADATA  members of ONE entry in credential_configurations_supported
//                        (the credential the wallet is going to ask for)
//
// Element ids and localStorage keys are prefixed vci_ so they cannot collide
// with the OpenID Provider / authorization server members, which the issuance
// page deliberately shares with oauth2_oidc_1.html.
//
//   name  member name (the part after vci_ is the id and the storage key)
//   type  'array' -> comma-separated in the UI, 'json' -> a JSON object/array
//         shown as JSON, 'string' -> plain text
//   desc  the tooltip
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "vci_metadata",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var VCI_METADATA = [
  { name: "credential_issuer", type: "string", dflt: "http://localhost:8081",
    desc: "REQUIRED. The Credential Issuer identifier — the URL the issuer " +
        "metadata was published under, and the value a wallet's proof of " +
        "possession must name as its audience." },
  { name: "credential_endpoint", type: "string",
   dflt: "http://localhost:8081/oid4vci/credential",
    desc: "REQUIRED. Where the Credential Request is sent, with the access " +
        "token as a Bearer credential." },
  { name: "authorization_servers", type: "array",
   dflt: "http://localhost:8080/realms/debugger-testing",
    desc: "OPTIONAL. The authorization servers that can authorize issuance " +
        "of these credentials. The RFC 8414 pane above retrieves this " +
        "server's metadata." },
  { name: "nonce_endpoint", type: "string",
   dflt: "http://localhost:8081/oid4vci/nonce",
    desc: "OPTIONAL. Returns the c_nonce that the wallet's proof of " +
        "possession must carry, so the issuer knows the proof is fresh." },
  { name: "notification_endpoint", type: "string",
   dflt: "http://localhost:8081/oid4vci/notification",
    desc: "OPTIONAL. Where a wallet reports what it did with an issued " +
        "credential." },
  { name: "deferred_credential_endpoint", type: "string", dflt: "",
    desc: "OPTIONAL. Where a wallet collects a credential the issuer could " +
        "not mint immediately (it answered with a transaction_id)." },
  { name: "batch_credential_issuance", type: "json", dflt: "",
    desc: "OPTIONAL. Present when the issuer can mint several credentials in " +
        "one request; batch_size is the most proofs it will accept." },
  { name: "credential_response_encryption", type: "json", dflt: "",
    desc: "OPTIONAL. The JWE algorithms the issuer supports for encrypting " +
        "the Credential Response, and whether encryption is required." },
  { name: "credential_request_encryption", type: "json", dflt: "",
    desc: "OPTIONAL. The issuer's own public keys (jwks, each with a kid) " +
        "for encrypting the Credential Request to it, the enc values its " +
        "endpoint can decode, and whether encryption is required. Note there " +
        "is no alg_values_supported here, unlike the response side: section " +
        "10 takes the JWE alg from the alg of the chosen JWK." },
  { name: "display", type: "json", dflt: "",
    desc: "OPTIONAL. How to display the Credential Issuer itself (name, " +
        "locale, logo)." },
  { name: "signed_metadata", type: "string", dflt: "",
    desc: "OPTIONAL. A JWT of this metadata document signed by the issuer. " +
        "Use Validate Signature in the pane above to verify it." }
];

var VCI_CONFIG_METADATA = [
  { name: "credential_configuration_id", type: "string",
   dflt: "IdentityCredential",
    desc: "The key of the chosen entry in " +
        "credential_configurations_supported. This is what the Credential " +
        "Request asks for." },
  { name: "format", type: "string", dflt: "dc+sd-jwt",
    desc: "REQUIRED. The credential format. dc+sd-jwt is the SD-JWT VC " +
        "format identifier; jwt_vc_json and jwt_vc_json-ld are a W3C " +
        "Verifiable Credential secured as a JWT; ldp_vc is one secured " +
        "with a Data Integrity proof; mso_mdoc is an ISO/IEC 18013-5 " +
        "mdoc. vc+jwt, vc+sd-jwt and vc+cose (W3C VC-JOSE-COSE), jpt " +
        "(JSON Proof Token, a draft) and sd-cwt (a draft) have no " +
        "OpenID4VCI format profile, so their media type names are used. " +
        "Changing it resets the binding method, signing algorithms and " +
        "proof types below to ones that format defines, unless they were " +
        "edited by hand." },
  { name: "credential_definition", type: "json", dflt: "",
    desc: "REQUIRED for jwt_vc_json. The W3C credential definition — its " +
        "`type` array is what identifies the credential in that format, in " +
        "place of the vct an SD-JWT VC uses." },
  { name: "vct", type: "string", dflt: "urn:idptools:sd-jwt-vc:identity",
    desc: "REQUIRED for dc+sd-jwt. The Verifiable Credential Type — what " +
        "kind of credential this is, and the vct claim the issued SD-JWT VC " +
        "will carry." },
  { name: "doctype", type: "string", dflt: "",
    desc: "REQUIRED for mso_mdoc (OpenID4VCI 1.0 Appendix A.2). The ISO/IEC " +
        "18013-5 document type, such as org.iso.18013.5.1.mDL for a mobile " +
        "driving licence." },
  { name: "scope", type: "string", dflt: "identity_credential",
    desc: "OPTIONAL. The OAuth 2.0 scope that asks the authorization server " +
        "for authorization to issue this credential." },
  { name: "cryptographic_binding_methods_supported", type: "array", dflt: "jwk",
    formatDependent: true,
    desc: "OPTIONAL. How the credential can be bound to the holder's key. " +
        "jwk means the holder's public key goes in the credential's " +
        "cnf claim; did:jwk and did:key name it as the credentialSubject's " +
        "DID; cose_key puts it in an mdoc's MSO. Defaults to what the " +
        "format defines." },
  { name: "credential_signing_alg_values_supported", type: "array",
   dflt: "ES256", formatDependent: true,
    desc: "The algorithms the issuer will sign the credential with, in the " +
        "format's own identifiers: JOSE alg names for the JWT formats, " +
        "Data Integrity cryptosuites (eddsa-rdfc-2022, ecdsa-rdfc-2019, " +
        "bbs-2023, ...) or Linked Data proof types (Ed25519Signature2020, " +
        "JsonWebSignature2020, ...) for ldp_vc, and COSE algorithm numbers " +
        "(-7 is ES256) for mso_mdoc. Defaults to what the format " +
        "defines." },
  { name: "proof_signing_alg_values_supported", type: "array",
   dflt: "ES256, RS256",
    desc: "From proof_types_supported.jwt: the algorithms the issuer accepts " +
        "on the wallet's JWT proof of possession." },
  { name: "proof_types_supported", type: "array", dflt: "jwt",
    formatDependent: true,
    desc: "OPTIONAL. The key proof types the issuer accepts (OID4VCI 1.0 " +
        "section 8.2.1): jwt is a holder-signed proof of possession, " +
        "attestation is a Key Attestation JWT vouching for the holder keys. " +
        "The Credential Request uses the type chosen on step 2, defaulting " +
        "to jwt." }
];

var metadataClient = require("./metadata_client");
// What each credential format allows, for the defaults below (#474).
var vcFormats = require("./vc_formats");
// The "-->not defined<--" marking is implemented once, for the OpenID Provider
// half of the same pane; the OID4VCI half gets it from there so the two cannot
// drift apart. (No cycle: op_metadata does not know about this module.)
var opMetadata = require("./op_metadata");

var PREFIX = "vci_";
function idFor(name) {
  log.debug("Entering idFor().");
  log.debug("Leaving idFor().");
  return PREFIX + name;
}

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
// Writing through metadata_client, so a member whose value is a JSON structure
// gets a <textarea> that can show it pretty-printed.
function setFieldValue(id, v) {
  log.debug("Entering setFieldValue().");
  metadataClient.setMetadataField(id, v);
  log.debug("Leaving setFieldValue().");
}
function fieldValue(id) {
  log.debug("Entering fieldValue().");
  var e = el(id);
  log.debug("Leaving fieldValue().");
  return e ? e.value : "";
}

// A metadata value -> the string shown in its field. An array of scalars reads
// better comma-separated; a structure (display, claims,
// batch_credential_issuance, credential_response_encryption) is pretty-printed
// JSON.
function toField(value) {
  log.debug("Entering toField().");
  log.debug("Leaving toField().");
  return metadataClient.valueToDisplay(value);
}

function writeToLocalStorage() {
  log.debug("Entering writeToLocalStorage().");
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    try {
      localStorage.setItem(idFor(m.name), fieldValue(idFor(m.name)));
    } catch (e) {
      // No storage available in this context.
    }
  });
  log.debug("Leaving writeToLocalStorage().");
}

// A member's placeholder value. The format-dependent ones (binding method,
// signing algorithms) follow the format, so a wallet that has not read an
// issuer's metadata yet still shows a combination the format defines.
function defaultValue(m, formatId) {
  log.debug("Entering defaultValue(). " + m.name);
  if (m.formatDependent) {
    var d = vcFormats.metadataDefaults(formatId || "dc+sd-jwt");
    if (d && d[m.name] !== undefined) {
      log.debug("Leaving defaultValue(). From the format.");
      return d[m.name];
    }
  }
  log.debug("Leaving defaultValue().");
  return m.dflt;
}

function loadFromLocalStorage() {
  log.debug("Entering loadFromLocalStorage().");
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    var v = null;
    try {
      v = localStorage.getItem(idFor(m.name));
    } catch (e) {
      // No storage available in this context.
    }
    // `format` comes before the members that depend on it, so its field
    // already holds this load's value when they are reached.
    setFieldValue(idFor(m.name), (v === null || v === undefined) ?
        defaultValue(m, fieldValue(idFor("format"))) : v);
  });
  log.debug("Leaving loadFromLocalStorage().");
}

// Every member back to its placeholder, the format-dependent ones for the
// default format.
function restoreDefaultFields() {
  log.debug("Entering restoreDefaultFields().");
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    setFieldValue(idFor(m.name), defaultValue(m, fieldValue(idFor("format"))));
  });
  log.debug("Leaving restoreDefaultFields().");
}

// The format field changed from `previous`: every format-dependent member
// still holding previous's default, or nothing, takes the new format's. One
// the user typed is theirs and is left alone. Answers the names changed.
function onFormatChange(previous) {
  log.debug("Entering onFormatChange(). from " + previous);
  var now = fieldValue(idFor("format"));
  var changed = [];
  VCI_CONFIG_METADATA.forEach(function (m) {
    if (!m.formatDependent) return;
    var current = fieldValue(idFor(m.name)).trim();
    var wasDefault = !current || current === defaultValue(m, previous) ||
        current === m.dflt;
    if (wasDefault && vcFormats.format(now)) {
      setFieldValue(idFor(m.name), defaultValue(m, now));
      changed.push(m.name);
    }
  });
  log.debug("Leaving onFormatChange(). " + changed.join(", "));
  return changed;
}

function clearFields() {
  log.debug("Entering clearFields().");
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    setFieldValue(idFor(m.name), "");
    // The note described a particular document; with that gone it would be a
    // claim about nothing.
    opMetadata.markNotDefined(idFor(m.name), false);
  });
  log.debug("Leaving clearFields().");
}

function clearStorage() {
  log.debug("Entering clearStorage().");
  // "" rather than removed: an ABSENT key falls back to the dummy default on
  // the next load, which would undo the clear.
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    try {
      localStorage.setItem(idFor(m.name), "");
    } catch (e) {
      // No storage available in this context.
    }
  });
  log.debug("Leaving clearStorage().");
}

// Fill the pane from a retrieved credential issuer metadata document, plus the
// one credential configuration the user picked out of
// credential_configurations_supported.
function populateFromMetadata(info, configId) {
  log.debug("Entering populateFromMetadata().");
  info = info || {};
  VCI_METADATA.forEach(function (m) {
    var v = toField(info[m.name]);
    setFieldValue(idFor(m.name), v);
    // A member this issuer does not publish is marked, not left blank: empty
    // and "not offered" are different things, and a wallet that cannot tell
    // them apart is exactly what this pane exists to prevent. walt.id publishes
    // no deferred_credential_endpoint, for instance — it cannot defer an
    // issuance, and the field being empty is the fact, not an oversight.
    opMetadata.markNotDefined(idFor(m.name),
      !Object.prototype.hasOwnProperty.call(info, m.name));
    try {
      localStorage.setItem(idFor(m.name), v);
    } catch (e) {
      // No storage available in this context.
    }
  });

  var configs = info.credential_configurations_supported || {};
  var id = configId || Object.keys(configs)[0] || "";
  var cfg = configs[id] || {};
  VCI_CONFIG_METADATA.forEach(function (m) {
    var v;
    if (m.name === "credential_configuration_id") {
      v = id;
    } else if (m.name === "proof_signing_alg_values_supported") {
      var jwtProof = (cfg.proof_types_supported || {}).jwt || {};
      v = toField(jwtProof.proof_signing_alg_values_supported);
    } else if (m.name === "proof_types_supported") {
      // The advertised key proof types are the KEYS of the object, not the
      // object itself (each value is that type's own parameters).
      v = toField(Object.keys(cfg.proof_types_supported || {}));
    } else {
      v = toField(cfg[m.name]);
    }
    setFieldValue(idFor(m.name), v);
    if (m.name !== "credential_configuration_id") {
      opMetadata.markNotDefined(idFor(m.name),
        !Object.prototype.hasOwnProperty.call(cfg, m.name));
    }
    try {
      localStorage.setItem(idFor(m.name), v);
    } catch (e) {
      // No storage available in this context.
    }
  });
  log.debug("Leaving populateFromMetadata().");
  return id;
}

// Fill the credential-configuration half of the pane from one of the
// built-in configurations (vc_formats.builtInConfiguration()), for a format
// the issuer does not advertise or before any metadata has been retrieved.
// The issuer-level half is left as it is. Answers the id, or "" for a format
// with no built-in configuration.
function populateFromBuiltIn(formatId) {
  log.debug("Entering populateFromBuiltIn(). " + formatId);
  var cfg = vcFormats.builtInConfiguration(formatId);
  if (!cfg) {
    log.debug("Leaving populateFromBuiltIn(). None.");
    return "";
  }
  VCI_CONFIG_METADATA.forEach(function (m) {
    var v = m.name === "credential_configuration_id" ? cfg.id :
        (cfg[m.name] === undefined ? "" : toField(cfg[m.name]));
    setFieldValue(idFor(m.name), v);
    // Not an issuer's document, so nothing in it is "not defined" by one.
    opMetadata.markNotDefined(idFor(m.name), false);
    try {
      localStorage.setItem(idFor(m.name), v);
    } catch (e) {
      // No storage available in this context.
    }
  });
  log.debug("Leaving populateFromBuiltIn().");
  return cfg.id;
}

// What the rest of the workflow needs to make a Credential Request, read back
// out of the pane (so a hand-edited override is honoured).
function currentRequestConfig() {
  log.debug("Entering currentRequestConfig().");
  log.debug("Leaving currentRequestConfig().");
  return {
    credentialIssuer: fieldValue(idFor("credential_issuer")),
    credentialEndpoint: fieldValue(idFor("credential_endpoint")),
    nonceEndpoint: fieldValue(idFor("nonce_endpoint")),
    notificationEndpoint: fieldValue(idFor("notification_endpoint")),
    credentialConfigurationId: fieldValue(idFor("credential_configuration_id")),
    format: fieldValue(idFor("format")),
    vct: fieldValue(idFor("vct")),
    proofAlgs: fieldValue(idFor("proof_signing_alg_values_supported"))
  };
}

module.exports = {
  VCI_METADATA: VCI_METADATA,
  VCI_CONFIG_METADATA: VCI_CONFIG_METADATA,
  PREFIX: PREFIX,
  idFor: idFor,
  toField: toField,
  writeToLocalStorage: writeToLocalStorage,
  loadFromLocalStorage: loadFromLocalStorage,
  clearFields: clearFields,
  clearStorage: clearStorage,
  populateFromMetadata: populateFromMetadata,
  populateFromBuiltIn: populateFromBuiltIn,
  defaultValue: defaultValue,
  restoreDefaultFields: restoreDefaultFields,
  onFormatChange: onFormatChange,
  currentRequestConfig: currentRequestConfig
};
