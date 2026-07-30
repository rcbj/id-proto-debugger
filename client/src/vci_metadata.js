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
// page deliberately shares with debugger.html.
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
    desc: "REQUIRED. The Credential Issuer identifier — the URL the issuer metadata was published under, and the value a wallet's proof of possession must name as its audience." },
  { name: "credential_endpoint", type: "string", dflt: "http://localhost:8081/oid4vci/credential",
    desc: "REQUIRED. Where the Credential Request is sent, with the access token as a Bearer credential." },
  { name: "authorization_servers", type: "array", dflt: "http://localhost:8080/realms/debugger-testing",
    desc: "OPTIONAL. The authorization servers that can authorize issuance of these credentials. The RFC 8414 pane above retrieves this server's metadata." },
  { name: "nonce_endpoint", type: "string", dflt: "http://localhost:8081/oid4vci/nonce",
    desc: "OPTIONAL. Returns the c_nonce that the wallet's proof of possession must carry, so the issuer knows the proof is fresh." },
  { name: "notification_endpoint", type: "string", dflt: "http://localhost:8081/oid4vci/notification",
    desc: "OPTIONAL. Where a wallet reports what it did with an issued credential." },
  { name: "deferred_credential_endpoint", type: "string", dflt: "",
    desc: "OPTIONAL. Where a wallet collects a credential the issuer could not mint immediately (it answered with a transaction_id)." },
  { name: "batch_credential_issuance", type: "json", dflt: "",
    desc: "OPTIONAL. Present when the issuer can mint several credentials in one request; batch_size is the most proofs it will accept." },
  { name: "credential_response_encryption", type: "json", dflt: "",
    desc: "OPTIONAL. The JWE algorithms the issuer supports for encrypting the Credential Response, and whether encryption is required." },
  { name: "display", type: "json", dflt: "",
    desc: "OPTIONAL. How to display the Credential Issuer itself (name, locale, logo)." },
  { name: "signed_metadata", type: "string", dflt: "",
    desc: "OPTIONAL. A JWT of this metadata document signed by the issuer. Use Validate Signature in the pane above to verify it." }
];

var VCI_CONFIG_METADATA = [
  { name: "credential_configuration_id", type: "string", dflt: "IdentityCredential",
    desc: "The key of the chosen entry in credential_configurations_supported. This is what the Credential Request asks for." },
  { name: "format", type: "string", dflt: "dc+sd-jwt",
    desc: "REQUIRED. The credential format. dc+sd-jwt is the SD-JWT VC format identifier (vc+sd-jwt in earlier drafts)." },
  { name: "vct", type: "string", dflt: "urn:idptools:sd-jwt-vc:identity",
    desc: "REQUIRED for dc+sd-jwt. The Verifiable Credential Type — what kind of credential this is, and the vct claim the issued SD-JWT VC will carry." },
  { name: "scope", type: "string", dflt: "identity_credential",
    desc: "OPTIONAL. The OAuth 2.0 scope that asks the authorization server for authorization to issue this credential." },
  { name: "cryptographic_binding_methods_supported", type: "array", dflt: "jwk",
    desc: "OPTIONAL. How the credential can be bound to the holder's key. jwk means the holder's public key goes in the credential's cnf claim." },
  { name: "credential_signing_alg_values_supported", type: "array", dflt: "RS256",
    desc: "The algorithms the issuer will sign the credential with." },
  { name: "proof_signing_alg_values_supported", type: "array", dflt: "ES256, RS256",
    desc: "From proof_types_supported.jwt: the algorithms the issuer accepts on the wallet's JWT proof of possession." }
];

var metadataClient = require("./metadata_client");
// The "-->not defined<--" marking is implemented once, for the OpenID Provider
// half of the same pane; the OID4VCI half gets it from there so the two cannot
// drift apart. (No cycle: op_metadata does not know about this module.)
var opMetadata = require("./op_metadata");

var PREFIX = "vci_";
function idFor(name) { return PREFIX + name; }

function el(id) { return document.getElementById(id); }
// Writing through metadata_client, so a member whose value is a JSON structure
// gets a <textarea> that can show it pretty-printed.
function setFieldValue(id, v) { metadataClient.setMetadataField(id, v); }
function fieldValue(id) { var e = el(id); return e ? e.value : ""; }

// A metadata value -> the string shown in its field. An array of scalars reads
// better comma-separated; a structure (display, claims, batch_credential_issuance,
// credential_response_encryption) is pretty-printed JSON.
function toField(value) {
  return metadataClient.valueToDisplay(value);
}

function writeToLocalStorage() {
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    try {
      localStorage.setItem(idFor(m.name), fieldValue(idFor(m.name)));
    } catch (e) {
      // No storage available in this context.
    }
  });
}

function loadFromLocalStorage() {
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    var v = null;
    try {
      v = localStorage.getItem(idFor(m.name));
    } catch (e) {
      // No storage available in this context.
    }
    setFieldValue(idFor(m.name), (v === null || v === undefined) ? m.dflt : v);
  });
}

function clearFields() {
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    setFieldValue(idFor(m.name), "");
    // The note described a particular document; with that gone it would be a
    // claim about nothing.
    opMetadata.markNotDefined(idFor(m.name), false);
  });
}

function clearStorage() {
  // "" rather than removed: an ABSENT key falls back to the dummy default on
  // the next load, which would undo the clear.
  VCI_METADATA.concat(VCI_CONFIG_METADATA).forEach(function (m) {
    try {
      localStorage.setItem(idFor(m.name), "");
    } catch (e) {
      // No storage available in this context.
    }
  });
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
    // A member this issuer does not publish is marked, not left blank: empty and
    // "not offered" are different things, and a wallet that cannot tell them
    // apart is exactly what this pane exists to prevent. walt.id publishes no
    // deferred_credential_endpoint, for instance — it cannot defer an issuance,
    // and the field being empty is the fact, not an oversight.
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

// What the rest of the workflow needs to make a Credential Request, read back
// out of the pane (so a hand-edited override is honoured).
function currentRequestConfig() {
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
  currentRequestConfig: currentRequestConfig
};
