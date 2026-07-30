// File: op_metadata.js
//
// ---------------------------------------------------------------------------
// OpenID Provider Metadata — OpenID Connect Discovery 1.0 section 3.
//
// Shared by the Configuration Parameters pane on BOTH debugger.html and
// debugger2.html (same element ids, same localStorage keys, same origin), so
// the two panes cannot drift apart.
//
// Every field the spec defines is shown in the Configuration Parameters pane so
// a discovery document can be inspected (and overridden) in full. The five that
// the debugger already drove before this table existed — authorization_endpoint,
// token_endpoint, userinfo_endpoint (#oidc_userinfo_endpoint), jwks_uri
// (#jwks_endpoint) and registration_endpoint — keep their original element ids
// and their own handling; they are NOT repeated here. Non-Discovery endpoints
// the pane also carries (introspection, revocation, device authorization) are
// likewise left alone.
//
//   name  the metadata member name, which is also the input's element id
//   type  'array'   -> comma-separated in the UI (values may contain spaces,
//                      e.g. response_types_supported "code id_token")
//         'boolean' -> true/false <select>
//         'string'  -> plain text
//   dflt  dummy default, in the same spirit as the other localhost placeholders.
//         The four booleans default to the values the spec itself defines.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "op_metadata",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");

var OP_METADATA = [
  { name: "issuer", type: "string", dflt: "https://localhost/oidc" },
  { name: "scopes_supported", type: "array", dflt: "openid, profile, email, address, phone, offline_access" },
  { name: "response_types_supported", type: "array", dflt: "code, id_token, id_token token, code id_token, code token, code id_token token" },
  { name: "response_modes_supported", type: "array", dflt: "query, fragment, form_post" },
  { name: "grant_types_supported", type: "array", dflt: "authorization_code, implicit, refresh_token, client_credentials, password, urn:ietf:params:oauth:grant-type:device_code" },
  { name: "acr_values_supported", type: "array", dflt: "0, 1" },
  { name: "subject_types_supported", type: "array", dflt: "public, pairwise" },
  { name: "id_token_signing_alg_values_supported", type: "array", dflt: "RS256, RS384, RS512, ES256, PS256, HS256" },
  { name: "id_token_encryption_alg_values_supported", type: "array", dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES, A128KW" },
  { name: "id_token_encryption_enc_values_supported", type: "array", dflt: "A128GCM, A192GCM, A256GCM, A128CBC-HS256" },
  { name: "userinfo_signing_alg_values_supported", type: "array", dflt: "RS256, ES256, HS256" },
  { name: "userinfo_encryption_alg_values_supported", type: "array", dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES" },
  { name: "userinfo_encryption_enc_values_supported", type: "array", dflt: "A128GCM, A256GCM, A128CBC-HS256" },
  { name: "request_object_signing_alg_values_supported", type: "array", dflt: "none, RS256, ES256, PS256" },
  { name: "request_object_encryption_alg_values_supported", type: "array", dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES" },
  { name: "request_object_encryption_enc_values_supported", type: "array", dflt: "A128GCM, A256GCM, A128CBC-HS256" },
  { name: "token_endpoint_auth_methods_supported", type: "array", dflt: "client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt, none" },
  { name: "token_endpoint_auth_signing_alg_values_supported", type: "array", dflt: "RS256, ES256, PS256, HS256" },
  { name: "display_values_supported", type: "array", dflt: "page, popup, touch, wap" },
  { name: "claim_types_supported", type: "array", dflt: "normal, aggregated, distributed" },
  { name: "claims_supported", type: "array", dflt: "sub, iss, aud, exp, iat, auth_time, nonce, acr, amr, azp, name, given_name, family_name, preferred_username, email, email_verified" },
  { name: "service_documentation", type: "string", dflt: "https://localhost/oidc/docs" },
  { name: "claims_locales_supported", type: "array", dflt: "en-US, en-GB, fr-CA" },
  { name: "ui_locales_supported", type: "array", dflt: "en-US, en-GB, fr-CA" },
  { name: "claims_parameter_supported", type: "boolean", dflt: "false" },
  { name: "request_parameter_supported", type: "boolean", dflt: "false" },
  { name: "request_uri_parameter_supported", type: "boolean", dflt: "true" },
  { name: "require_request_uri_registration", type: "boolean", dflt: "false" },
  { name: "op_policy_uri", type: "string", dflt: "https://localhost/oidc/policy" },
  { name: "op_tos_uri", type: "string", dflt: "https://localhost/oidc/tos" }
];

// ---------------------------------------------------------------------------
// Members RFC 8414 (OAuth 2.0 Authorization Server Metadata) section 2 defines
// that OpenID Connect Discovery 1.0 does NOT.
//
// Kept as a separate list because that distinction is real — an OIDC Discovery
// document legitimately omits all six, and they should show the
// -->not defined<-- note when it does — but every pane that shows OpenID
// Provider metadata shows these as well, so the operations below run over both
// lists (ALL_METADATA).
// ---------------------------------------------------------------------------
var AS_ONLY_METADATA = [
  { name: "revocation_endpoint_auth_methods_supported", type: "array", dflt: "client_secret_basic, client_secret_post, private_key_jwt" },
  { name: "revocation_endpoint_auth_signing_alg_values_supported", type: "array", dflt: "RS256, ES256, PS256" },
  { name: "introspection_endpoint_auth_methods_supported", type: "array", dflt: "client_secret_basic, client_secret_post, private_key_jwt" },
  { name: "introspection_endpoint_auth_signing_alg_values_supported", type: "array", dflt: "RS256, ES256, PS256" },
  { name: "code_challenge_methods_supported", type: "array", dflt: "S256, plain" },
  { name: "signed_metadata", type: "string", dflt: "" }
];

// Every member the Configuration Parameters panes carry: an authorization
// server can define both sets, and the panes have a field for each.
var ALL_METADATA = OP_METADATA.concat(AS_ONLY_METADATA);

// A discovery value -> the string shown in its field. Arrays of scalars are
// joined with ", " so members containing spaces survive the round trip; a JSON
// structure is pretty-printed (metadata_client decides which is which).
function opMetadataToField(value) {
  return metadataClient.valueToDisplay(value);
}

function el(id) { return document.getElementById(id); }
function fieldValue(id) { var e = el(id); return e ? e.value : ""; }
// Writing through metadata_client, so a member whose value is a JSON structure
// gets a <textarea> that can show it pretty-printed.
function setFieldValue(id, v) { metadataClient.setMetadataField(id, v); }

function writeOpMetadataToLocalStorage() {
  ALL_METADATA.forEach(function (m) {
    localStorage.setItem(m.name, fieldValue(m.name));
  });
}

function initOpMetadataDefaults() {
  ALL_METADATA.forEach(function (m) { localStorage.setItem(m.name, m.dflt); });
}

function loadOpMetadataFromLocalStorage() {
  ALL_METADATA.forEach(function (m) {
    var v = localStorage.getItem(m.name);
    setFieldValue(m.name, (v === null || v === undefined) ? m.dflt : v);
  });
}

// Fill the pane from a fetched discovery document. A member the OP omits is
// blanked rather than left showing a stale value from a previous provider.
function populateOpMetadataFromDiscovery(info) {
  info = info || {};
  ALL_METADATA.forEach(function (m) {
    var v = opMetadataToField(info[m.name]);
    setFieldValue(m.name, v);
    if (localStorage) localStorage.setItem(m.name, v);
  });
  // Anything the document left out gets the grayed-out note.
  applyNotDefinedNotes(info);
}


// Blank every member ON SCREEN only. Safe to call during page load, where the
// pane is reset to a known state before the stored values are read back.
function clearOpMetadataFields() {
  ALL_METADATA.forEach(function (m) { setFieldValue(m.name, ""); });
  clearNotDefinedNotes();
}

// Blank every member IN STORAGE. Only for the Clear button — never on load.
// The value is set to "" rather than removed on purpose: loadFromLocalStorage()
// falls back to the dummy default when a key is ABSENT, so removing the keys
// would resurrect the defaults on the next load and undo the clear.
function clearOpMetadataStorage() {
  ALL_METADATA.forEach(function (m) {
    try {
      localStorage.setItem(m.name, "");
    } catch (e) {
      // No storage available in this context.
    }
  });
}

// ---------------------------------------------------------------------------
// "not defined" notes.
//
// When a loaded discovery document omits a member, its field shows a grayed-out
// -->not defined<-- note instead of sitting empty and ambiguous. The note is a
// PLACEHOLDER (and, for the boolean <select>s, a transient option), never a
// value: the field stays empty, so the note is never saved, never sent, and
// vanishes the moment the value is overridden.
//
// The state is derived from the stored discovery document rather than stored
// separately, so it survives a reload and disappears when the document is
// cleared. Both debugger.html and debugger2.html apply it on load.
// ---------------------------------------------------------------------------
var DISCOVERY_INFO_KEY = "discovery_info";
var NOT_DEFINED_NOTE = "-->not defined<--";
var NOT_DEFINED_CLASS = "not-defined";

// Members the pane already carried under a different element id, so they get
// the same treatment as the rest.
var LEGACY_FIELDS = {
  authorization_endpoint: "authorization_endpoint",
  token_endpoint: "token_endpoint",
  oidc_userinfo_endpoint: "userinfo_endpoint",
  jwks_endpoint: "jwks_uri",
  registration_endpoint: "registration_endpoint"
};

function markNotDefined(id, on) {
  log.debug("Entering markNotDefined().");
  var e = el(id);
  if (!e) return;
  // Only ever annotate an EMPTY field: an overridden value speaks for itself.
  if (on && e.value) on = false;
  if (e.tagName === "SELECT") {
    var opt = e.querySelector('option[data-not-defined]');
    if (on) {
      if (!opt) {
        opt = document.createElement("option");
        opt.value = "";
        opt.textContent = NOT_DEFINED_NOTE;
        opt.setAttribute("data-not-defined", "true");
        e.insertBefore(opt, e.firstChild);
      }
      e.value = "";
      e.classList.add(NOT_DEFINED_CLASS);
    } else {
      if (opt) opt.parentNode.removeChild(opt);
      e.classList.remove(NOT_DEFINED_CLASS);
    }
    return;
  }
  if (on) {
    e.placeholder = NOT_DEFINED_NOTE;
    e.classList.add(NOT_DEFINED_CLASS);
  } else {
    if (e.placeholder === NOT_DEFINED_NOTE) e.placeholder = "";
    e.classList.remove(NOT_DEFINED_CLASS);
  }
  log.debug("Leaving markNotDefined().");
}

// Annotate every member the document does not define; un-annotate the rest.
function applyNotDefinedNotes(info) {
  info = info || {};
  ALL_METADATA.forEach(function (m) {
    markNotDefined(m.name, !Object.prototype.hasOwnProperty.call(info, m.name));
  });
  Object.keys(LEGACY_FIELDS).forEach(function (id) {
    markNotDefined(id, !Object.prototype.hasOwnProperty.call(info, LEGACY_FIELDS[id]));
  });
}

function clearNotDefinedNotes() {
  ALL_METADATA.forEach(function (m) { markNotDefined(m.name, false); });
  Object.keys(LEGACY_FIELDS).forEach(function (id) { markNotDefined(id, false); });
}

// Apply the notes from the discovery document held in storage (if any). Called
// on load by both debugger pages.
function applyNotesFromStoredDiscovery() {
  log.debug("Entering applyNotesFromStoredDiscovery().");
  var saved = null;
  try {
    saved = localStorage.getItem(DISCOVERY_INFO_KEY);
  } catch (e) {
    return;
  }
  if (!saved) { clearNotDefinedNotes(); return; }
  try {
    applyNotDefinedNotes(JSON.parse(saved));
  } catch (e) {
    clearNotDefinedNotes();
  }
  log.debug("Leaving applyNotesFromStoredDiscovery().");
}

module.exports = {
  OP_METADATA: OP_METADATA,
  AS_ONLY_METADATA: AS_ONLY_METADATA,
  ALL_METADATA: ALL_METADATA,
  toField: opMetadataToField,
  writeToLocalStorage: writeOpMetadataToLocalStorage,
  initDefaults: initOpMetadataDefaults,
  loadFromLocalStorage: loadOpMetadataFromLocalStorage,
  populateFromDiscovery: populateOpMetadataFromDiscovery,
  clearFields: clearOpMetadataFields,
  clearStorage: clearOpMetadataStorage,
  DISCOVERY_INFO_KEY: DISCOVERY_INFO_KEY,
  NOT_DEFINED_NOTE: NOT_DEFINED_NOTE,
  markNotDefined: markNotDefined,
  applyNotes: applyNotDefinedNotes,
  applyNotesFromStoredDiscovery: applyNotesFromStoredDiscovery,
  clearNotes: clearNotDefinedNotes
};
