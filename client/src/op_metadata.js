// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: op_metadata.js
//
// ---------------------------------------------------------------------------
// OpenID Provider Metadata — OpenID Connect Discovery 1.0 section 3.
//
// Shared by the Configuration Parameters pane on BOTH oauth2_oidc_1.html and
// oauth2_oidc_2.html (same element ids, same localStorage keys, same origin),
// so the two panes cannot drift apart.
//
// Every field the spec defines is shown in the Configuration Parameters pane so
// a discovery document can be inspected (and overridden) in full. The five that
// the debugger already drove before this table existed —
// authorization_endpoint, token_endpoint, userinfo_endpoint
// (#oidc_userinfo_endpoint), jwks_uri (#jwks_endpoint) and
// registration_endpoint — keep their original element ids and their own
// handling; they are NOT repeated here. Non-Discovery endpoints the pane also
// carries (introspection, revocation, device authorization) are likewise left
// alone.
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

// The rows are models/catalog/oauth.tsp, generated into ./catalog/. OP_METADATA
// is OpenID Connect Discovery 1.0 section 3, less the five members the pane
// carried under their own element ids before this table existed (see
// LEGACY_FIELDS below). AS_ONLY_METADATA is what RFC 8414 section 2 (and RFC
// 9449 section 5.1) define and Discovery does not: an OIDC Discovery document
// legitimately omits all of them, so they are kept as a list of their own.
var OP_METADATA = require("./catalog/op_metadata.json");
var AS_ONLY_METADATA = require("./catalog/as_only_metadata.json");

// Every member the Configuration Parameters panes carry: an authorization
// server can define both sets, and the panes have a field for each.
var ALL_METADATA = OP_METADATA.concat(AS_ONLY_METADATA);

// A discovery value -> the string shown in its field. Arrays of scalars are
// joined with ", " so members containing spaces survive the round trip; a JSON
// structure is pretty-printed (metadata_client decides which is which).
function opMetadataToField(value) {
  log.debug("Entering opMetadataToField().");
  log.debug("Leaving opMetadataToField().");
  return metadataClient.valueToDisplay(value);
}

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
function fieldValue(id) {
  log.debug("Entering fieldValue().");
  var e = el(id);
  log.debug("Leaving fieldValue().");
  return e ? e.value : "";
}
// Writing through metadata_client, so a member whose value is a JSON structure
// gets a <textarea> that can show it pretty-printed.
function setFieldValue(id, v) {
  log.debug("Entering setFieldValue().");
  metadataClient.setMetadataField(id, v);
  log.debug("Leaving setFieldValue().");
}

function writeOpMetadataToLocalStorage() {
  log.debug("Entering writeOpMetadataToLocalStorage().");
  ALL_METADATA.forEach(function (m) {
    localStorage.setItem(m.name, fieldValue(m.name));
  });
  log.debug("Leaving writeOpMetadataToLocalStorage().");
}

function initOpMetadataDefaults() {
  log.debug("Entering initOpMetadataDefaults().");
  ALL_METADATA.forEach(function (m) { localStorage.setItem(m.name, m.dflt); });
  log.debug("Leaving initOpMetadataDefaults().");
}

function loadOpMetadataFromLocalStorage() {
  log.debug("Entering loadOpMetadataFromLocalStorage().");
  ALL_METADATA.forEach(function (m) {
    var v = localStorage.getItem(m.name);
    setFieldValue(m.name, (v === null || v === undefined) ? m.dflt : v);
  });
  log.debug("Leaving loadOpMetadataFromLocalStorage().");
}

// Fill the pane from a fetched discovery document. A member the OP omits is
// blanked rather than left showing a stale value from a previous provider.
function populateOpMetadataFromDiscovery(info) {
  log.debug("Entering populateOpMetadataFromDiscovery().");
  info = info || {};
  ALL_METADATA.forEach(function (m) {
    var v = opMetadataToField(info[m.name]);
    setFieldValue(m.name, v);
    if (localStorage) localStorage.setItem(m.name, v);
  });
  // Anything the document left out gets the grayed-out note.
  applyNotDefinedNotes(info);
  log.debug("Leaving populateOpMetadataFromDiscovery().");
}


// Blank every member ON SCREEN only. Safe to call during page load, where the
// pane is reset to a known state before the stored values are read back.
function clearOpMetadataFields() {
  log.debug("Entering clearOpMetadataFields().");
  ALL_METADATA.forEach(function (m) { setFieldValue(m.name, ""); });
  clearNotDefinedNotes();
  log.debug("Leaving clearOpMetadataFields().");
}

// Blank every member IN STORAGE. Only for the Clear button — never on load.
// The value is set to "" rather than removed on purpose: loadFromLocalStorage()
// falls back to the dummy default when a key is ABSENT, so removing the keys
// would resurrect the defaults on the next load and undo the clear.
function clearOpMetadataStorage() {
  log.debug("Entering clearOpMetadataStorage().");
  ALL_METADATA.forEach(function (m) {
    try {
      localStorage.setItem(m.name, "");
    } catch (e) {
      // No storage available in this context.
    }
  });
  log.debug("Leaving clearOpMetadataStorage().");
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
// cleared. Both oauth2_oidc_1.html and oauth2_oidc_2.html apply it on load.
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
  if (!e) {
    log.debug("Leaving markNotDefined().");
    return;
  }
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
    log.debug("Leaving markNotDefined().");
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
  log.debug("Entering applyNotDefinedNotes().");
  info = info || {};
  ALL_METADATA.forEach(function (m) {
    markNotDefined(m.name, !Object.prototype.hasOwnProperty.call(info, m.name));
  });
  Object.keys(LEGACY_FIELDS).forEach(function (id) {
    markNotDefined(id, !Object.prototype.hasOwnProperty.call(info,
                   LEGACY_FIELDS[id]));
  });
  log.debug("Leaving applyNotDefinedNotes().");
}

function clearNotDefinedNotes() {
  log.debug("Entering clearNotDefinedNotes().");
  ALL_METADATA.forEach(function (m) { markNotDefined(m.name, false); });
  Object.keys(LEGACY_FIELDS).forEach(function (id) { markNotDefined(id,
              false); });
  log.debug("Leaving clearNotDefinedNotes().");
}

// Apply the notes from the discovery document held in storage (if any). Called
// on load by both debugger pages.
function applyNotesFromStoredDiscovery() {
  log.debug("Entering applyNotesFromStoredDiscovery().");
  var saved = null;
  try {
    saved = localStorage.getItem(DISCOVERY_INFO_KEY);
  } catch (e) {
    log.debug("Leaving applyNotesFromStoredDiscovery().");
    return;
  }
  if (!saved) {
    clearNotDefinedNotes();
    log.debug("Leaving applyNotesFromStoredDiscovery().");
    return;
  }
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
