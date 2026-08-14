// File: vc_issuance_1.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 1: discover the issuer and settle the configuration.
//
// Four panes:
//
//   1. Credential Issuer Metadata (OID4VCI) — retrieve, tabulate, validate its
//      signed_metadata, and pick which credential to ask for.
//   2. Authorization Server Metadata (RFC 8414) — the same pane debugger.html
//      has, writing to the SAME localStorage keys, so what is retrieved here
//      configures the OAuth2 / OIDC workflow that step 2 hands off to.
//   3. Configuration Parameters — every member both documents can define,
//      generated from the member lists so the pane cannot drift from them.
//   4. The hand-off to debugger.html?sdjwtvc=1.
//
// The fetch / table / signature-validation machinery is metadata_client.js,
// shared with debugger.html. The member lists are op_metadata.js (OpenID
// Provider + the RFC 8414-only members) and vci_metadata.js (credential
// issuer).
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var metadataSchema = require("./metadata_schema");
var opMetadata = require("./op_metadata");
var vciMetadata = require("./vci_metadata");
var sdJwtVc = require("./sd_jwt_vc");
var didLib = require("./did");
var urlSafety = require("./url_safety");

var log = bunyan.createLogger({ name: 'vc_issuance_1',
                                level: appconfig.LOG_LEVEL || 'info' });

// --- storage keys -----------------------------------------------------------
// The credential issuer document is this page's own; the authorization server
// document is deliberately the one debugger.html uses.
var VCI_STORE = metadataClient.createStore("vci_info", "vci_info_source");
var AS_STORE = metadataClient.createStore(opMetadata.DISCOVERY_INFO_KEY,
    "discovery_info_source");
var VCI_URL_KEY = "vci_metadata_endpoint";

var VCI_DOC_LABEL = "OID4VCI Credential Issuer Metadata";
var AS_DOC_LABEL = "OAuth 2.0 Authorization Server Metadata (RFC 8414)";
var VCI_WELL_KNOWN = "/.well-known/openid-credential-issuer";
var AS_WELL_KNOWN = "/.well-known/oauth-authorization-server";
var JWT_VC_ISSUER_WELL_KNOWN = "/.well-known/jwt-vc-issuer";

// The two documents currently on display.
var vciInfo = {};
var asInfo = {};
// Whether the last retrieval actually reached storage. A table on screen with
// nothing behind it is the state that makes Validate Signature look broken, so
// each pane knows which it is in and can say so.
var vciStored = true;
var asStored = true;

// ---------------------------------------------------------------------------
// The plain fields the Configuration Parameters pane carries besides the
// metadata member lists: the OAuth 2.0 client settings the authorization
// request needs, and the endpoints the debugger pane has always had under its
// own element ids. Ids and localStorage keys match debugger.html exactly.
// ---------------------------------------------------------------------------
var CLIENT_FIELDS = [
  { name: "client_id", dflt: "oidc-authorization-code-public",
    desc: "The OAuth 2.0 client the authorization request is made with. In " +
        "OID4VCI terms this is the wallet." },
  { name: "redirect_uri", dflt: "",
    desc: "Where the authorization server sends the authorization code: this " +
        "deployment's /callback, which forwards to debugger2.html. The " +
        "debugger pages pin this to their own configured origin, so an edit " +
        "here is only honoured if it points at that origin." },
  { name: "scope", dflt: "openid profile email",
    desc: "The scopes the authorization request asks for. Add the credential " +
        "configuration's scope value to ask the authorization server for " +
        "authorization to issue that credential." }
];

// `member` is the metadata member name; `name` is the element id and storage
// key, which for two of them is not the same thing (debugger.html has always
// called them that, and these fields exist to stay compatible with it).
var ENDPOINT_FIELDS = [
  { name: "authorization_endpoint", member: "authorization_endpoint", dflt: "",
   desc: "Where the user is sent to authenticate and authorize issuance. " +
   "Populated from the authorization server metadata." },
  { name: "token_endpoint", member: "token_endpoint", dflt: "",
   desc: "Where debugger2.html exchanges the authorization code for tokens. " +
   "Populated from the authorization server metadata." },
  { name: "oidc_userinfo_endpoint", member: "userinfo_endpoint", dflt: "",
   desc: "The OIDC userinfo endpoint (userinfo_endpoint). Not used by " +
   "issuance, but part of the metadata document." },
  { name: "jwks_endpoint", member: "jwks_uri", dflt: "",
   desc: "The authorization server's JWKS (jwks_uri) — the keys its tokens " +
   "are signed with." },
  { name: "registration_endpoint", member: "registration_endpoint", dflt: "",
   desc: "The OIDC Dynamic Client Registration endpoint " +
   "(registration_endpoint)." },
  { name: "introspection_endpoint", member: "introspection_endpoint", dflt: "",
   desc: "The token introspection endpoint (RFC 7662)." },
  { name: "revocation_endpoint", member: "revocation_endpoint", dflt: "",
   desc: "The token revocation endpoint (RFC 7009)." },
  { name: "device_authorization_endpoint",
   member: "device_authorization_endpoint", dflt: "",
   desc: "The device authorization endpoint (RFC 8628)." }
];

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
// Said once, by both panes, when the document could not be stored — the browser
// is out of quota or storage is blocked. The table is on screen and Validate
// Signature works now, from the copy in this page; neither survives leaving it.
function notStoredNote(stored) {
  log.debug("Entering notStoredNote().");
  if (stored) {
    log.debug("Leaving notStoredNote().");
    return "";
  }
  log.debug("Leaving notStoredNote().");
  return " NOTE: this browser would not store the document (storage full or " +
      "blocked), so it will be gone " +
         "when you leave this page and Validate Signature will ask you to retrieve it again.";
}

// A metadata table with rows in it. What a pane shows and what it can validate
// have to agree, so the failure messages distinguish "nothing retrieved" from
// "a table is on screen but the document behind it is gone".
function tableIsDisplayed(id) {
  log.debug("Entering tableIsDisplayed().");
  var t = el(id);
  log.debug("Leaving tableIsDisplayed().");
  return !!(t && t.querySelectorAll("tr").length);
}
function val(id) {
  log.debug("Entering val().");
  var e = el(id);
  log.debug("Leaving val().");
  return e ? e.value : "";
}
function setText(id, t) {
  log.debug("Entering setText().");
  var e = el(id);
  if (e) e.textContent = (t == null ? "" : String(t));
  log.debug("Leaving setText().");
}
function setVal(id, v) {
  log.debug("Entering setVal().");
  var e = el(id);
  if (e) e.value = (v == null ? "" : v);
  log.debug("Leaving setVal().");
}
function status(id, text, cls) {
  log.debug("Entering status().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving status().");
    return;
  }
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
  log.debug("Leaving status().");
}
function esc(v) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return metadataClient.escapeHtmlText(v);
}

// ---------------------------------------------------------------------------
// Pane 3 — the generated rows.
// ---------------------------------------------------------------------------
function fieldRow(id, label, desc, type) {
  log.debug("Entering fieldRow().");
  var input;
  if (type === "boolean") {
    input = '<select class="stored" id="' + esc(id) + '" name="' + esc(id) +
        '">' +
              '<option value="true">true</option>' +
              '<option value="false">false</option>' +
            '</select>';
  } else if (type === "json") {
    // These members are JSON structures, shown pretty-printed. (A scalar value
    // swaps the textarea back to an input — see
    // metadata_client.setMetadataField.)
    input = '<textarea class="stored metadata-json-field" id="' + esc(id) +
        '" name="' + esc(id) +
            '" rows="3" spellcheck="false"></textarea>';
  } else {
    input = '<input class="stored" type="text" id="' + esc(id) + '" name="' +
        esc(id) + '" max="512" />';
  }
  log.debug("Leaving fieldRow().");
  return '<tr>' +
           '<td><div class="tooltip"><label>' + esc(label) + ': </label>' +
             '<span class="tooltiptext">' + esc(desc) + '</span></div></td>' +
           '<td>' + input + '</td>' +
         '</tr>';
}

// One GROUP of the Configuration Parameters pane. Closing the previous group's
// table and opening the next is what turns a single 3,988px table into blocks
// that can sit side by side — nothing about a group depends on being in the
// same table as its neighbours, and the pane was that tall only because they
// were.
//
// `first` suppresses the closing tags before the first group, so the caller
// does not have to special-case it.
var configGroupOpen = false;
function groupRow(title, subtitle) {
  log.debug("Entering groupRow().");
  var out = configGroupOpen ? "</tbody></table></div>" : "";
  configGroupOpen = true;
  log.debug("Leaving groupRow().");
  return out +
    '<div class="vc-config-group">' +
    '<h4 class="vc-group-heading">' + esc(title) +
    (subtitle ? ' <span>' + esc(subtitle) + '</span>' : '') + "</h4>" +
    '<table class="vc-config-table" border="0"><tbody>';
}

function closeConfigGroups() {
  log.debug("Entering closeConfigGroups().");
  var out = configGroupOpen ? "</tbody></table></div>" : "";
  configGroupOpen = false;
  log.debug("Leaving closeConfigGroups().");
  return out;
}

function buildConfigRows() {
  log.debug("Entering buildConfigRows().");
  var html = "";
  configGroupOpen = false;

  html += groupRow("OAuth 2.0 client",
                   "used by the authorization request in step 2");
  CLIENT_FIELDS.forEach(function (f) { html += fieldRow(f.name, f.name,
                        f.desc); });

  html += groupRow("Authorization server endpoints",
                   "OpenID Connect Discovery 1.0 / RFC 8414");
  ENDPOINT_FIELDS.forEach(function (f) { html += fieldRow(f.name, f.name,
                          f.desc); });

  html += groupRow("Authorization server metadata",
                   "the remaining members of the RFC 8414 document");
  opMetadata.OP_METADATA.forEach(function (m) {
    html += fieldRow(m.name, m.name,
      "Authorization server / OpenID Provider metadata member " + m.name +
      ". Populated from the retrieved metadata document; override it here.",
          m.type);
  });
  opMetadata.AS_ONLY_METADATA.forEach(function (m) {
    html += fieldRow(m.name, m.name,
      "RFC 8414 metadata member " + m.name +
      " (defined by RFC 8414, not by OpenID Connect Discovery 1.0).", m.type);
  });

  html += groupRow("Credential issuer metadata",
                   "OID4VCI Credential Issuer Metadata");
  vciMetadata.VCI_METADATA.forEach(function (m) {
    html += fieldRow(vciMetadata.idFor(m.name), m.name, m.desc, m.type);
  });

  // The DID section sits between the issuer's metadata and the chosen
  // credential, because that is where it belongs in the story: who the issuer
  // says it is, then how it is identified, then what it will hand over.
  html += groupRow("Issuer DID document",
                   "W3C DID Core 1.0, resolved in the pane above");
  html += '<tr><td>' +
    '<div class="tooltip"><label for="did_enabled">Use DIDs for this ' +
        'credential: </label>' +
    '<span class="tooltiptext">Whether this run treats the issuer as a DID: ' +
        'resolving its document ' +
    'for the verification key rather than using the credential issuer URL. ' +
        'Default ON for ldp_vc, ' +
    'which is DID-native under VC Data Model 2.0, and OFF for every other ' +
        'format \u2014 SD-JWT VC ' +
    'defines no DID-based issuer signature mechanism, so using one there is ' +
        'a profile ' +
    'extension.</span></div></td>' +
    '<td><input type="checkbox" id="did_enabled" name="did_enabled" ' +
    'onchange="return vcissuance1.onDidEnabledChange();" />' +
    '<span class="vc-note" id="did_enabled_note"></span></td></tr>';
  didLib.DID_METADATA.forEach(function (m) {
    html += fieldRow(didLib.idFor(m.name), m.name, m.desc, m.type);
  });

  // The DID Configuration sits directly after the DID document, because it is
  // what makes that document worth anything: the document says which keys a DID
  // has, and this says why the DID should be believed to be this issuer at all.
  html += groupRow("DID Configuration",
                   "DIF Well Known DID Configuration \u2014 the origin's " +
                       "claim on the DID above");
  didLib.DID_CONFIGURATION_METADATA.forEach(function (m) {
    html += fieldRow(didLib.didConfigurationIdFor(m.name), m.name, m.desc,
                     m.type);
  });

  html += groupRow("Credential configuration",
                   "the chosen entry of credential_configurations_supported");
  // The chooser sits at the head of the fields it FILLS IN, not up in the
  // metadata pane. Every field below is one of these hard-to-guess values —
  // format, vct, scope, credential_definition, the proof algorithms — and they
  // all change together when a different credential is picked. Having the
  // control next to its effect is the difference between "why did those fields
  // change" and "of course they did".
  html += '<tr><td>' +
    '<div class="tooltip"><label>Credential to request: </label>' +
    '<span class="tooltiptext">Which entry of ' +
        'credential_configurations_supported this run asks ' +
    'for. Choosing one rewrites every field in this section from the ' +
        'retrieved metadata, and it is ' +
    'what step 2 names in the Credential Request. The list appears once a ' +
        'credential issuer ' +
    'metadata document has been retrieved.</span></div></td>' +
    '<td><select id="vci_credential_configuration_select" ' +
    'onchange="return ' +
        'vcissuance1.onCredentialConfigurationChange();"></select>' +
    '<span class="vc-note" id="vci_configuration_note"></span></td></tr>';
  vciMetadata.VCI_CONFIG_METADATA.forEach(function (m) {
    html += fieldRow(vciMetadata.idFor(m.name), m.name, m.desc, m.type);
  });

  html += closeConfigGroups();

  var body = el("config_rows");
  if (body) body.innerHTML = html;
  log.debug("Leaving buildConfigRows().");
}

// --- reading and writing the pane ------------------------------------------
function plainFields() {
  log.debug("Entering plainFields().");
  log.debug("Leaving plainFields().");
  return CLIENT_FIELDS.concat(ENDPOINT_FIELDS);
}

function loadConfiguration() {
  log.debug("Entering loadConfiguration().");
  plainFields().forEach(function (f) {
    var v = sdJwtVc.get(f.name);
    setVal(f.name, (v === null || v === undefined) ? defaultFor(f) : v);
  });
  opMetadata.loadFromLocalStorage();
  vciMetadata.loadFromLocalStorage();
  // The DID fields and the use-DIDs box, after the metadata load: the box's
  // default follows the chosen credential's FORMAT, which vciMetadata has only
  // just restored. Rendering it before that reads an empty format and defaults
  // every credential to off, including the ldp_vc that should be on.
  didLib.DID_METADATA.forEach(function (m) {
    var v = sdJwtVc.get(didLib.idFor(m.name));
    if (v !== null && v !== undefined) setVal(didLib.idFor(m.name), v);
  });
  didLib.DID_CONFIGURATION_METADATA.forEach(function (m) {
    var id = didLib.didConfigurationIdFor(m.name);
    var v = sdJwtVc.get(id);
    if (v !== null && v !== undefined) setVal(id, v);
  });
  setVal(DID_ID_KEY, sdJwtVc.get(DID_ID_KEY) || "");
  renderDidEnabled();
  log.debug("Leaving loadConfiguration().");
}

function defaultFor(f) {
  log.debug("Entering defaultFor().");
  // The same rule debugger.html and debugger2.html apply: the redirect URI is
  // this deployment's own /callback. They re-default anything that does not
  // start with it, so offering a different value here would only mislead.
  if (f.name === "redirect_uri") {
    log.debug("Leaving defaultFor().");
    return (appconfig.uiUrl || window.location.origin) + "/callback";
  }
  log.debug("Leaving defaultFor().");
  return f.dflt;
}

function saveConfiguration() {
  log.debug("Entering saveConfiguration().");
  plainFields().forEach(function (f) { sdJwtVc.set(f.name, val(f.name)); });
  // debugger2.html reads the client id and scope it posts to the token endpoint
  // from their own keys, so keep those in step with the client fields here.
  sdJwtVc.set("token_client_id", val("client_id"));
  sdJwtVc.set("token_scope", val("scope"));
  opMetadata.writeToLocalStorage();
  vciMetadata.writeToLocalStorage();
  // debugger.html writes ITS dummy defaults over everything on what it thinks
  // is a first visit. This configuration is not a first visit, and the whole
  // point of sharing the storage is that the debugger pages run on it.
  sdJwtVc.set("initialized", true);
  sdJwtVc.set("debugger_initialized", true);
  updateHandoffSummary();
  status("config_status", "Saved.", "vc-ok");
  log.debug("Leaving saveConfiguration().");
  return false;
}

function clearConfiguration() {
  log.debug("Entering clearConfiguration().");
  plainFields().forEach(function (f) { setVal(f.name, ""); sdJwtVc.set(f.name,
              ""); });
  opMetadata.clearFields();
  opMetadata.clearStorage();
  vciMetadata.clearFields();
  vciMetadata.clearStorage();
  updateHandoffSummary();
  status("config_status",
         "Cleared — every parameter is now empty, here and in local storage.",
         "vc-ok");
  log.debug("Leaving clearConfiguration().");
  return false;
}

function restoreDefaults() {
  log.debug("Entering restoreDefaults().");
  plainFields().forEach(function (f) { setVal(f.name, defaultFor(f)); });
  opMetadata.ALL_METADATA.forEach(function (m) {
    metadataClient.setMetadataField(m.name, m.dflt);
    opMetadata.markNotDefined(m.name, false);
  });
  vciMetadata.VCI_METADATA.concat(vciMetadata.VCI_CONFIG_METADATA)
                                  .forEach(function (m) {
    metadataClient.setMetadataField(vciMetadata.idFor(m.name), m.dflt);
  });
  saveConfiguration();
  status("config_status", "Defaults restored.", "vc-ok");
  log.debug("Leaving restoreDefaults().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 1 — the credential issuer metadata document.
// ---------------------------------------------------------------------------
function renderVciTable() {
  log.debug("Entering renderVciTable().");
  var provenance = VCI_STORE.readProvenance();
  var html = metadataClient.buildInfoTable(vciInfo, provenance);
  el("vci_metadata_table").innerHTML = html;
  el("vci_metadata_populate").innerHTML =
    '<input class="btn_vci_populate_meta_data btn2" id="vci_populate_button" ' +
        'type="button"' +
    ' value="Populate Meta Data" onclick="return vcissuance1.populateFromVci();" />';
  log.debug("Leaving renderVciTable().");
}

function renderCredentialConfigurations() {
  log.debug("Entering renderCredentialConfigurations().");
  var select = el("vci_credential_configuration_select");
  var note = el("vci_configuration_note");
  if (!select) {
    log.debug("Leaving renderCredentialConfigurations().");
    return;
  }
  var configs = (vciInfo && vciInfo.credential_configurations_supported) || {};
  var ids = Object.keys(configs);
  if (!ids.length) {
    // The chooser now lives among the fields it fills, which are always on
    // screen, so it cannot simply be hidden: say why it is empty instead.
    select.innerHTML = "";
    if (note) {
      note.textContent = " Retrieve the credential issuer metadata above to see what this issuer offers.";
      note.className = "vc-note vc-pending";
    }
    log.debug("Leaving renderCredentialConfigurations().");
    return;
  }
  var chosen = val(vciMetadata.idFor("credential_configuration_id")) || ids[0];
  select.innerHTML = ids.map(function (id) {
    var cfg = configs[id] || {};
    var label = id + (cfg.format ? " (" + cfg.format + ")" : "");
    return '<option value="' + esc(id) + '"' + (id === chosen ?
        ' selected="selected"' : '') + '>' +
           esc(label) + '</option>';
  }).join("");
  if (note) {
    note.textContent = " " + ids.length + " offered by this issuer.";
    note.className = "vc-note";
  }
  log.debug("Leaving renderCredentialConfigurations(). " + ids.length +
            " offered.");
}

// ---------------------------------------------------------------------------
// Loading a metadata document from a local file.
//
// The reason this exists is CORS. Both panes fetch a document from an origin
// the user names, and a credential issuer or authorization server that sends no
// Access-Control-Allow-Origin cannot be read by a browser at all — the request
// succeeds, the browser refuses to hand the body to the page, and there is
// nothing the page can do about it. Neither is that a rare configuration:
// metadata is meant to be read by servers, so plenty of deployments never
// thought about browsers. walt.id's own services send no CORS headers, which is
// why this suite runs a proxy in front of them.
//
// So the document can be fetched with curl and loaded from disk instead. It
// goes through applyVciDocument / applyAsDocument, the same functions the
// retrieve route uses, so everything downstream is identical — the table, the
// credential list, the Configuration Parameters, Validate Signature, and what
// debugger.html then shows.
//
// Following the pattern already on saml_request.html and wsfed_request.html: a
// visible button, a hidden file input it clicks, and the input's value cleared
// afterwards so choosing the SAME file again still fires a change event.
// ---------------------------------------------------------------------------
function readMetadataFile(evt, statusId, onDocument) {
  log.debug("Entering readMetadataFile(). statusId=" + statusId);
  var input = evt && evt.target;
  var file = input && input.files && input.files[0];
  if (!file) {
    log.debug("Leaving readMetadataFile(). Nothing chosen.");
    return false;
  }
  status(statusId, "Reading " + file.name + " …", "vc-pending");
  var reader = new FileReader();
  reader.onload = function () {
    log.debug("Entering onload().");
    var doc = null;
    try {
      doc = JSON.parse(String(reader.result || ""));
    } catch (e) {
      status(statusId, "That file is not JSON: " + e.message, "vc-bad");
      if (input) input.value = "";
      log.debug("Leaving onload().");
      return;
    }
    if (!doc || typeof doc !== "object" ||
        Object.prototype.toString.call(doc) === "[object Array]") {
      status(statusId,
          "That file is JSON, but a metadata document has to be a JSON object.",
          "vc-bad");
      if (input) input.value = "";
      log.debug("Leaving onload().");
      return;
    }
    try {
      onDocument(doc, file.name);
    } finally {
      // Cleared whatever happened, so the same file can be chosen again after a
      // correction — otherwise the second attempt fires no change event and the
      // button looks broken.
      if (input) input.value = "";
    }
    log.debug("Leaving onload().");
  };
  reader.onerror = function () {
    log.debug("Entering onerror().");
    status(statusId, "Could not read " + file.name + ".", "vc-bad");
    if (input) input.value = "";
    log.debug("Leaving onerror().");
  };
  reader.readAsText(file);
  log.debug("Leaving readMetadataFile().");
  return false;
}

function uploadVciMetadata() {
  log.debug("Entering uploadVciMetadata().");
  var f = el("vci_metadata_file");
  if (f) f.click();
  log.debug("Leaving uploadVciMetadata().");
  return false;
}

function onVciFileChange(evt) {
  log.debug("Entering onVciFileChange().");
  log.debug("Leaving onVciFileChange().");
  return readMetadataFile(evt, "vci_signed_metadata_status", function (doc,
                          name) {
    applyVciDocument(doc, { docLabel: VCI_DOC_LABEL, file: name }, "Loaded");
  });
}

function uploadAsMetadata() {
  log.debug("Entering uploadAsMetadata().");
  var f = el("as_metadata_file");
  if (f) f.click();
  log.debug("Leaving uploadAsMetadata().");
  return false;
}

function onAsFileChange(evt) {
  log.debug("Entering onAsFileChange().");
  log.debug("Leaving onAsFileChange().");
  return readMetadataFile(evt, "as_signed_metadata_status", function (doc,
                          name) {
    applyAsDocument(doc, { source: "rfc8414", docLabel: AS_DOC_LABEL,
                    file: name }, "Loaded");
  });
}

// Everything that happens to a credential issuer metadata document once it is
// in hand, whether it arrived over the network or off disk.
//
// Shared deliberately: an uploaded document has to configure the workflow
// exactly as a retrieved one does — same storage, same table, same credential
// list, same Configuration Parameters, same Validate Signature. Two code paths
// here would mean the upload route quietly did less, and the difference would
// only show up later as a pane that looks filled in but drives nothing.
function applyVciDocument(doc, provenance, verb) {
  log.debug("Entering applyVciDocument(). " + (provenance && (provenance.url ||
            provenance.file)));
  vciInfo = doc || {};
  vciStored = VCI_STORE.save(vciInfo, provenance);
  renderVciTable();
  renderCredentialConfigurations();
  defaultAuthorizationServerUrl();
  // Obtaining a document is what configures this workflow, so the Configuration
  // Parameters pane is filled in straight away. The Populate Meta Data button
  // below the table re-applies the document afterwards (e.g. to undo a
  // hand-edit, or after choosing another credential).
  var used = populateFromVciDocument();
  offerAdvertisedIssuerDid();
  defaultDidConfigurationUrl();
  status("vci_signed_metadata_status",
    (verb || "Loaded") + " " + Object.keys(vciInfo).length + " members; " +
    Object.keys(vciInfo.credential_configurations_supported || {}).length +
    ' credential configuration(s) offered. Configuration Parameters ' +
        'populated (credential "' +
    used + '").' + notStoredNote(vciStored), vciStored ?
        "vc-ok" : "vc-pending");
  log.debug("credential issuer metadata: " + JSON.stringify(vciInfo));
  log.debug("Leaving applyVciDocument().");
}

function retrieveVciMetadata() {
  log.debug("Entering retrieveVciMetadata().");
  var url = val(VCI_URL_KEY);
  sdJwtVc.set(VCI_URL_KEY, url);
  if (!isUrl(url)) {
    status("vci_signed_metadata_status", "That is not a valid URL.", "vc-bad");
    log.debug("Leaving retrieveVciMetadata().");
    return false;
  }
  status("vci_signed_metadata_status", "Retrieving " + url + " …",
         "vc-pending");
  log.debug("Leaving retrieveVciMetadata().");
  return metadataClient.fetchJson(url)
    .then(function (doc) {
      applyVciDocument(doc, { docLabel: VCI_DOC_LABEL, url: url }, "Retrieved");
    })
    .catch(function (e) {
      status("vci_signed_metadata_status", "Could not retrieve the metadata: " +
             e.message, "vc-bad");
    });
}

// Once the issuer says which authorization server protects it, offer that
// server's RFC 8414 endpoint in pane 2 — unless the user has already put
// something else there.
function defaultAuthorizationServerUrl() {
  log.debug("Entering defaultAuthorizationServerUrl().");
  var servers = vciInfo.authorization_servers;
  // OID4VCI section 11.2.3: authorization_servers is OPTIONAL, and when it is
  // absent the entity providing the Credential Issuer is also the authorization
  // server. walt.id's issuer omits it and is its own — so falling back to the
  // credential issuer is the difference between discovering that server and
  // leaving the pane pointed at whatever was there before.
  var as = (Object.prototype.toString.call(servers) === "[object Array]" &&
      servers.length)
    ? servers[0] : (vciInfo.credential_issuer || "");
  if (!as) {
    log.debug("Leaving defaultAuthorizationServerUrl(). The document names " +
              "no server.");
    return;
  }
  var current = val("oidc_discovery_endpoint");
  if (current && current.indexOf(AS_WELL_KNOWN) < 0) {
    log.debug("Leaving defaultAuthorizationServerUrl().");
    return;
  }
  if (current && current.indexOf(as) === 0) {
    log.debug("Leaving defaultAuthorizationServerUrl().");
    return;
  }
  setVal("oidc_discovery_endpoint", metadataClient.wellKnownCandidates(as,
         AS_WELL_KNOWN)[0]);
  sdJwtVc.set("oidc_discovery_endpoint", val("oidc_discovery_endpoint"));
  log.debug("Leaving defaultAuthorizationServerUrl(). " +
            val("oidc_discovery_endpoint"));
}

function clearVciMetadata() {
  log.debug("Entering clearVciMetadata().");
  vciInfo = {};
  VCI_STORE.forget();
  sdJwtVc.set(VCI_URL_KEY, "");
  setVal(VCI_URL_KEY, "");
  el("vci_metadata_table").innerHTML = "";
  el("vci_metadata_populate").innerHTML = "";
  el("vci_configuration_row").style.display = "none";
  vciMetadata.clearFields();
  vciMetadata.clearStorage();
  updateHandoffSummary();
  status("vci_signed_metadata_status", "Cleared.", "vc-ok");
  log.debug("Leaving clearVciMetadata().");
  return false;
}

// Fill the OID4VCI half of the Configuration Parameters pane from the document
// on display and the credential currently chosen. Returns which credential.
function populateFromVciDocument() {
  log.debug("Entering populateFromVciDocument().");
  var select = el("vci_credential_configuration_select");
  var chosen = select && select.value ? select.value : "";
  var used = vciMetadata.populateFromMetadata(vciInfo, chosen);
  updateHandoffSummary();
  log.debug("Leaving populateFromVciDocument().");
  return used;
}

// ---------------------------------------------------------------------------
// Reporting a schema check.
//
// The document is populated either way, and that is deliberate: this is a
// debugger. Refusing to populate an out-of-spec document would take away the
// one thing someone debugging an out-of-spec issuer needs — to see what their
// document actually does to a wallet. So the verdict is reported beside the
// populate, not in place of it.
//
// Errors and warnings are kept apart because they mean different things: an
// error is a MUST the document breaks, a warning is a SHOULD, a RECOMMENDED
// member, or something legal but odd. A checker that called both "invalid"
// would be ignored within a week.
// ---------------------------------------------------------------------------
function renderSchemaReport(hostId, result, spec) {
  log.debug("Entering renderSchemaReport().");
  var host = el(hostId);
  if (!host) {
    log.debug("Leaving renderSchemaReport().");
    return;
  }
  if (!result.errors.length && !result.warnings.length) {
    host.innerHTML = '<p class="vc-status vc-ok">Schema check: this document ' +
        'satisfies every rule ' +
      esc(spec) + " states for it.</p>";
    log.debug("Leaving renderSchemaReport().");
    return;
  }
  var row = function (item, kind) {
    log.debug("Entering row().");
    log.debug("Leaving row().");
    return "<tr><td class=\"" + (kind === "error" ? "vc-bad" : "vc-pending") +
        "\">" +
      (kind === "error" ? "ERROR" : "warning") + "</td><td><code>" +
       esc(item.member) + "</code></td>" +
      "<td>" + esc(item.message) + "</td><td>" + esc(item.cite || spec) +
          "</td></tr>";
  };
  host.innerHTML =
    '<p class="vc-status ' + (result.errors.length ? "vc-bad" : "vc-pending") +
        '">Schema check against ' +
    esc(spec) + ": " + result.errors.length + " error(s), " +
        result.warnings.length + " warning(s). " +
    "The Configuration Parameters were populated regardless, so you can see " +
        "what this document does." +
    "</p><table class=\"vc-token-table\"><thead><tr><th>Result</th><th>Member</th><th>What the " +
    "specification says</th><th>Where</th></tr></thead><tbody>" +
    result.errors.map(function (e) { return row(e, "error"); }).join("") +
    result.warnings.map(function (w) { return row(w, "warning"); }).join("") +
    "</tbody></table>";
  log.debug("Leaving renderSchemaReport().");
}

function populateFromVci() {
  log.debug("Entering populateFromVci().");
  if (!vciInfo || !Object.keys(vciInfo).length) {
    status("vci_signed_metadata_status",
           "Retrieve the credential issuer metadata first.", "vc-bad");
    log.debug("Leaving populateFromVci().");
    return false;
  }
  var used = populateFromVciDocument();
  // Checked at the moment the document is put to use, which is when being told
  // it is malformed is worth something.
  var check = metadataSchema.validateVciMetadata(vciInfo);
  renderSchemaReport("vci_schema_report", check, metadataSchema.VCI_SPEC);
  status("vci_signed_metadata_status",
    'Configuration Parameters populated from the credential issuer metadata ' +
        '(credential "' + used + '"). ' +
    metadataSchema.summarize(check, "Schema check"),
    check.errors.length ? "vc-bad" : (check.warnings.length ?
        "vc-pending" : "vc-ok"));
  log.debug("Leaving populateFromVci().");
  return false;
}

function onCredentialConfigurationChange() {
  log.debug("Entering onCredentialConfigurationChange().");
  // Only re-populate the credential-configuration half; the issuer-level values
  // are unaffected by which credential is chosen.
  if (vciInfo && Object.keys(vciInfo).length) populateFromVci();
  log.debug("Leaving onCredentialConfigurationChange().");
  return false;
  // The format may have changed, and with it whether DIDs default on.
  renderDidEnabled();
  log.debug("Leaving onCredentialConfigurationChange().");
}

// The issuer's signing keys: a jwks_uri in the document if it has one,
// otherwise SD-JWT VC key resolution — /.well-known/jwt-vc-issuer under the
// credential issuer identifier, whose document carries the jwks_uri.
function resolveIssuerJwksUri(doc) {
  log.debug("Entering resolveIssuerJwksUri().");
  if (doc && doc.jwks_uri) {
    log.debug("Leaving resolveIssuerJwksUri().");
    return Promise.resolve(doc.jwks_uri);
  }
  var issuer = (doc && doc.credential_issuer) || "";
  if (!issuer) {
    log.debug("Leaving resolveIssuerJwksUri().");
    return Promise.resolve("");
  }
  log.debug("Leaving resolveIssuerJwksUri().");
  return metadataClient.fetchWellKnown(issuer, JWT_VC_ISSUER_WELL_KNOWN)
    .then(function (found) { return (found.doc && found.doc.jwks_uri) || ""; })
    .catch(function (e) {
      // No JWT VC issuer document, or it named no keys: the caller reports the
      // signature as unverifiable, which is more useful than an exception here.
      log.debug("resolveIssuerJwksUri(): " + e.message);
      return "";
    });
}

function validateVciSignature() {
  log.debug("Entering validateVciSignature().");
  var out = function (text, cls) {
    log.debug("Entering out().");
    status("vci_signed_metadata_status", text, cls);
    log.debug("Leaving out().");
  };
  // The document as it arrived, falling back to the parsed copy and then to
  // what is on this page — so the button works whenever a table is displayed,
  // rather than only in the visit that retrieved it.
  var chosen = metadataClient.documentForValidation(VCI_STORE, vciInfo);
  if (!chosen.doc) {
    out(tableIsDisplayed("vci_metadata_table")
      ? "The table above was drawn from a document this browser no longer " +
          "has, so there is nothing to " +
        "validate against. Retrieve it again."
      : "Retrieve the credential issuer metadata first.", "vc-bad");
    log.debug("Leaving validateVciSignature(). Nothing to validate.");
    return false;
  }
  out("Resolving the issuer's keys …", "vc-pending");
  resolveIssuerJwksUri(chosen.doc)
    .then(function (jwksUri) {
      return metadataClient.validateSignedMetadata(chosen.doc, {
        issuerMember: "credential_issuer",
        jwksUri: jwksUri,
        noSignedMetadataNote: "(signed_metadata is optional in OID4VCI.)",
        progress: function (t) { out(t, "vc-pending"); }
      });
    })
    .then(function (verdict) {
      out(verdict + chosen.note, verdict.indexOf("VALID") === 0 ?
          "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      // Belt and braces, not a fix for an observed hang: resolveIssuerJwksUri()
      // and validateSignedMetadata() both catch their own failures and RESOLVE
      // with a message, so this chain does not reject today. It is here so that
      // removing either of those catches surfaces as a verdict rather than as a
      // pane stuck on a progress line.
      out("Could not validate the signature: " + e.message, "vc-bad");
    });
  log.debug("Leaving validateVciSignature(). source=" + chosen.source);
  return false;
}

// ---------------------------------------------------------------------------
// Pane 2 — the authorization server metadata document.
//
// Same document, same storage keys and same table markup as the Metadata
// Retrieval pane on debugger.html, so retrieving it here configures that page
// too.
// ---------------------------------------------------------------------------
function renderAsTable() {
  log.debug("Entering renderAsTable().");
  var provenance = AS_STORE.readProvenance();
  el("discovery_info_table").innerHTML = metadataClient.buildInfoTable(asInfo,
     provenance);
  el("discovery_info_meta_data_populate").innerHTML =
    '<input class="btn_oidc_populate_meta_data btn2" id="as_populate_button" ' +
        'type="button"' +
    ' value="Populate Meta Data" onclick="return vcissuance1.populateFromAs();" />';
  log.debug("Leaving renderAsTable().");
}

// The authorization server document, once in hand. Shared by the retrieve and
// upload routes for the same reason as applyVciDocument.
function applyAsDocument(doc, provenance, verb) {
  log.debug("Entering applyAsDocument(). " + (provenance && (provenance.url ||
            provenance.file)));
  asInfo = doc || {};
  asStored = AS_STORE.save(asInfo, provenance);
  // debugger.html reads this to decide which source its radio shows.
  sdJwtVc.set("metadata_source", "rfc8414");
  renderAsTable();
  populateFromAsDocument();
  status("as_signed_metadata_status",
    (verb || "Loaded") + " " + Object.keys(asInfo).length +
     " members and populated the Configuration " +
    "Parameters pane. This document — and those values — are now what " +
        "debugger.html shows too." +
    notStoredNote(asStored), asStored ? "vc-ok" : "vc-pending");
  log.debug("Leaving applyAsDocument().");
}

function retrieveAsMetadata() {
  log.debug("Entering retrieveAsMetadata().");
  var url = val("oidc_discovery_endpoint");
  sdJwtVc.set("oidc_discovery_endpoint", url);
  if (!isUrl(url)) {
    status("as_signed_metadata_status", "That is not a valid URL.", "vc-bad");
    log.debug("Leaving retrieveAsMetadata().");
    return false;
  }
  status("as_signed_metadata_status", "Retrieving " + url + " …", "vc-pending");
  log.debug("Leaving retrieveAsMetadata().");
  return metadataClient.fetchJson(url)
    .then(function (doc) {
      applyAsDocument(doc, { source: "rfc8414", docLabel: AS_DOC_LABEL,
                      url: url }, "Retrieved");
    })
    .catch(function (e) {
      status("as_signed_metadata_status", "Could not retrieve the metadata: " +
             e.message, "vc-bad");
    });
}

function clearAsMetadata() {
  log.debug("Entering clearAsMetadata().");
  asInfo = {};
  AS_STORE.forget();
  el("discovery_info_table").innerHTML = "";
  el("discovery_info_meta_data_populate").innerHTML = "";
  setVal("oidc_discovery_endpoint", "");
  sdJwtVc.set("oidc_discovery_endpoint", "");
  ENDPOINT_FIELDS.forEach(function (f) { setVal(f.name, ""); sdJwtVc.set(f.name,
                          ""); });
  opMetadata.clearFields();
  opMetadata.clearStorage();
  opMetadata.clearNotes();
  updateHandoffSummary();
  status("as_signed_metadata_status",
         "Cleared — here and on the debugger pages.", "vc-ok");
  log.debug("Leaving clearAsMetadata().");
  return false;
}

function populateFromAs() {
  log.debug("Entering populateFromAs().");
  if (!asInfo || !Object.keys(asInfo).length) {
    status("as_signed_metadata_status",
           "Retrieve the authorization server metadata first.", "vc-bad");
    log.debug("Leaving populateFromAs().");
    return false;
  }
  populateFromAsDocument();
  var asCheck = metadataSchema.validateAsMetadata(asInfo);
  renderSchemaReport("as_schema_report", asCheck, metadataSchema.AS_SPEC);
  status("as_signed_metadata_status",
    "Configuration Parameters populated. debugger.html will run with " +
        "these values. " +
    metadataSchema.summarize(asCheck, "Schema check"),
    asCheck.errors.length ? "vc-bad" : (asCheck.warnings.length ?
        "vc-pending" : "vc-ok"));
  log.debug("Leaving populateFromAs().");
  return false;
}

// Fill the authorization server half of the Configuration Parameters pane from
// the document on display: the endpoints that live under their own element ids,
// the scope, and every other member the document defines.
function populateFromAsDocument() {
  log.debug("Entering populateFromAsDocument().");
  ENDPOINT_FIELDS.forEach(function (f) {
    var v = opMetadata.toField(asInfo[f.member]);
    setVal(f.name, v);
    sdJwtVc.set(f.name, v);
    opMetadata.markNotDefined(f.name,
                              !Object.prototype.hasOwnProperty.call(asInfo,
                              f.member));
  });
  populateScope();
  // ... and everything else the document defines — both the OpenID Provider
  // members and the six RFC 8414 adds, which populateFromDiscovery covers.
  opMetadata.populateFromDiscovery(asInfo);
  sdJwtVc.set("debugger_initialized", true);
  // The debugger pages write their dummy defaults over everything on what they
  // think is a first visit; this configuration is not one.
  sdJwtVc.set("initialized", true);
  updateHandoffSummary();
  log.debug("Leaving populateFromAsDocument().");
}

// The scope the authorization request will ask for.
//
// NOT simply scopes_supported: that is everything the SERVER knows about, and
// asking for scopes the client is not allowed usually earns an invalid_scope
// instead of an authorization code. So an existing value is left alone, an
// empty one gets the usual OIDC three (limited to what the server advertises),
// and the chosen credential configuration's own scope — the OID4VCI way of
// asking for authorization to issue that credential — is appended when the
// server advertises it.
function populateScope() {
  log.debug("Entering populateScope().");
  var supported = asInfo.scopes_supported;
  var have = (Object.prototype.toString.call(supported) === "[object Array]") ?
      supported : [];
  var current = (val("scope") || "").split(/\s+/).filter(Boolean);
  if (!current.length) {
    current = ["openid", "profile", "email"].filter(function (s) {
      return !have.length || have.indexOf(s) >= 0;
    });
  }
  var credentialScope = val(vciMetadata.idFor("scope"));
  if (credentialScope && have.indexOf(credentialScope) >= 0 &&
      current.indexOf(credentialScope) < 0) {
    current.push(credentialScope);
  }
  var scopes = current.join(" ");
  setVal("scope", scopes);
  sdJwtVc.set("scope", scopes);
  sdJwtVc.set("token_scope", scopes);
  log.debug("Leaving populateScope().");
}

function validateAsSignature() {
  log.debug("Entering validateAsSignature().");
  var out = function (text, cls) {
    log.debug("Entering out().");
    status("as_signed_metadata_status", text, cls);
    log.debug("Leaving out().");
  };
  var chosen = metadataClient.documentForValidation(AS_STORE, asInfo);
  if (!chosen.doc) {
    out(tableIsDisplayed("discovery_info_table")
      ? "The table above was drawn from a document this browser no longer " +
          "has, so there is nothing to " +
        "validate against. Retrieve it again."
      : "Retrieve the authorization server metadata first.", "vc-bad");
    log.debug("Leaving validateAsSignature(). Nothing to validate.");
    return false;
  }
  metadataClient.validateSignedMetadata(chosen.doc, {
    issuerMember: "issuer",
    noSignedMetadataNote: "(signed_metadata is an RFC 8414 member; OIDC " +
        "Discovery does not define it.)",
    progress: function (t) { out(t, "vc-pending"); }
  }).then(function (verdict) {
    out(verdict + chosen.note, verdict.indexOf("VALID") === 0 ?
        "vc-ok" : "vc-bad");
  }).catch(function (e) {
    out("Could not validate the signature: " + e.message, "vc-bad");
  });
  log.debug("Leaving validateAsSignature(). source=" + chosen.source);
  return false;
}

// ---------------------------------------------------------------------------
// Pane 4 — the hand-off.
// ---------------------------------------------------------------------------
function updateHandoffSummary() {
  log.debug("Entering updateHandoffSummary().");
  var authz = val("authorization_endpoint");
  var cfg = vciMetadata.currentRequestConfig();
  var e = el("handoff_authorization_endpoint");
  if (e) e.textContent = authz || "—";
  e = el("handoff_credential");
  if (e) {
    e.textContent = cfg.credentialConfigurationId
      ? cfg.credentialConfigurationId + " (" + (cfg.format || "?") + ", vct " +
          (cfg.vct || "?") + ")"
      : "—";
  }
  // The note depends on the credential chosen and on what the authorization
  // server advertises, so it is refreshed whenever this summary is.
  describeMechanism();
  log.debug("Leaving updateHandoffSummary().");
}

// ---------------------------------------------------------------------------
// How the authorization request says which credential is wanted (OID4VCI
// section 3.3.4). Either a scope, or RFC 9396 authorization_details of type
// openid_credential — and the choice has consequences all the way to step 2,
// because a token response that granted credential_identifiers requires the
// Credential Request to name one of THEM and forbids
// credential_configuration_id.
// ---------------------------------------------------------------------------
var MECHANISM_KEY = "sdjwtvc_request_mechanism";

function requestMechanism() {
  log.debug("Entering requestMechanism().");
  var chosen = val("handoff_request_mechanism") || sdJwtVc.get(MECHANISM_KEY) ||
      "scope";
  log.debug("Leaving requestMechanism().");
  return chosen === "authorization_details" ? "authorization_details" : "scope";
}

// What the authorization request will carry, or "" for the scope route.
function authorizationDetailsForRequest() {
  log.debug("Entering authorizationDetailsForRequest().");
  if (requestMechanism() !== "authorization_details") {
    log.debug("Leaving authorizationDetailsForRequest(). Using a scope.");
    return "";
  }
  var configId = val(vciMetadata.idFor("credential_configuration_id"));
  if (!configId) {
    log.debug("Leaving authorizationDetailsForRequest(). No credential " +
              "configuration is selected.");
    return "";
  }
  var details = [{ type: "openid_credential",
      credential_configuration_id: configId }];
  log.debug("Leaving authorizationDetailsForRequest(). " +
            JSON.stringify(details));
  return JSON.stringify(details);
}

function describeMechanism() {
  log.debug("Entering describeMechanism().");
  var mechanism = requestMechanism();
  var supported = (asInfo && asInfo.authorization_details_types_supported) ||
      null;
  var note;
  if (mechanism === "authorization_details") {
    note = "The authorization request will carry " +
        authorizationDetailsForRequest() + ".";
    if (supported && supported.indexOf("openid_credential") === -1) {
      note += " This authorization server advertises " +
          "authorization_details types " + supported.join(", ") +
              " — not openid_credential — so it may refuse the request.";
    } else if (!supported) {
      note += " This authorization server does not advertise " +
          "authorization_details_types_supported, so " +
              "whether it understands them is unknown until the request is made.";
    }
  } else {
    note = "The authorization request will ask with scope=" + (val("scope") ||
        "(empty)") +
           ", and step 2 will name the credential by its configuration id.";
    if (supported && supported.indexOf("openid_credential") !== -1) {
      note += " This server also supports authorization_details of type openid_credential.";
    }
  }
  setText("handoff_mechanism_note", note);
  log.debug("Leaving describeMechanism().");
  return note;
}

function onRequestMechanismChange() {
  log.debug("Entering onRequestMechanismChange().");
  sdJwtVc.set(MECHANISM_KEY, requestMechanism());
  describeMechanism();
  log.debug("Leaving onRequestMechanismChange().");
  return true;
}

function startIssuance() {
  log.debug("Entering startIssuance().");
  saveConfiguration();

  // A pre-authorized offer (H.2 / H.3) authorizes the issuance by itself: the
  // End-User was identified out of band and the code in the offer is the proof
  // of it. There is no authorization request, so there is nothing for
  // debugger.html to do — the wallet goes straight to the token endpoint, which
  // step 2 does because that is where the request can be shown before it is
  // sent.
  var preAuthorized = sdJwtVc.offerPreAuthorizedCode();
  if (preAuthorized) {
    var lacking = [];
    if (!val("token_endpoint")) lacking.push("token_endpoint");
    if (!val(vciMetadata.idFor("credential_endpoint"))) lacking.push(
        "credential_endpoint");
    if (lacking.length) {
      status("handoff_status",
        "Cannot start: " + lacking.join(", ") + " " + (lacking.length === 1 ?
            "is" : "are") +
        " empty. Retrieve the metadata documents above first.", "vc-bad");
      log.debug("Leaving startIssuance(). The pre-authorized flow is not " +
                "configured.");
      return false;
    }
    sdJwtVc.startFlow();
    status("handoff_status",
      "This offer carries a pre-authorized code, so there is no " +
          "authorization request — " +
      "going straight to the Token Request …", "vc-pending");
    window.location.href = sdJwtVc.STEP2_URL;
    log.debug("Leaving startIssuance(). Pre-authorized: skipping the " +
              "authorization request.");
    return false;
  }

  var missing = [];
  if (!val("authorization_endpoint")) missing.push("authorization_endpoint");
  if (!val("token_endpoint")) missing.push("token_endpoint");
  if (!val("client_id")) missing.push("client_id");
  if (!val(vciMetadata.idFor("credential_endpoint"))) missing.push(
      "credential_endpoint");
  if (missing.length) {
    status("handoff_status",
      "Cannot start: " + missing.join(", ") + " " + (missing.length === 1 ?
          "is" : "are") +
      " empty. Retrieve the metadata documents above (or fill the fields in " +
          "by hand) first.", "vc-bad");
    log.debug("Leaving startIssuance().");
    return false;
  }
  // debugger.html runs whichever grant its select says; this workflow needs the
  // OIDC Authorization Code flow.
  sdJwtVc.set("authorization_grant_type", "oidc_authorization_code_flow");
  // Which of the two ways of naming the credential the authorization request
  // uses. debugger.html reads this; step 2 reads what the token response then
  // granted, and neither has to know how the choice was made.
  sdJwtVc.set(MECHANISM_KEY, requestMechanism());
  sdJwtVc.set("sdjwtvc_authorization_details",
              authorizationDetailsForRequest());
  // An authorization_code offer carries an issuer_state, and the authorization
  // request has to send it back — that is what ties the request to the offer.
  var issuerState = sdJwtVc.offerIssuerState();
  sdJwtVc.set("sdjwtvc_issuer_state", issuerState || "");
  if (issuerState) log.debug("The authorization request will carry " +
      "issuer_state=" + issuerState);
  sdJwtVc.startFlow();
  status("handoff_status", "Starting the OIDC Authorization Code flow …",
         "vc-pending");
  window.location.href = "/debugger.html?sdjwtvc=1";
  log.debug("Leaving startIssuance().");
  return false;
}

// ---------------------------------------------------------------------------
// The Credential Offer (OID4VCI section 4) — how an issuer-initiated issuance
// (Appendix H.1) arrives here.
//
// The issuer sends the End-User to this page with either the offer itself
// (credential_offer, URL-encoded JSON) or a URL to fetch it from
// (credential_offer_uri). Either way it is shown before anything is requested,
// and it fills in the issuer and the credential so the user does not have to.
// ---------------------------------------------------------------------------
function queryParam(name) {
  log.debug("Entering queryParam().");
  try {
    log.debug("Leaving queryParam().");
    return new URLSearchParams(window.location.search).get(name) || "";
  } catch (e) {
    log.debug("Leaving queryParam().");
    return "";
  }
}

function renderOffer(stored) {
  log.debug("Entering renderOffer().");
  var pane = el("pane_offer");
  if (!pane) {
    log.debug("Leaving renderOffer().");
    return;
  }
  if (!stored || !stored.offer) {
    pane.style.display = "none";
    log.debug("Leaving renderOffer(). There is no offer to show.");
    return;
  }
  var offer = stored.offer;
  var grants = offer.grants || {};
  var grantName = Object.keys(grants)[0] ||
      "(none stated — the wallet chooses)";
  var issuerState = (grants.authorization_code || {}).issuer_state;
  var preAuth = sdJwtVc.preAuthorizedGrant(offer);
  var txCode = sdJwtVc.offerTxCode(offer);
  pane.style.display = "";
  el("offer_issuer").textContent = offer.credential_issuer || "—";
  el("offer_configuration_ids").textContent =
    (offer.credential_configuration_ids || []).join(", ") || "—";
  var grantText = grantName;
  if (issuerState) {
    grantText += " (issuer_state " + issuerState + ")";
  } else if (preAuth) {
    // The code itself is shown: this is a debugger, and the whole request it
    // will be spent on is displayed on the next page anyway.
    grantText += " (pre-authorized_code " + (preAuth["pre-authorized_code"] ||
        "—") + ")";
    if (txCode) {
      grantText += " — a Transaction Code is required: " +
                   (txCode.length ? txCode.length + " " : "") +
                   (txCode.input_mode || "characters") +
                   (txCode.description ? ", \u201c" + txCode.description +
                    "\u201d" : "");
    } else {
      grantText += " — no Transaction Code required";
    }
  }
  el("offer_grant").textContent = grantText;
  el("offer_source").textContent = stored.source === "reference"
    ? "by reference (credential_offer_uri), fetched from the issuer"
    : "by value (credential_offer), in the URL";
  el("offer_json").textContent = JSON.stringify(offer, null, 2);
  log.debug("Leaving renderOffer().");
}

// Everything the offer decides: which issuer to talk to, and which credential.
function applyOffer(offer) {
  log.debug("Entering applyOffer().");
  var issuer = offer.credential_issuer || "";
  if (issuer) {
    // An issuer identifier can carry a path, and then the well-known segment
    // goes in front of it rather than after — see wellKnownCandidates().
    var metadataUrl = metadataClient.wellKnownCandidates(issuer,
        VCI_WELL_KNOWN)[0];
    setVal(VCI_URL_KEY, metadataUrl);
    sdJwtVc.set(VCI_URL_KEY, metadataUrl);
    setVal(vciMetadata.idFor("credential_issuer"), issuer);
  }
  var ids = offer.credential_configuration_ids || [];
  if (ids.length) {
    setVal(vciMetadata.idFor("credential_configuration_id"), ids[0]);
    sdJwtVc.set(vciMetadata.idFor("credential_configuration_id"), ids[0]);
  }
  log.debug("Leaving applyOffer(). issuer=" + issuer + ", credential=" +
            (ids[0] || "(none)"));
}

// Retrieve the offered issuer's metadata straight away: the user was offered a
// credential, not asked to go and look one up.
function offerRetrieved() {
  log.debug("Entering offerRetrieved().");
  status("vci_signed_metadata_status",
         "Retrieving the offering issuer's metadata …", "vc-pending");
  // The offer names the issuer; the issuer's metadata names the authorization
  // server. A wallet handed an offer discovers both without being asked, so the
  // user only has to approve.
  var chained = retrieveVciMetadata();
  if (chained && chained.then) {
    chained.then(function () {
      status("as_signed_metadata_status",
        "Retrieving the metadata of the authorization server the " +
            "issuer named …", "vc-pending");
      return retrieveAsMetadata();
    }).then(function () {
      status("offer_status",
        "Offer accepted. The issuer and its authorization server are " +
            "configured below; " +
        "start the issuance when you are ready.", "vc-ok");
    });
  }
  log.debug("Leaving offerRetrieved().");
}

// ---------------------------------------------------------------------------
// An offer that arrived on ANOTHER device (H.2 / H.3).
//
// Nothing navigates the wallet here: the End-User scanned a QR code with their
// phone, or copied what it encodes. OID4VCI registers the
// openid-credential-offer:// URI scheme for that hand-over, but the payload is
// the same in every form, so all three are accepted — the URI, an https link
// carrying the same query parameters, and the bare JSON.
// ---------------------------------------------------------------------------
function readScannedOffer(input) {
  log.debug("Entering readScannedOffer().");
  var text = String(input || "").trim();
  if (!text) {
    log.debug("Leaving readScannedOffer(). Nothing was pasted.");
    return { error: "Paste the offer first — whatever the QR code contains." };
  }

  // The bare Credential Offer object.
  if (text.charAt(0) === "{") {
    try {
      var direct = JSON.parse(text);
      log.debug("Leaving readScannedOffer(). Read the offer as JSON.");
      return { offer: direct, source: "value" };
    } catch (e) {
      log.debug("Leaving readScannedOffer(). That is not readable JSON.");
      return { error: "That looks like JSON but does not parse: " + e.message };
    }
  }

  // A URI carrying the offer. The scheme may be one no URL parser knows, so the
  // query is taken from the string itself rather than by parsing the whole URI.
  var query = text.indexOf("?") !== -1 ? text.slice(text.indexOf("?") +
      1) : text;
  var params;
  try {
    params = new URLSearchParams(query);
  } catch (e) {
    log.debug("Leaving readScannedOffer(). The query could not be read: " +
              e.message);
    return { error: "That is not a Credential Offer URI: " + e.message };
  }

  var byValue = params.get("credential_offer");
  if (byValue) {
    try {
      log.debug("Leaving readScannedOffer(). The offer was passed by value.");
      return { offer: JSON.parse(byValue), source: "value" };
    } catch (e) {
      log.debug("Leaving readScannedOffer(). credential_offer is not JSON.");
      return { error: "The credential_offer parameter is not readable JSON: " +
              e.message };
    }
  }

  var byReference = params.get("credential_offer_uri");
  if (byReference) {
    log.debug("Leaving readScannedOffer(). The offer is by reference: " +
              byReference);
    return { uri: byReference, source: "reference" };
  }

  log.debug("Leaving readScannedOffer(). No offer in what was pasted.");
  return { error: "No credential_offer or credential_offer_uri in that. " +
          "Paste the whole thing the QR " +
                  "code contains." };
}

function takeScannedOffer() {
  log.debug("Entering takeScannedOffer().");
  var read = readScannedOffer(val("scan_offer_input"));
  if (read.error) {
    status("scan_status", read.error, "vc-bad");
    log.debug("Leaving takeScannedOffer(). " + read.error);
    return false;
  }

  var accept = function (offer, source) {
    log.debug("Entering accept().");
    // Which cross-device use case this is depends on the offer, not on what was
    // chosen in step 0: only the issuer knows whether it can issue immediately.
    // Deferral shows up later, in the Credential Response, so the offer alone
    // cannot distinguish H.2 from H.3 — leave the choice as it stands unless it
    // makes no sense for a pre-authorized offer.
    if (sdJwtVc.preAuthorizedGrant(offer)) {
      var current = sdJwtVc.currentUseCase();
      if (current.id !== "offer-cross-device" &&
          current.id !== "offer-deferred") {
        sdJwtVc.setUseCase("offer-cross-device");
      }
    } else {
      sdJwtVc.setUseCase("offer-same-device");
    }
    sdJwtVc.storeOffer(offer, source);
    applyOffer(offer);
    renderOffer(sdJwtVc.storedOffer());
    status("scan_status", "Offer taken. Discovering the issuer it names …",
           "vc-ok");
    offerRetrieved();
    log.debug("Leaving accept().");
  };

  if (read.uri) {
    status("scan_status", "Fetching the Credential Offer from " + read.uri +
           " …", "vc-pending");
    metadataClient.fetchJson(read.uri)
      .then(function (offer) {
        accept(offer, "reference");
      })
      .catch(function (e) {
        status("scan_status", "Could not fetch the Credential Offer: " +
               e.message, "vc-bad");
        log.error("credential_offer_uri: " + e.message);
      });
    log.debug("Leaving takeScannedOffer(). Fetching by reference.");
    return false;
  }

  accept(read.offer, read.source);
  log.debug("Leaving takeScannedOffer(). Took an offer passed by value.");
  return false;
}

function acceptOfferFromQuery() {
  log.debug("Entering acceptOfferFromQuery().");
  var byValue = queryParam("credential_offer");
  var byReference = queryParam("credential_offer_uri");

  if (byValue) {
    var offer;
    try {
      offer = JSON.parse(byValue);
    } catch (e) {
      status("offer_status",
             "The credential_offer parameter is not readable JSON: " +
             e.message, "vc-bad");
      log.error("credential_offer is not JSON: " + e.message);
      log.debug("Leaving acceptOfferFromQuery().");
      return false;
    }
    sdJwtVc.setUseCase("offer-same-device");
    sdJwtVc.storeOffer(offer, "value");
    applyOffer(offer);
    renderOffer(sdJwtVc.storedOffer());
    offerRetrieved();
    log.debug("Leaving acceptOfferFromQuery(). Took an offer passed by value.");
    return true;
  }

  if (byReference) {
    sdJwtVc.setUseCase("offer-same-device");
    status("offer_status", "Fetching the Credential Offer from " + byReference +
           " …", "vc-pending");
    metadataClient.fetchJson(byReference)
      .then(function (offer) {
        sdJwtVc.storeOffer(offer, "reference");
        applyOffer(offer);
        renderOffer(sdJwtVc.storedOffer());
        status("offer_status", "Offer fetched.", "vc-ok");
        offerRetrieved();
      })
      .catch(function (e) {
        status("offer_status", "Could not fetch the Credential Offer: " +
               e.message, "vc-bad");
        log.error("credential_offer_uri: " + e.message);
      });
    log.debug("Leaving acceptOfferFromQuery(). Fetching an offer passed by " +
              "reference.");
    return true;
  }
  log.debug("Leaving acceptOfferFromQuery(). No offer in the URL.");
  return false;
}

function discardOffer() {
  log.debug("Entering discardOffer().");
  sdJwtVc.forgetOffer();
  sdJwtVc.setUseCase("wallet-initiated");
  renderOffer(null);
  sdJwtVc.renderUseCaseBadge();
  log.debug("Leaving discardOffer().");
  return false;
}

// ---------------------------------------------------------------------------
function isUrl(url) {
  log.debug("Entering isUrl().");
  try {
    log.debug("Leaving isUrl().");
    return Boolean(new URL(url));
  } catch (e) {
    log.debug("Leaving isUrl().");
    return false;
  }
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

function clickLink() {
  log.debug("Entering clickLink().");
  log.debug("Leaving clickLink().");
  return true;
}

function onload() {
  log.debug("Entering onload().");
  buildConfigRows();
  loadConfiguration();
  // The way of asking for the credential survives a reload like everything else
  // on this page.
  var storedMechanism = sdJwtVc.get(MECHANISM_KEY);
  if (storedMechanism && el("handoff_request_mechanism")) {
    el("handoff_request_mechanism").value = storedMechanism;
  }

  // The metadata URLs.
  var storedVciUrl = sdJwtVc.get(VCI_URL_KEY);
  setVal(VCI_URL_KEY, (storedVciUrl === null || storedVciUrl === undefined)
    ? (appconfig.oid4vciIssuerUrlDefault || "") + VCI_WELL_KNOWN
    : storedVciUrl);
  // The RFC 8414 pane defaults to the mock authorization server the STS service
  // publishes (empty where there is no such service). A stored value wins —
  // including the empty string a Clear leaves behind, so a clear survives a
  // reload instead of the default coming back.
  var storedAsUrl = sdJwtVc.get("oidc_discovery_endpoint");
  setVal("oidc_discovery_endpoint",
    (storedAsUrl === null || storedAsUrl === undefined)
      ? (appconfig.rfc8414MetadataUrlDefault || "")
      : storedAsUrl);

  // Whatever was retrieved last time, so the tables survive a reload.
  vciInfo = VCI_STORE.read() || {};
  if (Object.keys(vciInfo).length) { renderVciTable(); }
  // Unconditionally: the chooser now lives among the Configuration Parameters
  // and is on screen whether or not a document has been retrieved, so the
  // no-document case has to say why it is empty rather than render nothing.
  renderCredentialConfigurations();
  asInfo = AS_STORE.read() || {};
  if (Object.keys(asInfo).length) {
    renderAsTable();
    opMetadata.applyNotes(asInfo);
  }
  // The DID Configuration too, with its schema verdict — a pane that showed the
  // table but not the verdict would look as though the document had never been
  // checked. The linkage verdict is NOT restored: it depends on resolving a DID
  // over the network, and a remembered "LINKED" would be a claim about a fetch
  // that may no longer be true.
  didcfgInfo = DIDCFG_STORE.read() || {};
  if (Object.keys(didcfgInfo).length) {
    renderDidcfgTable();
    renderSchemaReport("didcfg_schema_report",
                       metadataSchema.validateDidConfiguration(didcfgInfo),
                       metadataSchema.DIDCFG_SPEC);
  }
  setVal(DIDCFG_URL_KEY, sdJwtVc.get(DIDCFG_URL_KEY) || "");
  defaultDidConfigurationUrl();

  var step = document.getElementById("vc_step_1");
  if (step) step.className = "vc-step-current";
  var step0 = document.getElementById("vc_step_0");
  if (step0) step0.className = "vc-step-done";
  sdJwtVc.renderUseCaseBadge();

  // An offer in the URL is an issuer-initiated issuance arriving (H.1); one in
  // storage is that same offer surviving a reload.
  if (!acceptOfferFromQuery()) renderOffer(sdJwtVc.storedOffer());

  updateHandoffSummary();
  log.debug("SD-JWT VC issuance step 1 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}


// ---------------------------------------------------------------------------
// The DID Configuration pane (DIF Well Known DID Configuration).
//
// Modelled on the authorization server pane above — a URL, Retrieve, Upload,
// Clear, a table of what came back, the values pushed into Configuration
// Parameters, and a schema report — because it is the same job on a third
// document and a reader should not have to learn a third set of controls.
//
// It differs in one way that is not cosmetic. The other two panes can only
// check a document's SHAPE; this one can also check whether it is TRUE. A DID
// Configuration exists to assert that an origin and a DID are the same entity,
// and that assertion is verifiable: resolve the DID independently, check the
// credential's signature against the keys it authorises to assert, and check
// the origin it names is the one it came from. So the pane has both — a schema
// report saying whether the document is well formed, and Verify Linkage saying
// whether it is honest. A document can pass either and fail the other.
// ---------------------------------------------------------------------------
var DIDCFG_URL_KEY = "didcfg_url";
var DIDCFG_DOC_LABEL = "DIF Well Known DID Configuration";
var DIDCFG_STORE = metadataClient.createStore("didcfg_info", "didcfg_source");
var didcfgInfo = {};
var didcfgStored = true;

function renderDidcfgTable() {
  log.debug("Entering renderDidcfgTable().");
  var host = el("didcfg_metadata_table");
  if (!host) {
    log.debug("Leaving renderDidcfgTable().");
    return;
  }
  host.innerHTML = Object.keys(didcfgInfo).length
    ? metadataClient.buildInfoTable(didcfgInfo, DIDCFG_STORE.readProvenance())
    : "";
  log.debug("Leaving renderDidcfgTable().");
}

// The document's own two members, plus the facts derived from the credential it
// carries. did.js does the deriving, so this pane and the DID Tools page cannot
// disagree about what a linkage says.
function populateFromDidConfiguration() {
  log.debug("Entering populateFromDidConfiguration().");
  var details = didLib.didConfigurationDetails(didcfgInfo);
  didLib.DID_CONFIGURATION_METADATA.forEach(function (m) {
    var id = didLib.didConfigurationIdFor(m.name);
    var v = details[m.name];
    var shown = (v === undefined || v === null) ? ""
      : (typeof v === "string" ? v : JSON.stringify(v, null, 2));
    setVal(id, shown);
    sdJwtVc.set(id, shown);
    // "not defined" is about the RESOURCE, not about the derived reading: a
    // missing origin is the document's omission, and marking it says so.
    opMetadata.markNotDefined(id, !shown);
  });
  log.debug("Leaving populateFromDidConfiguration().");
}

function applyDidConfigurationDocument(doc, provenance, verb) {
  log.debug("Entering applyDidConfigurationDocument().");
  didcfgInfo = doc || {};
  didcfgStored = DIDCFG_STORE.save(didcfgInfo, provenance);
  renderDidcfgTable();
  populateFromDidConfiguration();
  var check = metadataSchema.validateDidConfiguration(didcfgInfo);
  renderSchemaReport("didcfg_schema_report", check, metadataSchema.DIDCFG_SPEC);
  var linked = (didcfgInfo.linked_dids || []).length;
  status("didcfg_status",
    (verb || "Loaded") + " a DID Configuration linking " + linked +
     " DID(s), and populated the DID " +
    "Configuration section of Configuration Parameters. " +
    metadataSchema.summarize(check, "Schema check") +
    " Press Verify Linkage to check the signature and the origin, which the " +
        "schema cannot." +
    notStoredNote(didcfgStored),
    check.errors.length ? "vc-bad" : (check.warnings.length ?
        "vc-pending" : "vc-ok"));
  log.debug("Leaving applyDidConfigurationDocument(). " + linked +
            " linked DID(s).");
}

// The resource's location is fixed by the specification, so the field is
// offered rather than demanded: the origin comes from the credential issuer
// this browser discovered, and the path is the one the spec names.
function defaultDidConfigurationUrl() {
  log.debug("Entering defaultDidConfigurationUrl().");
  if ((val(DIDCFG_URL_KEY) || "").trim()) {
    log.debug("Leaving defaultDidConfigurationUrl(). A URL is already there.");
    return;
  }
  var issuer = (vciInfo || {}).credential_issuer ||
               sdJwtVc.get(vciMetadata.idFor("credential_issuer")) || "";
  if (!issuer) {
    log.debug("Leaving defaultDidConfigurationUrl(). No issuer to derive an " +
              "origin from.");
    return;
  }
  var url = "";
  try {
    url = didLib.didConfigurationUrl(new URL(issuer).origin);
  } catch (e) {
    // Not a URL, so it has no origin. The field stays empty and the user types
    // one.
    log.debug("defaultDidConfigurationUrl(): the credential issuer is " +
              "not a URL.");
    log.debug("Leaving defaultDidConfigurationUrl().");
    return;
  }
  setVal(DIDCFG_URL_KEY, url);
  sdJwtVc.set(DIDCFG_URL_KEY, url);
  log.debug("Leaving defaultDidConfigurationUrl(). Offered " + url);
}

function retrieveDidConfiguration() {
  log.debug("Entering retrieveDidConfiguration().");
  var url = (val(DIDCFG_URL_KEY) || "").trim();
  sdJwtVc.set(DIDCFG_URL_KEY, url);
  if (!isUrl(url)) {
    status("didcfg_status", "That is not a valid URL. The resource lives at " +
      didLib.DID_CONFIGURATION_PATH + " at an origin's root.", "vc-bad");
    log.debug("Leaving retrieveDidConfiguration().");
    return false;
  }
  status("didcfg_status", "Retrieving " + url + " …", "vc-pending");
  log.debug("Leaving retrieveDidConfiguration().");
  return metadataClient.fetchJson(url)
    .then(function (doc) {
      applyDidConfigurationDocument(doc, { docLabel: DIDCFG_DOC_LABEL,
                                    url: url }, "Retrieved");
    })
    .catch(function (e) {
      status("didcfg_status", "Could not retrieve the resource: " + e.message +
        (/Failed to fetch|NetworkError|CORS/i.test(e.message)
          ? " An origin that sends no CORS headers cannot be read by a " +
              "browser however right the URL " +
            "is — fetch it with curl and use Upload instead."
          : ""), "vc-bad");
    });
}

function uploadDidConfiguration() {
  log.debug("Entering uploadDidConfiguration().");
  var f = el("didcfg_file");
  if (f) f.click();
  log.debug("Leaving uploadDidConfiguration().");
  return false;
}

function onDidConfigurationFileChange(evt) {
  log.debug("Entering onDidConfigurationFileChange().");
  log.debug("Leaving onDidConfigurationFileChange().");
  return readMetadataFile(evt, "didcfg_status", function (doc, name) {
    applyDidConfigurationDocument(doc, { docLabel: DIDCFG_DOC_LABEL,
                                  file: name },
                                  "Loaded");
  });
}

function clearDidConfiguration() {
  log.debug("Entering clearDidConfiguration().");
  didcfgInfo = {};
  DIDCFG_STORE.forget();
  if (el("didcfg_metadata_table")) el("didcfg_metadata_table").innerHTML = "";
  if (el("didcfg_schema_report")) el("didcfg_schema_report").innerHTML = "";
  if (el("didcfg_verify_table")) el("didcfg_verify_table").innerHTML = "";
  setVal(DIDCFG_URL_KEY, "");
  sdJwtVc.set(DIDCFG_URL_KEY, "");
  didLib.DID_CONFIGURATION_METADATA.forEach(function (m) {
    var id = didLib.didConfigurationIdFor(m.name);
    setVal(id, "");
    sdJwtVc.set(id, "");
  });
  status("didcfg_status", "Cleared.", "vc-ok");
  log.debug("Leaving clearDidConfiguration().");
  return false;
}

// The check the schema cannot make. Verified against the origin the resource
// was FETCHED FROM, not the origin the credential names — comparing the
// credential with itself would pass for any document.
function verifyLoadedDidConfiguration() {
  log.debug("Entering verifyLoadedDidConfiguration().");
  if (!Object.keys(didcfgInfo).length) {
    status("didcfg_status", "Retrieve or upload a DID Configuration first.",
           "vc-bad");
    log.debug("Leaving verifyLoadedDidConfiguration().");
    return false;
  }
  var url = (val(DIDCFG_URL_KEY) || "").trim();
  var origin = "";
  try {
    origin = new URL(url).origin;
  } catch (e) {
    status("didcfg_status",
        "The Document URL is not a URL, so there is no origin to check this " +
      "linkage against. A linkage is a claim about one origin, and it has to " +
          "be the origin the " +
      "resource came from.", "vc-bad");
    log.debug("Leaving verifyLoadedDidConfiguration().");
    return false;
  }
  var host = el("didcfg_verify_table");
  if (host) host.innerHTML = "";
  status("didcfg_status", "Verifying the linkage against " + origin + " …",
         "vc-pending");
  var allowHttp = /^http:/.test(origin);
  var entries = didcfgInfo.linked_dids || [];
  log.debug("Leaving verifyLoadedDidConfiguration().");
  return Promise.all(entries.map(function (entry) {
    return didLib.verifyDomainLinkage(entry, origin, { allowHttp: allowHttp });
  })).then(function (results) {
    var rows = results.map(function (r) {
      var checks = r.checks.map(function (c) {
        return '<span class="' + (c.ok ? "vc-ok" : "vc-bad") + '">' + (c.ok ?
            "OK" : "FAILED") +
               "</span> " + esc(c.name + " — " + c.detail);
      }).join("<br />");
      return "<tr><td>" + esc(r.did || "(no DID)") + "<br /><span class=\"" +
             (r.valid ? "vc-ok" : "vc-bad") + "\">" + (r.valid ?
              "verified" : "not verified") +
             "</span></td><td>" + checks + "</td></tr>";
    }).join("");
    if (host) {
      host.innerHTML = "<table border='2' style='border:2px;'>" +
        "<tr><td><strong>Linked " +
            "DID</strong></td><td><strong>Checks</strong></td></tr>" +
        rows + "</table>";
    }
    var good = results.filter(function (r) { return r.valid; }).length;
    status("didcfg_status", good
      ? "LINKED: " + good + " of " + results.length +
          " credential(s) verify, so " + origin +
        " and the DID(s) they name are the same entity."
      : "NOT LINKED: none of the " + results.length +
          " credential(s) verify against " + origin +
        ". See the checks below — a document can be perfectly well formed " +
            "and still not be true.",
      good ? "vc-ok" : "vc-bad");
    log.debug("Leaving verifyLoadedDidConfiguration(). " + good + "/" +
              results.length + " verified.");
  }).catch(function (e) {
    status("didcfg_status", "The linkage could not be checked: " + e.message,
           "vc-bad");
  });
}

// ---------------------------------------------------------------------------
// The DID pane (W3C DID Core 1.0).
//
// Modelled on the two metadata panes above — Resolve / Upload / Clear, a table
// of what came back, and the values pushed into Configuration Parameters — with
// one honest difference: only did:web has anything to RETRIEVE. did:jwk and
// did:key ARE their key, so "resolving" them is a local decode, and the
// provenance line says which happened rather than implying a network call that
// never took place.
// ---------------------------------------------------------------------------
var DID_ID_KEY = "did_identifier";
var didDocument = null;

// Which format this run is configured for, so the DID default can follow it.
function configuredFormat() {
  log.debug("Entering configuredFormat().");
  log.debug("Leaving configuredFormat().");
  return sdJwtVc.get(vciMetadata.idFor("format")) ||
                     val(vciMetadata.idFor("format")) || "";
}

// DIDs default ON for ldp_vc and OFF for everything else. Stored as "1"/"0"
// once the user has touched the box, so an explicit choice survives a format
// change; with nothing stored the format decides. That distinction matters — a
// holder who deliberately turned DIDs off for ldp_vc should not have them
// turned back on by re-picking the same credential.
function didEnabledDefault() {
  log.debug("Entering didEnabledDefault().");
  log.debug("Leaving didEnabledDefault().");
  return configuredFormat() === sdJwtVc.FORMAT_LDP_VC;
}

function didEnabled() {
  log.debug("Entering didEnabled().");
  var stored = sdJwtVc.get("did_enabled");
  if (stored === "1") {
    log.debug("Leaving didEnabled().");
    return true;
  }
  if (stored === "0") {
    log.debug("Leaving didEnabled().");
    return false;
  }
  log.debug("Leaving didEnabled().");
  return didEnabledDefault();
}

function renderDidEnabled() {
  log.debug("Entering renderDidEnabled().");
  var box = el("did_enabled");
  if (box) box.checked = didEnabled();
  var format = configuredFormat() || "(no credential chosen yet)";
  setText("did_enabled_note", didEnabled()
    ? (didEnabledDefault()
        ? "On, the default for " + format + ": VC Data Model 2.0 is DID-native."
        : "On for " + format +
            " — a profile extension: SD-JWT VC defines no DID-based issuer " +
          "signature mechanism.")
    : "Off for " + format + ": the issuer is identified by its " +
        "credential_issuer URL and its keys " +
      "come from /.well-known/jwt-vc-issuer.");
  log.debug("Leaving renderDidEnabled().");
}

function onDidEnabledChange() {
  log.debug("Entering onDidEnabledChange().");
  var box = el("did_enabled");
  sdJwtVc.set("did_enabled", box && box.checked ? "1" : "0");
  renderDidEnabled();
  log.debug("Leaving onDidEnabledChange().");
  return true;
}


// An issuer may say which DID it also answers to, and where a credential from a
// given configuration will name it. Neither member is registered by OID4VCI —
// they are this issuer's extension — but they are the only way a wallet learns
// the DID from something it FETCHED rather than from the credential itself,
// which is the one source that cannot corroborate its own issuer.
//
// Offered, not imposed: the field is filled only when it is empty, because this
// pane is also where somebody tries a DID the issuer has not published, or a
// deliberately wrong one to watch the verification refuse it.
function offerAdvertisedIssuerDid() {
  log.debug("Entering offerAdvertisedIssuerDid().");
  var advertised = (vciInfo || {}).issuer_did || "";
  if (!advertised) {
    log.debug("Leaving offerAdvertisedIssuerDid(). This issuer " +
              "advertises none.");
    return;
  }
  if (!didLib.isDid(advertised)) {
    // Said so rather than filled in: a malformed advertisement is worth seeing.
    status("did_status", 'This issuer advertises issuer_did as "' + advertised +
      '", which is not a DID.', "vc-bad");
    log.debug("Leaving offerAdvertisedIssuerDid().");
    return;
  }
  var current = (val(DID_ID_KEY) || "").trim();
  if (current) {
    log.debug("Leaving offerAdvertisedIssuerDid(). A DID is already entered.");
    return;
  }
  setVal(DID_ID_KEY, advertised);
  sdJwtVc.set(DID_ID_KEY, advertised);
  var configured = (vciInfo.credential_configurations_supported || {});
  var perConfiguration = Object.keys(configured).filter(function (id) {
    return configured[id] && configured[id].issuer_identifier === advertised;
  });
  status("did_status", "This issuer advertises the DID " + advertised +
         " (issuer_did in its " +
    "metadata — an extension, not a registered member). " +
    (perConfiguration.length
      ? perConfiguration.length +
          " of its credential configurations name the issuer by that DID: " +
        perConfiguration.join(", ") + "."
      : "None of its credential configurations name the issuer by it, so " +
          "credentials will carry the " +
        "https identifier.") + " Resolve to see the document.", "vc-pending");
  log.debug("Leaving offerAdvertisedIssuerDid(). Offered " + advertised + ".");
}

// Push the resolved document into the editable Configuration Parameters fields.
function populateFromDidDocument() {
  log.debug("Entering populateFromDidDocument().");
  var doc = didDocument || {};
  didLib.DID_METADATA.forEach(function (m) {
    var v = doc[m.name];
    var shown = (v === undefined || v === null) ? ""
      : (typeof v === "string" ? v : JSON.stringify(v, null, 2));
    setVal(didLib.idFor(m.name), shown);
    sdJwtVc.set(didLib.idFor(m.name), shown);
    opMetadata.markNotDefined(didLib.idFor(m.name),
      !Object.prototype.hasOwnProperty.call(doc, m.name));
  });
  log.debug("Leaving populateFromDidDocument().");
}

function renderDidTable(provenance) {
  log.debug("Entering renderDidTable().");
  var host = el("did_document_table");
  if (!host) {
    log.debug("Leaving renderDidTable().");
    return;
  }
  host.innerHTML = didDocument
    ? metadataClient.buildInfoTable(didDocument, provenance)
    : "";
  log.debug("Leaving renderDidTable().");
}

function applyDidDocument(doc, provenance, verb, url) {
  log.debug("Entering applyDidDocument().");
  didDocument = doc || null;
  setVal("did_resolution_url", url || "");
  renderDidTable(provenance);
  populateFromDidDocument();
  var methods = didLib.verificationMethods(didDocument || {});
  status("did_status",
    verb + " a DID Document for " + ((didDocument || {}).id || "(no id)") +
        " with " +
    methods.length + " verification method(s): " +
    methods.map(function (m) { return (m.id || "").split("#")[1] ||
                m.id; }).join(", ") +
    ". " + (provenance && provenance.note ? provenance.note : ""), "vc-ok");
  log.debug("Leaving applyDidDocument().");
}

function resolveDid() {
  log.debug("Entering resolveDid().");
  var didValue = val(DID_ID_KEY).trim();
  sdJwtVc.set(DID_ID_KEY, didValue);
  var parsed = didLib.parse(didValue);
  if (!parsed) {
    status("did_status",
           'That is not a DID. A DID looks like "did:web:example.com", ' +
      '"did:jwk:eyJrdHki…" or "did:key:zDnae…".', "vc-bad");
    log.debug("Leaving resolveDid().");
    return false;
  }
  // did:web over plain http is allowed here because this suite's own issuer
  // runs on it. The method mandates https; a deployed site talking to a real
  // issuer will use it, and the only reason to relax it is a local stack.
  var allowHttp =
      /^https?:\/\/localhost|^http:\/\//.test(String(window.location.origin)) ||
                  /^did:web:(localhost|sts|127\.0\.0\.1)/.test(didValue);
  var url = parsed.method === "web"
    ? (allowHttp ? didLib.didWebToUrlInsecure(didValue) : didLib.didWebToUrl(
        didValue)) : "";
  setVal("did_resolution_url", url);
  status("did_status", parsed.method === "web"
    ? "Retrieving " + url + " …" : "Decoding the " + parsed.method +
        " locally …", "vc-pending");
  log.debug("Leaving resolveDid().");
  return didLib.resolve(didValue, { allowHttp: allowHttp })
    .then(function (r) {
      applyDidDocument(r.document, { url: r.url || "", note: "Source: " +
                       r.from + "." },
        r.url ? "Retrieved" : "Resolved", r.url);
    })
    .catch(function (e) {
      status("did_status", "Could not resolve that DID: " + e.message,
             "vc-bad");
    });
}

// Retrieve a DID Document from the URL in the Document URL field, whatever put
// it there — derived by Resolve above, or typed in by hand.
//
// This is not resolution and does not pretend to be. Resolve takes a DID and
// applies the method's own rules to find the document; this takes a URL and
// fetches it. The distinction is worth keeping because it is the whole reason
// to have the button: a did:web document is not always reachable where the
// method says it should be. It may be on a staging host, behind a tunnel, at a
// path the issuer has not published yet, or reachable only through a
// CORS-friendly proxy — and in each of those cases the DID is right, the URL is
// not the one the method derives, and the document is still the thing you want
// to look at.
//
// One consequence has to be reported rather than enforced. DID Core says a
// RESOLVED document's id MUST equal the DID that was resolved, and did.js
// refuses a mismatch for exactly that reason. Here the caller chose the URL, so
// refusing would defeat the purpose: inspecting a document that identifies
// itself as somebody else is a thing you would come to this pane to do. So a
// mismatch is a NOTE, said plainly, and everything downstream then describes
// the document's own id rather than what happens to be in the DID field.
//
// Everything after the fetch goes through applyDidDocument(), which is what
// makes the rest of the pane behave exactly as it does after a Resolve: the
// table, the Configuration Parameters fields, Verify Issuer Key and Verify
// Domain Linkage all read the same state and need to know nothing about where
// it came from.
function retrieveDidDocument() {
  log.debug("Entering retrieveDidDocument().");
  var url = (val("did_resolution_url") || "").trim();
  sdJwtVc.set("did_resolution_url", url);
  if (!url) {
    status("did_status", "Put a document URL in the Document URL field " +
           "first, or press Resolve to " +
      "derive one from a did:web.", "vc-bad");
    log.debug("Leaving retrieveDidDocument(). No URL.");
    return false;
  }
  // The same allowlist the navigation sinks use (client/src/url_safety.js):
  // only http and https. A DID document is fetched, not navigated to, so this
  // is not about script execution — it is that no other scheme can return one,
  // and saying so beats a fetch that fails with something obscure.
  if (!urlSafety.isSafeExternalUrl(url)) {
    status("did_status", 'A DID Document is fetched over http or https; "' +
           url +
      '" is neither.', "vc-bad");
    log.debug("Leaving retrieveDidDocument(). Refused the scheme.");
    return false;
  }

  var didValue = (val(DID_ID_KEY) || "").trim();
  status("did_status", "Retrieving " + url + " …", "vc-pending");
  log.debug("Leaving retrieveDidDocument(). Fetching " + url);
  return fetch(url, { credentials: "omit" })
    .then(function (r) {
      return r.text().then(function (text) {
        if (!r.ok) throw new Error(url + " answered HTTP " + r.status + ".");
        var doc;
        try {
          doc = JSON.parse(text);
        } catch (e) {
          // An HTML error page from a misconfigured host is the usual cause,
          // and a bare "Unexpected token <" would not say that.
          throw new Error(url + " did not return JSON: " + e.message);
        }
        if (!doc || typeof doc !== "object") {
          throw new Error(url +
                          " returned JSON, but not a DID Document object.");
        }
        return doc;
      });
    })
    .then(function (doc) {
      var note = "Retrieved from " + url +
          ", by URL rather than by resolving the DID.";
      if (!doc.id) {
        note += " This document carries no id, so there is nothing to check it against a DID.";
      } else if (!didValue) {
        // Fill the DID in from the document so the rest of the pane has
        // something to work with — Verify Domain Linkage asks about a DID, not
        // a URL.
        setVal(DID_ID_KEY, doc.id);
        sdJwtVc.set(DID_ID_KEY, doc.id);
        note += " The Issuer DID field was empty and has been filled in from the document's id.";
      } else if (doc.id !== didValue) {
        note += ' NOTE: this document identifies itself as "' + doc.id +
            '", not "' + didValue +
                '". Resolution would refuse that (DID Core: a resolved ' +
                    'document\'s id MUST be the ' +
                "DID resolved); a retrieval by URL cannot, because you chose " +
                    "the URL. Everything " +
                "below therefore describes " + doc.id + ".";
      }
      applyDidDocument(doc, { url: url, note: note }, "Retrieved", url);
    })
    .catch(function (e) {
      // The browser's own message for a blocked cross-origin read is the bare
      // "Failed to fetch", which says nothing about why — so the likely cause
      // is named and the way round it is offered. Punctuation is added only
      // when the message does not already end in some, because these arrive
      // both ways ("… answered HTTP 404." from above, "Failed to fetch" from
      // the browser).
      var message = e.message;
      if (/Failed to fetch|NetworkError|CORS/i.test(message)) {
        if (!/[.!?]$/.test(message)) message += ".";
        message += " A host that sends no CORS headers cannot be read by a " +
            "browser however right " +
                   "the URL is — fetch it with curl and use Upload instead.";
      }
      status("did_status", "Could not retrieve that document: " + message,
             "vc-bad");
    });
}

function uploadDidDocument() {
  log.debug("Entering uploadDidDocument().");
  var f = el("did_document_file");
  if (f) f.click();
  log.debug("Leaving uploadDidDocument().");
  return false;
}

function onDidFileChange(evt) {
  log.debug("Entering onDidFileChange().");
  log.debug("Leaving onDidFileChange().");
  return readMetadataFile(evt, "did_status", function (doc, name) {
    applyDidDocument(doc, { file: name, note: "Loaded from " + name +
                     ", not resolved." },
      "Loaded", "");
  });
}

function clearDidDocument() {
  log.debug("Entering clearDidDocument().");
  didDocument = null;
  sdJwtVc.set(DID_ID_KEY, "");
  setVal(DID_ID_KEY, "");
  setVal("did_resolution_url", "");
  renderDidTable(null);
  didLib.DID_METADATA.forEach(function (m) {
    setVal(didLib.idFor(m.name), "");
    sdJwtVc.set(didLib.idFor(m.name), "");
  });
  status("did_status", "Cleared.", "vc-ok");
  log.debug("Leaving clearDidDocument().");
  return false;
}

// Resolving a document proves nothing on its own. What matters is whether a key
// it publishes is the one the issuer actually signed with — so this checks the
// credential in hand against it, rather than reporting a green tick for having
// fetched some JSON.
function verifyDidBinding() {
  log.debug("Entering verifyDidBinding().");
  if (!didDocument) {
    status("did_status", "Resolve or upload a DID Document first.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!raw) {
    status("did_status", "There is no credential in this wallet to check the " +
           "document against. " +
      "Issue one first — this button answers \"is this the key that signed " +
          "it\", which needs " +
      "something signed.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var parsed;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    status("did_status", "The credential in this wallet could not be parsed: " +
           e.message, "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var named = parsed.format === sdJwtVc.FORMAT_LDP_VC
    ? ((parsed.document || {}).issuer || "")
    : ((parsed.payload || {}).iss || "");
  if (named && didDocument.id && named !== didDocument.id) {
    status("did_status", "This credential names its issuer as \"" + named +
           "\", but the document " +
      "resolved here describes \"" + didDocument.id +
          "\". They are different subjects, so the " +
      "keys below say nothing about that credential.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var keys = didLib.assertionKeys(didDocument);
  if (!keys.length) {
    status("did_status", "This document publishes no key that may assert, so " +
           "nothing here could " +
      "have signed a credential.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  if (parsed.format === sdJwtVc.FORMAT_LDP_VC) {
    var vm = ((parsed.document || {}).proof || {}).verificationMethod || "";
    var found = keys.filter(function (k) { return k.id === vm; })[0];
    status("did_status", found
      ? "The proof names " + vm + ", and this document publishes it (" +
          found.type + "). " +
        "Step 3 verifies the proof itself against that key."
      : "The proof names " + vm +
          ", which this document does NOT publish. Either the document is " +
        "stale or the credential was signed by something else.", found ?
            "vc-ok" : "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  // A JWS-secured credential: check the signature here and now.
  var header = parsed.header || {};
  var key = didLib.keyForKid(didDocument, header.kid);
  if (!key || !key.jwk) {
    status("did_status",
           "No key in this document matches the credential's kid (" +
      (header.kid || "none given") +
       "), or the matching key is not expressed as a JWK.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  status("did_status", "Verifying the credential signature against " + key.id +
         " …", "vc-pending");
  // verifyJwsWithJwks takes a JWK SET and reports {valid}, so the one key this
  // document named is wrapped as a set of one — verifying against every key in
  // the document would answer a weaker question than "did THIS method sign it".
  metadataClient.verifyJwsWithJwks(parsed.serialized.split("~")[0],
                                   { keys: [key.jwk] },
      "the credential")
    .then(function (verdict) {
      status("did_status", verdict && verdict.valid
        ? "VERIFIED: the credential's signature checks out against " + key.id +
            " from this DID " +
          "Document. The DID really does identify the key that signed it."
        : "The credential's signature does NOT verify against " + key.id +
          ". Resolving a document is not the same as it being the right one.",
        verdict && verdict.valid ? "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      status("did_status", "The signature could not be checked: " + e.message,
             "vc-bad");
    });
  log.debug("Leaving verifyDidBinding().");
  return false;
}

// ---------------------------------------------------------------------------
// Domain linkage (DIF Well Known DID Configuration).
//
// "Verify Issuer Key" above answers: does this document publish the key that
// signed the credential. This answers the question BEFORE that one, which is
// the one a DID cannot answer about itself: why should this DID be believed to
// be the same party as the https issuer the wallet discovered?
//
// For did:web the appearance of an answer is worse than none. Resolving
// did:web:example.com means fetching example.com, so reading a DID document off
// that origin to decide whether the DID belongs to it is circular. The linkage
// credential is not: the DID signs, with its own key, a credential naming the
// origin, and the verifier checks the signature against the keys the DID
// authorises to assert.
//
// The origin is taken from the CREDENTIAL ISSUER's identifier rather than from
// the DID, because the whole point is to connect the two: deriving the origin
// from the DID would ask whether the DID vouches for itself, which it always
// does.
function verifyDomainLinkage() {
  log.debug("Entering verifyDomainLinkage().");
  var didValue = (val(DID_ID_KEY) || "").trim() || (didDocument || {}).id || "";
  if (!didValue) {
    status("did_linkage_status",
           "Give a DID first — this checks whether an origin vouches for one.",
           "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  // Whatever the issuer metadata says its identifier is. That document is where
  // a wallet learned about this issuer, so it is the origin whose word is in
  // question.
  var issuer = sdJwtVc.get(vciMetadata.idFor("credential_issuer")) ||
               val(vciMetadata.idFor("credential_issuer")) || "";
  if (!issuer) {
    status("did_linkage_status",
           "Retrieve the credential issuer metadata first: the linkage is " +
      "between that issuer's ORIGIN and this DID, so there is nothing to " +
          "check it against yet.",
      "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  var origin;
  try {
    origin = new URL(issuer).origin;
  } catch (e) {
    status("did_linkage_status", 'The credential issuer identifier "' + issuer +
           '" is not a URL, so ' +
      "it has no origin to link.", "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  var allowHttp = /^http:/.test(origin);
  var host = el("did_linkage_table");
  if (host) host.innerHTML = "";
  status("did_linkage_status", "Fetching " +
         didLib.didConfigurationUrl(origin) + " …", "vc-pending");
  didLib.verifyOriginLinkage(origin, didValue, { allowHttp: allowHttp })
    .then(function (result) {
      // Every entry is shown, not only the matching one: an origin may link
      // several DIDs, and one that fails is as interesting as one that passes.
      //
      // Built in the SAME TWO-COLUMN SHAPE as the retrieved-metadata tables
      // above (see metadata_client.buildInfoTable), and that is a layout
      // requirement, not a stylistic one. The .discovery_info_table CSS is what
      // keeps these tables inside their pane, and it does that with
      // table-layout:fixed plus rules on the FIRST and SECOND columns only — a
      // 34% name column and a value column pinned to max-width:0 so it wraps
      // instead of stretching. This was a hand-rolled three-column table with
      // inline width attributes, so its third column had no cap and no
      // overflow-wrap: the checks column, which is the one carrying full DID
      // URLs and origins, was the one column free to push the table past the
      // edge. Measured at a 414px viewport it did exactly that (the wrapper
      // scrolled, 414px of content in a 380px box).
      //
      // So: no inline widths, two columns, and the DID and its verdict share
      // the name cell. The CSS then governs this table exactly as it governs
      // the other two in this pane.
      var rows = result.results.map(function (r) {
        var verdict = '<span class="' + (r.valid ? "vc-ok" : "vc-bad") + '">' +
                      (r.valid ? "verified" : "not verified") + "</span>";
        var checks = r.checks.map(function (c) {
          return '<span class="' + (c.ok ? "vc-ok" : "vc-bad") + '">' + (c.ok ?
              "OK" : "FAILED") +
                 "</span> " + metadataClient.escapeHtmlText(c.name + " — " +
                     c.detail);
        }).join("<br />");
        return "<tr><td>" + metadataClient.escapeHtmlText(r.did || "(no DID)") +
               "<br />" + verdict + "</td><td>" + checks + "</td></tr>";
      }).join("");
      if (host) {
        host.innerHTML = "<table border='2' style='border:2px;'>" +
          "<tr><td><strong>Linked " +
              "DID</strong></td><td><strong>Checks</strong></td></tr>" +
          rows + "</table>";
      }
      status("did_linkage_status", result.linked
        ? "LINKED: " + origin + " and " + didValue +
            " are the same entity, proved by a Domain " +
          "Linkage Credential signed by that DID's own key at " + result.url +
              "."
        : (result.matched.length
            ? "NOT LINKED: " + origin +
                " publishes a Domain Linkage Credential for " + didValue +
              ", but it does not verify. See the checks below."
            : "NOT LINKED: " + result.url + " vouches for " +
              (result.results.length ? result.results.length +
               " other DID(s)" : "no DID") +
              ", not for " + didValue +
                  ". An origin linking some DID has not linked this one."),
        result.linked ? "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      status("did_linkage_status", "Could not check the domain linkage: " +
             e.message + " (An issuer " +
        "need not publish this document — it is DIF's, not OID4VCI's — so " +
            "its absence is not a " +
        "failure of the credential.)", "vc-bad");
    });
  log.debug("Leaving verifyDomainLinkage().");
  return false;
}

module.exports = {
  retrieveDidConfiguration: retrieveDidConfiguration,
  uploadDidConfiguration: uploadDidConfiguration,
  onDidConfigurationFileChange: onDidConfigurationFileChange,
  clearDidConfiguration: clearDidConfiguration,
  verifyLoadedDidConfiguration: verifyLoadedDidConfiguration,
  resolveDid: resolveDid,
  retrieveDidDocument: retrieveDidDocument,
  uploadDidDocument: uploadDidDocument,
  onDidFileChange: onDidFileChange,
  clearDidDocument: clearDidDocument,
  verifyDidBinding: verifyDidBinding,
  verifyDomainLinkage: verifyDomainLinkage,
  onDidEnabledChange: onDidEnabledChange,
  didEnabled: didEnabled,
  renderDidEnabled: renderDidEnabled,
  retrieveVciMetadata: retrieveVciMetadata,
  uploadVciMetadata: uploadVciMetadata,
  onVciFileChange: onVciFileChange,
  uploadAsMetadata: uploadAsMetadata,
  onAsFileChange: onAsFileChange,
  discardOffer: discardOffer,
  acceptOfferFromQuery: acceptOfferFromQuery,
  takeScannedOffer: takeScannedOffer,
  readScannedOffer: readScannedOffer,
  clearVciMetadata: clearVciMetadata,
  populateFromVci: populateFromVci,
  onCredentialConfigurationChange: onCredentialConfigurationChange,
  validateVciSignature: validateVciSignature,
  retrieveAsMetadata: retrieveAsMetadata,
  clearAsMetadata: clearAsMetadata,
  populateFromAs: populateFromAs,
  validateAsSignature: validateAsSignature,
  saveConfiguration: saveConfiguration,
  onRequestMechanismChange: onRequestMechanismChange,
  describeMechanism: describeMechanism,
  authorizationDetailsForRequest: authorizationDetailsForRequest,
  clearConfiguration: clearConfiguration,
  restoreDefaults: restoreDefaults,
  startIssuance: startIssuance,
  updateHandoffSummary: updateHandoffSummary,
  togglePane: togglePane,
  clickLink: clickLink,
  onload: onload
};
