// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: vc_verifier.js
//
// ---------------------------------------------------------------------------
// THE DEBUGGER AS AN OPENID4VP 1.0 VERIFIER (#364): vc-verifier.html.
//
// This file is the page and nothing else. What a Verifier COMPOSES (the DCQL
// query, the certificate, the signed Request Object, the invocation URI) and
// how it CHECKS an answer are `vp_verifier.js`, which has no DOM so that
// tests/vp_verifier_engine.js can drive all of it in node.
//
// WHY THE API IS INVOLVED. `direct_post` has the wallet POST its answer to a
// `response_uri`, and a request by reference has it GET (or POST) a
// `request_uri`. A page can be neither, so the api hosts both on the page's
// behalf (api/oid4vp_verifier.js, docs/vc-verifier-api.md), exactly as it
// hosts the Shared Signals push receiver. The api is a STORE: the page signs
// the Request Object with a key that never leaves this tab, hands the api the
// compact JWS and the root certificate the leaf's Authority Information
// Access names, and polls for what the wallet sent. Without an api (the static
// sites) the page can still check an answer pasted into pane 4.
//
// NOTHING SECRET IS STORED, EXCEPT THE IDENTITY, AND THAT ONE IS AN
// OPT-OUT. The response decryption key, each request's leaf key and the api
// session's secret live in this page load only; VERIFIER_KEYS below is the
// configuration a reader would otherwise retype. The Verifier's IDENTITY —
// its root CA, its attester and its request key — is key material kept
// across runs (#470, B4), because a wallet configured with trust anchors
// can only trust what it was given before the request: see "THE
// VERIFIER'S IDENTITY" below.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var verifier = require("./vp_verifier");
var qrcode = require("qrcode-generator");

var log = bunyan.createLogger({ name: "vc_verifier",
                                level: appconfig.logLevel });

var API_URL = appconfig.apiUrl || "";
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;
var POLL_MS = 2000;
// While a wallet waits on a live signature (request_uri_method=post).
var LIVE_POLL_MS = 500;

// The fields remembered across page loads (localStorage, under their ids).
// Configuration only: see the header.
var VERIFIER_KEYS = [
  "vpv_query_id", "vpv_format", "vpv_type", "vpv_claims", "vpv_binding",
  "vpv_dcql", "vpv_client_prefix", "vpv_response_mode", "vpv_delivery",
  "vpv_scheme", "vpv_redirect_uri", "vpv_client_id_typed", "vpv_dc_signed",
  "vpv_trust_anchors", "vpv_fetch_via_api", "vpv_save_identity",
  "vpv_public_base_url", "vpv_issuer_bindings", "vpv_trusted_authorities",
  "vpv_profile", "vpv_claim_sets", "vpv_intent_to_retain", "vpv_request_key",
  "vpv_scope", "vpv_verifier_info", "vpv_transaction_data",
  "vpv_dc_multisigned", "vpv_dc_second_prefix"
];

// Whether issuer metadata, DID documents and status lists are fetched
// through the api (#470, B3). See fetchViaApi().
var FETCH_VIA_API_ID = "vpv_fetch_via_api";

// The configured iss-to-certificate mapping typed into pane 2 (SD-JWT VC
// -27 section 2.5): "<iss> = sha256:<hex>" or "<iss> = cn:<name>", one per
// line. Lines that are neither are ignored.
function issuerBindingsFromPage() {
  log.debug("Entering issuerBindingsFromPage().");
  var out = [];
  val("vpv_issuer_bindings").split(/\n/).forEach(function (line) {
    var m = /^\s*(\S+)\s*=\s*(sha256|cn):\s*(.+?)\s*$/i.exec(line);
    if (!m) {
      return;
    }
    var entry = { iss: m[1] };
    if (m[2].toLowerCase() === "sha256") {
      entry.sha256 = m[3];
    } else {
      entry.cn = m[3];
    }
    out.push(entry);
  });
  log.debug("Leaving issuerBindingsFromPage(). " + out.length);
  return out;
}

// The trust anchors typed into pane 2, one string per PEM certificate.
// Public certificates, so they are remembered like the other settings.
function trustAnchorsFromPage() {
  log.debug("Entering trustAnchorsFromPage().");
  var found = val("vpv_trust_anchors").match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving trustAnchorsFromPage(). " + found.length);
  return found;
}

// The label of the type field, per format: what DCQL's `meta` calls it.
var TYPE_LABELS = {
  "dc+sd-jwt": "vct",
  "jwt_vc_json": "type values",
  "mso_mdoc": "doctype",
  "ldp_vc": "type values"
};

// This page load's request: everything verifyResponse() needs, plus the api
// session that hosts it. Null until "Create the request".
var current = null;
var pollTimer = null;

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function val(id) {
  log.debug("Entering val(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving val(). No element.");
    return "";
  }
  if (e.type === "checkbox") {
    log.debug("Leaving val(). A checkbox.");
    return e.checked ? "1" : "";
  }
  log.debug("Leaving val().");
  return String(e.value || "");
}

function setVal(id, v) {
  log.debug("Entering setVal(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setVal(). No element.");
    return;
  }
  if (e.type === "checkbox") {
    e.checked = !!v && v !== "0";
    log.debug("Leaving setVal(). A checkbox.");
    return;
  }
  e.value = v;
  log.debug("Leaving setVal().");
}

function setText(id, text, cls) {
  log.debug("Entering setText(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setText(). No element.");
    return;
  }
  e.textContent = text;
  e.className = "vc-note vc-status" + (cls ? " " + cls : "");
  log.debug("Leaving setText().");
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) {
    fs.style.display = (fs.style.display === "none") ? "block" : "none";
  }
  log.debug("Leaving togglePane().");
  return false;
}

// ---------------------------------------------------------------------------
// THE VERIFIER'S IDENTITY (#470, B4).
//
// Until #470 every request made a new root CA, leaf, attester and request
// key, so only a wallet that fetches its anchor from the leaf's Authority
// Information Access could trust the Verifier: one CONFIGURED with anchors,
// or with an attester's key, or with a registered JWKS, refused every
// signed request, because what it had been given belonged to a run that was
// over. So three things now outlive a request:
//
//   the root CA      what a wallet anchors for x509_hash and x509_san_dns
//                    (the leaf stays per request: its SAN and its AIA name
//                    the api host and the session, which change);
//   the attester     whose key a wallet trusts for verifier_attestation;
//   the request key  the DID of decentralized_identifier, and the JWKS a
//                    wallet registered for a pre-registered client_id.
//
// They are KEY MATERIAL, under the rules every key-pair pane here follows
// (CLAUDE.md, "Key Implementation Notes"): kept in localStorage under
// vpv_identity only while "Keep this identity" (vpv_save_identity) is
// ticked, which is the default; unticking it removes the stored identity on
// the spot, saveState() removes it whenever the box is off, and so does
// every page load, so no path leaves yesterday's private keys behind. A
// page with no such box (an older cached copy) keeps saving: only an
// explicit "0" stops it. With saving off the identity lasts this page load,
// and the Download button and the import field carry it instead.
// ---------------------------------------------------------------------------
var IDENTITY_KEY = "vpv_identity";
var SAVE_IDENTITY_KEY = "vpv_save_identity";

// { root?, attester?, requestKey? }, as verifier.readVerifierIdentityFile()
// returns it. Each part is made when a prefix first needs it.
var identity = null;

// Why the stored identity could not be read, shown until another is used.
var identityProblem = "";

function savingIdentity() {
  log.debug("Entering savingIdentity().");
  var box = el(SAVE_IDENTITY_KEY);
  if (box) {
    log.debug("Leaving savingIdentity(). " + box.checked);
    return !!box.checked;
  }
  var stored = null;
  try {
    stored = localStorage.getItem(SAVE_IDENTITY_KEY);
  } catch (e) {
    stored = null;
  }
  log.debug("Leaving savingIdentity(). No box; stored " + stored);
  return stored !== "0";
}

function hasIdentityParts(id) {
  log.debug("Entering hasIdentityParts().");
  var any = !!(id && (id.root || id.attester || id.requestKey));
  log.debug("Leaving hasIdentityParts(). " + any);
  return any;
}

// Remove the stored identity when saving is off. Called from saveState()
// and on load, so it holds whichever way the box was cleared.
function purgeIdentityIfOff() {
  log.debug("Entering purgeIdentityIfOff().");
  if (savingIdentity()) {
    log.debug("Leaving purgeIdentityIfOff(). Saving.");
    return;
  }
  try {
    localStorage.removeItem(IDENTITY_KEY);
  } catch (e) {
    log.debug("purgeIdentityIfOff(): no storage — " + e.message);
  }
  log.debug("Leaving purgeIdentityIfOff(). Removed.");
}

function storeIdentity() {
  log.debug("Entering storeIdentity().");
  try {
    if (savingIdentity() && hasIdentityParts(identity)) {
      localStorage.setItem(IDENTITY_KEY, JSON.stringify(
        verifier.verifierIdentityFile(identity)));
    } else {
      localStorage.removeItem(IDENTITY_KEY);
    }
  } catch (e) {
    log.debug("storeIdentity(): no storage — " + e.message);
  }
  log.debug("Leaving storeIdentity().");
}

function loadIdentity() {
  log.debug("Entering loadIdentity().");
  purgeIdentityIfOff();
  identity = {};
  if (!savingIdentity()) {
    log.debug("Leaving loadIdentity(). Not saving.");
    return;
  }
  var text = null;
  try {
    text = localStorage.getItem(IDENTITY_KEY);
  } catch (e) {
    text = null;
  }
  if (!text) {
    log.debug("Leaving loadIdentity(). None stored.");
    return;
  }
  try {
    identity = verifier.readVerifierIdentityFile(text);
  } catch (e) {
    // Unreadable is not silently replaced: the reader is told, and a new
    // identity is made only when a request needs one.
    log.warn("loadIdentity(): the stored identity is unreadable — " +
             e.message);
    identityProblem = "The stored identity could not be read (" +
      e.message + "); a new one will be made.";
    identity = {};
  }
  log.debug("Leaving loadIdentity().");
}

// The parts a request needs, made now if they are missing. The root needs
// Web Crypto (makeSigner() says so first); the two keys are pure JS.
async function ensureIdentity(needRoot) {
  log.debug("Entering ensureIdentity(). root=" + !!needRoot);
  identity = identity || {};
  var made = false;
  if (needRoot && !identity.root) {
    identity.root = await verifier.makeVerifierRoot();
    made = true;
  }
  if (!identity.requestKey) {
    identity.requestKey = verifier.makeRequestKey();
    made = true;
  }
  if (!identity.attester) {
    identity.attester = verifier.makeAttester();
    made = true;
  }
  if (made) {
    storeIdentity();
  }
  showIdentity();
  log.debug("Leaving ensureIdentity(). made=" + made);
  return identity;
}

// What a wallet must be given to trust this Verifier, per prefix.
function identityTrustText() {
  log.debug("Entering identityTrustText().");
  var id = identity || {};
  var lines = [];
  lines.push("x509_hash, x509_san_dns: give the wallet this ROOT CA as a " +
             "trust anchor (each request's leaf is issued under it):");
  lines.push(id.root ? id.root.certificatePem.trim()
                     : "(not made yet: the first x509 request makes it)");
  lines.push("");
  lines.push("verifier_attestation: give the wallet the attester's JWKS " +
             "(its iss is " + (id.attester ? id.attester.iss
                                           : "not made yet") + "):");
  lines.push(id.attester ? JSON.stringify(id.attester.jwks, null, 2)
                         : "(not made yet)");
  lines.push("");
  lines.push("decentralized_identifier: the Verifier's DID, which " +
             "resolves with no network:");
  lines.push(id.requestKey ? verifier.clientIdFor("decentralized_identifier",
    id.requestKey, { didMethod: "jwk" }).replace(/^[^:]*:/, "")
                           : "(not made yet)");
  lines.push("");
  lines.push("pre-registered: the JWKS to register for the client_id:");
  lines.push(id.requestKey ? JSON.stringify(
    verifier.preRegisteredJwks(id.requestKey), null, 2) : "(not made yet)");
  log.debug("Leaving identityTrustText().");
  return lines.join("\n");
}

function showIdentity() {
  log.debug("Entering showIdentity().");
  setVal("vpv_identity_trust", identityTrustText());
  var how = savingIdentity()
    ? "Kept in this browser across runs (key material: untick \"Keep " +
      "this identity\" to remove it)."
    : "Not kept: this identity lasts this page load. Download it to " +
      "carry it.";
  setText("vpv_identity_status", (identityProblem ? identityProblem + " "
    : "") + how, identityProblem ? "vc-bad"
    : savingIdentity() ? "vc-ok" : "vc-pending");
  log.debug("Leaving showIdentity().");
}

function saveIdentityChanged() {
  log.debug("Entering saveIdentityChanged().");
  saveState();
  storeIdentity();
  showIdentity();
  log.debug("Leaving saveIdentityChanged().");
  return false;
}

// One JSON file, PEM and JWK: verifier.verifierIdentityFile()'s shape.
async function downloadIdentity() {
  log.debug("Entering downloadIdentity().");
  try {
    var canRoot = typeof crypto !== "undefined" && !!crypto.subtle;
    await ensureIdentity(canRoot);
    var text = JSON.stringify(verifier.verifierIdentityFile(identity),
                              null, 2) + "\n";
    var blob = new Blob([text], { type: "application/json" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "oid4vp-verifier-identity.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(function () {
      URL.revokeObjectURL(link.href);
    }, 0);
    setText("vpv_identity_status", "Downloaded. The file holds PRIVATE " +
      "keys: whoever has it can sign as this Verifier." +
      (canRoot ? "" : " It has no root CA: this page is not in a secure " +
       "context, so none can be made here."), "vc-ok");
  } catch (e) {
    log.warn("downloadIdentity(): " + e.message);
    setText("vpv_identity_status", "Could not download the identity: " +
            e.message, "vc-bad");
  }
  log.debug("Leaving downloadIdentity().");
  return false;
}

// The pasted file replaces the identity. The field itself is never stored.
function importIdentity() {
  log.debug("Entering importIdentity().");
  try {
    identity = verifier.readVerifierIdentityFile(
      val("vpv_identity_import").trim());
    identityProblem = "";
    setVal("vpv_identity_import", "");
    storeIdentity();
    showIdentity();
    setText("vpv_identity_status", "Imported (" +
      Object.keys(identity).join(", ") + ")" + (savingIdentity()
        ? ", and kept in this browser." : ", for this page load only."),
      "vc-ok");
  } catch (e) {
    log.debug("importIdentity(): " + e.message);
    setText("vpv_identity_status", "Not imported: " + e.message, "vc-bad");
  }
  log.debug("Leaving importIdentity().");
  return false;
}

// Throw the identity away. Every wallet that trusted the old one must be
// given the new one.
function newIdentity() {
  log.debug("Entering newIdentity().");
  identity = {};
  identityProblem = "";
  storeIdentity();
  showIdentity();
  setText("vpv_identity_status", "Discarded. A new identity is made by the " +
    "next request; a wallet that trusted the old one must be given the " +
    "new one.", "vc-pending");
  log.debug("Leaving newIdentity().");
  return false;
}

// ---------------------------------------------------------------------------
// STATE.
// ---------------------------------------------------------------------------
function saveState() {
  log.debug("Entering saveState().");
  try {
    VERIFIER_KEYS.forEach(function (id) {
      var v = val(id);
      if (el(id) && el(id).type === "checkbox") {
        localStorage.setItem(id, v ? "1" : "0");
      } else if (v) {
        localStorage.setItem(id, v);
      } else {
        localStorage.removeItem(id);
      }
    });
  } catch (e) {
    // No storage for this origin. Every field still works; nothing is kept.
    log.debug("saveState(): no storage — " + e.message);
  }
  // Key material behind its checkbox: off means removed, on every save.
  purgeIdentityIfOff();
  log.debug("Leaving saveState().");
}

function loadState() {
  log.debug("Entering loadState().");
  var viaApi = null;
  try {
    VERIFIER_KEYS.forEach(function (id) {
      var stored = localStorage.getItem(id);
      if (stored !== null && el(id)) {
        setVal(id, stored);
      }
    });
    viaApi = localStorage.getItem(FETCH_VIA_API_ID);
  } catch (e) {
    log.debug("loadState(): no storage — " + e.message);
  }
  initFetchViaApi(viaApi);
  loadIdentity();
  log.debug("Leaving loadState().");
}

// ---------------------------------------------------------------------------
// 1. WHAT TO ASK FOR.
// ---------------------------------------------------------------------------

// "address.country" -> ["address", "country"]; a number is an array index and
// `*` every element, as DCQL claims paths have them (section 7).
// transaction_data as typed into pane 2, encoded for `dcql`: undefined
// when empty.
function transactionDataFromPage(dcql) {
  log.debug("Entering transactionDataFromPage().");
  var text = val("vpv_transaction_data").trim();
  if (!text) {
    log.debug("Leaving transactionDataFromPage(). None.");
    return undefined;
  }
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving transactionDataFromPage(). Not JSON.");
    throw new Error("transaction_data is not JSON: " + e.message);
  }
  log.debug("Leaving transactionDataFromPage().");
  return verifier.encodeTransactionData(parsed, dcql);
}

// verifier_info as typed into pane 2: undefined when empty, else the parsed
// JSON (requestObjectClaims() says what is wrong with it).
function verifierInfoFromPage() {
  log.debug("Entering verifierInfoFromPage().");
  var text = val("vpv_verifier_info").trim();
  if (!text) {
    log.debug("Leaving verifierInfoFromPage(). None.");
    return undefined;
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving verifierInfoFromPage().");
    return parsed;
  } catch (e) {
    log.debug("Leaving verifierInfoFromPage(). Not JSON.");
    throw new Error("verifier_info is not JSON: " + e.message);
  }
}

// One line of the claims box: "[id:] path [= v1 | v2]".
function claimOf(line, intent) {
  log.debug("Entering claimOf().");
  var m = /^\s*(?:([A-Za-z0-9_-]+)\s*:\s*)?([^=]+?)\s*(?:=\s*(.*))?$/
    .exec(line);
  var claim = { path: pathOf(m ? m[2] : line) };
  if (m && m[1]) {
    claim.id = m[1];
  }
  if (m && m[3] !== undefined && m[3] !== null) {
    claim.values = m[3].split("|").map(function (v) {
      var t = v.trim();
      return t === "true" ? true : t === "false" ? false
        : /^-?\d+$/.test(t) ? Number(t) : t;
    }).filter(function (v) {
      return v !== "";
    });
  }
  if (intent === "true" || intent === "false") {
    claim.intentToRetain = intent === "true";
  }
  log.debug("Leaving claimOf().");
  return claim;
}

function pathOf(line) {
  log.debug("Entering pathOf().");
  var path = String(line).trim().split(".").filter(function (one) {
    return one.length > 0;
  }).map(function (one) {
    if (one === "*") {
      return null;
    }
    return /^\d+$/.test(one) ? Number(one) : one;
  });
  log.debug("Leaving pathOf(). " + path.length + " segment(s).");
  return path;
}

// The single credential query the fields describe.
function querySpec() {
  log.debug("Entering querySpec().");
  var format = val("vpv_format") || "dc+sd-jwt";
  var types = val("vpv_type").split(/\s+/).filter(Boolean);
  var spec = {
    id: val("vpv_query_id") || "credential",
    format: format,
    claims: val("vpv_claims").split(/\n/).filter(function (line) {
      return line.trim().length > 0;
    }).map(function (line) {
      return claimOf(line, format === "mso_mdoc" ?
                     val("vpv_intent_to_retain") : "");
    }),
    requireBinding: !!val("vpv_binding")
  };
  var sets = val("vpv_claim_sets").split(/\n/).map(function (line) {
    return line.split(",").map(function (id) {
      return id.trim();
    }).filter(Boolean);
  }).filter(function (set) {
    return set.length > 0;
  });
  if (sets.length) {
    spec.claimSets = sets;
  }
  if (val("vpv_trusted_authorities")) {
    var aki = verifier.akiValuesFromAnchors(trustAnchorsFromPage());
    setText("vpv_trusted_authorities_note", aki.values.length
      ? aki.values.length + " aki value(s) from the trust anchors." +
        (aki.missing.length ? " No SubjectKeyIdentifier in: " +
          aki.missing.join(", ") + "." : "")
      : "No trust anchor below has a SubjectKeyIdentifier, so no " +
        "trusted_authorities can be asked for.",
      aki.values.length ? "vc-ok" : "vc-bad");
    if (aki.values.length) {
      spec.trustedAuthorities = [{ type: "aki", values: aki.values }];
    }
  } else {
    setText("vpv_trusted_authorities_note", "");
  }
  if (format === "dc+sd-jwt") {
    spec.vct = types;
  } else if (format === "mso_mdoc") {
    spec.doctype = types[0] || "";
  } else {
    spec.types = types;
  }
  log.debug("Leaving querySpec(). " + format);
  return spec;
}

function regenerateDcql() {
  log.debug("Entering regenerateDcql().");
  try {
    var dcql = verifier.buildDcql({ queries: [querySpec()] });
    setVal("vpv_dcql", JSON.stringify(dcql, null, 2));
    setText("vpv_dcql_status", "Generated from the fields above.", "vc-ok");
  } catch (e) {
    // Not generated (#468, M4): the query the fields describe is one a
    // Wallet must reject — most often a type field left empty, which
    // Appendix B makes REQUIRED for every format. The last query that WAS
    // generated is cleared, so "Create the request" cannot quietly send a
    // query the fields no longer describe.
    setVal("vpv_dcql", "");
    setText("vpv_dcql_status", "Not generated: " + e.message, "vc-bad");
  }
  saveState();
  log.debug("Leaving regenerateDcql().");
  return false;
}

function showTypeLabel() {
  log.debug("Entering showTypeLabel().");
  var label = el("vpv_type_label");
  if (label) {
    label.textContent = TYPE_LABELS[val("vpv_format")] || "type";
  }
  log.debug("Leaving showTypeLabel().");
}

function formatChanged() {
  log.debug("Entering formatChanged().");
  showTypeLabel();
  regenerateDcql();
  log.debug("Leaving formatChanged().");
  return false;
}

// The trust anchors changed: the trusted_authorities a generated query asks
// for are drawn from them, so the query is drawn again when it asks.
function anchorsChanged() {
  log.debug("Entering anchorsChanged().");
  settingsChanged();
  if (val("vpv_trusted_authorities")) {
    regenerateDcql();
  }
  log.debug("Leaving anchorsChanged().");
  return false;
}

function settingsChanged() {
  log.debug("Entering settingsChanged().");
  // An unsigned request has nothing to fetch by reference: section 5.10's
  // request_uri carries a Request Object, which is signed.
  if (val("vpv_client_prefix") === "redirect_uri") {
    setVal("vpv_delivery", "value");
  }
  var row = el("vpv_client_id_row");
  if (row) {
    row.style.display = val("vpv_client_prefix") === "pre-registered"
      ? "" : "none";
  }
  var mode = val("vpv_response_mode");
  var dcNote = el("vpv_dc_api_note");
  if (dcNote) {
    // OpenID4VP 1.0 Appendix A.2: an unsigned request carries no client_id
    // (the audience is "origin:" + this page's origin), so the prefix is not
    // used; a signed one names its prefix in client_id, and its certificate
    // is made for THIS PAGE's host, not the api's. redirect_uri cannot be
    // signed (section 5.9.3).
    var signedDc = !!(el("vpv_dc_signed") && el("vpv_dc_signed").checked);
    dcNote.textContent = mode === "dc_api" || mode === "dc_api.jwt"
      ? "Nothing is hosted: the browser hands the request to a wallet " +
        "and the answer comes back to this page. " + (signedDc
          ? "Signed: client_id carries the Client Identifier prefix above, " +
            "and the certificate names this page's host (" +
            window.location.hostname + "), not the api's" +
            (val("vpv_client_prefix") === "redirect_uri"
              ? "; redirect_uri cannot be signed, so choose another " +
                "prefix or untick \"signed\"." : ".")
          : "Unsigned: no client_id is sent and the prefix above is not " +
            "used; the audience is origin:" + window.location.origin + ".")
      : "";
  }
  saveState();
  log.debug("Leaving settingsChanged().");
  return false;
}

// The DCQL as the reader left it in the textarea, which wins over the fields.
function dcqlFromPage() {
  log.debug("Entering dcqlFromPage().");
  var text = val("vpv_dcql").trim();
  if (!text) {
    var built = verifier.buildDcql({ queries: [querySpec()] });
    log.debug("Leaving dcqlFromPage(). Built from the fields.");
    return built;
  }
  var parsed = JSON.parse(text);
  if (!parsed || !Array.isArray(parsed.credentials) ||
      !parsed.credentials.length) {
    log.debug("Leaving dcqlFromPage(). No credentials.");
    throw new Error("The DCQL query has no credentials array.");
  }
  log.debug("Leaving dcqlFromPage().");
  return parsed;
}

// ---------------------------------------------------------------------------
// THE API, which hosts request_uri and response_uri.
// ---------------------------------------------------------------------------
async function apiJson(method, path, body, secret) {
  log.debug("Entering apiJson(). " + method + " " + path);
  var headers = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (secret) {
    headers.Authorization = "Bearer " + secret;
  }
  var response = await fetch(API_URL + path, {
    method: method, headers: headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  var text = await response.text();
  var json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (e) {
    log.debug("apiJson(): not JSON.");
    json = null;
  }
  if (!response.ok) {
    var why = (json && (json.error_description || json.error ||
                        (json.errors && json.errors.join("; ")))) ||
              text.slice(0, 200);
    log.debug("Leaving apiJson(). " + response.status);
    throw new Error(method + " " + path + " answered " + response.status +
                    (why ? ": " + why : ""));
  }
  log.debug("Leaving apiJson(). " + response.status);
  return json;
}

async function probeApi() {
  log.debug("Entering probeApi().");
  if (!BACKEND_AVAILABLE || !API_URL) {
    setText("vpv_api_status", "This deployment has no api, so it cannot " +
      "host a request_uri or a response_uri. An answer a wallet produced " +
      "can still be pasted into pane 4 and checked.", "vc-pending");
    log.debug("Leaving probeApi(). No backend.");
    return false;
  }
  try {
    var limits = await apiJson("GET", "/oid4vp/verifier/limits");
    if (limits && limits.enabled === false) {
      setText("vpv_api_status", "The api at " + API_URL + " has its " +
        "Verifier endpoints switched off (oid4vpVerifierEnabled).",
        "vc-bad");
      log.debug("Leaving probeApi(). Disabled.");
      return false;
    }
    setText("vpv_api_status", "The api at " + API_URL + " will host this " +
      "request's request_uri and response_uri" + (limits &&
      limits.publicBaseUrl ? ", handing wallets URLs under " +
      limits.publicBaseUrl + " (oid4vpVerifierPublicBaseUrl)" : "") + ".",
      "vc-ok");
    log.debug("Leaving probeApi(). Available.");
    return true;
  } catch (e) {
    setText("vpv_api_status", "The api at " + API_URL + " did not answer " +
      "(" + e.message + "). Pane 4 still checks a pasted answer.", "vc-bad");
    log.debug("Leaving probeApi(). " + e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// 2. HOW TO ASK, and 3. HANDING IT OVER.
// ---------------------------------------------------------------------------
function base64OfBytes(bytes) {
  log.debug("Entering base64OfBytes().");
  var binary = "";
  var view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (var i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  log.debug("Leaving base64OfBytes().");
  return btoa(binary);
}

// A compact JWS's header and payload, pretty-printed, for pane 3.
function decodeJws(compact) {
  log.debug("Entering decodeJws().");
  var parts = String(compact || "").split(".");
  var decode = function (part) {
    var padded = part.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    return JSON.parse(decodeURIComponent(escape(atob(padded))));
  };
  try {
    var text = JSON.stringify({ header: decode(parts[0]),
                                payload: decode(parts[1]) }, null, 2);
    log.debug("Leaving decodeJws().");
    return text;
  } catch (e) {
    log.debug("Leaving decodeJws(). " + e.message);
    return "(not a JWS: " + e.message + ")";
  }
}

// THE PREFIXES THAT NEED A CERTIFICATE. The others sign with a bare key
// (decentralized_identifier, verifier_attestation, pre-registered), except
// redirect_uri, which signs with nothing at all: OpenID4VP 1.0 section
// 5.9.3, "Requests using the redirect_uri Client Identifier Prefix cannot
// be signed" (#469, C17). It needs no certificate, no key and no secure
// context.
var X509_PREFIXES = ["x509_hash", "x509_san_dns"];

// The key a request is signed with, and what a wallet must be given to
// trust it, for one Client Identifier prefix. `dnsName` is the host the
// certificate names; `caIssuersUrl` the api URL serving its root (absent
// under the DC API, where nothing is hosted).
async function makeSigner(prefix, dnsName, caIssuersUrl) {
  log.debug("Entering makeSigner(). " + prefix);
  var signer = { prefix: prefix, attester: null, trust: "" };
  if (prefix === "redirect_uri") {
    // Unsigned: there is no identity to make, so nothing is generated and
    // no Web Crypto is asked for.
    signer.identity = {};
    signer.trust = "Nothing: a redirect_uri request is unsigned, and the " +
      "Client Identifier is the URL the answer goes to (section 5.9.3).";
    signer.dnsName = dnsName;
    log.debug("Leaving makeSigner(). Unsigned.");
    return signer;
  }
  if (X509_PREFIXES.indexOf(prefix) >= 0) {
    // THE CERTIFICATE NEEDS WEB CRYPTO until #463 moves x509.js and
    // key_material.js onto the pure-JS module. Said here by name rather
    // than left to fail as "Cannot read properties of undefined".
    if (typeof crypto === "undefined" || !crypto.subtle) {
      log.debug("Leaving makeSigner(). No secure context.");
      throw new Error("This page is not in a secure context (https or " +
        "localhost), so the browser offers no Web Crypto, and the " +
        "certificate an x509 Client Identifier is signed with cannot be " +
        "made (#463). The decentralized_identifier, verifier_attestation " +
        "and pre-registered prefixes need no certificate.");
    }
    // The ROOT is the identity's, kept across runs; the leaf is this
    // request's (#470, B4).
    var held = await ensureIdentity(true);
    signer.identity = await verifier.makeVerifierIdentity({
      dnsName: dnsName, caIssuersUrl: caIssuersUrl, root: held.root,
      keyAlg: val("vpv_request_key") || "ec-p256" });
    signer.trust = "The Verifier's root CA, the same for every request " +
      "while this identity is kept. A wallet that does not follow the " +
      "leaf's Authority Information Access must be given it as a trust " +
      "anchor:\n" + (signer.identity.rootPem || "");
  } else {
    var keys = await ensureIdentity(false);
    signer.identity = keys.requestKey;
    if (prefix === "verifier_attestation") {
      signer.attester = keys.attester;
      signer.trust = "The attester's keys (trust these):\n" +
        JSON.stringify(signer.attester.jwks, null, 2);
    } else if (prefix === "pre-registered") {
      signer.trust = "The JWKS the wallet must hold for this client_id:\n" +
        JSON.stringify(verifier.preRegisteredJwks(signer.identity), null, 2);
    }
  }
  signer.dnsName = dnsName;
  log.debug("Leaving makeSigner().");
  return signer;
}

function clientIdOf(signer, redirectUri) {
  log.debug("Entering clientIdOf(). " + signer.prefix);
  // verifier_attestation's value (the attestation's sub) is the api host:
  // the request key it signs with names no host of its own.
  var id = verifier.clientIdFor(signer.prefix, signer.identity, {
    dnsName: signer.dnsName, redirectUri: redirectUri,
    value: signer.prefix === "verifier_attestation" ? signer.dnsName
                                                     : undefined,
    clientId: val("vpv_client_id_typed").trim() || undefined,
    didMethod: "jwk" });
  if (signer.prefix === "decentralized_identifier") {
    signer.trust = "The Verifier's DID; it resolves with no network:\n" + id;
  }
  log.debug("Leaving clientIdOf(). " + id);
  return id;
}

async function signWith(signer, claims) {
  log.debug("Entering signWith(). " + signer.prefix);
  var jws = await verifier.signRequestObject({
    claims: claims, identity: signer.identity,
    attester: signer.attester || undefined });
  log.debug("Leaving signWith().");
  return jws;
}

// The invocation as a QR code, for a wallet on another device. A request by
// value can be too long for one; the page says so rather than drawing a
// code no camera can read.
function showQr(invocation) {
  log.debug("Entering showQr().");
  var host = el("vpv_qr");
  if (!host) {
    log.debug("Leaving showQr(). No element.");
    return;
  }
  host.innerHTML = "";
  if (!invocation) {
    setText("vpv_qr_note", "");
    log.debug("Leaving showQr(). Nothing to draw.");
    return;
  }
  try {
    var code = qrcode(0, "L");
    code.addData(invocation);
    code.make();
    // createSvgTag() draws rectangles from the bits alone; nothing of the
    // invocation's text reaches the markup.
    host.innerHTML = code.createSvgTag({ cellSize: 4, margin: 4,
                                         scalable: true });
    setText("vpv_qr_note", "Scan with a wallet on another device (" +
      invocation.length + " characters).", "vc-ok");
  } catch (e) {
    setText("vpv_qr_note", "Too long for a QR code (" + invocation.length +
      " characters): hand it over by reference instead.", "vc-pending");
  }
  log.debug("Leaving showQr().");
}

function isHaip() {
  log.debug("Entering isHaip().");
  log.debug("Leaving isHaip().");
  return val("vpv_profile") === "haip";
}

// Under the HAIP profile (#471, E1), refuse a request HAIP forbids this
// Verifier to send, naming each rule; say what it only RECOMMENDS.
function haipGate(r) {
  log.debug("Entering haipGate().");
  if (!isHaip()) {
    setText("vpv_profile_note", "");
    log.debug("Leaving haipGate(). Not HAIP.");
    return;
  }
  var found = verifier.haipRequestProblems(Object.assign({}, r, {
    formats: ((r.dcql || {}).credentials || []).map(function (q) {
      return q.format;
    }) }));
  setText("vpv_profile_note", found.advised.length
    ? "HAIP 1.0 advises: " + found.advised.join(" ") : "",
    found.advised.length ? "vc-warn" : "");
  if (found.refused.length) {
    log.debug("Leaving haipGate(). Refused.");
    throw new Error("HAIP 1.0 does not let this Verifier send that " +
                    "request: " + found.refused.join(" ") + " Change it, " +
                    "or choose the OpenID4VP 1.0 profile.");
  }
  log.debug("Leaving haipGate().");
}

async function createRequest() {
  log.debug("Entering createRequest().");
  saveState();
  stopPolling();
  var mode = val("vpv_response_mode") || "direct_post";
  if (mode === "dc_api" || mode === "dc_api.jwt") {
    log.debug("Leaving createRequest(). The Digital Credentials API.");
    return askThroughDcApi();
  }
  setText("vpv_create_status", "Working …", "vc-pending");
  try {
    var dcql = dcqlFromPage();
    if (!(await probeApi())) {
      throw new Error("There is no api to host the request and the answer.");
    }
    var prefix = val("vpv_client_prefix") || "x509_hash";
    var delivery = prefix === "redirect_uri" ? "value"
      : (val("vpv_delivery") || "reference-get");
    var live = delivery === "reference-post";
    var requestUriMethod = live ? "post"
      : delivery === "reference-get-explicit" ? "get" : undefined;
    var redirectUri = val("vpv_redirect_uri").trim();
    var create = { liveSigning: live };
    if (redirectUri) {
      create.redirectUri = redirectUri;
    }
    // The base a wallet reaches the api at, when the page's own is not one
    // (#470, B5): the api checks it is an https URL and builds the three
    // URLs from it. It serves on its own host whatever this says.
    var publicBase = val("vpv_public_base_url").trim();
    if (publicBase) {
      create.publicBaseUrl = publicBase;
    }
    haipGate({ dcApi: false, prefix: prefix, delivery: delivery,
               responseMode: mode, dcql: dcql, redirectUri: redirectUri });
    var hosted = await apiJson("POST", "/oid4vp/verifier", create);
    var host = new URL(hosted.responseUri).hostname;
    if (prefix === "x509_san_dns") {
      // Refused before a certificate is made: an IP address is never a
      // dNSName (clientIdFor() says why and what to use instead).
      verifier.clientIdFor(prefix, null, { dnsName: host });
    }
    var signer = await makeSigner(prefix, host, hosted.caIssuersUrl);
    var encryption = mode === "direct_post.jwt"
      ? await verifier.responseEncryptionKey() : null;
    var clientId = clientIdOf(signer, hosted.responseUri);
    var nonce = verifier.randomToken(16);
    var state = verifier.randomToken(16);
    var claimsInput = {
      clientId: clientId, responseUri: hosted.responseUri,
      responseMode: mode, nonce: nonce, state: state, dcql: dcql,
      encryptionJwk: encryption ? encryption.publicJwk : undefined,
      scope: val("vpv_scope").trim() || undefined,
      verifierInfo: verifierInfoFromPage(),
      transactionData: transactionDataFromPage(dcql)
    };
    var claims = verifier.requestObjectClaims(claimsInput);
    var requestObject = "";
    var invocation;
    if (prefix === "redirect_uri") {
      // Unsigned, by value: the claims ARE the parameters (section 5.1).
      var params = {};
      Object.keys(claims).forEach(function (name) {
        if (name === "iss" || name === "aud" || name === "iat" ||
            name === "exp" || name === "client_id") {
          return;
        }
        var v = claims[name];
        params[name] = typeof v === "string" ? v : JSON.stringify(v);
      });
      invocation = verifier.authorizationRequestUri({
        scheme: val("vpv_scheme"), clientId: clientId, params: params });
    } else {
      requestObject = await signWith(signer, claims);
      var published = { requestObject: requestObject,
                        redirectUri: redirectUri || undefined };
      if (signer.identity.rootDer) {
        published.caCertificate = base64OfBytes(signer.identity.rootDer);
      }
      await apiJson("PUT", "/oid4vp/verifier/" + hosted.id + "/request",
                    published, hosted.secret);
      invocation = delivery === "value"
        ? verifier.authorizationRequestUri({
          scheme: val("vpv_scheme"), clientId: clientId,
          requestObject: requestObject })
        : verifier.authorizationRequestUri({
          scheme: val("vpv_scheme"), clientId: clientId,
          requestUri: hosted.requestUri,
          requestUriMethod: requestUriMethod,
          // Section 5.1: under post the Verifier SHOULD send its
          // capabilities beside request_uri (#468, M8).
          clientMetadata: live ? claims.client_metadata : undefined });
    }
    current = {
      hosted: hosted,
      identity: signer.identity,
      signer: signer,
      claimsInput: claimsInput,
      live: live,
      session: {
        profile: isHaip() ? "haip" : "",
        transactionData: claimsInput.transactionData,
        clientId: clientId, nonce: nonce, state: state,
        responseUri: hosted.responseUri, responseMode: mode, dcql: dcql,
        decryptionJwk: encryption ? encryption.privateJwk : undefined
      },
      after: 0,
      answered: false
    };
    showRequest(invocation, clientId, requestObject, claims);
    setText("vpv_create_status", "The request is ready. Hand it to a " +
      "wallet (pane 3); its answer will appear in pane 4.", "vc-ok");
    startPolling();
  } catch (e) {
    log.warn("createRequest(): " + e.message);
    setText("vpv_create_status", e.message, "vc-bad");
  }
  log.debug("Leaving createRequest().");
  return false;
}

// THE DIGITAL CREDENTIALS API (OpenID4VP 1.0 Appendix A): the browser hands
// the request to a wallet the platform knows, and the answer comes back to
// this page, so nothing is hosted. Unsigned, the Client Identifier is this
// page's origin; signed, the request names its Client Identifier and lists
// this origin in expected_origins.
async function askThroughDcApi() {
  log.debug("Entering askThroughDcApi().");
  saveState();
  stopPolling();
  setText("vpv_create_status", "Working …", "vc-pending");
  try {
    if (typeof navigator === "undefined" || !navigator.credentials ||
        typeof DigitalCredential === "undefined") {
      throw new Error("This browser has no Digital Credentials API " +
        "(navigator.credentials.get with `digital`). It is in recent " +
        "Chromium-based browsers, on a secure origin, with a wallet the " +
        "platform knows.");
    }
    var mode = val("vpv_response_mode");
    if (mode !== "dc_api" && mode !== "dc_api.jwt") {
      mode = "dc_api";
    }
    var multisigned = !!val("vpv_dc_multisigned");
    var signed = !!val("vpv_dc_signed") || multisigned;
    var secondPrefix = val("vpv_dc_second_prefix") ||
      "decentralized_identifier";
    var origin = window.location.origin;
    var dcql = dcqlFromPage();
    haipGate({ dcApi: true, signed: signed, responseMode: mode, dcql: dcql,
               prefix: val("vpv_client_prefix") || "x509_hash" });
    if (multisigned) {
      haipGate({ dcApi: true, signed: true, responseMode: mode, dcql: dcql,
                 prefix: secondPrefix });
    }
    var encryption = mode === "dc_api.jwt"
      ? await verifier.responseEncryptionKey() : null;
    var nonce = verifier.randomToken(16);
    var signer = null;
    var clientId;
    if (signed) {
      var prefix = val("vpv_client_prefix") || "x509_hash";
      if (prefix === "redirect_uri") {
        throw new Error("A signed Digital Credentials API request needs a " +
          "Client Identifier a signature can stand for; redirect_uri " +
          "requests are unsigned. Untick \"signed\" to ask as this origin.");
      }
      signer = await makeSigner(prefix, window.location.hostname, undefined);
      clientId = clientIdOf(signer, undefined);
    } else {
      clientId = verifier.clientIdFor("origin", null, { origin: origin });
    }
    var transactionData = transactionDataFromPage(dcql);
    var claims = verifier.requestObjectClaims({
      clientId: signed ? clientId : undefined, responseMode: mode,
      nonce: nonce, dcql: dcql, transactionData: transactionData,
      encryptionJwk: encryption ? encryption.publicJwk : undefined,
      expectedOrigins: signed ? [origin] : undefined });
    var second = null;
    if (multisigned) {
      // A second prefix that yields the same client_id as the first (the
      // same kept request key under decentralized_identifier) is refused by
      // dcApiRequest(), naming it.
      second = await makeSigner(secondPrefix, window.location.hostname,
                                undefined);
    }
    var verifierInfo = verifierInfoFromPage();
    var request = await verifier.dcApiRequest({
      multisigned: multisigned,
      signers: multisigned ? [
        { identity: signer.identity, clientId: clientId,
          attester: signer.attester || undefined,
          verifierInfo: verifierInfo },
        { identity: second.identity, clientId: clientIdOf(second, undefined),
          attester: second.attester || undefined,
          verifierInfo: verifierInfo }] : undefined,
      signed: signed, claims: claims,
      identity: signer ? signer.identity : undefined, origin: origin,
      attester: signer && signer.attester ? signer.attester : undefined });
    current = {
      hosted: null, identity: signer ? signer.identity : {}, signer: signer,
      live: false,
      session: { profile: isHaip() ? "haip" : "",
                 transactionData: transactionData,
                 clientId: clientId, nonce: nonce, responseMode: mode,
                 dcql: dcql, origin: origin,
                 decryptionJwk: encryption ? encryption.privateJwk
                                           : undefined },
      after: 0, answered: false
    };
    setVal("vpv_invocation", JSON.stringify(request, null, 2));
    setVal("vpv_client_id", clientId);
    setVal("vpv_request_uri", "");
    setVal("vpv_response_uri", "");
    setVal("vpv_request_object", request.data && request.data.request
      ? decodeJws(request.data.request)
      : JSON.stringify(request.data, null, 2));
    setVal("vpv_root_pem", signer && signer.identity.rootPem || "");
    setVal("vpv_trust_out", signer ? signer.trust : "");
    showQr("");
    clearVerdict();
    setText("vpv_create_status", "Asking the browser for a credential " +
      "(" + request.protocol + ") …", "vc-pending");
    var credential = await navigator.credentials.get({
      digital: { requests: [request] } });
    var data = credential && credential.data;
    if (typeof data === "string") {
      data = JSON.parse(data);
    }
    current.answered = true;
    setText("vpv_create_status", "The wallet answered through the " +
      "browser (" + (credential && credential.protocol || "?") + ").",
      "vc-ok");
    await checkFields(data || {});
  } catch (e) {
    log.warn("askThroughDcApi(): " + e.message);
    setText("vpv_create_status", e.message, "vc-bad");
  }
  log.debug("Leaving askThroughDcApi().");
  return false;
}

// THE SAME-DEVICE FLOW without a redirect_uri (#468, M3). "Open it on this
// device" is the same-device flow, and HAIP 1.0 section 5.1 says of it:
// "Verifiers MUST include redirect_uri in the HTTP response to the Wallet's
// HTTP POST to the response_uri". This page has no HAIP mode, so it says so
// whenever a request is made with none configured: the wallet's browser
// then has nowhere to return to, and the session binding that redirect
// carries (OpenID4VP section 8.2's fresh value) is absent. A QR code
// scanned by another device needs none.
function sameDeviceNote() {
  log.debug("Entering sameDeviceNote().");
  if (val("vpv_redirect_uri").trim()) {
    setText("vpv_same_device_note", "");
    log.debug("Leaving sameDeviceNote(). Configured.");
    return;
  }
  setText("vpv_same_device_note", "No redirect_uri is configured (pane " +
    "2), so a wallet on THIS device has nowhere to send its browser back " +
    "to. For a same-device flow HAIP 1.0 section 5.1 says Verifiers MUST " +
    "include one; a QR code scanned on another device needs none.",
    "vc-pending");
  log.debug("Leaving sameDeviceNote(). Missing.");
}

// A host a wallet on ANOTHER device usually cannot reach (#470, B5):
// loopback, or a single-label name such as the compose service `api`.
function unreachableHost(url) {
  log.debug("Entering unreachableHost().");
  var host = "";
  try {
    host = new URL(url).hostname;
  } catch (e) {
    log.debug("Leaving unreachableHost(). Not a URL.");
    return "";
  }
  var local = host === "localhost" || /^127\./.test(host) ||
      host === "[::1]" || (host.indexOf(".") < 0 && host.indexOf(":") < 0);
  log.debug("Leaving unreachableHost(). " + local);
  return local ? host : "";
}

function showRequest(invocation, clientId, requestObject, claims) {
  log.debug("Entering showRequest().");
  setVal("vpv_invocation", invocation);
  var link = el("vpv_invocation_link");
  if (link) {
    link.href = invocation;
    link.style.display = "inline";
  }
  showQr(invocation);
  var far = unreachableHost(current.hosted.responseUri);
  if (far) {
    setText("vpv_qr_note", "The request_uri and response_uri are on " +
      far + ", which a wallet on another device usually cannot reach. " +
      "Set the public base URL in pane 2, or oid4vpVerifierPublicBaseUrl " +
      "on the api, to an address it can.", "vc-pending");
  }
  sameDeviceNote();
  setVal("vpv_client_id", clientId);
  setVal("vpv_request_uri", requestObject ? current.hosted.requestUri : "");
  setVal("vpv_response_uri", current.hosted.responseUri);
  setVal("vpv_request_object", requestObject ? decodeJws(requestObject)
    : JSON.stringify(claims, null, 2) + "\n(unsigned: sent as parameters)");
  setVal("vpv_root_pem", current.identity.rootPem || "");
  setVal("vpv_trust_out", current.signer ? current.signer.trust : "");
  var list = el("vpv_events");
  if (list) {
    list.innerHTML = "";
  }
  clearVerdict();
  setText("vpv_wait_status", "Waiting for the wallet …", "vc-pending");
  log.debug("Leaving showRequest().");
}

// ---------------------------------------------------------------------------
// 4. WHAT THE WALLET SENT.
// ---------------------------------------------------------------------------
function stopPolling() {
  log.debug("Entering stopPolling().");
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
  log.debug("Leaving stopPolling().");
}

// While the api holds a wallet's POST open for a live signature it waits
// waitMs (15 s by default), so the page polls fast enough to answer in it.
function pollInterval() {
  log.debug("Entering pollInterval().");
  log.debug("Leaving pollInterval().");
  return current && current.live ? LIVE_POLL_MS : POLL_MS;
}

function startPolling() {
  log.debug("Entering startPolling().");
  stopPolling();
  pollTimer = window.setTimeout(poll, pollInterval());
  log.debug("Leaving startPolling().");
}

function eventLine(event) {
  log.debug("Entering eventLine(). " + event.kind);
  var at = event.at ? new Date(event.at).toISOString() + " " : "";
  var text;
  if (event.kind === "request-fetched") {
    text = at + "The wallet fetched the Request Object (" +
      (event.method || "GET") + ")" +
      (event.walletNonce ? ", sending wallet_nonce " + event.walletNonce
                         : "") +
      (event.walletMetadata !== undefined ? " and wallet_metadata " +
        JSON.stringify(event.walletMetadata).slice(0, 300) : "") +
      (event.signingId ? "; the api is holding it open for a Request " +
        "Object signed with that nonce" : "") + "." +
      (event.problem ? " " + event.problem : "");
  } else if (event.kind === "request-signed") {
    text = at + (event.liveSigned
      ? "This page signed a fresh Request Object for that wallet, " +
        "echoing its wallet_nonce."
      : event.httpStatus
        ? "The wallet was answered HTTP " + event.httpStatus + " (" +
          (event.reason || "no reason given") + ")."
        : "The wallet was not given a Request Object signed for it (" +
          (event.reason || "no reason given") + ").");
  } else if (event.kind === "ca-fetched") {
    text = at + "The wallet fetched the Verifier's root certificate from " +
      "the leaf's Authority Information Access URL.";
  } else if (event.kind === "response") {
    text = at + "The wallet posted its answer (" +
      (event.contentType || "?") + "): " +
      Object.keys(event.fields || {}).join(", ") + "." +
      (event.redirectUri ? " It was sent on to " + event.redirectUri +
        " (response_code " + event.responseCode + ", fresh for this " +
        "answer: section 8.2)." : "") +
      (event.problem ? " " + event.problem : "");
  } else if (event.kind === "response-refused") {
    text = at + "The api refused a POST to response_uri: " +
      (event.problem || "no reason given") + ".";
  } else {
    text = at + event.kind;
  }
  log.debug("Leaving eventLine().");
  return text;
}

// A wallet POSTed to request_uri and the api is holding it open: sign a
// Request Object carrying its wallet_nonce (section 5.10) and hand it over.
// A 404 means the wait ran out and the wallet already has the one signed in
// advance, which the event that follows will say.
// What honouring wallet_metadata found, one line each in the event list.
function showWalletMetadataFindings(findings) {
  log.debug("Entering showWalletMetadataFindings().");
  var list = el("vpv_events");
  if (!list) {
    log.debug("Leaving showWalletMetadataFindings(). No list.");
    return;
  }
  (findings || []).forEach(function (f) {
    var li = document.createElement("li");
    li.className = f.level === "ok" ? "vc-ok" : "vc-pending";
    li.textContent = "wallet_metadata: " + f.text;
    list.appendChild(li);
  });
  log.debug("Leaving showWalletMetadataFindings().");
}

async function signLive(event) {
  log.debug("Entering signLive(). " + event.signingId);
  try {
    // What the wallet said it can do (section 5.10), honoured where this
    // Verifier can and reported where it cannot.
    var dcql = current.claimsInput.dcql || {};
    var plan = verifier.planForWalletMetadata(event.walletMetadata, {
      keyJwk: (current.signer.identity || {}).privateJwk,
      prefix: current.signer.prefix, responseMode:
        current.claimsInput.responseMode,
      responseAlg: current.claimsInput.encryptionJwk ? "ECDH-ES" : "",
      formats: (dcql.credentials || []).map(function (q) {
        return q.format;
      }) });
    var input = Object.assign({}, current.claimsInput, {
      walletNonce: event.walletNonce || undefined,
      encValuesSupported: plan.encValues });
    var claims = verifier.requestObjectClaims(input);
    var jws = await verifier.signRequestObject({
      claims: claims, identity: current.signer.identity,
      attester: current.signer.attester || undefined,
      algId: plan.signAlg });
    var served = plan.encryptTo
      ? await verifier.encryptRequestObject(jws, plan) : jws;
    await apiJson("PUT", "/oid4vp/verifier/" + current.hosted.id +
                  "/request/" + encodeURIComponent(event.signingId),
                  { requestObject: served }, current.hosted.secret);
    setVal("vpv_request_object", decodeJws(jws) + "\n(signed live, for " +
           "wallet_nonce " + (event.walletNonce || "none") +
           (plan.encryptTo ? "; then encrypted to the wallet's key" : "") +
           ")");
    showWalletMetadataFindings(plan.findings);
  } catch (e) {
    setText("vpv_wait_status", "Could not sign a live Request Object: " +
            e.message, "vc-bad");
  }
  log.debug("Leaving signLive().");
}

async function poll() {
  log.debug("Entering poll().");
  pollTimer = null;
  if (!current || current.answered || !current.hosted) {
    log.debug("Leaving poll(). Nothing to wait for.");
    return;
  }
  try {
    var got = await apiJson("GET", "/oid4vp/verifier/" + current.hosted.id +
                            "/events?after=" + current.after, undefined,
                            current.hosted.secret);
    var events = (got && got.events) || [];
    if (got && got.next !== undefined) {
      current.after = got.next;
    }
    var list = el("vpv_events");
    var answer = null;
    var toSign = [];
    events.forEach(function (event) {
      if (list) {
        var li = document.createElement("li");
        li.textContent = eventLine(event);
        list.appendChild(li);
      }
      if (event.kind === "request-fetched" && event.signingId) {
        toSign.push(event);
      }
      if (event.kind === "response" && !answer) {
        answer = event;
      }
    });
    var i;
    for (i = 0; i < toSign.length; i++) {
      await signLive(toSign[i]);
    }
    if (answer) {
      current.answered = true;
      setText("vpv_wait_status", "The wallet answered.", "vc-ok");
      await checkFields(answer.fields || {}, answer.contentType || "");
      log.debug("Leaving poll(). Answered.");
      return;
    }
  } catch (e) {
    setText("vpv_wait_status", "Waiting for the wallet; the last poll " +
      "failed: " + e.message, "vc-bad");
  }
  pollTimer = window.setTimeout(poll, pollInterval());
  log.debug("Leaving poll(). Still waiting.");
}

// ---------------------------------------------------------------------------
// THE ISSUER-SIDE FETCHES (#470, B3): an issuer's SD-JWT VC metadata and its
// JWKS, a did:web document, a Token Status List or a Bitstring Status List
// credential. From the page, each is a cross-origin GET that the browser
// lets the page read only if the server sends CORS headers — and SD-JWT VC
// metadata and did:web hosts generally send none, while Token Status List
// section 8.1 makes CORS only a SHOULD. So by default they go through the
// api's guarded proxy, POST /oid4vp/call, which no browser policy applies to
// and which carries the address policy, the timeouts and the size and
// redirect caps of every other outbound call.
//
// THE DEFAULT IS ON WHERE THERE IS AN API AND OFF WHERE THERE IS NONE. A
// Verifier that can only read issuers that happen to allow its origin
// reports "could not fetch" for most of the world, which is the wrong
// default wherever the api can do better. A static site has no api, so the
// box is unticked and disabled there and the browser fetches directly. A
// choice the reader made is remembered (an ordinary setting) and wins.
//
// Either way a fetch that fails throws an Error naming the URL, which the
// engine reports as a SKIP ("could not fetch …"), never as a signature
// FAIL: a key nobody could read is a check not performed.
// ---------------------------------------------------------------------------
function apiOffered() {
  log.debug("Entering apiOffered().");
  var on = BACKEND_AVAILABLE && !!API_URL;
  log.debug("Leaving apiOffered(). " + on);
  return on;
}

function fetchViaApi() {
  log.debug("Entering fetchViaApi().");
  var on = apiOffered() && !!val(FETCH_VIA_API_ID);
  log.debug("Leaving fetchViaApi(). " + on);
  return on;
}

// The ticked state on load: the reader's remembered choice, else the
// default above. Disabled where there is no api to choose.
function initFetchViaApi(stored) {
  log.debug("Entering initFetchViaApi().");
  var box = el(FETCH_VIA_API_ID);
  if (!box) {
    log.debug("Leaving initFetchViaApi(). No element.");
    return;
  }
  if (!apiOffered()) {
    box.checked = false;
    box.disabled = true;
    log.debug("Leaving initFetchViaApi(). No api.");
    return;
  }
  box.disabled = false;
  if (stored === null || stored === undefined) {
    box.checked = true;
  }
  log.debug("Leaving initFetchViaApi(). " + box.checked);
}

function bytesOfBase64(text) {
  log.debug("Entering bytesOfBase64().");
  var binary = atob(String(text || ""));
  var out = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  log.debug("Leaving bytesOfBase64(). " + out.length + " bytes.");
  return out;
}

function headerOf(headers, name) {
  log.debug("Entering headerOf(). " + name);
  var wanted = String(name).toLowerCase();
  var found = "";
  Object.keys(headers || {}).forEach(function (key) {
    if (key.toLowerCase() === wanted && !found) {
      found = String(headers[key]);
    }
  });
  log.debug("Leaving headerOf().");
  return found;
}

// One GET through POST /oid4vp/call, the body as bytes (responseEncoding
// base64, so a CWT status list arrives intact). A 400 is the api refusing
// (the address policy, most often), a 502 the server unreachable, and a
// non-2xx inside a 200 is what the server itself answered.
async function apiGet(url, accept) {
  log.debug("Entering apiGet(). " + url);
  var response;
  try {
    response = await fetch(API_URL + "/oid4vp/call", {
      method: "POST",
      headers: { "Content-Type": "application/json",
                 Accept: "application/json" },
      body: JSON.stringify({ url: url, method: "GET",
                             headers: { Accept: accept },
                             responseEncoding: "base64" })
    });
  } catch (e) {
    log.debug("Leaving apiGet(). The api did not answer.");
    throw new Error("GET " + url + " through the api: the api at " +
                    API_URL + " did not answer (" + e.message + ").");
  }
  var answer = null;
  try {
    answer = await response.json();
  } catch (e) {
    answer = null;
  }
  if (!response.ok || !answer) {
    var why = (answer && answer.error) || ("HTTP " + response.status);
    log.debug("Leaving apiGet(). The api answered " + response.status);
    throw new Error("GET " + url + " through the api: " +
      (response.status === 400 ? "the api refused it: " :
       "it could not be reached: ") + why);
  }
  if (!answer.ok) {
    log.debug("Leaving apiGet(). " + answer.status);
    throw new Error("GET " + url + " answered " + answer.status +
                    " (through the api).");
  }
  var body = answer.bodyEncoding === "base64" ? bytesOfBase64(answer.body)
    : new TextEncoder().encode(String(answer.body || ""));
  log.debug("Leaving apiGet(). " + body.length + " bytes.");
  return { body: body,
           contentType: headerOf(answer.headers, "content-type") };
}

// The browser's own GET. A server that sends no CORS headers makes fetch()
// throw a bare TypeError ("Failed to fetch") with nothing in it about why,
// so the URL and the likely reason are added.
async function browserGet(url, accept) {
  log.debug("Entering browserGet(). " + url);
  var response;
  try {
    response = await fetch(url, { headers: { Accept: accept } });
  } catch (e) {
    log.debug("Leaving browserGet(). " + e.message);
    throw new Error("GET " + url + " failed in the browser (" + e.message +
      "). A server that sends no CORS headers cannot be read from a page; " +
      (apiOffered() ? "tick \"through the api\" in pane 2."
                    : "this deployment has no api to fetch it through."));
  }
  if (!response.ok) {
    log.debug("Leaving browserGet(). " + response.status);
    throw new Error("GET " + url + " answered " + response.status);
  }
  var body = new Uint8Array(await response.arrayBuffer());
  log.debug("Leaving browserGet(). " + body.length + " bytes.");
  return { body: body,
           contentType: response.headers.get("content-type") || "" };
}

async function getBytes(url, accept) {
  log.debug("Entering getBytes(). " + url);
  var got = fetchViaApi() ? await apiGet(url, accept)
                          : await browserGet(url, accept);
  log.debug("Leaving getBytes().");
  return got;
}

async function fetchJson(url) {
  log.debug("Entering fetchJson(). " + url);
  var got = await getBytes(url, "application/json");
  var json;
  try {
    json = JSON.parse(new TextDecoder().decode(got.body));
  } catch (e) {
    log.debug("Leaving fetchJson(). Not JSON.");
    throw new Error("GET " + url + " did not answer JSON (" +
                    (got.contentType || "no Content-Type") + "): " +
                    e.message);
  }
  log.debug("Leaving fetchJson().");
  return json;
}

// The status lists' fetcher. The body is handed over as BYTES with its
// Content-Type, not as text: a Status List Token may be a binary CWT, and
// response.text() would turn it into replacement characters before the
// engine could say what it was. vp_verifier.js decodes UTF-8 itself.
async function fetchText(url, opts) {
  log.debug("Entering fetchText(). " + url);
  var accept = (opts && opts.accept) || "*/*";
  var got = await getBytes(url, accept);
  log.debug("Leaving fetchText(). " + got.body.length + " bytes.");
  return got;
}

function clearVerdict() {
  log.debug("Entering clearVerdict().");
  var table = el("vpv_checks");
  if (table) {
    table.innerHTML = "";
  }
  setVal("vpv_claims_out", "");
  var out = el("vpv_claims_out");
  if (out) {
    out.textContent = "";
  }
  setText("vpv_verdict", "");
  log.debug("Leaving clearVerdict().");
}

// One row per check, every one of them, built as text: the detail of a check
// often quotes what the wallet sent.
function renderChecks(result) {
  log.debug("Entering renderChecks().");
  clearVerdict();
  var table = el("vpv_checks");
  (result.checks || []).forEach(function (check) {
    if (!table) {
      return;
    }
    var row = table.insertRow(-1);
    row.id = "vpv_check_" + check.id;
    row.className = "vc-check-" + check.status +
      (check.essential && check.status === "skip" ? " vc-check-unperformed" :
       "");
    [check.status.toUpperCase(), check.group || "", check.label || check.id,
     check.detail || ""].forEach(function (text) {
      row.insertCell(-1).textContent = text;
    });
  });
  // HAIP 1.0 rows (#471, E1) are a conformance report beside the
  // validity verdict, not part of it.
  var failed = (result.checks || []).filter(function (check) {
    return check.status === "fail" && !check.profile;
  }).length;
  var total = (result.checks || []).filter(function (check) {
    return !check.profile;
  }).length;
  var profile = result.profile;
  setText("vpv_profile_verdict", !profile ? "" : profile.conformant
    ? "HAIP 1.0: the answer conforms to every HAIP rule checked."
    : "HAIP 1.0: the answer VIOLATES HAIP in " + profile.violations +
      " place" + (profile.violations === 1 ? "" : "s") + " (the rows " +
      "marked \"HAIP 1.0\"). Everything else was checked as far as it " +
      "could be.", !profile ? "" : profile.conformant ? "vc-ok" : "vc-bad");
  // Three verdicts (#467, S4). "incomplete" is nothing failed AND an
  // essential check — an issuer proof, an x5c chain's anchor, a holder
  // signature — was not performed. It is not a pass and is not drawn as
  // one: the presentation's authenticity was never established.
  var verdict = result.verdict || (result.ok ? "pass" : "fail");
  if (verdict === "pass") {
    setText("vpv_verdict", "Every check passed (" + total + ").", "vc-ok");
  } else if (verdict === "incomplete") {
    setText("vpv_verdict", "Nothing failed, but " + result.incomplete +
      " essential check" + (result.incomplete === 1 ? "" : "s") +
      " could not be performed, so this presentation is NOT verified " +
      "(the rows marked SKIP that establish authenticity say why).",
      "vc-warn");
  } else {
    setText("vpv_verdict", failed + " of " + total + " checks failed.",
            "vc-bad");
  }
  var out = el("vpv_claims_out");
  if (out) {
    out.textContent = JSON.stringify(result.presentations || [], null, 2);
  }
  log.debug("Leaving renderChecks(). failed=" + failed);
}

// `contentType` is the media type the api recorded the answer as arriving
// in, which verifyResponse() holds to section 8.2; undefined for an answer
// that did not come through response_uri (pasted, or the DC API).
async function checkFields(fields, contentType) {
  log.debug("Entering checkFields().");
  if (!current) {
    setText("vpv_verdict", "There is no request on this page to check the " +
      "answer against. Create one first: the nonce, the state and the " +
      "client_id an answer is held to are this page's.", "vc-bad");
    log.debug("Leaving checkFields(). No request.");
    return null;
  }
  try {
    var result = await verifier.verifyResponse({
      fields: fields,
      session: Object.assign({}, current.session,
                             { trustAnchors: trustAnchorsFromPage(),
                               issuerBindings: issuerBindingsFromPage() }),
      fetchJson: fetchJson, fetchText: fetchText, contentType: contentType,
      now: Math.floor(Date.now() / 1000) });
    renderChecks(result);
    log.debug("Leaving checkFields(). ok=" + result.ok);
    return result;
  } catch (e) {
    setText("vpv_verdict", "The answer could not be checked: " + e.message,
            "vc-bad");
    log.debug("Leaving checkFields(). " + e.message);
    return null;
  }
}

async function checkPasted() {
  log.debug("Entering checkPasted().");
  var text = val("vpv_pasted").trim();
  var fields;
  try {
    fields = text.charAt(0) === "{" ? JSON.parse(text)
                                    : verifier.parseResponse(text).raw;
  } catch (e) {
    setText("vpv_verdict", "That is neither a form body nor JSON: " +
            e.message, "vc-bad");
    log.debug("Leaving checkPasted(). Unreadable.");
    return false;
  }
  await checkFields(fields || {});
  log.debug("Leaving checkPasted().");
  return false;
}

async function reset() {
  log.debug("Entering reset().");
  stopPolling();
  if (current && current.hosted) {
    try {
      await apiJson("DELETE", "/oid4vp/verifier/" + current.hosted.id,
                    undefined, current.hosted.secret);
    } catch (e) {
      log.debug("reset(): the api session was already gone — " + e.message);
    }
  }
  current = null;
  ["vpv_invocation", "vpv_client_id", "vpv_request_uri", "vpv_response_uri",
   "vpv_request_object", "vpv_root_pem", "vpv_trust_out"
  ].forEach(function (id) {
    setVal(id, "");
  });
  var link = el("vpv_invocation_link");
  if (link) {
    link.style.display = "none";
  }
  showQr("");
  setText("vpv_same_device_note", "");
  var list = el("vpv_events");
  if (list) {
    list.innerHTML = "";
  }
  clearVerdict();
  setText("vpv_wait_status", "No request yet.");
  setText("vpv_create_status", "Started over.");
  log.debug("Leaving reset().");
  return false;
}

// The current request, for tests/vc_verifier_page.js, which plays the wallet
// in node and has to know what it is answering. Read-only copies.
function currentRequest() {
  log.debug("Entering currentRequest().");
  if (!current) {
    log.debug("Leaving currentRequest(). None.");
    return null;
  }
  var copy = JSON.parse(JSON.stringify({
    session: Object.assign({}, current.session, { decryptionJwk: undefined }),
    hosted: current.hosted ? {
      id: current.hosted.id, requestUri: current.hosted.requestUri,
      responseUri: current.hosted.responseUri,
      caIssuersUrl: current.hosted.caIssuersUrl } : null,
    trust: current.signer ? current.signer.trust : "",
    invocation: val("vpv_invocation")
  }));
  log.debug("Leaving currentRequest().");
  return copy;
}

function onload() {
  log.debug("Entering onload().");
  loadState();
  showTypeLabel();
  // A DCQL the reader edited by hand is kept; one is generated only when
  // there is none.
  if (!val("vpv_dcql").trim()) {
    regenerateDcql();
  }
  settingsChanged();
  showIdentity();
  probeApi();
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  togglePane: togglePane,
  regenerateDcql: regenerateDcql,
  formatChanged: formatChanged,
  settingsChanged: settingsChanged,
  anchorsChanged: anchorsChanged,
  createRequest: createRequest,
  checkPasted: checkPasted,
  askThroughDcApi: askThroughDcApi,
  reset: reset,
  saveIdentityChanged: saveIdentityChanged,
  downloadIdentity: downloadIdentity,
  importIdentity: importIdentity,
  newIdentity: newIdentity,
  currentRequest: currentRequest,
  onload: onload
};
