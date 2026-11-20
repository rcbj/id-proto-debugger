// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_predicates_page.js
//
// ---------------------------------------------------------------------------
// vc-predicates.html (#474): compose a PREDICATE query ("prove age >= 18",
// not "show me your birth date"), see the AnonCreds presentation request it
// maps onto, send it to this debugger's wallet, and verify the presentation
// that comes back. The query language is vp_query.js's and the AnonCreds
// work anoncreds_wallet.js's; this file is the DOM.
//
// Two query languages, and the page labels which is standard:
//   * DIF Presentation Exchange 2.1.1 with its Predicate Feature, carried as
//     presentation_definition — the OpenID4VP DRAFTS' query, REMOVED in 1.0;
//   * DCQL with the debugger's NON-STANDARD predicate extension, honoured
//     only when the credential query marks it critical.
// And a raw AnonCreds presentation request (the AnonCreds specification's
// own object, where its predicates are standardized) can be read in,
// converted to either, or proven directly with the held credential.
//
// The answer comes back to THIS page: the request's response_mode is
// fragment and its redirect_uri this page (a redirect_uri: Client
// Identifier), so it works on a deployment with no api. What the page
// keeps is the composed request (vcpred_request) — no key, no secret.
// ---------------------------------------------------------------------------

var vpQuery = require("./vp_query");
var anoncredsWallet = require("./anoncreds_wallet");
var sdJwtVc = require("./sd_jwt_vc");
var cbytes = require("./crypto_bytes");
var provider = require("./crypto_provider");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_predicates_page",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var REQUEST_KEY = "vcpred_request";
var WALLET_URL = "/vc-presentation-1.html";

function el(id) {
  log.debug("Entering el(). " + id);
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function val(id) {
  log.debug("Entering val(). " + id);
  var e = el(id);
  log.debug("Leaving val().");
  return e ? String(e.value || "") : "";
}

function setVal(id, v) {
  log.debug("Entering setVal(). " + id);
  var e = el(id);
  if (e) e.value = v === undefined || v === null ? "" : v;
  log.debug("Leaving setVal().");
}

function setText(id, v) {
  log.debug("Entering setText(). " + id);
  var e = el(id);
  if (e) e.textContent = v === undefined || v === null ? "" : String(v);
  log.debug("Leaving setText().");
}

function setStatus(id, text, cls) {
  log.debug("Entering setStatus(). " + id);
  var e = el(id);
  if (e) {
    e.textContent = text;
    e.className = "vc-status " + (cls || "");
  }
  log.debug("Leaving setStatus().");
}

function pretty(v) {
  log.debug("Entering pretty().");
  log.debug("Leaving pretty().");
  return JSON.stringify(v, null, 2);
}

// A table of rows [label, value, kind, class], written as text.
function renderRows(id, rows) {
  log.debug("Entering renderRows(). " + id);
  var host = el(id);
  if (!host) {
    log.debug("Leaving renderRows(). No host.");
    return;
  }
  host.textContent = "";
  var table = document.createElement("table");
  table.className = "vc-table vcp-result";
  rows.forEach(function (r) {
    var tr = document.createElement("tr");
    var th = document.createElement("th");
    th.textContent = r[0];
    var td = document.createElement("td");
    if (r[2] === "pre") {
      var pre = document.createElement("pre");
      pre.textContent = r[1];
      td.appendChild(pre);
    } else {
      td.textContent = r[1];
    }
    if (r[3]) td.className = r[3];
    tr.appendChild(th);
    tr.appendChild(td);
    table.appendChild(tr);
  });
  host.appendChild(table);
  log.debug("Leaving renderRows().");
}

function togglePane(id) {
  log.debug("Entering togglePane(). " + id);
  var fs = el(id);
  if (fs) fs.style.display = fs.style.display === "none" ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

function splitList(text) {
  log.debug("Entering splitList().");
  log.debug("Leaving splitList().");
  return String(text || "").split(",").map(function (x) {
    return x.trim();
  }).filter(function (x) {
    return x;
  });
}

// "age >= 18" per line -> [{ name, p_type, p_value, mode }].
function readPredicateLines(text, mode) {
  log.debug("Entering readPredicateLines().");
  var out = [];
  String(text || "").split(/\n/).forEach(function (line, i) {
    var t = line.trim();
    if (!t) return;
    var m = /^(.+?)\s*(>=|<=|>|<)\s*(-?\d+)$/.exec(t);
    if (!m) {
      throw new Error("predicate line " + (i + 1) + " is not \"name op " +
                      "integer\" (op one of >= > <= <): " +
                      JSON.stringify(t));
    }
    out.push({ name: m[1].trim(), p_type: m[2], p_value: Number(m[3]),
               mode: mode || "required" });
  });
  log.debug("Leaving readPredicateLines(). " + out.length);
  return out;
}

// --- pane 1: compose --------------------------------------------------------

function composeSpec() {
  log.debug("Entering composeSpec().");
  var restrictions = [];
  if (val("vcp_cred_def_id").trim()) {
    restrictions.push({ cred_def_id: val("vcp_cred_def_id").trim() });
  }
  log.debug("Leaving composeSpec().");
  return { language: val("vcp_language") || "pe",
           id: val("vcp_query_id").trim() || "credential",
           format: val("vcp_format") || "anoncreds",
           reveal: splitList(val("vcp_reveal")),
           predicates: readPredicateLines(val("vcp_predicates"),
                                          val("vcp_mode")),
           restrictions: restrictions,
           purpose: val("vcp_purpose").trim() || undefined };
}

function onLanguage() {
  log.debug("Entering onLanguage().");
  var pe = val("vcp_language") === "pe";
  var row = el("vcp_mode_row");
  if (row) row.style.display = pe ? "" : "none";
  setText("vcp_language_note", pe ? vpQuery.LABEL_PE + ". DIF " +
    "Presentation Exchange " + vpQuery.PE_VERSION + "'s Predicate Feature " +
    "is standard; OpenID4VP 1.0 has no presentation_definition." :
    vpQuery.LABEL_EXT + ": OpenID4VP 1.0's DCQL has no predicates. The " +
    "predicates go in " + vpQuery.EXT_PREDICATES + ", never in claims, and " +
    "are honoured only because " + vpQuery.EXT_CRIT + " lists them; a " +
    "wallet that ignores the extension discloses nothing extra.");
  log.debug("Leaving onLanguage().");
  return true;
}

// Append "<attr> <= YYYYMMDD" for "at least N years old today".
function addAgeOver() {
  log.debug("Entering addAgeOver().");
  var years = Number(val("vcp_age_years"));
  var attr = val("vcp_age_attr").trim() || "birthdate_dateint";
  if (!Number.isInteger(years) || years < 0) {
    setStatus("vcp_compose_status", "Years must be a whole number.",
              "vc-bad");
    log.debug("Leaving addAgeOver(). Bad years.");
    return false;
  }
  var line = attr + " <= " + vpQuery.ageThresholdDateInt(years, new Date());
  var cur = val("vcp_predicates").trim();
  setVal("vcp_predicates", (cur ? cur + "\n" : "") + line);
  setStatus("vcp_compose_status", "Added " + line + ": born on or before " +
            "that day is at least " + years + " today (AnonCreds' YYYYMMDD " +
            "convention).", "vc-ok");
  log.debug("Leaving addAgeOver().");
  return false;
}

function buildQuery() {
  log.debug("Entering buildQuery().");
  try {
    var q = vpQuery.buildQuery(composeSpec());
    setVal("vcp_query", pretty(q.presentation_definition || q.dcql_query));
    setStatus("vcp_compose_status", "Built a " + (q.presentation_definition ?
      "presentation_definition (" + vpQuery.LABEL_PE + ")" : "dcql_query " +
      "with the " + vpQuery.LABEL_EXT) + ".", "vc-ok");
    showMapping();
  } catch (e) {
    setStatus("vcp_compose_status", "Could not build the query: " +
              e.message, "vc-bad");
  }
  log.debug("Leaving buildQuery().");
  return false;
}

// The query in the text box, read: { model, language, query }.
function currentQuery() {
  log.debug("Entering currentQuery().");
  var text = val("vcp_query").trim();
  if (!text) {
    log.debug("Leaving currentQuery(). Empty.");
    throw new Error("there is no query yet: build one, or read an " +
                    "AnonCreds request in.");
  }
  var obj = JSON.parse(text);
  var isPe = obj && obj.input_descriptors !== undefined;
  var model = vpQuery.normalise(isPe ? { presentation_definition: obj } :
                                { dcql_query: obj });
  log.debug("Leaving currentQuery(). " + model.language);
  return { model: model, language: model.language, query: obj };
}

// --- pane 2: the equivalent AnonCreds request -------------------------------

function showMapping() {
  log.debug("Entering showMapping().");
  try {
    var cur = currentQuery();
    var rows = [["Query language", cur.model.label || cur.language]];
    if (cur.model.errors.length) {
      rows.push(["Problems", cur.model.errors.join(" "), "", "vc-bad"]);
    }
    cur.model.items.forEach(function (item) {
      var plan = vpQuery.nominalPlan(item);
      var req = vpQuery.anoncredsRequestFor(plan, {
        nonce: anoncredsWallet.nonceFor(nonceValue()) });
      rows.push(["AnonCreds request for " + item.id, pretty(req), "pre"]);
      item.predicates.forEach(function (p) {
        rows.push(["Predicate " + p.id, vpQuery.describePredicate(
          p.attribute, p.ops) + " (" + p.mode + ")" + (p.ops.kind ===
          "range" ? "" : " — not a range, so AnonCreds cannot prove it")]);
      });
      if (item.extension && (item.extension.note || item.extension.refuse)) {
        rows.push(["Extension", item.extension.refuse ||
                   item.extension.note, "", item.extension.refuse ?
                   "vc-bad" : ""]);
      }
      Object.keys(vpQuery.FORMAT_PREDICATES).forEach(function (f) {
        if (item.formats.indexOf(f) !== -1) {
          rows.push(["How " + f + " proves it",
                     vpQuery.capabilityOf(f).how]);
        }
      });
    });
    renderRows("vcp_mapping", rows);
    setStatus("vcp_mapping_status", "The nonce is the OpenID4VP nonce " +
      "mapped to decimal digits (anoncreds_wallet.js nonceFor()).", "");
  } catch (e) {
    renderRows("vcp_mapping", []);
    setStatus("vcp_mapping_status", "No mapping: " + e.message, "vc-bad");
  }
  log.debug("Leaving showMapping().");
  return false;
}

// A raw AnonCreds presentation request, read and turned into a query in the
// chosen language.
function readAnoncredsRequest() {
  log.debug("Entering readAnoncredsRequest().");
  var read = vpQuery.readAnoncredsRequest(val("vcp_anoncreds_request"));
  if (read.errors.length) {
    setStatus("vcp_anoncreds_status", "Not an AnonCreds presentation " +
              "request: " + read.errors.join(" "), "vc-bad");
    log.debug("Leaving readAnoncredsRequest(). Invalid.");
    return false;
  }
  var conv = vpQuery.specFromAnoncredsRequest(read.request,
                                              val("vcp_language") || "pe");
  var q = vpQuery.buildQuery(conv.spec);
  setVal("vcp_query", pretty(q.presentation_definition || q.dcql_query));
  showMapping();
  setStatus("vcp_anoncreds_status", "Read: " + Object.keys(
    read.request.requested_attributes || {}).length + " attribute " +
    "referent(s), " + Object.keys(read.request.requested_predicates ||
    {}).length + " predicate(s), converted into the query above." +
    (conv.warnings.length ? " " + conv.warnings.join(" ") : ""),
    conv.warnings.length ? "vc-pending" : "vc-ok");
  log.debug("Leaving readAnoncredsRequest().");
  return false;
}

function heldBundle() {
  log.debug("Entering heldBundle().");
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!anoncredsWallet.looksLikeBundle(raw)) {
    log.debug("Leaving heldBundle(). None.");
    return null;
  }
  log.debug("Leaving heldBundle().");
  return anoncredsWallet.parseBundle(raw);
}

// Prove the raw AnonCreds request with the credential this browser holds,
// with no OpenID4VP around it: the AnonCreds specification's own exchange.
function proveRawRequest() {
  log.debug("Entering proveRawRequest().");
  try {
    var read = vpQuery.readAnoncredsRequest(val("vcp_anoncreds_request"));
    if (read.errors.length) throw new Error(read.errors.join(" "));
    var b = heldBundle();
    if (!b) {
      throw new Error("this browser holds no AnonCreds credential (issue " +
                      "one, or load a bundle in the issuance workflow).");
    }
    var ls = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
    var made = anoncredsWallet.presentRequest(b, read.request, ls);
    setVal("vcp_vp_token", pretty(made.presentation));
    setVal("vcp_submission", "");
    setVal("vcp_raw_mode", "1");
    setStatus("vcp_anoncreds_status", "Proven with the held credential: " +
      Object.keys(read.request.requested_predicates || {}).length +
      " predicate(s) in zero knowledge. Verify it below.", "vc-ok");
    verifyPresentation();
  } catch (e) {
    setStatus("vcp_anoncreds_status", "Could not prove it: " + e.message,
              "vc-bad");
  }
  log.debug("Leaving proveRawRequest().");
  return false;
}

// --- pane 3: send to the wallet ---------------------------------------------

function nonceValue() {
  log.debug("Entering nonceValue().");
  var n = val("vcp_nonce").trim();
  if (!n) {
    n = cbytes.bytesToB64u(provider.randomBytes(16));
    setVal("vcp_nonce", n);
  }
  log.debug("Leaving nonceValue().");
  return n;
}

function returnUrl() {
  log.debug("Entering returnUrl().");
  log.debug("Leaving returnUrl().");
  return window.location.origin + window.location.pathname;
}

// The Authorization Request: the query as dcql_query or (OpenID4VP drafts)
// presentation_definition, answered to this page by fragment.
function authorizationRequest() {
  log.debug("Entering authorizationRequest().");
  var cur = currentQuery();
  var target = returnUrl();
  var params = { client_id: "redirect_uri:" + target,
                 response_type: "vp_token", response_mode: "fragment",
                 redirect_uri: target, nonce: nonceValue(),
                 state: "vcpred-" + Date.now().toString(36) };
  if (cur.language === "pe") {
    params.presentation_definition = JSON.stringify(cur.query);
  } else {
    params.dcql_query = JSON.stringify(cur.query);
  }
  var meta = { vp_formats_supported: {} };
  meta[vpQuery.EXT_METADATA] = vpQuery.verifierMetadataExtension();
  params.client_metadata = JSON.stringify(meta);
  log.debug("Leaving authorizationRequest().");
  return { params: params, cur: cur };
}

function showRequest() {
  log.debug("Entering showRequest().");
  try {
    var r = authorizationRequest();
    setVal("vcp_request_uri", WALLET_URL + "?" +
           new URLSearchParams(r.params).toString());
    setStatus("vcp_send_status", "The request asks the wallet to answer " +
      "to this page (" + returnUrl() + ") in the URL fragment.", "vc-ok");
  } catch (e) {
    setStatus("vcp_send_status", e.message, "vc-bad");
  }
  log.debug("Leaving showRequest().");
  return false;
}

function sendToWallet() {
  log.debug("Entering sendToWallet().");
  try {
    var r = authorizationRequest();
    sdJwtVc.setJson(REQUEST_KEY, { query: r.cur.query,
      language: r.cur.language, nonce: r.params.nonce,
      state: r.params.state, clientId: r.params.client_id,
      sentAt: new Date().toISOString() });
    var url = WALLET_URL + "?" + new URLSearchParams(r.params).toString();
    setVal("vcp_request_uri", url);
    window.location.href = url;
  } catch (e) {
    setStatus("vcp_send_status", "Not sent: " + e.message, "vc-bad");
  }
  log.debug("Leaving sendToWallet().");
  return false;
}

// --- pane 4: inspect what came back -----------------------------------------

// The schema, credential definition and revocation material to verify
// with: the held bundle's, or a bundle pasted here.
function verificationMaterial() {
  log.debug("Entering verificationMaterial().");
  var text = val("vcp_bundle").trim();
  var b = text ? anoncredsWallet.parseBundle(text) : heldBundle();
  if (!b) {
    log.debug("Leaving verificationMaterial(). None.");
    throw new Error("verifying needs the issuer's schema and credential " +
                    "definition: paste a bundle, or hold the credential " +
                    "in this browser.");
  }
  var schemas = {};
  schemas[b.schemaId] = b.schema;
  var cds = {};
  cds[b.credDefId] = b.credentialDefinition;
  var revocation = anoncredsWallet.revocationOf(b);
  log.debug("Leaving verificationMaterial().");
  return { schemas: schemas, credentialDefinitions: cds,
           revocationRegistryDefinitions: revocation ?
             revocation.definitions : {},
           revocationStatusLists: revocation ? [revocation.list] : [] };
}

function verifyPresentation() {
  log.debug("Entering verifyPresentation().");
  var rows = [];
  var overall = true;
  try {
    var tokenText = val("vcp_vp_token").trim();
    if (!tokenText) throw new Error("paste a vp_token first.");
    var token = JSON.parse(tokenText);
    var material = verificationMaterial();
    var r;
    if (val("vcp_raw_mode") === "1") {
      var raw = vpQuery.readAnoncredsRequest(val("vcp_anoncreds_request"));
      r = anoncredsWallet.verifyForQuery(Object.assign({ presentation: token,
        request: raw.request }, material));
      rows.push(["Request", "the raw AnonCreds presentation request " +
                 "(no OpenID4VP)"]);
    } else {
      var stored = sdJwtVc.getJson(REQUEST_KEY) || {};
      var cur = currentQuery();
      var item = cur.model.items[0];
      var presentation = token;
      if (cur.language === "pe") {
        var sub = val("vcp_submission").trim();
        var check = vpQuery.checkSubmission(cur.model.read,
                                            sub ? JSON.parse(sub) : null,
                                            token);
        rows.push(["presentation_submission", check.ok ? "matches the " +
          "definition and the vp_token (" + check.answered.join(", ") +
          ")" : check.errors.join(" "), "", check.ok ? "vc-ok" : "vc-bad"]);
        overall = overall && check.ok;
        var entry = check.entries[0];
        if (entry) {
          item = cur.model.items.filter(function (it) {
            return it.id === entry.id;
          })[0] || item;
          presentation = entry.target;
        }
      } else {
        var list = token[item.id];
        if (!Array.isArray(list) || !list.length) {
          throw new Error("the vp_token answers no credential query \"" +
                          item.id + "\" (OpenID4VP 1.0 section 8.1).");
        }
        presentation = list[0];
      }
      r = anoncredsWallet.verifyForQuery(Object.assign({
        presentation: presentation, item: item,
        nonce: stored.nonce || val("vcp_nonce") }, material));
    }
    rows.push(["CL proof", r.valid ? "verifies under the request's nonce " +
      r.request.nonce : r.errors.join(" "), "", r.valid ? "vc-ok" :
      "vc-bad"]);
    overall = overall && r.valid;
    r.predicates.forEach(function (p) {
      var ok = p.answered && r.valid;
      overall = overall && ok;
      rows.push(["Predicate " + p.name + " " + p.p_type + " " + p.p_value,
        ok ? "PROVEN in zero knowledge (sub-proof " + p.subProofIndex +
        "); the value of " + p.name + " is not in the presentation." :
        "not proven.", "", ok ? "vc-ok" : "vc-bad"]);
    });
    rows.push(["Revealed", pretty(r.revealed), "pre"]);
    rows.push(["AnonCreds request checked against", pretty(r.request),
               "pre"]);
    renderRows("vcp_inspect_result", rows);
    setStatus("vcp_inspect_status", overall ? "Every check passed: " +
      r.predicates.length + " predicate(s) proven, " +
      Object.keys(r.revealed).length + " attribute(s) revealed." :
      "The presentation does not verify.", overall ? "vc-ok" : "vc-bad");
  } catch (e) {
    renderRows("vcp_inspect_result", rows);
    setStatus("vcp_inspect_status", "Could not verify: " + e.message,
              "vc-bad");
  }
  log.debug("Leaving verifyPresentation().");
  return false;
}

// An answer arriving in the fragment (response_mode fragment): loaded into
// the inspect pane and verified.
function readFragment() {
  log.debug("Entering readFragment().");
  var hash = String(window.location.hash || "").replace(/^#/, "");
  if (!hash) {
    log.debug("Leaving readFragment(). Nothing.");
    return false;
  }
  var p = new URLSearchParams(hash);
  if (p.get("error")) {
    setStatus("vcp_inspect_status", "The wallet refused: " + p.get("error") +
      (p.get("error_description") ? " — " + p.get("error_description") :
       ""), "vc-bad");
    log.debug("Leaving readFragment(). Error answer.");
    return true;
  }
  if (!p.get("vp_token")) {
    log.debug("Leaving readFragment(). No vp_token.");
    return false;
  }
  var stored = sdJwtVc.getJson(REQUEST_KEY);
  if (stored) {
    setVal("vcp_query", pretty(stored.query));
    setVal("vcp_nonce", stored.nonce);
    if (el("vcp_language")) el("vcp_language").value = stored.language;
    onLanguage();
    showMapping();
  }
  var state = p.get("state");
  var tokenText = p.get("vp_token");
  try {
    tokenText = pretty(JSON.parse(tokenText));
  } catch (e) {
    log.debug("readFragment(): the vp_token is not JSON: " + e.message);
  }
  setVal("vcp_vp_token", tokenText);
  setVal("vcp_submission", p.get("presentation_submission") ?
         pretty(JSON.parse(p.get("presentation_submission"))) : "");
  setVal("vcp_raw_mode", "");
  if (stored && state !== stored.state) {
    setStatus("vcp_inspect_status", "The answer's state is not the " +
              "request's: it answers some other request.", "vc-bad");
    log.debug("Leaving readFragment(). State mismatch.");
    return true;
  }
  verifyPresentation();
  log.debug("Leaving readFragment().");
  return true;
}

// --- pane 5: capability advertisement ---------------------------------------

function showCapabilities() {
  log.debug("Entering showCapabilities().");
  var w = {};
  w[vpQuery.EXT_METADATA] = vpQuery.walletMetadataExtension();
  var v = {};
  v[vpQuery.EXT_METADATA] = vpQuery.verifierMetadataExtension();
  setText("vcp_wallet_metadata", pretty(w));
  setText("vcp_verifier_metadata", pretty(v));
  log.debug("Leaving showCapabilities().");
}

function loadExample() {
  log.debug("Entering loadExample().");
  if (el("vcp_format")) el("vcp_format").value = "anoncreds";
  setVal("vcp_reveal", "name");
  setVal("vcp_predicates", "age >= 18");
  buildQuery();
  log.debug("Leaving loadExample().");
  return false;
}

function init() {
  log.debug("Entering init().");
  onLanguage();
  showCapabilities();
  nonceValue();
  if (!readFragment()) {
    if (!val("vcp_query")) loadExample();
    else showMapping();
  }
  log.debug("Leaving init().");
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}

module.exports = {
  togglePane: togglePane,
  onLanguage: onLanguage,
  addAgeOver: addAgeOver,
  buildQuery: buildQuery,
  showMapping: showMapping,
  readAnoncredsRequest: readAnoncredsRequest,
  proveRawRequest: proveRawRequest,
  showRequest: showRequest,
  sendToWallet: sendToWallet,
  verifyPresentation: verifyPresentation,
  loadExample: loadExample,
  readFragment: readFragment
};
