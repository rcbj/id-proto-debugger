// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_presentation_2.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC presentation, step 2: choose what to disclose, and present it.
//
// This is the page selective disclosure exists for. The credential in this
// wallet carries every claim the issuer put in it; the verifier asked for some
// of them; and what leaves this browser is the holder's choice — which the
// wallet makes visible before anything is sent:
//
//   * one checkbox per Disclosure, with the ones the DCQL query asked for
//     marked, the extras marked as over-disclosure, and the always-visible
//     claims shown as what they are: not optional, they travel with the
//     issuer-signed JWT;
//   * the presentation assembled from that choice —
//     <Issuer-signed JWT>~<selected Disclosures>~<KB-JWT>;
//   * the Key Binding JWT itself, decoded: typ kb+jwt, this request's nonce,
//     the verifier's Client Identifier as aud, and sd_hash over exactly the
//     bytes
//     above (RFC 9901 section 4.3);
//   * the whole HTTP call, because with response_mode=direct_post the wallet is
//     the one making the request.
//
// Nothing is sent until Present is pressed, and Refuse is a first-class answer:
// OID4VP section 8.4 gives the wallet access_denied for exactly this.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");
var bbs2023 = require("./bbs2023");
// RDFC-1.0 for the holder's VP proof when the Verifier accepts only an RDFC
// suite or a legacy proof type (#475); loading it registers the
// canonicalizer with data_integrity.js, which vp_protocols.js signs through.
require("./data_integrity_rdfc");
var vcFormats = require("./vc_formats");
var didLib = require("./did");
var vpProtocols = require("./vp_protocols");
var cbor = require("./cbor");

var log = bunyan.createLogger({ name: 'vc_presentation_2',
                                level: appconfig.logLevel });

// What this page is working with.
var state = {
  request: null,
  dcql: null,
  credentialQuery: null,
  requested: [],
  credential: "",
  parsed: null,
  // The Disclosures, in credential order: { encoded, name, value, requested, checked }
  rows: [],
  built: null,
  // The answer around the presentation: { fields, idToken, encryption,
  // delivery }, rebuilt with it.
  response: null
};

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
function setText(id, text) {
  log.debug("Entering setText().");
  var e = el(id);
  if (e) e.textContent = (text == null ? "" : String(text));
  log.debug("Leaving setText().");
}
function setHtml(id, html) {
  log.debug("Entering setHtml().");
  var e = el(id);
  if (e) e.innerHTML = html;
  log.debug("Leaving setHtml().");
}
function setValue(id, v) {
  log.debug("Entering setValue().");
  var e = el(id);
  if (e) e.value = (v == null ? "" : v);
  log.debug("Leaving setValue().");
}
function setJson(id, value) {
  log.debug("Entering setJson().");
  var e = el(id);
  if (e) e.textContent = (value === undefined || value === null) ?
      "—" : JSON.stringify(value, null, 2);
  log.debug("Leaving setJson().");
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
function disable(id, off) {
  log.debug("Entering disable().");
  var e = el(id);
  if (e) e.disabled = !!off;
  log.debug("Leaving disable().");
}

// --- what there is to disclose ----------------------------------------------
function loadState() {
  log.debug("Entering loadState().");
  state.request = sdJwtVp.storedRequest();
  var params = (state.request && state.request.params) || {};
  state.dcql = sdJwtVp.requestObjectValue(params, "dcql_query") ||
               (state.request && state.request.dcql) || null;
  state.credentialQuery = sdJwtVp.dcqlCredentialQueries(state.dcql)[0] || null;
  state.requested = sdJwtVp.requestedClaims(state.dcql);
  state.credential = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  state.parsed = null;
  if (state.credential) {
    try {
      state.parsed = sdJwtVc.parseCredential(state.credential);
    } catch (e) {
      log.error("the stored credential could not be parsed: " + e.message);
    }
  }
  // Every Disclosure the credential carries, with whether this verifier asked
  // for it. The default choice is exactly what was asked for and nothing else —
  // a wallet should not have to be told to minimise.
  var previously = sdJwtVc.getJson(sdJwtVp.KEYS.SELECTED);
  // jwt_vc_json has no Disclosures, so there are no rows and nothing to choose:
  // the credential goes whole or not at all. That is a property of the format,
  // not an empty table, and renderDisclosures() says so. The format to present
  // in is the one the VERIFIER ASKED FOR, not the one the wallet happens to
  // hold. Reading it off the credential was silently wrong in one direction:
  // the wallet built whatever shape it had, the verifier parsed whatever shape
  // it requested, and when they differed the refusal named the symptom instead
  // of the cause — a dc+sd-jwt verifier splitting an ldp_vc JSON object on "~",
  // finding one part, and reporting a malformed presentation.
  //
  // held is kept separately because the MISMATCH is the thing worth saying out
  // loud; collapsing the two loses the ability to explain it.
  state.heldFormat = (state.parsed && state.parsed.format) || "";
  state.requestedFormat = sdJwtVp.firstCredentialQueryFormat(state.dcql);
  // With no format in the query there is nothing to disagree with, so the held
  // credential is the only sensible reading — and defaulting to dc+sd-jwt when
  // nothing is held preserves what this line did before.
  state.format = state.requestedFormat || state.heldFormat ||
      sdJwtVc.FORMAT_SD_JWT;
  // A wallet cannot answer a query for one format with a credential in another.
  // Recorded rather than thrown so the pane can explain it and disable Present,
  // which is the difference between a wallet that says why and one that sends
  // something the verifier cannot read.
  state.formatMismatch = !!(state.requestedFormat && state.heldFormat &&
                            state.requestedFormat !== state.heldFormat);
  state.selectable = state.format !== sdJwtVc.FORMAT_JWT_VC_JSON &&
      !ldpWhole();
  // SIOPv2: whether an ID Token is asked for, and whether it is ALL that is.
  state.wantsIdToken = vpProtocols.asksForIdToken(params);
  state.idTokenOnly = state.wantsIdToken && !vpProtocols.asksForVpToken(params);
  state.rows = ((state.parsed && state.parsed.disclosures) ||
      []).map(function (d) {
    var requested = state.requested.indexOf(d.name) !== -1;
    return {
      encoded: d.encoded,
      name: d.error ? "(unreadable)" : (d.arrayElement ?
          "(array element)" : d.name),
      value: d.value,
      error: d.error,
      requested: requested,
      checked: Object.prototype.toString.call(previously) === "[object Array]"
        ? previously.indexOf(d.encoded) !== -1
        : requested
    };
  });
  log.debug("Leaving loadState(). " + state.rows.length + " Disclosure(s), " +
            state.requested.length + " requested.");
}

// An ldp_vc whose proof is NOT selective (eddsa-rdfc-2022, ecdsa-jcs-2019,
// Ed25519Signature2020, ...): presented whole inside the holder's VP, the way
// a jwt_vc_json is, rather than derived from as a bbs-2023 one is (#475).
function ldpWhole() {
  log.debug("Entering ldpWhole().");
  var whole = state.format === sdJwtVc.FORMAT_LDP_VC && !!state.parsed &&
    state.parsed.format === sdJwtVc.FORMAT_LDP_VC && !state.parsed.ldpSelective;
  log.debug("Leaving ldpWhole(). " + whole);
  return whole;
}

function selectedEncoded() {
  log.debug("Entering selectedEncoded().");
  log.debug("Leaving selectedEncoded().");
  return state.rows.filter(function (r) { return r.checked; })
                           .map(function (r) { return r.encoded; });
}

// ldp_vc selects over canonical STATEMENTS, so what a row identifies is an
// index into the statement list rather than an encoded Disclosure.
function selectedStatementIndexes() {
  log.debug("Entering selectedStatementIndexes().");
  log.debug("Leaving selectedStatementIndexes().");
  return state.rows.filter(function (r) { return r.checked; })
    .map(function (r) { return r.statementIndex; });
}

// Canonicalizing is async and loadState() is not, so the statements are fetched
// once here and the panes re-rendered when they arrive. Until then the table
// says it is working rather than showing an empty selection the holder might
// take for "this credential reveals nothing".
function prepareLdpStatements() {
  log.debug("Entering prepareLdpStatements().");
  var doc = (state.parsed && state.parsed.document) || null;
  if (!doc) {
    log.debug("Leaving prepareLdpStatements().");
    return Promise.resolve(false);
  }
  var body = Object.assign({}, doc);
  delete body.proof;
  log.debug("Leaving prepareLdpStatements().");
  return bbs2023.canonicalizedStatements(body).then(function (statements) {
    state.statements = statements;
    // Default to the statements that mention a requested claim. The claim names
    // come from DCQL; a statement is an N-Quad, so the match is on the
    // predicate IRI's local name, which is what the context maps those claims
    // to.
    state.rows = statements.map(function (line, i) {
      var wanted = state.requested.some(function (name) {
        var leaf = String(name).split(".").pop();
        return line.indexOf("/" + leaf) !== -1 || line.indexOf("#" +
                            leaf) !== -1 ||
               new RegExp(leaf.replace(/_(\w)/g, function (m,
                          c) { return c.toUpperCase(); }))
                 .test(line);
      });
      return { statementIndex: i, name: "statement " + (i + 1),
              value: line.trim(),
               requested: wanted, checked: wanted, encoded: "", error: "" };
    });
    // A requested claim whose value is an OBJECT (credentialStatus) matched
    // only the statement linking to it; what the object says is in the
    // statements about the node at the far end, so those come too.
    var named = state.rows.filter(function (r) { return r.requested; })
      .map(function (r) { return r.statementIndex; });
    bbs2023.withDescribedNodes(statements, named).forEach(function (i) {
      state.rows[i].requested = true;
      state.rows[i].checked = true;
    });
    // A presentation bound to its holder has to SAY who the holder is: the
    // statement linking the credential to its credentialSubject names the
    // holder's DID, and without it the holder's proof is a signature by a key
    // the credential never mentions. Selected whenever the query requires
    // holder binding (DCQL's default) or a SIOPv2 ID Token goes with it.
    if (sdJwtVp.requiresKeyBinding(state.credentialQuery) ||
        state.wantsIdToken) {
      state.rows.forEach(function (r) {
        if (/[#/]credentialSubject>/.test(r.value)) {
          r.requested = true;
          r.checked = true;
        }
      });
    }
    log.debug("Leaving prepareLdpStatements(). " + statements.length +
              " statement(s).");
    return true;
  }).catch(function (e) {
    // jsonld wraps a document loader's refusal in an error of its own whose
    // message is generic ("Dereferencing a URL did not result in a valid
    // JSON-LD object..."); the loader's reason — which context, and where to
    // supply it — is its details.cause. Both are shown.
    var cause = e && e.details && e.details.cause;
    var why = e.message + (cause && cause.message ? " — " + cause.message
                                                 : "");
    // WARN, not error: this is a credential the wallet cannot process yet —
    // typically an issuer's context nobody has supplied — and it is reported
    // to the person on the status line with what to do. An error-level line
    // would be a console error on a page that is behaving correctly.
    log.warn("could not canonicalize the credential: " + why);
    status("vp_present_status", "This credential could not be canonicalized, " +
           "so no bbs-2023 proof can " +
      "be derived from it: " + why, "vc-bad");
    return false;
  });
}

// The claims that travel whatever the holder chooses: they are in the
// issuer-signed JWT itself, not in a Disclosure, so they cannot be withheld
// without breaking the signature.
function alwaysVisibleClaims() {
  log.debug("Entering alwaysVisibleClaims().");
  var payload = (state.parsed && state.parsed.payload) || {};
  var out = {};
  Object.keys(payload).forEach(function (k) {
    if (["_sd", "_sd_alg"].indexOf(k) !== -1) return;
    out[k] = payload[k];
  });
  log.debug("Leaving alwaysVisibleClaims().");
  return out;
}

function renderDisclosureTable() {
  log.debug("Entering renderDisclosureTable().");
  var rows = state.rows.map(function (r, i) {
    var valueText = (r.value === undefined) ? "" :
      (typeof r.value === "object" ? JSON.stringify(r.value) : String(r.value));
    var flag = r.requested
      ? '<span class="vc-ok">asked for</span>'
      : '<span class="vc-bad">not asked for</span>';
    return "<tr>" +
      '<td><input type="checkbox" id="vp_disclose_' + i + '"' + (r.checked ?
          ' checked="checked"' : '') +
      ' onchange="return vcpresentation2.onSelectionChange(' + i +
          ', this.checked);" /></td>' +
      "<td>" + esc(r.name) + "</td>" +
      "<td>" + esc(valueText) + "</td>" +
      "<td>" + flag + "</td>" +
      '<td class="vc-mono">' + esc(String(r.encoded).slice(0, 24) + "…") +
          "</td>" +
      "</tr>";
  }).join("");
  // With no Disclosures the table would render as an empty box, which reads as
  // a credential that carries nothing. Show what will actually be sent instead,
  // and say why none of it can be withheld.
  if (state.format === sdJwtVc.FORMAT_LDP_VC && !ldpWhole()) {
    var stmts = state.rows || [];
    setHtml("vp_disclosures_table",
      "<thead><tr><th style='width:6%'>Send</th><th " +
          "style='width:8%'>#</th><th>Canonical statement " +
      "(N-Quad)</th><th style='width:16%'>This " +
          "verifier</th></tr></thead><tbody>" +
      (stmts.length
        ? stmts.map(function (r, i) {
            return "<tr>" +
              '<td><input type="checkbox" id="vp_disclose_' + i + '"' +
              (r.checked ? ' checked="checked"' : "") +
              ' onchange="return vcpresentation2.onSelectionChange(' + i +
                  ', this.checked);" /></td>' +
              "<td>" + (r.statementIndex + 1) + "</td>" +
              '<td class="vc-mono">' + esc(r.value) + "</td>" +
              "<td>" + (r.requested ? '<span class="vc-ok">asked for</span>'
                                    : '<span class="vc-bad">not asked ' +
                                        'for</span>') + "</td></tr>";
          }).join("")
        : "<tr><td colspan='4'>Canonicalizing the credential…</td></tr>") +
      "</tbody>");
    var chosen = stmts.filter(function (r) { return r.checked; }).length;
    setHtml("vp_selection_summary",
      '<span class="vc-status vc-pending">This credential is ' +
          '<code>ldp_vc</code> with a ' +
      '<code>bbs-2023</code> proof, so the unit of disclosure is the ' +
          'canonical STATEMENT, not a claim: ' +
      "these " + stmts.length +
          " statements are what the issuer actually signed, and " + chosen +
      " will be sent. The count will not match the number of claims — one " +
          "claim can be several " +
      "statements. Each presentation derives a FRESH proof, so two " +
          "presentations of this credential " +
      "cannot be linked to each other.</span>");
    log.debug("Leaving renderDisclosures(). ldp_vc — " + stmts.length +
              " statement(s).");
    log.debug("Leaving renderDisclosureTable().");
    return;
  }
  if (!state.selectable) {
    var claims = (state.parsed && state.parsed.claims) || {};
    var names = Object.keys(claims);
    setHtml("vp_disclosures_table",
      "<thead><tr><th style='width:22%'>Claim</th><th>Value</th><th " +
          "style='width:18%'>This verifier</th>" +
      "</tr></thead><tbody>" +
      (names.length
        ? names.map(function (name) {
            var v = claims[name];
            return "<tr><td>" + esc(name) + "</td><td>" +
              esc(typeof v === "object" ? JSON.stringify(v) : String(v)) +
                  "</td><td>" +
              (state.requested.indexOf(name) !== -1
                ? '<span class="vc-ok">asked for</span>'
                : '<span class="vc-bad">not asked for</span>') + "</td></tr>";
          }).join("")
        : "<tr><td colspan='3'>This credential carries no claims.</td></tr>") +
      "</tbody>");
    var what = ldpWhole() ? "ldp_vc secured with " +
        esc(state.parsed.ldpSuite) : "jwt_vc_json";
    setHtml("vp_selection_summary",
      '<span class="vc-status vc-pending">This credential is ' + what +
          ', which has no selective ' +
      'disclosure: all ' + names.length +
          ' claim(s) above are sent, including any this verifier did not ' +
      'ask for. Withholding one would mean asking the issuer for a different ' +
          'credential.</span>');
    log.debug("Leaving renderDisclosures(). " + what + " — " + names.length +
              " claim(s), none selectable.");
    log.debug("Leaving renderDisclosureTable().");
    return;
  }
  setHtml("vp_disclosures_table",
    "<thead><tr><th style='width:6%'>Send</th><th " +
        "style='width:16%'>Claim</th><th style='width:34%'>Value</th>" +
    "<th style='width:16%'>This " +
        "verifier</th><th>Disclosure</th></tr></thead><tbody>" + rows +
        "</tbody>");

  var missing = state.requested.filter(function (name) {
    return !state.rows.some(function (r) { return r.name === name &&
                            r.checked; }) &&
           !(name in alwaysVisibleClaims());
  });
  var extra = state.rows.filter(function (r) { return r.checked &&
      !r.requested; })
                        .map(function (r) { return r.name; });
  setHtml("vp_selection_summary",
    "Selected " + selectedEncoded().length + " of " + state.rows.length +
        (state.format === sdJwtVc.FORMAT_MSO_MDOC ?
         " mdoc element(s) (namespace/element). " : " Disclosure(s). ") +
    (missing.length
      ? '<span class="vc-bad">Not selected, though the verifier ' +
          'asked for it: ' + esc(missing.join(", ")) +
        " — the presentation will be refused without it.</span> "
      : '<span class="vc-ok">Everything the verifier asked for is ' +
          'selected.</span> ') +
    (extra.length
      ? '<span class="vc-bad">Also sending ' + esc(extra.join(", ")) +
        ", which was not asked for: that is over-disclosure, and the point of this format is to avoid it.</span>"
      : ""));
  log.debug("Leaving renderDisclosureTable(). missing=" + missing.length +
            ", extra=" + extra.length);
  return missing.length === 0;
}

// ---------------------------------------------------------------------------
// Building the presentation, up front, so what Present sends is on the screen
// before it is sent — the same principle step 2 of the issuance workflow
// follows.
// ---------------------------------------------------------------------------
function buildPresentation() {
  log.debug("Entering buildPresentation().");
  var params = (state.request && state.request.params) || {};
  // The key the credential is actually bound to, chosen by matching its own
  // cnf.jwk rather than by assuming the holder key: under Holder of Key
  // (issuance step 2's DPoP pane) the credential is bound to the DPoP key, and
  // signing with the holder key would produce a presentation the verifier
  // refuses for a reason that reads as a broken wallet. Falls back to the
  // pasted field when holder-key saving is off.
  var holderKey = sdJwtVc.boundPrivateJwk(credentialCnfJwk(),
      "vp_holder_private_jwk");
  var priv = holderKey.jwk;
  renderHolderKeyRow(holderKey);
  // A self-issued ID Token alone presents no credential: there is nothing to
  // select or derive, only the token to sign.
  if (state.idTokenOnly) {
    state.built = null;
    setValue("vp_presentation", "");
    setValue("vp_kb_jwt", "");
    setJson("vp_kb_header", null);
    setJson("vp_kb_payload", null);
    setJson("vp_presented_claims", null);
    log.debug("Leaving buildPresentation(). ID Token only.");
    return finishResponse();
  }
  if (!state.parsed || !params.client_id || !params.nonce) {
    setValue("vp_presentation", "");
    setValue("vp_kb_jwt", "");
    setJson("vp_kb_header", null);
    setJson("vp_kb_payload", null);
    setValue("vp_assembled_call", "");
    status("vp_present_status",
      "There is not enough here to build a presentation: a request with a " +
          "nonce and a client_id, plus a " +
      "credential in this wallet.", "vc-bad");
    log.debug("Leaving buildPresentation(). Not enough state.");
    return Promise.resolve(false);
  }
  // Refused here rather than at the verifier. Building anyway produces a
  // presentation in the wrong shape, and the verifier's complaint is about
  // parsing ("this has 1 part(s)") rather than about the wallet having nothing
  // it was asked for — which sends the reader looking for a bug in the
  // serialization instead of at the credential in hand.
  if (state.formatMismatch) {
    setValue("vp_presentation", "");
    setValue("vp_kb_jwt", "");
    setJson("vp_kb_header", null);
    setJson("vp_kb_payload", null);
    setValue("vp_assembled_call", "");
    status("vp_present_status",
      "This verifier asked for a " + state.requestedFormat +
          " credential and this wallet holds a " +
      state.heldFormat + " one. A presentation cannot change a credential's " +
          "format: the two are " +
      "different artifacts, secured differently — " + state.heldFormat +
          " cannot be reshaped into " +
      state.requestedFormat + ". Issue a " + state.requestedFormat +
          " credential in the issuance " +
      "workflow, or start a presentation from a verifier that asks for " +
          state.heldFormat + ".",
      "vc-bad");
    log.debug("Leaving buildPresentation(). Format mismatch: asked for " +
              state.requestedFormat +
              ", holding " + state.heldFormat + ".");
    return Promise.resolve(false);
  }
  if (ldpWhole()) {
    // The whole credential, exactly as the issuer signed it: its proof covers
    // every statement, so nothing can be left out without breaking it. The
    // holder's VP around it is added by finishResponse().
    var doc = state.parsed.document;
    state.built = { presentation: JSON.stringify(doc), vpElement: doc,
                    format: sdJwtVc.FORMAT_LDP_VC };
    setValue("vp_presentation", state.built.presentation);
    setText("vp_sd_hash", "");
    setValue("vp_kb_jwt", "");
    setJson("vp_kb_header", null);
    setJson("vp_kb_payload", null);
    setJson("vp_presented_claims", state.parsed.claims);
    status("vp_present_status", "The whole " + state.parsed.ldpSuite +
           " credential goes, inside the holder's Verifiable Presentation.",
           "vc-ok");
    log.debug("Leaving buildPresentation(). ldp_vc, whole.");
    return finishResponse();
  }
  if (state.format === sdJwtVc.FORMAT_LDP_VC) {
    // No holder private key is needed: the BBS derived proof IS the holder's
    // act.
    //
    // Canonicalization is async, and onload calls this once before it finishes.
    // That first call has no statements and no issuer key, so it returns
    // quietly rather than deriving from nothing — attempting it logged an error
    // on every load, which is both noise and a console error the suite fails
    // on.
    if (!state.statements || !state.issuerBbsKey) {
      status("vp_present_status",
        "Canonicalizing the credential so its statements can be chosen…",
            "vc-pending");
      log.debug("Leaving buildPresentation(). ldp_vc not canonicalized yet.");
      return Promise.resolve(false);
    }
    var chosenIdx = selectedStatementIndexes();
    log.debug("Leaving buildPresentation().");
    return bbs2023.deriveProof(state.parsed.document, state.issuerBbsKey,
                               chosenIdx,
                               new TextEncoder().encode(params.nonce))
      .then(function (derived) {
        // What travels. A bbs-2023 presentation must carry more than the proof:
        // the verifier needs the statements being disclosed and their indexes
        // to check the proof at all, and the issuer's proof options to rebuild
        // the header the base proof was bound to. Sent as one JSON object; see
        // the shape note in the STS's verifyLdpVc().
        var proofOptions =
            Object.assign({ "@context": state.parsed.document["@context"] },
                                         state.parsed.document.proof || {});
        delete proofOptions.proofValue;
        var envelope = {
          cryptosuite: "bbs-2023",
          proof: bbs2023.bytesToB64u(derived.proof),
          disclosedIndexes: derived.disclosedIndexes,
          disclosedStatements: derived.disclosedStatements,
          proofOptions: proofOptions
        };
        state.built = { presentation: JSON.stringify(envelope),
            vpElement: envelope, derived: derived,
            format: sdJwtVc.FORMAT_LDP_VC };
        setValue("vp_presentation", state.built.presentation);
        setText("vp_sd_hash", "");
        setValue("vp_kb_jwt", "");
        setJson("vp_kb_header", { cryptosuite: "bbs-2023",
                disclosed: derived.disclosedIndexes.length,
                                  of: derived.statements.length });
        setJson("vp_kb_payload", derived.disclosedStatements);
        setJson("vp_presented_claims", derived.disclosedStatements);
        status("vp_present_status", "Derived a bbs-2023 proof disclosing " +
          derived.disclosedIndexes.length + " of " + derived.statements.length +
              " statements.", "vc-ok");
        log.debug("Leaving buildPresentation(). bbs-2023 proof derived.");
        return finishResponse();
      })
      .catch(function (e) {
        log.error("could not derive the bbs-2023 proof: " + e.message);
        status("vp_present_status", "Could not derive the proof: " + e.message,
               "vc-bad");
        return false;
      });
  }
  var keyBinding = sdJwtVp.requiresKeyBinding(state.credentialQuery);
  if (keyBinding && !priv) {
    status("vp_present_status",
      "This verifier requires a holder proof, but the private half of the " +
          "holder key is not available, " +
      "so no Key Binding JWT can be signed." +
      (holderKey.problem ? " " + holderKey.problem.charAt(0).toUpperCase() +
       holderKey.problem.slice(1) + "."
                         : " Paste it into the Holder private key field " +
                             "above, or turn saving back on " +
                           "for a future credential on issuance step 2."),
                               "vc-bad");
    log.debug("Leaving buildPresentation(). No holder key.");
    return Promise.resolve(false);
  }
  log.debug("Leaving buildPresentation().");
  return sdJwtVp.buildPresentationFor({
    credential: state.credential,
    parsed: state.parsed,
    selected: selectedEncoded(),
    holderPrivateJwk: priv,
    aud: params.client_id,
    nonce: params.nonce,
    keyBinding: keyBinding,
    // An mdoc's device signature covers the session transcript, which names
    // where the answer goes and, under direct_post.jwt, the key it is
    // encrypted to (OpenID4VP 1.0 Appendix B.2.6.1).
    responseUri: vpProtocols.responseTarget(params),
    encryptionJwk: responseEncryptionKey()
  }).then(function (built) {
    state.built = built;
    setValue("vp_presentation", built.presentation);
    setText("vp_sd_hash", built.sdHash);
    if (built.vp) {
      // A jwt_vc_json presentation has no Key Binding JWT; the Verifiable
      // Presentation JWT does that job, so it is shown in the same place rather
      // than leaving the pane blank.
      setValue("vp_kb_jwt", built.vp.jwt);
      setJson("vp_kb_header", built.vp.header);
      setJson("vp_kb_payload", built.vp.payload);
    } else if (built.mdoc) {
      // An mdoc's holder proof is its device signature, over the session
      // transcript: shown where a KB-JWT would be.
      setValue("vp_kb_jwt", "");
      setJson("vp_kb_header", { deviceAuth: "deviceSignature",
        cose: "COSE_Sign1, ES256 (-7), detached",
        signedOver: "DeviceAuthenticationBytes",
        disclosed: built.mdoc.disclosed.map(function (it) {
          return it.namespace + "/" + it.elementIdentifier;
        }) });
      setJson("vp_kb_payload", { SessionTranscript:
        cbor.toPlain(built.mdoc.transcript) });
    } else if (built.kb) {
      setValue("vp_kb_jwt", built.kb.jwt);
      setJson("vp_kb_header", built.kb.header);
      setJson("vp_kb_payload", built.kb.payload);
    } else {
      setValue("vp_kb_jwt", "");
      setJson("vp_kb_header", null);
      setJson("vp_kb_payload", null);
    }
    // What a verifier will end up knowing, computed from the bytes being sent.
    var presented = sdJwtVp.presentedClaims(built.presentation);
    setJson("vp_presented_claims", presented.claims);
    log.debug("Leaving buildPresentation(). Built " +
              built.presentation.length + " characters.");
    return finishResponse();
  }).catch(function (e) {
    log.error("could not build the presentation: " + e.message);
    status("vp_present_status", "Could not build the presentation: " +
           e.message, "vc-bad");
    return false;
  });
}

// ---------------------------------------------------------------------------
// The ANSWER around the presentation, as the chosen protocol and the request's
// response_mode make it (vp_protocols.js):
//
//   * an ldp_vc credential bound to its holder travels inside a W3C
//     VerifiablePresentation with the holder's own Data Integrity proof —
//     whenever the query requires holder binding, which is DCQL's default, and
//     always beside a SIOPv2 ID Token, which has to name the same key;
//   * a SIOPv2 request gets a self-issued ID Token, signed by the key the
//     credential is bound to (or, alone, by a pairwise key if chosen);
//   * direct_post.jwt encrypts the lot to the Verifier's key, and the
//     delivery is worked out once so Present does exactly what is shown.
// ---------------------------------------------------------------------------

// The private key a presentation's holder proof — and a SIOPv2 ID Token
// beside it — is signed with, for whichever format is held.
function holderSigningKey() {
  log.debug("Entering holderSigningKey().");
  var cnf = credentialCnfJwk();
  if (!cnf && state.parsed && state.parsed.format === sdJwtVc.FORMAT_LDP_VC) {
    var subject = ldpHolderDid();
    if (/^did:jwk:/.test(subject)) {
      cnf = didLib.didJwkToJwk(subject);
    } else if (/^did:key:/.test(subject)) {
      cnf = didLib.didKeyToJwk(subject);
    }
  }
  log.debug("Leaving holderSigningKey().");
  return sdJwtVc.boundPrivateJwk(cnf, "vp_holder_private_jwk");
}

// The DID an ldp_vc names its subject by: who the holder is, for the VP.
function ldpHolderDid() {
  log.debug("Entering ldpHolderDid().");
  var doc = (state.parsed && state.parsed.document) || {};
  var subject = [].concat(doc.credentialSubject || [])[0] || {};
  log.debug("Leaving ldpHolderDid().");
  return String(subject.id || "");
}

// Whether an ldp_vc goes inside a holder-signed VP.
function ldpNeedsHolderProof() {
  log.debug("Entering ldpNeedsHolderProof().");
  var needs = !!state.built && state.built.format === sdJwtVc.FORMAT_LDP_VC &&
    (sdJwtVp.requiresKeyBinding(state.credentialQuery) || state.wantsIdToken);
  log.debug("Leaving ldpNeedsHolderProof(). " + needs);
  return needs;
}

function wrapLdpForHolder() {
  log.debug("Entering wrapLdpForHolder().");
  var params = (state.request && state.request.params) || {};
  if (!ldpNeedsHolderProof()) {
    log.debug("Leaving wrapLdpForHolder(). Not needed.");
    return Promise.resolve(true);
  }
  var holder = ldpHolderDid();
  var key = holderSigningKey();
  if (!holder || !key.jwk) {
    status("vp_present_status", "This request needs a holder proof around " +
      "the ldp_vc presentation, and " + (holder ? "the private key of " +
      holder + " is not available" + (key.problem ? ": " + key.problem : "") :
      "the credential names no credentialSubject.id to be the holder") + ".",
      "vc-bad");
    log.debug("Leaving wrapLdpForHolder(). No holder key.");
    return Promise.resolve(false);
  }
  log.debug("Leaving wrapLdpForHolder().");
  return vpProtocols.ldpVerifiablePresentation({
    credential: state.built.vpElement,
    holder: holder,
    privateJwk: key.jwk,
    nonce: params.nonce,
    aud: params.client_id,
    // The suite is the one this key signs that the Verifier said it accepts
    // (vc_formats.holderSuiteFor()), so nobody has to pick a valid pair.
    accepts: verifierLdpAccepts()
  }).then(function (vp) {
    state.built.envelope = state.built.vpElement;
    state.built.vpElement = vp;
    state.built.presentation = JSON.stringify(vp);
    setValue("vp_presentation", state.built.presentation);
    setJson("vp_kb_header", vp.proof);
    log.debug("Leaving wrapLdpForHolder(). Wrapped.");
    return true;
  }).catch(function (e) {
    status("vp_present_status", "Could not sign the holder's Verifiable " +
           "Presentation: " + e.message, "vc-bad");
    log.debug("Leaving wrapLdpForHolder(). " + e.message);
    return false;
  });
}

// What the Verifier said it accepts for ldp_vc: client_metadata's
// vp_formats_supported (OpenID4VP 1.0 section 11.1), which may name
// cryptosuite_values and proof_type_values. Empty when it said nothing.
function verifierLdpAccepts() {
  log.debug("Entering verifierLdpAccepts().");
  var meta = (state.request && state.request.clientMetadata) || {};
  var formats = meta.vp_formats_supported || meta.vp_formats || {};
  log.debug("Leaving verifierLdpAccepts().");
  return formats[sdJwtVc.FORMAT_LDP_VC] || {};
}

// The pairwise key for this Verifier: made the first time, then reused so the
// person is the same subject to it next time and a different one to every
// other Verifier. Kept unless the holder said not to.
function pairwiseKey(clientId) {
  log.debug("Entering pairwiseKey().");
  var keep = sdJwtVc.get(sdJwtVp.KEYS.SIOP_SAVE_PAIRWISE) !== "0";
  var all = (keep && sdJwtVc.getJson(sdJwtVp.KEYS.SIOP_PAIRWISE_KEYS)) || {};
  if (all[clientId]) {
    log.debug("Leaving pairwiseKey(). Reused.");
    return Promise.resolve(all[clientId]);
  }
  if (state.pairwiseThisLoad && state.pairwiseThisLoad[clientId]) {
    log.debug("Leaving pairwiseKey(). This page load's.");
    return Promise.resolve(state.pairwiseThisLoad[clientId]);
  }
  log.debug("Leaving pairwiseKey(). New.");
  return vpProtocols.generateSubjectKey().then(function (jwk) {
    state.pairwiseThisLoad = state.pairwiseThisLoad || {};
    state.pairwiseThisLoad[clientId] = jwk;
    if (keep) {
      all[clientId] = jwk;
      sdJwtVc.setJson(sdJwtVp.KEYS.SIOP_PAIRWISE_KEYS, all);
    }
    return jwk;
  });
}

// The ID Token's key: the credential's holder key beside a presentation (the
// two must name the same key, or the identity and the credential are about
// two different people), and for an ID Token alone the holder key or a
// pairwise one, as chosen.
function idTokenKey() {
  log.debug("Entering idTokenKey().");
  var params = (state.request && state.request.params) || {};
  var pairwise = el("vp_siop_pairwise");
  if (state.idTokenOnly && pairwise && pairwise.checked) {
    log.debug("Leaving idTokenKey(). Pairwise.");
    return pairwiseKey(params.client_id).then(function (jwk) {
      return { jwk: jwk, boundTo: "a pairwise key for " + params.client_id };
    });
  }
  var key = holderSigningKey();
  if (!key.jwk && state.idTokenOnly) {
    // No credential and no holder key: a pairwise key is the only subject
    // this wallet has.
    log.debug("Leaving idTokenKey(). Pairwise, for want of a holder key.");
    return pairwiseKey(params.client_id).then(function (jwk) {
      return { jwk: jwk, boundTo: "a pairwise key for " + params.client_id +
               " (this wallet holds no holder key)" };
    });
  }
  log.debug("Leaving idTokenKey().");
  return Promise.resolve(key);
}

function chosenSubjectSyntax() {
  log.debug("Entering chosenSubjectSyntax().");
  var select = el("vp_subject_syntax");
  var preferred = (select && select.value) ||
      sdJwtVc.get(sdJwtVp.KEYS.SIOP_SUBJECT_SYNTAX) || "";
  log.debug("Leaving chosenSubjectSyntax().");
  return vpProtocols.chooseSubjectSyntax(
      state.request && state.request.clientMetadata, preferred);
}

function buildIdToken() {
  log.debug("Entering buildIdToken().");
  var params = (state.request && state.request.params) || {};
  if (!state.wantsIdToken) {
    setValue("vp_id_token", "");
    setJson("vp_id_token_header", null);
    setJson("vp_id_token_payload", null);
    log.debug("Leaving buildIdToken(). Not asked for.");
    return Promise.resolve(null);
  }
  var syntax = chosenSubjectSyntax();
  if (!syntax) {
    log.debug("Leaving buildIdToken(). No common subject syntax.");
    return Promise.reject(new Error("the Verifier accepts no subject " +
        "syntax this wallet can make, so the only answer is " +
        "subject_syntax_types_not_supported (Refuse sends it)."));
  }
  log.debug("Leaving buildIdToken().");
  return idTokenKey().then(function (key) {
    if (!key.jwk) {
      throw new Error("there is no key to sign the self-issued ID Token " +
        "with" + (key.problem ? ": " + key.problem : "."));
    }
    return vpProtocols.selfIssuedIdToken({
      privateJwk: key.jwk, syntax: syntax, aud: params.client_id,
      nonce: params.nonce
    }).then(function (t) {
      t.boundTo = key.boundTo;
      setValue("vp_id_token", t.jwt);
      setJson("vp_id_token_header", t.header);
      setJson("vp_id_token_payload", t.payload);
      setText("vp_id_token_note", "Signed with " + (key.boundTo ||
        "the holder key") + ", as a " + syntax + " subject. It proves " +
        "control of that key and nothing else: every claim in it is the " +
        "person's own say-so.");
      log.debug("Leaving buildIdToken(). " + t.payload.sub);
      return t;
    });
  });
}

function finishResponse() {
  log.debug("Entering finishResponse().");
  var params = (state.request && state.request.params) || {};
  var built = null;
  log.debug("Leaving finishResponse().");
  return wrapLdpForHolder().then(function (ok) {
    if (!ok) {
      return false;
    }
    built = state.built;
    return buildIdToken().then(function (idToken) {
      var vpToken = built ? sdJwtVp.vpToken(
          sdJwtVp.firstCredentialQueryId(state.dcql),
          built.vpElement || built.presentation) : null;
      var fields = vpProtocols.responseFields({
        vpToken: vpToken, idToken: idToken ? idToken.jwt : "",
        state: params.state });
      setJson("vp_vp_token", vpToken);
      var mode = vpProtocols.responseMode(params);
      var encrypting = mode === "direct_post.jwt" ?
        vpProtocols.encryptResponse({ fields: fields,
          clientMetadata: state.request.clientMetadata,
          key: responseEncryptionKey(),
          enc: (el("vp_response_enc") || {}).value }) :
        Promise.resolve(null);
      return encrypting.then(function (encryption) {
        var delivery = vpProtocols.deliveryFor(params, fields, encryption);
        state.response = { fields: fields, idToken: idToken,
                           encryption: encryption, delivery: delivery };
        renderEncryption(encryption);
        setValue("vp_assembled_call", vpProtocols.describeDelivery(delivery));
        return true;
      });
    });
  }).catch(function (e) {
    state.response = null;
    log.warn("could not finish the response: " + e.message);
    status("vp_present_status", "Could not build the answer: " + e.message,
           "vc-bad");
    setValue("vp_assembled_call", "");
    return false;
  });
}

function renderEncryption(encryption) {
  log.debug("Entering renderEncryption().");
  var row = el("vp_encryption_pane");
  if (row) row.style.display = encryption ? "" : "none";
  if (encryption) {
    setJson("vp_jwe_header", encryption.header);
    setValue("vp_jwe", encryption.jwe);
    setText("vp_jwe_note", "Encrypted " + encryption.header.alg + " / " +
      (encryption.enc || "no enc (HPKE Integrated Encryption)") +
      " to the Verifier's key " + (encryption.key.kid ||
      "(no kid)") + " from client_metadata.jwks. Only that Verifier can " +
      "read what is above; anybody on the way sees this.");
  }
  log.debug("Leaving renderEncryption().");
}

// The Verifier key a direct_post.jwt answer is encrypted to, or null. One
// choice, made here, because an mdoc's device signature names it and the
// encryption must then use the same key.
function responseEncryptionKey() {
  log.debug("Entering responseEncryptionKey().");
  var params = (state.request && state.request.params) || {};
  if (vpProtocols.responseMode(params) !== "direct_post.jwt") {
    log.debug("Leaving responseEncryptionKey(). Not encrypted.");
    return null;
  }
  var keys = vpProtocols.encryptionKeys(state.request.clientMetadata,
                                        keySelection());
  log.debug("Leaving responseEncryptionKey(). " + keys.length + " key(s).");
  return keys[0] || null;
}

// How a Verifier key is chosen (#312): the first one this wallet can use, in
// the Verifier's order — under HAIP only ECDH-ES P-256, and for an mdoc only
// a key with an RFC 7638 thumbprint, since the session transcript names it.
function keySelection() {
  log.debug("Entering keySelection().");
  log.debug("Leaving keySelection().");
  return { protocol: sdJwtVp.currentProtocol().id,
           needsThumbprint: state.format === "mso_mdoc" };
}

// Kept for the name: every caller that used to draw the call now finishes the
// whole answer.
function renderAssembledCall() {
  log.debug("Entering renderAssembledCall().");
  log.debug("Leaving renderAssembledCall().");
  return finishResponse();
}

function onSelectionChange(index, checked) {
  log.debug("Entering onSelectionChange(). index=" + index + ", checked=" +
            checked);
  if (state.rows[index]) state.rows[index].checked = !!checked;
  sdJwtVc.setJson(sdJwtVp.KEYS.SELECTED, selectedEncoded());
  var complete = renderDisclosureTable();
  buildPresentation().then(function (ok) {
    if (ok) {
      status("vp_present_status", complete
        ? "Ready: what is shown below is exactly what will be sent."
        : "Ready, but the selection is missing a claim the verifier asked " +
            "for — it will refuse this.",
        complete ? "vc-ok" : "vc-pending");
    }
  });
  log.debug("Leaving onSelectionChange().");
  return true;
}

function selectRequestedOnly() {
  log.debug("Entering selectRequestedOnly().");
  state.rows.forEach(function (r) { r.checked = r.requested; });
  sdJwtVc.setJson(sdJwtVp.KEYS.SELECTED, selectedEncoded());
  renderDisclosureTable();
  buildPresentation().then(function () {
    status("vp_present_status",
      "Selection reset to exactly what the verifier asked for — the minimum " +
          "that answers this request.",
      "vc-ok");
  });
  log.debug("Leaving selectRequestedOnly().");
  return false;
}

function selectAll() {
  log.debug("Entering selectAll().");
  state.rows.forEach(function (r) { r.checked = true; });
  sdJwtVc.setJson(sdJwtVp.KEYS.SELECTED, selectedEncoded());
  renderDisclosureTable();
  buildPresentation().then(function () {
    status("vp_present_status",
      "Every Disclosure selected. This is what a credential format without " +
          "selective disclosure would force " +
      "on you, and you can see how much more it is than the verifier " +
          "asked for.", "vc-pending");
  });
  log.debug("Leaving selectAll().");
  return false;
}

// --- sending it -------------------------------------------------------------
// Send `delivery` the way it says: the wallet POSTs it, the browser posts it
// as a form, or the browser is redirected with it. Answers a promise of
// { ok, statusCode, body, raw } for a POST, and never settles for the other
// two, because the page is navigating away.
function deliver(delivery) {
  log.debug("Entering deliver(). " + delivery.kind + " " + delivery.mode);
  if (delivery.kind === "redirect") {
    log.debug("Leaving deliver(). Redirecting.");
    window.location.href = delivery.url;
    return new Promise(function () {});
  }
  if (delivery.kind === "form") {
    var form = document.createElement("form");
    form.method = "POST";
    form.action = delivery.target;
    Object.keys(delivery.fields).forEach(function (k) {
      var input = document.createElement("input");
      var v = delivery.fields[k];
      input.type = "hidden";
      input.name = k;
      input.value = typeof v === "string" ? v : JSON.stringify(v);
      form.appendChild(input);
    });
    document.body.appendChild(form);
    log.debug("Leaving deliver(). Submitting the form.");
    form.submit();
    return new Promise(function () {});
  }
  log.debug("Leaving deliver(). POST.");
  // Straight from the browser, or through the debugger's api when step 0
  // says so (sd_jwt_vp.js verifierFetch()).
  return sdJwtVp.verifierFetch(delivery.target, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: delivery.body
  }).then(function (r) {
    return r.text().then(function (text) {
      var parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch (e) {
        // Not JSON: the raw text is what gets shown.
      }
      return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
    });
  });
}

// What step 3 shows, written BEFORE anything is sent: a redirect or a form
// post leaves this page and does not come back to write it afterwards.
function recordSent(response) {
  log.debug("Entering recordSent().");
  var params = (state.request && state.request.params) || {};
  var built = state.built || {};
  var r = state.response || {};
  var record = {
    protocol: sdJwtVp.currentProtocol().id,
    responseType: params.response_type || "",
    responseMode: vpProtocols.responseMode(params),
    delivery: r.delivery ? r.delivery.kind : "",
    // How the wallet reached the Verifier: from this page, or through the
    // debugger's api (POST /oid4vp/call). A browser-carried answer (fragment,
    // query, form_post) is always the browser's.
    route: r.delivery && r.delivery.kind === "post" && sdJwtVp.viaApi() ?
        "api" : "browser",
    presentation: built.presentation || "",
    format: built.format || state.format || "",
    kbJwt: built.kb ? built.kb.jwt : "",
    kbPayload: built.kb ? built.kb.payload : null,
    sdHash: built.sdHash || "",
    selected: selectedEncoded(),
    requested: state.idTokenOnly ? [] : state.requested,
    idToken: r.idToken ? r.idToken.jwt : "",
    idTokenPayload: r.idToken ? r.idToken.payload : null,
    idTokenHeader: r.idToken ? r.idToken.header : null,
    idTokenSyntax: r.idToken ? r.idToken.syntax : "",
    encryption: r.encryption ? { header: r.encryption.header,
      enc: r.encryption.enc, kid: r.encryption.key.kid || "",
      plaintext: r.encryption.plaintext, jwe: r.encryption.jwe } : null,
    holderBinding: built.envelope ? "VerifiablePresentation, " +
      vcFormats.ldpSuiteOf((built.vpElement || {}).proof) : "",
    sentAt: new Date().toISOString(),
    responseUri: r.delivery ? r.delivery.target : "",
    // The public key the answer was encrypted to: an mdoc's device signature
    // names it, so step 3 needs it to re-check that signature.
    encryptionJwk: r.encryption ? r.encryption.key : null,
    clientId: params.client_id,
    nonce: params.nonce,
    state: params.state || "",
    accepted: response ? !!response.ok : null,
    statusCode: response ? response.statusCode : 0,
    response: response ? (response.body || response.raw) :
      "(handed to the browser: " + (r.delivery ? r.delivery.mode : "") +
      " — the Verifier's answer is whatever page it shows next)"
  };
  sdJwtVc.setJson(sdJwtVp.KEYS.PRESENTATION, record);
  log.debug("Leaving recordSent().");
  return record;
}

function present() {
  log.debug("Entering present().");
  if (!state.response || !state.response.delivery) {
    status("vp_present_status", "There is no answer built yet.", "vc-bad");
    log.debug("Leaving present().");
    return false;
  }
  var delivery = state.response.delivery;
  if (!delivery.target) {
    status("vp_present_status", "The request names nowhere to send the " +
           "answer (" + delivery.mode + ").", "vc-bad");
    log.debug("Leaving present().");
    return false;
  }
  disable("vp_present_button", true);
  status("vp_present_status", "Answering " + delivery.target + " by " +
         delivery.mode + " …", "vc-pending");
  recordSent(null);
  deliver(delivery)
    .then(function (response) {
      var box = el("vp_response_body");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null,
            2) : response.raw;
      }
      // Whatever the verifier said, the wallet keeps a record of what it sent:
      // step 3 shows both sides.
      recordSent(response);
      if (!response.ok) {
        var err = (response.body && (response.body.error_description ||
            response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vp_present_status",
          "The verifier refused the response: " + err +
              " Step 3 shows what it answered.",
          "vc-bad");
        disable("vp_present_button", false);
        window.setTimeout(function () { window.location.href =
                          sdJwtVp.STEP3_URL; }, 1500);
        return;
      }
      status("vp_present_status",
             "The verifier accepted the response. Opening step 3 …",
             "vc-ok");
      window.location.href = sdJwtVp.STEP3_URL;
    })
    .catch(function (e) {
      log.error("the response could not be sent: " + e.message);
      status("vp_present_status", "The response could not be sent: " +
             e.message, "vc-bad");
      disable("vp_present_button", false);
    });
  log.debug("Leaving present().");
  return false;
}

// Refusing is an answer, and both protocols have one: OpenID4VP's
// access_denied (section 8.5) and SIOPv2's user_cancelled — or
// subject_syntax_types_not_supported, when the wallet cannot make a subject
// the Verifier accepts. It goes back the way an answer would, encrypted
// under direct_post.jwt.
function refuse() {
  log.debug("Entering refuse().");
  var params = (state.request && state.request.params) || {};
  if (!vpProtocols.responseTarget(params)) {
    status("vp_present_status",
      "Nothing was sent. There is nowhere to tell the verifier you " +
          "declined, either.", "vc-pending");
    log.debug("Leaving refuse().");
    return false;
  }
  disable("vp_refuse_button", true);
  var reason = state.wantsIdToken && !chosenSubjectSyntax() ?
      "subject_syntax" : "declined";
  var fields = vpProtocols.refusalFields(params, reason);
  var mode = vpProtocols.responseMode(params);
  var encrypting = mode === "direct_post.jwt" &&
      vpProtocols.encryptionKeys(state.request.clientMetadata,
                                 keySelection()).length ?
    vpProtocols.encryptResponse({ fields: fields,
      clientMetadata: state.request.clientMetadata,
      key: responseEncryptionKey() }) :
    Promise.resolve(null);
  encrypting
    .then(function (encryption) {
      var delivery = vpProtocols.deliveryFor(params, fields, encryption);
      if (mode === "direct_post.jwt" && !encryption) {
        delivery = vpProtocols.deliveryFor(
          Object.assign({}, params, { response_mode: "direct_post" }),
          fields, null);
      }
      return deliver(delivery);
    })
    .then(function () {
      status("vp_present_status",
        "Refused. " + fields.error + " was sent to the verifier and no " +
            "part of the credential left this browser.",
        "vc-pending");
    })
    .catch(function (e) {
      status("vp_present_status",
        "Refused. Nothing was disclosed; telling the verifier failed (" +
            e.message + "), which changes " +
        "nothing about what it knows.", "vc-pending");
    });
  log.debug("Leaving refuse().");
  return false;
}

// The SIOPv2 and encryption controls change the answer, not the
// presentation, so they rebuild the answer only.
function onAnswerOptionChange() {
  log.debug("Entering onAnswerOptionChange().");
  var select = el("vp_subject_syntax");
  if (select && select.value) {
    sdJwtVc.set(sdJwtVp.KEYS.SIOP_SUBJECT_SYNTAX, select.value);
  }
  var save = el("vp_siop_save_pairwise");
  if (save) {
    sdJwtVc.set(sdJwtVp.KEYS.SIOP_SAVE_PAIRWISE, save.checked ? "1" : "0");
    // An opt-out that leaves yesterday's private keys in storage is not an
    // opt-out.
    if (!save.checked) sdJwtVc.remove(sdJwtVp.KEYS.SIOP_PAIRWISE_KEYS);
  }
  finishResponse().then(function (ok) {
    if (ok) {
      status("vp_present_status", "Ready: what is shown below is exactly " +
             "what will be sent.", "vc-ok");
    }
  });
  log.debug("Leaving onAnswerOptionChange().");
  return true;
}

// The SIOPv2 and response-encryption panes, drawn for the request in hand.
function renderAnswerOptions() {
  log.debug("Entering renderAnswerOptions().");
  var params = (state.request && state.request.params) || {};
  var siopPane = el("vp_siop_pane");
  if (siopPane) siopPane.style.display = state.wantsIdToken ? "" : "none";
  var select = el("vp_subject_syntax");
  if (select) {
    var offered = vpProtocols.subjectSyntaxesOffered(
        state.request && state.request.clientMetadata);
    var both = vpProtocols.SUBJECT_SYNTAXES.filter(function (x) {
      return offered.indexOf(x) !== -1;
    });
    var chosen = chosenSubjectSyntax();
    select.innerHTML = both.map(function (x) {
      return '<option value="' + esc(x) + '"' + (x === chosen ?
             ' selected="selected"' : "") + ">" + esc(x) + "</option>";
    }).join("") || '<option value="">(none in common)</option>';
    setText("vp_subject_offered", offered.join(", "));
  }
  var pairRow = el("vp_siop_pairwise_row");
  if (pairRow) pairRow.style.display = state.idTokenOnly ? "" : "none";
  var save = el("vp_siop_save_pairwise");
  if (save) {
    save.checked = sdJwtVc.get(sdJwtVp.KEYS.SIOP_SAVE_PAIRWISE) !== "0";
  }
  var enc = el("vp_response_enc");
  if (enc) {
    var encs = vpProtocols.encValues(state.request &&
                                     state.request.clientMetadata);
    enc.innerHTML = encs.map(function (x) {
      return '<option value="' + esc(x) + '">' + esc(x) + "</option>";
    }).join("");
  }
  var encPane = el("vp_encryption_pane");
  if (encPane) {
    encPane.style.display = vpProtocols.responseMode(params) ===
        "direct_post.jwt" ? "" : "none";
  }
  log.debug("Leaving renderAnswerOptions().");
}

// ---------------------------------------------------------------------------
// The JSON-LD contexts pane. bbs2023.js ships only the standard contexts and
// this project's own; an issuer's vocabulary is supplied here, and kept in
// this browser. Adding one RELOADS the page, because canonicalization happens
// on load and a context added after it changes what the statements are.
// ---------------------------------------------------------------------------
function renderSuppliedContexts() {
  log.debug("Entering renderSuppliedContexts().");
  var supplied = bbs2023.suppliedContexts();
  var urls = Object.keys(supplied).sort();
  var rows = urls.length
    ? urls.map(function (url) {
      return '<tr><td><code>' + esc(url) + '</code></td><td>' +
        '<input class="btn2" type="button" value="Remove" ' +
        'data-context-url="' + esc(url) + '" ' +
        'onclick="return vcpresentation2.removeSuppliedContext(' +
        'this.getAttribute(\'data-context-url\'));" /></td></tr>';
    }).join('')
    : '<tr><td>None added. The standard W3C credentials contexts are ' +
      'built in.</td></tr>';
  var table = el("vp_contexts_list");
  if (table) {
    setHtml("vp_contexts_list", '<tbody>' + rows + '</tbody>');
  }
  log.debug("Leaving renderSuppliedContexts(). " + urls.length + ".");
}

function addSuppliedContext() {
  log.debug("Entering addSuppliedContext().");
  var url = (el("vp_context_url") || {}).value || "";
  var text = (el("vp_context_json") || {}).value || "";
  try {
    var added = bbs2023.addContext(url, text);
    status("vp_context_status", "Added " + added + ". Reloading so the " +
           "credential is canonicalized with it…", "vc-ok");
    renderSuppliedContexts();
    setTimeout(function () {
      window.location.reload();
    }, 300);
  } catch (e) {
    log.warn("addSuppliedContext(): " + e.message);
    status("vp_context_status", e.message, "vc-bad");
  }
  log.debug("Leaving addSuppliedContext().");
  return false;
}

function removeSuppliedContext(url) {
  log.debug("Entering removeSuppliedContext(). " + url);
  bbs2023.removeContext(url);
  renderSuppliedContexts();
  status("vp_context_status", "Removed " + url + ".", "vc-ok");
  log.debug("Leaving removeSuppliedContext().");
  return false;
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

// The paste-in row only appears when there is nothing in storage to sign with:
// with saving on it would be a field asking for something the page already has.
// The DPoP note, filled from the credential in hand rather than written into
// the markup, because the interesting half is conditional: a credential issued
// under Holder of Key is bound to the wallet's DPoP key, and THAT is the key
// this page signs the Key Binding JWT with. A static note could not say so. The
// cnf.jwk of the credential in hand.
//
// Read from the credential rather than from `state.parsed`, because
// state.parsed is the parse of a credential in the context of a verifier's
// REQUEST and is empty until one has arrived — while this note is about the
// credential, which is there either way. Sourcing it from state.parsed made the
// pane describe a wallet with no credential whenever the page was opened
// directly, which is exactly how it is opened when somebody wants to know what
// they are holding.
function credentialCnfJwk() {
  log.debug("Entering credentialCnfJwk().");
  var fromRequest = (state.parsed && state.parsed.payload &&
      state.parsed.payload.cnf &&
                     state.parsed.payload.cnf.jwk) || null;
  if (fromRequest) {
    log.debug("Leaving credentialCnfJwk(). From the parsed request context.");
    return fromRequest;
  }
  var held = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!held) {
    log.debug("Leaving credentialCnfJwk(). No credential is held.");
    return null;
  }
  var parsed = null;
  try {
    parsed = sdJwtVc.parseCredential(held);
  } catch (e) {
    // An unparseable credential is a state the other panes already report; this
    // note simply has nothing to add about its key binding.
    log.debug("credentialCnfJwk(): the held credential could not be parsed: " +
              e.message);
    log.debug("Leaving credentialCnfJwk().");
    return null;
  }
  // payload, not claims: `cnf` is a claim of the ISSUER-SIGNED JWT, while
  // parsed.claims is the disclosed claim set. jwt_vc_json and ldp_vc carry no
  // cnf at all — their holder binding is the credentialSubject's id — so null
  // here is a legitimate answer rather than a failure.
  var payload = (parsed && parsed.payload) || {};
  log.debug("Leaving credentialCnfJwk(). From the held credential. bound=" +
            (payload.cnf && payload.cnf.jwk ? "yes" : "no"));
  return (payload.cnf && payload.cnf.jwk) || null;
}

function renderDpopNote() {
  log.debug("Entering renderDpopNote().");
  var e = document.getElementById("vp_dpop_note");
  if (!e) {
    log.debug("Leaving renderDpopNote().");
    return;
  }
  var cnfJwk = credentialCnfJwk();
  var lines = [
    "OpenID4VP defines no DPoP: this exchange produces a Verifiable " +
        "Presentation rather than an " +
    "access token, so there is no token to sender-constrain. The wallet's " +
        "proof of possession " +
    "here is the Key Binding JWT below."
  ];
  if (!cnfJwk) {
    lines.push("This credential carries no cnf.jwk, so it has no key binding " +
               "at all and no " +
               "Key Binding JWT is required.");
  } else {
    var dpopPublic = sdJwtVc.getJson(sdJwtVc.KEYS.DPOP_PUBLIC_JWK);
    if (dpopPublic && sdJwtVc.samePublicKey(dpopPublic, cnfJwk)) {
      lines.push("This credential was issued under Holder of Key: its " +
                 "cnf.jwk IS this wallet's " +
                 "DPoP key, so the same key that sender-constrains the " +
                     "access token on the " +
                 "issuance side signs the Key Binding JWT here. One key, two " +
                     "mechanisms.");
    } else {
      lines.push("This credential is bound to a holder key of its own (Proof " +
                 "of Possession), " +
                 "which is independent of any DPoP key used during issuance " +
                     "\u2014 so it stays " +
                 "presentable even if that DPoP key is gone.");
    }
  }
  e.textContent = lines.join(" ");
  log.debug("Leaving renderDpopNote().");
}

function renderHolderKeyRow(holderKey) {
  log.debug("Entering renderHolderKeyRow().");
  renderDpopNote();
  var row = document.getElementById("vp_holder_key_row");
  var note = document.getElementById("vp_holder_key_note");
  if (!row) {
    log.debug("Leaving renderHolderKeyRow().");
    return;
  }
  var needed = (holderKey.source !== "storage");
  row.style.display = needed ? "" : "none";
  if (!note) {
    log.debug("Leaving renderHolderKeyRow().");
    return;
  }
  if (!needed) {
    // Which key it is matters now that there can be two: under Holder of Key
    // the credential is bound to the DPoP key, and a reader who does not know
    // which key signed the Key Binding JWT cannot tell a correct presentation
    // from a lucky one.
    note.textContent = holderKey.boundTo
      ? "Signing with " + holderKey.boundTo +
          ", which is the key this credential's cnf.jwk names."
      : "";
  } else if (holderKey.problem) {
    note.textContent = holderKey.problem;
  } else if (holderKey.jwk) {
    note.textContent = "Using the key pasted here. It is not stored.";
  } else {
    note.textContent = "Not in this browser's storage — paste the key pair you downloaded on issuance step 2.";
  }
  log.debug("Leaving renderHolderKeyRow().");
}

// Rebuild as the key is typed/pasted, so the presentation appears the moment a
// usable key is present rather than after some other interaction.
function onHolderKeyPasted() {
  log.debug("Entering onHolderKeyPasted().");
  buildPresentation();
  log.debug("Leaving onHolderKeyPasted().");
  return false;
}

function onload() {
  log.debug("Entering onload().");
  sdJwtVp.renderUseCaseBadge();
  var step = document.getElementById("vp_step_2");
  if (step) step.className = "vc-step-current";
  ["vp_step_0", "vp_step_1"].forEach(function (id) {
    var e = document.getElementById(id);
    if (e) e.className = "vc-step-done";
  });

  loadState();
  // The DPoP note describes the credential in hand, so it is rendered here
  // rather than only from renderHolderKeyRow(): buildPresentation() returns
  // early when there is no verifier request, and a wallet holding a credential
  // should still be able to see which key binds it.
  renderDpopNote();
  renderSuppliedContexts();
  // ldp_vc needs its canonical statements before anything can be selected or
  // derived, and that is async. The issuer's BBS key is fetched from the
  // credential's own verificationMethod — the credential says where its key is.
  if (state.format === sdJwtVc.FORMAT_LDP_VC && !ldpWhole()) {
    var vm = ((state.parsed.document || {}).proof || {}).verificationMethod ||
        "";
    // Resolved rather than fetched, because a verificationMethod is not always
    // a URL that can be fetched: an issuer named by DID names its key by DID
    // URL (did:web:…#bbs-1), and fetch() on that reports the issuer's key as
    // unreachable — which reads as a broken issuer rather than as a wallet that
    // cannot follow a DID. did.js handles both forms.
    didLib.resolveVerificationMethod(vm,
        // allowHttp PERMITS plain http rather than choosing it: resolve()
        // tries https first and falls back. See did.js.
        { allowHttp: true }).then(function (resolved) {
      var multibase = resolved.method.publicKeyMultibase;
      if (!multibase) {
        throw new Error("the verification method " + vm +
                        " publishes no publicKeyMultibase, so there " +
                        "is no BBS key in it. A BBS key has no JOSE " +
                            "representation and cannot arrive " +
                        "as a publicKeyJwk.");
      }
      state.issuerBbsKey = bbs2023.multibaseToBytes(multibase);
      return prepareLdpStatements();
    }).then(function (prepared) {
      // NOT on a failure. prepareLdpStatements() has already said why on the
      // status line; building now would find no statements and replace that
      // reason with "Canonicalizing the credential…", which is what a
      // credential the wallet cannot canonicalize used to look like — a step
      // that never finished, rather than one that refused.
      if (prepared === false) {
        return;
      }
      renderDisclosureTable();
      buildPresentation();
    }).catch(function (e) {
      log.error("could not prepare the ldp_vc presentation: " + e.message);
      // Two different failures arrive here, and the message has to say which:
      // the issuer's key could not be resolved, or the credential could not
      // be canonicalized — which, for a context nobody supplied, is fixed in
      // the JSON-LD Contexts pane rather than at the issuer.
      status("vp_present_status", state.issuerBbsKey
        ? "Could not canonicalize the credential: " + e.message
        : "Could not resolve the issuer's BBS key from " + vm + ": " +
          e.message,
             "vc-bad");
    });
  }
  // Show the paste-in row from the start when there is no stored private half:
  // buildPresentation() also renders it, but it returns early when there is not
  // enough state yet, which is exactly the case where the user most needs to be
  // told the key is missing and given somewhere to put it.
  renderHolderKeyRow(sdJwtVc.boundPrivateJwk(credentialCnfJwk(),
                     "vp_holder_private_jwk"));
  var params = (state.request && state.request.params) || {};
  setText("vp_verifier", params.client_id || "—");
  setText("vp_nonce", params.nonce || "—");
  setText("vp_requested", state.requested.length ?
          state.requested.join(", ") : "—");
  if (state.format === sdJwtVc.FORMAT_JWT_VC_JSON) {
    setText("vp_key_binding",
      "This credential is jwt_vc_json, so holder binding is a Verifiable " +
          "Presentation JWT signed with the " +
      "bound key — there is no Key Binding JWT, and no Disclosures to " +
          "choose between.");
  } else if (state.format === sdJwtVc.FORMAT_MSO_MDOC) {
    setText("vp_key_binding",
      "This credential is an ISO mdoc, so holder binding is the device " +
      "signature: a COSE_Sign1 by the device key the Mobile Security " +
      "Object names, over a session transcript binding this Verifier's " +
      "client_id, the nonce, where the answer goes and, encrypted, the key " +
      "it is encrypted to. There is no Key Binding JWT.");
  } else
  setText("vp_key_binding", sdJwtVp.requiresKeyBinding(state.credentialQuery)
    ? "required — the presentation carries a Key Binding JWT signed by the holder key"
    : "not required by this verifier, so the presentation may go without a " +
        "holder proof");
  setJson("vp_always_visible", alwaysVisibleClaims());

  if (!state.request) {
    status("vp_present_status",
      "There is no request to answer. Step 1 reads one from the verifier.",
          "vc-bad");
    log.debug("Leaving onload().");
    return;
  }
  renderAnswerOptions();
  if (state.idTokenOnly) {
    buildPresentation().then(function (ok) {
      if (ok) {
        status("vp_present_status", "Ready: a self-issued ID Token and " +
               "nothing else, exactly as shown below.", "vc-ok");
      }
    });
    log.debug("Leaving onload(). ID Token only.");
    return;
  }
  if (!state.parsed) {
    status("vp_present_status",
      "This wallet holds no credential that can be parsed, so there is " +
          "nothing to present.", "vc-bad");
    log.debug("Leaving onload().");
    return;
  }
  renderDisclosureTable();
  buildPresentation().then(function (ok) {
    if (ok) {
      status("vp_present_status",
        "Ready: what is shown below is exactly what will be sent, and " +
            "nothing else.", "vc-ok");
    }
  });
  log.debug("SD-JWT VC presentation step 2 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  renderDpopNote: renderDpopNote,
  onHolderKeyPasted: onHolderKeyPasted,
  onSelectionChange: onSelectionChange,
  selectRequestedOnly: selectRequestedOnly,
  selectAll: selectAll,
  present: present,
  refuse: refuse,
  onAnswerOptionChange: onAnswerOptionChange,
  togglePane: togglePane,
  addSuppliedContext: addSuppliedContext,
  removeSuppliedContext: removeSuppliedContext,
  onload: onload
};
