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
//   * one checkbox per Disclosure, with the ones the DCQL query asked for marked,
//     the extras marked as over-disclosure, and the always-visible claims shown
//     as what they are: not optional, they travel with the issuer-signed JWT;
//   * the presentation assembled from that choice —
//     <Issuer-signed JWT>~<selected Disclosures>~<KB-JWT>;
//   * the Key Binding JWT itself, decoded: typ kb+jwt, this request's nonce, the
//     verifier's Client Identifier as aud, and sd_hash over exactly the bytes
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
  built: null
};

function el(id) { return document.getElementById(id); }
function setText(id, text) { var e = el(id); if (e) e.textContent = (text == null ? "" : String(text)); }
function setHtml(id, html) { var e = el(id); if (e) e.innerHTML = html; }
function setValue(id, v) { var e = el(id); if (e) e.value = (v == null ? "" : v); }
function setJson(id, value) {
  var e = el(id);
  if (e) e.textContent = (value === undefined || value === null) ? "—" : JSON.stringify(value, null, 2);
}
function status(id, text, cls) {
  var e = el(id);
  if (!e) return;
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
}
function esc(v) { return metadataClient.escapeHtmlText(v); }
function disable(id, off) { var e = el(id); if (e) e.disabled = !!off; }

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
  // not an empty table, and renderDisclosures() says so.
  state.format = (state.parsed && state.parsed.format) || sdJwtVc.FORMAT_SD_JWT;
  state.selectable = state.format !== sdJwtVc.FORMAT_JWT_VC_JSON;
  state.rows = ((state.parsed && state.parsed.disclosures) || []).map(function (d) {
    var requested = state.requested.indexOf(d.name) !== -1;
    return {
      encoded: d.encoded,
      name: d.error ? "(unreadable)" : (d.arrayElement ? "(array element)" : d.name),
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

function selectedEncoded() {
  return state.rows.filter(function (r) { return r.checked; }).map(function (r) { return r.encoded; });
}

// The claims that travel whatever the holder chooses: they are in the
// issuer-signed JWT itself, not in a Disclosure, so they cannot be withheld
// without breaking the signature.
function alwaysVisibleClaims() {
  var payload = (state.parsed && state.parsed.payload) || {};
  var out = {};
  Object.keys(payload).forEach(function (k) {
    if (["_sd", "_sd_alg"].indexOf(k) !== -1) return;
    out[k] = payload[k];
  });
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
      '<td><input type="checkbox" id="vp_disclose_' + i + '"' + (r.checked ? ' checked="checked"' : '') +
      ' onchange="return vcpresentation2.onSelectionChange(' + i + ', this.checked);" /></td>' +
      "<td>" + esc(r.name) + "</td>" +
      "<td>" + esc(valueText) + "</td>" +
      "<td>" + flag + "</td>" +
      '<td class="vc-mono">' + esc(String(r.encoded).slice(0, 24) + "…") + "</td>" +
      "</tr>";
  }).join("");
  // With no Disclosures the table would render as an empty box, which reads as a
  // credential that carries nothing. Show what will actually be sent instead,
  // and say why none of it can be withheld.
  if (!state.selectable) {
    var claims = (state.parsed && state.parsed.claims) || {};
    var names = Object.keys(claims);
    setHtml("vp_disclosures_table",
      "<thead><tr><th style='width:22%'>Claim</th><th>Value</th><th style='width:18%'>This verifier</th>" +
      "</tr></thead><tbody>" +
      (names.length
        ? names.map(function (name) {
            var v = claims[name];
            return "<tr><td>" + esc(name) + "</td><td>" +
              esc(typeof v === "object" ? JSON.stringify(v) : String(v)) + "</td><td>" +
              (state.requested.indexOf(name) !== -1
                ? '<span class="vc-ok">asked for</span>'
                : '<span class="vc-bad">not asked for</span>') + "</td></tr>";
          }).join("")
        : "<tr><td colspan='3'>This credential carries no claims.</td></tr>") +
      "</tbody>");
    setHtml("vp_selection_summary",
      '<span class="vc-status vc-pending">This credential is jwt_vc_json, which has no selective ' +
      'disclosure: all ' + names.length + ' claim(s) above are sent, including any this verifier did not ' +
      'ask for. Withholding one would mean asking the issuer for a different credential.</span>');
    log.debug("Leaving renderDisclosures(). jwt_vc_json — " + names.length + " claim(s), none selectable.");
    return;
  }
  setHtml("vp_disclosures_table",
    "<thead><tr><th style='width:6%'>Send</th><th style='width:16%'>Claim</th><th style='width:34%'>Value</th>" +
    "<th style='width:16%'>This verifier</th><th>Disclosure</th></tr></thead><tbody>" + rows + "</tbody>");

  var missing = state.requested.filter(function (name) {
    return !state.rows.some(function (r) { return r.name === name && r.checked; }) &&
           !(name in alwaysVisibleClaims());
  });
  var extra = state.rows.filter(function (r) { return r.checked && !r.requested; })
                        .map(function (r) { return r.name; });
  setHtml("vp_selection_summary",
    "Selected " + selectedEncoded().length + " of " + state.rows.length + " Disclosure(s). " +
    (missing.length
      ? '<span class="vc-bad">Not selected, though the verifier asked for it: ' + esc(missing.join(", ")) +
        " — the presentation will be refused without it.</span> "
      : '<span class="vc-ok">Everything the verifier asked for is selected.</span> ') +
    (extra.length
      ? '<span class="vc-bad">Also sending ' + esc(extra.join(", ")) +
        ", which was not asked for: that is over-disclosure, and the point of this format is to avoid it.</span>"
      : ""));
  log.debug("Leaving renderDisclosureTable(). missing=" + missing.length + ", extra=" + extra.length);
  return missing.length === 0;
}

// ---------------------------------------------------------------------------
// Building the presentation, up front, so what Present sends is on the screen
// before it is sent — the same principle step 2 of the issuance workflow follows.
// ---------------------------------------------------------------------------
function buildPresentation() {
  log.debug("Entering buildPresentation().");
  var params = (state.request && state.request.params) || {};
  // Storage first; falling back to the field the user pasted the downloaded key
  // into when holder-key saving is turned off on issuance step 2.
  var holderKey = sdJwtVc.readHolderPrivateJwk("vp_holder_private_jwk");
  var priv = holderKey.jwk;
  renderHolderKeyRow(holderKey);
  if (!state.parsed || !params.client_id || !params.nonce) {
    setValue("vp_presentation", "");
    setValue("vp_kb_jwt", "");
    setJson("vp_kb_header", null);
    setJson("vp_kb_payload", null);
    setValue("vp_assembled_call", "");
    status("vp_present_status",
      "There is not enough here to build a presentation: a request with a nonce and a client_id, plus a " +
      "credential in this wallet.", "vc-bad");
    log.debug("Leaving buildPresentation(). Not enough state.");
    return Promise.resolve(false);
  }
  var keyBinding = sdJwtVp.requiresKeyBinding(state.credentialQuery);
  if (keyBinding && !priv) {
    status("vp_present_status",
      "This verifier requires a holder proof, but the private half of the holder key is not available, " +
      "so no Key Binding JWT can be signed." +
      (holderKey.problem ? " " + holderKey.problem.charAt(0).toUpperCase() + holderKey.problem.slice(1) + "."
                         : " Paste it into the Holder private key field above, or turn saving back on " +
                           "for a future credential on issuance step 2."), "vc-bad");
    log.debug("Leaving buildPresentation(). No holder key.");
    return Promise.resolve(false);
  }
  return sdJwtVp.buildPresentationFor({
    credential: state.credential,
    parsed: state.parsed,
    selected: selectedEncoded(),
    holderPrivateJwk: priv,
    aud: params.client_id,
    nonce: params.nonce,
    keyBinding: keyBinding
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
    } else if (built.kb) {
      setValue("vp_kb_jwt", built.kb.jwt);
      setJson("vp_kb_header", built.kb.header);
      setJson("vp_kb_payload", built.kb.payload);
    } else {
      setValue("vp_kb_jwt", "");
      setJson("vp_kb_header", null);
      setJson("vp_kb_payload", null);
    }
    setJson("vp_vp_token", sdJwtVp.vpToken(sdJwtVp.firstCredentialQueryId(state.dcql), built.presentation));
    renderAssembledCall();
    // What a verifier will end up knowing, computed from the bytes being sent.
    var presented = sdJwtVp.presentedClaims(built.presentation);
    setJson("vp_presented_claims", presented.claims);
    log.debug("Leaving buildPresentation(). Built " + built.presentation.length + " characters.");
    return true;
  }).catch(function (e) {
    log.error("could not build the presentation: " + e.message);
    status("vp_present_status", "Could not build the presentation: " + e.message, "vc-bad");
    return false;
  });
}

// The call Present will make. With direct_post the wallet POSTs a form to the
// verifier's Response URI (OID4VP section 8.2); with any other response mode the
// answer would go back through the browser instead, and this page says so rather
// than pretending to implement it.
function renderAssembledCall() {
  log.debug("Entering renderAssembledCall().");
  var params = (state.request && state.request.params) || {};
  var mode = String(params.response_mode || "fragment");
  if (!state.built) {
    setValue("vp_assembled_call", "");
    return "";
  }
  var form = [];
  form.push("vp_token=" + encodeURIComponent(JSON.stringify(
    sdJwtVp.vpToken(sdJwtVp.firstCredentialQueryId(state.dcql), state.built.presentation))));
  if (params.state) form.push("state=" + encodeURIComponent(params.state));
  var body = form.join("&");
  var text;
  if (mode === "direct_post") {
    text = ["POST " + (params.response_uri || "(no response_uri)"),
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: " + body.length,
            "",
            body].join("\n");
  } else {
    text = "This request asks for response_mode=" + mode + ", which returns the vp_token through the " +
           "browser (a redirect to " + (params.redirect_uri || "(no redirect_uri)") + ") rather than as a " +
           "POST from the wallet. This workflow implements direct_post; the presentation above is what " +
           "would travel either way:\n\n" + body;
  }
  setValue("vp_assembled_call", text);
  log.debug("Leaving renderAssembledCall(). mode=" + mode);
  return text;
}

function onSelectionChange(index, checked) {
  log.debug("Entering onSelectionChange(). index=" + index + ", checked=" + checked);
  if (state.rows[index]) state.rows[index].checked = !!checked;
  sdJwtVc.setJson(sdJwtVp.KEYS.SELECTED, selectedEncoded());
  var complete = renderDisclosureTable();
  buildPresentation().then(function (ok) {
    if (ok) {
      status("vp_present_status", complete
        ? "Ready: what is shown below is exactly what will be sent."
        : "Ready, but the selection is missing a claim the verifier asked for — it will refuse this.",
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
      "Selection reset to exactly what the verifier asked for — the minimum that answers this request.",
      "vc-ok");
  });
  return false;
}

function selectAll() {
  log.debug("Entering selectAll().");
  state.rows.forEach(function (r) { r.checked = true; });
  sdJwtVc.setJson(sdJwtVp.KEYS.SELECTED, selectedEncoded());
  renderDisclosureTable();
  buildPresentation().then(function () {
    status("vp_present_status",
      "Every Disclosure selected. This is what a credential format without selective disclosure would force " +
      "on you, and you can see how much more it is than the verifier asked for.", "vc-pending");
  });
  return false;
}

// --- sending it -------------------------------------------------------------
function present() {
  log.debug("Entering present().");
  var params = (state.request && state.request.params) || {};
  if (!state.built) {
    status("vp_present_status", "There is no presentation built yet.", "vc-bad");
    return false;
  }
  if (String(params.response_mode || "") !== "direct_post") {
    status("vp_present_status",
      "This workflow sends the presentation with response_mode=direct_post; this request asked for " +
      (params.response_mode || "the OAuth 2.0 default") + ".", "vc-bad");
    return false;
  }
  if (!params.response_uri) {
    status("vp_present_status", "The request has no response_uri to post the presentation to.", "vc-bad");
    return false;
  }
  disable("vp_present_button", true);
  status("vp_present_status", "Presenting to " + params.response_uri + " …", "vc-pending");
  var body = "vp_token=" + encodeURIComponent(JSON.stringify(
    sdJwtVp.vpToken(sdJwtVp.firstCredentialQueryId(state.dcql), state.built.presentation))) +
    (params.state ? "&state=" + encodeURIComponent(params.state) : "");
  fetch(params.response_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  })
    .then(function (r) {
      return r.text().then(function (text) {
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is what gets shown.
        }
        return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
      });
    })
    .then(function (response) {
      var box = el("vp_response_body");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      }
      // Whatever the verifier said, the wallet keeps a record of what it sent:
      // step 3 shows both sides.
      sdJwtVc.setJson(sdJwtVp.KEYS.PRESENTATION, {
        presentation: state.built.presentation,
        kbJwt: state.built.kb ? state.built.kb.jwt : "",
        kbPayload: state.built.kb ? state.built.kb.payload : null,
        sdHash: state.built.sdHash,
        selected: selectedEncoded(),
        requested: state.requested,
        sentAt: new Date().toISOString(),
        responseUri: params.response_uri,
        clientId: params.client_id,
        nonce: params.nonce,
        state: params.state || "",
        accepted: !!response.ok,
        statusCode: response.statusCode,
        response: response.body || response.raw
      });
      if (!response.ok) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vp_present_status",
          "The verifier refused the presentation: " + err + " Step 3 shows which of its checks failed.",
          "vc-bad");
        disable("vp_present_button", false);
        window.setTimeout(function () { window.location.href = sdJwtVp.STEP3_URL; }, 1500);
        return;
      }
      status("vp_present_status", "The verifier accepted the presentation. Opening step 3 …", "vc-ok");
      window.location.href = sdJwtVp.STEP3_URL;
    })
    .catch(function (e) {
      log.error("the presentation could not be sent: " + e.message);
      status("vp_present_status", "The presentation could not be sent: " + e.message, "vc-bad");
      disable("vp_present_button", false);
    });
  log.debug("Leaving present().");
  return false;
}

// Refusing is an answer, and OID4VP has one for it: access_denied to the same
// Response URI (section 8.4). The verifier learns the request was seen and
// declined — which is not the same as never having arrived.
function refuse() {
  log.debug("Entering refuse().");
  var params = (state.request && state.request.params) || {};
  if (!params.response_uri) {
    status("vp_present_status",
      "Nothing was sent. There is no response_uri to tell the verifier you declined, either.", "vc-pending");
    return false;
  }
  disable("vp_refuse_button", true);
  var body = "error=access_denied&error_description=" +
    encodeURIComponent("The holder declined to present this credential.") +
    (params.state ? "&state=" + encodeURIComponent(params.state) : "");
  fetch(params.response_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  })
    .then(function () {
      status("vp_present_status",
        "Refused. access_denied was sent to the verifier and no part of the credential left this browser.",
        "vc-pending");
    })
    .catch(function (e) {
      status("vp_present_status",
        "Refused. Nothing was disclosed; telling the verifier failed (" + e.message + "), which changes " +
        "nothing about what it knows.", "vc-pending");
    });
  log.debug("Leaving refuse().");
  return false;
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

// The paste-in row only appears when there is nothing in storage to sign with:
// with saving on it would be a field asking for something the page already has.
function renderHolderKeyRow(holderKey) {
  var row = document.getElementById("vp_holder_key_row");
  var note = document.getElementById("vp_holder_key_note");
  if (!row) return;
  var needed = (holderKey.source !== "storage");
  row.style.display = needed ? "" : "none";
  if (!note) return;
  if (!needed) {
    note.textContent = "";
  } else if (holderKey.problem) {
    note.textContent = holderKey.problem;
  } else if (holderKey.jwk) {
    note.textContent = "Using the key pasted here. It is not stored.";
  } else {
    note.textContent = "Not in this browser's storage — paste the key pair you downloaded on issuance step 2.";
  }
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
  // Show the paste-in row from the start when there is no stored private half:
  // buildPresentation() also renders it, but it returns early when there is not
  // enough state yet, which is exactly the case where the user most needs to be
  // told the key is missing and given somewhere to put it.
  renderHolderKeyRow(sdJwtVc.readHolderPrivateJwk("vp_holder_private_jwk"));
  var params = (state.request && state.request.params) || {};
  setText("vp_verifier", params.client_id || "—");
  setText("vp_nonce", params.nonce || "—");
  setText("vp_requested", state.requested.length ? state.requested.join(", ") : "—");
  if (state.format === sdJwtVc.FORMAT_JWT_VC_JSON) {
    setText("vp_key_binding",
      "This credential is jwt_vc_json, so holder binding is a Verifiable Presentation JWT signed with the " +
      "bound key — there is no Key Binding JWT, and no Disclosures to choose between.");
  } else
  setText("vp_key_binding", sdJwtVp.requiresKeyBinding(state.credentialQuery)
    ? "required — the presentation carries a Key Binding JWT signed by the holder key"
    : "not required by this verifier, so the presentation may go without a holder proof");
  setJson("vp_always_visible", alwaysVisibleClaims());

  if (!state.request) {
    status("vp_present_status",
      "There is no request to answer. Step 1 reads one from the verifier.", "vc-bad");
    return;
  }
  if (!state.parsed) {
    status("vp_present_status",
      "This wallet holds no credential that can be parsed, so there is nothing to present.", "vc-bad");
    return;
  }
  renderDisclosureTable();
  buildPresentation().then(function (ok) {
    if (ok) {
      status("vp_present_status",
        "Ready: what is shown below is exactly what will be sent, and nothing else.", "vc-ok");
    }
  });
  log.debug("SD-JWT VC presentation step 2 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  onHolderKeyPasted: onHolderKeyPasted,
  onSelectionChange: onSelectionChange,
  selectRequestedOnly: selectRequestedOnly,
  selectAll: selectAll,
  present: present,
  refuse: refuse,
  togglePane: togglePane,
  onload: onload
};
