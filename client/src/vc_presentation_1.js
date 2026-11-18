// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_presentation_1.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC presentation, step 1: the Verifier's Authorization Request.
//
// This is where a presentation starts for the wallet: a request arrives — in
// the query string, or as a request_uri the wallet has to fetch, or pasted in
// from a QR code on another device — and before anything is disclosed the
// wallet has to answer three questions:
//
//   1. WHO is asking?  The Client Identifier, and what its prefix means: with
//      `redirect_uri:` the identity IS the URL the response goes to and the
//      request cannot be signed; a pre-registered id can sign, and then the
//      signature is worth checking (OID4VP section 5.10, RFC 9101).
//   2. WHAT are they asking for?  The DCQL query, decoded into claim paths, next
//      to the credential this wallet actually holds.
//   3. HOW does the answer travel?  response_type, response_mode, response_uri —
//      direct_post means the wallet POSTs it rather than putting a credential in
//      a URL.
//
// Nothing is disclosed on this page. It reads the request, verifies what can be
// verified, and hands over to step 2.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");
var vpProtocols = require("./vp_protocols");
var vpQuery = require("./vp_query");
var x509 = require("./x509");

var log = bunyan.createLogger({ name: 'vc_presentation_1',
                                level: appconfig.logLevel });

// The request as this page understands it: { params, dcql, clientMetadata,
// source, signed, signatureVerdict }.
var request = null;

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
function val(id) {
  log.debug("Entering val().");
  var e = el(id);
  log.debug("Leaving val().");
  return e ? e.value : "";
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

// ---------------------------------------------------------------------------
// The Client Identifier Prefix (OID4VP section 5.10). What the wallet may
// conclude about who is asking depends entirely on it, so it is spelled out
// rather than left as a string in a table.
// ---------------------------------------------------------------------------
function clientIdentifier(clientId) {
  log.debug("Entering clientIdentifier(). client_id=" + clientId);
  var id = String(clientId || "");
  var colon = id.indexOf(":");
  var known = ["redirect_uri", "x509_san_dns", "x509_hash", "did",
      "verifier_attestation",
               "openid_federation", "decentralized_identifier",
                   "pre-registered", "origin"];
  var prefix = colon > 0 ? id.slice(0, colon) : "";
  if (known.indexOf(prefix) === -1) {
    // No recognised prefix: a pre-registered client, whose metadata and key the
    // wallet has out of band (section 5.10's fallback).
    log.debug("Leaving clientIdentifier(). Pre-registered.");
    return {
      prefix: "(none)", value: id, signable: true,
      note: "No Client Identifier Prefix, so this is a pre-registered " +
          "client: the wallet is expected to know " +
            "it — and its key — out of band. A signed request can therefore " +
                "be verified, and this workflow " +
            "looks for the key at the Verifier JWKS URL below."
    };
  }
  if (prefix === "redirect_uri") {
    log.debug("Leaving clientIdentifier(). redirect_uri prefix.");
    return {
      prefix: prefix, value: id.slice(colon + 1), signable: false,
      note: "The client_id IS the URL the response goes to. Such a request " +
          "cannot be signed — there is no key " +
            "the wallet could obtain for it — so what binds the request to " +
                "the verifier is only that the " +
            "presentation is sent to that same URL. All verifier metadata " +
                "has to come in client_metadata."
    };
  }
  if (prefix === "x509_hash" || prefix === "x509_san_dns") {
    log.debug("Leaving clientIdentifier(). " + prefix + " prefix.");
    return {
      prefix: prefix, value: id.slice(colon + 1), signable: true,
      note: prefix === "x509_hash" ?
        "The Verifier is named by the SHA-256 of its own certificate, " +
        "which the signed request carries in x5c. The wallet hashes that " +
        "certificate, verifies the request with its key, and follows its " +
        "chain to the trust anchor configured on step 0." :
        "The Verifier is named by a DNS name its certificate certifies, " +
        "carried in the signed request's x5c. The answer must go to that " +
        "same host."
    };
  }
  log.debug("Leaving clientIdentifier(). prefix=" + prefix);
  return {
    prefix: prefix, value: id.slice(colon + 1), signable: true,
    note: "The prefix says how the wallet is meant to authenticate the " +
        "verifier and find its metadata. This " +
          "workflow implements the pre-registered, redirect_uri, " +
              "x509_hash and x509_san_dns cases; for " + prefix +
          " it shows what arrived without claiming to have validated it."
  };
}

// --- reading the request ----------------------------------------------------
// Everything the page knows about a request, from whichever way it arrived.
function adoptParams(params, source) {
  log.debug("Entering adoptParams(). source=" + source);
  request = {
    params: params,
    source: source,
    receivedAt: new Date().toISOString(),
    dcql: sdJwtVp.requestObjectValue(params, "dcql_query"),
    // The OpenID4VP DRAFTS' query (DIF Presentation Exchange), removed in
    // 1.0; read when there is no dcql_query (vp_query.js).
    presentationDefinition: sdJwtVp.requestObjectValue(params,
      "presentation_definition"),
    clientMetadata: sdJwtVp.requestObjectValue(params, "client_metadata"),
    signed: false,
    signatureVerdict: ""
  };
  log.debug("Leaving adoptParams().");
  return request;
}

// A request passed by reference: fetch the Request Object and, when it is a
// signed JWT, verify it before believing a word of it.
function fetchRequestObject(uri, clientId, method) {
  log.debug("Entering fetchRequestObject(). uri=" + uri + " method=" +
            (method || "get"));
  status("vp_request_status", "Fetching the Request Object from " + uri + " …",
         "vc-pending");
  var accept = "application/oauth-authz-req+jwt, application/jwt, " +
               "application/json";
  var init = { headers: { "Accept": accept } };
  // request_uri_method=post (OpenID4VP 1.0 section 5.10): the wallet says
  // what it can do, and sends a nonce the signed request must echo, so a
  // Request Object made for some other wallet cannot be replayed at this one.
  var walletNonce = "";
  if (String(method || "").toLowerCase() === "post") {
    walletNonce = vpProtocols.walletNonce();
    init = {
      method: "POST",
      headers: { "Accept": accept,
                 "Content-Type": "application/x-www-form-urlencoded" },
      body: "wallet_metadata=" + encodeURIComponent(JSON.stringify(
              vpProtocols.walletMetadata())) +
            "&wallet_nonce=" + encodeURIComponent(walletNonce)
    };
  }
  log.debug("Leaving fetchRequestObject().");
  // Straight from the browser, or through the debugger's api when step 0
  // says so (sd_jwt_vp.js verifierFetch()).
  return sdJwtVp.verifierFetch(uri, init)
    .then(function (r) {
      if (!r.ok) throw new Error("the request_uri returned HTTP " + r.status +
          ".");
      return r.text();
    })
    .then(function (text) {
      var body = String(text || "").trim();
      if (body.split(".").length === 3) {
        // A signed Request Object (RFC 9101).
        var payload = metadataClient.b64uToJson(body.split(".")[1]);
        var params = {};
        sdJwtVp.REQUEST_PARAMS.forEach(function (name) {
          if (payload[name] === undefined) return;
          params[name] = typeof payload[name] === "object" ?
                 JSON.stringify(payload[name]) : String(payload[name]);
        });
        adoptParams(params, "request_uri (signed Request Object)");
        request.signed = true;
        request.outerClientId = clientId || "";
        request.walletNonce = walletNonce;
        request.requestUriMethod = walletNonce ? "post" : "get";
        request.requestObject = body;
        request.requestObjectHeader =
            metadataClient.b64uToJson(body.split(".")[0]);
        request.requestObjectPayload = payload;
        var prefix = vpProtocols.clientIdPrefix(clientId ||
            payload.client_id).prefix;
        if (prefix === "x509_hash" || prefix === "x509_san_dns") {
          return verifyX509Signature(body, clientId || payload.client_id);
        }
        return verifyRequestSignature(body, clientId || payload.client_id);
      }
      // An unsigned Request Object is JSON (still allowed by reference).
      var parsed = JSON.parse(body);
      var flat = {};
      Object.keys(parsed).forEach(function (k) {
        flat[k] = typeof parsed[k] === "object" ?
             JSON.stringify(parsed[k]) : String(parsed[k]);
      });
      adoptParams(flat, "request_uri (unsigned JSON)");
      request.signatureVerdict = "The Request Object was not signed, so nothing about its origin is proven.";
      log.debug("Leaving fetchRequestObject(). Unsigned JSON.");
      return request;
    });
}

// A Request Object whose Client Identifier is an x509 prefix: the key is the
// leaf certificate's, the identity is the certificate's hash or DNS name, and
// the trust is the chain up to the anchor configured on step 0.
function verifyX509Signature(compact, clientId) {
  log.debug("Entering verifyX509Signature().");
  log.debug("Leaving verifyX509Signature().");
  return vpProtocols.verifyX509Request({
    compact: compact,
    clientId: clientId,
    responseTarget: vpProtocols.responseTarget(request.params),
    trustAnchorPem: (sdJwtVc.get(sdJwtVp.KEYS.X509_TRUST_ANCHOR) || "")
        .trim(),
    verifyChain: x509.verifyChain
  }).then(function (result) {
    request.x509 = result;
    var sig = result.checks.filter(function (c) {
      return c.name === "signature";
    })[0];
    request.signatureValid = !!(sig && sig.ok);
    request.signatureVerdict = result.checks.map(function (c) {
      return (c.ok ? "OK " : "FAILED ") + c.name + " — " + c.detail;
    }).join("\n");
    log.debug("Leaving verifyX509Signature(). valid=" +
              request.signatureValid);
    return request;
  }).catch(function (e) {
    request.signatureValid = false;
    request.signatureVerdict = "Could not be checked: " + e.message;
    log.warn("the x509 Request Object could not be checked: " + e.message);
    return request;
  });
}

// The signature on a Request Object, against the keys this wallet is configured
// to trust for the verifier. For a pre-registered client that configuration IS
// the out-of-band knowledge OID4VP assumes.
function verifyRequestSignature(compact, clientId) {
  log.debug("Entering verifyRequestSignature().");
  var jwksUrl = verifierJwksUrl();
  if (!jwksUrl) {
    request.signatureVerdict = "The request is signed, but no Verifier JWKS " +
        "URL is configured, so the " +
      "signature cannot be checked. Anyone could have sent this.";
    log.debug("Leaving verifyRequestSignature(). No JWKS configured.");
    return Promise.resolve(request);
  }
  log.debug("Leaving verifyRequestSignature().");
  return sdJwtVp.verifierFetch(jwksUrl,
      { headers: { "Accept": "application/json" } })
    .then(function (r) {
      if (!r.ok) {
        throw new Error("the JWKS URL answered HTTP " + r.status + ".");
      }
      return r.json();
    })
    .then(function (jwks) {
      return metadataClient.verifyJwsWithJwks(compact, jwks,
          "the Request Object");
    })
    .then(function (v) {
      request.signatureValid = !!v.valid;
      request.signatureVerdict = (v.valid ? "VALID" : "INVALID") +
        " — checked against the keys at " + jwksUrl + " (alg " + v.header.alg +
            ", kid " + v.kid + ")." +
        (v.valid ?
         " The claims being asked for are the ones the verifier signed." : "");
      log.debug("Leaving verifyRequestSignature(). valid=" + v.valid);
      return request;
    })
    .catch(function (e) {
      request.signatureValid = false;
      request.signatureVerdict = "Could not be checked: " + e.message;
      log.error("the Request Object signature could not be checked: " +
                e.message);
      return request;
    });
}

// --- what the request asks for, against what the wallet holds ---------------
function heldCredential() {
  log.debug("Entering heldCredential().");
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!raw) {
    log.debug("Leaving heldCredential().");
    return null;
  }
  try {
    log.debug("Leaving heldCredential().");
    return { raw: raw, parsed: sdJwtVc.parseCredential(raw) };
  } catch (e) {
    log.error("the stored credential could not be parsed: " + e.message);
    log.debug("Leaving heldCredential().");
    return { raw: raw, parsed: null, error: e.message };
  }
}

// What the request asks for, against the credential in hand, in either
// query language: one row per DCQL credential query or PE Input
// Descriptor, each claim marked with what OpenID4VP 1.0 section 6.4.1 (or
// PE's Input Evaluation) makes of it here, and the predicates below.
function renderRequestedClaims() {
  log.debug("Entering renderRequestedClaims().");
  var held = heldCredential();
  var planned = sdJwtVp.planForRequest(request, held && held.parsed);
  var model = planned.model;
  if (!model.items.length) {
    setHtml("vp_requested_table",
      '<tbody><tr><td>This request carries no <code>dcql_query</code>, so it ' +
          'does not say which credential ' +
      'or which claims it wants. OID4VP requires one (or a ' +
          '<code>scope</code> standing for one).' +
      (model.errors.length && model.language ? " " +
       esc(model.errors.join(" ")) : "") + '</td></tr></tbody>');
    renderPredicates(planned);
    log.debug("Leaving renderRequestedClaims(). No query.");
    return planned;
  }
  var rows = "";
  model.items.forEach(function (item) {
    var q = item.query || {};
    // An mdoc query names its type by meta.doctype_value, which plays the
    // part vct_values plays for an SD-JWT VC.
    var vcts = ((q.meta || {}).vct_values ||
                ((q.meta || {}).doctype_value ? [q.meta.doctype_value] :
                 [])).join(", ");
    var heldVct = held && held.parsed ? ((held.parsed.payload || {}).vct ||
                                         held.parsed.docType || "") : "";
    var typeOk = !vcts || !heldVct || vcts.indexOf(heldVct) !== -1;
    var mine = planned.item === item ? planned.plan : null;
    var claimRows = mine && mine.claims ? mine.claims.rows : [];
    var cell = item.claims.length ? item.claims.map(function (c, i) {
      var r = claimRows[i] || {};
      var p = c.path.map(function (x) {
        return x === null ? "*" : String(x);
      }).join(".");
      var ok = r.status === "available";
      var why = !r.status ? "" : r.status === "available" ? "" :
        r.status === "absent" ? " (not in the credential you hold)" :
        " (" + r.status + ": " + r.reason + ")";
      return '<span class="' + (ok ? "vc-ok" : "vc-bad") + '">' + esc(p) +
        (c.values ? " = one of " + esc(JSON.stringify(c.values)) : "") +
        esc(why) + "</span>";
    }).join("<br>") : "(no claims named — the whole credential)";
    if (item.claimSets) {
      cell += "<br><em>claim_sets: " + esc(JSON.stringify(item.claimSets)) +
        (mine && mine.claims ? " — " + esc(mine.claims.reason) : "") +
        "</em>";
    }
    rows += "<tr><td>" + esc(item.id || "—") + "</td><td>" +
      esc(item.formats.join(", ") || "—") + "</td>" +
      '<td class="' + (typeOk ? "vc-ok" : "vc-bad") + '">' + esc(vcts ||
        "(any)") + "</td>" +
      "<td>" + (model.language === "dcql" ? (sdJwtVp.requiresKeyBinding(q) ?
        "required" : "not required") : "(PE: by format)") + "</td>" +
      "<td>" + cell + "</td></tr>";
  });
  setHtml("vp_requested_table",
    "<thead><tr><th style='width:16%'>" + (model.language === "pe" ?
      "Input Descriptor" : "Query id") + "</th><th " +
        "style='width:12%'>Format</th>" +
    "<th style='width:22%'>vct wanted</th><th style='width:12%'>Holder " +
        "binding</th>" +
    "<th>Claims asked for</th></tr></thead><tbody>" + rows + "</tbody>");
  setText("vp_query_language", model.language === "pe" ? model.label :
    "DCQL (OpenID4VP 1.0 section 6)");
  renderPredicates(planned);
  log.debug("Leaving renderRequestedClaims().");
  return planned;
}

// The predicates the request asks to be PROVEN, and what is not revealed:
// one row each, with how this credential proves it (or why it cannot).
function renderPredicates(planned) {
  log.debug("Entering renderPredicates().");
  var plan = planned && planned.plan;
  var item = planned && planned.item;
  var ext = item && item.extension;
  var notes = [];
  if (ext && ext.note) notes.push(ext.note);
  if (ext && ext.honoured) {
    notes.push("Predicates come from the " + vpQuery.LABEL_EXT + ", " +
               "honoured because the credential query lists " +
               vpQuery.EXT_PREDICATES + " in " + vpQuery.EXT_CRIT + ".");
  }
  if (planned && planned.model.language === "pe") {
    notes.push("Predicates come from DIF Presentation Exchange " +
               vpQuery.PE_VERSION + "'s Predicate Feature (" +
               vpQuery.LABEL_PE + ").");
  }
  if (!plan || !plan.predicates.length) {
    setHtml("vp_predicates_table", "<tbody><tr><td>No predicates: this " +
      "request asks only for claims." + (notes.length ? " " +
      esc(notes.join(" ")) : "") + "</td></tr></tbody>");
    log.debug("Leaving renderPredicates(). None.");
    return;
  }
  setHtml("vp_predicates_table",
    "<thead><tr><th style='width:22%'>Predicate</th><th style='width:10%'>" +
    "Mode</th><th style='width:16%'>How</th><th>Detail</th></tr></thead>" +
    "<tbody>" + plan.predicates.map(function (p) {
      var cls = p.ok ? (p.method === "disclose" ? "vc-rule-warn" : "vc-ok") :
        "vc-rule-block";
      var how = p.method === "zk" ? "proven (zero knowledge)" :
        p.method === "issuer-boolean" ? "issuer-computed claim" :
        p.method === "disclose" ? "VALUE DISCLOSED" : "REFUSED";
      return "<tr><td>" + esc(p.description) + "</td><td>" + esc(p.mode) +
        '</td><td class="' + cls + '">' + how + "</td><td>" + esc(p.reason) +
        "</td></tr>";
    }).join("") + "</tbody>");
  setText("vp_predicates_note", (plan.notRevealed.length ? "Not " +
    "revealed, though a predicate is proven over it: " +
    plan.notRevealed.join(", ") + ". " : "") + notes.join(" "));
  log.debug("Leaving renderPredicates().");
}

// The chosen protocol's rules, one row each: what it demands of this request
// and whether the request meets it. A blocking row is why Continue is off.
function renderRules(protocol, rules) {
  log.debug("Entering renderRules(). " + rules.length + " rule(s).");
  setText("vp_protocol_label", protocol.label);
  setHtml("vp_protocol_rules",
    "<thead><tr><th style='width:22%'>Rule</th><th style='width:10%'>" +
    "Result</th><th>Detail</th></tr></thead><tbody>" +
    rules.map(function (r) {
      var cls = r.ok ? "vc-ok" : (r.level === "block" ? "vc-rule-block" :
                                  "vc-rule-warn");
      var word = r.ok ? "OK" : (r.level === "block" ? "REFUSED" : "WARNING");
      return "<tr><td>" + esc(r.id) + '</td><td class="' + cls + '">' +
             word + "</td><td>" + esc(r.text) + "</td></tr>";
    }).join("") + "</tbody>");
  log.debug("Leaving renderRules().");
}

function renderRequest() {
  log.debug("Entering renderRequest().");
  if (!request) {
    status("vp_request_status",
      "No presentation request yet. A verifier sends one — step 0 starts at " +
          "one — or paste the request URI " +
      "from a QR code below.", "vc-pending");
    disable("vp_continue_button", true);
    log.debug("Leaving renderRequest(). Nothing to show.");
    return false;
  }
  var p = request.params || {};
  var who = clientIdentifier(p.client_id);
  setText("vp_client_id", p.client_id || "—");
  setText("vp_client_prefix", who.prefix + " → " + who.value);
  setText("vp_client_note", who.note);
  setText("vp_response_type", p.response_type || "—");
  setText("vp_response_mode", p.response_mode ||
          "(fragment, the OAuth 2.0 default)");
  setText("vp_response_uri", p.response_uri || p.redirect_uri || "—");
  setText("vp_nonce", p.nonce || "—");
  setText("vp_state", p.state || "—");
  setText("vp_source", request.source + " at " + request.receivedAt);
  setJson("vp_dcql", request.dcql || request.presentationDefinition);
  setJson("vp_client_metadata", request.clientMetadata);
  setValue("vp_request_raw", JSON.stringify(p, null, 2));
  setText("vp_signature_verdict", request.signed
    ? (request.signatureVerdict || "signed; not checked yet")
    : "This request is not signed. " + (who.signable
        ? "A pre-registered client could have signed it; this one did not."
        : "With the redirect_uri prefix it cannot be, which is by design."));
  var planned = renderRequestedClaims();

  // Everything the wallet needs before it can answer: first what the chosen
  // PROTOCOL demands of the request (vp_protocols.js), then what answering
  // demands of this wallet.
  var protocol = sdJwtVp.currentProtocol();
  var held = heldCredential();
  var rules = vpProtocols.requestRules(protocol.id, {
    request: request,
    x509: request.x509 || null,
    heldFormat: held && held.parsed ? held.parsed.format : "",
    requestedFormat: sdJwtVp.firstCredentialQueryFormat(request.dcql) ||
      (planned.item && planned.item.formats[0]) || ""
  });
  renderRules(protocol, rules);
  var problems = vpProtocols.blockingRules(rules).map(function (r) {
    return r.text.replace(/\.$/, "");
  });
  // What the QUERY makes impossible for the credential in hand: a values
  // mismatch or no satisfiable claim_sets option (OpenID4VP 1.0 section
  // 6.4.1: the credential is then not returned), a predicate it cannot
  // prove without disclosing, a critical extension it does not understand.
  if (!vpProtocols.asksForIdToken(p) || vpProtocols.asksForVpToken(p)) {
    (planned.blocking || []).forEach(function (b) {
      problems.push(String(b).replace(/\.$/, ""));
    });
  }
  // An ID Token on its own presents no credential, so there is nothing about
  // a held credential to check: the subject key is the holder key when there
  // is one, and a pairwise key otherwise (step 2).
  var idTokenOnly = vpProtocols.asksForIdToken(p) &&
                    !vpProtocols.asksForVpToken(p);
  // The format this verifier asked for, which is not necessarily the one in
  // hand. Empty when the query does not say, in which case there is nothing to
  // disagree with and the check below stays silent.
  var requestedFormat = sdJwtVp.firstCredentialQueryFormat(request.dcql);
  if (!request.dcql && planned.item && planned.item.formats.length &&
      held && held.parsed &&
      (planned.item.formats.indexOf(held.parsed.format) !== -1 ||
       (held.parsed.format === "anoncreds" &&
        planned.item.formats.indexOf("di_vc") !== -1))) {
    // A PE descriptor may list several formats; the held one is among
    // them, so there is nothing to disagree with.
    requestedFormat = held.parsed.format;
  } else if (!request.dcql && planned.item) {
    requestedFormat = planned.item.formats[0] || "";
  }
  // A missing holder key is only a dead end when there is no way to supply one.
  // Since the holder key pair can be deliberately kept out of localStorage
  // (issuance step 2), "not in storage" now has two meanings, and treating them
  // alike would strand the user one page before the field that fixes it.
  var holderKeyAdvisory = null;
  if (idTokenOnly) {
    holderKeyAdvisory = "This request asks for a self-issued ID Token " +
        "alone, so no credential is presented; step 2 chooses the key it " +
        "is signed with.";
  }
  else if (!held) problems.push("this wallet holds no credential to present");
  else if (!held.parsed) problems.push("the credential in storage cannot " +
           "be parsed: " + held.error);
  // Asked for one format, holding another. This blocks rather than advises,
  // because unlike a missing holder key there is nothing the next page can do
  // about it: a presentation cannot change a credential's format. Caught here
  // so the user is told before choosing disclosures, instead of at the verifier
  // — which reports it as a malformed presentation ("this has 1 part(s)"),
  // naming the parse failure rather than the credential in hand.
  else if (requestedFormat && held.parsed.format &&
           requestedFormat !== held.parsed.format) {
    problems.push("this verifier asked for a " + requestedFormat +
                  " credential and this wallet holds a " +
      held.parsed.format +
          " one — a presentation cannot convert between formats, so issue a " +
      requestedFormat + " credential first");
  }
  // A selectively disclosable ldp_vc (bbs-2023) needs no holder private key
  // at all: the derived proof IS the holder's act, and the credential names
  // its subject by id rather than by a cnf key the wallet must sign with.
  // Requiring one here refused every such request for want of a key the
  // format never uses. Any other ldp_vc goes whole inside a VP the holder
  // signs, so it needs the key like a jwt_vc_json does, below (#475).
  else if (held.parsed && held.parsed.format === sdJwtVc.FORMAT_LDP_VC &&
           held.parsed.ldpSelective) {
    holderKeyAdvisory = "This credential is ldp_vc with a " +
        held.parsed.ldpSuite + " proof, so no holder key is needed: " +
      "the derived proof itself is what proves the holder made this presentation.";
  }
  // A BBS JPT likewise: JPA section 7.3.2 needs no holder key, the
  // presentation proof being the binding (#478).
  else if (held.parsed && held.parsed.format === sdJwtVc.FORMAT_JPT &&
           (held.parsed.header || {}).alg === "BBS") {
    holderKeyAdvisory = "This credential is a BBS JSON Proof Token, so no " +
      "holder key is needed: the presentation proof itself binds it to " +
      "this request.";
  }
  else if (!sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK)) {
    if (sdJwtVc.holderPrivateKeyMayBeStored()) {
      // Saving is on and it is still absent: the key was never generated in
      // this browser, so there is nothing to paste and nothing to continue to.
      problems.push("the private half of the holder key is missing, so no " +
                    "Key Binding JWT can be signed");
    } else {
      // Deliberately not kept. Step 2 has a field to paste it into, so this
      // must NOT disable Continue.
      holderKeyAdvisory = "The holder key is not kept in this browser, by " +
          "the choice made on issuance " +
        "step 2 — paste it on the next page so the Key Binding JWT can be signed.";
    }
  }
  if (request.signed && request.signatureValid === false &&
      problems.indexOf("the Request Object's signature does not verify") ===
      -1) {
    problems.push("the Request Object's signature does not verify");
  }

  if (problems.length) {
    status("vp_request_status", "This request cannot be answered: " +
           problems.join("; ") + ".", "vc-bad");
    disable("vp_continue_button", true);
  } else {
    status("vp_request_status",
      "Request read" + (request.signed ? " and its signature checked" : "") +
      " under " + protocol.label + ". " + (idTokenOnly ?
        "It asks for a self-issued ID Token and no credential. Continue " +
        "to sign it." :
        "It asks for " + (planned.plan && !planned.plain ?
          planned.plan.disclose.length :
          sdJwtVp.requestedClaims(request.dcql).length) +
        " claim(s)" + (planned.plan && planned.plan.predicates.length ?
          " and " + planned.plan.predicates.length + " predicate(s) " +
          "proven without disclosing " +
          (planned.plan.notRevealed.join(", ") || "the value") : "") +
        " and nothing else has to be sent. Continue to choose " +
        "what to disclose.") +
      (holderKeyAdvisory ? " " + holderKeyAdvisory : ""),
      holderKeyAdvisory ? "vc-pending" : "vc-ok");
    disable("vp_continue_button", false);
  }
  sdJwtVp.storeRequest(request);
  log.debug("Leaving renderRequest(). problems=" + problems.length);
  return problems.length === 0;
}

// --- page actions -----------------------------------------------------------
// A request pasted in by hand: the cross-device case, where the wallet is on
// this device and the QR code is on the verifier's screen.
function usePastedRequest() {
  log.debug("Entering usePastedRequest().");
  var text = (val("vp_paste_request") || "").trim();
  if (!text) {
    status("vp_request_status",
           "Paste the request URI from the verifier's QR code first.",
           "vc-bad");
    log.debug("Leaving usePastedRequest().");
    return false;
  }
  var params = sdJwtVp.parseRequestUri(text);
  if (!Object.keys(params).length) {
    status("vp_request_status",
      "Nothing in that text looks like an OID4VP Authorization Request. It " +
          "should carry at least a client_id " +
      "and either a dcql_query or a request_uri.", "vc-bad");
    log.debug("Leaving usePastedRequest().");
    return false;
  }
  adoptParams(params, "pasted by hand");
  if (params.request_uri) {
    fetchRequestObject(params.request_uri, params.client_id,
                       params.request_uri_method)
      .then(renderRequest)
      .catch(function (e) {
        status("vp_request_status", "Could not fetch the Request Object: " +
               e.message, "vc-bad");
      });
    log.debug("Leaving usePastedRequest().");
    return false;
  }
  renderRequest();
  log.debug("Leaving usePastedRequest().");
  return false;
}

// The JWKS URL this wallet trusts for the verifier.
//
// Configured on step 0's Configuration Parameters pane. When it has not been,
// fall back to the DEPLOYMENT'S DEFAULT VERIFIER — deliberately not to the
// credential issuer, which this used to do: the mock hosts issuer and verifier
// together, but the moment issuance has been run against walt.id the issuer is
// a different service on a different port with a path in its identifier, and
// the derived URL pointed at nothing.
function verifierJwksUrl() {
  log.debug("Entering verifierJwksUrl().");
  var stored = (sdJwtVc.get(sdJwtVp.KEYS.VERIFIER_JWKS_URL) || "").trim();
  if (stored) {
    log.debug("Leaving verifierJwksUrl().");
    return stored;
  }
  var base = (sdJwtVc.get(sdJwtVp.KEYS.VERIFIER_BASE_URL) ||
              appconfig.oid4vpVerifierUrlDefault || "").trim();
  log.debug("Leaving verifierJwksUrl().");
  return base ? base.replace(/\/+$/, "") + "/oauth2/jwks" : "";
}

function forgetRequest() {
  log.debug("Entering forgetRequest().");
  sdJwtVp.forgetRequest();
  request = null;
  renderRequest();
  status("vp_request_status",
    "The request was discarded. Nothing was presented, and its nonce is now " +
        "useless to anyone.", "vc-pending");
  log.debug("Leaving forgetRequest().");
  return false;
}

function continueToDisclose() {
  log.debug("Entering continueToDisclose().");
  window.location.href = sdJwtVp.STEP2_URL;
  log.debug("Leaving continueToDisclose().");
  return false;
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

function onload() {
  log.debug("Entering onload().");
  sdJwtVp.renderUseCaseBadge();
  var step = document.getElementById("vp_step_1");
  if (step) step.className = "vc-step-current";
  var zero = document.getElementById("vp_step_0");
  if (zero) zero.className = "vc-step-done";


  // A request in the query string is the same-device flow: the verifier just
  // redirected the browser here with it.
  var fromQuery = sdJwtVp.parseRequestQuery(window.location.search);
  if (Object.keys(fromQuery).length) {
    adoptParams(fromQuery, fromQuery.request_uri ?
                "the verifier's redirect (by reference)"
                                                 : "the verifier's redirect " +
                                                     "(by value)");
    if (fromQuery.request_uri) {
      fetchRequestObject(fromQuery.request_uri, fromQuery.client_id,
                         fromQuery.request_uri_method)
        .then(renderRequest)
        .catch(function (e) {
          status("vp_request_status", "Could not fetch the Request Object: " +
                 e.message, "vc-bad");
          renderRequest();
        });
    } else {
      renderRequest();
    }
  } else {
    // Or one already read on an earlier visit — a reload must not lose it.
    var kept = sdJwtVp.storedRequest();
    if (kept) {
      request = kept;
      renderRequest();
    } else {
      renderRequest();
    }
  }
  log.debug("SD-JWT VC presentation step 1 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  usePastedRequest: usePastedRequest,
  forgetRequest: forgetRequest,
  continueToDisclose: continueToDisclose,
  clientIdentifier: clientIdentifier,
  renderRequest: renderRequest,
  togglePane: togglePane,
  onload: onload
};
