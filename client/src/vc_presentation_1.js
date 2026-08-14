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
  log.debug("Leaving clientIdentifier(). prefix=" + prefix);
  return {
    prefix: prefix, value: id.slice(colon + 1), signable: true,
    note: "The prefix says how the wallet is meant to authenticate the " +
        "verifier and find its metadata. This " +
          "workflow implements the pre-registered and redirect_uri " +
              "cases; for " + prefix +
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
    clientMetadata: sdJwtVp.requestObjectValue(params, "client_metadata"),
    signed: false,
    signatureVerdict: ""
  };
  log.debug("Leaving adoptParams().");
  return request;
}

// A request passed by reference: fetch the Request Object and, when it is a
// signed JWT, verify it before believing a word of it.
function fetchRequestObject(uri, clientId) {
  log.debug("Entering fetchRequestObject(). uri=" + uri);
  status("vp_request_status", "Fetching the Request Object from " + uri + " …",
         "vc-pending");
  log.debug("Leaving fetchRequestObject().");
  return fetch(uri, { headers: { "Accept": "application/oauth-authz-req+jwt, " +
               "application/jwt, application/json" } })
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
        request.requestObject = body;
        request.requestObjectHeader =
            metadataClient.b64uToJson(body.split(".")[0]);
        request.requestObjectPayload = payload;
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
  return metadataClient.fetchJson(jwksUrl)
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

function renderRequestedClaims() {
  log.debug("Entering renderRequestedClaims().");
  var queries = sdJwtVp.dcqlCredentialQueries(request && request.dcql);
  if (!queries.length) {
    setHtml("vp_requested_table",
      '<tbody><tr><td>This request carries no <code>dcql_query</code>, so it ' +
          'does not say which credential ' +
      'or which claims it wants. OID4VP requires one (or a ' +
          '<code>scope</code> standing for one).</td></tr></tbody>');
    log.debug("Leaving renderRequestedClaims(). No DCQL.");
    return;
  }
  var held = heldCredential();
  var available = {};
  if (held && held.parsed) {
    // What the credential can answer with, whichever format it is: an SD-JWT's
    // Disclosures plus its plain claims, or a jwt_vc_json's credentialSubject.
    // parseCredential() reduces both to the same `claims` map, so this does not
    // have to branch — and a jwt_vc_json, whose disclosures list is empty,
    // would otherwise look like a credential that can answer nothing.
    Object.keys(held.parsed.claims ||
                {}).forEach(function (name) { available[name] = true; });
    (held.parsed.disclosures || []).forEach(function (d) {
      if (!d.error && d.name !== null) available[d.name] = true;
    });
    Object.keys(held.parsed.payload || {}).forEach(function (k) {
      if (["_sd", "_sd_alg", "cnf", "vc"].indexOf(k) === -1) available[k] =
          true;
    });
  }
  var rows = "";
  queries.forEach(function (q) {
    var paths = sdJwtVp.dcqlClaimPaths(q);
    var vcts = ((q.meta || {}).vct_values || []).join(", ");
    var heldVct = held && held.parsed ? (held.parsed.payload || {}).vct : "";
    var typeOk = !vcts || !heldVct || vcts.indexOf(heldVct) !== -1;
    rows += "<tr><td>" + esc(q.id || "—") + "</td><td>" + esc(q.format || "—") +
        "</td>" +
            '<td class="' + (typeOk ? "vc-ok" : "vc-bad") + '">' + esc(vcts ||
                "(any)") + "</td>" +
            "<td>" + (sdJwtVp.requiresKeyBinding(q) ?
                "required" : "not required") + "</td>" +
            "<td>" + (paths.length
              ? paths.map(function (p) {
                  var have = !!available[p];
                  return '<span class="' + (have ? "vc-ok" : "vc-bad") + '">' +
                      esc(p) +
                         (have ? "" : " (not in the credential you hold)") +
                          "</span>";
                }).join("<br>")
              : "(no claims named — the whole credential)") + "</td></tr>";
  });
  setHtml("vp_requested_table",
    "<thead><tr><th style='width:16%'>Query id</th><th " +
        "style='width:12%'>Format</th>" +
    "<th style='width:22%'>vct wanted</th><th style='width:12%'>Holder " +
        "binding</th>" +
    "<th>Claims asked for</th></tr></thead><tbody>" + rows + "</tbody>");
  log.debug("Leaving renderRequestedClaims().");
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
  setJson("vp_dcql", request.dcql);
  setJson("vp_client_metadata", request.clientMetadata);
  setValue("vp_request_raw", JSON.stringify(p, null, 2));
  setText("vp_signature_verdict", request.signed
    ? (request.signatureVerdict || "signed; not checked yet")
    : "This request is not signed. " + (who.signable
        ? "A pre-registered client could have signed it; this one did not."
        : "With the redirect_uri prefix it cannot be, which is by design."));
  renderRequestedClaims();

  // Everything the wallet needs before it can present anything.
  var problems = [];
  if (!p.nonce) problems.push("no nonce (nothing would stop the presentation " +
      "being replayed)");
  if (String(p.response_type ||
      "") !== "vp_token") problems.push('response_type is not "vp_token"');
  if (String(p.response_mode || "") === "direct_post" && !p.response_uri) {
    problems.push("response_mode is direct_post but there is no response_uri " +
                  "to post to");
  }
  if (!request.dcql) problems.push("no dcql_query, so the request does not " +
      "say what it wants");
  var held = heldCredential();
  // The format this verifier asked for, which is not necessarily the one in
  // hand. Empty when the query does not say, in which case there is nothing to
  // disagree with and the check below stays silent.
  var requestedFormat = sdJwtVp.firstCredentialQueryFormat(request.dcql);
  // A missing holder key is only a dead end when there is no way to supply one.
  // Since the holder key pair can be deliberately kept out of localStorage
  // (issuance step 2), "not in storage" now has two meanings, and treating them
  // alike would strand the user one page before the field that fixes it.
  var holderKeyAdvisory = null;
  if (!held) problems.push("this wallet holds no credential to present");
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
  // ldp_vc needs no holder private key at all: the bbs-2023 derived proof IS
  // the holder's act, and the credential names its subject by id rather than by
  // a cnf key the wallet must sign with. Requiring one here refused every
  // ldp_vc request for want of a key the format never uses.
  else if (held.parsed && held.parsed.format === sdJwtVc.FORMAT_LDP_VC) {
    holderKeyAdvisory = "This credential is ldp_vc with a bbs-2023 proof, so " +
        "no holder key is needed: " +
      "the derived proof itself is what proves the holder made this presentation.";
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
  if (request.signed && request.signatureValid === false) {
    problems.push("the Request Object's signature does not verify");
  }

  if (problems.length) {
    status("vp_request_status", "This request cannot be answered: " +
           problems.join("; ") + ".", "vc-bad");
    disable("vp_continue_button", true);
  } else {
    status("vp_request_status",
      "Request read" + (request.signed ? " and its signature checked" : "") +
      ". It asks for " + sdJwtVp.requestedClaims(request.dcql).length +
          " claim(s) and nothing else has to be " +
      "sent. Continue to choose what to disclose." +
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
    fetchRequestObject(params.request_uri, params.client_id)
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
      fetchRequestObject(fromQuery.request_uri, fromQuery.client_id)
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
