// File: sd_jwt_vc_issuance_3.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 3: the credential the issuer returned.
//
// Everything here is done the way a verifier would do it, in the browser:
//
//   * split the Combined Serialization on ~ (RFC 9901 section 4);
//   * verify the issuer-signed JWT against the issuer's published keys, found
//     the SD-JWT VC way — /.well-known/jwt-vc-issuer under the issuer, whose
//     document names a jwks_uri;
//   * recompute each Disclosure's digest and look it up in _sd, which is what
//     proves the disclosed claim really was in the signed credential;
//   * show the claim set that results from presenting every Disclosure.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");

var log = bunyan.createLogger({ name: 'sd_jwt_vc_issuance_3',
                                level: appconfig.LOG_LEVEL || 'info' });

// The SD-JWT VC media types: the current one and the one earlier drafts used.
var SD_JWT_VC_TYPES = ["dc+sd-jwt", "vc+sd-jwt", "application/dc+sd-jwt", "application/vc+sd-jwt"];
var JWT_VC_ISSUER_WELL_KNOWN = "/.well-known/jwt-vc-issuer";

var parsed = null;
var meta = null;

function el(id) { return document.getElementById(id); }
function setText(id, text) { var e = el(id); if (e) e.textContent = (text == null ? "" : String(text)); }
function val(id) { var e = el(id); return e ? e.value : ""; }
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

// --- the serialization, with its parts called out ---------------------------
function renderSerialized(raw) {
  var parts = String(raw).split("~");
  var html = parts.map(function (part, i) {
    if (part === "") return "";
    var cls = (i === 0) ? "vc-part-jwt" : "vc-part-disclosure";
    return '<span class="' + cls + '">' + esc(part) + "</span>";
  }).join('<span class="vc-tilde">~</span>');
  el("vc_serialized").innerHTML = html;
  el("vc_credential_raw").value = raw;
}

// --- the checks table -------------------------------------------------------
function renderChecks(checks) {
  log.debug("Entering renderChecks().");
  var rows = checks.map(function (c) {
    return "<tr>" +
      "<td>" + esc(c.name) + "</td>" +
      '<td class="' + (c.ok ? "vc-ok" : (c.warn ? "" : "vc-bad")) + '">' +
        esc(c.ok ? "OK" : (c.warn ? "NOTE" : "FAILED")) + "</td>" +
      "<td>" + esc(c.detail) + "</td>" +
      "</tr>";
  }).join("");
  el("vc_checks").innerHTML =
    "<thead><tr><th style='width:22%'>Check</th><th style='width:10%'>Result</th><th>Detail</th></tr></thead>" +
    "<tbody>" + rows + "</tbody>";
  log.debug("Leaving renderChecks().");
}

// --- disclosures ------------------------------------------------------------
function renderDisclosures(rows, sdDigests) {
  log.debug("Entering renderDisclosures().");
  var body = rows.map(function (r, i) {
    var valueText = (r.value === undefined) ? "" :
      (typeof r.value === "object" ? JSON.stringify(r.value) : String(r.value));
    return "<tr>" +
      "<td>" + (i + 1) + "</td>" +
      "<td>" + esc(r.error ? "(unreadable)" : (r.arrayElement ? "(array element)" : r.name)) + "</td>" +
      "<td>" + esc(r.error ? r.error : valueText) + "</td>" +
      '<td class="vc-mono">' + esc(r.salt) + "</td>" +
      '<td class="vc-mono">' + esc(r.digest || "") + "</td>" +
      '<td class="' + (r.inSd ? "vc-ok" : "vc-bad") + '">' + (r.inSd ? "yes" : "no") + "</td>" +
      '<td class="vc-mono">' + esc(r.encoded) + "</td>" +
      "</tr>";
  }).join("");
  el("vc_disclosures").innerHTML =
    "<thead><tr><th style='width:3%'>#</th><th style='width:12%'>Claim</th><th style='width:22%'>Value</th>" +
    "<th style='width:14%'>Salt</th><th style='width:16%'>Digest</th><th style='width:6%'>In _sd</th>" +
    "<th>Disclosure (base64url)</th></tr></thead><tbody>" + body + "</tbody>";

  var matched = rows.filter(function (r) { return r.inSd; }).length;
  var undisclosed = sdDigests.length - matched;
  el("vc_disclosure_summary").innerHTML =
    esc(rows.length + " Disclosure(s); " + matched + " matched a digest in _sd. " +
        "_sd carries " + sdDigests.length + " digest(s), so " + undisclosed +
        " digest(s) have no Disclosure here — undisclosed claims, decoys, or both. " +
        "A verifier cannot tell which, which is the point.");
  log.debug("Leaving renderDisclosures().");
}

// --- issuer key resolution --------------------------------------------------
// A did:jwk identifier IS the key: the part after the method prefix is the
// base64url JWK itself, so it resolves without a network call. walt.id's issuer
// signs with one (iss = "did:jwk:eyJrdHkiOiJFQyIs…"), and a credential whose
// key is sitting in its own iss should not be reported as unverifiable.
function jwkFromDid(iss) {
  log.debug("Entering jwkFromDid(). iss=" + String(iss).slice(0, 40));
  var prefix = "did:jwk:";
  if (String(iss || "").indexOf(prefix) !== 0) {
    log.debug("Leaving jwkFromDid(). Not a did:jwk.");
    return null;
  }
  var encoded = String(iss).slice(prefix.length).split("#")[0];
  var jwk;
  try {
    jwk = metadataClient.b64uToJson(encoded);
  } catch (e) {
    // A did:jwk whose body is not base64url JSON is simply not resolvable here;
    // the other resolution paths still get their turn.
    log.debug("Leaving jwkFromDid(). Undecodable: " + e.message);
    return null;
  }
  log.debug("Leaving jwkFromDid(). Decoded a " + (jwk && jwk.kty) + " key.");
  return jwk && jwk.kty ? jwk : null;
}

// SD-JWT VC: the issuer publishes its keys at /.well-known/jwt-vc-issuer under
// the iss value. The credential issuer metadata retrieved in step 1 is used as
// a fallback when it carries a jwks_uri of its own.
function resolveIssuerJwks(iss) {
  log.debug("Entering resolveIssuerJwks().");
  var doc = sdJwtVc.getJson("vci_info") || {};
  var direct = doc.jwks_uri;

  var embedded = jwkFromDid(iss);
  if (embedded) {
    log.debug("Leaving resolveIssuerJwks(). The key is embedded in the did:jwk iss.");
    return Promise.resolve({ jwks: { keys: [embedded] }, from: "the did:jwk in iss" });
  }
  // The well-known segment goes in front of an issuer identifier's path, not
  // after it; both forms are tried. See metadata_client.wellKnownCandidates().
  var chain = iss
    ? metadataClient.fetchWellKnown(iss, JWT_VC_ISSUER_WELL_KNOWN).then(function (found) {
        var m = found.doc;
        if (m && m.jwks) return { jwks: m.jwks, from: found.url };
        if (m && m.jwks_uri) {
          return metadataClient.fetchJson(m.jwks_uri).then(function (j) {
            return { jwks: j, from: m.jwks_uri };
          });
        }
        throw new Error("the JWT VC issuer metadata names no keys.");
      })
    : Promise.reject(new Error("the credential has no iss to resolve keys from."));
  log.debug("Leaving resolveIssuerJwks().");
  return chain.catch(function (e) {
    if (direct) {
      return metadataClient.fetchJson(direct).then(function (j) { return { jwks: j, from: direct }; });
    }
    // Last resort: the keys of the Credential Issuer this credential was asked
    // for in step 1. An issuer whose iss is not a resolvable URL (a DID method
    // this page cannot resolve, say) still publishes them under its own
    // identifier — that is where walt.id's live.
    var issuerId = doc.credential_issuer;
    if (!issuerId) throw e;
    return metadataClient.fetchWellKnown(issuerId, JWT_VC_ISSUER_WELL_KNOWN)
      .then(function (found) {
        if (found.doc && found.doc.jwks) return { jwks: found.doc.jwks, from: found.url };
        if (found.doc && found.doc.jwks_uri) {
          return metadataClient.fetchJson(found.doc.jwks_uri).then(function (j) {
            return { jwks: j, from: found.doc.jwks_uri };
          });
        }
        throw e;
      });
  });
}

// --- verification -----------------------------------------------------------
function verify() {
  log.debug("Entering verify().");
  if (!parsed) return false;
  var checks = [];
  var payload = parsed.payload || {};
  var header = parsed.header || {};

  checks.push({
    name: "Media type (typ)",
    ok: SD_JWT_VC_TYPES.indexOf(String(header.typ)) >= 0,
    warn: false,
    detail: 'typ is "' + header.typ + '"; SD-JWT VC expects dc+sd-jwt (vc+sd-jwt in earlier drafts).'
  });
  checks.push({
    name: "Signing algorithm",
    ok: !!header.alg && header.alg !== "none",
    detail: "alg is " + header.alg + (header.kid ? " (kid " + header.kid + ")" : "") + "."
  });
  checks.push({
    name: "Credential type (vct)",
    ok: !!payload.vct,
    detail: payload.vct ? String(payload.vct) : "the credential carries no vct claim."
  });
  checks.push({
    name: "Key binding (cnf)",
    ok: !!(payload.cnf && payload.cnf.jwk),
    detail: (payload.cnf && payload.cnf.jwk)
      ? "cnf.jwk holds a " + payload.cnf.jwk.kty + " key" +
        (holderKeyMatches(payload.cnf.jwk) ? " — the holder key generated in step 2." :
         " that is NOT the holder key generated in step 2.")
      : "no cnf claim: this credential is not bound to a holder key."
  });
  checks.push({
    name: "Hash algorithm (_sd_alg)",
    ok: !payload._sd_alg || String(payload._sd_alg).toLowerCase() === "sha-256",
    warn: !!payload._sd_alg && String(payload._sd_alg).toLowerCase() !== "sha-256",
    detail: payload._sd_alg ? String(payload._sd_alg) : "absent, so the default sha-256 applies."
  });
  var now = Math.floor(Date.now() / 1000);
  checks.push({
    name: "Validity window",
    ok: (!payload.exp || payload.exp > now) && (!payload.nbf || payload.nbf <= now),
    detail: "iat " + isoOf(payload.iat) + ", nbf " + isoOf(payload.nbf) + ", exp " + isoOf(payload.exp) + "."
  });
  checks.push({
    name: "Key Binding JWT",
    ok: true,
    warn: !parsed.kbJwt,
    detail: parsed.kbJwt
      ? "present — the holder proved possession of the cnf key to a verifier."
      : "absent, which is correct for a credential as issued: a KB-JWT is added when the holder PRESENTS it."
  });
  renderChecks(checks);

  // The digests, then the signature (both asynchronous).
  var sdDigests = sdJwtVc.collectSdDigests(payload);
  Promise.all((parsed.disclosures || []).map(function (d) {
    if (d.error) return Promise.resolve(Object.assign({}, d, { digest: "", inSd: false }));
    return sdJwtVc.digestForDisclosure(d.encoded, payload._sd_alg)
      .then(function (digest) {
        return Object.assign({}, d, { digest: digest, inSd: sdDigests.indexOf(digest) >= 0 });
      })
      .catch(function (e) {
        return Object.assign({}, d, { digest: "", inSd: false, error: e.message });
      });
  })).then(function (rows) {
    renderDisclosures(rows, sdDigests);
    var bad = rows.filter(function (r) { return !r.inSd; }).length;
    checks.push({
      name: "Disclosure digests",
      ok: bad === 0,
      detail: bad === 0
        ? "every Disclosure's digest appears in _sd, so each disclosed claim really is part of the signed credential."
        : bad + " Disclosure(s) hash to a digest that is not in _sd."
    });
    renderChecks(checks);
  });

  status("vc_credential_status", "Verifying the issuer's signature …", "vc-pending");
  resolveIssuerJwks(payload.iss)
    .then(function (res) {
      return metadataClient.verifyJwsWithJwks(parsed.issuerJwt, res.jwks, "the issuer-signed JWT")
        .then(function (v) { return { v: v, from: res.from }; });
    })
    .then(function (r) {
      checks.push({
        name: "Issuer signature",
        ok: r.v.valid,
        detail: (r.v.valid ? "verified" : "DOES NOT verify") + " against the keys at " + r.from +
                " (alg " + r.v.header.alg + ", kid " + r.v.kid + ")."
      });
      renderChecks(checks);
      status("vc_credential_status",
        r.v.valid ? "The credential's issuer signature is valid." : "The credential's issuer signature is INVALID.",
        r.v.valid ? "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      checks.push({ name: "Issuer signature", ok: false,
                    detail: "could not be checked: " + e.message });
      renderChecks(checks);
      status("vc_credential_status", "Could not verify the issuer signature: " + e.message, "vc-bad");
    });
  log.debug("Leaving verify().");
  return false;
}

function holderKeyMatches(jwk) {
  var holder = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK);
  if (!holder || !jwk) return false;
  return holder.kty === jwk.kty && holder.crv === jwk.crv && holder.x === jwk.x && holder.y === jwk.y;
}

function isoOf(seconds) {
  if (!seconds) return "—";
  try {
    return new Date(seconds * 1000).toISOString();
  } catch (e) {
    return String(seconds);
  }
}

// --- page actions -----------------------------------------------------------
function copyCredential() {
  var area = el("vc_credential_raw");
  area.select();
  try {
    document.execCommand("copy");
    status("vc_copy_status", "Copied.", "vc-ok");
  } catch (e) {
    status("vc_copy_status", "Could not copy: " + e.message, "vc-bad");
  }
  return false;
}

function startOver() {
  window.location.href = "/sd-jwt-vc-issuance-1.html";
  return false;
}

// Step 4: refresh this credential (OID4VCI section 14.5). A separate page
// because it is a separate pair of calls, made later — often much later, when
// the validity window is running out.
function gotoRefresh() {
  window.location.href = sdJwtVc.STEP4_URL;
  return false;
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

// ---------------------------------------------------------------------------
// A batch request returns one credential per proof (OID4VCI section 8.3). They
// are all here; showing only the first would hide the very thing a batch request
// was made to demonstrate.
// ---------------------------------------------------------------------------
var credentials = [];
var showing = 0;

function renderCredentialPicker() {
  log.debug("Entering renderCredentialPicker().");
  var row = el("vc_batch_row");
  var select = el("vc_credential_select");
  if (!row || !select) return;
  if (credentials.length <= 1) {
    row.style.display = "none";
    log.debug("Leaving renderCredentialPicker(). Only one credential.");
    return;
  }
  var keys = meta.holderJwks || [];
  select.innerHTML = credentials.map(function (c, i) {
    var key = keys[i];
    return '<option value="' + i + '"' + (i === showing ? ' selected="selected"' : '') + '>' +
           "credential " + (i + 1) + " of " + credentials.length +
           (key && key.x ? " — bound to key " + String(key.x).slice(0, 12) + "…" : "") +
           "</option>";
  }).join("");
  row.style.display = "";
  setText("vc_batch_summary", "All " + credentials.length + " were issued from one Credential Request.");
  log.debug("Leaving renderCredentialPicker().");
}

function showCredential(index) {
  log.debug("Entering showCredential(). index=" + index);
  var raw = credentials[index] || "";
  if (!raw) {
    log.debug("Leaving showCredential(). Nothing at that index.");
    return false;
  }
  showing = index;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    status("vc_credential_status", "That credential could not be parsed: " + e.message, "vc-bad");
    el("vc_credential_raw").value = raw;
    return false;
  }
  renderSerialized(raw);
  el("vc_credential_raw").value = raw;
  setJson("vc_jwt_header", parsed.header);
  setJson("vc_jwt_payload", parsed.payload);
  setJson("vc_claims", sdJwtVc.disclosedClaims(parsed));
  status("vc_credential_status",
    "Credential parsed: " + parsed.disclosures.length + " Disclosure(s)" +
    (parsed.kbJwt ? " and a Key Binding JWT" : "") +
    (credentials.length > 1 ? " (credential " + (showing + 1) + " of " + credentials.length + ")" : "") +
    (meta.encrypted ? ", from an encrypted Credential Response" : "") + ".", "vc-ok");
  verify();
  log.debug("Leaving showCredential().");
  return true;
}

function onCredentialChange() {
  var select = el("vc_credential_select");
  if (select) showCredential(parseInt(select.value, 10) || 0);
  return true;
}

// ---------------------------------------------------------------------------
// The Notification Endpoint (OID4VCI section 11): what the wallet did with the
// credential. Optional for the wallet, which is why this is a button and not
// something that happens on load — an issuer cannot assume it will be told.
// ---------------------------------------------------------------------------
function notificationBody() {
  var body = { notification_id: meta.notificationId || "", event: val("vc_notification_event") || "credential_accepted" };
  var description = (val("vc_notification_description") || "").trim();
  if (description) body.event_description = description;
  return body;
}

function renderNotification() {
  log.debug("Entering renderNotification().");
  var pane = el("pane_notification");
  if (!pane) return false;
  var endpoint = meta.notificationEndpoint || "";
  var id = meta.notificationId || "";
  setText("vc_notification_id", id || "— none returned —");
  setText("vc_notification_endpoint", endpoint || "— this issuer publishes none —");
  if (!id || !endpoint) {
    // Nothing to send, and saying why is more useful than a dead button.
    setValue("vc_notification_request", "");
    if (el("vc_notification_button")) el("vc_notification_button").disabled = true;
    status("vc_notification_status", !endpoint
      ? "This issuer publishes no notification_endpoint, so there is nowhere to report to."
      : "The Credential Response carried no notification_id, so the issuer is not asking to be told.",
      "vc-pending");
    log.debug("Leaving renderNotification(). Nothing to send.");
    return false;
  }
  var body = JSON.stringify(notificationBody(), null, 2);
  setValue("vc_notification_request", [
    "POST " + endpoint,
    "Content-Type: application/json",
    "Authorization: Bearer " + (sdJwtVc.get("token_access_token") || "(no access token)"),
    "Content-Length: " + body.length,
    "",
    body
  ].join("\n"));
  log.debug("Leaving renderNotification().");
  return true;
}

function sendNotification() {
  log.debug("Entering sendNotification().");
  var endpoint = meta.notificationEndpoint || "";
  var body = notificationBody();
  if (!endpoint || !body.notification_id) {
    status("vc_notification_status", "There is nothing to notify: no endpoint or no notification_id.", "vc-bad");
    return false;
  }
  el("vc_notification_button").disabled = true;
  status("vc_notification_status", "Sending the notification …", "vc-pending");
  fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (sdJwtVc.get("token_access_token") || "")
    },
    body: JSON.stringify(body)
  })
    .then(function (r) {
      return r.text().then(function (text) {
        // 204 with no body is success (section 11.2); anything else should say why.
        if (r.status === 204) {
          status("vc_notification_status",
            "The issuer accepted the notification: " + body.event + " (204, no body).", "vc-ok");
          return;
        }
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is what gets shown.
        }
        var why = (parsed && (parsed.error_description || parsed.error)) || text || ("HTTP " + r.status);
        status("vc_notification_status", "The issuer refused the notification: " + why, "vc-bad");
        el("vc_notification_button").disabled = false;
      });
    })
    .catch(function (e) {
      log.error("the notification failed: " + e.message);
      status("vc_notification_status", "The notification failed: " + e.message, "vc-bad");
      el("vc_notification_button").disabled = false;
    });
  log.debug("Leaving sendNotification().");
  return false;
}

// Step 4 refreshes whatever the wallet is holding, so it has nothing to work
// with if nothing is held. A button rather than a redirect, matching step 4's own
// "Verify in step 3": the page does not move the browser out from under someone
// still reading the credential above.
function refreshInStepFour() {
  log.debug("Entering refreshInStepFour().");
  if (!(sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "").trim()) {
    // Say so here rather than sending them to a page that can only report the
    // same emptiness one navigation later.
    status("vc_next_status", "There is no credential in this wallet to refresh yet.", "vc-bad");
    log.debug("Leaving refreshInStepFour(). Nothing held.");
    return false;
  }
  window.location.href = sdJwtVc.STEP4_URL;
  log.debug("Leaving refreshInStepFour().");
  return false;
}

// The other thing to do with a verified credential: show it to a Verifier. This
// copies nothing — the presentation workflow reads the same storage keys this
// page does — so it is a navigation, and the only question worth answering
// before navigating is whether that workflow could get anywhere.
function presentIt() {
  log.debug("Entering presentIt().");
  var readiness = sdJwtVc.presentationReadiness();
  if (!readiness.ready) {
    status("vc_present_status", readiness.message, readiness.level);
    log.debug("Leaving presentIt(). Not ready.");
    return false;
  }
  window.location.href = sdJwtVc.PRESENTATION_URL;
  log.debug("Leaving presentIt().");
  return false;
}

// Reflect on load whether either next step has anything to act on, so both offers
// are honest before they are clicked rather than after.
function renderNextStep() {
  var held = (sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "").trim();
  var button = document.getElementById("vc_goto_step4_button");
  if (button) button.disabled = !held;
  if (!held) {
    status("vc_next_status", "Nothing is held yet — step 4 refreshes a credential this wallet already has.", "");
  } else {
    status("vc_next_status", "", "");
  }

  var readiness = sdJwtVc.presentationReadiness();
  var present = document.getElementById("vc_present_button");
  if (present) present.disabled = !readiness.ready;
  status("vc_present_status", readiness.message, readiness.level);
}

function onload() {
  log.debug("Entering onload().");
  sdJwtVc.renderUseCaseBadge();
  var step = document.getElementById("vc_step_3");
  if (step) step.className = "vc-step-current";
  ["vc_step_0", "vc_step_1", "vc_step_2"].forEach(function (id) {
    var e = document.getElementById(id);
    if (e) e.className = "vc-step-done";
  });

  // Before the early return below: when nothing is held onload stops there, and
  // that is precisely the case this offer has to describe.
  renderNextStep();

  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  meta = sdJwtVc.getJson(sdJwtVc.KEYS.CREDENTIAL_META) || {};
  setText("vc_meta_issuer", meta.issuer ? meta.issuer + "  (" + (meta.endpoint || "") + ")" : "—");
  // How this credential was obtained, in one line: what was asked for, when, and
  // the things about the exchange that are not visible in the credential itself.
  var provenance = meta.configurationId
    ? meta.configurationId + " / " + (meta.format || "?") + " / vct " + (meta.vct || "?") +
      " — requested " + (meta.requestedAt || "?")
    : "—";
  if (meta.configurationId) {
    if (meta.credentialCount > 1) provenance += " — " + meta.credentialCount + " credentials in one response";
    if (meta.encrypted) provenance += " — the Credential Response was encrypted";
    if (meta.deferred) {
      provenance += " — deferred, collected after " + (meta.deferredAttempts || "?") + " attempt(s)";
    }
    // A refreshed credential is not the one step 2 obtained, and step 3 should
    // not read as though it were (OID4VCI section 14.5).
    if (meta.refreshGeneration) {
      provenance += " — refreshed " + meta.refreshGeneration +
                    (meta.refreshGeneration === 1 ? " time" : " times") +
                    (meta.keyMode === "reuse" ? ", still bound to the original holder key"
                                              : ", bound to a new holder key");
    }
  }
  setText("vc_meta_request", provenance);

  if (!raw) {
    status("vc_credential_status",
      "No credential yet. Run step 1 (discovery), authenticate, then approve issuance in step 2.", "vc-bad");
    return;
  }
  credentials = sdJwtVc.getJson(sdJwtVc.KEYS.CREDENTIALS) || [raw];
  if (!credentials.length) credentials = [raw];
  renderCredentialPicker();
  showCredential(0);
  renderNotification();
  log.debug("SD-JWT VC issuance step 3 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  verify: verify,
  onCredentialChange: onCredentialChange,
  renderNotification: renderNotification,
  sendNotification: sendNotification,
  copyCredential: copyCredential,
  startOver: startOver,
  gotoRefresh: gotoRefresh,
  togglePane: togglePane,
  refreshInStepFour: refreshInStepFour,
  presentIt: presentIt,
  onload: onload
};
