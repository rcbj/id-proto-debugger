// File: vc_issuance_4.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 4: refreshing the credential.
//
// A credential does not last forever. Its claim values go out of date and its
// validity window runs out, and OID4VCI section 14.5 ("Refreshing Issued
// Credentials") names the two ways to deal with that:
//
//   1. the Wallet asks the Credential Endpoint again with a valid Access Token.
//      No End-User interaction. If the issuer gave the wallet a Refresh Token,
//      the wallet first gets a fresh Access Token from the Token Endpoint
//      (RFC 6749 section 6);
//   2. the issuer reissues the credential by starting the whole issuance again,
//      which DOES involve the End-User — the only route left when the wallet
//      holds neither a valid Access Token nor a valid Refresh Token.
//
// This page is the first mechanism, in the two calls it is made of:
//
//   pane 2   POST the Token Endpoint with grant_type=refresh_token
//   pane 3   POST the Credential Endpoint again — the same Credential Request
//            step 2 makes, with a proof of possession over a fresh c_nonce
//
// and then a fourth pane comparing what came back with what the wallet already
// had, because "it worked" is not the interesting part: WHAT the issuer changed
// is. Section 14.5 leaves that to the issuer ("whether to update both the
// signature and the claim values, or only the signature"), and section 14.3
// says the same of asking again with the same Access Token — the issuer decides
// whether the answer is the same credential or an updated one.
//
// The refreshed credential is kept apart from the one in hand until the holder
// says to replace it. That is also section 14.5: a wallet that ends up with two
// credentials of the same type and no idea which is current has made things
// worse, so the choice is put in front of whoever is looking.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var vciWallet = require("./vci_wallet");

var log = bunyan.createLogger({ name: 'vc_issuance_4',
                                level: appconfig.LOG_LEVEL || 'info' });

var REFRESH_GRANT = "refresh_token";

// The credential the wallet holds, the one a refresh produced, and everything
// built along the way. Rebuilt from local storage on load, so the page survives
// a reload with the refreshed credential intact.
var state = {
  config: null,
  // { raw, parsed, meta } for the credential in hand.
  current: null,
  // The Credential Request being assembled: keys, nonce, proof, body.
  request: { holderKeys: [], nonce: "", proofs: [], body: null, encryption: null },
  // Whether the access token about to be spent came from the Token Endpoint on
  // this page, or is the one the page arrived with (section 14.3's route). The
  // history says which, because they are different things to have done.
  accessTokenRefreshed: false,
  // { raw, all, meta, response } once the issuer has answered.
  refreshed: null,
  // The deferred issuance a refresh can also turn into (section 9). historyId is
  // the log row for the poll that is waiting to be resolved.
  deferred: { transactionId: "", intervalSeconds: 0, attempts: [], historyId: 0 }
};

function el(id) { return document.getElementById(id); }
function setText(id, text) { var e = el(id); if (e) e.textContent = (text == null ? "" : String(text)); }
function setHtml(id, html) { var e = el(id); if (e) e.innerHTML = html; }
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
function show(id, visible) { var e = el(id); if (e) e.style.display = visible ? "" : "none"; }
function disable(id, disabled) { var e = el(id); if (e) e.disabled = !!disabled; }
function esc(v) { return metadataClient.escapeHtmlText(v); }

function isoOf(seconds) {
  if (!seconds) return "—";
  try {
    return new Date(seconds * 1000).toISOString();
  } catch (e) {
    // A claim that is not a number of seconds at all: show it as it stands
    // rather than inventing a date for it.
    return String(seconds);
  }
}

// "in 29 days", "12 minutes ago" — a validity window is only meaningful next to
// now, and "1791234567" is not.
function relativeTo(seconds) {
  log.debug("Entering relativeTo(). seconds=" + seconds);
  if (!seconds) {
    log.debug("Leaving relativeTo(). No time to relate to.");
    return "";
  }
  var delta = Number(seconds) - Math.floor(Date.now() / 1000);
  var ahead = delta >= 0;
  var amount = Math.abs(delta);
  var unit = "second";
  var scale = [["minute", 60], ["hour", 60], ["day", 24]];
  for (var i = 0; i < scale.length && amount >= scale[i][1]; i++) {
    amount = Math.floor(amount / scale[i][1]);
    unit = scale[i][0];
  }
  var text = amount + " " + unit + (amount === 1 ? "" : "s");
  log.debug("Leaving relativeTo(). " + text + (ahead ? " ahead." : " ago."));
  return ahead ? "in " + text : text + " ago";
}

// --- what a JWT says about itself, for the access tokens shown here ---------
function jwtClaims(token) {
  var parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    return metadataClient.b64uToJson(parts[1]);
  } catch (e) {
    // Not a JWT this page can read; it is still a perfectly good bearer token.
    return null;
  }
}

// A token identified without printing the whole thing: enough to see that two
// tokens differ, and when this one runs out.
function describeToken(token) {
  if (!token) return "— none —";
  var claims = jwtClaims(token);
  var head = String(token).slice(0, 16) + "…" + String(token).slice(-6);
  if (!claims) return head + " (opaque — not a JWT this page can read)";
  return head + " — issued " + isoOf(claims.iat) + ", expires " + isoOf(claims.exp) +
         " (" + relativeTo(claims.exp) + ")" +
         (claims.scope ? ", scope " + claims.scope : "");
}

// ---------------------------------------------------------------------------
// Pane 1: the credential in hand.
//
// Why anyone would refresh: the validity window, and how much of it is left.
// ---------------------------------------------------------------------------
function loadCurrentCredential() {
  log.debug("Entering loadCurrentCredential().");
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  var meta = sdJwtVc.getJson(sdJwtVc.KEYS.CREDENTIAL_META) || {};
  if (!raw) {
    state.current = null;
    log.debug("Leaving loadCurrentCredential(). There is no credential.");
    return null;
  }
  var parsed;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    log.error("the stored credential could not be parsed: " + e.message);
    state.current = { raw: raw, parsed: null, meta: meta, error: e.message };
    log.debug("Leaving loadCurrentCredential(). Unparseable.");
    return state.current;
  }
  state.current = { raw: raw, parsed: parsed, meta: meta };
  log.debug("Leaving loadCurrentCredential().");
  return state.current;
}

function renderCurrentCredential() {
  log.debug("Entering renderCurrentCredential().");
  if (!state.current) {
    setText("vc_current_vct", "—");
    setText("vc_current_validity", "—");
    setText("vc_current_binding", "—");
    setText("vc_current_provenance", "—");
    status("vc_current_status",
      "There is no credential to refresh. Run steps 1 to 3 first — a refresh asks the issuer for a new " +
      "version of a credential the wallet already has.", "vc-bad");
    log.debug("Leaving renderCurrentCredential(). Nothing held.");
    return;
  }
  var meta = state.current.meta || {};
  var payload = (state.current.parsed && state.current.parsed.payload) || {};
  setText("vc_current_vct", payload.vct || "—");
  var expired = payload.exp && payload.exp <= Math.floor(Date.now() / 1000);
  setText("vc_current_validity",
    "nbf " + isoOf(payload.nbf) + ", exp " + isoOf(payload.exp) + " — " +
    (payload.exp ? (expired ? "EXPIRED " + relativeTo(payload.exp)
                            : "valid, expires " + relativeTo(payload.exp))
                 : "no exp claim, so it does not expire on its own"));
  var cnf = (payload.cnf && payload.cnf.jwk) || null;
  setText("vc_current_binding", cnf
    ? cnf.kty + " " + (cnf.crv || "") + " key " + String(cnf.x || "").slice(0, 16) + "…" +
      (holderKeyIsHeld(cnf) ? " — the holder key this browser generated"
                            : " — NOT a holder key this browser still has, so a proof for it cannot be signed")
    : "no cnf claim: this credential is not bound to a holder key");
  var provenance = (meta.configurationId || "?") + " from " + (meta.issuer || "?") +
                   ", requested " + (meta.requestedAt || "?");
  if (meta.refreshGeneration) {
    provenance += " — refreshed " + meta.refreshGeneration +
                  (meta.refreshGeneration === 1 ? " time" : " times") +
                  (meta.refreshedAt ? ", last at " + meta.refreshedAt : "");
  }
  setText("vc_current_provenance", provenance);

  if (state.current.error) {
    status("vc_current_status", "The stored credential could not be parsed: " + state.current.error, "vc-bad");
  } else if (expired) {
    status("vc_current_status",
      "This credential has expired. A refresh is exactly what section 14.5 is for — and if the Refresh Token " +
      "has expired too, the issuance has to start again from step 1.", "vc-pending");
  } else {
    status("vc_current_status",
      "This credential is still valid. Refreshing it anyway is legitimate: section 14.3 says the Credential " +
      "Endpoint may be asked again, and the issuer decides whether the answer is the same credential or an " +
      "updated one.", "vc-ok");
  }
  log.debug("Leaving renderCurrentCredential().");
}

// Whether the private half of the key a credential is bound to is still in this
// browser. Without it no proof of possession can be signed for that key, so a
// refresh would have to bind the new credential to a different one.
function holderKeyIsHeld(jwk) {
  if (!jwk) return false;
  // "Held" means a private half is AVAILABLE to sign with — from storage, or
  // from the field the user pasted the downloaded key into when holder key
  // saving is off on step 2.
  var available = sdJwtVc.readHolderPrivateJwk("vc_holder_private_jwk").jwk;
  if (!available) return false;
  // Compare that key's OWN public coordinates against what the credential is
  // bound to, rather than the separately stored public half. With saving off,
  // step 2 generates a fresh pair on every visit and stores only the public
  // half, so the stored value can easily belong to a different key than the one
  // just pasted here — trusting it would refuse a reuse that is perfectly valid.
  // An EC private JWK carries x/y, so it can answer for itself.
  return available.kty === jwk.kty && available.crv === jwk.crv &&
         available.x === jwk.x && available.y === jwk.y;
}

// ---------------------------------------------------------------------------
// The credential history pane.
//
// The same idea as the Token History pane on debugger2.html, but it records more
// than debugger2 does: **every attempt**, not only the ones that produced
// something the wallet kept. One row per attempt, newest first —
//
//   the issuance from step 2                       outcome: kept
//   an access-token refresh (RFC 6749 section 6)    success / failed
//   a Credential Request (section 14.5 / 14.3)      pending / failed / deferred
//   a poll of the Deferred Credential Endpoint      deferred / pending / failed
//   what the holder then decided                    kept / discarded
//
// — because "I tried to refresh and it did not work" is the case a debugger is
// most needed for, and a pane that shows only successes cannot tell you whether
// the request was refused, deferred, or never made.
//
// The rows the wallet HOLDS (outcome kept, with a credential) are the generations
// the navigation moves between; a log row cannot be activated, and says so. Being
// able to go BACK matters: a refresh that turned out worse than what it replaced
// is a real outcome, and a wallet that cannot return to the credential that was
// working is not much of a debugger.
// ---------------------------------------------------------------------------
var KIND_LABEL = {
  issuance: "Issuance (step 2)",
  token_refresh: "Access token refresh",
  credential_request: "Credential Request",
  deferred_poll: "Deferred collection"
};

var OUTCOME_LABEL = {
  success: "success",
  failed: "FAILED",
  deferred: "deferred",
  pending: "returned — not kept yet",
  kept: "kept",
  discarded: "discarded"
};

// success and kept read as good; a refusal reads as bad; everything else is a
// state you are in the middle of.
var OUTCOME_CLASS = {
  success: "vc-ok",
  kept: "vc-ok",
  failed: "vc-bad",
  discarded: "",
  deferred: "",
  pending: ""
};

// Two numbers, and every row has the first of them: `#` counts the attempts in
// the order they were made, so nothing in the log is unnumbered; `Gen` is the
// generation number, which only the rows the wallet HOLDS have, because only those
// are credentials it can go back to.
function historyTableHead() {
  return '<table class="vc-table"><thead><tr>' +
         "<th style='width:4%'>#</th><th style='width:5%'>Gen</th>" +
         "<th style='width:10%'>When</th><th style='width:13%'>Attempt</th>" +
         "<th style='width:11%'>Outcome</th><th style='width:24%'>What happened</th>" +
         "<th style='width:18%'>Credential</th><th>Action</th></tr></thead><tbody>";
}

// What the row says about the credential an attempt produced, if it produced one.
function credentialCell(entry) {
  var s = entry.summary || {};
  if (!entry.credential) return "&mdash;";
  var lines = [];
  if (s.vct) lines.push(esc(s.vct));
  lines.push("expires " + esc(isoOf(s.exp)) + (s.exp ? " (" + esc(relativeTo(s.exp)) + ")" : ""));
  lines.push("key " + esc(String(s.boundKey || "—").slice(0, 10)) + (s.boundKey ? "…" : ""));
  lines.push("sig " + esc(String(s.signature || "—").slice(0, 10)) + (s.signature ? "…" : ""));
  lines.push((s.disclosures || 0) + " disclosure(s)");
  return '<span style="font-size:90%;">' + lines.join("<br>") + "</span>";
}

function historyRow(entry, attemptNumber, generation, isActive) {
  var outcome = entry.outcome || "success";
  var classes = [];
  if (isActive) classes.push("vc-history-active");
  if (outcome === sdJwtVc.HISTORY_OUTCOME.PENDING) classes.push("vc-history-pending");
  var html = "<tr" + (classes.length ? ' class="' + classes.join(" ") + '"' : "") + ">";
  html += "<td>" + attemptNumber + "</td>";
  html += "<td>" + (generation ? generation : "&mdash;") + "</td>";
  html += '<td style="font-size:80%;">' + esc(String(entry.at || "").substring(0, 10)) + "<br>" +
          esc(String(entry.at || "").substring(11, 19)) + "</td>";
  html += "<td>" + esc(KIND_LABEL[entry.kind] || entry.kind || "") + "</td>";
  html += '<td class="' + (OUTCOME_CLASS[outcome] || "") + '">' +
          esc(OUTCOME_LABEL[outcome] || outcome) + "</td>";
  html += '<td style="font-size:90%;">' + esc(entry.detail || "") + "</td>";
  html += "<td>" + credentialCell(entry) + "</td>";
  html += "<td>";
  if (outcome === sdJwtVc.HISTORY_OUTCOME.PENDING) {
    html += '<input class="btn2" type="button" value="Keep" onclick="return vcissuance4.replaceCredential();" /> ' +
            '<input class="btn2" type="button" value="Discard" onclick="return vcissuance4.discardRefreshed();" />';
  } else if (isActive) {
    html += "<strong>In hand</strong>";
  } else if (generation) {
    html += '<input class="btn2" type="button" value="Activate" ' +
            'onclick="return vcissuance4.activateGeneration(' + entry.id + ');" />';
  } else {
    // A log row: nothing to activate, and saying so beats an empty cell.
    html += '<span class="vc-note">log only</span>';
  }
  html += "</td></tr>";
  return html;
}

function renderHistory() {
  log.debug("Entering renderHistory().");
  // Which generation is in hand is exactly what the presentation offer names, and
  // every path that changes it comes through here — keeping, discarding,
  // activating, stepping and clearing — so the offer is rebuilt with the table
  // rather than at each of those call sites. It goes at the TOP because the
  // empty-history return below is itself a state the offer has to describe
  // (nothing held, nothing to present), and this function only reads state.
  renderPresentOffer();
  var history = sdJwtVc.credentialHistory();
  var active = sdJwtVc.activeGeneration();
  var dropped = sdJwtVc.droppedGenerations();
  var held = sdJwtVc.heldGenerations();
  var generationOf = {};
  held.forEach(function (h) { generationOf[h.id] = h.generation; });

  var navButtons = ["vc_history_oldest_button", "vc_history_older_button", "vc_history_newer_button",
                    "vc_history_latest_button"];
  if (!history.length) {
    setHtml("vc_history_table", "");
    setText("vc_history_position", "nothing recorded yet");
    navButtons.concat(["vc_history_clear_button"]).forEach(function (id) { disable(id, true); });
    status("vc_history_status",
      "Nothing has been recorded yet. Every attempt on this page — refreshing the access token, asking the " +
      "Credential Endpoint, and what you then decided — is added here, and this is where you move between the " +
      "credentials the wallet has held.", "vc-pending");
    log.debug("Leaving renderHistory(). Empty.");
    return false;
  }

  var pending = history.filter(function (e) {
    return e.outcome === sdJwtVc.HISTORY_OUTCOME.PENDING;
  }).length;
  var failures = history.filter(function (e) {
    return e.outcome === sdJwtVc.HISTORY_OUTCOME.FAILED;
  }).length;
  setText("vc_history_position",
    (active ? "generation " + active.generation + " of " + active.total : "no generation in hand") +
    " — " + history.length + " attempt(s) recorded" +
    (failures ? ", " + failures + " failed" : "") +
    (pending ? ", " + pending + " waiting to be kept" : "") +
    (dropped ? " (" + dropped + " earlier generation(s) no longer kept)" : ""));

  var atOldest = !active || active.index <= 0;
  var atNewest = !active || active.index >= active.total - 1;
  disable("vc_history_oldest_button", atOldest);
  disable("vc_history_older_button", atOldest);
  disable("vc_history_newer_button", atNewest);
  disable("vc_history_latest_button", atNewest);
  disable("vc_history_clear_button", false);

  // One table, newest attempt first. Deliberately NOT grouped by credential type
  // any more: an access-token refresh has no vct, and a log of attempts only makes
  // sense in the order they were made.
  // The newest HISTORY_LIMIT attempts, newest first. The list is capped rather
  // than allowed to grow without limit, and it says so when it has to cap.
  var shown = history.slice(-sdJwtVc.HISTORY_LIMIT);
  var firstShown = history.length - shown.length;
  var html = historyTableHead();
  shown.slice().reverse().forEach(function (entry, i) {
    // Newest first, so the newest row carries the highest attempt number.
    var attemptNumber = firstShown + shown.length - i;
    html += historyRow(entry, attemptNumber, generationOf[entry.id], !!(active && active.id === entry.id));
  });
  html += "</tbody></table>";
  if (firstShown > 0) {
    html += '<p class="vc-note">The newest ' + sdJwtVc.HISTORY_LIMIT + " attempts are shown; " + firstShown +
            " older one(s) are no longer kept.</p>";
  }
  setHtml("vc_history_table", html);
  log.debug("Leaving renderHistory(). " + history.length + " attempt(s), " + shown.length + " shown, " +
            held.length + " generation(s), active " + (active ? active.generation : "none") + ".");
  return true;
}

// Everything on the page that depends on WHICH generation is in hand. Activating
// a different one changes the credential the proof of possession will be bound to
// and what a comparison is against, so both are rebuilt rather than left showing
// the previous generation's state.
function reloadHeldCredential(historyMessage, reissueMessage) {
  log.debug("Entering reloadHeldCredential().");
  loadCurrentCredential();
  renderCurrentCredential();
  renderHistory();
  renderReissue();
  if (state.refreshed) renderComparison();
  prepareReissue().then(function (ready) {
    renderReissue();
    if (ready) {
      // Set here rather than before the rebuild, or the message would claim a
      // request that has not been built yet.
      status("vc_reissue_status", reissueMessage ||
        "The request below is built for the generation now in hand, and is what will be sent.", "vc-ok");
    }
  });
  if (historyMessage) status("vc_history_status", historyMessage, "vc-ok");
  log.debug("Leaving reloadHeldCredential().");
}

function activateGeneration(id) {
  log.debug("Entering activateGeneration(). id=" + id);
  var entry = sdJwtVc.activateCredentialGeneration(id);
  if (!entry) {
    status("vc_history_status",
      "That generation is no longer in the history — a log row cannot be activated, and a trimmed one is gone.",
      "vc-bad");
    log.debug("Leaving activateGeneration(). No such generation.");
    return false;
  }
  var active = sdJwtVc.activeGeneration();
  reloadHeldCredential(
    "Generation " + active.generation + " of " + active.total + " (" +
    (entry.source || entry.kind || "issued") + ", recorded " + (entry.at || "?") +
    ") is now the credential the wallet holds, with the holder key it is bound to. " +
    (active.generation < active.total
      ? "It is not the newest one — which is a legitimate place to be, and what a wallet does when a refresh " +
        "turned out worse than what it replaced."
      : "It is the newest generation."));
  log.debug("Leaving activateGeneration().");
  return false;
}

// Backwards and forwards through the generations the wallet HELD — the log rows in
// between (a refused refresh, a discarded credential) are not places to be.
function historyStep(delta) {
  log.debug("Entering historyStep(). delta=" + delta);
  var held = sdJwtVc.heldGenerations();
  var active = sdJwtVc.activeGeneration();
  var target = active ? active.index + delta : -1;
  if (!held.length || target < 0 || target >= held.length) {
    status("vc_history_status", delta < 0
      ? "This is the oldest generation the history still has."
      : "This is the newest generation — a refresh above is what adds another.", "vc-pending");
    log.debug("Leaving historyStep(). Out of range.");
    return false;
  }
  log.debug("Leaving historyStep(). Moving to generation " + (target + 1) + ".");
  return activateGeneration(held[target].id);
}

function historyOlder() { return historyStep(-1); }
function historyNewer() { return historyStep(1); }

function historyJump(toEnd) {
  log.debug("Entering historyJump(). toEnd=" + toEnd);
  var held = sdJwtVc.heldGenerations();
  if (!held.length) {
    log.debug("Leaving historyJump(). No generations recorded.");
    return false;
  }
  log.debug("Leaving historyJump().");
  return activateGeneration(toEnd ? held[held.length - 1].id : held[0].id);
}

function historyOldest() { return historyJump(false); }
function historyLatest() { return historyJump(true); }

// Forgetting the list is not the same as giving up the credential: whatever is in
// hand stays in hand, and says so.
function clearHistory() {
  log.debug("Entering clearHistory().");
  sdJwtVc.clearCredentialHistory();
  renderHistory();
  status("vc_history_status",
    "The history was cleared. The credential the wallet holds is untouched — only the record of the earlier " +
    "generations is gone, so there is nothing left to navigate back to.", "vc-pending");
  log.debug("Leaving clearHistory().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 2: the Token Request (RFC 6749 section 6).
//
// grant_type=refresh_token, and nothing else about it is OID4VCI-specific: this
// is plain OAuth 2.0, which is the point section 14.5 is making. What IS
// specific is why the wallet wants it — the access token is about to be spent on
// the Credential Endpoint again.
// ---------------------------------------------------------------------------
function refreshParams() {
  log.debug("Entering refreshParams().");
  var refreshToken = sdJwtVc.get("token_refresh_token") || "";
  if (!refreshToken) {
    log.debug("Leaving refreshParams(). There is no refresh token.");
    return null;
  }
  var params = { grant_type: REFRESH_GRANT, refresh_token: refreshToken };
  var clientId = sdJwtVc.get("token_client_id") || sdJwtVc.get("client_id") || "";
  if (clientId) params.client_id = clientId;
  // A confidential client has to authenticate to the token endpoint. The secret
  // is whatever the OAuth2 pages were configured with; a public client (which is
  // what the workflow uses by default) has none and sends none.
  var secret = sdJwtVc.get("client_secret") || "";
  if (secret) params.client_secret = secret;
  // OPTIONAL, and narrowing only: RFC 6749 section 6 allows a scope no broader
  // than the one originally granted. Empty means "the same as before".
  var scope = (val("vc_refresh_scope") || "").trim();
  if (scope) params.scope = scope;
  log.debug("Leaving refreshParams().");
  return params;
}

function renderRefreshRequest() {
  log.debug("Entering renderRefreshRequest().");
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  var refreshToken = sdJwtVc.get("token_refresh_token") || "";
  setValue("vc_refresh_token_value", refreshToken);
  setText("vc_refresh_endpoint", endpoint || "— none configured —");
  setText("vc_refresh_current_access_token", describeToken(sdJwtVc.get("token_access_token") || ""));

  var params = refreshParams();
  if (!params) {
    setValue("vc_refresh_request", "");
    disable("vc_refresh_button", true);
    status("vc_refresh_status",
      "There is no refresh token. The authorization server did not issue one — OID4VCI's pre-authorized code " +
      "flow (H.2/H.3) normally does not — so this half cannot run. Section 14.5's other two routes are still " +
      "open: ask the Credential Endpoint again with the access token below (section 14.3), or start the " +
      "issuance over from step 1.", "vc-pending");
    log.debug("Leaving renderRefreshRequest(). Nothing to send.");
    return "";
  }
  if (!endpoint) {
    setValue("vc_refresh_request", "");
    disable("vc_refresh_button", true);
    status("vc_refresh_status",
      "No token_endpoint is configured. Retrieve the authorization server metadata in step 1.", "vc-bad");
    log.debug("Leaving renderRefreshRequest(). No endpoint.");
    return "";
  }
  var text = vciWallet.describeCall({
    method: "POST",
    url: endpoint,
    contentType: "application/x-www-form-urlencoded",
    body: vciWallet.encodeForm(params)
  });
  setValue("vc_refresh_request", text);
  disable("vc_refresh_button", false);
  log.debug("Leaving renderRefreshRequest().");
  return text;
}

function onRefreshScopeChange() {
  renderRefreshRequest();
  return true;
}

function sendRefreshRequest() {
  log.debug("Entering sendRefreshRequest().");
  var params = refreshParams();
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  if (!params || !endpoint) {
    status("vc_refresh_status", "There is nothing to send: no refresh token, or no token endpoint.", "vc-bad");
    return false;
  }
  var previousAccess = sdJwtVc.get("token_access_token") || "";
  var previousRefresh = params.refresh_token;
  disable("vc_refresh_button", true);
  status("vc_refresh_status", "Exchanging the refresh token for a fresh access token …", "vc-pending");
  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: vciWallet.encodeForm(params)
  })
    .then(function (r) {
      return r.text().then(function (text) {
        var body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is what gets shown.
        }
        return { ok: r.ok, statusCode: r.status, body: body, raw: text };
      });
    })
    .then(function (response) {
      var box = el("vc_refresh_response");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      }
      if (!response.ok || !response.body || !response.body.access_token) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        // A refused refresh is exactly the attempt worth having a record of.
        sdJwtVc.recordHistoryEntry({
          kind: sdJwtVc.HISTORY_KIND.TOKEN_REFRESH,
          outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
          detail: "HTTP " + response.statusCode + " from " + endpoint + " — " + err
        });
        renderHistory();
        status("vc_refresh_status",
          "The token endpoint refused the refresh: " + err +
          " A refresh token that has expired or been revoked leaves only one route — start the issuance " +
          "again from step 1 (section 14.5).", "vc-bad");
        disable("vc_refresh_button", false);
        log.debug("Leaving sendRefreshRequest(). Refused: " + err);
        return;
      }
      // Stored under the same names the OIDC leg uses, so everything downstream —
      // this page, step 2, token_detail.html — reads it without knowing which
      // call produced it.
      sdJwtVc.set("token_access_token", response.body.access_token);
      state.accessTokenRefreshed = true;
      if (response.body.id_token) sdJwtVc.set("token_id_token", response.body.id_token);
      var rotated = false;
      if (response.body.refresh_token) {
        rotated = response.body.refresh_token !== previousRefresh;
        sdJwtVc.set("token_refresh_token", response.body.refresh_token);
      }
      status("vc_refresh_status",
        "A fresh access token was issued" +
        (response.body.access_token === previousAccess
          ? " — and it is the same string as the old one, which is unusual but not forbidden."
          : ", replacing the one above.") +
        (response.body.refresh_token
          ? (rotated
              ? " The refresh token was rotated too, so the old one should be considered spent."
              : " The same refresh token came back, so it can be used again.")
          : " No new refresh token came back, so the old one still stands."),
        "vc-ok");
      var newClaims = jwtClaims(response.body.access_token) || {};
      sdJwtVc.recordHistoryEntry({
        kind: sdJwtVc.HISTORY_KIND.TOKEN_REFRESH,
        outcome: sdJwtVc.HISTORY_OUTCOME.SUCCESS,
        detail: "a fresh access token" +
                (newClaims.exp ? " expiring " + isoOf(newClaims.exp) : "") +
                (response.body.refresh_token
                  ? (rotated ? "; the refresh token was rotated" : "; the same refresh token came back")
                  : "; no new refresh token") +
                (response.body.scope ? "; scope " + response.body.scope : "")
      });
      renderRefreshRequest();
      renderReissue();
      renderHistory();
      // The proof was signed against the state before the refresh; nothing about
      // it depends on the access token, so it stays valid. Rebuilding the
      // assembled call is enough to show the new token in the Authorization
      // header.
      renderReissueCall();
    })
    .catch(function (e) {
      log.error("the refresh request failed: " + e.message);
      // The call never completed — CORS, DNS, a server that is not there. Still an
      // attempt, and the one hardest to diagnose from memory later.
      sdJwtVc.recordHistoryEntry({
        kind: sdJwtVc.HISTORY_KIND.TOKEN_REFRESH,
        outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
        detail: "the request to " + endpoint + " never completed: " + e.message
      });
      renderHistory();
      status("vc_refresh_status", "The refresh request failed: " + e.message, "vc-bad");
      disable("vc_refresh_button", false);
    });
  log.debug("Leaving sendRefreshRequest().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 3: the Credential Request, again.
//
// Byte for byte the request step 2 makes, which is why it is built with the same
// module. The one thing a refresh gets to decide differently is the key: staying
// bound to the key the credential in hand already uses is what makes the result
// a REPLACEMENT for it, and generating a new one produces a credential bound to
// something else — useful, but a different thing.
// ---------------------------------------------------------------------------
function keyChoice() {
  var choice = val("vc_refresh_key_mode") || "reuse";
  var cnf = state.current && state.current.parsed &&
            state.current.parsed.payload && state.current.parsed.payload.cnf;
  var boundJwk = (cnf && cnf.jwk) || null;
  // "Reuse" is only honest while the private half is still here.
  if (choice === "reuse" && !holderKeyIsHeld(boundJwk)) return "new";
  return choice;
}

// The paste-in row appears only when the private half is not in storage: with
// saving on it would be a field asking for something the page already has.
function renderHolderKeyRow() {
  var row = el("vc_holder_key_row");
  var note = el("vc_holder_key_note");
  if (!row) return;
  var stored = !!sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  row.style.display = stored ? "none" : "";
  if (!note) return;
  if (stored) {
    note.textContent = "";
    return;
  }
  var pasted = sdJwtVc.readHolderPrivateJwk("vc_holder_private_jwk");
  if (pasted.problem) note.textContent = pasted.problem;
  else if (pasted.jwk) note.textContent = "Using the key pasted here. It is not stored.";
  else {
    note.textContent = "Not in this browser's storage — paste the key pair you downloaded on step 2 to " +
      "reuse the bound key, or choose \"Generate a new holder key pair\".";
  }
}

// Re-evaluate as the key is pasted: whether "reuse" is available depends on it.
function onHolderKeyPasted() {
  log.debug("Entering onHolderKeyPasted().");
  renderReissue();
  log.debug("Leaving onHolderKeyPasted().");
  return false;
}

function holderKeyForRequest() {
  log.debug("Entering holderKeyForRequest().");
  if (keyChoice() === "reuse") {
    var priv = sdJwtVc.readHolderPrivateJwk("vc_holder_private_jwk").jwk;
    // The public half comes from storage when it is there; otherwise it is the
    // public part of the pasted private JWK, which for an EC key carries x/y.
    var pub = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK) ||
              (priv ? { kty: priv.kty, crv: priv.crv, x: priv.x, y: priv.y } : null);
    if (pub && priv) {
      log.debug("Leaving holderKeyForRequest(). Reusing the stored holder key.");
      return Promise.resolve({ publicJwk: pub, privateJwk: priv });
    }
  }
  log.debug("Leaving holderKeyForRequest(). Generating a new holder key.");
  // Deliberately NOT written over the wallet's holder key here: the credential in
  // hand is bound to that one, and until the refreshed credential is kept, the
  // private half of it is the only thing that can present the credential the
  // wallet actually has. keepRefreshed() parks the new pair; replaceCredential()
  // promotes it.
  return vciWallet.generateHolderKeyPair();
}

// Which Credential Dataset identifiers the token response granted, if the
// authorization used authorization_details (OID4VCI section 6.2). A refresh
// carries them forward: the refreshed access token was granted for the same
// credential, and section 8.2's rule about which parameter names it does not
// change because the request is a refresh.
function grantedIdentifiers() {
  log.debug("Entering grantedIdentifiers().");
  var details = sdJwtVc.getJson("token_authorization_details");
  var out = [];
  if (Object.prototype.toString.call(details) === "[object Array]") {
    details.forEach(function (d) {
      (((d || {}).credential_identifiers) || []).forEach(function (id) { out.push(id); });
    });
  }
  log.debug("Leaving grantedIdentifiers(). " + out.length + " granted.");
  return out;
}

function prepareReissue() {
  log.debug("Entering prepareReissue().");
  if (!state.config.credentialEndpoint) {
    setText("vc_reissue_nonce", "— (no issuer is configured)");
    setValue("vc_reissue_proof", "");
    setJson("vc_reissue_body", null);
    setValue("vc_reissue_request", "");
    status("vc_reissue_status",
      "No credential_endpoint is configured, so there is no request to build. Retrieve the credential " +
      "issuer metadata in step 1.", "vc-bad");
    log.debug("Leaving prepareReissue(). Nothing configured.");
    return Promise.resolve(false);
  }
  return holderKeyForRequest()
    .then(function (key) {
      state.request.holderKeys = [key];
      return vciWallet.fetchNonce(state.config.nonceEndpoint);
    })
    .then(function (result) {
      state.request.nonce = result.nonce;
      setText("vc_reissue_nonce", result.published
        ? (result.nonce || "— (the nonce endpoint returned no c_nonce)")
        : "— (this issuer publishes no nonce_endpoint)");
      return vciWallet.signProofs(state.request.holderKeys, {
        clientId: sdJwtVc.get("client_id") || "",
        credentialIssuer: state.config.credentialIssuer,
        nonce: state.request.nonce
      });
    })
    .then(function (proofs) {
      state.request.proofs = proofs;
      setValue("vc_reissue_proof", proofs[0] || "");
      var granted = grantedIdentifiers();
      state.request.body = vciWallet.buildRequestBody({
        credentialIdentifier: granted.length ? granted[0] : "",
        credentialConfigurationId: state.config.credentialConfigurationId,
        proofs: proofs,
        encryption: null
      });
      setJson("vc_reissue_body", state.request.body);
      renderReissueCall();
      log.debug("Leaving prepareReissue(). Ready.");
      return true;
    })
    .catch(function (e) {
      log.error("could not prepare the refresh credential request: " + e.message);
      setText("vc_reissue_nonce", "— (could not fetch one: " + e.message + ")");
      status("vc_reissue_status",
        "Could not prepare the Credential Request: " + e.message + " Sending it will try again.", "vc-bad");
      return false;
    });
}

function renderReissueCall() {
  log.debug("Entering renderReissueCall().");
  var endpoint = state.config ? state.config.credentialEndpoint : "";
  if (!endpoint || !state.request.body) {
    setValue("vc_reissue_request", "");
    return "";
  }
  var accessToken = sdJwtVc.get("token_access_token") || "";
  var text = vciWallet.describeCall({
    method: "POST",
    url: endpoint,
    contentType: "application/json",
    authorization: "Bearer " + (accessToken || "(no access token — refresh one above, or run step 1)"),
    body: JSON.stringify(state.request.body, null, 2)
  });
  setValue("vc_reissue_request", text);
  log.debug("Leaving renderReissueCall().");
  return text;
}

// What the pane says about the key and the token it is about to use.
function renderReissue() {
  log.debug("Entering renderReissue().");
  setText("vc_reissue_endpoint", state.config.credentialEndpoint || "—");
  setText("vc_reissue_access_token", describeToken(sdJwtVc.get("token_access_token") || ""));
  var cnf = state.current && state.current.parsed &&
            state.current.parsed.payload && state.current.parsed.payload.cnf;
  var boundJwk = (cnf && cnf.jwk) || null;
  var held = holderKeyIsHeld(boundJwk);
  var select = el("vc_refresh_key_mode");
  if (select) {
    var reuse = select.querySelector('option[value="reuse"]');
    if (!held) {
      // Nothing to reuse: say so on the option itself rather than letting it be
      // chosen and quietly meaning something else.
      if (reuse) {
        reuse.disabled = true;
        reuse.text = "Reuse the bound key — unavailable, its private half is not in this browser";
      }
      if (select.value === "reuse") select.value = "new";
    } else if (reuse) {
      // ...and put it back when the key becomes available again, which it now
      // can: pasting the downloaded key into the field below makes the bound key
      // usable without it ever being stored. Without this branch the option
      // stayed disabled for the life of the page and the paste had no effect.
      reuse.disabled = false;
      reuse.text = "Reuse the key the credential is already bound to";
    }
  }
  renderHolderKeyRow();
  setText("vc_refresh_key_note", keyChoice() === "reuse"
    ? "The refreshed credential will carry the same cnf.jwk, so it replaces the one in hand rather than " +
      "sitting beside it."
    : "A new key pair means the refreshed credential is bound to something else: a verifier will demand " +
      "proof of possession of THIS key, and the old credential still needs the old one.");
  log.debug("Leaving renderReissue().");
}

function onKeyModeChange() {
  log.debug("Entering onKeyModeChange().");
  status("vc_reissue_status", "Rebuilding the Credential Request …", "vc-pending");
  prepareReissue().then(function (ready) {
    renderReissue();
    if (ready) {
      status("vc_reissue_status",
        "Ready: the request below is what will be sent to the Credential Endpoint.", "vc-ok");
    }
  });
  log.debug("Leaving onKeyModeChange().");
  return true;
}

function requestRefreshedCredential() {
  log.debug("Entering requestRefreshedCredential().");
  var accessToken = sdJwtVc.get("token_access_token") || "";
  if (!accessToken) {
    status("vc_reissue_status",
      "There is no access token to present. Refresh one above, or run the issuance from step 1.", "vc-bad");
    return false;
  }
  if (!state.config.credentialEndpoint) {
    status("vc_reissue_status",
      "No credential_endpoint is configured. Retrieve the credential issuer metadata in step 1.", "vc-bad");
    return false;
  }
  disable("vc_reissue_button", true);

  var send = function () {
    status("vc_reissue_status", "Asking the Credential Endpoint for a refreshed credential …", "vc-pending");
    return fetch(state.config.credentialEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + (sdJwtVc.get("token_access_token") || "")
      },
      body: JSON.stringify(state.request.body)
    }).then(function (r) {
      return r.text().then(function (text) {
        return vciWallet.readCredentialResponse(r, text, null);
      });
    });
  };

  var ready = state.request.proofs.length ? Promise.resolve(true) : prepareReissue();
  ready
    .then(send)
    .then(function (response) {
      // A c_nonce is single use and short-lived, so the proof built when the page
      // loaded can be stale by the time anyone presses the button. Same recovery
      // as step 2: rebuild it and send once more.
      if (response.ok || !response.body || response.body.error !== "invalid_proof") return response;
      log.debug("the issuer rejected the proof; rebuilding it with a fresh nonce and retrying once.");
      // Two requests were made, so two rows: the retry is not a reason to hide the
      // refusal that caused it.
      sdJwtVc.recordHistoryEntry({
        kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
        outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
        detail: "invalid_proof — the c_nonce had been spent or had expired; rebuilding the proof and " +
                "retrying once"
      });
      renderHistory();
      status("vc_reissue_status",
        "The proof had gone stale (a c_nonce is single use) — rebuilding it and trying again …", "vc-pending");
      return prepareReissue().then(send);
    })
    .then(function (response) {
      var box = el("vc_reissue_response");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      }
      if (!response.ok && !(response.statusCode === 202 && response.body && response.body.transaction_id)) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        sdJwtVc.recordHistoryEntry({
          kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
          outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
          detail: "HTTP " + response.statusCode + " — " + err +
                  (response.statusCode === 401
                    ? " (section 14.3: the issuer may stop accepting an access token)" : "")
        });
        renderHistory();
        status("vc_reissue_status",
          "The issuer refused the request: " + err +
          (response.statusCode === 401
            ? " A 401 here is section 14.3's other outcome: the issuer has decided this access token is no " +
              "longer good enough, and the wallet has to refresh it (above) or re-authenticate from step 1."
            : ""), "vc-bad");
        disable("vc_reissue_button", false);
        log.debug("Leaving requestRefreshedCredential(). Refused: " + err);
        return;
      }
      if (response.body && response.body.transaction_id && !vciWallet.extractCredential(response.body)) {
        beginDeferred(response.body, response.statusCode);
        return;
      }
      var credential = vciWallet.extractCredential(response.body);
      if (!credential) {
        sdJwtVc.recordHistoryEntry({
          kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
          outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
          detail: "HTTP " + response.statusCode + " — the response carries no credential"
        });
        renderHistory();
        status("vc_reissue_status", "The issuer answered, but the response carries no credential.", "vc-bad");
        disable("vc_reissue_button", false);
        return;
      }
      keepRefreshed(credential, response.body, {});
      status("vc_reissue_status",
        "The issuer returned a credential. What changed is below — nothing has replaced the credential in " +
        "hand yet, and the Credential History pane lists it as waiting.", "vc-ok");
      renderComparison();
      // The pane above has to show the new credential the moment it arrives:
      // a history that only moves when something is KEPT looks broken.
      renderHistory();
      disable("vc_reissue_button", false);
    })
    .catch(function (e) {
      log.error("the refresh credential request failed: " + e.message);
      status("vc_reissue_status", "The Credential Request failed: " + e.message, "vc-bad");
      disable("vc_reissue_button", false);
    });
  log.debug("Leaving requestRefreshedCredential().");
  return false;
}

// Everything worth remembering about a refreshed credential, kept apart from the
// credential in hand until the holder decides (section 14.5).
function keepRefreshed(credential, responseBody, extra) {
  log.debug("Entering keepRefreshed().");
  var all = vciWallet.allCredentials(responseBody);
  var meta = {
    issuer: state.config.credentialIssuer,
    endpoint: state.config.credentialEndpoint,
    configurationId: state.config.credentialConfigurationId,
    format: state.config.format,
    vct: state.config.vct,
    requestedAt: new Date().toISOString(),
    notificationId: (responseBody && responseBody.notification_id) || "",
    request: state.request.body,
    holderJwk: (state.request.holderKeys[0] || {}).publicJwk || null,
    holderJwks: state.request.holderKeys.map(function (k) { return k.publicJwk; }),
    credentialCount: all.length,
    encrypted: false,
    notificationEndpoint: state.config.notificationEndpoint || "",
    // How this one came to be, which is what tells step 3 it is a refresh.
    refreshed: true,
    refreshGeneration: Number((state.current && state.current.meta && state.current.meta.refreshGeneration) || 0) + 1,
    refreshedAt: new Date().toISOString(),
    keyMode: keyChoice(),
    tokenRefreshed: state.accessTokenRefreshed
  };
  Object.keys(extra || {}).forEach(function (k) { meta[k] = extra[k]; });
  // One row for the attempt that produced this credential, resolved to kept or
  // discarded when the holder decides. The id rides in the metadata so a reload
  // can still resolve it.
  var historyId = state.deferred.historyId || 0;
  if (historyId) {
    sdJwtVc.updateHistoryEntry(historyId, {
      kind: sdJwtVc.HISTORY_KIND.DEFERRED_POLL,
      outcome: sdJwtVc.HISTORY_OUTCOME.PENDING,
      detail: "the deferred credential arrived after " + ((extra || {}).deferredAttempts || 1) + " attempt(s)",
      credential: credential,
      credentials: all.length ? all : [credential],
      meta: meta,
      holderJwk: meta.holderJwk,
      holderPrivateJwk: (state.request.holderKeys[0] || {}).privateJwk || null
    });
    state.deferred.historyId = 0;
  } else {
    historyId = sdJwtVc.recordHistoryEntry({
      kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
      outcome: sdJwtVc.HISTORY_OUTCOME.PENDING,
      detail: (meta.tokenRefreshed
                ? "the issuer returned a credential, on a refreshed access token"
                : "the issuer returned a credential, on the access token already in hand (section 14.3)") +
              (all.length > 1 ? " — " + all.length + " credentials" : "") +
              (meta.keyMode === "reuse" ? "; bound to the same holder key" : "; bound to a NEW holder key"),
      credential: credential,
      credentials: all.length ? all : [credential],
      meta: meta,
      holderJwk: meta.holderJwk,
      holderPrivateJwk: (state.request.holderKeys[0] || {}).privateJwk || null
    });
  }
  meta.historyId = historyId;
  sdJwtVc.set(sdJwtVc.KEYS.REFRESHED_CREDENTIAL, credential);
  sdJwtVc.setJson(sdJwtVc.KEYS.REFRESHED_CREDENTIALS, all.length ? all : [credential]);
  sdJwtVc.setJson(sdJwtVc.KEYS.REFRESHED_META, meta);
  // A refresh that bound a new key parks it here rather than becoming the
  // wallet's key: that only happens if this credential is kept. It has to be
  // stored, though, or a reload would leave a credential whose private key is
  // gone — exactly the state this page exists to avoid.
  if (meta.keyMode !== "reuse" && state.request.holderKeys.length) {
    sdJwtVc.setJson(sdJwtVc.KEYS.REFRESHED_HOLDER_JWK, state.request.holderKeys[0].publicJwk);
    sdJwtVc.setJson(sdJwtVc.KEYS.REFRESHED_HOLDER_PRIVATE_JWK, state.request.holderKeys[0].privateJwk);
  } else {
    sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_HOLDER_JWK);
    sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_HOLDER_PRIVATE_JWK);
  }
  state.refreshed = { raw: credential, all: all.length ? all : [credential], meta: meta };
  log.debug("Leaving keepRefreshed().");
}

// ---------------------------------------------------------------------------
// A refresh can be deferred too (OID4VCI section 9): the issuer answers 202
// with a transaction_id instead of a credential. Unlike step 2 this page does
// not poll on a timer — a refresh is not something anyone is waiting on — but
// the collection has to be possible, so it is a button.
// ---------------------------------------------------------------------------
function deferredEndpoint() {
  return (state.config && state.config.deferredCredentialEndpoint) ||
         sdJwtVc.get("vci_deferred_credential_endpoint") || "";
}

function renderDeferredAttempts() {
  var e = el("vc_reissue_deferred_attempts");
  if (!e) return;
  e.textContent = state.deferred.attempts.length
    ? state.deferred.attempts.map(function (a, i) {
        return (i + 1) + ". " + a.at + "  HTTP " + a.status + "  " + a.summary;
      }).join("\n")
    : "—";
}

function beginDeferred(body, statusCode) {
  log.debug("Entering beginDeferred(). transaction_id=" + body.transaction_id);
  state.deferred.transactionId = String(body.transaction_id);
  state.deferred.intervalSeconds = Number(body.interval) || 5;
  state.deferred.attempts = [];
  state.deferred.historyId = 0;
  sdJwtVc.recordHistoryEntry({
    kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
    outcome: sdJwtVc.HISTORY_OUTCOME.DEFERRED,
    detail: "HTTP " + statusCode + " — deferred as transaction " + state.deferred.transactionId +
            ", interval " + state.deferred.intervalSeconds + "s"
  });
  renderHistory();
  show("vc_reissue_deferred_row", true);
  setText("vc_reissue_transaction_id", state.deferred.transactionId +
    " at " + (deferredEndpoint() || "— no deferred_credential_endpoint is published —"));
  renderDeferredAttempts();
  status("vc_reissue_status",
    "The issuer answered " + statusCode + ": the refreshed credential is not ready yet. It asked for " +
    state.deferred.intervalSeconds + "s between attempts; collect it below.", "vc-pending");
  disable("vc_reissue_button", false);
  log.debug("Leaving beginDeferred().");
}

function pollDeferred() {
  log.debug("Entering pollDeferred().");
  var endpoint = deferredEndpoint();
  if (!state.deferred.transactionId) {
    status("vc_reissue_status", "There is no deferred refresh in progress.", "vc-bad");
    return false;
  }
  if (!endpoint) {
    status("vc_reissue_status", "This issuer publishes no deferred_credential_endpoint.", "vc-bad");
    return false;
  }
  status("vc_reissue_status", "Asking the Deferred Credential Endpoint …", "vc-pending");
  fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (sdJwtVc.get("token_access_token") || "")
    },
    body: JSON.stringify({ transaction_id: state.deferred.transactionId })
  })
    .then(function (r) {
      return r.text().then(function (text) { return vciWallet.readCredentialResponse(r, text, null); });
    })
    .then(function (response) {
      var credential = vciWallet.extractCredential(response.body);
      var summary = credential ? "the refreshed credential was issued"
        : (response.body && response.body.transaction_id)
          ? "still pending (interval " + (response.body.interval || state.deferred.intervalSeconds) + "s)"
          : (response.body && (response.body.error_description || response.body.error)) || response.raw;
      state.deferred.attempts.push({
        at: new Date().toISOString(),
        status: response.statusCode,
        summary: String(summary).slice(0, 200)
      });
      renderDeferredAttempts();
      if (!credential) {
        // A poll that came back "still working on it" is an attempt too.
        sdJwtVc.recordHistoryEntry({
          kind: sdJwtVc.HISTORY_KIND.DEFERRED_POLL,
          outcome: response.ok || response.statusCode === 202
            ? sdJwtVc.HISTORY_OUTCOME.DEFERRED : sdJwtVc.HISTORY_OUTCOME.FAILED,
          detail: "attempt " + state.deferred.attempts.length + ": HTTP " + response.statusCode + " — " + summary
        });
        renderHistory();
        status("vc_reissue_status", "Attempt " + state.deferred.attempts.length + ": " + summary, "vc-pending");
        return;
      }
      // The poll that produced the credential is the row keepRefreshed() resolves.
      state.deferred.historyId = sdJwtVc.recordHistoryEntry({
        kind: sdJwtVc.HISTORY_KIND.DEFERRED_POLL,
        outcome: sdJwtVc.HISTORY_OUTCOME.DEFERRED,
        detail: "attempt " + state.deferred.attempts.length + ": the credential was ready"
      });
      keepRefreshed(credential, response.body, {
        deferred: true,
        transactionId: state.deferred.transactionId,
        deferredEndpoint: endpoint,
        deferredAttempts: state.deferred.attempts.length
      });
      // Spent: the issuer invalidates it once the credential has been collected.
      state.deferred.transactionId = "";
      status("vc_reissue_status",
        "The refreshed credential arrived after " + state.deferred.attempts.length +
        (state.deferred.attempts.length === 1 ? " attempt." : " attempts.") +
        " What changed is below.", "vc-ok");
      renderComparison();
      renderHistory();
    })
    .catch(function (e) {
      log.error("the deferred refresh request failed: " + e.message);
      sdJwtVc.recordHistoryEntry({
        kind: sdJwtVc.HISTORY_KIND.DEFERRED_POLL,
        outcome: sdJwtVc.HISTORY_OUTCOME.FAILED,
        detail: "the request to " + endpoint + " never completed: " + e.message
      });
      renderHistory();
      status("vc_reissue_status", "The deferred request failed: " + e.message, "vc-bad");
    });
  log.debug("Leaving pollDeferred().");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 4: what changed.
//
// Section 14.5 leaves it to the issuer "whether to update both the signature and
// the claim values, or only the signature", and section 14.3 says the answer may
// even be the same credential over again. None of that can be assumed from the
// wallet's side — it has to be read off the two credentials, which is what this
// does.
// ---------------------------------------------------------------------------
function comparisonRows(before, after) {
  log.debug("Entering comparisonRows().");
  var b = before.payload || {};
  var a = after.payload || {};
  var bCnf = (b.cnf && b.cnf.jwk) || {};
  var aCnf = (a.cnf && a.cnf.jwk) || {};
  var rows = [
    { name: "vct", before: b.vct || "—", after: a.vct || "—" },
    { name: "iss", before: b.iss || "—", after: a.iss || "—" },
    { name: "sub", before: b.sub || "—", after: a.sub || "—" },
    { name: "Issued (iat)", before: isoOf(b.iat), after: isoOf(a.iat) },
    { name: "Not before (nbf)", before: isoOf(b.nbf), after: isoOf(a.nbf) },
    {
      name: "Expires (exp)",
      before: isoOf(b.exp) + (b.exp ? " (" + relativeTo(b.exp) + ")" : ""),
      after: isoOf(a.exp) + (a.exp ? " (" + relativeTo(a.exp) + ")" : "")
    },
    {
      name: "Bound key (cnf.jwk)",
      before: bCnf.x ? String(bCnf.x).slice(0, 20) + "…" : "—",
      after: aCnf.x ? String(aCnf.x).slice(0, 20) + "…" : "—"
    },
    {
      name: "Issuer signature",
      before: String(before.signature || "").slice(0, 20) + "…",
      after: String(after.signature || "").slice(0, 20) + "…"
    },
    {
      name: "Disclosures",
      before: String((before.disclosures || []).length),
      after: String((after.disclosures || []).length)
    },
    {
      name: "_sd digests",
      before: String(sdJwtVc.collectSdDigests(b).length),
      after: String(sdJwtVc.collectSdDigests(a).length)
    }
  ];
  log.debug("Leaving comparisonRows(). " + rows.length + " row(s).");
  return rows;
}

// Which disclosed claims differ, by value. Salts differ every time an issuer
// mints a credential — that is required, not a change of content — so the
// comparison is of the claims, never of the Disclosures themselves.
function claimDifferences(before, after) {
  log.debug("Entering claimDifferences().");
  var b = sdJwtVc.disclosedClaims(before);
  var a = sdJwtVc.disclosedClaims(after);
  var names = {};
  Object.keys(b).forEach(function (k) { names[k] = true; });
  Object.keys(a).forEach(function (k) { names[k] = true; });
  var out = [];
  Object.keys(names).sort().forEach(function (name) {
    // The SD-JWT machinery and the per-issuance metadata are not claim CONTENT:
    // a new iat is what a refresh is, and reporting it as a changed claim would
    // bury the ones that matter.
    if (["iat", "nbf", "exp", "cnf", "_sd", "_sd_alg"].indexOf(name) !== -1) return;
    var beforeValue = JSON.stringify(b[name]);
    var afterValue = JSON.stringify(a[name]);
    if (beforeValue === afterValue) return;
    out.push({
      name: name,
      before: name in b ? beforeValue : "(absent)",
      after: name in a ? afterValue : "(absent)"
    });
  });
  log.debug("Leaving claimDifferences(). " + out.length + " claim(s) differ.");
  return out;
}

function renderComparison() {
  log.debug("Entering renderComparison().");
  show("pane_compare", true);
  var refreshed = state.refreshed;
  if (!refreshed || !state.current) {
    show("pane_compare", false);
    log.debug("Leaving renderComparison(). Nothing to compare.");
    return false;
  }
  var after;
  try {
    after = sdJwtVc.parseCredential(refreshed.raw);
  } catch (e) {
    status("vc_compare_status", "The refreshed credential could not be parsed: " + e.message, "vc-bad");
    log.debug("Leaving renderComparison(). Unparseable.");
    return false;
  }
  var before = state.current.parsed;
  if (!before) {
    status("vc_compare_status",
      "The credential in hand could not be parsed, so there is nothing to compare against. The refreshed " +
      "credential is below and can still replace it.", "vc-pending");
  }

  var rows = before ? comparisonRows(before, after) : [];
  setHtml("vc_compare_table",
    "<thead><tr><th style='width:16%'>Member</th><th style='width:38%'>The credential in hand</th>" +
    "<th style='width:38%'>What the issuer just returned</th><th style='width:8%'>Changed</th></tr></thead>" +
    "<tbody>" + rows.map(function (r) {
      var changed = String(r.before) !== String(r.after);
      return "<tr>" +
        "<td>" + esc(r.name) + "</td>" +
        '<td class="vc-mono">' + esc(r.before) + "</td>" +
        '<td class="vc-mono">' + esc(r.after) + "</td>" +
        '<td class="' + (changed ? "vc-bad" : "vc-ok") + '">' + (changed ? "yes" : "no") + "</td>" +
        "</tr>";
    }).join("") + "</tbody>");

  var diffs = before ? claimDifferences(before, after) : [];
  setHtml("vc_compare_claims", diffs.length
    ? "<thead><tr><th style='width:16%'>Claim</th><th style='width:42%'>Before</th>" +
      "<th style='width:42%'>After</th></tr></thead><tbody>" +
      diffs.map(function (d) {
        return "<tr><td>" + esc(d.name) + '</td><td class="vc-mono">' + esc(d.before) +
               '</td><td class="vc-mono">' + esc(d.after) + "</td></tr>";
      }).join("") + "</tbody>"
    : "<tbody><tr><td>Not one disclosed claim VALUE differs — the End-User's data is the same. " +
      "The salts and therefore every Disclosure and digest are new regardless, because an issuer mints " +
      "them fresh each time.</td></tr></tbody>");

  // The verdict, in the terms section 14.5 uses.
  var sameCredential = before && before.serialized === after.serialized;
  var signatureChanged = before && before.signature !== after.signature;
  var windowChanged = before && ((before.payload || {}).exp !== (after.payload || {}).exp);
  var keyChanged = before &&
    JSON.stringify(((before.payload || {}).cnf || {}).jwk) !== JSON.stringify(((after.payload || {}).cnf || {}).jwk);
  var verdict;
  if (sameCredential) {
    verdict = "The issuer returned the very same credential, byte for byte. Section 14.3 allows exactly " +
              "that: asking again does not oblige an issuer to change anything.";
  } else if (!diffs.length && signatureChanged) {
    verdict = "Same claim values, new signature" + (windowChanged ? " and a new validity window" : "") +
              " — section 14.5's \"only the signature\" case. The credential is a fresh assertion of " +
              "unchanged facts.";
  } else if (diffs.length) {
    verdict = diffs.length + " claim value(s) changed as well as the signature — section 14.5's other " +
              "case, where the issuer updates the content too.";
  } else {
    verdict = "The credential differs, but not in its signature or its claim values.";
  }
  if (keyChanged) {
    verdict += " It is bound to a DIFFERENT holder key, so it does not replace the old credential for a " +
               "verifier holding the old key.";
  }
  status("vc_compare_status", verdict, sameCredential ? "vc-pending" : "vc-ok");

  setValue("vc_compare_refreshed_raw", refreshed.raw);
  setText("vc_compare_refreshed_meta",
    "Requested " + (refreshed.meta.requestedAt || "?") +
    " — refresh " + (refreshed.meta.refreshGeneration || 1) +
    ", " + (refreshed.meta.keyMode === "reuse" ? "bound to the same holder key" : "bound to a new holder key") +
    (refreshed.meta.deferred ? ", collected from the Deferred Credential Endpoint" : "") +
    (refreshed.meta.notificationId ? ", notification_id " + refreshed.meta.notificationId : ""));
  disable("vc_replace_button", false);
  disable("vc_discard_button", false);
  // A pending refresh is the newest thing on the screen and is not in storage, so
  // the offer has to disown it the moment it appears.
  renderPresentOffer();
  log.debug("Leaving renderComparison().");
  return true;
}

// ---------------------------------------------------------------------------
// The wallet's decision (section 14.5): "the Wallet might need to check if it
// already has a Credential of the same type and, if necessary, delete the old
// Credential. Otherwise, the Wallet might end up with more than one Credential
// of the same type, without knowing which one is the latest."
// ---------------------------------------------------------------------------
function replaceCredential() {
  log.debug("Entering replaceCredential().");
  if (!state.refreshed) {
    status("vc_compare_status", "There is no refreshed credential to promote.", "vc-bad");
    return false;
  }
  // The old one is kept where it can still be looked at — with the key it is
  // bound to, so keeping it means something — but it is no longer the credential
  // the workflow holds.
  if (state.current) {
    sdJwtVc.set(sdJwtVc.KEYS.PREVIOUS_CREDENTIAL, state.current.raw);
    sdJwtVc.setJson(sdJwtVc.KEYS.PREVIOUS_META, state.current.meta || {});
    sdJwtVc.setJson(sdJwtVc.KEYS.PREVIOUS_HOLDER_JWK, sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK));
    sdJwtVc.setJson(sdJwtVc.KEYS.PREVIOUS_HOLDER_PRIVATE_JWK,
      sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK));
  }
  sdJwtVc.set(sdJwtVc.KEYS.CREDENTIAL, state.refreshed.raw);
  sdJwtVc.setJson(sdJwtVc.KEYS.CREDENTIALS, state.refreshed.all);
  sdJwtVc.setJson(sdJwtVc.KEYS.CREDENTIAL_META, state.refreshed.meta);
  // Keeping a credential bound to a new key means adopting that key: it is what
  // a verifier will demand proof of possession of from now on.
  var newPublic = sdJwtVc.getJson(sdJwtVc.KEYS.REFRESHED_HOLDER_JWK);
  var newPrivate = sdJwtVc.getJson(sdJwtVc.KEYS.REFRESHED_HOLDER_PRIVATE_JWK);
  if (newPublic && newPrivate) {
    sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_JWK, newPublic);
    sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK, newPrivate);
  }
  // The attempt that produced this credential becomes the generation the wallet
  // holds — the same row, resolved, not a second one: one row per attempt.
  var replacedGeneration = sdJwtVc.activeGeneration();
  var pendingId = (state.refreshed.meta || {}).historyId || 0;
  var resolved = pendingId ? sdJwtVc.updateHistoryEntry(pendingId, {
    outcome: sdJwtVc.HISTORY_OUTCOME.KEPT,
    detail: (state.refreshed.meta.tokenRefreshed
              ? "kept, on a refreshed access token"
              : "kept, on the access token already in hand (section 14.3)") +
            (replacedGeneration ? "; replaced generation " + replacedGeneration.generation : ""),
    source: state.refreshed.meta.tokenRefreshed ? "refreshed" : "refreshed (§14.3)",
    holderJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK),
    holderPrivateJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK)
  }) : null;
  if (!resolved) {
    // The row was trimmed away (or written by an older build): record the
    // generation on its own rather than losing it.
    sdJwtVc.recordCredentialGeneration({
      kind: sdJwtVc.HISTORY_KIND.CREDENTIAL_REQUEST,
      source: state.refreshed.meta.tokenRefreshed ? "refreshed" : "refreshed (§14.3)",
      detail: "kept",
      credential: state.refreshed.raw,
      credentials: state.refreshed.all,
      meta: state.refreshed.meta,
      holderJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK),
      holderPrivateJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK)
    });
  }
  forgetRefreshed();
  state.refreshed = null;
  show("pane_compare", false);
  // Everything on the page now describes a different credential — including the
  // history, where this generation has just become the one in hand. Deliberately
  // WITHOUT navigating anywhere: the pane the holder just acted in is the pane
  // that has to show what the action did. Step 3 is a button away.
  var total = sdJwtVc.heldGenerations().length;
  reloadHeldCredential(
    "Generation " + total + " is now the credential the wallet holds. The one it replaced is still in the " +
    "list, so you can go back to it.",
    "Kept: the wallet now holds the refreshed credential. \u201cVerify in step 3\u201d opens it, and the " +
    "request below has been rebuilt to refresh it again.");
  disable("vc_goto_step3_button", false);
  log.debug("Leaving replaceCredential().");
  return false;
}

// Step 3 verifies whatever the wallet holds. A button rather than a redirect, so
// keeping a credential does not move the browser out from under whoever pressed
// it.
function verifyInStepThree() {
  window.location.href = sdJwtVc.STEP3_URL;
  return false;
}

// Hand off to the PRESENTATION workflow. Nothing is copied: that workflow reads
// the same storage keys this page writes, so what it will find is whatever is in
// hand right now — which is the whole reason the offer below spells out which
// generation that is.
function presentIt() {
  log.debug("Entering presentIt().");
  var readiness = sdJwtVc.presentationReadiness();
  if (!readiness.ready) {
    renderPresentOffer();
    log.debug("Leaving presentIt(). Not ready.");
    return false;
  }
  window.location.href = sdJwtVc.PRESENTATION_URL;
  log.debug("Leaving presentIt().");
  return false;
}

// This page is the one place where "the credential" is ambiguous, so the offer
// has to say which one would go. Two things make it ambiguous, and both are
// states this page puts the user in deliberately:
//   - several generations, of which one is in hand (and it need not be the
//     newest — going back to an older one is a supported thing to do here);
//   - a refreshed credential retrieved but NOT yet kept, which is the newest
//     thing on the screen and is not in storage at all, so it is not what a
//     Verifier would be shown.
function renderPresentOffer() {
  log.debug("Entering renderPresentOffer().");
  var readiness = sdJwtVc.presentationReadiness();
  var button = el("vc_present_button");
  if (button) button.disabled = !readiness.ready;
  var message = readiness.message;
  var level = readiness.level;
  if (readiness.ready) {
    var active = sdJwtVc.activeGeneration();
    if (active && active.total > 1) {
      message += " That is generation " + active.generation + " of " + active.total +
        (active.generation < active.total ? ", which is not the newest one." : ", the newest one.");
    }
    if (state.refreshed) {
      message += " The refreshed credential below has not been kept, so it is NOT what would be presented — " +
        "keep it first if that is the one you want shown.";
      level = "vc-pending";
    }
  }
  status("vc_present_status", message, level);
  log.debug("Leaving renderPresentOffer(). ready=" + readiness.ready);
}

// Everything a pending refresh left behind, including the key it would have
// bound: dropped together, or the next visit finds half of it.
function forgetRefreshed() {
  sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_CREDENTIAL);
  sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_CREDENTIALS);
  sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_META);
  sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_HOLDER_JWK);
  sdJwtVc.remove(sdJwtVc.KEYS.REFRESHED_HOLDER_PRIVATE_JWK);
}

function discardRefreshed() {
  log.debug("Entering discardRefreshed().");
  // The attempt stays in the log — it happened — but the credential itself goes,
  // because "discarded" has to mean discarded. What is left is the record that the
  // issuer returned one and the holder said no.
  var pendingId = ((state.refreshed || {}).meta || {}).historyId || 0;
  if (pendingId) {
    sdJwtVc.updateHistoryEntry(pendingId, {
      outcome: sdJwtVc.HISTORY_OUTCOME.DISCARDED,
      detail: "the issuer returned a credential and it was discarded, so the wallet never held it",
      credential: undefined,
      credentials: undefined,
      holderPrivateJwk: undefined
    });
  }
  forgetRefreshed();
  state.refreshed = null;
  show("pane_compare", false);
  renderHistory();
  status("vc_reissue_status",
    "The refreshed credential was discarded. The wallet still holds the credential from step 3 — which is a " +
    "real choice: an issuer cannot make a wallet keep what it returned.", "vc-pending");
  log.debug("Leaving discardRefreshed().");
  return false;
}

function copyRefreshed() {
  var area = el("vc_compare_refreshed_raw");
  if (!area) return false;
  area.select();
  try {
    document.execCommand("copy");
    status("vc_compare_status", "Copied.", "vc-ok");
  } catch (e) {
    status("vc_compare_status", "Could not copy: " + e.message, "vc-bad");
  }
  return false;
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

function onload() {
  log.debug("Entering onload().");
  sdJwtVc.renderUseCaseBadge();
  var step = document.getElementById("vc_step_4");
  if (step) step.className = "vc-step-current";
  ["vc_step_0", "vc_step_1", "vc_step_2", "vc_step_3"].forEach(function (id) {
    var e = document.getElementById(id);
    if (e) e.className = "vc-step-done";
  });

  state.config = sdJwtVc.storedRequestConfig();
  loadCurrentCredential();
  renderCurrentCredential();
  // If the workflow reached here from an older build (or step 2 never ran on this
  // browser) the credential in hand predates the history: record it, so there is
  // a generation 1 to navigate back to rather than a list that starts at the
  // first refresh.
  if (state.current && !sdJwtVc.hasCredentialHistory()) {
    sdJwtVc.recordCredentialGeneration({
      source: (state.current.meta && state.current.meta.refreshGeneration) ? "refreshed" : "issued",
      credential: state.current.raw,
      credentials: sdJwtVc.getJson(sdJwtVc.KEYS.CREDENTIALS) || [state.current.raw],
      meta: state.current.meta || {},
      holderJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK),
      holderPrivateJwk: sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK)
    });
  }
  renderHistory();
  renderRefreshRequest();
  renderReissue();

  // A refresh that has already happened is still here after a reload: it was
  // deliberately not promoted, so it must not quietly disappear either.
  var pending = sdJwtVc.get(sdJwtVc.KEYS.REFRESHED_CREDENTIAL) || "";
  if (pending) {
    state.refreshed = {
      raw: pending,
      all: sdJwtVc.getJson(sdJwtVc.KEYS.REFRESHED_CREDENTIALS) || [pending],
      meta: sdJwtVc.getJson(sdJwtVc.KEYS.REFRESHED_META) || {}
    };
    renderComparison();
  } else {
    show("pane_compare", false);
  }

  if (!state.current) {
    // Nothing to refresh, but the panes still show what the calls would be —
    // the same principle step 2 follows with no access token.
    status("vc_reissue_status",
      "There is no credential to refresh yet. The request below is what a refresh would send.", "vc-pending");
  }
  prepareReissue().then(function (ready) {
    renderReissue();
    if (!ready || !state.current) return;
    status("vc_reissue_status", sdJwtVc.get("token_access_token")
      ? "Ready: the proof of possession is signed and the request below is what will be sent."
      : "The request below is ready, but there is no access token to authorize it with — refresh one above, " +
        "or start again from step 1.",
      sdJwtVc.get("token_access_token") ? "vc-ok" : "vc-pending");
  });
  log.debug("SD-JWT VC issuance step 4 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  renderHistory: renderHistory,
  verifyInStepThree: verifyInStepThree,
  activateGeneration: activateGeneration,
  historyOlder: historyOlder,
  historyNewer: historyNewer,
  historyOldest: historyOldest,
  historyLatest: historyLatest,
  clearHistory: clearHistory,
  onRefreshScopeChange: onRefreshScopeChange,
  sendRefreshRequest: sendRefreshRequest,
  onKeyModeChange: onKeyModeChange,
  onHolderKeyPasted: onHolderKeyPasted,
  requestRefreshedCredential: requestRefreshedCredential,
  pollDeferred: pollDeferred,
  renderComparison: renderComparison,
  replaceCredential: replaceCredential,
  discardRefreshed: discardRefreshed,
  copyRefreshed: copyRefreshed,
  togglePane: togglePane,
  presentIt: presentIt,
  onload: onload
};
