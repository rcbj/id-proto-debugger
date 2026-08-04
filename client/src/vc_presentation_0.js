// File: vc_presentation_0.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC presentation, step 0: choose how the presentation starts.
//
// OID4VP describes a same-device and a cross-device flow, and two ways the
// Authorization Request itself can travel — by value in the query, or by
// reference at a request_uri where it can be signed. The choice is made once
// here; every later page shows which one is running.
//
// The buttons are generated from the list in sd_jwt_vp.js, so this page cannot
// drift from the badge the other pages show.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");

var log = bunyan.createLogger({ name: 'vc_presentation_0',
                                level: appconfig.logLevel });

// Where each flow begins. All three start at the VERIFIER — a presentation is
// something a verifier asks for — but at different pages of it.
var STARTS = {
  "same-device": { verifierPath: "/oid4vp/verifier", cta: "Go to the verifier's web page" },
  "same-device-signed": { verifierPath: "/oid4vp/start?by=reference",
                          cta: "Ask the verifier for a signed request" },
  "cross-device": { verifierPath: "/oid4vp/start?mode=cross-device",
                    cta: "Show the verifier's QR code" }
};

function esc(v) { return metadataClient.escapeHtmlText(v); }
function el(id) { return document.getElementById(id); }

function status(text, cls) {
  var e = el("vp_usecase_status");
  if (!e) return;
  e.textContent = text;
  e.className = "vc-note vc-status" + (cls ? " " + cls : "");
}

// Where the verifier's own start pages live.
//
// Those pages — /oid4vp/verifier and /oid4vp/start — are THIS debugger's mock
// verifier's invention (sts/server.js). A real verifier has no such thing, which
// is why walt.id's does not answer them. So the base is taken from explicit
// configuration first, and only guessed as a last resort.
//
// The guess used to be the credential issuer URL, whole, on the reasoning that
// the mock verifier shares an origin with the mock issuer. True for the mock, and
// wrong in two separate ways as soon as issuance has been run against walt.id:
// its Credential Issuer Identifier carries a PATH (http://localhost:7005/openid4vci),
// so appending /oid4vp/verifier produced
// http://localhost:7005/openid4vci/oid4vp/verifier — and its verifier is a
// different service on :7003 regardless. Only the ORIGIN of the issuer is a
// usable guess, and even then only because the mock happens to co-locate them.
//
// Returns the base and where it came from, because a guessed base that 404s and
// a configured one that 404s call for different things from the user.
function verifierBase() {
  log.debug("Entering verifierBase().");
  var stored = sdJwtVc.get(sdJwtVp.KEYS.VERIFIER_BASE_URL) || "";
  if (stored) return { base: trimBase(stored), source: "configured" };

  var configured = appconfig.oid4vpVerifierUrlDefault || "";
  if (configured) return { base: trimBase(configured), source: "configured" };

  // Last resort: the ORIGIN of whatever issuer the issuance workflow used.
  var issuer = sdJwtVc.storedRequestConfig().credentialIssuer ||
               appconfig.oid4vciIssuerUrlDefault || "";
  var origin = originOf(issuer);
  if (origin) return { base: origin, source: "guessed from the credential issuer" };

  log.debug("Leaving verifierBase().");
  return { base: "", source: "none" };
}

function trimBase(v) { return String(v).replace(/\/+$/, ""); }

// The scheme://host:port of a URL, dropping any path. Falls back to the trimmed
// string when it will not parse, so a hand-typed value is not silently discarded.
function originOf(url) {
  var s = String(url || "").trim();
  if (!s) return "";
  try {
    return new URL(s).origin;
  } catch (e) {
    return trimBase(s);
  }
}

function verifierBaseUrl() {
  log.debug("Entering verifierBaseUrl().");
  var b = verifierBase();
  log.debug("Leaving verifierBaseUrl(). base=" + b.base + " (" + b.source + ")");
  return b.base;
}

// ---------------------------------------------------------------------------
// The configuration pane.
//
// Two settings, both about the verifier, both hand-entered: an OID4VP verifier
// publishes no discovery document, so there is nothing to retrieve and populate
// them from the way issuance step 1 populates its pane from the issuer's
// metadata. Save / Clear All / Restore Defaults mirror that pane's controls so
// the two workflows behave the same way under the same buttons.
// ---------------------------------------------------------------------------
var CONFIG_FIELDS = [
  { id: "vp_verifier_base_url", key: "VERIFIER_BASE_URL" },
  { id: "vp_verifier_jwks_url", key: "VERIFIER_JWKS_URL" }
];

function configStatus(text, cls) {
  var e = el("config_status");
  if (!e) return;
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
}

function loadConfiguration() {
  log.debug("Entering loadConfiguration().");
  CONFIG_FIELDS.forEach(function (f) {
    var e = el(f.id);
    if (e) e.value = sdJwtVc.get(sdJwtVp.KEYS[f.key]) || "";
  });
  log.debug("Leaving loadConfiguration().");
}

function saveConfiguration() {
  log.debug("Entering saveConfiguration().");
  CONFIG_FIELDS.forEach(function (f) {
    var e = el(f.id);
    var v = e ? String(e.value || "").trim() : "";
    if (v) sdJwtVc.set(sdJwtVp.KEYS[f.key], v);
    else sdJwtVc.remove(sdJwtVp.KEYS[f.key]);
  });
  configStatus("Saved.", "vc-ok");
  // The base decides the start links below, so the chooser has to be redrawn or
  // it would keep offering links built from the previous value.
  render();
  log.debug("Leaving saveConfiguration().");
  return false;
}

function clearConfiguration() {
  log.debug("Entering clearConfiguration().");
  CONFIG_FIELDS.forEach(function (f) {
    sdJwtVc.remove(sdJwtVp.KEYS[f.key]);
    var e = el(f.id);
    if (e) e.value = "";
  });
  // Cleared, not defaulted: the pane now falls back to whatever the deployment
  // configures, which the chooser's status line names.
  configStatus("Cleared.", "");
  render();
  log.debug("Leaving clearConfiguration().");
  return false;
}

function restoreDefaults() {
  log.debug("Entering restoreDefaults().");
  var base = trimBase(appconfig.oid4vpVerifierUrlDefault || "");
  if (!base) {
    configStatus("This deployment configures no default verifier (oid4vpVerifierUrlDefault is empty), so " +
                 "there is nothing to restore \u2014 enter the verifier by hand.", "vc-bad");
    log.debug("Leaving restoreDefaults(). No default configured.");
    return false;
  }
  setFieldValue("vp_verifier_base_url", base);
  // The mock verifier signs Request Objects with the STS key and serves it at
  // /oauth2/jwks. Derived rather than configured separately, because for this
  // suite's own verifier the two always move together.
  setFieldValue("vp_verifier_jwks_url", base + "/oauth2/jwks");
  configStatus("Restored this suite's mock verifier. Save to apply.", "");
  log.debug("Leaving restoreDefaults().");
  return false;
}

// Step 0 had no collapsible panes before this one, so it had no toggle. Same
// behaviour as the other pages' so the legends act alike across the workflow.
function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

function setFieldValue(id, v) {
  var e = el(id);
  if (e) e.value = v;
}

// The format of the credential this wallet is holding, "" when there is none or
// it cannot be read.
function heldFormat() {
  log.debug("Entering heldFormat().");
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!raw) return "";
  try {
    return sdJwtVc.parseCredential(raw).format || "";
  } catch (e) {
    // Unparseable: renderCredentialState() already says so, and asking the
    // verifier for a format derived from a broken credential would be worse than
    // letting it use its default.
    log.debug("heldFormat(): the held credential could not be parsed: " + e.message);
    return "";
  }
  log.debug("Leaving heldFormat().");
}

function verifierPageUrl(id) {
  log.debug("Entering verifierPageUrl().");
  var base = verifierBaseUrl();
  var path = (STARTS[id] || {}).verifierPath || "/oid4vp/verifier";
  if (!base) return "";
  // Tell the verifier which format to ask for.
  //
  // Without this every flow here starts a request for the verifier's default,
  // dc+sd-jwt, whatever the wallet is holding — so a holder who has just been
  // issued an ldp_vc credential is sent to ask for one they do not have. The
  // wallet then either sends the wrong shape (which the verifier reports as a
  // malformed presentation, naming the parse failure rather than the cause) or,
  // now, refuses on step 1. Neither is the user's fault and neither is fixable
  // from the wallet side: the format is the VERIFIER's choice, so it has to be
  // made here, where the link to the verifier is built.
  //
  // Omitted when nothing is held, so the verifier keeps its own default and the
  // page behaves exactly as before for a wallet with no credential.
  var format = heldFormat();
  if (!format) return base + path;
  log.debug("Leaving verifierPageUrl().");
  return base + path + (path.indexOf("?") === -1 ? "?" : "&") +
         "format=" + encodeURIComponent(format);
}

function buttonHtml(uc, current) {
  log.debug("Entering buttonHtml(). id=" + uc.id);
  var start = STARTS[uc.id] || {};
  var classes = ["vc-usecase"];
  if (!uc.available) classes.push("vc-usecase-soon");
  if (uc.id === current.id) classes.push("vc-usecase-current");
  var html =
    '<button type="button" class="' + classes.join(" ") + '" id="vp_usecase_' + esc(uc.id) + '"' +
    (uc.available ? ' onclick="return vcpresentation0.choose(\'' + esc(uc.id) + '\');"' : ' disabled="disabled"') +
    '>' +
      '<span class="vc-usecase-head">' +
        '<span class="vc-usecase-spec">' + esc(uc.spec) + '</span>' +
        '<span class="vc-usecase-title">' + esc(uc.title) + '</span>' +
        (uc.id === current.id ? '<span class="vc-usecase-flag">currently selected</span>' : '') +
      '</span>' +
      '<span class="vc-usecase-summary">' + esc(uc.summary) + '</span>' +
      '<span class="vc-usecase-detail">' + esc(uc.detail) + '</span>' +
      '<span class="vc-usecase-mechanics">' + esc(uc.mechanics) + '</span>' +
      '<span class="vc-usecase-cta">' + esc(start.cta || "Choose this") + ' &rarr;</span>' +
    '</button>';
  log.debug("Leaving buttonHtml().");
  return html;
}

// What the wallet has to present with. Without a credential there is nothing to
// show a verifier, and saying so here is more use than letting step 2 discover it.
function renderCredentialState() {
  log.debug("Entering renderCredentialState().");
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  var host = el("vp_credential_state");
  if (!host) return false;
  if (!raw) {
    host.className = "vc-note vc-status vc-bad";
    host.innerHTML = "This wallet is not holding a credential yet, so there is nothing to present. " +
      '<a href="/vc-issuance-0.html">The issuance workflow</a> puts one here.';
    log.debug("Leaving renderCredentialState(). Nothing held.");
    return false;
  }
  var parsed = null;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    host.className = "vc-note vc-status vc-bad";
    host.textContent = "The credential in storage could not be parsed: " + e.message;
    log.debug("Leaving renderCredentialState(). Unparseable.");
    return false;
  }
  var hasKey = !!sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  // Absent-by-choice is not the same as absent-and-lost: the holder key pair can
  // be deliberately kept out of localStorage (issuance step 2), in which case it
  // is pasted in on step 2 of this workflow and the credential is perfectly
  // presentable. Saying "cannot be presented" for that case would be wrong.
  var optedOut = !hasKey && !sdJwtVc.holderPrivateKeyMayBeStored();
  host.className = "vc-note vc-status " + (hasKey ? "vc-ok" : (optedOut ? "vc-pending" : "vc-bad"));
  // Said per format, because "0 selectively-disclosable claims" is true of a
  // jwt_vc_json and tells the holder exactly the wrong thing: the credential is
  // full of claims, none of which can be withheld.
  host.textContent = "Holding a " + sdJwtVc.credentialLabel(parsed) +
    (parsed.format === sdJwtVc.FORMAT_JWT_VC_JSON
      ? " (jwt_vc_json) carrying " + Object.keys(parsed.claims).length +
        " claim(s), none of which can be withheld — that format has no selective disclosure"
      : " with " + parsed.disclosures.length + " selectively-disclosable claim(s)") +
    (hasKey
      ? ", and the holder key it is bound to — so it can be presented."
      : optedOut
        ? ". The holder key is not kept in this browser, by the choice made on issuance step 2 — you " +
          "will be asked to paste it when the presentation is assembled."
        : ", but NOT the private half of the key it is bound to, so no Key Binding JWT can be signed for it.");
  log.debug("Leaving renderCredentialState(). held=true, key=" + hasKey);
  return hasKey;
}

function render() {
  log.debug("Entering render().");
  var current = sdJwtVp.currentUseCase();
  var host = el("vp_usecases");
  if (host) {
    host.innerHTML = sdJwtVp.useCases().map(function (uc) {
      return buttonHtml(uc, current);
    }).join("");
  }
  renderCredentialState();
  // Name the base AND where it came from. A guessed one is the case that goes
  // wrong — the start pages below exist only on this debugger's mock verifier, so
  // a base guessed from, say, walt.id's issuer will 404 — and saying so here is
  // the difference between an obvious misconfiguration and an unreachable link.
  var b = verifierBase();
  var where = b.base
    ? "The verifier is " + b.base +
      (b.source === "configured"
        ? "."
        : " (guessed from the credential issuer — these start pages exist only on this " +
          "debugger's own mock verifier, so set oid4vpVerifierUrlDefault, or paste a request " +
          "into step 1 by hand, if that is not it).")
    : "The verifier is not configured yet — step 1 can take a request pasted in by hand instead.";
  status("Currently selected: " + current.spec + " · " + current.label + ". " + where,
         b.source === "guessed from the credential issuer" ? "vc-pending" : "");
  log.debug("Leaving render().");
}

// Choosing a flow records it and sends the End-User to the verifier, which is
// where a presentation is asked for. Nothing is presented by choosing.
function choose(id) {
  log.debug("Entering choose(). id=" + id);
  var uc = sdJwtVp.setUseCase(id);
  if (!uc) {
    status("That flow is not one this workflow knows about.", "vc-bad");
    return false;
  }
  // A request from a previous run belongs to that run: its nonce is spent.
  sdJwtVp.forgetRequest();
  var url = verifierPageUrl(uc.id);
  if (!url) {
    status("There is no verifier configured to ask for a presentation. Set one in step 1, or paste a " +
           "request there by hand.", "vc-bad");
    window.setTimeout(function () { window.location.href = sdJwtVp.STEP1_URL; }, 2500);
    return false;
  }
  status("Taking you to the verifier at " + url + " …", "vc-pending");
  window.location.href = url;
  log.debug("Leaving choose(). Sent to the verifier.");
  return false;
}

function onload() {
  log.debug("Entering onload().");
  // Before render(): the chooser's links and status line are built from these.
  loadConfiguration();
  render();
  var step = document.getElementById("vp_step_0");
  if (step) step.className = "vc-step-current";
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  choose: choose,
  render: render,
  verifierBaseUrl: verifierBaseUrl,
  togglePane: togglePane,
  saveConfiguration: saveConfiguration,
  clearConfiguration: clearConfiguration,
  restoreDefaults: restoreDefaults,
  verifierPageUrl: verifierPageUrl,
  onload: onload
};
