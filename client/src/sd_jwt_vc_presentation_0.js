// File: sd_jwt_vc_presentation_0.js
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

var log = bunyan.createLogger({ name: 'sd_jwt_vc_presentation_0',
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

// The verifier's own pages, derived from the configured verifier base URL. The
// mock verifier the STS service hosts lives under the same origin as the mock
// issuer, which is why this defaults to the issuer URL the issuance workflow
// already configured.
function verifierBaseUrl() {
  log.debug("Entering verifierBaseUrl().");
  var stored = sdJwtVc.get("sdjwtvp_verifier_base_url") || "";
  var issuer = sdJwtVc.storedRequestConfig().credentialIssuer || "";
  var base = stored || issuer || appconfig.oid4vciIssuerUrlDefault || "";
  log.debug("Leaving verifierBaseUrl(). base=" + base);
  return String(base).replace(/\/+$/, "");
}

function verifierPageUrl(id) {
  var base = verifierBaseUrl();
  var path = (STARTS[id] || {}).verifierPath || "/oid4vp/verifier";
  return base ? base + path : "";
}

function buttonHtml(uc, current) {
  log.debug("Entering buttonHtml(). id=" + uc.id);
  var start = STARTS[uc.id] || {};
  var classes = ["vc-usecase"];
  if (!uc.available) classes.push("vc-usecase-soon");
  if (uc.id === current.id) classes.push("vc-usecase-current");
  var html =
    '<button type="button" class="' + classes.join(" ") + '" id="vp_usecase_' + esc(uc.id) + '"' +
    (uc.available ? ' onclick="return sdjwtvp0.choose(\'' + esc(uc.id) + '\');"' : ' disabled="disabled"') +
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
      '<a href="/sd-jwt-vc-issuance-0.html">The issuance workflow</a> puts one here.';
    log.debug("Leaving renderCredentialState(). Nothing held.");
    return false;
  }
  var parsed = null;
  try {
    parsed = sdJwtVc.parseSdJwt(raw);
  } catch (e) {
    host.className = "vc-note vc-status vc-bad";
    host.textContent = "The credential in storage could not be parsed: " + e.message;
    log.debug("Leaving renderCredentialState(). Unparseable.");
    return false;
  }
  var payload = parsed.payload || {};
  var hasKey = !!sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  host.className = "vc-note vc-status " + (hasKey ? "vc-ok" : "vc-bad");
  host.textContent = "Holding a " + (payload.vct || "credential") + " with " +
    parsed.disclosures.length + " selectively-disclosable claim(s)" +
    (hasKey
      ? ", and the holder key it is bound to — so it can be presented."
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
  var base = verifierBaseUrl();
  status("Currently selected: " + current.spec + " · " + current.label + ". The verifier is " +
         (base || "not configured yet — step 1 can take a request pasted in by hand instead") + ".", "");
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
  verifierPageUrl: verifierPageUrl,
  onload: onload
};
