// File: vc_issuance_0.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 0: choose how the issuance starts.
//
// OID4VCI's Appendix H describes several ways a credential gets into a wallet.
// They are not different protocols — they differ in who starts, how the wallet
// learns what is on offer, and which grant authorizes it — so the choice is made
// once here and every later page follows it.
//
// The buttons are generated from the use-case list in sd_jwt_vc.js so this page
// cannot drift from the badge the other pages show. A use case that is not
// implemented yet is shown anyway, plainly marked: knowing what is coming is
// more useful than a shorter list.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");

var log = bunyan.createLogger({ name: 'vc_issuance_0',
                                level: appconfig.logLevel });

// Where each use case sends the user once it is chosen. The offer-based ones
// start at the issuer, not at the wallet — that is the whole point of them.
var STARTS = {
  "wallet-initiated": { url: "/vc-issuance-1.html", cta: "Start at the wallet" },
  "offer-same-device": { issuerPath: "/issuer", cta: "Go to the issuer's web page" },
  // Cross-device: the End-User is standing in front of the issuer's screen, and
  // what it shows is a QR code — so go straight to the screen that displays one
  // rather than to the issuer's front page.
  "offer-cross-device": { issuerPath: "/issuer/offer?mode=cross-device",
                          cta: "Show the issuer's QR code" },
  "offer-deferred": { issuerPath: "/issuer/offer?mode=deferred",
                      cta: "Show the issuer's QR code" }
};

function esc(v) { return metadataClient.escapeHtmlText(v); }

function el(id) { return document.getElementById(id); }

function status(text, cls) {
  var e = el("vc_usecase_status");
  if (!e) return;
  e.textContent = text;
  e.className = "vc-note vc-status" + (cls ? " " + cls : "");
}

// The issuer's web page, derived from the configured credential issuer. For the
// mock issuer that is <issuer>/issuer; a real one would be wherever it puts its
// "request your credential" link.
function issuerPageUrl(id) {
  log.debug("Entering issuerPageUrl(). id=" + id);
  var cfg = sdJwtVc.storedRequestConfig();
  var issuer = cfg.credentialIssuer || appconfig.oid4vciIssuerUrlDefault || "";
  var path = (STARTS[id] || {}).issuerPath || "/issuer";
  var url = issuer ? issuer.replace(/\/+$/, "") + path : "";
  log.debug("Leaving issuerPageUrl(). url=" + url);
  return url;
}

function buttonHtml(uc, current) {
  log.debug("Entering buttonHtml(). id=" + uc.id);
  var start = STARTS[uc.id] || {};
  var classes = ["vc-usecase"];
  if (!uc.available) classes.push("vc-usecase-soon");
  if (uc.id === current.id) classes.push("vc-usecase-current");
  var html =
    '<button type="button" class="' + classes.join(" ") + '" id="vc_usecase_' + esc(uc.id) + '"' +
    (uc.available ? ' onclick="return vcissuance0.choose(\'' + esc(uc.id) + '\');"' : ' disabled="disabled"') +
    '>' +
      '<span class="vc-usecase-head">' +
        '<span class="vc-usecase-spec">' + esc(uc.spec) + '</span>' +
        '<span class="vc-usecase-title">' + esc(uc.title) + '</span>' +
        (uc.id === current.id ? '<span class="vc-usecase-flag">currently selected</span>' : '') +
        (uc.available ? '' : '<span class="vc-usecase-flag vc-usecase-flag-soon">not implemented yet</span>') +
      '</span>' +
      '<span class="vc-usecase-summary">' + esc(uc.summary) + '</span>' +
      '<span class="vc-usecase-detail">' + esc(uc.detail) + '</span>' +
      '<span class="vc-usecase-mechanics">' + esc(uc.mechanics) + '</span>' +
      (uc.available ? '<span class="vc-usecase-cta">' + esc(start.cta || "Choose this") + ' &rarr;</span>' : '') +
    '</button>';
  log.debug("Leaving buttonHtml().");
  return html;
}

function render() {
  log.debug("Entering render().");
  var current = sdJwtVc.currentUseCase();
  var host = el("vc_usecases");
  if (host) {
    host.innerHTML = sdJwtVc.useCases().map(function (uc) {
      return buttonHtml(uc, current);
    }).join("");
  }
  status("Currently selected: " + current.spec + " · " + current.label +
         ". Choosing another one only changes how the issuance starts — the credential issuer and client " +
         "settings you have already configured stay as they are.", "");
  log.debug("Leaving render().");
}

// Choosing a use case records it, then sends the user to wherever that use case
// begins: the wallet for the wallet-initiated one, the ISSUER for an offer.
function choose(id) {
  log.debug("Entering choose(). id=" + id);
  var uc = sdJwtVc.setUseCase(id);
  if (!uc) {
    status("That use case is not one this workflow knows about.", "vc-bad");
    return false;
  }
  // A previous run's offer does not belong to this one.
  sdJwtVc.forgetOffer();

  if ((STARTS[uc.id] || {}).issuerPath) {
    var url = issuerPageUrl(uc.id);
    if (!url) {
      status("Set the credential issuer first (step 1 has the field) — the issuer's web page is where an " +
             "offer comes from, and this workflow does not know where it is yet.", "vc-bad");
      window.setTimeout(function () { window.location.href = "/vc-issuance-1.html"; }, 2500);
      return false;
    }
    status("Taking you to the issuer at " + url + " …", "vc-pending");
    window.location.href = url;
    log.debug("Leaving choose(). Sent to the issuer.");
    return false;
  }

  status("Starting at the wallet …", "vc-pending");
  window.location.href = (STARTS[uc.id] || {}).url || "/vc-issuance-1.html";
  log.debug("Leaving choose(). Sent to the wallet.");
  return false;
}

function onload() {
  log.debug("Entering onload().");
  render();
  var step = document.getElementById("vc_step_0");
  if (step) step.className = "vc-step-current";
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  choose: choose,
  render: render,
  issuerPageUrl: issuerPageUrl,
  onload: onload
};
