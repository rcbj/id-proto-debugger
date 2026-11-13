// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_issuance_0.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 0: choose how the issuance starts.
//
// OID4VCI's Appendix H describes several ways a credential gets into a wallet.
// They are not different protocols — they differ in who starts, how the wallet
// learns what is on offer, and which grant authorizes it — so the choice is
// made once here and every later page follows it.
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
// start at the ISSUER'S WEBSITE, not at the wallet — that is the whole point
// of them — and at one configured URL (`vc_issuer_site_url`), any issuer's,
// because nothing in OpenID4VCI says what an issuer's own pages are called.
// The two pre-authorized ones (cross-device, deferred) are offers a person
// gets wherever their issuer gives them out — an account page, an operator —
// which is why each says so rather than pretending to a page that makes one.
var STARTS = {
  "wallet-initiated": { url: "/vc-issuance-1.html",
                       cta: "Start at the wallet" },
  "offer-same-device": { site: true, cta: "Go to the issuer's website" },
  "offer-cross-device": { site: true, preAuthorized: true,
                          cta: "Go to the issuer's website" },
  "offer-deferred": { site: true, preAuthorized: true,
                      cta: "Go to the issuer's website" }
};

function esc(v) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return metadataClient.escapeHtmlText(v);
}

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function status(text, cls) {
  log.debug("Entering status().");
  var e = el("vc_usecase_status");
  if (!e) {
    log.debug("Leaving status().");
    return;
  }
  e.textContent = text;
  e.className = "vc-note vc-status" + (cls ? " " + cls : "");
  log.debug("Leaving status().");
}

// The issuer's website: the configured one, else this deployment's default,
// else nothing (the wallet then takes an offer pasted into step 1).
function issuerSiteUrl() {
  log.debug("Entering issuerSiteUrl().");
  var url = String(sdJwtVc.get(sdJwtVc.KEYS.ISSUER_SITE_URL) ||
                   appconfig.oid4vciIssuerSiteUrlDefault || "").trim();
  log.debug("Leaving issuerSiteUrl(). url=" + url);
  return url;
}

// The same page for every offer use case: what differs is what the reader
// asks for on it.
function issuerPageUrl(id) {
  log.debug("Entering issuerPageUrl(). id=" + id);
  var url = (STARTS[id] || {}).site ? issuerSiteUrl() : "";
  log.debug("Leaving issuerPageUrl(). url=" + url);
  return url;
}

// The field above the use cases.
function saveIssuerSite() {
  log.debug("Entering saveIssuerSite().");
  var e = el("vc_issuer_site_url");
  var v = e ? String(e.value || "").trim() : "";
  if (v) {
    sdJwtVc.set(sdJwtVc.KEYS.ISSUER_SITE_URL, v);
  } else {
    sdJwtVc.remove(sdJwtVc.KEYS.ISSUER_SITE_URL);
  }
  render();
  log.debug("Leaving saveIssuerSite().");
  return false;
}

function buttonHtml(uc, current) {
  log.debug("Entering buttonHtml(). id=" + uc.id);
  var start = STARTS[uc.id] || {};
  var classes = ["vc-usecase"];
  if (!uc.available) classes.push("vc-usecase-soon");
  if (uc.id === current.id) classes.push("vc-usecase-current");
  var html =
    '<button type="button" class="' + classes.join(" ") + '" id="vc_usecase_' +
        esc(uc.id) + '"' +
    (uc.available ? ' onclick="return vcissuance0.choose(\'' + esc(uc.id) +
     '\');"' : ' disabled="disabled"') +
    '>' +
      '<span class="vc-usecase-head">' +
        '<span class="vc-usecase-spec">' + esc(uc.spec) + '</span>' +
        '<span class="vc-usecase-title">' + esc(uc.title) + '</span>' +
        (uc.id === current.id ?
         '<span class="vc-usecase-flag">currently selected</span>' : '') +
        (uc.available ? '' : '<span class="vc-usecase-flag ' +
         'vc-usecase-flag-soon">not implemented yet</span>') +
      '</span>' +
      '<span class="vc-usecase-summary">' + esc(uc.summary) + '</span>' +
      '<span class="vc-usecase-detail">' + esc(uc.detail) + '</span>' +
      '<span class="vc-usecase-mechanics">' + esc(uc.mechanics) + '</span>' +
      (uc.available ? '<span class="vc-usecase-cta">' + esc(start.cta ||
       "Choose this") + ' &rarr;</span>' : '') +
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
         ". Choosing another one only changes how the issuance starts — the " +
             "credential issuer and client " +
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
    log.debug("Leaving choose().");
    return false;
  }
  // A previous run's offer does not belong to this one.
  sdJwtVc.forgetOffer();

  if ((STARTS[uc.id] || {}).site) {
    var url = issuerPageUrl(uc.id);
    if (!url) {
      status("Set the issuer's website first (the field above) — it is " +
             "where an offer comes from, and this workflow does not know " +
             "where it is yet. Or paste an offer into step 1.", "vc-bad");
      window.setTimeout(function () { window.location.href =
                        "/vc-issuance-1.html"; }, 2500);
      log.debug("Leaving choose().");
      return false;
    }
    status("Taking you to the issuer's website at " + url +
           ((STARTS[uc.id] || {}).preAuthorized
             ? " — a pre-authorized offer, with a transaction code, comes " +
               "from wherever your issuer makes one (an account page you " +
               "sign in to, or an operator); open its link here or paste it " +
               "into step 1"
             : "") + " …", "vc-pending");
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
  var site = el("vc_issuer_site_url");
  if (site) {
    site.value = sdJwtVc.get(sdJwtVc.KEYS.ISSUER_SITE_URL) ||
                 appconfig.oid4vciIssuerSiteUrlDefault || "";
  }
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
  issuerSiteUrl: issuerSiteUrl,
  saveIssuerSite: saveIssuerSite,
  onload: onload
};
