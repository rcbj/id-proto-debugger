// File: sd_jwt_vc_presentation_3.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC presentation, step 3: what the Verifier decided, and why.
//
// Two accounts of the same event, side by side:
//
//   what the WALLET sent   the presentation, the Key Binding JWT it signed, and
//                          the claim set that follows from those bytes — computed
//                          here rather than taken from what the page intended;
//   what the VERIFIER did  its verdict, check by check, fetched from its result
//                          endpoint (which is not part of OID4VP — a real
//                          verifier tells the End-User in its own UI; this makes
//                          the same information readable).
//
// The interesting part of a presentation is not "accepted": it is which rules
// were checked, and what the verifier ended up knowing. A wallet that sends more
// than was asked for still gets an "accepted", and that is exactly the failure
// this page is meant to make visible.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");

var log = bunyan.createLogger({ name: 'sd_jwt_vc_presentation_3',
                                level: appconfig.logLevel });

var sent = null;
var request = null;

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

// --- what the wallet sent ---------------------------------------------------
function renderWhatWasSent() {
  log.debug("Entering renderWhatWasSent().");
  if (!sent) {
    status("vp_sent_status",
      "Nothing has been presented yet. Step 2 is where a presentation is built and sent.", "vc-pending");
    log.debug("Leaving renderWhatWasSent(). Nothing sent.");
    return false;
  }
  setText("vp_sent_to", (sent.clientId || "—") + " at " + (sent.responseUri || "—"));
  setText("vp_sent_at", sent.sentAt || "—");
  setValue("vp_sent_presentation", sent.presentation || "");
  setValue("vp_sent_kb_jwt", sent.kbJwt || "");
  setJson("vp_sent_kb_payload", sent.kbPayload);

  // The parts, called out — the same treatment step 3 of the issuance workflow
  // gives a credential, except that here the last element is a KB-JWT rather
  // than nothing.
  var parts = String(sent.presentation || "").split("~");
  setHtml("vp_sent_serialized", parts.map(function (part, i) {
    if (part === "") return "";
    var cls = i === 0 ? "vc-part-jwt" : (i === parts.length - 1 ? "vc-part-kb" : "vc-part-disclosure");
    return '<span class="' + cls + '">' + esc(part) + "</span>";
  }).join('<span class="vc-tilde">~</span>'));

  // What a verifier can read out of exactly those bytes.
  var presented = null;
  try {
    presented = sdJwtVp.presentedClaims(sent.presentation);
    setJson("vp_sent_claims", presented.claims);
  } catch (e) {
    setText("vp_sent_claims", "The presentation could not be parsed back: " + e.message);
  }
  // What went, and what to call it. A jwt_vc_json presentation has no
  // Disclosures — counting them reports 0 and then reads every requested claim
  // as withheld, which is the opposite of what happened: that format sends
  // everything. Its unit is the claim.
  var jwtVcJson = presented && presented.parsed &&
                  presented.parsed.format === sdJwtVc.FORMAT_JWT_VC_JSON;
  var disclosed = presented
    ? (jwtVcJson ? Object.keys(presented.claims || {}).length : (presented.parsed.disclosures || []).length)
    : 0;
  var unit = jwtVcJson ? "claim" : "Disclosure";

  // Asked-for against actually-sent, compared by NAME rather than by count.
  // Counting was wrong in both directions: withholding one requested claim while
  // disclosing one that was not asked for nets to zero, and simply withholding a
  // claim gave a negative difference that read as "nothing more than was asked
  // for" — the reassuring message, for a presentation that did not answer the
  // request at all.
  //
  // A requested DCQL path names a claim at some depth; the Disclosure that has to
  // be sent for it is the one at the head of that path.
  var disclosedNames = presented
    ? (jwtVcJson
        ? Object.keys(presented.claims || {})
        : (presented.parsed.disclosures || []).map(function (d) { return d.name; }).filter(Boolean))
    : [];
  var requested = sent.requested || [];
  var requestedHeads = requested.map(function (p) { return String(p).split(".")[0]; });
  var missing = requested.filter(function (p) {
    return disclosedNames.indexOf(String(p).split(".")[0]) === -1;
  });
  var extraNames = disclosedNames.filter(function (n) { return requestedHeads.indexOf(n) === -1; });

  // Neither shortfall nor excess is something a verifier is obliged to report. An
  // OID4VP verifier may accept a presentation that answers only part of its DCQL
  // query — walt.id's verifier-api2 does, since none of its policies looks at
  // query fulfilment — and every verifier silently keeps claims it never asked
  // for. So both are said here, by the one party that can know.
  status("vp_answered", missing.length
    ? "NOT fully answered — withheld: " + missing.join(", ") +
      ". The verifier asked for " + requested.length + " claim(s) and " +
      (requested.length - missing.length) + " went. It may well accept this anyway and say nothing."
    : extraNames.length
      ? "Answered — and " + extraNames.length + " claim(s) went that were never asked for: " +
        extraNames.join(", ") + "."
      : "Answered exactly: every claim asked for was disclosed, and nothing else.",
    missing.length ? "vc-bad" : extraNames.length ? "vc-pending" : "vc-ok");

  status("vp_sent_status",
    "Presented " + disclosed + " " + unit + "(s) to " + (sent.clientId || "the verifier") + ", answering a " +
    "request for " + requested.length + " claim(s)." +
    (missing.length
      ? " " + missing.length + " of them were withheld (" + missing.join(", ") +
        "), so the request was not fully answered."
      : extraNames.length
        ? " That is " + extraNames.length + " more than was asked for (" + extraNames.join(", ") +
          ")" + (jwtVcJson
                   ? " — unavoidable in jwt_vc_json, which cannot send a subset."
                   : " — over-disclosure the verifier will never complain about.")
        : " Nothing more than was asked for."),
    missing.length ? "vc-bad" : extraNames.length ? "vc-pending" : "vc-ok");
  log.debug("Leaving renderWhatWasSent(). disclosed=" + disclosed + ", missing=" + missing.length +
            ", extra=" + extraNames.length);
  return true;
}

// The wallet's own re-check of the bytes it sent: sd_hash recomputed over them,
// and every Disclosure's digest looked up in _sd. If the wallet cannot verify its
// own presentation, no verifier will either.
function recheckOwnPresentation() {
  log.debug("Entering recheckOwnPresentation().");
  if (!sent || !sent.presentation) return Promise.resolve(false);
  var parsed;
  try {
    parsed = sdJwtVc.parseCredential(sent.presentation);
  } catch (e) {
    status("vp_recheck_status", "The presentation cannot be parsed: " + e.message, "vc-bad");
    return Promise.resolve(false);
  }
  var checks = [];
  var payload = parsed.payload || {};

  // A jwt_vc_json presentation is a Verifiable Presentation JWT: no KB-JWT, no
  // sd_hash and no Disclosure digests, because there are no Disclosures. The
  // questions are the same — is this fresh, is it for this verifier, and does
  // the embedded credential still verify — so they are asked of the artefact
  // that actually carries them.
  if (parsed.format === sdJwtVc.FORMAT_JWT_VC_JSON) {
    var vpPayload = parsed.payload || {};
    var embedded = [].concat((vpPayload.vp || {}).verifiableCredential || [])[0] || "";
    var inner = null;
    try {
      inner = sdJwtVc.parseCredential(embedded);
    } catch (e) {
      inner = null;
    }
    checks.push({
      name: "Verifiable Presentation JWT",
      ok: !!embedded,
      detail: embedded
        ? "the credential is carried inside the vp claim of a presentation JWT signed by the holder — this " +
          "format has no Key Binding JWT."
        : "the presentation carries no verifiableCredential."
    });
    checks.push({
      name: "Presentation nonce",
      ok: !!sent.nonce && vpPayload.nonce === sent.nonce,
      detail: "signed over the nonce " + (vpPayload.nonce || "—") +
              "; the request's nonce was " + (sent.nonce || "—") + "."
    });
    checks.push({
      name: "Presentation audience",
      ok: vpPayload.aud === sent.clientId,
      detail: "aud is " + (vpPayload.aud || "—") + "; the verifier's Client Identifier is " +
              (sent.clientId || "—") + "."
    });
    checks.push({
      name: "Selective disclosure",
      ok: true,
      detail: inner
        ? "none is possible in jwt_vc_json: all " + Object.keys(inner.claims || {}).length +
          " claim(s) in the credential were sent, whether or not the verifier asked for them."
        : "the embedded credential could not be read."
    });
    renderRecheck(checks);
    log.debug("Leaving recheckOwnPresentation(). jwt_vc_json, " + checks.length + " check(s).");
    return Promise.resolve(checks.every(function (c) { return c.ok; }));
  }

  var kbParts = String(parsed.kbJwt || "").split(".");
  var kbPayload = {};
  try {
    if (kbParts.length === 3) kbPayload = metadataClient.b64uToJson(kbParts[1]);
  } catch (e) {
    // An unreadable KB-JWT is reported by the check below rather than thrown.
  }
  checks.push({
    name: "Key Binding JWT present",
    ok: !!parsed.kbJwt,
    detail: parsed.kbJwt
      ? "the presentation ends in a KB-JWT, which is what makes it a presentation rather than a copy."
      : "there is no KB-JWT: this credential was presented without a holder proof."
  });
  checks.push({
    name: "KB-JWT nonce",
    ok: !!sent.nonce && kbPayload.nonce === sent.nonce,
    detail: "signed over the nonce " + (kbPayload.nonce || "—") +
            "; the request's nonce was " + (sent.nonce || "—") + "."
  });
  checks.push({
    name: "KB-JWT audience",
    ok: kbPayload.aud === sent.clientId,
    detail: "aud is " + (kbPayload.aud || "—") + "; the verifier's Client Identifier is " +
            (sent.clientId || "—") + "."
  });

  var prefix = sdJwtVp.presentedPrefix(parsed.issuerJwt,
    (parsed.disclosures || []).map(function (d) { return d.encoded; }));
  var sdDigests = sdJwtVc.collectSdDigests(payload);
  return sdJwtVp.sdHash(prefix, payload._sd_alg)
    .then(function (hash) {
      checks.push({
        name: "KB-JWT sd_hash",
        ok: kbPayload.sd_hash === hash,
        detail: kbPayload.sd_hash === hash
          ? "matches a hash recomputed here over the presented bytes, so nothing was added or removed after " +
            "signing."
          : "is " + (kbPayload.sd_hash || "—") + " but these bytes hash to " + hash + "."
      });
      return Promise.all((parsed.disclosures || []).map(function (d) {
        return sdJwtVc.digestForDisclosure(d.encoded, payload._sd_alg)
          .then(function (digest) { return sdDigests.indexOf(digest) >= 0; })
          .catch(function () { return false; });
      }));
    })
    .then(function (matches) {
      var bad = matches.filter(function (m) { return !m; }).length;
      checks.push({
        name: "Disclosure digests",
        ok: bad === 0,
        detail: bad === 0
          ? "every presented Disclosure hashes to a digest in the credential's _sd, so each disclosed claim " +
            "really is part of what the issuer signed."
          : bad + " presented Disclosure(s) are not in _sd."
      });
      renderRecheck(checks);
      log.debug("Leaving recheckOwnPresentation(). failed=" +
                checks.filter(function (c) { return !c.ok; }).length);
      return checks.every(function (c) { return c.ok; });
    });
}

// The wallet's own verdict table. Shared by both formats: the checks differ, how
// they are shown does not.
function renderRecheck(checks) {
  setHtml("vp_recheck_table",
    "<thead><tr><th style='width:22%'>Check</th><th style='width:10%'>Result</th><th>Detail</th></tr></thead>" +
    "<tbody>" + checks.map(function (c) {
      return "<tr><td>" + esc(c.name) + '</td><td class="' + (c.ok ? "vc-ok" : "vc-bad") + '">' +
             (c.ok ? "OK" : "FAILED") + "</td><td>" + esc(c.detail) + "</td></tr>";
    }).join("") + "</tbody>");
  var failed = checks.filter(function (c) { return !c.ok; }).length;
  status("vp_recheck_status", failed === 0
    ? "The wallet's own checks on what it sent all pass."
    : failed + " of the wallet's own checks on what it sent FAIL — the verifier was right to refuse.",
    failed === 0 ? "vc-ok" : "vc-bad");
}

// --- what the verifier said -------------------------------------------------
// Its result endpoint is not part of OID4VP: a real verifier shows the End-User
// its own page. This is the same information, machine-readable, so the workflow
// can show which of the verifier's checks passed rather than only "refused".
//
// Which is why only THIS debugger's own mock verifier is asked. The endpoint is
// its invention, at /oid4vp/result/<state> beside its Response URI; any other
// verifier records the outcome in its own back office, which a wallet has no
// route to and no business reading. walt.id's, for one, keeps it at a management
// API — so deriving the URL from whatever Response URI arrived and asking anyway
// just 404s, and reads on the page as a failure when the presentation in fact
// succeeded.
var MOCK_RESPONSE_URI = /\/oid4vp\/response$/;

function resultUrl() {
  if (!sent || !sent.responseUri || !sent.state) return "";
  if (!MOCK_RESPONSE_URI.test(String(sent.responseUri))) return "";
  return String(sent.responseUri).replace(/\/response$/, "/result/") + encodeURIComponent(sent.state);
}

function renderVerdict(verdict) {
  log.debug("Entering renderVerdict().");
  if (!verdict) {
    setHtml("vp_verifier_table",
      "<tbody><tr><td>The verifier has not recorded a verdict for this presentation.</td></tr></tbody>");
    return false;
  }
  var checks = verdict.checks || [];
  setHtml("vp_verifier_table",
    "<thead><tr><th style='width:22%'>The verifier checked</th><th style='width:10%'>Result</th>" +
    "<th>What it said</th></tr></thead><tbody>" +
    checks.map(function (c) {
      return "<tr><td>" + esc(c.name) + '</td><td class="' + (c.ok ? "vc-ok" : "vc-bad") + '">' +
             (c.ok ? "OK" : "FAILED") + "</td><td>" + esc(c.detail) + "</td></tr>";
    }).join("") + "</tbody>");
  setJson("vp_verifier_claims", verdict.claims || null);
  setText("vp_verifier_disclosed", (verdict.disclosed || []).join(", ") || "—");
  setText("vp_verifier_requested", (verdict.requested || []).join(", ") || "—");
  setText("vp_verifier_extra", (verdict.extraDisclosed || []).length
    ? (verdict.extraDisclosed || []).join(", ") + " — more than it asked for, and it kept them anyway"
    : "none — the wallet disclosed exactly what was asked for");
  var failed = checks.filter(function (c) { return !c.ok; });
  status("vp_verifier_status", verdict.refused
    ? "The wallet refused this request (" + (verdict.error || "access_denied") + "), so nothing was disclosed."
    : verdict.ok
      ? "The verifier ACCEPTED the presentation: all " + checks.length + " of its checks passed."
      : "The verifier REFUSED the presentation: " +
        failed.map(function (c) { return c.name; }).join(", ") + " failed.",
    verdict.ok ? "vc-ok" : "vc-bad");
  log.debug("Leaving renderVerdict(). ok=" + verdict.ok);
  return true;
}

function fetchVerdict() {
  log.debug("Entering fetchVerdict().");
  var url = resultUrl();
  if (!url) {
    // Two different reasons, and they are worth telling apart: a presentation
    // with no state cannot be looked up anywhere, while a presentation to someone
    // else's verifier has a verdict that simply is not the wallet's to read.
    var noState = !sent || !sent.state;
    status("vp_verifier_status", noState
      ? "This presentation carries no state, so its verdict cannot be looked up. What the verifier answered at " +
        "the time is below."
      : "This verifier publishes no per-check verdict a wallet can read — that endpoint is this debugger's own " +
        "mock verifier's invention, not part of OID4VP. What this one answered when the presentation was sent " +
        "is below, and the wallet's own re-check of exactly those bytes is beside it.", "vc-pending");
    setHtml("vp_verifier_table", "<tbody><tr><td>" + (noState
      ? "No state, so there is nothing to look up."
      : "Not published to the wallet by this verifier. Its answer to the direct_post is below.") +
      "</td></tr></tbody>");
    setJson("vp_verifier_raw", sent && sent.response);
    log.debug("Leaving fetchVerdict(). No result endpoint to ask. noState=" + noState);
    return Promise.resolve(false);
  }
  status("vp_verifier_status", "Asking the verifier what it decided …", "vc-pending");
  return metadataClient.fetchJson(url)
    .then(function (doc) {
      sdJwtVc.setJson(sdJwtVp.KEYS.RESULT, doc);
      setJson("vp_verifier_raw", doc);
      renderVerdict(doc.verdict);
      log.debug("Leaving fetchVerdict().");
      return true;
    })
    .catch(function (e) {
      log.error("the verifier's verdict could not be fetched: " + e.message);
      status("vp_verifier_status",
        "The verifier's verdict could not be fetched (" + e.message + "). What it answered when the " +
        "presentation was sent is below.", "vc-bad");
      setJson("vp_verifier_raw", sent && sent.response);
      // A verdict fetched on an earlier visit is better than nothing.
      var kept = sdJwtVc.getJson(sdJwtVp.KEYS.RESULT);
      if (kept) renderVerdict(kept.verdict);
      return false;
    });
}

function presentAgain() {
  window.location.href = sdJwtVp.STEP2_URL;
  return false;
}

function startOver() {
  sdJwtVp.forgetRequest();
  window.location.href = "/sd-jwt-vc-presentation-0.html";
  return false;
}

function copyPresentation() {
  var area = el("vp_sent_presentation");
  if (!area) return false;
  area.select();
  try {
    document.execCommand("copy");
    status("vp_copy_status", "Copied.", "vc-ok");
  } catch (e) {
    status("vp_copy_status", "Could not copy: " + e.message, "vc-bad");
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
  sdJwtVp.renderUseCaseBadge();
  var step = document.getElementById("vp_step_3");
  if (step) step.className = "vc-step-current";
  ["vp_step_0", "vp_step_1", "vp_step_2"].forEach(function (id) {
    var e = document.getElementById(id);
    if (e) e.className = "vc-step-done";
  });

  sent = sdJwtVc.getJson(sdJwtVp.KEYS.PRESENTATION);
  request = sdJwtVp.storedRequest();
  if (!renderWhatWasSent()) {
    log.debug("Leaving onload(). Nothing presented.");
    return;
  }
  recheckOwnPresentation();
  fetchVerdict();
  log.debug("SD-JWT VC presentation step 3 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  fetchVerdict: fetchVerdict,
  recheckOwnPresentation: recheckOwnPresentation,
  presentAgain: presentAgain,
  startOver: startOver,
  copyPresentation: copyPresentation,
  togglePane: togglePane,
  onload: onload
};
