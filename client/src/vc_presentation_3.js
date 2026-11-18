// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_presentation_3.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC presentation, step 3: what the Verifier decided, and why.
//
// Two accounts of the same event, side by side:
//
//   what the WALLET sent   the presentation, the Key Binding JWT it signed, and
//                          the claim set that follows from those bytes —
//                          computed here rather than taken from what the page
//                          intended;
//   what the VERIFIER did  its verdict, check by check, fetched from its result
//                          endpoint (which is not part of OID4VP — a real
//                          verifier tells the End-User in its own UI; this
//                          makes the same information readable).
//
// The interesting part of a presentation is not "accepted": it is which rules
// were checked, and what the verifier ended up knowing. A wallet that sends
// more than was asked for still gets an "accepted", and that is exactly the
// failure this page is meant to make visible.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
var sdJwtVp = require("./sd_jwt_vp");
var vpProtocols = require("./vp_protocols");
var didLib = require("./did");
var dpop = require("./dpop");
var mdoc = require("./mdoc");
var bbs2023 = require("./bbs2023");
// The whole-credential ldp_vc re-check verifies both proofs (#475): the
// holder's and the issuer's, RDFC suites included.
var dataIntegrity = require("./data_integrity_rdfc");
var vcFormats = require("./vc_formats");
// W3C VC-JOSE-COSE presentations (#477).
var vcJoseCose = require("./vc_jose_cose");
// AnonCreds presentations (#479).
var anoncreds = require("./anoncreds");
var anoncredsWallet = require("./anoncreds_wallet");
// JPT and SD-CWT presentations (#478).
var jwpLib = require("./jwp");
var sdCwt = require("./sd_cwt");

var log = bunyan.createLogger({ name: 'vc_presentation_3',
                                level: appconfig.logLevel });

var sent = null;
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

// --- what the wallet sent ---------------------------------------------------
function renderWhatWasSent() {
  log.debug("Entering renderWhatWasSent().");
  if (sent && !sent.presentation && sent.idToken) {
    // A self-issued ID Token on its own: there is no credential to show.
    setText("vp_sent_to", (sent.clientId || "—") + " at " +
            (sent.responseUri || "—"));
    setText("vp_sent_at", sent.sentAt || "—");
    status("vp_sent_status", "Sent a self-issued ID Token and no " +
           "credential: nothing anybody else vouched for left this wallet.",
           "vc-ok");
    status("vp_answered", "Answered: the request asked for an ID Token " +
           "alone.", "vc-ok");
    log.debug("Leaving renderWhatWasSent(). ID Token only.");
    return true;
  }
  if (!sent) {
    status("vp_sent_status",
      "Nothing has been presented yet. Step 2 is where a presentation is " +
          "built and sent.", "vc-pending");
    log.debug("Leaving renderWhatWasSent(). Nothing sent.");
    return false;
  }
  setText("vp_sent_to", (sent.clientId || "—") + " at " + (sent.responseUri ||
          "—"));
  setText("vp_sent_at", sent.sentAt || "—");
  setValue("vp_sent_presentation", sent.presentation || "");
  setValue("vp_sent_kb_jwt", sent.kbJwt || "");
  setJson("vp_sent_kb_payload", sent.kbPayload);

  // The parts, called out — the same treatment step 3 of the issuance workflow
  // gives a credential, except that here the last element is a KB-JWT rather
  // than nothing.
  var parts = mdoc.looksLikeDeviceResponse(sent.presentation) ?
      [sent.presentation] : String(sent.presentation || "").split("~");
  setHtml("vp_sent_serialized", parts.map(function (part, i) {
    if (part === "") return "";
    var cls = i === 0 ? "vc-part-jwt" : (i === parts.length - 1 ?
        "vc-part-kb" : "vc-part-disclosure");
    return '<span class="' + cls + '">' + esc(part) + "</span>";
  }).join('<span class="vc-tilde">~</span>'));

  // What a verifier can read out of exactly those bytes.
  var presented = null;
  try {
    presented = sdJwtVp.presentedClaims(sent.presentation);
    setJson("vp_sent_claims", presented.claims);
  } catch (e) {
    setText("vp_sent_claims", "The presentation could not be parsed back: " +
            e.message);
  }
  // What went, and what to call it. A jwt_vc_json presentation has no
  // Disclosures — counting them reports 0 and then reads every requested claim
  // as withheld, which is the opposite of what happened: that format sends
  // everything. Its unit is the claim.
  var jwtVcJson = presented && presented.parsed &&
                  presented.parsed.format === sdJwtVc.FORMAT_JWT_VC_JSON;
  // An mdoc's unit is the element, and its names are the claim map's.
  var isMdoc = !!(presented && presented.mdoc);
  var disclosed = presented
    ? ((jwtVcJson || isMdoc) ? Object.keys(presented.claims ||
        {}).length : (presented.parsed.disclosures || []).length)
    : 0;
  var unit = jwtVcJson ? "claim" : isMdoc ? "mdoc element" : "Disclosure";

  // Asked-for against actually-sent, compared by NAME rather than by count.
  // Counting was wrong in both directions: withholding one requested claim
  // while disclosing one that was not asked for nets to zero, and simply
  // withholding a claim gave a negative difference that read as "nothing more
  // than was asked for" — the reassuring message, for a presentation that did
  // not answer the request at all.
  //
  // A requested DCQL path names a claim at some depth; the Disclosure that has
  // to be sent for it is the one at the head of that path.
  var disclosedNames = presented
    ? ((jwtVcJson || isMdoc)
        ? Object.keys(presented.claims || {})
        : (presented.parsed.disclosures ||
           []).map(function (d) { return d.name; }).filter(Boolean))
    : [];
  var requested = sent.requested || [];
  var requestedHeads =
      requested.map(function (p) { return String(p).split(".")[0]; });
  var missing = requested.filter(function (p) {
    return disclosedNames.indexOf(String(p).split(".")[0]) === -1;
  });
  var extraNames = disclosedNames.filter(function (n) {
      return requestedHeads.indexOf(n) === -1; });

  // Neither shortfall nor excess is something a verifier is obliged to report.
  // An OID4VP verifier may accept a presentation that answers only part of its
  // DCQL query — walt.id's verifier-api2 does, since none of its policies looks
  // at query fulfilment — and every verifier silently keeps claims it never
  // asked for. So both are said here, by the one party that can know.
  status("vp_answered", missing.length
    ? "NOT fully answered — withheld: " + missing.join(", ") +
      ". The verifier asked for " + requested.length + " claim(s) and " +
      (requested.length - missing.length) +
       " went. It may well accept this anyway and say nothing."
    : extraNames.length
      ? "Answered — and " + extraNames.length +
          " claim(s) went that were never asked for: " +
        extraNames.join(", ") + "."
      : "Answered exactly: every claim asked for was disclosed, and " +
          "nothing else.",
    missing.length ? "vc-bad" : extraNames.length ? "vc-pending" : "vc-ok");

  status("vp_sent_status",
    "Presented " + disclosed + " " + unit + "(s) to " + (sent.clientId ||
        "the verifier") + ", answering a " +
    "request for " + requested.length + " claim(s)." +
    (missing.length
      ? " " + missing.length + " of them were withheld (" + missing.join(", ") +
        "), so the request was not fully answered."
      : extraNames.length
        ? " That is " + extraNames.length + " more than was asked for (" +
            extraNames.join(", ") +
          ")" + (jwtVcJson
                   ? " — unavoidable in jwt_vc_json, which cannot send a subset."
                   : " — over-disclosure the verifier will never " +
                       "complain about.")
        : " Nothing more than was asked for."),
    missing.length ? "vc-bad" : extraNames.length ? "vc-pending" : "vc-ok");
  log.debug("Leaving renderWhatWasSent(). disclosed=" + disclosed +
            ", missing=" + missing.length +
            ", extra=" + extraNames.length);
  return true;
}

// The bbs-2023 half of recheckOwnPresentation().
function recheckBbsPresentation() {
  log.debug("Entering recheckBbsPresentation().");
  var revealed = {};
  try {
    revealed = JSON.parse(sent.presentation);
  } catch (e) {
    revealed = {};
  }
  // Inside a holder-signed VerifiablePresentation when the request needed
  // holder binding: the reveal document is its verifiableCredential.
  var vpProof = null;
  if ([].concat(revealed.type || []).indexOf("VerifiablePresentation") !==
      -1) {
    vpProof = revealed.proof || null;
    revealed = [].concat(revealed.verifiableCredential || [])[0] || {};
  }
  var checks = [];
  var publicKey = null;
  try {
    var held = sdJwtVc.parseCredential(
      sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "");
    publicKey = bbs2023.parseBaseProofValue(
      ((held.document || {}).proof || {}).proofValue).publicKey;
  } catch (e) {
    log.warn("recheckBbsPresentation(): no base proof to read the " +
             "issuer's key from: " + e.message);
  }
  var verifying = publicKey ?
    bbs2023.verifyDerivedProof(revealed, publicKey) :
    Promise.resolve({ verified: false, reason: "the credential this " +
      "wallet holds is not here any more, so the issuer's key cannot be " +
      "read from its base proof." });
  log.debug("Leaving recheckBbsPresentation().");
  return verifying.then(function (r) {
    checks.push({ name: "Derived proof verifies", ok: r.verified,
                  detail: r.reason });
    var ph = r.presentationHeader ?
        new TextDecoder().decode(r.presentationHeader) : null;
    checks.push({ name: "Presentation header", ok: ph === sent.nonce,
      detail: ph === null ? "the derived proof could not be read." :
        "the presentation header is " + JSON.stringify(ph) + "; the " +
        "request's nonce is " + JSON.stringify(sent.nonce) + ". It is " +
        "bound INSIDE the proof: a replay is not caught by comparing a " +
        "claim, the proof itself fails to verify." });
    checks.push({ name: "Statements revealed", ok: !!r.nonMandatory,
      detail: r.nonMandatory ? (r.mandatory || []).length + " mandatory " +
        "and " + r.nonMandatory.length + " selectively disclosed " +
        "statement(s) went. The rest of the credential was withheld — not " +
        "hidden behind a digest, simply never proved." : "unknown." });
    if (vpProof) {
      checks.push({
        name: "Holder proof", ok: vpProof.challenge === sent.nonce &&
            vpProof.domain === sent.clientId,
        detail: "a " + vpProof.cryptosuite + " proof by " +
            vpProof.verificationMethod + " over the whole presentation, " +
            "challenge " + vpProof.challenge + " (the request's nonce is " +
            sent.nonce + "), domain " + vpProof.domain + " (the Verifier " +
            "is " + sent.clientId + ")."
      });
    }
    checks.push({
      name: "Unlinkability", ok: true,
      detail: "this proof was re-randomised at derivation, so presenting " +
          "the same credential again produces different bytes. Neither of " +
          "the other two formats can do that: they replay the issuer's " +
          "signature verbatim."
    });
    renderRecheck(checks);
    log.debug("Leaving recheckBbsPresentation(). " + checks.length +
              " check(s).");
    return true;
  });
}

// The wallet's own re-check of the bytes it sent: sd_hash recomputed over them,
// and every Disclosure's digest looked up in _sd. If the wallet cannot verify
// its own presentation, no verifier will either.
function recheckOwnPresentation() {
  log.debug("Entering recheckOwnPresentation().");
  if (!sent || !sent.presentation) {
    log.debug("Leaving recheckOwnPresentation().");
    return Promise.resolve(false);
  }
  // A whole-credential ldp_vc (#475): both proofs, by data_integrity.js.
  if (vcJoseCose.detect(sent.presentation)) {
    log.debug("Leaving recheckOwnPresentation(). VC-JOSE-COSE.");
    return recheckJoseCose();
  }
  if (anoncredsWallet.looksLikePresentation(sent.presentation)) {
    log.debug("Leaving recheckOwnPresentation(). AnonCreds.");
    return recheckAnoncreds();
  }
  if (jwpLib.looksLikeJwp(sent.presentation) ||
      (String(sent.presentation).indexOf(".") === -1 &&
       sdCwt.looksLikeSdCwt(sent.presentation))) {
    log.debug("Leaving recheckOwnPresentation(). JPT / SD-CWT.");
    return recheckJptSdCwt();
  }
  var whole = wholeLdpPresentation(sent.presentation);
  if (whole) {
    log.debug("Leaving recheckOwnPresentation(). ldp_vc, whole.");
    return recheckWholeLdp(whole);
  }
  // A bbs-2023 presentation is not a JWS at all, so none of the checks below
  // apply: there is no KB-JWT and no sd_hash. It is a reveal document with a
  // derived proof (W3C Data Integrity BBS Cryptosuites v1.0), and the wallet
  // verifies it exactly as a verifier would — against the issuer's key, which
  // the credential's base proof carries.
  if (String(sent.presentation ||
      "").indexOf('"cryptosuite":"bbs-2023"') !== -1) {
    log.debug("Leaving recheckOwnPresentation(). ldp_vc.");
    return recheckBbsPresentation();
  }

  if (mdoc.looksLikeDeviceResponse(sent.presentation)) {
    log.debug("Leaving recheckOwnPresentation(). mso_mdoc.");
    return recheckMdoc();
  }
  var parsed;
  try {
    parsed = sdJwtVc.parseCredential(sent.presentation);
  } catch (e) {
    status("vp_recheck_status", "The presentation cannot be parsed: " +
           e.message, "vc-bad");
    log.debug("Leaving recheckOwnPresentation().");
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
    var embedded = [].concat((vpPayload.vp || {}).verifiableCredential ||
        [])[0] || "";
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
        ? "the credential is carried inside the vp claim of a presentation " +
            "JWT signed by the holder — this " +
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
      detail: "aud is " + (vpPayload.aud || "—") +
          "; the verifier's Client Identifier is " +
              (sent.clientId || "—") + "."
    });
    checks.push({
      name: "Selective disclosure",
      ok: true,
      detail: inner
        ? "none is possible in jwt_vc_json: all " + Object.keys(inner.claims ||
            {}).length +
          " claim(s) in the credential were sent, whether or not the verifier asked for them."
        : "the embedded credential could not be read."
    });
    renderRecheck(checks);
    log.debug("Leaving recheckOwnPresentation(). jwt_vc_json, " +
              checks.length + " check(s).");
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
      : "there is no KB-JWT: this credential was presented without a " +
          "holder proof."
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
    detail: "aud is " + (kbPayload.aud || "—") +
        "; the verifier's Client Identifier is " +
            (sent.clientId || "—") + "."
  });

  var prefix = sdJwtVp.presentedPrefix(parsed.issuerJwt,
    (parsed.disclosures || []).map(function (d) { return d.encoded; }));
  var sdDigests = sdJwtVc.collectSdDigests(payload);
  log.debug("Leaving recheckOwnPresentation().");
  return sdJwtVp.sdHash(prefix, payload._sd_alg)
    .then(function (hash) {
      checks.push({
        name: "KB-JWT sd_hash",
        ok: kbPayload.sd_hash === hash,
        detail: kbPayload.sd_hash === hash
          ? "matches a hash recomputed here over the presented bytes, so " +
              "nothing was added or removed after " +
            "signing."
          : "is " + (kbPayload.sd_hash || "—") + " but these bytes hash to " +
              hash + "."
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
          ? "every presented Disclosure hashes to a digest in the " +
              "credential's _sd, so each disclosed claim " +
            "really is part of what the issuer signed."
          : bad + " presented Disclosure(s) are not in _sd."
      });
      renderRecheck(checks);
      log.debug("Leaving recheckOwnPresentation(). failed=" +
                checks.filter(function (c) { return !c.ok; }).length);
      return checks.every(function (c) { return c.ok; });
    });
}

// An mdoc re-checked from the DeviceResponse that went: the issuer's
// signature and every element's digest, then the device signature over the
// transcript rebuilt from what the wallet recorded about the request.
function recheckMdoc() {
  log.debug("Entering recheckMdoc().");
  var read;
  try {
    read = mdoc.readDeviceResponse(sent.presentation);
  } catch (e) {
    status("vp_recheck_status", "The DeviceResponse cannot be read: " +
           e.message, "vc-bad");
    log.debug("Leaving recheckMdoc(). Unreadable.");
    return Promise.resolve(false);
  }
  log.debug("Leaving recheckMdoc().");
  return mdoc.checkIssuerSigned(read.parsed).then(function (checks) {
    return mdoc.checkDeviceSignature(read, {
      clientId: sent.clientId, nonce: sent.nonce,
      responseUri: sent.responseUri,
      encryptionJwk: sent.encryptionJwk || null
    }).then(function (ok) {
      checks.push({ name: "Device signature", ok: ok, detail: ok ?
        "verifies with the MSO's device key over the session transcript " +
        "for this client_id, nonce and response URI" +
        (sent.encryptionJwk ? ", and the key the answer was encrypted to." :
         ".") : "does NOT verify over the transcript for this request." });
      checks.push({ name: "Selective disclosure", ok: true, detail:
        read.parsed.items.length + " element(s) went; the rest of the mdoc " +
        "was withheld and is represented only by digests in the MSO." });
      renderRecheck(checks);
      return checks.every(function (c) {
        return c.ok;
      });
    });
  });
}

// The wallet's own verdict table. Shared by both formats: the checks differ,
// how they are shown does not.
// A whole-credential ldp_vc presentation (#475): a VerifiablePresentation
// around a credential whose proof is not selective, or that credential bare
// when no holder binding was asked for. Answers { vp, credential } or null
// for anything else (a bbs-2023 envelope, a JWT, an mdoc).
function wholeLdpPresentation(text) {
  log.debug("Entering wholeLdpPresentation().");
  var doc;
  try {
    doc = JSON.parse(String(text || ""));
  } catch (e) {
    log.debug("Leaving wholeLdpPresentation(). Not JSON.");
    return null;
  }
  if (!doc || typeof doc !== "object") {
    log.debug("Leaving wholeLdpPresentation(). Not an object.");
    return null;
  }
  var isVp = [].concat(doc.type || []).indexOf("VerifiablePresentation") !==
      -1;
  var credential = isVp ? [].concat(doc.verifiableCredential || [])[0] : doc;
  if (!credential || typeof credential !== "object" ||
      !vcFormats.isLdpSecured(credential)) {
    log.debug("Leaving wholeLdpPresentation(). No recognised proof.");
    return null;
  }
  var suite = vcFormats.ldpSuiteOf([].concat(credential.proof)[0]);
  // A derived BbsBlsSignatureProof2020 or ecdsa-sd-2023 credential is a
  // whole JSON-LD credential too, checked the same way by data_integrity.js;
  // bbs-2023 has its own path below.
  if (vcFormats.isSelectiveLdpSuite(suite) &&
      suite !== "BbsBlsSignatureProof2020" && suite !== "ecdsa-sd-2023") {
    log.debug("Leaving wholeLdpPresentation(). Selective: " + suite);
    return null;
  }
  log.debug("Leaving wholeLdpPresentation(). " + suite);
  return { vp: isVp ? doc : null, credential: credential, suite: suite };
}

// The request's nonce as a derived BbsBlsSignatureProof2020 carries it.
function bytesToB64(text) {
  log.debug("Entering bytesToB64().");
  var bytes = new TextEncoder().encode(String(text));
  var bin = "";
  for (var i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  log.debug("Leaving bytesToB64().");
  return btoa(bin);
}

// A VC-JOSE-COSE presentation re-checked from the bytes that went (#477):
// a vp+jwt and the credential enveloped in it, or a vc+sd-jwt and its Key
// Binding JWT, each verified by vc_jose_cose.js.
function recheckJoseCose() {
  log.debug("Entering recheckJoseCose().");
  var checks = [];
  var row = function (name, r, detail) {
    log.debug("Entering row(). " + name);
    log.debug("Leaving row().");
    checks.push({ name: name, ok: !!r.valid, detail: r.valid ? detail +
      (r.warnings && r.warnings.length ? " Note: " + r.warnings.join(" ") :
       "") : r.errors.join(" ") });
  };
  log.debug("Leaving recheckJoseCose().");
  return vcJoseCose.verify(sent.presentation, { kbNonce: sent.nonce,
                                                kbAudience: sent.clientId })
    .then(function (outer) {
      if (outer.kind === "vp") {
        row("Holder's vp+jwt", outer, "signed by " +
            outer.verificationMethod + ".");
        var claims = outer.document || {};
        checks.push({ name: "Nonce and audience",
          ok: claims.nonce === sent.nonce && claims.aud === sent.clientId,
          detail: "nonce " + claims.nonce + " (the request's is " +
            sent.nonce + "), aud " + claims.aud + " (the Verifier is " +
            sent.clientId + ")." });
        var env = [].concat(claims.verifiableCredential || [])[0];
        var inner = vcJoseCose.unenvelope(env).secured;
        return vcJoseCose.verify(inner).then(function (vc) {
          row("Enveloped credential", vc, vc.format + " signed by " +
              vc.verificationMethod + ", carried as " +
              "EnvelopedVerifiableCredential.");
          return checks;
        });
      }
      row("Issuer's vc+sd-jwt", outer, (outer.disclosed || []).length +
          " Disclosure(s) went, signed by " + outer.verificationMethod + ".");
      var kb = outer.keyBinding || {};
      checks.push({ name: "Key Binding JWT", ok: !kb.present || !!kb.valid,
        detail: kb.present ? (kb.valid ? "nonce, audience and sd_hash " +
          "are this request's and the bytes that went." : kb.reason) :
          "none was sent." });
      return checks;
    }).then(function (all) {
      renderRecheck(all);
      log.debug("Leaving recheckJoseCose(). " + all.length + " check(s).");
      return true;
    });
}

// An AnonCreds presentation re-checked by anoncreds.js's verifier, against
// the request this debugger maps the OpenID4VP one to, with the held
// credential's schema and credential definition (#479).
function recheckAnoncreds() {
  log.debug("Entering recheckAnoncreds().");
  var pres = JSON.parse(sent.presentation);
  var held = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  var checks = [];
  try {
    var b = anoncredsWallet.parseBundle(held);
    var names = Object.keys(anoncredsWallet.revealedClaims(pres, null));
    var revocation = anoncredsWallet.revocationOf(b);
    // The request the presentation answered, as step 2 recorded it (it
    // carries the predicates); else the mapping rebuilt from what it
    // reveals, as before predicates existed.
    var request = sent.anoncredsRequest ||
      anoncredsWallet.presentationRequestFor(names, sent.nonce,
        revocation ? revocation.list.timestamp : null);
    var schemas = {};
    schemas[b.schemaId] = b.schema;
    var cds = {};
    cds[b.credDefId] = b.credentialDefinition;
    var r = anoncreds.verifyPresentation(
      anoncredsWallet.legacyPresentation(pres, request), {
      presentationRequest: request,
      schemas: schemas, credentialDefinitions: cds,
      revocationRegistryDefinitions: revocation ? revocation.definitions : {},
      revocationStatusLists: revocation ? [revocation.list] : [] });
    checks.push({ name: "AnonCreds presentation (CL)", ok: r.valid,
      detail: r.valid ? names.length + " attribute(s) revealed; the proof " +
        "verifies under the request nonce " + request.nonce + " (from the " +
        "OpenID4VP nonce by this debugger's mapping)" + (revocation ?
        ", with a non-revocation proof at the status list of " +
        revocation.list.timestamp : "") + "." :
        r.errors.join(" ") });
    (r.warnings || []).forEach(function (w) {
      checks.push({ name: "Note", ok: true, detail: w });
    });
    anoncredsWallet.provenPredicates(pres, request).forEach(function (p) {
      checks.push({ name: "Predicate " + p.name + " " + p.p_type + " " +
        p.p_value, ok: p.answered && r.valid, detail: p.answered ?
        "proven in zero knowledge by sub-proof " + p.subProofIndex +
        "; the value of " + p.name + " was not revealed." :
        "the presentation does not answer predicate " + p.referent + "." });
    });
  } catch (e) {
    checks.push({ name: "AnonCreds presentation (CL)", ok: false,
                  detail: "could not be re-checked: " + e.message });
  }
  renderRecheck(checks);
  log.debug("Leaving recheckAnoncreds().");
  return Promise.resolve(true);
}

// A JPT or an SD-CWT Key Binding Token re-checked from the bytes that went
// (#478), with the issuer key resolved from its kid / iss, against this
// request's nonce and the Verifier's Client Identifier.
function recheckJptSdCwt() {
  log.debug("Entering recheckJptSdCwt().");
  var isJpt = jwpLib.looksLikeJwp(sent.presentation);
  var kid;
  var iss;
  if (isJpt) {
    var h = jwpLib.parse(sent.presentation).issuerHeader.value;
    kid = h.kid;
    iss = h.iss;
  } else {
    var p = sdCwt.parse(sent.presentation);
    var k = p.sdCwt.protected.get(sdCwt.HEADER.kid);
    kid = k instanceof Uint8Array ? new TextDecoder().decode(k) : k;
    iss = p.sdCwt.payload.get(sdCwt.CLAIMS.iss);
  }
  log.debug("Leaving recheckJptSdCwt().");
  return sdJwtVp.issuerKeyFor(kid, iss).then(function (issuerKey) {
    var r = isJpt ?
      jwpLib.verify(sent.presentation, { issuerKey: issuerKey || {},
                                         nonce: sent.nonce,
                                         aud: sent.clientId }) :
      sdCwt.verify(sent.presentation, { issuerKey: issuerKey || undefined,
                                        aud: sent.clientId,
                                        cnonce: sent.nonce });
    var checks = [{
      name: isJpt ? "JSON Web Proof (" + jwpLib.DRAFT + ", DRAFT)" :
        "SD-CWT Key Binding Token (" + sdCwt.DRAFT + ", DRAFT)",
      ok: r.valid,
      detail: r.valid ? (isJpt ? r.disclosed.length + " payload slot(s) " +
        "disclosed; the proof, the Presentation Header's nonce and aud " +
        "verify." : (r.disclosed || []).length + " disclosure(s) went; " +
        "the issuer's signature, the KBT by the cnf key, aud and cnonce " +
        "verify.") : (issuerKey ? "" : "The issuer key (" + kid + ") " +
        "could not be resolved. ") + r.errors.join(" ")
    }];
    (r.warnings || []).forEach(function (w) {
      checks.push({ name: "Note", ok: true, detail: w });
    });
    renderRecheck(checks);
    return true;
  });
}

function proofRow(name, result) {
  log.debug("Entering proofRow(). " + name);
  var p = (result.proofs || [])[0] || {};
  var ok = !!result.valid;
  var detail = ok ? p.suite + " by " + p.verificationMethod + " verifies." :
      (p.suite || "the proof") + " does NOT verify: " +
      (p.reason || result.reason || "no reason given") + ".";
  log.debug("Leaving proofRow(). " + ok);
  return { name: name, ok: ok, detail: detail };
}

// Both proofs verified by data_integrity.js from the bytes that went, and
// the holder compared with the credential's subject.
function recheckWholeLdp(whole) {
  log.debug("Entering recheckWholeLdp(). " + whole.suite);
  var checks = [];
  var verifyingVp = whole.vp ? dataIntegrity.verifyProof(whole.vp) :
      Promise.resolve(null);
  log.debug("Leaving recheckWholeLdp().");
  return Promise.all([verifyingVp,
                      dataIntegrity.verifyProof(whole.credential)])
    .then(function (results) {
      var vpResult = results[0];
      var vcResult = results[1];
      checks.push(proofRow("Issuer proof", vcResult));
      if (vpResult) {
        var vpProof = [].concat(whole.vp.proof || [])[0] || {};
        checks.push(proofRow("Holder proof", vpResult));
        checks.push({
          name: "Challenge and domain",
          ok: vpProof.challenge === sent.nonce &&
              vpProof.domain === sent.clientId,
          detail: "challenge " + vpProof.challenge + " (the request's " +
              "nonce is " + sent.nonce + "), domain " + vpProof.domain +
              " (the Verifier is " + sent.clientId + ")."
        });
        var subject = [].concat(whole.credential.credentialSubject || [])[0] ||
            {};
        checks.push({
          name: "Holder is the subject",
          ok: !!whole.vp.holder && whole.vp.holder === subject.id,
          detail: "the VP's holder is " + whole.vp.holder + " and the " +
              "credential's subject is " + subject.id + "."
        });
      } else {
        checks.push({
          name: "Holder proof", ok: true,
          detail: "none: the request did not ask for holder binding, so " +
              "the credential went bare and anyone holding it could have " +
              "sent it."
        });
      }
      if (whole.suite === "BbsBlsSignatureProof2020") {
        var derived = [].concat(whole.credential.proof)[0] || {};
        var expected = sent.nonce ? bytesToB64(sent.nonce) : "";
        checks.push({
          name: "Proof nonce",
          ok: !expected || derived.nonce === expected,
          detail: "the derived proof's nonce is " + derived.nonce +
              (expected ? "; the request's nonce, base64, is " + expected +
              "." : ".")
        });
        checks.push({
          name: "Disclosure", ok: true,
          detail: ((vcResult.proofs[0] || {}).disclosedStatements || [])
            .length + " canonical statement(s) went, proved by a " +
            "BbsBlsSignatureProof2020 derived from the issuer's " +
            "BbsBlsSignature2020. The rest were never sent."
        });
      } else if (whole.suite === "ecdsa-sd-2023") {
        checks.push({
          name: "Disclosure", ok: true,
          detail: ((vcResult.proofs[0] || {}).disclosedStatements || [])
            .length + " canonical statement(s) went, each with the " +
            "issuer's own ecdsa-sd-2023 signature. Those signatures are the " +
            "same in every presentation of this credential, so a Verifier " +
            "can link them; only the holder's VP binds this one to the " +
            "request."
        });
      } else {
        checks.push({
          name: "Disclosure", ok: true,
          detail: "the whole credential went: " + whole.suite + " has no " +
              "selective disclosure, and its proof covers every statement."
        });
      }
      renderRecheck(checks);
      log.debug("Leaving recheckWholeLdp(). " + checks.length + " check(s).");
      return true;
    });
}

function renderRecheck(checks) {
  log.debug("Entering renderRecheck().");
  setHtml("vp_recheck_table",
    "<thead><tr><th style='width:22%'>Check</th><th " +
        "style='width:10%'>Result</th><th>Detail</th></tr></thead>" +
    "<tbody>" + checks.map(function (c) {
      return "<tr><td>" + esc(c.name) + '</td><td class="' + (c.ok ?
          "vc-ok" : "vc-bad") + '">' +
             (c.ok ? "OK" : "FAILED") + "</td><td>" + esc(c.detail) +
              "</td></tr>";
    }).join("") + "</tbody>");
  var failed = checks.filter(function (c) { return !c.ok; }).length;
  status("vp_recheck_status", failed === 0
    ? "The wallet's own checks on what it sent all pass."
    : failed + " of the wallet's own checks on what it sent FAIL — the " +
        "verifier was right to refuse.",
    failed === 0 ? "vc-ok" : "vc-bad");
  log.debug("Leaving renderRecheck().");
}

// ---------------------------------------------------------------------------
// How it was answered: the protocol, the delivery, and — re-checked from the
// bytes that went — the self-issued ID Token and the encryption around it.
// ---------------------------------------------------------------------------

// The key an ID Token's subject names (SIOPv2 section 11.1): sub_jwk whose
// thumbprint is sub, or the key a did:jwk / did:key subject IS.
function idTokenSubjectKey(header, payload) {
  log.debug("Entering idTokenSubjectKey().");
  var sub = String(payload.sub || "");
  if (/^did:jwk:/.test(sub)) {
    log.debug("Leaving idTokenSubjectKey(). did:jwk");
    return Promise.resolve({ jwk: didLib.didJwkToJwk(sub), how: "did:jwk" });
  }
  if (/^did:key:/.test(sub)) {
    log.debug("Leaving idTokenSubjectKey(). did:key");
    return Promise.resolve({ jwk: didLib.didKeyToJwk(sub), how: "did:key" });
  }
  if (!payload.sub_jwk) {
    log.debug("Leaving idTokenSubjectKey(). No key.");
    return Promise.resolve({ jwk: null, how: "none" });
  }
  log.debug("Leaving idTokenSubjectKey().");
  return dpop.thumbprint(payload.sub_jwk).then(function (tp) {
    return { jwk: payload.sub_jwk, how: "sub_jwk", thumbprintOk: tp === sub };
  });
}

// The key the presentation beside it is bound to, for the "same holder"
// check.
function presentationHolderKey() {
  log.debug("Entering presentationHolderKey().");
  if (mdoc.looksLikeDeviceResponse(sent.presentation)) {
    log.debug("Leaving presentationHolderKey(). mso_mdoc.");
    return mdoc.readDeviceResponse(sent.presentation).parsed.deviceJwk;
  }
  try {
    var p = JSON.parse(sent.presentation);
    var vm = ((p && p.proof) || {}).verificationMethod || "";
    var did = vm.split("#")[0];
    log.debug("Leaving presentationHolderKey(). ldp_vc.");
    return /^did:jwk:/.test(did) ? didLib.didJwkToJwk(did) :
           /^did:key:/.test(did) ? didLib.didKeyToJwk(did) : null;
  } catch (e) {
    // Not JSON: a JWT-shaped presentation.
  }
  try {
    var parsed = sdJwtVc.parseCredential(sent.presentation);
    var payload = parsed.payload || {};
    if (parsed.format === sdJwtVc.FORMAT_JWT_VC_JSON) {
      var inner = sdJwtVc.parseCredential([].concat((payload.vp || {})
          .verifiableCredential || [])[0] || "");
      payload = inner.payload || {};
    }
    log.debug("Leaving presentationHolderKey().");
    return (payload.cnf && payload.cnf.jwk) || null;
  } catch (e) {
    log.debug("Leaving presentationHolderKey(). Unreadable.");
    return null;
  }
}

function renderAnswer() {
  log.debug("Entering renderAnswer().");
  if (!sent) {
    log.debug("Leaving renderAnswer(). Nothing sent.");
    return Promise.resolve(false);
  }
  var protocol = vpProtocols.protocolById(sent.protocol) ||
      vpProtocols.protocolById(vpProtocols.DEFAULT_PROTOCOL);
  setText("vp_answer_protocol", protocol.label);
  setText("vp_answer_mode", (sent.responseType || "vp_token") + " / " +
          (sent.responseMode || "direct_post") + (sent.delivery ? " (" +
          sent.delivery + ")" : "") + (sent.route === "api" ?
          ", through the debugger's api" : ""));
  setText("vp_answer_binding", sent.holderBinding || (sent.kbJwt ?
          "Key Binding JWT" : sent.format === sdJwtVc.FORMAT_JWT_VC_JSON ?
          "Verifiable Presentation JWT" : "—"));
  setJson("vp_answer_id_token", sent.idToken ? { header: sent.idTokenHeader,
          payload: sent.idTokenPayload } : null);
  setJson("vp_answer_jwe_header", sent.encryption ?
          sent.encryption.header : null);
  var plaintext = null;
  if (sent.encryption) {
    try {
      plaintext = JSON.parse(sent.encryption.plaintext);
    } catch (e) {
      plaintext = sent.encryption.plaintext;
    }
  }
  setJson("vp_answer_plaintext", plaintext);
  var checks = [];
  if (sent.encryption) {
    checks.push({ name: "Encrypted", ok: true, detail: sent.encryption
      .header.alg + " / " + sent.encryption.enc + " to the Verifier's key " +
      (sent.encryption.kid || "(no kid)") + "; the form carried one field, " +
      "response." });
  } else if (sent.protocol === vpProtocols.PROTOCOL_HAIP) {
    checks.push({ name: "Encrypted", ok: false, detail: "HAIP 1.0 has the " +
      "answer encrypted, and this one went in the clear." });
  }
  var p = sent.idTokenPayload;
  if (!p) {
    renderAnswerChecks(checks);
    log.debug("Leaving renderAnswer(). No ID Token.");
    return Promise.resolve(true);
  }
  checks.push({ name: "iss equals sub", ok: p.iss === p.sub, detail:
    "iss " + p.iss + ", sub " + p.sub + " (SIOPv2 section 11)." });
  checks.push({ name: "ID Token aud", ok: p.aud === sent.clientId, detail:
    "aud " + p.aud + "; the Verifier is " + sent.clientId + "." });
  checks.push({ name: "ID Token nonce", ok: p.nonce === sent.nonce, detail:
    "nonce " + p.nonce + "; the request's was " + sent.nonce + "." });
  log.debug("Leaving renderAnswer().");
  return idTokenSubjectKey(sent.idTokenHeader || {}, p).then(function (key) {
    if (key.how === "sub_jwk") {
      checks.push({ name: "Subject is the key", ok: !!key.thumbprintOk,
        detail: "sub is " + (key.thumbprintOk ? "" : "NOT ") + "the RFC " +
        "7638 thumbprint of sub_jwk." });
    }
    if (!key.jwk) {
      checks.push({ name: "ID Token signature", ok: false, detail: "the " +
        "subject names no key to verify it with." });
      return null;
    }
    var holder = presentationHolderKey();
    if (sent.presentation) {
      checks.push({ name: "Same holder", ok: !!holder &&
        sdJwtVc.samePublicKey(holder, key.jwk), detail: holder ?
        "the ID Token's subject key " + (sdJwtVc.samePublicKey(holder,
        key.jwk) ? "IS" : "is NOT") + " the key the presentation is bound " +
        "to." : "the presentation names no holder key to compare with." });
    }
    return metadataClient.verifyJwsWithJwks(sent.idToken, { keys: [key.jwk] },
                                            "the ID Token");
  }).then(function (v) {
    if (v) {
      checks.push({ name: "ID Token signature", ok: !!v.valid, detail:
        v.valid ? "verifies with the key its subject names." :
        "does NOT verify with the key its subject names." });
    }
    renderAnswerChecks(checks);
    return true;
  }).catch(function (e) {
    checks.push({ name: "ID Token", ok: false, detail: e.message });
    renderAnswerChecks(checks);
    return false;
  });
}

function renderAnswerChecks(checks) {
  log.debug("Entering renderAnswerChecks().");
  setHtml("vp_answer_checks",
    "<thead><tr><th style='width:22%'>Check</th><th " +
        "style='width:10%'>Result</th><th>Detail</th></tr></thead>" +
    "<tbody>" + checks.map(function (c) {
      return "<tr><td>" + esc(c.name) + '</td><td class="' + (c.ok ?
          "vc-ok" : "vc-bad") + '">' + (c.ok ? "OK" : "FAILED") + "</td><td>" +
          esc(c.detail) + "</td></tr>";
    }).join("") + "</tbody>");
  var failed = checks.filter(function (c) { return !c.ok; }).length;
  status("vp_answer_status", !checks.length ? "Answered in the clear, with " +
    "no ID Token: there is nothing more to check here." : failed === 0 ?
    "Every check on the answer around the presentation passes." :
    failed + " check(s) on the answer FAIL.", failed ? "vc-bad" : "vc-ok");
  log.debug("Leaving renderAnswerChecks().");
}

// --- what the verifier said -------------------------------------------------
// OpenID4VP 1.0 section 8.2: the Response Endpoint answers the wallet's
// direct_post with 200 and, optionally, a `redirect_uri` the wallet sends the
// browser to. That answer is ALL a wallet is told. A Verifier's verdict —
// which of its checks passed — is recorded in its own back office, which a
// wallet has no route to and no business reading. (This page used to read
// one from iya-sts's demonstration endpoint /oid4vp/result/<state>, which
// iya-sts #594 deleted; the wallet's own re-check of exactly the bytes it
// sent is in the pane above, and that is the half a wallet can own.)
function showVerifierAnswer() {
  log.debug("Entering showVerifierAnswer().");
  if (!sent) {
    log.debug("Leaving showVerifierAnswer(). Nothing sent.");
    return false;
  }
  var answer = sent.response;
  var redirect = answer && typeof answer === "object" && answer.redirect_uri
    ? String(answer.redirect_uri) : "";
  var code = sent.statusCode ? "HTTP " + sent.statusCode : "an answer";
  var said;
  if (sent.accepted === null || sent.accepted === undefined) {
    // A fragment, query or form_post answer goes back through the BROWSER,
    // so the wallet never sees what the Verifier said to it.
    status("vp_verifier_status", "The answer was handed to the browser (" +
           (sent.responseMode || "") + "), so whatever the Verifier said, " +
           "it said to the page it sent the browser to, not to this wallet.",
           "vc-pending");
    setJson("vp_verifier_raw", answer === undefined ? null : answer);
    log.debug("Leaving showVerifierAnswer(). Through the browser.");
    return false;
  }
  if (sent.accepted) {
    said = "The Verifier answered " + code + ": it accepted the response." +
      (redirect ? " It sends the browser on to " + redirect + "." :
       " It named no redirect_uri, so the browser stays here.");
  } else {
    var err = (answer && typeof answer === "object" &&
               (answer.error_description || answer.error)) || code;
    said = "The Verifier refused the response: " + err + ".";
  }
  status("vp_verifier_status", said, sent.accepted ? "vc-ok" : "vc-bad");
  setJson("vp_verifier_raw", answer === undefined ? null : answer);
  log.debug("Leaving showVerifierAnswer(). accepted=" + !!sent.accepted);
  return !!sent.accepted;
}

function presentAgain() {
  log.debug("Entering presentAgain().");
  window.location.href = sdJwtVp.STEP2_URL;
  log.debug("Leaving presentAgain().");
  return false;
}

function startOver() {
  log.debug("Entering startOver().");
  sdJwtVp.forgetRequest();
  window.location.href = "/vc-presentation-0.html";
  log.debug("Leaving startOver().");
  return false;
}

function copyPresentation() {
  log.debug("Entering copyPresentation().");
  var area = el("vp_sent_presentation");
  if (!area) {
    log.debug("Leaving copyPresentation().");
    return false;
  }
  area.select();
  try {
    document.execCommand("copy");
    status("vp_copy_status", "Copied.", "vc-ok");
  } catch (e) {
    status("vp_copy_status", "Could not copy: " + e.message, "vc-bad");
  }
  log.debug("Leaving copyPresentation().");
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
  if (sent.presentation) {
    recheckOwnPresentation();
  } else {
    status("vp_recheck_status", "No credential was presented, so there is " +
           "no presentation to re-check.", "vc-ok");
  }
  renderAnswer();
  showVerifierAnswer();
  log.debug("SD-JWT VC presentation step 3 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  showVerifierAnswer: showVerifierAnswer,
  recheckOwnPresentation: recheckOwnPresentation,
  presentAgain: presentAgain,
  startOver: startOver,
  copyPresentation: copyPresentation,
  togglePane: togglePane,
  onload: onload
};
