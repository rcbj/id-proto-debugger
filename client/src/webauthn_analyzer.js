// File: webauthn_analyzer.js
//
// ---------------------------------------------------------------------------
// The WebAuthn Analyzer page: paste the artifacts of a ceremony somebody else
// performed, and see what is in them.
//
// This is the mode that works with ANY relying party. The debugger is not the
// RP here and performs no ceremony — it decodes bytes. So it needs no secure
// context, no authenticator, and no extension, which is what makes it the part
// of this workflow that is useful on the deployed static sites to a visitor who
// will not install anything.
//
// Input shapes accepted, in the order they are tried:
//   1. `PublicKeyCredential.toJSON()` — the Level 3 serialization, which is
//      what the extension captures and what a modern browser's console gives
//      you from `JSON.stringify(cred)`. Registration and assertion both.
//   2. This workflow's capture envelope ({ v, ceremony, request, response, …
//      }), in which case the REQUEST is shown too — the half no relying party
//      ever shows its user.
//   3. Individual base64url fields typed into the boxes, for the case where
//      somebody has one artifact and not a whole credential.
//
// **Nothing here uses innerHTML.** Every value on this page arrived by paste
// from a third party, and the whole page is built with createElement and
// textContent so there is no path from pasted bytes to markup. That is a
// stronger guarantee than sanitising, and it costs nothing because none of
// these panes need rich content.
//
// The public key is the one thing an assertion cannot carry: verifying one
// needs the key from the REGISTRATION that created the credential. So a decoded
// registration's key is remembered (localStorage, `webauthn_analyzer_keys`, by
// credential ID) and offered automatically when an assertion for that
// credential turns up. Storing it needs no opt-out checkbox and is not covered
// by the key-material rule in the root CLAUDE.md: a WebAuthn credential's
// private key never leaves the authenticator, so what is kept here is a PUBLIC
// key — the same class of thing as an IdP's certificate, which this debugger
// has always stored.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var appconfig = require(process.env.CONFIG_FILE);
var webauthn = require("./webauthn");
var cose = require("./cose");
var cbor = require("./cbor");
var panes = require("./webauthn_panes");

var log = bunyan.createLogger({ name: "webauthn_analyzer",
    level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var KEY_STORE = "webauthn_analyzer_keys";
var LAST_INPUT = "webauthn_analyzer_input";

// The DOM helpers and the five decode panes live in ./webauthn_panes, shared
// with the Lab page — those two differ in where the bytes came from and in
// nothing else, so a flags table that disagreed between them would be a bug
// visible only by comparing the pages.

var $ = panes.byId;
var clear = panes.clear;
var el = panes.el;
var status = panes.status;
// table() and row() are used by renderRequest below, which is this page's own
// pane rather than one of the shared five. Aliased rather than re-implemented —
// and note the bug that made this comment necessary: when the shared panes were
// extracted, the local table()/row() went with them and renderRequest kept
// calling them, so "What the relying party asked for" threw ReferenceError. It
// went unnoticed because that pane fills ONLY for an extension capture, and
// nothing exercised one until the inbox existed. A pane no test opens is a pane
// that is broken.
var table = panes.table;
var row = panes.row;

function renderClientData(cd) {
  log.debug("Entering renderClientData().");
  panes.renderClientData("wa_clientdata_body", "wa_clientdata_raw", cd);
  log.debug("Leaving renderClientData().");
}

function renderAuthenticatorData(ad) {
  log.debug("Entering renderAuthenticatorData().");
  panes.renderAuthenticatorData("wa_authdata_body", ad);
  log.debug("Leaving renderAuthenticatorData().");
}

function renderCoseKey(ad) {
  log.debug("Entering renderCoseKey().");
  log.debug("Leaving renderCoseKey().");
  return panes.renderCoseKey("wa_cose_body", "wa_cose_pem", ad);
}

function renderAttestation(att) {
  log.debug("Entering renderAttestation().");
  panes.renderAttestation("wa_attestation_body", "wa_attestation_raw", att);
  log.debug("Leaving renderAttestation().");
}

function renderChecks(result) {
  log.debug("Entering renderChecks().");
  panes.renderChecks("wa_verify_body", "wa_verify_status", result);
  log.debug("Leaving renderChecks().");
}

// --- stored public keys ------------------------------------------------------

function loadKeys() {
  log.debug("Entering loadKeys().");
  try {
    log.debug("Leaving loadKeys().");
    return JSON.parse(localStorage.getItem(KEY_STORE) || "{}");
  } catch (e) {
    // Unreadable store: start again rather than refusing to run. Nothing here
    // is irreplaceable — every entry can be recovered by pasting its
    // registration.
    log.warn("Could not read " + KEY_STORE + ": " + e.message);
    log.debug("Leaving loadKeys().");
    return {};
  }
}

function rememberKey(credentialId, jwk) {
  log.debug("Entering rememberKey(). credentialId=" + credentialId);
  var keys = loadKeys();
  keys[credentialId] = jwk;
  try {
    localStorage.setItem(KEY_STORE, JSON.stringify(keys));
  } catch (e) {
    // Quota, or storage disabled. The decode the user just asked for has
    // already happened and is on screen; only the convenience of reuse is lost.
    log.warn("Could not store the credential public key: " + e.message);
  }
  log.debug("Leaving rememberKey().");
}

// --- input parsing -----------------------------------------------------------

// Pull a credential out of whatever was pasted. Returns
// { ceremony, response, request } with base64url strings, or throws with a
// message that says what shape was expected.
function interpret(text) {
  log.debug("Entering interpret(). length=" + (text || "").length);
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error("That is not JSON. Paste a PublicKeyCredential (its " +
                    "toJSON() form), or a " +
                    "capture from the browser extension. " + e.message);
  }
  // The capture envelope.
  if (parsed && parsed.v && parsed.ceremony && (parsed.response ||
      parsed.error)) {
    log.debug("Leaving interpret(). shape=capture");
    return { ceremony: parsed.ceremony, response: parsed.response,
             request: parsed.request, envelope: parsed };
  }
  // A PublicKeyCredential.toJSON().
  if (parsed && parsed.response && parsed.id) {
    var isRegistration = !!parsed.response.attestationObject;
    log.debug("Leaving interpret(). shape=credential registration=" +
              isRegistration);
    return { ceremony: isRegistration ? "create" : "get", response: parsed,
            request: null };
  }
  // A bare response object.
  if (parsed && (parsed.attestationObject || parsed.authenticatorData)) {
    log.debug("Leaving interpret(). shape=bare response");
    return { ceremony: parsed.attestationObject ? "create" : "get",
             response: { response: parsed }, request: null };
  }
  throw new Error("Unrecognised shape. Expected a PublicKeyCredential with a " +
                  "`response` member " +
                  "(the toJSON() form), or this workflow's capture envelope.");
}

function renderRequest(request) {
  log.debug("Entering renderRequest().");
  var pane = $("wa_request_body");
  clear(pane);
  if (!request) {
    pane.appendChild(el("p", "wa-note",
      "No request options in this input. A pasted credential carries only " +
          "the ANSWER; the options " +
      "the relying party asked with — challenge, userVerification, " +
          "allowCredentials, attestation, " +
      "extensions, timeout — are visible only to something present when the " +
          "call was made. That is " +
      "what the browser extension captures."));
    log.debug("Leaving renderRequest().");
    return;
  }
  var t = table(pane);
  var pk = request.publicKey || request;
  Object.keys(pk).forEach(function (k) {
    var v = pk[k];
    row(t, k, (typeof v === "object" && v !== null) ?
        JSON.stringify(v) : String(v));
  });
  log.debug("Leaving renderRequest().");
}

// --- the button --------------------------------------------------------------

function analyze() {
  log.debug("Entering analyze().");
  log.info("Entering analyze().");
  var text = $("wa_input").value;
  var interpreted;
  try {
    interpreted = interpret(text);
  } catch (e) {
    status("wa_input_status", e.message, "bad");
    log.info("Leaving analyze(). input not understood");
    log.debug("Leaving analyze().");
    return;
  }
  try {
    localStorage.setItem(LAST_INPUT, text);
  } catch (e) {
    // Storage full or disabled. Only the convenience of a reload keeping the
    // last input is lost; the analysis below proceeds normally.
    log.warn("Could not remember the last input: " + e.message);
  }

  renderRequest(interpreted.request);

  // A REFUSED ceremony is a first-class capture — a NotAllowedError after a
  // thirty-second wait is one of the things a user most needs to see — and it
  // has no response to decode. Reading through it was a TypeError that emptied
  // every pane, which is the worst possible rendering of "the ceremony failed".
  if (!interpreted.response) {
    ["wa_clientdata_body", "wa_authdata_body", "wa_cose_body",
     "wa_attestation_body",
     "wa_verify_body"].forEach(function (id) {
      clear($(id));
    });
    var err = (interpreted.envelope && interpreted.envelope.error) || null;
    $("wa_clientdata_body").appendChild(el("p", "wa-bad",
      err
        ? "This ceremony did not complete: " + err.name + " — " + err.message +
          ".  WebAuthn reports one error for several situations on purpose " +
              "(no matching " +
          "credential, a declined prompt, a timeout), so this does not say " +
              "which. The request " +
          "above is still the whole story of what was asked for."
        : "This capture carries no response and no error, which should " +
            "not happen."));
    status("wa_input_status",
      "A refused ceremony. There are no artifacts to decode, but the request " +
          "options above are " +
      "exactly what the relying party asked for.", "");
    log.info("Leaving analyze(). refused ceremony rendered");
    log.debug("Leaving analyze().");
    return;
  }

  var response = interpreted.response.response || interpreted.response;

  var clientData, authData, jwk = null;
  try {
    clientData = webauthn.parseClientDataJSON(webauthn.base64urlToBytes(
        response.clientDataJSON));
    renderClientData(clientData);
  } catch (e) {
    status("wa_input_status", "clientDataJSON did not decode: " + e.message,
           "bad");
    log.info("Leaving analyze(). clientData failed");
    log.debug("Leaving analyze().");
    return;
  }

  try {
    if (interpreted.ceremony === "create") {
      var att = webauthn.parseAttestationObject(
        webauthn.base64urlToBytes(response.attestationObject));
      authData = att.authData;
      renderAttestation(att);
      renderAuthenticatorData(authData);
      jwk = renderCoseKey(authData);
      if (jwk && authData.credentialId) {
        rememberKey(webauthn.bytesToBase64url(authData.credentialId), jwk);
      }
      status("wa_input_status",
        "Registration decoded. The credential public key has been kept, so " +
            "an assertion for this " +
        "credential pasted here later can be verified.", "good");
    } else {
      authData = webauthn.parseAuthenticatorData(
        webauthn.base64urlToBytes(response.authenticatorData));
      clear($("wa_attestation_body"));
      $("wa_attestation_body").appendChild(el("p", "wa-note",
        "An assertion carries no attestation object. Attestation happens " +
            "once, at registration."));
      $("wa_attestation_raw").value = "";
      renderAuthenticatorData(authData);
      renderCoseKey(authData);
      status("wa_input_status", "Assertion decoded.", "good");
    }
  } catch (e) {
    status("wa_input_status", "The credential did not decode: " + e.message,
           "bad");
    log.info("Leaving analyze(). decode failed");
    log.debug("Leaving analyze().");
    return;
  }

  // Verification is only meaningful for an assertion, and only with a key.
  if (interpreted.ceremony === "get") {
    verifyPasted(interpreted.response, response, authData);
  } else {
    clear($("wa_verify_body"));
    $("wa_verify_body").appendChild(el("p", "wa-note",
      "Verifying a REGISTRATION means verifying its attestation statement " +
          "against a trusted " +
      "metadata service, which this page deliberately does not do — see the " +
          "attestation pane. " +
      "Paste an assertion for this credential to exercise the " +
          "signature check."));
    status("wa_verify_status", "", "");
  }
  log.info("Leaving analyze().");
  log.debug("Leaving analyze().");
}

// `credential` is the OUTER PublicKeyCredential — it carries the id; `response`
// is its inner `response` member, which does not. Conflating the two is how the
// stored-key lookup silently found nothing and the page reported "cannot
// verify" for a credential whose key it was holding.
function verifyPasted(credential, response, authData) {
  log.debug("Entering verifyPasted().");
  log.info("Entering verifyPasted().");
  var pasted = $("wa_public_key").value.trim();
  var jwk = null;
  if (pasted) {
    try {
      jwk = JSON.parse(pasted);
    } catch (e) {
      status("wa_verify_status",
             "The credential public key box does not hold JSON: " + e.message,
             "bad");
      log.debug("Leaving verifyPasted().");
      return;
    }
  } else {
    var keys = loadKeys();
    var id = credential.rawId || credential.id;
    jwk = keys[id] || null;
    if (jwk) {
      $("wa_public_key").value = JSON.stringify(jwk, null, 2);
    }
  }
  if (!jwk) {
    clear($("wa_verify_body"));
    $("wa_verify_body").appendChild(el("p", "wa-note",
      "No public key for this credential. An assertion is a signature and " +
          "nothing else — the key " +
      "that checks it comes from the registration that created the " +
          "credential. Paste that " +
      "registration here first, or put the credential's public key (as a " +
          "JWK) in the box above."));
    status("wa_verify_status",
           "Cannot verify without the credential public key.", "");
    log.debug("Leaving verifyPasted().");
    return;
  }

  var expected = {
    challenge: $("wa_expect_challenge").value.trim() || undefined,
    origin: $("wa_expect_origin").value.trim() || undefined,
    rpId: $("wa_expect_rpid").value.trim() || undefined,
    requireUserVerification: $("wa_expect_uv").checked,
  };
  var prev = $("wa_expect_signcount").value.trim();
  if (prev !== "") {
    expected.previousSignCount = parseInt(prev, 10);
  }

  webauthn.verifyAssertion({
    authenticatorData: webauthn.base64urlToBytes(response.authenticatorData),
    clientDataJSON: webauthn.base64urlToBytes(response.clientDataJSON),
    signature: webauthn.base64urlToBytes(response.signature),
    publicKeyJwk: jwk,
    expected: expected,
  }).then(function (result) {
    renderChecks(result);
    log.info("Leaving verifyPasted(). valid=" + result.valid);
  }).catch(function (e) {
    clear($("wa_verify_body"));
    $("wa_verify_body").appendChild(el("p", "wa-bad",
      "Verification could not run: " + e.message));
    status("wa_verify_status", "Verification could not run.", "bad");
    log.error("verifyAssertion threw: " + e.message);
  });
  log.debug("Leaving verifyPasted().");
}

// Pre-fill the expectations from the artifact itself. Convenience only, and
// labelled as such on the page: checking a challenge against the challenge the
// same document carries proves nothing, so these are a starting point for the
// user to correct, not an answer.
function fillExpectationsFromInput() {
  log.debug("Entering fillExpectationsFromInput().");
  try {
    var interpreted = interpret($("wa_input").value);
    var response = interpreted.response.response || interpreted.response;
    var cd = webauthn.parseClientDataJSON(webauthn.base64urlToBytes(
        response.clientDataJSON));
    $("wa_expect_challenge").value = cd.challenge || "";
    $("wa_expect_origin").value = cd.origin || "";
    try {
      $("wa_expect_rpid").value = new URL(cd.origin).hostname;
    } catch (e) {
      // A non-URL origin (an extension origin, say). Leave the RP ID for the
      // user rather than guessing at it.
      $("wa_expect_rpid").value = "";
    }
    status("wa_input_status",
        "Expectations filled in from the artifact itself — correct them to " +
                              "what the relying party actually issued before " +
                                  "trusting the verdict.", "");
  } catch (e) {
    status("wa_input_status", e.message, "bad");
  }
  log.debug("Leaving fillExpectationsFromInput().");
}

function clearAll() {
  log.debug("Entering clearAll().");
  ["wa_input", "wa_public_key", "wa_expect_challenge", "wa_expect_origin",
   "wa_expect_rpid",
   "wa_expect_signcount", "wa_clientdata_raw", "wa_cose_pem",
       "wa_attestation_raw"].forEach(function (id) {
    if ($(id)) {
      $(id).value = "";
    }
  });
  ["wa_clientdata_body", "wa_authdata_body", "wa_cose_body",
   "wa_attestation_body",
   "wa_verify_body", "wa_request_body"].forEach(function (id) {
    clear($(id));
  });
  status("wa_input_status", "", "");
  status("wa_verify_status", "", "");
  log.debug("Leaving clearAll().");
}

// --- the browser extension's captures ----------------------------------------
//
// The extension cannot be talked to directly from a page in a way that works in
// both browsers (externally_connectable is Chrome-only), so this is a
// namespaced window.postMessage handshake answered by a content script the
// extension puts on THIS origin. The same contract the extension's own tests
// use; if the two ever drift, tests/webauthn_extension.js is where it shows.
var BRIDGE_REQ = "idptools-webauthn-request";
var BRIDGE_RES = "idptools-webauthn-response";
var bridgeSeq = 0;
// The capture envelope shape this page can read. See the contract in
// docs/webauthn-plan.md; extension/src/shim.js writes it.
var SUPPORTED_CAPTURE_VERSION = 1;

// Presence, read synchronously off an attribute the extension sets at
// document_start. This is what distinguishes "no extension installed" from "the
// extension is there but has captured nothing" — two situations that look
// identical if you only ever ask for captures.
function extensionVersion() {
  log.debug("Entering extensionVersion().");
  log.debug("Leaving extensionVersion().");
  return document.documentElement.getAttribute(
      "data-idptools-webauthn-observer");
}

function askBridge(action) {
  log.debug("Entering askBridge().");
  log.debug("Leaving askBridge().");
  return new Promise(function (resolve) {
    var id = "p" + (++bridgeSeq) + "-" + Date.now();
    var timer = setTimeout(function () {
      window.removeEventListener("message", handler);
      resolve(null);
    }, 4000);
    function handler(event) {
      log.debug("Entering handler().");
      // RFC 9700 section 4.17 (requirement 15.3): a message listener must
      // exact-match the SENDER ORIGIN, not merely the source window. The two
      // are different checks — event.source identifies the window object a
      // message came from, which for a same-window bridge is this one either
      // way, while event.origin is what says the document in it is still the
      // document this page trusts. A page navigated to another origin inside
      // the same window still satisfies the source test.
      if (event.origin !== window.location.origin) {
        log.debug("Leaving handler(). Origin " + event.origin +
                  " is not this page's own.");
        return;
      }
      if (event.source !== window) {
        log.debug("Leaving handler().");
        return;
      }
      var d = event.data;
      if (!d || d.channel !== BRIDGE_RES || d.id !== id) {
        log.debug("Leaving handler().");
        return;
      }
      clearTimeout(timer);
      window.removeEventListener("message", handler);
      resolve(d.result || null);
      log.debug("Leaving handler().");
    }
    window.addEventListener("message", handler);
    window.postMessage({ channel: BRIDGE_REQ, id: id, action: action },
                       window.location.origin);
  });
}

function renderCaptures(answer) {
  log.debug("Entering renderCaptures().");
  var pane = $("wa_ext_body");
  clear(pane);
  var version = extensionVersion();
  if (!version) {
    status("wa_ext_status",
      "No extension detected on this page. Modes above work without it; the " +
          "extension is only needed " +
      "to watch a ceremony on somebody else's site.", "");
    log.debug("Leaving renderCaptures(). absent");
    return;
  }
  if (!answer) {
    status("wa_ext_status",
      "The extension is installed (version " + version +
          ") but did not answer. If it was just " +
      "reloaded, try again.", "bad");
    log.debug("Leaving renderCaptures().");
    return;
  }
  // Drift is a real failure mode — an unpacked extension does not auto-update —
  // but the thing to compare is the CAPTURE FORMAT, not the build stamp. The
  // extension and the site are stamped independently, so comparing those two
  // reported drift on every matched build, which is worse than no warning: a
  // warning that is always on is one nobody reads. The build number is shown
  // because it is useful when reporting a problem, and the format version is
  // what is checked, because that is what would actually break.
  var unsupported = (answer.captures || []).filter(function (c) {
    return c.v !== SUPPORTED_CAPTURE_VERSION;
  });
  var drift = unsupported.length > 0;

  if (!answer.armed) {
    status("wa_ext_status",
      "The extension is installed (version " + version +
          ") and is observing nothing. Open its popup, " +
      "enter the origin you want to watch, and confirm the permission the " +
          "browser asks for.", "");
  } else {
    status("wa_ext_status",
      "Observing " + answer.armed.origin + " until " +
      new Date(answer.armed.expires).toLocaleTimeString() + " — " +
      (answer.captures || []).length + " capture(s)." +
      (drift
        ? "  NOTE: " + unsupported.length + " capture(s) use format v" +
            unsupported[0].v +
          " and this page understands v" + SUPPORTED_CAPTURE_VERSION +
              ". The extension " +
          "(version " + (answer.version || "unknown") +
              ") does not update itself — reload it from " +
          "extension/dist."
        : "  Extension version " + (answer.version || "unknown") + "."),
      drift ? "bad" : "good");
  }

  var captures = answer.captures || [];
  if (!captures.length) {
    pane.appendChild(el("p", "wa-note",
      "No captures yet. Arm the extension for the origin you want to watch, " +
          "then perform the " +
      "ceremony there — a sign-in, an enrolment, whatever the site offers."));
    log.debug("Leaving renderCaptures().");
    return;
  }
  var t = panes.table(pane);
  captures.forEach(function (capture, index) {
    var tr = el("tr", capture.error ? "wa-bad-row" : null);
    var label = capture.ceremony + " · " + capture.origin +
      (capture.rpId ? " · rpId " + capture.rpId : "") +
      (capture.error ? " · " + capture.error.name : "") +
      " · " + capture.capturedAt;
    tr.appendChild(el("td", "wa-name", label));
    var cell = el("td", "wa-value");
    var load = document.createElement("input");
    load.type = "button";
    load.className = "btn2 wa-load-capture";
    load.value = capture.error ? "Load (refused ceremony)" : "Load";
    load.setAttribute("data-capture-index", String(index));
    load.addEventListener("click", function () {
      // The whole envelope, not just the response: the request half is what the
      // extension is for, and the Analyzer knows how to show it.
      $("wa_input").value = JSON.stringify(capture, null, 2);
      analyze();
    });
    cell.appendChild(load);
    tr.appendChild(cell);
    t.appendChild(tr);
  });
  log.debug("Leaving renderCaptures(). captures=" + captures.length);
}

async function refreshCaptures() {
  log.debug("Entering refreshCaptures().");
  renderCaptures(await askBridge("get"));
  log.debug("Leaving refreshCaptures().");
}

window.onload = function () {
  log.debug("Entering onload().");
  log.debug("Entering window.onload().");
  $("wa_analyze_button").addEventListener("click", analyze);
  $("wa_fill_button").addEventListener("click", fillExpectationsFromInput);
  $("wa_clear_button").addEventListener("click", clearAll);
  $("wa_ext_refresh").addEventListener("click", refreshCaptures);
  $("wa_ext_clear").addEventListener("click", function () {
    askBridge("clear").then(refreshCaptures);
  });
  $("wa_ext_done").addEventListener("click", function () {
    // The completion signal from the plan's disarm ladder: finishing here stops
    // the observation without the user having to remember to.
    askBridge("disarm").then(function () {
      status("wa_ext_status",
          "Observation stopped and the extension's capture buffer cleared. " +
                              "Remove the extension entirely from its popup " +
                                  "if you want it gone.", "good");
      refreshCaptures();
    });
  });
  refreshCaptures();

  $("wa_forget_button").addEventListener("click", function () {
    localStorage.removeItem(KEY_STORE);
    status("wa_input_status",
           "Remembered credential public keys have been forgotten.", "");
  });
  try {
    var last = localStorage.getItem(LAST_INPUT);
    if (last) {
      $("wa_input").value = last;
    }
  } catch (e) {
    // Storage unavailable; the page works exactly the same, it just opens
    // empty.
    log.warn("Could not restore the last input: " + e.message);
  }
  log.debug("Leaving window.onload().");
  log.debug("Leaving onload().");
};

// Exported for the browser tests, which drive these directly rather than
// re-implementing the page's own reading of its fields.
module.exports = {
  analyze: analyze,
  interpret: interpret,
};
