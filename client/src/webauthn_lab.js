// File: webauthn_lab.js
//
// ---------------------------------------------------------------------------
// The WebAuthn Lab: this origin acts as the relying party, so a real
// authenticator performs a real ceremony and every artifact is genuine.
//
// The Lab and the Analyzer differ in exactly one thing — where the bytes came
// from — so the decode panes are shared (./webauthn_panes) and only the ceremony
// belongs here.
//
// **The RP ID is not a free field, and the page says why.** WebAuthn ties the
// ceremony to the calling origin: the RP ID must be this origin's host or a
// registrable parent of it. A page at idptools.com cannot run a ceremony for
// acme.com, and that refusal *is* the phishing resistance — it is the single
// most useful thing this page demonstrates, so the field is prefilled from
// location.hostname and a deliberate mismatch is offered as a **demonstration**
// rather than hidden. Debugging somebody else's relying party is the Analyzer's
// job, or the extension's.
//
// **A secure context is required**, and unlike the Analyzer this page cannot
// work without one: `navigator.credentials` does not exist on a plain-HTTP
// origin that is not localhost. The capability pane says so in those words
// rather than letting the Create button fail with a TypeError. Measured on
// 2026-08-08: the containerized suite's http://client:3000 has no
// PublicKeyCredential at all until browser_flags.js relaxes the origin, after
// which a full ceremony succeeds — including with the single-label RP ID
// "client", which turned out to be fine.
//
// What this page will never do: name an RP ID this origin does not own, or
// pretend it can. See the non-goals in docs/webauthn-plan.md.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var appconfig = require(process.env.CONFIG_FILE);
var webauthn = require("./webauthn");
var panes = require("./webauthn_panes");

var log = bunyan.createLogger({ name: "webauthn_lab", level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var $ = panes.byId;
var el = panes.el;
var status = panes.status;

// The credentials this page has created, by credential id: the public key (so an
// assertion can be verified) and the sign count last seen (so a regression can
// be noticed). Public keys only — a WebAuthn private key never leaves the
// authenticator, so nothing here is covered by the key-material opt-out rule.
var STORE = "webauthn_lab_credentials";
var HANDOFF = "webauthn_analyzer_input";

function loadCredentials() {
  try {
    return JSON.parse(localStorage.getItem(STORE) || "{}");
  } catch (e) {
    // Unreadable store: start again rather than refusing to run. Every entry can
    // be recreated by registering again.
    log.warn("Could not read " + STORE + ": " + e.message);
    return {};
  }
}

function saveCredentials(creds) {
  try {
    localStorage.setItem(STORE, JSON.stringify(creds));
  } catch (e) {
    // Quota or storage disabled. The ceremony has already happened and its
    // result is on screen; only reuse on a later visit is lost.
    log.warn("Could not store the credential: " + e.message);
  }
}

function randomBytes(n) {
  var b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function b64u(bytes) {
  return webauthn.bytesToBase64url(bytes);
}

// --- capabilities -------------------------------------------------------------

function reportCapabilities() {
  log.info("Entering reportCapabilities().");
  var pane = $("wl_caps_body");
  panes.clear(pane);
  var t = panes.table(pane);

  var secure = window.isSecureContext;
  var hasApi = typeof window.PublicKeyCredential !== "undefined";
  panes.row(t, "secure context", secure ? "yes" : "no — WebAuthn is unavailable here",
            secure ? "wa-ok-row" : "wa-bad-row");
  panes.row(t, "PublicKeyCredential", hasApi ? "available" : "absent",
            hasApi ? "wa-ok-row" : "wa-bad-row");
  panes.row(t, "this origin", window.location.origin);
  panes.row(t, "RP ID this origin may use", window.location.hostname);

  if (!secure || !hasApi) {
    pane.appendChild(el("p", "wa-bad",
      "WebAuthn needs a secure context: HTTPS, or a localhost origin. On plain HTTP from any other " +
      "host the API is not merely restricted — navigator.credentials does not exist. Nothing on " +
      "this page can run until that is fixed; the Analyzer, which decodes artifacts rather than " +
      "producing them, works anywhere."));
    ["wl_create_button", "wl_get_button"].forEach(function (id) {
      if ($(id)) {
        $(id).disabled = true;
      }
    });
    log.info("Leaving reportCapabilities(). unavailable");
    return;
  }

  // These two are informational and asynchronous; a browser that lacks them is
  // not broken, so a rejection fills the row rather than failing the pane.
  if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      .then(function (available) {
        panes.row(t, "platform authenticator", available ? "available" : "not available");
      })
      .catch(function (e) {
        panes.row(t, "platform authenticator", "could not be determined: " + e.message);
      });
  }
  if (window.PublicKeyCredential.isConditionalMediationAvailable) {
    window.PublicKeyCredential.isConditionalMediationAvailable()
      .then(function (available) {
        panes.row(t, "conditional mediation", available ? "available" : "not available");
      })
      .catch(function (e) {
        panes.row(t, "conditional mediation", "could not be determined: " + e.message);
      });
  }
  log.info("Leaving reportCapabilities(). ready");
}

// --- the ceremony trace ---------------------------------------------------------

// A running account of what happened, in order, with the boundary the browser
// enforces drawn explicitly. This is the pane that answers "why can I not see
// the private key" before anybody asks it.
function trace(lines) {
  var pane = $("wl_trace_body");
  panes.clear(pane);
  var ol = el("ol", "wa-trace");
  lines.forEach(function (line) {
    var li = el("li", line.kind ? "wa-trace-" + line.kind : null, line.text);
    ol.appendChild(li);
  });
  pane.appendChild(ol);
  pane.appendChild(el("p", "wa-note",
    "Everything below the authenticator boundary — the private key, the PIN, the biometric, the " +
    "CTAP commands and the USB frames — is invisible to every page in every browser, by design. " +
    "This is a WebAuthn debugger; a CTAP debugger would have to be a native application."));
}

// --- registration -----------------------------------------------------------

function creationOptions() {
  log.debug("Entering creationOptions().");
  var algs = [];
  if ($("wl_alg_es256").checked) {
    algs.push({ type: "public-key", alg: -7 });
  }
  if ($("wl_alg_rs256").checked) {
    algs.push({ type: "public-key", alg: -257 });
  }
  if ($("wl_alg_eddsa").checked) {
    algs.push({ type: "public-key", alg: -8 });
  }
  var challenge = $("wl_reg_challenge").value.trim();
  var options = {
    rp: { name: $("wl_rp_name").value || "OAuth2/OIDC Debugger", id: $("wl_rp_id").value || undefined },
    user: {
      id: webauthn.base64urlToBytes($("wl_user_id").value),
      name: $("wl_user_name").value || "debugger@example.com",
      displayName: $("wl_user_display").value || "Debugger User",
    },
    challenge: webauthn.base64urlToBytes(challenge),
    pubKeyCredParams: algs,
    authenticatorSelection: {
      residentKey: $("wl_resident_key").value,
      userVerification: $("wl_reg_uv").value,
    },
    attestation: $("wl_attestation").value,
    timeout: parseInt($("wl_timeout").value, 10) || 60000,
  };
  if ($("wl_attachment").value) {
    options.authenticatorSelection.authenticatorAttachment = $("wl_attachment").value;
  }
  log.debug("Leaving creationOptions(). algs=" + algs.length);
  return options;
}

// The options, as JSON, so the pane shows what is about to be sent rather than
// describing it. Byte arrays render as base64url, which is what the Level 3
// JSON form uses.
function showCreationOptions() {
  var o;
  try {
    o = creationOptions();
  } catch (e) {
    status("wl_reg_status", "Those options cannot be assembled: " + e.message, "bad");
    return;
  }
  var shown = JSON.parse(JSON.stringify(o, function (k, v) {
    return v instanceof Uint8Array ? b64u(v) : v;
  }));
  shown.user.id = $("wl_user_id").value;
  shown.challenge = $("wl_reg_challenge").value;
  panes.setValue("wl_reg_request", JSON.stringify({ publicKey: shown }, null, 2));
}

function createCredential() {
  log.info("Entering createCredential().");
  var options;
  try {
    options = creationOptions();
  } catch (e) {
    status("wl_reg_status", "Those options cannot be assembled: " + e.message, "bad");
    return;
  }
  if (!options.pubKeyCredParams.length) {
    status("wl_reg_status", "Choose at least one algorithm — an empty pubKeyCredParams lets the " +
                            "authenticator pick anything, and most will refuse outright.", "bad");
    return;
  }
  showCreationOptions();
  status("wl_reg_status", "Waiting for the authenticator — touch it, or complete whatever it asks for.", "");
  trace([
    { text: "This page called navigator.credentials.create() with the options above." },
    { text: "The browser is now mediating: it checked the RP ID against this origin, and is " +
            "asking the authenticator." },
    { text: "The authenticator is waiting for you.", kind: "pending" },
  ]);

  navigator.credentials.create({ publicKey: options }).then(function (credential) {
    log.info("Registration returned a credential.");
    var response = credential.response;
    var att = webauthn.parseAttestationObject(new Uint8Array(response.attestationObject));
    var cd = webauthn.parseClientDataJSON(new Uint8Array(response.clientDataJSON));

    panes.renderClientData("wl_clientdata_body", "wl_clientdata_raw", cd);
    panes.renderAttestation("wl_attestation_body", "wl_attestation_raw", att);
    panes.renderAuthenticatorData("wl_authdata_body", att.authData);
    var jwk = panes.renderCoseKey("wl_cose_body", "wl_cose_pem", att.authData);

    var json = credentialToJson(credential, "create");
    panes.setValue("wl_reg_result", JSON.stringify(json, null, 2));

    if (jwk) {
      var creds = loadCredentials();
      creds[json.rawId] = {
        jwk: jwk,
        signCount: att.authData.signCount,
        created: new Date().toISOString(),
        rpId: options.rp.id || window.location.hostname,
      };
      saveCredentials(creds);
      refreshCredentialList();
    }

    trace([
      { text: "navigator.credentials.create() with the options shown above.", kind: "done" },
      { text: "The browser checked the RP ID against this origin and wrote clientDataJSON — " +
              "including the origin, which is what the authenticator's signature ends up covering.",
        kind: "done" },
      { text: "The authenticator generated a key pair, kept the private half, and returned the " +
              "public half inside the attestation object.", kind: "done" },
      { text: "The private key did not cross that boundary and never will.", kind: "boundary" },
      { text: "This page decoded the result: " +
              (jwk ? jwk.alg || jwk.kty : "no key") + ", credential " +
              json.rawId.slice(0, 16) + "…", kind: "done" },
    ]);
    status("wl_reg_status", "Registered. The credential's public key has been kept, so the " +
                            "authentication pane below can verify an assertion from it.", "good");
    log.info("Leaving createCredential(). ok");
  }).catch(function (e) {
    reportCeremonyFailure("wl_reg_status", e);
    log.info("Leaving createCredential(). refused: " + e.name);
  });
}

// WebAuthn deliberately collapses "no credential", "user declined" and "timed
// out" into one error for privacy reasons. Say that, rather than guessing at a
// cause the browser refused to give.
function reportCeremonyFailure(statusId, e) {
  log.warn("The ceremony did not complete: " + e.name + ": " + e.message);
  var text = e.name + ": " + e.message;
  if (e.name === "NotAllowedError") {
    text += "  —  WebAuthn reports one error for several situations on purpose: no matching " +
            "credential, a declined prompt, and a timeout are indistinguishable to this page. " +
            "That is a privacy property, not a gap in this debugger.";
  }
  if (e.name === "SecurityError") {
    text += "  —  usually the RP ID: it must be this origin's host (" + window.location.hostname +
            ") or a registrable parent of it. A page cannot run a ceremony for a domain it does " +
            "not own, which is exactly the phishing resistance WebAuthn exists to provide.";
  }
  status(statusId, text, "bad");
  trace([
    { text: "The ceremony was started." , kind: "done" },
    { text: "The browser or the authenticator refused it: " + e.name, kind: "bad" },
  ]);
}

// --- authentication ----------------------------------------------------------

function getAssertion() {
  log.info("Entering getAssertion().");
  var creds = loadCredentials();
  var chosen = $("wl_credential_select").value;
  var options = {
    challenge: webauthn.base64urlToBytes($("wl_auth_challenge").value.trim()),
    rpId: $("wl_auth_rpid").value || undefined,
    userVerification: $("wl_auth_uv").value,
    timeout: parseInt($("wl_timeout").value, 10) || 60000,
  };
  if (chosen) {
    options.allowCredentials = [{
      type: "public-key",
      id: webauthn.base64urlToBytes(chosen),
    }];
  }
  panes.setValue("wl_auth_request", JSON.stringify({
    publicKey: Object.assign({}, options, {
      challenge: $("wl_auth_challenge").value.trim(),
      allowCredentials: chosen ? [{ type: "public-key", id: chosen }] : undefined,
    })
  }, null, 2));
  status("wl_auth_status", "Waiting for the authenticator.", "");

  navigator.credentials.get({ publicKey: options }).then(function (assertion) {
    log.info("Assertion returned.");
    var response = assertion.response;
    var json = credentialToJson(assertion, "get");
    panes.setValue("wl_auth_result", JSON.stringify(json, null, 2));

    var record = creds[json.rawId];
    if (!record) {
      status("wl_auth_status",
        "The authenticator returned an assertion for a credential this page did not create, so " +
        "there is no public key here to check it with. Paste it into the Analyzer with the key.",
        "bad");
      return;
    }
    webauthn.verifyAssertion({
      authenticatorData: new Uint8Array(response.authenticatorData),
      clientDataJSON: new Uint8Array(response.clientDataJSON),
      signature: new Uint8Array(response.signature),
      publicKeyJwk: record.jwk,
      expected: {
        challenge: $("wl_auth_challenge").value.trim(),
        origin: window.location.origin,
        rpId: options.rpId || window.location.hostname,
        requireUserVerification: $("wl_auth_uv").value === "required",
        previousSignCount: record.signCount,
      },
    }).then(function (result) {
      panes.renderChecks("wl_verify_body", "wl_auth_status", result);
      panes.renderAuthenticatorData("wl_authdata_body", result.authenticatorData);
      panes.renderClientData("wl_clientdata_body", "wl_clientdata_raw", result.clientData);
      // Only advance the remembered counter on a ceremony that verified;
      // recording a counter from an assertion we just rejected would launder the
      // very regression the next check is supposed to catch.
      if (result.valid) {
        record.signCount = result.authenticatorData.signCount;
        creds[json.rawId] = record;
        saveCredentials(creds);
      }
      trace([
        { text: "navigator.credentials.get() with the options shown above.", kind: "done" },
        { text: "The browser wrote clientDataJSON with this origin in it and asked the " +
                "authenticator.", kind: "done" },
        { text: "The authenticator signed authenticatorData ‖ SHA-256(clientDataJSON) with the " +
                "private key it kept at registration.", kind: "done" },
        { text: "The private key did not cross that boundary. What came back is a signature.",
          kind: "boundary" },
        { text: result.valid
            ? "This page verified that signature against the public key from the registration."
            : "This page checked the signature and the ceremony's other conditions, and " +
              "something did not hold — see the checks above.",
          kind: result.valid ? "done" : "bad" },
      ]);
      log.info("Leaving getAssertion(). valid=" + result.valid);
    }).catch(function (e) {
      status("wl_auth_status", "Verification could not run: " + e.message, "bad");
      log.error("verifyAssertion threw: " + e.message);
    });
  }).catch(function (e) {
    reportCeremonyFailure("wl_auth_status", e);
    log.info("Leaving getAssertion(). refused: " + e.name);
  });
}

// --- the Level 3 JSON form ----------------------------------------------------

// PublicKeyCredential.toJSON() is WebAuthn Level 3 and is ABSENT from the Chrome
// the test suite pins (measured: present on 151, absent on 121). The interchange
// format for this whole workflow is that JSON, so it is produced here rather
// than depended on — unconditionally, not behind a feature test, because a
// browser-dependent code path would mean CI exercising something users do not.
function credentialToJson(credential, ceremony) {
  log.debug("Entering credentialToJson(). ceremony=" + ceremony);
  var r = credential.response;
  var response = ceremony === "create"
    ? {
        clientDataJSON: b64u(new Uint8Array(r.clientDataJSON)),
        attestationObject: b64u(new Uint8Array(r.attestationObject)),
        transports: r.getTransports ? r.getTransports() : undefined,
        publicKeyAlgorithm: r.getPublicKeyAlgorithm ? r.getPublicKeyAlgorithm() : undefined,
      }
    : {
        clientDataJSON: b64u(new Uint8Array(r.clientDataJSON)),
        authenticatorData: b64u(new Uint8Array(r.authenticatorData)),
        signature: b64u(new Uint8Array(r.signature)),
        userHandle: r.userHandle ? b64u(new Uint8Array(r.userHandle)) : undefined,
      };
  var out = {
    id: credential.id,
    rawId: b64u(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: response,
  };
  log.debug("Leaving credentialToJson().");
  return out;
}

// --- page wiring ---------------------------------------------------------------

function refreshCredentialList() {
  var select = $("wl_credential_select");
  var creds = loadCredentials();
  panes.clear(select);
  var any = el("option", null, "(any credential this authenticator holds)");
  any.value = "";
  select.appendChild(any);
  Object.keys(creds).forEach(function (id) {
    var o = el("option", null, id.slice(0, 24) + "…  " + (creds[id].jwk.alg || creds[id].jwk.kty) +
                                "  count " + creds[id].signCount);
    o.value = id;
    select.appendChild(o);
  });
  $("wl_credential_count").textContent = Object.keys(creds).length + " credential(s) registered here";
}

function newChallenge(id) {
  panes.setValue(id, b64u(randomBytes(32)));
}

function sendToAnalyzer(sourceId) {
  var text = $(sourceId).value;
  if (!text.trim()) {
    return;
  }
  try {
    localStorage.setItem(HANDOFF, text);
    window.location.href = "/webauthn_analyzer.html";
  } catch (e) {
    status("wl_reg_status", "Could not hand off to the Analyzer: " + e.message, "bad");
  }
}

window.onload = function () {
  log.debug("Entering window.onload().");
  // Prefill the two things the browser, not the user, decides.
  panes.setValue("wl_rp_id", window.location.hostname);
  panes.setValue("wl_auth_rpid", window.location.hostname);
  panes.setValue("wl_user_id", b64u(randomBytes(16)));
  newChallenge("wl_reg_challenge");
  newChallenge("wl_auth_challenge");

  reportCapabilities();
  refreshCredentialList();
  showCreationOptions();

  $("wl_create_button").addEventListener("click", createCredential);
  $("wl_get_button").addEventListener("click", getAssertion);
  $("wl_reg_challenge_button").addEventListener("click", function () {
    newChallenge("wl_reg_challenge");
    showCreationOptions();
  });
  $("wl_auth_challenge_button").addEventListener("click", function () {
    newChallenge("wl_auth_challenge");
  });
  $("wl_show_options_button").addEventListener("click", showCreationOptions);
  $("wl_reg_to_analyzer").addEventListener("click", function () {
    sendToAnalyzer("wl_reg_result");
  });
  $("wl_auth_to_analyzer").addEventListener("click", function () {
    sendToAnalyzer("wl_auth_result");
  });
  $("wl_forget_button").addEventListener("click", function () {
    localStorage.removeItem(STORE);
    refreshCredentialList();
    status("wl_reg_status", "This page has forgotten the credentials it registered. The " +
                            "authenticator still holds them — this page is not able to delete " +
                            "anything from it.", "");
  });
  log.debug("Leaving window.onload().");
};

module.exports = {
  credentialToJson: credentialToJson,
};
