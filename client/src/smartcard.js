// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: smartcard.js
//
// The smart-card page. The codecs have no DOM. This file is the
// panes, the storage opt-in, and the two calls that need the api:
// YubiCloud verify and PC/SC transmit. A PIN is never written to
// localStorage. An AES key, an OATH secret and a YubiCloud API key
// are written only when that field's box is checked, and clearing
// the box removes what was stored.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "smartcard",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var appconfig = {};
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfig = {};
}

var iso = require("./iso7816.js");
var otp = require("./yubico_otp.js");
var oath = require("./oath.js");
var piv = require("./piv.js");
var pgp = require("./openpgp_card.js");
var hsm = require("./yubihsm_auth.js");
var x509 = require("./x509.js");
var keys = require("./key_material.js");
var bytes = require("./crypto_bytes.js");
// The collapsible panes and the collapse / expand all switch.
var panes = require("./panes");

var PANES = ["otp", "oath", "piv", "pgp", "hsm", "reader"];
var SAVE = {
  otp: ["sc_save_otp_key", "sc_otp_aes_key"],
  oath: ["sc_save_oath_secret", "sc_oath_secret"],
  api: ["sc_save_api_key", "sc_otp_api_key"]
};

function backendAvailable() {
  log.debug("Entering backendAvailable().");
  var on = appconfig.backendAvailable !== false;
  log.debug("Leaving backendAvailable().");
  return on;
}

function apiBase() {
  log.debug("Entering apiBase().");
  var base = appconfig.apiUrl || "";
  log.debug("Leaving apiBase().");
  return base;
}

function show(id, on) {
  log.debug("Entering show().");
  var el = document.getElementById(id);
  if (!el) {
    log.debug("Leaving show(). Missing.");
    return;
  }
  if (on) {
    el.classList.remove("saml-hidden");
  } else {
    el.classList.add("saml-hidden");
  }
  log.debug("Leaving show().");
}

function valueOf(id) {
  log.debug("Entering valueOf().");
  var el = document.getElementById(id);
  var text = el ? String(el.value || "") : "";
  log.debug("Leaving valueOf().");
  return text;
}

function checked(id) {
  log.debug("Entering checked().");
  var el = document.getElementById(id);
  var on = !!(el && el.checked);
  log.debug("Leaving checked().");
  return on;
}

function setStatus(text) {
  log.debug("Entering setStatus().");
  var el = document.getElementById("sc_status");
  if (el) {
    el.textContent = text || "";
  }
  log.debug("Leaving setStatus().");
}

function esc(text) {
  log.debug("Entering esc().");
  var out = String(text == null ? "" : text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  log.debug("Leaving esc().");
  return out;
}

function render(id, rows) {
  log.debug("Entering render().");
  var el = document.getElementById(id);
  if (!el) {
    log.debug("Leaving render(). Missing.");
    return;
  }
  if (!rows || rows.length === 0) {
    el.innerHTML = "";
    log.debug("Leaving render(). Empty.");
    return;
  }
  var html = "<table class=\"saml-table\"><tbody>";
  var i = 0;
  for (i = 0; i < rows.length; i++) {
    html += "<tr><td class=\"saml-key\">" + esc(rows[i].label) +
        "</td><td>" + esc(rows[i].value) + "</td></tr>";
  }
  html += "</tbody></table>";
  el.innerHTML = html;
  log.debug("Leaving render().");
}

function storageGet(key) {
  log.debug("Entering storageGet().");
  var value = null;
  try {
    value = window.localStorage.getItem(key);
  } catch (e) {
    value = null;
  }
  log.debug("Leaving storageGet().");
  return value;
}

function storageSet(key, value) {
  log.debug("Entering storageSet().");
  try {
    window.localStorage.setItem(key, value);
  } catch (e) {
    log.debug("Leaving storageSet(). Refused.");
    return;
  }
  log.debug("Leaving storageSet().");
}

function storageRemove(key) {
  log.debug("Entering storageRemove().");
  try {
    window.localStorage.removeItem(key);
  } catch (e) {
    log.debug("Leaving storageRemove(). Refused.");
    return;
  }
  log.debug("Leaving storageRemove().");
}

// Only an explicit "1" keeps the secret. Anything else removes it,
// including a box that was cleared on an older page.
function restoreSecret(flag, field) {
  log.debug("Entering restoreSecret().");
  var on = storageGet(flag) === "1";
  var box = document.getElementById(flag);
  var input = document.getElementById(field);
  if (!on) {
    storageRemove(field);
    if (box) {
      box.checked = false;
    }
    log.debug("Leaving restoreSecret(). Off.");
    return;
  }
  if (box) {
    box.checked = true;
  }
  if (input) {
    input.value = storageGet(field) || "";
  }
  log.debug("Leaving restoreSecret().");
}

function storeSecret(flag, field) {
  log.debug("Entering storeSecret().");
  var on = checked(flag);
  if (on) {
    storageSet(flag, "1");
    storageSet(field, valueOf(field));
  } else {
    storageSet(flag, "0");
    storageRemove(field);
  }
  log.debug("Leaving storeSecret().");
}

// The box is the opt-in. Clearing it removes the stored secret
// now, not on the next decode.
function onSaveChange(which) {
  log.debug("Entering onSaveChange().");
  var pair = SAVE[which];
  if (!pair) {
    log.debug("Leaving onSaveChange(). Unknown.");
    return;
  }
  storeSecret(pair[0], pair[1]);
  log.debug("Leaving onSaveChange().");
}

function showApplication(name) {
  log.debug("Entering showApplication().");
  var which = PANES.indexOf(name) >= 0 ? name : "otp";
  var i = 0;
  for (i = 0; i < PANES.length; i++) {
    show("sc_pane_" + PANES[i], PANES[i] === which);
  }
  log.debug("Leaving showApplication().");
}

function report(outId, described) {
  log.debug("Entering report().");
  render(outId, described.rows);
  setStatus(described.summary);
  log.debug("Leaving report().");
}

function fail(outId, error) {
  log.debug("Entering fail().");
  render(outId, []);
  setStatus(error && error.message ? error.message : String(error));
  log.debug("Leaving fail().");
}

// A key types its OTP and then Enter. Decode as soon as that newline
// arrives, so touching the key in the Token field is the whole gesture.
function onOtpTyped() {
  log.debug("Entering onOtpTyped().");
  var field = document.getElementById("sc_otp_token");
  if (field && /\n/.test(field.value)) {
    field.value = field.value.replace(/\s+/g, "");
    decodeOtp();
  }
  log.debug("Leaving onOtpTyped().");
}

function decodeOtp() {
  log.debug("Entering decodeOtp().");
  storeSecret(SAVE.otp[0], SAVE.otp[1]);
  try {
    var described = otp.describeToken(valueOf("sc_otp_token"));
    var key = valueOf("sc_otp_aes_key").trim();
    if (key) {
      var plain = otp.decryptToken(valueOf("sc_otp_token"), key);
      described.rows.push({ label: "Private identity",
          value: plain.privateId });
      described.rows.push({ label: "Use counter",
          value: String(plain.useCounter) });
      described.rows.push({ label: "Timestamp low",
          value: String(plain.timestampLow) });
      described.rows.push({ label: "Timestamp high",
          value: String(plain.timestampHigh) });
      described.rows.push({ label: "Session use",
          value: String(plain.sessionUse) });
      described.rows.push({ label: "Random", value: plain.random });
      described.summary = "decrypted " + described.summary;
    }
    report("sc_otp_out", described);
  } catch (e) {
    fail("sc_otp_out", e);
  }
  log.debug("Leaving decodeOtp().");
}

function applyVerify(payload, nonce, apiKey, sentOtp) {
  log.debug("Entering applyVerify().");
  if (!payload || payload.error) {
    setStatus(payload && payload.error ? payload.error :
        "The verifier did not answer.");
    log.debug("Leaving applyVerify(). Error.");
    return;
  }
  var rows = [
    { label: "HTTP status", value: String(payload.status) }
  ];
  try {
    var parsed = otp.parseValidationResponse(payload.body || "", {
      nonce: nonce,
      otp: sentOtp,
      apiKey: apiKey
    });
    rows.push({ label: "Status", value: parsed.status });
    rows.push({ label: "Nonce", value: parsed.nonceMatches ?
        "matches" : "not checked" });
    rows.push({ label: "OTP", value: parsed.otpMatches ?
        "matches" : "not echoed" });
    rows.push({ label: "HMAC", value: parsed.hmacMatches ?
        "matches" : "not checked" });
    render("sc_otp_out", rows);
    setStatus(parsed.status);
  } catch (e) {
    rows.push({ label: "Response",
        value: e.message });
    render("sc_otp_out", rows);
    setStatus(e.message);
  }
  log.debug("Leaving applyVerify().");
}

function verifyOtp() {
  log.debug("Entering verifyOtp().");
  if (!backendAvailable()) {
    setStatus("Verification needs the api.");
    log.debug("Leaving verifyOtp(). No api.");
    return;
  }
  storeSecret(SAVE.api[0], SAVE.api[1]);
  var built = null;
  try {
    var verifier = valueOf("sc_otp_verifier").trim();
    built = otp.buildValidationRequest({
      otp: valueOf("sc_otp_token"),
      id: valueOf("sc_otp_id").trim(),
      apiKey: valueOf("sc_otp_api_key"),
      sl: "",
      timeout: ""
    });
    var payload = {
      body: built.body,
      sslValidate: true
    };
    if (verifier) {
      payload.verifier = verifier;
    } else {
      payload.server = Number(valueOf("sc_otp_server") || "1");
    }
    fetch(apiBase() + "/otp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().then(function (body) {
        applyVerify(body, built.nonce, valueOf("sc_otp_api_key"),
            built.otp);
      });
    }).catch(function (e) {
      setStatus(e.message);
    });
  } catch (e) {
    setStatus(e.message);
    log.debug("Leaving verifyOtp(). Refused.");
    return;
  }
  log.debug("Leaving verifyOtp().");
}

function oathSecret() {
  log.debug("Entering oathSecret().");
  var text = valueOf("sc_oath_secret").trim();
  var bytesOut = null;
  if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0 &&
      text.length > 0) {
    bytesOut = Buffer.from(text, "hex");
  } else {
    bytesOut = Buffer.from(text, "utf8");
  }
  log.debug("Leaving oathSecret().");
  return bytesOut;
}

function calculateHotp() {
  log.debug("Entering calculateHotp().");
  storeSecret(SAVE.oath[0], SAVE.oath[1]);
  try {
    var digits = Number(valueOf("sc_oath_digits"));
    var code = oath.hotp(oathSecret(),
        Number(valueOf("sc_oath_counter")), digits,
        valueOf("sc_oath_algorithm"));
    report("sc_oath_out", {
      summary: code,
      rows: [{ label: "HOTP", value: code }]
    });
  } catch (e) {
    fail("sc_oath_out", e);
  }
  log.debug("Leaving calculateHotp().");
}

function calculateTotp() {
  log.debug("Entering calculateTotp().");
  storeSecret(SAVE.oath[0], SAVE.oath[1]);
  try {
    var digits = Number(valueOf("sc_oath_digits"));
    var code = oath.totp(oathSecret(),
        Math.floor(Date.now() / 1000), {
          digits: digits,
          algorithm: valueOf("sc_oath_algorithm")
        });
    report("sc_oath_out", {
      summary: code,
      rows: [{ label: "TOTP", value: code }]
    });
  } catch (e) {
    fail("sc_oath_out", e);
  }
  log.debug("Leaving calculateTotp().");
}

function decodeOathCommand() {
  log.debug("Entering decodeOathCommand().");
  try {
    report("sc_oath_out", oath.describeCommand(valueOf("sc_oath_trace")));
  } catch (e) {
    fail("sc_oath_out", e);
  }
  log.debug("Leaving decodeOathCommand().");
}

function decodeOathResponse() {
  log.debug("Entering decodeOathResponse().");
  try {
    report("sc_oath_out",
        oath.describeResponse(valueOf("sc_oath_trace")));
  } catch (e) {
    fail("sc_oath_out", e);
  }
  log.debug("Leaving decodeOathResponse().");
}

function certRows(described) {
  log.debug("Entering certRows().");
  var rows = [
    { label: "Subject", value: described.subject },
    { label: "Issuer", value: described.issuer },
    { label: "Serial", value: described.serialHex },
    { label: "Not before", value: described.notBefore },
    { label: "Not after", value: described.notAfter },
    { label: "Signature", value: described.signatureAlgorithm },
    { label: "Public key", value: described.publicKey }
  ];
  log.debug("Leaving certRows().");
  return rows;
}

function showCertificate(der, prior) {
  log.debug("Entering showCertificate().");
  var pem = bytes.derToPem(der, "CERTIFICATE");
  x509.describeCertificate(pem).then(function (described) {
    render("sc_piv_out", prior.concat(certRows(described)));
    setStatus(described.subject);
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving showCertificate().");
}

function decodePivCommand() {
  log.debug("Entering decodePivCommand().");
  try {
    report("sc_piv_out", piv.describeCommand(valueOf("sc_piv_trace")));
  } catch (e) {
    fail("sc_piv_out", e);
  }
  log.debug("Leaving decodePivCommand().");
}

function decodePivResponse() {
  log.debug("Entering decodePivResponse().");
  try {
    var described = piv.describeResponse(valueOf("sc_piv_trace"));
    report("sc_piv_out", described);
    var cert = described.certificate;
    if (cert && cert.der) {
      showCertificate(cert.der, described.rows);
    } else if (cert && cert.deflated) {
      inflateGzip(cert.deflated).then(function (der) {
        var extra = [];
        try {
          extra = piv.attestationRows(der);
        } catch (e) {
          extra = [];
        }
        showCertificate(der, described.rows.concat(extra));
      }).catch(function (e) {
        setStatus(e.message);
      });
    }
  } catch (e) {
    fail("sc_piv_out", e);
  }
  log.debug("Leaving decodePivResponse().");
}

function inflateGzip(input) {
  log.debug("Entering inflateGzip().");
  if (typeof DecompressionStream !== "function") {
    log.debug("Leaving inflateGzip(). Unsupported.");
    return Promise.reject(new Error(
        "This browser cannot inflate a gzip certificate."));
  }
  var stream = new Blob([input]).stream()
      .pipeThrough(new DecompressionStream("gzip"));
  var pending = new Response(stream).arrayBuffer().then(function (buf) {
    return Buffer.from(buf);
  });
  log.debug("Leaving inflateGzip().");
  return pending;
}

function decodePgpCommand() {
  log.debug("Entering decodePgpCommand().");
  try {
    report("sc_pgp_out", pgp.describeCommand(valueOf("sc_pgp_trace")));
  } catch (e) {
    fail("sc_pgp_out", e);
  }
  log.debug("Leaving decodePgpCommand().");
}

function addKey(rows, pem) {
  log.debug("Entering addKey().");
  if (!pem) {
    log.debug("Leaving addKey(). None.");
    return;
  }
  keys.describePublicPem(pem).then(function (desc) {
    var text = desc ? (desc.kind +
        (desc.bits ? " " + desc.bits + "-bit" : "") +
        (desc.curve ? " " + desc.curve : "") +
        (desc.name ? " " + desc.name : "")) : "unrecognised";
    rows.push({ label: "Key", value: text });
    render("sc_pgp_out", rows);
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving addKey().");
}

function decodePgpResponse() {
  log.debug("Entering decodePgpResponse().");
  try {
    var response = pgp.describeResponse(valueOf("sc_pgp_trace"));
    report("sc_pgp_out", response);
    if (response.pem) {
      addKey(response.rows.slice(), response.pem);
    }
  } catch (e) {
    fail("sc_pgp_out", e);
  }
  log.debug("Leaving decodePgpResponse().");
}

function decodeHsmCommand() {
  log.debug("Entering decodeHsmCommand().");
  try {
    report("sc_hsm_out", hsm.describeCommand(valueOf("sc_hsm_trace")));
  } catch (e) {
    fail("sc_hsm_out", e);
  }
  log.debug("Leaving decodeHsmCommand().");
}

function decodeHsmResponse() {
  log.debug("Entering decodeHsmResponse().");
  try {
    report("sc_hsm_out", hsm.describeResponse(valueOf("sc_hsm_trace")));
  } catch (e) {
    fail("sc_hsm_out", e);
  }
  log.debug("Leaving decodeHsmResponse().");
}

function buildVerify() {
  log.debug("Entering buildVerify().");
  var pin = valueOf("sc_pin");
  if (!pin) {
    setStatus("The PIN field is empty.");
    log.debug("Leaving buildVerify(). Empty.");
    return;
  }
  var apdu = null;
  try {
    apdu = piv.verifyApdu(pin);
  } catch (e) {
    setStatus(e.message);
    log.debug("Leaving buildVerify(). PIN length.");
    return;
  }
  var box = document.getElementById("sc_reader_apdu");
  var pinBox = document.getElementById("sc_pin");
  if (box) {
    box.value = iso.toHex(apdu);
  }
  if (pinBox) {
    pinBox.value = "";
  }
  setStatus("PIV VERIFY APDU built, the PIN padded with FF to 8 " +
      "bytes. The PIN is not stored.");
  log.debug("Leaving buildVerify().");
}

function listReaders() {
  log.debug("Entering listReaders().");
  if (!backendAvailable()) {
    setStatus("Listing readers needs the api.");
    log.debug("Leaving listReaders(). No api.");
    return;
  }
  fetch(apiBase() + "/smartcard/readers")
    .then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok) {
          setStatus(body.error || "The readers could not be listed.");
          return;
        }
        var names = body.readers || [];
        var rows = names.map(function (name) {
          return { label: "Reader", value: name };
        });
        if (rows.length === 0) {
          rows = [{ label: "Readers", value: "(none)" }];
        }
        render("sc_reader_out", rows);
        setStatus(names.length + " reader(s)");
        if (names.length === 1) {
          var field = document.getElementById("sc_reader_name");
          if (field && !field.value) {
            field.value = names[0];
          }
        }
      });
    })
    .catch(function (e) {
      setStatus(e.message);
    });
  log.debug("Leaving listReaders().");
}

function readerApdus() {
  log.debug("Entering readerApdus().");
  var lines = valueOf("sc_reader_apdu").split(/\r?\n/)
    .map(function (line) {
      return line.trim();
    })
    .filter(function (line) {
      return line.length > 0;
    });
  log.debug("Leaving readerApdus().");
  return lines;
}

function transmitRows(body) {
  log.debug("Entering transmitRows().");
  var rows = [];
  (body.results || [body]).forEach(function (result, index) {
    (result.steps || []).forEach(function (step) {
      rows.push({ label: "APDU " + (index + 1) + " sent",
          value: step.apdu });
      rows.push({ label: "  answered", value: step.status +
          (step.data ? " " + step.data : "") });
    });
    rows.push({ label: "APDU " + (index + 1) + " status",
        value: result.status || "" });
    rows.push({ label: "APDU " + (index + 1) + " data",
        value: result.data || "(none)" });
  });
  log.debug("Leaving transmitRows().");
  return rows;
}

function transmitApdu() {
  log.debug("Entering transmitApdu().");
  if (!backendAvailable()) {
    setStatus("Transmit needs the api.");
    log.debug("Leaving transmitApdu(). No api.");
    return;
  }
  var apdus = readerApdus();
  if (apdus.length === 0) {
    setStatus("Enter at least one APDU.");
    log.debug("Leaving transmitApdu(). Empty.");
    return;
  }
  fetch(apiBase() + "/smartcard/transmit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      reader: valueOf("sc_reader_name"),
      apdus: apdus,
      getResponse: checked("sc_reader_get_response")
    })
  }).then(function (res) {
    return res.json().then(function (body) {
      if (!res.ok) {
        setStatus(body.error || "Transmit failed.");
        return;
      }
      render("sc_reader_out", transmitRows(body));
      var done = (body.results || [body]).length;
      setStatus(body.status + (done < apdus.length ?
          " — stopped after APDU " + done + " of " + apdus.length :
          ""));
    });
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving transmitApdu().");
}

function hidBytes(hex) {
  log.debug("Entering hidBytes().");
  var text = String(hex || "").replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]+$/.test(text) || text.length % 2 !== 0) {
    log.debug("Leaving hidBytes(). Hex.");
    throw new Error("The challenge is hex.");
  }
  log.debug("Leaving hidBytes().");
  return Buffer.from(text, "hex");
}

// HOW THE PAGE REACHES A KEY, chosen once for the whole page:
//
//   browser  from this page itself — the keyboard OTP in any browser, and
//            OTP-slot challenge-response over WebHID where the browser has
//            it (Chrome, Edge). No browser opens CCID: WebUSB refuses the
//            smart-card class, and Chrome's Web Smart Card API is offered
//            only to installed isolated web apps. So PIV, OATH, the
//            OpenPGP card and YubiHSM Auth cannot be reached this way.
//   api      through the api's reader relay, which uses the OS's own PC/SC
//            (pcsc-lite, macOS's PCSC framework, WinSCard). Any browser,
//            every application, challenge-response over CCID.
//
// The default is browser where WebHID exists and api where it does not
// (Firefox). The choice is remembered in this browser.
var TRANSPORT_KEY = "smartcard_transport";

function hasWebHid() {
  log.debug("Entering hasWebHid().");
  var has = typeof navigator !== "undefined" && !!navigator.hid;
  log.debug("Leaving hasWebHid(). " + has);
  return has;
}

function transport() {
  log.debug("Entering transport().");
  var chosen = valueOf("sc_transport");
  var value = chosen === "browser" || chosen === "api" ? chosen :
      (hasWebHid() ? "browser" : "api");
  log.debug("Leaving transport(). " + value);
  return value;
}

// The note beside the choice: what this choice can and cannot reach here.
function describeTransport() {
  log.debug("Entering describeTransport().");
  var note = document.getElementById("sc_transport_note");
  if (!note) {
    log.debug("Leaving describeTransport(). No note.");
    return;
  }
  var text = "";
  if (transport() === "browser") {
    text = hasWebHid() ?
      "OTP challenge-response over WebHID. PIV, OATH, OpenPGP and " +
      "YubiHSM Auth need the API: no browser opens a smart card." :
      "This browser has no WebHID, so only the typed OTP reaches the " +
      "key this way. Choose the API for everything else.";
  } else {
    text = relayProblem() || "Every application, through the api's " +
      "reader relay and this machine's PC/SC.";
  }
  note.textContent = text;
  log.debug("Leaving describeTransport().");
}

function onTransportChange() {
  log.debug("Entering onTransportChange().");
  storageSet(TRANSPORT_KEY, transport());
  describeTransport();
  detectKey();
  log.debug("Leaving onTransportChange().");
}

// The challenge goes over WebHID in browser mode and over CCID in api mode.
function hidTransport() {
  log.debug("Entering hidTransport().");
  var value = transport() === "api" ? "ccid" : "webhid";
  log.debug("Leaving hidTransport(). " + value);
  return value;
}

// Challenge-response through the API: over HID (api/otp_hid.js), which is
// how a key on USB answers, and over CCID through the reader relay when HID
// is not there — which is how a key on an NFC reader answers.
function challengeOverApi() {
  log.debug("Entering challengeOverApi().");
  var problem = relayProblem();
  if (problem) {
    setStatus(problem);
    log.debug("Leaving challengeOverApi(). " + problem);
    return;
  }
  var slot = valueOf("sc_hid_slot");
  var challenge = valueOf("sc_hid_challenge").replace(/\s+/g, "");
  setStatus("Sending the challenge over HID through the API. Touch the " +
      "key if it blinks.");
  fetch(apiBase() + "/smartcard/otp/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slot: slot, challenge: challenge,
                           variable: valueOf("sc_hid_hmac_mode") !== "fixed" })
  }).then(function (res) {
    return res.json().then(function (body) {
      if (res.ok) {
        render("sc_reader_out", [
          { label: "Response", value: body.response },
          { label: "Transport", value: "HID through the API (" +
              body.device + ")" },
          { label: "Frame read", value: body.raw }
        ]);
        setStatus("HID response through the API, " +
            body.response.length / 2 + " bytes, CRC good");
        return;
      }
      if (res.status === 400 || /slot configured|refused|did not take/i
          .test(body.error || "")) {
        setStatus(body.error || "The challenge was refused.");
        return;
      }
      setStatus("HID through the API: " + (body.error || res.status) +
          " Trying CCID, which is how a key on an NFC reader answers.");
      challengeOverCcid();
    });
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving challengeOverApi(). Sent.");
}

function sendHid() {
  log.debug("Entering sendHid().");
  if (hidTransport() === "ccid") {
    log.debug("Leaving sendHid(). Through the API.");
    challengeOverApi();
    return;
  }
  if (typeof navigator === "undefined" || !navigator.hid) {
    setStatus("This browser has no WebHID. Choose \"the API\" above: " +
        "the challenge then goes over CCID through the api's reader relay.");
    log.debug("Leaving sendHid(). No WebHID.");
    return;
  }
  var slot = parseInt(valueOf("sc_hid_slot"), 16);
  var challenge = null;
  try {
    challenge = hidBytes(valueOf("sc_hid_challenge"));
    otp.hidFrame(slot, challenge,
        { variable: valueOf("sc_hid_hmac_mode") !== "fixed" });
  } catch (e) {
    setStatus(e.message);
    log.debug("Leaving sendHid(). " + e.message);
    return;
  }
  // THE OTP INTERFACE, NOT FIDO. The slots answer on the key's HID
  // KEYBOARD interface (usage page 0x01, usage 0x06), through feature
  // reports, which WebHID allows on a keyboard collection. This filter was
  // usage page 0xF1D0 — the FIDO interface — until 2026-11-13: Chrome
  // blocks that page from WebHID outright, so no key was ever offered and
  // the button did nothing.
  navigator.hid.requestDevice({
    filters: [{ vendorId: 0x1050, usagePage: 0x0001, usage: 0x0006 }]
  }).then(function (devices) {
    if (!devices || devices.length === 0) {
      setStatus("No OTP HID device was chosen.");
      return null;
    }
    var device = devices[0];
    var opened = device.opened ? Promise.resolve() : device.open();
    return opened.then(function () {
      return otp.hidChallenge({
        send: function (report) {
          return device.sendFeatureReport(0, report);
        },
        receive: function () {
          return device.receiveFeatureReport(0);
        }
      }, slot, challenge, {
        variable: valueOf("sc_hid_hmac_mode") !== "fixed",
        onTouch: function () {
          setStatus("Touch the key.");
        }
      });
    });
  }).then(function (answer) {
    if (!answer) {
      return;
    }
    render("sc_reader_out", [
      { label: "Response", value: iso.toHex(answer.response) },
      { label: "Transport", value: "WebHID, from this browser" },
      { label: "Frame read", value: iso.toHex(answer.raw) }
    ]);
    setStatus("HID response, " + answer.response.length + " bytes, CRC good");
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving sendHid().");
}

// What /smartcard/limits said, so a CCID challenge can say why it cannot
// run rather than fail at the api.
var relay = { known: false, enabled: false, available: false, reason: "" };

function relayProblem() {
  log.debug("Entering relayProblem().");
  var why = null;
  if (!backendAvailable()) {
    why = "CCID needs the api, and this deployment has none.";
  } else if (!relay.known) {
    why = "The api has not said whether its reader relay is on.";
  } else if (!relay.enabled) {
    why = "The api's reader relay is off. Start the stack with " +
        "docker-compose-smartcard.yml (or set smartcardReaderEnabled: " +
        "true) to send a challenge over CCID.";
  } else if (!relay.available) {
    why = relay.reason || "The api has no PC/SC.";
  }
  log.debug("Leaving relayProblem(). " + (why ? "blocked" : "ok"));
  return why;
}

// The reader to use: the one named on the page, or — when the field is
// empty — the only reader the api can see, filled in for next time.
function chosenReader() {
  log.debug("Entering chosenReader().");
  var named = valueOf("sc_reader_name").trim();
  if (named) {
    log.debug("Leaving chosenReader(). Named.");
    return Promise.resolve(named);
  }
  var found = fetch(apiBase() + "/smartcard/readers").then(function (res) {
    return res.json().then(function (body) {
      if (!res.ok) {
        throw new Error(body.error || "The readers could not be listed.");
      }
      var names = body.readers || [];
      if (names.length !== 1) {
        throw new Error(names.length === 0 ? "The api sees no reader. Is " +
            "the key plugged in, and is the host's pcscd running?" :
            names.length + " readers: name one in the Reader name field.");
      }
      var field = document.getElementById("sc_reader_name");
      if (field) {
        field.value = names[0];
      }
      return names[0];
    });
  });
  log.debug("Leaving chosenReader(). Asking the api.");
  return found;
}

// Challenge-response over CCID: SELECT the OTP application, then CALCULATE
// with the slot in P1, on one connection through POST /smartcard/transmit.
function challengeOverCcid() {
  log.debug("Entering challengeOverCcid().");
  var problem = relayProblem();
  if (problem) {
    setStatus(problem);
    log.debug("Leaving challengeOverCcid(). " + problem);
    return;
  }
  var slot = parseInt(valueOf("sc_hid_slot"), 16);
  var apdus = null;
  try {
    apdus = [otp.ccidSelectApdu(),
             otp.ccidCalculateApdu(slot, hidBytes(valueOf("sc_hid_challenge")),
                 { variable: valueOf("sc_hid_hmac_mode") !== "fixed" })];
  } catch (e) {
    setStatus(e.message);
    log.debug("Leaving challengeOverCcid(). " + e.message);
    return;
  }
  setStatus("Sending the challenge over CCID. Touch the key if it blinks.");
  chosenReader().then(function (reader) {
    return fetch(apiBase() + "/smartcard/transmit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reader: reader, apdus: apdus,
                             getResponse: true })
    });
  }).then(function (res) {
    return res.json().then(function (body) {
      if (!res.ok) {
        throw new Error(body.error || "The relay refused the challenge.");
      }
      var results = body.results || [body];
      var last = results[results.length - 1] || {};
      if (results.length < 2 || !/^90/.test(String(last.status || ""))) {
        render("sc_reader_out", transmitRows(body));
        throw new Error("The key answered " + (last.status || "nothing") +
            (results.length < 2 ? " to SELECT of the OTP application." :
            ". Is the slot configured for challenge-response?"));
      }
      var response = otp.ccidResponse(slot, Buffer.from(last.data || "",
                                                        "hex"));
      render("sc_reader_out", [
        { label: "Response", value: iso.toHex(response) },
        { label: "Transport", value: "CCID through the api's reader relay" }
      ].concat(transmitRows(body)));
      setStatus("CCID response, " + response.length + " bytes");
    });
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving challengeOverCcid(). Sent.");
}

// ---------------------------------------------------------------------------
// READ FROM THE KEY, through the api's reader relay.
//
// Each application's read is a list of short sequences, each beginning with
// that application's SELECT, because the relay stops a sequence at the first
// answer that is not 90xx or 61xx — and a PIV slot with no certificate
// answers 6A82, which must not end the read. Every command here only READS:
// no VERIFY, no PIN, no password, nothing that changes the key. The answers
// go through the same decoders a pasted trace does.
// ---------------------------------------------------------------------------
function hexOf(fields) {
  log.debug("Entering hexOf().");
  var hex = iso.encodeCommand(fields).toString("hex");
  log.debug("Leaving hexOf().");
  return hex;
}

function selectHex(aid) {
  log.debug("Entering selectHex().");
  var hex = hexOf({ cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00,
                    data: Buffer.from(aid, "hex") });
  log.debug("Leaving selectHex().");
  return hex;
}

// PIV GET DATA of a BER-TLV object tag (SP 800-73-4 part 2, 3.1.2).
function pivGetData(tagHex) {
  log.debug("Entering pivGetData().");
  var tag = Buffer.from(tagHex, "hex");
  var hex = hexOf({ cla: 0x00, ins: 0xcb, p1: 0x3f, p2: 0xff,
                    data: Buffer.concat([Buffer.from([0x5c, tag.length]),
                                         tag]), le: 256 });
  log.debug("Leaving pivGetData().");
  return hex;
}

// The steps of each application's read: [label, [apdu hex, ...]].
function readPlan(app) {
  log.debug("Entering readPlan().");
  var plan = [];
  if (app === "otp") {
    plan = [["Slots (the OTP application's status)",
             [otp.ccidSelectApdu()]]];
  } else if (app === "oath") {
    var sel = oath.selectApdu().toString("hex");
    var calcAll = hexOf({ cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01,
      data: iso.encodeTlv(0x74,
          oath.totpChallenge(Math.floor(Date.now() / 1000))),
      le: 256 });
    plan = [
      ["Credentials (LIST)", [sel, oath.listApdu().toString("hex")]],
      ["Codes now (CALCULATE ALL, 30-second TOTP)", [sel, calcAll]]
    ];
  } else if (app === "piv") {
    var psel = selectHex(piv.PIV_AID);
    plan = [
      ["Version (GET VERSION)", [psel, hexOf({ cla: 0x00, ins: 0xfd,
                                                p1: 0x00, p2: 0x00,
                                                le: 256 })]],
      ["Serial (GET SERIAL)", [psel, hexOf({ cla: 0x00, ins: 0xf8,
                                              p1: 0x00, p2: 0x00,
                                              le: 256 })]],
      ["CHUID", [psel, pivGetData("5fc102")]],
      ["Discovery object", [psel, pivGetData("7e")]],
      ["Certificate, slot 9A (authentication)",
       [psel, pivGetData("5fc105")]],
      ["Certificate, slot 9C (signature)", [psel, pivGetData("5fc10a")]],
      ["Certificate, slot 9D (key management)",
       [psel, pivGetData("5fc10b")]],
      ["Certificate, slot 9E (card authentication)",
       [psel, pivGetData("5fc101")]],
      ["Attestation certificate, slot F9", [psel, pivGetData("5fff01")]],
      ["Attestation of slot 9A (ATTEST)", [psel, hexOf({ cla: 0x00,
                                                          ins: 0xf9,
                                                          p1: 0x9a,
                                                          p2: 0x00,
                                                          le: 256 })]]
    ];
  } else if (app === "pgp") {
    var gsel = selectHex(pgp.AID_PREFIX);
    var getData = function (tag) {
      return hexOf({ cla: 0x00, ins: 0xca, p1: 0x00, p2: tag, le: 256 });
    };
    var readKey = function (crt) {
      return hexOf({ cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
                     data: Buffer.from([crt, 0x00]), le: 256 });
    };
    plan = [
      ["Application related data", [gsel, getData(0x6e)]],
      ["Cardholder related data", [gsel, getData(0x65)]],
      ["Security support template", [gsel, getData(0x7a)]],
      ["Signature key", [gsel, readKey(0xb6)]],
      ["Decryption key", [gsel, readKey(0xb8)]],
      ["Authentication key", [gsel, readKey(0xa4)]]
    ];
  } else if (app === "hsm") {
    var hsel = hsm.selectApdu().toString("hex");
    plan = [
      ["Version", [hsel, hsm.versionApdu().toString("hex")]],
      ["Credentials (LIST)", [hsel, hsm.listApdu().toString("hex")]]
    ];
  }
  log.debug("Leaving readPlan(). " + plan.length + " step(s).");
  return plan;
}

// The SELECT answer of the OTP application, as rows.
function describeOtpStatus(hex) {
  log.debug("Entering describeOtpStatus().");
  var response = iso.parseResponse(hex);
  if (response.sw !== 0x9000) {
    log.debug("Leaving describeOtpStatus(). " + response.name);
    return { summary: response.name, rows: [] };
  }
  var st = otp.parseStatus(response.data);
  function slot(n, info) {
    return { label: "Slot " + n, value: info.configured ?
        "programmed" + (info.touch ? ", needs a touch" : "") : "empty" };
  }
  var described = {
    summary: "firmware " + st.version + "; slot 1 " +
        (st.slot1.configured ? "programmed" : "empty") + ", slot 2 " +
        (st.slot2.configured ? "programmed" : "empty"),
    rows: [{ label: "Firmware", value: st.version },
           { label: "Programming sequence",
             value: String(st.programSequence) },
           slot(1, st.slot1), slot(2, st.slot2),
           { label: "Note", value: "A programmed slot may hold a Yubico " +
               "OTP, a static password or challenge-response; the status " +
               "does not say which. Challenge-response on the Reader pane " +
               "answers 6985 for a slot that is not challenge-response." }]
  };
  log.debug("Leaving describeOtpStatus().");
  return described;
}

var READ_DECODERS = {
  otp: { out: "sc_otp_out", decode: describeOtpStatus },
  oath: { out: "sc_oath_out", decode: function (hex) {
    return oath.describeResponse(hex);
  } },
  piv: { out: "sc_piv_out", decode: function (hex) {
    return piv.describeResponse(hex);
  } },
  pgp: { out: "sc_pgp_out", decode: function (hex) {
    return pgp.describeResponse(hex);
  } },
  hsm: { out: "sc_hsm_out", decode: function (hex) {
    return hsm.describeResponse(hex);
  } }
};

function transmitSequence(reader, apdus) {
  log.debug("Entering transmitSequence().");
  var sent = fetch(apiBase() + "/smartcard/transmit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reader: reader, apdus: apdus, getResponse: true })
  }).then(function (res) {
    return res.json().then(function (body) {
      if (!res.ok) {
        throw new Error(body.error || "The relay refused the read.");
      }
      return body;
    });
  });
  log.debug("Leaving transmitSequence().");
  return sent;
}

// Rows for one step's answer, and — for a certificate or a public key —
// a promise of the rows that describe it.
function readRows(app, label, apdus, body) {
  log.debug("Entering readRows().");
  var results = body.results || [body];
  var last = results[results.length - 1] || {};
  if (results.length < apdus.length) {
    log.debug("Leaving readRows(). SELECT failed.");
    return { rows: [{ label: label, value: "SELECT answered " +
        (last.status || "nothing") + "; the application is not there or " +
        "is disabled" }], extra: null };
  }
  var described = null;
  try {
    described = READ_DECODERS[app].decode((last.data || "") +
                                          (last.status || ""));
  } catch (e) {
    log.debug("Leaving readRows(). Undecodable.");
    return { rows: [{ label: label, value: e.message }], extra: null };
  }
  var summary = described.summary;
  // An OATH applet with no accounts answers LIST and CALCULATE ALL with
  // 9000 and nothing else, which reads as nothing having happened.
  if (app === "oath" && /^9000$/.test(last.status || "") && !last.data) {
    summary = "no OATH accounts on this key (" + summary + ")";
  }
  // An OpenPGP key slot with nothing in it answers 6581 (a YubiKey) or 6A88
  // to the read of its public key — not a fault, an empty slot.
  if (app === "pgp" && /^(6581|6A88)$/i.test(last.status || "") &&
      apdus[apdus.length - 1].slice(2, 4) === "47") {
    summary = "no key in this slot (" + summary + ")";
  }
  var rows = [{ label: label, value: summary }];
  described.rows.forEach(function (row) {
    if (row.label !== "Status") {
      rows.push({ label: "    " + row.label, value: row.value });
    }
  });
  var extra = null;
  var cert = described.certificate;
  if (app === "piv" && cert && (cert.der || cert.deflated)) {
    var der = cert.der ? Promise.resolve(cert.der) :
        inflateGzip(cert.deflated);
    extra = der.then(function (raw) {
      return x509.describeCertificate(bytes.derToPem(raw, "CERTIFICATE"));
    }).then(function (desc) {
      return certRows(desc).map(function (row) {
        return { label: "    " + row.label, value: row.value };
      });
    });
  } else if (app === "pgp" && described.pem) {
    extra = keys.describePublicPem(described.pem).then(function (desc) {
      return [{ label: "    Key", value: desc ? desc.kind +
          (desc.bits ? " " + desc.bits + "-bit" : "") +
          (desc.curve ? " " + desc.curve : "") : "unrecognised" }];
    });
  }
  log.debug("Leaving readRows().");
  return { rows: rows, extra: extra };
}

// A message in the pane the user is looking at as well as on the status
// line, which is at the top of the page and out of sight from a pane.
function paneMessage(out, text) {
  log.debug("Entering paneMessage().");
  render(out, [{ label: "Not read", value: text }]);
  setStatus(text);
  log.debug("Leaving paneMessage().");
}

function readFromKey(app) {
  log.debug("Entering readFromKey(). " + app);
  if (!READ_DECODERS[app]) {
    log.debug("Leaving readFromKey(). Unknown application.");
    return;
  }
  var target = READ_DECODERS[app].out;
  if (transport() !== "api") {
    paneMessage(target, "Reading the key needs the API: no browser opens " +
        "a smart card. Set \"Talk to the key through\" at the top of the " +
        "page to the API.");
    log.debug("Leaving readFromKey(). Browser transport.");
    return;
  }
  var problem = relayProblem();
  if (problem) {
    paneMessage(target, problem);
    log.debug("Leaving readFromKey(). " + problem);
    return;
  }
  var plan = readPlan(app);
  var out = READ_DECODERS[app].out;
  var rows = [];
  var extras = [];
  setStatus("Reading from the key…");
  chosenReader().then(function (reader) {
    rows.push({ label: "Reader", value: reader });
    var chain = Promise.resolve();
    plan.forEach(function (step) {
      chain = chain.then(function () {
        return transmitSequence(reader, step[1]).then(function (body) {
          var got = readRows(app, step[0], step[1], body);
          var at = rows.length + got.rows.length;
          rows = rows.concat(got.rows);
          if (got.extra) {
            extras.push(got.extra.then(function (more) {
              return { at: at, rows: more };
            }, function (e) {
              return { at: at, rows: [{ label: "    Could not describe",
                                        value: e.message }] };
            }));
          }
          render(out, rows);
        });
      });
    });
    return chain;
  }).then(function () {
    return Promise.all(extras);
  }).then(function (more) {
    // Insert the described certificates and keys after their steps,
    // last first so the earlier positions stay right.
    more.sort(function (a, b) {
      return b.at - a.at;
    }).forEach(function (m) {
      rows.splice.apply(rows, [m.at, 0].concat(m.rows));
    });
    render(out, rows);
    if (app === "oath") {
      offerOathNames(rows);
    }
    setStatus("Read " + plan.length + " item(s) from the key.");
  }).catch(function (e) {
    rows.push({ label: "Stopped", value: e.message });
    render(out, rows);
    setStatus(e.message);
  });
  log.debug("Leaving readFromKey(). Started.");
}

// ---------------------------------------------------------------------------
// WRITING TO THE KEY, through the api's reader relay.
//
// One path for every application: the API must be the transport, the person
// confirms the exact change in a dialog first, and the result is shown in the
// pane. PINs, passwords and management keys are typed at the moment they are
// used and never stored, and nothing here ever sends a guessed one — a few
// wrong PINs block a PIN.
// ---------------------------------------------------------------------------
function writeToKey(out, apdus, question) {
  log.debug("Entering writeToKey().");
  if (transport() !== "api") {
    paneMessage(out, "Writing to the key needs the API. Set \"Talk to the " +
        "key through\" at the top of the page to the API.");
    log.debug("Leaving writeToKey(). Browser transport.");
    return Promise.resolve(null);
  }
  var problem = relayProblem();
  if (problem) {
    paneMessage(out, problem);
    log.debug("Leaving writeToKey(). " + problem);
    return Promise.resolve(null);
  }
  if (typeof window !== "undefined" && window.confirm &&
      !window.confirm(question)) {
    setStatus("Nothing was written.");
    log.debug("Leaving writeToKey(). Declined.");
    return Promise.resolve(null);
  }
  setStatus("Writing to the key…");
  var written = chosenReader().then(function (reader) {
    return transmitSequence(reader, apdus);
  }).then(function (body) {
    var results = body.results || [body];
    var last = results[results.length - 1] || {};
    var ok = results.length === apdus.length &&
        /^90/.test(String(last.status || ""));
    return { ok: ok, status: last.status || "", data: last.data || "",
             body: body, name: iso.statusName(parseInt(last.status, 16)) };
  });
  log.debug("Leaving writeToKey(). Sent.");
  return written;
}

// The OATH applet's SELECT answer: whether a password guards it.
function oathSelectState() {
  log.debug("Entering oathSelectState().");
  var state = chosenReader().then(function (reader) {
    return transmitSequence(reader, [oath.selectApdu().toString("hex")]);
  }).then(function (body) {
    var last = (body.results || [body])[0] || {};
    if (!/^90/.test(String(last.status || ""))) {
      throw new Error("The OATH applet did not answer SELECT (" +
          last.status + ").");
    }
    return oath.parseSelect(Buffer.from(last.data || "", "hex"));
  });
  log.debug("Leaving oathSelectState().");
  return state;
}

var OATH_PASSWORD_MESSAGE = "This key's OATH applet has a password. This " +
    "page does not send OATH passwords yet; remove it with Yubico " +
    "Authenticator or `ykman oath access change --clear`, or add the " +
    "account there.";

// The account the form describes: from a pasted otpauth:// link when there
// is one, otherwise from the fields.
function oathFormAccount() {
  log.debug("Entering oathFormAccount().");
  var uri = valueOf("sc_oath_add_uri").trim();
  var a = uri ? oath.parseOtpauth(uri) : {
    type: valueOf("sc_oath_add_type") || "TOTP",
    issuer: valueOf("sc_oath_add_issuer").trim(),
    account: valueOf("sc_oath_add_account").trim(),
    secret: valueOf("sc_oath_add_secret"),
    algorithm: valueOf("sc_oath_add_algorithm") || "SHA-1",
    digits: Number(valueOf("sc_oath_add_digits") || 6),
    period: Number(valueOf("sc_oath_add_period") || 30),
    counter: Number(valueOf("sc_oath_add_counter") || 0)
  };
  a.touch = checked("sc_oath_add_touch");
  a.name = oath.credentialName(a);
  a.key = oath.hmacKey(oath.base32Decode(a.secret), a.algorithm);
  log.debug("Leaving oathFormAccount().");
  return a;
}

function addOathAccount() {
  log.debug("Entering addOathAccount().");
  var out = "sc_oath_out";
  var a = null;
  var apdu = null;
  try {
    a = oathFormAccount();
    apdu = oath.putApdu({ name: a.name, type: a.type,
                          algorithm: a.algorithm, digits: a.digits,
                          secret: a.key, touch: a.touch,
                          counter: a.type === "HOTP" ? a.counter : 0 });
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving addOathAccount(). " + e.message);
    return;
  }
  var question = "Write this OATH account to the key?\n\n  " + a.name +
      "\n  " + a.type + ", " + a.algorithm + ", " + a.digits + " digits" +
      (a.touch ? ", touch required" : "") +
      "\n\nAn account with the same name on the key is replaced.";
  var gate = transport() === "api" && !relayProblem() ? oathSelectState() :
      Promise.resolve({});
  gate.then(function (sel) {
    if (sel && sel.challenge) {
      paneMessage(out, OATH_PASSWORD_MESSAGE);
      return null;
    }
    return writeToKey(out, [oath.selectApdu().toString("hex"),
                            apdu.toString("hex")], question);
  }).then(function (result) {
    if (!result) {
      return;
    }
    if (!result.ok) {
      paneMessage(out, "The key refused the account: " + result.status +
          " " + result.name + ".");
      return;
    }
    setStatus("Added " + a.name + ".");
    readFromKey("oath");
  }).catch(function (e) {
    paneMessage(out, e.message);
  });
  log.debug("Leaving addOathAccount().");
}

function deleteOathAccount() {
  log.debug("Entering deleteOathAccount().");
  var out = "sc_oath_out";
  var name = valueOf("sc_oath_del_name").trim();
  var apdu = null;
  try {
    apdu = oath.deleteApdu(name);
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving deleteOathAccount(). " + e.message);
    return;
  }
  var gate = transport() === "api" && !relayProblem() ? oathSelectState() :
      Promise.resolve({});
  gate.then(function (sel) {
    if (sel && sel.challenge) {
      paneMessage(out, OATH_PASSWORD_MESSAGE);
      return null;
    }
    return writeToKey(out, [oath.selectApdu().toString("hex"),
                            apdu.toString("hex")],
        "Delete the OATH account \"" + name + "\" from the key? Its " +
        "secret is gone for good: the key does not give it back.");
  }).then(function (result) {
    if (!result) {
      return;
    }
    if (!result.ok) {
      paneMessage(out, "The key did not delete it: " + result.status + " " +
          result.name + (result.status === "6984" ? " (no account by " +
          "that name)" : "") + ".");
      return;
    }
    setStatus("Deleted " + name + ".");
    readFromKey("oath");
  }).catch(function (e) {
    paneMessage(out, e.message);
  });
  log.debug("Leaving deleteOathAccount().");
}

// ---------------------------------------------------------------------------
// OTP SLOTS: program, delete, swap.
// ---------------------------------------------------------------------------
var SLOT1_WARNING = "\n\nSlot 1 holds the key's factory Yubico OTP " +
    "credential, which YubiCloud knows. Overwriting or deleting it cannot " +
    "be undone: no tool can put the factory credential back.";

function hexField(id, size, what) {
  log.debug("Entering hexField().");
  var text = valueOf(id).replace(/\s+/g, "");
  if (!text && size === 0) {
    log.debug("Leaving hexField(). Empty and optional.");
    return null;
  }
  if (!/^[0-9a-fA-F]*$/.test(text) || text.length % 2 !== 0 ||
      (size && text.length !== size * 2)) {
    log.debug("Leaving hexField(). Bad hex.");
    throw new Error(what + " is " + (size ? size * 2 + " " : "") +
        "hex characters.");
  }
  log.debug("Leaving hexField().");
  return Buffer.from(text, "hex");
}

function randomBytes(n) {
  log.debug("Entering randomBytes().");
  var out = new Uint8Array(n);
  window.crypto.getRandomValues(out);
  log.debug("Leaving randomBytes().");
  return Buffer.from(out);
}

// Fill the slot form's secrets from the browser's random source. They stay
// on screen, because the key never gives a secret back.
function generateSlotSecrets() {
  log.debug("Entering generateSlotSecrets().");
  var type = valueOf("sc_slot_type");
  var set = function (id, value) {
    var el = document.getElementById(id);
    if (el) {
      el.value = value;
    }
  };
  if (type === "hmac") {
    set("sc_slot_hmac_key", randomBytes(20).toString("hex"));
  } else if (type === "yubico-otp") {
    // "vv" marks a self-generated public identity, as ykman does.
    set("sc_slot_public_id", "vv" + otp.modhexEncode(randomBytes(5)));
    set("sc_slot_private_id", randomBytes(6).toString("hex"));
    set("sc_slot_aes_key", randomBytes(16).toString("hex"));
  } else {
    set("sc_slot_hotp_key", oathBase32(randomBytes(20)));
  }
  setStatus("Generated. Copy the secret now: the key will not give it back.");
  log.debug("Leaving generateSlotSecrets().");
}

function oathBase32(bytes) {
  log.debug("Entering oathBase32().");
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var bits = 0;
  var value = 0;
  var out = "";
  var i = 0;
  for (i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  log.debug("Leaving oathBase32().");
  return out;
}

function onSlotTypeChange() {
  log.debug("Entering onSlotTypeChange().");
  var type = valueOf("sc_slot_type");
  show("sc_slot_hmac", type === "hmac");
  show("sc_slot_otp", type === "yubico-otp");
  show("sc_slot_hotp", type === "hotp");
  log.debug("Leaving onSlotTypeChange().");
}

function slotFormConfig() {
  log.debug("Entering slotFormConfig().");
  var type = valueOf("sc_slot_type");
  var opts = { type: type };
  if (type === "hmac") {
    opts.key = hexField("sc_slot_hmac_key", null, "The HMAC key");
    opts.touch = checked("sc_slot_touch");
  } else if (type === "yubico-otp") {
    opts.publicId = otp.modhexDecode(valueOf("sc_slot_public_id").trim());
    opts.privateId = hexField("sc_slot_private_id", 6, "The private identity");
    opts.aesKey = hexField("sc_slot_aes_key", 16, "The AES key");
  } else {
    var secret = valueOf("sc_slot_hotp_key");
    opts.key = /^[0-9a-fA-F\s]+$/.test(secret) && secret.length % 2 === 0 &&
        valueOf("sc_slot_hotp_format") === "hex" ?
        Buffer.from(secret.replace(/\s+/g, ""), "hex") :
        oath.base32Decode(secret);
    opts.digits = Number(valueOf("sc_slot_hotp_digits") || 6);
    opts.imf = Number(valueOf("sc_slot_hotp_counter") || 0);
  }
  var described = { hmac: "HMAC-SHA1 challenge-response" +
      (opts.touch ? ", touch required" : ""),
    "yubico-otp": "Yubico OTP, public identity " +
      valueOf("sc_slot_public_id").trim(),
    hotp: "HOTP, " + opts.digits + " digits" }[type];
  var config = otp.slotConfig(opts);
  log.debug("Leaving slotFormConfig().");
  return { config: config, described: described };
}

function slotAfterWrite(result, done) {
  log.debug("Entering slotAfterWrite().");
  if (!result) {
    log.debug("Leaving slotAfterWrite(). Not sent.");
    return;
  }
  if (!result.ok) {
    paneMessage("sc_otp_out", "The key refused it: " + result.status + " " +
        result.name + (result.status === "6982" ? " (the slot's access " +
        "code is wrong or missing)" : "") + ".");
    log.debug("Leaving slotAfterWrite(). Refused.");
    return;
  }
  setStatus(done);
  readFromKey("otp");
  log.debug("Leaving slotAfterWrite().");
}

function programSlot() {
  log.debug("Entering programSlot().");
  var slot = Number(valueOf("sc_slot_number") || 2);
  var apdu = null;
  var made = null;
  try {
    made = slotFormConfig();
    apdu = otp.programSlotApdu(slot, made.config,
        hexField("sc_slot_access_code", 0, "The access code"));
  } catch (e) {
    paneMessage("sc_otp_out", e.message);
    log.debug("Leaving programSlot(). " + e.message);
    return;
  }
  writeToKey("sc_otp_out", [otp.ccidSelectApdu(), apdu],
      "Program OTP slot " + slot + " as " + made.described + "?\n\n" +
      "Whatever the slot holds now is replaced." +
      (slot === 1 ? SLOT1_WARNING : "")).then(function (result) {
    slotAfterWrite(result, "Programmed slot " + slot + ".");
  }).catch(function (e) {
    paneMessage("sc_otp_out", e.message);
  });
  log.debug("Leaving programSlot().");
}

function deleteSlot() {
  log.debug("Entering deleteSlot().");
  var slot = Number(valueOf("sc_slot_number") || 2);
  var apdu = null;
  try {
    apdu = otp.programSlotApdu(slot, null,
        hexField("sc_slot_access_code", 0, "The access code"));
  } catch (e) {
    paneMessage("sc_otp_out", e.message);
    log.debug("Leaving deleteSlot(). " + e.message);
    return;
  }
  writeToKey("sc_otp_out", [otp.ccidSelectApdu(), apdu],
      "Delete OTP slot " + slot + "? Its secret is gone for good." +
      (slot === 1 ? SLOT1_WARNING : "")).then(function (result) {
    slotAfterWrite(result, "Deleted slot " + slot + ".");
  }).catch(function (e) {
    paneMessage("sc_otp_out", e.message);
  });
  log.debug("Leaving deleteSlot().");
}

function swapSlots() {
  log.debug("Entering swapSlots().");
  writeToKey("sc_otp_out", [otp.ccidSelectApdu(), otp.swapSlotsApdu()],
      "Swap OTP slots 1 and 2? A short touch will then give what a long " +
      "touch gives now, and the other way round.").then(function (result) {
    slotAfterWrite(result, "Swapped slots 1 and 2.");
  }).catch(function (e) {
    paneMessage("sc_otp_out", e.message);
  });
  log.debug("Leaving swapSlots().");
}

// After a read, offer the account names for Delete.
function offerOathNames(rows) {
  log.debug("Entering offerOathNames().");
  var list = document.getElementById("sc_oath_names");
  if (!list) {
    log.debug("Leaving offerOathNames(). No list.");
    return;
  }
  list.innerHTML = "";
  rows.forEach(function (row) {
    var name = String(row.label || "").trim();
    if (/^    /.test(row.label) && /^(TOTP|HOTP)\b/.test(row.value)) {
      var option = document.createElement("option");
      option.value = name;
      list.appendChild(option);
    }
  });
  log.debug("Leaving offerOathNames().");
}

// ---------------------------------------------------------------------------
// IS A KEY THERE? The bar at the top of the page, green or red, for the
// transport chosen: the api's readers, or the devices this page holds over
// WebHID. Asked every few seconds while the tab is visible, and at once when
// the transport changes or a HID device comes or goes. It never prompts:
// getDevices() returns only what the person already granted.
// ---------------------------------------------------------------------------
var DETECT_EVERY_MS = 5000;
var detectTimer = null;

function showDetected(ok, text) {
  log.debug("Entering showDetected().");
  var bar = document.getElementById("sc_detect");
  if (bar) {
    bar.className = "sc-detect " + (ok ? "sc-detect-ok" : "sc-detect-no");
    bar.textContent = (ok ? "\u25cf " : "\u25cb ") + text;
  }
  log.debug("Leaving showDetected(). " + ok);
}

function isYubiKeyName(name) {
  log.debug("Entering isYubiKeyName().");
  var yes = /yubikey|yubico/i.test(String(name || ""));
  log.debug("Leaving isYubiKeyName(). " + yes);
  return yes;
}

function detectOverApi() {
  log.debug("Entering detectOverApi().");
  var problem = relayProblem();
  if (problem && (relay.known || !backendAvailable())) {
    showDetected(false, "No key reachable through the API: " + problem);
    log.debug("Leaving detectOverApi(). " + problem);
    return Promise.resolve();
  }
  var checked = fetch(apiBase() + "/smartcard/readers").then(function (res) {
    return res.json().then(function (body) {
      if (!res.ok) {
        showDetected(false, "No key reachable through the API: " +
            (body.error || res.status));
        return;
      }
      var names = body.readers || [];
      var keys = names.filter(isYubiKeyName);
      if (keys.length > 0) {
        showDetected(true, "Key detected through the API: " + keys[0] +
            (keys.length > 1 ? " (+" + (keys.length - 1) + " more)" : ""));
      } else if (names.length > 0) {
        showDetected(false, "The API sees " + names.length + " reader(s), " +
            "none of them a YubiKey: " + names.join(", "));
      } else {
        showDetected(false, "No key detected through the API: it sees no " +
            "reader. Is the key plugged in, and is pcscd running?");
      }
    });
  }).catch(function (e) {
    showDetected(false, "The API cannot be reached (" + e.message + "). " +
        "Has this browser accepted its certificate?");
  });
  log.debug("Leaving detectOverApi().");
  return checked;
}

function detectInBrowser() {
  log.debug("Entering detectInBrowser().");
  if (!hasWebHid()) {
    showDetected(false, "This browser cannot see a key: it has no WebHID. " +
        "A typed OTP still works; choose the API for everything else.");
    log.debug("Leaving detectInBrowser(). No WebHID.");
    return Promise.resolve();
  }
  var checked = navigator.hid.getDevices().then(function (devices) {
    var keys = (devices || []).filter(function (d) {
      return d.vendorId === 0x1050;
    });
    if (keys.length > 0) {
      showDetected(true, "Key detected in this browser (WebHID): " +
          (keys[0].productName || "YubiKey"));
    } else {
      showDetected(false, "No key granted to this page yet. Send challenge " +
          "on the Reader pane asks for one; a typed OTP needs no permission.");
    }
  }).catch(function (e) {
    showDetected(false, "WebHID refused to list devices: " + e.message);
  });
  log.debug("Leaving detectInBrowser().");
  return checked;
}

function detectKey() {
  log.debug("Entering detectKey().");
  if (typeof document !== "undefined" && document.hidden) {
    log.debug("Leaving detectKey(). Tab hidden.");
    return;
  }
  if (transport() === "api") {
    detectOverApi();
  } else {
    detectInBrowser();
  }
  log.debug("Leaving detectKey().");
}

function startDetecting() {
  log.debug("Entering startDetecting().");
  detectKey();
  if (detectTimer === null && typeof setInterval === "function") {
    detectTimer = setInterval(detectKey, DETECT_EVERY_MS);
  }
  if (hasWebHid()) {
    navigator.hid.addEventListener("connect", detectKey);
    navigator.hid.addEventListener("disconnect", detectKey);
  }
  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", detectKey);
  }
  log.debug("Leaving startDetecting().");
}

function readerLimits() {
  log.debug("Entering readerLimits().");
  fetch(apiBase() + "/smartcard/limits")
    .then(function (res) {
      return res.json();
    })
    .then(function (body) {
      var on = !!(body && body.enabled);
      relay.known = true;
      relay.enabled = on;
      relay.available = !!(body && body.available);
      relay.reason = (body && body.reason) || "";
      show("sc_reader_disabled", !on);
      show("sc_readers_button", on);
      show("sc_transmit_button", on);
      describeTransport();
      detectKey();
      var missing = document.getElementById("sc_reader_unavailable");
      if (missing) {
        missing.textContent = on && !relay.available ? relay.reason : "";
        show("sc_reader_unavailable", on && !relay.available);
      }
    })
    .catch(function (e) {
      log.warn("GET /smartcard/limits failed: " + e.message);
    });
  log.debug("Leaving readerLimits().");
}

function onload() {
  log.debug("Entering onload().");
  var live = backendAvailable();
  show("sc_backend_notice", !live);
  show("sc_verify_button", live);
  // The reader buttons wait for /smartcard/limits: the relay is off
  // unless the api's smartcardReaderEnabled is true.
  show("sc_readers_button", false);
  show("sc_transmit_button", false);
  if (live) {
    readerLimits();
  }
  restoreSecret(SAVE.otp[0], SAVE.otp[1]);
  restoreSecret(SAVE.oath[0], SAVE.oath[1]);
  restoreSecret(SAVE.api[0], SAVE.api[1]);
  var picker = document.getElementById("sc_transport");
  if (picker) {
    var saved = storageGet(TRANSPORT_KEY);
    picker.value = saved === "browser" || saved === "api" ? saved :
        (hasWebHid() ? "browser" : "api");
  }
  describeTransport();
  startDetecting();
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", function () {
    onload();
  });
}

module.exports = {
  onTransportChange: onTransportChange,
  programSlot: programSlot,
  deleteSlot: deleteSlot,
  swapSlots: swapSlots,
  generateSlotSecrets: generateSlotSecrets,
  onSlotTypeChange: onSlotTypeChange,
  addOathAccount: addOathAccount,
  deleteOathAccount: deleteOathAccount,
  onOtpTyped: onOtpTyped,
  readFromKey: readFromKey,
  // Exported for tests/smartcard_engine.js, which holds every plan to
  // read-only instructions.
  readPlan: readPlan,
  // The collapsible panes and the collapse / expand all switch, shared with
  // the XACML and GNAP pages.
  togglePane: panes.togglePane,
  setAllPanes: panes.setAllPanes,
  onload: onload,
  showApplication: showApplication,
  onSaveChange: onSaveChange,
  decodeOtp: decodeOtp,
  verifyOtp: verifyOtp,
  calculateHotp: calculateHotp,
  calculateTotp: calculateTotp,
  decodeOathCommand: decodeOathCommand,
  decodeOathResponse: decodeOathResponse,
  decodePivCommand: decodePivCommand,
  decodePivResponse: decodePivResponse,
  decodePgpCommand: decodePgpCommand,
  decodePgpResponse: decodePgpResponse,
  decodeHsmCommand: decodeHsmCommand,
  decodeHsmResponse: decodeHsmResponse,
  buildVerify: buildVerify,
  listReaders: listReaders,
  transmitApdu: transmitApdu,
  sendHid: sendHid
};
