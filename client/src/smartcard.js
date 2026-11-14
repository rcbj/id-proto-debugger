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

var PANES = ["otp", "oath", "piv", "pgp", "hsm", "reader", "reset"];
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
  if (app === "hsm" && /^9000$/.test(last.status || "") && !last.data &&
      apdus[apdus.length - 1].slice(2, 4) === "05") {
    summary = "no YubiHSM Auth credentials on this key (" + summary + ")";
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
  if (question !== null && typeof window !== "undefined" &&
      window.confirm && !window.confirm(question)) {
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

// ---------------------------------------------------------------------------
// YUBIHSM AUTH: add and delete credentials. Every write carries the
// applet's management key, and a wrong one costs one of its retries; the
// page never fills one in — "factory default" is a button the person
// presses, and a refusal is shown, never retried.
// ---------------------------------------------------------------------------
function hsmManagementKey() {
  log.debug("Entering hsmManagementKey().");
  var key = hexField("sc_hsm_mgmt_key", 16, "The management key");
  log.debug("Leaving hsmManagementKey().");
  return key;
}

function useHsmDefaultKey() {
  log.debug("Entering useHsmDefaultKey().");
  var field = document.getElementById("sc_hsm_mgmt_key");
  if (field) {
    field.value = "00000000000000000000000000000000";
  }
  setStatus("The factory management key: 16 zero bytes.");
  log.debug("Leaving useHsmDefaultKey().");
}

function onHsmTypeChange() {
  log.debug("Entering onHsmTypeChange().");
  var type = valueOf("sc_hsm_add_type");
  show("sc_hsm_add_derived", type === "derived");
  show("sc_hsm_add_keys", type === "keys");
  show("sc_hsm_add_ec", type === "ec");
  log.debug("Leaving onHsmTypeChange().");
}

function hsmRefused(result) {
  log.debug("Entering hsmRefused().");
  var sw = parseInt(result.status, 16);
  var why = "The key refused it: " + result.status + " " + result.name;
  if ((sw & 0xfff0) === 0x63c0) {
    why = "The management key is wrong; " + (sw & 0x0f) + " tries remain " +
        "before the applet locks. Nothing was written, and the page will " +
        "not try again on its own.";
  } else if (sw === 0x6983) {
    why = "The management key is blocked: no tries remain.";
  } else if (sw === 0x6a84) {
    why = "The applet is full: delete a credential first.";
  }
  paneMessage("sc_hsm_out", why);
  log.debug("Leaving hsmRefused().");
}

function addHsmCredential() {
  log.debug("Entering addHsmCredential().");
  var type = valueOf("sc_hsm_add_type");
  var label = valueOf("sc_hsm_add_label").trim();
  var apdu = null;
  try {
    var opts = {
      managementKey: hsmManagementKey(),
      label: label,
      algorithm: type === "ec" ? hsm.EC_P256 : hsm.AES128,
      credentialPassword: valueOf("sc_hsm_add_password"),
      touch: checked("sc_hsm_add_touch")
    };
    if (type === "derived") {
      opts.derivationPassword = valueOf("sc_hsm_add_derivation");
    } else if (type === "keys") {
      opts.keyEnc = hexField("sc_hsm_add_enc", 16, "The encryption key");
      opts.keyMac = hexField("sc_hsm_add_mac", 16, "The MAC key");
    } else {
      opts.privateKey = hexField("sc_hsm_add_ec_key", 32,
          "The P-256 private key");
    }
    apdu = hsm.putApdu(opts).toString("hex");
  } catch (e) {
    paneMessage("sc_hsm_out", e.message);
    log.debug("Leaving addHsmCredential(). " + e.message);
    return;
  }
  writeToKey("sc_hsm_out", [hsm.selectApdu().toString("hex"), apdu],
      "Write the YubiHSM Auth credential \"" + label + "\" (" +
      { derived: "AES-128, derived from a password",
        keys: "AES-128, from the keys given",
        ec: "EC P-256" }[type] +
      (checked("sc_hsm_add_touch") ? ", touch required" : "") +
      ") to the key?\n\nIt uses the management key you entered; a wrong " +
      "one costs one of its retries.").then(function (result) {
    if (!result) {
      return;
    }
    if (!result.ok) {
      hsmRefused(result);
      return;
    }
    setStatus("Added " + label + ".");
    readFromKey("hsm");
  }).catch(function (e) {
    paneMessage("sc_hsm_out", e.message);
  });
  log.debug("Leaving addHsmCredential().");
}

function deleteHsmCredential() {
  log.debug("Entering deleteHsmCredential().");
  var label = valueOf("sc_hsm_del_label").trim();
  var apdu = null;
  try {
    apdu = hsm.deleteApdu(hsmManagementKey(), label).toString("hex");
  } catch (e) {
    paneMessage("sc_hsm_out", e.message);
    log.debug("Leaving deleteHsmCredential(). " + e.message);
    return;
  }
  writeToKey("sc_hsm_out", [hsm.selectApdu().toString("hex"), apdu],
      "Delete the YubiHSM Auth credential \"" + label + "\" from the " +
      "key? Its keys are gone for good.").then(function (result) {
    if (!result) {
      return;
    }
    if (!result.ok) {
      hsmRefused(result);
      return;
    }
    setStatus("Deleted " + label + ".");
    readFromKey("hsm");
  }).catch(function (e) {
    paneMessage("sc_hsm_out", e.message);
  });
  log.debug("Leaving deleteHsmCredential().");
}

// ---------------------------------------------------------------------------
// What a refusal means, for the PIN and key writes.
// ---------------------------------------------------------------------------
function refusalText(status, what) {
  log.debug("Entering refusalText().");
  var sw = parseInt(status, 16);
  var text = "The key refused it: " + status + " " + iso.statusName(sw) + ".";
  if ((sw & 0xfff0) === 0x63c0) {
    text = (what || "The PIN") + " is wrong: " + (sw & 0x0f) + " tries " +
        "remain before it blocks. The page will not try again on its own.";
  } else if (sw === 0x6983) {
    text = (what || "The PIN") + " is blocked: no tries remain.";
  } else if (sw === 0x6982) {
    text = "Not authorised: the PIN or key was not accepted first.";
  } else if (sw === 0x6d00 || sw === 0x6e00) {
    text = "This key's firmware does not have that command (" + status +
        ").";
  }
  log.debug("Leaving refusalText().");
  return text;
}

// ---------------------------------------------------------------------------
// PIV: writes under the card management key run in a relay session —
// authenticate, then the command, then close, which resets the card.
// ---------------------------------------------------------------------------
function postJson(route, body) {
  log.debug("Entering postJson(). " + route);
  var sent = fetch(apiBase() + route, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(function (res) {
    return res.json().then(function (answer) {
      if (!res.ok) {
        throw new Error(answer.error || (route + " answered " + res.status));
      }
      return answer;
    });
  });
  log.debug("Leaving postJson().");
  return sent;
}

// Open a session, run `work(transmit)`, and close the session whatever
// happens. transmit(apdusHex) resolves to the last result.
function withPivSession(work) {
  log.debug("Entering withPivSession().");
  var id = null;
  var transmit = function (apdus) {
    return postJson("/smartcard/session/transmit", { id: id, apdus: apdus,
                                                     getResponse: true })
      .then(function (body) {
        var results = body.results || [body];
        var last = results[results.length - 1] || {};
        last.complete = results.length === apdus.length;
        return last;
      });
  };
  var done = chosenReader().then(function (reader) {
    return postJson("/smartcard/session", { reader: reader });
  }).then(function (opened) {
    id = opened.id;
    return work(transmit);
  });
  var closed = done.then(function (value) {
    return postJson("/smartcard/session/close", { id: id }).then(function () {
      return value;
    });
  }, function (e) {
    var close = id ? postJson("/smartcard/session/close", { id: id })
      .catch(function () {
        return null;
      }) : Promise.resolve();
    return close.then(function () {
      throw e;
    });
  });
  log.debug("Leaving withPivSession().");
  return closed;
}

// SELECT PIV, learn the management key's algorithm (GET METADATA; the
// form's choice where the firmware has none), and authenticate.
function pivAuthenticate(transmit) {
  log.debug("Entering pivAuthenticate().");
  var key = hexField("sc_piv_mgm_key", null, "The management key");
  if (!key || key.length === 0) {
    throw new Error("Enter the management key (or press Factory default).");
  }
  var alg = null;
  var authed = transmit([selectHex(piv.PIV_AID),
                         piv.metadataApdu(0x9b).toString("hex")])
    .then(function (meta) {
      alg = meta.complete && /^9000$/i.test(meta.status) ?
          piv.managementAlgorithmFromMetadata(Buffer.from(meta.data, "hex")) :
          null;
      alg = alg || valueOf("sc_piv_mgm_alg") || "3des";
      return transmit([piv.authWitnessApdu(alg).toString("hex")]);
    }).then(function (first) {
      if (!/^9000$/i.test(first.status)) {
        throw new Error("The key would not start authentication: " +
            refusalText(first.status, "The management key"));
      }
      var step = piv.authResponseApdu(alg, key, Buffer.from(first.data, "hex"),
          randomBytes(piv.MGM_ALGORITHMS[alg].block));
      return transmit([step.apdu.toString("hex")]).then(function (second) {
        if (!/^9000$/i.test(second.status) ||
            !piv.authCardProven(Buffer.from(second.data, "hex"),
                                step.expected)) {
          throw new Error("The management key is wrong (" + second.status +
              "). Nothing was changed.");
        }
        return alg;
      });
    });
  log.debug("Leaving pivAuthenticate().");
  return authed;
}

function pivSlot() {
  log.debug("Entering pivSlot().");
  var slot = parseInt(valueOf("sc_piv_slot") || "9a", 16);
  log.debug("Leaving pivSlot().");
  return slot;
}

// One management-key write: confirm, authenticate, send, report.
function pivManaged(question, apduFn, after) {
  log.debug("Entering pivManaged().");
  var out = "sc_piv_out";
  if (transport() !== "api" || relayProblem()) {
    paneMessage(out, transport() !== "api" ? "Writing to the key needs " +
        "the API. Set \"Talk to the key through\" to the API." :
        relayProblem());
    log.debug("Leaving pivManaged(). No relay.");
    return;
  }
  var apdu = null;
  try {
    apdu = apduFn();
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving pivManaged(). " + e.message);
    return;
  }
  if (window.confirm && !window.confirm(question)) {
    setStatus("Nothing was written.");
    log.debug("Leaving pivManaged(). Declined.");
    return;
  }
  setStatus("Authenticating with the management key…");
  withPivSession(function (transmit) {
    return pivAuthenticate(transmit).then(function () {
      return transmit([Buffer.isBuffer(apdu) ? apdu.toString("hex") : apdu]);
    });
  }).then(function (result) {
    if (!/^90/.test(result.status)) {
      paneMessage(out, refusalText(result.status));
      return;
    }
    after(result);
  }).catch(function (e) {
    paneMessage(out, e.message);
  });
  log.debug("Leaving pivManaged(). Sent.");
}

function usePivDefaultKey() {
  log.debug("Entering usePivDefaultKey().");
  var field = document.getElementById("sc_piv_mgm_key");
  if (field) {
    field.value = piv.DEFAULT_MANAGEMENT_KEY;
  }
  setStatus("The factory management key: 010203…0708, three times.");
  log.debug("Leaving usePivDefaultKey().");
}

function pivGenerate() {
  log.debug("Entering pivGenerate().");
  var slot = pivSlot();
  var alg = valueOf("sc_piv_gen_alg");
  pivManaged("Generate a new " + alg.toUpperCase() + " key in PIV slot " +
      slot.toString(16).toUpperCase() + "?\n\nA key already in the slot " +
      "is replaced and cannot be recovered.", function () {
    return piv.generateApdu(slot, alg, Number(valueOf("sc_piv_gen_pin")),
                            Number(valueOf("sc_piv_gen_touch")));
  }, function (result) {
    var spki = piv.generatedPublicKey(Buffer.from(result.data, "hex"), alg);
    var pem = bytes.derToPem(spki, "PUBLIC KEY");
    render("sc_piv_out", [{ label: "Generated", value: alg.toUpperCase() +
        " in slot " + slot.toString(16).toUpperCase() },
        { label: "Public key", value: pem }]);
    setStatus("Generated a key in slot " + slot.toString(16).toUpperCase() +
        ". Import a certificate for it to use it with most software.");
  });
  log.debug("Leaving pivGenerate().");
}

function pivImportCertificate() {
  log.debug("Entering pivImportCertificate().");
  var slot = pivSlot();
  pivManaged("Store this certificate in PIV slot " +
      slot.toString(16).toUpperCase() + "? A certificate already there is " +
      "replaced.", function () {
    var pem = valueOf("sc_piv_cert_pem");
    if (!/BEGIN CERTIFICATE/.test(pem)) {
      throw new Error("Paste a PEM certificate (-----BEGIN CERTIFICATE-----).");
    }
    return piv.putCertificateApdu(slot, Buffer.from(bytes.pemToDer(pem)));
  }, function () {
    setStatus("Stored the certificate.");
    readFromKey("piv");
  });
  log.debug("Leaving pivImportCertificate().");
}

function pivDeleteCertificate() {
  log.debug("Entering pivDeleteCertificate().");
  var slot = pivSlot();
  pivManaged("Delete the certificate in PIV slot " +
      slot.toString(16).toUpperCase() + "? The key stays.", function () {
    return piv.putCertificateApdu(slot, null);
  }, function () {
    setStatus("Deleted the certificate.");
    readFromKey("piv");
  });
  log.debug("Leaving pivDeleteCertificate().");
}

function pivDeleteKey() {
  log.debug("Entering pivDeleteKey().");
  var slot = pivSlot();
  pivManaged("Delete the KEY in PIV slot " + slot.toString(16).toUpperCase() +
      "? It cannot be recovered. (Firmware 5.7 and later.)", function () {
    return piv.deleteKeyApdu(slot);
  }, function () {
    setStatus("Deleted the key.");
    readFromKey("piv");
  });
  log.debug("Leaving pivDeleteKey().");
}

function pivSetManagementKey() {
  log.debug("Entering pivSetManagementKey().");
  var alg = valueOf("sc_piv_new_mgm_alg");
  pivManaged("Change the PIV management key to the new " +
      alg.toUpperCase() + " key?\n\nKeep it: without it, no key or " +
      "certificate on this applet can be changed, short of a reset.",
      function () {
    return piv.setManagementKeyApdu(alg, hexField("sc_piv_new_mgm_key",
        piv.MGM_ALGORITHMS[alg].keyLen, "The new management key"),
        checked("sc_piv_new_mgm_touch"));
  }, function () {
    setStatus("Changed the management key.");
    render("sc_piv_out", [{ label: "Management key", value: "changed to " +
        alg.toUpperCase() }]);
  });
  log.debug("Leaving pivSetManagementKey().");
}

// PIN and PUK changes need no management key: one sequence.
function pivPinWrite(kind) {
  log.debug("Entering pivPinWrite(). " + kind);
  var out = "sc_piv_out";
  var apdu = null;
  var what = kind === "puk" ? "The PUK" : "The PIN";
  var question = "";
  try {
    if (kind === "pin") {
      apdu = piv.changeReferenceApdu(0x80, valueOf("sc_piv_pin_old"),
          valueOf("sc_piv_pin_new"));
      question = "Change the PIV PIN?";
    } else if (kind === "puk") {
      apdu = piv.changeReferenceApdu(0x81, valueOf("sc_piv_puk_old"),
          valueOf("sc_piv_puk_new"));
      question = "Change the PIV PUK?";
    } else {
      apdu = piv.unblockPinApdu(valueOf("sc_piv_puk_old"),
          valueOf("sc_piv_pin_new"));
      question = "Unblock the PIV PIN with the PUK, setting the new PIN?";
      what = "The PUK";
    }
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving pivPinWrite(). " + e.message);
    return;
  }
  writeToKey(out, [selectHex(piv.PIV_AID), apdu.toString("hex")], question +
      "\n\nA wrong current value costs one of its tries.")
    .then(function (result) {
      if (!result) {
        return;
      }
      if (!result.ok) {
        paneMessage(out, result.status === "6985" ? "The key refused the " +
            "NEW value (6985). This key enforces PIN complexity: no " +
            "sequences such as 123456 or 654321, and no repeated digits. " +
            "The current value was right and no try was used." :
            refusalText(result.status, what));
        return;
      }
      render(out, [{ label: "Done", value: question.replace(/\?.*$/, "") }]);
      setStatus("Done.");
    }).catch(function (e) {
      paneMessage(out, e.message);
    });
  log.debug("Leaving pivPinWrite().");
}

// ---------------------------------------------------------------------------
// OPENPGP CARD: every write is SELECT, VERIFY the Admin PIN, then the change.
// ---------------------------------------------------------------------------
function useOpenPgpDefaultAdminPin() {
  log.debug("Entering useOpenPgpDefaultAdminPin().");
  var field = document.getElementById("sc_pgp_admin_pin");
  if (field) {
    field.value = "12345678";
  }
  setStatus("The factory Admin PIN: 12345678.");
  log.debug("Leaving useOpenPgpDefaultAdminPin().");
}

function pgpAdminWrite(commands, question, after) {
  log.debug("Entering pgpAdminWrite().");
  var out = "sc_pgp_out";
  var apdus = null;
  try {
    apdus = [selectHex(pgp.AID_PREFIX),
             pgp.verifyApdu(pgp.PW3, valueOf("sc_pgp_admin_pin"))
               .toString("hex")]
      .concat(commands().map(function (c) {
        return Buffer.isBuffer(c) ? c.toString("hex") : c;
      }));
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving pgpAdminWrite(). " + e.message);
    return Promise.resolve(null);
  }
  var written = writeToKey(out, apdus, question === null ? null : question +
      "\n\nThe Admin PIN is checked first; three wrong tries block it.")
    .then(function (result) {
      if (!result) {
        return null;
      }
      if (!result.ok) {
        paneMessage(out, refusalText(result.status, "The Admin PIN"));
        return null;
      }
      return after ? after(result) : result;
    }).catch(function (e) {
      // A failure before the card answered — no reader, the api out of
      // reach — said in the pane; until 2026-11-14 it was swallowed and
      // the status line read "Writing to the key…" for good.
      paneMessage(out, e.message);
      return null;
    });
  log.debug("Leaving pgpAdminWrite().");
  return written;
}

function pgpSaveCardholder() {
  log.debug("Entering pgpSaveCardholder().");
  var fields = [["sc_pgp_name", 0x5b], ["sc_pgp_login", 0x5e],
                ["sc_pgp_url", 0x5f50], ["sc_pgp_lang", 0x5f2d]];
  var filled = fields.filter(function (f) {
    return valueOf(f[0]).trim() !== "";
  });
  if (filled.length === 0) {
    paneMessage("sc_pgp_out", "Fill in at least one of name, login, URL " +
        "or language.");
    log.debug("Leaving pgpSaveCardholder(). Nothing to write.");
    return;
  }
  pgpAdminWrite(function () {
    return filled.map(function (f) {
      return pgp.putDataApdu(f[1], Buffer.from(valueOf(f[0]).trim(), "utf8"));
    });
  }, "Write the cardholder data to the OpenPGP card?", function () {
    setStatus("Saved the cardholder data.");
    readFromKey("pgp");
  });
  log.debug("Leaving pgpSaveCardholder().");
}

function pgpGenerate() {
  log.debug("Entering pgpGenerate().");
  var which = valueOf("sc_pgp_gen_key");
  var alg = valueOf("sc_pgp_gen_alg");
  var names = { sig: "signature", dec: "decryption", aut: "authentication" };
  var created = Math.floor(Date.now() / 1000);
  var fpr = null;
  pgpAdminWrite(function () {
    return [pgp.algorithmAttributesApdu(which, alg), pgp.generateApdu(which)];
  }, "Generate a new " + alg + " " + names[which] + " key on the OpenPGP " +
      "card?\n\nThe key now in that slot is destroyed, and anything " +
      "encrypted to it can no longer be decrypted.", function (result) {
    var answer = Buffer.from(result.data, "hex");
    fpr = pgp.v4Fingerprint(alg, answer, created);
    var found = {};
    var tmpl = iso.parseElements(answer).filter(function (node) {
      return node.tag === 0x7f49;
    })[0];
    (tmpl ? iso.parseElements(tmpl.value) : []).forEach(function (node) {
      if (node.tag === 0x81) {
        found.modulus = node.value;
      } else if (node.tag === 0x82) {
        found.exponent = node.value;
      } else if (node.tag === 0x86) {
        found.point = node.value;
      }
    });
    found.curve = alg === "ed25519" ? "Ed25519" :
        (alg === "cv25519" ? "X25519" : null);
    var pem = null;
    try {
      pem = pgp.publicKeyPem(found);
    } catch (e) {
      pem = null;
    }
    // The fingerprint and creation time, so GnuPG recognises the key.
    return pgpAdminWrite(function () {
      return [pgp.putDataApdu(pgp.KEY_REFS[which].fpr, fpr.fingerprint),
              pgp.putDataApdu(pgp.KEY_REFS[which].time, fpr.created)];
    }, null, function () {
      render("sc_pgp_out", [
        { label: "Generated", value: alg + " " + names[which] + " key" },
        { label: "Fingerprint", value: fpr.fingerprint.toString("hex")
            .toUpperCase().replace(/(.{4})/g, "$1 ").trim() },
        { label: "Created", value: new Date(created * 1000).toISOString() },
        { label: "Public key", value: pem || "(read the key to see it)" },
        { label: "Next", value: "In GnuPG: gpg --card-edit, then fetch or " +
            "generate a public key from the card's keys." }]);
      setStatus("Generated the " + names[which] + " key.");
      return true;
    });
  });
  log.debug("Leaving pgpGenerate().");
}

function pgpSetTouch() {
  log.debug("Entering pgpSetTouch().");
  var which = valueOf("sc_pgp_touch_key");
  var policy = Number(valueOf("sc_pgp_touch_policy"));
  pgpAdminWrite(function () {
    return [pgp.touchPolicyApdu(which, policy)];
  }, "Set the touch policy of the " + which + " key to " +
      ["off", "on", "fixed", "cached", "cached-fixed"][policy] + "?" +
      (policy === 2 || policy === 4 ? "\n\nFIXED cannot be turned off " +
      "again without resetting the OpenPGP applet." : ""), function () {
    setStatus("Set the touch policy.");
    readFromKey("pgp");
  });
  log.debug("Leaving pgpSetTouch().");
}

function pgpChangePin(kind) {
  log.debug("Entering pgpChangePin(). " + kind);
  var out = "sc_pgp_out";
  var admin = kind === "admin";
  var apdu = null;
  try {
    apdu = pgp.changePinApdu(admin ? pgp.PW3 : pgp.PW1,
        valueOf(admin ? "sc_pgp_admin_old" : "sc_pgp_pin_old"),
        valueOf(admin ? "sc_pgp_admin_new" : "sc_pgp_pin_new"));
  } catch (e) {
    paneMessage(out, e.message);
    log.debug("Leaving pgpChangePin(). " + e.message);
    return;
  }
  writeToKey(out, [selectHex(pgp.AID_PREFIX), apdu.toString("hex")],
      "Change the OpenPGP " + (admin ? "Admin PIN" : "PIN") + "?\n\nA " +
      "wrong current value costs one of its three tries.")
    .then(function (result) {
      if (!result) {
        return;
      }
      if (!result.ok) {
        paneMessage(out, result.status === "6985" ? "The key refused the " +
            "NEW value (6985): it may enforce PIN complexity (no sequences " +
            "or repeated digits)." : refusalText(result.status, admin ?
            "The Admin PIN" : "The PIN"));
        return;
      }
      render(out, [{ label: "Done", value: "Changed the " +
          (admin ? "Admin PIN" : "PIN") }]);
      setStatus("Changed.");
    }).catch(function (e) {
      paneMessage(out, e.message);
    });
  log.debug("Leaving pgpChangePin().");
}

// ---------------------------------------------------------------------------
// GENERATE A SECRET for any field, in the format that field takes, from
// the browser's random source. The field is switched to plain text so the
// value can be copied: the key never gives a secret back.
// ---------------------------------------------------------------------------
var P256_ORDER = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

function randomPassword(length) {
  log.debug("Entering randomPassword().");
  // Letters and digits without the look-alikes 0/O, 1/l/I.
  var alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  var out = "";
  while (out.length < length) {
    var b = randomBytes(1)[0];
    if (b < 256 - (256 % alphabet.length)) {
      out += alphabet[b % alphabet.length];
    }
  }
  log.debug("Leaving randomPassword().");
  return out;
}

function randomP256Scalar() {
  log.debug("Entering randomP256Scalar().");
  var hex = null;
  do {
    hex = randomBytes(32).toString("hex");
  } while (/^0+$/.test(hex) || hex >= P256_ORDER);
  log.debug("Leaving randomP256Scalar().");
  return hex;
}

function generateSecret(id, kind) {
  log.debug("Entering generateSecret(). " + id + " " + kind);
  var field = document.getElementById(id);
  if (!field) {
    log.debug("Leaving generateSecret(). No field.");
    return;
  }
  var value = "";
  // kind: "hex:N", "base32:N" (N random bytes), "password:N" (N
  // characters), "p256" (a private scalar), "pivmgm" (a key for the
  // chosen management-key algorithm).
  var m = /^(hex|base32|password):(\d+)$/.exec(kind || "");
  if (kind === "p256") {
    value = randomP256Scalar();
  } else if (kind === "pivmgm") {
    var alg = piv.MGM_ALGORITHMS[valueOf("sc_piv_new_mgm_alg") || "aes192"];
    value = randomBytes(alg.keyLen).toString("hex");
  } else if (m && m[1] === "hex") {
    value = randomBytes(Number(m[2])).toString("hex");
  } else if (m && m[1] === "base32") {
    value = oathBase32(randomBytes(Number(m[2])));
  } else if (m && m[1] === "password") {
    value = randomPassword(Number(m[2]));
  } else {
    log.debug("Leaving generateSecret(). Unknown kind.");
    return;
  }
  field.value = value;
  if (field.type === "password") {
    field.type = "text";
  }
  field.dispatchEvent(new Event("input", { bubbles: true }));
  setStatus("Generated. Copy it now: the key will not give it back.");
  log.debug("Leaving generateSecret().");
}

// ---------------------------------------------------------------------------
// RESET: wipe one application back to its factory state. Confirmed by
// typing "RESET <name>", never by a click alone. PIV and the OpenPGP card
// first block their PINs on purpose (the applets require it), which runs
// in a relay session; the others are one command.
// ---------------------------------------------------------------------------
var RESETS = {
  oath: { name: "OATH", what: "every OATH account and the applet's " +
      "password" },
  hsm: { name: "YUBIHSM AUTH", what: "every YubiHSM Auth credential; the " +
      "management key goes back to 16 zero bytes" },
  piv: { name: "PIV", what: "every PIV key and certificate; the PIN goes " +
      "back to 123456, the PUK to 12345678 and the management key to its " +
      "factory value" },
  pgp: { name: "OPENPGP", what: "all three OpenPGP keys and the cardholder " +
      "data; the PIN goes back to 123456 and the Admin PIN to 12345678" },
  otp: { name: "OTP", what: "both OTP slots, including slot 1's factory " +
      "Yubico OTP credential, which nothing can put back" }
};

function resetApplication(app) {
  log.debug("Entering resetApplication(). " + app);
  var out = "sc_reset_out";
  var spec = RESETS[app];
  if (!spec) {
    log.debug("Leaving resetApplication(). Unknown.");
    return;
  }
  if (transport() !== "api" || relayProblem()) {
    paneMessage(out, transport() !== "api" ? "Reset needs the API. Set " +
        "\"Talk to the key through\" to the API." : relayProblem());
    log.debug("Leaving resetApplication(). No relay.");
    return;
  }
  var typed = typeof window !== "undefined" && window.prompt ?
      window.prompt("This permanently erases " + spec.what + ".\n\n" +
          "Type RESET " + spec.name + " to go ahead.") : null;
  if (typed === null || typed.trim().toUpperCase() !==
      "RESET " + spec.name) {
    setStatus("Nothing was reset.");
    log.debug("Leaving resetApplication(). Not confirmed.");
    return;
  }
  setStatus("Resetting " + spec.name + "…");
  var done = null;
  if (app === "piv" || app === "pgp") {
    done = withPivSession(function (transmit) {
      return (app === "piv" ? piv : pgp).reset(transmit, function (text) {
        setStatus("Resetting " + spec.name + ": " + text);
      });
    }).then(function (tries) {
      return { ok: true, note: "blocked the PINs with " + tries +
          " deliberate wrong tries first, as the applet requires" };
    });
  } else {
    var apdus = {
      oath: [oath.selectApdu().toString("hex"),
             oath.resetApdu().toString("hex")],
      hsm: [hsm.selectApdu().toString("hex"), hsm.resetApdu().toString("hex")],
      otp: [otp.ccidSelectApdu(), otp.programSlotApdu(1, null),
            otp.programSlotApdu(2, null)]
    }[app];
    done = writeToKey(out, apdus, null).then(function (result) {
      if (!result) {
        return null;
      }
      if (!result.ok) {
        throw new Error(refusalText(result.status) +
            (app === "otp" && result.status === "6982" ? " A slot has an " +
            "access code: delete it on the Yubico OTP pane with the code." :
            ""));
      }
      return { ok: true, note: "" };
    });
  }
  done.then(function (r) {
    if (!r) {
      return;
    }
    render(out, [{ label: "Reset", value: spec.name + " is back to its " +
        "factory state" + (r.note ? "; " + r.note : "") + "." }]);
    setStatus("Reset " + spec.name + ".");
  }).catch(function (e) {
    paneMessage(out, e.message);
  });
  log.debug("Leaving resetApplication().");
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
  resetApplication: resetApplication,
  generateSecret: generateSecret,
  usePivDefaultKey: usePivDefaultKey,
  pivGenerate: pivGenerate,
  pivImportCertificate: pivImportCertificate,
  pivDeleteCertificate: pivDeleteCertificate,
  pivDeleteKey: pivDeleteKey,
  pivSetManagementKey: pivSetManagementKey,
  pivPinWrite: pivPinWrite,
  useOpenPgpDefaultAdminPin: useOpenPgpDefaultAdminPin,
  pgpSaveCardholder: pgpSaveCardholder,
  pgpGenerate: pgpGenerate,
  pgpSetTouch: pgpSetTouch,
  pgpChangePin: pgpChangePin,
  addHsmCredential: addHsmCredential,
  deleteHsmCredential: deleteHsmCredential,
  useHsmDefaultKey: useHsmDefaultKey,
  onHsmTypeChange: onHsmTypeChange,
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
