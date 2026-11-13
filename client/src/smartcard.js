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
        showCertificate(der, described.rows);
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
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80,
    data: Buffer.from(pin, "utf8"), le: null
  });
  var box = document.getElementById("sc_reader_apdu");
  var pinBox = document.getElementById("sc_pin");
  if (box) {
    box.value = iso.toHex(apdu);
  }
  if (pinBox) {
    pinBox.value = "";
  }
  setStatus("VERIFY APDU built. The PIN is not stored.");
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

var HID_POLL_MS = 20;
var HID_TOUCH_POLL_MS = 100;
var HID_WRITE_TRIES = 20;
var HID_DEADLINE_MS = 15000;

function delay(ms) {
  log.debug("Entering delay().");
  log.debug("Leaving delay().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function hidRead(device) {
  log.debug("Entering hidRead().");
  log.debug("Leaving hidRead().");
  return device.receiveFeatureReport(0).then(function (view) {
    return otp.hidReportBytes(view);
  });
}

// Wait for the key to take the previous report, then write this one.
function hidWrite(device, report) {
  log.debug("Entering hidWrite().");
  var tries = 0;
  function attempt() {
    return hidRead(device).then(function (status) {
      if (otp.hidCanWrite(status)) {
        return device.sendFeatureReport(0, report);
      }
      tries += 1;
      if (tries >= HID_WRITE_TRIES) {
        throw new Error("The key did not take the report.");
      }
      return delay(50).then(attempt);
    });
  }
  log.debug("Leaving hidWrite().");
  return attempt();
}

// Poll until the response frame is complete, the key gives up, or the
// deadline passes. A touch-wait is reported once on the status line.
function hidCollect(device) {
  log.debug("Entering hidCollect().");
  var state = { seq: 0, data: [] };
  var started = Date.now();
  var told = false;
  function poll() {
    if (Date.now() - started > HID_DEADLINE_MS) {
      throw new Error("No response from the key within " +
          (HID_DEADLINE_MS / 1000) + " seconds.");
    }
    return hidRead(device).then(function (report) {
      var step = otp.hidReadStep(state, report);
      if (step.kind === "done") {
        return device.sendFeatureReport(0, otp.hidResetReport())
          .then(function () {
            return Buffer.from(state.data);
          });
      }
      if (step.kind === "status") {
        throw new Error("The key answered with no response. Is the " +
            "slot configured for challenge-response?");
      }
      if (step.kind === "touch" && !told) {
        told = true;
        setStatus("Touch the key.");
      }
      if (step.kind === "data") {
        return poll();
      }
      return delay(step.kind === "touch" ? HID_TOUCH_POLL_MS :
          HID_POLL_MS).then(poll);
    });
  }
  log.debug("Leaving hidCollect().");
  return poll();
}

function sendHid() {
  log.debug("Entering sendHid().");
  if (typeof navigator === "undefined" || !navigator.hid) {
    setStatus("This browser has no WebHID.");
    log.debug("Leaving sendHid(). No WebHID.");
    return;
  }
  var slot = parseInt(valueOf("sc_hid_slot"), 16);
  var frame = null;
  try {
    frame = otp.hidFrame(slot, hidBytes(valueOf("sc_hid_challenge")));
  } catch (e) {
    setStatus(e.message);
    log.debug("Leaving sendHid(). Frame.");
    return;
  }
  var reports = otp.hidReports(frame);
  navigator.hid.requestDevice({
    filters: [{ vendorId: 0x1050, usagePage: 0xf1d0 }]
  }).then(function (devices) {
    if (!devices || devices.length === 0) {
      setStatus("No OTP HID device was chosen.");
      return null;
    }
    var device = devices[0];
    var opened = device.opened ? Promise.resolve() : device.open();
    return opened.then(function () {
      var chain = Promise.resolve();
      reports.forEach(function (report) {
        chain = chain.then(function () {
          return hidWrite(device, report);
        });
      });
      return chain.then(function () {
        return hidCollect(device);
      });
    });
  }).then(function (raw) {
    if (!raw) {
      return;
    }
    var response = otp.hidResponse(slot, raw);
    render("sc_reader_out", [
      { label: "Response", value: iso.toHex(response) },
      { label: "Frame read", value: iso.toHex(raw) }
    ]);
    setStatus("HID response, " + response.length + " bytes, CRC good");
  }).catch(function (e) {
    setStatus(e.message);
  });
  log.debug("Leaving sendHid().");
}

function readerLimits() {
  log.debug("Entering readerLimits().");
  fetch(apiBase() + "/smartcard/limits")
    .then(function (res) {
      return res.json();
    })
    .then(function (body) {
      var on = !!(body && body.enabled);
      show("sc_reader_disabled", !on);
      show("sc_readers_button", on);
      show("sc_transmit_button", on);
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
  var note = document.getElementById("sc_hid_note");
  if (note && (typeof navigator === "undefined" || !navigator.hid)) {
    note.textContent = "This browser has no WebHID. The keyboard " +
        "OTP field still works.";
  }
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", function () {
    onload();
  });
}

module.exports = {
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
