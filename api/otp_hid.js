// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: otp_hid.js
//
// ---------------------------------------------------------------------------
// OTP-SLOT CHALLENGE-RESPONSE OVER HID, FROM THE API — for a browser with no
// WebHID (Firefox).
//
// A YubiKey on USB answers challenge-response to its OTP slots on the HID
// keyboard interface and NOT on CCID: over USB CCID the CALCULATE command is
// refused with 6985, by yubikit as much as by this tree (checked on
// 2026-11-13), and only over NFC does the CCID route work. So the api speaks
// HID itself, through the optional `node-hid` module — hidapi on Linux
// (hidraw), macOS (IOKit) and Windows — exactly as ykman does.
//
// The exchange is client/src/yubico_otp.js's hidChallenge(), the same code
// the page runs over WebHID: this file only finds the device and turns
// node-hid's feature-report calls into the send/receive pair it drives.
//
// It needs a NATIVE api (api/native.js): in a container the key's hidraw
// node is neither present nor permitted to the container's user, and
// yubico_otp.js — which needs the client's packages — is not in the image.
// Both are said in so many words rather than failing obscurely.
// ---------------------------------------------------------------------------

"use strict";

var path = require("path");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "otp_hid",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var YUBICO_VENDOR = 0x1050;

function loadHid() {
  log.debug("Entering loadHid().");
  var hid = null;
  try {
    hid = require(["node", "hid"].join("-"));
  } catch (e) {
    hid = null;
  }
  log.debug("Leaving loadHid(). " + !!hid);
  return hid;
}

// The OTP code: yubico_otp.js beside this file (never, today) or in the
// checkout this api runs from.
function loadOtp() {
  log.debug("Entering loadOtp().");
  var candidates = [path.join(__dirname, "yubico_otp.js"),
                    path.join(__dirname, "..", "client", "src",
                              "yubico_otp.js")];
  var i = 0;
  for (i = 0; i < candidates.length; i++) {
    try {
      var mod = require(candidates[i]);
      log.debug("Leaving loadOtp(). " + candidates[i]);
      return mod;
    } catch (e) {
      log.debug("loadOtp(): " + candidates[i] + ": " + e.message);
    }
  }
  log.debug("Leaving loadOtp(). Not found.");
  return null;
}

// Whether HID can be used here, and if not, why — for /smartcard/limits.
function availability() {
  log.debug("Entering availability().");
  var out = { available: true, reason: null };
  if (!loadHid()) {
    out = { available: false, reason: "HID needs the node-hid module, " +
      "which this api does not have. Run the api natively (node " +
      "api/native.js --smartcard), where npm installs it." };
  } else if (!loadOtp()) {
    out = { available: false, reason: "HID needs client/src/yubico_otp.js " +
      "and the client's packages: run the api from a checkout with " +
      "`npm ci --prefix client` done." };
  }
  log.debug("Leaving availability(). " + out.available);
  return out;
}

// The key's OTP interface: the Yubico device whose collection is a
// keyboard (usage page 1, usage 6) — or, where hidapi does not report
// usages, interface 0, which is the OTP interface on every YubiKey.
function findOtpDevice(hid) {
  log.debug("Entering findOtpDevice().");
  var all = hid.devices().filter(function (d) {
    return d.vendorId === YUBICO_VENDOR;
  });
  var byUsage = all.filter(function (d) {
    return d.usagePage === 0x0001 && d.usage === 0x0006;
  });
  var found = byUsage[0] || all.filter(function (d) {
    return d.interface === 0;
  })[0] || null;
  log.debug("Leaving findOtpDevice(). " + (found ? found.path : "none"));
  return found;
}

// A feature report read through hidapi carries the report ID first when it
// is asked for nine bytes; the exchange wants the eight after it.
function eightBytes(data) {
  log.debug("Entering eightBytes().");
  var buf = Buffer.from(data || []);
  var out = buf.length === 9 ? buf.slice(1) : buf.slice(0, 8);
  log.debug("Leaving eightBytes().");
  return out;
}

// One challenge to slot 0x20/0x28/0x30/0x38. Resolves to
// { response: hex, raw: hex, device: product name }.
function challenge(slot, challengeBytes, opts) {
  log.debug("Entering challenge().");
  var o = opts || {};
  var hid = o.hid || loadHid();
  var otp = o.otp || loadOtp();
  var reason = !hid ? availability().reason :
      (!otp ? availability().reason : null);
  if (reason) {
    log.debug("Leaving challenge(). " + reason);
    return Promise.reject(new Error(reason));
  }
  var info = findOtpDevice(hid);
  if (!info) {
    log.debug("Leaving challenge(). No device.");
    return Promise.reject(new Error("No YubiKey OTP interface is " +
      "visible over HID. Is the key plugged in, and its OTP interface " +
      "enabled (ykman config usb)?"));
  }
  var device = null;
  try {
    device = new hid.HID(info.path);
  } catch (e) {
    log.debug("Leaving challenge(). Open failed.");
    return Promise.reject(new Error("The key's OTP interface could not " +
      "be opened (" + e.message + "). On Linux the user running the api " +
      "needs access to its hidraw node — the udev rules that come with " +
      "yubikey-manager grant it to the logged-in user."));
  }
  var wrapper = {
    send: function (report) {
      return Promise.resolve().then(function () {
        device.sendFeatureReport([0].concat(Array.from(report)));
      });
    },
    receive: function () {
      return Promise.resolve().then(function () {
        return eightBytes(device.getFeatureReport(0, 9));
      });
    }
  };
  var answered = otp.hidChallenge(wrapper, slot, challengeBytes,
      { variable: o.variable !== false }).then(function (got) {
    return { response: got.response.toString("hex"),
             raw: got.raw.toString("hex"),
             device: info.product || "YubiKey" };
  });
  var closed = answered.then(function (value) {
    device.close();
    return value;
  }, function (e) {
    try {
      device.close();
    } catch (ignored) {
      log.debug("challenge(): close after failure: " + ignored.message);
    }
    throw e;
  });
  log.debug("Leaving challenge(). Sent.");
  return closed;
}

// The request body: { slot: "38", challenge: "hex", variable: true }.
function describeChallenge(body) {
  log.debug("Entering describeChallenge().");
  var b = body || {};
  var slot = parseInt(String(b.slot || ""), 16);
  if ([0x20, 0x28, 0x30, 0x38].indexOf(slot) < 0) {
    log.debug("Leaving describeChallenge(). Bad slot.");
    return { ok: false, error: "The slot is 20, 28, 30 or 38." };
  }
  var hex = String(b.challenge || "").replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 ||
      hex.length > 128) {
    log.debug("Leaving describeChallenge(). Bad challenge.");
    return { ok: false, error: "The challenge is up to 64 bytes of hex." };
  }
  log.debug("Leaving describeChallenge().");
  return { ok: true, slot: slot, challenge: Buffer.from(hex, "hex"),
           variable: b.variable !== false && b.variable !== "false" };
}

module.exports = {
  availability: availability,
  findOtpDevice: findOtpDevice,
  eightBytes: eightBytes,
  challenge: challenge,
  describeChallenge: describeChallenge
};
