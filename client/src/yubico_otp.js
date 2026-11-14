// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: yubico_otp.js
//
// Yubico OTP. A token is modhex. The current form is 44 characters:
// 12 of public id and 32 of ciphertext. The older form is 32 to 48
// characters, and the last 32 are always the ciphertext. Anything else
// is refused by name.
//
// The ciphertext is one AES-128-ECB block. Web Crypto has no ECB, so
// the block is node-forge, which is the same implementation in the
// browser bundle and in node. A wrong key fails the CRC and is
// reported as a wrong key.
//
// Validation protocol 2.0 builds the request and reads the response.
// The live call is not made here: a browser cannot fetch YubiCloud,
// and POST /otp/verify is the api. The nonce is generated here and
// checked against the response.
//
// The HID frame is the OTP interface's 70-byte frame (64 bytes of
// payload, the slot, and the CRC). Challenge-response uses it. This
// file does not open a device.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "yubico_otp",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var forge = require("node-forge");
var hmacSha1 = require("@noble/hashes/hmac").hmac;
var sha1 = require("@noble/hashes/sha1").sha1;
var bytesLib = require("./crypto_bytes.js");

var MODHEX = "cbdefghijklnrtuv";
// ISO 13239 CRC, residual over a valid 16-byte block.
var CRC_RESIDUAL = 0xf0b8;
var NONCE_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// Yubico OTP challenge-response slots, and the HMAC-SHA1 ones beside
// them. The frame is the same; the slot byte is what the key reads.
var SLOT_OTP_1 = 0x20;
var SLOT_OTP_2 = 0x28;
var SLOT_HMAC_1 = 0x30;
var SLOT_HMAC_2 = 0x38;
var SLOT_DATA_SIZE = 64;
var FRAME_SIZE = 70;

var DEFAULT_HOSTS = [
  "api.yubico.com",
  "api2.yubico.com",
  "api3.yubico.com",
  "api4.yubico.com",
  "api5.yubico.com"
];
var VERIFY_PATH = "/wsapi/2.0/verify";

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  throw new Error(message);
}

function crc16(data) {
  log.debug("Entering crc16().");
  var crc = 0xffff;
  var i = 0;
  for (i = 0; i < data.length; i++) {
    crc ^= data[i];
    var bit = 0;
    for (bit = 0; bit < 8; bit++) {
      var lsb = crc & 1;
      crc >>= 1;
      if (lsb === 1) {
        crc ^= 0x8408;
      }
    }
  }
  log.debug("Leaving crc16().");
  return crc & 0xffff;
}

function modhexDecode(text) {
  log.debug("Entering modhexDecode().");
  var s = String(text).replace(/\s+/g, "").toLowerCase();
  if (s.length === 0) {
    log.debug("Leaving modhexDecode(). Empty.");
    reject("The OTP is empty.");
  }
  if (!/^[cbdefghijklnrtuv]+$/.test(s)) {
    log.debug("Leaving modhexDecode(). Not modhex.");
    reject("Not modhex. A Yubico OTP uses cbdefghijklnrtuv.");
  }
  if (s.length % 2 !== 0) {
    log.debug("Leaving modhexDecode(). Odd.");
    reject("Modhex length is odd.");
  }
  var out = Buffer.alloc(s.length / 2);
  var i = 0;
  for (i = 0; i < s.length; i += 2) {
    var hi = MODHEX.indexOf(s[i]);
    var lo = MODHEX.indexOf(s[i + 1]);
    out[i / 2] = (hi << 4) | lo;
  }
  log.debug("Leaving modhexDecode().");
  return out;
}

function modhexEncode(bytes) {
  log.debug("Entering modhexEncode().");
  var buf = Buffer.from(bytes);
  var out = "";
  var i = 0;
  for (i = 0; i < buf.length; i++) {
    out += MODHEX[(buf[i] >> 4) & 0x0f];
    out += MODHEX[buf[i] & 0x0f];
  }
  log.debug("Leaving modhexEncode().");
  return out;
}

// 44 characters is the current form. 32 to 48, even, is the older
// form, and a 32-character string is the ciphertext with no public id
// (the shape of the published test vectors).
function parseToken(text) {
  log.debug("Entering parseToken().");
  var s = String(text == null ? "" : text).replace(/\s+/g, "")
      .toLowerCase();
  if (s.length < 32 || s.length > 48 || (s.length % 2) !== 0) {
    log.debug("Leaving parseToken(). Length.");
    reject("A Yubico OTP is 32 to 48 modhex characters. " +
        "The current form is 44.");
  }
  var bytes = modhexDecode(s);
  var form = "older";
  var publicChars = s.length - 32;
  if (s.length === 44) {
    form = "current";
  } else if (s.length === 32) {
    form = "ciphertext only";
  }
  var publicId = bytes.slice(0, publicChars / 2);
  var ciphertext = bytes.slice(bytes.length - 16);
  log.debug("Leaving parseToken().");
  return {
    form: form,
    modhex: s,
    publicId: publicId,
    publicIdModhex: s.slice(0, publicChars),
    ciphertext: ciphertext
  };
}

function aesEcbDecrypt(key, block) {
  log.debug("Entering aesEcbDecrypt().");
  var decipher = forge.cipher.createDecipher("AES-ECB",
      forge.util.createBuffer(Buffer.from(key).toString("binary")));
  decipher.start();
  decipher.update(forge.util.createBuffer(
      Buffer.from(block).toString("binary")));
  // The block is not PKCS#7 padded. The callback accepts it as-is.
  var ok = decipher.finish(function () {
    return true;
  });
  if (!ok) {
    log.debug("Leaving aesEcbDecrypt(). Failed.");
    reject("AES-128-ECB decrypt failed.");
  }
  var out = Buffer.from(decipher.output.getBytes(), "binary");
  log.debug("Leaving aesEcbDecrypt().");
  return out;
}

function parseKey(hex) {
  log.debug("Entering parseKey().");
  var text = String(hex == null ? "" : hex).replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(text)) {
    log.debug("Leaving parseKey(). Length.");
    reject("The AES key is 16 bytes (32 hex characters).");
  }
  log.debug("Leaving parseKey().");
  return Buffer.from(text, "hex");
}

function decryptToken(tokenText, keyHex) {
  log.debug("Entering decryptToken().");
  var token = parseToken(tokenText);
  var key = parseKey(keyHex);
  var plain = aesEcbDecrypt(key, token.ciphertext);
  if (plain.length !== 16) {
    log.debug("Leaving decryptToken(). Block length.");
    reject("The decrypted block is not 16 bytes.");
  }
  if (crc16(plain) !== CRC_RESIDUAL) {
    log.debug("Leaving decryptToken(). CRC.");
    reject("The CRC does not match, which means the AES key is wrong.");
  }
  var use = plain.readUInt16LE(6);
  var stamp = plain[8] | (plain[9] << 8) | (plain[10] << 16);
  var out = {
    form: token.form,
    publicId: token.publicId.toString("hex"),
    publicIdModhex: token.publicIdModhex,
    privateId: plain.slice(0, 6).toString("hex"),
    useCounter: use,
    timestampLow: stamp & 0xffff,
    timestampHigh: (stamp >> 16) & 0xff,
    timestamp: stamp,
    sessionUse: plain[11],
    // The table prints the integer. The two bytes are little-endian,
    // the same way the use counter and the timestamp are.
    random: plain.readUInt16LE(12).toString(16).padStart(4, "0"),
    crc: plain.slice(14, 16).toString("hex")
  };
  log.debug("Leaving decryptToken().");
  return out;
}

function describeToken(tokenText) {
  log.debug("Entering describeToken().");
  var token = parseToken(tokenText);
  var rows = [
    { label: "Form", value: token.form },
    { label: "Public identity", value: token.publicIdModhex ||
        "(none — ciphertext only)" },
    { label: "Public identity (hex)", value: token.publicId.length ?
        token.publicId.toString("hex") : "(none)" },
    { label: "Ciphertext", value: token.ciphertext.length + " bytes" }
  ];
  log.debug("Leaving describeToken().");
  return { summary: token.form + " OTP", rows: rows, token: token };
}

function randomNonce(length) {
  log.debug("Entering randomNonce().");
  var n = length || 32;
  if (n < 16 || n > 40) {
    log.debug("Leaving randomNonce(). Length.");
    reject("A validation nonce is 16 to 40 characters.");
  }
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    log.debug("Leaving randomNonce(). No random.");
    reject("No random source for a nonce.");
  }
  var raw = new Uint8Array(n);
  crypto.getRandomValues(raw);
  var out = "";
  var i = 0;
  for (i = 0; i < n; i++) {
    out += NONCE_ALPHABET[raw[i] % NONCE_ALPHABET.length];
  }
  log.debug("Leaving randomNonce().");
  return out;
}

function decodeApiKey(text) {
  log.debug("Entering decodeApiKey().");
  var raw = String(text == null ? "" : text).replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || raw.length < 4) {
    log.debug("Leaving decodeApiKey(). Not base64.");
    reject("The API key is base64.");
  }
  var bytes = null;
  try {
    bytes = bytesLib.b64ToBytes(raw);
  } catch (e) {
    log.debug("Leaving decodeApiKey(). Decode.");
    reject("The API key is base64.");
  }
  if (!bytes || bytes.length < 1 || bytes.length > 64) {
    log.debug("Leaving decodeApiKey(). Length.");
    reject("The API key is base64.");
  }
  log.debug("Leaving decodeApiKey().");
  return Buffer.from(bytes);
}

function hmacBase64(key, message) {
  log.debug("Entering hmacBase64().");
  var mac = hmacSha1(sha1, key, Buffer.from(message, "utf8"));
  var out = bytesLib.bytesToB64(mac);
  log.debug("Leaving hmacBase64().");
  return out;
}

function signedLine(fields) {
  log.debug("Entering signedLine().");
  var keys = Object.keys(fields).filter(function (name) {
    return name !== "h" && fields[name] !== undefined &&
        fields[name] !== null && fields[name] !== "";
  }).sort();
  var line = keys.map(function (name) {
    return name + "=" + fields[name];
  }).join("&");
  log.debug("Leaving signedLine().");
  return line;
}

function buildValidationRequest(opts) {
  log.debug("Entering buildValidationRequest().");
  var options = opts || {};
  var token = parseToken(options.otp);
  var id = String(options.id == null ? "" : options.id).trim();
  if (!/^[0-9]+$/.test(id)) {
    log.debug("Leaving buildValidationRequest(). Id.");
    reject("The client id is digits.");
  }
  var nonce = options.nonce ? String(options.nonce) : randomNonce(32);
  if (!/^[A-Za-z0-9]{16,40}$/.test(nonce)) {
    log.debug("Leaving buildValidationRequest(). Nonce.");
    reject("A validation nonce is 16 to 40 letters and digits.");
  }
  var key = decodeApiKey(options.apiKey);
  var fields = { id: id, otp: token.modhex, nonce: nonce };
  if (options.timestamp) {
    fields.timestamp = String(options.timestamp);
  }
  if (options.sl) {
    fields.sl = String(options.sl);
  }
  if (options.timeout) {
    fields.timeout = String(options.timeout);
  }
  var line = signedLine(fields);
  var signature = hmacBase64(key, line);
  fields.h = signature;
  var names = Object.keys(fields).sort();
  var body = names.map(function (name) {
    return encodeURIComponent(name) + "=" +
        encodeURIComponent(fields[name]);
  }).join("&");
  log.debug("Leaving buildValidationRequest().");
  return {
    body: body,
    signed: line,
    nonce: nonce,
    otp: token.modhex,
    id: id,
    signature: signature
  };
}

function parseValidationBody(text) {
  log.debug("Entering parseValidationBody().");
  var raw = String(text == null ? "" : text).trim();
  if (!raw) {
    log.debug("Leaving parseValidationBody(). Empty.");
    reject("The validation response is empty.");
  }
  var parts = raw.indexOf("\n") >= 0 ? raw.split(/\r?\n/) : raw.split("&");
  var fields = {};
  var i = 0;
  for (i = 0; i < parts.length; i++) {
    var line = parts[i].trim();
    if (!line) {
      continue;
    }
    var eq = line.indexOf("=");
    if (eq < 1) {
      log.debug("Leaving parseValidationBody(). Line.");
      reject("A validation response line has no key.");
    }
    var name = line.slice(0, eq);
    var value = line.slice(eq + 1);
    try {
      value = decodeURIComponent(value.replace(/\+/g, "%2B"));
    } catch (e) {
      log.debug("Leaving parseValidationBody(). Encoding.");
      reject("A validation response value is not encoded.");
    }
    fields[name] = value;
  }
  log.debug("Leaving parseValidationBody().");
  return fields;
}

function parseValidationResponse(text, opts) {
  log.debug("Entering parseValidationResponse().");
  var options = opts || {};
  var fields = parseValidationBody(text);
  if (!fields.status) {
    log.debug("Leaving parseValidationResponse(). No status.");
    reject("The validation response has no status.");
  }
  var result = {
    status: fields.status,
    fields: fields,
    nonceMatches: null,
    otpMatches: null,
    hmacMatches: null
  };
  // Validation Protocol 2.0: the client checks that the response's otp
  // and nonce are the ones it sent. A signed answer for a different OTP
  // is otherwise accepted. An error status may omit otp; an OK may not.
  if (options.otp) {
    if (fields.otp === undefined && fields.status !== "OK") {
      result.otpMatches = null;
    } else {
      result.otpMatches = fields.otp === options.otp;
      if (!result.otpMatches) {
        log.debug("Leaving parseValidationResponse(). OTP.");
        reject("The response otp does not match the one this " +
            "request sent.");
      }
    }
  }
  if (options.nonce) {
    result.nonceMatches = fields.nonce === options.nonce;
    if (!result.nonceMatches) {
      log.debug("Leaving parseValidationResponse(). Nonce.");
      reject("The response nonce does not match the one " +
          "this request sent.");
    }
  }
  if (options.apiKey) {
    if (!fields.h) {
      log.debug("Leaving parseValidationResponse(). No HMAC.");
      reject("The validation response has no HMAC.");
    }
    var key = decodeApiKey(options.apiKey);
    var expect = hmacBase64(key, signedLine(fields));
    result.hmacMatches = expect === fields.h;
    if (!result.hmacMatches) {
      log.debug("Leaving parseValidationResponse(). HMAC.");
      reject("The response HMAC does not match.");
    }
  }
  log.debug("Leaving parseValidationResponse().");
  return result;
}

function defaultVerifier(which) {
  log.debug("Entering defaultVerifier().");
  var n = which === undefined || which === null || which === "" ?
      1 : Number(which);
  if (!Number.isInteger(n) || n < 1 || n > DEFAULT_HOSTS.length) {
    log.debug("Leaving defaultVerifier(). Server.");
    reject("The YubiCloud server is 1 to " + DEFAULT_HOSTS.length + ".");
  }
  var url = "https://" + DEFAULT_HOSTS[n - 1] + VERIFY_PATH;
  log.debug("Leaving defaultVerifier().");
  return url;
}

// OTP challenge-response is a 6-byte challenge in slot 0x20 or 0x28.
// HMAC-SHA1 challenge-response is slot 0x30 or 0x38 and up to 64
// bytes. The frame is what yubikit sends: the 64-byte payload, then
// the slot and the CRC of the payload, then three zero bytes.
//
// An HMAC slot is programmed fixed (the key HMACs all 64 bytes) or
// variable (HMAC_LT64: the key first drops every trailing byte equal
// to the last one, so the HMAC is over the challenge the caller
// meant). ykman programs variable. For variable, yubikit pads with a
// byte different from the challenge's last one, 01 after a 00 and 00
// otherwise, so the key's stripping removes exactly the padding:
//   challenge.ljust(SLOT_DATA_SIZE,
//       b"\1" if challenge.endswith(b"\0") else b"\0")
// For fixed, the 64 bytes ARE the challenge; a shorter one is zero
// filled, and the HMAC is over that 64-byte block. opts.variable
// defaults to true. It does not apply to the OTP slots.
function hidFrame(slot, challenge, opts) {
  log.debug("Entering hidFrame().");
  var options = opts || {};
  var known = slot === SLOT_OTP_1 || slot === SLOT_OTP_2 ||
      slot === SLOT_HMAC_1 || slot === SLOT_HMAC_2;
  if (!known) {
    log.debug("Leaving hidFrame(). Slot.");
    reject("The slot is 20, 28, 30 or 38.");
  }
  var data = Buffer.from(challenge || []);
  var hmac = slot === SLOT_HMAC_1 || slot === SLOT_HMAC_2;
  if (!hmac && data.length !== 6) {
    log.debug("Leaving hidFrame(). OTP challenge.");
    reject("An OTP challenge is 6 bytes.");
  }
  if (data.length > SLOT_DATA_SIZE) {
    log.debug("Leaving hidFrame(). Long.");
    reject("A HID challenge does not fit in 64 bytes.");
  }
  var variable = options.variable !== false;
  var fill = 0x00;
  if (hmac && variable && data.length > 0 &&
      data[data.length - 1] === 0x00) {
    fill = 0x01;
  }
  var payload = Buffer.alloc(SLOT_DATA_SIZE, fill);
  data.copy(payload, 0);
  var crc = crc16(payload);
  var frame = Buffer.alloc(FRAME_SIZE, 0);
  payload.copy(frame, 0);
  frame[64] = slot;
  frame[65] = crc & 0xff;
  frame[66] = (crc >> 8) & 0xff;
  log.debug("Leaving hidFrame().");
  return frame;
}

// What a slot computes for a challenge, so the page can show the
// expected answer when it holds the HMAC key. Variable mode strips the
// trailing run of the payload's last byte, as the key does.
function hmacChallengeBytes(frame, variable) {
  log.debug("Entering hmacChallengeBytes().");
  var payload = Buffer.from(frame).slice(0, SLOT_DATA_SIZE);
  if (variable === false) {
    log.debug("Leaving hmacChallengeBytes(). Fixed.");
    return payload;
  }
  var last = payload[SLOT_DATA_SIZE - 1];
  var end = SLOT_DATA_SIZE;
  while (end > 0 && payload[end - 1] === last) {
    end -= 1;
  }
  log.debug("Leaving hmacChallengeBytes().");
  return payload.slice(0, end);
}

// Feature reports are 8 bytes: 7 of the frame and a sequence byte.
// An all-zero packet is skipped, except the first and the last.
function hidReports(frame) {
  log.debug("Entering hidReports().");
  var buf = Buffer.from(frame);
  if (buf.length !== FRAME_SIZE) {
    log.debug("Leaving hidReports(). Length.");
    reject("A HID frame is 70 bytes.");
  }
  var reports = [];
  var seq = 0;
  var off = 0;
  for (off = 0; off < buf.length; off += 7) {
    var chunk = buf.slice(off, off + 7);
    var allZero = true;
    var i = 0;
    for (i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 0) {
        allZero = false;
      }
    }
    if (seq === 0 || seq === 9 || !allZero) {
      var report = Buffer.alloc(8, 0);
      chunk.copy(report, 0);
      report[7] = 0x80 | seq;
      reports.push(report);
    }
    seq += 1;
  }
  log.debug("Leaving hidReports().");
  return reports;
}

// THE READ SIDE OF THE HID EXCHANGE, as yubikit's otp.py does it. The
// last byte of every 8-byte feature report is a status: SLOT_WRITE
// (0x80) means the key has not taken the last write yet, RESP_PENDING
// (0x40) means this report carries response bytes and its low five
// bits are their sequence number, RESP_TIMEOUT_WAIT (0x20) means the
// key is waiting for a touch, and 0 is a plain status report. The
// page polls; these functions only read what a report says.
var HID_SLOT_WRITE_FLAG = 0x80;
var HID_RESP_PENDING_FLAG = 0x40;
var HID_RESP_TIMEOUT_WAIT_FLAG = 0x20;
var HID_SEQUENCE_MASK = 0x1f;
var HID_DUMMY_REPORT_WRITE = 0x8f;

// A feature report as 8 bytes. Some platforms hand back the report ID
// in front, which makes 9.
function hidReportBytes(view) {
  log.debug("Entering hidReportBytes().");
  var raw = Buffer.from(view.buffer ?
      new Uint8Array(view.buffer, view.byteOffset || 0, view.byteLength) :
      view);
  if (raw.length === 9) {
    raw = raw.slice(1);
  }
  if (raw.length !== 8) {
    log.debug("Leaving hidReportBytes(). Length.");
    reject("A feature report is 8 bytes, got " + raw.length + ".");
  }
  log.debug("Leaving hidReportBytes().");
  return raw;
}

function hidCanWrite(report) {
  log.debug("Entering hidCanWrite().");
  var ok = (report[7] & HID_SLOT_WRITE_FLAG) === 0;
  log.debug("Leaving hidCanWrite().");
  return ok;
}

// One step of the read. state is { seq, data } and starts { seq: 0,
// data: [] }. Returns { kind } where kind is "data" (keep reading),
// "done" (data holds the frame), "wait" or "touch" (poll again), or
// "status" (the key answered with no response at all).
function hidReadStep(state, report) {
  log.debug("Entering hidReadStep().");
  var status = report[7];
  var out = null;
  if (status & HID_RESP_PENDING_FLAG) {
    var seq = status & HID_SEQUENCE_MASK;
    if (seq === state.seq) {
      var i;
      for (i = 0; i < 7; i++) {
        state.data.push(report[i]);
      }
      state.seq += 1;
      out = { kind: "data" };
    } else if (seq === 0) {
      out = { kind: "done" };
    } else {
      out = { kind: "data" };
    }
  } else if (status === 0) {
    if (state.data.length > 0) {
      log.debug("Leaving hidReadStep(). Incomplete.");
      reject("The key stopped part way through its response.");
    }
    out = { kind: "status" };
  } else if (status & HID_RESP_TIMEOUT_WAIT_FLAG) {
    out = { kind: "touch" };
  } else {
    out = { kind: "wait" };
  }
  log.debug("Leaving hidReadStep(). " + out.kind);
  return out;
}

// The report that ends a read, so the key is ready for the next one.
function hidResetReport() {
  log.debug("Entering hidResetReport().");
  var report = Buffer.alloc(8, 0);
  report[0] = 0xff;
  report[7] = HID_DUMMY_REPORT_WRITE;
  log.debug("Leaving hidResetReport().");
  return report;
}

// The response in a finished frame: 20 bytes for HMAC-SHA1, 16 for a
// Yubico OTP challenge-response, each followed by a CRC whose residual
// over the whole is CRC_RESIDUAL.
function hidResponse(slot, frame) {
  log.debug("Entering hidResponse().");
  var size = slot === SLOT_HMAC_1 || slot === SLOT_HMAC_2 ? 20 : 16;
  var buf = Buffer.from(frame);
  if (buf.length < size + 2) {
    log.debug("Leaving hidResponse(). Short.");
    reject("The response is " + buf.length + " bytes; " + (size + 2) +
        " were expected.");
  }
  if (crc16(buf.slice(0, size + 2)) !== CRC_RESIDUAL) {
    log.debug("Leaving hidResponse(). CRC.");
    reject("The response CRC does not check.");
  }
  log.debug("Leaving hidResponse().");
  return buf.slice(0, size);
}

// THE SAME CHALLENGE-RESPONSE OVER CCID, for a browser with no WebHID.
// A YubiKey's OTP application also answers on the smart-card interface —
// it is how challenge-response works over NFC — so Firefox reaches the
// slots through the api's reader relay instead: SELECT the OTP
// application, then one CALCULATE whose P1 is the slot and whose data is
// the same 64-byte payload the HID frame carries (yubikit pads it the same
// way for both transports). The answer comes back bare, with no CRC
// framing: the first 20 bytes for an HMAC-SHA1 slot, 16 for an OTP slot.
var OTP_AID = "a000000527200101";
var INS_CALCULATE = 0x01;

function ccidSelectApdu() {
  log.debug("Entering ccidSelectApdu().");
  log.debug("Leaving ccidSelectApdu().");
  return "00a40400" + (OTP_AID.length / 2).toString(16).padStart(2, "0") +
      OTP_AID;
}

function ccidCalculateApdu(slot, challenge, opts) {
  log.debug("Entering ccidCalculateApdu().");
  var payload = hidFrame(slot, challenge, opts).slice(0, SLOT_DATA_SIZE);
  var header = Buffer.from([0x00, INS_CALCULATE, slot, 0x00,
                            SLOT_DATA_SIZE]);
  log.debug("Leaving ccidCalculateApdu().");
  return Buffer.concat([header, payload]).toString("hex");
}

function ccidResponse(slot, data) {
  log.debug("Entering ccidResponse().");
  var size = slot === SLOT_HMAC_1 || slot === SLOT_HMAC_2 ? 20 : 16;
  var buf = Buffer.from(data || []);
  if (buf.length < size) {
    log.debug("Leaving ccidResponse(). Short.");
    reject("The key answered " + buf.length + " bytes; " + size +
        " were expected. Is the slot configured for challenge-response?");
  }
  log.debug("Leaving ccidResponse().");
  return buf.slice(0, size);
}

module.exports = {
  OTP_AID: OTP_AID,
  ccidSelectApdu: ccidSelectApdu,
  ccidCalculateApdu: ccidCalculateApdu,
  ccidResponse: ccidResponse,
  MODHEX: MODHEX,
  CRC_RESIDUAL: CRC_RESIDUAL,
  DEFAULT_HOSTS: DEFAULT_HOSTS,
  VERIFY_PATH: VERIFY_PATH,
  SLOT_OTP_1: SLOT_OTP_1,
  SLOT_OTP_2: SLOT_OTP_2,
  SLOT_HMAC_1: SLOT_HMAC_1,
  SLOT_HMAC_2: SLOT_HMAC_2,
  crc16: crc16,
  modhexDecode: modhexDecode,
  modhexEncode: modhexEncode,
  parseToken: parseToken,
  decryptToken: decryptToken,
  describeToken: describeToken,
  randomNonce: randomNonce,
  buildValidationRequest: buildValidationRequest,
  parseValidationResponse: parseValidationResponse,
  defaultVerifier: defaultVerifier,
  hidFrame: hidFrame,
  hmacChallengeBytes: hmacChallengeBytes,
  hidReports: hidReports,
  hidReportBytes: hidReportBytes,
  hidCanWrite: hidCanWrite,
  hidReadStep: hidReadStep,
  hidResetReport: hidResetReport,
  hidResponse: hidResponse
};
