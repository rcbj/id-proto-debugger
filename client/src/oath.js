// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oath.js
//
// HOTP (RFC 4226) and TOTP (RFC 6238), and the YKOATH applet that
// stores them on a YubiKey. The calculator needs no key and no
// reader. PUT builds an APDU and does not send it.
//
// SHA-1, SHA-256 and SHA-512, and the digit counts the RFCs' own
// examples use: 6, 7 and 8. Web Crypto is not used. SHA-1 is what
// RFC 4226 specifies, and crypto.subtle has no SHA-512/256 either;
// @noble/hashes is the same code the hashing page already runs.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "oath",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var hmacFn = require("@noble/hashes/hmac").hmac;
var sha1 = require("@noble/hashes/sha1").sha1;
var sha256 = require("@noble/hashes/sha256").sha256;
var sha512 = require("@noble/hashes/sha512").sha512;
var iso = require("./iso7816.js");

var AID = "a0000005272101";
var HASHES = { "SHA-1": sha1, "SHA-256": sha256, "SHA-512": sha512 };
var TYPES = { "10": "HOTP", "20": "TOTP" };
var ALGOS = { "1": "SHA-1", "2": "SHA-256", "3": "SHA-512" };
var ALGO_CODE = { "SHA-1": 0x01, "SHA-256": 0x02, "SHA-512": 0x03 };
var TYPE_CODE = { "HOTP": 0x10, "TOTP": 0x20 };
var TAG_PROPERTY = 0x78;
var MIN_SECRET_BYTES = 14;

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  throw new Error(message);
}

function statusLabel(response) {
  log.debug("Entering statusLabel().");
  var text = response.sw.toString(16).toUpperCase().padStart(4, "0") +
      " " + response.name;
  log.debug("Leaving statusLabel().");
  return text;
}

function hashOf(name) {
  log.debug("Entering hashOf().");
  var fn = HASHES[name];
  if (!fn) {
    log.debug("Leaving hashOf(). Unknown.");
    reject("The algorithm is SHA-1, SHA-256 or SHA-512.");
  }
  log.debug("Leaving hashOf().");
  return fn;
}

function checkDigits(digits) {
  log.debug("Entering checkDigits().");
  if (digits !== 6 && digits !== 7 && digits !== 8) {
    log.debug("Leaving checkDigits().");
    reject("The digit count is 6, 7 or 8.");
  }
  log.debug("Leaving checkDigits().");
}

function counterBytes(counter) {
  log.debug("Entering counterBytes().");
  if (typeof counter !== "number" || !Number.isSafeInteger(counter) ||
      counter < 0) {
    log.debug("Leaving counterBytes(). Range.");
    reject("The counter is a non-negative integer.");
  }
  var buf = Buffer.alloc(8, 0);
  var hi = Math.floor(counter / 0x100000000);
  var lo = counter >>> 0;
  buf.writeUInt32BE(hi, 0);
  buf.writeUInt32BE(lo, 4);
  log.debug("Leaving counterBytes().");
  return buf;
}

function hotp(secret, counter, digits, algorithm) {
  log.debug("Entering hotp().");
  var n = digits === undefined ? 6 : digits;
  checkDigits(n);
  var algo = algorithm || "SHA-1";
  var key = Buffer.from(secret);
  if (key.length === 0) {
    log.debug("Leaving hotp(). Empty secret.");
    reject("The OATH secret is empty.");
  }
  var mac = hmacFn(hashOf(algo), key, counterBytes(counter));
  var offset = mac[mac.length - 1] & 0x0f;
  var bin = ((mac[offset] & 0x7f) << 24) |
      ((mac[offset + 1] & 0xff) << 16) |
      ((mac[offset + 2] & 0xff) << 8) |
      (mac[offset + 3] & 0xff);
  var code = String(bin % Math.pow(10, n)).padStart(n, "0");
  log.debug("Leaving hotp().");
  return code;
}

function totp(secret, when, opts) {
  log.debug("Entering totp().");
  var options = opts || {};
  var step = options.step === undefined ? 30 : options.step;
  var t0 = options.t0 === undefined ? 0 : options.t0;
  if (typeof when !== "number" || !Number.isFinite(when)) {
    log.debug("Leaving totp(). Time.");
    reject("The time is a number of seconds.");
  }
  if (!Number.isInteger(step) || step < 1) {
    log.debug("Leaving totp(). Step.");
    reject("The time step is a positive number of seconds.");
  }
  var counter = Math.floor((when - t0) / step);
  if (!Number.isSafeInteger(counter) || counter < 0) {
    log.debug("Leaving totp(). Counter.");
    reject("The time is before the epoch this step can count.");
  }
  var code = null;
  try {
    code = hotp(secret, counter, options.digits === undefined ? 8 :
        options.digits, options.algorithm || "SHA-1");
  } catch (e) {
    log.debug("Leaving totp().");
    throw e;
  }
  log.debug("Leaving totp().");
  return code;
}

function typeAndAlgorithm(byte) {
  log.debug("Entering typeAndAlgorithm().");
  var type = TYPES[(byte & 0xf0).toString(16)] ||
      ("type " + (byte & 0xf0).toString(16));
  var algorithm = ALGOS[String(byte & 0x0f)] ||
      ("algorithm " + (byte & 0x0f).toString(16));
  log.debug("Leaving typeAndAlgorithm().");
  return { type: type, algorithm: algorithm, byte: byte };
}

function nameBytes(name) {
  log.debug("Entering nameBytes().");
  var bytes = Buffer.from(String(name == null ? "" : name), "utf8");
  if (bytes.length < 1 || bytes.length > 64) {
    log.debug("Leaving nameBytes(). Length.");
    reject("A YKOATH name is 1 to 64 bytes.");
  }
  log.debug("Leaving nameBytes().");
  return bytes;
}

function secretBytes(secret) {
  log.debug("Entering secretBytes().");
  var bytes = Buffer.from(secret);
  if (bytes.length < 1 || bytes.length > 64) {
    log.debug("Leaving secretBytes(). Length.");
    reject("A YKOATH secret is 1 to 64 bytes.");
  }
  // yubikit pads a short key with zeros to 14 bytes before a PUT,
  // because the applet refuses a shorter one. HMAC pads its key with
  // zeros to the block size anyway, so the codes do not change.
  if (bytes.length < MIN_SECRET_BYTES) {
    bytes = Buffer.concat([bytes,
        Buffer.alloc(MIN_SECRET_BYTES - bytes.length, 0)]);
  }
  log.debug("Leaving secretBytes().");
  return bytes;
}

// PUT's data field. Every element is TLV except the property, which
// YKOATH writes as tag 78 and ONE value byte with no length (yubikit:
// struct.pack(">BB", TAG_PROPERTY, prop)). parseElements() would read
// that value byte as a length.
function putElements(data) {
  log.debug("Entering putElements().");
  var nodes = [];
  var i = 0;
  while (i < data.length) {
    var tag = data[i];
    if (tag === TAG_PROPERTY) {
      if (i + 1 >= data.length) {
        log.debug("Leaving putElements(). Property.");
        reject("The PUT property byte is missing.");
      }
      nodes.push({ tag: tag, value: data.slice(i + 1, i + 2) });
      i += 2;
      continue;
    }
    // YKOATH tags are one byte and its values are short, so the
    // length is one byte, or 81 and one byte.
    var length = data[i + 1];
    var start = i + 2;
    if (length === 0x81) {
      length = data[i + 2];
      start = i + 3;
    }
    if (length === undefined || length > 0x81 ||
        start + length > data.length) {
      log.debug("Leaving putElements(). Length.");
      reject("A PUT element runs past the command.");
    }
    nodes.push({ tag: tag, value: data.slice(start, start + length) });
    i = start + length;
  }
  log.debug("Leaving putElements().");
  return nodes;
}

function algoByte(type, algorithm) {
  log.debug("Entering algoByte().");
  if (TYPE_CODE[type] === undefined) {
    log.debug("Leaving algoByte(). Type.");
    reject("The credential type is HOTP or TOTP.");
  }
  if (ALGO_CODE[algorithm] === undefined) {
    log.debug("Leaving algoByte(). Algorithm.");
    reject("The algorithm is SHA-1, SHA-256 or SHA-512.");
  }
  log.debug("Leaving algoByte().");
  return TYPE_CODE[type] | ALGO_CODE[algorithm];
}

// PUT. The key tag's value is the algorithm byte, the digit count,
// then the secret. The APDU is returned and not sent.
function putApdu(opts) {
  log.debug("Entering putApdu().");
  var options = opts || {};
  var digits = options.digits === undefined ? 6 : options.digits;
  checkDigits(digits);
  var type = options.type || "TOTP";
  var algorithm = options.algorithm || "SHA-1";
  var packed = Buffer.concat([
    Buffer.from([algoByte(type, algorithm), digits]),
    secretBytes(options.secret)
  ]);
  var parts = [
    iso.encodeTlv(0x71, nameBytes(options.name)),
    iso.encodeTlv(0x73, packed)
  ];
  if (options.touch || options.onlyIncreasing) {
    var property = (options.onlyIncreasing ? 0x01 : 0) |
        (options.touch ? 0x02 : 0);
    parts.push(Buffer.from([TAG_PROPERTY, property]));
  }
  if (type === "HOTP" && options.counter) {
    if (!Number.isSafeInteger(options.counter) || options.counter < 0) {
      log.debug("Leaving putApdu(). Counter.");
      reject("The moving factor is a non-negative integer.");
    }
    var imf = Buffer.alloc(4, 0);
    imf.writeUInt32BE(options.counter, 0);
    parts.push(iso.encodeTlv(0x7a, imf));
  }
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00,
    data: Buffer.concat(parts), le: null
  });
  log.debug("Leaving putApdu().");
  return apdu;
}

function deleteApdu(name) {
  log.debug("Entering deleteApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x02, p1: 0x00, p2: 0x00,
    data: iso.encodeTlv(0x71, nameBytes(name)), le: null
  });
  log.debug("Leaving deleteApdu().");
  return apdu;
}

function resetApdu() {
  log.debug("Entering resetApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x04, p1: 0xde, p2: 0xad,
    data: Buffer.alloc(0), le: null
  });
  log.debug("Leaving resetApdu().");
  return apdu;
}

function selectApdu() {
  log.debug("Entering selectApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00,
    data: Buffer.from(AID, "hex"), le: 256
  });
  log.debug("Leaving selectApdu().");
  return apdu;
}

function listApdu() {
  log.debug("Entering listApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0xa1, p1: 0x00, p2: 0x00,
    data: Buffer.alloc(0), le: 256
  });
  log.debug("Leaving listApdu().");
  return apdu;
}

function calculateApdu(name, challenge, truncated) {
  log.debug("Entering calculateApdu().");
  var data = Buffer.concat([
    iso.encodeTlv(0x71, nameBytes(name)),
    iso.encodeTlv(0x74, Buffer.from(challenge))
  ]);
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0xa2, p1: 0x00, p2: truncated ? 0x01 : 0x00,
    data: data, le: 256
  });
  log.debug("Leaving calculateApdu().");
  return apdu;
}

function totpChallenge(when, step) {
  log.debug("Entering totpChallenge().");
  var s = step === undefined ? 30 : step;
  if (typeof when !== "number" || !Number.isFinite(when)) {
    log.debug("Leaving totpChallenge(). Time.");
    reject("The time is a number of seconds.");
  }
  var counter = Math.floor(when / s);
  log.debug("Leaving totpChallenge().");
  return counterBytes(counter);
}

function parseList(body) {
  log.debug("Entering parseList().");
  var nodes = iso.parseElements(body);
  var creds = [];
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    if (node.tag !== 0x72 || node.value.length < 1) {
      continue;
    }
    var kind = typeAndAlgorithm(node.value[0]);
    creds.push({
      name: node.value.slice(1).toString("utf8"),
      type: kind.type,
      algorithm: kind.algorithm
    });
  }
  log.debug("Leaving parseList().");
  return creds;
}

function parseCalculate(body) {
  log.debug("Entering parseCalculate().");
  var nodes = iso.parseElements(body);
  var node = null;
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    if (nodes[i].tag === 0x75 || nodes[i].tag === 0x76) {
      node = nodes[i];
    }
  }
  if (!node || node.value.length < 1) {
    log.debug("Leaving parseCalculate(). No response.");
    reject("The CALCULATE response has no code.");
  }
  var digits = node.value[0];
  var raw = node.value.slice(1);
  var code = null;
  if (raw.length === 4 && digits >= 6 && digits <= 8) {
    var bin = raw.readUInt32BE(0);
    code = String(bin % Math.pow(10, digits)).padStart(digits, "0");
  }
  log.debug("Leaving parseCalculate().");
  return {
    truncated: node.tag === 0x76,
    digits: digits,
    raw: raw,
    code: code
  };
}

function parseSelect(body) {
  log.debug("Entering parseSelect().");
  var nodes = iso.parseElements(body);
  var out = { version: null, name: null, challenge: null, algorithm: null };
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    if (node.tag === 0x79 && node.value.length >= 1) {
      out.version = Array.prototype.join.call(node.value, ".");
    } else if (node.tag === 0x71) {
      out.name = node.value.toString("utf8");
    } else if (node.tag === 0x74) {
      out.challenge = node.value;
    } else if (node.tag === 0x7b && node.value.length >= 1) {
      out.algorithm = ALGOS[String(node.value[0])] ||
          node.value[0].toString(16);
    }
  }
  log.debug("Leaving parseSelect().");
  return out;
}

function describeCommand(input) {
  log.debug("Entering describeCommand().");
  var command = iso.parseCommand(input);
  var aid = command.data.toString("hex");
  var summary = "INS " + command.ins.toString(16);
  var rows = [
    { label: "INS", value: command.ins.toString(16).padStart(2, "0")
        .toUpperCase() }
  ];
  if (command.ins === 0xa4 && aid.indexOf(AID) === 0) {
    summary = "SELECT OATH";
    rows = [
      { label: "Instruction", value: "SELECT" },
      { label: "AID", value: aid.toUpperCase() }
    ];
  } else if (command.ins === 0x01) {
    summary = "PUT";
    rows = [{ label: "Instruction", value: "PUT (not sent)" }];
    var nodes = putElements(command.data);
    var n = 0;
    for (n = 0; n < nodes.length; n++) {
      if (nodes[n].tag === 0x71) {
        rows.push({ label: "Name",
            value: nodes[n].value.toString("utf8") });
      } else if (nodes[n].tag === 0x73 && nodes[n].value.length >= 2) {
        var kind = typeAndAlgorithm(nodes[n].value[0]);
        rows.push({ label: "Type", value: kind.type });
        rows.push({ label: "Algorithm", value: kind.algorithm });
        rows.push({ label: "Digits", value: String(nodes[n].value[1]) });
        rows.push({ label: "Secret",
            value: (nodes[n].value.length - 2) + " bytes, not shown" });
      } else if (nodes[n].tag === TAG_PROPERTY) {
        var prop = nodes[n].value[0];
        var named = [];
        if (prop & 0x01) {
          named.push("only increasing");
        }
        if (prop & 0x02) {
          named.push("touch required");
        }
        rows.push({ label: "Property", value: named.join(", ") ||
            prop.toString(16) });
      } else if (nodes[n].tag === 0x7a && nodes[n].value.length === 4) {
        rows.push({ label: "Initial counter",
            value: String(nodes[n].value.readUInt32BE(0)) });
      }
    }
  } else if (command.ins === 0x02) {
    summary = "DELETE";
    rows = [{ label: "Instruction", value: "DELETE (not sent)" }];
  } else if (command.ins === 0x04) {
    summary = "RESET";
    rows = [{ label: "Instruction",
        value: "RESET (P1 P2 DE AD, not sent)" }];
  } else if (command.ins === 0xa1) {
    summary = "LIST";
    rows = [{ label: "Instruction", value: "LIST" }];
  } else if (command.ins === 0xa2) {
    summary = "CALCULATE";
    rows = [{ label: "Instruction", value: "CALCULATE" },
      { label: "Truncated", value: command.p2 === 0x01 ? "yes" : "no" }];
  } else if (command.ins === 0xa4) {
    summary = "CALCULATE ALL";
    rows = [{ label: "Instruction", value: "CALCULATE ALL" }];
  }
  log.debug("Leaving describeCommand().");
  return { summary: summary, rows: rows };
}

function describeResponse(input) {
  log.debug("Entering describeResponse().");
  var response = iso.parseResponse(input);
  var summary = statusLabel(response);
  var rows = [{ label: "Status", value: summary }];
  if (response.data.length === 0) {
    log.debug("Leaving describeResponse(). Status only.");
    return { summary: summary, rows: rows };
  }
  var creds = [];
  try {
    creds = parseList(response.data);
  } catch (e) {
    creds = [];
  }
  if (creds.length > 0 && response.data[0] === 0x72) {
    var i = 0;
    for (i = 0; i < creds.length; i++) {
      rows.push({ label: creds[i].name,
          value: creds[i].type + " " + creds[i].algorithm });
    }
    summary = creds.length + " credential(s), " + summary;
  } else if (response.data[0] === 0x75 || response.data[0] === 0x76) {
    var calc = parseCalculate(response.data);
    rows.push({ label: "Digits", value: String(calc.digits) });
    rows.push({ label: "Response", value: calc.code ||
        (calc.raw.length + " bytes") });
    summary = (calc.code || "response") + ", " + summary;
  } else if (response.data[0] === 0x79) {
    var selected = parseSelect(response.data);
    if (selected.version) {
      rows.push({ label: "Version", value: selected.version });
    }
    if (selected.name) {
      rows.push({ label: "Name", value: selected.name });
    }
    if (selected.challenge) {
      rows.push({ label: "Challenge",
          value: selected.challenge.length + " bytes (auth required)" });
    }
    summary = "SELECT response, " + summary;
  }
  log.debug("Leaving describeResponse().");
  return { summary: summary, rows: rows };
}

module.exports = {
  AID: AID,
  hotp: hotp,
  totp: totp,
  putApdu: putApdu,
  deleteApdu: deleteApdu,
  resetApdu: resetApdu,
  selectApdu: selectApdu,
  listApdu: listApdu,
  calculateApdu: calculateApdu,
  totpChallenge: totpChallenge,
  parseList: parseList,
  parseCalculate: parseCalculate,
  parseSelect: parseSelect,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
