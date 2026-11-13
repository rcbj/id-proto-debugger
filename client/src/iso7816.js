// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: iso7816.js
//
// ISO 7816-4 command and response APDUs, and BER-TLV, for the smart-card
// applications in issue #217 (PIV, OpenPGP card, OATH, YubiHSM Auth).
// Those applets share this encoding and nothing else. One reader here so
// the four of them cannot disagree about a length.
//
// A browser cannot open CCID, so this module only reads and writes bytes
// somebody already has. It performs no card operation.
//
// The input is untrusted: a paste box, or a trace from a reader. A declared
// length is checked against the bytes still remaining before it is believed.
// Indefinite BER length (0x80) is refused. These cards use definite lengths,
// and absorbing an indefinite one would hide a truncated object.
//
// Le is returned as a count of bytes, not as the wire byte. A short Le of
// 0x00 is 256. An extended Le of 0x0000 is 65536. Absent Le is null.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "iso7816",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// A PIV certificate object is a few kilobytes. A pasted trace of several
// exchanges is larger. Anything past this is not a card trace.
var MAX_INPUT_BYTES = 262144;
// A card object is a handful of constructed layers. Deeper than this is
// a document built to recurse, not a certificate.
var MAX_DEPTH = 8;
var MAX_TAG_BYTES = 4;

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  throw new Error(message);
}

function asBytes(input) {
  log.debug("Entering asBytes().");
  var bytes = null;
  if (Buffer.isBuffer(input)) {
    bytes = input;
  } else if (input instanceof Uint8Array) {
    bytes = Buffer.from(input);
  } else if (typeof input === "string") {
    var hex = input.replace(/[\s:]/g, "");
    if (hex.length === 0) {
      log.debug("Leaving asBytes(). Empty.");
      return Buffer.alloc(0);
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      log.debug("Leaving asBytes(). Not hex.");
      reject("Not hexadecimal.");
    }
    if (hex.length % 2 !== 0) {
      log.debug("Leaving asBytes(). Odd length.");
      reject("Hex length is odd.");
    }
    bytes = Buffer.from(hex, "hex");
  } else {
    log.debug("Leaving asBytes(). Not bytes.");
    reject("Expected a hex string or bytes.");
  }
  if (bytes.length > MAX_INPUT_BYTES) {
    log.debug("Leaving asBytes(). Too long.");
    reject("Input is longer than " + MAX_INPUT_BYTES + " bytes.");
  }
  log.debug("Leaving asBytes().");
  return bytes;
}

function toHex(input) {
  log.debug("Entering toHex().");
  var hex = asBytes(input).toString("hex");
  var spaced = hex.replace(/(..)/g, "$1 ").trim();
  log.debug("Leaving toHex().");
  return spaced;
}

function byteValue(name, n) {
  log.debug("Entering byteValue().");
  if (typeof n !== "number" || n < 0 || n > 255 || (n % 1) !== 0) {
    log.debug("Leaving byteValue(). Out of range.");
    reject(name + " is not a byte.");
  }
  log.debug("Leaving byteValue().");
  return n;
}

// A short Le wire byte of 0 means 256. An extended Le of 0 means 65536.
function leCount(hi, lo) {
  log.debug("Entering leCount().");
  var n = lo === undefined ? hi : ((hi << 8) | lo);
  if (n === 0) {
    n = lo === undefined ? 256 : 65536;
  }
  log.debug("Leaving leCount().");
  return n;
}

function leWire(le, extended) {
  log.debug("Entering leWire().");
  if (le < 1 || le > 65536 || (le % 1) !== 0) {
    log.debug("Leaving leWire(). Out of range.");
    reject("Le is not a byte count.");
  }
  if (!extended) {
    if (le > 256) {
      log.debug("Leaving leWire(). Needs extended.");
      reject("Le does not fit in a short APDU.");
    }
    log.debug("Leaving leWire().");
    return Buffer.from([le === 256 ? 0 : le]);
  }
  var n = le === 65536 ? 0 : le;
  log.debug("Leaving leWire().");
  return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
}

function parseCommand(input) {
  log.debug("Entering parseCommand().");
  var b = asBytes(input);
  if (b.length < 4) {
    log.debug("Leaving parseCommand(). Short header.");
    reject("Command is shorter than a header.");
  }
  var out = {
    cla: b[0],
    ins: b[1],
    p1: b[2],
    p2: b[3],
    data: Buffer.alloc(0),
    le: null,
    extended: false
  };
  if (b.length === 4) {
    log.debug("Leaving parseCommand().");
    return out;
  }
  if (b.length === 5) {
    out.le = leCount(b[4]);
    log.debug("Leaving parseCommand().");
    return out;
  }
  if (b[4] !== 0) {
    var lc = b[4];
    if (b.length === 5 + lc) {
      out.data = b.slice(5, 5 + lc);
    } else if (b.length === 6 + lc) {
      out.data = b.slice(5, 5 + lc);
      out.le = leCount(b[5 + lc]);
    } else {
      log.debug("Leaving parseCommand(). Lc mismatch.");
      reject("Command length does not match Lc.");
    }
    log.debug("Leaving parseCommand().");
    return out;
  }
  if (b.length < 7) {
    log.debug("Leaving parseCommand(). Short extended.");
    reject("Extended command is shorter than its length field.");
  }
  out.extended = true;
  if (b.length === 7) {
    out.le = leCount(b[5], b[6]);
    log.debug("Leaving parseCommand().");
    return out;
  }
  var elc = (b[5] << 8) | b[6];
  if (elc === 0) {
    log.debug("Leaving parseCommand(). Zero extended Lc.");
    reject("Extended Lc is zero.");
  }
  if (b.length === 7 + elc) {
    out.data = b.slice(7, 7 + elc);
  } else if (b.length === 9 + elc) {
    out.data = b.slice(7, 7 + elc);
    out.le = leCount(b[7 + elc], b[8 + elc]);
  } else {
    log.debug("Leaving parseCommand(). Extended Lc mismatch.");
    reject("Command length does not match extended Lc.");
  }
  log.debug("Leaving parseCommand().");
  return out;
}

function encodeCommand(fields) {
  log.debug("Entering encodeCommand().");
  var cla = byteValue("CLA", fields.cla);
  var ins = byteValue("INS", fields.ins);
  var p1 = byteValue("P1", fields.p1);
  var p2 = byteValue("P2", fields.p2);
  var data = fields.data ? asBytes(fields.data) : Buffer.alloc(0);
  var le = fields.le === undefined ? null : fields.le;
  var extended = !!fields.extended;
  if (data.length > 255) {
    extended = true;
  }
  if (le !== null && le > 256) {
    extended = true;
  }
  if (extended && data.length > 65535) {
    log.debug("Leaving encodeCommand(). Data too long.");
    reject("Command data does not fit in an extended APDU.");
  }
  var header = Buffer.from([cla, ins, p1, p2]);
  var parts = [header];
  if (data.length === 0 && le === null) {
    log.debug("Leaving encodeCommand().");
    return header;
  }
  if (extended) {
    if (data.length === 0) {
      parts.push(Buffer.from([0]));
      parts.push(leWire(le, true));
    } else {
      parts.push(Buffer.from([
        0, (data.length >> 8) & 0xff, data.length & 0xff
      ]));
      parts.push(data);
      if (le !== null) {
        parts.push(leWire(le, true));
      }
    }
  } else if (data.length === 0) {
    parts.push(leWire(le, false));
  } else {
    parts.push(Buffer.from([data.length]));
    parts.push(data);
    if (le !== null) {
      parts.push(leWire(le, false));
    }
  }
  log.debug("Leaving encodeCommand().");
  return Buffer.concat(parts);
}

function statusName(sw) {
  log.debug("Entering statusName().");
  var name = null;
  if (sw === 0x9000) {
    name = "success";
  } else if ((sw & 0xff00) === 0x6100) {
    name = "more data available";
  } else if (sw === 0x6982) {
    name = "security status not satisfied";
  } else if (sw === 0x6985) {
    name = "conditions of use not satisfied";
  } else if (sw === 0x6a80) {
    name = "incorrect parameters in the data field";
  } else if (sw === 0x6a82) {
    name = "file or application not found";
  } else if (sw === 0x6a86) {
    name = "incorrect parameters P1-P2";
  } else if (sw === 0x6a88) {
    name = "referenced data not found";
  } else if (sw === 0x6300) {
    // ISO 7816-4 names 6300 a warning with no further qualification.
    // These applets return it when a check fails and there is no counter.
    name = "verification failed";
  } else if ((sw & 0xfff0) === 0x63c0) {
    name = "verification failed, " + (sw & 0x0f) + " tries remaining";
  } else {
    name = sw.toString(16).toUpperCase().padStart(4, "0");
  }
  log.debug("Leaving statusName().");
  return name;
}

function parseResponse(input) {
  log.debug("Entering parseResponse().");
  var b = asBytes(input);
  if (b.length < 2) {
    log.debug("Leaving parseResponse(). Short.");
    reject("Response is shorter than a status word.");
  }
  var sw1 = b[b.length - 2];
  var sw2 = b[b.length - 1];
  var sw = (sw1 << 8) | sw2;
  var out = {
    data: b.slice(0, b.length - 2),
    sw1: sw1,
    sw2: sw2,
    sw: sw,
    name: statusName(sw)
  };
  // The byte the card sent. Short Le uses 0 to mean 256; this field
  // is the status byte, so 0 stays 0.
  if (sw1 === 0x61) {
    out.remaining = sw2;
  }
  if ((sw & 0xfff0) === 0x63c0) {
    out.triesRemaining = sw & 0x0f;
  }
  log.debug("Leaving parseResponse().");
  return out;
}

// One level of BER-TLV. No log line: walk() calls this for every
// constructed value, and a certificate is dozens of those. A named
// helper that logged would be the whole log. reject() on the error
// paths does log; an error is not the per-level cost.
function readElements(buf) {
  var nodes = [];
  var i = 0;
  while (i < buf.length) {
    var tagStart = i;
    var first = buf[i];
    i += 1;
    if ((first & 0x1f) === 0x1f) {
      var seen = 1;
      var more = true;
      while (more) {
        if (i >= buf.length || seen >= MAX_TAG_BYTES) {
          reject("TLV tag is truncated.");
        }
        var cont = buf[i];
        i += 1;
        seen += 1;
        more = (cont & 0x80) !== 0;
      }
    }
    var rawTag = buf.slice(tagStart, i);
    var hex = rawTag.toString("hex");
    if (i >= buf.length) {
      reject("Tag " + hex + " length is missing.");
    }
    var lenByte = buf[i];
    i += 1;
    var length = 0;
    if (lenByte === 0x80) {
      reject("Tag " + hex + " uses an indefinite length.");
    } else if (lenByte < 0x80) {
      length = lenByte;
    } else {
      var count = lenByte & 0x7f;
      if (count === 0 || count > 3) {
        reject("Tag " + hex + " has a length that does not fit.");
      }
      if (i + count > buf.length) {
        reject("Tag " + hex + " length is truncated.");
      }
      var c = 0;
      for (c = 0; c < count; c++) {
        length = (length * 256) + buf[i + c];
      }
      i += count;
    }
    if (i + length > buf.length) {
      reject("Tag " + hex + " length runs past the buffer.");
    }
    var value = buf.slice(i, i + length);
    i += length;
    nodes.push({
      tag: rawTag.reduce(function (n, byte) {
        return (n * 256) + byte;
      }, 0),
      tagHex: hex,
      constructed: (first & 0x20) !== 0,
      value: value
    });
  }
  return nodes;
}

// The recursive reader. Note the deliberate absence of the
// Entering/Leaving logging this codebase uses elsewhere: one
// certificate is dozens of tags, and a log line on each of them is
// the whole log. parseTlv() is the entry point.
function walk(buf, depth) {
  if (depth > MAX_DEPTH) {
    reject("TLV nesting is deeper than " + MAX_DEPTH + ".");
  }
  var nodes = readElements(buf);
  var n = 0;
  for (n = 0; n < nodes.length; n++) {
    if (nodes[n].constructed) {
      nodes[n].children = walk(nodes[n].value, depth + 1);
    }
  }
  return nodes;
}

function parseTlv(input) {
  log.debug("Entering parseTlv().");
  var buf = asBytes(input);
  var nodes = walk(buf, 1);
  log.debug("Leaving parseTlv().");
  return nodes;
}

// One level. The value is not read as children. Card applets use
// tags whose constructed bit is set (0x70, 0x72, 0x5F50) for a
// certificate, a name or a URL, which is not nested TLV. parseTlv()
// would descend into that value and refuse it.
function parseElements(input) {
  log.debug("Entering parseElements().");
  var nodes = readElements(asBytes(input));
  log.debug("Leaving parseElements().");
  return nodes;
}

function lengthBytes(length) {
  log.debug("Entering lengthBytes().");
  var out = null;
  if (length < 0x80) {
    out = Buffer.from([length]);
  } else if (length <= 0xff) {
    out = Buffer.from([0x81, length]);
  } else if (length <= 0xffff) {
    out = Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
  } else if (length <= 0xffffff) {
    out = Buffer.from([
      0x83,
      (length >> 16) & 0xff,
      (length >> 8) & 0xff,
      length & 0xff
    ]);
  } else {
    log.debug("Leaving lengthBytes(). Too long.");
    reject("TLV value does not fit in three length bytes.");
  }
  log.debug("Leaving lengthBytes().");
  return out;
}

function tagBytesOf(tag) {
  log.debug("Entering tagBytesOf().");
  var bytes = null;
  if (Buffer.isBuffer(tag) || tag instanceof Uint8Array) {
    bytes = Buffer.from(tag);
  } else if (typeof tag === "number" && tag >= 0 && tag <= 255 &&
      (tag % 1) === 0) {
    bytes = Buffer.from([tag]);
  } else {
    log.debug("Leaving tagBytesOf(). Bad tag.");
    reject("TLV tag is not one byte or a tag buffer.");
  }
  if (bytes.length === 0 || bytes.length > MAX_TAG_BYTES) {
    log.debug("Leaving tagBytesOf(). Bad length.");
    reject("TLV tag length is out of range.");
  }
  if (bytes.length === 1 && (bytes[0] & 0x1f) === 0x1f) {
    log.debug("Leaving tagBytesOf(). Needs continuation.");
    reject("A long-form tag needs its continuation bytes.");
  }
  log.debug("Leaving tagBytesOf().");
  return bytes;
}

function encodeTlv(tag, value) {
  log.debug("Entering encodeTlv().");
  var tagBytes = tagBytesOf(tag);
  var content = null;
  if (Array.isArray(value)) {
    tagBytes[0] = tagBytes[0] | 0x20;
    var parts = [];
    var n = 0;
    for (n = 0; n < value.length; n++) {
      parts.push(encodeTlv(value[n].tag, value[n].value));
    }
    content = Buffer.concat(parts);
  } else {
    content = asBytes(value);
  }
  var encoded = Buffer.concat([
    tagBytes, lengthBytes(content.length), content
  ]);
  log.debug("Leaving encodeTlv().");
  return encoded;
}

module.exports = {
  MAX_INPUT_BYTES: MAX_INPUT_BYTES,
  MAX_DEPTH: MAX_DEPTH,
  asBytes: asBytes,
  toHex: toHex,
  parseCommand: parseCommand,
  encodeCommand: encodeCommand,
  parseResponse: parseResponse,
  statusName: statusName,
  parseTlv: parseTlv,
  parseElements: parseElements,
  encodeTlv: encodeTlv
};
