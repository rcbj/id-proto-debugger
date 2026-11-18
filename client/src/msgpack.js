// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: msgpack.js
//
// ---------------------------------------------------------------------------
// MessagePack (https://github.com/msgpack/msgpack/blob/master/spec.md), the
// whole format but the extension types: what the W3C form of AnonCreds
// carries in a proofValue ("u" + base64url of a MessagePack value, written
// by anoncreds-rs's rmp-serde). Maps decode to Map so their key order and
// non-string keys survive; integers beyond 2^53 decode to BigInt.
//
// Encoding writes the smallest form of each value, as rmp-serde does.
//
// Recursive and run per item, so the codec's inner functions carry no
// Entering/Leaving pair — the hot-path exception the code style allows,
// stated as it requires; encode() and decode() log.
//
// NO DOM.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "msgpack",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var MAX_DEPTH = 64;

function Reader(bytes) {
  this.b = bytes;
  this.i = 0;
  this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
}

Reader.prototype.need = function (n) {
  if (this.i + n > this.b.length) {
    throw new Error("MessagePack: the input ends inside an item.");
  }
};

Reader.prototype.uint = function (n) {
  this.need(n);
  var v;
  if (n === 1) v = this.dv.getUint8(this.i);
  if (n === 2) v = this.dv.getUint16(this.i);
  if (n === 4) v = this.dv.getUint32(this.i);
  if (n === 8) {
    var big = this.dv.getBigUint64(this.i);
    v = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
  }
  this.i += n;
  return v;
};

Reader.prototype.int = function (n) {
  this.need(n);
  var v;
  if (n === 1) v = this.dv.getInt8(this.i);
  if (n === 2) v = this.dv.getInt16(this.i);
  if (n === 4) v = this.dv.getInt32(this.i);
  if (n === 8) {
    var big = this.dv.getBigInt64(this.i);
    v = big >= BigInt(Number.MIN_SAFE_INTEGER) &&
        big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
  }
  this.i += n;
  return v;
};

Reader.prototype.bytes = function (n) {
  this.need(n);
  var out = this.b.slice(this.i, this.i + n);
  this.i += n;
  return out;
};

function readItem(r, depth) {
  if (depth > MAX_DEPTH) {
    throw new Error("MessagePack: nested deeper than " + MAX_DEPTH + ".");
  }
  var t = r.uint(1);
  var n;
  if (t <= 0x7f) return t;
  if (t >= 0xe0) return t - 0x100;
  if (t >= 0xa0 && t <= 0xbf) return str(r, t & 0x1f);
  if (t >= 0x90 && t <= 0x9f) return arr(r, t & 0x0f, depth);
  if (t >= 0x80 && t <= 0x8f) return map(r, t & 0x0f, depth);
  switch (t) {
    case 0xc0:
      return null;
    case 0xc2:
      return false;
    case 0xc3:
      return true;
    case 0xc4: case 0xc5: case 0xc6:
      n = r.uint({ 0xc4: 1, 0xc5: 2, 0xc6: 4 }[t]);
      return r.bytes(n);
    case 0xca:
      r.need(4);
      n = r.dv.getFloat32(r.i);
      r.i += 4;
      return n;
    case 0xcb:
      r.need(8);
      n = r.dv.getFloat64(r.i);
      r.i += 8;
      return n;
    case 0xcc: return r.uint(1);
    case 0xcd: return r.uint(2);
    case 0xce: return r.uint(4);
    case 0xcf: return r.uint(8);
    case 0xd0: return r.int(1);
    case 0xd1: return r.int(2);
    case 0xd2: return r.int(4);
    case 0xd3: return r.int(8);
    case 0xd9: return str(r, r.uint(1));
    case 0xda: return str(r, r.uint(2));
    case 0xdb: return str(r, r.uint(4));
    case 0xdc: return arr(r, r.uint(2), depth);
    case 0xdd: return arr(r, r.uint(4), depth);
    case 0xde: return map(r, r.uint(2), depth);
    case 0xdf: return map(r, r.uint(4), depth);
    default:
      throw new Error("MessagePack: type 0x" + t.toString(16) + " (an " +
                      "extension or a reserved byte) is not read here.");
  }
}

function str(r, n) {
  return new TextDecoder("utf-8", { fatal: true }).decode(r.bytes(n));
}

function arr(r, n, depth) {
  var out = [];
  for (var i = 0; i < n; i++) out.push(readItem(r, depth + 1));
  return out;
}

function map(r, n, depth) {
  var out = new Map();
  for (var i = 0; i < n; i++) {
    var k = readItem(r, depth + 1);
    out.set(k, readItem(r, depth + 1));
  }
  return out;
}

function decode(bytes) {
  log.debug("Entering decode(). " + (bytes && bytes.length));
  var r = new Reader(bytes);
  var v = readItem(r, 0);
  if (r.i !== bytes.length) {
    log.debug("Leaving decode(). Trailing bytes.");
    throw new Error("MessagePack: " + (bytes.length - r.i) + " byte(s) " +
                    "after the item.");
  }
  log.debug("Leaving decode().");
  return v;
}

function pushUint(out, prefix, n, size) {
  out.push(prefix);
  var dv = new DataView(new ArrayBuffer(size));
  if (size === 1) dv.setUint8(0, n);
  if (size === 2) dv.setUint16(0, n);
  if (size === 4) dv.setUint32(0, n);
  if (size === 8) dv.setBigUint64(0, BigInt(n));
  for (var i = 0; i < size; i++) out.push(dv.getUint8(i));
}

function pushInt(out, prefix, n, size) {
  out.push(prefix);
  var dv = new DataView(new ArrayBuffer(size));
  if (size === 1) dv.setInt8(0, n);
  if (size === 2) dv.setInt16(0, n);
  if (size === 4) dv.setInt32(0, n);
  if (size === 8) dv.setBigInt64(0, BigInt(n));
  for (var i = 0; i < size; i++) out.push(dv.getUint8(i));
}

function lengthHead(out, n, fix, fixMax, c8, c16, c32) {
  if (fix !== null && n <= fixMax) {
    out.push(fix | n);
  } else if (c8 !== null && n <= 0xff) {
    pushUint(out, c8, n, 1);
  } else if (n <= 0xffff) {
    pushUint(out, c16, n, 2);
  } else {
    pushUint(out, c32, n, 4);
  }
}

function writeItem(out, v) {
  if (v === null || v === undefined) {
    out.push(0xc0);
  } else if (v === false) {
    out.push(0xc2);
  } else if (v === true) {
    out.push(0xc3);
  } else if (typeof v === "bigint") {
    if (v >= BigInt(0)) {
      pushUint(out, 0xcf, v, 8);
    } else {
      pushInt(out, 0xd3, v, 8);
    }
  } else if (typeof v === "number") {
    if (Number.isInteger(v) && Number.isSafeInteger(v)) {
      if (v >= 0) {
        if (v <= 0x7f) out.push(v);
        else if (v <= 0xff) pushUint(out, 0xcc, v, 1);
        else if (v <= 0xffff) pushUint(out, 0xcd, v, 2);
        else if (v <= 0xffffffff) pushUint(out, 0xce, v, 4);
        else pushUint(out, 0xcf, v, 8);
      } else if (v >= -32) {
        out.push(v + 0x100);
      } else if (v >= -0x80) {
        pushInt(out, 0xd0, v, 1);
      } else if (v >= -0x8000) {
        pushInt(out, 0xd1, v, 2);
      } else if (v >= -0x80000000) {
        pushInt(out, 0xd2, v, 4);
      } else {
        pushInt(out, 0xd3, v, 8);
      }
    } else {
      var dv = new DataView(new ArrayBuffer(8));
      dv.setFloat64(0, v);
      out.push(0xcb);
      for (var i = 0; i < 8; i++) out.push(dv.getUint8(i));
    }
  } else if (typeof v === "string") {
    var s = new TextEncoder().encode(v);
    lengthHead(out, s.length, 0xa0, 31, 0xd9, 0xda, 0xdb);
    for (var j = 0; j < s.length; j++) out.push(s[j]);
  } else if (v instanceof Uint8Array) {
    lengthHead(out, v.length, null, 0, 0xc4, 0xc5, 0xc6);
    for (var k = 0; k < v.length; k++) out.push(v[k]);
  } else if (Array.isArray(v)) {
    lengthHead(out, v.length, 0x90, 15, null, 0xdc, 0xdd);
    v.forEach(function (x) {
      writeItem(out, x);
    });
  } else {
    var entries = v instanceof Map ? Array.from(v.entries()) :
        Object.keys(v).filter(function (key) {
          return v[key] !== undefined;
        }).map(function (key) {
          return [key, v[key]];
        });
    lengthHead(out, entries.length, 0x80, 15, null, 0xde, 0xdf);
    entries.forEach(function (e) {
      writeItem(out, e[0]);
      writeItem(out, e[1]);
    });
  }
}

function encode(v) {
  log.debug("Entering encode().");
  var out = [];
  writeItem(out, v);
  log.debug("Leaving encode(). " + out.length + " bytes.");
  return new Uint8Array(out);
}

// A decoded value with every Map turned into an object (keys as strings),
// for reading.
function toPlain(v) {
  log.debug("Entering toPlain().");
  var out = v;
  if (Array.isArray(v)) {
    out = v.map(toPlain);
  } else if (v instanceof Map) {
    out = {};
    v.forEach(function (x, k) {
      out[String(k)] = toPlain(x);
    });
  }
  log.debug("Leaving toPlain().");
  return out;
}

module.exports = {
  encode: encode,
  decode: decode,
  toPlain: toPlain
};
