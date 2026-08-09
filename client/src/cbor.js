// File: cbor.js
//
// ---------------------------------------------------------------------------
// A decode-only CBOR reader (RFC 8949), for the two places WebAuthn puts CBOR
// where JSON would have been kinder: the attestation object, and the credential
// public key (a COSE_Key) buried inside the authenticator data.
//
// Decode only, deliberately. Nothing in this debugger produces CBOR — it reads
// what an authenticator produced — and an encoder would be code with no caller
// that still has to be maintained and kept safe.
//
// It reads UNTRUSTED input. Everything this module is handed came from an
// authenticator, or from a text box somebody pasted into, so the failure modes
// that matter are not "wrong value" but "hangs the tab" and "allocates a
// gigabyte". Three bounds address that, and each is checked BEFORE any
// allocation: the whole input is capped (MAX_INPUT_BYTES — a real attestation
// object is on the order of a kilobyte), nesting is capped (MAX_DEPTH, so a
// document that is nothing but ten thousand nested arrays cannot exhaust the
// stack), and a declared length is compared against the bytes actually
// remaining before it is believed. That last one is the important one: a
// five-byte input can claim a four-gigabyte byte string, and a reader that
// trusts the header allocates it.
//
// Two representation choices worth knowing, both made for fidelity because this
// is a debugger and the point is to show what is actually there:
//
//   * a CBOR map becomes a **Map**, not a plain object. COSE_Key is keyed by
//     integers — 1, 3, -1, -2, -3 — and negative ones at that; collapsing those
//     to object keys turns 1 and "1" into the same thing and loses the order the
//     authenticator chose. `toPlain()` is available for display code that would
//     rather have an object.
//   * indefinite-length items are REFUSED rather than accepted. CTAP2's
//     canonical CBOR forbids them, so encountering one in an attestation object
//     is a finding about the authenticator, and silently accepting it would hide
//     exactly the kind of defect somebody opened this debugger to look for.
//
// `decodeFirst()` exists because the authenticator data does not end where its
// CBOR does: with the AT flag set, the credential public key is a CBOR item
// embedded mid-buffer and the extension data (if any) follows it, so the parser
// has to be told where the key stopped. See webauthn.js.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "cbor",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      // A missing log level must not stop the module loading.
      return "info";
    }
  })()
});

var MAX_INPUT_BYTES = 2 * 1024 * 1024;
var MAX_DEPTH = 32;

// Major types, by the number in the top three bits.
var MT_UINT = 0, MT_NEGINT = 1, MT_BYTES = 2, MT_TEXT = 3,
    MT_ARRAY = 4, MT_MAP = 5, MT_TAG = 6, MT_SIMPLE = 7;

// A tagged value is kept rather than unwrapped: the tag number is information,
// and a debugger that quietly discarded it would be lying about the document.
function Tagged(tag, value) {
  this.tag = tag;
  this.value = value;
}

function CborError(message, offset) {
  var e = new Error(message + " (at byte " + offset + ")");
  e.name = "CborError";
  e.offset = offset;
  return e;
}

function Reader(bytes) {
  this.bytes = bytes;
  this.offset = 0;
}

// Every read goes through this, so there is one place that can run off the end.
Reader.prototype.take = function (n) {
  if (n < 0 || this.offset + n > this.bytes.length) {
    throw CborError("the item claims " + n + " byte(s) but only " +
                    (this.bytes.length - this.offset) + " remain", this.offset);
  }
  var slice = this.bytes.subarray(this.offset, this.offset + n);
  this.offset += n;
  return slice;
};

Reader.prototype.uint = function (n) {
  var b = this.take(n), v = 0;
  for (var i = 0; i < b.length; i++) {
    v = v * 256 + b[i];
  }
  return v;
};

// The argument of an item: the low five bits, or the 1/2/4/8 bytes after them.
// Returns { major, info, arg }, where arg is null for the indefinite form.
function readHead(reader) {
  var initial = reader.take(1)[0];
  var major = initial >> 5;
  var info = initial & 0x1f;
  var arg;
  if (info < 24) {
    arg = info;
  } else if (info === 24) {
    arg = reader.uint(1);
  } else if (info === 25) {
    arg = reader.uint(2);
  } else if (info === 26) {
    arg = reader.uint(4);
  } else if (info === 27) {
    // Beyond 2^53 the value cannot be held exactly in a JS number. Nothing
    // WebAuthn carries is that large, and quietly rounding a length would be
    // worse than refusing it.
    var hi = reader.uint(4), lo = reader.uint(4);
    arg = hi * 4294967296 + lo;
    if (!Number.isSafeInteger(arg)) {
      throw CborError("an 8-byte argument exceeds the exactly-representable range", reader.offset);
    }
  } else if (info === 31) {
    arg = null;
  } else {
    throw CborError("additional-information value " + info + " is reserved", reader.offset);
  }
  return { major: major, info: info, arg: arg };
}

// IEEE 754 half precision, which CBOR uses and JS has no native reader for.
function halfToNumber(bits) {
  var exponent = (bits & 0x7c00) >> 10;
  var fraction = bits & 0x03ff;
  var sign = (bits & 0x8000) ? -1 : 1;
  if (exponent === 0) {
    return sign * Math.pow(2, -14) * (fraction / 1024);
  }
  if (exponent === 0x1f) {
    return fraction ? NaN : sign * Infinity;
  }
  return sign * Math.pow(2, exponent - 15) * (1 + fraction / 1024);
}

// The recursive reader. Note the deliberate absence of the Entering/Leaving
// logging this codebase uses elsewhere: this runs once per CBOR item — hundreds
// of times for one attestation object — and logging each call would bury every
// other line in the log and slow the page for no diagnostic gain. The entry
// points below carry the logging instead.
function readValue(reader, depth) {
  if (depth > MAX_DEPTH) {
    throw CborError("nesting deeper than " + MAX_DEPTH + " levels", reader.offset);
  }
  var head = readHead(reader);

  if (head.arg === null && head.major !== MT_SIMPLE) {
    throw CborError("indefinite-length item (major type " + head.major + "). CTAP2's canonical " +
                    "CBOR forbids these, so one here is a finding about the producer", reader.offset);
  }

  var i, out, key;
  switch (head.major) {
    case MT_UINT:
      return head.arg;
    case MT_NEGINT:
      return -1 - head.arg;
    case MT_BYTES:
      // Copied rather than returned as a view: callers keep these around, and a
      // subarray pins the whole input buffer alive behind it.
      return new Uint8Array(reader.take(head.arg));
    case MT_TEXT:
      return new TextDecoder("utf-8", { fatal: true }).decode(reader.take(head.arg));
    case MT_ARRAY:
      out = [];
      for (i = 0; i < head.arg; i++) {
        out.push(readValue(reader, depth + 1));
      }
      return out;
    case MT_MAP:
      out = new Map();
      for (i = 0; i < head.arg; i++) {
        key = readValue(reader, depth + 1);
        if (key instanceof Uint8Array || Array.isArray(key) || key instanceof Map) {
          throw CborError("a map key of a non-scalar type", reader.offset);
        }
        if (out.has(key)) {
          throw CborError("duplicate map key " + JSON.stringify(key), reader.offset);
        }
        out.set(key, readValue(reader, depth + 1));
      }
      return out;
    case MT_TAG:
      return new Tagged(head.arg, readValue(reader, depth + 1));
    case MT_SIMPLE:
      if (head.info === 20) return false;
      if (head.info === 21) return true;
      if (head.info === 22) return null;
      if (head.info === 23) return undefined;
      if (head.info === 25) return halfToNumber(head.arg);
      if (head.info === 26) return new DataView(new Uint8Array([
        (head.arg >>> 24) & 0xff, (head.arg >>> 16) & 0xff,
        (head.arg >>> 8) & 0xff, head.arg & 0xff]).buffer).getFloat32(0);
      if (head.info === 27) {
        throw CborError("64-bit floats are not decoded here; nothing in WebAuthn uses one",
                        reader.offset);
      }
      if (head.info === 31) {
        throw CborError("a break stop code outside an indefinite-length item", reader.offset);
      }
      return { simple: head.arg };
    default:
      throw CborError("major type " + head.major + " is not a thing", reader.offset);
  }
}

function checkInput(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw CborError("expected a Uint8Array, got " + Object.prototype.toString.call(bytes), 0);
  }
  if (!bytes.length) {
    throw CborError("no input", 0);
  }
  if (bytes.length > MAX_INPUT_BYTES) {
    throw CborError("input is " + bytes.length + " bytes; the cap is " + MAX_INPUT_BYTES, 0);
  }
}

// Decode ONE item and report where it ended. For the credential public key,
// which sits in the middle of the authenticator data with the extension data
// behind it.
function decodeFirst(bytes) {
  log.debug("Entering decodeFirst(). bytes=" + (bytes && bytes.length));
  checkInput(bytes);
  var reader = new Reader(bytes);
  var value = readValue(reader, 0);
  log.debug("Leaving decodeFirst(). consumed=" + reader.offset);
  return { value: value, bytesRead: reader.offset };
}

// Decode an item and require it to be the WHOLE input. Trailing bytes after an
// attestation object mean the document is not what it claims to be, and a
// decoder that ignored them would report a perfectly good-looking result for it.
function decode(bytes) {
  log.debug("Entering decode(). bytes=" + (bytes && bytes.length));
  var first = decodeFirst(bytes);
  if (first.bytesRead !== bytes.length) {
    throw CborError("decoded one item but " + (bytes.length - first.bytesRead) +
                    " byte(s) follow it", first.bytesRead);
  }
  log.debug("Leaving decode().");
  return first.value;
}

// Maps to objects, byte strings to base64url, for display and for JSON. Lossy
// on purpose — integer and text keys that render alike collapse — so it is the
// display path only and never the parsing path.
function toPlain(value) {
  if (value instanceof Uint8Array) {
    return base64url(value);
  }
  if (Array.isArray(value)) {
    return value.map(toPlain);
  }
  if (value instanceof Tagged) {
    return { _tag: value.tag, value: toPlain(value.value) };
  }
  if (value instanceof Map) {
    var out = {};
    value.forEach(function (v, k) {
      out[String(k)] = toPlain(v);
    });
    return out;
  }
  return value;
}

function base64url(bytes) {
  var s = "";
  for (var i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  // btoa exists in the browser; Buffer is the node path the tests take.
  var b64 = (typeof btoa === "function")
    ? btoa(s)
    : Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

module.exports = {
  decode: decode,
  decodeFirst: decodeFirst,
  toPlain: toPlain,
  Tagged: Tagged,
  MAX_INPUT_BYTES: MAX_INPUT_BYTES,
  MAX_DEPTH: MAX_DEPTH,
};
