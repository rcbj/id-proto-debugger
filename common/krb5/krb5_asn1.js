// File: krb5_asn1.js
//
// ---------------------------------------------------------------------------
// DER for Kerberos v5's ASN.1 (RFC 4120 section 5).
//
// This is a purpose-built coder rather than a schema library, and the choice was
// made deliberately after phase 0. `asn1js` is already a client dependency and
// can express this grammar, but Kerberos's shape — every structure wrapped in an
// `[APPLICATION n]` tag, every field of every SEQUENCE carrying an explicit
// context tag, and a handful of types (`GeneralString`, `KerberosTime`,
// `KerberosFlags`) that are really constrained aliases — means the schema
// declarations end up longer than the code below, and a mismatch between a
// schema and the RFC is harder to see than a mismatch between a function and the
// RFC. The decoder page also needs a generic TLV tree for bytes it cannot
// identify, which a schema-driven parser does not give you.
//
// Everything is synchronous and byte-exact. No crypto here.
//
// FOUR THINGS IN HERE ARE THE ONES THAT GO WRONG:
//
//  * **Negative INTEGERs are real.** Checksum type -138 (HMAC-MD5, the one
//    etype 23 and S4U2Self use) and several ad-types are negative. An encoder
//    that assumes unsigned emits a two-byte positive value where a KDC expects
//    a two's-complement negative one, and the message is rejected as malformed
//    rather than as wrong.
//  * **KerberosFlags bit order.** Bit 0 is the MOST significant bit of the
//    FIRST octet, so `forwardable` (bit 1) is 0x40 of byte 0, not 0x02. Getting
//    this backwards produces a request whose options are a different set of
//    options, which a KDC answers perfectly correctly and uselessly.
//  * **KerberosTime carries no fractional seconds.** RFC 4120 requires exactly
//    `YYYYMMDDHHMMSSZ`. `Date.prototype.toISOString` gives milliseconds, and a
//    KDC that is strict about it says only "cannot decode".
//  * **DER wants minimal encodings.** Minimal integer length, definite lengths,
//    short form under 128. A KDC is entitled to refuse anything else and some
//    do.
//
// The reader is BOUNDED — a maximum input size and a maximum nesting depth —
// because the decoder page parses bytes a stranger pasted in, and a length field
// is an attacker-controlled allocation.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_asn1",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var toBytes = prim.toBytes;
var concat = prim.concat;

var MAX_INPUT_BYTES = 2 * 1024 * 1024;
var MAX_DEPTH = 32;

// Universal tags this grammar uses.
var TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OBJECT_IDENTIFIER: 0x06,
  SEQUENCE: 0x30,
  GENERAL_STRING: 0x1b,
  IA5_STRING: 0x16,
  GENERALIZED_TIME: 0x18
};

// [n] context-specific, constructed — which is what every named field of every
// Kerberos SEQUENCE is.
function contextTag(n) {
  if (n < 0 || n > 30) {
    throw new Error("krb5: context tag " + n + " out of range for this coder");
  }
  return 0xa0 | n;
}

// [APPLICATION n], constructed.
function applicationTag(n) {
  if (n < 0 || n > 30) {
    throw new Error("krb5: application tag " + n + " out of range for this " +
        "coder");
  }
  return 0x60 | n;
}


// ---------------------------------------------------------------------------
// A HOT PATH, and the Entering/Leaving logging this codebase uses everywhere
// else is deliberately absent from most of it.
//
// DER is read and written one tag-length-value at a time, so `readTlv`,
// `encodeLength`, `integerContent`, `readChildren`, `decInteger`,
// `decGeneralString`, `looksConstructed`, `encTaggedSequence` and
// `readTaggedSequence` are each called once per FIELD of every message —
// thousands of times for one exchange. Measured on this tree at
// `logLevel: "debug"` (which client/src/env/local.js and docker-tests.js both
// set, so the browser bundles really do run this way) logging them took 2,000
// encode/decode round trips from 72ms to 1,075ms, a 15x cost.
//
// This is the same call the codebase already makes for cbor.js's item decoder,
// and the reason is the one recorded in CLAUDE.md: a pair of log lines in a
// per-item accessor is not a trace, it is the entire log. The higher-level
// entry points here — readApplication, tree, describeTag, renderPrimitive —
// KEEP their logging, and that is where a trace of a decode actually lives.
//
// Do not "fix" this by adding the pairs back without re-measuring.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Writing.
// ---------------------------------------------------------------------------

function encodeLength(n) {
  if (n < 0x80) {
    return new Uint8Array([n]);
  }
  var bytes = [];
  var v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes.length > 4) {
    throw new Error("krb5: refusing to encode a length of " + n + " bytes");
  }
  return new Uint8Array([0x80 | bytes.length].concat(bytes));
}

// One tag-length-value.
function tlv(tag, value) {
  var v = toBytes(value);
  return concat([new Uint8Array([tag]), encodeLength(v.length), v]);
}

// Two's complement, minimal length. See the header note: negative values occur.
function integerContent(value) {
  if (typeof value !== "number" || !isFinite(value) || 
      Math.floor(value) !== value) {
    throw new Error("krb5: INTEGER must be a whole number, got " + value);
  }
  if (value === 0) {
    return new Uint8Array([0]);
  }
  var bytes = [];
  if (value > 0) {
    var v = value;
    while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
    // A leading bit of 1 would read as negative, so pad.
    if (bytes[0] & 0x80) bytes.unshift(0);
    return new Uint8Array(bytes);
  }
  // Smallest n whose range -(2^(8n-1)) .. 2^(8n-1)-1 contains the value.
  var n = 1;
  while (value < -Math.pow(2, 8 * n - 1)) n++;
  var m = value + Math.pow(2, 8 * n);
  bytes = new Array(n);
  for (var i = n - 1; i >= 0; i--) { bytes[i] = m & 0xff; m = Math.floor(m / 256); }
  return new Uint8Array(bytes);
}

function encInteger(value) { return tlv(TAG.INTEGER, integerContent(value)); }
function encOctetString(bytes) { return tlv(TAG.OCTET_STRING, toBytes(bytes)); }

// KerberosString ::= GeneralString. Realms and principal name components are
// this type, and they are case-sensitive on the wire: a realm is conventionally
// upper case and a KDC will not fold it for you.
function encGeneralString(text) { return tlv(TAG.GENERAL_STRING, 
    prim.utf8(text)); }

// KerberosFlags ::= BIT STRING (SIZE (32..MAX)). Always 32 bits here, no unused
// bits. The value is given as a list of set bit numbers, counting from the most
// significant bit of the first octet.
function encFlags(bitNumbers) {
  var bytes = new Uint8Array(4);
  (bitNumbers || []).forEach(function (bit) {
    if (bit < 0 || bit > 31) {
      throw new Error("krb5: flag bit " + bit + " out of range");
    }
    bytes[bit >> 3] |= 0x80 >> (bit & 7);
  });
  return tlv(TAG.BIT_STRING, concat([new Uint8Array([0]), bytes]));
}

function flagsFromBits(bitNumbers) {
  var bytes = new Uint8Array(4);
  (bitNumbers || 
      []).forEach(function (bit) { bytes[bit >> 3] |= 0x80 >> (bit & 7); });
  return bytes;
}

function bitsFromFlags(bytes) {
  var b = toBytes(bytes), out = [];
  for (var i = 0; i < b.length * 8; i++) {
    if (b[i >> 3] & (0x80 >> (i & 7))) out.push(i);
  }
  return out;
}

// KerberosTime ::= GeneralizedTime, "YYYYMMDDHHMMSSZ" and nothing else. No
// milliseconds, no offset, no fractional part.
function formatKerberosTime(date) {
  var d = (date instanceof Date) ? date : new Date(date);
  if (isNaN(d.getTime())) {
    throw new Error("krb5: not a date: " + date);
  }
  function two(n) { return (n < 10 ? "0" : "") + n; }
  return String(d.getUTCFullYear()) + two(d.getUTCMonth() + 1) + 
      two(d.getUTCDate()) +
         two(d.getUTCHours()) + two(d.getUTCMinutes()) + 
             two(d.getUTCSeconds()) + "Z";
}

function parseKerberosTime(text) {
  var s = String(text);
  var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) {
    throw new Error("krb5: KerberosTime must be YYYYMMDDHHMMSSZ, got " + 
        JSON.stringify(s));
  }
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

function encKerberosTime(date) {
  return tlv(TAG.GENERALIZED_TIME, prim.utf8(formatKerberosTime(date)));
}

function encSequence(items) { return tlv(TAG.SEQUENCE, concat(items)); }

// A SEQUENCE whose fields are context-tagged, skipping the ones that are
// absent. Every OPTIONAL field in this grammar is expressed by passing
// undefined or null, which is what keeps the message builders readable.
function encTaggedSequence(fields) {
  var parts = [];
  fields.forEach(function (f) {
    if (f === null || f === undefined) {
      return;
    }
    if (f.value === null || f.value === undefined) {
      return;
    }
    parts.push(tlv(contextTag(f.tag), f.value));
  });
  return encSequence(parts);
}

function encApplication(n, inner) { return tlv(applicationTag(n), inner); }
function encContext(n, inner) { return tlv(contextTag(n), inner); }

function encSequenceOf(items) { return encSequence(items); }

// ---------------------------------------------------------------------------
// Reading.
//
// readTlv returns a view rather than a copy where it can, and every read is
// bounds-checked against the buffer it was given rather than against the
// buffer's own length claim.
// ---------------------------------------------------------------------------

function readTlv(bytes, offset, depth) {
  var b = toBytes(bytes);
  var at = offset || 0;
  if ((depth || 0) > MAX_DEPTH) {
    throw new Error("krb5: ASN.1 nested deeper than " + MAX_DEPTH);
  }
  if (at + 2 > b.length) {
    throw new Error("krb5: truncated ASN.1 at offset " + at + " (need a tag " +
        "and a length)");
  }
  var tag = b[at];
  var lenByte = b[at + 1];
  var headerLen = 2;
  var len;
  if (lenByte < 0x80) {
    len = lenByte;
  } else if (lenByte === 0x80) {
    // Indefinite length is BER, not DER, and Kerberos is DER. Refusing it is
    // not pedantry: an indefinite length in a KDC reply means something is
    // re-encoding the traffic.
    throw new Error("krb5: indefinite ASN.1 length at offset " + at + 
        " — DER requires a definite length");
  } else {
    var n = lenByte & 0x7f;
    if (n > 4) {
      throw new Error("krb5: ASN.1 length field of " + n + 
          " bytes at offset " + at);
    }
    if (at + 2 + n > b.length) {
      throw new Error("krb5: truncated ASN.1 length at offset " + at);
    }
    len = 0;
    for (var i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    headerLen = 2 + n;
  }
  var valueStart = at + headerLen;
  var valueEnd = valueStart + len;
  if (valueEnd > b.length) {
    throw new Error("krb5: ASN.1 element at offset " + at + " claims " + len +
      " bytes but only " + (b.length - valueStart) + " remain");
  }
  return {
    tag: tag,
    length: len,
    headerLength: headerLen,
    start: at,
    valueStart: valueStart,
    end: valueEnd,
    value: b.subarray(valueStart, valueEnd),
    // The element's ORIGINAL bytes, header included. Anything relayed onward —
    // a Ticket, a KDC-REQ-BODY covered by a checksum — must be reproduced
    // exactly, and re-encoding from `tag` and `length` would not do it: a
    // sender that used a non-minimal long-form length would come back with a
    // different header and a checksum that no longer matches, for no visible
    // reason.
    raw: b.subarray(at, valueEnd)
  };
}

// Every element of a constructed value, in order.
function readChildren(value, depth) {
  var b = toBytes(value);
  var out = [];
  var at = 0;
  while (at < b.length) {
    var t = readTlv(b, at, (depth || 0) + 1);
    out.push(t);
    at = t.end;
  }
  return out;
}

// A context-tagged SEQUENCE reduced to a map from tag number to the element
// INSIDE that tag. Explicit tagging means each [n] wraps exactly one element,
// and unwrapping it here is what keeps the message readers short.
function readTaggedSequence(value, depth) {
  var map = {};
  readChildren(value, depth).forEach(function (child) {
    if ((child.tag & 0xc0) !== 0x80) {
      throw new Error("krb5: expected a context tag in this SEQUENCE, saw 0x" + 
          child.tag.toString(16));
    }
    var n = child.tag & 0x1f;
    var inner = readChildren(child.value, (depth || 0) + 1);
    if (inner.length !== 1) {
      throw new Error("krb5: context tag [" + n + "] wraps " + inner.length + 
          " elements, expected 1");
    }
    map[n] = inner[0];
  });
  return map;
}

function expectTag(t, tag, what) {
  if (t.tag !== tag) {
    throw new Error("krb5: expected " + what + " (tag 0x" + tag.toString(16) +
      ") but found tag 0x" + t.tag.toString(16));
  }
  return t;
}

function decInteger(t) {
  expectTag(t, TAG.INTEGER, "an INTEGER");
  var b = t.value;
  if (b.length === 0) {
    throw new Error("krb5: zero-length INTEGER");
  }
  if (b.length > 6) {
    throw new Error("krb5: INTEGER of " + b.length + " bytes is out of range " +
        "for this coder");
  }
  var negative = (b[0] & 0x80) !== 0;
  var v = 0;
  for (var i = 0; i < b.length; i++) v = v * 256 + b[i];
  return negative ? v - Math.pow(2, 8 * b.length) : v;
}

function decOctetString(t) {
  expectTag(t, TAG.OCTET_STRING, "an OCTET STRING");
  return t.value;
}

function decGeneralString(t) {
  // GeneralString is what RFC 4120 specifies, but IA5String turns up in the
  // wild from implementations that took the "IA5 subset" note as licence.
  // Accepting both costs nothing and refusing it would reject real traffic.
  if (t.tag !== TAG.GENERAL_STRING && t.tag !== TAG.IA5_STRING) {
    expectTag(t, TAG.GENERAL_STRING, "a KerberosString");
  }
  var s = "";
  for (var i = 0; i < t.value.length; i++) s += String.fromCharCode(t.value[i]);
  return s;
}

function decKerberosTime(t) {
  expectTag(t, TAG.GENERALIZED_TIME, "a KerberosTime");
  return parseKerberosTime(decLatin1(t.value));
}

function decLatin1(bytes) {
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

function decFlags(t) {
  expectTag(t, TAG.BIT_STRING, "a KerberosFlags BIT STRING");
  if (t.value.length < 1) {
    throw new Error("krb5: empty BIT STRING");
  }
  // The first content octet is the count of unused trailing bits.
  return t.value.subarray(1);
}

function decSequenceOf(t) {
  expectTag(t, TAG.SEQUENCE, "a SEQUENCE");
  return readChildren(t.value);
}

// Unwrap [APPLICATION n] and return the SEQUENCE inside it.
function readApplication(bytes, expectedNumber) {
  log.debug("Entering readApplication().");
  var b = toBytes(bytes);
  if (b.length > MAX_INPUT_BYTES) {
    log.debug("Leaving readApplication().");
    throw new Error("krb5: refusing to parse " + b.length + " bytes (limit " + 
        MAX_INPUT_BYTES + ")");
  }
  var outer = readTlv(b, 0, 0);
  if ((outer.tag & 0xe0) !== 0x60) {
    log.debug("Leaving readApplication().");
    throw new Error("krb5: not a Kerberos message — the outermost tag is 0x" +
      outer.tag.toString(16) + ", expected an [APPLICATION n] constructed " +
          "tag (0x60-0x7e)");
  }
  var number = outer.tag & 0x1f;
  if (expectedNumber !== undefined && number !== expectedNumber) {
    log.debug("Leaving readApplication().");
    throw new Error("krb5: expected [APPLICATION " + expectedNumber + 
        "] but found [APPLICATION " + number + "]");
  }
  var inner = readChildren(outer.value, 1);
  if (inner.length !== 1) {
    log.debug("Leaving readApplication().");
    throw new Error("krb5: [APPLICATION " + number + "] wraps " + 
        inner.length + " elements, expected 1");
  }
  expectTag(inner[0], TAG.SEQUENCE, "the SEQUENCE inside [APPLICATION " + 
      number + "]");
  log.debug("Leaving readApplication().");
  return { applicationNumber: number, sequence: inner[0], outer: outer };
}

// The application number without parsing anything else — how the api's relay
// decides whether a payload is a Kerberos request at all, and how the decoder
// page picks which reader to run.
function peekApplicationNumber(bytes) {
  var b = toBytes(bytes);
  if (b.length < 2) {
    return null;
  }
  if ((b[0] & 0xe0) !== 0x60) {
    return null;
  }
  return b[0] & 0x1f;
}

// ---------------------------------------------------------------------------
// A generic structural tree, for bytes this codec cannot identify.
//
// The decoder page's fallback: when a paste is not a message any reader knows,
// showing its TLV structure is far more useful than "could not parse". It also
// makes a codec bug visible — a field in the wrong context tag is obvious here
// and invisible in a semantic view that skipped it.
// ---------------------------------------------------------------------------
var TAG_NAMES = {
  0x01: "BOOLEAN",
  0x02: "INTEGER",
  0x03: "BIT STRING",
  0x04: "OCTET STRING",
  0x05: "NULL",
  0x06: "OBJECT IDENTIFIER",
  0x0c: "UTF8String",
  0x10: "SEQUENCE",
  0x11: "SET",
  0x13: "PrintableString",
  0x16: "IA5String",
  0x17: "UTCTime",
  0x18: "GeneralizedTime",
  0x1b: "GeneralString",
  0x30: "SEQUENCE",
  0x31: "SET"
};

function describeTag(tag) {
  log.debug("Entering describeTag().");
  var cls = tag & 0xc0;
  var constructed = (tag & 0x20) !== 0;
  var number = tag & 0x1f;
  if (cls === 0x00) {
    log.debug("Leaving describeTag().");
    return TAG_NAMES[tag] || TAG_NAMES[number] || ("universal " + number);
  }
  if (cls === 0x40) {
    log.debug("Leaving describeTag().");
    return "[APPLICATION " + number + "]";
  }
  if (cls === 0x80) {
    log.debug("Leaving describeTag().");
    return "[" + number + "]";
  }
  log.debug("Leaving describeTag().");
  return "[PRIVATE " + number + "]" + (constructed ? "" : " primitive");
}

// Is this value plausibly a nested structure rather than opaque bytes? Used
// only to decide whether to recurse for display; a wrong guess costs a prettier
// tree, not correctness.
function looksConstructed(t) {
  if ((t.tag & 0x20) === 0) {
    return false;
  }
  if (t.length === 0) {
    return false;
  }
  try {
    var children = readChildren(t.value, 0);
    return children.length > 0 && 
        children[children.length - 1].end === t.value.length;
  } catch (e) {
    // Not parseable as a sequence of elements: treat as opaque.
    return false;
  }
}

function tree(bytes, depth) {
  log.debug("Entering tree().");
  var d = depth || 0;
  var b = toBytes(bytes);
  if (b.length > MAX_INPUT_BYTES) {
    log.debug("Leaving tree().");
    throw new Error("krb5: refusing to parse " + b.length + " bytes (limit " + 
        MAX_INPUT_BYTES + ")");
  }
  var out = [];
  var at = 0;
  while (at < b.length) {
    var t = readTlv(b, at, d);
    var node = {
      tag: t.tag,
      tagName: describeTag(t.tag),
      offset: t.start,
      length: t.length,
      bytes: t.value
    };
    if (looksConstructed(t)) {
      if (d < MAX_DEPTH) {
        node.children = tree(t.value, d + 1);
      } else {
        // The depth limit is a display cap, not a parse error: bytes pasted
        // into the decoder page should still render as far as they go. But it
        // must be VISIBLE, because a constructed element rendered as a hex leaf
        // reads as "this is opaque data" — the opposite of the truth, and
        // exactly the kind of silent cap that makes a tool lie about what it
        // examined.
        node.depthLimited = true;
        node.text = "(nesting deeper than " + MAX_DEPTH + " levels — not " +
            "expanded; " +
                    t.length + " bytes)";
      }
    } else {
      node.text = renderPrimitive(t);
    }
    out.push(node);
    at = t.end;
  }
  log.debug("Leaving tree().");
  return out;
}

// A readable rendering of a primitive value for the tree view. Deliberately
// tolerant: this runs on bytes that may not be what their tag claims.
function renderPrimitive(t) {
  log.debug("Entering renderPrimitive().");
  try {
    if (t.tag === TAG.INTEGER) {
      log.debug("Leaving renderPrimitive().");
      return String(decInteger(t));
    }
    if (t.tag === TAG.GENERAL_STRING || t.tag === TAG.IA5_STRING) {
      log.debug("Leaving renderPrimitive().");
      return decLatin1(t.value);
    }
    if (t.tag === TAG.GENERALIZED_TIME) {
      log.debug("Leaving renderPrimitive().");
      return decLatin1(t.value);
    }
    if (t.tag === TAG.BIT_STRING && t.value.length === 5) {
      log.debug("Leaving renderPrimitive().");
      return "bits set: " + (bitsFromFlags(t.value.subarray(1)).join(", ") || 
          "(none)");
    }
  } catch (e) {
    // Fall through to hex: a value that does not decode as its tag claims is
    // exactly what the reader is here to show.
  }
  var hex = prim.toHex(t.value);
  log.debug("Leaving renderPrimitive().");
  return hex.length > 128 ? hex.slice(0, 128) + "… (" + t.value.length + 
      " bytes)" : hex;
}

module.exports = {
  TAG: TAG,
  MAX_INPUT_BYTES: MAX_INPUT_BYTES,
  contextTag: contextTag,
  applicationTag: applicationTag,
  // writing
  tlv: tlv,
  encodeLength: encodeLength,
  integerContent: integerContent,
  encInteger: encInteger,
  encOctetString: encOctetString,
  encGeneralString: encGeneralString,
  encFlags: encFlags,
  encKerberosTime: encKerberosTime,
  encSequence: encSequence,
  encSequenceOf: encSequenceOf,
  encTaggedSequence: encTaggedSequence,
  encApplication: encApplication,
  encContext: encContext,
  flagsFromBits: flagsFromBits,
  bitsFromFlags: bitsFromFlags,
  formatKerberosTime: formatKerberosTime,
  parseKerberosTime: parseKerberosTime,
  // reading
  readTlv: readTlv,
  readChildren: readChildren,
  readTaggedSequence: readTaggedSequence,
  readApplication: readApplication,
  peekApplicationNumber: peekApplicationNumber,
  expectTag: expectTag,
  decInteger: decInteger,
  decOctetString: decOctetString,
  decGeneralString: decGeneralString,
  decKerberosTime: decKerberosTime,
  decFlags: decFlags,
  decSequenceOf: decSequenceOf,
  decLatin1: decLatin1,
  // display
  tree: tree,
  describeTag: describeTag
};
