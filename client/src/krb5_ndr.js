// File: krb5_ndr.js
//
// ---------------------------------------------------------------------------
// Just enough NDR to read and write the Windows PAC's logon information.
//
// NDR is the RPC marshalling of [MS-RPCE], and nothing else in Kerberos prepares
// you for it: the whole of RFC 4120 is ASN.1 DER, and then one authorization-data
// element arrives in a completely different encoding because it came from a
// different part of Windows. This file is the reader and writer for that, and it is
// deliberately not a general NDR implementation — it covers the constructs
// KERB_VALIDATION_INFO actually uses and refuses the rest rather than guessing.
//
// ---------------------------------------------------------------------------
// FIVE RULES, and every one of them is a SILENT corruption when broken. None of
// them produces an exception or an out-of-range value; each produces a structure
// that parses cleanly and says something false.
//
//  1. **Everything is little-endian.** The opposite of the wire format the rest of
//     Kerberos uses. A big-endian read produces plausible-looking garbage: a SID's
//     sub-authority count becomes 16 million, a RID becomes an address.
//  2. **Alignment is by natural size, measured from the START OF THE STREAM.** A
//     4-byte field is preceded by padding until the offset is a multiple of 4; an
//     8-byte field until a multiple of 8. Miss one pad byte and every field after it
//     is read from the wrong place — and the values stay in range, so nothing looks
//     wrong.
//  3. **`FILETIME` IS NOT A 64-BIT INTEGER.** It is `struct { DWORD dwLowDateTime;
//     DWORD dwHighDateTime; }` ([MS-DTYP]), so its members are 4-byte and its
//     alignment is **4**, not 8. Reading it with an 8-aligned 64-bit read inserts
//     padding NDR never wrote. It happens to be harmless for the six FILETIMEs at
//     the top of KERB_VALIDATION_INFO, because they sit at struct offsets 0, 8, 16…
//     anyway — and that is exactly what makes it dangerous, since the bug hides
//     until it reaches `LastSuccessfulILogon` halfway down. Note the consequence:
//     KERB_VALIDATION_INFO contains no 8-aligned member at all, so a correct reader
//     never pads inside it, and its fixed part is completely dense.
//  4. **Pointers are REFERENT IDS, not offsets.** A non-zero 4-byte value means "the
//     pointed-to data is present, and it appears LATER in the stream". Zero means
//     NULL. The data does not live at that number. So a reader takes placeholders
//     while walking the fixed part and then reads the deferred parts afterwards, IN
//     FIELD ORDER. For an ARRAY of structures containing pointers, all the elements'
//     fixed parts come first and only then the referents — reading each element's
//     pointer target as it goes gets the right answer for a one-element array and
//     the wrong one for every longer array, which is a bug that ships.
//  5. **Conformant arrays carry their own count, again.** A `[size_is(n)]` array is
//     preceded in its deferred position by a 4-byte maximum count, normally equal to
//     the count already read in the fixed part — but it is what governs the read, and
//     trusting the earlier copy is how a malformed PAC becomes an over-read.
//
// The reader is BOUNDED: a maximum length, a credible-array-size limit, and every
// read checked against the buffer rather than against a length the buffer itself
// declared. These are bytes out of a ticket issued by somebody else's KDC.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_ndr",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var MAX_NDR_BYTES = 1024 * 1024;
// A PAC listing more groups than this is not a PAC. Windows' own practical
// limit is far lower, and an unbounded count is an allocation an attacker
// chooses.
var MAX_ARRAY_ELEMENTS = 8192;

// ---------------------------------------------------------------------------
// Reading.
// ---------------------------------------------------------------------------

function createReader(bytes) {
  log.debug("Entering createReader().");
  var b = prim.toBytes(bytes);
  if (b.length > MAX_NDR_BYTES) {
    log.debug("Leaving createReader().");
    throw new Error("krb5: refusing to read " + b.length + " bytes of NDR " +
        "(limit " + MAX_NDR_BYTES + ")");
  }
  var at = 0;

  function need(n, what) {
    if (at + n > b.length) {
      throw new Error("krb5: NDR ran off the end reading " + (what || (n +
          " bytes")) + " at offset " +
        at + " (" + (b.length - at) + " byte(s) remain of " + b.length + ")");
    }
  }

  function align(size) {
    var pad = (size - (at % size)) % size;
    need(pad, "alignment padding");
    at += pad;
  }

  function u32() {
    align(4); need(4, "a 32-bit value");
    var v = ((b[at]) | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at +
        3] << 24)) >>> 0;
    at += 4;
    return v;
  }

  var r = {
    get offset() { return at; },
    get length() { return b.length; },
    get remaining() { return b.length - at; },
    seek: function (n) {
      if (n < 0 || n > b.length) {
        throw new Error("krb5: cannot seek to " + n + " in a " + b.length +
            "-byte NDR stream");
      }
      at = n;
    },
    align: align,
    u8: function () { need(1, "a byte"); return b[at++]; },
    u16: function () {
      align(2); need(2, "a 16-bit value");
      var v = b[at] | (b[at + 1] << 8);
      at += 2;
      return v;
    },
    u32: u32,
    // A genuine 8-aligned ULONG64. The PAC's own header uses one;
    // KERB_VALIDATION_INFO does not — see rule 3.
    u64: function () {
      align(8); need(8, "a 64-bit value");
      var lo = ((b[at]) | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at +
          3] << 24)) >>> 0;
      var hi = ((b[at + 4]) | (b[at + 5] << 8) | (b[at + 6] << 16) | (b[at +
          7] << 24)) >>> 0;
      at += 8;
      return { low: lo, high: hi, value: hi * 0x100000000 + lo };
    },
    bytes: function (n) {
      need(n, n + " bytes");
      var out = b.subarray(at, at + n);
      at += n;
      return out;
    },
    // A referent id: non-zero means the data follows later in the stream, zero
    // means NULL. It is NOT an offset, and that distinction is rule 4.
    pointer: function () { return u32() !== 0; },
    arrayCount: function (what) {
      log.debug("Entering arrayCount().");
      var n = u32();
      if (n > MAX_ARRAY_ELEMENTS) {
        log.debug("Leaving arrayCount().");
        throw new Error("krb5: an NDR array of " + n + " " + (what ||
            "element(s)") +
          " is not credible (limit " + MAX_ARRAY_ELEMENTS + "). Check the " +
              "byte order — NDR is " +
          "LITTLE-endian, unlike the rest of Kerberos.");
      }
      log.debug("Leaving arrayCount().");
      return n;
    }
  };
  log.debug("Leaving createReader().");
  return r;
}

// FILETIME: 100-nanosecond intervals since 1601-01-01 UTC, as TWO 32-bit halves
// (rule 3). Two sentinel values are meaningful rather than exceptional, and a
// reader that rendered them as dates in the year 30828 would be technically
// right and useless.
var FILETIME_EPOCH_DIFFERENCE_MS = 11644473600000;

function readFileTime(r) {
  log.debug("Entering readFileTime().");
  var lo = r.u32();
  var hi = r.u32();
  if (hi === 0x7fffffff && lo === 0xffffffff) {
    log.debug("Leaving readFileTime().");
    return {
      low: lo,
      high: hi,
      never: true,
      text: "(never — 0x7FFFFFFFFFFFFFFF)",
      date: null
    };
  }
  if (hi === 0 && lo === 0) {
    log.debug("Leaving readFileTime().");
    return {
      low: lo,
      high: hi,
      unset: true,
      text: "(not set — zero)",
      date: null
    };
  }
  var date = new Date((hi * 0x100000000 +
      lo) / 10000 - FILETIME_EPOCH_DIFFERENCE_MS);
  log.debug("Leaving readFileTime().");
  return {
    low: lo,
    high: hi,
    date: date,
    text: isNaN(date.getTime()) ? "(unreadable)" : date.toISOString()
  };
}

function fileTimeFromDate(date) {
  log.debug("Entering fileTimeFromDate().");
  if (date === null || date === undefined) {
    log.debug("Leaving fileTimeFromDate().");
    return { low: 0, high: 0 };
  }
  if (date === "never") {
    log.debug("Leaving fileTimeFromDate().");
    return { low: 0xffffffff, high: 0x7fffffff };
  }
  var t = (date instanceof Date ? date.getTime() : Number(date)) +
      FILETIME_EPOCH_DIFFERENCE_MS;
  var ticks = Math.round(t) * 10000;
  log.debug("Leaving fileTimeFromDate().");
  return { low: ticks % 0x100000000, high: Math.floor(ticks / 0x100000000) };
}

// RPC_UNICODE_STRING: Length and MaximumLength in BYTES (not characters), then
// a referent id. The characters arrive later, in field order.
function readUnicodeStringHeader(r) {
  log.debug("Entering readUnicodeStringHeader().");
  var length = r.u16();
  var maximumLength = r.u16();
  var present = r.pointer();
  log.debug("Leaving readUnicodeStringHeader().");
  return {
    length: length,
    maximumLength: maximumLength,
    present: present,
    value: null
  };
}

// The deferred half: a conformant VARYING array of UTF-16LE code units, so it
// carries both a maximum count and an actual count with an offset between them.
function readUnicodeStringValue(r, header) {
  log.debug("Entering readUnicodeStringValue().");
  if (!header.present) {
    header.value = null;
    log.debug("Leaving readUnicodeStringValue().");
    return header;
  }
  var maxCount = r.arrayCount("UTF-16 code unit(s)");
  var offset = r.u32();
  var actualCount = r.arrayCount("UTF-16 code unit(s)");
  if (offset !== 0) {
    // Legal NDR, but Windows does not emit it here, and honouring it silently
    // would conceal a structure that is really being misread.
    log.debug("Leaving readUnicodeStringValue().");
    throw new Error("krb5: an RPC_UNICODE_STRING with a non-zero array " +
        "offset (" + offset +
      ") — Windows does not emit that, so this PAC is malformed or is being " +
          "read at the wrong offset");
  }
  if (actualCount > maxCount) {
    log.debug("Leaving readUnicodeStringValue().");
    throw new Error("krb5: an RPC_UNICODE_STRING claims " + actualCount +
        " characters in an array " +
      "of at most " + maxCount);
  }
  var s = "";
  for (var i = 0; i < actualCount; i++) s += String.fromCharCode(r.u16());
  // Windows does not count a terminator in Length, but some producers do. Trim
  // only TRAILING NULs: one in the middle is corruption worth seeing, not worth
  // hiding.
  while (s.length && s.charCodeAt(s.length - 1) === 0) s = s.slice(0, -1);
  header.value = s;
  log.debug("Leaving readUnicodeStringValue().");
  return header;
}

// RPC_SID, plus the canonical display form — a SID is what a Windows service
// actually authorizes against, so `S-1-5-21-…` matters more here than the bytes
// do.
function readSid(r) {
  log.debug("Entering readSid().");
  var revision = r.u8();
  var subAuthorityCount = r.u8();
  if (subAuthorityCount > 15) {
    log.debug("Leaving readSid().");
    throw new Error("krb5: a SID with " + subAuthorityCount + " " +
        "sub-authorities (the maximum is 15) " +
      "— this is not a SID, or it is being read at the wrong offset");
  }
  var authorityBytes = r.bytes(6);
  // The identifier authority is the ONE big-endian field in the structure. That
  // kind of inconsistency is why this reader is hand-written.
  var authority = 0;
  for (var i = 0; i < 6; i++) authority = authority * 256 + authorityBytes[i];
  var subAuthorities = [];
  for (var j = 0; j < subAuthorityCount; j++) subAuthorities.push(r.u32());
  log.debug("Leaving readSid().");
  return {
    revision: revision,
    authority: authority,
    subAuthorities: subAuthorities,
    text: "S-" + revision + "-" + authority + (subAuthorities.length ? "-" +
        subAuthorities.join("-") : "")
  };
}

// A pointed-to SID: the deferred form is a conformant structure, so its
// sub-authority count appears AHEAD of the structure as well as inside it, and
// the two must agree.
function readConformantSid(r) {
  var declaredCount = r.arrayCount("SID sub-authorit(ies)");
  var sid = readSid(r);
  if (declaredCount !== sid.subAuthorities.length) {
    throw new Error("krb5: a SID's conformant count (" + declaredCount +
        ") does not match its own " +
      "sub-authority count (" + sid.subAuthorities.length + ")");
  }
  return sid;
}

function parseSidText(text) {
  log.debug("Entering parseSidText().");
  var m = /^S-(\d+)-(\d+)((?:-\d+)*)$/.exec(String(text || "").trim());
  if (!m) {
    log.debug("Leaving parseSidText().");
    throw new Error("krb5: '" + text + "' is not a SID in S-R-A-S… form");
  }
  var subs = m[3] ? m[3].split("-").slice(1).map(Number) : [];
  if (subs.length > 15) {
    log.debug("Leaving parseSidText().");
    throw new Error("krb5: a SID may have at most 15 sub-authorities");
  }
  log.debug("Leaving parseSidText().");
  return {
    revision: Number(m[1]),
    authority: Number(m[2]),
    subAuthorities: subs,
    text: m[0]
  };
}

function sidWithRid(sid, rid) {
  return (sid ? sid.text : "(no domain SID)") + "-" + rid;
}

// ---------------------------------------------------------------------------
// Writing.
//
// The writer exists so the mock KDC can mint a PAC and so the tests can build one
// by hand and read it back with the reader above. Round-tripping through our own
// pair proves consistency and NOT correctness — the two halves can agree on the same
// mistake — so the tests also check the bytes against fixed offsets taken from
// [MS-PAC] and read a capture produced elsewhere.
// ---------------------------------------------------------------------------

function createWriter() {
  log.debug("Entering createWriter().");
  var chunks = [];
  var at = 0;
  // Referent ids are arbitrary and non-zero; Windows hands them out from
  // 0x00020000 upward in steps of 4, and matching that makes a hand comparison
  // with a real capture readable.
  var nextReferent = 0x00020000;

  function push(arr) {
    chunks.push(arr);
    at += arr.length;
  }

  var w = {
    get offset() { return at; },
    align: function (size) {
      var pad = (size - (at % size)) % size;
      if (pad) push(new Uint8Array(pad));
    },
    u8: function (v) { push(new Uint8Array([v & 0xff])); return w; },
    u16: function (v) {
      w.align(2);
      push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff]));
      return w;
    },
    u32: function (v) {
      w.align(4);
      push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff,
          (v >>> 24) & 0xff]));
      return w;
    },
    u64: function (lo, hi) {
      w.align(8);
      push(new Uint8Array([
        lo & 0xff, (lo >>> 8) & 0xff, (lo >>> 16) & 0xff, (lo >>> 24) & 0xff,
        hi & 0xff, (hi >>> 8) & 0xff, (hi >>> 16) & 0xff, (hi >>> 24) & 0xff
      ]));
      return w;
    },
    bytes: function (b) { push(prim.toBytes(b)); return w; },
    zeros: function (n) { push(new Uint8Array(n)); return w; },
    // A non-NULL referent id, or NULL.
    pointer: function (present) {
      if (!present) {
        return w.u32(0);
      }
      var id = nextReferent;
      nextReferent += 4;
      return w.u32(id);
    },
    fileTime: function (date) {
      var ft = fileTimeFromDate(date);
      // Two 32-bit halves, NOT an 8-aligned u64 — rule 3.
      w.u32(ft.low);
      w.u32(ft.high);
      return w;
    },
    build: function () {
      var out = new Uint8Array(at), o = 0;
      chunks.forEach(function (c) { out.set(c, o); o += c.length; });
      return out;
    },
    // Overwrite four bytes already emitted — needed for a length that is only
    // known once the rest is encoded.
    patchU32: function (offset, v) {
      var out = w.build();
      out[offset] = v & 0xff;
      out[offset + 1] = (v >>> 8) & 0xff;
      out[offset + 2] = (v >>> 16) & 0xff;
      out[offset + 3] = (v >>> 24) & 0xff;
      chunks = [out];
      return w;
    }
  };
  log.debug("Leaving createWriter().");
  return w;
}

// The fixed half of an RPC_UNICODE_STRING. Lengths are in BYTES; Windows sets
// MaximumLength equal to Length here (no terminator), and a reader that assumed
// otherwise would read a stray character.
function writeUnicodeStringHeader(w, value) {
  var present = value !== null && value !== undefined;
  var bytesLength = present ? value.length * 2 : 0;
  w.u16(bytesLength);
  w.u16(bytesLength);
  w.pointer(present);
}

function writeUnicodeStringValue(w, value) {
  if (value === null || value === undefined) {
    return;
  }
  w.u32(value.length);   // maximum count
  w.u32(0);              // offset
  w.u32(value.length);   // actual count
  for (var i = 0; i < value.length; i++) w.u16(value.charCodeAt(i));
}

function writeSid(w, sid) {
  var s = typeof sid === "string" ? parseSidText(sid) : sid;
  w.u8(s.revision);
  w.u8(s.subAuthorities.length);
  var a = new Uint8Array(6), v = s.authority;
  for (var i = 5; i >= 0; i--) { a[i] = v % 256; v = Math.floor(v / 256); }
  w.bytes(a);
  s.subAuthorities.forEach(function (sub) { w.u32(sub); });
}

function writeConformantSid(w, sid) {
  var s = typeof sid === "string" ? parseSidText(sid) : sid;
  w.u32(s.subAuthorities.length);   // the conformance, ahead of the structure
  writeSid(w, s);
}

// ---------------------------------------------------------------------------
// The [MS-RPCE] section 2.2.6 type-marshalling headers, which wrap any structure
// serialized on its own rather than as an RPC parameter. Sixteen bytes, and the PAC's
// logon information is the only place in Kerberos you will meet them:
//
//   common header  (8): Version=1, Endianness=0x10 (little-endian, ASCII),
//                       CommonHeaderLength=8, Filler=0xCCCCCCCC
//   private header (8): ObjectBufferLength, Filler=0
//
// The 0xCC filler is not decoration — it is how you recognise these sixteen bytes in
// a hex dump, and `01 10 08 00 cc cc cc cc` at the front of a buffer is the reliable
// sign that what follows is NDR rather than DER.
// ---------------------------------------------------------------------------

var TYPE_MARSHALLING_HEADER_BYTES = 16;

function writeTypeMarshallingHeaders(w) {
  w.u8(1);                                        // Version
  w.u8(0x10);                                     // little-endian, ASCII
  w.u16(8);                                       // CommonHeaderLength
  w.bytes([0xcc, 0xcc, 0xcc, 0xcc]);              // Filler
  w.u32(0);                                       // ObjectBufferLength — patched later
  w.u32(0);                                       // Filler
  return 8;                                       // the offset of ObjectBufferLength
}

function readTypeMarshallingHeaders(r) {
  log.debug("Entering readTypeMarshallingHeaders().");
  var version = r.u8();
  var endianness = r.u8();
  var commonHeaderLength = r.u16();
  var filler = r.bytes(4);
  var objectBufferLength = r.u32();
  r.u32();                                        // private-header filler
  if (version !== 1) {
    log.debug("Leaving readTypeMarshallingHeaders().");
    throw new Error("krb5: NDR type-marshalling version " + version +
        ", expected 1");
  }
  if (endianness !== 0x10) {
    log.debug("Leaving readTypeMarshallingHeaders().");
    throw new Error("krb5: this NDR stream declares byte order 0x" +
        endianness.toString(16) +
      "; only 0x10 (little-endian, ASCII) is handled. 0x00 would be " +
          "big-endian NDR, which " +
      "Windows does not emit.");
  }
  if (commonHeaderLength !== 8) {
    log.debug("Leaving readTypeMarshallingHeaders().");
    throw new Error("krb5: NDR common header length " + commonHeaderLength +
        ", expected 8");
  }
  log.debug("Leaving readTypeMarshallingHeaders().");
  return {
    version: version,
    endianness: endianness,
    objectBufferLength: objectBufferLength,
    filler: prim.toHex(filler)
  };
}

module.exports = {
  createReader: createReader,
  createWriter: createWriter,
  readFileTime: readFileTime,
  fileTimeFromDate: fileTimeFromDate,
  readUnicodeStringHeader: readUnicodeStringHeader,
  readUnicodeStringValue: readUnicodeStringValue,
  writeUnicodeStringHeader: writeUnicodeStringHeader,
  writeUnicodeStringValue: writeUnicodeStringValue,
  readSid: readSid,
  readConformantSid: readConformantSid,
  writeSid: writeSid,
  writeConformantSid: writeConformantSid,
  parseSidText: parseSidText,
  sidWithRid: sidWithRid,
  writeTypeMarshallingHeaders: writeTypeMarshallingHeaders,
  readTypeMarshallingHeaders: readTypeMarshallingHeaders,
  TYPE_MARSHALLING_HEADER_BYTES: TYPE_MARSHALLING_HEADER_BYTES,
  FILETIME_EPOCH_DIFFERENCE_MS: FILETIME_EPOCH_DIFFERENCE_MS,
  MAX_NDR_BYTES: MAX_NDR_BYTES,
  MAX_ARRAY_ELEMENTS: MAX_ARRAY_ELEMENTS
};
