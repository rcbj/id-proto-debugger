// File: krb5_keytab.js
//
// ---------------------------------------------------------------------------
// MIT keytab files, read-only.
//
// A keytab is how a service holds its long-term key, and it is the thing that
// turns the decoder page from "here is the shape of your ticket" into "here is
// what is INSIDE your ticket" — a service ticket's enc-part is encrypted under
// the service's key, and the keytab is where that key lives. Being able to paste
// one in is the difference between reading the envelope and reading the letter.
//
// Two format details that are not optional:
//
//  * **Version 0x0501 is LITTLE-endian and 0x0502 is BIG-endian.** The same file
//    structure, byte order reversed, distinguished only by the two-byte header.
//    Reading a 0x0501 keytab as big-endian gives component counts in the tens of
//    thousands and a parse that fails somewhere unrelated.
//  * **A NEGATIVE entry size marks a deleted slot.** `ktutil` does not compact
//    the file when a key is removed; it flips the sign of the length so the space
//    can be reused. Treating that as a length walks off the end of the buffer;
//    treating it as the end of the file loses every entry after the first
//    deletion.
//
// Nothing here writes a keytab. Generating one is a credential-creation
// operation, and this page's job is to explain what somebody already has.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var kcrypto = require("./krb5_crypto.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_keytab",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var MAX_KEYTAB_BYTES = 1024 * 1024;
var MAX_ENTRIES = 4096;

function reader(bytes, bigEndian) {
  log.debug("Entering reader().");
  var b = prim.toBytes(bytes);
  var at = 0;
  log.debug("Leaving reader().");
  return {
    get offset() { return at; },
    get remaining() { return b.length - at; },
    seek: function (n) { at = n; },
    skip: function (n) { at += n; },
    u8: function () {
      if (at + 1 > b.length) {
        throw new Error("krb5: keytab truncated at offset " + at);
      }
      return b[at++];
    },
    u16: function () {
      if (at + 2 > b.length) {
        throw new Error("krb5: keytab truncated at offset " + at);
      }
      var v = bigEndian ? (b[at] << 8) | b[at + 1] : (b[at + 1] << 8) | b[at];
      at += 2;
      return v;
    },
    i32: function () {
      if (at + 4 > b.length) {
        throw new Error("krb5: keytab truncated at offset " + at);
      }
      var v = bigEndian
        ? (b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]
        : (b[at + 3] << 24) | (b[at + 2] << 16) | (b[at + 1] << 8) | b[at];
      at += 4;
      return v | 0;                          // signed: a negative size is a deleted slot
    },
    u32: function () { return this.i32() >>> 0; },
    countedString: function () {
      log.debug("Entering countedString().");
      var n = this.u16();
      if (at + n > b.length) {
        log.debug("Leaving countedString().");
        throw new Error("krb5: keytab string of " + n + " bytes runs past " +
            "the end");
      }
      var s = "";
      for (var i = 0; i < n; i++) s += String.fromCharCode(b[at + i]);
      at += n;
      log.debug("Leaving countedString().");
      return s;
    },
    countedBytes: function () {
      var n = this.u16();
      if (at + n > b.length) {
        throw new Error("krb5: keytab key of " + n + " bytes runs past the " +
            "end");
      }
      var out = b.subarray(at, at + n);
      at += n;
      return out;
    }
  };
}

function parseKeytab(bytes) {
  log.debug("Entering parseKeytab().");
  var b = prim.toBytes(bytes);
  if (b.length > MAX_KEYTAB_BYTES) {
    throw new Error("krb5: refusing to parse a " + b.length + "-byte keytab " +
        "(limit " + MAX_KEYTAB_BYTES + ")");
  }
  if (b.length < 4) {
    throw new Error("krb5: too short to be a keytab");
  }
  if (b[0] !== 0x05) {
    throw new Error("krb5: not a keytab — it must start with 0x05, this " +
        "starts with 0x" +
      b[0].toString(16) + ". (A base64 keytab pasted as text is the usual " +
          "cause.)");
  }
  var version = b[1];
  if (version !== 0x01 && version !== 0x02) {
    throw new Error("krb5: keytab format version 0x05" + ("0" +
        version.toString(16)).slice(-2) +
      " is not one this reader knows (expected 0x0501 or 0x0502)");
  }
  var bigEndian = (version === 0x02);
  var r = reader(b, bigEndian);
  r.seek(2);

  var entries = [];
  var deleted = 0;
  while (r.remaining >= 4 && entries.length + deleted < MAX_ENTRIES) {
    var start = r.offset;
    var size = r.i32();
    if (size === 0) break;                   // padding at the end of the file
    if (size < 0) {
      // A deleted slot. Its space is still reserved, so skip |size| bytes and
      // keep going: entries after a deletion are perfectly valid, and stopping
      // here would silently lose them.
      deleted++;
      r.seek(start + 4 + Math.abs(size));
      continue;
    }
    var entryEnd = start + 4 + size;
    if (entryEnd > b.length) {
      // An implausibly large entry size in a small file is almost never a
      // truncated file — it is the byte order being wrong, because the same
      // four bytes read the other way round are a sensible number. Saying so
      // here is the difference between a five-minute fix and an afternoon: the
      // header is the ONLY thing that declares the order, and a keytab copied
      // between architectures or produced by a non-MIT tool is exactly how it
      // goes wrong.
      var hint = "";
      if (size > 0xffff) {
        hint = " — a size that large in a " + b.length + "-byte file almost " +
            "always means the BYTE " +
          "ORDER is wrong. This file declares version 0x05" +
          ("0" + version.toString(16)).slice(-2) + ", i.e. " + (bigEndian ?
              "big" : "little") +
          "-endian; read the other way those four bytes are " +
          (bigEndian
            ? ((b[start + 3] << 24) | (b[start + 2] << 16) | (b[start +
                1] << 8) | b[start]) >>> 0
            : ((b[start] << 24) | (b[start + 1] << 16) | (b[start +
                2] << 8) | b[start + 3]) >>> 0) +
          ".";
      }
      throw new Error("krb5: keytab entry at offset " + start + " claims " +
          size +
        " bytes but only " + (b.length - start - 4) + " remain" + hint);
    }
    var numComponents = r.u16();
    if (version === 0x01) numComponents -= 1;      // 0x0501 counts the realm
    if (numComponents < 0 || numComponents > 16) {
      throw new Error("krb5: keytab entry at offset " + start + " claims " +
          numComponents +
        " name components, which is not credible — is the byte order right? " +
        "(this file declares version 0x05" + ("0" +
            version.toString(16)).slice(-2) + ")");
    }
    var realm = r.countedString();
    var components = [];
    for (var i = 0; i < numComponents; i++) components.push(r.countedString());
    var nameType = (version === 0x02) ? r.u32() : 0;
    var timestamp = r.u32();
    var vno8 = r.u8();
    var keyType = r.u16();
    var keyValue = r.countedBytes();
    // vno32 is present only if there is room for it inside this entry — which
    // is how the format expresses "optional" with no flag.
    var kvno = vno8;
    if (entryEnd - r.offset >= 4) kvno = r.u32();
    r.seek(entryEnd);

    entries.push({
      realm: realm,
      components: components,
      principal: components.join("/") + "@" + realm,
      nameType: nameType,
      timestamp: timestamp ? new Date(timestamp * 1000) : null,
      kvno: kvno,
      etype: keyType,
      etypeName: kcrypto.etypeName(keyType),
      supported: kcrypto.isSupportedEtype(keyType),
      key: keyValue
    });
  }
  log.debug("Leaving parseKeytab(). entries=" + entries.length +
      ", deleted slots=" + deleted);
  return {
    version: 0x0500 | version,
    bigEndian: bigEndian,
    entries: entries,
    deletedSlots: deleted
  };
}

// The keys from a keytab in the shape the decoder's decryption wants.
function keysFromKeytab(parsed) {
  log.debug("Leaving keysFromKeytab().");
  log.debug("Entering keysFromKeytab().");
  return (parsed.entries ||
      []).filter(function (e) { return e.supported; }).map(function (e) {
    return {
      etype: e.etype,
      key: e.key,
      label: "keytab " + e.principal + " (kvno " + e.kvno + ", " +
          e.etypeName + ")"
    };
  });
}

module.exports = {
  parseKeytab: parseKeytab,
  keysFromKeytab: keysFromKeytab,
  MAX_KEYTAB_BYTES: MAX_KEYTAB_BYTES
};
