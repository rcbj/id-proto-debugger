// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes.js
//
// ---------------------------------------------------------------------------
// W3C Verifiable Credential Barcodes v1.0 (Working Draft, 22 August 2026,
// https://www.w3.org/TR/vc-barcodes/): a credential printed ON a physical
// document, in a barcode, and signed over what the document already prints
// in machine-readable form, so a copied barcode on a forged card does not
// verify. #480.
//
// Three cases, one mechanism:
//   * MachineReadableZone — an ID card or travel document. The credential is
//     a QR code beside the MRZ, and the signature also covers every MRZ line.
//   * AamvaDriversLicenseScannableInformation — a North American driver's
//     licence. The credential rides inside the licence's own PDF417, and the
//     signature also covers the mandatory AAMVA fields its
//     protectedComponentIndex selects.
//   * IsoDrivingLicenceMachineReadableInformation (Appendix B, INFORMATIVE
//     and "expected to be refined ... before use") — an ISO/IEC 18013-2
//     licence. The signature covers the data groups DG1..DG11 a 2-byte
//     protectedComponentIndex selects, each as "DGn" + base64url(contents)
//     + "\n" in data-group NUMBER order, and the credential rides in DG11.
//     No vector exists; tests/vc_barcodes_engine.js builds one and holds it
//     to Digital Bazaar's cryptosuite. Neither published context names the
//     type, so a credential issued here carries a one-term inline context
//     mapping it into the vc-barcodes vocabulary (see ISO_CONTEXT).
// In each, the proof is ecdsa-xi-2023 (data_integrity.js): ecdsa-rdfc-2019
// with SHA-256 of the "optical data" appended to what is signed. The
// credential is CBOR-LD (cborld.js), registry entry 100.
//
// WHERE THE PUBLISHED BARCODES AND THE TR DISAGREE, THE BARCODES WIN, because
// a debugger that follows the prose verifies none of them:
//   * base45 is RFC 9285 (pairs of bytes, three digits, least significant
//     first) — the TR links a generic big-integer "Base Encoding" instead;
//   * the CBOR-LD tag is 51997 [100, ...] — the TR's text says "0x0664",
//     which is the 7.x form (decoded here too);
//   * ecdsa-xi-2023 hashes with SHA-256 on P-384 as well;
//   * the terse status list's listLength is a parameter: the TR says 2^26
//     MUST, and its own example works only with 2^17.
//
// NO DOM.
// ---------------------------------------------------------------------------

var cborld = require("./cborld");
var dataIntegrity = require("./data_integrity");
var provider = require("./crypto_provider");
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_barcodes",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var REGISTRY_ENTRY = 100;
var QR_PREFIX = "VC1-";
var BASE45_MULTIBASE = "R";
var CRYPTOSUITE = "ecdsa-xi-2023";
var SPEC = "W3C Verifiable Credential Barcodes v1.0 (Working Draft, " +
  "22 August 2026)";

var CONTEXTS = ["https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/vc-barcodes/v1"];
var MRZ = "MachineReadableZone";
var AAMVA = "AamvaDriversLicenseScannableInformation";
var ISO_IDL = "IsoDrivingLicenceMachineReadableInformation";
var VCB_VOCAB = "https://w3id.org/vc-barcodes#";

// Appendix B names the type and https://w3id.org/vc-barcodes/v1 does not
// define it (nor MachineReadableInformation), so a credential naming it by
// its short name needs a context that does. This is the smallest one that
// says nothing the TR does not: the term, in the vocabulary every other
// vc-barcodes term is in. It is inline rather than a URL because inventing
// a context URL for somebody else's vocabulary is worse than spending the
// ~120 bytes; CBOR-LD carries an embedded context as an ordinary map, and
// Digital Bazaar's library writes the same bytes for it
// (tests/vc_barcodes_engine.js).
var ISO_CONTEXT = {};
ISO_CONTEXT[ISO_IDL] = VCB_VOCAB + ISO_IDL;

// Appendix B.1: the components are the ISO/IEC 18013-2 data groups in
// ascending order of NUMBER, and bit i of the 2-byte index is the i-th.
// Numerically: a code-point sort would put DG10 and DG11 before DG2.
var ISO_DATA_GROUPS = ["DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7",
  "DG8", "DG9", "DG10", "DG11"];
// Ibid.: "The encoded VCB is expected to be placed in Data Group 11".
var ISO_VCB_GROUP = "DG11";

// VC Barcodes Appendix A: the 22 mandatory AAMVA data elements, in
// code-point order. Bit i of protectedComponentIndex (most significant bit
// of the first byte first) is element i.
var AAMVA_MANDATORY = ["DAC", "DAD", "DAG", "DAI", "DAJ", "DAK", "DAQ",
  "DAU", "DAY", "DBA", "DBB", "DBC", "DBD", "DCA", "DCB", "DCD", "DCF",
  "DCG", "DCS", "DDE", "DDF", "DDG"];

// ---------------------------------------------------------------------------
// Base45 (RFC 9285).
// ---------------------------------------------------------------------------

var B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

function base45Encode(bytes) {
  log.debug("Entering base45Encode().");
  var b = cbytes.asBytes(bytes);
  var out = "";
  for (var i = 0; i + 1 < b.length; i += 2) {
    var n = b[i] * 256 + b[i + 1];
    out += B45.charAt(n % 45) + B45.charAt(Math.floor(n / 45) % 45) +
      B45.charAt(Math.floor(n / 2025));
  }
  if (b.length % 2) {
    var last = b[b.length - 1];
    out += B45.charAt(last % 45) + B45.charAt(Math.floor(last / 45));
  }
  log.debug("Leaving base45Encode().");
  return out;
}

function base45Decode(text) {
  log.debug("Entering base45Decode().");
  var s = String(text);
  if (s.length % 3 === 1) {
    log.debug("Leaving base45Decode(). Bad length.");
    throw new Error("base45 text of " + s.length + " characters: a length " +
                    "one more than a multiple of three is impossible (RFC " +
                    "9285 section 4.3).");
  }
  var out = [];
  for (var i = 0; i < s.length; i += 3) {
    var digits = [];
    for (var j = i; j < Math.min(i + 3, s.length); j++) {
      var d = B45.indexOf(s.charAt(j));
      if (d === -1) {
        log.debug("Leaving base45Decode(). Bad character.");
        throw new Error("character " + JSON.stringify(s.charAt(j)) +
                        " at " + j + " is not base45.");
      }
      digits.push(d);
    }
    var n = digits[0] + digits[1] * 45 + (digits.length === 3 ?
                                          digits[2] * 2025 : 0);
    if (digits.length === 3) {
      if (n > 0xffff) {
        log.debug("Leaving base45Decode(). Triple too large.");
        throw new Error("base45 triple at " + i + " exceeds 65535.");
      }
      out.push(n >> 8, n & 0xff);
    } else {
      if (n > 0xff) {
        log.debug("Leaving base45Decode(). Pair too large.");
        throw new Error("base45 pair at " + i + " exceeds 255.");
      }
      out.push(n);
    }
  }
  log.debug("Leaving base45Decode().");
  return new Uint8Array(out);
}

// ---------------------------------------------------------------------------
// The barcode's character encodings (VC Barcodes sections 3.1 and A).
// ---------------------------------------------------------------------------

// The QR code text: "VC1-" then multibase base45 ("R" + base45). Every
// character is in the QR alphanumeric set, which is the point.
function qrText(bytes) {
  log.debug("Entering qrText().");
  log.debug("Leaving qrText().");
  return QR_PREFIX + BASE45_MULTIBASE + base45Encode(bytes);
}

function fromQrText(text) {
  log.debug("Entering fromQrText().");
  var s = String(text || "").replace(/[\r\n]+/g, "");
  if (s.indexOf(QR_PREFIX + BASE45_MULTIBASE) !== 0) {
    log.debug("Leaving fromQrText(). No prefix.");
    throw new Error("a VC barcode's QR text begins \"VC1-R\" (VC Barcodes " +
                    "section 3.1.2); this begins " +
                    JSON.stringify(s.slice(0, 5)) + ".");
  }
  log.debug("Leaving fromQrText().");
  return base45Decode(s.slice(5));
}

// The PDF417 field: base64url, RECOMMENDED; the spec's two examples print
// one in base64 and one in base64url, both padded, so both are read, with or
// without a multibase "u".
function pdf417FieldText(bytes) {
  log.debug("Entering pdf417FieldText().");
  log.debug("Leaving pdf417FieldText().");
  return cbytes.bytesToB64u(bytes);
}

function fromPdf417FieldText(text) {
  log.debug("Entering fromPdf417FieldText().");
  var s = String(text || "").replace(/\s+/g, "");
  if (s.charAt(0) === "u") s = s.slice(1);
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) {
    log.debug("Leaving fromPdf417FieldText(). Not base64.");
    throw new Error("the PDF417 credential field is not base64 or " +
                    "base64url.");
  }
  log.debug("Leaving fromPdf417FieldText().");
  return cbytes.b64uToBytes(s.replace(/=+$/, ""));
}

// ---------------------------------------------------------------------------
// AAMVA DL/ID card design standard (2020): the PDF417's text.
// ---------------------------------------------------------------------------

// { header, subfiles: [{ type, offset, length, elements: [[id, data]] }],
//   elements: { id: data } (every subfile's, first wins) }. Read by the
// subfile designators; a designator's length is advisory, because the
// spec's own example gets one wrong (ZZ says 0202 for 206 bytes).
function parseAamva(text) {
  log.debug("Entering parseAamva().");
  var s = String(text || "");
  var ansi = s.indexOf("ANSI ");
  if (ansi === -1 && s.indexOf("AAMVA") === -1) {
    log.debug("Leaving parseAamva(). No header.");
    throw new Error("not AAMVA PDF417 data: the \"ANSI \" file type is " +
                    "missing from the header.");
  }
  var at = (ansi === -1 ? s.indexOf("AAMVA") : ansi) + 5;
  var header = { iin: s.substr(at, 6), version: s.substr(at + 6, 2),
                 jurisdictionVersion: s.substr(at + 8, 2),
                 entries: parseInt(s.substr(at + 10, 2), 10) };
  if (!(header.entries > 0)) {
    log.debug("Leaving parseAamva(). No entries.");
    throw new Error("the AAMVA header names no subfiles.");
  }
  var subfiles = [];
  var elements = {};
  for (var i = 0; i < header.entries; i++) {
    var d = at + 12 + i * 10;
    var sub = { type: s.substr(d, 2), offset: parseInt(s.substr(d + 2, 4), 10),
                length: parseInt(s.substr(d + 6, 4), 10), elements: [] };
    if (!/^[A-Z]{2}$/.test(sub.type) || isNaN(sub.offset)) {
      log.debug("Leaving parseAamva(). Bad designator.");
      throw new Error("subfile designator " + (i + 1) + " is malformed.");
    }
    var start = s.indexOf(sub.type, sub.offset);
    if (start !== sub.offset) start = s.indexOf(sub.type, d + 10);
    var end = s.indexOf("\r", start);
    var body = s.slice(start + 2, end === -1 ? s.length : end);
    body.split("\n").forEach(function (line) {
      if (line.length < 3) return;
      sub.elements.push([line.slice(0, 3), line.slice(3)]);
      if (elements[line.slice(0, 3)] === undefined) {
        elements[line.slice(0, 3)] = line.slice(3);
      }
    });
    subfiles.push(sub);
  }
  log.debug("Leaving parseAamva(). " + subfiles.length + " subfiles.");
  return { header: header, subfiles: subfiles, elements: elements };
}

// protectedComponentIndex <-> the element ids it selects.
function componentIndex(ids) {
  log.debug("Entering componentIndex().");
  var bits = new Uint8Array(3);
  (ids || []).forEach(function (id) {
    var i = AAMVA_MANDATORY.indexOf(id);
    if (i === -1) {
      log.debug("Leaving componentIndex(). Not mandatory.");
      throw new Error(id + " is not one of the 22 mandatory AAMVA " +
                      "elements, and only those can be protected.");
    }
    bits[i >> 3] |= 0x80 >> (i & 7);
  });
  log.debug("Leaving componentIndex().");
  return "u" + cbytes.bytesToB64u(bits);
}

function protectedComponents(index) {
  log.debug("Entering protectedComponents().");
  var s = String(index || "");
  if (s.charAt(0) !== "u") {
    log.debug("Leaving protectedComponents(). Not base64url.");
    throw new Error("protectedComponentIndex must be multibase base64url " +
                    "(\"u\" + 4 characters); this is " + JSON.stringify(s) +
                    ".");
  }
  var bits = cbytes.b64uToBytes(s.slice(1));
  if (bits.length !== 3) {
    log.debug("Leaving protectedComponents(). Wrong length.");
    throw new Error("protectedComponentIndex must be 3 bytes; this is " +
                    bits.length + ".");
  }
  if (bits[2] & 0x03) {
    log.debug("Leaving protectedComponents(). Padding set.");
    throw new Error("protectedComponentIndex's last two bits are padding " +
                    "and must be 0.");
  }
  var ids = AAMVA_MANDATORY.filter(function (id, i) {
    return bits[i >> 3] & (0x80 >> (i & 7));
  });
  log.debug("Leaving protectedComponents(). " + ids.join(","));
  return ids;
}

// ---------------------------------------------------------------------------
// ISO/IEC 18013-2 driving licences (VC Barcodes Appendix B, informative).
//
// The optical data is the licence's compact-encoded machine-readable data,
// organised into data groups DG1..DG11. HOW that encoding is split into
// data groups ("as delimited by the data group delimiter character") is
// ISO/IEC 18013-2's, which is not freely available, so this module does
// not guess at it: it takes the data groups already separated, as
//     DG1: <contents>
//     DG2: hex:<contents as hex>
// one per line, the contents literal text (UTF-8) in which \n, \r, \t,
// \\ and \xNN stand for those bytes, or hex after "hex:".
// ---------------------------------------------------------------------------

// The credentialSubject's types, with the vocabulary IRI of each of this
// module's types read as its short name (a credential that names the type
// by IRI rather than through a context means the same thing).
function subjectTypes(subject) {
  log.debug("Entering subjectTypes().");
  var types = [].concat((subject && subject.type) || []).map(function (t) {
    var s = String(t);
    return s.indexOf(VCB_VOCAB) === 0 ? s.slice(VCB_VOCAB.length) : s;
  });
  log.debug("Leaving subjectTypes(). " + types.join(","));
  return types;
}

function unescapeGroupText(text, label) {
  log.debug("Entering unescapeGroupText(). " + label);
  var out = [];
  var plain = "";
  var flush = function flush() {
    log.debug("Entering flush().");
    if (plain) {
      Array.prototype.push.apply(out, Array.from(cbytes.strBytes(plain)));
      plain = "";
    }
    log.debug("Leaving flush().");
  };
  for (var i = 0; i < text.length; i++) {
    var c = text.charAt(i);
    if (c !== "\\") {
      plain += c;
      continue;
    }
    var n = text.charAt(i + 1);
    var simple = { n: 10, r: 13, t: 9, "\\": 92 }[n];
    if (simple !== undefined) {
      flush();
      out.push(simple);
      i += 1;
    } else if (n === "x" && /^[0-9a-fA-F]{2}$/.test(text.substr(i + 2, 2))) {
      flush();
      out.push(parseInt(text.substr(i + 2, 2), 16));
      i += 3;
    } else {
      log.debug("Leaving unescapeGroupText(). Bad escape.");
      throw new Error(label + ": \"\\" + n + "\" is not an escape this " +
                      "reads (\\n, \\r, \\t, \\\\ or \\xNN).");
    }
  }
  flush();
  log.debug("Leaving unescapeGroupText().");
  return new Uint8Array(out);
}

// { DG1: Uint8Array, ... } from the text form above, or from an object
// whose values are bytes or strings (UTF-8).
function parseIsoDataGroups(input) {
  log.debug("Entering parseIsoDataGroups().");
  var groups = {};
  if (input && typeof input === "object" && !(input instanceof Uint8Array)) {
    Object.keys(input).forEach(function (k) {
      if (ISO_DATA_GROUPS.indexOf(k) === -1) {
        log.debug("Leaving parseIsoDataGroups(). Unknown group.");
        throw new Error(k + " is not one of the ISO/IEC 18013-2 data " +
                        "groups DG1..DG11.");
      }
      var v = input[k];
      groups[k] = typeof v === "string" ? cbytes.strBytes(v) :
        cbytes.asBytes(v);
    });
    log.debug("Leaving parseIsoDataGroups(). Object.");
    return groups;
  }
  String(input || "").split(/\r?\n/).forEach(function (line, n) {
    if (!line.trim()) {
      return;
    }
    var m = /^\s*(DG\d+)\s*[:=] ?(.*)$/.exec(line);
    if (!m) {
      log.debug("Leaving parseIsoDataGroups(). Bad line.");
      throw new Error("line " + (n + 1) + " is not \"DGn: contents\".");
    }
    var name = m[1];
    if (ISO_DATA_GROUPS.indexOf(name) === -1) {
      log.debug("Leaving parseIsoDataGroups(). Unknown group.");
      throw new Error("line " + (n + 1) + ": " + name + " is not one of " +
                      "the data groups DG1..DG11 (VC Barcodes Appendix B).");
    }
    if (groups[name]) {
      log.debug("Leaving parseIsoDataGroups(). Duplicate.");
      throw new Error("line " + (n + 1) + ": " + name + " appears twice.");
    }
    var body = m[2];
    if (/^hex:/i.test(body)) {
      var h = body.slice(4).replace(/\s+/g, "");
      if (!/^([0-9a-fA-F]{2})*$/.test(h)) {
        log.debug("Leaving parseIsoDataGroups(). Bad hex.");
        throw new Error(name + ": the contents after \"hex:\" are not " +
                        "hex.");
      }
      groups[name] = cbytes.hexToBytes(h);
    } else {
      groups[name] = unescapeGroupText(body, name);
    }
  });
  if (!Object.keys(groups).length) {
    log.debug("Leaving parseIsoDataGroups(). Empty.");
    throw new Error("no data groups (\"DG1: ...\" lines).");
  }
  log.debug("Leaving parseIsoDataGroups(). " +
            Object.keys(groups).join(","));
  return groups;
}

// The text form of a set of data groups, in data-group order: printable
// text as text (with the escapes above), anything else as hex.
function formatIsoDataGroups(groups) {
  log.debug("Entering formatIsoDataGroups().");
  var lines = ISO_DATA_GROUPS.filter(function (name) {
    return groups[name] !== undefined;
  }).map(function (name) {
    var b = cbytes.asBytes(groups[name]);
    var text = null;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(b);
    } catch (e) {
      text = null;
    }
    if (text === null || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text) &&
        text.replace(/[^\x00-\x1f\x7f]/g, "").length * 4 > text.length) {
      return name + ": hex:" + cbytes.bytesToHex(b);
    }
    return name + ": " + text.replace(/\\/g, "\\\\")
      .replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t")
      .replace(/[\x00-\x1f\x7f]/g, function (c) {
        return "\\x" + ("0" + c.charCodeAt(0).toString(16)).slice(-2);
      });
  });
  log.debug("Leaving formatIsoDataGroups().");
  return lines.join("\n");
}

// The data groups with the credential's field as DG11's contents.
function withVcbInDg11(groups, field) {
  log.debug("Entering withVcbInDg11().");
  var g = Object.assign({}, typeof groups === "string" ?
                        parseIsoDataGroups(groups) : groups);
  g[ISO_VCB_GROUP] = cbytes.strBytes(field);
  log.debug("Leaving withVcbInDg11().");
  return g;
}

// protectedComponentIndex <-> data groups (Appendix B.1): two bytes, the
// first 11 bits DG1..DG11, the last five padding and 0.
function isoComponentIndex(names) {
  log.debug("Entering isoComponentIndex().");
  var bits = new Uint8Array(2);
  (names || []).forEach(function (name) {
    var i = ISO_DATA_GROUPS.indexOf(name);
    if (i === -1) {
      log.debug("Leaving isoComponentIndex(). Not a data group.");
      throw new Error(name + " is not one of the data groups DG1..DG11.");
    }
    bits[i >> 3] |= 0x80 >> (i & 7);
  });
  log.debug("Leaving isoComponentIndex().");
  return "u" + cbytes.bytesToB64u(bits);
}

function isoProtectedGroups(index) {
  log.debug("Entering isoProtectedGroups().");
  var s = String(index || "");
  if (s.charAt(0) !== "u" || s.length !== 4) {
    log.debug("Leaving isoProtectedGroups(). Not 4 characters.");
    throw new Error("an IsoDrivingLicenceMachineReadableInformation " +
                    "protectedComponentIndex is multibase base64url of two " +
                    "bytes, \"u\" + 3 characters (\"a total of 4 " +
                    "characters\", Appendix B.1); this is " +
                    JSON.stringify(s) + ".");
  }
  var bits = cbytes.b64uToBytes(s.slice(1));
  if (bits.length !== 2) {
    log.debug("Leaving isoProtectedGroups(). Wrong length.");
    throw new Error("protectedComponentIndex must be 2 bytes; this is " +
                    bits.length + ".");
  }
  if (bits[1] & 0x1f) {
    log.debug("Leaving isoProtectedGroups(). Padding set.");
    throw new Error("protectedComponentIndex's last five bits are padding " +
                    "and must be 0 (Appendix B.1).");
  }
  var names = ISO_DATA_GROUPS.filter(function (name, i) {
    return bits[i >> 3] & (0x80 >> (i & 7));
  });
  log.debug("Leaving isoProtectedGroups(). " + names.join(","));
  return names;
}

// Appendix B.2: for each protected data group, in data-group order,
// "DGn" + base64url(its contents) + "\n". base64url is RFC 4648 section 5
// WITHOUT padding: the TR says only "a base64url encoding", and unpadded is
// what every other base64url in Data Integrity and in this TR's multibase
// values is. tests/vc_barcodes_engine.js asserts this by spelling the rule
// out with node's own Buffer.
function isoCanonical(groups, index) {
  log.debug("Entering isoCanonical().");
  var g = typeof groups === "string" ? parseIsoDataGroups(groups) :
      (groups || {});
  var parts = isoProtectedGroups(index).map(function (name) {
    if (g[name] === undefined) {
      log.debug("Leaving isoCanonical(). Missing group.");
      throw new Error("the protectedComponentIndex protects " + name +
                      ", and the licence data has no " + name + ".");
    }
    return name + cbytes.bytesToB64u(g[name]) + "\n";
  });
  log.debug("Leaving isoCanonical().");
  return parts.join("");
}

// ---------------------------------------------------------------------------
// The optical data (VC Barcodes section 3.2.4.4): the protected components,
// each ending "\n", ordered by the type's rule, joined, SHA-256.
// ---------------------------------------------------------------------------

function mrzLines(mrz) {
  log.debug("Entering mrzLines().");
  var lines = Array.isArray(mrz) ? mrz.slice() :
      String(mrz || "").split(/\r?\n/);
  lines = lines.map(function (l) {
    return String(l).replace(/\s+$/, "");
  }).filter(function (l) {
    return l.length;
  });
  if (!lines.length) {
    log.debug("Leaving mrzLines(). Empty.");
    throw new Error("no MRZ lines.");
  }
  log.debug("Leaving mrzLines(). " + lines.length);
  return lines;
}

// Every line in the order printed; no sorting.
function mrzCanonical(mrz) {
  log.debug("Entering mrzCanonical().");
  log.debug("Leaving mrzCanonical().");
  return mrzLines(mrz).map(function (l) {
    return l + "\n";
  }).join("");
}

// The selected mandatory elements as "ID" + data + "\n", in code-point
// order. `elements` is { id: data } (parseAamva's) or the PDF417 text.
function aamvaCanonical(elements, index) {
  log.debug("Entering aamvaCanonical().");
  var el = typeof elements === "string" ? parseAamva(elements).elements :
      (elements || {});
  var parts = protectedComponents(index).map(function (id) {
    if (el[id] === undefined) {
      log.debug("Leaving aamvaCanonical(). Missing element.");
      throw new Error("the protectedComponentIndex protects " + id +
                      ", and the PDF417 has no " + id + ".");
    }
    return id + el[id] + "\n";
  }).sort();
  log.debug("Leaving aamvaCanonical().");
  return parts.join("");
}

function sha256Of(text) {
  log.debug("Entering sha256Of().");
  log.debug("Leaving sha256Of().");
  return provider.digest("sha256", cbytes.strBytes(text));
}

// { canonical, opticalDataBytes } for a credential's subject, given what the
// document prints: { mrz } or { aamva (elements or PDF417 text) }.
function opticalData(credential, printed) {
  log.debug("Entering opticalData().");
  var subject = (credential && credential.credentialSubject) || {};
  var type = subjectTypes(subject);
  var p = printed || {};
  var canonical;
  if (type.indexOf(MRZ) !== -1) {
    canonical = mrzCanonical(p.mrz);
  } else if (type.indexOf(AAMVA) !== -1) {
    canonical = aamvaCanonical(p.aamva, subject.protectedComponentIndex);
  } else if (type.indexOf(ISO_IDL) !== -1) {
    if (p.iso === undefined) {
      log.debug("Leaving opticalData(). No data groups.");
      throw new Error("an " + ISO_IDL + " credential signs the licence's " +
                      "data groups, and none were given.");
    }
    canonical = isoCanonical(p.iso, subject.protectedComponentIndex);
  } else {
    log.debug("Leaving opticalData(). Unknown subject type.");
    throw new Error("credentialSubject.type is " + JSON.stringify(type) +
                    "; VC Barcodes defines " + MRZ + ", " + AAMVA +
                    " and (Appendix B, informative) " + ISO_IDL + ".");
  }
  log.debug("Leaving opticalData().");
  return { canonical: canonical, opticalDataBytes: sha256Of(canonical) };
}

// ---------------------------------------------------------------------------
// Status (section 2.2): TerseBitstringStatusListEntry.
// ---------------------------------------------------------------------------

function expandStatus(entry, opts) {
  log.debug("Entering expandStatus().");
  var o = opts || {};
  var e = entry || {};
  var listLength = o.listLength || Math.pow(2, 26);
  var purpose = o.statusPurpose || "revocation";
  var i = Number(e.terseStatusListIndex);
  if (!Number.isInteger(i) || i < 0 || i > 0xffffffff) {
    log.debug("Leaving expandStatus(). Bad index.");
    throw new Error("terseStatusListIndex must be an unsigned 32-bit " +
                    "integer.");
  }
  var list = Math.floor(i / listLength);
  log.debug("Leaving expandStatus().");
  return {
    type: "BitstringStatusListEntry",
    statusPurpose: purpose,
    statusListCredential: String(e.terseStatusListBaseUrl || "") + "/" +
      purpose + "/" + list,
    statusListIndex: String(i % listLength)
  };
}

// ---------------------------------------------------------------------------
// Issue and verify.
// ---------------------------------------------------------------------------

// An unsigned OpticalBarcodeCredential for one of the three subject types.
// opts: { issuer, subjectType (MRZ, AAMVA or ISO_IDL), protect (AAMVA
// element ids, or ISO data groups),
// contexts (more @contexts after the two required ones), status
// ({ terseStatusListBaseUrl, terseStatusListIndex }) }.
function credentialTemplate(opts) {
  log.debug("Entering credentialTemplate().");
  var o = opts || {};
  var subject = { type: [AAMVA, ISO_IDL].indexOf(o.subjectType) !== -1 ?
                  o.subjectType : MRZ };
  var contexts = CONTEXTS.slice();
  if (subject.type === AAMVA) {
    subject.protectedComponentIndex = componentIndex(o.protect ||
                                                     ["DAC", "DAQ", "DCS"]);
  } else if (subject.type === ISO_IDL) {
    var groups = o.protect || ["DG1"];
    if (groups.indexOf(ISO_VCB_GROUP) !== -1) {
      log.debug("Leaving credentialTemplate(). DG11 protected.");
      throw new Error("the credential is carried in " + ISO_VCB_GROUP +
                      ", so " + ISO_VCB_GROUP + " cannot be protected: " +
                      "\"the corresponding element of " +
                      "protectedComponentIndex is set to 0\" (Appendix " +
                      "B.1). A signature cannot cover its own container.");
    }
    subject.protectedComponentIndex = isoComponentIndex(groups);
    contexts.push(ISO_CONTEXT);
  }
  var vc = {
    "@context": contexts.concat(o.contexts || []),
    type: ["VerifiableCredential", "OpticalBarcodeCredential"],
    credentialSubject: subject,
    issuer: o.issuer
  };
  if (o.status) {
    vc.credentialStatus = Object.assign({
      type: "TerseBitstringStatusListEntry" }, o.status);
  }
  log.debug("Leaving credentialTemplate().");
  return vc;
}

// opts: { privateJwk (P-256 or P-384), verificationMethod, printed
// ({ mrz }, { aamva } or { iso }), documentLoader, created (default false:
// the
// published barcodes carry none, and it costs bytes) }. Answers
// { credential, cborld, text, canonical, opticalDataBytes, carrier }, where
// text is the QR text for an MRZ credential and the PDF417 field (base64url)
// for an AAMVA or ISO one; carrier is "qr", "pdf417" or "dg11".
async function issue(unsigned, opts) {
  log.debug("Entering issue().");
  var o = opts || {};
  var optical = opticalData(unsigned, o.printed);
  var signed = await dataIntegrity.createProof(unsigned, {
    suite: CRYPTOSUITE, privateJwk: o.privateJwk,
    verificationMethod: o.verificationMethod,
    proofPurpose: "assertionMethod",
    created: o.created === undefined ? false : o.created,
    addContext: false, documentLoader: o.documentLoader,
    extraInformation: optical.opticalDataBytes
  });
  var bytes = await cborld.encode(signed, { registryEntryId: REGISTRY_ENTRY,
    documentLoader: o.documentLoader });
  var types = subjectTypes(unsigned.credentialSubject);
  var isMrz = types.indexOf(MRZ) !== -1;
  log.debug("Leaving issue(). " + bytes.length + " bytes.");
  return { credential: signed, cborld: bytes, canonical: optical.canonical,
           opticalDataBytes: optical.opticalDataBytes,
           text: isMrz ? qrText(bytes) : pdf417FieldText(bytes),
           carrier: isMrz ? "qr" : types.indexOf(ISO_IDL) !== -1 ? "dg11" :
             "pdf417" };
}

// The barcode's bytes from whatever was scanned or pasted: QR text, the
// PDF417 field, the whole AAMVA PDF417 text (the credential is read from
// element ZZA of subfile ZZ, as the TR's example puts it), an ISO
// licence's data groups ("DGn: ..." lines; the credential is DG11's
// contents, Appendix B.1), or hex.
function barcodeBytes(input) {
  log.debug("Entering barcodeBytes().");
  if (input instanceof Uint8Array) {
    log.debug("Leaving barcodeBytes(). Bytes.");
    return { bytes: input, carrier: "bytes" };
  }
  var s = String(input || "").trim();
  if (s.indexOf(QR_PREFIX) === 0) {
    log.debug("Leaving barcodeBytes(). QR text.");
    return { bytes: fromQrText(s), carrier: "qr" };
  }
  if (/^DG\d+\s*[:=]/.test(s)) {
    var groups = parseIsoDataGroups(s);
    if (!groups[ISO_VCB_GROUP] || !groups[ISO_VCB_GROUP].length) {
      log.debug("Leaving barcodeBytes(). No DG11.");
      throw new Error("the data groups have no " + ISO_VCB_GROUP + ", " +
                      "which is where Appendix B.1 expects the credential.");
    }
    log.debug("Leaving barcodeBytes(). ISO DG11.");
    return { bytes: fromPdf417FieldText(cbytes.bytesToStr(
      groups[ISO_VCB_GROUP])), carrier: "dg11", iso: groups };
  }
  if (s.indexOf("ANSI ") !== -1 || s.charAt(0) === "@") {
    var aamva = parseAamva(input);
    var zza = null;
    aamva.subfiles.forEach(function (sub) {
      sub.elements.forEach(function (e) {
        if (sub.type === "ZZ" && e[0] === "ZZA" && zza === null) zza = e[1];
      });
    });
    if (zza === null) {
      log.debug("Leaving barcodeBytes(). No ZZA.");
      throw new Error("the AAMVA data has no ZZA element in a ZZ subfile, " +
                      "which is where the VC Barcodes example carries the " +
                      "credential.");
    }
    log.debug("Leaving barcodeBytes(). AAMVA ZZA.");
    return { bytes: fromPdf417FieldText(zza), carrier: "pdf417",
             aamva: aamva };
  }
  if (/^(d9|D9)[0-9a-fA-F\s]+$/.test(s)) {
    log.debug("Leaving barcodeBytes(). Hex.");
    return { bytes: cbytes.hexToBytes(s.replace(/\s+/g, "")),
             carrier: "hex" };
  }
  log.debug("Leaving barcodeBytes(). PDF417 field.");
  return { bytes: fromPdf417FieldText(s), carrier: "pdf417" };
}

// opts: { printed ({ mrz }, { aamva } or { iso }; for a whole AAMVA PDF417
// or an ISO licence's data groups they are read from the input when not
// given), documentLoader, resolveKey }.
// Answers { valid, reason, credential, cborld, format, registryEntryId,
// canonical, opticalDataBytes, proof, protected, status }.
async function verify(input, opts) {
  log.debug("Entering verify().");
  var o = opts || {};
  var got = barcodeBytes(input);
  var framed = cborld.parse(got.bytes);
  var out = { valid: false, carrier: got.carrier, cborld: got.bytes,
              format: framed.format,
              registryEntryId: framed.registryEntryId, spec: SPEC };
  out.credential = await cborld.decode(got.bytes, {
    documentLoader: o.documentLoader,
    appContextMap: framed.format === "legacy-singleton" ?
      cborld.VCB_LEGACY_APP_CONTEXTS : undefined });
  var proof = [].concat(out.credential.proof || [])[0] || {};
  out.proofType = proof.type;
  out.cryptosuite = proof.cryptosuite;
  var subject = out.credential.credentialSubject || {};
  out.subjectTypes = subjectTypes(subject);
  var isIso = out.subjectTypes.indexOf(ISO_IDL) !== -1;
  if (subject.protectedComponentIndex) {
    try {
      out.protected = isIso ?
        isoProtectedGroups(subject.protectedComponentIndex) :
        protectedComponents(subject.protectedComponentIndex);
    } catch (e) {
      out.reason = e.message;
      log.debug("Leaving verify(). Bad index.");
      return out;
    }
  }
  if (out.credential.credentialStatus) {
    out.status = out.credential.credentialStatus;
  }
  var printed = Object.assign({}, o.printed);
  if (!printed.aamva && got.aamva) printed.aamva = got.aamva.elements;
  if (!printed.iso && got.iso) {
    printed.iso = got.iso;
  }
  if (isIso && got.carrier === "dg11" && out.protected &&
      out.protected.indexOf(ISO_VCB_GROUP) !== -1) {
    out.reason = "the credential was read from " + ISO_VCB_GROUP + " and " +
      "its protectedComponentIndex protects " + ISO_VCB_GROUP + ": a " +
      "signature cannot cover its own container, and Appendix B.1 says " +
      "that bit \"is set to 0\".";
    log.debug("Leaving verify(). DG11 protected.");
    return out;
  }
  if (proof.cryptosuite === CRYPTOSUITE) {
    // Section 3.2.4.5: the proof configuration must be exactly this.
    if (proof.type !== "DataIntegrityProof") {
      out.reason = "an " + CRYPTOSUITE + " proof's type must be " +
        "DataIntegrityProof (VC Barcodes section 3.2.4.5).";
      log.debug("Leaving verify(). Bad proof type.");
      return out;
    }
    try {
      var optical = opticalData(out.credential, printed);
      out.canonical = optical.canonical;
      out.opticalDataBytes = optical.opticalDataBytes;
    } catch (e) {
      out.reason = "the optical data the signature covers could not be " +
        "assembled: " + e.message;
      log.debug("Leaving verify(). No optical data.");
      return out;
    }
  }
  var r = await dataIntegrity.verifyProof(out.credential, {
    documentLoader: o.documentLoader, resolveKey: o.resolveKey,
    extraInformation: out.opticalDataBytes });
  out.proof = r.proofs[0];
  out.valid = r.valid;
  out.reason = r.valid ? "" : r.reason;
  if (!r.valid && out.opticalDataBytes && r.proofs[0] &&
      !r.proofs[0].unsupported) {
    out.reason += " The signature covers the optical data too, so a " +
      "barcode moved to a document that prints different data (or MRZ / " +
      "AAMVA text typed differently) fails exactly like this.";
  }
  log.debug("Leaving verify(). " + out.valid);
  return out;
}

module.exports = {
  SPEC: SPEC,
  CRYPTOSUITE: CRYPTOSUITE,
  REGISTRY_ENTRY: REGISTRY_ENTRY,
  MRZ: MRZ,
  AAMVA: AAMVA,
  AAMVA_MANDATORY: AAMVA_MANDATORY,
  ISO_IDL: ISO_IDL,
  ISO_CONTEXT: ISO_CONTEXT,
  ISO_DATA_GROUPS: ISO_DATA_GROUPS,
  ISO_VCB_GROUP: ISO_VCB_GROUP,
  subjectTypes: subjectTypes,
  parseIsoDataGroups: parseIsoDataGroups,
  formatIsoDataGroups: formatIsoDataGroups,
  withVcbInDg11: withVcbInDg11,
  isoComponentIndex: isoComponentIndex,
  isoProtectedGroups: isoProtectedGroups,
  isoCanonical: isoCanonical,
  base45Encode: base45Encode,
  base45Decode: base45Decode,
  qrText: qrText,
  fromQrText: fromQrText,
  pdf417FieldText: pdf417FieldText,
  fromPdf417FieldText: fromPdf417FieldText,
  parseAamva: parseAamva,
  componentIndex: componentIndex,
  protectedComponents: protectedComponents,
  mrzCanonical: mrzCanonical,
  aamvaCanonical: aamvaCanonical,
  opticalData: opticalData,
  expandStatus: expandStatus,
  credentialTemplate: credentialTemplate,
  barcodeBytes: barcodeBytes,
  issue: issue,
  verify: verify
};
