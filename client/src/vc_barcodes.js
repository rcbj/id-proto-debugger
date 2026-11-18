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
// Two cases, one mechanism:
//   * MachineReadableZone — an ID card or travel document. The credential is
//     a QR code beside the MRZ, and the signature also covers every MRZ line.
//   * AamvaDriversLicenseScannableInformation — a North American driver's
//     licence. The credential rides inside the licence's own PDF417, and the
//     signature also covers the mandatory AAMVA fields its
//     protectedComponentIndex selects.
// Either way the proof is ecdsa-xi-2023 (data_integrity.js): ecdsa-rdfc-2019
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
  var type = [].concat(subject.type || []);
  var p = printed || {};
  var canonical;
  if (type.indexOf(MRZ) !== -1) {
    canonical = mrzCanonical(p.mrz);
  } else if (type.indexOf(AAMVA) !== -1) {
    canonical = aamvaCanonical(p.aamva, subject.protectedComponentIndex);
  } else {
    log.debug("Leaving opticalData(). Unknown subject type.");
    throw new Error("credentialSubject.type is " + JSON.stringify(type) +
                    "; VC Barcodes defines " + MRZ + " and " + AAMVA + ".");
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

// An unsigned OpticalBarcodeCredential for one of the two subject types.
// opts: { issuer, subjectType (MRZ or AAMVA), protect (AAMVA element ids),
// contexts (more @contexts after the two required ones), status
// ({ terseStatusListBaseUrl, terseStatusListIndex }) }.
function credentialTemplate(opts) {
  log.debug("Entering credentialTemplate().");
  var o = opts || {};
  var subject = { type: o.subjectType === AAMVA ? AAMVA : MRZ };
  if (subject.type === AAMVA) {
    subject.protectedComponentIndex = componentIndex(o.protect ||
                                                     ["DAC", "DAQ", "DCS"]);
  }
  var vc = {
    "@context": CONTEXTS.concat(o.contexts || []),
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
// ({ mrz } or { aamva }), documentLoader, created (default false: the
// published barcodes carry none, and it costs bytes) }. Answers
// { credential, cborld, text, canonical, opticalDataBytes }, where text is
// the QR text for an MRZ credential and the PDF417 field for an AAMVA one.
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
  var isMrz = [].concat(unsigned.credentialSubject.type).indexOf(MRZ) !== -1;
  log.debug("Leaving issue(). " + bytes.length + " bytes.");
  return { credential: signed, cborld: bytes, canonical: optical.canonical,
           opticalDataBytes: optical.opticalDataBytes,
           text: isMrz ? qrText(bytes) : pdf417FieldText(bytes),
           carrier: isMrz ? "qr" : "pdf417" };
}

// The barcode's bytes from whatever was scanned or pasted: QR text, the
// PDF417 field, the whole AAMVA PDF417 text (the credential is read from
// element ZZA of subfile ZZ, as the TR's example puts it), or hex.
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

// opts: { printed ({ mrz } or { aamva }; for a whole AAMVA PDF417 the
// elements are read from it when not given), documentLoader, resolveKey }.
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
  if (subject.protectedComponentIndex) {
    try {
      out.protected = protectedComponents(subject.protectedComponentIndex);
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
