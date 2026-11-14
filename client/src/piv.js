// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: piv.js
//
// PIV, NIST SP 800-73-4, plus the Yubico commands a YubiKey adds
// (version, serial, metadata, attestation). This reads APDUs and the
// data objects they carry. It does not talk to a card: GENERAL
// AUTHENTICATE is decoded and not performed, and a VERIFY is reported
// as a PIN of N bytes rather than shown.
//
// A certificate is unwrapped here, including the gzip form SP 800-73
// puts in tag 70, and the DER is handed back for client/src/x509.js.
// This file does not parse a certificate and does not require zlib:
// a browser bundle has no node zlib, so the inflater is passed in.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "piv",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var iso = require("./iso7816.js");
var forge = require("node-forge");

// The full PIV application identifier. A SELECT of the RID alone
// (A000000308) is the same application and is named as such.
var PIV_AID = "a00000030800001000";
var PIV_RID = "a000000308";

var SLOTS = {
  "9a": "PIV authentication",
  "9b": "card management key",
  "9c": "digital signature",
  "9d": "key management",
  "9e": "card authentication",
  "f9": "attestation"
};

// Retired key-management slots are 0x82 through 0x95.
var RETIRED_FIRST = 0x82;
var RETIRED_LAST = 0x95;

// SP 800-78-4 algorithm identifiers, plus the sizes Yubico added.
var ALGORITHMS = {
  "00": "3DES",
  "03": "3DES",
  "05": "RSA 3072",
  "06": "RSA 1024",
  "07": "RSA 2048",
  "08": "AES-128",
  "0a": "AES-192",
  "0c": "AES-256",
  "11": "ECC P-256",
  "14": "ECC P-384",
  "16": "RSA 4096",
  "e0": "Ed25519",
  "e1": "X25519"
};

// SP 800-73-4 Part 1 data objects. The tag is three bytes except the
// discovery object, which is 0x7E.
var OBJECTS = {
  "7e": "discovery object",
  "7f61": "biometric information templates group",
  "5fc101": "X.509 certificate for card authentication",
  "5fc102": "card holder unique identifier",
  "5fc103": "cardholder fingerprints",
  "5fc105": "X.509 certificate for PIV authentication",
  "5fc106": "security object",
  "5fc107": "card capability container",
  "5fc108": "cardholder facial image",
  "5fc109": "printed information",
  "5fc10a": "X.509 certificate for digital signature",
  "5fc10b": "X.509 certificate for key management",
  "5fc10c": "key history object",
  "5fc121": "cardholder iris images",
  "5fc122": "secure messaging certificate signer",
  "5fc123": "pairing code reference data",
  // Yubico: the attestation certificate for the key in slot F9, the
  // one that signs what ATTEST returns. Factory-loaded by Yubico.
  "5fff01": "attestation certificate (Yubico, slot F9)"
};

var PIN_POLICY = {
  "0": "default",
  "1": "never",
  "2": "once",
  "3": "always"
};

var TOUCH_POLICY = {
  "0": "default",
  "1": "never",
  "2": "always",
  "3": "cached"
};

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  throw new Error(message);
}

function hexByte(n) {
  log.debug("Entering hexByte().");
  var out = n.toString(16).padStart(2, "0");
  log.debug("Leaving hexByte().");
  return out;
}

function statusLabel(response) {
  log.debug("Entering statusLabel().");
  var text = response.sw.toString(16).toUpperCase().padStart(4, "0") +
      " " + response.name;
  log.debug("Leaving statusLabel().");
  return text;
}

function slotName(p2) {
  log.debug("Entering slotName().");
  var key = hexByte(p2);
  if (SLOTS[key]) {
    log.debug("Leaving slotName().");
    return SLOTS[key] + " (" + key.toUpperCase() + ")";
  }
  if (p2 >= RETIRED_FIRST && p2 <= RETIRED_LAST) {
    log.debug("Leaving slotName(). Retired.");
    return "retired key management " +
        (p2 - RETIRED_FIRST + 1) + " (" + key.toUpperCase() + ")";
  }
  log.debug("Leaving slotName(). Unnamed.");
  return "slot " + key.toUpperCase();
}

// VERIFY's P2 names a PIN, not a key slot (SP 800-73-4 Part 2
// section 3.2.1). 96 and 97 are the on-card biometric references.
var PIN_REFERENCES = {
  "00": "global PIN",
  "80": "PIV card application PIN",
  "81": "PIN unblocking key (PUK)",
  "96": "primary finger OCC",
  "97": "secondary finger OCC"
};
var PIN_LENGTH = 8;

function pinReferenceName(p2) {
  log.debug("Entering pinReferenceName().");
  var key = hexByte(p2);
  var name = (PIN_REFERENCES[key] || "reference") + " (" +
      key.toUpperCase() + ")";
  log.debug("Leaving pinReferenceName().");
  return name;
}

// VERIFY of the application PIN. SP 800-73-4 Part 2 section 3.2.1:
// the PIN is 6 to 8 characters, padded with FF to 8 bytes. An
// unpadded PIN is a different reference value, and the card counts
// it as a wrong one.
function verifyApdu(pin, reference) {
  log.debug("Entering verifyApdu().");
  var bytes = Buffer.from(String(pin == null ? "" : pin), "utf8");
  if (bytes.length < 6 || bytes.length > PIN_LENGTH) {
    log.debug("Leaving verifyApdu(). Length.");
    reject("A PIV PIN is 6 to 8 characters.");
  }
  var padded = Buffer.concat([bytes,
      Buffer.alloc(PIN_LENGTH - bytes.length, 0xff)]);
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x20, p1: 0x00,
    p2: reference === undefined ? 0x80 : reference,
    data: padded, le: null
  });
  log.debug("Leaving verifyApdu().");
  return apdu;
}

function algorithmName(p1) {
  log.debug("Entering algorithmName().");
  var key = hexByte(p1);
  var name = ALGORITHMS[key] || ("algorithm " + key.toUpperCase());
  log.debug("Leaving algorithmName().");
  return name;
}

function objectName(tagHex) {
  log.debug("Entering objectName().");
  var key = String(tagHex).toLowerCase();
  if (OBJECTS[key]) {
    log.debug("Leaving objectName().");
    return OBJECTS[key];
  }
  var n = parseInt(key, 16);
  // Retired certificate objects are 5FC10D through 5FC120.
  if (n >= 0x5fc10d && n <= 0x5fc120) {
    log.debug("Leaving objectName(). Retired certificate.");
    return "retired X.509 certificate for key management " +
        (n - 0x5fc10d + 1);
  }
  log.debug("Leaving objectName(). Unnamed.");
  return "data object " + key.toUpperCase();
}

// The Yubico attestation extensions, 1.3.6.1.4.1.41482.3.N, from
// developers.yubico.com/PIV/Introduction/PIV_attestation.html. The
// content octets of the OID up to and including the 3 arc; N follows.
var YUBICO_ATTESTATION_ARC = "2b0601040182c40a03";
var ATTEST_PIN_POLICY = { "1": "never", "2": "once per session",
    "3": "always" };
var ATTEST_TOUCH_POLICY = { "1": "never", "2": "always",
    "3": "cached for 15s" };
var FORM_FACTORS = {
  "1": "USB-A keychain",
  "2": "USB-A nano",
  "3": "USB-C keychain",
  "4": "USB-C nano",
  "5": "Lightning and USB-C"
};

// Every Extension SEQUENCE in a certificate, as { oid, value } with
// the extnValue's content octets. Not a certificate parser: it finds
// SEQUENCE { OID, [BOOLEAN,] OCTET STRING } inside the [3] wrapper of
// the TBSCertificate and nothing else. describeCertificate() in
// x509.js is still what reads the certificate.
function certificateExtensions(der) {
  log.debug("Entering certificateExtensions().");
  var top = iso.parseElements(der);
  if (top.length !== 1 || top[0].tag !== 0x30) {
    log.debug("Leaving certificateExtensions(). Not a certificate.");
    reject("Not a DER certificate.");
  }
  var tbs = iso.parseElements(top[0].value)[0];
  if (!tbs || tbs.tag !== 0x30) {
    log.debug("Leaving certificateExtensions(). No TBS.");
    reject("The certificate has no TBSCertificate.");
  }
  var wrapper = childByTag(iso.parseElements(tbs.value), 0xa3);
  var out = [];
  if (!wrapper) {
    log.debug("Leaving certificateExtensions(). None.");
    return out;
  }
  var list = iso.parseElements(wrapper.value);
  var items = list.length && list[0].tag === 0x30 ?
      iso.parseElements(list[0].value) : [];
  var i = 0;
  for (i = 0; i < items.length; i++) {
    var parts = iso.parseElements(items[i].value);
    var oid = childByTag(parts, 0x06);
    var value = childByTag(parts, 0x04);
    if (oid && value) {
      out.push({ oid: oid.value.toString("hex"), value: value.value });
    }
  }
  log.debug("Leaving certificateExtensions().");
  return out;
}

// The serial extension is a DER INTEGER inside the OCTET STRING.
function attestationSerial(value) {
  log.debug("Entering attestationSerial().");
  var nodes = iso.parseElements(value);
  if (nodes.length !== 1 || nodes[0].tag !== 0x02 ||
      nodes[0].value.length < 1 || nodes[0].value.length > 6) {
    log.debug("Leaving attestationSerial(). Shape.");
    return null;
  }
  var n = 0;
  var i = 0;
  for (i = 0; i < nodes[0].value.length; i++) {
    n = (n * 256) + nodes[0].value[i];
  }
  log.debug("Leaving attestationSerial().");
  return n;
}

// Rows for the Yubico extensions in a certificate: the device
// attestation certificate in 5FFF01 carries the firmware version, and
// a certificate ATTEST returns for a slot carries all of them.
function attestationRows(der) {
  log.debug("Entering attestationRows().");
  var rows = [];
  var exts = certificateExtensions(iso.asBytes(der));
  var i = 0;
  for (i = 0; i < exts.length; i++) {
    var oid = exts[i].oid;
    if (oid.indexOf(YUBICO_ATTESTATION_ARC) !== 0 ||
        oid.length !== YUBICO_ATTESTATION_ARC.length + 2) {
      continue;
    }
    var arc = parseInt(oid.slice(-2), 16);
    var v = exts[i].value;
    if (arc === 3 && v.length === 3) {
      rows.push({ label: "Firmware (Yubico 3.3)",
          value: v[0] + "." + v[1] + "." + v[2] });
    } else if (arc === 7) {
      var serial = attestationSerial(v);
      rows.push({ label: "YubiKey serial (Yubico 3.7)",
          value: serial === null ? iso.toHex(v) : String(serial) });
    } else if (arc === 8 && v.length === 2) {
      rows.push({ label: "PIN policy (Yubico 3.8)",
          value: ATTEST_PIN_POLICY[String(v[0])] || hexByte(v[0]) });
      rows.push({ label: "Touch policy (Yubico 3.8)",
          value: ATTEST_TOUCH_POLICY[String(v[1])] || hexByte(v[1]) });
    } else if (arc === 9 && v.length === 1) {
      var fips = (v[0] & 0x80) !== 0;
      rows.push({ label: "Form factor (Yubico 3.9)",
          value: (FORM_FACTORS[String(v[0] & 0x7f)] ||
              hexByte(v[0])) + (fips ? ", FIPS" : "") });
    } else if (arc === 10) {
      rows.push({ label: "FIPS certified (Yubico 3.10)", value: "yes" });
    } else if (arc === 11) {
      rows.push({ label: "CSPN certified (Yubico 3.11)", value: "yes" });
    } else {
      rows.push({ label: "Yubico extension 3." + arc,
          value: iso.toHex(v) });
    }
  }
  log.debug("Leaving attestationRows().");
  return rows;
}

function childByTag(nodes, tag) {
  log.debug("Entering childByTag().");
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    if (nodes[i].tag === tag) {
      log.debug("Leaving childByTag().");
      return nodes[i];
    }
  }
  log.debug("Leaving childByTag(). Absent.");
  return null;
}

// Tag 0x53 is the data-object wrapper. Its value is the inner TLV
// whether or not the wrapper was marked constructed.
function innerNodes(body) {
  log.debug("Entering innerNodes().");
  var nodes = iso.parseElements(body);
  if (nodes.length === 1 && nodes[0].tag === 0x53) {
    var inner = iso.parseElements(nodes[0].value);
    log.debug("Leaving innerNodes(). Wrapped.");
    return inner;
  }
  log.debug("Leaving innerNodes().");
  return nodes;
}

// The certificate container. Tag 0x70 is the certificate, gzip when
// the cert-info byte (tag 0x71) has its low bit set. A body that is
// already a bare certificate (the attestation command often returns
// one) is returned as DER with no container.
function certificateFields(body) {
  log.debug("Entering certificateFields().");
  var bytes = iso.asBytes(body);
  if (bytes.length === 0) {
    log.debug("Leaving certificateFields(). Empty.");
    reject("The response has no certificate.");
  }
  if (bytes[0] === 0x30) {
    log.debug("Leaving certificateFields(). Bare certificate.");
    return {
      wrapped: false,
      compressed: false,
      certInfo: null,
      der: bytes,
      deflated: null
    };
  }
  var nodes = innerNodes(bytes);
  var cert = childByTag(nodes, 0x70);
  var info = childByTag(nodes, 0x71);
  if (!cert) {
    log.debug("Leaving certificateFields(). No tag 70.");
    reject("No PIV certificate (tag 70).");
  }
  var certInfo = null;
  if (info && info.value.length > 0) {
    certInfo = info.value[0];
  }
  // SP 800-73: the low bit of CertInfo is gzip. A gzip header with
  // no CertInfo is still gzip — some attestations omit the byte.
  var compressed = (certInfo !== null && (certInfo & 0x01) === 0x01) ||
      (certInfo === null && cert.value.length >= 2 &&
          cert.value[0] === 0x1f && cert.value[1] === 0x8b);
  log.debug("Leaving certificateFields().");
  return {
    wrapped: true,
    compressed: compressed,
    certInfo: certInfo,
    der: compressed ? null : cert.value,
    deflated: compressed ? cert.value : null
  };
}

// inflate is optional. Without it a gzip container comes back with
// der null and the compressed bytes in deflated, so the caller can
// inflate asynchronously (a browser DecompressionStream).
function unwrapCertificate(body, inflate) {
  log.debug("Entering unwrapCertificate().");
  var fields = certificateFields(body);
  if (!fields.compressed) {
    log.debug("Leaving unwrapCertificate(). Uncompressed.");
    return fields;
  }
  if (typeof inflate !== "function") {
    log.debug("Leaving unwrapCertificate(). Needs inflate.");
    return fields;
  }
  var der = null;
  try {
    der = iso.asBytes(inflate(fields.deflated));
  } catch (e) {
    log.debug("Leaving unwrapCertificate(). Inflate failed.");
    reject("The gzip certificate did not inflate: " + e.message);
  }
  if (der.length < 2 || der[0] !== 0x30) {
    log.debug("Leaving unwrapCertificate(). Not a certificate.");
    reject("The inflated certificate is not a DER certificate.");
  }
  fields.der = der;
  log.debug("Leaving unwrapCertificate().");
  return fields;
}

function describeGetData(command) {
  log.debug("Entering describeGetData().");
  var data = command.data;
  if (data.length < 2 || data[0] !== 0x5c) {
    log.debug("Leaving describeGetData(). No tag list.");
    reject("A PIV GET DATA carries tag 5C and the object tag.");
  }
  var len = data[1];
  if (data.length < 2 + len) {
    log.debug("Leaving describeGetData(). Short tag.");
    reject("The GET DATA object tag is shorter than its length.");
  }
  var tag = data.slice(2, 2 + len).toString("hex");
  log.debug("Leaving describeGetData().");
  return {
    summary: "GET DATA " + objectName(tag),
    rows: [
      { label: "Instruction", value: "GET DATA" },
      { label: "Object", value: objectName(tag) },
      { label: "Tag", value: tag.toUpperCase() }
    ]
  };
}

function describeGeneralAuthenticate(command) {
  log.debug("Entering describeGeneralAuthenticate().");
  var rows = [
    { label: "Instruction", value: "GENERAL AUTHENTICATE" },
    { label: "Algorithm", value: algorithmName(command.p1) },
    { label: "Slot", value: slotName(command.p2) }
  ];
  if (command.data.length === 0) {
    log.debug("Leaving describeGeneralAuthenticate(). No body.");
    return {
      summary: "GENERAL AUTHENTICATE " + slotName(command.p2),
      rows: rows
    };
  }
  var nodes = iso.parseElements(command.data);
  var dyn = childByTag(nodes, 0x7c);
  var inner = dyn ? iso.parseElements(dyn.value) : nodes;
  var witness = childByTag(inner, 0x80);
  var challenge = childByTag(inner, 0x81);
  var response = childByTag(inner, 0x82);
  var exponentiation = childByTag(inner, 0x85);
  if (witness) {
    rows.push({ label: "Witness",
        value: witness.value.length + " bytes" });
  }
  if (challenge) {
    rows.push({ label: "Challenge",
        value: iso.toHex(challenge.value) });
  }
  if (response) {
    rows.push({ label: "Response",
        value: response.value.length + " bytes (not checked)" });
  }
  if (exponentiation) {
    rows.push({ label: "Exponentiation (ECDH peer key)",
        value: exponentiation.value.length + " bytes" });
  }
  rows.push({ label: "Performed", value: "no — decoded only" });
  log.debug("Leaving describeGeneralAuthenticate().");
  return {
    summary: "GENERAL AUTHENTICATE " + slotName(command.p2),
    rows: rows
  };
}

function describeCommand(input) {
  log.debug("Entering describeCommand().");
  var command = iso.parseCommand(input);
  var ins = command.ins;
  var described = null;
  if (ins === 0xa4) {
    var aid = command.data.toString("hex");
    var which = "application " + aid.toUpperCase();
    if (aid === PIV_AID) {
      which = "PIV application";
    } else if (aid.indexOf(PIV_RID) === 0) {
      which = "PIV application (RID)";
    }
    described = {
      summary: "SELECT " + which,
      rows: [
        { label: "Instruction", value: "SELECT" },
        { label: "Application", value: which },
        { label: "AID", value: aid.toUpperCase() }
      ]
    };
  } else if (ins === 0xcb) {
    described = describeGetData(command);
  } else if (ins === 0x87) {
    described = describeGeneralAuthenticate(command);
  } else if (ins === 0x20) {
    described = {
      summary: "VERIFY " + pinReferenceName(command.p2),
      rows: [
        { label: "Instruction", value: "VERIFY" },
        { label: "Reference", value: pinReferenceName(command.p2) },
        { label: "Data", value: "PIN (" + command.data.length +
            " bytes, not shown)" }
      ]
    };
  } else if (ins === 0xf9) {
    described = {
      summary: "ATTEST " + slotName(command.p2),
      rows: [
        { label: "Instruction", value: "ATTEST (Yubico)" },
        { label: "Slot", value: slotName(command.p2) }
      ]
    };
  } else if (ins === 0xf7) {
    described = {
      summary: "GET METADATA " + slotName(command.p2),
      rows: [
        { label: "Instruction", value: "GET METADATA (Yubico)" },
        { label: "Slot", value: slotName(command.p2) }
      ]
    };
  } else if (ins === 0xf8) {
    described = {
      summary: "GET SERIAL",
      rows: [{ label: "Instruction", value: "GET SERIAL (Yubico)" }]
    };
  } else if (ins === 0xfd) {
    described = {
      summary: "GET VERSION",
      rows: [{ label: "Instruction", value: "GET VERSION (Yubico)" }]
    };
  } else {
    described = {
      summary: "INS " + hexByte(ins).toUpperCase(),
      rows: [
        { label: "CLA", value: hexByte(command.cla).toUpperCase() },
        { label: "INS", value: hexByte(ins).toUpperCase() },
        { label: "P1", value: hexByte(command.p1).toUpperCase() },
        { label: "P2", value: hexByte(command.p2).toUpperCase() },
        { label: "Data", value: command.data.length + " bytes" }
      ]
    };
  }
  log.debug("Leaving describeCommand().");
  return described;
}

function metadataRows(body) {
  log.debug("Entering metadataRows().");
  var nodes = iso.parseElements(body);
  var rows = [{ label: "Object", value: "key metadata (Yubico)" }];
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    var value = node.value;
    if (node.tag === 0x01 && value.length >= 1) {
      rows.push({ label: "Algorithm", value: algorithmName(value[0]) });
    } else if (node.tag === 0x02 && value.length >= 2) {
      var pin = PIN_POLICY[String(value[0])] || hexByte(value[0]);
      var touch = TOUCH_POLICY[String(value[1])] || hexByte(value[1]);
      rows.push({ label: "PIN policy", value: pin });
      rows.push({ label: "Touch policy", value: touch });
    } else if (node.tag === 0x03 && value.length >= 1) {
      // yubikit ORIGIN_GENERATED = 1, ORIGIN_IMPORTED = 2.
      var origin = value[0] === 0x01 ? "generated" :
          (value[0] === 0x02 ? "imported" : hexByte(value[0]));
      rows.push({ label: "Origin", value: origin });
    } else if (node.tag === 0x04) {
      rows.push({ label: "Public key", value: value.length + " bytes" });
    } else if (node.tag === 0x05 && value.length >= 1) {
      rows.push({ label: "Default value",
          value: value[0] ? "yes" : "no" });
    } else if (node.tag === 0x06 && value.length >= 2) {
      rows.push({ label: "Retries", value: value[1] + " of " +
          value[0] + " remaining" });
    } else {
      rows.push({ label: "Tag " + node.tagHex.toUpperCase(),
          value: iso.toHex(value) });
    }
  }
  log.debug("Leaving metadataRows().");
  return rows;
}

function describeResponse(input, inflate) {
  log.debug("Entering describeResponse().");
  var response = iso.parseResponse(input);
  var summary = statusLabel(response);
  var rows = [
    { label: "Status", value: summary }
  ];
  if (response.triesRemaining !== undefined) {
    rows.push({ label: "Tries remaining",
        value: String(response.triesRemaining) });
  }
  if (response.remaining !== undefined) {
    rows.push({ label: "Remaining",
        value: String(response.remaining) });
  }
  if (response.data.length === 0) {
    log.debug("Leaving describeResponse(). Status only.");
    return { summary: summary, rows: rows, certificate: null };
  }
  var certificate = null;
  var looksLikeCert = response.data[0] === 0x30 ||
      response.data[0] === 0x53 || response.data[0] === 0x70;
  if (looksLikeCert) {
    try {
      certificate = unwrapCertificate(response.data, inflate);
    } catch (e) {
      certificate = null;
    }
  }
  if (certificate && (certificate.der || certificate.deflated)) {
    rows.push({ label: "Certificate", value: certificate.compressed ?
        "gzip-compressed" : "uncompressed" });
    if (certificate.certInfo !== null) {
      rows.push({ label: "CertInfo",
          value: hexByte(certificate.certInfo).toUpperCase() });
    }
    if (certificate.der) {
      rows.push({ label: "DER", value: certificate.der.length + " bytes" });
      try {
        rows = rows.concat(attestationRows(certificate.der));
      } catch (e) {
        rows.push({ label: "Yubico extensions",
            value: "not read: " + e.message });
      }
    } else {
      rows.push({ label: "Compressed",
          value: certificate.deflated.length +
              " bytes, inflater not supplied" });
    }
    summary = "certificate, " + summary;
  } else if (response.data.length === 4) {
    var serial = response.data.readUInt32BE(0);
    rows.push({ label: "Serial", value: String(serial) });
    summary = "serial " + serial + ", " + summary;
  } else if (response.data.length === 3) {
    var version = response.data[0] + "." + response.data[1] + "." +
        response.data[2];
    rows.push({ label: "Version", value: version });
    summary = "version " + version + ", " + summary;
  } else {
    try {
      var meta = metadataRows(response.data);
      rows = rows.concat(meta);
      summary = "metadata, " + summary;
    } catch (e) {
      rows.push({ label: "Data",
          value: response.data.length + " bytes" });
    }
  }
  log.debug("Leaving describeResponse().");
  return { summary: summary, rows: rows, certificate: certificate };
}

// ---------------------------------------------------------------------------
// WRITING (SP 800-73-4 part 2, and Yubico's PIV extensions as yubikit sends
// them). DOM-free: the page sends what these build through the api's relay.
// ---------------------------------------------------------------------------

// The card management key's algorithms: SP 800-78-4 identifiers, the
// cipher's block size and the key length.
var MGM_ALGORITHMS = {
  "3des": { id: 0x03, block: 8, keyLen: 24, forge: "3DES-ECB" },
  "aes128": { id: 0x08, block: 16, keyLen: 16, forge: "AES-ECB" },
  "aes192": { id: 0x0a, block: 16, keyLen: 24, forge: "AES-ECB" },
  "aes256": { id: 0x0c, block: 16, keyLen: 32, forge: "AES-ECB" }
};
var MGM_BY_ID = { "3": "3des", "8": "aes128", "10": "aes192",
                  "12": "aes256" };
var DEFAULT_MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708";

// The key algorithms GENERATE takes.
var KEY_ALGORITHMS = {
  "rsa1024": 0x06, "rsa2048": 0x07, "rsa3072": 0x05, "rsa4096": 0x16,
  "eccp256": 0x11, "eccp384": 0x14, "ed25519": 0xe0, "x25519": 0xe1
};

// Slot -> the data object its certificate lives in.
function certificateObject(slot) {
  log.debug("Entering certificateObject().");
  var fixed = { 0x9a: "5fc105", 0x9c: "5fc10a", 0x9d: "5fc10b",
                0x9e: "5fc101", 0xf9: "5fff01" };
  var hex = fixed[slot];
  if (!hex && slot >= RETIRED_FIRST && slot <= RETIRED_LAST) {
    hex = (0x5fc10d + (slot - RETIRED_FIRST)).toString(16);
  }
  if (!hex) {
    log.debug("Leaving certificateObject(). Unknown slot.");
    reject("The slot is 9A, 9C, 9D, 9E or a retired slot 82 to 95.");
  }
  log.debug("Leaving certificateObject().");
  return hex;
}

function mgmAlgorithm(name) {
  log.debug("Entering mgmAlgorithm().");
  var alg = MGM_ALGORITHMS[String(name || "").toLowerCase()];
  if (!alg) {
    log.debug("Leaving mgmAlgorithm(). Unknown.");
    reject("The management key algorithm is 3DES, AES-128, AES-192 or " +
        "AES-256.");
  }
  log.debug("Leaving mgmAlgorithm().");
  return alg;
}

// One ECB block operation with no padding, which is what mutual
// authentication encrypts: single blocks.
function ecb(algName, key, data, decrypt) {
  log.debug("Entering ecb().");
  var alg = mgmAlgorithm(algName);
  var k = Buffer.from(key);
  if (k.length !== alg.keyLen) {
    log.debug("Leaving ecb(). Wrong key length.");
    reject("A " + algName.toUpperCase() + " management key is " +
        alg.keyLen + " bytes (" + alg.keyLen * 2 + " hex characters).");
  }
  var cipher = decrypt ?
      forge.cipher.createDecipher(alg.forge, forge.util.createBuffer(
          k.toString("binary"))) :
      forge.cipher.createCipher(alg.forge, forge.util.createBuffer(
          k.toString("binary")));
  cipher.start();
  cipher.update(forge.util.createBuffer(Buffer.from(data)
      .toString("binary")));
  cipher.finish(function () {
    return true;
  });
  var out = Buffer.from(cipher.output.getBytes(), "binary");
  log.debug("Leaving ecb().");
  return out;
}

// Mutual authentication with the card management key, step 1: ask for a
// witness. 7C { 80 (empty) }.
function authWitnessApdu(algName) {
  log.debug("Entering authWitnessApdu().");
  var alg = mgmAlgorithm(algName);
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x87, p1: alg.id,
      p2: 0x9b, data: iso.encodeTlv(0x7c, iso.encodeTlv(0x80,
          Buffer.alloc(0))), le: 256 });
  log.debug("Leaving authWitnessApdu().");
  return apdu;
}

// Step 2: decrypt the witness the card sent and send it back with a
// challenge of our own. Returns { apdu, expected }: the card's answer
// (tag 82) must equal `expected`, the challenge encrypted under the key —
// which is how the page knows the card holds the same key.
function authResponseApdu(algName, key, witnessAnswer, challenge) {
  log.debug("Entering authResponseApdu().");
  var alg = mgmAlgorithm(algName);
  var outer = iso.parseElements(Buffer.from(witnessAnswer));
  var dyn = outer.filter(function (n) {
    return n.tag === 0x7c;
  })[0];
  var witness = dyn ? iso.parseElements(dyn.value).filter(function (n) {
    return n.tag === 0x80;
  })[0] : null;
  if (!witness || witness.value.length !== alg.block) {
    log.debug("Leaving authResponseApdu(). No witness.");
    reject("The card did not send a witness of one " + alg.block +
        "-byte block. Is the algorithm right?");
  }
  var chal = Buffer.from(challenge);
  if (chal.length !== alg.block) {
    log.debug("Leaving authResponseApdu(). Bad challenge.");
    reject("The challenge is one " + alg.block + "-byte block.");
  }
  var decrypted = ecb(algName, key, witness.value, true);
  var data = iso.encodeTlv(0x7c, Buffer.concat([
    iso.encodeTlv(0x80, decrypted), iso.encodeTlv(0x81, chal)]));
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x87, p1: alg.id,
      p2: 0x9b, data: data, le: 256 });
  log.debug("Leaving authResponseApdu().");
  return { apdu: apdu, expected: ecb(algName, key, chal, false) };
}

// Whether the card's answer to step 2 proves it holds the key.
function authCardProven(answer, expected) {
  log.debug("Entering authCardProven().");
  var outer = iso.parseElements(Buffer.from(answer));
  var dyn = outer.filter(function (n) {
    return n.tag === 0x7c;
  })[0];
  var got = dyn ? iso.parseElements(dyn.value).filter(function (n) {
    return n.tag === 0x82;
  })[0] : null;
  var ok = !!got && Buffer.from(got.value).equals(Buffer.from(expected));
  log.debug("Leaving authCardProven(). " + ok);
  return ok;
}

// Yubico GET METADATA (INS F7) of a slot; for 9B its algorithm tells
// which cipher the management key uses.
function metadataApdu(slot) {
  log.debug("Entering metadataApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0xf7, p1: 0x00, p2: slot,
      le: 256 });
  log.debug("Leaving metadataApdu().");
  return apdu;
}

function managementAlgorithmFromMetadata(body) {
  log.debug("Entering managementAlgorithmFromMetadata().");
  var node = iso.parseElements(Buffer.from(body)).filter(function (n) {
    return n.tag === 0x01;
  })[0];
  var name = node && node.value.length ? MGM_BY_ID[String(node.value[0])] :
      null;
  log.debug("Leaving managementAlgorithmFromMetadata(). " + name);
  return name || null;
}

// GENERATE ASYMMETRIC KEY PAIR in a slot, with optional PIN and touch
// policies (Yubico tags AA and AB; 0 or absent is the slot's default).
function generateApdu(slot, algorithm, pinPolicy, touchPolicy) {
  log.debug("Entering generateApdu().");
  var alg = KEY_ALGORITHMS[String(algorithm || "").toLowerCase()];
  if (alg === undefined) {
    log.debug("Leaving generateApdu(). Unknown algorithm.");
    reject("The key algorithm is one of " +
        Object.keys(KEY_ALGORITHMS).join(", ") + ".");
  }
  var inner = [iso.encodeTlv(0x80, Buffer.from([alg]))];
  if (pinPolicy) {
    inner.push(iso.encodeTlv(0xaa, Buffer.from([pinPolicy])));
  }
  if (touchPolicy) {
    inner.push(iso.encodeTlv(0xab, Buffer.from([touchPolicy])));
  }
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x47, p1: 0x00, p2: slot,
      data: iso.encodeTlv(0xac, Buffer.concat(inner)), le: 256 });
  log.debug("Leaving generateApdu().");
  return apdu;
}

function derInteger(bytes) {
  log.debug("Entering derInteger().");
  var b = Buffer.from(bytes);
  var i = 0;
  while (i < b.length - 1 && b[i] === 0) {
    i += 1;
  }
  b = b.slice(i);
  if (b[0] & 0x80) {
    b = Buffer.concat([Buffer.from([0]), b]);
  }
  log.debug("Leaving derInteger().");
  return iso.encodeTlv(0x02, b);
}

// The public key GENERATE answered with (7F49), as a DER
// SubjectPublicKeyInfo.
function generatedPublicKey(answer, algorithm) {
  log.debug("Entering generatedPublicKey().");
  var outer = iso.parseElements(Buffer.from(answer));
  var tmpl = outer.filter(function (n) {
    return n.tag === 0x7f49;
  })[0];
  if (!tmpl) {
    log.debug("Leaving generatedPublicKey(). No 7F49.");
    reject("The card's answer has no public key template (7F49).");
  }
  var parts = {};
  iso.parseElements(tmpl.value).forEach(function (n) {
    parts[n.tag] = n.value;
  });
  var name = String(algorithm || "").toLowerCase();
  var oid = function (hex) {
    return iso.encodeTlv(0x06, Buffer.from(hex, "hex"));
  };
  var spki = null;
  if (/^rsa/.test(name)) {
    var rsaKey = iso.encodeTlv(0x30, Buffer.concat([derInteger(parts[0x81]),
        derInteger(parts[0x82])]));
    spki = iso.encodeTlv(0x30, Buffer.concat([
      iso.encodeTlv(0x30, Buffer.concat([oid("2a864886f70d010101"),
          Buffer.from([0x05, 0x00])])),
      iso.encodeTlv(0x03, Buffer.concat([Buffer.from([0]), rsaKey]))]));
  } else if (name === "eccp256" || name === "eccp384") {
    spki = iso.encodeTlv(0x30, Buffer.concat([
      iso.encodeTlv(0x30, Buffer.concat([oid("2a8648ce3d0201"),
          oid(name === "eccp256" ? "2a8648ce3d030107" : "2b81040022")])),
      iso.encodeTlv(0x03, Buffer.concat([Buffer.from([0]), parts[0x86]]))]));
  } else if (name === "ed25519" || name === "x25519") {
    spki = iso.encodeTlv(0x30, Buffer.concat([
      iso.encodeTlv(0x30, oid(name === "ed25519" ? "2b6570" : "2b656e")),
      iso.encodeTlv(0x03, Buffer.concat([Buffer.from([0]), parts[0x86]]))]));
  } else {
    log.debug("Leaving generatedPublicKey(). Unknown algorithm.");
    reject("Unknown key algorithm " + algorithm + ".");
  }
  log.debug("Leaving generatedPublicKey().");
  return spki;
}

// PUT DATA of a slot's certificate object: 53 { 70 cert, 71 00, FE }.
// An empty `der` deletes the certificate.
function putCertificateApdu(slot, der) {
  log.debug("Entering putCertificateApdu().");
  var object = Buffer.from(certificateObject(slot), "hex");
  var value = der && der.length ? Buffer.concat([
    iso.encodeTlv(0x70, Buffer.from(der)),
    iso.encodeTlv(0x71, Buffer.from([0x00])),
    iso.encodeTlv(0xfe, Buffer.alloc(0))]) : Buffer.alloc(0);
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0xdb, p1: 0x3f, p2: 0xff,
      data: Buffer.concat([iso.encodeTlv(0x5c, object),
                           iso.encodeTlv(0x53, value)]) });
  log.debug("Leaving putCertificateApdu().");
  return apdu;
}

// Yubico MOVE KEY (INS F6) to slot FF, which deletes the key in `slot`
// (firmware 5.7 and later).
function deleteKeyApdu(slot) {
  log.debug("Entering deleteKeyApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0xf6, p1: 0xff, p2: slot });
  log.debug("Leaving deleteKeyApdu().");
  return apdu;
}

function pinBlock(pin, what) {
  log.debug("Entering pinBlock().");
  var bytes = Buffer.from(String(pin == null ? "" : pin), "utf8");
  if (bytes.length < 6 || bytes.length > PIN_LENGTH) {
    log.debug("Leaving pinBlock(). Wrong length.");
    reject(what + " is 6 to 8 characters.");
  }
  log.debug("Leaving pinBlock().");
  return Buffer.concat([bytes, Buffer.alloc(PIN_LENGTH - bytes.length,
                                            0xff)]);
}

// CHANGE REFERENCE DATA for the PIN (80) or PUK (81): old then new.
function changeReferenceApdu(reference, oldValue, newValue) {
  log.debug("Entering changeReferenceApdu().");
  var what = reference === 0x81 ? "A PUK" : "A PIN";
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x24, p1: 0x00,
      p2: reference, data: Buffer.concat([pinBlock(oldValue, what),
                                          pinBlock(newValue, what)]) });
  log.debug("Leaving changeReferenceApdu().");
  return apdu;
}

// RESET RETRY COUNTER: unblock the PIN with the PUK.
function unblockPinApdu(puk, newPin) {
  log.debug("Entering unblockPinApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x2c, p1: 0x00, p2: 0x80,
      data: Buffer.concat([pinBlock(puk, "A PUK"),
                           pinBlock(newPin, "A PIN")]) });
  log.debug("Leaving unblockPinApdu().");
  return apdu;
}

// Yubico SET MANAGEMENT KEY (INS FF): P2 FE requires a touch to use it.
function setManagementKeyApdu(algName, key, requireTouch) {
  log.debug("Entering setManagementKeyApdu().");
  var alg = mgmAlgorithm(algName);
  var k = Buffer.from(key);
  if (k.length !== alg.keyLen) {
    log.debug("Leaving setManagementKeyApdu(). Wrong length.");
    reject("A " + algName.toUpperCase() + " management key is " +
        alg.keyLen + " bytes.");
  }
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0xff, p1: 0xff,
      p2: requireTouch ? 0xfe : 0xff,
      data: Buffer.concat([Buffer.from([alg.id, 0x9b, k.length]), k]) });
  log.debug("Leaving setManagementKeyApdu().");
  return apdu;
}

module.exports = {
  MGM_ALGORITHMS: MGM_ALGORITHMS,
  KEY_ALGORITHMS: KEY_ALGORITHMS,
  DEFAULT_MANAGEMENT_KEY: DEFAULT_MANAGEMENT_KEY,
  certificateObject: certificateObject,
  ecb: ecb,
  authWitnessApdu: authWitnessApdu,
  authResponseApdu: authResponseApdu,
  authCardProven: authCardProven,
  metadataApdu: metadataApdu,
  managementAlgorithmFromMetadata: managementAlgorithmFromMetadata,
  generateApdu: generateApdu,
  generatedPublicKey: generatedPublicKey,
  putCertificateApdu: putCertificateApdu,
  deleteKeyApdu: deleteKeyApdu,
  changeReferenceApdu: changeReferenceApdu,
  unblockPinApdu: unblockPinApdu,
  setManagementKeyApdu: setManagementKeyApdu,
  PIV_AID: PIV_AID,
  slotName: slotName,
  algorithmName: algorithmName,
  objectName: objectName,
  certificateFields: certificateFields,
  attestationRows: attestationRows,
  unwrapCertificate: unwrapCertificate,
  pinReferenceName: pinReferenceName,
  verifyApdu: verifyApdu,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
