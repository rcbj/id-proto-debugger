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
  "5fc123": "pairing code reference data"
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

module.exports = {
  PIV_AID: PIV_AID,
  slotName: slotName,
  algorithmName: algorithmName,
  objectName: objectName,
  certificateFields: certificateFields,
  unwrapCertificate: unwrapCertificate,
  pinReferenceName: pinReferenceName,
  verifyApdu: verifyApdu,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
