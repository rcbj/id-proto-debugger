// File: openpgp_card.js
//
// OpenPGP card 3.4. The application id starts with D27600012401.
// This reads application related data, algorithm attributes,
// fingerprints, generation times and the public key. A public key
// that is RSA, a named curve or Ed25519 is handed back as an SPKI
// PEM, which is the form client/src/key_material.js already reads.
//
// PSO:CDS and decipher are named and not performed. There is no
// OpenPGP message format here.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "openpgp_card",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var iso = require("./iso7816.js");
var bytesLib = require("./crypto_bytes.js");

var AID_PREFIX = "d27600012401";

var ALGORITHMS = {
  "01": "RSA",
  "12": "ECDH",
  "13": "ECDSA",
  "16": "EdDSA"
};

var CURVES = {
  "2a8648ce3d030107": "P-256",
  "2b81040022": "P-384",
  "2b81040023": "P-521",
  "2b8104000a": "secp256k1",
  "2b06010401da470f01": "Ed25519",
  "2b060104019755010501": "X25519"
};

var CURVE_OID = {
  "P-256": "2a8648ce3d030107",
  "P-384": "2b81040022",
  "P-521": "2b81040023",
  "secp256k1": "2b8104000a",
  "Ed25519": "2b06010401da470f01",
  "X25519": "2b060104019755010501"
};

var EC_PUBLIC = "2a8648ce3d0201";
var RSA_OID = "2a864886f70d010101";
var ED25519_OID = "2b6570";
var X25519_OID = "2b656e";

// These values are themselves TLV. The constructed bit is not a
// reliable signal: 5F50 is a URL, and B6 holds a public key.
var CONTAINERS = {
  "6e": true,
  "65": true,
  "73": true,
  "7f49": true,
  "7f48": true,
  "b6": true,
  "b8": true,
  "a4": true
};

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  throw new Error(message);
}

function statusLabel(response) {
  log.debug("Entering statusLabel().");
  var text = response.sw.toString(16).toUpperCase().padStart(4, "0") +
      " " + response.name;
  log.debug("Leaving statusLabel().");
  return text;
}

function seq(children) {
  log.debug("Entering seq().");
  var out = iso.encodeTlv(0x30, children);
  log.debug("Leaving seq().");
  return out;
}

function intContent(buf) {
  log.debug("Entering intContent().");
  var body = Buffer.from(buf);
  if (body.length === 0 || (body[0] & 0x80) !== 0) {
    body = Buffer.concat([Buffer.from([0x00]), body]);
  }
  log.debug("Leaving intContent().");
  return body;
}

function bitString(payload) {
  log.debug("Entering bitString().");
  var out = Buffer.concat([Buffer.from([0x00]), Buffer.from(payload)]);
  log.debug("Leaving bitString().");
  return out;
}

function rsaSpki(modulus, exponent) {
  log.debug("Entering rsaSpki().");
  var pk = seq([
    { tag: 0x02, value: intContent(modulus) },
    { tag: 0x02, value: intContent(exponent) }
  ]);
  var spki = seq([
    { tag: 0x30, value: [
      { tag: 0x06, value: Buffer.from(RSA_OID, "hex") },
      { tag: 0x05, value: Buffer.alloc(0) }
    ] },
    { tag: 0x03, value: bitString(pk) }
  ]);
  log.debug("Leaving rsaSpki().");
  return bytesLib.derToPem(spki, "PUBLIC KEY");
}

function ecSpki(curveOid, point) {
  log.debug("Entering ecSpki().");
  var spki = seq([
    { tag: 0x30, value: [
      { tag: 0x06, value: Buffer.from(EC_PUBLIC, "hex") },
      { tag: 0x06, value: Buffer.from(curveOid, "hex") }
    ] },
    { tag: 0x03, value: bitString(point) }
  ]);
  log.debug("Leaving ecSpki().");
  return bytesLib.derToPem(spki, "PUBLIC KEY");
}

function okpSpki(oidHex, point) {
  log.debug("Entering okpSpki().");
  var spki = seq([
    { tag: 0x30, value: [
      { tag: 0x06, value: Buffer.from(oidHex, "hex") }
    ] },
    { tag: 0x03, value: bitString(point) }
  ]);
  log.debug("Leaving okpSpki().");
  return bytesLib.derToPem(spki, "PUBLIC KEY");
}

function curveByLength(point) {
  log.debug("Entering curveByLength().");
  var name = null;
  if (point.length === 65) {
    name = "P-256";
  } else if (point.length === 97) {
    name = "P-384";
  } else if (point.length === 133) {
    name = "P-521";
  }
  log.debug("Leaving curveByLength().");
  return name;
}

function publicKeyPem(found) {
  log.debug("Entering publicKeyPem().");
  var pem = null;
  if (found.modulus && found.exponent) {
    pem = rsaSpki(found.modulus, found.exponent);
  } else if (found.point) {
    var curve = found.curve;
    if (!curve) {
      curve = curveByLength(found.point);
    }
    if (curve === "Ed25519" && found.point.length === 32) {
      pem = okpSpki(ED25519_OID, found.point);
    } else if (curve === "X25519" && found.point.length === 32) {
      pem = okpSpki(X25519_OID, found.point);
    } else if (curve && CURVE_OID[curve] && found.point[0] === 0x04) {
      pem = ecSpki(CURVE_OID[curve], found.point);
    }
  }
  log.debug("Leaving publicKeyPem().");
  return pem;
}

function parseAlgorithmAttributes(value) {
  log.debug("Entering parseAlgorithmAttributes().");
  var bytes = Buffer.from(value);
  if (bytes.length < 1) {
    log.debug("Leaving parseAlgorithmAttributes(). Empty.");
    reject("Algorithm attributes are empty.");
  }
  var id = bytes[0].toString(16).padStart(2, "0");
  var name = ALGORITHMS[id] || ("algorithm " + id.toUpperCase());
  var out = { algorithm: name, id: id.toUpperCase(), curve: null,
      oid: null };
  if (bytes[0] === 0x01) {
    if (bytes.length < 5) {
      log.debug("Leaving parseAlgorithmAttributes(). Short RSA.");
      reject("RSA algorithm attributes are shorter than 5 bytes.");
    }
    out.modulusBits = bytes.readUInt16BE(1);
    out.exponentBits = bytes.readUInt16BE(3);
    if (bytes.length >= 6) {
      out.importFormat = bytes[5];
    }
  } else if (bytes.length >= 2) {
    var oidLen = bytes[1];
    if (bytes.length < 2 + oidLen) {
      log.debug("Leaving parseAlgorithmAttributes(). Short OID.");
      reject("The curve OID is shorter than its length.");
    }
    var oid = bytes.slice(2, 2 + oidLen).toString("hex");
    out.oid = oid;
    out.curve = CURVES[oid] || oid;
  }
  log.debug("Leaving parseAlgorithmAttributes().");
  return out;
}

function fingerprintText(value) {
  log.debug("Entering fingerprintText().");
  var bytes = Buffer.from(value);
  if (bytes.length !== 60 && bytes.length !== 0) {
    log.debug("Leaving fingerprintText(). Length.");
    return bytes.toString("hex");
  }
  var parts = [];
  var i = 0;
  for (i = 0; i < bytes.length; i += 20) {
    var one = bytes.slice(i, i + 20);
    var blank = true;
    var j = 0;
    for (j = 0; j < one.length; j++) {
      if (one[j] !== 0) {
        blank = false;
      }
    }
    parts.push(blank ? "(not set)" : one.toString("hex"));
  }
  log.debug("Leaving fingerprintText().");
  return parts.join(", ");
}

function generationText(value) {
  log.debug("Entering generationText().");
  var bytes = Buffer.from(value);
  var labels = ["signature", "decryption", "authentication"];
  var parts = [];
  var i = 0;
  for (i = 0; i + 4 <= bytes.length && i / 4 < 3; i += 4) {
    var stamp = bytes.readUInt32BE(i);
    var text = stamp === 0 ? "(not set)" :
        new Date(stamp * 1000).toISOString();
    parts.push(labels[i / 4] + " " + text);
  }
  log.debug("Leaving generationText().");
  return parts.join("; ");
}

function collect(nodes, found, rows) {
  log.debug("Entering collect().");
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    var hex = node.tagHex.toLowerCase();
    if (hex === "4f") {
      rows.push({ label: "AID", value: node.value.toString("hex")
          .toUpperCase() });
    } else if (hex === "5f50") {
      rows.push({ label: "URL", value: node.value.toString("utf8") });
    } else if (hex === "5b") {
      rows.push({ label: "Name", value: node.value.toString("utf8") });
    } else if (hex === "5f2d") {
      rows.push({ label: "Language",
          value: node.value.toString("utf8") });
    } else if (hex === "c1" || hex === "c2" || hex === "c3") {
      var which = hex === "c1" ? "Signature" :
          (hex === "c2" ? "Decryption" : "Authentication");
      var attr = parseAlgorithmAttributes(node.value);
      var text = attr.algorithm;
      if (attr.modulusBits) {
        text += ", modulus " + attr.modulusBits + " bits";
      }
      if (attr.curve) {
        text += ", " + attr.curve;
        found.curve = attr.curve;
      }
      rows.push({ label: which + " algorithm", value: text });
    } else if (hex === "c4") {
      rows.push({ label: "PW status", value: iso.toHex(node.value) });
    } else if (hex === "c5") {
      rows.push({ label: "Fingerprints",
          value: fingerprintText(node.value) });
    } else if (hex === "c6") {
      rows.push({ label: "CA fingerprints",
          value: fingerprintText(node.value) });
    } else if (hex === "cd") {
      rows.push({ label: "Generation",
          value: generationText(node.value) });
    } else if (hex === "93" && node.value.length === 3) {
      var counter = (node.value[0] << 16) | (node.value[1] << 8) |
          node.value[2];
      rows.push({ label: "Signature counter", value: String(counter) });
    } else if (hex === "81") {
      found.modulus = node.value;
      rows.push({ label: "Modulus",
          value: node.value.length + " bytes" });
    } else if (hex === "82") {
      found.exponent = node.value;
      rows.push({ label: "Exponent",
          value: node.value.length + " bytes" });
    } else if (hex === "86") {
      found.point = node.value;
      rows.push({ label: "Public point",
          value: node.value.length + " bytes" });
    }
    if (CONTAINERS[hex]) {
      collect(iso.parseElements(node.value), found, rows);
    }
  }
  log.debug("Leaving collect().");
}

function describeData(input) {
  log.debug("Entering describeData().");
  var bytes = iso.asBytes(input);
  var nodes = iso.parseElements(bytes);
  var found = { modulus: null, exponent: null, point: null, curve: null };
  var rows = [];
  collect(nodes, found, rows);
  var pem = publicKeyPem(found);
  if (pem) {
    rows.push({ label: "Public key", value: pem });
  }
  var summary = rows.length ? rows[0].value : "OpenPGP data";
  log.debug("Leaving describeData().");
  return { summary: summary, rows: rows, pem: pem };
}

function describeCommand(input) {
  log.debug("Entering describeCommand().");
  var command = iso.parseCommand(input);
  var rows = [];
  var summary = "INS " + command.ins.toString(16);
  var dataHex = command.data.toString("hex");
  if (command.ins === 0xa4 && dataHex.indexOf(AID_PREFIX) === 0) {
    summary = "SELECT OpenPGP card";
    rows = [
      { label: "Instruction", value: "SELECT" },
      { label: "AID", value: dataHex.toUpperCase() }
    ];
  } else if (command.ins === 0xca || command.ins === 0xcb) {
    summary = "GET DATA";
    var tag = command.ins === 0xca ?
        command.p1.toString(16).padStart(2, "0") +
        command.p2.toString(16).padStart(2, "0") : "in the data field";
    rows = [
      { label: "Instruction", value: "GET DATA" },
      { label: "Tag", value: tag.toUpperCase() }
    ];
  } else if (command.ins === 0x2a && command.p1 === 0x9e &&
      command.p2 === 0x9a) {
    summary = "PSO:CDS";
    rows = [
      { label: "Instruction", value: "COMPUTE DIGITAL SIGNATURE" },
      { label: "Data", value: command.data.length + " bytes" },
      { label: "Performed", value: "no — decoded only" }
    ];
  } else if (command.ins === 0x2a && command.p1 === 0x80 &&
      command.p2 === 0x86) {
    summary = "PSO:DECIPHER";
    rows = [
      { label: "Instruction", value: "DECIPHER" },
      { label: "Data", value: command.data.length + " bytes" },
      { label: "Performed", value: "no — decoded only" }
    ];
  } else if (command.ins === 0x88) {
    summary = "INTERNAL AUTHENTICATE";
    rows = [
      { label: "Instruction", value: "INTERNAL AUTHENTICATE" },
      { label: "Data", value: command.data.length + " bytes" },
      { label: "Performed", value: "no — decoded only" }
    ];
  } else {
    rows = [
      { label: "INS", value: command.ins.toString(16)
          .padStart(2, "0").toUpperCase() },
      { label: "Data", value: command.data.length + " bytes" }
    ];
  }
  log.debug("Leaving describeCommand().");
  return { summary: summary, rows: rows };
}

function describeResponse(input) {
  log.debug("Entering describeResponse().");
  var response = iso.parseResponse(input);
  var summary = statusLabel(response);
  var described = { summary: summary,
      rows: [{ label: "Status", value: summary }],
      pem: null };
  if (response.data.length === 0) {
    log.debug("Leaving describeResponse(). Status only.");
    return described;
  }
  try {
    var data = describeData(response.data);
    described.rows = described.rows.concat(data.rows);
    described.pem = data.pem;
    described.summary = data.summary + ", " + described.summary;
  } catch (e) {
    described.rows.push({ label: "Data",
        value: response.data.length + " bytes" });
  }
  log.debug("Leaving describeResponse().");
  return described;
}

module.exports = {
  AID_PREFIX: AID_PREFIX,
  parseAlgorithmAttributes: parseAlgorithmAttributes,
  publicKeyPem: publicKeyPem,
  describeData: describeData,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
