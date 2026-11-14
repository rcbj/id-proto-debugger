// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
var sha1 = require("@noble/hashes/sha1").sha1;

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
// reliable signal: 5F50 is a URL, and B6 holds a public key. 7A is
// the security support template that holds the signature counter.
var CONTAINERS = {
  "6e": true,
  "65": true,
  "7a": true,
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
    // OpenPGP card 3.4 section 4.4.3.9: the algorithm ID, then the
    // curve OID's content octets with NO tag and NO length byte, then
    // an optional import-format byte (FF: public key included). The
    // first OID byte is not a length; P-256's is 2A.
    var oidBytes = bytes.slice(1);
    var oid = oidBytes.toString("hex");
    if (!CURVES[oid] && oidBytes.length > 1 &&
        oidBytes[oidBytes.length - 1] === 0xff) {
      oidBytes = oidBytes.slice(0, oidBytes.length - 1);
      oid = oidBytes.toString("hex");
      out.importFormat = 0xff;
    }
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

// ---------------------------------------------------------------------------
// WRITING (OpenPGP smart card application 3.4). DOM-free; the page sends
// these through the api's relay. Every write is preceded by VERIFY of the
// right password in the same sequence: PW3 (the Admin PIN) for PUT DATA
// and GENERATE, PW1 for the user PIN's own change.
// ---------------------------------------------------------------------------
var PW1 = 0x81;
var PW3 = 0x83;
var KEY_REFS = {
  sig: { crt: 0xb6, attr: 0xc1, fpr: 0xc7, time: 0xce },
  dec: { crt: 0xb8, attr: 0xc2, fpr: 0xc8, time: 0xcf },
  aut: { crt: 0xa4, attr: 0xc3, fpr: 0xc9, time: 0xd0 }
};
// Algorithm attributes (4.4.3.9): RSA is 01, modulus bits, public
// exponent bits (32), import format 00; ECC is the algorithm ID and the
// curve's OID without its tag and length.
var ATTRIBUTES = {
  "rsa2048": "010800002000", "rsa3072": "010c00002000",
  "rsa4096": "011000002000",
  "nistp256-ecdsa": "132a8648ce3d030107",
  "nistp384-ecdsa": "132b81040022",
  "nistp256-ecdh": "122a8648ce3d030107",
  "ed25519": "162b06010401da470f01",
  "cv25519": "122b060104019755010501"
};

function pinBytes(pin, min, what) {
  log.debug("Entering pinBytes().");
  var bytes = Buffer.from(String(pin == null ? "" : pin), "utf8");
  if (bytes.length < min || bytes.length > 127) {
    log.debug("Leaving pinBytes(). Wrong length.");
    reject(what + " is at least " + min + " characters.");
  }
  log.debug("Leaving pinBytes().");
  return bytes;
}

// VERIFY PW1 for signing (81), PW1 for everything else (82), or PW3 (83).
function verifyApdu(reference, pin) {
  log.debug("Entering verifyApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x20, p1: 0x00,
      p2: reference, data: pinBytes(pin, reference === PW3 ? 8 : 6,
          reference === PW3 ? "The Admin PIN" : "The PIN") });
  log.debug("Leaving verifyApdu().");
  return apdu;
}

// CHANGE REFERENCE DATA: PW1 (81) or PW3 (83), old then new.
function changePinApdu(reference, oldPin, newPin) {
  log.debug("Entering changePinApdu().");
  var min = reference === PW3 ? 8 : 6;
  var what = reference === PW3 ? "The Admin PIN" : "The PIN";
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x24, p1: 0x00,
      p2: reference, data: Buffer.concat([pinBytes(oldPin, min, what),
                                          pinBytes(newPin, min, what)]) });
  log.debug("Leaving changePinApdu().");
  return apdu;
}

// PUT DATA of a data object: name 5B, login 5E, URL 5F50, language 5F2D,
// sex 5F35, an algorithm attribute C1-C3, a fingerprint C7-C9, a
// generation time CE-D0, a touch policy D6-D8.
function putDataApdu(tag, value) {
  log.debug("Entering putDataApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0xda, p1: (tag >> 8) & 0xff,
      p2: tag & 0xff, data: Buffer.from(value || []) });
  log.debug("Leaving putDataApdu().");
  return apdu;
}

function keyRef(which) {
  log.debug("Entering keyRef().");
  var ref = KEY_REFS[which];
  if (!ref) {
    log.debug("Leaving keyRef(). Unknown.");
    reject("The key is sig, dec or aut.");
  }
  log.debug("Leaving keyRef().");
  return ref;
}

function algorithmAttributesApdu(which, algorithm) {
  log.debug("Entering algorithmAttributesApdu().");
  var attr = ATTRIBUTES[algorithm];
  if (!attr) {
    log.debug("Leaving algorithmAttributesApdu(). Unknown.");
    reject("The algorithm is one of " + Object.keys(ATTRIBUTES).join(", ") +
        ".");
  }
  var apdu = putDataApdu(keyRef(which).attr, Buffer.from(attr, "hex"));
  log.debug("Leaving algorithmAttributesApdu().");
  return apdu;
}

// GENERATE ASYMMETRIC KEY PAIR (P1 80) for the sig, dec or aut key.
function generateApdu(which) {
  log.debug("Entering generateApdu().");
  var apdu = iso.encodeCommand({ cla: 0x00, ins: 0x47, p1: 0x80, p2: 0x00,
      data: Buffer.from([keyRef(which).crt, 0x00]), le: 256 });
  log.debug("Leaving generateApdu().");
  return apdu;
}

// Touch policy (Yubico UIF, D6-D8): 0 off, 1 on, 2 fixed, 3 cached,
// 4 cached-fixed; the second byte is the button's feature flag.
function touchPolicyApdu(which, policy) {
  log.debug("Entering touchPolicyApdu().");
  var tag = { sig: 0xd6, dec: 0xd7, aut: 0xd8 }[which];
  if (!tag || [0, 1, 2, 3, 4].indexOf(Number(policy)) < 0) {
    log.debug("Leaving touchPolicyApdu(). Bad input.");
    reject("The key is sig, dec or aut, and the policy 0 to 4.");
  }
  var apdu = putDataApdu(tag, Buffer.from([Number(policy), 0x20]));
  log.debug("Leaving touchPolicyApdu().");
  return apdu;
}

function mpi(bytes) {
  log.debug("Entering mpi().");
  var b = Buffer.from(bytes);
  var i = 0;
  while (i < b.length - 1 && b[i] === 0) {
    i += 1;
  }
  b = b.slice(i);
  var bits = b.length === 0 ? 0 : (b.length - 1) * 8 +
      (32 - Math.clz32(b[0]));
  log.debug("Leaving mpi().");
  return Buffer.concat([Buffer.from([bits >> 8, bits & 0xff]), b]);
}

// The v4 public-key packet body and fingerprint (RFC 4880 sections 5.5.2
// and 12.2; RFC 6637 and draft-ietf-openpgp-crypto-refresh for ECC), as
// GnuPG computes them — so the fingerprint written to the card is the one
// gpg expects for the key it later sees there. `answer` is GENERATE's
// 7F49; `created` is seconds since 1970.
function v4Fingerprint(algorithm, answer, created) {
  log.debug("Entering v4Fingerprint().");
  var outer = iso.parseElements(Buffer.from(answer));
  var tmpl = outer.filter(function (n) {
    return n.tag === 0x7f49;
  })[0];
  if (!tmpl) {
    log.debug("Leaving v4Fingerprint(). No 7F49.");
    reject("The card's answer has no public key template (7F49).");
  }
  var parts = {};
  iso.parseElements(tmpl.value).forEach(function (n) {
    parts[n.tag] = n.value;
  });
  var time = Buffer.alloc(4);
  time.writeUInt32BE(created >>> 0, 0);
  var body = null;
  var oidField = function (hex) {
    var o = Buffer.from(hex, "hex");
    return Buffer.concat([Buffer.from([o.length]), o]);
  };
  if (/^rsa/.test(algorithm)) {
    body = Buffer.concat([Buffer.from([4]), time, Buffer.from([1]),
        mpi(parts[0x81]), mpi(parts[0x82])]);
  } else if (algorithm === "ed25519") {
    body = Buffer.concat([Buffer.from([4]), time, Buffer.from([22]),
        oidField("2b06010401da470f01"),
        mpi(Buffer.concat([Buffer.from([0x40]), parts[0x86]]))]);
  } else if (algorithm === "cv25519") {
    body = Buffer.concat([Buffer.from([4]), time, Buffer.from([18]),
        oidField("2b060104019755010501"),
        mpi(Buffer.concat([Buffer.from([0x40]), parts[0x86]])),
        Buffer.from([0x03, 0x01, 0x08, 0x07])]);
  } else if (/^nistp/.test(algorithm)) {
    var oidHex = /^nistp256/.test(algorithm) ? "2a8648ce3d030107" :
        "2b81040022";
    var ecdh = /ecdh$/.test(algorithm);
    body = Buffer.concat([Buffer.from([4]), time,
        Buffer.from([ecdh ? 18 : 19]), oidField(oidHex), mpi(parts[0x86]),
        ecdh ? Buffer.from([0x03, 0x01, 0x08, 0x07]) : Buffer.alloc(0)]);
  } else {
    log.debug("Leaving v4Fingerprint(). Unknown.");
    reject("Unknown algorithm " + algorithm + ".");
  }
  var packet = Buffer.concat([Buffer.from([0x99, body.length >> 8,
      body.length & 0xff]), body]);
  var fpr = Buffer.from(sha1(packet));
  log.debug("Leaving v4Fingerprint().");
  return { fingerprint: fpr, created: time, body: body };
}

// ---------------------------------------------------------------------------
// RESET (3.4 section 7.2.16-17): block PW1 and PW3 by spending their tries
// with a wrong value (eight zero bytes, as yubikit's reset() sends), then
// TERMINATE DF and ACTIVATE FILE. Afterwards: PIN 123456, Admin PIN
// 12345678, no keys, no cardholder data. Same `transmit` and `progress`
// as piv.reset().
// ---------------------------------------------------------------------------
var BLOCK_LIMIT = 256;

function blockApdu(reference) {
  log.debug("Entering blockApdu().");
  log.debug("Leaving blockApdu().");
  return iso.encodeCommand({ cla: 0x00, ins: 0x20, p1: 0x00, p2: reference,
                             data: Buffer.alloc(8, 0x00) });
}

function terminateApdu() {
  log.debug("Entering terminateApdu().");
  log.debug("Leaving terminateApdu().");
  return iso.encodeCommand({ cla: 0x00, ins: 0xe6, p1: 0x00, p2: 0x00 });
}

function activateApdu() {
  log.debug("Entering activateApdu().");
  log.debug("Leaving activateApdu().");
  return iso.encodeCommand({ cla: 0x00, ins: 0x44, p1: 0x00, p2: 0x00 });
}

function blockReference(transmit, reference, what, progress) {
  log.debug("Entering blockReference(). " + what);
  var spent = 0;
  var hex = blockApdu(reference).toString("hex");
  function step() {
    if (spent >= BLOCK_LIMIT) {
      throw new Error(what + " did not block after " + BLOCK_LIMIT +
          " tries; stopping.");
    }
    return transmit([hex]).then(function (r) {
      var sw = parseInt(r.status, 16);
      spent += 1;
      if (sw === 0x6983) {
        return spent;
      }
      if ((sw & 0xfff0) === 0x63c0 || sw === 0x6982) {
        if (progress) {
          progress(what + ": blocking");
        }
        return step();
      }
      if (sw === 0x9000) {
        throw new Error(what + " was ACCEPTED by eight zero bytes; " +
            "stopping without resetting.");
      }
      throw new Error(what + " answered " + r.status + "; stopping.");
    });
  }
  var done = step();
  log.debug("Leaving blockReference().");
  return done;
}

function reset(transmit, progress) {
  log.debug("Entering reset().");
  var total = 0;
  var done = transmit([iso.encodeCommand({ cla: 0x00, ins: 0xa4, p1: 0x04,
      p2: 0x00, data: Buffer.from(AID_PREFIX, "hex") }).toString("hex")])
    .then(function () {
      return blockReference(transmit, PW1, "The PIN", progress);
    }).then(function (n) {
      total += n;
      return blockReference(transmit, PW3, "The Admin PIN", progress);
    }).then(function (n) {
      total += n;
      return transmit([terminateApdu().toString("hex")]);
    }).then(function (r) {
      if (!/^9000$/i.test(r.status)) {
        throw new Error("TERMINATE answered " + r.status + ".");
      }
      return transmit([activateApdu().toString("hex")]);
    }).then(function (r) {
      if (!/^9000$/i.test(r.status)) {
        throw new Error("ACTIVATE answered " + r.status + ".");
      }
      return total;
    });
  log.debug("Leaving reset().");
  return done;
}

module.exports = {
  reset: reset,
  blockApdu: blockApdu,
  terminateApdu: terminateApdu,
  activateApdu: activateApdu,
  PW1: PW1,
  PW3: PW3,
  ATTRIBUTES: ATTRIBUTES,
  verifyApdu: verifyApdu,
  changePinApdu: changePinApdu,
  putDataApdu: putDataApdu,
  algorithmAttributesApdu: algorithmAttributesApdu,
  generateApdu: generateApdu,
  touchPolicyApdu: touchPolicyApdu,
  v4Fingerprint: v4Fingerprint,
  KEY_REFS: KEY_REFS,
  AID_PREFIX: AID_PREFIX,
  parseAlgorithmAttributes: parseAlgorithmAttributes,
  publicKeyPem: publicKeyPem,
  describeData: describeData,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
