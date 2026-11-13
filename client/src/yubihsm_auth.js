// File: yubihsm_auth.js
//
// The YubiKey applet that authenticates TO a YubiHSM 2 (yubikit
// 5.8.0, yubikit/hsmauth.py). It builds and reads APDUs. It does
// not open a session on an HSM, and a CALCULATE result is the three
// session keys a host would hand to one.
//
// The traces this module round-trips are containers this code
// built from that layout. They are not a capture from a key.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "yubihsm_auth",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var pbkdf2 = require("@noble/hashes/pbkdf2").pbkdf2;
var sha256 = require("@noble/hashes/sha256").sha256;
var iso = require("./iso7816.js");

var AID = "a000000527210701";
var AES128 = 38;
var EC_P256 = 39;
var MANAGEMENT_LEN = 16;
var PASSWORD_LEN = 16;
var EC_KEY_LEN = 32;

var ALGORITHMS = {};
ALGORITHMS[AES128] = "AES-128 Yubico authentication";
ALGORITHMS[EC_P256] = "EC P-256 Yubico authentication";

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

function algorithmName(byte) {
  log.debug("Entering algorithmName().");
  var name = ALGORITHMS[byte] ||
      ("algorithm " + Number(byte).toString(16).toUpperCase());
  log.debug("Leaving algorithmName().");
  return name;
}

function labelBytes(label) {
  log.debug("Entering labelBytes().");
  var bytes = Buffer.from(String(label == null ? "" : label), "utf8");
  if (bytes.length < 1 || bytes.length > 64) {
    log.debug("Leaving labelBytes(). Length.");
    reject("A label is 1 to 64 bytes.");
  }
  log.debug("Leaving labelBytes().");
  return bytes;
}

function passwordBytes(value) {
  log.debug("Entering passwordBytes().");
  var bytes = null;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    bytes = Buffer.from(value);
    if (bytes.length !== PASSWORD_LEN) {
      log.debug("Leaving passwordBytes(). Length.");
      reject("A credential password is 16 bytes.");
    }
  } else {
    bytes = Buffer.from(String(value == null ? "" : value), "utf8");
    if (bytes.length > PASSWORD_LEN) {
      log.debug("Leaving passwordBytes(). Long.");
      reject("A credential password is 16 bytes.");
    }
    if (bytes.length < PASSWORD_LEN) {
      bytes = Buffer.concat([
        bytes, Buffer.alloc(PASSWORD_LEN - bytes.length, 0)
      ]);
    }
  }
  log.debug("Leaving passwordBytes().");
  return bytes;
}

function keyBytes(value, length, label) {
  log.debug("Entering keyBytes().");
  var bytes = null;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    bytes = Buffer.from(value);
  } else {
    var text = String(value == null ? "" : value).replace(/\s+/g, "");
    if (!/^[0-9a-fA-F]+$/.test(text) || text.length !== length * 2) {
      log.debug("Leaving keyBytes(). Hex.");
      reject(label + " is " + length + " bytes.");
    }
    bytes = Buffer.from(text, "hex");
  }
  if (bytes.length !== length) {
    log.debug("Leaving keyBytes(). Length.");
    reject(label + " is " + length + " bytes.");
  }
  log.debug("Leaving keyBytes().");
  return bytes;
}

// PBKDF2-HMAC-SHA256, salt "Yubico", 10000 rounds, 32 bytes.
// The first half is the encryption key and the second the MAC key.
function deriveKeys(password) {
  log.debug("Entering deriveKeys().");
  var text = String(password == null ? "" : password);
  if (!text) {
    log.debug("Leaving deriveKeys(). Empty.");
    reject("The derivation password is empty.");
  }
  var derived = pbkdf2(sha256, Buffer.from(text, "utf8"),
      Buffer.from("Yubico", "utf8"), { c: 10000, dkLen: 32 });
  var bytes = Buffer.from(derived);
  log.debug("Leaving deriveKeys().");
  return { enc: bytes.slice(0, 16), mac: bytes.slice(16, 32) };
}

function algorithmCode(value) {
  log.debug("Entering algorithmCode().");
  var code = Number(value);
  if (code !== AES128 && code !== EC_P256) {
    log.debug("Leaving algorithmCode(). Unknown.");
    reject("The algorithm is 38 (AES-128) or 39 (EC P-256).");
  }
  log.debug("Leaving algorithmCode().");
  return code;
}

// PUT builds the APDU and does not send it. An empty EC private
// key means the key generates the pair.
function putApdu(opts) {
  log.debug("Entering putApdu().");
  var options = opts || {};
  var code = algorithmCode(options.algorithm);
  var parts = [
    iso.encodeTlv(0x7b, keyBytes(options.managementKey,
        MANAGEMENT_LEN, "The management key")),
    iso.encodeTlv(0x71, labelBytes(options.label)),
    iso.encodeTlv(0x74, Buffer.from([code]))
  ];
  if (code === AES128) {
    var enc = options.keyEnc;
    var mac = options.keyMac;
    if (options.derivationPassword) {
      var derived = deriveKeys(options.derivationPassword);
      enc = derived.enc;
      mac = derived.mac;
    }
    parts.push(iso.encodeTlv(0x75,
        keyBytes(enc, MANAGEMENT_LEN, "The encryption key")));
    parts.push(iso.encodeTlv(0x76,
        keyBytes(mac, MANAGEMENT_LEN, "The MAC key")));
  } else {
    var priv = options.privateKey;
    var privBytes = (priv === undefined || priv === null || priv === "") ?
        Buffer.alloc(0) : keyBytes(priv, EC_KEY_LEN, "The private key");
    parts.push(iso.encodeTlv(0x7d, privBytes));
  }
  parts.push(iso.encodeTlv(0x73,
      passwordBytes(options.credentialPassword)));
  parts.push(iso.encodeTlv(0x7a,
      Buffer.from([options.touch ? 1 : 0])));
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00,
    data: Buffer.concat(parts), le: null
  });
  log.debug("Leaving putApdu().");
  return apdu;
}

function deleteApdu(managementKey, label) {
  log.debug("Entering deleteApdu().");
  var data = Buffer.concat([
    iso.encodeTlv(0x7b, keyBytes(managementKey,
        MANAGEMENT_LEN, "The management key")),
    iso.encodeTlv(0x71, labelBytes(label))
  ]);
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x02, p1: 0x00, p2: 0x00,
    data: data, le: null
  });
  log.debug("Leaving deleteApdu().");
  return apdu;
}

function calculateApdu(opts) {
  log.debug("Entering calculateApdu().");
  var options = opts || {};
  var context = iso.asBytes(options.context || Buffer.alloc(0));
  if (context.length === 0) {
    log.debug("Leaving calculateApdu(). No context.");
    reject("CALCULATE needs a context.");
  }
  var parts = [
    iso.encodeTlv(0x71, labelBytes(options.label)),
    iso.encodeTlv(0x77, context)
  ];
  if (options.publicKey) {
    var point = iso.asBytes(options.publicKey);
    if (point.length !== 65 || point[0] !== 0x04) {
      log.debug("Leaving calculateApdu(). Public key.");
      reject("The YubiHSM public key is 0x04 followed by x and y.");
    }
    parts.push(iso.encodeTlv(0x7c, point));
  }
  if (options.cardCryptogram) {
    parts.push(iso.encodeTlv(0x78,
        iso.asBytes(options.cardCryptogram)));
  }
  parts.push(iso.encodeTlv(0x73,
      passwordBytes(options.credentialPassword)));
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x03, p1: 0x00, p2: 0x00,
    data: Buffer.concat(parts), le: 256
  });
  log.debug("Leaving calculateApdu().");
  return apdu;
}

function listApdu() {
  log.debug("Entering listApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x05, p1: 0x00, p2: 0x00,
    data: Buffer.alloc(0), le: 256
  });
  log.debug("Leaving listApdu().");
  return apdu;
}

function resetApdu() {
  log.debug("Entering resetApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x06, p1: 0xde, p2: 0xad,
    data: Buffer.alloc(0), le: null
  });
  log.debug("Leaving resetApdu().");
  return apdu;
}

function versionApdu() {
  log.debug("Entering versionApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0x07, p1: 0x00, p2: 0x00,
    data: Buffer.alloc(0), le: 256
  });
  log.debug("Leaving versionApdu().");
  return apdu;
}

function selectApdu() {
  log.debug("Entering selectApdu().");
  var apdu = iso.encodeCommand({
    cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00,
    data: Buffer.from(AID, "hex"), le: 256
  });
  log.debug("Leaving selectApdu().");
  return apdu;
}

function parseList(body) {
  log.debug("Entering parseList().");
  var nodes = iso.parseElements(body);
  var creds = [];
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    if (node.tag !== 0x72) {
      continue;
    }
    if (node.value.length < 3) {
      log.debug("Leaving parseList(). Short.");
      reject("A credential list entry is shorter than 3 bytes.");
    }
    var value = node.value;
    var labelLen = value.length - 3;
    creds.push({
      algorithm: value[0],
      algorithmName: algorithmName(value[0]),
      touch: value[1] !== 0,
      label: value.slice(2, 2 + labelLen).toString("utf8"),
      counter: value[value.length - 1]
    });
  }
  log.debug("Leaving parseList().");
  return creds;
}

// The raw CALCULATE body, not a TLV. yubikit SessionKeys.parse
// splits it into three 16-byte keys.
function parseSessionKeys(body) {
  log.debug("Entering parseSessionKeys().");
  var bytes = iso.asBytes(body);
  if (bytes.length < 48) {
    log.debug("Leaving parseSessionKeys(). Short.");
    reject("Session keys are 48 bytes.");
  }
  var out = {
    keySenc: bytes.slice(0, 16),
    keySmac: bytes.slice(16, 32),
    keySrmac: bytes.slice(32, 48)
  };
  log.debug("Leaving parseSessionKeys().");
  return out;
}

function versionText(bytes) {
  log.debug("Entering versionText().");
  var parts = [];
  var i = 0;
  for (i = 0; i < bytes.length; i++) {
    parts.push(String(bytes[i]));
  }
  log.debug("Leaving versionText().");
  return parts.join(".");
}

function secretRow(label, length) {
  log.debug("Entering secretRow().");
  var text = length === 0 ? "empty (generate on the key)" :
      (length + " bytes, not shown");
  log.debug("Leaving secretRow().");
  return { label: label, value: text };
}

function describeCommand(input) {
  log.debug("Entering describeCommand().");
  var command = iso.parseCommand(input);
  var summary = "INS " + command.ins.toString(16);
  var rows = [
    { label: "INS", value: command.ins.toString(16).padStart(2, "0")
        .toUpperCase() }
  ];
  var aid = command.data.toString("hex");
  if (command.ins === 0xa4 && aid.indexOf(AID) === 0) {
    summary = "SELECT YubiHSM Auth";
    rows = [
      { label: "Instruction", value: "SELECT" },
      { label: "AID", value: aid.toUpperCase() }
    ];
  } else if (command.ins === 0x01) {
    summary = "PUT (not sent)";
    rows = [{ label: "Instruction", value: "PUT (not sent)" }];
    var nodes = iso.parseElements(command.data);
    var n = 0;
    for (n = 0; n < nodes.length; n++) {
      var node = nodes[n];
      if (node.tag === 0x71) {
        rows.push({ label: "Label",
            value: node.value.toString("utf8") });
      } else if (node.tag === 0x74 && node.value.length >= 1) {
        rows.push({ label: "Algorithm",
            value: algorithmName(node.value[0]) });
      } else if (node.tag === 0x7a && node.value.length >= 1) {
        rows.push({ label: "Touch",
            value: node.value[0] ? "required" : "not required" });
      } else if (node.tag === 0x7b) {
        rows.push(secretRow("Management key", node.value.length));
      } else if (node.tag === 0x73) {
        rows.push(secretRow("Credential password", node.value.length));
      } else if (node.tag === 0x75) {
        rows.push(secretRow("Encryption key", node.value.length));
      } else if (node.tag === 0x76) {
        rows.push(secretRow("MAC key", node.value.length));
      } else if (node.tag === 0x7d) {
        rows.push(secretRow("Private key", node.value.length));
      }
    }
  } else if (command.ins === 0x02) {
    summary = "DELETE (not sent)";
    rows = [{ label: "Instruction", value: "DELETE (not sent)" }];
  } else if (command.ins === 0x03) {
    summary = "CALCULATE (not performed)";
    rows = [
      { label: "Instruction", value: "CALCULATE" },
      { label: "Performed", value: "no — decoded only" },
      { label: "Result", value: "session keys a host would hand " +
          "to a YubiHSM 2" }
    ];
  } else if (command.ins === 0x04) {
    summary = "GET CHALLENGE";
    rows = [
      { label: "Instruction", value: "GET CHALLENGE" },
      { label: "Symmetric", value: "8-byte host challenge" },
      { label: "Asymmetric", value: "EPK-OCE" }
    ];
  } else if (command.ins === 0x05) {
    summary = "LIST";
    rows = [{ label: "Instruction", value: "LIST" }];
  } else if (command.ins === 0x06) {
    summary = "RESET";
    rows = [{ label: "Instruction",
        value: "RESET (P1 P2 DE AD, not sent)" }];
  } else if (command.ins === 0x07) {
    summary = "GET VERSION";
    rows = [{ label: "Instruction", value: "GET VERSION" }];
  }
  log.debug("Leaving describeCommand().");
  return { summary: summary, rows: rows };
}

function describeResponse(input) {
  log.debug("Entering describeResponse().");
  var response = iso.parseResponse(input);
  var summary = statusLabel(response);
  var rows = [{ label: "Status", value: summary }];
  var body = response.data;
  var sessionKeys = null;
  if (body.length === 0) {
    log.debug("Leaving describeResponse(). Status only.");
    return { summary: summary, rows: rows, sessionKeys: null };
  }
  var nodes = null;
  try {
    nodes = iso.parseElements(body);
  } catch (e) {
    nodes = null;
  }
  if (nodes && nodes.length > 0 && nodes[0].tag === 0x72) {
    var creds = parseList(body);
    var i = 0;
    for (i = 0; i < creds.length; i++) {
      var cred = creds[i];
      rows.push({ label: cred.label, value: cred.algorithmName +
          ", touch " + (cred.touch ? "required" : "not required") +
          ", counter " + cred.counter });
    }
    summary = creds.length + " credential(s), " + summary;
  } else if (nodes && nodes.length === 1 && nodes[0].tag === 0x79) {
    var version = versionText(nodes[0].value);
    rows.push({ label: "Version", value: version });
    summary = "version " + version + ", " + summary;
  } else if (body.length === 48) {
    sessionKeys = parseSessionKeys(body);
    rows.push({ label: "key_senc",
        value: iso.toHex(sessionKeys.keySenc) });
    rows.push({ label: "key_smac",
        value: iso.toHex(sessionKeys.keySmac) });
    rows.push({ label: "key_srmac",
        value: iso.toHex(sessionKeys.keySrmac) });
    rows.push({ label: "Handed to",
        value: "a YubiHSM 2, by a host. This page does not " +
            "open an HSM session." });
    summary = "session keys, " + summary;
  } else if (body.length === 65 && body[0] === 0x04) {
    rows.push({ label: "Public key",
        value: "EC P-256 uncompressed point" });
    summary = "public key, " + summary;
  } else if (body.length === 3) {
    var rawVersion = versionText(body);
    rows.push({ label: "Version", value: rawVersion });
    summary = "version " + rawVersion + ", " + summary;
  } else if (body.length === 1) {
    rows.push({ label: "Retries", value: String(body[0]) });
    summary = "retries " + body[0] + ", " + summary;
  } else if (body.length === 8) {
    rows.push({ label: "Host challenge", value: iso.toHex(body) });
    summary = "host challenge, " + summary;
  } else {
    rows.push({ label: "Data", value: body.length + " bytes" });
  }
  log.debug("Leaving describeResponse().");
  return { summary: summary, rows: rows, sessionKeys: sessionKeys };
}

module.exports = {
  AID: AID,
  AES128: AES128,
  EC_P256: EC_P256,
  algorithmName: algorithmName,
  deriveKeys: deriveKeys,
  putApdu: putApdu,
  deleteApdu: deleteApdu,
  calculateApdu: calculateApdu,
  listApdu: listApdu,
  resetApdu: resetApdu,
  versionApdu: versionApdu,
  selectApdu: selectApdu,
  parseList: parseList,
  parseSessionKeys: parseSessionKeys,
  describeCommand: describeCommand,
  describeResponse: describeResponse
};
