// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: smartcard_engine.js
//
// ---------------------------------------------------------------------------
// ISO 7816-4 command and response APDUs, and BER-TLV, driven in NODE with
// no browser and no reader. client/src/iso7816.js has no DOM, which is
// what lets this job exist: a length that overruns has to be an error
// here, because a page that sliced the value short and showed it would
// look like a successful read of a truncated object.
//
// The vectors are the cases the encoding defines (1, 2S, 3S, 4S, 2E, 3E,
// 4E), Yubico's published OTP vectors, the RFC 4226 and RFC 6238
// appendices, and APDU containers this code built for PIV, YKOATH, the
// OpenPGP card and YubiHSM Auth. Those containers are not captures.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it
// has not been told about. This job parses no arguments at all — it drives
// a module in process and has no base url to visit — so node ignores the
// pair and there is nothing to declare. Do not add commander here without
// also declaring `--url`; see tests/CLAUDE.md.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "smartcard_engine",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

// The module under test is read from the client TREE rather than from a
// flat copy beside this script. tests/Dockerfile copies that tree, and
// __dirname/.. is /usr/src in the image and the repository root in a
// checkout. Through module_paths.js rather than a bare require(), for the
// reason tests/CLAUDE.md gives: node resolves a module's own requires
// from where THAT module lives, so iso7816.js's require("bunyan") would
// be looked for under client/node_modules, which neither the image nor a
// tests-only install has.
const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const paths = require("./module_paths.js");
const iso = paths.requireSharedModule(
    [path.join(SRC, "iso7816.js")], "client/src/iso7816.js");
const piv = paths.requireSharedModule(
    [path.join(SRC, "piv.js")], "client/src/piv.js");
const otp = paths.requireSharedModule(
    [path.join(SRC, "yubico_otp.js")], "client/src/yubico_otp.js");
const oath = paths.requireSharedModule(
    [path.join(SRC, "oath.js")], "client/src/oath.js");
const pgp = paths.requireSharedModule(
    [path.join(SRC, "openpgp_card.js")], "client/src/openpgp_card.js");
const hsm = paths.requireSharedModule(
    [path.join(SRC, "yubihsm_auth.js")], "client/src/yubihsm_auth.js");
const x509 = paths.requireSharedModule(
    [path.join(SRC, "x509.js")], "client/src/x509.js");
const keys = paths.requireSharedModule(
    [path.join(SRC, "key_material.js")], "client/src/key_material.js");
const bytes = paths.requireSharedModule(
    [path.join(SRC, "crypto_bytes.js")], "client/src/crypto_bytes.js");
const otpHid = paths.requireSharedModule(
  [path.join(REPO, "api", "otp_hid.js"), path.join(__dirname, "otp_hid.js")],
  "api/otp_hid.js");
const otpVerify = paths.requireSharedModule(
    [path.join(REPO, "api", "otp_verify.js"),
        path.join(__dirname, "otp_verify.js")],
    "api/otp_verify.js");
const reader = paths.requireSharedModule(
    [path.join(REPO, "api", "smartcard_reader.js"),
        path.join(__dirname, "smartcard_reader.js")],
    "api/smartcard_reader.js");

const zlib = require("zlib");
const crypto = require("crypto");

function fromHex(text) {
  log.debug("Entering fromHex().");
  log.debug("Leaving fromHex().");
  return Buffer.from(String(text).replace(/\s+/g, ""), "hex");
}

function cmd(extra) {
  log.debug("Entering cmd().");
  var out = {
    cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00,
    data: Buffer.alloc(0), le: null, extended: false
  };
  var key = null;
  for (key in extra) {
    if (Object.prototype.hasOwnProperty.call(extra, key)) {
      out[key] = extra[key];
    }
  }
  log.debug("Leaving cmd().");
  return out;
}

function assertBytes(actual, expected, label) {
  log.debug("Entering assertBytes().");
  if (actual.equals(expected)) {
    log.debug("Leaving assertBytes().");
    return;
  }
  var detail = actual.length > 64 ? (actual.length + " bytes") :
      iso.toHex(actual);
  var want = expected.length > 64 ? (expected.length + " bytes") :
      iso.toHex(expected);
  log.debug("Leaving assertBytes().");
  assert.fail(label + ": " + detail + " rather than " + want);
}

function throws(fn, text) {
  log.debug("Entering throws().");
  var caught = null;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, "expected an error containing \"" + text + "\".");
  assert.ok(String(caught.message).indexOf(text) >= 0,
      "\"" + caught.message + "\" does not contain \"" + text + "\".");
  log.debug("Leaving throws().");
}

function expectCommand(label, input, expected) {
  log.debug("Entering expectCommand().");
  var parsed = iso.parseCommand(input);
  assert.strictEqual(parsed.cla, expected.cla, label + " CLA");
  assert.strictEqual(parsed.ins, expected.ins, label + " INS");
  assert.strictEqual(parsed.p1, expected.p1, label + " P1");
  assert.strictEqual(parsed.p2, expected.p2, label + " P2");
  assert.strictEqual(parsed.le, expected.le, label + " Le");
  assert.strictEqual(parsed.extended, expected.extended,
      label + " extended");
  assertBytes(parsed.data, expected.data, label + " data");
  var wire = expected.wire ? iso.asBytes(expected.wire) :
      iso.asBytes(input);
  assertBytes(iso.encodeCommand(parsed), wire, label + " re-encode");
  log.debug("Leaving expectCommand().");
}

function asEncoded(node) {
  log.debug("Entering asEncoded().");
  var tag = node.tag <= 255 ? node.tag : Buffer.from(node.tagHex, "hex");
  var value = node.value;
  if (node.constructed) {
    value = [];
    var i = 0;
    for (i = 0; i < node.children.length; i++) {
      value.push(asEncoded(node.children[i]));
    }
  }
  log.debug("Leaving asEncoded().");
  return { tag: tag, value: value };
}

// Re-encoding is only equal to the input when the input already used the
// shortest definite length. A long form of a short value is accepted on
// read and written back short; that case is asserted on its own.
function roundTripTlv(label, input) {
  log.debug("Entering roundTripTlv().");
  var nodes = iso.parseTlv(input);
  var parts = [];
  var i = 0;
  for (i = 0; i < nodes.length; i++) {
    var item = asEncoded(nodes[i]);
    parts.push(iso.encodeTlv(item.tag, item.value));
  }
  assertBytes(Buffer.concat(parts), iso.asBytes(input), label);
  log.debug("Leaving roundTripTlv().");
}

function nested(levels) {
  log.debug("Entering nested().");
  var node = { tag: 0x80, value: Buffer.from([0xaa]) };
  var n = 0;
  for (n = 0; n < levels; n++) {
    node = { tag: 0xa0, value: [node] };
  }
  var encoded = iso.encodeTlv(node.tag, node.value);
  log.debug("Leaving nested().");
  return encoded;
}

// ===========================================================================
// 1. Command APDUs. Le is a count of bytes: short 0x00 is 256, extended
//    0x0000 is 65536.
// ===========================================================================
function commandsRoundTrip() {
  log.debug("Entering commandsRoundTrip().");
  expectCommand("case 1", "00 a4 04 00", cmd({}));
  expectCommand("case 1 pasted", "00:A4:04:00", cmd({
    wire: "00 a4 04 00"
  }));
  expectCommand("case 1 with breaks", "00\nA4 04\t00", cmd({
    wire: "00 a4 04 00"
  }));
  expectCommand("case 2S Le 256", "00 a4 04 00 00", cmd({ le: 256 }));
  expectCommand("case 2S Le 8", "00 a4 04 00 08", cmd({ le: 8 }));
  expectCommand("case 3S", "00 a4 04 00 02 3f 00", cmd({
    data: Buffer.from([0x3f, 0x00])
  }));
  expectCommand("case 4S Le 256", "00 a4 04 00 02 3f 00 00", cmd({
    data: Buffer.from([0x3f, 0x00]), le: 256
  }));
  expectCommand("case 4S Le 1", "00 a4 04 00 02 3f 00 01", cmd({
    data: Buffer.from([0x3f, 0x00]), le: 1
  }));
  expectCommand("case 2E Le 256", "00 a4 04 00 00 01 00", cmd({
    le: 256, extended: true
  }));
  expectCommand("case 2E Le 65536", "00 a4 04 00 00 00 00", cmd({
    le: 65536, extended: true
  }));
  expectCommand("case 2E Le 5", "00 a4 04 00 00 00 05", cmd({
    le: 5, extended: true
  }));
  expectCommand("case 3E", "00 a4 04 00 00 00 01 ff", cmd({
    data: Buffer.from([0xff]), extended: true
  }));
  expectCommand("case 4E", "00 a4 04 00 00 00 01 ff 01 00", cmd({
    data: Buffer.from([0xff]), le: 256, extended: true
  }));
  expectCommand("VERIFY header", "0c 20 00 80", cmd({
    cla: 0x0c, ins: 0x20, p1: 0x00, p2: 0x80
  }));

  var shortData = Buffer.alloc(255, 0x11);
  var shortWire = Buffer.concat([
    fromHex("00 a4 04 00 ff"), shortData
  ]);
  expectCommand("case 3S at 255", shortWire, cmd({ data: shortData }));

  var longData = Buffer.alloc(256, 0x22);
  var longWire = Buffer.concat([
    fromHex("00 a4 04 00 00 01 00"), longData
  ]);
  expectCommand("case 3E at 256", longWire, cmd({
    data: longData, extended: true
  }));

  var maxData = Buffer.alloc(65535, 0x33);
  var maxWire = Buffer.concat([
    fromHex("00 a4 04 00 00 ff ff"), maxData, fromHex("00 00")
  ]);
  expectCommand("case 4E at 65535, Le 65536", maxWire, cmd({
    data: maxData, le: 65536, extended: true
  }));

  // A body that fits in a short APDU stays short unless the caller
  // asks for the extended form. Le above 256 forces it anyway.
  assertBytes(iso.encodeCommand(cmd({ le: 256, extended: true })),
      fromHex("00 a4 04 00 00 01 00"), "forced case 2E");
  assertBytes(iso.encodeCommand(cmd({ le: 257 })),
      fromHex("00 a4 04 00 00 01 01"), "Le 257 forces extended");
  assertBytes(iso.encodeCommand(cmd({ extended: true })),
      fromHex("00 a4 04 00"), "no extended case 1");
  assert.strictEqual(iso.toHex(fromHex("00a40400")), "00 a4 04 00");
  assert.strictEqual(iso.toHex(Uint8Array.from([0x00, 0xa4])), "00 a4");

  log.info("OK — short and extended command APDUs round-trip, and Le " +
      "is a byte count.");
  log.debug("Leaving commandsRoundTrip().");
}

function commandRefusals() {
  log.debug("Entering commandRefusals().");
  var bad = [
    ["00 a4 04", "Command is shorter than a header."],
    ["", "Command is shorter than a header."],
    ["00 a4 04 00 02 ff", "Command length does not match Lc."],
    ["00 a4 04 00 00 01",
      "Extended command is shorter than its length field."],
    ["00 a4 04 00 00 00 00 aa", "Extended Lc is zero."],
    ["00 a4 04 00 00 00 01 ff ee",
      "Command length does not match extended Lc."],
    ["zz", "Not hexadecimal."],
    ["abc", "Hex length is odd."],
    ["0x00 a4 04 00", "Not hexadecimal."]
  ];
  var i = 0;
  for (i = 0; i < bad.length; i++) {
    (function (input, text) {
      throws(function () {
        iso.parseCommand(input);
      }, text);
    })(bad[i][0], bad[i][1]);
  }
  throws(function () {
    iso.parseCommand(null);
  }, "Expected a hex string or bytes.");
  throws(function () {
    iso.encodeCommand(cmd({ cla: 256 }));
  }, "CLA is not a byte.");
  throws(function () {
    iso.encodeCommand(cmd({ le: 0 }));
  }, "Le is not a byte count.");
  throws(function () {
    iso.encodeCommand(cmd({ le: 1.5 }));
  }, "Le is not a byte count.");
  throws(function () {
    iso.encodeCommand(cmd({ data: Buffer.alloc(65536) }));
  }, "Command data does not fit in an extended APDU.");
  throws(function () {
    iso.asBytes(Buffer.alloc(iso.MAX_INPUT_BYTES + 1));
  }, "Input is longer than " + iso.MAX_INPUT_BYTES + " bytes.");
  log.info("OK — a command whose length does not match Lc is refused, " +
      "and so is an input past the cap.");
  log.debug("Leaving commandRefusals().");
}

// ===========================================================================
// 2. Status words this family returns. Anything else is four hex digits.
// ===========================================================================
function expectStatus(hexText, sw, name, extra) {
  log.debug("Entering expectStatus().");
  var out = iso.parseResponse(hexText);
  assert.strictEqual(out.sw, sw, hexText);
  assert.strictEqual(out.sw1, (sw >> 8) & 0xff, hexText);
  assert.strictEqual(out.sw2, sw & 0xff, hexText);
  assert.strictEqual(out.name, name, hexText);
  assert.strictEqual(iso.statusName(sw), name, hexText);
  var remaining = extra ? extra.remaining : undefined;
  var tries = extra ? extra.tries : undefined;
  assert.strictEqual(out.remaining, remaining, hexText + " remaining");
  assert.strictEqual(out.triesRemaining, tries, hexText + " tries");
  log.debug("Leaving expectStatus().");
}

function responsesNameTheStatusWord() {
  log.debug("Entering responsesNameTheStatusWord().");
  expectStatus("90 00", 0x9000, "success", null);
  expectStatus("61 ff", 0x61ff, "more data available",
      { remaining: 255 });
  expectStatus("61 00", 0x6100, "more data available",
      { remaining: 0 });
  expectStatus("69 82", 0x6982, "security status not satisfied", null);
  expectStatus("69 85", 0x6985,
      "conditions of use not satisfied", null);
  expectStatus("6a 80", 0x6a80,
      "incorrect parameters in the data field", null);
  expectStatus("6a 82", 0x6a82, "file or application not found", null);
  expectStatus("6a 86", 0x6a86, "incorrect parameters P1-P2", null);
  expectStatus("6a 88", 0x6a88, "referenced data not found", null);
  expectStatus("63 00", 0x6300, "verification failed", null);
  expectStatus("63 c3", 0x63c3,
      "verification failed, 3 tries remaining", { tries: 3 });
  expectStatus("63 c0", 0x63c0,
      "verification failed, 0 tries remaining", { tries: 0 });
  expectStatus("6f 00", 0x6f00, "6F00", null);
  // Named in ISO 7816-4, and deliberately not named here: a guess
  // would read as a decoding. 6983 is the next word a PIV VERIFY
  // returns once the tries counter hits zero.
  expectStatus("69 83", 0x6983, "6983", null);
  expectStatus("64 00", 0x6400, "6400", null);

  var withData = iso.parseResponse("01 02 90 00");
  assertBytes(withData.data, fromHex("01 02"), "response data");
  assert.strictEqual(withData.name, "success");
  var embedded = iso.parseResponse("90 00 90 00");
  assertBytes(embedded.data, fromHex("90 00"),
      "status is the last two bytes");
  throws(function () {
    iso.parseResponse("90");
  }, "Response is shorter than a status word.");
  throws(function () {
    iso.parseResponse(Uint8Array.from([0x61]));
  }, "Response is shorter than a status word.");

  log.info("OK — the status words this family returns are named, and " +
      "any other word is its four hex digits.");
  log.debug("Leaving responsesNameTheStatusWord().");
}

// ===========================================================================
// 3. BER-TLV. Indefinite length is refused. A length past the buffer
//    names the tag and does not return a short value.
// ===========================================================================
function tlvRoundTripAndRefusals() {
  log.debug("Entering tlvRoundTripAndRefusals().");
  assert.deepStrictEqual(iso.parseTlv(""), []);
  assert.deepStrictEqual(iso.parseTlv(Buffer.alloc(0)), []);

  var primitive = iso.parseTlv("80 02 01 02");
  assert.strictEqual(primitive.length, 1);
  assert.strictEqual(primitive[0].tag, 0x80);
  assert.strictEqual(primitive[0].tagHex, "80");
  assert.strictEqual(primitive[0].constructed, false);
  assert.strictEqual(primitive[0].children, undefined);
  assertBytes(primitive[0].value, fromHex("01 02"), "primitive value");
  roundTripTlv("primitive", "80 02 01 02");
  roundTripTlv("empty primitive", "80 00");
  roundTripTlv("siblings", "80 01 01 81 01 02");

  var nestedNodes = iso.parseTlv("a0 05 a1 03 80 01 aa");
  assert.strictEqual(nestedNodes[0].tag, 0xa0);
  assert.strictEqual(nestedNodes[0].constructed, true);
  assert.strictEqual(nestedNodes[0].children[0].tag, 0xa1);
  assert.strictEqual(nestedNodes[0].children[0].children[0].tag, 0x80);
  assertBytes(nestedNodes[0].children[0].children[0].value,
      Buffer.from([0xaa]), "nested value");
  roundTripTlv("nested", "a0 05 a1 03 80 01 aa");
  roundTripTlv("empty constructed", "a0 00");

  var language = iso.parseTlv("5f 2d 02 65 6e");
  assert.strictEqual(language[0].tag, 0x5f2d);
  assert.strictEqual(language[0].tagHex, "5f2d");
  assert.strictEqual(language[0].constructed, false);
  assertBytes(language[0].value, Buffer.from("en"), "language");
  roundTripTlv("multi-byte tag", "5f 2d 02 65 6e");
  roundTripTlv("four-byte tag", "1f 80 80 00 00");

  var at127 = iso.encodeTlv(0x04, Buffer.alloc(127, 0x11));
  assert.strictEqual(at127[1], 127);
  roundTripTlv("short length", at127);
  var at128 = iso.encodeTlv(0x04, Buffer.alloc(128, 0x11));
  assert.strictEqual(at128[1], 0x81);
  assert.strictEqual(at128[2], 128);
  roundTripTlv("one length byte", at128);
  var at256 = iso.encodeTlv(0x04, Buffer.alloc(256, 0x22));
  assert.strictEqual(at256[1], 0x82);
  assert.strictEqual(at256[2], 0x01);
  assert.strictEqual(at256[3], 0x00);
  roundTripTlv("two length bytes", at256);
  var at64k = iso.encodeTlv(0x04, Buffer.alloc(65536, 0x33));
  assert.strictEqual(at64k[1], 0x83);
  assert.strictEqual(at64k[2], 0x01);
  assert.strictEqual(at64k[3], 0x00);
  assert.strictEqual(at64k[4], 0x00);
  roundTripTlv("three length bytes", at64k);

  // A long form of a one-byte value is legal BER and is what a card
  // writes when it always emits the long form. Reading it has to
  // yield the value. Writing it back uses the short form.
  var loose = iso.parseTlv("04 81 01 ff");
  assertBytes(loose[0].value, Buffer.from([0xff]), "non-minimal");
  assertBytes(iso.encodeTlv(0x04, loose[0].value), fromHex("04 01 ff"),
      "written back short");

  var bad = [
    ["80 80", "Tag 80 uses an indefinite length."],
    ["04 05 01 02", "Tag 04 length runs past the buffer."],
    ["04 83 ff ff ff 00", "Tag 04 length runs past the buffer."],
    ["1f", "TLV tag is truncated."],
    ["5f", "TLV tag is truncated."],
    ["5f 2d", "Tag 5f2d length is missing."],
    ["04 82 01", "Tag 04 length is truncated."],
    ["04 84 00 00 00 01", "Tag 04 has a length that does not fit."],
    ["1f 80 80 80 00", "TLV tag is truncated."],
    ["a0 03 80 80 ff", "Tag 80 uses an indefinite length."]
  ];
  var i = 0;
  for (i = 0; i < bad.length; i++) {
    (function (input, text) {
      throws(function () {
        iso.parseTlv(input);
      }, text);
    })(bad[i][0], bad[i][1]);
  }
  throws(function () {
    iso.encodeTlv(0x1f, Buffer.from([0x01]));
  }, "A long-form tag needs its continuation bytes.");
  throws(function () {
    iso.encodeTlv(0x5f2d, Buffer.from("en"));
  }, "TLV tag is not one byte or a tag buffer.");

  var held = iso.parseTlv(nested(7));
  var depth = 0;
  var current = held;
  for (depth = 0; depth < 7; depth++) {
    assert.strictEqual(current.length, 1, "depth " + depth);
    assert.strictEqual(current[0].constructed, true, "depth " + depth);
    assert.strictEqual(current[0].tag, 0xa0, "depth " + depth);
    current = current[0].children;
  }
  assert.strictEqual(current[0].tag, 0x80);
  assertBytes(current[0].value, Buffer.from([0xaa]), "innermost");
  throws(function () {
    iso.parseTlv(nested(8));
  }, "TLV nesting is deeper than 8.");

  log.info("OK — BER-TLV round-trips, an overrun names its tag, and " +
      "indefinite length is refused.");
  log.debug("Leaving tlvRoundTripAndRefusals().");
}

// ===========================================================================
// 4. The division that lets this job exist. walk() is the hot path.
// ===========================================================================
function theModuleStaysACodec() {
  log.debug("Entering theModuleStaysACodec().");
  assert.strictEqual(iso.MAX_INPUT_BYTES, 262144);
  assert.strictEqual(iso.MAX_DEPTH, 8);
  var source = fs.readFileSync(path.join(SRC, "iso7816.js"), "utf8");
  var code = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  var forbidden = ["document", "window", "localStorage",
      "sessionStorage", "crypto.subtle", "pcsclite"];
  var i = 0;
  for (i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/iso7816.js reaches " + forbidden[i] + ".");
  }
  var requires = code.match(/require\(([^)]*)\)/g);
  assert.deepStrictEqual(requires, [
    "require(\"bunyan\")",
    "require(process.env.CONFIG_FILE)"
  ]);
  var walkStart = source.indexOf("function walk(");
  var walkEnd = source.indexOf("function parseTlv(");
  assert.ok(walkStart > 0 && walkEnd > walkStart, "walk() is missing.");
  assert.ok(source.slice(walkStart, walkEnd).indexOf("log.") < 0,
      "walk() logs, and it is the hot path. parseTlv() is the entry.");
  log.info("OK — the codec reaches no DOM and no reader, and walk() " +
      "does not log.");
  log.debug("Leaving theModuleStaysACodec().");
}

function responseOf(body, sw1, sw2) {
  log.debug("Entering responseOf().");
  var out = Buffer.concat([
    iso.asBytes(body),
    Buffer.from([sw1 === undefined ? 0x90 : sw1,
        sw2 === undefined ? 0x00 : sw2])
  ]);
  log.debug("Leaving responseOf().");
  return out;
}

function rowText(rows) {
  log.debug("Entering rowText().");
  var text = (rows || []).map(function (row) {
    return row.label + "=" + row.value;
  }).join("\n");
  log.debug("Leaving rowText().");
  return text;
}

async function pivCertificates() {
  log.debug("Entering pivCertificates().");
  var tag = Buffer.from("5fc105", "hex");
  var getData = iso.encodeCommand({
    cla: 0x00, ins: 0xcb, p1: 0x3f, p2: 0xff,
    data: Buffer.concat([Buffer.from([0x5c, tag.length]), tag]),
    le: 256
  });
  var named = piv.describeCommand(getData);
  assert.ok(named.summary.indexOf("PIV authentication") >= 0,
      named.summary);
  var verify = iso.encodeCommand({
    cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x80,
    data: Buffer.from("123456", "utf8"), le: null
  });
  var pin = piv.describeCommand(verify);
  assert.ok(rowText(pin.rows).indexOf("not shown") >= 0);
  assert.ok(rowText(pin.rows).indexOf("123456") < 0,
      "the PIN was copied into the description");
  // SP 800-73-4 Part 2 3.2.1: FF-padded to 8 bytes. The YubiKey
  // default PIN 123456 is 313233343536FFFF on the wire.
  assert.strictEqual(piv.verifyApdu("123456").toString("hex"),
      "0020008008313233343536ffff");
  assert.ok(pin.summary.indexOf("PIV card application PIN") >= 0,
      pin.summary);
  throws(function () {
    piv.verifyApdu("12345");
  }, "A PIV PIN is 6 to 8 characters.");
  // yubikit: ORIGIN_GENERATED = 1, ORIGIN_IMPORTED = 2; retries is
  // total then remaining.
  var meta = rowText(piv.describeResponse(
      fromHex("010111 02020102 030101 06020302 9000")).rows);
  assert.ok(meta.indexOf("Origin=generated") >= 0, meta);
  assert.ok(meta.indexOf("Retries=2 of 3 remaining") >= 0, meta);
  var failed = piv.describeResponse(Buffer.from([0x69, 0x82]));
  assert.ok(failed.summary.indexOf("6982") >= 0, failed.summary);
  assert.strictEqual(failed.certificate, null);

  var pair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  var pem = await x509.selfSignedCertPem({
    subject: "CN=piv-test",
    publicPem: pair.publicKey,
    privatePem: pair.privateKey
  });
  var der = Buffer.from(bytes.pemToDer(pem));
  var inner = Buffer.concat([
    iso.encodeTlv(0x70, der),
    iso.encodeTlv(0x71, Buffer.from([0x00]))
  ]);
  var wrapped = piv.describeResponse(responseOf(
      iso.encodeTlv(0x53, inner)));
  assert.strictEqual(wrapped.certificate.compressed, false);
  var described = await x509.describeCertificate(
      bytes.derToPem(wrapped.certificate.der, "CERTIFICATE"));
  assert.ok(described.subject.indexOf("piv-test") >= 0,
      described.subject);

  var gzipped = zlib.gzipSync(der);
  var gzInner = Buffer.concat([
    iso.encodeTlv(0x70, gzipped),
    iso.encodeTlv(0x71, Buffer.from([0x01]))
  ]);
  var held = piv.unwrapCertificate(iso.encodeTlv(0x53, gzInner),
      function (compressed) {
        return zlib.gunzipSync(compressed);
      });
  assert.ok(held.der.equals(der), "gzip certificate did not round-trip");
  var again = await x509.describeCertificate(
      bytes.derToPem(held.der, "CERTIFICATE"));
  assert.ok(again.subject.indexOf("piv-test") >= 0, again.subject);
  log.info("OK — PIV names the authentication certificate, hides a " +
      "PIN, and a gzip container inflates to the same certificate.");
  log.debug("Leaving pivCertificates().");
}

// A REAL attestation chain, not one this code built: go-piv/piv-go
// (Apache-2.0), v2/piv/key_test.go, TestVerify "ValidChain". The
// device certificate is what a YubiKey keeps in object 5FFF01; the
// key certificate is what ATTEST returned for slot 9A. openssl
// asn1parse of the latter shows 3.3 = 050403, 3.7 = 020400F00F14,
// 3.8 = 0201 and 3.9 = 04.
var PIVGO_DEVICE_CERT_B64 =
  "MIIC+jCCAeKgAwIBAgIJAKs/UIpBjg1uMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV" +
  "BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw" +
  "MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0" +
  "dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zdJWGnk" +
  "aLE8Rb+TP7iSffhJV9SJEp2Me4QcfVidgHqyIdo0lruBk69RF1nrmS3i+G1yyUh/" +
  "ymAPZkcQCpms0E23Dmhue1VRpBedcsVtO/xSrfu0qAWTslp/k57ry6vkidrQU1cx" +
  "l2KodH3KTmnZmaskQD8eGtxXwcmLOmhKem6GSqhN/3QznaDhZmVUAvUKSOaIzOxn" +
  "2u1mDHhGwaHhR7dklsDwN7oni4WWX1GJXtzpB8j6JhoqyqXwSbq+ck54PfzUoOFd" +
  "/2yKyFRDXnQvzbNL7+afbxBQQMxxo1e24DNE/cp+K09eT7Gh1Urao6meaSssN4aV" +
  "FfmkhC2NapGKMQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBAMwEgYDVR0TAQH/" +
  "BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAJfOLOQYGyIMQ5y+sDkYz+e6G" +
  "H8BqqiYL9VOC3U3KQX9mrtZnaIexqJOCQyCFOSvaTFJvOfNiCCKQuLbmS+Qn4znd" +
  "nSitCsdJSFKskQP7hbXqUK01epb6iTuuko4w3V57YVudnniZBD2s4XoNcJ6BFizZ" +
  "3iXQqRMaLVfFHS9Qx0iLZLcR2s29nIl6NI/qFdIgkyo07J5cPnBiD6wxQft8FdfR" +
  "bgx9yrrjY0mvj/k5LRN6lab8lTolgI5luJtKNueq96LVkTkAzcCaJPQ9YQ4cxeU9" +
  "OapsEeOk6xf5bRPtdf0WhEKthXywt9D0pSHhAI+fpLNe/VtlZpt3hn9aTbqSug==";
var PIVGO_KEY_CERT_B64 =
  "MIICVTCCAT2gAwIBAgIQAU4Yg7Qnw9FZgMBEaJ7ZMzANBgkqhkiG9w0BAQsFADAh" +
  "MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw" +
  "MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl" +
  "c3RhdGlvbiA5YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABATzM3sJuwemL2Ha" +
  "HkGIzmCVjUMreNIVrRLOvnbZjoVflk1eab/iLUlKzk/2jXTu9TISRg2dhyXcutct" +
  "vnqr66yjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYCBADw" +
  "DxQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0B" +
  "AQsFAAOCAQEAFX0hL5gi/g4ZM7vCH5kDAtma7eBp0LpbCzR313GGyBR7pJFtuj2l" +
  "bWU+V3SFRihXBTDb8q+uvyCBqgz1szdZzrpfjqNkhEPfPNabxjxJxVoe6Gdcn115" +
  "aduxfqqT2u+YIsERzaIIIisehLQkc/5zLkpocA6jbKBZnZWUBJIxuz4QmYTIf0O4" +
  "HPE2o4JbAyGx/hRaqVvDgNeAz94ZFjb4Mp3RNbbdRUZB0ehrT/IGRJoHRu2HKFGM" +
  "ylRJL2kjKPoEc4XHbCu+MfmAIrQ4Xseg85zyI7ThhYvAzktdLHhQyfYr4wrrLCN3" +
  "oeTzmiqIHe9AataJXQ+mEQEEc9TNY23RFg==";

async function pivAttestation() {
  log.debug("Entering pivAttestation().");
  var device = Buffer.from(PIVGO_DEVICE_CERT_B64, "base64");
  var key = Buffer.from(PIVGO_KEY_CERT_B64, "base64");
  // GET DATA 5FFF01 answers 53 { 70 cert, 71 00, FE 00 }.
  var container = Buffer.concat([
    fromHex("53 82"), Buffer.from([((device.length + 9) >> 8) & 0xff,
        (device.length + 9) & 0xff]),
    fromHex("70 82"), Buffer.from([(device.length >> 8) & 0xff,
        device.length & 0xff]),
    device, fromHex("71 01 00 fe 00 90 00")
  ]);
  assert.strictEqual(piv.objectName("5fff01"),
      "attestation certificate (Yubico, slot F9)");
  var dev = rowText(piv.describeResponse(container).rows);
  assert.ok(dev.indexOf("Firmware (Yubico 3.3)=5.4.3") >= 0, dev);
  assert.ok(dev.indexOf("serial") < 0, dev);
  var attested = rowText(piv.describeResponse(
      Buffer.concat([key, fromHex("9000")])).rows);
  assert.ok(attested.indexOf("Firmware (Yubico 3.3)=5.4.3") >= 0,
      attested);
  assert.ok(attested.indexOf("YubiKey serial (Yubico 3.7)=15732500") >= 0,
      attested);
  assert.ok(attested.indexOf("PIN policy (Yubico 3.8)=once per session") >=
      0, attested);
  assert.ok(attested.indexOf("Touch policy (Yubico 3.8)=never") >= 0,
      attested);
  assert.ok(attested.indexOf("Form factor (Yubico 3.9)=USB-C nano") >= 0,
      attested);
  var described = await x509.describeCertificate(
      bytes.derToPem(key, "CERTIFICATE"));
  assert.ok(String(described.subject).indexOf("YubiKey PIV Attestation 9a")
      >= 0, described.subject);
  log.info("OK — a real YubiKey attestation pair (piv-go's test vector) " +
      "decodes from 5FFF01 and from ATTEST, Yubico extensions included.");
  log.debug("Leaving pivAttestation().");
}

function otpVectors() {
  log.debug("Entering otpVectors().");
  var key = "000102030405060708090a0b0c0d0e0f";
  var first = otp.decryptToken(
      "dvgtiblfkbgturecfllberrvkinnctnn", key);
  assert.strictEqual(first.privateId, "010203040506");
  assert.strictEqual(first.useCounter, 1);
  assert.strictEqual(first.timestampLow, 1);
  assert.strictEqual(first.timestampHigh, 1);
  assert.strictEqual(first.sessionUse, 1);
  assert.strictEqual(first.random, "0000");
  assert.strictEqual(first.crc, "36fe");
  var second = otp.decryptToken(
      "rnibcnfhdninbrdebccrndfhjgnhftee", key);
  assert.strictEqual(second.sessionUse, 2);
  assert.strictEqual(second.crc, "5211");
  var third = otp.decryptToken(
      "iikkijbdknrrdhfdrjltvgrbkkjblcbh", key);
  assert.strictEqual(third.useCounter, 0x0fff);
  assert.strictEqual(third.crc, "5494");
  otp.decryptToken("dcihgvrhjeucvrinhdfddbjhfjftjdei",
      "88888888888888888888888888888888");
  var zeros = otp.decryptToken(
      "kkkncjnvcnenkjvjgncjihljiibgbhbh",
      "00000000000000000000000000000000");
  assert.strictEqual(zeros.crc, "6aa9");
  var other = otp.decryptToken("iucvrkjiegbhidrcicvlgrcgkgurhjnj",
      "c4422890653076cde73d449b191b416a");
  assert.strictEqual(other.privateId, "33c69e7f249e");
  assert.strictEqual(other.useCounter, 1);
  assert.strictEqual(other.timestampLow, 0x13a7);
  assert.strictEqual(other.timestampHigh, 0x24);
  assert.strictEqual(other.sessionUse, 0);
  assert.strictEqual(other.random, "c63c");
  assert.strictEqual(other.crc, "861c");
  throws(function () {
    otp.decryptToken("dvgtiblfkbgturecfllberrvkinnctnn",
        "ffffffffffffffffffffffffffffffff");
  }, "The CRC does not match");
  throws(function () {
    otp.parseToken("z".repeat(44));
  }, "Not modhex.");
  throws(function () {
    otp.parseToken("cccc");
  }, "A Yubico OTP is 32 to 48");

  var secret = "mG5be6ZJU1qBGz24yPh/ESM3UdU=";
  var built = otp.buildValidationRequest({
    id: "1",
    otp: "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft",
    nonce: "jrFwbaYFhn0HoxZIsd9LQ6w2ceU",
    apiKey: secret
  });
  assert.strictEqual(built.signature, "+ja8S3IjbX593/LAgTBixwPNGX4=");
  var answered = [
    "nonce=0123456789abcdef",
    "otp=cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj",
    "sl=25",
    "status=OK",
    "t=2019-06-06T05:14:15Z0369",
    "h=iCV9uFJDtuyELQsxFPnR80Yj2XU="
  ].join("\n");
  var parsed = otp.parseValidationResponse(answered, {
    nonce: "0123456789abcdef",
    apiKey: secret
  });
  assert.strictEqual(parsed.status, "OK");
  assert.strictEqual(parsed.hmacMatches, true);
  throws(function () {
    otp.parseValidationResponse(answered, {
      nonce: "0123456789abcdefXXX",
      apiKey: secret
    });
  }, "response nonce does not match");
  // Validation Protocol 2.0 requires the echoed otp to be checked too.
  var echoed = otp.parseValidationResponse(answered, {
    nonce: "0123456789abcdef",
    otp: "cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj",
    apiKey: secret
  });
  assert.strictEqual(echoed.otpMatches, true);
  throws(function () {
    otp.parseValidationResponse(answered, {
      nonce: "0123456789abcdef",
      otp: "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft",
      apiKey: secret
    });
  }, "response otp does not match");
  var refused = otp.parseValidationResponse(
      "nonce=0123456789abcdef\nstatus=BAD_SIGNATURE", {
        nonce: "0123456789abcdef",
        otp: "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft"
      });
  assert.strictEqual(refused.otpMatches, null);
  throws(function () {
    otp.parseValidationResponse("nonce=0123456789abcdef\nstatus=OK", {
      nonce: "0123456789abcdef",
      otp: "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft"
    });
  }, "response otp does not match");

  var posted = otpVerify.describeRequest({ body: built.body });
  assert.strictEqual(posted.ok, true, posted.error);
  assert.strictEqual(posted.url,
      "https://api.yubico.com/wsapi/2.0/verify");
  var secondServer = otpVerify.describeRequest({
    body: built.body, server: 2
  });
  assert.ok(secondServer.url.indexOf("api2.yubico.com") >= 0);
  assert.strictEqual(otpVerify.describeRequest({
    body: built.body,
    verifier: "http://example.com/verify"
  }).ok, false);
  assert.strictEqual(otpVerify.describeRequest({
    body: built.body,
    verifier: "https://user:pass@example.com/verify"
  }).ok, false);
  assert.strictEqual(otpVerify.describeRequest({
    body: built.body,
    verifier: "https://example.com/a/../b"
  }).ok, false);
  assert.strictEqual(otpVerify.describeRequest({
    body: built.body,
    verifier: "https://example.com/verify?x=1"
  }).ok, false);
  assert.strictEqual(otpVerify.describeRequest({ body: "id=1" }).ok,
      false);

  var frame = otp.hidFrame(0x20, Buffer.from("010203040506", "hex"));
  assert.strictEqual(frame.length, 70);
  assert.strictEqual(frame[64], 0x20);
  var reports = otp.hidReports(frame);
  assert.strictEqual(reports[0][7], 0x80);
  assert.strictEqual(reports[reports.length - 1][7], 0x80 | 9);
  // HMAC variable mode pads the way yubikit's calculate_hmac_sha1
  // does: ljust(64, b"\1" if challenge.endswith(b"\0") else b"\0").
  var endsZero = otp.hidFrame(0x30, fromHex("aa 00"));
  assert.strictEqual(endsZero.slice(0, 64).toString("hex"),
      "aa00" + "01".repeat(62));
  var endsOne = otp.hidFrame(0x38, fromHex("aa 01"));
  assert.strictEqual(endsOne.slice(0, 64).toString("hex"),
      "aa01" + "00".repeat(62));
  assert.strictEqual(otp.hmacChallengeBytes(endsZero).toString("hex"),
      "aa00");
  assert.strictEqual(otp.hmacChallengeBytes(endsOne).toString("hex"),
      "aa01");
  // Fixed mode: the 64 bytes are the challenge, zero filled.
  var fixed = otp.hidFrame(0x30, fromHex("aa 00"), { variable: false });
  assert.strictEqual(fixed.slice(0, 64).toString("hex"),
      "aa" + "00".repeat(63));
  assert.strictEqual(otp.hmacChallengeBytes(fixed, false).length, 64);
  // The CRC is over the padded payload, so it differs between modes.
  assert.notStrictEqual(endsZero.slice(65, 67).toString("hex"),
      fixed.slice(65, 67).toString("hex"));
  // OTP slots are not padded with 01.
  assert.strictEqual(otp.hidFrame(0x20, fromHex("0102030405 00"))
      .slice(6, 64).toString("hex"), "00".repeat(58));
  hidReadProtocol();
  log.info("OK — published OTP vectors decrypt, both HMACs match, " +
      "and the verifier refuses a bad URL.");
  log.debug("Leaving otpVectors().");
}

// A key's answer to a challenge, as the 8-byte feature reports it
// returns: response bytes plus the complemented CRC, 7 to a report,
// each with RESP_PENDING and its sequence number, then a report with
// sequence 0 that ends the frame.
function hidAnswer(response) {
  log.debug("Entering hidAnswer().");
  var inv = (~otp.crc16(response)) & 0xffff;
  var frame = Buffer.concat([response,
      Buffer.from([inv & 0xff, (inv >> 8) & 0xff])]);
  var reports = [];
  var seq = 0;
  var off = 0;
  for (off = 0; off < frame.length; off += 7) {
    var report = Buffer.alloc(8, 0);
    frame.slice(off, off + 7).copy(report, 0);
    report[7] = 0x40 | seq;
    reports.push(report);
    seq += 1;
  }
  var end = Buffer.alloc(8, 0);
  end[7] = 0x40;
  reports.push(end);
  log.debug("Leaving hidAnswer().");
  return reports;
}

function hidReadProtocol() {
  log.debug("Entering hidReadProtocol().");
  var busy = Buffer.alloc(8, 0);
  busy[7] = 0x80;
  assert.strictEqual(otp.hidCanWrite(busy), false);
  assert.strictEqual(otp.hidCanWrite(Buffer.alloc(8, 0)), true);
  var nine = new Uint8Array(9);
  nine[8] = 0x20;
  assert.strictEqual(otp.hidReportBytes(new DataView(nine.buffer))[7],
      0x20);

  var hmac = Buffer.from("0123456789abcdef0123456789abcdef01234567",
      "hex");
  var state = { seq: 0, data: [] };
  var touch = Buffer.alloc(8, 0);
  touch[7] = 0x20;
  var wait = Buffer.alloc(8, 0);
  wait[7] = 0x01;
  assert.strictEqual(otp.hidReadStep(state, touch).kind, "touch");
  assert.strictEqual(otp.hidReadStep(state, wait).kind, "wait");
  var answer = hidAnswer(hmac);
  var kinds = answer.map(function (report) {
    return otp.hidReadStep(state, report).kind;
  });
  assert.deepStrictEqual(kinds, ["data", "data", "data", "data", "done"]);
  var got = otp.hidResponse(0x30, Buffer.from(state.data));
  assert.strictEqual(got.toString("hex"), hmac.toString("hex"));

  var otpResponse = Buffer.from("00112233445566778899aabbccddeeff",
      "hex");
  var otpState = { seq: 0, data: [] };
  hidAnswer(otpResponse).forEach(function (report) {
    otp.hidReadStep(otpState, report);
  });
  assert.strictEqual(otp.hidResponse(0x20,
      Buffer.from(otpState.data)).toString("hex"),
      otpResponse.toString("hex"));

  var bad = Buffer.from(state.data);
  bad[0] ^= 1;
  throws(function () {
    otp.hidResponse(0x30, bad);
  }, "CRC does not check");
  assert.strictEqual(otp.hidReadStep({ seq: 0, data: [] },
      Buffer.alloc(8, 0)).kind, "status");
  throws(function () {
    otp.hidReadStep({ seq: 1, data: [1] }, Buffer.alloc(8, 0));
  }, "stopped part way");
  var reset = otp.hidResetReport();
  assert.strictEqual(reset[0], 0xff);
  assert.strictEqual(reset[7], 0x8f);
  log.info("OK — the HID read follows the sequence numbers, waits on " +
      "busy and touch, and checks the response CRC.");
  log.debug("Leaving hidReadProtocol().");
}

function oathVectors() {
  log.debug("Entering oathVectors().");
  var sha1 = Buffer.from("12345678901234567890", "utf8");
  var hotpCodes = ["755224", "287082", "359152", "969429", "338314",
      "254676", "287922", "162583", "399871", "520489"];
  var i = 0;
  for (i = 0; i < hotpCodes.length; i++) {
    assert.strictEqual(oath.hotp(sha1, i), hotpCodes[i],
        "HOTP counter " + i);
  }
  var totpSha1 = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"]
  ];
  for (i = 0; i < totpSha1.length; i++) {
    assert.strictEqual(oath.totp(sha1, totpSha1[i][0]), totpSha1[i][1],
        "TOTP SHA-1 " + totpSha1[i][0]);
  }
  var sha256 = Buffer.from(
      "12345678901234567890123456789012", "utf8");
  var totpSha256 = [
    [59, "46119246"],
    [1111111109, "68084774"],
    [1111111111, "67062674"],
    [1234567890, "91819424"],
    [2000000000, "90698825"],
    [20000000000, "77737706"]
  ];
  for (i = 0; i < totpSha256.length; i++) {
    assert.strictEqual(oath.totp(sha256, totpSha256[i][0], {
      algorithm: "SHA-256"
    }), totpSha256[i][1], "TOTP SHA-256 " + totpSha256[i][0]);
  }
  var sha512 = Buffer.from(
      "12345678901234567890".repeat(3) + "1234", "utf8");
  assert.strictEqual(sha512.length, 64);
  var totpSha512 = [
    [59, "90693936"],
    [1111111109, "25091201"],
    [1111111111, "99943326"],
    [1234567890, "93441116"],
    [2000000000, "38618901"],
    [20000000000, "47863826"]
  ];
  for (i = 0; i < totpSha512.length; i++) {
    assert.strictEqual(oath.totp(sha512, totpSha512[i][0], {
      algorithm: "SHA-512"
    }), totpSha512[i][1], "TOTP SHA-512 " + totpSha512[i][0]);
  }
  throws(function () {
    oath.hotp(sha1, 0, 5);
  }, "The digit count is 6, 7 or 8.");

  var secret = Buffer.from("12345678901234567890", "utf8");
  var put = oath.putApdu({
    name: "demo", secret: secret, type: "TOTP", digits: 6
  });
  var putText = rowText(oath.describeCommand(put).rows);
  assert.ok(putText.indexOf("not shown") >= 0);
  assert.ok(putText.indexOf("12345678901234567890") < 0);
  // The property is tag 78 and one byte with NO length (yubikit's
  // struct.pack(">BB", TAG_PROPERTY, prop)); a short key is padded
  // to 14 bytes, as yubikit does.
  var touchPut = oath.putApdu({
    name: "t", secret: Buffer.from("0102030405", "hex"), type: "HOTP",
    digits: 6, touch: true, counter: 5
  });
  assert.strictEqual(touchPut.toString("hex"),
      "00010000" + "1d" + "710174" + "7310" + "1106" +
      "0102030405" + "00".repeat(9) + "7802" + "7a0400000005");
  var touchText = rowText(oath.describeCommand(touchPut).rows);
  assert.ok(touchText.indexOf("touch required") >= 0, touchText);
  assert.ok(touchText.indexOf("Initial counter") >= 0, touchText);
  assert.strictEqual(oath.resetApdu().toString("hex"), "0004dead");
  var listed = iso.encodeTlv(0x72, Buffer.concat([
    Buffer.from([0x21]), Buffer.from("demo", "utf8")
  ]));
  var creds = oath.parseList(listed);
  assert.strictEqual(creds[0].name, "demo");
  assert.strictEqual(creds[0].type, "TOTP");
  assert.strictEqual(creds[0].algorithm, "SHA-1");
  var code = Buffer.alloc(4);
  code.writeUInt32BE(755224, 0);
  var calc = oath.parseCalculate(iso.encodeTlv(0x76,
      Buffer.concat([Buffer.from([6]), code])));
  assert.strictEqual(calc.code, "755224");

  // A FULL CALCULATE response (75) is the whole HMAC, and the code is
  // its dynamic truncation. RFC 4226 Appendix D, count 0 and 1.
  var full0 = oath.parseCalculate(fromHex("75 15 06 " +
      "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"));
  assert.strictEqual(full0.truncated, false);
  assert.strictEqual(full0.code, "755224");
  assert.strictEqual(oath.parseCalculate(fromHex("75 15 06 " +
      "75a48a19d4cbe100644e8ac1397eea747a2d33ab")).code, "287082");
  // RFC 4226 Appendix D's truncated value for count 1.
  assert.strictEqual(oath.parseCalculate(fromHex("76 05 06 41397eea"))
      .code, "287082");
  // RFC 6238 Appendix B, T = 59, SHA-256, 8 digits: 46119246. The
  // 32-byte HMAC is node's, from the RFC's seed and T = 1.
  var sha256Seed = Buffer.from("12345678901234567890123456789012");
  var mac256 = crypto.createHmac("sha256", sha256Seed)
      .update(fromHex("0000000000000001")).digest();
  assert.strictEqual(oath.parseCalculate(Buffer.concat([
    fromHex("75 21 08"), mac256
  ])).code, "46119246");
  // CALCULATE ALL, written by hand from the YKOATH grammar: name 71
  // then 76 (truncated), 77 (HOTP) or 7C (touch), digits first.
  var all = oath.parseCalculateAll(fromHex(
      "71 05 746f747031 76 05 06 4c93cf18" +
      "71 05 686f747031 77 01 06" +
      "71 05 746f756368 7c 01 08"));
  assert.deepStrictEqual(all.map(function (c) {
    return [c.name, c.kind, c.digits, c.code];
  }), [
    ["totp1", "truncated", 6, "755224"],
    ["hotp1", "HOTP, not calculated", 6, null],
    ["touch", "touch required, not calculated", 8, null]
  ]);
  var allText = rowText(oath.describeResponse(fromHex(
      "71 05 746f747031 76 05 06 4c93cf18 90 00")).rows);
  assert.ok(allText.indexOf("totp1=755224 (truncated)") >= 0, allText);
  throws(function () {
    oath.parseCalculateAll(fromHex("71 05 746f747031 72 01 06"));
  }, "A CALCULATE ALL response is name (71) and response " +
      "(75, 76, 77 or 7C) pairs.");
  log.info("OK — RFC 4226 and RFC 6238 codes match, and a YKOATH " +
      "PUT does not show the secret.");
  log.debug("Leaving oathVectors().");
}

async function openpgpKeys() {
  log.debug("Entering openpgpKeys().");
  var rsaAttr = pgp.parseAlgorithmAttributes(
      Buffer.from([0x01, 0x08, 0x00, 0x00, 0x11]));
  assert.strictEqual(rsaAttr.modulusBits, 2048);
  assert.strictEqual(rsaAttr.exponentBits, 17);
  var oid = Buffer.from("2a8648ce3d030107", "hex");
  // OpenPGP card 3.4 4.4.3.9: the OID follows the algorithm ID with
  // no length byte. These are the bytes gpg writes for C1.
  var ecc = pgp.parseAlgorithmAttributes(
      fromHex("13 2a 86 48 ce 3d 03 01 07"));
  assert.strictEqual(ecc.curve, "P-256");
  var ed = pgp.parseAlgorithmAttributes(
      fromHex("16 2b 06 01 04 01 da 47 0f 01"));
  assert.strictEqual(ed.curve, "Ed25519");
  var withImport = pgp.parseAlgorithmAttributes(
      fromHex("12 2b 06 01 04 01 97 55 01 05 01 ff"));
  assert.strictEqual(withImport.curve, "X25519");
  assert.strictEqual(withImport.importFormat, 0xff);
  var counted = pgp.describeData(iso.encodeTlv(0x7a,
      iso.encodeTlv(0x93, Buffer.from([0, 1, 2]))));
  assert.ok(counted.rows.some(function (row) {
    return row.label === "Signature counter" && row.value === "258";
  }), "the counter inside 7A is read");

  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaJwk = rsa.publicKey.export({ format: "jwk" });
  var rsaPem = pgp.publicKeyPem({
    modulus: Buffer.from(rsaJwk.n, "base64url"),
    exponent: Buffer.from(rsaJwk.e, "base64url")
  });
  var rsaDesc = await keys.describePublicPem(rsaPem);
  assert.strictEqual(rsaDesc.kind, "rsa");
  assert.ok(rsaDesc.bits >= 2040 && rsaDesc.bits <= 2048, rsaDesc.bits);

  var ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecJwk = ec.publicKey.export({ format: "jwk" });
  var point = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(ecJwk.x, "base64url"),
    Buffer.from(ecJwk.y, "base64url")
  ]);
  var ecPem = pgp.publicKeyPem({ point: point, curve: "P-256" });
  var ecDesc = await keys.describePublicPem(ecPem);
  assert.strictEqual(ecDesc.kind, "ec");
  assert.strictEqual(ecDesc.curve, "P-256");

  var ed = crypto.generateKeyPairSync("ed25519");
  var edJwk = ed.publicKey.export({ format: "jwk" });
  var edPem = pgp.publicKeyPem({
    point: Buffer.from(edJwk.x, "base64url"),
    curve: "Ed25519"
  });
  var edDesc = await keys.describePublicPem(edPem);
  assert.strictEqual(edDesc.kind, "okp");
  assert.strictEqual(edDesc.name, "Ed25519");

  var x = crypto.generateKeyPairSync("x25519");
  var xJwk = x.publicKey.export({ format: "jwk" });
  var xPem = pgp.publicKeyPem({
    point: Buffer.from(xJwk.x, "base64url"),
    curve: "X25519"
  });
  var xDer = Buffer.from(bytes.pemToDer(xPem));
  assert.ok(xDer.toString("hex").indexOf("2b656e") >= 0,
      "X25519 SPKI is missing its OID");

  var fp = Buffer.alloc(60, 0);
  fp[0] = 0xab;
  var printed = pgp.describeData(iso.encodeTlv(0xc5, fp));
  assert.ok(rowText(printed.rows).indexOf("(not set)") >= 0);
  assert.ok(rowText(printed.rows).indexOf("ab") === 0 ||
      rowText(printed.rows).indexOf("ab") > 0);
  log.info("OK — OpenPGP SPKI imports as RSA, P-256 and Ed25519, " +
      "and X25519 carries its OID.");
  log.debug("Leaving openpgpKeys().");
}

function yubihsmTraces() {
  log.debug("Entering yubihsmTraces().");
  var password = "secret-password!";
  assert.strictEqual(Buffer.byteLength(password, "utf8"), 16);
  var derived = hsm.deriveKeys("password");
  var native = crypto.pbkdf2Sync("password", "Yubico", 10000, 32,
      "sha256");
  assert.ok(derived.enc.equals(native.slice(0, 16)));
  assert.ok(derived.mac.equals(native.slice(16)));
  var put = hsm.putApdu({
    managementKey: Buffer.alloc(16, 0x11),
    label: "door",
    algorithm: hsm.AES128,
    keyEnc: Buffer.alloc(16, 0x22),
    keyMac: Buffer.alloc(16, 0x33),
    credentialPassword: password,
    touch: true
  });
  var putText = rowText(hsm.describeCommand(put).rows);
  assert.ok(putText.indexOf("door") >= 0);
  assert.ok(putText.indexOf("not shown") >= 0);
  assert.ok(putText.indexOf(password) < 0);
  assert.ok(putText.indexOf("11 11 11") < 0);
  assert.strictEqual(hsm.resetApdu().toString("hex"), "0006dead");
  var value = Buffer.concat([
    Buffer.from([hsm.AES128, 1]),
    Buffer.from("door", "utf8"),
    Buffer.from([4])
  ]);
  var listed = hsm.parseList(iso.encodeTlv(0x72, value));
  assert.strictEqual(listed[0].label, "door");
  assert.strictEqual(listed[0].touch, true);
  assert.strictEqual(listed[0].counter, 4);
  var shown = hsm.describeResponse(responseOf(
      iso.encodeTlv(0x72, value)));
  assert.ok(shown.summary.indexOf("1 credential") >= 0, shown.summary);
  var keys48 = Buffer.concat([
    Buffer.alloc(16, 0x11),
    Buffer.alloc(16, 0x22),
    Buffer.alloc(16, 0x33)
  ]);
  var session = hsm.describeResponse(responseOf(keys48));
  assert.ok(rowText(session.rows).indexOf("YubiHSM 2") >= 0);
  assert.ok(session.sessionKeys.keySenc.equals(Buffer.alloc(16, 0x11)));
  assert.ok(session.sessionKeys.keySrmac.equals(Buffer.alloc(16, 0x33)));
  var version = hsm.describeResponse(responseOf(
      iso.encodeTlv(0x79, Buffer.from([5, 7, 1]))));
  assert.ok(rowText(version.rows).indexOf("5.7.1") >= 0);
  var calc = hsm.describeCommand(hsm.calculateApdu({
    label: "door",
    context: Buffer.alloc(16, 0x44),
    credentialPassword: password
  }));
  assert.ok(rowText(calc.rows).indexOf("not") >= 0 ||
      calc.summary.indexOf("not performed") >= 0);
  assert.ok(rowText(calc.rows).indexOf(password) < 0);
  log.info("OK — a constructed YubiHSM Auth list, PUT, CALCULATE, " +
      "version and reset decode, and the session keys are labeled " +
      "for a YubiHSM 2.");
  log.debug("Leaving yubihsmTraces().");
}

function readerRefusals() {
  log.debug("Entering readerRefusals().");
  var usual = "Yubico YubiKey OTP+FIDO+CCID 00 00";
  assert.strictEqual(reader.checkReaderName(usual).ok, true);
  ["http://keys.example", "localhost:88", "/dev/bus/usb", "a/../b",
      "", "x\ny"].forEach(function (name) {
    assert.strictEqual(reader.checkReaderName(name).ok, false, name);
  });
  var limits = reader.limits();
  assert.strictEqual(limits.enabled, false,
      "the reader relay must be off without smartcardReaderEnabled");
  assert.strictEqual(limits.available, false);
  assert.ok(limits.reason.indexOf("smartcardReaderEnabled") >= 0);
  assert.strictEqual(reader.enabled({ smartcardReaderEnabled: "true" }),
      false, "only the boolean true turns the relay on");
  var on = reader.limits({ smartcardReaderEnabled: true });
  assert.strictEqual(on.enabled, true);
  assert.strictEqual(typeof on.available, "boolean");
  if (!on.available) {
    assert.ok(on.reason && on.reason.length > 0);
  }
  assert.strictEqual(reader.describeTransmit({
    reader: usual, apdu: "00a4"
  }).ok, false);
  var good = reader.describeTransmit({
    reader: usual, apdu: "00 a4 04 00"
  });
  assert.strictEqual(good.ok, true, good.error);
  assert.strictEqual(good.apdu.length, 4);
  var huge = "00a40400" + "aa".repeat(8192);
  assert.strictEqual(reader.describeTransmit({
    reader: usual, apdu: huge
  }).ok, false);
  var sequence = reader.describeTransmit({
    reader: usual, apdus: ["00a4040008a000000308000010", "00cb3fff"]
  });
  assert.strictEqual(sequence.ok, true, sequence.error);
  assert.strictEqual(sequence.apdus.length, 2);
  assert.strictEqual(sequence.getResponse, true);
  assert.strictEqual(reader.describeTransmit({
    reader: usual, apdu: "00a40400", getResponse: false
  }).getResponse, false);
  var many = [];
  while (many.length <= reader.MAX_SEQUENCE) {
    many.push("00a40400");
  }
  assert.strictEqual(reader.describeTransmit({
    reader: usual, apdus: many
  }).ok, false);
  assert.ok(reader.describeTransmit({
    reader: usual, apdus: ["00a40400", "00"]
  }).error.indexOf("APDU 2") === 0);
  log.info("OK — a reader name that is a URL, a port or a path is " +
      "refused, an APDU has a floor and a cap, a sequence has a cap, " +
      "and the relay is off by default.");
  log.debug("Leaving readerRefusals().");
}

// A card that answers from a script: each entry is the expected APDU
// in hex and the answer it gives.
function scriptedCard(script) {
  log.debug("Entering scriptedCard().");
  var sent = [];
  var i = 0;
  log.debug("Leaving scriptedCard().");
  return {
    sent: sent,
    send: function (apdu) {
      var hex = apdu.toString("hex");
      sent.push(hex);
      var entry = script[i];
      i += 1;
      if (!entry || entry[0] !== hex) {
        return Promise.reject(new Error("unexpected APDU " + hex));
      }
      return Promise.resolve(Buffer.from(entry[1], "hex"));
    }
  };
}

async function readerExchanges() {
  log.debug("Entering readerExchanges().");
  assert.strictEqual(reader.withLe(fromHex("00cb3fff"), 0x10)
      .toString("hex"), "00cb3fff10");
  assert.strictEqual(reader.withLe(fromHex("00ca006e00"), 0x2a)
      .toString("hex"), "00ca006e2a");
  assert.strictEqual(reader.withLe(fromHex("00cb3fff055c035fc10500"),
      0x40).toString("hex"), "00cb3fff055c035fc10540");
  assert.strictEqual(reader.withLe(fromHex("00cb3fff055c035fc105"),
      0x40).toString("hex"), "00cb3fff055c035fc10540");
  assert.strictEqual(reader.withLe(fromHex("00cb3fff000001aa0000"),
      0x40), null, "an extended APDU has no one-byte Le");

  // 61xx twice: the data is the concatenation and the final status is
  // the last GET RESPONSE's.
  var card = scriptedCard([
    ["00cb3fff055c035fc10500", "aabb6104"],
    ["00c0000004", "ccddeeff6102"],
    ["00c0000002", "11229000"]
  ]);
  var answer = await reader.exchange(card.send,
      fromHex("00cb3fff055c035fc10500"), true);
  assert.strictEqual(answer.data, "aabbccddeeff1122");
  assert.strictEqual(answer.status, "9000");
  assert.strictEqual(answer.steps.length, 3);

  // GET RESPONSE keeps the logical channel of the command.
  var channel = scriptedCard([
    ["01ca006e00", "6101"],
    ["01c0000001", "779000"]
  ]);
  assert.strictEqual((await reader.exchange(channel.send,
      fromHex("01ca006e00"), true)).data, "77");

  // 6Cxx resends with the Le the card asked for.
  var wrongLe = scriptedCard([
    ["00ca006e00", "6c03"],
    ["00ca006e03", "0102039000"]
  ]);
  var fixed = await reader.exchange(wrongLe.send, fromHex("00ca006e00"),
      true);
  assert.strictEqual(fixed.data, "010203");
  assert.strictEqual(fixed.status, "9000");

  // getResponse off is the raw exchange.
  var raw = scriptedCard([["00cb3fff055c035fc10500", "aabb6104"]]);
  var rawAnswer = await reader.exchange(raw.send,
      fromHex("00cb3fff055c035fc10500"), false);
  assert.strictEqual(rawAnswer.status, "6104");
  assert.strictEqual(raw.sent.length, 1);

  // A sequence stops at the first APDU that fails.
  var pin = scriptedCard([
    ["00a4040005a000000308", "9000"],
    ["0020008008313233343536ffff", "63c2"]
  ]);
  var results = await reader.runSequence(pin.send, [
    fromHex("00a4040005a000000308"),
    fromHex("0020008008313233343536ffff"),
    fromHex("00cb3fff055c035fc10500")
  ], true);
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[1].status, "63C2");

  // transmit() opens ONE connection, exclusive for a sequence.
  var EventEmitter = require("events");
  var opened = [];
  var factory = function () {
    var pcsc = new EventEmitter();
    pcsc.close = function () {};
    setImmediate(function () {
      pcsc.emit("reader", {
        name: "Fake Reader 00",
        SCARD_SHARE_SHARED: 2,
        SCARD_SHARE_EXCLUSIVE: 1,
        SCARD_LEAVE_CARD: 0,
        connect: function (opts, cb) {
          opened.push(opts.share_mode);
          cb(null, 2);
        },
        transmit: function (apdu, max, protocol, cb) {
          cb(null, Buffer.from("9000", "hex"));
        },
        disconnect: function (how, cb) {
          cb();
        }
      });
    });
    return pcsc;
  };
  var done = await reader.transmit("Fake Reader 00",
      [fromHex("00a40400"), fromHex("00cb3fff")], { factory: factory });
  assert.strictEqual(done.results.length, 2);
  assert.deepStrictEqual(opened, [1]);
  await reader.transmit("Fake Reader 00", [fromHex("00a40400")],
      { factory: factory });
  assert.deepStrictEqual(opened, [1, 2]);

  // A connect failure keeps pcsclite's own text.
  var refusing = function () {
    var pcsc = new EventEmitter();
    pcsc.close = function () {};
    setImmediate(function () {
      pcsc.emit("reader", {
        name: "Fake Reader 00",
        SCARD_SHARE_SHARED: 2,
        SCARD_SHARE_EXCLUSIVE: 1,
        connect: function (opts, cb) {
          cb(new Error("SCardConnect error: Card is unpowered." +
              "(0x80100067)"));
        }
      });
    });
    return pcsc;
  };
  var said = null;
  try {
    await reader.transmit("Fake Reader 00", [fromHex("00a40400")],
        { factory: refusing });
  } catch (e) {
    said = e.message;
  }
  assert.ok(said && said.indexOf("Card is unpowered.(0x80100067)") >= 0,
      said);
  assert.ok(said.indexOf("No card in") < 0, said);

  // GET RESPONSE keeps the channel and nothing else, in both CLA
  // ranges: 13 (chained, channel 3) -> 03, 51 (further, channel 5)
  // -> 41, 71 (further, chained) -> 41.
  assert.strictEqual(reader.responseCla(0x13), 0x03);
  assert.strictEqual(reader.responseCla(0x51), 0x41);
  assert.strictEqual(reader.responseCla(0x71), 0x41);
  // YKOATH answers 61xx and wants SEND REMAINING (A5), not C0.
  var oathCard = scriptedCard([
    ["00a4040007a000000527210100", "79030500009000"],
    ["00a1000000", "7205216465616d6f6110"],
    ["00a5000010", "720521626262626290" + "00"]
  ]);
  var oathRun = await reader.runSequence(oathCard.send, [
    fromHex("00a4040007a000000527210100"), fromHex("00a1000000")
  ], true);
  assert.strictEqual(oathRun.length, 2);
  assert.strictEqual(oathRun[1].status, "9000", oathCard.sent.join());
  assert.strictEqual(reader.describeTransmit({ reader: "R",
      apdu: "00a1000000", remainingIns: "a5" }).remainingIns, 0xa5);
  assert.strictEqual(reader.describeTransmit({ reader: "R",
      apdu: "00a1000000", remainingIns: "b0" }).ok, false);
  log.info("OK — 61xx is followed by GET RESPONSE on the same channel, " +
      "6Cxx is resent with the Le asked for, a sequence stops at a " +
      "failure and runs on one exclusive connection, and YKOATH gets " +
      "SEND REMAINING.");
  log.debug("Leaving readerExchanges().");
}

function enginesStayOffTheDom() {
  log.debug("Entering enginesStayOffTheDom().");
  var names = ["piv.js", "yubico_otp.js", "oath.js",
      "openpgp_card.js", "yubihsm_auth.js"];
  var forbidden = ["document", "window", "localStorage",
      "sessionStorage", "pcsclite"];
  var n = 0;
  for (n = 0; n < names.length; n++) {
    var source = fs.readFileSync(path.join(SRC, names[n]), "utf8");
    var code = source.replace(/\/\*[\s\S]*?\*\//g, "")
        .split("\n").filter(function (line) {
          return !/^\s*\/\//.test(line);
        }).join("\n");
    var f = 0;
    for (f = 0; f < forbidden.length; f++) {
      assert.ok(code.indexOf(forbidden[f]) < 0,
          names[n] + " reaches " + forbidden[f] + ".");
    }
  }
  var page = fs.readFileSync(path.join(REPO, "client", "public",
      "smartcard.html"), "utf8");
  assert.ok(page.indexOf("sc_backend_notice") >= 0);
  assert.ok(page.indexOf("webauthn.html") >= 0);
  var index = fs.readFileSync(path.join(REPO, "client", "public",
      "index.html"), "utf8");
  var at = index.indexOf('href="/smartcard.html"');
  assert.ok(at > 0, "the landing page has no smart-card card");
  assert.ok(index.slice(at, at + 500).indexOf(
      "data-not-on-static") < 0);
  log.info("OK — the codecs have no DOM, and the page is an " +
      "ordinary landing card.");
  log.debug("Leaving enginesStayOffTheDom().");
}

// THE PANES COLLAPSE, LIKE THE XACML AND GNAP PAGES'. Every application
// pane's legend toggles its own body, the body has the id the legend names,
// the collapse / expand all switch is there, and the bundle exports the two
// functions those handlers call — a handler naming a function the bundle
// does not export is a click that throws in the page and does nothing.
function panesCollapse() {
  log.debug("Entering panesCollapse().");
  var page = fs.readFileSync(path.join(REPO, "client", "public",
      "smartcard.html"), "utf8");
  ["config", "otp", "oath", "piv", "pgp", "hsm", "reader", "reset"]
    .forEach(function (name) {
    var id = "sc_pane_" + name;
    assert.ok(page.indexOf("smartcard.togglePane('" + id + "_body')") >= 0,
        id + "'s legend does not toggle it");
    assert.ok(page.indexOf('class="saml-pane-body" id="' + id + '_body"') >=
        0, id + " has no body for its legend to toggle");
  });
  assert.ok(page.indexOf('onchange="return smartcard.setAllPanes(') >= 0,
      "smartcard.html has no collapse / expand all switch");
  var source = fs.readFileSync(path.join(SRC, "smartcard.js"), "utf8");
  assert.ok(/togglePane:\s*panes\.togglePane/.test(source) &&
      /setAllPanes:\s*panes\.setAllPanes/.test(source),
      "smartcard.js does not export the pane functions its page calls");
  log.info("OK — every smart-card pane collapses, and the switch is there.");
  log.debug("Leaving panesCollapse().");
}

// CHALLENGE-RESPONSE OVER CCID, for a browser with no WebHID. The SELECT is
// the OTP application's AID, and the CALCULATE carries in its data exactly
// the 64-byte payload the HID frame carries — so a key answers the two
// transports alike — with the slot in P1. And the WebHID path asks for the
// key's OTP KEYBOARD interface: it asked for the FIDO usage page until
// 2026-11-13, which Chrome blocks from WebHID, so it never found a key.
function challengeOverCcid() {
  log.debug("Entering challengeOverCcid().");
  assert.strictEqual(otp.ccidSelectApdu(), "00a4040008a000000527200101");
  var challenge = Buffer.from("0102030405", "hex");
  var apdu = Buffer.from(otp.ccidCalculateApdu(0x38, challenge), "hex");
  assert.deepStrictEqual(Array.from(apdu.slice(0, 5)),
      [0x00, 0x01, 0x38, 0x00, 0x40]);
  var frame = otp.hidFrame(0x38, challenge);
  assert.ok(apdu.slice(5).equals(frame.slice(0, 64)),
      "the CALCULATE data is not the HID frame's payload");
  assert.strictEqual(apdu.length, 69);
  // A challenge ending in 0x00 is padded with 0x01 in variable mode.
  var zeroEnd = Buffer.from(otp.ccidCalculateApdu(0x30,
      Buffer.from("aa00", "hex")), "hex");
  assert.strictEqual(zeroEnd[5 + 2], 0x01);
  assert.throws(function () {
    otp.ccidCalculateApdu(0x20, Buffer.from("01", "hex"));
  }, /6 bytes/);
  var answer = Buffer.alloc(20, 7);
  assert.ok(otp.ccidResponse(0x30, answer).equals(answer));
  assert.strictEqual(otp.ccidResponse(0x20, Buffer.alloc(18, 1)).length, 16);
  assert.throws(function () {
    otp.ccidResponse(0x30, Buffer.alloc(4));
  }, /configured for challenge-response/);
  var page = fs.readFileSync(path.join(SRC, "smartcard.js"), "utf8");
  assert.ok(/usagePage:\s*0x0001,\s*usage:\s*0x0006/.test(page),
      "the WebHID filter does not ask for the OTP keyboard interface");
  assert.ok(!/usagePage:\s*0xf1d0/i.test(page),
      "the WebHID filter asks for the FIDO usage page, which Chrome blocks");
  var html = fs.readFileSync(path.join(REPO, "client", "public",
      "smartcard.html"), "utf8");
  assert.ok(html.indexOf('id="sc_transport"') >= 0 &&
      html.indexOf('value="browser"') >= 0 &&
      html.indexOf('value="api"') >= 0,
      "the page offers no choice between the browser and the api");
  // The OTP application's status, as a YubiKey 5 with slot 1 programmed
  // (needing a touch) and slot 2 empty answered SELECT on 2026-11-13.
  var st = otp.parseStatus(Buffer.from("00000101050a", "hex"));
  assert.strictEqual(st.version, "0.0.1");
  assert.strictEqual(st.programSequence, 1);
  assert.deepStrictEqual(st.slot1, { configured: true, touch: true });
  assert.deepStrictEqual(st.slot2, { configured: false, touch: false });
  var both = otp.parseStatus(Buffer.from("050402070300", "hex"));
  assert.strictEqual(both.version, "5.4.2");
  assert.deepStrictEqual(both.slot2, { configured: true, touch: false });
  assert.throws(function () {
    otp.parseStatus(Buffer.from("0102", "hex"));
  }, /6 bytes/);
  log.info("OK — challenge-response over CCID is SELECT then CALCULATE " +
      "with the HID payload, and WebHID asks for the OTP interface.");
  log.debug("Leaving challengeOverCcid().");
}

// "READ FROM THE KEY" ONLY READS. Every APDU in every application's read
// plan is SELECT, GET DATA, a LIST or CALCULATE, PIV's GET VERSION / GET
// SERIAL / ATTEST, or OpenPGP's GENERATE ASYMMETRIC KEY PAIR with P1=0x81 —
// which READS the public key and generates nothing. No VERIFY, no PIN, no
// PUT, no DELETE, no RESET: a plan that grew one would be a button that
// changes a key, and this fails it.
function readPlansOnlyRead() {
  log.debug("Entering readPlansOnlyRead().");
  var page = paths.requireSharedModule(
    [path.join(SRC, "smartcard.js")], "client/src/smartcard.js");
  var allowed = {
    otp: [0xa4],                 // SELECT, whose answer is the slot status
    oath: [0xa4, 0xa1],          // SELECT / CALCULATE ALL, LIST
    piv: [0xa4, 0xcb, 0xfd, 0xf8, 0xf9],
    pgp: [0xa4, 0xca, 0x47],
    hsm: [0xa4, 0x05, 0x07]
  };
  var count = 0;
  Object.keys(allowed).forEach(function (app) {
    var plan = page.readPlan(app);
    assert.ok(plan.length > 0, app + " has no read plan");
    plan.forEach(function (step) {
      assert.ok(/^00a40400/.test(step[1][0]),
          app + " " + step[0] + " does not begin with SELECT");
      step[1].forEach(function (hex) {
        var ins = parseInt(hex.slice(2, 4), 16);
        assert.ok(allowed[app].indexOf(ins) >= 0, app + " " + step[0] +
            " sends INS " + hex.slice(2, 4) + ", which is not a read");
        if (app === "pgp" && ins === 0x47) {
          assert.strictEqual(hex.slice(4, 6), "81", "OpenPGP " + step[0] +
              " would GENERATE a key: P1 must be 81 (read)");
        }
        if (app === "oath" && ins === 0xa4 && hex.slice(4, 8) !== "0400") {
          assert.strictEqual(hex.slice(4, 8), "0001",
              "OATH " + step[0] + " is not CALCULATE ALL");
        }
        count += 1;
      });
    });
  });
  log.info("OK — " + count + " APDUs across " + Object.keys(allowed).length +
      " read plans are all reads.");
  log.debug("Leaving readPlansOnlyRead().");
}

// ADDING AN OATH ACCOUNT: base32 per RFC 4648's own test vectors, the
// otpauth:// key-URI example, the period-in-name convention Yubico
// Authenticator uses, long keys hashed to the block size, and a PUT built
// from it that decodes back to the account.
function oathAccountInput() {
  log.debug("Entering oathAccountInput().");
  var vectors = [["", null], ["MY======", "f"], ["MZXQ====", "fo"],
                 ["MZXW6===", "foo"], ["MZXW6YQ=", "foob"],
                 ["MZXW6YTB", "fooba"], ["MZXW6YTBOI======", "foobar"]];
  vectors.forEach(function (v) {
    if (v[1] === null) {
      assert.throws(function () {
        oath.base32Decode(v[0]);
      }, /base32/);
      return;
    }
    assert.strictEqual(oath.base32Decode(v[0]).toString("utf8"), v[1]);
    assert.strictEqual(oath.base32Decode(v[0].toLowerCase()
      .replace(/=/g, "")).toString("utf8"), v[1]);
  });
  assert.throws(function () {
    oath.base32Decode("ABC1");
  }, /base32/);
  var link = oath.parseOtpauth("otpauth://totp/Example:alice@google.com" +
      "?secret=JBSWY3DPEHPK3PXP&issuer=Example");
  assert.deepStrictEqual([link.type, link.issuer, link.account,
                          link.algorithm, link.digits, link.period],
                         ["TOTP", "Example", "alice@google.com", "SHA-1",
                          6, 30]);
  var hotp = oath.parseOtpauth("otpauth://hotp/Acme:bob?secret=MZXW6&" +
      "algorithm=SHA512&digits=8&counter=7");
  assert.deepStrictEqual([hotp.type, hotp.issuer, hotp.account,
                          hotp.algorithm, hotp.digits, hotp.counter],
                         ["HOTP", "Acme", "bob", "SHA-512", 8, 7]);
  assert.throws(function () {
    oath.parseOtpauth("https://example.com");
  }, /otpauth/);
  assert.strictEqual(oath.credentialName({ issuer: "Example",
      account: "alice", type: "TOTP", period: 30 }), "Example:alice");
  assert.strictEqual(oath.credentialName({ issuer: "Example",
      account: "alice", type: "TOTP", period: 60 }), "60/Example:alice");
  assert.strictEqual(oath.credentialName({ account: "bob", type: "HOTP",
      period: 60 }), "bob");
  assert.strictEqual(oath.hmacKey(Buffer.alloc(64, 1), "SHA-1").length, 64);
  assert.strictEqual(oath.hmacKey(Buffer.alloc(65, 1), "SHA-1").length, 20);
  assert.strictEqual(oath.hmacKey(Buffer.alloc(100, 1), "SHA-512").length,
                     100);
  var key = oath.hmacKey(oath.base32Decode(link.secret), "SHA-1");
  var put = oath.putApdu({ name: "Example:alice@google.com", type: "TOTP",
      algorithm: "SHA-1", digits: 6, secret: key, touch: true });
  var described = oath.describeCommand(put);
  assert.ok(/PUT/.test(described.summary), described.summary);
  assert.ok(JSON.stringify(described.rows).indexOf("Example:alice@google" +
      ".com") >= 0, "the PUT does not carry the account's name");
  log.info("OK — base32, otpauth links, period names and long keys turn " +
      "into the PUT the applet takes.");
  log.debug("Leaving oathAccountInput().");
}

// PROGRAMMING AN OTP SLOT, byte for byte against yubikit (python3-ykman
// 4.0.7's yubikit.yubiotp, get_config()), and the CCID framing yubikit's
// write_update uses: INS 0x01, P1 1 or 3, the config and the current access
// code; delete is 52 zero bytes; swap is P1 6 with no data.
function otpSlotConfigs() {
  log.debug("Entering otpSlotConfigs().");
  var k = Buffer.from("0102030405060708090a0b0c0d0e0f1011121314", "hex");
  var h = Buffer.from("3132333435363738393031323334353637383930", "hex");
  var expected = {
    hmac: [{ type: "hmac", key: k }, "00000000000000000000000000000000111213" +
      "1400000102030405060708090a0b0c0d0e0f100000000000000024402600" +
      "00064d"],
    touch: [{ type: "hmac", key: k, touch: true }, "000000000000000000000" +
      "000000000001112131400000102030405060708090a0b0c0d0e0f1000000000" +
      "00000024402e0000c48b"],
    acc: [{ type: "hmac", key: k, accCode: Buffer.from("aabbccddeeff",
      "hex") }, "000000000000000000000000000000001112131400000102030405" +
      "060708090a0b0c0d0e0f10aabbccddeeff0024402600006ddf"],
    otp: [{ type: "yubico-otp", publicId: Buffer.from("010203040506",
      "hex"), privateId: Buffer.from("a1a2a3a4a5a6", "hex"),
      aesKey: Buffer.from("000102030405060708090a0b0c0d0e0f", "hex") },
      "01020304050600000000000000000000a1a2a3a4a5a6000102030405060708" +
      "090a0b0c0d0e0f000000000000063420000000c041"],
    hotp: [{ type: "hotp", key: h }, "0000000000000000000000000000000037" +
      "383930000031323334353637383930313233343536000000000000003460" +
      "4000005fc0"],
    hotp8: [{ type: "hotp", key: h, digits: 8, imf: 32 }, "0000000000000" +
      "000000000000000000037383930000231323334353637383930313233343536" +
      "0000000000000034604200 00948f".replace(/ /g, "")]
  };
  Object.keys(expected).forEach(function (name) {
    assert.strictEqual(otp.slotConfig(expected[name][0]).toString("hex"),
        expected[name][1], name + " does not match yubikit");
  });
  var apdu = otp.programSlotApdu(2, otp.slotConfig(expected.hmac[0]));
  assert.strictEqual(apdu.slice(0, 10), "000103003a");
  assert.strictEqual(apdu.length, (5 + 58) * 2);
  assert.strictEqual(otp.programSlotApdu(1, null).slice(0, 10),
      "000101003a");
  assert.ok(/^0+$/.test(otp.programSlotApdu(1, null).slice(10)));
  assert.strictEqual(otp.swapSlotsApdu(), "00010600");
  assert.throws(function () {
    otp.programSlotApdu(3, null);
  }, /1 or 2/);
  assert.throws(function () {
    otp.slotConfig({ type: "hmac", key: Buffer.alloc(21, 1) });
  }, /20 bytes/);
  assert.throws(function () {
    otp.slotConfig({ type: "hotp", key: h, imf: 17 });
  }, /multiple of 16/);
  log.info("OK — OTP slot configurations match yubikit byte for byte.");
  log.debug("Leaving otpSlotConfigs().");
}

// A SCRIPTED KEY for the whole HID exchange: it takes the frame's reports
// (refusing a write while it is still busy with the last), waits once for
// a touch, sends hidAnswer()'s reports, and takes the reset report. The
// same key behind a fake node-hid exercises api/otp_hid.js, whose
// feature-report reads arrive with hidapi's report-ID byte first.
function scriptedHidKey(response, frameReports) {
  log.debug("Entering scriptedHidKey().");
  var key = { written: [], resetSeen: false, frameDone: false };
  var answer = hidAnswer(response);
  var touchShown = false;
  var reportsLeft = null;
  key.sendNow = function (report) {
    var r = Buffer.from(report);
    if (r[0] === 0xff && r[7] === 0x8f) {
      key.resetSeen = true;
    } else {
      key.written.push(r);
    }
  };
  key.send = function (report) {
    key.sendNow(report);
    return Promise.resolve();
  };
  key.receive = function () {
    return Promise.resolve(key.receiveNow());
  };
  key.receiveNow = function () {
    var out = Buffer.alloc(8, 0);
    if (key.written.length >= frameReports && !key.resetSeen) {
      if (!touchShown) {
        touchShown = true;
        out[7] = 0x20;
      } else {
        reportsLeft = reportsLeft || answer.slice();
        out = reportsLeft.length > 1 ? reportsLeft.shift() : reportsLeft[0];
      }
    }
    return out;
  };
  log.debug("Leaving scriptedHidKey().");
  return key;
}

async function hidExchangeEndToEnd() {
  log.debug("Entering hidExchangeEndToEnd().");
  var crypto = require("crypto");
  var secret = Buffer.from("0102030405060708090a0b0c0d0e0f1011121314", "hex");
  var challenge = Buffer.from("0102030405", "hex");
  var expected = crypto.createHmac("sha1", secret).update(challenge).digest();
  var frameReports = otp.hidReports(otp.hidFrame(0x38, challenge)).length;
  var key = scriptedHidKey(expected, frameReports);
  var touched = 0;
  var got = await otp.hidChallenge(key, 0x38, challenge, {
    sleep: function () {
      return Promise.resolve();
    },
    onTouch: function () {
      touched += 1;
    }
  });
  assert.strictEqual(got.response.toString("hex"), expected.toString("hex"));
  assert.strictEqual(touched, 1, "the touch wait was not reported once");
  assert.ok(key.resetSeen, "the reset report was not written");
  var frame = otp.hidFrame(0x38, challenge);
  assert.deepStrictEqual(key.written.map(function (r) {
    return r.toString("hex");
  }), otp.hidReports(frame).map(function (r) {
    return Buffer.from(r).toString("hex");
  }), "the key did not receive the frame hidFrame() built");

  // The api's path, with the same key behind a fake node-hid.
  var hidKey = scriptedHidKey(expected, frameReports);
  var fakeHid = {
    devices: function () {
      return [{ vendorId: 0x1050, usagePage: 0xf1d0, usage: 1,
                interface: 1, path: "fido" },
              { vendorId: 0x1050, usagePage: 1, usage: 6, interface: 0,
                path: "otp", product: "YubiKey OTP+FIDO+CCID" }];
    },
    HID: function (devicePath) {
      assert.strictEqual(devicePath, "otp", "opened the wrong interface");
      this.sendFeatureReport = function (bytes) {
        assert.strictEqual(bytes[0], 0, "no report ID first");
        hidKey.sendNow(Buffer.from(bytes.slice(1)));
        return bytes.length;
      };
      this.getFeatureReport = function (id, length) {
        assert.strictEqual(length, 9);
        return [0].concat(Array.from(hidKey.receiveNow()));
      };
      this.close = function () {};
    }
  };
  var viaApi = await otpHid.challenge(0x38, challenge,
      { hid: fakeHid, otp: otp });
  assert.strictEqual(viaApi.response, expected.toString("hex"));
  assert.strictEqual(viaApi.device, "YubiKey OTP+FIDO+CCID");
  assert.deepStrictEqual(otpHid.describeChallenge({ slot: "38",
      challenge: "0102" }).slot, 0x38);
  assert.strictEqual(otpHid.describeChallenge({ slot: "40" }).ok, false);
  assert.strictEqual(otpHid.describeChallenge({ slot: "30",
      challenge: "zz" }).ok, false);
  assert.strictEqual(otpHid.eightBytes([0, 1, 2, 3, 4, 5, 6, 7, 8])
      .toString("hex"), "0102030405060708");
  await assert.rejects(otpHid.challenge(0x38, challenge, { hid: {
    devices: function () {
      return [];
    } }, otp: otp }), /No YubiKey OTP interface/);
  log.info("OK — the HID exchange answers a scripted key in the page's " +
      "and the api's wrappers alike, and the api opens the OTP interface.");
  log.debug("Leaving hidExchangeEndToEnd().");
}

// PIV WRITING, against yubikit (python3-ykman 4.0.7's PivSession over a
// connection that records what it sends). yubikit encodes these as
// extended APDUs and this tree as short ones — ISO 7816-4 allows both —
// so the comparison is of instruction, parameters and data.
var PIV_YUBIKIT = {
  generate: ["00", "47", "00", "9c", "ac09800114aa0103ab0102"],
  changePin: ["00", "24", "00", "80", "313233343536ffff363534333231ffff"],
  changePuk: ["00", "24", "00", "81", "31323334353637383837363534333231"],
  unblock: ["00", "2c", "00", "80", "3132333435363738363534333231ffff"],
  setMgmAes192Touch: ["00", "ff", "ff", "fe", "0a9b18" + "11".repeat(24)],
  setMgm3des: ["00", "ff", "ff", "ff", "039b18" +
      "000102030405060708090a0b0c0d0e0f1011121314151617"],
  deleteCert: ["00", "db", "3f", "ff", "5c035fc1055300"]
};

function sameCommand(apdu, expected, what) {
  log.debug("Entering sameCommand().");
  var c = iso.parseCommand(apdu);
  var got = [c.cla, c.ins, c.p1, c.p2].map(function (b) {
    return ("0" + b.toString(16)).slice(-2);
  }).concat([Buffer.from(c.data).toString("hex")]);
  assert.deepStrictEqual(got, expected, what + " differs from yubikit");
  log.debug("Leaving sameCommand().");
}

function pivWriteCommands() {
  log.debug("Entering pivWriteCommands().");
  sameCommand(piv.generateApdu(0x9c, "eccp384", 3, 2), PIV_YUBIKIT.generate,
      "GENERATE");
  sameCommand(piv.changeReferenceApdu(0x80, "123456", "654321"),
      PIV_YUBIKIT.changePin, "change PIN");
  sameCommand(piv.changeReferenceApdu(0x81, "12345678", "87654321"),
      PIV_YUBIKIT.changePuk, "change PUK");
  sameCommand(piv.unblockPinApdu("12345678", "654321"), PIV_YUBIKIT.unblock,
      "unblock PIN");
  sameCommand(piv.setManagementKeyApdu("aes192", Buffer.alloc(24, 0x11),
      true), PIV_YUBIKIT.setMgmAes192Touch, "set management key");
  sameCommand(piv.setManagementKeyApdu("3des", Buffer.from(
      "000102030405060708090a0b0c0d0e0f1011121314151617", "hex"), false),
      PIV_YUBIKIT.setMgm3des, "set 3DES management key");
  sameCommand(piv.putCertificateApdu(0x9a, null), PIV_YUBIKIT.deleteCert,
      "delete certificate");
  var put = iso.parseCommand(piv.putCertificateApdu(0x9a,
      Buffer.from("010203", "hex")));
  assert.strictEqual(Buffer.from(put.data).toString("hex"),
      "5c035fc105530a7003010203710100fe00", "PUT certificate");
  assert.strictEqual(piv.certificateObject(0x82), "5fc10d");
  assert.strictEqual(piv.certificateObject(0x95), "5fc120");
  assert.strictEqual(piv.ecb("aes128", Buffer.from(
      "000102030405060708090a0b0c0d0e0f", "hex"), Buffer.from(
      "00112233445566778899aabbccddeeff", "hex")).toString("hex"),
      "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 is not FIPS-197's");
  assert.throws(function () {
    piv.changeReferenceApdu(0x80, "12345", "654321");
  }, /6 to 8/);

  // Mutual authentication against a simulated card, for each cipher: the
  // card encrypts a witness, the page decrypts it and challenges back, the
  // card proves itself by encrypting the challenge. A card holding a
  // different key is caught.
  ["3des", "aes128", "aes192", "aes256"].forEach(function (alg) {
    var spec = piv.MGM_ALGORITHMS[alg];
    var key = crypto.randomBytes(spec.keyLen);
    var witness = crypto.randomBytes(spec.block);
    var challenge = crypto.randomBytes(spec.block);
    var step1 = iso.parseCommand(piv.authWitnessApdu(alg));
    assert.strictEqual(Buffer.from(step1.data).toString("hex"), "7c028000");
    var cardWitness = iso.encodeTlv(0x7c, iso.encodeTlv(0x80,
        piv.ecb(alg, key, witness, false)));
    var step2 = piv.authResponseApdu(alg, key, cardWitness, challenge);
    var sent = iso.parseElements(iso.parseElements(Buffer.from(
        iso.parseCommand(step2.apdu).data))[0].value);
    assert.ok(sent[0].value.equals(witness), alg + ": witness not decrypted");
    assert.ok(sent[1].value.equals(challenge), alg + ": challenge not sent");
    var cardProof = iso.encodeTlv(0x7c, iso.encodeTlv(0x82,
        piv.ecb(alg, key, challenge, false)));
    assert.ok(piv.authCardProven(cardProof, step2.expected), alg +
        ": a card with the key is not believed");
    var impostor = iso.encodeTlv(0x7c, iso.encodeTlv(0x82,
        piv.ecb(alg, crypto.randomBytes(spec.keyLen), challenge, false)));
    assert.ok(!piv.authCardProven(impostor, step2.expected), alg +
        ": a card without the key is believed");
  });
  log.info("OK — PIV writes match yubikit, and mutual authentication " +
      "proves the card in 3DES and three AES sizes.");
  log.debug("Leaving pivWriteCommands().");
}

// OPENPGP CARD WRITING: the v4 fingerprints written after GENERATE, held to
// GnuPG 2.2.27's own for three keys it generated (each rebuilt as the
// card's 7F49 answer), and the command shapes of the 3.4 specification.
var GPG_KEYS =
  [
    {
      "alg": "ed25519",
      "created": 1794621806,
      "tlv": {
        "86": "4d14ecd07e499552a9fc3d818a27512e9a911ff950ee68f9ff29b8a21c62fc54"
      },
      "fingerprint": "e66cc44cea126ec649872293ae36941908cb9bc1"
    },
    {
      "alg": "cv25519",
      "created": 1794621806,
      "tlv": {
        "86": "c6c82f49916c8eda723c35f70a34a3b73728c6405569c45d4cfe08e912c94449"
      },
      "fingerprint": "6bf4773f1363aadba4f54271bf8b4ca586fdbd5f"
    },
    {
      "alg": "rsa2048",
      "created": 1794621806,
      "tlv": {
        "81": "a9dcf73c080f989d58b1b3dd28ba6df97b387b14a31bac7825ffc843d6be70990b90eefa51dd408e90931c78312adce40a4c17195e99d5774cd4179ad4510d6ff5f2af8a37ae217d87e906fbf4be4877657c43a084b02427f574c92912200c9dd3f94cd022411f94d38c2d73540fb4885042d121b71a7166a64489ed112feecc43cd7712e79efe1d0f764e7c1378140c0ca0e1085fd16b36ebe8344b33bcaa3348bc3e7e2b54d670d1a6e28b0054a1fae5696318b9f23fa6eb9131a21e53472ff99033331c106aa51b8e678fb6065b213ebd7a196b5181f378a6a376a08ab78e84100c62bc073dbbedaf2466344dc9607e758d4ec8433d824267aee852d65d37",
        "82": "010001"
      },
      "fingerprint": "b0a37febdb420404212b0482c5883fdb8279ca6d"
    }
  ];

function pgpWriteCommands() {
  log.debug("Entering pgpWriteCommands().");
  GPG_KEYS.forEach(function (k) {
    var inner = Buffer.concat(Object.keys(k.tlv).map(function (tag) {
      return iso.encodeTlv(parseInt(tag, 16), Buffer.from(k.tlv[tag], "hex"));
    }));
    var answer = iso.encodeTlv(Buffer.from("7f49", "hex"), inner);
    assert.strictEqual(pgp.v4Fingerprint(k.alg, answer, k.created)
        .fingerprint.toString("hex"), k.fingerprint, k.alg +
        " fingerprint differs from GnuPG's");
  });
  sameCommand(pgp.verifyApdu(pgp.PW3, "12345678"),
      ["00", "20", "00", "83", "3132333435363738"], "VERIFY PW3");
  sameCommand(pgp.changePinApdu(pgp.PW1, "123456", "654321"),
      ["00", "24", "00", "81", "313233343536363534333231"], "change PW1");
  sameCommand(pgp.putDataApdu(0x5b, Buffer.from("Doe<<John")),
      ["00", "da", "00", "5b", "446f653c3c4a6f686e"], "PUT DATA name");
  sameCommand(pgp.putDataApdu(0x5f50, Buffer.from("https://x")),
      ["00", "da", "5f", "50", "68747470733a2f2f78"], "PUT DATA URL");
  sameCommand(pgp.algorithmAttributesApdu("sig", "ed25519"),
      ["00", "da", "00", "c1", "162b06010401da470f01"], "attributes");
  sameCommand(pgp.generateApdu("dec"), ["00", "47", "80", "00", "b800"],
      "GENERATE");
  sameCommand(pgp.touchPolicyApdu("aut", 1), ["00", "da", "00", "d8",
      "0120"], "touch policy");
  assert.throws(function () {
    pgp.verifyApdu(pgp.PW3, "1234567");
  }, /Admin PIN/);
  log.info("OK — OpenPGP fingerprints match GnuPG's, and the writes have " +
      "the 3.4 specification's shapes.");
  log.debug("Leaving pgpWriteCommands().");
}

// EVERY BUTTON REACHES A FUNCTION. A handler naming something the bundle
// does not export is a click that throws in the page and does nothing —
// which is what this page looked like from Firefox before its fixes.
function handlersAreExported() {
  log.debug("Entering handlersAreExported().");
  var html = fs.readFileSync(path.join(REPO, "client", "public",
      "smartcard.html"), "utf8");
  var page = paths.requireSharedModule([path.join(SRC, "smartcard.js")],
      "client/src/smartcard.js");
  var named = {};
  (html.match(/smartcard\.([A-Za-z]+)\(/g) || []).forEach(function (m) {
    named[m.slice(10, -1)] = true;
  });
  var missing = Object.keys(named).filter(function (fn) {
    return typeof page[fn] !== "function";
  });
  assert.deepStrictEqual(missing, [], "smartcard.html calls functions the " +
      "bundle does not export: " + missing.join(", "));
  log.info("OK — all " + Object.keys(named).length + " handlers on " +
      "smartcard.html are exported.");
  log.debug("Leaving handlersAreExported().");
}

// RESET: the PIN-blocking loops against simulated applets. A PIV applet
// refuses RESET until PIN and PUK are blocked; an OpenPGP one TERMINATE
// until PW1 and PW3 are. The loops must block both, then reset, and stop
// — sending no wiping command — if a card ever ACCEPTS the wrong value.
function simulatedApplet(rules) {
  log.debug("Entering simulatedApplet().");
  var tries = { a: 3, b: 3 };
  var log2 = [];
  var applet = function (hexes) {
    var hex = hexes[0];
    log2.push(hex.slice(0, 8));
    var ins = hex.slice(2, 4);
    var status = "9000";
    if (ins === "a4") {
      status = "9000";
    } else if (hex.slice(0, 8) === rules.a) {
      status = rules.acceptA ? "9000" : (tries.a > 1 ?
          "63c" + (--tries.a).toString(16) : (tries.a = 0, "6983"));
    } else if (hex.slice(0, 8) === rules.b) {
      status = tries.b > 1 ? "63c" + (--tries.b).toString(16) :
          (tries.b = 0, "6983");
    } else if (rules.wipe.indexOf(ins) >= 0) {
      status = tries.a === 0 && tries.b === 0 ? "9000" : "6985";
    }
    return Promise.resolve({ status: status, data: "" });
  };
  applet.sent = log2;
  log.debug("Leaving simulatedApplet().");
  return applet;
}

async function resetLoops() {
  log.debug("Entering resetLoops().");
  var pivCard = simulatedApplet({ a: "00200080", b: "002c0080",
                                  wipe: ["fb"] });
  var spent = await piv.reset(pivCard);
  assert.strictEqual(spent, 6, "PIV: 3 PIN and 3 PUK tries");
  assert.strictEqual(pivCard.sent[pivCard.sent.length - 1], "00fb0000",
      "PIV: RESET is not last");
  var pgpCard = simulatedApplet({ a: "00200081", b: "00200083",
                                  wipe: ["e6", "44"] });
  spent = await pgp.reset(pgpCard);
  assert.strictEqual(spent, 6);
  assert.deepStrictEqual(pgpCard.sent.slice(-2), ["00e60000", "00440000"],
      "OpenPGP: TERMINATE then ACTIVATE");
  var accepting = simulatedApplet({ a: "00200080", b: "002c0080",
                                    wipe: ["fb"], acceptA: true });
  await assert.rejects(piv.reset(accepting), /ACCEPTED/);
  assert.ok(accepting.sent.indexOf("00fb0000") < 0,
      "a card that accepted the wrong PIN was reset anyway");
  log.info("OK — the reset loops block both PINs, then reset, and refuse " +
      "to reset a card that accepts the wrong value.");
  log.debug("Leaving resetLoops().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  commandsRoundTrip();
  commandRefusals();
  responsesNameTheStatusWord();
  tlvRoundTripAndRefusals();
  theModuleStaysACodec();
  await pivCertificates();
  await pivAttestation();
  otpVectors();
  oathVectors();
  await openpgpKeys();
  yubihsmTraces();
  readerRefusals();
  await readerExchanges();
  enginesStayOffTheDom();
  panesCollapse();
  challengeOverCcid();
  readPlansOnlyRead();
  oathAccountInput();
  otpSlotConfigs();
  await hidExchangeEndToEnd();
  pivWriteCommands();
  pgpWriteCommands();
  handlersAreExported();
  await resetLoops();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
});
