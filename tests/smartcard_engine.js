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
  log.info("OK — published OTP vectors decrypt, both HMACs match, " +
      "and the verifier refuses a bad URL.");
  log.debug("Leaving otpVectors().");
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
  var ecc = pgp.parseAlgorithmAttributes(Buffer.concat([
    Buffer.from([0x13, oid.length]), oid
  ]));
  assert.strictEqual(ecc.curve, "P-256");

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
  assert.strictEqual(typeof limits.available, "boolean");
  if (!limits.available) {
    assert.ok(limits.reason && limits.reason.length > 0);
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
  log.info("OK — a reader name that is a URL, a port or a path is " +
      "refused, and an APDU has a floor and a cap.");
  log.debug("Leaving readerRefusals().");
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

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  commandsRoundTrip();
  commandRefusals();
  responsesNameTheStatusWord();
  tlvRoundTripAndRefusals();
  theModuleStaysACodec();
  await pivCertificates();
  otpVectors();
  oathVectors();
  await openpgpKeys();
  yubihsmTraces();
  readerRefusals();
  enginesStayOffTheDom();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
});
