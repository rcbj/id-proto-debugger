const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const crypto = require("crypto");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'encoding_tools',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
// THIS FILE DRIVES THE PAGE; tests/hash_engine.js CHECKS THE BYTES.
// The split is the one crypto_engines.js makes against encryption_tools.js
// and for the same reason: a digest is where being wrong looks exactly like
// being right, so correctness is asserted in node against OpenSSL and against
// the specifications' own sample values, and what is asserted HERE is that
// the controls are wired to the engine — including the two panes added for
// FIPS 202 and SP 800-185, whose vectors are used below precisely because
// they come from NIST rather than from the code under test.
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Hashing is synchronous and pure JavaScript now (client/src/hash_tools.js,
// which replaced this page's crypto.subtle calls when the FIPS 202 pane was
// added — Web Crypto has no SHA-3 in any browser). The generous wait is kept
// anyway: the values still arrive through a click handler on a busy CI host,
// and nothing is gained by tightening it.
var cryptoWait = Math.max(waitTime, 15000);

// ===========================================================================
// Independent reference implementations — the test computes the expected
// output itself (never trusts the page to grade its own answer).
// ===========================================================================
function expectedBase64(str) {
  log.debug("Entering expectedBase64().");
  log.debug("Leaving expectedBase64().");
  return Buffer.from(str, "utf8").toString("base64");
}

function expectedUri(str) {
  log.debug("Entering expectedUri().");
  log.debug("Leaving expectedUri().");
  return encodeURIComponent(str);
}

// CRC-32 (IEEE 802.3, reflected) — mirrors the page's implementation, computed
// here from scratch so the comparison is a genuine known-answer check.
var CRC32_TABLE = (function () {
  var table = new Array(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function expectedCrc32(str) {
  log.debug("Entering expectedCrc32().");
  var bytes = Buffer.from(str, "utf8");
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
  }
  crc = (crc ^ 0xFFFFFFFF) >>> 0;
  log.debug("Leaving expectedCrc32().");
  return ("0000000" + crc.toString(16)).slice(-8);
}

// Map the page's SHA algorithm labels to Node's crypto hash names.
var SHA_ALGS = {
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
  "SHA-512/224": "sha512-224",
  "SHA-512/256": "sha512-256",
};

// The FIPS 202 pane. node's OpenSSL has all six of these functions, so the
// expected value is computed here rather than transcribed — and SHAKE takes
// its output length, which is the argument the pane grows a field for.
var SHA3_ALGS = {
  "SHA3-224": "sha3-224",
  "SHA3-256": "sha3-256",
  "SHA3-384": "sha3-384",
  "SHA3-512": "sha3-512",
};

function expectedSha(alg, str) {
  log.debug("Entering expectedSha().");
  log.debug("Leaving expectedSha().");
  return crypto.createHash(SHA_ALGS[alg]).update(str, "utf8").digest("hex");
}

function expectedSha3(alg, str) {
  log.debug("Entering expectedSha3().");
  log.debug("Leaving expectedSha3().");
  return crypto.createHash(SHA3_ALGS[alg]).update(str, "utf8").digest("hex");
}

function expectedShake(alg, str, bits) {
  log.debug("Entering expectedShake().");
  log.debug("Leaving expectedShake().");
  return crypto.createHash(alg.toLowerCase(), { outputLength: bits / 8 })
      .update(str, "utf8").digest("hex");
}

// ===========================================================================
// NIST SP 800-185's own sample values, transcribed from that document's
// appendix.
//
// They are used HERE, in the browser test, rather than only in
// tests/hash_engine.js, and the reason is what a Selenium job can and cannot
// say. There is no cSHAKE, KMAC, TupleHash or ParallelHash in node's crypto
// and none in any browser, so a page driving those four functions has no
// second implementation to be compared against in this process — and
// comparing it against the very library it bundles would assert nothing. A
// published vector is the one reference that is neither. Each case names the
// controls it sets, so a failure says which field stopped being read.
// ===========================================================================
var KMAC_SAMPLE_KEY = "404142434445464748494a4b4c4d4e4f" +
    "505152535455565758595a5b5c5d5e5f";
var SP800185_CASES = [
  { name: "KMAC128 Sample #1", fn: "KMAC128", message: "00010203",
    key: KMAC_SAMPLE_KEY, customization: "", outputBits: "256",
    expected: "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f45" +
        "6ee14e" },
  { name: "KMAC128 Sample #2", fn: "KMAC128", message: "00010203",
    key: KMAC_SAMPLE_KEY, customization: "My Tagged Application",
    outputBits: "256",
    expected: "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811" +
        "324aa5" },
  { name: "KMAC256 Sample #4", fn: "KMAC256", message: "00010203",
    key: KMAC_SAMPLE_KEY, customization: "My Tagged Application",
    outputBits: "512",
    expected: "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a" +
        "68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27" +
        "773a8dd" },
  { name: "cSHAKE256 Sample #3", fn: "cSHAKE256", message: "00010203",
    key: "", customization: "Email Signature", outputBits: "512",
    expected: "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896ee" +
        "e0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c74646952" +
        "7281c8c" },
  { name: "TupleHash128 Sample #2", fn: "TupleHash128",
    message: "000102\n101112131415", key: "",
    customization: "My Tuple App", outputBits: "256",
    expected: "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588" +
        "e96dfb" },
  { name: "ParallelHash128 Sample #2", fn: "ParallelHash128",
    message: "000102030405060710111213141516172021222324252627", key: "",
    customization: "Parallel Data", blockBytes: "8", outputBits: "256",
    expected: "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e49579" +
        "5b7206" }
];

// ===========================================================================
// UI helpers
// ===========================================================================
async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", el);
  await el.click();
  log.debug("Leaving click().");
}

async function setInput(driver, locator, text) {
  log.debug("Entering setInput().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
  log.debug("Leaving setInput().");
}

async function getValue(driver, locator) {
  log.debug("Entering getValue().");
  log.debug("Leaving getValue().");
  return await driver.findElement(locator).getAttribute("value");
}

// Wait until a field's value satisfies pred(value), then return the value.
async function waitForValue(driver, locator, pred, msg, timeout) {
  log.debug("Entering waitForValue().");
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return pred(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  log.debug("Leaving waitForValue().");
  return await getValue(driver, locator);
}

// The inline handlers read "return encoding_tools.<fn>(...)". Match on a
// substring (not the exact attribute) so this keeps working against the
// HTML-minified static build, which strips the trailing ";" from handlers.
function onclickBtn(fn) {
  log.debug("Entering onclickBtn().");
  log.debug("Leaving onclickBtn().");
  return By.xpath("//input[contains(@onclick, \"encoding_tools." + fn +
                  "(\")]");
}

// ===========================================================================
// Per-pane exercises
// ===========================================================================

// Base64 — set a new value, Encode, confirm the encoding, then Decode and
// confirm the decoded value equals the ORIGINAL unencoded input (round-trip).
async function base64Activities(driver) {
  log.debug("Entering base64Activities().");
  var input = "Encode me → café 100% ✓ (Base64 test)";
  var expected = expectedBase64(input);
  log.info("Base64: set a new Unencoded value and click Encode.");
  await setInput(driver, By.id("b64_unencoded"), input);
  await click(driver, onclickBtn("base64Encode"));
  var encoded = await waitForValue(driver, By.id("b64_encoded"),
    function (v) { return v === expected; },
    "Base64 Encode did not produce the expected value.");
  assert.strictEqual(encoded, expected, "Base64 encoded value is incorrect.");
  log.info("Base64 Encode produced the expected value.");

  log.info("Base64: click Decode and confirm it round-trips to the original.");
  // Clear the unencoded box first so we know Decode is what refills it.
  await driver.findElement(By.id("b64_unencoded")).clear();
  await click(driver, onclickBtn("base64Decode"));
  var decoded = await waitForValue(driver, By.id("b64_unencoded"),
    function (v) { return v === input; },
    "Base64 Decode did not round-trip back to the original value.");
  assert.strictEqual(decoded, input,
    "Base64 decoded value does not equal the original unencoded value.");
  log.info("Base64 round-trip verified: decoded value equals the original.");
  log.debug("Leaving base64Activities().");
}

// URI encoding — set a new value, Encode, confirm the encoding, then Decode
// and confirm the round-trip back to the original.
async function uriActivities(driver) {
  log.debug("Entering uriActivities().");
  var input = "state=a b&scope=openid profile/email?x=1#frag";
  var expected = expectedUri(input);
  log.info("URI: set a new Unencoded value and click Encode.");
  await setInput(driver, By.id("uri_unencoded"), input);
  await click(driver, onclickBtn("uriEncode"));
  var encoded = await waitForValue(driver, By.id("uri_encoded"),
    function (v) { return v === expected; },
    "URI Encode did not produce the expected value.");
  assert.strictEqual(encoded, expected, "URI encoded value is incorrect.");
  log.info("URI Encode produced the expected value.");

  log.info("URI: click Decode and confirm it round-trips to the original.");
  await driver.findElement(By.id("uri_unencoded")).clear();
  await click(driver, onclickBtn("uriDecode"));
  var decoded = await waitForValue(driver, By.id("uri_unencoded"),
    function (v) { return v === input; },
    "URI Decode did not round-trip back to the original value.");
  assert.strictEqual(decoded, input,
    "URI decoded value does not equal the original unencoded value.");
  log.info("URI round-trip verified: decoded value equals the original.");
  log.debug("Leaving uriActivities().");
}

// Checksum — set a new value and Encode. A checksum is one-way (no Decode), so
// correctness is verified against an independently computed CRC-32.
async function checksumActivities(driver) {
  log.debug("Entering checksumActivities().");
  var input = "checksum test — CRC-32 of this exact string";
  var expected = expectedCrc32(input);
  log.info("Checksum: set a new Unencoded value and click Encode.");
  await setInput(driver, By.id("checksum_unencoded"), input);
  await click(driver, onclickBtn("checksum"));
  var encoded = await waitForValue(driver, By.id("checksum_encoded"),
    function (v) { return v === expected; },
    "Checksum Encode did not produce the expected CRC-32 value.");
  assert.strictEqual(encoded, expected,
    "CRC-32 checksum does not match the independently computed value.");
  log.info("Checksum verified against independently computed CRC-32: " +
           expected);
  log.debug("Leaving checksumActivities().");
}

// SHA hashing — set a new value, then exercise the Encode button for every
// digest size offered in the dropdown, validating each against Node's crypto.
async function shaActivities(driver) {
  log.debug("Entering shaActivities().");
  var input = "hash me please — SHA test string";
  log.info("SHA: set a new Unencoded value.");
  await setInput(driver, By.id("sha_unencoded"), input);

  var sizeSelect = new Select(driver.findElement(By.id("sha_size")));
  for (var alg in SHA_ALGS) {
    if (!SHA_ALGS.hasOwnProperty(alg)) continue;
    var expected = expectedSha(alg, input);
    log.info("SHA: select " + alg + " and click Encode.");
    await sizeSelect.selectByValue(alg);
    await click(driver, onclickBtn("shaHash"));
    var digest = await waitForValue(driver, By.id("sha_encoded"),
      function (v) { return v === expected; },
      alg + " Encode did not produce the expected digest.");
    assert.strictEqual(digest, expected,
      alg + " digest does not match the independently computed value.");
    log.info(alg + " digest verified (" + digest.length + " hex chars).");
  }
  log.debug("Leaving shaActivities().");
}

// SHA-3 / SHAKE (FIPS 202) — the pane added for the post-quantum standards.
// Every fixed-output function is validated against node's OpenSSL, both
// SHAKEs at two lengths each, and the legacy Keccak option against the
// published pre-FIPS value that is NOT its SHA-3 namesake.
async function sha3Activities(driver) {
  log.debug("Entering sha3Activities().");
  var input = "hash me please — FIPS 202 test string";
  log.info("SHA-3: set a new Unencoded value.");
  await setInput(driver, By.id("sha3_unencoded"), input);

  var algSelect = new Select(driver.findElement(By.id("sha3_alg")));
  for (var alg in SHA3_ALGS) {
    if (!SHA3_ALGS.hasOwnProperty(alg)) continue;
    var expected = expectedSha3(alg, input);
    log.info("SHA-3: select " + alg + " and click Encode.");
    await algSelect.selectByValue(alg);
    await click(driver, onclickBtn("sha3Hash"));
    var digest = await waitForValue(driver, By.id("sha3_encoded"),
      function (v) { return v === expected; },
      alg + " Encode did not produce the expected digest.");
    assert.strictEqual(digest, expected,
      alg + " digest does not match the independently computed value.");
    log.info(alg + " digest verified (" + digest.length + " hex chars).");
  }

  // The output-length field belongs to the extendable-output functions and
  // to nothing else: a box that accepts a value the computation ignores is
  // worse than no box, because it reads as a length that was applied.
  await algSelect.selectByValue("SHA3-256");
  var lengthField = driver.findElement(By.id("sha3_output_bits"));
  assert.ok(!(await lengthField.isEnabled()),
    "The output-length field is enabled for SHA3-256, which has its length " +
        "in its name.");
  for (var shake of ["SHAKE128", "SHAKE256"]) {
    await algSelect.selectByValue(shake);
    assert.ok(await driver.findElement(By.id("sha3_output_bits")).isEnabled(),
      "The output-length field is disabled for " + shake +
          ", which is an extendable-output function.");
    for (var bits of [256, 1024]) {
      var wanted = expectedShake(shake, input, bits);
      log.info("SHAKE: " + shake + " at " + bits + " bits.");
      await setInput(driver, By.id("sha3_output_bits"), String(bits));
      await click(driver, onclickBtn("sha3Hash"));
      var out = await waitForValue(driver, By.id("sha3_encoded"),
        function (v) { return v === wanted; },
        shake + " at " + bits + " bits did not produce the expected output.");
      assert.strictEqual(out, wanted,
        shake + " at " + bits + " bits does not match the independently " +
            "computed value.");
    }
  }

  // Legacy Keccak is NOT SHA-3 — different padding, different digest — and
  // the pane exists to make that visible rather than to hide it.
  log.info("SHA-3: the legacy Keccak option is not SHA3-256.");
  await algSelect.selectByValue("Keccak-256");
  await driver.findElement(By.id("sha3_unencoded")).clear();
  await click(driver, onclickBtn("sha3Hash"));
  var keccakEmpty = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfa" +
      "d8045d85a470";
  var keccak = await waitForValue(driver, By.id("sha3_encoded"),
    function (v) { return v === keccakEmpty; },
    "Keccak-256 of the empty string is not the published pre-FIPS value.");
  assert.strictEqual(keccak, keccakEmpty,
    "The Keccak-256 option is not computing pre-FIPS Keccak.");
  assert.notStrictEqual(keccak, expectedSha3("SHA3-256", ""),
    "The Keccak-256 option produced SHA3-256's digest, so the two paddings " +
        "have been confused.");

  // The notes are half of why these panes exist, so they are asserted like
  // any other output: an empty box beside a digest is a pane that computed
  // something and explained nothing.
  await algSelect.selectByValue("SHAKE128");
  await setInput(driver, By.id("sha3_output_bits"), "4096");
  await click(driver, onclickBtn("sha3Hash"));
  var notes = await waitForValue(driver, By.id("sha3_notes"),
    function (v) { return v.indexOf("capacity 128") > 0; },
    "SHAKE128's notes do not say its security is capped by its capacity.");
  assert.ok(notes.indexOf("FIPS 202") >= 0,
    "SHAKE128's notes do not name FIPS 202.");
  assert.ok(/FIPS 203|FIPS 204/.test(notes),
    "SHAKE128's notes do not say which post-quantum standard uses it.");
  assert.ok(/Grover/.test(notes),
    "SHAKE128's notes say nothing about a quantum attacker.");
  log.info("SHA-3 pane verified, notes included.");
  log.debug("Leaving sha3Activities().");
}

// SP 800-185 — cSHAKE / KMAC / TupleHash / ParallelHash, driven through the
// pane with that document's own sample inputs and compared against its own
// published outputs.
async function sp800185Activities(driver) {
  log.debug("Entering sp800185Activities().");
  var fnSelect = new Select(driver.findElement(By.id("sp185_fn")));
  for (var i = 0; i < SP800185_CASES.length; i++) {
    var c = SP800185_CASES[i];
    log.info("SP 800-185: " + c.name + ".");
    await fnSelect.selectByValue(c.fn);
    await setInput(driver, By.id("sp185_message"), c.message);
    if (c.key) {
      await setInput(driver, By.id("sp185_key"), c.key);
    }
    await setInput(driver, By.id("sp185_customization"),
                   c.customization || "");
    if (c.blockBytes) {
      await setInput(driver, By.id("sp185_block_bytes"), c.blockBytes);
    }
    await setInput(driver, By.id("sp185_output_bits"), c.outputBits);
    await click(driver, onclickBtn("sp185Compute"));
    var expected = c.expected;
    var out = await waitForValue(driver, By.id("sp185_encoded"),
      function (v) { return v === expected; },
      c.name + " did not produce the value published in SP 800-185.");
    assert.strictEqual(out, expected,
      c.name + " does not match the value published in SP 800-185.");
    log.info(c.name + " verified against NIST's own sample value.");
  }

  // A key belongs to KMAC and to nothing else; N belongs to cSHAKE and to
  // nothing else; B belongs to ParallelHash. A field the selected function
  // does not read has to SAY it is not read, or its value looks applied.
  log.info("SP 800-185: the inapplicable argument fields are disabled.");
  await fnSelect.selectByValue("cSHAKE128");
  assert.ok(!(await driver.findElement(By.id("sp185_key")).isEnabled()),
    "The key field is enabled for cSHAKE128, which takes no key.");
  assert.ok(
    await driver.findElement(By.id("sp185_function_name")).isEnabled(),
    "The function-name field is disabled for cSHAKE, the one function whose " +
        "N is an argument.");
  await fnSelect.selectByValue("KMAC128");
  assert.ok(await driver.findElement(By.id("sp185_key")).isEnabled(),
    "The key field is disabled for KMAC128, which needs one.");
  assert.ok(
    !(await driver.findElement(By.id("sp185_function_name")).isEnabled()),
    "The function-name field is enabled for KMAC, which fixes its own N.");
  assert.ok(
    !(await driver.findElement(By.id("sp185_block_bytes")).isEnabled()),
    "The block-size field is enabled for KMAC, which has no blocks.");
  await fnSelect.selectByValue("ParallelHash128");
  assert.ok(await driver.findElement(By.id("sp185_block_bytes")).isEnabled(),
    "The block-size field is disabled for ParallelHash, whose answer " +
        "depends on it.");

  var notes = await getValue(driver, By.id("sp185_notes"));
  assert.ok(notes.indexOf("SP 800-185") >= 0,
    "The SP 800-185 pane's notes do not name the document.");
  log.info("SP 800-185 pane verified against six published sample values.");
  log.debug("Leaving sp800185Activities().");
}

// Exercise every Copy button on the page. Clipboard access is unreliable in
// headless Chrome, and the page's copyField() swallows any such error, so this
// only confirms the buttons are present and clickable (no assertion on the
// clipboard contents).
async function copyButtonActivities(driver) {
  log.debug("Entering copyButtonActivities().");
  var copyButtons = await driver.findElements(By.css(".et-copy"));
  assert.ok(copyButtons.length >= 16,
    "Expected at least 16 Copy buttons (one per value box across the six " +
        "panes), found " + copyButtons.length + ".");
  log.info("Clicking all " + copyButtons.length + " Copy buttons.");
  for (var i = 0; i < copyButtons.length; i++) {
    try {
      await driver.executeScript("arguments[0].click();", copyButtons[i]);
    } catch (e) {
      log.warn("Copy button " + i + " click issue (ignored): " + e.message);
    }
  }
  log.info("All Copy buttons exercised.");
  log.debug("Leaving copyButtonActivities().");
}

// Confirm the page's onload seeded every Unencoded field and auto-ran each
// Encode/hash so the Encoded fields are populated on first load.
async function defaultsOnLoad(driver) {
  log.debug("Entering defaultsOnLoad().");
  log.info("Verify default values are populated on load.");
  await waitForValue(driver, By.id("b64_encoded"),
    function (v) { return v.length > 0; },
    "Base64 Encoded field was not auto-populated on load.");
  await waitForValue(driver, By.id("uri_encoded"),
    function (v) { return v.length > 0; },
    "URI Encoded field was not auto-populated on load.");
  await waitForValue(driver, By.id("checksum_encoded"),
    function (v) { return v.length > 0; },
    "Checksum Encoded field was not auto-populated on load.");
  await waitForValue(driver, By.id("sha_encoded"),
    function (v) { return v.length > 0; },
    "SHA Encoded field was not auto-populated on load.");
  // The FIPS 202 pane is seeded with "abc" — the input that document's own
  // examples use — so the digest on screen at load is one a reader can look
  // up rather than a value only this code can produce.
  var sha3Default = await waitForValue(driver, By.id("sha3_encoded"),
    function (v) { return v.length > 0; },
    "SHA-3 Encoded field was not auto-populated on load.");
  assert.strictEqual(sha3Default, expectedSha3("SHA3-256", "abc"),
    "The SHA-3 pane does not load holding SHA3-256(\"abc\").");
  // ...and the SP 800-185 pane is seeded with KMAC Sample #1, whose expected
  // output is printed in that document. If the page loads holding the wrong
  // value, everything below it is being computed wrongly too.
  var kmacDefault = await waitForValue(driver, By.id("sp185_encoded"),
    function (v) { return v.length > 0; },
    "SP 800-185 Result field was not auto-populated on load.");
  assert.strictEqual(kmacDefault, SP800185_CASES[0].expected,
    "The SP 800-185 pane does not load holding KMAC Sample #1's published " +
        "value.");
  log.info("All Encoded fields populated on load, and the two hashing " +
           "panes hold the specifications' own sample values.");
  log.debug("Leaving defaultsOnLoad().");
}

async function encodingToolsActivities(driver) {
  log.debug("Entering encodingToolsActivities().");
  log.info("Open the Encoding / Hashing Tools page via the debugger " +
           "Tools pane.");
  await driver.get(baseUrl + "/oauth2_oidc_1.html");
  await click(driver, By.id("tools_expand_button"));
  var link = By.css('a[href="/encoding_tools.html?from=oauth2_oidc_1.html"]');
  await driver.wait(until.elementLocated(link), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(link)), waitTime);
  await click(driver, link);

  log.info("Wait for the Encoding / Hashing Tools page to load.");
  await waitForValue(driver, By.id("sha_unencoded"),
    function (v) { return v.length > 0; },
    "Encoding / Hashing Tools page did not load / defaults not populated.");

  await defaultsOnLoad(driver);
  await base64Activities(driver);
  await uriActivities(driver);
  await checksumActivities(driver);
  await shaActivities(driver);
  await sha3Activities(driver);
  await sp800185Activities(driver);
  await copyButtonActivities(driver);
  log.debug("Leaving encodingToolsActivities().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "new" headless honors the --unsafely-treat-insecure-origin-as-secure
    // override below, which is what makes crypto.subtle (Web Crypto, used by
    // SHA hashing) available on the non-localhost containerized origin.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // NO SECURE-ORIGIN OVERRIDE, DELIBERATELY, AND THIS IS AN ASSERTION.
  //
  // This job used to pass --unsafely-treat-insecure-origin-as-secure for the
  // debugger origin, because the SHA pane hashed with crypto.subtle and Web
  // Crypto exists only in a secure context: http://localhost is one, but the
  // containerized runs serve the client at http://client:3000, which is not,
  // and the pane silently had no cryptography there. Adding the FIPS 202 pane
  // ended that — Web Crypto has no SHA-3 in any browser, so the whole page
  // moved to client/src/hash_tools.js, which is pure JavaScript. Running
  // WITHOUT the override is what holds it that way: on the containerized
  // stack this test now fails if anything on this page reaches for
  // crypto.subtle again. Do not add the flag back to fix such a failure.
  // Date.now() alone is NOT unique: run-report.js runs jobs in a pool,
  // and two starting in the same millisecond would share a profile —
  // one Chrome then refuses to start on the other's. See CONCURRENCY
  // in run-report.js.
  options.addArguments("--user-data-dir=/tmp/encoding-tools-chrome-" +
                       Date.now() + "-" + process.pid);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  // process.exit() is synchronous termination, so it would skip the finally
  // below and orphan the browser — and one headless Chrome is ~15 processes,
  // which is how a run of this suite once left 559 of them on the machine.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await encodingToolsActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('encoding_tools')
  .description("Run Encoding / Hashing Tools UI test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
