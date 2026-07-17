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
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// SHA hashing runs through the Web Crypto API (crypto.subtle) which, though
// fast, can exceed the short element-wait on a busy CI host — give the async
// results a separate, generous timeout.
var cryptoWait = Math.max(waitTime, 15000);

// ===========================================================================
// Independent reference implementations — the test computes the expected
// output itself (never trusts the page to grade its own answer).
// ===========================================================================
function expectedBase64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

function expectedUri(str) {
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
  var bytes = Buffer.from(str, "utf8");
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
  }
  crc = (crc ^ 0xFFFFFFFF) >>> 0;
  return ("0000000" + crc.toString(16)).slice(-8);
}

// Map the page's SHA algorithm labels to Node's crypto hash names.
var SHA_ALGS = {
  "SHA-1": "sha1",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

function expectedSha(alg, str) {
  return crypto.createHash(SHA_ALGS[alg]).update(str, "utf8").digest("hex");
}

// ===========================================================================
// UI helpers
// ===========================================================================
async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}

async function setInput(driver, locator, text) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await el.clear();
  await el.sendKeys(text);
}

async function getValue(driver, locator) {
  return await driver.findElement(locator).getAttribute("value");
}

// Wait until a field's value satisfies pred(value), then return the value.
async function waitForValue(driver, locator, pred, msg, timeout) {
  await driver.wait(async function () {
    try {
      var v = await driver.findElement(locator).getAttribute("value");
      return pred(v || "");
    } catch (e) {
      return false;
    }
  }, timeout || cryptoWait, msg);
  return await getValue(driver, locator);
}

// The inline handlers read "return encoding_tools.<fn>(...)". Match on a
// substring (not the exact attribute) so this keeps working against the
// HTML-minified static build, which strips the trailing ";" from handlers.
function onclickBtn(fn) {
  return By.xpath("//input[contains(@onclick, \"encoding_tools." + fn + "(\")]");
}

// ===========================================================================
// Per-pane exercises
// ===========================================================================

// Base64 — set a new value, Encode, confirm the encoding, then Decode and
// confirm the decoded value equals the ORIGINAL unencoded input (round-trip).
async function base64Activities(driver) {
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
}

// URI encoding — set a new value, Encode, confirm the encoding, then Decode
// and confirm the round-trip back to the original.
async function uriActivities(driver) {
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
}

// Checksum — set a new value and Encode. A checksum is one-way (no Decode), so
// correctness is verified against an independently computed CRC-32.
async function checksumActivities(driver) {
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
  log.info("Checksum verified against independently computed CRC-32: " + expected);
}

// SHA hashing — set a new value, then exercise the Encode button for every
// digest size offered in the dropdown, validating each against Node's crypto.
async function shaActivities(driver) {
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
}

// Exercise every Copy button on the page. Clipboard access is unreliable in
// headless Chrome, and the page's copyField() swallows any such error, so this
// only confirms the buttons are present and clickable (no assertion on the
// clipboard contents).
async function copyButtonActivities(driver) {
  var copyButtons = await driver.findElements(By.css(".et-copy"));
  assert.ok(copyButtons.length >= 8,
    "Expected at least 8 Copy buttons (2 per pane), found " + copyButtons.length + ".");
  log.info("Clicking all " + copyButtons.length + " Copy buttons.");
  for (var i = 0; i < copyButtons.length; i++) {
    try {
      await driver.executeScript("arguments[0].click();", copyButtons[i]);
    } catch (e) {
      log.warn("Copy button " + i + " click issue (ignored): " + e.message);
    }
  }
  log.info("All Copy buttons exercised.");
}

// Confirm the page's onload seeded every Unencoded field and auto-ran each
// Encode/hash so the Encoded fields are populated on first load.
async function defaultsOnLoad(driver) {
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
  log.info("All Encoded fields populated on load.");
}

async function encodingToolsActivities(driver) {
  log.info("Open the Encoding / Hashing Tools page via the debugger Tools pane.");
  await driver.get(baseUrl + "/debugger.html");
  await click(driver, By.id("tools_expand_button"));
  var link = By.css('a[href="/encoding_tools.html?from=debugger.html"]');
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
  await copyButtonActivities(driver);
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    // "new" headless honors the --unsafely-treat-insecure-origin-as-secure
    // override below, which is what makes crypto.subtle (Web Crypto, used by
    // SHA hashing) available on the non-localhost containerized origin.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  // SHA hashing uses the Web Crypto API (crypto.subtle), exposed by browsers
  // only in a "secure context". http://localhost is treated as secure, but the
  // containerized runs serve the client at http://client:3000 (non-secure),
  // where crypto.subtle would be undefined. Treat the debugger origin as
  // trustworthy so crypto.subtle is available. (Only takes effect with a
  // --user-data-dir also set.)
  var secureOrigin = baseUrl.replace(/\/+$/, "");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + secureOrigin);
  options.addArguments("--user-data-dir=/tmp/encoding-tools-chrome-" + Date.now());
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await encodingToolsActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
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
