// File: algorithm_panes.js
//
// EVERY ALGORITHM IN THE JWT TOOLS AND ENCRYPTION PANES, EXERCISED IN A
// BROWSER — not merely present in the menu.
//
// `algorithm_menus.js` proves the OPTION exists and matches the engine. That
// is a different claim from the option working: a `<select>` can offer an
// algorithm the page then fails to wire up, and the failure is a status line
// nobody reads in a test that never selected it. On 2026-08-28 the JWT Tools
// signing menu offered thirteen of twenty-seven and the Encryption page's JWE
// pane three of six content encryptions, so the menus were widened — and a
// widened menu with nothing driving it is a promise of the same kind this
// suite keeps finding broken elsewhere.
//
// THE ENGINES ARE NOT WHAT IS UNDER TEST HERE. `jws_engine.js` drives all
// twenty-seven signature algorithms and `jose_jwe_encryption.js` all
// thirty-six alg/enc pairs, both in node against RFC vectors and OpenSSL. What
// only a browser can show is the WIRING: that choosing an option generates a
// key of the right kind, signs with it, and puts something back on the page.
//
// SLH-DSA-SHAKE-128s IS DRIVEN LIKE THE REST AND IS THE REASON THIS JOB IS NOT
// FASTER: that parameter set is the small-signature, slow-signing one and
// costs about twelve seconds for a single signature. It is kept because a
// twelve-second option that silently stopped working would look exactly like a
// slow one.

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "algorithm_panes",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";

// The options a `<select>` offers, read from the live page rather than from
// the source — this job is about what a person can actually choose.
async function optionsOf(driver, id) {
  log.debug("Entering optionsOf(). id=" + id);
  var values = await driver.executeScript(
    "var s = document.getElementById(arguments[0]);" +
    "return s ? Array.prototype.slice.call(s.options).map(function (o) {" +
    "  return { value: o.value, disabled: !!o.disabled }; }) : null;", id);
  assert.ok(values && values.length,
    "no <select id=\"" + id + "\"> with options on this page.");
  log.debug("Leaving optionsOf(). " + values.length + " option(s).");
  return values;
}

// NOTHING MAY BE DISABLED. The capability probe used to grey out the AES-192
// options because Chrome's Web Crypto refuses that size; jose_jwe.js performs
// them in JavaScript now, and an option this tool can perform must never be
// unselectable. See the note at encUnsupportedReason().
function assertNothingDisabled(options, id) {
  log.debug("Entering assertNothingDisabled().");
  var disabled = options.filter(function (o) { return o.disabled; })
    .map(function (o) { return o.value; });
  assert.strictEqual(disabled.length, 0,
    id + " has disabled option(s): " + disabled.join(", ") +
    ". Every algorithm these pages offer is one they can perform — in " +
    "JavaScript where the browser will not — so nothing here may be greyed " +
    "out. That greying is what hid three registered JOSE algorithms until " +
    "2026-08-28.");
  log.debug("Leaving assertNothingDisabled().");
}

async function everyJwtToolsSignatureWorks(driver) {
  log.debug("Entering everyJwtToolsSignatureWorks().");
  await driver.get(baseUrl + "/jwt_tools.html");
  await driver.wait(until.elementLocated(By.id("sign_alg")), 20000);
  var options = await optionsOf(driver, "sign_alg");
  assertNothingDisabled(options, "sign_alg");

  var signed = 0;
  for (var i = 0; i < options.length; i++) {
    var alg = options[i].value;
    var result = await driver.executeAsyncScript(
      "var done = arguments[arguments.length - 1];" +
      "document.getElementById('sign_alg').value = arguments[0];" +
      // CLEARED FIRST, and this is not housekeeping. signJWT() leaves the
      // PREVIOUS token in place when it fails, so a stale one from the
      // algorithm before reads as a three-part JWS and the assertion passes
      // for an algorithm that did not work at all. This test did exactly that
      // on its first run and reported RS256's token as EdDSA-Ed25519's.
      "document.getElementById('jwt_tools_encoded').value = '';" +
      "Promise.resolve(jwt_tools.generateSigningKeys())" +
      "  .then(function () { return jwt_tools.signJWT(); })" +
      "  .then(function () {" +
      "    var t = document.getElementById('jwt_tools_encoded').value;" +
      "    done({ token: t," +
      "           status: (document.getElementById('sign_status') || {})" +
      "             .value || '' });" +
      "  }, function (e) { done({ error: e.message }); });", alg);
    assert.ok(!result.error,
      alg + ": signing threw in the page: " + result.error);
    assert.ok(result.token && result.token.split(".").length === 3,
      alg + ": choosing this algorithm must produce a three-part JWS. The " +
      "page said: " + String(result.status).slice(0, 200));
    // The header must name the algorithm that was chosen — except for the two
    // Edwards curves, which share the registered value `EdDSA` because RFC
    // 8037 puts the curve in the key rather than in the header.
    var header = JSON.parse(Buffer.from(result.token.split(".")[0],
      "base64url").toString("utf8"));
    var expected = alg.indexOf("EdDSA") === 0 ? "EdDSA" : alg;
    if (alg !== "none") {
      assert.strictEqual(header.alg, expected,
        alg + ": the header must name the REGISTERED algorithm (" + expected +
        "), not the engine's internal identifier.");
    }
    signed++;
  }
  log.info("[jwt tools] OK — all " + signed + " signature algorithm(s) sign " +
           "in the page and name the registered alg in the header.");
  log.debug("Leaving everyJwtToolsSignatureWorks().");
}

async function everyEncryptionPaneCombinationWorks(driver) {
  log.debug("Entering everyEncryptionPaneCombinationWorks().");
  await driver.get(baseUrl + "/encryption_tools.html");
  await driver.wait(until.elementLocated(By.id("enc_jwe_enc")), 20000);
  // The capability probe is asynchronous, and reading the menu before it has
  // settled would assert on a page that has not finished deciding.
  await driver.sleep(2000);
  var algs = await optionsOf(driver, "enc_jwe_alg");
  var encs = await optionsOf(driver, "enc_jwe_enc");
  assertNothingDisabled(algs, "enc_jwe_alg");
  assertNothingDisabled(encs, "enc_jwe_enc");

  var pairs = 0;
  for (var a = 0; a < algs.length; a++) {
    for (var e = 0; e < encs.length; e++) {
      var alg = algs[a].value;
      var enc = encs[e].value;
      var result = await driver.executeAsyncScript(
        "var done = arguments[arguments.length - 1];" +
        "document.getElementById('enc_jwe_alg').value = arguments[0];" +
        "document.getElementById('enc_jwe_enc').value = arguments[1];" +
        "document.getElementById('enc_jwe_plaintext').value = " +
            "'{\"claim\":\"round-trip\"}';" +
        "Promise.resolve(encryption_tools.jweGenerateKeys())" +
        // The key fields are filled asynchronously; encrypting before they
        // are populated fails in a way that names the key and not the timing.
        "  .then(function () {" +
        "    return new Promise(function (r) { setTimeout(r, 400); }); })" +
        "  .then(function () { return encryption_tools.jweEncrypt(); })" +
        "  .then(function () { return encryption_tools.jweDecrypt(); })" +
        "  .then(function () {" +
        "    done({ jwe: document.getElementById('enc_jwe_ciphertext').value," +
        "           plaintext: document.getElementById('enc_jwe_plaintext')" +
        "             .value," +
        "           status: document.getElementById('enc_jwe_status')" +
        "             .value });" +
        "  }, function (err) { done({ error: err.message }); });", alg, enc);
      assert.ok(!result.error,
        alg + "/" + enc + ": the pane threw: " + result.error);
      assert.strictEqual(String(result.jwe).split(".").length, 5,
        alg + "/" + enc + ": a compact JWE has five segments. The page said: " +
        String(result.status).slice(0, 200));
      assert.ok(result.plaintext.indexOf("round-trip") !== -1,
        alg + "/" + enc + ": the decrypted plaintext should be what was " +
        "encrypted; the pane holds " +
        String(result.plaintext).slice(0, 120));
      pairs++;
    }
  }
  log.info("[encryption] OK — all " + pairs + " alg/enc pair(s) encrypt and " +
           "decrypt in the page, including the AES-192 sizes Chrome's Web " +
           "Crypto refuses.");
  log.debug("Leaving everyEncryptionPaneCombinationWorks().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. url=" + baseUrl);
  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options().addArguments("--headless=new",
    "--no-sandbox", "--disable-dev-shm-usage");
  // THE ORIGIN THIS PAGE IS SERVED FROM MUST BE TREATED AS SECURE, and there
  // is no `browserFlags.chromeOptions()` to do it — that name was never
  // exported, so the `?:` this replaced ALWAYS took its else branch and built
  // a plain Chrome with none of the flags. On a host run that is invisible:
  // the base url is http://localhost:3000, and localhost is potentially
  // trustworthy all by itself, so `crypto.subtle` exists and every algorithm
  // here signs. In the containerized run the client is http://client:3000,
  // which is not, so `crypto.subtle` is UNDEFINED and the first signature the
  // page attempts fails with
  //
  //   HS256: ... The page said: Error: Cannot read properties of undefined
  //       (reading 'importKey')
  //
  // naming HS256 and importKey and nothing about the origin. See
  // tests/CLAUDE.md on the secure-context hazard, and addBrowserAccessFlags().
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  // EdDSA is one of the twenty-seven signature algorithms this job drives, and
  // the containerized Chrome refuses `Ed25519` to importKey without this.
  browserFlags.addWebCryptoEd25519Flags(options);
  options.setLoggingPrefs(prefs);
  var driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  try {
    await everyJwtToolsSignatureWorks(driver);
    await everyEncryptionPaneCombinationWorks(driver);
    var entries = await driver.manage().logs().get(logging.Type.BROWSER);
    var severe = entries.filter(function (entry) {
      return entry.level.name === "SEVERE" &&
        !browserFlags.isTransientLoadError(entry.message);
    });
    assert.strictEqual(severe.length, 0,
      "every operation here is one the page is expected to perform, so the " +
      "console must be clean; got " + severe.length + ": " +
      severe.map(function (e) { return e.message; }).join(" | ")
        .slice(0, 400));
    log.info("[console] OK — no SEVERE entries.");
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("algorithm_panes")
  .description("Every algorithm the JWT Tools and Encryption panes offer is " +
      "exercised in a browser, not merely listed.")
  .addOption(new Option("-u, --url <url>", "base url of the client"))
  .parse(process.argv);
if (program.opts().url) {
  baseUrl = program.opts().url;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
