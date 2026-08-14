// File: webauthn_analyzer_page.js
//
// ---------------------------------------------------------------------------
// The WebAuthn Analyzer page (webauthn_analyzer.html) driven in a browser.
//
// Named `_page` on purpose. `client/src/webauthn_analyzer.js` is a bundle
// source, and the tests image copies borrowed client modules FLAT beside the
// test scripts — so a test called `webauthn_analyzer.js` would collide with it
// exactly as `tests/jwk_pem.js` collided with `client/src/jwk_pem.js`, where
// the module silently replaced the test and the job passed having run nothing.
// Same trap, avoided by name. See tests/jwk_pem_encoding.js.
//
// What this covers that tests/webauthn_decode.js cannot: that the PAGE puts the
// decoded values on the screen. The node test proves the arithmetic; this
// proves the arithmetic reaches the user, which is a different failure — a pane
// that stays empty because an element id was renamed decodes perfectly and
// shows nothing.
//
// The artifacts are the same real ceremonies the node test uses
// (tests/webauthn_vectors.json), so no authenticator, no IdP and no network are
// needed. This page performs no ceremony, which is the whole point of the mode:
// it therefore does not even need a secure context.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_analyzer_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, "webauthn_vectors.json"), "utf8"));

// The toJSON() shape the page accepts, built from a vector. Chrome 121 has no
// toJSON(), so the vectors hold the pieces and this assembles the same object a
// newer browser would have produced — which is also exactly what the shim in
// client/src/webauthn.js will have to emit.
function asCredentialJson(vector, ceremony) {
  log.debug("Entering asCredentialJson().");
  const response = ceremony === "create"
    ? { clientDataJSON: vector.clientDataJSON,
        attestationObject: vector.attestationObject,
        transports: vector.oracle ? vector.oracle.transports : undefined }
    : { clientDataJSON: vector.clientDataJSON,
       authenticatorData: vector.authenticatorData,
        signature: vector.signature, userHandle: vector.userHandle ||
            undefined };
  log.debug("Leaving asCredentialJson().");
  return JSON.stringify({
    id: vector.id, rawId: vector.rawId, type: "public-key",
    authenticatorAttachment: vector.authenticatorAttachment,
    clientExtensionResults: vector.clientExtensionResults || {},
    response: response,
  }, null, 2);
}

async function setValue(driver, id, text) {
  log.debug("Entering setValue().");
  const field = await driver.findElement(By.id(id));
  await driver.executeScript("arguments[0].value = '';", field);
  // sendKeys on a 1.5KB base64url blob is slow and flaky; set it and fire the
  // event the page would have seen. The page reads .value on click, so this is
  // the same state a paste produces.
  await driver.executeScript(
    "arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new " +
        "Event('input'));",
    field, text);
  log.debug("Leaving setValue().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf().");
  const els = await driver.findElements(By.id(id));
  if (!els.length) {
    log.debug("Leaving textOf().");
    return null;
  }
  log.debug("Leaving textOf().");
  return (await els[0].getText()).trim();
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf().");
  const els = await driver.findElements(By.id(id));
  if (!els.length) {
    log.debug("Leaving valueOf().");
    return null;
  }
  log.debug("Leaving valueOf().");
  return (await els[0].getAttribute("value")) || "";
}

// Wait for CONTENT rather than for an element: every pane on this page is
// static markup that exists during parsing and says nothing about whether the
// decode has run. See tests/wait_for.js for why this rule exists.
async function waitForText(driver, id, predicate, what) {
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = (await textOf(driver, id)) || "";
      return predicate(last);
    }, waitTime * 4);
  } catch (e) {
    throw new Error(what + " — #" + id + " holds: \"" + last.slice(0, 300) +
                    "\"");
  }
  log.debug("Leaving waitForText().");
  return last;
}

let failures = 0;
async function section(name, fn) {
  log.debug("Entering section().");
  try {
    const detail = await fn();
    log.info("PASS  " + name + (detail ? " — " + detail : ""));
  } catch (e) {
    failures++;
    log.error("FAIL  " + name + " — " + (e && e.message ? e.message : e));
  }
  log.debug("Leaving section().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  // This page needs no secure context of its own, but it does run Web Crypto
  // for the signature check, and on the containerized origin crypto.subtle is
  // undefined without these. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).setLoggingPrefs(prefs).build();

  try {
    await driver.get(baseUrl + "/webauthn_analyzer.html");
    await driver.wait(until.elementLocated(By.id("wa_input")), waitTime * 4);
    await driver.executeScript("localStorage.clear();");
    await driver.navigate().refresh();
    await driver.wait(until.elementLocated(By.id("wa_input")), waitTime * 4);

    await section("a registration decodes onto the page", async () => {
      await setValue(driver, "wa_input",
                     asCredentialJson(VECTORS.es256_registration, "create"));
      await driver.findElement(By.id("wa_analyze_button")).click();

      const authData = await waitForText(driver, "wa_authdata_body",
        (t) => /sign count/i.test(t),
         "the authenticator data pane never filled");
      assert.ok(/AAGUID/.test(authData),
                "the AAGUID should be shown for a registration");
      assert.ok(/UP ✓/.test(authData), "UP should be shown as set");
      assert.ok(/AT ✓/.test(authData), "AT should be set on a registration");

      const cose = await waitForText(driver, "wa_cose_body",
        (t) => /jwk\.kty/.test(t), "the COSE key pane never filled");
      assert.ok(/ES256/.test(cose), "the algorithm should be named: " +
                cose.slice(0, 120));

      const pem = await valueOf(driver, "wa_cose_pem");
      assert.ok(/^-----BEGIN PUBLIC KEY-----/.test(pem),
        "the SPKI PEM should be rendered; got: " + pem.slice(0, 60));

      const att = await waitForText(driver, "wa_attestation_body",
        (t) => /fmt/.test(t), "the attestation pane never filled");
      assert.ok(/packed/.test(att), "the attestation format should be shown");

      const cd = await waitForText(driver, "wa_clientdata_body",
        (t) => /webauthn\.create/.test(t), "the client data pane never filled");
      assert.ok(/http:\/\/localhost:3199/.test(cd),
                "the origin should be shown");
      return "flags, AAGUID, COSE key, PEM, attestation and client data all on screen";
    });

    await section("an assertion verifies against the key kept from that " +
                  "registration", async () => {
      await setValue(driver, "wa_input",
                     asCredentialJson(VECTORS.es256_assertion, "get"));
      // The expectations are the relying party's; supply the real ones.
      await setValue(driver, "wa_expect_challenge",
        Buffer.from(Uint8Array.from([0xca, 0xfe, 0xba,
                    0xbe].concat(Array(28).fill(0x22))))
          .toString("base64").replace(/\+/g, "-").replace(/\//g,
              "_").replace(/=+$/, ""));
      await setValue(driver, "wa_expect_origin", "http://localhost:3199");
      await setValue(driver, "wa_expect_rpid", "localhost");
      await driver.findElement(By.id("wa_analyze_button")).click();

      const verdict = await waitForText(driver, "wa_verify_status",
        (t) => /VALID|NOT VALID/.test(t),
         "the verification pane never reported a verdict");
      assert.ok(/^VALID/.test(verdict), "the assertion should verify: " +
                verdict);

      const checks = await textOf(driver, "wa_verify_body");
      assert.ok(/signature verifies/.test(checks),
                "the signature check should be listed");
      // The public key was never pasted — it came from the registration above.
      const key = await valueOf(driver, "wa_public_key");
      assert.ok(/"kty"/.test(key),
        "the credential public key should have been recalled from the " +
            "registration, not pasted");
      return verdict;
    });

    await section("a tampered signature is reported as exactly that",
                  async () => {
      const bad = JSON.parse(asCredentialJson(VECTORS.es256_assertion, "get"));
      // Flip one base64url character in the signature.
      const sig = bad.response.signature;
      bad.response.signature = sig.slice(0, 8) + (sig[8] === "A" ? "B" : "A") +
          sig.slice(9);
      await setValue(driver, "wa_input", JSON.stringify(bad, null, 2));
      await driver.findElement(By.id("wa_analyze_button")).click();

      const verdict = await waitForText(driver, "wa_verify_status",
        (t) => /NOT VALID/.test(t),
         "a tampered signature should have produced a NOT VALID verdict");
      const checks = await textOf(driver, "wa_verify_body");
      assert.ok(/✗.*signature verifies/.test(checks),
        "the signature check should be the one marked failed: " +
            checks.slice(0, 200));
      assert.ok(!/✗.*challenge matches/.test(checks),
        "and nothing else should be marked failed — the pane must name the " +
            "right cause");
      return verdict;
    });

    await section("a UV-clear assertion fails on the flag, with the " +
                  "signature still valid", async () => {
      // The registration first, so its key is remembered.
      await setValue(driver, "wa_input",
                     asCredentialJson(VECTORS.uv_clear_registration, "create"));
      await driver.findElement(By.id("wa_analyze_button")).click();
      await waitForText(driver, "wa_cose_body", (t) => /jwk\.kty/.test(t),
        "the UV-clear registration did not decode");

      await setValue(driver, "wa_input",
                     asCredentialJson(VECTORS.uv_clear_assertion, "get"));
      await setValue(driver, "wa_public_key", "");
      const uv = await driver.findElement(By.id("wa_expect_uv"));
      if (!(await uv.isSelected())) {
        await uv.click();
      }
      await driver.findElement(By.id("wa_analyze_button")).click();

      await waitForText(driver, "wa_verify_status", (t) => /NOT VALID/.test(t),
        "UV was required and not performed, so the verdict should be " +
            "NOT VALID");
      const checks = await textOf(driver, "wa_verify_body");
      assert.ok(/✗.*user verification/.test(checks),
        "the UV check should be the failure: " + checks.slice(0, 200));
      assert.ok(/✓.*signature verifies/.test(checks),
        "and the SIGNATURE must still be shown as valid — reporting a bad " +
            "signature here would " +
        "send the user after the wrong problem entirely");
      return "UV ✗, signature ✓";
    });

    await section("nonsense input is refused by name, not by silence",
                  async () => {
      await setValue(driver, "wa_input", "this is not json");
      await driver.findElement(By.id("wa_analyze_button")).click();
      const st = await waitForText(driver, "wa_input_status", (t) =>
          t.length > 0,
        "pasting nonsense produced no message at all");
      assert.ok(/not JSON/i.test(st),
                "the message should say what was wrong: " + st);
      return st.slice(0, 60);
    });

    await section("no pane overflows its box", async () => {
      await setValue(driver, "wa_input",
                     asCredentialJson(VECTORS.rs256_registration, "create"));
      await driver.findElement(By.id("wa_analyze_button")).click();
      await waitForText(driver, "wa_cose_body", (t) => /jwk\.n/.test(t),
        "the RSA key never rendered");
      // An RSA modulus is the longest unbreakable string this page will ever
      // hold; if anything is going to push out of its pane it is this.
      const m = await driver.executeScript(
        "var doc = document.documentElement;" +
        "var worst = 0, id = null;" +
        "Array.prototype.slice.call(document.querySelectorAll('.wa-pane')).forEach(function (p) {" +
        "  var pr = p.getBoundingClientRect();" +
        "  Array.prototype.slice.call(p.querySelectorAll('*')).forEach(function (e) {" +
        "    var r = e.getBoundingClientRect();" +
        "    if (r.width && Math.round(r.right - pr.right) > worst) {" +
        "      worst = Math.round(r.right - pr.right); id = e.id || " +
            "e.className; }" +
        "  });" +
        "});" +
        "return { worst: worst, id: id, sideways: doc.scrollWidth > " +
            "doc.clientWidth + 2 };");
      assert.ok(m.worst <= 2,
        "content escapes its pane by " + m.worst + "px (" + m.id +
            "). A table holding base64url " +
        "sizes itself to its longest line unless it is table-layout: fixed " +
            "with overflow-wrap.");
      assert.strictEqual(m.sideways, false,
                         "and the page must not scroll sideways.");
      return "worst overhang " + m.worst + "px, no sideways scroll";
    });

    const severe = (await driver.manage().logs().get(logging.Type.BROWSER))
      .filter((e) => e.level.name === "SEVERE");
    assert.strictEqual(severe.length, 0,
      "the page logged browser errors:\n" + severe.map((e) =>
          e.message).join("\n"));
    log.info("PASS  no console errors");

    if (failures) {
      log.error(failures + " section(s) failed.");
      process.exitCode = 1;
      log.debug("Leaving test().");
      return;
    }
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exitCode = 1;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("webauthn_analyzer_page")
  .description("Drive the WebAuthn Analyzer page against real ceremony " +
      "artifacts.")
  .addOption(new Option("-u, --url <url>",
      "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser."))
  .action((options) => {
    if (options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (options.browser) {
      headless = false;
    }
  });
program.parse(process.argv);

test();
