// File: webauthn_lab_page.js
//
// ---------------------------------------------------------------------------
// The WebAuthn Lab page (webauthn.html) driving REAL ceremonies against the
// WebDriver virtual authenticator.
//
// Named `_page` for the same reason webauthn_analyzer_page.js is: the tests
// image copies borrowed client modules flat beside the test scripts, and a test
// sharing a bundle's basename gets silently replaced by it. That is not
// hypothetical — it had disabled the jwk_pem job entirely. See
// tests/jwk_pem_encoding.js.
//
// **The virtual authenticator is the mock smart card.**
// `addVirtualAuthenticator` is a WebDriver-standard command backed by Chrome's
// CDP WebAuthn domain: a CTAP2 authenticator with configurable user
// verification, resident-key support and transports, entirely in the browser.
// No hardware, no touch, deterministic, headless. Its knobs are what make the
// negatives possible — `setIsUserVerified` and `setHasUserVerification` produce
// a genuine UV-clear ceremony, and `removeAllCredentials` produces the
// no-credential path.
//
// Two things measured on 2026-08-08 that shape this file. The JS bindings'
// VirtualAuthenticatorOptions setters return **undefined**, unlike the Java
// ones, so they cannot be chained — and the failure is not "no authenticator"
// but `NotAllowedError: WebAuthn is not supported on sites with TLS certificate
// errors`, which sends you hunting through origins and certificates. And a
// UV-required ceremony against an authenticator that cannot verify is refused
// by the BROWSER, so the relying-party-side UV check cannot be exercised from
// this page at all; that lives in tests/webauthn_decode.js, where the material
// can be manufactured.
// ---------------------------------------------------------------------------

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { VirtualAuthenticatorOptions, Transport, Protocol } =
  require("selenium-webdriver/lib/virtual_authenticator");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "webauthn_lab_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

// NB: not chainable. See the header.
function authenticatorOptions(opts) {
  log.debug("Entering authenticatorOptions().");
  const vo = new VirtualAuthenticatorOptions();
  vo.setProtocol(Protocol.CTAP2);
  vo.setTransport(Transport.USB);
  vo.setHasResidentKey(true);
  vo.setIsUserConsenting(true);
  vo.setHasUserVerification(opts.hasUserVerification !== false);
  vo.setIsUserVerified(opts.isUserVerified !== false);
  log.debug("Leaving authenticatorOptions().");
  return vo;
}

async function textOf(driver, id) {
  log.debug("Entering textOf().");
  const els = await driver.findElements(By.id(id));
  log.debug("Leaving textOf().");
  return els.length ? (await els[0].getText()).trim() : null;
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf().");
  const els = await driver.findElements(By.id(id));
  log.debug("Leaving valueOf().");
  return els.length ? ((await els[0].getAttribute("value")) || "") : null;
}

// Wait for CONTENT. Every pane here is static markup that exists during parsing
// and says nothing about whether the ceremony has finished; an elementLocated
// plus a sleep is the bet this suite has lost repeatedly. See
// tests/wait_for.js.
async function waitForText(driver, id, predicate, what) {
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = (await textOf(driver, id)) || "";
      return predicate(last);
    }, waitTime * 6);
  } catch (e) {
    throw new Error(what + " — #" + id + " holds: \"" + last.slice(0, 300) +
                    "\"");
  }
  log.debug("Leaving waitForText().");
  return last;
}

async function waitForValue(driver, id, predicate, what) {
  log.debug("Entering waitForValue().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = (await valueOf(driver, id)) || "";
      return predicate(last);
    }, waitTime * 6);
  } catch (e) {
    throw new Error(what + " — #" + id + " holds: \"" + last.slice(0, 200) +
                    "\"");
  }
  log.debug("Leaving waitForValue().");
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
    // "=new", never bare --headless: the image pins Chrome 121, where the old
    // headless implementation ignores
    // --unsafely-treat-insecure-origin-as-secure and so leaves this page with
    // no navigator.credentials at all.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  // The containerized origin (http://client:3000) is not a secure context, and
  // WebAuthn does not merely degrade there — PublicKeyCredential is undefined.
  // Measured: with these flags a full ceremony succeeds, single-label RP ID and
  // all. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder().forBrowser("chrome")
    .setChromeOptions(options).setLoggingPrefs(prefs).build();

  let authenticatorId = null;
  try {
    await driver.get(baseUrl + "/webauthn.html");
    await driver.wait(until.elementLocated(By.id("wl_create_button")),
                      waitTime * 4);
    await driver.executeScript("localStorage.clear();");
    await driver.navigate().refresh();
    await driver.wait(until.elementLocated(By.id("wl_create_button")),
                      waitTime * 4);

    await section("the capability pane reports a usable environment",
                  async () => {
      const caps = await waitForText(driver, "wl_caps_body", (t) =>
          /secure context/.test(t),
        "the capability pane never filled");
      assert.ok(/PublicKeyCredential\s*available/.test(caps.replace(/\s+/g,
                " ")),
        "PublicKeyCredential should be available here. If it is not, the " +
            "origin is not a secure " +
        "context and browser_flags.js did not relax it: " + caps.slice(0, 200));
      const disabled = await driver.findElement(By.id("wl_create_button"))
          .getAttribute("disabled");
      assert.ok(!disabled,
          "the Create button should be enabled when the API is available");
      // The RP ID is prefilled from the origin, and it must be, because a page
      // cannot name a domain it does not own.
      const rpId = await valueOf(driver, "wl_rp_id");
      assert.ok(rpId && rpId.length,
                "the RP ID should be prefilled from this origin; got " + rpId);
      return "RP ID prefilled as " + rpId;
    });

    await driver.addVirtualAuthenticator(
      authenticatorOptions({ hasUserVerification: true,
                           isUserVerified: true }));

    await section("registration runs a real ceremony and decodes it",
                  async () => {
      await driver.findElement(By.id("wl_create_button")).click();
      const result = await waitForValue(driver, "wl_reg_result", (v) =>
          /"attestationObject"/.test(v),
        "the registration never produced a credential");
      const parsed = JSON.parse(result);
      assert.strictEqual(parsed.type, "public-key", "the credential type");
      assert.ok(parsed.rawId, "a rawId should be present");
      assert.ok(parsed.response.clientDataJSON,
                "clientDataJSON should be present");

      const authData = await waitForText(driver, "wl_authdata_body", (t) =>
          /AAGUID/.test(t),
        "the authenticator data pane never filled");
      assert.ok(/AT ✓/.test(authData), "AT should be set on a registration");
      assert.ok(/UV ✓/.test(authData),
                "UV should be set — this authenticator verifies");

      const cose = await waitForText(driver, "wl_cose_body", (t) =>
          /jwk\.kty/.test(t),
        "the COSE key pane never filled");
      assert.ok(/ES256/.test(cose),
                "ES256 was requested and should be what came back");
      const pem = await valueOf(driver, "wl_cose_pem");
      assert.ok(/BEGIN PUBLIC KEY/.test(pem),
                "the SPKI PEM should be rendered");

      const cd = await textOf(driver, "wl_clientdata_body");
      assert.ok(/webauthn\.create/.test(cd),
                "clientData.type should be webauthn.create");
      return "credential " + parsed.rawId.slice(0, 16) +
          "…, ES256, PEM rendered";
    });

    await section("the ceremony trace names the authenticator boundary",
                  async () => {
      const trace = await waitForText(driver, "wl_trace_body", (t) =>
          t.length > 0,
        "the ceremony trace never filled");
      assert.ok(/private key did not cross/.test(trace),
        "the trace must state that the private key never crossed the " +
            "boundary — that is the " +
        "single most useful thing this page has to say: " + trace.slice(0,
            200));
      assert.ok(/CTAP/.test(trace),
        "and it must say that CTAP is not observable, rather than leaving " +
            "the user to look for " +
        "a pane that cannot exist");
      return "boundary and CTAP both stated";
    });

    await section("authentication verifies against the key from that " +
                  "registration", async () => {
      await driver.findElement(By.id("wl_get_button")).click();
      const verdict = await waitForText(driver, "wl_auth_status", (t) =>
          /VALID|NOT VALID/.test(t),
        "the assertion never produced a verdict");
      assert.ok(/^VALID/.test(verdict), "the assertion should verify: " +
                verdict);
      const checks = await textOf(driver, "wl_verify_body");
      assert.ok(/✓.*signature verifies/.test(checks),
                "the signature check should be listed as passing");
      assert.ok(/✓.*rpIdHash/.test(checks),
                "the RP ID hash check should be listed as passing");
      const result = await valueOf(driver, "wl_auth_result");
      assert.ok(/"signature"/.test(result),
                "the assertion JSON should be shown");
      return verdict;
    });

    await section("the sign counter advances between two assertions",
                  async () => {
      const before = await textOf(driver, "wl_authdata_body");
      const firstCount = parseInt((before.match(/sign count\s+(\d+)/) || [])[1],
          10);
      await driver.findElement(By.id("wl_get_button")).click();
      await driver.wait(async function () {
        const t = await textOf(driver, "wl_authdata_body");
        const c = parseInt((t.match(/sign count\s+(\d+)/) || [])[1], 10);
        return Number.isFinite(c) && c > firstCount;
      }, waitTime * 6,
          "the sign counter did not advance across two assertions");
      const after = await textOf(driver, "wl_authdata_body");
      const secondCount = parseInt((after.match(/sign count\s+(\d+)/) || [])[1],
          10);
      const verdict = await textOf(driver, "wl_auth_status");
      assert.ok(/^VALID/.test(verdict),
        "and the second assertion must still verify — the counter check " +
            "compares against the " +
        "count this page remembered, so an off-by-one here reads as a cloned " +
            "authenticator: " + verdict);
      return firstCount + " → " + secondCount;
    });

    await section("a credential the authenticator does not hold is " +
                  "reported, not hung", async () => {
      await driver.removeAllCredentials();
      await driver.findElement(By.id("wl_get_button")).click();
      const st = await waitForText(driver, "wl_auth_status",
        (t) => /NotAllowedError|NOT VALID/.test(t),
        "removing every credential should have produced a reported failure");
      assert.ok(/NotAllowedError/.test(st),
                "the browser's error should be surfaced: " + st);
      // WebAuthn collapses several situations into one error on purpose; the
      // page must say that rather than guess which one happened.
      assert.ok(/privacy|indistinguishable|several situations/i.test(st),
        "and the page should explain that this error is deliberately " +
            "ambiguous rather than " +
        "guessing at a cause: " + st);
      return "reported as NotAllowedError with the ambiguity explained";
    });

    await section("no pane overflows its box", async () => {
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
      assert.ok(m.worst <= 2, "content escapes its pane by " + m.worst +
                "px (" + m.id + ")");
      assert.strictEqual(m.sideways, false,
                         "and the page must not scroll sideways");
      return "worst overhang " + m.worst + "px";
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
    if (authenticatorId !== null) {
      try {
        await driver.removeVirtualAuthenticator();
      } catch (e) {
        // The session is going away anyway; a failure to detach a virtual
        // authenticator must not mask the test's own result.
        log.warn("Could not remove the virtual authenticator: " + e.message);
      }
    }
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("webauthn_lab_page")
  .description("Drive the WebAuthn Lab page against the WebDriver virtual " +
      "authenticator.")
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
