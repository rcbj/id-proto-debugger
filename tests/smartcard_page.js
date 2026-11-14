// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: smartcard_page.js
//
// The smart-card page in a browser. Named _page so it does not
// collide with client/src/smartcard.js when the tests image copies
// modules flat. See the note at the top of
// tests/webauthn_analyzer_page.js.
//
// It types an OTP and refuses a string that is not one. It does not
// click Verify and it does not call YubiCloud. The layout check
// fills the PIV trace with a long line and asserts the pane holds it.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadUrl } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "smartcard_page",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const TOKEN = "cccccccccccccccccccccccccccccccccccccccccccc";

async function setValue(driver, id, text) {
  log.debug("Entering setValue().");
  const field = await driver.findElement(By.id(id));
  await driver.executeScript(
      "arguments[0].value = arguments[1];" +
      "arguments[0].dispatchEvent(new Event('input'));",
      field, text);
  log.debug("Leaving setValue().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf().");
  const el = await driver.findElement(By.id(id));
  const text = await el.getText();
  log.debug("Leaving textOf().");
  return text;
}

async function waitForText(driver, id, predicate, what) {
  log.debug("Entering waitForText().");
  let last = "";
  try {
    await driver.wait(async function () {
      last = (await textOf(driver, id)) || "";
      return predicate(last);
    }, waitTime * 4);
  } catch (e) {
    throw new Error(what + " — #" + id + " holds: \"" +
        last.slice(0, 300) + "\"");
  }
  log.debug("Leaving waitForText().");
  return last;
}

// THE WRITE FORMS, OFFLINE. On the containerized stack the api's relay is
// on and reaches no reader, so every write runs its own checks and then
// fails for want of a reader — and each must SAY so, in the pane it was
// started from, not only on a status line out of sight. Confirmations are
// answered yes (and the reset phrase given) so the code behind them runs.
// RUNS IN THE BROWSER: ACTION has no bunyan; its result is logged here.
const ACTION = `
  var js = arguments[0], outId = arguments[1], done = arguments[2];
  var out = document.getElementById(outId);
  if (out) { out.innerHTML = ""; }
  document.getElementById("sc_status").textContent = "";
  try { (new Function(js))(); } catch (e) { done("THREW " + e.message); return; }
  var started = Date.now();
  (function wait() {
    var text = out ? out.innerText : "";
    if (text || Date.now() - started > 8000) {
      done(text || ("(no pane text) status: " +
        document.getElementById("sc_status").textContent));
      return;
    }
    setTimeout(wait, 150);
  })();`;

async function act(driver, js, outId, expect, what) {
  log.debug("Entering act(). " + what);
  const got = await driver.executeAsyncScript(ACTION, js, outId);
  assert.ok(expect.test(got), what + " — " + outId + " says: " +
      String(got).slice(0, 300));
  log.debug("Leaving act().");
  return got;
}

async function offlineForms(driver) {
  log.debug("Entering offlineForms().");
  await driver.executeScript(
      "window.confirm = function () { return true; };" +
      "window.__reset = '';" +
      "window.prompt = function () { return window.__reset; };" +
      "document.getElementById('sc_transport').value = 'api';" +
      "smartcard.onTransportChange();");
  // The bar: the API sees no reader on this stack, and says so, in red.
  await driver.wait(async function () {
    return /sc-detect-no/.test(await driver.executeScript(
        "return document.getElementById('sc_detect').className;"));
  }, waitTime * 4, "the key-detected bar never turned red");

  // Every Generate button fills its field in that field's format.
  const generated = await driver.executeScript(
      "var out = {};" +
      "Array.prototype.forEach.call(document.querySelectorAll(" +
      "  'button.sc-gen'), function (b) {" +
      "  b.click();" +
      "  var id = /generateSecret\\('([a-z_]+)'/.exec(" +
      "      b.getAttribute('onclick'))[1];" +
      "  out[id] = document.getElementById(id).value; });" +
      "return out;");
  const formats = {
    sc_oath_add_secret: /^[A-Z2-7]{32}$/, sc_oath_secret: /^[0-9a-f]{40}$/,
    sc_slot_hmac_key: /^[0-9a-f]{40}$/, sc_slot_hotp_key: /^[A-Z2-7]{32}$/,
    sc_slot_private_id: /^[0-9a-f]{12}$/, sc_slot_aes_key: /^[0-9a-f]{32}$/,
    sc_hsm_add_derivation: /^[A-Za-z2-9]{16}$/,
    sc_hsm_add_password: /^[A-Za-z2-9]{16}$/,
    sc_hsm_add_enc: /^[0-9a-f]{32}$/, sc_hsm_add_mac: /^[0-9a-f]{32}$/,
    sc_hsm_add_ec_key: /^[0-9a-f]{64}$/, sc_piv_new_mgm_key: /^[0-9a-f]{48}$/
  };
  Object.keys(formats).forEach(function (id) {
    assert.ok(formats[id].test(generated[id] || ""), id + " generated " +
        JSON.stringify(generated[id]));
  });
  await driver.executeScript(
      "['hmac', 'yubico-otp', 'hotp'].forEach(function (t) {" +
      "  document.getElementById('sc_slot_type').value = t;" +
      "  smartcard.onSlotTypeChange(); smartcard.generateSlotSecrets(); });" +
      "['derived', 'keys', 'ec'].forEach(function (t) {" +
      "  document.getElementById('sc_hsm_add_type').value = t;" +
      "  smartcard.onHsmTypeChange(); });");

  const NO_READER = /reader|PC\/SC|pcscd|service|SCard|readers/i;
  const set = function (id, v) {
    return "document.getElementById('" + id + "').value = " +
        JSON.stringify(v) + ";";
  };
  // OATH.
  await act(driver, set("sc_oath_add_uri", "") +
      set("sc_oath_add_secret", "not base32!") + "smartcard.addOathAccount();",
      "sc_oath_out", /base32/, "a bad OATH secret");
  await act(driver, set("sc_oath_add_uri", "otpauth://totp/Ex:alice?" +
      "secret=JBSWY3DPEHPK3PXP&issuer=Ex&period=60") +
      "smartcard.addOathAccount();", "sc_oath_out", NO_READER,
      "an OATH account with no reader");
  await act(driver, set("sc_oath_del_name", "") +
      "smartcard.deleteOathAccount();", "sc_oath_out", /name|empty|1 to 64/i,
      "deleting an unnamed account");
  await act(driver, set("sc_oath_del_name", "Ex:alice") +
      "smartcard.deleteOathAccount();", "sc_oath_out", NO_READER,
      "deleting with no reader");
  // OTP slots.
  await act(driver, set("sc_slot_type", "yubico-otp") +
      set("sc_slot_aes_key", "abc") + "smartcard.programSlot();",
      "sc_otp_out", /AES key|hex/, "a bad AES key");
  await act(driver, set("sc_slot_type", "hmac") +
      "smartcard.onSlotTypeChange(); smartcard.generateSlotSecrets();" +
      "smartcard.programSlot();", "sc_otp_out", NO_READER,
      "programming with no reader");
  await act(driver, set("sc_slot_access_code", "12") +
      "smartcard.deleteSlot();", "sc_otp_out", /access code|hex/,
      "a bad access code");
  await act(driver, set("sc_slot_access_code", "") +
      "smartcard.swapSlots();", "sc_otp_out", NO_READER, "swapping");
  // YubiHSM Auth.
  await act(driver, set("sc_hsm_mgmt_key", "") +
      "smartcard.addHsmCredential();", "sc_hsm_out", /management key/i,
      "no HSM management key");
  await act(driver, "smartcard.useHsmDefaultKey();" +
      set("sc_hsm_add_label", "t") + set("sc_hsm_add_type", "derived") +
      "smartcard.addHsmCredential();", "sc_hsm_out", NO_READER,
      "an HSM credential with no reader");
  await act(driver, set("sc_hsm_del_label", "t") +
      "smartcard.deleteHsmCredential();", "sc_hsm_out", NO_READER,
      "an HSM delete with no reader");
  // PIV.
  await act(driver, set("sc_piv_mgm_key", "") + "smartcard.pivGenerate();",
      "sc_piv_out", /management key|reader|SCard|service/i,
      "no PIV management key");
  await act(driver, "smartcard.usePivDefaultKey();" +
      set("sc_piv_cert_pem", "nope") + "smartcard.pivImportCertificate();",
      "sc_piv_out", /PEM/, "a non-PEM certificate");
  await act(driver, "smartcard.pivDeleteKey();", "sc_piv_out", NO_READER,
      "a PIV key delete with no reader");
  await act(driver, set("sc_piv_pin_old", "12") + set("sc_piv_pin_new",
      "482915") + "smartcard.pivPinWrite('pin');", "sc_piv_out", /6 to 8/,
      "a short PIV PIN");
  await act(driver, set("sc_piv_puk_old", "12345678") +
      set("sc_piv_pin_new", "482915") + "smartcard.pivPinWrite('unblock');",
      "sc_piv_out", NO_READER, "an unblock with no reader");
  await act(driver, "smartcard.pivSetManagementKey();", "sc_piv_out",
      NO_READER, "a management-key change with no reader");
  // OpenPGP card.
  await act(driver, "smartcard.useOpenPgpDefaultAdminPin();" +
      set("sc_pgp_name", "") + set("sc_pgp_login", "") + set("sc_pgp_url",
      "") + set("sc_pgp_lang", "") + "smartcard.pgpSaveCardholder();",
      "sc_pgp_out", /at least one/, "empty cardholder data");
  await act(driver, set("sc_pgp_name", "Doe<<J") +
      "smartcard.pgpSaveCardholder();", "sc_pgp_out", NO_READER,
      "cardholder data with no reader");
  await act(driver, "smartcard.pgpGenerate();", "sc_pgp_out", NO_READER,
      "OpenPGP generation with no reader");
  await act(driver, "smartcard.pgpSetTouch();", "sc_pgp_out", NO_READER,
      "a touch policy with no reader");
  await act(driver, set("sc_pgp_pin_old", "1") + set("sc_pgp_pin_new",
      "482915") + "smartcard.pgpChangePin('user');", "sc_pgp_out",
      /at least 6/, "a short OpenPGP PIN");
  // Reading, every application.
  for (const app of ["otp", "oath", "piv", "pgp", "hsm"]) {
    await act(driver, "smartcard.readFromKey('" + app + "');",
        "sc_" + app + "_out", NO_READER, "reading " + app);
  }
  // Reset: a wrong phrase sends nothing; the right one meets no reader.
  await act(driver, "window.__reset = 'no';" +
      "smartcard.resetApplication('oath');", "sc_reset_out",
      /Nothing was reset/, "a wrong reset phrase");
  await act(driver, "window.__reset = 'RESET OATH';" +
      "smartcard.resetApplication('oath');", "sc_reset_out", NO_READER,
      "a reset with no reader");
  await act(driver, "window.__reset = 'RESET PIV';" +
      "smartcard.resetApplication('piv');", "sc_reset_out", NO_READER,
      "a PIV reset with no reader");
  // Challenge-response through the API: HID is unavailable here, CCID
  // finds no reader.
  await act(driver, set("sc_hid_challenge", "0102030405") +
      set("sc_hid_slot", "38") + "smartcard.sendHid();", "sc_status",
      /HID|reader|CCID/i, "challenge-response through the API");
  // In browser mode, the CCID applications say they need the API.
  await act(driver, "document.getElementById('sc_transport').value = " +
      "'browser'; smartcard.onTransportChange();" +
      "smartcard.readFromKey('piv');", "sc_piv_out", /needs the API/,
      "reading PIV in browser mode");
  await act(driver, "smartcard.addOathAccount();", "sc_oath_out",
      /needs the API|API/, "writing OATH in browser mode");
  await driver.executeScript("document.getElementById('sc_transport')" +
      ".value = 'api'; smartcard.onTransportChange();");
  log.info("PASS  every write form checks its input and, with no reader, " +
           "says so in its own pane");
  log.debug("Leaving offlineForms().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await loadUrl(driver, baseUrl + "/smartcard.html");
    await driver.wait(until.elementLocated(By.id("sc_otp_token")),
        waitTime * 4);
    await setValue(driver, "sc_otp_token", TOKEN);
    await driver.findElement(By.id("sc_otp_decode")).click();
    const shown = await waitForText(driver, "sc_otp_out",
        function (text) {
          return text.indexOf("cccccccccccc") >= 0;
        }, "the public identity never appeared");
    assert.ok(shown.indexOf("cccccccccccc") >= 0, shown);

    await setValue(driver, "sc_otp_token", "z".repeat(44));
    await driver.findElement(By.id("sc_otp_decode")).click();
    const refused = await waitForText(driver, "sc_status",
        function (text) {
          return text.indexOf("Not modhex.") >= 0;
        }, "a bad OTP was not refused by name");
    assert.ok(refused.indexOf("Not modhex.") >= 0, refused);

    const verify = await driver.findElements(By.id("sc_verify_button"));
    assert.strictEqual(verify.length, 1);
    const longLine = "aa".repeat(2000);
    await driver.findElement(By.id("sc_app")).sendKeys("PIV");
    await driver.executeScript(
        "document.getElementById('sc_app').dispatchEvent(" +
        "new Event('change'));");
    await driver.wait(until.elementLocated(By.id("sc_piv_trace")),
        waitTime * 4);
    await setValue(driver, "sc_piv_trace", longLine);
    await driver.findElement(By.id("sc_piv_response")).click();
    await driver.wait(until.elementLocated(By.id("sc_piv_out")),
        waitTime * 4);
    const fit = await driver.executeScript(
        "var panes = document.querySelectorAll('.saml-pane');" +
        "var worst = 0; var id = null; var i = 0;" +
        "for (i = 0; i < panes.length; i++) {" +
        "  var pane = panes[i];" +
        "  if (pane.className.indexOf('saml-hidden') >= 0) continue;" +
        "  var box = pane.getBoundingClientRect();" +
        "  var kids = pane.querySelectorAll('*');" +
        "  var k = 0;" +
        "  for (k = 0; k < kids.length; k++) {" +
        "    var rect = kids[k].getBoundingClientRect();" +
        "    if (!rect.width) continue;" +
        "    var over = Math.round(rect.right - box.right);" +
        "    if (over > worst) { worst = over;" +
        "      id = kids[k].id || kids[k].className; }" +
        "  }" +
        "}" +
        "var doc = document.documentElement;" +
        "return { worst: worst, id: id," +
        "  sideways: doc.scrollWidth > doc.clientWidth + 2 };");
    assert.ok(fit.worst <= 2,
        "content escapes its pane by " + fit.worst + "px (" +
        fit.id + ")");
    assert.strictEqual(fit.sideways, false,
        "the page scrolls sideways");
    await offlineForms(driver);
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
  .name("smartcard_page")
  .description("Drive the smart-card page.")
  .addOption(new Option("-u, --url <url>", "Set base URL.")
      .makeOptionMandatory())
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
