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
