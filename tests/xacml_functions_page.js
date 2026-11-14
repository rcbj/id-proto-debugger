// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_functions_page.js
//
// ---------------------------------------------------------------------------
// EVERY XACML 3.0 STANDARD FUNCTION AND DATATYPE, THROUGH THE XACML PAGE.
//
// The same table xacml_functions_engine.js runs in node
// (tests/xacml_function_cases.js), run here through xacml.html itself: each
// case is pasted into the import box and imported, the editor draws it, the
// decision form asks for it, and the decision heading must read what the
// table says. Each importable case's ALFA — read off the editor's own ALFA
// view — is then imported back and must decide the same. Both are removed
// before the next case, so the repository never holds more than two.
//
// It drives the page's bundle rather than a copy of the engine, which is the
// point: the page is where a user meets these functions, and the editor's
// drawing of every expression the table has is exercised along the way.
//
// Cases run in batches inside one in-page script each — the page redraws
// synchronously, so no element handle outlives a call — and a batch is kept
// well inside the WebDriver script timeout.
// ---------------------------------------------------------------------------

"use strict";

const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadUrl } = require("./page_load.js");
const paths = require("./module_paths.js");
const cases = require("./xacml_function_cases.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_functions_page",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const BATCH = 40;

// RUNS IN THE BROWSER: no bunyan here (see the repo-root CLAUDE.md). It
// returns one row per case, which is logged in node.
const RUN_BATCH = `
  var batch = arguments[0];
  var page = window.xacml;
  function el(id) { return document.getElementById(id); }
  function status() {
    var st = el("xacml_status");
    return { text: st ? st.textContent : "",
             warn: st ? st.className.indexOf("xacml-warn") >= 0 : false };
  }
  function importAs(name, text) {
    el("xacml_status").textContent = "";
    el("xacml_import_name").value = name;
    el("xacml_import").value = text;
    page.importPolicy();
    return status();
  }
  function decideWith(name) {
    el("xacml_decide_policy").value = name;
    el("xacml_subject").value = "alice";
    el("xacml_action").value = "GET";
    el("xacml_resource").value = "r";
    el("xacml_request").value = "";
    page.decide();
    var dec = el("xacml_decision");
    var h = dec ? dec.querySelector("h3") : null;
    return h ? h.textContent.trim() : "problem: " +
      (dec ? dec.textContent.trim() : "no decision box");
  }
  function removeOpen(name) {
    el("xacml_open").value = name;
    page.openPolicy();
    page.removePolicy();
  }
  return batch.map(function (c) {
    var row = { name: c.name, expect: c.expect, got: "", alfa: "" };
    var st = importAs("case", c.xml);
    if (st.warn) {
      row.got = "Refused";
      row.why = st.text;
      return row;
    }
    row.got = decideWith("case");
    var pres = el("xacml_editor").querySelectorAll("details pre");
    var alfa = pres.length > 0 ? pres[0].textContent : "";
    var back = importAs("case-alfa", alfa);
    if (back.warn) {
      row.alfa = "its ALFA does not import: " + back.text;
    } else {
      row.alfa = decideWith("case-alfa");
      removeOpen("case-alfa");
    }
    removeOpen("case");
    return row;
  });`;

async function openFresh(driver) {
  log.debug("Entering openFresh().");
  await loadUrl(driver, baseUrl + "/xacml.html");
  await driver.executeScript(
      "try { localStorage.removeItem('xacml_repository'); } catch (e) {}");
  await loadUrl(driver, baseUrl + "/xacml.html");
  await driver.wait(async function () {
    return driver.executeScript(
        "return document.readyState === 'complete' && " +
        "typeof window.xacml === 'object' && window.xacml !== null && " +
        "!!document.getElementById('xacml_import');");
  }, waitTime * 4, "the XACML page never finished loading");
  log.debug("Leaving openFresh().");
}

async function everyCaseThroughThePage(driver, built) {
  log.debug("Entering everyCaseThroughThePage().");
  var wrong = [];
  var alfaChecked = 0;
  for (var start = 0; start < built.cases.length; start += BATCH) {
    var batch = built.cases.slice(start, start + BATCH).map(function (c) {
      return { name: c.name, expect: c.expect, xml: c.xml };
    });
    var rows = await driver.executeScript(RUN_BATCH, batch);
    rows.forEach(function (row) {
      if (row.got !== row.expect) {
        wrong.push(row.name + ": expected " + row.expect + ", got " +
                   row.got + (row.why ? " (" + row.why + ")" : ""));
      }
      if (row.got !== "Refused") {
        alfaChecked += 1;
        if (row.alfa !== row.got) {
          wrong.push(row.name + ": " + row.got + " as XML, " + row.alfa +
                     " as its ALFA");
        }
      }
    });
    log.info("batch " + (start / BATCH + 1) + ": cases " + (start + 1) +
             "-" + (start + batch.length) + " run");
  }
  assert.deepStrictEqual(wrong, [], wrong.length + " case(s) wrong on the " +
                         "page:\n  " + wrong.join("\n  "));
  log.info("PASS  all " + built.cases.length + " cases decide on the page " +
           "as XACML 3.0 Appendix A says, and " + alfaChecked +
           " decide the same again from the editor's ALFA");
  log.debug("Leaving everyCaseThroughThePage().");
}

async function test() {
  log.debug("Entering test().");
  var functions = paths.requireSharedModule(
    [path.join(__dirname, "..", "client", "src", "xacml",
               "xacml_functions.js")],
    "client/src/xacml/xacml_functions.js");
  var built = cases.buildAll(functions.names());
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await openFresh(driver);
    await everyCaseThroughThePage(driver, built);
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
  .name("xacml_functions_page")
  .description("Run every XACML function case through xacml.html.")
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
