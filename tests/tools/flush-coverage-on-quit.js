// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: flush-coverage-on-quit.js
//
// ---------------------------------------------------------------------------
// SEND THE PAGE'S BROWSER COVERAGE ONE LAST TIME BEFORE THE BROWSER CLOSES.
//
// client/src/coverage_beacon.js, appended to every bundle by the coverage
// build, POSTs window.__coverage__ to the client's /coverage once a second
// and when the page is hidden. `driver.quit()` fires neither: it kills the
// browser outright. So whatever a job's LAST page ran in its last second —
// usually the assertions the job exists for — was never sent, and the
// frontend total moved by a hundred lines between two runs of the same
// tree (webauthn.js alone by 91), which made a floor of 69.1% a coin toss.
//
// This wraps WebDriver.prototype.quit: before the real quit it sends the
// page's coverage with a SYNCHRONOUS request from inside the page, so it has
// landed before the browser goes. It is bounded (FLUSH_MS) and it swallows
// every failure — a page on another origin has no /coverage, a page with no
// bundle has no __coverage__, a wedged renderer answers nothing — because
// collecting coverage is never worth failing or hanging a job over.
//
// ONLY WHEN COVERAGE=true, which is ./run-coverage.sh. Every other run gets
// the real quit untouched. Loaded by `--require` from run-report.js beside
// attach-admin-token.js; it lives in tools/ for the reason that file does.
// The in-page script is data the browser runs and carries no log lines.
// ---------------------------------------------------------------------------
'use strict';

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "flush-coverage-on-quit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const FLUSH_MS = 5000;

const FLUSH_SCRIPT =
  "if (!window.__coverage__) { return 'none'; }" +
  "try {" +
  "  var x = new XMLHttpRequest();" +
  "  x.open('POST', '/coverage', false);" +
  "  x.setRequestHeader('Content-Type', 'application/json');" +
  "  x.send(JSON.stringify(window.__coverage__));" +
  "  return 'sent ' + x.status;" +
  "} catch (e) { return 'failed ' + e; }";

function install() {
  log.debug("Entering install().");
  if (String(process.env.COVERAGE || "") !== "true") {
    log.debug("Leaving install(). Not a coverage run.");
    return;
  }
  let webdriver = null;
  try {
    webdriver = require("selenium-webdriver");
  } catch (e) {
    // A job with no Selenium has no browser to flush.
    log.debug("Leaving install(). No selenium-webdriver.");
    return;
  }
  const proto = webdriver.WebDriver && webdriver.WebDriver.prototype;
  if (!proto || proto.quit.__coverageFlush) {
    log.debug("Leaving install(). Nothing to wrap.");
    return;
  }
  const realQuit = proto.quit;
  const wrapped = async function quitAfterCoverage() {
    log.debug("Entering quitAfterCoverage().");
    const driver = this;
    let timer = null;
    let said = "timed out";
    try {
      said = await Promise.race([
        driver.executeScript(FLUSH_SCRIPT),
        new Promise(function (resolve) {
          timer = setTimeout(resolve, FLUSH_MS, "timed out");
        })
      ]);
    } catch (e) {
      // See the header: a failed flush loses coverage, never the job.
      said = "failed " + e.message;
    } finally {
      clearTimeout(timer);
    }
    log.debug("Leaving quitAfterCoverage(). Coverage " + said + ".");
    return realQuit.apply(driver, arguments);
  };
  wrapped.__coverageFlush = true;
  proto.quit = wrapped;
  log.debug("Leaving install(). quit() flushes coverage first.");
}

install();
