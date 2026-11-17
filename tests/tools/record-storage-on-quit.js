// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: tools/record-storage-on-quit.js
//
// ---------------------------------------------------------------------------
// EVERY BROWSER STORAGE KEY A RUN ACTUALLY WROTE, read just before each
// browser closes.
//
// The storage model (models/storage/) is held to the keys the client SOURCE
// names by tests/storage_inventory.js, which reads them with acorn — and 133
// call sites build their key in a way no static reading can follow (a
// helper's parameter, a key from another module). This sees what those sites
// wrote. Preloaded into every job by run-report.js (`--require`), it wraps
// selenium-webdriver's WebDriver.prototype.quit() the way
// flush-coverage-on-quit.js does: before the browser is closed, it reads the
// key NAMES (never a value: a value can be a token) of localStorage and
// sessionStorage on the page the browser is on, and appends one JSON line to
// STORAGE_RECORD_FILE when that page is on STORAGE_RECORD_ORIGIN, the
// debugger's own origin. tests/storage_keys_recorded.js runs last and holds
// every recorded key to the model.
//
// localStorage is per origin and survives navigation, so the page a test
// ends on sees every local key the run's pages on that origin wrote; a test
// that ends on an identity provider's page records nothing, which loses a
// sample and never invents one.
//
// IT CAN NEVER FAIL A JOB. The read is bounded, every error is swallowed, and
// the real quit() always runs. With STORAGE_RECORD_FILE unset (any run that
// is not run-report.js's) it installs nothing.
// ---------------------------------------------------------------------------

'use strict';

const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "record-storage-on-quit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const READ_MS = 3000;

// JavaScript in a string, evaluated in the page: not this file's control
// flow, so the logging convention does not reach inside it.
const READ_SCRIPT =
  "var out = { origin: location.origin, local: [], session: [] };" +
  "try { out.local = Object.keys(window.localStorage); } catch (e) {}" +
  "try { out.session = Object.keys(window.sessionStorage); } catch (e) {}" +
  "return out;";

function install() {
  log.debug("Entering install().");
  const file = process.env.STORAGE_RECORD_FILE || "";
  const origin = process.env.STORAGE_RECORD_ORIGIN || "";
  if (!file || !origin) {
    log.debug("Leaving install(). Not recording.");
    return;
  }
  let webdriver = null;
  try {
    webdriver = require("selenium-webdriver");
  } catch (e) {
    log.debug("Leaving install(). No selenium-webdriver.");
    return;
  }
  const proto = webdriver.WebDriver && webdriver.WebDriver.prototype;
  if (!proto || proto.quit.__storageRecord) {
    log.debug("Leaving install(). Nothing to wrap.");
    return;
  }
  const script = path.basename(process.argv[1] || "");
  const realQuit = proto.quit;
  const wrapped = async function quitAfterRecordingStorage() {
    log.debug("Entering quitAfterRecordingStorage().");
    const driver = this;
    let timer = null;
    try {
      const seen = await Promise.race([
        driver.executeScript(READ_SCRIPT),
        new Promise(function (resolve) {
          timer = setTimeout(resolve, READ_MS, null);
        })
      ]);
      if (seen && seen.origin === origin &&
          (seen.local.length || seen.session.length)) {
        fs.appendFileSync(file, JSON.stringify({
          script: script, origin: seen.origin,
          local: seen.local, session: seen.session }) + "\n");
      }
    } catch (e) {
      // See the header: a failed read loses a sample, never the job.
      log.debug("quitAfterRecordingStorage(): " + e.message);
    } finally {
      clearTimeout(timer);
    }
    log.debug("Leaving quitAfterRecordingStorage().");
    return realQuit.apply(driver, arguments);
  };
  wrapped.__storageRecord = true;
  proto.quit = wrapped;
  log.debug("Leaving install(). quit() records storage first.");
}

install();
