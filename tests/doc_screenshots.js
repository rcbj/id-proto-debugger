// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: doc_screenshots.js
//
// ---------------------------------------------------------------------------
// SCREENSHOTS FOR THE USER DOCUMENTATION, TAKEN BY THE TESTS THAT DRIVE THE
// PAGES BEING DOCUMENTED.
//
// docs/oauth2-oidc/ walks a reader through every OAuth 2.0 grant and every
// OpenID Connect flow the debugger offers, one screen at a time, and the
// pictures in it come from here. They are taken by the Selenium jobs that
// already drive those exact screens — oauth2_*.js, oidc_flows.js and the
// helpers in common/tests.js — rather than by a second script that would walk
// the same pages and drift from them the first time a field moved.
//
// **IT DOES NOTHING UNLESS `DOC_SCREENSHOT_DIR` IS SET**, and every function
// here returns at once when it is not. An ordinary run of the suite takes no
// picture, writes no file and changes no window size; the calls sprinkled
// through the jobs are inert. Set it to a directory and each call writes one
// PNG there:
//
//   DOC_SCREENSHOT_DIR=docs/oauth2-oidc/images node oidc_flows.js -u ...
//
// A file is named `<prefix>-<name>.png`. The prefix is the GRANT or FLOW
// (`setPrefix()`, called once by the job), and the name is the STEP, which is
// how one helper in common/tests.js can serve both the OAuth2 Authorization
// Code job and the OIDC one without either overwriting the other's pictures.
//
// WHAT A CALL CAPTURES. With `ids`, the smallest rectangle around those
// elements (the ones that exist and are drawn), plus a margin — so a pane's
// legend and its fieldset, which are siblings in this markup, come out as one
// picture. Without, the whole document. Either way the capture goes through
// the DevTools protocol's `Page.captureScreenshot` with `captureBeyondViewport`
// rather than WebDriver's screenshot, because WebDriver's stops at the bottom
// of the viewport and every pane worth showing here is taller than one.
//
// **A SCREENSHOT MUST NEVER FAIL A TEST.** Every error in here is logged and
// swallowed: a job that passed its assertions and could not take a picture
// has still passed, and a documentation run that lost one picture should say
// so in the log rather than turn a green job red.
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");

var appconfig = {};
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "doc_screenshots",
                                level: appconfig.LOG_LEVEL || "info" });

// The window every picture is taken in. Wide enough that the configuration
// pane's two-column rows do not wrap, which is how the page is meant to be
// read; the height only matters for whole-document captures and is not a
// limit on them.
const WINDOW_WIDTH = 1280;
const WINDOW_HEIGHT = 1000;

// The margin, in CSS pixels, around an element capture.
const MARGIN = 12;

// The tallest whole-document capture. The second page of this workflow grows
// a history table that can run to thousands of pixels, and a picture taller
// than this is not one a reader will scroll through.
const MAX_HEIGHT = 2600;

let prefix = "screenshot";
let sized = false;

// The directory to write to, or "" when screenshots are off.
function outputDir() {
  log.debug("Entering outputDir().");
  const dir = String(process.env.DOC_SCREENSHOT_DIR || "").trim();
  log.debug("Leaving outputDir().");
  return dir;
}

// True when this run should take pictures at all.
function enabled() {
  log.debug("Entering enabled().");
  const on = !!outputDir();
  log.debug("Leaving enabled().");
  return on;
}

// Name the grant or flow every following picture belongs to.
function setPrefix(value) {
  log.debug("Entering setPrefix().");
  prefix = String(value || "screenshot")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  log.debug("Leaving setPrefix(). prefix=" + prefix);
}

// The rectangle to capture, in document coordinates. Runs IN THE BROWSER,
// through executeScript, so it has no `log` and must not be given one.
function measureInPage(ids, margin, maxHeight) {
  var doc = document.documentElement;
  var width = Math.max(doc.scrollWidth, document.body.scrollWidth);
  var height = Math.max(doc.scrollHeight, document.body.scrollHeight);
  if (!ids || !ids.length) {
    return { x: 0, y: 0, width: width, height: Math.min(height, maxHeight) };
  }
  var left = Infinity;
  var top = Infinity;
  var right = -Infinity;
  var bottom = -Infinity;
  ids.forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) {
      return;
    }
    var r = el.getBoundingClientRect();
    if (!r.width || !r.height) {
      return;
    }
    left = Math.min(left, r.left + window.scrollX);
    top = Math.min(top, r.top + window.scrollY);
    right = Math.max(right, r.right + window.scrollX);
    bottom = Math.max(bottom, r.bottom + window.scrollY);
  });
  if (left === Infinity) {
    return null;
  }
  left = Math.max(0, left - margin);
  top = Math.max(0, top - margin);
  right = Math.min(width, right + margin);
  bottom = Math.min(height, bottom + margin);
  return { x: left, y: top, width: right - left,
           height: Math.min(bottom - top, maxHeight) };
}

// Take one picture. `name` is the step; `ids` optionally narrows the picture
// to those elements, and `maxHeight` cuts it off below that many pixels (the
// discovery table, for one, runs to a few thousand). Resolves to the file
// written, or "" when nothing was.
async function snap(driver, name, { ids = [], maxHeight = MAX_HEIGHT } = {}) {
  log.debug("Entering snap().");
  if (!enabled()) {
    log.debug("Leaving snap(). Screenshots are off.");
    return "";
  }
  const file = path.resolve(outputDir(), prefix + "-" + name + ".png");
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (!sized) {
      await driver.manage().window().setRect({ width: WINDOW_WIDTH,
                                               height: WINDOW_HEIGHT });
      sized = true;
    }
    // Let a pane that was just revealed, or a smooth scroll that was just
    // asked for, come to rest before it is photographed.
    await new Promise(function (resolve) {
      setTimeout(resolve, 400);
    });
    const clip = await driver.executeScript(
      "return (" + measureInPage.toString() + ")(arguments[0], " +
          "arguments[1], arguments[2]);",
      ids, MARGIN, maxHeight);
    if (!clip) {
      log.warn("snap(): none of " + ids.join(", ") + " is on the page " +
               "and drawn; no picture for " + name + ".");
      log.debug("Leaving snap(). Nothing to capture.");
      return "";
    }
    const shot = await driver.sendAndGetDevToolsCommand(
      "Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
        clip: { x: clip.x, y: clip.y, width: clip.width,
                height: clip.height, scale: 1 },
      });
    fs.writeFileSync(file, Buffer.from(shot.data, "base64"));
    log.info("Documentation screenshot written: " + file);
  } catch (e) {
    log.warn("snap(): could not write " + file + ": " + e.message);
    log.debug("Leaving snap(). Failed.");
    return "";
  }
  log.debug("Leaving snap().");
  return file;
}

module.exports = { enabled, setPrefix, snap };
