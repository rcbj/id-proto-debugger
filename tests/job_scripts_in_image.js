// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: job_scripts_in_image.js
//
// Every script a job in run-report.js names must reach the tests image.
//
// ---------------------------------------------------------------------------
// Why this needs a test.
//
// tests/Dockerfile copies test scripts one COPY at a time, and nothing at
// build time notices a job whose script was never copied: the image builds,
// the stack comes up, and the job dies a few minutes in with
// `Cannot find module '/usr/src/app/<name>.js'`. Between 2026-11-12 and
// 2026-11-13 that happened three times in a row on develop
// (rfc9068_engine.js, rp_metadata_choices_engine.js, oauth_scope_engine.js),
// each one a new node-only job whose author ran it on a host, where every
// file is present, and never in the container.
//
// So this job reads the job list the way the runner builds it — every
// `script: "<name>"` literal in run-report.js — and checks it in whichever
// place it finds itself:
//
//  * in a CHECKOUT (client/package.json beside tests/), it parses the
//    `COPY tests/...` sources out of tests/Dockerfile, expands their `*`
//    globs against tests/, and asserts every script is among them. This is
//    the half that fails before anybody builds an image.
//  * in the IMAGE, it asserts every script exists beside it in /usr/src/app.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "job_scripts_in_image",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to
      // info loses only the configured verbosity.
      return "info";
    }
  })(),
});

// The `script: "<name>"` literals in run-report.js. A job whose script is
// computed rather than written out is invisible here, and there is none.
function jobScripts(runReportText) {
  log.debug("Entering jobScripts().");
  var re = /script:\s*"([^"]+)"/g;
  var names = {};
  var m;
  while ((m = re.exec(runReportText)) !== null) {
    names[m[1]] = true;
  }
  var result = Object.keys(names).sort();
  log.debug("Leaving jobScripts().");
  return result;
}

// A shell-style `*` glob over one directory level, as COPY uses it here.
function globToRegExp(glob) {
  log.debug("Entering globToRegExp().");
  var escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, "[^/]*");
  log.debug("Leaving globToRegExp().");
  return new RegExp("^" + escaped + "$");
}

// The file names under tests/ that some `COPY tests/...` line brings into
// the image. Continuation lines are joined first; `--from=` copies take
// from another stage and are not sources in this directory.
function copiedTestFiles(dockerfileText, testsDir) {
  log.debug("Entering copiedTestFiles().");
  var joined = dockerfileText.replace(/\\\r?\n/g, " ");
  var present = fs.readdirSync(testsDir);
  var copied = {};
  joined.split(/\r?\n/).forEach(function (line) {
    var words = line.trim().split(/\s+/);
    if (words[0] !== "COPY") {
      return;
    }
    words.slice(1, -1).forEach(function (src) {
      if (src.indexOf("tests/") !== 0) {
        return;
      }
      var rest = src.slice("tests/".length);
      if (rest.indexOf("/") !== -1) {
        return;
      }
      var re = globToRegExp(rest);
      present.forEach(function (name) {
        if (re.test(name)) {
          copied[name] = true;
        }
      });
    });
  });
  log.debug("Leaving copiedTestFiles().");
  return copied;
}

function main() {
  log.debug("Entering main().");
  var here = __dirname;
  var scripts = jobScripts(
      fs.readFileSync(path.join(here, "run-report.js"), "utf8"));
  assert.ok(scripts.length > 100,
      "expected the job list from run-report.js, found " + scripts.length +
      " script literals — has the job declaration changed shape?");

  var checkout = fs.existsSync(
      path.join(here, "..", "client", "package.json")) &&
      fs.existsSync(path.join(here, "Dockerfile"));
  var missing;
  if (checkout) {
    var copied = copiedTestFiles(
        fs.readFileSync(path.join(here, "Dockerfile"), "utf8"), here);
    missing = scripts.filter(function (s) {
      return !copied[s];
    });
    log.info("Checkout: " + scripts.length + " job scripts, " +
        Object.keys(copied).length + " files copied by tests/Dockerfile.");
  } else {
    missing = scripts.filter(function (s) {
      return !fs.existsSync(path.join(here, s));
    });
    log.info("Image: " + scripts.length + " job scripts checked in " +
        here + ".");
  }
  assert.deepStrictEqual(missing, [],
      "job scripts named in run-report.js that the tests image does not " +
      "contain — add a COPY for each to tests/Dockerfile: " +
      missing.join(", "));
  log.info("PASS  every job script reaches the tests image.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error(e.message);
  process.exitCode = 1;
}
