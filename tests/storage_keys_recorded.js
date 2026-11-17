// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: storage_keys_recorded.js
//
// ---------------------------------------------------------------------------
// EVERY STORAGE KEY THIS RUN'S PAGES WROTE IS ONE THE STORAGE MODEL DECLARES.
//
// tools/record-storage-on-quit.js, preloaded into every job, wrote the key
// names each browser held on the debugger's origin just before it closed
// (STORAGE_RECORD_FILE). This runs LAST (`last: true` in run-report.js) and
// holds every one to common/model/storage.json: a key no model declares, and
// no declared prefix covers, fails, naming it and the jobs that saw it. It is
// the run-time half of tests/data_model.js's static check, and the only half
// that sees the keys a page builds at run time.
//
// A fix is a declaration in models/storage/ (with the right class: a secret
// declared `ordinary` would be stored like any other key), then
// `node models/tools/generate.mjs`.
//
// Skips, as a fact about the run rather than a defect, when no browser job
// recorded anything (a focused mode, or a run with no browser jobs). Node
// only.
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const { declineToRun } = require("./expectation.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "storage_keys_recorded",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

new Command()
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

function storageModel() {
  log.debug("Entering storageModel().");
  const file = path.join(__dirname, "..", "common", "model", "storage.json");
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  log.debug("Leaving storageModel().");
  return doc.keys.filter(function (k) {
    return !k.member;
  });
}

function main() {
  log.debug("Entering main().");
  const file = process.env.STORAGE_RECORD_FILE || "";
  const lines = file && fs.existsSync(file) ?
    fs.readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
  if (!lines.length) {
    declineToRun(log, "no browser job recorded any storage on the " +
      "debugger's origin this run (" + (file || "STORAGE_RECORD_FILE " +
      "unset") + "), so there is nothing to hold to the model.");
    log.debug("Leaving main(). Skipped.");
    return;
  }
  const declared = storageModel();
  const exact = new Set(declared.filter(function (k) {
    return !k.prefix;
  }).map(function (k) {
    return k.key;
  }));
  const prefixes = declared.filter(function (k) {
    return k.prefix;
  }).map(function (k) {
    return k.key;
  });
  const secrets = new Set(declared.filter(function (k) {
    return k.class === "secret";
  }).map(function (k) {
    return k.key;
  }));
  const localOnly = new Set(declared.filter(function (k) {
    return k.class === "bearer";
  }).map(function (k) {
    return k.key;
  }));
  const undeclared = new Map();
  const broken = [];
  let samples = 0;
  lines.forEach(function (line) {
    let record;
    try {
      record = JSON.parse(line);
    } catch (e) {
      return;
    }
    samples = samples + 1;
    [["local", record.local], ["session", record.session]]
      .forEach(function (pair) {
        (pair[1] || []).forEach(function (key) {
          if (secrets.has(key)) {
            broken.push("`" + key + "` is a secret and was found in " +
              pair[0] + "Storage after " + record.script);
            return;
          }
          if (pair[0] === "local" && localOnly.has(key)) {
            broken.push("`" + key + "` is a bearer token and was found " +
              "in localStorage after " + record.script);
            return;
          }
          const covered = exact.has(key) || prefixes.some(function (p) {
            return key.indexOf(p) === 0;
          });
          if (!covered) {
            const seen = undeclared.get(key) || new Set();
            seen.add(record.script);
            undeclared.set(key, seen);
          }
        });
      });
  });
  const problems = broken.slice();
  Array.from(undeclared.keys()).sort().forEach(function (key) {
    problems.push("`" + key + "` is declared by no models/storage file " +
      "(seen after " + Array.from(undeclared.get(key)).sort().join(", ") +
      ")");
  });
  if (problems.length) {
    problems.forEach(function (p) {
      log.error(p);
    });
    log.debug("Leaving main(). Undeclared keys.");
    throw new Error(problems.length + " storage keys written this run " +
      "are not what models/storage/ declares. Declare each with its " +
      "class, regenerate, and run again.");
  }
  log.info("Every storage key in " + samples + " recorded browser(s) is " +
           "declared, and no secret or bearer token was where it may not be.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error(e && e.message ? e.message : String(e));
  process.exitCode = 1;
}
