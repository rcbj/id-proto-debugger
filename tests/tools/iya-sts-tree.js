// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: tools/iya-sts-tree.js
//
// PRINT WHERE iya-sts'S COMPILED TREE IS ON THIS HOST, COPYING IT OUT OF THE
// IMAGE FIRST WHEN IT IS NOT ALREADY CACHED.
//
// The work is iyaStsRoot() in tests/module_paths.js, which is what every job
// that loads iya-sts's modules calls. This is the launchers' way in to the
// same function (common.sh, warmIyaStsTree): a host run calls it once before
// the job pool starts, so a pool of jobs does not race to make the first copy,
// and a run that cannot get the tree stops there, naming the image, rather
// than as a dozen jobs failing to load a module.
//
// Prints the directory on stdout and nothing else; exits 1 with the reason on
// stderr. A tool and not a test, which is why it is under tools/.
'use strict';

const bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "iya-sts-tree",
  stream: process.stderr,
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to
      // info loses only the configured verbosity.
      return "info";
    }
  })()
});

function main() {
  log.debug("Entering main().");
  const paths = require("../module_paths.js");
  let dir;
  try {
    dir = paths.iyaStsRoot(function (message) {
      log.warn(message);
    });
  } catch (e) {
    log.error("Cannot obtain iya-sts's tree: " + e.message);
    log.debug("Leaving main(). Failed.");
    return 1;
  }
  process.stdout.write(dir + "\n");
  log.debug("Leaving main().");
  return 0;
}

process.exitCode = main();
