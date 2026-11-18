// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: no_direct_webcrypto_engine.js
//
// ---------------------------------------------------------------------------
// NO BROWSER CODE CALLS WEB CRYPTO EXCEPT THE OPT-IN BACKEND (#463).
//
// Every cryptographic operation the debugger performs in a browser is
// common/crypto/crypto_provider.js's, in pure JS, so it works on every
// deployment: the static sites, the plain-HTTP containerized stack (where
// crypto.subtle does not exist) and the embedded build. The one place that
// may touch crypto.subtle is common/crypto/crypto_webcrypto.js, the OPTIONAL
// backend a caller opts in to, which falls back to pure JS.
//
// So this reads every module that reaches a browser bundle — client/src and
// everything common/ stages into it (common/*.js, common/crypto,
// common/krb5, common/spiffe) — and fails on any property access to
// `subtle` outside that one file, naming the file and line. Comments are
// ignored, so a sentence about Web Crypto is not a call to it.
//
// A crypto.subtle call anywhere else is a regression: that operation would
// silently stop working on a plain-HTTP page. Route it through
// crypto_provider.js, or through crypto_webcrypto.js if it must be Web
// Crypto and opt-in.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "no_direct_webcrypto_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// The one module allowed to touch crypto.subtle.
const ALLOWED = "crypto_webcrypto.js";

// Fewer files than this means the sweep is reading the wrong tree, and a
// pass over it would mean nothing.
const MIN_FILES = 150;

// In a checkout the sources are beside tests/. In the tests image they are
// the copy tests/Dockerfile stages at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  var i;
  for (i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

// The source with comments removed, line numbers kept: a block comment's
// lines become empty lines rather than disappearing.
function codeOnly(source) {
  log.debug("Entering codeOnly().");
  var text = source.replace(/\/\*[\s\S]*?\*\//g, function (block) {
    return block.replace(/[^\n]/g, "");
  }).split("\n").map(function (line) {
    return /^\s*\/\//.test(line) ? "" : line.replace(/\s\/\/\s.*$/, "");
  });
  log.debug("Leaving codeOnly().");
  return text;
}

// A property access to `subtle`: `crypto.subtle`, `window.crypto.subtle`,
// `globalThis.crypto.subtle`, `g.crypto.subtle`, `crypto["subtle"]`. Not a
// CSS class such as "wa-subtle", which is preceded by a hyphen.
const SUBTLE = /(\.\s*subtle\b|\[\s*["']subtle["']\s*\])/;

function offendingLines(file) {
  log.debug("Entering offendingLines(). " + file);
  var out = [];
  codeOnly(fs.readFileSync(file, "utf8")).forEach(function (line, index) {
    if (SUBTLE.test(line)) {
      out.push(path.basename(file) + ":" + (index + 1) + ": " + line.trim());
    }
  });
  log.debug("Leaving offendingLines(). " + out.length);
  return out;
}

// Every .js file that reaches a browser bundle. Staged copies of common/
// modules in client/src (left by an interrupted build) are skipped by name,
// because their originals are read from common/.
function bundleSources(root) {
  log.debug("Entering bundleSources().");
  var dirs = [path.join(root, "client", "src"), path.join(root, "common"),
              path.join(root, "common", "crypto"),
              path.join(root, "common", "krb5"),
              path.join(root, "common", "spiffe")];
  var commonNames = new Set();
  dirs.slice(1).forEach(function (dir) {
    if (fs.existsSync(dir)) {
      fs.readdirSync(dir).forEach(function (n) {
        commonNames.add(n);
      });
    }
  });
  var files = [];
  dirs.forEach(function (dir, index) {
    if (!fs.existsSync(dir)) {
      return;
    }
    fs.readdirSync(dir).forEach(function (n) {
      if (!/\.js$/.test(n)) {
        return;
      }
      if (index === 0 && commonNames.has(n)) {
        return;
      }
      files.push(path.join(dir, n));
    });
  });
  log.debug("Leaving bundleSources(). " + files.length);
  return files;
}

// The detector itself, on lines it must and must not flag, so a pass below
// cannot come from a pattern that matches nothing.
function theDetectorDetects() {
  log.debug("Entering theDetectorDetects().");
  ["  return crypto.subtle.digest('SHA-256', d);",
   "var s = window.crypto.subtle;",
   "await globalThis.crypto . subtle.sign(p, k, d);",
   "var s = crypto['subtle'];"].forEach(function (line) {
    assert.ok(SUBTLE.test(line), "the detector missed: " + line);
  });
  ["el('div', 'wa-subtle', text);",
   "var subtleNote = 'x';"].forEach(function (line) {
    assert.ok(!SUBTLE.test(line), "the detector flagged: " + line);
  });
  assert.deepStrictEqual(codeOnly("// crypto.subtle.x()\n/* crypto.subtle\n" +
      "*/ a();\nb(); // crypto.subtle"), ["", "", " a();", "b();"],
      "comments are not stripped as expected");
  log.info("[detector] OK — it flags every spelling of a subtle access and " +
           "neither a CSS class nor a comment.");
  log.debug("Leaving theDetectorDetects().");
}

function onlyTheOptInBackendTouchesWebCrypto() {
  log.debug("Entering onlyTheOptInBackendTouchesWebCrypto().");
  var root = repoRoot();
  var files = bundleSources(root);
  assert.ok(files.length >= MIN_FILES, "only " + files.length + " source " +
      "files under " + root + "; the floor is " + MIN_FILES + ", so this is " +
      "not the tree it is meant to read.");
  var allowed = files.filter(function (f) {
    return path.basename(f) === ALLOWED;
  });
  assert.strictEqual(allowed.length, 1, "expected exactly one " + ALLOWED +
      " (common/crypto), found " + allowed.length);
  assert.ok(offendingLines(allowed[0]).length > 0, ALLOWED + " no longer " +
      "touches crypto.subtle at all, so this check would pass vacuously; " +
      "if the opt-in backend moved, move ALLOWED with it.");
  var found = [];
  files.forEach(function (f) {
    if (path.basename(f) !== ALLOWED) {
      found = found.concat(offendingLines(f));
    }
  });
  assert.deepStrictEqual(found, [], "Web Crypto is called outside the " +
      "opt-in backend, so these operations stop working on a plain-HTTP " +
      "page (#463). Route each through crypto_provider.js, or through " +
      ALLOWED + " if it must be Web Crypto:\n  " + found.join("\n  "));
  log.info("[sweep] OK — " + files.length + " browser source files read; " +
           "only " + ALLOWED + " touches crypto.subtle.");
  log.debug("Leaving onlyTheOptInBackendTouchesWebCrypto().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  theDetectorDetects();
  onlyTheOptInBackendTouchesWebCrypto();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
