// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: crypto_resolve.js
//
// ---------------------------------------------------------------------------
// Lets NODE load a client/src module that requires one of common/crypto/'s.
//
// The pure-JS crypto engines (crypto_bytes, hash_tools, symmetric_crypto,
// pk_encryption, pqc, hbs, and whatever #463 adds beside them) live in
// common/crypto/ and are written to be STAGED flat beside their callers:
// client/build.js and client/Dockerfile copy them into client/src before
// browserify runs, so `require("./pqc")` in jws.js finds a sibling. That is
// right for a bundle and wrong for node, which resolves a relative require
// against the directory the requiring file is in — so a checkout that loads
// client/src/jws.js in node (most of tests/, and common/generate_tls_cert.js
// under every launcher) gets `Cannot find module './pqc'`.
//
// install() closes that gap without a staged copy. It wraps node's resolver
// so that, ONLY when ordinary resolution has already failed:
//
//   1. a `./<name>` or `./<name>.js` request whose <name>.js exists in
//      common/crypto/ resolves to that file; and
//   2. a bare package request (`@noble/...`, `bunyan`, `node-forge`) made BY a
//      file in common/crypto/ is retried against the node_modules beside the
//      repository's client/, tests/ and api/ packages, plus any the caller
//      names — common/ has no node_modules of its own.
//
// Because both rules fire only after a MODULE_NOT_FOUND, a tree in which the
// files are already flat (the tests image, a staged client/src) resolves
// exactly as it did without this, and so does every package with its own
// node_modules.
//
// It is in common/ and NOT in common/crypto/ on purpose: everything in that
// directory is staged into the browser bundles, and this file is node-only.
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");
const Module = require("module");

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// common/ is outside the reach of tests/node_modules — see common/tests.js.
// So this is the same call shape backed by console, writing to STDERR,
// because common/generate_tls_cert.js loads this and its stdout is a channel
// a shell parses. Debug output is off by default; flip DEBUG to follow a
// call through. The methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[crypto_resolve]";
var log = {
  debug: function () {
    if (!DEBUG) {
      return;
    }
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

// Where common/crypto/ is. This file sits in common/ in a checkout, but the
// tests image copies it FLAT beside the test scripts (/usr/src/app), where
// common/crypto/ is /usr/src/common/crypto — so both are candidates.
function findCryptoDir() {
  log.debug("Entering findCryptoDir().");
  const candidates = [
    path.join(__dirname, "crypto"),
    path.join(__dirname, "..", "common", "crypto")
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      log.debug("Leaving findCryptoDir(). " + candidate);
      return candidate;
    }
  }
  log.debug("Leaving findCryptoDir(). Not found.");
  return null;
}

const CRYPTO_DIR = findCryptoDir();
const fallbackModules = [];
let installed = false;

function addFallback(dir) {
  log.debug("Entering addFallback(). dir=" + dir);
  if (fs.existsSync(dir) && fallbackModules.indexOf(dir) === -1) {
    fallbackModules.push(dir);
  }
  log.debug("Leaving addFallback().");
}

// The common/crypto/ file a failed relative request names, or null.
function cryptoTarget(request) {
  log.debug("Entering cryptoTarget(). request=" + request);
  const match = /^\.\/([A-Za-z0-9_]+)(\.js)?$/.exec(request);
  if (!CRYPTO_DIR || !match) {
    log.debug("Leaving cryptoTarget(). Not a sibling request.");
    return null;
  }
  const candidate = path.join(CRYPTO_DIR, match[1] + ".js");
  if (!fs.existsSync(candidate)) {
    log.debug("Leaving cryptoTarget(). No such module in common/crypto.");
    return null;
  }
  log.debug("Leaving cryptoTarget(). " + candidate);
  return candidate;
}

function isBareRequest(request) {
  log.debug("Entering isBareRequest().");
  const bare = !request.startsWith(".") && !path.isAbsolute(request) &&
      !request.startsWith("node:");
  log.debug("Leaving isBareRequest(). " + bare);
  return bare;
}

// Install the resolver once per process. `extraModules` is an optional list
// of further node_modules directories for rule 2.
function install(extraModules) {
  log.debug("Entering install().");
  if (CRYPTO_DIR) {
    const root = path.join(CRYPTO_DIR, "..", "..");
    ["client", "tests", "api"].forEach(function (pkg) {
      addFallback(path.join(root, pkg, "node_modules"));
    });
  }
  (extraModules || []).forEach(addFallback);
  if (installed) {
    log.debug("Leaving install(). Already installed.");
    return CRYPTO_DIR;
  }
  installed = true;
  const original = Module._resolveFilename;
  Module._resolveFilename = function (request, parent, isMain, options) {
    try {
      return original.call(this, request, parent, isMain, options);
    } catch (e) {
      if (e.code !== "MODULE_NOT_FOUND" || !parent || !parent.filename) {
        throw e;
      }
      const target = cryptoTarget(request);
      if (target) {
        return target;
      }
      if (CRYPTO_DIR && fallbackModules.length > 0 &&
          path.dirname(parent.filename) === CRYPTO_DIR &&
          isBareRequest(request)) {
        return original.call(this, request, parent, isMain,
          Object.assign({}, options, { paths: fallbackModules }));
      }
      throw e;
    }
  };
  log.debug("Leaving install(). " + CRYPTO_DIR);
  return CRYPTO_DIR;
}

module.exports = {
  install: install,
  CRYPTO_DIR: CRYPTO_DIR
};
