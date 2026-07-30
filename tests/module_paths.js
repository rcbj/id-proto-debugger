// File: module_paths.js
//
// ---------------------------------------------------------------------------
// Makes the tests' own dependencies resolvable for a module borrowed from
// client/src.
//
// Two tests exercise the real in-browser modules rather than a copy of their
// logic: xmlsec_interop.js loads client/src/xmldsig.js, and
// wstrust_schema_validate.js loads client/src/wstrust_msg.js. Node resolves a
// module's own requires relative to WHERE THAT MODULE LIVES, so those modules
// look for node-forge / bunyan under client/node_modules — which a checkout that
// has installed only the tests' dependencies does not have.
//
// Those packages are dependencies of THIS package, so tests/node_modules is added
// as a global resolution fallback and the shared modules load either way. In the
// tests container the shared files are copied next to the test scripts, so their
// requires already resolve from tests/node_modules and this is a no-op.
// ---------------------------------------------------------------------------

const path = require("path");
const fs = require("fs");

function addTestsModulesToResolutionPath() {
  const testsModules = path.join(__dirname, "node_modules");
  if (!fs.existsSync(testsModules)) return false;
  const existing = process.env.NODE_PATH ? process.env.NODE_PATH.split(path.delimiter) : [];
  if (existing.indexOf(testsModules) >= 0) return true;
  process.env.NODE_PATH = existing.concat([testsModules]).join(path.delimiter);
  require("module").Module._initPaths();
  return true;
}

// Load a module that may live next to the tests (container) or in client/src (a
// checkout), with the resolution fallback applied and a pointed error when a
// dependency of that module is what is actually missing.
function requireSharedModule(candidates, what) {
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    addTestsModulesToResolutionPath();
    try {
      return require(candidate);
    } catch (e) {
      throw new Error("found " + candidate + " but could not load it: " + e.message +
        (/Cannot find module/.test(e.message)
          ? " — run `npm install` in tests/ so the shared module's dependencies resolve."
          : ""));
    }
  }
  throw new Error("could not locate " + what + " (looked in: " + candidates.join(", ") + ")");
}

module.exports = {
  addTestsModulesToResolutionPath: addTestsModulesToResolutionPath,
  requireSharedModule: requireSharedModule
};
