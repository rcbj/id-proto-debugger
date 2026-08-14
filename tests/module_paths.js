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
// look for node-forge / bunyan under client/node_modules — which a checkout
// that has installed only the tests' dependencies does not have.
//
// Those packages are dependencies of THIS package, so tests/node_modules is
// added as a global resolution fallback and the shared modules load either way.
// In the tests container the shared files are copied next to the test scripts,
// so their requires already resolve from tests/node_modules and this is a
// no-op.
// ---------------------------------------------------------------------------

const path = require("path");
const fs = require("fs");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "module_paths",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function addTestsModulesToResolutionPath() {
  log.debug("Entering addTestsModulesToResolutionPath().");
  const testsModules = path.join(__dirname, "node_modules");
  if (!fs.existsSync(testsModules)) {
    log.debug("Leaving addTestsModulesToResolutionPath().");
    return false;
  }
  const existing = process.env.NODE_PATH ?
      process.env.NODE_PATH.split(path.delimiter) : [];
  if (existing.indexOf(testsModules) >= 0) {
    log.debug("Leaving addTestsModulesToResolutionPath().");
    return true;
  }
  process.env.NODE_PATH = existing.concat([testsModules]).join(path.delimiter);
  require("module").Module._initPaths();
  log.debug("Leaving addTestsModulesToResolutionPath().");
  return true;
}

// Load a module that may live next to the tests (container) or in client/src (a
// checkout), with the resolution fallback applied and a pointed error when a
// dependency of that module is what is actually missing.
function requireSharedModule(candidates, what) {
  log.debug("Entering requireSharedModule().");
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    addTestsModulesToResolutionPath();
    try {
      log.debug("Leaving requireSharedModule().");
      return require(candidate);
    } catch (e) {
      throw new Error("found " + candidate + " but could not load it: " +
                      e.message +
        (/Cannot find module/.test(e.message)
          ? " — run `npm install` in tests/ so the shared module's dependencies resolve."
          : ""));
    }
  }
  throw new Error("could not locate " + what + " (looked in: " +
                  candidates.join(", ") + ")");
}

// ---------------------------------------------------------------------------
// Locating a module that lives in the mock STS.
//
// sts/ is a SUBMODULE — a separate repository (rcbj/mock-sts) — so a change to the
// mock KDC is written in a sibling checkout, pushed there, and only then does this
// repository's gitlink move. Between those two steps the submodule does not carry the
// change, and a test that could not run until the push would make that loop unusable.
//
// Hence three orders of preference, and the middle one is the one that had to be added
// after it cost a debugging round:
//
//  1. Normally: the submodule, then the tests image's flat copies.
//  2. `MOCK_STS_DIR=../mock-sts` — an EXPLICIT override, for verifying a change to a
//     module that ALREADY EXISTS in the submodule. The fallback below cannot help
//     there: the file is present, just stale, so it is found and used and the change
//     under test is silently not exercised. That failure is genuinely confusing,
//     because the test fails asserting something the developer just implemented.
//  3. Otherwise, a sibling checkout if the submodule lacks the file entirely.
//
// Cases 2 and 3 both WARN, naming the reason. A green run against an unpushed working
// copy corresponds to no commit, and that has to be impossible to miss.
// ---------------------------------------------------------------------------
function mockStsModule(name, warn) {
  const say = warn || function () {};
  const override = process.env.MOCK_STS_DIR;
  if (override) {
    const overridden = path.join(override, name);
    if (fs.existsSync(overridden)) {
      say("MOCK_STS_DIR is set, so " + overridden + " is being used INSTEAD of the sts/ " +
        "submodule. This run reflects a working copy rather than the commit the gitlink points " +
        "at. Unset MOCK_STS_DIR to test what is committed.");
      return overridden;
    }
    say("MOCK_STS_DIR is set to " + override + " but it does not contain " + name +
      "; falling back to the submodule.");
  }
  const candidates = [
    path.join(__dirname, "..", "sts", name),         // a checkout with the submodule initialised
    path.join(__dirname, "sts", name),               // the tests image
    path.join(__dirname, "sts_" + name)              // the tests image, flattened with a prefix
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  const sibling = path.join(__dirname, "..", "..", "mock-sts", name);
  if (fs.existsSync(sibling)) {
    say("USING AN UNPUSHED WORKING COPY: " + sibling + ". The sts/ submodule does not carry " +
      name + " yet, so this run reflects a sibling checkout rather than the commit this " +
      "repository's gitlink points at. Push mock-sts and bump the gitlink before trusting a " +
      "green result here.");
    return sibling;
  }
  return null;
}

module.exports = {
  addTestsModulesToResolutionPath: addTestsModulesToResolutionPath,
  requireSharedModule: requireSharedModule,
  mockStsModule: mockStsModule
};
