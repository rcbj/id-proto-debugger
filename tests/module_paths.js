// File: module_paths.js
//
// ---------------------------------------------------------------------------
// Makes the tests' own dependencies resolvable for a module borrowed from
// client/src.
//
// Two tests exercise the real in-browser modules rather than a copy of their
// logic: xmlsec_interop.js loads common/xmldsig.js, and
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
// ---------------------------------------------------------------------------
// THE MOCK'S OWN LAYOUT IS NOT FLAT ANY MORE, AND THIS IS WHERE THAT IS
// ABSORBED.
//
// Until mock-sts 0f986b3 ("Reorganizing source code.") every module in that
// repository sat in its root, so `sts/krb5_kdc.js` was the whole of the
// question. That commit moved all of them into subdirectories — `common/`,
// `kerberos/`, `oauth-oidc/`, `oid4vc/`, `saml/`, `scim/`, `authn/`, `ldap/`,
// `tls/`, `ws-trust/`, `ws-federation/`, `mgmt-api/`, `admin-ui/`, `spiffe/`
// and `common/vendored/` — and a resolver that only looked in the root then
// found NOTHING, in four Kerberos tests at once, each of which reports it as
// "could not find the mock KDC" and blames the gitlink.
//
// So this searches for the module BY NAME rather than holding a name → folder
// table. A table would be a second transcription of somebody else's directory
// layout, kept in this repository, and it would be wrong again the next time
// that layout moved — which is exactly the failure being fixed here. The
// search is bounded to the root, its immediate subdirectories and
// `common/vendored` (one level deeper, and the only place a two-level module
// lives), so it cannot wander into `node_modules` and cannot cost more than a
// couple of readdirs.
//
// It also still finds the OLD flat layout, because the root is searched first —
// which matters for the tests image, where the files are copied in under
// `tests/sts/` mirroring the new structure, and for a sibling checkout that
// somebody has not yet pulled.
// ---------------------------------------------------------------------------
const MOCK_STS_SKIP_DIRS = ["node_modules", ".git", "node-ldapjs", "env",
                            "protos", "contexts", "coverage"];

function mockStsSearchDirs(root) {
  const dirs = [root];
  let entries = [];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (e) {
    // An uninitialised submodule is an EMPTY DIRECTORY rather than a missing
    // one, and a path that is neither is simply not a candidate. Either way
    // there is nothing to search and the caller's next candidate is tried.
    return dirs;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (MOCK_STS_SKIP_DIRS.indexOf(entry.name) >= 0) continue;
    dirs.push(path.join(root, entry.name));
  }
  // The one module directory that is two levels down: the mock's vendored
  // copies of this project's own client modules (bbs2023.js and friends).
  dirs.push(path.join(root, "common", "vendored"));
  return dirs;
}

function findInMockSts(root, name) {
  for (const dir of mockStsSearchDirs(root)) {
    const candidate = path.join(dir, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

// ---------------------------------------------------------------------------
// CONFIG_FILE HAS TO MEAN THE SAME FILE INSIDE THE MOCK AS IT DOES OUT HERE.
//
// Every test script here opens with `require(process.env.CONFIG_FILE)`, and
// node resolves that relative path against the MODULE doing the requiring —
// tests/ — so `./env/test-idptools-com.js` is tests/env/test-idptools-com.js
// and always has been. The mock STS cannot use that rule: thirteen of its
// modules read the same variable from four different directories, so
// sts/common/config_file.js resolves it ONCE against two candidates of its own
// — the mock's package root, then the process's CWD.
//
// Neither candidate is tests/. On a local run that goes unnoticed because
// sts/env/local.js exists and the first candidate hits; on a run against a
// deployed site CONFIG_FILE is ./env/test-idptools-com.js, the mock has no such
// file, and run-report.js spawns every job from the REPOSITORY ROOT rather than
// from tests/, so the CWD candidate misses too. config_file.js then leaves the
// path relative — deliberately, so its guarded readers still load — and
// sts/common/config.js, which is the one unguarded reader, dies on
// `require('./env/test-idptools-com.js')` resolved against sts/common/. The
// message names a file nobody typed a path to and no line of it says
// "CONFIG_FILE", "sts" or "tests".
//
// So the gap is closed on THIS side, where the file actually lives, and only
// when the mock's own two candidates would both miss. That last part is what
// keeps a local run byte-identical: sts/env/local.js is still preferred over
// tests/env/local.js, because it is the mock's OWN configuration and carries
// its keys, and this project must not start quietly substituting one for the
// other. The rewrite is to an ABSOLUTE path, which is what config_file.js
// itself would have written and what makes it idempotent for the next reader.
// ---------------------------------------------------------------------------
function alignConfigFileForMockSts(stsRoot, say) {
  const given = process.env.CONFIG_FILE;
  // The same three cases config_file.js leaves alone: unset (a leaf module
  // loaded with no configuration at all), already absolute, or a bare
  // specifier naming an installed package rather than a path.
  if (!given || path.isAbsolute(given) || !given.startsWith(".")) {
    return given;
  }
  const mockWouldFind = [
    path.resolve(stsRoot, given),
    path.resolve(process.cwd(), given)
  ];
  for (const candidate of mockWouldFind) {
    if (fs.existsSync(candidate)) {
      return given;
    }
  }
  const here = path.resolve(__dirname, given);
  if (!fs.existsSync(here)) {
    // Nothing this side can offer either. Left exactly as it was, so the
    // failure is the one the operator's own path produces rather than one
    // invented here about a file that was never found.
    return given;
  }
  say("CONFIG_FILE=" + given + " names no file the mock STS can resolve " +
    "(it looks under " + stsRoot + " and under the current directory, " +
    process.cwd() + "). It does name " + here + ", which is what every test " +
    "script here means by it, so CONFIG_FILE is being made absolute to that " +
    "before the mock's modules read it.");
  process.env.CONFIG_FILE = here;
  return here;
}

function mockStsModule(name, warn) {
  const say = warn || function () {};
  const override = process.env.MOCK_STS_DIR;
  if (override) {
    const overridden = findInMockSts(override, name);
    if (overridden) {
      say("MOCK_STS_DIR is set, so " + overridden + " is being used INSTEAD of the sts/ " +
        "submodule. This run reflects a working copy rather than the commit the gitlink points " +
        "at. Unset MOCK_STS_DIR to test what is committed.");
      alignConfigFileForMockSts(override, say);
      return overridden;
    }
    say("MOCK_STS_DIR is set to " + override + " but it does not contain " + name +
      "; falling back to the submodule.");
  }
  const roots = [
    // a checkout with the submodule initialised, then the tests image
    path.join(__dirname, "..", "sts"),
    path.join(__dirname, "sts")
  ];
  for (const root of roots) {
    const found = findInMockSts(root, name);
    if (found) {
      alignConfigFileForMockSts(root, say);
      return found;
    }
  }
  // The tests image also flattens two modules with a prefix, because they are
  // loaded on their own and have no relative requires to satisfy.
  const flattened = path.join(__dirname, "sts_" + name);
  if (fs.existsSync(flattened)) return flattened;
  const siblingRoot = path.join(__dirname, "..", "..", "mock-sts");
  const sibling = findInMockSts(siblingRoot, name);
  if (sibling) {
    alignConfigFileForMockSts(siblingRoot, say);
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
  mockStsModule: mockStsModule,
  // Exported for tests/krb5_codec_sync.js, which needs the same "where does
  // the mock keep its modules now" answer for a whole DIRECTORY rather than
  // for one file, and must not grow a second copy of the layout.
  mockStsSearchDirs: mockStsSearchDirs,
  findInMockSts: findInMockSts,
  // Exported so a test can assert the rewrite rather than only benefit from
  // it — see tests/config_file_resolution.js.
  alignConfigFileForMockSts: alignConfigFileForMockSts
};
