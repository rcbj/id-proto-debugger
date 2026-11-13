// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// Locating a module that lives in iya-sts.
//
// iya-sts is a separate repository (rcbj/iya-sts), and this one no longer
// carries a checkout of it: the stack RUNS its release image
// (IYA_STS_IMAGE, defaulted in docker-compose-run-tests.yml), and a job that
// loads iya-sts's modules in process loads them out of THAT image's
// /usr/src/sts — compiled, with its own node_modules — so the code a job
// loads is the code the stack is talking to. Three orders of preference:
//
//  1. `MOCK_STS_DIR=../iya-sts` — an EXPLICIT override, for verifying a
//     change in a working copy before iya-sts releases it. It WARNS, because
//     a green run against an unreleased tree corresponds to no image.
//  2. The tests image, where tests/Dockerfile copied the image's tree into
//     ./sts (`COPY --from=iyasts /usr/src/sts ./sts`).
//  3. A host run: the same tree, copied out of the image once into a cache
//     directory keyed by the image (iyaStsTree() below).
//
// When none of the three can be had — no docker, an image that cannot be
// pulled — iyaStsTree() THROWS, naming the image and the way out. A job that
// needs iya-sts's code and cannot get it has failed; reporting it as a skip
// is how a check stops running without anybody noticing.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE MOCK'S OWN LAYOUT IS NOT FLAT ANY MORE, AND THIS IS WHERE THAT IS
// ABSORBED.
//
// Until iya-sts 0f986b3 ("Reorganizing source code.") every module in that
// repository sat in its root, so `sts/krb5_kdc.js` was the whole of the
// question. That commit moved all of them into subdirectories — `common/`,
// `kerberos/`, `oauth-oidc/`, `oid4vc/`, `saml/`, `scim/`, `authn/`, `ldap/`,
// `tls/`, `ws-trust/`, `ws-federation/`, `mgmt-api/`, `admin-ui/`, `spiffe/`
// and `common/vendored/` (`common/crypto_impl/` since iya-sts b09958f3, on
// 2026-10-25) — and a resolver that only looked in the root then
// found NOTHING, in four Kerberos tests at once, each of which reports it as
// "could not find the mock KDC" and blames the gitlink.
//
// So this searches for the module BY NAME rather than holding a name → folder
// table. A table would be a second transcription of somebody else's directory
// layout, kept in this repository, and it would be wrong again the next time
// that layout moved — which is exactly the failure being fixed here. The
// search is bounded to the root, its immediate subdirectories and
// `common/crypto_impl` (one level deeper, and the only place a two-level
// module lives; `common/vendored` is the same directory's name before that
// move, and is still searched for a gitlink from before it), so it cannot
// wander into `node_modules` and cannot cost more than a couple of readdirs.
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
  // `common/crypto_impl` since iya-sts b09958f3; `common/vendored` before
  // it, kept so an older gitlink still resolves.
  dirs.push(path.join(root, "common", "crypto_impl"));
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

// ---------------------------------------------------------------------------
// WHICH iya-sts IMAGE, AND WHERE ITS TREE IS ON THIS HOST.
//
// The image is IYA_STS_IMAGE when that is set, and otherwise the default
// docker-compose-run-tests.yml gives `${IYA_STS_IMAGE:-...}` — read out of
// that file rather than written here a second time, so a release bump is one
// edit. (The file sits at the repository root in a checkout and flat beside
// the tests in the tests image.)
//
// That default NESTS another one: it is the private mirror copy,
// `${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}/iya-sts:<version>`,
// so it is read by matching braces rather than up to the first `}`, and the
// inner `${NAME:-default}` is expanded the way compose expands it (the
// variable when set and non-empty, the default otherwise).
// ---------------------------------------------------------------------------
const IYA_STS_IMAGE_OPEN = "${IYA_STS_IMAGE:-";

function expandComposeDefaults(value) {
  log.debug("Entering expandComposeDefaults().");
  const out = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}/g,
    function (all, name, fallback) {
      return process.env[name] ? process.env[name] : fallback;
    });
  log.debug("Leaving expandComposeDefaults().");
  return out;
}

function iyaStsImageDefault(text) {
  log.debug("Entering iyaStsImageDefault().");
  const start = text.indexOf(IYA_STS_IMAGE_OPEN);
  if (start < 0) {
    log.debug("Leaving iyaStsImageDefault(). None.");
    return null;
  }
  let depth = 1;
  for (let i = start + IYA_STS_IMAGE_OPEN.length; i < text.length; i++) {
    if (text.startsWith("${", i)) {
      depth++;
      i++;
    } else if (text.charAt(i) === "}") {
      depth--;
      if (depth === 0) {
        log.debug("Leaving iyaStsImageDefault(). Found.");
        return expandComposeDefaults(
          text.slice(start + IYA_STS_IMAGE_OPEN.length, i));
      }
    } else if (text.charAt(i) === "\n") {
      break;
    }
  }
  log.debug("Leaving iyaStsImageDefault(). Unbalanced.");
  return null;
}

function iyaStsImage() {
  log.debug("Entering iyaStsImage().");
  if (process.env.IYA_STS_IMAGE) {
    log.debug("Leaving iyaStsImage(). From IYA_STS_IMAGE.");
    return process.env.IYA_STS_IMAGE;
  }
  const candidates = [
    path.join(__dirname, "..", "docker-compose-run-tests.yml"),
    path.join(__dirname, "docker-compose-run-tests.yml")
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    const image = iyaStsImageDefault(fs.readFileSync(candidate, "utf8"));
    if (image) {
      log.debug("Leaving iyaStsImage(). Default from " + candidate + ".");
      return image;
    }
  }
  log.debug("Leaving iyaStsImage(). No default found.");
  throw new Error("no iya-sts image: IYA_STS_IMAGE is unset and no " +
    "docker-compose-run-tests.yml names a ${IYA_STS_IMAGE:-...} default " +
    "(looked in: " + candidates.join(", ") + ").");
}

// The docker command, as an argv prefix. IYA_STS_DOCKER is how a launcher
// that reaches the daemon through sudo (common.sh, resolveDockerSudo) says
// so; a plain host run uses `docker`.
function iyaStsDockerArgv() {
  log.debug("Entering iyaStsDockerArgv().");
  const words = (process.env.IYA_STS_DOCKER || "docker").trim().split(/\s+/);
  log.debug("Leaving iyaStsDockerArgv().");
  return words;
}

function iyaStsDocker(args, options) {
  log.debug("Entering iyaStsDocker().");
  const argv = iyaStsDockerArgv();
  const result = require("child_process").spawnSync(argv[0],
    argv.slice(1).concat(args),
    Object.assign({ encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
                  options || {}));
  log.debug("Leaving iyaStsDocker().");
  return result;
}

function iyaStsCacheRoot() {
  log.debug("Entering iyaStsCacheRoot().");
  if (process.env.IYA_STS_TREE_CACHE) {
    log.debug("Leaving iyaStsCacheRoot(). From IYA_STS_TREE_CACHE.");
    return process.env.IYA_STS_TREE_CACHE;
  }
  const base = process.env.XDG_CACHE_HOME ||
    path.join(require("os").homedir(), ".cache");
  log.debug("Leaving iyaStsCacheRoot().");
  return path.join(base, "id-proto-debugger", "iya-sts");
}

// The image's id, pulling it first when it is not on this machine. The id —
// not only the tag — is in the cache key, so a tag that is moved (a
// candidate re-pushed under the same name) cannot be served from a stale
// copy.
function iyaStsImageId(image) {
  log.debug("Entering iyaStsImageId().");
  let inspected = iyaStsDocker(["image", "inspect", "--format", "{{.Id}}",
                                image]);
  if (inspected.status !== 0) {
    const pulled = iyaStsDocker(["pull", "-q", image]);
    if (pulled.status !== 0) {
      log.debug("Leaving iyaStsImageId(). Pull failed.");
      throw new Error("could not pull " + image + " (" +
        ((pulled.stderr || "") + (pulled.error ? pulled.error.message : ""))
          .trim() +
        "). It is a package on ghcr.io; `docker login ghcr.io` with a " +
        "token that can read packages, or set MOCK_STS_DIR to a tree of " +
        "iya-sts that has server.js and node_modules.");
    }
    inspected = iyaStsDocker(["image", "inspect", "--format", "{{.Id}}",
                              image]);
  }
  const id = (inspected.stdout || "").trim().replace(/^sha256:/, "");
  if (inspected.status !== 0 || !id) {
    log.debug("Leaving iyaStsImageId(). Inspect failed.");
    throw new Error("could not inspect " + image + ": " +
      (inspected.stderr || "").trim());
  }
  log.debug("Leaving iyaStsImageId().");
  return id;
}

// ---------------------------------------------------------------------------
// iya-sts's compiled tree on THIS host, copied out of the image once.
//
// `docker create` makes a container without starting it — the documented way
// to read a filesystem out of an image — and `docker cp` takes /usr/src/sts
// out of it into a scratch directory beside the cache entry, which is then
// RENAMED into place. A rename is atomic, so a pool of jobs that all ask at
// once can only ever see a complete tree or none; the losers of that race
// throw their copy away. The cache is keyed by the image reference and its
// id, so a release bump is a new directory and the old one is never reused.
// ---------------------------------------------------------------------------
function iyaStsTree() {
  log.debug("Entering iyaStsTree().");
  const image = iyaStsImage();
  const id = iyaStsImageId(image);
  const key = image.replace(/[^A-Za-z0-9._-]+/g, "_") + "-" + id.slice(0, 12);
  const root = iyaStsCacheRoot();
  const dir = path.join(root, key);
  if (fs.existsSync(path.join(dir, "server.js"))) {
    log.debug("Leaving iyaStsTree(). Cached at " + dir + ".");
    return dir;
  }
  fs.mkdirSync(root, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(root, ".extract-"));
  const created = iyaStsDocker(["create", image]);
  const cid = (created.stdout || "").trim();
  if (created.status !== 0 || !cid) {
    fs.rmSync(scratch, { recursive: true, force: true });
    log.debug("Leaving iyaStsTree(). docker create failed.");
    throw new Error("could not create a container from " + image + ": " +
      (created.stderr || "").trim());
  }
  let copied;
  try {
    copied = iyaStsDocker(["cp", cid + ":/usr/src/sts/.", scratch + "/"]);
  } finally {
    iyaStsDocker(["rm", "-f", cid]);
  }
  if (copied.status !== 0 ||
      !fs.existsSync(path.join(scratch, "server.js")) ||
      !fs.existsSync(path.join(scratch, "node_modules"))) {
    fs.rmSync(scratch, { recursive: true, force: true });
    log.debug("Leaving iyaStsTree(). Nothing usable copied.");
    throw new Error("could not copy a runnable /usr/src/sts out of " + image +
      " (server.js or node_modules missing): " +
      (copied.stderr || "").trim());
  }
  try {
    fs.renameSync(scratch, dir);
  } catch (e) {
    // Another job got there first; its tree is the same image's.
    fs.rmSync(scratch, { recursive: true, force: true });
    if (!fs.existsSync(path.join(dir, "server.js"))) {
      log.debug("Leaving iyaStsTree(). Rename failed.");
      throw e;
    }
  }
  log.debug("Leaving iyaStsTree(). Extracted to " + dir + ".");
  return dir;
}

// The root a job loads iya-sts's modules from, in the order the note at the
// top of this section gives. Never null: it throws instead.
function iyaStsRoot(warn) {
  log.debug("Entering iyaStsRoot().");
  const say = warn || function () {};
  const override = process.env.MOCK_STS_DIR;
  if (override) {
    say("MOCK_STS_DIR is set, so " + override + " is being used INSTEAD " +
      "of the iya-sts image (" + (process.env.IYA_STS_IMAGE || "the " +
      "default") + "). This run reflects that tree rather than a release. " +
      "Unset MOCK_STS_DIR to test what the stack runs.");
    log.debug("Leaving iyaStsRoot(). MOCK_STS_DIR.");
    return override;
  }
  const inImage = path.join(__dirname, "sts");
  if (fs.existsSync(path.join(inImage, "server.js"))) {
    log.debug("Leaving iyaStsRoot(). The tests image's copy.");
    return inImage;
  }
  const extracted = iyaStsTree();
  log.debug("Leaving iyaStsRoot(). Extracted from the image.");
  return extracted;
}

function mockStsModule(name, warn) {
  log.debug("Entering mockStsModule().");
  const say = warn || function () {};
  const root = iyaStsRoot(say);
  const found = findInMockSts(root, name);
  if (found) {
    alignConfigFileForMockSts(root, say);
  }
  log.debug("Leaving mockStsModule().");
  return found;
}

module.exports = {
  addTestsModulesToResolutionPath: addTestsModulesToResolutionPath,
  requireSharedModule: requireSharedModule,
  mockStsModule: mockStsModule,
  // Where iya-sts's tree is, for a test that needs a whole DIRECTORY rather
  // than one file (tests/krb5_codec_sync.js, tests/spiffe_engine.js), and
  // the image it comes from; tests/tools/iya-sts-tree.js is the launchers'
  // way in to the same answer.
  iyaStsRoot: iyaStsRoot,
  iyaStsTree: iyaStsTree,
  iyaStsImage: iyaStsImage,
  // Exported for tests/krb5_codec_sync.js, which needs the same "where does
  // the mock keep its modules now" answer for a whole DIRECTORY rather than
  // for one file, and must not grow a second copy of the layout.
  mockStsSearchDirs: mockStsSearchDirs,
  findInMockSts: findInMockSts,
  // Exported so a test can assert the rewrite rather than only benefit from
  // it — see tests/config_file_resolution.js.
  alignConfigFileForMockSts: alignConfigFileForMockSts
};
