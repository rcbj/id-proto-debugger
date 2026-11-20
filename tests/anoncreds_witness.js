// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_witness.js
//
// ---------------------------------------------------------------------------
// WHERE THE ANONCREDS WITNESS IS (#479): anoncreds-rs v0.2.3 with its node
// binding @hyperledger/anoncreds-nodejs 0.5.0, as
// tests/anoncreds-witness/Dockerfile builds it into the private mirror. A
// shared module, not a test; the AnonCreds jobs require it.
//
// In order:
//
//   1. ANONCREDS_WITNESS_DIR, a directory holding that node_modules (a
//      working copy someone installed by hand);
//   2. /usr/src/anoncreds-witness, where tests/Dockerfile copies it;
//   3. a host cache, ~/.cache/id-proto-debugger/anoncreds-witness/<tag>,
//      copied once out of the mirror image with `docker create` + `docker
//      cp`, the way iya-sts's tree is (module_paths.js iyaStsTree()).
//
// When none can be had the job FAILS naming the image, rather than skipping:
// a witness that is quietly absent is a suite that checks nothing.
// ---------------------------------------------------------------------------

const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");
const url = require("url");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds_witness",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const TAG = "anoncreds-witness:0.5.0-0.2.3";
const BINDING = path.join("node_modules", "@hyperledger",
                          "anoncreds-nodejs");

function image() {
  log.debug("Entering image().");
  var mirror = process.env.IMAGE_MIRROR ||
    "ghcr.io/rcbj/id-proto-debugger/mirror";
  log.debug("Leaving image().");
  return process.env.ANONCREDS_WITNESS_IMAGE || mirror + "/" + TAG;
}

function holds(dir) {
  log.debug("Entering holds(). " + dir);
  var ok = !!dir && fs.existsSync(path.join(dir, BINDING, "native",
                                            "libanoncreds.so"));
  log.debug("Leaving holds(). " + ok);
  return ok;
}

function docker(args) {
  log.debug("Entering docker(). " + args[0]);
  var r = childProcess.spawnSync("docker", args, { encoding: "utf8" });
  log.debug("Leaving docker(). " + r.status);
  return r;
}

function fromImage() {
  log.debug("Entering fromImage().");
  var img = image();
  var dir = path.join(os.homedir(), ".cache", "id-proto-debugger",
                      "anoncreds-witness", img.replace(/[^A-Za-z0-9._-]+/g,
                                                       "_"));
  if (holds(dir)) {
    log.debug("Leaving fromImage(). Cached.");
    return dir;
  }
  // A FROM scratch image has no command, so create needs one; it never runs.
  var created = docker(["create", img, "/none"]);
  var cid = (created.stdout || "").trim();
  if (created.status !== 0 || !cid) {
    log.debug("Leaving fromImage(). docker create failed.");
    throw new Error("could not create a container from " + img + " (`docker " +
                    "login ghcr.io` first?): " +
                    (created.stderr || "").trim());
  }
  // Pooled jobs reach this at the same moment, so each copies into a
  // directory of its own and RENAMES it into place: two `docker cp`s into
  // one directory fail with "file exists" part-way through. The loser of the
  // rename uses the winner's copy.
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  var tmp = fs.mkdtempSync(dir + ".tmp-");
  var copied;
  try {
    copied = docker(["cp", cid + ":/anoncreds/.", tmp + "/"]);
  } finally {
    docker(["rm", "-f", cid]);
  }
  if (copied.status !== 0 || !holds(tmp)) {
    fs.rmSync(tmp, { recursive: true, force: true });
    log.debug("Leaving fromImage(). docker cp failed.");
    throw new Error("could not copy the witness out of " + img + ": " +
                    (copied.stderr || "").trim());
  }
  publish(tmp, dir);
  log.debug("Leaving fromImage(). Copied to " + dir + ".");
  return dir;
}

// Move a complete copy into place, or keep the one another job put there.
function publish(tmp, dir) {
  log.debug("Entering publish().");
  if (fs.existsSync(dir) && !holds(dir)) {
    // An incomplete copy from an older run that died part-way.
    fs.rmSync(dir, { recursive: true, force: true });
  }
  try {
    fs.renameSync(tmp, dir);
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (!holds(dir)) {
      log.debug("Leaving publish(). Rename failed.");
      throw e;
    }
  }
  log.debug("Leaving publish().");
}

function witnessDir() {
  log.debug("Entering witnessDir().");
  var candidates = [process.env.ANONCREDS_WITNESS_DIR,
                    "/usr/src/anoncreds-witness"];
  for (var i = 0; i < candidates.length; i++) {
    if (holds(candidates[i])) {
      log.debug("Leaving witnessDir(). " + candidates[i]);
      return candidates[i];
    }
  }
  try {
    var dir = fromImage();
    log.debug("Leaving witnessDir(). " + dir);
    return dir;
  } catch (e) {
    log.debug("Leaving witnessDir(). None.");
    throw new Error("the AnonCreds witness (anoncreds-rs) is not available: " +
                    "set ANONCREDS_WITNESS_DIR, or make " + image() +
                    " pullable. " + e.message);
  }
}

// { anoncreds (the native binding, registered), ac (the shared API:
// Schema, CredentialDefinition, ...) }.
async function load() {
  log.debug("Entering load().");
  var dir = witnessDir();
  var binding = await import(url.pathToFileURL(path.join(dir, BINDING,
                                               "build", "index.mjs")).href);
  var shared = await import(url.pathToFileURL(path.join(dir, "node_modules",
    "@hyperledger", "anoncreds-shared", "build", "index.mjs")).href);
  log.info("AnonCreds witness: anoncreds-rs " + binding.anoncreds.version() +
           " from " + dir + ".");
  log.debug("Leaving load().");
  return { anoncreds: binding.anoncreds, ac: shared };
}

module.exports = { TAG: TAG, image: image, witnessDir: witnessDir,
                   load: load };
