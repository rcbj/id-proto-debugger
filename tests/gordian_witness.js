// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_witness.js
//
// ---------------------------------------------------------------------------
// WHERE THE GORDIAN ENVELOPE WITNESS IS (#480): Blockchain Commons'
// bc-envelope-cli 0.35.0, as tests/gordian-witness/Dockerfile builds it into
// the private mirror. A shared module, not a test; gordian_envelope_engine.js
// requires it.
//
// In order:
//
//   1. GORDIAN_ENVELOPE_CLI, the path of an `envelope` binary (one built by
//      hand: cargo install --locked bc-envelope-cli@0.35.0);
//   2. /usr/local/bin/bc-envelope, where tests/Dockerfile copies it;
//   3. a host cache, ~/.cache/id-proto-debugger/gordian-witness/<image>,
//      copied once out of the mirror image with `docker create` + `docker
//      cp`, as tests/anoncreds_witness.js does.
//
// When none can be had the job FAILS naming the image, rather than skipping:
// a witness that is quietly absent is a suite that checks nothing.
// ---------------------------------------------------------------------------

const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gordian_witness",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const TAG = "gordian-witness:0.35.0";
const VERSION = "bc-envelope-cli 0.35.0";

function image() {
  log.debug("Entering image().");
  var mirror = process.env.IMAGE_MIRROR ||
    "ghcr.io/rcbj/id-proto-debugger/mirror";
  log.debug("Leaving image().");
  return process.env.GORDIAN_WITNESS_IMAGE || mirror + "/" + TAG;
}

// The binary's own --version, or "" when it is not one that runs.
function versionOf(bin) {
  log.debug("Entering versionOf(). " + bin);
  if (!bin || !fs.existsSync(bin)) {
    log.debug("Leaving versionOf(). Absent.");
    return "";
  }
  var r = childProcess.spawnSync(bin, ["--version"], { encoding: "utf8" });
  log.debug("Leaving versionOf(). " + r.status);
  return r.status === 0 ? (r.stdout || "").trim() : "";
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
                      "gordian-witness", img.replace(/[^A-Za-z0-9._-]+/g,
                                                     "_"));
  var bin = path.join(dir, "envelope");
  if (versionOf(bin)) {
    log.debug("Leaving fromImage(). Cached.");
    return bin;
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
  fs.mkdirSync(dir, { recursive: true });
  // Pooled jobs reach this at the same moment, so each copies to a name of
  // its own and RENAMES it into place, which is atomic: a second `docker cp`
  // onto the same path would hand the first job a half-written binary.
  var tmp = bin + ".tmp-" + process.pid + "-" + Date.now();
  var copied;
  try {
    copied = docker(["cp", cid + ":/envelope/envelope", tmp]);
  } finally {
    docker(["rm", "-f", cid]);
  }
  if (copied.status !== 0 || !versionOf(tmp)) {
    fs.rmSync(tmp, { force: true });
    log.debug("Leaving fromImage(). docker cp failed.");
    throw new Error("could not copy the witness out of " + img + ": " +
                    (copied.stderr || "").trim());
  }
  fs.renameSync(tmp, bin);
  log.debug("Leaving fromImage(). Copied to " + bin + ".");
  return bin;
}

// The path of a bc-envelope-cli binary of the pinned version.
function binary() {
  log.debug("Entering binary().");
  var candidates = [process.env.GORDIAN_ENVELOPE_CLI,
                    "/usr/local/bin/bc-envelope"];
  for (var i = 0; i < candidates.length; i++) {
    var v = versionOf(candidates[i]);
    if (v) {
      if (v !== VERSION) {
        log.warn("Gordian witness " + candidates[i] + " is " + v + ", not " +
                 VERSION + ".");
      }
      log.debug("Leaving binary(). " + candidates[i]);
      return candidates[i];
    }
  }
  try {
    var bin = fromImage();
    log.debug("Leaving binary(). " + bin);
    return bin;
  } catch (e) {
    log.debug("Leaving binary(). None.");
    throw new Error("the Gordian Envelope witness (bc-envelope-cli) is not " +
                    "available: set GORDIAN_ENVELOPE_CLI, or make " + image() +
                    " pullable. " + e.message);
  }
}

// run(args...) -> stdout, trimmed; throws with the tool's stderr.
function runner() {
  log.debug("Entering runner().");
  var bin = binary();
  log.info("Gordian witness: " + versionOf(bin) + " at " + bin + ".");
  log.debug("Leaving runner().");
  return function run() {
    var args = Array.prototype.slice.call(arguments);
    var r = childProcess.spawnSync(bin, args, { encoding: "utf8" });
    if (r.status !== 0) {
      throw new Error("envelope " + args[0] + ": " +
                      (r.stderr || r.stdout || "").trim());
    }
    return (r.stdout || "").trim();
  };
}

module.exports = { TAG: TAG, VERSION: VERSION, binary: binary,
                   runner: runner };
