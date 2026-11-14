#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: native.js
//
// ---------------------------------------------------------------------------
// RUN THE API NATIVELY — ON LINUX, MACOS OR WINDOWS — FROM A CHECKOUT.
//
//   node api/native.js [--smartcard] [--config env/local.js]
//
// The api normally runs in a container, and on Linux a container reaches a
// smart card through the host's pcscd socket (docker-compose-smartcard.yml).
// On macOS and Windows it cannot: Docker Desktop runs containers in a VM
// with no view of the host's smart-card service. Running the api as an
// ordinary process puts it beside the OS's own PC/SC — pcsc-lite on Linux,
// the PCSC framework (CryptoTokenKit) on macOS, WinSCard on Windows — and
// the `pcsclite` module binds to whichever this is. Nothing else changes:
// the page talks to https://localhost:4000 as it always does.
//
// What this does that `node server.js` alone does not, because the image
// does it at build time:
//
//   * NODE_PATH is api/node_modules, so common/data.js and common/xmldsig.js
//     — which server.js loads from ../common in a checkout — find their
//     packages, and CONFIG_FILE is made absolute, because those modules
//     require() it from common/ rather than from api/;
//   * the stack's TLS pair is made with common/generate_tls_cert.js when
//     generated-tls/ has none (generate-tls-cert.sh is bash, which Windows
//     does not have), and passed as TLS_CERT_FILE / TLS_KEY_FILE;
//   * with --smartcard, SMARTCARD_READER_ENABLED=true (which env/local.js
//     reads) and a check that `pcsclite` loads, naming what this OS needs
//     when it does not.
//
// Stop the containerized api first (it holds port 4000): run the rest of
// the stack with `docker-compose up client sts`, or without it.
//
// Uses only node's own modules, because it runs before anything is
// installed: so its `log` is console-backed rather than bunyan, like the
// build scripts' (see the repo-root CLAUDE.md). The shim's own methods are
// the one place the Entering/Leaving convention cannot apply.
// ---------------------------------------------------------------------------

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

var DEBUG = process.env.NATIVE_DEBUG === "1";
var log = {
  debug: function () {
    if (DEBUG) {
      console.log.apply(console, ["[native]"].concat(
        Array.prototype.slice.call(arguments)));
    }
  },
  info: function () {
    console.log.apply(console, ["[native]"].concat(
      Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console, ["[native]"].concat(
      Array.prototype.slice.call(arguments)));
  }
};

const API = __dirname;
const ROOT = path.join(API, "..");

function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  const out = { smartcard: false, config: "env/local.js" };
  for (let at = 0; at < argv.length; at += 1) {
    if (argv[at] === "--smartcard") {
      out.smartcard = true;
    } else if (argv[at] === "--config" && argv[at + 1]) {
      out.config = argv[at + 1];
      at += 1;
    } else {
      log.debug("Leaving parseArgs(). Unknown argument.");
      throw new Error("unknown argument " + argv[at] + ". Usage: node " +
                      "api/native.js [--smartcard] [--config env/local.js]");
    }
  }
  log.debug("Leaving parseArgs().");
  return out;
}

// What this OS needs for PC/SC, said once when `pcsclite` does not load.
function pcscAdvice() {
  log.debug("Entering pcscAdvice().");
  const advice = {
    linux: "Install pcscd and the PC/SC headers (Debian/Ubuntu: `sudo apt " +
      "install pcscd libpcsclite-dev python3 make g++`; Fedora: `sudo dnf " +
      "install pcsc-lite pcsc-lite-devel gcc-c++ make`), make sure pcscd " +
      "is running, then `npm install` in api/.",
    darwin: "macOS has PC/SC built in. Install the Xcode command line tools " +
      "(`xcode-select --install`) so the binding can compile, then " +
      "`npm install` in api/.",
    win32: "Windows has PC/SC built in (the Smart Card service starts when " +
      "a reader appears). Install the Visual Studio Build Tools with the " +
      "'Desktop development with C++' workload and Python 3 so the binding " +
      "can compile, then `npm install` in api\\."
  };
  log.debug("Leaving pcscAdvice().");
  return advice[process.platform] || "Install your OS's PC/SC library " +
    "and headers and a C++ compiler, then `npm install` in api/.";
}

function pcscLoads() {
  log.debug("Entering pcscLoads().");
  const probe = spawnSync(process.execPath, ["-e", "require('pcsclite')"], {
    cwd: API, env: Object.assign({}, process.env,
      { NODE_PATH: path.join(API, "node_modules") }),
    encoding: "utf8"
  });
  const ok = probe.status === 0;
  log.debug("Leaving pcscLoads(). " + ok);
  return { ok: ok, why: (probe.stderr || "").split("\n").filter(Boolean)
    .slice(0, 3).join(" ") };
}

// The stack's TLS pair, made the way generate-tls-cert.sh makes it.
function tlsPair() {
  log.debug("Entering tlsPair().");
  const dir = path.join(ROOT, "generated-tls");
  const cert = path.join(dir, "stack-tls-cert.pem");
  const key = path.join(dir, "stack-tls-key.pem");
  if (fs.existsSync(cert) && fs.existsSync(key)) {
    log.debug("Leaving tlsPair(). Present.");
    return { cert: cert, key: key };
  }
  const clientModules = path.join(ROOT, "client", "node_modules");
  if (!fs.existsSync(path.join(clientModules, "pkijs"))) {
    log.debug("Leaving tlsPair(). No client packages.");
    throw new Error("generated-tls/ has no certificate, and making one " +
      "needs the client's packages (client/src/x509.js uses pkijs). Run " +
      "`npm ci --prefix client`, or ./generate-tls-cert.sh where there is " +
      "bash, and start again.");
  }
  log.info("No TLS pair in generated-tls/; making one.");
  const made = spawnSync(process.execPath, [
    path.join(ROOT, "common", "generate_tls_cert.js"),
    "--out-dir", dir, "--ca-dir", path.join(ROOT, "generated-tls-ca")
  ], { cwd: ROOT, stdio: "inherit",
       env: Object.assign({}, process.env, { NODE_PATH: clientModules }) });
  if (made.status !== 0 || !fs.existsSync(cert)) {
    log.debug("Leaving tlsPair(). The generator failed.");
    throw new Error("common/generate_tls_cert.js did not make a pair.");
  }
  log.info("Trust generated-tls-ca/stack-tls-root.pem in this browser " +
           "once, or accept the warning on both 3000 and 4000.");
  log.debug("Leaving tlsPair(). Made.");
  return { cert: cert, key: key };
}

function main() {
  log.debug("Entering main().");
  const args = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(path.join(API, "node_modules", "express"))) {
    log.debug("Leaving main(). No install.");
    throw new Error("api/node_modules is missing. Run `npm install` in " +
                    "api/ first.");
  }
  const config = path.resolve(API, args.config);
  if (!fs.existsSync(config)) {
    log.debug("Leaving main(). No config.");
    throw new Error("no config at " + config);
  }
  const tls = tlsPair();
  // The client's packages too, when installed: the HID path for OTP
  // challenge-response (api/otp_hid.js) runs client/src/yubico_otp.js.
  const clientModules = path.join(ROOT, "client", "node_modules");
  const nodePath = [path.join(API, "node_modules")].concat(
    fs.existsSync(clientModules) ? [clientModules] : []).join(path.delimiter);
  const env = Object.assign({}, process.env, {
    CONFIG_FILE: config,
    NODE_PATH: nodePath,
    TLS_CERT_FILE: process.env.TLS_CERT_FILE || tls.cert,
    TLS_KEY_FILE: process.env.TLS_KEY_FILE || tls.key
  });
  if (args.smartcard) {
    const pcsc = pcscLoads();
    if (!pcsc.ok) {
      log.error("The smart-card relay is on, but `pcsclite` does not load " +
                "here (" + pcsc.why + "). " + pcscAdvice() + " The api " +
                "starts anyway, and the page says PC/SC is missing.");
    } else {
      log.info("PC/SC: pcsclite loads on " + os.platform() + ".");
    }
    if (!fs.existsSync(path.join(API, "node_modules", "node-hid"))) {
      log.info("HID: node-hid is not installed, so OTP challenge-response " +
               "from a browser with no WebHID is unavailable. `npm install` " +
               "in api/ installs it (prebuilt for Linux, macOS, Windows).");
    }
    if (!fs.existsSync(clientModules)) {
      log.info("HID: client/node_modules is missing; OTP " +
               "challenge-response over HID also needs `npm ci --prefix " +
               "client`.");
    }
    env.SMARTCARD_READER_ENABLED = "true";
  }
  log.info("Starting the api natively on " + os.platform() + " (" +
           os.arch() + ") with " + path.relative(ROOT, config) +
           (args.smartcard ? ", reader relay ON" : "") + ".");
  const child = spawn(process.execPath, ["server.js"], { cwd: API, env: env,
                                                         stdio: "inherit" });
  child.on("exit", function (code, signal) {
    log.info("The api exited (" + (signal || code) + ").");
    process.exitCode = code === null ? 1 : code;
  });
  ["SIGINT", "SIGTERM"].forEach(function (sig) {
    process.on(sig, function () {
      child.kill(sig);
    });
  });
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error(e.message);
  process.exitCode = 1;
}
