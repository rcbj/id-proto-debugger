// File: build.js — emits the three unpacked builds from one source tree.
//
//   dist/chrome    what a user loads through chrome://extensions
//   dist/firefox   what a user loads through about:debugging
//   dist/ci        chrome, plus autoarm.json, for the browser test
//
// The CI build exists because a WebDriver session cannot click the browser's
// native permission dialog. It differs from the shipped build in ONE way — a
// bundled autoarm.json naming the origin to observe — and
// tests/webauthn_extension.js asserts that difference is the only one. A
// test-only bypass inside the arm path would mean CI exercising a code path
// users never run.
//
// The version is the repo's M.N.O, stamped here, because an unpacked extension
// does not auto-update and the debugger's pages compare their build against the
// extension's. Omit the stamp and it silently reads 0.0.0 — the same trap the
// client and api images carry a COPY VERSION for.
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// extension/ has no package.json of its own.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[build]";
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

const HERE = __dirname;
const SRC = path.join(HERE, "src");
const DIST = path.join(HERE, "dist");
const BASE = JSON.parse(fs.readFileSync(path.join(HERE, "manifest.base.json"),
    "utf8"));

function version() {
  log.debug("Entering version().");
  // client/version.js owns the M.N.O scheme for the whole repository; reuse it
  // rather than reimplementing, so a release bump moves everything at once.
  try {
    const out = execFileSync(process.execPath,
      [path.join(HERE, "..", "client", "version.js"), "--print"],
       { encoding: "utf8" }).trim();
    if (/^\d+\.\d+\.\d+$/.test(out)) {
      log.debug("Leaving version().");
      return out;
    }
  } catch (e) {
    // version.js has no --print, or is unavailable. Fall through to VERSION.
  }
  try {
    const mn = fs.readFileSync(path.join(HERE, "..", "VERSION"), "utf8").trim();
    const stamp = process.env.BUILD_NUMBER ||
      new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    log.debug("Leaving version().");
    return mn + "." + stamp;
  } catch (e) {
    throw new Error("cannot determine a version: no client/version.js " +
                    "--print and no VERSION file. " +
                    "Shipping 0.0.0 would break the debugger's drift check, " +
                        "so this is fatal.");
  }
}

// A Chrome extension version must be up to four dot-separated integers, each
// under 65536. The M.N.O stamp is YYYYMMDDHHMMSS, far past that, so it is split
// into parts the browser will accept while staying recognisable.
function manifestVersion(v) {
  log.debug("Entering manifestVersion().");
  const parts = v.split(".");
  const stamp = parts[2] || "0";
  log.debug("Leaving manifestVersion().");
  return [parts[0], parts[1], stamp.slice(0, 8) % 65536 || 1,
          stamp.slice(8) % 65536 || 0].join(".");
}

const FILES = ["shim.js", "relay.js", "background.js", "bridge.js",
    "popup.html", "popup.js"];

function emit(name, mutate) {
  log.debug("Entering emit().");
  const out = path.join(DIST, name);
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  FILES.forEach(function (f) {
    fs.copyFileSync(path.join(SRC, f), path.join(out, f));
  });
  const manifest = JSON.parse(JSON.stringify(BASE));
  const v = version();
  manifest.version = manifestVersion(v);
  manifest.version_name = v;
  mutate(manifest, out);
  fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest,
                   null, 2) + "\n");
  console.log("[extension] wrote " + path.relative(HERE, out) + " (version " +
              manifest.version +
              ", version_name " + v + ")");
  log.debug("Leaving emit().");
}

emit("chrome", function () {});

emit("firefox", function (manifest) {
  // Firefox wants an explicit id for a temporary add-on, and an event page
  // rather than a service worker.
  manifest.browser_specific_settings = {
    gecko: { id: "webauthn-observer@idptools.com",
            strict_min_version: "128.0" },
  };
  manifest.background = { scripts: ["background.js"] };
});

emit("ci", function (manifest, out) {
  const origins = (process.env.EXTENSION_AUTOARM_ORIGINS ||
      "http://localhost:8099")
    .split(",").map(function (o) { return o.trim(); }).filter(Boolean);
  fs.writeFileSync(path.join(out, "autoarm.json"),
                   JSON.stringify({ origins: origins }, null, 2) + "\n");
  origins.forEach(function (o) {
    manifest.host_permissions.push(o.replace(/\/+$/, "") + "/*");
  });
  console.log("[extension] ci build auto-arms: " + origins.join(", "));
});
