// File: build.js — emits the three unpacked builds from one source tree.
//
//   dist/chrome    what a user loads through chrome://extensions
//   dist/firefox   what a user loads through about:debugging
//   dist/ci        chrome, plus autoarm.json, for the browser test
//
// The CI build exists because a WebDriver session cannot click the browser's
// native permission dialog. It differs from the shipped build in ONE way — a
// bundled autoarm.json naming the origin to observe — and tests/webauthn_extension.js
// asserts that difference is the only one. A test-only bypass inside the arm
// path would mean CI exercising a code path users never run.
//
// The version is the repo's M.N.O, stamped here, because an unpacked extension
// does not auto-update and the debugger's pages compare their build against the
// extension's. Omit the stamp and it silently reads 0.0.0 — the same trap the
// client and api images carry a COPY VERSION for.
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const HERE = __dirname;
const SRC = path.join(HERE, "src");
const DIST = path.join(HERE, "dist");
const BASE = JSON.parse(fs.readFileSync(path.join(HERE, "manifest.base.json"), "utf8"));

function version() {
  // client/version.js owns the M.N.O scheme for the whole repository; reuse it
  // rather than reimplementing, so a release bump moves everything at once.
  try {
    const out = execFileSync(process.execPath,
      [path.join(HERE, "..", "client", "version.js"), "--print"], { encoding: "utf8" }).trim();
    if (/^\d+\.\d+\.\d+$/.test(out)) {
      return out;
    }
  } catch (e) {
    // version.js has no --print, or is unavailable. Fall through to VERSION.
  }
  try {
    const mn = fs.readFileSync(path.join(HERE, "..", "VERSION"), "utf8").trim();
    const stamp = process.env.BUILD_NUMBER ||
      new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    return mn + "." + stamp;
  } catch (e) {
    throw new Error("cannot determine a version: no client/version.js --print and no VERSION file. " +
                    "Shipping 0.0.0 would break the debugger's drift check, so this is fatal.");
  }
}

// A Chrome extension version must be up to four dot-separated integers, each
// under 65536. The M.N.O stamp is YYYYMMDDHHMMSS, far past that, so it is split
// into parts the browser will accept while staying recognisable.
function manifestVersion(v) {
  const parts = v.split(".");
  const stamp = parts[2] || "0";
  return [parts[0], parts[1], stamp.slice(0, 8) % 65536 || 1, stamp.slice(8) % 65536 || 0].join(".");
}

const FILES = ["shim.js", "relay.js", "background.js", "bridge.js", "popup.html", "popup.js"];

function emit(name, mutate) {
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
  fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log("[extension] wrote " + path.relative(HERE, out) + " (version " + manifest.version +
              ", version_name " + v + ")");
}

emit("chrome", function () {});

emit("firefox", function (manifest) {
  // Firefox wants an explicit id for a temporary add-on, and an event page
  // rather than a service worker.
  manifest.browser_specific_settings = {
    gecko: { id: "webauthn-observer@idptools.com", strict_min_version: "128.0" },
  };
  manifest.background = { scripts: ["background.js"] };
});

emit("ci", function (manifest, out) {
  const origins = (process.env.EXTENSION_AUTOARM_ORIGINS || "http://localhost:8099")
    .split(",").map(function (o) { return o.trim(); }).filter(Boolean);
  fs.writeFileSync(path.join(out, "autoarm.json"),
                   JSON.stringify({ origins: origins }, null, 2) + "\n");
  origins.forEach(function (o) {
    manifest.host_permissions.push(o.replace(/\/+$/, "") + "/*");
  });
  console.log("[extension] ci build auto-arms: " + origins.join(", "));
});
