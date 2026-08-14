#!/usr/bin/env node
'use strict';

// Application version: M.N.O
//
//   M.N  major.minor, declared in the repo-root VERSION file (currently 0.9).
//        Bump it there — it is the single source of truth.
//   O    the build number: a value that identifies THIS build and no other.
//        By default it is the UTC build instant as YYYYMMDDHHMMSS, which is
//        unique per build, monotonically increasing, and self-describing (the
//        version alone tells you when the artifact was produced). Set
//        BUILD_NUMBER to override it — e.g. with a CI run number — in which
//        case keeping it unique and increasing is the caller's responsibility.
//
// The number is fixed when an artifact is BUILT, not when it runs: both build
// paths stamp it into a version.json that ships with the artifact, so every
// page of a given deployment reports the same build, and restarting a
// container does not invent a new one.
//
//   client/Dockerfile   runs `node version.js --stamp public` during the image
//                       build; server.js reads that file at startup.
//   client/build.js     stamps dist/ at the start of the static build.
//
// Run directly to print or stamp:
//   node version.js                 -> 0.9.20260726143205
//   node version.js --json          -> the full record
//   node version.js --stamp <dir>   -> writes <dir>/version.json, prints version
//   node version.js --check-manifests  -> non-zero if a package.json is stale
//   node version.js --sync-manifests   -> rewrites stale package.json versions

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// the repo-root VERSION file can be read before any install has happened.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[version]";
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

const VERSION_FILE = 'VERSION';
const STAMP_FILE = 'version.json';

// The repo-root VERSION file. In a checkout it is one level above client/; in
// the container image it is copied next to this script.
function readMajorMinor() {
  log.debug("Entering readMajorMinor().");
  const candidates = [
    path.join(__dirname, '..', VERSION_FILE),
    path.join(__dirname, VERSION_FILE),
  ];
  for (const p of candidates) {
    try {
      const raw = fs.readFileSync(p, 'utf8').trim();
      const m = raw.match(/^(\d+)\.(\d+)$/);
      if (m) {
        log.debug("Leaving readMajorMinor().");
        return { major: m[1], minor: m[2] };
      }
      if (raw) console.error('[version] ignoring malformed ' + p + ': "' + raw +
          '" (want M.N)');
    } catch (e) {
      /* try the next candidate */
    }
  }
  // Never fail a build over this — an unknown major.minor is still reportable.
  console.error('[version] no readable ' + VERSION_FILE +
                '; falling back to 0.0');
  log.debug("Leaving readMajorMinor().");
  return { major: '0', minor: '0' };
}

function utcStamp(d) {
  log.debug("Entering utcStamp().");
  const p = (n, w) => {
    log.debug("Entering p().");
    log.debug("Leaving p().");
    return String(n).padStart(w || 2, '0');
  };
  log.debug("Leaving utcStamp().");
  return '' + d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
}

// Best-effort commit id, for the footer tooltip. Absent inside the container
// image (no .git in the build context) unless GIT_COMMIT is passed in.
function gitCommit() {
  log.debug("Entering gitCommit().");
  if (process.env.GIT_COMMIT) {
    log.debug("Leaving gitCommit().");
    return String(process.env.GIT_COMMIT).trim().substring(0, 12);
  }
  try {
    log.debug("Leaving gitCommit().");
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'],
      { cwd: __dirname, stdio: ['ignore', 'pipe',
       'ignore'] }).toString().trim();
  } catch (e) {
    log.debug("Leaving gitCommit().");
    return '';
  }
}

// Compute a fresh version record for a build happening now.
function resolve() {
  log.debug("Entering resolve().");
  const { major, minor } = readMajorMinor();
  const now = new Date();
  const build = (process.env.BUILD_NUMBER &&
      String(process.env.BUILD_NUMBER).trim())
    || utcStamp(now);
  const commit = gitCommit();
  log.debug("Leaving resolve().");
  return {
    version: major + '.' + minor + '.' + build,
    major: major,
    minor: minor,
    build: build,
    commit: commit,
    builtAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
}

// Human-readable provenance for the footer tooltip.
function buildInfo(v) {
  log.debug("Entering buildInfo().");
  log.debug("Leaving buildInfo().");
  return 'Build ' + v.build + ' — built ' + v.builtAt + (v.commit ?
      ' — commit ' + v.commit : '');
}

// Write the record next to the artifact so it ships with it.
function stamp(dir) {
  log.debug("Entering stamp().");
  const v = resolve();
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, STAMP_FILE), JSON.stringify(v, null, 2) +
                     '\n');
  } catch (e) {
    console.error('[version] could not write ' + path.join(dir, STAMP_FILE) +
                  ': ' + e.message);
  }
  log.debug("Leaving stamp().");
  return v;
}

// Read the record stamped at build time; compute one only if the artifact was
// never stamped (a bare `node server.js` from a checkout), so a served page
// always reports the build it came from.
function load(dir) {
  log.debug("Entering load().");
  try {
    const v = JSON.parse(fs.readFileSync(path.join(dir, STAMP_FILE), 'utf8'));
    if (v && v.version) {
      log.debug("Leaving load().");
      return v;
    }
  } catch (e) {
    /* not stamped */
  }
  log.debug("Leaving load().");
  return resolve();
}

// --- package.json manifests -------------------------------------------------
// Every project in the repo carries the same M.N in its package.json version,
// with the semver patch component pinned to 0 (the real build number lives in
// VERSION / version.json, and package.json must hold a valid semver). These
// helpers keep the four in step with VERSION — a bump that updates only VERSION
// would otherwise leave them silently stale.
const MANIFESTS = ['api', 'client', 'tests', 'sts'];

function manifestVersion() {
  log.debug("Entering manifestVersion().");
  const { major, minor } = readMajorMinor();
  log.debug("Leaving manifestVersion().");
  return major + '.' + minor + '.0';
}

// [{ path, actual, expected, ok }] for each manifest present in the tree. In a
// container image (where the sibling projects are not copied) this is empty.
function checkManifests() {
  log.debug("Entering checkManifests().");
  const want = manifestVersion();
  const out = [];
  for (const name of MANIFESTS) {
    const file = path.join(__dirname, '..', name, 'package.json');
    let actual;
    try {
      actual = JSON.parse(fs.readFileSync(file, 'utf8')).version;
    } catch (e) {
      continue;
    }
    out.push({ path: name + '/package.json', actual: actual, expected: want,
             ok: actual === want });
  }
  log.debug("Leaving checkManifests().");
  return out;
}

// Rewrite any stale manifest (and its lock's root entry) in place.
function syncManifests() {
  log.debug("Entering syncManifests().");
  const want = manifestVersion();
  const changed = [];
  for (const entry of checkManifests()) {
    if (entry.ok) continue;
    const name = entry.path.split('/')[0];
    const file = path.join(__dirname, '..', name, 'package.json');
    const text = fs.readFileSync(file, 'utf8');
    fs.writeFileSync(file, text.replace(/("version":\s*)"[^"]*"/, '$1"' + want +
                     '"'));
    const lockFile = path.join(__dirname, '..', name, 'package-lock.json');
    try {
      const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      lock.version = want;
      if (lock.packages && lock.packages['']) lock.packages[''].version = want;
      fs.writeFileSync(lockFile, JSON.stringify(lock, null, 2) + '\n');
    } catch (e) {
      /* no lock, or unreadable — the manifest is what matters */
    }
    changed.push(entry.path + ': ' + entry.actual + ' -> ' + want);
  }
  log.debug("Leaving syncManifests().");
  return changed;
}

module.exports = { resolve, stamp, load, buildInfo, checkManifests,
    syncManifests, STAMP_FILE };

if (require.main === module) {
  const args = process.argv.slice(2);
  const i = args.indexOf('--stamp');
  if (i >= 0) {
    const dir = args[i + 1] || path.join(__dirname, 'public');
    const v = stamp(path.isAbsolute(dir) ? dir : path.join(__dirname, dir));
    console.log(v.version);
  } else if (args.indexOf('--check-manifests') >= 0) {
    const stale = checkManifests().filter((m) => !m.ok);
    stale.forEach((m) => console.error('[version] ' + m.path + ' is ' +
                  m.actual + ', expected ' + m.expected));
    if (stale.length) { console.error('[version] run: node client/version.js ' +
        '--sync-manifests'); process.exit(1); }
    console.log('all package.json versions match ' + manifestVersion());
  } else if (args.indexOf('--sync-manifests') >= 0) {
    const changed = syncManifests();
    changed.forEach((c) => console.log('[version] ' + c));
    console.log(changed.length ? 'synced ' + changed.length +
                ' manifest(s)' : 'already in sync');
  } else if (args.indexOf('--json') >= 0) {
    console.log(JSON.stringify(resolve(), null, 2));
  } else {
    console.log(resolve().version);
  }
}
