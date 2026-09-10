#!/usr/bin/env node
'use strict';

// File: coverage_merge.js
//
// ---------------------------------------------------------------------------
// THE ONE COVERAGE NUMBER, AND THE ONE RANKED LIST OF WHAT IS ACTUALLY
// UNTESTED.
//
// Coverage here is collected in THREE domains and rendered as three reports —
// the browser bundles (Istanbul), the api process (c8) and the in-process jobs
// (NODE_V8_COVERAGE + c8). COVERAGE.md explains why the third exists and then
// states the limitation this file removes:
//
//     "The same module can appear in two reports, at two paths. … The two do
//      not merge, and neither number alone is the module's real coverage: read
//      both. Nothing here tries to reconcile them."
//
// "Read both" is fine for one module and useless for a work list. Ranking the
// files by what each report calls uncovered points at the wrong work, and it
// does so in exactly the way COVERAGE.md warns about for the third domain — it
// was fixed for the TOTAL and never for the FILE LIST. Measured on the report
// this was written against:
//
//     common/xmldsig.js     1,844 uncovered lines and 37.8% in the api report,
//                           which is its #1 entry, and 513 at 71.4% in the
//                           frontend one — and 90.6% once the three are
//                           merged, where it is twelfth.
//     client/src/x509.js    588 and 64.7% in the frontend report, its #2
//                           entry; 89.5% merged.
//
// Whoever writes tests off the top of either list writes the tests that
// already exist. What survives the merge is different code and there is less
// of it: 84.7% merged against 74.1 / 70.8 / 84.2 for the three domains as this
// file counts them, and against the 74.1 / 66.6 / 84.2 the reports themselves
// publish. Two separate effects, worth telling apart — merging the domains
// accounts for most of it, and the exclusions below for the rest.
//
// It also moves what is at the TOP. `client/src/saml_message.js` is #1 of the
// in-process report at 1,318 uncovered lines and is still 59.9% merged, which
// is a genuine gap; `common/xmldsig.js` heads the api report and is not one.
//
// WHY BASENAMES ARE NOT ENOUGH, and why this file carries a resolver rather
// than a `path.basename()` call. The obvious merge — key on the file name — is
// wrong here in a way that is invisible in the output: `api/server.js` and
// `api/node-ldapjs/lib/server.js` are both `server.js`, so a basename merge
// silently adds a vendored library's uncovered lines to the api's own and
// reports the sum under one name. 47 basenames in the three reports resolve to
// more than one path. So every source file is resolved to a REPO-RELATIVE path
// here, and anything that cannot be resolved is reported by name rather than
// dropped — a merge that quietly loses a file is a coverage number that
// improves for no reason.
//
// WHAT IS EXCLUDED, AND WHY IT IS NOT THE SAME QUESTION AS WHAT IS UNTESTED.
// See EXCLUSIONS below. The rule applied there is ownership, not difficulty:
// code this repository does not write and would not change is not work this
// report should be pointing at. The api's c8 invocation
// (docker-compose-coverage.yml) excludes the same set at COLLECTION time, so
// the published api number agrees with this one; the in-process domain already
// did (`coverageExcludes()` in run-report.js).
//
// THE RATCHET. `--check` compares the merged per-domain and union totals with
// tests/coverage_floors.json and exits non-zero on a drop. Nothing read any of
// these numbers before: .github/workflows/tests.yml uploads ./coverage as an
// artifact and stops, so coverage could fall by ten points between two green
// runs and nothing would say so.
//
// WHERE THIS RUNS, AND WHY IT HAS NO BUNYAN. On the HOST, from
// ./run-coverage.sh, after the stack has been torn down — the three lcov files
// are on the host bind mount by then and the containers that could render them
// are gone. A host checkout need not have run `npm install` in tests/, so this
// file takes no dependency at all, and carries the console-backed `log` of the
// same shape client/build.js and client/static_site.js carry, for the reason
// the repo-root CLAUDE.md gives for those. The methods below are the one place
// the Entering/Leaving convention cannot apply: a log line inside log.debug()
// is infinite recursion.
//
// Usage:
//
//   node tests/coverage_merge.js                    # merge and rank
//   node tests/coverage_merge.js --top 40
//   node tests/coverage_merge.js --check            # the ratchet
//   node tests/coverage_merge.js --write-floors     # record today as the floor
// ---------------------------------------------------------------------------

var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var execFileSync = require("child_process").execFileSync;

var DEBUG = String(process.env.COVERAGE_MERGE_DEBUG || "") === "true";
var LOG_TAG = "[coverage_merge]";
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

var REPO_ROOT = path.resolve(__dirname, "..");

// The three reports, by the name this file calls each domain. `lcov.info` is
// written by every one of the three renderers (nyc for the frontend, c8 for
// the other two), which is what makes one parser enough.
var DOMAINS = [
  { name: "frontend", file: "frontend/report/lcov.info",
    what: "browser bundles, Istanbul" },
  { name: "api", file: "api/lcov.info", what: "the api process, c8" },
  { name: "node", file: "node/lcov.info", what: "in-process jobs, c8" }
];

// ---------------------------------------------------------------------------
// RESOLVING A SOURCE PATH TO A REPO-RELATIVE ONE.
//
// Each domain records the paths its own filesystem had, and none of the three
// is this repository's layout:
//
//   frontend  `src/x509.js`            — relative to /usr/src/app in the
//                                        client image, where client/src is
//                                        `src`.
//   api       `xmldsig.js`             — /usr/src/app in the api image, which
//                                        is api/ with common/data.js,
//                                        common/xmldsig.js and client/
//                                        version.js copied in FLAT beside it.
//   node      `sd_jwt_vc.js`           — /usr/src/app in the tests image, where
//                                        every shared module is copied flat
//                                        beside the test scripts.
//   node      `../client/src/jws.js`   — the same domain on a HOST run, where
//                                        the modules are where they live.
//
// So a bare name is resolved by SEARCHING the directories that image copies
// from, in the order that image copies them, and the search is over the real
// working tree rather than a hard-coded list — a module that moves is then
// found at its new home instead of vanishing from the report.
// ---------------------------------------------------------------------------

// Where a flat name in each domain may have come from, most specific first.
// Order decides collisions exactly as the COPY order in the Dockerfiles does.
var SEARCH_ROOTS = {
  frontend: ["client/src", "common", "client"],
  api: ["api", "common", "common/spiffe", "client"],
  node: ["client/src", "common", "common/krb5", "common/spiffe", "api",
         "infra/edge", "client", "tests"]
};

// Directory hints, applied before any search. A recorded path that already has
// a directory part says where it came from and does not need looking up.
var PREFIX_RULES = {
  frontend: [["src/", "client/src/"]],
  api: [["node-ldapjs/", "api/node-ldapjs/"], ["env/", "api/env/"]],
  node: [["../client/src/", "client/src/"], ["../common/", "common/"],
         ["../api/", "api/"], ["../infra/", "infra/"], ["env/", "tests/env/"]]
};

// The names a search cannot resolve on its own, stated rather than left to
// precedence.
//
//   api/version.js is client/version.js (api/Dockerfile: `COPY
//   client/version.js /usr/src/app/version.js`). A checkout that has built the
//   api image has a real api/version.js on disk, gitignored, so the tracked-
//   file rule below would reject BOTH candidates and fall through to
//   precedence — which would name the generated copy.
//
//   sts_bbs2023.js is the mock STS's vendored copy, renamed by tests/
//   Dockerfile so it can sit beside this repository's own bbs2023.js
//   (`COPY sts/common/vendored/bbs2023.js ./sts_bbs2023.js`). Nothing in this
//   tree is called that, so no search can find it; mapping it to the path it
//   came from is also what puts it behind the `sts/` exclusion, where it
//   belongs.
var OVERRIDES = {
  "api:version.js": "client/version.js",
  "node:sts_bbs2023.js": "sts/common/vendored/bbs2023.js"
};

// ---------------------------------------------------------------------------
// WHICH COPY OF A FILE IS THE FILE.
//
// Several modules here exist at more than one path in a working tree, because
// a Docker build cannot COPY from outside its context and the build stages
// them: `common/xmldsig.js` is staged to `api/xmldsig.js` and to
// `client/src/xmldsig.js`, `common/data.js` to both as well. Those staged
// copies are build output — untracked, and mostly gitignored — and the reports
// name them, because that is what the container had.
//
// Resolving to one of them splits a module's coverage across two rows and
// understates BOTH. It is also how the merged number came out at 81.8% on the
// first run of this file rather than 83.2%: `common/xmldsig.js` was three
// rows, and its api row (`api/xmldsig.js`, 1,475 uncovered) headed the work
// list while the module itself was 86.8% covered — the very failure this file
// exists to end, reproduced inside it.
//
// So a candidate that git TRACKS beats one it does not. That is the question
// actually being asked — which of these paths is the source and which is a
// copy of it — and it needs no list to maintain: a module staged somewhere new
// tomorrow is resolved correctly by a rule that was never edited.
//
// Degrading is deliberate and loud. Without git (a tarball, an image with no
// .git), the set is empty, every candidate is equally untracked, and
// precedence decides as it did before — with one warning saying so, since a
// silent fallback here is a merged number that is quietly wrong.
// ---------------------------------------------------------------------------
// Returns { files, submodules }. `files` is every tracked path; `submodules`
// is every gitlink (mode 160000) — `sts` and the two `node-ldapjs` checkouts —
// and it is needed as much as the first list, because git tracks a submodule
// as ONE entry and not as its contents. Without it, `api/node-ldapjs/lib/
// server.js` is an untracked path like any other, and the fall-through below
// resolves the vendored library's `server.js` to `api/server.js`: 685
// uncovered lines of somebody else's code added to the api's own row, under a
// name that is not theirs. That is precisely the failure the whole resolver
// exists to prevent, arriving through the rule written to prevent it.
function trackedFiles() {
  log.debug("Entering trackedFiles().");
  var out = { files: {}, submodules: [] };
  var text = "";
  try {
    text = execFileSync("git", ["ls-files", "-s"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    log.warn("git ls-files failed (" + e.message + "). Cannot tell a source " +
      "file from a staged copy of one, so search-root precedence decides " +
      "and a module staged into two directories may be split across two " +
      "rows.");
    log.debug("Leaving trackedFiles(). No git.");
    return out;
  }
  text.split(/\r?\n/).forEach(function (line) {
    if (line === "") return;
    // `<mode> <sha> <stage>\t<path>`
    var tab = line.indexOf("\t");
    if (tab < 0) return;
    var rel = line.substring(tab + 1);
    out.files[rel] = true;
    if (line.substring(0, 6) === "160000") out.submodules.push(rel);
  });
  log.debug("Leaving trackedFiles(). " + Object.keys(out.files).length +
    " file(s), " + out.submodules.length + " submodule(s).");
  return out;
}

// Whether a path is inside a submodule this repository points at. A submodule
// is somebody else's checkout, so every file in it is a source file rather
// than a staged copy of one, and a path leading into it is to be believed.
function underSubmodule(rel, tracked) {
  log.debug("Entering underSubmodule(). " + rel);
  for (var i = 0; i < tracked.submodules.length; i++) {
    if (rel.indexOf(tracked.submodules[i] + "/") === 0) {
      log.debug("Leaving underSubmodule(). Yes: " + tracked.submodules[i]);
      return true;
    }
  }
  log.debug("Leaving underSubmodule(). No.");
  return false;
}

// The content hash of a file in the tree, for telling a duplicate apart from a
// genuine collision. Two tracked paths holding the SAME BYTES are one module
// as far as coverage is concerned and merging them is right; two holding
// different bytes are two modules and picking either by precedence is a guess
// worth warning about.
var hashCache = {};

function contentHash(rel) {
  log.debug("Entering contentHash(). " + rel);
  if (hashCache[rel] !== undefined) {
    log.debug("Leaving contentHash(). Cached.");
    return hashCache[rel];
  }
  var digest = null;
  try {
    digest = crypto.createHash("sha256")
      .update(fs.readFileSync(path.join(REPO_ROOT, rel)))
      .digest("hex");
  } catch (e) {
    log.debug("contentHash(): cannot read " + rel + ": " + e.message);
  }
  hashCache[rel] = digest;
  log.debug("Leaving contentHash().");
  return digest;
}

// ---------------------------------------------------------------------------
// WHAT THIS REPORT IS NOT ABOUT.
//
// Ownership, not difficulty. Every entry here is code this repository does not
// write and would not change, so a report that counts it is a report pointing
// at work nobody should do:
//
//   api/node-ldapjs/**  a fork of ldapjs, vendored and used UNMODIFIED, pinned
//                       at upstream's final commit because upstream is
//                       decommissioned. About 3,700 lines at 56%, and it
//                       supplies the #2 entry of the api report — `lib/
//                       server.js`, 685 uncovered lines — with
//                       `lib/client/client.js` not far behind. The in-process
//                       domain already excluded it (coverageExcludes() in
//                       run-report.js); the api domain did not, and dropping
//                       it moves that report from 66.6% to 70.8% with no test
//                       written.
//   sts/**              the mock STS, somebody else's checkout (a submodule).
//                       Its own suite is in its own repository since
//                       2026-08-28.
//   client/version.js   a BUILD script. It runs at image build time and its
//                       coverage is whatever happened to execute at require
//                       time in a container that never calls it — 36.6%, which
//                       is a fact about the api's startup rather than about
//                       this file.
//   **/env/*.js         configuration. api/env/*.js, client/src/env/*.js and
//                       tests/env/*.js are values, and a value that this run
//                       did not select is not an untested branch.
//   **/node_modules/**  never ours.
//
// Everything else stays in, INCLUDING code that is hard to reach. A file
// excluded because covering it is awkward is a file nobody will ever cover.
// ---------------------------------------------------------------------------
var EXCLUSIONS = [
  { pattern: /^api\/node-ldapjs\//, why: "vendored ldapjs, used unmodified" },
  { pattern: /^sts\//, why: "the mock STS, a submodule" },
  { pattern: /(^|\/)node_modules\//, why: "third-party" },
  { pattern: /^client\/version\.js$/, why: "a build script" },
  { pattern: /(^|\/)env\/[^/]+\.js$/, why: "configuration, not code" }
];

function isExcluded(rel) {
  log.debug("Entering isExcluded(). " + rel);
  for (var i = 0; i < EXCLUSIONS.length; i++) {
    if (EXCLUSIONS[i].pattern.test(rel)) {
      log.debug("Leaving isExcluded(). Excluded: " + EXCLUSIONS[i].why);
      return EXCLUSIONS[i].why;
    }
  }
  log.debug("Leaving isExcluded(). Kept.");
  return null;
}

// Every .js file under the search roots, by basename. Built once from the real
// tree: a module that moves between directories is then still found, and a
// basename that exists in two roots is reported as ambiguous rather than
// resolved by luck.
function buildFileIndex() {
  log.debug("Entering buildFileIndex().");
  var index = {};
  var roots = {};
  Object.keys(SEARCH_ROOTS).forEach(function (domain) {
    SEARCH_ROOTS[domain].forEach(function (root) {
      roots[root] = true;
    });
  });
  Object.keys(roots).forEach(function (root) {
    var dir = path.join(REPO_ROOT, root);
    var names = [];
    try {
      names = fs.readdirSync(dir);
    } catch (e) {
      log.debug("buildFileIndex(): no " + root + ": " + e.message);
      return;
    }
    names.forEach(function (name) {
      if (!/\.js$/.test(name)) return;
      var rel = root + "/" + name;
      var full = path.join(REPO_ROOT, rel);
      var stat = null;
      try {
        stat = fs.statSync(full);
      } catch (e) {
        return;
      }
      if (!stat.isFile()) return;
      if (!index[name]) index[name] = [];
      index[name].push(rel);
    });
  });
  log.debug("Leaving buildFileIndex(). " + Object.keys(index).length +
    " name(s).");
  return index;
}

// Choose between several files of one name. Returns
// { rel, candidates, duplicate } — `duplicate` is true when the candidates
// that survived are byte-identical, which makes the choice between them
// immaterial rather than a guess.
function chooseCandidate(domain, found, tracked) {
  log.debug("Entering chooseCandidate(). " + found.length + " candidate(s).");
  var pool = found;
  var haveTracked = found.filter(function (rel) {
    return tracked.files[rel];
  });
  // A source file beats a staged copy of one. Where NONE is tracked (no git,
  // or a name that is build output everywhere it appears) the whole pool
  // stands and precedence decides, as it did before this rule existed.
  if (haveTracked.length) {
    pool = haveTracked;
  }
  var order = SEARCH_ROOTS[domain] || [];
  var chosen = null;
  for (var r = 0; r < order.length && chosen === null; r++) {
    for (var f = 0; f < pool.length; f++) {
      if (path.dirname(pool[f]) === order[r]) {
        chosen = pool[f];
        break;
      }
    }
  }
  // Whether a rule chose, or nothing did. A name in two of a domain's search
  // roots is answered by their ORDER, which is the Dockerfile's COPY order and
  // is knowledge — `server.js` in the api domain is api/server.js and not
  // client/server.js, and saying so every run trains the reader to skip the
  // warnings. A name in NO root of this domain is a guess, and that is the one
  // worth printing.
  var byPrecedence = chosen !== null;
  if (chosen === null) chosen = pool[0];
  var duplicate = false;
  if (pool.length > 1) {
    var first = contentHash(pool[0]);
    duplicate = first !== null && pool.every(function (rel) {
      return contentHash(rel) === first;
    });
  }
  log.debug("Leaving chooseCandidate(). " + chosen);
  return { rel: chosen, candidates: pool, duplicate: duplicate,
           byPrecedence: byPrecedence };
}

// A recorded source path, as this repository spells it. Returns
// { rel, how, ambiguous, duplicate } — `how` says which rule fired, so an
// entry that looks wrong in the report can be traced to the rule that produced
// it, and `rel` is null when nothing resolved.
function resolveSourcePath(domain, sf, index, tracked) {
  log.debug("Entering resolveSourcePath(). " + domain + ":" + sf);
  var clean = String(sf || "").replace(/^\.\//, "");
  var override = OVERRIDES[domain + ":" + clean];
  if (override) {
    log.debug("Leaving resolveSourcePath(). Override.");
    return { rel: override, how: "override", ambiguous: null };
  }
  // A directory hint. It is accepted only when it names a file this tree
  // actually TRACKS, and the check is not defensive tidying — it is the second
  // half of the staged-copy rule above, and without it that rule is bypassed
  // by every module the client build stages.
  //
  // `common/xmldsig.js` is the case. client/build.js stages it into
  // `client/src/` at build time exactly as it stages `common/data.js`, so the
  // frontend report records `src/xmldsig.js` — and `client/src/xmldsig.js`
  // does not exist in a checkout at all, only inside the image. Taken at face
  // value the hint produces a row for a file that is not there, holding the
  // browser's 45.4%, while the module's own row holds the other two domains at
  // 85.4%: two rows, both understated, and the first of them fourth on the
  // work list. Falling through to the search resolves it to `common/xmldsig.js`
  // and the three domains merge.
  //
  // The hint still stands when the search finds nothing, which is what keeps a
  // vendored path like `node-ldapjs/lib/server.js` — no basename of this
  // tree's — resolving to the directory it plainly came from.
  var rules = PREFIX_RULES[domain] || [];
  var hinted = null;
  for (var i = 0; i < rules.length && hinted === null; i++) {
    if (clean.indexOf(rules[i][0]) === 0) {
      hinted = rules[i][1] + clean.substring(rules[i][0].length);
    }
  }
  if (hinted !== null &&
      (tracked.files[hinted] || underSubmodule(hinted, tracked))) {
    log.debug("Leaving resolveSourcePath(). Prefix rule, believed.");
    return { rel: hinted, how: "prefix", ambiguous: null, duplicate: null };
  }
  // An absolute path, or one with a directory part no rule knows. Anything
  // under the repository root is already repo-relative once trimmed.
  if (clean.indexOf(REPO_ROOT + "/") === 0) {
    log.debug("Leaving resolveSourcePath(). Under the repo root.");
    return { rel: clean.substring(REPO_ROOT.length + 1), how: "absolute",
             ambiguous: null };
  }
  var base = path.basename(clean);
  var found = index[base];
  if (!found || !found.length) {
    if (hinted !== null) {
      log.debug("Leaving resolveSourcePath(). Prefix rule, untracked.");
      return { rel: hinted, how: "prefix (untracked)", ambiguous: null,
               duplicate: null };
    }
    log.debug("Leaving resolveSourcePath(). Unresolved.");
    return { rel: null, how: "unresolved", ambiguous: null, duplicate: null };
  }
  var picked = chooseCandidate(domain, found, tracked);
  log.debug("Leaving resolveSourcePath(). " + picked.rel);
  return {
    rel: picked.rel,
    how: "search",
    // Only a choice between files that are NOT the same bytes, and that no
    // search root of this domain settled, is worth reporting: the rest is this
    // tree's own staging and its own COPY order, and 15 lines of warning about
    // those is 15 lines nobody reads.
    ambiguous: (picked.candidates.length > 1 && !picked.duplicate &&
                !picked.byPrecedence) ? picked.candidates : null,
    duplicate: picked.duplicate ? picked.candidates : null
  };
}

// ---------------------------------------------------------------------------
// READING AN LCOV FILE.
//
// Only three record types matter here. `SF:` opens a file, `DA:<line>,<count>`
// is one line's hit count, `end_of_record` closes it. LF/LH are TOTALS the
// renderer computed and they are deliberately ignored — recomputing from the
// DA records is what makes a union possible at all, and it also means a
// disagreement between LF and the DA records cannot silently become the
// answer.
// ---------------------------------------------------------------------------
function parseLcov(file) {
  log.debug("Entering parseLcov(). " + file);
  var text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    log.debug("Leaving parseLcov(). Unreadable: " + e.message);
    return null;
  }
  var files = {};
  var current = null;
  text.split(/\r?\n/).forEach(function (line) {
    if (line.indexOf("SF:") === 0) {
      current = line.substring(3).trim();
      if (!files[current]) files[current] = {};
      return;
    }
    if (line === "end_of_record") {
      current = null;
      return;
    }
    if (current === null || line.indexOf("DA:") !== 0) return;
    var parts = line.substring(3).split(",");
    var lineNo = parseInt(parts[0], 10);
    var count = parseInt(parts[1], 10);
    if (isNaN(lineNo) || isNaN(count)) return;
    var have = files[current][lineNo];
    files[current][lineNo] = (have === undefined) ? count :
        Math.max(have, count);
  });
  log.debug("Leaving parseLcov(). " + Object.keys(files).length + " file(s).");
  return files;
}

// ---------------------------------------------------------------------------
// THE MERGE.
//
// A line is covered if ANY domain saw it run, which is the only reading that
// answers the question the reports are read for — "is this code tested?" —
// rather than "did this particular harness reach it?".
//
// The line NUMBERS are what makes this sound: all three domains instrument the
// same file on disk, so line 412 is line 412 in every report. The frontend
// bundles are the one place worth checking that claim, and they hold: Istanbul
// instruments each module BEFORE browserify concatenates it and records the
// module's own line numbers, which is why its report renders against
// client/src sources at all.
// ---------------------------------------------------------------------------
function mergeDomains(coverageDir) {
  log.debug("Entering mergeDomains().");
  var index = buildFileIndex();
  var tracked = trackedFiles();
  var out = { domains: {}, union: {}, unresolved: [], ambiguous: [],
              duplicates: {}, excluded: {}, missing: [] };
  DOMAINS.forEach(function (domain) {
    var file = path.join(coverageDir, domain.file);
    var parsed = parseLcov(file);
    if (parsed === null) {
      out.missing.push({ domain: domain.name, file: file });
      log.warn("no " + domain.name + " report at " + file +
        " — it is not in the merged number.");
      return;
    }
    var perDomain = {};
    Object.keys(parsed).forEach(function (sf) {
      var resolved = resolveSourcePath(domain.name, sf, index, tracked);
      var rel = resolved.rel;
      if (rel === null) {
        // Kept under a name that says where it came from. Dropping it would
        // make the total better for no reason, which is the one direction a
        // coverage number must never move by itself.
        rel = "(unresolved) " + domain.name + ":" + sf;
        out.unresolved.push({ domain: domain.name, sf: sf });
      } else if (resolved.ambiguous) {
        out.ambiguous.push({ domain: domain.name, sf: sf, rel: rel,
                            candidates: resolved.ambiguous });
      } else if (resolved.duplicate) {
        out.duplicates[rel] = resolved.duplicate;
      }
      var why = isExcluded(rel);
      if (why) {
        out.excluded[rel] = why;
        return;
      }
      if (!perDomain[rel]) perDomain[rel] = {};
      if (!out.union[rel]) out.union[rel] = {};
      Object.keys(parsed[sf]).forEach(function (lineNo) {
        var count = parsed[sf][lineNo];
        var was = perDomain[rel][lineNo];
        perDomain[rel][lineNo] = (was === undefined) ? count :
            Math.max(was, count);
        var had = out.union[rel][lineNo];
        out.union[rel][lineNo] = (had === undefined) ? count :
            Math.max(had, count);
      });
    });
    out.domains[domain.name] = perDomain;
  });
  log.debug("Leaving mergeDomains(). " + Object.keys(out.union).length +
    " file(s).");
  return out;
}

function totalsOf(files) {
  log.debug("Entering totalsOf().");
  var found = 0;
  var hit = 0;
  Object.keys(files).forEach(function (rel) {
    Object.keys(files[rel]).forEach(function (lineNo) {
      found++;
      if (files[rel][lineNo] > 0) hit++;
    });
  });
  log.debug("Leaving totalsOf(). " + hit + "/" + found);
  return { hit: hit, found: found,
           pct: found ? (100 * hit / found) : 100 };
}

// ---------------------------------------------------------------------------
// OUTPUT.
// ---------------------------------------------------------------------------

function pad(text, width) {
  log.debug("Entering pad().");
  var s = String(text);
  while (s.length < width) s += " ";
  log.debug("Leaving pad().");
  return s;
}

function padLeft(text, width) {
  log.debug("Entering padLeft().");
  var s = String(text);
  while (s.length < width) s = " " + s;
  log.debug("Leaving padLeft().");
  return s;
}

function rankFiles(union) {
  log.debug("Entering rankFiles().");
  var rows = Object.keys(union).map(function (rel) {
    var t = totalsOf({ x: union[rel] });
    return { rel: rel, missed: t.found - t.hit, found: t.found, pct: t.pct };
  });
  // Most uncovered LINES first, not worst percentage: a 40-line helper at 20%
  // is nine lines of work and a 2,000-line module at 60% is eight hundred.
  // Percentage decides ties so the smaller, worse-covered file sorts above an
  // equally-missed better-covered one.
  rows.sort(function (a, b) {
    if (b.missed !== a.missed) return b.missed - a.missed;
    return a.pct - b.pct;
  });
  log.debug("Leaving rankFiles(). " + rows.length + " row(s).");
  return rows;
}

function printReport(merged, top) {
  log.debug("Entering printReport().");
  console.log("");
  console.log("MERGED COVERAGE");
  console.log("===============");
  console.log("");
  DOMAINS.forEach(function (domain) {
    var files = merged.domains[domain.name];
    if (!files) {
      console.log("  " + pad(domain.name, 10) + " (no report)");
      return;
    }
    var t = totalsOf(files);
    console.log("  " + pad(domain.name, 10) +
      padLeft(t.pct.toFixed(1) + "%", 7) + "   " +
      padLeft(t.hit + "/" + t.found, 15) + "   " + domain.what);
  });
  var union = totalsOf(merged.union);
  console.log("  " + pad("UNION", 10) + padLeft(union.pct.toFixed(1) + "%", 7) +
    "   " + padLeft(union.hit + "/" + union.found, 15) +
    "   a line any domain ran");
  console.log("");
  var rows = rankFiles(merged.union).filter(function (row) {
    return row.missed > 0;
  });
  console.log("UNTESTED CODE, MOST UNCOVERED LINES FIRST (top " + top + " of " +
    rows.length + " files with any)");
  console.log("");
  console.log("  " + padLeft("missed", 7) + padLeft("cov", 8) +
    padLeft("lines", 8) + "   file");
  rows.slice(0, top).forEach(function (row) {
    console.log("  " + padLeft(row.missed, 7) +
      padLeft(row.pct.toFixed(1) + "%", 8) + padLeft(row.found, 8) + "   " +
      row.rel);
  });
  console.log("");
  var excluded = Object.keys(merged.excluded);
  if (excluded.length) {
    console.log("Excluded (" + excluded.length + " file(s)): code this " +
      "repository does not own or does not run.");
    var byReason = {};
    excluded.forEach(function (rel) {
      var why = merged.excluded[rel];
      byReason[why] = (byReason[why] || 0) + 1;
    });
    Object.keys(byReason).forEach(function (why) {
      console.log("  " + padLeft(byReason[why], 5) + "  " + why);
    });
    console.log("");
  }
  // Both of these are how this file goes stale, so neither is quiet. An
  // unresolved path means a report names a file this resolver cannot place —
  // its lines are still counted, under a name that says so — and an ambiguous
  // one means a basename now exists in two search roots, where precedence is
  // deciding rather than knowledge.
  if (merged.unresolved.length) {
    log.warn(merged.unresolved.length + " source path(s) could not be " +
      "resolved to a file in this tree. They are counted under an " +
      "'(unresolved)' name. Add a rule to PREFIX_RULES or SEARCH_ROOTS:");
    merged.unresolved.slice(0, 20).forEach(function (item) {
      log.warn("  " + item.domain + ": " + item.sf);
    });
  }
  if (merged.ambiguous.length) {
    log.warn(merged.ambiguous.length + " source path(s) matched more than " +
      "one file, and those files are NOT identical, so search-root " +
      "precedence chose between two different modules of one name:");
    merged.ambiguous.slice(0, 20).forEach(function (item) {
      log.warn("  " + item.domain + ": " + item.sf + " -> " + item.rel +
        "  (also: " + item.candidates.join(", ") + ")");
    });
  }
  // Not a warning. Byte-identical copies are one module counted once, which is
  // the right answer — but a checkout carrying two committed copies of a file
  // is worth being able to see, because one of them will be edited alone.
  var dupes = Object.keys(merged.duplicates);
  if (dupes.length) {
    console.log("Identical copies, merged onto one row (" + dupes.length +
      " file(s)):");
    dupes.slice(0, 10).forEach(function (rel) {
      console.log("  " + rel + "  <-  " +
        merged.duplicates[rel].join(", "));
    });
    if (dupes.length > 10) {
      console.log("  … and " + (dupes.length - 10) + " more.");
    }
    console.log("");
  }
  log.debug("Leaving printReport().");
}

// A merged lcov, so the union can be rendered by anything that reads one
// (genhtml, a coverage service, an editor's gutter). Written with repo-relative
// SF paths, which none of the three inputs has and which is the only spelling
// that resolves from a checkout.
function writeMergedLcov(merged, outFile) {
  log.debug("Entering writeMergedLcov().");
  var lines = [];
  Object.keys(merged.union).sort().forEach(function (rel) {
    var counts = merged.union[rel];
    var numbers = Object.keys(counts).map(Number).sort(function (a, b) {
      return a - b;
    });
    var hit = 0;
    lines.push("TN:");
    lines.push("SF:" + rel);
    numbers.forEach(function (lineNo) {
      lines.push("DA:" + lineNo + "," + counts[lineNo]);
      if (counts[lineNo] > 0) hit++;
    });
    lines.push("LF:" + numbers.length);
    lines.push("LH:" + hit);
    lines.push("end_of_record");
  });
  try {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, lines.join("\n") + "\n", "utf8");
  } catch (e) {
    log.warn("could not write " + outFile + ": " + e.message);
    log.debug("Leaving writeMergedLcov(). Failed.");
    return false;
  }
  log.info("merged lcov: " + outFile);
  log.debug("Leaving writeMergedLcov().");
  return true;
}

function writeJson(merged, outFile) {
  log.debug("Entering writeJson().");
  var payload = { generated: new Date().toISOString(), domains: {},
                  union: null, files: [] };
  DOMAINS.forEach(function (domain) {
    if (!merged.domains[domain.name]) return;
    payload.domains[domain.name] = totalsOf(merged.domains[domain.name]);
  });
  payload.union = totalsOf(merged.union);
  payload.files = rankFiles(merged.union);
  try {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, JSON.stringify(payload, null, 2) + "\n", "utf8");
  } catch (e) {
    log.warn("could not write " + outFile + ": " + e.message);
    log.debug("Leaving writeJson(). Failed.");
    return false;
  }
  log.info("merged summary: " + outFile);
  log.debug("Leaving writeJson().");
  return true;
}

// ---------------------------------------------------------------------------
// THE RATCHET.
//
// A floor per domain plus one for the union, in tests/coverage_floors.json.
// The check FAILS on a drop and says which domain moved and by how much.
//
// TWO THINGS IT DELIBERATELY DOES NOT DO. It does not fail when a report is
// MISSING — a run that collected nothing has a different problem and reporting
// it as a coverage regression names the wrong thing (the missing report is
// warned about, loudly, by mergeDomains()). And it does not raise the floors
// by itself: an automatic ratchet turns one lucky run into a threshold nobody
// chose, and the next honest run is red for it. `--write-floors` is how they
// move, deliberately, in a commit somebody reviewed.
// ---------------------------------------------------------------------------
var FLOORS_FILE = path.join(__dirname, "coverage_floors.json");

// THE SLACK, AND WHY IT IS SPENT WHEN THE FLOOR IS WRITTEN RATHER THAN WHEN IT
// IS CHECKED.
//
// A merged coverage number is not exactly reproducible. A job skipped for want
// of a service — walt.id, a real domain controller, a browser that cannot
// side-load an extension — takes its lines with it, and the pool decides which
// process records a module first. So a floor recorded at exactly what one run
// achieved is a coin toss for the next one.
//
// The margin is therefore subtracted ONCE, by `--write-floors`, and `--check`
// is then exact. The alternative — record the achievement and forgive a drop
// at check time — puts the same slack in a place where nobody reading
// coverage_floors.json can see it, so the file states a number the build does
// not actually enforce. Here the number in that file is the number that must
// be met.
//
// A point is well below the smallest regression worth a red build: deleting
// the tests for any one of the top thirty files in this report moves the union
// by more than that.
var FLOOR_MARGIN = 1.0;

function readFloors() {
  log.debug("Entering readFloors().");
  try {
    var text = fs.readFileSync(FLOORS_FILE, "utf8");
    log.debug("Leaving readFloors().");
    return JSON.parse(text);
  } catch (e) {
    log.debug("Leaving readFloors(). None: " + e.message);
    return null;
  }
}

function checkFloors(merged) {
  log.debug("Entering checkFloors().");
  var floors = readFloors();
  if (!floors) {
    log.warn("no " + FLOORS_FILE + " — nothing to check against. " +
      "`--write-floors` records this run as the floor.");
    log.debug("Leaving checkFloors(). No floors.");
    return true;
  }
  var ok = true;
  var actual = { union: totalsOf(merged.union) };
  DOMAINS.forEach(function (domain) {
    if (!merged.domains[domain.name]) return;
    actual[domain.name] = totalsOf(merged.domains[domain.name]);
  });
  Object.keys(floors.floors || {}).forEach(function (key) {
    var floor = floors.floors[key];
    if (!actual[key]) {
      log.warn("floor for '" + key + "' has no report in this run — not " +
        "checked. A run that collected nothing is a different failure.");
      return;
    }
    var got = actual[key].pct;
    if (got < floor) {
      log.error("COVERAGE REGRESSION: " + key + " is " + got.toFixed(1) +
        "%, below its floor of " + floor.toFixed(1) + "%. " +
        actual[key].hit + "/" + actual[key].found + " lines. Find what " +
        "stopped being covered in coverage/merged/summary.json before " +
        "lowering this.");
      ok = false;
      return;
    }
    log.info("floor ok: " + pad(key, 10) + got.toFixed(1) + "% >= " +
      floor.toFixed(1) + "%");
  });
  log.debug("Leaving checkFloors(). ok=" + ok);
  return ok;
}

function writeFloors(merged) {
  log.debug("Entering writeFloors().");
  var floors = { comment: "Coverage floors, checked by " +
      "tests/coverage_merge.js --check (run by ./run-coverage.sh). Falling " +
      "below any of these fails the run. Each is what a run achieved less a " +
      "margin of " + FLOOR_MARGIN + " of a point, because a job skipped for " +
      "want of a service takes its lines with it; --write-floors applies " +
      "that margin. Raise them deliberately when coverage improves; never " +
      "lower one without saying in the commit message what stopped being " +
      "tested.",
    updated: new Date().toISOString().substring(0, 10),
    achieved: {}, floors: {} };
  function record(key, totals) {
    log.debug("Entering record(). " + key);
    floors.achieved[key] = Number(totals.pct.toFixed(1));
    floors.floors[key] = Number((totals.pct - FLOOR_MARGIN).toFixed(1));
    log.debug("Leaving record().");
  }
  DOMAINS.forEach(function (domain) {
    if (!merged.domains[domain.name]) return;
    record(domain.name, totalsOf(merged.domains[domain.name]));
  });
  record("union", totalsOf(merged.union));
  try {
    fs.writeFileSync(FLOORS_FILE, JSON.stringify(floors, null, 2) + "\n",
      "utf8");
  } catch (e) {
    log.error("could not write " + FLOORS_FILE + ": " + e.message);
    log.debug("Leaving writeFloors(). Failed.");
    return false;
  }
  log.info("wrote " + FLOORS_FILE);
  log.debug("Leaving writeFloors().");
  return true;
}

// ---------------------------------------------------------------------------
// MAIN.
//
// Hand-rolled argument reading rather than commander, for the reason at the
// top of this file: it runs on the HOST, where tests/node_modules need not
// exist.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  var out = { coverageDir: path.join(REPO_ROOT, "coverage"), top: 30,
              check: false, writeFloors: false, json: true };
  for (var i = 2; i < argv.length; i++) {
    var arg = argv[i];
    if (arg === "--check") {
      out.check = true;
    } else if (arg === "--write-floors") {
      out.writeFloors = true;
    } else if (arg === "--no-json") {
      out.json = false;
    } else if (arg === "--top") {
      out.top = parseInt(argv[++i], 10) || out.top;
    } else if (arg === "--coverage-dir") {
      out.coverageDir = path.resolve(argv[++i] || out.coverageDir);
    } else if (arg === "-h" || arg === "--help") {
      out.help = true;
    } else {
      log.warn("unknown argument: " + arg);
    }
  }
  log.debug("Leaving parseArgs().");
  return out;
}

function usage() {
  log.debug("Entering usage().");
  console.log("usage: node tests/coverage_merge.js [options]");
  console.log("");
  console.log("  --coverage-dir DIR  where the three reports are " +
    "(default ./coverage)");
  console.log("  --top N             how many files to rank (default 30)");
  console.log("  --check             fail if a total is below its floor " +
    "(tests/coverage_floors.json)");
  console.log("  --write-floors      record this run's totals as the floors");
  console.log("  --no-json           do not write coverage/merged/" +
    "summary.json");
  log.debug("Leaving usage().");
}

function main() {
  log.debug("Entering main().");
  var args = parseArgs(process.argv);
  if (args.help) {
    usage();
    log.debug("Leaving main(). Help.");
    return 0;
  }
  var merged = mergeDomains(args.coverageDir);
  if (Object.keys(merged.union).length === 0) {
    log.error("no coverage was read from " + args.coverageDir + ". Run " +
      "./run-coverage.sh first.");
    log.debug("Leaving main(). Nothing to merge.");
    return 1;
  }
  printReport(merged, args.top);
  writeMergedLcov(merged, path.join(args.coverageDir, "merged", "lcov.info"));
  if (args.json) {
    writeJson(merged, path.join(args.coverageDir, "merged", "summary.json"));
  }
  if (args.writeFloors) {
    if (!writeFloors(merged)) {
      log.debug("Leaving main(). Could not write floors.");
      return 1;
    }
  }
  if (args.check) {
    if (!checkFloors(merged)) {
      log.debug("Leaving main(). Below a floor.");
      return 1;
    }
  }
  log.debug("Leaving main().");
  return 0;
}

process.exit(main());
