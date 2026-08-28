// File: compose_env_forwarding.js
//
// Every variable the COMPOSE FILES read from the environment must be listed in
// COMPOSE_FORWARDED_VARS (common/common.sh), because `sudo` empties the
// environment on the way to compose.
//
// ---------------------------------------------------------------------------
// Why this needs a test, and why nothing else could have caught it.
//
// docker_compose() in common/common.sh runs compose under `sudo`, and sudo's
// default env_reset means the only variables that survive are the assignments
// written on its command line. The function builds that list from
// COMPOSE_FORWARDED_VARS. So a compose file that reads a variable — either as
// a `${NAME}` substitution or as a bare `- NAME` entry under `environment:` —
// is reading a variable that exists ONLY if that name is on the list.
//
// EVERY FAILURE OF THIS KIND IS SILENT, AND IN BOTH DIRECTIONS:
//
//  * `${NAME:-}` with a default substitutes to the empty string and compose
//    prints no warning at all. `TEST_CONCURRENCY=6 ./docker-run-tests.sh`
//    therefore reached run-report.js as an EMPTY TEST_CONCURRENCY for as long
//    as that passthrough existed: parseInt("") is NaN, the pool fell back to
//    sizing itself from the container's cores, and the run looked exactly like
//    one where nothing had been asked for. The wall clock was the only
//    evidence, and the wall clock is what the person setting it was trying to
//    change. tests/CLAUDE.md and the root CLAUDE.md both documented it as
//    working.
//  * A bare `- NAME` passes nothing when NAME is unset, which is the whole
//    point of that form — so STS_LOG_LEVEL=info left the mock at its debug
//    default, i.e. at about half that service's CPU, on the one stack where
//    several jobs drive one instance at once.
//
// Neither shows up as an error anywhere, and no existing test reads a compose
// file for this. This one does the whole comparison: it parses every compose
// file in the repository for both forms, parses COMPOSE_FORWARDED_VARS out of
// common/common.sh, and asserts the first set is contained in the second. It
// also asserts the reverse is not silently true by accident — a name on the
// list that no compose file reads is dead weight and is reported, though only
// as a warning, since a launcher may legitimately forward one ahead of use.
//
// No browser and no services: node only, so it never skips as a whole. The
// compose files and common.sh are copied into the tests image
// (tests/Dockerfile) so it runs there too.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");
const { Command, Option } = require("commander");

var log = bunyan.createLogger({
  name: "compose_env_forwarding",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});

// Flat in the tests container, in the repository root in a checkout — the same
// arrangement tests/static_site_exclusions.js reads its four files under.
function locate(candidates) {
  log.debug("Entering locate().");
  log.debug("Leaving locate().");
  return candidates.filter(function (p) {
    return fs.existsSync(p);
  })[0];
}

// The compose files that docker_compose() is ever pointed at. Named rather
// than globbed because the image's copy is flat: a glob of __dirname would
// find whatever else ends in .yml there, and a glob of "../" finds nothing in
// the container.
const COMPOSE_FILE_NAMES = [
  "docker-compose-run-tests.yml",
  "docker-compose-coverage.yml",
  "docker-compose.yml",
  "local-tests.yml",
  "keycloak-tests.yml",
];

function composeFiles() {
  log.debug("Entering composeFiles().");
  const found = [];
  COMPOSE_FILE_NAMES.forEach(function (name) {
    const p = locate([
      path.join(__dirname, name),
      path.join(__dirname, "..", name)]);
    if (p) {
      found.push({ name: name, path: p });
    }
  });
  log.debug("Leaving composeFiles(). " + found.length + " found.");
  return found;
}

const COMMON_SH_PATH = locate([
  path.join(__dirname, "common.sh"),
  path.join(__dirname, "..", "common", "common.sh")]);

// The names common.sh will put on sudo's command line. The assignment is built
// up across several lines (it is too long for one), so this reads every
// COMPOSE_FORWARDED_VARS= assignment in the file and unions them rather than
// matching a single line — which is exactly the drift the style rules warn a
// source-inspection test about.
function forwardedVars(source) {
  log.debug("Entering forwardedVars().");
  const names = new Set();
  const re = /^COMPOSE_FORWARDED_VARS=\"([^\"]*)\"/gm;
  var m;
  while ((m = re.exec(source)) !== null) {
    m[1].split(/\s+/).forEach(function (word) {
      // The continuation lines begin with the variable's own expansion.
      if (word && word.indexOf("$") === -1) {
        names.add(word);
      }
    });
  }
  log.debug("Leaving forwardedVars(). " + names.size + " names.");
  return names;
}

// Every `${NAME}` / `${NAME:-...}` a compose file substitutes. Compose reads
// these from ITS OWN environment, which is the one sudo just emptied.
function substitutedVars(source) {
  log.debug("Entering substitutedVars().");
  const names = new Set();
  const re = /\$\{([A-Z_][A-Z0-9_]*)/g;
  var m;
  while ((m = re.exec(source)) !== null) {
    names.add(m[1]);
  }
  log.debug("Leaving substitutedVars(). " + names.size + " names.");
  return names;
}

// Every bare `- NAME` under an `environment:` list, which is compose's "pass
// this through from my environment if it is set" form. Comments are stripped
// first: both of the files carrying this form explain it in a comment that
// spells the variable out, and a comment is not a declaration.
function passedThroughVars(source) {
  log.debug("Entering passedThroughVars().");
  const names = new Set();
  source.split("\n").forEach(function (line) {
    if (/^\s*#/.test(line)) {
      return;
    }
    const m = /^\s+-\s+([A-Z_][A-Z0-9_]*)\s*$/.exec(line);
    if (m) {
      names.add(m[1]);
    }
  });
  log.debug("Leaving passedThroughVars(). " + names.size + " names.");
  return names;
}

// The names compose itself defines rather than reads. COMPOSE_PROJECT_NAME and
// friends are compose's own, and a variable a compose file substitutes into a
// path it also WRITES is still read from the environment, so nothing is
// exempted on that ground. This list is deliberately empty and exists to be
// the one place an exemption would go, with its reason beside it.
const NOT_FROM_THE_ENVIRONMENT = new Set([]);

function everyVariableAComposeFileReadsIsForwarded(forwarded, files) {
  log.debug("Entering everyVariableAComposeFileReadsIsForwarded().");
  const missing = [];
  files.forEach(function (file) {
    const source = fs.readFileSync(file.path, "utf8");
    const read = new Set([
      ...substitutedVars(source),
      ...passedThroughVars(source)]);
    read.forEach(function (name) {
      if (NOT_FROM_THE_ENVIRONMENT.has(name) || forwarded.has(name)) {
        return;
      }
      missing.push(name + " (" + file.name + ")");
    });
  });
  assert.deepStrictEqual(missing, [],
    "These variables are read from the environment by a compose file and are " +
    "NOT in COMPOSE_FORWARDED_VARS (common/common.sh), so docker_compose() " +
    "will not put them on sudo's command line and compose will see them " +
    "unset. A `${NAME:-}` substitution then yields the empty string with no " +
    "warning and a bare `- NAME` passes nothing, so the setting is ignored " +
    "and the run reports success: " + missing.join(", "));
  log.info("every variable the compose files read is forwarded past sudo (" +
           files.length + " files, " + forwarded.size + " forwarded names).");
  log.debug("Leaving everyVariableAComposeFileReadsIsForwarded().");
}

// The three that tune a containerized run, asserted BY NAME. The check above
// is the general rule and would pass just as well if somebody deleted the
// passthrough from the compose file — the variable would then be read by
// nothing and there would be nothing to forward. That is the shape this whole
// arrangement failed in for as long as it existed, so the settings the
// launchers document are pinned here from both ends: the compose file must
// read them and common.sh must forward them.
const TUNING_VARS = [
  { name: "TEST_CONCURRENCY", file: "docker-compose-run-tests.yml" },
  { name: "TEST_JOB_TIMEOUT_MS", file: "docker-compose-run-tests.yml" },
  { name: "STS_LOG_LEVEL", file: "docker-compose-run-tests.yml" },
];

function theTuningVariablesReachTheContainer(forwarded, files) {
  log.debug("Entering theTuningVariablesReachTheContainer().");
  TUNING_VARS.forEach(function (want) {
    const file = files.filter(function (f) {
      return f.name === want.file;
    })[0];
    assert.ok(file, want.file + " was not found beside this test or in the " +
      "repository root, so " + want.name + "'s passthrough could not be " +
      "checked. This test must not pass without reading that file.");
    const source = fs.readFileSync(file.path, "utf8");
    const read = new Set([
      ...substitutedVars(source),
      ...passedThroughVars(source)]);
    assert.ok(read.has(want.name),
      want.name + " is documented by ./docker-run-tests.sh and " +
      "./run-coverage.sh as tuning a containerized run, but " + want.file +
      " does not read it — so the value never reaches the tests container " +
      "and run-report.js falls back to its own default with no warning.");
    assert.ok(forwarded.has(want.name),
      want.name + " is read by " + want.file + " but is not in " +
      "COMPOSE_FORWARDED_VARS (common/common.sh), so sudo drops it before " +
      "compose can substitute it.");
  });
  log.info("the three tuning variables are read by the compose file AND " +
           "forwarded past sudo: " + TUNING_VARS.map(function (v) {
             return v.name;
           }).join(", "));
  log.debug("Leaving theTuningVariablesReachTheContainer().");
}

// A name on the list that nothing reads is not a failure — a launcher may
// forward one ahead of the compose file that will use it — but it is worth
// saying, because the list is the only record of what crosses sudo and a stale
// entry makes it a worse record.
function anUnreadForwardedNameIsReported(forwarded, files) {
  log.debug("Entering anUnreadForwardedNameIsReported().");
  const read = new Set();
  files.forEach(function (file) {
    const source = fs.readFileSync(file.path, "utf8");
    substitutedVars(source).forEach(function (n) {
      read.add(n);
    });
    passedThroughVars(source).forEach(function (n) {
      read.add(n);
    });
  });
  const unread = [];
  forwarded.forEach(function (name) {
    // COMPOSE_PROJECT_NAME is compose's own and appears in no file.
    if (name === "COMPOSE_PROJECT_NAME" || read.has(name)) {
      return;
    }
    unread.push(name);
  });
  if (unread.length) {
    log.warn("forwarded past sudo but read by no compose file in this " +
             "checkout: " + unread.join(", ") + ". Harmless, but the list " +
             "is the only record of what crosses sudo.");
  }
  log.debug("Leaving anUnreadForwardedNameIsReported().");
}

function test() {
  log.debug("Entering test().");
  assert.ok(COMMON_SH_PATH,
    "common/common.sh was not found beside this test or in the repository " +
    "root. COMPOSE_FORWARDED_VARS is defined there and this test asserts " +
    "nothing without it.");
  const files = composeFiles();
  assert.ok(files.length > 0,
    "no compose file was found beside this test or in the repository root, " +
    "so there was nothing to compare against COMPOSE_FORWARDED_VARS. This " +
    "test must fail rather than pass vacuously.");
  const forwarded = forwardedVars(fs.readFileSync(COMMON_SH_PATH, "utf8"));
  assert.ok(forwarded.size > 0,
    "no COMPOSE_FORWARDED_VARS assignment was parsed out of " +
    COMMON_SH_PATH + ". The assignment is built up across several lines; if " +
    "its shape changed, forwardedVars() has to change with it rather than " +
    "reporting an empty set.");
  assert.ok(forwarded.has("CONFIG_FILE"),
    "CONFIG_FILE is not among the parsed COMPOSE_FORWARDED_VARS, which it " +
    "has been since the list existed — so the parse is wrong rather than " +
    "the list.");

  everyVariableAComposeFileReadsIsForwarded(forwarded, files);
  theTuningVariablesReachTheContainer(forwarded, files);
  anUnreadForwardedNameIsReported(forwarded, files);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("compose_env_forwarding")
  .description("Verify that every variable the compose files read from the " +
               "environment is forwarded past sudo by common/common.sh.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
