// File: image_mirror_coverage.js
//
// Every image the containerized test stack PULLS, and every base image a
// Dockerfile it BUILDS names in a FROM, must come from the private mirror on
// ghcr.io — and the mirror must list it.
//
// ---------------------------------------------------------------------------
// Why this needs a test.
//
// On 2026-09-27 the scheduled run died three seconds in: a token request to
// auth.docker.io was reset and the first `FROM eclipse-temurin:11-jdk` could
// not be resolved. docker-compose-run-tests.yml now takes everything from
// ghcr.io/rcbj/id-proto-debugger/mirror (.github/image-mirror.txt, copied by
// .github/workflows/mirror-images.yml), in two ways:
//
//  * a service that is only run names the mirror in its `image:`;
//  * a FROM is redirected by the build's `additional_contexts`, which BuildKit
//    consults before any registry — the only way to reach sts/Dockerfile,
//    which is the iya-sts submodule's and is not edited here.
//
// BOTH FAIL OPEN. A FROM with no matching named context is not an error: it is
// pulled from Docker Hub, exactly as before, and the run is green until the
// day Docker Hub is not there. The likeliest way in is not an edit here at
// all but a submodule bump that moves sts/Dockerfile to a new node tag. So
// this reads the compose file, the list and the five Dockerfiles and asserts:
//
//  1. every `image:` is either the mirror (with a path the list has) or one of
//     this repository's own built images under IMAGE_REGISTRY;
//  2. every named context in x-mirror-contexts points at a listed path;
//  3. every `build:` carries those contexts;
//  4. every external FROM (and COPY --from) in a built Dockerfile has one.
//
// Node only, no services. A missing file FAILS rather than skips, because a
// check that compares nothing is the shape of bug it is here to catch.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");
const { Command, Option } = require("commander");

var log = bunyan.createLogger({
  name: "image_mirror_coverage",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// In the repository this file is tests/; in the tests image everything is
// flat in one directory and the Dockerfiles are renamed on COPY (see
// tests/Dockerfile). Each entry is [repository path, flat name].
const FILES = {
  compose: ["docker-compose-run-tests.yml", "docker-compose-run-tests.yml"],
  list: [".github/image-mirror.txt", "image-mirror.txt"],
};
// The Dockerfiles docker-compose-run-tests.yml builds.
const DOCKERFILES = {
  "api/Dockerfile": "api_Dockerfile",
  "client/Dockerfile": "client_Dockerfile",
  "keycloak-wsfed/Dockerfile": "keycloak-wsfed_Dockerfile",
  "tests/Dockerfile": "tests_Dockerfile",
  "sts/Dockerfile": "sts_Dockerfile",
};

const MIRROR_PREFIX = "${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}/";
const BUILT_PREFIXES = [
  "${IMAGE_REGISTRY:-ghcr.io/rcbj/id-proto-debugger}/",
  "${STS_IMAGE:-${IMAGE_REGISTRY:-ghcr.io/rcbj/id-proto-debugger}/",
];

function locate(repoPath, flatName) {
  log.debug("Entering locate().");
  const found = [
    path.join(__dirname, "..", repoPath),
    path.join(__dirname, flatName)].filter(function (p) {
    return fs.existsSync(p);
  })[0];
  assert.ok(found,
    repoPath + " was found neither in the repository nor beside this test " +
    "as " + flatName + ". This check must fail rather than pass vacuously; " +
    "if the file moved, move it here too (and in tests/Dockerfile).");
  log.debug("Leaving locate(). " + found);
  return found;
}

function mirrorPaths(source) {
  log.debug("Entering mirrorPaths().");
  const paths = new Set();
  source.split("\n").forEach(function (line) {
    const t = line.trim();
    if (!t || t.charAt(0) === "#") {
      return;
    }
    const cols = t.split(/\s+/);
    assert.strictEqual(cols.length, 2,
      "image-mirror.txt: expected `upstream  mirror-path`, got: " + line);
    paths.add(cols[1]);
  });
  log.debug("Leaving mirrorPaths(). " + paths.size + " paths.");
  return paths;
}

// Non-comment lines only, with any trailing comment left alone: nothing this
// reads carries one.
function codeLines(source) {
  log.debug("Entering codeLines().");
  log.debug("Leaving codeLines().");
  return source.split("\n").filter(function (line) {
    return !/^\s*#/.test(line);
  });
}

function everyImageIsMirroredOrBuiltHere(lines, paths) {
  log.debug("Entering everyImageIsMirroredOrBuiltHere().");
  const bad = [];
  var n = 0;
  lines.forEach(function (line) {
    const m = /^\s+image:\s*(\S+)\s*$/.exec(line);
    if (!m) {
      return;
    }
    n++;
    const ref = m[1];
    if (ref.indexOf(MIRROR_PREFIX) === 0) {
      if (!paths.has(ref.slice(MIRROR_PREFIX.length))) {
        bad.push(ref + " (mirror path not in image-mirror.txt)");
      }
      return;
    }
    const built = BUILT_PREFIXES.some(function (p) {
      return ref.indexOf(p) === 0;
    });
    if (!built) {
      bad.push(ref + " (neither the mirror nor IMAGE_REGISTRY)");
    }
  });
  assert.ok(n > 0, "no `image:` line was parsed out of the compose file.");
  assert.deepStrictEqual(bad, [],
    "These images in docker-compose-run-tests.yml would be pulled from " +
    "somewhere other than the ghcr.io mirror: " + bad.join(", "));
  log.info(n + " image references, all from the mirror or built here.");
  log.debug("Leaving everyImageIsMirroredOrBuiltHere().");
}

// The `x-mirror-contexts:` block: two-space-indented `key: docker-image://…`
// lines up to the next top-level key. Returns the context names.
function mirrorContexts(lines, paths) {
  log.debug("Entering mirrorContexts().");
  const start = lines.findIndex(function (line) {
    return /^x-mirror-contexts:/.test(line);
  });
  assert.ok(start >= 0,
    "docker-compose-run-tests.yml has no top-level x-mirror-contexts block.");
  const names = new Set();
  const bad = [];
  for (var i = start + 1; i < lines.length; i++) {
    if (/^\S/.test(lines[i])) {
      break;
    }
    const m = /^\s+"?([^":]+(?::[^"]+)?)"?:\s*docker-image:\/\/(\S+)\s*$/
      .exec(lines[i]);
    if (!m) {
      continue;
    }
    names.add(m[1]);
    if (m[2].indexOf(MIRROR_PREFIX) !== 0 ||
        !paths.has(m[2].slice(MIRROR_PREFIX.length))) {
      bad.push(m[1] + " -> " + m[2]);
    }
  }
  assert.ok(names.size > 0, "x-mirror-contexts parsed as empty.");
  assert.deepStrictEqual(bad, [],
    "These named contexts do not point at a listed mirror path: " +
    bad.join(", "));
  log.debug("Leaving mirrorContexts(). " + names.size + " contexts.");
  return names;
}

function everyBuildCarriesTheContexts(source) {
  log.debug("Entering everyBuildCarriesTheContexts().");
  const code = codeLines(source).join("\n");
  const builds = (code.match(/^\s+build:\s*$/gm) || []).length;
  const uses = (code.match(/\*mirror-contexts\b/g) || []).length;
  assert.ok(builds > 0, "no `build:` section was parsed.");
  assert.strictEqual(uses, builds,
    "docker-compose-run-tests.yml has " + builds + " build sections and " +
    uses + " references to *mirror-contexts. A build without them resolves " +
    "its FROMs against Docker Hub.");
  log.info(builds + " builds, each with the mirror contexts.");
  log.debug("Leaving everyBuildCarriesTheContexts().");
}

// BuildKit looks a FROM up by its familiar name with `:latest` dropped, so
// `ubuntu:latest` and `ubuntu` both need the context called `ubuntu`.
function contextKey(ref) {
  log.debug("Entering contextKey().");
  log.debug("Leaving contextKey().");
  return ref.replace(/^docker\.io\/(library\/)?/, "").replace(/:latest$/, "");
}

function externalRefs(source) {
  log.debug("Entering externalRefs().");
  const stages = new Set();
  const args = {};
  const refs = [];
  codeLines(source).forEach(function (line) {
    var m = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S*)/.exec(line);
    if (m) {
      args[m[1]] = m[2];
      return;
    }
    m = /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (m) {
      var ref = m[1].replace(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/,
        function (all, name) {
          return name in args ? args[name] : all;
        });
      if (ref !== "scratch" && !stages.has(ref) && ref.indexOf("$") < 0) {
        refs.push(ref);
      }
      if (m[2]) {
        stages.add(m[2]);
      }
      return;
    }
    m = /--from=(\S+)/.exec(line);
    if (m && /[:/]/.test(m[1]) && !stages.has(m[1])) {
      refs.push(m[1]);
    }
  });
  log.debug("Leaving externalRefs(). " + refs.length + " refs.");
  return refs;
}

function everyFromHasAContext(names) {
  log.debug("Entering everyFromHasAContext().");
  const bad = [];
  var n = 0;
  Object.keys(DOCKERFILES).forEach(function (repoPath) {
    const file = locate(repoPath, DOCKERFILES[repoPath]);
    externalRefs(fs.readFileSync(file, "utf8")).forEach(function (ref) {
      n++;
      if (!names.has(contextKey(ref))) {
        bad.push(repoPath + ": " + ref);
      }
    });
  });
  assert.ok(n > 0, "no FROM was parsed out of any Dockerfile.");
  assert.deepStrictEqual(bad, [],
    "These base images have no named context in x-mirror-contexts, so " +
    "BuildKit would pull them from their upstream registry. Add each to " +
    ".github/image-mirror.txt and to x-mirror-contexts in " +
    "docker-compose-run-tests.yml: " + bad.join(", "));
  log.info(n + " external FROMs in " + Object.keys(DOCKERFILES).length +
           " Dockerfiles, each redirected to the mirror.");
  log.debug("Leaving everyFromHasAContext().");
}

function test() {
  log.debug("Entering test().");
  const compose = fs.readFileSync(locate.apply(null, FILES.compose), "utf8");
  const paths = mirrorPaths(fs.readFileSync(locate.apply(null, FILES.list),
    "utf8"));
  assert.ok(paths.size > 0, "image-mirror.txt lists no images.");
  const lines = codeLines(compose);
  everyImageIsMirroredOrBuiltHere(lines, paths);
  const names = mirrorContexts(lines, paths);
  everyBuildCarriesTheContexts(compose);
  everyFromHasAContext(names);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("image_mirror_coverage")
  .description("Verify that every image the test stack pulls or builds " +
               "from comes from the ghcr.io mirror.")
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
