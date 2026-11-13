// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: image_mirror_coverage.js
//
// Every image the four compose files PULL, and every base image a Dockerfile
// they BUILD names in a FROM, must come from the private mirror on ghcr.io —
// and the mirror must list it. iya-sts's release image included: the stacks
// run the mirror's private copy of it, not iya-sts's public package.
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
//    consults before any registry — the only way to reach the companion's
//    Dockerfile, which is iya-sts's, built from that repository's tag, and
//    not edited here.
//
// BOTH FAIL OPEN. A FROM with no matching named context is not an error: it is
// pulled from Docker Hub, exactly as before, and the run is green until the
// day Docker Hub is not there. So this reads each of COMPOSE_FILES, the list
// and the Dockerfiles built from this repository and asserts, per file:
//
//  1. every `image:` (and every `docker-image://` context) is either the
//     mirror (with a path the list has) or one of this repository's own
//     built images — under IMAGE_REGISTRY, or a local `rcbj/<name>` on a
//     service that has a `build:`;
//  2. it has an x-mirror-contexts block, and every named context in it
//     points at a listed path;
//  3. every `build:` carries those contexts;
//  4. every `dockerfile:` it builds is one this test reads;
// and, across them:
//  5. every external FROM (and COPY --from) in a built Dockerfile has a
//     context in every file's block;
//  6. every compose file names the SAME iya-sts release, as a mirror path,
//     and the companion is built from that release's tag
//     (iyaStsReleaseIsNamedOnce()).
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
  list: [".github/image-mirror.txt", "image-mirror.txt"],
  builds: [".github/image-mirror-builds.txt", "image-mirror-builds.txt"],
};
// The compose files that start a stack. Their flat names in the tests image
// are their own (tests/Dockerfile COPYs each one). The overlays layered on
// top of them add no image and no build, so they are not read.
const COMPOSE_FILES = ["docker-compose-run-tests.yml",
  "docker-compose.yml", "local-tests.yml", "keycloak-tests.yml"];
// The Dockerfiles those compose files build.
const DOCKERFILES = {
  "api/Dockerfile": "api_Dockerfile",
  "client/Dockerfile": "client_Dockerfile",
  "keycloak-wsfed/Dockerfile": "keycloak-wsfed_Dockerfile",
  "shibboleth-idp/Dockerfile": "shibboleth-idp_Dockerfile",
  "tests/Dockerfile": "tests_Dockerfile",
};
// Dockerfiles built OUTSIDE the compose files — by the deploy and image
// workflows and two local scripts — whose FROMs must still be mirror
// copies, and which the network-fetch check reads like the rest.
const OTHER_DOCKERFILES = {
  "infra/Dockerfile": "infra_Dockerfile",
  "deploy/Dockerfile": "deploy_Dockerfile",
  "embedded/Dockerfile": "embedded_Dockerfile",
};
// Where those three are built. Each `-f <dir>/Dockerfile` in these files
// must sit in a command that redirects ubuntu to the mirror with
// `--build-context ubuntu=docker-image://...`. Flat names are their own.
const OTHER_BUILDERS = {
  ".github/workflows/terraform.yml": "terraform.yml",
  ".github/workflows/website-deploy-test.yml": "website-deploy-test.yml",
  ".github/workflows/website-deploy.yml": "website-deploy.yml",
  ".github/workflows/dockerimage.yml": "dockerimage.yml",
  "deploy/deploy-local.sh": "deploy-local.sh",
  "infra/terraform-local.sh": "terraform-local.sh",
};

// ---------------------------------------------------------------------------
// NETWORK FETCHES IN A BUILD, AND THE ONES STILL ALLOWED.
//
// A RUN that downloads with curl, wget or `nvm install`, a `git clone`, or an
// ADD of a URL reaches a host outside the mirror at build time, so it has
// the same failure mode the mirror exists to remove. Package-manager
// installs (apt-get, npm) are NOT counted: they are in every Dockerfile in
// the tree, they resolve against their own registries' mirrors, and moving
// them is a different piece of work.
//
// The rest must be in this list or the test fails, and an entry that no
// longer matches anything fails too, so the list only ever shrinks. Each is
// a fetch that predates this check; the way off it is the one the
// Shibboleth side-car took — an image built into the mirror from the pinned
// download (.github/image-mirror-builds.txt), COPY --from in the Dockerfile.
// ---------------------------------------------------------------------------
const NVM_SH = "https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/" +
  "install.sh";
const AWSCLI = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip";
const KNOWN_FETCHES = [
  // nvm's installer and the node it installs (nodejs.org), in the five
  // images that put node on ubuntu.
  ["api/Dockerfile", NVM_SH], ["api/Dockerfile", "nvm install"],
  ["client/Dockerfile", NVM_SH], ["client/Dockerfile", "nvm install"],
  ["tests/Dockerfile", NVM_SH], ["tests/Dockerfile", "nvm install"],
  ["deploy/Dockerfile", NVM_SH], ["deploy/Dockerfile", "nvm install"],
  ["embedded/Dockerfile", NVM_SH], ["embedded/Dockerfile", "nvm install"],
  // Chrome for Testing and its chromedriver, pinned by version.
  ["tests/Dockerfile", "https://edgedl.me.gvt1.com/edgedl/chrome/" +
    "chrome-for-testing"],
  // The Keycloak 8.0.1 server distribution and the cloudtrust module.
  ["keycloak-wsfed/Dockerfile", "https://downloads.jboss.org/keycloak/" +
    "8.0.1/keycloak-8.0.1.tar.gz"],
  ["keycloak-wsfed/Dockerfile", "https://github.com/cloudtrust/" +
    "keycloak-wsfed/releases/download/8.0.1-1.0/" +
    "keycloak-wsfed-8.0.1-1.0.tar.gz"],
  // The AWS CLI and Terraform in the two deployment images.
  ["infra/Dockerfile", AWSCLI],
  ["infra/Dockerfile", "https://releases.hashicorp.com/terraform/"],
  ["deploy/Dockerfile", AWSCLI],
];

const MIRROR_PREFIX = "${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}/";
// The names an image BUILT here goes by: under IMAGE_REGISTRY on the test
// stack (tests.yml pushes those), and a bare local `rcbj/<name>` in the
// other three files (dockerimage.yml retags and publishes rcbj/api and
// rcbj/client from docker-compose.yml's build). Either is accepted only on a
// service that has a `build:`, so a pulled image cannot hide behind one.
const BUILT_PREFIXES = [
  "${IMAGE_REGISTRY:-ghcr.io/rcbj/id-proto-debugger}/",
  "rcbj/",
];
// iya-sts's release image is named `${IYA_STS_IMAGE:-<default>}` so that a
// candidate can be run instead, and its companion
// `${IYA_STS_COMPANION_IMAGE:-<default>}`; the DEFAULT is what is checked.
const IYA_STS_OPEN = "${IYA_STS_IMAGE:-";
const COMPANION_OPEN = "${IYA_STS_COMPANION_IMAGE:-";
// Variables whose `${NAME:-default}` IS the mirror or registry prefix, and
// so are part of a reference rather than a wrapper around one.
const PREFIX_VARIABLES = ["IMAGE_MIRROR", "IMAGE_REGISTRY", "IMAGE_TAG"];

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

// The mirror paths a list names: the SECOND column of image-mirror.txt
// (`upstream  mirror-path`), or the FIRST of image-mirror-builds.txt
// (`mirror-path  source`), selected by `column`.
function mirrorPaths(source, column) {
  log.debug("Entering mirrorPaths().");
  const paths = new Set();
  source.split("\n").forEach(function (line) {
    const t = line.trim();
    if (!t || t.charAt(0) === "#") {
      return;
    }
    const cols = t.split(/\s+/);
    assert.strictEqual(cols.length, 2,
      "mirror list: expected two columns, got: " + line);
    paths.add(cols[column === undefined ? 1 : column]);
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

// `${NAME:-X}` -> X, matching braces, for a variable that WRAPS a reference
// (IYA_STS_IMAGE, IYA_STS_COMPANION_IMAGE, ...) rather than being a prefix
// inside one; X itself nests `${IMAGE_MIRROR:-...}`. Anything else is
// returned unchanged.
function unwrapIyaStsImage(ref) {
  log.debug("Entering unwrapIyaStsImage().");
  const m = /^\$\{([A-Za-z_][A-Za-z0-9_]*):-/.exec(ref);
  if (!m || PREFIX_VARIABLES.indexOf(m[1]) >= 0) {
    log.debug("Leaving unwrapIyaStsImage(). Not wrapped.");
    return ref;
  }
  const inner = balancedDefault(ref, 0, m[0]);
  log.debug("Leaving unwrapIyaStsImage().");
  return inner === null ? ref : inner;
}

// The default inside the `${NAME:-...}` (open = "${NAME:-") that starts at
// `start`, read up to ITS closing brace rather than the first one; null when
// unbalanced on that line.
function balancedDefault(text, start, open) {
  log.debug("Entering balancedDefault().");
  const opener = open || IYA_STS_OPEN;
  var depth = 1;
  for (var i = start + opener.length; i < text.length; i++) {
    if (text.startsWith("${", i)) {
      depth++;
      i++;
    } else if (text.charAt(i) === "}") {
      depth--;
      if (depth === 0) {
        log.debug("Leaving balancedDefault(). Found.");
        return text.slice(start + opener.length, i);
      }
    } else if (text.charAt(i) === "\n") {
      break;
    }
  }
  log.debug("Leaving balancedDefault(). Unbalanced.");
  return null;
}

// Every `${OPEN...}` default in `text`, each read by matching braces.
function defaultsOf(name, text, open) {
  log.debug("Entering defaultsOf(). " + name);
  const found = [];
  var at = text.indexOf(open);
  while (at >= 0) {
    const ref = balancedDefault(text, at, open);
    assert.ok(ref !== null,
      name + ": a " + open + "...} default has unbalanced braces.");
    found.push({ file: name, ref: ref });
    at = text.indexOf(open, at + open.length);
  }
  log.debug("Leaving defaultsOf(). " + found.length);
  return found;
}

// A BUILD CONTEXT IS SOURCE, AND A REMOTE ONE IS FETCHED AT BUILD TIME.
// `context:` must be this checkout (`.` or a path in it). A git URL or an
// http(s) tarball is a test run reaching GitHub or a web server for its
// source, which is what building the companion into the mirror ended.
function noRemoteBuildContext(name, lines) {
  log.debug("Entering noRemoteBuildContext(). " + name);
  const bad = [];
  var n = 0;
  lines.forEach(function (line) {
    const m = /^\s+context:\s*(\S+)\s*$/.exec(line);
    if (!m) {
      return;
    }
    n++;
    const ref = unwrapIyaStsImage(m[1]);
    if (/^(?:https?:|git@|git:|ssh:)|\.git(?:#|$)/.test(ref)) {
      bad.push(ref);
    }
  });
  assert.deepStrictEqual(bad, [],
    name + " builds from a remote context, fetched at build time: " +
    bad.join(", ") + ". Build it into the mirror instead " +
    "(.github/image-mirror-builds.txt) and pull it as an `image:`.");
  log.info(name + ": " + n + " build contexts, all local.");
  log.debug("Leaving noRemoteBuildContext().");
}

// Service name -> whether its block has a `build:`. Services are the
// two-space keys under the top-level `services:`.
function servicesWithBuild(lines) {
  log.debug("Entering servicesWithBuild().");
  const built = {};
  var inServices = false;
  var service = null;
  lines.forEach(function (line) {
    if (/^\S/.test(line)) {
      inServices = /^services:\s*$/.test(line);
      service = null;
      return;
    }
    if (!inServices) {
      return;
    }
    const m = /^  ([A-Za-z0-9_.-]+):\s*$/.exec(line);
    if (m) {
      service = m[1];
      built[service] = false;
      return;
    }
    if (service && /^    build:\s*$/.test(line)) {
      built[service] = true;
    }
  });
  log.debug("Leaving servicesWithBuild().");
  return built;
}

function everyImageIsMirroredOrBuiltHere(name, lines, paths) {
  log.debug("Entering everyImageIsMirroredOrBuiltHere(). " + name);
  const built = servicesWithBuild(lines);
  const bad = [];
  var n = 0;
  var service = null;
  lines.forEach(function (line) {
    const svc = /^  ([A-Za-z0-9_.-]+):\s*$/.exec(line);
    if (svc) {
      service = svc[1];
    }
    const m = /^\s+image:\s*(\S+)\s*$/.exec(line) ||
      /^\s+"?[^\s":]+(?::[^\s"]+)?"?:\s*docker-image:\/\/(\S+)\s*$/
        .exec(line);
    if (!m) {
      return;
    }
    n++;
    const ref = unwrapIyaStsImage(m[1]);
    if (ref.indexOf(MIRROR_PREFIX) === 0) {
      if (!paths.has(ref.slice(MIRROR_PREFIX.length))) {
        bad.push(ref + " (mirror path not in image-mirror.txt)");
      }
      return;
    }
    const local = BUILT_PREFIXES.some(function (p) {
      return ref.indexOf(p) === 0;
    });
    if (!local) {
      bad.push(ref + " (neither the mirror nor a name built here)");
    } else if (!/^\s+image:/.test(line) || !built[service]) {
      bad.push(ref + " (a built-here name on " + service +
        ", which builds nothing)");
    }
  });
  assert.ok(n > 0, "no `image:` line was parsed out of " + name + ".");
  assert.deepStrictEqual(bad, [],
    "These images in " + name + " would be pulled from somewhere other " +
    "than the ghcr.io mirror: " + bad.join(", "));
  log.info(name + ": " + n + " image references, all from the mirror or " +
    "built here.");
  log.debug("Leaving everyImageIsMirroredOrBuiltHere().");
}

// The `x-mirror-contexts:` block: two-space-indented `key: docker-image://…`
// lines up to the next top-level key. Returns the context names.
function mirrorContexts(name, lines, paths) {
  log.debug("Entering mirrorContexts(). " + name);
  const start = lines.findIndex(function (line) {
    return /^x-mirror-contexts:/.test(line);
  });
  assert.ok(start >= 0,
    name + " has no top-level x-mirror-contexts block.");
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
  assert.ok(names.size > 0, name + ": x-mirror-contexts parsed as empty.");
  assert.deepStrictEqual(bad, [],
    name + ": these named contexts do not point at a listed mirror path: " +
    bad.join(", "));
  log.debug("Leaving mirrorContexts(). " + names.size + " contexts.");
  return names;
}

function everyBuildCarriesTheContexts(name, source) {
  log.debug("Entering everyBuildCarriesTheContexts(). " + name);
  const code = codeLines(source).join("\n");
  const builds = (code.match(/^\s+build:\s*$/gm) || []).length;
  const uses = (code.match(/\*mirror-contexts\b/g) || []).length;
  assert.ok(builds > 0, name + ": no `build:` section was parsed.");
  assert.strictEqual(uses, builds,
    name + " has " + builds + " build sections and " +
    uses + " references to *mirror-contexts. A build without them resolves " +
    "its FROMs against Docker Hub.");
  log.info(name + ": " + builds + " builds, each with the mirror contexts.");
  log.debug("Leaving everyBuildCarriesTheContexts().");
}

// A Dockerfile the compose file builds and DOCKERFILES does not name is
// one whose FROMs nobody reads, so a new built service would pass this
// test while pulling its base from Docker Hub. Every `dockerfile:` path
// must be listed. (The companion's comes from a git context and names
// none.)
function everyBuiltDockerfileIsRead(name, lines) {
  log.debug("Entering everyBuiltDockerfileIsRead(). " + name);
  const missing = [];
  var n = 0;
  lines.forEach(function (line) {
    const m = /^\s+dockerfile:\s*(\S+)\s*$/.exec(line);
    if (!m) {
      return;
    }
    n++;
    const file = m[1].replace(/^\.\//, "");
    if (!(file in DOCKERFILES)) {
      missing.push(file);
    }
  });
  assert.ok(n > 0, name + ": no `dockerfile:` was parsed.");
  assert.deepStrictEqual(missing, [],
    name + " builds these Dockerfiles and this test " +
    "does not read them. Add each to DOCKERFILES here and COPY it into " +
    "tests/Dockerfile: " + missing.join(", "));
  log.info(name + ": " + n + " dockerfile: entries, each one read.");
  log.debug("Leaving everyBuiltDockerfileIsRead().");
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

// The Dockerfiles one compose file builds, as DOCKERFILES keys.
function builtDockerfiles(lines) {
  log.debug("Entering builtDockerfiles().");
  const files = [];
  lines.forEach(function (line) {
    const m = /^\s+dockerfile:\s*(\S+)\s*$/.exec(line);
    if (m) {
      files.push(m[1].replace(/^\.\//, ""));
    }
  });
  log.debug("Leaving builtDockerfiles(). " + files.length);
  return files;
}

function everyFromHasAContext(name, names, files) {
  log.debug("Entering everyFromHasAContext(). " + name);
  const bad = [];
  var n = 0;
  files.forEach(function (repoPath) {
    const file = locate(repoPath, DOCKERFILES[repoPath]);
    externalRefs(fs.readFileSync(file, "utf8")).forEach(function (ref) {
      n++;
      if (!names.has(contextKey(ref))) {
        bad.push(repoPath + ": " + ref);
      }
    });
  });
  assert.ok(n > 0, name + ": no FROM was parsed out of its Dockerfiles.");
  assert.deepStrictEqual(bad, [],
    "These base images have no named context in " + name + "'s " +
    "x-mirror-contexts, so BuildKit would pull them from their upstream " +
    "registry. Add each to .github/image-mirror.txt and to every compose " +
    "file's x-mirror-contexts: " + bad.join(", "));
  log.info(name + ": " + n + " external FROMs in " + files.length +
           " Dockerfiles, each redirected to the mirror.");
  log.debug("Leaving everyFromHasAContext().");
}

// ---------------------------------------------------------------------------
// WHAT A DOCKERFILE FETCHES WHILE IT BUILDS.
// ---------------------------------------------------------------------------

// Instructions with `\` continuations joined and comment lines dropped, and
// each ARG's default substituted into the instructions after it, so a URL
// held in an ARG is seen where it is used.
function instructions(source) {
  log.debug("Entering instructions().");
  const out = [];
  const args = {};
  var current = "";
  source.split("\n").forEach(function (line) {
    if (/^\s*#/.test(line)) {
      return;
    }
    if (/\\\s*$/.test(line)) {
      current += line.replace(/\\\s*$/, " ");
      return;
    }
    current += line;
    var text = current.trim();
    current = "";
    if (!text) {
      return;
    }
    Object.keys(args).forEach(function (name) {
      text = text.split("${" + name + "}").join(args[name])
        .split("$" + name).join(args[name]);
    });
    const arg = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S*)/.exec(text);
    if (arg) {
      args[arg[1]] = arg[2];
    }
    out.push(text);
  });
  log.debug("Leaving instructions(). " + out.length);
  return out;
}

// Each network fetch in a Dockerfile: the URLs a RUN hands curl, wget or
// `git clone`, an `nvm install`, and every ADD of a URL (with whether it
// carries --checksum). apt-get and npm are deliberately not counted.
function fetchesIn(source) {
  log.debug("Entering fetchesIn().");
  const found = [];
  instructions(source).forEach(function (text) {
    const urls = text.match(/https?:\/\/[^\s"'|;)]+/g) || [];
    if (/^RUN\s/i.test(text)) {
      if (/\b(?:curl|wget)\b[^&|;]*https?:\/\/|\bgit\s+clone\b/
        .test(text) || /\b(?:curl|wget)\b[^&|;]*\$\{?[A-Za-z]/
        .test(text) && urls.length) {
        urls.forEach(function (url) {
          found.push({ url: url, checksum: false });
        });
      }
      if (/\bnvm\s+install\b/.test(text)) {
        found.push({ url: "nvm install", checksum: false });
      }
    } else if (/^ADD\s/i.test(text) && urls.length) {
      urls.forEach(function (url) {
        found.push({ url: url, checksum: /--checksum=/.test(text) });
      });
    }
  });
  log.debug("Leaving fetchesIn(). " + found.length);
  return found;
}

function noUnlistedNetworkFetch() {
  log.debug("Entering noUnlistedNetworkFetch().");
  const all = Object.assign({}, DOCKERFILES, OTHER_DOCKERFILES);
  const bad = [];
  const used = new Set();
  var n = 0;
  Object.keys(all).forEach(function (repoPath) {
    const source = fs.readFileSync(locate(repoPath, all[repoPath]), "utf8");
    fetchesIn(source).forEach(function (fetch) {
      n++;
      const known = KNOWN_FETCHES.findIndex(function (entry) {
        return entry[0] === repoPath && fetch.url.indexOf(entry[1]) === 0;
      });
      if (known < 0) {
        bad.push(repoPath + ": " + fetch.url);
      } else {
        used.add(known);
      }
    });
  });
  assert.deepStrictEqual(bad, [],
    "These Dockerfiles download from outside the mirror while they build: " +
    bad.join(", ") + ". Build the download into a mirror image " +
    "(.github/image-mirror-builds.txt, ADD --checksum) and COPY --from it, " +
    "as shibboleth-idp/Dockerfile does. apt-get and npm are not counted.");
  const stale = KNOWN_FETCHES.filter(function (entry, i) {
    return !used.has(i);
  }).map(function (entry) {
    return entry[0] + ": " + entry[1];
  });
  assert.deepStrictEqual(stale, [],
    "KNOWN_FETCHES lists downloads no Dockerfile makes any more; delete " +
    "them so the list only shrinks: " + stale.join(", "));
  log.info(n + " network fetches in " + Object.keys(all).length +
    " Dockerfiles, each one of the " + KNOWN_FETCHES.length +
    " known ones.");
  log.debug("Leaving noUnlistedNetworkFetch().");
}

// The three Dockerfiles built outside compose: every external FROM is a
// name image-mirror.txt copies (so a --build-context can redirect it), and
// every place that builds one passes that context for ubuntu.
function otherDockerfilesUseTheMirror(upstreams) {
  log.debug("Entering otherDockerfilesUseTheMirror().");
  const bad = [];
  Object.keys(OTHER_DOCKERFILES).forEach(function (repoPath) {
    const source = fs.readFileSync(
      locate(repoPath, OTHER_DOCKERFILES[repoPath]), "utf8");
    externalRefs(source).forEach(function (ref) {
      if (!upstreams.has(contextKey(ref))) {
        bad.push(repoPath + ": FROM " + ref + " is not in image-mirror.txt");
      } else if (contextKey(ref) !== "ubuntu") {
        bad.push(repoPath + ": FROM " + ref + " — its builders redirect " +
          "only ubuntu; add a --build-context for it there and here");
      }
    });
  });
  var builds = 0;
  Object.keys(OTHER_BUILDERS).forEach(function (repoPath) {
    const lines = fs.readFileSync(
      locate(repoPath, OTHER_BUILDERS[repoPath]), "utf8").split("\n");
    lines.forEach(function (line, i) {
      const m = new RegExp("-f\\s+\"?(?:\\$\\{REPO_ROOT\\}/)?" +
        "(infra|deploy|embedded)/Dockerfile").exec(line);
      if (!m) {
        return;
      }
      builds++;
      const command = lines.slice(Math.max(0, i - 6), i + 3).join("\n");
      if (!/--build-context\s+"?ubuntu=docker-image:\/\//.test(command)) {
        bad.push(repoPath + ":" + (i + 1) + " builds " + m[1] +
          "/Dockerfile without --build-context ubuntu=docker-image://...");
      }
    });
  });
  assert.ok(builds > 0, "no build of infra, deploy or embedded was found.");
  assert.deepStrictEqual(bad, [],
    "Dockerfiles built outside the compose files would pull from Docker " +
    "Hub: " + bad.join("; "));
  log.info(Object.keys(OTHER_DOCKERFILES).length + " Dockerfiles built " +
    "outside compose, in " + builds + " places, each from the mirror.");
  log.debug("Leaving otherDockerfilesUseTheMirror().");
}

// The images BUILT into the mirror: a local source is a Dockerfile whose
// every ADD of a URL is pinned by --checksum, since that pin is the whole
// of what makes the mirror copy trustworthy.
function mirrorBuildsArePinned(builds) {
  log.debug("Entering mirrorBuildsArePinned().");
  const bad = [];
  var n = 0;
  builds.forEach(function (row) {
    if (row.source.indexOf("./") !== 0) {
      return;
    }
    const dir = row.source.slice(2).replace(/\/$/, "");
    const flat = dir.replace(/\//g, "-") + "_Dockerfile";
    const source = fs.readFileSync(locate(dir + "/Dockerfile", flat), "utf8");
    fetchesIn(source).forEach(function (fetch) {
      n++;
      if (!fetch.checksum) {
        bad.push(row.path + ": " + fetch.url);
      }
    });
  });
  assert.ok(n > 0, "no pinned download was parsed out of a mirror build.");
  assert.deepStrictEqual(bad, [],
    "These mirror builds download without ADD --checksum: " +
    bad.join(", "));
  log.info(n + " downloads in the mirror builds, each pinned by checksum.");
  log.debug("Leaving mirrorBuildsArePinned().");
}

// The rows of image-mirror-builds.txt.
function buildRows(source) {
  log.debug("Entering buildRows().");
  const rows = [];
  source.split("\n").forEach(function (line) {
    const t = line.trim();
    if (!t || t.charAt(0) === "#") {
      return;
    }
    const cols = t.split(/\s+/);
    rows.push({ path: cols[0], source: cols[1] });
  });
  log.debug("Leaving buildRows(). " + rows.length);
  return rows;
}

// The upstream names image-mirror.txt copies, as BuildKit looks them up.
function upstreamNames(source) {
  log.debug("Entering upstreamNames().");
  const names = new Set();
  source.split("\n").forEach(function (line) {
    const t = line.trim();
    if (t && t.charAt(0) !== "#") {
      names.add(contextKey(t.split(/\s+/)[0]));
    }
  });
  log.debug("Leaving upstreamNames(). " + names.size);
  return names;
}

// ---------------------------------------------------------------------------
// THE iya-sts RELEASE IS NAMED ONCE.
//
// docker-compose-run-tests.yml's `${IYA_STS_IMAGE:-...}` default is the one
// place the release is named; tests/module_paths.js and common/common.sh read
// it from there. The other compose files cannot read it (compose has no
// include for a default), so they repeat it, and the companion is built from
// the iya-sts repository at the matching tag
// (`${IYA_STS_COMPANION_CONTEXT:-https://...git#v<version>:companion}`).
// Each repetition is a place a release bump can miss, and a miss is a stack
// running one release beside a companion — or a host stack — of another,
// which fails naming a protocol. So every one is held to the first.
//
// And the default is the MIRROR's copy of that release, `${IMAGE_MIRROR:-
// ...}/iya-sts:<version>`, refreshed from iya-sts's published package by the
// Mirror Images workflow — not that public package itself. A default that
// names ghcr.io/rcbj/iya-sts directly is a stack depending on a package
// outside this repository's area, which is what this whole test forbids.
// ---------------------------------------------------------------------------

function iyaStsReleaseIsNamedOnce(builds) {
  log.debug("Entering iyaStsReleaseIsNamedOnce().");
  var images = [];
  var companions = [];
  COMPOSE_FILES.forEach(function (name) {
    const text = codeLines(fs.readFileSync(locate(name, name), "utf8"))
      .join("\n");
    images = images.concat(defaultsOf(name, text, IYA_STS_OPEN));
    companions = companions.concat(defaultsOf(name, text, COMPANION_OPEN));
  });
  assert.ok(images.length > 0 && images[0].file === COMPOSE_FILES[0],
    "docker-compose-run-tests.yml names no ${IYA_STS_IMAGE:-...} default.");
  const release = images[0].ref;
  assert.ok(release.indexOf(MIRROR_PREFIX + "iya-sts:") === 0,
    "the iya-sts default " + release + " is not the mirror's copy " +
    "(" + MIRROR_PREFIX + "iya-sts:<version>).");
  const tag = /:([^:/@]+)$/.exec(release);
  assert.ok(tag, "the iya-sts default " + release + " carries no tag.");
  const disagree = images.filter(function (one) {
    return one.ref !== release;
  }).map(function (one) {
    return one.file + ": " + one.ref;
  });
  assert.deepStrictEqual(disagree, [],
    "These compose files run a different iya-sts release from " +
    "docker-compose-run-tests.yml's " + release + ": " + disagree.join(", "));
  COMPOSE_FILES.forEach(function (name) {
    assert.ok(images.some(function (one) {
      return one.file === name;
    }), name + " does not run ${IYA_STS_IMAGE:-" + release + "}.");
  });
  // The companion: the mirror image of this release's tag, in every file
  // that runs one, and built into the mirror from that same tag.
  const companionPath = "iya-sts-companion:v" + tag[1];
  const wanted = MIRROR_PREFIX + companionPath;
  assert.ok(companions.length >= 3,
    "expected the companion's IYA_STS_COMPANION_IMAGE default in three " +
    "compose files, found " + companions.length + ".");
  const stale = companions.filter(function (one) {
    return one.ref !== wanted;
  }).map(function (one) {
    return one.file + ": " + one.ref;
  });
  assert.deepStrictEqual(stale, [],
    "The companion must be the mirror's build of the iya-sts release the " +
    "stack runs (" + wanted + "): " + stale.join(", "));
  const source = "https://github.com/rcbj/iya-sts.git#v" + tag[1] +
    ":companion";
  const row = builds.filter(function (one) {
    return one.path === companionPath;
  })[0];
  assert.ok(row, "image-mirror-builds.txt does not build " + companionPath +
    ", the companion of the release the stack runs.");
  assert.strictEqual(row.source, source,
    "image-mirror-builds.txt builds " + companionPath + " from " +
    row.source + ", not from that release's tag (" + source + ").");
  log.info("iya-sts " + release + " is named the same way in " +
    images.length + " places, and its companion " + companionPath +
    " in " + companions.length + ", built from v" + tag[1] + ".");
  log.debug("Leaving iyaStsReleaseIsNamedOnce().");
}

function test() {
  log.debug("Entering test().");
  const list = fs.readFileSync(locate.apply(null, FILES.list), "utf8");
  const buildList = fs.readFileSync(locate.apply(null, FILES.builds),
    "utf8");
  const builds = buildRows(buildList);
  const paths = mirrorPaths(list);
  mirrorPaths(buildList, 0).forEach(function (one) {
    paths.add(one);
  });
  assert.ok(paths.size > 0, "image-mirror.txt lists no images.");
  COMPOSE_FILES.forEach(function (name) {
    const compose = fs.readFileSync(locate(name, name), "utf8");
    const lines = codeLines(compose);
    everyImageIsMirroredOrBuiltHere(name, lines, paths);
    const names = mirrorContexts(name, lines, paths);
    everyBuildCarriesTheContexts(name, compose);
    everyBuiltDockerfileIsRead(name, lines);
    noRemoteBuildContext(name, lines);
    everyFromHasAContext(name, names, builtDockerfiles(lines));
  });
  otherDockerfilesUseTheMirror(upstreamNames(list));
  noUnlistedNetworkFetch();
  mirrorBuildsArePinned(builds);
  iyaStsReleaseIsNamedOnce(builds);
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
