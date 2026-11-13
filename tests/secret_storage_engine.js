// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: secret_storage_engine.js
//
// ---------------------------------------------------------------------------
// What the browser may keep, driven in node with no browser and no network.
//
//   * A client secret or a password is never written to localStorage or
//     sessionStorage, by any module under client/src.
//   * The three bearer credentials that are not the workflow's output
//     (registration_access_token, dcr_initial_access_token,
//     introspection_bearer_token) are never written to localStorage.
//   * No OAuth 2.0 / OIDC page marks a secret, password or one of those
//     bearer fields with the `stored` class.
//   * Every page with such a field purges older copies on load.
//
// client/src/secret_storage.js is exercised against two in-memory stores,
// and the pages are checked by reading them.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments, so
// node ignores that pair. Do not add commander here without declaring
// `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "secret_storage_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the sources are beside tests/. In the tests image they are
// the copy tests/Dockerfile stages at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  var i;
  for (i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const REPO = repoRoot();
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");
const secretStorage = paths.requireSharedModule(
    [path.join(SRC, "secret_storage.js")],
    "client/src/secret_storage.js");

// The OAuth 2.0 / OIDC pages the rule was written for.
const OAUTH_PAGES = ["oauth2_oidc_1", "oauth2_oidc_2", "token_detail",
    "introspection", "jwks", "userinfo", "logout"];

// A boolean that says whether a secret exists. Not a credential.
const ALLOWED_SECRETISH_KEYS = ["client_has_secret"];

function memoryStore(initial) {
  log.debug("Entering memoryStore().");
  var data = Object.assign({}, initial || {});
  var store = {
    data: data,
    getItem: function (key) {
      return Object.prototype.hasOwnProperty.call(data, key) ?
          data[key] : null;
    },
    setItem: function (key, value) {
      data[key] = String(value);
    },
    removeItem: function (key) {
      delete data[key];
    }
  };
  log.debug("Leaving memoryStore().");
  return store;
}

function codeLines(source) {
  log.debug("Entering codeLines().");
  var text = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  log.debug("Leaving codeLines().");
  return text;
}

function purgeRemovesEveryOlderCopy() {
  log.debug("Entering purgeRemovesEveryOlderCopy().");
  var seeded = {};
  secretStorage.SECRET_KEYS.forEach(function (key) {
    seeded[key] = "s3cret";
  });
  secretStorage.SESSION_KEYS.forEach(function (key) {
    seeded[key] = "bearer";
  });
  seeded.client_id = "kept";
  var local = memoryStore(seeded);
  var session = memoryStore({ client_secret: "s3cret",
      registration_access_token: "bearer" });
  secretStorage.purgeOnLoad(local, session);
  assert.deepStrictEqual(Object.keys(local.data), ["client_id"],
      "purgeOnLoad left a secret or a bearer token in localStorage");
  assert.deepStrictEqual(Object.keys(session.data),
      ["registration_access_token"],
      "purgeOnLoad removed a bearer token from sessionStorage, or left " +
      "a secret there");
  secretStorage.purgeOnLoad(null, undefined);
  log.info("OK — a load removes every stored secret and every " +
      "localStorage bearer token.");
  log.debug("Leaving purgeRemovesEveryOlderCopy().");
}

function sessionKeysOnly() {
  log.debug("Entering sessionKeysOnly().");
  var session = memoryStore();
  secretStorage.sessionSet(session, "client_secret", "s3cret");
  secretStorage.sessionSet(session, "token_password", "pw");
  assert.deepStrictEqual(session.data, {},
      "sessionSet stored a secret");
  secretStorage.sessionSet(session, "registration_access_token", "rat");
  assert.strictEqual(secretStorage.sessionGet(session,
      "registration_access_token"), "rat");
  secretStorage.sessionSet(session, "registration_access_token", "");
  assert.deepStrictEqual(session.data, {},
      "an empty value was stored rather than removed");
  assert.strictEqual(secretStorage.sessionGet(memoryStore(
      { client_secret: "x" }), "client_secret"), "");
  log.info("OK — sessionStorage takes the three bearer keys and nothing " +
      "else.");
  log.debug("Leaving sessionKeysOnly().");
}

function registrationDocumentLosesItsCredentials() {
  log.debug("Entering registrationDocumentLosesItsCredentials().");
  var doc = JSON.stringify({ client_id: "c", client_secret: "s3cret",
      registration_access_token: "rat", client_name: "n" });
  var stored = JSON.parse(secretStorage.withoutSecretMembers(doc));
  assert.deepStrictEqual(stored, { client_id: "c", client_name: "n" });
  var broken = '{ "client_id": "c", "client_secret": "s3\\"cret",';
  var scrubbed = secretStorage.withoutSecretMembers(broken);
  assert.ok(scrubbed.indexOf("s3") < 0,
      "a half-edited document kept its secret: " + scrubbed);
  assert.ok(scrubbed.indexOf('"client_id": "c"') >= 0);
  log.info("OK — the stored registration document carries no credential.");
  log.debug("Leaving registrationDocumentLosesItsCredentials().");
}

// Every literal key written to either store, anywhere under client/src.
function literalWrites(code) {
  log.debug("Entering literalWrites().");
  var re = /(localStorage|sessionStorage)\s*\.\s*setItem\(\s*["']([^"']+)["']/g;
  var found = [];
  var m;
  while ((m = re.exec(code)) !== null) {
    found.push({ store: m[1], key: m[2] });
  }
  log.debug("Leaving literalWrites().");
  return found;
}

function noModuleWritesASecret() {
  log.debug("Entering noModuleWritesASecret().");
  var files = fs.readdirSync(SRC).filter(function (name) {
    return /\.js$/.test(name) && name !== "secret_storage.js";
  });
  var problems = [];
  files.forEach(function (name) {
    var code = codeLines(fs.readFileSync(path.join(SRC, name), "utf8"));
    literalWrites(code).forEach(function (w) {
      var secretish = /secret|passw/i.test(w.key) &&
          ALLOWED_SECRETISH_KEYS.indexOf(w.key) < 0;
      if (secretish || secretStorage.SECRET_KEYS.indexOf(w.key) >= 0) {
        problems.push(name + " writes " + w.key + " to " + w.store);
      }
      if (w.store === "localStorage" &&
          secretStorage.SESSION_KEYS.indexOf(w.key) >= 0) {
        problems.push(name + " writes the bearer token " + w.key +
            " to localStorage");
      }
    });
    var read = new RegExp("(localStorage|sessionStorage)\\s*\\.\\s*" +
        "getItem\\(\\s*[\"'](" + secretStorage.SECRET_KEYS.join("|") +
        ")[\"']");
    var hit = code.match(read);
    if (hit) {
      problems.push(name + " still reads " + hit[2] + " from " + hit[1]);
    }
  });
  var userinfo = codeLines(fs.readFileSync(path.join(SRC, "userinfo.js"),
      "utf8"));
  if (/storeField\(\s*["'][^"']*(secret|passw)/i.test(userinfo)) {
    problems.push("userinfo.js stores a secret field through storeField()");
  }
  assert.deepStrictEqual(problems, [], problems.join("\n"));
  log.info("OK — no module writes a secret or a password to any storage, " +
      "or a bearer token to localStorage.");
  log.debug("Leaving noModuleWritesASecret().");
}

function noPageMarksASecretStored() {
  log.debug("Entering noPageMarksASecretStored().");
  var problems = [];
  OAUTH_PAGES.forEach(function (page) {
    var file = path.join(PUBLIC, page + ".html");
    if (!fs.existsSync(file)) {
      return;
    }
    var html = fs.readFileSync(file, "utf8");
    var tags = html.match(/<(input|textarea|select)\b[^>]*>/g) || [];
    tags.forEach(function (tag) {
      var id = (tag.match(/\bid="([^"]+)"/) || [])[1] || "";
      var stored = /\bclass="[^"]*\bstored\b/.test(tag);
      var credential = /secret|passw/i.test(id) ||
          secretStorage.SESSION_KEYS.indexOf(id) >= 0;
      if (stored && credential) {
        problems.push(page + ".html marks " + id + " as stored");
      }
    });
  });
  assert.deepStrictEqual(problems, [], problems.join("\n"));
  log.info("OK — no OAuth page marks a credential field as stored.");
  log.debug("Leaving noPageMarksASecretStored().");
}

function thePagesPurgeOnLoad() {
  log.debug("Entering thePagesPurgeOnLoad().");
  ["oauth2_oidc_1.js", "oauth2_oidc_2.js", "introspection.js",
   "userinfo.js"].forEach(function (name) {
    var code = codeLines(fs.readFileSync(path.join(SRC, name), "utf8"));
    assert.ok(code.indexOf('require("./secret_storage")') >= 0,
        name + " does not load secret_storage.js");
    assert.ok(code.indexOf("secretStorage.purgeOnLoad(") >= 0,
        name + " does not purge stored secrets on load");
  });
  var step1 = codeLines(fs.readFileSync(path.join(SRC, "oauth2_oidc_1.js"),
      "utf8"));
  assert.ok(step1.indexOf("withoutSecretMembers(") >= 0,
      "the stored registration document can still carry client_secret");
  assert.ok(step1.indexOf("confidentialClient:") >= 0,
      "the RFC 9700 public-client check has no basis but a stored secret");
  log.info("OK — every page with a credential field purges on load.");
  log.debug("Leaving thePagesPurgeOnLoad().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  purgeRemovesEveryOlderCopy();
  sessionKeysOnly();
  registrationDocumentLosesItsCredentials();
  noModuleWritesASecret();
  noPageMarksASecretStored();
  thePagesPurgeOnLoad();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
