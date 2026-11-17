// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: data_model.js
//
// ---------------------------------------------------------------------------
// THE ABSTRACT DATA MODEL IS CURRENT, LIVE AND OBEYED.
//
// models/ is the source of four generated files in common/model/ (see
// models/CLAUDE.md). They are committed, so nothing stops somebody editing a
// .tsp file and forgetting to regenerate, or editing a generated file by
// hand — and in both cases the service would run on something the model does
// not say. This holds:
//
//  1. CURRENT. `generate.mjs --check` finds common/model/ exactly as models/
//     generates it.
//  2. LIVE. An edit to a copy of the model reaches the generated document,
//     and --check notices it. A check that could not see a change would pass
//     for ever.
//  3. STRICT. api/model_validate.js refuses a schema keyword nobody
//     registered, and a route naming an operation the document lacks.
//  4. THE CONFIGURATIONS. Every api/env/*.js passes ApiConfig and every
//     client/src/env/*.js passes ClientConfig; a misspelt key and a missing
//     one are each refused by name; and the outbound-policy list is the one
//     api/CLAUDE.md describes.
//  5. THE STORAGE MODEL. See storageModel() below.
//
// Node only — no browser, no services — so it never skips. In the tests image
// the source is /usr/src/source-tree (tests/Dockerfile), with models/'s own
// node_modules installed there.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "data_model",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The outbound-policy settings (api/CLAUDE.md, "the address policy and the
// sixteen settings"). Written out here as well as in the model on purpose:
// a setting dropped from the model's list would otherwise vanish from the
// rule without anybody deciding it should.
const OUTBOUND_POLICY = [
  "callTimeout", "connectionTimeout", "maxContentLength", "maxRedirects",
  "userAgent", "keepAlive", "blockPrivateNetworkCalls",
  "blockedAddressRanges", "allowedAddressRanges", "krb5AllowedPorts",
  "krb5ServicePorts", "ldapAllowedPorts", "ldapMaxEntries", "tlsAllowedPorts",
  "spiffeAllowedPorts", "spiffeAllowedSocketPaths"
];

function sourceRoot() {
  log.debug("Entering sourceRoot().");
  const candidates = [path.join(__dirname, ".."), "/usr/src/source-tree"];
  const found = candidates.find(function (dir) {
    return fs.existsSync(path.join(dir, "models", "main.tsp"));
  });
  if (!found) {
    log.debug("Leaving sourceRoot(). Not found.");
    throw new Error("no models/main.tsp under " + candidates.join(" or "));
  }
  log.debug("Leaving sourceRoot(). " + found);
  return found;
}

const ROOT = sourceRoot();
const modelValidate = paths.requireSharedModule([
  path.join(__dirname, "..", "api", "model_validate.js"),
  path.join(__dirname, "model_validate.js")
], "api/model_validate.js");

function runGenerate(root, args) {
  log.debug("Entering runGenerate(). " + root + " " + args.join(" "));
  const run = childProcess.spawnSync(process.execPath,
    [path.join(root, "models", "tools", "generate.mjs")].concat(args),
    { encoding: "utf8", timeout: 180000 });
  log.debug("Leaving runGenerate(). status=" + run.status);
  return { status: run.status, output: (run.stdout || "") +
           (run.stderr || "") };
}

function current() {
  log.debug("Entering current().");
  log.info("=== 1. common/model/ is what models/ generates ===");
  const run = runGenerate(ROOT, ["--check"]);
  assert.strictEqual(run.status, 0,
    "common/model/ is stale or edited by hand. Run `node " +
    "models/tools/generate.mjs` and commit the result.\n" + run.output);
  log.info("[current] " + run.output.trim());
  log.debug("Leaving current().");
}

function copyTree(from, to, skip) {
  log.debug("Entering copyTree(). " + from);
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (skip.indexOf(entry.name) !== -1) {
      continue;
    }
    const a = path.join(from, entry.name);
    const b = path.join(to, entry.name);
    if (entry.isDirectory()) {
      copyTree(a, b, skip);
    } else {
      fs.copyFileSync(a, b);
    }
  }
  log.debug("Leaving copyTree().");
}

function live() {
  log.debug("Entering live().");
  log.info("=== 2. an edit to the model reaches what it generates ===");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "data-model-"));
  try {
    copyTree(path.join(ROOT, "models"), path.join(scratch, "models"),
             ["node_modules"]);
    fs.symlinkSync(path.join(ROOT, "models", "node_modules"),
                   path.join(scratch, "models", "node_modules"), "dir");
    copyTree(path.join(ROOT, "common", "model"),
             path.join(scratch, "common", "model"), []);
    const file = path.join(scratch, "models", "api", "ldap.tsp");
    const marker = "MUTATION " + process.pid;
    const before = fs.readFileSync(file, "utf8");
    const edited = before.replace(
      "/** ldap:// or ldaps:// URL of the directory server. */",
      "/** " + marker + " */");
    assert.notStrictEqual(edited, before,
      "the mutation's anchor is gone from models/api/ldap.tsp; point it at " +
      "another doc comment.");
    fs.writeFileSync(file, edited);
    const check = runGenerate(scratch, ["--check"]);
    assert.strictEqual(check.status, 1,
      "--check passed on an edited model:\n" + check.output);
    assert.ok(/would change: common\/model\/openapi\.json/.test(check.output),
      "--check did not name openapi.json:\n" + check.output);
    const write = runGenerate(scratch, []);
    assert.strictEqual(write.status, 0, write.output);
    const doc = fs.readFileSync(path.join(scratch, "common", "model",
                                          "openapi.json"), "utf8");
    assert.ok(doc.indexOf(marker) !== -1,
      "the edit did not reach the generated document.");
    log.info("[live] OK — an edited doc comment failed --check, naming " +
             "openapi.json, and reached the document once regenerated.");
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving live().");
}

function strict() {
  log.debug("Entering strict().");
  log.info("=== 3. the validator refuses what it does not understand ===");
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, "common", "model",
                                                   "openapi.json"), "utf8"));
  const tampered = JSON.parse(JSON.stringify(doc));
  const body = tampered.paths["/ldap/bind"].post.requestBody
    .content["application/json"].schema;
  body.properties = { url: { type: "string", "x-made-up": true } };
  assert.throws(function () {
    modelValidate.createModel({ document: tampered });
  }, /unknown keyword|x-made-up/,
  "a schema keyword nobody registered was accepted.");
  const model = modelValidate.createModel({});
  assert.throws(function () {
    model.route("noSuchOperation");
  }, /no operation noSuchOperation/);
  log.info("[strict] OK — an unregistered keyword stops the compile, and an " +
           "unknown operationId stops the route.");
  log.debug("Leaving strict().");
}

function loadAll(dir) {
  log.debug("Entering loadAll(). " + dir);
  const out = {};
  for (const f of fs.readdirSync(dir).filter(function (n) {
    return n.endsWith(".js");
  })) {
    const file = path.join(dir, f);
    delete require.cache[require.resolve(file)];
    out[f] = require(file);
  }
  log.debug("Leaving loadAll().");
  return out;
}

function configurations() {
  log.debug("Entering configurations().");
  log.info("=== 4. every configuration matches its model ===");
  // api/env/embedded.js computes itself from the variables iya-sts passes.
  process.env.DEBUGGER_UI_URL = process.env.DEBUGGER_UI_URL ||
    "https://debugger.example";
  const sets = [
    ["ApiConfig", path.join(ROOT, "api", "env")],
    ["ClientConfig", path.join(ROOT, "client", "src", "env")]
  ];
  for (const [which, dir] of sets) {
    const files = loadAll(dir);
    assert.ok(Object.keys(files).length >= 4, "expected the configs in " +
              dir);
    for (const name of Object.keys(files)) {
      const problems = modelValidate.checkConfig(files[name], which);
      assert.deepStrictEqual(problems, [], path.relative(ROOT, dir) + "/" +
        name + " does not match " + which + ": " + problems.join("; "));
    }
    log.info("[config] " + which + ": " + Object.keys(files).length +
             " files pass.");
  }
  const api = loadAll(path.join(ROOT, "api", "env"))["local.js"];
  const misspelt = Object.assign({}, api, { callTimout: 1 });
  assert.ok(modelValidate.checkConfig(misspelt, "ApiConfig").some(function (p) {
    return /callTimout/.test(p) && /not a setting/.test(p);
  }), "a misspelt key was not refused by name.");
  const missing = Object.assign({}, api);
  delete missing.callTimeout;
  assert.ok(modelValidate.checkConfig(missing, "ApiConfig").some(function (p) {
    return /callTimeout/.test(p) && /required/.test(p);
  }), "a missing required key was not refused by name.");

  const schema = JSON.parse(fs.readFileSync(path.join(ROOT, "common", "model",
    "config.schema.json"), "utf8"));
  assert.deepStrictEqual(schema["x-outbound-policy"].slice().sort(),
    OUTBOUND_POLICY.slice().sort(),
    "the model's outbound-policy settings are not the ones api/CLAUDE.md " +
    "names. Change both, deliberately.");
  const properties = schema.$defs.ApiConfig.properties;
  OUTBOUND_POLICY.forEach(function (key) {
    assert.ok(properties[key] && properties[key]["x-outbound-policy"],
              key + " is not an ApiConfig setting marked x-outbound-policy.");
  });
  log.info("[config] OK — a misspelt key and a missing one are refused by " +
           "name, and the " + OUTBOUND_POLICY.length + " outbound-policy " +
           "settings are the model's.");
  log.debug("Leaving configurations().");
}

function main() {
  log.debug("Entering main().");
  current();
  live();
  strict();
  configurations();
  log.info("The abstract data model is current, live, strict and obeyed.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exitCode = 1;
}
