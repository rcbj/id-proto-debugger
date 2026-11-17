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
//  5. THE STORAGE MODEL. Every key tests/storage_inventory.js reads out of
//     client/src is declared in models/storage/, every declared key is still
//     named, every area the source shows agrees with the declaration, and
//     the generated class lists are the ones secret_storage.js held as
//     literals before them.
//  6. THE EMBEDDED CONTRACT. Every variable models/contract/ declares is
//     read in the file it names, and every process.env.DEBUGGER_* the tree
//     reads is declared.
//  7. THE OAUTH CATALOGUE. The tables client/src/op_metadata.js and
//     client/src/rp_metadata_choices.js export are exactly the rows
//     models/catalog/oauth.tsp generates into client/src/catalog/.
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
    // The catalogues, so the copy starts as current as the original.
    copyTree(path.join(ROOT, "client", "src", "catalog"),
             path.join(scratch, "client", "src", "catalog"), []);
    // The documents the generator writes a region of.
    fs.mkdirSync(path.join(scratch, "embedded"));
    fs.copyFileSync(path.join(ROOT, "embedded", "CLAUDE.md"),
                    path.join(scratch, "embedded", "CLAUDE.md"));
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

// What secret_storage.js held as literals until the storage model replaced
// them (2026-11-16). Written out here so that a change to a class list is a
// decision made twice, in the model and here, rather than a declaration
// filed under the wrong class by accident.
const REPLACED = {
  secretKeys: ["client_secret", "token_client_secret",
    "refresh_client_secret", "revocation_client_secret",
    "tokenexchange_client_secret", "introspection_client_secret",
    "userinfo_client_secret", "token_password", "password"],
  sessionKeys: ["registration_access_token", "dcr_initial_access_token",
    "introspection_bearer_token"],
  secretMembers: ["client_secret", "registration_access_token"],
  keypairs: {
    samltools_saml_save_keypair: ["samltools_saml_sp_private_key",
      "samltools_saml_sp_public_key"],
    wstrust_wst_save_keypair: ["wstrust_wst_sp_private_key",
      "wstrust_wst_sp_cert"],
    wsfedtools_wsfed_save_keypair: ["wsfedtools_wsfed_rp_private_key",
      "wsfedtools_wsfed_rp_cert"],
    sdjwtvc_save_holder_key: ["sdjwtvc_holder_private_jwk",
      "sdjwtvc_refreshed_holder_private_jwk",
      "sdjwtvc_previous_holder_private_jwk", "sdjwtvc_dpop_private_jwk"]
  }
};

function sorted(list) {
  log.debug("Entering sorted().");
  log.debug("Leaving sorted().");
  return list.slice().sort();
}

// sd_jwt_vc.js keeps its holder-key list as a literal: the tests image
// copies that module FLAT and loads it in node, where a require of
// ../../common/model would not resolve. So the literal is held to the model
// here instead of being read from it.
function holderKeysLiteral() {
  log.debug("Entering holderKeysLiteral().");
  const source = fs.readFileSync(path.join(ROOT, "client", "src",
                                           "sd_jwt_vc.js"), "utf8");
  const m = /var HOLDER_PRIVATE_KEYS = \[([\s\S]*?)\];/.exec(source);
  assert.ok(m, "client/src/sd_jwt_vc.js no longer declares " +
            "HOLDER_PRIVATE_KEYS; hold its replacement to the model here.");
  const keys = (m[1].replace(/\/\/.*$/gm, "").match(/"[^"]+"/g) || [])
    .map(function (q) {
      return q.slice(1, -1);
    });
  log.debug("Leaving holderKeysLiteral().");
  return keys;
}

function storageModel() {
  log.debug("Entering storageModel().");
  log.info("=== 5. every storage key the client names is declared ===");
  const inventoryModule = require("./storage_inventory.js");
  const found = inventoryModule.inventory(path.join(ROOT, "client"));
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, "common", "model",
    "storage.json"), "utf8"));
  const classes = JSON.parse(fs.readFileSync(path.join(ROOT, "common",
    "model", "storage_classes.json"), "utf8"));
  const declared = new Map();
  const prefixes = [];
  doc.keys.forEach(function (k) {
    if (k.member) {
      return;
    }
    if (k.prefix) {
      prefixes.push(k);
    } else {
      declared.set(k.key, k);
    }
  });
  const problems = [];
  // Every key the source names is declared, or sits under a declared
  // prefix.
  for (const [key, entry] of found.keys) {
    const covered = declared.has(key) || prefixes.some(function (p) {
      return key.indexOf(p.key) === 0;
    });
    if (!covered) {
      problems.push("`" + key + "` (" + Array.from(entry.modules).join(", ") +
        ") is named by the client and declared by no models/storage file");
    }
    const d = declared.get(key);
    if (d && d.area && d.area !== "either" && d.class !== "secret" &&
        d.class !== "bearer") {
      entry.areas.forEach(function (area) {
        if (area !== d.area) {
          problems.push("`" + key + "` is declared " + d.area + " and " +
            Array.from(entry.modules).join(", ") + " uses " + area);
        }
      });
    }
  }
  // Every declared key is still named, apart from the secret and bearer
  // keys, which are declared precisely so that nothing writes them.
  for (const [key, d] of declared) {
    if (d.class === "secret" || d.class === "bearer") {
      continue;
    }
    if (!found.keys.has(key)) {
      problems.push("`" + key + "` is declared in " + d.group + "'s file " +
        "and no client module names it any more");
    }
  }
  prefixes.forEach(function (p) {
    if (!found.prefixes.has(p.key)) {
      problems.push("prefix `" + p.key + "` is declared and no client " +
        "module builds a key from it");
    }
  });
  assert.deepStrictEqual(problems, [], "the storage model and the client " +
    "disagree:\n  " + problems.join("\n  "));

  // The class lists are the ones they replaced.
  ["secretKeys", "sessionKeys", "secretMembers"].forEach(function (name) {
    assert.deepStrictEqual(sorted(classes[name]), sorted(REPLACED[name]),
      name + " in storage_classes.json is not the list it replaced. A " +
      "change to it is deliberate: make it in models/storage/ and here.");
  });
  assert.deepStrictEqual(Object.keys(classes.keypairs).sort(),
    Object.keys(REPLACED.keypairs).sort(), "the key-pair checkboxes changed");
  Object.keys(REPLACED.keypairs).forEach(function (optOut) {
    assert.deepStrictEqual(sorted(classes.keypairs[optOut]),
      sorted(REPLACED.keypairs[optOut]), optOut + " gates other keys now");
    assert.ok(declared.has(optOut), "the checkbox key `" + optOut +
      "` is not itself declared");
  });
  assert.deepStrictEqual(sorted(holderKeysLiteral()),
    sorted(classes.keypairs.sdjwtvc_save_holder_key),
    "client/src/sd_jwt_vc.js's HOLDER_PRIVATE_KEYS is not the model's " +
    "sdjwtvc_save_holder_key list.");
  log.info("[storage] OK — " + found.keys.size + " keys and " +
    found.prefixes.size + " prefixes named by the client, every one " +
    "declared, none declared and unnamed; the class lists are the ones " +
    "they replaced. " + found.dynamic.length + " call sites build their " +
    "key in a way the inventory cannot read (a helper's parameter, a key " +
    "from another module) and are not checked here.");
  log.debug("Leaving storageModel().");
}

function readSources(dirs) {
  log.debug("Entering readSources().");
  const out = {};
  dirs.forEach(function (dir) {
    const full = path.join(ROOT, dir);
    if (!fs.existsSync(full)) {
      return;
    }
    fs.readdirSync(full).filter(function (f) {
      return f.endsWith(".js");
    }).forEach(function (f) {
      out[dir + "/" + f] = fs.readFileSync(path.join(full, f), "utf8");
    });
  });
  log.debug("Leaving readSources().");
  return out;
}

function embeddedContract() {
  log.debug("Entering embeddedContract().");
  log.info("=== 6. the embedded contract is what the tree reads ===");
  const contract = JSON.parse(fs.readFileSync(path.join(ROOT, "common",
    "model", "embedded_contract.json"), "utf8"));
  const sources = readSources(["api", "api/env", "common", "client/src",
                               "client/src/env"]);
  const declared = contract.variables.map(function (v) {
    return v.name;
  });
  const problems = [];
  // Each declared variable is read where the model says. api/server.js is
  // not in every layout (the tests image has api/env only), so a file that
  // is absent is not counted against the model.
  contract.variables.forEach(function (v) {
    v.readBy.forEach(function (file) {
      if (file === "node" || !(file in sources)) {
        return;
      }
      if (sources[file].indexOf("process.env." + v.name) === -1) {
        problems.push(v.name + " is declared as read by " + file +
                      ", which does not read it");
      }
    });
  });
  // Every DEBUGGER_* the tree reads is declared.
  Object.keys(sources).forEach(function (file) {
    const reads = sources[file].match(/process\.env\.DEBUGGER_[A-Z_]+/g) ||
      [];
    reads.forEach(function (read) {
      const name = read.slice("process.env.".length);
      if (declared.indexOf(name) === -1) {
        problems.push(file + " reads " + name + ", which " +
                      "models/contract/main.tsp does not declare");
      }
    });
  });
  assert.deepStrictEqual(problems, [], "the embedded contract and the " +
    "tree disagree:\n  " + problems.join("\n  "));
  log.info("[contract] OK — " + declared.length + " variables, each read " +
           "where the model says, and no DEBUGGER_ variable undeclared.");
  log.debug("Leaving embeddedContract().");
}

// The JSON a catalogue generates, read from the tree rather than required,
// so the comparison is against the file on disk and not a cached module.
function catalogJson(name) {
  log.debug("Entering catalogJson(). " + name);
  const file = path.join(ROOT, "client", "src", "catalog", name + ".json");
  const rows = JSON.parse(fs.readFileSync(file, "utf8"));
  log.debug("Leaving catalogJson().");
  return rows;
}

function oauthCatalogue() {
  log.debug("Entering oauthCatalogue().");
  log.info("=== 7. the OAuth metadata tables are the generated catalogue ===");
  const src = path.join(ROOT, "client", "src");
  // Through module_paths, so bunyan and jws.js's dependencies resolve from
  // tests/node_modules in the tests image, where source-tree has none.
  const op = paths.requireSharedModule([path.join(src, "op_metadata.js")],
    "client/src/op_metadata.js");
  const rp = paths.requireSharedModule(
    [path.join(src, "rp_metadata_choices.js")],
    "client/src/rp_metadata_choices.js");
  const pairs = [
    ["op_metadata.js OP_METADATA", op.OP_METADATA, "op_metadata"],
    ["op_metadata.js AS_ONLY_METADATA", op.AS_ONLY_METADATA,
     "as_only_metadata"],
    ["rp_metadata_choices.js CHOICES", rp.CHOICES, "rp_metadata_choices"],
    ["rp_metadata_choices.js NOT_CLIENT_CHOICES", rp.NOT_CLIENT_CHOICES,
     "rp_not_client_choices"]
  ];
  pairs.forEach(function (pair) {
    assert.deepStrictEqual(pair[1], catalogJson(pair[2]), pair[0] +
      " is not client/src/catalog/" + pair[2] + ".json. Edit " +
      "models/catalog/oauth.tsp and regenerate, never the module.");
  });
  assert.deepStrictEqual(op.ALL_METADATA,
    op.OP_METADATA.concat(op.AS_ONLY_METADATA),
    "op_metadata.js ALL_METADATA is not OP_METADATA then AS_ONLY_METADATA.");
  assert.strictEqual(rp.CHOICES.length, 19,
    "RP Metadata Choices 1.0 section 2 has nineteen members, not " +
    rp.CHOICES.length + ".");
  log.info("[oauth] OK — " + pairs.length + " tables, " +
           (op.ALL_METADATA.length + rp.CHOICES.length +
            rp.NOT_CLIENT_CHOICES.length) + " rows, each the generated " +
           "catalogue.");
  log.debug("Leaving oauthCatalogue().");
}

function main() {
  log.debug("Entering main().");
  current();
  live();
  strict();
  configurations();
  storageModel();
  embeddedContract();
  oauthCatalogue();
  log.info("The abstract data model is current, live, strict and obeyed.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exitCode = 1;
}
