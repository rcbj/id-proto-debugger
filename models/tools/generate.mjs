#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/tools/generate.mjs
//
// COMPILES THE ABSTRACT DATA MODEL AND WRITES common/model/.
//
//   node models/tools/generate.mjs           write every generated file
//   node models/tools/generate.mjs --check   write nothing; exit 1 and name
//                                            each file that would change
//
// Needs `npm install` in models/ once; nothing else in the tree does, and
// nothing that ships does. The output is COMMITTED, because api/native.js,
// client/build.js and embedded/build.sh all run from a checkout where no
// TypeSpec compiler may be installed (models/CLAUDE.md, "Why the output is
// committed").
//
// What it writes:
//
//   openapi.json        the api, OpenAPI 3.1 (@typespec/openapi3)
//   config.schema.json  ApiConfig and ClientConfig (@typespec/json-schema)
//   storage.json        every declared browser storage key
//   storage_classes.json  the secret, bearer, secret-member and keypair
//                       lists client/src/secret_storage.js enforces
//   embedded_contract.json  the embedded tree's variables and paths
//
// and, from models/catalog/, one client/src/catalog/<name>.json per typed
// `const` (the protocol catalogues a client module reads).
//
// Every file is JSON written with two-space indentation and a final newline,
// so a diff of one is readable and --check compares bytes.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compile, NodeHost, getDoc, serializeValueAsJson } from
  "@typespec/compiler";
import { SyntaxKind } from "@typespec/compiler/ast";
import { readFacts } from "../lib/debugger_lib.mjs";

// A build script that runs before or outside an install: console-backed, of
// the usual shape (CLAUDE.md, "Five places cannot reach bunyan").
const DEBUG = process.env.MODEL_DEBUG === "1";
const log = {
  debug: function (message) {
    if (DEBUG) {
      console.error("[generate] " + message);
    }
  },
  info: function (message) {
    console.error("[generate] " + message);
  },
  error: function (message) {
    console.error("[generate] ERROR " + message);
  }
};

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MODELS = path.join(HERE, "..");
const ROOT = path.join(MODELS, "..");
const OUT = path.join(ROOT, "common", "model");
// The protocol catalogues (models/catalog/) are read by client modules that
// the tests image copies FLAT, so each is written beside them and required as
// "./catalog/<name>.json", which resolves in a checkout, in a bundle and in
// a flat copy alike.
const CATALOG_OUT = path.join(ROOT, "client", "src", "catalog");
const CATALOG_SRC = path.join(MODELS, "catalog");

const STORAGE_CLASS_AREA = {
  secret: "none",
  bearer: "session"
};

function json(value) {
  log.debug("Entering json().");
  log.debug("Leaving json().");
  return JSON.stringify(value, null, 2) + "\n";
}

function readTree(dir) {
  log.debug("Entering readTree(). " + dir);
  const out = {};
  if (!fs.existsSync(dir)) {
    log.debug("Leaving readTree(). No such directory.");
    return out;
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      Object.assign(out, readTree(full));
    } else {
      out[full] = fs.readFileSync(full, "utf8");
    }
  }
  log.debug("Leaving readTree().");
  return out;
}

async function compileModel(scratch) {
  log.debug("Entering compileModel().");
  const program = await compile(NodeHost, path.join(MODELS, "main.tsp"), {
    outputDir: scratch,
    emit: ["@typespec/openapi3", "@typespec/json-schema"],
    options: {
      "@typespec/openapi3": {
        "emitter-output-dir": path.join(scratch, "openapi3"),
        "file-type": "json",
        "openapi-versions": ["3.1.0"]
      },
      "@typespec/json-schema": {
        "emitter-output-dir": path.join(scratch, "json-schema"),
        "file-type": "json",
        "bundleId": "config.schema.json"
      }
    }
  });
  const problems = program.diagnostics.map(function (d) {
    const where = d.target && d.target.file ? d.target.file.path : "";
    return d.severity + " " + d.code + ": " + d.message +
      (where ? " (" + path.relative(ROOT, where) + ")" : "");
  });
  if (program.hasError()) {
    log.debug("Leaving compileModel(). The compile failed.");
    throw new Error("the model did not compile:\n  " +
      problems.join("\n  "));
  }
  problems.forEach(function (p) {
    log.info(p);
  });
  log.debug("Leaving compileModel().");
  return program;
}

function propertyKey(property) {
  log.debug("Entering propertyKey().");
  log.debug("Leaving propertyKey().");
  return property.name;
}

// The facts the decorators recorded, checked as a whole. Each refusal is a
// rule the code already follows and that a decorator cannot see on its own.
function checkFacts(facts) {
  log.debug("Entering checkFacts().");
  const errors = [];
  for (const [property, f] of facts.storageKeys) {
    const where = property.model.name + "." + property.name;
    const want = STORAGE_CLASS_AREA[f.class];
    if (want && f.area !== want) {
      errors.push(where + ": a " + f.class + " key's area is " + want +
        ", not " + (f.area || "unstated"));
    }
    if (!want && f.area === "none") {
      errors.push(where + ": a " + f.class + " key is stored somewhere");
    }
    if (f.class === "keypair" && !f.optOut) {
      errors.push(where + ": a keypair key names the checkbox that gates " +
        "it (optOut)");
    }
    if (f.class !== "keypair" && f.optOut) {
      errors.push(where + ": only a keypair key has an optOut");
    }
    if (f.member && f.class !== "secret") {
      errors.push(where + ": a secret member is class secret");
    }
    if (!facts.storageGroups.has(property.model)) {
      errors.push(where + ": its model has no @storageGroup");
    }
  }
  for (const [model] of facts.storageGroups) {
    if (!model.properties.size) {
      errors.push(model.name + ": a storage model with no keys");
    }
  }
  log.debug("Leaving checkFacts(). " + errors.length + " errors.");
  return errors;
}

function storageDocument(facts) {
  log.debug("Entering storageDocument().");
  const keys = [];
  const seen = new Map();
  const errors = [];
  for (const [model, module] of facts.storageGroups) {
    for (const property of model.properties.values()) {
      const f = facts.storageKeys.get(property);
      if (!f) {
        errors.push(model.name + "." + property.name + " has no @storageKey");
        continue;
      }
      const key = propertyKey(property);
      const id = (f.prefix ? "prefix:" : "") + (f.member ? "member:" : "") +
        key;
      if (seen.has(id)) {
        errors.push(key + " is declared by both " + seen.get(id) + " and " +
          model.name);
      }
      seen.set(id, model.name);
      const entry = { key: key, class: f.class, group: module };
      ["area", "optOut", "prefix", "member"].forEach(function (name) {
        if (f[name] !== undefined) {
          entry[name] = f[name];
        }
      });
      keys.push(entry);
    }
  }
  keys.sort(function (a, b) {
    return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0);
  });
  log.debug("Leaving storageDocument().");
  return { errors: errors, document: { keys: keys } };
}

// The four lists the client enforces with, and nothing else: they are
// bundled into every page that includes secret_storage.js, so the full
// inventory would cost every bundle the size of every key.
function storageClasses(document) {
  log.debug("Entering storageClasses().");
  const plainKeys = document.keys.filter(function (k) {
    return !k.prefix && !k.member;
  });
  const names = function (predicate) {
    return plainKeys.filter(predicate).map(function (k) {
      return k.key;
    });
  };
  const optOuts = {};
  plainKeys.forEach(function (k) {
    if (k.class === "keypair") {
      (optOuts[k.optOut] = optOuts[k.optOut] || []).push(k.key);
    }
  });
  log.debug("Leaving storageClasses().");
  return {
    secretKeys: names(function (k) {
      return k.class === "secret";
    }),
    sessionKeys: names(function (k) {
      return k.class === "bearer";
    }),
    secretMembers: document.keys.filter(function (k) {
      return k.member;
    }).map(function (k) {
      return k.key;
    }),
    keypairs: optOuts
  };
}

function contractDocument(program, facts) {
  log.debug("Entering contractDocument().");
  const variables = [];
  for (const [property, f] of facts.contractVariables) {
    const entry = { name: property.name, required: !property.optional,
                    readBy: f.readBy.slice() };
    if (f.consumer) {
      entry.consumer = f.consumer;
    }
    if (f.defaultValue !== undefined) {
      entry.defaultValue = f.defaultValue;
    }
    entry.doc = (getDoc(program, property) || "").replace(/\s+/g, " ");
    variables.push(entry);
  }
  const paths = [];
  for (const [property, f] of facts.contractPaths) {
    paths.push({ name: property.name, path: f.path, kind: f.kind,
                 doc: (getDoc(program, property) || "").replace(/\s+/g, " ")
    });
  }
  log.debug("Leaving contractDocument().");
  return { variables: variables, paths: paths };
}

// THE DOCUMENTS THAT QUOTE THE MODEL. A table in a CLAUDE.md that repeats a
// model drifts from it the first time somebody edits one and not the other,
// so the generator writes it, between two marker comments, and --check
// compares it like any generated file.
function markdownTable(contract) {
  log.debug("Entering markdownTable().");
  const rows = ["| Variable | Read by | Effect |", "|---|---|---|"];
  contract.variables.forEach(function (v) {
    const read = v.readBy.map(function (r) {
      return r === "node" ? "node" : "`" + r + "`";
    }).join(", ");
    const extra = v.defaultValue !== undefined ?
      " Default `" + v.defaultValue + "`." : "";
    rows.push("| `" + v.name + "`" + (v.required ? "" : " (optional)") +
      " | " + read + " | " + v.doc.replace(/\|/g, "\\|") + extra + " |");
  });
  log.debug("Leaving markdownTable().");
  return rows.join("\n") + "\n";
}

const REGIONS = [
  { file: "embedded/CLAUDE.md", name: "embedded-variables",
    render: function (outputs) {
      return markdownTable(outputs.contract);
    } }
];

function regionMarkers(name) {
  log.debug("Entering regionMarkers(). " + name);
  log.debug("Leaving regionMarkers().");
  return {
    begin: "<!-- model:" + name + " (generated from models/; do not " +
      "edit) -->\n",
    end: "<!-- /model:" + name + " -->"
  };
}

// The file's text with the region replaced, or an Error naming what is
// missing.
function withRegion(text, name, content) {
  log.debug("Entering withRegion(). " + name);
  const m = regionMarkers(name);
  const a = text.indexOf(m.begin);
  const b = text.indexOf(m.end);
  if (a === -1 || b === -1 || b < a) {
    log.debug("Leaving withRegion(). No markers.");
    throw new Error("the region " + name + " has no markers; add\n  " +
      m.begin.trim() + "\n  " + m.end);
  }
  log.debug("Leaving withRegion().");
  return text.slice(0, a + m.begin.length) + content +
    text.slice(b);
}

// "SSF_EVENT_TYPES" -> "ssf_event_types.json".
function catalogFileName(constName) {
  log.debug("Entering catalogFileName(). " + constName);
  log.debug("Leaving catalogFileName().");
  return constName.toLowerCase() + ".json";
}

/**
 * Every `const` declared in a file under models/catalog/, serialized as the
 * JSON its declared type says it is. A catalogue is DATA — rows a client
 * module reads — and a typed const is TypeSpec's own way to write data: the
 * row model is closed, so a row with a member its model does not declare is
 * a compile error, exactly like a decorator's argument.
 */
function catalogues(program) {
  log.debug("Entering catalogues().");
  const out = {};
  for (const file of program.sourceFiles.values()) {
    const where = file.file.path;
    if (path.relative(CATALOG_SRC, where).startsWith("..")) {
      continue;
    }
    const found = [];
    (function walk(node) {
      if (!node) {
        return;
      }
      if (node.kind === SyntaxKind.ConstStatement) {
        found.push(node);
      }
      const inner = node.statements;
      if (Array.isArray(inner)) {
        inner.forEach(walk);
      } else if (inner) {
        walk(inner);
      }
    })(file);
    found.forEach(function (node) {
      const value = program.checker.getValueForNode(node.value);
      const name = catalogFileName(node.id.sv);
      if (out[name]) {
        throw new Error("two catalogues are both " + name);
      }
      out[name] = serializeValueAsJson(program, value, value.type);
    });
  }
  log.debug("Leaving catalogues(). " + Object.keys(out).length);
  return out;
}

function outboundPolicyList(facts) {
  log.debug("Entering outboundPolicyList().");
  const names = [];
  for (const property of facts.outboundPolicy) {
    names.push(property.name);
  }
  log.debug("Leaving outboundPolicyList().");
  return names;
}

// The emitted OpenAPI document, with the one thing a model should not hold:
// nothing. It is read back exactly as emitted, re-serialized so the bytes do
// not depend on the emitter's own formatting.
function openApiDocument(scratch) {
  log.debug("Entering openApiDocument().");
  const file = path.join(scratch, "openapi3", "openapi.json");
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  log.debug("Leaving openApiDocument().");
  return doc;
}

function configSchema(scratch, outbound) {
  log.debug("Entering configSchema().");
  const file = path.join(scratch, "json-schema", "config.schema.json");
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  // Close both top-level objects. The emitter leaves a model open, and an
  // open config schema would accept the misspelt key it exists to catch.
  for (const name of Object.keys(doc.$defs || {})) {
    const def = doc.$defs[name];
    if (/Config$/.test(name) && def.type === "object") {
      def.additionalProperties = false;
    }
  }
  doc["x-outbound-policy"] = outbound;
  log.debug("Leaving configSchema().");
  return doc;
}

async function generate() {
  log.debug("Entering generate().");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ipd-model-"));
  try {
    const program = await compileModel(scratch);
    const facts = readFacts(program);
    const errors = checkFacts(facts);
    const storage = storageDocument(facts);
    errors.push.apply(errors, storage.errors);
    if (errors.length) {
      throw new Error("the model's facts disagree with each other:\n  " +
        errors.join("\n  "));
    }
    const outbound = outboundPolicyList(facts);
    const files = {};
    files["openapi.json"] = json(openApiDocument(scratch));
    files["config.schema.json"] = json(configSchema(scratch, outbound));
    files["storage.json"] = json(storage.document);
    files["storage_classes.json"] = json(storageClasses(storage.document));
    const catalog = {};
    const rows = catalogues(program);
    Object.keys(rows).forEach(function (name) {
      catalog[name] = json(rows[name]);
    });
    const contract = contractDocument(program, facts);
    files["embedded_contract.json"] = json(contract);
    const regions = REGIONS.map(function (r) {
      const file = path.join(ROOT, r.file);
      const text = fs.readFileSync(file, "utf8");
      return { file: file,
               text: withRegion(text, r.name,
                                r.render({ contract: contract })) };
    });
    log.debug("Leaving generate().");
    return { files: files, regions: regions, catalog: catalog };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

async function main() {
  log.debug("Entering main().");
  const check = process.argv.indexOf("--check") !== -1;
  const generated = await generate();
  const files = generated.files;
  const existing = readTree(OUT);
  const stale = [];
  for (const name of Object.keys(files)) {
    const target = path.join(OUT, name);
    if (existing[target] !== files[name]) {
      stale.push(path.relative(ROOT, target));
    }
    delete existing[target];
  }
  generated.regions.forEach(function (r) {
    if (fs.readFileSync(r.file, "utf8") !== r.text) {
      stale.push(path.relative(ROOT, r.file));
    }
  });
  const existingCatalog = readTree(CATALOG_OUT);
  for (const name of Object.keys(generated.catalog)) {
    const target = path.join(CATALOG_OUT, name);
    if (existingCatalog[target] !== generated.catalog[name]) {
      stale.push(path.relative(ROOT, target));
    }
    delete existingCatalog[target];
  }
  const extra = Object.keys(existing).concat(Object.keys(existingCatalog))
    .map(function (f) {
      return path.relative(ROOT, f);
    });
  if (check) {
    if (stale.length || extra.length) {
      log.error("common/model/ is not what models/ generates.");
      stale.forEach(function (f) {
        log.error("  would change: " + f);
      });
      extra.forEach(function (f) {
        log.error("  is not generated: " + f);
      });
      log.error("Run `node models/tools/generate.mjs` and commit the result.");
      log.debug("Leaving main(). Stale.");
      process.exitCode = 1;
      return;
    }
    log.info("common/model/ is current (" + Object.keys(files).length +
      " files, " + generated.regions.length + " documents).");
    log.debug("Leaving main(). Current.");
    return;
  }
  fs.mkdirSync(OUT, { recursive: true });
  for (const name of Object.keys(files)) {
    fs.writeFileSync(path.join(OUT, name), files[name]);
  }
  generated.regions.forEach(function (r) {
    fs.writeFileSync(r.file, r.text);
  });
  if (Object.keys(generated.catalog).length) {
    fs.mkdirSync(CATALOG_OUT, { recursive: true });
  }
  for (const name of Object.keys(generated.catalog)) {
    fs.writeFileSync(path.join(CATALOG_OUT, name), generated.catalog[name]);
  }
  extra.forEach(function (f) {
    fs.rmSync(path.join(ROOT, f));
  });
  log.info("wrote " + Object.keys(files).length + " files to common/model/" +
    (stale.length ? " (" + stale.length + " changed)" : " (none changed)"));
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error(e && e.message ? e.message : String(e));
  process.exitCode = 1;
});
