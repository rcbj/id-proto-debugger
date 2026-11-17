// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: storage_inventory.js
//
// ---------------------------------------------------------------------------
// EVERY BROWSER STORAGE KEY THE CLIENT SOURCE NAMES, read out of the source.
//
// The storage model (models/storage/*.tsp) declares each key once, with what
// it is: a secret that is never stored, a bearer token kept in sessionStorage
// only, key material behind a save checkbox, or ordinary configuration.
// tests/data_model.js holds that model to THIS inventory in both directions:
// a key the source names and the model does not is undeclared, and a key the
// model declares and nothing names is dead.
//
// What is found, by parsing each client/src/*.js with acorn:
//
//  * a string literal as the first argument of setItem/getItem/removeItem on
//    localStorage, sessionStorage, or any object (a helper's `s` or `store`);
//  * a `const`/`var` holding a string, or an object or array of strings,
//    when one of them is that argument (`KEYS.SAVE_CCACHE`, `TOKEN_KEY`);
//  * every string in an object or array whose name ends in KEYS or _KEY —
//    the shape every module here uses for the keys its helpers write;
//  * `PREFIX + x`, or a template that begins with text, as a PREFIX;
//  * on the five pages that persist every `.stored` field under a prefix
//    (saml_request, saml_tools, wstrust_tools, wsfed_request, pki), each such
//    field's id, prefixed.
//
// Anything else is a DYNAMIC site, reported with its file and line, and the
// model has to account for it with a prefix (StorageFacts.prefix).
//
//   node storage_inventory.js            print the inventory as JSON
//   node storage_inventory.js --draft    print a first-draft .tsp per module
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "storage_inventory",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const METHODS = ["setItem", "getItem", "removeItem"];

// What a storage key looks like, for the constants scanned by name.
const KEY_SHAPE = /^[A-Za-z_][A-Za-z0-9_.:-]*$/;

// The pages whose script persists every `.stored` field, and the prefix it
// writes them under (each module's STORE_PREFIX).
const STORED_PAGES = {
  "saml_request.js": "saml_request.html",
  "saml_tools.js": "saml_tools.html",
  "wstrust_tools.js": "wstrust_tools.html",
  "wsfed_request.js": "wsfed_request.html",
  "pki.js": "pki.html"
};

function parse(file) {
  log.debug("Entering parse(). " + file);
  const source = fs.readFileSync(file, "utf8");
  const ast = acorn.parse(source, { ecmaVersion: "latest",
                                    sourceType: "script",
                                    allowHashBang: true,
                                    allowReturnOutsideFunction: true,
                                    locations: true });
  log.debug("Leaving parse().");
  return ast;
}

function stringsOf(node) {
  log.debug("Entering stringsOf().");
  const out = [];
  if (!node) {
    log.debug("Leaving stringsOf(). None.");
    return out;
  }
  if (node.type === "Literal" && typeof node.value === "string") {
    out.push(node.value);
  } else if (node.type === "ObjectExpression") {
    node.properties.forEach(function (p) {
      if (p.value && p.value.type === "Literal" &&
          typeof p.value.value === "string") {
        out.push(p.value.value);
      }
    });
  } else if (node.type === "ArrayExpression") {
    node.elements.forEach(function (e) {
      if (e && e.type === "Literal" && typeof e.value === "string") {
        out.push(e.value);
      }
    });
  }
  log.debug("Leaving stringsOf(). " + out.length);
  return out;
}

// name -> { value } for a string, { members: {k: v} } for an object of
// strings, { items: [..] } for an array of strings.
function constantsOf(ast) {
  log.debug("Entering constantsOf().");
  const constants = {};
  walk.simple(ast, {
    VariableDeclarator: function (node) {
      if (!node.id || node.id.type !== "Identifier" || !node.init) {
        return;
      }
      const init = node.init;
      if (init.type === "Literal" && typeof init.value === "string") {
        constants[node.id.name] = { value: init.value };
      } else if (init.type === "ObjectExpression") {
        const members = {};
        init.properties.forEach(function (p) {
          const key = p.key && (p.key.name || p.key.value);
          if (key && p.value && p.value.type === "Literal" &&
              typeof p.value.value === "string") {
            members[key] = p.value.value;
          }
        });
        constants[node.id.name] = { members: members };
      } else if (init.type === "ArrayExpression") {
        constants[node.id.name] = { items: stringsOf(init) };
      }
    }
  });
  log.debug("Leaving constantsOf().");
  return constants;
}

function areaOf(callee) {
  log.debug("Entering areaOf().");
  const object = callee.object;
  let name = "";
  if (object.type === "Identifier") {
    name = object.name;
  } else if (object.type === "MemberExpression" && object.property) {
    name = object.property.name || "";
  }
  log.debug("Leaving areaOf(). " + name);
  if (name === "localStorage") {
    return "local";
  }
  if (name === "sessionStorage") {
    return "session";
  }
  return "unknown";
}

// What the key argument is: { key }, { prefix } or { dynamic }.
function resolveKey(node, constants) {
  log.debug("Entering resolveKey().");
  if (!node) {
    log.debug("Leaving resolveKey(). No argument.");
    return { dynamic: "no argument" };
  }
  if (node.type === "Literal" && typeof node.value === "string") {
    log.debug("Leaving resolveKey(). Literal.");
    return { key: node.value };
  }
  if (node.type === "Identifier" && constants[node.name] &&
      constants[node.name].value !== undefined) {
    log.debug("Leaving resolveKey(). Constant.");
    return { key: constants[node.name].value };
  }
  if (node.type === "MemberExpression" && node.object.type === "Identifier" &&
      constants[node.object.name] && constants[node.object.name].members &&
      !node.computed && node.property) {
    const value = constants[node.object.name].members[node.property.name];
    if (value !== undefined) {
      log.debug("Leaving resolveKey(). Member.");
      return { key: value };
    }
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const left = resolveKey(node.left, constants);
    if (left.key !== undefined) {
      log.debug("Leaving resolveKey(). Prefix.");
      return { prefix: left.key };
    }
    if (left.prefix !== undefined) {
      log.debug("Leaving resolveKey(). Prefix of a prefix.");
      return { prefix: left.prefix };
    }
  }
  if (node.type === "TemplateLiteral" && node.quasis.length &&
      node.quasis[0].value.cooked) {
    log.debug("Leaving resolveKey(). Template prefix.");
    return { prefix: node.quasis[0].value.cooked };
  }
  log.debug("Leaving resolveKey(). Dynamic.");
  return { dynamic: node.type };
}

function storedIds(html) {
  log.debug("Entering storedIds().");
  const ids = [];
  const tag = /<[a-zA-Z][^>]*>/g;
  let m;
  while ((m = tag.exec(html)) !== null) {
    const text = m[0];
    const cls = /\sclass\s*=\s*"([^"]*)"/.exec(text);
    const id = /\sid\s*=\s*"([^"]*)"/.exec(text);
    if (cls && id && /(^|\s)stored(\s|$)/.test(cls[1])) {
      ids.push(id[1]);
    }
  }
  log.debug("Leaving storedIds(). " + ids.length);
  return ids;
}

/**
 * The inventory of a client tree rooted at `clientDir` (client/): every key
 * by name with the modules that name it and the areas they use, the
 * prefixes, and the dynamic sites.
 */
function inventory(clientDir) {
  log.debug("Entering inventory(). " + clientDir);
  const src = path.join(clientDir, "src");
  const keys = new Map();
  const prefixes = new Map();
  const dynamic = [];
  function note(map, name, module, area, how) {
    const entry = map.get(name) || { modules: new Set(), areas: new Set(),
                                     how: new Set() };
    entry.modules.add(module);
    if (area !== "unknown") {
      entry.areas.add(area);
    }
    entry.how.add(how);
    map.set(name, entry);
  }
  const files = fs.readdirSync(src).filter(function (f) {
    return f.endsWith(".js");
  }).sort();
  for (const f of files) {
    let ast;
    try {
      ast = parse(path.join(src, f));
    } catch (e) {
      log.warn("could not parse client/src/" + f + ": " + e.message);
      continue;
    }
    const constants = constantsOf(ast);
    Object.keys(constants).forEach(function (name) {
      if (!/KEYS$|_KEY$/.test(name)) {
        return;
      }
      const c = constants[name];
      const values = c.value !== undefined ? [c.value] :
        (c.members ? Object.values(c.members) : (c.items || []));
      // A constant named *_KEY is not always a storage key (a PIV
      // management key, a CSR's form field): only a value spelt like one.
      values.filter(function (v) {
        return KEY_SHAPE.test(v);
      }).forEach(function (v) {
        note(keys, v, f, "unknown", "constant " + name);
      });
    });
    walk.simple(ast, {
      CallExpression: function (node) {
        const callee = node.callee;
        if (callee.type !== "MemberExpression" || callee.computed ||
            METHODS.indexOf(callee.property.name) === -1) {
          return;
        }
        const area = areaOf(callee);
        const found = resolveKey(node.arguments[0], constants);
        if (found.key !== undefined) {
          note(keys, found.key, f, area, callee.property.name);
        } else if (found.prefix !== undefined) {
          note(prefixes, found.prefix, f, area, callee.property.name);
        } else {
          dynamic.push({ module: f, line: node.loc.start.line,
                         area: area, argument: found.dynamic });
        }
      }
    });
    if (STORED_PAGES[f]) {
      const prefix = constants.STORE_PREFIX && constants.STORE_PREFIX.value;
      const page = path.join(clientDir, "public", STORED_PAGES[f]);
      if (prefix && fs.existsSync(page)) {
        storedIds(fs.readFileSync(page, "utf8")).forEach(function (id) {
          note(keys, prefix + id, f, "local", ".stored on " +
               STORED_PAGES[f]);
        });
      }
    }
  }
  log.debug("Leaving inventory(). " + keys.size + " keys.");
  return { keys: keys, prefixes: prefixes, dynamic: dynamic };
}

function plain(map) {
  log.debug("Entering plain().");
  const out = {};
  Array.from(map.keys()).sort().forEach(function (k) {
    const e = map.get(k);
    out[k] = { modules: Array.from(e.modules).sort(),
               areas: Array.from(e.areas).sort(),
               how: Array.from(e.how).sort() };
  });
  log.debug("Leaving plain().");
  return out;
}

module.exports = { inventory: inventory, plain: plain,
                   STORED_PAGES: STORED_PAGES };

if (require.main === module) {
  const clientDir = process.argv.find(function (a) {
    return a.indexOf("--client=") === 0;
  });
  const dir = clientDir ? clientDir.slice("--client=".length) :
    path.join(__dirname, "..", "client");
  const found = inventory(dir);
  process.stdout.write(JSON.stringify({
    keys: plain(found.keys),
    prefixes: plain(found.prefixes),
    dynamic: found.dynamic
  }, null, 2) + "\n");
}
