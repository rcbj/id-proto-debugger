// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: client_module_bindings.js
//
// ---------------------------------------------------------------------------
// Every `name.member` in the browser bundles' source names something that is
// in scope: declared in that file (a var/let/const, a function, a parameter,
// a catch binding, or a sloppy-mode assignment), or a global the browser or
// the bundler provides.
//
// Why this exists. On 2026-11-17 vc_issuance_1.js called vcFormats.format()
// with no `var vcFormats = require("./vc_formats")` in the file (#482). Every
// node test passed — none of them loads that page's module — and the
// containerized suite then lost five jobs to one browser error,
// `Uncaught ReferenceError: vcFormats is not defined`, reported by each as a
// timeout or an assertion about something else entirely. A missing require
// is visible in the source without a browser, so it is checked here, in
// node, in a second, on every run.
//
// The modules common/ stages into client/src at build time (common/crypto,
// common/krb5, common/spiffe, common/xmldsig.js, common/data.js) are bundle
// source too and are read the same way. No browser and no services.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "client_module_bindings",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

// What the page, the bundler and the language provide. A name here is never
// required, so using one is not a missing require.
const GLOBALS = new Set([
  "Array", "ArrayBuffer", "BigInt", "Boolean", "Buffer", "DataView", "Date",
  "Error", "Float32Array", "Float64Array", "Int8Array", "Int16Array",
  "Int32Array", "Intl", "JSON", "Map", "Math", "Number", "Object", "Promise",
  "Proxy", "Reflect", "RegExp", "Set", "String", "Symbol", "TextDecoder",
  "TextEncoder", "Uint8Array", "Uint16Array", "Uint32Array",
  "Uint8ClampedArray", "URL", "URLSearchParams", "WeakMap", "WeakSet",
  "arguments", "atob", "btoa", "console", "crypto", "document", "globalThis",
  "history", "localStorage", "location", "module", "navigator", "performance",
  "process", "require", "self", "sessionStorage", "window"
]);

function bindTarget(declared, p) {
  log.debug("Entering bindTarget().");
  if (!p) {
    log.debug("Leaving bindTarget(). Nothing.");
    return;
  }
  if (p.type === "Identifier") {
    declared.add(p.name);
  } else if (p.type === "ObjectPattern") {
    p.properties.forEach(function (q) {
      bindTarget(declared, q.value || q.argument);
    });
  } else if (p.type === "ArrayPattern") {
    p.elements.forEach(function (q) {
      bindTarget(declared, q);
    });
  } else if (p.type === "AssignmentPattern") {
    bindTarget(declared, p.left);
  } else if (p.type === "RestElement") {
    bindTarget(declared, p.argument);
  }
  log.debug("Leaving bindTarget().");
}

// Every name the file binds anywhere. Scope is deliberately flattened: the
// defect this catches is a name bound NOWHERE in the file, which no scoping
// subtlety can make right.
function declaredNames(ast) {
  log.debug("Entering declaredNames().");
  const declared = new Set();
  walk.full(ast, function (n) {
    if (n.type === "VariableDeclarator") {
      bindTarget(declared, n.id);
    } else if ((n.type === "FunctionDeclaration" ||
                n.type === "FunctionExpression" ||
                n.type === "ClassDeclaration") && n.id) {
      declared.add(n.id.name);
    } else if (n.type === "AssignmentExpression" &&
               n.left.type === "Identifier") {
      declared.add(n.left.name);
    } else if (n.type === "CatchClause" && n.param) {
      bindTarget(declared, n.param);
    }
    if (/Function/.test(n.type)) {
      (n.params || []).forEach(function (p) {
        bindTarget(declared, p);
      });
    }
  });
  log.debug("Leaving declaredNames(). " + declared.size);
  return declared;
}

function unboundIn(file) {
  log.debug("Entering unboundIn(). " + file);
  const ast = acorn.parse(fs.readFileSync(file, "utf8"), {
    ecmaVersion: "latest", sourceType: "script", allowHashBang: true,
    allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true });
  const declared = declaredNames(ast);
  const unbound = new Set();
  walk.simple(ast, {
    MemberExpression: function (n) {
      if (n.object.type === "Identifier" && !declared.has(n.object.name) &&
          !GLOBALS.has(n.object.name)) {
        unbound.add(n.object.name);
      }
    }
  });
  log.debug("Leaving unboundIn(). " + unbound.size);
  return Array.from(unbound);
}

function bundleSources(root) {
  log.debug("Entering bundleSources().");
  const out = [];
  const add = function (dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir).filter(function (f) {
      return /\.js$/.test(f);
    }).forEach(function (f) {
      out.push(path.join(dir, f));
    });
  };
  add(path.join(root, "client", "src"));
  ["crypto", "krb5", "spiffe"].forEach(function (d) {
    add(path.join(root, "common", d));
  });
  ["xmldsig.js", "data.js"].forEach(function (f) {
    if (fs.existsSync(path.join(root, "common", f))) {
      out.push(path.join(root, "common", f));
    }
  });
  log.debug("Leaving bundleSources(). " + out.length);
  return out;
}

function main() {
  log.debug("Entering main().");
  const root = repoRoot();
  const files = bundleSources(root);
  const problems = [];
  files.forEach(function (file) {
    unboundIn(file).forEach(function (name) {
      problems.push(path.relative(root, file) + " uses `" + name + ".` " +
        "and binds `" + name + "` nowhere — a missing require?");
    });
  });
  assert.ok(files.length > 50, "found only " + files.length + " bundle " +
            "source files under " + root);
  assert.deepStrictEqual(problems, [], "names used and never bound, each " +
    "an Uncaught ReferenceError in the browser:\n  " +
    problems.join("\n  "));
  log.info("client_module_bindings: every name used in " + files.length +
           " bundle source files is bound or a known global.");
  log.debug("Leaving main().");
}

try {
  main();
} catch (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
}
