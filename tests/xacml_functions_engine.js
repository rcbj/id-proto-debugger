// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_functions_engine.js
//
// ---------------------------------------------------------------------------
// EVERY XACML 3.0 STANDARD FUNCTION AND DATATYPE, IN NODE, AGAINST THE
// ANSWERS APPENDIX A GIVES.
//
// The cases are tests/xacml_function_cases.js, one policy each with the
// decision it must produce (Permit, NotApplicable, Indeterminate, or Refused
// at import), and this runs them through the same workbench the XACML page
// uses. Each importable one is then written out as ALFA by the workbench,
// imported back, and asked again: the two decisions must agree, which is
// what holds the ALFA writer and reader to every expression the table has.
//
// xacml_functions_page.js runs the same table in a browser through the
// page's own Import and Ask controls.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_functions_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const paths = require("./module_paths.js");
const cases = require("./xacml_function_cases.js");

function load(name) {
  log.debug("Entering load().");
  var loaded = paths.requireSharedModule(
    [path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving load().");
  return loaded;
}

const workbench = load("xacml_workbench.js");
const functions = load("xacml/xacml_functions.js");

// The decision `bench` gives for the policy kept as `name`, or "Refused"
// when it was never imported.
function decisionOf(bench, name) {
  log.debug("Entering decisionOf().");
  var answer = bench.decide({ policy: name, subject: "alice",
                              action: "GET", resource: "r" });
  log.debug("Leaving decisionOf(). " + answer.decision);
  return answer.decision || ("problem: " + answer.problem);
}

// Every case gives the decision the table says.
function everyCaseDecides(built) {
  log.debug("Entering everyCaseDecides().");
  var wrong = [];
  built.cases.forEach(function (c) {
    var bench = workbench.createWorkbench(workbench.memoryRepository());
    var imported = bench.importText("case", c.xml);
    var got = imported.ok ? decisionOf(bench, "case") : "Refused";
    if (got !== c.expect) {
      wrong.push(c.name + ": expected " + c.expect + ", got " + got +
                 (imported.ok ? "" : " (" + imported.why + ")"));
    }
  });
  assert.deepStrictEqual(wrong, [], wrong.length + " case(s) wrong:\n  " +
                         wrong.join("\n  "));
  log.info("PASS  all " + built.cases.length + " function and datatype " +
           "cases give the decision XACML 3.0 Appendix A says");
  log.debug("Leaving everyCaseDecides().");
}

// Every standard function the engine registers is used by some case, except
// the one the table cannot drive (xpath-node-count needs a request content
// document, and xacml_engine.js covers it), so a function added to the
// registry without a case fails here.
function everyFunctionIsUsed(built) {
  log.debug("Entering everyFunctionIsUsed().");
  var unused = functions.names().map(function (uri) {
    return uri.replace(/^.*:function:/, "");
  }).filter(function (short) {
    return built.used.indexOf(short) < 0 && short !== "xpath-node-count";
  });
  assert.deepStrictEqual(unused, [],
    "functions no case exercises: " + unused.join(", "));
  log.info("PASS  every registered function but xpath-node-count is used " +
           "by a case (" + functions.names().length + " functions)");
  log.debug("Leaving everyFunctionIsUsed().");
}

// Written as ALFA and read back, every importable case decides the same.
function alfaRoundTrips(built) {
  log.debug("Entering alfaRoundTrips().");
  var wrong = [];
  var count = 0;
  built.cases.forEach(function (c) {
    if (c.expect === "Refused") {
      return;
    }
    var bench = workbench.createWorkbench(workbench.memoryRepository());
    if (!bench.importText("case", c.xml).ok) {
      return;
    }
    count += 1;
    var alfa = bench.editorView("case").alfa;
    var back = bench.importText("alfa", alfa);
    if (!back.ok) {
      wrong.push(c.name + ": its ALFA does not import (" + back.why + ")");
      return;
    }
    var before = decisionOf(bench, "case");
    var after = decisionOf(bench, "alfa");
    if (before !== after) {
      wrong.push(c.name + ": " + before + " as XML, " + after + " as ALFA");
    }
  });
  assert.deepStrictEqual(wrong, [], wrong.length + " ALFA round trip(s) " +
                         "wrong:\n  " + wrong.join("\n  "));
  log.info("PASS  " + count + " cases written as ALFA and read back decide " +
           "the same");
  log.debug("Leaving alfaRoundTrips().");
}

function test() {
  log.debug("Entering test().");
  var built = cases.buildAll(functions.names());
  everyCaseDecides(built);
  everyFunctionIsUsed(built);
  alfaRoundTrips(built);
  log.info("xacml_functions_engine: all checks passed.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exitCode = 1;
}
