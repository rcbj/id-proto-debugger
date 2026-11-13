// File: xacml_engine.js
//
// ---------------------------------------------------------------------------
// The XACML editor and the decision test, driven in node with no
// browser and no network. The subject is the workbench: the same
// calls the page makes. A provider's behaviour is not an input.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments,
// so node ignores that pair. Do not add commander here without
// declaring `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_engine",
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
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");

function load(name) {
  log.debug("Entering load().");
  var loaded = paths.requireSharedModule(
    [path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving load().");
  return loaded;
}

const workbench = load("xacml_workbench.js");
const model = load("xacml/xacml_model.js");
const LOG_OBLIGATION = "urn:sts:xacml:obligation:log";

function fresh() {
  log.debug("Entering fresh().");
  var bench = workbench.createWorkbench(workbench.memoryRepository());
  log.debug("Leaving fresh().");
  return bench;
}

function ask(bench, subject, policy) {
  log.debug("Entering ask().");
  var answer = bench.decide({
    policy: policy || "",
    subject: subject,
    action: "GET",
    resource: "https://example.com/a"
  });
  log.debug("Leaving ask().");
  return answer;
}

function sampleAllowsAlice() {
  log.debug("Entering sampleAllowsAlice().");
  var bench = fresh();
  var created = bench.loadSample();
  assert.strictEqual(created.ok, true, created.why);
  var view = bench.editorView("sample");
  assert.strictEqual(view.problems.length, 0,
    view.problems.join("; "));
  assert.ok(view.tree.length >= 4, "the sample tree is drawn");
  assert.ok(String(view.alfa).indexOf("namespace example {") === 0,
    "ALFA on this page is written in the example namespace");
  var alice = ask(bench, "alice");
  assert.strictEqual(alice.decision, "Permit", alice.decision);
  assert.strictEqual(alice.enforcement.allowed, true);
  assert.deepStrictEqual(
    alice.applicablePolicies.map(function (one) { return one.id; }),
    ["sample"]);
  var bob = ask(bench, "bob");
  assert.strictEqual(bob.decision, "Deny");
  assert.strictEqual(bob.enforcement.allowed, false);
  assert.strictEqual(bob.enforcements[1].bias, "permit-biased");
  assert.strictEqual(bob.enforcements[1].allowed, false);
  var empty = bench.decide({
    subject: "", action: "GET", resource: "", attributes: []
  });
  assert.strictEqual(empty.asked, false);
  log.info("OK — the sample permits alice and denies bob.");
  log.debug("Leaving sampleAllowsAlice().");
}

function refusedEditLeavesTheDocument() {
  log.debug("Entering refusedEditLeavesTheDocument().");
  var bench = fresh();
  assert.strictEqual(bench.loadSample().ok, true);
  var before = bench.editorView("sample").document;
  var refused = bench.edit({
    policy: "sample",
    path: "",
    action: "edit-match",
    value: "carol"
  });
  assert.strictEqual(refused.ok, false);
  assert.ok(/not a Match/i.test(refused.why), refused.why);
  assert.strictEqual(bench.editorView("sample").document, before);
  log.info("OK — a refused edit leaves the stored document.");
  log.debug("Leaving refusedEditLeavesTheDocument().");
}

function policySetRefusesARule() {
  log.debug("Entering policySetRefusesARule().");
  var bench = fresh();
  assert.strictEqual(bench.createBlank("set", "policyset").ok, true);
  var before = bench.editorView("set").document;
  var refused = bench.edit({
    policy: "set", path: "", action: "add-rule", effect: "Permit"
  });
  assert.strictEqual(refused.ok, false);
  assert.ok(/PolicySet holds policies/.test(refused.why), refused.why);
  assert.strictEqual(bench.editorView("set").document, before);
  log.info("OK — a PolicySet refuses a rule.");
  log.debug("Leaving policySetRefusesARule().");
}

function variableNameMayNotContainADot() {
  log.debug("Entering variableNameMayNotContainADot().");
  var bench = fresh();
  assert.strictEqual(bench.createBlank("named", "policy").ok, true);
  var before = bench.editorView("named").document;
  var refused = bench.edit({
    policy: "named", path: "", action: "add-variable",
    variableId: "a.b"
  });
  assert.strictEqual(refused.ok, false);
  assert.ok(/may not contain a dot/.test(refused.why), refused.why);
  assert.strictEqual(bench.editorView("named").document, before);
  log.info("OK — a variable name may not contain a dot.");
  log.debug("Leaving variableNameMayNotContainADot().");
}

function referenceResolvesFromTheRepository() {
  log.debug("Entering referenceResolvesFromTheRepository().");
  var bench = fresh();
  assert.strictEqual(bench.loadSample().ok, true);
  assert.strictEqual(bench.createBlank("wrapper", "policyset").ok,
                      true);
  var added = bench.edit({
    policy: "wrapper", path: "", action: "add-policy-reference",
    ref: "sample"
  });
  assert.strictEqual(added.ok, true, added.why);
  var allowed = ask(bench, "alice", "wrapper");
  assert.strictEqual(allowed.decision, "Permit",
    (allowed.status || {}).message || allowed.problem);
  assert.strictEqual(bench.setEnabled("sample", false).ok, true);
  var missing = ask(bench, "alice", "wrapper");
  assert.strictEqual(missing.decision, "Deny");
  assert.ok(/UnresolvedReference/.test((missing.status || {}).message),
    (missing.status || {}).message);
  var switched = bench.edit({
    policy: "wrapper", path: "", action: "edit-policy",
    combiningAlgId: model.POLICY_ALG.FIRST_APPLICABLE
  });
  assert.strictEqual(switched.ok, true, switched.why);
  var indeterminate = ask(bench, "alice", "wrapper");
  assert.strictEqual(indeterminate.decision, "Indeterminate");
  assert.strictEqual(indeterminate.enforcement.allowed, false);
  assert.strictEqual(indeterminate.enforcements[1].allowed, true);
  log.info("OK — a PolicyIdReference resolves, and a missing one " +
           "is reported.");
  log.debug("Leaving referenceResolvesFromTheRepository().");
}

function obligationPath(bench) {
  log.debug("Entering obligationPath().");
  var found = "";
  bench.editorView("sample").tree.forEach(function (row) {
    if (row.kind === "obligation" &&
        String(row.label).indexOf("Obligation ") === 0) {
      found = row.path;
    }
  });
  log.debug("Leaving obligationPath().");
  return found;
}

function anUndischargeableObligationRefuses() {
  log.debug("Entering anUndischargeableObligationRefuses().");
  var bench = fresh();
  assert.strictEqual(bench.loadSample().ok, true);
  var added = bench.edit({
    policy: "sample", path: "", action: "add-policy-obligation"
  });
  assert.strictEqual(added.ok, true, added.why);
  var path = obligationPath(bench);
  assert.ok(path, "the obligation is in the tree");
  var renamed = bench.edit({
    policy: "sample", path: path, action: "edit-obligation",
    id: "urn:example:xacml:obligation:email"
  });
  assert.strictEqual(renamed.ok, true, renamed.why);
  var blocked = ask(bench, "alice");
  assert.strictEqual(blocked.decision, "Permit");
  assert.strictEqual(blocked.enforcement.allowed, false);
  assert.strictEqual(blocked.enforcements[1].allowed, false);
  assert.ok(blocked.obligations.indexOf(
    "urn:example:xacml:obligation:email") >= 0);
  var logged = bench.edit({
    policy: "sample", path: path, action: "edit-obligation",
    id: LOG_OBLIGATION
  });
  assert.strictEqual(logged.ok, true, logged.why);
  var allowed = ask(bench, "alice");
  assert.strictEqual(allowed.decision, "Permit");
  assert.strictEqual(allowed.enforcement.allowed, true);
  assert.strictEqual(allowed.enforcements[1].allowed, true);
  log.info("OK — only the log obligation is dischargeable.");
  log.debug("Leaving anUndischargeableObligationRefuses().");
}

function alfaAndRequestsAgree() {
  log.debug("Entering alfaAndRequestsAgree().");
  var source = fresh();
  assert.strictEqual(source.loadSample().ok, true);
  var view = source.editorView("sample");
  var again = fresh();
  var imported = again.importText("", view.alfa);
  assert.strictEqual(imported.ok, true, imported.why);
  assert.strictEqual(ask(again, "alice").decision, "Permit");
  assert.strictEqual(ask(again, "bob").decision, "Deny");
  var xml = "<Request xmlns=\"" + model.NS_XACML + "\">" +
    "<Attributes Category=\"" + model.CATEGORY.ACCESS_SUBJECT + "\">" +
    "<Attribute AttributeId=\"" + model.ATTRIBUTE.SUBJECT_ID + "\">" +
    "<AttributeValue DataType=\"" + model.TYPE.STRING + "\">" +
    "alice</AttributeValue></Attribute></Attributes></Request>";
  var fromXml = source.decide({ policy: "sample", requestText: xml });
  assert.strictEqual(fromXml.decision, "Permit",
    (fromXml.status || {}).message || fromXml.problem);
  var json = JSON.stringify({
    Request: {
      AccessSubject: {
        Attribute: [{
          AttributeId: model.ATTRIBUTE.SUBJECT_ID,
          DataType: "string",
          Value: "bob"
        }]
      }
    }
  });
  var fromJson = source.decide({
    policy: "sample", requestText: json
  });
  assert.strictEqual(fromJson.decision, "Deny",
    (fromJson.status || {}).message || fromJson.problem);
  log.info("OK — ALFA, request XML and the JSON Profile agree.");
  log.debug("Leaving alfaAndRequestsAgree().");
}

function pageWiring() {
  log.debug("Entering pageWiring().");
  var html = fs.readFileSync(path.join(PUBLIC, "xacml.html"), "utf8");
  var css = fs.readFileSync(
    path.join(PUBLIC, "css", "xacml.css"), "utf8");
  var index = fs.readFileSync(path.join(PUBLIC, "index.html"), "utf8");
  ["xacml_status", "xacml_open", "xacml_decide_policy",
   "xacml_enabled", "xacml_is_root", "xacml_editor", "xacml_name",
   "xacml_kind", "xacml_import_name", "xacml_import", "xacml_subject",
   "xacml_action", "xacml_resource", "xacml_request",
   "xacml_attributes", "xacml_decision"].forEach(function (id) {
    assert.ok(html.indexOf('id="' + id + '"') >= 0,
      "xacml.html is missing #" + id);
  });
  assert.ok(html.indexOf('src="/js/xacml.js"') >= 0);
  assert.ok(/only\s+ones the PDP sees/.test(html),
    "the page must say the request is the whole attribute set");
  assert.ok(html.indexOf('href="/css/xacml.css"') >= 0);
  ["xacml-edit", "xacml-sub", "xacml-warn", "xacml-note",
   "xacml-tree", "xacml-attr"].forEach(function (name) {
    assert.ok(css.indexOf("." + name) >= 0,
      "xacml.css does not define ." + name);
  });
  for (var depth = 0; depth <= 9; depth++) {
    assert.ok(css.indexOf(".xacml-indent-" + depth) >= 0,
      "missing indent " + depth);
  }
  var card = index.match(
    /<a class="landing-card" href="\/xacml\.html"[^>]*>/);
  assert.ok(card, "the landing page does not link the XACML page");
  assert.ok(card[0].indexOf("data-not-on-static") < 0,
    "the XACML card is browser-only and ships on the static sites");
  var engineDir = path.join(SRC, "xacml");
  fs.readdirSync(engineDir).forEach(function (name) {
    if (!/\.js$/.test(name)) {
      return;
    }
    var text = fs.readFileSync(path.join(engineDir, name), "utf8");
    assert.ok(!/require\(["'][^"']*iya-sts/.test(text), name);
    assert.ok(!/require\(["'][^"']*\/sts\//.test(text), name);
  });
  log.info("OK — the page, the card and the engine are wired.");
  log.debug("Leaving pageWiring().");
}

function main() {
  log.debug("Entering main().");
  sampleAllowsAlice();
  refusedEditLeavesTheDocument();
  policySetRefusesARule();
  variableNameMayNotContainADot();
  referenceResolvesFromTheRepository();
  anUndischargeableObligationRefuses();
  alfaAndRequestsAgree();
  pageWiring();
  log.info("xacml_engine: all checks passed.");
  log.debug("Leaving main().");
}

main();
