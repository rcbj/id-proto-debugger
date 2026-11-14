// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
const alfa = load("xacml/xacml_alfa.js");
const xmlEngine = load("xacml/xacml_xml.js");
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

function alfaKeepsEveryComparison() {
  log.debug("Entering alfaKeepsEveryComparison().");
  // Each ordering function written as ALFA and read back must be the same
  // function. `-equal` is also the tail of `-greater-than-or-equal` and
  // `-less-than-or-equal`, and an emitter that took the first suffix in
  // its table wrote both as `==`, which reads back as integer-equal.
  var names = ["equal", "greater-than", "greater-than-or-equal",
               "less-than", "less-than-or-equal"];
  names.forEach(function (name) {
    var functionId = "urn:oasis:names:tc:xacml:1.0:function:integer-" + name;
    var policy = "<Policy xmlns=\"" + model.NS_XACML + "\" " +
      "PolicyId=\"cmp\" Version=\"1.0\" RuleCombiningAlgId=\"" +
      "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:" +
      "deny-unless-permit\"><Target/><Rule RuleId=\"r\" " +
      "Effect=\"Permit\"><Condition><Apply FunctionId=\"" + functionId +
      "\"><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:" +
      "integer-one-and-only\"><AttributeDesignator AttributeId=\"age\" " +
      "Category=\"" + model.CATEGORY.ACCESS_SUBJECT + "\" DataType=\"" +
      model.TYPE.INTEGER + "\" MustBePresent=\"false\"/></Apply>" +
      "<AttributeValue DataType=\"" + model.TYPE.INTEGER + "\">5" +
      "</AttributeValue></Apply></Condition></Rule></Policy>";
    var parsed = xmlEngine.parsePolicy(policy);
    var back = alfa.parse(alfa.write(parsed));
    var condition = back.rules[0].condition;
    assert.strictEqual(condition.functionId, functionId,
      "integer-" + name + " came back as " + condition.functionId);
  });
  log.info("OK — ALFA keeps every comparison operator.");
  log.debug("Leaving alfaKeepsEveryComparison().");
}

function alfaKeepsMustBePresentAndIssuer() {
  log.debug("Entering alfaKeepsMustBePresentAndIssuer().");
  // MustBePresent and Issuer belong to one use of an attribute. ALFA
  // writes them after the short name, `role[mustbepresent
  // issuer="..."]`, and reading that back must give the same
  // designators. Without them a MustBePresent designator came back
  // optional, turning a missing attribute's Indeterminate into
  // NotApplicable, and a designator with an Issuer matched any issuer.
  var designator = function (id, mustBePresent, issuer) {
    return "<AttributeDesignator AttributeId=\"" + id + "\" " +
      "Category=\"" + model.CATEGORY.ACCESS_SUBJECT + "\" DataType=\"" +
      model.TYPE.STRING + "\" MustBePresent=\"" + mustBePresent + "\"" +
      (issuer ? " Issuer=\"" + issuer + "\"" : "") + "/>";
  };
  var value = "<AttributeValue DataType=\"" + model.TYPE.STRING +
    "\">x</AttributeValue>";
  var policy = "<Policy xmlns=\"" + model.NS_XACML + "\" " +
    "PolicyId=\"q\" Version=\"1.0\" RuleCombiningAlgId=\"" +
    "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:" +
    "deny-overrides\"><Target/><Rule RuleId=\"r\" Effect=\"Permit\">" +
    "<Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:" +
    "1.0:function:string-equal\">" + value +
    designator("a", "true", "https://issuer.example/&quot;q\\") +
    "</Match></AllOf></AnyOf></Target><Condition>" +
    "<Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:" +
    "string-is-in\">" + value + designator("b", "false", "iss") +
    "</Apply></Condition></Rule></Policy>";
  var parsed = xmlEngine.parsePolicy(policy);
  var text = alfa.write(parsed);
  assert.ok(text.indexOf("[mustbepresent issuer=") >= 0, text);
  assert.ok(text.indexOf("[issuer=\"iss\"]") >= 0, text);
  var back = alfa.parse(text);
  var match = back.rules[0].target.anyOf[0].allOf[0].matches[0].reference;
  assert.strictEqual(match.mustBePresent, true);
  assert.strictEqual(match.issuer, "https://issuer.example/\"q\\");
  var used = back.rules[0].condition.args[1];
  assert.strictEqual(used.mustBePresent, false);
  assert.strictEqual(used.issuer, "iss");
  assert.strictEqual(alfa.write(back), text);
  var plain = alfa.parse("namespace e { attribute role { " +
    "category = subjectCat id = \"role\" type = string } " +
    "policy p { apply denyOverrides rule r { permit " +
    "target clause role[mustbepresent] == \"x\" } } }");
  var reference = plain.rules[0].target.anyOf[0].allOf[0].matches[0]
    .reference;
  assert.strictEqual(reference.mustBePresent, true);
  assert.strictEqual(reference.issuer, null);
  assert.throws(function () {
    alfa.parse("namespace e { attribute role { category = subjectCat " +
      "id = \"role\" type = string } policy p { apply denyOverrides " +
      "rule r { permit target clause role[mandatory] == \"x\" } } }");
  }, /Unknown qualifier "mandatory"/);
  log.info("OK — ALFA keeps MustBePresent and Issuer.");
  log.debug("Leaving alfaKeepsMustBePresentAndIssuer().");
}

function inheritedNamesAreUnknown() {
  log.debug("Entering inheritedNamesAreUnknown().");
  // A name a document chose is looked up as an own member. Before, an
  // ALFA category or attribute called constructor or toString read
  // Object or Function through the prototype and was accepted.
  assert.throws(function () {
    alfa.parse("namespace e { attribute a { category = constructor " +
      "id = \"x\" type = string } policy p { apply denyUnlessPermit " +
      "rule r { permit target clause a == \"1\" } } }");
  }, /Unknown category "constructor"/);
  assert.throws(function () {
    alfa.parse("namespace e { policy p { apply denyUnlessPermit " +
      "rule r { permit condition toString == \"1\" } } }");
  }, /never declared/);
  var bench = fresh();
  var unknown = bench.importText("proto", "<Policy xmlns=\"" +
    model.NS_XACML + "\" PolicyId=\"proto\" Version=\"1.0\" " +
    "RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:" +
    "rule-combining-algorithm:deny-unless-permit\"><Target/>" +
    "<Rule RuleId=\"r\" Effect=\"Permit\"><Condition>" +
    "<Apply FunctionId=\"toString\"/></Condition></Rule></Policy>");
  assert.strictEqual(unknown.ok, false);
  assert.ok(/Unknown function "toString"/.test(unknown.why), unknown.why);
  log.info("OK — constructor and toString are unknown names.");
  log.debug("Leaving inheritedNamesAreUnknown().");
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
  // The collapsible panes, the switch, the Editor and SAML Tools panes,
  // upload / download / copy, and folded explanatory text.
  ["xacml_pane_repository", "xacml_pane_files", "xacml_pane_editor",
   "xacml_pane_decision", "xacml_pane_saml_tools"].forEach(function (id) {
    assert.ok(new RegExp('class="saml-pane" id="' + id + '"').test(html),
      id + " is not a collapsible pane");
  });
  assert.ok(html.indexOf('onchange="return xacml.setAllPanes(') >= 0,
    "xacml.html has no collapse / expand all switch");
  ["xacml_upload", "xacml_export_layout"].forEach(function (id) {
    assert.ok(html.indexOf('id="' + id + '"') >= 0,
      "xacml.html is missing #" + id);
  });
  assert.ok(html.indexOf('class="saml-explain"') >= 0,
    "the explanatory text is not folded");
  assert.ok(html.indexOf("saml_tools.html?from=xacml.html") >= 0,
    "the SAML Tools pane is missing");
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

// A literal that is not a value of its datatype is refused at the edit,
// for a Match and for a value inside a condition, and the stored document
// is left as it was. It used to be stored, and only the decision said so,
// as a syntax-error status a deny-unless-permit policy turns into a Deny.
function illTypedLiteralsAreRefused() {
  log.debug("Entering illTypedLiteralsAreRefused().");
  var bench = fresh();
  assert.strictEqual(bench.loadSample().ok, true);
  var match = ".rules.0.target.anyOf.0.allOf.0.matches.0";
  var integerEqual = "urn:oasis:names:tc:xacml:1.0:function:integer-equal";
  var before = bench.editorView("sample").document;
  var refused = bench.edit({ policy: "sample", path: match,
    action: "edit-match", matchId: integerEqual, value: "notanint" });
  assert.strictEqual(refused.ok, false, JSON.stringify(refused));
  assert.ok(/not a valid integer/.test(refused.why), refused.why);
  assert.strictEqual(bench.editorView("sample").document, before);
  var accepted = bench.edit({ policy: "sample", path: match,
    action: "edit-match", matchId: integerEqual, value: "42" });
  assert.strictEqual(accepted.ok, true, JSON.stringify(accepted));

  assert.strictEqual(bench.edit({ policy: "sample", path: ".rules.0",
    action: "add-condition" }).ok, true);
  var value = ".rules.0.condition.args.0";
  before = bench.editorView("sample").document;
  refused = bench.edit({ policy: "sample", path: value,
    action: "edit-value", lexical: "soon",
    type: "http://www.w3.org/2001/XMLSchema#dateTime" });
  assert.strictEqual(refused.ok, false, JSON.stringify(refused));
  assert.strictEqual(bench.editorView("sample").document, before);
  accepted = bench.edit({ policy: "sample", path: value,
    action: "edit-value", lexical: "contractor" });
  assert.strictEqual(accepted.ok, true, JSON.stringify(accepted));
  log.info("OK — an ill-typed literal is refused at the edit.");
  log.debug("Leaving illTypedLiteralsAreRefused().");
}

// A document grown by every offer the editor makes: the sample, then each
// addition at every row, twice over, so the second pass reaches the rows the
// first one made (a condition's arguments, an obligation's assignments).
function grownSample() {
  log.debug("Entering grownSample().");
  var bench = fresh();
  assert.strictEqual(bench.loadSample().ok, true);
  var applied = 0;
  for (var pass = 0; pass < 2; pass++) {
    bench.editorView("sample").tree.forEach(function (row) {
      (row.options.additions || []).forEach(function (one) {
        var done = bench.edit({ policy: "sample", path: row.path,
                                action: one.action });
        assert.ok(done.ok || done.why, one.action + " at '" + row.path +
          "' neither succeeded nor said why");
        if (done.ok) {
          applied += 1;
        }
      });
    });
  }
  log.debug("Leaving grownSample(). " + applied + " additions.");
  return { bench: bench, applied: applied };
}

// EVERY ADDITION THE EDITOR OFFERS IS ONE IT CAN MAKE, and the document it
// leaves still loads, writes ALFA and decides; every removable row removes.
function everyOfferedEditApplies() {
  log.debug("Entering everyOfferedEditApplies().");
  var grown = grownSample();
  var bench = grown.bench;
  assert.ok(grown.applied > 30, "only " + grown.applied + " additions applied");
  var view = bench.editorView("sample");
  assert.ok(view.document && view.alfa, "the grown document is drawn");
  var answer = ask(bench, "alice");
  assert.ok(["Permit", "Deny", "NotApplicable", "Indeterminate"]
    .indexOf(answer.decision) >= 0, answer.decision);
  var removable = view.tree.filter(function (row) {
    return row.options.removable;
  }).map(function (row) {
    return row.path;
  });
  assert.ok(removable.length > 10, "removable rows: " + removable.length);
  // Deepest first, so a removal never shifts an index a later one names.
  removable.reverse().forEach(function (where) {
    var gone = bench.edit({ policy: "sample", path: where,
                            action: "remove" });
    assert.ok(gone.ok || gone.why, "remove at '" + where + "'");
  });
  assert.ok(bench.editorView("sample").document, "still a document");
  log.info("OK — " + grown.applied + " offered additions and " +
    removable.length + " removals apply.");
  log.debug("Leaving everyOfferedEditApplies().");
}

// AN EDIT SENT TO THE WRONG KIND OF NODE IS REFUSED, and the stored document
// is unchanged: `edit-rule` on a Match used to give the Match an effect and
// say "Rule updated."
function wrongKindEditsAreRefused() {
  log.debug("Entering wrongKindEditsAreRefused().");
  var bench = grownSample().bench;
  var edits = {
    "edit-policy": ["policy", "policySet"],
    "edit-rule": ["rule"],
    "edit-obligation": ["obligation"],
    "edit-assignment": ["assignment"],
    "edit-variable": ["variable"],
    "edit-designator": []
  };
  var refused = 0;
  var seen = {};
  bench.editorView("sample").tree.forEach(function (row) {
    seen[row.kind] = true;
    Object.keys(edits).forEach(function (action) {
      if (edits[action].indexOf(row.kind) >= 0 ||
          (action === "edit-designator" && row.edit && row.edit.node &&
           row.edit.node.kind === "designator")) {
        return;
      }
      var before = bench.editorView("sample").document;
      var done = bench.edit({ policy: "sample", path: row.path,
                              action: action, id: "urn:example:wrong",
                              effect: "Deny", name: "wrong",
                              attributeId: "urn:example:wrong" });
      assert.strictEqual(done.ok, false, action + " on a " + row.kind +
        " at '" + row.path + "' was accepted");
      assert.ok(done.why, action + " says why");
      assert.strictEqual(bench.editorView("sample").document, before,
        action + " on a " + row.kind + " changed the document");
      refused += 1;
    });
  });
  ["rule", "match", "obligation", "assignment", "variable", "expression"]
    .forEach(function (kind) {
      assert.ok(seen[kind], "the grown sample has a " + kind);
    });
  log.info("OK — " + refused + " wrong-kind edits are refused.");
  log.debug("Leaving wrongKindEditsAreRefused().");
}

function main() {
  log.debug("Entering main().");
  sampleAllowsAlice();
  refusedEditLeavesTheDocument();
  illTypedLiteralsAreRefused();
  policySetRefusesARule();
  variableNameMayNotContainADot();
  referenceResolvesFromTheRepository();
  anUndischargeableObligationRefuses();
  alfaAndRequestsAgree();
  alfaKeepsEveryComparison();
  alfaKeepsMustBePresentAndIssuer();
  inheritedNamesAreUnknown();
  everyOfferedEditApplies();
  wrongKindEditsAreRefused();
  pageWiring();
  log.info("xacml_engine: all checks passed.");
  log.debug("Leaving main().");
}

main();
