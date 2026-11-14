// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_formats.js
//
// ---------------------------------------------------------------------------
// THE THREE WAYS A POLICY OR A REQUEST IS WRITTEN DOWN, AND WHAT EACH REFUSES.
//
//   * ALFA: a nested PolicySet carrying variables, obligations and advice,
//     an integer comparison and a nested set, written to ALFA and read back,
//     then written to XML and read back again — and asked the same questions
//     at every stage, because a round trip that changes a decision is a
//     round trip that rewrote the policy;
//   * the JSON Profile: a request in the shorthand categories and in the
//     long form, inferred and explicit datatypes, through the PDP to a JSON
//     Response carrying obligations, advice and the policy identifier list;
//   * XML: a Response document read back, CombinerParameters surviving a
//     write, and the syntax errors each reader names.
//
// No browser, no network, no stack.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_formats",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const SRC = path.join(__dirname, "..", "client", "src");
const paths = require("./module_paths.js");

function load(name) {
  log.debug("Entering load().");
  var loaded = paths.requireSharedModule(
    [path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving load().");
  return loaded;
}

// The workbench installs the ALFA language instance the module forwards to.
load("xacml_workbench.js");
const xml = load("xacml/xacml_xml.js");
const json = load("xacml/xacml_json.js");
const alfa = load("xacml/xacml_alfa.js");
const pdp = load("xacml/xacml_pdp.js");

const NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const XS = "http://www.w3.org/2001/XMLSchema#";
const SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const AGE = "urn:example:age";
const FN = "urn:oasis:names:tc:xacml:1.0:function:";
const ALG3 = "urn:oasis:names:tc:xacml:3.0:";
const ALG1 = "urn:oasis:names:tc:xacml:1.0:";

function des(id, type) {
  return '<AttributeDesignator Category="' + SUBJECT + '" AttributeId="' +
    id + '" DataType="' + XS + type + '" MustBePresent="false"/>';
}

function val(type, text) {
  return '<AttributeValue DataType="' + XS + type + '">' + text +
    "</AttributeValue>";
}

function one(type, id) {
  return '<Apply FunctionId="' + FN + type + '-one-and-only">' +
    des(id, type) + "</Apply>";
}

// alice is named; anybody over 18 is admitted by the nested set.
const RICH = '<PolicySet xmlns="' + NS + '" PolicySetId="rich" ' +
  'Version="1.0" PolicyCombiningAlgId="' + ALG3 +
  'policy-combining-algorithm:permit-overrides"><Target/>' +
  '<Policy PolicyId="named" Version="1.0" RuleCombiningAlgId="' + ALG1 +
  'rule-combining-algorithm:first-applicable"><Target/>' +
  '<VariableDefinition VariableId="isAlice"><Apply FunctionId="' + FN +
  'string-equal">' + one("string", SUBJECT_ID) + val("string", "alice") +
  "</Apply></VariableDefinition>" +
  '<Rule RuleId="alice" Effect="Permit"><Target/><Condition>' +
  '<VariableReference VariableId="isAlice"/></Condition></Rule>' +
  '<Rule RuleId="others" Effect="Deny"><Target/></Rule>' +
  "<ObligationExpressions>" +
  '<ObligationExpression ObligationId="urn:example:log" FulfillOn="Permit">' +
  '<AttributeAssignmentExpression AttributeId="urn:example:reason">' +
  val("string", "named") + "</AttributeAssignmentExpression>" +
  "</ObligationExpression></ObligationExpressions>" +
  "<AdviceExpressions>" +
  '<AdviceExpression AdviceId="urn:example:explain" AppliesTo="Deny">' +
  '<AttributeAssignmentExpression AttributeId="urn:example:why">' +
  val("string", "not alice") + "</AttributeAssignmentExpression>" +
  "</AdviceExpression></AdviceExpressions>" +
  "</Policy>" +
  '<PolicySet PolicySetId="adults" Version="1.0" PolicyCombiningAlgId="' +
  ALG3 + 'policy-combining-algorithm:deny-unless-permit"><Target/>' +
  '<Policy PolicyId="age" Version="1.0" RuleCombiningAlgId="' + ALG3 +
  'rule-combining-algorithm:deny-overrides"><Target/>' +
  '<Rule RuleId="over18" Effect="Permit"><Target/><Condition>' +
  '<Apply FunctionId="' + FN + 'integer-greater-than">' +
  one("integer", AGE) + val("integer", "18") + "</Apply></Condition>" +
  "</Rule></Policy></PolicySet></PolicySet>";

function requestXml(who, age) {
  log.debug("Entering requestXml().");
  log.debug("Leaving requestXml().");
  return '<Request xmlns="' + NS + '" ReturnPolicyIdList="true" ' +
    'CombinedDecision="false"><Attributes Category="' + SUBJECT + '">' +
    '<Attribute AttributeId="' + SUBJECT_ID + '" IncludeInResult="false">' +
    val("string", who) + "</Attribute>" +
    (age === null ? "" : '<Attribute AttributeId="' + AGE +
      '" IncludeInResult="false">' + val("integer", String(age)) +
      "</Attribute>") + "</Attributes></Request>";
}

const QUESTIONS = [["alice", 10, "Permit"], ["bob", 30, "Permit"],
                   ["bob", 10, "Deny"], ["carol", null, "Deny"]];

function decisionsOf(node, what) {
  log.debug("Entering decisionsOf().");
  QUESTIONS.forEach(function (q) {
    const req = xml.parseRequest(requestXml(q[0], q[1]));
    const got = pdp.evaluate(node, req);
    assert.strictEqual(got.decision, q[2],
      what + ": " + q[0] + (q[1] === null ? "" : " aged " + q[1]));
  });
  log.debug("Leaving decisionsOf().");
}

function alfaRoundTrip() {
  log.debug("Entering alfaRoundTrip().");
  const original = xml.parsePolicy(RICH);
  decisionsOf(original, "the XML as written");
  const text = alfa.write(original);
  assert.ok(/policyset/.test(text) && /apply/.test(text),
    "ALFA output: " + text.slice(0, 300));
  const back = alfa.parse(text);
  decisionsOf(back, "read back from ALFA");
  const again = xml.parsePolicy(xml.writePolicy(back));
  decisionsOf(again, "ALFA, then XML, then read again");
  assert.strictEqual(alfa.write(again), text,
    "ALFA written from the twice-converted policy differs from the first");
  // The comment forms and a policy with no `apply` line.
  const commented = "// a line comment\n/* a block\n comment */\n" + text;
  decisionsOf(alfa.parse(commented), "ALFA with comments");
  assert.throws(function () {
    alfa.parse(text.replace(/\n\s*apply [^\n]*\n/, "\n"));
  }, /apply/, "a policy with no combining algorithm is refused by name");
  assert.throws(function () {
    alfa.parse("namespace example { policyset p { apply permitOverrides " +
               "wibble } }");
  }, /Unexpected|wibble|line/i, "an unexpected word inside a block");
  log.info("OK — a nested PolicySet survives XML -> ALFA -> XML with every " +
           "decision intact; comments read and errors named.");
  log.debug("Leaving alfaRoundTrip().");
}

function jsonProfile() {
  log.debug("Entering jsonProfile().");
  const node = xml.parsePolicy(RICH);
  const shorthand = JSON.stringify({ Request: {
    ReturnPolicyIdList: true,
    AccessSubject: { Attribute: [
      { AttributeId: SUBJECT_ID, Value: "alice" },
      { AttributeId: AGE, Value: 10 }
    ] }
  } });
  const req = json.parseRequest(shorthand);
  const answer = pdp.evaluate(node, req);
  assert.strictEqual(answer.decision, "Permit");
  const written = json.writeResponse(answer);
  const result = written.Response[0];
  assert.strictEqual(result.Decision, "Permit");
  assert.ok(result.Obligations && result.Obligations[0].Id ===
    "urn:example:log", "the Permit carries its obligation: " +
    JSON.stringify(result));
  assert.ok(result.PolicyIdentifierList,
    "ReturnPolicyIdList asked for the identifiers: " +
    JSON.stringify(result));
  const longForm = JSON.stringify({ Request: { Category: [{
    CategoryId: SUBJECT, Attribute: [
      { AttributeId: SUBJECT_ID, Value: "bob", DataType: "string" },
      { AttributeId: AGE, Value: "10", DataType: XS + "integer" }
    ] }] } });
  const denied = json.writeResponse(pdp.evaluate(node,
    json.parseRequest(longForm))).Response[0];
  assert.strictEqual(denied.Decision, "Deny");
  assert.ok(denied.AssociatedAdvice &&
    denied.AssociatedAdvice[0].Id === "urn:example:explain",
    "the Deny carries its advice: " + JSON.stringify(denied));
  const broken = json.writeResponse({ decision: "Indeterminate",
    status: { code: "urn:oasis:names:tc:xacml:1.0:status:processing-error",
              message: "went wrong" } }).Response[0];
  assert.strictEqual(broken.Status.StatusMessage, "went wrong",
    "an Indeterminate keeps its status message");
  assert.strictEqual(json.inferType(true), XS + "boolean");
  assert.strictEqual(json.inferType(5, "5"), XS + "integer");
  assert.strictEqual(json.inferType(5, "5.0"), XS + "double",
    "5.0 is a double, which only the source text can tell");
  assert.throws(function () {
    json.parseRequest("{not json");
  }, /not valid JSON/);
  assert.throws(function () {
    json.parseRequest(JSON.stringify({ Request: { Category: [{}] } }));
  }, /CategoryId/);
  log.info("OK — the JSON Profile both ways: shorthand and long form in, " +
           "obligations, advice and policy identifiers out.");
  log.debug("Leaving jsonProfile().");
}

function xmlReadersAndErrors() {
  log.debug("Entering xmlReadersAndErrors().");
  const response = '<Response xmlns="' + NS + '"><Result>' +
    "<Decision>Deny</Decision><Status><StatusCode Value=\"" +
    "urn:oasis:names:tc:xacml:1.0:status:ok\"/></Status>" +
    '<Obligations><Obligation ObligationId="urn:example:log">' +
    '<AttributeAssignment AttributeId="urn:example:reason" DataType="' +
    XS + 'string">x</AttributeAssignment></Obligation></Obligations>' +
    "</Result></Response>";
  const read = xml.parseResponse(response);
  const results = read.results || read;
  assert.ok(Array.isArray(results) && results.length === 1,
    "one Result: " + JSON.stringify(read).slice(0, 300));
  assert.strictEqual(results[0].decision, "Deny");
  assert.throws(function () {
    xml.parseResponse('<Request xmlns="' + NS + '"/>');
  }, /Expected <Response>/);

  const withParameters = '<Policy xmlns="' + NS + '" PolicyId="params" ' +
    'Version="1.0" RuleCombiningAlgId="' + ALG3 +
    'rule-combining-algorithm:deny-overrides"><Target/>' +
    '<CombinerParameters><CombinerParameter ParameterName="weight">' +
    val("integer", "3") + "</CombinerParameter></CombinerParameters>" +
    '<RuleCombinerParameters RuleIdRef="r"><CombinerParameter ' +
    'ParameterName="priority">' + val("string", "high") +
    "</CombinerParameter></RuleCombinerParameters>" +
    '<Rule RuleId="r" Effect="Permit"><Target/></Rule></Policy>';
  const first = xml.writePolicy(xml.parsePolicy(withParameters));
  assert.ok(/CombinerParameter[^>]*ParameterName="weight"/.test(first) &&
    /RuleCombinerParameters[^>]*RuleIdRef="r"/.test(first),
    "combiner parameters are written back: " + first.slice(0, 600));
  assert.strictEqual(xml.writePolicy(xml.parsePolicy(first)), first,
    "and they are stable across a second round trip");

  assert.throws(function () {
    xml.parsePolicy("<Policy");
  }, /well-formed/);
  assert.throws(function () {
    xml.parsePolicy('<Policy xmlns="' + NS + '" PolicyId="m" Version="1.0" ' +
      'RuleCombiningAlgId="' + ALG3 + 'rule-combining-algorithm:' +
      'deny-overrides"><Target><AnyOf><AllOf><Match MatchId="' + FN +
      'string-equal">' + des(SUBJECT_ID, "string") +
      "</Match></AllOf></AnyOf></Target></Policy>");
  }, /AttributeValue/, "a Match with no AttributeValue is refused by name");
  log.info("OK — a Response read back, combiner parameters kept, and the " +
           "XML reader's errors named.");
  log.debug("Leaving xmlReadersAndErrors().");
}

function main() {
  log.debug("Entering main().");
  alfaRoundTrip();
  jsonProfile();
  xmlReadersAndErrors();
  log.info("xacml_formats: all checks passed.");
  log.debug("Leaving main().");
}

main();
