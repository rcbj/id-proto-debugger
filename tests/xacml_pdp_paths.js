// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_pdp_paths.js
//
// ---------------------------------------------------------------------------
// THE PDP'S LESS-TRAVELLED PATHS, END TO END: XML policy and request in,
// decision out, through client/src/xacml/xacml_xml.js and xacml_pdp.js.
//
//   * only-one-applicable (C.9): none applicable, exactly one, two, and a
//     target that cannot be evaluated;
//   * VariableDefinition and VariableReference, including one variable
//     defined in terms of another;
//   * the three environment attributes the PDP supplies itself (10.2.5),
//     from the clock it is handed, and a request's own value winning;
//   * the PIP — a resolver consulted only when the request is silent — and
//     MustBePresent turning an empty bag into missing-attribute;
//   * legacy permit-overrides over a policy that fails to evaluate, which
//     must come out Indeterminate and NOT Permit (see xacml_combiners.js).
//
// No browser, no network, no stack.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_pdp_paths",
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

const xml = load("xacml/xacml_xml.js");
const pdp = load("xacml/xacml_pdp.js");

const NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const XS = "http://www.w3.org/2001/XMLSchema#";
const SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const ENV = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";
const SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const FN = "urn:oasis:names:tc:xacml:1.0:function:";
const RULE_ALG = "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:";
const POLICY_ALG = "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:";
const CLEARANCE = "urn:example:clearance";

function designator(category, id, type, mustBePresent) {
  return '<AttributeDesignator Category="' + category + '" AttributeId="' +
    id + '" DataType="' + XS + type + '" MustBePresent="' +
    (mustBePresent ? "true" : "false") + '"/>';
}

function value(type, text) {
  return '<AttributeValue DataType="' + XS + type + '">' + text +
    "</AttributeValue>";
}

// A Target matching subject-id == who, or an empty Target.
function target(who) {
  log.debug("Entering target().");
  if (!who) {
    log.debug("Leaving target(). Empty.");
    return "<Target/>";
  }
  log.debug("Leaving target().");
  return "<Target><AnyOf><AllOf><Match MatchId=\"" + FN + "string-equal\">" +
    value("string", who) +
    designator(SUBJECT, SUBJECT_ID, "string", false) +
    "</Match></AllOf></AnyOf></Target>";
}

function rule(id, effect, condition) {
  return '<Rule RuleId="' + id + '" Effect="' + effect + '"><Target/>' +
    (condition ? "<Condition>" + condition + "</Condition>" : "") +
    "</Rule>";
}

function policy(id, alg, inner, who) {
  return '<Policy xmlns="' + NS + '" PolicyId="' + id +
    '" Version="1.0" RuleCombiningAlgId="' +
    // first-applicable kept its XACML 1.0 identifier in 3.0.
    (alg === "first-applicable"
      ? "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:"
      : RULE_ALG) + alg + '">' +
    target(who) + inner + "</Policy>";
}

function policySet(id, alg, policies) {
  return '<PolicySet xmlns="' + NS + '" PolicySetId="' + id +
    '" Version="1.0" PolicyCombiningAlgId="' + POLICY_ALG + alg + '">' +
    "<Target/>" + policies.map(function (one) {
      return one.replace(' xmlns="' + NS + '"', "");
    }).join("") + "</PolicySet>";
}

function request(attributes) {
  log.debug("Entering request().");
  const byCategory = {};
  attributes.forEach(function (one) {
    byCategory[one.category] = byCategory[one.category] || [];
    byCategory[one.category].push('<Attribute AttributeId="' + one.id +
      '" IncludeInResult="false">' + value(one.type || "string", one.text) +
      "</Attribute>");
  });
  log.debug("Leaving request().");
  return '<Request xmlns="' + NS + '" ReturnPolicyIdList="false" ' +
    'CombinedDecision="false">' + Object.keys(byCategory).map(function (c) {
      return '<Attributes Category="' + c + '">' + byCategory[c].join("") +
        "</Attributes>";
    }).join("") + "</Request>";
}

function decide(policyXml, attributes, options) {
  log.debug("Entering decide().");
  const parsed = xml.parsePolicy(policyXml);
  const node = parsed.policy || parsed.node || parsed;
  assert.ok(node && (node.kind === "Policy" || node.kind === "PolicySet"),
    "the test policy did not parse: " + JSON.stringify(parsed).slice(0, 300));
  const req = xml.parseRequest(request(attributes));
  const out = pdp.evaluate(node, req.request || req, options || {});
  log.debug("Leaving decide(). " + out.decision);
  return out;
}

function as(who) {
  return [{ category: SUBJECT, id: SUBJECT_ID, text: who }];
}

function onlyOneApplicable() {
  log.debug("Entering onlyOneApplicable().");
  const set = policySet("ooa", "only-one-applicable", [
    policy("for-alice", "deny-overrides", rule("r", "Permit"), "alice"),
    policy("for-bob", "deny-overrides", rule("r", "Deny"), "bob"),
    policy("also-alice", "deny-overrides", rule("r", "Permit"), "alice")
  ]);
  assert.strictEqual(decide(set, as("carol")).decision, "NotApplicable",
    "no policy applies to carol");
  assert.strictEqual(decide(set, as("bob")).decision, "Deny",
    "exactly one policy applies to bob, and its decision is the set's");
  const two = decide(set, as("alice"));
  assert.strictEqual(two.decision, "Indeterminate",
    "two policies apply to alice, which C.9 makes Indeterminate");
  const broken = policySet("ooa-broken", "only-one-applicable", [
    policy("needs-clearance", "deny-overrides", rule("r", "Permit"), "") ,
  ].map(function (one) {
    return one.replace("<Target/>", "<Target><AnyOf><AllOf>" +
      "<Match MatchId=\"" + FN + "string-equal\">" + value("string", "x") +
      designator(SUBJECT, CLEARANCE, "string", true) +
      "</Match></AllOf></AnyOf></Target>");
  }));
  assert.strictEqual(decide(broken, as("alice")).decision, "Indeterminate",
    "a target that needs a missing attribute cannot say whether it applies");
  log.info("OK — only-one-applicable: none, one, two, and an unevaluable " +
           "target.");
  log.debug("Leaving onlyOneApplicable().");
}

function variables() {
  log.debug("Entering variables().");
  const isAlice = '<VariableDefinition VariableId="isAlice">' +
    '<Apply FunctionId="' + FN + 'string-equal">' +
    '<Apply FunctionId="' + FN + 'string-one-and-only">' +
    designator(SUBJECT, SUBJECT_ID, "string", false) + "</Apply>" +
    value("string", "alice") + "</Apply></VariableDefinition>";
  const notAlice = '<VariableDefinition VariableId="notAlice">' +
    '<Apply FunctionId="' + FN + 'not">' +
    '<VariableReference VariableId="isAlice"/></Apply></VariableDefinition>';
  const p = policy("vars", "first-applicable", isAlice + notAlice +
    rule("permit-alice", "Permit",
         '<VariableReference VariableId="isAlice"/>') +
    rule("deny-others", "Deny",
         '<VariableReference VariableId="notAlice"/>'), "");
  const alice = decide(p, as("alice"));
  assert.strictEqual(alice.decision, "Permit", JSON.stringify(alice.status));
  assert.strictEqual(decide(p, as("bob")).decision, "Deny",
    "a variable defined through another variable");
  assert.strictEqual(decide(p, []).decision, "Indeterminate",
    "one-and-only over an empty bag is a processing error, through the " +
    "variable as much as directly");
  log.info("OK — VariableReference, chained, and an error through one.");
  log.debug("Leaving variables().");
}

function environment() {
  log.debug("Entering environment().");
  const now = new Date("2026-11-14T08:30:15.250Z");
  const checks = [
    ["date", "current-date", "2026-11-14Z", "2026-11-15Z"],
    ["time", "current-time", "08:30:15Z", "08:30:16Z"],
    ["dateTime", "current-dateTime", "2026-11-14T08:30:15Z",
     "2026-11-14T08:30:16Z"]
  ];
  checks.forEach(function (c) {
    const type = c[0];
    const id = "urn:oasis:names:tc:xacml:1.0:environment:" + c[1];
    const equal = '<Apply FunctionId="' + FN + type + '-equal">' +
      '<Apply FunctionId="' + FN + type + '-one-and-only">' +
      designator(ENV, id, type, true) + "</Apply>" + value(type, c[2]) +
      "</Apply>";
    const p = policy("env-" + type, "deny-overrides",
                     rule("r", "Permit", equal), "");
    assert.strictEqual(decide(p, [], { now: now }).decision, "Permit",
      c[1] + " is supplied from the clock the PDP is handed");
    const later = new Date(now.getTime() +
                           (type === "date" ? 86400000 : 1000));
    assert.strictEqual(decide(p, [], { now: later }).decision,
      "NotApplicable", c[1] + " follows that clock");
    assert.strictEqual(decide(p, [{ category: ENV, id: id, type: type,
      text: c[3] }], { now: now }).decision, "NotApplicable",
      "a " + c[1] + " the request carries wins over the clock: the PEP is " +
      "saying what time the decision is about");
  });
  log.info("OK — current-date, current-time and current-dateTime.");
  log.debug("Leaving environment().");
}

function resolverAndMustBePresent() {
  log.debug("Entering resolverAndMustBePresent().");
  const cleared = '<Apply FunctionId="' + FN + 'string-is-in">' +
    value("string", "secret") +
    designator(SUBJECT, CLEARANCE, "string", true) + "</Apply>";
  const p = policy("pip", "deny-overrides",
                   rule("r", "Permit", cleared), "");
  const missing = decide(p, as("alice"));
  assert.strictEqual(missing.decision, "Indeterminate",
    "MustBePresent over an empty bag");
  assert.ok(/missing-attribute/.test(String(missing.status.code)),
    "and the status says which kind of error: " +
    JSON.stringify(missing.status));
  let asked = 0;
  const resolver = function (d) {
    asked += 1;
    if (d.attributeId !== CLEARANCE) {
      return [];
    }
    return [require(path.join(SRC, "xacml", "xacml_datatypes.js"))
      .parseValue(XS + "string", "secret")];
  };
  assert.strictEqual(decide(p, as("alice"), { resolver: resolver }).decision,
    "Permit", "the PIP supplies what the request did not carry");
  assert.ok(asked > 0, "the resolver was consulted");
  asked = 0;
  assert.strictEqual(decide(p, as("alice").concat([{ category: SUBJECT,
    id: CLEARANCE, text: "public" }]), { resolver: resolver }).decision,
    "NotApplicable", "the request's own value wins over the PIP's");
  assert.strictEqual(asked, 0,
    "the PIP is not asked about an attribute the request carried");
  log.info("OK — the PIP fills only silence, and MustBePresent refuses an " +
           "empty bag.");
  log.debug("Leaving resolverAndMustBePresent().");
}

function legacyPermitOverridesDoesNotPermitOnError() {
  log.debug("Entering legacyPermitOverridesDoesNotPermitOnError().");
  const needsClearance = '<Apply FunctionId="' + FN + 'string-is-in">' +
    value("string", "secret") +
    designator(SUBJECT, CLEARANCE, "string", true) + "</Apply>";
  const set = policySet("legacy-po", "permit-overrides", [
    policy("broken", "deny-overrides",
           rule("r", "Permit", needsClearance), ""),
    policy("never", "deny-overrides", rule("r", "Permit"), "nobody")
  ]);
  assert.strictEqual(decide(set, as("alice")).decision, "Indeterminate",
    "legacy permit-overrides over a policy that failed to evaluate: C.12 " +
    "says Indeterminate, and Permit here would grant on an error");
  log.info("OK — legacy permit-overrides end to end: an error is " +
           "Indeterminate.");
  log.debug("Leaving legacyPermitOverridesDoesNotPermitOnError().");
}

function main() {
  log.debug("Entering main().");
  onlyOneApplicable();
  variables();
  environment();
  resolverAndMustBePresent();
  legacyPermitOverridesDoesNotPermitOnError();
  log.info("xacml_pdp_paths: all checks passed.");
  log.debug("Leaving main().");
}

main();
