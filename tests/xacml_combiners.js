// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_combiners.js
//
// ---------------------------------------------------------------------------
// EVERY COMBINING ALGORITHM, AGAINST APPENDIX C OF XACML 3.0, EXHAUSTIVELY.
//
// The PDP's combiners (client/src/xacml/xacml_pdp.js, COMBINERS) are checked
// against a second reading of the same pseudocode below: every sequence of
// up to four child decisions drawn from the six XACML 3.0 decision values,
// 1,555 sequences per algorithm. Two things are compared for each: the
// DECISION, and HOW MANY CHILDREN WERE EVALUATED. The second is not a detail:
// the specification's pseudocode returns from inside the loop, and a child
// that was never evaluated contributes no obligations, so a combiner with the
// right decision and the wrong early exit returns the wrong Response.
//
// Each reference below is transcribed from the OASIS Standard of 22 January
// 2013, Appendix C, section by section. The legacy rule combiners read a
// rule's EFFECT where an error occurred; in 3.0's extended Indeterminate a
// Deny rule that errs is Indeterminate{D} and a Permit rule Indeterminate{P},
// so that is how the effect is read here, with {DP} counting as both.
//
// THIS JOB FOUND A REAL DEFECT ON ITS FIRST RUN: the policy-combining legacy
// permit-overrides (C.12) returned PERMIT when a child policy was
// Indeterminate, where the specification returns Deny if any policy denied
// and Indeterminate otherwise. A policy set whose policies failed to evaluate
// granted access.
//
// No browser, no network, no stack.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_combiners",
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

const model = load("xacml/xacml_model.js");
const pdp = load("xacml/xacml_pdp.js");
const D = model.DECISION;

const VALUES = [D.PERMIT, D.DENY, D.NOT_APPLICABLE, D.INDETERMINATE_D,
                D.INDETERMINATE_P, D.INDETERMINATE_DP];

function isIndet(d) {
  return d === D.INDETERMINATE || d === D.INDETERMINATE_D ||
         d === D.INDETERMINATE_P || d === D.INDETERMINATE_DP;
}

// Each reference takes the child decisions and returns
// { decision, evaluated } — evaluated being how many children it read.

// C.2 Deny-overrides.
function denyOverrides(children) {
  log.debug("Entering denyOverrides().");
  let eD = false;
  let eP = false;
  let eDP = false;
  let permit = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.DENY) {
      log.debug("Leaving denyOverrides(). Deny.");
      return { decision: D.DENY, evaluated: i + 1 };
    }
    permit = permit || d === D.PERMIT;
    eD = eD || d === D.INDETERMINATE_D;
    eP = eP || d === D.INDETERMINATE_P;
    eDP = eDP || d === D.INDETERMINATE_DP;
  }
  const n = children.length;
  let out = D.NOT_APPLICABLE;
  if (eDP) {
    out = D.INDETERMINATE_DP;
  } else if (eD && (eP || permit)) {
    out = D.INDETERMINATE_DP;
  } else if (eD) {
    out = D.INDETERMINATE_D;
  } else if (permit) {
    out = D.PERMIT;
  } else if (eP) {
    out = D.INDETERMINATE_P;
  }
  log.debug("Leaving denyOverrides().");
  return { decision: out, evaluated: n };
}

// C.4 Permit-overrides.
function permitOverrides(children) {
  log.debug("Entering permitOverrides().");
  let eD = false;
  let eP = false;
  let eDP = false;
  let deny = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.PERMIT) {
      log.debug("Leaving permitOverrides(). Permit.");
      return { decision: D.PERMIT, evaluated: i + 1 };
    }
    deny = deny || d === D.DENY;
    eD = eD || d === D.INDETERMINATE_D;
    eP = eP || d === D.INDETERMINATE_P;
    eDP = eDP || d === D.INDETERMINATE_DP;
  }
  const n = children.length;
  let out = D.NOT_APPLICABLE;
  if (eDP) {
    out = D.INDETERMINATE_DP;
  } else if (eP && (eD || deny)) {
    out = D.INDETERMINATE_DP;
  } else if (eP) {
    out = D.INDETERMINATE_P;
  } else if (deny) {
    out = D.DENY;
  } else if (eD) {
    out = D.INDETERMINATE_D;
  }
  log.debug("Leaving permitOverrides().");
  return { decision: out, evaluated: n };
}

// C.6 Deny-unless-permit.
function denyUnlessPermit(children) {
  log.debug("Entering denyUnlessPermit().");
  for (let i = 0; i < children.length; i++) {
    if (children[i] === D.PERMIT) {
      log.debug("Leaving denyUnlessPermit(). Permit.");
      return { decision: D.PERMIT, evaluated: i + 1 };
    }
  }
  log.debug("Leaving denyUnlessPermit(). Deny.");
  return { decision: D.DENY, evaluated: children.length };
}

// C.7 Permit-unless-deny.
function permitUnlessDeny(children) {
  log.debug("Entering permitUnlessDeny().");
  for (let i = 0; i < children.length; i++) {
    if (children[i] === D.DENY) {
      log.debug("Leaving permitUnlessDeny(). Deny.");
      return { decision: D.DENY, evaluated: i + 1 };
    }
  }
  log.debug("Leaving permitUnlessDeny(). Permit.");
  return { decision: D.PERMIT, evaluated: children.length };
}

// C.8 First-applicable, rule and policy versions alike.
function firstApplicable(children) {
  log.debug("Entering firstApplicable().");
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.NOT_APPLICABLE) {
      continue;
    }
    log.debug("Leaving firstApplicable(). Child " + i + ".");
    return { decision: isIndet(d) ? D.INDETERMINATE : d, evaluated: i + 1 };
  }
  log.debug("Leaving firstApplicable(). None applied.");
  return { decision: D.NOT_APPLICABLE, evaluated: children.length };
}

// C.10 Legacy deny-overrides, RULE combining.
function legacyDenyRules(children) {
  log.debug("Entering legacyDenyRules().");
  let error = false;
  let potentialDeny = false;
  let permit = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.DENY) {
      log.debug("Leaving legacyDenyRules(). Deny.");
      return { decision: D.DENY, evaluated: i + 1 };
    }
    permit = permit || d === D.PERMIT;
    if (isIndet(d)) {
      error = true;
      potentialDeny = potentialDeny || d === D.INDETERMINATE_D ||
                      d === D.INDETERMINATE_DP;
    }
  }
  let out = D.NOT_APPLICABLE;
  if (potentialDeny) {
    out = D.INDETERMINATE;
  } else if (permit) {
    out = D.PERMIT;
  } else if (error) {
    out = D.INDETERMINATE;
  }
  log.debug("Leaving legacyDenyRules().");
  return { decision: out, evaluated: children.length };
}

// C.10 Legacy deny-overrides, POLICY combining: an Indeterminate policy
// returns Deny AT ONCE, inside the loop.
function legacyDenyPolicies(children) {
  log.debug("Entering legacyDenyPolicies().");
  let permit = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.DENY || isIndet(d)) {
      log.debug("Leaving legacyDenyPolicies(). Deny.");
      return { decision: D.DENY, evaluated: i + 1 };
    }
    permit = permit || d === D.PERMIT;
  }
  log.debug("Leaving legacyDenyPolicies().");
  return { decision: permit ? D.PERMIT : D.NOT_APPLICABLE,
           evaluated: children.length };
}

// C.12 Legacy permit-overrides, RULE combining.
function legacyPermitRules(children) {
  log.debug("Entering legacyPermitRules().");
  let error = false;
  let potentialPermit = false;
  let deny = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.PERMIT) {
      log.debug("Leaving legacyPermitRules(). Permit.");
      return { decision: D.PERMIT, evaluated: i + 1 };
    }
    deny = deny || d === D.DENY;
    if (isIndet(d)) {
      error = true;
      potentialPermit = potentialPermit || d === D.INDETERMINATE_P ||
                        d === D.INDETERMINATE_DP;
    }
  }
  let out = D.NOT_APPLICABLE;
  if (potentialPermit) {
    out = D.INDETERMINATE;
  } else if (deny) {
    out = D.DENY;
  } else if (error) {
    out = D.INDETERMINATE;
  }
  log.debug("Leaving legacyPermitRules().");
  return { decision: out, evaluated: children.length };
}

// C.12 Legacy permit-overrides, POLICY combining: Deny before an error, and
// an error is INDETERMINATE, never Permit.
function legacyPermitPolicies(children) {
  log.debug("Entering legacyPermitPolicies().");
  let error = false;
  let deny = false;
  for (let i = 0; i < children.length; i++) {
    const d = children[i];
    if (d === D.PERMIT) {
      log.debug("Leaving legacyPermitPolicies(). Permit.");
      return { decision: D.PERMIT, evaluated: i + 1 };
    }
    deny = deny || d === D.DENY;
    error = error || isIndet(d);
  }
  let out = D.NOT_APPLICABLE;
  if (deny) {
    out = D.DENY;
  } else if (error) {
    out = D.INDETERMINATE;
  }
  log.debug("Leaving legacyPermitPolicies().");
  return { decision: out, evaluated: children.length };
}

const R = model.RULE_ALG;
const P = model.POLICY_ALG;
const CASES = [
  [R.DENY_OVERRIDES, denyOverrides], [R.ORDERED_DENY_OVERRIDES, denyOverrides],
  [P.DENY_OVERRIDES, denyOverrides], [P.ORDERED_DENY_OVERRIDES, denyOverrides],
  [R.PERMIT_OVERRIDES, permitOverrides],
  [R.ORDERED_PERMIT_OVERRIDES, permitOverrides],
  [P.PERMIT_OVERRIDES, permitOverrides],
  [P.ORDERED_PERMIT_OVERRIDES, permitOverrides],
  [R.DENY_UNLESS_PERMIT, denyUnlessPermit],
  [P.DENY_UNLESS_PERMIT, denyUnlessPermit],
  [R.PERMIT_UNLESS_DENY, permitUnlessDeny],
  [P.PERMIT_UNLESS_DENY, permitUnlessDeny],
  [R.FIRST_APPLICABLE, firstApplicable],
  [P.FIRST_APPLICABLE, firstApplicable],
  [R.LEGACY_DENY_OVERRIDES, legacyDenyRules],
  [R.LEGACY_ORDERED_DENY_OVERRIDES, legacyDenyRules],
  [P.LEGACY_DENY_OVERRIDES, legacyDenyPolicies],
  [P.LEGACY_ORDERED_DENY_OVERRIDES, legacyDenyPolicies],
  [R.LEGACY_PERMIT_OVERRIDES, legacyPermitRules],
  [R.LEGACY_ORDERED_PERMIT_OVERRIDES, legacyPermitRules],
  [P.LEGACY_PERMIT_OVERRIDES, legacyPermitPolicies],
  [P.LEGACY_ORDERED_PERMIT_OVERRIDES, legacyPermitPolicies]
];

// Every sequence of 0..max children over VALUES.
function sequences(max) {
  log.debug("Entering sequences().");
  let out = [[]];
  let layer = [[]];
  for (let n = 1; n <= max; n++) {
    const next = [];
    layer.forEach(function (prefix) {
      VALUES.forEach(function (v) {
        next.push(prefix.concat([v]));
      });
    });
    out = out.concat(next);
    layer = next;
  }
  log.debug("Leaving sequences(). " + out.length);
  return out;
}

function everyCombinerMatchesAppendixC() {
  log.debug("Entering everyCombinerMatchesAppendixC().");
  const all = sequences(4);
  let checked = 0;
  CASES.forEach(function (pair) {
    const uri = pair[0];
    const reference = pair[1];
    assert.ok(uri, "an algorithm identifier is missing from xacml_model.js");
    const combine = pdp.lookupCombiner(uri);
    assert.ok(combine, "no combiner is registered for " + uri);
    all.forEach(function (children) {
      let evaluated = 0;
      const got = combine(children.map(function (d, i) {
        return { id: "child" + i };
      }), function (index) {
        evaluated = Math.max(evaluated, index + 1);
        return { decision: children[index] };
      });
      const want = reference(children);
      const what = uri + " over [" + children.join(", ") + "]";
      assert.strictEqual(got.decision, want.decision, what + ": decision");
      assert.strictEqual(evaluated, want.evaluated,
        what + ": evaluated " + evaluated + " child(ren), the " +
        "specification " + want.evaluated + " — an extra one would add its " +
        "obligations to the Response.");
      assert.strictEqual(got.results.length, want.evaluated,
        what + ": the results handed back for obligations");
      checked += 1;
    });
  });
  log.info("OK — " + CASES.length + " algorithm identifiers over " +
           all.length + " child sequences each: " + checked + " cases agree " +
           "with Appendix C on the decision and on what was evaluated.");
  log.debug("Leaving everyCombinerMatchesAppendixC().");
}

// The two security-relevant rows, by name, so a regression says what it is.
function anErrorNeverPermits() {
  log.debug("Entering anErrorNeverPermits().");
  const combine = pdp.lookupCombiner(P.LEGACY_PERMIT_OVERRIDES);
  const got = combine([{}, {}], function (index) {
    return { decision: [D.NOT_APPLICABLE, D.INDETERMINATE][index] };
  });
  assert.strictEqual(got.decision, D.INDETERMINATE,
    "legacy permit-overrides over a policy set whose only applicable policy " +
    "failed to evaluate returned " + got.decision + ". C.12 returns " +
    "Indeterminate: an error must not grant access.");
  const denied = combine([{}, {}], function (index) {
    return { decision: [D.INDETERMINATE, D.DENY][index] };
  });
  assert.strictEqual(denied.decision, D.DENY,
    "C.12 checks atLeastOneDeny before atLeastOneError.");
  log.info("OK — a policy that fails to evaluate never makes legacy " +
           "permit-overrides Permit.");
  log.debug("Leaving anErrorNeverPermits().");
}

function unknownAlgorithmIsRefused() {
  log.debug("Entering unknownAlgorithmIsRefused().");
  assert.strictEqual(pdp.lookupCombiner("urn:example:not-an-algorithm"),
    null, "an unknown combining algorithm resolved to something");
  assert.throws(function () {
    pdp.lookupCombiner(P.ONLY_ONE_APPLICABLE)([], function () {
      return { decision: D.NOT_APPLICABLE };
    });
  }, /only-one-applicable/, "only-one-applicable is evaluated by the " +
    "policy-set evaluator and must say so if reached as a combiner");
  log.info("OK — an unknown algorithm resolves to nothing, and " +
           "only-one-applicable refuses the ordinary path.");
  log.debug("Leaving unknownAlgorithmIsRefused().");
}

function main() {
  log.debug("Entering main().");
  everyCombinerMatchesAppendixC();
  anErrorNeverPermits();
  unknownAlgorithmIsRefused();
  log.info("xacml_combiners: all checks passed.");
  log.debug("Leaving main().");
}

main();
