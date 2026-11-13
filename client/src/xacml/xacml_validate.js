// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml_validate.js
//
// ---------------------------------------------------------------------------
// STATIC VALIDATION: THE ERRORS A POLICY CAN BE REFUSED FOR BEFORE ANY REQUEST
// ARRIVES.
//
// XACML is statically typed. Every function declares the type and the arity of
// its parameters, every expression has a type derivable without evaluating it,
// and section 5.29 says a PDP verifies the arguments are of the correct type.
// So a policy that adds a string to an integer is WRONG — not "wrong for some
// requests", wrong — and a PDP that finds out at evaluation time reports it as
// an Indeterminate, once per request, for ever.
//
// FIVE CASES IN THE OASIS CONFORMANCE SUITE EXIST FOR THIS AND FOR NOTHING
// ELSE, and upstream renamed their `Request.xml` and `Response.xml` to
// `.ignore` precisely so that no runner could evaluate them and pass by
// accident. Without this file all five load happily and produce a decision:
//
//   IIC003  `string-equal(<AttributeValue>, <AttributeDesignator>)` — a
//           designator is a BAG and string-equal takes two primitives. The
//           policy is missing a `string-one-and-only`. This is the single
//           commonest mistake in hand-written XACML.
//   IIC012  a `<Condition>` whose expression is `integer-subtract`, which
//           returns an integer. A Condition must be a boolean.
//   IIC014  `integer-add(<integer>, <AttributeValue DataType="string">5</>)`
//           — a string literal that LOOKS like a number, in an argument
//           position that requires an integer.
//   IIC332  `string-substring(s, -2, 8)` — a literal index out of range.
//   IIC335  the same, on `anyURI-substring`.
//
// The last two are why a function may carry a `staticCheck`: some constraints
// are about a literal's VALUE rather than its type, and they are checkable
// exactly when the value is written into the policy rather than fetched.
//
// ---------------------------------------------------------------------------
// WHERE THIS IS CALLED FROM, AND WHY IT IS NOT IN THE XML READER.
//
// It validates the MODEL, so it is the same check for a policy that arrived as
// XACML XML, as JSON, or as ALFA — which is the rule this whole directory is
// built on (see `xacml_model.js`). `xacml_xml.js` calls it at the end of
// `parsePolicy()`; an ALFA import reaches the same call because the page
// stores the converted model as XML and `xacml_workbench.js` reads that
// document back through `parsePolicy()`. (The JSON Profile reads requests,
// never policies.) Putting the logic in any one reader would mean another
// accepted policies the first refused.
//
// ---------------------------------------------------------------------------
// IT IS DELIBERATELY INCOMPLETE IN ONE DIRECTION AND SAYS SO.
//
// Where a type CANNOT be determined statically the check is skipped rather
// than guessed. `map` returns a bag whose element type is the mapped
// function's return type; `any-of` takes its bag either way round. Declaring
// those strictly would REFUSE LEGAL POLICIES AT LOAD, which is a far worse
// failure than missing an error at load — a policy that will not load protects
// nothing at all, while one that goes Indeterminate at least fails closed
// under `deny-unless-permit`. So the rule is: refuse only what is certainly
// wrong.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const ownMembers = require('./xacml_own_members');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');
const functions = require('./xacml_functions');

// ---------------------------------------------------------------------------
// THE STATIC TYPE OF AN EXPRESSION.
//
// Returns `{ kind, type }` where kind is 'primitive', 'bag' or 'function', or
// null when the type genuinely cannot be known. A null `type` inside a
// non-null result means "this kind, of some type I cannot name" — the two are
// different answers and collapsing them would turn "I do not know" into "any
// type is fine".
// ---------------------------------------------------------------------------
/**
 * Derives the static type of a policy expression without evaluating it,
 * pushing any certain type error onto `problems`.
 *
 * A literal's lexical form is checked against its declared datatype here.
 * Where the type cannot be known the answer is null rather than a guess.
 * @param expression - a model expression node
 * @param scope - the variable definitions in scope
 * @param problems - the list each problem found is appended to
 * @returns `{ kind, type }` with kind 'primitive', 'bag' or 'function' (a
 * null `type` meaning of some type it cannot name), or null when unknown
 */
function staticTypeOf(expression, scope, problems) {
  log.debug('Entering staticTypeOf(). kind=' +
            (expression ? expression.kind : 'none'));
  if (!expression) {
    log.debug('Leaving staticTypeOf(). No expression.');
    return null;
  }
  if (expression.kind === 'value') {
    // The DECLARED datatype, and the lexical form is checked against it here —
    // which is the one piece of evaluation this file does, because a literal's
    // value cannot change between load and evaluation, so a bad one is a
    // permanent defect rather than a runtime condition.
    if (!datatypes.typeOf(expression.type)) {
      problems.push('Unknown datatype "' + expression.type +
                    '" on an <AttributeValue>.');
      log.debug('Leaving staticTypeOf(). Unknown datatype.');
      return null;
    }
    log.debug('Leaving staticTypeOf(). A literal.');
    return { kind: 'primitive', type: expression.type };
  }
  if (expression.kind === 'designator' || expression.kind === 'selector') {
    // A BAG. Always. This is the fact IIC003 turns on, and the reason
    // `one-and-only` exists at all.
    log.debug('Leaving staticTypeOf(). A bag from a ' + expression.kind + '.');
    return { kind: 'bag', type: expression.dataType };
  }
  if (expression.kind === 'function') {
    log.debug('Leaving staticTypeOf(). A function reference.');
    return { kind: 'function', type: null };
  }
  if (expression.kind === 'variableRef') {
    // Own members only (2026-11-12): a VariableReference to `constructor`
    // is to a variable nobody defined, not to Object.
    const definition = ownMembers.read(scope.variables,
                                       expression.variableId);
    if (!definition) {
      problems.push('VariableReference names "' + expression.variableId +
                    '", which no VariableDefinition in this policy defines.');
      log.debug('Leaving staticTypeOf(). Undefined variable.');
      return null;
    }
    if (ownMembers.read(scope.inProgress, expression.variableId)) {
      // Already reported by the caller that opened the cycle; returning null
      // here stops the recursion rather than reporting it a second time.
      log.debug('Leaving staticTypeOf(). Cyclic variable.');
      return null;
    }
    ownMembers.put(scope.inProgress, expression.variableId, true);
    const type = staticTypeOf(definition, scope, problems);
    delete scope.inProgress[expression.variableId];
    log.debug('Leaving staticTypeOf(). A variable reference.');
    return type;
  }
  if (expression.kind === 'apply') {
    const type = checkApply(expression, scope, problems);
    log.debug('Leaving staticTypeOf(). An application.');
    return type;
  }
  problems.push('Unrecognised expression kind "' + expression.kind + '".');
  log.debug('Leaving staticTypeOf(). Unrecognised.');
  return null;
}

// ---------------------------------------------------------------------------
// ONE <Apply>: the function exists, the arity is right, and every argument is
// of the kind and type the parameter declares.
// ---------------------------------------------------------------------------
function checkApply(expression, scope, problems) {
  log.debug('Entering checkApply(). function=' + expression.functionId);
  const definition = functions.lookup(expression.functionId);
  if (!definition) {
    problems.push('Unknown function "' + expression.functionId + '".');
    log.debug('Leaving checkApply(). Unknown function.');
    return null;
  }
  const declared = definition.args || [];
  const variadic = definition.variadic || null;
  if (!variadic && expression.args.length !== declared.length) {
    problems.push(expression.functionId + ' takes ' + declared.length +
                  ' argument(s) and is given ' + expression.args.length + '.');
  } else if (variadic && expression.args.length < declared.length) {
    problems.push(expression.functionId + ' takes at least ' +
                  declared.length + ' argument(s) and is given ' +
                  expression.args.length + '.');
  }
  expression.args.forEach(function (argument, index) {
    const parameter = index < declared.length ? declared[index] : variadic;
    const actual = staticTypeOf(argument, scope, problems);
    if (!parameter || !actual) {
      return;
    }
    // `any` is the escape hatch, used where the SPECIFICATION genuinely allows
    // either — see the header. It is never used to paper over a parameter
    // whose type is merely inconvenient to state.
    if (parameter.kind === 'any') {
      return;
    }
    if (parameter.kind !== actual.kind) {
      problems.push(expression.functionId + ' argument ' + (index + 1) +
                    ' must be ' + article(parameter.kind) + ' ' +
                    parameter.kind + ' and is ' + article(actual.kind) + ' ' +
                    actual.kind +
                    (actual.kind === 'bag'
                      ? '. An AttributeDesignator or AttributeSelector is ' +
                        'always a bag; wrap it in the matching ' +
                        '-one-and-only function.'
                      : '.'));
      return;
    }
    if (parameter.type && actual.type &&
        model.canonicalType(parameter.type) !==
        model.canonicalType(actual.type)) {
      problems.push(expression.functionId + ' argument ' + (index + 1) +
                    ' must be of type ' + short(parameter.type) +
                    ' and is ' + short(actual.type) + '.');
    }
  });
  if (typeof definition.staticCheck === 'function') {
    definition.staticCheck(expression.args, function (message) {
      problems.push(message);
    });
  }
  const returns = definition.returns || null;
  log.debug('Leaving checkApply().');
  return returns ? { kind: returns.kind, type: returns.type } : null;
}

function article(kind) {
  log.debug("Entering article().");
  log.debug("Leaving article().");
  return kind === 'a' ? 'a' : (/^[aeiou]/.test(kind) ? 'an' : 'a');
}

// The short name of a datatype, for a message a policy author can act on. The
// full URI is correct and unreadable; `integer` and
// `http://www.w3.org/2001/XMLSchema#integer` say the same thing and only one
// of them fits on a line beside the other type it is being compared with.
function short(uri) {
  log.debug("Entering short().");
  const row = datatypes.typeOf(uri);
  log.debug("Leaving short().");
  return row ? row.name : uri;
}

// ---------------------------------------------------------------------------
// A CONDITION MUST BE EXACTLY ONE BOOLEAN. Section 5.28.
//
// The check IIC012 exists for. `integer-subtract` returns an integer, and a
// Condition that yields one is not "false" or "Indeterminate" — it is a policy
// that does not typecheck.
// ---------------------------------------------------------------------------
function checkCondition(condition, scope, problems, where) {
  log.debug('Entering checkCondition().');
  if (!condition) {
    log.debug('Leaving checkCondition(). No condition.');
    return;
  }
  const type = staticTypeOf(condition, scope, problems);
  if (!type) {
    log.debug('Leaving checkCondition(). Type unknown.');
    return;
  }
  if (type.kind !== 'primitive' ||
      (type.type && model.canonicalType(type.type) !== model.TYPE.BOOLEAN)) {
    problems.push('The <Condition> of ' + where + ' must evaluate to ' +
                  'exactly one boolean; this one evaluates to ' +
                  (type.kind === 'bag' ? 'a bag of ' : '') +
                  short(type.type || 'an unknown type') + '.');
  }
  log.debug('Leaving checkCondition().');
}

// ---------------------------------------------------------------------------
// A <Match>: the function must be a two-argument predicate returning boolean,
// its first argument the literal and its second one value out of the bag.
//
// The Match's own semantics unwrap the bag, so what is checked here is the
// ELEMENT type against the parameter — not the bag. Checking the bag would
// reject every well-formed Match there is.
// ---------------------------------------------------------------------------
function checkMatch(match, scope, problems) {
  log.debug('Entering checkMatch(). matchId=' + match.matchId);
  const definition = functions.lookup(match.matchId);
  if (!definition) {
    problems.push('Unknown match function "' + match.matchId + '".');
    log.debug('Leaving checkMatch(). Unknown function.');
    return;
  }
  const declared = definition.args || [];
  if (declared.length !== 2) {
    problems.push('The MatchId "' + match.matchId + '" names a function of ' +
                  declared.length + ' argument(s); a <Match> needs one of ' +
                  'two.');
  }
  if (definition.returns &&
      model.canonicalType(definition.returns.type) !== model.TYPE.BOOLEAN) {
    problems.push('The MatchId "' + match.matchId + '" names a function ' +
                  'returning ' + short(definition.returns.type) +
                  '; a <Match> needs one returning boolean.');
  }
  const literal = staticTypeOf(match.value, scope, problems);
  const reference = staticTypeOf(match.reference, scope, problems);
  if (declared.length === 2 && literal && literal.type &&
      declared[0].type &&
      model.canonicalType(declared[0].type) !==
      model.canonicalType(literal.type)) {
    problems.push('The <AttributeValue> in a <Match> using "' +
                  match.matchId + '" must be of type ' +
                  short(declared[0].type) + ' and is ' + short(literal.type) +
                  '.');
  }
  if (declared.length === 2 && reference && reference.type &&
      declared[1].type &&
      model.canonicalType(declared[1].type) !==
      model.canonicalType(reference.type)) {
    problems.push('The attribute referenced in a <Match> using "' +
                  match.matchId + '" must be of type ' +
                  short(declared[1].type) + ' and is ' +
                  short(reference.type) + '.');
  }
  log.debug('Leaving checkMatch().');
}

function checkTarget(target, scope, problems) {
  log.debug("Entering checkTarget().");
  if (!target) {
    log.debug("Leaving checkTarget().");
    return;
  }
  target.anyOf.forEach(function (anyOf) {
    anyOf.allOf.forEach(function (allOf) {
      allOf.matches.forEach(function (match) {
        checkMatch(match, scope, problems);
      });
    });
  });
  log.debug("Leaving checkTarget().");
}

function checkObligations(holders, scope, problems) {
  log.debug("Entering checkObligations().");
  (holders || []).forEach(function (holder) {
    if (holder.on !== model.EFFECT.PERMIT && holder.on !== model.EFFECT.DENY) {
      problems.push('"' + holder.id + '" fires on "' + holder.on +
                    '", which is neither Permit nor Deny.');
    }
    holder.assignments.forEach(function (assignment) {
      staticTypeOf(assignment.expression, scope, problems);
    });
  });
  log.debug("Leaving checkObligations().");
}

// ---------------------------------------------------------------------------
// THE WHOLE TREE.
// ---------------------------------------------------------------------------
function checkPolicy(policy, problems) {
  log.debug('Entering checkPolicy(). id=' + policy.id);
  const scope = { variables: policy.variables || {}, inProgress: {} };
  if (!functions.lookup && false) {
    log.debug("Leaving checkPolicy().");
    return;
  }
  Object.keys(scope.variables).forEach(function (id) {
    ownMembers.put(scope.inProgress, id, true);
    staticTypeOf(scope.variables[id], scope, problems);
    delete scope.inProgress[id];
  });
  checkTarget(policy.target, scope, problems);
  policy.rules.forEach(function (rule) {
    checkTarget(rule.target, scope, problems);
    checkCondition(rule.condition, scope, problems,
                   'rule "' + rule.id + '"');
    checkObligations(rule.obligations, scope, problems);
    checkObligations(rule.advice, scope, problems);
  });
  checkObligations(policy.obligations, scope, problems);
  checkObligations(policy.advice, scope, problems);
  log.debug('Leaving checkPolicy(). ' + problems.length + ' problem(s).');
}

function checkPolicySet(policySet, problems) {
  log.debug('Entering checkPolicySet(). id=' + policySet.id);
  const scope = { variables: {}, inProgress: {} };
  checkTarget(policySet.target, scope, problems);
  checkObligations(policySet.obligations, scope, problems);
  checkObligations(policySet.advice, scope, problems);
  policySet.children.forEach(function (child) {
    if (child.kind === 'Policy') {
      checkPolicy(child, problems);
    } else if (child.kind === 'PolicySet') {
      checkPolicySet(child, problems);
    }
    // A PolicyIdReference is NOT followed. The referenced document is somebody
    // else's and may not even be loaded yet — and conformance case IIE003 is
    // about exactly that: it references a policy that does not typecheck, and
    // its own Special.txt says the referenced policies "must not be evaluated
    // (or syntax- and type-checked) until the evaluation of the PolicySet
    // calls for" them. Validating through a reference here would refuse a
    // policy set the specification says is fine.
  });
  log.debug('Leaving checkPolicySet(). ' + problems.length + ' problem(s).');
}

// ---------------------------------------------------------------------------
// THE ENTRY POINT. Throws on the first problem, listing all of them.
//
// All of them rather than the first, because a policy author fixing one type
// error at a time through a reload cycle is the thing that makes static
// checking feel like an obstacle instead of a service — and the PAP's editor
// renders this list beside the policy.
// ---------------------------------------------------------------------------
/**
 * Checks a Policy or PolicySet statically for the errors a policy can be
 * refused for before any request arrives.
 *
 * A PolicyIdReference is not followed.
 * @param policy - a Policy or PolicySet from the model
 * @returns true when the policy typechecks
 * @throws an IndeterminateError with the syntax-error status, listing every
 * problem found in its message and in `xacmlDetail.problems`
 */
function validate(policy) {
  log.debug('Entering validate(). id=' + policy.id);
  const problems = [];
  if (policy.kind === 'Policy') {
    checkPolicy(policy, problems);
  } else if (policy.kind === 'PolicySet') {
    checkPolicySet(policy, problems);
  } else {
    problems.push('A policy document must be a Policy or a PolicySet.');
  }
  if (problems.length) {
    log.debug('Leaving validate(). Refused.');
    throw model.syntaxError(
      'The policy "' + policy.id + '" does not typecheck: ' +
      problems.join(' '), { problems: problems });
  }
  log.debug('Leaving validate(). Clean.');
  return true;
}

// The same walk without throwing, for the PAP's editor — which wants to SHOW
// the problems beside the form rather than refuse the page.
/**
 * Runs the same checks as `validate()` and returns the problems instead of
 * throwing, for the PAP's editor.
 * @param policy - a Policy or PolicySet from the model
 * @returns the problems found, as strings; empty when clean
 */
function problemsIn(policy) {
  log.debug("Entering problemsIn().");
  const problems = [];
  if (policy.kind === 'Policy') {
    checkPolicy(policy, problems);
  } else if (policy.kind === 'PolicySet') {
    checkPolicySet(policy, problems);
  }
  log.debug("Leaving problemsIn().");
  return problems;
}

/**
 * Static validation of a XACML policy model: the type and literal errors a
 * policy is refused for at load.
 *
 * It validates the model, so it is the same check for XML, JSON and ALFA,
 * and it refuses only what is certainly wrong.
 * @namespace
 */
module.exports = {
  validate: validate,
  problemsIn: problemsIn,
  staticTypeOf: staticTypeOf
};
