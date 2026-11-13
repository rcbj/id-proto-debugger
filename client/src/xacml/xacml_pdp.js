// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pdp.js
//
// ---------------------------------------------------------------------------
// THE POLICY DECISION POINT: A REQUEST AND A POLICY IN, A DECISION OUT.
//
// This file knows nothing about XML, JSON or ALFA. It evaluates the shapes in
// `xacml_model.js`, and if a function in here ever asks which syntax a policy
// arrived in, the separation this directory is built on has failed — see that
// file's header.
//
// It also knows nothing about HTTP, the directory or the console. The only
// thing it reaches outside itself for is an ATTRIBUTE, through the resolver on
// the context — which is what makes `xacml_pip.js` swappable and what lets the
// conformance runner drive the whole engine in-process with no service, no
// port and no container.
//
// ---------------------------------------------------------------------------
// THE FOUR THINGS A PDP GETS WRONG, IN THE ORDER THEY COST THE MOST.
//
// 1. COLLAPSING THE EXTENDED INDETERMINATE VALUES. Argued at length in
//    `xacml_model.js`. The combining algorithms below (`COMBINERS`) are the
//    only consumer of them and the reason they exist; `externalDecision()` is
//    called ONCE, at the very bottom of `evaluate()`, and a second call site
//    anywhere is a bug.
//
// 2. TREATING A MISSING ATTRIBUTE AS FALSE. An `AttributeDesignator` that
//    finds nothing returns an EMPTY BAG, and what happens next is decided by
//    `MustBePresent` and by the function the bag is handed to — not by this
//    file. `string-one-and-only` on an empty bag is Indeterminate, while
//    `string-is-in` on one is False. Short-circuiting "nothing there" in
//    the resolver would make the second right and the first silently wrong,
//    and the wrong answer is the permissive one.
//
// 3. LETTING A TARGET'S INDETERMINATE BECOME A NO-MATCH. A `Target` whose
//    Match could not be evaluated is Indeterminate, and the rule under it is
//    then `Indeterminate{Effect}` rather than `NotApplicable`. Those two look
//    identical in a log — nothing applied — and one of them means a Deny was
//    possible.
//
// 4. PROPAGATING OBLIGATIONS FROM AN INDETERMINATE. Section 7.18: obligations
//    travel up only from a Permit or a Deny. A PDP that carried them from an
//    Indeterminate would hand a PEP instructions derived from an evaluation
//    that did not happen.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');
const functions = require('./xacml_functions');

const DECISION = model.DECISION;
const MATCH = model.MATCH;
const EFFECT = model.EFFECT;

// ---------------------------------------------------------------------------
// THE EVALUATION CONTEXT.
//
// Everything one decision needs, built once per request. The `resolver` is the
// PIP and is optional: with none, a designator sees only what the request
// carried, which is the pure-XACML behaviour the conformance suite expects and
// is why the suite can drive this with no directory anywhere.
// ---------------------------------------------------------------------------
/**
 * Builds the evaluation context for one decision.
 *
 * The context carries the request, the optional PIP resolver, a clock
 * fixed for the whole evaluation, and the lists of included attributes
 * and applicable policies collected while evaluating. XPath is not
 * supported: its `countNodes()` throws a processing error.
 * @param request - the request, in the shapes of `xacml_model.js`
 * @param options - optional; `resolver` (the PIP) and `now` (a Date)
 * @returns the context
 */
function makeContext(request, options) {
  log.debug('Entering makeContext().');
  const settings = options || {};
  const context = {
    request: request,
    resolver: settings.resolver || null,
    // The three environment attributes a PDP must SUPPLY when the request does
    // not carry them (section 10.2.5). Fixed for the whole evaluation rather
    // than read per designator — two references to `current-time` inside one
    // decision must not be able to straddle a second boundary and produce a
    // policy that contradicts itself.
    now: settings.now || new Date(),
    // Every attribute the request asked to have echoed back, and every policy
    // identifier that turned out to be applicable. Collected during evaluation
    // because neither can be worked out afterwards.
    includedAttributes: [],
    applicablePolicies: [],
    countNodes: function () {
      log.debug("Entering countNodes().");
      log.debug("Leaving countNodes().");
      // To be replaced if XPath support is ever wired up (no module provides
      // it today). Until then this refuses rather than returning 0 — a node
      // count of zero is a perfectly ordinary answer, so a stub returning it
      // would make every XPath policy quietly evaluate against an empty
      // document.
      throw model.processingError(
        'This PDP has no XPath support wired up, so xpath-node-count and ' +
        'AttributeSelector cannot be evaluated.');
    }
  };
  log.debug('Leaving makeContext().');
  return context;
}

// ---------------------------------------------------------------------------
// ATTRIBUTE RESOLUTION.
//
// The request first, then the PIP, then — for the three environment attributes
// only — this service's clock. That order matters: a request that carries
// `current-time` uses the one it carried, because a PEP that supplied it is
// asserting the time the decision is ABOUT, which is not necessarily now.
// ---------------------------------------------------------------------------
/**
 * Resolves an AttributeDesignator to a bag of values.
 *
 * Looks in the request first, then asks the PIP, then — for the three
 * environment attributes only — supplies them from the context's clock.
 * A designator that finds nothing yields an empty bag unless
 * `MustBePresent` is set.
 * @param designator - the designator expression
 * @param context - the evaluation context from `makeContext()`
 * @returns a bag of values
 * @throws a processing error carrying a missing-attribute status when a
 *   required attribute is absent
 */
function resolveDesignator(designator, context) {
  log.debug('Entering resolveDesignator(). id=' + designator.attributeId);
  const values = [];
  context.request.categories.forEach(function (category) {
    if (category.category !== designator.category) {
      return;
    }
    category.attributes.forEach(function (attribute) {
      if (attribute.attributeId !== designator.attributeId) {
        return;
      }
      // The Issuer is a FILTER and only when the designator names one. A
      // designator with no Issuer matches an attribute whatever its issuer —
      // not only attributes that have none, which is the reading that makes
      // every issued attribute invisible.
      if (designator.issuer && attribute.issuer !== designator.issuer) {
        return;
      }
      attribute.values.forEach(function (value) {
        if (model.canonicalType(value.type) !== designator.dataType) {
          return;
        }
        values.push(datatypes.parseValue(designator.dataType, value.lexical));
      });
    });
  });
  if (values.length === 0 && context.resolver) {
    // THE PIP. Consulted only when the request carried nothing, which is the
    // ordering every deployment expects: what the PEP asserted wins over what
    // the directory holds, because the PEP is describing this request and the
    // directory is describing the world.
    const supplied = context.resolver(designator, context);
    if (supplied && supplied.length) {
      supplied.forEach(function (value) {
        values.push(value);
      });
    }
  }
  if (values.length === 0) {
    const synthesized = environmentAttribute(designator, context);
    if (synthesized !== null) {
      values.push(synthesized);
    }
  }
  if (values.length === 0 && designator.mustBePresent) {
    // See defect 2 in the header: this is the ONLY place an empty bag becomes
    // an error, and it happens because the policy asked for it to.
    log.debug('Leaving resolveDesignator(). Missing and MustBePresent.');
    throw model.missingAttribute(
      'The attribute "' + designator.attributeId + '" in category "' +
      designator.category + '" is not present, and the policy requires it ' +
      '(MustBePresent="true").',
      { attributeId: designator.attributeId,
        category: designator.category,
        dataType: designator.dataType });
  }
  log.debug('Leaving resolveDesignator(). ' + values.length + ' value(s).');
  return model.bag(designator.dataType, values);
}

// The three the PDP supplies itself. Returns null for anything else, which is
// what keeps this from being a general-purpose fallback that invents values.
function environmentAttribute(designator, context) {
  log.debug("Entering environmentAttribute().");
  if (designator.category !== model.CATEGORY.ENVIRONMENT) {
    log.debug("Leaving environmentAttribute().");
    return null;
  }
  const now = context.now;
  const iso = now.toISOString();
  if (designator.attributeId === model.ATTRIBUTE.CURRENT_DATETIME &&
      designator.dataType === model.TYPE.DATETIME) {
    log.debug("Leaving environmentAttribute().");
    return datatypes.parseValue(model.TYPE.DATETIME, iso.replace(/\.\d+Z$/,
                                                                'Z'));
  }
  if (designator.attributeId === model.ATTRIBUTE.CURRENT_DATE &&
      designator.dataType === model.TYPE.DATE) {
    log.debug("Leaving environmentAttribute().");
    return datatypes.parseValue(model.TYPE.DATE, iso.slice(0, 10) + 'Z');
  }
  if (designator.attributeId === model.ATTRIBUTE.CURRENT_TIME &&
      designator.dataType === model.TYPE.TIME) {
    log.debug("Leaving environmentAttribute().");
    return datatypes.parseValue(model.TYPE.TIME,
                                iso.slice(11, 19) + 'Z');
  }
  log.debug("Leaving environmentAttribute().");
  return null;
}

// ---------------------------------------------------------------------------
// EXPRESSION EVALUATION. Always returns a BAG — see `xacml_functions.js`.
// ---------------------------------------------------------------------------
/**
 * Evaluates an expression and returns its result as a bag.
 *
 * A literal, a designator, a selector, a variable reference, an Apply or
 * a function reference; a failure is thrown as an XACML error rather
 * than returned.
 * @param expression - the expression, in the shapes of `xacml_model.js`
 * @param context - the evaluation context from `makeContext()`
 * @param variables - the policy's variable table from `makeVariables()`,
 *   or null
 * @returns a bag
 */
function evaluateExpression(expression, context, variables) {
  log.debug('Entering evaluateExpression(). kind=' + expression.kind);
  if (expression.kind === 'value') {
    const value = datatypes.parseValue(expression.type, expression.lexical);
    log.debug('Leaving evaluateExpression(). A literal.');
    return model.singleton(expression.type, value);
  }
  if (expression.kind === 'designator') {
    log.debug('Leaving evaluateExpression(). A designator.');
    return resolveDesignator(expression, context);
  }
  if (expression.kind === 'selector') {
    log.debug('Leaving evaluateExpression(). A selector.');
    // Deliberately not silently empty. An AttributeSelector this PDP cannot
    // evaluate must be Indeterminate rather than an empty bag: an empty bag is
    // a perfectly ordinary result that a policy may well be written to expect,
    // so returning one would make an unimplemented feature look like a
    // deliberate decision.
    throw model.processingError(
      'AttributeSelector is not evaluable without XPath support over the ' +
      'request <Content>.');
  }
  if (expression.kind === 'variableRef') {
    log.debug('Leaving evaluateExpression(). A variable reference.');
    return resolveVariable(expression.variableId, context, variables);
  }
  if (expression.kind === 'function') {
    // A bare function reference is only meaningful as the first argument of a
    // higher-order function, and those are lazy and never call this. Reaching
    // here means one was used as a value.
    log.debug('Leaving evaluateExpression(). A misplaced function.');
    throw model.syntaxError(
      '<Function FunctionId="' + expression.functionId + '"/> is only valid ' +
      'as the first argument of a higher-order function.');
  }
  if (expression.kind === 'apply') {
    const definition = functions.lookup(expression.functionId);
    if (!definition) {
      log.debug('Leaving evaluateExpression(). Unknown function.');
      throw model.syntaxError(
        'Unknown function "' + expression.functionId + '".');
    }
    if (definition.lazy) {
      // See `xacml_functions.js`: `and`, `or`, `n-of`, the six higher-order
      // functions and `map` get their arguments UNEVALUATED, because
      // short-circuiting and function-valued arguments both depend on it.
      const evaluate = function (child, innerContext) {
        log.debug("Entering evaluate().");
        log.debug("Leaving evaluate().");
        return evaluateExpression(child, innerContext, variables);
      };
      const lazyResult = definition.apply(expression.args, context, evaluate);
      log.debug('Leaving evaluateExpression(). A lazy application.');
      return lazyResult;
    }
    const argumentBags = expression.args.map(function (argument) {
      return evaluateExpression(argument, context, variables);
    });
    const result = functions.invoke(definition, argumentBags, context);
    log.debug('Leaving evaluateExpression(). Applied ' +
              expression.functionId + '.');
    return result;
  }
  log.debug('Leaving evaluateExpression(). Unrecognised expression.');
  throw model.syntaxError('Unrecognised expression kind "' +
                          expression.kind + '".');
}

// ---------------------------------------------------------------------------
// VARIABLES, WITH CYCLE DETECTION AND MEMOISATION.
//
// A `VariableDefinition` is evaluated at most once per decision, which is both
// an optimisation and a correctness rule: a variable holding a designator over
// an attribute a PIP is asked for must not be able to produce two different
// bags within one decision.
//
// The cycle check is not theoretical. `VariableReference` may name a variable
// defined later in the same policy, so a definition CAN refer to itself
// through a chain, and without this the failure is a stack overflow that takes
// the whole service down rather than an Indeterminate for one request.
// ---------------------------------------------------------------------------
function resolveVariable(id, context, variables) {
  log.debug('Entering resolveVariable(). id=' + id);
  if (!variables || !variables.definitions[id]) {
    log.debug('Leaving resolveVariable(). Undefined.');
    throw model.syntaxError(
      'VariableReference names "' + id + '", which no VariableDefinition in ' +
      'this policy defines.');
  }
  if (Object.prototype.hasOwnProperty.call(variables.values, id)) {
    log.debug('Leaving resolveVariable(). Memoised.');
    return variables.values[id];
  }
  if (variables.inProgress[id]) {
    log.debug('Leaving resolveVariable(). Cyclic.');
    throw model.syntaxError(
      'VariableDefinition "' + id + '" refers to itself, directly or ' +
      'through another variable.');
  }
  variables.inProgress[id] = true;
  try {
    const value = evaluateExpression(variables.definitions[id], context,
                                     variables);
    variables.values[id] = value;
    log.debug('Leaving resolveVariable(). Evaluated.');
    return value;
  } finally {
    // Cleared whether or not it threw, so that a variable which was
    // Indeterminate once is retried rather than reported as cyclic the second
    // time — which would be a different error about the same thing.
    delete variables.inProgress[id];
  }
}

/**
 * Builds the variable table for one policy's VariableDefinitions.
 *
 * Each variable is evaluated once, on first reference, and cached.
 * @param definitions - the definitions keyed by VariableId, or nothing
 * @returns the variable table
 */
function makeVariables(definitions) {
  log.debug("Entering makeVariables().");
  log.debug("Leaving makeVariables().");
  return { definitions: definitions || {}, values: {}, inProgress: {} };
}

// ---------------------------------------------------------------------------
// TARGET MATCHING.
//
// Three levels, and the quantifier flips at each one. See `readTarget()` in
// `xacml_xml.js` for why the element names read backwards from what they do.
// ---------------------------------------------------------------------------
function evaluateMatch(match, context, variables) {
  log.debug('Entering evaluateMatch(). matchId=' + match.matchId);
  const definition = functions.lookup(match.matchId);
  if (!definition) {
    log.debug('Leaving evaluateMatch(). Unknown match function.');
    throw model.syntaxError('Unknown match function "' + match.matchId + '".');
  }
  const attributeBag = evaluateExpression(match.reference, context, variables);
  const literal = evaluateExpression(match.value, context, variables);
  // A Match applies its function to the literal and EACH value in the bag, and
  // is a match if any one of them is true. That is `any-of` in all but name,
  // and writing it out here rather than delegating keeps the Indeterminate
  // handling below visible.
  let sawTrue = false;
  let firstError = null;
  for (let i = 0; i < attributeBag.values.length; i += 1) {
    try {
      const result = functions.invoke(
        definition,
        [literal, model.singleton(attributeBag.type, attributeBag.values[i])],
        context);
      if (result.values.length === 1 && result.values[0] === true) {
        sawTrue = true;
        break;
      }
    } catch (error) {
      // ONE value failing does not sink the Match. The specification's
      // `any-of` semantics say a match is found if ANY application is true, so
      // an error on one value only matters when no other value matched — which
      // is why the error is remembered rather than rethrown here.
      if (!firstError) {
        firstError = error;
      }
    }
  }
  if (sawTrue) {
    log.debug('Leaving evaluateMatch(). Match.');
    return MATCH.MATCH;
  }
  if (firstError) {
    log.debug('Leaving evaluateMatch(). Indeterminate.');
    throw firstError;
  }
  log.debug('Leaving evaluateMatch(). No-match.');
  return MATCH.NO_MATCH;
}

/**
 * Matches a Target against the request (section 7.6).
 *
 * An absent Target matches everything. An Indeterminate is thrown rather
 * than turned into a No-match.
 * @param target - the Target, or null
 * @param context - the evaluation context from `makeContext()`
 * @param variables - the variable table, or null
 * @returns one of `MATCH`'s values
 */
function evaluateTarget(target, context, variables) {
  log.debug('Entering evaluateTarget().');
  if (!target) {
    // An absent or empty Target matches everything. Section 7.6.
    log.debug('Leaving evaluateTarget(). Absent, so Match.');
    return MATCH.MATCH;
  }
  let indeterminate = false;
  for (let i = 0; i < target.anyOf.length; i += 1) {
    const anyOfResult = evaluateAnyOf(target.anyOf[i], context, variables);
    if (anyOfResult === MATCH.NO_MATCH) {
      // A Target is a conjunction: one No-match settles it, whatever the
      // others would have done. Returning here rather than continuing is also
      // what stops an unrelated Indeterminate from masking a definite miss.
      log.debug('Leaving evaluateTarget(). No-match.');
      return MATCH.NO_MATCH;
    }
    if (anyOfResult === MATCH.INDETERMINATE) {
      indeterminate = true;
    }
  }
  if (indeterminate) {
    log.debug('Leaving evaluateTarget(). Indeterminate.');
    return MATCH.INDETERMINATE;
  }
  log.debug('Leaving evaluateTarget(). Match.');
  return MATCH.MATCH;
}

function evaluateAnyOf(anyOf, context, variables) {
  log.debug("Entering evaluateAnyOf().");
  let indeterminate = false;
  for (let i = 0; i < anyOf.allOf.length; i += 1) {
    const allOfResult = evaluateAllOf(anyOf.allOf[i], context, variables);
    if (allOfResult === MATCH.MATCH) {
      log.debug("Leaving evaluateAnyOf().");
      return MATCH.MATCH;
    }
    if (allOfResult === MATCH.INDETERMINATE) {
      indeterminate = true;
    }
  }
  log.debug("Leaving evaluateAnyOf().");
  return indeterminate ? MATCH.INDETERMINATE : MATCH.NO_MATCH;
}

function evaluateAllOf(allOf, context, variables) {
  log.debug("Entering evaluateAllOf().");
  let indeterminate = false;
  for (let i = 0; i < allOf.matches.length; i += 1) {
    let result;
    try {
      result = evaluateMatch(allOf.matches[i], context, variables);
    } catch (error) {
      // The error's status is not lost — it is what makes the enclosing
      // decision's Status say `missing-attribute` rather than
      // `processing-error` — so it is carried on the sentinel rather than
      // being swallowed here.
      indeterminate = true;
      allOf.lastError = error;
      continue;
    }
    if (result === MATCH.NO_MATCH) {
      log.debug("Leaving evaluateAllOf().");
      return MATCH.NO_MATCH;
    }
  }
  log.debug("Leaving evaluateAllOf().");
  return indeterminate ? MATCH.INDETERMINATE : MATCH.MATCH;
}

// ---------------------------------------------------------------------------
// RULE EVALUATION. Section 7.11.
// ---------------------------------------------------------------------------
/**
 * Evaluates one Rule (section 7.11).
 *
 * A Target or Condition that cannot be evaluated gives
 * `Indeterminate{Effect}` with the error's status, never NotApplicable.
 * @param rule - the Rule
 * @param context - the evaluation context from `makeContext()`
 * @param variables - the enclosing policy's variable table
 * @returns an object with `decision` and, where there was one, `status`
 */
function evaluateRule(rule, context, variables) {
  log.debug('Entering evaluateRule(). id=' + rule.id);
  let targetResult;
  try {
    targetResult = evaluateTarget(rule.target, context, variables);
  } catch (error) {
    log.debug('Leaving evaluateRule(). Target threw.');
    return withStatus(model.indeterminateOfEffect(rule.effect), error);
  }
  if (targetResult === MATCH.NO_MATCH) {
    log.debug('Leaving evaluateRule(). Target did not match.');
    return { decision: DECISION.NOT_APPLICABLE };
  }
  if (targetResult === MATCH.INDETERMINATE) {
    // See defect 3 in the header. This is the case that is easy to write as
    // NotApplicable and that hides a possible Deny when it is.
    log.debug('Leaving evaluateRule(). Target was Indeterminate.');
    return withStatus(model.indeterminateOfEffect(rule.effect),
                      rule.target && rule.target.anyOf
                        ? lastTargetError(rule.target) : null);
  }
  if (!rule.condition) {
    log.debug('Leaving evaluateRule(). No condition, so the Effect.');
    return firedRule(rule, context, variables);
  }
  let conditionResult;
  try {
    conditionResult = evaluateExpression(rule.condition, context, variables);
  } catch (error) {
    log.debug('Leaving evaluateRule(). Condition threw.');
    return withStatus(model.indeterminateOfEffect(rule.effect), error);
  }
  if (conditionResult.values.length !== 1 ||
      model.canonicalType(conditionResult.type) !== model.TYPE.BOOLEAN) {
    log.debug('Leaving evaluateRule(). Condition was not one boolean.');
    return withStatus(model.indeterminateOfEffect(rule.effect),
                      model.processingError(
                        'A <Condition> must evaluate to exactly one ' +
                        'boolean.'));
  }
  if (conditionResult.values[0] === true) {
    log.debug('Leaving evaluateRule(). Condition true, so the Effect.');
    return firedRule(rule, context, variables);
  }
  log.debug('Leaving evaluateRule(). Condition false.');
  return { decision: DECISION.NOT_APPLICABLE };
}

// ---------------------------------------------------------------------------
// A RULE THAT FIRED, WITH ITS OBLIGATIONS ALREADY RESOLVED.
//
// XACML 3.0 put obligations on RULES as well as on policies (2.0 had them only
// on the latter), and they have to be resolved HERE rather than by the policy
// above — this is the only place that still has the rule's variables in scope,
// and an `AttributeAssignmentExpression` may reference one.
//
// Resolving can THROW: an assignment whose expression is Indeterminate makes
// the whole rule Indeterminate rather than the rule succeeding with an
// obligation missing. Section 7.18 is explicit about it, and the alternative is
// worse than it sounds — a PEP that is handed a Permit with one of its two
// obligations quietly dropped enforces half of what the policy said.
// ---------------------------------------------------------------------------
function firedRule(rule, context, variables) {
  log.debug('Entering firedRule(). id=' + rule.id);
  try {
    const result = { decision: rule.effect };
    result.obligationsResolved = collect(rule.obligations, rule.effect,
                                         context, variables);
    result.adviceResolved = collect(rule.advice, rule.effect, context,
                                    variables);
    log.debug('Leaving firedRule(). ' + rule.effect + '.');
    return result;
  } catch (error) {
    log.debug('Leaving firedRule(). An obligation could not be resolved.');
    return withStatus(model.indeterminateOfEffect(rule.effect), error);
  }
}

function lastTargetError(target) {
  log.debug("Entering lastTargetError().");
  let found = null;
  target.anyOf.forEach(function (anyOf) {
    anyOf.allOf.forEach(function (allOf) {
      if (allOf.lastError && !found) {
        found = allOf.lastError;
      }
    });
  });
  log.debug("Leaving lastTargetError().");
  return found;
}

function withStatus(decision, error) {
  log.debug("Entering withStatus().");
  log.debug("Leaving withStatus().");
  return { decision: decision,
           status: error ? { code: error.xacmlStatus,
                             message: error.message,
                             detail: error.xacmlDetail } : null };
}

// ---------------------------------------------------------------------------
// THE COMBINING ALGORITHMS. Twelve identifiers; the block below says how they
// are written and why.
// ---------------------------------------------------------------------------
/**
 * The combining algorithms, keyed by rule- and policy-combining algorithm
 * identifier.
 *
 * Each entry controls evaluation of its children rather than being handed
 * their results, so it can stop as soon as the outcome is settled.
 */
const COMBINERS = {};

// ---------------------------------------------------------------------------
// A COMBINER CONTROLS EVALUATION; IT IS NOT HANDED RESULTS.
//
// THIS IS THE SHAPE THE FIRST CONFORMANCE RUN GOT WRONG, and the failure is
// worth recording because it is invisible in the DECISION and shows up only in
// the obligations. Eight IID cases failed on it.
//
// The specification's pseudocode returns from INSIDE the loop —
// `if (decision == Deny) return Deny;` — so a `deny-overrides` set whose
// fourth policy denies never evaluates the fifth. Evaluate all five up front
// and combine afterwards and you get the same decision every time, because Deny
// still wins; but you have also run policy5, and IF IT CARRIES AN OBLIGATION
// THAT OBLIGATION IS NOW IN THE RESPONSE. IID307 expects one obligation and a
// pre-evaluating implementation returns two, with the right decision attached.
//
// So a combiner is handed the children and a function that evaluates one on
// demand, and it returns BOTH the decision and the results it actually
// produced. Obligations are then collected from that list rather than from the
// children — which makes "we never ran it, so it contributes nothing" true by
// construction rather than by a filter somebody has to remember.
//
// Each is transcribed from the specification's own pseudocode in Appendix C
// rather than reasoned out. These are short enough to look obvious and are
// not: the ordering of the final tests in `deny-overrides` alone distinguishes
// four different wrong implementations that each pass the simple cases.
//
// THE ORDERED VARIANTS ARE THE UNORDERED ONES. This implementation evaluates
// children in document order always, so `ordered-deny-overrides` and
// `deny-overrides` are the same function here. That is conformant — the
// specification PERMITS reordering for the unordered variants and does not
// require it — and it is the right choice for a mock, where reproducibility is
// the whole point. It is ALSO what makes the early exit above well defined:
// "the first Deny" means something only if the order is fixed.
// ---------------------------------------------------------------------------
function combiner(uris, implementation) {
  log.debug("Entering combiner().");
  uris.forEach(function (uri) {
    COMBINERS[uri] = implementation;
  });
  log.debug("Leaving combiner().");
}

// --- deny-overrides, XACML 3.0 (C.2) ----------------------------------------
combiner([model.RULE_ALG.DENY_OVERRIDES,
          model.RULE_ALG.ORDERED_DENY_OVERRIDES,
          model.POLICY_ALG.DENY_OVERRIDES,
          model.POLICY_ALG.ORDERED_DENY_OVERRIDES],
         function (children, evaluateChild) {
  log.debug('Entering denyOverrides(). ' + children.length + ' child(ren).');
  const results = [];
  let errorD = false;
  let errorP = false;
  let errorDP = false;
  let permit = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.DENY) {
      log.debug('Leaving denyOverrides(). A Deny at ' + i + ' stops here.');
      return { decision: DECISION.DENY, results: results };
    }
    if (decision === DECISION.PERMIT) {
      permit = true;
    } else if (decision === DECISION.INDETERMINATE_D) {
      errorD = true;
    } else if (decision === DECISION.INDETERMINATE_P) {
      errorP = true;
    } else if (decision === DECISION.INDETERMINATE_DP ||
               decision === DECISION.INDETERMINATE) {
      errorDP = true;
    }
  }
  // The order of these five tests IS the algorithm. Moving any one of them
  // produces something that passes the ordinary cases and differs on the
  // interesting ones.
  let decision;
  if (errorDP) {
    decision = DECISION.INDETERMINATE_DP;
  } else if (errorD && (errorP || permit)) {
    decision = DECISION.INDETERMINATE_DP;
  } else if (errorD) {
    decision = DECISION.INDETERMINATE_D;
  } else if (permit) {
    decision = DECISION.PERMIT;
  } else if (errorP) {
    decision = DECISION.INDETERMINATE_P;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  log.debug('Leaving denyOverrides(). ' + decision + '.');
  return { decision: decision, results: results };
});

// --- permit-overrides, XACML 3.0 (C.3) — the exact mirror -------------------
combiner([model.RULE_ALG.PERMIT_OVERRIDES,
          model.RULE_ALG.ORDERED_PERMIT_OVERRIDES,
          model.POLICY_ALG.PERMIT_OVERRIDES,
          model.POLICY_ALG.ORDERED_PERMIT_OVERRIDES],
         function (children, evaluateChild) {
  log.debug('Entering permitOverrides(). ' + children.length + ' child(ren).');
  const results = [];
  let errorD = false;
  let errorP = false;
  let errorDP = false;
  let deny = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.PERMIT) {
      log.debug('Leaving permitOverrides(). A Permit at ' + i + '.');
      return { decision: DECISION.PERMIT, results: results };
    }
    if (decision === DECISION.DENY) {
      deny = true;
    } else if (decision === DECISION.INDETERMINATE_D) {
      errorD = true;
    } else if (decision === DECISION.INDETERMINATE_P) {
      errorP = true;
    } else if (decision === DECISION.INDETERMINATE_DP ||
               decision === DECISION.INDETERMINATE) {
      errorDP = true;
    }
  }
  let decision;
  if (errorDP) {
    decision = DECISION.INDETERMINATE_DP;
  } else if (errorP && (errorD || deny)) {
    decision = DECISION.INDETERMINATE_DP;
  } else if (errorP) {
    decision = DECISION.INDETERMINATE_P;
  } else if (deny) {
    decision = DECISION.DENY;
  } else if (errorD) {
    decision = DECISION.INDETERMINATE_D;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  log.debug('Leaving permitOverrides(). ' + decision + '.');
  return { decision: decision, results: results };
});

// --- deny-unless-permit / permit-unless-deny (C.6, C.7) ---------------------
// The two algorithms that CANNOT return NotApplicable or Indeterminate. That
// is their whole purpose: they turn any uncertainty into a definite answer, so
// a PEP is never handed one it has to have a policy about.
combiner([model.RULE_ALG.DENY_UNLESS_PERMIT,
          model.POLICY_ALG.DENY_UNLESS_PERMIT],
         function (children, evaluateChild) {
  const results = [];
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    if (result.decision === DECISION.PERMIT) {
      return { decision: DECISION.PERMIT, results: results };
    }
  }
  return { decision: DECISION.DENY, results: results };
});

combiner([model.RULE_ALG.PERMIT_UNLESS_DENY,
          model.POLICY_ALG.PERMIT_UNLESS_DENY],
         function (children, evaluateChild) {
  const results = [];
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    if (result.decision === DECISION.DENY) {
      return { decision: DECISION.DENY, results: results };
    }
  }
  return { decision: DECISION.PERMIT, results: results };
});

// --- first-applicable (C.8) -------------------------------------------------
// A 1.0 algorithm, so it produces a PLAIN Indeterminate rather than an
// extended one. Not an oversight: the extended values were introduced for the
// overrides algorithms, and first-applicable stops at the first child that
// decided anything, so there is no second child whose direction could matter.
//
// It is also the algorithm where the early exit is most obviously load-bearing
// — "first applicable" is a statement about evaluation order, not a filter.
combiner([model.RULE_ALG.FIRST_APPLICABLE,
          model.POLICY_ALG.FIRST_APPLICABLE],
         function (children, evaluateChild) {
  log.debug('Entering firstApplicable().');
  const results = [];
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.NOT_APPLICABLE) {
      continue;
    }
    if (model.isIndeterminate(decision)) {
      log.debug('Leaving firstApplicable(). Indeterminate at ' + i + '.');
      return { decision: DECISION.INDETERMINATE, results: results };
    }
    log.debug('Leaving firstApplicable(). ' + decision + ' at ' + i + '.');
    return { decision: decision, results: results };
  }
  log.debug('Leaving firstApplicable(). NotApplicable.');
  return { decision: DECISION.NOT_APPLICABLE, results: results };
});

// --- the legacy 1.0 overrides algorithms ------------------------------------
// GENUINELY DIFFERENT FUNCTIONS rather than aliases of the 3.0 ones, and the
// rule and policy versions of each differ from EACH OTHER too — the policy
// version of legacy deny-overrides returns DENY where an error occurred and the
// rule version returns Indeterminate. Both spellings appear in the wild.
combiner([model.RULE_ALG.LEGACY_DENY_OVERRIDES,
          model.RULE_ALG.LEGACY_ORDERED_DENY_OVERRIDES],
         function (children, evaluateChild) {
  const results = [];
  let error = false;
  let potentialDeny = false;
  let permit = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.DENY) {
      return { decision: DECISION.DENY, results: results };
    }
    if (decision === DECISION.PERMIT) {
      permit = true;
    } else if (model.isIndeterminate(decision)) {
      error = true;
      // The extended value already records which way the rule could have gone,
      // which is exactly what the 2.0 pseudocode reads `effect(rule)` for — so
      // no rule needs to be carried alongside the result.
      if (decision === DECISION.INDETERMINATE_D ||
          decision === DECISION.INDETERMINATE_DP) {
        potentialDeny = true;
      }
    }
  }
  let decision;
  if (potentialDeny) {
    decision = DECISION.INDETERMINATE;
  } else if (permit) {
    decision = DECISION.PERMIT;
  } else if (error) {
    decision = DECISION.INDETERMINATE;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  return { decision: decision, results: results };
});

combiner([model.RULE_ALG.LEGACY_PERMIT_OVERRIDES,
          model.RULE_ALG.LEGACY_ORDERED_PERMIT_OVERRIDES],
         function (children, evaluateChild) {
  const results = [];
  let error = false;
  let potentialPermit = false;
  let deny = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.PERMIT) {
      return { decision: DECISION.PERMIT, results: results };
    }
    if (decision === DECISION.DENY) {
      deny = true;
    } else if (model.isIndeterminate(decision)) {
      error = true;
      if (decision === DECISION.INDETERMINATE_P ||
          decision === DECISION.INDETERMINATE_DP) {
        potentialPermit = true;
      }
    }
  }
  let decision;
  if (potentialPermit) {
    decision = DECISION.INDETERMINATE;
  } else if (deny) {
    decision = DECISION.DENY;
  } else if (error) {
    decision = DECISION.INDETERMINATE;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  return { decision: decision, results: results };
});

combiner([model.POLICY_ALG.LEGACY_DENY_OVERRIDES,
          model.POLICY_ALG.LEGACY_ORDERED_DENY_OVERRIDES],
         function (children, evaluateChild) {
  const results = [];
  let error = false;
  let permit = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.DENY) {
      return { decision: DECISION.DENY, results: results };
    }
    if (decision === DECISION.PERMIT) {
      permit = true;
    } else if (model.isIndeterminate(decision)) {
      error = true;
    }
  }
  // DENY, not Indeterminate — the policy version differs from the rule version
  // here and this is the whole of the difference.
  let decision;
  if (error) {
    decision = DECISION.DENY;
  } else if (permit) {
    decision = DECISION.PERMIT;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  return { decision: decision, results: results };
});

combiner([model.POLICY_ALG.LEGACY_PERMIT_OVERRIDES,
          model.POLICY_ALG.LEGACY_ORDERED_PERMIT_OVERRIDES],
         function (children, evaluateChild) {
  const results = [];
  let error = false;
  let deny = false;
  for (let i = 0; i < children.length; i += 1) {
    const result = evaluateChild(i);
    results.push(result);
    const decision = result.decision;
    if (decision === DECISION.PERMIT) {
      return { decision: DECISION.PERMIT, results: results };
    }
    if (decision === DECISION.DENY) {
      deny = true;
    } else if (model.isIndeterminate(decision)) {
      error = true;
    }
  }
  let decision;
  if (error) {
    decision = DECISION.PERMIT;
  } else if (deny) {
    decision = DECISION.DENY;
  } else {
    decision = DECISION.NOT_APPLICABLE;
  }
  return { decision: decision, results: results };
});

// `only-one-applicable` is the one algorithm that cannot be written this way at
// all: it has to know which children are APPLICABLE before evaluating any of
// them, because "more than one applies" is itself the error it reports and
// finding that out by evaluating would already have run the policies it is
// about to say should not both have run. It lives in `evaluatePolicySet()`;
// this entry exists so that `lookupCombiner()` reports it as known.
combiner([model.POLICY_ALG.ONLY_ONE_APPLICABLE], function () {
  throw model.processingError(
    'only-one-applicable is evaluated in evaluatePolicySet(), not through ' +
    'the ordinary combiner path. Reaching here is a bug in this file.');
});

/**
 * Returns the combining algorithm registered for an identifier.
 *
 * @param uri - the rule- or policy-combining algorithm identifier
 * @returns the combiner, or null when the identifier is unknown
 */
function lookupCombiner(uri) {
  log.debug("Entering lookupCombiner().");
  log.debug("Leaving lookupCombiner().");
  return COMBINERS[uri] || null;
}

// ---------------------------------------------------------------------------
// POLICY AND POLICY SET EVALUATION. Sections 7.12 and 7.13.
// ---------------------------------------------------------------------------
/**
 * Evaluates one Policy (section 7.12).
 *
 * An unknown rule-combining algorithm is an Indeterminate with a
 * syntax-error status. Obligations and advice are attached from the rules'
 * results, and an applicable policy is recorded on the context.
 * @param policy - the Policy
 * @param context - the evaluation context from `makeContext()`
 * @returns an object with `decision`, `status` and any obligations and
 *   advice
 */
function evaluatePolicy(policy, context) {
  log.debug('Entering evaluatePolicy(). id=' + policy.id);
  const variables = makeVariables(policy.variables);
  const combine = lookupCombiner(policy.combiningAlgId);
  if (!combine) {
    log.debug('Leaving evaluatePolicy(). Unknown combining algorithm.');
    return { decision: DECISION.INDETERMINATE_DP,
             status: { code: model.STATUS.SYNTAX_ERROR,
                       message: 'Unknown rule-combining algorithm "' +
                                policy.combiningAlgId + '".' } };
  }
  let targetResult;
  try {
    targetResult = evaluateTarget(policy.target, context, variables);
  } catch (error) {
    log.debug('Leaving evaluatePolicy(). Target threw.');
    return withStatus(DECISION.INDETERMINATE_DP, error);
  }
  if (targetResult === MATCH.NO_MATCH) {
    log.debug('Leaving evaluatePolicy(). Target did not match.');
    return { decision: DECISION.NOT_APPLICABLE };
  }
  if (targetResult === MATCH.INDETERMINATE) {
    log.debug('Leaving evaluatePolicy(). Target was Indeterminate.');
    return withStatus(DECISION.INDETERMINATE_DP,
                      policy.target ? lastTargetError(policy.target) : null);
  }
  const combination = combine(policy.rules, function (index) {
    return evaluateRule(policy.rules[index], context, variables);
  });
  const decision = combination.decision;
  const combined = { decision: decision,
                     status: firstStatus(combination.results) };
  attachObligations(combined, policy, combination.results, context,
                    variables);
  if (decision !== DECISION.NOT_APPLICABLE) {
    context.applicablePolicies.push({ kind: 'Policy', id: policy.id,
                                      version: policy.version });
  }
  log.debug('Leaving evaluatePolicy(). ' + decision + '.');
  return combined;
}

/**
 * Evaluates one PolicySet (section 7.13), including only-one-applicable.
 *
 * Policy and policy set references are resolved through the repository.
 * @param policySet - the PolicySet
 * @param context - the evaluation context from `makeContext()`
 * @param repository - resolves references to other policies, or null
 * @returns an object with `decision`, `status` and any obligations and
 *   advice
 */
function evaluatePolicySet(policySet, context, repository) {
  log.debug('Entering evaluatePolicySet(). id=' + policySet.id);
  let targetResult;
  try {
    targetResult = evaluateTarget(policySet.target, context, null);
  } catch (error) {
    log.debug('Leaving evaluatePolicySet(). Target threw.');
    return withStatus(DECISION.INDETERMINATE_DP, error);
  }
  if (targetResult === MATCH.NO_MATCH) {
    log.debug('Leaving evaluatePolicySet(). Target did not match.');
    return { decision: DECISION.NOT_APPLICABLE };
  }
  if (targetResult === MATCH.INDETERMINATE) {
    log.debug('Leaving evaluatePolicySet(). Target was Indeterminate.');
    return withStatus(DECISION.INDETERMINATE_DP,
                      policySet.target ? lastTargetError(policySet.target)
                                       : null);
  }
  const children = policySet.children.map(function (child) {
    return resolveChild(child, repository);
  });
  // only-one-applicable produces a combination in the SAME shape a combiner
  // does — a decision and the results actually produced — precisely so that it
  // falls through to the same `attachObligations()` call below. Returning
  // early here is what made cases IIIA025 and IIIA026 drop the POLICY SET's own
  // obligations while keeping the selected policy's, which is a Response that
  // is right about the decision and short by half on what the PEP must do.
  const onlyOne = policySet.combiningAlgId ===
                  model.POLICY_ALG.ONLY_ONE_APPLICABLE;
  const combine = onlyOne
    ? function (nodes, evaluateChild) {
        return evaluateOnlyOneApplicable(nodes, context, repository,
                                         evaluateChild);
      }
    : lookupCombiner(policySet.combiningAlgId);
  if (!combine) {
    log.debug('Leaving evaluatePolicySet(). Unknown combining algorithm.');
    return { decision: DECISION.INDETERMINATE_DP,
             status: { code: model.STATUS.SYNTAX_ERROR,
                       message: 'Unknown policy-combining algorithm "' +
                                policySet.combiningAlgId + '".' } };
  }
  const combination = combine(children, function (index) {
    return evaluateNode(children[index], context, repository);
  });
  const decision = combination.decision;
  const combined = { decision: decision,
                     status: firstStatus(combination.results) };
  attachObligations(combined, policySet, combination.results, context, null);
  if (decision !== DECISION.NOT_APPLICABLE) {
    context.applicablePolicies.push({ kind: 'PolicySet', id: policySet.id,
                                      version: policySet.version });
  }
  log.debug('Leaving evaluatePolicySet(). ' + decision + '.');
  return combined;
}

// ---------------------------------------------------------------------------
// only-one-applicable (C.9). The one algorithm that needs to know which
// children are APPLICABLE before evaluating any of them — because "more than
// one applies" is itself the error it reports, and finding that out by
// evaluating them would already have run policies it is about to say should
// not both have run.
// ---------------------------------------------------------------------------
function evaluateOnlyOneApplicable(children, context, repository,
                                   evaluateChild) {
  log.debug('Entering evaluateOnlyOneApplicable().');
  let selected = -1;
  for (let i = 0; i < children.length; i += 1) {
    let applicable;
    try {
      applicable = evaluateTarget(children[i].target, context, null);
    } catch (error) {
      log.debug('Leaving evaluateOnlyOneApplicable(). A target threw.');
      return { decision: DECISION.INDETERMINATE_DP, results: [],
               status: { code: error.xacmlStatus, message: error.message } };
    }
    if (applicable === MATCH.INDETERMINATE) {
      log.debug('Leaving evaluateOnlyOneApplicable(). A target was ' +
                'Indeterminate.');
      return { decision: DECISION.INDETERMINATE_DP, results: [] };
    }
    if (applicable === MATCH.MATCH) {
      if (selected >= 0) {
        log.debug('Leaving evaluateOnlyOneApplicable(). Two applied.');
        return { decision: DECISION.INDETERMINATE_DP, results: [],
                 status: { code: model.STATUS.PROCESSING_ERROR,
                           message: 'More than one policy in an ' +
                                    'only-one-applicable set is applicable.' }
               };
      }
      selected = i;
    }
  }
  if (selected < 0) {
    log.debug('Leaving evaluateOnlyOneApplicable(). None applied.');
    return { decision: DECISION.NOT_APPLICABLE, results: [] };
  }
  const result = evaluateChild(selected);
  log.debug('Leaving evaluateOnlyOneApplicable(). Evaluated the one.');
  return { decision: result.decision, results: [result] };
}

function evaluateNode(node, context, repository) {
  log.debug("Entering evaluateNode().");
  if (node.kind === 'Policy') {
    log.debug("Leaving evaluateNode().");
    return evaluatePolicy(node, context);
  }
  if (node.kind === 'PolicySet') {
    log.debug("Leaving evaluateNode().");
    return evaluatePolicySet(node, context, repository);
  }
  log.debug("Leaving evaluateNode().");
  return { decision: DECISION.INDETERMINATE_DP,
           status: { code: model.STATUS.SYNTAX_ERROR,
                     message: 'Cannot evaluate a node of kind "' +
                              node.kind + '".' } };
}

// ---------------------------------------------------------------------------
// POLICY REFERENCES.
//
// A `PolicyIdReference` names a document the PDP has to find somewhere else —
// which is what a Policy Retrieval Point is, and here it is a plain map handed
// in by the caller. An unresolvable reference is Indeterminate rather than
// skipped: a policy set that quietly ignored a reference it could not find
// would evaluate a SUBSET of the policy somebody wrote and report no problem.
// ---------------------------------------------------------------------------
function resolveChild(child, repository) {
  log.debug("Entering resolveChild().");
  if (child.kind !== 'PolicyIdReference' &&
      child.kind !== 'PolicySetIdReference') {
    log.debug("Leaving resolveChild().");
    return child;
  }
  const found = repository ? repository[child.ref] : null;
  if (!found) {
    log.debug("Leaving resolveChild().");
    return { kind: 'UnresolvedReference', ref: child.ref, target: null };
  }
  log.debug("Leaving resolveChild().");
  return found;
}

// ---------------------------------------------------------------------------
// OBLIGATIONS AND ADVICE. Section 7.18.
//
// Two rules, and the second is defect 4 in the header:
//   * an expression fires only when its FulfillOn / AppliesTo equals the
//     decision;
//   * nothing is collected at all unless the decision is Permit or Deny.
// ---------------------------------------------------------------------------
function attachObligations(combined, node, childResults, context, variables) {
  log.debug('Entering attachObligations().');
  if (combined.decision !== DECISION.PERMIT &&
      combined.decision !== DECISION.DENY) {
    log.debug('Leaving attachObligations(). Not a Permit or a Deny.');
    return;
  }
  const obligations = [];
  const advice = [];
  // From the children first, so that the order a PEP sees is inner-to-outer,
  // which is the order they were decided in.
  childResults.forEach(function (result) {
    if (result.decision !== combined.decision) {
      return;
    }
    (result.obligationsResolved || []).forEach(function (item) {
      obligations.push(item);
    });
    (result.adviceResolved || []).forEach(function (item) {
      advice.push(item);
    });
  });
  collect(node.obligations, combined.decision, context, variables)
    .forEach(function (item) {
      obligations.push(item);
    });
  collect(node.advice, combined.decision, context, variables)
    .forEach(function (item) {
      advice.push(item);
    });
  combined.obligationsResolved = obligations;
  combined.adviceResolved = advice;
  log.debug('Leaving attachObligations(). ' + obligations.length +
            ' obligation(s), ' + advice.length + ' advice.');
}

function collect(expressions, decision, context, variables) {
  log.debug("Entering collect().");
  const resolved = [];
  (expressions || []).forEach(function (expression) {
    if (expression.on !== decision) {
      return;
    }
    const assignments = [];
    expression.assignments.forEach(function (assignment) {
      const bag = evaluateExpression(assignment.expression, context,
                                     variables);
      bag.values.forEach(function (value) {
        assignments.push({ attributeId: assignment.attributeId,
                           category: assignment.category,
                           issuer: assignment.issuer,
                           type: bag.type,
                           value: value,
                           lexical: datatypes.writeValue(bag.type, value) });
      });
    });
    resolved.push({ id: expression.id, assignments: assignments });
  });
  log.debug("Leaving collect().");
  return resolved;
}

// The status of the first child that had one, so that an Indeterminate at the
// top says WHY rather than merely that something went wrong somewhere below.
function firstStatus(results) {
  log.debug("Entering firstStatus().");
  for (let i = 0; i < results.length; i += 1) {
    if (results[i].status) {
      log.debug("Leaving firstStatus().");
      return results[i].status;
    }
  }
  log.debug("Leaving firstStatus().");
  return null;
}

// ---------------------------------------------------------------------------
// THE ENTRY POINT.
//
// `externalDecision()` is called HERE and nowhere else — the one place the
// extended Indeterminate values are folded back to the four a caller sees.
// ---------------------------------------------------------------------------
/**
 * Evaluates a request against a policy or policy set and returns the
 * decision a caller sees.
 *
 * This is the one place the extended Indeterminate values are folded into
 * the four external decisions. An error escaping the evaluation becomes
 * an Indeterminate with its message rather than a throw.
 * @param policy - the root Policy or PolicySet
 * @param request - the request
 * @param options - optional; `resolver`, `now` and `repository`
 * @returns the response: `decision`, `status`, `obligations`, `advice`
 *   and `policyIdentifiers`
 */
function evaluate(policy, request, options) {
  log.debug('Entering evaluate().');
  const settings = options || {};
  const context = makeContext(request, settings);
  let result;
  try {
    result = evaluateNode(policy, context, settings.repository || null);
  } catch (error) {
    // A throw that escapes the tree is a bug in this file rather than a
    // decision, and it is reported as an Indeterminate carrying the message
    // instead of taking the caller down — a PDP that crashes is a PDP that
    // fails open somewhere upstream.
    log.debug('Leaving evaluate(). An error escaped the evaluation.');
    result = { decision: DECISION.INDETERMINATE,
               status: { code: error.xacmlStatus ||
                               model.STATUS.PROCESSING_ERROR,
                         message: error.message } };
  }
  const response = {
    decision: model.externalDecision(result.decision),
    status: result.status || { code: model.STATUS.OK },
    obligations: result.obligationsResolved || [],
    advice: result.adviceResolved || [],
    policyIdentifiers: request.returnPolicyIdList
      ? context.applicablePolicies : []
  };
  log.debug('Leaving evaluate(). ' + response.decision + '.');
  return response;
}

/**
 * The XACML 3.0 policy decision point: a request and a policy in, a
 * decision out.
 *
 * It knows nothing of XML, JSON, ALFA, HTTP or the directory; the only
 * thing it reaches outside itself for is an attribute, through the
 * context's resolver.
 * @namespace
 */
module.exports = {
  evaluate: evaluate,
  evaluatePolicy: evaluatePolicy,
  evaluatePolicySet: evaluatePolicySet,
  evaluateRule: evaluateRule,
  evaluateTarget: evaluateTarget,
  evaluateExpression: evaluateExpression,
  makeContext: makeContext,
  makeVariables: makeVariables,
  resolveDesignator: resolveDesignator,
  lookupCombiner: lookupCombiner,
  COMBINERS: COMBINERS
};
