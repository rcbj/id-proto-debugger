// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_model.js
//
// ---------------------------------------------------------------------------
// THE POLICY MODEL, AND THE ONE THING EVERY OTHER FILE IN THIS DIRECTORY
// AGREES ABOUT.
//
// XACML has three surface syntaxes here — the core XML of the specification,
// the JSON Profile's request and response, and ALFA — and this file is what
// all three are renderings OF. Nothing in here parses or serializes anything.
// It is the vocabulary: the identifiers the specification fixes, the shape of
// a policy tree, and the decision values a PDP is allowed to produce.
//
// THE RULE THIS DIRECTORY IS BUILT ON, and it is the same argument
// `common/crypto_impl/xmldsig.js` makes about canonicalization one layer down: a
// GRAMMAR IS A READING, and three readings of XACML would be three chances to
// disagree with the PDP at the far end. So there is one model. `xacml_xml.js`
// reads XML into it, `xacml_json.js` reads and writes the JSON Profile,
// `xacml_alfa.js` reads and writes ALFA, and `xacml_pdp.js` evaluates it —
// and NONE of them may branch on which syntax a policy arrived in. If a
// function in `xacml_pdp.js` ever asks whether it is looking at something that
// came from XML, this separation has failed and the fix is here rather than
// there.
//
// ---------------------------------------------------------------------------
// THE FOUR DECISIONS ARE SEVEN, AND THAT IS THE SINGLE MOST IMPORTANT THING ON
// THIS PAGE.
//
// A XACML 2.0 PDP returned one of four values. XACML 3.0 splits one of them,
// and an implementation that does not is subtly wrong in a way that passes
// almost every test somebody writes by hand:
//
//   Permit           the rule applies and its Effect is Permit
//   Deny             the rule applies and its Effect is Deny
//   NotApplicable    nothing applied
//   Indeterminate    something went wrong — and 3.0 asks WHICH WAY it could
//                    have gone if it had not:
//
//     Indeterminate{P}    could only have been Permit
//     Indeterminate{D}    could only have been Deny
//     Indeterminate{DP}   could have been either
//
// The three exist for the combining algorithms and for nothing else. A
// `deny-overrides` combination that meets an `Indeterminate{D}` has met
// something that MIGHT have been a Deny, and the whole point of
// deny-overrides is that a possible Deny outranks an actual Permit. Collapse
// the three back into one `Indeterminate` and that algorithm silently returns
// Permit where the specification says Deny — which is a policy that permits
// something because an attribute lookup failed, reported to nobody. This is
// the defect the conformance suite's IID cases exist to catch, and it is why
// the values below are seven constants rather than four.
//
// A PDP's EXTERNAL answer is still one of four: `externalDecision()` folds the
// three back down at the very edge, once, on the way into a Response. Inside
// the tree they never collapse.
//
// ---------------------------------------------------------------------------
// EVERY IDENTIFIER HERE IS A STRING FROM THE SPECIFICATION AND IS SPELT OUT.
//
// No identifier in this file is built by concatenation, and that is a decision
// rather than verbosity. XACML's URIs are nearly-identical long strings that
// differ in one segment — `urn:oasis:names:tc:xacml:1.0:function:string-equal`
// against `urn:oasis:names:tc:xacml:3.0:function:string-equal`, which is not
// the same function and does not exist — and a table built by joining a
// version onto a name produces a URI that looks right in the source, matches
// nothing at evaluation time, and fails as `NotApplicable` rather than as an
// error. Written out, a wrong one is visible in a diff.
//
// The version segments really are inconsistent, and the inconsistency is the
// specification's rather than a mistake here: most functions are `1.0`, the
// set of them added in 2.0 and 3.0 carry those, and the categories moved from
// `1.0:subject-category` to `3.0:attribute-category` for everything but the
// subject. Do not "tidy" them.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');

// ---------------------------------------------------------------------------
// DECISIONS.
// ---------------------------------------------------------------------------
/**
 * The seven XACML 3.0 decision values, the three extended Indeterminates
 * spelt with the braces the specification uses.
 */
const DECISION = {
  PERMIT: 'Permit',
  DENY: 'Deny',
  NOT_APPLICABLE: 'NotApplicable',
  INDETERMINATE: 'Indeterminate',
  // The extended three. Their names carry the braces the specification writes
  // them with, so that a decision printed in a log or a test failure is the
  // string the specification uses rather than a private spelling somebody has
  // to translate.
  INDETERMINATE_P: 'Indeterminate{P}',
  INDETERMINATE_D: 'Indeterminate{D}',
  INDETERMINATE_DP: 'Indeterminate{DP}'
};

// The four a caller outside the PDP is ever shown.
/**
 * The four decisions a caller outside the PDP is ever shown.
 */
const EXTERNAL_DECISIONS = [DECISION.PERMIT, DECISION.DENY,
                            DECISION.NOT_APPLICABLE, DECISION.INDETERMINATE];

// ---------------------------------------------------------------------------
// EFFECTS. A Rule has one; an ObligationExpression fires on one.
// ---------------------------------------------------------------------------
/**
 * The two Rule effects, Permit and Deny.
 */
const EFFECT = { PERMIT: 'Permit', DENY: 'Deny' };

// ---------------------------------------------------------------------------
// TARGET MATCH RESULTS. Not decisions — a Target does not decide anything, it
// says whether the thing under it is even in scope. Three values, because a
// Target whose attribute lookup failed is neither a match nor a miss.
// ---------------------------------------------------------------------------
/**
 * The three Target match results: Match, No-match and Indeterminate.
 */
const MATCH = {
  MATCH: 'Match',
  NO_MATCH: 'No-match',
  INDETERMINATE: 'Indeterminate'
};

// ---------------------------------------------------------------------------
// STATUS CODES (XACML 3.0 section 5.57). Three, and each says something
// different about WHY there is no decision — which is the half of an
// Indeterminate that makes it debuggable.
// ---------------------------------------------------------------------------
/**
 * The XACML status code URIs: ok, missing-attribute, syntax-error and
 * processing-error.
 */
const STATUS = {
  OK: 'urn:oasis:names:tc:xacml:1.0:status:ok',
  MISSING_ATTRIBUTE: 'urn:oasis:names:tc:xacml:1.0:status:missing-attribute',
  SYNTAX_ERROR: 'urn:oasis:names:tc:xacml:1.0:status:syntax-error',
  PROCESSING_ERROR: 'urn:oasis:names:tc:xacml:1.0:status:processing-error'
};

// ---------------------------------------------------------------------------
// THE STANDARD ATTRIBUTE CATEGORIES.
//
// Note the version segments, which are the specification's own inconsistency
// and catch everybody once: the access-subject category kept its `1.0`
// `subject-category` prefix, and resource, action and environment moved to
// `3.0:attribute-category`. A table that spelt all four the same way would
// match the subject and silently fail to match the other three.
// ---------------------------------------------------------------------------
/**
 * The standard attribute category URIs, with the specification's own
 * mixture of 1.0 subject-category and 3.0 attribute-category prefixes.
 */
const CATEGORY = {
  ACCESS_SUBJECT:
    'urn:oasis:names:tc:xacml:1.0:subject-category:access-subject',
  RECIPIENT_SUBJECT:
    'urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject',
  INTERMEDIARY_SUBJECT:
    'urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject',
  CODEBASE: 'urn:oasis:names:tc:xacml:1.0:subject-category:codebase',
  REQUESTING_MACHINE:
    'urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine',
  RESOURCE: 'urn:oasis:names:tc:xacml:3.0:attribute-category:resource',
  ACTION: 'urn:oasis:names:tc:xacml:3.0:attribute-category:action',
  ENVIRONMENT: 'urn:oasis:names:tc:xacml:3.0:attribute-category:environment'
};

// ---------------------------------------------------------------------------
// THE STANDARD ATTRIBUTE IDENTIFIERS THIS IMPLEMENTATION KNOWS BY NAME.
//
// Only the ones something here actually reaches for. `current-time`,
// `current-date` and `current-dateTime` are the three the PDP must be able to
// SUPPLY when a request does not carry them (section 10.2.5), which is what
// makes them different from every other identifier in a policy.
// ---------------------------------------------------------------------------
/**
 * The standard attribute identifiers this implementation reaches for by
 * name, including the three current-time values the PDP must supply.
 */
const ATTRIBUTE = {
  SUBJECT_ID: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
  RESOURCE_ID: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id',
  ACTION_ID: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
  CURRENT_TIME: 'urn:oasis:names:tc:xacml:1.0:environment:current-time',
  CURRENT_DATE: 'urn:oasis:names:tc:xacml:1.0:environment:current-date',
  CURRENT_DATETIME:
    'urn:oasis:names:tc:xacml:1.0:environment:current-dateTime'
};

// ---------------------------------------------------------------------------
// DATATYPES.
//
// Seventeen, and the split between them is worth knowing: twelve are XML
// Schema types (so their lexical space is somebody else's specification and
// this implementation must not invent one), and five are XACML's own —
// rfc822Name, x500Name, dnsName, ipAddress and xpathExpression. The five are
// where the interesting comparison rules live, because "equal" for an email
// address is not string equality: the domain is case-insensitive and the
// local part is not.
// ---------------------------------------------------------------------------
/**
 * The seventeen datatype URIs: twelve XML Schema types and XACML's own five.
 */
const TYPE = {
  STRING: 'http://www.w3.org/2001/XMLSchema#string',
  BOOLEAN: 'http://www.w3.org/2001/XMLSchema#boolean',
  INTEGER: 'http://www.w3.org/2001/XMLSchema#integer',
  DOUBLE: 'http://www.w3.org/2001/XMLSchema#double',
  TIME: 'http://www.w3.org/2001/XMLSchema#time',
  DATE: 'http://www.w3.org/2001/XMLSchema#date',
  DATETIME: 'http://www.w3.org/2001/XMLSchema#dateTime',
  DAYTIME_DURATION:
    'http://www.w3.org/2001/XMLSchema#dayTimeDuration',
  YEARMONTH_DURATION:
    'http://www.w3.org/2001/XMLSchema#yearMonthDuration',
  ANYURI: 'http://www.w3.org/2001/XMLSchema#anyURI',
  HEXBINARY: 'http://www.w3.org/2001/XMLSchema#hexBinary',
  BASE64BINARY: 'http://www.w3.org/2001/XMLSchema#base64Binary',
  RFC822NAME: 'urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name',
  X500NAME: 'urn:oasis:names:tc:xacml:1.0:data-type:x500Name',
  DNSNAME: 'urn:oasis:names:tc:xacml:2.0:data-type:dnsName',
  IPADDRESS: 'urn:oasis:names:tc:xacml:2.0:data-type:ipAddress',
  XPATH_EXPRESSION: 'urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression'
};

// XACML 3.0 moved the two duration types out of the 2005 XQuery namespace and
// into XML Schema's. Documents in the wild — and several cases in the vendored
// conformance suite — still carry the old spelling, so both are accepted on
// the way IN and only the new one is ever written OUT. Being liberal here
// costs nothing and rejecting them would fail cases over a namespace rather
// than over a decision.
/**
 * The pre-3.0 XQuery spellings of the two duration types, mapped to the XML
 * Schema URIs; accepted on the way in, never written out.
 */
const LEGACY_TYPE_ALIASES = {
  'http://www.w3.org/TR/2002/WD-xquery-operators-20020816#dayTimeDuration':
    TYPE.DAYTIME_DURATION,
  'http://www.w3.org/TR/2002/WD-xquery-operators-20020816#yearMonthDuration':
    TYPE.YEARMONTH_DURATION
};

// ---------------------------------------------------------------------------
// THE COMBINING ALGORITHMS.
//
// Twelve identifiers and only ten distinct behaviours, because `deny-overrides`
// and `ordered-deny-overrides` differ solely in whether the children may be
// evaluated out of order — and since this implementation evaluates them in
// document order always, the ordered pair is the unordered one under another
// name. That is CONFORMANT rather than a shortcut: the specification permits
// an implementation to reorder for the unordered variants, it does not require
// it, and doing so would buy nothing here and cost reproducibility in a mock
// whose whole job is to be inspected.
//
// The `2.0` versions of deny-overrides and permit-overrides are the LEGACY
// ones and are genuinely different functions rather than aliases — they were
// defined before extended Indeterminate existed and treat it as a plain
// Indeterminate. Both spellings appear in the conformance suite.
// ---------------------------------------------------------------------------
/**
 * The rule-combining algorithm identifiers, the 3.0 ones and the legacy 1.0
 * and 1.1 ones.
 */
const RULE_ALG = {
  DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides',
  PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides',
  ORDERED_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:' +
    'ordered-deny-overrides',
  ORDERED_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:' +
    'ordered-permit-overrides',
  DENY_UNLESS_PERMIT:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:' +
    'deny-unless-permit',
  PERMIT_UNLESS_DENY:
    'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:' +
    'permit-unless-deny',
  FIRST_APPLICABLE:
    'urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable',
  LEGACY_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides',
  LEGACY_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides',
  LEGACY_ORDERED_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:' +
    'ordered-deny-overrides',
  LEGACY_ORDERED_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:' +
    'ordered-permit-overrides'
};

/**
 * The policy-combining algorithm identifiers, the 3.0 ones and the legacy
 * 1.0 and 1.1 ones, with only-one-applicable.
 */
const POLICY_ALG = {
  DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides',
  PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides',
  ORDERED_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:' +
    'ordered-deny-overrides',
  ORDERED_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:' +
    'ordered-permit-overrides',
  DENY_UNLESS_PERMIT:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:' +
    'deny-unless-permit',
  PERMIT_UNLESS_DENY:
    'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:' +
    'permit-unless-deny',
  FIRST_APPLICABLE:
    'urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable',
  ONLY_ONE_APPLICABLE:
    'urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:' +
    'only-one-applicable',
  LEGACY_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides',
  LEGACY_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides',
  LEGACY_ORDERED_DENY_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:' +
    'ordered-deny-overrides',
  LEGACY_ORDERED_PERMIT_OVERRIDES:
    'urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:' +
    'ordered-permit-overrides'
};

// The XACML 3.0 core XML namespace. The `wd-17` in it is not a typo and is not
// a working draft left behind by accident: the OASIS standard shipped with
// that namespace and every conforming document carries it. Changing it to
// something that reads more like a released specification would make this
// implementation reject every real policy in existence.
/**
 * The XACML 3.0 core XML namespace, `wd-17` being the standard's own.
 */
const NS_XACML = 'urn:oasis:names:tc:xacml:3.0:core:schema:wd-17';

// ---------------------------------------------------------------------------
// FOLD AN EXTENDED INDETERMINATE DOWN TO WHAT A CALLER OUTSIDE THE PDP SEES.
//
// Called ONCE, at the edge, on the way into a Response. Calling it anywhere
// inside the evaluation is the defect the header warns about, so it is a named
// function rather than an inline `.replace()` — a grep for it should find one
// call site in `xacml_pdp.js` and nothing else.
// ---------------------------------------------------------------------------
/**
 * Folds an extended Indeterminate down to the plain Indeterminate a
 * Response carries; every other decision is returned unchanged.
 *
 * Called once, at the edge of the PDP, never inside the evaluation.
 * @param decision - a decision value from `DECISION`
 * @returns one of the four `EXTERNAL_DECISIONS`
 */
function externalDecision(decision) {
  log.debug('Entering externalDecision(). decision=' + decision);
  if (decision === DECISION.INDETERMINATE_P ||
      decision === DECISION.INDETERMINATE_D ||
      decision === DECISION.INDETERMINATE_DP) {
    log.debug('Leaving externalDecision(). Folded to Indeterminate.');
    return DECISION.INDETERMINATE;
  }
  log.debug('Leaving externalDecision(). Unchanged.');
  return decision;
}

/**
 * Tells whether a decision is any of the four Indeterminate values.
 * @param decision - a decision value from `DECISION`
 * @returns true for Indeterminate and its three extended forms
 */
function isIndeterminate(decision) {
  log.debug("Entering isIndeterminate().");
  log.debug("Leaving isIndeterminate().");
  return decision === DECISION.INDETERMINATE ||
         decision === DECISION.INDETERMINATE_P ||
         decision === DECISION.INDETERMINATE_D ||
         decision === DECISION.INDETERMINATE_DP;
}

// ---------------------------------------------------------------------------
// THE INDETERMINATE A RULE PRODUCES WHEN ITS OWN EVALUATION FAILS.
//
// Section 7.11: a Rule that cannot be evaluated is Indeterminate in the
// direction of its OWN Effect, because that is the only decision it could ever
// have produced. This is the whole reason the extended values exist, and it is
// one line — which is exactly why it is easy to leave out and hard to notice
// missing.
// ---------------------------------------------------------------------------
/**
 * Returns the Indeterminate in the direction of a Rule's own Effect
 * (section 7.11): Indeterminate{P} for Permit, Indeterminate{D} otherwise.
 * @param effect - the Rule's Effect, a value from `EFFECT`
 * @returns `DECISION.INDETERMINATE_P` or `DECISION.INDETERMINATE_D`
 */
function indeterminateOfEffect(effect) {
  log.debug('Entering indeterminateOfEffect(). effect=' + effect);
  if (effect === EFFECT.PERMIT) {
    log.debug('Leaving indeterminateOfEffect(). Indeterminate{P}.');
    return DECISION.INDETERMINATE_P;
  }
  log.debug('Leaving indeterminateOfEffect(). Indeterminate{D}.');
  return DECISION.INDETERMINATE_D;
}

// ---------------------------------------------------------------------------
// A DATATYPE URI, WITH THE TWO LEGACY DURATION SPELLINGS ACCEPTED.
//
// One place, so that "we accept the old namespace" is a fact about this
// function rather than something scattered through the XML reader, the JSON
// reader and the function library — where three copies would be three chances
// for one of them to reject a document the other two accept.
// ---------------------------------------------------------------------------
/**
 * Returns a datatype URI with the two legacy duration spellings mapped to
 * their XML Schema URIs; any other URI is returned unchanged.
 * @param uri - a datatype URI
 * @returns the canonical datatype URI
 */
function canonicalType(uri) {
  log.debug('Entering canonicalType(). uri=' + uri);
  const alias = LEGACY_TYPE_ALIASES[uri];
  if (alias) {
    log.debug('Leaving canonicalType(). Legacy duration spelling mapped.');
    return alias;
  }
  log.debug('Leaving canonicalType(). Unchanged.');
  return uri;
}

// ---------------------------------------------------------------------------
// A BAG.
//
// EVERY value in XACML is a bag, and an implementation that forgets it is
// wrong in a way that looks like it works. `AttributeDesignator` returns a
// bag, `AttributeSelector` returns a bag, a function like `string-bag` builds
// one, and `string-one-and-only` exists precisely because most functions need
// exactly one value and the language has no way to promise that statically.
//
// A bag is UNORDERED and may hold duplicates, which is why this is a plain
// array behind a constructor rather than a Set: `bag-size` counts duplicates,
// and a Set would silently give a different answer for a conformance case that
// exists to check exactly that.
//
// An `AttributeValue` in a policy is a bag of one. Nothing in this
// implementation ever holds a bare value, so there is no code path where a
// caller has to remember to wrap one — which is the shape the mistake takes.
// ---------------------------------------------------------------------------
/**
 * Builds a bag: an unordered array of values of one datatype, duplicates
 * kept. Every value in this implementation is held in one.
 * @param type - the datatype URI, canonicalised by `canonicalType()`
 * @param values - the values; an empty bag when absent
 * @returns an object with `type` and `values`
 */
function bag(type, values) {
  log.debug("Entering bag().");
  log.debug("Leaving bag().");
  return { type: canonicalType(type), values: values || [] };
}

/**
 * Builds an empty bag of a datatype.
 * @param type - the datatype URI
 * @returns a bag with no values
 */
function emptyBag(type) {
  log.debug("Entering emptyBag().");
  log.debug("Leaving emptyBag().");
  return bag(type, []);
}

/**
 * Builds a bag of one value.
 * @param type - the datatype URI
 * @param value - the one value
 * @returns a bag holding `value`
 */
function singleton(type, value) {
  log.debug("Entering singleton().");
  log.debug("Leaving singleton().");
  return bag(type, [value]);
}

/**
 * Tells whether a bag is empty, treating a missing bag as empty.
 * @param candidate - a bag, or nothing
 * @returns true when there is no bag or it holds no values
 */
function isEmptyBag(candidate) {
  log.debug("Entering isEmptyBag().");
  log.debug("Leaving isEmptyBag().");
  return !candidate || !candidate.values || candidate.values.length === 0;
}

// ---------------------------------------------------------------------------
// THE ERROR EVERY FAILURE IN THIS DIRECTORY IS RAISED AS.
//
// It carries a STATUS CODE, because the difference between "the policy is
// malformed", "an attribute the policy required is not there" and "something
// else went wrong" is the entire content of an Indeterminate — and a plain
// `Error` would collapse all three into a message a Response cannot carry.
//
// `IndeterminateError` rather than `XacmlError` deliberately: it is thrown
// only where the answer becomes Indeterminate, so a `throw` of anything else
// in this directory is a bug in this directory rather than a decision.
// ---------------------------------------------------------------------------
/**
 * Builds the error every failure in this directory is raised as: an Error
 * named `IndeterminateError` carrying `xacmlStatus` and `xacmlDetail`.
 *
 * Thrown only where the answer becomes Indeterminate.
 * @param status - a `STATUS` URI; processing-error when absent
 * @param message - the error message
 * @param detail - an optional detail value, null when absent
 * @returns the error, to be thrown by the caller
 */
function IndeterminateError(status, message, detail) {
  log.debug("Entering IndeterminateError().");
  const error = /** @type {any} */ (new Error(message));
  error.name = 'IndeterminateError';
  error.xacmlStatus = status || STATUS.PROCESSING_ERROR;
  error.xacmlDetail = detail || null;
  log.debug("Leaving IndeterminateError().");
  return error;
}

/**
 * Builds an `IndeterminateError` with the missing-attribute status.
 * @param message - the error message
 * @param detail - an optional detail value
 * @returns the error, to be thrown by the caller
 */
function missingAttribute(message, detail) {
  log.debug("Entering missingAttribute().");
  log.debug("Leaving missingAttribute().");
  return IndeterminateError(STATUS.MISSING_ATTRIBUTE, message, detail);
}

/**
 * Builds an `IndeterminateError` with the syntax-error status.
 * @param message - the error message
 * @param detail - an optional detail value
 * @returns the error, to be thrown by the caller
 */
function syntaxError(message, detail) {
  log.debug("Entering syntaxError().");
  log.debug("Leaving syntaxError().");
  return IndeterminateError(STATUS.SYNTAX_ERROR, message, detail);
}

/**
 * Builds an `IndeterminateError` with the processing-error status.
 * @param message - the error message
 * @param detail - an optional detail value
 * @returns the error, to be thrown by the caller
 */
function processingError(message, detail) {
  log.debug("Entering processingError().");
  log.debug("Leaving processingError().");
  return IndeterminateError(STATUS.PROCESSING_ERROR, message, detail);
}

/**
 * The XACML 3.0 policy model: the vocabulary every syntax in this directory
 * reads into and the PDP evaluates.
 *
 * The identifiers the specification fixes, the seven decision values, bags
 * and the error an Indeterminate is raised as. Nothing here parses.
 * @namespace
 */
module.exports = {
  DECISION: DECISION,
  EXTERNAL_DECISIONS: EXTERNAL_DECISIONS,
  EFFECT: EFFECT,
  MATCH: MATCH,
  STATUS: STATUS,
  CATEGORY: CATEGORY,
  ATTRIBUTE: ATTRIBUTE,
  TYPE: TYPE,
  LEGACY_TYPE_ALIASES: LEGACY_TYPE_ALIASES,
  RULE_ALG: RULE_ALG,
  POLICY_ALG: POLICY_ALG,
  NS_XACML: NS_XACML,
  externalDecision: externalDecision,
  isIndeterminate: isIndeterminate,
  indeterminateOfEffect: indeterminateOfEffect,
  canonicalType: canonicalType,
  bag: bag,
  emptyBag: emptyBag,
  singleton: singleton,
  isEmptyBag: isEmptyBag,
  IndeterminateError: IndeterminateError,
  missingAttribute: missingAttribute,
  syntaxError: syntaxError,
  processingError: processingError
};
