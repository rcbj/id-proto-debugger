// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_xml.js
//
// ---------------------------------------------------------------------------
// XACML 3.0 CORE XML, READ INTO THE MODEL AND WRITTEN BACK OUT.
//
// One of three readers — the JSON Profile and ALFA are the others — and all
// three produce the SAME `xacml_model.js` shapes. Nothing downstream of this
// file knows a policy came from XML. See the header of `xacml_model.js` for
// why that is the rule this directory is built on.
//
// This file reads with `@xmldom/xmldom`, which the api and this service
// already depend on for SAML and WS-Federation, and it uses no XPath at all —
// the policy grammar is walked by element name, because an XPath per element
// would be slower and would hide what is actually a very small tree walk. (An
// `AttributeSelector` is read and carried, and the PDP refuses to evaluate
// one: `xacml/CLAUDE.md`, *What is not here yet*.)
//
// ---------------------------------------------------------------------------
// THE PARSER IS DELIBERATELY STRICT, AND SIX CONFORMANCE CASES DEPEND ON IT.
//
// Six cases in the vendored suite carry `Request.xml.ignore` and
// `Response.xml.ignore` — upstream renamed them so that no runner would
// evaluate them — because the POLICY in those cases is invalid and the whole
// assertion is that loading it FAILS. A permissive parser that shrugged at an
// unknown element or a missing attribute would load all six, produce a
// decision, and pass every one of them for the wrong reason.
//
// So an unrecognised element inside a construct this file understands is a
// SYNTAX ERROR rather than something skipped. The one deliberate looseness is
// the XML NAMESPACE: elements are matched on local name, because documents in
// the wild carry the 3.0 namespace, the 2.0 namespace and occasionally none,
// and rejecting a policy over its namespace declaration would fail cases about
// namespaces rather than about decisions. `xsi:schemaLocation` is ignored
// entirely — several cases in this suite carry one that points at the XACML
// 2.0 schema, which upstream's README lists as a defect in the original AT&T
// files.
//
// ---------------------------------------------------------------------------
// AN `AttributeValue` IS NOT PARSED HERE.
//
// It is carried as its LEXICAL FORM plus its declared datatype, and turned
// into a value by `xacml_datatypes.js` at evaluation time. That is not
// laziness — it is what keeps a bad lexical form an INDETERMINATE at
// evaluation rather than a load-time failure, which is the difference between
// a policy that refuses one request and a policy that will not load at all.
// The exception is `xpathExpression`, which has to capture the namespace
// bindings in scope AT THE POINT IT WAS WRITTEN, and those are gone once the
// element is out of the document.
// ---------------------------------------------------------------------------

const { DOMParser, XMLSerializer } = require('./xacml_xml_parser');
const { log, xmlEscape } = require('../xacml_runtime');
const ownMembers = require('./xacml_own_members');
const model = require('./xacml_model');
const validate = require('./xacml_validate');

// ---------------------------------------------------------------------------
// SMALL DOM HELPERS. All of them match on LOCAL NAME — see the header.
// ---------------------------------------------------------------------------

/**
 * Returns a node's local name, its namespace prefix removed.
 * @param node - a DOM node
 * @returns the local name, or '' for no node
 */
function localName(node) {
  log.debug("Entering localName().");
  if (!node) {
    log.debug("Leaving localName().");
    return '';
  }
  if (node.localName) {
    log.debug("Leaving localName().");
    return node.localName;
  }
  const name = node.nodeName || '';
  const colon = name.indexOf(':');
  log.debug("Leaving localName().");
  return colon < 0 ? name : name.slice(colon + 1);
}

/**
 * Returns a node's element children, skipping text and comments.
 * @param node - a DOM node
 * @returns the child elements, in document order
 */
function elementChildren(node) {
  log.debug("Entering elementChildren().");
  const result = [];
  if (!node || !node.childNodes) {
    log.debug("Leaving elementChildren().");
    return result;
  }
  for (let i = 0; i < node.childNodes.length; i += 1) {
    const child = node.childNodes[i];
    if (child.nodeType === 1) {
      result.push(child);
    }
  }
  log.debug("Leaving elementChildren().");
  return result;
}

/**
 * Returns a node's element children with a given local name.
 * @param node - a DOM node
 * @param name - the local name to match
 * @returns the matching child elements, in document order
 */
function childrenNamed(node, name) {
  log.debug("Entering childrenNamed().");
  log.debug("Leaving childrenNamed().");
  return elementChildren(node).filter(function (child) {
    return localName(child) === name;
  });
}

/**
 * Returns a node's first element child with a given local name.
 * @param node - a DOM node
 * @param name - the local name to match
 * @returns the first matching child element, or null
 */
function firstNamed(node, name) {
  log.debug("Entering firstNamed().");
  const found = childrenNamed(node, name);
  log.debug("Leaving firstNamed().");
  return found.length ? found[0] : null;
}

function attribute(node, name) {
  log.debug("Entering attribute().");
  if (!node || !node.getAttribute) {
    log.debug("Leaving attribute().");
    return null;
  }
  const value = node.getAttribute(name);
  log.debug("Leaving attribute().");
  return value === null || value === '' ? null : value;
}

function requiredAttribute(node, name) {
  log.debug("Entering requiredAttribute().");
  const value = attribute(node, name);
  if (value === null) {
    throw model.syntaxError(
      '<' + localName(node) + '> is missing the required "' + name +
      '" attribute.');
  }
  log.debug("Leaving requiredAttribute().");
  return value;
}

// The text of an element, children and all. `AttributeValue` may hold markup
// for a structured datatype, so this concatenates text nodes rather than
// insisting on a single one.
/**
 * Returns the concatenated text of an element and all its descendants.
 * @param node - a DOM element
 * @returns the text, '' for no node
 */
function textOf(node) {
  log.debug("Entering textOf().");
  let text = '';
  if (!node || !node.childNodes) {
    log.debug("Leaving textOf().");
    return text;
  }
  for (let i = 0; i < node.childNodes.length; i += 1) {
    const child = node.childNodes[i];
    if (child.nodeType === 3 || child.nodeType === 4) {
      text += child.nodeValue;
    } else if (child.nodeType === 1) {
      text += textOf(child);
    }
  }
  log.debug("Leaving textOf().");
  return text;
}

function booleanAttribute(node, name, fallback) {
  log.debug("Entering booleanAttribute().");
  const value = attribute(node, name);
  if (value === null) {
    log.debug("Leaving booleanAttribute().");
    return fallback;
  }
  log.debug("Leaving booleanAttribute().");
  return value === 'true' || value === '1';
}

// ---------------------------------------------------------------------------
// THE NAMESPACE BINDINGS IN SCOPE AT AN ELEMENT.
//
// Walked up the tree, because an `xpathExpression` written deep in a policy
// may use a prefix declared on the document element — and once the value is
// out of the document there is nothing left to resolve it against. Collecting
// them at parse time is the only moment this information exists.
// ---------------------------------------------------------------------------
/**
 * Collects the namespace bindings in scope at an element by walking up the
 * tree, an inner declaration winning over an outer one.
 * @param node - a DOM element
 * @returns an object mapping each prefix ('' for the default namespace) to
 * its namespace URI
 */
function namespacesInScope(node) {
  log.debug('Entering namespacesInScope().');
  const bindings = {};
  let current = node;
  while (current && current.nodeType === 1) {
    if (current.attributes) {
      for (let i = 0; i < current.attributes.length; i += 1) {
        const attr = current.attributes[i];
        if (attr.name === 'xmlns') {
          // An inner declaration wins, so a binding already collected from a
          // DEEPER element is not overwritten by an outer one.
          if (bindings[''] === undefined) {
            bindings[''] = attr.value;
          }
        } else if (attr.name.indexOf('xmlns:') === 0) {
          const prefix = attr.name.slice(6);
          if (bindings[prefix] === undefined) {
            bindings[prefix] = attr.value;
          }
        }
      }
    }
    current = current.parentNode;
  }
  log.debug('Leaving namespacesInScope(). ' +
            Object.keys(bindings).length + ' binding(s).');
  return bindings;
}

// ---------------------------------------------------------------------------
// EXPRESSIONS.
//
// The six things that can appear where XACML expects an <Expression>. The
// substitution group is closed, so anything else here is a syntax error rather
// than something to skip — see the header.
// ---------------------------------------------------------------------------
// The <Description> of an element, or ''. Read because it is the one part of a
// policy that exists purely for the next person, and a round trip through the
// editor that dropped it would silently delete every explanation the author
// wrote — the change nobody notices until they go looking for the reason a
// rule is there.
function descriptionOf(node) {
  log.debug("Entering descriptionOf().");
  const found = firstNamed(node, 'Description');
  log.debug("Leaving descriptionOf().");
  return found ? textOf(found).trim() : '';
}

/**
 * Reads an element in XACML's Expression substitution group into a model
 * expression node.
 * @param node - an AttributeValue, Apply, Function, VariableReference,
 * AttributeDesignator or AttributeSelector element
 * @returns the model expression node
 * @throws an IndeterminateError with the syntax-error status for any other
 * element or a malformed one
 */
function readExpression(node) {
  log.debug('Entering readExpression(). element=' + localName(node));
  const name = localName(node);
  if (name === 'AttributeValue') {
    const type = model.canonicalType(requiredAttribute(node, 'DataType'));
    const expression = { kind: 'value', type: type, lexical: textOf(node) };
    if (type === model.TYPE.XPATH_EXPRESSION) {
      // See the header: the bindings have to be captured now.
      expression.namespaces = namespacesInScope(node);
      expression.xpathCategory = attribute(node, 'XPathCategory');
    }
    log.debug('Leaving readExpression(). AttributeValue.');
    return expression;
  }
  if (name === 'AttributeDesignator') {
    log.debug('Leaving readExpression(). AttributeDesignator.');
    return {
      kind: 'designator',
      category: requiredAttribute(node, 'Category'),
      attributeId: requiredAttribute(node, 'AttributeId'),
      dataType: model.canonicalType(requiredAttribute(node, 'DataType')),
      issuer: attribute(node, 'Issuer'),
      // MustBePresent is REQUIRED by the schema and defaults to nothing. A
      // missing one is treated as false, which is the permissive reading and
      // the one every implementation takes — but it is recorded as a default
      // rather than assumed, because the difference between false and absent
      // is the difference between "not there is fine" and "nobody said".
      mustBePresent: booleanAttribute(node, 'MustBePresent', false)
    };
  }
  if (name === 'AttributeSelector') {
    log.debug('Leaving readExpression(). AttributeSelector.');
    return {
      kind: 'selector',
      category: requiredAttribute(node, 'Category'),
      path: requiredAttribute(node, 'Path'),
      dataType: model.canonicalType(requiredAttribute(node, 'DataType')),
      contextSelectorId: attribute(node, 'ContextSelectorId'),
      mustBePresent: booleanAttribute(node, 'MustBePresent', false),
      namespaces: namespacesInScope(node)
    };
  }
  if (name === 'Apply') {
    const args = elementChildren(node)
      .filter(function (child) {
        // <Description> is allowed inside <Apply> and is not an argument.
        // Treating it as one would shift every argument by a place and produce
        // an arity error naming the wrong function.
        return localName(child) !== 'Description';
      })
      .map(readExpression);
    log.debug('Leaving readExpression(). Apply with ' + args.length +
              ' argument(s).');
    // The <Description> filtered out above is KEPT rather than discarded. It
    // is optional syntax that means nothing to the evaluator and everything to
    // the next reader, and the editor rewrites the whole document on every
    // edit — so a part the reader drops is not merely unread, it is DELETED by
    // the first click. Same argument as `descriptionOf()` above it.
    return { kind: 'apply',
             functionId: requiredAttribute(node, 'FunctionId'),
             description: descriptionOf(node),
             args: args };
  }
  if (name === 'Function') {
    // A function used as a VALUE — the first argument of a higher-order
    // function. It is not applied here and carries no arguments.
    log.debug('Leaving readExpression(). Function reference.');
    return { kind: 'function',
             functionId: requiredAttribute(node, 'FunctionId') };
  }
  if (name === 'VariableReference') {
    log.debug('Leaving readExpression(). VariableReference.');
    return { kind: 'variableRef',
             variableId: requiredAttribute(node, 'VariableId') };
  }
  log.debug('Leaving readExpression(). Unrecognised.');
  throw model.syntaxError('<' + name + '> is not a XACML expression.');
}

// ---------------------------------------------------------------------------
// TARGETS.
//
// Target -> AnyOf* (all must match)
// AnyOf  -> AllOf* (at least one must match)
// AllOf  -> Match* (all must match)
//
// The nesting reads backwards from the element names and is the thing most
// worth being careful about: `AnyOf` holds `AllOf` children and is satisfied
// when ANY of them is, while the `Target` above it is satisfied only when ALL
// of its `AnyOf` children are. An absent or empty Target matches EVERYTHING,
// which is why `null` is a meaningful value here rather than an omission.
// ---------------------------------------------------------------------------
/**
 * Reads a `<Target>` into the model's AnyOf/AllOf/Match nesting.
 * @param node - the Target element, or nothing
 * @returns `{ anyOf }`, or null for an absent or empty Target, which
 * matches everything
 * @throws an IndeterminateError with the syntax-error status for an empty
 * AnyOf or AllOf
 */
function readTarget(node) {
  log.debug('Entering readTarget().');
  if (!node) {
    log.debug('Leaving readTarget(). Absent, so it matches everything.');
    return null;
  }
  const anyOf = childrenNamed(node, 'AnyOf').map(function (anyOfNode) {
    const allOf = childrenNamed(anyOfNode, 'AllOf').map(function (allOfNode) {
      const matches = childrenNamed(allOfNode, 'Match').map(readMatch);
      if (matches.length === 0) {
        throw model.syntaxError('<AllOf> must hold at least one <Match>.');
      }
      return { matches: matches };
    });
    if (allOf.length === 0) {
      throw model.syntaxError('<AnyOf> must hold at least one <AllOf>.');
    }
    return { allOf: allOf };
  });
  if (anyOf.length === 0) {
    log.debug('Leaving readTarget(). Empty, so it matches everything.');
    return null;
  }
  log.debug('Leaving readTarget(). ' + anyOf.length + ' AnyOf.');
  return { anyOf: anyOf };
}

function readMatch(node) {
  log.debug('Entering readMatch().');
  const value = firstNamed(node, 'AttributeValue');
  if (!value) {
    throw model.syntaxError('<Match> must hold an <AttributeValue>.');
  }
  const designator = firstNamed(node, 'AttributeDesignator');
  const selector = firstNamed(node, 'AttributeSelector');
  if (!designator && !selector) {
    throw model.syntaxError(
      '<Match> must hold an <AttributeDesignator> or an ' +
      '<AttributeSelector>.');
  }
  log.debug('Leaving readMatch().');
  return { matchId: requiredAttribute(node, 'MatchId'),
           value: readExpression(value),
           reference: readExpression(designator || selector) };
}

// ---------------------------------------------------------------------------
// OBLIGATIONS AND ADVICE.
//
// Structurally identical and semantically not: a PEP MUST honour an obligation
// or refuse the request, and MAY ignore advice. They are read by one function
// and kept in two lists, because collapsing them into one list with a flag is
// how the distinction gets lost at the point it matters.
// ---------------------------------------------------------------------------
function readExpressionHolders(parent, wrapper, item, idAttribute) {
  log.debug("Entering readExpressionHolders().");
  const container = firstNamed(parent, wrapper);
  if (!container) {
    log.debug("Leaving readExpressionHolders().");
    return [];
  }
  log.debug("Leaving readExpressionHolders().");
  return childrenNamed(container, item).map(function (node) {
    return {
      id: requiredAttribute(node, idAttribute),
      // FulfillOn on an obligation, AppliesTo on advice. Same idea, two
      // spellings, and the specification is the reason rather than this file.
      on: requiredAttribute(node,
                            item === 'ObligationExpression' ? 'FulfillOn'
                                                            : 'AppliesTo'),
      assignments: childrenNamed(node, 'AttributeAssignmentExpression')
        .map(function (assignment) {
          const children = elementChildren(assignment);
          if (children.length !== 1) {
            throw model.syntaxError(
              '<AttributeAssignmentExpression> must hold exactly one ' +
              'expression.');
          }
          return {
            attributeId: requiredAttribute(assignment, 'AttributeId'),
            category: attribute(assignment, 'Category'),
            issuer: attribute(assignment, 'Issuer'),
            expression: readExpression(children[0])
          };
        })
    };
  });
}

function readObligations(parent) {
  log.debug("Entering readObligations().");
  log.debug("Leaving readObligations().");
  return readExpressionHolders(parent, 'ObligationExpressions',
                               'ObligationExpression', 'ObligationId');
}

function readAdvice(parent) {
  log.debug("Entering readAdvice().");
  log.debug("Leaving readAdvice().");
  return readExpressionHolders(parent, 'AdviceExpressions',
                               'AdviceExpression', 'AdviceId');
}

// ---------------------------------------------------------------------------
// RULES, POLICIES AND POLICY SETS.
// ---------------------------------------------------------------------------
function readRule(node) {
  log.debug('Entering readRule().');
  const condition = firstNamed(node, 'Condition');
  const effect = requiredAttribute(node, 'Effect');
  if (effect !== model.EFFECT.PERMIT && effect !== model.EFFECT.DENY) {
    throw model.syntaxError(
      'A <Rule> Effect must be "Permit" or "Deny"; this one is "' + effect +
      '".');
  }
  let conditionExpression = null;
  if (condition) {
    const children = elementChildren(condition);
    if (children.length !== 1) {
      throw model.syntaxError(
        '<Condition> must hold exactly one expression; this one holds ' +
        children.length + '.');
    }
    conditionExpression = readExpression(children[0]);
  }
  log.debug('Leaving readRule(). id=' + attribute(node, 'RuleId'));
  return { id: requiredAttribute(node, 'RuleId'),
           effect: effect,
           description: descriptionOf(node),
           target: readTarget(firstNamed(node, 'Target')),
           condition: conditionExpression,
           obligations: readObligations(node),
           advice: readAdvice(node) };
}

function readVariableDefinitions(node) {
  log.debug('Entering readVariableDefinitions().');
  const variables = {};
  childrenNamed(node, 'VariableDefinition').forEach(function (definition) {
    const id = requiredAttribute(definition, 'VariableId');
    // Own members only (2026-11-12): `toString` is not "defined twice", and
    // `__proto__` is stored as a variable rather than as the prototype.
    if (ownMembers.has(variables, id)) {
      // The specification requires VariableId to be unique within a policy,
      // and the vendored suite has a case for it. A duplicate silently
      // overwriting the first would make which definition wins depend on
      // document order, which is not something a policy author can see.
      throw model.syntaxError(
        'VariableId "' + id + '" is defined twice in one <Policy>.');
    }
    const children = elementChildren(definition);
    if (children.length !== 1) {
      throw model.syntaxError(
        '<VariableDefinition> must hold exactly one expression.');
    }
    ownMembers.put(variables, id, readExpression(children[0]));
  });
  log.debug('Leaving readVariableDefinitions(). ' +
            Object.keys(variables).length + ' variable(s).');
  return variables;
}

// ---------------------------------------------------------------------------
// <PolicyDefaults> / <PolicySetDefaults>, WHICH IS ONE ELEMENT WITH TWO NAMES.
//
// It holds an <XPathVersion>, and the specification (section 5.14) says that
// element MUST be present when the policy contains an <AttributeSelector> or
// an `xpathExpression` value. Nothing here READS it — this implementation
// evaluates no XPath, so there is no dialect to switch on a URI — but it is
// carried, because a policy that arrived
// schema-valid and left without it would leave through this service's own
// writer, and two of the vendored conformance policies carry one.
//
// The rest of what the element may hold in later profiles is not read and not
// written: what is not in the model is lost on the first edit, and saying so
// here is the point of this comment.
// ---------------------------------------------------------------------------
function readXPathVersion(node, wrapper) {
  log.debug('Entering readXPathVersion(). wrapper=' + wrapper);
  const defaults = firstNamed(node, wrapper);
  if (!defaults) {
    log.debug('Leaving readXPathVersion(). Absent.');
    return null;
  }
  const version = firstNamed(defaults, 'XPathVersion');
  log.debug('Leaving readXPathVersion(). ' + (version ? 'Present.' : 'Empty.'));
  return version ? textOf(version).trim() : null;
}

// ---------------------------------------------------------------------------
// COMBINER PARAMETERS.
//
// Four elements — <CombinerParameters>, <RuleCombinerParameters>,
// <PolicyCombinerParameters> and <PolicySetCombinerParameters> — and they are
// the one part of the policy syntax this PDP is CERTAIN to ignore. Section C
// of the specification is explicit that none of the twelve standard combining
// algorithms takes a parameter, so a document may carry these and no standard
// algorithm can read them.
//
// THEY ARE STILL READ, AND THE REASON IS NOT SYMMETRY. The editor serializes
// the whole document on every single edit, so an element the reader skips is
// silently deleted the moment somebody renames a rule. Carrying them makes the
// round trip lossless; it does not make them mean anything, which is why
// `xacml_editor.js` shows them and lets them be removed and does NOT offer to
// add one — see the argument there.
//
// The several <CombinerParameters> elements a policy may carry are flattened
// into one list and written back as one element. They are a NAMED SET for an
// algorithm rather than an ordered document structure, so the grouping carries
// no meaning to lose.
// ---------------------------------------------------------------------------
function readCombinerParameterList(node) {
  log.debug("Entering readCombinerParameterList().");
  log.debug("Leaving readCombinerParameterList().");
  return childrenNamed(node, 'CombinerParameter').map(function (one) {
    const children = elementChildren(one);
    if (children.length !== 1) {
      throw model.syntaxError(
        '<CombinerParameter> must hold exactly one <AttributeValue>.');
    }
    return { name: requiredAttribute(one, 'ParameterName'),
             value: readExpression(children[0]) };
  });
}

function readCombinerParameters(node) {
  log.debug('Entering readCombinerParameters().');
  let out = [];
  childrenNamed(node, 'CombinerParameters').forEach(function (group) {
    out = out.concat(readCombinerParameterList(group));
  });
  log.debug('Leaving readCombinerParameters(). ' + out.length +
            ' parameter(s).');
  return out;
}

// The three that name what they are FOR. One shape, three element names and
// three id attributes, so one reader — collapsing them into a single list with
// a flag is how the distinction gets lost at the point it matters, which is
// the same argument obligations and advice are read by one function under.
function readReferencedCombinerParameters(node, element, idAttribute) {
  log.debug('Entering readReferencedCombinerParameters(). element=' + element);
  const out = childrenNamed(node, element).map(function (group) {
    return { ref: requiredAttribute(group, idAttribute),
             parameters: readCombinerParameterList(group) };
  });
  log.debug('Leaving readReferencedCombinerParameters(). ' + out.length +
            ' group(s).');
  return out;
}

function readPolicy(node) {
  log.debug('Entering readPolicy().');
  const rules = childrenNamed(node, 'Rule').map(readRule);
  const seen = {};
  rules.forEach(function (rule) {
    if (ownMembers.has(seen, rule.id)) {
      throw model.syntaxError(
        'RuleId "' + rule.id + '" appears twice in one <Policy>.');
    }
    ownMembers.put(seen, rule.id, true);
  });
  log.debug('Leaving readPolicy(). ' + rules.length + ' rule(s).');
  return {
    kind: 'Policy',
    id: requiredAttribute(node, 'PolicyId'),
    description: descriptionOf(node),
    version: attribute(node, 'Version') || '1.0',
    combiningAlgId: requiredAttribute(node, 'RuleCombiningAlgId'),
    xpathVersion: readXPathVersion(node, 'PolicyDefaults'),
    target: readTarget(firstNamed(node, 'Target')),
    variables: readVariableDefinitions(node),
    rules: rules,
    combinerParameters: readCombinerParameters(node),
    ruleCombinerParameters: readReferencedCombinerParameters(
      node, 'RuleCombinerParameters', 'RuleIdRef'),
    obligations: readObligations(node),
    advice: readAdvice(node),
    maxDelegationDepth: attribute(node, 'MaxDelegationDepth')
  };
}

function readPolicySet(node) {
  log.debug('Entering readPolicySet().');
  const children = [];
  elementChildren(node).forEach(function (child) {
    const name = localName(child);
    if (name === 'Policy') {
      children.push(readPolicy(child));
    } else if (name === 'PolicySet') {
      children.push(readPolicySet(child));
    } else if (name === 'PolicyIdReference') {
      children.push({ kind: 'PolicyIdReference', ref: textOf(child).trim(),
                      version: attribute(child, 'Version') });
    } else if (name === 'PolicySetIdReference') {
      children.push({ kind: 'PolicySetIdReference', ref: textOf(child).trim(),
                      version: attribute(child, 'Version') });
    }
  });
  log.debug('Leaving readPolicySet(). ' + children.length + ' child(ren).');
  return {
    kind: 'PolicySet',
    id: requiredAttribute(node, 'PolicySetId'),
    description: descriptionOf(node),
    version: attribute(node, 'Version') || '1.0',
    combiningAlgId: requiredAttribute(node, 'PolicyCombiningAlgId'),
    xpathVersion: readXPathVersion(node, 'PolicySetDefaults'),
    target: readTarget(firstNamed(node, 'Target')),
    children: children,
    combinerParameters: readCombinerParameters(node),
    // The two that name a CHILD of this set rather than a rule. Read
    // separately because the element name says which kind of child is being
    // named, and a document that named a Policy with the PolicySet spelling
    // would be wrong in a way one merged list could not express.
    policyCombinerParameters: readReferencedCombinerParameters(
      node, 'PolicyCombinerParameters', 'PolicyIdRef'),
    policySetCombinerParameters: readReferencedCombinerParameters(
      node, 'PolicySetCombinerParameters', 'PolicySetIdRef'),
    obligations: readObligations(node),
    advice: readAdvice(node),
    // A PolicySet may carry it too (section 5.1), and reading it on a Policy
    // and not here would lose it on exactly the documents that use delegation.
    maxDelegationDepth: attribute(node, 'MaxDelegationDepth')
  };
}

// ---------------------------------------------------------------------------
// THE ENTRY POINTS.
// ---------------------------------------------------------------------------
/**
 * Parses XML text into a DOM document, refusing a malformed one rather than
 * returning a partial tree.
 * @param xml - the document text
 * @returns the parsed DOM document
 * @throws an IndeterminateError with the syntax-error status when the text
 * is not well-formed or has no root element
 */
function parseDocument(xml) {
  log.debug('Entering parseDocument().');
  // `@xmldom/xmldom` reports a malformed document by CALLING A HANDLER rather
  // than throwing, and its default handler writes to the console and carries
  // on — so without this, a truncated policy parses to a partial tree and
  // fails much later as something that is not an element. Six conformance
  // cases assert that a bad document is refused, and every one of them would
  // pass for the wrong reason.
  // `onError` IS THE ONLY SPELLING. The older `errorHandler` object is not
  // merely deprecated in @xmldom/xmldom 0.9 — passing one THROWS a TypeError
  // out of the constructor ("errorHandler object is no longer supported"), so
  // carrying both spellings defensively is not free: it makes every parse fail
  // before a document is read. It cost the first conformance run here, where
  // 449 of 455 cases reported "could not be loaded" and named an option rather
  // than a policy.
  const errors = [];
  const parser = new DOMParser({
    onError: function (level, message) {
      log.debug("Entering onError().");
      // Warnings are ignored deliberately. Several policies in the vendored
      // suite carry an `xsi:schemaLocation` pointing at the XACML 2.0 schema —
      // upstream's README lists it as a defect in the original AT&T files —
      // and refusing those would fail cases over a schema hint rather than
      // over a decision.
      if (level === 'error' || level === 'fatalError') {
        errors.push(String(message));
      }
      log.debug("Leaving onError().");
    }
  });
  const document = parser.parseFromString(xml, 'text/xml');
  if (errors.length) {
    log.debug('Leaving parseDocument(). Malformed.');
    throw model.syntaxError('The document is not well-formed XML: ' +
                            errors[0], { errors: errors });
  }
  if (!document || !document.documentElement) {
    log.debug('Leaving parseDocument(). No document element.');
    throw model.syntaxError('The document has no root element.');
  }
  log.debug('Leaving parseDocument(). Root is ' +
            localName(document.documentElement) + '.');
  return document;
}

/**
 * Reads a XACML 3.0 Policy or PolicySet document into the model and
 * validates it statically.
 * @param xml - the policy document text
 * @returns the Policy or PolicySet model
 * @throws an IndeterminateError with the syntax-error status when the
 * document is malformed, has another root or does not typecheck
 */
function parsePolicy(xml) {
  log.debug('Entering parsePolicy().');
  const root = parseDocument(xml).documentElement;
  const name = localName(root);
  if (name === 'Policy' || name === 'PolicySet') {
    const parsed = name === 'Policy' ? readPolicy(root)
                                     : readPolicySet(root);
    // STATIC VALIDATION IS PART OF LOADING, not a separate step a caller can
    // forget. XACML is statically typed and a policy that does not typecheck
    // is wrong for every request rather than for some — see
    // `xacml_validate.js`. An ALFA import comes through here too (the console
    // writes it out as XML and the store's write parses it), so both syntaxes
    // refuse the same documents; the JSON Profile carries no policies.
    validate.validate(parsed);
    log.debug('Leaving parsePolicy(). A valid ' + name + '.');
    return parsed;
  }
  log.debug('Leaving parsePolicy(). Wrong root element.');
  throw model.syntaxError(
    'A policy document\'s root must be <Policy> or <PolicySet>; this one is ' +
    '<' + name + '>.');
}

// ---------------------------------------------------------------------------
// A REQUEST.
//
// The shape is flat on purpose: a list of categories, each holding a list of
// attributes, each holding a bag of values. That is what the specification
// says a request IS, and the temptation to index it by category on the way in
// is worth resisting — a request may carry the SAME category twice (which is
// how the Multiple Decision Profile's scheme 2.3 works), and a map keyed by
// category would silently lose one of them.
// ---------------------------------------------------------------------------
/**
 * Reads a XACML 3.0 `<Request>` document into the model's flat request
 * shape.
 * @param xml - the request document text
 * @returns `{ returnPolicyIdList, combinedDecision, categories }`
 * @throws an IndeterminateError with the syntax-error status when the
 * document is malformed or its root is not a Request
 */
function parseRequest(xml) {
  log.debug('Entering parseRequest().');
  const root = parseDocument(xml).documentElement;
  if (localName(root) !== 'Request') {
    log.debug('Leaving parseRequest(). Wrong root element.');
    throw model.syntaxError(
      'A request document\'s root must be <Request>; this one is <' +
      localName(root) + '>.');
  }
  const parsed = readRequest(root);
  log.debug('Leaving parseRequest(). ' + parsed.categories.length +
            ' category(ies).');
  return parsed;
}

// ---------------------------------------------------------------------------
// A <Request> ELEMENT, READ — SPLIT OUT OF THE FUNCTION ABOVE.
//
// `parseRequest()` takes a whole DOCUMENT, which is what a PDP is POSTed. This
// takes the NODE, because `POST /xacml/pip` carries a `<Request>` nested inside
// an envelope of this service's own and therefore has no document to hand over.
//
// **IT IS A SPLIT AND NOT A SECOND READER, WHICH IS THE ENTIRE POINT.** The
// alternative was to serialize the nested subtree back to a string and hand it
// to `parseRequest()` — which would put an XML SERIALIZER in the path of every
// PIP query, and a round trip through one is exactly where namespace
// declarations inherited from an ancestor go missing. Two readings of a
// request would also be two chances to disagree about what a request IS, which
// is the thing this file exists to prevent.
// ---------------------------------------------------------------------------
/**
 * Reads a `<Request>` element already in a DOM, for a request nested inside
 * another envelope (`POST /xacml/pip`).
 * @param root - the Request element
 * @returns `{ returnPolicyIdList, combinedDecision, categories }`
 */
function readRequest(root) {
  log.debug('Entering readRequest().');
  const categories = childrenNamed(root, 'Attributes').map(function (node) {
    const content = firstNamed(node, 'Content');
    return {
      category: requiredAttribute(node, 'Category'),
      id: attribute(node, 'id'),
      // The <Content> is kept as a DOM node rather than as text, because an
      // AttributeSelector would run an XPath over it (none is evaluated yet)
      // and re-parsing at every evaluation would be both slow and a second
      // chance to disagree about namespaces.
      content: content || null,
      attributes: childrenNamed(node, 'Attribute').map(function (each) {
        return {
          attributeId: requiredAttribute(each, 'AttributeId'),
          issuer: attribute(each, 'Issuer'),
          includeInResult: booleanAttribute(each, 'IncludeInResult',
                                            false),
          values: childrenNamed(each, 'AttributeValue')
            .map(function (valueNode) {
              return {
                type: model.canonicalType(
                  requiredAttribute(valueNode, 'DataType')),
                lexical: textOf(valueNode),
                node: valueNode
              };
            })
        };
      })
    };
  });
  log.debug('Leaving readRequest(). ' + categories.length + ' category(ies).');
  return {
    returnPolicyIdList: booleanAttribute(root, 'ReturnPolicyIdList', false),
    combinedDecision: booleanAttribute(root, 'CombinedDecision', false),
    categories: categories
  };
}

// ---------------------------------------------------------------------------
// A RESPONSE, READ BACK.
//
// Only the conformance runner needs this — a PDP produces responses and does
// not consume them. It is here rather than in the test because the runner
// comparing responses must read them the same way this implementation writes
// them, and two readings would be the very thing this directory refuses.
// ---------------------------------------------------------------------------
/**
 * Reads a XACML 3.0 `<Response>` document back, for the conformance runner.
 * @param xml - the response document text
 * @returns `{ results }`, each result with its decision, status,
 * obligations and advice
 * @throws an IndeterminateError with the syntax-error status when the
 * document is malformed or its root is not a Response
 */
function parseResponse(xml) {
  log.debug('Entering parseResponse().');
  const root = parseDocument(xml).documentElement;
  if (localName(root) !== 'Response') {
    throw model.syntaxError('Expected <Response>, found <' +
                            localName(root) + '>.');
  }
  const results = childrenNamed(root, 'Result').map(function (node) {
    const status = firstNamed(node, 'Status');
    const statusCode = status ? firstNamed(status, 'StatusCode') : null;
    return {
      decision: textOf(firstNamed(node, 'Decision')).trim(),
      status: statusCode ? { code: attribute(statusCode, 'Value') } : null,
      obligations: readResponseAssignments(node, 'Obligations', 'Obligation',
                                           'ObligationId'),
      advice: readResponseAssignments(node, 'AssociatedAdvice', 'Advice',
                                      'AdviceId')
    };
  });
  log.debug('Leaving parseResponse(). ' + results.length + ' result(s).');
  return { results: results };
}

function readResponseAssignments(parent, wrapper, item, idAttribute) {
  log.debug("Entering readResponseAssignments().");
  const container = firstNamed(parent, wrapper);
  if (!container) {
    log.debug("Leaving readResponseAssignments().");
    return [];
  }
  log.debug("Leaving readResponseAssignments().");
  return childrenNamed(container, item).map(function (node) {
    return {
      id: attribute(node, idAttribute),
      assignments: childrenNamed(node, 'AttributeAssignment')
        .map(function (assignment) {
          return {
            attributeId: attribute(assignment, 'AttributeId'),
            category: attribute(assignment, 'Category'),
            type: model.canonicalType(attribute(assignment, 'DataType') ||
                                      model.TYPE.STRING),
            lexical: textOf(assignment)
          };
        })
    };
  });
}


// ---------------------------------------------------------------------------
// THE MODEL, WRITTEN BACK OUT AS XACML 3.0 XML.
//
// The reader's inverse, and the PAP is what needs it: the guided editor works
// on the MODEL, so every structural change has to be serialized back into the
// document `ou=policies` actually stores. An ALFA import needs it too — ALFA
// in, model, XML out is the whole of what an ALFA compiler is here
// (`xacml_admin.js`'s `import-alfa`).
//
// TWO THINGS IT DELIBERATELY DOES NOT PRESERVE, and both are worth knowing
// before pointing the editor at a hand-authored policy:
//
//   * COMMENTS AND WHITESPACE. The model does not carry them, so a document
//     that goes through the editor comes back reformatted and stripped of
//     anything a person wrote between the elements. That is why the store
//     keeps the document AS AUTHORED and why opening a policy in the editor
//     and saving it is a deliberate act rather than a side effect of viewing.
//   * ATTRIBUTE ORDER. Written in the schema's order rather than the source's.
//
// Neither changes what a policy MEANS — `tests/xacml_service.js` asserts that
// a document through the reader and back decides identically — but the diff
// after an edit will be large, and somebody expecting a one-line change should
// know why before they see it.
// ---------------------------------------------------------------------------

// Every attribute value and every text node goes through `xmlEscape`, which is
// the same function every other document this service emits is escaped with —
// so the policy writer and the SAML writer cannot disagree about what escaping
// is.
function attr(name, value) {
  log.debug("Entering attr().");
  if (value === null || value === undefined || value === '') {
    log.debug("Leaving attr().");
    return '';
  }
  log.debug("Leaving attr().");
  return ' ' + name + '="' + xmlEscape(String(value)) + '"';
}

function indent(depth) {
  log.debug("Entering indent().");
  log.debug("Leaving indent().");
  return new Array(depth + 1).join('  ');
}

// ---------------------------------------------------------------------------
// THE NAMESPACE BINDINGS AN XPATH NEEDS, WRITTEN BACK ONTO THE ELEMENT THAT
// USES IT.
//
// An `<AttributeSelector Path="//md:record/md:patient"/>` means nothing
// without the binding for `md:`, and that binding is a property of the
// DOCUMENT the selector arrived in — captured at read time by
// `namespacesInScope()`, because by the time the model is evaluated the DOM is
// gone. Until this existed the reader captured them and the writer dropped
// them, so the FIRST EDIT of a policy containing a selector produced a
// document whose XPath could not resolve a single prefix. Nothing failed
// loudly: an unresolvable prefix is an empty bag, an empty bag is
// NotApplicable, and NotApplicable looks exactly like a policy that decided
// you may not.
//
// TWO RULES, and both are about being narrow rather than tidy:
//
//   Only PREFIXED bindings are written. A default `xmlns=` on an element also
//   rebinds THAT ELEMENT'S OWN NAME, and these elements are XACML elements
//   written unprefixed — declaring `xmlns="http://www.medico.com/..."` on an
//   <AttributeSelector> would move the selector itself out of the XACML
//   namespace and produce a document nothing can read.
//
//   Only prefixes the path actually USES are written. Every binding in scope
//   at read time includes `xsi`, `xacml-context` and whatever else the root
//   declared, and copying all of them onto every selector is noise on a
//   document people read. Over-inclusion is safe here — a prefix matched
//   inside a quoted string in the XPath costs one unused declaration — while
//   under-inclusion is the failure above, so the test is deliberately loose.
// ---------------------------------------------------------------------------
function namespaceAttrs(namespaces, usedIn) {
  log.debug('Entering namespaceAttrs().');
  if (!namespaces) {
    log.debug('Leaving namespaceAttrs(). None captured.');
    return '';
  }
  const text = String(usedIn || '');
  const used = {};
  const pattern = /([A-Za-z_][A-Za-z0-9_.-]*):/g;
  let found = pattern.exec(text);
  while (found) {
    used[found[1]] = true;
    found = pattern.exec(text);
  }
  const out = Object.keys(namespaces).filter(function (prefix) {
    return prefix !== '' && used[prefix] &&
           namespaces[prefix] !== model.NS_XACML;
  }).sort().map(function (prefix) {
    return attr('xmlns:' + prefix, namespaces[prefix]);
  }).join('');
  log.debug('Leaving namespaceAttrs(). ' + (out ? 'Declared.' : 'Nothing.'));
  return out;
}

function writeExpression(expression, depth) {
  log.debug('Entering writeExpression(). kind=' + expression.kind);
  const pad = indent(depth);
  if (expression.kind === 'value') {
    const lexical = String(expression.lexical === undefined
                             ? '' : expression.lexical);
    // An `xpathExpression` value is an XPath, so it carries the same two
    // things a selector does: the category the path is evaluated against, and
    // the prefix bindings it uses. Both were captured by the reader and both
    // were dropped here until this line existed — see `namespaceAttrs()`.
    const xpath = model.canonicalType(expression.type) ===
                  model.TYPE.XPATH_EXPRESSION;
    log.debug('Leaving writeExpression(). AttributeValue.');
    return pad + '<AttributeValue' + attr('DataType', expression.type) +
      (xpath ? attr('XPathCategory', expression.xpathCategory) +
               namespaceAttrs(expression.namespaces, lexical) : '') + '>' +
      xmlEscape(lexical) + '</AttributeValue>';
  }
  if (expression.kind === 'designator') {
    log.debug('Leaving writeExpression(). AttributeDesignator.');
    return pad + '<AttributeDesignator' +
      attr('Category', expression.category) +
      attr('AttributeId', expression.attributeId) +
      attr('DataType', expression.dataType) +
      attr('Issuer', expression.issuer) +
      // MustBePresent is written ALWAYS, including when false. The schema
      // requires it, and relying on a reader to default a missing one is a
      // liberty worth not needing in a document this service produced itself.
      ' MustBePresent="' + (expression.mustBePresent ? 'true' : 'false') +
      '"/>';
  }
  if (expression.kind === 'selector') {
    log.debug('Leaving writeExpression(). AttributeSelector.');
    return pad + '<AttributeSelector' +
      attr('Category', expression.category) +
      attr('Path', expression.path) +
      attr('DataType', expression.dataType) +
      attr('ContextSelectorId', expression.contextSelectorId) +
      namespaceAttrs(expression.namespaces, expression.path) +
      ' MustBePresent="' + (expression.mustBePresent ? 'true' : 'false') +
      '"/>';
  }
  if (expression.kind === 'function') {
    log.debug('Leaving writeExpression(). Function.');
    return pad + '<Function' + attr('FunctionId', expression.functionId) +
      '/>';
  }
  if (expression.kind === 'variableRef') {
    log.debug('Leaving writeExpression(). VariableReference.');
    return pad + '<VariableReference' +
      attr('VariableId', expression.variableId) + '/>';
  }
  if (expression.kind === 'apply') {
    // <Description> FIRST, because the schema's sequence puts it there and an
    // <Apply> whose description followed its arguments is a document this
    // reader accepts and a schema validator does not — which is the same trap
    // `writeTarget()` argues about an omitted <Target/>.
    const described = expression.description
      ? indent(depth + 1) + '<Description>' +
        xmlEscape(expression.description) + '</Description>\n'
      : '';
    const inner = (expression.args || []).map(function (argument) {
      return writeExpression(argument, depth + 1);
    }).join('\n');
    log.debug('Leaving writeExpression(). Apply.');
    return pad + '<Apply' + attr('FunctionId', expression.functionId) + '>' +
      (described || inner ? '\n' + described + inner +
                            (inner ? '\n' : '') + pad : '') + '</Apply>';
  }
  log.debug('Leaving writeExpression(). Unwritable.');
  throw model.syntaxError('Cannot write an expression of kind "' +
                          expression.kind + '".');
}

function writeTarget(target, depth) {
  log.debug('Entering writeTarget().');
  const pad = indent(depth);
  // AN ABSENT TARGET AND AN EMPTY ONE MEAN THE SAME THING — match everything —
  // and `<Target/>` is written for both, because the schema REQUIRES the
  // element on a Rule and a Policy. Omitting it where the model holds null
  // would produce a document this service's own reader accepts and somebody
  // else's schema validator rejects, which is the worst of both.
  if (!target || !target.anyOf || !target.anyOf.length) {
    log.debug('Leaving writeTarget(). Empty.');
    return pad + '<Target/>';
  }
  const body = target.anyOf.map(function (anyOf) {
    const allOfs = anyOf.allOf.map(function (allOf) {
      const matches = allOf.matches.map(function (match) {
        return indent(depth + 3) + '<Match' +
          attr('MatchId', match.matchId) + '>\n' +
          writeExpression(match.value, depth + 4) + '\n' +
          writeExpression(match.reference, depth + 4) + '\n' +
          indent(depth + 3) + '</Match>';
      }).join('\n');
      return indent(depth + 2) + '<AllOf>\n' + matches + '\n' +
        indent(depth + 2) + '</AllOf>';
    }).join('\n');
    return indent(depth + 1) + '<AnyOf>\n' + allOfs + '\n' +
      indent(depth + 1) + '</AnyOf>';
  }).join('\n');
  log.debug('Leaving writeTarget(). ' + target.anyOf.length + ' AnyOf.');
  return pad + '<Target>\n' + body + '\n' + pad + '</Target>';
}

function writeHolders(holders, depth, wrapper, item, idAttr, onAttr) {
  log.debug("Entering writeHolders().");
  if (!holders || !holders.length) {
    log.debug("Leaving writeHolders().");
    return '';
  }
  const pad = indent(depth);
  const body = holders.map(function (holder) {
    const assignments = (holder.assignments || []).map(function (one) {
      return indent(depth + 2) + '<AttributeAssignmentExpression' +
        attr('AttributeId', one.attributeId) +
        attr('Category', one.category) +
        attr('Issuer', one.issuer) + '>\n' +
        writeExpression(one.expression, depth + 3) + '\n' +
        indent(depth + 2) + '</AttributeAssignmentExpression>';
    }).join('\n');
    return indent(depth + 1) + '<' + item + attr(idAttr, holder.id) +
      attr(onAttr, holder.on) + '>' +
      (assignments ? '\n' + assignments + '\n' + indent(depth + 1) : '') +
      '</' + item + '>';
  }).join('\n');
  log.debug("Leaving writeHolders().");
  return '\n' + pad + '<' + wrapper + '>\n' + body + '\n' + pad + '</' +
    wrapper + '>';
}

// <PolicyDefaults> / <PolicySetDefaults>. Written only when there is a version
// to put in it, because an empty <PolicyDefaults/> is not schema-valid — the
// element exists to hold the XPathVersion.
function writeDefaults(xpathVersion, depth, wrapper) {
  log.debug("Entering writeDefaults().");
  if (!xpathVersion) {
    log.debug("Leaving writeDefaults().");
    return '';
  }
  const pad = indent(depth);
  log.debug("Leaving writeDefaults().");
  return '\n' + pad + '<' + wrapper + '>\n' +
    indent(depth + 1) + '<XPathVersion>' + xmlEscape(xpathVersion) +
    '</XPathVersion>\n' + pad + '</' + wrapper + '>';
}

// The four combiner-parameter elements. See `readCombinerParameters()` for why
// they are carried at all: nothing here reads them, and the writer's job is to
// make sure an edit does not delete them.
function writeCombinerParameterList(parameters, depth) {
  log.debug("Entering writeCombinerParameterList().");
  log.debug("Leaving writeCombinerParameterList().");
  return (parameters || []).map(function (one) {
    return indent(depth) + '<CombinerParameter' +
      attr('ParameterName', one.name) + '>\n' +
      writeExpression(one.value, depth + 1) + '\n' +
      indent(depth) + '</CombinerParameter>';
  }).join('\n');
}

function writeCombinerParameters(parameters, depth) {
  log.debug("Entering writeCombinerParameters().");
  if (!parameters || !parameters.length) {
    log.debug("Leaving writeCombinerParameters().");
    return '';
  }
  const pad = indent(depth);
  log.debug("Leaving writeCombinerParameters().");
  return '\n' + pad + '<CombinerParameters>\n' +
    writeCombinerParameterList(parameters, depth + 1) + '\n' +
    pad + '</CombinerParameters>';
}

function writeReferencedCombinerParameters(groups, depth, element,
                                           idAttribute) {
  log.debug("Entering writeReferencedCombinerParameters().");
  if (!groups || !groups.length) {
    log.debug("Leaving writeReferencedCombinerParameters().");
    return '';
  }
  const pad = indent(depth);
  log.debug("Leaving writeReferencedCombinerParameters().");
  return groups.map(function (group) {
    return '\n' + pad + '<' + element + attr(idAttribute, group.ref) + '>\n' +
      writeCombinerParameterList(group.parameters, depth + 1) + '\n' +
      pad + '</' + element + '>';
  }).join('');
}

function writeRule(rule, depth) {
  log.debug('Entering writeRule(). id=' + rule.id);
  const pad = indent(depth);
  let body = '';
  if (rule.description) {
    body += '\n' + indent(depth + 1) + '<Description>' +
      xmlEscape(rule.description) + '</Description>';
  }
  body += '\n' + writeTarget(rule.target, depth + 1);
  if (rule.condition) {
    body += '\n' + indent(depth + 1) + '<Condition>\n' +
      writeExpression(rule.condition, depth + 2) + '\n' +
      indent(depth + 1) + '</Condition>';
  }
  body += writeHolders(rule.obligations, depth + 1, 'ObligationExpressions',
                       'ObligationExpression', 'ObligationId', 'FulfillOn');
  body += writeHolders(rule.advice, depth + 1, 'AdviceExpressions',
                       'AdviceExpression', 'AdviceId', 'AppliesTo');
  log.debug('Leaving writeRule().');
  return pad + '<Rule' + attr('RuleId', rule.id) +
    attr('Effect', rule.effect) + '>' + body + '\n' + pad + '</Rule>';
}

function writePolicyBody(policy, depth, withNamespace) {
  log.debug("Entering writePolicyBody().");
  const pad = indent(depth);
  let body = '';
  if (policy.description) {
    body += '\n' + indent(depth + 1) + '<Description>' +
      xmlEscape(policy.description) + '</Description>';
  }
  // THE ORDER OF WHAT FOLLOWS IS THE SCHEMA'S SEQUENCE AND NOT A PREFERENCE:
  // Description, PolicyDefaults, Target, then the repeatable group, then the
  // two expression holders. A body assembled in a different order parses back
  // here perfectly and fails somebody else's schema validator, which is the
  // worst of both — the same trap `writeTarget()` argues about.
  body += writeDefaults(policy.xpathVersion, depth + 1, 'PolicyDefaults');
  body += '\n' + writeTarget(policy.target, depth + 1);
  body += writeCombinerParameters(policy.combinerParameters, depth + 1);
  body += writeReferencedCombinerParameters(policy.ruleCombinerParameters,
                                            depth + 1,
                                            'RuleCombinerParameters',
                                            'RuleIdRef');
  Object.keys(policy.variables || {}).forEach(function (id) {
    body += '\n' + indent(depth + 1) + '<VariableDefinition' +
      attr('VariableId', id) + '>\n' +
      writeExpression(policy.variables[id], depth + 2) + '\n' +
      indent(depth + 1) + '</VariableDefinition>';
  });
  (policy.rules || []).forEach(function (rule) {
    body += '\n' + writeRule(rule, depth + 1);
  });
  body += writeHolders(policy.obligations, depth + 1, 'ObligationExpressions',
                       'ObligationExpression', 'ObligationId', 'FulfillOn');
  body += writeHolders(policy.advice, depth + 1, 'AdviceExpressions',
                       'AdviceExpression', 'AdviceId', 'AppliesTo');
  log.debug("Leaving writePolicyBody().");
  return pad + '<Policy' +
    (withNamespace ? ' xmlns="' + model.NS_XACML + '"' : '') +
    attr('PolicyId', policy.id) +
    attr('Version', policy.version || '1.0') +
    attr('RuleCombiningAlgId', policy.combiningAlgId) +
    // Optional, and carried rather than honoured: this PDP implements no
    // administrative delegation, so the depth is written back exactly as it
    // was found and read by nothing. `xacml/CLAUDE.md` says so out loud rather
    // than letting the attribute imply otherwise.
    attr('MaxDelegationDepth', policy.maxDelegationDepth) + '>' +
    body + '\n' + pad + '</Policy>';
}

// THE NAMESPACE IS DECLARED ON THE ROOT AND NOWHERE ELSE, which is why the
// nested calls pass `false`. A `xmlns` repeated on every descendant is legal
// and is noise; more to the point, a nested Policy carrying its own default
// namespace declaration reads as though it might be a DIFFERENT namespace, and
// somebody will eventually change one of them.
function writePolicySetBody(policySet, depth, withNamespace) {
  log.debug("Entering writePolicySetBody().");
  const pad = indent(depth);
  let body = '';
  if (policySet.description) {
    body += '\n' + indent(depth + 1) + '<Description>' +
      xmlEscape(policySet.description) + '</Description>';
  }
  body += writeDefaults(policySet.xpathVersion, depth + 1,
                        'PolicySetDefaults');
  body += '\n' + writeTarget(policySet.target, depth + 1);
  body += writeCombinerParameters(policySet.combinerParameters, depth + 1);
  body += writeReferencedCombinerParameters(
    policySet.policyCombinerParameters, depth + 1,
    'PolicyCombinerParameters', 'PolicyIdRef');
  body += writeReferencedCombinerParameters(
    policySet.policySetCombinerParameters, depth + 1,
    'PolicySetCombinerParameters', 'PolicySetIdRef');
  (policySet.children || []).forEach(function (child) {
    if (child.kind === 'Policy') {
      body += '\n' + writePolicyBody(child, depth + 1, false);
    } else if (child.kind === 'PolicySet') {
      body += '\n' + writePolicySetBody(child, depth + 1, false);
    } else if (child.kind === 'PolicyIdReference' ||
               child.kind === 'PolicySetIdReference') {
      body += '\n' + indent(depth + 1) + '<' + child.kind +
        attr('Version', child.version) + '>' + xmlEscape(child.ref) +
        '</' + child.kind + '>';
    }
  });
  body += writeHolders(policySet.obligations, depth + 1,
                       'ObligationExpressions', 'ObligationExpression',
                       'ObligationId', 'FulfillOn');
  body += writeHolders(policySet.advice, depth + 1, 'AdviceExpressions',
                       'AdviceExpression', 'AdviceId', 'AppliesTo');
  log.debug("Leaving writePolicySetBody().");
  return pad + '<PolicySet' +
    (withNamespace ? ' xmlns="' + model.NS_XACML + '"' : '') +
    attr('PolicySetId', policySet.id) +
    attr('Version', policySet.version || '1.0') +
    attr('PolicyCombiningAlgId', policySet.combiningAlgId) +
    attr('MaxDelegationDepth', policySet.maxDelegationDepth) + '>' +
    body + '\n' + pad + '</PolicySet>';
}

/**
 * Writes a Policy or PolicySet model out as a XACML 3.0 XML document, in the
 * schema's element order.
 * @param policy - a Policy or PolicySet from the model
 * @returns the document text, with an XML declaration
 */
function writePolicy(policy) {
  log.debug('Entering writePolicy(). id=' + policy.id);
  const body = policy.kind === 'PolicySet'
    ? writePolicySetBody(policy, 0, true)
    : writePolicyBody(policy, 0, true);
  log.debug('Leaving writePolicy().');
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + body + '\n';
}

/**
 * XACML 3.0 core XML: reads policies, requests and responses into the model
 * and writes policies back out.
 *
 * A strict reader, walked by element name with `@xmldom/xmldom`; a policy
 * is validated statically as part of loading.
 * @namespace
 */
module.exports = {
  parsePolicy: parsePolicy,
  writePolicy: writePolicy,
  parseRequest: parseRequest,
  readRequest: readRequest,
  parseResponse: parseResponse,
  parseDocument: parseDocument,
  localName: localName,
  elementChildren: elementChildren,
  childrenNamed: childrenNamed,
  firstNamed: firstNamed,
  textOf: textOf,
  namespacesInScope: namespacesInScope,
  readExpression: readExpression,
  readTarget: readTarget
};
