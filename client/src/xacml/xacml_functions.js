// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml_functions.js
//
// ---------------------------------------------------------------------------
// THE STANDARD FUNCTION LIBRARY, GENERATED OVER THE DATATYPE TABLE RATHER THAN
// WRITTEN OUT.
//
// XACML 3.0 defines a little over two hundred function identifiers, and the
// OASIS XACML 3.0 conformance suite exercises 210 of them. They are NOT two
// hundred functions: `string-is-in`, `integer-is-in`, `date-is-in` and eleven
// more are ONE function and a table row each, and the same is true of `-bag`,
// `-bag-size`, `-one-and-only`, `-intersection`, `-union`, `-subset`,
// `-set-equals`, `-at-least-one-member-of`, `-equal` and the four comparison
// operators.
//
// So `generic()` below defines a family once and registers it for every type
// that has the operation, and this file holds about thirty real
// implementations rather than two hundred near-copies. That is not brevity for
// its own sake. Two hundred hand-written functions is two hundred chances to
// paste `string`'s comparison into `anyURI`'s row — and the one that got it
// wrong would be the one nobody wrote a test for, because a test written by
// the same person would paste the same mistake.
//
// ---------------------------------------------------------------------------
// EVERY VALUE IS A BAG, INCLUDING THE ONES THAT ARE NOT.
//
// An expression in XACML evaluates to a bag. `AttributeDesignator` returns
// one, `AttributeSelector` returns one, and an `AttributeValue` returns a bag
// of exactly one — which is why nothing in this implementation ever holds a
// bare value and there is no code path where somebody has to remember to wrap
// one. That is the shape the mistake takes elsewhere.
//
// A function declares each parameter as `primitive` or `bag`:
//
//   primitive   the argument bag MUST hold exactly one value, and the
//               function is handed that value. A bag of nought or of two is
//               Indeterminate — which is what `string-one-and-only` exists to
//               make explicit, and what happens implicitly here.
//   bag         the function is handed the whole bag.
//
// Getting that distinction wrong is the second commonest defect in a PDP after
// the extended Indeterminate values, and it fails silently: a function handed
// a two-element bag where it expected one value quietly uses the first, and a
// policy that should have been Indeterminate returns Permit.
//
// ---------------------------------------------------------------------------
// TEN FUNCTIONS MUST NOT HAVE THEIR ARGUMENTS EVALUATED UP FRONT.
//
// `and`, `or` and `n-of` SHORT-CIRCUIT — the specification says so in as many
// words, and it matters for more than speed: an argument that would be
// Indeterminate must not make the whole expression Indeterminate if an earlier
// argument already settled it. `and(false, <missing attribute>)` is False, not
// Indeterminate.
//
// The six higher-order functions (`any-of`, `all-of`, `any-of-any`,
// `all-of-any`, `any-of-all`, `all-of-all`) and `map` take a FUNCTION as their
// first argument, which is not a value at all.
//
// Both are handled by marking a function `lazy`: it receives the unevaluated
// argument expressions and an evaluator, instead of resolved bags. A lazy
// function is the exception and says why; everything else is strict.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const ownMembers = require('./xacml_own_members');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');

const TYPE = model.TYPE;
/**
 * The standard function library, keyed by function identifier.
 *
 * Each entry declares its parameters as `primitive` or `bag`, its return,
 * and an `apply`; a `lazy` entry receives unevaluated arguments.
 */
const FUNCTIONS = {};

// The three URI prefixes the standard functions live under. Spelt out for the
// reason `xacml_model.js` spells out its identifiers: these differ by one
// segment and a wrong one matches nothing.
const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const F2 = 'urn:oasis:names:tc:xacml:2.0:function:';
const F3 = 'urn:oasis:names:tc:xacml:3.0:function:';

function define(uri, definition) {
  log.debug("Entering define().");
  definition.uri = uri;
  FUNCTIONS[uri] = definition;
  log.debug("Leaving define().");
}

// ---------------------------------------------------------------------------
// SMALL HELPERS OVER BAGS.
// ---------------------------------------------------------------------------

// A literal integer argument, or null when the argument is not a literal at
// all. Used only by static checks: a range rule can be enforced at load time
// exactly when the value is written into the policy rather than fetched.
function literalInteger(expression) {
  log.debug("Entering literalInteger().");
  if (!expression || expression.kind !== 'value' ||
      model.canonicalType(expression.type) !== TYPE.INTEGER) {
    log.debug("Leaving literalInteger().");
    return null;
  }
  const text = String(expression.lexical).trim();
  if (!/^[+-]?\d+$/.test(text)) {
    log.debug("Leaving literalInteger().");
    return null;
  }
  log.debug("Leaving literalInteger().");
  return parseInt(text, 10);
}

function boolBag(value) {
  log.debug("Entering boolBag().");
  log.debug("Leaving boolBag().");
  return model.singleton(TYPE.BOOLEAN, value);
}

function intBag(value) {
  log.debug("Entering intBag().");
  log.debug("Leaving intBag().");
  return model.singleton(TYPE.INTEGER, BigInt(value));
}

// Whether a bag already holds a value equal to one, at the bag's own type.
// Used by union, intersection, subset and set-equals, all of which are defined
// in terms of "the same value" rather than "the same object".
function bagHas(row, values, candidate) {
  log.debug("Entering bagHas().");
  for (let i = 0; i < values.length; i += 1) {
    if (row.equal(values[i], candidate)) {
      log.debug("Leaving bagHas().");
      return true;
    }
  }
  log.debug("Leaving bagHas().");
  return false;
}

// ---------------------------------------------------------------------------
// EVERY TYPE-PARAMETERISED FAMILY, DEFINED ONCE.
//
// `typesWith('compare')` is what keeps `boolean-greater-than` from existing:
// the comparison family is registered only for the types whose table row has
// an ordering, so a policy naming a function XACML does not define fails as an
// unknown function rather than as a wrong answer.
// ---------------------------------------------------------------------------
function allTypes() {
  log.debug("Entering allTypes().");
  log.debug("Leaving allTypes().");
  return Object.keys(datatypes.TYPES).filter(function (uri) {
    // xpathExpression has no equality and takes part in no family. Section
    // A.3.15 defines no bag or comparison functions over it at all.
    return uri !== TYPE.XPATH_EXPRESSION;
  });
}

function typesWith(capability) {
  log.debug("Entering typesWith().");
  log.debug("Leaving typesWith().");
  return allTypes().filter(function (uri) {
    return typeof datatypes.TYPES[uri][capability] === 'function';
  });
}

// ---------------------------------------------------------------------------
// WHICH VERSION SEGMENT A TYPE'S FAMILY FUNCTIONS LIVE UNDER, AND WHY IT IS
// NOT THE SAME FOR ALL OF THEM.
//
// Almost every type-parameterised function is `1.0` — `string-is-in`,
// `integer-bag`, `date-one-and-only`. THE TWO DURATION TYPES ARE ENTIRELY
// `3.0`, every function of them without exception, because those types did not
// exist in XACML 1.0 in the form 3.0 uses: they moved out of the 2005 XQuery
// namespace and the whole family was re-issued under the new version.
//
// This is the specification's inconsistency rather than a choice here, and it
// is precisely the reason `xacml_model.js` spells its identifiers out instead
// of building them. Getting it wrong does not fail loudly — a policy naming
// `urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-bag` would find no
// such function and go Indeterminate, and the error would name a URI that
// looks exactly like the twelve working ones beside it.
//
// Verified against the OASIS conformance suite, which uses all 26 of the
// duration function URIs and every one of them at 3.0.
// ---------------------------------------------------------------------------
function familyPrefix(uri) {
  log.debug("Entering familyPrefix().");
  if (uri === TYPE.DAYTIME_DURATION || uri === TYPE.YEARMONTH_DURATION) {
    log.debug("Leaving familyPrefix().");
    return F3;
  }
  log.debug("Leaving familyPrefix().");
  return F1;
}

function generic(suffix, types, definitionFor) {
  log.debug("Entering generic().");
  types.forEach(function (uri) {
    const row = datatypes.TYPES[uri];
    const definition = definitionFor(row, uri);
    // The FUNCTION NAME is the type's own short name, which is what the
    // specification uses — `dayTimeDuration-equal`, not
    // `http://...#dayTimeDuration-equal`. Building it from `row.name` is the
    // one place a name is concatenated in this directory, and it is safe
    // because the short names come from the table rather than from a URI.
    define(familyPrefix(uri) + row.name + '-' + suffix, definition.body);
  });
  log.debug("Leaving generic().");
}

// --- equality ---------------------------------------------------------------
generic('equal', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'primitive', type: uri },
           { kind: 'primitive', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return boolBag(row.equal(values[0], values[1]));
    }
  } };
});

// --- ordering ---------------------------------------------------------------
// Four operators over one comparison. `compare` may return null — see
// `compareTemporal()` in the datatype table — and null means the two values
// are genuinely incomparable, which is Indeterminate rather than false.
const COMPARISONS = [
  { suffix: 'greater-than', holds: function (c) {
    log.debug("Entering holds().");
    log.debug("Leaving holds().");
    return c > 0;
  } },
  { suffix: 'greater-than-or-equal', holds: function (c) {
    log.debug("Entering holds().");
    log.debug("Leaving holds().");
    return c >= 0;
  } },
  { suffix: 'less-than', holds: function (c) {
    log.debug("Entering holds().");
    log.debug("Leaving holds().");
    return c < 0;
  } },
  { suffix: 'less-than-or-equal', holds: function (c) {
    log.debug("Entering holds().");
    log.debug("Leaving holds().");
    return c <= 0;
  } }
];

COMPARISONS.forEach(function (comparison) {
  generic(comparison.suffix, typesWith('compare'), function (row, uri) {
    return { body: {
      returns: { kind: 'primitive', type: TYPE.BOOLEAN },
      args: [{ kind: 'primitive', type: uri },
             { kind: 'primitive', type: uri }],
      apply: function (values) {
        log.debug("Entering apply().");
        const c = row.compare(values[0], values[1]);
        if (c === null) {
          throw model.processingError(
            'Two ' + row.name + ' values are not comparable: one carries a ' +
            'timezone and the other does not, and the ordering differs ' +
            'across the range a missing timezone could be.');
        }
        log.debug("Leaving apply().");
        return boolBag(comparison.holds(c));
      }
    } };
  });
});

// --- bag construction and inspection ----------------------------------------
generic('bag', allTypes(), function (row, uri) {
  return { body: {
    returns: { kind: 'bag', type: uri },
    variadic: { kind: 'primitive', type: uri },
    args: [],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return model.bag(uri, values);
    }
  } };
});

generic('bag-size', allTypes(), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.INTEGER },
    args: [{ kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return intBag(values[0].values.length);
    }
  } };
});

generic('one-and-only', allTypes(), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: uri },
    args: [{ kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      const contents = values[0].values;
      // The whole point of this function. A bag of nought and a bag of two are
      // BOTH errors, and they are different errors: nothing was there, or too
      // much was. Reported separately because a policy author debugging one
      // needs to know which.
      if (contents.length === 0) {
        throw model.missingAttribute(
          row.name + '-one-and-only was given an empty bag.');
      }
      if (contents.length > 1) {
        throw model.processingError(
          row.name + '-one-and-only was given a bag of ' + contents.length +
          ' values and requires exactly one.');
      }
      log.debug("Leaving apply().");
      return model.singleton(uri, contents[0]);
    }
  } };
});

generic('is-in', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'primitive', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return boolBag(bagHas(row, values[1].values, values[0]));
    }
  } };
});

generic('intersection', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'bag', type: uri },
    args: [{ kind: 'bag', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      const result = [];
      values[0].values.forEach(function (candidate) {
        // Two conditions, and the second is the one that is easy to leave out:
        // the result of an intersection is a SET, so a value already taken is
        // not taken twice even when the left bag holds it twice.
        if (bagHas(row, values[1].values, candidate) &&
            !bagHas(row, result, candidate)) {
          result.push(candidate);
        }
      });
      log.debug("Leaving apply().");
      return model.bag(uri, result);
    }
  } };
});

generic('union', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'bag', type: uri },
    args: [{ kind: 'bag', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      const result = [];
      values.forEach(function (source) {
        source.values.forEach(function (candidate) {
          if (!bagHas(row, result, candidate)) {
            result.push(candidate);
          }
        });
      });
      log.debug("Leaving apply().");
      return model.bag(uri, result);
    }
  } };
});

generic('at-least-one-member-of', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'bag', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      const found = values[0].values.some(function (candidate) {
        return bagHas(row, values[1].values, candidate);
      });
      log.debug("Leaving apply().");
      return boolBag(found);
    }
  } };
});

generic('subset', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'bag', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      const all = values[0].values.every(function (candidate) {
        return bagHas(row, values[1].values, candidate);
      });
      log.debug("Leaving apply().");
      return boolBag(all);
    }
  } };
});

generic('set-equals', typesWith('equal'), function (row, uri) {
  return { body: {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'bag', type: uri }, { kind: 'bag', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      // SET equality, so duplicates and order are both irrelevant — which is
      // why this is two subset tests rather than a length check and a walk.
      // `{a, a, b}` and `{a, b}` are equal sets, and a length check would
      // call them different.
      const left = values[0].values;
      const right = values[1].values;
      const forward = left.every(function (candidate) {
        return bagHas(row, right, candidate);
      });
      const backward = right.every(function (candidate) {
        return bagHas(row, left, candidate);
      });
      log.debug("Leaving apply().");
      return boolBag(forward && backward);
    }
  } };
});

// ---------------------------------------------------------------------------
// LOGICAL FUNCTIONS. Three of the ten lazy ones.
// ---------------------------------------------------------------------------

// Evaluate one argument expression and insist it is a single boolean.
function asBoolean(bag, where) {
  log.debug("Entering asBoolean().");
  if (!bag || bag.values.length !== 1) {
    throw model.processingError(
      where + ' requires each argument to be exactly one boolean; it was ' +
      'given a bag of ' + (bag ? bag.values.length : 0) + '.');
  }
  if (model.canonicalType(bag.type) !== TYPE.BOOLEAN) {
    throw model.processingError(
      where + ' requires boolean arguments; it was given ' + bag.type + '.');
  }
  log.debug("Leaving asBoolean().");
  return bag.values[0];
}

define(F1 + 'and', {
  lazy: true,
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  variadic: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [],
  // LAZY BECAUSE THE SPECIFICATION SAYS SO, AND THE REASON IS NOT SPEED.
  // A.3.5: evaluation stops at the first False, leaving the rest unevaluated.
  // So `and(false, <a designator that is missing>)` is False — where evaluating
  // both first would make it Indeterminate, and a policy would refuse where it
  // should have declined.
  apply: function (expressions, context, evaluate) {
    log.debug('Entering and(). ' + expressions.length + ' argument(s).');
    for (let i = 0; i < expressions.length; i += 1) {
      const value = asBoolean(evaluate(expressions[i], context), 'and');
      if (value === false) {
        log.debug('Leaving and(). False at argument ' + i + '.');
        return boolBag(false);
      }
    }
    // No arguments is True, per A.3.5. That is not an edge case nobody hits:
    // an empty `and` is what an <Apply> with no children evaluates to.
    log.debug('Leaving and(). True.');
    return boolBag(true);
  }
});

define(F1 + 'or', {
  lazy: true,
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  variadic: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [],
  apply: function (expressions, context, evaluate) {
    log.debug('Entering or(). ' + expressions.length + ' argument(s).');
    for (let i = 0; i < expressions.length; i += 1) {
      const value = asBoolean(evaluate(expressions[i], context), 'or');
      if (value === true) {
        log.debug('Leaving or(). True at argument ' + i + '.');
        return boolBag(true);
      }
    }
    log.debug('Leaving or(). False.');
    return boolBag(false);
  }
});

define(F1 + 'not', {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [{ kind: 'primitive', type: TYPE.BOOLEAN }],
  apply: function (values) {
    log.debug("Entering apply().");
    log.debug("Leaving apply().");
    return boolBag(!values[0]);
  }
});

define(F1 + 'n-of', {
  lazy: true,
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [{ kind: 'primitive', type: TYPE.INTEGER }],
  variadic: { kind: 'primitive', type: TYPE.BOOLEAN },
  // LAZY for `and`'s reason: A.3.5 says evaluation stops once `n` arguments
  // have been found true, so the arguments after that one are not evaluated
  // and their being Indeterminate does not matter.
  apply: function (expressions, context, evaluate) {
    log.debug('Entering nOf(). ' + expressions.length + ' argument(s).');
    if (expressions.length === 0) {
      throw model.processingError(
        'n-of requires at least one argument: the count.');
    }
    const countBag = evaluate(expressions[0], context);
    if (countBag.values.length !== 1 ||
        model.canonicalType(countBag.type) !== TYPE.INTEGER) {
      throw model.processingError(
        "n-of's first argument must be exactly one integer.");
    }
    const needed = Number(countBag.values[0]);
    const available = expressions.length - 1;
    if (needed < 0) {
      throw model.processingError('n-of was asked for ' + needed +
                                  ' true arguments.');
    }
    if (needed > available) {
      throw model.processingError(
        'n-of was asked for ' + needed + ' true arguments out of ' +
        available + ', which cannot be satisfied.');
    }
    if (needed === 0) {
      log.debug('Leaving nOf(). Zero required, so trivially true.');
      return boolBag(true);
    }
    let found = 0;
    for (let i = 1; i < expressions.length; i += 1) {
      if (asBoolean(evaluate(expressions[i], context), 'n-of') === true) {
        found += 1;
        if (found >= needed) {
          log.debug('Leaving nOf(). Reached ' + needed + '.');
          return boolBag(true);
        }
      }
    }
    log.debug('Leaving nOf(). Only ' + found + ' of ' + needed + '.');
    return boolBag(false);
  }
});

// ---------------------------------------------------------------------------
// ARITHMETIC.
//
// The integer family is BigInt and the double family is IEEE 754, and they are
// registered separately rather than sharing an implementation with a cast —
// because a shared one would have to pick a numeric representation and every
// choice loses one of the two.
// ---------------------------------------------------------------------------
function arithmetic(name, uri, arity, compute) {
  log.debug("Entering arithmetic().");
  const args = [];
  for (let i = 0; i < arity; i += 1) {
    args.push({ kind: 'primitive', type: uri });
  }
  define(F1 + name, {
    returns: { kind: 'primitive', type: uri },
    args: args,
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return model.singleton(uri, compute.apply(null, values));
    }
  });
  log.debug("Leaving arithmetic().");
}

// BigInt(0) rather than a `0n` literal: envify's esprima cannot parse one,
// and browserify fails the bundle with "Unexpected token ILLEGAL" (see
// tests/jwk_pem_encoding.js bigIntLiteralsStayOutOfTheBundles()).
var _B0 = BigInt(0);

arithmetic('integer-add', TYPE.INTEGER, 2, function (a, b) { return a + b; });
arithmetic('integer-subtract', TYPE.INTEGER, 2,
           function (a, b) { return a - b; });
arithmetic('integer-multiply', TYPE.INTEGER, 2,
           function (a, b) { return a * b; });
arithmetic('integer-abs', TYPE.INTEGER, 1,
           function (a) { return a < _B0 ? -a : a; });
arithmetic('double-add', TYPE.DOUBLE, 2, function (a, b) { return a + b; });
arithmetic('double-subtract', TYPE.DOUBLE, 2,
           function (a, b) { return a - b; });
arithmetic('double-multiply', TYPE.DOUBLE, 2,
           function (a, b) { return a * b; });
arithmetic('double-abs', TYPE.DOUBLE, 1, function (a) { return Math.abs(a); });

define(F1 + 'integer-divide', {
  returns: { kind: 'primitive', type: TYPE.INTEGER },
  args: [{ kind: 'primitive', type: TYPE.INTEGER },
         { kind: 'primitive', type: TYPE.INTEGER }],
  apply: function (values) {
    log.debug("Entering apply().");
    if (values[1] === _B0) {
      // Indeterminate rather than a crash or an Infinity. A.3.4 makes division
      // by zero an error, and a PDP that returned Infinity here would carry a
      // value no subsequent comparison could do anything sensible with.
      throw model.processingError('integer-divide by zero.');
    }
    log.debug("Leaving apply().");
    // BigInt division truncates toward zero, which is what xs:integer division
    // does. `Math.floor` would be wrong for negative operands.
    return model.singleton(TYPE.INTEGER, values[0] / values[1]);
  }
});

define(F1 + 'double-divide', {
  returns: { kind: 'primitive', type: TYPE.DOUBLE },
  args: [{ kind: 'primitive', type: TYPE.DOUBLE },
         { kind: 'primitive', type: TYPE.DOUBLE }],
  apply: function (values) {
    log.debug("Entering apply().");
    if (values[1] === 0) {
      throw model.processingError('double-divide by zero.');
    }
    log.debug("Leaving apply().");
    return model.singleton(TYPE.DOUBLE, values[0] / values[1]);
  }
});

define(F1 + 'integer-mod', {
  returns: { kind: 'primitive', type: TYPE.INTEGER },
  args: [{ kind: 'primitive', type: TYPE.INTEGER },
         { kind: 'primitive', type: TYPE.INTEGER }],
  apply: function (values) {
    log.debug("Entering apply().");
    if (values[1] === _B0) {
      throw model.processingError('integer-mod by zero.');
    }
    log.debug("Leaving apply().");
    return model.singleton(TYPE.INTEGER, values[0] % values[1]);
  }
});

define(F1 + 'round', {
  returns: { kind: 'primitive', type: TYPE.DOUBLE },
  args: [{ kind: 'primitive', type: TYPE.DOUBLE }],
  apply: function (values) {
    log.debug("Entering apply().");
    // xs:double rounding is round-half-to-EVEN, and `Math.round` is
    // round-half-up. They differ on exactly the values a test suite picks:
    // 0.5 is 0 here and 1 there, 2.5 is 2 here and 3 there.
    const value = values[0];
    if (!isFinite(value)) {
      log.debug("Leaving apply().");
      return model.singleton(TYPE.DOUBLE, value);
    }
    const floor = Math.floor(value);
    const difference = value - floor;
    let result;
    if (difference > 0.5) {
      result = floor + 1;
    } else if (difference < 0.5) {
      result = floor;
    } else {
      result = floor % 2 === 0 ? floor : floor + 1;
    }
    log.debug("Leaving apply().");
    return model.singleton(TYPE.DOUBLE, result);
  }
});

define(F1 + 'floor', {
  returns: { kind: 'primitive', type: TYPE.DOUBLE },
  args: [{ kind: 'primitive', type: TYPE.DOUBLE }],
  apply: function (values) {
    log.debug("Entering apply().");
    if (!isFinite(values[0])) {
      log.debug("Leaving apply().");
      return model.singleton(TYPE.DOUBLE, values[0]);
    }
    log.debug("Leaving apply().");
    return model.singleton(TYPE.DOUBLE, Math.floor(values[0]));
  }
});

define(F1 + 'double-to-integer', {
  returns: { kind: 'primitive', type: TYPE.INTEGER },
  args: [{ kind: 'primitive', type: TYPE.DOUBLE }],
  apply: function (values) {
    log.debug("Entering apply().");
    if (!isFinite(values[0])) {
      throw model.processingError(
        'double-to-integer cannot convert ' + values[0] + '.');
    }
    log.debug("Leaving apply().");
    // Truncation toward zero, per A.3.4 — not rounding.
    return model.singleton(TYPE.INTEGER, BigInt(Math.trunc(values[0])));
  }
});

define(F1 + 'integer-to-double', {
  returns: { kind: 'primitive', type: TYPE.DOUBLE },
  args: [{ kind: 'primitive', type: TYPE.INTEGER }],
  apply: function (values) {
    log.debug("Entering apply().");
    log.debug("Leaving apply().");
    return model.singleton(TYPE.DOUBLE, Number(values[0]));
  }
});

// ---------------------------------------------------------------------------
// STRING AND ANYURI OPERATIONS.
//
// `-contains`, `-starts-with`, `-ends-with` and `-substring` exist for both
// string and anyURI, and the anyURI ones take a STRING as the needle and an
// anyURI as the haystack — an asymmetry that is the specification's and is the
// kind of thing a generated family would get wrong, which is why these four
// are registered explicitly rather than through `generic()`.
// ---------------------------------------------------------------------------
function stringish(name, haystackType, compute) {
  log.debug("Entering stringish().");
  define(F3 + name, {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'primitive', type: TYPE.STRING },
           { kind: 'primitive', type: haystackType }],
    apply: function (values) {
      log.debug("Entering apply().");
      const haystack = haystackType === TYPE.STRING ? values[1]
                                                    : String(values[1]);
      log.debug("Leaving apply().");
      return boolBag(compute(String(values[0]), haystack));
    }
  });
  log.debug("Leaving stringish().");
}

stringish('string-contains', TYPE.STRING, function (needle, haystack) {
  return haystack.indexOf(needle) >= 0;
});
stringish('string-starts-with', TYPE.STRING, function (needle, haystack) {
  return haystack.lastIndexOf(needle, 0) === 0;
});
stringish('string-ends-with', TYPE.STRING, function (needle, haystack) {
  return needle.length <= haystack.length &&
         haystack.indexOf(needle, haystack.length - needle.length) >= 0;
});
stringish('anyURI-contains', TYPE.ANYURI, function (needle, haystack) {
  return haystack.indexOf(needle) >= 0;
});
stringish('anyURI-starts-with', TYPE.ANYURI, function (needle, haystack) {
  return haystack.lastIndexOf(needle, 0) === 0;
});
stringish('anyURI-ends-with', TYPE.ANYURI, function (needle, haystack) {
  return needle.length <= haystack.length &&
         haystack.indexOf(needle, haystack.length - needle.length) >= 0;
});

function substring(name, subjectType) {
  log.debug("Entering substring().");
  define(F3 + name, {
    returns: { kind: 'primitive', type: TYPE.STRING },
    // A LITERAL INDEX OUT OF RANGE IS A STATIC ERROR, not a runtime one, and
    // that is what conformance cases IIC332 and IIC335 assert: a policy
    // carrying `substring(uri, -2, 8)` must be REFUSED at load rather than
    // going Indeterminate for every request forever. See `xacml_validate.js`.
    staticCheck: function (args, report) {
      log.debug("Entering staticCheck().");
      const from = literalInteger(args[1]);
      const to = literalInteger(args[2]);
      if (from !== null && from < 0) {
        report(name + "'s second argument is " + from + '; a substring ' +
               'start index may not be negative.');
      }
      if (to !== null && to < -1) {
        report(name + "'s third argument is " + to + '; a substring end ' +
               'index may not be below -1 (-1 means "to the end").');
      }
      if (from !== null && to !== null && to !== -1 && to < from) {
        report(name + ' was given the range ' + from + '..' + to +
               ', which runs backwards.');
      }
      log.debug("Leaving staticCheck().");
    },
    args: [{ kind: 'primitive', type: subjectType },
           { kind: 'primitive', type: TYPE.INTEGER },
           { kind: 'primitive', type: TYPE.INTEGER }],
    apply: function (values) {
      log.debug("Entering apply().");
      const subject = String(values[0]);
      const from = Number(values[1]);
      const to = Number(values[2]);
      // A.3.10: the indices are ZERO-BASED, `to` may be -1 meaning "to the
      // end", and an index outside the string is an ERROR rather than a
      // silently clamped slice. JavaScript's `slice` clamps, which would turn
      // a policy bug into a wrong answer.
      const end = to === -1 ? subject.length : to;
      if (from < 0 || from > subject.length || end > subject.length ||
          (to !== -1 && to < from)) {
        throw model.processingError(
          name + ' was given indices ' + from + ' and ' + to +
          ' for a value of length ' + subject.length + '.');
      }
      log.debug("Leaving apply().");
      return model.singleton(TYPE.STRING, subject.slice(from, end));
    }
  });
  log.debug("Leaving substring().");
}

substring('string-substring', TYPE.STRING);
substring('anyURI-substring', TYPE.ANYURI);

define(F1 + 'string-normalize-space', {
  returns: { kind: 'primitive', type: TYPE.STRING },
  args: [{ kind: 'primitive', type: TYPE.STRING }],
  apply: function (values) {
    log.debug("Entering apply().");
    log.debug("Leaving apply().");
    // Leading and trailing whitespace only. It does NOT collapse internal
    // runs, despite the name suggesting xs:normalizeSpace, which does.
    return model.singleton(TYPE.STRING, String(values[0]).trim());
  }
});

define(F1 + 'string-normalize-to-lower-case', {
  returns: { kind: 'primitive', type: TYPE.STRING },
  args: [{ kind: 'primitive', type: TYPE.STRING }],
  apply: function (values) {
    log.debug("Entering apply().");
    log.debug("Leaving apply().");
    return model.singleton(TYPE.STRING, String(values[0]).toLowerCase());
  }
});

define(F3 + 'string-concatenate', {
  returns: { kind: 'primitive', type: TYPE.STRING },
  variadic: { kind: 'primitive', type: TYPE.STRING },
  args: [],
  apply: function (values) {
    log.debug("Entering apply().");
    log.debug("Leaving apply().");
    return model.singleton(TYPE.STRING, values.join(''));
  }
});

// The `-from-string` and `-to-string` conversions, one pair per type. Every
// one is the datatype table's own parse and write, which is what stops
// `integer-from-string` and an `<AttributeValue>` of the same lexical form
// producing two different values.
allTypes().forEach(function (uri) {
  const row = datatypes.TYPES[uri];
  define(F3 + 'string-from-' + row.name, {
    returns: { kind: 'primitive', type: TYPE.STRING },
    args: [{ kind: 'primitive', type: uri }],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return model.singleton(TYPE.STRING, row.write(values[0]));
    }
  });
  define(F3 + row.name + '-from-string', {
    returns: { kind: 'primitive', type: uri },
    args: [{ kind: 'primitive', type: TYPE.STRING }],
    apply: function (values) {
      log.debug("Entering apply().");
      log.debug("Leaving apply().");
      return model.singleton(uri, row.parse(values[0]));
    }
  });
});

// ---------------------------------------------------------------------------
// DATE AND TIME ARITHMETIC.
//
// Six functions, and the two that add a yearMonthDuration are the interesting
// ones: adding a month to the 31st does not give the 31st of the next month,
// because there may not be one. XML Schema's rule is to CLAMP to the last day
// of the target month, and an implementation that let the day overflow would
// turn 2024-01-31 plus one month into 2024-03-02.
// ---------------------------------------------------------------------------
/**
 * Adds a number of months to a date value, clamping the day to the last
 * day of the target month as XML Schema requires.
 *
 * @param value - a parsed date or dateTime value
 * @param months - the months to add, possibly negative
 * @returns a new value; the input is not changed
 */
function addMonths(value, months) {
  log.debug("Entering addMonths().");
  const total = (value.year * 12) + (value.month - 1) + months;
  const year = Math.floor(total / 12);
  const month = (total % 12 + 12) % 12 + 1;
  const day = Math.min(value.day, daysInMonth(year, month));
  log.debug("Leaving addMonths().");
  return Object.assign({}, value, { year: year, month: month, day: day });
}

function daysInMonth(year, month) {
  log.debug("Entering daysInMonth().");
  const lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month === 2 &&
      ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0)) {
    log.debug("Leaving daysInMonth().");
    return 29;
  }
  log.debug("Leaving daysInMonth().");
  return lengths[month - 1];
}

// THE ARITHMETIC IS ON THE LOCAL COMPONENTS AND THE TIMEZONE IS CARRIED
// THROUGH UNCHANGED, which is the opposite of what `instantSeconds()` does and
// is why this does not call it.
//
// `2002-03-22T08:23:47-05:00` plus `P5DT2H` is `2002-03-27T10:23:47-05:00` —
// the wall clock advances and the offset is untouched. Normalising to UTC
// first, adding, and then re-labelling the result with the original offset
// shifts it twice and lands five hours out. Cases IIC102 and IIC104 are that
// exact sum, and this implementation got it wrong in the direction that still
// produced a perfectly well-formed dateTime.
function addSeconds(value, seconds) {
  log.debug("Entering addSeconds().");
  const local = (value.shape === 'time' ? 0
                  : datatypes.daysFromCivil(value.year, value.month,
                                            value.day) * 86400) +
                value.hour * 3600 + value.minute * 60 + value.second;
  const total = local + seconds;
  const days = Math.floor(total / 86400);
  let rest = total - days * 86400;
  const hour = Math.floor(rest / 3600);
  rest -= hour * 3600;
  const minute = Math.floor(rest / 60);
  const second = rest - minute * 60;
  const civil = civilFromDays(days);
  log.debug("Leaving addSeconds().");
  return { shape: value.shape, year: civil.year, month: civil.month,
           day: civil.day, hour: hour, minute: minute, second: second,
           tz: value.tz };
}

// The inverse of `daysFromCivil()` in the datatype table, and it lives here
// rather than there because only this file needs it — date arithmetic is the
// only thing that turns a day count back into a date.
/**
 * Converts a count of days since 1970-01-01 to a civil date.
 *
 * The inverse of `daysFromCivil()` in `xacml_datatypes.js`.
 * @param days - the day count
 * @returns an object with `year`, `month` and `day`
 */
function civilFromDays(days) {
  log.debug("Entering civilFromDays().");
  const z = days + 719468;
  const era = Math.floor((z >= 0 ? z : z - 146096) / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) +
                          Math.floor(doe / 36524) -
                          Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp + (mp < 10 ? 3 : -9);
  log.debug("Leaving civilFromDays().");
  return { year: y + (m <= 2 ? 1 : 0), month: m, day: d };
}

function temporalArithmetic(name, subjectType, durationType, sign) {
  log.debug("Entering temporalArithmetic().");
  define(F3 + name, {
    returns: { kind: 'primitive', type: subjectType },
    args: [{ kind: 'primitive', type: subjectType },
           { kind: 'primitive', type: durationType }],
    apply: function (values) {
      log.debug("Entering apply().");
      const subject = values[0];
      const duration = values[1];
      let result;
      if (durationType === TYPE.YEARMONTH_DURATION) {
        result = addMonths(subject, sign * duration.months);
      } else {
        result = addSeconds(subject, sign * duration.seconds);
      }
      log.debug("Leaving apply().");
      return model.singleton(subjectType, result);
    }
  });
  log.debug("Leaving temporalArithmetic().");
}

temporalArithmetic('dateTime-add-dayTimeDuration', TYPE.DATETIME,
                   TYPE.DAYTIME_DURATION, 1);
temporalArithmetic('dateTime-subtract-dayTimeDuration', TYPE.DATETIME,
                   TYPE.DAYTIME_DURATION, -1);
temporalArithmetic('dateTime-add-yearMonthDuration', TYPE.DATETIME,
                   TYPE.YEARMONTH_DURATION, 1);
temporalArithmetic('dateTime-subtract-yearMonthDuration', TYPE.DATETIME,
                   TYPE.YEARMONTH_DURATION, -1);
temporalArithmetic('date-add-yearMonthDuration', TYPE.DATE,
                   TYPE.YEARMONTH_DURATION, 1);
temporalArithmetic('date-subtract-yearMonthDuration', TYPE.DATE,
                   TYPE.YEARMONTH_DURATION, -1);

// ---------------------------------------------------------------------------
// REGULAR EXPRESSIONS.
//
// XACML uses the XML Schema regular expression language, which is NOT
// JavaScript's. Four differences matter and each one silently changes what a
// policy matches:
//
//   1. AN XML SCHEMA REGEX IS ANCHORED. `bc` matches the string `bc` and not
//      `abcd`. JavaScript's is unanchored, so a policy meant to match one
//      resource would match every resource containing its name — which is a
//      permit granted far too widely, and the single most dangerous defect in
//      this file.
//   2. `\i` and `\c` are XML name-character classes that JavaScript has no
//      equivalent for.
//   3. A hyphen inside a character class can be a class-subtraction operator.
//   4. `.` excludes the line terminators, as it does in JavaScript, so that
//      one agrees.
//
// This handles 1 and 2, which are what the conformance suite exercises, and
// refuses rather than guessing on 3 — a class subtraction silently
// mistranslated is a regex that matches the wrong things.
// ---------------------------------------------------------------------------
/**
 * Translates an XML Schema regular expression into an anchored JavaScript
 * RegExp.
 *
 * Handles the anchoring and the `\i` and `\c` classes.
 * @param pattern - the XML Schema pattern
 * @returns the RegExp
 * @throws a processing error for character class subtraction, which is
 *   refused rather than approximated
 */
function xmlSchemaRegExp(pattern) {
  log.debug('Entering xmlSchemaRegExp().');
  if (/\[[^\]]*-\[/.test(pattern)) {
    log.debug('Leaving xmlSchemaRegExp(). Class subtraction refused.');
    throw model.processingError(
      'The regular expression "' + pattern + '" uses XML Schema character ' +
      'class subtraction, which has no JavaScript equivalent and is not ' +
      'translated here. Refused rather than approximated, because a regex ' +
      'that matches almost the right things is worse than one that fails.');
  }
  // \i is a letter, underscore or colon — the characters an XML name may
  // start with. \c is those plus digits, hyphen and full stop.
  const translated = pattern
    .replace(/\\i/g, '[A-Za-z_:]')
    .replace(/\\I/g, '[^A-Za-z_:]')
    .replace(/\\c/g, '[A-Za-z0-9_:.\\-]')
    .replace(/\\C/g, '[^A-Za-z0-9_:.\\-]');
  // ANCHORED — difference 1. The `^(?:` … `)$` wrapping rather than bare `^`
  // and `$` so that a top-level alternation in the pattern cannot escape the
  // anchors: `^a|b$` anchors only two of the branches.
  log.debug('Leaving xmlSchemaRegExp(). Translated and anchored.');
  return new RegExp('^(?:' + translated + ')$');
}

function regexpMatch(name, subjectType, subjectText) {
  log.debug("Entering regexpMatch().");
  define((subjectType === TYPE.STRING ? F1 : F2) + name, {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    args: [{ kind: 'primitive', type: TYPE.STRING },
           { kind: 'primitive', type: subjectType }],
    apply: function (values) {
      log.debug("Entering apply().");
      const expression = xmlSchemaRegExp(String(values[0]));
      log.debug("Leaving apply().");
      return boolBag(expression.test(subjectText(values[1])));
    }
  });
  log.debug("Leaving regexpMatch().");
}

regexpMatch('string-regexp-match', TYPE.STRING, function (v) {
  return String(v);
});
regexpMatch('anyURI-regexp-match', TYPE.ANYURI, function (v) {
  return String(v);
});
regexpMatch('rfc822Name-regexp-match', TYPE.RFC822NAME, function (v) {
  return v.local + '@' + v.domain;
});
regexpMatch('x500Name-regexp-match', TYPE.X500NAME, function (v) {
  return datatypes.writeValue(TYPE.X500NAME, v);
});
regexpMatch('dnsName-regexp-match', TYPE.DNSNAME, function (v) {
  return datatypes.writeValue(TYPE.DNSNAME, v);
});
regexpMatch('ipAddress-regexp-match', TYPE.IPADDRESS, function (v) {
  return datatypes.writeValue(TYPE.IPADDRESS, v);
});

// ---------------------------------------------------------------------------
// THE TWO SPECIAL MATCH FUNCTIONS.
//
// Neither is equality and neither is a regex. They are the two places XACML
// defines a domain-specific "does this name match this pattern", and both are
// asymmetric — the pattern is the first argument and the value the second, and
// swapping them changes the answer.
// ---------------------------------------------------------------------------
define(F1 + 'rfc822Name-match', {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [{ kind: 'primitive', type: TYPE.STRING },
         { kind: 'primitive', type: TYPE.RFC822NAME }],
  apply: function (values) {
    log.debug("Entering apply().");
    const pattern = String(values[0]);
    const name = values[1];
    // A.3.14 defines three shapes of pattern, and they are genuinely
    // different rather than three spellings of one:
    if (pattern.indexOf('@') >= 0) {
      // A whole address: the local part matches exactly (case-sensitively)
      // and the domain case-insensitively.
      const at = pattern.lastIndexOf('@');
      const local = pattern.slice(0, at);
      const domain = pattern.slice(at + 1).toLowerCase();
      log.debug("Leaving apply().");
      return boolBag(local === name.local && domain === name.domain);
    }
    if (pattern.charAt(0) === '.') {
      log.debug("Leaving apply().");
      // A sub-domain pattern: the value's domain must END with it. `.acme.com`
      // matches `bob@sales.acme.com` and NOT `bob@acme.com` — the leading dot
      // means "strictly below", which is the half that gets implemented as a
      // plain `endsWith` and then matches the domain itself.
      return boolBag(name.domain.endsWith(pattern.toLowerCase()));
    }
    log.debug("Leaving apply().");
    // A bare domain: the value's domain must equal it.
    return boolBag(name.domain === pattern.toLowerCase());
  }
});

define(F1 + 'x500Name-match', {
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
  args: [{ kind: 'primitive', type: TYPE.X500NAME },
         { kind: 'primitive', type: TYPE.X500NAME }],
  apply: function (values) {
    log.debug("Entering apply().");
    // A.3.13: true when the first name is the TERMINAL SEQUENCE of the second
    // — that is, the first is an ancestor of or equal to the second in the
    // directory tree. `O=Acme` matches `CN=bob,O=Acme` and not the reverse.
    const pattern = values[0].rdns;
    const subject = values[1].rdns;
    if (pattern.length > subject.length) {
      log.debug("Leaving apply().");
      return boolBag(false);
    }
    const offset = subject.length - pattern.length;
    for (let i = 0; i < pattern.length; i += 1) {
      const a = pattern[i];
      const b = subject[offset + i];
      if (a.attribute !== b.attribute ||
          a.value.toLowerCase() !== b.value.toLowerCase()) {
        log.debug("Leaving apply().");
        return boolBag(false);
      }
    }
    log.debug("Leaving apply().");
    return boolBag(true);
  }
});

// ---------------------------------------------------------------------------
// THE HIGHER-ORDER FUNCTIONS.
//
// Six of them plus `map`, and all are lazy because their FIRST argument is a
// function reference rather than a value. The six differ only in which side is
// quantified over and how, which is why they are one implementation and a
// table — and why their names are so easy to mix up:
//
//   any-of      one value against a bag; true if the function holds for ANY
//   all-of      one value against a bag; true if it holds for ALL
//   any-of-any  two bags; true if it holds for ANY pair
//   all-of-any  true if, for every member of the FIRST bag, it holds for
//               SOME member of the second
//   any-of-all  true if, for every member of the SECOND bag, it holds for
//               SOME member of the first
//   all-of-all  true if it holds for EVERY pair
//
// `all-of-any` and `any-of-all` are mirror images and are the pair that gets
// swapped. The names read backwards from what they do: `all-of-any` quantifies
// ALL over the first bag, not over the "any".
// ---------------------------------------------------------------------------
function functionReference(expression, context, evaluate, where) {
  log.debug("Entering functionReference().");
  if (!expression || expression.kind !== 'function') {
    throw model.processingError(
      where + " requires a <Function> as its first argument.");
  }
  const definition = ownMembers.read(FUNCTIONS, expression.functionId);
  if (!definition) {
    throw model.processingError(
      'Unknown function "' + expression.functionId + '" passed to ' + where +
      '.');
  }
  log.debug("Leaving functionReference().");
  return definition;
}

// Apply a resolved function definition to two already-resolved single values.
function applyPair(definition, left, right, context) {
  log.debug("Entering applyPair().");
  const result = invoke(definition, [model.singleton(left.type, left.value),
                                     model.singleton(right.type, right.value)],
                        context);
  log.debug("Leaving applyPair().");
  return asBoolean(result, definition.uri);
}

// THE SIX SPLIT ACROSS TWO VERSION SEGMENTS AND THE SPLIT LOOKS ARBITRARY.
// `any-of`, `all-of` and `any-of-any` are 3.0; `all-of-all`, `all-of-any` and
// `any-of-all` are 1.0, because those three existed in XACML 1.0 and the other
// three were re-specified in 3.0 to take their bag argument either way round.
// So the prefix is per function rather than per family, and it is passed in.
// Verified against the OASIS conformance suite, which uses all six.
function higherOrder(prefix, name, combine) {
  log.debug("Entering higherOrder().");
  define(prefix + name, {
    lazy: true,
    returns: { kind: 'primitive', type: TYPE.BOOLEAN },
    // `any-of` and `all-of` take their bag either way round in XACML 3.0, so
    // the two value parameters are declared `any`: a stricter declaration
    // would REFUSE a legal policy at load, which is a far worse failure than
    // missing a type error at load. The strict check still happens at
    // evaluation, where the actual bags are in hand.
    args: [{ kind: 'function' }, { kind: 'any' }, { kind: 'any' }],
    apply: function (expressions, context, evaluate) {
      log.debug('Entering higherOrder(). name=' + name);
      const definition = functionReference(expressions[0], context, evaluate,
                                           name);
      const bags = expressions.slice(1).map(function (expression) {
        return evaluate(expression, context);
      });
      const answer = combine(definition, bags, context);
      log.debug('Leaving higherOrder(). ' + answer);
      return boolBag(answer);
    }
  });
  log.debug("Leaving higherOrder().");
}

// `any-of` and `all-of` take one value and one bag — and either way round,
// because XACML 3.0 allows the bag to be the first or the second argument.
// Which is which is decided by which argument has more than one value, and
// where both are bags of one it does not matter.
function oneAgainstBag(definition, bags, context, quantifier) {
  log.debug("Entering oneAgainstBag().");
  const first = bags[0];
  const second = bags[1];
  const valueFirst = first.values.length === 1 && second.values.length !== 1;
  const single = valueFirst ? first : second;
  const many = valueFirst ? second : first;
  const test = many.values.map(function (candidate) {
    const pair = valueFirst
      ? [{ type: single.type, value: single.values[0] },
         { type: many.type, value: candidate }]
      : [{ type: many.type, value: candidate },
         { type: single.type, value: single.values[0] }];
    return applyPair(definition, pair[0], pair[1], context);
  });
  log.debug("Leaving oneAgainstBag().");
  return quantifier === 'any' ? test.some(Boolean) : test.every(Boolean);
}

higherOrder(F3, 'any-of', function (definition, bags, context) {
  return oneAgainstBag(definition, bags, context, 'any');
});
higherOrder(F3, 'all-of', function (definition, bags, context) {
  return oneAgainstBag(definition, bags, context, 'all');
});

higherOrder(F3, 'any-of-any', function (definition, bags, context) {
  return bags[0].values.some(function (left) {
    return bags[1].values.some(function (right) {
      return applyPair(definition, { type: bags[0].type, value: left },
                       { type: bags[1].type, value: right }, context);
    });
  });
});

higherOrder(F1, 'all-of-all', function (definition, bags, context) {
  return bags[0].values.every(function (left) {
    return bags[1].values.every(function (right) {
      return applyPair(definition, { type: bags[0].type, value: left },
                       { type: bags[1].type, value: right }, context);
    });
  });
});

higherOrder(F1, 'all-of-any', function (definition, bags, context) {
  // For EVERY member of the first bag, SOME member of the second satisfies it.
  return bags[0].values.every(function (left) {
    return bags[1].values.some(function (right) {
      return applyPair(definition, { type: bags[0].type, value: left },
                       { type: bags[1].type, value: right }, context);
    });
  });
});

higherOrder(F1, 'any-of-all', function (definition, bags, context) {
  // The mirror image: for EVERY member of the SECOND bag, SOME member of the
  // first satisfies it.
  return bags[1].values.every(function (right) {
    return bags[0].values.some(function (left) {
      return applyPair(definition, { type: bags[0].type, value: left },
                       { type: bags[1].type, value: right }, context);
    });
  });
});

define(F3 + 'map', {
  lazy: true,
  // The element type of the result is whatever the mapped function returns,
  // which is not knowable from this declaration — `type: null` is how the
  // validator is told "a bag, of something I cannot name here" and is why it
  // skips the type half of the check rather than guessing.
  returns: { kind: 'bag', type: null },
  args: [{ kind: 'function' }, { kind: 'bag' }],
  apply: function (expressions, context, evaluate) {
    log.debug('Entering map().');
    const definition = functionReference(expressions[0], context, evaluate,
                                         'map');
    const bags = expressions.slice(1).map(function (expression) {
      return evaluate(expression, context);
    });
    // The LAST bag is the one mapped over; any earlier arguments are passed
    // through unchanged to every application. With one bag that is just "apply
    // to each member", which is what almost every use looks like.
    const target = bags[bags.length - 1];
    const fixed = bags.slice(0, bags.length - 1);
    let resultType = null;
    const values = target.values.map(function (candidate) {
      const args = fixed.concat([model.singleton(target.type, candidate)]);
      const produced = invoke(definition, args, context);
      if (produced.values.length !== 1) {
        throw model.processingError(
          'map expects its function to produce exactly one value per ' +
          'member; ' + definition.uri + ' produced ' +
          produced.values.length + '.');
      }
      resultType = produced.type;
      return produced.values[0];
    });
    log.debug('Leaving map(). ' + values.length + ' value(s).');
    // An empty input bag gives an empty output bag, and its TYPE is then
    // unknowable from the data — the function's declared return type is the
    // only source. Falling back to the input's type would be wrong for a
    // mapping that changes type, which is most of them.
    return model.bag(resultType || declaredReturnType(definition) ||
                     target.type, values);
  }
});

function declaredReturnType(definition) {
  log.debug("Entering declaredReturnType().");
  log.debug("Leaving declaredReturnType().");
  return definition.returns || null;
}

// ---------------------------------------------------------------------------
// XPATH.
//
// One function, and it is here rather than in the optional set because the
// conformance suite's IIF cases reach it. It needs the request's <Content>,
// which only the evaluation context has — so it is given the context and is
// the only function in this file that reads anything but its arguments.
// ---------------------------------------------------------------------------
define(F3 + 'xpath-node-count', {
  needsContext: true,
  returns: { kind: 'primitive', type: TYPE.INTEGER },
  args: [{ kind: 'primitive', type: TYPE.XPATH_EXPRESSION }],
  apply: function (values, context) {
    log.debug('Entering xpathNodeCount().');
    if (!context || typeof context.countNodes !== 'function') {
      throw model.processingError(
        'xpath-node-count needs a request context that can reach <Content>; ' +
        'this evaluation was given none.');
    }
    const count = context.countNodes(values[0]);
    log.debug('Leaving xpathNodeCount(). ' + count + ' node(s).');
    return intBag(count);
  }
});

// ---------------------------------------------------------------------------
// INVOKE A FUNCTION WITH ALREADY-RESOLVED ARGUMENT BAGS.
//
// This is where the `primitive` / `bag` distinction the header warns about is
// actually enforced, in ONE place — so a function definition cannot forget to
// check, because it never sees an unchecked argument.
// ---------------------------------------------------------------------------
/**
 * Invokes a function with already-resolved argument bags.
 *
 * Checks the arity, and hands a `primitive` parameter its one value; a
 * bag of any other size is a processing error.
 * @param definition - the function's entry in `FUNCTIONS`
 * @param argumentBags - one bag per argument
 * @param context - the evaluation context, for functions that need one
 * @returns the result bag
 * @throws a processing error on wrong arity or a primitive argument whose
 *   bag does not hold exactly one value
 */
function invoke(definition, argumentBags, context) {
  log.debug('Entering invoke(). uri=' + definition.uri);
  const expected = definition.args || [];
  const variadic = definition.variadic || null;
  if (!variadic && argumentBags.length !== expected.length) {
    log.debug('Leaving invoke(). Wrong arity.');
    throw model.processingError(
      definition.uri + ' takes ' + expected.length + ' argument(s) and was ' +
      'given ' + argumentBags.length + '.');
  }
  if (variadic && argumentBags.length < expected.length) {
    log.debug('Leaving invoke(). Too few arguments.');
    throw model.processingError(
      definition.uri + ' takes at least ' + expected.length +
      ' argument(s) and was given ' + argumentBags.length + '.');
  }
  const resolved = argumentBags.map(function (bag, index) {
    const declaration = index < expected.length ? expected[index] : variadic;
    if (declaration.kind === 'bag') {
      return bag;
    }
    // A PRIMITIVE parameter. Exactly one value, or Indeterminate — see the
    // header. This is the check that stops a two-element bag being silently
    // truncated to its first member.
    if (bag.values.length !== 1) {
      throw model.processingError(
        definition.uri + ' expects exactly one value for argument ' +
        (index + 1) + ' and was given a bag of ' + bag.values.length + '.');
    }
    return bag.values[0];
  });
  const result = definition.needsContext
    ? definition.apply(resolved, context)
    : definition.apply(resolved, context);
  log.debug('Leaving invoke(). uri=' + definition.uri);
  return result;
}

/**
 * Returns the function registered for an identifier.
 *
 * @param uri - the function identifier
 * @returns the definition, or null when the identifier is unknown
 */
function lookup(uri) {
  log.debug("Entering lookup().");
  log.debug("Leaving lookup().");
  // An own member only (2026-11-12): a policy naming `toString` names no
  // function.
  return ownMembers.read(FUNCTIONS, uri) || null;
}

/**
 * Lists every registered function identifier.
 *
 * @returns the identifiers, sorted
 */
function names() {
  log.debug("Entering names().");
  log.debug("Leaving names().");
  return Object.keys(FUNCTIONS).sort();
}

/**
 * The XACML 3.0 standard function library, generated over the datatype
 * table rather than written out.
 *
 * Every value is a bag; `invoke()` enforces the primitive / bag
 * distinction in one place.
 * @namespace
 */
module.exports = {
  FUNCTIONS: FUNCTIONS,
  lookup: lookup,
  names: names,
  invoke: invoke,
  xmlSchemaRegExp: xmlSchemaRegExp,
  civilFromDays: civilFromDays,
  addMonths: addMonths
};
