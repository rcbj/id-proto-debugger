// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_json.js
//
// ---------------------------------------------------------------------------
// THE JSON PROFILE OF XACML 3.0 (v1.1), WHICH IS WHAT ANYBODY ACTUALLY SENDS.
//
// The core specification is XML and almost nothing speaks it on the wire any
// more: a PEP posts JSON to a PDP endpoint, which is what the REST Profile
// says and what every current implementation offers. So this file is the
// SECOND of the three readers over `xacml_model.js` — see that file's header
// for why there is one model and three renderings rather than three parsers.
//
// It reads a REQUEST and writes a RESPONSE, and it does not read or write
// policies. The JSON Profile does not define a policy syntax at all: policies
// stay XML (or ALFA, through `xacml_alfa.js`), and the profile covers only
// the decision exchange. That surprises people who expect symmetry, so it is
// worth saying rather than leaving them to look for the missing half.
//
// ---------------------------------------------------------------------------
// FOUR THINGS THIS PROFILE DOES THAT XML DOES NOT, AND ALL FOUR ARE TRAPS.
//
// 1. THE DATATYPE IS OPTIONAL AND IS INFERRED FROM THE JSON TYPE. A bare
//    `"Value": 5` is an integer and `"Value": 5.0` is... also an integer,
//    because JSON has ONE number type and `JSON.parse` gives back `5` for
//    both. The profile's answer (section 3.3.3) is that a number is an integer
//    unless it has a fractional part or an exponent, which cannot be recovered
//    from the parsed value — so `looksLikeDouble()` reads the RAW TEXT. An
//    implementation that inferred from `Number.isInteger()` alone types
//    `5.0` as an integer, and `integer-equal` against a double then fails the
//    static type check for a reason the author cannot see in their own JSON.
//
// 2. THE CATEGORY HAS SHORTHAND NAMES. `"AccessSubject"` means
//    `urn:oasis:names:tc:xacml:1.0:subject-category:access-subject`, and the
//    four standard ones each have one. A request may ALSO use the generic
//    `"Category"` array with explicit `CategoryId`s, and may use both at once.
//
// 3. THE DATATYPE MAY BE A SHORT NAME TOO. `"DataType": "integer"` is legal
//    and means the XML Schema URI. Both spellings appear in real requests.
//
// 4. A VALUE MAY BE AN ARRAY, AND THAT IS A BAG rather than a single value of
//    an array type. `"Value": ["a", "b"]` is a two-element bag; there is no
//    array datatype in XACML.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY REFUSED.
//
// An unknown datatype short name, a category with no attributes, a `Value`
// that is an object, and a request that is not an object with a `Request`
// member. All of them are a 400 rather than an Indeterminate: a malformed
// REQUEST is the caller's mistake and telling them so is more use than a
// decision they will read as an authorization answer. A well-formed request
// that the POLICY cannot decide about is the Indeterminate case, and that one
// comes back as a 200 carrying a Response — which is the distinction a PEP
// needs and the one most easily collapsed.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const ownMembers = require('./xacml_own_members');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');

// ---------------------------------------------------------------------------
// THE SHORTHAND CATEGORY NAMES (section 4.2.1).
// ---------------------------------------------------------------------------
/**
 * The JSON Profile's shorthand category names (section 4.2.1), each mapped
 * to its category URI.
 */
const SHORTHAND_CATEGORY = {
  AccessSubject: model.CATEGORY.ACCESS_SUBJECT,
  RecipientSubject: model.CATEGORY.RECIPIENT_SUBJECT,
  IntermediarySubject: model.CATEGORY.INTERMEDIARY_SUBJECT,
  Codebase: model.CATEGORY.CODEBASE,
  RequestingMachine: model.CATEGORY.REQUESTING_MACHINE,
  Resource: model.CATEGORY.RESOURCE,
  Action: model.CATEGORY.ACTION,
  Environment: model.CATEGORY.ENVIRONMENT
};

// ---------------------------------------------------------------------------
// THE SHORT DATATYPE NAMES (section 3.3.2).
//
// Built from the datatype table rather than written out, because the short
// name IS `row.name` — which is the one place in this directory where deriving
// an identifier is safe, since both sides come from the same table. A second
// hand-written list here would be a second chance to disagree with
// `xacml_datatypes.js` about what `dayTimeDuration` is called.
// ---------------------------------------------------------------------------
/**
 * The JSON Profile's short datatype names (section 3.3.2), each mapped to its
 * datatype URI; built from `xacml_datatypes.js`'s table.
 */
const SHORT_TYPE = {};
Object.keys(datatypes.TYPES).forEach(function (uri) {
  SHORT_TYPE[datatypes.TYPES[uri].name] = uri;
});

/**
 * Resolves a `DataType` member, given as a datatype URI or a short name, to
 * a canonical datatype URI.
 * @param name - a datatype URI or short name
 * @returns the datatype URI, or null when absent or unknown
 */
function resolveType(name) {
  log.debug("Entering resolveType().");
  if (!name) {
    log.debug("Leaving resolveType().");
    return null;
  }
  const text = String(name);
  if (datatypes.typeOf(text)) {
    log.debug("Leaving resolveType().");
    return model.canonicalType(text);
  }
  // An own member only (2026-11-12): `DataType: "constructor"` is an
  // unknown datatype, refused as one, and never Object.
  const short = ownMembers.read(SHORT_TYPE, text);
  if (short) {
    log.debug("Leaving resolveType().");
    return short;
  }
  log.debug("Leaving resolveType().");
  return null;
}

// ---------------------------------------------------------------------------
// THE DATATYPE OF A VALUE THAT DID NOT DECLARE ONE.
//
// `raw` is the value as `JSON.parse` produced it; `text` is the ORIGINAL
// source text for it where the caller could recover one. See trap 1: the text
// is the only place the difference between `5` and `5.0` survives.
// ---------------------------------------------------------------------------
/**
 * Infers the datatype of a value that declared none, from its JSON type.
 *
 * A number is a double only when its source text has a fractional part or
 * an exponent, so `5.0` needs `text` to be told from `5`. A string is never
 * sniffed for anything but a string.
 * @param raw - the value as `JSON.parse` produced it
 * @param text - the value's original source text, where recoverable
 * @returns a datatype URI, or null for a value of no inferable type
 */
function inferType(raw, text) {
  log.debug('Entering inferType(). typeof=' + typeof raw);
  if (typeof raw === 'boolean') {
    log.debug('Leaving inferType(). boolean.');
    return model.TYPE.BOOLEAN;
  }
  if (typeof raw === 'number') {
    const looksLikeDouble = text !== null && text !== undefined &&
                            /[.eE]/.test(String(text));
    log.debug('Leaving inferType(). ' +
              (looksLikeDouble ? 'double.' : 'integer.'));
    return looksLikeDouble ? model.TYPE.DOUBLE : model.TYPE.INTEGER;
  }
  if (typeof raw === 'string') {
    // A string is a string. The profile does NOT sniff for something that
    // looks like a date, and neither does this — `"2026-09-04"` in a request
    // with no DataType is the STRING `2026-09-04`, and a policy comparing it
    // with `date-equal` gets a static type error rather than a silent
    // coercion. Guessing here would make the same request mean two things
    // depending on its content.
    log.debug('Leaving inferType(). string.');
    return model.TYPE.STRING;
  }
  log.debug('Leaving inferType(). Not inferable.');
  return null;
}

// The source text for each attribute value, recovered by a shallow re-scan of
// the raw body. Only numbers need it — see trap 1 — so this looks for the
// number tokens and nothing else, and returns null when it cannot be sure.
function numericTexts(body) {
  log.debug('Entering numericTexts().');
  const found = [];
  const pattern = /"Value"\s*:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let match = pattern.exec(body);
  while (match) {
    found.push(match[1]);
    match = pattern.exec(body);
  }
  log.debug('Leaving numericTexts(). ' + found.length + ' number(s).');
  return found;
}

// ---------------------------------------------------------------------------
// ONE ATTRIBUTE.
// ---------------------------------------------------------------------------
function readAttribute(source, numbers, counter) {
  log.debug('Entering readAttribute().');
  if (!source || typeof source !== 'object') {
    throw model.syntaxError('An Attribute must be an object.');
  }
  const attributeId = source.AttributeId;
  if (!attributeId || typeof attributeId !== 'string') {
    throw model.syntaxError('An Attribute must carry a string AttributeId.');
  }
  // Trap 4: an array is a BAG, not a value of an array type.
  const raw = Object.prototype.hasOwnProperty.call(source, 'Value')
    ? source.Value : null;
  const list = Array.isArray(raw) ? raw : [raw];
  const declared = resolveType(source.DataType);
  if (source.DataType && !declared) {
    throw model.syntaxError(
      'Unknown DataType "' + source.DataType + '" on attribute "' +
      attributeId + '". Use a XACML datatype URI or one of its short names ' +
      '(' + Object.keys(SHORT_TYPE).sort().join(', ') + ').');
  }
  const values = list.map(function (one) {
    if (one !== null && typeof one === 'object') {
      throw model.syntaxError(
        'The Value of attribute "' + attributeId + '" is an object. XACML ' +
        'has no structured datatype reachable this way; use Content and an ' +
        'AttributeSelector instead.');
    }
    const text = typeof one === 'number'
      ? (counter.index < numbers.length ? numbers[counter.index] : null)
      : null;
    if (typeof one === 'number') {
      counter.index += 1;
    }
    const type = declared || inferType(one, text);
    if (!type) {
      throw model.syntaxError(
        'The Value of attribute "' + attributeId + '" has no DataType and ' +
        'none can be inferred from it.');
    }
    return { type: type, lexical: lexicalOf(one, type) };
  });
  log.debug('Leaving readAttribute(). ' + values.length + ' value(s).');
  return { attributeId: attributeId,
           issuer: source.Issuer || null,
           includeInResult: source.IncludeInResult === true,
           values: values };
}

// The LEXICAL form a JSON value denotes, which is what the model holds — see
// `xacml_xml.js`'s header for why values are carried lexically and parsed at
// evaluation. A JSON boolean is `true`/`false` rather than `True`, and a JSON
// number is its own decimal text.
function lexicalOf(raw, type) {
  log.debug("Entering lexicalOf().");
  if (raw === null || raw === undefined) {
    log.debug("Leaving lexicalOf().");
    return '';
  }
  if (typeof raw === 'boolean') {
    log.debug("Leaving lexicalOf().");
    return raw ? 'true' : 'false';
  }
  log.debug("Leaving lexicalOf().");
  return String(raw);
}

// ---------------------------------------------------------------------------
// A REQUEST.
//
// `body` is the RAW TEXT and `parsed` the object, and both are needed: the
// object is the request and the text is the only place the integer/double
// distinction survives. A caller with only the object gets the profile's
// documented behaviour minus trap 1, which is why `parseRequest()` takes text.
// ---------------------------------------------------------------------------
/**
 * Reads a JSON Profile request into the model's request shape.
 * @param body - the raw request text (preferred, since only the text keeps
 * the integer/double distinction) or an already parsed object
 * @returns `{ returnPolicyIdList, combinedDecision, categories }`, each
 * category `{ category, id, content, attributes }`
 * @throws an IndeterminateError with the syntax-error status when the body
 * is not JSON, has no `Request` member or holds a malformed category
 */
function parseRequest(body) {
  log.debug('Entering parseRequest().');
  let parsed;
  try {
    parsed = typeof body === 'string' ? JSON.parse(body) : body;
  } catch (error) {
    log.debug('Leaving parseRequest(). Not JSON.');
    throw model.syntaxError('The request is not valid JSON: ' +
                            error.message);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.Request ||
      typeof parsed.Request !== 'object') {
    log.debug('Leaving parseRequest(). No Request member.');
    throw model.syntaxError(
      'A JSON Profile request is an object with a "Request" member.');
  }
  const request = parsed.Request;
  const numbers = typeof body === 'string' ? numericTexts(body) : [];
  const counter = { index: 0 };
  const categories = [];

  function addCategory(categoryId, source) {
    log.debug("Entering addCategory().");
    if (!source) {
      log.debug("Leaving addCategory().");
      return;
    }
    const list = Array.isArray(source) ? source : [source];
    list.forEach(function (one) {
      if (!one || typeof one !== 'object') {
        throw model.syntaxError('A category must be an object.');
      }
      const attributes = one.Attribute
        ? (Array.isArray(one.Attribute) ? one.Attribute : [one.Attribute])
        : [];
      categories.push({
        category: categoryId || one.CategoryId,
        id: one.Id || null,
        // <Content> is XML and reaches the JSON profile as a string. It is
        // carried through unparsed: nothing in this phase evaluates an
        // AttributeSelector, and parsing it here to throw it away would be a
        // second XML parser in a file that has no business owning one.
        content: one.Content || null,
        attributes: attributes.map(function (attribute) {
          return readAttribute(attribute, numbers, counter);
        })
      });
    });
    log.debug("Leaving addCategory().");
  }

  // The shorthand names first, then the generic array — a request may use
  // both, and the profile does not say one wins, because they name different
  // categories. Duplicates across the two are left as duplicates rather than
  // merged: two `Attributes` elements of the same category is a legal request
  // (it is how the Multiple Decision Profile's scheme 2.3 works) and merging
  // them would silently change what a policy sees.
  Object.keys(SHORTHAND_CATEGORY).forEach(function (name) {
    if (request[name]) {
      addCategory(SHORTHAND_CATEGORY[name], request[name]);
    }
  });
  if (request.Category) {
    const list = Array.isArray(request.Category) ? request.Category
                                                 : [request.Category];
    list.forEach(function (one) {
      if (!one || !one.CategoryId) {
        throw model.syntaxError(
          'An entry in "Category" must carry a CategoryId.');
      }
      addCategory(one.CategoryId, one);
    });
  }
  log.debug('Leaving parseRequest(). ' + categories.length + ' category(ies).');
  return {
    returnPolicyIdList: request.ReturnPolicyIdList === true,
    combinedDecision: request.CombinedDecision === true,
    categories: categories
  };
}

// ---------------------------------------------------------------------------
// A RESPONSE.
//
// The decision is one of the FOUR external values — `xacml_pdp.js` has already
// folded the extended Indeterminate down by the time anything reaches here,
// and this file must never see `Indeterminate{D}`. If it ever does, the single
// `externalDecision()` call site rule in `xacml_model.js` has been broken.
// ---------------------------------------------------------------------------
/**
 * Writes a PDP decision as a JSON Profile response.
 *
 * The status message is carried only on a non-ok status; obligations,
 * advice and the policy identifier list are written when present.
 * @param decision - the PDP's result, whose decision is one of the four
 * external values
 * @returns an object of the shape `{ Response: [result] }`
 */
function writeResponse(decision) {
  log.debug('Entering writeResponse(). ' + decision.decision);
  const result = { Decision: decision.decision };
  const status = decision.status || { code: model.STATUS.OK };
  result.Status = { StatusCode: { Value: status.code } };
  if (status.message && status.code !== model.STATUS.OK) {
    // The message is carried on an Indeterminate and dropped on a Permit or a
    // Deny — a status message beside a decision reads as a caveat on it, and
    // there is none.
    result.Status.StatusMessage = status.message;
  }
  if (decision.obligations && decision.obligations.length) {
    result.Obligations = decision.obligations.map(writeObligation);
  }
  if (decision.advice && decision.advice.length) {
    result.AssociatedAdvice = decision.advice.map(writeObligation);
  }
  if (decision.policyIdentifiers && decision.policyIdentifiers.length) {
    const policies = decision.policyIdentifiers.filter(function (one) {
      return one.kind === 'Policy';
    });
    const sets = decision.policyIdentifiers.filter(function (one) {
      return one.kind === 'PolicySet';
    });
    result.PolicyIdentifierList = {};
    if (policies.length) {
      result.PolicyIdentifierList.PolicyIdReference =
        policies.map(referenceOf);
    }
    if (sets.length) {
      result.PolicyIdentifierList.PolicySetIdReference = sets.map(referenceOf);
    }
  }
  log.debug('Leaving writeResponse().');
  return { Response: [result] };
}

function referenceOf(one) {
  log.debug("Entering referenceOf().");
  log.debug("Leaving referenceOf().");
  return { Id: one.id, Version: one.version };
}

function writeObligation(obligation) {
  log.debug("Entering writeObligation().");
  const written = { Id: obligation.id };
  if (obligation.assignments && obligation.assignments.length) {
    written.AttributeAssignment = obligation.assignments.map(function (one) {
      const assignment = { AttributeId: one.attributeId,
                           Value: one.lexical,
                           DataType: shortNameOf(one.type) };
      if (one.category) {
        assignment.Category = one.category;
      }
      if (one.issuer) {
        assignment.Issuer = one.issuer;
      }
      return assignment;
    });
  }
  log.debug("Leaving writeObligation().");
  return written;
}

// The short name where there is one, because that is what the profile's own
// examples use and what a reader of a response can act on. The URI is correct
// and unreadable.
function shortNameOf(uri) {
  log.debug("Entering shortNameOf().");
  const row = datatypes.typeOf(uri);
  log.debug("Leaving shortNameOf().");
  return row ? row.name : uri;
}

/**
 * The JSON Profile of XACML 3.0 (v1.1): reads a decision request and writes
 * a decision response over the policy model.
 *
 * The profile defines no policy syntax, so this file reads and writes no
 * policies.
 * @namespace
 */
module.exports = {
  parseRequest: parseRequest,
  writeResponse: writeResponse,
  resolveType: resolveType,
  inferType: inferType,
  SHORTHAND_CATEGORY: SHORTHAND_CATEGORY,
  SHORT_TYPE: SHORT_TYPE
};
