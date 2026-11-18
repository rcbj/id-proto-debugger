// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_query.js
//
// ---------------------------------------------------------------------------
// PREDICATE QUERIES FOR CREDENTIAL PRESENTATIONS (#474): the query language
// a Verifier uses to ask "prove age >= 18" instead of "show me your birth
// date", for OpenID4VP and AnonCreds. No DOM.
//
// THREE QUERY LANGUAGES, AND WHICH OF THEM IS STANDARD:
//
//   1. DIF Presentation Exchange 2.1.1 (presentation_definition and
//      presentation_submission), WITH ITS PREDICATE FEATURE — the
//      standard starting point. A field of an Input Descriptor's
//      constraints carries `predicate: "required" | "preferred"` and a JSON
//      Schema `filter` restricted to minimum, exclusiveMinimum, maximum,
//      exclusiveMaximum (and const, enum and their `not`), and the Holder
//      returns the boolean result instead of the value. The OpenID4VP
//      DRAFTS carried a presentation_definition in the Authorization
//      Request and a presentation_submission beside the vp_token; OpenID4VP
//      1.0 REMOVED BOTH in favour of DCQL. Every label here says so:
//      LABEL_PE.
//
//   2. DCQL (OpenID4VP 1.0 section 6), which has NO predicates. A claims
//      query's `values` is an exact type-and-value match, a SHOULD, and
//      best effort (section 6.4.1); and a wallet MUST ignore a property it
//      does not understand (section 6.1). selectClaims() is section 6.4.1
//      exactly.
//
//   3. THIS DEBUGGER'S DCQL EXTENSION (non-standard, and labelled so in
//      code, UI and docs): the same predicate semantics as (1), in a
//      credential query, made safe against a wallet that ignores it.
//        * The predicates are in their own member, EXT_PREDICATES, and the
//          claim a predicate is about MUST NOT also be in `claims`. A 1.0
//          wallet ignoring the member therefore discloses NOTHING extra —
//          it returns the credential without the proof, and the Verifier
//          refuses it for want of one. An ad-hoc predicate member on a
//          claims query would be the opposite: an ignoring wallet would
//          disclose the raw value it was meant to protect, so a query that
//          names the same claim in both places is refused here outright.
//        * It is honoured only when the credential query lists it in
//          EXT_CRIT, JOSE `crit` style (RFC 7515 section 4.1.11): listed,
//          a wallet that cannot prove a predicate MUST NOT return that
//          credential; unlisted, it is ignored exactly as section 6.1 says
//          an unknown property is; a crit entry the wallet does not
//          understand refuses the credential query.
//
// HOW A PREDICATE IS PROVEN DEPENDS ON THE FORMAT (FORMAT_PREDICATES):
//   * anoncreds — natively, in zero knowledge: AnonCreds requested_predicates
//     {name, p_type (>=, >, <=, <), p_value (an integer)}, CL range proofs.
//     minimum -> ">=", exclusiveMinimum -> ">", maximum -> "<=",
//     exclusiveMaximum -> "<". A date is an integer YYYYMMDD, the AnonCreds
//     specification's convention ("Date and Date/Time Predicates").
//   * mso_mdoc — no zero-knowledge predicates; ISO/IEC 18013-5 has the
//     ISSUER compute age_over_NN booleans. A lower bound on an age claim is
//     answered by disclosing age_over_NN when the mdoc carries it (THIS
//     DEBUGGER'S MAPPING, labelled so).
//   * dc+sd-jwt, vc+sd-jwt, jwt_vc_json, ldp_vc, jpt, sd-cwt — none. A
//     `required` predicate those formats cannot prove is REFUSED rather than
//     answered with the value. A `preferred` one may, per PE ("SHOULD"),
//     fall back to the value — only when the caller allows it
//     (allowPreferredDisclosure); the default is to refuse.
//
// CAPABILITY ADVERTISEMENT (non-standard, no specification defines one):
// EXT_METADATA in wallet_metadata and in client_metadata —
// walletMetadataExtension() / verifierMetadataExtension().
//
// FAIL-CLOSED THROUGHOUT: a filter keyword this module does not implement
// is a non-match, a predicate that cannot be evaluated is unproven, and an
// unproven required predicate refuses the credential.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_query",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var PE_VERSION = "2.1.1";
var LABEL_PE = "OpenID4VP drafts \u2014 presentation_definition, removed " +
  "in 1.0";
var LABEL_EXT = "id-proto-debugger DCQL predicate extension " +
  "(non-standard)";
var EXT_PREDICATES = "x_debugger_predicates";
var EXT_CRIT = "x_debugger_crit";
var EXT_METADATA = "x_debugger_predicates_supported";
var UNDERSTOOD_CRIT = [EXT_PREDICATES];
var P_TYPES = [">=", ">", "<=", "<"];
var P_NAMES = { ">=": "ge", ">": "gt", "<=": "le", "<": "lt" };
var RANGE_KEYWORDS = { minimum: ">=", exclusiveMinimum: ">",
                       maximum: "<=", exclusiveMaximum: "<" };
var RESTRICTION_TAGS = ["schema_id", "schema_issuer_id", "schema_name",
                        "schema_version", "issuer_id", "cred_def_id",
                        "rev_reg_id"];
var META_NAMES = ["vct", "type", "@context", "issuer", "iss", "doctype"];
var I32_MIN = -2147483648;
var I32_MAX = 2147483647;
var DCQL_ID = /^[A-Za-z0-9_-]+$/;
var AGE_CLAIMS = ["age_in_years", "age"];

// What each format can do with a predicate. `zk` lists the operations
// proven without disclosing the value; `issuerBoolean` an issuer-computed
// claim that answers some of them.
var FORMAT_PREDICATES = {
  "anoncreds": { zk: "range", ops: P_TYPES.slice(), integerOnly: true,
    how: "AnonCreds requested_predicates, proven in zero knowledge by CL " +
         "range proofs (AnonCreds v1.0). Integers only; a date is " +
         "YYYYMMDD." },
  "mso_mdoc": { zk: "", ops: [], issuerBoolean: "age_over_NN",
    how: "no zero-knowledge predicates. ISO/IEC 18013-5 has the issuer " +
         "compute age_over_NN booleans; a lower bound on an age claim is " +
         "answered by disclosing age_over_NN (this debugger's mapping)." },
  "dc+sd-jwt": { zk: "", ops: [], how: "selective disclosure only: an " +
    "SD-JWT VC can withhold a claim or disclose it, and has no way to " +
    "prove a predicate over one." },
  "vc+sd-jwt": { zk: "", ops: [], how: "selective disclosure only, as " +
    "dc+sd-jwt." },
  "jwt_vc_json": { zk: "", ops: [], how: "no selective disclosure and no " +
    "predicates: the credential goes whole." },
  "ldp_vc": { zk: "", ops: [], how: "bbs-2023 and ecdsa-sd-2023 disclose " +
    "or withhold a statement; neither proves a range over one." },
  "jpt": { zk: "", ops: [], how: "JSON Web Proofs (draft) define no " +
    "predicate proofs." },
  "sd-cwt": { zk: "", ops: [], how: "selective disclosure only (draft)." }
};

function isArray(v) {
  log.debug("Entering isArray().");
  log.debug("Leaving isArray().");
  return Object.prototype.toString.call(v) === "[object Array]";
}

function isObject(v) {
  log.debug("Entering isObject().");
  log.debug("Leaving isObject().");
  return !!v && typeof v === "object" && !isArray(v);
}

function parseMaybeJson(v) {
  log.debug("Entering parseMaybeJson().");
  if (typeof v !== "string") {
    log.debug("Leaving parseMaybeJson(). Not a string.");
    return v;
  }
  try {
    var out = JSON.parse(v);
    log.debug("Leaving parseMaybeJson(). JSON.");
    return out;
  } catch (e) {
    log.debug("Leaving parseMaybeJson(). " + e.message);
    throw new Error("not JSON: " + e.message);
  }
}

// ---------------------------------------------------------------------------
// JSONPath: the subset Presentation Exchange's examples use — $, .name,
// ['name'] / ["name"], [n] and [*]. Anything else is refused by name rather
// than half-evaluated.
// ---------------------------------------------------------------------------

function parseJsonPath(text) {
  log.debug("Entering parseJsonPath().");
  var s = String(text || "");
  if (s.charAt(0) !== "$") {
    log.debug("Leaving parseJsonPath(). No root.");
    throw new Error("a JSONPath begins with $: " + JSON.stringify(s));
  }
  var out = [];
  var i = 1;
  while (i < s.length) {
    var c = s.charAt(i);
    if (c === ".") {
      var m = /^\.([A-Za-z0-9_@$-]+|\*)/.exec(s.slice(i));
      if (!m) {
        log.debug("Leaving parseJsonPath(). Bad member.");
        throw new Error("unsupported JSONPath at " + i + ": " +
                        JSON.stringify(s));
      }
      out.push(m[1] === "*" ? null : m[1]);
      i += m[0].length;
    } else if (c === "[") {
      var b = /^\[(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|(\d+)|(\*))\]/
        .exec(s.slice(i));
      if (!b) {
        log.debug("Leaving parseJsonPath(). Bad bracket.");
        throw new Error("unsupported JSONPath at " + i + ": " +
                        JSON.stringify(s));
      }
      if (b[1] !== undefined) out.push(b[1].replace(/\\(.)/g, "$1"));
      else if (b[2] !== undefined) out.push(b[2].replace(/\\(.)/g, "$1"));
      else if (b[3] !== undefined) out.push(Number(b[3]));
      else out.push(null);
      i += b[0].length;
    } else {
      log.debug("Leaving parseJsonPath(). Unexpected character.");
      throw new Error("unsupported JSONPath at " + i + ": " +
                      JSON.stringify(s));
    }
  }
  log.debug("Leaving parseJsonPath(). " + out.length + " segment(s).");
  return out;
}

// A JSONPath for a list of segments, the inverse of parseJsonPath().
function jsonPathOf(segments) {
  log.debug("Entering jsonPathOf().");
  var out = "$";
  segments.forEach(function (seg) {
    if (seg === null) out += "[*]";
    else if (typeof seg === "number") out += "[" + seg + "]";
    else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(seg)) out += "." + seg;
    else out += "['" + String(seg).replace(/(['\\])/g, "\\$1") + "']";
  });
  log.debug("Leaving jsonPathOf().");
  return out;
}

// Every value a list of segments selects from root (null: every element or
// member, as DCQL's claims path pointer and JSONPath's [*] both mean).
function selectAll(root, segments) {
  log.debug("Entering selectAll().");
  var current = [root];
  segments.forEach(function (seg) {
    var next = [];
    current.forEach(function (node) {
      if (seg === null) {
        if (isArray(node)) next = next.concat(node);
        else if (isObject(node)) {
          Object.keys(node).forEach(function (k) {
            next.push(node[k]);
          });
        }
      } else if (typeof seg === "number") {
        if (isArray(node) && seg < node.length) next.push(node[seg]);
      } else if (isObject(node) &&
                 Object.prototype.hasOwnProperty.call(node, seg)) {
        next.push(node[seg]);
      }
    });
    current = next;
  });
  log.debug("Leaving selectAll(). " + current.length + " match(es).");
  return current;
}

// The attribute a path names: its last string segment. This is how a path
// meets an AnonCreds attribute (which is flat) and the wallet's claim map.
function attributeOf(segments) {
  log.debug("Entering attributeOf().");
  for (var i = segments.length - 1; i >= 0; i--) {
    if (typeof segments[i] === "string") {
      log.debug("Leaving attributeOf(). " + segments[i]);
      return segments[i];
    }
  }
  log.debug("Leaving attributeOf(). None.");
  return "";
}

// ---------------------------------------------------------------------------
// JSON Schema (draft-07), the subset PE filters use. An unimplemented
// keyword is reported and counts as a NON-match: fail closed.
// ---------------------------------------------------------------------------

var FILTER_KEYWORDS = ["type", "const", "enum", "not", "pattern",
  "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum",
  "exclusiveMaximum", "format", "formatMinimum", "formatMaximum",
  "formatExclusiveMinimum", "formatExclusiveMaximum", "contains",
  "minItems", "maxItems", "items", "$schema", "description", "title"];

function unsupportedKeywords(schema) {
  log.debug("Entering unsupportedKeywords().");
  var out = [];
  if (!isObject(schema)) {
    log.debug("Leaving unsupportedKeywords(). Not an object.");
    return out;
  }
  Object.keys(schema).forEach(function (k) {
    if (FILTER_KEYWORDS.indexOf(k) === -1) out.push(k);
  });
  ["not", "contains", "items"].forEach(function (k) {
    if (isObject(schema[k])) out = out.concat(unsupportedKeywords(schema[k]));
  });
  log.debug("Leaving unsupportedKeywords(). " + out.length);
  return out;
}

function jsonType(v) {
  log.debug("Entering jsonType().");
  var t = v === null ? "null" : isArray(v) ? "array" : typeof v;
  log.debug("Leaving jsonType(). " + t);
  return t;
}

function sameJson(a, b) {
  log.debug("Entering sameJson().");
  log.debug("Leaving sameJson().");
  return JSON.stringify(a) === JSON.stringify(b);
}

// A date (YYYY-MM-DD, or the date part of a date-time) as a sortable
// string, or null.
function dateKey(v) {
  log.debug("Entering dateKey().");
  var m = /^(\d{4})-(\d{2})-(\d{2})(?:$|T)/.exec(String(v));
  log.debug("Leaving dateKey(). " + !!m);
  return m ? m[1] + m[2] + m[3] : null;
}

// Whether value validates against schema. Recursion over `not`, `contains`
// and `items` only, so the depth is the filter's own.
function filterMatches(schema, value) {
  log.debug("Entering filterMatches().");
  if (schema === true || schema === undefined) {
    log.debug("Leaving filterMatches(). Empty schema.");
    return true;
  }
  if (!isObject(schema) || unsupportedKeywords(schema).length) {
    log.debug("Leaving filterMatches(). Unsupported: fail closed.");
    return false;
  }
  var t = jsonType(value);
  var ok = true;
  if (schema.type !== undefined) {
    var types = [].concat(schema.type);
    ok = types.some(function (ty) {
      if (ty === "integer") return t === "number" && Number.isInteger(value);
      return ty === t;
    });
  }
  if (ok && schema.const !== undefined) ok = sameJson(schema.const, value);
  if (ok && isArray(schema.enum)) {
    ok = schema.enum.some(function (e) {
      return sameJson(e, value);
    });
  }
  if (ok && isObject(schema.not)) ok = !filterMatches(schema.not, value);
  if (ok && t === "string") {
    if (typeof schema.pattern === "string") {
      try {
        ok = new RegExp(schema.pattern, "u").test(value);
      } catch (e) {
        log.debug("filterMatches(): bad pattern " + e.message);
        ok = false;
      }
    }
    if (ok && typeof schema.minLength === "number") {
      ok = value.length >= schema.minLength;
    }
    if (ok && typeof schema.maxLength === "number") {
      ok = value.length <= schema.maxLength;
    }
    if (ok && (schema.format === "date" || schema.format === "date-time")) {
      ok = dateKey(value) !== null;
    }
    var dk = dateKey(value);
    [["formatMinimum", function (a, b) {
      return a >= b;
    }], ["formatExclusiveMinimum", function (a, b) {
      return a > b;
    }], ["formatMaximum", function (a, b) {
      return a <= b;
    }], ["formatExclusiveMaximum", function (a, b) {
      return a < b;
    }]].forEach(function (pair) {
      if (ok && schema[pair[0]] !== undefined) {
        var bound = dateKey(schema[pair[0]]);
        ok = dk !== null && bound !== null && pair[1](dk, bound);
      }
    });
  }
  if (ok && t === "number") {
    if (typeof schema.minimum === "number") ok = value >= schema.minimum;
    if (ok && typeof schema.maximum === "number") ok = value <= schema.maximum;
    if (ok && typeof schema.exclusiveMinimum === "number") {
      ok = value > schema.exclusiveMinimum;
    }
    if (ok && typeof schema.exclusiveMaximum === "number") {
      ok = value < schema.exclusiveMaximum;
    }
    // Draft-04's boolean exclusiveMinimum is not draft-07: fail closed.
    if (ok && (typeof schema.exclusiveMinimum === "boolean" ||
               typeof schema.exclusiveMaximum === "boolean")) {
      ok = false;
    }
  }
  if (ok && t === "array") {
    if (typeof schema.minItems === "number") {
      ok = value.length >= schema.minItems;
    }
    if (ok && typeof schema.maxItems === "number") {
      ok = value.length <= schema.maxItems;
    }
    if (ok && isObject(schema.contains)) {
      ok = value.some(function (x) {
        return filterMatches(schema.contains, x);
      });
    }
    if (ok && isObject(schema.items)) {
      ok = value.every(function (x) {
        return filterMatches(schema.items, x);
      });
    }
  }
  log.debug("Leaving filterMatches(). " + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// Predicates: what a predicate filter asks, as operations.
// ---------------------------------------------------------------------------

// { kind: "range", bounds: [{ p_type, p_value }] } | { kind: "const",
// value, negated } | { kind: "enum", values, negated }, or { error }.
// PE 2.1.1's Predicate Feature: "the set of JSON Schema descriptors which
// comprise the value of the filter property MUST be restricted according to
// the desired predicate operation".
function predicateOps(filter) {
  log.debug("Entering predicateOps().");
  if (!isObject(filter)) {
    log.debug("Leaving predicateOps(). No filter.");
    return { error: "a predicate field MUST also have a filter (PE 2.1.1, " +
             "Predicate Feature)." };
  }
  var keys = Object.keys(filter).filter(function (k) {
    return ["$schema", "description", "title"].indexOf(k) === -1;
  });
  var ranges = keys.filter(function (k) {
    return RANGE_KEYWORDS[k] !== undefined;
  });
  if (ranges.length) {
    var extra = keys.filter(function (k) {
      return RANGE_KEYWORDS[k] === undefined && k !== "type";
    });
    var type = [].concat(filter.type || []);
    if (extra.length || !type.length || type.some(function (t) {
      return t !== "number" && t !== "integer";
    })) {
      log.debug("Leaving predicateOps(). Not a plain range.");
      return { error: "a range predicate's filter is type number (or " +
               "integer) and minimum / exclusiveMinimum / maximum / " +
               "exclusiveMaximum only; this one also has " +
               (extra.join(", ") || "no numeric type") + "." };
    }
    var bounds = [];
    for (var i = 0; i < ranges.length; i++) {
      var v = filter[ranges[i]];
      if (typeof v !== "number" || !isFinite(v)) {
        log.debug("Leaving predicateOps(). Bound not a number.");
        return { error: ranges[i] + " is " + JSON.stringify(v) + ", not a " +
                 "number (draft-07; draft-04's boolean form is not what PE " +
                 "uses)." };
      }
      bounds.push({ keyword: ranges[i], p_type: RANGE_KEYWORDS[ranges[i]],
                    p_value: v });
    }
    log.debug("Leaving predicateOps(). Range, " + bounds.length + ".");
    return { kind: "range", bounds: bounds };
  }
  var inner = filter;
  var negated = false;
  if (isObject(filter.not) && keys.length === 1) {
    inner = filter.not;
    negated = true;
  }
  var ikeys = Object.keys(inner).filter(function (k) {
    return k !== "type";
  });
  if (ikeys.length === 1 && ikeys[0] === "const") {
    log.debug("Leaving predicateOps(). Const.");
    return { kind: "const", value: inner.const, negated: negated };
  }
  if (ikeys.length === 1 && ikeys[0] === "enum" && isArray(inner.enum)) {
    log.debug("Leaving predicateOps(). Enum.");
    return { kind: "enum", values: inner.enum.slice(), negated: negated };
  }
  log.debug("Leaving predicateOps(). Not a predicate filter.");
  return { error: "a predicate's filter is a numeric range, const, enum " +
           "or the not of const or enum (PE 2.1.1); " +
           JSON.stringify(filter) + " is none of those." };
}

// "age >= 18 and age < 65", for a person.
function describePredicate(name, ops) {
  log.debug("Entering describePredicate().");
  var out;
  if (!ops || ops.error) out = name + ": " + ((ops || {}).error || "?");
  else if (ops.kind === "range") {
    out = ops.bounds.map(function (b) {
      return name + " " + b.p_type + " " + b.p_value;
    }).join(" and ");
  } else if (ops.kind === "const") {
    out = name + (ops.negated ? " != " : " == ") + JSON.stringify(ops.value);
  } else {
    out = name + (ops.negated ? " not in " : " in ") +
      JSON.stringify(ops.values);
  }
  log.debug("Leaving describePredicate().");
  return out;
}

// The AnonCreds predicate referent for one bound: deterministic, so a
// Verifier rebuilding the request reaches the same referents.
function predicateReferent(base, bound) {
  log.debug("Entering predicateReferent().");
  var v = String(bound.p_value).replace(/^-/, "m");
  log.debug("Leaving predicateReferent().");
  return String(base).replace(/[^A-Za-z0-9_-]/g, "_") + "_" +
    P_NAMES[bound.p_type] + "_" + v;
}

// YYYYMMDD as an integer, from YYYY-MM-DD or a Date.
function dateInt(v) {
  log.debug("Entering dateInt().");
  var key = v instanceof Date ? v.toISOString().slice(0, 10) : String(v);
  var k = dateKey(key);
  if (k === null) {
    log.debug("Leaving dateInt(). Not a date.");
    throw new Error("not a date (YYYY-MM-DD): " + JSON.stringify(v));
  }
  log.debug("Leaving dateInt().");
  return Number(k);
}

// "At least `years` old on `today`" over a YYYYMMDD birth date: born on or
// before today minus `years`, i.e. birthdate_dateint <= that YYYYMMDD — the
// AnonCreds specification's own example ("birth_dateint <= 20020116").
function ageThresholdDateInt(years, today) {
  log.debug("Entering ageThresholdDateInt().");
  var t = today instanceof Date ? today : new Date(today || Date.now());
  var y = t.getUTCFullYear() - Number(years);
  var md = t.toISOString().slice(5, 10).replace("-", "");
  // 29 February in a year that has none: the last day that is old enough
  // is 28 February.
  if (md === "0229" && !(y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0))) {
    md = "0228";
  }
  log.debug("Leaving ageThresholdDateInt().");
  return Number(String(y) + md);
}

// ---------------------------------------------------------------------------
// Presentation Exchange 2.1.1: presentation_definition.
// ---------------------------------------------------------------------------

function readField(f, where, errors) {
  log.debug("Entering readField(). " + where);
  if (!isObject(f)) {
    errors.push(where + " is not an object.");
    log.debug("Leaving readField(). Not an object.");
    return null;
  }
  if (!isArray(f.path) || !f.path.length || f.path.some(function (p) {
    return typeof p !== "string";
  })) {
    errors.push(where + ".path is a non-empty array of JSONPath strings.");
    log.debug("Leaving readField(). No path.");
    return null;
  }
  var paths = [];
  f.path.forEach(function (p, i) {
    try {
      paths.push(parseJsonPath(p));
    } catch (e) {
      errors.push(where + ".path[" + i + "]: " + e.message);
    }
  });
  if (f.filter !== undefined && !isObject(f.filter)) {
    errors.push(where + ".filter is a JSON Schema object.");
  }
  if (isObject(f.filter) && unsupportedKeywords(f.filter).length) {
    errors.push(where + ".filter uses " +
                unsupportedKeywords(f.filter).join(", ") + ", which this " +
                "debugger does not evaluate (a non-match, failing closed).");
  }
  var out = { id: f.id, name: f.name, purpose: f.purpose, paths: paths,
              pathText: f.path.slice(), filter: f.filter,
              optional: f.optional === true,
              intentToRetain: f.intent_to_retain === true,
              predicate: f.predicate,
              attribute: paths.length ? attributeOf(paths[0]) : "" };
  if (f.predicate !== undefined) {
    if (f.predicate !== "required" && f.predicate !== "preferred") {
      errors.push(where + ".predicate is \"required\" or \"preferred\", " +
                  "not " + JSON.stringify(f.predicate) + ".");
    }
    out.ops = predicateOps(f.filter);
    if (out.ops.error) errors.push(where + ": " + out.ops.error);
  }
  log.debug("Leaving readField().");
  return out;
}

function readRequirement(sr, where, groups, errors) {
  log.debug("Entering readRequirement(). " + where);
  if (!isObject(sr)) {
    errors.push(where + " is not an object.");
    log.debug("Leaving readRequirement().");
    return;
  }
  if (sr.rule !== "all" && sr.rule !== "pick") {
    errors.push(where + ".rule is \"all\" or \"pick\".");
  }
  if ((sr.from === undefined) === (sr.from_nested === undefined)) {
    errors.push(where + " has exactly one of from and from_nested.");
  }
  if (sr.from !== undefined && groups.indexOf(sr.from) === -1) {
    errors.push(where + ".from names group " + JSON.stringify(sr.from) +
                ", which no Input Descriptor is in.");
  }
  ["count", "min", "max"].forEach(function (k) {
    if (sr[k] !== undefined && !(Number.isInteger(sr[k]) && sr[k] >= 0)) {
      errors.push(where + "." + k + " is a non-negative integer.");
    }
  });
  if (isArray(sr.from_nested)) {
    sr.from_nested.forEach(function (n, i) {
      readRequirement(n, where + ".from_nested[" + i + "]", groups, errors);
    });
  }
  log.debug("Leaving readRequirement().");
}

// { definition, descriptors, errors, warnings }. Errors make it unusable.
function readDefinition(input) {
  log.debug("Entering readDefinition().");
  var errors = [];
  var warnings = [];
  var pd;
  try {
    pd = parseMaybeJson(input);
  } catch (e) {
    log.debug("Leaving readDefinition(). Not JSON.");
    return { definition: null, descriptors: [], errors:
             ["presentation_definition is " + e.message], warnings: [] };
  }
  if (!isObject(pd)) {
    log.debug("Leaving readDefinition(). Not an object.");
    return { definition: null, descriptors: [], errors:
             ["presentation_definition is a JSON object."], warnings: [] };
  }
  if (typeof pd.id !== "string" || !pd.id) {
    errors.push("presentation_definition.id is a non-empty string.");
  }
  if (!isArray(pd.input_descriptors) || !pd.input_descriptors.length) {
    errors.push("presentation_definition.input_descriptors is a non-empty " +
                "array.");
  }
  var seen = {};
  var groups = [];
  var descriptors = (isArray(pd.input_descriptors) ? pd.input_descriptors :
    []).map(function (d, i) {
      var where = "input_descriptors[" + i + "]";
      if (!isObject(d)) {
        errors.push(where + " is not an object.");
        return null;
      }
      if (typeof d.id !== "string" || !d.id) {
        errors.push(where + ".id is a non-empty string.");
      } else if (seen[d.id]) {
        errors.push(where + ".id " + JSON.stringify(d.id) + " is not " +
                    "unique.");
      }
      seen[d.id] = true;
      var c = d.constraints === undefined ? {} : d.constraints;
      if (!isObject(c)) errors.push(where + ".constraints is an object.");
      if (c.limit_disclosure !== undefined &&
          ["required", "preferred"].indexOf(c.limit_disclosure) === -1) {
        errors.push(where + ".constraints.limit_disclosure is " +
                    "\"required\" or \"preferred\".");
      }
      var fields = (isArray(c.fields) ? c.fields : []).map(function (f, j) {
        return readField(f, where + ".constraints.fields[" + j + "]",
                         errors);
      }).filter(function (f) {
        return f;
      });
      if (c.fields !== undefined && !isArray(c.fields)) {
        errors.push(where + ".constraints.fields is an array.");
      }
      [].concat(d.group || []).forEach(function (g) {
        if (groups.indexOf(g) === -1) groups.push(g);
      });
      return { id: d.id, name: d.name, purpose: d.purpose,
               format: d.format || pd.format || null,
               group: [].concat(d.group || []), fields: fields,
               limitDisclosure: c.limit_disclosure || "" };
    }).filter(function (d) {
      return d;
    });
  if (pd.submission_requirements !== undefined) {
    if (!isArray(pd.submission_requirements)) {
      errors.push("submission_requirements is an array.");
    } else {
      pd.submission_requirements.forEach(function (sr, i) {
        readRequirement(sr, "submission_requirements[" + i + "]", groups,
                        errors);
      });
    }
  }
  if (pd.frame !== undefined) {
    warnings.push("frame (JSON-LD framing) is not applied by this debugger.");
  }
  log.debug("Leaving readDefinition(). " + errors.length + " error(s).");
  return { definition: pd, descriptors: descriptors, errors: errors,
           warnings: warnings };
}

// ---------------------------------------------------------------------------
// Submission requirements (PE 2.1.1, "Submission Requirement Rules").
// ---------------------------------------------------------------------------

function requirementMet(sr, descriptors, answered) {
  log.debug("Entering requirementMet().");
  var n;
  var total;
  if (sr.from !== undefined) {
    var inGroup = descriptors.filter(function (d) {
      return d.group.indexOf(sr.from) !== -1;
    });
    total = inGroup.length;
    n = inGroup.filter(function (d) {
      return answered.indexOf(d.id) !== -1;
    }).length;
  } else {
    var nested = (sr.from_nested || []).map(function (x) {
      return requirementMet(x, descriptors, answered);
    });
    total = nested.length;
    n = nested.filter(function (x) {
      return x;
    }).length;
  }
  var ok;
  if (sr.rule === "all") ok = n === total;
  else {
    ok = true;
    if (sr.count !== undefined) ok = n === sr.count;
    if (ok && sr.min !== undefined) ok = n >= sr.min;
    if (ok && sr.max !== undefined) ok = n <= sr.max;
  }
  log.debug("Leaving requirementMet(). " + n + "/" + total + " " + ok);
  return ok;
}

// Whether a set of answered descriptor ids satisfies the definition. With
// no submission_requirements every Input Descriptor is required.
function submissionRequirementsMet(read, answered) {
  log.debug("Entering submissionRequirementsMet().");
  var srs = (read.definition || {}).submission_requirements;
  var problems = [];
  if (!isArray(srs) || !srs.length) {
    read.descriptors.forEach(function (d) {
      if (answered.indexOf(d.id) === -1) {
        problems.push("Input Descriptor \"" + d.id + "\" is not answered " +
                      "(with no submission_requirements, every one is " +
                      "required)");
      }
    });
  } else {
    srs.forEach(function (sr, i) {
      if (!requirementMet(sr, read.descriptors, answered)) {
        problems.push("submission_requirements[" + i + "] (" + sr.rule +
                      (sr.from !== undefined ? " from " + sr.from :
                       " from_nested") + ") is not met");
      }
    });
  }
  log.debug("Leaving submissionRequirementsMet(). " + problems.length);
  return { ok: problems.length === 0, problems: problems };
}

// ---------------------------------------------------------------------------
// presentation_submission.
// ---------------------------------------------------------------------------

// entries: [{ id, format, path, path_nested }]
function buildSubmission(definitionId, entries, id) {
  log.debug("Entering buildSubmission().");
  log.debug("Leaving buildSubmission().");
  return { id: id || "submission-" + definitionId,
           definition_id: definitionId,
           descriptor_map: entries.map(function (e) {
             var out = { id: e.id, format: e.format, path: e.path || "$" };
             if (e.path_nested) out.path_nested = e.path_nested;
             return out;
           }) };
}

function readDescriptorMapEntry(e, where, root, errors) {
  log.debug("Entering readDescriptorMapEntry(). " + where);
  if (!isObject(e)) {
    errors.push(where + " is not an object.");
    log.debug("Leaving readDescriptorMapEntry().");
    return null;
  }
  ["id", "format", "path"].forEach(function (k) {
    if (typeof e[k] !== "string" || !e[k]) {
      errors.push(where + "." + k + " is a non-empty string.");
    }
  });
  var target;
  try {
    var hits = selectAll(root, parseJsonPath(e.path));
    if (!hits.length) {
      errors.push(where + ".path " + JSON.stringify(e.path) + " selects " +
                  "nothing in the vp_token.");
    }
    target = hits[0];
  } catch (err) {
    errors.push(where + ".path: " + err.message);
  }
  if (e.path_nested !== undefined && target !== undefined) {
    var inner = typeof target === "string" && /^\s*[[{]/.test(target) ?
      JSON.parse(target) : target;
    var nested = readDescriptorMapEntry(e.path_nested, where + ".path_nested",
                                        inner, errors);
    if (nested && nested.id !== e.id) {
      errors.push(where + ".path_nested.id is the entry's own id, " +
                  JSON.stringify(e.id) + ".");
    }
  }
  log.debug("Leaving readDescriptorMapEntry().");
  return { id: e.id, format: e.format, path: e.path, target: target };
}

// Check a presentation_submission against the definition and the vp_token
// it describes. { ok, errors, entries: [{ id, format, path, target }],
// answered: [descriptor ids] }.
function checkSubmission(read, submission, vpToken) {
  log.debug("Entering checkSubmission().");
  var errors = [];
  var sub;
  try {
    sub = parseMaybeJson(submission);
  } catch (e) {
    log.debug("Leaving checkSubmission(). Not JSON.");
    return { ok: false, errors: ["presentation_submission is " + e.message],
             entries: [], answered: [] };
  }
  if (!isObject(sub)) {
    log.debug("Leaving checkSubmission(). Absent.");
    return { ok: false, errors: ["there is no presentation_submission; the " +
             "OpenID4VP drafts put one beside every vp_token answering a " +
             "presentation_definition."], entries: [], answered: [] };
  }
  if (typeof sub.id !== "string" || !sub.id) {
    errors.push("presentation_submission.id is a non-empty string.");
  }
  var defId = (read.definition || {}).id;
  if (sub.definition_id !== defId) {
    errors.push("presentation_submission.definition_id is " +
                JSON.stringify(sub.definition_id) + "; the request's " +
                "presentation_definition.id is " + JSON.stringify(defId) +
                ".");
  }
  if (!isArray(sub.descriptor_map)) {
    errors.push("presentation_submission.descriptor_map is an array.");
  }
  var known = read.descriptors.map(function (d) {
    return d.id;
  });
  var root = vpToken;
  if (typeof root === "string" && /^\s*[[{]/.test(root)) {
    try {
      root = JSON.parse(root);
    } catch (e) {
      log.debug("checkSubmission(): vp_token text is not JSON.");
    }
  }
  var entries = (isArray(sub.descriptor_map) ? sub.descriptor_map : [])
    .map(function (e, i) {
      var out = readDescriptorMapEntry(e, "descriptor_map[" + i + "]", root,
                                       errors);
      if (out && known.indexOf(out.id) === -1) {
        errors.push("descriptor_map[" + i + "].id " +
                    JSON.stringify(out.id) + " is no Input Descriptor of " +
                    "the definition.");
      }
      return out;
    }).filter(function (e) {
      return e;
    });
  var answered = [];
  entries.forEach(function (e) {
    if (answered.indexOf(e.id) === -1 && known.indexOf(e.id) !== -1) {
      answered.push(e.id);
    }
  });
  var met = submissionRequirementsMet(read, answered);
  errors = errors.concat(met.problems.map(function (p) {
    return p + ".";
  }));
  log.debug("Leaving checkSubmission(). " + errors.length + " error(s).");
  return { ok: errors.length === 0, errors: errors, entries: entries,
           answered: answered };
}

// ---------------------------------------------------------------------------
// The debugger's DCQL predicate extension (NON-STANDARD).
// ---------------------------------------------------------------------------

function pathKey(path) {
  log.debug("Entering pathKey().");
  log.debug("Leaving pathKey().");
  return JSON.stringify(path);
}

// { present, critical, honoured, predicates, errors, refuse, note }.
// refuse is set when the wallet MUST NOT return this credential query
// whatever it holds: an unknown crit entry, or a malformed extension.
function readExtension(cq) {
  log.debug("Entering readExtension().");
  var out = { present: false, critical: false, honoured: false,
              predicates: [], errors: [], refuse: "", note: "" };
  var preds = cq ? cq[EXT_PREDICATES] : undefined;
  var crit = cq ? cq[EXT_CRIT] : undefined;
  out.present = preds !== undefined;
  if (crit !== undefined) {
    if (!isArray(crit) || !crit.length || crit.some(function (c) {
      return typeof c !== "string";
    })) {
      out.refuse = EXT_CRIT + " is a non-empty array of member names.";
      log.debug("Leaving readExtension(). Bad crit.");
      return out;
    }
    var unknown = crit.filter(function (c) {
      return UNDERSTOOD_CRIT.indexOf(c) === -1;
    });
    if (unknown.length) {
      out.refuse = EXT_CRIT + " names " + unknown.join(", ") + ", which " +
        "this wallet does not understand; a critical extension that is " +
        "not understood refuses the credential query.";
      log.debug("Leaving readExtension(). Unknown crit.");
      return out;
    }
    out.critical = crit.indexOf(EXT_PREDICATES) !== -1;
    if (out.critical && !out.present) {
      out.refuse = EXT_CRIT + " lists " + EXT_PREDICATES + " and the " +
        "credential query has none.";
      log.debug("Leaving readExtension(). Crit without predicates.");
      return out;
    }
  }
  if (!out.present) {
    log.debug("Leaving readExtension(). None.");
    return out;
  }
  if (!out.critical) {
    out.note = EXT_PREDICATES + " is present but not listed in " + EXT_CRIT +
      ", so it is ignored, as OpenID4VP 1.0 section 6.1 has an unknown " +
      "property ignored. Nothing it names is disclosed.";
    log.debug("Leaving readExtension(). Not critical: ignored.");
    return out;
  }
  if (!isArray(preds) || !preds.length) {
    out.refuse = EXT_PREDICATES + " is a non-empty array.";
    log.debug("Leaving readExtension(). Not an array.");
    return out;
  }
  var claimPaths = (isArray(cq.claims) ? cq.claims : []).map(function (c) {
    return pathKey((c || {}).path);
  });
  var ids = {};
  preds.forEach(function (p, i) {
    var where = EXT_PREDICATES + "[" + i + "]";
    if (!isObject(p)) {
      out.errors.push(where + " is not an object.");
      return;
    }
    if (typeof p.id !== "string" || !DCQL_ID.test(p.id) || ids[p.id]) {
      out.errors.push(where + ".id is a unique string of letters, digits, " +
                      "_ and -.");
    }
    ids[p.id] = true;
    if (!isArray(p.path) || !p.path.length || p.path.some(function (s) {
      return !(typeof s === "string" || s === null ||
               (Number.isInteger(s) && s >= 0));
    })) {
      out.errors.push(where + ".path is a claims path pointer (OpenID4VP " +
                      "1.0 section 7).");
      return;
    }
    if (claimPaths.indexOf(pathKey(p.path)) !== -1) {
      out.errors.push(where + " is about " + JSON.stringify(p.path) +
        ", which `claims` also requests: a wallet ignoring this extension " +
        "would then disclose the very value the predicate protects.");
    }
    var ops = predicateOps(p.filter);
    if (ops.error) out.errors.push(where + ": " + ops.error);
    out.predicates.push({ id: p.id, path: p.path.slice(),
      attribute: attributeOf(p.path), filter: p.filter, ops: ops,
      mode: "required" });
  });
  if (out.errors.length) {
    out.refuse = "the " + LABEL_EXT + " is malformed: " +
      out.errors.join(" ");
  } else {
    out.honoured = true;
  }
  log.debug("Leaving readExtension(). " + out.predicates.length +
            " predicate(s).");
  return out;
}

// ---------------------------------------------------------------------------
// One model of a query, whichever language it came in.
//
// { language: "pe" | "dcql", label, items: [{ id, formats, claims:
//   [{ id, path, attribute, values, optional, filter, pathAlternatives }],
//   claimSets, predicates: [{ id, path, attribute, filter, ops, mode,
//   optional }], restrictions, extension, metaFields }], errors, warnings,
//   read (PE only), credentialSets (DCQL only) }
// ---------------------------------------------------------------------------

function restrictionOf(field) {
  log.debug("Entering restrictionOf().");
  var tag = field.attribute;
  if (RESTRICTION_TAGS.indexOf(tag) === -1 || field.predicate !== undefined ||
      !isObject(field.filter)) {
    log.debug("Leaving restrictionOf(). Not a restriction.");
    return null;
  }
  var f = field.filter;
  var values = f.const !== undefined ? [f.const] :
    isArray(f.enum) ? f.enum : null;
  if (!values) {
    log.debug("Leaving restrictionOf(). Neither const nor enum.");
    return null;
  }
  log.debug("Leaving restrictionOf(). " + tag);
  return values.map(function (v) {
    var o = {};
    o[tag] = String(v);
    return o;
  });
}

function itemFromDescriptor(d) {
  log.debug("Entering itemFromDescriptor(). " + d.id);
  var item = { id: d.id, formats: d.format ? Object.keys(d.format) : [],
               claims: [], claimSets: null, predicates: [],
               restrictions: null, metaFields: [], extension: null,
               limitDisclosure: d.limitDisclosure, descriptor: d };
  d.fields.forEach(function (f) {
    var r = restrictionOf(f);
    if (r) {
      item.restrictions = (item.restrictions || []).concat(r);
      return;
    }
    if (f.predicate !== undefined) {
      item.predicates.push({ id: f.id || f.attribute,
        path: f.paths[0], pathAlternatives: f.paths,
        attribute: f.attribute, filter: f.filter, ops: f.ops,
        mode: f.predicate, optional: f.optional });
      return;
    }
    if (META_NAMES.indexOf(f.attribute) !== -1) {
      item.metaFields.push(f);
      return;
    }
    item.claims.push({ id: f.id, path: f.paths[0], pathAlternatives: f.paths,
                       attribute: f.attribute, filter: f.filter,
                       optional: f.optional });
  });
  log.debug("Leaving itemFromDescriptor().");
  return item;
}

function itemFromCredentialQuery(cq) {
  log.debug("Entering itemFromCredentialQuery().");
  var ext = readExtension(cq);
  var item = { id: cq.id, formats: cq.format ? [cq.format] : [],
               claims: (isArray(cq.claims) ? cq.claims : []).map(
                 function (c) {
                   var path = isArray((c || {}).path) ? c.path : [];
                   return { id: c.id, path: path, pathAlternatives: [path],
                            attribute: attributeOf(path),
                            values: isArray(c.values) ? c.values : undefined,
                            optional: false };
                 }),
               claimSets: isArray(cq.claim_sets) ? cq.claim_sets : null,
               predicates: ext.honoured ? ext.predicates : [],
               restrictions: null, metaFields: [], extension: ext,
               query: cq };
  log.debug("Leaving itemFromCredentialQuery().");
  return item;
}

// query: { presentation_definition } or { dcql_query }, each an object or
// its JSON. presentation_definition wins only when there is no dcql_query.
function normalise(query) {
  log.debug("Entering normalise().");
  var q = query || {};
  if (q.dcql_query !== undefined && q.dcql_query !== null &&
      q.dcql_query !== "") {
    var dcql;
    try {
      dcql = parseMaybeJson(q.dcql_query);
    } catch (e) {
      log.debug("Leaving normalise(). DCQL is not JSON.");
      return { language: "dcql", items: [], errors: ["dcql_query is " +
               e.message], warnings: [] };
    }
    var cqs = isArray((dcql || {}).credentials) ? dcql.credentials : [];
    var warnings = [];
    if (q.presentation_definition) {
      warnings.push("the request carries both dcql_query and " +
                    "presentation_definition; OpenID4VP 1.0 has only the " +
                    "first, and it is the one answered.");
    }
    log.debug("Leaving normalise(). DCQL, " + cqs.length + ".");
    return { language: "dcql", label: "DCQL (OpenID4VP 1.0 section 6)",
             dcql: dcql, items: cqs.map(itemFromCredentialQuery),
             credentialSets: dcql.credential_sets || null,
             errors: cqs.length ? [] : ["dcql_query.credentials is a " +
                                         "non-empty array."],
             warnings: warnings };
  }
  if (q.presentation_definition !== undefined &&
      q.presentation_definition !== null &&
      q.presentation_definition !== "") {
    var read = readDefinition(q.presentation_definition);
    log.debug("Leaving normalise(). PE.");
    return { language: "pe", label: LABEL_PE, read: read,
             definition: read.definition,
             items: read.descriptors.map(itemFromDescriptor),
             errors: read.errors, warnings: read.warnings };
  }
  log.debug("Leaving normalise(). Nothing.");
  return { language: "", items: [], errors: ["the request carries neither " +
           "a dcql_query nor a presentation_definition."], warnings: [] };
}

// ---------------------------------------------------------------------------
// Selecting claims (OpenID4VP 1.0 section 6.4.1), exactly.
//
// lookup(path) -> { found: bool, value } for the held credential.
// ---------------------------------------------------------------------------

// Section 6.3: "the type and value of the claim both match exactly for at
// least one of the elements in the array".
function valueMatches(values, value) {
  log.debug("Entering valueMatches().");
  var ok = values.some(function (v) {
    return typeof v === typeof value && v === value;
  });
  log.debug("Leaving valueMatches(). " + ok);
  return ok;
}

// One row per claims query: { id, path, attribute, status, value, reason }
// status: "available", "absent", "value-mismatch".
function claimRow(claim, lookup) {
  log.debug("Entering claimRow().");
  var hit = lookup(claim.path) || { found: false };
  var row = { id: claim.id, path: claim.path, attribute: claim.attribute,
              values: claim.values, status: "available", value: hit.value,
              reason: "" };
  if (!hit.found) {
    row.status = "absent";
    row.reason = "the credential has no such claim.";
  } else if (claim.values !== undefined &&
             !valueMatches(claim.values, hit.value)) {
    row.status = "value-mismatch";
    row.reason = "it holds " + JSON.stringify(hit.value) + " and the " +
      "Verifier asked for one of " + JSON.stringify(claim.values) +
      " (exact type and value, OpenID4VP 1.0 section 6.3), so it is " +
      "treated as if it did not exist (section 6.4.1).";
  }
  log.debug("Leaving claimRow(). " + row.status);
  return row;
}

// { satisfied, rows, selected: [claims], chosenSet (index or -1), reason }
function selectClaims(item, lookup) {
  log.debug("Entering selectClaims().");
  var rows = item.claims.map(function (c) {
    return claimRow(c, lookup);
  });
  var usable = function (r) {
    log.debug("Entering usable().");
    log.debug("Leaving usable().");
    return r.status === "available";
  };
  if (!item.claims.length) {
    log.debug("Leaving selectClaims(). No claims: mandatory only.");
    return { satisfied: true, rows: rows, selected: [], chosenSet: -1,
             reason: "the query names no claims, so only what is " +
             "mandatory to present goes (section 6.4.1)." };
  }
  if (!item.claimSets) {
    var short = rows.filter(function (r) {
      return !usable(r);
    });
    log.debug("Leaving selectClaims(). All claims, " + short.length +
              " short.");
    return { satisfied: short.length === 0, rows: rows,
             selected: short.length ? [] : item.claims.slice(),
             chosenSet: -1, reason: short.length ? "every claim in " +
             "`claims` is requested (section 6.4.1) and " +
             short.map(function (r) {
               return JSON.stringify(r.path) + " cannot be delivered: " +
                 r.reason;
             }).join("; ") + " So the credential is not returned." :
             "every claim requested is available." };
  }
  var byId = {};
  item.claims.forEach(function (c, i) {
    byId[c.id] = i;
  });
  for (var s = 0; s < item.claimSets.length; s++) {
    var set = item.claimSets[s] || [];
    var ok = set.length > 0 && set.every(function (id) {
      return byId[id] !== undefined && usable(rows[byId[id]]);
    });
    if (ok) {
      rows.forEach(function (r) {
        if (set.indexOf(r.id) === -1 && r.status === "available") {
          r.status = "not-in-chosen-set";
          r.reason = "claim_sets option " + s + " is the first this " +
            "credential satisfies, and it does not include this claim.";
        }
      });
      log.debug("Leaving selectClaims(). Set " + s + ".");
      return { satisfied: true, rows: rows, chosenSet: s,
               selected: set.map(function (id) {
                 return item.claims[byId[id]];
               }),
               reason: "claim_sets option " + s + " (" + set.join(", ") +
               ") is the first this credential satisfies." };
    }
  }
  log.debug("Leaving selectClaims(). No set.");
  return { satisfied: false, rows: rows, selected: [], chosenSet: -1,
           reason: "no claim_sets option can be satisfied, so no claims " +
           "are returned and the credential is not returned (section " +
           "6.4.1)." };
}

// PE fields: each must yield a Field Query Result (PE 2.1.1, "Input
// Evaluation"): the first path that selects a value passing the filter.
function peClaimRow(claim, lookup) {
  log.debug("Entering peClaimRow().");
  var row = { id: claim.id, path: claim.path, attribute: claim.attribute,
              status: "absent", value: undefined, reason: "",
              optional: claim.optional };
  for (var i = 0; i < claim.pathAlternatives.length; i++) {
    var hit = lookup(claim.pathAlternatives[i]) || { found: false };
    if (!hit.found) continue;
    if (claim.filter === undefined || filterMatches(claim.filter, hit.value)) {
      row.status = "available";
      row.value = hit.value;
      row.path = claim.pathAlternatives[i];
      log.debug("Leaving peClaimRow(). Available.");
      return row;
    }
    row.status = "filter-mismatch";
    row.value = hit.value;
    row.reason = "it holds " + JSON.stringify(hit.value) + ", which does " +
      "not validate against the filter " + JSON.stringify(claim.filter) + ".";
  }
  if (row.status === "absent") row.reason = "the credential has no such " +
    "claim.";
  log.debug("Leaving peClaimRow(). " + row.status);
  return row;
}

// ---------------------------------------------------------------------------
// Predicates against a held credential: how (and whether) each is proven.
// ---------------------------------------------------------------------------

function capabilityOf(format) {
  log.debug("Entering capabilityOf(). " + format);
  log.debug("Leaving capabilityOf().");
  return FORMAT_PREDICATES[format] || { zk: "", ops: [],
    how: "this debugger knows no predicate mechanism for " + format + "." };
}

function i32Of(v) {
  log.debug("Entering i32Of().");
  var s = String(v);
  if (!/^[+-]?\d+$/.test(s)) {
    log.debug("Leaving i32Of(). Not an integer.");
    return null;
  }
  var n = Number(s);
  log.debug("Leaving i32Of().");
  return n >= I32_MIN && n <= I32_MAX ? n : null;
}

// The value a predicate is evaluated over: a held claim, as a number when
// the claim is an integer held as text (AnonCreds raw values are text).
function predicateValue(pred, lookup) {
  log.debug("Entering predicateValue().");
  var alts = pred.pathAlternatives || [pred.path];
  for (var i = 0; i < alts.length; i++) {
    var hit = lookup(alts[i]) || { found: false };
    if (hit.found) {
      log.debug("Leaving predicateValue(). Found.");
      return hit;
    }
  }
  log.debug("Leaving predicateValue(). Absent.");
  return { found: false };
}

// The threshold NN for which age_over_NN answers this range, or null: only
// a single lower bound on an age claim (>= NN, or > NN-1).
function ageOverThreshold(pred) {
  log.debug("Entering ageOverThreshold().");
  if (AGE_CLAIMS.indexOf(pred.attribute) === -1 || !pred.ops ||
      pred.ops.kind !== "range" || pred.ops.bounds.length !== 1) {
    log.debug("Leaving ageOverThreshold(). Not an age lower bound.");
    return null;
  }
  var b = pred.ops.bounds[0];
  var nn = b.p_type === ">=" ? b.p_value : b.p_type === ">" ?
    b.p_value + 1 : null;
  log.debug("Leaving ageOverThreshold(). " + nn);
  return Number.isInteger(nn) && nn >= 0 && nn <= 99 ? nn : null;
}

// One predicate's plan: { id, attribute, description, mode, method,
// holds, ok, reason, anoncreds: [{ referent, name, p_type, p_value }],
// disclose: [names], notRevealed }.
//   method "zk"              proven without disclosing (AnonCreds CL)
//          "issuer-boolean"  answered by an issuer-computed claim (mdoc)
//          "disclose"        the value is disclosed (preferred, allowed)
//          "refused"         cannot be answered; ok false
function planPredicate(pred, format, lookup, opts) {
  log.debug("Entering planPredicate(). " + pred.id);
  var o = opts || {};
  var cap = capabilityOf(format);
  var out = { id: pred.id, attribute: pred.attribute, mode: pred.mode,
              description: describePredicate(pred.attribute, pred.ops),
              method: "refused", holds: null, ok: false, reason: "",
              anoncreds: [], disclose: [], notRevealed: pred.attribute,
              optional: !!pred.optional };
  if (!pred.ops || pred.ops.error) {
    out.reason = (pred.ops || {}).error || "no predicate.";
    log.debug("Leaving planPredicate(). Malformed.");
    return out;
  }
  var hit = predicateValue(pred, lookup);
  if (!hit.found && format === "mso_mdoc" && ageOverThreshold(pred) !==
      null) {
    hit = { found: false, mdocOnly: true };
  } else if (!hit.found) {
    out.reason = "the credential has no " + pred.attribute + " claim to " +
      "evaluate it over.";
    log.debug("Leaving planPredicate(). Absent.");
    return out;
  }
  var numeric = hit.found ? (typeof hit.value === "number" ? hit.value :
    i32Of(hit.value)) : null;
  if (hit.found) {
    out.holds = pred.ops.kind === "range" ?
      (numeric !== null && filterMatches(pred.filter, numeric)) :
      filterMatches(pred.filter, hit.value);
  }
  if (cap.zk === "range" && pred.ops.kind === "range") {
    var bad = pred.ops.bounds.filter(function (b) {
      return !Number.isInteger(b.p_value) || b.p_value < I32_MIN ||
        b.p_value > I32_MAX;
    });
    if (bad.length) {
      out.reason = "an AnonCreds p_value is an integer; " +
        bad.map(function (b) {
          return b.keyword + " " + b.p_value;
        }).join(", ") + " is not one.";
    } else if (i32Of(hit.value) === null) {
      out.reason = "AnonCreds proves a predicate only over an attribute " +
        "the issuer encoded as an integer, and " + pred.attribute + " is " +
        JSON.stringify(hit.value) + ".";
    } else if (!out.holds) {
      out.reason = "this credential does not satisfy " + out.description +
        " (it holds " + hit.value + "), so no proof exists.";
    } else {
      out.method = "zk";
      out.ok = true;
      out.reason = "proven in zero knowledge (CL range proof); the value " +
        "of " + pred.attribute + " is not revealed.";
      out.anoncreds = pred.ops.bounds.map(function (b) {
        return { referent: predicateReferent(pred.id, b),
                 name: pred.attribute, p_type: b.p_type,
                 p_value: b.p_value };
      });
    }
    log.debug("Leaving planPredicate(). AnonCreds: " + out.method);
    return out;
  }
  var nn = format === "mso_mdoc" ? ageOverThreshold(pred) : null;
  if (nn !== null) {
    var element = "age_over_" + (nn < 10 ? "0" + nn : String(nn));
    var flag = lookup([element]) || { found: false };
    if (flag.found && flag.value === true) {
      out.method = "issuer-boolean";
      out.ok = true;
      out.holds = true;
      out.disclose = [element];
      out.reason = "answered by the issuer-computed " + element + " = true " +
        "(ISO/IEC 18013-5 age attestation; this debugger's mapping of the " +
        "predicate). " + pred.attribute + " itself is not disclosed.";
      log.debug("Leaving planPredicate(). age_over_NN.");
      return out;
    }
    if (flag.found) {
      out.holds = false;
      out.reason = "the mdoc's " + element + " is " +
        JSON.stringify(flag.value) + ", so the predicate is not satisfied.";
      log.debug("Leaving planPredicate(). age_over_NN false.");
      return out;
    }
  }
  if (!hit.found) {
    out.reason = "the credential has neither " + pred.attribute + " nor an " +
      "age_over_NN element that answers it.";
    log.debug("Leaving planPredicate(). Absent (mdoc).");
    return out;
  }
  if (pred.mode === "preferred" && o.allowPreferredDisclosure) {
    out.method = "disclose";
    out.ok = true;
    out.disclose = [pred.attribute];
    out.notRevealed = "";
    out.reason = format + " cannot prove a predicate (" + cap.how + "); " +
      "the predicate is only \"preferred\", which PE 2.1.1 lets the " +
      "holder answer with the value, and that was allowed: " +
      pred.attribute + " IS disclosed.";
    log.debug("Leaving planPredicate(). Disclosed (preferred).");
    return out;
  }
  out.reason = format + " cannot prove " + out.description + " without " +
    "disclosing " + pred.attribute + " (" + cap.how + "), so the " +
    (pred.mode === "preferred" ? "preferred predicate is refused (this " +
     "wallet does not fall back to the value unless allowed)" :
     "required predicate is refused rather than answered with the value") +
    ".";
  log.debug("Leaving planPredicate(). Refused.");
  return out;
}

// The whole plan for one query item against a held credential.
// held: { format, lookup(path) -> { found, value }, ids: { schema_id, ...}
// (AnonCreds identifiers, for restrictions) }. opts:
// { allowPreferredDisclosure }.
//
// { ok, language, itemId, refusals: [text], claims: <selectClaims or PE
//   rows>, disclose: [attribute names], predicates: [planPredicate],
//   anoncredsPredicates: [...], notRevealed: [names], notes: [text] }
function planFor(model, item, held, opts) {
  log.debug("Entering planFor(). " + (item && item.id));
  var out = { ok: false, language: model.language, itemId: item.id,
              refusals: [], claims: null, disclose: [], predicates: [],
              anoncredsPredicates: [], notRevealed: [], notes: [] };
  if (model.errors && model.errors.length) {
    out.refusals = out.refusals.concat(model.errors);
  }
  if (item.extension && item.extension.refuse) {
    out.refusals.push(item.extension.refuse);
  }
  if (item.extension && item.extension.note) {
    out.notes.push(item.extension.note);
  }
  if (item.formats.length && held.format &&
      item.formats.indexOf(held.format) === -1 &&
      !(held.format === "anoncreds" && held.w3c &&
        item.formats.indexOf("di_vc") !== -1)) {
    out.refusals.push("the query asks for " + item.formats.join(" or ") +
                      " and this wallet holds " + held.format + ".");
  }
  if (item.restrictions && held.ids) {
    var met = item.restrictions.some(function (r) {
      return Object.keys(r).every(function (k) {
        return String(held.ids[k]) === String(r[k]);
      });
    });
    if (!met) {
      out.refusals.push("the credential does not meet the restrictions " +
                        JSON.stringify(item.restrictions) + ".");
    }
  }
  if (model.language === "dcql") {
    out.claims = selectClaims(item, held.lookup);
    if (!out.claims.satisfied) out.refusals.push(out.claims.reason);
    out.disclose = out.claims.selected.map(function (c) {
      return c.attribute;
    });
  } else {
    var rows = item.claims.map(function (c) {
      return peClaimRow(c, held.lookup);
    });
    item.metaFields.forEach(function (f) {
      var r = peClaimRow({ id: f.id, path: f.paths[0], pathAlternatives:
        f.paths, attribute: f.attribute, filter: f.filter,
        optional: f.optional }, held.lookup);
      r.meta = true;
      rows.push(r);
    });
    var short = rows.filter(function (r) {
      return r.status !== "available" && !r.optional;
    });
    out.claims = { satisfied: short.length === 0, rows: rows,
      reason: short.length ? "no Field Query Result for " +
        short.map(function (r) {
          return JSON.stringify(r.path);
        }).join(", ") + " (PE 2.1.1 Input Evaluation), so the Input " +
        "Descriptor cannot be answered." : "every field has a Field Query " +
        "Result." };
    if (short.length) out.refusals.push(out.claims.reason);
    out.disclose = rows.filter(function (r) {
      return r.status === "available" && !r.meta;
    }).map(function (r) {
      return r.attribute;
    });
  }
  item.predicates.forEach(function (p) {
    var plan = planPredicate(p, held.format, held.lookup, opts);
    out.predicates.push(plan);
    if (!plan.ok && !(plan.optional && plan.holds === null)) {
      out.refusals.push("predicate " + plan.id + " (" + plan.description +
                        "): " + plan.reason);
    }
    out.disclose = out.disclose.concat(plan.disclose.filter(function (n) {
      return out.disclose.indexOf(n) === -1;
    }));
    out.anoncredsPredicates = out.anoncredsPredicates.concat(plan.anoncreds);
    if (plan.ok && plan.notRevealed &&
        out.notRevealed.indexOf(plan.notRevealed) === -1) {
      out.notRevealed.push(plan.notRevealed);
    }
  });
  // CL cannot reveal an attribute and prove a predicate over it in one
  // presentation, and asking for both defeats the predicate anyway.
  out.predicates.forEach(function (p) {
    if (p.method === "zk" && out.disclose.indexOf(p.attribute) !== -1) {
      out.refusals.push(p.attribute + " is both requested and predicated: " +
                        "revealing it would make the predicate pointless, " +
                        "and AnonCreds refuses it.");
    }
  });
  out.ok = out.refusals.length === 0;
  log.debug("Leaving planFor(). ok=" + out.ok + ", " +
            out.refusals.length + " refusal(s).");
  return out;
}

// ---------------------------------------------------------------------------
// AnonCreds.
// ---------------------------------------------------------------------------

// The plan a VERIFIER reproduces, holding no credential: every claim (or
// `names`, the attributes a presentation revealed — a DCQL claim_sets
// choice is the wallet's) and every range predicate the item asks for.
// Fed to anoncredsRequestFor(), it reaches the request the wallet proved.
function nominalPlan(item, names) {
  log.debug("Entering nominalPlan().");
  var disclose = names ? names.slice() : item.claims.map(function (c) {
    return c.attribute;
  });
  var preds = [];
  item.predicates.forEach(function (p) {
    if (p.ops && p.ops.kind === "range") {
      p.ops.bounds.forEach(function (b) {
        preds.push({ referent: predicateReferent(p.id, b),
                     name: p.attribute, p_type: b.p_type,
                     p_value: b.p_value });
      });
    }
  });
  log.debug("Leaving nominalPlan().");
  return { disclose: disclose, anoncredsPredicates: preds };
}

// The AnonCreds presentation request for a plan: one requested attribute
// per disclosed claim (referent: the attribute name, as anoncreds_wallet.js
// always has), one requested predicate per bound. opts: { nonce (decimal
// digits), name, version, revocationTimestamp, restrictions }.
function anoncredsRequestFor(plan, opts) {
  log.debug("Entering anoncredsRequestFor().");
  var o = opts || {};
  var attrs = {};
  plan.disclose.forEach(function (n) {
    attrs[String(n)] = { name: String(n) };
    if (o.restrictions) attrs[String(n)].restrictions = o.restrictions;
  });
  var preds = {};
  plan.anoncredsPredicates.forEach(function (p) {
    preds[p.referent] = { name: p.name, p_type: p.p_type,
                          p_value: p.p_value };
    if (o.restrictions) preds[p.referent].restrictions = o.restrictions;
  });
  var out = { nonce: String(o.nonce), name: o.name || "OpenID4VP request",
              version: o.version || "1.0", requested_attributes: attrs,
              requested_predicates: preds };
  if (o.revocationTimestamp !== undefined &&
      o.revocationTimestamp !== null) {
    out.non_revoked = { from: o.revocationTimestamp,
                        to: o.revocationTimestamp };
  }
  log.debug("Leaving anoncredsRequestFor(). " + Object.keys(attrs).length +
            " attribute(s), " + Object.keys(preds).length + " predicate(s).");
  return out;
}

// The AnonCreds specification's presentation request object, checked:
// { request, errors }.
function readAnoncredsRequest(input) {
  log.debug("Entering readAnoncredsRequest().");
  var errors = [];
  var r;
  try {
    r = parseMaybeJson(input);
  } catch (e) {
    log.debug("Leaving readAnoncredsRequest(). Not JSON.");
    return { request: null, errors: ["the presentation request is " +
             e.message] };
  }
  if (!isObject(r)) {
    log.debug("Leaving readAnoncredsRequest(). Not an object.");
    return { request: null, errors: ["the presentation request is a JSON " +
             "object."] };
  }
  ["name", "version"].forEach(function (k) {
    if (typeof r[k] !== "string") errors.push(k + " is a string.");
  });
  if (typeof r.nonce !== "string" || !/^\d+$/.test(r.nonce)) {
    errors.push("nonce is a string of decimal digits (an 80-bit number).");
  }
  if (!isObject(r.requested_attributes)) {
    errors.push("requested_attributes is an object.");
  } else {
    Object.keys(r.requested_attributes).forEach(function (ref) {
      var a = r.requested_attributes[ref];
      var hasName = isObject(a) && typeof a.name === "string";
      var hasNames = isObject(a) && isArray(a.names) && a.names.length > 0;
      if (hasName === hasNames) {
        errors.push("requested_attributes." + ref + " has one of name and " +
                    "names, not both.");
      }
    });
  }
  if (r.requested_predicates !== undefined &&
      !isObject(r.requested_predicates)) {
    errors.push("requested_predicates is an object.");
  }
  Object.keys(isObject(r.requested_predicates) ? r.requested_predicates :
              {}).forEach(function (ref) {
    var p = r.requested_predicates[ref];
    var where = "requested_predicates." + ref;
    if (!isObject(p) || typeof p.name !== "string") {
      errors.push(where + ".name is a string.");
      return;
    }
    if (P_TYPES.indexOf(p.p_type) === -1) {
      errors.push(where + ".p_type is one of " + P_TYPES.join(" ") + ".");
    }
    if (!Number.isInteger(p.p_value) || p.p_value < I32_MIN ||
        p.p_value > I32_MAX) {
      errors.push(where + ".p_value is an integer.");
    }
  });
  if (r.non_revoked !== undefined && (!isObject(r.non_revoked) ||
      ["from", "to"].some(function (k) {
        return r.non_revoked[k] !== undefined &&
          !Number.isInteger(r.non_revoked[k]);
      }))) {
    errors.push("non_revoked is { from, to }, each an integer timestamp.");
  }
  log.debug("Leaving readAnoncredsRequest(). " + errors.length +
            " error(s).");
  return { request: r, errors: errors };
}

// ---------------------------------------------------------------------------
// Composing a query (the page, the Verifier, and an AnonCreds request read
// back into either language).
//
// spec: { language: "pe" | "dcql", id, format, reveal: [names],
//   predicates: [{ id, name, p_type, p_value, mode }], restrictions:
//   [{ tag: value }], purpose }
// ---------------------------------------------------------------------------

var FILTER_KEYWORD_FOR = { ">=": "minimum", ">": "exclusiveMinimum",
                           "<=": "maximum", "<": "exclusiveMaximum" };

function filterFor(bounds) {
  log.debug("Entering filterFor().");
  var f = { type: "integer" };
  bounds.forEach(function (b) {
    f[FILTER_KEYWORD_FOR[b.p_type]] = b.p_value;
  });
  log.debug("Leaving filterFor().");
  return f;
}

// Predicates grouped by attribute, so "age >= 18 and age < 65" is ONE
// field with two bounds (a filter cannot hold minimum twice).
function groupPredicates(predicates) {
  log.debug("Entering groupPredicates().");
  var groups = [];
  predicates.forEach(function (p) {
    if (P_TYPES.indexOf(p.p_type) === -1) {
      throw new Error("p_type is one of " + P_TYPES.join(" ") + ", not " +
                      JSON.stringify(p.p_type) + ".");
    }
    var g = groups.filter(function (x) {
      return x.name === p.name && (x.mode || "required") ===
        (p.mode || "required") && !x.bounds.some(function (b) {
          return FILTER_KEYWORD_FOR[b.p_type] ===
            FILTER_KEYWORD_FOR[p.p_type];
        });
    })[0];
    if (!g) {
      g = { id: p.id || p.name, name: p.name, mode: p.mode || "required",
            bounds: [] };
      groups.push(g);
    }
    g.bounds.push({ p_type: p.p_type, p_value: Number(p.p_value) });
  });
  log.debug("Leaving groupPredicates(). " + groups.length);
  return groups;
}

function peFormatFor(format) {
  log.debug("Entering peFormatFor(). " + format);
  var out = {};
  if (format === "di_vc") {
    out.di_vc = { proof_type: ["DataIntegrityProof"],
                  cryptosuite: ["anoncreds-2023"] };
  } else {
    out[format] = {};
  }
  log.debug("Leaving peFormatFor().");
  return out;
}

function buildQuery(spec) {
  log.debug("Entering buildQuery(). " + spec.language);
  var id = spec.id || "credential";
  var format = spec.format || "anoncreds";
  var groups = groupPredicates(spec.predicates || []);
  if (spec.language === "pe") {
    var fields = [];
    (spec.restrictions || []).forEach(function (r) {
      Object.keys(r).forEach(function (tag) {
        fields.push({ path: ["$." + tag], filter: { type: "string",
                                                    const: r[tag] } });
      });
    });
    (spec.reveal || []).forEach(function (n) {
      fields.push({ path: [jsonPathOf(["credentialSubject", n]),
                           jsonPathOf([n])] });
    });
    groups.forEach(function (g) {
      fields.push({ id: g.id, path: [jsonPathOf(["credentialSubject",
        g.name]), jsonPathOf([g.name])], filter: filterFor(g.bounds),
        predicate: g.mode });
    });
    var descriptor = { id: id, format: peFormatFor(format),
                       constraints: { limit_disclosure: "required",
                                      fields: fields } };
    if (spec.purpose) descriptor.purpose = spec.purpose;
    log.debug("Leaving buildQuery(). PE.");
    return { presentation_definition: { id: spec.definitionId ||
      "predicates-" + id, input_descriptors: [descriptor] } };
  }
  var cq = { id: id, format: format };
  if ((spec.reveal || []).length) {
    cq.claims = spec.reveal.map(function (n) {
      return { path: [n] };
    });
  }
  if (groups.length) {
    cq[EXT_PREDICATES] = groups.map(function (g) {
      return { id: g.id.replace(/[^A-Za-z0-9_-]/g, "_"), path: [g.name],
               filter: filterFor(g.bounds) };
    });
    cq[EXT_CRIT] = [EXT_PREDICATES];
  }
  log.debug("Leaving buildQuery(). DCQL.");
  return { dcql_query: { credentials: [cq] } };
}

// An AnonCreds presentation request as a spec for buildQuery(): its
// requested attributes become claims, its predicates predicates. A
// restriction that is not a plain conjunction of tags is dropped with a
// warning (PE fields express only one tag each).
function specFromAnoncredsRequest(req, language) {
  log.debug("Entering specFromAnoncredsRequest().");
  var reveal = [];
  var warnings = [];
  var restrictions = null;
  var noteRestriction = function (r) {
    log.debug("Entering noteRestriction().");
    if (r === undefined) {
      log.debug("Leaving noteRestriction(). None.");
      return;
    }
    var list = [].concat(r);
    var plain = list.every(function (x) {
      return isObject(x) && Object.keys(x).every(function (k) {
        return RESTRICTION_TAGS.indexOf(k) !== -1;
      });
    });
    if (!plain) {
      warnings.push("a restriction " + JSON.stringify(r) + " is not a " +
                    "list of tag conjunctions and is not carried over.");
      log.debug("Leaving noteRestriction(). Not plain.");
      return;
    }
    restrictions = list;
    log.debug("Leaving noteRestriction().");
  };
  Object.keys(req.requested_attributes || {}).forEach(function (ref) {
    var a = req.requested_attributes[ref];
    [].concat(a.names || a.name).forEach(function (n) {
      if (reveal.indexOf(n) === -1) reveal.push(n);
    });
    noteRestriction(a.restrictions);
  });
  var predicates = Object.keys(req.requested_predicates || {}).map(
    function (ref) {
      var p = req.requested_predicates[ref];
      noteRestriction(p.restrictions);
      return { id: p.name, name: p.name, p_type: p.p_type,
               p_value: p.p_value, mode: "required" };
    });
  var single = restrictions && restrictions.length === 1 ? restrictions :
    null;
  if (restrictions && !single) {
    warnings.push("a restriction with alternatives (OR) is not carried " +
                  "over: a PE field holds one const per tag.");
  }
  log.debug("Leaving specFromAnoncredsRequest().");
  return { spec: { language: language || "pe", id: "anoncreds",
                   format: "anoncreds", reveal: reveal,
                   predicates: predicates, restrictions: single || [],
                   definitionId: req.name ? String(req.name)
                     .replace(/[^A-Za-z0-9_.-]/g, "-") : undefined },
           warnings: warnings };
}

// ---------------------------------------------------------------------------
// Capability advertisement (NON-STANDARD: no specification defines one).
// ---------------------------------------------------------------------------

function formatsTable() {
  log.debug("Entering formatsTable().");
  var out = {};
  Object.keys(FORMAT_PREDICATES).forEach(function (f) {
    var c = FORMAT_PREDICATES[f];
    if (c.zk) out[f] = { proof: "zero-knowledge", p_types: c.ops.slice() };
    else if (c.issuerBoolean) {
      out[f] = { proof: "issuer-computed", claims: [c.issuerBoolean] };
    }
  });
  log.debug("Leaving formatsTable().");
  return out;
}

// What this wallet puts in wallet_metadata (OpenID4VP 1.0 section 10 /
// request_uri_method=post) under EXT_METADATA.
function walletMetadataExtension() {
  log.debug("Entering walletMetadataExtension().");
  log.debug("Leaving walletMetadataExtension().");
  return { query_languages: ["presentation_definition", "dcql:" +
                             EXT_PREDICATES],
           crit_understood: UNDERSTOOD_CRIT.slice(),
           formats: formatsTable(),
           note: "id-proto-debugger extension; no specification defines " +
                 "predicate capability metadata." };
}

// What a Verifier puts in client_metadata under EXT_METADATA: the formats
// whose predicate proofs it verifies.
function verifierMetadataExtension(formats) {
  log.debug("Entering verifierMetadataExtension().");
  var table = formatsTable();
  var out = {};
  [].concat(formats || Object.keys(table)).forEach(function (f) {
    if (table[f]) out[f] = table[f];
  });
  log.debug("Leaving verifierMetadataExtension().");
  return { formats: out, note: "id-proto-debugger extension; no " +
           "specification defines predicate capability metadata." };
}

module.exports = {
  PE_VERSION: PE_VERSION,
  LABEL_PE: LABEL_PE,
  LABEL_EXT: LABEL_EXT,
  EXT_PREDICATES: EXT_PREDICATES,
  EXT_CRIT: EXT_CRIT,
  EXT_METADATA: EXT_METADATA,
  P_TYPES: P_TYPES,
  FORMAT_PREDICATES: FORMAT_PREDICATES,
  parseJsonPath: parseJsonPath,
  jsonPathOf: jsonPathOf,
  selectAll: selectAll,
  attributeOf: attributeOf,
  filterMatches: filterMatches,
  unsupportedKeywords: unsupportedKeywords,
  predicateOps: predicateOps,
  describePredicate: describePredicate,
  predicateReferent: predicateReferent,
  dateInt: dateInt,
  ageThresholdDateInt: ageThresholdDateInt,
  readDefinition: readDefinition,
  submissionRequirementsMet: submissionRequirementsMet,
  buildSubmission: buildSubmission,
  checkSubmission: checkSubmission,
  readExtension: readExtension,
  normalise: normalise,
  valueMatches: valueMatches,
  selectClaims: selectClaims,
  capabilityOf: capabilityOf,
  ageOverThreshold: ageOverThreshold,
  planPredicate: planPredicate,
  planFor: planFor,
  nominalPlan: nominalPlan,
  anoncredsRequestFor: anoncredsRequestFor,
  readAnoncredsRequest: readAnoncredsRequest,
  buildQuery: buildQuery,
  specFromAnoncredsRequest: specFromAnoncredsRequest,
  walletMetadataExtension: walletMetadataExtension,
  verifierMetadataExtension: verifierMetadataExtension
};
