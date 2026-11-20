// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_schema.js
//
// ---------------------------------------------------------------------------
// JSON Schema validation of an ACDC against the schema its s names (#480).
//
// The ACDC specification has the schema govern the credential: a verifier
// validates the credential body AS PRESENTED (compact, partial or full)
// against the schema whose SAID is its s. The dialect is the schema's own
// $schema: draft-07, or 2020-12 when it names it — the two keri-ts 2.2.9
// and keripy accept.
//
// The engine is @cfworker/json-schema 4.1.6 (MIT), the one keri-ts uses, and
// it is used the way keri-ts uses it (keri-ts core/json-schema.js):
//
//   - `format` never rejects: neither keripy's validator nor keri-ts checks
//     formats, so each `format` keyword is removed before validating;
//   - `$dynamicRef`, which the engine cannot interpret, is refused rather
//     than silently ignored;
//   - an invalid `pattern` is a refusal of the schema, not of the data.
//
// It interprets schemas and generates no code, so it works under any
// Content-Security-Policy. Pure JavaScript.
//
// NO DOM.
// ---------------------------------------------------------------------------

var cfworker = require("@cfworker/json-schema");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc_schema",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Keyword positions that hold subschemas; everything else is data.
var SINGLES = ["items", "contains", "additionalProperties",
               "unevaluatedProperties", "propertyNames", "not", "if", "then",
               "else", "contentSchema", "unevaluatedItems",
               "additionalItems"];
var MAPS = ["$defs", "definitions", "properties", "patternProperties",
            "dependentSchemas", "dependencies"];
var LISTS = ["prefixItems", "allOf", "anyOf", "oneOf", "items"];

function isMap(v) {
  log.debug("Entering isMap().");
  log.debug("Leaving isMap().");
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Every subschema of `schema`, itself included, by keyword position.
function visit(schema, each) {
  log.debug("Entering visit().");
  if (!isMap(schema)) {
    log.debug("Leaving visit(). Not a schema object.");
    return;
  }
  each(schema);
  SINGLES.forEach(function (k) {
    visit(schema[k], each);
  });
  MAPS.forEach(function (k) {
    if (isMap(schema[k])) {
      Object.keys(schema[k]).forEach(function (name) {
        visit(schema[k][name], each);
      });
    }
  });
  LISTS.forEach(function (k) {
    if (Array.isArray(schema[k])) {
      schema[k].forEach(function (s) {
        visit(s, each);
      });
    }
  });
  log.debug("Leaving visit().");
}

// The dialect a schema selects with $schema: "2020-12" or "7".
function dialectOf(schema) {
  log.debug("Entering dialectOf().");
  log.debug("Leaving dialectOf().");
  return isMap(schema) && typeof schema.$schema === "string" &&
    schema.$schema.indexOf("2020-12") !== -1 ? "2020-12" : "7";
}

// A copy of `schema` prepared as keri-ts prepares it: formats removed,
// $dynamicRef refused, patterns checked.
function prepare(schema) {
  log.debug("Entering prepare().");
  var copy = JSON.parse(JSON.stringify(schema));
  visit(copy, function (s) {
    if (typeof s.format === "string") {
      delete s.format;
    }
    if (Object.prototype.hasOwnProperty.call(s, "$dynamicRef")) {
      throw new Error("the schema uses $dynamicRef, which this engine " +
                      "cannot interpret; it is refused rather than " +
                      "ignored.");
    }
    if (typeof s.pattern === "string") {
      new RegExp(s.pattern, "u");
    }
    if (isMap(s.patternProperties)) {
      Object.keys(s.patternProperties).forEach(function (p) {
        new RegExp(p, "u");
      });
    }
  });
  log.debug("Leaving prepare().");
  return copy;
}

// Validate `data` (the credential body as presented) against `schema`.
// Answers { valid, dialect, errors: ["path: message"], reason }.
function validate(schema, data) {
  log.debug("Entering validate().");
  var dialect = dialectOf(schema);
  var prepared;
  try {
    prepared = prepare(schema);
  } catch (e) {
    log.debug("Leaving validate(). Schema refused.");
    return { valid: false, dialect: dialect, errors: [],
             reason: "the schema cannot be used: " + e.message };
  }
  var outcome;
  try {
    outcome = new cfworker.Validator(prepared, dialect, false)
      .validate(data);
  } catch (e) {
    log.debug("Leaving validate(). Engine error.");
    return { valid: false, dialect: dialect, errors: [],
             reason: "the schema cannot be applied: " + e.message };
  }
  var errors = (outcome.errors || []).filter(function (e) {
    return e.keyword !== "properties" && e.keyword !== "oneOf" ||
      outcome.errors.length === 1;
  }).map(function (e) {
    return (e.instanceLocation || "#").replace(/^#/, "data") + ": " +
      e.error;
  });
  log.debug("Leaving validate(). " + outcome.valid);
  return { valid: !!outcome.valid, dialect: dialect, errors: errors,
           reason: outcome.valid ? "" : errors.slice(0, 3).join("; ") };
}

module.exports = {
  validate: validate,
  dialectOf: dialectOf,
  prepare: prepare
};
