// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_function_cases.js
//
// ---------------------------------------------------------------------------
// EVERY XACML 3.0 STANDARD FUNCTION, AS A POLICY WITH A KNOWN ANSWER.
//
// One case is one Policy holding one Permit rule whose Condition applies the
// function under test to literal values and checks what came back. The
// combining algorithm is first-applicable, so the three outcomes say three
// different things:
//
//   Permit          the function returned what XACML 3.0 Appendix A says
//   NotApplicable   it returned something else
//   Indeterminate   it raised a processing error (or a literal did not parse)
//
// and each case names the one it expects. The expected values are read from
// the specification and from the datatypes' own lexical rules (XML Schema
// Part 2 for the xs: types, A.3 and B for the XACML ones), never from what
// this engine happens to answer — a table copied from the implementation's
// output would pass whatever the implementation does.
//
// It is DATA and a builder, with no engine and no DOM, so that the same cases
// run twice: in node against the engine (xacml_functions_engine.js), and in a
// browser through xacml.html's import and Decide controls
// (xacml_functions_page.js). Function identifiers are written short
// ("integer-add") and resolved by the caller, because the version segment of
// each URI (1.0, 2.0 or 3.0) is the engine's registry's business and is
// checked by the OASIS conformance cases in xacml_engine.js.
// ---------------------------------------------------------------------------

"use strict";

const bunyan = require("bunyan");

const log = bunyan.createLogger({
  name: "xacml_function_cases",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const XS = "http://www.w3.org/2001/XMLSchema#";
const XACML_TYPE = {
  rfc822Name: "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name",
  x500Name: "urn:oasis:names:tc:xacml:1.0:data-type:x500Name",
  dnsName: "urn:oasis:names:tc:xacml:2.0:data-type:dnsName",
  ipAddress: "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress"
};
const NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const FIRST_APPLICABLE =
  "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable";

// The URI of a short type name: an XML Schema type unless it is one of the
// four XACML defines itself.
function typeUri(name) {
  log.debug("Entering typeUri().");
  const uri = XACML_TYPE[name] || XS + name;
  log.debug("Leaving typeUri().");
  return uri;
}

function escapeXml(text) {
  log.debug("Entering escapeXml().");
  const escaped = String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  log.debug("Leaving escapeXml().");
  return escaped;
}

// ---------------------------------------------------------------------------
// THE EXPRESSION BUILDER. An expression is a function of the resolver, so a
// case can be written before anybody knows the URIs.
// ---------------------------------------------------------------------------

// <AttributeValue> of the short type `type`.
function v(type, text) {
  log.debug("Entering v().");
  const built = function () {
    return "<AttributeValue DataType=\"" + typeUri(type) + "\">" +
      escapeXml(text) + "</AttributeValue>";
  };
  log.debug("Leaving v().");
  return built;
}

// <Apply> of the function named `name`.
function a(name) {
  log.debug("Entering a().");
  const args = Array.prototype.slice.call(arguments, 1);
  const built = function (uriOf) {
    return "<Apply FunctionId=\"" + uriOf(name) + "\">" +
      args.map(function (arg) {
        return arg(uriOf);
      }).join("") + "</Apply>";
  };
  log.debug("Leaving a().");
  return built;
}

// <Function> reference, for the higher-order functions and map.
function fn(name) {
  log.debug("Entering fn().");
  const built = function (uriOf) {
    return "<Function FunctionId=\"" + uriOf(name) + "\"/>";
  };
  log.debug("Leaving fn().");
  return built;
}

// <Apply> of a function identifier given whole, for the case that names a
// function the engine does not have.
function unknownApply(uri) {
  log.debug("Entering unknownApply().");
  const args = Array.prototype.slice.call(arguments, 1);
  const built = function (uriOf) {
    return "<Apply FunctionId=\"" + escapeXml(uri) + "\">" +
      args.map(function (arg) {
        return arg(uriOf);
      }).join("") + "</Apply>";
  };
  log.debug("Leaving unknownApply().");
  return built;
}

// A bag of `type` from literal texts.
function bag(type) {
  log.debug("Entering bag().");
  const values = Array.prototype.slice.call(arguments, 1);
  const built = a.apply(null, [type + "-bag"].concat(values.map(function (t) {
    return v(type, t);
  })));
  log.debug("Leaving bag().");
  return built;
}

// The bag size of `expression` equals `n`.
function sizeIs(type, expression, n) {
  log.debug("Entering sizeIs().");
  const built = a("integer-equal", a(type + "-bag-size", expression),
                  v("integer", String(n)));
  log.debug("Leaving sizeIs().");
  return built;
}

// ---------------------------------------------------------------------------
// THE SAMPLE VALUES. For every type: two values `lo` and `hi` that are not
// equal, `same`, a DIFFERENT lexical form of `lo` that the type's equality
// must nevertheless call equal (where the type has one — that is most of
// what each datatype's parser and equality are for), and `bad`, a text the
// type must refuse. For the totally ordered types `lo` < `hi`.
// ---------------------------------------------------------------------------
const SAMPLES = [
  { type: "string", lo: "abc", hi: "abd", bad: null, ordered: true },
  { type: "boolean", lo: "true", hi: "false", same: "1", bad: "yes" },
  { type: "integer", lo: "9", hi: "10", same: "+09", bad: "1.5",
    ordered: true },
  { type: "double", lo: "1.5", hi: "1E1", same: "15E-1", bad: "one",
    ordered: true },
  { type: "anyURI", lo: "https://a.example/x", hi: "https://b.example/y",
    bad: null },
  { type: "hexBinary", lo: "0fa1", hi: "ff", same: "0FA1", bad: "0fa" },
  { type: "base64Binary", lo: "aGVsbG8=", hi: "d29ybGQ=", bad: "a===" },
  { type: "date", lo: "2020-02-29", hi: "2021-01-01", bad: "2021-02-29",
    ordered: true },
  { type: "time", lo: "10:00:00", hi: "23:59:59.5", same: "10:00:00.000",
    bad: "24:01:00", ordered: true },
  // 12:00+01:00 is 11:00Z, after lo; `same` is lo written in another zone.
  { type: "dateTime", lo: "2020-02-29T10:00:00Z",
    hi: "2020-02-29T12:00:00+01:00", same: "2020-02-29T05:00:00-05:00",
    bad: "2020-02-30T10:00:00Z", ordered: true },
  // 14 months and 15; P1Y2M and P14M are the same duration.
  { type: "yearMonthDuration", lo: "P1Y2M", hi: "P15M", same: "P14M",
    bad: "P1D" },
  // 36 hours and 37; PT36H and P1DT12H are the same duration.
  { type: "dayTimeDuration", lo: "PT36H", hi: "P1DT13H", same: "P1DT12H",
    bad: "P1Y" },
  // B.13: the domain part is compared without regard to case, the local
  // part with it.
  { type: "rfc822Name", lo: "Anne@example.com", hi: "bob@example.com",
    same: "Anne@EXAMPLE.com", bad: "no-at-sign" },
  { type: "x500Name", lo: "cn=Anne,o=Example", hi: "cn=Bob,o=Example",
    bad: null },
  { type: "dnsName", lo: "www.example.com", hi: "*.example.org",
    bad: "bad..name" },
  { type: "ipAddress", lo: "192.168.1.10", hi: "10.0.0.1/255.0.0.0:443",
    bad: "10.0.0" }
];

// An <AttributeValue> of a DataType given whole.
function unknownValue(typeUriText, text) {
  log.debug("Entering unknownValue().");
  const built = function () {
    return "<AttributeValue DataType=\"" + escapeXml(typeUriText) + "\">" +
      escapeXml(text) + "</AttributeValue>";
  };
  log.debug("Leaving unknownValue().");
  return built;
}

// One case.
function kase(name, expect, expression) {
  log.debug("Entering kase().");
  const made = { name: name, expect: expect, expression: expression };
  log.debug("Leaving kase().");
  return made;
}

// The generic families every type has: equality, the bag functions and the
// set functions (A.3.1, A.3.10, A.3.11), plus the comparisons for the
// ordered types (A.3.6, A.3.7) and the string conversions (A.3.9).
function genericCases(s) {
  log.debug("Entering genericCases().");
  const t = s.type;
  const lo = v(t, s.lo);
  const hi = v(t, s.hi);
  const out = [
    kase(t + "-equal holds of a value and itself", "Permit",
         a(t + "-equal", lo, lo)),
    kase(t + "-equal refuses two different values", "NotApplicable",
         a(t + "-equal", lo, hi)),
    kase(t + "-one-and-only of a bag of one", "Permit",
         a(t + "-equal", a(t + "-one-and-only", bag(t, s.lo)), lo)),
    kase(t + "-one-and-only of a bag of two is an error", "Indeterminate",
         a(t + "-equal", a(t + "-one-and-only", bag(t, s.lo, s.hi)), lo)),
    kase(t + "-one-and-only of an empty bag is an error", "Indeterminate",
         a(t + "-equal", a(t + "-one-and-only", bag(t)), lo)),
    kase(t + "-bag-size counts duplicates", "Permit",
         sizeIs(t, bag(t, s.lo, s.hi, s.lo), 3)),
    kase(t + "-is-in finds a member", "Permit",
         a(t + "-is-in", lo, bag(t, s.hi, s.lo))),
    kase(t + "-is-in misses a non-member", "NotApplicable",
         a(t + "-is-in", lo, bag(t, s.hi))),
    kase(t + "-at-least-one-member-of", "Permit",
         a(t + "-at-least-one-member-of", bag(t, s.lo),
           bag(t, s.hi, s.lo))),
    kase(t + "-at-least-one-member-of with no overlap", "NotApplicable",
         a(t + "-at-least-one-member-of", bag(t, s.lo), bag(t, s.hi))),
    kase(t + "-subset", "Permit",
         a(t + "-subset", bag(t, s.lo, s.lo), bag(t, s.lo, s.hi))),
    kase(t + "-subset refuses a superset", "NotApplicable",
         a(t + "-subset", bag(t, s.lo, s.hi), bag(t, s.lo))),
    kase(t + "-set-equals ignores order and duplicates", "Permit",
         a(t + "-set-equals", bag(t, s.lo, s.hi), bag(t, s.hi, s.lo, s.lo))),
    kase(t + "-intersection keeps the common value once", "Permit",
         sizeIs(t, a(t + "-intersection", bag(t, s.lo, s.hi, s.hi),
                     bag(t, s.hi, s.hi)), 1)),
    kase(t + "-union drops duplicates", "Permit",
         sizeIs(t, a(t + "-union", bag(t, s.lo, s.lo), bag(t, s.hi, s.lo)),
                2)),
    // A.3.9: the from-string/string-from pair round-trips a value.
    kase(t + "-from-string of string-from-" + t + " round-trips", "Permit",
         a(t + "-equal",
           a(t + "-from-string", a("string-from-" + t, lo)), lo))
  ];
  if (s.same) {
    out.push(kase(t + "-equal compares values, not spellings (" + s.same +
                  ")", "Permit", a(t + "-equal", lo, v(t, s.same))));
  }
  if (s.bad) {
    out.push(kase(t + " refuses the literal \"" + s.bad + "\"",
                  "Indeterminate", a(t + "-equal", v(t, s.bad), lo)));
    out.push(kase(t + "-from-string refuses \"" + s.bad + "\"",
                  "Indeterminate",
                  a(t + "-equal", a(t + "-from-string", v("string", s.bad)),
                    lo)));
  }
  if (s.ordered) {
    out.push(
      kase(t + "-less-than", "Permit", a(t + "-less-than", lo, hi)),
      kase(t + "-less-than is strict", "NotApplicable",
           a(t + "-less-than", lo, lo)),
      kase(t + "-less-than-or-equal", "Permit",
           a(t + "-less-than-or-equal", lo, lo)),
      kase(t + "-greater-than", "Permit", a(t + "-greater-than", hi, lo)),
      kase(t + "-greater-than the wrong way round", "NotApplicable",
           a(t + "-greater-than", lo, hi)),
      kase(t + "-greater-than-or-equal", "Permit",
           a(t + "-greater-than-or-equal", hi, hi)));
  }
  log.debug("Leaving genericCases().");
  return out;
}

function int(n) {
  log.debug("Entering int().");
  const built = v("integer", String(n));
  log.debug("Leaving int().");
  return built;
}

function dbl(n) {
  log.debug("Entering dbl().");
  const built = v("double", String(n));
  log.debug("Leaving dbl().");
  return built;
}

function str(s) {
  log.debug("Entering str().");
  const built = v("string", s);
  log.debug("Leaving str().");
  return built;
}

function bool(b) {
  log.debug("Entering bool().");
  const built = v("boolean", b ? "true" : "false");
  log.debug("Leaving bool().");
  return built;
}

// An integer result equals `n`.
function intIs(expression, n) {
  log.debug("Entering intIs().");
  const built = a("integer-equal", expression, int(n));
  log.debug("Leaving intIs().");
  return built;
}

function dblIs(expression, n) {
  log.debug("Entering dblIs().");
  const built = a("double-equal", expression, dbl(n));
  log.debug("Leaving dblIs().");
  return built;
}

function strIs(expression, s) {
  log.debug("Entering strIs().");
  const built = a("string-equal", expression, str(s));
  log.debug("Leaving strIs().");
  return built;
}

// A.3.2 and A.3.3: arithmetic, and the integer/double conversions.
function arithmeticCases() {
  log.debug("Entering arithmeticCases().");
  const out = [
    kase("integer-add takes any number of arguments", "Permit",
         intIs(a("integer-add", int(2), int(3), int(-7)), -2)),
    kase("integer-subtract", "Permit",
         intIs(a("integer-subtract", int(2), int(5)), -3)),
    kase("integer-multiply", "Permit",
         intIs(a("integer-multiply", int(-4), int(6), int(2)), -48)),
    kase("integer-divide truncates toward zero", "Permit",
         intIs(a("integer-divide", int(-7), int(2)), -3)),
    kase("integer-divide by zero is an error", "Indeterminate",
         intIs(a("integer-divide", int(1), int(0)), 0)),
    kase("integer-mod", "Permit", intIs(a("integer-mod", int(17), int(5)), 2)),
    kase("integer-mod by zero is an error", "Indeterminate",
         intIs(a("integer-mod", int(1), int(0)), 0)),
    kase("integer-abs", "Permit", intIs(a("integer-abs", int(-12)), 12)),
    kase("double-add", "Permit",
         dblIs(a("double-add", dbl(1.5), dbl(2.25)), 3.75)),
    kase("double-subtract", "Permit",
         dblIs(a("double-subtract", dbl(1.5), dbl(2)), -0.5)),
    kase("double-multiply", "Permit",
         dblIs(a("double-multiply", dbl(1.5), dbl(-4)), -6)),
    kase("double-divide", "Permit",
         dblIs(a("double-divide", dbl(7), dbl(2)), 3.5)),
    kase("double-divide by zero is an error", "Indeterminate",
         dblIs(a("double-divide", dbl(1), dbl(0)), 0)),
    kase("double-add of four", "Permit",
         dblIs(a("double-add", dbl(0.5), dbl(0.25), dbl(0.25), dbl(1)), 2)),
    kase("double-multiply of three", "Permit",
         dblIs(a("double-multiply", dbl(0.5), dbl(4), dbl(-1)), -2)),
    kase("integer-add of one argument is refused at load", "Refused",
         intIs(a("integer-add", int(1)), 1)),
    kase("integer-subtract of three is refused at load", "Refused",
         intIs(a("integer-subtract", int(1), int(2), int(3)), 1)),
    kase("double-abs", "Permit", dblIs(a("double-abs", dbl(-2.5)), 2.5)),
    kase("round goes to the nearest even on a half", "Permit",
         dblIs(a("round", dbl(2.5)), 2)),
    kase("round of 3.5", "Permit", dblIs(a("round", dbl(3.5)), 4)),
    kase("floor of a negative", "Permit", dblIs(a("floor", dbl(-1.5)), -2)),
    kase("double-to-integer truncates", "Permit",
         intIs(a("double-to-integer", dbl(-2.9)), -2)),
    kase("integer-to-double", "Permit",
         dblIs(a("integer-to-double", int(7)), 7)),
    kase("an arithmetic function refuses a bag where a value goes",
         "Refused", intIs(a("integer-abs", bag("integer", "1", "2")), 1)),
    kase("an integer function refuses a double", "Refused",
         intIs(a("integer-abs", dbl(1)), 1))
  ];
  log.debug("Leaving arithmeticCases().");
  return out;
}

// A.3.4, A.3.9 and A.3.12: the string functions and the conversions whose
// output text is fixed by the canonical forms.
function stringCases() {
  log.debug("Entering stringCases().");
  const out = [
    kase("string-normalize-space trims both ends only", "Permit",
         strIs(a("string-normalize-space", str("  a  b \t")), "a  b")),
    kase("string-normalize-to-lower-case", "Permit",
         strIs(a("string-normalize-to-lower-case", str("MiXeD")), "mixed")),
    kase("string-concatenate", "Permit",
         strIs(a("string-concatenate", str("ab"), str(""), str("cd")),
               "abcd")),
    kase("string-starts-with", "Permit",
         a("string-starts-with", str("ab"), str("abc"))),
    kase("string-starts-with is case-sensitive", "NotApplicable",
         a("string-starts-with", str("AB"), str("abc"))),
    kase("string-ends-with", "Permit",
         a("string-ends-with", str("bc"), str("abc"))),
    kase("string-contains", "Permit",
         a("string-contains", str("b"), str("abc"))),
    kase("string-contains misses", "NotApplicable",
         a("string-contains", str("x"), str("abc"))),
    kase("string-substring from 1 to 3", "Permit",
         strIs(a("string-substring", str("abcde"), int(1), int(3)), "bc")),
    kase("string-substring to the end with -1", "Permit",
         strIs(a("string-substring", str("abcde"), int(2), int(-1)), "cde")),
    kase("string-substring past the end is an error", "Indeterminate",
         strIs(a("string-substring", str("abc"), int(1), int(9)), "bc")),
    kase("anyURI-starts-with", "Permit",
         a("anyURI-starts-with", str("https://"),
           v("anyURI", "https://a.example/x"))),
    kase("anyURI-ends-with", "Permit",
         a("anyURI-ends-with", str("/x"), v("anyURI", "https://a.example/x"))),
    kase("anyURI-contains", "Permit",
         a("anyURI-contains", str("example"),
           v("anyURI", "https://a.example/x"))),
    kase("anyURI-substring", "Permit",
         strIs(a("anyURI-substring", v("anyURI", "https://a.example/x"),
                 int(0), int(5)), "https")),
    kase("string-from-integer is canonical", "Permit",
         strIs(a("string-from-integer", int("+007")), "7")),
    kase("string-from-boolean is canonical", "Permit",
         strIs(a("string-from-boolean", v("boolean", "1")), "true")),
    kase("boolean-from-string", "Permit",
         a("boolean-from-string", str("true"))),
    kase("integer-from-string", "Permit",
         intIs(a("integer-from-string", str("-12")), -12)),
    kase("double-from-string", "Permit",
         dblIs(a("double-from-string", str("2.5E1")), 25)),
    kase("string-from-string is the identity", "Permit",
         strIs(a("string-from-string", str("x y")), "x y")),
    kase("string-regexp-match", "Permit",
         a("string-regexp-match", str("a[bc]+d"), str("abcbd"))),
    kase("string-regexp-match fails", "NotApplicable",
         a("string-regexp-match", str("a[bc]+d"), str("abed"))),
    kase("string-regexp-match with the \\d escape", "Permit",
         a("string-regexp-match", str("\\d{3}-\\d{4}"), str("555-1234"))),
    kase("string-regexp-match refuses a malformed pattern", "Indeterminate",
         a("string-regexp-match", str("a(b"), str("ab"))),
    // A.3.13 IS xf:matches, WHICH SEARCHES. A pattern matches anywhere in
    // the value unless it says ^ or $ — the opposite of an XML Schema pattern
    // facet, which this engine implemented until 2026-11-13.
    kase("string-regexp-match finds a match anywhere", "Permit",
         a("string-regexp-match", str("b+"), str("abbbc"))),
    kase("string-regexp-match honours ^ and $", "NotApplicable",
         a("string-regexp-match", str("^b+$"), str("abbbc"))),
    kase("string-regexp-match anchored on the whole value", "Permit",
         a("string-regexp-match", str("^a[bc]+d$"), str("abcbd"))),
    kase("string-regexp-match with ^ alone", "NotApplicable",
         a("string-regexp-match", str("^admin"), str("not-admin"))),
    kase("string-regexp-match with the \\i name class", "Permit",
         a("string-regexp-match", str("^\\i\\c*$"), str("_name-1.x"))),
    kase("string-regexp-match with the \\i class refusing a digit",
         "NotApplicable",
         a("string-regexp-match", str("^\\i"), str("1name"))),
    kase("anyURI-regexp-match searches the URI", "Permit",
         a("anyURI-regexp-match", str("example"),
           v("anyURI", "https://a.example/x"))),
    kase("x500Name-regexp-match sees the name as written", "Permit",
         a("x500Name-regexp-match", str("^cn=Anne"),
           v("x500Name", "cn=Anne,o=Example"))),
    kase("ipAddress-regexp-match sees the port as written", "Permit",
         a("ipAddress-regexp-match", str(":443$"),
           v("ipAddress", "10.0.0.1:443"))),
    kase("anyURI-regexp-match", "Permit",
         a("anyURI-regexp-match", str("https://[a-z.]+/x"),
           v("anyURI", "https://a.example/x"))),
    kase("ipAddress-regexp-match", "Permit",
         a("ipAddress-regexp-match", str("10\\.[0-9.]+"),
           v("ipAddress", "10.0.0.1"))),
    kase("dnsName-regexp-match", "Permit",
         a("dnsName-regexp-match", str("[a-z.]*example\\.com"),
           v("dnsName", "www.example.com"))),
    kase("rfc822Name-regexp-match", "Permit",
         a("rfc822Name-regexp-match", str("[a-z]+@example\\.com"),
           v("rfc822Name", "anne@example.com"))),
    kase("x500Name-regexp-match", "Permit",
         a("x500Name-regexp-match", str("cn=[A-Za-z]+,o=Example"),
           v("x500Name", "cn=Anne,o=Example"))),
    kase("regexp-match refuses class subtraction rather than guess",
         "Indeterminate",
         a("string-regexp-match", str("[a-z-[aeiou]]+"), str("bcd")))
  ];
  log.debug("Leaving stringCases().");
  return out;
}

// A.3.7 and A.3.8: date arithmetic, including the month-end rule.
function temporalCases() {
  log.debug("Entering temporalCases().");
  function dt(t) {
    return v("dateTime", t);
  }
  function d(t) {
    return v("date", t);
  }
  const out = [
    kase("dateTime-add-dayTimeDuration crosses midnight", "Permit",
         a("dateTime-equal",
           a("dateTime-add-dayTimeDuration", dt("2020-02-28T23:00:00Z"),
             v("dayTimeDuration", "PT2H")), dt("2020-02-29T01:00:00Z"))),
    kase("dateTime-subtract-dayTimeDuration", "Permit",
         a("dateTime-equal",
           a("dateTime-subtract-dayTimeDuration", dt("2021-03-01T00:00:00Z"),
             v("dayTimeDuration", "P1D")), dt("2021-02-28T00:00:00Z"))),
    kase("dateTime-add-yearMonthDuration clamps to the month's end",
         "Permit",
         a("dateTime-equal",
           a("dateTime-add-yearMonthDuration", dt("2020-01-31T08:00:00Z"),
             v("yearMonthDuration", "P1M")), dt("2020-02-29T08:00:00Z"))),
    kase("dateTime-subtract-yearMonthDuration", "Permit",
         a("dateTime-equal",
           a("dateTime-subtract-yearMonthDuration", dt("2020-03-31T00:00:00Z"),
             v("yearMonthDuration", "P1Y1M")), dt("2019-02-28T00:00:00Z"))),
    kase("date-add-yearMonthDuration over a leap day", "Permit",
         a("date-equal",
           a("date-add-yearMonthDuration", d("2020-02-29"),
             v("yearMonthDuration", "P1Y")), d("2021-02-28"))),
    kase("date-subtract-yearMonthDuration", "Permit",
         a("date-equal",
           a("date-subtract-yearMonthDuration", d("2021-01-15"),
             v("yearMonthDuration", "P2M")), d("2020-11-15"))),
    kase("a negative duration subtracts", "Permit",
         a("dateTime-equal",
           a("dateTime-add-dayTimeDuration", dt("2020-01-01T00:00:00Z"),
             v("dayTimeDuration", "-PT1M")), dt("2019-12-31T23:59:00Z"))),
    kase("dateTime-equal with fractional seconds", "Permit",
         a("dateTime-equal", dt("2020-01-01T00:00:00.5Z"),
           dt("2020-01-01T01:00:00.500+01:00"))),
    kase("a date with a time zone", "Permit",
         a("date-equal", d("2020-01-01Z"), d("2020-01-01+00:00"))),
    kase("time with a zone compares as an instant", "Permit",
         a("time-less-than", v("time", "10:00:00+02:00"),
           v("time", "09:00:00Z"))),
    kase("string-from-date round-trips a zone", "Permit",
         a("date-equal",
           a("date-from-string", a("string-from-date", d("2020-01-01-05:00"))),
           d("2020-01-01-05:00")))
  ];
  log.debug("Leaving temporalCases().");
  return out;
}

// A.3.5: and, or, not, n-of — including their laziness.
function logicalCases() {
  log.debug("Entering logicalCases().");
  const boom = a("integer-divide", int(1), int(0));
  const boomTrue = a("integer-equal", boom, int(1));
  const out = [
    kase("and of no arguments is true", "Permit", a("and")),
    kase("or of no arguments is false", "NotApplicable", a("or")),
    kase("and", "Permit", a("and", bool(true), bool(true))),
    kase("and with one false", "NotApplicable",
         a("and", bool(true), bool(false))),
    kase("and stops at the first false", "NotApplicable",
         a("and", bool(false), boomTrue)),
    kase("and meets an error before any false", "Indeterminate",
         a("and", boomTrue, bool(true))),
    kase("or stops at the first true", "Permit",
         a("or", bool(true), boomTrue)),
    kase("or of falses", "NotApplicable", a("or", bool(false), bool(false))),
    kase("not", "Permit", a("not", bool(false))),
    kase("n-of 2 of three", "Permit",
         a("n-of", int(2), bool(true), bool(false), bool(true))),
    kase("n-of 3 of three with a false", "NotApplicable",
         a("n-of", int(3), bool(true), bool(false), bool(true))),
    kase("n-of 0 is true without looking", "Permit",
         a("n-of", int(0), boomTrue)),
    kase("n-of asking for more than it has is an error", "Indeterminate",
         a("n-of", int(3), bool(true))),
    kase("n-of stops once it has enough", "Permit",
         a("n-of", int(1), bool(true), boomTrue)),
    kase("a condition must be boolean", "Refused", int(1)),
    kase("an unknown function is refused", "Refused",
         unknownApply("urn:example:no-such-function", int(1)))
  ];
  log.debug("Leaving logicalCases().");
  return out;
}

// A.3.12: the higher-order functions and map.
function higherOrderCases() {
  log.debug("Entering higherOrderCases().");
  const ints = function () {
    return bag.apply(null, ["integer"].concat(
      Array.prototype.slice.call(arguments).map(String)));
  };
  const lt = fn("integer-less-than");
  const out = [
    kase("any-of: 3 is less than some member", "Permit",
         a("any-of", lt, int(3), ints(1, 5))),
    kase("any-of: 9 is less than none", "NotApplicable",
         a("any-of", lt, int(9), ints(1, 5))),
    kase("all-of: 0 is less than every member", "Permit",
         a("all-of", lt, int(0), ints(1, 5))),
    kase("all-of: 3 is not less than every member", "NotApplicable",
         a("all-of", lt, int(3), ints(1, 5))),
    kase("any-of-any", "Permit",
         a("any-of-any", fn("integer-equal"), ints(1, 2), ints(3, 2))),
    kase("all-of-any: every first is below some second", "Permit",
         a("all-of-any", lt, ints(1, 4), ints(2, 5))),
    kase("all-of-any fails when one first is not", "NotApplicable",
         a("all-of-any", lt, ints(1, 6), ints(2, 5))),
    kase("any-of-all: some first is below every second", "Permit",
         a("any-of-all", lt, ints(9, 1), ints(2, 5))),
    kase("all-of-all", "Permit",
         a("all-of-all", lt, ints(1, 2), ints(3, 4))),
    kase("all-of-all fails on one pair", "NotApplicable",
         a("all-of-all", lt, ints(1, 3), ints(3, 4))),
    kase("map applies a function to each member", "Permit",
         a("string-set-equals",
           a("map", fn("string-normalize-to-lower-case"),
             bag("string", "A", "b", "C")),
           bag("string", "a", "b", "c"))),
    kase("map with a fixed argument", "Permit",
         a("integer-set-equals",
           a("map", fn("integer-add"), int(10), ints(1, 2)), ints(11, 12))),
    kase("map of an empty bag is empty", "Permit",
         sizeIs("string", a("map", fn("string-normalize-space"),
                            bag("string")), 0)),
    kase("a higher-order function needs a function", "Refused",
         a("any-of", int(1), int(1), ints(1))),
    kase("map with the bag first and a fixed argument after", "Permit",
         a("string-set-equals",
           a("map", fn("string-concatenate"), bag("string", "a", "b"),
             str("!")),
           bag("string", "a!", "b!"))),
    kase("map with two bags is refused at load", "Refused",
         sizeIs("integer", a("map", fn("integer-add"), ints(1), ints(2)),
                1)),
    kase("map whose function returns a bag is refused at load", "Refused",
         sizeIs("integer", a("map", fn("integer-bag"), ints(1, 2)), 2))
  ];
  log.debug("Leaving higherOrderCases().");
  return out;
}

// A.3.14: rfc822Name-match and x500Name-match.
function nameMatchCases() {
  log.debug("Entering nameMatchCases().");
  const mbox = function (t) {
    return v("rfc822Name", t);
  };
  const out = [
    kase("rfc822Name-match of a whole mailbox", "Permit",
         a("rfc822Name-match", str("Anne@EXAMPLE.com"),
           mbox("Anne@example.com"))),
    kase("rfc822Name-match compares the local part with case", "NotApplicable",
         a("rfc822Name-match", str("anne@example.com"),
           mbox("Anne@example.com"))),
    kase("rfc822Name-match of a domain", "Permit",
         a("rfc822Name-match", str("example.com"), mbox("anne@EXAMPLE.com"))),
    kase("rfc822Name-match of a domain refuses a subdomain", "NotApplicable",
         a("rfc822Name-match", str("example.com"),
           mbox("anne@mail.example.com"))),
    kase("rfc822Name-match of a leading-dot domain takes subdomains",
         "Permit",
         a("rfc822Name-match", str(".example.com"),
           mbox("anne@mail.example.com"))),
    kase("x500Name-match of a terminal sequence", "Permit",
         a("x500Name-match", v("x500Name", "o=Example"),
           v("x500Name", "cn=Anne,o=Example"))),
    kase("x500Name-match refuses a non-terminal sequence", "NotApplicable",
         a("x500Name-match", v("x500Name", "cn=Anne"),
           v("x500Name", "cn=Anne,o=Example")))
  ];
  log.debug("Leaving nameMatchCases().");
  return out;
}

// B.4: the ipAddress and dnsName grammars, whose parts are compared parsed.
function addressCases() {
  log.debug("Entering addressCases().");
  const ip = function (t) {
    return v("ipAddress", t);
  };
  const dns = function (t) {
    return v("dnsName", t);
  };
  const out = [
    kase("ipAddress with a mask and a port range", "Permit",
         a("ipAddress-equal", ip("10.0.0.1/255.0.0.0:80-90"),
           ip("10.0.0.1/255.0.0.0:80-90"))),
    kase("ipAddress with a different port is a different value",
         "NotApplicable",
         a("ipAddress-equal", ip("10.0.0.1:80"), ip("10.0.0.1:81"))),
    kase("ipAddress with an open-ended port range", "Permit",
         a("ipAddress-equal", ip("10.0.0.1:1024-"), ip("10.0.0.1:1024-"))),
    kase("ipAddress with an upper-bounded port range", "Permit",
         a("ipAddress-equal", ip("10.0.0.1:-1023"), ip("10.0.0.1:-1023"))),
    kase("an IPv6 address is bracketed and its case does not matter",
         "Permit",
         a("ipAddress-equal", ip("[2001:DB8::1]:443"),
           ip("[2001:db8::1]:443"))),
    kase("an IPv6 address with a bracketed mask", "Permit",
         a("ipAddress-equal", ip("[2001:db8::]/[ffff:ffff::]:80"),
           ip("[2001:db8::]/[ffff:ffff::]:80"))),
    kase("an IPv6 mask is part of the value", "NotApplicable",
         a("ipAddress-equal", ip("[2001:db8::]/[ffff:ffff::]"),
           ip("[2001:db8::]/[ffff::]"))),
    kase("an IPv6 address with an embedded IPv4 tail", "Permit",
         a("ipAddress-equal", ip("[::ffff:192.0.2.1]"),
           ip("[::ffff:192.0.2.1]"))),
    kase("an unbracketed IPv6 address is refused", "Indeterminate",
         a("ipAddress-equal", ip("2001:db8::1"), ip("10.0.0.1"))),
    kase("an IPv6 address with two :: is refused", "Indeterminate",
         a("ipAddress-equal", ip("[2001::db8::1]"), ip("10.0.0.1"))),
    kase("a port that is not a number is refused", "Indeterminate",
         a("ipAddress-equal", ip("10.0.0.1:http"), ip("10.0.0.1"))),
    kase("a bare - is not a port range", "Indeterminate",
         a("ipAddress-equal", ip("10.0.0.1:-"), ip("10.0.0.1"))),
    kase("dnsName compares the host without case", "Permit",
         a("dnsName-equal", dns("WWW.Example.COM:443"),
           dns("www.example.com:443"))),
    kase("dnsName with a trailing dot", "Permit",
         a("dnsName-equal", dns("example.com."), dns("example.com."))),
    kase("dnsName refuses a wildcard that is not left-most", "Indeterminate",
         a("dnsName-equal", dns("www.*.example.com"), dns("example.com"))),
    kase("dnsName refuses a top label beginning with a digit",
         "Indeterminate",
         a("dnsName-equal", dns("example.123"), dns("example.com"))),
    kase("dnsName refuses a label ending in a hyphen", "Indeterminate",
         a("dnsName-equal", dns("bad-.example.com"), dns("example.com"))),
    kase("dnsName refuses a wildcard alone", "Indeterminate",
         a("dnsName-equal", dns("*"), dns("example.com")))
  ];
  log.debug("Leaving addressCases().");
  return out;
}

// More of the XML Schema lexical rules, each a refusal or an equality the
// datatype parser has to get right.
function lexicalCases() {
  log.debug("Entering lexicalCases().");
  const out = [
    kase("24:00:00 is a time (the end of a day)", "Permit",
         a("time-equal", v("time", "24:00:00"), v("time", "24:00:00"))),
    kase("2000-02-29 is a date (a 400-year leap)", "Permit",
         a("date-equal", v("date", "2000-02-29"), v("date", "2000-02-29"))),
    kase("1900-02-29 is not a date (a century, not a leap)", "Indeterminate",
         a("date-equal", v("date", "1900-02-29"), v("date", "1900-03-01"))),
    kase("April has no 31st", "Indeterminate",
         a("date-equal", v("date", "2021-04-31"), v("date", "2021-05-01"))),
    kase("a dateTime at 24:00:00 is the next day's midnight", "Permit",
         a("dateTime-equal", v("dateTime", "2020-12-31T24:00:00Z"),
           v("dateTime", "2021-01-01T00:00:00Z"))),
    kase("a negative year", "Permit",
         a("date-less-than", v("date", "-0044-03-15"),
           v("date", "0001-01-01"))),
    kase("a time zone beyond 14:00 is refused", "Indeterminate",
         a("date-equal", v("date", "2020-01-01+15:00"),
           v("date", "2020-01-01"))),
    kase("a dayTimeDuration with fractional seconds", "Permit",
         a("dayTimeDuration-equal", v("dayTimeDuration", "PT1.5S"),
           v("dayTimeDuration", "PT1.500S"))),
    kase("a duration with no fields is refused", "Indeterminate",
         a("dayTimeDuration-equal", v("dayTimeDuration", "P"),
           v("dayTimeDuration", "PT0S"))),
    kase("a negative yearMonthDuration", "NotApplicable",
         a("yearMonthDuration-equal", v("yearMonthDuration", "-P1M"),
           v("yearMonthDuration", "P1M"))),
    // A.3.6/A.3.7 define no ordering functions over the durations.
    kase("there is no yearMonthDuration-less-than", "Refused",
         unknownApply("urn:oasis:names:tc:xacml:3.0:function:" +
                      "yearMonthDuration-less-than",
                      v("yearMonthDuration", "P1M"),
                      v("yearMonthDuration", "P2M"))),
    kase("there is no dayTimeDuration-greater-than", "Refused",
         unknownApply("urn:oasis:names:tc:xacml:3.0:function:" +
                      "dayTimeDuration-greater-than",
                      v("dayTimeDuration", "PT2H"),
                      v("dayTimeDuration", "PT1H"))),
    kase("double INF is greater than any finite double", "Permit",
         a("double-greater-than", dbl("INF"), dbl("1E308"))),
    // XML Schema's value space has ONE NaN, so it equals itself; the OASIS
    // conformance cases IIC350 and IIC358 expect exactly this, and an
    // IEEE 754 reading of A.3.1 gets it wrong.
    kase("double NaN equals itself (one NaN in the value space)", "Permit",
         a("double-equal", dbl("NaN"), dbl("NaN"))),
    kase("an integer of more digits than a double holds", "Permit",
         a("integer-less-than", int("9007199254740993"),
           int("9007199254740994"))),
    kase("hexBinary of an odd length is refused", "Indeterminate",
         a("hexBinary-equal", v("hexBinary", "abc"), v("hexBinary", "ab"))),
    kase("an empty hexBinary", "Permit",
         a("hexBinary-equal", v("hexBinary", ""), v("hexBinary", ""))),
    kase("base64Binary ignores the whitespace between groups", "Permit",
         a("base64Binary-equal", v("base64Binary", "aGVs bG8="),
           v("base64Binary", "aGVsbG8="))),
    kase("x500Name compares attribute types without case", "Permit",
         a("x500Name-equal", v("x500Name", "CN=Anne, O=Example"),
           v("x500Name", "cn=Anne,o=Example"))),
    kase("an rfc822Name local part keeps its case", "NotApplicable",
         a("rfc822Name-equal", v("rfc822Name", "anne@example.com"),
           v("rfc822Name", "Anne@example.com"))),
    kase("an unknown datatype is refused at load", "Refused",
         a("string-equal", unknownValue("urn:example:no-such-type", "x"),
           str("x")))
  ];
  log.debug("Leaving lexicalCases().");
  return out;
}

// Every case, in a stable order.
function allCases() {
  log.debug("Entering allCases().");
  let out = [];
  SAMPLES.forEach(function (s) {
    out = out.concat(genericCases(s));
  });
  out = out.concat(arithmeticCases(), stringCases(), temporalCases(),
                   logicalCases(), higherOrderCases(), nameMatchCases(),
                   addressCases(), lexicalCases());
  log.debug("Leaving allCases(). " + out.length + " case(s).");
  return out;
}

// The policy document for one case, with `uriOf` turning a short function
// name into its identifier.
function policyXml(c, uriOf, id) {
  log.debug("Entering policyXml().");
  const xml = "<Policy xmlns=\"" + NS + "\" PolicyId=\"" + id +
    "\" Version=\"1.0\" RuleCombiningAlgId=\"" + FIRST_APPLICABLE + "\">" +
    "<Target/><Rule RuleId=\"" + id + "-rule\" Effect=\"Permit\"><Target/>" +
    "<Condition>" + c.expression(uriOf) + "</Condition></Rule></Policy>";
  log.debug("Leaving policyXml().");
  return xml;
}

// A resolver over a list of function identifiers (the engine's names()):
// the one identifier whose last segment is the short name. Throws on none
// or several, so a typo in this table cannot quietly test something else.
function resolverOver(identifiers) {
  log.debug("Entering resolverOver().");
  const byShort = {};
  identifiers.forEach(function (uri) {
    const short = uri.replace(/^.*:function:/, "");
    (byShort[short] = byShort[short] || []).push(uri);
  });
  const resolve = function (short) {
    const found = Object.prototype.hasOwnProperty.call(byShort, short) ?
      byShort[short] : [];
    if (found.length !== 1) {
      throw new Error("xacml_function_cases: \"" + short + "\" names " +
                      found.length + " function(s).");
    }
    return found[0];
  };
  log.debug("Leaving resolverOver().");
  return resolve;
}

// Every case as {name, expect, xml}, ready to import.
function buildAll(identifiers) {
  log.debug("Entering buildAll().");
  const uriOf = resolverOver(identifiers);
  const used = {};
  const counting = function (short) {
    used[short] = true;
    return uriOf(short);
  };
  const built = allCases().map(function (c, i) {
    return { name: c.name, expect: c.expect,
             xml: policyXml(c, counting, "case-" + i) };
  });
  log.debug("Leaving buildAll(). " + built.length + " case(s).");
  return { cases: built, used: Object.keys(used) };
}

module.exports = {
  SAMPLES: SAMPLES,
  allCases: allCases,
  policyXml: policyXml,
  resolverOver: resolverOver,
  buildAll: buildAll
};
