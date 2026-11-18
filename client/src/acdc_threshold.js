// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_threshold.js
//
// ---------------------------------------------------------------------------
// KERI signing thresholds (#480): the current-key threshold kt and the next
// threshold nt of a key event, numeric or WEIGHTED (KERI specification,
// "Signing threshold"; held to cesr-ts 2.2.1's Tholder, which mirrors
// keripy).
//
//   numeric   "2"                     two distinct verified indices (hex)
//   weighted  ["1/2","1/2","1/2"]     one clause: the weights of the
//                                     verified indices sum to at least 1
//   clauses   [["1/2","1/2"],["1"]]   a list of clauses, ANDed: every
//                                     clause must reach 1
//   nested    [{"1/2":["1","1"]},"1/2"]  a member that is itself a group:
//                                     its outer weight counts when its own
//                                     members sum to at least 1
//
// Weights are 0, 1 or a fraction n/d in [0, 1]; each clause, and each nested
// group, must be able to reach 1 (otherwise the threshold is unsatisfiable
// and refused). The indices are positions in the key list, read left to
// right across the clauses and the nested members. Arithmetic is exact
// (BigInt rationals), never floating point.
//
// NO DOM.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc_threshold",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var ZERO = BigInt(0);
var ONE = BigInt(1);

function gcd(a, b) {
  log.debug("Entering gcd().");
  var x = a < ZERO ? -a : a;
  var y = b < ZERO ? -b : b;
  while (y !== ZERO) {
    var t = x % y;
    x = y;
    y = t;
  }
  log.debug("Leaving gcd().");
  return x === ZERO ? ONE : x;
}

function rational(n, d) {
  log.debug("Entering rational().");
  if (d === ZERO) {
    log.debug("Leaving rational(). Zero denominator.");
    throw new Error("a threshold weight has denominator 0.");
  }
  var g = gcd(n, d);
  log.debug("Leaving rational().");
  return { n: n / g, d: d / g };
}

function add(a, b) {
  log.debug("Entering add().");
  log.debug("Leaving add().");
  return rational(a.n * b.d + b.n * a.d, a.d * b.d);
}

function atLeastOne(r) {
  log.debug("Entering atLeastOne().");
  log.debug("Leaving atLeastOne().");
  return r.n >= r.d;
}

// "1", "0" or "n/d" in [0, 1].
function parseWeight(text) {
  log.debug("Entering parseWeight().");
  if (typeof text !== "string") {
    log.debug("Leaving parseWeight(). Not a string.");
    throw new Error("a threshold weight is a string, not " +
                    JSON.stringify(text) + ".");
  }
  var t = text.trim();
  var r;
  if (/^\d+$/.test(t)) {
    r = { n: BigInt(t), d: ONE };
  } else {
    var m = /^(\d+)\/(\d+)$/.exec(t);
    if (!m) {
      log.debug("Leaving parseWeight(). Malformed.");
      throw new Error("threshold weight " + JSON.stringify(text) +
                      " is not 0, 1 or a fraction n/d.");
    }
    r = rational(BigInt(m[1]), BigInt(m[2]));
  }
  if (r.n > r.d) {
    log.debug("Leaving parseWeight(). Above 1.");
    throw new Error("threshold weight " + text + " is above 1.");
  }
  log.debug("Leaving parseWeight().");
  return r;
}

function isMap(v) {
  log.debug("Entering isMap().");
  log.debug("Leaving isMap().");
  return !!v && typeof v === "object" && !Array.isArray(v);
}

// sith (a key event's kt or nt) -> { weighted, num, clauses, size, text }.
// A numeric threshold is a hex string; a weighted one a list.
function parse(sith) {
  log.debug("Entering parse().");
  if (typeof sith === "string" && /^[0-9a-f]+$/.test(sith)) {
    log.debug("Leaving parse(). Numeric.");
    return { weighted: false, num: parseInt(sith, 16), clauses: null,
             size: parseInt(sith, 16), text: sith };
  }
  if (typeof sith === "string" && sith.trim().charAt(0) === "[") {
    log.debug("Leaving parse(). JSON text.");
    return parse(JSON.parse(sith));
  }
  if (!Array.isArray(sith) || sith.length === 0) {
    log.debug("Leaving parse(). Not a threshold.");
    throw new Error("threshold " + JSON.stringify(sith) + " is neither a " +
                    "hex number nor a non-empty list of weights.");
  }
  var wrap = sith.some(function (e) {
    return !Array.isArray(e);
  });
  var source = wrap ? [sith] : sith;
  var size = 0;
  var clauses = source.map(function (clause) {
    if (!Array.isArray(clause) || clause.length === 0) {
      throw new Error("an empty weighted threshold clause.");
    }
    var top = { n: ZERO, d: ONE };
    var out = clause.map(function (entry) {
      if (!isMap(entry)) {
        var w = parseWeight(entry);
        top = add(top, w);
        size += 1;
        return w;
      }
      var keys = Object.keys(entry);
      if (keys.length !== 1 || !Array.isArray(entry[keys[0]]) ||
          entry[keys[0]].length === 0) {
        throw new Error("a nested threshold group is one weight mapped to " +
                        "a non-empty list of member weights.");
      }
      var outer = parseWeight(keys[0]);
      var sum = { n: ZERO, d: ONE };
      var members = entry[keys[0]].map(function (mw) {
        var r = parseWeight(mw);
        sum = add(sum, r);
        size += 1;
        return r;
      });
      if (!atLeastOne(sum)) {
        throw new Error("the members of nested group " + keys[0] +
                        " can never reach 1.");
      }
      top = add(top, outer);
      return { weight: outer, members: members };
    });
    if (!atLeastOne(top)) {
      throw new Error("a weighted threshold clause can never reach 1: " +
                      JSON.stringify(clause) + ".");
    }
    return out;
  });
  log.debug("Leaving parse(). Weighted, " + size + " weights.");
  return { weighted: true, num: null, clauses: clauses, size: size,
           text: JSON.stringify(sith) };
}

// Do the verified key indices satisfy the threshold?
function satisfy(th, indices) {
  log.debug("Entering satisfy().");
  var unique = {};
  (indices || []).forEach(function (i) {
    unique[i] = true;
  });
  var have = Object.keys(unique).map(Number);
  if (!th.weighted) {
    log.debug("Leaving satisfy(). Numeric.");
    return th.num > 0 && have.length >= th.num;
  }
  if (have.length === 0) {
    log.debug("Leaving satisfy(). No indices.");
    return false;
  }
  var offset = 0;
  for (var c = 0; c < th.clauses.length; c++) {
    var sum = { n: ZERO, d: ONE };
    for (var e = 0; e < th.clauses[c].length; e++) {
      var entry = th.clauses[c][e];
      if (entry.members === undefined) {
        if (unique[offset]) {
          sum = add(sum, entry);
        }
        offset += 1;
        continue;
      }
      var inner = { n: ZERO, d: ONE };
      for (var m = 0; m < entry.members.length; m++) {
        if (unique[offset]) {
          inner = add(inner, entry.members[m]);
        }
        offset += 1;
      }
      if (atLeastOne(inner)) {
        sum = add(sum, entry.weight);
      }
    }
    if (!atLeastOne(sum)) {
      log.debug("Leaving satisfy(). Clause " + c + " short.");
      return false;
    }
  }
  log.debug("Leaving satisfy(). Satisfied.");
  return true;
}

// A threshold against the key list it governs: a numeric one between 1 and
// the number of keys (0 only with no keys), a weighted one with exactly one
// weight per key. Answers "" or the reason.
function checkAgainst(th, count, what) {
  log.debug("Entering checkAgainst().");
  var label = what || "kt";
  if (th.weighted) {
    log.debug("Leaving checkAgainst(). Weighted.");
    return th.size === count ? "" : label + " has " + th.size +
      " weights for " + count + " keys.";
  }
  if (count === 0) {
    log.debug("Leaving checkAgainst(). No keys.");
    return th.num === 0 ? "" : label + " " + th.text + " with no keys.";
  }
  log.debug("Leaving checkAgainst().");
  return th.num >= 1 && th.num <= count ? "" : label + " " + th.text +
    " is not between 1 and " + count + ".";
}

module.exports = {
  parse: parse,
  satisfy: satisfy,
  checkAgainst: checkAgainst,
  parseWeight: parseWeight
};
