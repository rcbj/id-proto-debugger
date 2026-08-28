// File: spiffe_bundle.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE TRUST BUNDLE DOCUMENT: reading one, and saying what is wrong with
// it.
//
// A SPIFFE trust bundle is a JWK Set with two extra members —
// `spiffe_sequence` and `spiffe_refresh_hint` — and it is the ROOT OF TRUST for
// a whole trust domain. Everything else in this workflow rests on it: an
// X509-SVID is verified against the `x509-svid` keys in it, a JWT-SVID against
// the `jwt-svid` ones, and a federation relationship is nothing but an
// agreement to fetch somebody else's.
//
// This module is `common/` for the reason `spiffe_id.js` is: three callers, one
// document format. `api/spiffe_client.js` checks a bundle it fetched before
// reporting it as usable, `client/src/spiffe_bundle_pane.js` renders one with
// no network at all, and `tests/spiffe_bundle.js` drives both against
// hand-written documents that are wrong in one way each. NO DOM.
//
// ---------------------------------------------------------------------------
// THE ONE RULE THAT MATTERS, AND WHY IT IS AN ERROR RATHER THAN A WARNING
//
// **A JWK in a SPIFFE bundle MUST carry `use`, and a consumer MUST IGNORE one
// whose `use` is missing or unrecognised.** That sentence is why a bundle full
// of keys with no `use` is not a slightly imperfect bundle: it is a bundle that
// VERIFIES NOTHING, and it fails with no error anywhere pointing back at it.
// The X509-SVID that will not validate names a signature; the JWT-SVID that
// will not validate names a key id; neither names the bundle that silently had
// no usable keys in it. So this module reports it as an error and counts, for
// each `use`, how many keys survived — because "0 usable x509-svid keys" is the
// only form of that report anybody can act on.
//
// The two registered values are `x509-svid` and `jwt-svid`. Anything else is
// reported as ignored rather than as invalid: the specification says a consumer
// ignores what it does not recognise, and a future `use` this build has never
// heard of is not a defect in somebody else's bundle.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT CHECKED HERE
//
// The cryptography. This module reads a document; it does not verify a
// signature, walk a chain or open an X.509 certificate. Two reasons: it has to
// run unchanged in a browser bundle and in node, and the two have completely
// different certificate machinery (`client/src/x509.js` against
// `crypto.X509Certificate`); and mixing "is this document well formed" with "do
// these keys verify that credential" gives a caller one answer where it needs
// two. `x5c` is checked for SHAPE — present, an array, one entry, base64 — and
// handed on.
// ---------------------------------------------------------------------------

// The same bunyan-or-console logger `spiffe_id.js` carries, and for the same
// reason: this module is reached from a client bundle, from `tests/` and from
// `api/`, and only the first two can resolve bunyan. See the long note there.
var log = (function () {
  try {
    var bunyan = require("bunyan");
    return bunyan.createLogger({
      name: "spiffe_bundle",
      level: (function () {
        try {
          return require(process.env.CONFIG_FILE).logLevel || "info";
        } catch (e) {
          // No CONFIG_FILE resolvable here — a node caller, not a bundle.
          return "info";
        }
      })()
    });
  } catch (e) {
    var DEBUG = false;
    var TAG = "[spiffe_bundle]";
    return {
      debug: function () {
        if (!DEBUG) {
          return;
        }
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      info: function () {
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      warn: function () {
        console.warn.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      error: function () {
        console.error.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      }
    };
  }
})();

// The two registered `use` values. Named here once so a typo is a constant
// rather than a string in four comparisons.
var USE_X509 = "x509-svid";
var USE_JWT = "jwt-svid";
var REGISTERED_USES = [USE_X509, USE_JWT];

// A bundle is a small document. This is not a security bound — the api's
// `maxContentLength` is — it is a bound on what is worth parsing twice in a
// browser, and it is generous: a trust domain retaining four authorities of
// each kind is a handful of kilobytes.
var MAX_BUNDLE_BYTES = 1048576;

var BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

function isObject(value) {
  log.debug("Entering isObject().");
  var ok = !!value && typeof value === "object" && !Array.isArray(value);
  log.debug("Leaving isObject(). " + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// PARSING.
//
// Takes text or an already-parsed object, and always returns a report rather
// than throwing — every caller is answering somebody. The report separates
// three things that a single `ok` would collapse:
//
//   errors   the document cannot be used as a trust bundle
//   warnings it can, but something in it will not do what its author expected
//   ignored  keys a conforming consumer discards, with the reason
//
// A bundle with keys and no usable ones is an ERROR, not a warning: see the
// header.
// ---------------------------------------------------------------------------
function describe(input) {
  log.debug("Entering describe().");
  var report = {
    ok: false,
    errors: [],
    warnings: [],
    keys: [],
    ignored: [],
    counts: {},
    sequence: null,
    refreshHint: null,
    raw: null
  };
  report.counts[USE_X509] = 0;
  report.counts[USE_JWT] = 0;

  var document = input;
  if (typeof input === "string") {
    if (input.length > MAX_BUNDLE_BYTES) {
      report.errors.push("The document is " + input.length + " bytes, past " +
                         "the " + MAX_BUNDLE_BYTES + "-byte ceiling this " +
                         "reader will parse.");
      log.debug("Leaving describe(). Too large.");
      return report;
    }
    try {
      document = JSON.parse(input);
    } catch (e) {
      report.errors.push("The document is not JSON: " + e.message + ". A " +
                         "SPIFFE bundle endpoint answers with a JWK Set; an " +
                         "HTML error page from a proxy is the usual thing to " +
                         "find here instead.");
      log.debug("Leaving describe(). Not JSON.");
      return report;
    }
  }
  if (!isObject(document)) {
    report.errors.push("A trust bundle is a JSON object (a JWK Set). This " +
                       "is " + (Array.isArray(document) ? "an array" :
                                typeof document) + ".");
    log.debug("Leaving describe(). Not an object.");
    return report;
  }
  report.raw = document;

  // `spiffe_sequence`. Not required by the specification, and its absence is a
  // warning rather than an error — but a consumer that caches bundles has no
  // way to tell an older document from a newer one without it, which is
  // exactly the case federation exists to handle.
  if (document.spiffe_sequence === undefined ||
      document.spiffe_sequence === null) {
    report.warnings.push("There is no spiffe_sequence. A consumer holding a " +
                         "cached copy of this bundle cannot tell whether " +
                         "this one is newer, so a rotation may be applied " +
                         "out of order or not at all.");
  } else if (typeof document.spiffe_sequence !== "number" ||
             !isFinite(document.spiffe_sequence) ||
             Math.floor(document.spiffe_sequence) !==
               document.spiffe_sequence ||
             document.spiffe_sequence < 0) {
    report.errors.push("spiffe_sequence must be a non-negative integer; this " +
                       "one is " + JSON.stringify(document.spiffe_sequence) +
                       ".");
  } else {
    report.sequence = document.spiffe_sequence;
  }

  // `spiffe_refresh_hint`, in SECONDS. Absent is fine and means the consumer
  // decides; zero is not, and is worth naming because it reads as "do not
  // cache" and means "refresh as fast as you can", which is a denial of
  // service aimed at whoever published it.
  if (document.spiffe_refresh_hint === undefined ||
      document.spiffe_refresh_hint === null) {
    report.warnings.push("There is no spiffe_refresh_hint, so how often to " +
                         "re-fetch this bundle is the consumer's decision.");
  } else if (typeof document.spiffe_refresh_hint !== "number" ||
             !isFinite(document.spiffe_refresh_hint) ||
             document.spiffe_refresh_hint < 0) {
    report.errors.push("spiffe_refresh_hint must be a non-negative number of " +
                       "seconds; this one is " +
                       JSON.stringify(document.spiffe_refresh_hint) + ".");
  } else {
    report.refreshHint = document.spiffe_refresh_hint;
    if (document.spiffe_refresh_hint === 0) {
      report.warnings.push("spiffe_refresh_hint is 0, which asks every " +
                           "consumer to re-fetch this bundle as often as it " +
                           "can rather than to stop caching it.");
    }
  }

  if (!Object.prototype.hasOwnProperty.call(document, "keys")) {
    report.errors.push("A JWK Set has a keys member and this document has " +
                       "none. If this came from a bundle endpoint, check " +
                       "that the URL is the endpoint and not the service's " +
                       "index page.");
    log.debug("Leaving describe(). No keys member.");
    return report;
  }
  if (!Array.isArray(document.keys)) {
    report.errors.push("The keys member of a JWK Set is an array; this one " +
                       "is " + typeof document.keys + ".");
    log.debug("Leaving describe(). keys is not an array.");
    return report;
  }

  document.keys.forEach(function (jwk, index) {
    var described = describeKey(jwk, index);
    if (described.ignored) {
      report.ignored.push(described);
      return;
    }
    report.keys.push(described);
    report.counts[described.use] = (report.counts[described.use] || 0) + 1;
    described.problems.forEach(function (problem) {
      report.warnings.push("keys[" + index + "]: " + problem);
    });
  });

  // The rule from the header, stated as the only form of it anybody can act
  // on. A bundle with keys, all of which a conforming consumer discards, is
  // reported as the error it is.
  if (document.keys.length && !report.keys.length) {
    report.errors.push("Every one of the " + document.keys.length + " keys " +
                       "in this bundle is one a conforming consumer MUST " +
                       "IGNORE, so this bundle verifies nothing at all — and " +
                       "it does so silently, because the failure surfaces as " +
                       "an SVID that will not validate rather than as " +
                       "anything naming the bundle. See the ignored list.");
  }
  if (!document.keys.length) {
    report.warnings.push("The bundle holds no keys, so nothing in this trust " +
                         "domain can be verified with it. That is a valid " +
                         "document and an unusable trust anchor.");
  }
  if (report.keys.length && !report.counts[USE_X509]) {
    report.warnings.push("There is no " + USE_X509 + " key, so no X509-SVID " +
                         "from this trust domain can be verified with this " +
                         "bundle.");
  }
  if (report.keys.length && !report.counts[USE_JWT]) {
    report.warnings.push("There is no " + USE_JWT + " key, so no JWT-SVID " +
                         "from this trust domain can be verified with this " +
                         "bundle.");
  }

  report.ok = report.errors.length === 0;
  log.debug("Leaving describe(). ok=" + report.ok + ", " + report.keys.length +
            " usable key(s), " + report.ignored.length + " ignored.");
  return report;
}

// One JWK. Returns either `{ ignored: true, reason, index }` — the conforming
// consumer's own verdict — or a description with a (possibly empty) list of
// problems that do not make the key unusable.
function describeKey(jwk, index) {
  log.debug("Entering describeKey(). index=" + index);
  if (!isObject(jwk)) {
    log.debug("Leaving describeKey(). Not an object.");
    return { ignored: true, index: index,
             reason: "not a JSON object, so it is not a JWK" };
  }
  var use = jwk.use;
  if (use === undefined || use === null || use === "") {
    log.debug("Leaving describeKey(). No use.");
    return { ignored: true, index: index, kid: jwk.kid || "",
             reason: "it carries no use member. A consumer MUST IGNORE a JWK " +
                     "in a SPIFFE bundle whose use is missing — this is the " +
                     "single most consequential thing that can be wrong with " +
                     "a bundle, because nothing downstream reports it." };
  }
  if (REGISTERED_USES.indexOf(use) === -1) {
    log.debug("Leaving describeKey(). Unrecognised use.");
    return { ignored: true, index: index, kid: jwk.kid || "",
             use: String(use),
             reason: "its use is " + JSON.stringify(use) + ", which is " +
                     "neither " + USE_X509 + " nor " + USE_JWT + ". A " +
                     "consumer ignores what it does not recognise, so this " +
                     "key is discarded rather than refused." };
  }

  var described = {
    ignored: false,
    index: index,
    use: use,
    kid: jwk.kid === undefined ? "" : String(jwk.kid),
    kty: jwk.kty === undefined ? "" : String(jwk.kty),
    crv: jwk.crv === undefined ? "" : String(jwk.crv),
    alg: jwk.alg === undefined ? "" : String(jwk.alg),
    x5c: [],
    problems: [],
    jwk: jwk
  };

  if (!described.kty) {
    described.problems.push("there is no kty, so nothing can tell what kind " +
                            "of key this is");
  }

  // A private member in a published trust bundle. Worth its own line: it is
  // the one defect here that is a disclosure rather than a malfunction, and a
  // bundle endpoint is by definition something everybody fetches.
  ["d", "p", "q", "dp", "dq", "qi", "k"].forEach(function (member) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      described.problems.push("it carries the private member \"" + member +
                              "\". A trust bundle publishes PUBLIC keys and " +
                              "is fetched by everybody who federates with " +
                              "this trust domain — treat this key as " +
                              "compromised rather than as a formatting " +
                              "mistake");
    }
  });

  if (use === USE_X509) {
    // An x509-svid key IS a certificate: the JWK members are the public key
    // and `x5c` is the authority itself. Without it there is nothing to build
    // a chain from, so this one is a problem rather than a nicety.
    if (!Object.prototype.hasOwnProperty.call(jwk, "x5c")) {
      described.problems.push("an " + USE_X509 + " key carries the " +
                              "authority certificate in x5c, and this one " +
                              "has none — so there is nothing here to build " +
                              "a certificate chain from");
    } else if (!Array.isArray(jwk.x5c) || !jwk.x5c.length) {
      described.problems.push("x5c must be a non-empty array of base64 DER " +
                              "certificates");
    } else {
      jwk.x5c.forEach(function (entry, position) {
        var text = String(entry == null ? "" : entry);
        if (!text || !BASE64.test(text)) {
          described.problems.push("x5c[" + position + "] is not base64. Note " +
                                  "that x5c is base64 and NOT base64url, " +
                                  "which is the opposite of every other " +
                                  "member of a JWK and is the mistake to " +
                                  "look for first");
          return;
        }
        described.x5c.push(text);
      });
      if (jwk.x5c.length > 1) {
        described.problems.push("x5c holds " + jwk.x5c.length + " " +
                                "certificates. A SPIFFE trust bundle " +
                                "publishes trust ANCHORS, so each " + USE_X509 +
                                " key is one self-signed authority rather " +
                                "than a chain");
      }
    }
  } else {
    // A jwt-svid key is identified by its `kid`, which is what a JWT-SVID's
    // header names. Without one a verifier has to try every key, which works
    // and is not what the header is for.
    if (!described.kid) {
      described.problems.push("a " + USE_JWT + " key has no kid, so a " +
                              "verifier cannot select it by the kid in a " +
                              "JWT-SVID header and has to try every key in " +
                              "the bundle");
    }
    if (Object.prototype.hasOwnProperty.call(jwk, "x5c")) {
      described.problems.push("a " + USE_JWT + " key carries x5c. That is " +
                              "not wrong, and nothing will read it: a " +
                              "JWT-SVID is verified against the JWK members, " +
                              "never against a certificate");
    }
  }

  log.debug("Leaving describeKey(). use=" + use + ", " +
            described.problems.length + " problem(s).");
  return described;
}

// The keys a conforming consumer would actually use for one purpose. Separate
// from `describe()` because this is the question an implementation asks and the
// other is the question a person asks.
function keysFor(report, use) {
  log.debug("Entering keysFor(). use=" + use);
  var rows = (report && report.keys) || [];
  var matched = rows.filter(function (key) {
    return key.use === use;
  });
  log.debug("Leaving keysFor(). " + matched.length + " key(s).");
  return matched;
}

module.exports = {
  USE_X509: USE_X509,
  USE_JWT: USE_JWT,
  REGISTERED_USES: REGISTERED_USES,
  MAX_BUNDLE_BYTES: MAX_BUNDLE_BYTES,
  describe: describe,
  describeKey: describeKey,
  keysFor: keysFor
};
