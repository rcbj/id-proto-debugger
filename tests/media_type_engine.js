// File: media_type_engine.js
//
// ---------------------------------------------------------------------------
// The media type comparison behind the RFC 9068 "typ" checks on two pages
// (token_detail.js's Validate Claims and jwt_tools.js's RFC 9068
// Compliance), driven in NODE with no browser — because the module it is
// built on (client/src/media_type.js) has no DOM.
//
// The spellings asserted here are NOT this code's: every one is the RFC's
// own. RFC 9068 §2.1 RECOMMENDS "at+jwt"; §4 tells a resource server to
// accept "at+jwt" or "application/at+jwt" and reject everything else;
// Figure 2 prints "at+JWT"; §7.1.1 registers the subtype "at+jwt"; and RFC
// 7515 §4.1.9 — which §2.1 cites for the prefix rule — makes media type
// names case-insensitive, so Figure 2's spelling is the same media type and
// not a different one. A page check that compares strings for equality
// accepts some subset of those spellings, and this bug is exactly the kind
// a page round trip cannot see: the page checks the comparison against
// itself. So the matrix lives here.
// ---------------------------------------------------------------------------

// NOTE ON OPTIONS: this job parses no arguments at all — it drives a module
// in process and has no base url to visit — so node ignores the --url pair
// run-report.js passes every job. Do not add commander here without also
// declaring --url; see tests/CLAUDE.md.
const assert = require("assert");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'media_type_engine',
                                level: appconfig.LOG_LEVEL || appconfig.logLevel || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The module under test lives next to this script in the tests image and in
// client/src in a checkout — see the note in tests/module_paths.js, and the
// tests/Dockerfile COPY that puts it here.
const paths = require("./module_paths.js");
const mediaType = paths.requireSharedModule(
  [path.join(__dirname, "..", "client", "src", "media_type.js"),
   path.join(__dirname, "media_type.js")],
  "client/src/media_type.js");

// ---- The spellings RFC 9068 itself uses, every one accepted ----------------
var accepted = [
  ["at+jwt",            "RFC 9068 §2.1's RECOMMENDED spelling"],
  ["at+JWT",            "RFC 9068 Figure 2's spelling"],
  ["AT+JWT",            "RFC 7515 §4.1.9 case-insensitivity, uppercased"],
  ["application/at+jwt", "RFC 9068 §4's second accepted spelling"],
  ["Application/AT+JWT", "the prefix rule and the case rule together"]
];
accepted.forEach(function (pair) {
  var spelling = pair[0], because = pair[1];
  assert.ok(mediaType.matchesMediaType(spelling, 'at+jwt'),
            '"' + spelling + '" (' + because + ') must match "at+jwt"');
});
log.info("All " + accepted.length + " RFC spellings accepted.");

// ---- What §4 says to reject -------------------------------------------------
var rejected = [
  ["JWT",                     "an ID token's type is not an access token's"],
  ["application/jwt",         "the prefixed ID-token type is not it either"],
  ["",                        "the empty string is no media type"],
  ["application/application/at+jwt",
                              "only ONE leading prefix is dropped (§4.1.9)"],
  [123,                       "a JOSE header parameter is a JSON string"],
  [null,                      "not a string either"],
  [undefined,                 "or missing"]
];
rejected.forEach(function (pair) {
  var value = pair[0], because = pair[1];
  assert.ok(!mediaType.matchesMediaType(value, 'at+jwt'),
            JSON.stringify(value) + " (" + because + ") must not match \"at+jwt\"");
});
log.info("All " + rejected.length + " non-spellings rejected.");

// ---- The normal form both rules together produce ---------------------------
assert.strictEqual(mediaType.normalizeMediaType("Application/AT+JWT"), 'at+jwt',
  "normalizeMediaType must lowercase and drop one application/ prefix");
assert.strictEqual(mediaType.normalizeMediaType('at+jwt'), 'at+jwt',
  "the already-short spelling is unchanged");
log.info("media_type_engine: all assertions passed.");
