// File: edge_landing.js
//
// ---------------------------------------------------------------------------
// The client half of the edge landings' hand-off contract.
//
// The hosted sites are static (S3 + CloudFront) and two protocols return their
// result as an HTTP POST from the IdP, which static hosting cannot receive.
// Both POSTs are answered at the CDN edge instead, by Lambda@Edge functions
// under infra/edge/:
//
//   /wsfed              wsfed_landing.js  — the WS-Federation wresult
//   /samlacs, /samlslo  saml_landing.js   — the SAML Response / LogoutResponse
//
// Neither has anywhere to stash what it caught, so each hands it to the
// browser: a generated same-origin page writes the value into sessionStorage
// under the key names below and replaces itself with the matching response
// page, carrying ?posted=1. The response pages read those keys ONCE and delete
// them — a token left behind would make the next visit render a stale sign-in
// as though it had just happened.
//
// WHY THIS IS DUPLICATED. infra/edge/edge_common.js declares the same names.
// Those files are zipped and deployed into AWS by Terraform; this one is
// browserified into the page by the site build. They ship separately and cannot
// import each other. tests/edge_landing_contract.js loads both and fails on
// drift, because a rename on one side alone shows up only as a deployed site
// reporting that nothing arrived — which names nothing.
//
// No DOM and no crypto: safe to load from Node, which is what lets the contract
// check compare the two directly instead of scraping source. Its one require is
// bunyan, for the logging convention — so the contract check loads this file
// through tests/module_paths.js, because bunyan does not resolve from
// client/src in a checkout that installed only the tests' dependencies.
// ---------------------------------------------------------------------------

// <meta name="wsfed-landing" content="..."> on every page a landing generates.
// The name is historical (the WS-Federation landing came first) and is kept
// because remote-run-tests.sh probes for it; it means "an edge landing
// answered".

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "edge_landing",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var MARKER = "cloudfront-edge";

var WSFED = {
  responsePage: "/wsfed_response.html",
  // "1" after a successful hand-off; "blocked" when the generated page could
  // not write sessionStorage at all (disabled, or a partitioned context).
  handoffParam: "posted",
  wresultKey: "wsfed_edge_wresult",
  wctxKey: "wsfed_edge_wctx",
  waKey: "wsfed_edge_wa"
};

var SAML = {
  responsePage: "/saml_response.html",
  handoffParam: "posted",
  // The SAMLResponse exactly as the IdP sent it — still base64, and still
  // DEFLATE-compressed if it came over the Redirect binding. The landing does
  // not decode it: decodeSamlParam() on the response page already handles both
  // and is the decoder the direct ?SAMLResponse= path has always used.
  responseKey: "saml_edge_response",
  relayStateKey: "saml_edge_relaystate"
};

// Read a landing's hand-off out of sessionStorage and remove it. `keys` is the
// subset of the contract to take, as { resultName: storageKey }. Returns an
// object of the same shape with strings (empty when absent), plus `ok`: false
// when storage could not be read at all, which the caller must report rather
// than showing an empty page.
function takeHandoff(keys) {
  log.debug("Entering takeHandoff().");
  var out = { ok: true };
  var names = Object.keys(keys);
  try {
    if (typeof sessionStorage === "undefined" || !sessionStorage) {
      out.ok = false;
      names.forEach(function (n) { out[n] = ""; });
      log.debug("Leaving takeHandoff().");
      return out;
    }
    names.forEach(function (n) { out[n] = sessionStorage.getItem(keys[n]) ||
                  ""; });
    names.forEach(function (n) { sessionStorage.removeItem(keys[n]); });
  } catch (e) {
    out.ok = false;
    names.forEach(function (n) { if (out[n] === undefined) out[n] = ""; });
  }
  log.debug("Leaving takeHandoff().");
  return out;
}

module.exports = {
  MARKER: MARKER,
  WSFED: WSFED,
  SAML: SAML,
  takeHandoff: takeHandoff
};
