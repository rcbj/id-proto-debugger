// File: wsfed_msg.js
//
// Pure WS-Federation Passive Requestor Profile message construction, factored
// out of wsfed_request.js so it can be unit-tested without a DOM (mirrors the
// wstrust_msg.js split). Given the values the page reads from its form it
// produces the sign-in / sign-out request parameter sets and the optional
// inline <wst:RequestSecurityToken> (wreq). No DOM, no crypto — safe to require
// from Node.
//
// WS-Federation Passive Requestor Profile sign-in is a top-level browser
// navigation to the IdP passive endpoint with query parameters (wa=wsignin1.0,
// wtrealm, wreply, wctx, wct, wfresh, whr, wauth, wp, wreq). The request itself
// is NOT signed in this profile; trust is established out-of-band via metadata
// / realm registration. All signature/encryption handling lives on the inbound
// token (wresult) side, in wsfed_response.js.

var wm = require("./wstrust_msg"); // buildRst() for the inline wreq RST

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "wsfed_msg",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var WSFED_NS = "http://docs.oasis-open.org/wsfed/federation/200706";
var WA_SIGNIN = "wsignin1.0";
var WA_SIGNOUT = "wsignout1.0";
var WA_SIGNOUT_CLEANUP = "wsignoutcleanup1.0";

function trimOrEmpty(s) {
  log.debug("Entering trimOrEmpty().");
  log.debug("Leaving trimOrEmpty().");
  return String(s == null ? '' : s).trim();
}

// Build the ordered WS-Federation sign-in request parameters. `o` mirrors the
// page form:
//   realm (wtrealm), reply (wreply), context (wctx), includeTimestamp (wct),
//   timestamp (explicit wct value, else now), freshness (wfresh), homeRealm
//   (whr), authType (wauth), policy (wp), request (inline wreq RST), requestPtr
//   (wreqptr).
// Returns an array of [name, value] pairs (blanks omitted) so parameter
// ordering is stable and predictable (wa first).
function buildSignInParams(o) {
  log.debug("Entering buildSignInParams().");
  o = o || {};
  var params = [];
  params.push(['wa', WA_SIGNIN]);

  var realm = trimOrEmpty(o.realm);
  if (realm) params.push(['wtrealm', realm]);

  var reply = trimOrEmpty(o.reply);
  if (reply) params.push(['wreply', reply]);

  var ctx = trimOrEmpty(o.context);
  if (ctx) params.push(['wctx', ctx]);

  if (o.includeTimestamp) {
    var wct = trimOrEmpty(o.timestamp) || new Date().toISOString();
    params.push(['wct', wct]);
  }

  // wfresh is an integer number of minutes; 0 (force reauth) is meaningful, so
  // only omit it when the field is blank.
  var fresh = trimOrEmpty(o.freshness);
  if (fresh !== '') params.push(['wfresh', fresh]);

  var homeRealm = trimOrEmpty(o.homeRealm);
  if (homeRealm) params.push(['whr', homeRealm]);

  var authType = trimOrEmpty(o.authType);
  if (authType) params.push(['wauth', authType]);

  var policy = trimOrEmpty(o.policy);
  if (policy) params.push(['wp', policy]);

  // wreqptr (a URL reference to the RST) takes precedence over an inline wreq;
  // most IdPs prefer/accept the inline wreq.
  var reqPtr = trimOrEmpty(o.requestPtr);
  var req = trimOrEmpty(o.request);
  if (reqPtr) params.push(['wreqptr', reqPtr]);
  else if (req) params.push(['wreq', req]);

  log.debug("Leaving buildSignInParams().");
  return params;
}

// Build the sign-out request parameters. `o`: reply (wreply), cleanup (use
// wsignoutcleanup1.0 instead of wsignout1.0), realm (optional wtrealm).
function buildSignOutParams(o) {
  log.debug("Entering buildSignOutParams().");
  o = o || {};
  var params = [];
  params.push(['wa', o.cleanup ? WA_SIGNOUT_CLEANUP : WA_SIGNOUT]);
  var reply = trimOrEmpty(o.reply);
  if (reply) params.push(['wreply', reply]);
  var realm = trimOrEmpty(o.realm);
  if (realm) params.push(['wtrealm', realm]);
  log.debug("Leaving buildSignOutParams().");
  return params;
}

// Serialize [name,value] pairs (or a plain object) to a URL-encoded query
// string.
function toQueryString(params) {
  log.debug("Entering toQueryString().");
  var pairs = Array.isArray(params)
    ? params
    : Object.keys(params).map(function (k) { return [k, params[k]]; });
  log.debug("Leaving toQueryString().");
  return pairs.map(function (p) {
    return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1] == null ?
                              '' : p[1]);
  }).join('&');
}

// Build a full sign-in/sign-out URL: endpoint + query (respecting any query
// string already present on the endpoint).
function buildUrl(endpoint, params) {
  log.debug("Entering buildUrl().");
  var qs = toQueryString(params);
  var ep = trimOrEmpty(endpoint);
  if (!ep) {
    log.debug("Leaving buildUrl().");
    return '?' + qs;
  }
  var sep = ep.indexOf('?') >= 0 ? '&' : '?';
  log.debug("Leaving buildUrl().");
  return ep + sep + qs;
}

// Optional inline wreq RequestSecurityToken — delegate to the shared WS-Trust
// RST builder (o mirrors wstrust_msg.buildRst's options).
function buildWReq(o) {
  log.debug("Entering buildWReq().");
  log.debug("Leaving buildWReq().");
  return wm.buildRst(o || {});
}

module.exports = {
  WSFED_NS: WSFED_NS,
  WA_SIGNIN: WA_SIGNIN,
  WA_SIGNOUT: WA_SIGNOUT,
  WA_SIGNOUT_CLEANUP: WA_SIGNOUT_CLEANUP,
  buildSignInParams: buildSignInParams,
  buildSignOutParams: buildSignOutParams,
  toQueryString: toQueryString,
  buildUrl: buildUrl,
  buildWReq: buildWReq
};
