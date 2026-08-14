// File: wsfed_landing.js
//
// ---------------------------------------------------------------------------
// Lambda@Edge (viewer-request) — the WS-Federation Passive Requestor Profile
// landing endpoint for the STATIC S3 + CloudFront deployments. Path: /wsfed.
//
// WHY THIS ONE HAS NO ALTERNATIVE
//
// Every other protocol here can be made static by choosing a binding the
// browser can finish alone. OAuth2/OIDC return on a redirect. SAML has three
// bindings and can be asked to return its Response over HTTP-Redirect to a
// static page — the debugger does exactly that when no landing is available
// (responseProtocolBinding() in client/src/saml_request.js), which is why the
// SAML jobs pass on a backendless target even without saml_landing.js.
//
// The WS-Federation Passive Requestor Profile defines exactly one way to
// deliver the token: after authenticating, the IdP renders a form that
// auto-POSTs wa/wresult/wctx to the RP's wreply URL. There is no redirect
// response binding to ask for, and S3 answers a POST with 405/403 — so without
// this function the round trip cannot complete on static hosting at all.
//
// WHAT IT DOES — a faithful port of the api's POST/GET /wsfed route
// (api/server.js, handleWsFedLanding) to a place with no server-side storage:
//
//   * sign-in  — a wresult is present. The api stashes it and passes ?id=; there
//     is nothing to stash here, so it goes to the browser in sessionStorage and
//     the page is sent to wsfed_response.html?posted=1. See edge_common.js for
//     why sessionStorage and not the URL.
//   * sign-out — no wresult (wa=wsignout1.0 / wsignoutcleanup1.0, or Keycloak's
//     finishLogout, which sends no wa at all): 302 to
//     wsfed_response.html?signout=<the wa that arrived, or 1>. Byte-identical
//     to the api, so nothing downstream has to know which landing answered.
//   * a sign-in with no token — NOT a sign-out, and refused as such; see below.
//
// The shared helpers, the hand-off contract and the CloudFront size limits all
// live in edge_common.js.
// ---------------------------------------------------------------------------
'use strict';

var common = require('./edge_common.js');

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// Lambda@Edge bundles these handlers alone, with no dependencies.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[wsfed_landing]";
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

var CONTRACT = common.CONTRACTS.wsfed;
var RESPONSE_PAGE = CONTRACT.responsePage;

exports.handler = async function (event) {
  log.debug("Entering handler().");
  var request = event.Records[0].cf.request;
  console.log('Entering wsfed-landing handler. method=' + request.method +
              ' uri=' + request.uri);

  var read = common.readParams(request);
  var wa = read.params.wa || '';
  var wctx = read.params.wctx || '';
  var wresult = read.params.wresult || '';

  if (read.truncated) {
    console.log('Leaving wsfed-landing handler: request body was truncated ' +
                'by CloudFront.');
    log.debug("Leaving handler().");
    return common.truncatedPage('wresult', RESPONSE_PAGE);
  }

  if (wresult) {
    // wresult is RAW XML (a WS-Trust RSTR carrying the assertion) — unlike
    // SAMLResponse it is neither base64 nor DEFLATE encoded, so it is forwarded
    // verbatim. The same note is on the api landing.
    var values = {};
    values[CONTRACT.wresultKey] = wresult;
    values[CONTRACT.wctxKey] = wctx;
    values[CONTRACT.waKey] = wa;
    var response = common.handoffPage({
      contract: CONTRACT,
      values: values,
      title: 'Receiving the WS-Federation token…',
      lead: 'Redirecting to the WS-Federation Response page…',
      fallback: { label: 'wresult', value: wresult },
      tooLarge: 'The IdP returned a <code>wresult</code> of ' +
                Buffer.byteLength(wresult, 'utf8') + ' bytes.'
    });
    console.log('Leaving wsfed-landing handler: sign-in, status ' +
                response.status + '.');
    log.debug("Leaving handler().");
    return response;
  }

  // A sign-in that arrived with no token is NOT a sign-out, and must not be
  // reported as one — "Signed out at the IdP" after a successful login is the
  // kind of message that sends you to the IdP's logs for an hour.
  //
  // The realistic cause is this distribution's own viewer-protocol-policy: an
  // http wreply is answered 301 to https, and a browser following a 301
  // re-issues the request as a GET with no body, so the token is gone before
  // this function runs. (Nothing here can prevent that — the protocol redirect
  // happens ahead of the viewer-request trigger — but it can be named.) The
  // other cause is an IdP configured to return over GET, which the passive
  // profile does not do.
  if (wa === 'wsignin1.0') {
    console.log('Leaving wsfed-landing handler: wa=wsignin1.0 with ' +
                'no wresult.');
    log.debug("Leaving handler().");
    return common.htmlResponse(400, 'Bad Request',
                               common.page('Sign-in returned no token',
      '<h1>A sign-in came back with no token</h1>\n' +
      '<p>This landing was reached with <code>wa=wsignin1.0</code> but no ' +
          '<code>wresult</code>, over ' +
      'HTTP <strong>' + common.htmlEscape(request.method) +
          '</strong>. That is not a sign-out, so it ' +
      'is not being reported as one.</p>\n<p>Two things do this:</p>\n<ul>\n' +
      '<li>The <code>wreply</code> sent to the IdP was <code>http://</code>. ' +
          'This distribution answers ' +
      'plain HTTP with a 301 to HTTPS, and a browser following a 301 ' +
          're-sends the request as a GET with ' +
      'no body — so the token was dropped one hop before here. Use an ' +
          '<code>https://</code> ' +
      '<code>wreply</code>.</li>\n' +
      '<li>The IdP returned the token over GET. The Passive Requestor ' +
          'Profile auto-POSTs it, so an IdP ' +
      'doing otherwise needs its configuration checked.</li>\n</ul>\n' +
      '<p><a href="' + RESPONSE_PAGE +
          '">Open the WS-Federation Response page</a> to paste a ' +
      '<code>wresult</code> in by hand.</p>'));
  }

  // Sign-out carries no token. Keycloak's finishLogout sends no wa at all, so
  // fall back to "1" exactly as the api landing does — the response page and
  // the test both accept 1 / wsignout1.0 / wsignoutcleanup1.0.
  var target = RESPONSE_PAGE + '?signout=' + encodeURIComponent(wa || '1');
  console.log('Leaving wsfed-landing handler: no wresult, redirecting to ' +
              target + '.');
  log.debug("Leaving handler().");
  return common.redirectResponse(target);
};

// Exported for the behaviour checks in the test suite. Lambda only ever calls
// exports.handler; the drift check reads edge_common.js's CONTRACTS.
exports.contract = CONTRACT;
