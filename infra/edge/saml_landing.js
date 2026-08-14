// File: saml_landing.js
//
// ---------------------------------------------------------------------------
// Lambda@Edge (viewer-request) — the SAML 2.0 Assertion Consumer Service and
// Single Logout service for the STATIC S3 + CloudFront deployments.
// Paths: /samlacs and /samlslo (one function, both paths, exactly as the api
// registers one handler on both — api/server.js, handleSamlAcs).
//
// WHY THIS EXISTS WHEN SAML ALREADY WORKED STATICALLY
//
// It worked, but out of profile. SAML has three bindings, and with no landing
// the debugger asks the IdP to return the *Response* over HTTP-Redirect to the
// static saml_response.html page (responseProtocolBinding() in
// client/src/saml_request.js). That is how the "HTTP-POST binding" job passes
// on a backendless target: it POSTs the AuthnRequest and receives a GET.
//
// Two problems with relying on that, both real:
//
//   1. saml-profiles-2.0-os section 4.1.2, step 5 is explicit — "Either the
//      HTTP POST, or HTTP Artifact binding can be used to transfer the message
//      to the service provider through the user agent. ... The HTTP Redirect
//      binding MUST NOT be used, as the response will typically exceed the URL
//      length permitted by most user agents."
//
//   2. That stated reason bites first on an ENCRYPTED assertion, and measurably
//      so. Ciphertext does not compress: a plain Keycloak Response DEFLATEs to
//      ~42% of its size, an encrypted one only to ~71%, because DEFLATE can do
//      nothing with base64'd random bytes beyond stripping base64's own
//      padding. Measured on a realistic Keycloak response with real RSA-2048
//      material, the redirect URL goes from ~3.0 KB (plain) to ~7.0 KB
//      (encrypted) against CloudFront's 8,192-byte URL cap — and each extra
//      attribute or role mapper adds another 350-450 bytes. It fits until it
//      abruptly does not, which is the worst way for a debugging tool to
//      behave.
//
// With this landing the static sites use the POST binding, like everyone else,
// and the encrypted-assertion workflow works there at all.
//
// The Redirect binding is NOT removed — real deployments do use it, and it
// stays the fallback whenever no landing is deployed. This function accepts it
// too (a GET carrying SAMLResponse) and forwards it the same way, so pointing
// an IdP at /samlacs works whichever binding it chooses.
//
// WHAT IT DOES
//
//   * SAMLResponse (POST or GET) — handed to saml_response.html through
//     sessionStorage, then ?posted=1. It is passed through EXACTLY as it
//     arrived: still base64, still DEFLATE-compressed if that is how it came.
//     Nothing is decoded here, because decodeSamlParam() on the response page
//     already handles both encodings and has been doing so for the direct
//     ?SAMLResponse= path — one decoder, already tested.
//   * SAMLart — refused with an explanation. The Artifact binding needs a
//     server-side SOAP ArtifactResolve back-channel to the IdP; the api does
//     that (resolveArtifact()), and an edge function on a viewer request
//     cannot. This is the one SAML leg that genuinely cannot go static.
//   * SAMLRequest — an IdP-initiated LogoutRequest arriving at /samlslo. The
//     api does not handle it either; say so rather than 404-ing silently.
//
// Shared helpers, the hand-off contract and the CloudFront limits:
// edge_common.js.
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
var LOG_TAG = "[saml_landing]";
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

var CONTRACT = common.CONTRACTS.saml;
var RESPONSE_PAGE = CONTRACT.responsePage;

exports.handler = async function (event) {
  log.debug("Entering handler().");
  var request = event.Records[0].cf.request;
  console.log('Entering saml-landing handler. method=' + request.method +
              ' uri=' + request.uri);

  var read = common.readParams(request);
  var samlResponse = read.params.SAMLResponse || '';
  var relayState = read.params.RelayState || '';
  var artifact = read.params.SAMLart || '';
  var samlRequest = read.params.SAMLRequest || '';

  if (read.truncated) {
    console.log('Leaving saml-landing handler: request body was truncated by ' +
                'CloudFront.');
    log.debug("Leaving handler().");
    return common.truncatedPage('SAMLResponse', RESPONSE_PAGE);
  }

  if (samlResponse) {
    var values = {};
    values[CONTRACT.responseKey] = samlResponse;
    values[CONTRACT.relayStateKey] = relayState;
    var response = common.handoffPage({
      contract: CONTRACT,
      values: values,
      title: 'Receiving the SAML response…',
      lead: 'Redirecting to the SAML Response page…',
      // The no-JavaScript copy is the base64 as it arrived; the response page's
      // paste box decodes it the same way the hand-off path does.
      fallback: { label: 'SAMLResponse', value: samlResponse },
      tooLarge: 'The IdP returned a <code>SAMLResponse</code> of ' +
                Buffer.byteLength(samlResponse, 'utf8') + ' bytes (base64).'
    });
    console.log('Leaving saml-landing handler: response, status ' +
                response.status +
                ', RelayState ' + (relayState ? 'present' : 'absent') + '.');
    log.debug("Leaving handler().");
    return response;
  }

  if (artifact) {
    // Deliberately not a generic error: this is the one thing about SAML that
    // static hosting really cannot do, and it should say so precisely rather
    // than looking like a bug in the landing.
    console.log('Leaving saml-landing handler: SAMLart cannot be resolved at ' +
                'the edge.');
    log.debug("Leaving handler().");
    return common.htmlResponse(501, 'Not Implemented',
                               common.page('Artifact binding needs a backend',
      '<h1>The HTTP-Artifact binding cannot be completed here</h1>\n' +
      '<p>A <code>SAMLart</code> is only a reference. Resolving it means ' +
          'opening a ' +
      '<strong>server-to-server SOAP</strong> connection to the IdP\'s ' +
          'Artifact Resolution Service and ' +
      'sending a signed <code>&lt;ArtifactResolve&gt;</code> — a ' +
          'back-channel call, with the SP\'s ' +
      'private key, that a CloudFront viewer-request function cannot ' +
          'make.</p>\n' +
      '<p>This is the one SAML binding that needs the api backend (its ' +
          '<code>/samlacs</code> route does ' +
      'exactly this). Use the HTTP-POST or HTTP-Redirect binding on a static ' +
          'deployment.</p>'));
  }

  if (samlRequest) {
    // IdP-initiated logout. The api's handler ignores it too; the difference is
    // that this one explains itself.
    console.log('Leaving saml-landing handler: SAMLRequest (IdP-initiated) ' +
                'is not handled.');
    log.debug("Leaving handler().");
    return common.htmlResponse(400, 'Bad Request',
                               common.page('IdP-initiated request not handled',
      '<h1>This landing received a <code>SAMLRequest</code>, not a ' +
          'response</h1>\n' +
      '<p>That is an IdP-initiated message — most often a ' +
          '<code>&lt;LogoutRequest&gt;</code> sent to the ' +
      'SP\'s Single Logout service. This debugger drives SP-initiated flows ' +
          'and does not answer ' +
      'IdP-initiated requests, so there is nothing to render.</p>\n' +
      '<p>Start the flow from the <a href="/saml_request.html">SAML Test ' +
          'Tools</a> page.</p>'));
  }

  console.log('Leaving saml-landing handler: nothing to render.');
  log.debug("Leaving handler().");
  return common.htmlResponse(400, 'Bad Request', common.page('No SAML message',
    '<h1>No SAML message arrived</h1>\n' +
    '<p>This is the SAML Assertion Consumer Service / Single Logout landing, ' +
        'reached over HTTP ' +
    '<strong>' + common.htmlEscape(request.method) +
        '</strong> with no <code>SAMLResponse</code>, ' +
    '<code>SAMLart</code> or <code>SAMLRequest</code>. It is not a page to ' +
        'visit directly — the IdP ' +
    'posts here at the end of a flow.</p>\n' +
    '<p>Start one from the <a href="/saml_request.html">SAML Test Tools</a> ' +
        'page, or open the ' +
    '<a href="' + RESPONSE_PAGE +
        '">SAML Response</a> page to paste a response in by hand.</p>'));
};

exports.contract = CONTRACT;
