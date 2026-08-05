'use strict';
//
// File: server.js
//
//
// WS-Trust 1.4 STS mock.
//
// A deliberately small, dependency-light Security Token Service that speaks
// enough WS-Trust to exercise the OAuth2/OIDC Debugger's WS-Trust workflow end
// to end in the test suite. It accepts a SOAP RequestSecurityToken (RST) and
// dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT / plain UsernameToken echo, per TokenType),
//               a Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A request carrying an
// OnBehalfOf/ActAs token (delegation) is also accepted. This is a TEST STS —
// it does not verify request signatures or enforce real policy.
//
// The project's real intent is to run against Apache CXF's WS-Trust STS; this
// mock is the CI fallback (see the plan / README) and the app can target either.
//
// Config via env:
//   CONFIG_FILE  the configuration module to load, chosen the same way as for the
//                api and client services (e.g. ./env/local.js). It supplies the
//                log level; env/docker-tests.js is what the containerized test
//                stack uses.
//   STS_PORT     listening port (default 8081)
//   STS_ISSUER   the WS-Trust issuer name (default the mock's own)
//
// Logging: everything this mock does is written to the log at DEBUG level — every
// endpoint call (path, request headers and body, response headers and body,
// status code and elapsed time), and every SAML assertion, JWT and SD-JWT VC both
// BEFORE and AFTER it was signed or encrypted. Drop the level to info (see
// env/test.js) for a quiet run.
//
// ---------------------------------------------------------------------------
// This file is now the SHELL only: it loads the modules and listens. It used to be
// all 4,489 lines of the service, which is why the split happened — eight protocol
// families in one file meant no way to see what was in it short of reading it.
//
//   helpers.js       the log, the keys, and the helpers more than one protocol needs
//   app.js           the express app and every middleware, which must be installed
//                    before any route module loads
//   saml2.js         SAML 2.0 assertions: build, sign, encrypt
//   wstrust.js       WS-Trust 1.4 RST/RSTR and the /sts endpoints
//   oauth2.js        RFC 8414 metadata, JWKS, and the mock authorization server
//   vc_configs.js    the credential configurations this issuer offers
//   vc_offers.js     Credential Offers, pre-authorized codes, deferred state
//   vc_did.js        the did:web document and the DIF domain linkage credential
//   vc_issuer.js     OID4VCI: metadata, proofs, the three credential formats
//   vc_verifier.js   OID4VP: the request, and verifying what comes back
//   sts_metadata.js  GET /sts-metadata — every endpoint and every spec, listed
//
// **Requiring a module registers its endpoints.** Each one does `app.get(...)` at
// its top level against the shared app from app.js, rather than exporting a
// register() function — which kept every handler exactly where it was written
// instead of re-indented inside a wrapper. So the order below is the route
// order. Nothing here has overlapping paths, so it does not currently matter, but
// a module registering a wildcard would care a great deal. sts_metadata.js is last
// on purpose: it reads the router to list what everything else registered, and
// while it re-reads it per request, being last means it is never the reason a
// route is missing.
// ---------------------------------------------------------------------------

const app = require('./app');
const { log, PORT, ISSUER } = require('./helpers');

require('./wstrust');
require('./oauth2');
require('./vc_offers');
require('./vc_did');
require('./vc_issuer');
require('./vc_verifier');
require('./sts_metadata');

app.listen(PORT, '0.0.0.0', function () {
  log.info('WS-Trust STS mock listening on :' + PORT + ' (issuer ' + ISSUER + '); POST SOAP RST to /sts');
  log.info('RFC 8414 metadata at /.well-known/oauth-authorization-server; ' +
           'OpenID Provider Configuration at /.well-known/openid-configuration; JWKS at /oauth2/jwks');
  log.info('OID4VCI issuer metadata at /.well-known/openid-credential-issuer; ' +
           'credential endpoint at /oid4vci/credential');
  log.info('Issuer-initiated (OID4VCI H.1): the issuer web page is at /issuer; ' +
           'it builds a Credential Offer and sends the browser to the wallet.');
  log.info('Mock authorization server endpoints: /oauth2/authorize (login screen), /oauth2/login, ' +
           '/oauth2/token, /oauth2/userinfo, /oauth2/introspect, /oauth2/revoke, /oauth2/register, ' +
           '/oauth2/logout');
  log.info('Every endpoint call, and every token or assertion before and after it was signed, ' +
           'is written to this log at debug level.');
  log.info('Every endpoint and every specification this service implements is listed at ' +
           '/sts-metadata (add ?format=json for the machine-readable form).');
});
