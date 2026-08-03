'use strict';
//
// File: sts_metadata.js
//
// ---------------------------------------------------------------------------
// GET /sts-metadata — what this mock is, endpoint by endpoint and spec by spec.
//
// It exists because this service now speaks eight protocol families across ten
// modules, and there was no way to find out what it offers short of reading
// server.js. It answers three questions: what can I call, what may I call it
// with, and what specification is it pretending to implement.
//
// **The endpoint list is read from Express's own router, not written down here.**
// That is the whole design. A hand-kept list of endpoints in a file next to the
// endpoints is a list that goes stale the first time somebody adds a route, and
// the failure is silent in the worst direction — the page still looks complete.
// So `app._router.stack` is walked on every request and the table below only
// supplies the NAME and the description for a path it finds. Two consequences,
// both shown on the page rather than hidden:
//
//   * a route that is registered and undescribed is listed as UNDOCUMENTED. It
//     still appears, with its methods, because the page's first duty is to be a
//     true list of what is callable.
//   * a description for a path that is NOT registered is listed as a stale entry.
//     That is the direction that catches a route being renamed or removed.
//
// `tests/sts_metadata.js` fails on either, which is what makes the page's claim to
// completeness worth something. It is also why the route walk happens per request
// instead of at require time: at require time the answer would depend on module
// load order, and a module loaded after this one would be missing.
//
// The specs are necessarily hand-written — no server can introspect which
// document it is implementing — so they are written CONSERVATIVELY. Each says
// what this mock actually does against it, including where it does less than the
// specification requires, because a list of specs that overstates is worse than
// no list at all in a tool people use to learn those specs.
// ---------------------------------------------------------------------------

const app = require('./app');
const { log, xmlEscape, baseUrlOf, ISSUER, PORT } = require('./helpers');

// ---------------------------------------------------------------------------
// The specifications this service implements, and how far.
//
// `coverage` is the honest part: "full" means a client conforming to that
// document works against this mock; "partial" says what is missing; "mock" means
// the shape is right and the enforcement is deliberately absent, which is what a
// test double is for.
// ---------------------------------------------------------------------------
const SPECS = [
  { id: 'ws-trust', name: 'WS-Trust 1.4 (and 1.0-1.3)',
    where: 'OASIS ws-sx',
    url: 'https://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html',
    coverage: 'partial: Issue, Renew, Validate and Cancel over SOAP 1.1 and 1.2. ' +
              'Request signatures are not verified and no policy is enforced — this is a test STS.' },
  { id: 'wss-username', name: 'WS-Security UsernameToken Profile 1.1',
    where: 'OASIS wss',
    url: 'https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-UsernameTokenProfile.pdf',
    coverage: 'mock: a UsernameToken is accepted when both members are present. No password is ever ' +
              'checked, except that the literal "invalid" is refused so a negative test can force a failure.' },
  { id: 'saml2', name: 'SAML 2.0 Core',
    where: 'OASIS saml-core-2.0-os',
    url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
    coverage: 'partial: issues signed Assertions (AuthnStatement, AttributeStatement, ' +
              'SubjectConfirmation, Conditions). It is an assertion ISSUER, not an IdP — there is no ' +
              'Web SSO profile here.' },
  { id: 'xmldsig', name: 'XML Signature and XML Encryption',
    where: 'W3C',
    url: 'https://www.w3.org/TR/xmldsig-core1/',
    coverage: 'full for what it emits: enveloped signature, exclusive canonicalization, ' +
              'RSA-SHA256; AES-256-CBC content encryption with an RSA-OAEP wrapped key.' },
  { id: 'rfc6749', name: 'RFC 6749 — OAuth 2.0',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc6749',
    coverage: 'partial: authorization_code, implicit, password, client_credentials and refresh_token. ' +
              'Client authentication is accepted, not verified.' },
  { id: 'rfc6750', name: 'RFC 6750 — Bearer Token Usage',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc6750',
    coverage: 'partial: bearer tokens are read from the Authorization header. Credential endpoints ' +
              'check that a token is PRESENT but cannot validate one issued by a separate ' +
              'authorization server.' },
  { id: 'rfc7009', name: 'RFC 7009 — Token Revocation',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7009',
    coverage: 'full: revocation takes effect — a revoked token is reported inactive by introspection.' },
  { id: 'rfc7515', name: 'RFC 7515/7516/7517/7518 — JWS, JWE, JWK, JWA',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7515',
    coverage: 'partial: RS256 signatures throughout; RSA-OAEP-256 with A128GCM/A256GCM for the ' +
              'encrypted Credential Request and Response.' },
  { id: 'rfc7519', name: 'RFC 7519 — JSON Web Token',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7519',
    coverage: 'full: every token this service issues is an RS256 JWT that verifies against the ' +
              'published JWKS.' },
  { id: 'rfc7591', name: 'RFC 7591 — Dynamic Client Registration',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7591',
    coverage: 'full: registers a client, returns its credentials and a registration access token.' },
  { id: 'rfc7592', name: 'RFC 7592 — Dynamic Client Registration Management',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7592',
    coverage: 'full for the three operations: read, update and delete a registered client, each ' +
              'guarded by the registration access token issued with it.' },
  { id: 'rfc7636', name: 'RFC 7636 — PKCE',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7636',
    coverage: 'partial: S256 and plain are advertised and the challenge is carried through the ' +
              'authorization code.' },
  { id: 'rfc7662', name: 'RFC 7662 — Token Introspection',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7662',
    coverage: 'full: honest active/inactive, with the claims of the token presented.' },
  { id: 'rfc7800', name: 'RFC 7800 — Proof-of-Possession Key Semantics',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7800',
    coverage: 'full for the use made of it: cnf.jwk binds an issued credential to the holder key ' +
              'whose possession was proved.' },
  { id: 'rfc8414', name: 'RFC 8414 — Authorization Server Metadata',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8414',
    coverage: 'full: every member section 2 defines, plus a genuinely signed signed_metadata. ' +
              'Served at the well-known path and with an issuer path component appended.' },
  { id: 'rfc8693', name: 'RFC 8693 — Token Exchange',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8693',
    coverage: 'partial: the grant is accepted at the token endpoint and the subject token becomes ' +
              'the identity in the issued token.' },
  { id: 'rfc9396', name: 'RFC 9396 — Rich Authorization Requests',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9396',
    coverage: 'partial: authorization_details of type openid_credential, which is how OID4VCI asks ' +
              'for a credential without a scope. Granted details come back on the token response.' },
  { id: 'oidc', name: 'OpenID Connect Core 1.0',
    where: 'OpenID Foundation', url: 'https://openid.net/specs/openid-connect-core-1_0.html',
    coverage: 'partial: id_token with nonce, at_hash and c_hash, and the three authentication ' +
              'flows. There is no userinfo endpoint and no request object here.' },
  { id: 'oid4vci', name: 'OpenID for Verifiable Credential Issuance 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html',
    coverage: 'partial but broad: issuer metadata, nonce, proof of possession, batch issuance, ' +
              'deferred issuance, Credential Offers (Appendix H.1/H.2/H.3), the pre-authorized code ' +
              'grant with tx_code, credential_identifiers, request and response encryption ' +
              '(section 10), and the Notification Endpoint (section 11).' },
  { id: 'oid4vp', name: 'OpenID for Verifiable Presentations 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html',
    coverage: 'partial: Authorization Requests by value and as a signed Request Object by reference, ' +
              'response_mode=direct_post, a DCQL query, and full verification of what comes back. ' +
              'No presentation_definition (DIF PE) — DCQL only.' },
  { id: 'sd-jwt', name: 'RFC 9901 — Selective Disclosure for JWTs (SD-JWT)',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9901',
    coverage: 'full for issuance and verification: _sd digests with a decoy, salted Disclosures, the ' +
              'Combined Serialization, and a Key Binding JWT checked including sd_hash over the exact ' +
              'bytes presented.' },
  { id: 'sd-jwt-vc', name: 'SD-JWT-based Verifiable Credentials (draft-ietf-oauth-sd-jwt-vc)',
    where: 'IETF', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/',
    coverage: 'partial: vct, cnf holder binding, and the /.well-known/jwt-vc-issuer key resolution ' +
              'document. Naming the issuer by DID is an EXTENSION — this document defines no ' +
              'DID-based issuer signature mechanism.' },
  { id: 'vcdm', name: 'W3C Verifiable Credentials Data Model 1.1 and 2.0',
    where: 'W3C', url: 'https://www.w3.org/TR/vc-data-model-2.0/',
    coverage: 'partial: the VC-JWT encoding of VCDM 1.1 (jwt_vc_json) and VCDM 2.0 credentials with ' +
              'an embedded proof (ldp_vc).' },
  { id: 'di-bbs', name: 'W3C Data Integrity — bbs-2023 cryptosuite',
    where: 'W3C', url: 'https://www.w3.org/TR/vc-di-bbs/',
    coverage: 'full for base proofs and derived proofs over BLS12-381, including the mandatory ' +
              'pointers and the unlinkable selective disclosure a derived proof provides.' },
  { id: 'rdf-c14n', name: 'RDF Dataset Canonicalization (URDNA2015) and JSON-LD 1.1',
    where: 'W3C', url: 'https://www.w3.org/TR/rdf-canon/',
    coverage: 'full for what Data Integrity needs. JSON-LD contexts are VENDORED, never fetched: ' +
              'canonicalization that depended on a network fetch would be neither reproducible nor safe.' },
  { id: 'did-core', name: 'W3C DID Core 1.0 (did:web, did:key, did:jwk)',
    where: 'W3C', url: 'https://www.w3.org/TR/did-1.0/',
    coverage: 'partial: this service PUBLISHES a did:web document with two verification methods. ' +
              'The wallet side resolves all three methods.' },
  { id: 'did-config', name: 'DIF Well Known DID Configuration',
    where: 'DIF',
    url: 'https://identity.foundation/well-known-did-configuration/resources/did-configuration/',
    coverage: 'full in the JWT form: a Domain Linkage Credential proving this origin and this DID ' +
              'are the same entity. The Linked Data Proof form is not served.' }
];

// ---------------------------------------------------------------------------
// What each endpoint IS. Keyed by the Express path so it can be joined to the
// router's own list; the HTTP methods are never written here, because the router
// knows them and this file would only get them wrong.
//
// `group` orders the page. `specs` are ids from SPECS above; a typo there is
// reported on the page rather than silently dropping the link.
// ---------------------------------------------------------------------------
const ENDPOINTS = [
  // --- service ---
  { path: '/healthcheck', group: 'Service', name: 'Health check',
    specs: [], what: 'Liveness only. Answers 200 with a JSON message; used by the compose healthcheck.' },
  { path: '/sts-metadata', group: 'Service', name: 'This page',
    specs: [], what: 'Every endpoint this service registers, with its methods, and every ' +
                     'specification it implements. Add ?format=json for the machine-readable form.' },
  { path: '/docs', group: 'Service', name: 'Service documentation',
    specs: ['rfc8414'], what: 'What the RFC 8414 service_documentation member points at.' },
  { path: '/policy', group: 'Service', name: 'Operator policy',
    specs: ['rfc8414'], what: 'What op_policy_uri points at.' },
  { path: '/tos', group: 'Service', name: 'Terms of service',
    specs: ['rfc8414'], what: 'What op_tos_uri points at.' },
  // Registered by app.options('*', cors(...)) rather than by a protocol module,
  // and listed because it IS callable and the page's first duty is to be a true
  // list of what is. It was the first thing the drift check caught: a route that
  // exists and is described nowhere.
  { path: '*', group: 'Service', name: 'CORS preflight',
    specs: [], what: 'Answers the preflight for every path, and sets ' +
                     'Access-Control-Allow-Private-Network so a page on an https origin can call ' +
                     'this service on loopback (Chrome Private Network Access).' },

  // --- WS-Trust ---
  { path: '/sts', group: 'WS-Trust', name: 'Security Token Service',
    specs: ['ws-trust', 'wss-username', 'saml2', 'xmldsig'],
    what: 'POST a SOAP RequestSecurityToken; dispatches on wst:RequestType (Issue, Renew, Validate, ' +
          'Cancel) and returns an RSTR. GET describes the endpoint. Add ?encrypt=1 to have the issued ' +
          'assertion returned as an EncryptedAssertion.' },
  { path: '/sts/cert', group: 'WS-Trust', name: 'STS certificate',
    specs: ['ws-trust'], what: 'The PEM certificate whose key signs the assertions, so a relying ' +
                               'party can verify them.' },

  // --- OAuth 2.0 / OIDC ---
  { path: '/.well-known/oauth-authorization-server', group: 'OAuth 2.0 / OIDC',
    name: 'Authorization Server Metadata', specs: ['rfc8414'],
    what: 'Every member RFC 8414 section 2 defines, plus a genuinely signed signed_metadata.' },
  { path: '/.well-known/oauth-authorization-server/*', group: 'OAuth 2.0 / OIDC',
    name: 'Authorization Server Metadata (issuer with a path)', specs: ['rfc8414'],
    what: 'The same document at the section 3.1 shape, where the issuer identifier carries a path.' },
  { path: '/oauth2/jwks', group: 'OAuth 2.0 / OIDC', name: 'JWKS',
    specs: ['rfc7515', 'rfc7519'],
    what: 'The signing key as a single RS256 JWK with its x5c. Regenerated on every start, so it is ' +
          'served no-store.' },
  { path: '/oauth2/authorize', group: 'OAuth 2.0 / OIDC', name: 'Authorization endpoint',
    specs: ['rfc6749', 'oidc', 'rfc7636', 'rfc9396'],
    what: 'Shows a login screen, then issues a code, token and/or id_token per response_type. ' +
          'Carries PKCE, nonce, authorization_details and OID4VCI issuer_state.' },
  { path: '/oauth2/login', group: 'OAuth 2.0 / OIDC', name: 'Login form target',
    specs: ['oidc'],
    what: 'Where the login screen posts. No password is checked; the username typed becomes the ' +
          'identity in every token that follows.' },
  { path: '/oauth2/logout', group: 'OAuth 2.0 / OIDC', name: 'Session end',
    specs: ['oidc'], what: 'Drops the session cookie and returns to post_logout_redirect_uri.' },
  { path: '/oauth2/token', group: 'OAuth 2.0 / OIDC', name: 'Token endpoint',
    specs: ['rfc6749', 'oidc', 'rfc8693', 'rfc9396', 'oid4vci'],
    what: 'authorization_code, refresh_token, client_credentials, password, token-exchange, and ' +
          "OID4VCI's pre-authorized_code with tx_code enforcement." },
  { path: '/oauth2/introspect', group: 'OAuth 2.0 / OIDC', name: 'Introspection endpoint',
    specs: ['rfc7662'], what: 'Honest active/inactive with the presented token\'s claims.' },
  { path: '/oauth2/revoke', group: 'OAuth 2.0 / OIDC', name: 'Revocation endpoint',
    specs: ['rfc7009'], what: 'Revocation that takes effect: introspection then reports inactive.' },
  { path: '/oauth2/register', group: 'OAuth 2.0 / OIDC', name: 'Dynamic client registration',
    specs: ['rfc7591'], what: 'Registers a client and returns its credentials plus a registration ' +
                              'access token.' },
  { path: '/oauth2/register/:client_id', group: 'OAuth 2.0 / OIDC',
    name: 'Registered client management', specs: ['rfc7592', 'rfc6750'],
    what: 'Read, update or delete a registered client, guarded by its registration access token.' },

  // --- OID4VCI ---
  { path: '/.well-known/openid-credential-issuer', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Issuer Metadata', specs: ['oid4vci'],
    what: 'The credential configurations on offer, the endpoints, batch and encryption support, and ' +
          'this issuer\'s DID (issuer_did, an extension).' },
  { path: '/.well-known/openid-credential-issuer/*', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Issuer Metadata (issuer with a path)', specs: ['oid4vci'],
    what: 'The same document where the Credential Issuer Identifier carries a path, which is what ' +
          'forces well-known path insertion.' },
  { path: '/.well-known/jwt-vc-issuer', group: 'VC Issuance (OID4VCI)',
    name: 'JWT VC Issuer Metadata', specs: ['sd-jwt-vc'],
    what: 'SD-JWT VC key resolution: the issuer identifier and its jwks_uri, plus issuer_did beside ' +
          'them as an extension.' },
  { path: '/.well-known/jwt-vc-issuer/*', group: 'VC Issuance (OID4VCI)',
    name: 'JWT VC Issuer Metadata (issuer with a path)', specs: ['sd-jwt-vc'],
    what: 'The same document, well-known path inserted before the issuer\'s path.' },
  { path: '/oid4vci/nonce', group: 'VC Issuance (OID4VCI)', name: 'Nonce endpoint',
    specs: ['oid4vci'], what: 'A fresh c_nonce for a proof of possession. Single use.' },
  { path: '/oid4vci/credential', group: 'VC Issuance (OID4VCI)', name: 'Credential endpoint',
    specs: ['oid4vci', 'sd-jwt', 'sd-jwt-vc', 'vcdm', 'di-bbs', 'rdf-c14n', 'rfc7800', 'rfc7515',
             'rfc6750'],
    what: 'Mints dc+sd-jwt, jwt_vc_json or ldp_vc per the configuration asked for. Verifies the ' +
          'wallet\'s proof, supports batch issuance, and accepts an encrypted request and/or returns ' +
          'an encrypted response.' },
  { path: '/oid4vci/deferred_credential', group: 'VC Issuance (OID4VCI)',
    name: 'Deferred credential endpoint', specs: ['oid4vci', 'rfc6750'],
    what: 'Collects a credential the issuer answered 202 for, against its transaction_id.' },
  { path: '/oid4vci/notification', group: 'VC Issuance (OID4VCI)', name: 'Notification endpoint',
    specs: ['oid4vci', 'rfc6750'], what: 'Section 11: the wallet reports what it did with the credential. ' +
                              'Validated and recorded.' },
  { path: '/oid4vci/notification/:id', group: 'VC Issuance (OID4VCI)',
    name: 'Notification readback (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests: what the wallet reported against a notification_id.' },
  { path: '/oid4vci/last_request', group: 'VC Issuance (OID4VCI)',
    name: 'Last Credential Request (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests: whether the last Credential Request arrived encrypted, and how.' },
  { path: '/oid4vci/credential-offer/:id', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Offer by reference', specs: ['oid4vci'],
    what: 'Serves an offer fetched via credential_offer_uri.' },
  { path: '/issuer', group: 'VC Issuance (OID4VCI)', name: 'Issuer web page',
    specs: ['oid4vci'], what: 'Appendix H.1: where an End-User starts an issuer-initiated flow.' },
  { path: '/issuer/offer', group: 'VC Issuance (OID4VCI)', name: 'Build a Credential Offer',
    specs: ['oid4vci'],
    what: 'Builds an offer and either sends the browser to the wallet or renders a QR code. ' +
          '?mode=cross-device (H.2) and ?mode=deferred (H.3) select the pre-authorized code grant ' +
          'with a Transaction Code.' },
  { path: '/bbs/keys/1', group: 'VC Issuance (OID4VCI)', name: 'BBS public key',
    specs: ['di-bbs'],
    what: 'The BLS12-381 key an ldp_vc proof is verified with, as a Multikey. This is what a plain ' +
          'ldp_vc credential\'s verificationMethod dereferences to.' },

  // --- DIDs ---
  { path: '/.well-known/did.json', group: 'Decentralized Identifiers',
    name: 'DID document (did:web)', specs: ['did-core'],
    what: 'This issuer as a did:web, with the RS256 key as a JsonWebKey2020 and the BBS key as a ' +
          'Multikey. The DID is derived from the request Host, so one container works at any address.' },
  { path: '/.well-known/did-configuration.json', group: 'Decentralized Identifiers',
    name: 'Domain Linkage Credential', specs: ['did-config', 'vcdm', 'rfc7519'],
    what: 'Proves this origin and this DID are the same entity. For did:web it is the only ' +
          'non-circular proof: resolving did:web:host means fetching host.' },

  // --- OID4VP ---
  { path: '/oid4vp/verifier', group: 'VC Presentation (OID4VP)', name: 'Verifier web page',
    specs: ['oid4vp'], what: 'Where a presentation starts: the verifier asks, the wallet answers.' },
  { path: '/oid4vp/start', group: 'VC Presentation (OID4VP)', name: 'Build an Authorization Request',
    specs: ['oid4vp'],
    what: 'response_type=vp_token with a DCQL query, a fresh nonce and response_mode=direct_post, ' +
          'passed by value or by reference, with a QR screen for cross-device.' },
  { path: '/oid4vp/request/:id', group: 'VC Presentation (OID4VP)', name: 'Request Object',
    specs: ['oid4vp', 'rfc7519'],
    what: 'The signed Request Object fetched via request_uri.' },
  { path: '/oid4vp/response', group: 'VC Presentation (OID4VP)', name: 'Response URI',
    specs: ['oid4vp', 'sd-jwt', 'sd-jwt-vc', 'di-bbs', 'rdf-c14n', 'vcdm'],
    what: 'Where the wallet POSTs the vp_token, and where it is really verified: issuer signature, ' +
          'every Disclosure digest against _sd, the Key Binding JWT including sd_hash, the validity ' +
          'window, and whether the claims asked for arrived.' },
  { path: '/oid4vp/result/:state', group: 'VC Presentation (OID4VP)',
    name: 'Verification verdict (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for the wallet\'s step 3 and for tests: the per-check verdict for a presentation.' },
  { path: '/oid4vp/done', group: 'VC Presentation (OID4VP)', name: 'Presentation complete page',
    specs: ['oid4vp'], what: 'Where the End-User lands after a cross-device presentation.' }
];

const SPEC_BY_ID = {};
SPECS.forEach(function (s) { SPEC_BY_ID[s.id] = s; });

// ---------------------------------------------------------------------------
// The router's own list of what is registered, grouped by path so the three
// methods on /oauth2/register/:client_id read as one endpoint.
//
// Express 4 keeps the routes on app._router.stack. It is a private member, which
// is worth a word: the alternative is a list maintained by hand, and this page
// exists precisely because that list cannot be trusted. If a future Express moves
// it, the tests fail loudly (the page reports every described path as stale)
// rather than quietly reporting nothing.
// ---------------------------------------------------------------------------
function registeredRoutes() {
  log.debug("Entering registeredRoutes().");
  const router = app._router || app.router;
  const stack = (router && router.stack) || [];
  const byPath = new Map();
  stack.forEach(function (layer) {
    if (!layer.route || !layer.route.path) return;
    const path = String(layer.route.path);
    const methods = Object.keys(layer.route.methods || {})
      .filter(function (m) { return m !== '_all'; })
      .map(function (m) { return m.toUpperCase(); });
    if (!byPath.has(path)) byPath.set(path, new Set());
    methods.forEach(function (m) { byPath.get(path).add(m); });
  });
  const out = [];
  byPath.forEach(function (methods, path) {
    out.push({ path: path, methods: Array.from(methods).sort() });
  });
  log.debug("Leaving registeredRoutes(). " + out.length + " path(s).");
  return out;
}

// Join the router's paths to their descriptions, and report both kinds of drift.
function describeEndpoints() {
  log.debug("Entering describeEndpoints().");
  const described = new Map();
  ENDPOINTS.forEach(function (e) { described.set(e.path, e); });

  const rows = [];
  const undocumented = [];
  registeredRoutes().forEach(function (route) {
    const entry = described.get(route.path);
    if (entry) {
      rows.push(Object.assign({}, entry, { methods: route.methods, documented: true }));
      described.delete(route.path);
      return;
    }
    undocumented.push(route.path);
    rows.push({ path: route.path, methods: route.methods, group: 'Undocumented',
                name: '(undocumented)', specs: [],
                what: 'This route is registered but sts_metadata.js does not describe it.',
                documented: false });
  });
  // Whatever is left was described and is not registered.
  const stale = Array.from(described.keys());
  // Any spec id that no entry references, and any reference to a spec that does
  // not exist. Both are drift in the same table.
  const referenced = new Set();
  rows.forEach(function (r) { (r.specs || []).forEach(function (id) { referenced.add(id); }); });
  const unknownSpecs = Array.from(referenced).filter(function (id) { return !SPEC_BY_ID[id]; });
  log.debug("Leaving describeEndpoints(). " + rows.length + " row(s), " + undocumented.length +
            " undocumented, " + stale.length + " stale.");
  return { rows: rows, undocumented: undocumented, stale: stale, unknownSpecs: unknownSpecs };
}

const GROUP_ORDER = ['Service', 'WS-Trust', 'OAuth 2.0 / OIDC', 'VC Issuance (OID4VCI)',
                     'Decentralized Identifiers', 'VC Presentation (OID4VP)', 'Undocumented'];

function groupsOf(rows) {
  const seen = [];
  GROUP_ORDER.forEach(function (g) {
    if (rows.some(function (r) { return r.group === g; })) seen.push(g);
  });
  rows.forEach(function (r) {
    if (seen.indexOf(r.group) === -1) seen.push(r.group);
  });
  return seen;
}

function esc(v) { return xmlEscape(v == null ? '' : String(v)); }

function specLinks(ids) {
  if (!ids || !ids.length) return '<span class="none">&mdash;</span>';
  return ids.map(function (id) {
    const spec = SPEC_BY_ID[id];
    if (!spec) return '<span class="bad">unknown spec id "' + esc(id) + '"</span>';
    return '<a href="#spec-' + esc(id) + '">' + esc(spec.name.split(' — ')[0].split(' (')[0]) + '</a>';
  }).join(', ');
}

// The page. No script anywhere: the Content-Security-Policy this service sets is
// default-src 'none' with script-src 'none', so an inline <style> is the only
// decoration available — which is all a table needs.
function renderPage(base, report) {
  log.debug("Entering renderPage().");
  const rows = report.rows;
  let html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8" />' +
    '<meta name="viewport" content="width=device-width, initial-scale=1" />' +
    '<title>Mock STS &mdash; endpoints and specifications</title><style>' +
    'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;' +
    'margin:0;padding:2rem;color:#222;background:#fbfbfd;line-height:1.45}' +
    'h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.1rem;margin:2rem 0 .5rem;' +
    'border-bottom:2px solid #12107c;padding-bottom:.25rem;color:#12107c}' +
    'p.lead{margin:.25rem 0 1.5rem;color:#555;max-width:60rem}' +
    'table{border-collapse:collapse;width:100%;margin:0 0 1rem;background:#fff}' +
    'th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.9rem}' +
    'th{background:#f0f0f5}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85rem;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;word-break:break-all}' +
    '.m{font-weight:600;color:#0b6b4f;white-space:nowrap}.none{color:#999}' +
    '.bad{color:#b00020;font-weight:600}.warn{background:#fff8e1;border:1px solid #ffe082;' +
    'padding:.6rem .8rem;margin:.5rem 0;border-radius:4px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:.6rem .8rem;margin:.5rem 0;border-radius:4px}' +
    'td.p{width:22%}td.n{width:18%}td.s{width:16%}dl{margin:0}dt{font-weight:600;margin-top:.75rem}' +
    'dd{margin:.15rem 0 0 0;color:#444}small{color:#666}' +
    '</style></head><body>';

  html += '<h1>Mock Security Token Service</h1>';
  html += '<p class="lead">Every endpoint this service registers and every specification it ' +
    'implements. The endpoint list is read from the running Express router on each request, not ' +
    'from a list kept by hand, so it cannot claim an endpoint that is not there or miss one that ' +
    'is. Issuer identifier <code>' + esc(base) + '</code>; WS-Trust issuer <code>' + esc(ISSUER) +
    '</code>; listening on port ' + esc(PORT) + '.</p>';

  html += '<p class="lead"><strong>This is a test double.</strong> It signs everything with a key ' +
    'generated fresh at each start, it never checks a password, and it does not validate access ' +
    'tokens issued by a separate authorization server. The <em>coverage</em> column below says where ' +
    'each specification is implemented in full and where the shape is right but the enforcement is ' +
    'deliberately absent.</p>';

  // Drift, if any. Shown at the top because it is the thing a reader most needs
  // to know about the rest of the page.
  if (report.undocumented.length || report.stale.length || report.unknownSpecs.length) {
    html += '<div class="warn"><strong>This page is out of step with the router.</strong><ul>';
    if (report.undocumented.length) {
      html += '<li>Registered but not described here: ' +
        report.undocumented.map(function (p) { return '<code>' + esc(p) + '</code>'; }).join(', ') +
        '. They are listed below under <em>Undocumented</em>.</li>';
    }
    if (report.stale.length) {
      html += '<li>Described here but NOT registered: ' +
        report.stale.map(function (p) { return '<code>' + esc(p) + '</code>'; }).join(', ') +
        '. Either the route was renamed or the description is stale.</li>';
    }
    if (report.unknownSpecs.length) {
      html += '<li>Endpoints reference specification ids that do not exist: ' +
        report.unknownSpecs.map(function (i) { return '<code>' + esc(i) + '</code>'; }).join(', ') +
        '.</li>';
    }
    html += '</ul></div>';
  } else {
    html += '<div class="ok">Every registered route is described, and every description matches a ' +
      'registered route (' + rows.length + ' endpoints).</div>';
  }

  groupsOf(rows).forEach(function (group) {
    html += '<h2>' + esc(group) + '</h2><table><thead><tr><th class="p">Path</th>' +
      '<th>Methods</th><th class="n">Name</th><th>What it is</th><th class="s">Specifications</th>' +
      '</tr></thead><tbody>';
    rows.filter(function (r) { return r.group === group; })
      .sort(function (a, b) { return a.path < b.path ? -1 : (a.path > b.path ? 1 : 0); })
      .forEach(function (r) {
        html += '<tr><td class="p"><code>' + esc(r.path) + '</code></td>' +
          '<td class="m">' + esc(r.methods.join(', ')) + '</td>' +
          '<td class="n">' + (r.documented === false ? '<span class="bad">' + esc(r.name) + '</span>'
                                                     : esc(r.name)) + '</td>' +
          '<td>' + esc(r.what) + '</td>' +
          '<td class="s">' + specLinks(r.specs) + '</td></tr>';
      });
    html += '</tbody></table>';
  });

  html += '<h2>Specifications implemented</h2><table><thead><tr><th class="n">Specification</th>' +
    '<th>Published by</th><th>Coverage in this mock</th></tr></thead><tbody>';
  SPECS.forEach(function (s) {
    html += '<tr id="spec-' + esc(s.id) + '"><td class="n"><a href="' + esc(s.url) +
      '" target="_blank" rel="noopener noreferrer">' + esc(s.name) + '</a></td>' +
      '<td>' + esc(s.where) + '</td><td>' + esc(s.coverage) + '</td></tr>';
  });
  html += '</tbody></table>';

  html += '<p><small>Machine-readable: <code>' + esc(base) +
    '/sts-metadata?format=json</code>. This document is not a specification-defined discovery ' +
    'document &mdash; for those, see <code>/.well-known/oauth-authorization-server</code>, ' +
    '<code>/.well-known/openid-credential-issuer</code>, <code>/.well-known/jwt-vc-issuer</code>, ' +
    '<code>/.well-known/did.json</code> and ' +
    '<code>/.well-known/did-configuration.json</code>.</small></p>';
  html += '</body></html>';
  log.debug("Leaving renderPage(). " + html.length + " characters.");
  return html;
}

function metadataJson(base, report) {
  return {
    service: 'idptools mock Security Token Service',
    issuer: base,
    wsTrustIssuer: ISSUER,
    port: PORT,
    testDouble: true,
    endpoints: report.rows.map(function (r) {
      return { path: r.path, methods: r.methods, name: r.name, group: r.group,
               description: r.what, specs: r.specs, documented: r.documented !== false };
    }),
    specifications: SPECS,
    // The drift report is part of the document, not just the page: a test asserts
    // these are empty, which is the only thing that keeps the descriptions honest.
    undocumentedPaths: report.undocumented,
    stalePaths: report.stale,
    unknownSpecIds: report.unknownSpecs
  };
}

app.get('/sts-metadata', function (req, res) {
  log.debug("Entering the STS metadata endpoint.");
  const base = baseUrlOf(req);
  const report = describeEndpoints();
  if (String(req.query.format || '').toLowerCase() === 'json') {
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(metadataJson(base, report), null, 2));
    log.debug("Leaving the STS metadata endpoint. JSON.");
    return;
  }
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(renderPage(base, report));
  log.debug("Leaving the STS metadata endpoint. HTML, " + report.rows.length + " endpoints.");
});

module.exports = {
  SPECS: SPECS,
  ENDPOINTS: ENDPOINTS,
  registeredRoutes: registeredRoutes,
  describeEndpoints: describeEndpoints
};
