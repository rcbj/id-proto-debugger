'use strict';
//
// File: oauth2.js
//
// ===========================================================================
// The endpoints the RFC 8414 metadata advertises.
//
// A dummy authorization server: every endpoint in the metadata document answers,
// and every token it issues is a real RS256 JWT signed with the STS key, so it
// verifies against the JWKS the same document points at (/oauth2/jwks).
//
//   GET  /oauth2/authorize   authorization endpoint (code / implicit / hybrid)
//   POST /oauth2/token       authorization_code, refresh_token, password,
//                            client_credentials, token-exchange
//   *    /oauth2/userinfo    OIDC Core 5.3, on GET and POST — the one protected
//                            endpoint here that verifies the token first
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
//   GET  /oauth2/logout      end_session_endpoint (RP-Initiated Logout)
//   GET  /oauth2/jwks        the signing key (above, with the metadata)
//   GET  /docs /policy /tos  the documents the metadata links to
//
// It authenticates NOBODY: the authorization endpoint issues a code for whoever
// asks (the "user" is the login_hint, or a fixed mock subject), and any client
// secret is accepted. That is the point — it exists so the debugger's panes have
// something complete to talk to, not to enforce anything. What it does do
// properly is the mechanics a client can check: PKCE verification, single-use
// authorization codes, real signatures, honest introspection, and revocation
// that actually takes effect.
// ===========================================================================
//
// It also serves BOTH discovery documents — the RFC 8414 metadata and the OpenID
// Provider Configuration an OIDC client looks for — and the JWKS they advertise,
// because those describe THIS server: the endpoints below are the ones the
// metadata promises, and keeping the promise beside the thing that keeps it is
// what stops the two drifting. The OIDC document is the RFC 8414 one extended, for
// the same reason at one remove: two documents describing one server must not be
// two hand-kept copies of the members they share.
//
// The one place it reaches outside itself is the OID4VCI pre-authorized code
// grant: the codes and the issuer_states are minted by the Credential Offer
// (vc_offers.js) and redeemed here, because redeeming a code is a token endpoint's
// job whatever minted it. That is a one-way dependency — the offer module knows
// nothing about this one.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const app = require('./app');
const { log, logArtifact, STS, baseUrlOf, b64u, jsonFromB64u, nowSec, randomId,
        xmlEscape, parseBody, oauthError, signJwt, userFor } = require('./helpers');
const dpop = require('./dpop');
const { VCI_CONFIGS, VCI_CONFIG_ID, VCI_SCOPE } = require('./vc_configs');
const { deferredAccessTokens, issuerStates, preAuthorizedCodes } = require('./vc_offers');
// ---------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata
//
// A dummy metadata document with EVERY member RFC 8414 section 2 defines
// populated, so the debugger's Configuration Parameters pane can be filled from
// a real endpoint. Served at the well-known path from section 3, and also with
// an issuer path component appended (section 3.1) so both shapes resolve.
//
// The issuer and every endpoint are derived from the URL the request arrived
// on, so the document is self-consistent whether it is reached as
// http://localhost:8081 (host) or http://sts:8081 (compose network).
// ---------------------------------------------------------------------------
function asMetadata(req) {
  log.debug("Entering asMetadata().");
  const base = baseUrlOf(req);
  const metadata = {
    // --- REQUIRED ---
    issuer: base,
    authorization_endpoint: base + '/oauth2/authorize',
    token_endpoint: base + '/oauth2/token',
    // Every combination the authorization endpoint actually issues: it splits
    // response_type on whitespace and accepts any mixture of code, token and
    // id_token, so `id_token token` belongs here too — OpenID Connect Dynamic
    // Registration names it as one an OP should support, and leaving it out of
    // the list while honouring it is the same drift as the reverse.
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token',
                               'id_token token', 'code id_token token'],
    // --- RECOMMENDED / OPTIONAL ---
    jwks_uri: base + '/oauth2/jwks',
    registration_endpoint: base + '/oauth2/register',
    // `address` and `phone` were listed here and are gone: OIDC Core section 5.4
    // makes each of these scopes a request for a NAMED set of claims, and userFor()
    // mints no address and no phone_number, so the two were a promise of claims
    // that could never arrive. It reads as an omission next to the
    // claims_supported list in the OIDC document, which is the whole reason the
    // two documents are built from this one object.
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    // query and fragment only. `form_post` was advertised here and is NOT
    // implemented: redirectBack() answers every authorization request with a 302
    // to the redirect_uri, so a client that asked for form_post would be sent a
    // redirect anyway and would sit waiting for a POST that never arrives. A
    // metadata member is a promise the endpoint has to keep, and the failure of
    // this particular one is silent at the client end, which is the worst kind.
    response_modes_supported: ['query', 'fragment'],
    // Only what the token endpoint below actually implements — the metadata
    // should not promise a grant this server would refuse. (No device_code:
    // there is no device authorization endpoint to start that flow.)
    grant_types_supported: ['authorization_code', 'implicit', 'refresh_token', 'client_credentials',
                            'password', 'urn:ietf:params:oauth:grant-type:token-exchange',
                            // OID4VCI's pre-authorized code grant, which the
                            // cross-device Credential Offers use.
                            'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    // RFC 9396. OID4VCI's other way of saying which credential is wanted:
    // authorization_details of type openid_credential, instead of a scope.
    authorization_details_types_supported: ['openid_credential'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post',
                                            'client_secret_jwt', 'private_key_jwt', 'none'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256', 'PS256', 'HS256'],
    service_documentation: base + '/docs',
    // One locale, because there is one: the login screen is the only UI this
    // server renders and it is written in English, and nothing here reads the
    // ui_locales request parameter. The list used to name four, which a client
    // is entitled to read as "ask for fr-CA and you will get it".
    ui_locales_supported: ['en-US'],
    op_policy_uri: base + '/policy',
    op_tos_uri: base + '/tos',
    revocation_endpoint: base + '/oauth2/revoke',
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    introspection_endpoint: base + '/oauth2/introspect',
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    introspection_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    code_challenge_methods_supported: ['S256', 'plain'],
    // RFC 9207. redirectBack() puts `iss` on every authorization response this
    // server sends, success and error alike, so this is simply true — and it was
    // true and unadvertised, which is the half that buys a client nothing: a
    // client only knows it may REQUIRE the parameter (and so refuse a mix-up
    // attacker's response that lacks it) if the metadata says the server sends it.
    authorization_response_iss_parameter_supported: true,
    // RFC 9449 section 5.1. Its presence is how a wallet learns DPoP is on offer
    // at all — there is no other signal, so an authorization server that supports
    // DPoP and does not advertise it will simply never be asked for it.
    dpop_signing_alg_values_supported: dpop.SIGNING_ALGS
    // signed_metadata is added below — it is a JWT OF this object, so it cannot
    // be one of the claims it signs.
  };
  log.debug("Leaving asMetadata().");
  return metadata;
}

// RFC 8414 section 2.1: signed_metadata is a JWT whose claims are the metadata
// members, signed by the issuer, and carrying iss and sub. Genuinely signed
// with the STS key so it can be verified (public key at /sts/cert, JWKS below).
function signedMetadata(meta) {
  log.debug("Entering signedMetadata().");
  const claims = Object.assign({}, meta, { sub: meta.issuer });
  logArtifact('RFC 8414 signed_metadata', 'before signing', claims);
  try {
    const signed = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.issuer, expiresIn: 3600, keyid: STS.kid });
    logArtifact('RFC 8414 signed_metadata', 'after signing', signed);
    log.debug("Leaving signedMetadata().");
    return signed;
  } catch (e) {
    log.error('signed_metadata: ' + e.message);
    log.debug("Leaving signedMetadata(). Nothing was signed.");
    return undefined;
  }
}

function sendAsMetadata(req, res) {
  log.debug("Entering sendAsMetadata().");
  const meta = asMetadata(req);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendAsMetadata().");
}

app.get('/.well-known/oauth-authorization-server', sendAsMetadata);

// Issuer-with-path form, e.g. /.well-known/oauth-authorization-server/tenant1.
app.get('/.well-known/oauth-authorization-server/*', sendAsMetadata);

// ---------------------------------------------------------------------------
// OpenID Connect Discovery 1.0 — GET /.well-known/openid-configuration
//
// The OTHER discovery document, and the one most OIDC clients look for first:
// a relying party given nothing but an issuer identifier finds this path and
// expects everything it needs to be in what comes back. Without it this server
// spoke OIDC — id_token, nonce, at_hash, c_hash, three flows — and could not be
// CONFIGURED by an OIDC client, which is a strange thing for a mock whose whole
// job is to be pointed at by clients.
//
// **It is built by extending the RFC 8414 document rather than beside it.** The
// two documents describe one server, they overlap in about twenty members, and
// two hand-kept copies of twenty members disagree the first time somebody edits
// one of them — a client configured from openid-configuration would then behave
// differently from one configured from oauth-authorization-server against the
// same endpoints, and nothing would report it. So asMetadata() is the single
// source and this function adds only what OpenID Connect Discovery defines on
// top of it. RFC 8414 was written from this document and the member names are
// the same registry, so the overlap is genuine and not a coincidence worth
// preserving by hand.
//
// What is DELIBERATELY ABSENT, since a discovery document is read as a promise:
//
//   * `acr_values_supported`, `display_values_supported`, the id_token and
//     userinfo ENCRYPTION members, `check_session_iframe`: none are implemented,
//     and an empty or invented value for any of them is worse than the member's
//     absence, which says exactly the right thing.
//   * WebFinger (section 2). Issuer discovery from an e-mail address is a
//     separate endpoint (/.well-known/webfinger) and this service does not have
//     one; the issuer is expected to be known already.
//
// One honesty note that has no metadata member to live in, so it lives here:
// claims_supported below is the exact set idToken() emits, not a menu, and the
// id_token carries all of it whatever scope was asked for. The UserInfo endpoint
// is the one place a scope changes the answer (section 5.4), so the two can
// return different subsets of the same list — which is what that section
// describes rather than a disagreement between them.
// ---------------------------------------------------------------------------
function oidcMetadata(req, issuer) {
  log.debug("Entering oidcMetadata(). issuer=" + (issuer || '(the request base URL)'));
  const base = baseUrlOf(req);
  const metadata = Object.assign(asMetadata(req), {
    // --- REQUIRED by OpenID Connect Discovery 1.0 section 3 -----------------
    // issuer, authorization_endpoint, token_endpoint, jwks_uri and
    // response_types_supported come from the RFC 8414 document above.
    //
    // RECOMMENDED, and here: the section 5.3 UserInfo Endpoint. It is a
    // protected resource, it accepts a Bearer or a DPoP-bound token through the
    // same check as every other protected endpoint in this service, and — unlike
    // them — it verifies the token before answering, because a profile is a
    // statement about somebody this server authenticated.
    userinfo_endpoint: base + '/oauth2/userinfo',
    // Section 5.3.2's signed response, offered because RFC 7591 registration is
    // offered: a client that registers `userinfo_signed_response_alg: "RS256"`
    // gets `application/jwt` back, signed with the same key as everything else.
    // `none` is the default and means the plain JSON of section 5.3.2.
    userinfo_signing_alg_values_supported: ['RS256', 'none'],
    //
    // `public`: the `sub` userFor() mints is urn:sts-mock:user:<username> and is
    // the same value for every client that asks, which is what public MEANS.
    // Claiming `pairwise` would be a claim about a calculation this server does
    // not perform.
    subject_types_supported: ['public'],
    // Every JWT this service signs goes through signJwt(), which is RS256 and
    // only RS256. The id_token is not encrypted, so there is no *_enc member.
    id_token_signing_alg_values_supported: ['RS256'],

    // --- RECOMMENDED / OPTIONAL, and true of this server --------------------
    // Exactly what idToken() puts in the token, in the order it puts it there.
    // A client can read this list and know that asking for anything else — an
    // address, a phone number, an acr — gets it nothing.
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'auth_time', 'nonce', 'azp',
                       'jti', 'at_hash', 'c_hash', 'name', 'given_name', 'family_name',
                       'preferred_username', 'email', 'email_verified'],
    claim_types_supported: ['normal'],
    // Three parameters this server reads and three it does not, stated as the
    // booleans the specification defines rather than left to a client to
    // discover by sending one and watching it be ignored. The authorization
    // endpoint honours prompt=none and prompt=login (and nothing else), and it
    // does not accept a `claims` parameter, a `request` object or a `request_uri`
    // — which is the same "no request object here" the /sts-metadata coverage
    // note already says in prose.
    prompt_values_supported: ['none', 'login'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    // Moot while request_uri_parameter_supported is false, and stated anyway:
    // the member's default is true, so leaving it out would have this server
    // promising to enforce a registration requirement it has no code for.
    require_request_uri_registration: false,
    // OpenID Connect RP-Initiated Logout 1.0. /oauth2/logout drops the session
    // cookie and returns to post_logout_redirect_uri — but it neither requires
    // nor checks id_token_hint, and it does not validate the redirect target
    // against anything, so this is the shape of RP-initiated logout rather than
    // its security. It is advertised because the alternative is a client with no
    // way to end a session that this server really does end.
    end_session_endpoint: base + '/oauth2/logout',
    // Neither logout notification specification is implemented: no front-channel
    // iframe is rendered and no back-channel POST is sent. Both members default
    // to false, and both are stated because "the OP did not mention it" and "the
    // OP said no" read identically to a client and only one of them is a fact
    // this server is prepared to stand behind.
    frontchannel_logout_supported: false,
    backchannel_logout_supported: false
  });
  // The path-appended form's issuer (see below). Assigned after the merge so it
  // replaces the base URL asMetadata() derived, and assigned rather than merged
  // so the member keeps its position at the top of the document.
  if (issuer) metadata.issuer = issuer;
  log.debug("Leaving oidcMetadata(). " + Object.keys(metadata).length + " member(s).");
  return metadata;
}

// signed_metadata is an RFC 8414 member and OpenID Connect Discovery does not
// define it. It is included anyway: the two documents share one member registry,
// an OIDC client ignores members it does not know, and a signed copy of THIS
// document — the OIDC members included — is the only way to check that what
// arrived is what the issuer published.
function sendOidcMetadata(req, res, issuer) {
  log.debug("Entering sendOidcMetadata().");
  const meta = oidcMetadata(req, issuer);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendOidcMetadata().");
}

app.get('/.well-known/openid-configuration', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint.");
  sendOidcMetadata(req, res);
  log.debug("Leaving the OpenID Connect Discovery endpoint.");
});

// ---------------------------------------------------------------------------
// An issuer identifier with a path component, which the two specifications
// resolve to two DIFFERENT URLs — the single most common reason a discovery
// fetch 404s, so both are served.
//
//   OpenID Connect Discovery 1.0 section 4  APPENDS:  https://host/tenant1/.well-known/openid-configuration
//   RFC 8414 section 3.1                    INSERTS:  https://host/.well-known/openid-configuration/tenant1
//
// The appended form gets the issuer it was asked for, built back up from the path
// the request arrived on: that shape exists precisely so a multi-tenant server can
// answer for one tenant, and a document at /tenant1/... claiming to be issued by
// https://host is one a conforming client MUST reject (the issuer has to match the
// one the URL was built from). The endpoints inside it stay where they really are,
// since nothing requires them to live under the issuer.
//
// The inserted form is the RFC 8414 shape and is answered the way the
// oauth-authorization-server route above answers it — with the request's base URL
// as the issuer — so the two behave alike.
// ---------------------------------------------------------------------------
app.get('/.well-known/openid-configuration/*', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint (RFC 8414 inserted-path form).");
  sendOidcMetadata(req, res);
  log.debug("Leaving the OpenID Connect Discovery endpoint (RFC 8414 inserted-path form).");
});

app.get('/*/.well-known/openid-configuration', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint (issuer-path form).");
  // req.params[0] is everything before /.well-known — the issuer's path
  // component, one segment or several.
  const path = String(req.params[0] || '').replace(/^\/+|\/+$/g, '');
  sendOidcMetadata(req, res, baseUrlOf(req) + (path ? '/' + path : ''));
  log.debug("Leaving the OpenID Connect Discovery endpoint (issuer-path form). path=" + path);
});

// The JWKS the metadata advertises, so jwks_uri actually resolves: the STS
// signing key as a single RS256 JWK.
app.get('/oauth2/jwks', function (req, res) {
  log.debug("Entering the JWKS endpoint.");
  try {
    const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
    const b64u = function (hex) {
      return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
      keys: [{
        kty: 'RSA', use: 'sig', alg: 'RS256', kid: STS.kid,
        n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
        x5c: [STS.certB64]
      }]
    }, null, 2));
    log.debug("Leaving the JWKS endpoint.");
  } catch (e) {
    log.error('could not publish the JWKS: ' + e.message);
    res.status(500).type('application/json').send(JSON.stringify({ error: e.message }));
    log.debug("Leaving the JWKS endpoint. It failed.");
  }
});

const SESSION_COOKIE = 'sts_mock_session';

const SESSION_TTL_MS = 60 * 60 * 1000;

const LOGIN_TTL_MS = 10 * 60 * 1000;

const ACCESS_TOKEN_TTL = 3600;

const REFRESH_TOKEN_TTL = 30 * 24 * 3600;

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const authzCodes = new Map();       // code -> the authorization request it came from

const sessions = new Map();         // session id -> the signed-in user

const pendingLogins = new Map();    // login id -> the authorization request being interrupted

const revokedJtis = new Set();      // tokens revoked via /oauth2/revoke

const registeredClients = new Map();// client_id -> { metadata, registrationAccessToken }

// Client credentials from either client_secret_basic or client_secret_post. No
// secret is ever checked; what matters is which client is being claimed.
function clientFrom(req, body) {
  log.debug("Entering clientFrom().");
  const auth = req.headers['authorization'] || '';
  if (/^Basic\s+/i.test(auth)) {
    try {
      const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      const client = { client_id: decodeURIComponent(i < 0 ? decoded : decoded.slice(0, i)) };
      log.debug("Leaving clientFrom(). client_secret_basic named " + client.client_id + ".");
      return client;
    } catch (e) {
      log.error('could not read the Basic credential: ' + e.message);
      // Fall through to the form parameter.
    }
  }
  log.debug("Leaving clientFrom(). client_id from the body: " + (body.client_id || '(none)'));
  return { client_id: body.client_id || '' };
}

function accessToken(base, opts) {
  log.debug("Entering accessToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.audience || base + '/resource',
    client_id: opts.client_id, scope: opts.scope || '', typ: 'Bearer',
    jti: randomId(16), iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL,
    username: user.username
  };
  if (opts.act) payload.act = opts.act;
  // RFC 9449 section 6.1: a DPoP-bound access token names the key it is bound to
  // in the `cnf.jkt` confirmation claim (RFC 7800's `cnf`, with RFC 9449's `jkt`
  // member). The claim travels INSIDE the signed token, which is what lets a
  // resource server check the binding without asking the authorization server
  // anything — and what stops the wallet nominating its own key.
  if (opts.jkt) payload.cnf = { jkt: opts.jkt };
  // OID4VCI section 6.2: when the authorization was expressed as
  // authorization_details, the token response grants credential_identifiers and
  // the Credential Request must use one of them. They ride in the access token
  // so the credential endpoint can verify one without consulting any state — the
  // token is signed, so the wallet cannot award itself an identifier.
  if (opts.authorization_details) payload.authorization_details = opts.authorization_details;
  const token = signJwt(payload);
  log.debug("Leaving accessToken().");
  return token;
}

function refreshToken(base, opts) {
  log.debug("Entering refreshToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const token = signJwt({
    // username travels with the refresh token, so refreshing keeps describing
    // the person who actually signed in.
    iss: base, sub: opts.sub || user.sub, aud: base, client_id: opts.client_id,
    scope: opts.scope || '', typ: 'Refresh', jti: randomId(16), username: user.username,
    iat: iat, nbf: iat, exp: iat + REFRESH_TOKEN_TTL,
    // RFC 9449 section 5: a refresh token issued to a PUBLIC client alongside a
    // DPoP-bound access token is itself bound to the same key. A wallet is a
    // public client and cannot authenticate, so without this the long-lived half
    // of the grant would stay a bearer credential and binding the short-lived
    // half would buy very little. The refresh grant enforces it, which is what
    // makes the OID4VCI section 14.5 refresh on step 4 carry a proof of its own.
    cnf: opts.jkt ? { jkt: opts.jkt } : undefined
  });
  log.debug("Leaving refreshToken().");
  return token;
}

// OIDC section 3.1.3.6: at_hash / c_hash are the base64url of the left half of
// the SHA-256 of the ASCII of the token.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const h = crypto.createHash('sha256').update(String(value), 'ascii').digest();
  log.debug("Leaving halfHash().");
  return b64u(h.subarray(0, h.length / 2));
}

function idToken(base, opts) {
  log.debug("Entering idToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.client_id, typ: 'ID',
    iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL, auth_time: opts.auth_time || iat,
    azp: opts.client_id, jti: randomId(16),
    name: user.name, given_name: user.given_name, family_name: user.family_name,
    preferred_username: user.preferred_username, email: user.email,
    email_verified: user.email_verified
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.access_token) payload.at_hash = halfHash(opts.access_token);
  if (opts.code) payload.c_hash = halfHash(opts.code);
  const token = signJwt(payload);
  log.debug("Leaving idToken().");
  return token;
}

function hasScope(scope, name) {
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

function tokenSet(base, opts) {
  log.debug("Entering tokenSet(). scope=" + (opts.scope || '(none)'));
  const access = accessToken(base, opts);
  const body = {
    access_token: access,
    // RFC 9449 section 5: `DPoP`, not `Bearer`, when the token is bound. This is
    // how the wallet learns it must send a proof on every subsequent call — a
    // bound token announced as Bearer would be presented as one and refused.
    token_type: opts.jkt ? 'DPoP' : 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: opts.scope || ''
  };
  if (opts.authorization_details) body.authorization_details = opts.authorization_details;
  if (opts.withRefresh !== false) body.refresh_token = refreshToken(base, opts);
  if (hasScope(opts.scope, 'openid')) {
    body.id_token = idToken(base, Object.assign({}, opts, { access_token: access }));
  }
  log.debug("Leaving tokenSet(). Issued: " + Object.keys(body).join(', '));
  return body;
}

// --- authorization endpoint + login screen ----------------------------------
// A browser flow, so it behaves like one: an unauthenticated request is shown a
// login screen, and only once the user has signed in does the endpoint issue
// the authorization code (or the implicit/hybrid tokens) and redirect back to
// the client.
//
//   GET  /oauth2/authorize   no session  -> the login screen
//                            session     -> issue and redirect to redirect_uri
//   POST /oauth2/login       signs the user in, then redirects BACK to
//                            /oauth2/authorize with the original request, which
//                            then proceeds as normal
//
// No password is checked — the username typed in is simply who the tokens then
// describe. A session cookie means the next authorization request does not
// prompt again; prompt=login forces it to.
function cookiesOf(req) {
  log.debug("Entering cookiesOf().");
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (part) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  log.debug("Leaving cookiesOf(). " + Object.keys(out).length + " cookie(s).");
  return out;
}

function sessionOf(req) {
  log.debug("Entering sessionOf().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) {
    log.debug("Leaving sessionOf(). No session cookie.");
    return null;
  }
  const session = sessions.get(id);
  if (!session) {
    log.debug("Leaving sessionOf(). The cookie names no session this server knows.");
    return null;
  }
  if (session.expires < Date.now()) {
    sessions.delete(id);
    log.debug("Leaving sessionOf(). The session had expired and was discarded.");
    return null;
  }
  log.debug("Leaving sessionOf(). Signed in as " + session.user.username + ".");
  return session;
}

// The authorization request, as the query string it arrived as. Kept whole so
// the redirect back after login is the same request over again.
function queryString(query, omit) {
  log.debug("Entering queryString().");
  const usp = new URLSearchParams();
  Object.keys(query).forEach(function (k) {
    if (omit && omit.indexOf(k) >= 0) return;
    usp.set(k, query[k]);
  });
  log.debug("Leaving queryString().");
  return usp.toString();
}

function loginPage(base, login, error) {
  log.debug("Entering loginPage(). client_id=" + (login.query.client_id || '(none)') +
            (error ? ", showing an error" : ""));
  const q = login.query;
  const scope = q.scope || '(none requested)';
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Sign in — mock authorization server</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:28px 32px;width:380px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}label{display:block;font-size:.85em;font-weight:600;' +
    'margin:12px 0 4px}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;' +
    'border:1px solid #bbb;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:20px}' +
    'button{flex:1;padding:9px 12px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
    'font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px 0}code{font-family:ui-monospace,' +
    'SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Sign in</h1>' +
    '<p class="sub">Mock authorization server at <code>' + xmlEscape(base) + '</code></p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<form method="post" action="/oauth2/login">' +
    '<input type="hidden" name="login_id" value="' + xmlEscape(login.id) + '">' +
    '<label for="username">Username</label>' +
    '<input type="text" id="username" name="username" autocomplete="username" autofocus' +
    ' value="' + xmlEscape(q.login_hint || '') + '">' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="current-password">' +
    '<div class="row"><button type="submit" id="kc-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="kc-cancel" name="action" value="cancel" class="secondary">Cancel</button></div>' +
    '</form><div class="meta">' +
    '<div>No password is checked. The username you enter is the identity the issued tokens describe.</div>' +
    '<div>client_id: <code>' + xmlEscape(q.client_id || '') + '</code></div>' +
    '<div>scope: <code>' + xmlEscape(scope) + '</code></div>' +
    '<div>redirect_uri: <code>' + xmlEscape(q.redirect_uri || '') + '</code></div>' +
    (q.issuer_state
      ? '<div>issuer_state: <code>' + xmlEscape(q.issuer_state) + '</code>' +
        (issuerStates.has(String(q.issuer_state)) ? ' (from a Credential Offer this issuer made)' : '') +
        '</div>'
      : '') +
    '</div></div></body></html>\n';
  log.debug("Leaving loginPage().");
  return page;
}

// Build the authorization response for a signed-in user and redirect back to
// the client. Everything after authentication — which is "as normal".
// authorization_details (RFC 9396) as OID4VCI uses it: an array of objects of
// type openid_credential, each naming a credential_configuration_id. Unreadable
// JSON is not silently dropped — a wallet that sent nonsense should be told.
function parseAuthorizationDetails(raw) {
  log.debug("Entering parseAuthorizationDetails().");
  if (!raw) {
    log.debug("Leaving parseAuthorizationDetails(). None were sent.");
    return { details: null };
  }
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch (e) {
    log.debug("Leaving parseAuthorizationDetails(). Not JSON: " + e.message);
    return { error: 'authorization_details is not readable JSON: ' + e.message };
  }
  if (!Array.isArray(parsed)) {
    log.debug("Leaving parseAuthorizationDetails(). Not an array.");
    return { error: 'authorization_details must be a JSON array.' };
  }
  const wanted = [];
  for (let i = 0; i < parsed.length; i++) {
    const d = parsed[i] || {};
    if (d.type !== 'openid_credential') {
      log.debug("Leaving parseAuthorizationDetails(). Unsupported type: " + d.type);
      return { error: 'authorization_details type "' + d.type + '" is not supported; ' +
                      'this issuer understands openid_credential.' };
    }
    const configId = d.credential_configuration_id;
    if (configId && !VCI_CONFIGS[configId]) {
      log.debug("Leaving parseAuthorizationDetails(). Unknown configuration: " + configId);
      return { error: 'credential_configuration_id "' + configId + '" is not one this issuer offers.' };
    }
    wanted.push({ type: 'openid_credential', credential_configuration_id: configId || VCI_CONFIG_ID });
  }
  log.debug("Leaving parseAuthorizationDetails(). " + wanted.length + " detail(s).");
  return { details: wanted.length ? wanted : null };
}

function issueAuthorizationResponse(req, res, query, user, authTime) {
  log.debug("Entering issueAuthorizationResponse(). response_type=" + (query.response_type || '(none)') +
            ", user=" + user.username);
  const base = baseUrlOf(req);
  const redirectUri = String(query.redirect_uri);
  const types = String(query.response_type || '').split(/\s+/).filter(Boolean);
  const scope = String(query.scope || 'openid');
  const out = {};
  const parsedDetails = parseAuthorizationDetails(query.authorization_details);
  if (parsedDetails.error) {
    log.debug("Leaving issueAuthorizationResponse(). " + parsedDetails.error);
    return redirectBack(res, base, redirectUri, query.state,
      { error: 'invalid_authorization_details', error_description: parsedDetails.error },
      types.length > 1 || types.indexOf('code') < 0);
  }
  const authorizationDetails = parsedDetails.details;
  if (authorizationDetails) {
    logArtifact('authorization_details', 'as requested', authorizationDetails);
  }

  if (types.indexOf('code') >= 0) {
    const code = randomId(24);
    authzCodes.set(code, {
      client_id: String(query.client_id), redirect_uri: redirectUri, scope: scope,
      nonce: query.nonce, user: user, auth_time: authTime,
      code_challenge: query.code_challenge, code_challenge_method: query.code_challenge_method || 'plain',
      // RFC 9449 section 10: the JWK Thumbprint of the DPoP key the client
      // intends to use, taken at the authorization request so the code itself is
      // bound. Stored verbatim and never derived — the whole value of the
      // parameter is that it was fixed BEFORE the code existed.
      dpop_jkt: query.dpop_jkt ? String(query.dpop_jkt) : '',
      // What the wallet asked to be authorized for, if it used
      // authorization_details rather than a scope. The token response has to
      // echo it back with the credential_identifiers it grants.
      authorization_details: authorizationDetails,
      expires: Date.now() + AUTH_CODE_TTL_MS
    });
    out.code = code;
  }
  if (types.indexOf('token') >= 0) {
    out.access_token = accessToken(base, { user: user, client_id: String(query.client_id), scope: scope });
    out.token_type = 'Bearer';
    out.expires_in = ACCESS_TOKEN_TTL;
    out.scope = scope;
  }
  if (types.indexOf('id_token') >= 0) {
    out.id_token = idToken(base, {
      user: user, client_id: String(query.client_id), nonce: query.nonce, auth_time: authTime,
      access_token: out.access_token, code: out.code
    });
  }
  // Only a bare code goes in the query; anything carrying a token uses the
  // fragment, per OAuth 2.0 / OIDC.
  logArtifact('Authorization response', 'as returned to the client', out);
  redirectBack(res, base, redirectUri, query.state, out,
    types.length > 1 || types.indexOf('code') < 0);
  log.debug("Leaving issueAuthorizationResponse().");
}

function redirectBack(res, base, redirectUri, state, params, fragment) {
  log.debug("Entering redirectBack(). fragment=" + !!fragment);
  const usp = new URLSearchParams();
  Object.keys(params).forEach(function (k) { if (params[k] !== undefined) usp.set(k, params[k]); });
  if (state !== undefined) usp.set('state', state);
  usp.set('iss', base);
  const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
  res.redirect(302, redirectUri + sep + usp.toString());
  log.debug("Leaving redirectBack().");
}

app.get('/oauth2/authorize', function (req, res) {
  log.debug("Entering the authorization endpoint.");
  const base = baseUrlOf(req);
  const q = req.query || {};
  const redirectUri = String(q.redirect_uri || '');

  // Without a usable redirect_uri there is nowhere to report an error TO, so it
  // is reported here instead (OAuth 2.0 section 4.1.2.1).
  if (!redirectUri || !/^https?:\/\//i.test(redirectUri)) {
    log.debug("Leaving the authorization endpoint. There is no usable redirect_uri to report to.");
    return oauthError(res, 400, 'invalid_request', 'A valid absolute redirect_uri is required.');
  }
  const fail = function (error, description) {
    log.debug("Leaving the authorization endpoint. Reporting " + error + " to the client.");
    redirectBack(res, base, redirectUri, q.state, { error: error, error_description: description }, false);
  };
  if (!q.client_id) return fail('invalid_request', 'client_id is required.');
  const types = String(q.response_type || '').split(/\s+/).filter(Boolean);
  const known = ['code', 'token', 'id_token'];
  if (!types.length || types.some(function (t) { return known.indexOf(t) < 0; })) {
    return fail('unsupported_response_type', 'response_type "' + (q.response_type || '') + '" is not supported.');
  }

  // issuer_state (OID4VCI section 4.1.1): if this request came from a Credential
  // Offer this server issued, say so — it is what ties the authorization request
  // back to the offer, and seeing it arrive is most of its debugging value.
  if (q.issuer_state) {
    const known = issuerStates.get(String(q.issuer_state));
    if (known && known.expires >= Date.now()) {
      log.debug("The authorization request carries an issuer_state from a Credential Offer this issuer made" +
                " (credential_configuration_ids=" + (known.configurationIds || []).join(', ') + ").");
    } else {
      log.debug("The authorization request carries an issuer_state this issuer does not recognise: " +
                q.issuer_state);
    }
  }

  // Already signed in? Then this is the second pass — after the login screen,
  // or a later request on the same session — and the response goes out now.
  const session = sessionOf(req);
  const forcePrompt = String(q.prompt || '').split(/\s+/).indexOf('login') >= 0;
  if (session && !forcePrompt) {
    log.debug("Leaving the authorization endpoint. The session stands, so the response goes out now.");
    return issueAuthorizationResponse(req, res, q, session.user, session.authTime);
  }
  if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
    // OIDC: prompt=none must not show any UI.
    return fail('login_required', 'No session, and prompt=none forbids showing the login screen.');
  }

  // Otherwise: authenticate the user first. The request is stashed so the login
  // POST can send the browser back to it unchanged.
  const login = {
    id: randomId(18),
    query: JSON.parse(JSON.stringify(q)),
    expires: Date.now() + LOGIN_TTL_MS
  };
  pendingLogins.set(login.id, login);
  pendingLogins.forEach(function (v, k) { if (v.expires < Date.now()) pendingLogins.delete(k); });
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(loginPage(base, login, ''));
  log.debug("Leaving the authorization endpoint. Showing the login screen first.");
});

app.post('/oauth2/login', function (req, res) {
  log.debug("Entering the login endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const login = pendingLogins.get(String(body.login_id || ''));
  if (!login || login.expires < Date.now()) {
    pendingLogins.delete(String(body.login_id || ''));
    log.debug("Leaving the login endpoint. The form had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This login form has expired. Start the authorization request again.');
  }
  const redirectUri = String(login.query.redirect_uri);

  if (String(body.action || '') === 'cancel') {
    pendingLogins.delete(login.id);
    log.debug("Leaving the login endpoint. The user cancelled.");
    return redirectBack(res, base, redirectUri, login.query.state,
      { error: 'access_denied', error_description: 'The user cancelled at the login screen.' }, false);
  }

  const username = String(body.username || '').trim();
  // The only two ways to fail: no username to put in the tokens, and the
  // reserved password the rest of this mock also refuses.
  if (!username) {
    log.debug("Leaving the login endpoint. No username was entered, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Enter a username. It does not have to exist — it is the identity the ' +
                                  'issued tokens will describe.'));
  }
  if (String(body.password || '') === 'invalid') {
    log.debug("Leaving the login endpoint. The reserved password was used, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Authentication failed for ' + username + '.'));
  }

  pendingLogins.delete(login.id);
  const sessionId = randomId(24);
  sessions.set(sessionId, {
    user: userFor(username), authTime: nowSec(), expires: Date.now() + SESSION_TTL_MS
  });
  res.set('Set-Cookie', SESSION_COOKIE + '=' + sessionId + '; Path=/; HttpOnly; SameSite=Lax');

  // Back to the authorization endpoint with the original request — minus
  // prompt, which has now been honoured and would otherwise prompt forever.
  res.redirect(302, base + '/oauth2/authorize?' + queryString(login.query, ['prompt']));
  log.debug("Leaving the login endpoint. " + username + " is signed in; back to the authorization endpoint.");
});

// Ends the session, so the next authorization request prompts again.
app.get('/oauth2/logout', function (req, res) {
  log.debug("Entering the logout endpoint.");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (id) sessions.delete(id);
  res.set('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0');
  const target = req.query.post_logout_redirect_uri;
  if (target && /^https?:\/\//i.test(String(target))) {
    log.debug("Leaving the logout endpoint. Redirecting to " + target + ".");
    return res.redirect(302, String(target));
  }
  res.status(200).type('text/plain').send('Signed out of the mock authorization server.\n');
  log.debug("Leaving the logout endpoint.");
});

// ---------------------------------------------------------------------------
// OpenID Connect Core 1.0 section 5.3 — the UserInfo Endpoint.
//
// A protected resource: present the access token from an OIDC flow and get back
// the claims about the person it was issued for. GET and POST both, because
// section 5.3.1 requires both, and the token comes from the Authorization header
// only — RFC 6750 section 2.3's query-parameter form is NOT RECOMMENDED by its
// own specification, leaks the token into logs and referrers, and could not carry
// a DPoP-bound token in any case.
//
// **This is the one protected endpoint here that refuses a token it did not
// issue, and the exception is the point rather than an inconsistency.** The
// Credential, Deferred Credential and Notification endpoints accept a foreign
// token because OID4VCI lets the authorization server be somebody else, so
// refusing one would break the flow this mock exists to exercise. UserInfo is
// defined the other way round: it answers "who did YOU authenticate", and about
// the subject of a signature it cannot check this server knows nothing at all. A
// mock that made up a profile for an unverifiable token would be teaching the
// wrong lesson to the client reading its output — and it is also what makes
// `cnf.jkt` mean something here, since the binding is only real on a token whose
// signature was checked first.
//
// So four things are checked, and each has a distinct answer so a client can tell
// them apart:
//
//   * the signature, issuer and expiry (401 invalid_token, with the reason — an
//     expired token and a forged one are different problems and "invalid_token"
//     alone sends people looking in the wrong place)
//   * `typ`, so a refresh token or an id_token presented here is refused rather
//     than quietly answered. They are all RS256 JWTs from the same key, so
//     nothing but this claim distinguishes them
//   * revocation, because /oauth2/revoke has to mean the same thing at every
//     endpoint that reads a token — introspection reporting `active: false`
//     while UserInfo still answers would make revocation decorative
//   * the `openid` scope (403 insufficient_scope), which is what a token from the
//     client_credentials or token-exchange grant lacks: those have no end-user,
//     and there is no profile to return for a token that never described one
//
// Scope gating, and why the id_token does NOT do the same. Section 5.4 makes
// `profile` and `email` requests for a named set of claims AT THIS ENDPOINT, so
// this is one place in this mock where a scope genuinely changes the answer, and
// that is worth being able to watch. The id_token still carries everything
// whatever was asked for, which the same section permits — the claims go in the
// id_token when there is no access token to fetch them with — and it is also the
// only behaviour that can serve the implicit flow this server offers.
// ---------------------------------------------------------------------------

// Which claims each scope asks for (section 5.4), restricted to the ones
// userFor() actually mints — `address` and `phone` are not in scopes_supported
// for exactly that reason, so they are not here either.
const USERINFO_SCOPE_CLAIMS = {
  profile: ['name', 'given_name', 'family_name', 'preferred_username'],
  email: ['email', 'email_verified']
};

// The reason a token failed to verify, in the words a person debugging it needs.
// jwt.verify() throws one of a small set of named errors and the distinction
// between them is the whole diagnosis, so it is not collapsed into "invalid".
function tokenFailure(token) {
  log.debug("Entering tokenFailure().");
  try {
    jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
    log.debug("Leaving tokenFailure(). It verifies after all.");
    return '';
  } catch (e) {
    let why;
    if (e.name === 'TokenExpiredError') {
      why = 'This access token expired at ' + new Date(e.expiredAt).toISOString() + '.';
    } else if (e.name === 'NotBeforeError') {
      why = 'This access token is not valid yet (nbf is in the future).';
    } else {
      // Everything else — a bad signature, a token from another issuer, an
      // opaque string that is not a JWT at all. They are one answer because the
      // server genuinely cannot tell them apart, and saying so is honest.
      why = 'This access token was not issued by this server, or its signature does not verify ' +
            'against the key at /oauth2/jwks (' + e.message + '). Unlike the OID4VCI credential ' +
            'endpoints, UserInfo cannot accept a token from a separate authorization server: it ' +
            'has nothing to say about a subject it did not authenticate.';
    }
    log.debug("Leaving tokenFailure(). " + e.name);
    return why;
  }
}

function userinfoResponse(req, res) {
  log.debug("Entering userinfoResponse(). method=" + req.method);
  const base = baseUrlOf(req);

  // The Bearer/DPoP check every protected endpoint in this service shares. It
  // answers the request itself and returns null when the token is missing, is
  // bound and presented as Bearer, or comes with a proof that does not hold up.
  const presented = dpop.presentedAccessToken(req, res, 'the userinfo endpoint');
  if (!presented) {
    log.debug("Leaving userinfoResponse(). No usable access token was presented.");
    return;
  }

  // RFC 6750 section 3: a 401 from a protected resource carries a challenge
  // naming the scheme, and 403 insufficient_scope names the scope that was
  // missing. Without them a client is told it failed but not what to change.
  //
  // The description goes out twice — in the header and in the JSON body — and
  // the header copy has to be cut down to ASCII first. An HTTP field value is
  // ASCII (RFC 9110 section 5.5), node's setHeader THROWS on anything else
  // rather than mangling it, and the descriptions in this file are prose written
  // with em dashes and curly quotes like every other comment here. The first one
  // that reached the header turned a 401 into a 500 — which is the worst place
  // in the service to have one, because the exception replaces the very message
  // that was explaining what went wrong. Quotes go too: they would close the
  // quoted-string early. The body keeps the real text; JSON is UTF-8.
  const headerSafe = function (text) {
    return String(text)
      .replace(/[‘’]/g, "'").replace(/[“”]/g, "'")
      .replace(/[–—]/g, '-').replace(/…/g, '...')
      .replace(/"/g, "'")
      .replace(/[^\x20-\x7E]/g, '');
  };
  const challenge = function (status, error, description, extra) {
    const scheme = presented.scheme === 'dpop' ? 'DPoP' : 'Bearer';
    res.set('WWW-Authenticate', scheme + ' error="' + error + '", error_description="' +
            headerSafe(description) + '"' + (extra || ''));
    log.debug("Leaving userinfoResponse(). " + error + ".");
    return oauthError(res, status, error, description);
  };

  if (!presented.verified) {
    return challenge(401, 'invalid_token', tokenFailure(presented.accessToken));
  }
  const claims = presented.claims || {};
  if (claims.typ !== 'Bearer') {
    return challenge(401, 'invalid_token',
      'This is a "' + (claims.typ || 'unknown') + '" token, not an access token. Every token this ' +
      'server issues is an RS256 JWT signed with the same key, so the typ claim is the only thing ' +
      'that tells a refresh token or an id_token apart from the access token UserInfo needs.');
  }
  if (claims.jti && revokedJtis.has(claims.jti)) {
    return challenge(401, 'invalid_token',
      'This access token was revoked at /oauth2/revoke. Introspection reports it inactive, and ' +
      'UserInfo answers the same way — a revocation that only some endpoints honoured would be ' +
      'worse than none.');
  }
  if (!hasScope(claims.scope, 'openid')) {
    return challenge(403, 'insufficient_scope',
      'UserInfo needs an access token issued with the "openid" scope; this one was issued with ' +
      (claims.scope ? '"' + claims.scope + '"' : 'no scope at all') + '. A client_credentials or ' +
      'token-exchange token has no end-user behind it, so there is no profile to return.',
      ', scope="openid"');
  }

  // Who the token was issued for. `sub` comes from the token rather than from
  // userFor(), because section 5.3.2 requires the sub here to be the one the
  // client saw in the id_token and the token is the record of what that was; the
  // rest is rebuilt from the username that travels with it.
  const user = userFor(claims.username);
  const body = { sub: claims.sub || user.sub };
  Object.keys(USERINFO_SCOPE_CLAIMS).forEach(function (scope) {
    if (!hasScope(claims.scope, scope)) return;
    USERINFO_SCOPE_CLAIMS[scope].forEach(function (name) { body[name] = user[name]; });
  });
  logArtifact('UserInfo response', 'as returned', body);

  // Section 5.3.2: the response is JSON unless the client registered a
  // `userinfo_signed_response_alg`, in which case it is a JWT of the same claims
  // with `iss` and `aud` added — the two members that make a signed response
  // worth having, since without them it could be replayed to another client.
  // This is read from the RFC 7591 registration the client already did here, so
  // the two features meet where they should: register asking for a signed
  // response and this endpoint starts signing for that client.
  const registered = registeredClients.get(String(claims.client_id || '')) || {};
  const alg = String(registered.userinfo_signed_response_alg || 'none');
  if (alg !== 'none') {
    if (alg !== 'RS256') {
      // Refused rather than downgraded to JSON: silently ignoring the algorithm
      // a client registered would leave it verifying a signature that is not
      // there, and this key signs RS256 only.
      log.debug("Leaving userinfoResponse(). The client registered an alg this server cannot sign.");
      return oauthError(res, 500, 'server_error',
        'This client registered userinfo_signed_response_alg="' + alg + '", and this server signs ' +
        'RS256 only (see userinfo_signing_alg_values_supported).');
    }
    const signed = signJwt(Object.assign({ iss: base, aud: claims.client_id, typ: 'UserInfo' }, body));
    res.status(200).type('application/jwt').set('Cache-Control', 'no-store').send(signed);
    log.debug("Leaving userinfoResponse(). A signed UserInfo response for " + body.sub + ".");
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving userinfoResponse(). " + Object.keys(body).length + " claim(s) for " + body.sub + ".");
}

app.get('/oauth2/userinfo', userinfoResponse);

app.post('/oauth2/userinfo', userinfoResponse);

// --- token endpoint ---------------------------------------------------------
// ---------------------------------------------------------------------------
// NON-SPEC: the DPoP nonce switch.
//
// RFC 9449 sections 8 and 9 let a server demand a server-supplied nonce in every
// proof, which turns the first request of a session into a 401/retry handshake.
// Whether to do that is a deployment's choice, and both answers are worth being
// able to try — a wallet that handles the happy path but not the handshake is a
// wallet that works until it meets a server that asks.
//
// So it is a runtime switch rather than configuration: a test, or somebody
// reading the page, can turn it on, watch the retry, and turn it off again
// without restarting the service. GET reports; POST {"required": true|false}
// sets. Listed on /sts-metadata as non-spec, because it is.
// ---------------------------------------------------------------------------
app.get('/dpop/nonce-mode', function (req, res) {
  log.debug("Entering the DPoP nonce-mode endpoint (read).");
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
    .send(JSON.stringify(dpop.state(), null, 2));
  log.debug("Leaving the DPoP nonce-mode endpoint (read).");
});

app.post('/dpop/nonce-mode', function (req, res) {
  log.debug("Entering the DPoP nonce-mode endpoint (write).");
  const body = parseBody(req);
  // Only an explicit boolean, so a typo cannot silently leave the switch in a
  // state nobody chose: a test that means to turn nonces OFF and leaves them on
  // makes every later section in the run fail for an invisible reason.
  const wanted = body.required;
  if (wanted !== true && wanted !== false && wanted !== 'true' && wanted !== 'false') {
    log.debug("Leaving the DPoP nonce-mode endpoint. Refused.");
    return oauthError(res, 400, 'invalid_request',
      'Send {"required": true} or {"required": false}.');
  }
  dpop.setNonceMode(wanted === true || wanted === 'true');
  // A change of policy invalidates nothing already issued, but the replay cache
  // is process-wide and a test that has just been refusing proofs on purpose
  // wants a clean slate for the next section.
  dpop.forgetProofs();
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
    .send(JSON.stringify(dpop.state(), null, 2));
  log.debug("Leaving the DPoP nonce-mode endpoint (write). required=" + dpop.nonceModeOn());
});

app.post('/oauth2/token', function (req, res) {
  log.debug("Entering the token endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const client = clientFrom(req, body);
  const grant = String(body.grant_type || '');
  res.set('Cache-Control', 'no-store');

  // --- DPoP (RFC 9449 section 5) -------------------------------------------
  // Optional, and checked before any grant is considered so that every grant
  // gets the same treatment: a wallet that sends a proof gets a bound token
  // whether it arrived by authorization code, by pre-authorized code or by
  // refresh. A wallet that sends none gets a Bearer token exactly as before,
  // which is what keeps this switch invisible to the workflows that do not use
  // it.
  let dpopJkt = '';
  if (req.headers['dpop'] !== undefined) {
    const checked = dpop.verifyProof(req.headers['dpop'], {
      htm: req.method, htu: dpop.htuOf(req)
    });
    if (!checked.ok) {
      // Section 8: when the server wants a nonce it does not refuse outright —
      // it ASKS, with a fresh nonce in the header and `use_dpop_nonce` as the
      // error, and the wallet retries once. Answering a plain invalid_dpop_proof
      // here would leave a conforming client with no way forward.
      if (checked.needNonce) {
        res.set('DPoP-Nonce', dpop.issueNonce());
        log.debug("Leaving the token endpoint. Asking the client for a DPoP nonce.");
        return oauthError(res, 400, 'use_dpop_nonce',
          'Authorization server requires nonce in DPoP proof');
      }
      log.debug("Leaving the token endpoint. The DPoP proof was refused.");
      return oauthError(res, 400, 'invalid_dpop_proof', checked.description);
    }
    dpopJkt = checked.jkt;
    log.debug("This Token Request carries a valid DPoP proof. jkt=" + dpopJkt);
  }
  // Note there is no "DPoP required" mode here. Nonce mode makes proofs FRESHER;
  // it does not make them mandatory. A request with no DPoP header is a Bearer
  // request and is answered as one, so turning nonce mode on cannot break the
  // Bearer clients this server also exists to exercise.

  const respond = function (payload) {
    res.status(200).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving the token endpoint. Issued: " + Object.keys(payload).join(', '));
  };

  // Turn what was authorized into what may be requested: OID4VCI calls these
  // Credential Dataset identifiers, and they are the issuer's own names for
  // "this credential, for this End-User".
  const grantIdentifiers = function (details, user) {
    log.debug("Entering grantIdentifiers().");
    if (!details) return null;
    log.debug("Leaving grantIdentifiers().");
    return details.map(function (d) {
      return {
        type: 'openid_credential',
        credential_configuration_id: d.credential_configuration_id,
        credential_identifiers: [
          d.credential_configuration_id + ':' +
          b64u(crypto.createHash('sha256')
            .update(String((user && user.sub) || 'anonymous') + ':' + d.credential_configuration_id)
            .digest()).slice(0, 16)
        ]
      };
    });
  };

  if (grant === 'authorization_code') {
    const record = authzCodes.get(String(body.code || ''));
    if (!record) return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used authorization code.');
    authzCodes.delete(String(body.code));  // single use
    if (record.expires < Date.now()) return oauthError(res, 400, 'invalid_grant', 'The authorization code has expired.');
    if (body.redirect_uri && body.redirect_uri !== record.redirect_uri) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    }
    if (record.code_challenge) {
      const verifier = String(body.code_verifier || '');
      if (!verifier) return oauthError(res, 400, 'invalid_grant', 'PKCE was used, so code_verifier is required.');
      const computed = record.code_challenge_method === 'S256'
        ? b64u(crypto.createHash('sha256').update(verifier, 'ascii').digest())
        : verifier;
      if (computed !== record.code_challenge) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        return oauthError(res, 400, 'invalid_grant', 'The code_verifier does not match the code_challenge.');
      }
    }
    // RFC 9449 section 10: when the authorization request named a key with
    // `dpop_jkt`, the code is bound to it and only that key may redeem it. This
    // closes the window PKCE does not: an attacker who steals the code AND the
    // code_verifier still cannot use them, because they cannot sign for the key.
    if (record.dpop_jkt) {
      if (!dpopJkt) {
        log.debug("Leaving the token endpoint. The code is DPoP-bound and no proof came with it.");
        return oauthError(res, 400, 'invalid_grant',
          'The authorization request bound this code to a DPoP key (dpop_jkt), so the Token ' +
          'Request must carry a DPoP proof from that key.');
      }
      if (record.dpop_jkt !== dpopJkt) {
        log.debug("Leaving the token endpoint. The code's dpop_jkt does not match the proof.");
        return oauthError(res, 400, 'invalid_grant',
          'This authorization code is bound to DPoP key ' + record.dpop_jkt +
          ', but the proof was signed by ' + dpopJkt + '.');
      }
      log.debug("The authorization code's dpop_jkt matches the proof. jkt=" + dpopJkt);
    }
    return respond(tokenSet(base, {
      jkt: dpopJkt,
      user: record.user, client_id: record.client_id, scope: record.scope,
      nonce: record.nonce, auth_time: record.auth_time,
      authorization_details: grantIdentifiers(record.authorization_details, record.user)
    }));
  }

  // OID4VCI's pre-authorized code grant (Appendix H.2 / H.3, RFC-registered as
  // urn:ietf:params:oauth:grant-type:pre-authorized_code). No authorization
  // request happened: the End-User was identified out of band and the code in
  // the Credential Offer is the authorization. When the offer said a
  // Transaction Code is required, the wallet must present the one the End-User
  // read off the issuer's screen.
  if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    const code = String(body['pre-authorized_code'] || '');
    const record = preAuthorizedCodes.get(code);
    if (!record) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used pre-authorized code.');
    }
    if (record.expires < Date.now()) {
      preAuthorizedCodes.delete(code);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The pre-authorized code has expired.');
    }
    const presented = String(body.tx_code || '');
    if (record.txCode) {
      if (!presented) {
        log.debug("Leaving the token endpoint. The grant was refused: no tx_code.");
        return oauthError(res, 400, 'invalid_grant',
          'This pre-authorized code requires the Transaction Code shown by the issuer (tx_code).');
      }
      if (presented !== record.txCode) {
        log.debug("Leaving the token endpoint. The grant was refused: the tx_code is wrong.");
        return oauthError(res, 400, 'invalid_grant', 'The Transaction Code is not correct.');
      }
    }
    // Single use, like an authorization code.
    preAuthorizedCodes.delete(code);
    const issued = tokenSet(base, {
      jkt: dpopJkt,
      user: record.user, client_id: client.client_id, scope: VCI_SCOPE, withRefresh: false
    });
    // Remember which access token belongs to a deferred issuance, so the
    // credential endpoint knows to answer 202 rather than a credential.
    if (record.deferred) {
      deferredAccessTokens.add(issued.access_token);
      log.debug("This access token belongs to a DEFERRED issuance.");
    }
    return respond(issued);
  }

  if (grant === 'refresh_token') {
    let claims;
    try {
      claims = jwt.verify(String(body.refresh_token || ''), STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      log.error('the refresh token is not valid: ' + e.message);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The refresh token is not valid: ' + e.message);
    }
    if (revokedJtis.has(claims.jti)) return oauthError(res, 400, 'invalid_grant', 'The refresh token was revoked.');
    // RFC 9449 section 5: a bound refresh token may only be redeemed by its own
    // key. Without this the refresh token would be a bearer credential that
    // mints bound access tokens for whoever holds it — which is worse than not
    // binding at all, because the token_type would say `DPoP` and imply a
    // guarantee that was never checked.
    const boundTo = dpop.jktOf(claims);
    if (boundTo) {
      if (!dpopJkt) {
        log.debug("Leaving the token endpoint. The refresh token is bound and no proof came.");
        return oauthError(res, 400, 'invalid_grant',
          'This refresh token is bound to a DPoP key, so the Token Request must carry a DPoP ' +
          'proof from that key.');
      }
      if (boundTo !== dpopJkt) {
        log.debug("Leaving the token endpoint. The refresh token's cnf.jkt does not match.");
        return oauthError(res, 400, 'invalid_grant',
          'This refresh token is bound to DPoP key ' + boundTo + ', but the proof was signed ' +
          'by ' + dpopJkt + '.');
      }
    }
    return respond(tokenSet(base, {
      // A refresh keeps whatever binding it had: re-binding to the key that
      // happens to have signed this request would let a stolen bound token be
      // laundered into one bound to the thief's key.
      jkt: boundTo || dpopJkt,
      user: userFor(claims.username), client_id: claims.client_id,
      scope: body.scope ? String(body.scope) : claims.scope
    }));
  }

  if (grant === 'client_credentials') {
    // No user is involved, so no refresh token and no ID token.
    return respond(tokenSet(base, {
      jkt: dpopJkt,
      sub: client.client_id || 'unknown-client', username: client.client_id,
      client_id: client.client_id, scope: String(body.scope || ''), withRefresh: false,
      user: Object.assign(userFor(client.client_id), { sub: client.client_id || 'unknown-client' })
    }));
  }

  if (grant === 'password') {
    const username = String(body.username || '');
    if (!username || !body.password) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_request', 'username and password are required.');
    }
    // The one credential this mock rejects, so a negative test has something to
    // fail on (the WS-Trust side of this service does the same).
    if (body.password === 'invalid') {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Authentication failed for user ' + username + '.');
    }
    return respond(tokenSet(base, {
      jkt: dpopJkt,
      user: userFor(username), client_id: client.client_id, scope: String(body.scope || 'openid')
    }));
  }

  if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    const subjectToken = String(body.subject_token || '');
    if (!subjectToken) return oauthError(res, 400, 'invalid_request', 'subject_token is required.');
    let subject = {};
    try {
      subject = jwt.verify(subjectToken, STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      // A token from somewhere else: exchange it anyway, but say who it was for
      // as best it can be read.
      log.debug("The subject_token was not signed by this server; reading it without verifying.");
      try {
        subject = jsonFromB64u(subjectToken.split('.')[1]) || {};
      } catch (e2) {
        log.error('the subject_token could not be read at all: ' + e2.message);
        subject = {};
      }
    }
    let act;
    if (body.actor_token) {
      try {
        act = { sub: (jsonFromB64u(String(body.actor_token).split('.')[1]) || {}).sub };
      } catch (e) {
        log.error('the actor_token could not be read: ' + e.message);
        act = undefined;
      }
    }
    const exchanged = tokenSet(base, {
      jkt: dpopJkt,
      sub: subject.sub || 'urn:sts-mock:exchanged',
      user: Object.assign(userFor(subject.username), subject.sub ? { sub: subject.sub } : {}),
      client_id: client.client_id, scope: String(body.scope || subject.scope || ''),
      audience: body.audience || body.resource, act: act, withRefresh: false
    });
    exchanged.issued_token_type = 'urn:ietf:params:oauth:token-type:access_token';
    return respond(exchanged);
  }

  log.debug("Leaving the token endpoint.");
  log.debug("Leaving the token endpoint. The grant type is not supported.");
  return oauthError(res, 400, 'unsupported_grant_type', 'grant_type "' + grant + '" is not supported.');
});

// --- introspection (RFC 7662) ------------------------------------------------
app.post('/oauth2/introspect', function (req, res) {
  log.debug("Entering the introspection endpoint.");
  const body = parseBody(req);
  res.set('Cache-Control', 'no-store');
  const inactive = function () {
    res.status(200).type('application/json').send(JSON.stringify({ active: false }));
    log.debug("Leaving the introspection endpoint. The token is not active.");
  };
  const token = String(body.token || '');
  if (!token) return inactive();
  let claims;
  try {
    claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Expired, forged, or simply not one of ours.
    log.debug("Introspection: the token does not verify (" + e.message + "), so it is inactive.");
    return inactive();
  }
  if (revokedJtis.has(claims.jti)) return inactive();
  res.status(200).type('application/json').send(JSON.stringify({
    active: true,
    scope: claims.scope || '',
    client_id: claims.client_id,
    username: claims.username,
    // A bound token is not a Bearer token, and an introspection response that
    // says otherwise invites the caller to accept it as one.
    token_type: claims.typ === 'Refresh' ? 'refresh_token'
                                        : (dpop.jktOf(claims) ? 'DPoP' : 'Bearer'),
    // RFC 9449 section 6.1 / RFC 7662: the confirmation travels to the resource
    // server so it can check the binding itself.
    cnf: claims.cnf,
    exp: claims.exp, iat: claims.iat, nbf: claims.nbf,
    sub: claims.sub, aud: claims.aud, iss: claims.iss, jti: claims.jti
  }));
  log.debug("Leaving the introspection endpoint. The token is active.");
});

// --- revocation (RFC 7009) ---------------------------------------------------
// "The authorization server responds with HTTP 200 for both a successful
// revocation and an invalid token" — so this always succeeds. A revoked jti
// stops introspecting as active and stops refreshing.
app.post('/oauth2/revoke', function (req, res) {
  log.debug("Entering the revocation endpoint.");
  const body = parseBody(req);
  const token = String(body.token || '');
  if (token) {
    try {
      const claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
      if (claims.jti) revokedJtis.add(claims.jti);
    } catch (e) {
      // RFC 7009: an invalid token is still a successful revocation.
      log.debug("Revocation: the token does not verify (" + e.message + "), so there is nothing to revoke.");
    }
  }
  res.status(200).set('Cache-Control', 'no-store').end();
  log.debug("Leaving the revocation endpoint. " + revokedJtis.size + " token(s) revoked so far.");
});

// --- dynamic client registration (RFC 7591) + management (RFC 7592) ----------
function clientRecord(base, metadata, clientId, secret, token) {
  log.debug("Entering clientRecord(). client_id=" + clientId);
  const record = Object.assign({}, metadata, {
    client_id: clientId,
    client_id_issued_at: nowSec(),
    client_secret: secret,
    client_secret_expires_at: 0,               // 0 = never
    registration_access_token: token,
    registration_client_uri: base + '/oauth2/register/' + clientId
  });
  log.debug("Leaving clientRecord().");
  return record;
}

app.post('/oauth2/register', function (req, res) {
  log.debug("Entering the client registration endpoint.");
  const base = baseUrlOf(req);
  const metadata = parseBody(req);
  if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
    return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris must be an array.');
  }
  const clientId = 'sts-mock-client-' + randomId(8);
  const record = clientRecord(base, metadata, clientId, randomId(24), randomId(24));
  registeredClients.set(clientId, record);
  res.status(201).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record, null, 2));
  log.debug("Leaving the client registration endpoint. Registered " + clientId + ".");
});

// The management calls all authenticate with the registration access token the
// registration handed out.
function withRegisteredClient(req, res, handler) {
  log.debug("Entering withRegisteredClient(). client_id=" + req.params.client_id);
  const record = registeredClients.get(req.params.client_id);
  if (!record) {
    log.debug("Leaving withRegisteredClient(). No such client.");
    return oauthError(res, 404, 'invalid_client', 'No such registered client.');
  }
  const auth = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (auth !== record.registration_access_token) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving withRegisteredClient(). The registration access token did not match.");
    return oauthError(res, 401, 'invalid_token', 'The registration access token does not match.');
  }
  const result = handler(record);
  log.debug("Leaving withRegisteredClient().");
  return result;
}

app.get('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client read endpoint.");
  withRegisteredClient(req, res, function (record) {
    res.status(200).type('application/json').send(JSON.stringify(record, null, 2));
  });
  log.debug("Leaving the client read endpoint.");
});

app.put('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client update endpoint.");
  withRegisteredClient(req, res, function (record) {
    const updated = Object.assign({}, parseBody(req), {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      client_secret: record.client_secret,
      client_secret_expires_at: record.client_secret_expires_at,
      registration_access_token: record.registration_access_token,
      registration_client_uri: record.registration_client_uri
    });
    registeredClients.set(record.client_id, updated);
    res.status(200).type('application/json').send(JSON.stringify(updated, null, 2));
  });
  log.debug("Leaving the client update endpoint.");
});

app.delete('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client delete endpoint.");
  withRegisteredClient(req, res, function (record) {
    registeredClients.delete(record.client_id);
    res.status(204).end();
  });
  log.debug("Leaving the client delete endpoint.");
});

// --- the documents the metadata links to ------------------------------------
app.get('/docs', function (req, res) {
  log.debug("Entering the service documentation endpoint.");
  res.type('text/plain').send(
    'Mock authorization server (service_documentation).\n\n' +
    'Every endpoint in ' + baseUrlOf(req) + '/.well-known/oauth-authorization-server answers.\n' +
    'Tokens are RS256 JWTs signed with the key at ' + baseUrlOf(req) + '/oauth2/jwks.\n' +
    'No credential is ever verified: this server exists to exercise a client.\n');
  log.debug("Leaving the service documentation endpoint.");
});

app.get('/policy', function (req, res) {
  log.debug("Entering the policy document endpoint.");
  res.type('text/plain').send('Mock authorization server policy (op_policy_uri). Test data only.\n');
  log.debug("Leaving the policy document endpoint.");
});

app.get('/tos', function (req, res) {
  log.debug("Entering the terms of service endpoint.");
  res.type('text/plain').send('Mock authorization server terms of service (op_tos_uri). Test data only.\n');
  log.debug("Leaving the terms of service endpoint.");
});

module.exports = {
  asMetadata: asMetadata,
  accessToken: accessToken,
  tokenSet: tokenSet,
  sessions: sessions,
  registeredClients: registeredClients
};
