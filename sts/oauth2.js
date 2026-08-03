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
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
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
// It also serves the RFC 8414 metadata document and the JWKS that document
// advertises, because those describe THIS server: the endpoints below are the ones
// the metadata promises, and keeping the promise beside the thing that keeps it is
// what stops the two drifting.
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
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'code id_token token'],
    // --- RECOMMENDED / OPTIONAL ---
    jwks_uri: base + '/oauth2/jwks',
    registration_endpoint: base + '/oauth2/register',
    scopes_supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
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
    ui_locales_supported: ['en-US', 'en-GB', 'fr-CA', 'de-DE'],
    op_policy_uri: base + '/policy',
    op_tos_uri: base + '/tos',
    revocation_endpoint: base + '/oauth2/revoke',
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    introspection_endpoint: base + '/oauth2/introspect',
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    introspection_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    code_challenge_methods_supported: ['S256', 'plain']
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
    iat: iat, nbf: iat, exp: iat + REFRESH_TOKEN_TTL
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
    token_type: 'Bearer',
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

// --- token endpoint ---------------------------------------------------------
app.post('/oauth2/token', function (req, res) {
  log.debug("Entering the token endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const client = clientFrom(req, body);
  const grant = String(body.grant_type || '');
  res.set('Cache-Control', 'no-store');

  const respond = function (payload) {
    res.status(200).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving the token endpoint. Issued: " + Object.keys(payload).join(', '));
  };

  // Turn what was authorized into what may be requested: OID4VCI calls these
  // Credential Dataset identifiers, and they are the issuer's own names for
  // "this credential, for this End-User".
  const grantIdentifiers = function (details, user) {
    if (!details) return null;
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
    return respond(tokenSet(base, {
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
    return respond(tokenSet(base, {
      user: userFor(claims.username), client_id: claims.client_id,
      scope: body.scope ? String(body.scope) : claims.scope
    }));
  }

  if (grant === 'client_credentials') {
    // No user is involved, so no refresh token and no ID token.
    return respond(tokenSet(base, {
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
    token_type: claims.typ === 'Refresh' ? 'refresh_token' : 'Bearer',
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
