// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/oauth.tsp
//
// OAuth 2.0 / OpenID Connect: the proxies the OAuth2/OIDC workflow calls
// when a request is "initiated from the back end" — the token endpoint
// (RFC 6749, with PKCE and the device grant), introspection (RFC 7662),
// revocation (RFC 7009), token exchange (RFC 8693), device authorization
// (RFC 8628), dynamic client registration (RFC 7591 / RFC 7592) and
// UserInfo (OIDC Core 5.3) — plus the IANA JWT claims registry the token
// page labels claims from. See docs/oauth2-oidc/.
//
// THIS IS THE FAMILY WHERE THE PASSTHROUGH RULE MATTERS MOST. Everything a
// user typed — grant_type, client_id, client_secret, code, redirect_uri,
// scope, code_verifier, a custom parameter, a token — is forwarded as typed,
// and a debugger exists to send a malformed one and show the authorization
// server's error. So every such member is @passthrough: its JSON type is
// stated and nothing about its content. Only the api's OWN members — the
// endpoint URL it is told to call, sslValidate, auth_style, http_trace, the
// registration method — have types that mean something, and the only member
// any operation REQUIRES is the URL, which no handler can do without.
//
// THE ANSWERS ARE THE FAR END'S. Each handler answers with the status the
// authorization server answered and the body it sent, parsed as JSON where
// it was JSON and as a string where it was not. So every status the far end
// can plausibly give is listed (Relay below), and the far end's members are
// documented with `unknown` types: the api relays a non-conforming answer
// unchanged, and that must not read as the api's own gap. What IS the api's
// own is typed exactly: the failure when nothing came back (500), the HTTP
// trace it attaches when asked (`http_exchange`), and the two summaries
// /revoke and /register write themselves.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.OAuth;

// ---------------------------------------------------------------------------
// The api's own members, shared.
// ---------------------------------------------------------------------------

/**
 * Whether to verify the far end's TLS certificate. `false` or the string
 * "false" turns verification off, and anything else leaves it on
 * (verifiesCertificates() in api/ssl_validate.js). The page's radio
 * buttons send the strings "true" and "false"; until #434 the string
 * "false" verified anyway.
 */
alias SslValidate = boolean | string | null;

/**
 * Where the client credentials go. Truthy: in the form body. Falsy or
 * absent: an HTTP Basic header (RFC 6749 section 2.3.1). The page sends a
 * boolean; callers have sent strings such as "post".
 */
alias AuthStyle = boolean | string | null;

/**
 * true or "true" asks for the HTTP exchange with the far end to be attached
 * to the answer as `http_exchange`. Opt-in per call, because it repeats the
 * request verbatim, Authorization header and all.
 */
alias HttpTrace = boolean | string | null;

/** A note on every endpoint URL the api is told to call. */
alias UrlChecks = "api/ssrf_guard.js, through the outbound agents in api/server.js: http: and https: only, and the address policy (blockPrivateNetworkCalls, blockedAddressRanges). Anything axios cannot parse as a URL fails the call (500)";

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** A token request (RFC 6749 section 4, RFC 7636, RFC 8628 section 3.4),
 *  turned into a form body by common/data.js convertToOAuth2Format(). */
model TokenRequest {
  /** The token endpoint the api POSTs to. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  token_endpoint: string;

  sslValidate?: SslValidate;
  auth_style?: AuthStyle;
  http_trace?: HttpTrace;

  /**
   * Chooses which parameters convertToOAuth2Format() sends:
   * authorization_code, client_credentials, password, refresh_token or
   * urn:ietf:params:oauth:grant-type:device_code. Anything else is sent
   * with only resource, scope and the custom parameters.
   */
  @passthrough
  grant_type?: string | null;

  @passthrough
  client_id?: string | null;

  /** Never stored by the page; a dummy in every fixture. */
  @passthrough
  client_secret?: string | null;

  @passthrough
  code?: string | null;

  @passthrough
  redirect_uri?: string | null;

  @passthrough
  scope?: string | null;

  @passthrough
  code_verifier?: string | null;

  @passthrough
  username?: string | null;

  @passthrough
  password?: string | null;

  @passthrough
  refresh_token?: string | null;

  @passthrough
  device_code?: string | null;

  @passthrough
  resource?: string | null;

  /** Parameter name to value, each appended to the form body as typed. */
  @passthrough
  customParams?: Record<unknown> | null;
}

/** An introspection request (RFC 7662 section 2.1). The caller's
 *  Authorization header is forwarded as it arrived. */
model IntrospectionRequest {
  /** The introspection endpoint the api POSTs to. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  introspectionEndpoint: string;

  @passthrough
  token?: string | null;

  @passthrough
  token_type_hint?: string | null;
}

/** A revocation request (RFC 7009 section 2.1). */
model RevocationRequest {
  /** The revocation endpoint the api POSTs to. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  revocation_endpoint: string;

  sslValidate?: SslValidate;
  auth_style?: AuthStyle;

  @passthrough
  token?: string | null;

  @passthrough
  token_type_hint?: string | null;

  @passthrough
  client_id?: string | null;

  @passthrough
  client_secret?: string | null;
}

/** A token exchange request (RFC 8693 section 2.1). */
model TokenExchangeRequest {
  /** The token endpoint the api POSTs to. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  token_endpoint: string;

  sslValidate?: SslValidate;
  auth_style?: AuthStyle;
  http_trace?: HttpTrace;

  /** Sent as typed; the page sends the token-exchange URN. */
  @passthrough
  grant_type?: string | null;

  @passthrough
  subject_token?: string | null;

  @passthrough
  subject_token_type?: string | null;

  @passthrough
  actor_token?: string | null;

  @passthrough
  actor_token_type?: string | null;

  @passthrough
  requested_token_type?: string | null;

  @passthrough
  resource?: string | null;

  @passthrough
  audience?: string | null;

  @passthrough
  scope?: string | null;

  @passthrough
  client_id?: string | null;

  @passthrough
  client_secret?: string | null;
}

/** A device authorization request (RFC 8628 section 3.1). */
model DeviceAuthorizationRequest {
  /** The device authorization endpoint the api POSTs to. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  device_authorization_endpoint: string;

  sslValidate?: SslValidate;
  auth_style?: AuthStyle;

  @passthrough
  client_id?: string | null;

  @passthrough
  client_secret?: string | null;

  @passthrough
  scope?: string | null;
}

/**
 * A dynamic client registration call: create (POST the registration
 * endpoint), read (GET), update (PUT) or delete (DELETE the client
 * configuration endpoint), RFC 7591 / RFC 7592.
 */
model RegistrationRequest {
  /** The HTTP method, any case. Absent, null or empty is POST. */
  method?: string | null;

  /** registration_endpoint for create, registration_client_uri after. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  url: string;

  sslValidate?: SslValidate;

  /** An initial access token, or the registration access token, sent as
   *  `Authorization: Bearer` with this value after it. */
  @passthrough
  bearer_token?: string | null;

  /** The client metadata, sent as the JSON body on POST and PUT. */
  @passthrough
  metadata?: unknown;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/**
 * The api's own failure: the far end could not be reached or gave no
 * answer (a name that does not resolve, a refused connection, a timeout, a
 * body past maxContentLength, too many redirects, a blocked address or
 * scheme), or the call could not be made at all. `error` is an object only
 * where a handler's last-resort catch serialized an Error, which is `{}`.
 */
model Failure {
  error: string | Record<unknown>;

  /** Present when the caller asked for http_trace, on /token and
   *  /tokenexchange. `response` is null in it. */
  http_exchange?: HttpExchange;
}

/**
 * An OAuth 2.0 error response (RFC 6749 section 5.2), as the far end sent
 * it. Its members are the far end's, so they are documented, not held.
 */
model OAuthError {
  error?: unknown;
  error_description?: unknown;
  error_uri?: unknown;
  ...Record<unknown>;
}

/** A token response (RFC 6749 section 5.1, OIDC Core 3.1.3.3, RFC 8693
 *  section 2.2), or an error, as the far end sent it. */
model TokenAnswer {
  access_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
  refresh_token?: unknown;
  scope?: unknown;
  id_token?: unknown;
  issued_token_type?: unknown;
  error?: unknown;
  error_description?: unknown;
  error_uri?: unknown;

  /** The api's own, attached when http_trace asked for it and the body is
   *  an object that has no member of this name already. */
  http_exchange?: HttpExchange;

  ...Record<unknown>;
}

/** An introspection response (RFC 7662 section 2.2), as sent. */
model IntrospectionAnswer {
  active?: unknown;
  scope?: unknown;
  client_id?: unknown;
  username?: unknown;
  token_type?: unknown;
  exp?: unknown;
  iat?: unknown;
  nbf?: unknown;
  sub?: unknown;
  aud?: unknown;
  iss?: unknown;
  jti?: unknown;
  ...Record<unknown>;
}

/** A device authorization response (RFC 8628 section 3.2), as sent. */
model DeviceAuthorizationAnswer {
  device_code?: unknown;
  user_code?: unknown;
  verification_uri?: unknown;
  verification_uri_complete?: unknown;
  expires_in?: unknown;
  interval?: unknown;
  ...Record<unknown>;
}

/** A client information response (RFC 7591 section 3.2.1), as sent. */
model RegistrationAnswer {
  client_id?: unknown;
  client_secret?: unknown;
  registration_access_token?: unknown;
  registration_client_uri?: unknown;
  ...Record<unknown>;
}

/** OIDC UserInfo claims (OIDC Core 5.3.2), as sent, when JSON. */
model UserInfoAnswer {
  sub?: unknown;
  ...Record<unknown>;
}

/**
 * The api's summary of a revocation the far end accepted. RFC 7009 has
 * the server answer 200 with an empty body, so the api says what happened
 * itself and puts whatever body there was in `data`.
 */
model RevocationAccepted {
  message: "Token revocation request accepted (RFC 7009).";
  status: int32;
  statusText: string;
  data: unknown;
}

/**
 * The api's summary of a registration call the far end answered with no
 * body — a DELETE's 204 (RFC 7592 section 2.3) — sent as 200 so the
 * browser receives a body at all.
 */
model RegistrationSucceeded {
  message: "Client registration request succeeded.";
  status: int32;
  statusText: string;
}

/**
 * The far end's body as the api relays it: the JSON value it sent, or the
 * text when it was not JSON (an HTML error page, an empty body as "").
 * `T` describes the object a conforming server sends; nothing about it is
 * held, because the api relays a non-conforming one unchanged.
 */
@friendlyName("OAuth.Relayed{name}", T)
union Relayed<T> {
  T,
  string,
  null,
  boolean,
  float64,
  unknown[],
}

/** The 2xx statuses a far end answers and the api relays. */
alias RelayedSuccess = 200 | 201 | 202 | 204;

/**
 * The other statuses a far end plausibly answers, which the api relays. A
 * 3xx is one axios did not follow (it had no Location). api/model_validate.js
 * matches a status exactly — it reads no `default` and no `4XX` range — so
 * each is listed; a status missing here is recorded as a MODEL GAP, which is
 * the cue to add it.
 */
alias RelayedFailure = 301 | 302 | 303 | 307 | 308 |
  400 | 401 | 403 | 404 | 405 | 406 | 409 | 410 | 413 | 415 | 422 | 429 |
  500 | 501 | 502 | 503 | 504;

/** What the far end answered, relayed with its own status. */
model Relay<S, T> {
  @statusCode statusCode: S;
  @body body: Relayed<T>;
}

/** 400: the body was not the shape this operation takes. */
model Refused {
  @statusCode statusCode: 400;
  @body body: IdProtoDebugger.Api.ModelRefusal;
}

/** 500: nothing came back from the far end, or the call was not made. */
model NoAnswer {
  @statusCode statusCode: 500;
  @body body: Failure;
}

alias TokenAnswers = Relay<RelayedSuccess | RelayedFailure, TokenAnswer> |
  Refused | NoAnswer;

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Make a token request: every grant the workflow offers. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/token")
@post
@operationId("oauthToken")
op token(@body body: TokenRequest): TokenAnswers;

/** Introspect a token. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/introspection")
@post
@operationId("oauthIntrospection")
op introspection(
  /** Forwarded to the introspection endpoint as it arrived: Basic client
   *  credentials or a Bearer token. */
  @passthrough
  @header
  authorization?: string,

  @body body: IntrospectionRequest,
): Relay<RelayedSuccess | RelayedFailure, IntrospectionAnswer> | Refused |
  NoAnswer;

/** Revoke an access or refresh token. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/revoke")
@post
@operationId("oauthRevoke")
op revoke(@body body: RevocationRequest): {
  @statusCode statusCode: RelayedSuccess;
  @body body: RevocationAccepted;
} | Relay<RelayedFailure, OAuthError> | Refused | NoAnswer;

/** Exchange one token for another. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/tokenexchange")
@post
@operationId("oauthTokenExchange")
op tokenExchange(@body body: TokenExchangeRequest): TokenAnswers;

/** Start the device authorization grant. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/deviceauthorization")
@post
@operationId("oauthDeviceAuthorization")
op deviceAuthorization(@body body: DeviceAuthorizationRequest):
  Relay<RelayedSuccess | RelayedFailure, DeviceAuthorizationAnswer> |
  Refused | NoAnswer;

/** Create, read, update or delete a dynamically registered client. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/register")
@post
@operationId("oauthRegister")
op register(@body body: RegistrationRequest): {
  @statusCode statusCode: 200;
  @body body: RegistrationSucceeded;
} | Relay<RelayedSuccess | RelayedFailure, RegistrationAnswer> | Refused |
  NoAnswer;

/**
 * The UserInfo answer when it is not JSON: a signed, encrypted, or signed
 * then encrypted JWT (OIDC Core 5.3.2), relayed byte for byte under the
 * far end's own content type.
 */
model UserInfoJwt {
  @statusCode statusCode: RelayedSuccess;
  @header contentType: "application/jwt";
  @body body: string;
}

// An ALIAS and not a model, on purpose: spreading a named model makes the
// emitter put these parameters under components/parameters and refer to
// them by $ref, and api/model_validate.js reads `in` off each parameter
// without resolving a $ref — so the query went unchecked. Inline, it is.

/** What GET and POST /userinfo take: everything is in the query. */
alias UserInfoQuery = {
  /** The UserInfo endpoint, base64, with its query already on it. The api
   *  always calls it with GET. */
  @checkedInCode(UrlChecks)
  @minLength(1)
  @query
  userinfo_endpoint: string;

  /** The page repeats the scope here; the api does not read it. */
  @passthrough
  @query
  scope?: string;

  /** The page repeats the claims request here; the api does not read it. */
  @passthrough
  @query
  claims?: string;

  /** The access token, forwarded as it arrived. */
  @passthrough
  @header
  authorization?: string;
};

alias UserInfoAnswers = Relay<RelayedSuccess | RelayedFailure,
  UserInfoAnswer> | UserInfoJwt | Refused | NoAnswer;

/** Call a UserInfo endpoint. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/userinfo")
@get
@operationId("oauthUserInfo")
op userInfo(...UserInfoQuery): UserInfoAnswers;

/** The same call, made with POST by a page set to; the api still GETs. */
@tag("OAuth 2.0 / OpenID Connect")
@route("/userinfo")
@post
@operationId("oauthUserInfoPost")
op userInfoPost(...UserInfoQuery): UserInfoAnswers;

/** Whatever IANA's server answered instead of the registry, relayed. */
model RegistryError {
  ...Record<unknown>;
}

/**
 * The IANA "JSON Web Token Claims" registry, as IANA publishes it (XML),
 * fetched once and kept for the life of the process. The token page labels
 * the claims it shows from it.
 */
@tag("OAuth 2.0 / OpenID Connect")
@route("/claimdescription")
@get
@operationId("claimDescription")
op claimDescription(): {
  @statusCode statusCode: 200;
  @header contentType: "application/xml";
  @body body: string;
} | {
  // Express's res.send() sets an ETag and answers a matching
  // If-None-Match itself: a browser that already holds the registry gets
  // 304 with no body (seen by GET /model/gaps on 2026-11-16).
  @statusCode statusCode: 304;
} | Relay<RelayedFailure, RegistryError> | NoAnswer;
