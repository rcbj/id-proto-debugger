// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/oid4vp.tsp
//
// OPENID4VP THROUGH THE API: the wallet's route to a Verifier that sends no
// CORS headers (POST /oid4vp/call), and the document a page reads to learn
// that there is an api at all (GET /oid4vp/limits). See api/oid4vp_proxy.js
// and docs/sd-jwt-vc-presentation.md.
//
// THE CALL keeps the SSF proxy's outcomes: a refusal by this service is a
// 400 (a shape refusal, or the address policy refusing the URL or a redirect
// hop), a network failure is a 502, and anything the Verifier answered is a
// 200 carrying its status.
//
// WHERE THE CHECKS ARE. The schema holds the JSON types. Every check on a
// value is api/oid4vp_proxy.js's, which tests/api_oid4vp_proxy.js drives
// with no listener and no Verifier.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Oid4vp;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** One request to a Verifier, as the wallet composed it. */
model CallRequest {
  /** The request_uri, response_uri or redirect_uri, exactly as the Verifier
   *  named it. */
  @checkedInCode("api/oid4vp_proxy.js: required, and an absolute http:// or https:// URL; the address policy applies when it is called")
  url?: string | null;

  /** GET or POST, any case. Absent is GET. */
  @checkedInCode("api/oid4vp_proxy.js: GET or POST, compared upper-cased")
  method?: string | null;

  /** Header name to value; each value is sent as text, null is dropped. */
  @checkedInCode("api/ssf_proxy.js sanitizeHeaders(): each name a token, no framing or hop-by-hop header, no CR or LF in a value")
  @passthrough
  headers?: Record<unknown> | null;

  /** The form-encoded body, exactly as it is to travel. Empty is none. */
  @checkedInCode("api/oid4vp_proxy.js: a string, none on a GET, at most oid4vpMaxRequestBytes")
  @passthrough
  body?: unknown;

  /** "text" (absent: the default) or "base64": how the far end's body
   *  comes back. base64 is for bytes that are not text, a CWT status list. */
  @checkedInCode("api/oid4vp_proxy.js: \"text\" or \"base64\"")
  responseEncoding?: string | null;

  /** Only false or "false" turns off certificate verification. */
  @checkedInCode("api/oid4vp_proxy.js: only false or \"false\" turns verification off")
  sslValidate?: boolean | string | null;

  /** true or "true" attaches http_exchange to the answer. */
  @checkedInCode("api/server.js: only true or \"true\" asks for the trace")
  http_trace?: boolean | string | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/**
 * What the Verifier said. `body` is the text as it arrived (a Request Object
 * is a JWS; a reply may be JSON or nothing); `json` is its parse when it is
 * JSON, and null otherwise.
 */
model Answer {
  status: int32;
  ok: boolean;
  headers: Record<unknown>;
  body: string;

  /** "base64" when the call asked for responseEncoding base64: `body` is
   *  then the bytes in base64 and `json` is null. Absent for text. */
  bodyEncoding?: "base64";

  json: unknown;
  http_exchange?: HttpExchange;
}

/**
 * This service refused the request: its shape, or the address policy on the
 * URL or a redirect hop (then `code` is EBLOCKEDADDRESS or
 * EPROTOCOLNOTALLOWED).
 */
model Refused {
  error: string;
  code?: string | null;
  http_exchange?: HttpExchange;
}

/** The Verifier could not be reached. `code` is the network error's. */
model Unreachable {
  error: string;
  code: string;
  http_exchange?: HttpExchange;
}

/** What the OpenID4VP proxy will and will not do. */
model Limits {
  methods: string[];
  responseEncodings: string[];
  refusedHeaders: string[];
  maxRequestBytes: int64;
  statusRule: string;
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Carry one request to a Verifier. A Verifier's own error is a 200 carrying
 *  its status. */
@tag("OpenID4VP")
@route("/oid4vp/call")
@post
@operationId("oid4vpCall")
op call(@body body: CallRequest): Ok<Answer> |
  BadRequest<Refused | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<Unreachable>;

/** What the OpenID4VP proxy does. A static deployment has no api and gets no
 *  answer, which is how the page knows. */
@tag("OpenID4VP")
@route("/oid4vp/limits")
@get
@operationId("oid4vpLimits")
op limits(): Ok<Limits>;

// ---------------------------------------------------------------------------
// THE VERIFIER ROLE (issue #364): the request_uri and response_uri this api
// hosts on a page's behalf, because a page is not an HTTP server. Five
// routes are the PAGE's and three are a WALLET's; the Wallet's answers are
// OAuth's `{error, error_description}` and the page's are `{error}`. Every
// bound and every refusal is api/oid4vp_verifier.js's, which
// tests/api_oid4vp_verifier.js drives with and without a listener.
// ---------------------------------------------------------------------------

/** A Verifier session, as the page asks for one. */
model VerifierCreateRequest {
  /** The redirect_uri answered to a Wallet's post (section 8.2). */
  @checkedInCode("api/oid4vp_verifier.js: at most 4096 characters, no line break")
  @passthrough
  redirectUri?: string | null;

  /** The session's absolute lifetime, ms. */
  @checkedInCode("api/oid4vp_verifier.js: a positive whole number, at most oid4vpVerifierTtlMs")
  ttlMs?: float64 | string | null;

  /** The session's lifetime untouched, ms. */
  @checkedInCode("api/oid4vp_verifier.js: a positive whole number, at most oid4vpVerifierIdleTtlMs")
  idleTtlMs?: float64 | string | null;

  /** Hold a Wallet's request_uri POST (section 5.10) for the page to sign
   *  a Request Object carrying its wallet_nonce. */
  liveSigning?: boolean | null;

  /** The base the three URLs are built from, overriding
   *  oid4vpVerifierPublicBaseUrl and the caller's own base: an address a
   *  Wallet can reach. It only shapes the strings handed back. */
  @checkedInCode("api/oid4vp_verifier.js: an absolute https URL, at most 2048 characters, with no credentials, query or fragment")
  publicBaseUrl?: string | null;
}

/** The Request Object the page signed for ONE held Wallet. */
model VerifierPublishForRequest {
  /** The signed Request Object, a compact JWS; or, when the Wallet's
   *  wallet_metadata gave a key to encrypt to, that JWS encrypted to it, a
   *  compact JWE (section 5.10; RFC 9101 section 4). */
  @checkedInCode("api/oid4vp_verifier.js: required, three base64url segments (a JWS) or five (a JWE), at most oid4vpVerifierMaxRequestObjectBytes")
  @passthrough
  requestObject?: string | null;
}

/** What the page signed, to be served at request_uri. */
model VerifierPublishRequest {
  /** The signed Request Object, a compact JWS. */
  @checkedInCode("api/oid4vp_verifier.js: required, three base64url segments, at most oid4vpVerifierMaxRequestObjectBytes")
  @passthrough
  requestObject?: string | null;

  /** The root CA certificate served at caIssuersUrl: base64 DER, or PEM. */
  @checkedInCode("api/oid4vp_verifier.js: base64 that decodes to a DER SEQUENCE, at most oid4vpVerifierMaxRequestObjectBytes")
  @passthrough
  caCertificate?: string | null;

  /** Replaces the redirect_uri the session was created with. */
  @checkedInCode("api/oid4vp_verifier.js: at most 4096 characters, no line break")
  @passthrough
  redirectUri?: string | null;
}

/** A new session and the three URLs a Wallet reaches it at. */
model VerifierCreated {
  /** 32 hex digits. */
  id: string;

  /** 32 hex digits: `Authorization: Bearer <secret>` on every page call. */
  secret: string;

  requestUri: string;
  responseUri: string;
  caIssuersUrl: string;

  /** Whether a Wallet's request_uri POST is held for the page to sign. */
  liveSigning: boolean;

  /** The sooner of the two expiries. */
  expiresAt: string;
}

/** One thing a Wallet did. */
model VerifierEvent {
  /** From 0, never reused; what `after` counts. */
  seq: int32;

  at: string;

  /** request-fetched, request-signed, ca-fetched, response or
   *  response-refused. */
  kind: string;

  method?: string;

  /** The Content-Type header as the Wallet sent it. */
  contentType?: string;

  /** request-fetched by POST: the Accept header as the Wallet sent it.
   *  Section 5.10 says it MUST be application/oauth-authz-req+jwt. */
  accept?: string;

  /** The answer's fields, each the text that arrived. */
  fields?: Record<unknown>;

  /** request_uri_method=post: wallet_metadata, parsed when it is JSON. */
  walletMetadata?: unknown;

  walletNonce?: unknown;
  remoteAddress?: string;

  /** What was wrong with what arrived. On response-refused, why it was
   *  not kept. On request-fetched and response, a MUST the Wallet broke
   *  while the api still served or kept it (accept and report): a
   *  request_uri POST that is not application/x-www-form-urlencoded or
   *  has no Accept of application/oauth-authz-req+jwt (section 5.10), a
   *  JSON answer to response_uri (section 8.2), a wallet_nonce no
   *  pre-signed object can carry. */
  problem?: string;

  /** response: the redirect_uri the Wallet was answered with, carrying
   *  this answer's response_code. */
  redirectUri?: string;

  /** response: the fresh, cryptographically random value (128 bits,
   *  base64url) added to redirect_uri as `response_code` for this one
   *  answer (section 8.2; the name is section 13.3's). */
  responseCode?: string;

  /** Live signing: on a request-fetched event, the Wallet is held and the
   *  page signs for it at /request/{signingId}; on request-signed, which
   *  wait it closes (absent when the cap meant no wait at all). */
  signingId?: string;

  /** request-fetched under live signing: how long the Wallet is held. */
  waitMs?: float64;

  /** request-fetched under live signing: when the wait runs out. */
  signBy?: string;

  /** request-signed: true when the Wallet got the page's live object. */
  liveSigned?: boolean;

  /** request-signed with liveSigned false: why the page's object was not
   *  served, and what the Wallet got instead. */
  reason?: string;

  /** request-signed: the HTTP error the Wallet was answered with — 503
   *  when it sent a wallet_nonce no Request Object could be signed with in
   *  time (OpenID4VP section 5.10.2). Absent when it got an object. */
  httpStatus?: int32;
}

/** What Wallets did since the cursor. */
model VerifierEvents {
  events: VerifierEvent[];

  /** The cursor for the next call: how many events were ever recorded. */
  next: int32;

  /** How many were dropped by the caps. */
  dropped: int32;

  expiresAt: string;
}

/** The Verifier role's bounds, and whether this service hosts it. */
model VerifierLimits {
  enabled: boolean;
  ttlMs: float64;
  idleTtlMs: float64;
  maxSessions: float64;
  maxSessionsPerCaller: float64;
  maxEvents: float64;
  maxResponseBytes: float64;
  maxRequestObjectBytes: float64;
  maxSessionBytes: float64;
  liveSignWaitMs: float64;
  maxPendingSignings: float64;

  /** oid4vpVerifierPublicBaseUrl, or "" when unset: the URLs then use the
   *  base the page reached this service at. */
  publicBaseUrl: string;

  /** How many sessions this process holds now. */
  held: int32;

  requestObjectMediaType: "application/oauth-authz-req+jwt";
  caMediaType: "application/pkix-cert";

  /** This service verifies nothing a Wallet sends. */
  verifies: false;

  note: string;
}

/** A refusal to a WALLET, in OAuth's shape. */
model WalletError {
  error: string;
  error_description: string;
}

/** A refusal to the PAGE. */
model PageError {
  error: string;
}

/** A page call without the session's secret. */
model Unauthorized {
  @statusCode statusCode: 401;
  @header("WWW-Authenticate") challenge: string;
  @body body: PageError;
}

/** request_uri_method=post: the Wallet sent a wallet_nonce, which section
 *  5.10 says the Verifier MUST put in the Request Object, and the page did
 *  not sign one carrying it in time (or too many Wallets already wait).
 *  Section 5.10.2: any HTTP error makes the Wallet terminate. */
model LiveSignUnavailable {
  @statusCode statusCode: 503;
  @body body: WalletError;
}

/** No session has that id: never created, deleted, or expired. */
model NoSession<T> {
  @statusCode statusCode: 404;
  @body body: T;
}

/** What the Verifier role will hold. A static deployment has no api and
 *  gets no answer, which is how the page knows. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/limits")
@get
@operationId("oid4vpVerifierLimits")
op verifierLimits(): Ok<VerifierLimits>;

/** Create a Verifier session. */
@tag("OpenID4VP")
@route("/oid4vp/verifier")
@post
@operationId("oid4vpVerifierCreate")
@checkedInCode("api/oid4vp_verifier.js: oid4vpVerifierEnabled (403), oid4vpVerifierMaxSessions and oid4vpVerifierMaxSessionsPerCaller, counted by the caller's address (400)")
op verifierCreate(@body body: VerifierCreateRequest): {
  @statusCode statusCode: 201;
  @body body: VerifierCreated;
} | BadRequest<PageError | IdProtoDebugger.Api.ModelRefusal> | {
  @statusCode statusCode: 403;
  @body body: PageError;
};

/** Publish the signed Request Object and the CA certificate. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/request")
@put
@operationId("oid4vpVerifierPublish")
@checkedInCode("api/oid4vp_verifier.js: the session exists (404), the Bearer secret is its own (401)")
op verifierPublish(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: VerifierPublishRequest,
): Ok<{
  ok: true;
}> | BadRequest<PageError | IdProtoDebugger.Api.ModelRefusal> |
  Unauthorized | NoSession<PageError>;

/** Answer ONE Wallet held under live signing with the Request Object the
 *  page signed for its wallet_nonce (section 5.10). */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/request/{signingId}")
@put
@operationId("oid4vpVerifierPublishFor")
@checkedInCode("api/oid4vp_verifier.js: the session exists (404), the Bearer secret is its own (401), a Wallet is waiting on signingId (404)")
op verifierPublishFor(
  @path id: string,
  @path signingId: string,
  @header("Authorization") authorization?: string,
  @body body: VerifierPublishForRequest,
): Ok<{
  ok: true;
}> | BadRequest<PageError | IdProtoDebugger.Api.ModelRefusal> |
  Unauthorized | NoSession<PageError>;

/** A Wallet fetches the Request Object (section 5.7). */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/request")
@get
@operationId("oid4vpVerifierRequestGet")
op verifierRequestGet(@path id: string): {
  @statusCode statusCode: 200;
  @header contentType: "application/oauth-authz-req+jwt";
  @body body: string;
} | NoSession<WalletError>;

/** A Wallet fetches the Request Object by POST, request_uri_method=post
 *  (section 5.10), carrying wallet_metadata and wallet_nonce. Under live
 *  signing the answer waits for the page, up to
 *  oid4vpVerifierLiveSignWaitMs; a Wallet that sent a wallet_nonce is then
 *  answered 503, and one that sent none gets the pre-signed object. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/request")
@post
@operationId("oid4vpVerifierRequestPost")
op verifierRequestPost(
  @path id: string,
  /** Section 5.10 makes it a form; a JSON body is still served, and its
   *  request-fetched event carries a `problem` saying so. */
  @header contentType: "application/x-www-form-urlencoded" |
    "application/json",
  @passthrough
  @body body: Record<unknown>,
): {
  @statusCode statusCode: 200;
  @header contentType: "application/oauth-authz-req+jwt";
  @body body: string;
} | NoSession<WalletError> | LiveSignUnavailable;

/** The Verifier's root CA certificate, at the leaf's AIA caIssuers URL. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/ca")
@get
@operationId("oid4vpVerifierCa")
op verifierCa(@path id: string): {
  @statusCode statusCode: 200;
  @header contentType: "application/pkix-cert";
  @body body: bytes;
} | NoSession<WalletError>;

/** A Wallet's answer (section 8.2), kept field by field as it arrived. A
 *  JSON body is kept too, and its `response` event carries a `problem`
 *  naming section 8.2's form-encoding MUST. `redirect_uri`, when the page
 *  set one, carries a fresh `response_code` for this answer. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/response")
@post
@operationId("oid4vpVerifierResponse")
@checkedInCode("api/oid4vp_verifier.js: the session exists (404); the body is a form or a JSON object, at most oid4vpVerifierMaxResponseBytes (400)")
op verifierResponse(
  @path id: string,
  @header contentType: "application/x-www-form-urlencoded" |
    "application/json",
  @passthrough
  @body body: Record<unknown>,
): Ok<{
  redirect_uri?: string;
}> | BadRequest<WalletError | IdProtoDebugger.Api.ModelRefusal> |
  NoSession<WalletError>;

/** What Wallets did since `after`. A cursor, not a destructive read. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}/events")
@get
@operationId("oid4vpVerifierEvents")
op verifierEvents(
  @path id: string,
  @header("Authorization") authorization?: string,

  /** The `next` of the previous call. Not a number, or negative, is 0. */
  @checkedInCode("api/oid4vp_verifier.js: read with Number(); anything not a finite non-negative number is 0")
  @query
  after?: string,
): Ok<VerifierEvents> | Unauthorized | NoSession<PageError>;

/** Delete a session. */
@tag("OpenID4VP")
@route("/oid4vp/verifier/{id}")
@delete
@operationId("oid4vpVerifierDelete")
op verifierDelete(
  @path id: string,
  @header("Authorization") authorization?: string,
): Ok<{
  ok: true;
  deleted: string;
}> | Unauthorized | NoSession<PageError>;
