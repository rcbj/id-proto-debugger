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
