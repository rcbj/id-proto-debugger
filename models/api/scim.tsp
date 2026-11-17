// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/scim.tsp
//
// SCIM 2.0 (RFC 7643, RFC 7644): one call to a SCIM server on the page's
// behalf, and the limits document. The page calls a SCIM server straight
// from the browser by default; this endpoint is for what a browser cannot do
// — a server that sends no CORS headers, a self-signed certificate, and the
// whole exchange reported. See docs/scim.md.
//
// THE THREE OUTCOMES, which every answer below keeps apart:
//
// * 400 — this service refused: no url, a relative one, a method RFC 7644
//   does not use, a framing header, a body on a GET or a DELETE.
// * 502 — the SCIM server could not be reached.
// * 200 — the server ANSWERED, whatever its status: a 409 `uniqueness`, a
//   404, a 403 and the 501 on /Me are the most useful things it says.
//
// WHERE THE CHECKS ARE. The schema holds the JSON types. Every check on a
// value is api/scim_proxy.js's describeRequest(), which tests/scim_protocol.js
// drives with no server at all, and each such member says so.
//
// HttpExchange is declared here and read by ssf.tsp and gnap.tsp as well: it
// is server.js's buildHttpTrace(), which every proxied call shares.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Scim;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** One SCIM request, as the page composed it. */
model CallRequest {
  /** The ABSOLUTE URL: the service root plus the path and query. */
  @checkedInCode("api/scim_proxy.js: required, and an absolute http:// or https:// URL; the address policy applies when it is called")
  url?: string | null;

  /** GET, POST, PUT, PATCH or DELETE, any case. Absent is GET. */
  @checkedInCode("api/scim_proxy.js: one of the five RFC 7644 methods, compared upper-cased")
  method?: string | null;

  /** Header name to value; each value is sent as text, null is dropped. */
  @checkedInCode("api/scim_proxy.js: each name a token, no framing or hop-by-hop header, no CR or LF in a value")
  @passthrough
  headers?: Record<unknown> | null;

  /** The SCIM document: JSON, or text sent exactly as given. */
  @checkedInCode("api/scim_proxy.js: none on a GET or a DELETE; at most scimMaxRequestBytes once serialised")
  @passthrough
  body?: unknown;

  /** Only false or "false" turns off certificate verification. */
  @checkedInCode("api/scim_proxy.js: only false or \"false\" turns verification off")
  sslValidate?: boolean | string | null;

  /** true or "true" attaches http_exchange to the answer. */
  @checkedInCode("api/server.js: only true or \"true\" asks for the trace")
  http_trace?: boolean | string | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** The request as it left this service, headers it added included. */
model SentRequest {
  method: string;
  url: string;
  headers: Record<unknown>;
  body: string;
}

/** The response as it arrived, the body cut at the trace's limit. */
model ReceivedResponse {
  status: int32;
  statusText: string;
  headers: Record<unknown>;
  body: string;
  bodyTruncated: boolean;
  bodyLength: int64;
}

/**
 * What this service saw of a call it made, attached as `http_exchange` when
 * the caller asked for it. `response` is null when there was none, and
 * `error` then says why.
 */
model HttpExchange {
  request: SentRequest;
  response: ReceivedResponse | null;
  timing: {
    totalMs: int64;
  };
  error: string | null;
}

/**
 * What the SCIM server said. `ok` is a 2xx; a SCIM error document fills
 * `scimType` and `detail`, and `notJson` is the parse error of a body that
 * is not JSON — which is something in front of the server answering.
 */
model Answer {
  status: int32;
  ok: boolean;
  headers: Record<unknown>;
  body: unknown;
  rawBody: string;
  scimType: string;
  detail: string;
  notJson: string;
  http_exchange?: HttpExchange;
}

/** The server could not be reached. `code` is the network error's. */
model Unreachable {
  error: string;
  code: string;
  http_exchange?: HttpExchange;
}

/** What the SCIM proxy will and will not do. */
model Limits {
  methods: string[];
  refusedHeaders: string[];

  /** Each refused header, lower-cased, to why. */
  refusedHeaderReasons: Record<string>;

  maxRequestBytes: int64;
  maxResponseBytes: int64 | null;
  callTimeoutMs: int64 | null;
  connectionTimeoutMs: int64 | null;
  maxRedirects: int64 | null;
  sslValidateDefault: true;
  addressPolicy: string;
  statusRule: string;
  whatThisIsNot: string;
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Perform one SCIM request. A SCIM error is a 200 carrying its status. */
@tag("SCIM")
@route("/scim")
@post
@operationId("scimCall")
op call(@body body: CallRequest): Ok<Answer> |
  BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<Unreachable>;

/**
 * What the SCIM proxy will and will not do, so the page can say so before a
 * call fails. A static deployment has no api and gets no answer.
 */
@tag("SCIM")
@route("/scim/limits")
@get
@operationId("scimLimits")
op limits(): Ok<Limits>;
