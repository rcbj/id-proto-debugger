// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/gnap.tsp
//
// GNAP (RFC 9635): one request the PAGE has already signed, forwarded as it
// was built, and the limits document. The proof covers the URL and the body,
// so this service sends exactly that URL and that body string; the signing
// key never arrives here. The one exception is the mtls proof, whose
// certificate and key are presented on a connection opened for that one
// call. See docs/gnap.md.
//
// THE THREE OUTCOMES: a refusal by this service is a 400, a network failure
// is a 502, and a GNAP error from the authorization server is a 200 carrying
// its status and error code.
//
// WHERE THE CHECKS ARE. The schema holds the JSON types. Every check on a
// value is api/gnap_proxy.js's describeRequest(), which tests/api_gnap.js
// drives with no server at all.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";
import "./scim.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Gnap;


// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** One signed GNAP request, as the page built it. */
model CallRequest {
  /** The ABSOLUTE URL the page signed. */
  @checkedInCode("api/gnap_proxy.js: required, and an absolute http:// or https:// URL; the address policy applies when it is called")
  url?: string | null;

  /** GET, POST, PATCH, DELETE or OPTIONS, any case. Absent is POST. */
  @checkedInCode("api/gnap_proxy.js: one of the five RFC 9635 methods, compared upper-cased")
  method?: string | null;

  /** Header name to value, the proof's Signature, Signature-Input and
   *  Content-Digest among them; each value is sent as text. */
  @checkedInCode("api/gnap_proxy.js: each name a token, no framing or hop-by-hop header, no CR or LF in a value")
  @passthrough
  headers?: Record<unknown> | null;

  /** The body the proof covers: text, sent byte for byte, or JSON. */
  @checkedInCode("api/gnap_proxy.js: none on a GET or an OPTIONS; at most gnapMaxRequestBytes once serialised")
  @passthrough
  body?: unknown;

  /** The mtls proof's certificate (RFC 9635 section 7.3.2), in PEM. */
  @checkedInCode("api/gnap_proxy.js: with clientKeyPem or not at all, at most 64 KiB, an https url, a PEM certificate whose key clientKeyPem is")
  clientCertificatePem?: string | null;

  /** The mtls proof's private key, unencrypted PEM. Never echoed. */
  @checkedInCode("api/gnap_proxy.js: with clientCertificatePem or not at all, at most 64 KiB, an unencrypted PEM private key")
  clientKeyPem?: string | null;

  /** Only false or "false" turns off certificate verification. */
  @checkedInCode("api/gnap_proxy.js: only false or \"false\" turns verification off")
  sslValidate?: boolean | string | null;

  /** true or "true" attaches http_exchange to the answer. */
  @checkedInCode("api/server.js: only true or \"true\" asks for the trace")
  http_trace?: boolean | string | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/**
 * What the authorization server said. `ok` is a 2xx; `error` and
 * `description` are its GNAP error, whether it sent a bare code or an
 * object; `notJson` is the parse error of a body that is not JSON.
 */
model Answer {
  status: int32;
  ok: boolean;
  headers: Record<unknown>;
  body: unknown;
  rawBody: string;
  error: string;
  description: string;
  noBody: boolean;
  notJson: string;
  http_exchange?: HttpExchange;
}

/** The server could not be reached. `code` is the network error's. */
model Unreachable {
  error: string;
  code: string;
  http_exchange?: HttpExchange;
}

/** What the GNAP relay will forward. */
model Limits {
  methods: string[];
  refusedHeaders: string[];
  maxRequestBytes: int64;
  maxResponseBytes: int64 | null;
  callTimeoutMs: int64 | null;
  connectionTimeoutMs: int64 | null;
  maxRedirects: int64 | null;
  sslValidateDefault: true;

  /** Whether the address layers of the policy are on here. */
  addressPolicyEnabled: boolean;

  /** The proofs a forwarded request may carry. */
  proofs: string[];

  mtls: string;
  statusRule: string;
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Forward one signed GNAP request. A GNAP error is a 200 carrying its
 *  status. */
@tag("GNAP")
@route("/gnap/call")
@post
@operationId("gnapCall")
op call(@body body: CallRequest): Ok<Answer> |
  BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<Unreachable>;

/**
 * What the GNAP relay will forward. A static deployment has no api, and the
 * page then calls the authorization server itself.
 */
@tag("GNAP")
@route("/gnap/limits")
@get
@operationId("gnapLimits")
op limits(): Ok<Limits>;
