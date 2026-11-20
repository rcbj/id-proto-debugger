// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/wstrust.tsp
//
// The WS-Trust SOAP proxy: the page builds a RequestSecurityToken and this
// posts it to the STS server-side, because a SOAP endpoint almost never sends
// the CORS headers a browser needs. See docs/v0.9.5/wstrust.md.
//
// THE STS'S OWN ANSWER IS A 200 HERE, whatever its status: a SOAP Fault with
// a 500 is the most useful thing an STS says, so it is carried in
// `{ status, body }` rather than turned into an error. This service's 500
// means the STS could not be reached at all.
//
// The schema holds url and soap's presence and type, which the route itself
// checked. The URL's scheme stays in the handler; the address is the
// outbound agent's.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.WsTrust;

model ProxyRequest {
  /** The STS endpoint. */
  @refusal(#{ message: "url and soap are required." })
  @checkedInCode("api/server.js: an absolute http(s) URL (400, url must be an absolute http(s) URL.); the address is the outbound agent's")
  @minLength(1)
  url: string;

  /** The SOAP envelope, sent as written. */
  @refusal(#{ message: "url and soap are required." })
  @minLength(1)
  @passthrough
  soap: string;

  /**
   * "1.1" (text/xml and a SOAPAction header) or anything else for SOAP 1.2
   * (the action inside application/soap+xml). Compared after String(), so
   * the number 1.1 is SOAP 1.1 too. Absent is 1.2.
   */
  @checkedInCode("api/server.js: String(soapVersion) === \"1.1\" is SOAP 1.1; everything else is 1.2")
  soapVersion?: string | numeric | null;

  /** The WS-Addressing action, into SOAPAction or the content type. */
  @passthrough
  action?: string | null;

  /**
   * Only false, or the text "false" (a form sends text), turns certificate
   * verification off.
   */
  sslValidate?: boolean | string | null;
}

/** What the STS answered, whatever its status. */
model StsAnswer {
  /** The STS's HTTP status. */
  status: int32;

  /** Its body as text: an RSTR, an RSTRC or a SOAP Fault. */
  body: string;
}

@tag("WS-Trust")
@route("/wstrust")
@post
@operationId("wstrustProxy")
op proxy(
  @header contentType: "application/json" |
    "application/x-www-form-urlencoded",
  @body body: ProxyRequest,
): IdProtoDebugger.Api.Ok<StsAnswer> |
  IdProtoDebugger.Api.BadRequest<IdProtoDebugger.Api.Refusal |
    IdProtoDebugger.Api.ModelRefusal> | {
    /** The STS could not be reached: a name, a refusal, a timeout, a cap. */
    @statusCode statusCode: 500;
    @body body: IdProtoDebugger.Api.Refusal;
  };
