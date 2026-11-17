// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/common.tsp
//
// What more than one endpoint family answers.

import "@typespec/http";
import "../lib/debugger_lib.tsp";

using Http;

namespace IdProtoDebugger.Api;

/**
 * A request this service refused, or a call it could not complete. `error`
 * is a sentence for a person; `code`, where the endpoint has one, is the
 * stable name a caller branches on.
 */
model Refusal {
  error: string;
  code?: string | null;
}

/**
 * The validator's own refusal: the body was not the JSON shape this
 * operation takes. `code` is always EMODELREQUEST, and `error` names the
 * member and what was wrong with it.
 */
model ModelRefusal {
  error: string;
  code: "EMODELREQUEST";
}

/** 400: this service refused the request, and says why. */
@error
model BadRequest<T> {
  @statusCode statusCode: 400;
  @body body: T;
}

/** 502: the far end could not be reached, or did not answer. */
@error
model BadGateway<T> {
  @statusCode statusCode: 502;
  @body body: T;
}

/** 200 with a JSON body. */
model Ok<T> {
  @statusCode statusCode: 200;
  @body body: T;
}

// ---------------------------------------------------------------------------
// The trace every proxied call attaches as `http_exchange` when its caller
// asks (`http_trace`): api/server.js's buildHttpTrace(). One model, because
// it is one function.
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
