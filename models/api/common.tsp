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
