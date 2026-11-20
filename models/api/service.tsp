// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/service.tsp
//
// The api's own endpoints: liveness, and the record of answers that did not
// match this document.

import "@typespec/http";
import "@typespec/openapi";
import "./common.tsp";

using Http;
using OpenAPI;

namespace IdProtoDebugger.Api.Service;

/** The liveness answer. */
model Health {
  message: "Success";
}

/** Whether the api is up. Touches nothing beyond the process. */
@tag("Service")
@route("/healthcheck")
@get
@operationId("healthcheck")
op healthcheck(): Ok<Health>;

/**
 * One answer that did not match its operation's response schema. Recorded
 * only where `validateResponses` is on, which is a test configuration; the
 * answer itself was sent unchanged. No member value is recorded, only where
 * the schema and the answer disagreed, because an answer can carry a token.
 */
model ModelGap {
  operationId: string;
  status: int32;
  instancePath: string;
  keyword: string;
  message: string;
  count: int32;
}

/** Every recorded gap since the process started. */
model ModelGaps {
  validateResponses: true;
  gaps: ModelGap[];
}

/**
 * The answers this process sent that its API document does not describe.
 * Answers 404 where `validateResponses` is off — the record is not kept.
 */
@tag("Service")
@route("/model/gaps")
@get
@operationId("modelGaps")
op modelGaps(): Ok<ModelGaps> | {
  @statusCode statusCode: 404;
  @body body: IdProtoDebugger.Api.Refusal;
};

/** The API document itself: this file's output, OpenAPI 3.1. */
@tag("Service")
@route("/api-docs.json")
@get
@operationId("apiDocument")
op apiDocument(): Ok<Record<unknown>>;

/**
 * The API document in Swagger UI (swagger-ui-dist, served from this api's
 * own node_modules under /api-docs/assets/, which is static and outside this
 * document).
 */
@tag("Service")
@route("/api-docs")
@get
@operationId("apiDocumentIndex")
op apiDocumentIndex(): {
  @statusCode statusCode: 200;
  @header contentType: "text/html";
  @body body: string;
};

/** The explorer's initializer script. */
@tag("Service")
@route("/api-docs/init.js")
@get
@operationId("apiDocumentInit")
op apiDocumentInit(): {
  @statusCode statusCode: 200;
  @header contentType: "application/javascript";
  @body body: string;
};

/** Every operation in the API document, as a page with no script. */
@tag("Service")
@route("/api-docs/operations")
@get
@operationId("apiOperations")
op apiOperations(): {
  @statusCode statusCode: 200;
  @header contentType: "text/html";
  @body body: string;
};
