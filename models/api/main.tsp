// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/main.tsp
//
// THE API SERVICE'S HTTP SURFACE. models/tools/generate.mjs emits it as
// common/model/openapi.json (OpenAPI 3.1); api/model_validate.js builds a
// request validator for every operation from that file, and in a test run
// holds every answer to it.
//
// One file per endpoint family, each in a namespace of its own, so an
// operationId names its family. The rule every family follows is in
// models/CLAUDE.md, "What a request model says": the schema refuses what no
// handler could use — a member of the wrong JSON type, a required member
// that is missing — and says NOTHING about the content of a protocol message
// the api forwards, which is marked @passthrough.

import "@typespec/http";
import "@typespec/openapi";
import "@typespec/openapi3";
import "../lib/debugger_lib.tsp";
import "./common.tsp";
import "./service.tsp";
import "./ldap.tsp";
import "./scim.tsp";
import "./ssf.tsp";
import "./gnap.tsp";

using Http;
using OpenAPI;

/**
 * The id-proto-debugger api: a guarded proxy and relay for the protocol
 * workflows a browser cannot complete on its own. Every endpoint that
 * connects anywhere does so to a target its caller names, under the address
 * policy, timeouts and caps of the api's configuration.
 */
@service(#{ title: "id-proto-debugger API" })
@info(#{ version: "model" })
@server(
  "/",
  "The api's own origin. Embedded, it is the debugger's origin + /api."
)
namespace IdProtoDebugger.Api;
