// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/wsfed.tsp
//
// WS-Federation's Passive Requestor Profile landing, and the stash the page
// reads what arrived there from. See docs/v0.9.6/wsfed.md.
//
// The landing is what an IDENTITY PROVIDER'S BROWSER reaches — wa, wresult
// and wctx in a form or a query string somebody else wrote — so, like the
// SAML landings (saml.tsp), its request is validated for the ENVELOPE ONLY:
// every member optional and `unknown`, and nothing an identity provider
// sends is refused. wresult is RAW XML, not base64, and is stored verbatim.
// It always answers with a 302: to the results page with the stash id for a
// sign-in, or with `signout=<wa>` for a sign-out, which carries no token.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";
import "./saml.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.WsFed;

/** What the identity provider sends, in a form or a query string. */
model Landing {
  /** wsignin1.0, wsignout1.0, wsignoutcleanup1.0. Echoed on a sign-out. */
  @passthrough
  wa?: unknown;

  /** The RequestSecurityTokenResponse, raw XML. Absent is a sign-out. */
  @passthrough
  wresult?: unknown;

  /** The context the relying party sent, returned as written. */
  @passthrough
  wctx?: unknown;
}

/** The same members, in the query string. */
alias LandingQuery = {
  @query @passthrough wa?: unknown;
  @query @passthrough wresult?: unknown;
  @query @passthrough wctx?: unknown;
};

/** 302 to the results page: `?id=` for a sign-in, `?signout=` for not. */
model SentOn {
  @statusCode statusCode: 302;
  @header location: string;
}

alias LandingAnswers = SentOn | IdProtoDebugger.Api.Saml.PlainText<500>;

/**
 * The passive sign-in landing, POST: the identity provider's auto-submitted
 * form. The query string is read too, after the form.
 */
@tag("WS-Federation")
@route("/wsfed")
@post
@operationId("wsfedLandingPost")
op landingPost(
  @header contentType: "application/x-www-form-urlencoded" |
    "application/json",
  /** A JSON array is read as no member at all: a sign-out, as always. */
  @body body: Landing | unknown[],
  ...LandingQuery,
): LandingAnswers;

/** The landing, GET: wsignoutcleanup1.0 is delivered as one. */
@tag("WS-Federation")
@route("/wsfed")
@get
@operationId("wsfedLandingGet")
op landingGet(...LandingQuery): LandingAnswers;

/**
 * Read back what the landing stashed. The same stash as GET /samlresponse,
 * so either reads either's id.
 */
@tag("WS-Federation")
@route("/wsfedresponse")
@get
@operationId("wsfedResponse")
op response(...IdProtoDebugger.Api.Saml.ExchangeQuery):
  IdProtoDebugger.Api.Saml.ExchangeAnswers;
