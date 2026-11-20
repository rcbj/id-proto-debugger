// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/saml.tsp
//
// SAML 2.0 and SAML 1.1: the metadata proxy, request signing, the artifact
// back-channel's context, and the landings an IDENTITY PROVIDER'S BROWSER
// reaches — the assertion consumer and Single Logout services — together with
// the stash the page reads what arrived there from. See docs/v0.9.5/saml.md and
// docs/v0.9.5/saml11.md.
//
// TWO KINDS OF CALLER, and the rule is different for each.
//
// * The page (/samlmetadata, /samlsign, /samlartifactctx, /samlresponse)
//   sends JSON or a query string this repository wrote. Its members are
//   typed, and a member of the wrong type is refused.
//
// * An identity provider (/samlacs, /samlacs/artifact, /samlslo) sends a
//   FORM, or a query string, that somebody else wrote — and a debugger's
//   landing exists to show what it sent. So its request is validated for
//   the ENVELOPE ONLY: every member is optional, every member is `unknown`,
//   and a field nobody expected, a repeated one or a missing one still
//   reaches the page. The one check those landings make, that the relay
//   state is text, stays in the handler, because it answers as text/plain
//   and a schema refusal is JSON.
//
// The landings answer a browser, not a script: a 302 to the results page,
// whose Location carries the stash id, or a sentence in text/plain.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Saml;

// ---------------------------------------------------------------------------
// Answers more than one operation gives.
// ---------------------------------------------------------------------------

/** A sentence for the person at the browser, as text/plain. */
model PlainText<Status> {
  @statusCode statusCode: Status;
  @header contentType: "text/plain";
  @body body: string;
}

/**
 * 302 to the debugger's results page. The Location carries the id the page
 * reads the stashed message back with, from GET /samlresponse.
 */
model SentOn {
  @statusCode statusCode: 302;
  @header location: string;
}

/**
 * What a landing stored, as it arrived. Normally text; a field the far end
 * sent twice is stored as the list it was parsed into, and a bracketed one
 * as an object, because the landing passes on what it was given.
 */
alias Arrived = string | unknown[] | Record<unknown>;

/** A stashed exchange. The SAML and WS-Federation landings share one. */
model Exchange {
  /** The decoded protocol message (or a WS-Federation wresult verbatim). */
  responseXml: Arrived;

  /** The RelayState, TARGET or wctx that came back with it. Empty if none. */
  relayState: Arrived;
}

// QUERY PARAMETERS ARE ALIASES, NOT MODELS. A named model spread into an
// operation is emitted as `$ref`s into components/parameters, and
// api/model_validate.js reads a parameter's `in` and `schema` directly — so
// a parameter behind a `$ref` would be documented and never checked. An
// alias is inlined into each operation that spreads it.

/** Read a stashed exchange by the id its landing redirected with. */
alias ExchangeQuery = {
  /** The id from the landing's Location. Unknown or expired is a 404. */
  @query
  @checkedInCode("api/server.js: looked up in the ten-minute exchange stash; absent, unknown or expired answers 404")
  id?: string;
};

alias ExchangeAnswers = Ok<Exchange> |
  BadRequest<IdProtoDebugger.Api.ModelRefusal> | {
    @statusCode statusCode: 404;
    @body body: IdProtoDebugger.Api.Refusal;
  };

// ---------------------------------------------------------------------------
// GET /samlmetadata
// ---------------------------------------------------------------------------

alias MetadataQuery = {
  /**
   * The metadata URL, BASE64-encoded so it survives query escaping. Its
   * scheme is checked after decoding.
   */
  @query
  @checkedInCode("api/server.js: decoded from base64, then must be an absolute http(s) URL (400, url must be an absolute http(s) URL.)")
  url?: string;
};

/** The metadata document, as the server sent it. */
model Metadata {
  @statusCode statusCode: 200;
  @header contentType: "application/xml";
  @body body: string;
}

/**
 * The metadata server answered with an error status: that status, and its
 * body as text.
 */
model MetadataServerError {
  @minValue(400)
  @maxValue(599)
  @statusCode
  statusCode: int32;

  @header contentType: "text/plain";
  @body body: string;
}

/**
 * Fetch an identity provider's SAML metadata server-side, because the
 * descriptor endpoint sends no CORS headers. The URL is the caller's, under
 * the address policy, timeouts and caps.
 */
@tag("SAML")
@route("/samlmetadata")
@get
@operationId("samlMetadata")
op fetchMetadata(...MetadataQuery): Metadata |
  BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal> |
  {
    /** The metadata could not be fetched: a name, a timeout, a cap. */
    @statusCode statusCode: 500;
    @body body: IdProtoDebugger.Api.Refusal;
  } | MetadataServerError;

// ---------------------------------------------------------------------------
// POST /samlsign
// ---------------------------------------------------------------------------

/** Sign a request for the binding it is sent on. */
model SignRequest {
  /** The unsigned AuthnRequest or LogoutRequest. */
  @refusal(#{ message: "xml and privateKeyPem are required." })
  @minLength(1)
  @passthrough
  xml: string;

  /** The service provider's RSA private key, PEM. Never stored. */
  @refusal(#{ message: "xml and privateKeyPem are required." })
  @minLength(1)
  privateKeyPem: string;

  /** post, artifact, or anything else for the HTTP-Redirect binding. */
  @checkedInCode("api/server.js: post and artifact are named; every other value, and none, is the redirect binding")
  binding?: string | null;

  /** The SignatureMethod URI. Absent is rsa-sha256. */
  @checkedInCode("common/xmldsig.js: rsaSigAlgRefusal() — an RSA method this signer implements (400 samlsign: SignatureMethod … is not an RSA method …)")
  sigAlg?: string | null;

  /** The identity provider's endpoint. Absent: only the query string. */
  @passthrough
  destination?: string | null;

  /** A certificate for KeyInfo, PEM. Absent: no KeyInfo. */
  certPem?: string | null;

  /** Sent as written. The artifact binding replaces it with its handle. */
  @passthrough
  relayState?: string | null;

  /** AuthnRequest or LogoutRequest. Read, and changes nothing. */
  @passthrough
  rootElement?: string | null;

  /** The artifact binding only: the Artifact Resolution Service's URL. */
  arsUrl?: string | null;

  /** The artifact binding only: the <Issuer> of the ArtifactResolve. */
  @passthrough
  spEntityId?: string | null;
}

/** The HTTP-Redirect binding: a signed query string. */
model SignedRedirect {
  mode: "redirect";

  /** destination + the query string, or the query string alone. */
  location: string;

  /** SAMLRequest[&RelayState]&SigAlg&Signature. */
  queryString: string;
}

/** The HTTP-POST binding: the form the browser auto-submits. */
model SignedPost {
  mode: "post";
  location: string;
  params: {
    SAMLRequest: string;
    RelayState?: string;
  };

  /** The enveloped-signed document, for display. */
  signedXml: string;
}

@tag("SAML")
@route("/samlsign")
@post
@operationId("samlSign")
op sign(@body body: SignRequest): Ok<SignedRedirect | SignedPost> |
  BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal> |
  {
    /** The signer failed: a key that is not a key, typically. */
    @statusCode statusCode: 500;
    @body body: IdProtoDebugger.Api.Refusal;
  };

// ---------------------------------------------------------------------------
// POST /samlartifactctx
// ---------------------------------------------------------------------------

/** WS-Addressing headers for the artifact back-channel's SOAP envelope. */
model WsAddressing {
  /** Only a truthy value adds the headers. */
  enabled?: boolean | null;

  /** wsa:To. Empty is the ARS URL. */
  @passthrough
  to?: string | null;

  /** wsa:MessageID. Empty is a fresh urn:uuid. */
  @passthrough
  messageId?: string | null;

  @passthrough
  action?: string | null;

  @passthrough
  replyTo?: string | null;

  @passthrough
  from?: string | null;
}

/**
 * What resolving an artifact will need, registered before the request goes
 * out. The key is optional (neither version requires the resolution request
 * to be signed); the address is not.
 */
model ArtifactContextRequest {
  /**
   * The Artifact Resolution Service (2.0) or SAML responder (1.1). Fetched
   * later, by the landing, under the address policy.
   */
  @refusal(#{ message: "arsUrl is required." })
  @minLength(1)
  arsUrl: string;

  /** Signs the resolution request when present; unsigned when not. */
  privateKeyPem?: string | null;

  certPem?: string | null;

  @passthrough
  spEntityId?: string | null;

  @checkedInCode("common/xmldsig.js: checked when the resolution request is signed; a failure is the landing's 500")
  sigAlg?: string | null;

  /** "1.1" for a SAML 1.1 responder; anything else is SAML 2.0. */
  @checkedInCode("api/server.js: exactly \"1.1\" selects SAML 1.1; every other value is 2.0")
  samlVersion?: string | null;

  wsa?: WsAddressing | null;
}

/** The handle to carry in RelayState (or SAML 1.1's TARGET). */
model ArtifactContext {
  /** art:<id>. Expires with the exchange stash. */
  relayState: string;
}

@tag("SAML")
@route("/samlartifactctx")
@post
@operationId("samlArtifactContext")
op artifactContext(@body body: ArtifactContextRequest): Ok<ArtifactContext> |
  BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal>;

// ---------------------------------------------------------------------------
// The landings: assertion consumer and Single Logout.
// ---------------------------------------------------------------------------

/**
 * What an identity provider sends, in a form or a query string. Nothing
 * here is refused by the schema: see the head of this file.
 */
model Landing {
  /** POST binding: base64 XML. Redirect binding: DEFLATE then base64. */
  @passthrough
  SAMLResponse?: unknown;

  /** SAML 2.0's relay state, returned byte for byte. */
  @checkedInCode("api/server.js: must be a string, else 400 text/plain ACS: invalid RelayState. (also TARGET's)")
  @passthrough
  RelayState?: unknown;

  /** SAML 1.1's relay state, read when RelayState is absent. */
  @passthrough
  TARGET?: unknown;

  /** An artifact, resolved over the SOAP back-channel. */
  @checkedInCode("api/server.js: resolved with the context RelayState names (art:<id>); no context, no Response or a failed call is a 500")
  @passthrough
  SAMLart?: unknown;
}

/** The same members, in the query string. */
alias LandingQuery = {
  @query @passthrough SAMLResponse?: unknown;
  @query @passthrough RelayState?: unknown;
  @query @passthrough TARGET?: unknown;
  @query @passthrough SAMLart?: unknown;
};

alias LandingAnswers = SentOn | PlainText<400> | PlainText<500>;

/**
 * What the identity provider's browser POSTs: a form, or JSON. A JSON array
 * is accepted too and read as no member at all, because the landing has
 * always answered one (with its "no SAMLResponse" sentence) rather than
 * refused it.
 */
alias LandingBody = {
  @header contentType: "application/x-www-form-urlencoded" |
    "application/json";
  @body body: Landing | unknown[];
};

/**
 * The assertion consumer, POST: a SAMLResponse is decoded, stashed and the
 * browser sent on to the results page; a SAMLart is resolved first. The
 * query string is read too, after the form.
 */
@tag("SAML")
@route("/samlacs")
@post
@operationId("samlAcsPost")
op acsPost(...LandingBody, ...LandingQuery): LandingAnswers;

/** The assertion consumer, GET: the redirect binding's query string. */
@tag("SAML")
@route("/samlacs")
@get
@operationId("samlAcsGet")
op acsGet(...LandingQuery): LandingAnswers;

/**
 * SAML 1.1's Browser/Artifact consumer, at a location of its own because a
 * 1.1 service provider picks the profile by the consumer it names. A SAMLart
 * and TARGET arrive on a GET.
 */
@tag("SAML")
@route("/samlacs/artifact")
@get
@operationId("samlAcsArtifact")
op acsArtifact(...LandingQuery): LandingAnswers;

/** Single Logout, POST: a LogoutResponse (or LogoutRequest) to show. */
@tag("SAML")
@route("/samlslo")
@post
@operationId("samlSloPost")
op sloPost(...LandingBody, ...LandingQuery): LandingAnswers;

/** Single Logout, GET: the redirect binding's query string. */
@tag("SAML")
@route("/samlslo")
@get
@operationId("samlSloGet")
op sloGet(...LandingQuery): LandingAnswers;

/** Read back what a SAML landing stashed. */
@tag("SAML")
@route("/samlresponse")
@get
@operationId("samlResponse")
op response(...ExchangeQuery): ExchangeAnswers;
