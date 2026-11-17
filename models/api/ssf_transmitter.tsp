// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/ssf_transmitter.tsp
//
// THE HOSTED SSF TRANSMITTER (#363): an OpenID SSF 1.0 transmitter this api
// runs on a page's behalf, so that a receiver which treats its partner as a
// full transmitter — discovery, a stream created AT the transmitter, status,
// subjects, verification, RFC 8936 poll — has something to talk to. The page
// signs every SET; this service holds the public key and delivers.
//
// TWO CALLERS. Four routes are the PAGE's, authorized by the owner key it
// was given at creation, and answer `{ error }` on a refusal. The rest are
// the RECEIVER's — SSF's own stream management API and the RFC 8936 poll
// endpoint, authorized by the receiver credential (RFC 6750) — and answer
// as SSF does: the stream configuration, an empty 200 or 204, or
// `{err, description}`. Discovery and the JWKS take no credential.
//
// WHERE THE CHECKS ARE. Every member of a receiver's request is
// @passthrough: a receiver under test may send anything, and the answer must
// be SSF's own refusal from api/ssf_transmitter.js rather than this
// validator's EMODELREQUEST. tests/api_ssf.js drives that module with no
// listener.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";
import "./ssf.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.SsfTransmitter;

alias Refusals = BadRequest<IdProtoDebugger.Api.Refusal |
  IdProtoDebugger.Api.ModelRefusal>;

alias SetError = IdProtoDebugger.Api.Ssf.SetError;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** A transmitter, as the page asks for one. */
model CreateRequest {
  /** A name for it, cut at 200 characters. */
  label?: string | null;

  /** The PUBLIC half of the key the page signs with, as a JWK Set. */
  @checkedInCode("api/ssf_transmitter.js: one to ten JWKs, each with a kty and no private member")
  @passthrough
  jwks?: unknown;

  /** The event type URIs this transmitter offers (events_supported). */
  @checkedInCode("api/ssf_transmitter.js: an array of at most 100 strings")
  @passthrough
  eventsSupported?: unknown;

  /** The bearer token receivers present; absent is generated. */
  @checkedInCode("api/ssf_transmitter.js: 16 to 512 characters, no whitespace")
  @passthrough
  receiverCredential?: unknown;

  /** How long it may go unused, in ms. */
  @checkedInCode("api/ssf_transmitter.js: a positive whole number, at most ssfTransmitterIdleTtlMs")
  idleTtlMs?: float64 | string | null;

  /** How long it lives, in ms. */
  @checkedInCode("api/ssf_transmitter.js: a positive whole number, at most ssfTransmitterTtlMs")
  ttlMs?: float64 | string | null;
}

/** A SET the page signed, for one of the transmitter's streams. */
model DeliverRequest {
  @checkedInCode("api/ssf_transmitter.js: a stream a receiver created here (404)")
  @passthrough
  stream_id?: unknown;

  /** The compact JWS. */
  @checkedInCode("api/ssf_transmitter.js: required, a compact JWS, at most ssfTransmitterMaxEventBytes")
  @passthrough
  token?: unknown;

  /** Only false or "false" turns off certificate verification of the
   *  receiver's push endpoint. */
  @checkedInCode("api/ssl_validate.js: only false or \"false\" turns verification off")
  sslValidate?: boolean | string | null;
}

/** Any request a receiver sends to the stream management API. */
model ReceiverRequest {
  @passthrough stream_id?: unknown;
  @passthrough events_requested?: unknown;
  @passthrough delivery?: unknown;
  @passthrough description?: unknown;
  @passthrough status?: unknown;
  @passthrough reason?: unknown;
  @passthrough subject?: unknown;
  @passthrough verified?: unknown;
  @passthrough state?: unknown;
}

/** An RFC 8936 poll request. */
model PollRequest {
  @passthrough maxEvents?: unknown;
  @passthrough returnImmediately?: unknown;
  @passthrough ack?: unknown;
  @passthrough setErrs?: unknown;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** SSF 1.0 section 7.1, the Transmitter Configuration Metadata. */
model Metadata {
  spec_version: string;
  issuer: string;
  jwks_uri: string;
  delivery_methods_supported: string[];
  configuration_endpoint: string;
  status_endpoint: string;
  add_subject_endpoint: string;
  remove_subject_endpoint: string;
  verification_endpoint: string;
  authorization_schemes: {
    spec_urn: string;
  }[];
  default_subjects: string;
}

/** SSF 1.0 section 8.1.1, as a receiver sees it. */
model Stream {
  stream_id: string;
  iss: string;
  aud: string;
  events_supported: string[];
  events_requested: string[];
  events_delivered: string[];
  delivery: {
    method: string;
    endpoint_url: string;
  };
  min_verification_interval: int32;
  description?: string;
}

/** A stream as the page sees it: the receiver's view and this service's
 *  state. Never the receiver's authorization_header. */
model OwnerStream {
  ...Stream;
  status: string;
  reason: string;
  subjects: unknown[];
  pushAuthorized: boolean;
  queued: int32;
  held: int32;
  createdAt: string;
}

/** One line of what happened at the transmitter. */
model LogRow {
  at: string;
  kind: string;
  stream_id?: string;
  jti?: string;
  detail?: string;
  status?: int32;
  accepted?: boolean;
  err?: string;
  description?: string;
}

/** A verification event the receiver asked for and the page owes. */
model Pending {
  stream_id: string;
  state: string;
  at: string;
}

/** The whole transmitter, as the page sees it. */
model Transmitter {
  id: string;
  label: string;
  issuer: string;
  discoveryUrl: string;
  `metadata`: Metadata;
  jwks: {
    keys: unknown[];
  };
  eventsSupported: string[];
  createdAt: string;
  expiresAt: string;
  streams: OwnerStream[];
  pendingVerifications: Pending[];
  log: LogRow[];
}

model Created {
  ok: true;
  transmitter: Transmitter;

  /** The page's credential for its own four routes. Shown once. */
  ownerKey: string;

  /** The bearer token receivers present. Shown once. */
  receiverCredential: string;

  note: string;
}

model Read {
  ok: true;
  transmitter: Transmitter;
}

model Deleted {
  ok: true;
  deleted: string;
}

/** What a push answered (RFC 8935 section 2.3 and 2.4). */
model PushOutcome {
  status: int32;
  accepted: boolean;
  err: string;
  description: string;
  detail: string;
}

model Delivered {
  ok: true;

  /** push, queued (poll), held (paused) or dropped (disabled). */
  action: string;

  jti: string;
  stream_id: string;

  /** What about the SET does not match the stream. Delivered anyway. */
  findings: string[];

  note: string;
  push?: PushOutcome;
}

/** RFC 8936 section 2.3. */
model Polled {
  sets: Record<string>;
  moreAvailable: boolean;
}

model StatusAnswer {
  stream_id: string;
  status: string;
  reason?: string;
}

model OwnerNotFound {
  @statusCode statusCode: 404;
  @body body: IdProtoDebugger.Api.Refusal;
}

model OwnerUnauthorized {
  @statusCode statusCode: 401;
  @header("WWW-Authenticate") challenge: string;
  @body body: IdProtoDebugger.Api.Refusal;
}

alias OwnerRefusals = OwnerNotFound | OwnerUnauthorized;

model NotFound {
  @statusCode statusCode: 404;
  @body body: SetError;
}

model Unauthorized {
  @statusCode statusCode: 401;
  @header("WWW-Authenticate") challenge: string;
  @body body: SetError;
}

model Invalid {
  @statusCode statusCode: 400;
  @body body: SetError;
}

model Conflict {
  @statusCode statusCode: 409;
  @body body: SetError;
}

alias ReceiverRefusals = Unauthorized | NotFound | Invalid;

model Empty200 {
  @statusCode statusCode: 200;
}

model Empty204 {
  @statusCode statusCode: 204;
}

// ---------------------------------------------------------------------------
// The page's operations.
// ---------------------------------------------------------------------------

/** Host a transmitter. Refused when off, at a limit, or given a private key. */
@tag("Shared Signals")
@route("/ssf/transmitter")
@post
@operationId("ssfTransmitterCreate")
@checkedInCode("api/ssf_transmitter.js: ssfTransmitterEnabled, ssfTransmitterMaxInstances and ssfTransmitterMaxInstancesPerCaller, counted by the caller's address")
op create(@body body: CreateRequest): Ok<Created> | Refusals;

/** The transmitter, its streams, what is pending and what happened. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}")
@get
@operationId("ssfTransmitterRead")
op read(
  @path id: string,
  @header("Authorization") authorization?: string,
): Ok<Read> | OwnerRefusals;

/** Delete it. Its streams and queues go with it. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}")
@delete
@operationId("ssfTransmitterDelete")
op remove(
  @path id: string,
  @header("Authorization") authorization?: string,
): Ok<Deleted> | OwnerRefusals;

/** Deliver a SET the page signed: pushed now, or queued for a poll. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/deliver")
@post
@operationId("ssfTransmitterDeliver")
op deliver(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: DeliverRequest,
): Ok<Delivered> | OwnerRefusals | Refusals;

// ---------------------------------------------------------------------------
// The receiver's operations.
// ---------------------------------------------------------------------------

/** SSF 1.0 section 7: the configuration metadata. Public. */
@tag("Shared Signals")
@route("/.well-known/ssf-configuration/ssf/transmitter/{id}")
@get
@operationId("ssfTransmitterMetadata")
op configurationMetadata(@path id: string): Ok<Metadata> | NotFound;

/** The public keys every SET verifies against. Public. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/jwks")
@get
@operationId("ssfTransmitterJwks")
op jwks(@path id: string): {
  @statusCode statusCode: 200;
  @header contentType: "application/jwk-set+json";
  @body body: {
    keys: unknown[];
  };
} | NotFound;

/** SSF 1.0 section 8.1.1.1: create a stream. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/stream")
@post
@operationId("ssfTransmitterStreamCreate")
op createStream(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): {
  @statusCode statusCode: 201;
  @body body: Stream;
} | ReceiverRefusals | Conflict;

/** SSF 1.0 section 8.1.1.2: one stream, or all of them. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/stream")
@get
@operationId("ssfTransmitterStreamRead")
op readStream(
  @path id: string,
  @header("Authorization") authorization?: string,
  @query stream_id?: string,
): Ok<Stream | Stream[]> | ReceiverRefusals;

/** SSF 1.0 section 8.1.1.3: update the Receiver-Supplied members given. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/stream")
@patch
@operationId("ssfTransmitterStreamUpdate")
op updateStream(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Ok<Stream> | ReceiverRefusals;

/** SSF 1.0 section 8.1.1.4: replace them. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/stream")
@put
@operationId("ssfTransmitterStreamReplace")
op replaceStream(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Ok<Stream> | ReceiverRefusals;

/** SSF 1.0 section 8.1.1.5: delete a stream. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/stream")
@delete
@operationId("ssfTransmitterStreamDelete")
op deleteStream(
  @path id: string,
  @header("Authorization") authorization?: string,
  @query stream_id?: string,
): Empty204 | ReceiverRefusals;

/** SSF 1.0 section 8.1.2.1: a stream's status. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/status")
@get
@operationId("ssfTransmitterStatusRead")
op readStatus(
  @path id: string,
  @header("Authorization") authorization?: string,
  @query stream_id?: string,
): Ok<StatusAnswer> | ReceiverRefusals;

/** SSF 1.0 section 8.1.2.2: change it. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/status")
@post
@operationId("ssfTransmitterStatusUpdate")
op updateStatus(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Ok<StatusAnswer> | ReceiverRefusals;

/** SSF 1.0 section 8.1.3.2: add a subject. An empty 200. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/subjects/add")
@post
@operationId("ssfTransmitterSubjectAdd")
op addSubject(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Empty200 | ReceiverRefusals;

/** SSF 1.0 section 8.1.3.3: remove one. A 204. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/subjects/remove")
@post
@operationId("ssfTransmitterSubjectRemove")
op removeSubject(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Empty204 | ReceiverRefusals;

/** SSF 1.0 section 8.1.4.2: ask for a verification event. 204: queued,
 *  for the page to sign and send. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/verify")
@post
@operationId("ssfTransmitterVerify")
op verify(
  @path id: string,
  @header("Authorization") authorization?: string,
  @body body: ReceiverRequest,
): Empty204 | ReceiverRefusals;

/** RFC 8936: poll a stream. What is returned stays queued until acked. */
@tag("Shared Signals")
@route("/ssf/transmitter/{id}/poll/{streamId}")
@post
@operationId("ssfTransmitterPoll")
op poll(
  @path id: string,
  @path streamId: string,
  @header("Authorization") authorization?: string,
  @body body: PollRequest,
): Ok<Polled> | ReceiverRefusals;
