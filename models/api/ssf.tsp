// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/ssf.tsp
//
// SHARED SIGNALS (OpenID SSF 1.0, RFC 8417, RFC 8935, RFC 8936): one call to
// a transmitter on the page's behalf, the limits document, and the RFC 8935
// PUSH RECEIVER this api hosts because a page is not an HTTP server. See
// docs/v0.9.5/ssf.md.
//
// THE CALL keeps the SCIM proxy's three outcomes: a refusal by this service
// is a 400, a network failure is a 502, and an SSF error from the
// transmitter is a 200 carrying its status and RFC 8935 `{err,
// description}`.
//
// THE RECEIVER is four routes, and one of them is not this service's caller
// talking: POST /ssf/receiver/{id} is a TRANSMITTER delivering a Security
// Event Token, so its body is the compact JWS itself
// (application/secevent+jwt, no JSON around it) and its answers are RFC
// 8935's — 202 with no body, or `{err, description}`.
//
// WHERE THE CHECKS ARE. The schema holds the JSON types. Every check on a
// value is api/ssf_proxy.js's or api/ssf_receiver.js's, which
// tests/api_ssf.js drives with no listener and no transmitter.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";
import "./scim.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Ssf;

alias Refusals = BadRequest<IdProtoDebugger.Api.Refusal |
  IdProtoDebugger.Api.ModelRefusal>;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** One call to a transmitter's endpoint, as the page composed it. */
model CallRequest {
  /** The ABSOLUTE URL, from the transmitter's configuration metadata. */
  @checkedInCode("api/ssf_proxy.js: required, and an absolute http:// or https:// URL; the address policy applies when it is called")
  url?: string | null;

  /** GET, POST, PUT, PATCH or DELETE, any case. Absent is GET. */
  @checkedInCode("api/ssf_proxy.js: one of the five SSF 1.0 methods, compared upper-cased")
  method?: string | null;

  /** Header name to value; each value is sent as text, null is dropped. */
  @checkedInCode("api/ssf_proxy.js: each name a token, no framing or hop-by-hop header, no CR or LF in a value")
  @passthrough
  headers?: Record<unknown> | null;

  /** The request document: JSON, or text sent exactly as given. A DELETE
   *  may carry one, since it names the stream it deletes. */
  @checkedInCode("api/ssf_proxy.js: none on a GET; at most ssfMaxRequestBytes once serialised")
  @passthrough
  body?: unknown;

  /** Only false or "false" turns off certificate verification. */
  @checkedInCode("api/ssf_proxy.js: only false or \"false\" turns verification off")
  sslValidate?: boolean | string | null;

  /** true or "true" attaches http_exchange to the answer. */
  @checkedInCode("api/server.js: only true or \"true\" asks for the trace")
  http_trace?: boolean | string | null;
}

/**
 * A push inbox, as the page asks for one. Each of the three numbers may be
 * less than this service's setting of the same name, never more; absent is
 * that setting.
 */
model ReceiverRequest {
  /** A name for the inbox, cut at 200 characters. */
  label?: string | null;

  /** The Authorization header every push must carry: the stream's
   *  delivery.authorization_header. Empty is an OPEN inbox. */
  @checkedInCode("api/ssf_receiver.js: at most 4096 characters once trimmed")
  @passthrough
  authorization?: string | null;

  /** How long the inbox may go unused, in ms. */
  @checkedInCode("api/ssf_receiver.js: a positive whole number, at most ssfReceiverIdleTtlMs")
  idleTtlMs?: float64 | string | null;

  /** How long the inbox lives, in ms. */
  @checkedInCode("api/ssf_receiver.js: a positive whole number, at most ssfReceiverTtlMs")
  ttlMs?: float64 | string | null;

  /** How many bytes of events it holds before the oldest are dropped. */
  @checkedInCode("api/ssf_receiver.js: a positive whole number, at most ssfReceiverMaxInboxBytes and at least ssfReceiverMaxEventBytes")
  maxInboxBytes?: float64 | string | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/**
 * What the transmitter said. `ok` is a 2xx, and a 204 with no body is one
 * (`noBody`). `err` and `description` are RFC 8935 section 2.4's, which SSF
 * uses on every endpoint; `notJson` is the parse error of a body that is
 * not JSON.
 */
model Answer {
  status: int32;
  ok: boolean;
  headers: Record<unknown>;
  body: unknown;
  rawBody: string;
  err: string;
  description: string;
  noBody: boolean;
  notJson: string;
  http_exchange?: HttpExchange;
}

/** The transmitter could not be reached. `code` is the network error's. */
model Unreachable {
  error: string;
  code: string;
  http_exchange?: HttpExchange;
}

/** The push receiver's own bounds, as GET /ssf/limits reports them. */
model ReceiverLimits {
  enabled: boolean;
  ttlMs: float64;
  idleTtlMs: float64;
  maxInboxes: float64;
  maxInboxesPerCaller: float64;
  maxEvents: float64;
  maxEventBytes: float64;
  maxInboxBytes: float64;
  ceilings: string;

  /** How many inboxes this process holds now. */
  held: int32;

  mediaType: "application/secevent+jwt";

  /** This service checks no signature: it holds no transmitter's key. */
  verifies: false;

  note: string;
  doesNotVerify: string;
}

/** The hosted transmitter's bounds (#363), as GET /ssf/limits reports
 *  them. See models/api/ssf_transmitter.tsp. */
model TransmitterLimits {
  enabled: boolean;
  ttlMs: float64;
  idleTtlMs: float64;
  maxInstances: float64;
  maxInstancesPerCaller: float64;
  maxStreams: float64;
  maxQueued: float64;
  maxEventBytes: float64;

  /** How many transmitters this process hosts now. */
  held: int32;

  /** This service signs nothing: the page does. */
  signs: false;

  note: string;
}

/** What the SSF proxy will and will not do, and the receiver's bounds. */
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
  receiver: ReceiverLimits | null;
  transmitter?: TransmitterLimits;
  addressPolicy: string;

  /** Whether the address layers of the policy are on here. */
  addressPolicyEnabled: boolean;

  statusRule: string;
  deliveryFromTheBrowser: string;
  whatThisIsNot: string;
}

/** One inbox, as every receiver answer describes it. */
model Inbox {
  /** 32 hex digits; the inbox's whole address. */
  id: string;

  label: string;
  createdAt: string;

  /** Empty until the first push. */
  lastPushAt: string;

  /** Whether pushes must carry an Authorization header. */
  authenticated: boolean;

  idleTtlMs: float64;
  ttlMs: float64;
  maxInboxBytes: float64;

  /** The sooner of the two expiries. */
  expiresAt: string;

  pushes: int32;
  dropped: int32;
  waiting: int32;
}

/** A new inbox, and the URL a stream's delivery.endpoint_url takes. */
model Created {
  ok: true;
  inbox: Inbox;

  /** This api's address as the caller reached it, plus the inbox's path. */
  deliveryEndpoint: string;

  note: string;
  authentication: string;
}

/**
 * RFC 8935 section 2.4: the SET Error Code (`invalid_request`,
 * `authentication_failed`, ...) and the sentence that explains it.
 */
model SetError {
  err: string;
  description: string;
}

/**
 * One delivery, as it arrived. `header` and `claims` are the decoded JWS
 * header and payload, or null with `problem` saying why; nothing is
 * verified.
 */
model Event {
  seq: int32;
  at: string;
  token: string;
  bytes: int32;

  /** The media type the push named, lower-cased, parameters dropped. */
  contentType: string;

  /** Whether that was application/secevent+jwt. */
  correctMediaType: boolean;

  /** Whether the push carried an Authorization header. */
  authorization: boolean;

  header: unknown;
  claims: unknown;
  problem: string;
}

/** Everything since the cursor. */
model Drained {
  ok: true;
  inbox: Inbox;

  /** The cursor actually used: `after`, clamped to 0..total. */
  from: int32;

  events: Event[];

  /** How many pushes the inbox has ever accepted. */
  total: int32;
}

/** An inbox emptied (`?clear=true`). */
model Cleared {
  ok: true;
  cleared: int32;
  inbox: Inbox;
}

/** An inbox deleted. */
model Deleted {
  ok: true;
  deleted: string;
}

/** No inbox has that id: never created, deleted, or expired. */
model NotFound<T> {
  @statusCode statusCode: 404;
  @body body: T;
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Perform one call to a transmitter. An SSF error is a 200 carrying its
 *  status. */
@tag("Shared Signals")
@route("/ssf/call")
@post
@operationId("ssfCall")
op call(@body body: CallRequest): Ok<Answer> | Refusals |
  BadGateway<Unreachable>;

/**
 * What the SSF proxy will and will not do, and whether this service hosts a
 * push receiver. A static deployment has no api and gets no answer.
 */
@tag("Shared Signals")
@route("/ssf/limits")
@get
@operationId("ssfLimits")
op limits(): Ok<Limits>;

/** Create a push inbox. Refused when receivers are off or at a limit. */
@tag("Shared Signals")
@route("/ssf/receiver")
@post
@operationId("ssfReceiverCreate")
@checkedInCode("api/ssf_receiver.js: ssfReceiverEnabled, ssfReceiverMaxInboxes and ssfReceiverMaxInboxesPerCaller, counted by the caller's address")
op createReceiver(@body body: ReceiverRequest): Ok<Created> | Refusals;

/**
 * A TRANSMITTER delivers one Security Event Token (RFC 8935 section 2.1).
 * The body is the compact JWS, with no form encoding and no JSON wrapper.
 * application/jwt is accepted and recorded as the wrong type, because a
 * receiver that dispatched on it would drop the token with no error anybody
 * sees.
 */
@tag("Shared Signals")
@route("/ssf/receiver/{id}")
@post
@operationId("ssfReceiverPush")
@checkedInCode("api/ssf_receiver.js: the inbox exists (404), the Authorization header is the one it was created with (401), the body is not empty and at most ssfReceiverMaxEventBytes (400)")
op push(
  @path id: string,
  @header("Content-Type") contentType: "application/secevent+jwt" |
    "application/jwt",
  @header("Authorization") authorization?: string,
  @body body: string,
): {
  @statusCode statusCode: 202;
} | {
  @statusCode statusCode: 400;
  @body body: SetError;
} | {
  @statusCode statusCode: 401;
  @header("WWW-Authenticate") challenge: string;
  @body body: SetError;
} | NotFound<SetError>;

/**
 * What has arrived since `after`. A cursor, not a destructive read: a
 * second tab sees the same events.
 */
@tag("Shared Signals")
@route("/ssf/receiver/{id}/events")
@get
@operationId("ssfReceiverEvents")
op events(
  @path id: string,

  /** The first sequence number wanted. Not a number, or negative, is 0. */
  @checkedInCode("api/ssf_receiver.js: read with Number(); anything not a finite non-negative number is 0")
  @query
  after?: string,
): Ok<Drained> | NotFound<IdProtoDebugger.Api.Refusal>;

/** Delete an inbox, or with `clear=true` only empty it. */
@tag("Shared Signals")
@route("/ssf/receiver/{id}")
@delete
@operationId("ssfReceiverDelete")
op deleteReceiver(
  @path id: string,

  /** "true" empties the inbox and keeps it. Anything else deletes it. */
  @checkedInCode("api/server.js: only the text true clears")
  @query
  clear?: string,
): Ok<Cleared | Deleted> | NotFound<IdProtoDebugger.Api.Refusal>;
