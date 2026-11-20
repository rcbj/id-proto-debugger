// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/krb5.tsp
//
// Kerberos v5 (RFC 4120): the KDC relay, the service relay, the SPNEGO
// (RFC 4178) HTTP exchange and a limits document. Kerberos is DER over TCP
// and UDP port 88, so a browser cannot reach a KDC: the api is a guarded
// byte relay (api/krb5_relay.js, api/krb5_frame.js) rather than a proxy of
// anything HTTP-shaped. See docs/v0.9.5/kerberos.md and docs/v0.9.5/spnego.md.
//
// THE THREE OUTCOMES, which every answer below keeps apart:
//
// * 400 — this service refused: a message that is not base64, bytes that
//   are not a Kerberos request, a port that is not allowed, a blocked
//   address.
// * 502 — the far end could not be reached or did not answer: a name that
//   does not resolve, nothing listening, a timeout.
// * 200 — the far end ANSWERED. A KRB-ERROR is an answer; so is a 401 with a
//   `WWW-Authenticate: Negotiate` challenge, which is the first half of
//   every SPNEGO exchange.
//
// WHERE THE CHECKS ARE. The schema holds the JSON shape and the presence of
// what each route's own handler used to check for. Everything about a value
// — the base64 alphabet, the bytes' shape, the port, the address — stays in
// the code. The base64 check is the route's own and is a VALUE check, so it
// stays in api/server.js; the frame and port checks are the relay's, which
// is also a library the tests call.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Krb5;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** A KDC request to relay: an AS-REQ or a TGS-REQ. */
model KdcRequest {
  /** The KDC's host name or address. */
  @refusal(#{
    message: "host and message are required. message is the Kerberos request, base64-encoded."
  })
  @checkedInCode("api/krb5_relay.js: trimmed and refused when blank (EKRB5NOHOST); resolved, and every address held to the address policy (EBLOCKEDADDRESS)")
  @minLength(1)
  host: string;

  /** The request, base64 or base64url. */
  @refusal(#{
    message: "host and message are required. message is the Kerberos request, base64-encoded."
  })
  @checkedInCode("api/server.js: the base64 alphabet, before decoding, and a message that decodes to nothing; api/krb5_frame.js: an AS-REQ or TGS-REQ whose outer length accounts for every byte (EKRB5NOTKERBEROS)")
  @minLength(1)
  message: string;

  /** The KDC's port. Absent, null or empty is 88. */
  @checkedInCode("api/krb5_relay.js: parsed as an integer (EKRB5NOPORT), and in krb5AllowedPorts (EKRB5PORTNOTALLOWED)")
  port?: int64 | string | null;

  /** "udp" is UDP; anything else, or nothing, is TCP. */
  transport?: string | null;
}

/** An AP-REQ to present to a Kerberos service. */
model ServiceRequest {
  /** The service's host name or address. */
  @refusal(#{
    message: "host, port and message are required. Unlike the KDC there is no default port: a Kerberos service can be on any port, so it has to be named."
  })
  @checkedInCode("api/krb5_relay.js: trimmed and refused when blank (EKRB5NOHOST); resolved, and every address held to the address policy (EBLOCKEDADDRESS)")
  @minLength(1)
  host: string;

  /**
   * The service's port. There is no default: a Kerberos service can be on
   * any port. Required, but not by the schema — 0 is refused with the same
   * sentence as a missing port, and 0 is a value.
   */
  @refusal(#{
    message: "host, port and message are required. Unlike the KDC there is no default port: a Kerberos service can be on any port, so it has to be named."
  })
  @checkedInCode("api/server.js: absent, null, empty or 0 is refused as missing; api/krb5_relay.js: parsed as an integer (EKRB5NOPORT), POST /krb5/service enabled at all (EKRB5SERVICENOTENABLED) and the port in krb5ServicePorts (EKRB5PORTNOTALLOWED)")
  port?: int64 | string | null;

  /** A GSS-wrapped AP-REQ, or a bare one, base64 or base64url. */
  @refusal(#{
    message: "host, port and message are required. Unlike the KDC there is no default port: a Kerberos service can be on any port, so it has to be named."
  })
  @checkedInCode("api/server.js: the base64 alphabet, and a message that decodes to nothing; api/krb5_frame.js: a bare AP-REQ, or an InitialContextToken naming Kerberos v5 and wrapping one, every length accounted for (EKRB5NOTKERBEROS)")
  @minLength(1)
  message: string;

  /** "udp" is UDP; anything else, or nothing, is TCP. */
  transport?: string | null;
}

/** One step of a SPNEGO handshake: a GET of a protected resource. */
model SpnegoRequest {
  /** The protected resource. */
  @refusal(#{
    message: "url is required. It is the SPNEGO-protected resource to fetch."
  })
  @checkedInCode("api/server.js: an absolute http(s) URL; the outbound address policy and limits, as on every caller-named fetch")
  @minLength(1)
  url: string;

  /**
   * The SPNEGO token, base64, exactly as it follows "Negotiate " in the
   * Authorization header. Absent or empty is the unauthenticated first
   * request, which carries no Authorization header at all.
   */
  @checkedInCode("api/server.js: the base64 alphabet")
  @passthrough
  token?: string | null;

  /** Only false, or the string "false", turns off certificate checks. */
  sslValidate?: boolean | string | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** What was relayed, as the pre-flight named it. */
model RelayedRequest {
  /** AS-REQ, TGS-REQ, AP-REQ or GSS-wrapped AP-REQ. */
  message: string;

  bytes: int64;
}

/** Where the relay connected. */
model RelayTarget {
  host: string;
  address: string;
  port: int32;
  transport: "tcp" | "udp";

  /** False when the host was an address literal. */
  resolved: boolean;
}

model RelayTiming {
  totalMs: int64;

  /** Null over UDP, which has no connection. */
  connectMs: int64 | null;
}

/** The KDC's reply. */
model KdcAnswer {
  /** The reply, base64. */
  reply: string;

  /** AS-REP, TGS-REP, KRB-ERROR, or what the first byte was. */
  replyMessage: string | null;

  request: RelayedRequest;
  target: RelayTarget;
  timing: RelayTiming;
}

/**
 * The service's answer. A service that closed without answering is not a
 * failure — a client that did not ask for mutual authentication is not
 * owed a reply — and answers `reply: null` with a `note` and nothing else.
 */
model ServiceAnswer {
  /** The answer, base64, or null when the service sent none. */
  reply: string | null;

  replyMessage: string | null;
  request?: RelayedRequest;
  target?: RelayTarget;
  timing?: RelayTiming;
  note?: string;
}

/** Both sides of one SPNEGO step, headers included. */
model SpnegoAnswer {
  request: {
    method: "GET";
    url: string;

    /** What was sent, the User-Agent this service adds included. */
    headers: Record<string>;
  };
  response: {
    /** The far end's status. 401 is the protocol, not a failure. */
    status: int32;

    statusText: string;
    headers: Record<unknown>;

    /** Capped for display at spnegoBodyChars. */
    body: string;

    bodyTruncated: boolean;
    bodyLength: int64;
  };
  timing: {
    totalMs: int64;
  };
}

/** A refusal or a network failure; `code` names which (EKRB5...). */
model Failure {
  error: string;
  code?: string | null;
}

/** What the relay will and will not do. */
model Limits {
  allowedPorts: int32[];

  /** The service ports, or "any". Empty is POST /krb5/service off. */
  servicePorts: int32[] | "any";

  serviceEnabled: boolean;
  addressPolicyEnabled: boolean;
  spnegoEnabled: true;
  spnegoBodyChars: int64;
  limits: {
    connectTimeout: int64;
    callTimeout: int64;
    maxReplyBytes: int64;
  };
}

alias Refused = BadRequest<Failure | IdProtoDebugger.Api.ModelRefusal>;

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Relay a Kerberos request to a KDC and return its reply. */
@tag("Kerberos")
@route("/krb5/kdc")
@post
@operationId("krb5Kdc")
op kdc(@body body: KdcRequest): Ok<KdcAnswer> | Refused | BadGateway<Failure>;

/** Present an AP-REQ to a Kerberos service and return its answer. */
@tag("Kerberos")
@route("/krb5/service")
@post
@operationId("krb5Service")
op service(@body body: ServiceRequest): Ok<ServiceAnswer> | Refused |
  BadGateway<Failure>;

/** Perform one step of a SPNEGO HTTP handshake and report both sides. */
@tag("Kerberos")
@route("/krb5/spnego")
@post
@operationId("krb5Spnego")
op spnego(@body body: SpnegoRequest): Ok<SpnegoAnswer> | Refused |
  BadGateway<Failure>;

/** What the Kerberos relay will and will not do. */
@tag("Kerberos")
@route("/krb5/limits")
@get
@operationId("krb5Limits")
op limits(): Ok<Limits>;
