// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/spiffe.tsp
//
// SPIFFE and SPIRE: one endpoint for every method on both gRPC surfaces —
// the Workload API and the SPIRE Server API — a fetch of the bundle
// endpoint, and a limits document that publishes the method catalogue.
// gRPC is HTTP/2 with its status in the trailers, which `fetch` can neither
// send nor read, so api/spiffe_client.js makes the call. See docs/spiffe.md.
//
// ONE operation for forty-nine methods, as the route is: every method is
// (service, method, request) over one wire format, and the method list is
// DERIVED FROM THE VENDORED PROTOS. The request message is therefore an
// object the schema says nothing about; the protos are its schema.
//
// THE THREE OUTCOMES:
//
// * 400 — this service refused: an address it will not dial, a socket path
//   outside the allow-list, a method that is not on the surface.
// * 502 — the server could not be reached, or answered and was not who it
//   had to be (`identityMismatch`).
// * 200 — SPIFFE ANSWERED, and `ok: false` with a gRPC status is an answer:
//   PERMISSION_DENIED, UNAUTHENTICATED and UNIMPLEMENTED are the most
//   useful things this workflow shows.
//
// WHERE THE CHECKS ARE. The schema holds the JSON shape and the presence of
// the address (POST /spiffe/call) and the url (POST /spiffe/bundle), which
// the routes themselves check. Everything about a value is
// api/spiffe_client.js's — and the bundle URL's scheme is the route's own,
// in one check with its presence, so that check stays and the schema only
// keeps its sentence for a missing or mistyped url.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Spiffe;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** The X509-SVID to present to the SPIRE Server API. */
model Identity {
  /** The certificate chain, PEM or base64 DER. */
  @checkedInCode("api/spiffe_client.js: both halves or neither, and readable as PEM or base64 DER (ESPIFFEBADIDENTITY)")
  certPem?: string | null;

  /** Its private key, PEM or base64 PKCS#8 DER. */
  @checkedInCode("api/spiffe_client.js: both halves or neither (ESPIFFEBADIDENTITY)")
  keyPem?: string | null;
}

/** One call on either gRPC surface. */
model CallRequest {
  /** host:port, tcp://host:port, unix:///path or unix:/path. */
  @refusal(#{
    message: "address is required: host:port, tcp://host:port or unix:///path/to/api.sock. Note that a unix: path is resolved on the machine running this api, which is not the machine running your browser."
  })
  @checkedInCode("api/spiffe_client.js: the address grammar (ESPIFFEBADADDRESS); a port in spiffeAllowedPorts (ESPIFFEPORTNOTALLOWED) and the address policy (EBLOCKEDADDRESS); a socket path under spiffeAllowedSocketPaths, within sun_path, present and a socket (ESPIFFESOCKET...)")
  @minLength(1)
  address: string;

  /** workload, entry, agent, bundle, svid, trustdomain or debug. */
  @checkedInCode("api/spiffe_client.js: one of the services the protos define (ESPIFFENOSERVICE)")
  service?: string | null;

  /** The method, as the .proto writes it. GET /spiffe/limits lists them. */
  @checkedInCode("api/spiffe_client.js: a method of that service (ESPIFFENOMETHOD)")
  method?: string | null;

  /** The request message. Bytes fields take base64. Absent is empty. */
  @passthrough
  request?: Record<unknown> | null;

  /** gRPC metadata to send, name to value. */
  @checkedInCode("api/spiffe_client.js: a token name, not grpc- reserved, a value with no CR or LF (ESPIFFEBADMETADATA)")
  metadata?: Record<unknown> | null;

  /** How many messages of a stream to read, capped at
   *  spiffeMaxStreamMessages. */
  @checkedInCode("api/spiffe_client.js: parsed as an integer, at least 1 and at most spiffeMaxStreamMessages")
  maxMessages?: int64 | string | null;

  /** Only false leaves out the workload.spiffe.io header the Workload API
   *  requires — which is how a caller sees a server refuse a client that
   *  forgot it. */
  securityHeader?: boolean | null;

  /** The SPIRE Server API without TLS, for a deployment that has mutual
   *  TLS off. Only true. */
  plaintext?: boolean | null;

  /** spiffe-id (the default), trust-domain or none. */
  @checkedInCode("api/spiffe_client.js: one of the three (ESPIFFEBADMODE)")
  serverIdentityMode?: string | null;

  /** The SPIFFE ID the server must present. */
  @checkedInCode("api/spiffe_client.js: needed in spiffe-id mode unless trustDomain derives it (ESPIFFENOSERVERID)")
  serverId?: string | null;

  /** The trust domain, which derives the server's SPIFFE ID. */
  @checkedInCode("common/spiffe/spiffe_id.js: a trust domain that can name a server (ESPIFFEBADTRUSTDOMAIN); needed in trust-domain mode (ESPIFFENOTRUSTDOMAIN)")
  trustDomain?: string | null;

  /** The x509-svid authorities, PEM or base64 concatenated DER. */
  @checkedInCode("api/spiffe_client.js: needed unless serverIdentityMode is none (ESPIFFENOTRUSTBUNDLE), and holding a certificate (ESPIFFEBADTRUSTBUNDLE)")
  trustBundle?: string | null;

  identity?: Identity | null;
}

/** A fetch of a SPIFFE bundle endpoint. */
model BundleRequest {
  /** The bundle endpoint, http(s). */
  @refusal(#{
    message: "url is required and must be an http:// or https:// URL. A SPIFFE bundle endpoint is plain HTTPS — it is the ONE surface of SPIFFE that is, which is why this endpoint is an ordinary fetch and the other one is gRPC."
  })
  @checkedInCode("api/server.js: an absolute http(s) URL, once trimmed, answered with this same sentence; the outbound address policy and limits, as on every caller-named fetch")
  url: string;

  /** Only false turns off certificate verification. */
  sslValidate?: boolean | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** A gRPC status. */
model GrpcStatus {
  code: int32;
  name: string;
  details: string;
}

model Timing {
  totalMs: int64;
}

/**
 * What SPIFFE said. `ok` is false for every status but OK, and that is
 * still an answer.
 */
model CallAnswer {
  ok: boolean;
  surface: "workload" | "server";
  service: string;
  serviceLabel: string;
  method: string;

  /** The gRPC path, /package.Service/Method. */
  path: string;

  streaming: {
    request: boolean;
    response: boolean;

    /** What ended the read: end, messages, size or timeout. */
    stopped: string;

    wanted: int32;
  };
  target: string;
  resolvedAddress: string;
  transport: "tcp" | "unix";

  /** Whether the channel was TLS. */
  tls: boolean;

  /** What the server's certificate said, when there was one. */
  peer: Record<unknown>;

  status: GrpcStatus;

  /** The response messages, as JSON. */
  messages: unknown[];

  /** The request message as it was sent. */
  sent: Record<unknown>;

  timing: Timing;
}

/** A refusal or a failure from the client. */
model CallFailure {
  error: string;
  code: string | null;

  /** A server answered, with a certificate a trusted authority signed,
   *  and was somebody else. */
  identityMismatch: boolean;

  peer: Record<unknown> | null;
  timing: Timing;
}

/** The handler's own refusal: no address. */
model HandlerRefusal {
  error: string;
}

/** What came back from the bundle endpoint, and what is wrong with it. */
model BundleAnswer {
  /** A 2xx and a usable bundle. */
  ok: boolean;

  url: string;
  httpStatus: int32;
  headers: Record<unknown>;
  body: string;

  /** common/spiffe/spiffe_bundle.js's reading of the body. */
  report: {
    ok: boolean;
    errors: string[];
    warnings: string[];
    keys: Record<unknown>[];
    ignored: Record<unknown>[];
    counts: Record<int32>;
    sequence: int64 | null;
    refreshHint: numeric | null;
  };
  timing: Timing;
}

model BundleFailure {
  error: string;
  code: string;
  timing: Timing;
}

/** One method of the catalogue. */
model CatalogueMethod {
  service: string;
  serviceLabel: string;
  name: string;
  path: string;
  requestStream: boolean;
  responseStream: boolean;
  what: string;
  example: Record<unknown>;
  described: boolean;
}

model CatalogueService {
  service: string;
  label: string;
  methods: CatalogueMethod[];
}

/** What the SPIFFE client will and will not do, and every method. */
model Limits {
  ports: int32[] | "any";
  socketPaths: string[] | "any";
  maxSocketPathBytes: int32;
  connectionTimeoutMs: int64;
  callTimeoutMs: int64;
  maxResultBytes: int64;
  maxStreamMessages: int32;
  streamTimeoutMs: int64;
  addressPolicy: boolean;
  serverIdentityModes: string[];
  securityHeader: string;
  surfaces: {
    workload: CatalogueService[];
    server: CatalogueService[];
  };
  notes: string[];
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** One call on the Workload API or the SPIRE Server API. */
@tag("SPIFFE")
@route("/spiffe/call")
@post
@operationId("spiffeCall")
op call(@body body: CallRequest): Ok<CallAnswer> |
  BadRequest<CallFailure | HandlerRefusal | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<CallFailure>;

/** Fetch a bundle endpoint and say what is wrong with what came back. */
@tag("SPIFFE")
@route("/spiffe/bundle")
@post
@operationId("spiffeBundle")
op bundle(@body body: BundleRequest): Ok<BundleAnswer> |
  BadRequest<HandlerRefusal | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<BundleFailure>;

/** What the SPIFFE client will do, with the catalogue of every method. */
@tag("SPIFFE")
@route("/spiffe/limits")
@get
@operationId("spiffeLimits")
op limits(): Ok<Limits>;
