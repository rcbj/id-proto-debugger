// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/tls.tsp
//
// TLS and mutual TLS: the probe the PKI page asks to open a connection with
// the certificates it issued, its limits document, and the certificate this
// api serves. A page cannot choose a client certificate or a truststore, and
// cannot read the handshake it made, so api/tls_probe.js opens the socket.
// See docs/v0.9.6/pki.md.
//
// THE THREE OUTCOMES:
//
// * 400 — this service refused: a bad port, a version range that allows
//   nothing, a client certificate with no key, a path that is not one.
// * 502 — the server could not be reached: a name that does not resolve,
//   nothing listening, a timeout. (A name list OpenSSL could not read is a
//   502 as well, ETLSBADNAMELIST, which is what the handler has always
//   answered.)
// * 200 — a handshake was attempted, and a FAILED handshake is a 200: the
//   alert is the answer.
//
// WHERE THE CHECKS ARE. The schema holds the JSON shape and the presence of
// host and port, which the route itself used to check. Every value check —
// the port's range and allow-list, the TLS versions, the name lists' shape,
// the truststore's size, the HTTP path — is api/tls_probe.js's.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Tls;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** Text with at least one character: how a port arrives from a form. */
@minLength(1)
scalar PortText extends string;

/** The one GET to make over the connection once it is up. */
model HttpRequest {
  /** An origin-form path. The method is GET and is not negotiable. */
  @checkedInCode("api/tls_probe.js: present, starting with \"/\", at most maxHttpPathLength characters, no whitespace (ETLSBADHTTPPATH)")
  path?: string | null;
}

/** One TLS connection, and optionally a second without the client
 *  certificate. */
model ConnectRequest {
  /** The server's host name or address. */
  @refusal(#{ message: "host and port are required." })
  @checkedInCode("api/tls_probe.js: trimmed and refused when blank (ETLSNOHOST); resolved, and every address held to the address policy (EBLOCKEDADDRESS)")
  @minLength(1)
  host: string;

  /** The server's port, a number or its text. */
  @refusal(#{ message: "host and port are required." })
  @checkedInCode("api/tls_probe.js: an integer from 1 to 65535 (ETLSBADPORT) in tlsAllowedPorts (ETLSPORTNOTALLOWED)")
  port: int64 | PortText;

  /** SNI and the name verified. Absent is the host; null sends none. */
  @passthrough
  servername?: string | null;

  /** TLSv1, TLSv1.1, TLSv1.2 or TLSv1.3. */
  @checkedInCode("api/tls_probe.js: one of the four, and not above maxVersion (ETLSBADVERSION)")
  minVersion?: string | null;

  /** TLSv1, TLSv1.1, TLSv1.2 or TLSv1.3. */
  @checkedInCode("api/tls_probe.js: one of the four (ETLSBADVERSION)")
  maxVersion?: string | null;

  /** An OpenSSL cipher list, handed to OpenSSL as written. */
  @passthrough
  ciphers?: string | null;

  /** An OpenSSL supported-groups list: where ML-KEM is chosen. */
  @checkedInCode("api/tls_probe.js: colon-separated OpenSSL names of a conservative alphabet (ETLSBADNAMELIST); OpenSSL itself refuses a name it does not know (ETLSGROUPS)")
  groups?: string | null;

  /** An OpenSSL signature-algorithms list. */
  @checkedInCode("api/tls_probe.js: colon-separated OpenSSL names of a conservative alphabet (ETLSBADNAMELIST); OpenSSL itself refuses a name it does not know (ETLSSIGALGS)")
  sigalgs?: string | null;

  /** The ALPN protocols to offer. */
  @passthrough
  alpnProtocols?: string[] | null;

  /** The truststore, PEM: one bundle, or a list of them. */
  @checkedInCode("api/tls_probe.js: at most maxTrustAnchors certificates in all (ETLSTRUSTTOOLARGE)")
  trustCertificates?: string[] | string | null;

  /** Add the platform roots. Absent is: only when no anchors were given. */
  includeSystemRoots?: boolean | null;

  /** The client certificate chain, PEM, leaf first. */
  @checkedInCode("api/tls_probe.js: refused without clientKeyPem (ETLSNOCLIENTKEY); OpenSSL refuses material it cannot use (ETLSCLIENTMATERIAL)")
  clientCertificatePem?: string | null;

  /** Its private key, PEM. */
  clientKeyPem?: string | null;

  /** The private key's passphrase. Never echoed. */
  clientKeyPassphrase?: string | null;

  /** Connect a second time without the client certificate, to find out
   *  whether the server requires one. */
  mutualAuthProbe?: boolean | null;

  /** One GET over the connection: a path, or `{ path }`. Absent, null,
   *  false or empty asks for none. */
  httpRequest?: string | boolean | HttpRequest | null;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** An error as node and OpenSSL reported it. */
model TlsError {
  code: string | null;
  message: string;
  library: string | null;
  reason: string | null;
}

/**
 * One handshake. `connected` says whether the TLS session was established;
 * `usable` whether it was still good once the peer had had its say — a TLS
 * 1.3 server refuses a client certificate AFTER the handshake completes.
 */
model Handshake {
  connected: boolean;
  host: string;
  address: string;
  port: int32;
  servername: string | null;
  elapsedMs: int64;
  clientCertificateOffered: boolean;
  trustStore: {
    pastedAnchors: int32;
    systemRoots: boolean;
  };
  authorized: boolean;
  authorizationError: string | null;

  /** Each certificate the server sent, leaf first, described. */
  peerChain: Record<unknown>[];

  /** Set when the connection failed before a session existed. */
  error?: TlsError;

  // Set when the session was established.
  usable?: boolean;
  postHandshakeError?: TlsError | null;
  closedByPeer?: boolean;
  peerData?: boolean;
  protocol?: string | null;
  cipher?: {
    name: string | null;
    standardName: string | null;
    version: string | null;
  };
  alpnProtocol?: string | null;
  postQuantum?: Record<unknown>;
  sessionReused?: boolean | null;
  peerChainTruncated?: boolean;
  peerChainBytes?: int64;

  // Set when an httpRequest was asked for.
  httpRequest?: {
    method: "GET";
    path: string;
    headers: Record<string>;
  };
  httpResponse?: {
    parsed: boolean;
    statusLine: string | null;
    statusCode?: int32 | null;
    bytes: int64;
    truncated: boolean;
    endedBy: string;
  };
}

/** The handshake report. A failed handshake is reported, not thrown. */
model ConnectAnswer {
  result: Handshake;

  /** The second handshake, when mutualAuthProbe was asked for. */
  withoutClientCertificate?: Handshake;

  /** What the two handshakes, read together, say. */
  mutualAuth?: {
    verdict: "required" | "not-required" | "certificate-rejected" |
      "required-and-rejected" | "unknown";
    detail: string;
  };
}

/** A refusal or a network failure; `code` names which (ETLS...). */
model Failure {
  error: string;
  code?: string | null;
}

/** What the probe will and will not do. */
model Limits {
  allowedPorts: int32[] | "any";
  connectionTimeoutMs: int64;
  callTimeoutMs: int64;
  maxChainBytes: int64;
  maxTrustAnchors: int32;
  postHandshakeGraceMs: int64;
  tlsVersions: string[];
  addressPolicyEnabled: boolean;
  mutualAuthProbeAvailable: true;
  httpRequestAvailable: true;
  httpRequestMethod: "GET";
  httpResponseGraceMs: int64;
  maxHttpPathLength: int32;
  nodeVersion: string;
  systemRootCount: int32;
}

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Open a TLS connection and report both sides of the handshake. */
@tag("TLS")
@route("/tls/connect")
@post
@operationId("tlsConnect")
op connect(@body body: ConnectRequest): Ok<ConnectAnswer> |
  BadRequest<Failure | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<Failure>;

/** What the TLS probe will and will not do. */
@tag("TLS")
@route("/tls/limits")
@get
@operationId("tlsLimits")
op limits(): Ok<Limits>;

/**
 * The certificate this api serves, PEM, so a caller can trust it before it
 * verifies anything. 404 on a plain listener: "not serving TLS" and "will
 * not say with what" are different answers.
 */
@tag("TLS")
@route("/tls/server-certificate")
@get
@operationId("tlsServerCertificate")
op serverCertificate(): {
  @statusCode statusCode: 200;
  @header contentType: "application/x-pem-file";
  @body pem: string;
} | {
  @statusCode statusCode: 404;
  @body body: {
    error: string;
    code: "ENOTLS";
  };
};
