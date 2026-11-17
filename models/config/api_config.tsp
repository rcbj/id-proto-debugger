// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/config/api_config.tsp
//
// api/env/*.js. A setting marked @outboundPolicy is one every outbound call
// site must honour (api/CLAUDE.md, "the address policy and the sixteen
// settings"); the generated schema carries x-outbound-policy on each, and
// that is the list.

import "@typespec/json-schema";
import "../lib/debugger_lib.tsp";

using TypeSpec.JsonSchema;
using IdProtoDebugger.Lib;

@jsonSchema
namespace IdProtoDebugger.Config;

/** A bunyan level. */
union LogLevel {
  "trace", "debug", "info", "warn", "error", "fatal",
}

/** A TCP port, as a number or as the string a config file often holds. */
union Port {
  int32, string,
}

/** The api service's configuration: one of api/env/*.js. */
model ApiConfig {
  /** This service's own origin, as the client reaches it. */
  @minLength(1) apiUrl: string;

  /** The client's origin: the CORS allow-list and every redirect back. */
  @minLength(1) uiUrl: string;

  /** Bind https (common/tls_listener.js). Off is plain HTTP. */
  https?: boolean;

  /** The interface to bind. Read as `host`; `hostname` is the older name. */
  hostname?: string;
  host?: string;

  port: Port;
  logLevel: LogLevel;

  /** The TLS pair, when https is on, if not the stack's default files. */
  tlsCertFile?: string;
  tlsKeyFile?: string;

  // --- Outbound calls -----------------------------------------------------

  /** Milliseconds for a whole outbound call. Positive. */
  @outboundPolicy @minValueExclusive(0) callTimeout: numeric;

  /** Milliseconds to a usable connection: DNS, TCP and TLS. Positive. */
  @outboundPolicy @minValueExclusive(0) connectionTimeout: numeric;

  /** Bytes of a response before it is abandoned. Positive. */
  @outboundPolicy @minValueExclusive(0) maxContentLength: numeric;

  /** Redirects followed. 0 is legal and means none. */
  @outboundPolicy @minValue(0) maxRedirects: int32;

  /** The User-Agent; {{VERSION}} is the build's version. */
  @outboundPolicy userAgent?: string;

  /** Pool outbound connections. Only an explicit false turns it off. */
  @outboundPolicy keepAlive?: boolean;

  /** The address policy. Only an explicit false turns it off. */
  @outboundPolicy blockPrivateNetworkCalls: boolean;

  /** CIDR blocks or first-last pairs the address policy refuses. */
  @outboundPolicy blockedAddressRanges: string[];

  /** Non-empty: an allow-list that REPLACES the block-list. Embedded only. */
  @outboundPolicy allowedAddressRanges?: string[];

  // --- Raw-socket relays --------------------------------------------------

  /** Ports POST /krb5/kdc may dial. */
  @outboundPolicy krb5AllowedPorts?: int32[];

  /** Ports POST /krb5/service may dial. Empty turns it off. */
  @outboundPolicy krb5ServicePorts?: int32[];

  /** Ports an LDAP URL may name. */
  @outboundPolicy ldapAllowedPorts?: int32[];

  /** Entries one LDAP search returns at most. */
  @outboundPolicy @minValueExclusive(0) ldapMaxEntries?: int32;

  /** Ports POST /tls/connect may dial, or "any". */
  @outboundPolicy tlsAllowedPorts?: int32[] | "any";

  /** Ports a SPIFFE TCP address may name. */
  @outboundPolicy spiffeAllowedPorts?: int32[];

  /** Directories a SPIFFE unix-socket path must be under. */
  @outboundPolicy spiffeAllowedSocketPaths?: string[];

  /**
   * Bytes of request a wallet may hand POST /oid4vp/call to carry. Positive;
   * the route uses 262144 when it is absent or not positive.
   */
  @outboundPolicy @minValueExclusive(0) oid4vpMaxRequestBytes?: int32;

  /** Messages read from one SPIFFE server stream. */
  spiffeMaxStreamMessages?: int32;

  /** Milliseconds a SPIFFE server stream may stay open. */
  spiffeStreamTimeout?: int32;

  // --- Request caps -------------------------------------------------------

  scimMaxRequestBytes?: int32;
  ssfMaxRequestBytes?: int32;
  gnapMaxRequestBytes?: int32;

  // --- The SSF push receiver (api/ssf_receiver.js) ------------------------

  ssfReceiverEnabled?: boolean;
  ssfReceiverTtlMs?: int32;
  ssfReceiverIdleTtlMs?: int32;
  ssfReceiverMaxInboxes?: int32;
  ssfReceiverMaxInboxesPerCaller?: int32;
  ssfReceiverMaxEvents?: int32;
  ssfReceiverMaxEventBytes?: int32;
  ssfReceiverMaxInboxBytes?: int32;

  /** The hosted SSF transmitter (#363): api/ssf_transmitter.js. */
  ssfTransmitterEnabled?: boolean;
  ssfTransmitterTtlMs?: int32;
  ssfTransmitterIdleTtlMs?: int32;
  ssfTransmitterMaxInstances?: int32;
  ssfTransmitterMaxInstancesPerCaller?: int32;
  ssfTransmitterMaxStreams?: int32;
  ssfTransmitterMaxQueued?: int32;
  ssfTransmitterMaxEventBytes?: int32;

  // --- Hardware -----------------------------------------------------------

  /** Open the PC/SC reader (docker-compose-smartcard.yml). */
  smartcardReaderEnabled?: boolean;

  // --- SAML and WS-Federation service provider ----------------------------

  spEntityId?: string;
  acsUrl?: string;
  sloUrl?: string;
  wsfedAcsUrl?: string;

  // --- Test runs ----------------------------------------------------------

  /**
   * Hold every answer to the API document and keep the record at
   * GET /model/gaps. A test setting: it costs a schema check per answer.
   */
  validateResponses?: boolean;
}
