// File: embedded.js
//
// ---------------------------------------------------------------------------
// THE API'S CONFIGURATION WHEN IT RUNS INSIDE THE MOCK STS.
//
// The mock STS embeds this debugger (embedded/CLAUDE.md): it serves the UI as
// static files on an origin of its own, proxies `<origin>/api/*` — with the
// `/api` stripped — to THIS service, and forks this service as a child
// listening on a unix socket. So unlike every other file in this directory,
// the addresses here are not known when the file is written; they are the
// debugger's public origin, which only the parent knows, and it hands it over
// in the environment:
//
//   DEBUGGER_UI_URL                    the origin, no trailing slash
//                                      (https://localhost:8444). Everything
//                                      address-shaped below is derived from it.
//   DEBUGGER_ALLOWED_ADDRESS_RANGES    a JSON array of ranges — CIDR blocks or
//                                      first-last pairs — the ONLY addresses
//                                      this api may dial (api/ssrf_guard.js's
//                                      allow-list mode). Invalid JSON FAILS
//                                      CLOSED: see allowedAddressRanges below.
//   DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS
//                                      "true" / "false", read only when there
//                                      is no allow-list. Default true.
//   DEBUGGER_LOG_LEVEL                 bunyan level; default info.
//   DEBUGGER_LISTEN_SOCKET             read by common/tls_listener.js, not
//                                      here — it is how the service binds.
//
// This file is REQUIRED BY TESTS with none of those set (every file in
// api/env is read by tests/api_connect_timeout.js), so an absent variable must
// produce a usable configuration rather than a throw: the origin falls back to
// the conventional https://localhost:8444 and says so on stderr.
//
// Why stderr and a bare write rather than a logger: this is a configuration
// file, read by `require()` before any logger exists, and every other file in
// this directory is a plain object literal. Stdout is kept clean on purpose.
//
// The limits, ports and timeouts are api/env/local.js's, unchanged — the same
// service doing the same work — and they are copied rather than required so
// that a change to a developer's local stack is not silently a change to what
// the mock STS ships.
// ---------------------------------------------------------------------------
'use strict';

var DEFAULT_UI_URL = 'https://localhost:8444';

// One line on stderr. Not a logger: see the header. It carries no
// Entering/Leaving pair for the reason the console shims in client/build.js
// give for their own methods — it IS the log line, and there is no logger
// in this file for a trace to go through.
function warnConfig(message) {
  process.stderr.write('[api/env/embedded.js] ' + message + '\n');
}

var uiUrl = String(process.env.DEBUGGER_UI_URL || '').trim()
    .replace(/\/+$/, '');
if (!uiUrl) {
  uiUrl = DEFAULT_UI_URL;
  if (process.env.DEBUGGER_LISTEN_SOCKET) {
    // Only worth saying when this is actually the embedded service starting;
    // a test that reads the file for its limits has no origin to give.
    warnConfig('DEBUGGER_UI_URL is not set; using ' + DEFAULT_UI_URL + '.');
  }
}
var apiUrl = uiUrl + '/api';

// ---------------------------------------------------------------------------
// THE ADDRESS POLICY, and why a bad value refuses everything.
//
// A non-empty allow-list is what product mode passes: the embedded api may
// dial only the mock STS it lives in. A value that is not JSON, or JSON that
// is not an array, is a mistake on the parent's side — and the one thing a
// mistake must not do is open the relay. So it becomes an allow-list whose
// only entry is a sentence, which api/ssrf_guard.js cannot parse as a range:
// that is an allow-list with no usable entry, which the guard FAILS CLOSED on
// and names in its own error log. The sentence is the entry so that the log
// line says what went wrong without anybody having to find this file.
// ---------------------------------------------------------------------------
var allowedAddressRanges = [];
var rawAllowed = process.env.DEBUGGER_ALLOWED_ADDRESS_RANGES;
if (rawAllowed !== undefined && String(rawAllowed).trim() !== '') {
  var parsedAllowed = null;
  try {
    parsedAllowed = JSON.parse(rawAllowed);
  } catch (e) {
    warnConfig('DEBUGGER_ALLOWED_ADDRESS_RANGES is not valid JSON (' +
               ((e && e.message) || e) + '); failing closed — every ' +
               'outbound address will be refused.');
    parsedAllowed = ['(DEBUGGER_ALLOWED_ADDRESS_RANGES was not valid JSON)'];
  }
  if (!Array.isArray(parsedAllowed)) {
    warnConfig('DEBUGGER_ALLOWED_ADDRESS_RANGES is not a JSON array; ' +
               'failing closed — every outbound address will be refused.');
    parsedAllowed = ['(DEBUGGER_ALLOWED_ADDRESS_RANGES was not a JSON array)'];
  }
  allowedAddressRanges = parsedAllowed.map(function (entry) {
    return String(entry);
  });
}

// Read only when there is no allow-list (an allow-list switches the policy on
// regardless). Only an explicit "false" turns it off, which is the guard's own
// rule for the boolean: a typo stays safe.
var blockPrivateNetworkCalls = !/^\s*false\s*$/i.test(
    String(process.env.DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS || 'true'));

var config = {
  apiUrl: apiUrl,
  uiUrl: uiUrl,
  // PLAIN HTTP. The TLS is the mock STS's, on the debugger's public origin;
  // this service listens on a unix socket only that service can reach, and
  // common/tls_listener.js binds plain HTTP there whatever this says anyway.
  https: false,
  hostname: "127.0.0.1",
  // Unused on a socket, kept because server.js reads it for the TCP case.
  port: "4000",
  logLevel: process.env.DEBUGGER_LOG_LEVEL || "info",
  // --- api/env/local.js's limits, unchanged (see the header) ---------------
  callTimeout: 10000,
  connectionTimeout: 5000,
  maxContentLength: 1048576,
  maxRedirects: 5,
  userAgent: "Identity Protocol Debugger/{{VERSION}}",
  keepAlive: true,
  krb5AllowedPorts: [88, 464, 749],
  krb5ServicePorts: [8888],
  ldapAllowedPorts: [389, 636, 1389, 1636, 3268, 3269],
  ldapMaxEntries: 1000,
  scimMaxRequestBytes: 1048576,
  ssfMaxRequestBytes: 262144,
  ssfReceiverEnabled: true,
  ssfReceiverTtlMs: 3600000,
  ssfReceiverMaxInboxes: 20,
  ssfReceiverMaxEvents: 200,
  ssfReceiverMaxEventBytes: 65536,
  tlsAllowedPorts: "any",
  spiffeAllowedPorts: [8081, 8092, 8181],
  spiffeAllowedSocketPaths: ["/tmp/spire-agent/", "/tmp/spire-server/"],
  spiffeMaxStreamMessages: 4,
  spiffeStreamTimeout: 45000,
  // --- the SAML and WS-Federation landings, on the public origin -----------
  // The entity id is the UI origin's, as on every other stack; the three
  // landings are this service's, which on this stack means under `/api`.
  spEntityId: uiUrl + "/saml/sp",
  acsUrl: apiUrl + "/samlacs",
  sloUrl: apiUrl + "/samlslo",
  wsfedAcsUrl: apiUrl + "/wsfed",
  // --- the address policy ---------------------------------------------------
  // allowedAddressRanges, when non-empty, REPLACES blockedAddressRanges and
  // ignores blockPrivateNetworkCalls; see api/ssrf_guard.js.
  allowedAddressRanges: allowedAddressRanges,
  blockPrivateNetworkCalls: blockPrivateNetworkCalls,
  blockedAddressRanges: [
    "127.0.0.0/8",        // loopback
    "0.0.0.0/8",          // "this host on this network"
    "10.0.0.0/8",         // RFC 1918 private
    "172.16.0.0/12",      // RFC 1918 private
    "192.168.0.0/16",     // RFC 1918 private
    "169.254.0.0/16",     // link-local — includes cloud metadata
    "100.64.0.0/10",      // RFC 6598 carrier-grade NAT
    "192.0.0.0/24",       // IETF protocol assignments
    "198.18.0.0/15",      // benchmarking
    "::1/128",            // IPv6 loopback
    "fe80::/10",          // IPv6 link-local
    "fc00::/7"            // IPv6 unique local
  ]
};

module.exports = config;
