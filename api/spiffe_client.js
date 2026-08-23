// File: spiffe_client.js
//
// ---------------------------------------------------------------------------
// The guarded SPIFFE client behind the POST /spiffe/* endpoints.
//
// SPIFFE's server side is THREE surfaces and only one of them is HTTP:
//
//   the bundle endpoint    plain HTTPS, one GET returning a JWK Set. That one
//                          is an ordinary axios call and is made in server.js;
//                          nothing in this file touches it.
//   the Workload API       gRPC. What a WORKLOAD talks to, to be given an
//                          identity. On a Unix socket and on TCP.
//   the SPIRE Server API   gRPC. What an OPERATOR and an AGENT talk to:
//                          registration entries, attestation, bundles, minting.
//                          On a Unix socket and on TCP, and its TCP port is
//                          MUTUAL TLS.
//
// gRPC is HTTP/2 with a binary framing and trailers, and a browser cannot
// produce it: `fetch` will not open an HTTP/2 stream, cannot send trailers,
// cannot read a `grpc-status`, and cannot present a client certificate. So the
// whole of both gRPC surfaces has to live here, the way RFC 4511 lives in
// `ldap_client.js` — the page describes the call, this file makes it, and both
// halves are reported. `GET /spiffe/limits` publishes what this service will
// and will not do, so the page can say so before a call fails.
//
// ---------------------------------------------------------------------------
// FORTY-NINE METHODS, AND THE CATALOGUE IS DERIVED RATHER THAN TYPED
//
// Seven on the Workload API and forty-two across the SPIRE Server API's six
// services. `catalogue()` builds that list by walking the SERVICE DEFINITIONS
// the protos produced, not by listing method names in this file — the argument
// the mock STS's `sts_metadata.js` makes about routes, applied to a surface
// Express knows nothing about. A method that exists and is undescribed is drift
// nothing else can see, and `tests/spiffe_catalogue.js` asserts the two agree
// in both directions: every method has a note, and every note names a method.
//
// ---------------------------------------------------------------------------
// THE PROTOS ARE VENDORED, VERBATIM, AND THAT IS THE POINT
//
// `api/protos/` holds the SPIFFE project's own `workloadapi.proto` and the
// `spire-api-sdk`'s, byte-identical to the copies the mock STS carries. The
// wire matching what a REAL client and a REAL SPIRE server expect is the entire
// reason `@grpc/grpc-js` is a dependency here, so an edit to one of these files
// would give that up silently — the debugger would go on agreeing with the
// mock and interoperate with nothing. `tests/spiffe_proto_sync.js` compares the
// two copies for exactly that reason, and a missing proto is not a degraded
// feature: it throws at require time, because a client that starts and then
// answers `Unimplemented` to everything is worse than one that does not start.
//
// ---------------------------------------------------------------------------
// WHY api/ssrf_guard.js DOES NOT COVER THIS, AND WHAT IS DONE INSTEAD
//
// The same reason `krb5_relay.js`, `ldap_client.js` and `tls_probe.js` each
// give: the guard is installed on the shared **axios** instance — a request
// interceptor plus `lookup` and `createConnection` hooks on the outbound agents
// — and grpc-js opens its own socket with no axios in the path and no agent to
// hook. So this is the FOURTH enforcement of the same policy for a transport
// the guard has never seen, and like the other three it reuses the guard's
// DECISION (`blockedRangeFor`) rather than its own copy of the ranges. Two
// implementations of an address policy is one implementation and one hole.
//
// Four things bound a TCP call, and the third is new here:
//
//  1. **The address must parse as `tcp://host:port`, `host:port` or
//     `unix://path`.** An unrecognised scheme is refused rather than defaulted,
//     because grpc-js's own resolver treats an unknown one as a DNS name.
//  2. **The address policy**, shared with the other three call sites.
//  3. **Resolve, then dial the LITERAL that was checked**, closing the
//     DNS-rebinding window. This costs NOTHING here, and that is worth stating
//     because it costs `ldap_client.js` something real: for `ldaps:` that file
//     has to hand TLS the ORIGINAL NAME as `servername` or certificate
//     verification compares a certificate against an IP address and fails every
//     time. SPIFFE has no such problem, because **SPIFFE authentication is not
//     hostname authentication**: the far end is identified by the SPIFFE ID in
//     its certificate's URI subjectAltName, and a SPIRE server's certificate
//     carries no DNS name and no matching CN at all. See
//     `serverIdentityCheck()`
//     — the ordinary `checkServerIdentity` is REPLACED rather than relaxed.
//  4. **A port allowlist**, `spiffeAllowedPorts`, defaulting to the three
//     ports this ecosystem actually uses: 8081 (a real `spire-server`'s
//     default), and 8092 and 8181 (the mock STS's Workload API and SPIRE
//     Server API, which had to move because 8081 is its HTTP port). `"any"` is
//     accepted, spelled as a word so that widening it cannot be a plausible
//     typo.
//
// ---------------------------------------------------------------------------
// AND ONE BOUND NOTHING ELSE IN THIS SERVICE HAS NEEDED: A FILESYSTEM PATH
//
// `SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to `go-spiffe`,
// `spiffe-helper` and the SPIRE agent, so a SPIFFE client that could not reach
// a Unix socket would be unable to talk to the thing every real deployment
// runs. That makes this the only endpoint in this service that opens a
// connection to a **path its caller chose**, and the address policy cannot see
// it: there is no address to judge.
//
// So it gets a bound of its own, `spiffeAllowedSocketPaths`, and it is a
// PREFIX allowlist defaulting to SPIRE's own two directories
// (`/tmp/spire-agent/`, `/tmp/spire-server/`). What it is protecting against is
// not exotic: an api reachable from anywhere, pointed at a path on the machine
// it runs on, is a way to make that machine connect to one of its own local
// services and report what came back. `"any"` is accepted with the same spelled
// word, and a deployment that wants it should have said so.
//
// Two smaller things the same check does, because both cost a confusing failure
// otherwise. A Unix socket path is bounded by `sun_path` at **108 bytes** on
// Linux, and past that `bind`/`connect` fails with a message about the address
// being in use — naming something that is not the problem. And a path that
// exists and is NOT a socket is refused by name rather than dialled, because
// "connection refused" on a regular file reads as a service that is down.
//
// ---------------------------------------------------------------------------
// THE STREAMS ARE BOUNDED, AND SAYING SO IS PART OF THE ANSWER
//
// Four Workload API methods and two SPIRE Server API methods are streams, and a
// real client holds `FetchX509SVID` open for the life of the process — the mock
// re-sends on it at half the SVID lifetime so that a client's ROTATION path can
// be exercised without anybody waiting an hour. An HTTP endpoint cannot hold a
// stream open on a browser's behalf, so this file reads up to
// `spiffeMaxStreamMessages` messages or until `callTimeout`, cancels, and
// reports **how it stopped** — `messages`, `timeout` or `end`. A client that
// reported only the first message would make a rotation invisible; one that
// reported nothing about why it stopped would make a timeout look like a server
// that sent one message and went quiet.
//
// ---------------------------------------------------------------------------
// THE THREE OUTCOMES, and collapsing them is the mistake this endpoint exists
// to avoid — the rule `POST /ldap/*` and `POST /scim` already follow.
//
//   * a refusal by THIS service (an address it will not dial, a method that is
//     not on the surface, a malformed identity) — **400**;
//   * a network failure (no route, refused, a TLS handshake that failed) —
//     **502**;
//   * **a gRPC STATUS from the far end — 200**, with `ok: false` and the code.
//
// The third is the whole point on this surface. `PERMISSION_DENIED` on a method
// the caller's entity is not allowed, `UNAUTHENTICATED` when nothing was
// presented, `UNIMPLEMENTED` with the reason a server gives for not doing
// something, `INVALID_ARGUMENT` on a JWT-SVID request with no audience — those
// are SPIFFE answering, and they are the most interesting thing this workflow
// ever shows. `UNAUTHENTICATED` and `PERMISSION_DENIED` in particular are two
// different instructions to a client ("authenticate" and "you may not"), and a
// debugger that reported both as a failure would hide the distinction SPIRE
// went to the trouble of making.
// ---------------------------------------------------------------------------

const dns = require('dns');
const fs = require('fs');
const net = require('net');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const loader = require('@grpc/proto-loader');

// The grammar, from common/ rather than from a copy here. See the long note at
// the top of that file about how it reaches this directory.
const spiffeId = require('../common/spiffe/spiffe_id.js');

const DEFAULT_ALLOWED_PORTS = [8081, 8092, 8181];
const DEFAULT_ALLOWED_SOCKET_PATHS =
  ['/tmp/spire-agent/', '/tmp/spire-server/'];
const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_CALL_TIMEOUT_MS = 10000;
const DEFAULT_MAX_RESULT_BYTES = 1048576;
const DEFAULT_MAX_STREAM_MESSAGES = 4;

// A STREAM GETS A DEADLINE OF ITS OWN, and the reason is the same one
// `connectionTimeout` and `callTimeout` already split between them: they bound
// different things. `callTimeout` asks "how long may a server take to answer",
// and ten seconds is generous for that. A stream is not an answer — it is a
// subscription a real client holds for the life of its process — so the
// interesting event on one is the SECOND message, and on a Workload API that
// re-sends at half the SVID lifetime the second message is a rotation.
//
// The mock STS puts a FLOOR of thirty seconds under that period, so a stream
// bounded by `callTimeout` can never observe a rotation no matter how short the
// SVID lifetime is set — the call would always end first, reporting `timeout`
// after one message, which is indistinguishable from a server that sent one and
// went quiet. Forty-five seconds clears the floor with margin.
const DEFAULT_STREAM_TIMEOUT_MS = 45000;

// Linux's `sun_path` is 108 bytes including the terminator. macOS's is 104.
// The smaller number is used so that a path this service accepts works on both,
// and so that the refusal says a number rather than "it depends".
const MAX_SOCKET_PATH_BYTES = 103;

// ---------------------------------------------------------------------------
// LOADING THE PROTOS.
//
// `bytes: String` is the load option that makes the rest of this file simple,
// and it is worth naming: with it, protobufjs hands every `bytes` field back as
// BASE64 rather than as a Buffer, so a response is already JSON-serialisable
// and nothing here has to walk a message converting buffers. The same option
// works in reverse — protobufjs's writer accepts a base64 string wherever a
// `bytes` field is expected — so a caller sends a CSR as base64 and it arrives
// as bytes with no conversion at either end. `longs: String` is there for the
// same reason: a `uint64` expiry as a JavaScript number is wrong above 2^53 and
// silently so.
//
// `keepCase: true` keeps the field names the `.proto` writes, which is what the
// page shows and what SPIRE's own documentation uses. It does NOT reach
// protobufjs's built-in well-known types — see STRUCT_FIELDS below, which is
// the trap that costs everybody one afternoon.
// ---------------------------------------------------------------------------
const PROTO_DIR = path.join(__dirname, 'protos');

const LOAD_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  bytes: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_DIR]
};

const WORKLOAD_PROTO = 'workloadapi.proto';

const SERVER_PROTOS = [
  'spire/api/server/entry/v1/entry.proto',
  'spire/api/server/agent/v1/agent.proto',
  'spire/api/server/bundle/v1/bundle.proto',
  'spire/api/server/svid/v1/svid.proto',
  'spire/api/server/trustdomain/v1/trustdomain.proto',
  'spire/api/server/debug/v1/debug.proto'
];

function loadServices() {
  const workload = grpc.loadPackageDefinition(
    loader.loadSync(WORKLOAD_PROTO, LOAD_OPTIONS));
  const server = grpc.loadPackageDefinition(
    loader.loadSync(SERVER_PROTOS, LOAD_OPTIONS));
  const services = {
    workload: workload.SpiffeWorkloadAPI,
    entry: server.spire && server.spire.api.server.entry.v1.Entry,
    agent: server.spire && server.spire.api.server.agent.v1.Agent,
    bundle: server.spire && server.spire.api.server.bundle.v1.Bundle,
    svid: server.spire && server.spire.api.server.svid.v1.SVID,
    trustdomain: server.spire &&
      server.spire.api.server.trustdomain.v1.TrustDomain,
    debug: server.spire && server.spire.api.server.debug.v1.Debug
  };
  Object.keys(services).forEach(function (name) {
    if (!services[name]) {
      throw new Error('spiffe_client: the ' + name + ' service is not in the ' +
        'vendored protos under api/protos. This is a build problem rather ' +
        'than a runtime one — see the note at the top of ' +
        'api/spiffe_client.js.');
    }
  });
  return services;
}

const SERVICES = loadServices();

// Which surface each service belongs to. The Workload API and the SPIRE Server
// API are authenticated in OPPOSITE ways — the first must not require a
// credential and the second requires an X509-SVID — so a call has to know which
// one it is on before it builds any credentials at all.
const SURFACE_OF = {
  workload: 'workload',
  entry: 'server',
  agent: 'server',
  bundle: 'server',
  svid: 'server',
  trustdomain: 'server',
  debug: 'server'
};

const SERVICE_LABELS = {
  workload: 'SpiffeWorkloadAPI',
  entry: 'Entry',
  agent: 'Agent',
  bundle: 'Bundle',
  svid: 'SVID',
  trustdomain: 'TrustDomain',
  debug: 'Debug'
};

// ---------------------------------------------------------------------------
// THE TWO WELL-KNOWN-TYPE TABLES, AND WHY THEY ARE TYPED OUT.
//
// `keepCase: true` does not reach protobufjs's built-in well-known types, so
// the two places one appears need handling this file does explicitly rather
// than by walking the descriptors. That is a deliberate trade and the reason is
// worth having: a field descriptor's `typeName` is a RELATIVE protobuf name
// (`Filter`, `types.EntryMask`, `Federated_bundles`), so resolving one means
// implementing protobuf's own name-resolution algorithm — more code, with more
// to be wrong in it, than naming six fields.
//
// What keeps a typed-out table honest is a test rather than a convention:
// `tests/spiffe_catalogue.js` walks every message in the vendored protos and
// fails if a wrapper-typed or Struct-typed field is not in one of these.
//
//   WRAPPED_FIELDS  `google.protobuf.StringValue` and friends are MESSAGES, so
//                   the wire form is `{ value: x }` and a bare `x` serialises
//                   to nothing at all — with no throw and no warning. These are
//                   the filter fields of ListEntries and ListAgents, where the
//                   wrapper is how "not set" is told apart from "set to false".
//                   A caller may send either form; the bare one is wrapped
//                   here.
//
//   STRUCT_FIELDS   a `google.protobuf.Struct` decodes to
//                   `{ fields: { k: { stringValue: v, kind: 'stringValue' }}}`
//                   — camelCase members in a family that is otherwise entirely
//                   snake_case. `ValidateJWTSVID` answered 200 with empty
//                   claims for exactly this reason until a real client asked
//                   for them. Flattened to plain JSON on the way out.
// ---------------------------------------------------------------------------
const WRAPPED_FIELDS = {
  'entry.ListEntries': ['filter.by_hint', 'filter.by_downstream'],
  'entry.GetAuthorizedEntries': [],
  'agent.ListAgents': ['filter.by_banned', 'filter.by_can_reattest'],
  'agent.CountAgents': ['filter.by_banned', 'filter.by_can_reattest'],
  'entry.CountEntries': ['filter.by_hint', 'filter.by_downstream']
};

const STRUCT_FIELDS = {
  'workload.ValidateJWTSVID': ['claims']
};

// ---------------------------------------------------------------------------
// WHAT EACH METHOD IS FOR, and what a caller has to put in the request.
//
// This is the table the page's method picker is built from, so a `request`
// example here is what a person first sees. It is NOT the source of the method
// LIST — that is derived from the service definitions in `catalogue()` — so a
// method cannot be hidden by being left out of this, only left undescribed, and
// the test named above fails on that.
// ---------------------------------------------------------------------------
const METHOD_NOTES = {
  // --- the Workload API -------------------------------------------------
  'workload.FetchX509SVID': {
    what: 'One X509-SVID per entitled registration entry, each with its ' +
          'PRIVATE KEY and the trust domain bundle. This is the call a ' +
          'workload makes to be given an identity, and it needs no ' +
          'credential — the Workload Endpoint specification says the ' +
          'endpoint ' +
          'MUST NOT require one, because a workload has no root of trust ' +
          'until this call gives it one.',
    request: {}
  },
  'workload.FetchX509Bundles': {
    what: 'The X.509 trust bundles alone — this trust domain\'s and every ' +
          'federated one\'s — with no identity and no private key. What a ' +
          'service that only VERIFIES peers needs.',
    request: {}
  },
  'workload.FetchJWTSVID': {
    what: 'A JWT-SVID for the audience(s) asked for. Refuses a call with no ' +
          'audience, and every conforming implementation does: a JWT-SVID is ' +
          'a bearer credential, and the audience is the only thing stopping ' +
          'one issued for service A being replayed against service B.',
    request: { audience: ['spiffe://example.org/db'] }
  },
  'workload.FetchJWTBundles': {
    what: 'The JWT verification keys as JWK Sets — JSON, where the X.509 ' +
          'bundles are concatenated DER.',
    request: {}
  },
  'workload.ValidateJWTSVID': {
    what: 'Verifies a JWT-SVID: the signature against the trust domain\'s ' +
          'JWT ' +
          'authorities, exp with no leeway, the audience, and that the sub ' +
          'belongs to the trust domain whose key verified it. The point of ' +
          'the call is to be told NO, so this is the one method in the ' +
          'family ' +
          'that behaves like a production one.',
    request: { audience: 'spiffe://example.org/db', svid: '<a JWT-SVID>' }
  },
  'workload.FetchWITSVID': {
    what: 'Workload Identity Tokens. On the service because they are in the ' +
          'SPIFFE proto; a server that issues none answers Unimplemented, ' +
          'which is the answer this call exists to show you.',
    request: { audience: ['spiffe://example.org/db'] }
  },
  'workload.FetchWITBundles': {
    what: 'The WIT half of the bundle stream. Same answer as FetchWITSVID ' +
          'from a server that issues no WIT-SVIDs.',
    request: {}
  },

  // --- Entry ------------------------------------------------------------
  'entry.CountEntries': {
    what: 'How many registration entries the server holds. Administrator or ' +
          'the local socket.',
    request: {}
  },
  'entry.ListEntries': {
    what: 'The registration entries: which identity a workload gets, under ' +
          'which parent, matching which selectors. `filter.by_hint` and ' +
          '`filter.by_downstream` are google.protobuf wrappers on the wire — ' +
          'send the bare value and this service wraps it.',
    request: { page_size: 20 }
  },
  'entry.GetEntry': {
    what: 'One entry by its id. NOT by its SPIFFE ID: several entries may ' +
          'name one identity under different parents and selectors, which is ' +
          'the case a client that keys on the SPIFFE ID gets wrong.',
    request: { id: '<entry id>' }
  },
  'entry.BatchCreateEntry': {
    what: 'Create registration entries. A batch answers PER ENTRY, so a ' +
          'partial success is normal and the per-row status is the result — ' +
          'reading only the transport status reports a batch of ten with ' +
          'nine ' +
          'failures as a success.',
    request: { entries: [{
      spiffe_id: { trust_domain: 'example.org', path: '/example' },
      parent_id: { trust_domain: 'example.org', path: '/spire/server' },
      selectors: [{ type: 'unix', value: 'uid:1000' }],
      x509_svid_ttl: 3600
    }] }
  },
  'entry.BatchUpdateEntry': {
    what: 'Update entries. Without an `entry_mask` every field of the ' +
          'submitted entry is applied, which is what `spire-server entry ' +
          'update` relies on and is how a field gets cleared by accident.',
    request: { entries: [{ id: '<entry id>', x509_svid_ttl: 7200 }],
               input_mask: { x509_svid_ttl: true } }
  },
  'entry.BatchDeleteEntry': {
    what: 'Delete entries by id, per-row status again.',
    request: { ids: ['<entry id>'] }
  },
  'entry.GetAuthorizedEntries': {
    what: 'What THIS CALLER is entitled to, rather than what the server ' +
          'holds. An AGENT method: it answers the agent on the connection, ' +
          'so ' +
          'the credential decides the answer and there is nothing to name in ' +
          'the request.',
    request: {}
  },
  'entry.SyncAuthorizedEntries': {
    what: 'The streaming form of the same question, for an agent keeping a ' +
          'local cache: send the ids and revisions you hold and be told what ' +
          'changed. Bidirectional, so this service writes the request, ends ' +
          'its side and reads what comes back.',
    request: {}
  },

  // --- Agent ------------------------------------------------------------
  'agent.CountAgents': {
    what: 'How many agents have attested here.',
    request: {}
  },
  'agent.ListAgents': {
    what: 'The attested agents, with the selectors their attestation ' +
          'claimed. ' +
          'Note `unverified:true` on a mock\'s agents — an attestation ' +
          'payload ' +
          'nothing checked is a claim, not a fact.',
    request: {}
  },
  'agent.GetAgent': {
    what: 'One agent by its SPIFFE ID, which is always under the reserved ' +
          '/spire/agent path.',
    request: { id: { trust_domain: 'example.org',
                     path: '/spire/agent/join_token/<uuid>' } }
  },
  'agent.DeleteAgent': {
    what: 'Forget an agent. It may attest again; a BAN is what stops that.',
    request: { id: { trust_domain: 'example.org', path: '/spire/agent/...' } }
  },
  'agent.BanAgent': {
    what: 'Refuse this agent from now on, including a fresh attestation. The ' +
          'difference from DeleteAgent is the whole reason both exist.',
    request: { id: { trust_domain: 'example.org', path: '/spire/agent/...' } }
  },
  'agent.AttestAgent': {
    what: 'Become an agent. OPEN TO EVERYBODY — it has to be, because an ' +
          'agent has no SVID until this call gives it one, which is why the ' +
          'SPIRE Server API\'s TCP port ASKS FOR a client certificate and ' +
          'does ' +
          'not REQUIRE one. Bidirectional: the params go up, an SVID or a ' +
          'challenge comes back. The CSR is real even where the attestation ' +
          'payload is taken on trust.',
    request: { params: {
      data: { type: 'join_token', payload: '<a join token>' },
      params: { csr: '<base64 DER PKCS#10>' }
    } }
  },
  'agent.RenewAgent': {
    what: 'Renew the agent ON THE CONNECTION — never one named in the ' +
          'request, which is the distinction that made this method ' +
          'answerable at all once the surface authenticated its callers.',
    request: { params: { csr: '<base64 DER PKCS#10>' } }
  },
  'agent.CreateJoinToken': {
    what: 'Mint a join token: the one attestation payload a SPIRE server ' +
          'ISSUES and can therefore verify. Single-use, expiring, and ' +
          'optionally bound to one agent id.',
    request: { ttl: 600 }
  },
  'agent.PostStatus': {
    what: 'An agent reporting its own health. An agent method, so the ' +
          'credential decides who is reporting.',
    request: {}
  },

  // --- Bundle -----------------------------------------------------------
  'bundle.GetBundle': {
    what: 'This trust domain\'s own bundle. OPEN TO EVERYBODY, in a real ' +
          'SPIRE server too: it is the root of trust and it is published.',
    request: {}
  },
  'bundle.CountBundles': {
    what: 'How many FEDERATED bundles are held. This trust domain\'s own is ' +
          'not one of them.',
    request: {}
  },
  'bundle.AppendBundle': {
    what: 'Add authorities to this trust domain\'s own bundle. A server is ' +
          'right to refuse: it would publish an authority it holds no key ' +
          'for, which every workload in the trust domain would then trust.',
    request: { x509_authorities: [], jwt_authorities: [] }
  },
  'bundle.PublishJWTAuthority': {
    what: 'The JWT half of AppendBundle, for a DOWNSTREAM server. Same ' +
          'refusal, same reason.',
    request: { jwt_authority: {} }
  },
  'bundle.PublishWITAuthority': {
    what: 'The WIT half. A server that issues no WIT-SVIDs answers ' +
          'Unimplemented.',
    request: { wit_authority: {} }
  },
  'bundle.ListFederatedBundles': {
    what: 'Every foreign trust domain\'s bundle this server holds.',
    request: {}
  },
  'bundle.GetFederatedBundle': {
    what: 'One foreign bundle by trust domain NAME — `example.com`, not ' +
          '`spiffe://example.com`.',
    request: { trust_domain: 'example.com' }
  },
  'bundle.BatchCreateFederatedBundle': {
    what: 'Push a foreign bundle in. A bundle is PUSHED and never FETCHED ' +
          'here: dereferencing a URL the far end chose is a server-side ' +
          'request forgery with a specification citation attached.',
    request: { bundle: [{ trust_domain: 'example.com', x509_authorities: [],
                          jwt_authorities: [] }] }
  },
  'bundle.BatchUpdateFederatedBundle': {
    what: 'Replace a foreign bundle that is already held.',
    request: { bundle: [{ trust_domain: 'example.com' }] }
  },
  'bundle.BatchSetFederatedBundle': {
    what: 'Create or replace — the idempotent form, which is what a ' +
          'configuration loop wants.',
    request: { bundle: [{ trust_domain: 'example.com' }] }
  },
  'bundle.BatchDeleteFederatedBundle': {
    what: 'Stop federating. `mode` decides what happens to the registration ' +
          'entries that federate with it, and the default RESTRICT refuses ' +
          'while any still do.',
    request: { trust_domains: ['example.com'], mode: 'RESTRICT' }
  },

  // --- SVID -------------------------------------------------------------
  'svid.MintX509SVID': {
    what: '`spire-server x509 mint`: a one-off certificate outside any ' +
          'registration entry. The CSR is the ONLY statement of what is ' +
          'wanted, so the identity is read out of it rather than out of an ' +
          'entry — which is what makes this method different from every ' +
          'other minting call here.',
    request: { csr: '<base64 DER PKCS#10>', ttl: 3600 }
  },
  'svid.MintJWTSVID': {
    what: 'A JWT-SVID for an identity you name. Refuses with no audience, ' +
          'for the reason FetchJWTSVID does.',
    request: { id: { trust_domain: 'example.org', path: '/example' },
               audience: ['spiffe://example.org/db'], ttl: 300 }
  },
  'svid.MintWITSVID': {
    what: 'The WIT form. Unimplemented on a server that issues none.',
    request: {}
  },
  'svid.BatchNewX509SVID': {
    what: 'What an AGENT calls to sign the CSRs of the workloads it is ' +
          'attesting — one per entry id. Only the public key is read out of ' +
          'each CSR; the identity comes from the entry.',
    request: { params: [{ entry_id: '<entry id>',
                          csr: '<base64 DER PKCS#10>' }] }
  },
  'svid.NewJWTSVID': {
    what: 'The agent\'s form of MintJWTSVID: an entry id rather than an ' +
          'identity, because an agent may not name an identity it was not ' +
          'given.',
    request: { entry_id: '<entry id>',
               audience: ['spiffe://example.org/db'] }
  },
  'svid.BatchNewWITSVID': {
    what: 'The WIT form. Unimplemented on a server that issues none.',
    request: { params: [] }
  },
  'svid.NewDownstreamX509CA': {
    what: 'A signing certificate for a NESTED SPIRE server. The DOWNSTREAM ' +
          'entity, and the only method on this surface that hands out a ' +
          'certificate which can sign others.',
    request: { csr: '<base64 DER PKCS#10>' }
  },

  // --- TrustDomain ------------------------------------------------------
  'trustdomain.ListFederationRelationships': {
    what: 'Which trust domains this one federates with, at which bundle ' +
          'endpoint, under which profile.',
    request: {}
  },
  'trustdomain.GetFederationRelationship': {
    what: 'One relationship by trust domain name.',
    request: { trust_domain: 'example.com' }
  },
  'trustdomain.BatchCreateFederationRelationship': {
    what: 'Record a relationship. `https_web` trusts the public web PKI for ' +
          'the endpoint; `https_spiffe` trusts a SPIFFE ID, which is the ' +
          'profile that makes federation self-contained.',
    request: { federation_relationships: [{
      trust_domain: 'example.com',
      bundle_endpoint_url: 'https://example.com/bundle',
      https_spiffe: { endpoint_spiffe_id: {
        trust_domain: 'example.com', path: '/spire/server' } }
    }] }
  },
  'trustdomain.BatchUpdateFederationRelationship': {
    what: 'Change one.',
    request: { federation_relationships: [{ trust_domain: 'example.com' }] }
  },
  'trustdomain.BatchDeleteFederationRelationship': {
    what: 'Stop recording one. This does not delete the BUNDLE — that is ' +
          'BatchDeleteFederatedBundle, and the two being separate is the ' +
          'point.',
    request: { trust_domains: ['example.com'] }
  },
  'trustdomain.RefreshBundle': {
    what: 'Ask the server to go and FETCH a federated bundle. A server may ' +
          'well refuse, naming the URL it is not fetching — the same refusal ' +
          'WS-Federation\'s wreqptr and OIDC\'s jwks_uri get here, and for ' +
          'the ' +
          'same reason.',
    request: { trust_domain: 'example.com' }
  },

  // --- Debug ------------------------------------------------------------
  'debug.GetInfo': {
    what: 'Uptime, and how many entries, agents and federated bundles the ' +
          'server holds. LOCAL-ONLY in SPIRE\'s own authorization table, so ' +
          'an administrator\'s SVID over TCP is refused it — that reads like ' +
          'an omission and is not: it is a health check for whoever is ' +
          'standing on the host.',
    request: {}
  }
};

function resolvePositiveNumber(value, fallback, name, log) {
  log.debug("Entering resolvePositiveNumber().");
  if (typeof value === 'number' && isFinite(value) && value > 0) {
    log.debug("Leaving resolvePositiveNumber().");
    return value;
  }
  if (value !== undefined && value !== null) {
    log.error('spiffe_client: ' + name + ' is not a positive number (' +
              JSON.stringify(value) + '); using ' + fallback + '.');
  }
  log.debug("Leaving resolvePositiveNumber().");
  return fallback;
}

// The port allowlist, with `ldap_client.js`'s rules: a malformed entry is
// dropped with its reason logged, an allowlist that ends up empty refuses every
// call (the safe direction, and almost certainly a mistake, so it is logged as
// one), and `"any"` is a word rather than a symbol.
function resolveAllowedPorts(value, log) {
  log.debug("Entering resolveAllowedPorts().");
  if (value === undefined || value === null) {
    log.debug("Leaving resolveAllowedPorts(). Default.");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  if (value === 'any') {
    log.debug("Leaving resolveAllowedPorts(). Any port is allowed.");
    return 'any';
  }
  if (!Array.isArray(value)) {
    log.error('spiffe_client: spiffeAllowedPorts must be an array of port ' +
              'numbers, or the string "any"; using the default ' +
              DEFAULT_ALLOWED_PORTS.join(', ') + '.');
    log.debug("Leaving resolveAllowedPorts(). Default.");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  const ports = [];
  for (const entry of value) {
    const port = typeof entry === 'number' ? entry : parseInt(entry, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error('spiffe_client: ignoring spiffeAllowedPorts entry ' +
                JSON.stringify(entry) +
                ' — a port must be an integer from 1 to 65535.');
      continue;
    }
    if (ports.indexOf(port) === -1) {
      ports.push(port);
    }
  }
  if (!ports.length) {
    log.error('spiffe_client: spiffeAllowedPorts contained no usable ports, ' +
              'so every gRPC call will be refused. That is the safe ' +
              'direction, but it is almost certainly a configuration mistake.');
  }
  log.debug("Leaving resolveAllowedPorts().");
  return ports;
}

// The socket-path allowlist. Prefixes rather than exact paths, because SPIRE's
// own layout puts the socket under a directory whose last component a
// deployment chooses.
function resolveAllowedSocketPaths(value, log) {
  log.debug("Entering resolveAllowedSocketPaths().");
  if (value === undefined || value === null) {
    log.debug("Leaving resolveAllowedSocketPaths(). Default.");
    return DEFAULT_ALLOWED_SOCKET_PATHS.slice();
  }
  if (value === 'any') {
    log.debug("Leaving resolveAllowedSocketPaths(). Any path is allowed.");
    return 'any';
  }
  if (!Array.isArray(value)) {
    log.error('spiffe_client: spiffeAllowedSocketPaths must be an array of ' +
              'path prefixes, or the string "any"; using the default ' +
              DEFAULT_ALLOWED_SOCKET_PATHS.join(', ') + '.');
    log.debug("Leaving resolveAllowedSocketPaths(). Default.");
    return DEFAULT_ALLOWED_SOCKET_PATHS.slice();
  }
  const prefixes = [];
  for (const entry of value) {
    const text = String(entry == null ? '' : entry).trim();
    if (!text || text.charAt(0) !== '/') {
      log.error('spiffe_client: ignoring spiffeAllowedSocketPaths entry ' +
                JSON.stringify(entry) +
                ' — a prefix must be an absolute path.');
      continue;
    }
    if (prefixes.indexOf(text) === -1) {
      prefixes.push(text);
    }
  }
  if (!prefixes.length) {
    log.error('spiffe_client: spiffeAllowedSocketPaths contained no usable ' +
              'prefixes, so every Unix socket call will be refused. That is ' +
              'the safe direction and is almost certainly a mistake.');
  }
  log.debug("Leaving resolveAllowedSocketPaths().");
  return prefixes;
}

// ---------------------------------------------------------------------------
// THE ADDRESS.
//
// Three spellings, and an unrecognised scheme is REFUSED rather than defaulted.
// That matters more here than it does for LDAP: grpc-js's own resolver treats
// an unknown scheme as a DNS name, so `htp://host:8081` would be dialled as a
// host called "htp" — a DNS failure naming something that is not the mistake.
//
//   unix:///var/run/x.sock   a Unix socket. Also `unix:/var/run/x.sock`, which
//                            is grpc's own relative-path spelling and is the
//                            one `SPIFFE_ENDPOINT_SOCKET` usually carries.
//   tcp://host:port          explicit
//   host:port                the bare form every SPIRE document uses
// ---------------------------------------------------------------------------
function parseAddress(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    return { ok: false, reason: 'an address is required and none was given' };
  }
  const unix = /^unix:(\/\/)?(\/.*)$/i.exec(text);
  if (unix) {
    return { ok: true, kind: 'unix', socketPath: unix[2],
             target: 'unix://' + unix[2], display: 'unix://' + unix[2] };
  }
  if (/^unix:/i.test(text)) {
    return { ok: false,
             reason: 'a unix: address names an ABSOLUTE path — unix:///run/' +
                     'x.sock or unix:/run/x.sock' };
  }
  let authority = text;
  const tcp = /^tcp:\/\/(.+)$/i.exec(text);
  if (tcp) {
    authority = tcp[1];
  } else if (/^[a-z][a-z0-9+.\-]*:\/\//i.test(text)) {
    return { ok: false,
             reason: 'the scheme is not one this service dials. A SPIFFE ' +
                     'gRPC ' +
                     'address is host:port, tcp://host:port or unix:///path' };
  }
  // An IPv6 literal is written in brackets and the colon inside it is not the
  // port separator. Getting this wrong turns [::1]:8181 into a host of "[".
  let host;
  let port;
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
  if (v6) {
    host = v6[1];
    port = v6[2] ? parseInt(v6[2], 10) : null;
  } else {
    const parts = authority.split(':');
    if (parts.length > 2) {
      return { ok: false,
               reason: 'an IPv6 literal is written in brackets — [::1]:8181' };
    }
    host = parts[0];
    port = parts.length > 1 ? parseInt(parts[1], 10) : null;
  }
  if (!host) {
    return { ok: false, reason: 'the address names no host' };
  }
  if (port === null) {
    return { ok: false,
             reason: 'the address names no port. gRPC has no default port ' +
                     'and ' +
                     'guessing one would dial something nobody asked for' };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, reason: 'the port is not a number from 1 to 65535' };
  }
  return { ok: true, kind: 'tcp', host: host, port: port,
           target: host + ':' + port, display: 'tcp://' + host + ':' + port };
}

// ---------------------------------------------------------------------------
// CONCATENATED DER, SPLIT INTO PEM BLOCKS — and this is not housekeeping.
//
// `FetchX509SVID` hands back the trust bundle as CONCATENATED DER, and node's
// `ca` option reads a DER buffer as ONE certificate and silently ignores
// everything after it. So a trust domain that has rotated — which is every one
// that has been up for a day — hands over two authorities, node keeps the
// first, and an SVID signed by the second is refused with a message about a
// signature and nothing about the bundle. The mock STS's own server records
// hitting this from the other side.
//
// Splitting needs no X.509 parser: each certificate is a DER SEQUENCE, so the
// length is in the header and the next one starts after it. A short read or a
// nonsense length stops the walk rather than throwing, because a bundle this
// service could not split is still worth reporting the readable part of.
// ---------------------------------------------------------------------------
function splitDerCertificates(buffer) {
  const out = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (buffer[offset] !== 0x30) {
      break;
    }
    if (offset + 2 > buffer.length) {
      break;
    }
    const first = buffer[offset + 1];
    let headerLength;
    let bodyLength;
    if (first < 0x80) {
      headerLength = 2;
      bodyLength = first;
    } else {
      const count = first & 0x7f;
      if (count === 0 || count > 4 || offset + 2 + count > buffer.length) {
        break;
      }
      headerLength = 2 + count;
      bodyLength = 0;
      for (let i = 0; i < count; i++) {
        bodyLength = (bodyLength * 256) + buffer[offset + 2 + i];
      }
    }
    const end = offset + headerLength + bodyLength;
    if (end > buffer.length) {
      break;
    }
    out.push(buffer.slice(offset, end));
    offset = end;
  }
  return out;
}

function derToPem(der, label) {
  const body = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
  return '-----BEGIN ' + label + '-----\n' + body.replace(/\n$/, '') +
         '\n-----END ' + label + '-----\n';
}

// A trust bundle in whatever the caller had, turned into the separate PEM
// blocks node needs. Accepts PEM already (passed through), base64 concatenated
// DER (split, then converted) or an array of either.
function bundleToPem(value) {
  const items = Array.isArray(value) ? value : [value];
  const blocks = [];
  items.forEach(function (item) {
    const text = String(item == null ? '' : item).trim();
    if (!text) {
      return;
    }
    if (text.indexOf('-----BEGIN') !== -1) {
      blocks.push(text.endsWith('\n') ? text : text + '\n');
      return;
    }
    const der = Buffer.from(text.replace(/\s+/g, ''), 'base64');
    splitDerCertificates(der).forEach(function (one) {
      blocks.push(derToPem(one, 'CERTIFICATE'));
    });
  });
  return blocks.join('');
}

// The URI subjectAltNames off a peer certificate as node reports it. node
// exposes `subjectaltname` as a single comma-separated string — `URI:spiffe://
// example.org/spire/server, DNS:x` — and there is no structured form, so this
// splits it. A comma inside a URI would break this and cannot occur: a comma is
// not in the SPIFFE path character class.
function uriNamesOf(certificate) {
  const text = String((certificate && certificate.subjectaltname) || '');
  if (!text) {
    return [];
  }
  return text.split(',').map(function (part) {
    return part.trim();
  }).filter(function (part) {
    return part.slice(0, 4).toUpperCase() === 'URI:';
  }).map(function (part) {
    return part.slice(4);
  });
}

function createSpiffeClient(appconfig, guard, log, deps) {
  log.debug("Entering createSpiffeClient().");
  appconfig = appconfig || {};
  const logger = log || { debug() {}, info() {}, warn() {}, error() {} };

  // Injectable for the reason `krb5_relay.js`'s and `ldap_client.js`'s are: a
  // deadline cannot be tested against a resolver that works, and `dns.lookup`
  // is getaddrinfo, so it ignores `dns.setServers` and cannot be pointed at a
  // black hole from inside the process. Nothing in server.js supplies these.
  const lookup = (deps && deps.lookup) || dns.lookup;
  const statSocket = (deps && deps.statSync) || fs.statSync;

  const allowedPorts =
    resolveAllowedPorts(appconfig.spiffeAllowedPorts, logger);
  const anyPort = allowedPorts === 'any';
  const allowedSocketPaths =
    resolveAllowedSocketPaths(appconfig.spiffeAllowedSocketPaths, logger);
  const anySocketPath = allowedSocketPaths === 'any';
  const connectTimeout = resolvePositiveNumber(appconfig.connectionTimeout,
    DEFAULT_CONNECT_TIMEOUT_MS, 'connectionTimeout', logger);
  const callTimeout = resolvePositiveNumber(appconfig.callTimeout,
    DEFAULT_CALL_TIMEOUT_MS, 'callTimeout', logger);
  const maxResultBytes = resolvePositiveNumber(appconfig.maxContentLength,
    DEFAULT_MAX_RESULT_BYTES, 'maxContentLength', logger);
  const maxStreamMessages = resolvePositiveNumber(
    appconfig.spiffeMaxStreamMessages, DEFAULT_MAX_STREAM_MESSAGES,
    'spiffeMaxStreamMessages', logger);
  const streamTimeout = resolvePositiveNumber(appconfig.spiffeStreamTimeout,
    DEFAULT_STREAM_TIMEOUT_MS, 'spiffeStreamTimeout', logger);
  const addressPolicyEnabled = !!(guard && guard.enabled);

  logger.info('spiffe_client: ports ' +
    (anyPort ? 'ANY (spiffeAllowedPorts is "any")'
             : (allowedPorts.join(', ') || '(none — every call is refused)')) +
    '; socket paths ' +
    (anySocketPath ? 'ANY (spiffeAllowedSocketPaths is "any")'
                   : (allowedSocketPaths.join(', ') ||
                      '(none — every socket call is refused)')) +
    '; connect timeout ' + connectTimeout + ' milliseconds; call timeout ' +
    callTimeout + ' milliseconds; result cap ' + maxResultBytes +
    ' bytes and ' + maxStreamMessages + ' stream message(s); stream ' +
    'deadline ' + streamTimeout + ' milliseconds; address policy ' +
    (addressPolicyEnabled ? 'ENABLED (shared with ssrf_guard)' : 'disabled'));

  function refuse(message, code) {
    const error = new Error(message);
    error.code = code || 'ESPIFFEREFUSED';
    error.refused = true;
    return error;
  }

  function assertPortAllowed(port) {
    log.debug("Entering assertPortAllowed().");
    if (anyPort) {
      log.debug("Leaving assertPortAllowed(). Any port is allowed.");
      return;
    }
    if (allowedPorts.indexOf(port) === -1) {
      log.debug("Leaving assertPortAllowed(). The port is not allowed.");
      throw refuse('Refusing to open a gRPC connection to port ' + port +
        '. This service speaks SPIFFE to SPIFFE ports only (' +
        (allowedPorts.join(', ') || 'none configured') + '). Add the port to ' +
        'spiffeAllowedPorts if this deployment needs it, or set that setting ' +
        'to the string "any".', 'ESPIFFEPORTNOTALLOWED');
    }
    log.debug("Leaving assertPortAllowed().");
  }

  // The three checks a caller-chosen filesystem path gets. See the header for
  // why this endpoint has them and no other endpoint in this service does.
  function assertSocketAllowed(socketPath) {
    log.debug("Entering assertSocketAllowed().");
    if (Buffer.byteLength(socketPath, 'utf8') > MAX_SOCKET_PATH_BYTES) {
      log.debug("Leaving assertSocketAllowed(). Too long.");
      throw refuse('That socket path is ' +
        Buffer.byteLength(socketPath, 'utf8') + ' bytes. A Unix socket path ' +
        'is bounded by sun_path at ' + MAX_SOCKET_PATH_BYTES + ' bytes here, ' +
        'and past it the operating system fails the connect with a message ' +
        'about the address already being in use — which names something that ' +
        'is not the problem. Move the socket somewhere shorter.',
        'ESPIFFESOCKETPATHTOOLONG');
    }
    if (!anySocketPath) {
      const allowed = allowedSocketPaths.some(function (prefix) {
        return socketPath === prefix ||
               socketPath.slice(0, prefix.length) === prefix;
      });
      if (!allowed) {
        log.debug("Leaving assertSocketAllowed(). Not under a prefix.");
        throw refuse('Refusing to connect to the Unix socket ' + socketPath +
          '. This service connects only to sockets under ' +
          (allowedSocketPaths.join(', ') || 'no configured prefix') +
          '. A path is not an address, so the address policy cannot judge ' +
          'one ' +
          '— this allowlist is what stands in its place. Add the prefix to ' +
          'spiffeAllowedSocketPaths, or set that setting to the string "any".',
          'ESPIFFESOCKETNOTALLOWED');
      }
    }
    let stat = null;
    try {
      stat = statSocket(socketPath);
    } catch (e) {
      log.debug("Leaving assertSocketAllowed(). Not there.");
      throw refuse('There is nothing at ' + socketPath + ' (' + e.code +
        '). A Workload API socket is created by the agent when it starts, so ' +
        'this usually means the agent is not running or SPIFFE_ENDPOINT_' +
        'SOCKET names somewhere else. Note that the path is resolved on the ' +
        'machine running this api, which is not the machine running your ' +
        'browser.', 'ESPIFFESOCKETMISSING');
    }
    if (!stat.isSocket()) {
      log.debug("Leaving assertSocketAllowed(). Not a socket.");
      throw refuse('There is something at ' + socketPath + ' and it is not a ' +
        'socket. Dialling it would fail with "connection refused", which ' +
        'reads as a service that is down rather than as a path that names ' +
        'the wrong thing.', 'ESPIFFENOTASOCKET');
    }
    log.debug("Leaving assertSocketAllowed().");
  }

  // Resolve a name and return an address that has passed the policy, then dial
  // THAT. The lookup has its own deadline for the reason `ldap_client.js`
  // records: until a name resolves, neither of the other budgets has started,
  // and an unbounded `dns.lookup` is a browser waiting on an api that never
  // answers. A late callback is dropped rather than raced — `dns.lookup` runs
  // in the libuv threadpool and cannot be cancelled.
  function resolveAllowedAddress(host) {
    log.debug("Entering resolveAllowedAddress(). host=" + host);
    log.debug("Leaving resolveAllowedAddress(). The promise is pending.");
    return new Promise(function (resolve, reject) {
      const literalFamily = net.isIP(host);
      if (literalFamily) {
        const range = addressPolicyEnabled && guard.blockedRangeFor(host);
        if (range) {
          return reject(refuse('Refusing to open a gRPC connection to ' +
            host + ': it is in the blocked range ' + range + '. This service ' +
            'does not connect to loopback or private network addresses. Set ' +
            'blockPrivateNetworkCalls to false in the api configuration if ' +
            'this deployment is meant to — the local and containerized ' +
            'stacks do, because their SPIRE server IS a private address.',
            'EBLOCKEDADDRESS'));
        }
        return resolve({ address: host, family: literalFamily });
      }
      let settled = false;
      const deadline = setTimeout(function () {
        if (settled) {
          return;
        }
        settled = true;
        logger.warn('spiffe_client: gave up resolving ' + host + ' after ' +
                    connectTimeout + ' milliseconds');
        reject(refuse('Timed out after ' + connectTimeout + ' milliseconds ' +
          'resolving ' + host + '. The name was never turned into an ' +
          'address, so no connection was attempted — this is a DNS problem ' +
          'on the machine running this service rather than anything about ' +
          'the SPIRE server.', 'ESPIFFEDNSTIMEOUT'));
      }, connectTimeout);
      lookup(host, { all: true }, function (err, addresses) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(deadline);
        if (err) {
          return reject(refuse('Could not resolve ' + host + ': ' +
            err.message + ' (' + err.code + ').', 'ESPIFFEDNS'));
        }
        const list = Array.isArray(addresses) ? addresses : [addresses];
        for (const entry of list) {
          const range = addressPolicyEnabled &&
            guard.blockedRangeFor(entry.address);
          if (range) {
            logger.warn('spiffe_client: refused ' + host + ' -> ' +
                        entry.address + ' (' + range + ')');
            return reject(refuse('Refusing to connect to ' + host +
              ': it resolves to ' + entry.address + ', which is in the ' +
              'blocked range ' + range + '. A name is judged by what it ' +
              'RESOLVES to, so localtest.me and 127.0.0.1.nip.io are caught ' +
              'by this same rule.', 'EBLOCKEDADDRESS'));
          }
        }
        if (!list.length) {
          return reject(refuse('Could not resolve ' + host +
            ': the resolver returned no addresses.', 'ESPIFFEDNS'));
        }
        resolve({ address: list[0].address, family: list[0].family });
      });
    });
  }

  // -------------------------------------------------------------------------
  // SPIFFE-AWARE SERVER VERIFICATION.
  //
  // The single most important twenty lines in this file, and the place a
  // reasonable implementation goes wrong. A SPIRE server's TLS certificate
  // carries **no DNS subjectAltName and no CN naming a host**: its only
  // subjectAltName is `URI:spiffe://<trust domain>/spire/server`. So node's
  // ordinary `checkServerIdentity` — which compares a hostname against DNS
  // names and the CN — CANNOT pass, and the failure it produces
  // (`ERR_TLS_CERT_ALTNAME_INVALID`, "Hostname/IP does not match") reads as a
  // certificate problem rather than as a check that was never applicable.
  //
  // The two wrong ways out of that are both worse than the problem. Turning
  // `rejectUnauthorized` off discards the CHAIN check as well, which is the one
  // that matters. Passing `ssl_target_name_override` makes the hostname check
  // pass by lying about the hostname, which verifies nothing and looks like it
  // does.
  //
  // So the check is REPLACED. The chain is still verified against the trust
  // bundle by TLS itself; what this adds is the SPIFFE half — the far end's
  // URI SAN, matched three ways, and the mode is the caller's explicit choice:
  //
  //   spiffe-id     it must be exactly this SPIFFE ID. The default, and what a
  //                 real client does: `spiffe://<trust domain>/spire/server`.
  //   trust-domain  any SPIFFE ID in this trust domain. Looser, and honest
  //                 about being so.
  //   none          check nothing and REPORT what was presented. Explicit,
  //                 never a fallback, and the report is the point — a debugger
  //                 whose only answer to a mismatch is "it failed" cannot show
  //                 which identity actually turned up.
  //
  // An SVID has EXACTLY ONE URI SAN. Several is refused rather than searched:
  // choosing between two would be deciding which identity the far end has.
  // -------------------------------------------------------------------------
  // A failed SPIFFE-ID check is not a network failure and must not be reported
  // as one. TLS gives back only an Error, and grpc-js wraps it in an
  // UNAVAILABLE whose details begin "No connection established" — which reads
  // as a server that is not there, when in fact a server answered, presented a
  // valid certificate from a trusted authority, and turned out to be somebody
  // else. That is one of the most interesting things this workflow can show,
  // so the reason is recorded on the way past and the answer names it.
  function remember(seen, message) {
    log.debug("Entering remember().");
    seen.identityError = message;
    log.debug("Leaving remember().");
    return new Error(message);
  }

  function serverIdentityCheck(mode, expectedId, expectedDomain, seen) {
    log.debug("Entering serverIdentityCheck().");
    log.debug("Leaving serverIdentityCheck(). Returning the callback.");
    return function (host, certificate) {
      const uris = uriNamesOf(certificate);
      seen.uris = uris;
      seen.subject = (certificate && certificate.subject) || null;
      seen.issuer = (certificate && certificate.issuer) || null;
      seen.validFrom = (certificate && certificate.valid_from) || '';
      seen.validTo = (certificate && certificate.valid_to) || '';
      seen.identityError = '';
      if (mode === 'none') {
        return undefined;
      }
      if (!uris.length) {
        return remember(seen, 'The server presented a certificate with no ' +
          'URI ' +
          'subjectAltName, so it carries no SPIFFE ID at all. That is not a ' +
          'SPIFFE server certificate — check that this address is the SPIRE ' +
          'Server API and not something else listening on TLS.');
      }
      if (uris.length > 1) {
        return remember(seen, 'The server presented a certificate with ' +
          uris.length + ' URI subjectAltNames (' + uris.join(', ') + '). An ' +
          'SVID has exactly one, and choosing between two would be deciding ' +
          'which identity the far end has.');
      }
      const presented = uris[0];
      if (mode === 'trust-domain') {
        if (!spiffeId.memberOf(presented, expectedDomain)) {
          return remember(seen, 'The server is ' + presented + ', which is ' +
            'not in ' +
            'the trust domain ' + expectedDomain + '. Note that membership ' +
            'is decided by comparing parsed trust domains and never by a ' +
            'prefix test, so spiffe://' + expectedDomain +
            '.example.invalid/x does not pass.');
        }
        return undefined;
      }
      if (presented !== expectedId) {
        return remember(seen, 'The server is ' + presented + ' and this call ' +
          'expected ' + expectedId + '. The chain verified — that is a real ' +
          'certificate from a trusted authority — but it names a different ' +
          'identity, which is precisely the cross-domain confusion a trust ' +
          'bundle exists to prevent.');
      }
      return undefined;
    };
  }

  // The metadata a call carries. Refused BY SHAPE rather than by an allowlist,
  // which is the decision `scim_proxy.js` records: a debugger has to be able to
  // send the header a server it has never met asks for. What is refused is the
  // set that changes the shape of the request — anything whose name is not a
  // token, anything whose value carries CR or LF, and the `grpc-` reserved
  // prefix, which is the framing itself.
  function buildMetadata(headers, surface, securityHeader) {
    log.debug("Entering buildMetadata().");
    const metadata = new grpc.Metadata();
    // The one header the Workload Endpoint specification requires, and the one
    // check a permissive SPIFFE server still makes. It is not a security
    // control — anybody can send a header — it exists so a caller cannot reach
    // the endpoint BY ACCIDENT, and a client that omits it has a bug that only
    // a conforming server will ever report.
    if (surface === 'workload' && securityHeader !== false) {
      metadata.set('workload.spiffe.io', 'true');
    }
    const given = headers || {};
    Object.keys(given).forEach(function (name) {
      const key = String(name);
      if (!/^[!#$%&'*+\-.^_`|~0-9a-zA-Z]+$/.test(key)) {
        throw refuse('The metadata name ' + JSON.stringify(key) + ' is not a ' +
          'token, so it cannot go on the wire.', 'ESPIFFEBADMETADATA');
      }
      if (key.toLowerCase().slice(0, 5) === 'grpc-') {
        throw refuse('The metadata name ' + key + ' is reserved: the grpc- ' +
          'prefix is the framing itself, and setting one changes how the far ' +
          'end reads the call rather than what it is told.',
          'ESPIFFEBADMETADATA');
      }
      const value = String(given[name] == null ? '' : given[name]);
      if (/[\r\n]/.test(value)) {
        throw refuse('The value of the metadata ' + key + ' carries a ' +
          'carriage return or a line feed.', 'ESPIFFEBADMETADATA');
      }
      metadata.set(key.toLowerCase(), value);
    });
    log.debug("Leaving buildMetadata().");
    return metadata;
  }

  // Wrap the fields the protos declare as google.protobuf wrappers, where the
  // caller sent a bare value. See WRAPPED_FIELDS for why the list is explicit.
  function wrapFields(key, request) {
    log.debug("Entering wrapFields().");
    const paths = WRAPPED_FIELDS[key] || [];
    paths.forEach(function (dotted) {
      const parts = dotted.split('.');
      let node = request;
      for (let i = 0; i < parts.length - 1; i++) {
        if (!node || typeof node !== 'object') {
          return;
        }
        node = node[parts[i]];
      }
      if (!node || typeof node !== 'object') {
        return;
      }
      const last = parts[parts.length - 1];
      const value = node[last];
      if (value === undefined || value === null) {
        return;
      }
      if (typeof value === 'object' && !Array.isArray(value)) {
        return;
      }
      node[last] = { value: value };
    });
    log.debug("Leaving wrapFields().");
    return request;
  }

  // A google.protobuf.Struct as plain JSON. The members are camelCase because
  // keepCase does not reach the well-known types — see STRUCT_FIELDS.
  function structToJson(struct) {
    log.debug("Entering structToJson().");
    if (!struct || typeof struct !== 'object' || !struct.fields) {
      log.debug("Leaving structToJson(). Not a Struct.");
      return struct;
    }
    const out = {};
    Object.keys(struct.fields).forEach(function (name) {
      out[name] = valueToJson(struct.fields[name]);
    });
    log.debug("Leaving structToJson().");
    return out;
  }

  function valueToJson(value) {
    log.debug("Entering valueToJson().");
    if (!value || typeof value !== 'object') {
      log.debug("Leaving valueToJson(). Not a Value.");
      return value;
    }
    const kind = value.kind;
    if (kind === 'nullValue') {
      log.debug("Leaving valueToJson(). null.");
      return null;
    }
    if (kind === 'numberValue') {
      log.debug("Leaving valueToJson(). number.");
      return value.numberValue;
    }
    if (kind === 'stringValue') {
      log.debug("Leaving valueToJson(). string.");
      return value.stringValue;
    }
    if (kind === 'boolValue') {
      log.debug("Leaving valueToJson(). bool.");
      return value.boolValue;
    }
    if (kind === 'structValue') {
      log.debug("Leaving valueToJson(). struct.");
      return structToJson(value.structValue);
    }
    if (kind === 'listValue') {
      const values = (value.listValue && value.listValue.values) || [];
      log.debug("Leaving valueToJson(). list.");
      return values.map(valueToJson);
    }
    log.debug("Leaving valueToJson(). Unknown kind.");
    return null;
  }

  function flattenStructs(key, message) {
    log.debug("Entering flattenStructs().");
    const fields = STRUCT_FIELDS[key] || [];
    fields.forEach(function (name) {
      if (message && Object.prototype.hasOwnProperty.call(message, name)) {
        message[name] = structToJson(message[name]);
      }
    });
    log.debug("Leaving flattenStructs().");
    return message;
  }

  // The gRPC status names, by code. Both halves matter to a debugger: the
  // number is what a client library reports and the name is what SPIRE's own
  // documentation and this workflow's authorization table are written in.
  function statusOf(error) {
    log.debug("Entering statusOf().");
    const code = (error && typeof error.code === 'number') ? error.code : 2;
    let name = 'UNKNOWN';
    Object.keys(grpc.status).forEach(function (key) {
      if (grpc.status[key] === code && /^[A-Z_]+$/.test(key)) {
        name = key;
      }
    });
    log.debug("Leaving statusOf(). " + code + ' ' + name);
    return { code: code, name: name,
             details: String((error && error.details) ||
                             (error && error.message) || '') };
  }

  // A gRPC error that is a STATUS FROM THE FAR END, as against a transport
  // failure — the difference between a 200 with `ok: false` and a 502, and the
  // most consequential decision this file makes.
  //
  // TWO SHAPES COUNT AS TRANSPORT, and the second one is the black hole.
  //
  //  * `UNAVAILABLE` whose details name a connection rather than a refusal:
  //    grpc-js reporting that it never got one. A server that is not there.
  //  * `DEADLINE_EXCEEDED` WITH NO MESSAGES RECEIVED. An address that is
  //    routed nowhere does not refuse a connection — nothing answers the SYN
  //    at all — so the call simply runs out the budget this service set, and
  //    reporting that as "the server answered DEADLINE_EXCEEDED" would be a
  //    200 describing an answer that never existed. The message count is what
  //    keeps this narrow: a STREAM that produced messages and then hit the
  //    deadline is a success with a note (see the timer in invoke()), which is
  //    the ordinary outcome of holding FetchX509SVID open and is nothing to do
  //    with the network.
  //
  // Everything else came back over the wire and is an ANSWER.
  function isTransportFailure(error, received) {
    log.debug("Entering isTransportFailure().");
    const code = error && error.code;
    const details = String((error && (error.details || error.message)) || '');
    // The alternation stays on one line: breaking a regular expression means
    // concatenating strings into `new RegExp`, which is a second place for it
    // to be wrong and reads worse than the line it saves.
    const unreachable = code === grpc.status.UNAVAILABLE &&
      /No connection established|Connection dropped|DNS resolution failed|Name resolution|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|certificate|handshake|socket/i
        .test(details);
    const silent = code === grpc.status.DEADLINE_EXCEEDED && !received;
    log.debug("Leaving isTransportFailure(). " + (unreachable || silent));
    return !!(unreachable || silent);
  }

  function methodKey(service, method) {
    return service + '.' + method;
  }

  // The method definition off the service, by the name the `.proto` writes.
  // grpc-js lowers the first letter (`fetchX509Svid`), so the client object
  // carries both spellings and the one that matches the proto is used here —
  // a lookup that silently missed would produce a client that advertises the
  // service and answers Unimplemented to everything.
  function methodDefinition(service, method) {
    log.debug("Entering methodDefinition().");
    const definition = SERVICES[service] && SERVICES[service].service;
    if (!definition) {
      log.debug("Leaving methodDefinition(). No service.");
      return null;
    }
    const found = definition[method] ||
      Object.keys(definition).map(function (key) {
        return definition[key];
      }).find(function (entry) {
        return entry.originalName === method ||
               entry.path.split('/').pop() === method;
      });
    log.debug("Leaving methodDefinition(). " + (found ? 'found' : 'not found'));
    return found || null;
  }

  // -----------------------------------------------------------------------
  // THE CATALOGUE. Derived from the service definitions the protos produced,
  // never typed out — see the header.
  // -----------------------------------------------------------------------
  function catalogue() {
    log.debug("Entering catalogue().");
    const surfaces = { workload: [], server: [] };
    Object.keys(SERVICES).forEach(function (service) {
      const definition = SERVICES[service].service;
      const methods = Object.keys(definition).map(function (key) {
        const entry = definition[key];
        const name = entry.path.split('/').pop();
        const note = METHOD_NOTES[methodKey(service, name)] || null;
        return {
          service: service,
          serviceLabel: SERVICE_LABELS[service],
          name: name,
          path: entry.path,
          requestStream: !!entry.requestStream,
          responseStream: !!entry.responseStream,
          what: note ? note.what : '',
          example: note ? note.request : {},
          described: !!note
        };
      }).sort(function (a, b) {
        return a.name.localeCompare(b.name);
      });
      surfaces[SURFACE_OF[service]].push({
        service: service, label: SERVICE_LABELS[service], methods: methods
      });
    });
    log.debug("Leaving catalogue().");
    return surfaces;
  }

  function limits() {
    log.debug("Entering limits().");
    const value = {
      ports: anyPort ? 'any' : allowedPorts.slice(),
      socketPaths: anySocketPath ? 'any' : allowedSocketPaths.slice(),
      maxSocketPathBytes: MAX_SOCKET_PATH_BYTES,
      connectionTimeoutMs: connectTimeout,
      callTimeoutMs: callTimeout,
      maxResultBytes: maxResultBytes,
      maxStreamMessages: maxStreamMessages,
      streamTimeoutMs: streamTimeout,
      addressPolicy: addressPolicyEnabled,
      serverIdentityModes: ['spiffe-id', 'trust-domain', 'none'],
      securityHeader: 'workload.spiffe.io',
      surfaces: catalogue(),
      // Said here rather than left to be met as a handshake failure, because
      // it is the fact about this workflow that surprises everybody once.
      notes: [
        'The Workload API is never authenticated: its specification says a ' +
        'client MUST NOT be required to authenticate, because a workload has ' +
        'no root of trust until that call gives it one.',
        'The SPIRE Server API\'s TCP port is mutual TLS and its Unix socket ' +
        'is the local entity. Those are opposite postures on one service and ' +
        'reading it as an inconsistency is the mistake to avoid.',
        'A SPIRE server\'s certificate carries no DNS name, so hostname ' +
        'verification cannot pass and is REPLACED here by a check on the ' +
        'SPIFFE ID in its URI subjectAltName.',
        'A stream is read for at most ' + maxStreamMessages + ' message(s) ' +
        'or ' + streamTimeout + ' milliseconds — its own deadline, longer ' +
        'than a unary call\'s ' + callTimeout + ' — and the answer says ' +
        'which stopped it.'
      ]
    };
    log.debug("Leaving limits().");
    return value;
  }

  // -----------------------------------------------------------------------
  // BUILDING THE CHANNEL.
  // -----------------------------------------------------------------------
  async function channelFor(options, surface) {
    log.debug("Entering channelFor().");
    const parsed = parseAddress(options.address);
    if (!parsed.ok) {
      log.debug("Leaving channelFor(). The address does not parse.");
      throw refuse('That address is not one this service dials: ' +
        parsed.reason + '.', 'ESPIFFEBADADDRESS');
    }
    let target;
    if (parsed.kind === 'unix') {
      assertSocketAllowed(parsed.socketPath);
      target = 'unix://' + parsed.socketPath;
    } else {
      assertPortAllowed(parsed.port);
      const resolved = await resolveAllowedAddress(parsed.host);
      // Dial the LITERAL that was checked. Unlike ldaps: this costs nothing —
      // see the header: SPIFFE identifies the far end by its SPIFFE ID, not by
      // a hostname, so there is no `servername` to preserve.
      target = net.isIPv6(resolved.address)
        ? '[' + resolved.address + ']:' + parsed.port
        : resolved.address + ':' + parsed.port;
      parsed.resolvedAddress = resolved.address;
    }

    const seen = {};
    let credentials;
    let tlsUsed = false;
    // The Workload API is plain, always, and this is the specification
    // speaking rather than a simplification: "Transport Layer Security MUST
    // NOT be required". A client that demanded it here would be unable to
    // bootstrap. `plaintext` on the server surface is the caller saying that
    // this deployment has `spiffe.authRequired` off.
    if (surface === 'workload' || options.plaintext === true) {
      credentials = grpc.credentials.createInsecure();
    } else {
      const mode = options.serverIdentityMode || 'spiffe-id';
      if (['spiffe-id', 'trust-domain', 'none'].indexOf(mode) === -1) {
        throw refuse('serverIdentityMode must be spiffe-id, trust-domain or ' +
          'none; it was ' + JSON.stringify(mode) + '.', 'ESPIFFEBADMODE');
      }
      const trustDomain = String(options.trustDomain || '').trim();
      let expectedId = String(options.serverId || '').trim();
      if (mode === 'spiffe-id' && !expectedId) {
        if (!trustDomain) {
          throw refuse('Verifying the server needs either the SPIFFE ID to ' +
            'expect or the trust domain to derive it from. A SPIRE server is ' +
            'spiffe://<trust domain>/spire/server.', 'ESPIFFENOSERVERID');
        }
        try {
          expectedId = spiffeId.serverId(trustDomain);
        } catch (e) {
          throw refuse('The trust domain ' + JSON.stringify(trustDomain) +
            ' cannot name a server: ' + e.message, 'ESPIFFEBADTRUSTDOMAIN');
        }
      }
      if (mode === 'trust-domain' && !trustDomain) {
        throw refuse('serverIdentityMode "trust-domain" needs the trust ' +
          'domain to check against.', 'ESPIFFENOTRUSTDOMAIN');
      }
      if (mode !== 'none' && !options.trustBundle) {
        throw refuse('Verifying the server needs its trust bundle — the ' +
          'x509-svid authorities of the trust domain, as PEM or as base64 ' +
          'DER. Fetch it from the bundle endpoint, or take it off any ' +
          'X509-SVID the Workload API handed you: that response carries the ' +
          'bundle beside the identity for exactly this.',
          'ESPIFFENOTRUSTBUNDLE');
      }
      const rootPem = options.trustBundle ? bundleToPem(options.trustBundle)
                                          : null;
      if (options.trustBundle && !rootPem) {
        throw refuse('The trust bundle supplied held no certificate this ' +
          'service could read. It takes PEM, or base64 CONCATENATED DER — ' +
          'which is what the Workload API returns and what node reads as one ' +
          'certificate, silently ignoring the rest.', 'ESPIFFEBADTRUSTBUNDLE');
      }
      const identity = options.identity || null;
      let keyPem = null;
      let certPem = null;
      if (identity && (identity.keyPem || identity.certPem)) {
        if (!identity.keyPem || !identity.certPem) {
          throw refuse('A client identity needs BOTH the certificate and its ' +
            'private key. An X509-SVID from the Workload API carries the key ' +
            'beside the certificate, which is what makes it usable here.',
            'ESPIFFEBADIDENTITY');
        }
        certPem = bundleToPem(identity.certPem);
        keyPem = String(identity.keyPem).indexOf('-----BEGIN') !== -1
          ? String(identity.keyPem)
          : derToPem(Buffer.from(String(identity.keyPem).replace(/\s+/g, ''),
                                 'base64'), 'PRIVATE KEY');
        if (!certPem) {
          throw refuse('The client certificate supplied could not be read as ' +
            'PEM or as base64 DER.', 'ESPIFFEBADIDENTITY');
        }
      }
      credentials = grpc.credentials.createSsl(
        rootPem ? Buffer.from(rootPem, 'utf8') : null,
        keyPem ? Buffer.from(keyPem, 'utf8') : null,
        certPem ? Buffer.from(certPem, 'utf8') : null,
        { checkServerIdentity: serverIdentityCheck(mode, expectedId,
                                                   trustDomain, seen),
          // The chain check stays on in every mode, including `none`: that
          // mode turns off the SPIFFE-ID check and nothing else. Turning this
          // off as well would discard the one check that matters and would
          // make the two modes indistinguishable in the answer.
          rejectUnauthorized: mode !== 'none' });
      tlsUsed = true;
    }

    log.debug("Leaving channelFor().");
    return { parsed: parsed, target: target, credentials: credentials,
             tls: tlsUsed, seen: seen };
  }

  // -----------------------------------------------------------------------
  // MAKING THE CALL. One path for all forty-nine methods, four call shapes.
  // -----------------------------------------------------------------------
  function invoke(client, definition, request, metadata, wanted, key) {
    log.debug("Entering invoke().");
    log.debug("Leaving invoke(). The promise is pending.");
    return new Promise(function (resolve) {
      const messages = [];
      let bytes = 0;
      let settled = false;
      let stopped = '';
      const method = definition.originalName ||
        definition.path.split('/').pop();
      // See DEFAULT_STREAM_TIMEOUT_MS: a stream and a call are bounded by
      // different questions, so they get different budgets.
      const budget = (definition.requestStream || definition.responseStream)
        ? streamTimeout : callTimeout;
      const deadline = new Date(Date.now() + budget);

      function finish(status, extra) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(Object.assign({ status: status, messages: messages,
                                stopped: stopped || 'end' }, extra || {}));
      }

      function keep(message) {
        const flattened = flattenStructs(key, message);
        const text = JSON.stringify(flattened);
        bytes += text ? text.length : 0;
        messages.push(flattened);
        if (bytes >= maxResultBytes) {
          stopped = 'size';
          return false;
        }
        if (messages.length >= wanted) {
          stopped = 'messages';
          return false;
        }
        return true;
      }

      const timer = setTimeout(function () {
        if (settled) {
          return;
        }
        stopped = 'timeout';
        try {
          if (call && call.cancel) {
            call.cancel();
          }
        } catch (e) {
          log.debug('invoke(): cancelling after the deadline threw ' +
                    e.message);
        }
        // A stream that has already produced messages and was stopped by the
        // deadline is a SUCCESS with a note, not a failure: holding
        // FetchX509SVID open is what a real client does, and reporting the
        // deadline as an error would make the normal case an error path.
        finish(messages.length ? { code: 0, name: 'OK', details: '' }
                               : { code: grpc.status.DEADLINE_EXCEEDED,
                                   name: 'DEADLINE_EXCEEDED',
                                   details: 'This service waited ' +
                                     budget + ' milliseconds and the far end ' +
                                     'sent nothing.' },
               messages.length ? {} : { transport: true });
      }, budget);

      let call;
      if (!definition.requestStream && !definition.responseStream) {
        call = client[method](request, metadata, { deadline: deadline },
          function (err, reply) {
            if (err) {
              return finish(statusOf(err),
                { transport: isTransportFailure(err, messages.length),
                  error: err });
            }
            keep(reply);
            finish({ code: 0, name: 'OK', details: '' });
          });
        return;
      }

      if (definition.requestStream) {
        call = client[method](metadata, { deadline: deadline });
      } else {
        call = client[method](request, metadata, { deadline: deadline });
      }

      call.on('data', function (message) {
        if (!keep(message)) {
          try {
            call.cancel();
          } catch (e) {
            log.debug('invoke(): cancelling a full stream threw ' + e.message);
          }
          finish({ code: 0, name: 'OK', details: '' });
        }
      });
      call.on('error', function (err) {
        // CANCELLED after this service cancelled is this service's own doing
        // and is not an answer. Anything else is.
        if (err && err.code === grpc.status.CANCELLED && stopped) {
          return finish({ code: 0, name: 'OK', details: '' });
        }
        finish(statusOf(err),
          { transport: isTransportFailure(err, messages.length), error: err });
      });
      call.on('end', function () {
        finish({ code: 0, name: 'OK', details: '' });
      });
      call.on('status', function (status) {
        if (status && status.code !== grpc.status.OK && !settled) {
          finish(statusOf(status),
            { transport: isTransportFailure(status, messages.length),
              error: status });
        }
      });

      if (definition.requestStream) {
        // ONE WRITE, AND THE STREAM IS DELIBERATELY LEFT OPEN.
        //
        // This looks like a leak and is the only correct thing to do. Both
        // bidirectional methods here are REQUEST/RESPONSE conversations that
        // may take more than one turn — `AttestAgent` may answer the params
        // with a CHALLENGE rather than an SVID, and the agent has to still be
        // there to answer it — so a client that half-closes as soon as it has
        // written has told the server the conversation is over before hearing
        // whether it was.
        //
        // It is not a theoretical point. A server that ends its own side when
        // it sees the client's `end` will do so while the reply is still being
        // produced, and the write that follows lands on a stream nobody is
        // reading: the call completes with status OK and NO MESSAGES, which
        // reads as a server that accepted an attestation and issued nothing.
        // That is exactly what this endpoint did until the stream was left
        // open, and `tests/spiffe_protocol.js` asserts a non-empty AttestAgent
        // response for that reason rather than asserting the status alone.
        //
        // What stops the call is therefore the message cap or the deadline,
        // both of which are reported in `stopped` — never a half-close.
        call.write(request);
      }
    });
  }

  async function call(options) {
    log.debug("Entering call().");
    options = options || {};
    const service = String(options.service || '');
    const method = String(options.method || '');
    if (!Object.prototype.hasOwnProperty.call(SERVICES, service)) {
      log.debug("Leaving call(). No such service.");
      throw refuse('There is no SPIFFE service called ' +
        JSON.stringify(service) + ' here. The surfaces are ' +
        Object.keys(SERVICES).join(', ') + '.', 'ESPIFFENOSERVICE');
    }
    const definition = methodDefinition(service, method);
    if (!definition) {
      log.debug("Leaving call(). No such method.");
      throw refuse('The ' + SERVICE_LABELS[service] + ' service has no ' +
        'method called ' + JSON.stringify(method) + '. GET /spiffe/limits ' +
        'lists every method on every surface.', 'ESPIFFENOMETHOD');
    }
    const surface = SURFACE_OF[service];
    const key = methodKey(service, method);
    const wanted = Math.min(
      Math.max(parseInt(options.maxMessages, 10) || 1, 1), maxStreamMessages);

    const request = wrapFields(key, options.request &&
      typeof options.request === 'object' && !Array.isArray(options.request)
        ? options.request : {});
    const metadata = buildMetadata(options.metadata, surface,
                                   options.securityHeader);
    const channel = await channelFor(options, surface);

    // The channel options, and the one that is here for a reason rather than
    // for tidiness. gRPC derives BOTH the :authority header and the TLS SNI
    // from the target, and the target is the LITERAL this service resolved and
    // checked — so without this, SNI is an IP address, which RFC 6066 does not
    // permit and node warns about and will one day drop. Setting the authority
    // back to the name the CALLER gave restores what an ordinary client would
    // have sent. It changes nothing about who the far end is proved to be:
    // that is decided by the SPIFFE ID in its certificate, by the check in
    // serverIdentityCheck(), and never by this string.
    const channelOptions = {};
    if (channel.parsed.kind === 'tcp' && !net.isIP(channel.parsed.host)) {
      channelOptions['grpc.default_authority'] =
        channel.parsed.host + ':' + channel.parsed.port;
    }
    const client = new SERVICES[service](channel.target, channel.credentials,
                                         channelOptions);
    let outcome;
    try {
      outcome = await invoke(client, definition, request, metadata, wanted,
                             key);
    } finally {
      try {
        grpc.closeClient(client);
      } catch (e) {
        log.debug('call(): closing the client threw ' + e.message);
      }
    }

    const answer = {
      ok: outcome.status.code === 0,
      surface: surface,
      service: service,
      serviceLabel: SERVICE_LABELS[service],
      method: method,
      path: definition.path,
      streaming: {
        request: !!definition.requestStream,
        response: !!definition.responseStream,
        stopped: outcome.stopped,
        wanted: wanted
      },
      target: channel.parsed.display,
      resolvedAddress: channel.parsed.resolvedAddress || '',
      transport: channel.parsed.kind,
      tls: channel.tls,
      peer: channel.seen,
      status: outcome.status,
      messages: outcome.messages,
      sent: request
    };
    if (channel.seen.identityError) {
      // A server answered and was refused for WHO IT IS. Reported as its own
      // outcome rather than as a network failure, because those are different
      // facts and only one of them is about the network.
      const mismatch = refuse(channel.seen.identityError,
                              'ESPIFFESERVERIDENTITY');
      mismatch.refused = false;
      mismatch.network = true;
      mismatch.identityMismatch = true;
      mismatch.answer = answer;
      log.debug("Leaving call(). The server was not who it had to be.");
      throw mismatch;
    }
    if (outcome.transport) {
      const error = refuse(outcome.status.details, 'ESPIFFEUNAVAILABLE');
      error.refused = false;
      error.network = true;
      error.answer = answer;
      log.debug("Leaving call(). Transport failure.");
      throw error;
    }
    log.debug("Leaving call(). status=" + outcome.status.name);
    return answer;
  }

  log.debug("Leaving createSpiffeClient().");
  return {
    call: call,
    catalogue: catalogue,
    limits: limits,
    parseAddress: parseAddress
  };
}

module.exports = {
  createSpiffeClient: createSpiffeClient,
  // Exported with no network in them so `tests/spiffe_engine.js` can assert
  // every refusal and every conversion with nothing on the other end — the
  // split `scim_proxy.js` records, applied to the parts of this file that can
  // have it.
  parseAddress: parseAddress,
  splitDerCertificates: splitDerCertificates,
  bundleToPem: bundleToPem,
  derToPem: derToPem,
  uriNamesOf: uriNamesOf,
  SERVICES: SERVICES,
  SURFACE_OF: SURFACE_OF,
  SERVICE_LABELS: SERVICE_LABELS,
  METHOD_NOTES: METHOD_NOTES,
  WRAPPED_FIELDS: WRAPPED_FIELDS,
  STRUCT_FIELDS: STRUCT_FIELDS,
  MAX_SOCKET_PATH_BYTES: MAX_SOCKET_PATH_BYTES,
  DEFAULT_STREAM_TIMEOUT_MS: DEFAULT_STREAM_TIMEOUT_MS,
  DEFAULT_ALLOWED_PORTS: DEFAULT_ALLOWED_PORTS,
  DEFAULT_ALLOWED_SOCKET_PATHS: DEFAULT_ALLOWED_SOCKET_PATHS
};
