// File: api_krb5_relay.js
//
// api/krb5_relay.js and api/krb5_frame.js — the guarded byte relay behind
// POST /krb5/kdc.
//
// ---------------------------------------------------------------------------
// Why this test exists, and why it is the important one in phase 2.
//
// Every other outbound call this service makes goes through axios, and
// api/ssrf_guard.js is installed there: an interceptor plus `lookup` and
// `createConnection` hooks on the agents. **A raw `net.connect` walks past all of
// it.** So this relay is a second enforcement of the same policy for a transport
// the guard has never seen, and a second enforcement is exactly the kind of thing
// that is subtly weaker than the first unless something holds it to account.
//
// It is also a BROADER primitive than anything this service had before. The HTTP
// endpoints fetch URLs; this one carries caller-supplied bytes to a
// caller-supplied host and port. An HTTP fetcher aimed at port 22 gets nothing
// useful. A byte relay aimed at port 22 is a port scanner with a payload of the
// caller's choosing. Four things bound it and all four are tested here:
//
//   1. the address policy, shared with the HTTP side (loopback and private refused);
//   2. resolve-then-connect-to-the-literal, so a NAME is judged by what it resolves to;
//   3. a port allowlist, which is new;
//   4. a message-shape pre-flight, so the payload must be a Kerberos request
//      before a socket is opened at all.
//
// Plus the limits, and one assertion that earns its keep more than the rest: a
// host that **connects and then says nothing** must still be waiting well past
// the connect budget and fail only at the call budget. That assertion fails
// against an implementation that expresses both deadlines with one timer — which
// is the natural way to write it — and it is the same case api_connect_timeout.js
// makes for the HTTP side.
//
// Every listener here is a throwaway on 127.0.0.1 with the address policy
// DISABLED, which is what the local and containerized stacks do anyway (their KDC
// is a private address). The policy itself is tested separately, enabled.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const net = require("net");
const dgram = require("dgram");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_krb5_relay",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout these are under api/; the tests image copies them flat beside the
// test scripts (see tests/Dockerfile). Resolved through module_paths.js so both
// layouts work and a missing COPY fails with a pointed message rather than a bare
// MODULE_NOT_FOUND.
const paths = require("./module_paths.js");
function apiModule(name) {
  return paths.requireSharedModule(
    [path.join(__dirname, "..", "api", name), path.join(__dirname, name)], name);
}
const relayMod = apiModule("krb5_relay.js");
const frame = apiModule("krb5_frame.js");
const ssrfGuard = apiModule("ssrf_guard.js");

const quiet = { debug() {}, info() {}, warn() {}, error() {} };

// A minimal well-formed AS-REQ shell: the outer [APPLICATION 10] tag with a
// declared length that matches. The relay's pre-flight reads no further than
// this, deliberately — see api/krb5_frame.js on why the guard does not import the
// full codec.
function asReq(contentBytes) {
  const content = contentBytes || Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);
  return Buffer.concat([Buffer.from([0x6a, content.length]), content]);
}
function tgsReq() { const c = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]); return Buffer.concat([Buffer.from([0x6c, c.length]), c]); }
function apReq() { const c = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]); return Buffer.concat([Buffer.from([0x6e, c.length]), c]); }
// A KRB-ERROR, which is what a KDC answers with most of the time.
function krbError() { const c = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]); return Buffer.concat([Buffer.from([0x7e, c.length]), c]); }

// The relay as the local and containerized stacks configure it: the address
// policy off, because their KDC is on a private address.
function localRelay(overrides) {
  const cfg = Object.assign({
    blockPrivateNetworkCalls: false,
    krb5AllowedPorts: [88, 464, 749],
    connectionTimeout: 700,
    callTimeout: 2500,
    maxContentLength: 4096
  }, overrides || {});
  const guard = ssrfGuard.createGuard(cfg, quiet);
  return relayMod.createRelay(cfg, guard, quiet);
}

// The throwaway listeners below bind port 0, so the OS hands out an ephemeral
// high port — which the allowlist correctly refuses. That refusal is the feature
// working, so the port is added to the allowlist for the tests that need a real
// exchange, rather than the allowlist being widened globally (which would leave
// the allowlist untested by everything else in this file).
function relayAllowing(port, overrides) {
  return localRelay(Object.assign({ krb5AllowedPorts: [88, 464, 749, port] }, overrides || {}));
}

// A throwaway listener, torn down properly.
//
// Two details, both of which cost a hang while this file was being written.
// `server.close(cb)` stops ACCEPTING and then waits for every already-accepted
// socket to be destroyed — and most of the handlers below deliberately never
// close their end (that is what "a host that says nothing" means), so the close
// callback never fired and the whole test stalled until the timeout. So the
// accepted sockets are tracked and destroyed here. And each one gets an `error`
// listener because the relay destroys its side of the connection, which can
// arrive as ECONNRESET: an `error` with no listener on a socket is an uncaught
// exception, i.e. a crash in the test rather than in the code under test.
async function withTcpServer(handler, fn) {
  const sockets = new Set();
  const server = net.createServer(function (socket) {
    sockets.add(socket);
    socket.on("error", function () {});
    socket.on("close", function () { sockets.delete(socket); });
    handler(socket);
  });
  await new Promise(function (resolve) { server.listen(0, "127.0.0.1", resolve); });
  const port = server.address().port;
  try {
    return await fn(port);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(function (resolve) { server.close(resolve); });
  }
}

async function withUdpServer(handler, fn) {
  const socket = dgram.createSocket("udp4");
  await new Promise(function (resolve) { socket.bind(0, "127.0.0.1", resolve); });
  socket.on("message", function (msg, rinfo) { handler(socket, msg, rinfo); });
  const port = socket.address().port;
  try {
    return await fn(port);
  } finally {
    await new Promise(function (resolve) { socket.close(resolve); });
  }
}

async function mustReject(what, promise, code) {
  let threw = null;
  try {
    await promise;
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, "expected a refusal: " + what);
  if (code) {
    assert.strictEqual(threw.code, code,
      what + ": refused with " + threw.code + " rather than " + code + " (" + threw.message + ")");
  }
  log.debug("refused as it should: " + what + " [" + threw.code + "] " + threw.message);
  return threw;
}

// ---------------------------------------------------------------------------
// The happy path, and the framing.
// ---------------------------------------------------------------------------
async function relaysAKerberosExchangeOverTcp() {
  log.debug("Entering relaysAKerberosExchangeOverTcp().");
  const relay = localRelay();
  const request = asReq();
  let seen = null;

  const result = await withTcpServer(function (socket) {
    let buf = Buffer.alloc(0);
    socket.on("data", function (chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const declared = buf.readUInt32BE(0);
      if (buf.length < 4 + declared) return;
      seen = { declared: declared, message: buf.subarray(4, 4 + declared) };
      const reply = krbError();
      const framed = Buffer.alloc(4 + reply.length);
      framed.writeUInt32BE(reply.length, 0);
      reply.copy(framed, 4);
      socket.write(framed);
    });
  }, function (port) {
    return relayAllowing(port).send({ host: "127.0.0.1", port: port, message: request });
  });

  // The four-byte big-endian prefix is computed by the relay, not supplied by the
  // caller, and it must describe the message exactly.
  assert.ok(seen, "the listener received nothing");
  assert.strictEqual(seen.declared, request.length,
    "the TCP length prefix must equal the message length");
  assert.strictEqual(Buffer.compare(seen.message, request), 0,
    "the message must arrive byte-for-byte as it was given");

  assert.strictEqual(result.request.message, "AS-REQ", "the request must be identified");
  assert.strictEqual(result.replyMessage, "KRB-ERROR",
    "the reply must be identified — a KDC answers most requests with an error, and saying which " +
    "one is the whole value of this endpoint");
  assert.strictEqual(Buffer.compare(Buffer.from(result.reply), krbError()), 0,
    "the reply must come back with its length prefix REMOVED");
  assert.strictEqual(result.target.transport, "tcp", "transport");
  assert.strictEqual(result.target.address, "127.0.0.1", "the address actually connected to");
  assert.strictEqual(result.target.resolved, false, "a literal address was not resolved");
  assert.ok(result.timing.totalMs >= 0 && result.timing.connectMs !== null,
    "the timings must be reported — a debugger's user wants to know where the time went");

  // A KDC answers an AS-REQ and a TGS-REQ. An AP-REQ is NOT relayed here — it goes to
  // a service, and the two have different port policies, so the endpoints are
  // separate. The refusal for that case is asserted below.
  for (const [name, message] of [["TGS-REQ", tgsReq()]]) {
    const r = await withTcpServer(function (socket) {
      socket.on("data", function () {
        const reply = krbError();
        const framed = Buffer.alloc(4 + reply.length);
        framed.writeUInt32BE(reply.length, 0);
        reply.copy(framed, 4);
        socket.write(framed);
      });
    }, function (port) {
      return relayAllowing(port).send({ host: "127.0.0.1", port: port, message: message });
    });
    assert.strictEqual(r.request.message, name, name + " must be relayed");
  }

  // A NAME must be resolved and then connected to by literal. "localhost" is the
  // one name every host has, so this exercises the resolve path without needing
  // external DNS.
  const named = await withTcpServer(function (socket) {
    socket.on("data", function () {
      const reply = krbError();
      const framed = Buffer.alloc(4 + reply.length);
      framed.writeUInt32BE(reply.length, 0);
      reply.copy(framed, 4);
      socket.write(framed);
    });
  }, function (port) {
    return relayAllowing(port).send({ host: "localhost", port: port, message: asReq() });
  });
  assert.strictEqual(named.target.resolved, true, "a hostname must be reported as resolved");
  assert.ok(net.isIP(named.target.address),
    "and the address actually connected to must be reported as a literal, because that is what " +
    "closes the DNS-rebinding window: " + named.target.address);

  log.debug("Leaving relaysAKerberosExchangeOverTcp().");
}

// ---------------------------------------------------------------------------
// The two deadlines, which are additive rather than one shadowing the other.
//
// This is the assertion that earns its keep. A host that CONNECTS AND THEN SAYS
// NOTHING must be given until callTimeout — it is alive and thinking, which is
// what a loaded domain controller looks like — while a dead address must fail at
// connectTimeout. An implementation that expresses both with one timer makes
// whichever is smaller the only one that ever fires, and that implementation
// passes a test which only checks that something eventually failed.
// ---------------------------------------------------------------------------
async function connectAndCallDeadlinesAreSeparate() {
  log.debug("Entering connectAndCallDeadlinesAreSeparate().");
  const relay = localRelay({ connectionTimeout: 400, callTimeout: 2000 });

  // Connects, then silence.
  const startedQuiet = Date.now();
  await withTcpServer(function (socket) {
    // Accept and say nothing at all. Hold the socket so it does not close.
    socket.on("data", function () {});
  }, async function (port) {
    const err = await mustReject("a host that connects and then says nothing",
      relayAllowing(port, { connectionTimeout: 400, callTimeout: 2000 })
        .send({ host: "127.0.0.1", port: port, message: asReq() }), "EKRB5CALLTIMEOUT");
    const elapsed = Date.now() - startedQuiet;
    assert.ok(elapsed > 400 + 200,
      "a connected-but-silent host failed after " + elapsed + "ms, at or near the 400ms CONNECT " +
      "budget. It must be given until the 2000ms CALL budget: the connection was established, so " +
      "the host is alive. This is what fails when both deadlines share one timer.");
    assert.ok(/did not answer/.test(err.message),
      "and the message must distinguish 'nothing is listening' from 'it did not answer': " + err.message);
  });

  // A dead address must fail at the CONNECT budget, well before the call budget.
  // 198.51.100.0/24 is TEST-NET-2 (RFC 5737) and is not routed anywhere.
  const startedDead = Date.now();
  const deadRelay = localRelay({ connectionTimeout: 350, callTimeout: 5000,
    krb5AllowedPorts: [88] });
  const err = await mustReject("an address nothing is listening on",
    deadRelay.send({ host: "198.51.100.7", port: 88, message: asReq() }));
  const deadElapsed = Date.now() - startedDead;
  assert.ok(["EKRB5CONNECTTIMEOUT", "EKRB5SOCKET"].indexOf(err.code) !== -1,
    "a dead address must fail as a connect problem, got " + err.code);
  assert.ok(deadElapsed < 4000,
    "a dead address took " + deadElapsed + "ms; it must fail at the connect budget (350ms), not " +
    "wait out the 5000ms call budget");

  log.debug("Leaving connectAndCallDeadlinesAreSeparate().");
}

// ---------------------------------------------------------------------------
// The reply cap, applied to what the far end DECLARED.
// ---------------------------------------------------------------------------
async function repliesAreCappedBeforeTheyAreRead() {
  log.debug("Entering repliesAreCappedBeforeTheyAreRead().");
  const relay = localRelay({ maxContentLength: 2048 });

  // Announce far more than the cap and then send nothing. The refusal must come
  // from the DECLARED length, immediately — not after the bytes arrive, which for
  // a host that announces four gigabytes and streams slowly is the difference
  // between a refusal and an out-of-memory.
  const started = Date.now();
  await withTcpServer(function (socket) {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(64 * 1024 * 1024, 0);
    socket.write(header);
    // ...and never the body.
  }, async function (port) {
    const err = await mustReject("a reply announcing more than the cap",
      relayAllowing(port, { maxContentLength: 2048 })
        .send({ host: "127.0.0.1", port: port, message: asReq() }), "EKRB5BADFRAME");
    assert.ok(/announces 67108864 bytes/.test(err.message),
      "the refusal must quote the declared size: " + err.message);
    assert.ok(/maxContentLength/.test(err.message),
      "and name the setting that governs it, so it can be raised deliberately");
  });
  assert.ok(Date.now() - started < 1500,
    "the cap must be applied to the DECLARED length immediately, not after waiting for the body");

  // A reply exactly at the cap is accepted: an off-by-one here would refuse
  // legitimate traffic, and a KDC reply with a large PAC is genuinely big.
  const body = Buffer.concat([krbError(), Buffer.alloc(2048 - krbError().length, 0x41)]);
  const atCap = await withTcpServer(function (socket) {
    socket.on("data", function () {
      const framed = Buffer.alloc(4 + body.length);
      framed.writeUInt32BE(body.length, 0);
      body.copy(framed, 4);
      socket.write(framed);
    });
  }, function (port) {
    return relayAllowing(port, { maxContentLength: 2048 })
      .send({ host: "127.0.0.1", port: port, message: asReq() });
  });
  assert.strictEqual(atCap.reply.length, 2048, "a reply exactly at the cap must be accepted");

  // The top bit of the length prefix is reserved by RFC 4120.
  await withTcpServer(function (socket) {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(0x80000010, 0);
    socket.write(header);
  }, async function (port) {
    const err = await mustReject("a length prefix with the reserved top bit set",
      relayAllowing(port, { maxContentLength: 2048 })
        .send({ host: "127.0.0.1", port: port, message: asReq() }), "EKRB5BADFRAME");
    assert.ok(/top bit/.test(err.message), "the refusal must say which bit: " + err.message);
  });

  // A connection that closes before a complete reply is NOT a timeout, and saying
  // which it was matters: one means nothing answered, the other means something
  // answered and gave up.
  await withTcpServer(function (socket) {
    socket.on("data", function () {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(500, 0);
      socket.write(header);
      socket.write(Buffer.alloc(10));
      socket.end();
    });
  }, async function (port) {
    const err = await mustReject("a connection closed mid-reply",
      relayAllowing(port, { maxContentLength: 2048 })
        .send({ host: "127.0.0.1", port: port, message: asReq() }), "EKRB5SHORTREPLY");
    assert.ok(/closed after/.test(err.message),
      "a short reply must be distinguished from a timeout: " + err.message);
  });

  log.debug("Leaving repliesAreCappedBeforeTheyAreRead().");
}

// ---------------------------------------------------------------------------
// The port allowlist, which is new with this endpoint.
// ---------------------------------------------------------------------------
async function onlyKerberosPortsAreReachable() {
  log.debug("Entering onlyKerberosPortsAreReachable().");
  const relay = relayMod.createRelay(
    { blockPrivateNetworkCalls: false, krb5AllowedPorts: [88, 464, 749] },
    ssrfGuard.createGuard({ blockPrivateNetworkCalls: false }, quiet), quiet);
  assert.deepStrictEqual(relay.allowedPorts, [88, 464, 749], "the configured ports");

  // The ports somebody would actually try. Each must be refused BEFORE a socket
  // is opened — which is why these use a listener-free address and still fail
  // instantly.
  for (const port of [22, 25, 80, 443, 3306, 5432, 6379, 8080, 9200, 11211]) {
    const err = await mustReject("port " + port,
      relay.send({ host: "127.0.0.1", port: port, message: asReq() }), "EKRB5PORTNOTALLOWED");
    assert.ok(/port scanner/.test(err.message),
      "the refusal should explain WHY a byte relay restricts ports: " + err.message);
  }
  // And the allowed ones get past the port check (they then fail to connect,
  // which is a different error and proves the check passed).
  for (const port of [88, 464, 749]) {
    const err = await mustReject("port " + port + " passes the allowlist",
      relay.send({ host: "127.0.0.1", port: port, message: asReq() }));
    assert.notStrictEqual(err.code, "EKRB5PORTNOTALLOWED",
      "port " + port + " is on the allowlist and must not be refused by it");
  }

  // Configuration robustness. A malformed entry must be dropped with a reason,
  // and — the important half — an allowlist that ends up empty must refuse
  // everything rather than silently allow everything.
  const noted = [];
  const messy = relayMod.resolveAllowedPorts([88, "464", -1, 70000, "not a port", 88],
    { error: function (m) { noted.push(m); }, info() {}, debug() {}, warn() {} });
  assert.deepStrictEqual(messy, [88, 464],
    "valid entries must survive, a string port must be accepted, and duplicates collapse");
  assert.strictEqual(noted.length, 3, "each dropped entry must be logged: " + noted.join(" | "));

  const emptyRelay = relayMod.createRelay(
    { blockPrivateNetworkCalls: false, krb5AllowedPorts: ["nonsense"] },
    ssrfGuard.createGuard({ blockPrivateNetworkCalls: false }, quiet), quiet);
  assert.deepStrictEqual(emptyRelay.allowedPorts, [],
    "an allowlist with nothing usable in it must be empty, not defaulted");
  await mustReject("any port when the allowlist is empty",
    emptyRelay.send({ host: "127.0.0.1", port: 88, message: asReq() }), "EKRB5PORTNOTALLOWED");

  // A missing setting falls back to the Kerberos defaults rather than to nothing.
  const defaulted = relayMod.createRelay({ blockPrivateNetworkCalls: false },
    ssrfGuard.createGuard({ blockPrivateNetworkCalls: false }, quiet), quiet);
  assert.deepStrictEqual(defaulted.allowedPorts, relayMod.DEFAULT_ALLOWED_PORTS,
    "an absent krb5AllowedPorts must default to the Kerberos ports");

  log.debug("Leaving onlyKerberosPortsAreReachable().");
}

// ---------------------------------------------------------------------------
// The address policy — the half api/ssrf_guard.js cannot reach, because there is
// no axios in this path.
// ---------------------------------------------------------------------------
async function theAddressPolicyAppliesToRawSockets() {
  log.debug("Entering theAddressPolicyAppliesToRawSockets().");
  const cfg = { blockPrivateNetworkCalls: true, krb5AllowedPorts: [88] };
  const guard = ssrfGuard.createGuard(cfg, quiet);
  const relay = relayMod.createRelay(cfg, guard, quiet);
  assert.strictEqual(relay.addressPolicyEnabled, true,
    "the relay must report that the policy is on, and must share the guard's decision rather " +
    "than keeping its own copy of the ranges");

  // Literals. Node never calls a DNS resolver for one, which is the gap that made
  // the HTTP guard need a createConnection hook as well as a lookup hook — and
  // the same gap exists here.
  for (const address of ["127.0.0.1", "127.1.2.3", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                         "169.254.169.254", "::1", "::ffff:127.0.0.1"]) {
    const err = await mustReject("the literal " + address,
      relay.send({ host: address, port: 88, message: asReq() }), "EBLOCKEDADDRESS");
    assert.ok(/blocked range/.test(err.message), "the refusal must name the range: " + err.message);
  }
  // 169.254.169.254 is the cloud metadata service, and it hands out credentials.
  const metadata = await mustReject("cloud metadata",
    relay.send({ host: "169.254.169.254", port: 88, message: asReq() }), "EBLOCKEDADDRESS");
  assert.ok(/169\.254\.169\.254/.test(metadata.message), "named in the refusal");

  // A NAME is judged by what it resolves to. "localhost" resolves to loopback on
  // every host, so this is the resolve-then-check path without external DNS.
  const named = await mustReject("a name that resolves to loopback",
    relay.send({ host: "localhost", port: 88, message: asReq() }), "EBLOCKEDADDRESS");
  assert.ok(/resolves to/.test(named.message),
    "the refusal must say the name was judged by its resolved address: " + named.message);
  assert.ok(/localtest\.me|nip\.io/.test(named.message),
    "and should name the public services that exist to point at loopback, since that is the " +
    "technique this rule defeats: " + named.message);

  // Only an explicit false disables it: a missing key, a typo, or a stringly
  // "false" must not open the policy.
  for (const value of [undefined, null, "false", "no", 0, {}]) {
    const c = { blockPrivateNetworkCalls: value, krb5AllowedPorts: [88] };
    const r = relayMod.createRelay(c, ssrfGuard.createGuard(c, quiet), quiet);
    assert.strictEqual(r.addressPolicyEnabled, true,
      "blockPrivateNetworkCalls=" + JSON.stringify(value) + " must NOT disable the address policy; " +
      "only an explicit boolean false does");
    await mustReject("loopback with blockPrivateNetworkCalls=" + JSON.stringify(value),
      r.send({ host: "127.0.0.1", port: 88, message: asReq() }), "EBLOCKEDADDRESS");
  }

  // ...and an explicit false does disable it, because the local and containerized
  // stacks need exactly that: their KDC is a private address. A guard that could
  // not be turned off would make this feature impossible to develop against.
  const off = { blockPrivateNetworkCalls: false, krb5AllowedPorts: [88] };
  const openRelay = relayMod.createRelay(off, ssrfGuard.createGuard(off, quiet), quiet);
  assert.strictEqual(openRelay.addressPolicyEnabled, false, "an explicit false disables it");
  const err = await mustReject("loopback with the policy explicitly off",
    openRelay.send({ host: "127.0.0.1", port: 88, message: asReq() }));
  assert.notStrictEqual(err.code, "EBLOCKEDADDRESS",
    "with the policy off, loopback must fail for a NETWORK reason (nothing listening), not a " +
    "policy one — got " + err.code + ": " + err.message);

  log.debug("Leaving theAddressPolicyAppliesToRawSockets().");
}

// ---------------------------------------------------------------------------
// The message-shape pre-flight, which is what keeps this from being a tunnel.
// ---------------------------------------------------------------------------
async function onlyKerberosRequestsAreRelayed() {
  log.debug("Entering onlyKerberosRequestsAreRelayed().");
  const relay = localRelay();

  const cases = [
    ["an empty payload", Buffer.alloc(0)],
    ["plain text", Buffer.from("GET / HTTP/1.1\r\n\r\n")],
    ["base64 that was never decoded", Buffer.from("akYwRKEDAgEF")],
    ["a bare DER SEQUENCE", Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05])],
    ["an AS-REP (a reply, not a request)", Buffer.from([0x6b, 0x03, 0x02, 0x01, 0x05])],
    ["a KRB-ERROR", krbError()],
    // An AP-REQ is a Kerberos request, but not one a KDC answers. The refusal must
    // point at the other endpoint rather than merely saying no — a caller who is told
    // "not Kerberos" about a perfectly good AP-REQ will not believe it.
    ["an AP-REQ, which goes to a service", apReq()],
    ["a GSS-wrapped AP-REQ", Buffer.concat([Buffer.from([0x60, 0x12]), Buffer.alloc(18)])],
    ["a Ticket", Buffer.from([0x61, 0x03, 0x02, 0x01, 0x05])],
    ["an Authenticator", Buffer.from([0x62, 0x03, 0x02, 0x01, 0x05])],
    ["a declared length shorter than the payload", Buffer.from([0x6a, 0x02, 0x02, 0x01, 0x05])],
    ["a declared length longer than the payload", Buffer.from([0x6a, 0x40, 0x02, 0x01, 0x05])],
    ["an indefinite length (BER)", Buffer.from([0x6a, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00])],
    ["a five-byte length field", Buffer.from([0x6a, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00])],
    ["one byte", Buffer.from([0x6a])],
    ["a payload over the request cap", Buffer.concat([Buffer.from([0x6a, 0x84]),
      Buffer.alloc(frame.MAX_REQUEST_BYTES + 8)])]
  ];
  for (const [label, payload] of cases) {
    const err = await mustReject(label, relay.send({ host: "127.0.0.1", port: 88, message: payload }),
      "EKRB5NOTKERBEROS");
    assert.ok(/Kerberos/.test(err.message),
      label + ": the refusal must say what this endpoint carries: " + err.message);
  }

  // The pre-flight must come FIRST — before the port check — so a caller sending
  // the wrong bytes is told about the bytes rather than about ports. The cheapest
  // and most specific diagnosis wins.
  const wrongBoth = await mustReject("wrong payload AND a wrong port",
    relay.send({ host: "127.0.0.1", port: 22, message: Buffer.from("nonsense") }));
  assert.strictEqual(wrongBoth.code, "EKRB5NOTKERBEROS",
    "with both wrong, the PAYLOAD refusal must win: a caller told 'port 22 is not allowed' will " +
    "change the port and hit the real problem second");

  // Text that looks like it was meant to be base64 gets a pointed hint, because
  // that is the mistake somebody will actually make.
  const looksText = await mustReject("something texty",
    relay.send({ host: "127.0.0.1", port: 88, message: Buffer.from("YUYwRKEDAgEF") }));
  assert.ok(/base64/.test(looksText.message),
    "a texty payload should suggest the base64 mistake: " + looksText.message);

  // And the bad-input cases that are not about the payload.
  await mustReject("no host", relay.send({ host: "", port: 88, message: asReq() }), "EKRB5NOHOST");
  await mustReject("a non-numeric port",
    relay.send({ host: "127.0.0.1", port: "eighty-eight", message: asReq() }), "EKRB5NOPORT");
  await mustReject("an unresolvable name",
    relay.send({ host: "no-such-host.invalid", port: 88, message: asReq() }), "EKRB5DNS");

  log.debug("Leaving onlyKerberosRequestsAreRelayed().");
}

// ---------------------------------------------------------------------------
// The SERVICE endpoint's policy, which is deliberately different.
//
// A Kerberos service can be on any port — 443, 1433, 389 — so no small allowlist
// bounds this endpoint the way one bounds the KDC relay. What bounds it is the
// payload check: a GSS InitialContextToken naming the Kerberos v5 mechanism and
// wrapping a well-formed AP-REQ, or a bare AP-REQ, and nothing else. And because that
// is a broader capability, it is OFF until configured: an absent or empty
// krb5ServicePorts refuses every call.
// ---------------------------------------------------------------------------
async function theServiceEndpointIsOffUntilConfigured() {
  log.debug("Entering theServiceEndpointIsOffUntilConfigured().");
  const gssApReq = Buffer.concat([
    Buffer.from([0x60, 0x12]),
    Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]),
    Buffer.from([0x01, 0x00]),
    Buffer.from([0x6e, 0x03, 0x30, 0x01, 0x05])
  ]);

  // Absent: refused, and the refusal must say the endpoint is not enabled rather than
  // blaming the port — otherwise an operator adds ports forever and nothing changes.
  const off = localRelay();
  assert.strictEqual(off.serviceEnabled, false,
    "with no krb5ServicePorts the service endpoint must report itself disabled");
  const disabled = await mustReject("the service endpoint with no ports configured",
    off.send({ host: "127.0.0.1", port: 8888, message: gssApReq, purpose: "service" }),
    "EKRB5SERVICENOTENABLED");
  assert.ok(/not enabled/.test(disabled.message) && /krb5ServicePorts/.test(disabled.message),
    "the refusal must name the setting that enables it: " + disabled.message);

  // Configured with one port: that port passes the policy, others do not.
  const configured = localRelay({ krb5ServicePorts: [8888] });
  assert.deepStrictEqual(configured.servicePorts, [8888], "the configured service port");
  assert.strictEqual(configured.serviceEnabled, true, "and the endpoint reports itself enabled");
  const wrongPort = await mustReject("a service port that is not allowed",
    configured.send({ host: "127.0.0.1", port: 9999, message: gssApReq, purpose: "service" }),
    "EKRB5PORTNOTALLOWED");
  assert.ok(/krb5ServicePorts/.test(wrongPort.message), "and names the setting");
  const allowed = await mustReject("the allowed service port (nothing listening)",
    configured.send({ host: "127.0.0.1", port: 8888, message: gssApReq, purpose: "service" }));
  assert.notStrictEqual(allowed.code, "EKRB5PORTNOTALLOWED",
    "the configured port must pass the policy and fail for a network reason instead, got " +
    allowed.code);

  // "any": the escape hatch, spelled as a word so it cannot be a typo.
  const anyPort = localRelay({ krb5ServicePorts: "any" });
  assert.strictEqual(anyPort.servicePorts, "any", "the wildcard is reported as such");
  const onAny = await mustReject("an arbitrary port with krb5ServicePorts: any",
    anyPort.send({ host: "127.0.0.1", port: 31337, message: gssApReq, purpose: "service" }));
  assert.notStrictEqual(onAny.code, "EKRB5PORTNOTALLOWED",
    'with "any" no port is refused by the port policy, got ' + onAny.code);

  // The payload check is what bounds it, so it has to be strict. Each of these is
  // something somebody could plausibly aim at an arbitrary port.
  const payloads = [
    ["an AS-REQ", asReq()],
    ["a TGS-REQ", tgsReq()],
    ["a KRB-ERROR", krbError()],
    ["an HTTP request", Buffer.from("GET / HTTP/1.1\r\nHost: x\r\n\r\n")],
    ["a Redis command", Buffer.from("*1\r\n$4\r\nPING\r\n")],
    ["a TLS ClientHello", Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])],
    ["0x60 then arbitrary bytes", Buffer.concat([Buffer.from([0x60, 0x05]), Buffer.from("hello")])],
    ["a GSS token naming SPNEGO", Buffer.concat([
      Buffer.from([0x60, 0x0d]),
      Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]),
      Buffer.from([0x01, 0x00]), Buffer.from([0x6e, 0x01, 0x05])])],
    ["a GSS token wrapping an AP-REP", Buffer.concat([
      Buffer.from([0x60, 0x12]),
      Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]),
      Buffer.from([0x02, 0x00]), Buffer.from([0x6f, 0x03, 0x30, 0x01, 0x05])])],
    ["a GSS token wrapping something that is not an AP-REQ", Buffer.concat([
      Buffer.from([0x60, 0x12]),
      Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]),
      Buffer.from([0x01, 0x00]), Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05])])]
  ];
  // Each refusal is checked for WHICH layer fired, not merely that something did.
  //
  // These checks are layered — the mechanism OID, then the token id, then the inner
  // message — and a payload that fails one usually fails the next as well. So an
  // assertion that only looks at the error CODE is satisfied no matter which layer
  // refused, and removing any single check goes undetected. Mutation-testing found
  // exactly that: disabling the OID check and disabling the token-id check both left
  // this test green, because a later check caught the same payload. Naming the
  // expected reason pins each layer on its own.
  const expectedReason = {
    "a GSS token naming SPNEGO": /SPNEGO|mechanism/,
    "a GSS token wrapping an AP-REP": /token id/,
    "a GSS token wrapping something that is not an AP-REQ": /not an AP-REQ/,
    "0x60 then arbitrary bytes": /too short|mechanism/
  };
  for (const [label, payload] of payloads) {
    const err = await mustReject(label + " sent to the service endpoint",
      anyPort.send({ host: "127.0.0.1", port: 31337, message: payload, purpose: "service" }),
      "EKRB5NOTKERBEROS");
    assert.ok(/AP-REQ|Kerberos/.test(err.message),
      label + ": the refusal must say what this endpoint carries: " + err.message);
    if (expectedReason[label]) {
      assert.ok(expectedReason[label].test(err.message),
        label + ": expected the refusal to come from the " + expectedReason[label] +
        " check specifically, so that removing that one check fails this test rather than being " +
        "masked by a later one. Got: " + err.message);
    }
  }

  // And the two legal shapes get past the payload check.
  for (const [label, payload] of [["a GSS-wrapped AP-REQ", gssApReq],
                                  ["a bare AP-REQ", apReq()]]) {
    const err = await mustReject(label + " passes the payload check",
      anyPort.send({ host: "127.0.0.1", port: 31337, message: payload, purpose: "service" }));
    assert.notStrictEqual(err.code, "EKRB5NOTKERBEROS",
      label + " must pass the payload check and fail for a network reason instead, got " + err.code);
  }

  log.debug("Leaving theServiceEndpointIsOffUntilConfigured().");
}

// ---------------------------------------------------------------------------
// UDP, which exists because KRB_ERR_RESPONSE_TOO_BIG is itself worth seeing.
// ---------------------------------------------------------------------------
async function udpWorksAndFailsHonestly() {
  log.debug("Entering udpWorksAndFailsHonestly().");
  const relay = localRelay({ callTimeout: 1200 });

  const result = await withUdpServer(function (socket, msg, rinfo) {
    // UDP carries NO length prefix: the datagram is the message. A relay that
    // framed it anyway would send four junk bytes a KDC cannot parse.
    assert.strictEqual(Buffer.compare(msg, asReq()), 0,
      "a UDP datagram must carry the message with NO length prefix");
    const reply = krbError();
    socket.send(reply, rinfo.port, rinfo.address);
  }, function (port) {
    return relayAllowing(port, { callTimeout: 1200 })
      .send({ host: "127.0.0.1", port: port, transport: "udp", message: asReq() });
  });
  assert.strictEqual(result.target.transport, "udp", "transport reported");
  assert.strictEqual(result.replyMessage, "KRB-ERROR", "the reply is identified");

  // Silence over UDP must fail with an explanation that says UDP is
  // unacknowledged and points at TCP — which is what a client does anyway when a
  // KDC answers KRB_ERR_RESPONSE_TOO_BIG.
  const started = Date.now();
  // An ALLOWED port with nothing listening on it. UDP is connectionless, so the
  // datagram goes out and the silence is what has to be timed out — which is the
  // behaviour being tested. Port 9 would have been refused by the allowlist first,
  // and the test would have passed for the wrong reason.
  const err = await mustReject("a UDP KDC that never answers",
    relay.send({ host: "127.0.0.1", port: 88, transport: "udp", message: asReq() }),
    "EKRB5CALLTIMEOUT");
  assert.ok(/TCP/.test(err.message) && /RESPONSE_TOO_BIG/.test(err.message),
    "the UDP timeout must point at the TCP retry and name the error that causes it: " + err.message);
  assert.ok(Date.now() - started >= 1000, "and must wait out the call budget");

  log.debug("Leaving udpWorksAndFailsHonestly().");
}

// ---------------------------------------------------------------------------
// Every path settles.
//
// api/CLAUDE.md records that three HTTP handlers answered only when an error
// carried a `response`, so every NETWORK-level failure sent no reply at all and
// left the browser waiting forever. For this endpoint a network-level failure is
// the common case, not the rare one — the whole point is aiming it at a host that
// may not be there — so "it always settles" is a property worth asserting
// directly rather than hoping for.
// ---------------------------------------------------------------------------
async function everyPathSettles() {
  log.debug("Entering everyPathSettles().");
  const relay = localRelay({ connectionTimeout: 300, callTimeout: 900, maxContentLength: 512 });
  const attempts = [
    ["refused connection", { host: "127.0.0.1", port: 88, message: asReq() }],
    ["blocked payload", { host: "127.0.0.1", port: 88, message: Buffer.from("x") }],
    ["bad port", { host: "127.0.0.1", port: 22, message: asReq() }],
    ["bad host", { host: "no-such-host.invalid", port: 88, message: asReq() }],
    ["udp silence", { host: "127.0.0.1", port: 88, transport: "udp", message: asReq() }]
  ];
  for (const [label, opts] of attempts) {
    const settled = await Promise.race([
      relay.send(opts).then(function () { return "resolved"; }, function () { return "rejected"; }),
      new Promise(function (resolve) { setTimeout(function () { resolve("HUNG"); }, 5000); })
    ]);
    assert.notStrictEqual(settled, "HUNG",
      label + ": the relay never settled. A promise that neither resolves nor rejects is the " +
      "hang api/CLAUDE.md warns about, and for this endpoint it is the common path.");
    log.debug(label + " settled as " + settled);
  }
  log.debug("Leaving everyPathSettles().");
}

// ---------------------------------------------------------------------------
// The framing helpers on their own.
// ---------------------------------------------------------------------------
function framingHelpersAreExact() {
  log.debug("Entering framingHelpersAreExact().");
  const message = asReq();
  const framed = frame.frameForTcp(message);
  assert.strictEqual(framed.length, message.length + 4, "the prefix is four bytes");
  assert.strictEqual(framed.readUInt32BE(0), message.length, "big-endian, and the message's length");
  assert.strictEqual(Buffer.compare(framed.subarray(4), message), 0, "the message is unchanged");

  // Partial reads: a KDC's reply arrives in whatever chunks TCP feels like.
  assert.deepStrictEqual(frame.readTcpFrame(Buffer.alloc(0), 4096), { complete: false, need: 4 });
  assert.deepStrictEqual(frame.readTcpFrame(framed.subarray(0, 2), 4096), { complete: false, need: 2 });
  const partial = frame.readTcpFrame(framed.subarray(0, 5), 4096);
  assert.strictEqual(partial.complete, false, "a header with one body byte is incomplete");
  assert.strictEqual(partial.need, framed.length - 5, "and must say how much more is needed");
  const whole = frame.readTcpFrame(framed, 4096);
  assert.strictEqual(whole.complete, true, "the whole frame is complete");
  assert.strictEqual(whole.consumed, framed.length, "and reports what it consumed");

  assert.strictEqual(frame.describeReply(Buffer.from([0x6b])), "AS-REP", "reply naming");
  assert.strictEqual(frame.describeReply(Buffer.from([0x7e])), "KRB-ERROR", "reply naming");
  assert.ok(/unrecognised/.test(frame.describeReply(Buffer.from([0x41]))),
    "an unrecognised reply must be described as such rather than guessed at");
  assert.strictEqual(frame.describeReply(Buffer.alloc(0)), null, "no reply, no name");
  log.debug("Leaving framingHelpersAreExact().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying api/krb5_relay.js and api/krb5_frame.js.");
  framingHelpersAreExact();
  await relaysAKerberosExchangeOverTcp();
  await onlyKerberosRequestsAreRelayed();
  await onlyKerberosPortsAreReachable();
  await theAddressPolicyAppliesToRawSockets();
  await theServiceEndpointIsOffUntilConfigured();
  await repliesAreCappedBeforeTheyAreRead();
  await connectAndCallDeadlinesAreSeparate();
  await udpWorksAndFailsHonestly();
  await everyPathSettles();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_krb5_relay")
  .description("Verify the Kerberos relay's address policy, port allowlist, message pre-flight and limits.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
