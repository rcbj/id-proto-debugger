// File: embedded_deployment.js
//
// ---------------------------------------------------------------------------
// THE DEBUGGER EMBEDDED IN THE MOCK STS: the four seams this repository owns.
//
// The mock STS serves this debugger's UI on an origin of its own, proxies
// `<origin>/api/*` to the api with `/api` stripped, and forks the api as a
// child on a unix socket (embedded/CLAUDE.md). The mock STS is the consumer
// and tests its half; what can be wrong on THIS side, and would surface over
// there as something naming nothing here, is:
//
//   1. common/tls_listener.js on a socket path — binds plain HTTP whatever
//      `https` says, 0600, removes a STALE socket and nothing else, reports
//      no certificate, and tells a forking parent it is listening. A socket
//      left 0755 is one any local user can drive the relay through; a parent
//      never told is a proxy that 502s until it guesses.
//   2. client/src/env/embedded.js, evaluated with a fake `window` — the UI's
//      addresses are the page's own origin and the mock STS defaults carry the
//      placeholder the mock STS substitutes. A wrong derivation here is an
//      identity provider told to post to a path the proxy does not serve.
//   3. api/env/embedded.js, required in a child with the environment the mock
//      STS sets — the same derivations, and an allow-list that FAILS CLOSED
//      on a value that is not a JSON array.
//   4. client/build.js refuses a DEPLOYMENT it does not know rather than
//      quietly producing the static build.
//
// api/ssrf_guard.js's allow-list mode itself is tests/api_ssrf_guard.js's.
//
// No browser and no services: node only, so it never skips. In the tests
// image the four modules arrive flat under the names tests/Dockerfile gives
// them; in a checkout they are read where they live.
// ---------------------------------------------------------------------------
const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "embedded_deployment",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The first of `candidates` that exists, or null.
function locate(candidates) {
  log.debug("Entering locate().");
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      log.debug("Leaving locate(). " + candidate);
      return candidate;
    }
  }
  log.debug("Leaving locate(). None.");
  return null;
}

const TLS_LISTENER = locate([
  path.join(__dirname, "..", "common", "tls_listener.js"),
  path.join(__dirname, "tls_listener.js")]);
const CLIENT_ENV = locate([
  path.join(__dirname, "..", "client", "src", "env", "embedded.js"),
  path.join(__dirname, "embedded_client_env.js")]);
const API_ENV = locate([
  path.join(__dirname, "..", "api", "env", "embedded.js"),
  path.join(__dirname, "embedded_api_env.js")]);
const SSRF_GUARD = locate([
  path.join(__dirname, "..", "api", "ssrf_guard.js"),
  path.join(__dirname, "ssrf_guard.js")]);
const BUILD_JS = locate([path.join(__dirname, "..", "client", "build.js")]);

// A private directory for sockets. Kept short: a unix socket path is limited
// to ~107 bytes, and a deep TMPDIR has pushed a path past it before.
function socketDir() {
  log.debug("Entering socketDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "emb-"));
  log.debug("Leaving socketDir(). " + dir);
  return dir;
}

// GET / over a unix socket; resolves { status, body }.
function getOverSocket(socketPath, headers) {
  log.debug("Entering getOverSocket().");
  log.debug("Leaving getOverSocket(). The promise is pending.");
  return new Promise(function (resolve, reject) {
    // agent:false — node's global agent keeps connections alive and keys its
    // pool by socket PATH, so a second listener on the same path would be
    // handed the first one's dead connection and fail with EPIPE.
    const req = http.request({ socketPath: socketPath, path: "/probe",
      agent: false, headers: headers || {} }, function (res) {
      let body = "";
      res.on("data", function (d) { body += d; });
      res.on("end", function () {
        resolve({ status: res.statusCode, body: body });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function waitListening(server) {
  log.debug("Entering waitListening().");
  log.debug("Leaving waitListening(). The promise is pending.");
  return new Promise(function (resolve, reject) {
    if (server.listening) {
      return resolve();
    }
    server.once("listening", function () {
      // The chmod runs in tls_listener's own listen callback, which was
      // registered first and so has already run by the time this one does.
      resolve();
    });
    server.once("error", reject);
  });
}

// ---------------------------------------------------------------------------
// 1. tls_listener.listen() on a socket path.
// ---------------------------------------------------------------------------
async function socketListener() {
  log.debug("Entering socketListener().");
  log.info("=== common/tls_listener.js on a unix socket ===");
  assert.ok(TLS_LISTENER, "common/tls_listener.js was not found.");
  const tlsListener = require(TLS_LISTENER);
  const dir = socketDir();
  const socketPath = path.join(dir, "api.sock");
  const app = function (req, res) {
    res.end("proto=" + (req.socket.encrypted ? "https" : "http"));
  };

  assert.strictEqual(tlsListener.socketPathFor({ socketPath: socketPath }),
    socketPath, "an explicit option must be what socketPathFor() returns.");

  // `https: true` with NO certificate would throw on a TCP listener; on a
  // socket it must not even be asked about.
  const server = tlsListener.listen(app, { https: true },
      { name: "embedded-test", socketPath: socketPath });
  await waitListening(server);
  const mode = fs.statSync(socketPath).mode & 0o777;
  assert.strictEqual(mode, 0o600, "the socket must be mode 0600, got 0" +
      mode.toString(8));
  assert.ok(fs.lstatSync(socketPath).isSocket(), "the path must be a socket.");
  const answer = await getOverSocket(socketPath);
  assert.strictEqual(answer.body, "proto=http",
    "the socket listener must be PLAIN HTTP whatever `https` says, got: " +
        answer.body);
  assert.strictEqual(tlsListener.serverCertificate(), null,
    "serverCertificate() must be null on a socket listener.");
  assert.strictEqual(tlsListener.isSecure(), false,
    "isSecure() must be false on a socket listener.");
  await new Promise(function (resolve) {
    server.close(resolve);
  });
  assert.ok(!fs.existsSync(socketPath),
    "closing the listener should remove its socket file.");

  // A STALE socket — left by a process that exited without closing, which is
  // what SIGKILL does — is removed and the bind succeeds.
  const stale = childProcess.spawnSync(process.execPath, ["-e",
    "require('net').createServer().listen(process.argv[1], function () {" +
    " process.exit(0); });", socketPath], { encoding: "utf8" });
  assert.strictEqual(stale.status, 0, "the stale-socket fixture failed: " +
      stale.stderr);
  assert.ok(fs.lstatSync(socketPath).isSocket(),
    "the fixture should have left a socket file behind.");
  const second = tlsListener.listen(app, {},
      { name: "embedded-test", socketPath: socketPath });
  await waitListening(second);
  assert.strictEqual((await getOverSocket(socketPath)).body, "proto=http",
    "a listener must bind over a stale socket file.");
  await new Promise(function (resolve) {
    second.close(resolve);
  });

  // Anything that is NOT a socket is somebody's file, and is not removed.
  const regular = path.join(dir, "not-a-socket");
  fs.writeFileSync(regular, "keep me");
  let refused = null;
  try {
    tlsListener.listen(app, {}, { name: "embedded-test",
        socketPath: regular });
  } catch (e) {
    refused = e;
  }
  assert.ok(refused && /not a unix socket/.test(refused.message),
    "a regular file at the socket path must be refused, got: " +
        (refused && refused.message));
  assert.strictEqual(fs.readFileSync(regular, "utf8"), "keep me",
    "and it must be left exactly as it was.");

  // FORKED: the parent is told, once, over IPC.
  const script = path.join(dir, "child.js");
  fs.writeFileSync(script,
    "var l = require(" + JSON.stringify(TLS_LISTENER) + ");\n" +
    "var s = l.listen(function (q, r) { r.end('ok'); }, {},\n" +
    "  { name: 'forked', socketPath: process.env.DEBUGGER_LISTEN_SOCKET });\n" +
    "process.on('disconnect', function () { s.close(); });\n");
  const forkedSocket = path.join(dir, "forked.sock");
  const child = childProcess.fork(script, [], {
    env: Object.assign({}, process.env,
        { DEBUGGER_LISTEN_SOCKET: forkedSocket }),
    stdio: ["ignore", "ignore", "pipe", "ipc"]
  });
  const message = await new Promise(function (resolve, reject) {
    const timer = setTimeout(function () {
      reject(new Error("the forked listener never sent its message"));
    }, 10000);
    child.once("message", function (m) {
      clearTimeout(timer);
      resolve(m);
    });
    child.once("exit", function (code) {
      clearTimeout(timer);
      reject(new Error("the forked listener exited with " + code));
    });
  });
  assert.deepStrictEqual(message,
    { type: "debugger-api-listening", socket: forkedSocket },
    "the IPC message must be exactly the contract's, got: " +
        JSON.stringify(message));
  assert.strictEqual(fs.statSync(forkedSocket).mode & 0o777, 0o600,
    "the socket must already be 0600 when the parent is told.");
  child.disconnect();
  await new Promise(function (resolve) {
    child.once("exit", resolve);
  });
  fs.rmSync(dir, { recursive: true, force: true });
  log.info("[socket] OK — plain HTTP despite https:true, 0600, no " +
           "certificate, a stale socket replaced, a regular file refused " +
           "and kept, and the forking parent told exactly once.");
  log.debug("Leaving socketListener().");
}

// ---------------------------------------------------------------------------
// 2. client/src/env/embedded.js, as the browser evaluates it.
// ---------------------------------------------------------------------------
function clientEnvironment() {
  log.debug("Entering clientEnvironment().");
  log.info("=== client/src/env/embedded.js with a fake window ===");
  assert.ok(CLIENT_ENV, "client/src/env/embedded.js was not found.");
  const source = fs.readFileSync(CLIENT_ENV, "utf8");

  function evaluate(windowValue) {
    log.debug("Entering evaluate().");
    const sandbox = { module: { exports: {} } };
    if (windowValue !== undefined) {
      sandbox.window = windowValue;
    }
    vm.runInNewContext(source, sandbox, { filename: "embedded.js" });
    log.debug("Leaving evaluate().");
    return sandbox.module.exports;
  }

  const origin = "https://debugger.example.test:8444";
  const c = evaluate({ location: { origin: origin } });
  const expected = {
    uiUrl: origin,
    apiUrl: origin + "/api",
    spEntityId: origin + "/saml/sp",
    acsUrl: origin + "/api/samlacs",
    sloUrl: origin + "/api/samlslo",
    wsfedAcsUrl: origin + "/api/wsfed",
    backendAvailable: true,
    krb5KdcHostDefault: "localhost",
    ldapUrlDefault: "ldap://localhost:389",
    spiffeWorkloadAddressDefault: "localhost:8092"
  };
  Object.keys(expected).forEach(function (key) {
    assert.strictEqual(c[key], expected[key],
      key + " should be " + JSON.stringify(expected[key]) + ", got " +
          JSON.stringify(c[key]));
  });
  const STS = "__STS_EMBED_STS_URL__";
  const sts = {
    wstrustStsUrlDefault: STS + "/sts",
    oid4vciIssuerUrlDefault: STS,
    oid4vpVerifierUrlDefault: STS,
    rfc8414MetadataUrlDefault: STS + "/.well-known/oauth-authorization-server",
    krb5SpnegoUrlDefault: STS + "/spnego/protected",
    spiffeServerAddressDefault: STS,
    spiffeBundleUrlDefault: STS + "/spiffe/bundle",
    scimBaseUrlDefault: STS + "/scim/v2",
    ssfTransmitterUrlDefault: STS,
    samlMetadataUrlDefault: STS + "/saml2/metadata",
    wsfedMetadataUrlDefault: STS +
        "/FederationMetadata/2007-06/FederationMetadata.xml"
  };
  Object.keys(sts).forEach(function (key) {
    assert.strictEqual(c[key], sts[key],
      key + " should be " + JSON.stringify(sts[key]) + ", got " +
          JSON.stringify(c[key]));
  });

  // The keys build.js checks the placeholder against must be exactly these,
  // or a default could lose the literal with no bundle failing the check.
  if (BUILD_JS) {
    const build = fs.readFileSync(BUILD_JS, "utf8").replace(/\s+/g, " ");
    const m = /const STS_PLACEHOLDER_KEYS = \[([^\]]*)\]/.exec(build);
    assert.ok(m, "client/build.js no longer declares STS_PLACEHOLDER_KEYS.");
    const declared = (m[1].match(/'[^']+'/g) || [])
      .map(function (q) { return q.slice(1, -1); }).sort();
    assert.deepStrictEqual(declared, Object.keys(sts).sort(),
      "client/build.js's STS_PLACEHOLDER_KEYS must name exactly the defaults " +
          "client/src/env/embedded.js builds from the placeholder.");
  }

  // No window (node reading the file): '' rather than a throw.
  const bare = evaluate(undefined);
  assert.strictEqual(bare.uiUrl, "", "with no window, uiUrl should be ''.");
  assert.strictEqual(bare.apiUrl, "/api",
    "with no window, apiUrl should be the bare prefix.");
  log.info("[client env] OK — the page's origin, /api and the four landings " +
           "derived, eleven mock STS defaults on the placeholder, three " +
           "socket targets on localhost, and no throw without a window.");
  log.debug("Leaving clientEnvironment().");
}

// ---------------------------------------------------------------------------
// 3. api/env/embedded.js, required in a child with the mock STS's environment.
// ---------------------------------------------------------------------------
function readApiEnv(env) {
  log.debug("Entering readApiEnv().");
  const clean = Object.assign({}, process.env);
  ["DEBUGGER_UI_URL", "DEBUGGER_ALLOWED_ADDRESS_RANGES",
   "DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS", "DEBUGGER_LOG_LEVEL",
   "DEBUGGER_LISTEN_SOCKET"].forEach(function (k) {
    delete clean[k];
  });
  const run = childProcess.spawnSync(process.execPath, ["-e",
    "process.stdout.write(JSON.stringify(require(process.argv[1])))",
    API_ENV], { env: Object.assign(clean, env), encoding: "utf8" });
  assert.strictEqual(run.status, 0, "requiring api/env/embedded.js failed: " +
      run.stderr);
  log.debug("Leaving readApiEnv().");
  return { config: JSON.parse(run.stdout), stderr: run.stderr };
}

function apiEnvironment() {
  log.debug("Entering apiEnvironment().");
  log.info("=== api/env/embedded.js with the mock STS's environment ===");
  assert.ok(API_ENV, "api/env/embedded.js was not found.");
  assert.ok(SSRF_GUARD, "api/ssrf_guard.js was not found.");
  const guardModule = require(SSRF_GUARD);
  const quiet = { debug: function () {
    log.debug("Entering debug().");
    log.debug("Leaving debug().");
  }, info: function () {
    log.debug("Entering info().");
    log.debug("Leaving info().");
  }, warn: function () {
    log.debug("Entering warn().");
    log.debug("Leaving warn().");
  }, error: function () {
    log.debug("Entering error().");
    log.debug("Leaving error().");
  } };

  const withList = readApiEnv({
    DEBUGGER_UI_URL: "https://localhost:8444/",
    DEBUGGER_ALLOWED_ADDRESS_RANGES: "[\"127.0.0.0/8\", \"::1/128\"]",
    DEBUGGER_LOG_LEVEL: "warn"
  }).config;
  const expected = {
    uiUrl: "https://localhost:8444",
    apiUrl: "https://localhost:8444/api",
    spEntityId: "https://localhost:8444/saml/sp",
    acsUrl: "https://localhost:8444/api/samlacs",
    sloUrl: "https://localhost:8444/api/samlslo",
    wsfedAcsUrl: "https://localhost:8444/api/wsfed",
    https: false,
    logLevel: "warn"
  };
  Object.keys(expected).forEach(function (key) {
    assert.strictEqual(withList[key], expected[key],
      key + " should be " + JSON.stringify(expected[key]) + ", got " +
          JSON.stringify(withList[key]));
  });
  assert.deepStrictEqual(withList.allowedAddressRanges,
    ["127.0.0.0/8", "::1/128"], "the allow-list should be read from JSON.");
  const listed = guardModule.createGuard(withList, quiet);
  assert.strictEqual(listed.mode, "allow");
  assert.strictEqual(listed.blockedRangeFor("127.0.0.1"), null,
    "the configured allow-list must admit loopback.");
  assert.ok(listed.blockedRangeFor("93.184.215.14"),
    "and refuse a public address.");

  // Not JSON, and JSON that is not an array: both FAIL CLOSED.
  ["[127.0.0.0/8", "{\"ranges\":[\"127.0.0.0/8\"]}"].forEach(function (raw) {
    const bad = readApiEnv({ DEBUGGER_UI_URL: "https://localhost:8444",
        DEBUGGER_ALLOWED_ADDRESS_RANGES: raw });
    assert.ok(/failing closed/.test(bad.stderr),
      "a bad allow-list should be reported on stderr, got: " + bad.stderr);
    const guard = guardModule.createGuard(bad.config, quiet);
    assert.strictEqual(guard.enabled, true);
    assert.strictEqual(guard.mode, "allow",
      JSON.stringify(raw) + " must still select allow-list mode.");
    ["127.0.0.1", "::1", "10.0.0.1", "8.8.8.8"].forEach(function (ip) {
      assert.ok(guard.blockedRangeFor(ip),
        "with DEBUGGER_ALLOWED_ADDRESS_RANGES=" + raw + " every address " +
            "must be refused, but " + ip + " was allowed.");
    });
  });

  // Absent or []: no allow-list, and the block switch follows its variable.
  [{}, { DEBUGGER_ALLOWED_ADDRESS_RANGES: "[]" }].forEach(function (env) {
    const on = readApiEnv(env).config;
    assert.deepStrictEqual(on.allowedAddressRanges, [],
      "no allow-list expected for " + JSON.stringify(env));
    assert.strictEqual(on.blockPrivateNetworkCalls, true,
      "blockPrivateNetworkCalls should default to true.");
    assert.strictEqual(on.uiUrl, "https://localhost:8444",
      "an absent DEBUGGER_UI_URL falls back to https://localhost:8444.");
    const off = readApiEnv(Object.assign({
      DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS: "false" }, env)).config;
    assert.strictEqual(off.blockPrivateNetworkCalls, false,
      "DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS=false should turn it off.");
    const typo = readApiEnv(Object.assign({
      DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS: "flase" }, env)).config;
    assert.strictEqual(typo.blockPrivateNetworkCalls, true,
      "only an explicit \"false\" may turn it off; a typo stays safe.");
  });
  log.info("[api env] OK — the origin, /api and the landings derived from " +
           "DEBUGGER_UI_URL, plain HTTP, the allow-list read, a bad one " +
           "failing closed, and the block switch honouring only \"false\".");
  log.debug("Leaving apiEnvironment().");
}

// ---------------------------------------------------------------------------
// 4. client/build.js refuses a deployment it does not know.
// ---------------------------------------------------------------------------
function buildRefusesUnknownDeployment() {
  log.debug("Entering buildRefusesUnknownDeployment().");
  log.info("=== client/build.js and DEPLOYMENT ===");
  if (!BUILD_JS) {
    log.info("[build] client/build.js is not in this layout; skipping.");
    log.debug("Leaving buildRefusesUnknownDeployment(). Skipped.");
    return;
  }
  // OUT_DIR is a throwaway, so even a broken check could not touch
  // client/dist — the refusal is supposed to come before anything is written.
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "emb-build-"));
  fs.writeFileSync(path.join(out, "sentinel"), "untouched");
  const run = childProcess.spawnSync(process.execPath, [BUILD_JS], {
    env: Object.assign({}, process.env,
        { DEPLOYMENT: "embeded", OUT_DIR: out }),
    encoding: "utf8", timeout: 60000 });
  assert.notStrictEqual(run.status, 0,
    "DEPLOYMENT=embeded (a typo) must fail the build.");
  assert.ok(/DEPLOYMENT must be "static" \(the default\) or "embedded"/
      .test(run.stderr), "and say why, got: " + run.stderr);
  assert.strictEqual(fs.readFileSync(path.join(out, "sentinel"), "utf8"),
    "untouched", "the refusal must come before OUT_DIR is emptied.");
  fs.rmSync(out, { recursive: true, force: true });
  log.info("[build] OK — an unknown DEPLOYMENT is refused before anything " +
           "is written.");
  log.debug("Leaving buildRefusesUnknownDeployment().");
}

async function test() {
  log.debug("Entering test().");
  await socketListener();
  clientEnvironment();
  apiEnvironment();
  buildRefusesUnknownDeployment();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("embedded_deployment")
  .description("Verify this repository's half of embedding the debugger in " +
      "the mock STS.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().then(function () {
  log.debug("test() resolved.");
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
