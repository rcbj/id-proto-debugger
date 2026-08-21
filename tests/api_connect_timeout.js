// File: api_connect_timeout.js
//
// The api's outbound LIMITS: api/connect_timeout.js, and the four settings in
// api/env/*.js that bound every axios call the service makes — callTimeout,
// connectionTimeout, maxContentLength and maxRedirects — plus the userAgent
// those calls identify themselves with, and the keepAlive that pools their
// connections. axios's own defaults are no timeout, no connect-phase timeout at
// all, an unlimited response size, 21 redirects and a User-Agent of
// "axios/x.y.z", so each has to be passed explicitly at every call site — which
// is the other half of what this checks, by reading server.js.
//
// No browser and no services: node only, so it never skips.
//
// The property under test is the one that makes connectionTimeout worth having
// as a setting separate from callTimeout, and it is easy to implement something
// that merely LOOKS like it:
//
//   * a stalled CONNECT must be given up on at connectionTimeout;
//   * a connection that succeeded must NOT be — the budget is spent, and from
//     there on only callTimeout applies.
//
// The second half is what an AbortSignal.timeout (the obvious way to do this in
// axios, and what this code did first) gets wrong: it starts counting when it
// is created, so it kills a perfectly healthy slow response as readily as a
// dead host, and whichever of the two settings was smaller became the only one
// that ever fired. Case 2 below fails against that implementation and passes
// against this one, which is the whole reason it exists.
//
// TLS is checked separately because the disarm event differs: a TLSSocket that
// has completed the TCP handshake and then stalls mid-negotiation has emitted
// 'connect' but not 'secureConnect', so disarming on the wrong one leaves the
// stall unbounded.
const assert = require("assert");
const http = require("http");
const https = require("https");
const net = require("net");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_connect_timeout",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout these live under api/; the tests image copies them flat next to
// the test scripts (see tests/Dockerfile).
var connectTimeout = paths.requireSharedModule(
  [__dirname + "/../api/connect_timeout.js", __dirname + "/connect_timeout.js"],
  "connect_timeout.js");
var guardModule = paths.requireSharedModule(
  [__dirname + "/../api/ssrf_guard.js", __dirname + "/ssrf_guard.js"],
   "ssrf_guard.js");

var quiet = { debug: function () {
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

function listen(server) {
  log.debug("Entering listen().");
  log.debug("Leaving listen().");
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1",
                  function () { resolve(server.address().port); });
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

/**
 * Issue one request through a given agent and report how it ended.
 *
 * @returns {Promise<{outcome: string, error: Error, elapsed: number}>} outcome is
 *   'error', 'response', or 'pending' if neither happened within `settle` ms.
 */
function attempt(options, agent, settle) {
  log.debug("Entering attempt().");
  log.debug("Leaving attempt().");
  return new Promise(function (resolve) {
    var started = Date.now();
    var done = false;
    function finish(outcome, error) {
      log.debug("Entering finish().");
      if (done) {
        log.debug("Leaving finish().");
        return;
      }
      done = true;
      resolve({ outcome: outcome, error: error, elapsed: Date.now() -
              started });
      log.debug("Leaving finish().");
    }
    var transport = options.protocol === "https:" ? https : http;
    var req = transport.request(Object.assign({}, options, { agent: agent }),
        function (res) {
      res.resume();
      finish("response");
    });
    req.on("error", function (e) { finish("error", e); });
    req.end();
    setTimeout(function () {
      if (!done) req.destroy();
      finish("pending");
    }, settle);
  });
}

// A DNS lookup that never answers: the socket is created and its connect stays
// pending forever. Deterministic, unlike aiming at an address one hopes is
// blackholed.
function hangingLookup() {
  log.debug("Entering hangingLookup()."); /* deliberately never calls back */ 
  log.debug("Leaving hangingLookup().");
}

// ---------------------------------------------------------------------------
// 1. A stalled connect is given up on at connectionTimeout.
// ---------------------------------------------------------------------------
async function stalledConnectIsAborted() {
  log.debug("Entering stalledConnectIsAborted().");
  log.info("=== A connect that never completes ===");
  var agent = connectTimeout.withConnectTimeout(
    new http.Agent({ lookup: hangingLookup }), 400);

  var result = await attempt({ host: "stalled.example", port: 80, path: "/" },
      agent, 3000);

  assert.strictEqual(result.outcome, "error",
    "a connect that never completes must fail, not hang (outcome: " +
        result.outcome + ").");
  assert.strictEqual(result.error.code, "ECONNECTTIMEOUT",
    "and fail as a connect timeout, not as something else: " +
    result.error.code + " / " + result.error.message);
  assert.ok(result.elapsed >= 350 && result.elapsed < 1500,
    "it must fail at about the configured 400ms, not sooner or much " +
        "later (took " +
    result.elapsed + "ms).");
  assert.ok(/connectionTimeout/.test(result.error.message),
    "the message should name the setting responsible, so the cause is " +
        "findable: " +
    result.error.message);
  // A socket that never connected has no remoteAddress, so naming the target
  // takes deliberate effort — and without it the error says only "the remote
  // host", which on a service that calls many is no help at all.
  assert.ok(/stalled\.example:80/.test(result.error.message),
    "and must name the host:port it failed to reach: " + result.error.message);
  log.info("[stalled connect] OK — refused after " + result.elapsed +
           "ms with " +
           result.error.code + ".");
  log.debug("Leaving stalledConnectIsAborted().");
}

// ---------------------------------------------------------------------------
// 2. A CONNECTED socket is not touched. This is the point of the whole
//    exercise: a slow IdP must get the full callTimeout, not the connect
//    budget.
// ---------------------------------------------------------------------------
async function connectedSocketSurvives() {
  log.debug("Entering connectedSocketSurvives().");
  log.info("=== A host that connects and then answers slowly ===");
  var silent = http.createServer(function (req,
      res) { /* accepts, never answers */ });
  var port = await listen(silent);

  var agent = connectTimeout.withConnectTimeout(new http.Agent(), 300);
  // Well past the 300ms connect budget: if the timer were still armed, or armed
  // against the whole call, this would come back as an error at ~300ms.
  var result = await attempt({ host: "127.0.0.1", port: port, path: "/" },
      agent, 1500);

  assert.strictEqual(result.outcome, "pending",
    "a connected-but-silent host must NOT be cut off by connectionTimeout — " +
        "that is what " +
    "callTimeout is for. Outcome was " + result.outcome +
    (result.error ? " (" + result.error.code + ": " + result.error.message +
     ")" : "") +
    " after " + result.elapsed + "ms.");
  silent.close();
  log.info("[connected] OK — still waiting after " + result.elapsed +
           "ms, five times the connect budget: the timer disarmed on connect.");
  log.debug("Leaving connectedSocketSurvives().");
}

// ---------------------------------------------------------------------------
// 3. TLS: a handshake that stalls is inside the budget ('secureConnect', not
//    'connect', is what counts as connected).
// ---------------------------------------------------------------------------
async function stalledTlsHandshakeIsAborted() {
  log.debug("Entering stalledTlsHandshakeIsAborted().");
  log.info("=== A TLS handshake that never completes ===");
  // Plain TCP: it accepts the connection, so the socket's 'connect' fires, but
  // it speaks no TLS, so 'secureConnect' never does.
  var deaf =
      net.createServer(function (socket) { /* accepts, never negotiates */ });
  var port = await listen(deaf);

  var agent = connectTimeout.withConnectTimeout(
    new https.Agent({ rejectUnauthorized: false }), 400);
  var result = await attempt(
    { protocol: "https:", host: "127.0.0.1", port: port, path: "/" }, agent,
     3000);

  assert.strictEqual(result.outcome, "error",
    "a TLS handshake that never completes must fail (outcome: " +
        result.outcome + ").");
  assert.strictEqual(result.error.code, "ECONNECTTIMEOUT",
    "and fail as a connect timeout — if the timer disarmed on the TCP " +
        "'connect' this " +
    "would hang instead. Got: " + result.error.code + " / " +
        result.error.message);
  assert.ok(result.elapsed >= 350 && result.elapsed < 1500,
    "at about the configured 400ms (took " + result.elapsed + "ms).");
  deaf.close();
  log.info("[tls] OK — the stalled handshake was refused after " +
           result.elapsed + "ms.");
  log.debug("Leaving stalledTlsHandshakeIsAborted().");
}

// ---------------------------------------------------------------------------
// 4. It composes with the SSRF guard rather than replacing its hook.
// ---------------------------------------------------------------------------
async function composesWithTheSsrfGuard() {
  log.debug("Entering composesWithTheSsrfGuard().");
  log.info("=== Wrapping a guarded agent keeps the guard ===");
  var guard = guardModule.createGuard({}, quiet);
  assert.ok(guard.enabled,
            "the guard must be ON when the configuration says nothing.");
  assert.strictEqual(typeof guard.createAgent, "function",
    "ssrf_guard must expose createAgent, which is how a per-call agent keeps " +
        "the hooks.");

  var served = 0;
  var victim = http.createServer(function (req,
      res) { served++; res.end("SECRET"); });
  var port = await listen(victim);

  var agent = connectTimeout.withConnectTimeout(guard.createAgent("http"),
      5000);
  var result = await attempt({ host: "127.0.0.1", port: port, path: "/" },
      agent, 3000);

  assert.strictEqual(result.outcome, "error",
    "a loopback connection through a guarded+timed agent must still " +
        "be refused.");
  assert.strictEqual(result.error.code, "EBLOCKEDADDRESS",
    "and refused by the guard, not by the timeout: " + result.error.code);
  assert.ok(result.elapsed < 1000,
    "immediately, rather than after the connect budget (took " +
        result.elapsed + "ms).");
  assert.strictEqual(served, 0,
    "the request must never reach the server (served " + served + " times).");
  victim.close();

  // And the off switch still yields a usable agent, since server.js builds one
  // unconditionally and only the guarding is configurable.
  var off = guardModule.createGuard({ blockPrivateNetworkCalls: false }, quiet);
  var plain = off.createAgent("https", { rejectUnauthorized: false });
  assert.ok(plain instanceof https.Agent,
    "createAgent must return an https.Agent when the guard is disabled too.");
  assert.strictEqual(plain.options.rejectUnauthorized, false,
    "and must honour the options it was given — several endpoints " +
        "deliberately allow " +
    "a self-signed IdP certificate.");
  var onAgent = guard.createAgent("https", { rejectUnauthorized: false });
  assert.strictEqual(onAgent.options.rejectUnauthorized, false,
    "including when the guard is enabled.");
  assert.strictEqual(typeof onAgent.options.lookup, "function",
    "a guarded agent must carry the guard's DNS lookup, which is the " +
        "layer that " +
    "survives a redirect.");
  log.info("[compose] OK — the guard refuses first, the timeout wraps it, " +
           "and agent options survive.");
  log.debug("Leaving composesWithTheSsrfGuard().");
}

// ---------------------------------------------------------------------------
// 5. withConnectTimeout declines to do anything with a nonsensical budget,
//    rather than arming a timer that fires immediately.
// ---------------------------------------------------------------------------
function refusesNonsensicalBudgets() {
  log.debug("Entering refusesNonsensicalBudgets().");
  log.info("=== A nonsensical budget leaves the agent alone ===");
  [0, -1, NaN, undefined, "400"].forEach(function (bad) {
    var agent = new http.Agent();
    var before = agent.createConnection;
    var after = connectTimeout.withConnectTimeout(agent, bad);
    assert.strictEqual(after, agent, "the same agent must come back for " +
                       JSON.stringify(bad) + ".");
    assert.strictEqual(agent.createConnection, before,
      "createConnection must be untouched for a budget of " +
          JSON.stringify(bad) +
      " — arming a timer on it would abort every call.");
  });
  // A resolved, positive budget does wrap it.
  var wrapped = new http.Agent();
  var original = wrapped.createConnection;
  connectTimeout.withConnectTimeout(wrapped, 400);
  assert.notStrictEqual(wrapped.createConnection, original,
    "a positive budget must wrap createConnection.");
  log.info("[budgets] OK — only a positive, finite number arms anything.");
  log.debug("Leaving refusesNonsensicalBudgets().");
}

// ---------------------------------------------------------------------------
// 6. What ships: every api/env config carries both settings, and every axios
//    call in server.js is bounded by both.
// ---------------------------------------------------------------------------
function shippedConfiguration() {
  log.debug("Entering shippedConfiguration().");
  log.info("=== The shipped configuration and call sites ===");
  var apiDir = fs.existsSync(path.join(__dirname, "..", "api", "env"))
    ? path.join(__dirname, "..", "api")
    : null;
  if (!apiDir) {
    log.info("[shipped] api/env is not in this image; skipping the " +
             "config half.");
  } else {
    var files = fs.readdirSync(path.join(apiDir, "env")).filter(function (f) {
      return f.endsWith(".js");
    });
    assert.ok(files.length >= 3, "expected the api/env configs to be present.");
    files.forEach(function (file) {
      var config = require(path.join(apiDir, "env", file));
      assert.ok(Number.isInteger(config.maxRedirects) &&
                config.maxRedirects >= 0,
        "api/env/" + file +
            " must set maxRedirects as a whole number >= 0 (0 is legal " +
        "and means 'do not follow'), got: " +
            JSON.stringify(config.maxRedirects));
      ["callTimeout", "connectionTimeout",
       "maxContentLength"].forEach(function (key) {
        assert.strictEqual(typeof config[key], "number",
          "api/env/" + file + " must set " + key + " as a number, got: " +
          JSON.stringify(config[key]));
        assert.ok(config[key] > 0,
          "api/env/" + file + "'s " + key +
              " must be positive — 0 means no timeout to " +
          "axios, and for maxContentLength it means refusing every response " +
              "with a body.");
      });
      assert.ok(config.connectionTimeout <= config.callTimeout,
        "api/env/" + file + ": connectionTimeout (" + config.connectionTimeout +
        ") should not exceed callTimeout (" + config.callTimeout +
        ") — the whole call cannot outlast its own connect budget.");
    });
    log.info("[shipped] OK — " + files.length + " api/env configs carry both " +
             "timeouts, the size cap and the redirect cap.");

    // Every axios call must be bounded. A new call site added without these is
    // exactly the regression this catches, and nothing else would.
    var source = fs.readFileSync(path.join(apiDir, "server.js"), "utf8");
    // Comment lines are dropped first: the file explains in prose why a bare
    // https.Agent is wrong, and that sentence must not read as the mistake it
    // describes. Line numbers are preserved so a failure still points
    // somewhere.
    var lines = source.split("\n").map(function (line) {
      return /^\s*(\/\/|\*|\/\*)/.test(line) ? "" : line;
    });
    var code = lines.join("\n");
    var sites = 0;
    lines.forEach(function (line, i) {
      if (!/\baxios(\.(get|post|put|patch|delete)\s*\(|\s*\(\s*\{)/.test(
          line)) return;
      sites++;
      var window_ = lines.slice(i, i + 20).join("\n");
      assert.ok(/timeout:\s*CALL_TIMEOUT/.test(window_),
        "the axios call at server.js:" + (i + 1) +
            " has no `timeout: CALL_TIMEOUT`.");
      assert.ok(/maxRedirects:\s*MAX_REDIRECTS/.test(window_),
        "the axios call at server.js:" + (i + 1) + " has no `maxRedirects: " +
        "MAX_REDIRECTS`, so it will follow axios's default of 21 hops.");
      assert.ok(/maxContentLength:\s*MAX_CONTENT_LENGTH/.test(window_),
        "the axios call at server.js:" + (i + 1) +
            " has no `maxContentLength: " +
        "MAX_CONTENT_LENGTH`, so it will buffer a response of any " +
            "size axios's " +
        "default (-1, unlimited) allows.");
      assert.ok(/outboundHttpsAgent\(/.test(window_) &&
                /outboundHttpAgent\(/.test(window_),
        "the axios call at server.js:" + (i + 1) +
            " must take its agents from " +
        "outboundHttpAgent()/outboundHttpsAgent(), or it has neither the " +
            "connect timeout " +
        "nor the SSRF guard's agent hooks.");
    });
    // A floor, not an exact count: adding an outbound call is fine, quietly
    // losing one of the bounded ones is not. 11 is where it stands — ten
    // caller-directed endpoints plus /claimdescription, which used to be a bare
    // `fetch` with no timeout and no cap at all.
    assert.ok(sites >= 11,
      "expected to find the api's axios call sites; found " + sites + ".");
    assert.ok(!/new\s+(\(require\('https'\)\.Agent\)|https\.Agent)\(/.test(
              code),
      "server.js must not build a bare https.Agent: that replaces " +
          "axios.defaults.httpsAgent " +
      "and drops the SSRF guard's hooks along with the connect timeout.");
    log.info("[shipped] OK — all " + sites + " axios call sites are bounded " +
             "by both timeouts, the size cap and the redirect cap.");
  }
  log.debug("Leaving shippedConfiguration().");
}

// ---------------------------------------------------------------------------
// 7. maxContentLength: an oversized response is abandoned, a normal one is not.
//
// Driven through axios itself rather than through a re-implementation, because
// the enforcement is axios's and what is being asserted is that the CAP IS
// PASSED TO IT and that its default (-1, unlimited) is not what applies.
// Skipped where the api's axios is not installed, since the tests package does
// not depend on it.
// ---------------------------------------------------------------------------
async function maxContentLengthIsEnforced() {
  log.debug("Entering maxContentLengthIsEnforced().");
  log.info("=== The response size cap ===");
  var axios = null;
  try {
    axios = require(path.join(__dirname, "..", "api", "node_modules", "axios"));
  } catch (e) {
    log.info("[size] the api's axios is not installed here; skipping " +
             "this case. (" +
             e.code + ")");
    log.debug("Leaving maxContentLengthIsEnforced().");
    return;
  }

  var CAP = 64 * 1024;
  // Serves however many bytes the path asks for, in small chunks, so the cap
  // has to be enforced as the body arrives rather than from a Content-Length
  // header.
  var big = http.createServer(function (req, res) {
    var total = parseInt(req.url.slice(1), 10);
    res.writeHead(200, { "Content-Type": "text/plain" });
    var chunk = Buffer.alloc(4096, 0x61);
    var sent = 0;
    (function push() {
      while (sent < total) {
        sent += chunk.length;
        if (!res.write(chunk)) return res.once("drain", push);
      }
      res.end();
    })();
  });
  var port = await listen(big);
  var base = "http://127.0.0.1:" + port + "/";

  // Under the cap: unaffected.
  var ok = await axios.get(base + (CAP / 2), { maxContentLength: CAP,
      timeout: 5000 });
  assert.strictEqual(ok.status, 200, "a response under the cap must succeed.");
  assert.ok(ok.data.length >= CAP / 2,
    "and must arrive whole (" + ok.data.length + " bytes).");

  // Over the cap: refused.
  var failure = null;
  try {
    await axios.get(base + (CAP * 4), { maxContentLength: CAP, timeout: 5000 });
  } catch (e) {
    failure = e;
  }
  assert.ok(failure,
            "a response larger than maxContentLength must be refused.");
  assert.ok(/maxContentLength/.test(failure.message),
    "and refused for that reason, not by the timeout: " + failure.message);

  // The control that gives the assertion above its meaning: the same oversized
  // response is fine when no cap is set, so what was refused was the SIZE.
  var uncapped = await axios.get(base + (CAP * 4), { timeout: 5000 });
  assert.strictEqual(uncapped.status, 200,
    "without a cap the same oversized response succeeds — which is " +
        "axios's default " +
    "(-1, unlimited) and the reason this setting has to be passed explicitly.");

  big.close();
  log.info("[size] OK — " + (CAP / 1024) +
           "KiB cap: a half-size body arrives, a " +
           "4x body is refused naming maxContentLength, and the same body is " +
           "accepted with no cap set.");
  log.debug("Leaving maxContentLengthIsEnforced().");
}

// ---------------------------------------------------------------------------
// 8. maxRedirects: a chain within the cap is followed, one past it is refused —
//    and the SSRF guard is still enforced ON A REDIRECT HOP, which is the
//    reason the cap and the guard are talked about together.
// ---------------------------------------------------------------------------
async function maxRedirectsIsEnforced() {
  log.debug("Entering maxRedirectsIsEnforced().");
  log.info("=== The redirect cap ===");
  var axios = null;
  try {
    axios = require(path.join(__dirname, "..", "api", "node_modules", "axios"));
  } catch (e) {
    log.info("[redirects] the api's axios is not installed here; skipping. (" +
             e.code + ")");
    log.debug("Leaving maxRedirectsIsEnforced().");
    return;
  }

  // /hop/N redirects to /hop/N-1 and /hop/0 answers, so the chain length is the
  // number in the URL.
  var hops = http.createServer(function (req, res) {
    var m = /^\/hop\/(\d+)/.exec(req.url);
    var left = m ? parseInt(m[1], 10) : 0;
    if (left > 0) {
      res.writeHead(302, { Location: "/hop/" + (left - 1) });
      return res.end();
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ARRIVED");
  });
  var port = await listen(hops);
  var base = "http://127.0.0.1:" + port;

  var ok = await axios.get(base + "/hop/4", { maxRedirects: 5, timeout: 5000 });
  assert.strictEqual(ok.data, "ARRIVED",
    "a chain within the cap must be followed to the end.");

  var failure = null;
  try {
    await axios.get(base + "/hop/9", { maxRedirects: 5, timeout: 5000 });
  } catch (e) {
    failure = e;
  }
  assert.ok(failure, "a chain longer than maxRedirects must be refused.");
  assert.ok(/redirect/i.test(failure.message),
    "and refused for that reason rather than by the timeout: " +
        failure.message);

  // 0 does not mean "unlimited" — it means do not follow, and hand back the
  // 3xx.
  var unfollowed = await axios.get(base + "/hop/3", {
    maxRedirects: 0, timeout: 5000,
    validateStatus: function () { return true; } });
  assert.strictEqual(unfollowed.status, 302,
    "maxRedirects: 0 must return the 3xx unfollowed, not follow it and " +
        "not error.");
  hops.close();

  // The hop itself goes through the agent, so the SSRF guard applies to it.
  // This is the claim that matters: layer 1 (the URL pre-flight) sees only the
  // FIRST url, so without this a public host could redirect the service
  // anywhere private. A custom range is used so the first hop, which has to be
  // reachable, is not itself blocked — the default policy blocks the loopback
  // this fixture runs on.
  var guard = guardModule.createGuard(
    { blockedAddressRanges: ["192.0.2.0/24"] }, quiet);
  var redirector = http.createServer(function (req, res) {
    res.writeHead(302, { Location: "http://192.0.2.1/secret" });
    res.end();
  });
  var rport = await listen(redirector);

  var blocked = null;
  try {
    await axios.get("http://127.0.0.1:" + rport + "/", {
      maxRedirects: 5,
      timeout: 5000,
      httpAgent: connectTimeout.withConnectTimeout(guard.createAgent("http"),
          4000),
      httpsAgent: guard.createAgent("https")
    });
  } catch (e) {
    blocked = e;
  }
  assert.ok(blocked, "a redirect to a blocked address must not be followed.");
  assert.strictEqual(blocked.code, "EBLOCKEDADDRESS",
    "and must be refused by the guard on the redirect hop, not time out or " +
        "connect: " +
    blocked.code + " / " + blocked.message);
  redirector.close();

  // A redirect to a NON-HTTP scheme. The api's scheme interceptor sees only the
  // first URL, so this one is refused by follow-redirects itself — which is
  // worth asserting precisely because it is somebody else's guarantee, not
  // ours.
  var schemeHop = http.createServer(function (req, res) {
    res.writeHead(302, { Location: "file:///etc/passwd" });
    res.end();
  });
  var sport = await listen(schemeHop);
  var schemeFailure = null;
  try {
    await axios.get("http://127.0.0.1:" + sport + "/", { maxRedirects: 5,
                    timeout: 5000 });
  } catch (e) {
    schemeFailure = e;
  }
  assert.ok(schemeFailure, "a redirect to file:// must not be followed.");
  assert.ok(/unsupported protocol/i.test(schemeFailure.message),
    "and must be refused as a protocol problem: " + schemeFailure.message);
  schemeHop.close();

  log.info("[redirects] OK — 4 hops followed, 9 refused, 0 returns the 3xx, " +
           "a redirect " +
           "to a blocked address is refused on the hop by the guard, and one " +
               "to file:// " +
           "is refused as an unsupported protocol.");
  log.debug("Leaving maxRedirectsIsEnforced().");
}

// ---------------------------------------------------------------------------
// 9. The outbound User-Agent: the template ships, the version placeholder is
//    the one the rest of the repo uses, and the api image can actually resolve
//    a build version to put in it.
// ---------------------------------------------------------------------------
function userAgentIsConfigured() {
  log.debug("Entering userAgentIsConfigured().");
  log.info("=== The outbound User-Agent ===");
  var repoRoot = path.join(__dirname, "..");
  if (!fs.existsSync(path.join(repoRoot, "api", "env"))) {
    log.info("[user-agent] api/env is not in this image; skipping.");
    log.debug("Leaving userAgentIsConfigured().");
    return;
  }

  fs.readdirSync(path.join(repoRoot, "api", "env"))
    .filter(function (f) { return f.endsWith(".js"); })
    .forEach(function (file) {
      var config = require(path.join(repoRoot, "api", "env", file));
      assert.strictEqual(typeof config.userAgent, "string",
        "api/env/" + file + " must set userAgent as a string, got: " +
        JSON.stringify(config.userAgent));
      assert.ok(config.userAgent.trim(),
        "api/env/" + file +
            "'s userAgent must not be blank — axios would send a " +
        "User-Agent header with nothing after the colon.");
      assert.ok(config.userAgent.indexOf("{{VERSION}}") >= 0,
        "api/env/" + file +
            "'s userAgent should carry the {{VERSION}} placeholder, " +
        "or the header will name no build: " +
            JSON.stringify(config.userAgent));
    });

  // The placeholder has to be the one server.js substitutes. These are two
  // separate files and nothing else compares them.
  var source = fs.readFileSync(path.join(repoRoot, "api", "server.js"), "utf8");
  assert.ok(/\{\{VERSION\}\}/.test(source),
    "server.js must substitute the same {{VERSION}} placeholder the " +
        "configs use.");

  // Every call site must carry the header, or that call is still `axios/x.y.z`.
  var lines = source.split("\n").map(function (line) {
    return /^\s*(\/\/|\*|\/\*)/.test(line) ? "" : line;
  });
  var sites = 0;
  lines.forEach(function (line, i) {
    if (!/\baxios(\.(get|post|put|patch|delete)\s*\(|\s*\(\s*\{)/.test(
        line)) return;
    sites++;
    var window_ = lines.slice(i, i + 20).join("\n");
    if (/headers:\s*withUserAgent\(/.test(window_)) {
      return;
    }
    // The headers may be HOISTED rather than built at the call site, and one
    // call site has to hoist them: POST /token puts the headers it sent into
    // the HTTP trace it hands back, and building them a second time for the
    // trace is how a trace comes to describe a request that was never made.
    // So a `headers:` naming a local is followed ONE step — to the assignment
    // that gave it its value, which must itself be withUserAgent(). A plain
    // object, or a local assigned from anything else, still fails: what is
    // checked is where the value came from, not how it was spelled.
    var named = window_.match(/headers:\s*([A-Za-z_$][\w$]*)\s*[,}\n]/);
    var above = lines.slice(Math.max(0, i - 40), i).join("\n");
    var assigned = !!named && new RegExp("(?:var|let|const)\\s+" +
        named[1] + "\\s*=\\s*withUserAgent\\(").test(above);
    assert.ok(assigned,
      "the axios call at server.js:" + (i + 1) +
          " does not take its headers from " +
      "withUserAgent(), so it announces itself as axios rather than as " +
          "this service. Write `headers: withUserAgent(...)` at the call, or " +
          "assign one to a local in the 40 lines above it and pass that" +
          (named ? " — `" + named[1] + "` is passed here and nothing above " +
              "assigns it from withUserAgent()." : "."));
  });
  assert.ok(sites >= 11, "expected the api's axios call sites; found " + sites +
            ".");

  // And the version itself must be resolvable the way server.js resolves it —
  // api/Dockerfile copies the repo VERSION and the client's version.js in for
  // exactly this, and omitting either silently yields 0.0.x.
  var versionModule = path.join(repoRoot, "client", "version.js");
  if (fs.existsSync(versionModule)) {
    var appversion = require(versionModule);
    var resolved = appversion.load(path.join(repoRoot, "api"));
    assert.ok(/^\d+\.\d+\.\S+$/.test(resolved.version),
      "the version must come out as M.N.O, got: " + resolved.version);
    assert.ok(!/^0\.0\./.test(resolved.version),
      "a version of 0.0.x means the VERSION file was not found — " +
          "which is what " +
      "happens if api/Dockerfile stops COPYing it: " + resolved.version);

    var dockerfile = fs.readFileSync(path.join(repoRoot, "api", "Dockerfile"),
        "utf8");
    assert.ok(/COPY\s+VERSION\s/.test(dockerfile),
      "api/Dockerfile must COPY the repo-root VERSION file, or the image " +
          "reports 0.0.x.");
    assert.ok(/COPY\s+client\/version\.js\s/.test(dockerfile),
      "api/Dockerfile must COPY client/version.js, which is what " +
          "server.js loads.");
    assert.ok(/version\.js --stamp/.test(dockerfile),
      "api/Dockerfile must stamp version.json, so the User-Agent names " +
          "the BUILD " +
      "rather than a number invented at each container start.");
    log.info("[user-agent] OK — every call site sends it, all configs " +
             "carry the " +
             "{{VERSION}} template, and the version resolves to " +
                 resolved.version + ".");
    log.debug("Leaving userAgentIsConfigured().");
    return;
  }
  log.info("[user-agent] OK — every call site sends it and all configs carry " +
           "the template.");
  log.debug("Leaving userAgentIsConfigured().");
}

// ---------------------------------------------------------------------------
// 10. keepAlive: connections are actually reused, and the agents are SHARED —
//     which is not a detail. A keep-alive agent that is discarded after one
//     response still holds that response's socket in its free pool and nothing
//     closes it, so per-call agents plus keepAlive leak a descriptor per call.
// ---------------------------------------------------------------------------
async function keepAliveIsConfigured() {
  log.debug("Entering keepAliveIsConfigured().");
  log.info("=== Connection pooling ===");

  var connections = 0;
  var served = 0;
  var idp = http.createServer(function (req, res) {
    served++;
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  idp.on("connection", function () { connections++; });
  var port = await listen(idp);

  function get(agent) {
    log.debug("Entering get().");
    log.debug("Leaving get().");
    return new Promise(function (resolve, reject) {
      var req = http.request({ host: "127.0.0.1", port: port, path: "/",
          agent: agent },
        function (res) {
          res.resume();
          res.on("end", resolve);
        });
      req.on("error", reject);
      req.end();
    });
  }

  // Pooling on, through ONE agent built the way server.js builds them.
  var pooled = connectTimeout.withConnectTimeout(
    guardModule.createGuard({ blockPrivateNetworkCalls: false }, quiet)
      .createAgent("http", { keepAlive: true }), 4000);
  for (var i = 0; i < 3; i++) {
    await get(pooled);
  }
  assert.strictEqual(served, 3, "all three requests should have been served.");
  assert.strictEqual(connections, 1,
    "with keepAlive on, three requests through one agent must reuse a " +
        "single TCP " +
    "connection; the server saw " + connections + ".");

  // Pooling off: a connection each.
  connections = 0;
  served = 0;
  var unpooled = connectTimeout.withConnectTimeout(
    guardModule.createGuard({ blockPrivateNetworkCalls: false }, quiet)
      .createAgent("http", { keepAlive: false }), 4000);
  for (var j = 0; j < 3; j++) {
    await get(unpooled);
  }
  assert.strictEqual(connections, 3,
    "with keepAlive off each request must open its own connection; the " +
        "server saw " +
    connections + ".");

  // The leak, demonstrated: a throwaway keep-alive agent is still holding its
  // socket after the response completed. This is why server.js caches agents.
  var throwaway = new http.Agent({ keepAlive: true });
  await get(throwaway);
  await sleep(150);
  var held = Object.keys(throwaway.freeSockets || {}).reduce(function (n, k) {
    return n + throwaway.freeSockets[k].length;
  }, 0);
  assert.strictEqual(held, 1,
    "a discarded keep-alive agent should still be holding its socket " +
        "(this is the " +
    "leak that makes per-call agents wrong once keepAlive is on); held " +
        held + ".");
  throwaway.destroy();
  idp.close();

  // Which is why server.js must not build one per call.
  var repoRoot = path.join(__dirname, "..");
  var serverPath = path.join(repoRoot, "api", "server.js");
  if (fs.existsSync(serverPath)) {
    var source = fs.readFileSync(serverPath, "utf8");
    assert.ok(/function agentFor\(/.test(source) &&
              /outboundAgentCache/.test(source),
      "server.js must cache its outbound agents (agentFor + a cache), or " +
          "keepAlive " +
      "pools nothing and leaks the socket it parked.");
    // `[^{}]*` rather than `\s*` between the brace and the return: every
    // function in this tree opens with log.debug("Entering ...") and closes
    // with a matching Leaving, so a check that demands the return be the very
    // first token fails on the logging convention rather than on a per-call
    // agent. Refusing any `{`/`}` in between still pins the return to this
    // function.
    assert.ok(/function outboundHttpAgent\(\)\s*\{[^{}]*return agentFor\(/.test(
              source),
      "outboundHttpAgent() must return the cached agent rather than " +
          "a new one.");
    assert.ok(
        /function outboundHttpsAgent\([^)]*\)\s*\{[^{}]*return agentFor\(/.test(
        source),
      "outboundHttpsAgent() must return the cached agent rather than " +
          "a new one.");

    fs.readdirSync(path.join(repoRoot, "api", "env"))
      .filter(function (f) { return f.endsWith(".js"); })
      .forEach(function (file) {
        var config = require(path.join(repoRoot, "api", "env", file));
        assert.strictEqual(typeof config.keepAlive, "boolean",
          "api/env/" + file +
              " must set keepAlive as a boolean (a quoted \"false\" is " +
          "truthy), got: " + JSON.stringify(config.keepAlive));
      });
  }

  log.info("[keep-alive] OK — 3 requests over 1 connection when on, 3 when " +
           "off, the " +
           "discarded-agent socket leak reproduced, and server.js caches " +
               "its agents.");
  log.debug("Leaving keepAliveIsConfigured().");
}

async function test() {
  log.debug("Entering test().");
  await stalledConnectIsAborted();
  await connectedSocketSurvives();
  await stalledTlsHandshakeIsAborted();
  await composesWithTheSsrfGuard();
  refusesNonsensicalBudgets();
  await maxContentLengthIsEnforced();
  await maxRedirectsIsEnforced();
  userAgentIsConfigured();
  await keepAliveIsConfigured();
  shippedConfiguration();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_connect_timeout")
  .description("Verify the api's outbound call and connection timeouts.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
