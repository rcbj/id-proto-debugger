// File: api_ssrf_guard.js
//
// The api's outbound address policy (api/ssrf_guard.js).
//
// That service fetches URLs its CALLER supplies — the token, introspection,
// revocation, device-authorization and userinfo endpoints, the SAML
// ArtifactResolve back-channel, the WS-Trust STS and the generic proxy — so
// without a guard anyone who can reach it can use it to probe 127.0.0.1, the
// deployment's private neighbours, or 169.254.169.254, where a cloud instance
// hands out credentials. This test is what says the guard actually refuses them.
//
// No browser and no services: node only, so it never skips.
//
// It exercises BOTH layers, because either alone is insufficient:
//   * the URL pre-flight (assertUrlAllowed), which is what produces the error a
//     caller sees;
//   * the DNS lookup on the agents, which is the layer that holds when a call is
//     REDIRECTED — axios follows redirects itself, so a public host answering
//     "302 Location: http://127.0.0.1:8080/" never passes through the pre-flight a
//     second time. Rather than pull axios in (the tests package does not have it),
//     the agent is driven directly with http.request: that is precisely the code
//     path a redirect hop takes.
//
// Sources of truth this test deliberately does NOT duplicate: the default range
// list and the parsing live in the module, and are asserted through its API.
const assert = require("assert");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_ssrf_guard",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the module is at api/ssrf_guard.js; the tests image copies it flat
// next to the test scripts (see tests/Dockerfile).
var guardModule = paths.requireSharedModule(
  [__dirname + "/../api/ssrf_guard.js", __dirname + "/ssrf_guard.js"], "ssrf_guard.js");

// A logger the guard can call without the output drowning the test.
var quiet = { debug: function () {}, info: function () {}, warn: function () {}, error: function () {} };

function listen(server) {
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve(server.address().port); });
  });
}

// ---------------------------------------------------------------------------
// 1. Which addresses the default policy blocks.
// ---------------------------------------------------------------------------
function addressMatrix() {
  log.info("=== The default policy, address by address ===");
  var guard = guardModule.createGuard({}, quiet);
  assert.ok(guard.enabled, "the guard must be ON when the configuration says nothing.");
  assert.ok(guard.ranges.length >= 10,
    "the default policy should cover loopback, the private ranges and their IPv6 equivalents, got " +
    guard.ranges.length + ".");

  var blocked = [
    ["127.0.0.1", "loopback"],
    ["127.1.2.3", "the rest of 127/8"],
    ["0.0.0.0", "this host on this network"],
    ["10.1.2.3", "RFC 1918"],
    ["172.16.0.1", "RFC 1918, first address"],
    ["172.31.255.255", "RFC 1918, last address"],
    ["192.168.1.1", "RFC 1918"],
    ["169.254.169.254", "cloud instance metadata"],
    ["100.64.0.1", "carrier-grade NAT"],
    ["::1", "IPv6 loopback"],
    ["fe80::1", "IPv6 link-local"],
    ["fd12:3456::1", "IPv6 unique local"],
    ["::ffff:127.0.0.1", "IPv4-mapped loopback — the classic way past a naive check"],
    ["::ffff:10.0.0.1", "IPv4-mapped RFC 1918"],
    ["0:0:0:0:0:ffff:7f00:1", "IPv4-mapped loopback, written out"],
    ["fe80::1%eth0", "a zone index must not defeat the match"]
  ];
  blocked.forEach(function (pair) {
    assert.ok(guard.blockedRangeFor(pair[0]),
      pair[0] + " (" + pair[1] + ") must be blocked, and is not.");
  });

  // The other half of the claim: it must not block the internet.
  var allowed = [
    ["8.8.8.8", "public"],
    ["1.1.1.1", "public"],
    ["172.15.255.255", "just below RFC 1918's 172.16/12"],
    ["172.32.0.1", "just above RFC 1918's 172.16/12"],
    ["2606:4700:4700::1111", "public IPv6"],
    ["::ffff:8.8.8.8", "IPv4-mapped public"]
  ];
  allowed.forEach(function (pair) {
    assert.strictEqual(guard.blockedRangeFor(pair[0]), null,
      pair[0] + " (" + pair[1] + ") must NOT be blocked — a guard that blocks the internet is useless.");
  });
  log.info("[policy] OK — " + blocked.length + " private/loopback forms refused, " +
           allowed.length + " public ones allowed, across " + guard.ranges.length + " ranges.");
}

// ---------------------------------------------------------------------------
// 2. The configuration takes RANGES, in either notation, and says why it refuses
//    anything else.
// ---------------------------------------------------------------------------
function rangeConfiguration() {
  log.info("=== The range configuration ===");
  var good = ["10.0.0.0/8", "10.0.0.0-10.255.255.255", "fc00::/7", "2001:db8::1-2001:db8::ff", "0.0.0.0/0"];
  good.forEach(function (entry) {
    var parsed = guardModule.parseRange(entry);
    assert.ok(!parsed.error, "\"" + entry + "\" is a valid range and should parse, got: " + parsed.error);
  });

  // A single address is refused ON PURPOSE: this list is a network policy, and a
  // one-host entry nearly always means the block that host sits in.
  var refused = [
    ["10.1.2.3", /single address/],
    ["10.0.0.0/33", /prefix length/],
    ["10.255.0.0-10.0.0.0", /starts after it ends/],
    ["10.0.0.0-fc00::", /mixes IPv4 and IPv6/],
    ["", /empty/],
    ["garbage/8", /not an address range/]
  ];
  refused.forEach(function (pair) {
    var parsed = guardModule.parseRange(pair[0]);
    assert.ok(parsed.error, "\"" + pair[0] + "\" must be refused as a range.");
    assert.ok(pair[1].test(parsed.error),
      "the refusal of \"" + pair[0] + "\" should say why (expected " + pair[1] + "), got: " + parsed.error);
  });

  // A configured policy replaces the defaults, and a first-last range works as a
  // range: inside blocked, outside allowed.
  var custom = guardModule.createGuard(
    { blockedAddressRanges: ["172.20.0.0-172.20.255.255"] }, quiet);
  assert.deepStrictEqual(custom.ranges, ["172.20.0.0-172.20.255.255"],
    "a configured list should replace the defaults wholesale, got: " + JSON.stringify(custom.ranges));
  assert.ok(custom.blockedRangeFor("172.20.13.9"), "an address inside the configured range must be blocked.");
  assert.ok(custom.blockedRangeFor("::ffff:172.20.0.9"),
    "and so must its IPv4-mapped form.");
  assert.strictEqual(custom.blockedRangeFor("172.21.0.1"), null,
    "an address outside the configured range must be allowed.");
  assert.strictEqual(custom.blockedRangeFor("127.0.0.1"), null,
    "loopback is NOT blocked by a policy that does not name it — the list is the policy.");
  log.info("[config] OK — " + good.length + " range forms accepted, " + refused.length +
           " malformed entries refused with a reason, and a configured list replaces the defaults.");
}

// ---------------------------------------------------------------------------
// 3. Layer one: the URL pre-flight.
// ---------------------------------------------------------------------------
async function urlPreflight() {
  log.info("=== Layer 1: the URL pre-flight ===");
  var guard = guardModule.createGuard({}, quiet);

  async function refuses(url, why) {
    var failed = null;
    try {
      await guard.assertUrlAllowed(url);
    } catch (e) {
      failed = e;
    }
    assert.ok(failed, url + " must be refused (" + why + ").");
    assert.strictEqual(failed.code, "EBLOCKEDADDRESS",
      "the refusal should carry the EBLOCKEDADDRESS code, got: " + failed.code);
    assert.ok(/Refusing to call/.test(failed.message),
      "and a message a caller can act on, got: " + failed.message);
  }

  await refuses("http://127.0.0.1:8080/token", "literal loopback");
  await refuses("http://localhost:8080/token", "a NAME that resolves to loopback");
  await refuses("http://[::1]:8080/token", "bracketed IPv6 loopback");
  await refuses("http://169.254.169.254/latest/meta-data/", "cloud instance metadata");
  await refuses("http://10.0.0.1/", "RFC 1918");
  await refuses("https://127.0.0.1/", "https makes no difference");

  // Allowed: a public literal, checked without touching the network so this test
  // needs no internet.
  await guard.assertUrlAllowed("http://8.8.8.8/");
  await guard.assertUrlAllowed("https://[2606:4700:4700::1111]/");
  log.info("[preflight] OK — loopback by literal, by name and by IPv6, metadata and RFC 1918 all refused; " +
           "public literals allowed.");
}

// ---------------------------------------------------------------------------
// 4. Layer two: the agent's DNS lookup — the layer that survives a REDIRECT.
// ---------------------------------------------------------------------------
async function agentLayer() {
  log.info("=== Layer 2: the agent (what a redirect hop goes through) ===");
  var guard = guardModule.createGuard({}, quiet);

  var served = 0;
  var victim = http.createServer(function (req, res) { served++; res.end("SECRET-FROM-LOOPBACK"); });
  var port = await listen(victim);

  function fetchWith(agent) {
    return new Promise(function (resolve, reject) {
      var req = http.request({ host: "127.0.0.1", port: port, path: "/", agent: agent },
        function (res) {
          var body = "";
          res.on("data", function (d) { body += d; });
          res.on("end", function () { resolve(body); });
        });
      req.on("error", reject);
      req.end();
    });
  }

  // Control first: without the guard the server really is reachable, so the
  // refusal below cannot be a broken fixture.
  var control = await fetchWith(undefined);
  assert.strictEqual(control, "SECRET-FROM-LOOPBACK",
    "the fixture server should be reachable with an ordinary agent.");

  var blocked = null;
  try {
    await fetchWith(guard.httpAgent);
  } catch (e) {
    blocked = e;
  }
  assert.ok(blocked, "a connection through the guarded agent must be refused.");
  assert.strictEqual(blocked.code, "EBLOCKEDADDRESS",
    "and refused by the guard, not by something else: " + (blocked && blocked.message));
  assert.strictEqual(served, 1,
    "the guarded request must never reach the server (it was served " + served + " times, expected 1 — " +
    "the control request only).");
  victim.close();
  log.info("[agent] OK — the guarded agent refuses the connection before the socket is opened, " +
           "which is the same path a redirect hop takes; an ordinary agent reaches the same server.");
}

// ---------------------------------------------------------------------------
// 5. install(): what it does to the http client, and the off switch.
// ---------------------------------------------------------------------------
function installation() {
  log.info("=== Installing on the http client ===");
  function stubAxios() {
    return {
      defaults: {},
      interceptors: { request: { handlers: [], use: function (fn) { this.handlers.push(fn); } } }
    };
  }

  var on = stubAxios();
  var enabledGuard = guardModule.createGuard({}, quiet);
  var report = enabledGuard.install(on);
  assert.ok(report.enabled, "install() should report the guard as enabled.");
  assert.ok(on.defaults.httpAgent && on.defaults.httpsAgent,
    "both agents must be set, or a redirect over the other scheme would go unchecked.");
  assert.strictEqual(on.interceptors.request.handlers.length, 1,
    "the pre-flight interceptor should be registered exactly once.");

  // The off switch: a deployment whose identity providers really are private
  // (this suite's own local and docker stacks) must be able to turn it off.
  var off = stubAxios();
  var disabled = guardModule.createGuard({ blockPrivateNetworkCalls: false }, quiet);
  assert.strictEqual(disabled.enabled, false, "an explicit false must disable the guard.");
  var offReport = disabled.install(off);
  assert.strictEqual(offReport.enabled, false, "install() should report it as disabled.");
  assert.ok(!off.defaults.httpAgent && !off.defaults.httpsAgent,
    "a disabled guard must not install its agents.");
  assert.strictEqual(off.interceptors.request.handlers.length, 0,
    "nor its interceptor.");

  // And only an explicit false: a missing key, or anything truthy-ish, stays safe.
  [undefined, null, "false", 0, "no"].forEach(function (value) {
    var g = guardModule.createGuard({ blockPrivateNetworkCalls: value }, quiet);
    assert.strictEqual(g.enabled, true,
      "blockPrivateNetworkCalls=" + JSON.stringify(value) + " must NOT disable the guard — " +
      "only a real false may, so a typo cannot open it.");
  });
  log.info("[install] OK — enabled: both agents plus one interceptor; disabled: neither; " +
           "and only a real `false` disables it.");
}

// ---------------------------------------------------------------------------
// 6. The wiring and the shipped policy — only checkable in a checkout, where the
//    api directory is next door. The tests image copies the module flat, so these
//    are reported as skipped there rather than silently passing.
// ---------------------------------------------------------------------------
function shippedConfiguration() {
  log.info("=== The wiring and the shipped configuration ===");
  var apiDir = path.join(__dirname, "..", "api");
  if (!fs.existsSync(path.join(apiDir, "server.js"))) {
    log.info("[shipped] the api directory is not next to the tests (the container's flat layout); " +
             "skipping the wiring and env-file checks.");
    return;
  }

  // The guard is worthless if nothing installs it.
  var server = fs.readFileSync(path.join(apiDir, "server.js"), "utf8");
  assert.ok(/ssrf_guard/.test(server) && /\.install\(\s*axios\s*\)/.test(server),
    "api/server.js must install the guard on the axios instance every endpoint uses.");

  // The policy each deployment ships with. local and docker-tests are the
  // deliberate exceptions: on those stacks the identity provider and the mock STS
  // ARE private addresses, so the guard would refuse every call the service exists
  // to make.
  var expected = { "local.js": false, "docker-tests.js": false, "test.js": true };
  Object.keys(expected).forEach(function (file) {
    var full = path.join(apiDir, "env", file);
    if (!fs.existsSync(full)) return;
    var config = require(full);
    assert.strictEqual(config.blockPrivateNetworkCalls, expected[file],
      "api/env/" + file + " should set blockPrivateNetworkCalls=" + expected[file] + ", got: " +
      JSON.stringify(config.blockPrivateNetworkCalls));
    assert.ok(Array.isArray(config.blockedAddressRanges) && config.blockedAddressRanges.length,
      "api/env/" + file + " should carry the blocked ranges, so the policy is visible where it is deployed.");
    config.blockedAddressRanges.forEach(function (entry) {
      var parsed = guardModule.parseRange(entry);
      assert.ok(!parsed.error,
        "api/env/" + file + " has an unusable range \"" + entry + "\": it " + parsed.error + ".");
    });
  });
  log.info("[shipped] OK — server.js installs the guard, and every api/env config carries a usable " +
           "range list (local and docker-tests disable it deliberately; test.js keeps it on).");
}

async function test() {
  addressMatrix();
  rangeConfiguration();
  await urlPreflight();
  await agentLayer();
  installation();
  shippedConfiguration();
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("api_ssrf_guard")
  .description("Verify the api's outbound address policy (api/ssrf_guard.js).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
