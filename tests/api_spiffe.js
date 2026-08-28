// File: api_spiffe.js
//
// ---------------------------------------------------------------------------
// THE THREE SPIFFE ENDPOINTS ON THE API, OVER HTTP.
//
// `POST /spiffe/call`, `POST /spiffe/bundle` and `GET /spiffe/limits`.
// `spiffe_engine.js` asserts the client's rules with no network and
// `spiffe_protocol.js` calls all forty-nine methods in process; what is left,
// and what only exists here, is **the status-code rule** — which is the single
// most consequential decision this endpoint makes and the one a naive
// implementation gets wrong.
//
// ---------------------------------------------------------------------------
// THE THREE OUTCOMES, AND WHY THE THIRD IS THE POINT
//
//   400  a refusal by THIS service. An address it will not dial, a socket path
//        outside the allowlist, a method that is not on the surface. The caller
//        asked for something the api will not do.
//   502  a network failure — and a server that answered and turned out to be
//        somebody else, which is reported separately with `identityMismatch`.
//   200  **a gRPC status from the far end, whatever it is**, with `ok: false`
//        and the code.
//
// That last one is the whole reason this file exists. `PERMISSION_DENIED` on a
// method the caller's entity may not use, `UNAUTHENTICATED` when nothing was
// presented, `UNIMPLEMENTED` with the reason a server gives for declining,
// `INVALID_ARGUMENT` on a JWT-SVID request with no audience — every one of
// those is SPIFFE ANSWERING, and an api that reported them as failures would
// put the most interesting half of this workflow behind an error page. It is
// the same rule `POST /ldap/*` and `POST /scim` follow, and it is asserted here
// on the STATUS of every negative rather than on the body, because a body can
// be right while the transport code is wrong and the page reads the code first.
//
// It needs the api. It does NOT need a browser, and it needs the mock STS only
// for the section that has a server to talk to — the refusals are asserted
// against addresses that are deliberately unreachable, which is what makes them
// fast and independent of anything being up.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_spiffe",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const API_URL = process.env.API_URL || "http://localhost:4000";
const STS_URL = process.env.STS_URL || "https://localhost:8081";
// The API's view of the mock, which on the containerized stack is a different
// name from this test's. Its own variable for the reason LDAP_URL is.
const WORKLOAD_ADDRESS = process.env.SPIFFE_WORKLOAD_ADDRESS ||
  "localhost:8092";
const SERVER_ADDRESS = process.env.SPIFFE_SERVER_ADDRESS || "localhost:8181";
const BUNDLE_URL = process.env.SPIFFE_BUNDLE_URL ||
  (process.env.API_STS_URL || STS_URL) + "/spiffe/bundle";
const TRUST_DOMAIN = process.env.SPIFFE_TRUST_DOMAIN || "example.org";

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

async function post(path, body) {
  log.debug("Entering post(). " + path);
  const response = await fetch(API_URL + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = JSON.parse(text);
  } catch (e) {
    payload = { error: text };
  }
  log.debug("Leaving post(). " + response.status);
  return { status: response.status, payload: payload };
}

// The gate, and it names what is actually true rather than what is missing. On
// a static deployment there is no api at all, and a line naming a missing
// endpoint invites somebody to go looking for one — the correction
// tests/CLAUDE.md records about `api_ldap.js`.
async function gate() {
  log.debug("Entering gate().");
  let response = null;
  try {
    response = await fetch(API_URL + "/spiffe/limits");
  } catch (e) {
    log.warn("SKIPPING: the api at " + API_URL + " could not be reached (" +
      e.message + "). This deployment has no api behind it, so neither of " +
      "SPIFFE's gRPC surfaces exists here — which is the known state of a " +
      "static site rather than something to go looking for.");
    log.debug("Leaving gate(). Unreachable.");
    return null;
  }
  if (response.status === 404) {
    log.warn("SKIPPING: the api at " + API_URL + " answered 404 for GET " +
      "/spiffe/limits, so it is an older build with no SPIFFE support. That " +
      "is a different thing from a SPIRE server that will not answer.");
    log.debug("Leaving gate(). 404.");
    return null;
  }
  if (!response.ok) {
    throw new Error("GET /spiffe/limits answered " + response.status);
  }
  const limits = await response.json();
  log.debug("Leaving gate(). Available.");
  return limits;
}

// ---------------------------------------------------------------------------
// 1. GET /spiffe/limits — how the page knows what it may ask for.
// ---------------------------------------------------------------------------
function testLimits(limits) {
  log.debug("Entering testLimits().");
  check("the limits publish the ports, the socket prefixes and both " +
    "deadlines, so the page can say what will happen BEFORE a call fails " +
    "rather than reporting its own limits as somebody else's fault",
    function () {
      assert.ok(limits.ports === "any" || Array.isArray(limits.ports));
      assert.ok(limits.socketPaths === "any" ||
        Array.isArray(limits.socketPaths));
      assert.ok(limits.callTimeoutMs > 0);
      assert.ok(limits.streamTimeoutMs > limits.callTimeoutMs,
        "a stream and a call are bounded by different questions");
      assert.ok(limits.maxStreamMessages >= 1);
      assert.strictEqual(limits.securityHeader, "workload.spiffe.io");
      assert.deepStrictEqual(limits.serverIdentityModes,
        ["spiffe-id", "trust-domain", "none"]);
    });

  check("the catalogue it publishes is all forty-nine methods, so the page's " +
    "picker is built from what this service can ACTUALLY call rather than " +
    "from a list typed twice", function () {
      const surfaces = limits.surfaces;
      assert.ok(surfaces && surfaces.workload && surfaces.server);
      let total = 0;
      let described = 0;
      ["workload", "server"].forEach(function (surface) {
        surfaces[surface].forEach(function (group) {
          group.methods.forEach(function (method) {
            total++;
            if (method.what) described++;
            assert.ok(method.path.endsWith("/" + method.name), method.path);
          });
        });
      });
      assert.strictEqual(total, 49);
      assert.strictEqual(described, 49,
        "a method offered with no explanation is one the page shows and " +
        "cannot describe");
    });

  check("it names the asymmetry that surprises everybody once: the Workload " +
    "API is never authenticated and the SPIRE Server API's TCP port is " +
    "mutual TLS", function () {
      const notes = (limits.notes || []).join(" ");
      assert.ok(/MUST NOT be required|never authenticated/i.test(notes),
        "the notes must say the Workload API requires no credential: " +
        notes.slice(0, 200));
      assert.ok(/mutual TLS/i.test(notes));
      assert.ok(/no DNS name/i.test(notes),
        "and that hostname verification cannot apply to a SPIRE server");
    });
  log.debug("Leaving testLimits().");
}

// ---------------------------------------------------------------------------
// 2. THE REFUSALS — 400, with the code, against addresses nothing answers on.
// ---------------------------------------------------------------------------
const REFUSALS = [
  { what: "no address at all",
    body: { service: "debug", method: "GetInfo" },
    must: /address is required/ },
  { what: "a scheme this service does not dial",
    body: { address: "htp://nowhere.invalid:8181", service: "debug",
            method: "GetInfo" },
    code: "ESPIFFEBADADDRESS" },
  { what: "an address with no port — gRPC has no default one",
    body: { address: "nowhere.invalid", service: "debug",
            method: "GetInfo" },
    code: "ESPIFFEBADADDRESS" },
  { what: "a port outside the allowlist",
    body: { address: "198.51.100.7:22", service: "debug", method: "GetInfo" },
    code: "ESPIFFEPORTNOTALLOWED" },
  { what: "a service that is on neither surface",
    body: { address: "198.51.100.7:8181", service: "everything",
            method: "GetInfo" },
    code: "ESPIFFENOSERVICE" },
  { what: "a method that service does not have",
    body: { address: "198.51.100.7:8181", service: "debug",
            method: "GetEverything" },
    code: "ESPIFFENOMETHOD" },
  { what: "a Unix socket outside the prefix allowlist — the one bound in " +
          "this service that the address policy cannot judge, because a path " +
          "is not an address",
    body: { address: "unix:///etc/passwd", service: "debug",
            method: "GetInfo" },
    code: "ESPIFFESOCKETNOTALLOWED" },
  { what: "a metadata name that is not a token",
    body: { address: "198.51.100.7:8181", service: "bundle",
            method: "GetBundle", metadata: { "not a token": "x" } },
    code: "ESPIFFEBADMETADATA" },
  { what: "a metadata value carrying a line feed",
    body: { address: "198.51.100.7:8181", service: "bundle",
            method: "GetBundle", metadata: { "x-thing": "a\nb" } },
    code: "ESPIFFEBADMETADATA" },
  { what: "verifying a server with no trust bundle to verify it against",
    body: { address: "198.51.100.7:8181", service: "bundle",
            method: "GetBundle", trustDomain: "example.org" },
    code: "ESPIFFENOTRUSTBUNDLE" }
];

async function testRefusals() {
  log.debug("Entering testRefusals().");
  for (const row of REFUSALS) {
    const answer = await post("/spiffe/call", row.body);
    check("400 with a reason: " + row.what, function () {
      assert.strictEqual(answer.status, 400,
        "a refusal by this service is a 400 — the caller asked for something " +
        "the api will not do, which is a different thing from a server that " +
        "did not answer. Got " + answer.status + ": " +
        JSON.stringify(answer.payload).slice(0, 200));
      if (row.code) {
        assert.strictEqual(answer.payload.code, row.code,
          "the refusal must name WHICH check fired: \"it was refused\" is " +
          "satisfied by the wrong one");
      }
      if (row.must) {
        assert.ok(row.must.test(answer.payload.error), answer.payload.error);
      }
    });
  }
  log.debug("Leaving testRefusals().");
}

// ---------------------------------------------------------------------------
// 3. A NETWORK FAILURE IS A 502, and every path answers.
//
// Pointing this endpoint at a host that may not be there is the POINT, so the
// no-response branch is a common branch rather than a rare one — and a handler
// whose fallback sat inside `if (error.response)` would send no reply at all.
// ---------------------------------------------------------------------------
async function testNetworkFailure() {
  log.debug("Entering testNetworkFailure().");
  const started = Date.now();
  const answer = await post("/spiffe/call", {
    address: "198.51.100.7:8181", service: "bundle", method: "GetBundle",
    serverIdentityMode: "none" });
  const elapsed = Date.now() - started;
  check("a server that is not there is a 502 and not a 400 — the caller " +
    "asked for something reasonable and the far end did not deliver",
    function () {
      assert.strictEqual(answer.status, 502,
        "got " + answer.status + ": " +
        JSON.stringify(answer.payload).slice(0, 200));
      assert.ok(answer.payload.error, "a 502 with no message says nothing");
      assert.notStrictEqual(answer.payload.identityMismatch, true,
        "nothing answered, so this is not a question about who it was");
    });
  check("and it SETTLED rather than hanging — every path here resolves or " +
    "rejects, because a browser waiting on an api that never replies is the " +
    "one failure this endpoint must not have (" + elapsed + "ms)",
    function () {
      assert.ok(elapsed < 120000, "it took " + elapsed + "ms");
    });
  log.debug("Leaving testNetworkFailure().");
}

// ---------------------------------------------------------------------------
// 4. A gRPC STATUS IS A 200. The rule this file exists for.
// ---------------------------------------------------------------------------
async function testStatusIsTwoHundred() {
  log.debug("Entering testStatusIsTwoHundred().");

  const noAudience = await post("/spiffe/call", {
    address: WORKLOAD_ADDRESS, service: "workload", method: "FetchJWTSVID",
    request: {} });
  check("INVALID_ARGUMENT from the far end is a 200 with ok:false and the " +
    "code — the call completed and the answer was no", function () {
      assert.strictEqual(noAudience.status, 200,
        "got " + noAudience.status + ": " +
        JSON.stringify(noAudience.payload).slice(0, 300));
      assert.strictEqual(noAudience.payload.ok, false);
      assert.strictEqual(noAudience.payload.status.name, "INVALID_ARGUMENT");
      assert.ok(noAudience.payload.status.details,
        "the reason the server gave is the most useful part of the answer");
    });

  const wit = await post("/spiffe/call", {
    address: WORKLOAD_ADDRESS, service: "workload", method: "FetchWITSVID",
    request: { audience: ["spiffe://" + TRUST_DOMAIN + "/x"] } });
  check("UNIMPLEMENTED is a 200 too, with the reason the server publishes " +
    "for declining", function () {
      assert.strictEqual(wit.status, 200);
      assert.strictEqual(wit.payload.ok, false);
      assert.strictEqual(wit.payload.status.name, "UNIMPLEMENTED");
    });

  const denied = await post("/spiffe/call", {
    address: SERVER_ADDRESS, service: "entry", method: "CountEntries",
    trustDomain: TRUST_DOMAIN, serverIdentityMode: "none" });
  check("an authorization refusal is a 200 as well — SPIRE distinguishes " +
    "\"authenticate\" from \"you may not\", and an api that reported both as " +
    "failures would throw that distinction away", function () {
      assert.strictEqual(denied.status, 200,
        "got " + denied.status + ": " +
        JSON.stringify(denied.payload).slice(0, 300));
      assert.strictEqual(denied.payload.ok, false);
      assert.ok(denied.payload.status.name === "UNAUTHENTICATED" ||
        denied.payload.status.name === "PERMISSION_DENIED",
        "expected an authorization refusal and got " +
        denied.payload.status.name);
    });

  const ok = await post("/spiffe/call", {
    address: WORKLOAD_ADDRESS, service: "workload", method: "FetchX509SVID" });
  check("a successful call reports the transport, the TLS state and how the " +
    "stream stopped, because \"one message\" and \"stopped waiting\" are " +
    "different facts about the same answer", function () {
      assert.strictEqual(ok.status, 200);
      assert.strictEqual(ok.payload.ok, true, ok.payload.error);
      assert.strictEqual(ok.payload.transport, "tcp");
      assert.strictEqual(ok.payload.tls, false,
        "the Workload API is plain, always: its specification says TLS MUST " +
        "NOT be required");
      assert.strictEqual(ok.payload.streaming.response, true);
      assert.ok(["messages", "timeout", "size", "end"]
        .indexOf(ok.payload.streaming.stopped) !== -1,
        "got " + ok.payload.streaming.stopped);
      assert.ok(ok.payload.messages.length >= 1);
    });

  check("and the request it SENT is echoed back, which is how the page shows " +
    "both halves of the exchange", function () {
      assert.ok(ok.payload.sent && typeof ok.payload.sent === "object");
      assert.strictEqual(ok.payload.method, "FetchX509SVID");
      assert.strictEqual(ok.payload.serviceLabel, "SpiffeWorkloadAPI");
    });

  // The identity mismatch, which is the negative that is neither a refusal nor
  // a network failure and would be mis-reported as either.
  const mismatch = await post("/spiffe/call", {
    address: SERVER_ADDRESS, service: "bundle", method: "GetBundle",
    trustDomain: TRUST_DOMAIN,
    serverId: "spiffe://" + TRUST_DOMAIN + "/definitely-not-the-server",
    trustBundle: await trustBundleFromWorkloadApi() });
  check("a server that answered and turned out to be somebody else is a 502 " +
    "flagged identityMismatch — the chain verified, so this is neither a " +
    "refusal by the api nor a server that was not there", function () {
      assert.strictEqual(mismatch.status, 502,
        "got " + mismatch.status + ": " +
        JSON.stringify(mismatch.payload).slice(0, 300));
      assert.strictEqual(mismatch.payload.identityMismatch, true);
      assert.ok(mismatch.payload.peer && mismatch.payload.peer.uris,
        "the answer must report WHICH identity turned up — a debugger whose " +
        "only answer to a mismatch is \"it failed\" cannot show that");
    });
  log.debug("Leaving testStatusIsTwoHundred().");
}

// The bundle the Workload API hands out beside every SVID, which is what the
// SPIRE Server API is verified against. Fetched rather than configured, for
// the reason the page does it: it is right there in the response.
async function trustBundleFromWorkloadApi() {
  log.debug("Entering trustBundleFromWorkloadApi().");
  const answer = await post("/spiffe/call", {
    address: WORKLOAD_ADDRESS, service: "workload", method: "FetchX509SVID" });
  const svid = ((answer.payload.messages || [])[0] || {}).svids;
  log.debug("Leaving trustBundleFromWorkloadApi().");
  return (svid && svid[0] && svid[0].bundle) || "";
}

// ---------------------------------------------------------------------------
// 5. POST /spiffe/bundle — the one SPIFFE surface that is ordinary HTTP.
// ---------------------------------------------------------------------------
async function testBundleEndpoint() {
  log.debug("Entering testBundleEndpoint().");
  const good = await post("/spiffe/bundle", { url: BUNDLE_URL });
  check("the bundle endpoint is fetched and DESCRIBED, not merely relayed — " +
    "the one defect that matters in a bundle reports no error anywhere else",
    function () {
      assert.strictEqual(good.status, 200,
        "got " + good.status + ": " +
        JSON.stringify(good.payload).slice(0, 200));
      assert.strictEqual(good.payload.httpStatus, 200);
      assert.ok(good.payload.report, "no report came back");
      assert.ok(good.payload.report.ok,
        good.payload.report.errors.join("; "));
      assert.ok(good.payload.report.counts["x509-svid"] >= 1);
      assert.ok(good.payload.body, "the raw document must come back too");
    });

  const notAUrl = await post("/spiffe/bundle", { url: "spiffe://example.org" });
  check("a bundle endpoint that is not an http(s) URL is a 400 — this is the " +
    "one surface of SPIFFE that IS plain HTTPS, which is why this endpoint " +
    "is an ordinary fetch and the other one is gRPC", function () {
      assert.strictEqual(notAUrl.status, 400);
      assert.ok(/http/i.test(notAUrl.payload.error));
    });

  const missing = await post("/spiffe/bundle",
    { url: STS_URL + "/definitely-not-a-bundle-endpoint" });
  check("a 404 from a bundle endpoint is an ANSWER — usually the answer that " +
    "the path is wrong — so it comes back as a 200 with the report saying " +
    "why the document is unusable", function () {
      assert.strictEqual(missing.status, 200,
        "got " + missing.status);
      assert.strictEqual(missing.payload.ok, false);
      assert.ok(missing.payload.report.errors.length >= 1,
        "the report has to say what was wrong with what came back");
    });
  log.debug("Leaving testBundleEndpoint().");
}

async function test() {
  log.debug("Entering test().");
  const limits = await gate();
  if (!limits) {
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  testLimits(limits);
  await testRefusals();
  await testNetworkFailure();

  // The sections below need something on the other end. Skipped with a named
  // reason rather than failing, because a stack without the mock's SPIFFE
  // surfaces is not a defect in this endpoint.
  let reachable = false;
  try {
    const probe = await post("/spiffe/call", { address: WORKLOAD_ADDRESS,
      service: "workload", method: "FetchX509Bundles" });
    reachable = probe.status === 200 && probe.payload.ok;
  } catch (e) {
    reachable = false;
  }
  if (!reachable) {
    log.warn("SKIPPING the sections that need a SPIFFE server: the api could " +
      "not reach a Workload API at " + WORKLOAD_ADDRESS + ". Note that " +
      "address is resolved by the API and not by this test, so localhost " +
      "there means the machine the api runs on.");
  } else {
    await testStatusIsTwoHundred();
    await testBundleEndpoint();
  }

  log.info(checks + " checks passed.");
  assert.ok(checks >= 13,
    "Only " + checks + " checks ran. A section has stopped being called.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_spiffe")
  .description("Drive the api's three SPIFFE endpoints over HTTP, and assert " +
    "the status-code rule that only exists here: a refusal by the api is a " +
    "400, a network failure is a 502, and a gRPC status from the far end — " +
    "PERMISSION_DENIED, UNAUTHENTICATED, UNIMPLEMENTED — is a 200 with the " +
    "code, because those are SPIFFE answering.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
    "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
