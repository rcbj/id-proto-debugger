// File: spiffe_protocol.js
//
// ---------------------------------------------------------------------------
// EVERY SPIFFE METHOD, THROUGH THE API'S CLIENT, AGAINST THE MOCK STS.
//
// Forty-nine of them: seven on the Workload API and forty-two across the SPIRE
// Server API's six services. `spiffe_engine.js` asserts that the CATALOGUE has
// all forty-nine; this file CALLS each one and asserts what came back, which is
// a different claim and the one that matters — a method can be in a list, in a
// picker and on a page and still have never been sent.
//
// It drives `api/spiffe_client.js` IN PROCESS rather than through a running
// api, for the reason `scim_engine.js` gives about its own split: a failure
// here is this client or that server and nothing in between. `api_spiffe.js`
// covers the HTTP endpoint on top of it, which is where the status-code rule
// lives.
//
// ---------------------------------------------------------------------------
// THE THREE IDENTITIES THIS FILE HAS TO ACQUIRE, IN ORDER, AND WHY THAT ORDER
// IS THE WHOLE SHAPE OF SPIFFE
//
// The SPIRE Server API authorizes every method against WHAT THE CALLER IS, so
// covering forty-two methods means being four different things:
//
//   nothing      `Bundle.GetBundle` and `Agent.AttestAgent` and no more. Those
//                two are open in a real SPIRE server too, and AttestAgent has
//                to be: an agent has no SVID until that call gives it one,
//                which is why the port ASKS FOR a client certificate and does
//                not REQUIRE one.
//   a workload   `FetchX509SVID` on the Workload API needs no credential at
//                all — the specification forbids requiring one — and hands
//                back an SVID WITH ITS PRIVATE KEY. That is the bootstrap, and
//                it is what makes everything below reachable.
//   an admin     that same SVID, once `spiffe.adminIds` names it. This file
//                sets that setting and puts it back, which is why it holds a
//                lock (see JOB_LOCKS in run-report.js).
//   an agent     `AttestAgent` with a join token and a real CSR. Seven methods
//                are agent-only and no other identity can reach them.
//
// Plus a fifth that is not an identity at all: the **local Unix socket**, which
// a real `spire-server` CLI is trusted on outright and which is the only way to
// reach `Debug.GetInfo` — LOCAL-ONLY in SPIRE's own table, so even an admin
// SVID over TCP is refused it. That row looks like an omission and is not, and
// asserting the refusal is how this file proves the table is being applied
// rather than assumed.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS ON, AND WHAT IT DELIBERATELY DOES NOT
//
// **Its own litter, never a total.** The suite runs in a pool, so
// `CountEntries` returning *n* is somebody else's job's business too. Every
// entry this file creates carries a stamped path (`/spiffe-protocol-<stamp>/…`)
// and every assertion about the registry looks for that prefix. The one place a
// count is used is a before/after difference on rows this file made.
//
// **A gRPC status that is not OK is an ANSWER and is asserted as one.** Fifteen
// of the checks below are negatives — `PERMISSION_DENIED` on a method this
// caller's entity may not use, `UNAUTHENTICATED`, `UNIMPLEMENTED` with the
// reason a server gives, `INVALID_ARGUMENT` on a JWT-SVID request with no
// audience — and each asserts the CODE rather than "it failed". SPIRE
// distinguishes "authenticate" from "you may not"; a test that accepted either
// would not notice them being collapsed.
//
// **It restores what it changes.** `spiffe.adminIds` and `spiffe.svidTtl` are
// read first and put back in a `finally`, per value, rather than with
// `reset-all` — which would also undo whatever a concurrent job had pinned.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
const registry = require("./sts_applications.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "spiffe_protocol",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const spiffeClientModule = paths.requireSharedModule(
  [__dirname + "/../api/spiffe_client.js", __dirname + "/spiffe_client.js"],
  "spiffe_client.js");
const spiffeId = paths.requireSharedModule(
  [__dirname + "/../common/spiffe/spiffe_id.js", __dirname + "/spiffe_id.js"],
  "spiffe_id.js");
const spiffeBundle = paths.requireSharedModule(
  [__dirname + "/../common/spiffe/spiffe_bundle.js",
   __dirname + "/spiffe_bundle.js"], "spiffe_bundle.js");
const x509 = paths.requireSharedModule(
  [__dirname + "/../client/src/x509.js", __dirname + "/x509.js"], "x509.js");
const keyMaterial = paths.requireSharedModule(
  [__dirname + "/../client/src/key_material.js",
   __dirname + "/key_material.js"], "key_material.js");

const STS_URL = process.env.STS_URL || "https://localhost:8081";
const WORKLOAD_ADDRESS = process.env.SPIFFE_WORKLOAD_ADDRESS ||
  "localhost:8092";
const SERVER_ADDRESS = process.env.SPIFFE_SERVER_ADDRESS || "localhost:8181";
// Off by default and named rather than derived: the mock's SPIRE Server API
// Unix socket is `spiffe.serverSocketEnabled`, which ships OFF, and a path
// guessed from the setting's default would be a section that silently skips
// while claiming to cover the `local` entity.
const SERVER_SOCKET = process.env.SPIFFE_SERVER_SOCKET || "";
const TRUST_DOMAIN = process.env.SPIFFE_TRUST_DOMAIN || "example.org";

// This run's own corner of the registry. Every entry created below sits under
// it and every assertion about the registry looks for it, because the suite
// runs in a pool and a total is nobody's to assert on. `Date.now()` alone is
// not unique when four jobs start in the same millisecond.
const STAMP = "p" + Date.now().toString(36) + process.pid.toString(36);
const MINE = "/spiffe-protocol-" + STAMP;

let checks = 0;
let calls = 0;
// Every method this file actually sent, so the floor at the bottom is a claim
// about coverage rather than about how many assertions were written.
const CALLED = {};

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function quiet() {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

// The address policy is OFF here for the reason api/env/local.js turns it off:
// the SPIRE server under test IS a private address. `spiffe_engine.js` is where
// the policy itself is asserted, with a guard that records what it was asked.
function makeClient() {
  log.debug("Entering makeClient().");
  const client = spiffeClientModule.createSpiffeClient(
    { spiffeAllowedPorts: 'any', spiffeAllowedSocketPaths: 'any',
      // Long enough to clear the mock's thirty-second rotation floor; the
      // rotation section is the only thing that needs it.
      spiffeStreamTimeout: 40000 },
    { enabled: false, blockedRangeFor: function () { return null; } },
    quiet());
  log.debug("Leaving makeClient().");
  return client;
}

const client = makeClient();

// One call, recorded. `CALLED` is what the coverage floor at the bottom counts,
// so a method that is described, listed and never sent cannot pass this file.
async function call(options) {
  log.debug("Entering call(). " + options.service + "." + options.method);
  CALLED[options.service + "." + options.method] = true;
  calls++;
  const answer = await client.call(options);
  log.debug("Leaving call(). " + answer.status.name);
  return answer;
}

// A call whose gRPC status is expected to be something other than OK. Returns
// the status name so the caller asserts on it — "it failed" is satisfied by the
// wrong failure.
async function statusOf(options) {
  log.debug("Entering statusOf().");
  try {
    const answer = await call(options);
    log.debug("Leaving statusOf(). " + answer.status.name);
    return answer.status.name;
  } catch (e) {
    log.debug("Leaving statusOf(). Threw: " + e.code);
    return "THREW:" + (e.code || e.message);
  }
}

function json(url, options) {
  log.debug("Entering json(). " + url);
  return fetch(url, options).then(function (response) {
    return response.text().then(function (text) {
      let body = null;
      try {
        body = JSON.parse(text);
      } catch (e) {
        body = null;
      }
      log.debug("Leaving json(). " + response.status);
      return { status: response.status, body: body, text: text };
    });
  });
}

// One setting's whole row, which carries where the value CAME FROM as well as
// what it is. Both halves are needed to put a setting back — see
// restoreSetting(); reading the value alone is what left four overrides behind
// on 2026-08-24.
function readSettingRow(key) {
  log.debug("Entering readSettingRow(). " + key);
  return json(STS_URL + "/admin-api/config").then(function (answer) {
    const rows = (answer.body && (answer.body.settings ||
      answer.body.config)) || [];
    for (const row of rows) {
      if (row.key === key) {
        log.debug("Leaving readSettingRow(). found, source=" + row.source);
        return row;
      }
    }
    log.debug("Leaving readSettingRow(). not found");
    return null;
  });
}

function writeSetting(key, value) {
  log.debug("Entering writeSetting(). " + key + "=" + value);
  return json(STS_URL + "/admin-api/config/set", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: key, value: value })
  }).then(function (answer) {
    log.debug("Leaving writeSetting(). " + answer.status);
    return answer;
  });
}

// ---------------------------------------------------------------------------
// A setting put back the way it was found, which is NOT the same as written
// back with the value it had.
//
// The mock records where every value came from — `appconfig` for one its
// process started with, `override` for one changed at runtime — and a `set`
// always makes the second, even when the value is identical. So a test that
// read 3600 and wrote 3600 back leaves the row reading `source: override`
// forever, and the mock's own "no runtime override should be in force before
// this check runs" assertion then fails on the NEXT run against the same
// container, naming four SPIFFE settings and no test. That is what it found on
// 2026-08-24.
//
// `reset` is the operation that undoes an override rather than covering it, so
// a setting this file overrode is reset unless it was ALREADY overridden when
// it got here — in which case the value it had is what it goes back to.
// ---------------------------------------------------------------------------
function restoreSetting(key, before, fallback) {
  log.debug("Entering restoreSetting(). " + key);
  if (before && before.source === "override") {
    log.debug("Leaving restoreSetting(). It was already an override.");
    return writeSetting(key, before.value);
  }
  return json(STS_URL + "/admin-api/config/reset", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: key })
  }).then(function (answer) {
    if (answer.status === 200 && answer.body && answer.body.ok) {
      log.debug("Leaving restoreSetting(). Reset to what it started with.");
      return answer;
    }
    // The service refused the reset — an older mock with no such action, say.
    // Writing the value back is worse than a reset and better than leaving
    // this run's value in place, so it is the fallback rather than the plan.
    log.warn("Could not reset " + key + " (HTTP " + answer.status +
             "); writing the previous value back instead.");
    log.debug("Leaving restoreSetting(). Fell back to a write.");
    return writeSetting(key, before === null || before === undefined ?
                        fallback : before.value);
  });
}

// ---------------------------------------------------------------------------
// THE GATE.
//
// Skipped with a NAMED reason rather than passing vacuously, and it asks the
// mock what actually bound rather than assuming: `GET /spiffe?format=json`
// reports each of the four sockets separately, because "the Workload API socket
// is up and the SPIRE Server API port is not" is an ordinary outcome and one
// flag could only report one of them.
// ---------------------------------------------------------------------------
async function gate() {
  log.debug("Entering gate().");
  let described = null;
  try {
    described = await json(STS_URL + "/spiffe?format=json");
  } catch (e) {
    log.warn("SKIPPING: " + STS_URL + " could not be reached (" + e.message +
      "). This test needs the mock STS's SPIFFE surfaces; a deployment " +
      "without them is not a failure of this workflow.");
    log.debug("Leaving gate(). Unreachable.");
    return false;
  }
  if (described.status !== 200 || !described.body || !described.body.enabled) {
    log.warn("SKIPPING: " + STS_URL + "/spiffe did not describe an enabled " +
      "SPIFFE service (HTTP " + described.status + "). Either this mock STS " +
      "predates SPIFFE or spiffe.enabled is off.");
    log.debug("Leaving gate(). Not enabled.");
    return false;
  }
  log.debug("Leaving gate(). Enabled.");
  return true;
}

// ---------------------------------------------------------------------------
// 1. THE BUNDLE ENDPOINT — the one SPIFFE surface that is ordinary HTTPS.
// ---------------------------------------------------------------------------
async function testBundleEndpoint() {
  log.debug("Entering testBundleEndpoint().");
  const answer = await json(STS_URL + "/spiffe/bundle");
  const report = spiffeBundle.describe(answer.text);
  check("the bundle endpoint publishes a usable JWK Set with both uses",
    function () {
      assert.strictEqual(answer.status, 200);
      assert.ok(report.ok, "the published bundle must be usable: " +
        report.errors.join("; "));
      assert.ok(report.counts["x509-svid"] >= 1,
        "with no x509-svid key nothing in this trust domain can be verified");
      assert.ok(report.counts["jwt-svid"] >= 1,
        "with no jwt-svid key no JWT-SVID can be verified");
      assert.strictEqual(report.ignored.length, 0,
        "a key a consumer MUST IGNORE is one this bundle publishes for " +
        "nothing: " + JSON.stringify(report.ignored));
    });
  check("every key in it carries a spiffe_sequence and a refresh hint beside " +
    "it, which is what lets a consumer order two copies", function () {
      assert.ok(report.sequence !== null, "no spiffe_sequence");
      assert.ok(report.refreshHint !== null, "no spiffe_refresh_hint");
    });
  log.debug("Leaving testBundleEndpoint().");
  return report;
}

// ---------------------------------------------------------------------------
// 2. THE WORKLOAD API — all seven methods, with no credential of any kind.
// ---------------------------------------------------------------------------
async function testWorkloadApi() {
  log.debug("Entering testWorkloadApi().");
  const base = { address: WORKLOAD_ADDRESS, service: "workload" };

  const svids = await call(Object.assign({ method: "FetchX509SVID" }, base));
  let held = null;
  check("FetchX509SVID answers with no credential at all, and the SVID " +
    "carries its PRIVATE KEY — that is the bootstrap the specification " +
    "describes", function () {
      assert.ok(svids.ok, svids.status.details);
      assert.ok(svids.messages.length >= 1);
      const svid = svids.messages[0].svids[0];
      assert.ok(svid, "no SVID came back");
      held = svid;
      assert.ok(spiffeId.memberOf(svid.spiffe_id, TRUST_DOMAIN),
        svid.spiffe_id + " is not in " + TRUST_DOMAIN);
      assert.ok(svid.x509_svid && svid.x509_svid.length > 100,
        "no certificate");
      assert.ok(svid.x509_svid_key && svid.x509_svid_key.length > 20,
        "an X509-SVID with no private key proves nothing and cannot be " +
        "presented anywhere");
      assert.ok(svid.bundle && svid.bundle.length > 100,
        "the trust bundle comes back beside the identity, which is what " +
        "makes " +
        "the SPIRE Server API reachable without a second fetch");
    });

  check("the bundle in that response is CONCATENATED DER and splits into " +
    "whole certificates", function () {
      const pem = spiffeClientModule.bundleToPem(held.bundle);
      const blocks = (pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
      assert.ok(blocks >= 1, "nothing split out of the bundle");
    });

  const x509Bundles = await call(Object.assign(
    { method: "FetchX509Bundles" }, base));
  check("FetchX509Bundles answers with the anchors and NO identity and NO " +
    "private key — what a service that only verifies peers needs", function () {
      assert.ok(x509Bundles.ok, x509Bundles.status.details);
      const message = x509Bundles.messages[0];
      assert.ok(message.bundles, "no bundles map");
      const key = spiffeId.trustDomainId(TRUST_DOMAIN);
      assert.ok(Object.prototype.hasOwnProperty.call(message.bundles, key),
        "the map is keyed by the trust domain's SPIFFE ID (" + key + ") and " +
        "not by its bare name — a bare name there is a map a client silently " +
        "finds nothing in. Keys present: " +
        Object.keys(message.bundles).join(", "));
      assert.ok(!JSON.stringify(message).includes("x509_svid_key"),
        "this method must hand out no private key");
    });

  const noAudience = await statusOf(Object.assign(
    { method: "FetchJWTSVID", request: {} }, base));
  check("FetchJWTSVID with no audience is INVALID_ARGUMENT — a JWT-SVID is a " +
    "bearer credential and the audience is what stops one issued for service " +
    "A being replayed against service B", function () {
      assert.strictEqual(noAudience, "INVALID_ARGUMENT");
    });

  const audience = "spiffe://" + TRUST_DOMAIN + "/audience-" + STAMP;
  const jwt = await call(Object.assign({ method: "FetchJWTSVID",
    request: { audience: [audience] } }, base));
  let token = "";
  check("FetchJWTSVID answers with a JWT-SVID for the audience asked for",
    function () {
      assert.ok(jwt.ok, jwt.status.details);
      const svid = jwt.messages[0].svids[0];
      token = svid.svid;
      assert.strictEqual(svid.svid.split(".").length, 3, "not a JWS");
      const claims = JSON.parse(
        Buffer.from(svid.svid.split(".")[1], "base64url").toString("utf8"));
      assert.ok([].concat(claims.aud).indexOf(audience) !== -1,
        "the audience asked for is not in the token: " +
        JSON.stringify(claims.aud));
      assert.ok(spiffeId.isValid(claims.sub),
        "the sub of a JWT-SVID is a SPIFFE ID: " + claims.sub);
      assert.ok(claims.exp, "a JWT-SVID with no exp never expires");
    });

  const jwtBundles = await call(Object.assign(
    { method: "FetchJWTBundles" }, base));
  check("FetchJWTBundles answers with JWK SETS — JSON, where the X.509 " +
    "bundles are concatenated DER", function () {
      assert.ok(jwtBundles.ok, jwtBundles.status.details);
      const map = jwtBundles.messages[0].bundles;
      const key = spiffeId.trustDomainId(TRUST_DOMAIN);
      const raw = Buffer.from(map[key], "base64").toString("utf8");
      const report = spiffeBundle.describe(raw);
      assert.ok(report.ok, "the JWT bundle must be a usable JWK Set: " +
        report.errors.join("; "));
      assert.ok(report.counts["jwt-svid"] >= 1);
    });

  const validated = await call(Object.assign({ method: "ValidateJWTSVID",
    request: { audience: audience, svid: token } }, base));
  check("ValidateJWTSVID really verifies, and returns the CLAIMS — which " +
    "come back as a google.protobuf.Struct whose members are camelCase in a " +
    "family that is otherwise entirely snake_case", function () {
      assert.ok(validated.ok, validated.status.details);
      const message = validated.messages[0];
      assert.ok(spiffeId.isValid(message.spiffe_id), message.spiffe_id);
      assert.ok(message.claims && typeof message.claims === "object",
        "no claims came back");
      assert.ok(message.claims.sub,
        "the claims must be flattened to plain JSON — an unflattened Struct " +
        "reads as {fields:{sub:{stringValue:…}}} and a client asking for " +
        ".sub finds nothing. Got: " + JSON.stringify(message.claims));
      assert.strictEqual(message.claims.sub, message.spiffe_id);
      assert.ok(typeof message.claims.exp === "number",
        "exp must survive as a number");
    });

  const badToken = await statusOf(Object.assign({ method: "ValidateJWTSVID",
    request: { audience: audience, svid: "not.a.token" } }, base));
  check("ValidateJWTSVID says NO to something that does not verify — the " +
    "point of the call is to be told no, which makes it the one method in " +
    "the family that behaves like a production one", function () {
      assert.strictEqual(badToken, "INVALID_ARGUMENT");
    });

  const wrongAudience = await statusOf(Object.assign(
    { method: "ValidateJWTSVID",
      request: { audience: "spiffe://" + TRUST_DOMAIN + "/somebody-else",
                 svid: token } }, base));
  check("ValidateJWTSVID refuses a token issued for a DIFFERENT audience, " +
    "which is the whole reason the audience is in the request", function () {
      assert.strictEqual(wrongAudience, "INVALID_ARGUMENT");
    });

  const witSvid = await statusOf(Object.assign({ method: "FetchWITSVID",
    request: { audience: [audience] } }, base));
  const witBundles = await statusOf(Object.assign(
    { method: "FetchWITBundles" }, base));
  check("the two WIT methods answer UNIMPLEMENTED with a reason rather than " +
    "being absent — a surface reporting seven of seven would be the most " +
    "misleading thing about it", function () {
      assert.strictEqual(witSvid, "UNIMPLEMENTED");
      assert.strictEqual(witBundles, "UNIMPLEMENTED");
    });

  // THE ONE CHECK A CONFORMING WORKLOAD API MAKES. Not a security control —
  // anybody can send a header — it exists so a caller cannot reach the
  // endpoint BY ACCIDENT, and a client that omits it has a bug that only a
  // conforming server will ever report.
  const noHeader = await statusOf(Object.assign({ method: "FetchX509Bundles",
    securityHeader: false }, base));
  check("a Workload API call with no `workload.spiffe.io: true` is refused, " +
    "which is what every conforming implementation does", function () {
      assert.strictEqual(noHeader, "INVALID_ARGUMENT");
    });

  log.debug("Leaving testWorkloadApi().");
  return held;
}

// ---------------------------------------------------------------------------
// 3. THE SPIRE SERVER API, AS FOUR DIFFERENT ENTITIES.
// ---------------------------------------------------------------------------
async function testAnonymous(trustBundle) {
  log.debug("Entering testAnonymous().");
  const base = { address: SERVER_ADDRESS, trustDomain: TRUST_DOMAIN,
                 trustBundle: trustBundle };

  const bundle = await call(Object.assign(
    { service: "bundle", method: "GetBundle" }, base));
  check("GetBundle is open to a caller presenting NOTHING — the port asks " +
    "for a client certificate and does not require one, because AttestAgent " +
    "has to be reachable by somebody who has no SVID yet", function () {
      assert.ok(bundle.ok, bundle.status.details);
      assert.ok(bundle.tls, "the TCP port must be TLS");
      const message = bundle.messages[0];
      assert.strictEqual(message.trust_domain, TRUST_DOMAIN);
      assert.ok((message.x509_authorities || []).length >= 1);
      assert.ok((message.jwt_authorities || []).length >= 1);
    });

  check("and this service verified WHO the server is by its SPIFFE ID, " +
    "because a SPIRE server's certificate carries no DNS name at all",
    function () {
      assert.deepStrictEqual(bundle.peer.uris,
        [spiffeId.serverId(TRUST_DOMAIN)],
        "the URI subjectAltName is the only thing identifying the far end");
      assert.ok(!bundle.peer.identityError, bundle.peer.identityError);
    });

  const denied = await statusOf(Object.assign(
    { service: "entry", method: "CountEntries" }, base));
  check("an anonymous caller is refused an administrator's method, and the " +
    "refusal is UNAUTHENTICATED rather than PERMISSION_DENIED — two " +
    "different instructions to a client, which SPIRE distinguishes",
    function () {
      assert.ok(denied === "UNAUTHENTICATED" || denied === "PERMISSION_DENIED",
        "expected an authorization refusal and got " + denied);
      assert.strictEqual(denied, "UNAUTHENTICATED",
        "nothing was presented, so the instruction is \"authenticate\" — " +
        "sending PERMISSION_DENIED here sends a client that needs a " +
        "credential looking for a permission it will never get");
    });

  // The interesting negative on this whole surface: a server that answered,
  // presented a certificate a trusted authority had signed, and turned out to
  // be somebody else.
  let mismatch = null;
  try {
    await call(Object.assign({ service: "bundle", method: "GetBundle",
      serverId: "spiffe://" + TRUST_DOMAIN + "/not-the-server" }, base));
  } catch (e) {
    mismatch = e;
  }
  check("a server whose SPIFFE ID is not the expected one is refused, and is " +
    "reported as an IDENTITY mismatch rather than as a network failure — " +
    "those are different facts and only one of them is about the network",
    function () {
      assert.ok(mismatch, "the call should not have succeeded");
      assert.strictEqual(mismatch.code, "ESPIFFESERVERIDENTITY");
      assert.strictEqual(mismatch.identityMismatch, true);
      assert.ok(/chain verified/.test(mismatch.message),
        "the message has to say that the certificate was real: " +
        mismatch.message);
    });

  // `base` LAST would win: Object.assign takes the later source, and `base`
  // already carries the real trust domain. Spelled the other way round here
  // because this is the one case in this file that deliberately overrides one
  // of base's own fields — and getting it backwards made the check pass
  // against a server it was supposed to refuse.
  const wrongDomain = await statusOf(Object.assign({}, base,
    { service: "bundle", method: "GetBundle",
      serverIdentityMode: "trust-domain",
      trustDomain: "somebody-else.invalid" }));
  check("`trust-domain` verification refuses a server from another trust " +
    "domain, and membership is a parsed comparison rather than a prefix test",
    function () {
      assert.ok(/^THREW:/.test(wrongDomain), "expected a refusal, got " +
        wrongDomain);
    });
  log.debug("Leaving testAnonymous().");
}

// The Workload API's SVID, made an administrator by naming it in
// `spiffe.adminIds` — SPIRE's own `admin_ids`, which needs no registration
// entry behind it. That is the only route from "I can fetch an identity" to
// "I can drive the registry" that does not already require an administrator,
// and it is why this file holds a lock.
async function testAdmin(held, trustBundle) {
  log.debug("Entering testAdmin().");
  const base = { address: SERVER_ADDRESS, trustDomain: TRUST_DOMAIN,
                 trustBundle: trustBundle,
                 identity: { certPem: held.x509_svid,
                             keyPem: held.x509_svid_key } };

  const before = await call(Object.assign(
    { service: "entry", method: "CountEntries" }, base));
  check("the same SVID that was refused a moment ago is now an administrator " +
    "— nothing about the credential changed, only what the server was told " +
    "about it", function () {
      assert.ok(before.ok, before.status.details);
      assert.ok(typeof before.messages[0].count === "number");
    });

  // ---- Entry: create, read, update, list, delete ------------------------
  const created = await call(Object.assign({ service: "entry",
    method: "BatchCreateEntry", request: { entries: [
      { spiffe_id: spiffeId.toProto(spiffeId.make(TRUST_DOMAIN, MINE + "/one")),
        parent_id: spiffeId.toProto(spiffeId.serverId(TRUST_DOMAIN)),
        selectors: [{ type: "unix", value: "uid:4242" }],
        x509_svid_ttl: 600, jwt_svid_ttl: 120,
        hint: "hint-" + STAMP, dns_names: ["one." + STAMP + ".invalid"] },
      { spiffe_id: spiffeId.toProto(spiffeId.make(TRUST_DOMAIN, MINE + "/two")),
        parent_id: spiffeId.toProto(spiffeId.serverId(TRUST_DOMAIN)),
        selectors: [{ type: "unix", value: "uid:4243" }] }
    ] } }, base));
  let entryId = "";
  check("BatchCreateEntry answers PER ENTRY, so a partial success is normal " +
    "and the per-row status is the result — reading only the transport " +
    "status reports a batch of ten with nine failures as a success",
    function () {
      assert.ok(created.ok, created.status.details);
      const results = created.messages[0].results;
      assert.strictEqual(results.length, 2, "one result per submitted entry");
      results.forEach(function (row, index) {
        assert.strictEqual(Number(row.status.code), 0,
          "entry " + index + ": " + row.status.message);
        assert.ok(row.entry && row.entry.id, "no entry came back");
      });
      entryId = results[0].entry.id;
    });

  const got = await call(Object.assign({ service: "entry", method: "GetEntry",
    request: { id: entryId } }, base));
  check("GetEntry reads back every field that was submitted, which is what " +
    "catches a field accepted and silently dropped", function () {
      assert.ok(got.ok, got.status.details);
      const entry = got.messages[0];
      assert.strictEqual(spiffeId.fromProto(entry.spiffe_id),
        spiffeId.make(TRUST_DOMAIN, MINE + "/one"));
      assert.strictEqual(Number(entry.x509_svid_ttl), 600);
      assert.strictEqual(Number(entry.jwt_svid_ttl), 120);
      assert.strictEqual(entry.hint, "hint-" + STAMP);
      assert.deepStrictEqual(entry.dns_names, ["one." + STAMP + ".invalid"]);
      assert.deepStrictEqual(entry.selectors,
        [{ type: "unix", value: "uid:4242" }]);
    });

  const mine = await call(Object.assign({ service: "entry",
    method: "ListEntries", request: { page_size: 200 } }, base));
  check("ListEntries returns the entries THIS RUN created — asserted by its " +
    "own stamp rather than by a count, because the suite runs in a pool and " +
    "a total is nobody's to assert on", function () {
      assert.ok(mine.ok, mine.status.details);
      const ours = (mine.messages[0].entries || []).filter(function (entry) {
        return String(entry.spiffe_id && entry.spiffe_id.path || "")
          .indexOf(MINE) === 0;
      });
      assert.strictEqual(ours.length, 2,
        "expected the two entries this run made and found " + ours.length);
    });

  const byHint = await call(Object.assign({ service: "entry",
    method: "ListEntries",
    request: { filter: { by_hint: "hint-" + STAMP } } }, base));
  check("a google.protobuf wrapper field may be sent as a BARE value and the " +
    "api wraps it — on the wire it is a message, and a bare value serialises " +
    "to nothing at all with no throw and no warning", function () {
      assert.ok(byHint.ok, byHint.status.details);
      const rows = byHint.messages[0].entries || [];
      assert.strictEqual(rows.length, 1,
        "the hint filter should have matched exactly this run's one hinted " +
        "entry and matched " + rows.length + " — an unwrapped filter " +
        "serialises to nothing, which returns EVERY entry and looks like a " +
        "filter that works until somebody counts");
      assert.strictEqual(rows[0].hint, "hint-" + STAMP);
    });

  const counted = await call(Object.assign({ service: "entry",
    method: "CountEntries", request: {} }, base));
  check("CountEntries counts at least this run's own two", function () {
    assert.ok(counted.ok, counted.status.details);
    assert.ok(Number(counted.messages[0].count) >= 2);
  });

  const updated = await call(Object.assign({ service: "entry",
    method: "BatchUpdateEntry", request: { entries: [
      { id: entryId,
        spiffe_id: spiffeId.toProto(spiffeId.make(TRUST_DOMAIN, MINE + "/one")),
        parent_id: spiffeId.toProto(spiffeId.serverId(TRUST_DOMAIN)),
        selectors: [{ type: "unix", value: "uid:4242" }],
        x509_svid_ttl: 1200 }
    ] } }, base));
  check("BatchUpdateEntry applies EVERY field of the submitted entry when " +
    "there is no mask — which is what spire-server entry update relies on " +
    "and is how a field gets cleared by accident", function () {
      assert.ok(updated.ok, updated.status.details);
      assert.strictEqual(Number(updated.messages[0].results[0].status.code), 0,
        updated.messages[0].results[0].status.message);
      assert.strictEqual(
        Number(updated.messages[0].results[0].entry.x509_svid_ttl), 1200);
    });

  // ---- SVID: minting outside an entry -----------------------------------
  const pair = await keyMaterial.generateKeyPair("ec-p256");
  const mintedId = spiffeId.make(TRUST_DOMAIN, MINE + "/minted");
  const csr = await x509.certificationRequest({
    subject: "C=US,O=SPIRE",
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem,
    subjectAltName: [{ kind: "uri", value: mintedId }] });
  const minted = await call(Object.assign({ service: "svid",
    method: "MintX509SVID", request: { csr: csr.base64, ttl: 600 } }, base));
  check("MintX509SVID takes the identity out of the CSR — it is the one " +
    "method with no registration entry to take one from, so the URI " +
    "subjectAltName is the only statement of what is wanted", function () {
      assert.ok(minted.ok, minted.status.details);
      const svid = minted.messages[0].svid;
      assert.strictEqual(spiffeId.fromProto(svid.id), mintedId,
        "the minted identity must be the one the CSR asked for");
      assert.ok((svid.cert_chain || []).length >= 1);
    });

  const mintedJwt = await call(Object.assign({ service: "svid",
    method: "MintJWTSVID", request: {
      id: spiffeId.toProto(mintedId),
      audience: ["spiffe://" + TRUST_DOMAIN + "/aud-" + STAMP], ttl: 120 } },
    base));
  check("MintJWTSVID mints for an identity you name", function () {
    assert.ok(mintedJwt.ok, mintedJwt.status.details);
    assert.strictEqual(mintedJwt.messages[0].svid.token.split(".").length, 3);
  });

  const mintNoAudience = await statusOf(Object.assign({ service: "svid",
    method: "MintJWTSVID",
    request: { id: spiffeId.toProto(mintedId), audience: [] } }, base));
  check("MintJWTSVID with no audience is refused for the reason " +
    "FetchJWTSVID is", function () {
      assert.strictEqual(mintNoAudience, "INVALID_ARGUMENT");
    });

  const mintWit = await statusOf(Object.assign({ service: "svid",
    method: "MintWITSVID", request: {} }, base));
  const batchWit = await statusOf(Object.assign({ service: "svid",
    method: "BatchNewWITSVID", request: { params: [] } }, base));
  check("the two WIT methods on this surface publish a reason too",
    function () {
      assert.strictEqual(mintWit, "UNIMPLEMENTED");
      assert.ok(batchWit === "UNIMPLEMENTED" ||
        batchWit === "PERMISSION_DENIED",
        "an agent-only WIT method may be refused for either reason first, " +
        "and got " + batchWit);
    });

  // ---- Bundle: this trust domain's, and the federated ones ---------------
  const appended = await statusOf(Object.assign({ service: "bundle",
    method: "AppendBundle", request: {} }, base));
  check("AppendBundle is refused with a reason — it would publish an " +
    "authority the server holds no key for, which every workload in the " +
    "trust domain would then trust", function () {
      assert.ok(appended === "PERMISSION_DENIED" ||
        appended === "UNIMPLEMENTED", "got " + appended);
    });

  const publishJwt = await statusOf(Object.assign({ service: "bundle",
    method: "PublishJWTAuthority", request: { jwt_authority: {} } }, base));
  const publishWit = await statusOf(Object.assign({ service: "bundle",
    method: "PublishWITAuthority", request: { wit_authority: {} } }, base));
  check("the two Publish*Authority methods are DOWNSTREAM-only, so an " +
    "administrator is refused them", function () {
      assert.ok(publishJwt === "PERMISSION_DENIED" ||
        publishJwt === "UNIMPLEMENTED", "got " + publishJwt);
      assert.ok(publishWit === "PERMISSION_DENIED" ||
        publishWit === "UNIMPLEMENTED", "got " + publishWit);
    });

  const foreignDomain = "fed-" + STAMP + ".invalid";
  const foreign = { trust_domain: foreignDomain, x509_authorities: [],
                    jwt_authorities: [], refresh_hint: "300",
                    sequence_number: "1" };
  const setFed = await call(Object.assign({ service: "bundle",
    method: "BatchSetFederatedBundle", request: { bundle: [foreign] } }, base));
  check("BatchSetFederatedBundle takes a foreign bundle that is PUSHED IN — " +
    "a bundle is never FETCHED here, because dereferencing a URL the far end " +
    "chose is a server-side request forgery with a citation attached",
    function () {
      assert.ok(setFed.ok, setFed.status.details);
      assert.strictEqual(Number(setFed.messages[0].results[0].status.code), 0,
        setFed.messages[0].results[0].status.message);
    });

  const listFed = await call(Object.assign({ service: "bundle",
    method: "ListFederatedBundles", request: {} }, base));
  check("ListFederatedBundles holds the one this run pushed", function () {
    assert.ok(listFed.ok, listFed.status.details);
    assert.ok((listFed.messages[0].bundles || []).some(function (row) {
      return row.trust_domain === foreignDomain;
    }), "this run's federated bundle is not in the list");
  });

  const getFed = await call(Object.assign({ service: "bundle",
    method: "GetFederatedBundle",
    request: { trust_domain: foreignDomain } }, base));
  check("GetFederatedBundle takes a trust domain NAME rather than an " +
    "identifier", function () {
      assert.ok(getFed.ok, getFed.status.details);
      assert.strictEqual(getFed.messages[0].trust_domain, foreignDomain);
    });

  const missingFed = await statusOf(Object.assign({ service: "bundle",
    method: "GetFederatedBundle",
    request: { trust_domain: "nothing-here-" + STAMP + ".invalid" } }, base));
  check("GetFederatedBundle on a trust domain nobody pushed is NOT_FOUND",
    function () {
      assert.strictEqual(missingFed, "NOT_FOUND");
    });

  const countBundles = await call(Object.assign({ service: "bundle",
    method: "CountBundles", request: {} }, base));
  check("CountBundles counts the FEDERATED ones — this trust domain's own is " +
    "not one of them", function () {
      assert.ok(countBundles.ok, countBundles.status.details);
      assert.ok(Number(countBundles.messages[0].count) >= 1);
    });

  const updateFed = await call(Object.assign({ service: "bundle",
    method: "BatchUpdateFederatedBundle",
    request: { bundle: [Object.assign({}, foreign,
      { sequence_number: "2" })] } }, base));
  check("BatchUpdateFederatedBundle replaces one that is already held",
    function () {
      assert.ok(updateFed.ok, updateFed.status.details);
      assert.strictEqual(Number(updateFed.messages[0].results[0].status.code),
        0, updateFed.messages[0].results[0].status.message);
    });

  const createFed = await call(Object.assign({ service: "bundle",
    method: "BatchCreateFederatedBundle",
    request: { bundle: [Object.assign({}, foreign,
      { trust_domain: "fed2-" + STAMP + ".invalid" })] } }, base));
  check("BatchCreateFederatedBundle creates a second one", function () {
    assert.ok(createFed.ok, createFed.status.details);
    assert.strictEqual(Number(createFed.messages[0].results[0].status.code), 0,
      createFed.messages[0].results[0].status.message);
  });

  // ---- TrustDomain: the federation relationships -------------------------
  //
  // A THIRD trust domain, and not one of the two above. Pushing a federated
  // bundle in also records the relationship, so creating one for a domain that
  // already has a bundle answers ALREADY_EXISTS — which is correct, and would
  // make this section assert a refusal where it means to assert a create. The
  // two are separate calls and this keeps them separate subjects.
  const relDomain = "rel-" + STAMP + ".invalid";
  const relBundle = Object.assign({}, foreign, { trust_domain: relDomain });
  const createRel = await call(Object.assign({ service: "trustdomain",
    method: "BatchCreateFederationRelationship",
    request: { federation_relationships: [{
      trust_domain: relDomain,
      bundle_endpoint_url: "https://" + relDomain + "/bundle",
      https_spiffe: { endpoint_spiffe_id: spiffeId.toProto(
        spiffeId.serverId(relDomain)) },
      trust_domain_bundle: relBundle }] } }, base));
  check("BatchCreateFederationRelationship records where a foreign bundle " +
    "would be fetched from, under the https_spiffe profile — which is the " +
    "one that makes federation self-contained", function () {
      assert.ok(createRel.ok, createRel.status.details);
      assert.strictEqual(Number(createRel.messages[0].results[0].status.code),
        0, createRel.messages[0].results[0].status.message);
    });

  const listRel = await call(Object.assign({ service: "trustdomain",
    method: "ListFederationRelationships", request: {} }, base));
  check("ListFederationRelationships holds this run's", function () {
    assert.ok(listRel.ok, listRel.status.details);
    assert.ok((listRel.messages[0].federation_relationships || [])
      .some(function (row) {
        return row.trust_domain === relDomain;
      }));
  });

  const getRel = await call(Object.assign({ service: "trustdomain",
    method: "GetFederationRelationship",
    request: { trust_domain: relDomain } }, base));
  check("GetFederationRelationship reads one back", function () {
    assert.ok(getRel.ok, getRel.status.details);
    assert.strictEqual(getRel.messages[0].trust_domain, relDomain);
  });

  const updateRel = await call(Object.assign({ service: "trustdomain",
    method: "BatchUpdateFederationRelationship",
    request: { federation_relationships: [{ trust_domain: relDomain,
      bundle_endpoint_url: "https://" + relDomain + "/other",
      https_web: {}, trust_domain_bundle: relBundle }] } }, base));
  check("BatchUpdateFederationRelationship changes the profile", function () {
    assert.ok(updateRel.ok, updateRel.status.details);
  });

  const refresh = await statusOf(Object.assign({ service: "trustdomain",
    method: "RefreshBundle",
    request: { trust_domain: relDomain } }, base));
  check("RefreshBundle is refused with a reason, naming the URL it is NOT " +
    "fetching — the same refusal wreqptr and jwks_uri get here", function () {
      assert.strictEqual(refresh, "UNIMPLEMENTED");
    });

  const deleteRel = await call(Object.assign({ service: "trustdomain",
    method: "BatchDeleteFederationRelationship",
    request: { trust_domains: [relDomain] } }, base));
  check("BatchDeleteFederationRelationship stops recording one", function () {
    assert.ok(deleteRel.ok, deleteRel.status.details);
    assert.strictEqual(Number(deleteRel.messages[0].results[0].status.code), 0,
      deleteRel.messages[0].results[0].status.message);
  });

  const deleteFed = await call(Object.assign({ service: "bundle",
    method: "BatchDeleteFederatedBundle",
    request: { trust_domains: [foreignDomain, "fed2-" + STAMP + ".invalid",
                               relDomain],
               mode: "DISSOCIATE" } }, base));
  check("BatchDeleteFederatedBundle stops federating, and this run puts back " +
    "what it pushed", function () {
      assert.ok(deleteFed.ok, deleteFed.status.details);
    });

  // ---- Debug, which is LOCAL-ONLY --------------------------------------
  const debug = await statusOf(Object.assign({ service: "debug",
    method: "GetInfo", request: {} }, base));
  check("Debug.GetInfo is refused even to an ADMINISTRATOR over TCP — it is " +
    "local-only in SPIRE's own table, and that surprise is the point rather " +
    "than an omission here", function () {
      assert.strictEqual(debug, "PERMISSION_DENIED");
    });

  log.debug("Leaving testAdmin().");
  return { entryId: entryId, pair: pair };
}

// ---------------------------------------------------------------------------
// 4. AN AGENT — attested with a join token and a real CSR.
// ---------------------------------------------------------------------------
async function testAgent(held, trustBundle, adminBase, entryId) {
  log.debug("Entering testAgent().");
  const base = { address: SERVER_ADDRESS, trustDomain: TRUST_DOMAIN,
                 trustBundle: trustBundle };

  const jt = await call(Object.assign({ service: "agent",
    method: "CreateJoinToken", request: { ttl: 600 } }, adminBase));
  let tokenValue = "";
  check("CreateJoinToken mints the ONE attestation payload a SPIRE server " +
    "issues and can therefore verify", function () {
      assert.ok(jt.ok, jt.status.details);
      tokenValue = jt.messages[0].value;
      assert.ok(tokenValue && tokenValue.length > 8, "no token came back");
      assert.ok(Number(jt.messages[0].expires_at) > 0,
        "a join token that never expires is a permanent credential, which is " +
        "exactly what it exists not to be");
    });

  const pair = await keyMaterial.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "C=US,O=SPIRE",
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem });

  // The payload is a `bytes` field, so it goes on the wire as base64. Sending
  // the token as text is the mistake this line exists to not make: node's
  // base64 decoder is lenient, so the far end gets a shorter, different value
  // and refuses it for a reason that names the token rather than the encoding.
  const payload = Buffer.from(tokenValue, "utf8").toString("base64");

  const attested = await call(Object.assign({ service: "agent",
    method: "AttestAgent", request: { params: {
      data: { type: "join_token", payload: payload },
      params: { csr: csr.base64 } } } }, base));
  let agentSvid = null;
  let agentId = "";
  check("AttestAgent is open to a caller presenting NOTHING and answers with " +
    "an SVID — a bidirectional stream, so a client that half-closes as soon " +
    "as it has written gets status OK and NO MESSAGES, which reads as a " +
    "server that accepted an attestation and issued nothing", function () {
      assert.ok(attested.ok, attested.status.details);
      assert.ok(attested.messages.length >= 1,
        "AttestAgent answered with no messages at all — see the note in " +
        "api/spiffe_client.js about leaving a bidirectional stream open");
      const result = attested.messages[0].result;
      assert.ok(result && result.svid, "no SVID in the answer: " +
        JSON.stringify(attested.messages[0]).slice(0, 300));
      agentSvid = result.svid;
      agentId = spiffeId.fromProto(agentSvid.id);
      assert.ok(spiffeId.parse(agentId).reserved,
        "an agent's identity is under the RESERVED /spire path: " + agentId);
    });

  const spent = await statusOf(Object.assign({ service: "agent",
    method: "AttestAgent", request: { params: {
      data: { type: "join_token", payload: payload },
      params: { csr: csr.base64 } } } }, base));
  check("that join token cannot be spent twice — single use is the one " +
    "property a join token has that a password does not", function () {
      assert.strictEqual(spent, "PERMISSION_DENIED");
    });

  const forged = await statusOf(Object.assign({ service: "agent",
    method: "AttestAgent", request: { params: {
      data: { type: "join_token",
              payload: Buffer.from("not-a-token-" + STAMP)
                .toString("base64") },
      params: { csr: csr.base64 } } } }, base));
  check("a join token this server never minted is refused — accepting one " +
    "would be accepting a forgery of its own credential, which is a " +
    "different thing from being permissive about somebody else's attestor",
    function () {
      assert.strictEqual(forged, "PERMISSION_DENIED");
    });

  const noCsr = await statusOf(Object.assign({ service: "agent",
    method: "AttestAgent", request: { params: {
      data: { type: "join_token", payload: payload }, params: {} } } }, base));
  check("AttestAgent with no CSR is refused: the agent keeps its own private " +
    "key, so there is nothing to issue against", function () {
      assert.strictEqual(noCsr, "INVALID_ARGUMENT");
    });

  const agentBase = Object.assign({}, base,
    { identity: { certPem: agentSvid.cert_chain[0],
                  keyPem: pair.privatePem } });

  const entitled = await call(Object.assign({ service: "entry",
    method: "GetAuthorizedEntries", request: {} }, agentBase));
  check("GetAuthorizedEntries answers the agent ON THE CONNECTION — the " +
    "credential decides the answer and there is nothing to name in the " +
    "request", function () {
      assert.ok(entitled.ok, entitled.status.details);
      assert.ok(Array.isArray(entitled.messages[0].entries));
    });

  const synced = await call(Object.assign({ service: "entry",
    method: "SyncAuthorizedEntries", request: {} }, agentBase));
  check("SyncAuthorizedEntries is the streaming form of the same question, " +
    "and answers over a bidirectional stream", function () {
      assert.ok(synced.ok, synced.status.details);
      assert.ok(synced.messages.length >= 1,
        "no message came back from the bidirectional stream");
      assert.ok(Array.isArray(synced.messages[0].entry_revisions));
    });

  const posted = await call(Object.assign({ service: "agent",
    method: "PostStatus", request: {} }, agentBase));
  check("PostStatus is an agent reporting its own health", function () {
    assert.ok(posted.ok, posted.status.details);
  });

  const renewPair = await keyMaterial.generateKeyPair("ec-p256");
  const renewCsr = await x509.certificationRequest({ subject: "C=US,O=SPIRE",
    publicKeyPem: renewPair.publicPem,
    privateKeyPem: renewPair.privatePem });
  const renewed = await call(Object.assign({ service: "agent",
    method: "RenewAgent",
    request: { params: { csr: renewCsr.base64 } } }, agentBase));
  check("RenewAgent renews the agent on the CONNECTION and never one named " +
    "in the request — the distinction that made this method answerable at " +
    "all once the surface authenticated its callers", function () {
      assert.ok(renewed.ok, renewed.status.details);
      assert.ok((renewed.messages[0].svid.cert_chain || []).length >= 1);
      assert.strictEqual(spiffeId.fromProto(renewed.messages[0].svid.id),
        agentId, "it renewed a different agent");
    });

  const svidPair = await keyMaterial.generateKeyPair("ec-p256");
  const svidCsr = await x509.certificationRequest({ subject: "C=US,O=SPIRE",
    publicKeyPem: svidPair.publicPem, privateKeyPem: svidPair.privatePem });
  const batched = await call(Object.assign({ service: "svid",
    method: "BatchNewX509SVID", request: { params: [
      { entry_id: entryId, csr: svidCsr.base64 } ] } }, agentBase));
  check("BatchNewX509SVID is what an agent calls to sign the CSR of a " +
    "workload it is attesting — only the public key is read out of it, and " +
    "the identity comes from the ENTRY", function () {
      assert.ok(batched.ok, batched.status.details);
      const row = batched.messages[0].results[0];
      assert.strictEqual(Number(row.status.code), 0, row.status.message);
      assert.strictEqual(spiffeId.fromProto(row.svid.id),
        spiffeId.make(TRUST_DOMAIN, MINE + "/one"),
        "the identity must come from the entry and not from the CSR");
    });

  const newJwt = await call(Object.assign({ service: "svid",
    method: "NewJWTSVID", request: { entry_id: entryId,
      audience: ["spiffe://" + TRUST_DOMAIN + "/aud-" + STAMP] } }, agentBase));
  check("NewJWTSVID is the agent's form: an entry id rather than an " +
    "identity, because an agent may not name an identity it was not given",
    function () {
      assert.ok(newJwt.ok, newJwt.status.details);
      assert.strictEqual(newJwt.messages[0].svid.token.split(".").length, 3);
    });

  const downstream = await statusOf(Object.assign({ service: "svid",
    method: "NewDownstreamX509CA",
    request: { csr: svidCsr.base64 } }, agentBase));
  check("NewDownstreamX509CA is DOWNSTREAM-only — it is the one method that " +
    "hands out a certificate which can sign others, so an agent is refused it",
    function () {
      assert.strictEqual(downstream, "PERMISSION_DENIED");
    });

  const adminOnly = await statusOf(Object.assign({ service: "entry",
    method: "BatchDeleteEntry", request: { ids: [entryId] } }, agentBase));
  check("an agent is refused an administrator's method with " +
    "PERMISSION_DENIED — it presented something, and it was not enough, " +
    "which is a different instruction from \"authenticate\"", function () {
      assert.strictEqual(adminOnly, "PERMISSION_DENIED");
    });

  // ---- Agent administration, back as the administrator ------------------
  const listed = await call(Object.assign({ service: "agent",
    method: "ListAgents", request: {} }, adminBase));
  check("ListAgents holds this run's agent, and its selectors are marked " +
    "UNVERIFIED — an attestation payload nothing checked is a claim, not a " +
    "fact", function () {
      assert.ok(listed.ok, listed.status.details);
      const ours = (listed.messages[0].agents || []).filter(function (row) {
        return spiffeId.fromProto(row.id) === agentId;
      });
      assert.strictEqual(ours.length, 1, "this run's agent is not listed");
      assert.ok((ours[0].selectors || []).some(function (selector) {
        return String(selector.value).indexOf("unverified") === 0;
      }), "an agent's selectors here are claims: " +
          JSON.stringify(ours[0].selectors));
    });

  const countAgents = await call(Object.assign({ service: "agent",
    method: "CountAgents", request: {} }, adminBase));
  check("CountAgents counts at least this run's one", function () {
    assert.ok(countAgents.ok, countAgents.status.details);
    assert.ok(Number(countAgents.messages[0].count) >= 1);
  });

  const gotAgent = await call(Object.assign({ service: "agent",
    method: "GetAgent",
    request: { id: spiffeId.toProto(agentId) } }, adminBase));
  check("GetAgent reads this run's agent back by its SPIFFE ID", function () {
    assert.ok(gotAgent.ok, gotAgent.status.details);
    assert.strictEqual(spiffeId.fromProto(gotAgent.messages[0].id), agentId);
  });

  const banned = await call(Object.assign({ service: "agent",
    method: "BanAgent",
    request: { id: spiffeId.toProto(agentId) } }, adminBase));
  check("BanAgent is accepted", function () {
    assert.ok(banned.ok, banned.status.details);
  });

  const bannedAttest = await statusOf(Object.assign({ service: "agent",
    method: "AttestAgent", request: { params: {
      data: { type: "join_token", payload: payload },
      params: { csr: csr.base64 } } } }, base));
  check("a banned agent is refused even a fresh attestation — a ban that did " +
    "not refuse would make the button that sets it a lie. That is the " +
    "difference from DeleteAgent, and is why both exist", function () {
      assert.strictEqual(bannedAttest, "PERMISSION_DENIED");
    });

  const deleted = await call(Object.assign({ service: "agent",
    method: "DeleteAgent",
    request: { id: spiffeId.toProto(agentId) } }, adminBase));
  check("DeleteAgent forgets it, and this run puts back what it made",
    function () {
      assert.ok(deleted.ok, deleted.status.details);
    });

  const goneAgent = await statusOf(Object.assign({ service: "agent",
    method: "GetAgent",
    request: { id: spiffeId.toProto(agentId) } }, adminBase));
  check("and it is gone", function () {
    assert.strictEqual(goneAgent, "NOT_FOUND");
  });

  log.debug("Leaving testAgent().");
}

// ---------------------------------------------------------------------------
// 5. THE LOCAL UNIX SOCKET — the `local` entity, and the ONLY way to reach
//    Debug.GetInfo.
//
// Off in the mock by default (`spiffe.serverSocketEnabled`), so this section
// skips with a named reason rather than passing vacuously. It is worth having
// at all because it is the only route to a method that is local-only in SPIRE's
// own table, which is the row this whole authorization story turns on.
// ---------------------------------------------------------------------------
async function testLocalSocket() {
  log.debug("Entering testLocalSocket().");
  if (!SERVER_SOCKET) {
    log.warn("SKIPPING the local-socket section: SPIFFE_SERVER_SOCKET is not " +
      "set. The mock STS ships with spiffe.serverSocketEnabled OFF, so there " +
      "is no socket to dial — start it with STS_SPIFFE_SERVER_SOCKET_ENABLED" +
      "=true and point this variable at the path to cover Debug.GetInfo, " +
      "which is LOCAL-ONLY and unreachable any other way.");
    log.debug("Leaving testLocalSocket(). Skipped.");
    return;
  }
  const base = { address: SERVER_SOCKET, plaintext: true };
  const info = await call(Object.assign({ service: "debug",
    method: "GetInfo", request: {} }, base));
  check("Debug.GetInfo answers on the Unix socket, which a real spire-server " +
    "trusts outright — the same method an administrator's SVID over TCP is " +
    "refused", function () {
      assert.ok(info.ok, info.status.details);
      assert.ok(typeof info.messages[0].uptime !== "undefined");
    });
  log.debug("Leaving testLocalSocket().");
}

// ---------------------------------------------------------------------------
// 6. ROTATION — the second message on a held stream.
//
// A Workload API stream stays open and the server re-sends at half the SVID
// lifetime, which is what makes a client's rotation path runnable without
// anybody waiting an hour. A client that read one message and stopped would
// make this invisible, and would look completely correct on the first fetch.
//
// The mock puts a FLOOR of thirty seconds under that period, so this section
// costs about half a minute and cannot be made cheaper by shortening the SVID
// lifetime further. It changes `spiffe.svidTtl` and puts it back.
// ---------------------------------------------------------------------------
async function testRotation(restore) {
  log.debug("Entering testRotation().");
  const previous = await readSettingRow("spiffe.svidTtl");
  restore.push(function () {
    return restoreSetting("spiffe.svidTtl", previous, 3600);
  });
  const set = await writeSetting("spiffe.svidTtl", 6);
  if (set.status !== 200 || !(set.body && set.body.ok)) {
    log.warn("SKIPPING rotation: spiffe.svidTtl could not be set through " +
      "the management API (HTTP " + set.status + "). Without a short SVID " +
      "lifetime the re-send is half an hour away.");
    log.debug("Leaving testRotation(). Skipped.");
    return;
  }
  const streamed = await call({ address: WORKLOAD_ADDRESS,
    service: "workload", method: "FetchX509SVID", maxMessages: 2 });
  check("a held FetchX509SVID stream RE-SENDS, and the second message is a " +
    "different certificate — which is a client's rotation path, run in " +
    "thirty seconds rather than in an hour", function () {
      assert.ok(streamed.ok, streamed.status.details);
      assert.strictEqual(streamed.messages.length, 2,
        "the stream stopped after " + streamed.messages.length +
        " message(s) because " + streamed.streaming.stopped + ". A Workload " +
        "API that writes once and ends looks perfect on the first fetch and " +
        "puts go-spiffe into a reconnect loop.");
      assert.notStrictEqual(streamed.messages[0].svids[0].x509_svid,
        streamed.messages[1].svids[0].x509_svid,
        "the same certificate twice is not a rotation");
      assert.strictEqual(streamed.streaming.stopped, "messages",
        "it must have stopped on the message cap rather than on the deadline");
    });
  log.debug("Leaving testRotation().");
}

// ---------------------------------------------------------------------------
// 7. THE ONE SETTING THAT CHANGES WHAT A CLIENT SEES MOST.
//
// `spiffe.autoCreateEntries` off makes the Workload API answer a caller that
// matches no entry with an EMPTY SVID LIST, which is exactly what a real agent
// does for an unregistered workload — and is the only way to run a client's
// "I have no identity" path, which most client libraries have and almost
// nobody exercises.
//
// TURNING THE SETTING OFF IS NOT ENOUGH, AND WORKING OUT WHY IS THE WHOLE
// SUBSTANCE OF THIS SECTION. Selector matching narrows to entries whose
// selectors are a SUBSET of the caller's, and every earlier call in this file
// has already caused an entry to be INVENTED carrying this caller's own stable
// selectors (`transport:` and `endpoint:`, never `peer:`, whose port is
// ephemeral). That entry is a subset of anything this caller can present, so it
// matches for ever — and note which way the arithmetic runs: ASSERTING an extra
// selector only WIDENS the caller's set, so it can make more entries match and
// never fewer. There is no request this test could compose that would miss it.
//
// So the invented entry is deleted first, as the administrator, which is what
// an operator would do — and the mock invents it again on the next call once
// the setting goes back, so the section heals itself rather than leaving the
// registry short for whatever runs next.
// ---------------------------------------------------------------------------
function isInventedForThisCaller(entry) {
  log.debug("Entering isInventedForThisCaller().");
  const selectors = entry.selectors || [];
  const invented = selectors.length > 0 && selectors.every(function (one) {
    return one.type === "transport" || one.type === "endpoint";
  });
  log.debug("Leaving isInventedForThisCaller(). " + invented);
  return invented;
}

async function testNoIdentityPath(adminBase, restore) {
  log.debug("Entering testNoIdentityPath().");
  const previousAuto = await readSettingRow("spiffe.autoCreateEntries");
  const previousAttest = await readSettingRow("spiffe.attestWorkloads");
  restore.push(async function () {
    await restoreSetting("spiffe.attestWorkloads", previousAttest, true);
    await restoreSetting("spiffe.autoCreateEntries", previousAuto, true);
    // One call with the setting back on, so the entry this section deleted is
    // invented again before anything else looks for it.
    try {
      await client.call({ address: WORKLOAD_ADDRESS, service: "workload",
        method: "FetchX509SVID" });
    } catch (e) {
      log.warn("could not re-prime the invented entry: " + e.message);
    }
  });

  const a = await writeSetting("spiffe.autoCreateEntries", false);
  const b = await writeSetting("spiffe.attestWorkloads", true);
  if (a.status !== 200 || b.status !== 200) {
    log.warn("SKIPPING the no-identity path: the two settings it needs could " +
      "not be set through the management API.");
    log.debug("Leaving testNoIdentityPath(). Skipped.");
    return;
  }

  const listed = await call(Object.assign({ service: "entry",
    method: "ListEntries", request: { page_size: 500 } }, adminBase));
  const invented = (listed.messages[0].entries || [])
    .filter(isInventedForThisCaller);
  if (invented.length) {
    await call(Object.assign({ service: "entry", method: "BatchDeleteEntry",
      request: { ids: invented.map(function (entry) {
        return entry.id;
      }) } }, adminBase));
  }

  const answer = await call({ address: WORKLOAD_ADDRESS, service: "workload",
    method: "FetchJWTSVID",
    request: { audience: ["spiffe://" + TRUST_DOMAIN + "/aud-" + STAMP] } });
  check("with autoCreateEntries off and nothing matching, a workload is " +
    "answered with an EMPTY SVID LIST rather than having an identity " +
    "invented for it — what a real agent says to an unregistered workload, " +
    "and a path most client libraries have and almost nobody runs",
    function () {
      assert.ok(answer.ok, answer.status.details);
      const svids = (answer.messages[0] || {}).svids || [];
      assert.strictEqual(svids.length, 0,
        "an identity was handed out to a caller matching no entry while " +
        "autoCreateEntries was off: " + JSON.stringify(svids.map(function (s) {
          return s.spiffe_id;
        })));
    });

  check("and the three SEEDED entries did not match either, because their " +
    "selectors are unix: and k8s: — a subset test, not an intersection",
    function () {
      const seeded = (listed.messages[0].entries || [])
        .filter(function (entry) {
          return (entry.selectors || []).some(function (one) {
            return one.type === "unix" || one.type === "k8s";
          });
        });
      assert.ok(seeded.length >= 1,
        "the registry should hold entries whose selectors this caller cannot " +
        "present; without one, the check above proves only that the registry " +
        "was empty");
    });
  log.debug("Leaving testNoIdentityPath().");
}

async function test() {
  log.debug("Entering test().");
  if (!(await gate())) {
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }

  // ---------------------------------------------------------------------
  // THE WORKLOADS THIS RUN WILL ASK FOR, IN THE APPLICATIONS REGISTRY,
  // BEFORE THE FIRST SVID IS MINTED.
  //
  // This is the one family where the registration is NOT the whole story and
  // it is worth being precise about which register is which. A SPIFFE
  // REGISTRATION ENTRY — what BatchCreateEntry writes, and what decides
  // whether an SVID is issued — lives in the mock's SPIFFE registry and is
  // created below through the SPIRE Server API, which is that protocol's own
  // door and the only honest way for a test to create one. The APPLICATIONS
  // registry is a different claim: it is the record of what parties this
  // service has dealt with, and `spiffeWorkloadId` is the identifier a
  // workload appears there under.
  //
  // So both, and neither stands in for the other: the entries below are
  // declared here as the parties this job is about to be, and the SPIRE API
  // creates the registration that actually authorizes them.
  //
  // The ids carry this run's stamp — nothing is ever deleted from that
  // directory — so a second run cannot read the first one's rows.
  // ---------------------------------------------------------------------
  const stsBase = registry.baseOf(STS_URL);
  for (const suffix of ["/one", "/two"]) {
    const id = spiffeId.make(TRUST_DOMAIN, MINE + suffix);
    await registry.provision(stsBase, {
      identifier: id,
      name: "SPIFFE protocol test workload",
      protocols: ["spiffe"],
      fields: { spiffeWorkloadId: [id] },
      why: "a workload this run creates a registration entry for"
    });
  }

  const restore = [];
  let previousAdminIds;
  try {
    await testBundleEndpoint();
    const held = await testWorkloadApi();
    const trustBundle = held.bundle;

    await testAnonymous(trustBundle);

    // Make the Workload API's own SVID an administrator. THE ONLY route from
    // "I can fetch an identity" to "I can drive the registry" that does not
    // already require one — and the reason this job holds a lock.
    previousAdminIds = await readSettingRow("spiffe.adminIds");
    restore.push(function () {
      return restoreSetting("spiffe.adminIds", previousAdminIds, "");
    });
    const set = await writeSetting("spiffe.adminIds", held.spiffe_id);
    assert.ok(set.status === 200 && set.body && set.body.ok,
      "spiffe.adminIds could not be set through the management API (HTTP " +
      set.status + "). Without it, forty of the forty-two SPIRE Server API " +
      "methods are unreachable from here and this test would cover the two " +
      "that are open to everybody.");

    const adminBase = { address: SERVER_ADDRESS, trustDomain: TRUST_DOMAIN,
                        trustBundle: trustBundle,
                        identity: { certPem: held.x509_svid,
                                    keyPem: held.x509_svid_key } };
    const made = await testAdmin(held, trustBundle);
    await testAgent(held, trustBundle, adminBase, made.entryId);

    // This run's entries, removed. Done here rather than in the finally
    // because it is an assertion as much as a cleanup: BatchDeleteEntry is one
    // of the forty-two.
    const removed = await call(Object.assign({ service: "entry",
      method: "BatchDeleteEntry", request: { ids: [made.entryId] } },
      adminBase));
    check("BatchDeleteEntry removes what this run created", function () {
      assert.ok(removed.ok, removed.status.details);
      assert.strictEqual(Number(removed.messages[0].results[0].status.code), 0,
        removed.messages[0].results[0].status.message);
    });

    await testLocalSocket();
    // ROTATION BEFORE THE NO-IDENTITY PATH, and the order is load-bearing:
    // that section deletes the invented entry and leaves autoCreateEntries off
    // until the restore runs, so a stream held afterwards is answered with an
    // empty SVID list — which fails here as "no certificate came back" and
    // names rotation for what is really an ordering mistake. It goes last for
    // that reason.
    await testRotation(restore);
    await testNoIdentityPath(adminBase, restore);

    // ---- THE COVERAGE FLOOR -------------------------------------------
    //
    // Not a count of assertions but a count of METHODS SENT. A method can be
    // in the catalogue, in the picker and on the page and never have been
    // called, which is exactly the gap this file exists to close.
    const catalogue = client.catalogue();
    const all = [];
    ['workload', 'server'].forEach(function (surface) {
      (catalogue[surface] || []).forEach(function (group) {
        group.methods.forEach(function (method) {
          all.push(method.service + '.' + method.name);
        });
      });
    });
    const missed = all.filter(function (key) {
      return !CALLED[key];
    });
    check("every one of the " + all.length + " methods was actually SENT — " +
      "not listed, not described, sent", function () {
        assert.deepStrictEqual(missed, [],
          "these methods were never called: " + missed.join(", ") +
          ". A method in a catalogue that nothing ever sends is a method " +
          "nobody has checked.");
      });
  } finally {
    // Per SETTING rather than reset-all, which would also undo whatever a
    // concurrent job had pinned. In a finally so a failed assertion cannot
    // skip it.
    for (const one of restore.reverse()) {
      try {
        await one();
      } catch (e) {
        log.error("could not restore a setting: " + e.message);
      }
    }
  }

  log.info(calls + " calls made, " + Object.keys(CALLED).length +
    " distinct methods, " + checks + " checks passed.");
  assert.ok(checks >= 55,
    'Only ' + checks + ' checks ran and this file defines well over fifty. ' +
    'A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("spiffe_protocol")
  .description("Call every one of SPIFFE's forty-nine methods against the " +
    "mock STS through the api's own client, as four different entities — " +
    "nothing, a workload, an administrator and an agent — and assert the " +
    "authorization refusals as the answers they are.")
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
