// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: api_gnap.js
//
// ---------------------------------------------------------------------------
// POST /gnap/call, END TO END, over HTTP to a running api, with iya-sts
// at the far end. Modelled on api_ssf.js. What only this job can see:
//
//   * GET /gnap/limits, the document the page reads to learn there is
//     an api at all, including that mtls is offered;
//   * every refusal the relay makes, as a 400 from the ROUTE (the body
//     parser in front of it included), the client-certificate pair
//     among them: half a pair, http, not PEM, a key that is not the
//     certificate's, a body over gnapMaxRequestBytes;
//   * the address policy still covering the route;
//   * that the relay forwards the SIGNED BYTES unchanged: an httpsig
//     and an attached-JWS grant request sent through it are granted by
//     iya-sts, a tampered one is refused as a bad proof, and the grant
//     is revoked through it;
//   * the mtls proof made BY THE API: a grant request whose key is a
//     certificate is granted when the api presents that certificate,
//     refused when it presents none, and a continuation is refused when
//     a different certificate is presented;
//   * the three outcomes as statuses: 400 refused here, 200 carrying
//     the authorization server's answer, 502 unreachable.
//
// iya-sts must be in development mode, which grants the page's default
// sample (subject information) with no administrator involved. In
// product mode the job fails and says why.
// ---------------------------------------------------------------------------
"use strict";

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const { mustBeAbleTo } = require("./expectation.js");
const paths = require("./module_paths.js");
const live = require("./gnap_live.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_gnap",
  level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const gnap = paths.requireSharedModule(
  [path.join(__dirname, "..", "client", "src", "gnap_client.js")],
  "client/src/gnap_client.js");

var apiUrl = process.env.API_URL || "https://localhost:4000";
var stsUrl = String(process.env.GNAP_AS_URL || process.env.STS_URL ||
  "https://localhost:8081").replace(/\/+$/, "").replace(/\/sts$/, "");
// The api verifies iya-sts's certificate unless told not to. Inside the
// stack it has the stack's root; a host run against a self-signed
// iya-sts sets GNAP_TLS_INSECURE=1, which the page's checkbox mirrors.
var sslValidate = process.env.GNAP_TLS_INSECURE !== "1";

const FINISH = "https://gnap-finish.invalid/done";

let checks = 0;
let skips = [];
let limits = null;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function skip(what, why) {
  log.debug("Entering skip(). " + what);
  skips.push(what + ": " + why);
  log.warn("  SKIPPED — " + what + " — " + why);
  log.debug("Leaving skip().");
}

async function json(method, route, body) {
  log.debug("Entering json(). " + method + " " + route);
  const init = { method: method, headers: {} };
  if (body !== undefined && body !== null) {
    init.headers["Content-Type"] = "application/json";
    init.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const response = await fetch(apiUrl + route, init);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (e) {
      payload = null;
    }
  }
  log.debug("Leaving json(). " + response.status);
  return { status: response.status, body: payload, text: text };
}

// A prepared GNAP request, as the page hands it to the relay.
async function relay(prepared, extra) {
  log.debug("Entering relay(). " + prepared.method + " " + prepared.url);
  const body = Object.assign({
    url: prepared.url,
    method: prepared.method,
    headers: prepared.headers,
    body: prepared.body,
    sslValidate: sslValidate
  }, extra || {});
  if (prepared.mtls && !(extra && extra.bare) &&
      !body.clientCertificatePem) {
    body.clientCertificatePem = prepared.mtls.certificatePem;
    body.clientKeyPem = prepared.mtls.privateKeyPem;
  }
  delete body.bare;
  const answer = await json("POST", "/gnap/call", body);
  log.debug("Leaving relay(). " + answer.status);
  return answer;
}

async function theLimitsDocumentIsPublished() {
  log.info("[limits] GET /gnap/limits");
  const answer = await json("GET", "/gnap/limits");
  check("GET /gnap/limits answers 200", function () {
    assert.strictEqual(answer.status, 200, answer.text);
  });
  limits = answer.body;
  check("it names the five RFC 9635 methods", function () {
    assert.deepStrictEqual(limits.methods,
      ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]);
  });
  check("it offers all four key proofs, mtls among them", function () {
    assert.deepStrictEqual(limits.proofs,
      ["httpsig", "jwsd", "jws", "mtls"]);
    assert.ok(/clientCertificatePem/.test(limits.mtls), limits.mtls);
  });
  check("it publishes the request cap and the shared caps", function () {
    assert.ok(limits.maxRequestBytes > 0);
    assert.ok(limits.maxResponseBytes > 0);
    assert.ok(limits.callTimeoutMs > 0);
    assert.ok(limits.connectionTimeoutMs > 0);
    assert.strictEqual(typeof limits.maxRedirects, "number");
    assert.strictEqual(typeof limits.addressPolicyEnabled, "boolean");
  });
}

async function theRelayRefusesBeforeTheNetwork() {
  log.info("[refusals] each is a 400 from POST /gnap/call");
  const pair = live.makeClientCertificate("api-gnap-refusals");
  const other = live.makeClientCertificate("api-gnap-other");
  const target = "https://as.example/gnap";
  const cases = [
    ["no url", {}, /url is required/],
    ["a relative url", { url: "/gnap" }, /absolute/],
    ["a file: url", { url: "file:///etc/passwd" }, /absolute/],
    ["a method RFC 9635 does not use", { url: target, method: "TRACE" },
      /method must be/],
    ["a body on GET", { url: target, method: "GET", body: "{}" }, /GET/],
    ["a Content-Length header", { url: target,
      headers: { "Content-Length": "2" } }, /Content-Length/],
    ["a Host header", { url: target, headers: { Host: "x" } }, /Host/],
    ["a header value with CR/LF", { url: target,
      headers: { "X-A": "a\r\nX-B: b" } }, /carriage return/],
    ["a header name that is not a token", { url: target,
      headers: { "a b": "c" } }, /not a token/],
    ["a certificate without its key", { url: target,
      clientCertificatePem: pair.certificatePem }, /go together/],
    ["a key without its certificate", { url: target,
      clientKeyPem: pair.keyPem }, /go together/],
    ["a client certificate on http", { url: "http://as.example/gnap",
      clientCertificatePem: pair.certificatePem,
      clientKeyPem: pair.keyPem }, /https/],
    ["a certificate that is not PEM", { url: target,
      clientCertificatePem: "MIIB", clientKeyPem: pair.keyPem },
      /not a PEM certificate/],
    ["a key that is not the certificate's", { url: target,
      clientCertificatePem: pair.certificatePem,
      clientKeyPem: other.keyPem }, /not the private key/],
    ["a body over gnapMaxRequestBytes", { url: target,
      body: "x".repeat(limits.maxRequestBytes + 1) }, /at most/]
  ];
  let i;
  for (i = 0; i < cases.length; i++) {
    const one = cases[i];
    const answer = await json("POST", "/gnap/call", one[1]);
    check("refused with a 400: " + one[0], function () {
      assert.strictEqual(answer.status, 400, answer.text.slice(0, 300));
      assert.ok(one[2].test((answer.body || {}).error || ""),
        "the reason does not say why: " + answer.text.slice(0, 300));
    });
  }
}

async function theAddressPolicyStillApplies() {
  log.info("[proxy] api/ssrf_guard.js covers /gnap/call");
  if (!limits.addressPolicyEnabled) {
    skip("the address layers refuse loopback and cloud metadata",
      "this api has blockPrivateNetworkCalls off, because on this " +
      "network iya-sts IS a private address. tests/api_ssrf_guard.js " +
      "drives those layers directly.");
    check("the api SAYS the address layers are off", function () {
      assert.strictEqual(limits.addressPolicyEnabled, false);
    });
    return;
  }
  const loopback = await json("POST", "/gnap/call",
    { url: "http://127.0.0.1:1/gnap", method: "OPTIONS" });
  check("a loopback address is refused BY THE GUARD", function () {
    assert.strictEqual(loopback.status, 502, loopback.text);
    assert.strictEqual((loopback.body || {}).code, "EBLOCKEDADDRESS",
      loopback.text);
  });
  const pair = live.makeClientCertificate("api-gnap-guard");
  const metadata = await json("POST", "/gnap/call",
    { url: "https://169.254.169.254/gnap", method: "POST", body: "{}",
      clientCertificatePem: pair.certificatePem,
      clientKeyPem: pair.keyPem });
  check("the metadata address is refused BY THE GUARD on the mtls " +
    "agent too", function () {
    assert.strictEqual(metadata.status, 502, metadata.text);
    assert.strictEqual((metadata.body || {}).code, "EBLOCKEDADDRESS",
      metadata.text);
  });
}

function grantOf(answer, what) {
  log.debug("Entering grantOf(). " + what);
  assert.strictEqual(answer.status, 200, what + ": the relay answered " +
    answer.status + " " + answer.text.slice(0, 300));
  const relayed = answer.body || {};
  if (relayed.status === 401 && /product mode/.test(relayed.description)) {
    throw new Error("iya-sts is in product mode and refuses a key " +
      "nobody provisioned, so no grant can be obtained through the " +
      "relay with a key made here. Run against development mode.");
  }
  assert.strictEqual(relayed.status, 200, what + ": iya-sts answered " +
    relayed.status + " " + (relayed.rawBody || "").slice(0, 400));
  const grant = relayed.body || {};
  assert.ok(grant.continue && grant.continue.uri &&
    grant.continue.access_token, what + ": no continuation");
  assert.ok(grant.interact && grant.interact.redirect,
    what + ": no interaction");
  log.debug("Leaving grantOf().");
  return grant;
}

async function signedBytesArriveUnchanged(grantUrl) {
  log.info("[relay] the signed request reaches iya-sts byte for byte");
  const record = await gnap.generateKey("ES256", "api-gnap");
  let i;
  const proofs = ["httpsig", "jws"];
  for (i = 0; i < proofs.length; i++) {
    const proof = proofs[i];
    const prepared = await gnap.prepare(record, "POST", grantUrl, {
      json: gnap.withClient(gnap.sampleRequest(FINISH, "n-api"), record,
        proof, { name: "api_gnap" }),
      proof: proof
    });
    const grant = grantOf(await relay(prepared), proof + " via the api");
    check(proof + ": a grant request sent through the api is granted",
      function () {
        assert.ok(grant.continue.uri);
      });
    const gone = await relay(await gnap.prepare(record, "DELETE",
      grant.continue.uri, { token: grant.continue.access_token.value,
        proof: proof }));
    check(proof + ": the grant is revoked through the api", function () {
      assert.strictEqual(gone.status, 200, gone.text);
      assert.strictEqual(gone.body.status, 204, gone.text);
    });
  }
  const prepared = await gnap.prepare(record, "POST", grantUrl, {
    json: gnap.withClient(gnap.sampleRequest(FINISH, "n-api2"), record,
      "httpsig", { name: "api_gnap" }),
    proof: "httpsig"
  });
  const altered = await relay(prepared, { body: prepared.body + " " });
  check("a body altered after signing is refused by iya-sts as a bad " +
    "proof, and the relay reports it as a 200 carrying that answer",
    function () {
      assert.strictEqual(altered.status, 200, altered.text);
      assert.strictEqual(altered.body.status, 401, altered.text);
      assert.strictEqual(altered.body.error, "invalid_client",
        altered.text);
    });
}

async function theApiMakesTheMtlsProof(grantUrl) {
  log.info("[mtls] the api presents the client certificate");
  const pair = live.makeClientCertificate("api-gnap-mtls");
  const record = gnap.recordFromCertificate(pair.certificatePem,
    pair.keyPem);
  const make = async function (nonce) {
    log.debug("Entering make(). " + nonce);
    const out = await gnap.prepare(record, "POST", grantUrl, {
      json: gnap.withClient(gnap.sampleRequest(FINISH, nonce), record,
        "mtls", { name: "api_gnap mtls" }),
      proof: "mtls"
    });
    log.debug("Leaving make().");
    return out;
  };
  const bare = await relay(await make("n-m1"), { bare: true });
  check("an mtls grant request sent with no certificate is refused " +
    "by iya-sts (RFC 9635 section 7.3.2)", function () {
    assert.strictEqual(bare.status, 200, bare.text);
    assert.strictEqual(bare.body.status, 401, bare.text);
    assert.ok(/client certificate/.test(bare.body.description),
      bare.text);
  });
  const grant = grantOf(await relay(await make("n-m2")),
    "mtls via the api");
  check("an mtls grant request is granted when the api presents the " +
    "certificate", function () {
    assert.ok(grant.continue.uri);
  });
  const stranger = live.makeClientCertificate("api-gnap-stranger");
  // A revocation needs no interact_ref and no wait, so what iya-sts
  // judges here is the certificate alone.
  const wrong = await relay(await gnap.prepare(record, "DELETE",
    grant.continue.uri, { token: grant.continue.access_token.value,
      proof: "mtls" }), { clientCertificatePem: stranger.certificatePem,
    clientKeyPem: stranger.keyPem });
  check("revoking the grant over a different certificate is refused",
    function () {
      assert.strictEqual(wrong.status, 200, wrong.text);
      assert.strictEqual(wrong.body.status, 401, wrong.text);
    });
  const gone = await relay(await gnap.prepare(record, "DELETE",
    grant.continue.uri, { token: grant.continue.access_token.value,
      proof: "mtls" }));
  check("the mtls grant is revoked through the api", function () {
    assert.strictEqual(gone.status, 200, gone.text);
    assert.strictEqual(gone.body.status, 204, gone.text);
  });
}

async function theThreeOutcomesAreDistinct() {
  log.info("[outcomes] 400, 200 and 502");
  const unreachable = await json("POST", "/gnap/call",
    { url: "https://127.0.0.1:1/gnap", method: "OPTIONS",
      sslValidate: false });
  check("a server that cannot be reached is a 502", function () {
    assert.strictEqual(unreachable.status, 502, unreachable.text);
    assert.ok((unreachable.body || {}).code, unreachable.text);
  });
}

async function test() {
  log.debug("Entering test().");
  const reachable = await fetch(apiUrl + "/gnap/limits")
    .then(function (r) {
      return r.status === 200;
    }).catch(function () {
      return false;
    });
  mustBeAbleTo(reachable, "The api this job was pointed at,", apiUrl +
    ", did not answer GET /gnap/limits. Start the stack, or set " +
    "API_URL to one that does.");
  await theLimitsDocumentIsPublished();
  await theRelayRefusesBeforeTheNetwork();
  await theAddressPolicyStillApplies();
  const discovery = await relay({ method: "OPTIONS",
    url: stsUrl + "/gnap", headers: {}, body: "" });
  check("discovery through the api reaches iya-sts", function () {
    assert.strictEqual(discovery.status, 200, discovery.text);
    assert.strictEqual(discovery.body.status, 200, discovery.text);
    assert.ok(discovery.body.body.grant_request_endpoint);
  });
  const grantUrl = discovery.body.body.grant_request_endpoint;
  await signedBytesArriveUnchanged(grantUrl);
  await theApiMakesTheMtlsProof(grantUrl);
  await theThreeOutcomesAreDistinct();
  log.info(checks + " checks passed" +
    (skips.length ? ", " + skips.length + " skipped." : "."));
  assert.ok(checks >= 28, "Only " + checks + " checks ran. A section " +
    "has stopped being called.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_gnap")
  .description("Drive POST /gnap/call end to end: the limits document, " +
    "every refusal as a 400, the address policy, signed bytes " +
    "forwarded unchanged, and the mtls proof made by the api.")
  .addOption(new Option("-u, --url <url>",
    "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
