// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: cors_proxy_engine.js
//
// ---------------------------------------------------------------------------
// tests/cors-proxy/cors-proxy.js, driven in node with no browser and no
// stack (#431).
//
// That proxy is what lets the debugger's browser-based wallet reach walt.id's
// issuer and verifier and the Polaris verifier, none of which send CORS
// headers. Until this job it was exercised only INDIRECTLY, by those
// interoperability jobs — so a broken preflight showed up as four walt.id
// failures naming walt.id, and a header the proxy forgot to expose showed up
// as a wallet that "did not get" a DPoP nonce the server plainly sent.
//
// So this starts the real handler in front of a throwaway upstream, in plain
// and TLS modes, and asserts what a browser depends on: the preflight answer
// (methods, reflected request headers, the origin allow-list), the CORS
// headers on a real response and the ones it exposes, header and body
// pass-through, a merged Vary, the 502 when the upstream is down or presents
// a certificate that does not verify, and a health endpoint that answers
// without the upstream. Plus the configuration: the old WALTID_* names still
// read, and the combinations that cannot work stop it at startup.
// ---------------------------------------------------------------------------

// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments — it
// serves its own sockets — so node ignores the pair. Do not add commander
// here without also declaring `--url`; see tests/CLAUDE.md.
const assert = require("assert");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");
const forge = require("node-forge");

var appconfig = {};
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // A host run with no CONFIG_FILE: the default level below is enough.
  appconfig = { configProblem: e.message };
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "cors_proxy_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());
if (appconfig.configProblem) {
  log.debug("No CONFIG_FILE: " + appconfig.configProblem);
}

// In the tests image the proxy is copied flat beside this script; in a
// checkout it is in tests/cors-proxy/.
const paths = require("./module_paths.js");
const proxy = paths.requireSharedModule(
  [path.join(__dirname, "cors-proxy.js"),
   path.join(__dirname, "cors-proxy", "cors-proxy.js")],
  "tests/cors-proxy/cors-proxy.js");

// ---------------------------------------------------------------------------
// Fixtures: a self-signed certificate for "localhost", and servers on
// ephemeral ports.
// ---------------------------------------------------------------------------
function makeCertificate(dir, name) {
  log.debug("Entering makeCertificate(). " + name);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "0" + forge.util.bytesToHex(forge.random.getBytes(8));
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const subject = [{ name: "commonName", value: "localhost" }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: "basicConstraints", cA: true },
    { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" },
                                         { type: 7, ip: "127.0.0.1" }] }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const certFile = path.join(dir, name + "-cert.pem");
  const keyFile = path.join(dir, name + "-key.pem");
  fs.writeFileSync(certFile, forge.pki.certificateToPem(cert));
  fs.writeFileSync(keyFile, forge.pki.privateKeyToPem(keys.privateKey));
  log.debug("Leaving makeCertificate().");
  return { certFile: certFile, keyFile: keyFile,
           pem: fs.readFileSync(certFile) };
}

function listen(server) {
  log.debug("Entering listen().");
  log.debug("Leaving listen().");
  return new Promise(function (resolve, reject) {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", function () {
      resolve(server.address().port);
    });
  });
}

function close(server) {
  log.debug("Entering close().");
  log.debug("Leaving close().");
  return new Promise(function (resolve) {
    if (server.closeAllConnections) server.closeAllConnections();
    server.close(function () {
      resolve();
    });
  });
}

// The upstream: echoes what it received as JSON, and answers with the
// headers a wallet reads plus some the proxy must strip or merge.
function upstreamHandler(scheme) {
  log.debug("Entering upstreamHandler(). " + scheme);
  log.debug("Leaving upstreamHandler().");
  return function (req, res) {
    let body = "";
    req.on("data", function (d) {
      body += d;
    });
    req.on("end", function () {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
      res.setHeader("DPoP-Nonce", "nonce-from-upstream");
      res.setHeader("X-Upstream", scheme);
      res.setHeader("Vary", "Accept");
      // A service that DID send CORS headers: the proxy's own must win, or
      // the browser sees two Access-Control-Allow-Origin values and refuses.
      res.setHeader("Access-Control-Allow-Origin", "https://evil.example");
      res.writeHead(req.url === "/missing" ? 404 : 200);
      res.end(JSON.stringify({ method: req.method, url: req.url,
        host: req.headers.host, custom: req.headers["x-custom"] || null,
        body: body }));
    });
  };
}

function request(port, opts) {
  log.debug("Entering request(). " + (opts.method || "GET") + " " +
            opts.path);
  const transport = opts.ca ? https : http;
  log.debug("Leaving request().");
  return new Promise(function (resolve, reject) {
    const req = transport.request({
      host: "127.0.0.1", port: port, method: opts.method || "GET",
      path: opts.path, headers: opts.headers || {}, ca: opts.ca,
      servername: opts.ca ? "localhost" : undefined
    }, function (res) {
      let body = "";
      res.on("data", function (d) {
        body += d;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: body });
      });
    });
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function startProxy(env) {
  log.debug("Entering startProxy().");
  const server = proxy.createProxy(proxy.readConfig(env));
  const port = await listen(server);
  log.debug("Leaving startProxy(). port=" + port);
  return { server: server, port: port };
}

// ---------------------------------------------------------------------------
// The checks.
// ---------------------------------------------------------------------------
function checkConfig() {
  log.debug("Entering checkConfig().");
  const defaults = proxy.readConfig({});
  assert.strictEqual(defaults.upstream, "localhost:7006");
  assert.strictEqual(defaults.port, 7005);
  assert.strictEqual(defaults.anyOrigin, true);
  assert.strictEqual(defaults.upstreamTls, false);
  assert.deepStrictEqual(defaults.deprecated, []);

  const old = proxy.readConfig({ WALTID_UPSTREAM: "svc:7004",
                                 WALTID_PROXY_PORT: "7003" });
  assert.strictEqual(old.upstream, "svc:7004",
    "the pre-#431 WALTID_UPSTREAM is still read");
  assert.strictEqual(old.port, 7003,
    "the pre-#431 WALTID_PROXY_PORT is still read");
  assert.strictEqual(old.deprecated.length, 2,
    "and both are reported as deprecated");

  const both = proxy.readConfig({ CORS_PROXY_UPSTREAM: "new:1",
    WALTID_UPSTREAM: "old:2" });
  assert.strictEqual(both.upstream, "new:1", "the new name wins");
  assert.deepStrictEqual(both.deprecated, []);

  assert.strictEqual(proxy.readConfig({ CORS_PROXY_UPSTREAM: "svc",
    CORS_PROXY_UPSTREAM_TLS: "1" }).upstreamPort, 443,
    "an upstream with no port defaults to 443 in TLS mode");
  assert.deepStrictEqual(proxy.readConfig({
    CORS_PROXY_ALLOWED_ORIGINS: "https://a.example, https://b.example"
  }).allowedOrigins, ["https://a.example", "https://b.example"]);

  assert.throws(function () {
    proxy.readConfig({ CORS_PROXY_ALLOW_CREDENTIALS: "1" });
  }, /needs CORS_PROXY_ALLOWED_ORIGINS/,
  "credentials with * stop the proxy at startup");
  assert.throws(function () {
    proxy.readConfig({ CORS_PROXY_TLS_CERT_FILE: "/x.pem" });
  }, /set together/, "half a TLS pair stops the proxy at startup");
  assert.throws(function () {
    proxy.readConfig({ CORS_PROXY_PORT: "port" });
  }, /not a port number/);
  log.info("[config] OK — defaults, the WALTID_* aliases, and the " +
           "combinations that cannot work.");
  log.debug("Leaving checkConfig().");
}

async function checkPlainMode() {
  log.debug("Entering checkPlainMode().");
  const upstream = http.createServer(upstreamHandler("http"));
  const upstreamPort = await listen(upstream);
  const p = await startProxy({ CORS_PROXY_UPSTREAM: "127.0.0.1:" +
                               upstreamPort });
  try {
    // A preflight that names its headers gets them back, and every method.
    let r = await request(p.port, { method: "OPTIONS", path: "/credential",
      headers: { Origin: "https://wallet.example",
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type, dpop, x-custom" } });
    assert.strictEqual(r.status, 204, "a preflight is answered here");
    assert.strictEqual(r.headers["access-control-allow-origin"], "*");
    assert.strictEqual(r.headers["access-control-allow-headers"],
      "content-type, dpop, x-custom",
      "Access-Control-Request-Headers is reflected");
    ["PUT", "DELETE", "PATCH", "POST"].forEach(function (m) {
      assert.ok(r.headers["access-control-allow-methods"].indexOf(m) !== -1,
        m + " is an allowed method");
    });
    assert.strictEqual(r.headers["access-control-max-age"], "86400");

    // Without a list it falls back to the two the wallet always sends; a
    // malformed list is not reflected.
    r = await request(p.port, { method: "OPTIONS", path: "/",
      headers: { Origin: "https://wallet.example" } });
    assert.strictEqual(r.headers["access-control-allow-headers"],
      "Content-Type, Authorization");
    r = await request(p.port, { method: "OPTIONS", path: "/",
      headers: { Origin: "https://wallet.example",
        "Access-Control-Request-Headers": "a b; c" } });
    assert.strictEqual(r.headers["access-control-allow-headers"],
      "Content-Type, Authorization", "a malformed list is not reflected");

    // A real request: status, body and headers pass through, Host is the
    // upstream's, the upstream's own CORS header is replaced, and the
    // headers a wallet reads are exposed.
    r = await request(p.port, { method: "POST", path: "/credential?x=1",
      body: "{\"proof\":1}", headers: { Origin: "https://wallet.example",
        "Content-Type": "application/json", "X-Custom": "kept" } });
    assert.strictEqual(r.status, 200);
    const echoed = JSON.parse(r.body);
    assert.strictEqual(echoed.method, "POST");
    assert.strictEqual(echoed.url, "/credential?x=1");
    assert.strictEqual(echoed.body, "{\"proof\":1}");
    assert.strictEqual(echoed.custom, "kept");
    assert.strictEqual(echoed.host, "127.0.0.1:" + upstreamPort,
      "the upstream sees its own Host");
    assert.strictEqual(r.headers["access-control-allow-origin"], "*",
      "the upstream's own Access-Control-Allow-Origin is replaced");
    assert.strictEqual(r.headers["dpop-nonce"], "nonce-from-upstream");
    assert.strictEqual(r.headers["x-upstream"], "http");
    const exposed = r.headers["access-control-expose-headers"];
    ["WWW-Authenticate", "DPoP-Nonce", "Location", "Content-Type"]
      .forEach(function (h) {
        assert.ok(exposed.indexOf(h) !== -1, h + " is exposed");
      });

    for (const m of ["PUT", "DELETE"]) {
      r = await request(p.port, { method: m, path: "/manage" });
      assert.strictEqual(JSON.parse(r.body).method, m,
        m + " is forwarded");
    }
    r = await request(p.port, { path: "/missing" });
    assert.strictEqual(r.status, 404, "the upstream's status passes through");
  } finally {
    await close(p.server);
    await close(upstream);
  }
  log.info("[plain] OK — preflight, pass-through, exposed headers and " +
           "every method.");
  log.debug("Leaving checkPlainMode().");
}

async function checkUpstreamDownAndHealth() {
  log.debug("Entering checkUpstreamDownAndHealth().");
  // A port that was open a moment ago and is not now.
  const gone = http.createServer();
  const gonePort = await listen(gone);
  await close(gone);
  const p = await startProxy({ CORS_PROXY_UPSTREAM: "127.0.0.1:" +
                               gonePort });
  try {
    let r = await request(p.port, { path: "/anything",
      headers: { Origin: "https://wallet.example" } });
    assert.strictEqual(r.status, 502);
    assert.strictEqual(JSON.parse(r.body).error, "upstream_unavailable");
    assert.strictEqual(r.headers["access-control-allow-origin"], "*",
      "the 502 is readable by the page");

    r = await request(p.port, { path: proxy.HEALTH_PATH });
    assert.strictEqual(r.status, 200,
      "the health endpoint answers with the upstream down");
    assert.strictEqual(JSON.parse(r.body).status, "ok");
  } finally {
    await close(p.server);
  }
  log.info("[down/health] OK — 502 with a reason, and a health endpoint " +
           "that does not touch the upstream.");
  log.debug("Leaving checkUpstreamDownAndHealth().");
}

async function checkOriginAllowList() {
  log.debug("Entering checkOriginAllowList().");
  const upstream = http.createServer(upstreamHandler("http"));
  const upstreamPort = await listen(upstream);
  const p = await startProxy({ CORS_PROXY_UPSTREAM: "127.0.0.1:" +
    upstreamPort, CORS_PROXY_ALLOWED_ORIGINS: "https://wallet.example",
    CORS_PROXY_ALLOW_CREDENTIALS: "1" });
  try {
    let r = await request(p.port, { path: "/",
      headers: { Origin: "https://wallet.example" } });
    assert.strictEqual(r.headers["access-control-allow-origin"],
      "https://wallet.example", "a listed origin is echoed");
    assert.strictEqual(r.headers["access-control-allow-credentials"], "true");
    const vary = r.headers.vary.split(/\s*,\s*/);
    assert.ok(vary.indexOf("Origin") !== -1, "Vary names Origin");
    assert.ok(vary.indexOf("Accept") !== -1,
      "and keeps the upstream's own Vary");

    r = await request(p.port, { path: "/",
      headers: { Origin: "https://other.example" } });
    assert.strictEqual(r.status, 200,
      "an unlisted origin's request is still forwarded");
    assert.strictEqual(r.headers["access-control-allow-origin"], undefined,
      "but carries no Access-Control-Allow-Origin");
    assert.strictEqual(r.headers["access-control-allow-credentials"],
      undefined);

    r = await request(p.port, { method: "OPTIONS", path: "/",
      headers: { Origin: "https://other.example",
        "Access-Control-Request-Method": "POST" } });
    assert.strictEqual(r.status, 403, "an unlisted origin's preflight is " +
      "refused");

    r = await request(p.port, { path: "/" });
    assert.strictEqual(r.status, 200,
      "a request with no Origin (not a browser) is forwarded");
  } finally {
    await close(p.server);
    await close(upstream);
  }
  log.info("[origins] OK — listed origins echoed with Vary and " +
           "credentials, others refused at preflight.");
  log.debug("Leaving checkOriginAllowList().");
}

async function checkTlsModes(dir) {
  log.debug("Entering checkTlsModes().");
  const front = makeCertificate(dir, "front");
  const back = makeCertificate(dir, "back");
  const stranger = makeCertificate(dir, "stranger");
  const upstream = https.createServer({ cert: fs.readFileSync(back.certFile),
    key: fs.readFileSync(back.keyFile) }, upstreamHandler("https"));
  const upstreamPort = await listen(upstream);
  // TLS on both sides: served with `front`, the upstream verified against
  // `back`. "localhost" rather than 127.0.0.1, because the upstream is
  // verified BY NAME.
  const p = await startProxy({ CORS_PROXY_UPSTREAM: "localhost:" +
    upstreamPort, CORS_PROXY_UPSTREAM_TLS: "1",
    CORS_PROXY_UPSTREAM_CA_FILE: back.certFile,
    CORS_PROXY_TLS_CERT_FILE: front.certFile,
    CORS_PROXY_TLS_KEY_FILE: front.keyFile });
  // The same upstream, verified against a CA that did not issue it.
  const wrong = await startProxy({ CORS_PROXY_UPSTREAM: "localhost:" +
    upstreamPort, CORS_PROXY_UPSTREAM_TLS: "1",
    CORS_PROXY_UPSTREAM_CA_FILE: stranger.certFile });
  try {
    let r = await request(p.port, { ca: front.pem, method: "OPTIONS",
      path: "/", headers: { Origin: "https://wallet.example" } });
    assert.strictEqual(r.status, 204, "a preflight over TLS");
    r = await request(p.port, { ca: front.pem, method: "POST",
      path: "/response", body: "vp_token=x",
      headers: { Origin: "https://wallet.example" } });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.headers["x-upstream"], "https",
      "the upstream was spoken to over TLS");
    assert.strictEqual(JSON.parse(r.body).body, "vp_token=x");
    assert.strictEqual(r.headers["access-control-allow-origin"], "*");

    r = await request(wrong.port, { path: "/" });
    assert.strictEqual(r.status, 502,
      "an upstream certificate that does not verify is a 502, not a pass");
  } finally {
    await close(p.server);
    await close(wrong.server);
    await close(upstream);
  }
  log.info("[tls] OK — served over TLS, upstream over TLS and verified, " +
           "and refused when it does not verify.");
  log.debug("Leaving checkTlsModes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The test-stack CORS proxy, in node.");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cors-proxy-"));
  try {
    checkConfig();
    await checkPlainMode();
    await checkUpstreamDownAndHealth();
    await checkOriginAllowList();
    await checkTlsModes(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (error) {
  log.error(error.stack || error.message);
  process.exit(1);
});
