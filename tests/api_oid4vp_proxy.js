// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_oid4vp_proxy.js
//
// ---------------------------------------------------------------------------
// POST /oid4vp/call's rules (api/oid4vp_proxy.js), in node, with no Verifier
// and no api running: the module has no axios and no network in it, so every
// refusal it can produce is asserted here by name, the way scim_engine.js and
// ssf_engine.js hold their proxies.
//
//   * a missing or relative URL, a method other than GET and POST, a header
//     ssf_proxy.js refuses by shape (Host, Content-Length, a CR/LF value), a
//     body on a GET, a body that is not a string, and a body past
//     oid4vpMaxRequestBytes — each a 400 with its reason;
//   * the defaults a wallet relies on: a POST body is form-encoded unless the
//     page says otherwise, and the answer is TEXT, because a Request Object is
//     a compact JWS and not JSON;
//   * the status rule: whatever the Verifier answered is reported, a 400
//     included.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const fs = require("fs");
const paths = require("./module_paths.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "api_oid4vp_proxy",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const http = require("http");
const guardModule = paths.requireSharedModule(
  [path.join(__dirname, "..", "api", "ssrf_guard.js"),
   path.join(__dirname, "ssrf_guard.js")], "api/ssrf_guard.js");
const proxy = paths.requireSharedModule(
  [path.join(__dirname, "..", "api", "oid4vp_proxy.js"),
   path.join(__dirname, "oid4vp_proxy.js")], "api/oid4vp_proxy.js");

function refused(input, pattern, why) {
  log.debug("Entering refused(). " + why);
  const r = proxy.describeRequest(input, {});
  assert.strictEqual(r.ok, false, why + " should be refused: " +
                     JSON.stringify(r));
  assert.ok(pattern.test(r.error), why + ": the refusal should say " +
            pattern + "; it said: " + r.error);
  log.debug("Leaving refused().");
}

// THE ADDRESS POLICY, as it applies to this endpoint. The relay is an axios
// call through the shared instance the guard is installed on (asserted from
// the source below), so it is the guard that refuses a caller-chosen private
// target. That is asserted here with the guard ENABLED, exactly as a deployed
// api runs it — the suite's own api runs with it off (api/env/docker-tests.js,
// because iya-sts and Keycloak are private addresses there), so a live call
// to that api would prove nothing about the refusal.
//
//   * a request_uri or response_uri on loopback, a private range, a name that
//     resolves to loopback, IPv6 loopback or the cloud metadata address is a
//     request this module ACCEPTS by shape and the guard then refuses;
//   * a redirect hop to a loopback literal, which never passes the URL check
//     again, is refused by the guarded agent — the path follow-redirects takes.
async function addressPolicy() {
  log.debug("Entering addressPolicy().");
  // A logger the guard can call without its output drowning the test, the
  // shape api_ssrf_guard.js uses.
  const quiet = {};
  ["debug", "info", "warn", "error"].forEach(function (level) {
    quiet[level] = function quietLog() {
      log.debug("Entering quietLog(). " + level);
      log.debug("Leaving quietLog().");
    };
  });
  const guard = guardModule.createGuard({ blockPrivateNetworkCalls: true },
                                        quiet);
  const targets = [
    ["https://127.0.0.1:8081/oid4vp/request/x", "a loopback literal"],
    ["https://localhost:8081/oid4vp/response", "a name resolving to loopback"],
    ["https://[::1]:8081/request.jwt", "IPv6 loopback"],
    ["https://10.0.0.5/request.jwt", "a private range"],
    ["http://169.254.169.254/latest/meta-data/", "the cloud metadata address"]
  ];
  for (const t of targets) {
    const shaped = proxy.describeRequest({ url: t[0], method: "POST",
                                           body: "response=x" }, {});
    assert.ok(shaped.ok, t[1] + ": the relay's own checks are about shape " +
              "and should accept it, leaving the address to the guard");
    let refusal = null;
    try {
      await guard.assertUrlAllowed(shaped.url);
    } catch (e) {
      refusal = e;
    }
    assert.ok(refusal && refusal.code === "EBLOCKEDADDRESS", t[1] + " (" +
      t[0] + ") must be refused by the address policy; got " +
      (refusal ? refusal.code : "no refusal"));
  }
  // A redirect hop: the guarded agent itself, driven the way follow-redirects
  // drives it for a Location the URL check never saw.
  const server = http.createServer(function (req, res) {
    res.end("reached");
  });
  await new Promise(function (r) {
    server.listen(0, "127.0.0.1", r);
  });
  const port = server.address().port;
  const hop = await new Promise(function (resolve) {
    const req = http.request({ host: "127.0.0.1", port: port,
      path: "/oid4vp/response", method: "POST", agent: guard.httpAgent },
    function (res) {
      res.resume();
      resolve({ reached: true });
    });
    req.on("error", function (e) {
      resolve({ reached: false, code: e.code });
    });
    req.end("response=x");
  });
  server.close();
  assert.ok(!hop.reached && hop.code === "EBLOCKEDADDRESS", "a redirect " +
    "hop to a loopback literal must be refused by the guarded agent; got " +
    JSON.stringify(hop));
  log.info("PASS the address policy refuses private targets and a " +
           "redirect to one.");
  log.debug("Leaving addressPolicy().");
}

async function main() {
  log.debug("Entering main().");
  await addressPolicy();
  const url = "https://verifier.example/request.jwt?state=s";
  refused({}, /url is required/, "no url");
  refused({ url: "/request.jwt" }, /absolute http/, "a relative url");
  refused({ url: "ftp://verifier.example/x" }, /absolute http/,
          "a non-http url");
  refused({ url: url, method: "PUT" }, /GET or POST/, "PUT");
  refused({ url: url, method: "DELETE" }, /GET or POST/, "DELETE");
  refused({ url: url, headers: { Host: "other.example" } }, /Host/i,
          "a Host header");
  refused({ url: url, method: "POST", body: "a=b",
            headers: { "Content-Length": "3" } }, /Content-Length/i,
          "a Content-Length header");
  refused({ url: url, headers: { Accept: "x\r\nInjected: 1" } },
          /carriage return|line feed/, "a header value with CR/LF");
  refused({ url: url, method: "GET", body: "wallet_nonce=n" },
          /GET carries no body/, "a body on a GET");
  refused({ url: url, method: "POST", body: { vp_token: {} } },
          /must be a string/, "a body that is not a string");
  refused({ url: url, responseEncoding: "hex" }, /"text" or "base64"/,
          "a responseEncoding that is neither text nor base64");
  const big = "x".repeat(proxy.DEFAULT_MAX_REQUEST_BYTES + 1);
  refused({ url: url, method: "POST", body: big },
          /oid4vpMaxRequestBytes/, "a body past the cap");
  log.info("PASS every refusal names its rule.");

  let r = proxy.describeRequest({ url: url, method: "post",
    body: "wallet_metadata=%7B%7D&wallet_nonce=n" }, {});
  assert.ok(r.ok, JSON.stringify(r));
  assert.strictEqual(r.method, "POST");
  assert.strictEqual(r.headers["Content-Type"],
    "application/x-www-form-urlencoded", "a POST body is form-encoded by " +
    "default, as both OpenID4VP bodies are");
  assert.strictEqual(r.headers.Accept, "*/*");
  assert.strictEqual(r.sslValidate, true, "TLS is checked unless the page " +
                     "says otherwise");
  r = proxy.describeRequest({ url: url, sslValidate: false,
    headers: { Accept: "application/oauth-authz-req+jwt" } }, {});
  assert.strictEqual(r.sslValidate, false);
  assert.strictEqual(r.headers.Accept, "application/oauth-authz-req+jwt",
    "the page's Accept is kept");
  assert.strictEqual(r.body, null);
  assert.strictEqual(r.responseEncoding, "text", "a body comes back as " +
                     "text unless the caller asks for its bytes");
  r = proxy.describeRequest({ url: url, responseEncoding: "base64",
    headers: { Accept: "application/statuslist+cwt" } }, {});
  assert.ok(r.ok, JSON.stringify(r));
  assert.strictEqual(r.responseEncoding, "base64");
  assert.strictEqual(proxy.maxRequestBytes({ oid4vpMaxRequestBytes: 10 }),
                     10);
  assert.strictEqual(proxy.maxRequestBytes({ oid4vpMaxRequestBytes: 0 }),
    proxy.DEFAULT_MAX_REQUEST_BYTES, "a non-positive cap falls back");
  log.info("PASS the defaults a wallet relies on.");

  const jws = "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln";
  let a = proxy.readResponse(200, { "content-type":
    "application/oauth-authz-req+jwt" }, jws);
  assert.strictEqual(a.body, jws, "a Request Object comes back as text");
  assert.strictEqual(a.json, null);
  a = proxy.readResponse(400, {}, '{"error":"invalid_request"}');
  assert.strictEqual(a.ok, false);
  assert.strictEqual(a.status, 400, "a Verifier's refusal is reported " +
                     "with its own status");
  assert.strictEqual(a.json.error, "invalid_request");
  // A binary body (a CWT Status List Token's first bytes, a COSE_Sign1
  // tag 18 and a protected header) survives byte for byte under base64,
  // which the Verifier page's status list fetch relies on (#470, B3).
  const cwt = Buffer.from([0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0xff,
                           0x00, 0x80]);
  a = proxy.readResponse(200, { "content-type": "application/statuslist+cwt" },
                         cwt, "base64");
  assert.strictEqual(a.bodyEncoding, "base64");
  assert.ok(Buffer.from(a.body, "base64").equals(cwt), "the bytes come " +
            "back exactly as they arrived");
  assert.strictEqual(a.json, null);
  a = proxy.readResponse(404, {}, null, "base64");
  assert.strictEqual(a.ok, false);
  assert.strictEqual(a.body, "");
  const limits = proxy.limits({});
  assert.deepStrictEqual(limits.methods, ["GET", "POST"]);
  assert.deepStrictEqual(limits.responseEncodings, ["text", "base64"]);
  assert.ok(limits.refusedHeaders.indexOf("host") !== -1);
  log.info("PASS the Verifier's answer and the published limits.");

  // The route is registered, and its no-response branch answers. In a
  // checkout that is api/server.js; the tests image carries it as text,
  // beside the flat modules, as api_server.js.txt (tests/Dockerfile).
  const serverPath = [path.join(__dirname, "..", "api", "server.js"),
                      path.join(__dirname, "api_server.js.txt")]
    .filter(function (one) {
      return fs.existsSync(one);
    })[0];
  if (!serverPath) {
    log.info("api_oid4vp_proxy: all checks passed (api/server.js is not " +
             "in this image, so the route checks were not run).");
    log.debug("Leaving main(). No server.js.");
    return;
  }
  const server = fs.readFileSync(serverPath, "utf8");
  const start = server.indexOf("app.post('/oid4vp/call'");
  assert.ok(start !== -1, "api/server.js registers POST /oid4vp/call");
  const handler = server.slice(start, server.indexOf("app.get(" +
    "'/oid4vp/limits'", start));
  assert.ok(/blocked \? STATUS_400 : 502/.test(handler) &&
            /EBLOCKEDADDRESS/.test(handler) &&
            /EPROTOCOLNOTALLOWED/.test(handler), "the no-response branch " +
    "must answer: 400 for an address-policy or scheme refusal, 502 for " +
    "anything else (api/CLAUDE.md)");
  assert.ok(/outboundHttpsAgent\(/.test(handler) &&
            /outboundHttpAgent\(/.test(handler), "the call must use the " +
    "guarded outbound agents, or it drops the SSRF guard's hooks");
  // Every outbound setting a new call site may not drop (api/CLAUDE.md,
  // Outbound calls): the whole-call timeout, the response size cap and the
  // redirect cap, beside this endpoint's own request-body cap.
  [["timeout: CALL_TIMEOUT", "callTimeout"],
   ["maxContentLength: MAX_CONTENT_LENGTH", "maxContentLength"],
   ["maxRedirects: MAX_REDIRECTS", "maxRedirects"]].forEach(function (one) {
    assert.ok(handler.indexOf(one[0]) !== -1, "POST /oid4vp/call must set " +
      one[1] + " (" + one[0] + ")");
  });
  assert.ok(/\baxios\(\{/.test(handler), "and must call the shared axios " +
    "instance the guard is installed on");
  assert.ok(/responseType: binary \? 'arraybuffer' : 'text'/.test(handler),
    "a base64 call must read the body as bytes, not as text");
  // connectionTimeout rides on the outbound agents, asserted above.
  log.info("api_oid4vp_proxy: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
