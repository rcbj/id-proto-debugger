// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_oid4vp_verifier.js
//
// ---------------------------------------------------------------------------
// THE VERIFIER ROLE'S request_uri AND response_uri (api/oid4vp_verifier.js,
// issue #364), in two halves.
//
//   1. THE MODULE, always, with no listener: the whole lifecycle — create,
//      publish, a Wallet's GET and POST of the Request Object, the CA
//      certificate, an answer kept field by field, the events cursor,
//      delete — and every bound: the secret, the size caps, the session and
//      per-caller caps, the event ring, the switch, and both expiries on a
//      clock this file moves.
//   2. THE ROUTES, over HTTP, when run-report.js hands this job an API_URL
//      (every target with an api; a static site has none). That half is the
//      wiring no module test can see: the statuses, the two media types a
//      Wallet compares (`application/oauth-authz-req+jwt` with no charset,
//      `application/pkix-cert` as bytes), the form body kept VERBATIM past
//      the extended urlencoded parser, the 401 challenge, and a CORS
//      preflight that lets the page send Authorization with PUT and DELETE.
//
// Node only — no browser, no Wallet, no Verifier.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
const { mustBeAbleTo } = require("./expectation.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "api_oid4vp_verifier",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const verifier = paths.requireSharedModule(
  [path.join(__dirname, "..", "api", "oid4vp_verifier.js"),
   path.join(__dirname, "oid4vp_verifier.js")], "api/oid4vp_verifier.js");

const program = new Command();
program
  .name("api_oid4vp_verifier")
  .description("The OpenID4VP Verifier role's request_uri and response_uri " +
      "the api hosts for a page: the module's lifecycle and bounds in " +
      "node, and the routes over HTTP when API_URL is given.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

const API_URL = process.env.API_URL
  ? process.env.API_URL.replace(/\/+$/, "") : "";

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// A compact JWS by shape. Nothing here verifies it, and neither does the
// api: the page signs and the Wallet verifies.
function fakeJws(claims) {
  log.debug("Entering fakeJws().");
  const out = [{ alg: "ES256", typ: "oauth-authz-req+jwt" }, claims]
    .map(function (o) {
      return Buffer.from(JSON.stringify(o)).toString("base64url");
    }).join(".") + "." +
    Buffer.from("not a signature").toString("base64url");
  log.debug("Leaving fakeJws().");
  return out;
}

// A DER SEQUENCE, which is all the module asks of a certificate.
const CA_DER = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);

// ---------------------------------------------------------------------------
// 1. THE MODULE.
// ---------------------------------------------------------------------------
function moduleLifecycle() {
  log.debug("Entering moduleLifecycle().");
  log.info("[module] the lifecycle, with no listener");
  verifier.reset();
  const cfg = {};
  const made = verifier.create(cfg, { redirectUri: "https://rp.example/done" },
                               "10.0.0.1");
  check("create answers 201 with a 32-hex id and secret", function () {
    assert.strictEqual(made.ok, true);
    assert.strictEqual(made.status, 201);
    assert.match(made.id, /^[0-9a-f]{32}$/);
    assert.match(made.secret, /^[0-9a-f]{32}$/);
    assert.notStrictEqual(made.id, made.secret);
    assert.ok(!isNaN(Date.parse(made.expiresAt)));
  });
  check("the three URLs share one base and one host", function () {
    const urls = verifier.urlsFor("https://api.example:4000/", made.id);
    const root = "https://api.example:4000/oid4vp/verifier/" + made.id;
    assert.strictEqual(urls.requestUri, root + "/request");
    assert.strictEqual(urls.responseUri, root + "/response");
    assert.strictEqual(urls.caIssuersUrl, root + "/ca");
  });
  const bearer = "Bearer " + made.secret;
  check("before a publish, the Request Object and the CA are 404",
    function () {
      const r = verifier.fetchRequest(cfg, made.id, { method: "GET" });
      assert.strictEqual(r.status, 404);
      assert.match(r.error_description, /not published/);
      assert.strictEqual(verifier.fetchCa(cfg, made.id).status, 404);
    });
  const jws = fakeJws({ client_id: "x509_hash:abc", nonce: "n-1" });
  check("publish without the secret is 401, with another one is 401",
    function () {
      const none = verifier.publish(cfg, made.id, "", { requestObject: jws });
      assert.strictEqual(none.status, 401);
      assert.match(none.error, /carried none/);
      const wrong = verifier.publish(cfg, made.id, "Bearer " +
        "0".repeat(32), { requestObject: jws });
      assert.strictEqual(wrong.status, 401);
      assert.match(wrong.error, /different one/);
      assert.strictEqual(verifier.publish(cfg, "f".repeat(32), bearer,
        { requestObject: jws }).status, 404);
    });
  check("publish refuses what is not a compact JWS", function () {
    ["", "a.b", "a.b.c.d.e", "a b.c.d", ".b.c"].forEach(function (bad) {
      const r = verifier.publish(cfg, made.id, bearer,
                                 { requestObject: bad });
      assert.strictEqual(r.status, 400, JSON.stringify(bad));
    });
  });
  check("publish refuses a certificate that is not DER", function () {
    const r = verifier.publish(cfg, made.id, bearer,
      { requestObject: jws, caCertificate: "not base64!" });
    assert.strictEqual(r.status, 400);
    const s = verifier.publish(cfg, made.id, bearer,
      { requestObject: jws, caCertificate: Buffer.from("hello")
        .toString("base64") });
    assert.strictEqual(s.status, 400);
    assert.match(s.error, /SEQUENCE/);
  });
  check("publish stores the object and the CA (PEM accepted, scheme in " +
    "any case)", function () {
    const pem = "-----BEGIN CERTIFICATE-----\n" +
      CA_DER.toString("base64") + "\n-----END CERTIFICATE-----\n";
    const r = verifier.publish(cfg, made.id, "bearer " + made.secret,
      { requestObject: jws, caCertificate: pem });
    assert.deepStrictEqual(r, { ok: true, status: 200 });
  });
  check("a Wallet's GET is served the JWS as " +
    "application/oauth-authz-req+jwt", function () {
    const r = verifier.fetchRequest(cfg, made.id,
      { method: "GET", remoteAddress: "192.0.2.7" });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.contentType, "application/oauth-authz-req+jwt");
    assert.strictEqual(r.body, jws);
  });
  check("a Wallet's POST records wallet_metadata (parsed) and " +
    "wallet_nonce", function () {
    const form = "wallet_metadata=" + encodeURIComponent(JSON.stringify(
      { vp_formats_supported: { "dc+sd-jwt": {} } })) + "&wallet_nonce=wn-42";
    const r = verifier.fetchRequest(cfg, made.id, { method: "POST",
      contentType: "application/x-www-form-urlencoded", rawBody: form });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, jws);
  });
  check("the CA certificate is served as DER", function () {
    const r = verifier.fetchCa(cfg, made.id, "192.0.2.7");
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.contentType, "application/pkix-cert");
    assert.ok(Buffer.isBuffer(r.body) && r.body.equals(CA_DER));
  });
  const answer = "vp_token=" + encodeURIComponent('{"q":["eyJ.a.b~"]}') +
    "&state=s%201&presentation_submission[0]=kept&state=s2";
  check("an answer is kept field by field as it arrived, and " +
    "redirect_uri is answered", function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/x-www-form-urlencoded; charset=utf-8", rawBody: answer,
      remoteAddress: "192.0.2.7" });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body, { redirect_uri: "https://rp.example/done" });
  });
  check("a JSON answer is accepted and recorded as JSON", function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/json", rawBody: '{"response":"a.b.c.d.e"}' });
    assert.strictEqual(r.status, 200);
  });
  check("an answer in another media type is refused and RECORDED",
    function () {
      const r = verifier.respond(cfg, made.id,
        { contentType: "text/plain", rawBody: "vp_token=x" });
      assert.strictEqual(r.status, 400);
      assert.strictEqual(r.error, "invalid_request");
    });
  let events;
  check("the events come back in order with every detail", function () {
    const out = verifier.events(cfg, made.id, bearer, undefined);
    assert.strictEqual(out.status, 200);
    events = out.events;
    assert.deepStrictEqual(events.map(function (e) {
      return e.kind;
    }), ["request-fetched", "request-fetched", "ca-fetched", "response",
      "response", "response-refused"]);
    assert.strictEqual(out.next, 6);
    assert.strictEqual(events[0].method, "GET");
    assert.strictEqual(events[0].remoteAddress, "192.0.2.7");
    assert.strictEqual(events[1].method, "POST");
    assert.strictEqual(events[1].walletNonce, "wn-42");
    assert.deepStrictEqual(events[1].walletMetadata,
      { vp_formats_supported: { "dc+sd-jwt": {} } });
    assert.deepStrictEqual(events[3].fields, {
      vp_token: '{"q":["eyJ.a.b~"]}',
      state: ["s 1", "s2"],
      "presentation_submission[0]": "kept"
    });
    assert.strictEqual(events[3].contentType,
      "application/x-www-form-urlencoded; charset=utf-8");
    assert.deepStrictEqual(events[4].fields, { response: "a.b.c.d.e" });
    assert.strictEqual(events[4].contentType, "application/json");
    assert.match(events[5].problem, /text\/plain/);
    events.forEach(function (e, i) {
      assert.strictEqual(e.seq, i);
      assert.ok(!("bytes" in e));
    });
  });
  check("the cursor hands back only what is new", function () {
    const out = verifier.events(cfg, made.id, bearer, "4");
    assert.deepStrictEqual(out.events.map(function (e) {
      return e.seq;
    }), [4, 5]);
    assert.strictEqual(verifier.events(cfg, made.id, bearer, "6")
      .events.length, 0);
    assert.strictEqual(verifier.events(cfg, made.id, bearer, "99")
      .events.length, 0);
    assert.strictEqual(verifier.events(cfg, made.id, bearer, "soon")
      .events.length, 6);
  });
  check("events and delete need the secret", function () {
    assert.strictEqual(verifier.events(cfg, made.id, "", "0").status, 401);
    assert.strictEqual(verifier.remove(cfg, made.id, "Bearer nope")
      .status, 401);
  });
  check("delete, and then everything is 404", function () {
    const r = verifier.remove(cfg, made.id, bearer);
    assert.deepStrictEqual(r, { ok: true, status: 200, deleted: made.id });
    assert.strictEqual(verifier.fetchRequest(cfg, made.id, {}).status, 404);
    assert.strictEqual(verifier.fetchCa(cfg, made.id).status, 404);
    assert.strictEqual(verifier.respond(cfg, made.id,
      { contentType: "application/x-www-form-urlencoded", rawBody: "a=b" })
      .status, 404);
    assert.strictEqual(verifier.events(cfg, made.id, bearer).status, 404);
    assert.strictEqual(verifier.remove(cfg, made.id, bearer).status, 404);
  });
  log.debug("Leaving moduleLifecycle().");
}

function moduleBounds() {
  log.debug("Entering moduleBounds().");
  log.info("[module] the bounds");
  verifier.reset();
  check("disabled refuses create with 403 naming the setting", function () {
    const r = verifier.create({ oid4vpVerifierEnabled: false }, {}, "a");
    assert.strictEqual(r.status, 403);
    assert.match(r.error, /oid4vpVerifierEnabled/);
    assert.strictEqual(verifier.limits({ oid4vpVerifierEnabled: false })
      .enabled, false);
  });
  check("the per-caller cap counts by address", function () {
    const cfg = { oid4vpVerifierMaxSessionsPerCaller: 2 };
    assert.strictEqual(verifier.create(cfg, {}, "a").ok, true);
    assert.strictEqual(verifier.create(cfg, {}, "a").ok, true);
    const third = verifier.create(cfg, {}, "a");
    assert.strictEqual(third.status, 400);
    assert.match(third.error, /oid4vpVerifierMaxSessionsPerCaller/);
    assert.strictEqual(verifier.create(cfg, {}, "b").ok, true);
  });
  check("the global cap counts everybody", function () {
    const r = verifier.create({ oid4vpVerifierMaxSessions: 3 }, {}, "c");
    assert.strictEqual(r.status, 400);
    assert.match(r.error, /oid4vpVerifierMaxSessions /);
  });
  verifier.reset();
  check("a lifetime above its ceiling, or malformed, is refused",
    function () {
      const r = verifier.create({ oid4vpVerifierTtlMs: 1000 },
                                { ttlMs: 2000 }, "a");
      assert.strictEqual(r.status, 400);
      assert.match(r.error, /oid4vpVerifierTtlMs = 1000/);
      assert.strictEqual(verifier.create({}, { idleTtlMs: 1.5 }, "a").status,
                         400);
      assert.strictEqual(verifier.create({}, { idleTtlMs: true }, "a")
        .status, 400);
      assert.strictEqual(verifier.create({}, { redirectUri: "a\nb" }, "a")
        .status, 400);
    });
  const cfg = { oid4vpVerifierMaxRequestObjectBytes: 200,
    oid4vpVerifierMaxResponseBytes: 100, oid4vpVerifierMaxEvents: 3,
    oid4vpVerifierMaxSessionBytes: 150 };
  const made = verifier.create(cfg, {}, "a");
  const bearer = "Bearer " + made.secret;
  check("an oversized Request Object is refused naming the setting",
    function () {
      const big = fakeJws({ pad: "x".repeat(300) });
      const r = verifier.publish(cfg, made.id, bearer,
                                 { requestObject: big });
      assert.strictEqual(r.status, 400);
      assert.match(r.error, /oid4vpVerifierMaxRequestObjectBytes/);
    });
  check("an oversized answer is refused and recorded as refused",
    function () {
      const r = verifier.respond(cfg, made.id, { contentType:
        "application/x-www-form-urlencoded", rawBody: "vp_token=" +
        "x".repeat(200) });
      assert.strictEqual(r.status, 400);
      assert.match(r.error_description, /oid4vpVerifierMaxResponseBytes/);
      const out = verifier.events(cfg, made.id, bearer, 0);
      assert.strictEqual(out.events[0].kind, "response-refused");
      assert.ok(!out.events[0].fields);
    });
  check("an answer to a session with no published object is still " +
    "kept, with {} when no redirect_uri was set", function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/x-www-form-urlencoded", rawBody: "vp_token=" +
      "y".repeat(80) });
    assert.deepStrictEqual(r.body, {});
  });
  check("the session's byte cap drops the OLDEST answer", function () {
    verifier.respond(cfg, made.id, { contentType:
      "application/x-www-form-urlencoded", rawBody: "vp_token=" +
      "z".repeat(80) });
    const out = verifier.events(cfg, made.id, bearer, 0);
    const answers = out.events.filter(function (e) {
      return e.kind === "response";
    });
    assert.strictEqual(answers.length, 1);
    assert.strictEqual(answers[0].fields.vp_token, "z".repeat(80));
    assert.ok(out.dropped >= 1);
  });
  check("the event ring keeps the newest oid4vpVerifierMaxEvents",
    function () {
      verifier.publish(cfg, made.id, bearer, { requestObject: "a.b." });
      for (let i = 0; i < 5; i++) {
        verifier.fetchRequest(cfg, made.id, { method: "GET" });
      }
      const out = verifier.events(cfg, made.id, bearer, 0);
      assert.strictEqual(out.events.length, 3);
      assert.strictEqual(out.events[2].seq, out.next - 1);
    });
  check("an unsecured (alg none) object is let through by shape",
    function () {
      assert.strictEqual(verifier.fetchRequest(cfg, made.id,
        { method: "GET" }).body, "a.b.");
    });
  log.debug("Leaving moduleBounds().");
}

function moduleExpiry() {
  log.debug("Entering moduleExpiry().");
  log.info("[module] both expiries, on a clock this file moves");
  verifier.reset();
  let t = 1000000;
  verifier.setClock(function () {
    return t;
  });
  try {
    const cfg = { oid4vpVerifierTtlMs: 1000, oid4vpVerifierIdleTtlMs: 300 };
    const a = verifier.create(cfg, {}, "a");
    const bearer = "Bearer " + a.secret;
    check("use keeps a session alive past its idle lifetime", function () {
      t += 200;
      assert.strictEqual(verifier.events(cfg, a.id, bearer).status, 200);
      t += 200;
      assert.strictEqual(verifier.events(cfg, a.id, bearer).status, 200);
    });
    check("the idle lifetime ends an untouched session", function () {
      t += 300;
      assert.strictEqual(verifier.events(cfg, a.id, bearer).status, 404);
    });
    const b = verifier.create(cfg, {}, "a");
    check("the absolute lifetime ends a busy one", function () {
      for (let i = 0; i < 4; i++) {
        t += 250;
        verifier.events(cfg, b.id, "Bearer " + b.secret);
      }
      assert.strictEqual(verifier.limits(cfg).held, 0);
    });
    const c = verifier.create(cfg, { idleTtlMs: 50 }, "a");
    check("a session's own shorter lifetime is honoured", function () {
      t += 60;
      assert.strictEqual(verifier.fetchRequest(cfg, c.id, {}).status, 404);
      assert.match(verifier.fetchRequest(cfg, c.id, {}).error_description,
                   /expired/);
    });
  } finally {
    verifier.setClock(null);
    verifier.reset();
  }
  log.debug("Leaving moduleExpiry().");
}

// ---------------------------------------------------------------------------
// 2. THE ROUTES.
// ---------------------------------------------------------------------------
async function call(method, route, options) {
  log.debug("Entering call(). " + method + " " + route);
  const opts = options || {};
  const init = { method: method, headers: Object.assign({},
    opts.headers || {}) };
  if (opts.json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.form !== undefined) {
    init.headers["Content-Type"] = "application/x-www-form-urlencoded";
    init.body = opts.form;
  } else if (opts.text !== undefined) {
    init.headers["Content-Type"] = opts.contentType || "text/plain";
    init.body = opts.text;
  }
  const response = await fetch(API_URL + route, init);
  const bytes = Buffer.from(await response.arrayBuffer());
  let body = null;
  try {
    body = JSON.parse(bytes.toString("utf8"));
  } catch (e) {
    body = null;
  }
  log.debug("Leaving call(). " + response.status);
  return { status: response.status, headers: response.headers, bytes: bytes,
    text: bytes.toString("utf8"), body: body };
}

async function routes() {
  log.debug("Entering routes().");
  log.info("[routes] over HTTP at " + API_URL);
  const limits = await call("GET", "/oid4vp/verifier/limits");
  check("GET /oid4vp/verifier/limits is 200 and the role is on", function () {
    assert.strictEqual(limits.status, 200);
    assert.strictEqual(limits.body.enabled, true);
    assert.strictEqual(limits.body.requestObjectMediaType,
                       "application/oauth-authz-req+jwt");
    ["ttlMs", "idleTtlMs", "maxSessions", "maxSessionsPerCaller",
     "maxEvents", "maxResponseBytes", "maxRequestObjectBytes"]
      .forEach(function (name) {
        assert.ok(limits.body[name] > 0, name);
      });
  });
  const preflight = await call("OPTIONS", "/oid4vp/verifier/x/request", {
    headers: { Origin: "https://page.example",
      "Access-Control-Request-Method": "PUT",
      "Access-Control-Request-Headers": "authorization,content-type" } });
  check("CORS lets the page send Authorization with PUT and DELETE",
    function () {
      const methods = preflight.headers.get("access-control-allow-methods") ||
        "";
      assert.ok(/PUT/.test(methods) && /DELETE/.test(methods), methods);
      assert.match(preflight.headers.get("access-control-allow-headers") ||
        "", /authorization/i);
    });
  const made = await call("POST", "/oid4vp/verifier",
    { json: { redirectUri: "https://rp.example/after" } });
  check("POST /oid4vp/verifier is 201 with the three URLs", function () {
    assert.strictEqual(made.status, 201, made.text);
    const root = API_URL + "/oid4vp/verifier/" + made.body.id;
    assert.strictEqual(made.body.requestUri, root + "/request");
    assert.strictEqual(made.body.responseUri, root + "/response");
    assert.strictEqual(made.body.caIssuersUrl, root + "/ca");
    assert.match(made.body.secret, /^[0-9a-f]{32}$/);
  });
  const base = "/oid4vp/verifier/" + made.body.id;
  const auth = { Authorization: "Bearer " + made.body.secret };
  try {
    const early = await call("GET", base + "/request");
    check("a Request Object before the publish is 404", function () {
      assert.strictEqual(early.status, 404);
      assert.strictEqual(early.body.error, "not_found");
    });
    const jws = fakeJws({ client_id: "x509_hash:abc", nonce: "n-2" });
    const anon = await call("PUT", base + "/request",
      { json: { requestObject: jws } });
    check("a publish without the secret is 401 with a challenge",
      function () {
        assert.strictEqual(anon.status, 401);
        assert.match(anon.headers.get("www-authenticate") || "", /^Bearer/);
        assert.ok(anon.body.error);
      });
    const typed = await call("PUT", base + "/request",
      { headers: auth, json: { requestObject: 5 } });
    check("a requestObject that is not a string is the model's 400",
      function () {
        assert.strictEqual(typed.status, 400);
        assert.strictEqual(typed.body.code, "EMODELREQUEST");
      });
    const published = await call("PUT", base + "/request", { headers: auth,
      json: { requestObject: jws, caCertificate: CA_DER.toString("base64") }
    });
    check("PUT publishes", function () {
      assert.strictEqual(published.status, 200, published.text);
      assert.deepStrictEqual(published.body, { ok: true });
    });
    const got = await call("GET", base + "/request");
    check("GET request_uri serves the JWS, media type exact", function () {
      assert.strictEqual(got.status, 200);
      assert.strictEqual(got.headers.get("content-type"),
                         "application/oauth-authz-req+jwt");
      assert.strictEqual(got.text, jws);
    });
    const posted = await call("POST", base + "/request", { form:
      "wallet_metadata=%7B%22a%22%3A1%7D&wallet_nonce=wn-http" });
    check("POST request_uri serves the same JWS", function () {
      assert.strictEqual(posted.status, 200);
      assert.strictEqual(posted.text, jws);
    });
    const ca = await call("GET", base + "/ca");
    check("GET ca serves DER as application/pkix-cert", function () {
      assert.strictEqual(ca.status, 200);
      assert.strictEqual(ca.headers.get("content-type"),
                         "application/pkix-cert");
      assert.ok(ca.bytes.equals(CA_DER));
    });
    const form = "vp_token=%7B%22q%22%3A%5B%22e~%22%5D%7D" +
      "&presentation_submission[a]=1&state=one&state=two";
    const answered = await call("POST", base + "/response", { form: form });
    check("the response_uri answers redirect_uri (section 8.2)",
      function () {
        assert.strictEqual(answered.status, 200, answered.text);
        assert.deepStrictEqual(answered.body,
          { redirect_uri: "https://rp.example/after" });
      });
    const big = await call("POST", base + "/response", { form: "vp_token=" +
      "x".repeat(limits.body.maxResponseBytes + 1) });
    check("an answer over oid4vpVerifierMaxResponseBytes is 400",
      function () {
        assert.strictEqual(big.status, 400);
        assert.strictEqual(big.body.error, "invalid_request");
      });
    const denied = await call("GET", base + "/events?after=0");
    check("events without the secret is 401", function () {
      assert.strictEqual(denied.status, 401);
    });
    const drained = await call("GET", base + "/events?after=0",
                               { headers: auth });
    check("the events carry the form VERBATIM past the extended parser",
      function () {
        assert.strictEqual(drained.status, 200);
        const kinds = drained.body.events.map(function (e) {
          return e.kind;
        });
        assert.deepStrictEqual(kinds, ["request-fetched", "request-fetched",
          "ca-fetched", "response", "response-refused"]);
        assert.strictEqual(drained.body.events[1].walletNonce, "wn-http");
        assert.deepStrictEqual(drained.body.events[1].walletMetadata,
                               { a: 1 });
        assert.deepStrictEqual(drained.body.events[3].fields, {
          vp_token: '{"q":["e~"]}',
          "presentation_submission[a]": "1",
          state: ["one", "two"]
        });
        assert.strictEqual(drained.body.next, 5);
      });
    const later = await call("GET", base + "/events?after=4",
                             { headers: auth });
    check("the cursor", function () {
      assert.strictEqual(later.body.events.length, 1);
      assert.strictEqual(later.body.events[0].seq, 4);
    });
    const wrongDelete = await call("DELETE", base,
      { headers: { Authorization: "Bearer " + "0".repeat(32) } });
    check("delete with another secret is 401", function () {
      assert.strictEqual(wrongDelete.status, 401);
    });
    const deleted = await call("DELETE", base, { headers: auth });
    check("delete", function () {
      assert.strictEqual(deleted.status, 200);
      assert.deepStrictEqual(deleted.body,
                             { ok: true, deleted: made.body.id });
    });
    const after = [
      await call("GET", base + "/request"),
      await call("GET", base + "/ca"),
      await call("POST", base + "/response", { form: "vp_token=x" }),
      await call("GET", base + "/events", { headers: auth }),
      await call("PUT", base + "/request",
                 { headers: auth, json: { requestObject: jws } }),
      await call("DELETE", base, { headers: auth })
    ];
    check("and then every route is 404", function () {
      after.forEach(function (one, i) {
        assert.strictEqual(one.status, 404, "route " + i + ": " + one.text);
      });
    });
  } finally {
    await call("DELETE", base, { headers: auth }).catch(function () {
      return null;
    });
  }
  log.debug("Leaving routes().");
}

async function main() {
  log.debug("Entering main().");
  moduleLifecycle();
  moduleBounds();
  moduleExpiry();
  if (API_URL) {
    const reachable = await fetch(API_URL + "/oid4vp/verifier/limits")
      .then(function (r) {
        return r.status === 200;
      }).catch(function () {
        return false;
      });
    mustBeAbleTo(reachable, "The api this job was pointed at,", API_URL +
      ", did not answer GET /oid4vp/verifier/limits. Start the stack, or " +
      "set API_URL to one that does — inside the tests container the api " +
      "is https://api:4000.");
    await routes();
  } else {
    log.info("[routes] not run: no API_URL. run-report.js passes one on " +
      "every target with an api; a static site has none.");
  }
  const floor = API_URL ? 49 : 31;
  assert.ok(checks >= floor, "Only " + checks + " checks ran and this file " +
    "defines at least " + floor + ". A section has stopped being called.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
