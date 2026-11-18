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
//      clock this file moves. And LIVE SIGNING (request_uri_method=post,
//      section 5.10) on timers this file fires: a held Wallet answered with
//      the page's object; a Wallet that sent a wallet_nonce answered 503 on
//      a timeout or at the cap (section 5.10.2), never the pre-signed
//      object that cannot carry it; the fallback for one that sent none;
//      and no wait left behind by a delete, an expiry or a shutdown.
//   2. THE ROUTES, over HTTP, when run-report.js hands this job an API_URL
//      (every target with an api; a static site has none). That half is the
//      wiring no module test can see: the statuses, the two media types a
//      Wallet compares (`application/oauth-authz-req+jwt` with no charset,
//      `application/pkix-cert` as bytes), the form body kept VERBATIM past
//      the extended urlencoded parser, the 401 challenge, and a CORS
//      preflight that lets the page send Authorization with PUT and DELETE,
//      and live signing with a real Wallet POST held open while the page
//      PUTs the object it signed for that Wallet.
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
      contentType: "application/x-www-form-urlencoded",
      accept: "application/oauth-authz-req+jwt", rawBody: form });
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
  let firstRedirect = "";
  check("an answer is kept field by field as it arrived, and " +
    "redirect_uri is answered with a fresh response_code (section 8.2)",
  function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/x-www-form-urlencoded; charset=utf-8", rawBody: answer,
      remoteAddress: "192.0.2.7" });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(Object.keys(r.body), ["redirect_uri"]);
    firstRedirect = r.body.redirect_uri;
    assert.match(firstRedirect,
      /^https:\/\/rp\.example\/done\?response_code=[A-Za-z0-9_-]{22}$/,
      "the configured URL plus 128 random bits, base64url (section 8.2: " +
      "\"RECOMMENDED to use a cryptographic random value of 128 bits or " +
      "more\")");
  });
  check("a JSON answer is accepted and recorded as JSON, and gets its own " +
    "response_code", function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/json", rawBody: '{"response":"a.b.c.d.e"}' });
    assert.strictEqual(r.status, 200);
    assert.notStrictEqual(r.body.redirect_uri, firstRedirect,
      "section 8.2: a FRESH value for every answer");
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
    assert.ok(!/Accept|content type/.test(events[1].problem || ""),
      "a POST to request_uri as section 5.10 has it (form, Accept " +
      "application/oauth-authz-req+jwt) reports neither: " +
      events[1].problem);
    assert.strictEqual(events[1].accept, "application/oauth-authz-req+jwt");
    assert.deepStrictEqual(events[3].fields, {
      vp_token: '{"q":["eyJ.a.b~"]}',
      state: ["s 1", "s2"],
      "presentation_submission[0]": "kept"
    });
    assert.strictEqual(events[3].contentType,
      "application/x-www-form-urlencoded; charset=utf-8");
    assert.ok(!("problem" in events[3]), "a form answer reports nothing");
    assert.strictEqual(events[3].redirectUri, firstRedirect,
      "the event records the redirect_uri the Wallet was given");
    assert.strictEqual(events[3].redirectUri, "https://rp.example/done" +
      "?response_code=" + events[3].responseCode,
      "and the fresh value in it");
    assert.deepStrictEqual(events[4].fields, { response: "a.b.c.d.e" });
    assert.strictEqual(events[4].contentType, "application/json");
    assert.match(events[4].problem, /section 8\.2.*MUST.*x-www-form-urlencoded/,
      "a JSON answer is kept AND reported (D2)");
    assert.notStrictEqual(events[4].responseCode, events[3].responseCode);
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

// #469 and #468: what the module REPORTS without refusing. D1 — a POST to
// request_uri that breaks section 5.10's media type or Accept MUST is
// served, and its event names the rule; D2 is in moduleLifecycle(). M3 — every
// redirect_uri carries a fresh 128-bit response_code, beside whatever query
// and fragment the page gave it.
function moduleReportedProblems() {
  log.debug("Entering moduleReportedProblems().");
  log.info("[module] accept and report: section 5.10's POST, section " +
           "8.2's fresh value");
  verifier.reset();
  const cfg = {};
  const made = verifier.create(cfg,
    { redirectUri: "https://rp.example/done?lang=en#top" }, "a");
  const bearer = "Bearer " + made.secret;
  const jws = fakeJws({ client_id: "x509_hash:abc", nonce: "n-p" });
  verifier.publish(cfg, made.id, bearer, { requestObject: jws });
  const RIGHT = "application/oauth-authz-req+jwt";
  const cases = [
    ["a conforming POST", { contentType:
      "application/x-www-form-urlencoded", accept: RIGHT,
      rawBody: "wallet_metadata=%7B%7D" }, null],
    ["Accept in another case, among others, with a q", { contentType:
      "application/x-www-form-urlencoded",
      accept: "application/OAuth-Authz-Req+JWT;q=1, */*;q=0.1",
      rawBody: "wallet_metadata=%7B%7D" }, null],
    ["a JSON body", { contentType: "application/json", accept: RIGHT,
      rawBody: '{"wallet_metadata":{}}' },
     /JSON.*section 5\.10.*MUST use the content type application\/x-www/],
    ["no Accept", { contentType: "application/x-www-form-urlencoded",
      rawBody: "wallet_metadata=%7B%7D" },
     /no Accept header.*section 5\.10/],
    ["Accept */* only", { contentType: "application/x-www-form-urlencoded",
      accept: "*/*", rawBody: "wallet_metadata=%7B%7D" },
     /Accept "\*\/\*"/],
    ["text/plain and no Accept", { contentType: "text/plain",
      rawBody: "wallet_metadata=%7B%7D" },
     /"text\/plain".*content type.*no Accept header/]
  ];
  cases.forEach(function (c, i) {
    check("request_uri POST, " + c[0] + ": served, " + (c[2] ?
      "and the problem is reported" : "and nothing is reported"),
    function () {
      const r = verifier.fetchRequest(cfg, made.id,
        Object.assign({ method: "POST" }, c[1]));
      assert.strictEqual(r.status, 200, "accept and report: it is served");
      assert.strictEqual(r.body, jws);
      const ev = verifier.events(cfg, made.id, bearer, i).events[0];
      assert.strictEqual(ev.kind, "request-fetched");
      // No wallet_nonce, so section 5.10's nonce problem is not in play.
      const own = String(ev.problem || "");
      if (c[2]) {
        assert.match(own, c[2]);
      } else {
        assert.strictEqual(own, "", "nothing but the nonce: " + ev.problem);
      }
    });
  });
  check("a GET is never held to section 5.10's POST rules", function () {
    verifier.fetchRequest(cfg, made.id, { method: "GET" });
    const ev = verifier.events(cfg, made.id, bearer, cases.length).events[0];
    assert.strictEqual(ev.method, "GET");
    assert.ok(!("problem" in ev));
  });
  check("redirect_uri keeps the page's query and fragment, and the " +
    "response_code goes in the query", function () {
    const r = verifier.respond(cfg, made.id, { contentType:
      "application/x-www-form-urlencoded", rawBody: "vp_token=%7B%7D" });
    const u = new URL(r.body.redirect_uri);
    assert.strictEqual(u.origin + u.pathname, "https://rp.example/done");
    assert.strictEqual(u.searchParams.get("lang"), "en");
    assert.strictEqual(u.hash, "#top");
    assert.strictEqual(Buffer.from(u.searchParams.get("response_code"),
      "base64url").length, 16, "128 bits (section 8.2 RECOMMENDS at least)");
  });
  check("every answer gets a different response_code", function () {
    const seen = new Set();
    for (let i = 0; i < 64; i++) {
      const r = verifier.respond(cfg, made.id, { contentType:
        "application/x-www-form-urlencoded", rawBody: "vp_token=%7B%7D" });
      seen.add(new URL(r.body.redirect_uri).searchParams
        .get("response_code"));
    }
    assert.strictEqual(seen.size, 64);
  });
  check("a redirect_uri that is not an absolute URL still gets one, " +
    "before its fragment", function () {
    const odd = verifier.create(cfg, { redirectUri: "done#x" }, "b");
    const r = verifier.respond(cfg, odd.id, { contentType:
      "application/x-www-form-urlencoded", rawBody: "vp_token=%7B%7D" });
    assert.match(r.body.redirect_uri, /^done\?response_code=[\w-]{22}#x$/);
  });
  verifier.reset();
  log.debug("Leaving moduleReportedProblems().");
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

// Timers this file fires, so a live-signing timeout is asserted without
// waiting for one. `live` is what is still scheduled.
function fakeTimers() {
  log.debug("Entering fakeTimers().");
  const live = new Map();
  let next = 0;
  const out = {
    live: live,
    set: function set(fn, ms) {
      log.debug("Entering set(). " + ms);
      next++;
      live.set(next, { fn: fn, ms: ms });
      log.debug("Leaving set().");
      return next;
    },
    clear: function clear(id) {
      log.debug("Entering clear().");
      live.delete(id);
      log.debug("Leaving clear().");
    },
    fireAll: function fireAll() {
      log.debug("Entering fireAll().");
      const due = Array.from(live.values());
      live.clear();
      due.forEach(function (one) {
        one.fn();
      });
      log.debug("Leaving fireAll(). " + due.length);
      return due.length;
    }
  };
  log.debug("Leaving fakeTimers().");
  return out;
}

function walletPost(nonce) {
  log.debug("Entering walletPost().");
  const form = "wallet_metadata=" + encodeURIComponent(JSON.stringify(
    { request_object_signing_alg_values_supported: ["ES256"] })) +
    (nonce ? "&wallet_nonce=" + encodeURIComponent(nonce) : "");
  log.debug("Leaving walletPost().");
  return { method: "POST", contentType: "application/x-www-form-urlencoded",
    accept: "application/oauth-authz-req+jwt", rawBody: form,
    remoteAddress: "192.0.2.9" };
}

async function moduleLiveSigning() {
  log.debug("Entering moduleLiveSigning().");
  log.info("[module] live signing, on timers this file fires");
  verifier.reset();
  const timers = fakeTimers();
  verifier.setTimers(timers);
  try {
    const cfg = { oid4vpVerifierLiveSignWaitMs: 5000,
      oid4vpVerifierMaxPendingSignings: 2 };
    check("limits reports the two live-signing settings, defaulted",
      function () {
        const def = verifier.limits({});
        assert.strictEqual(def.liveSignWaitMs, 15000);
        assert.strictEqual(def.maxPendingSignings, 4);
        const set = verifier.limits(cfg);
        assert.strictEqual(set.liveSignWaitMs, 5000);
        assert.strictEqual(set.maxPendingSignings, 2);
      });
    check("create refuses a liveSigning that is not a boolean", function () {
      const r = verifier.create(cfg, { liveSigning: "yes" }, "a");
      assert.strictEqual(r.status, 400);
      assert.match(r.error, /liveSigning/);
    });
    const made = verifier.create(cfg, { liveSigning: true }, "a");
    const bearer = "Bearer " + made.secret;
    const preSigned = fakeJws({ nonce: "pre" });
    const liveJws = fakeJws({ nonce: "pre", wallet_nonce: "wn-live" });
    check("create answers liveSigning", function () {
      assert.strictEqual(made.liveSigning, true);
      assert.strictEqual(verifier.create(cfg, {}, "b").liveSigning, false);
    });
    verifier.publish(cfg, made.id, bearer, { requestObject: preSigned });
    check("a GET under live signing is served at once", function () {
      const r = verifier.fetchRequest(cfg, made.id, { method: "GET" });
      assert.strictEqual(r.body, preSigned);
      assert.ok(!r.pending);
      assert.strictEqual(timers.live.size, 0);
    });
    const held = verifier.fetchRequest(cfg, made.id, walletPost("wn-live"));
    let fetched;
    check("a POST is held, and request-fetched carries a signingId",
      function () {
        assert.strictEqual(held.ok, true);
        assert.match(held.signingId, /^[0-9a-f]{32}$/);
        assert.ok(held.pending instanceof Promise);
        assert.strictEqual(verifier.pendingCount(made.id), 1);
        assert.strictEqual(timers.live.size, 1);
        assert.strictEqual(Array.from(timers.live.values())[0].ms, 5000);
        const out = verifier.events(cfg, made.id, bearer, 1);
        fetched = out.events[0];
        assert.strictEqual(fetched.kind, "request-fetched");
        assert.strictEqual(fetched.signingId, held.signingId);
        assert.strictEqual(fetched.walletNonce, "wn-live");
        assert.strictEqual(fetched.waitMs, 5000);
        assert.ok(!isNaN(Date.parse(fetched.signBy)));
      });
    check("a PUT for a signingId needs the secret, and an unknown one " +
      "is 404", function () {
      assert.strictEqual(verifier.publishFor(cfg, made.id, held.signingId,
        "", { requestObject: liveJws }).status, 401);
      assert.strictEqual(verifier.publishFor(cfg, made.id, held.signingId,
        "Bearer " + "0".repeat(32), { requestObject: liveJws }).status, 401);
      const unknown = verifier.publishFor(cfg, made.id, "f".repeat(32),
        bearer, { requestObject: liveJws });
      assert.strictEqual(unknown.status, 404);
      assert.match(unknown.error, /signingId/);
      assert.strictEqual(verifier.publishFor(cfg, "e".repeat(32),
        held.signingId, bearer, { requestObject: liveJws }).status, 404);
    });
    check("a PUT that is not a compact JWS is 400 and the Wallet still " +
      "waits", function () {
      const r = verifier.publishFor(cfg, made.id, held.signingId, bearer,
        { requestObject: "a.b" });
      assert.strictEqual(r.status, 400);
      assert.strictEqual(verifier.pendingCount(made.id), 1);
    });
    check("the page's PUT answers the held Wallet", function () {
      const r = verifier.publishFor(cfg, made.id, held.signingId, bearer,
        { requestObject: liveJws });
      assert.deepStrictEqual(r, { ok: true, status: 200 });
      assert.strictEqual(verifier.pendingCount(), 0);
      assert.strictEqual(timers.live.size, 0);
    });
    const answered = await held.pending;
    check("the Wallet gets the live object; request-signed says " +
      "liveSigned true", function () {
      assert.strictEqual(answered.status, 200);
      assert.strictEqual(answered.contentType,
                         "application/oauth-authz-req+jwt");
      assert.strictEqual(answered.body, liveJws);
      const out = verifier.events(cfg, made.id, bearer, fetched.seq + 1);
      assert.strictEqual(out.events.length, 1);
      assert.strictEqual(out.events[0].kind, "request-signed");
      assert.strictEqual(out.events[0].signingId, held.signingId);
      assert.strictEqual(out.events[0].liveSigned, true);
      assert.ok(!("reason" in out.events[0]));
      assert.strictEqual(verifier.publishFor(cfg, made.id, held.signingId,
        bearer, { requestObject: liveJws }).status, 404);
      assert.strictEqual(verifier.fetchRequest(cfg, made.id,
        { method: "GET" }).body, preSigned);
    });
    const late = verifier.fetchRequest(cfg, made.id, walletPost("wn-late"));
    check("a timeout with a wallet_nonce does not fall back", function () {
      assert.ok(late.pending);
      assert.strictEqual(timers.fireAll(), 1);
      assert.strictEqual(verifier.pendingCount(), 0);
    });
    const timedOut = await late.pending;
    check("OpenID4VP 5.10/5.10.2: the Wallet that sent a wallet_nonce is " +
      "answered 503, never the object that cannot carry it", function () {
      assert.strictEqual(timedOut.ok, false);
      assert.strictEqual(timedOut.status, 503);
      assert.strictEqual(timedOut.error, "temporarily_unavailable");
      assert.match(timedOut.error_description, /wallet_nonce/);
      assert.ok(!("body" in timedOut));
      const out = verifier.events(cfg, made.id, bearer, 0);
      const last = out.events[out.events.length - 1];
      assert.strictEqual(last.kind, "request-signed");
      assert.strictEqual(last.signingId, late.signingId);
      assert.strictEqual(last.liveSigned, false);
      assert.strictEqual(last.httpStatus, 503);
      assert.match(last.reason, /oid4vpVerifierLiveSignWaitMs \(5000 ms\)/);
      assert.match(last.reason, /5\.10\.2/);
      assert.strictEqual(verifier.publishFor(cfg, made.id, late.signingId,
        bearer, { requestObject: liveJws }).status, 404);
    });
    const bare = verifier.fetchRequest(cfg, made.id, walletPost(""));
    check("a POST without wallet_nonce still waits", function () {
      assert.ok(bare.pending);
      assert.strictEqual(timers.fireAll(), 1);
    });
    const fellBack = await bare.pending;
    check("and on a timeout falls back to the pre-signed object, which " +
      "has no nonce to carry", function () {
      assert.strictEqual(fellBack.status, 200);
      assert.strictEqual(fellBack.body, preSigned);
      const out = verifier.events(cfg, made.id, bearer, 0);
      const last = out.events[out.events.length - 1];
      assert.strictEqual(last.liveSigned, false);
      assert.ok(!("httpStatus" in last));
      assert.match(last.reason, /sent no wallet_nonce/);
    });
    const noNonce = verifier.fetchRequest(cfg, made.id, walletPost("gone"));
    check("a Wallet that goes away releases its wait", function () {
      assert.ok(noNonce.pending);
      noNonce.cancel();
      assert.strictEqual(verifier.pendingCount(), 0);
      assert.strictEqual(timers.live.size, 0);
    });
    const cancelled = await noNonce.pending;
    check("the cancelled wait records why, and serves nothing", function () {
      assert.strictEqual(cancelled.ok, false);
      assert.ok(!("body" in cancelled));
      const out = verifier.events(cfg, made.id, bearer, 0);
      const last = out.events[out.events.length - 1];
      assert.match(last.reason, /closed/);
      assert.ok(!("httpStatus" in last));
    });
    const one = verifier.fetchRequest(cfg, made.id, walletPost("a"));
    const two = verifier.fetchRequest(cfg, made.id, walletPost("b"));
    const three = verifier.fetchRequest(cfg, made.id, walletPost("c"));
    const four = verifier.fetchRequest(cfg, made.id, walletPost(""));
    check("oid4vpVerifierMaxPendingSignings: one more with a wallet_nonce " +
      "is answered 503 at once (section 5.10.2)", function () {
        assert.ok(one.pending && two.pending);
        assert.ok(!three.pending);
        assert.strictEqual(three.status, 503);
        assert.strictEqual(three.error, "temporarily_unavailable");
        assert.ok(!("body" in three));
        assert.strictEqual(verifier.pendingCount(made.id), 2);
        const out = verifier.events(cfg, made.id, bearer, 0);
        const tail = out.events.slice(-4);
        assert.strictEqual(tail[0].kind, "request-fetched");
        assert.ok(!("signingId" in tail[0]));
        assert.strictEqual(tail[0].walletNonce, "c");
        assert.strictEqual(tail[1].kind, "request-signed");
        assert.strictEqual(tail[1].liveSigned, false);
        assert.strictEqual(tail[1].httpStatus, 503);
        assert.match(tail[1].reason, /oid4vpVerifierMaxPendingSignings is 2/);
        assert.ok(!("walletNonce" in tail[2]));
        assert.ok(!("httpStatus" in tail[3]));
      });
    check("and one more without a wallet_nonce gets the pre-signed object",
      function () {
        assert.ok(!four.pending);
        assert.strictEqual(four.status, 200);
        assert.strictEqual(four.body, preSigned);
      });
    check("DELETE releases every held Wallet and clears every timer",
      function () {
        assert.strictEqual(timers.live.size, 2);
        assert.strictEqual(verifier.remove(cfg, made.id, bearer).status, 200);
        assert.strictEqual(verifier.pendingCount(), 0);
        assert.strictEqual(timers.live.size, 0);
      });
    const released = await Promise.all([one.pending, two.pending]);
    check("a Wallet released by a DELETE is told the session is gone",
      function () {
        released.forEach(function (r) {
          assert.strictEqual(r.status, 404);
          assert.strictEqual(r.error, "not_found");
        });
      });
    let t = 5000000;
    verifier.setClock(function () {
      return t;
    });
    const exp = verifier.create({ oid4vpVerifierIdleTtlMs: 300 },
                                { liveSigning: true }, "a");
    verifier.publish(cfg, exp.id, "Bearer " + exp.secret,
                     { requestObject: preSigned });
    const waiting = verifier.fetchRequest(cfg, exp.id, walletPost("x"));
    check("expiry, found by the sweep, releases the wait and its timer",
      function () {
        assert.ok(waiting.pending);
        assert.strictEqual(timers.live.size, 1);
        t += 1000;
        verifier.limits({ oid4vpVerifierIdleTtlMs: 300 });
        assert.strictEqual(verifier.pendingCount(), 0);
        assert.strictEqual(timers.live.size, 0);
      });
    assert.strictEqual((await waiting.pending).status, 404);
    verifier.setClock(null);
    const sd = verifier.create(cfg, { liveSigning: true }, "a");
    verifier.publish(cfg, sd.id, "Bearer " + sd.secret,
                     { requestObject: preSigned });
    const atShutdown = verifier.fetchRequest(cfg, sd.id, walletPost("y"));
    check("shutdown() releases every wait and clears every timer",
      function () {
        assert.strictEqual(verifier.shutdown(), 1);
        assert.strictEqual(verifier.pendingCount(), 0);
        assert.strictEqual(timers.live.size, 0);
        assert.strictEqual(verifier.limits({}).held, 0);
      });
    assert.strictEqual((await atShutdown.pending).status, 404);
    const off = verifier.create(cfg, {}, "a");
    verifier.publish(cfg, off.id, "Bearer " + off.secret,
                     { requestObject: preSigned });
    check("liveSigning off: a POST is served at once, exactly as before",
      function () {
        const r = verifier.fetchRequest(cfg, off.id, walletPost("z"));
        assert.deepStrictEqual(Object.keys(r).sort(),
                               ["body", "contentType", "ok", "status"]);
        assert.strictEqual(r.body, preSigned);
        assert.strictEqual(timers.live.size, 0);
        const ev = verifier.events(cfg, off.id, "Bearer " + off.secret, 0)
          .events;
        assert.deepStrictEqual(ev.map(function (e) {
          return e.kind;
        }), ["request-fetched"]);
        assert.ok(!("signingId" in ev[0]));
        assert.strictEqual(ev[0].walletNonce, "z");
        assert.match(ev[0].problem, /wallet_nonce.*5\.10/);
        verifier.fetchRequest(cfg, off.id, walletPost(""));
        const plain = verifier.events(cfg, off.id, "Bearer " + off.secret,
                                      1).events[0];
        assert.ok(!("problem" in plain), "no nonce, nothing to report");
      });
  } finally {
    verifier.setClock(null);
    verifier.setTimers(null);
    verifier.reset();
  }
  log.debug("Leaving moduleLiveSigning().");
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
      "wallet_metadata=%7B%22a%22%3A1%7D&wallet_nonce=wn-http",
      headers: { Accept: "application/oauth-authz-req+jwt" } });
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
    check("the response_uri answers redirect_uri with a fresh " +
      "response_code (section 8.2)", function () {
        assert.strictEqual(answered.status, 200, answered.text);
        assert.match(answered.body.redirect_uri,
          /^https:\/\/rp\.example\/after\?response_code=[\w-]{22}$/);
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
        assert.strictEqual(drained.body.events[1].accept,
          "application/oauth-authz-req+jwt", "server.js hands the module " +
          "the Wallet's Accept header");
        assert.ok(!/Accept|content type/.test(
          drained.body.events[1].problem || ""),
          String(drained.body.events[1].problem));
        assert.strictEqual(drained.body.events[3].responseCode,
          new URL(answered.body.redirect_uri).searchParams
            .get("response_code"));
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

// Poll the events, as the page does, until one matches or `ms` runs out.
async function pollFor(base, auth, match, ms) {
  log.debug("Entering pollFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const got = await call("GET", base + "/events?after=0", { headers: auth });
    const hit = (got.body && got.body.events || []).filter(match)[0];
    if (hit) {
      log.debug("Leaving pollFor(). Found " + hit.seq);
      return hit;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  log.debug("Leaving pollFor(). Not found.");
  return null;
}

async function liveRoutes() {
  log.debug("Entering liveRoutes().");
  log.info("[routes] live signing over HTTP");
  const limits = await call("GET", "/oid4vp/verifier/limits");
  check("limits reports liveSignWaitMs and maxPendingSignings",
    function () {
      assert.ok(limits.body.liveSignWaitMs > 0);
      assert.ok(limits.body.maxPendingSignings > 0);
    });
  const made = await call("POST", "/oid4vp/verifier",
    { json: { liveSigning: true } });
  check("POST /oid4vp/verifier with liveSigning answers it", function () {
    assert.strictEqual(made.status, 201, made.text);
    assert.strictEqual(made.body.liveSigning, true);
  });
  const base = "/oid4vp/verifier/" + made.body.id;
  const auth = { Authorization: "Bearer " + made.body.secret };
  try {
    const preSigned = fakeJws({ nonce: "pre-http" });
    const liveJws = fakeJws({ nonce: "pre-http", wallet_nonce: "wn-held" });
    await call("PUT", base + "/request", { headers: auth,
      json: { requestObject: preSigned } });
    const started = Date.now();
    const wallet = call("POST", base + "/request", { form:
      "wallet_metadata=%7B%7D&wallet_nonce=wn-held" });
    const fetched = await pollFor(base, auth, function (e) {
      return e.kind === "request-fetched" && e.signingId;
    }, limits.body.liveSignWaitMs);
    check("the page sees request-fetched with a signingId while the " +
      "Wallet is held", function () {
      assert.ok(fetched, "no request-fetched event with a signingId");
      assert.strictEqual(fetched.walletNonce, "wn-held");
      assert.strictEqual(fetched.waitMs, limits.body.liveSignWaitMs);
    });
    const signPath = base + "/request/" + fetched.signingId;
    const anon = await call("PUT", signPath,
      { json: { requestObject: liveJws } });
    const unknown = await call("PUT", base + "/request/" + "f".repeat(32),
      { headers: auth, json: { requestObject: liveJws } });
    const typed = await call("PUT", signPath,
      { headers: auth, json: { requestObject: 5 } });
    check("the signing PUT: 401 without the secret, 404 for an unknown " +
      "signingId, the model's 400 for a wrong type", function () {
      assert.strictEqual(anon.status, 401);
      assert.match(anon.headers.get("www-authenticate") || "", /^Bearer/);
      assert.strictEqual(unknown.status, 404);
      assert.match(unknown.body.error, /signingId/);
      assert.strictEqual(typed.status, 400);
      assert.strictEqual(typed.body.code, "EMODELREQUEST");
    });
    const signed = await call("PUT", signPath,
      { headers: auth, json: { requestObject: liveJws } });
    const answered = await wallet;
    check("the held Wallet is answered with the page's object", function () {
      assert.strictEqual(signed.status, 200, signed.text);
      assert.deepStrictEqual(signed.body, { ok: true });
      assert.strictEqual(answered.status, 200);
      assert.strictEqual(answered.headers.get("content-type"),
                         "application/oauth-authz-req+jwt");
      assert.strictEqual(answered.text, liveJws);
      assert.ok(Date.now() - started < limits.body.liveSignWaitMs);
    });
    const after = await call("GET", base + "/events?after=0",
                             { headers: auth });
    check("request-signed says liveSigned true", function () {
      const last = after.body.events[after.body.events.length - 1];
      assert.strictEqual(last.kind, "request-signed");
      assert.strictEqual(last.signingId, fetched.signingId);
      assert.strictEqual(last.liveSigned, true);
    });
    const again = await call("PUT", signPath,
      { headers: auth, json: { requestObject: liveJws } });
    const got = await call("GET", base + "/request");
    check("a second PUT is 404, and GET still serves the pre-signed object",
      function () {
        assert.strictEqual(again.status, 404);
        assert.strictEqual(got.text, preSigned);
      });
    // Fill the session's waits with Wallets that each sent a wallet_nonce;
    // the next one cannot be signed for, and section 5.10.2 has it answered
    // with an HTTP error at once rather than the pre-signed object.
    const held = [];
    for (let i = 0; i < limits.body.maxPendingSignings; i++) {
      held.push(call("POST", base + "/request", { form:
        "wallet_nonce=wn-hold-" + i }));
    }
    let allHeld = false;
    const holdUntil = Date.now() + limits.body.liveSignWaitMs;
    while (!allHeld && Date.now() < holdUntil) {
      const seen = await call("GET", base + "/events?after=0",
                              { headers: auth });
      allHeld = (seen.body.events || []).filter(function (e) {
        return e.signingId && /^wn-hold-/.test(String(e.walletNonce));
      }).length === limits.body.maxPendingSignings;
      if (!allHeld) {
        await new Promise(function (resolve) {
          setTimeout(resolve, 100);
        });
      }
    }
    const refused = await call("POST", base + "/request", { form:
      "wallet_nonce=wn-one-too-many" });
    check("at oid4vpVerifierMaxPendingSignings, a Wallet with a " +
      "wallet_nonce is answered 503 temporarily_unavailable", function () {
      assert.ok(allHeld, "the held Wallets were never recorded");
      assert.strictEqual(refused.status, 503, refused.text);
      assert.strictEqual(refused.body.error, "temporarily_unavailable");
      assert.match(refused.body.error_description, /wallet_nonce/);
    });
    await call("DELETE", base, { headers: auth });
    const releasedAll = await Promise.all(held);
    check("a DELETE releases the held Wallets with a 404", function () {
      releasedAll.forEach(function (r) {
        assert.strictEqual(r.status, 404);
      });
    });
  } finally {
    await call("DELETE", base, { headers: auth }).catch(function () {
      return null;
    });
  }
  log.debug("Leaving liveRoutes().");
}

async function main() {
  log.debug("Entering main().");
  moduleLifecycle();
  moduleReportedProblems();
  moduleBounds();
  moduleExpiry();
  await moduleLiveSigning();
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
    await liveRoutes();
  } else {
    log.info("[routes] not run: no API_URL. run-report.js passes one on " +
      "every target with an api; a static site has none.");
  }
  const floor = API_URL ? 90 : 63;
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
