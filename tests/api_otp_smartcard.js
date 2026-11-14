// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_otp_smartcard.js
//
// ---------------------------------------------------------------------------
// THE API'S TWO SMART-CARD ENDPOINT FAMILIES, OVER HTTP, AGAINST THE RUNNING
// SERVICE.
//
// POST /otp/verify sends a Yubico OTP validation request the page has
// already signed, as Validation Protocol 2.0 says: an HTTP GET of
// /wsapi/2.0/verify with the signed fields as the query string. This job is
// the far end. It runs a verifier of its own on an HTTPS port in this
// process, points the api at it, and checks what arrives and what comes
// back:
//
//   * the request is a GET, to the verifier's path, carrying exactly the
//     fields the page signed and in the same text — the signature `h` is over
//     that text, so a re-encoded field is a request YubiCloud rejects as
//     BAD_SIGNATURE;
//   * the verifier's answer reaches the caller verbatim, as a 200 whatever
//     the verifier said, because status=REPLAYED_OTP or an HTTP 4xx is what
//     the page exists to show; an exchange trace is attached when asked;
//   * every shape this service must refuse is a 400 naming the problem, and
//     sends nothing;
//   * a verifier that cannot be reached is a 502.
//
// The smart-card reader relay sends ANY APDU to a card on the machine the api
// runs on, which is why it is off unless an operator turns it on. On this
// stack it is off, and that is asserted: /smartcard/limits says so and both
// relay endpoints answer 403 rather than reaching for a reader. The relay's
// exchange logic is driven in node by smartcard_engine.js with a scripted
// card, which is the only card any test here has.
//
// The api must be able to open a connection to this process, which on the
// containerized stack it does by the compose name `tests`
// (OTP_VERIFIER_HOST overrides it).
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
const path = require("path");
const paths = require("./module_paths.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "api_otp_smartcard",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

var apiUrl = process.env.API_URL || "https://localhost:4000";
var verifierHost = process.env.OTP_VERIFIER_HOST || "tests";

function sharedModule(dir, name) {
  log.debug("Entering sharedModule().");
  const found = paths.requireSharedModule(
    [path.join(__dirname, "..", dir, name), path.join(__dirname, name)],
    dir + "/" + name);
  log.debug("Leaving sharedModule().");
  return found;
}

const keys = sharedModule(path.join("client", "src"), "key_material.js");
const x509 = sharedModule(path.join("client", "src"), "x509.js");

// A 44-character Yubico OTP in modhex, the current form, and a
// well-formed signed body around it. The values are made up; nothing here
// checks an AES key, because the api does not have one — the page does.
const OTP = "cccjgjgkhcbbirdrfdnlnghhfgrtnnlgedjlftrbdeut";
const NONCE = "aBcDeFgHiJkLmNoPqRsT";
const SIGNED = "id=87&nonce=" + NONCE + "&otp=" + OTP +
  "&timestamp=1&h=dGVzdHNpZ25hdHVyZQ%2Bx%2F%3D";

async function call(method, route, body) {
  log.debug("Entering call(). " + method + " " + route);
  const init = { method: method, headers: {} };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(apiUrl + route, init);
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    json = null;
  }
  log.debug("Leaving call(). " + response.status);
  return { status: response.status, json: json, text: text };
}

// A Validation Protocol 2.0 verifier: it records each request and answers
// with whatever `answer` currently says.
async function startVerifier() {
  log.debug("Entering startVerifier().");
  const key = await keys.generateKeyPair("ec-p256");
  const cert = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=" + verifierHost + ",O=idptools",
    subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("tls-server")
  });
  const state = { seen: [], answer: { status: 200, body: "" } };
  const server = https.createServer({ key: key.privatePem, cert: cert.pem },
      function (req, res) {
    state.seen.push({ method: req.method, url: req.url,
                      userAgent: req.headers["user-agent"] || "" });
    res.writeHead(state.answer.status, { "Content-Type": "text/plain" });
    res.end(state.answer.body);
  });
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  state.server = server;
  state.base = "https://" + verifierHost + ":" + server.address().port;
  log.debug("Leaving startVerifier(). " + state.base);
  return state;
}

// A verifier answer in the protocol's own line format.
function protocolAnswer(status) {
  log.debug("Entering protocolAnswer().");
  const text = "h=c2lnbmVkYnl0aGV2ZXJpZmllcg==\r\n" +
    "t=2026-11-13T00:00:00Z0001\r\n" +
    "otp=" + OTP + "\r\nnonce=" + NONCE + "\r\n" +
    "sl=100\r\nstatus=" + status + "\r\n";
  log.debug("Leaving protocolAnswer().");
  return text;
}

async function limits() {
  log.debug("Entering limits().");
  const otp = await call("GET", "/otp/limits");
  assert.strictEqual(otp.status, 200, otp.text);
  assert.strictEqual(otp.json.method, "GET");
  assert.strictEqual(otp.json.defaultVerifier,
      "https://api.yubico.com/wsapi/2.0/verify");
  assert.strictEqual(otp.json.servers.length, 5);
  assert.ok(otp.json.maxBodyBytes > 0);
  const card = await call("GET", "/smartcard/limits");
  assert.strictEqual(card.status, 200, card.text);
  assert.strictEqual(card.json.enabled, false,
      "the reader relay is on for this stack: " + card.text);
  assert.strictEqual(card.json.available, false);
  assert.ok(/off/i.test(card.json.reason), card.json.reason);
  log.info("PASS  /otp/limits names the protocol and servers; " +
           "/smartcard/limits says the relay is off");
  log.debug("Leaving limits().");
}

async function relayIsOff() {
  log.debug("Entering relayIsOff().");
  const readers = await call("GET", "/smartcard/readers");
  assert.strictEqual(readers.status, 403, readers.text);
  const sent = await call("POST", "/smartcard/transmit",
      { reader: "Yubico YubiKey OTP+FIDO+CCID 00 00",
        apdus: ["00a4040008a000000308000010"] });
  assert.strictEqual(sent.status, 403, sent.text);
  assert.ok(/off/i.test(sent.json.error), sent.json.error);
  log.info("PASS  with the relay off, listing readers and sending an APDU " +
           "are both 403");
  log.debug("Leaving relayIsOff().");
}

async function verifiedThroughTheApi(verifier) {
  log.debug("Entering verifiedThroughTheApi().");
  verifier.answer = { status: 200, body: protocolAnswer("OK") };
  const before = verifier.seen.length;
  const answer = await call("POST", "/otp/verify", {
    body: SIGNED, verifier: verifier.base + "/wsapi/2.0/verify",
    sslValidate: false, http_trace: true });
  assert.strictEqual(answer.status, 200, answer.text);
  assert.strictEqual(verifier.seen.length, before + 1,
      "the verifier was not called (is " + verifier.base +
      " reachable from the api? set OTP_VERIFIER_HOST)");
  const got = verifier.seen[verifier.seen.length - 1];
  assert.strictEqual(got.method, "GET");
  // The query arrives byte for byte as the page signed it.
  assert.strictEqual(got.url, "/wsapi/2.0/verify?" + SIGNED);
  assert.ok(/^Identity Protocol Debugger\//.test(got.userAgent),
      "the User-Agent does not name the debugger: " + got.userAgent);
  assert.strictEqual(answer.json.ok, true);
  assert.strictEqual(answer.json.status, 200);
  assert.strictEqual(answer.json.body, protocolAnswer("OK"));
  assert.ok(answer.json.http_exchange, "no exchange trace was attached");
  log.info("PASS  POST /otp/verify sends the signed fields unchanged as a " +
           "GET and returns the verifier's answer verbatim, with a trace");
  log.debug("Leaving verifiedThroughTheApi().");
}

async function verifierRefusalsAreShown(verifier) {
  log.debug("Entering verifierRefusalsAreShown().");
  verifier.answer = { status: 200, body: protocolAnswer("REPLAYED_OTP") };
  const replayed = await call("POST", "/otp/verify", {
    body: SIGNED, verifier: verifier.base + "/wsapi/2.0/verify",
    sslValidate: "false" });
  assert.strictEqual(replayed.status, 200, replayed.text);
  assert.ok(/status=REPLAYED_OTP/.test(replayed.json.body));
  assert.strictEqual(replayed.json.http_exchange, undefined,
      "a trace was attached when none was asked for");
  verifier.answer = { status: 403, body: "forbidden" };
  const forbidden = await call("POST", "/otp/verify", {
    body: SIGNED, verifier: verifier.base + "/wsapi/2.0/verify",
    sslValidate: false });
  assert.strictEqual(forbidden.status, 200, forbidden.text);
  assert.strictEqual(forbidden.json.ok, false);
  assert.strictEqual(forbidden.json.status, 403);
  log.info("PASS  a verifier's REPLAYED_OTP and its HTTP 403 both reach the " +
           "caller as a 200 carrying them");
  log.debug("Leaving verifierRefusalsAreShown().");
}

async function shapesAreRefused(verifier) {
  log.debug("Entering shapesAreRefused().");
  const before = verifier.seen.length;
  const at = verifier.base + "/wsapi/2.0/verify";
  const refusals = [
    [{ verifier: at }, /form/],
    [{ body: SIGNED + "\r\nX-Injected: 1", verifier: at }, /line break/],
    [{ body: SIGNED + "&" + "x".repeat(4000), verifier: at }, /longer/],
    [{ body: "=nameless", verifier: at }, /not a form/],
    [{ body: SIGNED + "&extra=1", verifier: at }, /unknown field/],
    [{ body: SIGNED.replace("id=87", "id=eighty"), verifier: at },
     /client id/],
    [{ body: SIGNED.replace(OTP, "abc"), verifier: at }, /modhex/],
    [{ body: SIGNED.replace(NONCE, "short"), verifier: at }, /nonce/],
    [{ body: SIGNED.replace(/h=[^&]*/, "h=not*base64"), verifier: at },
     /base64/],
    [{ body: SIGNED, server: 9 }, /YubiCloud server/],
    [{ body: SIGNED, verifier: "http://" + verifierHost + "/v" }, /https/],
    [{ body: SIGNED, verifier: "https://u:p@" + verifierHost + "/v" },
     /userinfo/],
    [{ body: SIGNED, verifier: at + "?x=1" }, /query string/],
    [{ body: SIGNED, verifier: "not a url" }, /not a URL/],
    [{ body: SIGNED, verifier: "" + "https://" + verifierHost + "/a/../b" },
     /\.\./]
  ];
  for (const [body, why] of refusals) {
    const answer = await call("POST", "/otp/verify", body);
    assert.strictEqual(answer.status, 400,
        JSON.stringify(body).slice(0, 120) + " -> " + answer.text);
    assert.ok(why.test(answer.json.error),
        "refused for the wrong reason: " + answer.json.error);
  }
  assert.strictEqual(verifier.seen.length, before,
      "a refused request still reached the verifier");
  log.info("PASS  " + refusals.length + " malformed requests are each a 400 " +
           "naming the problem, and none is sent");
  log.debug("Leaving shapesAreRefused().");
}

async function unreachableIs502(verifier) {
  log.debug("Entering unreachableIs502().");
  const port = verifier.server.address().port;
  // The port this process just closed: nothing is listening on it.
  await new Promise(function (resolve) {
    verifier.server.close(resolve);
  });
  const answer = await call("POST", "/otp/verify", {
    body: SIGNED,
    verifier: "https://" + verifierHost + ":" + port + "/wsapi/2.0/verify",
    sslValidate: false, http_trace: true });
  assert.strictEqual(answer.status, 502, answer.text);
  assert.ok(/could not be reached/.test(answer.json.error),
      answer.json.error);
  log.info("PASS  a verifier that cannot be reached is a 502");
  log.debug("Leaving unreachableIs502().");
}

async function test() {
  log.debug("Entering test().");
  let verifier = null;
  try {
    await limits();
    await relayIsOff();
    verifier = await startVerifier();
    await verifiedThroughTheApi(verifier);
    await verifierRefusalsAreShown(verifier);
    await shapesAreRefused(verifier);
    await unreachableIs502(verifier);
    verifier = null;
    log.info("Test completed successfully.");
  } catch (e) {
    log.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  } finally {
    if (verifier && verifier.server.listening) {
      verifier.server.close();
    }
  }
  log.debug("Leaving test().");
}

test();
