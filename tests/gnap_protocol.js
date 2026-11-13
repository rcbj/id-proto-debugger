// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: gnap_protocol.js
//
// ---------------------------------------------------------------------------
// THE WHOLE GNAP LIFE OF A GRANT, against iya-sts, with this
// repository's client (client/src/gnap_client.js) and a browser for the
// one part a person does. For each of the four key proofs — httpsig,
// jwsd, jws and mtls — it:
//
//   1. asks for an access token to iya-sts's Shared Signals transmitter
//      (`ssf.read`) with a redirect interaction. iya-sts creates an
//      application for the new key and refuses the scope as its own
//      protected one; the job declares ssf.read on that entry through
//      /admin-api, as an administrator would, and asks again;
//   2. opens the interaction in Chrome, signs in at iya-sts, presses
//      Allow, and reads the finish redirect (RFC 9635 section 4.2.1),
//      checking its `hash` against section 4.2.3;
//   3. continues with the interact_ref (section 5.1), waiting the
//      `wait` iya-sts names and following the fresh continuation token
//      a too_fast answer carries, until the token is issued;
//   4. presents the token at the transmitter (GET /ssf/stream with the
//      GNAP scheme and the key's proof), and once WITHOUT the proof,
//      which a bound token must not survive;
//   5. rotates the token's value at the management URI (section 6.1)
//      and shows the old value is dead and the new one works;
//   6. rotates the CLIENT KEY (section 6.1.1 with section 7.3's nested
//      proofs) — not for mtls, for which section 7.3.2.1 defines no
//      rotation — and shows the new key works and the old one does not;
//   7. revokes the token (section 6.2) and shows it is refused, then
//      revokes the grant (section 5.4);
//   8. forgets the application entry.
//
// The mtls proof is made by this process: the request goes over a TLS
// connection presenting a self-signed certificate, which development
// mode pins (gnap.mtlsTrust auto). POST /gnap/call making the same
// proof on the page's behalf is api_gnap.js's.
//
// In PRODUCT mode an unprovisioned key is refused before anything here
// can happen, and the job FAILS saying so: it is not a pass with the
// interesting half missing.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments.
// ---------------------------------------------------------------------------
"use strict";

const assert = require("assert");
const https = require("https");
const path = require("path");
const webdriver = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const live = require("./gnap_live.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gnap_protocol",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const paths = require("./module_paths.js");
const gnap = paths.requireSharedModule(
  [path.join(__dirname, "..", "client", "src", "gnap_client.js")],
  "client/src/gnap_client.js");

const FINISH = "https://gnap-finish.invalid/done";
const WAIT_MS = 20000;
const insecure = process.env.GNAP_TLS_INSECURE === "1";

function stsBase() {
  log.debug("Entering stsBase().");
  var raw = process.env.GNAP_AS_URL || process.env.STS_URL ||
    process.env.WSTRUST_STS_URL || "https://localhost:8081";
  raw = String(raw).replace(/\/+$/, "").replace(/\/sts$/, "");
  log.debug("Leaving stsBase(). " + raw);
  return raw;
}

function errorOf(json) {
  log.debug("Entering errorOf().");
  var err = json && json.error;
  if (!err) {
    log.debug("Leaving errorOf(). None.");
    return { code: "", description: "" };
  }
  if (typeof err === "string") {
    log.debug("Leaving errorOf(). String.");
    return { code: err, description: "" };
  }
  log.debug("Leaving errorOf().");
  return { code: String(err.code || ""),
    description: String(err.description || "") };
}

// One request, on a connection of its own. A prepared mtls request
// carries the certificate and key it must be sent with; `bare` sends
// it without them, to see the proof refused.
function send(prepared, bare) {
  log.debug("Entering send(). " + prepared.method + " " + prepared.url);
  return new Promise(function (resolve, reject) {
    var url = new URL(prepared.url);
    var body = prepared.body || "";
    var headers = {};
    Object.keys(prepared.headers || {}).forEach(function (name) {
      headers[name] = prepared.headers[name];
    });
    if (body) {
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    var options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: prepared.method,
      headers: headers,
      agent: false,
      rejectUnauthorized: !insecure
    };
    if (prepared.mtls && !bare) {
      options.cert = prepared.mtls.certificatePem;
      options.key = prepared.mtls.privateKeyPem;
    }
    var req = https.request(options, function (res) {
      var chunks = [];
      res.on("data", function (chunk) {
        chunks.push(chunk);
      });
      res.on("end", function () {
        var text = Buffer.concat(chunks).toString("utf8");
        var json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch (e) {
          json = null;
        }
        resolve({ status: res.statusCode, text: text, json: json });
      });
    });
    req.on("error", function (err) {
      reject(err);
    });
    if (body) {
      req.write(body);
    }
    req.end();
    log.debug("Leaving send().");
  });
}

function sleep(ms) {
  log.debug("Entering sleep(). " + ms);
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function makeRecord(proof) {
  log.debug("Entering makeRecord(). " + proof);
  if (proof === "mtls") {
    var pair = live.makeClientCertificate("gnap-protocol-mtls");
    log.debug("Leaving makeRecord(). Certificate.");
    return gnap.recordFromCertificate(pair.certificatePem, pair.keyPem);
  }
  var record = await gnap.generateKey("ES256", "gnap-protocol-" + proof);
  log.debug("Leaving makeRecord().");
  return record;
}

async function ask(record, proof, grantUrl, nonce) {
  log.debug("Entering ask(). " + proof);
  var json = gnap.withClient(gnap.ssfSampleRequest(FINISH, nonce),
    record, proof, { name: "gnap_protocol " + proof,
      uri: "https://client.example/gnap.html" });
  var answer = await send(await gnap.prepare(record, "POST", grantUrl,
    { json: json, proof: proof }));
  log.debug("Leaving ask(). HTTP " + answer.status);
  return answer;
}

// Step 1. The grant, after an administrator has declared the scope.
async function obtainGrant(base, grantUrl, record, proof, nonce,
    application) {
  log.debug("Entering obtainGrant(). " + proof);
  var first = await ask(record, proof, grantUrl, nonce);
  var err = errorOf(first.json);
  if (first.status === 401 && /product mode/.test(err.description)) {
    throw new Error("iya-sts is in product mode, which refuses a key " +
      "nobody provisioned before any grant exists, so the grant " +
      "lifecycle cannot be driven with a key made here. Run against a " +
      "development-mode iya-sts. It answered: " + first.text);
  }
  assert.strictEqual(first.status, 403, proof + ": the first request " +
    "should be refused for the protected scope; got HTTP " +
    first.status + " " + first.text.slice(0, 500));
  assert.strictEqual(err.code, "request_denied");
  assert.ok(err.description.indexOf(application) >= 0 &&
    /protected scope/.test(err.description), proof + ": the refusal " +
    "should name " + application + " and the protected scope: " +
    err.description);
  await live.declareSsfRead(base, application);
  var granted = await ask(record, proof, grantUrl, nonce);
  var json = granted.json || {};
  assert.strictEqual(granted.status, 200, proof + ": after declaring " +
    "ssf.read the grant was refused: " + granted.text.slice(0, 500));
  assert.ok(json.continue && json.continue.uri &&
    json.continue.access_token && json.continue.access_token.value,
    proof + ": the grant has no continuation");
  assert.ok(json.interact && /^https:\/\//.test(json.interact.redirect),
    proof + ": the grant has no redirect interaction");
  assert.strictEqual(typeof json.interact.finish, "string",
    proof + ": the grant has no finish nonce");
  assert.ok(!json.access_token, proof + ": a token was issued before " +
    "anybody approved it");
  log.info(proof + ": grant pending, interaction at " +
    json.interact.redirect);
  log.debug("Leaving obtainGrant().");
  return json;
}

// Step 2. The person, and the finish redirect's hash.
async function approve(driver, grantUrl, grant, nonce, proof) {
  log.debug("Entering approve(). " + proof);
  var finished = await live.approveInBrowser(driver, webdriver,
    grant.interact.redirect, FINISH, "gnap-" + proof, WAIT_MS);
  var found = gnap.finishFromUrl(finished);
  assert.ok(found.ref, proof + ": the finish redirect has no " +
    "interact_ref: " + finished);
  var expected = await gnap.interactionHash(nonce, grant.interact.finish,
    found.ref, grantUrl);
  assert.strictEqual(found.hash, expected, proof + ": the interaction " +
    "hash does not match section 4.2.3");
  log.info(proof + ": approved; the finish hash matches.");
  log.debug("Leaving approve().");
  return found.ref;
}

// Step 3. Continue until the token is issued.
async function continueToToken(record, proof, grant, interactRef) {
  log.debug("Entering continueToToken(). " + proof);
  var cont = grant.continue;
  var tooFast = 0;
  var i;
  for (i = 0; i < 6; i++) {
    await sleep(((cont.wait || 1) * 1000) + 250);
    var answer = await send(await gnap.prepare(record, "POST", cont.uri,
      { token: cont.access_token.value, proof: proof,
        json: { interact_ref: interactRef } }));
    var err = errorOf(answer.json);
    if (err.code === "too_fast") {
      tooFast++;
      assert.ok(answer.json.continue && answer.json.continue.access_token,
        proof + ": too_fast carried no continuation to follow");
      cont = answer.json.continue;
      continue;
    }
    assert.strictEqual(answer.status, 200, proof + ": continuing " +
      "failed: " + answer.text.slice(0, 500));
    var token = answer.json.access_token;
    assert.ok(token && token.value, proof + ": no access token after " +
      "approval: " + answer.text.slice(0, 500));
    assert.ok(token.manage && token.manage.uri &&
      token.manage.access_token && token.manage.access_token.value,
      proof + ": the token has no management URI and token");
    assert.ok(answer.json.subject && answer.json.subject.sub_ids &&
      answer.json.subject.sub_ids.length, proof + ": the subject " +
      "information asked for was not returned");
    log.info(proof + ": token issued after " + tooFast +
      " too_fast answer(s); subject " +
      JSON.stringify(answer.json.subject.sub_ids[0]));
    log.debug("Leaving continueToToken().");
    return { token: token, cont: answer.json.continue || cont };
  }
  log.debug("Leaving continueToToken(). Gave up.");
  throw new Error(proof + ": no token after six continuations");
}

async function atResource(base, record, proof, token) {
  log.debug("Entering atResource(). " + proof);
  var answer = await send(await gnap.prepare(record, "GET",
    base + "/ssf/stream", { token: token, proof: proof }));
  log.debug("Leaving atResource(). HTTP " + answer.status);
  return answer;
}

async function lifecycle(driver, base, grantUrl, proof) {
  log.debug("Entering lifecycle(). " + proof);
  var record = await makeRecord(proof);
  var application = live.applicationFor(record);
  var nonce = "n-" + proof + "-" + Date.now();
  var declared = false;
  try {
    var grant = await obtainGrant(base, grantUrl, record, proof, nonce,
      application);
    declared = true;
    var ref = await approve(driver, grantUrl, grant, nonce, proof);
    var issued = await continueToToken(record, proof, grant, ref);
    var token = issued.token;

    // Step 4.
    var used = await atResource(base, record, proof, token.value);
    assert.strictEqual(used.status, 200, proof + ": the transmitter " +
      "refused the token: " + used.text.slice(0, 500));
    var unproved = await send(await gnap.prepare(record, "GET",
      base + "/ssf/stream", { token: token.value, proof: proof,
        sign: false }), true);
    assert.strictEqual(unproved.status, 401, proof + ": a bound token " +
      "was accepted with no proof: HTTP " + unproved.status);
    log.info(proof + ": the token works at the transmitter with its " +
      "proof and not without it.");

    // Step 5.
    var rotated = await send(await gnap.prepare(record, "POST",
      token.manage.uri, { token: token.manage.access_token.value,
        proof: proof }));
    assert.strictEqual(rotated.status, 200, proof + ": token rotation " +
      "failed: " + rotated.text.slice(0, 500));
    var next = rotated.json.access_token;
    assert.ok(next && next.value && next.value !== token.value,
      proof + ": token rotation returned no new value");
    assert.strictEqual((await atResource(base, record, proof,
      token.value)).status, 401, proof + ": the rotated-away value " +
      "still works");
    assert.strictEqual((await atResource(base, record, proof,
      next.value)).status, 200, proof + ": the new value does not work");
    token = next;
    log.info(proof + ": the token value rotated.");

    // Step 6.
    var signer = record;
    if (proof === "mtls") {
      await assert.rejects(gnap.prepare(record, "POST", token.manage.uri,
        { token: token.manage.access_token.value, proof: proof,
          json: { key: gnap.keyObject(record, proof) },
          rotateTo: record }), /7\.3\.2\.1/,
        "mtls key rotation should be refused by the client");
      log.info("mtls: no key rotation (RFC 9635 section 7.3.2.1).");
    } else {
      var newKey = await gnap.generateKey("ES256", "gnap-rotated-" + proof);
      var moved = await send(await gnap.prepare(record, "POST",
        token.manage.uri, { token: token.manage.access_token.value,
          proof: proof, json: { key: gnap.keyObject(newKey, proof) },
          rotateTo: newKey }));
      assert.strictEqual(moved.status, 200, proof + ": client key " +
        "rotation failed: " + moved.text.slice(0, 500));
      token = moved.json.access_token || token;
      assert.strictEqual((await atResource(base, newKey, proof,
        token.value)).status, 200, proof + ": the new key cannot use " +
        "the token");
      assert.strictEqual((await atResource(base, record, proof,
        token.value)).status, 401, proof + ": the old key still uses " +
        "the token after rotation");
      signer = newKey;
      log.info(proof + ": the client key rotated.");
    }

    // Step 7.
    var revoked = await send(await gnap.prepare(signer, "DELETE",
      token.manage.uri, { token: token.manage.access_token.value,
        proof: proof }));
    assert.ok(revoked.status >= 200 && revoked.status < 300,
      proof + ": token revocation failed: HTTP " + revoked.status + " " +
      revoked.text.slice(0, 300));
    assert.strictEqual((await atResource(base, signer, proof,
      token.value)).status, 401, proof + ": a revoked token still works");
    var cont = issued.cont;
    var ended = await send(await gnap.prepare(signer, "DELETE", cont.uri,
      { token: cont.access_token.value, proof: proof }));
    assert.ok(ended.status >= 200 && ended.status < 300,
      proof + ": grant revocation failed: HTTP " + ended.status + " " +
      ended.text.slice(0, 300));
    log.info(proof + ": token and grant revoked.");
  } finally {
    if (declared) {
      await live.forgetApplication(base, application);
    }
  }
  log.debug("Leaving lifecycle().");
}

async function main() {
  log.debug("Entering main().");
  var base = stsBase();
  var discovery = await send({ method: "OPTIONS", url: base + "/gnap",
    headers: {}, body: "" });
  assert.strictEqual(discovery.status, 200, "OPTIONS /gnap failed: " +
    discovery.text.slice(0, 300));
  var grantUrl = discovery.json.grant_request_endpoint;
  var proofs = discovery.json.key_proofs_supported || [];
  ["httpsig", "jwsd", "jws", "mtls"].forEach(function (one) {
    assert.ok(proofs.indexOf(one) >= 0, "discovery does not offer " + one);
  });
  assert.strictEqual(discovery.json.key_rotation_supported, true,
    "discovery does not offer key rotation");
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
    "--disable-dev-shm-usage", "--window-size=1200,1600");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new webdriver.Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  try {
    var all = ["httpsig", "jwsd", "jws", "mtls"];
    var i;
    for (i = 0; i < all.length; i++) {
      await lifecycle(driver, base, grantUrl, all[i]);
    }
  } finally {
    await driver.quit();
  }
  log.info("gnap_protocol: every proof completed the grant lifecycle.");
  log.debug("Leaving main().");
}

main().catch(function (err) {
  log.error(err && err.stack ? err.stack : String(err));
  process.exitCode = 1;
});
