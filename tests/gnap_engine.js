// File: gnap_engine.js
//
// ---------------------------------------------------------------------------
// The GNAP client instance, driven in node. The signature checks use
// node's own crypto, which is a second implementation of the same
// bytes. The live half posts one signed grant to iya-sts and reads
// the answer. It does not register a client and it does not change
// that server. A continuation token, when one is issued, is deleted.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments,
// so node ignores that pair. Do not add commander here without
// declaring `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gnap_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");

function load(name) {
  log.debug("Entering load().");
  var loaded = paths.requireSharedModule(
    [path.join(SRC, name)], "client/src/" + name);
  log.debug("Leaving load().");
  return loaded;
}

function loadProxy() {
  log.debug("Entering loadProxy().");
  var loaded = paths.requireSharedModule([
    path.join(__dirname, "gnap_proxy.js"),
    path.join(REPO, "api", "gnap_proxy.js")
  ], "api/gnap_proxy.js");
  log.debug("Leaving loadProxy().");
  return loaded;
}

const gnap = load("gnap_client.js");
const proxy = loadProxy();
var localInsecure = process.env.GNAP_TLS_INSECURE === "1";

function stsBase() {
  log.debug("Entering stsBase().");
  var raw = process.env.GNAP_AS_URL || process.env.WSTRUST_STS_URL ||
    process.env.OID4VCI_ISSUER_URL || "https://localhost:8081";
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
  return {
    code: String(err.code || ""),
    description: String(err.description || "")
  };
}

function postOnce(prepared, insecure) {
  log.debug("Entering postOnce().");
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
    var req = https.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: prepared.method,
      headers: headers,
      rejectUnauthorized: !insecure
    }, function (res) {
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
        log.debug("Leaving postOnce(). HTTP " + res.statusCode);
        resolve({
          status: res.statusCode,
          text: text,
          json: json
        });
      });
    });
    req.on("error", function (err) {
      log.debug("Leaving postOnce(). " + err.code);
      reject(err);
    });
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function certError(err) {
  log.debug("Entering certError().");
  var code = err && err.code;
  var yes = code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "CERT_HAS_EXPIRED";
  log.debug("Leaving certError(). " + yes);
  return yes;
}

async function post(prepared) {
  log.debug("Entering post().");
  var host = new URL(prepared.url).hostname;
  var local = host === "localhost" || host === "127.0.0.1";
  if (localInsecure) {
    var open = await postOnce(prepared, true);
    log.debug("Leaving post(). Insecure.");
    return open;
  }
  try {
    var verified = await postOnce(prepared, false);
    log.debug("Leaving post(). Verified.");
    return verified;
  } catch (e) {
    if (certError(e) && local && !process.env.NODE_EXTRA_CA_CERTS) {
      localInsecure = true;
      log.info("The local authorization server certificate is not " +
        "in the trust store. Later calls to this host skip " +
        "verification.");
      var retried = await postOnce(prepared, true);
      log.debug("Leaving post(). Local retry.");
      return retried;
    }
    log.debug("Leaving post(). Failed.");
    throw e;
  }
}

async function signatureAgreesWithNode() {
  log.debug("Entering signatureAgreesWithNode().");
  var record = await gnap.generateKey("ES256", "node-es256");
  var prepared = await gnap.prepare(record, "POST",
    "https://as.example/gnap", {
      json: { access_token: { access: [{ type: "ssf",
        actions: ["read"] }] } },
      proof: "httpsig",
      httpsig: { created: 1700000000, nonce: "n-fixed",
        keyid: record.kid }
    });
  var base = prepared.signatures[0].base;
  var match = /sig1=:([A-Za-z0-9+/=]+):/.exec(
    prepared.headers.Signature);
  assert.ok(match, "the Signature header carries sig1");
  var key = crypto.createPublicKey({
    key: record.publicJwk, format: "jwk"
  });
  var ok = crypto.verify("sha256", Buffer.from(base, "utf8"), {
    key: key, dsaEncoding: "ieee-p1363"
  }, Buffer.from(match[1], "base64"));
  assert.ok(ok, "node did not verify the Web Crypto ES256 signature");
  assert.ok(prepared.headers["Content-Digest"].indexOf("sha-256=:") ===
    0);
  log.info("OK — node verifies the ES256 HTTP message signature.");
  log.debug("Leaving signatureAgreesWithNode().");
}

async function ed25519AgreesWithNode() {
  log.debug("Entering ed25519AgreesWithNode().");
  var record = await gnap.generateKey("EdDSA", "node-ed25519");
  var prepared = await gnap.prepare(record, "POST",
    "https://as.example/gnap", {
      json: { subject: { sub_id_formats: ["opaque"] } },
      proof: "httpsig",
      httpsig: { created: 1700000000, nonce: "n-ed",
        keyid: record.kid }
    });
  var match = /sig1=:([A-Za-z0-9+/=]+):/.exec(
    prepared.headers.Signature);
  var key = crypto.createPublicKey({
    key: record.publicJwk, format: "jwk"
  });
  var ok = crypto.verify(null, Buffer.from(
    prepared.signatures[0].base, "utf8"), key,
    Buffer.from(match[1], "base64"));
  assert.ok(ok, "node did not verify the Ed25519 signature");
  log.info("OK — node verifies the Ed25519 HTTP message signature.");
  log.debug("Leaving ed25519AgreesWithNode().");
}

async function digestAndHashAgree() {
  log.debug("Entering digestAndHashAgree().");
  var body = "{\"a\":1}";
  var digest = await gnap.contentDigest(body);
  var hash = crypto.createHash("sha256").update(body).digest("base64");
  assert.strictEqual(digest, "sha-256=:" + hash + ":");
  var got = await gnap.interactionHash("client", "server", "ref",
    "https://as.example/gnap");
  var expect = crypto.createHash("sha256")
    .update("client\nserver\nref\nhttps://as.example/gnap")
    .digest("base64url");
  assert.strictEqual(got, expect);
  var other = await gnap.interactionHash("client", "server", "ref",
    "https://as.example/gnap", "sha-512");
  assert.notStrictEqual(other, got);
  await assert.rejects(function () {
    return gnap.interactionHash("c", "s", "r", "https://as.example/gnap",
      "sha3-512");
  });
  log.info("OK — the digest and the interaction hash match node.");
  log.debug("Leaving digestAndHashAgree().");
}

async function rotationCoversTheFirstSignature() {
  log.debug("Entering rotationCoversTheFirstSignature().");
  var current = await gnap.generateKey("ES256", "rotate-old");
  var next = await gnap.generateKey("ES256", "rotate-new");
  var prepared = await gnap.prepare(current, "POST",
    "https://as.example/token/manage", {
      json: { key: gnap.keyObject(next, "httpsig") },
      token: "continue-token",
      proof: "httpsig",
      rotateTo: next
    });
  assert.strictEqual(prepared.signatures.length, 2);
  assert.strictEqual(prepared.signatures[1].label, "new-key");
  assert.ok(prepared.signatures[1].base.indexOf(
    "\"signature\";key=\"sig1\"") >= 0);
  assert.ok(prepared.headers.Signature.indexOf("new-key=:") >= 0);
  var published = gnap.keyObject(current, "httpsig");
  assert.strictEqual(published.proof, "httpsig");
  assert.ok(published.jwk.x);
  assert.ok(published.jwk.d === undefined);
  log.info("OK — rotation signs the first signature, and the " +
    "public key omits d.");
  log.debug("Leaving rotationCoversTheFirstSignature().");
}

function theProxyRefusesWhatItShould() {
  log.debug("Entering theProxyRefusesWhatItShould().");
  function refused(input) {
    var out = proxy.describeRequest(input, {});
    assert.strictEqual(out.ok, false, JSON.stringify(out));
    return out.error;
  }
  assert.ok(refused({}).indexOf("url is required") >= 0);
  assert.ok(refused({ url: "/gnap" }).indexOf("absolute") >= 0);
  assert.ok(refused({ url: "file:///etc/passwd" })
    .indexOf("absolute") >= 0);
  assert.ok(refused({
    url: "https://as.example/gnap",
    headers: { "Content-Length": "4" }
  }).indexOf("Content-Length") >= 0);
  assert.ok(refused({
    url: "https://as.example/gnap",
    method: "GET",
    body: "{}"
  }).indexOf("GET") >= 0);
  var kept = proxy.describeRequest({
    url: "https://as.example/gnap",
    method: "POST",
    body: "{\"a\":1}",
    headers: { "Content-Type": "application/jose" }
  }, {});
  assert.strictEqual(kept.ok, true);
  assert.strictEqual(kept.body, "{\"a\":1}");
  assert.strictEqual(kept.headers["Content-Type"], "application/jose");
  assert.strictEqual(kept.sslValidate, true);
  var off = proxy.describeRequest({
    url: "https://as.example/gnap",
    sslValidate: false
  }, {});
  assert.strictEqual(off.sslValidate, false);
  var read = proxy.readResponse(401, {},
    "{\"error\":{\"code\":\"invalid_client\"," +
    "\"description\":\"no\"}}");
  assert.strictEqual(read.error, "invalid_client");
  assert.strictEqual(read.ok, false);
  var limits = proxy.limits({ gnapMaxRequestBytes: 100 });
  assert.strictEqual(limits.maxRequestBytes, 100);
  log.info("OK — the relay refuses a relative URL, a file URL, a " +
    "length header and a body on GET, and it keeps a signed string.");
  log.debug("Leaving theProxyRefusesWhatItShould().");
}

function pageWiring() {
  log.debug("Entering pageWiring().");
  var html = fs.readFileSync(path.join(PUBLIC, "gnap.html"), "utf8");
  var css = fs.readFileSync(path.join(PUBLIC, "css", "gnap.css"),
    "utf8");
  var index = fs.readFileSync(path.join(PUBLIC, "index.html"), "utf8");
  ["gnap_status", "gnap_alg", "gnap_save_keypair", "gnap_public",
   "gnap_private", "gnap_grant", "gnap_proof", "gnap_via",
   "gnap_insecure", "gnap_api", "gnap_display", "gnap_request",
   "gnap_client_nonce", "gnap_redirect", "gnap_user_code",
   "gnap_as_nonce", "gnap_finish_url", "gnap_interact_ref",
   "gnap_hash", "gnap_hash_expected", "gnap_continue_uri",
   "gnap_continue_token", "gnap_token", "gnap_manage_uri",
   "gnap_call_method", "gnap_call_url", "gnap_signed",
   "gnap_response"].forEach(function (id) {
    assert.ok(html.indexOf('id="' + id + '"') >= 0,
      "gnap.html is missing #" + id);
  });
  assert.ok(html.indexOf('src="/js/gnap.js"') >= 0);
  assert.ok(/already\s+signed/.test(html));
  assert.ok(html.indexOf('href="/css/gnap.css"') >= 0);
  ["gnap-note", "gnap-warn", "gnap-mono", "gnap-field",
   "gnap-intro"].forEach(function (name) {
    assert.ok(css.indexOf("." + name) >= 0,
      "gnap.css does not define ." + name);
  });
  var card = index.match(
    /<a class="landing-card" href="\/gnap\.html"[^>]*>/);
  assert.ok(card, "the landing page does not link the GNAP page");
  assert.ok(card[0].indexOf("data-not-on-static") < 0,
    "the GNAP card signs in the browser and ships on the static sites");
  ["gnap_client.js", "gnap.js"].forEach(function (name) {
    var text = fs.readFileSync(path.join(SRC, name), "utf8");
    assert.ok(!/require\(["'][^"']*iya-sts/.test(text), name);
    assert.ok(!/require\(["'][^"']*\/sts\//.test(text), name);
  });
  log.info("OK — the page, the card and the client are wired.");
  log.debug("Leaving pageWiring().");
}

function tamper(prepared) {
  log.debug("Entering tamper().");
  var headers = {};
  Object.keys(prepared.headers).forEach(function (name) {
    headers[name] = prepared.headers[name];
  });
  headers.Signature = headers.Signature.replace(
    /sig1=:([^:]+):/, function (all, b64) {
      var flipped = b64.charAt(0) === "A" ? "B" : "A";
      return "sig1=:" + flipped + b64.slice(1) + ":";
    });
  log.debug("Leaving tamper().");
  return {
    method: prepared.method,
    url: prepared.url,
    headers: headers,
    body: prepared.body
  };
}

async function revokeIfIssued(record, json) {
  log.debug("Entering revokeIfIssued().");
  var cont = json && json.continue;
  if (!cont || !cont.uri) {
    log.debug("Leaving revokeIfIssued(). No continuation.");
    return;
  }
  var token = cont.access_token && cont.access_token.value;
  var prepared = await gnap.prepare(record, "DELETE", cont.uri, {
    token: token,
    proof: "httpsig"
  });
  var gone = await post(prepared);
  log.info("Revoked the continuation. HTTP " + gone.status);
  log.debug("Leaving revokeIfIssued().");
}

function proved(answer) {
  log.debug("Entering proved().");
  var err = errorOf(answer.json);
  var issued = answer.json && (answer.json.continue ||
    answer.json.interact || answer.json.access_token);
  if (issued && answer.status >= 200 && answer.status < 300) {
    log.debug("Leaving proved(). Issued.");
    return;
  }
  assert.ok(answer.status >= 400 && answer.status < 500,
    "expected a grant or a client error, got " + answer.status +
    " " + answer.text.slice(0, 500));
  assert.ok(/not registered/.test(err.description),
    "a signature that verified is refused as an unregistered key; " +
    "got " + answer.text.slice(0, 500));
  log.debug("Leaving proved(). Unregistered.");
}

async function liveGrant() {
  log.debug("Entering liveGrant().");
  var base = stsBase();
  var discovery = await post({
    method: "OPTIONS",
    url: base + "/gnap",
    headers: {},
    body: ""
  });
  assert.strictEqual(discovery.status, 200,
    "OPTIONS /gnap failed: " + discovery.text.slice(0, 400));
  assert.ok(discovery.json && discovery.json.grant_request_endpoint,
    "discovery has no grant_request_endpoint");
  assert.ok((discovery.json.key_proofs_supported || [])
    .indexOf("httpsig") >= 0, "discovery does not offer httpsig");
  var grantUrl = discovery.json.grant_request_endpoint;
  var record = await gnap.generateKey("ES256", "debugger-live");
  var display = {
    name: "GNAP debugger",
    uri: "https://client.example/gnap.html"
  };
  function grantJson(proof) {
    log.debug("Entering grantJson().");
    var json = gnap.withClient(gnap.sampleRequest(
      "https://client.example/gnap.html", "n-live"), record, proof,
      display);
    log.debug("Leaving grantJson().");
    return json;
  }
  var prepared = await gnap.prepare(record, "POST", grantUrl, {
    json: grantJson("httpsig"),
    proof: "httpsig"
  });
  var answer = await post(prepared);
  proved(answer);
  await revokeIfIssued(record, answer.json);
  var broken = await post(tamper(prepared));
  var brokenErr = errorOf(broken.json);
  assert.ok(/does not verify/.test(brokenErr.description),
    "a tampered signature should be refused as a bad proof; got " +
    broken.text.slice(0, 500));
  var unsigned = await gnap.prepare(record, "POST", grantUrl, {
    json: grantJson("httpsig"),
    sign: false
  });
  var bare = await post(unsigned);
  var bareErr = errorOf(bare.json);
  assert.strictEqual(bareErr.code, "invalid_client");
  assert.ok(!/not registered/.test(bareErr.description),
    "an unsigned request was treated as a verified key: " +
    bare.text.slice(0, 500));
  var detached = await gnap.prepare(record, "POST", grantUrl, {
    json: grantJson("jwsd"),
    proof: "jwsd"
  });
  var detachedAnswer = await post(detached);
  proved(detachedAnswer);
  await revokeIfIssued(record, detachedAnswer.json);
  var attached = await gnap.prepare(record, "POST", grantUrl, {
    json: grantJson("jws"),
    proof: "jws"
  });
  var attachedAnswer = await post(attached);
  proved(attachedAnswer);
  await revokeIfIssued(record, attachedAnswer.json);
  log.info("OK — iya-sts accepted httpsig, jwsd and jws, and " +
    "refused a tampered signature and an unsigned request.");
  log.debug("Leaving liveGrant().");
}

async function main() {
  log.debug("Entering main().");
  await signatureAgreesWithNode();
  await ed25519AgreesWithNode();
  await digestAndHashAgree();
  await rotationCoversTheFirstSignature();
  theProxyRefusesWhatItShould();
  pageWiring();
  try {
    await liveGrant();
  } catch (e) {
    log.error("The live grant against iya-sts failed: " +
      (e && e.message ? e.message : e));
    log.debug("Leaving main(). Live grant failed.");
    throw e;
  }
  log.info("gnap_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (err) {
  console.error(err);
  process.exit(1);
});
