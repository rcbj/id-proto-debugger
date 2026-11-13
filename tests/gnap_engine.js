// File: gnap_engine.js
//
// ---------------------------------------------------------------------------
// The GNAP client instance, driven in node. The signature checks use
// node's own crypto, which is a second implementation of the same
// bytes. The mtls half checks what the client and the relay do with a
// certificate, offline. The live half sends the page's default sample
// (subject information, with an interaction) to iya-sts with httpsig,
// jwsd and jws: development mode must GRANT it with no administrator
// involved, and the job continues one grant and revokes all three. In
// product mode an unprovisioned key cannot be granted anything, and the
// job checks the proofs only and says so. The full lifecycle, with the
// interaction approved in a browser and the token used and managed, is
// gnap_protocol.js.
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
const live = require("./gnap_live.js");
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

// RFC 9421 section 2.2.2. The vectors are the normalisations the
// coordinator's issue names, and each is checked in the signature base
// and in the URL the request is sent to, which must be the same.
async function targetUriIsTheUriAsSent() {
  log.debug("Entering targetUriIsTheUriAsSent().");
  [
    ["HTTPS://AS.Example:443", "https://as.example/"],
    ["https://as.example:443/gnap?x=1#frag", "https://as.example/gnap?x=1"],
    ["http://AS.example:80/a/../gnap", "http://as.example/gnap"],
    ["https://as.example:8443/Gnap", "https://as.example:8443/Gnap"]
  ].forEach(function (one) {
    assert.strictEqual(gnap.targetUri(one[0]), one[1], one[0]);
  });
  var record = await gnap.generateKey("ES256", "target");
  var prepared = await gnap.prepare(record, "POST",
    "HTTPS://AS.Example:443", {
      json: {}, proof: "httpsig",
      httpsig: { created: 1700000000, nonce: "n", keyid: "target" }
    });
  assert.strictEqual(prepared.url, "https://as.example/");
  assert.strictEqual(prepared.signatures[0].base.split("\n")[1],
    "\"@target-uri\": https://as.example/");
  var detached = await gnap.prepare(record, "GET",
    "https://AS.example:443", { proof: "jwsd" });
  var header = JSON.parse(Buffer.from(detached.headers["Detached-JWS"]
    .split(".")[0], "base64url").toString("utf8"));
  assert.strictEqual(header.uri, "https://as.example/");
  assert.throws(function () {
    gnap.targetUri("/gnap");
  }, /absolute/);
  log.info("OK — @target-uri, the JWS uri and the URL sent are the " +
    "same normalised URI.");
  log.debug("Leaving targetUriIsTheUriAsSent().");
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
   "gnap_response", "gnap_mtls_cert", "gnap_mtls_key",
   "gnap_manage_token", "gnap_call_token", "gnap_generate",
   "gnap_fill_sample", "gnap_fill_ssf_sample", "gnap_send",
   "gnap_check_hash", "gnap_continue", "gnap_revoke_grant",
   "gnap_rotate_token", "gnap_rotate_key", "gnap_revoke_token",
   "gnap_fill_resource", "gnap_send_call"].forEach(function (id) {
    assert.ok(html.indexOf('id="' + id + '"') >= 0,
      "gnap.html is missing #" + id);
  });
  assert.ok(html.indexOf('src="/js/gnap.js"') >= 0);
  assert.ok(html.indexOf('<option value="mtls">') >= 0,
    "the proof menu does not offer mtls");
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

// RFC 7638 thumbprint of the client key. iya-sts names the application
// it creates for an unseen key in development mode `gnap-jkt-<this>`,
// so finding it in a refusal shows the AS verified THIS key.
// What the AS made of one signed grant request for the default sample
// (subject information, with an interaction). Exactly two answers are
// acceptable, and only one of them is a grant:
//   issued   — development mode: a pending grant with an interaction
//              and a continuation. No administrator is involved.
//   product  — product mode: the proof verified and the key is not
//              provisioned (STS-GNAP-0082). Nothing can be granted to
//              a key made here, and the caller says so.
function classify(answer) {
  log.debug("Entering classify().");
  var json = answer.json || {};
  var err = errorOf(answer.json);
  if (answer.status >= 200 && answer.status < 300 && !err.code &&
      json.continue) {
    log.debug("Leaving classify(). Issued.");
    return "issued";
  }
  if (answer.status === 401 && err.code === "invalid_client" &&
      /not registered/.test(err.description) &&
      /product mode/.test(err.description)) {
    log.debug("Leaving classify(). Product mode.");
    return "product";
  }
  log.debug("Leaving classify(). Unexpected.");
  throw new assert.AssertionError({
    message: "expected a grant or a product-mode refusal of an " +
      "unregistered key; got HTTP " + answer.status + " " +
      answer.text.slice(0, 500)
  });
}

// The answer must be a grant, and it must carry what the sample asked
// for: an interaction (redirect and user_code, with a redirect finish)
// and a continuation (RFC 9635 section 3).
function assertGrant(answer, proof) {
  log.debug("Entering assertGrant(). proof=" + proof);
  var json = answer.json || {};
  assert.ok(json.continue && json.continue.uri &&
    json.continue.access_token && json.continue.access_token.value,
    proof + ": the grant has no continuation (RFC 9635 section 3.1): " +
    answer.text.slice(0, 500));
  assert.ok(json.interact && /^https?:\/\//.test(json.interact.redirect),
    proof + ": the grant has no redirect interaction: " +
    answer.text.slice(0, 500));
  assert.strictEqual(typeof json.interact.finish, "string",
    proof + ": the grant has no finish nonce (RFC 9635 section 3.3.5)");
  assert.ok(!json.access_token, proof + ": an access token was issued " +
    "for a request that asked for none");
  log.debug("Leaving assertGrant().");
}

// Section 5: continue once (iya-sts asks for a wait, so too_fast is
// the expected answer, and it hands over a fresh continuation token),
// then section 5.4: revoke with whichever token is current.
async function continueAndRevoke(record, json, proof, tryContinue) {
  log.debug("Entering continueAndRevoke(). proof=" + proof);
  var uri = json.continue.uri;
  var token = json.continue.access_token.value;
  if (tryContinue) {
    var again = await post(await gnap.prepare(record, "POST", uri, {
      token: token,
      proof: proof
    }));
    var againErr = errorOf(again.json);
    assert.ok((again.status >= 200 && again.status < 300) ||
      againErr.code === "too_fast",
      proof + ": continuing the grant failed: HTTP " + again.status +
      " " + again.text.slice(0, 500));
    var next = again.json && again.json.continue;
    if (next && next.access_token && next.access_token.value) {
      token = next.access_token.value;
      uri = next.uri || uri;
    }
    log.info("Continued the grant (" + proof + "): HTTP " +
      again.status + (againErr.code ? " " + againErr.code : "") + ".");
  }
  var gone = await post(await gnap.prepare(record, "DELETE", uri, {
    token: token,
    proof: proof
  }));
  assert.ok(gone.status >= 200 && gone.status < 300,
    proof + ": revoking the grant failed: HTTP " + gone.status + " " +
    gone.text.slice(0, 500));
  log.info("Revoked the grant (" + proof + "): HTTP " + gone.status +
    ".");
  log.debug("Leaving continueAndRevoke().");
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
  async function ask(proof) {
    log.debug("Entering ask(). proof=" + proof);
    var answer = await post(await gnap.prepare(record, "POST", grantUrl,
      { json: grantJson(proof), proof: proof }));
    log.debug("Leaving ask().");
    return answer;
  }
  var first = await ask("httpsig");
  var kind = classify(first);
  if (kind === "issued") {
    assertGrant(first, "httpsig");
    await continueAndRevoke(record, first.json, "httpsig", true);
  } else {
    log.warn("iya-sts is in product mode and this key is not " +
      "provisioned, so no grant was issued. Only the proofs were " +
      "checked here. gnap_protocol.js needs development mode.");
  }
  var tampered = await post(tamper(await gnap.prepare(record, "POST",
    grantUrl, { json: grantJson("httpsig"), proof: "httpsig" })));
  var tamperedErr = errorOf(tampered.json);
  assert.strictEqual(tamperedErr.code, "invalid_client",
    "a tampered signature should be invalid_client; got " +
    tampered.text.slice(0, 500));
  assert.ok(/does not verify/.test(tamperedErr.description),
    "a tampered signature should be refused as a bad proof; got " +
    tampered.text.slice(0, 500));
  var bare = await post(await gnap.prepare(record, "POST", grantUrl, {
    json: grantJson("httpsig"),
    sign: false
  }));
  var bareErr = errorOf(bare.json);
  assert.strictEqual(bareErr.code, "invalid_client",
    "an unsigned request should be invalid_client; got " +
    bare.text.slice(0, 500));
  assert.ok(!/not registered/.test(bareErr.description),
    "an unsigned request was treated as a verified key: " +
    bare.text.slice(0, 500));
  var proofs = ["jwsd", "jws"];
  var i;
  for (i = 0; i < proofs.length; i++) {
    var answer = await ask(proofs[i]);
    var got = classify(answer);
    assert.strictEqual(got, kind, proofs[i] + " was answered " + got +
      " where httpsig was answered " + kind + ": " +
      answer.text.slice(0, 500));
    if (got === "issued") {
      assertGrant(answer, proofs[i]);
      await continueAndRevoke(record, answer.json, proofs[i], false);
    }
  }
  log.info(kind === "issued"
    ? "OK — iya-sts issued a grant for the default sample with httpsig, " +
      "jwsd and jws and no administrator involved; each was revoked, " +
      "and a tampered signature and an unsigned request were refused."
    : "OK (product mode) — iya-sts verified httpsig, jwsd and jws and " +
      "refused the unregistered key; a tampered signature and an " +
      "unsigned request were refused as bad proofs. No grant issued.");
  log.debug("Leaving liveGrant().");
}

// RFC 9635 section 7.3.2. The mtls record signs nothing: the request
// is the body, the key object is the certificate, and the certificate
// and key ride beside the request for whoever opens the connection.
// Section 7.3.2.1 defines no rotation, so the client refuses one.
async function mtlsIsACertificateAndNoSignature() {
  log.debug("Entering mtlsIsACertificateAndNoSignature().");
  var pair = live.makeClientCertificate("gnap-engine-mtls");
  var record = gnap.recordFromCertificate(pair.certificatePem,
    pair.keyPem);
  var der = new crypto.X509Certificate(pair.certificatePem).raw
    .toString("base64");
  var key = gnap.keyObject(record, "mtls");
  assert.deepStrictEqual(key, { proof: "mtls", cert: der });
  var prepared = await gnap.prepare(record, "POST",
    "https://as.example/gnap", {
      json: gnap.withClient(gnap.sampleRequest("https://c.example/",
        "n"), record, "mtls"),
      proof: "mtls",
      token: "t"
    });
  assert.strictEqual(prepared.signatures.length, 0);
  assert.strictEqual(prepared.headers.Signature, undefined);
  assert.strictEqual(prepared.headers["Detached-JWS"], undefined);
  assert.strictEqual(prepared.headers.Authorization, "GNAP t");
  assert.strictEqual(JSON.parse(prepared.body).client.key.cert, der);
  assert.strictEqual(prepared.mtls.certificatePem, pair.certificatePem);
  assert.strictEqual(prepared.mtls.privateKeyPem, pair.keyPem);
  await assert.rejects(gnap.prepare(record, "POST",
    "https://as.example/token/x", { proof: "mtls", rotateTo: record,
      json: {} }), /7\.3\.2\.1/);
  var jwkRecord = await gnap.generateKey("ES256", "no-cert");
  await assert.rejects(gnap.prepare(jwkRecord, "POST",
    "https://as.example/gnap", { proof: "mtls", json: {} }),
    /certificate/);
  assert.throws(function () {
    gnap.recordFromCertificate(pair.certificatePem, "");
  }, /private key/);
  assert.throws(function () {
    gnap.recordFromCertificate("not pem", pair.keyPem);
  }, /PEM certificate/);
  var described = proxy.describeRequest({
    url: "https://as.example/gnap",
    clientCertificatePem: pair.certificatePem,
    clientKeyPem: pair.keyPem
  }, {});
  assert.strictEqual(described.ok, true, JSON.stringify(described));
  assert.strictEqual(described.clientCertificatePem, pair.certificatePem);
  var other = live.makeClientCertificate("gnap-engine-other");
  [
    [{ clientCertificatePem: pair.certificatePem }, /go together/],
    [{ clientKeyPem: pair.keyPem }, /go together/],
    [{ url: "http://as.example/gnap", clientCertificatePem:
      pair.certificatePem, clientKeyPem: pair.keyPem }, /https/],
    [{ clientCertificatePem: "x", clientKeyPem: pair.keyPem },
      /not a PEM certificate/],
    [{ clientCertificatePem: pair.certificatePem, clientKeyPem: "x" },
      /not an unencrypted PEM private key/],
    [{ clientCertificatePem: pair.certificatePem,
      clientKeyPem: other.keyPem }, /not the private key/]
  ].forEach(function (one) {
    var input = Object.assign({ url: "https://as.example/gnap" }, one[0]);
    var out = proxy.describeRequest(input, {});
    assert.strictEqual(out.ok, false, JSON.stringify(one[0]));
    assert.ok(one[1].test(out.error), out.error);
  });
  log.info("OK — mtls carries the certificate, signs nothing, refuses " +
    "rotation, and the relay checks the pair before it sends.");
  log.debug("Leaving mtlsIsACertificateAndNoSignature().");
}

// The default sample asks for subject information only; the SSF one
// asks for ssf.read too. Both carry an interaction with this page as
// the redirect finish.
function samplesAreWhatTheySay() {
  log.debug("Entering samplesAreWhatTheySay().");
  var plain = gnap.sampleRequest("https://c.example/gnap.html", "n1");
  assert.strictEqual(plain.access_token, undefined);
  assert.deepStrictEqual(plain.subject, { sub_id_formats: ["opaque"] });
  assert.strictEqual(plain.interact.finish.uri,
    "https://c.example/gnap.html");
  var ssf = gnap.ssfSampleRequest("https://c.example/gnap.html", "n2");
  assert.deepStrictEqual(ssf.access_token, { access: ["ssf.read"] });
  assert.strictEqual(ssf.interact.finish.nonce, "n2");
  log.info("OK — the two samples ask for what they say.");
  log.debug("Leaving samplesAreWhatTheySay().");
}

async function main() {
  log.debug("Entering main().");
  await signatureAgreesWithNode();
  await ed25519AgreesWithNode();
  await digestAndHashAgree();
  await rotationCoversTheFirstSignature();
  await targetUriIsTheUriAsSent();
  theProxyRefusesWhatItShould();
  await mtlsIsACertificateAndNoSignature();
  samplesAreWhatTheySay();
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
