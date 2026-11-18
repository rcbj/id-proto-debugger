// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_verifier_page.js
//
// ---------------------------------------------------------------------------
// THE DEBUGGER AS THE OPENID4VP VERIFIER, IN A BROWSER (#364).
//
// tests/vp_verifier_engine.js proves what vp_verifier.js composes and checks,
// and tests/api_oid4vp_verifier.js proves the api's routes. Neither loads the
// page, and three things only break here:
//
//   * the page CREATES a request through the api: a session, a certificate
//     made in the browser, a Request Object signed in the browser and
//     published to the api, and an openid4vp:// invocation naming it;
//   * the api's request_uri, root certificate and response_uri are reachable
//     by a wallet that is NOT the browser, with the right media types;
//   * the page POLLS the api, finds the wallet's answer, checks it, and draws
//     one row per check.
//
// NODE PLAYS THE WALLET. It fetches the request_uri and the root the leaf's
// AIA names, reads the nonce, state and client_id from the signed Request
// Object, and builds the presentation with the Wallet workflow's own
// `sd_jwt_vp.buildPresentation()`. That is the debugger agreeing with
// itself, which is why the independent wallet (rcbj/oid4vc-wallet) is #364's
// PR 2; what THIS job adds is everything between the two ends.
//
// The issuer is named by a `did:jwk`, so the page resolves its key locally and
// nothing here needs an issuer on the network.
//
// Three rounds: direct_post with every check passing, direct_post.jwt (the
// answer encrypted with the Wallet's own encryptResponse() to the key the
// Request Object carries), and a KB-JWT with the wrong nonce, which must fail
// exactly the KB-JWT nonce row.
//
// Needs the api (API_URL). On a target without one (a static site) the page
// says so, and this job asserts that it does and stops there.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadUrl } = require("./page_load.js");
const paths = require("./module_paths.js");
// The user guide's pictures (docs/vc/). Inert unless DOC_SCREENSHOT_DIR is
// set, so an ordinary run takes none.
const docShots = require("./doc_screenshots.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_verifier_page",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var apiUrl = process.env.API_URL || "";
const WAIT = Number(process.env.TEST_WAIT_TIME_MS) ||
    Math.max(Number(appconfig.waitTime) || 2000, 20000);
const VCT = "urn:example:verifier-page:1";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
const sdJwtVp = load("sd_jwt_vp.js");
const vp = load("vp_protocols.js");

// ---------------------------------------------------------------------------
// THE WALLET'S CREDENTIAL, issued here.
// ---------------------------------------------------------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function sha256b64u(text) {
  log.debug("Entering sha256b64u().");
  log.debug("Leaving sha256b64u().");
  return b64u(nodeCrypto.createHash("sha256").update(text).digest());
}

function ecPair() {
  log.debug("Entering ecPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving ecPair().");
  return { privateKey: pair.privateKey,
           publicJwk: pair.publicKey.export({ format: "jwk" }),
           privateJwk: pair.privateKey.export({ format: "jwk" }) };
}

function nodeJws(header, payload, key) {
  log.debug("Entering nodeJws().");
  const input = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving nodeJws().");
  return input + "." + b64u(sig);
}

function disclosure(salt, name, value) {
  log.debug("Entering disclosure().");
  log.debug("Leaving disclosure().");
  return b64u(JSON.stringify([salt, name, value]));
}

// An SD-JWT VC from an issuer named by did:jwk, bound to the holder's key.
function issueCredential(holder) {
  log.debug("Entering issueCredential().");
  const issuer = ecPair();
  const did = "did:jwk:" + b64u(JSON.stringify({ kty: "EC", crv: "P-256",
    x: issuer.publicJwk.x, y: issuer.publicJwk.y }));
  const now = Math.floor(Date.now() / 1000);
  const d = [disclosure("s1", "given_name", "Erika"),
             disclosure("s2", "family_name", "Mustermann"),
             disclosure("s3", "birthdate", "1963-08-12")];
  const jwt = nodeJws({ alg: "ES256", typ: "dc+sd-jwt", kid: did + "#0" }, {
    iss: did, iat: now - 60, nbf: now - 60, exp: now + 86400, vct: VCT,
    _sd_alg: "sha-256", _sd: d.map(sha256b64u),
    cnf: { jwk: holder.publicJwk }
  }, issuer);
  log.debug("Leaving issueCredential().");
  return { jwt: jwt, wanted: [d[0], d[1]] };
}

// ---------------------------------------------------------------------------
// THE PAGE.
// ---------------------------------------------------------------------------
async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript(
      "var e = document.getElementById(arguments[0]);" +
      "if (e.type === 'checkbox') { e.checked = !!arguments[1]; }" +
      "else { e.value = arguments[1]; }", id, value);
  log.debug("Leaving setField().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). " + id);
  const text = await driver.executeScript(
      "var e = document.getElementById(arguments[0]);" +
      "return e ? String(e.textContent || '') : '';", id);
  log.debug("Leaving textOf().");
  return text;
}

async function openPage(driver) {
  log.debug("Entering openPage().");
  await loadUrl(driver, baseUrl + "/vc-verifier.html");
  await driver.wait(async function () {
    return await driver.executeScript(
        "return !!(window.vcverifier && window.vcverifier.createRequest);");
  }, WAIT, "window.vcverifier.createRequest is not there: either " +
      "public/js/vc_verifier.js 404'd or the bundle threw before it " +
      "exported, and every button on the page is a ReferenceError.");
  await driver.wait(async function () {
    return (await textOf(driver, "vpv_api_status")).trim().length > 0;
  }, WAIT, "the page never said whether the api can host the request");
  log.debug("Leaving openPage().");
}

// Fill pane 1 and 2, press Create, and read back what the page made.
async function createRequest(driver, mode, opts) {
  log.debug("Entering createRequest(). " + mode);
  const o = opts || {};
  await setField(driver, "vpv_query_id", "credential");
  await setField(driver, "vpv_format", "dc+sd-jwt");
  await setField(driver, "vpv_type", VCT);
  await setField(driver, "vpv_claims", "given_name\nfamily_name");
  await setField(driver, "vpv_binding", true);
  await setField(driver, "vpv_dcql", "");
  await driver.executeScript("window.vcverifier.regenerateDcql();");
  await setField(driver, "vpv_client_prefix", o.prefix || "x509_hash");
  await setField(driver, "vpv_response_mode", mode);
  await setField(driver, "vpv_delivery", o.delivery || "reference-get");
  await setField(driver, "vpv_redirect_uri", "");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  await driver.findElement(By.id("btn_vpv_create")).click();
  await driver.wait(async function () {
    return /ready|failed|refused|answered|no api|did not/i.test(
        await textOf(driver, "vpv_create_status"));
  }, WAIT, "Create the request never finished");
  const said = await textOf(driver, "vpv_create_status");
  assert.ok(/ready/i.test(said), "Creating the request said: " + said);
  const request = await driver.executeScript(
      "return window.vcverifier.currentRequest();");
  assert.ok(request && request.hosted && request.hosted.requestUri,
      "the page holds no request after Create: " + JSON.stringify(request));
  log.debug("Leaving createRequest(). " + request.hosted.id);
  return request;
}

async function waitForVerdict(driver) {
  log.debug("Entering waitForVerdict().");
  await driver.wait(async function () {
    return /passed|failed|could not/i.test(
        await textOf(driver, "vpv_verdict"));
  }, WAIT, "the page never drew a verdict; it says: " +
      await textOf(driver, "vpv_wait_status"));
  const rows = await driver.executeScript(
      "return Array.prototype.slice.call(" +
      "  document.querySelectorAll('#vpv_checks tr')).map(function (r) {" +
      "  return { id: r.id, cls: r.className, text: r.textContent }; });");
  const verdict = await textOf(driver, "vpv_verdict");
  log.debug("Leaving waitForVerdict(). " + rows.length + " row(s).");
  return { verdict: verdict, rows: rows };
}

// ---------------------------------------------------------------------------
// THE WALLET, in node.
// ---------------------------------------------------------------------------
function jwsPart(compact, index) {
  log.debug("Entering jwsPart().");
  log.debug("Leaving jwsPart().");
  return JSON.parse(Buffer.from(compact.split(".")[index], "base64url")
                    .toString("utf8"));
}

async function walletFetchesTheRequest(request) {
  log.debug("Entering walletFetchesTheRequest().");
  const got = await fetch(request.hosted.requestUri);
  const body = await got.text();
  check("the request_uri answers 200 with application/oauth-authz-req+jwt",
      function () {
        assert.strictEqual(got.status, 200, body.slice(0, 200));
        assert.strictEqual(got.headers.get("content-type"),
                           "application/oauth-authz-req+jwt");
      });
  const header = jwsPart(body, 0);
  const claims = jwsPart(body, 1);
  check("the Request Object is typed, carries x5c, and names this " +
      "session's nonce, state, client_id and response_uri", function () {
        assert.strictEqual(header.typ, "oauth-authz-req+jwt");
        assert.ok(Array.isArray(header.x5c) && header.x5c.length === 1,
            "x5c should carry the leaf alone: " + JSON.stringify(header));
        assert.strictEqual(claims.nonce, request.session.nonce);
        assert.strictEqual(claims.state, request.session.state);
        assert.strictEqual(claims.client_id, request.session.clientId);
        assert.strictEqual(claims.response_uri, request.hosted.responseUri);
        assert.ok(/^x509_hash:/.test(claims.client_id));
      });
  const ca = await fetch(request.hosted.caIssuersUrl);
  const der = Buffer.from(await ca.arrayBuffer());
  check("the root certificate the leaf's AIA names is served as DER",
      function () {
        assert.strictEqual(ca.status, 200);
        assert.strictEqual(ca.headers.get("content-type"),
                           "application/pkix-cert");
        assert.strictEqual(der[0], 0x30, "not a DER SEQUENCE");
      });
  log.debug("Leaving walletFetchesTheRequest().");
  return claims;
}

async function walletAnswers(claims, holder, credential, opts) {
  log.debug("Entering walletAnswers().");
  const o = opts || {};
  const built = await sdJwtVp.buildPresentation({
    credential: credential.jwt + "~" + credential.wanted.join("~") + "~",
    selected: credential.wanted, holderPrivateJwk: holder.privateJwk,
    aud: claims.client_id, nonce: o.nonce || claims.nonce,
    keyBinding: true });
  const fields = vp.responseFields({
    vpToken: { credential: [built.presentation] }, state: claims.state });
  let body;
  if (claims.response_mode === "direct_post.jwt") {
    const sealed = await vp.encryptResponse({ fields: fields,
      clientMetadata: claims.client_metadata, enc: "A128GCM" });
    body = vp.formEncode({ response: sealed.jwe });
  } else {
    body = vp.formEncode(fields);
  }
  const posted = await fetch(claims.response_uri, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body });
  const text = await posted.text();
  check("the response_uri accepts the wallet's POST (" +
      claims.response_mode + ")", function () {
        assert.strictEqual(posted.status, 200, text.slice(0, 200));
      });
  log.debug("Leaving walletAnswers().");
}

// ---------------------------------------------------------------------------
// LIVE SIGNING (#364, PR 3): a decentralized_identifier request under
// request_uri_method=post. The wallet (node) POSTs a wallet_nonce to the
// request_uri; the api holds that POST while the page signs a fresh Request
// Object echoing it (OpenID4VP 1.0 section 5.10), and the wallet's answer
// to THAT object must pass.
// ---------------------------------------------------------------------------
async function liveSigningRound(driver) {
  log.debug("Entering liveSigningRound().");
  log.info("=== decentralized_identifier, request_uri_method=post, live " +
           "wallet_nonce ===");
  await driver.executeScript("return window.vcverifier.reset();");
  const request = await createRequest(driver, "direct_post", {
    prefix: "decentralized_identifier", delivery: "reference-post" });
  check("the invocation says request_uri_method=post and a DID client_id",
      function () {
        assert.ok(/request_uri_method=post/.test(request.invocation),
                  request.invocation);
        // The Client Identifier Prefix is part of client_id itself
        // (OpenID4VP 1.0 section 5.9).
        assert.ok(/^decentralized_identifier:did:jwk:/.test(
            request.session.clientId), request.session.clientId);
      });
  const walletNonce = nodeCrypto.randomBytes(12).toString("base64url");
  const got = await fetch(request.hosted.requestUri, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ wallet_nonce: walletNonce,
      wallet_metadata: JSON.stringify({
        vp_formats_supported: { "dc+sd-jwt": {} } }) }).toString() });
  const body = await got.text();
  const header = jwsPart(body, 0);
  const claims = jwsPart(body, 1);
  check("the wallet's POST is answered with a Request Object signed LIVE " +
      "that echoes its wallet_nonce", function () {
        // A 503 is the page missing the api's wait: a wallet that sent a
        // wallet_nonce is never given the object signed in advance
        // (OpenID4VP section 5.10.2).
        assert.strictEqual(got.status, 200, "HTTP " + got.status + " " +
            body.slice(0, 200));
        assert.strictEqual(claims.wallet_nonce, walletNonce,
            "wallet_nonce is " + JSON.stringify(claims.wallet_nonce) + ".");
      });
  check("a decentralized_identifier request names the DID's key in kid " +
      "and carries no x5c", function () {
        // kid is a DID URL: the DID, without the client_id's prefix, then a
        // fragment naming the key.
        const did = claims.client_id.replace(/^decentralized_identifier:/, "");
        assert.ok(String(header.kid || "").indexOf(did + "#") === 0,
            JSON.stringify(header));
        assert.ok(!header.x5c, JSON.stringify(header));
      });
  const holder = ecPair();
  const credential = issueCredential(holder);
  await walletAnswers(claims, holder, credential);
  const seen = await waitForVerdict(driver);
  await docShots.snap(driver, "07-live-signed-request",
                      { ids: ["pane_response"] });
  check("every check on the answer to the live-signed request passes",
      function () {
        assert.ok(/every check passed/i.test(seen.verdict),
            seen.verdict + "\n" + seen.rows.filter(function (r) {
              return /fail/.test(r.cls);
            }).map(function (r) {
              return r.text;
            }).join("\n"));
      });
  const events = await driver.executeScript(
      "return Array.prototype.slice.call(" +
      "  document.querySelectorAll('#vpv_events li')).map(function (li) {" +
      "  return li.textContent; });");
  check("the page reports that it signed a fresh Request Object", function () {
    assert.ok(/signed a fresh Request Object/.test(events.join("\n")),
              events.join("\n"));
  });
  log.debug("Leaving liveSigningRound().");
}

// The QR code a wallet on another device scans, and the Digital Credentials
// API button in a browser that has no such API (headless Chrome has no
// platform wallet), which must say so rather than fail silently.
async function qrAndDcApi(driver) {
  log.debug("Entering qrAndDcApi().");
  log.info("=== QR code and the Digital Credentials API ===");
  await driver.executeScript("return window.vcverifier.reset();");
  await createRequest(driver, "direct_post");
  const qr = await driver.executeScript(
      "var e = document.querySelector('#vpv_qr svg');" +
      "return e ? e.querySelectorAll('rect,path').length : 0;");
  check("the invocation is drawn as a QR code", function () {
    assert.ok(qr > 0, "no SVG in #vpv_qr");
  });
  await driver.executeScript("return window.vcverifier.reset();");
  await setField(driver, "vpv_response_mode", "dc_api");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  await driver.findElement(By.id("btn_vpv_dc_api")).click();
  await driver.wait(async function () {
    return /Digital Credentials API|Asking the browser|answered/i.test(
        await textOf(driver, "vpv_create_status"));
  }, WAIT, "the Digital Credentials API button said nothing");
  const said = await textOf(driver, "vpv_create_status");
  check("without a Digital Credentials API the page says so by name",
      function () {
        assert.ok(/no Digital Credentials API|Asking the browser/i.test(said),
                  said);
      });
  await setField(driver, "vpv_response_mode", "direct_post");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  log.debug("Leaving qrAndDcApi().");
}

// ---------------------------------------------------------------------------
// THE ROUNDS.
// ---------------------------------------------------------------------------
async function oneRound(driver, mode, opts) {
  log.debug("Entering oneRound(). " + mode);
  log.info("=== " + mode + (opts && opts.nonce ? ", wrong nonce" : "") +
           " ===");
  const shots = (opts && opts.shots) || "";
  await driver.executeScript("return window.vcverifier.reset();");
  const request = await createRequest(driver, mode);
  if (shots === "01") {
    await docShots.snap(driver, "01-what-to-ask", { ids: ["pane_query"] });
    await docShots.snap(driver, "02-how-to-ask", { ids: ["pane_request"] });
    await docShots.snap(driver, "03-hand-off", { ids: ["pane_handoff"] });
  }
  const claims = await walletFetchesTheRequest(request);
  const holder = ecPair();
  const credential = issueCredential(holder);
  await walletAnswers(claims, holder, credential, opts);
  const seen = await waitForVerdict(driver);
  if (shots) {
    await docShots.snap(driver, shots === "01" ? "04-checks" : shots,
                        { ids: ["pane_response"] });
  }
  log.debug("Leaving oneRound(). " + seen.verdict);
  return seen;
}

function rowFor(seen, id) {
  log.debug("Entering rowFor(). " + id);
  const row = seen.rows.find(function (r) {
    return r.id === "vpv_check_" + id;
  });
  log.debug("Leaving rowFor(). " + !!row);
  return row;
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,2400");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await openPage(driver);
    const apiSays = await textOf(driver, "vpv_api_status");
    if (!apiUrl) {
      check("with no api the page says it cannot host a request", function () {
        assert.ok(/no api|did not answer|switched off/i.test(apiSays),
            "The page says: " + apiSays);
      });
      log.info(checks + " checks passed (no api on this target).");
      log.debug("Leaving test(). No api.");
      return;
    }
    check("the page found the api's Verifier endpoints", function () {
      assert.ok(/will host/i.test(apiSays), "The page says: " + apiSays);
    });

    docShots.setPrefix("vc-verifier");
    let seen = await oneRound(driver, "direct_post", { shots: "01" });
    check("every check on a correct direct_post answer passes", function () {
      assert.ok(/every check passed/i.test(seen.verdict),
          seen.verdict + "\n" + seen.rows.filter(function (r) {
            return /fail/.test(r.cls);
          }).map(function (r) {
            return r.text;
          }).join("\n"));
    });
    check("and each check is its own row, the KB-JWT nonce among them",
        function () {
          assert.ok(seen.rows.length >= 10, seen.rows.length + " rows");
          const nonceRow = rowFor(seen, "credential[0].kb.nonce");
          assert.ok(nonceRow && /pass/.test(nonceRow.cls),
              JSON.stringify(nonceRow));
          const status = rowFor(seen, "status");
          assert.ok(status && /skip/.test(status.cls),
              "this credential carries no status, so the status summary " +
              "is a SKIP: " + JSON.stringify(status));
        });

    seen = await oneRound(driver, "direct_post.jwt",
                          { shots: "05-checks-direct-post-jwt" });
    check("an encrypted direct_post.jwt answer is decrypted and passes",
        function () {
          assert.ok(/every check passed/i.test(seen.verdict), seen.verdict);
          const decrypt = rowFor(seen, "response.decrypt");
          assert.ok(decrypt && /pass/.test(decrypt.cls),
              JSON.stringify(decrypt));
        });

    seen = await oneRound(driver, "direct_post", { nonce: "not-the-nonce",
                          shots: "06-checks-wrong-nonce" });
    check("a KB-JWT with the wrong nonce fails that row and no other",
        function () {
          const failed = seen.rows.filter(function (r) {
            return /fail/.test(r.cls);
          }).map(function (r) {
            return r.id;
          });
          assert.deepStrictEqual(failed, ["vpv_check_credential[0].kb.nonce"],
              "Failed rows: " + failed.join(", "));
        });

    await liveSigningRound(driver);
    await qrAndDcApi(driver);

    await driver.executeScript("return window.vcverifier.reset();");
    log.info(checks + " checks passed.");
    assert.ok(checks >= 20, "Only " + checks + " checks ran.");
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("vc_verifier_page")
  .description("Drive vc-verifier.html, the debugger as the OpenID4VP " +
      "Verifier: create a request through the api, answer it from node as " +
      "the wallet over direct_post and direct_post.jwt, and read every " +
      "check the page draws.")
  .addOption(new Option("-u, --url <url>", "base url of the client"))
  .parse(process.argv);

if (program.opts().url) {
  baseUrl = program.opts().url;
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
