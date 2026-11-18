// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_jose_cose_presentation.js
//
// ---------------------------------------------------------------------------
// The wallet's presentation pages, in Chrome, presenting W3C VC-JOSE-COSE
// credentials (#477), with what they build checked by implementations that
// share no code with the wallet. Credentials are made in node, handed to the
// wallet as issuance leaves one in storage, and the request is handed to
// step 1 by value; nothing is posted.
//
//   1. a vc+jwt signed by jose, its subject the holder's did:jwk: step 2
//      builds a vp+jwt the holder signs, carrying the credential as an
//      EnvelopedVerifiableCredential, with the request's nonce and the
//      Verifier's Client Identifier — jose verifies the vp+jwt with the
//      holder's key and the enveloped vc+jwt with the issuer's;
//   2. a vc+cose signed by @auth0/cose: the same, the envelope's data: URL
//      base64, @auth0/cose verifying the credential inside;
//   3. a vc+sd-jwt issued by @sd-jwt/core with every subject claim
//      disclosable and the holder's key as cnf, asked for one claim: the
//      presentation carries that Disclosure only and a Key Binding JWT,
//      which @sd-jwt/core verifies, key binding included.
//
// Needs only the client.
// ---------------------------------------------------------------------------

const { Builder, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const nodeCrypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require("commander");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");
const { waitForStatus, waitForValue } = require("./wait_for");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_jose_cose_presentation",
    level: appconfig.logLevel || "info" });

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 20000;
var stepWait = waitTime * 4;

const VERIFIER = "https://verifier.example/response";
const CLIENT_ID = "redirect_uri:" + VERIFIER;

function keyPair(crv) {
  log.debug("Entering keyPair(). " + crv);
  var pair = crv === "Ed25519" ? nodeCrypto.generateKeyPairSync("ed25519") :
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv });
  var pub = pair.publicKey.export({ format: "jwk" });
  var did = "did:jwk:" +
    Buffer.from(JSON.stringify(pub)).toString("base64url");
  log.debug("Leaving keyPair().");
  return { pair: pair, pub: pub,
           priv: pair.privateKey.export({ format: "jwk" }), did: did,
           kid: did + "#0" };
}

function credential(issuer, subjectId) {
  log.debug("Entering credential().");
  log.debug("Leaving credential().");
  return { "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential"], issuer: issuer,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: { id: subjectId, given_name: "Alice",
                         family_name: "Liddell" } };
}

function requestQuery(format, nonce) {
  log.debug("Entering requestQuery(). " + format);
  var dcql = { credentials: [{ id: "cred", format: format,
    claims: [{ path: ["credentialSubject", "given_name"] }] }] };
  var q = new URLSearchParams({ client_id: CLIENT_ID,
    response_type: "vp_token", response_mode: "direct_post",
    response_uri: VERIFIER, nonce: nonce, state: "st-" + nonce,
    dcql_query: JSON.stringify(dcql),
    client_metadata: JSON.stringify({ vp_formats_supported: {} }) });
  log.debug("Leaving requestQuery().");
  return q.toString();
}

async function presentThroughThePages(driver, held, holder, query) {
  log.debug("Entering presentThroughThePages().");
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html");
  await waitForContent.waitForPageBundle(driver, "step 1");
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);",
    held, JSON.stringify(holder.pub), JSON.stringify(holder.priv));
  await loadUrl(driver, baseUrl + "/vc-presentation-1.html?" + query);
  await waitForContent.waitForPageBundle(driver, "step 1, with the request");
  await waitForStatus(driver, "vp_request_status", function (s) {
    return /Request read/.test(s);
  }, "step 1 should read the request", stepWait);
  await driver.executeScript(
    "var b=document.getElementById('vp_continue_button'); if (b) b.click();");
  await driver.wait(until.urlContains("vc-presentation-2.html"), stepWait,
                    "Continue should reach step 2");
  await waitForContent.waitForPageBundle(driver, "step 2");
  var text;
  try {
    text = await waitForValue(driver, "vp_presentation", function (v) {
      return v.trim().length > 40;
    }, "step 2 should build a presentation", stepWait);
  } catch (e) {
    var said = await driver.executeScript(
      "var e=document.getElementById('vp_present_status');" +
      "return e ? e.textContent : '(no status)';");
    log.debug("Leaving presentThroughThePages(). Step 2 said: " + said);
    throw new Error(e.message + " — step 2 says: " + said);
  }
  log.debug("Leaving presentThroughThePages().");
  return text.trim();
}

// The vp+jwt's own checks, and the enveloped credential it carries.
async function checkEnvelopingVp(jose, vpJwt, holder, nonce, label) {
  log.debug("Entering checkEnvelopingVp(). " + label);
  var v = await jose.compactVerify(vpJwt, holder.pair.publicKey);
  assert.strictEqual(v.protectedHeader.typ, "vp+jwt",
                     label + ": the presentation is a vp+jwt");
  var vp = JSON.parse(Buffer.from(v.payload).toString());
  assert.strictEqual(vp.nonce, nonce, label + ": the request's nonce");
  assert.strictEqual(vp.aud, CLIENT_ID, label + ": the Verifier as aud");
  assert.strictEqual(vp.vp, undefined, label + ": no vp claim");
  var env = [].concat(vp.verifiableCredential)[0];
  assert.deepStrictEqual([].concat(env.type),
                         ["EnvelopedVerifiableCredential"],
                         label + ": the credential is enveloped");
  log.debug("Leaving checkEnvelopingVp().");
  return env;
}

async function test() {
  log.debug("Entering test().");
  var jose = await import("jose");
  var cose = require("@auth0/cose");
  var core = await import("@sd-jwt/core");
  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    log.info("=== 1. vc+jwt (jose) ===");
    var issuer = keyPair("P-256");
    var holder = keyPair("P-256");
    var vc = credential(issuer.did, holder.did);
    var vcJwt = await new jose.CompactSign(Buffer.from(JSON.stringify(vc)))
      .setProtectedHeader({ alg: "ES256", typ: "vc+jwt", cty: "vc",
                            kid: issuer.kid }).sign(issuer.pair.privateKey);
    var nonce1 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var built = await presentThroughThePages(driver, vcJwt, holder,
                                             requestQuery("vc+jwt", nonce1));
    var env = await checkEnvelopingVp(jose, built, holder, nonce1, "vc+jwt");
    assert.strictEqual(env.id, "data:application/vc+jwt," + vcJwt,
                       "vc+jwt: the enveloped credential is the one issued");
    await jose.compactVerify(vcJwt, issuer.pair.publicKey);
    log.info("PASS vc+jwt: an enveloped vp+jwt with the request's nonce and " +
             "aud; jose verifies both.");

    log.info("=== 2. vc+cose (@auth0/cose) ===");
    var holder2 = keyPair("P-256");
    var vc2 = credential(issuer.did, holder2.did);
    var signed = await cose.Sign1.sign(new cose.ProtectedHeaders([
      [cose.Headers.Algorithm, cose.Algorithms.ES256],
      [16, "application/vc+cose"],
      [cose.Headers.KeyID, Buffer.from(issuer.kid)]]), undefined,
      Buffer.from(JSON.stringify(vc2)), issuer.pair.privateKey);
    var coseText = Buffer.from(signed.encode()).toString("base64url");
    var nonce2 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var built2 = await presentThroughThePages(driver, coseText, holder2,
      requestQuery("vc+cose", nonce2));
    var env2 = await checkEnvelopingVp(jose, built2, holder2, nonce2,
                                       "vc+cose");
    var m = /^data:application\/vc\+cose;base64,(.*)$/.exec(env2.id);
    assert.ok(m, "vc+cose: the envelope's data: URL is base64");
    await cose.Sign1.decode(Buffer.from(m[1], "base64"))
      .verify(issuer.pair.publicKey);
    log.info("PASS vc+cose: enveloped in the holder's vp+jwt; @auth0/cose " +
             "verifies the credential inside.");

    log.info("=== 3. vc+sd-jwt (@sd-jwt/core), one claim of two ===");
    var holder3 = keyPair("P-256");
    var vc3 = credential(issuer.did, holder3.did);
    var verifyWith = function (key) {
      return async function (data, sig) {
        return nodeCrypto.verify("sha256", Buffer.from(data),
          { key: key, dsaEncoding: "ieee-p1363" },
          Buffer.from(sig, "base64url"));
      };
    };
    var instance = new core.SdJwtInstance({
      signer: async function (data) {
        return Buffer.from(nodeCrypto.sign("sha256", Buffer.from(data),
          { key: issuer.pair.privateKey, dsaEncoding: "ieee-p1363" }))
          .toString("base64url");
      },
      verifier: verifyWith(issuer.pair.publicKey), signAlg: "ES256",
      kbVerifier: verifyWith(holder3.pair.publicKey),
      hasher: async function (data, alg) {
        return new Uint8Array(nodeCrypto.createHash(alg.replace("-", ""))
          .update(data).digest());
      },
      hashAlg: "sha-256",
      saltGenerator: async function () {
        return nodeCrypto.randomBytes(16).toString("base64url");
      }
    });
    var sdJwt = await instance.issue(Object.assign({ cnf: { jwk:
      holder3.pub } }, vc3), { credentialSubject: { _sd: ["given_name",
      "family_name"] } }, { header: { typ: "vc+sd-jwt", kid: issuer.kid } });
    var nonce3 = "n-" + nodeCrypto.randomBytes(8).toString("hex");
    var built3 = await presentThroughThePages(driver, sdJwt, holder3,
      requestQuery("vc+sd-jwt", nonce3));
    var verified = await instance.verify(built3, { keyBindingNonce: nonce3,
      requiredClaimKeys: [] });
    assert.ok(verified.kb, "vc+sd-jwt: a Key Binding JWT went");
    assert.strictEqual(verified.kb.payload.nonce, nonce3,
                       "vc+sd-jwt: its nonce is the request's");
    assert.strictEqual(verified.kb.payload.aud, CLIENT_ID,
                       "vc+sd-jwt: its aud is the Verifier");
    assert.strictEqual(verified.payload.credentialSubject.given_name,
                       "Alice", "vc+sd-jwt: the asked-for claim went");
    assert.strictEqual(verified.payload.credentialSubject.family_name,
                       undefined, "vc+sd-jwt: the other did not");
    log.info("PASS vc+sd-jwt: one Disclosure and a Key Binding JWT; " +
             "@sd-jwt/core verifies both.");
    log.info("vc_jose_cose_presentation: all checks passed.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                             "base url of the debugger's client"));
program.addOption(new Option("-h, --headless <headless>",
                             "run Chrome headless (default true)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) {
  baseUrl = opts.url;
  log.info("Setting url to " + baseUrl);
}
if (opts.headless === "false") headless = false;

test().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
