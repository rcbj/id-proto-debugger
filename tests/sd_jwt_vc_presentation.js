// File: sd_jwt_vc_presentation.js
//
// The SD-JWT VC PRESENTATION workflow, end to end:
//
//   step 0 (vc-presentation-0.html)
//     which OID4VP flow to run — request by value, signed request by reference,
//     or cross-device — and whether this wallet is even holding a credential.
//
//   step 1 (vc-presentation-1.html)
//     the verifier's Authorization Request: read from the redirect, or fetched
//     from a request_uri and its signature verified, with the DCQL query decoded
//     into the claims being asked for.
//
//   step 2 (vc-presentation-2.html)
//     the holder chooses which Disclosures to send; the wallet builds the
//     SD-JWT+KB — issuer-signed JWT, those Disclosures, and a Key Binding JWT
//     over this request's nonce with sd_hash across exactly those bytes — and
//     POSTs the vp_token to the Response URI.
//
//   step 3 (vc-presentation-3.html)
//     the verifier's verdict, check by check, next to the wallet's own re-check
//     of the bytes it sent.
//
// The credential presented is minted here, directly against the mock Credential
// Issuer, rather than by driving the whole issuance workflow: what is under test
// is the presentation, and the precondition it needs is "the wallet holds a
// credential and the key it is bound to".
//
// POSITIVE: the flow above, twice (request by value and signed by reference),
// with the presentation independently verified in this test — sd_hash recomputed,
// the KB-JWT signature checked against the cnf key, and the claim set the
// verifier ended up with compared against what it asked for.
//
// NEGATIVE: five ways a presentation must be refused —
//   * a claim the verifier asked for withheld (driven through the pages);
//   * a presentation replayed against a different request (wrong nonce);
//   * a Key Binding JWT signed by a key the credential is not bound to;
//   * a Disclosure the issuer never signed, spliced in;
//   * a Disclosure removed after the KB-JWT was signed (sd_hash mismatch).
//
// Needs the STS mock only: it is the Credential Issuer, the Verifier, and the
// authorization server all at once, so no identity provider is involved.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
const crypto = require("crypto");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'sd_jwt_vc_presentation',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 20000);
// The budget every waitFor* in ./wait_for.js uses. Set once: one test file
// runs per process.
require("./wait_for").configure({ timeout: fetchWait });

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var VCI_CONFIG_ID = process.env.OID4VCI_CONFIG_ID || "IdentityCredential";
var EXPECTED_VCT = "urn:idptools:sd-jwt-vc:identity";
// What the mock verifier asks for. Two of the six claims the credential carries,
// which is what makes the selective part of selective disclosure observable.
var REQUESTED = (process.env.OID4VP_CLAIMS || "given_name,family_name").split(",");
var DCQL_ID = "identity_credential";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function b64u(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString("utf8")); }

function httpJson(url, options) {
  log.debug("Entering httpJson().");
  options = options || {};
  log.debug("Leaving httpJson().");
  return fetch(url, options).then(function (r) {
    return r.text().then(function (text) {
      var body = null;
      try {
        body = JSON.parse(text);
      } catch (e) {
        // Not JSON: the caller gets the raw text instead.
      }
      return { status: r.status, ok: r.ok, body: body, raw: text };
    });
  });
}

async function click(driver, locator) {
  log.debug("Entering click().");
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await driver.sleep(120);
  try {
    await e.click();
  } catch (err) {
    // Something is overlapping the element; click it through the DOM instead.
    await driver.executeScript("arguments[0].click();", e);
  }
  await driver.sleep(250);
  log.debug("Leaving click().");
}

// text()/value() and the waitFor* family live in ./wait_for.js — one
// implementation, shared by these suites. It waits on CONTENT rather than on the
// element: every field here is static markup, so locating it proves nothing about
// whether the page has filled it in, and the fixed sleeps that used to stand in
// for that lost the race periodically. It also reports what the field LAST held
// on a timeout, which the local copy of waitForStatus could not — its message was
// built before the first poll, so it always said "(last status: )".
const { text, value, waitForStatus, waitForValue } = require("./wait_for");
function severeErrors(driver) {
  return driver.manage().logs().get(logging.Type.BROWSER).then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// ---------------------------------------------------------------------------
// A credential to present.
//
// Minted straight from the mock Credential Issuer: a holder key pair generated
// here, a c_nonce, a proof of possession, and the Credential Request. What comes
// back — with the private half of that key — is exactly the state the issuance
// workflow leaves in the browser, which is this workflow's precondition.
// ---------------------------------------------------------------------------
async function mintCredential(label) {
  log.debug("Entering mintCredential(). label=" + label);
  var meta = (await httpJson(issuerBase + "/.well-known/openid-credential-issuer")).body;
  assert.ok(meta && meta.credential_endpoint, "the mock credential issuer should publish its metadata.");
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var publicJwk = pair.publicKey.export({ format: "jwk" });
  var privateJwk = pair.privateKey.export({ format: "jwk" });
  var nonce = (await httpJson(meta.nonce_endpoint, { method: "POST" })).body.c_nonce;
  var head = b64u(JSON.stringify({
    typ: "openid4vci-proof+jwt", alg: "ES256",
    jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }
  }));
  var claims = b64u(JSON.stringify({
    iss: "presentation-test", aud: meta.credential_issuer,
    iat: Math.floor(Date.now() / 1000), nonce: nonce
  }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var response = await httpJson(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer presentation-test-token" },
    body: JSON.stringify({
      credential_configuration_id: VCI_CONFIG_ID,
      proofs: { jwt: [head + "." + claims + "." + sig] }
    })
  });
  assert.ok(response.ok, "the mock issuer should mint a credential, got HTTP " + response.status +
    " " + response.raw);
  var credential = response.body.credentials[0].credential;
  var payload = jsonFromB64u(credential.split("~")[0].split(".")[1]);
  assert.strictEqual(payload.vct, EXPECTED_VCT, "the credential should be the configured type.");
  assert.ok(payload.cnf && payload.cnf.jwk, "and be bound to the holder key generated here.");
  log.info("[credential] minted a " + payload.vct + " for " + (label || "the presentation tests") +
           " with " + credential.split("~").filter(Boolean).length + " part(s).");
  log.debug("Leaving mintCredential().");
  return {
    credential: credential,
    payload: payload,
    publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
    privateJwk: privateJwk,
    privateKey: pair.privateKey,
    disclosures: credential.split("~").slice(1).filter(Boolean)
  };
}

// Put it where the wallet pages look for it — the same localStorage names the
// issuance workflow writes.
async function planCredentialIntoWallet(driver, held) {
  log.debug("Entering planCredentialIntoWallet().");
  await driver.get(baseUrl + "/vc-presentation-0.html");
  await driver.wait(until.elementLocated(By.id("vp_usecases")), waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credentials', JSON.stringify([arguments[0]]));" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);" +
    "localStorage.setItem('sdjwtvc_credential_meta', arguments[3]);" +
    // The verifier lives on the same service as the issuer for this mock, but
    // step 0 no longer INFERS that: it has a Configuration Parameters pane, and a
    // configured verifier wins over anything derived. Set it explicitly so this
    // suite points at the STS it actually started, rather than at whatever
    // oid4vpVerifierUrlDefault the target carries — http://localhost:8081 for
    // local.js, http://sts:8081 containerized, empty for the deployed sites.
    "localStorage.setItem('sdjwtvp_verifier_base_url', arguments[4]);" +
    "localStorage.setItem('sdjwtvp_verifier_jwks_url', arguments[4] + '/oauth2/jwks');" +
    "localStorage.setItem('vci_credential_issuer', arguments[4]);",
    held.credential, JSON.stringify(held.publicJwk), JSON.stringify(held.privateJwk),
    JSON.stringify({ issuer: issuerBase, configurationId: VCI_CONFIG_ID, vct: EXPECTED_VCT,
                     requestedAt: new Date().toISOString() }),
    issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vp_usecases")), waitTime);
  await driver.sleep(400);
  log.debug("Leaving planCredentialIntoWallet().");
}

// ---------------------------------------------------------------------------
// Building presentations here, independently of the pages: the negatives need
// presentations the wallet would never build.
// ---------------------------------------------------------------------------
function sdHash(prefix) {
  return b64u(crypto.createHash("sha256").update(prefix, "ascii").digest());
}

function signKbJwt(opts) {
  log.debug("Entering signKbJwt().");
  var header = b64u(JSON.stringify({ typ: opts.typ || "kb+jwt", alg: "ES256" }));
  var payload = b64u(JSON.stringify({
    iat: opts.iat || Math.floor(Date.now() / 1000),
    aud: opts.aud,
    nonce: opts.nonce,
    sd_hash: opts.sdHash
  }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(header + "." + payload),
    { key: opts.key, dsaEncoding: "ieee-p1363" }));
  log.debug("Leaving signKbJwt().");
  return header + "." + payload + "." + sig;
}

// A presentation, exactly as a correct wallet would build it — and the knobs the
// negatives need to break one of the rules at a time.
function buildPresentation(held, opts) {
  log.debug("Entering buildPresentation().");
  var issuerJwt = held.credential.split("~")[0];
  var selected = opts.disclosures || held.disclosures.filter(function (d) {
    var arr = JSON.parse(b64uDecode(d).toString("utf8"));
    return REQUESTED.indexOf(arr[1]) !== -1;
  });
  var prefix = [issuerJwt].concat(selected).join("~") + "~";
  var kb = signKbJwt({
    key: opts.key || held.privateKey,
    aud: opts.aud,
    nonce: opts.nonce,
    iat: opts.iat,
    typ: opts.typ,
    // sd_hash over a DIFFERENT prefix is how a presentation altered after
    // signing is simulated.
    sdHash: sdHash(opts.sdHashOver || prefix)
  });
  var body = opts.presentPrefix || prefix;
  log.debug("Leaving buildPresentation().");
  return { presentation: body + kb, prefix: prefix, kb: kb, selected: selected };
}

function postPresentation(responseUri, state, presentation) {
  var token = {};
  token[DCQL_ID] = [presentation];
  return httpJson(responseUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "vp_token=" + encodeURIComponent(JSON.stringify(token)) +
          "&state=" + encodeURIComponent(state)
  });
}

// A fresh Authorization Request from the mock verifier, read out of the redirect
// it answers with — which is what a wallet on the same device receives.
async function freshRequest(byReference) {
  log.debug("Entering freshRequest(). byReference=" + !!byReference);
  var r = await fetch(issuerBase + "/oid4vp/start" + (byReference ? "?by=reference" : ""),
    { redirect: "manual" });
  var location = r.headers.get("location");
  assert.ok(location, "the verifier should redirect the wallet with its request.");
  var query = location.slice(location.indexOf("?") + 1);
  var params = {};
  query.split("&").forEach(function (pair) {
    var eq = pair.indexOf("=");
    params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
  });
  log.debug("Leaving freshRequest(). state=" + params.state);
  return { params: params, location: location };
}

async function verdictFor(state) {
  var r = await httpJson(issuerBase + "/oid4vp/result/" + encodeURIComponent(state));
  assert.ok(r.ok, "the verifier should report what it decided, got HTTP " + r.status);
  return r.body;
}

// ---------------------------------------------------------------------------
// The verifier's own checks, exercised directly.
//
// No browser: these are presentations a correct wallet would never build, so
// building them here is the only way to find out whether the verifier actually
// enforces the rules — which is the part that matters, because a wallet that
// tests itself proves nothing.
// ---------------------------------------------------------------------------
async function verifierNegatives(held) {
  log.debug("Entering verifierNegatives().");
  log.info("=== NEGATIVE: presentations the verifier must refuse ===");

  function failedChecks(verdict) {
    return (verdict.checks || []).filter(function (c) { return !c.ok; })
      .map(function (c) { return c.name; });
  }

  // ---- a presentation replayed against a different request -----------------
  var first = await freshRequest();
  var second = await freshRequest();
  var forFirst = buildPresentation(held, {
    aud: first.params.client_id, nonce: first.params.nonce
  });
  var replayed = await postPresentation(second.params.response_uri, second.params.state,
    forFirst.presentation);
  assert.strictEqual(replayed.status, 400,
    "a presentation made for another request must be refused, got HTTP " + replayed.status);
  var replayVerdict = (await verdictFor(second.params.state)).verdict;
  assert.ok(failedChecks(replayVerdict).indexOf("KB-JWT nonce") !== -1,
    "and the nonce is what should fail. Failed: " + failedChecks(replayVerdict).join(", "));
  assert.ok(/nonce/i.test(replayed.body.error_description || ""),
    "the refusal should say so. Got: " + (replayed.body.error_description || "").slice(0, 120));
  log.info("[negative] OK — a replayed presentation is refused: " + failedChecks(replayVerdict).join(", "));

  // ---- a Key Binding JWT signed by the wrong key ---------------------------
  var wrong = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var third = await freshRequest();
  var wrongKey = buildPresentation(held, {
    aud: third.params.client_id, nonce: third.params.nonce, key: wrong.privateKey
  });
  var wrongKeyResult = await postPresentation(third.params.response_uri, third.params.state,
    wrongKey.presentation);
  assert.strictEqual(wrongKeyResult.status, 400,
    "a presentation signed by a key the credential is not bound to must be refused.");
  var wrongKeyVerdict = (await verdictFor(third.params.state)).verdict;
  assert.ok(failedChecks(wrongKeyVerdict).indexOf("KB-JWT signature") !== -1,
    "and the KB-JWT signature is what should fail. Failed: " + failedChecks(wrongKeyVerdict).join(", "));
  log.info("[negative] OK — a KB-JWT signed by another key is refused (holder binding means the cnf key, " +
           "not a key the presenter chose).");

  // ---- a Disclosure the issuer never signed -------------------------------
  var fourth = await freshRequest();
  var invented = b64u(JSON.stringify([b64u(crypto.randomBytes(16)), "age_over_21", true]));
  var spliced = buildPresentation(held, {
    aud: fourth.params.client_id, nonce: fourth.params.nonce,
    disclosures: held.disclosures.filter(function (d) {
      var arr = JSON.parse(b64uDecode(d).toString("utf8"));
      return REQUESTED.indexOf(arr[1]) !== -1;
    }).concat([invented])
  });
  var splicedResult = await postPresentation(fourth.params.response_uri, fourth.params.state,
    spliced.presentation);
  assert.strictEqual(splicedResult.status, 400,
    "a Disclosure the issuer never signed must be refused — that is a forged claim.");
  var splicedVerdict = (await verdictFor(fourth.params.state)).verdict;
  assert.ok(failedChecks(splicedVerdict).indexOf("Disclosure digests") !== -1,
    "and the digest check is what should fail. Failed: " + failedChecks(splicedVerdict).join(", "));
  assert.ok(!("age_over_21" in (splicedVerdict.claims || {})),
    "the invented claim must not appear in what the verifier believes.");
  log.info("[negative] OK — an invented Disclosure (age_over_21=true) is refused: it hashes to no digest " +
           "in _sd.");

  // ---- a Disclosure removed after the KB-JWT was signed -------------------
  // sd_hash is what makes this detectable: the KB-JWT commits to exactly the
  // bytes presented, so dropping one afterwards no longer matches.
  var fifth = await freshRequest();
  var all = held.disclosures.slice();
  var full = buildPresentation(held, {
    aud: fifth.params.client_id, nonce: fifth.params.nonce, disclosures: all
  });
  var trimmedPrefix = [held.credential.split("~")[0]].concat(all.slice(0, 1)).join("~") + "~";
  var trimmed = buildPresentation(held, {
    aud: fifth.params.client_id, nonce: fifth.params.nonce,
    disclosures: all,               // the KB-JWT still commits to all of them …
    presentPrefix: trimmedPrefix    // … but only one is actually presented.
  });
  var trimmedResult = await postPresentation(fifth.params.response_uri, fifth.params.state,
    trimmed.presentation);
  assert.strictEqual(trimmedResult.status, 400,
    "altering the presentation after the KB-JWT was signed must be refused.");
  var trimmedVerdict = (await verdictFor(fifth.params.state)).verdict;
  assert.ok(failedChecks(trimmedVerdict).indexOf("KB-JWT sd_hash") !== -1,
    "and sd_hash is what should catch it. Failed: " + failedChecks(trimmedVerdict).join(", "));
  log.info("[negative] OK — a presentation edited after signing is refused by sd_hash (" +
           full.selected.length + " committed, 1 presented).");

  // ---- and the same credential, presented correctly, IS accepted ----------
  // Without this the negatives above prove only that the verifier refuses
  // everything.
  var sixth = await freshRequest();
  var good = buildPresentation(held, { aud: sixth.params.client_id, nonce: sixth.params.nonce });
  var goodResult = await postPresentation(sixth.params.response_uri, sixth.params.state,
    good.presentation);
  assert.ok(goodResult.ok, "the same credential presented correctly must be accepted, got HTTP " +
    goodResult.status + " " + goodResult.raw);
  var goodVerdict = (await verdictFor(sixth.params.state)).verdict;
  assert.ok(goodVerdict.ok, "and the verdict should say so.");
  assert.deepStrictEqual(goodVerdict.disclosed.slice().sort(), REQUESTED.slice().sort(),
    "with exactly the claims asked for. Got: " + goodVerdict.disclosed.join(", "));
  log.info("[negative] OK — the control case is accepted, so the refusals above are about the defects and " +
           "not about the verifier.");
  log.debug("Leaving verifierNegatives().");
}

// ---------------------------------------------------------------------------
// POSITIVE: the workflow, through the pages.
// ---------------------------------------------------------------------------
async function presentThroughThePages(driver, held, byReference) {
  log.debug("Entering presentThroughThePages().");
  log.info("=== POSITIVE: presenting through the pages (" +
           (byReference ? "signed request by reference" : "request by value") + ") ===");

  // ---- step 0 -------------------------------------------------------------
  await planCredentialIntoWallet(driver, held);
  var holding = await text(driver, "vp_credential_state");
  assert.ok(/Holding a urn:idptools/.test(holding),
    "step 0 should say what the wallet is holding. Got: " + holding);
  assert.ok(/can be presented/.test(holding),
    "and that it has the key it is bound to. Got: " + holding);
  var cards = await driver.executeScript("return document.querySelectorAll('#vp_usecases button').length;");
  assert.strictEqual(cards, 3, "step 0 should offer the three OID4VP flows, got " + cards + ".");
  log.info("[step0] " + holding);

  // Choosing a flow goes to the VERIFIER: a presentation is something a verifier
  // asks for, so the workflow starts there.
  await click(driver, By.id(byReference ? "vp_usecase_same-device-signed" : "vp_usecase_same-device"));
  if (!byReference) {
    await driver.wait(until.elementLocated(By.id("present_by_value")), fetchWait,
      "choosing the flow should open the verifier's own web page.");
    var verifierPage = await driver.getCurrentUrl();
    assert.ok(verifierPage.indexOf(issuerBase) === 0,
      "which is hosted by the verifier, got: " + verifierPage);
    log.info("[step0] OK — the flow starts at the verifier: " + verifierPage);
    await click(driver, By.id("present_by_value"));
  }
  // As in the issuance suite: if the verifier's hand-off does not arrive, name the
  // URL the browser is actually on. The verifier builds it from OID4VP_WALLET_URL
  // (falling back to OID4VCI_WALLET_URL), and that default only works when the
  // browser and the wallet share a host.
  await driver.wait(until.urlContains("vc-presentation-1.html"), fetchWait,
    "the verifier should send the wallet the request.");

  // The wallet PAGE is in that URL — but is it this wallet? The verifier builds the
  // hand-off from OID4VP_WALLET_URL (falling back to OID4VCI_WALLET_URL), whose
  // default only works when the browser and the wallet share a host; in the
  // containerized stack the browser is in the tests container, where
  // localhost:3000 is nothing. The URL check above passes either way — the path is
  // right, only the origin is wrong — and what follows is a bare timeout waiting
  // for a page that never loaded. Check the origin and say so instead.
  var landedAt = await driver.getCurrentUrl();
  assert.ok(landedAt.indexOf(baseUrl) === 0,
    "the verifier sent the browser to " + landedAt + ", but the wallet under test is " + baseUrl +
    ". The verifier builds that URL from OID4VP_WALLET_URL / OID4VCI_WALLET_URL: set it to the base URL " +
    "the BROWSER uses (the containerized stack needs http://client:3000).");

  // ---- step 1: the request ------------------------------------------------
  await driver.wait(until.elementLocated(By.id("vp_request_status")), waitTime);
  await waitForStatus(driver, "vp_request_status",
    function (s) { return /Request read|cannot be answered/.test(s); },
    "step 1 never reported on the request");
  var request = await driver.executeScript(
    "return { clientId: document.getElementById('vp_client_id').textContent.trim()," +
    "         prefix: document.getElementById('vp_client_prefix').textContent.trim()," +
    "         note: document.getElementById('vp_client_note').textContent.trim()," +
    "         responseType: document.getElementById('vp_response_type').textContent.trim()," +
    "         responseMode: document.getElementById('vp_response_mode').textContent.trim()," +
    "         responseUri: document.getElementById('vp_response_uri').textContent.trim()," +
    "         nonce: document.getElementById('vp_nonce').textContent.trim()," +
    "         state: document.getElementById('vp_state').textContent.trim()," +
    "         dcql: document.getElementById('vp_dcql').textContent.trim()," +
    "         signature: document.getElementById('vp_signature_verdict').textContent.trim()," +
    "         source: document.getElementById('vp_source').textContent.trim()," +
    "         status: document.getElementById('vp_request_status').textContent.trim() };");
  assert.strictEqual(request.responseType, "vp_token",
    "OID4VP's response type is vp_token. Got: " + request.responseType);
  assert.strictEqual(request.responseMode, "direct_post",
    "the mock verifier asks for direct_post. Got: " + request.responseMode);
  assert.ok(request.responseUri.indexOf(issuerBase) === 0,
    "the response goes to the verifier. Got: " + request.responseUri);
  assert.ok(request.nonce && request.nonce !== "—",
    "a request without a nonce could be replayed; there should be one.");
  var dcql = JSON.parse(request.dcql);
  assert.strictEqual(dcql.credentials[0].format, "dc+sd-jwt",
    "the DCQL query should ask for the SD-JWT VC format.");
  assert.deepStrictEqual(dcql.credentials[0].claims.map(function (c) { return c.path.join("."); }),
    REQUESTED, "and name the claims it wants.");
  assert.ok(/Request read/.test(request.status),
    "step 1 should be able to answer this request. Got: " + request.status);

  if (byReference) {
    assert.ok(/request_uri/.test(request.source),
      "the request should have been fetched by reference. Got: " + request.source);
    assert.ok(/^VALID/.test(request.signature),
      "and its signature verified against the verifier's keys. Got: " + request.signature);
    assert.ok(/pre-registered/.test(request.note),
      "a signed request means a pre-registered client here. Got: " + request.note);
    log.info("[step1] OK — signed Request Object fetched by reference: " + request.signature);
  } else {
    assert.ok(/redirect_uri/.test(request.prefix),
      "by value the mock uses the redirect_uri client identifier prefix. Got: " + request.prefix);
    assert.ok(/cannot be signed/.test(request.note),
      "and the page should say why such a request cannot be signed. Got: " + request.note);
    log.info("[step1] OK — request by value, " + request.prefix);
  }

  // What is being asked for, against what the wallet holds.
  var asked = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vp_requested_table tbody tr'))" +
    "  .map(function (tr) {" +
    "    var td = tr.querySelectorAll('td');" +
    "    return { id: td[0].textContent.trim(), format: td[1].textContent.trim()," +
    "             vct: td[2].textContent.trim(), binding: td[3].textContent.trim()," +
    "             claims: td[4].textContent.trim(), missing: /not in the credential/.test(td[4].textContent) };" +
    "  });");
  assert.strictEqual(asked.length, 1, "one credential query, one row.");
  assert.strictEqual(asked[0].vct, EXPECTED_VCT, "the vct wanted should be shown.");
  assert.strictEqual(asked[0].binding, "required",
    "holder binding defaults to required, and the page should say so.");
  assert.ok(!asked[0].missing,
    "every claim asked for is in the credential this wallet holds. Got: " + asked[0].claims);
  log.info("[step1] asks for: " + asked[0].claims.replace(/\s+/g, " "));

  await click(driver, By.id("vp_continue_button"));
  await driver.wait(until.urlContains("vc-presentation-2.html"), waitTime,
    "step 1 should continue to the disclosure choice.");

  // ---- step 2: the choice and the presentation ----------------------------
  await driver.wait(until.elementLocated(By.id("vp_presentation")), waitTime);
  await waitForStatus(driver, "vp_present_status", function (s) { return /Ready|Could not/.test(s); },
    "step 2 never built a presentation");
  var rows = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vp_disclosures_table tbody tr'))" +
    "  .map(function (tr) {" +
    "    var td = tr.querySelectorAll('td');" +
    "    return { checked: td[0].querySelector('input').checked, claim: td[1].textContent.trim()," +
    "             value: td[2].textContent.trim(), asked: /asked for/.test(td[3].textContent) &&" +
    "                                                     !/not asked/.test(td[3].textContent) };" +
    "  });");
  assert.ok(rows.length >= 5,
    "the credential carries several selectively-disclosable claims, got " + rows.length + ".");
  var checkedClaims = rows.filter(function (r) { return r.checked; }).map(function (r) { return r.claim; });
  assert.deepStrictEqual(checkedClaims.slice().sort(), REQUESTED.slice().sort(),
    "the default selection should be exactly what the verifier asked for — a wallet should not have to be " +
    "told to minimise. Got: " + checkedClaims.join(", "));
  rows.forEach(function (r) {
    assert.strictEqual(r.asked, REQUESTED.indexOf(r.claim) !== -1,
      "each row should say whether this verifier asked for that claim. " + r.claim + " says " + r.asked);
  });
  log.info("[step2] " + rows.length + " Disclosure(s); selected by default: " + checkedClaims.join(", "));

  // The presentation, the KB-JWT, and the assembled call — all shown before
  // anything is sent.
  var built = await driver.executeScript(
    "return { presentation: document.getElementById('vp_presentation').value," +
    "         kbJwt: document.getElementById('vp_kb_jwt').value," +
    "         kbHeader: document.getElementById('vp_kb_header').textContent.trim()," +
    "         kbPayload: document.getElementById('vp_kb_payload').textContent.trim()," +
    "         sdHash: document.getElementById('vp_sd_hash').textContent.trim()," +
    "         vpToken: document.getElementById('vp_vp_token').textContent.trim()," +
    "         claims: document.getElementById('vp_presented_claims').textContent.trim()," +
    "         call: document.getElementById('vp_assembled_call').value };");
  var kbHeader = JSON.parse(built.kbHeader);
  var kbPayload = JSON.parse(built.kbPayload);
  assert.strictEqual(kbHeader.typ, "kb+jwt", "RFC 9901 section 4.3 requires typ kb+jwt.");
  assert.strictEqual(kbHeader.alg, "ES256", "and an alg that is not none.");
  assert.strictEqual(kbPayload.nonce, request.nonce, "the KB-JWT carries the request's nonce.");
  assert.strictEqual(kbPayload.aud, request.clientId,
    "and is addressed to the verifier's Client Identifier.");
  assert.ok(kbPayload.iat, "and says when it was signed.");
  assert.strictEqual(kbPayload.sd_hash, built.sdHash, "sd_hash is shown next to the KB-JWT carrying it.");

  // Recomputed here: the page's arithmetic is not evidence.
  var parts = built.presentation.split("~");
  var prefix = parts.slice(0, parts.length - 1).join("~") + "~";
  assert.strictEqual(kbPayload.sd_hash, sdHash(prefix),
    "sd_hash must be the hash of the issuer-signed JWT and the presented Disclosures, each followed by a tilde.");
  assert.strictEqual(parts[parts.length - 1], built.kbJwt,
    "the presentation should end in the KB-JWT shown above it.");
  var presentedNames = parts.slice(1, parts.length - 1).filter(Boolean).map(function (d) {
    return JSON.parse(b64uDecode(d).toString("utf8"))[1];
  });
  assert.deepStrictEqual(presentedNames.slice().sort(), REQUESTED.slice().sort(),
    "and carry exactly the Disclosures selected. Got: " + presentedNames.join(", "));
  var vpToken = JSON.parse(built.vpToken);
  assert.ok(Array.isArray(vpToken[DCQL_ID]) && vpToken[DCQL_ID][0] === built.presentation,
    "the vp_token is a JSON object keyed by the DCQL credential query id (OID4VP section 8.1).");
  assert.strictEqual(built.call.split("\n")[0], "POST " + request.responseUri,
    "the assembled call should be the POST to the Response URI. Got: " + built.call.split("\n")[0]);
  // The KB-JWT verifies against the key the credential is bound to.
  var cnfKey = crypto.createPublicKey({ key: held.payload.cnf.jwk, format: "jwk" });
  var kbParts = built.kbJwt.split(".");
  assert.ok(crypto.verify("sha256", Buffer.from(kbParts[0] + "." + kbParts[1]), {
    key: cnfKey, dsaEncoding: "ieee-p1363"
  }, b64uDecode(kbParts[2])),
    "the KB-JWT must verify against the cnf key in the credential.");
  log.info("[step2] OK — SD-JWT+KB built: " + presentedNames.length + " Disclosure(s), sd_hash " +
           built.sdHash.slice(0, 12) + "…, KB-JWT verified against cnf.jwk here.");

  // ---- present it ---------------------------------------------------------
  await click(driver, By.id("vp_present_button"));
  await driver.wait(until.urlContains("vc-presentation-3.html"), fetchWait,
    "presenting should open step 3 with the verdict.");
  await driver.sleep(600);

  // ---- step 3: both accounts of it ---------------------------------------
  await waitForStatus(driver, "vp_verifier_status",
    function (s) { return /ACCEPTED|REFUSED|could not be fetched/.test(s); },
    "step 3 never reported the verifier's verdict");
  var verdictText = await text(driver, "vp_verifier_status");
  assert.ok(/ACCEPTED/.test(verdictText),
    "the verifier should have accepted this presentation. Got: " + verdictText);
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vp_verifier_table tbody tr'))" +
    "  .map(function (tr) {" +
    "    var td = tr.querySelectorAll('td');" +
    "    return { name: td[0].textContent.trim(), result: td[1].textContent.trim() };" +
    "  });");
  assert.ok(checks.length >= 10,
    "the verifier should report every check it made, got " + checks.length + ".");
  assert.strictEqual(checks.filter(function (c) { return c.result !== "OK"; }).length, 0,
    "and all of them should pass: " + JSON.stringify(checks));
  ["Issuer signature", "Disclosure digests", "KB-JWT signature", "KB-JWT sd_hash", "KB-JWT nonce",
   "KB-JWT audience", "Requested claims"].forEach(function (name) {
    assert.ok(checks.some(function (c) { return c.name === name; }),
      "the verifier must check " + name + ". Checks: " + checks.map(function (c) { return c.name; }).join(", "));
  });
  var own = await driver.executeScript(
    "return { status: document.getElementById('vp_recheck_status').textContent.trim()," +
    "         rows: Array.prototype.slice.call(document.querySelectorAll('#vp_recheck_table tbody tr'))" +
    "                 .map(function (tr) { var td = tr.querySelectorAll('td');" +
    "                                      return td[0].textContent.trim() + '=' + td[1].textContent.trim(); }) };");
  assert.ok(/all pass/.test(own.status),
    "the wallet's own checks on what it sent should pass too. Got: " + own.status);
  var disclosedText = await text(driver, "vp_verifier_disclosed");
  var extraText = await text(driver, "vp_verifier_extra");
  assert.deepStrictEqual(disclosedText.split(", ").sort(), REQUESTED.slice().sort(),
    "the verifier should have received exactly the claims it asked for. Got: " + disclosedText);
  assert.ok(/^none/.test(extraText),
    "and nothing more — no over-disclosure. Got: " + extraText);
  var verifierClaims = JSON.parse(await text(driver, "vp_verifier_claims"));
  REQUESTED.forEach(function (name) {
    assert.ok(name in verifierClaims, "the verifier should know " + name + ".");
  });
  ["email", "birthdate", "nationality", "address"].forEach(function (name) {
    assert.ok(!(name in verifierClaims),
      "and must NOT know " + name + ": it was never disclosed. Claims: " + Object.keys(verifierClaims).join(", "));
  });
  log.info("[step3] OK — verifier accepted; " + checks.length + " checks passed; it knows " +
           Object.keys(verifierClaims).join(", ") + " and nothing else.");
  log.debug("Leaving presentThroughThePages().");
  return { checks: checks, claims: verifierClaims };
}

// ---------------------------------------------------------------------------
// NEGATIVE, through the pages: withhold a claim the verifier asked for.
//
// The wallet is allowed to send less — it is the holder's credential — and the
// verifier is entitled to refuse. Both halves of that have to work, and the
// pages have to say which check failed rather than "no".
// ---------------------------------------------------------------------------
async function withholdARequestedClaim(driver, held) {
  log.debug("Entering withholdARequestedClaim().");
  log.info("=== NEGATIVE: withholding a claim the verifier asked for ===");
  await planCredentialIntoWallet(driver, held);
  var request = await freshRequest();
  // Straight to step 1 with the request, the way the verifier's redirect arrives.
  await driver.get(baseUrl + "/vc-presentation-1.html?" +
    request.location.slice(request.location.indexOf("?") + 1));
  await driver.wait(until.elementLocated(By.id("vp_request_status")), waitTime);
  await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
    "the request should be readable");
  await click(driver, By.id("vp_continue_button"));
  await driver.wait(until.elementLocated(By.id("vp_disclosures_table")), waitTime);
  await waitForStatus(driver, "vp_present_status", function (s) { return /Ready/.test(s); },
    "step 2 never built a presentation");

  // Deselect the first claim the verifier asked for.
  var target = await driver.executeScript(
    "var rows = Array.prototype.slice.call(document.querySelectorAll('#vp_disclosures_table tbody tr'));" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  var box = td[0].querySelector('input');" +
    "  if (box.checked) { box.click(); return td[1].textContent.trim(); }" +
    "} return null;", REQUESTED[0]);
  assert.ok(target, "there should have been a selected claim to deselect.");
  var summary = await waitForStatus(driver, "vp_selection_summary",
    function (s) { return new RegExp(target).test(s) && /asked for it/.test(s); },
    "the page should warn that a claim the verifier asked for is not selected");
  assert.ok(new RegExp(target).test(summary) && /asked for it/.test(summary),
    "the page should warn that a claim the verifier asked for is not selected. Got: " + summary);
  var warned = await text(driver, "vp_present_status");
  assert.ok(/missing a claim the verifier asked for/.test(warned),
    "and say the verifier will refuse it. Got: " + warned);
  log.info("[negative] withheld " + target + "; the page warns: " + summary.replace(/\s+/g, " ").slice(0, 120));

  // Send it anyway: the verifier must refuse, and step 3 must say which check.
  await click(driver, By.id("vp_present_button"));
  await driver.wait(until.urlContains("vc-presentation-3.html"), fetchWait,
    "a refused presentation should still open step 3 — that is where the reason is.");
  await driver.sleep(600);
  var verdict = await waitForStatus(driver, "vp_verifier_status",
    function (s) { return /ACCEPTED|REFUSED/.test(s); }, "step 3 never reported the verdict");
  assert.ok(/REFUSED/.test(verdict), "the verifier must refuse it. Got: " + verdict);
  assert.ok(/Requested claims/.test(verdict),
    "and the failing check should be the one about the claims it asked for. Got: " + verdict);
  var failed = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vp_verifier_table tbody tr'))" +
    "  .filter(function (tr) { return tr.querySelectorAll('td')[1].textContent.trim() !== 'OK'; })" +
    "  .map(function (tr) { var td = tr.querySelectorAll('td');" +
    "                       return { name: td[0].textContent.trim(), detail: td[2].textContent.trim() }; });");
  assert.strictEqual(failed.length, 1,
    "exactly one check should fail — everything else about the presentation was fine: " +
    JSON.stringify(failed));
  assert.strictEqual(failed[0].name, "Requested claims");
  assert.ok(new RegExp(target).test(failed[0].detail),
    "and it should name the missing claim. Got: " + failed[0].detail);
  // The wallet's own checks still pass: what it sent was a valid presentation,
  // just not the one asked for. That distinction is the point of showing both.
  var own = await text(driver, "vp_recheck_status");
  assert.ok(/all pass/.test(own),
    "the presentation itself was well-formed — the wallet's own checks should still pass. Got: " + own);

  // And the wallet says so on its OWN side of the page, without being told by the
  // verifier. This mock does refuse an unanswered request; a real verifier need
  // not — walt.id's accepts it silently — so the wallet's statement is the only
  // one always available, and it is checked here rather than only in the
  // interoperability suite, which is skipped when walt.id is not running.
  var answered = await text(driver, "vp_answered");
  assert.ok(/NOT fully answered/.test(answered),
    "step 3 should say on the wallet's own account that the request was not fully answered. Got: " +
    answered);
  assert.ok(new RegExp(target).test(answered),
    "and name the withheld claim. Got: " + answered);
  log.info("[negative] OK — refused for " + failed[0].name + ": " + failed[0].detail.slice(0, 90) +
           "; the wallet's own account: " + answered.slice(0, 90));
  log.debug("Leaving withholdARequestedClaim().");
}

// ---------------------------------------------------------------------------
// The same layout rule the issuance pages have to keep: everything these panes
// display is base64url with no break opportunity in it, so nothing may run off
// the side of a pane and the page must not scroll sideways. Checked with values
// far longer than the real ones, because the real ones are short enough to hide
// the defect.
// ---------------------------------------------------------------------------
async function panesContainTheirContent(driver) {
  log.debug("Entering panesContainTheirContent().");
  log.info("=== Nothing overflows its pane ===");
  var pages = ["vc-presentation-0.html", "vc-presentation-1.html",
               "vc-presentation-2.html", "vc-presentation-3.html"];
  for (var i = 0; i < pages.length; i++) {
    await driver.get(baseUrl + "/" + pages[i]);
    await driver.wait(until.elementLocated(By.id("vp_steps")), waitTime);
    await driver.sleep(500);
    var result = await driver.executeScript(
      "var long = new Array(24).join('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9');" +
      "Array.prototype.slice.call(document.querySelectorAll('.dbg-pane code')).forEach(function (c) {" +
      "  if (c.id) c.textContent = long;" +
      "});" +
      "var out = [];" +
      "Array.prototype.slice.call(document.querySelectorAll('.dbg-pane')).forEach(function (pane) {" +
      "  var pr = pane.getBoundingClientRect();" +
      "  Array.prototype.slice.call(pane.querySelectorAll('code, pre, textarea, table')).forEach(function (e) {" +
      "    var r = e.getBoundingClientRect();" +
      "    if (r.width <= 0) return;" +
      "    var over = Math.round(r.right - (pr.right - 12));" +
      "    if (over > 0) out.push({ pane: pane.id, tag: e.tagName, id: e.id || '(none)', over: over });" +
      "  });" +
      "});" +
      "var ol = document.getElementById('vp_steps');" +
      "var items = Array.prototype.slice.call(ol.querySelectorAll('li'));" +
      "return { overflowing: out," +
      "         doc: document.documentElement.scrollWidth - document.documentElement.clientWidth," +
      "         steps: items.length," +
      "         stepTops: items.map(function (li) { return Math.round(li.getBoundingClientRect().top); }) };");
    assert.strictEqual(result.overflowing.length, 0,
      pages[i] + ": these elements extend past the pane that contains them — " +
      result.overflowing.map(function (o) {
        return o.id + " (" + o.tag + " in " + o.pane + ", " + o.over + "px)";
      }).join(", "));
    assert.ok(result.doc <= 0,
      pages[i] + " should not scroll horizontally, even with values this long. Got " + result.doc + "px.");
    // And the workflow's own step links: all four, on one row, like the issuance
    // workflow's five.
    assert.strictEqual(result.steps, 4, pages[i] + " should link to all four steps.");
    assert.strictEqual(Math.max.apply(null, result.stepTops) - Math.min.apply(null, result.stepTops), 0,
      pages[i] + ": the step links should be on one row. Tops: " + JSON.stringify(result.stepTops));
    log.info("[layout] " + pages[i] + ": every box fits its pane, four step links on one row.");
  }
  log.info("[layout] OK — all four presentation pages.");
  log.debug("Leaving panesContainTheirContent().");
}

// ---------------------------------------------------------------------------
// Refusing is an answer too (OID4VP section 8.4).
// ---------------------------------------------------------------------------
async function refusingIsAnAnswer(driver, held) {
  log.debug("Entering refusingIsAnAnswer().");
  log.info("=== The holder refuses ===");
  await planCredentialIntoWallet(driver, held);
  var request = await freshRequest();
  await driver.get(baseUrl + "/vc-presentation-1.html?" +
    request.location.slice(request.location.indexOf("?") + 1));
  await driver.wait(until.elementLocated(By.id("vp_continue_button")), waitTime);
  await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
    "the request should be readable");
  await click(driver, By.id("vp_continue_button"));
  await driver.wait(until.elementLocated(By.id("vp_refuse_button")), waitTime);
  await waitForStatus(driver, "vp_present_status", function (s) { return /Ready/.test(s); },
    "step 2 never built a presentation");
  await click(driver, By.id("vp_refuse_button"));
  await waitForStatus(driver, "vp_present_status", function (s) { return /Refused/.test(s); },
    "refusing should say so");
  var doc = await verdictFor(request.params.state);
  assert.ok(doc.verdict && doc.verdict.refused,
    "the verifier should have been told the holder declined. Got: " + JSON.stringify(doc.verdict));
  assert.strictEqual(doc.verdict.error, "access_denied",
    "with the error OID4VP defines for it. Got: " + doc.verdict.error);
  assert.ok(!doc.verdict.claims, "and no claims should have reached it.");
  log.info("[refuse] OK — access_denied reached the verifier and nothing was disclosed.");
  log.debug("Leaving refusingIsAnAnswer().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. issuer/verifier=" + issuerBase + ", wallet=" + baseUrl);
  var held = await mintCredential("the positive flow");
  await verifierNegatives(held);

  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options().setLoggingPrefs(prefs)
    .addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox", "--disable-dev-shm-usage");
  }
  // Two environment hazards this workflow is exposed to, both silent: it is all Web
  // Crypto (holder key pairs, proofs of possession, Key Binding JWTs, signature
  // verification), which needs a secure context; and its pages must fetch this
  // suite's services on loopback, which a deployed https page may not do without
  // the private-network flags. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    await presentThroughThePages(driver, held, false);
    await presentThroughThePages(driver, held, true);
    await refusingIsAnAnswer(driver, held);
    await panesContainTheirContent(driver);

    var errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the workflow logged browser errors:\n" + errors.join("\n"));
    log.info("[browser] OK — no console errors across the workflow.");

    // Runs after the console check: a refused presentation legitimately earns a
    // 400, which Chrome logs as a page error.
    await withholdARequestedClaim(driver, held);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option('-u, --url <url>', 'base url of the debugger under test'));
program.addOption(new Option('-h, --headless <headless>', 'run headless (true/false)'));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
