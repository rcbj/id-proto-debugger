// File: sd_jwt_vc_waltid.js
//
// The SD-JWT VC issuance workflow driven against **walt.id issuer-api2** — a
// real, independently written OpenID4VCI 1.0 Credential Issuer — instead of the
// mock issuer in sts/. The mock stays: it is what lets the other suite test
// error paths and run with no third-party image. This file answers a different
// question, and only that one:
//
//     does what we built actually interoperate with someone else's
//     implementation of the same specification?
//
// It is deliberately the SAME pages, the same bundles and the same buttons the
// mock-issuer suite drives. Nothing here is walt.id-specific on our side; every
// difference below is a difference in the issuer, and the workflow either
// copes with it or the test fails:
//
//   * walt.id's Credential Issuer Identifier has a PATH (…/openid4vci), so its
//     metadata lives at /.well-known/openid-credential-issuer/openid4vci —
//     RFC 8414 section 3.1 inserts the well-known segment, it is not appended.
//   * it publishes no `authorization_servers`, which per OID4VCI section 11.2.3
//     means it is its own authorization server.
//   * it signs with a did:jwk, so the credential's `iss` is not a URL and the
//     verification key is carried inside the identifier.
//   * it authenticates the End-User at an EXTERNAL OpenID Provider — here, the
//     same Keycloak realm the rest of the suite uses. So the run is a genuine
//     three-party issuance: our wallet, walt.id, and Keycloak.
//
// Both implemented use cases are covered: H.6 (wallet-initiated) and H.1
// (issuer-initiated Credential Offer, created through walt.id's own management
// API, exactly as walt.id's portal would create it).
//
// Needs the waltid-issuer container and Keycloak. WALTID_ISSUER_URL locates the
// issuer (default http://localhost:7005) and KEYCLOAK_BASE_URL the IdP.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'sd_jwt_vc_waltid',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 25000);
// The budget every waitFor* in ./wait_for.js uses. Set once: one test file
// runs per process.
require("./wait_for").configure({ timeout: fetchWait });

// walt.id's service, and the Credential Issuer Identifier it publishes — which
// is the service URL plus a path. That path is the whole point of several of
// the assertions below.
var waltidBase = (process.env.WALTID_ISSUER_URL ||
    "http://localhost:7005").replace(/\/+$/, "");
var issuerId = waltidBase + "/openid4vci";
var metadataUrl = waltidBase +
    "/.well-known/openid-credential-issuer/openid4vci";
var keycloakBase = process.env.KEYCLOAK_BASE_URL || "http://localhost:8080";

// The OIDC Authorization Code public client the suite provisions; its user has
// the same name and password, and the same first and last name. walt.id copies
// the id_token's given_name / family_name into the credential, so that user's
// name is what the issued credential must end up carrying.
var clientId = process.env.SD_JWT_VC_CLIENT_ID ||
    "oidc-authorization-code-public";
var CONFIGURATION_ID = "identity_credential";
var PROFILE_ID = "identityCredentialSdJwt";
var SD_JWT_VC_TYP = "dc+sd-jwt";
var PRE_AUTHORIZED_GRANT =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

const waitForContent = require("./wait_for.js");

// "The page's bundle has run", which is a different question from "the page's
// markup is there" and the one that matters before pressing anything: every
// control in this application is wired with an inline onclick naming a
// browserify --standalone global, so a click that lands before the bundle has
// executed raises ReferenceError inside the page and does nothing at all out
// here. waitForPageBundle() in tests/wait_for.js reads the page's own script
// tags, so this needs no table of global names, and its note records what the
// missing wait cost.
async function pageBundleReady(driver) {
  log.debug("Entering pageBundleReady().");
  await waitForContent.waitForPageBundle(driver,
    "the page this test just navigated to");
  log.debug("Leaving pageBundleReady().");
}

// ---------------------------------------------------------------------------
// helpers (same shapes as sd_jwt_vc_issuance.js, so the two read alike)
// ---------------------------------------------------------------------------
function b64uDecode(s) {
  log.debug("Entering b64uDecode().");
  log.debug("Leaving b64uDecode().");
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function jsonFromB64u(s) {
  log.debug("Entering jsonFromB64u().");
  log.debug("Leaving jsonFromB64u().");
  return JSON.parse(b64uDecode(s).toString("utf8"));
}

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
  await driver.executeScript("arguments[0].scrollIntoView({ block: " +
                             "'center' });", e);
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
// implementation, shared by these suites. It waits on CONTENT rather than on
// the element: every field here is static markup, so locating it proves nothing
// about whether the page has filled it in, and the fixed sleeps that used to
// stand in for that lost the race periodically. It also reports what the field
// LAST held on a timeout, which the local copy of waitForStatus could not — its
// message was built before the first poll, so it always said "(last status: )".
const { text, value, waitForStatus, waitForValue } = require("./wait_for");
function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  log.debug("Leaving severeErrors().");
  return driver.manage().logs().get(logging.Type.BROWSER)
                       .then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      // A favicon that is not there is not a page error.
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// Start every section from a wallet pointed at the WRONG issuer.
//
// Clearing is not enough to prove that a step configured anything: the fields
// fall back to this deployment's defaults, and a default that happens to be
// right makes the assertion vacuous. A deliberately wrong value cannot be
// satisfied by accident — whatever is correct afterwards was put there by the
// thing under test.
var WRONG_ISSUER = "http://localhost:1/not-the-offering-issuer";

async function misconfigureTheWallet(driver) {
  log.debug("Entering misconfigureTheWallet().");
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "var wrong = {" +
    "  vci_metadata_endpoint: arguments[0] + " +
        "'/.well-known/openid-credential-issuer'," +
    "  vci_credential_issuer: arguments[0]," +
    "  vci_credential_endpoint: arguments[0] + '/credential'," +
    "  vci_deferred_credential_endpoint: arguments[0] + " +
        "'/deferred_credential'," +
    "  vci_credential_configuration_id: 'NotTheOfferedCredential'," +
    "  authorization_endpoint: arguments[0] + '/authorize'," +
    "  token_endpoint: arguments[0] + '/token'" +
    "};" +
    "Object.keys(wrong).forEach(function (k) { " +
        "window.localStorage.setItem(k, wrong[k]); });",
    WRONG_ISSUER);
  log.debug("Leaving misconfigureTheWallet(). The wallet now points at " +
            WRONG_ISSUER + ".");
}

// ---------------------------------------------------------------------------
// What the wallet is up against: walt.id's published metadata, read directly.
// This section makes the interop differences explicit, so that a failure later
// can be read as "the workflow mishandled X" rather than "something broke".
// ---------------------------------------------------------------------------
async function whatWaltidPublishes() {
  log.debug("Entering whatWaltidPublishes().");
  var inserted = await httpJson(metadataUrl);
  assert.strictEqual(inserted.status, 200,
    "walt.id should serve its credential issuer metadata at the RFC 8414 " +
        "path-inserted URL " +
    metadataUrl + ". Got HTTP " + inserted.status +
        ". Is the waltid-issuer container up?");
  var meta = inserted.body;

  assert.strictEqual(meta.credential_issuer, issuerId,
    "the Credential Issuer Identifier should be " + issuerId + ". Got: " +
        meta.credential_issuer);

  // The identifier has a path, so the two ways of building a well-known URL are
  // different strings — and only one of them is where the document is. A wallet
  // that appends finds nothing here, which is exactly the bug this suite exists
  // to keep fixed.
  var appended = await httpJson(issuerId +
      "/.well-known/openid-credential-issuer");
  assert.ok(appended.status === 404,
    "appending the well-known to an issuer identifier WITH a path should not " +
        "find the document " +
    "(that is what makes this a real interop test). Got HTTP " +
        appended.status + ".");

  var config = (meta.credential_configurations_supported ||
      {})[CONFIGURATION_ID];
  assert.ok(config, "walt.id should offer the " + CONFIGURATION_ID +
            " configuration. Got: " +
    Object.keys(meta.credential_configurations_supported || {}).join(", "));
  assert.strictEqual(config.format, SD_JWT_VC_TYP,
    "the offered credential should be an SD-JWT VC (" + SD_JWT_VC_TYP +
        "). Got: " + config.format);
  assert.ok(meta.nonce_endpoint,
      "OID4VCI 1.0 issuers publish a nonce_endpoint; walt.id's is missing.");
  assert.ok(!meta.authorization_servers,
    "this deployment of walt.id is its own authorization server, so " +
        "authorization_servers should be " +
    "absent — the wallet has to fall back to the credential issuer. Got: " +
    JSON.stringify(meta.authorization_servers));

  var as = await httpJson(waltidBase +
      "/.well-known/oauth-authorization-server/openid4vci");
  assert.strictEqual(as.status, 200,
      "walt.id should publish RFC 8414 metadata at the inserted path.");
  assert.strictEqual(as.body.issuer, issuerId,
                     "its authorization server should be the issuer itself.");
  assert.ok(String(as.body.grant_types_supported ||
            "").indexOf("authorization_code") !== -1,
    "the authorization code grant should be supported. Got: " +
        JSON.stringify(as.body.grant_types_supported));

  log.info("[waltid] OK — a real OID4VCI 1.0 issuer at " + issuerId +
           ": " + SD_JWT_VC_TYP + " " + CONFIGURATION_ID +
               ", metadata at the path-inserted URL, " +
           "its own authorization server.");
  log.debug("Leaving whatWaltidPublishes().");
  return meta;
}

// ---------------------------------------------------------------------------
// Step 1 driven against walt.id, then the hand-off. Shared by both use cases:
// they differ in how the wallet was configured, not in what happens next.
// ---------------------------------------------------------------------------
async function configureFromWaltid(driver) {
  log.debug("Entering configureFromWaltid().");
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
        metadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "step 1 should retrieve walt.id's credential issuer metadata");

  assert.strictEqual(await value(driver, "vci_credential_issuer"), issuerId,
    "the pane should be populated from walt.id's document.");
  assert.strictEqual(await value(driver, "vci_credential_endpoint"), issuerId +
                     "/credential",
    "the credential endpoint should come from that document.");
  assert.strictEqual(await value(driver, "vci_nonce_endpoint"), issuerId +
                     "/nonce",
    "the nonce endpoint should come from that document.");
  // Choose the credential to ask for, the way a user does: the pane lists every
  // configuration the issuer supports and this deployment of walt.id may well
  // publish more than one (their public demo publishes twenty).
  await driver.executeScript(
    "var s = document.getElementById('vci_credential_configuration_select');" +
    "s.value = arguments[0];" +
    "vcissuance1.onCredentialConfigurationChange();", CONFIGURATION_ID);
  await waitForValue(driver, "vci_credential_configuration_id",
    function (v) { return v === CONFIGURATION_ID; },
    "choosing the credential configuration should select it");
  assert.strictEqual(await value(driver, "vci_format"), SD_JWT_VC_TYP,
    "the chosen configuration should be an SD-JWT VC.");

  // walt.id names no authorization server, so the wallet has to conclude that
  // the credential issuer is one — and look for its metadata at the inserted
  // path, under the issuer's own path component.
  var asUrl = await value(driver, "oidc_discovery_endpoint");
  assert.strictEqual(asUrl, waltidBase +
                     "/.well-known/oauth-authorization-server/openid4vci",
    "with no authorization_servers member the wallet should fall back to the " +
        "credential issuer " +
    "itself, at the path-inserted well-known URL. Got: " + asUrl);

  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "step 1 should retrieve walt.id's authorization server metadata");
  assert.strictEqual(await value(driver, "authorization_endpoint"), issuerId +
                     "/authorize",
    "the authorization endpoint should come from walt.id's RFC 8414 document.");
  assert.strictEqual(await value(driver, "token_endpoint"), issuerId + "/token",
    "the token endpoint should come from walt.id's RFC 8414 document.");

  // The credential configuration's scope is how an authorization code request
  // asks for authorization to issue that credential (OID4VCI section 5.1.2).
  await driver.executeScript(
    "document.getElementById('scope').value = arguments[0];" +
    "document.getElementById('client_id').value = arguments[1];",
    CONFIGURATION_ID, clientId);
  var save = await driver.findElements(By.id("config_save_button"));
  if (save.length) {
    await click(driver, By.id("config_save_button"));
  }
  log.debug("Leaving configureFromWaltid().");
}

// The OIDC leg: our page hands off to oauth2_oidc_1.html, walt.id's
// authorization endpoint bounces the browser to Keycloak, the user signs in
// there, and walt.id issues its own authorization code which oauth2_oidc_2.html
// exchanges.
async function authorizeAtWaltid(driver) {
  log.debug("Entering authorizeAtWaltid().");
  await click(driver, By.id("start_issuance_button"));

  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "walt.id should send the End-User to Keycloak to authenticate.");
  var loginUrl = await driver.getCurrentUrl();
  assert.ok(loginUrl.indexOf(keycloakBase) === 0,
    "the login should happen at the external OpenID Provider walt.id was " +
        "configured with (" +
    keycloakBase + "). Got: " + loginUrl);

  await driver.findElement(By.id("username")).sendKeys(clientId);
  await driver.findElement(By.id("password")).sendKeys(clientId);
  await click(driver, By.id("kc-login"));

  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "after authenticating, the workflow should come back to step 2 " +
        "with tokens.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "step 2 should have an access token issued BY WALT.ID.");

  var accessToken = await value(driver, "vc_access_token");
  var claims = jsonFromB64u(accessToken.split(".")[1]);
  assert.strictEqual(claims.iss, issuerId,
    "the access token should have been issued by walt.id itself. Got iss: " +
        claims.iss);
  log.info("[waltid] OK — authenticated at Keycloak and came back with an " +
           "access token walt.id issued.");
  log.debug("Leaving authorizeAtWaltid().");
  return accessToken;
}

// Approve on step 2 — which fetches walt.id's c_nonce, signs an
// openid4vci-proof+jwt with the holder key, and POSTs the Credential Request.
async function approveAndCollect(driver) {
  log.debug("Entering approveAndCollect().");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should fetch a c_nonce from walt.id and sign a proof " +
      "of possession with it.");

  // The c_nonce is displayed, not typed: it lives in a <code>, so read its
  // text.
  var nonce = await text(driver, "vc_nonce");
  var proof = await value(driver, "vc_proof_jwt");
  var proofHeader = jsonFromB64u(proof.split(".")[0]);
  var proofPayload = jsonFromB64u(proof.split(".")[1]);
  // The page writes an explanatory "— (…)" in that spot when it has no nonce,
  // so a non-empty string is not enough on its own.
  assert.ok(nonce && nonce.indexOf("\u2014") !== 0,
    "walt.id's nonce endpoint should have answered with a c_nonce. Got: " +
        nonce);
  assert.strictEqual(proofHeader.typ, "openid4vci-proof+jwt",
    "the proof should be typed as OID4VCI requires. Got: " + proofHeader.typ);
  assert.strictEqual(proofPayload.aud, issuerId,
    "the proof's audience must be walt.id's Credential Issuer " +
        "Identifier. Got: " + proofPayload.aud);
  assert.strictEqual(proofPayload.nonce, nonce,
    "the proof should carry the c_nonce walt.id handed out.");

  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "walt.id should accept the Credential Request and the workflow should " +
        "move to step 3.");
  await driver.sleep(900);
  log.info("[waltid] OK — walt.id accepted our c_nonce, our proof of " +
           "possession and our " +
           "Credential Request, and issued a credential.");
  log.debug("Leaving approveAndCollect().");
}

// Step 3: what the page concluded, and the same credential checked here so a
// page that merely claims the credential is fine cannot pass.
async function checkCredential(driver, what, opts) {
  log.debug("Entering checkCredential().");
  opts = opts || {};
  var credential = await value(driver, "vc_credential_raw");
  assert.ok(credential && credential.indexOf("~") !== -1,
    "step 3 should show the Combined Serialization walt.id returned.");
  assert.strictEqual(credential.trim().slice(-1), "~",
    "an SD-JWT VC with no Key Binding JWT ends with '~' (RFC 9901).");

  var parts = credential.split("~");
  var header = jsonFromB64u(parts[0].split(".")[0]);
  var payload = jsonFromB64u(parts[0].split(".")[1]);
  assert.strictEqual(header.typ, SD_JWT_VC_TYP,
    "the issuer-signed JWT should be typed " + SD_JWT_VC_TYP + ". Got: " +
        header.typ);
  assert.ok(String(payload.iss).indexOf("did:jwk:") === 0,
    "walt.id signs with a did:jwk, so that is what iss should be. Got: " +
        payload.iss);
  assert.ok(payload.cnf && payload.cnf.jwk,
    "the credential should be bound to the holder key step 2 generated.");
  assert.strictEqual(payload.vct, issuerId + "/" + CONFIGURATION_ID,
    "the vct should be the type walt.id publishes for this " +
        "configuration. Got: " + payload.vct);

  // The credential must be bound to the key THIS browser generated. The holder
  // key is displayed on step 2 and we are on step 3 by now, so take it from
  // what the workflow recorded when it made the request — a different source
  // from the credential itself, which is what makes the comparison worth
  // making.
  var record = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem('sdjwtvc_credential_meta') || '{}');");
  assert.ok(record.holderJwk && record.holderJwk.x,
    "the workflow should record the holder key it asked the issuer to bind " +
        "to. Got: " +
    JSON.stringify(record.holderJwk));
  assert.strictEqual(payload.cnf.jwk.x, record.holderJwk.x,
    "the cnf key should be the holder key this browser generated, " +
        "not another.");

  // Whoever signed in at Keycloak is who the credential is about: walt.id maps
  // the id_token's given_name into it. That is the three-party flow, proven.
  var disclosed = {};
  parts.slice(1).filter(Boolean).forEach(function (d) {
    var parsed = JSON.parse(b64uDecode(d).toString("utf8"));
    disclosed[parsed[1]] = parsed[2];
  });
  var subjectName = disclosed.given_name || payload.given_name;
  if (opts.subjectFromKeycloak === false) {
    // A pre-authorized issuance has no authentication behind it at all: the
    // issuer decided who this credential is about before the wallet appeared,
    // so what it must NOT be is the identity of some signed-in user.
    assert.ok(subjectName,
      "the credential should still describe somebody. Got: " +
          JSON.stringify(disclosed));
    assert.notStrictEqual(subjectName, clientId,
      "nobody authenticated in this flow, so the subject cannot be the " +
          "Keycloak user — that would mean " +
      "an identity leaked in from another section. Got: " + subjectName);
  } else {
    assert.strictEqual(subjectName, clientId,
      "the credential should describe the user who authenticated at " +
          "Keycloak (" + clientId +
      "), which is how walt.id's id_token claims mapping is wired. Got: " +
          subjectName);
  }

  // And the page's own verdicts, which are what a user reads.
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks " +
        "tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { name: td[0].textContent.trim(), result: " +
        "td[1].textContent.trim()," +
    "           detail: td[2].textContent.trim() };" +
    "});");
  assert.ok(checks.length >= 7, "step 3 should report its checks, got " +
            checks.length + ".");
  var failed = checks.filter(function (c) { return c.result === "FAILED"; });
  assert.strictEqual(failed.length, 0,
    "no check should fail for a credential a real issuer just issued: " +
    failed.map(function (c) { return c.name + " — " + c.detail; }).join("; "));
  var signature =
      checks.filter(function (c) { return c.name === "Issuer signature"; })[0];
  assert.ok(signature && signature.result === "OK",
    "step 3 must verify walt.id's issuer signature — the key is inside the " +
        "did:jwk in iss. Got: " +
    JSON.stringify(signature));
  var binding =
      checks.filter(function (c) { return c.name === "Key binding (cnf)"; })[0];
  assert.ok(binding && binding.result === "OK",
    "the credential must be bound to the holder key step 2 generated. Got: " +
        JSON.stringify(binding));
  var digests = checks.filter(function (c) {
      return c.name === "Disclosure digests"; })[0];
  assert.ok(digests && digests.result === "OK",
    "every Disclosure's digest must be found in _sd. Got: " +
        JSON.stringify(digests));

  log.info("[waltid] OK — " + what +
           ": walt.id's SD-JWT VC verifies, is bound to the holder key, " +
           "carries vct " + payload.vct + " and describes " + subjectName +
               ".");
  log.debug("Leaving checkCredential().");
}

// ---------------------------------------------------------------------------
// H.6 — wallet-initiated: the wallet is given walt.id's metadata URL and takes
// it from there.
// ---------------------------------------------------------------------------
async function walletInitiated(driver) {
  log.debug("Entering walletInitiated().");
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-0.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vc_usecase_wallet-initiated")),
                    waitTime);
  await click(driver, By.id("vc_usecase_wallet-initiated"));
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    fetchWait,
    "choosing the wallet-initiated use case should start at the wallet.");

  await configureFromWaltid(driver);
  await authorizeAtWaltid(driver);
  await approveAndCollect(driver);
  await checkCredential(driver, "wallet-initiated (H.6)");
  log.debug("Leaving walletInitiated().");
}

// Sign out of the identity provider.
//
// walt.id delegates authentication to Keycloak, and Keycloak remembers. Once
// one section has signed in, the next authorization request is answered from
// that session and no login form is ever shown — so a section that asserts the
// End-User is sent to the IdP would hang waiting for a form that is not coming.
//
// driver.manage().deleteAllCookies() clears only the origin the browser is
// currently on, which is the wallet; the session cookie lives on Keycloak's
// origin. Hence the trip there first, to a document that is certain to exist
// and will not redirect.
async function signOutOfKeycloak(driver) {
  log.debug("Entering signOutOfKeycloak().");
  await driver.get(keycloakBase +
                   "/realms/debugger-testing/.well-known/openid-configuration");
  await driver.manage().deleteAllCookies();
  log.debug("Leaving signOutOfKeycloak(). The browser holds no session at " +
            keycloakBase + ".");
}

// ---------------------------------------------------------------------------
// H.1 — issuer-initiated: walt.id's OWN management API creates the Credential
// Offer, exactly as its portal would, and the wallet is handed it.
// ---------------------------------------------------------------------------
async function issuerInitiated(driver) {
  log.debug("Entering issuerInitiated().");
  // This section asserts that the End-User is sent to the IdP, so it must start
  // without the session the previous one left behind.
  await signOutOfKeycloak(driver);
  var created = await httpJson(waltidBase + "/issuer2/credential-offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      profileId: PROFILE_ID,
      authMethod: "AUTHORIZED",
      issuerStateMode: "INCLUDE",
      valueMode: "BY_VALUE"
    })
  });
  assert.strictEqual(created.status, 201,
    "walt.id should create an authorization-code Credential Offer. Got HTTP " +
        created.status +
    ": " + created.raw.slice(0, 300));

  var offerUrl = new URL(String(created.body.credentialOffer)
    .replace("openid-credential-offer://", "https://wallet.invalid/"));
  var offerParam = offerUrl.searchParams.get("credential_offer");
  assert.ok(offerParam, "the offer should be passed by value. Got: " +
            created.body.credentialOffer);
  var offer = JSON.parse(offerParam);
  assert.strictEqual(offer.credential_issuer, issuerId,
                     "the offer should name walt.id as the issuer.");
  var issuerState = ((offer.grants || {}).authorization_code ||
      {}).issuer_state;
  assert.ok(issuerState,
            "an issuer-initiated offer carries an issuer_state. Got: " +
            offerParam);

  // Hand it to the wallet the way the openid-credential-offer link does.
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html?credential_offer=" +
                   encodeURIComponent(offerParam));
  await driver.wait(until.elementLocated(By.id("pane_offer")), fetchWait,
    "the wallet should show the Credential Offer it was handed.");
  await driver.wait(async function () {
    return !!(await value(driver, "authorization_endpoint"));
  }, fetchWait, "the wallet should discover walt.id and its authorization " +
      "server from the offer alone.");

  assert.strictEqual(await value(driver, "vci_metadata_endpoint"), metadataUrl,
    "the offer names only the issuer identifier, so the wallet has to derive " +
        "the path-inserted " +
    "metadata URL from it.");
  assert.strictEqual(await value(driver, "vci_credential_configuration_id"),
                     CONFIGURATION_ID,
    "the offered credential should be the one selected.");
  assert.strictEqual(await value(driver, "authorization_endpoint"), issuerId +
                     "/authorize",
    "the wallet should have followed the offer all the way to walt.id's " +
        "authorization server.");
  log.info("[waltid] OK — walt.id's own Credential Offer configured the " +
           "wallet with nothing typed in.");

  await driver.executeScript(
    "document.getElementById('scope').value = arguments[0];" +
    "document.getElementById('client_id').value = arguments[1];",
    CONFIGURATION_ID, clientId);
  var save = await driver.findElements(By.id("config_save_button"));
  if (save.length) {
    await click(driver, By.id("config_save_button"));
  }

  await authorizeAtWaltid(driver);
  await approveAndCollect(driver);
  await checkCredential(driver, "issuer-initiated (H.1)");

  // walt.id ties the issuance to the offer through issuer_state; the session it
  // created for that offer should be the one that ended in a credential.
  var session = await httpJson(waltidBase + "/issuer2/sessions/" + issuerState);
  if (session.status === 200) {
    log.info("[waltid] the issuance session walt.id created for this offer " +
             "reports: " +
             JSON.stringify(session.body).slice(0, 200));
  }
  log.debug("Leaving issuerInitiated().");
}

// ---------------------------------------------------------------------------
// H.2 — cross-device, against walt.id.
//
// walt.id's management API mints a pre-authorized offer with a Transaction Code
// exactly as its portal would (authMethod PRE_AUTHORIZED, txCode, txCodeValue),
// and the wallet is handed what a QR code would have carried. No authorization
// request happens anywhere in this flow, which also means Keycloak is not
// involved: the End-User was identified by the issuer beforehand.
// ---------------------------------------------------------------------------
async function crossDeviceOffer(driver) {
  log.debug("Entering crossDeviceOffer().");
  var TX = "13579";
  var created = await httpJson(waltidBase + "/issuer2/credential-offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      profileId: PROFILE_ID,
      authMethod: "PRE_AUTHORIZED",
      valueMode: "BY_VALUE",
      txCode: { input_mode: "numeric", length: TX.length,
                description: "Type the code shown on the issuer screen" },
      txCodeValue: TX
    })
  });
  assert.strictEqual(created.status, 201,
    "walt.id should create a pre-authorized Credential Offer. Got HTTP " +
        created.status +
    ": " + created.raw.slice(0, 300));
  assert.strictEqual(created.body.txCodeValue, TX,
    "the issuer keeps the Transaction Code it will demand; that is the value " +
        "its screen would show.");

  var offerUri = String(created.body.credentialOffer);
  var offerParam = new URL(offerUri.replace("openid-credential-offer://",
      "https://wallet.invalid/"))
    .searchParams.get("credential_offer");
  assert.ok(offerParam, "the offer should be passed by value here. Got: " +
            offerUri.slice(0, 120));
  var offer = JSON.parse(offerParam);
  var grant = offer.grants[PRE_AUTHORIZED_GRANT];
  assert.ok(grant, "an H.2 offer uses the pre-authorized code grant. Got: " +
            Object.keys(offer.grants));
  assert.ok(grant["pre-authorized_code"],
            "it should carry the pre-authorized code itself.");
  assert.ok(grant.tx_code && grant.tx_code.length === TX.length,
    "it should say a Transaction Code of that length is required — its " +
        "shape, not its value. Got: " +
    JSON.stringify(grant.tx_code));
  assert.strictEqual(offerUri.indexOf(TX), -1,
    "the Transaction Code must not travel in the offer: it reaches the " +
        "End-User by another channel, " +
    "which is what makes a QR code anyone can photograph safe to display.");
  log.info("[waltid] OK — walt.id minted a pre-authorized offer whose " +
           "tx_code requirement is stated but " +
           "whose value is not in it.");

  // ---- the wallet takes what the QR code carried --------------------------
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
        offerUri);
  await click(driver, By.id("scan_offer_button"));
  // Wait for the value the OFFER should produce, not merely for a non-empty
  // field: the wallet was deliberately pointed somewhere else, so "not empty"
  // is already true and would wave the test through before anything happened.
  await driver.wait(async function () {
    return (await value(driver, "vci_credential_endpoint")) === issuerId +
            "/credential";
  }, fetchWait, "taking walt.id's offer should discover the issuer it names.");
  await waitForValue(driver, "vci_metadata_endpoint",
    function (v) { return v === metadataUrl; },
    "the offer names only the issuer identifier, so the wallet has to derive " +
        "the path-inserted metadata URL");
  assert.strictEqual(await value(driver, "vci_credential_endpoint"), issuerId +
                     "/credential",
    "and read walt.id's metadata from there.");
  var grantShown = await text(driver, "offer_grant");
  assert.ok(grantShown.indexOf("pre-authorized_code") !== -1 &&
            /Transaction Code is required/.test(grantShown),
    "the pane should show the grant and that a Transaction Code is " +
        "required. Got: " + grantShown);

  // The credential to ask for, and the client walt.id will see.
  await driver.executeScript(
    "document.getElementById('scope').value = arguments[0];" +
    "document.getElementById('client_id').value = arguments[1];",
    CONFIGURATION_ID, clientId);
  var save = await driver.findElements(By.id("config_save_button"));
  if (save.length) {
    await click(driver, By.id("config_save_button"));
  }

  // ---- no authorization request, and no Keycloak --------------------------
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "a pre-authorized offer must not go through an authorization " +
        "server at all.");
  await driver.wait(async function () {
    return !!(await text(driver, "vc_pre_authorized_code"));
  }, fetchWait,
      "step 2 should show the pre-authorized code it is about to redeem.");
  var currentUrl = await driver.getCurrentUrl();
  assert.strictEqual(currentUrl.indexOf(keycloakBase), -1,
    "nobody should have been sent to an identity provider. Got: " + currentUrl);

  // walt.id refuses a wrong Transaction Code, as it must.
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = '00000'; " +
        "vcissuance2.onTxCodeChange();");
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return /refused/i.test((await text(driver, "vc_token_status")) || "");
  }, fetchWait, "walt.id should refuse a wrong Transaction Code.");
  assert.strictEqual(await value(driver, "vc_access_token"), "",
    "a wrong Transaction Code must not produce an access token.");
  log.info("[waltid] OK — walt.id refused a wrong Transaction Code: " +
           (await text(driver, "vc_token_status")));

  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; " +
        "vcissuance2.onTxCodeChange();", TX);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the right Transaction Code should redeem walt.id's " +
      "pre-authorized code.");
  var claims = jsonFromB64u((await value(driver,
      "vc_access_token")).split(".")[1]);
  assert.strictEqual(claims.iss, issuerId,
    "the access token should have been issued by walt.id. Got iss: " +
        claims.iss);
  log.info("[waltid] OK — the pre-authorized code was redeemed at walt.id " +
           "with the Transaction Code.");

  await approveAndCollect(driver);
  await checkCredential(driver, "cross-device (H.2)",
                        { subjectFromKeycloak: false });
  log.debug("Leaving crossDeviceOffer().");
}

// ---------------------------------------------------------------------------
// H.3 — deferred issuance, against walt.id.
//
// walt.id's issuer-api2 has no Deferred Credential Endpoint: it does not
// advertise deferred_credential_endpoint and issues everything immediately.
// That is a legitimate implementation choice — OID4VCI section 9 makes the
// endpoint OPTIONAL — so what is worth checking is that our wallet reads the
// capability off the metadata rather than assuming it, and does not offer a
// deferred flow that this issuer cannot perform.
//
// The mock issuer covers the deferred mechanics themselves
// (tests/sd_jwt_vc_issuance.js), which is exactly the division of labour the
// two stacks are for: the mock exercises what real deployments do not do.
// ---------------------------------------------------------------------------
async function deferredNotSupportedHere(driver) {
  log.debug("Entering deferredNotSupportedHere().");
  var meta = (await httpJson(metadataUrl)).body;
  assert.ok(!meta.deferred_credential_endpoint,
    "walt.id does not implement deferred issuance; if that has changed, this " +
        "section should start " +
    "exercising it instead of asserting its absence. Got: " +
        meta.deferred_credential_endpoint);

  // The wallet must show that as "not defined" rather than inventing an
  // endpoint — a wallet that guesses <issuer>/deferred_credential would send a
  // Deferred Credential Request into a 404 the moment an issuer took its time.
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
        metadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "step 1 should retrieve walt.id's credential issuer metadata");

  var deferredField = await value(driver, "vci_deferred_credential_endpoint");
  assert.strictEqual(deferredField, "",
    "the wallet should leave the deferred endpoint empty for an issuer that " +
        "publishes none. Got: " +
    deferredField);
  // Empty is not enough on its own: empty and "this issuer does not offer it"
  // are different facts, and a wallet that cannot tell them apart is what this
  // pane exists to prevent. The field carries the same "-->not defined<--" note
  // the OpenID Provider half uses — as a placeholder, so an overriding value
  // still shows through.
  var marks = await driver.executeScript(
    "var out = {};" +
    "['vci_deferred_credential_endpoint'," +
        "'vci_credential_endpoint'].forEach(function (id) {" +
    "  var e = document.getElementById(id);" +
    "  out[id] = e ? { value: e.value, note: e.placeholder || '' } : null;" +
    "}); return out;");
  assert.strictEqual(marks.vci_deferred_credential_endpoint.note,
                     "-->not defined<--",
    "the deferred endpoint should be marked as not defined by this " +
        "issuer. Got: " +
    JSON.stringify(marks.vci_deferred_credential_endpoint));
  assert.strictEqual(marks.vci_credential_endpoint.note, "",
    "and a member the issuer DOES publish should carry no such note. Got: " +
    JSON.stringify(marks.vci_credential_endpoint));
  log.info("[waltid] OK — walt.id publishes no deferred_credential_endpoint, " +
           "and the wallet says so " +
           "rather than inventing one.");
  log.debug("Leaving deferredNotSupportedHere().");
}

// ---------------------------------------------------------------------------
// The optional parts of OID4VCI, against a real issuer that does not offer
// them.
//
// walt.id's issuer-api2 publishes no authorization_details_types_supported, no
// notification_endpoint, no batch_credential_issuance and no
// credential_response_encryption. Every one of those is OPTIONAL in the
// specification, so this is not a defect — but it is exactly the situation a
// wallet gets wrong: assuming an optional feature is there, or offering the
// End-User something the issuer cannot do.
//
// So what is checked here is capability detection. The mock issuer covers the
// mechanics of each feature (tests/sd_jwt_vc_issuance.js); this covers the
// other half, which only a second implementation can show: behaving correctly
// when the feature is absent.
//
// If walt.id gains any of these, the assertions below fail loudly rather than
// quietly testing nothing — which is the point of asserting the absence rather
// than skipping.
// ---------------------------------------------------------------------------
async function optionalFeaturesAbsentHere(driver) {
  log.debug("Entering optionalFeaturesAbsentHere().");
  var meta = (await httpJson(metadataUrl)).body;
  var asMeta = (await httpJson(waltidBase +
      "/.well-known/oauth-authorization-server/openid4vci")).body;

  var absent = {
    authorization_details_types_supported: asMeta.authorization_details_types_supported,
    notification_endpoint: meta.notification_endpoint,
    batch_credential_issuance: meta.batch_credential_issuance,
    credential_response_encryption: meta.credential_response_encryption,
    deferred_credential_endpoint: meta.deferred_credential_endpoint
  };
  Object.keys(absent).forEach(function (member) {
    assert.ok(!absent[member],
      "this section is about what walt.id does NOT offer, and it now offers " +
          member + " (" +
      JSON.stringify(absent[member]) +
          "). Start exercising it instead of asserting its absence.");
  });
  log.info("[waltid] OK — walt.id offers none of: " +
           Object.keys(absent).join(", ") + ".");

  // ---- the wallet's configuration pane says so ---------------------------
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
                    waitTime);
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
        metadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "step 1 should retrieve walt.id's credential issuer metadata");

  var marks = await driver.executeScript(
    "var out = {};" +
    "['vci_notification_endpoint','vci_batch_credential_issuance'," +
    " 'vci_credential_response_encryption'," +
        "'vci_deferred_credential_endpoint'," +
    " 'vci_credential_endpoint'].forEach(function (id) {" +
    "  var e = document.getElementById(id);" +
    "  out[id] = e ? { value: e.value, note: e.placeholder || '' } : null;" +
    "}); return out;");
  ["vci_notification_endpoint", "vci_batch_credential_issuance",
   "vci_credential_response_encryption",
       "vci_deferred_credential_endpoint"].forEach(function (id) {
    assert.ok(marks[id], "the pane should carry " + id + ".");
    assert.strictEqual(marks[id].value, "",
      id + " should be empty for an issuer that does not publish it. Got: " +
          marks[id].value);
    assert.strictEqual(marks[id].note, "-->not defined<--",
      id + " should be marked as not defined rather than left ambiguously " +
          "blank. Got: " +
      JSON.stringify(marks[id]));
  });
  assert.strictEqual(marks.vci_credential_endpoint.note, "",
    "while a member walt.id DOES publish carries no such note. Got: " +
    JSON.stringify(marks.vci_credential_endpoint));
  log.info("[waltid] OK — every optional member walt.id omits is marked not " +
           "defined, and the ones it " +
           "publishes are not.");

  // ---- step 1 does not promise authorization_details ---------------------
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "step 1 should retrieve walt.id's authorization server metadata");
  await driver.executeScript(
    "document.getElementById('handoff_request_mechanism').value = " +
        "'authorization_details';" +
    "vcissuance1.onRequestMechanismChange();");
  var note = await waitForStatus(driver, "handoff_mechanism_note",
    function (s) { return s.trim() !== ""; },
    "step 1 said nothing about the request mechanism it was switched to");
  assert.ok(/does not advertise authorization_details_types_supported|may refuse/.test(note),
    "choosing authorization_details against a server that does not advertise " +
        "support for it should say " +
    "so, rather than implying it will work. Got: " + note);
  log.info("[waltid] OK — the workflow warns that this server does not " +
           "advertise authorization_details.");

  // Back to the scope path, which is what this issuer supports, and then all
  // the way to a credential — so the section proves the wallet still WORKS
  // here, not just that it complains.
  await driver.executeScript(
    "document.getElementById('handoff_request_mechanism').value = 'scope';" +
    "vcissuance1.onRequestMechanismChange();" +
    "document.getElementById('scope').value = arguments[0];" +
    "document.getElementById('client_id').value = arguments[1];",
    CONFIGURATION_ID, clientId);
  var save = await driver.findElements(By.id("config_save_button"));
  if (save.length) {
    await click(driver, By.id("config_save_button"));
  }

  await signOutOfKeycloak(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("start_issuance_button")),
                    waitTime);
  await authorizeAtWaltid(driver);

  // Step 2 must offer neither batching nor encryption against this issuer.
  var options = await driver.executeScript(
    "return { batchDisabled: " +
        "document.getElementById('vc_batch_size').disabled," +
    "         batchMax: document.getElementById('vc_batch_size').max," +
    "         batchNote: " +
        "document.getElementById('vc_batch_note').textContent.trim()," +
    "         encDisabled: " +
        "document.getElementById('vc_encrypt_response').disabled," +
    "         encChecked: " +
        "document.getElementById('vc_encrypt_response').checked," +
    "         encNote: " +
        "document.getElementById('vc_encrypt_note').textContent.trim()," +
    "         identifierMode: " +
        "document.getElementById('vc_identifier_mode').textContent.trim() };");
  assert.strictEqual(options.batchDisabled, true,
    "with no batch_credential_issuance advertised, asking for several keys " +
        "should not be offered. Got: " +
    JSON.stringify(options));
  assert.ok(/does not advertise batch_credential_issuance/.test(
            options.batchNote),
    "and the pane should say why. Got: " + options.batchNote);
  assert.strictEqual(options.encDisabled, true,
    "with no credential_response_encryption advertised, encryption should " +
        "not be offered.");
  assert.strictEqual(options.encChecked, false, "and certainly not requested.");
  assert.ok(/does not advertise credential_response_encryption/.test(
            options.encNote),
    "with the reason. Got: " + options.encNote);
  assert.ok(/credential_configuration_id/.test(options.identifierMode),
    "and the credential should be named by its configuration id, since no " +
        "identifiers were granted. Got: " +
    options.identifierMode);
  log.info("[waltid] OK — step 2 offers neither batching nor encryption " +
           "here, and names the credential by " +
           "configuration id.");

  var body = JSON.parse(await text(driver, "vc_request_body"));
  assert.strictEqual(body.proofs.jwt.length, 1,
                     "so the request carries exactly one proof.");
  assert.ok(!body.credential_response_encryption,
    "and no encryption parameters. Got: " +
        JSON.stringify(body.credential_response_encryption));
  assert.ok(!("credential_identifier" in body),
    "and no credential_identifier, which was never granted. Got: " +
        JSON.stringify(body));

  await approveAndCollect(driver);
  await checkCredential(driver, "with every optional feature absent");

  // ---- step 3 offers no notification it cannot send ---------------------
  var notification = await driver.executeScript(
    "return { id: " +
        "document.getElementById('vc_notification_id').textContent.trim()," +
    "         endpoint: document.getElementById('vc_notification_endpoint').textContent.trim()," +
    "         request: " +
        "document.getElementById('vc_notification_request').value," +
    "         disabled: " +
        "document.getElementById('vc_notification_button').disabled," +
    "         status: document.getElementById('vc_notification_status').textContent.trim()," +
    "         pickerShown: " +
        "document.getElementById('vc_batch_row').style.display !== 'none' };");
  assert.strictEqual(notification.disabled, true,
    "there is nowhere to notify, so the button should be disabled rather " +
        "than failing when pressed.");
  assert.strictEqual(notification.request, "",
    "and no call should be assembled. Got: " + notification.request.slice(0,
        120));
  assert.ok(/publishes no notification_endpoint|no notification_id/.test(
            notification.status),
    "step 3 should say why it cannot notify. Got: " + notification.status);
  assert.strictEqual(notification.pickerShown, false,
    "and with one credential there is nothing to pick between.");
  log.info("[waltid] OK — step 3 does not offer a notification this issuer " +
           "never asked for.");
  log.debug("Leaving optionalFeaturesAbsentHere().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. waltid=" + issuerId + ", keycloak=" +
           keycloakBase);
  await whatWaltidPublishes();

  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options().setLoggingPrefs(prefs)
    .addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox",
                         "--disable-dev-shm-usage");
  }
  // Two environment hazards this workflow is exposed to, both silent: it is all
  // Web Crypto (holder key pairs, proofs of possession, Key Binding JWTs,
  // signature verification), which needs a secure context; and its pages must
  // fetch this suite's services on loopback, which a deployed https page may
  // not do without the private-network flags. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await walletInitiated(driver);

    var errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the workflow logged browser errors while talking to walt.id:\n" +
          errors.join("\n"));
    log.info("[waltid] OK — no console errors driving a real issuer.");

    await issuerInitiated(driver);
    await crossDeviceOffer(driver);
    await deferredNotSupportedHere(driver);
    await optionalFeaturesAbsentHere(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option('-u, --url <url>',
                  'base url of the debugger under test'));
program.addOption(new Option('-h, --headless <headless>',
                  'run headless (true/false)'));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
