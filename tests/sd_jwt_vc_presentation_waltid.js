// File: sd_jwt_vc_presentation_waltid.js
//
// The SD-JWT VC PRESENTATION workflow driven against walt.id's verifier-api2 —
// an independently written OpenID4VP 1.0 verifier with DCQL — instead of the mock
// Verifier the STS service hosts.
//
// A mock that agrees with us proves only that we agree with ourselves. The
// issuance side already has this check (tests/sd_jwt_vc_waltid.js against
// issuer-api2); this is its counterpart for presentation. Same pages, same
// buttons, someone else's implementation on the other end:
//
//   1. a credential is ISSUED by walt.id through our own issuance workflow, so
//      the thing being presented was not minted by us either. That is the whole
//      point — our wallet has to present a credential whose salts, disclosure
//      layout, signing algorithm (ES256, not RS256) and `iss` (a did:jwk, not a
//      URL) are all walt.id's choices;
//   2. walt.id's management API creates a verification session with a DCQL query,
//      exactly as its portal would;
//   3. our four presentation pages read that request, choose disclosures, sign
//      the Key Binding JWT and POST the vp_token to walt.id;
//   4. walt.id's own session record is read back and asserted on — its status,
//      its policy results, and the claims it ended up with.
//
// POSITIVE: the flow above.
// NEGATIVE: the same flow with a claim the verifier asked for withheld — walt.id
// must not report success, and its own DCQL/policy machinery is what refuses it.
//
// Needs the waltid-verifier container (WALTID_VERIFIER_URL), the waltid-issuer
// container (WALTID_ISSUER_URL) and Keycloak — walt.id's issuer authenticates the
// End-User there. Skipped when WALTID_VERIFIER_URL is unset, like the issuer's
// interoperability job.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const browserFlags = require("./browser_flags.js");
const crypto = require("crypto");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'sd_jwt_vc_presentation_waltid',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 30000);
// The budget every waitFor* in ./wait_for.js uses. Set once: one test file
// runs per process.
require("./wait_for").configure({ timeout: fetchWait });

// walt.id's two services, each behind its own CORS proxy. These are the addresses
// the BROWSER uses, which is also what walt.id publishes in everything it builds.
var verifierBase = (process.env.WALTID_VERIFIER_URL || "http://localhost:7003").replace(/\/+$/, "");
var issuerBase = (process.env.WALTID_ISSUER_URL || "http://localhost:7005").replace(/\/+$/, "");
// walt.id's Credential Issuer Identifier has a path; its metadata therefore lives
// at the RFC 8414 path-inserted location, which is what our wallet has to derive.
var issuerId = issuerBase + "/openid4vci";
var metadataUrl = issuerBase + "/.well-known/openid-credential-issuer/openid4vci";
var keycloakBase = process.env.KEYCLOAK_BASE_URL || "http://localhost:8080";
var realmBase = keycloakBase + "/realms/debugger-testing";

// The credential configuration and issuance profile waltid/config defines.
var CONFIGURATION_ID = process.env.WALTID_CONFIGURATION_ID || "identity_credential";
var PROFILE_ID = process.env.WALTID_PROFILE_ID || "identityCredentialSdJwt";
// The OIDC client our wallet authorizes with, and the Keycloak user it signs in
// as; the suite provisions both.
var clientId = process.env.SD_JWT_VC_CLIENT_ID || "oidc-authorization-code-public";

// What walt.id will be asked to verify. Two claims, both selectively disclosable
// in waltid/config's profile, so the selective part is observable.
var REQUESTED = ["given_name", "birthdate"];
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
  options = options || {};
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
}

// text()/value() and the waitFor* family live in ./wait_for.js — one
// implementation, shared by these suites. It waits on CONTENT rather than on the
// element: every field here is static markup, so locating it proves nothing about
// whether the page has filled it in, and the fixed sleeps that used to stand in
// for that lost the race periodically. It also reports what the field LAST held
// on a timeout, which the local copy of waitForStatus could not — its message was
// built before the first poll, so it always said "(last status: )".
const { text, value, waitForStatus, waitForValue, waitForFilled } = require("./wait_for");
function severeErrors(driver) {
  return driver.manage().logs().get(logging.Type.BROWSER).then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// ---------------------------------------------------------------------------
// Phase 1 — a credential ISSUED BY walt.id, through our issuance workflow.
//
// Deliberately not minted here and not taken from the other suite's leftovers:
// the credential this test presents has to be one walt.id built, and getting it
// the way a user would is also the cheapest way to be sure of that.
// ---------------------------------------------------------------------------
async function signOutOfKeycloak(driver) {
  log.debug("Entering signOutOfKeycloak().");
  await driver.get(realmBase + "/protocol/openid-connect/logout");
  await driver.sleep(600);
  var confirm = await driver.findElements(By.id("kc-logout"));
  if (confirm.length) {
    await click(driver, By.id("kc-logout"));
    await driver.sleep(600);
  }
  log.debug("Leaving signOutOfKeycloak().");
}

async function issueFromWaltid(driver) {
  log.info("=== Phase 1: walt.id issues the credential (through our own pages) ===");
  await signOutOfKeycloak(driver);
  await driver.get(baseUrl + "/vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
  await driver.sleep(500);

  // walt.id's metadata, at the path-inserted well-known location.
  //
  // Every wait below insists on "Retrieved". Accepting "Could not" as well —
  // which this function used to do — makes the whole configuration step vacuous:
  // the retrieval failed, the endpoint fields stayed empty, and the first thing
  // that actually noticed was a 30-second timeout waiting for a Keycloak login
  // screen that nothing had navigated to.
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];", metadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "walt.id's credential issuer metadata was not retrieved");
  assert.strictEqual(await value(driver, "vci_credential_issuer"), issuerId,
    "the metadata should name walt.id's Credential Issuer Identifier (with its path).");

  // Choose the credential the way a user does, through the configurations the
  // metadata advertised: that populates the scope and the format alongside the
  // identifier, which setting the identifier alone does not.
  await driver.executeScript(
    "var s = document.getElementById('vci_credential_configuration_select');" +
    "s.value = arguments[0];" +
    "vcissuance1.onCredentialConfigurationChange();", CONFIGURATION_ID);
  await waitForValue(driver, "vci_credential_configuration_id",
    function (v) { return v === CONFIGURATION_ID; },
    "choosing the credential configuration should select it");

  // walt.id publishes no authorization_servers, so it is its own — and its
  // identifier HAS a path, so the metadata is at the RFC 8414 path-INSERTED URL.
  // The page derives that itself; do not overwrite it here. Appending instead
  // (…/openid4vci/.well-known/oauth-authorization-server) is a 404, which is the
  // very bug the issuance suite exists to keep fixed.
  var asUrl = await value(driver, "oidc_discovery_endpoint");
  assert.strictEqual(asUrl, issuerBase + "/.well-known/oauth-authorization-server/openid4vci",
    "the wallet should fall back to the credential issuer at the path-inserted well-known URL. Got: " +
    asUrl);
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); },
    "walt.id's authorization server metadata was not retrieved");

  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];" +
    "document.getElementById('scope').value = arguments[1];",
    clientId, CONFIGURATION_ID);
  var save = await driver.findElements(By.id("config_save_button"));
  if (save.length) {
    await click(driver, By.id("config_save_button"));
    await driver.sleep(400);
  }

  // The hand-off cannot work without these, and an empty authorization endpoint
  // is why the old version of this function timed out at the login screen rather
  // than reporting what was actually wrong.
  assert.strictEqual(await value(driver, "authorization_endpoint"), issuerId + "/authorize",
    "the authorization endpoint should have come from walt.id's RFC 8414 document.");
  assert.strictEqual(await value(driver, "token_endpoint"), issuerId + "/token",
    "the token endpoint should have come from walt.id's RFC 8414 document.");

  // Hand off to the OIDC leg. walt.id's authorization endpoint redirects to
  // Keycloak, which is where the End-User actually signs in.
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "walt.id should have sent the browser to Keycloak to authenticate the End-User.");
  await driver.findElement(By.id("username")).sendKeys(clientId);
  await driver.findElement(By.id("password")).sendKeys(clientId);
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("vc-issuance-2.html"), fetchWait,
    "the code should have been exchanged and the workflow returned to step 2.");

  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should have built the Credential Request.");
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("vc-issuance-3.html"), fetchWait,
    "approving should have obtained a credential from walt.id.");
  var credential = await waitForFilled(driver, "vc_credential_raw",
    "step 3 should be showing the credential walt.id issued");
  var payload = jsonFromB64u(credential.split("~")[0].split(".")[1]);
  var header = jsonFromB64u(credential.split("~")[0].split(".")[0]);
  // The things that make this walt.id's credential and not ours.
  assert.ok(/^did:jwk:/.test(String(payload.iss)),
    "walt.id signs with a did:jwk, so iss should be one. Got: " + payload.iss);
  assert.strictEqual(header.alg, "ES256",
    "walt.id signs SD-JWT VCs with ES256 (our mock uses RS256). Got: " + header.alg);
  assert.ok(payload.cnf && payload.cnf.jwk,
    "and it should be bound to the holder key our wallet generated.");
  var disclosures = credential.split("~").slice(1).filter(Boolean).map(function (d) {
    return JSON.parse(b64uDecode(d).toString("utf8"))[1];
  });
  REQUESTED.forEach(function (name) {
    assert.ok(disclosures.indexOf(name) !== -1,
      "the credential must carry " + name + " as a Disclosure for this test to mean anything. Got: " +
      disclosures.join(", "));
  });
  log.info("[phase1] OK — walt.id issued a " + payload.vct + " (alg " + header.alg + ", iss " +
           String(payload.iss).slice(0, 24) + "…) with Disclosures: " + disclosures.join(", "));
  return { credential: credential, payload: payload, disclosures: disclosures };
}

// ---------------------------------------------------------------------------
// Phase 2 — walt.id's verification session.
//
// Created through its management API, exactly as its portal would: a DCQL query
// naming the claims wanted, and the flow type that produces a URL for a wallet.
// The response carries both shapes of Authorization Request — the short
// "bootstrap" one (client_id + request_uri) and the full one (by value) — which is
// what lets this suite exercise our step 1 both ways.
// ---------------------------------------------------------------------------
// The `meta` member is REQUIRED in a DCQL credential query (OID4VP section 6.1),
// and for SD-JWT VC it is the vct the verifier will accept. It is read off the
// credential walt.id just issued rather than guessed: walt.id derives the vct from
// its own baseUrl, so hardcoding it here would be a second place to get wrong.
function dcqlQuery(vct, claims) {
  return {
    credentials: [{
      id: DCQL_ID,
      format: "dc+sd-jwt",
      meta: { vct_values: [vct] },
      claims: (claims || REQUESTED).map(function (name) { return { path: [name] }; })
    }]
  };
}

async function createVerificationSession(opts) {
  log.debug("Entering createVerificationSession().");
  assert.ok((opts || {}).vct,
    "a verification session needs the vct to ask for; pass the one walt.id issued.");
  var setup = {
    flow_type: "cross_device",
    core_flow: {
      dcql_query: dcqlQuery((opts || {}).vct, (opts || {}).claims),
      signed_request: false,
      encrypted_response: false,
      // walt.id's own policies, run on what it receives. `signature` is the one
      // that matters here: it is walt.id checking the credential and the Key
      // Binding JWT our wallet produced.
      policies: { vc_policies: ["signature", "expiration", "not-before"] }
    },
    url_config: {}
  };
  var created = await httpJson(verifierBase + "/verification-session/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(setup)
  });
  assert.ok(created.status === 200 || created.status === 201,
    "walt.id should create a verification session. Got HTTP " + created.status + ": " +
    created.raw.slice(0, 400));
  assert.ok(created.body && created.body.sessionId,
    "the response should carry a sessionId. Got: " + created.raw.slice(0, 300));
  assert.ok(created.body.fullAuthorizationRequestUrl || created.body.bootstrapAuthorizationRequestUrl,
    "and an Authorization Request URL for the wallet. Got: " + created.raw.slice(0, 300));
  log.debug("Leaving createVerificationSession(). sessionId=" + created.body.sessionId);
  return created.body;
}

function sessionInfo(sessionId) {
  return httpJson(verifierBase + "/verification-session/" + encodeURIComponent(sessionId) + "/info");
}

// The query string of whichever request URL walt.id produced, which is what our
// step 1 reads — the same bytes a QR code would have carried.
function requestQuery(session, byReference) {
  var url = byReference
    ? (session.bootstrapAuthorizationRequestUrl || session.fullAuthorizationRequestUrl)
    : (session.fullAuthorizationRequestUrl || session.bootstrapAuthorizationRequestUrl);
  var s = String(url);
  var q = s.indexOf("?");
  assert.ok(q > 0, "walt.id's Authorization Request URL should carry a query string. Got: " + s);
  return s.slice(q + 1);
}

// ---------------------------------------------------------------------------
// Phase 3 — present it, through our pages.
// ---------------------------------------------------------------------------
async function presentToWaltid(driver, session, opts) {
  var byReference = !!(opts || {}).byReference;
  var withhold = (opts || {}).withhold || "";
  log.info("=== Phase 3: presenting to walt.id (" +
           (byReference ? "request by reference" : "request by value") +
           (withhold ? ", withholding " + withhold : "") + ") ===");

  await driver.get(baseUrl + "/vc-presentation-1.html?" + requestQuery(session, byReference));
  await driver.wait(until.elementLocated(By.id("vp_request_status")), waitTime);
  var requestStatus = await waitForStatus(driver, "vp_request_status",
    function (s) { return /Request read|cannot be answered|Could not/.test(s); },
    "step 1 never reported on walt.id's request");
  var request = await driver.executeScript(
    "return { clientId: document.getElementById('vp_client_id').textContent.trim()," +
    "         prefix: document.getElementById('vp_client_prefix').textContent.trim()," +
    "         responseType: document.getElementById('vp_response_type').textContent.trim()," +
    "         responseMode: document.getElementById('vp_response_mode').textContent.trim()," +
    "         responseUri: document.getElementById('vp_response_uri').textContent.trim()," +
    "         nonce: document.getElementById('vp_nonce').textContent.trim()," +
    "         dcql: document.getElementById('vp_dcql').textContent.trim()," +
    "         signature: document.getElementById('vp_signature_verdict').textContent.trim()," +
    "         source: document.getElementById('vp_source').textContent.trim() };");
  assert.ok(/Request read/.test(requestStatus),
    "our wallet should be able to answer walt.id's request. Got: " + requestStatus +
    " (client_id " + request.clientId + ", response_mode " + request.responseMode + ")");
  assert.strictEqual(request.responseType, "vp_token",
    "walt.id should ask for a vp_token. Got: " + request.responseType);
  assert.strictEqual(request.responseMode, "direct_post",
    "and for response_mode=direct_post. Got: " + request.responseMode);
  assert.ok(request.responseUri.indexOf(verifierBase) === 0,
    "the response goes back to walt.id. Got: " + request.responseUri);
  assert.ok(request.nonce && request.nonce !== "—", "with a nonce to bind the presentation to.");
  var dcql = JSON.parse(request.dcql);
  assert.strictEqual(dcql.credentials[0].format, "dc+sd-jwt",
    "walt.id's DCQL query should name the SD-JWT VC format.");
  assert.ok(((dcql.credentials[0].meta || {}).vct_values || []).length,
    "and the vct it will accept, which our step 1 checks against the credential in hand.");
  var askedFor = dcql.credentials[0].claims.map(function (c) {
    return Object.prototype.toString.call(c.path) === "[object Array]" ? c.path.join(".") : String(c.path);
  });
  log.info("[phase3] walt.id asks (" + request.source + "): client_id " + request.clientId +
           ", claims " + askedFor.join(", ") + "; signature: " + request.signature);

  await click(driver, By.id("vp_continue_button"));
  await driver.wait(until.elementLocated(By.id("vp_disclosures_table")), waitTime);
  await waitForStatus(driver, "vp_present_status", function (s) { return /Ready|Could not/.test(s); },
    "step 2 never built a presentation for walt.id's request");

  // The default selection is what walt.id asked for. For the negative, take one
  // of those away.
  var selected = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vp_disclosures_table tbody tr'))" +
    "  .filter(function (tr) { return tr.querySelectorAll('td')[0].querySelector('input').checked; })" +
    "  .map(function (tr) { return tr.querySelectorAll('td')[1].textContent.trim(); });");
  assert.deepStrictEqual(selected.slice().sort(), askedFor.slice().sort(),
    "the wallet should default to exactly the claims walt.id asked for. Got: " + selected.join(", "));
  if (withhold) {
    await driver.executeScript(
      "var rows = Array.prototype.slice.call(document.querySelectorAll('#vp_disclosures_table tbody tr'));" +
      "for (var i = 0; i < rows.length; i++) {" +
      "  var td = rows[i].querySelectorAll('td');" +
      "  if (td[1].textContent.trim() === arguments[0]) { td[0].querySelector('input').click(); return; }" +
      "}", withhold);
    await driver.sleep(900);
  }

  var built = await driver.executeScript(
    "return { presentation: document.getElementById('vp_presentation').value," +
    "         kbPayload: document.getElementById('vp_kb_payload').textContent.trim()," +
    "         sdHash: document.getElementById('vp_sd_hash').textContent.trim() };");
  var kbPayload = JSON.parse(built.kbPayload);
  assert.strictEqual(kbPayload.aud, request.clientId,
    "the Key Binding JWT must be addressed to walt.id's Client Identifier.");
  assert.strictEqual(kbPayload.nonce, request.nonce, "and carry the nonce from its request.");
  // Recomputed here, over the bytes being sent.
  var parts = built.presentation.split("~");
  var prefix = parts.slice(0, parts.length - 1).join("~") + "~";
  assert.strictEqual(kbPayload.sd_hash,
    b64u(crypto.createHash("sha256").update(prefix, "ascii").digest()),
    "sd_hash must be the hash of the issuer-signed JWT and the presented Disclosures, each followed " +
    "by a tilde.");
  log.info("[phase3] built an SD-JWT+KB with " + (parts.length - 2) + " Disclosure(s) for walt.id.");

  await click(driver, By.id("vp_present_button"));
  await driver.wait(until.urlContains("vc-presentation-3.html"), fetchWait,
    "presenting should open step 3, whatever walt.id decided.");
  await driver.sleep(800);
  var sent = await driver.executeScript(
    "return { status: document.getElementById('vp_sent_status').textContent.trim()," +
    "         recheck: document.getElementById('vp_recheck_status').textContent.trim()," +
    "         presentation: document.getElementById('vp_sent_presentation').value };");
  assert.ok(/all pass/.test(sent.recheck),
    "the wallet's own checks on what it sent should pass. Got: " + sent.recheck);
  log.info("[phase3] " + sent.status.replace(/\s+/g, " ").slice(0, 140));
  return { presentation: sent.presentation, request: request, askedFor: askedFor };
}

// walt.id's own account of what happened, read from its session record.
async function waltidVerdict(sessionId, label) {
  log.debug("Entering waltidVerdict(). sessionId=" + sessionId);
  var info = null;
  var deadline = Date.now() + 20000;
  // walt.id validates asynchronously: the session moves through its states after
  // the POST is answered, so the record is polled rather than read once.
  while (Date.now() < deadline) {
    info = await sessionInfo(sessionId);
    assert.ok(info.ok, "walt.id should report its session. Got HTTP " + info.status);
    var status = String(info.body.status || "");
    if (/SUCCESS|FAIL|ERROR|COMPLETE|REJECT/i.test(status)) break;
    if (info.body.presented_credentials || info.body.policy_results || info.body.failure) break;
    await new Promise(function (r) { setTimeout(r, 1000); });
  }
  log.info("[waltid] " + label + " — session " + sessionId + " status=" +
           JSON.stringify(info.body.status) +
           (info.body.failure ? ", failure=" + JSON.stringify(info.body.failure).slice(0, 200) : ""));
  log.debug("Leaving waltidVerdict().");
  return info.body;
}

// ---------------------------------------------------------------------------
// POSITIVE
// ---------------------------------------------------------------------------
async function positiveFlow(driver, held, byReference) {
  var session = await createVerificationSession({ vct: held.payload.vct });
  var presented = await presentToWaltid(driver, session, { byReference: byReference });
  var verdict = await waltidVerdict(session.sessionId,
    "positive (" + (byReference ? "by reference" : "by value") + ")");

  var status = String(verdict.status || "");
  assert.ok(!/FAIL|ERROR|REJECT/i.test(status),
    "walt.id should not have failed this presentation. status=" + status +
    ", failure=" + JSON.stringify(verdict.failure || null).slice(0, 300));
  assert.ok(!verdict.failure,
    "and should record no failure. Got: " + JSON.stringify(verdict.failure || null).slice(0, 300));

  // What walt.id ended up with. Its record carries the raw presentation and the
  // credentials it parsed out of it; the claims are asserted against the ones it
  // asked for, which is the whole point of selective disclosure.
  var raw = JSON.stringify(verdict.presented_credentials || verdict.presented_raw_data ||
                           verdict.presented_presentations || {});
  REQUESTED.forEach(function (name) {
    assert.ok(raw.indexOf(name) !== -1,
      "walt.id should have received " + name + ". Its record: " + raw.slice(0, 400));
  });
  ["email", "phone_number"].forEach(function (name) {
    assert.ok(raw.indexOf(name) === -1,
      "and must NOT have received " + name + " — it was never disclosed. Its record: " + raw.slice(0, 400));
  });
  // Every policy walt.id ran on our presentation, and how it went.
  var policies = JSON.stringify(verdict.policy_results || {});
  assert.ok(policies.indexOf("false") === -1 || policies.indexOf("success") !== -1,
    "walt.id's policy results should not report a failure: " + policies.slice(0, 400));
  log.info("[positive] OK — walt.id accepted a presentation of a credential it issued, with " +
           REQUESTED.join(" + ") + " disclosed and nothing else. Policies: " +
           policies.slice(0, 200));
  return { session: session, verdict: verdict, presented: presented };
}

// ---------------------------------------------------------------------------
// NEGATIVE 1 — a claim walt.id asked for is withheld.
//
// The presentation is otherwise perfect: the issuer's signature, the digests and
// the Key Binding JWT are all valid, and our wallet's own checks pass. What is
// wrong is that it does not answer the question.
//
// And walt.id accepts it. That is not a bug in this test and not one in our
// wallet: verifier-api2 runs a fixed set of policies over a dc+sd-jwt
// presentation — audience, nonce, sd_hash, the KB-JWT signature, exp/nbf — and
// none of them asks whether the DCQL query was actually satisfied (there is no
// such policy in waltid-verification-policies2-vp at 0.23.0). So the claim it
// asked for is simply absent from what it recorded, and its status is SUCCESSFUL
// anyway.
//
// Which makes this the OID4VP counterpart of over-disclosure, from the other
// side: a verifier that does not check cannot complain, so the only party in a
// position to notice is the wallet. That is what is asserted here — walt.id did
// not receive the claim, and OUR step 3 says the request went unanswered.
// ---------------------------------------------------------------------------
async function negativeWithheldClaim(driver, held) {
  log.info("=== NEGATIVE 1: withholding a claim walt.id asked for ===");
  var session = await createVerificationSession({ vct: held.payload.vct });
  await presentToWaltid(driver, session, { withhold: REQUESTED[0] });
  var verdict = await waltidVerdict(session.sessionId, "negative (withheld " + REQUESTED[0] + ")");

  // Whatever it decided, the withheld claim must not have reached it: that is the
  // guarantee selective disclosure actually makes, and it is ours to keep.
  var raw = JSON.stringify(verdict.presented_credentials || verdict.presented_raw_data ||
                           verdict.presented_presentations || {});
  assert.ok(raw.indexOf(REQUESTED[0]) === -1,
    "the withheld claim (" + REQUESTED[0] + ") must not appear in what walt.id received. Its record: " +
    raw.slice(0, 400));
  assert.ok(raw.indexOf(REQUESTED[1]) !== -1,
    "while the claim that WAS disclosed (" + REQUESTED[1] + ") should. Its record: " + raw.slice(0, 400));

  // The wallet is the one that has to notice, and it is on step 3 already.
  var shortfall = await driver.executeScript(
    "return { answered: document.getElementById('vp_answered').textContent.trim()," +
    "         sent: document.getElementById('vp_sent_status').textContent.trim() };");
  assert.ok(/NOT fully answered/.test(shortfall.answered),
    "step 3 should say the request was not fully answered — no verifier is going to say it for us. Got: " +
    shortfall.answered);
  assert.ok(shortfall.answered.indexOf(REQUESTED[0]) !== -1,
    "and should name the claim that was withheld. Got: " + shortfall.answered);
  assert.ok(/withheld/.test(shortfall.sent),
    "and the pane's own summary should not read as though nothing was missing. Got: " + shortfall.sent);

  log.info("[negative 1] OK — " + REQUESTED[0] + " never reached walt.id, our step 3 reports the " +
           "shortfall, and walt.id itself said status=" + JSON.stringify(verdict.status) +
           " (it runs no DCQL-fulfilment policy — recorded here as an interop finding).");
}

// ---------------------------------------------------------------------------
// NEGATIVE 2 — a replayed presentation, which walt.id DOES refuse.
//
// Without this the suite proves nothing by walt.id's SUCCESSFUL: a verifier that
// accepted everything would pass every other assertion here. So take the exact
// bytes it just accepted and post them to a SECOND session. The Key Binding JWT
// carries the first session's nonce, which is what makes it a replay, and
// nonce-check is a policy walt.id really does run.
//
// Posted directly rather than through the pages: our wallet will not build a
// presentation carrying someone else's nonce, and that is the point of it.
// ---------------------------------------------------------------------------
async function negativeReplay(held, accepted) {
  log.info("=== NEGATIVE 2: replaying an accepted presentation into a fresh session ===");
  var session = await createVerificationSession({ vct: held.payload.vct });
  var params = new URLSearchParams(requestQuery(session, false));
  var responseUri = params.get("response_uri");
  var state = params.get("state");
  var freshNonce = params.get("nonce");
  assert.ok(responseUri, "the second session's request should carry a response_uri.");
  assert.ok(freshNonce, "and a nonce of its own, which is what the replayed bytes will not match.");

  var vpToken = {};
  vpToken[DCQL_ID] = [accepted.presentation];
  var form = "vp_token=" + encodeURIComponent(JSON.stringify(vpToken)) +
             (state ? "&state=" + encodeURIComponent(state) : "");
  var posted = await httpJson(responseUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form
  });
  log.info("[negative 2] walt.id answered the replay with HTTP " + posted.status + ": " +
           String(posted.raw).replace(/\s+/g, " ").slice(0, 200));

  var verdict = await waltidVerdict(session.sessionId, "negative (replayed presentation)");
  var status = String(verdict.status || "");
  var refused = posted.status >= 400 || /FAIL|ERROR|REJECT/i.test(status) || !!verdict.failure;
  assert.ok(refused,
    "walt.id must refuse a presentation bound to another session's nonce — if it accepts this, its " +
    "SUCCESSFUL on the positive cases means nothing. HTTP " + posted.status + ", status=" + status +
    ", failure=" + JSON.stringify(verdict.failure || null).slice(0, 300));
  assert.notStrictEqual(status.toUpperCase(), "SUCCESSFUL",
    "and must not record the replayed session as successful. failure=" +
    JSON.stringify(verdict.failure || null).slice(0, 300));
  log.info("[negative 2] OK — walt.id refused the replay (HTTP " + posted.status + ", status=" + status +
           "), so its acceptance of the honest presentations is a real verdict.");
}

// ---------------------------------------------------------------------------
async function test() {
  log.info("Starting Test run. verifier=" + verifierBase + ", issuer=" + issuerBase +
           ", wallet=" + baseUrl);

  // Fail early and clearly when the container is not there, rather than in the
  // middle of the browser flow.
  var live = await httpJson(verifierBase + "/livez").catch(function (e) {
    return { ok: false, status: 0, raw: e.message };
  });
  assert.ok(live.status && live.status < 500,
    "walt.id's verifier should be reachable at " + verifierBase + " (HTTP " + live.status + " " +
    String(live.raw).slice(0, 200) + "). Is the waltid-verifier container up?");
  log.info("[waltid] verifier is up: GET /livez -> HTTP " + live.status);

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
    var held = await issueFromWaltid(driver);
    var accepted = await positiveFlow(driver, held, false);
    await positiveFlow(driver, held, true);

    var errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the workflow logged browser errors:\n" + errors.join("\n"));
    log.info("[browser] OK — no console errors across the walt.id presentation flow.");

    // After the console check: a refused presentation legitimately earns a 4xx,
    // which Chrome logs as a page error.
    await negativeWithheldClaim(driver, held);
    await negativeReplay(held, accepted.presented);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
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
