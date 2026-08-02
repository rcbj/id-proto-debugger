// File: jwt_vc_json_presentation.js
//
// ---------------------------------------------------------------------------
// OID4VP presentation of a jwt_vc_json credential, against the mock Verifier the
// STS service hosts.
//
// The sibling of sd_jwt_vc_presentation.js, which covers the same four pages in
// dc+sd-jwt. Separate for the same reason the issuance tests are: that suite is
// built around choosing Disclosures, and this format has none.
//
// The four places a format-blind implementation still LOOKS like it works, which
// are therefore what this asserts:
//
//   * nothing to select — the page must say why, not render an empty table;
//   * holder binding is the Verifiable Presentation JWT's own signature, where an
//     SD-JWT uses a Key Binding JWT;
//   * the DCQL paths are rooted at credentialSubject, so the wallet has to map
//     them onto the claim names it holds. Miss that and every requested claim is
//     reported WITHHELD while all of them were in fact sent — alarming to the
//     holder and false;
//   * the presentation over-discloses by construction, so "nothing more than was
//     asked for" would be a lie.
//
// Plus the negatives, built here rather than through the pages, because a wallet
// that only tests itself proves nothing about the verifier: a VP JWT signed by
// the wrong key, and a replay of accepted bytes into a second session.
// ---------------------------------------------------------------------------

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const crypto = require("crypto");
const browserFlags = require("./browser_flags.js");
const common = require("./jwt_vc_json_common.js");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "jwt_vc_json_presentation",
                                level: appconfig.logLevel || "info" });

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
// The mock hosts the issuer and the verifier on one service.
var verifierBase = process.env.OID4VP_VERIFIER_URL || issuerBase;

const { text, waitForStatus, waitForValue } = require("./wait_for");

async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await driver.sleep(120);
  try {
    await e.click();
  } catch (err) {
    // Something is overlapping it; click through the DOM instead.
    await driver.executeScript("arguments[0].click();", e);
  }
  await driver.sleep(250);
}

function severeErrors(driver) {
  const logging = require("selenium-webdriver/lib/logging");
  return driver.manage().logs().get(logging.Type.BROWSER).then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// --- through the pages ------------------------------------------------------
async function presentThroughThePages(driver, held) {
  log.info("=== jwt_vc_json presented through the four pages ===");
  await common.plantIntoWallet(driver, {
    By: By, until: until, baseUrl: baseUrl, waitTime: waitTime,
    credential: held.credential, publicJwk: held.publicJwk, privateJwk: held.privateJwk,
    verifierBase: verifierBase, issuerBase: issuerBase
  });

  const request = await common.freshJwtVcJsonRequest(verifierBase, false);
  const dcql = JSON.parse(request.params.dcql_query);
  assert.strictEqual(dcql.credentials[0].format, common.FORMAT,
    "the verifier should be asking for jwt_vc_json.");
  assert.deepStrictEqual(dcql.credentials[0].claims[0].path.slice(0, 1), ["credentialSubject"],
    "and address its claims under credentialSubject, where a W3C VC keeps them. Got: " +
    JSON.stringify(dcql.credentials[0].claims[0].path));

  await driver.get(baseUrl + "/sd-jwt-vc-presentation-1.html?" + request.location.split("?")[1]);
  await waitForStatus(driver, "vp_request_status", function (s) { return /Request read/.test(s); },
    "step 1 should read a jwt_vc_json request", waitTime);
  await click(driver, By.id("vp_continue_button"));

  await driver.wait(until.elementLocated(By.id("vp_presentation")), waitTime);
  const presentation = await waitForValue(driver, "vp_presentation",
    function (v) { return v.trim().length > 80; }, "step 2 should build a presentation", waitTime);
  assert.strictEqual(presentation.indexOf("~"), -1,
    "a jwt_vc_json presentation is a VP JWT, not an SD-JWT Combined Serialization. Got: " +
    presentation.slice(0, 60));
  assert.strictEqual(presentation.split(".").length, 3, "and is a three-part JWS.");

  const vpPayload = common.jsonFromB64u(presentation.split(".")[1]);
  assert.ok(vpPayload.vp && [].concat(vpPayload.vp.verifiableCredential)[0] === held.credential,
    "the VP JWT should carry the held credential whole inside its vp claim.");
  assert.strictEqual(vpPayload.nonce, request.params.nonce,
    "the VP JWT carries the request nonce — this format has no KB-JWT to carry it.");
  assert.strictEqual(String(vpPayload.aud), String(request.params.client_id),
    "and the verifier's Client Identifier as its audience.");

  const summary = await text(driver, "vp_selection_summary");
  assert.ok(/no selective disclosure/.test(summary),
    "step 2 should say why there is nothing to choose. Said: " + summary);

  await click(driver, By.id("vp_present_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-presentation-3.html"), waitTime,
    "presenting should reach step 3.");

  const verdict = await waitForStatus(driver, "vp_verifier_status",
    function (s) { return /ACCEPTED|REFUSED/.test(s); }, "the verifier should reach a verdict", waitTime);
  assert.ok(/ACCEPTED/.test(verdict),
    "the verifier should accept a correctly built VP JWT. Said: " + verdict);

  const recheck = await waitForStatus(driver, "vp_recheck_status", function (s) { return s.trim() !== ""; },
    "the wallet should re-check what it sent", waitTime);
  assert.ok(/all pass/.test(recheck), "the wallet's own checks should pass. Said: " + recheck);

  // The claim-path mapping, which is the assertion that fails if the wallet
  // compares a DCQL path against its flat claim names without stripping
  // credentialSubject.
  const sent = await text(driver, "vp_sent_status");
  assert.ok(!/were withheld/.test(sent),
    "nothing can be withheld in jwt_vc_json, so the summary must not say anything was. Said: " + sent);
  assert.ok(/more than was asked for/.test(sent) && /jwt_vc_json/.test(sent),
    "and it should name the over-disclosure as a property of the format. Said: " + sent);
  const answered = await text(driver, "vp_answered");
  assert.ok(!/NOT fully answered/.test(answered),
    "the request WAS answered — every claim it asked for went. Said: " + answered);

  log.info("[pages] OK — VP JWT accepted, nothing reported as withheld, over-disclosure named.");
  return presentation;
}

// --- the verifier's own checks ----------------------------------------------
// Presentations a correct wallet would never build, so the only way to find out
// whether the verifier enforces its rules is to build them here.
async function verifierNegatives(held, acceptedPresentation) {
  log.info("=== The verifier's checks on a VP JWT ===");

  const signVp = function (privateKey, request, credential) {
    const header = common.b64u(JSON.stringify({ alg: "ES256", typ: "JWT" }));
    const payload = common.b64u(JSON.stringify({
      iss: "urn:holder", aud: request.params.client_id, nonce: request.params.nonce,
      iat: Math.floor(Date.now() / 1000),
      vp: { "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiablePresentation"], verifiableCredential: [credential] }
    }));
    const sig = common.b64u(crypto.sign(null, Buffer.from(header + "." + payload),
      { key: privateKey, dsaEncoding: "ieee-p1363" }));
    return header + "." + payload + "." + sig;
  };
  const submit = async function (request, presentation) {
    await common.httpJson(request.params.response_uri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        vp_token: JSON.stringify({ identity_credential: [presentation] }),
        state: request.params.state
      }).toString()
    });
    const result = await common.verdictFor(verifierBase, request.params.state);
    return result.verdict || {};
  };
  const failedCheck = function (verdict) {
    return (verdict.checks || []).filter(function (c) { return !c.ok; })
      .map(function (c) { return c.name; }).join(", ");
  };

  // Signed by a key the credential is not bound to.
  const wrong = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const r1 = await common.freshJwtVcJsonRequest(verifierBase, false);
  const v1 = await submit(r1, signVp(wrong.privateKey, r1, held.credential));
  assert.strictEqual(v1.ok, false, "a VP JWT signed by the wrong key must be refused.");
  assert.ok(/Holder binding/.test(failedCheck(v1)),
    "and refused for the holder binding specifically, not for something incidental. Failed: " +
    failedCheck(v1));
  log.info("[verifier] OK — a VP JWT signed by the wrong key is refused (" + failedCheck(v1) + ").");

  // Replay: bytes the verifier already accepted, into a second session.
  const r2 = await common.freshJwtVcJsonRequest(verifierBase, false);
  const v2 = await submit(r2, acceptedPresentation);
  assert.strictEqual(v2.ok, false,
    "replaying an accepted presentation into a new session must be refused — otherwise the nonce buys " +
    "nothing and the acceptance above means nothing either.");
  assert.ok(/Nonce/.test(failedCheck(v2)),
    "and refused on the nonce. Failed: " + failedCheck(v2));
  log.info("[verifier] OK — a replayed presentation is refused (" + failedCheck(v2) + ").");

  // A tampered credential inside an otherwise valid presentation.
  const parts = held.credential.split(".");
  const tampered = parts[0] + "." + parts[1] + "." + parts[2].slice(0, -4) + "AAAA";
  const r3 = await common.freshJwtVcJsonRequest(verifierBase, false);
  const v3 = await submit(r3, signVp(held.privateKey, r3, tampered));
  assert.strictEqual(v3.ok, false, "a tampered credential must be refused.");
  assert.ok(/Issuer signature/.test(failedCheck(v3)),
    "on the issuer signature. Failed: " + failedCheck(v3));
  log.info("[verifier] OK — a tampered credential is refused (" + failedCheck(v3) + ").");

  // An SD-JWT answering a jwt_vc_json query. Worth its own case because a
  // Combined Serialization ALSO splits into three dot-separated parts, so a
  // verifier that only counted them would report the wrong problem.
  const sdJwtLike = held.credential + "~";
  const r4 = await common.freshJwtVcJsonRequest(verifierBase, false);
  const v4 = await submit(r4, sdJwtLike);
  assert.strictEqual(v4.ok, false, "an SD-JWT answering a jwt_vc_json query must be refused.");
  assert.ok(/Format/.test(failedCheck(v4)),
    "and named as a format problem rather than an undecodable JWT. Failed: " + failedCheck(v4));
  log.info("[verifier] OK — an SD-JWT answering a jwt_vc_json query is refused (" + failedCheck(v4) + ").");
}

async function test() {
  log.info("Running jwt_vc_json presentation against issuer " + issuerBase + ", verifier " + verifierBase);
  // Failures, not skips: see the note in jwt_vc_json_issuance.js.
  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.meta, "no credential issuer metadata at " + issuerBase + ". Start the STS mock.");
  assert.ok(found.id,
    "this issuer offers no jwt_vc_json credential configuration, so nothing of this format can be " +
    "presented. Offered: " + Object.keys(found.meta.credential_configurations_supported || {}).join(", "));
  const held = await common.mintJwtVcJson(issuerBase, found.id);
  common.assertIsJwtVcJson(held.credential, "the issuer");

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage", "--window-size=1500,1300");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    const accepted = await presentThroughThePages(driver, held);
    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0, "the pages logged browser errors:\n" + errors.join("\n"));
    // After the console check: these drive the verifier directly, not the pages.
    await verifierNegatives(held, accepted);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program.addOption(new Option("-u, --url <url>", "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>", "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
