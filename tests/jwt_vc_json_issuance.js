// File: jwt_vc_json_issuance.js
//
// ---------------------------------------------------------------------------
// OID4VCI issuance in the jwt_vc_json format, against the mock Credential
// Issuer the STS service hosts.
//
// The sibling of sd_jwt_vc_issuance.js, which covers the same workflow in
// dc+sd-jwt. Kept separate rather than folded in as a flag, because most of
// that suite is about Disclosures — choosing them, hashing them, the decoy
// digest, the sd_hash that commits to which ones went — and none of that exists
// in this format. A flag would leave those sections skipped and the run would
// read as though selective disclosure had been declined rather than being
// unavailable.
//
// What this asserts is the format's own contract and the wallet's handling of
// it:
//
//   * the issuer ADVERTISES jwt_vc_json properly — credential_definition.type
//     in place of a vct, since a W3C VC has no vct;
//   * what comes back is genuinely a VC-JWT and not an SD-JWT wearing the
//     configuration id;
//   * the issuer signature verifies against the published JWKS;
//   * holder binding is present, and WHICH kind it is is reported rather than
//     assumed — the mock uses cnf.jwk, walt.id uses a subject DID;
//   * the wallet's own pages read the credential correctly: step 3 shows it,
//     and the presentation workflow's entry point describes it as a credential
//     that cannot withhold anything.
//
// What it deliberately does NOT re-do: the authorization leg. Getting an access
// token through oauth2_oidc_1.html and back is identical for both formats and
// is covered end to end by sd_jwt_vc_issuance.js; repeating it here would
// double the slowest part of the suite to test nothing new.
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
var log = bunyan.createLogger({ name: "jwt_vc_json_issuance",
                                level: appconfig.logLevel || "info" });

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/,
    "");

const { text, waitForStatus } = require("./wait_for");

function severeErrors(driver) {
  log.debug("Entering severeErrors().");
  const logging = require("selenium-webdriver/lib/logging");
  log.debug("Leaving severeErrors().");
  return driver.manage().logs().get(logging.Type.BROWSER)
                       .then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// --- what the issuer says it offers ----------------------------------------
async function metadataAdvertisesTheFormat() {
  log.debug("Entering metadataAdvertisesTheFormat().");
  log.info("=== The issuer advertises jwt_vc_json ===");
  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.meta,
            "the mock credential issuer should publish its metadata at " +
            issuerBase);
  assert.ok(found.id,
    "this issuer offers no jwt_vc_json credential configuration. Offered: " +
    Object.keys((found.meta || {}).credential_configurations_supported ||
                {}).join(", "));

  const entry = found.entry;
  assert.strictEqual(entry.format, common.FORMAT,
                     "the configuration should name the format.");
  assert.ok(entry.credential_definition &&
            Array.isArray(entry.credential_definition.type),
    "a jwt_vc_json configuration identifies its credential with " +
        "credential_definition.type — there is no " +
    "vct in this format. Got: " + JSON.stringify(entry.credential_definition));
  assert.ok(entry.credential_definition.type.indexOf(
            "VerifiableCredential") >= 0,
    "and that type array starts from VerifiableCredential. Got: " +
    JSON.stringify(entry.credential_definition.type));
  assert.ok(!entry.vct,
    "a jwt_vc_json configuration should NOT carry a vct: that is the SD-JWT " +
        "VC way of naming a credential, " +
    "and advertising both would tell a wallet two different things.");
  log.info("[metadata] OK — " + found.id + " offers " +
           entry.credential_definition.type.join("/") +
           " as " + entry.format + ".");
  log.debug("Leaving metadataAdvertisesTheFormat().");
  return found;
}

// --- what actually comes back ----------------------------------------------
async function issuesARealVcJwt(found) {
  log.debug("Entering issuesARealVcJwt().");
  log.info("=== The credential endpoint issues a VC-JWT ===");
  const held = await common.mintJwtVcJson(issuerBase, found.id);
  const parsed = common.assertIsJwtVcJson(held.credential, "the mock issuer");

  // The issuer signature, checked here rather than trusted: this is the one
  // assertion that fails if the issuer signs with a key it does not publish.
  const header = common.jsonFromB64u(held.credential.split(".")[0]);
  const jwks = (await common.httpJson(issuerBase + "/oauth2/jwks")).body;
  const key = ((jwks || {}).keys ||
      []).filter(function (k) { return k.kid === header.kid; })[0];
  assert.ok(key, "the issuer should publish the key it signed with (kid " +
            header.kid + "). Published: " +
    ((jwks || {}).keys || []).map(function (k) { return k.kid; }).join(", "));
  const parts = held.credential.split(".");
  const verified = crypto.verify("sha256", Buffer.from(parts[0] + "." +
      parts[1]),
    crypto.createPublicKey({ key: key, format: "jwk" }), Buffer.from(parts[2],
                           "base64url"));
  assert.ok(verified, "the credential's signature should verify against the " +
            "issuer's published JWKS.");

  const binding = common.holderBindingOf(parsed.payload);
  assert.notStrictEqual(binding.kind, "none",
    "an issued credential should say who may present it — cnf.jwk or a " +
        "subject DID in " +
    "credentialSubject.id. It carries neither.");
  assert.strictEqual(binding.kind, "cnf.jwk",
    "the MOCK issuer binds with cnf.jwk (walt.id's own profiles use a " +
        "subject DID instead, which is what " +
    "the walt.id job reports). Got: " + binding.kind);
  assert.strictEqual(binding.jwk.x, held.publicJwk.x,
    "and binds it to the key the proof of possession presented.");

  const claimCount = Object.keys(parsed.credentialSubject)
      .filter(function (k) { return k !== "id"; }).length;
  assert.ok(claimCount > 0,
            "the credential should assert something about its subject.");
  log.info("[issuance] OK — a " + parsed.types.join("/") + " with " +
           claimCount +
           " claim(s), signed by " + header.kid + ", bound by " + binding.kind +
               ".");
  log.debug("Leaving issuesARealVcJwt().");
  return held;
}

// --- the wallet's pages read it --------------------------------------------
// Issuing a credential the workflow cannot then display would be a hollow pass,
// so the credential goes into the wallet and the pages are asked about it.
async function theWalletPagesReadIt(driver, held) {
  log.debug("Entering theWalletPagesReadIt().");
  log.info("=== The wallet pages read a jwt_vc_json credential ===");
  await common.plantIntoWallet(driver, {
    By: By, until: until, baseUrl: baseUrl, waitTime: waitTime,
    credential: held.credential, publicJwk: held.publicJwk,
        privateJwk: held.privateJwk,
    verifierBase: issuerBase, issuerBase: issuerBase
  });

  // Issuance step 3 — the credential in hand.
  await driver.get(baseUrl + "/vc-issuance-3.html");
  await driver.wait(until.elementLocated(By.id("vc_credential_raw")), waitTime);
  await driver.sleep(700);
  const raw = await text(driver, "vc_credential_raw");
  assert.ok(String(raw).indexOf("~") === -1 || String(raw).trim() === "",
    "step 3 should be showing the VC-JWT it was given, not something with " +
        "Disclosures in it.");

  // The presentation workflow's entry point is where the format's one real
  // consequence has to be stated, so this is asserted rather than eyeballed.
  await driver.get(baseUrl + "/vc-presentation-0.html");
  await driver.wait(until.elementLocated(By.id("vp_credential_state")),
                    waitTime);
  const state = await waitForStatus(driver, "vp_credential_state",
    function (s) { return s.trim() !== ""; },
              "step 0 should describe the held credential", waitTime);
  assert.ok(/jwt_vc_json/.test(state),
    "it should name the format it is holding. Said: " + state);
  assert.ok(/no selective disclosure|cannot be withheld/.test(state),
    "and say that nothing in it can be withheld — the one thing this format " +
        "changes for a holder. Said: " +
    state);
  assert.ok(!/0 selectively-disclosable/.test(state),
    "and must NOT report it as a credential with 0 selectively-disclosable " +
        "claims: it is full of claims, " +
    "none of which can be withheld, which is a different statement. Said: " +
        state);
  log.info("[wallet] OK — step 3 shows it and step 0 describes the format " +
           "honestly.");
  log.debug("Leaving theWalletPagesReadIt().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running jwt_vc_json issuance against " + issuerBase);
  // Not reachable, or not offering the format, is a FAILURE rather than a skip.
  // This job exists to prove jwt_vc_json issuance works; a run in which it
  // quietly did nothing is the outcome that looks like success and is not.
  const found = await common.jwtVcJsonConfigurationId(issuerBase);
  assert.ok(found.meta,
    "no credential issuer metadata at " + issuerBase +
        ". Start the STS mock and set " +
    "WSTRUST_STS_URL / OID4VCI_ISSUER_URL.");
  assert.ok(found.id,
    "this issuer offers no jwt_vc_json credential configuration, so the " +
        "format is untested. Offered: " +
    Object.keys(found.meta.credential_configurations_supported ||
                {}).join(", "));

  await metadataAdvertisesTheFormat();
  const held = await issuesARealVcJwt(found);

  var options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage",
                       "--window-size=1500,1300");
  // Crypto and this suite's services on loopback — see tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await theWalletPagesReadIt(driver, held);
    const errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0, "the pages logged browser errors:\n" +
                       errors.join("\n"));
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "base url of the debugger under test"));
program.addOption(new Option("-h, --headless <headless>",
                  "run headless (true/false)"));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
