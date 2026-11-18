// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_user_guide.js
//
// ---------------------------------------------------------------------------
// THE VC WORKFLOWS AS docs/vc/ DESCRIBES THEM, DRIVEN AGAINST ANY OPENID4VCI
// CREDENTIAL ISSUER, AND THE SCREENSHOTS THAT GUIDE IS ILLUSTRATED WITH.
//
// docs/vc/ is the user guide to the Verifiable Credential pages, and its
// tutorials are the walks this job takes. It takes them the way the guide
// tells a reader to: the issuer is ANY OpenID4VCI Credential Issuer
// (OID4VCI_ISSUER_URL, here iya-sts), every value typed into a page comes
// from that issuer's metadata or from the offer its own website made, and
// no issuer setting is changed. It uses only pre-authorized offers, which a
// Credential Issuer may redeem for a wallet it has never seen
// (`pre-authorized_grant_anonymous_access_supported`). In the suite it
// declares the shared test wallet in iya-sts's registry first, as every
// wallet job does; with VC_GUIDE_NO_PROVISION=1 it registers nothing at all,
// which is how the guide's pictures are taken against an issuer somebody
// else runs (VC_GUIDE_HOLDER_USERNAME / _PASSWORD then name the account its
// offer page signs in as, and without one the offer sections are skipped).
//
// What it drives, in order:
//
//   1. step 0's use-case chooser;
//   2. the Authorization Code flow as the wallet's registered public client
//      (VC_GUIDE_CLIENT_ID; declared by the job unless
//      VC_GUIDE_NO_PROVISION=1), then step 4: the refresh token, the
//      Credential Endpoint asked again, What Changed, and the refreshed
//      credential kept as the Credential History's second generation;
//      then a pre-authorized offer with a Transaction Code, taken on step 1,
//      redeemed on step 2 and verified on step 3;
//   3. the same with DPoP turned on at step 2;
//   4. a deferred offer (the Deferred Issuance pane on step 2);
//   5. the jwt_vc_json and ldp_vc configurations, when the issuer offers
//      them, for step 3's per-format checks;
//   6. DID Tools against the issuer's own origin (did:web and its DID
//      Configuration), and the VC Barcodes, Gordian Envelope and ACDC pages
//      with the samples those pages carry;
//   7. presentation of the held credential to the debugger's OWN Verifier
//      page, when the api is reachable from the page (API_URL), under
//      OpenID4VP 1.0 and under HAIP 1.0.
//
// THE OFFER is made on the issuer's own website — the place OpenID4VCI
// leaves it to — here iya-sts's account portal (/portal/wallet), which is
// the only iya-sts-shaped thing in this file, and the guide describes it as
// "your issuer's credential offer page".
//
// SCREENSHOTS: every snap() below is inert unless DOC_SCREENSHOT_DIR is set
// (see doc_screenshots.js), so an ordinary run takes none:
//
//   DOC_SCREENSHOT_DIR=$PWD/../docs/vc/images \
//     CONFIG_FILE=$PWD/env/local.js node vc_user_guide.js -u <client>
//
// Every assertion here holds whether or not pictures are being taken.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "vc_user_guide",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());
const browserFlags = require("./browser_flags.js");
const common = require("./jwt_vc_json_common.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const docShots = require("./doc_screenshots.js");
const { usernameFor } = require("./random_username.js");
const { loadUrl } = require("./page_load.js");
const waitForContent = require("./wait_for.js");

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const ISSUER = (process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
let BASE = "https://localhost:3000";
const API_URL = String(process.env.API_URL || "").replace(/\/+$/, "");
// WHO SIGNS IN on the issuer's offer page. An issuer that creates accounts on
// first sight (the suite's) takes any name; one in product mode needs an
// account somebody made for the purpose, named here.
const HOLDER_USERNAME = String(process.env.VC_GUIDE_HOLDER_USERNAME || "");
const HOLDER_PASSWORD = String(process.env.VC_GUIDE_HOLDER_PASSWORD || "");
// A DOCUMENTATION RUN against an issuer this job does not own registers
// nothing there (VC_GUIDE_NO_PROVISION=1). The suite's run declares the
// wallet in the issuer's registry first, as every other wallet job does.
const NO_PROVISION = process.env.VC_GUIDE_NO_PROVISION === "1";
// A DOCUMENTATION RUN FROM AN ORIGIN THE ISSUER DOES NOT LIST. A wallet page
// reads the issuer's metadata with fetch(), so the issuer's CORS policy has
// to name the page's origin; the suite's issuer names the suite's client,
// and an issuer somebody else runs names theirs. VC_GUIDE_IGNORE_CORS=1
// starts Chrome with --disable-web-security so a build served on a scratch
// port can take the guide's pictures. Nothing the pages do changes but
// that: the requests and the screens are the ones a listed origin gets.
// Never set by a launcher.
const IGNORE_CORS = process.env.VC_GUIDE_IGNORE_CORS === "1";
// THE WALLET'S CLIENT AT THE ISSUER'S AUTHORIZATION SERVER. In a provisioning
// run this job declares it (public, with this client's /callback as its
// redirect URI); in a no-provision run it is a client somebody registered
// already, and with none named the pages keep their own client_id.
const GUIDE_CLIENT_ID = String(process.env.VC_GUIDE_CLIENT_ID ||
    (process.env.VC_GUIDE_NO_PROVISION === "1" ? "" : "vc-user-guide-wallet"));
// Who signs in, and the client the pages name: set by setUpTheIssuer().
const holder = { username: "", password: "" };
const WAIT = Number(process.env.TEST_WAIT_TIME_MS) > 0
  ? Math.max(20000, Number(process.env.TEST_WAIT_TIME_MS) * 4) : 20000;
require("./wait_for").configure({ timeout: WAIT });

let checks = 0;
function ok(what) {
  log.debug("Entering ok().");
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving ok().");
}

async function snap(driver, name, ids, maxHeight) {
  log.debug("Entering snap(). " + name);
  const opts = { ids: ids || [] };
  if (maxHeight) {
    opts.maxHeight = maxHeight;
  }
  await docShots.snap(driver, name, opts);
  log.debug("Leaving snap().");
}

async function clickId(driver, id) {
  log.debug("Entering clickId(). " + id);
  await driver.wait(until.elementLocated(By.id(id)), WAIT,
    "the page should have #" + id);
  await driver.executeScript(
    "document.getElementById(arguments[0]).scrollIntoView({block:'center'});" +
    "document.getElementById(arguments[0]).click();", id);
  log.debug("Leaving clickId().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). " + id);
  const text = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return e ? String(e.value !== undefined && e.tagName !== 'DIV' &&" +
    "  e.tagName !== 'SPAN' && e.tagName !== 'CODE' && e.tagName !== 'PRE' &&" +
    "  e.tagName !== 'TD' ? e.value : e.textContent).trim() : null;", id);
  log.debug("Leaving textOf().");
  return text;
}

async function openPage(driver, name) {
  log.debug("Entering openPage(). " + name);
  await loadUrl(driver, BASE + "/" + name);
  await waitForContent.waitForPageBundle(driver,
    name + " should load its bundle", WAIT);
  log.debug("Leaving openPage().");
}

// An offer made on the issuer's own website for a person signed in there.
async function offerFor(driver, configuration, mode, label) {
  log.debug("Entering offerFor(). " + configuration + " " + mode);
  const screen = await common.offerFromThePortalWallet(driver, {
    By: By, until: until, stsBase: ISSUER,
    username: holder.username || usernameFor(label || "guide"),
    password: holder.password || undefined, mode: mode,
    configuration: configuration, wait: WAIT, consentScreen: consentScreen });
  assert.ok(/credential_offer(_uri)?=/.test(screen.offerUri),
    "the issuer's offer page should show a Credential Offer: " +
    screen.offerUri);
  log.debug("Leaving offerFor().");
  return screen;
}

// Step 1 with nothing remembered, the offer typed into its Receive pane.
async function takeOffer(driver, screen, shots) {
  log.debug("Entering takeOffer().");
  await openPage(driver, "vc-issuance-1.html");
  await driver.executeScript("localStorage.clear();");
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-1.html should reload", WAIT);
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), WAIT);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
    screen.offerUri);
  if (shots) {
    await snap(driver, "01-receive-offer", ["pane_scan"]);
  }
  await clickId(driver, "scan_offer_button");
  await driver.wait(until.elementLocated(By.id("start_issuance_button")),
    WAIT, "taking the offer should offer Start Issuance");
  await driver.wait(async function () {
    const t = await textOf(driver, "vci_metadata_endpoint");
    return !!t;
  }, WAIT, "taking the offer should name the issuer's metadata endpoint");
  await driver.sleep(1000);
  if (shots) {
    await snap(driver, "02-offer", ["pane_offer"]);
    await snap(driver, "03-issuer-metadata", ["pane_vci"], 1400);
    await snap(driver, "04-authorization-server-metadata", ["pane_as"], 1400);
    await snap(driver, "05-configuration", ["pane_config"], 1800);
  }
  ok("step 1 took the offer and retrieved the issuer's metadata");
  await useTheWalletClient(driver);
  await clickId(driver, "start_issuance_button");
  await driver.wait(until.urlContains("vc-issuance-2.html"), WAIT,
    "a pre-authorized offer goes straight to the Token Request");
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-2.html should load", WAIT);
  await driver.wait(until.elementLocated(By.id("vc_tx_code")), WAIT);
  log.debug("Leaving takeOffer().");
}

// Step 2: the Transaction Code, the Token Request, then Approve.
async function redeem(driver, screen, opts) {
  log.debug("Entering redeem().");
  const shots = opts.shots;
  if (opts.dpop) {
    await driver.executeScript(
      "var c = document.getElementById('vc_dpop_enabled');" +
      "if (!c.checked) { c.click(); }");
    await driver.sleep(500);
  }
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0];" +
    "vcissuance2.onTxCodeChange();", screen.txCode);
  await driver.sleep(500);
  if (shots) {
    await snap(driver, shots + "-token-request", ["pane_pre_authorized"]);
  }
  await clickId(driver, "vc_token_request_button");
  await driver.wait(async function () {
    return !!(await driver.executeScript(
      "var e = document.getElementById('vc_access_token');" +
      "return e ? (e.value || e.textContent || '').trim() : '';"));
  }, WAIT, "the Transaction Code should redeem the pre-authorized code");
  ok("the pre-authorized code and Transaction Code were redeemed");
  await driver.sleep(500);
  if (opts.dpop) {
    const dpop = await textOf(driver, "vc_dpop_token_status");
    log.info("DPoP token status: " + dpop);
    if (shots) {
      await snap(driver, shots + "-dpop", ["pane_dpop"]);
    }
  }
  if (shots && !opts.dpop) {
    await snap(driver, shots + "-token-response", ["pane_pre_authorized"]);
    await snap(driver, shots + "-credential-request", ["pane_request"]);
    await snap(driver, shots + "-request-options", ["pane_request_options"]);
    await snap(driver, shots + "-approve", ["pane_approval"]);
  }
  await clickId(driver, "vc_approve_button");
  log.debug("Leaving redeem().");
}

async function waitForStep3(driver, extra) {
  log.debug("Entering waitForStep3().");
  await driver.wait(until.urlContains("vc-issuance-3.html"), WAIT +
    (extra || 0), "approving should issue the credential and open step 3");
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-3.html should load", WAIT);
  await driver.wait(async function () {
    return !!(await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_credential');"));
  }, WAIT, "the wallet should store the credential");
  await driver.sleep(1500);
  log.debug("Leaving waitForStep3().");
}

async function stepZero(driver) {
  log.debug("Entering stepZero().");
  docShots.setPrefix("vc-issuance");
  await openPage(driver, "vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.id("vc_usecases")), WAIT);
  await driver.wait(async function () {
    return await driver.executeScript(
      "return document.getElementById('vc_usecases').children.length > 0;");
  }, WAIT, "step 0 should draw its use cases");
  await snap(driver, "00-use-cases", []);
  ok("step 0 drew its use cases");
  log.debug("Leaving stepZero().");
}

async function preAuthorizedWithTxCode(driver) {
  log.debug("Entering preAuthorizedWithTxCode().");
  log.info("=== pre-authorized code with a Transaction Code ===");
  docShots.setPrefix("vc-pre-authorized");
  const screen = await offerFor(driver, "IdentityCredential",
    "cross-device", "guide-preauth");
  assert.ok(screen.txCode, "the offer should come with a Transaction Code");
  await takeOffer(driver, screen, true);
  await redeem(driver, screen, { shots: "06" });
  await waitForStep3(driver);
  await snap(driver, "07-credential", ["pane_credential"]);
  await snap(driver, "08-issuer-signed-jwt", ["pane_jwt"]);
  await snap(driver, "09-disclosures", ["pane_disclosures"]);
  await snap(driver, "10-claims", ["pane_claims"]);
  await snap(driver, "11-notification", ["pane_notification"]);
  const body = await driver.executeScript("return document.body.innerText;");
  assert.ok(!/signature (is )?invalid/i.test(body),
    "step 3 should not report an invalid issuer signature");
  ok("step 3 verified the SD-JWT VC");
  log.debug("Leaving preAuthorizedWithTxCode().");
}

async function withDpop(driver) {
  log.debug("Entering withDpop().");
  log.info("=== the same, with DPoP ===");
  docShots.setPrefix("vc-dpop");
  const screen = await offerFor(driver, "IdentityCredential",
    "cross-device", "guide-dpop");
  await takeOffer(driver, screen, false);
  await redeem(driver, screen, { shots: "01", dpop: true });
  await waitForStep3(driver);
  ok("a DPoP-bound access token was used for the Credential Request");
  log.debug("Leaving withDpop().");
}

async function deferred(driver) {
  log.debug("Entering deferred().");
  log.info("=== a deferred offer ===");
  docShots.setPrefix("vc-deferred");
  const screen = await offerFor(driver, "IdentityCredential", "deferred",
    "guide-deferred");
  await takeOffer(driver, screen, false);
  await redeem(driver, screen, {});
  await driver.wait(async function () {
    const t = await textOf(driver, "vc_transaction_id");
    return (t && t !== "—") ||
      (await driver.getCurrentUrl()).indexOf("vc-issuance-3.html") >= 0;
  }, WAIT, "a deferred offer should open the Deferred Issuance pane");
  if ((await driver.getCurrentUrl()).indexOf("vc-issuance-2.html") >= 0) {
    await snap(driver, "01-deferred-pane", ["pane_deferred"]);
  }
  await waitForStep3(driver, 20000);
  ok("the deferred credential was collected by polling");
  log.debug("Leaving deferred().");
}

async function otherFormats(driver) {
  log.debug("Entering otherFormats().");
  const meta = await common.issuerMetadata(ISSUER);
  const configs = (meta && meta.credential_configurations_supported) || {};
  const wanted = { jwt_vc_json: "vc-jwt-vc-json", ldp_vc: "vc-ldp-vc" };
  const ids = Object.keys(configs);
  const formats = Object.keys(wanted);
  for (let i = 0; i < formats.length; i++) {
    const format = formats[i];
    const id = ids.filter(function (one) {
      return configs[one].format === format;
    })[0];
    if (!id) {
      log.info("The issuer offers no " + format + " configuration; " +
               "skipping that section.");
      continue;
    }
    log.info("=== " + format + " (" + id + ") ===");
    docShots.setPrefix(wanted[format]);
    const screen = await offerFor(driver, id, "cross-device",
      "guide-" + format.replace(/_/g, ""));
    await takeOffer(driver, screen, false);
    await redeem(driver, screen, {});
    await waitForStep3(driver);
    await snap(driver, "01-credential", ["pane_credential"]);
    await snap(driver, "02-checks", ["pane_jwt"]);
    await snap(driver, "03-claims", ["pane_claims"]);
    ok("step 3 read the " + format + " credential");
  }
  log.debug("Leaving otherFormats().");
}

// The account and the client the offer and authorization code sections use.
// What is created is named in the log, so a run against somebody else's
// issuer leaves a list of what to remove.
async function setUpTheIssuer() {
  log.debug("Entering setUpTheIssuer().");
  holder.username = HOLDER_USERNAME || usernameFor("guide");
  holder.password = HOLDER_PASSWORD;
  if (NO_PROVISION) {
    log.debug("Leaving setUpTheIssuer(). Nothing is provisioned.");
    return;
  }
  if (!holder.password) {
    holder.password = "Guide-" + nodeCrypto.randomBytes(9)
      .toString("base64url") + "-Aa1!";
  }
  const meta = await common.issuerMetadata(ISSUER);
  const scopes = ["openid", "profile", "email", "offline_access"]
    .concat(common.credentialScopes(meta));
  await common.provisionWallet(ISSUER, {
    clientId: GUIDE_CLIENT_ID, name: "VC user guide wallet",
    grantTypes: ["urn:ietf:params:oauth:grant-type:pre-authorized_code",
                 "authorization_code", "refresh_token"],
    redirectUris: [BASE + "/callback"], scopes: scopes,
    why: "the wallet the user guide's tutorials collect credentials with" });
  await registry.ensurePerson(registry.stsBaseFor(ISSUER), holder.username,
                              holder.password);
  log.info("Provisioned at " + ISSUER + ": the public client " +
           GUIDE_CLIENT_ID + " (redirect URI " + BASE + "/callback) and " +
           "the account " + holder.username + ".");
  log.debug("Leaving setUpTheIssuer().");
}

// Step 1's client_id, set to the wallet's registration and saved, when this
// run has one; otherwise the pages keep their own.
async function useTheWalletClient(driver) {
  log.debug("Entering useTheWalletClient().");
  if (!GUIDE_CLIENT_ID) {
    log.debug("Leaving useTheWalletClient(). No client named.");
    return;
  }
  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];" +
    "document.getElementById('config_save_button').click();",
    GUIDE_CLIENT_ID);
  await driver.sleep(500);
  log.debug("Leaving useTheWalletClient().");
}

async function waitForStatusText(driver, id, re, why) {
  log.debug("Entering waitForStatusText(). " + id);
  let said = "";
  await driver.wait(async function () {
    said = await textOf(driver, id) || "";
    return re.test(said);
  }, WAIT, why);
  log.debug("Leaving waitForStatusText().");
  return said;
}

// Appendix H.6: step 1 already holds the issuer's metadata (from
// issuerMetadataPanes()); Start Issuance runs the Authorization Code flow,
// the holder signs in at the authorization server, and step 2 requests.
async function authorizationCode(driver) {
  log.debug("Entering authorizationCode().");
  log.info("=== the Authorization Code flow ===");
  docShots.setPrefix("vc-authorization-code");
  await useTheWalletClient(driver);
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-1.html should reload", WAIT);
  await driver.wait(until.elementLocated(By.id("start_issuance_button")),
    WAIT);
  await driver.sleep(1000);
  await snap(driver, "01-authorize-issuance", ["pane_handoff"]);
  await clickId(driver, "start_issuance_button");
  await driver.wait(until.elementLocated(By.id("username")), WAIT,
    "Start Issuance should reach the authorization server's sign-in");
  await driver.findElement(By.id("username")).sendKeys(holder.username);
  await driver.findElement(By.id("password")).sendKeys(holder.password);
  await driver.findElement(By.id("kc-login")).click();
  await consentScreen.passInBrowser(driver, By);
  await driver.wait(until.urlContains("vc-issuance-2.html"), WAIT,
    "the code should be exchanged and step 2 opened");
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-2.html should load", WAIT);
  await driver.wait(async function () {
    return !!(await driver.executeScript(
      "var e = document.getElementById('vc_access_token');" +
      "return e ? (e.value || e.textContent || '').trim() : '';"));
  }, WAIT, "step 2 should show the access token the code bought");
  await driver.sleep(1500);
  await snap(driver, "02-tokens", ["pane_tokens"]);
  await snap(driver, "03-credential-request", ["pane_request"]);
  ok("the Authorization Code flow returned to step 2 with tokens");
  await clickId(driver, "vc_approve_button");
  await waitForStep3(driver);
  await snap(driver, "04-credential", ["pane_credential"]);
  ok("step 3 holds the credential issued by authorization code");
  log.debug("Leaving authorizationCode().");
}

// Step 4 on the credential in hand: refresh the access token, ask the
// Credential Endpoint again, compare, keep, and the history.
async function refreshIt(driver) {
  log.debug("Entering refreshIt().");
  log.info("=== step 4: refresh ===");
  docShots.setPrefix("vc-refresh");
  await openPage(driver, "vc-issuance-4.html");
  await driver.wait(until.elementLocated(By.id("pane_current")), WAIT);
  await driver.sleep(1500);
  await snap(driver, "01-current", ["pane_current"]);
  await snap(driver, "02-history", ["pane_history"]);
  const refreshToken = await textOf(driver, "vc_refresh_token_value");
  if (!refreshToken) {
    await snap(driver, "03-refresh-token", ["pane_refresh"]);
    log.info("The authorization server issued no refresh token; step 4 " +
             "says so, and the refresh is not driven.");
    log.debug("Leaving refreshIt(). No refresh token.");
    return;
  }
  await clickId(driver, "vc_refresh_button");
  const said = await waitForStatusText(driver, "vc_refresh_status",
    new RegExp("fresh access token was issued|refused the refresh|" +
               "refresh request failed|nothing to send"),
    "the refresh should finish");
  assert.ok(/fresh access token was issued/.test(said),
    "the refresh should succeed: " + said);
  await snap(driver, "03-refresh-token", ["pane_refresh"]);
  ok("the refresh token bought a fresh access token");
  await clickId(driver, "vc_reissue_button");
  const reissued = await waitForStatusText(driver, "vc_reissue_status",
    /returned a credential|refused|failed|not ready/,
    "the Credential Request should finish");
  assert.ok(/returned a credential/.test(reissued),
    "the issuer should return a refreshed credential: " + reissued);
  await driver.sleep(1000);
  await snap(driver, "04-reissue", ["pane_reissue"]);
  await snap(driver, "05-what-changed", ["pane_compare"]);
  await clickId(driver, "vc_replace_button");
  await driver.wait(async function () {
    return /^generation 2 of 2/.test(
      await textOf(driver, "vc_history_position") || "");
  }, WAIT, "keeping it should add a generation to the history");
  await driver.sleep(800);
  await snap(driver, "06-history-after", ["pane_history"]);
  ok("the refreshed credential was kept as generation 2");
  log.debug("Leaving refreshIt().");
}

// Step 1 with no offer at all: the issuer's metadata retrieved from its URL,
// the way a wallet-initiated issuance (Appendix H.6) begins.
async function issuerMetadataPanes(driver) {
  log.debug("Entering issuerMetadataPanes().");
  log.info("=== step 1: the issuer's metadata ===");
  docShots.setPrefix("vc-metadata");
  await openPage(driver, "vc-issuance-1.html");
  await driver.executeScript("localStorage.clear();");
  await driver.navigate().refresh();
  await waitForContent.waitForPageBundle(driver,
    "vc-issuance-1.html should reload", WAIT);
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")),
    WAIT);
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];",
    ISSUER + "/.well-known/openid-credential-issuer");
  await clickId(driver, "vci_retrieve_button");
  await driver.wait(async function () {
    return await driver.executeScript(
      "var t = document.getElementById('vci_metadata_table');" +
      "return !!t && t.querySelectorAll('tr').length > 2;");
  }, WAIT, "retrieving the Credential Issuer Metadata should fill its table");
  ok("step 1 retrieved the Credential Issuer Metadata");
  await clickIfShown(driver, "vci_validate_signed_metadata_button");
  await driver.sleep(1500);
  await clickIfShown(driver, "as_retrieve_button");
  await driver.sleep(2000);
  const did = await textOf(driver, "did_identifier");
  if (did) {
    await clickIfShown(driver, "did_resolve_button");
    await driver.sleep(2000);
  }
  await clickIfShown(driver, "didcfg_retrieve_button");
  await driver.sleep(1500);
  await clickIfShown(driver, "didcfg_verify_button");
  await driver.sleep(1500);
  // The four documents sit side by side on this page, so they are one
  // picture.
  await snap(driver, "01-metadata-documents", ["pane_vci", "pane_did",
    "pane_as", "pane_didcfg"], 1600);
  await snap(driver, "05-configuration-parameters", ["pane_config"], 2000);
  await snap(driver, "06-client-authentication", ["pane_client_auth"]);
  await snap(driver, "07-claims-to-request", ["pane_claims"]);
  await snap(driver, "08-authorize-issuance", ["pane_handoff"]);
  await snap(driver, "09-receive-offer", ["pane_scan"]);
  log.debug("Leaving issuerMetadataPanes().");
}

async function clickIfShown(driver, id) {
  log.debug("Entering clickIfShown(). " + id);
  const shown = await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "return !!e && !e.disabled && e.offsetParent !== null;", id);
  if (shown) {
    await clickId(driver, id);
  }
  log.debug("Leaving clickIfShown(). " + shown);
  return shown;
}

// DID Tools against the issuer's own origin: its did:web document and the
// DIF DID Configuration that links that DID to the origin.
async function didTools(driver) {
  log.debug("Entering didTools().");
  log.info("=== DID Tools ===");
  docShots.setPrefix("did-tools");
  const origin = new URL(ISSUER);
  const did = "did:web:" + encodeURIComponent(origin.host);
  await openPage(driver, "did-tools.html");
  await driver.wait(until.elementLocated(By.id("did_identifier")), WAIT);
  await driver.executeScript(
    "document.getElementById('did_identifier').value = arguments[0];" +
    "document.getElementById('did_tools_origin').value = arguments[1];",
    did, origin.origin);
  await clickId(driver, "did_resolve_button");
  await driver.wait(async function () {
    return /resolved|retrieved|could not|fail|error/i.test(
      await textOf(driver, "did_status") || "");
  }, WAIT, "Resolve should say what it did");
  const resolved = await textOf(driver, "did_status");
  log.info("DID Tools said: " + resolved);
  await snap(driver, "01-resolve", ["pane_did"], 1600);
  await snap(driver, "02-members", ["pane_did_members"], 1600);
  await clickId(driver, "did_linkage_button");
  await driver.wait(async function () {
    const t = await textOf(driver, "did_linkage_status") || "";
    return t.length > 3 && !/^Fetching/.test(t);
  }, WAIT, "Verify Linkage should say what it found");
  log.info("Domain linkage said: " +
           await textOf(driver, "did_linkage_status"));
  await snap(driver, "03-domain-linkage", ["pane_did_linkage"], 1600);
  ok("DID Tools resolved " + did + " and checked its domain linkage");
  log.debug("Leaving didTools().");
}

// ---------------------------------------------------------------------------
// PRESENTATION TO THE DEBUGGER'S OWN VERIFIER. The wallet holds an SD-JWT VC
// from a test issuer named by did:jwk (so the Verifier page can check the
// issuer's signature with no network), the Verifier page creates a request
// through the api in one tab, and the wallet pages answer it in another.
// ---------------------------------------------------------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function ecPair() {
  log.debug("Entering ecPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving ecPair().");
  return { privateKey: pair.privateKey,
           publicJwk: pair.publicKey.export({ format: "jwk" }),
           privateJwk: pair.privateKey.export({ format: "jwk" }) };
}

const GUIDE_VCT = "urn:example:guide:identity";

function testCredential(holder) {
  log.debug("Entering testCredential().");
  const issuer = ecPair();
  const did = "did:jwk:" + b64u(JSON.stringify({ kty: "EC", crv: "P-256",
    x: issuer.publicJwk.x, y: issuer.publicJwk.y }));
  const now = Math.floor(Date.now() / 1000);
  const disclosures = [["given_name", "Erika"], ["family_name", "Mustermann"],
                       ["birthdate", "1963-08-12"], ["email",
                       "erika@example.com"]].map(function (c, i) {
    return b64u(JSON.stringify(["salt-" + i + "-" +
      nodeCrypto.randomBytes(6).toString("hex"), c[0], c[1]]));
  });
  const header = { alg: "ES256", typ: "dc+sd-jwt", kid: did + "#0" };
  const payload = { iss: did, iat: now - 60, nbf: now - 60,
    exp: now + 86400, vct: GUIDE_VCT, _sd_alg: "sha-256",
    _sd: disclosures.map(function (d) {
      return b64u(nodeCrypto.createHash("sha256").update(d).digest());
    }), cnf: { jwk: holder.publicJwk } };
  const input = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: issuer.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving testCredential().");
  return input + "." + b64u(sig) + "~" + disclosures.join("~") + "~";
}

async function holdTestCredential(driver) {
  log.debug("Entering holdTestCredential().");
  const holder = ecPair();
  const credential = testCredential(holder);
  await openPage(driver, "vc-presentation-0.html");
  await driver.executeScript(
    "localStorage.clear();" +
    "localStorage.setItem('sdjwtvc_credential', arguments[0]);" +
    "localStorage.setItem('sdjwtvc_credentials'," +
    "  JSON.stringify([arguments[0]]));" +
    "localStorage.setItem('sdjwtvc_holder_jwk', arguments[1]);" +
    "localStorage.setItem('sdjwtvc_holder_private_jwk', arguments[2]);",
    credential, JSON.stringify(holder.publicJwk),
    JSON.stringify(holder.privateJwk));
  log.debug("Leaving holdTestCredential().");
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.executeScript(
    "var e = document.getElementById(arguments[0]);" +
    "if (e.type === 'checkbox') { e.checked = !!arguments[1]; }" +
    "else { e.value = arguments[1]; }", id, value);
  log.debug("Leaving setField().");
}

// The Verifier page, in the tab it is in: the query and the request.
async function verifierRequest(driver, profile, mode) {
  log.debug("Entering verifierRequest(). " + profile + " " + mode);
  await openPage(driver, "vc-verifier.html");
  await driver.wait(async function () {
    return (await textOf(driver, "vpv_api_status") || "").length > 3;
  }, WAIT, "the Verifier page should say whether the api can host it");
  await setField(driver, "vpv_query_id", "identity");
  await setField(driver, "vpv_format", "dc+sd-jwt");
  await setField(driver, "vpv_type", GUIDE_VCT);
  await setField(driver, "vpv_claims", "given_name\nfamily_name");
  await setField(driver, "vpv_binding", true);
  await setField(driver, "vpv_dcql", "");
  await driver.executeScript("window.vcverifier.regenerateDcql();");
  await setField(driver, "vpv_profile", profile);
  await setField(driver, "vpv_client_prefix", "x509_hash");
  await setField(driver, "vpv_response_mode", mode);
  await setField(driver, "vpv_delivery", "reference-get");
  await driver.executeScript("window.vcverifier.settingsChanged();");
  await clickId(driver, "btn_vpv_create");
  await driver.wait(async function () {
    return /ready|failed|refused|no api|did not/i.test(
      await textOf(driver, "vpv_create_status") || "");
  }, WAIT, "Create the request never finished");
  const said = await textOf(driver, "vpv_create_status");
  assert.ok(/ready/i.test(said), "Creating the request said: " + said);
  const out = await driver.executeScript(
    "var r = window.vcverifier.currentRequest();" +
    "return { invocation: r.invocation," +
    "  root: document.getElementById('vpv_root_pem').value ||" +
    "    document.getElementById('vpv_root_pem').textContent };");
  assert.ok(out.invocation, "the Verifier page made no invocation");
  log.debug("Leaving verifierRequest().");
  return out;
}

// The wallet, in its own tab: step 0's protocol and trust anchor, the
// request pasted into step 1, the claims chosen on step 2, and step 3.
async function walletAnswers(driver, protocol, request, shots) {
  log.debug("Entering walletAnswers(). " + protocol);
  await openPage(driver, "vc-presentation-0.html");
  await driver.wait(until.elementLocated(By.id("vp_protocol_" + protocol)),
    WAIT);
  await driver.executeScript(
    "document.getElementById('vp_protocol_' + arguments[0]).click();" +
    "document.getElementById('vp_x509_trust_anchor').value = arguments[1];" +
    "document.getElementById('config_save_button').click();",
    protocol, request.root.trim());
  await driver.sleep(800);
  if (shots) {
    await snap(driver, "01-roles-and-credential", ["vp_roles",
      "vp_credential_state"]);
    await snap(driver, "02-configuration", ["pane_config"]);
    await snap(driver, "03-protocol", ["vp_protocols", "vp_protocol_status"]);
    await snap(driver, "04-flow", ["vp_usecases", "vp_usecase_status"]);
  }
  await openPage(driver, "vc-presentation-1.html");
  await driver.wait(until.elementLocated(By.id("vp_paste_request")), WAIT);
  await driver.executeScript(
    "document.getElementById('vp_paste_request').value = arguments[0];",
    request.invocation);
  if (shots) {
    await snap(driver, "05-paste-request", ["pane_receive"]);
  }
  await clickId(driver, "vp_use_pasted_button");
  await driver.wait(async function () {
    return /Request read|cannot be answered/.test(
      await textOf(driver, "vp_request_status") || "");
  }, WAIT, "step 1 should read the request");
  const status = await textOf(driver, "vp_request_status");
  assert.ok(/Request read/.test(status), "step 1 said: " + status);
  if (shots) {
    await snap(driver, "06-rules", ["pane_rules"]);
    await snap(driver, "07-authorization-request", ["pane_request"], 2000);
    await snap(driver, "08-what-is-asked", ["pane_requested"]);
  }
  ok("step 1 read the Verifier's request under " + protocol);
  await clickId(driver, "vp_continue_button");
  await driver.wait(until.urlContains("vc-presentation-2.html"), WAIT,
    "Continue should open step 2");
  await waitForContent.waitForPageBundle(driver,
    "vc-presentation-2.html should load", WAIT);
  await driver.wait(async function () {
    return /Ready/.test(await textOf(driver, "vp_present_status") || "");
  }, WAIT, "step 2 should be ready to present");
  if (shots) {
    await snap(driver, "09-what-was-asked", ["pane_ask"], 1600);
    await snap(driver, "10-choose", ["pane_choose"], 1600);
    await snap(driver, "11-presentation", ["pane_presentation"], 1600);
    await snap(driver, "12-present", ["pane_present"], 1600);
  }
  await clickId(driver, "vp_present_button");
  await driver.wait(until.urlContains("vc-presentation-3.html"), WAIT,
    "presenting should reach step 3");
  await waitForContent.waitForPageBundle(driver,
    "vc-presentation-3.html should load", WAIT);
  await driver.wait(async function () {
    return /accepted|refused|answered|HTTP/i.test(
      await textOf(driver, "vp_verifier_status") || "");
  }, WAIT, "step 3 should report the Verifier's answer");
  await driver.sleep(1000);
  if (shots) {
    await snap(driver, "13-what-was-sent", ["pane_sent"], 1600);
    await snap(driver, "14-own-checks", ["pane_recheck"], 1600);
    await snap(driver, "15-how-answered", ["pane_answer"], 1600);
    await snap(driver, "16-verifier-answer", ["pane_verifier"], 1600);
  }
  log.debug("Leaving walletAnswers().");
}

async function presentToOwnVerifier(driver, protocol, profile, mode,
                                    prefix) {
  log.debug("Entering presentToOwnVerifier(). " + protocol);
  log.info("=== presentation to the debugger's Verifier: " + protocol +
           ", " + mode + " ===");
  docShots.setPrefix(prefix);
  await holdTestCredential(driver);
  const verifierTab = await driver.getWindowHandle();
  const request = await verifierRequest(driver, profile, mode);
  await snap(driver, "00-verifier-request", ["pane_handoff"]);
  await driver.switchTo().newWindow("tab");
  const walletTab = await driver.getWindowHandle();
  await walletAnswers(driver, protocol, request, true);
  await driver.switchTo().window(verifierTab);
  await driver.wait(async function () {
    return /passed|failed|could not/i.test(
      await textOf(driver, "vpv_verdict") || "");
  }, WAIT, "the Verifier page should check the wallet's answer");
  const verdict = await textOf(driver, "vpv_verdict");
  await snap(driver, "17-verifier-checks", ["pane_response"]);
  assert.ok(/every check passed/i.test(verdict),
    "the debugger's Verifier should accept the wallet's answer: " + verdict);
  ok("the debugger's own Verifier accepted the " + protocol + " answer");
  await driver.switchTo().window(walletTab);
  await driver.close();
  await driver.switchTo().window(verifierTab);
  log.debug("Leaving presentToOwnVerifier().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. client=" + BASE + ", issuer=" + ISSUER +
           ", api=" + (API_URL || "(none)"));
  var options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, BASE);
  if (IGNORE_CORS) {
    log.warn("VC_GUIDE_IGNORE_CORS=1: Chrome runs with " +
             "--disable-web-security (a documentation run only).");
    options.addArguments("--disable-web-security");
  }
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await driver.manage().window().setRect({ width: 1280, height: 1000 });
    await stepZero(driver);
    await setUpTheIssuer();
    await issuerMetadataPanes(driver);
    if (NO_PROVISION && !HOLDER_USERNAME) {
      log.info("SKIPPED the sections that take an offer or sign in: this " +
               "is a documentation run against an issuer this job may not " +
               "register anything at (VC_GUIDE_NO_PROVISION=1), and no " +
               "account to sign in with was named " +
               "(VC_GUIDE_HOLDER_USERNAME).");
    } else {
      if (GUIDE_CLIENT_ID && holder.password) {
        await authorizationCode(driver);
        await refreshIt(driver);
      } else {
        log.info("SKIPPED the Authorization Code flow: it needs a " +
                 "registered client (VC_GUIDE_CLIENT_ID) and the holder's " +
                 "password.");
      }
      await preAuthorizedWithTxCode(driver);
      await withDpop(driver);
      await deferred(driver);
      await otherFormats(driver);
    }
    await didTools(driver);
    if (API_URL) {
      await presentToOwnVerifier(driver, "oid4vp", "openid4vp",
        "direct_post", "vp-openid4vp");
      await presentToOwnVerifier(driver, "haip", "haip", "direct_post.jwt",
        "vp-haip");
    } else {
      log.info("No API_URL: the presentation sections need the api that " +
               "hosts the Verifier page's request, and are not run.");
    }
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully. " + checks + " checks.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("vc_user_guide")
  .description("Drive the VC workflows the way docs/vc/ describes them, " +
      "against any OpenID4VCI Credential Issuer, and take the guide's " +
      "screenshots when DOC_SCREENSHOT_DIR is set.")
  .addOption(new Option("-u, --url <url>",
      "base url of the client under test"))
  .parse(process.argv);
const cliOptions = program.opts();
if (cliOptions.url) {
  BASE = String(cliOptions.url).replace(/\/$/, "");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
