// File: dpop_workflow.js
//
// DPoP (RFC 9449) through the VC Issuance pages, in a browser.
//
// tests/dpop.js checks the wallet's crypto against the RFCs' own published
// vectors, and tests/sts_dpop.js checks the server's twelve section 4.3 checks
// over HTTP. This file checks the part neither can: that the PAGES actually use
// them, and that the token which comes back is really bound.
//
// That distinction is why this file exists. The pane is the easiest part of
// this feature to get convincingly wrong: it can display a key pair, a
// thumbprint and a decoded proof while the access token still arrives as an
// ordinary Bearer token — the wallet would LOOK as though it had DPoP and have
// none. So the assertions that carry this file are the ones about what came
// back:
//
//   * the access token's own cnf.jkt equals the thumbprint of the key the page
//     shows — recomputed here from the displayed JWK, not read off the page;
//   * token_type is DPoP, not Bearer;
//   * under Holder of Key the CREDENTIAL's cnf.jwk is that same key, which is
//     the entire claim of the second checkbox;
//   * and the assembled call shows `Authorization: DPoP` with a `DPoP:` header
//     line, because a pane that describes a request the page does not make is
//     worse than no pane at all on a page whose product IS the request.
//
// It also checks the two checkboxes are honest about each other. Holder of Key
// needs a DPoP key to reuse, so it cannot take effect with DPoP off — and a
// ticked box that silently does nothing is the sort of quiet lie this suite
// exists to catch.
//
// Driven with the pre-authorized code grant (OID4VCI Appendix H.2), so it needs
// the STS mock and the client and NO identity provider — which is why it is a
// job of its own rather than a section of sd_jwt_vc_issuance.js.

const assert = require("assert");
const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "dpop_workflow",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const browserFlags = require("./browser_flags.js");
const waitForContent = require("./wait_for.js");

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
const STS = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
let BASE = "http://localhost:3000";

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

async function txt(driver, id) {
  log.debug("Entering txt().");
  log.debug("Leaving txt().");
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); return " +
        "e?e.textContent:'(missing)';", id);
}

async function val(driver, id) {
  log.debug("Entering val().");
  log.debug("Leaving val().");
  return await driver.executeScript(
    "var e=document.getElementById(arguments[0]); return e?e.value:null;", id);
}

// Waits on CONTENT, not on an element: every field read here is static markup
// that exists during parsing, so elementLocated would succeed while saying
// nothing about whether the page has filled it in. Same reasoning as
// tests/wait_for.js.
async function waitFor(driver, id, re, what) {
  log.debug("Entering waitFor().");
  var last = "";
  try {
    await driver.wait(async function () {
      last = await txt(driver, id);
      return re.test(last);
    }, 25000, what);
  } catch (e) {
    throw new Error(what + " (last: " + JSON.stringify(String(last).slice(0,
                    260)) + ")");
  }
  log.debug("Leaving waitFor().");
  return last;
}

// An assertion rather than a running tally: a failure here means the wallet is
// not doing DPoP, and a run that carried on would report later successes about
// a wallet whose token is not bound.
function check(label, cond, detail) {
  log.debug("Entering check().");
  assert.ok(cond, label + (detail === undefined ? "" : "  -> " + detail));
  log.info("[dpop] OK — " + label);
  log.debug("Leaving check().");
}

async function paneBeforeAnythingIsSent(driver) {
  log.debug("Entering paneBeforeAnythingIsSent().");
  log.info("=== The DPoP pane, before anything is sent ===");
  // Configured the way step 1 would configure it, so this file is about DPoP
  // rather than about discovery.
  await driver.get(BASE + "/vc-issuance-2.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vc_dpop_enabled")), 20000,
    "vc-issuance-2.html has no DPoP pane");
  await driver.executeScript(
    "localStorage.clear();" +
    "localStorage.setItem('credential_issuer', arguments[0]);" +
    "localStorage.setItem('credential_endpoint', arguments[0] + " +
        "'/oid4vci/credential');" +
    "localStorage.setItem('nonce_endpoint', arguments[0] + '/oid4vci/nonce');" +
    "localStorage.setItem('token_endpoint', arguments[0] + '/oauth2/token');" +
    "localStorage.setItem('vci_credential_configuration_id', " +
        "'IdentityCredential');" +
    "localStorage.setItem('client_id', 'dpop-workflow-client');" +
    "localStorage.setItem('dpop_signing_alg_values_supported', " +
        "'ES256, RS256');", STS);
  await driver.navigate().refresh();
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vc_dpop_enabled")), 20000);
  await driver.sleep(1200);

  check("the DPoP pane is on issuance step 2",
    (await driver.findElements(By.id("pane_dpop"))).length === 1,
     "pane_dpop is missing");
  check("both checkboxes are there",
    (await driver.findElements(By.id("vc_dpop_enabled"))).length === 1 &&
    (await driver.findElements(By.id("vc_dpop_holder_of_key"))).length === 1,
    "one of the two checkboxes is missing");
  check("DPoP is OFF by default",
    (await driver.executeScript(
      "return document.getElementById('vc_dpop_enabled').checked;")) === false,
    "it defaults to ON, which would change the workflow's default path — the " +
        "Bearer flow is what " +
    "the specifications describe first and what the rest of the suite " +
        "exercises");
  check("and the note says the token will be a Bearer token",
    /Bearer/.test(await txt(driver, "vc_dpop_enabled_note")),
    await txt(driver, "vc_dpop_enabled_note"));
  check("the server's advertised dpop_signing_alg_values_supported is shown",
    /ES256/.test(await txt(driver, "vc_dpop_server_algs")),
    await txt(driver, "vc_dpop_server_algs"));

  // The two checkboxes must be honest about each other.
  //
  // WAIT ON THE NOTE, not on a fixed sleep after the click. `.click()` returns
  // once the event is dispatched, not once the handler has rewritten the note,
  // and a `sleep(900)` here is a bet that the rewrite lands inside 900ms — it
  // wins on an idle machine and loses under a full suite run, where it failed
  // as "a ticked box that silently does nothing", which is a statement about
  // the product rather than about the wait. waitFor() above is what every other
  // read in this file uses and it is faster in the normal case as well.
  await driver.findElement(By.id("vc_dpop_holder_of_key")).click();
  var bindingNote = await waitFor(driver, "vc_dpop_binding_note",
    /needs a DPoP key/,
    "ticking Holder of Key with DPoP off should rewrite the binding note");
  check("Holder of Key with DPoP off says the credential gets a holder " +
        "key of its own",
    /needs a DPoP key/.test(bindingNote) &&
      /holder key of its own/.test(bindingNote),
    "a ticked box that silently does nothing is the failure this checks " +
        "for. Note: " +
    await txt(driver, "vc_dpop_binding_note"));

  // Turning DPoP on must produce a key and its thumbprint. The key is generated
  // by Web Crypto, so it arrives on a promise: wait for the thumbprint to be
  // there rather than for two seconds to pass.
  await driver.findElement(By.id("vc_dpop_enabled")).click();
  var jkt = (await waitFor(driver, "vc_dpop_jkt", /[A-Za-z0-9_-]{43}/,
    "turning DPoP on should generate a key pair and show its jkt")).trim();
  check("turning DPoP on generates a key pair and shows its jkt",
    /^[A-Za-z0-9_-]{43}$/.test(jkt),
    "a base64url SHA-256 is 43 characters; got " + JSON.stringify(jkt));
  var publicJwk = await txt(driver, "vc_dpop_public_jwk");
  check("the public JWK is shown and carries no private half",
    /"kty"/.test(publicJwk) && !/"d"/.test(publicJwk),
    "this JWK travels in every proof header, so a private member here would " +
        "be published: " +
    publicJwk.slice(0, 140));
  check("Holder of Key is now in force",
    /Holder of Key: one key/.test(await txt(driver, "vc_dpop_binding_note")),
    await txt(driver, "vc_dpop_binding_note"));

  // The thumbprint recomputed in the browser from the DISPLAYED key, by an
  // implementation written here — so a wrong member order or a stray member in
  // the page's own thumbprint is caught rather than agreed with.
  var recomputed = await driver.executeScript(
    "var jwk = JSON.parse(document.getElementById('vc_dpop_public_jwk').textContent);" +
    "var canonical = jwk.kty === 'RSA'" +
    "  ? JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })" +
    "  : JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });" +
    "return crypto.subtle.digest('SHA-256', new " +
        "TextEncoder().encode(canonical))" +
    "  .then(function (h) {" +
    "    return btoa(String.fromCharCode.apply(null, new Uint8Array(h)))" +
    "      .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');" +
    "  });");
  check("the displayed jkt is the RFC 7638 thumbprint of the displayed key",
    recomputed === jkt, "page says " + jkt + ", recomputed independently as " +
        recomputed);
  log.debug("Leaving paneBeforeAnythingIsSent().");
}

// The mock issuer's cross-device screen carries the offer URI and the
// Transaction Code; step 1's Receive pane takes the offer; step 2 redeems it
// with the pre-authorized code grant, which needs no identity provider.
async function boundTokenThroughTheOfferFlow(driver) {
  log.debug("Entering boundTokenThroughTheOfferFlow().");
  log.info("=== A really bound token, through the real offer flow ===");
  await driver.get(STS + "/issuer/offer?mode=cross-device");
  await driver.wait(until.elementLocated(By.id("offer_uri")), 20000,
    "the issuer's cross-device offer screen did not load");
  var screen = await driver.executeScript(
    "return { offerUri: " +
        "document.getElementById('offer_uri').textContent.trim()," +
    "         txCode: document.getElementById('tx_code')" +
    "                 ? " +
        "document.getElementById('tx_code').textContent.trim() : '' };");
  check("the issuer's cross-device screen offers a credential-offer URI",
    screen.offerUri.indexOf("openid-credential-offer://") === 0,
                            screen.offerUri.slice(0, 100));
  check("...and a Transaction Code", /^[0-9]{4,8}$/.test(screen.txCode),
        screen.txCode);

  await driver.get(BASE + "/vc-issuance-1.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), 20000);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];",
        screen.offerUri);
  await driver.findElement(By.id("scan_offer_button")).click();
  // A pre-authorized offer needs no authorization request, so Start Issuance
  // goes straight to step 2.
  await driver.wait(until.elementLocated(By.id("start_issuance_button")), 25000,
    "taking the offer produced no Start Issuance button");
  await driver.sleep(1500);
  await driver.executeScript(
      "document.getElementById('start_issuance_button').click();");
  await driver.wait(until.urlContains("vc-issuance-2.html"), 25000,
    "a pre-authorized offer should go straight to step 2");
  await driver.wait(until.elementLocated(By.id("vc_dpop_enabled")), 20000);
  await driver.sleep(1500);

  check("DPoP survived the hand-off from step 1 — it is stored, not per-page",
    (await driver.executeScript(
      "return document.getElementById('vc_dpop_enabled').checked;")) === true,
    "the checkbox came back unchecked, so the preference did not survive a " +
        "navigation");
  var jkt = (await txt(driver, "vc_dpop_jkt")).trim();
  check("and so did the key pair", /^[A-Za-z0-9_-]{43}$/.test(jkt),
    "jkt after the hand-off: " + JSON.stringify(jkt));

  check("step 2 is in the pre-authorized state",
    (await driver.findElements(By.id("vc_token_request_button"))).length === 1,
    "the offer did not put step 2 into the pre-authorized Token Request " +
        "state, so the rest of " +
    "this test would prove nothing");
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; " +
        "vcissuance2.onTxCodeChange();",
    screen.txCode);
  await driver.executeScript(
      "document.getElementById('vc_token_request_button').click();");
  var tokenStatus = await waitFor(driver, "vc_token_status",
      /issued|refused|failed/i,
    "the Token Request produced no status");
  check("the pre-authorized Token Request succeeded WITH a DPoP proof",
    /An access token was issued/.test(tokenStatus), tokenStatus.slice(0, 260));

  // What came back — the assertions the pane cannot fake.
  var binding = await txt(driver, "vc_dpop_token_status");
  check("the token really came back bound to this wallet's key",
    /Bound to this wallet's key/.test(binding) && binding.indexOf(jkt) !== -1,
    binding.slice(0, 300));
  check("...and token_type was DPoP, not Bearer",
    /token_type = DPoP/.test(binding), binding.slice(0, 300));

  var cnf = await driver.executeScript(
    "var parts = localStorage.getItem('token_access_token').split('.');" +
    "var json = decodeURIComponent(escape(atob(" +
    "  parts[1].replace(/-/g,'+').replace(/_/g,'/'))));" +
    "return JSON.parse(json).cnf || null;");
  check("the access token ITSELF carries cnf.jkt equal to the wallet's " +
        "thumbprint",
    cnf && cnf.jkt === jkt,
    "this is what the pane cannot fake: the binding is inside the signed " +
        "token. cnf=" +
    JSON.stringify(cnf) + ", wallet jkt=" + jkt);

  var proof = await txt(driver, "vc_dpop_last_proof");
  check("the DPoP proof that was sent is shown decoded",
    /dpop\+jwt/.test(proof) && /"htm": "POST"/.test(proof) &&
                     /oauth2\/token/.test(proof),
    proof.slice(0, 240));
  check("...and the Token Request proof carries no ath — there was no " +
        "token yet",
    !/"ath"/.test(proof),
    "an ath here would be a claim about a token that does not exist: " +
        proof.slice(0, 300));

  var call = await val(driver, "vc_approval_request");
  check("the assembled Credential Request shows Authorization: DPoP and a " +
        "DPoP header line",
    /Authorization: DPoP /.test(call) && /^DPoP: /m.test(call),
    "a pane showing `Authorization: DPoP` with no DPoP header beside it " +
        "describes a request every " +
    "conforming server refuses. First lines: " +
        String(call).split("\n").slice(0, 5).join(" | "));
  log.debug("Leaving boundTokenThroughTheOfferFlow().");
  return jkt;
}

async function credentialIsBoundToTheDpopKey(driver) {
  log.debug("Entering credentialIsBoundToTheDpopKey().");
  log.info("=== Holder of Key: the credential is bound to the DPoP key ===");
  await driver.executeScript(
      "document.getElementById('vc_approve_button').click();");
  var approved = "";
  try {
    await driver.wait(async function () {
      // A successful issuance NAVIGATES to step 3, so waiting only on a status
      // element of the page that has gone away reads as "(missing)".
      if ((await driver.getCurrentUrl()).indexOf("vc-issuance-3") !== -1) {
        approved = "(went on to step 3)";
        return true;
      }
      approved = await txt(driver, "vc_approval_status");
      return /issued|refused|failed|could not/i.test(approved);
    }, 30000, "approving produced neither a status nor a navigation");
  } catch (e) {
    throw new Error("approving produced neither a status nor a " +
                    "navigation (last: " +
                    JSON.stringify(String(approved).slice(0, 220)) + ")");
  }
  check("the Credential Request succeeded with a DPoP-bound token",
    !/refused|failed|could not/i.test(approved), approved.slice(0, 280));

  var credentialCnf = await driver.executeScript(
    "var c = localStorage.getItem('sdjwtvc_credential');" +
    "if (!c) return null;" +
    "var parts = c.split('~')[0].split('.');" +
    "var json = decodeURIComponent(escape(atob(" +
    "  parts[1].replace(/-/g,'+').replace(/_/g,'/'))));" +
    "return (JSON.parse(json).cnf || {}).jwk || null;");
  var dpopPublic = await driver.executeScript(
    "return JSON.parse(localStorage.getItem('sdjwtvc_dpop_public_jwk') " +
        "|| 'null');");
  check("the credential's cnf.jwk IS the DPoP key",
    credentialCnf && dpopPublic && credentialCnf.kty === dpopPublic.kty &&
    credentialCnf.x === dpopPublic.x && credentialCnf.y === dpopPublic.y,
    "this is the whole claim of the second checkbox — one key as the access " +
        "token's cnf.jkt and " +
    "as the credential's cnf.jwk. credential cnf.jwk=" +
        JSON.stringify(credentialCnf) +
    "  dpop public=" + JSON.stringify(dpopPublic));
  log.debug("Leaving credentialIsBoundToTheDpopKey().");
}

// The consequence of Holder of Key that reaches the OTHER workflow. A wallet
// that reached for the holder key here would produce a presentation the
// verifier refuses, and the complaint would be about the Key Binding JWT's
// signature rather than about the wrong key having been chosen.
async function presentationSideKnowsWhichKey(driver) {
  log.debug("Entering presentationSideKnowsWhichKey().");
  log.info("=== The presentation side, where OpenID4VP has no DPoP ===");
  await driver.get(BASE + "/vc-presentation-2.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("pane_dpop_note")), 20000,
    "presentation step 2 has no Key Binding and DPoP pane");
  await driver.sleep(1200);
  var note = await txt(driver, "vp_dpop_note");
  check("presentation step 2 states that OpenID4VP defines no DPoP",
    /OpenID4VP defines no DPoP/.test(note), note.slice(0, 280));
  check("...and recognises that this credential was issued under Holder of Key",
    /Holder of Key/.test(note),
    "the note is built from the credential in hand, so it should recognise " +
        "that its cnf.jwk is " +
    "this wallet's DPoP key. Note: " + note.slice(0, 320));
  log.debug("Leaving presentationSideKnowsWhichKey().");
}

async function turningItOffDiscardsTheKey(driver) {
  log.debug("Entering turningItOffDiscardsTheKey().");
  log.info("=== Turning DPoP off ===");
  await driver.get(BASE + "/vc-issuance-2.html");
  await pageBundleReady(driver);
  await driver.wait(until.elementLocated(By.id("vc_dpop_enabled")), 20000);
  await driver.sleep(1200);
  await driver.findElement(By.id("vc_dpop_enabled")).click();
  await driver.sleep(1200);
  check("turning DPoP off discards the key pair",
    (await driver.executeScript(
      "return localStorage.getItem('sdjwtvc_dpop_private_jwk');")) === null,
    "the private key survived being switched off — a key nothing will use " +
        "again, which a later " +
    "session could pick up and bind a credential to by accident");
  check("and the jkt display is cleared",
    (await txt(driver, "vc_dpop_jkt")).trim() === "—", await txt(driver,
     "vc_dpop_jkt"));
  log.debug("Leaving turningItOffDiscardsTheKey().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. client=" + BASE + ", sts=" + STS);

  var options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
                       "--disable-dev-shm-usage");
  // Web Crypto and the private-network flags. Every proof on this page is
  // signed with crypto.subtle, which does not exist on the containerized
  // suite's
  // http://client:3000 origin unless that origin is treated as secure — and
  // without the flag the symptom is a timeout waiting for a key pair, naming
  // nothing about crypto. See tests/browser_flags.js.
  browserFlags.addBrowserAccessFlags(options, BASE);
  var driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await driver.manage().window().setRect({ width: 1500, height: 1200 });
    await paneBeforeAnythingIsSent(driver);
    await boundTokenThroughTheOfferFlow(driver);
    await credentialIsBoundToTheDpopKey(driver);
    await presentationSideKnowsWhichKey(driver);
    await turningItOffDiscardsTheKey(driver);
  } finally {
    await driver.quit();
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("dpop_workflow")
  .description("Verify DPoP (RFC 9449) through the VC Issuance pages: the " +
      "pane, the binding, Holder of Key.")
  .addOption(new Option("-u, --url <url>", "base url of the client under test"))
  .parse(process.argv);
const cliOptions = program.opts();
if (cliOptions.url) BASE = String(cliOptions.url).replace(/\/$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
