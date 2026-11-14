// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: gnap_page.js
//
// ---------------------------------------------------------------------------
// THE GNAP PAGE, DRIVEN IN CHROME against iya-sts through the api. Every
// button a person presses for a grant's whole life is pressed here, and
// every request goes through POST /gnap/call:
//
//   1. discovery, a generated key, and the default sample (subject
//      information) granted with no administrator involved, then the
//      grant revoked;
//   2. the SSF sample refused as a protected scope, the scope declared
//      on the key's application through /admin-api, and the grant
//      issued;
//   3. the interaction: the page's redirect link opened, the person
//      signed in at iya-sts and pressed Allow, and the browser sent back
//      to gnap.html, where the page checks the interaction hash itself;
//   4. Continue (past too_fast) to an access token with a management
//      URI, and the token used at iya-sts's Shared Signals transmitter
//      from the Signed call pane;
//   5. Rotate the access token, Rotate the client key, each followed by
//      a call that works; Revoke the access token, after which the call
//      is refused; Revoke grant;
//   6. mtls: a certificate pasted, the default sample granted with the
//      api presenting it; refused on the browser path, as it must be;
//   7. the save box: cleared, neither private key is left in storage.
//
// iya-sts must be in development mode; in product mode the job fails
// and says why.
// ---------------------------------------------------------------------------
"use strict";

const assert = require("assert");
const webdriver = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { mustBeAbleTo } = require("./expectation.js");
const live = require("./gnap_live.js");
const { loadUrl } = require("./page_load.js");
const By = webdriver.By;

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "gnap_page",
  level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var apiUrl = process.env.API_URL || "https://localhost:4000";
var stsUrl = String(process.env.GNAP_AS_URL || process.env.STS_URL ||
  "https://localhost:8081").replace(/\/+$/, "").replace(/\/sts$/, "");
var insecure = process.env.GNAP_TLS_INSECURE === "1";

const WAIT = 20000;
const declared = [];

async function fill(driver, id, value) {
  log.debug("Entering fill(). " + id);
  const field = await driver.findElement(By.id(id));
  await field.clear();
  if (value) {
    // A long PEM through sendKeys is slow and lossy on newlines in
    // some drivers; the value is set the way a paste sets it.
    await driver.executeScript("arguments[0].value = arguments[1];",
      field, value);
  }
  log.debug("Leaving fill().");
}

async function click(driver, id) {
  log.debug("Entering click(). " + id);
  const button = await driver.findElement(By.id(id));
  await driver.executeScript("arguments[0].scrollIntoView();", button);
  await button.click();
  log.debug("Leaving click().");
}

async function valueOf(driver, id) {
  log.debug("Entering valueOf(). " + id);
  const value = await driver.findElement(By.id(id))
    .getAttribute("value");
  log.debug("Leaving valueOf().");
  return value || "";
}

// The status line is where every button reports. Waits for it to match,
// and fails with what it says instead.
async function statusMatches(driver, pattern, what) {
  log.debug("Entering statusMatches(). " + what);
  let last = "";
  try {
    await driver.wait(async function () {
      last = await driver.findElement(By.id("gnap_status")).getText();
      return pattern.test(last);
    }, WAIT);
  } catch (e) {
    const response = await valueOf(driver, "gnap_response");
    throw new Error(what + ": the status line says \"" + last +
      "\" and the response box holds " + response.slice(0, 600));
  }
  log.debug("Leaving statusMatches(). " + last);
  return last;
}

// Click, then wait for a status that is NEW and matches.
async function press(driver, id, pattern, what) {
  log.debug("Entering press(). " + id);
  await driver.executeScript(
    "document.getElementById('gnap_status').textContent = '';");
  await click(driver, id);
  const said = await statusMatches(driver, pattern, what);
  log.debug("Leaving press().");
  return said;
}

async function responseJson(driver) {
  log.debug("Entering responseJson().");
  const text = await valueOf(driver, "gnap_response");
  const body = text.replace(/^HTTP \d*\n/, "");
  let parsed = null;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    parsed = null;
  }
  log.debug("Leaving responseJson().");
  return { text: text, json: parsed };
}

async function openFresh(driver) {
  log.debug("Entering openFresh().");
  await loadUrl(driver, baseUrl + "/gnap.html");
  await driver.executeScript("localStorage.removeItem('gnap_state');" +
    "localStorage.removeItem('gnap_private_jwk');" +
    "localStorage.removeItem('gnap_mtls_key');");
  await loadUrl(driver, baseUrl + "/gnap.html");
  await driver.wait(async function () {
    return driver.executeScript("return typeof window.gnap === " +
      "'object' && typeof window.gnap.sendGrant === 'function';");
  }, WAIT, "the gnap bundle did not load");
  await fill(driver, "gnap_api", apiUrl);
  await fill(driver, "gnap_grant", stsUrl + "/gnap");
  const box = await driver.findElement(By.id("gnap_insecure"));
  if ((await box.isSelected()) !== insecure) {
    await box.click();
  }
  log.debug("Leaving openFresh().");
}

async function theSubjectSampleIsGranted(driver) {
  log.info("[1] discovery, a key, and the default sample");
  await press(driver, "gnap_discover", /Discovery answered HTTP 200/,
    "discovery through the api");
  await press(driver, "gnap_generate", /Generated a ES256 key/,
    "generating a key");
  await press(driver, "gnap_fill_sample", /subject information/,
    "filling the default sample");
  const request = JSON.parse(await valueOf(driver, "gnap_request"));
  assert.strictEqual(request.access_token, undefined,
    "the default sample should ask for no access token");
  const said = await press(driver, "gnap_send",
    /Grant response HTTP|refused the grant/, "sending the default sample");
  if (/product mode/.test((await responseJson(driver)).text)) {
    throw new Error("iya-sts is in product mode and refuses the page's " +
      "new key. Run against development mode.");
  }
  assert.ok(/Grant response HTTP 200/.test(said), said);
  const grant = (await responseJson(driver)).json;
  assert.ok(grant && grant.continue && grant.interact,
    "the grant has no continuation or interaction");
  assert.ok(await valueOf(driver, "gnap_continue_uri"),
    "the page did not keep the continuation URI");
  await press(driver, "gnap_revoke_grant",
    /Revocation answered HTTP 204/, "revoking the subject grant");
  log.info("[1] OK — iya-sts granted the default sample with nobody " +
    "declaring anything, and the grant was revoked.");
}

async function theSsfGrantIsIssuedAndApproved(driver) {
  log.info("[2] the SSF sample, the protected scope, and the approval");
  const publicJwk = JSON.parse(await valueOf(driver, "gnap_public"));
  const application = live.applicationFor({ publicJwk: publicJwk });
  await press(driver, "gnap_fill_ssf_sample", /ssf\.read/,
    "filling the SSF sample");
  const refused = await press(driver, "gnap_send", /refused the grant/,
    "sending the SSF sample before the scope is declared");
  assert.ok(/request_denied/.test(refused), refused);
  assert.ok((await responseJson(driver)).text.indexOf(application) >= 0,
    "the refusal does not name " + application);
  await live.declareSsfRead(stsUrl, application);
  declared.push(application);
  await press(driver, "gnap_send", /Grant response HTTP 200/,
    "sending the SSF sample after the scope is declared");
  const href = await driver.findElement(By.id("gnap_redirect"))
    .getAttribute("href");
  assert.ok(/^https:\/\//.test(href || ""),
    "the page drew no interaction link");
  log.info("[2] following the page's interaction link: " + href);
  await live.approveInBrowser(driver, webdriver, href,
    baseUrl + "/gnap.html", "gnap-page", WAIT);
  await statusMatches(driver, /The interaction hash matches\./,
    "the page checking the finish redirect's hash");
  assert.ok(await valueOf(driver, "gnap_interact_ref"),
    "the page did not read interact_ref from the finish redirect");
  log.info("[2] OK — approved, and the page checked the hash.");
}

async function theTokenIsIssuedUsedAndManaged(driver) {
  log.info("[3] continue, use, rotate, revoke");
  let i;
  for (i = 0; i < 6 && !(await valueOf(driver, "gnap_token")); i++) {
    await driver.sleep(5500);
    await press(driver, "gnap_continue",
      /Continuation HTTP 200|too_fast/, "continuing");
  }
  const first = await valueOf(driver, "gnap_token");
  assert.ok(first, "no access token after continuing");
  assert.ok(await valueOf(driver, "gnap_manage_uri"),
    "no management URI");
  await press(driver, "gnap_fill_resource", /Shared Signals/,
    "filling the Shared Signals call");
  await press(driver, "gnap_send_call", /Call answered HTTP 200/,
    "using the token at the transmitter");

  await press(driver, "gnap_rotate_token", /Rotated the access token/,
    "rotating the access token");
  const second = await valueOf(driver, "gnap_token");
  assert.notStrictEqual(second, first, "the token value did not change");
  await fill(driver, "gnap_call_token", first);
  await press(driver, "gnap_send_call", /Call answered HTTP 401/,
    "using the rotated-away value");
  await press(driver, "gnap_fill_resource", /Shared Signals/,
    "refilling the call");
  await press(driver, "gnap_send_call", /Call answered HTTP 200/,
    "using the new value");

  const before = await valueOf(driver, "gnap_public");
  await press(driver, "gnap_rotate_key", /Rotated the client key/,
    "rotating the client key");
  assert.notStrictEqual(await valueOf(driver, "gnap_public"), before,
    "the page still shows the old key");
  await press(driver, "gnap_fill_resource", /Shared Signals/,
    "refilling the call after key rotation");
  await press(driver, "gnap_send_call", /Call answered HTTP 200/,
    "using the token with the new key");

  const last = await valueOf(driver, "gnap_token");
  await press(driver, "gnap_revoke_token",
    /Revoked the access token\. HTTP 204/, "revoking the access token");
  await fill(driver, "gnap_call_token", last);
  await press(driver, "gnap_send_call", /Call answered HTTP 401/,
    "using the revoked token");
  await press(driver, "gnap_revoke_grant",
    /Revocation answered HTTP 204/, "revoking the SSF grant");
  log.info("[3] OK — the token worked, rotated, survived a key " +
    "rotation and died when revoked.");
}

async function mtlsGoesThroughTheApi(driver) {
  log.info("[4] mtls");
  const pair = live.makeClientCertificate("gnap-page-mtls");
  const proof = await driver.findElement(By.id("gnap_proof"));
  await proof.findElement(By.css("option[value='mtls']")).click();
  await fill(driver, "gnap_mtls_cert", pair.certificatePem);
  await fill(driver, "gnap_mtls_key", pair.keyPem);
  await press(driver, "gnap_fill_sample", /subject information/,
    "filling the default sample for mtls");
  const via = await driver.findElement(By.id("gnap_via"));
  await via.findElement(By.css("option[value='browser']")).click();
  await press(driver, "gnap_send", /through the API/,
    "sending mtls from the browser");
  await via.findElement(By.css("option[value='api']")).click();
  await press(driver, "gnap_send", /Grant response HTTP 200/,
    "sending mtls through the api");
  const body = JSON.parse((await valueOf(driver, "gnap_signed"))
    .split("\n\n").slice(1).join("\n\n"));
  assert.strictEqual(body.client.key.proof, "mtls");
  assert.ok(pair.certificatePem.replace(/\s+/g, "")
    .indexOf(body.client.key.cert) >= 0,
    "the request does not carry the pasted certificate");
  await press(driver, "gnap_revoke_grant",
    /Revocation answered HTTP 204/, "revoking the mtls grant");
  log.info("[4] OK — the api presented the certificate.");
}

async function theSaveBoxRemovesBothKeys(driver) {
  log.info("[5] the save box");
  const stored = await driver.executeScript("return [" +
    "localStorage.getItem('gnap_private_jwk')," +
    "localStorage.getItem('gnap_mtls_key')];");
  assert.ok(stored[0] && stored[1], "both private keys should be " +
    "stored while the box is ticked");
  await click(driver, "gnap_save_keypair");
  await statusMatches(driver, /removed/, "clearing the save box");
  const after = await driver.executeScript("return [" +
    "localStorage.getItem('gnap_private_jwk')," +
    "localStorage.getItem('gnap_mtls_key')];");
  assert.deepStrictEqual(after, [null, null],
    "a private key is still in storage after the box was cleared");
  await click(driver, "gnap_save_keypair");
  log.info("[5] OK.");
}

async function preconditions() {
  log.debug("Entering preconditions().");
  const ok = async function (url) {
    log.debug("Entering ok(). " + url);
    const answer = await fetch(url).then(function (r) {
      return r.status < 500;
    }).catch(function () {
      return false;
    });
    log.debug("Leaving ok().");
    return answer;
  };
  const ready = await ok(baseUrl + "/gnap.html") &&
    await ok(apiUrl + "/gnap/limits");
  log.debug("Leaving preconditions(). " + ready);
  return ready;
}

async function test() {
  log.debug("Entering test().");
  mustBeAbleTo(await preconditions(), "The client and the api this job " +
    "was pointed at,", baseUrl + "/gnap.html and " + apiUrl +
    "/gnap/limits, did not both answer. Start the stack, or set --url " +
    "and API_URL to ones that do.");
  log.info("driving " + baseUrl + "/gnap.html through " + apiUrl +
    " against " + stsUrl);
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
    "--disable-dev-shm-usage", "--window-size=1400,2000");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new webdriver.Builder().forBrowser("chrome")
    .setChromeOptions(options).build();
  try {
    await openFresh(driver);
    await theSubjectSampleIsGranted(driver);
    await theSsfGrantIsIssuedAndApproved(driver);
    await theTokenIsIssuedUsedAndManaged(driver);
    await mtlsGoesThroughTheApi(driver);
    await theSaveBoxRemovesBothKeys(driver);
    log.info("Test completed successfully.");
  } finally {
    let i;
    for (i = 0; i < declared.length; i++) {
      await live.forgetApplication(stsUrl, declared[i]);
    }
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("gnap_page")
  .description("Drive gnap.html through a grant's whole life against " +
    "iya-sts, through the api.")
  .addOption(new Option("-u, --url <url>",
    "base url of the site under test").default(baseUrl))
  .parse(process.argv);
baseUrl = program.opts().url || baseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
