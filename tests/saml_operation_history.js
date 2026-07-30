// File: saml_operation_history.js
//
// Operations History pane on the SAML request page (saml_request.html) — the
// SAML counterpart of the Operation History pane on debugger2.html.
//
// It records every attempted call to the IdP with its timestamp, binding, SAML
// version, both entity IDs, and the result — Failure (never left the browser,
// or refused by the IdP), Sent (dispatched, no answer yet), or Success (the IdP
// answered with a Success status). Critically, a dispatch is NOT a success: a
// request sent to an endpoint that rejects it must not be logged as one.
//
// No IdP is needed: the pre-dispatch failures come from the page's own checks,
// the dispatch aims at a URL on the test server, and the resolution is driven by
// handing the SAML Response page a crafted SAMLResponse. The full round-trip
// against Keycloak is covered by saml_sso.js.
//
// run-report spawns this with --url, like every other test here.

const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_operation_history',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
// Signing an AuthnRequest is pure-JS RSA; give it room on a busy host.
var cryptoWait = Math.max(waitTime, 20000);

async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", el);
  await el.click();
}
async function setInput(driver, id, text) {
  var el = driver.findElement(By.id(id));
  await el.clear();
  await el.sendKeys(text);
}
async function selectValue(driver, id, value) {
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
}
function btn(fn) {
  return By.xpath("//input[contains(@onclick, \"saml_request." + fn + "(\")]");
}

// The rendered history, newest first, as objects.
async function historyRows(driver) {
  return driver.executeScript(
    "var rows = document.querySelectorAll('#saml_operation_history tbody tr');" +
    "var out = [];" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var c = rows[i].getElementsByTagName('td');" +
    "  out.push({ n: c[0].textContent.trim(), time: c[1].textContent.trim()," +
    "             operation: c[2].textContent.trim(), binding: c[3].textContent.trim()," +
    "             version: c[4].textContent.trim(), sp: c[5].textContent.trim()," +
    "             idp: c[6].textContent.trim(), result: c[7].textContent.trim()," +
    "             resultClass: c[7].className });" +
    "}" +
    "return out;");
}
async function waitForRows(driver, count, what) {
  await driver.wait(async function () {
    return (await historyRows(driver)).length >= count;
  }, cryptoWait, what);
  return historyRows(driver);
}

// Crafted IdP answers. decodeSamlParam() falls back to treating the base64 as a
// raw (POST-binding) message when it is not deflated, so plain base64 is enough.
function b64(xml) { return Buffer.from(xml, 'utf8').toString('base64'); }
const RESP_OPEN = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
  ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_hist1" Version="2.0"' +
  ' IssueInstant="2026-01-01T00:00:00Z">' +
  '<saml:Issuer>https://history-test.example.com/idp</saml:Issuer>';
const DENIED_RESPONSE_B64 = b64(RESP_OPEN +
  '<samlp:Status>' +
  '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">' +
  '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/>' +
  '</samlp:StatusCode>' +
  '<samlp:StatusMessage>invalid_signature</samlp:StatusMessage>' +
  '</samlp:Status></samlp:Response>');
const SUCCESS_RESPONSE_B64 = b64(RESP_OPEN +
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
  '</samlp:Response>');

async function openPage(driver) {
  await driver.get(baseUrl + "/saml_request.html");
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
}

async function operationHistoryActivities(driver) {
  // Clean slate: the page persists both its configuration and the history.
  await openPage(driver);
  await driver.executeScript("window.localStorage.clear();");
  await openPage(driver);

  // ---- The pane itself ---------------------------------------------------
  log.info("=== Operations History pane ===");
  var empty = await driver.findElement(By.css('#saml_operation_history .saml-history-empty')).getText();
  assert.ok(empty.indexOf('No IdP calls recorded') !== -1,
    "The empty history should say so. Found: " + empty);
  // It sits below the Tools pane, outside the three-column grid.
  var order = await driver.executeScript(
    "var t = document.getElementById('pane_tools'), h = document.getElementById('pane_history');" +
    "return { after: !!(t.compareDocumentPosition(h) & Node.DOCUMENT_POSITION_FOLLOWING)," +
    "         inCols: !!h.closest('.saml-cols') };");
  assert.ok(order.after, "The Operations History pane must come after the Tools pane.");
  assert.ok(!order.inCols, "The Operations History pane should span the page, below the columns.");
  log.info("[pane] OK — present, empty, and positioned below Tools.");

  // ---- Failure: SAML 1.x cannot be sent -----------------------------------
  log.info("=== Recording failures ===");
  await selectValue(driver, 'saml_version', '1.1');
  await click(driver, btn('callIdp'));
  var rows = await waitForRows(driver, 1, "the SAML 1.1 send attempt was not recorded.");
  assert.strictEqual(rows[0].operation, 'Send AuthnRequest', "wrong operation recorded: " + rows[0].operation);
  assert.strictEqual(rows[0].version, '1.1', "the SAML version was not recorded: " + rows[0].version);
  assert.ok(rows[0].result.indexOf('Failure') === 0, "expected a failure, got: " + rows[0].result);
  assert.ok(rows[0].result.indexOf('IdP-initiated') !== -1, "the reason is missing: " + rows[0].result);
  assert.strictEqual(rows[0].resultClass, 'saml-bad', "a failure should be styled as one.");
  assert.ok(/^\d{4}-\d{2}-\d{2}/.test(rows[0].time), "no timestamp recorded: " + rows[0].time);

  // ---- Failure: no SLO endpoint / no prior login --------------------------
  await selectValue(driver, 'saml_version', '2.0');
  await click(driver, btn('singleLogout'));
  rows = await waitForRows(driver, 2, "the Single Logout attempt was not recorded.");
  assert.strictEqual(rows[0].operation, 'Single Logout', "wrong operation recorded: " + rows[0].operation);
  assert.ok(rows[0].result.indexOf('Failure') === 0, "expected a failure, got: " + rows[0].result);
  assert.ok(rows[0].binding === 'HTTP-Redirect' || rows[0].binding === 'HTTP-POST',
    "Single Logout should record the binding it would use: " + rows[0].binding);

  // ---- Failure: metadata load that cannot resolve -------------------------
  await setInput(driver, 'saml_metadata_url', baseUrl + '/no-such-metadata.xml');
  await click(driver, btn('loadMetadata'));
  rows = await waitForRows(driver, 3, "the metadata load failure was not recorded.");
  assert.strictEqual(rows[0].operation, 'Load IdP Metadata', "wrong operation recorded: " + rows[0].operation);
  assert.ok(rows[0].result.indexOf('Failure') === 0, "expected a failure, got: " + rows[0].result);
  assert.strictEqual(rows[0].binding, '—', "a metadata load has no protocol binding: " + rows[0].binding);
  log.info("[failures] OK — 3 failed attempts recorded with their reasons.");

  // ---- Success: a dispatched AuthnRequest ---------------------------------
  // Point the Redirect SSO endpoint at a page on this server: the browser is
  // handed over exactly as it would be to an IdP, and the entry must already be
  // written when it leaves.
  log.info("=== Recording a dispatched AuthnRequest ===");
  var ssoUrl = baseUrl + '/saml_response.html';
  var spEntityId = 'https://history-test.example.com/sp';
  var idpEntityId = 'https://history-test.example.com/idp';
  await selectValue(driver, 'saml_binding', 'redirect');
  await setInput(driver, 'saml_sso_redirect', ssoUrl);
  await setInput(driver, 'saml_sp_entity_id', spEntityId);
  await setInput(driver, 'saml_idp_entity_id', idpEntityId);
  // Unsigned, so no key generation is needed for the dispatch.
  var signBox = driver.findElement(By.id('saml_sign_request'));
  if (await signBox.isSelected()) await click(driver, By.id('saml_sign_request'));

  await click(driver, btn('callIdp'));
  await driver.wait(until.urlContains('SAMLRequest='), cryptoWait,
    "the browser was not handed over to the (stand-in) IdP endpoint.");
  log.info("[dispatch] OK — redirected to the IdP with a SAMLRequest.");

  // Back on the page, the dispatch must be in the history.
  await openPage(driver);
  rows = await waitForRows(driver, 4, "the dispatched AuthnRequest was not recorded.");
  var sent = rows[0];
  assert.strictEqual(sent.operation, 'Send AuthnRequest', "wrong operation: " + sent.operation);
  assert.strictEqual(sent.binding, 'HTTP-Redirect', "wrong binding: " + sent.binding);
  assert.strictEqual(sent.version, '2.0', "wrong version: " + sent.version);
  assert.strictEqual(sent.sp, spEntityId, "wrong SP entityID: " + sent.sp);
  assert.strictEqual(sent.idp, idpEntityId, "wrong IdP entityID: " + sent.idp);
  assert.ok(sent.result.indexOf('Sent') === 0,
    "a dispatched request must be recorded as Sent, not as a success: " + sent.result);
  assert.ok(sent.result.indexOf(ssoUrl) !== -1, "the destination should be noted: " + sent.result);
  assert.strictEqual(sent.resultClass, 'saml-pending', "a pending dispatch should be styled as pending.");
  assert.strictEqual(sent.n, '4', "entries should be numbered in the order they happened: " + sent.n);
  log.info("[history] OK — the dispatch survived the navigation, recorded as Sent (not Success).");

  // ---- The IdP's answer resolves the pending entry ------------------------
  // A non-Success StatusCode must turn the dispatch into a Failure — this is
  // the case a "the request was sent" log gets wrong.
  log.info("=== Resolving a dispatch from the IdP's answer ===");
  await driver.get(baseUrl + '/saml_response.html?SAMLResponse=' + encodeURIComponent(DENIED_RESPONSE_B64));
  await driver.wait(until.elementLocated(By.id('saml_resp_status')), waitTime);
  await driver.sleep(400);
  await openPage(driver);
  rows = await waitForRows(driver, 4, "the history disappeared after the response.");
  var denied = rows[0];
  assert.ok(denied.result.indexOf('Failure') === 0,
    "a refused AuthnRequest must be recorded as a Failure, got: " + denied.result);
  assert.ok(denied.result.indexOf('Responder') !== -1 && denied.result.indexOf('RequestDenied') !== -1,
    "the IdP's status codes should be recorded: " + denied.result);
  assert.ok(denied.result.indexOf('invalid_signature') !== -1,
    "the IdP's StatusMessage should be recorded: " + denied.result);
  assert.strictEqual(denied.resultClass, 'saml-bad', "a refusal should be styled as a failure.");
  assert.strictEqual(rows.length, 4, "resolving must update the entry, not append one.");
  log.info("[resolve] OK — a refused request is recorded as a Failure with the IdP's status.");

  // And a Success status resolves to Success.
  await openPage(driver);
  await click(driver, btn('callIdp'));
  await driver.wait(until.urlContains('SAMLRequest='), cryptoWait, "the second dispatch did not leave.");
  await driver.get(baseUrl + '/saml_response.html?SAMLResponse=' + encodeURIComponent(SUCCESS_RESPONSE_B64));
  await driver.wait(until.elementLocated(By.id('saml_resp_status')), waitTime);
  await driver.sleep(400);
  await openPage(driver);
  rows = await waitForRows(driver, 5, "the second dispatch was not recorded.");
  assert.ok(rows[0].result.indexOf('Success') === 0,
    "a Success status should resolve the dispatch as a success: " + rows[0].result);
  assert.strictEqual(rows[0].resultClass, 'saml-ok', "a success should be styled as one.");
  assert.ok(rows[1].result.indexOf('Failure') === 0,
    "resolving the newest pending entry must not disturb the earlier one: " + rows[1].result);
  log.info("[resolve] OK — a Success status closes the dispatch as a success.");

  // ---- Ordering + persistence + clearing ----------------------------------
  var times = rows.map(function (r) { return r.time; });
  assert.strictEqual(rows.length, 5, "expected exactly 5 entries, got " + rows.length);
  assert.ok(times[0] >= times[times.length - 1], "the history should be newest-first.");

  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  rows = await waitForRows(driver, 5, "the history did not survive a reload.");
  log.info("[persistence] OK — " + rows.length + " entries survived a reload.");

  // ---- The same pane on the SAML Response page ---------------------------
  log.info("=== Operations History on the SAML Response page ===");
  await driver.get(baseUrl + '/saml_response.html');
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  var respRows = await waitForRows(driver, 5, "the response page does not show the shared log.");
  assert.strictEqual(respRows.length, rows.length,
    "both pages should show the same log: " + respRows.length + " vs " + rows.length);
  assert.strictEqual(respRows[0].result, rows[0].result,
    "the newest entry should read the same on both pages.");
  // It sits below the Tools pane here too.
  var respOrder = await driver.executeScript(
    "var t = document.getElementById('pane_tools'), h = document.getElementById('pane_history');" +
    "return !!(t.compareDocumentPosition(h) & Node.DOCUMENT_POSITION_FOLLOWING);");
  assert.ok(respOrder, "the Operations History pane must come after the Tools pane here as well.");

  // Landing here with no response must NOT touch the log (it repopulates from
  // the cached response, which says nothing about any pending call).
  var beforeReload = respRows.map(function (r) { return r.result; }).join('|');
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  respRows = await waitForRows(driver, 5, "the log vanished on the response page.");
  assert.strictEqual(respRows.map(function (r) { return r.result; }).join('|'), beforeReload,
    "redisplaying a cached response must not re-resolve the log.");
  log.info("[response page] OK — same log, same results, below Tools.");

  // Clearing from the response page empties it for the request page too.
  await click(driver, By.xpath("//input[contains(@onclick, \"saml_response.clearOperationHistory(\")]"));
  await driver.wait(async function () {
    return (await historyRows(driver)).length === 0;
  }, waitTime, "Clear History did not empty the pane on the response page.");
  await openPage(driver);
  assert.strictEqual((await historyRows(driver)).length, 0,
    "clearing on the response page should clear the shared log.");
  log.info("[response page] OK — Clear History clears the shared log.");

  // Re-record one entry so the request page's own Clear History is exercised.
  await selectValue(driver, 'saml_version', '1.1');
  await click(driver, btn('callIdp'));
  await waitForRows(driver, 1, "could not re-record an entry.");
  await selectValue(driver, 'saml_version', '2.0');

  await click(driver, btn('clearOperationHistory'));
  await driver.wait(async function () {
    return (await historyRows(driver)).length === 0;
  }, waitTime, "Clear History did not empty the pane.");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  assert.strictEqual((await historyRows(driver)).length, 0, "the cleared history came back after a reload.");
  log.info("[clear] OK — Clear History empties it for good.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + baseUrl.replace(/\/+$/, ""));
  options.addArguments("--user-data-dir=/tmp/saml-history-chrome-" + Date.now());
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run.");
    await driver.manage().deleteAllCookies();
    await operationHistoryActivities(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program
  .name('saml_operation_history')
  .description("Run the SAML Operations History UI test (no IdP required).")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
