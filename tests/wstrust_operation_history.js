// File: wstrust_operation_history.js
//
// Operations History pane on the WS-Trust pages (wstrust_tools.html and
// wstrust_response.html) — the WS-Trust counterpart of the SAML log, sharing
// the same store implementation (client/src/op_history.js).
//
// It records every attempted call to the STS with its timestamp, WS-Trust
// version, operation, the user the request was made as, and the result:
//
//   Failure  the request never left the browser, or the STS refused it;
//   Sent     dispatched, no answer rendered yet;
//   Success  the STS answered with a token (Issue/Renew) or a status.
//
// Driven against the WS-Trust STS mock in sts/ (started by the caller, or by
// the compose stack), which returns a SOAP Fault when the password is the
// literal "invalid" — that is how the refusal path is exercised.
//
// run-report spawns this with --url, like every other test here.

const { Builder, By, until } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'wstrust_operation_history',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var headless = true;
var waitTime = appconfig.waitTime;
var callWait = Math.max(waitTime, 20000);

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
  if (text) await el.sendKeys(text);
}
async function selectValue(driver, id, value) {
  await new Select(driver.findElement(By.id(id))).selectByValue(value);
}
function btn(page, fn) {
  return By.xpath("//input[contains(@onclick, \"" + page + "." + fn + "(\")]");
}

// The rendered log, newest first: # | Time | Operation | Version | User | STS | Result
async function historyRows(driver) {
  return driver.executeScript(
    "var rows = document.querySelectorAll('#wst_operation_history tbody tr');" +
    "var out = [];" +
    "for (var i = 0; i < rows.length; i++) {" +
    "  var c = rows[i].getElementsByTagName('td');" +
    "  out.push({ n: c[0].textContent.trim(), time: c[1].textContent.trim()," +
    "             operation: c[2].textContent.trim(), version: c[3].textContent.trim()," +
    "             user: c[4].textContent.trim(), endpoint: c[5].textContent.trim()," +
    "             result: c[6].textContent.trim(), resultClass: c[6].className });" +
    "}" +
    "return out;");
}
async function waitForRows(driver, count, what) {
  await driver.wait(async function () {
    return (await historyRows(driver)).length >= count;
  }, callWait, what);
  return historyRows(driver);
}
async function waitForResult(driver, index, prefix, what) {
  await driver.wait(async function () {
    var rows = await historyRows(driver);
    return rows.length > index && rows[index].result.indexOf(prefix) === 0;
  }, callWait, what);
  return historyRows(driver);
}

async function openTools(driver) {
  await driver.get(baseUrl + "/wstrust_tools.html");
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
}

// A request the STS mock will accept (or refuse, with password "invalid").
async function configureRequest(driver, opts) {
  await selectValue(driver, 'wst_trust_version', opts.version);
  await selectValue(driver, 'wst_operation', opts.operation);
  await setInput(driver, 'wst_sts_url', opts.stsUrl === undefined ? stsUrl : opts.stsUrl);
  await selectValue(driver, 'wst_cred_mode', 'usernametoken');
  await setInput(driver, 'wst_username', opts.user || 'wstrust');
  await setInput(driver, 'wst_password', opts.password || 'wstrust');
  // Call the STS straight from the browser: the mock sends permissive CORS, and
  // this test does not require the API proxy to be up.
  await click(driver, By.id('wst_initiateFromFrontEnd'));
}

async function operationHistoryActivities(driver) {
  await openTools(driver);
  await driver.executeScript("window.localStorage.clear();");
  await openTools(driver);

  // ---- The pane itself ----------------------------------------------------
  log.info("=== Operations History pane ===");
  var empty = await driver.findElement(By.css('#wst_operation_history .saml-history-empty')).getText();
  assert.ok(empty.indexOf('No STS calls recorded') !== -1, "The empty log should say so. Found: " + empty);
  log.info("[pane] OK — present and empty.");

  // ---- Failure before the request leaves the browser ----------------------
  log.info("=== Recording a pre-flight failure ===");
  await configureRequest(driver, { version: '1.3', operation: 'issue', stsUrl: '' });
  await click(driver, btn('wstrust_tools', 'callSts'));
  var rows = await waitForRows(driver, 1, "the failed attempt was not recorded.");
  assert.ok(rows[0].result.indexOf('Failure') === 0, "expected a failure, got: " + rows[0].result);
  assert.ok(rows[0].result.indexOf('no STS endpoint') !== -1, "the reason is missing: " + rows[0].result);
  assert.strictEqual(rows[0].operation, 'Issue', "wrong operation: " + rows[0].operation);
  assert.strictEqual(rows[0].version, '1.3', "wrong WS-Trust version: " + rows[0].version);
  assert.strictEqual(rows[0].user, 'wstrust', "wrong user: " + rows[0].user);
  assert.strictEqual(rows[0].resultClass, 'saml-bad', "a failure should be styled as one.");
  assert.ok(/^\d{4}-\d{2}-\d{2}/.test(rows[0].time), "no timestamp recorded: " + rows[0].time);
  log.info("[failure] OK — recorded with version, operation, user, and reason.");

  // ---- A real Issue against the STS mock: Sent -> Success -----------------
  log.info("=== Issue against the STS (Sent -> Success) ===");
  await configureRequest(driver, { version: '1.4', operation: 'issue', user: 'wstrust' });
  await click(driver, btn('wstrust_tools', 'callSts'));
  // The call navigates to the response page, which resolves the entry.
  await driver.wait(until.urlContains('wstrust_response.html'), callWait,
    "the browser did not land on the response page.");
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  rows = await waitForResult(driver, 0, 'Success', "the Issue was not resolved to Success.");
  assert.strictEqual(rows[0].operation, 'Issue', "wrong operation: " + rows[0].operation);
  assert.strictEqual(rows[0].version, '1.4', "wrong WS-Trust version: " + rows[0].version);
  assert.strictEqual(rows[0].user, 'wstrust', "wrong user: " + rows[0].user);
  assert.ok(rows[0].result.indexOf('token issued') !== -1,
    "the success detail should say a token came back: " + rows[0].result);
  assert.strictEqual(rows[0].resultClass, 'saml-ok', "a success should be styled as one.");
  assert.strictEqual(rows.length, 2, "expected 2 entries, got " + rows.length);
  log.info("[issue] OK — dispatched as Sent and resolved to Success on the response page.");

  // The response page shows the same shared log.
  var respRows = await historyRows(driver);
  assert.strictEqual(respRows.length, 2, "the response page should show the shared log.");
  log.info("[response page] OK — carries the same log.");

  // ---- A refused Issue: Sent -> Failure with the SOAP Fault ---------------
  log.info("=== Refused Issue (Sent -> Failure) ===");
  await openTools(driver);
  await configureRequest(driver, { version: '1.4', operation: 'issue', user: 'wstrust', password: 'invalid' });
  await click(driver, btn('wstrust_tools', 'callSts'));
  await driver.wait(until.urlContains('wstrust_response.html'), callWait,
    "the browser did not land on the response page for the refused call.");
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  rows = await waitForResult(driver, 0, 'Failure', "the refused Issue was not resolved to Failure.");
  assert.ok(rows[0].result.indexOf('SOAP Fault') !== -1,
    "the STS's fault should be recorded: " + rows[0].result);
  assert.strictEqual(rows[0].resultClass, 'saml-bad', "a refusal should be styled as a failure.");
  assert.strictEqual(rows.length, 3, "resolving must update the entry, not append one.");
  assert.ok(rows[1].result.indexOf('Success') === 0,
    "resolving must not disturb the earlier entry: " + rows[1].result);
  log.info("[refusal] OK — a SOAP Fault is recorded as a Failure with its reason.");

  // Redisplaying the same exchange must not resolve anything again.
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id('pane_history')), waitTime);
  var again = await waitForRows(driver, 3, "the log vanished on reload.");
  assert.strictEqual(again.map(function (r) { return r.result; }).join('|'),
    rows.map(function (r) { return r.result; }).join('|'),
    "redisplaying a stored exchange must not re-resolve the log.");
  log.info("[idempotence] OK — a redisplayed exchange resolves nothing further.");

  // ---- Clearing is shared across both pages -------------------------------
  await click(driver, btn('wstrust_response', 'clearOperationHistory'));
  await driver.wait(async function () {
    return (await historyRows(driver)).length === 0;
  }, waitTime, "Clear History did not empty the pane on the response page.");
  await openTools(driver);
  assert.strictEqual((await historyRows(driver)).length, 0,
    "clearing on the response page should clear the shared log.");
  log.info("[clear] OK — Clear History clears the log for both pages.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) options.addArguments("--headless=new");
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + baseUrl.replace(/\/+$/, ""));
  options.addArguments("--user-data-dir=/tmp/wstrust-history-chrome-" + Date.now());
  const driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();

  try {
    log.info("Starting Test run. STS=" + stsUrl);
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
  .name('wstrust_operation_history')
  .description("Run the WS-Trust Operations History UI test (needs the STS mock).")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) { log.info("Setting url to " + options.url); baseUrl = options.url; }
    if (!!options.browser) { log.info("Using browser. headless = false."); headless = false; }
  });
program.parse(process.argv).opts();

test();
