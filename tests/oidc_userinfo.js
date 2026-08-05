// File: oidc_userinfo.js
//
// The UserInfo endpoint (OIDC Core section 5.3) reached the way a user reaches
// it: through the three "UserInfo Data" links debugger2.html puts on its three
// token sets. Tokens come from the OIDC Authorization Code flow, then:
//
//   1. Token Endpoint Results          — the set the flow produced
//   2. Token Endpoint Results for      — the set the most recent refresh call
//      Refresh Token Call                produced
//   3. Currently Viewing               — the set selected from Token History
//
// For each: click its UserInfo Data link, press Retrieve UserInfo on the page it
// lands on WITHOUT touching the configuration, check the response describes the
// user who signed in, and come back with "Return to debugger".
//
// WHY THREE, when one call to one endpoint would prove the endpoint works. The
// three links do not differ in what they call — they differ in WHICH ACCESS
// TOKEN they carry (`?type=token_access_token`, `?type=refresh_access_token`,
// `?type=history_access&generation=N`), and the interesting failure is a link
// that carries the wrong one. That failure is invisible in the response: every
// token here belongs to the same user, so all three answers look identical and
// correct. This test therefore reads the access token the userinfo page loaded
// and requires it to be the one from the pane the link was in — which is the
// only way the refresh link carrying the stale pre-refresh token, or the history
// link carrying the live token instead of the generation it names, would show up.
//
// "Use the default configuration" is asserted rather than assumed, and the
// default is the API (back-end) — so this job needs the api service, as a user
// pressing that button with an untouched page does. The markup reads the other
// way and is worth knowing about: the front-end radio carries checked="true" and
// the back-end one checked="false", but `checked="false"` is still the attribute
// being PRESENT, so both are checked in the source and the last of two radios
// sharing a name wins. The effective default therefore matches every other
// initiation pane in the debugger; the front-end checked="true" is dead intent.
//
// OP-agnostic, like tests/oidc_flows.js: everything server-specific arrives in
// the environment, so the same script runs against the mock STS and Keycloak.

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
const browserFlags = require("./browser_flags.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oidc_userinfo',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata } = require("../common/tests.js")({ By, until, Select, waitTime, log, assert });

const FLOW_LABEL = "OIDC Authorization Code Flow(code)";

// The three token sets, in the order the page produces them. `pane` is the
// container the link must live in — checked, because "the link exists somewhere
// on the page" would pass if all three ended up in one pane.
const SOURCES = [
  {
    name: "Token Endpoint Results",
    pane: "token_endpoint_result",
    link: 'a[href="/userinfo.html?type=token_access_token"]',
    accessTokenField: "token_access_token",
    idTokenField: "token_id_token",
  },
  {
    name: "Token Endpoint Results for Refresh Token Call",
    pane: "refresh_endpoint_result",
    link: 'a[href="/userinfo.html?type=refresh_access_token"]',
    accessTokenField: "refresh_access_token",
    idTokenField: "refresh_id_token",
  },
  {
    name: "Currently Viewing",
    pane: "currently-viewing-panel",
    link: 'a[href^="/userinfo.html?type=history_access"]',
    accessTokenField: "cv_access_token",
    idTokenField: "cv_id_token",
  },
];

function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function claimsOf(token) {
  const parts = String(token).split(".");
  assert.strictEqual(parts.length, 3, "Expected a three-part JWS, got " + parts.length + " part(s).");
  return JSON.parse(b64uDecode(parts[1]).toString("utf8"));
}

async function valueOf(driver, id) {
  const found = await driver.findElements(By.id(id));
  if (!found.length) return null;
  return await found[0].getAttribute("value");
}

// ---------------------------------------------------------------------------
// Tokens, through the Authorization Code flow.
// ---------------------------------------------------------------------------
async function obtainTokens(driver, { clientId, scope, user }) {
  log.info("Entering obtainTokens().");
  // NO driver.get() here. The caller has just run discovery, and Populate fills
  // the FIELDS — storage is only written later, when something calls
  // writeValuesToLocalStorage() (Authorize, or a link click). So reloading
  // debugger.html at this point repopulates every field FROM STORAGE, quietly
  // restoring the seeded placeholders (`https://localhost/oidc/...`) over what
  // discovery just found. The symptom is three pages away: the UserInfo page
  // shows the placeholder endpoint and the call goes nowhere.
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")), waitTime * 3);
  // The Configuration Parameters pane auto-collapses once discovery has run, so
  // the dropdown can be present and invisible. Expand only when it is.
  if (!(await driver.findElement(By.id("authorization_grant_type")).isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(By.id("authorization_grant_type"))), waitTime);
  }
  await new Select(await driver.findElement(By.id("authorization_grant_type")))
    .selectByVisibleText(FLOW_LABEL);

  await driver.wait(until.elementLocated(By.id("client_id")), waitTime);
  if (!(await driver.findElement(By.id("client_id")).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(By.id("client_id"))), waitTime);
  await driver.findElement(By.id("client_id")).clear();
  await driver.findElement(By.id("client_id")).sendKeys(clientId);
  await driver.findElement(By.id("scope")).clear();
  await driver.findElement(By.id("scope")).sendKeys(scope);
  await driver.findElement(By.id("redirect_uri")).clear();
  await driver.findElement(By.id("redirect_uri")).sendKeys(baseUrl + "/callback");
  await driver.findElement(By.css("input[type=\"submit\"][value=\"Authorize\"]")).click();

  // The OP may already have a session, in which case it answers straight away.
  await driver.wait(async function () {
    if ((await driver.getCurrentUrl()).indexOf("/debugger2.html") >= 0) return true;
    return (await driver.findElements(By.id("username"))).length > 0;
  }, waitTime * 4, "Neither the OP's login screen nor a return to debugger2.html arrived.");
  if ((await driver.findElements(By.id("username"))).length) {
    await driver.findElement(By.id("username")).clear();
    await driver.findElement(By.id("username")).sendKeys(user);
    const pw = await driver.findElements(By.id("password"));
    if (pw.length) await pw[0].sendKeys(user);
    await driver.findElement(By.id("kc-login")).click();
  }
  await driver.wait(until.urlContains("/debugger2.html"), waitTime * 5);

  // Browser-direct, so this job needs the client and the OP and nothing else.
  // (It is the Token Request that is switched here, not the UserInfo call — that
  // one is left at its own default, which is the point of the test.)
  await driver.wait(until.elementLocated(By.id("token_initiateFromFrontEnd")), waitTime * 3);
  const frontEnd = await driver.findElement(By.id("token_initiateFromFrontEnd"));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});", frontEnd);
  await frontEnd.click();

  await driver.findElement(By.id("token_client_id")).clear();
  await driver.findElement(By.id("token_client_id")).sendKeys(clientId);
  await driver.findElement(By.id("token_scope")).clear();
  await driver.findElement(By.id("token_scope")).sendKeys(scope);
  await driver.findElement(By.id("token_redirect_uri")).clear();
  await driver.findElement(By.id("token_redirect_uri")).sendKeys(baseUrl + "/callback");
  await driver.findElement(By.className("token_btn")).click();

  let accessToken = "";
  await driver.wait(async function () {
    accessToken = (await valueOf(driver, "token_access_token")) || "";
    return accessToken.split(".").length === 3;
  }, waitTime * 6, "The Token Request produced no access token.");
  log.info("Leaving obtainTokens().");
  return accessToken;
}

// The refresh call, which is what fills the second pane. Its own results pane is
// separate from the first, and the access token in it is a NEW one — which is
// the whole reason the second UserInfo link is worth testing.
async function refreshTokens(driver) {
  log.info("Entering refreshTokens().");
  const before = (await valueOf(driver, "refresh_access_token")) || "";
  const btn = By.id("refresh_btn");
  await driver.wait(until.elementLocated(btn), waitTime * 3);
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             await driver.findElement(btn));
  await driver.findElement(btn).click();
  let refreshed = "";
  await driver.wait(async function () {
    refreshed = (await valueOf(driver, "refresh_access_token")) || "";
    return refreshed.split(".").length === 3 && refreshed !== before;
  }, waitTime * 6, "The refresh call produced no new access token in the refresh results pane.");
  log.info("Leaving refreshTokens().");
  return refreshed;
}

// ---------------------------------------------------------------------------
// One UserInfo Data link, end to end.
// ---------------------------------------------------------------------------
async function exerciseUserInfoLink(driver, source, expected) {
  log.info("Entering exerciseUserInfoLink(). source=" + source.name);

  // The link must be in ITS pane, and there must be exactly one of it.
  const pane = await driver.findElements(By.id(source.pane));
  assert.ok(pane.length, "The \"" + source.name + "\" pane (#" + source.pane + ") is not on the page.");
  const links = await pane[0].findElements(By.css(source.link));
  assert.strictEqual(links.length, 1,
    "The \"" + source.name + "\" pane should hold exactly one UserInfo Data link (" + source.link +
    "), and holds " + links.length + ".");
  assert.strictEqual((await links[0].getText()).trim(), "UserInfo Data",
    "The link in \"" + source.name + "\" does not read \"UserInfo Data\".");

  // The access token that pane is showing: what the page must then use.
  const paneAccessToken = await valueOf(driver, source.accessTokenField);
  assert.ok(paneAccessToken && paneAccessToken.split(".").length === 3,
    "The \"" + source.name + "\" pane holds no access token to ask UserInfo about.");
  const paneIdToken = await valueOf(driver, source.idTokenField);
  assert.ok(paneIdToken && paneIdToken.split(".").length === 3,
    "The \"" + source.name + "\" pane holds no ID token, so it should not be offering a UserInfo " +
    "Data link at all.");

  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});", links[0]);
  await links[0].click();
  await driver.wait(until.urlContains("/userinfo.html"), waitTime * 3);

  // The default configuration, asserted rather than assumed — and left alone,
  // because "just click call" is what this test is about.
  //
  // That default is the API (back-end), matching every other initiation pane in
  // the debugger. Worth stating, because the markup reads the other way: the
  // front-end radio carries checked="true" and the back-end one checked="false"
  // — and `checked="false"` is still the ATTRIBUTE BEING PRESENT, so both are
  // checked in the source and, for two radios sharing a name, the last one wins.
  // The front-end `checked="true"` is dead intent. This assertion pins the real
  // behaviour so that changing it is a deliberate act rather than a silent switch
  // to a path that needs no api.
  const backEnd = await driver.findElement(By.id("userinfo_initiateFromBackEnd"));
  assert.ok(await backEnd.isSelected(),
    "The UserInfo page no longer defaults to initiating the call from the api. This test presses " +
    "Retrieve UserInfo without touching the configuration, so a changed default silently exercises " +
    "a different path.");
  const endpoint = await valueOf(driver, "userinfo_endpoint");
  assert.strictEqual(endpoint, expected.userinfoEndpoint,
    "The UserInfo page is pointed at \"" + endpoint + "\", not at the endpoint discovery published (" +
    expected.userinfoEndpoint + ").");

  // THE check this test exists for: the page carries the token from the pane the
  // link was in. All three sets describe the same user, so a wrong token here
  // produces a response that looks perfectly correct.
  const loaded = await valueOf(driver, "token_access_token");
  assert.strictEqual(loaded, paneAccessToken,
    "The UserInfo page loaded a different access token from the one in the \"" + source.name +
    "\" pane. The response would still look right — every token here belongs to the same user — " +
    "so this is the only place the wrong one shows up.");

  await driver.findElement(By.css("input[type=\"submit\"][value=\"Retrieve UserInfo\"]")).click();

  // Wait for the CONTENT: the textarea ships with whitespace in it, which is
  // truthy and is not JSON. See tests/wait_for.js.
  let output = "";
  try {
    await driver.wait(async function () {
      output = (await valueOf(driver, "userinfo_output")) || "";
      if (!output.trim()) return false;
      try {
        JSON.parse(output);
        return true;
      } catch (e) {
        return false;
      }
    }, waitTime * 6);
  } catch (e) {
    throw new Error("The UserInfo call from \"" + source.name + "\" produced no JSON. The output box " +
                    "holds: \"" + output.trim().slice(0, 300) + "\".");
  }
  const claims = JSON.parse(output);
  log.info("[" + source.name + "] UserInfo returned: " + Object.keys(claims).sort().join(", "));

  // Who it describes. preferred_username is the login name on both OPs; `sub` is
  // opaque and is compared against the ID token from the SAME pane, which ties
  // the response to the token that fetched it.
  assert.strictEqual(claims.preferred_username, expected.user,
    "UserInfo from \"" + source.name + "\" describes " + claims.preferred_username +
    ", not the user who signed in (" + expected.user + ").");
  assert.ok(claims.sub, "The UserInfo response carries no sub.");
  assert.strictEqual(claims.sub, claimsOf(paneIdToken).sub,
    "UserInfo answered about " + claims.sub + ", but the ID token in the same pane describes " +
    claimsOf(paneIdToken).sub + ". OIDC Core section 5.3.2 requires them to match.");
  log.info("[" + source.name + "] OK — UserInfo describes " + claims.preferred_username +
           " (sub " + claims.sub + "), matching the ID token in that pane.");

  // ...and back, which is the other half of "exercise the page".
  const back = By.partialLinkText("Return to debugger");
  await driver.wait(until.elementLocated(back), waitTime);
  await driver.findElement(back).click();
  await driver.wait(until.urlContains("/debugger2.html"), waitTime * 3);
  await driver.wait(until.elementLocated(By.id(source.pane)), waitTime * 3);
  log.info("[" + source.name + "] OK — Return to debugger came back with the pane intact.");
  log.info("Leaving exerciseUserInfoLink().");
  return claims;
}

// ---------------------------------------------------------------------------
// Make a Token History entry the active one, which is what puts anything in the
// "Currently Viewing" pane — that pane is empty until a set is Activated.
//
// Generation 1 on purpose: it is the set the ORIGINAL flow produced, and by this
// point the live panes hold the refreshed set. So the history link is asked for
// a token that is demonstrably not the current one, which is the only way to
// tell "the link carries the generation it names" from "the link carries
// whatever is latest".
//
// The row is found by its # cell rather than by the onclick attribute: the
// deployed builds are minified and the minifier rewrites onclick quoting, so an
// XPath over that attribute is a known way to write a test that passes locally
// and fails on the real site.
// ---------------------------------------------------------------------------
async function activateHistoryGeneration(driver, generation) {
  log.info("Entering activateHistoryGeneration(). generation=" + generation);
  const panel = By.id("token-history-panel");
  await driver.wait(until.elementLocated(panel), waitTime * 3);
  await driver.wait(until.elementIsVisible(driver.findElement(panel)), waitTime * 3);
  const button = By.xpath("//div[@id='token-history-panel']//tr[td[1][normalize-space()='" +
                          generation + "']]//input[@value='Activate']");
  const found = await driver.findElements(button);
  assert.strictEqual(found.length, 1,
    "Token History has no Activate button for generation " + generation + " (found " + found.length +
    "). Either the refresh call did not add a second set, or that generation is already active.");
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});", found[0]);
  await found[0].click();
  await driver.wait(async function () {
    const pane = await driver.findElements(By.id("cv_access_token"));
    if (!pane.length) return false;
    const v = await pane[0].getAttribute("value");
    return !!(v && v.split(".").length === 3);
  }, waitTime * 4, "Activating generation " + generation + " did not fill the Currently Viewing pane.");
  log.info("Leaving activateHistoryGeneration().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder()
    .forBrowser("chrome").setChromeOptions(options).setLoggingPrefs(loggingPrefs).build();

  try {
    const stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
    const stsBase = stsUrl.replace(/\/sts\/?$/, "");
    const discovery = process.env.DISCOVERY_ENDPOINT ||
                      (stsBase + "/.well-known/openid-configuration");
    const clientId = process.env.CLIENT_ID || "oidc-userinfo-test-client";
    const scope = process.env.SCOPE || "openid profile email";
    const user = process.env.OIDC_LOGIN_USER || "userinfouser";

    const res = await fetch(discovery);
    assert.ok(res.ok, "GET " + discovery + " answered " + res.status + ".");
    const metadata = await res.json();
    assert.ok(metadata.userinfo_endpoint,
      "This OP publishes no userinfo_endpoint, so there is nothing for these links to call. " +
      "Metadata: " + discovery);
    const expected = { user: user, userinfoEndpoint: metadata.userinfo_endpoint };
    log.info("Running against " + metadata.issuer + ", UserInfo at " + metadata.userinfo_endpoint + ".");

    await driver.manage().deleteAllCookies();
    await driver.get(baseUrl + "/debugger.html");
    await driver.executeScript("window.localStorage.clear();");
    await driver.get(baseUrl + "/debugger.html");
    await populateMetadata(driver, discovery);

    const originalAccessToken = await obtainTokens(driver, { clientId: clientId, scope: scope, user: user });
    log.info("[tokens] OK — the Authorization Code flow produced a token set.");

    // Pane 1 before anything else: the refresh call replaces what the second
    // pane holds, and running it first would leave nothing to distinguish them.
    const first = await exerciseUserInfoLink(driver, SOURCES[0], expected);

    const refreshedAccessToken = await refreshTokens(driver);
    log.info("[refresh] OK — the refresh call produced a second, different token set.");
    const second = await exerciseUserInfoLink(driver, SOURCES[1], expected);

    // The third set comes from Token History, which needs a set activated first.
    await activateHistoryGeneration(driver, 1);
    const cvToken = await valueOf(driver, "cv_access_token");
    assert.strictEqual(cvToken, originalAccessToken,
      "Currently Viewing shows generation 1, so it should hold the access token the original flow " +
      "produced. It holds a different one — which would make the UserInfo answer right by accident.");
    assert.notStrictEqual(cvToken, refreshedAccessToken,
      "Currently Viewing is showing the REFRESHED token while claiming to show generation 1.");
    log.info("[history] OK — generation 1 activated, holding the original flow's access token.");
    const third = await exerciseUserInfoLink(driver, SOURCES[2], expected);

    // One user, three routes to the same answer. Checked because the per-pane
    // assertions above would all pass if each pane somehow described a different
    // person, which would mean the links had been crossed with another session.
    assert.strictEqual(first.sub, second.sub,
      "The refresh call's UserInfo answer describes a different subject from the original.");
    assert.strictEqual(first.sub, third.sub,
      "Token History's UserInfo answer describes a different subject from the original.");
    log.info("[all three] OK — every UserInfo Data link answered for " + first.sub + ".");

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oidc_userinfo')
  .description("The UserInfo endpoint through all three of debugger2.html's UserInfo Data links.")
  .addOption(new Option("-u, --url <url>", "Set base URL.").makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser (only works within device)."))
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
