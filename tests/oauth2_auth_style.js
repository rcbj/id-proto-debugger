// File: oauth2_auth_style.js
//
// The AUTH STYLE radios on oauth2_oidc_2.html — POST or Header — on the two
// panes that send a client secret to the token endpoint: "Exchange
// Authorization Code for Access Token" and the Refresh Token pane. Issue #328.
//
// Header means RFC 6749 section 2.3.1's HTTP Basic: the client id and secret
// go in an `Authorization: Basic` header, and the secret is NOT in the body.
// Two bugs broke it, and this job is written to catch both:
//
//   1. The BROWSER path never sent the header. convertToOAuth2Format() leaves
//      the secret out of the body for the Header style, and nothing put it in
//      a header instead, so the request carried no client credential at all.
//      A server that holds the client to client_secret_basic answers 401
//      invalid_client (the mock's STS-OAUTH-0019).
//   2. A page load LOST the choice. loadValuesFromLocalStorage() restored the
//      token pane's Header choice onto the REFRESH pane's radios and left the
//      token pane at resetUI()'s POST, and the next button press then wrote
//      POST over what the user had chosen. The callback redirect is a page
//      load, so on the api path too a Header choice never reached the token
//      endpoint — the api's own Basic header code was right and was never
//      asked for.
//
// One job per INITIATION (AUTH_STYLE_INITIATE=front|back), because the two
// paths build the header in different processes: the page's
// clientBasicAuthHeader() for the browser, and api/server.js's /token for the
// api. Each job:
//
//   * registers a CONFIDENTIAL client declaring client_secret_basic, so the
//     mock refuses a token request that does not present the secret by Basic;
//   * signs in through the Authorization Code flow;
//   * reloads oauth2_oidc_2.html under two MIXED stored choices (token Header
//     and refresh POST, then the reverse) and requires each pane to come back
//     with its OWN choice — the mixed case is the one bug 2 got wrong both
//     ways round;
//   * requires the request PREVIEW of each pane to show the Basic header and
//     no client_secret in the body;
//   * redeems the code and then refreshes, and reads the REQUEST off each
//     pane's HTTP tab: an Authorization header whose value is exactly
//     Basic base64(client_id:client_secret), and the secret nowhere in the
//     panel in the clear. On the api path the panel is the api's own trace of
//     ITS call to the token endpoint, so that is the request that left.
//
// Against the mock STS only: it is in this project's control, and it enforces
// the registered method, which is what makes a token coming back mean the
// header was sent rather than merely that the server was lenient.

const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require('commander');
const browserFlags = require("./browser_flags.js");
const registry = require("./sts_applications.js");
// The mock STS's consent screen. See tests/oidc_userinfo.js.
const consentScreen = require("./consent_screen.js");
const { loadUrl } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_auth_style',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, clickStable, valueOf } =
       require("../common/tests.js")({ By, until, Select, waitTime, log,
       assert });

const FLOW_LABEL = "OIDC Authorization Code Flow(code)";

// Letters and digits only, so the two encoders agree: the page form-encodes
// both halves before base64 (RFC 6749 section 2.3.1) and the api encodes the
// secret alone, and for these characters encoding changes nothing.
const CLIENT_SECRET = "authStyleSecret7Qx2Lm9Vb4Nc8Rz";

// What both ends must put in the header for this client.
function expectedBasic(clientId) {
  log.debug("Entering expectedBasic().");
  log.debug("Leaving expectedBasic().");
  return "Basic " + Buffer.from(encodeURIComponent(clientId) + ":" +
      encodeURIComponent(CLIENT_SECRET)).toString("base64");
}

// Scroll a control into view and click it. The radios live in long panes, and
// a click on one outside the viewport is "element not interactable".
async function clickInView(driver, id, what) {
  log.debug("Entering clickInView(). id=" + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime * 3);
  const element = await driver.findElement(By.id(id));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             element);
  await clickStable(driver, By.id(id), what);
  log.debug("Leaving clickInView().");
}

async function typeInto(driver, id, value) {
  log.debug("Entering typeInto(). id=" + id);
  const element = await driver.findElement(By.id(id));
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'});",
                             element);
  await element.clear();
  await element.sendKeys(value);
  log.debug("Leaving typeInto().");
}

// The checked state of all four Auth Style radios. `checked` is read as a
// PROPERTY, which is what the page sets and what a submit would read; the
// markup's checked="true" / checked="false" attributes are both "present" and
// say nothing.
async function readAuthStyleRadios(driver) {
  log.debug("Entering readAuthStyleRadios().");
  // NOTE: serialized and evaluated IN THE BROWSER, where there is no `log`.
  // Exempt from the Entering/Leaving convention — see the repo-root CLAUDE.md.
  const state = await driver.executeScript(function () {
    function on(id) {
      var el = document.getElementById(id);
      return el ? !!el.checked : null;
    }
    return {
      tokenPost: on("token_postAuthStyleCheckToken"),
      tokenHeader: on("token_headerAuthStyleCheckToken"),
      refreshPost: on("refresh_postAuthStyleCheckToken"),
      refreshHeader: on("refresh_headerAuthStyleCheckToken")
    };
  });
  log.debug("Leaving readAuthStyleRadios(). " + JSON.stringify(state));
  return state;
}

// Store a choice for each pane, reload the page the way the callback redirect
// loads it, and require each pane to come back with its own choice.
async function assertChoiceSurvivesReload(driver, tokenPost, refreshPost) {
  log.debug("Entering assertChoiceSurvivesReload().");
  const label = "token=" + (tokenPost ? "POST" : "Header") + ", refresh=" +
      (refreshPost ? "POST" : "Header");
  await driver.executeScript(
      "window.localStorage.setItem('token_post_auth_style', arguments[0]);" +
      "window.localStorage.setItem('refresh_post_auth_style', arguments[1]);",
      String(tokenPost), String(refreshPost));
  await loadUrl(driver, await driver.getCurrentUrl());
  await driver.wait(until.elementLocated(
      By.id("token_postAuthStyleCheckToken")), waitTime * 3);
  const radios = await readAuthStyleRadios(driver);
  assert.deepStrictEqual(radios, {
    tokenPost: tokenPost, tokenHeader: !tokenPost,
    refreshPost: refreshPost, refreshHeader: !refreshPost
  }, "Stored " + label + " and reloaded oauth2_oidc_2.html; each pane " +
     "should come back with its OWN choice. The radios read " +
     JSON.stringify(radios) + ".");
  log.info("[reload] OK — " + label + " survived a page load, each pane " +
           "restoring its own choice.");
  log.debug("Leaving assertChoiceSurvivesReload().");
}

// Sign in through the Authorization Code flow and come back to
// oauth2_oidc_2.html holding a code. The token request is NOT made here.
async function signInForCode(driver, { clientId, scope, user }) {
  log.debug("Entering signInForCode().");
  log.info("Entering signInForCode().");
  // No driver.get() first: discovery has just filled the fields and storage
  // is not written until Authorize. See obtainTokens() in oidc_userinfo.js.
  await driver.wait(until.elementLocated(By.id("authorization_grant_type")),
                    waitTime * 3);
  if (!(await driver.findElement(By.id("authorization_grant_type"))
      .isDisplayed())) {
    await driver.findElement(By.id("config_expand_button")).click();
    await driver.wait(until.elementIsVisible(driver.findElement(By.id(
                      "authorization_grant_type"))), waitTime);
  }
  await new Select(await driver.findElement(By.id("authorization_grant_type")))
    .selectByVisibleText(FLOW_LABEL);

  await driver.wait(until.elementLocated(By.id("client_id")), waitTime);
  if (!(await driver.findElement(By.id("client_id")).isDisplayed())) {
    await driver.findElement(By.id("authz_expand_button")).click();
  }
  await driver.wait(until.elementIsVisible(driver.findElement(By.id(
                    "client_id"))), waitTime);
  await typeInto(driver, "client_id", clientId);
  await typeInto(driver, "scope", scope);
  await typeInto(driver, "redirect_uri", baseUrl + "/callback");
  await driver.findElement(By.css(
                           "input[type=\"submit\"][value=\"Authorize\"]"))
                           .click();

  await driver.wait(async function () {
    if ((await driver.getCurrentUrl())
        .indexOf("/oauth2_oidc_2.html") >= 0) return true;
    return (await driver.findElements(By.id("username"))).length > 0;
  }, waitTime * 4,
      "Neither the OP's login screen nor a return to oauth2_oidc_2.html " +
          "arrived.");
  if ((await driver.findElements(By.id("username"))).length) {
    await driver.findElement(By.id("username")).clear();
    await driver.findElement(By.id("username")).sendKeys(user);
    const pw = await driver.findElements(By.id("password"));
    if (pw.length) await pw[0].sendKeys(user);
    await driver.findElement(By.id("kc-login")).click();
    await consentScreen.passInBrowser(driver, By);
  }
  await driver.wait(until.urlContains("/oauth2_oidc_2.html"), waitTime * 5);
  await driver.wait(until.elementLocated(By.id("code")), waitTime * 3);
  const code = await valueOf(driver, "code");
  assert.ok(code, "Back on oauth2_oidc_2.html with no authorization code in " +
            "the code field.");
  log.info("Leaving signInForCode().");
  log.debug("Leaving signInForCode().");
}

// A request preview must show the Basic header and keep the secret out of the
// body.
async function assertPreview(driver, which, clientId) {
  log.debug("Entering assertPreview(). which=" + which);
  const fn = which === "token" ? "recalculateTokenRequestDescription" :
      "recalculateRefreshRequestDescription";
  await driver.executeScript("oauth2_oidc_2." + fn + "();");
  const preview = await valueOf(driver,
      "display_" + which + "_request_form_textarea1");
  log.info("[" + which + "] preview:\n" + preview);
  const wanted = "Authorization: Basic base64(" + clientId +
      ":<client_secret>)";
  assert.ok((preview || "").indexOf(wanted) >= 0,
    "The " + which + " request preview should show \"" + wanted + "\" for " +
    "the Header auth style. It reads:\n" + preview);
  const body = (preview || "").split("Message Body:")[1] || "";
  assert.ok(body.indexOf("client_secret=") < 0 &&
            body.indexOf(CLIENT_SECRET) < 0,
    "The Header auth style moves the secret OUT of the body, and the " +
    which + " request preview still puts it there:\n" + preview);
  log.info("[" + which + "] OK — the preview shows the Basic header and no " +
           "secret in the body.");
  log.debug("Leaving assertPreview().");
}

// The REQUEST half of a pane's HTTP tab: its header table, as name -> value
// with the names lower-cased, its body, and the whole panel's text.
async function readSentRequest(driver, which) {
  log.debug("Entering readSentRequest(). which=" + which);
  // NOTE: serialized and evaluated IN THE BROWSER, where there is no `log`.
  // Exempt from the Entering/Leaving convention — see the repo-root CLAUDE.md.
  const sent = await driver.executeScript(function (panelId) {
    var panel = document.getElementById(panelId);
    if (!panel) {
      return null;
    }
    var headers = {};
    var table = panel.querySelector("table.dbg-http-table");
    if (table) {
      Array.prototype.forEach.call(table.querySelectorAll("tr"),
          function (row) {
        var cells = row.querySelectorAll("td");
        if (cells.length === 2) {
          headers[cells[0].textContent.toLowerCase()] = cells[1].textContent;
        }
      });
    }
    var body = panel.querySelector(".dbg-http-body");
    return {
      headers: headers,
      body: body ? body.textContent : null,
      text: panel.textContent
    };
  }, which + "_http_exchange");
  log.debug("Leaving readSentRequest().");
  return sent;
}

async function assertSentWithBasic(driver, which, clientId) {
  log.debug("Entering assertSentWithBasic(). which=" + which);
  const sent = await readSentRequest(driver, which);
  assert.ok(sent, "oauth2_oidc_2.html has no #" + which + "_http_exchange " +
            "panel to read the request from.");
  log.info("[" + which + "] request headers: " +
           JSON.stringify(sent.headers) + "; body: " + sent.body);
  assert.strictEqual(sent.headers.authorization, expectedBasic(clientId),
    "The " + which + " request should carry Authorization: " +
    expectedBasic(clientId) + " (RFC 6749 section 2.3.1). Its headers were " +
    JSON.stringify(sent.headers) + ".");
  assert.ok((sent.body || "").indexOf("client_secret") < 0,
    "The Header auth style sends the secret in the Authorization header " +
    "ONLY, and the " + which + " request body carries a client_secret: " +
    sent.body);
  assert.ok((sent.text || "").indexOf(CLIENT_SECRET) < 0,
    "The client secret appears in the clear somewhere in the " + which +
    " request's HTTP panel, and Header style should send it only inside " +
    "the base64 of the Basic credential.");
  log.info("[" + which + "] OK — sent with Authorization: Basic and no " +
           "secret in the body.");
  log.debug("Leaving assertSentWithBasic().");
}

// Wait for a field to hold a new JWS, failing with the pane's own error text
// if the token endpoint refused the request instead.
async function waitForToken(driver, field, errorField, before, what) {
  log.debug("Entering waitForToken(). field=" + field);
  let value = "";
  await driver.wait(async function () {
    value = (await valueOf(driver, field)) || "";
    if (value.split(".").length === 3 && value !== before) return true;
    const error = (await valueOf(driver, errorField)) || "";
    if (error.trim()) {
      throw new Error("The token endpoint refused the " + what + ": " +
                      error);
    }
    return false;
  }, waitTime * 6, "The " + what + " produced no access token.");
  log.debug("Leaving waitForToken().");
  return value;
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    // "=new", not bare --headless — see tests/oidc_flows.js.
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder()
    .forBrowser("chrome").setChromeOptions(options)
        .setLoggingPrefs(loggingPrefs).build();

  // process.exit() would skip the finally below and orphan the browser.
  // Record the failure, let the finally quit the driver, THEN exit.
  let testFailed = false;
  try {
    const initiate = String(process.env.AUTH_STYLE_INITIATE || "front")
        .toLowerCase();
    assert(["front", "back"].indexOf(initiate) >= 0,
      "AUTH_STYLE_INITIATE must be \"front\" or \"back\", not \"" +
          process.env.AUTH_STYLE_INITIATE + "\".");
    const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
    const stsBase = stsUrl.replace(/\/sts\/?$/, "");
    const discovery = process.env.DISCOVERY_ENDPOINT ||
                      (stsBase + "/.well-known/openid-configuration");
    // One client per initiation, so the two jobs in the pool never reconcile
    // the same entry under each other.
    const clientId = "auth-style-test-client-" + initiate;
    const scope = "openid profile email";
    const user = "authstyleuser";

    // -----------------------------------------------------------------
    // A CONFIDENTIAL client that DECLARES client_secret_basic. The declared
    // method is what makes the mock hold the request to it: a token request
    // that does not present the secret by Basic is refused with
    // STS-OAUTH-0019, which is issue #328's symptom.
    // -----------------------------------------------------------------
    await registry.provision(registry.stsBaseFor(discovery), {
      identifier: clientId,
      name: "Auth Style, " + initiate + "-end initiated (mock STS)",
      protocols: ["oauth2", "oidc"],
      fields: {
        oauthClientId: clientId,
        oauthRedirectUri: [baseUrl + "/callback"],
        oauthResponseType: ["code"],
        oauthGrantType: ["authorization_code", "refresh_token"],
        oauthScope: scope.split(/\s+/).filter(Boolean),
        oauthTokenEndpointAuthMethod: "client_secret_basic",
        oauthClientSecret: CLIENT_SECRET,
        oauthConfidential: "TRUE"
      },
      why: "the confidential client whose secret must travel by HTTP Basic"
    });

    await driver.manage().deleteAllCookies();
    await loadUrl(driver, baseUrl + "/oauth2_oidc_1.html");
    await driver.executeScript("window.localStorage.clear();");
    await loadUrl(driver, baseUrl + "/oauth2_oidc_1.html");
    await populateMetadata(driver, discovery);
    await signInForCode(driver, { clientId: clientId, scope: scope,
                                  user: user });

    // -----------------------------------------------------------------
    // BUG 2: each pane restores its OWN choice across a page load. The two
    // mixed cases first — they are the ones the cross-wired restore got
    // wrong in both directions — and then Header on both, which is what the
    // calls below are made with.
    // -----------------------------------------------------------------
    await assertChoiceSurvivesReload(driver, false, true);
    await assertChoiceSurvivesReload(driver, true, false);
    await assertChoiceSurvivesReload(driver, false, false);

    // -----------------------------------------------------------------
    // THE TOKEN REQUEST.
    // -----------------------------------------------------------------
    const initiateId = initiate === "front" ? "FrontEnd" : "BackEnd";
    const tokenRadio = "token_initiateFrom" + initiateId;
    await driver.wait(until.elementLocated(By.id(tokenRadio)), waitTime * 3);
    if (initiate === "back") {
      const offered = await driver.findElement(By.id(tokenRadio))
          .isEnabled();
      assert.ok(offered, "This job tests the api path and the page " +
                "disables the back-end radio, so this target has no api. " +
                "run-report.js should not have scheduled it here.");
    }
    await clickInView(driver, tokenRadio, "the token " + initiate +
                      "-end radio");
    // Clicked as a user does, though it is already the restored choice: its
    // handler is what writes storage and redraws the preview.
    await clickInView(driver, "token_headerAuthStyleCheckToken",
                      "the token pane's Header auth style");
    await typeInto(driver, "token_client_id", clientId);
    await typeInto(driver, "token_client_secret", CLIENT_SECRET);
    await typeInto(driver, "token_scope", scope);
    await typeInto(driver, "token_redirect_uri", baseUrl + "/callback");
    await assertPreview(driver, "token", clientId);

    await clickStable(driver, By.className("token_btn"), "Get Token");
    const accessToken = await waitForToken(driver, "token_access_token",
        "display_token_error_form_textarea1", "",
        "authorization code exchange");
    log.info("[token/" + initiate + "] OK — the confidential client " +
             "redeemed its code under client_secret_basic.");
    await assertSentWithBasic(driver, "token", clientId);

    // -----------------------------------------------------------------
    // THE REFRESH REQUEST.
    // -----------------------------------------------------------------
    const refreshToken = await valueOf(driver, "refresh_refresh_token");
    assert.ok(refreshToken, "The code exchange returned no refresh token, " +
              "so there is no Refresh Request to make.");
    await clickInView(driver, "refresh_initiateFrom" + initiateId,
                      "the refresh " + initiate + "-end radio");
    await clickInView(driver, "refresh_headerAuthStyleCheckToken",
                      "the refresh pane's Header auth style");
    // The pane takes its secret from the dynamic-registration result in
    // storage, which this flow never wrote; a user types it, as here.
    await typeInto(driver, "refresh_client_secret", CLIENT_SECRET);
    await assertPreview(driver, "refresh", clientId);

    const before = (await valueOf(driver, "refresh_access_token")) || "";
    await clickStable(driver, By.id("refresh_btn"), "the refresh button");
    const refreshed = await waitForToken(driver, "refresh_access_token",
        "display_refresh_error_form_textarea1", before, "refresh request");
    assert.notStrictEqual(refreshed, accessToken,
      "The refresh pane holds the same access token the code bought.");
    log.info("[refresh/" + initiate + "] OK — the refresh succeeded under " +
             "client_secret_basic.");
    await assertSentWithBasic(driver, "refresh", clientId);

    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    testFailed = true;
  } finally {
    await driver.quit();
  }
  if (testFailed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oauth2_auth_style')
  .description("The Auth Style radios (POST / Header) on the token and " +
      "refresh panes, against the mock STS.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-i, --initiate <end>",
      "front or back (overrides AUTH_STYLE_INITIATE).")
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if (!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (!!options.initiate) {
      process.env.AUTH_STYLE_INITIATE = options.initiate;
    }
    if (!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
