const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'oauth2_implicit',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000";
var logout_post_redirect_uri_value = baseUrl + "/logout.html";
var headless = true;
var waitTime = appconfig.waitTime;

const { populateMetadata, getAccessTokenImplicit, verifyAccessToken } =
       require("../common/tests.js")({ By, until, Select, waitTime, log, jwt,
       assert });



async function logout(driver) {
  log.debug("Entering logout().");
  // Set the post-logout redirect URI and trigger the OIDC logout
  log.info("Entering logout().");
  log.info("Find logout Button");
  logout_button = By.id("logout_btn");
  log.info("Find logout_post_redirect_uri.");
  logout_post_redirect_uri = By.id("logout_post_redirect_uri");
  log.info("Wait for logout_post_redirect_uri.");
  await driver.wait(until.elementLocated(logout_post_redirect_uri), waitTime);
  log.info("Wait for logout_post_redirect_uri to be visible.");
  await driver.findElement(logout_post_redirect_uri).clear();
  await driver.wait(until.elementIsVisible(driver.findElement(
                    logout_post_redirect_uri)), waitTime);
  log.info("Set post_redirect_uri for logout.");
  await driver.findElement(logout_post_redirect_uri)
                           .sendKeys(logout_post_redirect_uri_value);
  log.info("Click logout_btn.");
  await driver.findElement(logout_button).click();

  // Confirm logout on the Keycloak logout page
  log.info("Wait for kc_logout.");
  kc_logout = By.id("kc-logout");
  await driver.wait(until.elementLocated(kc_logout), waitTime);
  log.info("Wait for kc-logout to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(kc_logout)),
                    waitTime);

  log.info("Click kc_logout.");
  await driver.findElement(kc_logout).click();

  // Follow the link back to the debugger front page
  log.info("Click link to return to the front page of the debugger.");
  returnToDebugLink = By.partialLinkText('Return to debugger');
  await driver.wait(until.elementLocated(returnToDebugLink), waitTime);
  await driver.findElement(returnToDebugLink).click();

  // Verify the debugger has reloaded by waiting for the authorization form's
  // expand button and client_id field
  log.info("Find authz_expand_button.");
  authz_expand_button = By.id("authz_expand_button");
  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  log.info("Waiting for authz_expand_button to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(
                    authz_expand_button)), waitTime);

  log.info("Find client_id.");
  client_id = By.id("client_id");
  log.info("Wait for client_id");
  await driver.findElement(client_id);
  log.info("Wait for client_id to be visible.");
  await driver.wait(until.elementIsVisible(driver.findElement(client_id)),
                    waitTime);
  log.debug("Leaving logout().");
}

// An implicit flow has no second call to compose, so once the token is on
// oauth2_oidc_2.html the page's first row of panes — Configuration
// Parameters, Tools, and the token request — is collapsed by default,
// leaving the tokens
// as what the page opens on. Read off the live CSS rather than the inline
// style attribute, so a rule that expanded a pane some other way is still
// caught, and check each pane's legend is still there to expand it: collapsed
// must mean collapsed, not gone.
async function verifyFirstPaneRowCollapsed(driver) {
  log.debug("Entering verifyFirstPaneRowCollapsed().");
  log.info("Entering verifyFirstPaneRowCollapsed().");
  const panes = [["config_fieldset", "config_expand_button",
      "Configuration Parameters"],
                 ["tools_fieldset", "tools_expand_button", "Tools"],
                 ["token_fieldset", "token_expand_button",
                  "the token request"]];
  for (const [fieldsetId, legendId, name] of panes) {
    await driver.wait(until.elementLocated(By.id(fieldsetId)), waitTime);
    const display =
        await driver.findElement(By.id(fieldsetId)).getCssValue("display");
    assert.strictEqual(display, "none",
      "The " + name +
          " pane should be collapsed by default once an implicit flow has " +
      "returned a token, but #" + fieldsetId + " has display: " + display +
          ".");
    await driver.wait(until.elementIsVisible(driver.findElement(By.id(
                      legendId))), waitTime,
      "The " + name + " pane's title (#" + legendId +
          ") should still be visible, so the " +
      "collapsed pane can be expanded.");
  }
  log.info("Leaving verifyFirstPaneRowCollapsed().");
  log.debug("Leaving verifyFirstPaneRowCollapsed().");
}

// The Authorization Endpoint Results pane. For an implicit flow this is the
// only place the token is ever shown — there is no token endpoint call — so it
// has to be a pane like every other one on the page, and the token has to carry
// the same links and buttons it would get had a code exchange returned it.
//
// Two of these assertions are about what the pane used to do. It rendered the
// id_token into a second container, so an OIDC Implicit Flow showed two panes
// both titled "Authorization Endpoint Results"; and a token that was not where
// it looked became the placeholder NO_..._PRESENTED_IN_EXPECTED_LOCATIONS in
// the token's own field, where it reads as something the identity provider
// said.
async function verifyAuthorizationEndpointResultsPane(driver, access_token) {
  log.debug("Entering verifyAuthorizationEndpointResultsPane().");
  log.info("Entering verifyAuthorizationEndpointResultsPane().");
  const facts = await driver.executeScript(function () {
    var panes = Array.prototype.filter.call(
      document.querySelectorAll(".dbg-pane"),
      function (pane) {
        var legend = pane.querySelector(".dbg-legend");
        return !!legend && legend.textContent.trim().indexOf("Authorization " +
            "Endpoint Results") === 0;
      });
    var pane = panes[0] || null;
    var fieldset = pane ? pane.querySelector("fieldset") : null;
    var copy = pane ? pane.querySelector('input[value="Copy Token"]') : null;
    var accessField = document.getElementById("authz_access_token");
    var revoke = pane ? pane.querySelector(".revoke_token_btn") : null;
    var history = [];
    try {
      history = JSON.parse(window.localStorage.getItem("token_history") ||
          "[]");
    } catch (e) {
      history = [];
    }
    return {
      paneCount: panes.length,
      legendTarget: pane ?
          pane.querySelector(".dbg-legend").getAttribute("data-target") : null,
      fieldsetId: fieldset ? fieldset.id : null,
      text: pane ? pane.textContent : "",
      hrefs: pane ? Array.prototype.map.call(pane.querySelectorAll("a"),
          function (a) {
        return a.getAttribute("href");
      }) : [],
      revokeButtons: pane ?
          pane.querySelectorAll(".revoke_token_btn").length : 0,
      revokeType: revoke ? revoke.getAttribute("data-revoke-type") : null,
      revokeGeneration: revoke ?
          revoke.getAttribute("data-revoke-generation") : null,
      copyOnClick: copy ? copy.getAttribute("onclick") : null,
      accessFieldValue: accessField ? accessField.value : null,
      idFieldPresent: !!document.getElementById("authz_id_token"),
      tokenHistory: history,
      currentAccessSlot: window.localStorage.getItem("token_access_token")
    };
  });

  // Every link and the Revoke button name a token by a `type` the target page
  // knows. Which types they use is not fixed — a set that has reached Token
  // History is named by generation, because the current-token slots stop
  // meaning this token the moment a hybrid flow exchanges its code — so what is
  // asserted is the property that matters either way: the token each control
  // names is the one displayed beside it.
  const tokenNamedBy = function (type, generation) {
    log.debug("Entering tokenNamedBy().");
    if (type === "access" || type === "token_access_token") {
      log.debug("Leaving tokenNamedBy().");
      return facts.currentAccessSlot;
    }
    if (type === "history_access") {
      const entry = facts.tokenHistory[parseInt(generation, 10)];
      log.debug("Leaving tokenNamedBy().");
      return entry ? entry.access_token : undefined;
    }
    log.debug("Leaving tokenNamedBy().");
    return undefined;
  };
  const linkTo = function (page) {
    log.debug("Entering linkTo().");
    const href = facts.hrefs.filter(function (h) { return h && h.indexOf(page +
        "?") === 0; })[0];
    if (!href) {
      log.debug("Leaving linkTo().");
      return null;
    }
    const params = new URLSearchParams(href.substring(href.indexOf("?") + 1));
    log.debug("Leaving linkTo().");
    return { href: href, type: params.get("type"),
            generation: params.get("generation") };
  };

  assert.strictEqual(facts.paneCount, 1,
    "There should be exactly one Authorization Endpoint Results pane; found " +
        facts.paneCount +
    ". Two means the id_token has been given a container of its own again.");
  assert.ok(facts.legendTarget && facts.fieldsetId === facts.legendTarget,
    "The pane's title should be a .dbg-legend whose data-target names its " +
        "own fieldset, the way every " +
    "other pane on the page is built. data-target=" + facts.legendTarget +
        ", fieldset id=" + facts.fieldsetId + ".");
  assert.strictEqual(facts.accessFieldValue, access_token,
    "The pane's access token field should hold the token the flow returned.");
  // The three pages the Token Endpoint Results pane links a token to. UserInfo
  // is on the access token's row here, which is where it works: the call is
  // authenticated with the access token, and this flow returns no id_token to
  // hang it off the way that pane does.
  ["/token_detail.html", "/introspection.html",
   "/userinfo.html"].forEach(function (page) {
    const link = linkTo(page);
    assert.ok(link, "The access token needs its " + page +
              " link. Links found: " + JSON.stringify(facts.hrefs));
    assert.strictEqual(tokenNamedBy(link.type, link.generation), access_token,
      "The " + page +
          " link should name the token displayed beside it. It names type=" +
          link.type +
      (link.generation === null ? "" : ", generation=" + link.generation) +
       ".");
  });
  assert.strictEqual(facts.revokeButtons, 1,
    "The access token needs its Revoke Token button.");
  assert.strictEqual(tokenNamedBy(facts.revokeType, facts.revokeGeneration),
                     access_token,
    "Revoke Token should revoke the token displayed beside it, not whichever " +
        "token is current. " +
    "It names data-revoke-type=" + facts.revokeType +
        ", data-revoke-generation=" + facts.revokeGeneration + ".");
  // The onclick is the whole button: DOMPurify strips inline event handlers, so
  // a pane written to the DOM through it has a Copy Token button that copies
  // nothing and — being inside a <form> — submits it and reloads the page.
  assert.ok(facts.copyOnClick &&
            facts.copyOnClick.indexOf("#authz_access_token") >= 0,
    "The Copy Token button should carry an onclick naming this pane's own " +
        "field. onclick=" + facts.copyOnClick);
  assert.ok(facts.text.indexOf("PRESENTED_IN_EXPECTED_LOCATIONS") < 0,
    "The pane should not contain a NO_..._PRESENTED_IN_EXPECTED_LOCATIONS " +
        "placeholder.");
  assert.ok(!facts.idFieldPresent,
    "OAuth2 Implicit Grant asks for no id_token, so the pane should not draw " +
        "an ID Token row.");

  // Registered with the Expand/Collapse all switch. Asserted by driving the
  // switch rather than by reading its list, since the list is in the page's
  // markup and a pane can be added to one and not the other.
  const collapsed = await driver.executeScript(
    "dbgSetAllPanes(false); return " +
        "document.getElementById(arguments[0]).style.display;",
        facts.fieldsetId);
  assert.strictEqual(collapsed, "none",
    "Collapse all panes should collapse the Authorization Endpoint Results " +
        "pane; its fieldset (" +
    facts.fieldsetId + ") is not in the switch's list.");
  const expanded = await driver.executeScript(
    "dbgSetAllPanes(true); return " +
        "document.getElementById(arguments[0]).style.display;",
        facts.fieldsetId);
  assert.strictEqual(expanded, "block",
    "Expand all panes should expand the Authorization Endpoint Results " +
        "pane again.");
  log.info("Leaving verifyAuthorizationEndpointResultsPane().");
  log.debug("Leaving verifyAuthorizationEndpointResultsPane().");
}

// An implicit flow's tokens come back on the authorization response, which is
// the only chance there is to record them: saveTokenSetToHistory() is otherwise
// reached only from a token endpoint call, and this flow makes none. Missing
// from Token History means missing from Currently Viewing and from every
// history_* link as well, so the token set reads as never issued.
async function verifyTokenRecordedInHistories(driver, access_token) {
  log.debug("Entering verifyTokenRecordedInHistories().");
  log.info("Entering verifyTokenRecordedInHistories().");
  // NO Entering/Leaving logging inside this function, or anything it declares.
  // Selenium serialises the function and evaluates it IN THE BROWSER, where
  // there is no bunyan and no `log` — so a log line here is not a log line, it
  // is `javascript error: log is not defined` from executeScript, reported
  // against this test with nothing in the message about the page or the logger.
  // Anything to be logged has to be logged out here, from what the function
  // returns.
  const recorded = await driver.executeScript(function () {
    function parse(key) {
      try {
        return JSON.parse(window.localStorage.getItem(key) || "[]");
      } catch (e) {
        return [];
      }
    }
    var panel = document.getElementById("token-history-panel");
    return {
      tokenHistory: parse("token_history"),
      operations: parse("operation_history")
                        .map(function (o) { return o.operation; }),
      tokenPanelVisible: !!panel &&
          window.getComputedStyle(panel).display !== "none"
    };
  });

  const fromAuthorization = recorded.tokenHistory.filter(function (entry) {
    return entry.source === "authorization";
  });
  assert.strictEqual(fromAuthorization.length, 1,
    "The authorization response's token set should be recorded in Token " +
        "History exactly once. " +
    "Sources found: " + JSON.stringify(recorded.tokenHistory.map(function (e) {
        return e.source; })));
  assert.strictEqual(fromAuthorization[0].access_token, access_token,
    "The recorded token set should hold the access token the flow returned.");
  // The panel is hidden by the page's no-query-string branch, which an implicit
  // response trips: its parameters are in the fragment, so there is no query
  // string to tell the response apart from a page opened fresh.
  assert.ok(recorded.tokenPanelVisible,
    "The Token History panel should be on the screen once it has an entry.");
  assert.ok(recorded.operations.indexOf("Authorization Endpoint") >= 0,
    "Operation History should record the Authorization Endpoint call. " +
        "Operations found: " +
    JSON.stringify(recorded.operations));
  log.info("Leaving verifyTokenRecordedInHistories().");
  log.debug("Leaving verifyTokenRecordedInHistories().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if(headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  // Use /tmp instead of the container's tiny (64MB) /dev/shm, which otherwise
  // crashes the Chrome tab on heavy pages (e.g. jwt_tools) under coverage.
  options.addArguments("--disable-dev-shm-usage");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak,
  // which browsers otherwise block (mixed content / Private Network Access).
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
      "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();

  try {
    const discovery_endpoint = process.env.DISCOVERY_ENDPOINT;
    const client_id = process.env.CLIENT_ID;
    const scope = process.env.SCOPE;
    const user = process.env.USER;

    assert(discovery_endpoint,
           "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");

    // Run the end-to-end implicit flow: load metadata, obtain and verify the
    // access token, then log out
    log.info("Kicking off test.");
    await driver.get(baseUrl + "/oauth2_oidc_1.html");
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    let access_token = await getAccessTokenImplicit(driver, client_id, scope,
        { baseUrl });
    log.info("Access token: " + access_token);
    log.info("Calling verifyAccessToken().");
    await verifyAccessToken(access_token, client_id, scope, { user });
    log.info("Calling verifyFirstPaneRowCollapsed().");
    await verifyFirstPaneRowCollapsed(driver);
    log.info("Calling verifyTokenRecordedInHistories().");
    await verifyTokenRecordedInHistories(driver, access_token);
    // Last of the three: it drives the Expand/Collapse all switch, which leaves
    // every pane expanded — including the row the check above requires
    // collapsed.
    log.info("Calling verifyAuthorizationEndpointResultsPane().");
    await verifyAuthorizationEndpointResultsPane(driver, access_token);
    log.info("Logging out.");
    await logout(driver);
    log.info("Test completed successfully.")
  } catch (error) {
    log.error(error.message);
    process.exit(1);
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name('oauth_authorization_code')
  .description("Run test.")
  .addOption(
    new Option(
      "-u, --url <url>",
      "Set base URL.")
    .makeOptionMandatory()
  )
  .addOption(
    new Option(
      "-b, --browser",
      "Display browser (only works within device).")
  )
  .action((options) => {
    if(!!options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
      logout_post_redirect_uri_value = options.url + "/logout.html";
    }
    if(!!options.browser) {
      log.info("Using browser. headless = false.");
      headless = false;
    }
  });

program.parse(process.argv).opts();

test();
