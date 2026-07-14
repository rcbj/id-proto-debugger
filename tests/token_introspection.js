const { Builder, By, until, logging } = require("selenium-webdriver");
const { Select } = require('selenium-webdriver/lib/select');
const chrome = require("selenium-webdriver/chrome");
const jwt = require("jsonwebtoken");
const assert = require("assert");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'token_introspection',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());
var baseUrl = "http://localhost:3000"

// The public static-content deployments (test.idptools.com / idptools.com) have
// no api backend, and Keycloak's introspection endpoint is not CORS-enabled, so
// a browser introspection call is blocked. Against those targets the test
// EXPECTS that CORS/network error instead of an active introspection result.
var STATIC_CONTENT_SITE_HOSTS = ["test.idptools.com", "idptools.com"];
function isStaticContentSite(url) {
  try {
    return STATIC_CONTENT_SITE_HOSTS.includes(new URL(url).hostname);
  } catch (e) {
    return false;
  }
}
var headless = true;
var waitTime = appconfig.waitTime;

async function populateMetadata(driver, discovery_endpoint) {
  oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
  btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
  btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

  // Wait until page is loaded
  await driver.wait(until.elementLocated(oidc_discovery_endpoint), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(oidc_discovery_endpoint)), waitTime);

  // Enter discovery endpoint
  await driver.findElement(oidc_discovery_endpoint).clear();
  await driver.findElement(oidc_discovery_endpoint).sendKeys(discovery_endpoint);
  await driver.findElement(btn_oidc_discovery_endpoint).click();

  // Populate metadata
  await driver.wait(until.elementLocated(btn_oidc_populate_meta_data), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(btn_oidc_populate_meta_data)), waitTime);
  await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(btn_oidc_populate_meta_data));
  await driver.findElement(btn_oidc_populate_meta_data).click();
}

// Sign in via the OIDC Authorization Code Flow (with PKCE for the public
// client) and return the access + refresh tokens. This leaves the debugger2
// page rendered with the "Token Endpoint Results" pane, whose access/refresh
// rows each carry an "Introspect Token" link.
async function getAccessToken(driver, client_id, client_secret, scope, pkce_enabled) {
  log.info("Entering getAccessToken().");
  authorization_grant_type = By.id("authorization_grant_type");
  usePKCE_yes = By.id("usePKCE-yes");
  usePKCE_no = By.id("usePKCE-no");
  authz_expand_button = By.id("authz_expand_button");
  client_id_ = By.id("client_id");
  scope_ = By.id("scope");
  token_client_id = By.id("token_client_id");
  token_client_secret = By.id("token_client_secret");
  token_scope = By.id("token_scope");
  btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
  keycloak_username = By.id("username");
  keycloak_password = By.id("password");
  keycloak_kc_login = By.id("kc-login");
  token_btn = By.className("token_btn");
  token_access_token = By.id("token_access_token");
  display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

  // Select OIDC authorization code flow login type
  log.info("Set authorization_grant_type to OIDC Authorization Code Flow(code).");
  await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OIDC Authorization Code Flow(code)');
  await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
  await driver.wait(until.elementLocated(usePKCE_no), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

  if (pkce_enabled) {
    await driver.findElement(usePKCE_yes).click();
  } else {
    await driver.findElement(usePKCE_no).click();
  }

  await driver.wait(until.elementLocated(authz_expand_button), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
  await driver.findElement(authz_expand_button).click();
  await driver.wait(until.elementLocated(client_id_), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

  // Submit credentials
  await driver.findElement(client_id_).clear();
  await driver.findElement(client_id_).sendKeys(client_id);
  await driver.findElement(scope_).clear();
  await driver.findElement(scope_).sendKeys(scope);
  redirect_uri = By.id("redirect_uri");
  await driver.findElement(redirect_uri).clear();
  await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(btn_authorize).click();

  // Login to Keycloak
  try {
    await driver.wait(until.elementLocated(keycloak_username), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
  } catch (error) {
    log.error("Unable to log into keycloak.");
    authz_error_report = await driver.findElement(By.id("authz-error-report"));
    authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
    throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
  }

  await driver.findElement(keycloak_username).clear();
  await driver.findElement(keycloak_username).sendKeys(client_id);
  await driver.findElement(keycloak_password).clear();
  await driver.findElement(keycloak_password).sendKeys(client_id);
  await driver.findElement(keycloak_kc_login).click();

  // Submit credentials (again) on the token endpoint form
  await driver.wait(until.elementLocated(token_client_id), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

  await driver.findElement(token_client_id).clear();
  await driver.findElement(token_client_id).sendKeys(client_id);
  await driver.findElement(token_client_secret).clear();
  await driver.findElement(token_client_secret).sendKeys(client_secret);
  await driver.findElement(token_scope).clear();
  await driver.findElement(token_scope).sendKeys(scope);
  token_redirect_uri = By.id("token_redirect_uri");
  await driver.findElement(token_redirect_uri).clear();
  await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
  await driver.findElement(token_btn).click();

  // Get access token result
  async function waitForVisibility(element) {
    await driver.wait(until.elementLocated(element), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    return element;
  }

  let visibleAccessTokenElement = await Promise.any([
    waitForVisibility(token_access_token),
    waitForVisibility(display_token_error_form_textarea1)
  ]);

  let access_token = await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  let response_text = access_token.match(/responseText: (.*)/);
  assert.notStrictEqual(jwt.decode(access_token, { complete: true }), null,
    "Cannot obtain access token. Request result: " + (response_text ? response_text[1] : "no response text"));

  // Capture the refresh token from the Token Endpoint results pane.
  let refresh_token = "";
  try {
    refresh_token = await driver.findElement(By.id("token_refresh_token")).getAttribute("value");
  } catch (e) {
    log.warn("No refresh token element found.");
  }
  assert(refresh_token && refresh_token.length > 0,
    "No refresh token was returned. Ensure the scope includes offline_access.");

  log.info("Obtained access token and refresh token.");
  return { access_token, refresh_token };
}

// Exchange the refresh token for a fresh token set by driving the "Get Token"
// button in the Refresh Token pane. This renders the "Token Endpoint Results
// for Refresh Token Call" pane, whose latest-access/latest-refresh rows each
// carry an "Introspect Token" link (type=refresh_access / refresh_refresh).
async function refreshTokenCall(driver, client_secret) {
  log.info("Making a refresh token call to populate the refresh-call token panes.");

  // The refresh grant authenticates as the (confidential) client, so it needs
  // the client secret. The refresh pane pre-fills #refresh_client_secret from
  // localStorage("client_secret"), which is only written on the authorization
  // page and is therefore empty here — set it explicitly so Keycloak does not
  // reject the refresh with "unauthorized_client".
  if (!!client_secret) {
    const secretField = await driver.findElement(By.id("refresh_client_secret"));
    await driver.executeScript("arguments[0].value = arguments[1];", secretField, client_secret);
  }

  const refresh_btn = By.id("refresh_btn");
  await driver.wait(until.elementLocated(refresh_btn), waitTime);
  const btnEl = await driver.findElement(refresh_btn);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", btnEl);
  await driver.wait(until.elementIsVisible(btnEl), waitTime);
  await btnEl.click();

  // Wait for the latest access token to be populated by the refresh response.
  // Use a generous timeout independent of waitTime: this is a network round
  // trip to the token endpoint, not a local DOM wait.
  const refresh_access_token = By.id("refresh_access_token");
  const refreshTimeout = Math.max(waitTime, 15000);
  await driver.wait(until.elementLocated(refresh_access_token), refreshTimeout);
  await driver.wait(async () => {
    try {
      const v = await driver.findElement(refresh_access_token).getAttribute("value");
      return !!v && jwt.decode(v, { complete: true }) !== null;
    } catch (e) {
      return false;
    }
  }, refreshTimeout, "Refresh token call did not produce a new access token.");
  log.info("Refresh token call completed; latest access/refresh tokens are available.");
}

// Activate a Token History entry so the "Currently Viewing" pane renders. That
// pane's access/refresh rows carry the two history introspect links
// (type=history_access / history_refresh, with a generation index). Returns
// the activated index.
async function activateTokenHistoryEntry(driver, index) {
  log.info("Activating Token History entry index=" + index + ".");
  const activateBtn = By.css(`#token-history-panel input[type='button'][value='Activate'][onclick*='selectTokenSet(${index})']`);
  await driver.wait(until.elementLocated(activateBtn), waitTime);
  const btnEl = await driver.findElement(activateBtn);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", btnEl);
  await driver.wait(until.elementIsVisible(btnEl), waitTime);
  await btnEl.click();

  // The Currently Viewing pane should now expose the history introspect links.
  await driver.wait(until.elementLocated(
    By.css(`a[href="/introspection.html?type=history_access&generation=${index}"]`)), waitTime);
  log.info("Token History entry activated; Currently Viewing pane rendered.");
  return index;
}

// Follows the "Introspect Token" link identified by its full type query (e.g.
// "access", "refresh_access", or "history_refresh&generation=1"), runs the
// introspection on introspection.html authenticating as the confidential
// client (via HTTP Basic, through the backend to avoid browser CORS
// restrictions), and returns the raw introspection output JSON string.
async function introspectTokenViaUI(driver, type, client_id, client_secret) {
  log.info("Introspecting token via UI. type=" + type);

  // Click the "Introspect Token" link rendered next to the token field.
  const link = By.css(`a[href="/introspection.html?type=${type}"]`);
  await driver.wait(until.elementLocated(link), waitTime);
  const linkEl = await driver.findElement(link);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", linkEl);
  await linkEl.click();

  // We are now on introspection.html. Configure client authentication.
  const clientIdField = By.id("introspection_client_id");
  await driver.wait(until.elementLocated(clientIdField), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(clientIdField)), waitTime);

  // The link should have pre-populated the correct token to be introspected.
  // Every token the six links reference (access, refresh/offline, and their
  // refresh-call and history variants) is a Keycloak JWT, so a successful
  // decode confirms the link carried a real token rather than an empty value.
  const introspectionToken = await driver.findElement(By.id("introspection_token")).getAttribute("value");
  assert(introspectionToken && introspectionToken.length > 0,
    "The Introspect Token link for type=" + type + " did not populate a token.");
  assert.notStrictEqual(jwt.decode(introspectionToken, { complete: true }), null,
    "The Introspect Token link for type=" + type + " populated a value that is not a decodable token.");

  // The introspection endpoint should have been populated from the discovery
  // document when the metadata was loaded.
  const endpointValue = await driver.findElement(By.id("introspection_endpoint")).getAttribute("value");
  assert(endpointValue && endpointValue.length > 0,
    "Introspection endpoint was not populated from the discovery document.");

  // Use the backend to avoid browser CORS restrictions on the IdP.
  await driver.findElement(By.id("introspection_initiateFromBackEnd")).click();

  // Authenticate the client via HTTP Basic with its credentials.
  await new Select(await driver.findElement(By.id("introspection_authentication_type"))).selectByValue("basic_auth");
  await driver.findElement(clientIdField).clear();
  await driver.findElement(clientIdField).sendKeys(client_id);
  const clientSecretField = await driver.findElement(By.id("introspection_client_secret"));
  await clientSecretField.clear();
  if (!!client_secret) {
    await clientSecretField.sendKeys(client_secret);
  }

  // Trigger the introspection call.
  await driver.findElement(By.css('input[value="Introspect Token"]')).click();

  // Wait for the output textarea to be populated.
  const output = By.id("introspection_output");
  await driver.wait(async () => {
    try {
      const v = (await driver.findElement(output).getAttribute("value") || "").trim();
      return v.length > 0;
    } catch (e) {
      return false;
    }
  }, waitTime, "Introspection produced no output for type=" + type);

  const outputText = (await driver.findElement(output).getAttribute("value") || "").trim();
  log.info("Introspection output (" + type + "): " + outputText.replace(/\n/g, " "));
  return outputText;
}

// Asserts that clicking an "Introspect Token" link produced a working call to
// the Token Introspection endpoint: the Introspection Output text box holds
// valid JSON containing "active": true (RFC 7662). Anything else — non-JSON
// output, a missing "active" field, or active=false — means something is wrong
// and the test fails.
function assertIntrospectionActive(outputText, type) {
  let parsed = null;
  try {
    parsed = JSON.parse(outputText);
  } catch (e) {
    parsed = null;
  }
  assert(parsed !== null,
    "Introspection output for the " + type + " link was not valid JSON: " + outputText);

  // On the static-content deployments there is no backend and Keycloak's
  // introspection endpoint is not CORS-enabled, so the browser call is blocked.
  // Expect that CORS/network error (readyState 0 / status 0 / status "error")
  // rather than an active introspection result.
  if (isStaticContentSite(baseUrl)) {
    assert(parsed.status === "error" && parsed.request && parsed.request.status === 0,
      "Introspection for the " + type + " link on a static site was expected to be blocked " +
      "by CORS (status 0 error), but got: " + outputText);
    log.info("Introspection was blocked by CORS as expected on the static site. type=" + type);
    return;
  }

  assert.strictEqual(parsed.active, true,
    "Introspection for the " + type + " link did not report the token as active (expected \"active\": true). Output: " + outputText);
  log.info("Introspect Token link produced a valid active introspection. type=" + type);
}

// Returns from introspection.html to debugger2.html via the "Return to
// debugger" link, then confirms the debugger2 page reloaded and the access
// token is visible in the Token Endpoint Results pane (re-rendered from local
// storage).
async function returnToDebugger(driver) {
  log.info("Clicking the 'Return to debugger' link.");
  const link = By.css('a[href="/debugger2.html?redirectFromTokenDetail=true"]');
  await driver.wait(until.elementLocated(link), waitTime);
  await driver.findElement(link).click();

  // Confirm debugger2 loaded and the access token is visible.
  const token_access_token = By.id("token_access_token");
  await driver.wait(until.elementLocated(token_access_token), waitTime);
  await driver.wait(until.elementIsVisible(driver.findElement(token_access_token)), waitTime);
  const accessTokenValue = await driver.findElement(token_access_token).getAttribute("value");
  assert(accessTokenValue && accessTokenValue.length > 0,
    "After returning to the debugger, the access token was not visible on the debugger2 page.");
  log.info("Debugger2 page loaded and the access token is visible.");
}

async function test() {
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless");
  }
  options.addArguments("--no-sandbox");
  // Test-only: allow a deployed HTTPS debugger (e.g. https://test.idptools.com)
  // to make discovery/token XHRs to a plaintext http://localhost Keycloak, which
  // browsers otherwise block (mixed content / Private Network Access).
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");
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
    // Public (PKCE) clients may have no secret; treat it as optional.
    const client_secret = process.env.CLIENT_SECRET || "";
    const scope = process.env.SCOPE;
    const user = process.env.USER;
    let pkce_enabled = process.env.PKCE_ENABLED;
    // The Token Introspection Endpoint must be called by a client that is
    // permitted to introspect. The public/PKCE client used to obtain the tokens
    // is not, so introspection authenticates as the confidential client.
    const introspection_client_id = process.env.INTROSPECTION_CLIENT_ID;
    const introspection_client_secret = process.env.INTROSPECTION_CLIENT_SECRET;

    assert(discovery_endpoint, "DISCOVERY_ENDPOINT environment variable is not set.");
    assert(client_id, "CLIENT_ID environment variable is not set.");
    assert(scope, "SCOPE environment variable is not set.");
    assert(user, "USER environment variable is not set.");
    assert(pkce_enabled, "PKCE_ENABLED environment variable is not set.");
    assert(introspection_client_id, "INTROSPECTION_CLIENT_ID environment variable is not set.");
    assert(introspection_client_secret, "INTROSPECTION_CLIENT_SECRET environment variable is not set.");

    if (pkce_enabled === "true") {
      pkce_enabled = true;
    } else if (pkce_enabled === "false") {
      pkce_enabled = false;
    } else {
      log.info("PKCE_ENABLED must be true or false.");
      process.exit(1);
    }

    // Load the debugger, populate IdP metadata from discovery, and run the
    // OIDC Authorization Code flow to obtain an access token and refresh token.
    log.info("Kicking off test.");
    await driver.get(baseUrl);
    log.info("Calling populateMetadata().");
    await populateMetadata(driver, discovery_endpoint);
    log.info("Calling getAccessToken().");
    const { access_token, refresh_token } = await getAccessToken(driver, client_id, client_secret, scope, pkce_enabled);
    assert(access_token, "No access token was retrieved.");
    assert(refresh_token, "No refresh token was retrieved.");

    // The debugger renders SIX distinct "Introspect Token" links across three
    // panes. For each one: click it, confirm the Introspection Output holds
    // valid JSON with "active": true, then follow "Return to debugger" and
    // confirm debugger2 reloads with the access token visible.
    //
    // Order matters: the initial access/refresh tokens are introspected BEFORE
    // the refresh call, because refreshing rotates the refresh token and would
    // invalidate the original one.

    // 1 & 2 — Token Endpoint Results pane (initial access + refresh tokens).
    log.info("[1/6] Introspecting the Token Endpoint access token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "access", introspection_client_id, introspection_client_secret), "access");
    await returnToDebugger(driver);

    log.info("[2/6] Introspecting the Token Endpoint refresh token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "refresh", introspection_client_id, introspection_client_secret), "refresh");
    await returnToDebugger(driver);

    // Exchange the refresh token for a fresh token set to populate the
    // refresh-call pane (and add a second Token History entry).
    await refreshTokenCall(driver, client_secret);

    // 3 & 4 — Refresh call results pane (latest access + refresh tokens).
    log.info("[3/6] Introspecting the refresh-call latest access token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "refresh_access", introspection_client_id, introspection_client_secret), "refresh_access");
    await returnToDebugger(driver);

    log.info("[4/6] Introspecting the refresh-call latest refresh token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "refresh_refresh", introspection_client_id, introspection_client_secret), "refresh_refresh");
    await returnToDebugger(driver);

    // 5 & 6 — Currently Viewing pane, reached by activating a Token History
    // entry. Activate the most recent entry (index 1, from the refresh call) so
    // both of its tokens are still valid.
    const generation = await activateTokenHistoryEntry(driver, 1);

    log.info("[5/6] Introspecting the Token History access token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "history_access&generation=" + generation, introspection_client_id, introspection_client_secret), "history_access");
    // Returning to the debugger re-renders the Currently Viewing pane from the
    // persisted active index, so the history refresh link is present again
    // without needing to re-activate the entry.
    await returnToDebugger(driver);

    log.info("[6/6] Introspecting the Token History refresh token link.");
    assertIntrospectionActive(await introspectTokenViaUI(driver, "history_refresh&generation=" + generation, introspection_client_id, introspection_client_secret), "history_refresh");
    await returnToDebugger(driver);

    log.info("All six Introspect Token links produced a valid active introspection and returned to the debugger.");
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
  .name('token_introspection')
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
