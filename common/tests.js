//
// common/tests.js — code shared by the Selenium test scripts in /tests.
//
// The test scripts each used to carry their own near-identical copies of
// populateMetadata(), getAccessToken() and verifyAccessToken(). That logic now
// lives here so it is defined in one place. Where the copies genuinely differed
// (grant-type label, whether a refresh token is returned, which token claims to
// assert) those differences are surfaced as function options rather than baked
// into forked copies.
//
// This module deliberately requires nothing itself. It lives in /common, which
// is outside the reach of tests/node_modules (and of /usr/src/app/node_modules
// in the test container), so a bare require("selenium-webdriver")/require("jsonwebtoken")
// here would fail to resolve. Instead the caller — which already has these in
// scope — injects the Selenium primitives (By, until, Select), the bunyan
// logger, the configured waitTime, and the jwt/assert helpers. Usage:
//
//   const { populateMetadata, getAccessTokenAuthCode, verifyAccessToken } =
//     require("../common/tests.js")({ By, until, Select, waitTime, log, jwt, assert });
//   await populateMetadata(driver, discovery_endpoint);
//
// Note: baseUrl is NOT injected here. Each test script mutates its own baseUrl
// at runtime (via the --url CLI option, parsed after this module is required),
// so the flows that need it take it as a call-time option instead of capturing
// a stale default at require time.
//
module.exports = ({ By, until, Select, waitTime, log, jwt, assert }) => {
  // Resolve once an element is located and visible, then return the locator.
  async function waitForVisibility(driver, element) {
    await driver.wait(until.elementLocated(element), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(element)), waitTime);
    return element;
  }

  async function populateMetadata(driver, discovery_endpoint) {
    log.info("Entering populateMetadata().");
    // Locate the discovery endpoint field and its related buttons
    const oidc_discovery_endpoint = By.id("oidc_discovery_endpoint");
    const btn_oidc_discovery_endpoint = By.className("btn_oidc_discovery_endpoint");
    const btn_oidc_populate_meta_data = By.className("btn_oidc_populate_meta_data");

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
    log.info("Leaving populateMetadata().");
  }

  // Authorization-Code family flow (OAuth2 Authorization Code Grant / OIDC
  // Authorization Code Flow). Drives the debugger authorization form, logs into
  // Keycloak, submits the token-endpoint form, and returns the resulting token.
  //
  // options:
  //   baseUrl              — required; used to build the redirect_uri (mutated at runtime).
  //   grantType            — visible text of the grant to select in the dropdown.
  //   returnRefreshToken   — when true, also capture the refresh token and return
  //                          { access_token, refresh_token } (asserting a refresh
  //                          token was issued); otherwise return access_token.
  async function getAccessTokenAuthCode(driver, client_id, client_secret, scope, pkce_enabled, {
    baseUrl,
    grantType = "OIDC Authorization Code Flow(code)",
    returnRefreshToken = false,
  } = {}) {
    log.info("Entering getAccessTokenAuthCode().");
    const authorization_grant_type = By.id("authorization_grant_type");
    const usePKCE_yes = By.id("usePKCE-yes");
    const usePKCE_no = By.id("usePKCE-no");
    const authz_expand_button = By.id("authz_expand_button");
    const client_id_ = By.id("client_id");
    const scope_ = By.id("scope");
    const token_client_id = By.id("token_client_id");
    const token_client_secret = By.id("token_client_secret");
    const token_scope = By.id("token_scope");
    const btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
    const keycloak_username = By.id("username");
    const keycloak_password = By.id("password");
    const keycloak_kc_login = By.id("kc-login");
    const token_btn = By.className("token_btn");
    const token_access_token = By.id("token_access_token");
    const display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

    // Select the grant type, then choose whether to use PKCE.
    log.info("Set authorization_grant_type to " + grantType + ".");
    await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText(grantType);
    await driver.wait(until.elementLocated(usePKCE_yes), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_yes)), waitTime);
    await driver.wait(until.elementLocated(usePKCE_no), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(usePKCE_no)), waitTime);

    if (pkce_enabled) {
      await driver.findElement(usePKCE_yes).click();
    } else {
      await driver.findElement(usePKCE_no).click();
    }

    // Expand the authorization section and wait for the client_id field.
    await driver.wait(until.elementLocated(authz_expand_button), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
    await driver.findElement(authz_expand_button).click();
    await driver.wait(until.elementLocated(client_id_), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

    // Submit credentials on the authorization form.
    await driver.findElement(client_id_).clear();
    await driver.findElement(client_id_).sendKeys(client_id);
    await driver.findElement(scope_).clear();
    await driver.findElement(scope_).sendKeys(scope);
    const redirect_uri = By.id("redirect_uri");
    await driver.findElement(redirect_uri).clear();
    await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
    await driver.findElement(btn_authorize).click();

    // Login to Keycloak
    try {
      await driver.wait(until.elementLocated(keycloak_username), waitTime);
      await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
    } catch (error) {
      log.error("Unable to log into keycloak.");
      const authz_error_report = await driver.findElement(By.id("authz-error-report"));
      const authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
      throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
    }

    await driver.findElement(keycloak_username).clear();
    await driver.findElement(keycloak_username).sendKeys(client_id);
    await driver.findElement(keycloak_password).clear();
    await driver.findElement(keycloak_password).sendKeys(client_id);
    await driver.findElement(keycloak_kc_login).click();

    // Back on debugger2.html — submit the token-endpoint form.
    await driver.wait(until.elementLocated(token_client_id), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

    await driver.findElement(token_client_id).clear();
    await driver.findElement(token_client_id).sendKeys(client_id);
    await driver.findElement(token_client_secret).clear();
    await driver.findElement(token_client_secret).sendKeys(client_secret);
    await driver.findElement(token_scope).clear();
    await driver.findElement(token_scope).sendKeys(scope);
    const token_redirect_uri = By.id("token_redirect_uri");
    await driver.findElement(token_redirect_uri).clear();
    await driver.findElement(token_redirect_uri).sendKeys(baseUrl + "/callback");
    await driver.findElement(token_btn).click();

    // Wait for whichever appears first: the access token field or the error field.
    let visibleAccessTokenElement = await Promise.any([
      waitForVisibility(driver, token_access_token),
      waitForVisibility(driver, display_token_error_form_textarea1),
    ]);

    let access_token = await driver.findElement(visibleAccessTokenElement).getAttribute("value");
    let response_text = access_token.match(/responseText: (.*)/);
    assert.notStrictEqual(jwt.decode(access_token, { complete: true }), null,
      "Cannot obtain access token. Request result: " + (response_text ? response_text[1] : "no response text"));

    if (returnRefreshToken) {
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

    log.info("Begin returning token.");
    return access_token;
  }

  // Client Credentials grant. No Keycloak login: the token-endpoint form is
  // submitted directly on debugger2.html.
  async function getAccessTokenClientCredentials(driver, client_id, client_secret, scope) {
    log.info("Entering getAccessTokenClientCredentials().");
    const authorization_grant_type = By.id("authorization_grant_type");
    const token_client_id = By.id("token_client_id");

    // Select the Client Credential grant and wait for the token form to render.
    await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Client Credential');
    await driver.wait(until.elementLocated(token_client_id), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

    const token_client_secret = By.id("token_client_secret");
    const token_scope = By.id("token_scope");
    const token_btn = By.className("token_btn");
    const token_access_token = By.id("token_access_token");
    const display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

    // Submit credentials
    await driver.findElement(token_client_id).clear();
    await driver.findElement(token_client_id).sendKeys(client_id);
    await driver.findElement(token_client_secret).clear();
    await driver.findElement(token_client_secret).sendKeys(client_secret);
    await driver.findElement(token_scope).clear();
    await driver.findElement(token_scope).sendKeys(scope);
    await driver.findElement(token_btn).click();

    try {
      let visibleAccessTokenElement = await Promise.any([
        waitForVisibility(driver, token_access_token),
        waitForVisibility(driver, display_token_error_form_textarea1),
      ]);
      log.info("Returning visibleAccessTokenElement value.");
      return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
    } catch (e) {
      log.error("An error occurred: " + e.message);
    }
  }

  // Implicit grant. Logs into Keycloak, then the token is delivered straight to
  // the results pane (no token-endpoint form).
  //
  // options:
  //   baseUrl — required; used to build the redirect_uri (mutated at runtime).
  async function getAccessTokenImplicit(driver, client_id, scope, { baseUrl } = {}) {
    log.info("Entering getAccessTokenImplicit().");
    const authorization_grant_type = By.id("authorization_grant_type");
    const authz_expand_button = By.id("authz_expand_button");
    const client_id_ = By.id("client_id");
    const scope_ = By.id("scope");
    const btn_authorize = By.css("input[type=\"submit\"][value=\"Authorize\"]");
    const keycloak_username = By.id("username");
    const keycloak_password = By.id("password");
    const keycloak_kc_login = By.id("kc-login");
    const token_access_token = By.id("token_access_token");
    const display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

    // Select OAuth2 Implicit Grant
    await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Implicit Grant');

    // Expand the authorization section and wait for the client_id field to render
    await driver.wait(until.elementLocated(authz_expand_button), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(authz_expand_button)), waitTime);
    await driver.findElement(authz_expand_button).click();
    await driver.wait(until.elementLocated(client_id_), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(client_id_)), waitTime);

    // Fill in the client_id, scope, and redirect_uri, then submit the request
    await driver.findElement(client_id_).clear();
    await driver.findElement(client_id_).sendKeys(client_id);
    await driver.findElement(scope_).clear();
    await driver.findElement(scope_).sendKeys(scope);
    const redirect_uri = By.id("redirect_uri");
    await driver.findElement(redirect_uri).clear();
    await driver.findElement(redirect_uri).sendKeys(baseUrl + "/callback");
    await driver.findElement(btn_authorize).click();

    // Wait for the Keycloak login form, reporting any authorization error if it never appears
    try {
      await driver.wait(until.elementLocated(keycloak_username), waitTime);
      await driver.wait(until.elementIsVisible(driver.findElement(keycloak_username)), waitTime);
    } catch (error) {
      log.error("Unable to log into keycloak.");
      const authz_error_report = await driver.findElement(By.id("authz-error-report"));
      const authz_error_report_paragraphs = await authz_error_report.findElements(By.css("p"));
      throw new Error(await authz_error_report_paragraphs[authz_error_report_paragraphs.length - 1].getText());
    }

    // Enter the Keycloak username/password and submit the login form
    await driver.findElement(keycloak_username).clear();
    await driver.findElement(keycloak_username).sendKeys(client_id);
    await driver.findElement(keycloak_password).clear();
    await driver.findElement(keycloak_password).sendKeys(client_id);
    await driver.findElement(keycloak_kc_login).click();

    // Wait for whichever appears first: the access token field or the error field.
    let visibleAccessTokenElement = await Promise.any([
      waitForVisibility(driver, token_access_token),
      waitForVisibility(driver, display_token_error_form_textarea1),
    ]);

    log.info("Begin returning token.");
    return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  }

  // Resource Owner Password Credentials grant. Configures the debugger2.html
  // token form (OIDC-artifacts off, PKCE off, POST auth style, back-end
  // initiation) and submits username/password directly.
  async function getAccessTokenPassword(driver, client_id, client_secret, scope, username, password) {
    log.info("Entering getAccessTokenPassword().");

    // Select Resource Owner Password Credential grant type on debugger.html
    const authorization_grant_type = By.id("authorization_grant_type");
    await driver.wait(until.elementLocated(authorization_grant_type), waitTime);
    await new Select(await driver.findElement(authorization_grant_type)).selectByVisibleText('OAuth2 Resource Owner Password Credential Grant');

    // Wait for debugger2.html to load
    const token_client_id = By.id("token_client_id");
    await driver.wait(until.elementLocated(token_client_id), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_client_id)), waitTime);

    // Select OIDC No
    const noCheckOIDCArtifacts = By.id("noCheckOIDCArtifacts");
    await driver.wait(until.elementLocated(noCheckOIDCArtifacts), waitTime);
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(noCheckOIDCArtifacts));
    await driver.findElement(noCheckOIDCArtifacts).click();

    // Select PKCE No
    const usePKCENo = By.id("usePKCE-no");
    await driver.wait(until.elementLocated(usePKCENo), waitTime);
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(usePKCENo));
    await driver.findElement(usePKCENo).click();

    // Collapse config pane
    const config_expand_button = By.id("config_expand_button");
    await driver.wait(until.elementLocated(config_expand_button), waitTime);
    const configBtnEl = await driver.findElement(config_expand_button);
    const configBtnVal = await configBtnEl.getAttribute("value");
    if (configBtnVal === "Hide") {
      await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", configBtnEl);
      await configBtnEl.click();
    }

    // Select POST auth style
    const token_postAuthStyleCheckToken = By.id("token_postAuthStyleCheckToken");
    await driver.wait(until.elementLocated(token_postAuthStyleCheckToken), waitTime);
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_postAuthStyleCheckToken));
    await driver.findElement(token_postAuthStyleCheckToken).click();

    // Select Back-end initiation
    const token_initiateFromBackEnd = By.id("token_initiateFromBackEnd");
    await driver.wait(until.elementLocated(token_initiateFromBackEnd), waitTime);
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_initiateFromBackEnd));
    await driver.findElement(token_initiateFromBackEnd).click();

    // Fill in credentials
    await driver.findElement(token_client_id).clear();
    await driver.findElement(token_client_id).sendKeys(client_id);

    const token_client_secret = By.id("token_client_secret");
    await driver.findElement(token_client_secret).clear();
    await driver.findElement(token_client_secret).sendKeys(client_secret);

    const token_scope = By.id("token_scope");
    await driver.findElement(token_scope).clear();
    await driver.findElement(token_scope).sendKeys(scope);

    const token_username = By.id("token_username");
    await driver.wait(until.elementLocated(token_username), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_username)), waitTime);
    await driver.findElement(token_username).clear();
    await driver.findElement(token_username).sendKeys(client_id);

    const token_password = By.id("token_password");
    await driver.wait(until.elementLocated(token_password), waitTime);
    await driver.wait(until.elementIsVisible(driver.findElement(token_password)), waitTime);
    await driver.findElement(token_password).clear();
    await driver.findElement(token_password).sendKeys(password);

    // Click Get Token
    const token_btn = By.className("token_btn");
    await driver.executeScript("arguments[0].scrollIntoView({ behavior: 'smooth', block: 'center' });", await driver.findElement(token_btn));
    await driver.findElement(token_btn).click();

    const token_access_token = By.id("token_access_token");
    const display_token_error_form_textarea1 = By.id("display_token_error_form_textarea1");

    let visibleAccessTokenElement = await Promise.any([
      waitForVisibility(driver, token_access_token),
      waitForVisibility(driver, display_token_error_form_textarea1),
    ]);

    log.info("Begin returning token.");
    return await driver.findElement(visibleAccessTokenElement).getAttribute("value");
  }

  // Decode the access token JWT and assert its claims. The base assertions
  // (decodable, client id claim, scope) apply everywhere; the rest are opt-in so
  // each grant type asserts only what it expects.
  //
  // options:
  //   user                 — assert payload.sub === user (skipped when omitted).
  //   audience             — assert payload.aud === audience (skipped when omitted).
  //   issuer               — assert payload.iss === issuer (skipped when omitted).
  //   clientIdClaim        — which claim carries the client id ("azp" by default,
  //                          "client_id" for the client-credentials grant).
  //   verifyIdentityClaims — assert given_name/family_name/email (default true).
  //   verifyTyp            — assert payload.typ === "Bearer" (default false).
  async function verifyAccessToken(access_token, client_id, scope, {
    user,
    audience,
    issuer,
    clientIdClaim = "azp",
    verifyIdentityClaims = true,
    verifyTyp = false,
  } = {}) {
    async function compareScopes(scope1, scope2) {
      scope1 = scope1.split(" ");
      scope2 = scope2.split(" ");

      return scope2.every(element => scope1.includes(element));
    }

    // Decode the JWT and assert its claims match what the flow expects
    let decoded_access_token = jwt.decode(access_token, { complete: true });
    let response_text = access_token.match(/responseText: (.*)/);

    assert.notStrictEqual(decoded_access_token, null, "Cannot decode access token. Request result: " + (response_text ? response_text[1] : "no response text"));
    assert.strictEqual(decoded_access_token.payload[clientIdClaim], client_id, "Access token " + clientIdClaim + " does not match client ID.");
    assert.strictEqual(await compareScopes(decoded_access_token.payload.scope, scope), true, "Access token scope does not match scope.");
    if (user !== undefined) {
      assert.strictEqual(decoded_access_token.payload.sub, user, "Access token SUB does not match user ID: access_token.payload.sub=" + decoded_access_token.payload.sub + " , user=" + user);
    }
    if (audience !== undefined) {
      assert.strictEqual(decoded_access_token.payload.aud, audience, "Access token aud does not match " + audience);
    }
    if (issuer !== undefined) {
      assert.strictEqual(decoded_access_token.payload.iss, issuer, "Access token iss does not match " + issuer);
    }
    if (verifyIdentityClaims) {
      assert.strictEqual(decoded_access_token.payload.given_name, client_id, "Access token given_name does not match.");
      assert.strictEqual(decoded_access_token.payload.family_name, client_id, "Access token family_name does not match.");
      assert.strictEqual(decoded_access_token.payload.email, `${client_id}@iyasec.io`, "Access token email does not match.");
    }
    if (verifyTyp) {
      assert.strictEqual(decoded_access_token.payload.typ, "Bearer", "Access Token typ does not match.");
    }
  }

  return {
    populateMetadata,
    getAccessTokenAuthCode,
    getAccessTokenClientCredentials,
    getAccessTokenImplicit,
    getAccessTokenPassword,
    verifyAccessToken,
  };
};
