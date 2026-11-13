// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oauth_scope_engine.js
//
// ---------------------------------------------------------------------------
// The token-request scope, driven in node with no browser and no
// network. scopes_supported is everything an authorization server
// knows, and no request starts from it. An OIDC authorization request
// starts from the OIDC basics the server advertised and an OAuth 2.0
// one from nothing. A code exchange sends no scope (RFC 6749 section
// 4.1.3), a refresh none unless the reader narrowed it (section 6),
// client credentials none of the scopes about a user, and a scope the
// reader typed is kept because the page marks it edited.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments, so
// node ignores that pair. Do not add commander here without declaring
// `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "oauth_scope_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  var i;
  for (i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const REPO = repoRoot();
const SRC = path.join(REPO, "client", "src");
const paths = require("./module_paths.js");
const oauthScope = paths.requireSharedModule(
    [path.join(SRC, "oauth_scope.js")],
    "client/src/oauth_scope.js");

// What iya-sts advertises, including the protected names a client that
// did not declare them must not send.
const ADVERTISED = ["openid", "profile", "email", "offline_access",
    "scim:read", "ssf:read", "admin:read"];
const DUMP = ADVERTISED.join(" ");

function codeLines(source) {
  log.debug("Entering codeLines().");
  var text = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  log.debug("Leaving codeLines().");
  return text;
}

function readSource(name) {
  log.debug("Entering readSource().");
  var text = fs.readFileSync(path.join(SRC, name), "utf8");
  log.debug("Leaving readSource().");
  return text;
}

// tokenRequestScope(grant, stored, edited, authorizationScope,
// scopesSupported). `edited` is the page's persisted mark that the
// reader typed into the field.
function codeExchangeSendsNothing() {
  log.debug("Entering codeExchangeSendsNothing().");
  var grants = ["authorization_code", "oidc_authorization_code_flow",
      "authorization_grant", "device_authorization_grant",
      "implicit_grant"];
  var i;
  for (i = 0; i < grants.length; i++) {
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], DUMP, false, DUMP, ADVERTISED), "",
        grants[i] + " kept a seeded scope");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false, "openid profile email", ADVERTISED), "",
        grants[i] + " prefilled a scope");
  }
  log.info("OK — a code exchange sends no seeded scope.");
  log.debug("Leaving codeExchangeSendsNothing().");
}

// The mark, not the value, decides. A typed value that happens to equal
// a default survives a reload; so does a field the reader emptied.
function aTypedScopeIsKept() {
  log.debug("Entering aTypedScopeIsKept().");
  var grants = ["authorization_code", "refresh_token",
      "client_credentials", "password"];
  var i;
  for (i = 0; i < grants.length; i++) {
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "openid profile", true, "openid profile",
        ADVERTISED), "openid profile",
        grants[i] + " cleared a typed scope equal to the prefill");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], DUMP, true, "openid", ADVERTISED), DUMP,
        grants[i] + " rewrote a typed scope");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", true, "openid", ADVERTISED), "",
        grants[i] + " refilled a field the reader emptied");
  }
  // Not edited: whatever is stored is the page's own earlier prefill,
  // and is replaced.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "password", "calendar.read", false, "openid", ADVERTISED),
      "openid");
  log.info("OK — a scope the reader typed is kept, whatever it is.");
  log.debug("Leaving aTypedScopeIsKept().");
}

function refreshStaysEmptyUnlessEdited() {
  log.debug("Entering refreshStaysEmptyUnlessEdited().");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", DUMP, false, DUMP, ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", "", false, "openid profile email", ADVERTISED),
      "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", "openid", true, DUMP, ADVERTISED), "openid");
  log.info("OK — a refresh omits scope unless the reader narrowed it.");
  log.debug("Leaving refreshStaysEmptyUnlessEdited().");
}

function passwordUsesTheAuthorizationScopeOrBasics() {
  log.debug("Entering passwordUsesTheAuthorizationScopeOrBasics().");
  var grants = ["resource_owner", "password"];
  var i;
  for (i = 0; i < grants.length; i++) {
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false, "", ADVERTISED), "openid profile email",
        grants[i] + " did not fall back to the basics");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false, "calendar.read", ADVERTISED),
        "calendar.read",
        grants[i] + " did not take the authorization-step scope");
  }
  assert.strictEqual(oauthScope.tokenRequestScope(
      "password", "", false, "", ["openid", "profile", "api"]),
      "openid profile");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "password", "", false, "", null), "openid profile email");
  log.info("OK — password prefills from the authorization scope or " +
      "the OIDC basics.");
  log.debug("Leaving passwordUsesTheAuthorizationScopeOrBasics().");
}

// RFC 6749 section 4.4 has no user, so the scopes about one are never
// a client-credentials default, and nothing left means no scope.
function clientCredentialsDropsUserScopes() {
  log.debug("Entering clientCredentialsDropsUserScopes().");
  var grants = ["client_credential", "client_credentials"];
  var i;
  for (i = 0; i < grants.length; i++) {
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false, "openid profile email", ADVERTISED), "",
        grants[i] + " sent the OIDC basics");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false,
        "openid profile email address phone offline_access api",
        ADVERTISED), "api",
        grants[i] + " kept a user-centric scope");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", false, "", ADVERTISED), "",
        grants[i] + " invented a scope");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "openid", true, "", ADVERTISED), "openid",
        grants[i] + " overrode the reader");
  }
  assert.deepStrictEqual(oauthScope.USER_CENTRIC_SCOPES,
      ["openid", "profile", "email", "address", "phone",
       "offline_access"]);
  log.info("OK — client credentials drops the user scopes.");
  log.debug("Leaving clientCredentialsDropsUserScopes().");
}

// OIDC flows start from the basics the server advertised; OAuth 2.0
// flows from nothing. Never the advertisement.
function authorizationScopeIsNeverTheAdvertisement() {
  log.debug("Entering authorizationScopeIsNeverTheAdvertisement().");
  var oidc = ["oidc_authorization_code_flow", "oidc_implicit_flow",
      "oidc_implicit_flow_id_token", "oidc_hybrid_code_id_token",
      "oidc_hybrid_code_token", "oidc_hybrid_code_id_token_token"];
  var oauth = ["authorization_grant", "implicit_grant",
      "resource_owner", "client_credential",
      "device_authorization_grant", "", undefined];
  var i;
  for (i = 0; i < oidc.length; i++) {
    assert.strictEqual(oauthScope.authorizationScope(oidc[i],
        ADVERTISED), "openid profile email", oidc[i]);
    assert.strictEqual(oauthScope.authorizationScope(oidc[i],
        ["openid", "scim:read"]), "openid", oidc[i]);
  }
  for (i = 0; i < oauth.length; i++) {
    assert.strictEqual(oauthScope.authorizationScope(oauth[i],
        ADVERTISED), "", String(oauth[i]));
  }
  log.info("OK — the authorization scope is the OIDC basics or nothing.");
  log.debug("Leaving authorizationScopeIsNeverTheAdvertisement().");
}

function registrationIntersects() {
  log.debug("Entering registrationIntersects().");
  assert.strictEqual(oauthScope.registrationScope(ADVERTISED),
      "openid profile email");
  assert.strictEqual(oauthScope.registrationScope(
      ["openid", "profile", "scim:read"]), "openid profile");
  assert.strictEqual(oauthScope.registrationScope(["api"]), "");
  assert.strictEqual(oauthScope.registrationScope([]), "");
  assert.strictEqual(oauthScope.registrationScope(null),
      "openid profile email");
  assert.strictEqual(oauthScope.registrationScope(""),
      "openid profile email");
  // The comma-separated field and the array are the same list.
  assert.strictEqual(oauthScope.joinAdvertised(
      "openid, profile, email, scim:read"),
      "openid profile email scim:read");
  log.info("OK — a registration asks for the OIDC basics the server " +
      "advertised.");
  log.debug("Leaving registrationIntersects().");
}

function theEngineReachesNoDom() {
  log.debug("Entering theEngineReachesNoDom().");
  var code = codeLines(readSource("oauth_scope.js"));
  var forbidden = ["document", "window", "localStorage",
      "sessionStorage", "jQuery", "DOMPurify", "innerHTML"];
  var i;
  for (i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/oauth_scope.js reaches " + forbidden[i]);
  }
  log.info("OK — the engine reaches no DOM.");
  log.debug("Leaving theEngineReachesNoDom().");
}

function thePagesStopSeedingTheAdvertisement() {
  log.debug("Entering thePagesStopSeedingTheAdvertisement().");
  var page = codeLines(readSource("oauth2_oidc_1.js"));
  var jwks = codeLines(readSource("jwks.js"));
  var step2 = codeLines(readSource("oauth2_oidc_2.js"));
  assert.ok(page.indexOf("oauthScope.tokenRequestScope(") >= 0,
      "oauth2_oidc_1.js does not decide the token-request scope.");
  assert.ok(jwks.indexOf("oauthScope.tokenRequestScope(") >= 0,
      "jwks.js does not decide the token-request scope.");
  assert.ok(step2.indexOf("oauthScope.tokenRequestScope(") >= 0,
      "oauth2_oidc_2.js does not heal a seeded token scope.");
  assert.ok(page.indexOf('setItem("token_scope", scopesSupported') < 0,
      "Populate still stores scopes_supported as token_scope.");
  assert.ok(jwks.indexOf('setItem("token_scope", scopesSupported') < 0,
      "The JWKS populate path still stores scopes_supported as " +
      "token_scope.");
  assert.ok(page.indexOf("scopes_supported.join") < 0,
      "The registration default is still every advertised scope.");
  assert.ok(page.indexOf("discoveryInfo.scopes_supported") >= 0,
      "Scope is no longer taken from discovery at all.");
  assert.ok(page.indexOf('$("#scope").val(scopesSupported)') < 0 &&
      jwks.indexOf('setNamedValue("scope", scopesSupported)') < 0,
      "Populate still seeds the authorization scope with every " +
      "advertised scope.");
  assert.ok(page.indexOf("oauthScope.authorizationScope(") >= 0 &&
      jwks.indexOf("oauthScope.authorizationScope(") >= 0,
      "Populate does not take the authorization scope from the engine.");
  assert.ok(step2.indexOf('markScopeEdited("token_scope_edited")') >= 0 &&
      step2.indexOf('markScopeEdited("refresh_scope_edited")') >= 0,
      "Typing into a scope field is not recorded as an edit.");
  assert.ok(step2.indexOf('scopeEdited("token_scope_edited")') >= 0 &&
      step2.indexOf('scopeEdited("refresh_scope_edited")') >= 0,
      "The reload does not consult the edit marks.");
  assert.ok(step2.indexOf(
      '$("#refresh_scope").val(localStorage.getItem("scope"))') < 0,
      "A successful token call still copies the authorization scope " +
      "into the refresh.");
  assert.ok(step2.indexOf("var scopeLine = $(\"#token_scope\").val();") >=
      0, "The token-request preview no longer reads #token_scope.");
  assert.ok(step2.indexOf("if (scopeLine && grant_type !=") >= 0,
      "The token-request preview still emits an empty scope.");
  assert.ok(step2.indexOf("if (refreshScopeLine)") >= 0,
      "The refresh preview still emits an empty scope.");
  log.info("OK — the pages no longer seed the token request from " +
      "scopes_supported.");
  log.debug("Leaving thePagesStopSeedingTheAdvertisement().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  codeExchangeSendsNothing();
  aTypedScopeIsKept();
  refreshStaysEmptyUnlessEdited();
  passwordUsesTheAuthorizationScopeOrBasics();
  clientCredentialsDropsUserScopes();
  authorizationScopeIsNeverTheAdvertisement();
  registrationIntersects();
  theEngineReachesNoDom();
  thePagesStopSeedingTheAdvertisement();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
