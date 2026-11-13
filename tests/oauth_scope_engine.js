// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oauth_scope_engine.js
//
// ---------------------------------------------------------------------------
// The token-request scope, driven in node with no browser and no
// network. scopes_supported is everything an authorization server
// knows. A code exchange must not send it (RFC 6749 section 4.1.3), a
// refresh must not send it unless the reader narrowed it (section 6),
// and a registration must ask only for the OIDC basics the server
// advertised.
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

function codeExchangeSendsNothing() {
  log.debug("Entering codeExchangeSendsNothing().");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "authorization_code", DUMP, DUMP, ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "oidc_authorization_code_flow", "", "openid profile email",
      ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "authorization_grant", "", DUMP, ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "device_authorization_grant", DUMP, DUMP, ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "implicit_grant", "", "openid", ADVERTISED), "");
  // The reader typed one. It is not the advertisement and not the
  // prefill, so it stays, including on a code exchange.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "authorization_code", "openid", DUMP, ADVERTISED), "openid");
  // The value client credentials would have prefilled is not a scope
  // this grant sends.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "authorization_code", "openid profile email", DUMP, ADVERTISED),
      "");
  log.info("OK — a code exchange sends no seeded scope.");
  log.debug("Leaving codeExchangeSendsNothing().");
}

function refreshStaysEmptyUnlessNarrowed() {
  log.debug("Entering refreshStaysEmptyUnlessNarrowed().");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", DUMP, DUMP, ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", "", "openid profile email", ADVERTISED), "");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", "openid", DUMP, ADVERTISED), "openid");
  // The original grant's own scope, repeated, is not a narrowing.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", "openid profile email offline_access",
      "openid profile email offline_access", ADVERTISED), "");
  // Any order of the whole advertisement is still the dump.
  var reversed = ADVERTISED.slice().reverse().join(" ");
  assert.strictEqual(oauthScope.tokenRequestScope(
      "refresh_token", reversed, DUMP, ADVERTISED), "");
  log.info("OK — a refresh omits scope unless the reader narrowed it.");
  log.debug("Leaving refreshStaysEmptyUnlessNarrowed().");
}

function grantsThatAskUseBasicsOrTheAuthorizationScope() {
  log.debug("Entering grantsThatAskUseBasicsOrTheAuthorizationScope().");
  var grants = ["client_credential", "client_credentials",
      "resource_owner", "password"];
  var i;
  for (i = 0; i < grants.length; i++) {
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "", DUMP, ADVERTISED), "openid profile email",
        grants[i] + " prefilled from the advertisement");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], DUMP, "calendar.read", ADVERTISED),
        "calendar.read",
        grants[i] + " kept the authorization-step scope");
    assert.strictEqual(oauthScope.tokenRequestScope(
        grants[i], "calendar.read", DUMP, ADVERTISED),
        "calendar.read",
        grants[i] + " kept a scope the reader typed");
  }
  // The server did not advertise email. Do not ask for it.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "client_credentials", "", "", ["openid", "profile", "api"]),
      "openid profile");
  // No advertisement at all: the three basics, not an empty string.
  assert.strictEqual(oauthScope.tokenRequestScope(
      "password", "", "", null), "openid profile email");
  log.info("OK — client credentials and password prefill from the " +
      "authorization scope or the OIDC basics.");
  log.debug("Leaving grantsThatAskUseBasicsOrTheAuthorizationScope().");
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
  assert.ok(oauthScope.isAdvertisedDump(
      "email openid profile scim:read",
      ["openid", "profile", "email", "scim:read"]));
  assert.ok(!oauthScope.isAdvertisedDump("openid profile", ADVERTISED));
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
  refreshStaysEmptyUnlessNarrowed();
  grantsThatAskUseBasicsOrTheAuthorizationScope();
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
