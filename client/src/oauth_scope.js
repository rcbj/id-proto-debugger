// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: oauth_scope.js
//
// ---------------------------------------------------------------------------
// What scope an authorization request, a token request, a refresh, and
// a dynamic registration may start from.
//
// scopes_supported is everything the authorization server knows about.
// It is the right thing to SHOW, and the wrong thing to SEND: a code
// exchange has no scope parameter at all (RFC 6749 section 4.1.3), a
// refresh that omits scope asks for the original grant (section 6), and
// a client-credentials or password grant — or a registration — that
// names every advertised scope asks for privileges this client was
// never given. Servers that issue a scope only to a client that
// declared it answer invalid_scope, and the token response is never
// drawn.
//
// The OIDC basics (openid, profile, email), limited to what the server
// advertised, are what an OIDC authorization request and a registration
// start from. An OAuth 2.0 authorization request starts from nothing.
// Password starts from the authorization scope or the basics. Client
// credentials starts from the authorization scope without the scopes
// that only mean something about a user, and sends none when nothing is
// left. A value the reader typed is kept whatever it is: the page
// records that the field was edited and passes that fact in, rather
// than guessing it from the value. No DOM.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "oauth_scope",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The three scopes an ordinary OpenID Connect client asks for. Not a
// substitute for scopes_supported: the intersection is.
var OIDC_BASIC_SCOPES = ["openid", "profile", "email"];

// Scopes about the person who signed in. A client-credentials grant
// has no such person (RFC 6749 section 4.4), so these are never its
// default.
var USER_CENTRIC_SCOPES = ["openid", "profile", "email", "address",
  "phone", "offline_access"];

// Grants whose token request carries a scope. The authorization-code
// grant does not (RFC 6749 section 4.1.3), and neither does a refresh
// unless the reader narrows it (section 6). The page-1 select and the
// token grant_type spell the same two grants differently.
function scopeOnTokenRequest(grant) {
  log.debug("Entering scopeOnTokenRequest().");
  var on = isClientCredentials(grant) || isPassword(grant);
  log.debug("Leaving scopeOnTokenRequest().");
  return on;
}

function isClientCredentials(grant) {
  log.debug("Entering isClientCredentials().");
  var on = grant === "client_credential" ||
      grant === "client_credentials";
  log.debug("Leaving isClientCredentials().");
  return on;
}

function isPassword(grant) {
  log.debug("Entering isPassword().");
  var on = grant === "resource_owner" || grant === "password";
  log.debug("Leaving isPassword().");
  return on;
}

// The page-1 select's OpenID Connect flows all start "oidc_".
function isOidcFlow(grant) {
  log.debug("Entering isOidcFlow().");
  var on = typeof grant === "string" && grant.indexOf("oidc_") === 0;
  log.debug("Leaving isOidcFlow().");
  return on;
}

// One scope string, an array, or a comma-separated field, as names.
function scopeNames(value) {
  log.debug("Entering scopeNames().");
  if (value == null || value === "") {
    log.debug("Leaving scopeNames().");
    return [];
  }
  var names;
  if (Array.isArray(value)) {
    names = value.map(function (item) {
      return String(item).trim();
    });
  } else {
    names = String(value).split(/[\s,]+/);
  }
  var out = [];
  var i;
  for (i = 0; i < names.length; i++) {
    if (names[i]) {
      out.push(names[i]);
    }
  }
  log.debug("Leaving scopeNames().");
  return out;
}

// The advertisement, in the order it was published, as one scope string.
function joinAdvertised(scopesSupported) {
  log.debug("Entering joinAdvertised().");
  var joined = scopeNames(scopesSupported).join(" ");
  log.debug("Leaving joinAdvertised().");
  return joined;
}

// openid profile email, limited to what the server advertised. No
// advertisement at all keeps the three; an advertisement that contains
// none of them is the empty string, and the caller omits scope.
function registrationScope(scopesSupported) {
  log.debug("Entering registrationScope().");
  if (scopesSupported == null || scopesSupported === "") {
    log.debug("Leaving registrationScope(). No advertisement.");
    return OIDC_BASIC_SCOPES.join(" ");
  }
  var advertised = scopeNames(scopesSupported);
  var basics = OIDC_BASIC_SCOPES.filter(function (name) {
    return advertised.indexOf(name) >= 0;
  });
  log.debug("Leaving registrationScope().");
  return basics.join(" ");
}

// The authorization request's starting scope. An OIDC flow asks for
// the basics the server advertised; an OAuth 2.0 flow names no scope
// of its own, so it starts empty. Never the whole advertisement.
function authorizationScope(grant, scopesSupported) {
  log.debug("Entering authorizationScope().");
  var scope = isOidcFlow(grant) ? registrationScope(scopesSupported) : "";
  log.debug("Leaving authorizationScope().");
  return scope;
}

// The authorization scope without the names that are about a user.
function withoutUserScopes(value) {
  log.debug("Entering withoutUserScopes().");
  var kept = scopeNames(value).filter(function (name) {
    return USER_CENTRIC_SCOPES.indexOf(name) < 0;
  });
  log.debug("Leaving withoutUserScopes().");
  return kept.join(" ");
}

// What a grant prefills when the reader has not edited the field.
// Client credentials: the authorization scope less the user scopes, or
// nothing. Password: the authorization scope, or the OIDC basics. A
// code exchange and a refresh: nothing.
function prefilledScope(grant, authorizationScopeValue, scopesSupported) {
  log.debug("Entering prefilledScope().");
  var authz = scopeNames(authorizationScopeValue).join(" ");
  var scope = "";
  if (isClientCredentials(grant)) {
    scope = withoutUserScopes(authz);
  } else if (isPassword(grant)) {
    scope = authz || registrationScope(scopesSupported);
  }
  log.debug("Leaving prefilledScope().");
  return scope;
}

// The scope a token request or a refresh should carry.
//
//   grant               page-1 select value, or the token grant_type
//   stored              what the field (or localStorage) already holds
//   edited              true when the reader typed into the field
//   authorizationScope  the authorization request's scope
//   scopesSupported     the provider's scopes_supported, in any of the
//                       shapes scopeNames() accepts
//
// An edited field is kept exactly, empty included. Otherwise the
// grant's prefill: the value is the page's, so it follows the grant
// and the advertisement rather than an earlier visit.
function tokenRequestScope(grant, stored, edited, authorizationScopeValue,
    scopesSupported) {
  log.debug("Entering tokenRequestScope().");
  if (edited) {
    var kept = stored == null ? "" : String(stored);
    log.debug("Leaving tokenRequestScope(). Edited by the reader.");
    return kept;
  }
  var prefilled = prefilledScope(grant, authorizationScopeValue,
      scopesSupported);
  log.debug("Leaving tokenRequestScope().");
  return prefilled;
}

module.exports = {
  OIDC_BASIC_SCOPES: OIDC_BASIC_SCOPES,
  USER_CENTRIC_SCOPES: USER_CENTRIC_SCOPES,
  scopeOnTokenRequest: scopeOnTokenRequest,
  isOidcFlow: isOidcFlow,
  scopeNames: scopeNames,
  joinAdvertised: joinAdvertised,
  registrationScope: registrationScope,
  authorizationScope: authorizationScope,
  prefilledScope: prefilledScope,
  tokenRequestScope: tokenRequestScope
};
