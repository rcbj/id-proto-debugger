// File: oauth_scope.js
//
// ---------------------------------------------------------------------------
// What scope a token request, a refresh, and a dynamic registration may
// start from.
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
// The OIDC basics (openid, profile, email) are what those two grants
// and a registration may prefill with, and only the ones the server
// actually advertised. A value the reader typed is kept. No DOM.
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

// Grants whose token request carries a scope. The authorization-code
// grant does not (RFC 6749 section 4.1.3), and neither does a refresh
// unless the reader narrows it (section 6). The page-1 select and the
// token grant_type spell the same two grants differently.
function scopeOnTokenRequest(grant) {
  log.debug("Entering scopeOnTokenRequest().");
  var on = grant === "client_credential" ||
      grant === "client_credentials" ||
      grant === "resource_owner" ||
      grant === "password";
  log.debug("Leaving scopeOnTokenRequest(). on=" + on);
  return on;
}

// One scope string, an array, or a comma-separated field, as names.
function scopeNames(value) {
  log.debug("Entering scopeNames().");
  if (value == null || value === "") {
    log.debug("Leaving scopeNames(). Empty.");
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

// Sorted, so "email openid" and "openid email" are the same list. Used
// only to recognise the seeded advertisement, never as a value to send.
function canonical(value) {
  log.debug("Entering canonical().");
  var sorted = scopeNames(value).slice().sort().join(" ");
  log.debug("Leaving canonical().");
  return sorted;
}

// True when `value` is the whole advertisement, in any order. An empty
// advertisement matches nothing: there is no dump to recognise.
function isAdvertisedDump(value, scopesSupported) {
  log.debug("Entering isAdvertisedDump().");
  var dumped = canonical(scopesSupported);
  var same = dumped.length > 0 && canonical(value) === dumped;
  log.debug("Leaving isAdvertisedDump(). same=" + same);
  return same;
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

// What client credentials or password would prefill when the field is
// empty: the authorization-step scope, or the OIDC basics when that
// scope is itself the advertisement.
function prefilledScope(authorizationScope, scopesSupported) {
  log.debug("Entering prefilledScope().");
  var authz = scopeNames(authorizationScope).join(" ");
  if (authz && !isAdvertisedDump(authz, scopesSupported)) {
    log.debug("Leaving prefilledScope(). Authorization scope.");
    return authz;
  }
  var basics = registrationScope(scopesSupported);
  log.debug("Leaving prefilledScope(). OIDC basics.");
  return basics;
}

// The scope a token request or a refresh should carry.
//
//   grant               page-1 select value, or the token grant_type
//   stored              what the field (or localStorage) already holds
//   authorizationScope  the authorization request's scope
//   scopesSupported     the provider's scopes_supported, in any of the
//                       shapes scopeNames() accepts
//
// Client credentials and password keep a stored value that is not the
// advertisement, and otherwise take prefilledScope(). A code exchange
// and a refresh send nothing unless the reader narrowed it: the
// advertisement and the value the other grants prefill are not a
// narrowing.
function tokenRequestScope(grant, stored, authorizationScope,
    scopesSupported) {
  log.debug("Entering tokenRequestScope().");
  var kept = scopeNames(stored).join(" ");
  var prefilled = prefilledScope(authorizationScope, scopesSupported);
  if (!scopeOnTokenRequest(grant)) {
    if (kept && !isAdvertisedDump(kept, scopesSupported) &&
        kept !== prefilled) {
      log.debug("Leaving tokenRequestScope(). Kept.");
      return kept;
    }
    log.debug("Leaving tokenRequestScope(). Empty.");
    return "";
  }
  if (kept && !isAdvertisedDump(kept, scopesSupported)) {
    log.debug("Leaving tokenRequestScope(). Kept.");
    return kept;
  }
  log.debug("Leaving tokenRequestScope(). Prefilled.");
  return prefilled;
}

module.exports = {
  OIDC_BASIC_SCOPES: OIDC_BASIC_SCOPES,
  scopeOnTokenRequest: scopeOnTokenRequest,
  scopeNames: scopeNames,
  joinAdvertised: joinAdvertised,
  isAdvertisedDump: isAdvertisedDump,
  registrationScope: registrationScope,
  prefilledScope: prefilledScope,
  tokenRequestScope: tokenRequestScope
};
