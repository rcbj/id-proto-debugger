// File: token_handoff.js
//
// ---------------------------------------------------------------------------
// A ONE-SHOT ACCESS TOKEN HANDOFF, from the OAuth2 / OIDC workflow to a page
// that needs a bearer token and has no way of its own to obtain one.
//
// The SCIM page is the first caller. RFC 7644 section 2 names an OAuth 2.0
// bearer token as an authentication scheme and then says nothing whatever
// about where one comes from — which leaves a page offering a token field, a
// reader holding no token, and no route between the two but another tab and a
// clipboard. This module is that route: the SCIM page marks itself as waiting
// and sends the browser to oauth2_oidc_1.html; that workflow runs exactly as
// it always does; and whichever of its three token-bearing responses arrives
// first drops the access token into the slot below and offers a way back.
//
// WHY sessionStorage AND NOT localStorage, which every other cross-page state
// here uses. A bearer token is a credential, and the SCIM page's whole
// arrangement around one is an opt-IN to storing it (`scim_save_token`, which
// ships clear). A handoff that wrote the token to localStorage would store it
// on the reader's behalf without asking — the opt-in would still be clear and
// still be a lie. sessionStorage is scoped to the tab and dies with it, the
// handoff is a single same-tab navigation, and `take()` REMOVES what it
// returns, so the slot holds a token for the length of one page load. The
// identity provider round trip goes out of this tab and comes back to it,
// which is what makes the tab-scoped store enough.
//
// The delivered token also EXPIRES. A slot that was filled and never collected
// would otherwise sit there until the tab closed, and be picked up by a visit
// to the consuming page an hour later that has nothing to do with it — a
// bearer token appearing in a field nobody filled is worse than no handoff.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "token_handoff",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var KEYS = {
  // "1" while a workflow is waiting for a token.
  ACTIVE: "token_handoff_active",
  // Where the browser goes back to, once there is one.
  RETURN: "token_handoff_return",
  // What to call the waiting workflow, on the banners the OAuth2 / OIDC pages
  // put up. Shown as TEXT and never as markup — it crosses a page load.
  LABEL: "token_handoff_label",
  // The delivered access token. ONE SHOT: take() removes it.
  TOKEN: "token_handoff_token",
  // How it was obtained: { source, at }. Also read as TEXT.
  META: "token_handoff_meta",
  // ---------------------------------------------------------------------
  // THE REST OF THE TOKEN SET, and it is a SEPARATE SLOT rather than more
  // members on META for a reason worth stating: the first consumer of this
  // module — the SCIM page — wants an access token and nothing else, and
  // `take()`'s answer has to go on meaning exactly what it meant. So this
  // is additive: a caller that does not ask for it is unaffected, and a
  // caller that does gets `{ idToken, refreshToken, tokenType, expiresIn,
  // scope }` beside the token it already had.
  //
  // WHY A SECOND CONSUMER NEEDED MORE. The Shared Signals workflow keeps a
  // TOKEN HISTORY — every set of tokens used in the session, the way the
  // OAuth2 / OIDC results page does — and it reports WHO THE AUTHENTICATED
  // USER IS. Neither is answerable from an access token: this service's
  // are opaque to a client, and the identity is in the ID Token. A
  // hand-off that carried only the bearer credential would leave that page
  // showing a signed-in user it could not name.
  //
  // It is `sessionStorage` like everything else here and it is dropped by
  // the same `cancel()`, so nothing about the lifetime changes.
  // ---------------------------------------------------------------------
  SET: "token_handoff_set"
};

// How long a delivered token stays collectable, in milliseconds. The gap this
// has to cover is one click — the reader pressing "Return" on the banner — so
// half an hour is already generous; it is not the token's own lifetime and
// says nothing about it.
var TTL_MS = 30 * 60 * 1000;

// The store, or null where there is none (a node test, a browser with storage
// switched off). Every function below tolerates the null: the handoff is a
// convenience and a page without it must still work.
function store() {
  log.debug("Entering store().");
  var s = null;
  try {
    s = window.sessionStorage;
  } catch (e) {
    // Storage disabled for this origin. Nothing to fall back to — localStorage
    // is deliberately not used here; see the header.
    s = null;
  }
  log.debug("Leaving store(). " + (s ? "present" : "none"));
  return s;
}

function get(key) {
  log.debug("Entering get(). " + key);
  var s = store();
  if (!s) {
    log.debug("Leaving get(). No store.");
    return "";
  }
  try {
    var value = s.getItem(key) || "";
    log.debug("Leaving get(). " + value.length + " characters.");
    return value;
  } catch (e) {
    log.debug("Leaving get(). Unreadable.");
    return "";
  }
}

function put(key, value) {
  log.debug("Entering put(). " + key);
  var s = store();
  if (!s) {
    log.debug("Leaving put(). No store.");
    return false;
  }
  try {
    s.setItem(key, value);
    log.debug("Leaving put(). Written.");
    return true;
  } catch (e) {
    log.debug("Leaving put(). " + e.message);
    return false;
  }
}

function drop(key) {
  log.debug("Entering drop(). " + key);
  var s = store();
  if (!s) {
    log.debug("Leaving drop(). No store.");
    return;
  }
  try {
    s.removeItem(key);
  } catch (e) {
    // Nothing to remove, or no storage. Either way there is nothing to do.
  }
  log.debug("Leaving drop().");
}

// ---------------------------------------------------------------------------
// The caller's side.
// ---------------------------------------------------------------------------

// Mark a workflow as waiting for a token. `returnUrl` is where the OAuth2 /
// OIDC pages offer to send the browser back to, and `label` is what they call
// the workflow on the banner.
//
// Any token left in the slot is dropped here rather than in take(): starting a
// new handoff must not hand back the one an abandoned handoff delivered.
function start(options) {
  log.debug("Entering start().");
  var settings = options || {};
  var returnUrl = String(settings.returnUrl || "");
  var label = String(settings.label || "the workflow that asked for it");
  if (!returnUrl) {
    log.warn("a token handoff was started with no return url, so there " +
        "would be nowhere to come back to");
    log.debug("Leaving start(). No return url.");
    return false;
  }
  drop(KEYS.TOKEN);
  drop(KEYS.META);
  drop(KEYS.SET);
  var ok = put(KEYS.ACTIVE, "1") && put(KEYS.RETURN, returnUrl) &&
      put(KEYS.LABEL, label);
  if (!ok) {
    log.warn("a token handoff could not be recorded — this browser has no " +
        "session storage for this origin, so the token cannot be carried " +
        "back automatically");
    log.debug("Leaving start(). Not recorded.");
    return false;
  }
  log.debug("Leaving start(). " + label + " -> " + returnUrl);
  return true;
}

function isActive() {
  log.debug("Entering isActive().");
  var active = get(KEYS.ACTIVE) === "1";
  log.debug("Leaving isActive(). " + active);
  return active;
}

function returnUrl() {
  log.debug("Entering returnUrl().");
  var url = get(KEYS.RETURN);
  log.debug("Leaving returnUrl(). " + (url || "(none)"));
  return url;
}

function label() {
  log.debug("Entering label().");
  var text = get(KEYS.LABEL) || "the workflow that asked for it";
  log.debug("Leaving label(). " + text);
  return text;
}

// Give the whole thing up: no token is waiting for anybody. Called when the
// reader dismisses the banner, and when the consuming page has collected.
function cancel() {
  log.debug("Entering cancel().");
  [KEYS.ACTIVE, KEYS.RETURN, KEYS.LABEL, KEYS.TOKEN, KEYS.META, KEYS.SET]
    .forEach(function (key) {
      drop(key);
    });
  log.debug("Leaving cancel().");
}

// ---------------------------------------------------------------------------
// The OAuth2 / OIDC workflow's side.
// ---------------------------------------------------------------------------

// Put an access token in the slot. Refused unless a handoff is active, so an
// ordinary visit to the token pages writes nothing anywhere.
//
// `source` names the response it came out of — the token endpoint, a refresh,
// the authorization response — and is shown to the reader, because "which of
// the three tokens on this page is the one that went back" is exactly the
// question a handoff invites.
function deliver(token, source, set) {
  log.debug("Entering deliver(). source=" + source);
  if (!isActive()) {
    log.debug("Leaving deliver(). No handoff is active.");
    return false;
  }
  var value = String(token || "");
  if (!value) {
    log.debug("Leaving deliver(). No token.");
    return false;
  }
  if (!put(KEYS.TOKEN, value)) {
    log.warn("an access token could not be handed off — this browser has no " +
        "session storage for this origin");
    log.debug("Leaving deliver(). Not stored.");
    return false;
  }
  put(KEYS.META, JSON.stringify({ source: String(source || ""),
      at: new Date().getTime() }));
  // The rest of the set, when the caller has one. OPTIONAL and third, so
  // every existing call site is unchanged and a caller that passes nothing
  // leaves the slot empty rather than writing an object of empty strings —
  // which take() would then hand back as a set that looked delivered.
  if (set && typeof set === "object") {
    var extra = {
      idToken: String(set.idToken || ""),
      refreshToken: String(set.refreshToken || ""),
      tokenType: String(set.tokenType || ""),
      scope: String(set.scope || ""),
      expiresIn: Number(set.expiresIn) || 0
    };
    var carries = extra.idToken || extra.refreshToken || extra.tokenType ||
        extra.scope || extra.expiresIn;
    if (carries) {
      put(KEYS.SET, JSON.stringify(extra));
    }
  }
  log.debug("Leaving deliver(). " + value.length + " characters.");
  return true;
}

function isDelivered() {
  log.debug("Entering isDelivered().");
  var delivered = get(KEYS.TOKEN) !== "";
  log.debug("Leaving isDelivered(). " + delivered);
  return delivered;
}

// ---------------------------------------------------------------------------
// The consuming page's side.
// ---------------------------------------------------------------------------

// Collect what was delivered, and CLEAR THE SLOT whether or not there was
// anything in it. The return is
//
//   { token, source, at, expired }
//
// with an empty token when nothing was waiting, and `expired: true` when
// something was and it had been there too long — which is reported rather than
// returned, so the page can say why a token it was expecting is not there
// instead of filling a field with a token from a forgotten round trip.
function take() {
  log.debug("Entering take().");
  var token = get(KEYS.TOKEN);
  var meta = {};
  try {
    meta = JSON.parse(get(KEYS.META) || "{}") || {};
  } catch (e) {
    // Somebody else's bytes in our slot, or a half-written value. The token is
    // still usable; only the provenance is lost.
    meta = {};
  }
  var set = null;
  try {
    var stored = get(KEYS.SET);
    set = stored ? JSON.parse(stored) : null;
  } catch (e) {
    // Same reasoning: an unreadable extra slot costs the ID Token and the
    // refresh token, and the access token this handoff exists for is fine.
    set = null;
  }
  var at = Number(meta.at || 0);
  var expired = !!token && at > 0 &&
      (new Date().getTime() - at) > TTL_MS;
  cancel();
  if (expired) {
    log.debug("Leaving take(). Expired.");
    return { token: "", source: String(meta.source || ""), at: at,
        expired: true, set: null };
  }
  log.debug("Leaving take(). " + (token ? "a token" : "nothing") +
      (set ? " and the rest of the set" : ""));
  return { token: token, source: String(meta.source || ""), at: at,
      expired: false,
      // `null` when the delivering page carried only a bearer token, which is
      // every caller before the Shared Signals workflow. A consumer that
      // needs the ID Token says so rather than assuming.
      set: set };
}

module.exports = {
  KEYS: KEYS,
  TTL_MS: TTL_MS,
  start: start,
  isActive: isActive,
  returnUrl: returnUrl,
  label: label,
  cancel: cancel,
  deliver: deliver,
  isDelivered: isDelivered,
  take: take
};
