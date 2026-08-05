// File: oauth_dpop.js
//
// DPoP (RFC 9449) for the OAuth2 / OIDC workflow — the wallet-free half of what
// sd_jwt_vc.js holds for the SD-JWT VC workflow: the on/off switch, the key
// pair, the nonce, and what the token endpoint said about the binding.
//
// WHY THIS EXISTS AS A SECOND STATE HOLDER, when dpop.js is already shared.
// debugger.html and debugger2.html are used by two workflows. DPoP arrived with
// the VC one, and both pages read `sdJwtVc.dpopEnabled()` directly — but neither
// read was gated on the VC workflow being ACTIVE, and the two workflows share one
// localStorage. So switching DPoP on once in VC issuance step 2 silently put a
// `dpop_jkt` on every subsequent OAuth2/OIDC authorization request and a proof on
// every browser-direct Token Request, with no control anywhere on those pages to
// stop it. DPoP was, from the OAuth2/OIDC workflow's point of view, mandatory.
//
// Rather than gate those reads on the VC flow (which would leave the OAuth2/OIDC
// workflow unable to use DPoP at all), the OAuth2/OIDC workflow gets its own
// switch, defaulting OFF, and its own key. The two workflows now share the
// mechanism (dpop.js) and nothing else: turning DPoP off here cannot destroy the
// key a credential was bound to, and turning it on there cannot bind a token the
// user of this page never asked to have bound.
//
// No DOM and no jQuery in here, for the same reason dpop.js has none: it is the
// state, and the pages are what render it.

var dpopLib = require("./dpop.js");

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "oauth_dpop",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// All prefixed oauth_dpop_ so that nothing here can be mistaken for — or
// overwrite — the VC workflow's sdjwtvc_dpop_* keys.
var KEYS = {
  ENABLED: "oauth_dpop_enabled",
  ALG: "oauth_dpop_alg",
  PUBLIC_JWK: "oauth_dpop_public_jwk",
  PRIVATE_JWK: "oauth_dpop_private_jwk",
  // The RFC 7638 thumbprint of the public half. Stored rather than recomputed
  // because debugger.html needs it for the dpop_jkt authorization parameter,
  // where hashing is asynchronous and the request is assembled synchronously.
  JKT: "oauth_dpop_jkt",
  // The most recent server-supplied nonce (RFC 9449 sections 8 and 9), kept so
  // the next request uses it without paying for the 401 handshake again.
  NONCE: "oauth_dpop_nonce",
  // What the token endpoint actually returned, so the pane can report whether
  // the token came back bound instead of assuming that asking made it so.
  TOKEN_TYPE: "oauth_dpop_token_type",
  TOKEN_JKT: "oauth_dpop_token_jkt",
  // The jkt that was actually sent on the authorization request, so the pane can
  // say whether the CODE was bound as well as the token.
  JKT_SENT: "oauth_dpop_jkt_sent"
};

function get(key) {
  try {
    return localStorage.getItem(key);
  } catch (e) {
    // Storage disabled or a private window. DPoP is then simply unavailable,
    // which is the same answer as "switched off" and needs no special case.
    log.debug("oauth_dpop.get(): storage is unreadable: " + e.message);
    return null;
  }
}

function set(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    log.debug("oauth_dpop.set(): storage is unwritable: " + e.message);
  }
}

function remove(key) {
  try {
    localStorage.removeItem(key);
  } catch (e) {
    log.debug("oauth_dpop.remove(): storage is unwritable: " + e.message);
  }
}

function getJson(key) {
  var raw = get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    // A half-written or hand-edited value. Treated as absent rather than thrown,
    // so a corrupt key degrades to "no DPoP" instead of breaking the page.
    log.debug("oauth_dpop.getJson(): " + key + " is not JSON: " + e.message);
    return null;
  }
}

// Opt IN. Only an explicit "1" turns it on, so a missing, misspelled or
// half-written preference leaves the workflow exactly as it was before DPoP
// existed — an ordinary Bearer exchange.
function enabled() {
  return get(KEYS.ENABLED) === "1";
}

function setEnabled(on) {
  log.debug("Entering setEnabled(). on=" + !!on);
  set(KEYS.ENABLED, on ? "1" : "0");
  if (!on) {
    // The key goes with the switch, as it does in the VC workflow: a key nothing
    // will use again is one a later session could pick up and bind a token to by
    // accident, and leaving it would also leave the pane showing a thumbprint
    // for a mechanism that is off.
    remove(KEYS.PRIVATE_JWK);
    remove(KEYS.PUBLIC_JWK);
    remove(KEYS.JKT);
    remove(KEYS.NONCE);
    remove(KEYS.ALG);
    forgetBinding();
    log.debug("setEnabled(): DPoP turned off, so its key pair, nonce and binding record went with it.");
  }
  log.debug("Leaving setEnabled().");
}

function keyPair() {
  var privateJwk = getJson(KEYS.PRIVATE_JWK);
  var publicJwk = getJson(KEYS.PUBLIC_JWK);
  if (!privateJwk || !publicJwk) return null;
  return {
    alg: get(KEYS.ALG) || dpopLib.DEFAULT_ALG,
    publicJwk: publicJwk,
    privateJwk: privateJwk
  };
}

function jkt() {
  return get(KEYS.JKT) || "";
}

function storeKeyPair(pair, thumb) {
  log.debug("Entering storeKeyPair(). alg=" + (pair && pair.alg));
  set(KEYS.PUBLIC_JWK, JSON.stringify(pair.publicJwk));
  set(KEYS.PRIVATE_JWK, JSON.stringify(pair.privateJwk));
  set(KEYS.ALG, pair.alg || dpopLib.DEFAULT_ALG);
  if (thumb) set(KEYS.JKT, thumb);
  log.debug("Leaving storeKeyPair(). jkt=" + (thumb || "(not computed)"));
}

// Generate a key pair and remember it with its thumbprint. Returns a promise —
// Web Crypto is asynchronous, and the thumbprint is what the authorization
// request needs before anything else can happen.
function generateKeyPair(alg) {
  log.debug("Entering generateKeyPair(). alg=" + (alg || dpopLib.DEFAULT_ALG));
  return dpopLib.generateKeyPair(alg || dpopLib.DEFAULT_ALG)
    .then(function (pair) {
      return dpopLib.thumbprint(pair.publicJwk).then(function (thumb) {
        storeKeyPair(pair, thumb);
        log.debug("Leaving generateKeyPair(). jkt=" + thumb);
        return { pair: pair, jkt: thumb };
      });
    });
}

// The key this workflow will actually sign with, generating one on first use.
// Callers get a promise for {pair, jkt} or null when DPoP is off — "off" is not
// an error and must not reject, or every call site would need a catch that means
// "carry on as a Bearer request".
function ensureKeyPair(alg) {
  log.debug("Entering ensureKeyPair().");
  if (!enabled()) {
    log.debug("Leaving ensureKeyPair(). DPoP is off.");
    return Promise.resolve(null);
  }
  var existing = keyPair();
  if (existing) {
    log.debug("Leaving ensureKeyPair(). Reusing the stored key pair.");
    return Promise.resolve({ pair: existing, jkt: jkt() });
  }
  return generateKeyPair(alg);
}

function nonce() {
  return get(KEYS.NONCE) || "";
}

function rememberNonce(value) {
  if (!value) return;
  log.debug("Entering rememberNonce().");
  set(KEYS.NONCE, String(value));
  log.debug("Leaving rememberNonce().");
}

// What the wire layer needs, in the shape vci_wallet.dpopHeadersFor() already
// takes — so the OAuth2/OIDC workflow and the VC workflow reach the network
// through one implementation rather than two that could disagree.
function context() {
  if (!enabled()) return null;
  var pair = keyPair();
  if (!pair) return null;
  return { key: pair, nonce: nonce(), remember: rememberNonce };
}

// Whether a proof can be made right now, and if not, why. The distinction that
// matters is the same one the VC workflow draws: DPoP switched on with no key is
// not a configuration, it is a request that is about to go out unbound.
function readiness() {
  var on = enabled();
  if (!on) return { on: false, ready: false, problem: null, jkt: "" };
  var pair = keyPair();
  if (pair) return { on: true, ready: true, problem: null, jkt: jkt() };
  return {
    on: true, ready: false, jkt: "",
    problem: "DPoP is on but no key pair has been generated yet, so the request would go out unbound."
  };
}

// --- what came back ---------------------------------------------------------

// Record the token endpoint's own answer. `token_type: DPoP` and a cnf.jkt in
// the access token are the only evidence the binding took; asking for it does
// not make it so, and a server that ignores DPoP answers with a perfectly
// ordinary Bearer token.
function rememberBinding(tokenType, boundJkt) {
  log.debug("Entering rememberBinding(). token_type=" + tokenType + ", jkt=" + (boundJkt || "(none)"));
  set(KEYS.TOKEN_TYPE, String(tokenType || ""));
  set(KEYS.TOKEN_JKT, String(boundJkt || ""));
  log.debug("Leaving rememberBinding().");
}

function forgetBinding() {
  remove(KEYS.TOKEN_TYPE);
  remove(KEYS.TOKEN_JKT);
  remove(KEYS.JKT_SENT);
}

// The cnf.jkt an access token carries, read WITHOUT verifying the signature —
// this is a display of what the token says about itself, and the page says so.
// A non-JWT (an opaque token, which is legal) simply has nothing to report.
function jktOfToken(accessToken) {
  var parts = String(accessToken || "").split(".");
  if (parts.length !== 3) return "";
  try {
    var padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var claims = JSON.parse(decodeURIComponent(escape(atob(padded))));
    return (claims && claims.cnf && claims.cnf.jkt) ? String(claims.cnf.jkt) : "";
  } catch (e) {
    // Opaque, encrypted, or simply not ours. Nothing to show, and nothing wrong.
    log.debug("jktOfToken(): the access token carries no readable claims: " + e.message);
    return "";
  }
}

// The verdict the pane renders: did the token come back bound to THIS key?
// Three outcomes rather than two, because "the server ignored DPoP" and "the
// server bound it to a different key" are different problems, and collapsing
// them into "not bound" hides the second one entirely.
function bindingVerdict(accessToken) {
  log.debug("Entering bindingVerdict().");
  var asked = enabled();
  var mine = jkt();
  var tokenType = get(KEYS.TOKEN_TYPE) || "";
  var boundTo = accessToken !== undefined ? jktOfToken(accessToken) : (get(KEYS.TOKEN_JKT) || "");
  if (!asked) {
    log.debug("Leaving bindingVerdict(). DPoP was not asked for.");
    return { state: "off", text: "DPoP is off — this is an ordinary Bearer token." };
  }
  if (!boundTo) {
    log.debug("Leaving bindingVerdict(). Nothing bound.");
    return {
      state: "unbound",
      text: "A DPoP proof was sent, but the token came back with no cnf.jkt" +
            (tokenType ? " and token_type=" + tokenType : "") +
            " — this authorization server issued an ordinary Bearer token."
    };
  }
  if (mine && boundTo !== mine) {
    log.debug("Leaving bindingVerdict(). Bound to another key.");
    return {
      state: "mismatch",
      text: "The token is bound to " + boundTo + ", which is NOT this page's key (" + mine + "). " +
            "Nothing here can present it."
    };
  }
  log.debug("Leaving bindingVerdict(). Bound to this key.");
  return {
    state: "bound",
    text: "The token is sender-constrained: cnf.jkt = " + boundTo +
          ", the thumbprint of this page's DPoP key" +
          (tokenType ? ", and token_type=" + tokenType : "") + "."
  };
}

// The jkt that actually travelled on the authorization request, recorded there
// and read back here. A jkt sent for a key that has since been regenerated makes
// the code unredeemable, and that deserves naming rather than surfacing as an
// unexplained invalid_grant.
function rememberJktSent(value) {
  set(KEYS.JKT_SENT, String(value || ""));
}

function jktSent() {
  return get(KEYS.JKT_SENT) || "";
}

module.exports = {
  KEYS: KEYS,
  enabled: enabled,
  setEnabled: setEnabled,
  keyPair: keyPair,
  jkt: jkt,
  generateKeyPair: generateKeyPair,
  ensureKeyPair: ensureKeyPair,
  nonce: nonce,
  rememberNonce: rememberNonce,
  context: context,
  readiness: readiness,
  rememberBinding: rememberBinding,
  forgetBinding: forgetBinding,
  jktOfToken: jktOfToken,
  bindingVerdict: bindingVerdict,
  rememberJktSent: rememberJktSent,
  jktSent: jktSent
};
