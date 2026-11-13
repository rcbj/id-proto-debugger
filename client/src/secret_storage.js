// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: secret_storage.js
//
// ---------------------------------------------------------------------------
// What the OAuth 2.0 / OIDC workflow may keep in browser storage, and what
// it may not.
//
//   * A client secret or a user's password is NEVER stored, in any storage.
//     It lives in its field for one page load. A secret needed on step 2
//     after the authorization redirect is typed again there.
//   * A bearer credential that is not the workflow's output (the DCR
//     registration access token, the initial access token, the bearer
//     token the introspection endpoint is called with) is kept in
//     sessionStorage only: it survives the identity provider's redirect
//     within the tab and is gone when the tab closes.
//
// purgeOnLoad() removes every secret key from both stores and every bearer
// key from localStorage, so a copy an older build wrote does not outlive the
// first load of this one. tests/secret_storage_engine.js reads the pages for
// a write that breaks either rule. No DOM: the stores are passed in.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "secret_storage",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Keys a secret or a password was written under by an earlier build, or
// could be by a field id. None of them may be written again.
var SECRET_KEYS = [
  "client_secret",
  "token_client_secret",
  "refresh_client_secret",
  "revocation_client_secret",
  "tokenexchange_client_secret",
  "introspection_client_secret",
  "userinfo_client_secret",
  "token_password",
  "password"
];

// Bearer credentials kept for the tab only.
var SESSION_KEYS = [
  "registration_access_token",
  "dcr_initial_access_token",
  "introspection_bearer_token"
];

// Members of a client registration that are credentials. The metadata
// editor may show them for the page load; its stored copy may not.
var SECRET_MEMBERS = ["client_secret", "registration_access_token"];

function removeQuietly(store, key) {
  log.debug("Entering removeQuietly().");
  if (!store) {
    log.debug("Leaving removeQuietly(). No store.");
    return;
  }
  try {
    store.removeItem(key);
  } catch (e) {
    log.debug("removeQuietly(): could not remove " + key + ": " +
        e.message);
  }
  log.debug("Leaving removeQuietly().");
}

// local and session are the two Storage objects (either may be absent).
function purgeOnLoad(local, session) {
  log.debug("Entering purgeOnLoad().");
  SECRET_KEYS.forEach(function (key) {
    removeQuietly(local, key);
    removeQuietly(session, key);
  });
  SESSION_KEYS.forEach(function (key) {
    removeQuietly(local, key);
  });
  log.debug("Leaving purgeOnLoad().");
}

function sessionGet(session, key) {
  log.debug("Entering sessionGet().");
  var value = "";
  if (SESSION_KEYS.indexOf(key) < 0) {
    log.debug("Leaving sessionGet(). Not a session key.");
    return value;
  }
  try {
    value = (session && session.getItem(key)) || "";
  } catch (e) {
    log.debug("sessionGet(): " + e.message);
  }
  log.debug("Leaving sessionGet().");
  return value;
}

// An empty value removes the key rather than storing "".
function sessionSet(session, key, value) {
  log.debug("Entering sessionSet().");
  if (SESSION_KEYS.indexOf(key) < 0 || !session) {
    log.debug("Leaving sessionSet(). Refused.");
    return;
  }
  try {
    if (value) {
      session.setItem(key, String(value));
    } else {
      session.removeItem(key);
    }
  } catch (e) {
    log.debug("sessionSet(): " + e.message);
  }
  log.debug("Leaving sessionSet().");
}

// The client metadata JSON with its credential members removed, for
// storage. Text that is not a JSON object has each such member's string
// value blanked instead, so a half-edited document keeps its shape and
// loses only the secret.
function withoutSecretMembers(text) {
  log.debug("Entering withoutSecretMembers().");
  var source = text == null ? "" : String(text);
  var parsed = null;
  try {
    parsed = JSON.parse(source);
  } catch (e) {
    parsed = null;
  }
  var out;
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    SECRET_MEMBERS.forEach(function (name) {
      delete parsed[name];
    });
    out = JSON.stringify(parsed, null, 2);
  } else {
    out = source;
    SECRET_MEMBERS.forEach(function (name) {
      var pattern = new RegExp('("' + name +
          '"\\s*:\\s*")(?:[^"\\\\]|\\\\.)*(")', "g");
      out = out.replace(pattern, "$1$2");
    });
  }
  log.debug("Leaving withoutSecretMembers().");
  return out;
}

module.exports = {
  SECRET_KEYS: SECRET_KEYS,
  SESSION_KEYS: SESSION_KEYS,
  SECRET_MEMBERS: SECRET_MEMBERS,
  purgeOnLoad: purgeOnLoad,
  sessionGet: sessionGet,
  sessionSet: sessionSet,
  withoutSecretMembers: withoutSecretMembers
};
