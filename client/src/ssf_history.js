// File: ssf_history.js
//
// ---------------------------------------------------------------------------
// TWO HISTORIES THE SHARED SIGNALS PAGE KEEPS, AND WHY NEITHER IS
// `op_history.js`.
//
// That module is the OPERATIONS log — one row per call, with a result — and
// this page uses it too, unchanged, for exactly that. What it cannot hold is
// the two things this workflow is actually about:
//
//   THE TOKEN HISTORY. Every set of tokens used in this session, the way the
//   OAuth2 / OIDC results page keeps one — because an SSF receiver's whole
//   relationship with a transmitter runs on a bearer token, a stream outlives
//   the token that created it, and "which token was I holding when that
//   stream stopped answering" is a question with no other way of being asked.
//   It is a SEPARATE STORE from that page's `token_history` and not a second
//   view of it: these are the tokens this workflow HAS USED, which is a
//   different set from the tokens that page has obtained — a hand-off
//   delivers one of many, and a token pasted in by hand was never on that
//   page at all.
//
//   THE MESSAGE HISTORY. Every Security Event Token this page SENT or
//   RECEIVED, whole, with what it decoded to and what every check said. A row
//   in an operations log can say "a push was refused"; only this can say
//   which event, to whom, signed with what, and what the receiver's
//   `description` was.
//
// ---------------------------------------------------------------------------
// WHAT IS AND IS NOT WRITTEN DOWN, WHICH IS THE ONE DECISION HERE WITH A
// CONSEQUENCE.
//
// **THE TOKEN HISTORY IS `sessionStorage` AND NOT `localStorage`**, which is
// the opposite of what the OAuth2 / OIDC page does with its own, and it is
// deliberate. That page's history is the point of the page — it is a debugger
// for tokens and a reader comes back to it. Here a token is a CREDENTIAL this
// workflow is using to drive somebody's control plane, and the page can do
// everything it does without ever surviving a tab. `token_handoff.js` makes
// the same choice for the same reason and says so at length. A reader who
// wants a token kept has the OAuth2 / OIDC workflow, which offers exactly
// that.
//
// **THE MESSAGE HISTORY IS `localStorage` AND THE TOKENS IN IT ARE NOT
// CREDENTIALS.** A Security Event Token is a signed statement that something
// happened; holding one grants nothing and presenting one to anybody achieves
// nothing. It is evidence, and evidence is the thing a debugger most needs to
// survive the navigation to another page and back. What IS stripped is the
// `Authorization` header of the exchange that carried it — see
// `redactExchange()` — because that is a credential and it is the one part of
// a push that is.
//
// ---------------------------------------------------------------------------
// NO DOM. Both stores are read and written here and RENDERED by the page, so
// `tests/ssf_engine.js` drives the capping, the redaction and the ordering in
// node with no browser. The rule `scim_client.js`, `jws.js` and the encryption
// engines follow.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "ssf_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var TOKEN_KEY = 'ssf_token_history';
var MESSAGE_KEY = 'ssf_message_history';

// A thousand of each, which is `op_history.js`'s cap and the OAuth2 / OIDC
// page's. A browser has about five megabytes and a SET is under a kilobyte, so
// the cap is about keeping a page that ran overnight from being unreadable
// rather than about the quota.
var LIMIT = 1000;

// The headers whose VALUE is a credential. They lose the whole value rather
// than part of it, because guessing which part of a credential is secret is
// how a redactor leaves half of one behind — the rule the OAuth2 / OIDC page's
// `redactExchangeForStorage()` states and this follows.
var REDACTED_HEADERS = ['authorization', 'proxy-authorization', 'cookie',
  'dpop'];

var REDACTED = '(redacted — not stored)';

function store(kind) {
  log.debug("Entering store(). " + kind);
  try {
    var s = kind === 'token' ? window.sessionStorage : window.localStorage;
    log.debug("Leaving store(). present");
    return s;
  } catch (e) {
    // Storage disabled for this origin, or no window at all (the node tests).
    // Every function below tolerates the null: a history is a convenience and
    // the page must work without one.
    log.debug("Leaving store(). none");
    return null;
  }
}

function read(kind, key) {
  log.debug("Entering read(). " + key);
  var s = store(kind);
  if (!s) {
    log.debug("Leaving read(). No store.");
    return [];
  }
  try {
    var parsed = JSON.parse(s.getItem(key) || '[]');
    log.debug("Leaving read(). " +
        (Object.prototype.toString.call(parsed) === '[object Array]'
          ? parsed.length : 0) + " entry/entries.");
    return Object.prototype.toString.call(parsed) === '[object Array]'
      ? parsed : [];
  } catch (e) {
    // Somebody else's bytes in our slot, or a half-written value. An empty
    // history is a better answer than a thrown page.
    log.debug("Leaving read(). Unreadable.");
    return [];
  }
}

function write(kind, key, rows) {
  log.debug("Entering write(). " + key);
  var s = store(kind);
  if (!s) {
    log.debug("Leaving write(). No store.");
    return false;
  }
  var list = rows;
  if (list.length > LIMIT) {
    list = list.slice(list.length - LIMIT);
  }
  try {
    s.setItem(key, JSON.stringify(list));
    log.debug("Leaving write(). Written.");
    return true;
  } catch (e) {
    // The quota. Drop the OLDEST half and try once more: a history that
    // refused to record anything new because it was full would stop being a
    // history at the moment it mattered.
    log.warn("the " + key + " store is full; the oldest half is being " +
        "dropped so that recording can continue");
    try {
      s.setItem(key, JSON.stringify(list.slice(Math.floor(list.length / 2))));
      log.debug("Leaving write(). Written after trimming.");
      return true;
    } catch (e2) {
      log.debug("Leaving write(). Refused.");
      return false;
    }
  }
}

function newId(prefix) {
  log.debug("Entering newId().");
  log.debug("Leaving newId().");
  return prefix + Date.now().toString(36) +
      Math.floor(Math.random() * 1e6).toString(36);
}

// ---------------------------------------------------------------------------
// THE TOKEN HISTORY.
//
// One entry per SET OF TOKENS this workflow was given. `source` says where
// from — the OAuth2 / OIDC hand-off, a paste, a refresh — because "which of
// these did I actually use" is the question a reader has, and a hand-off
// delivers one set out of a page's many.
//
// `subject` and `claims` are read off the ID Token by the caller and stored as
// TEXT: this module parses nothing, so a malformed token is a row that says so
// rather than an exception in a history.
// ---------------------------------------------------------------------------
function recordTokens(entry) {
  log.debug("Entering recordTokens().");
  var asked = entry || {};
  var rows = read('token', TOKEN_KEY);
  var saved = {
    id: newId('tok'),
    timestamp: new Date().toISOString(),
    source: String(asked.source || 'unknown'),
    accessToken: String(asked.accessToken || ''),
    idToken: String(asked.idToken || ''),
    refreshToken: String(asked.refreshToken || ''),
    tokenType: String(asked.tokenType || ''),
    scope: String(asked.scope || ''),
    expiresIn: Number(asked.expiresIn) || 0,
    // WHO THIS TOKEN SAYS YOU ARE. The page reads it off the ID Token's `sub`
    // and its name claims; it is stored rather than recomputed because the
    // token may be gone by the time somebody reads the row — a refresh
    // replaces it, and the history is what is left.
    subject: String(asked.subject || ''),
    subjectName: String(asked.subjectName || ''),
    issuer: String(asked.issuer || ''),
    audience: String(asked.audience || ''),
    // What this token was USED for on this page, appended as it happens. It
    // is the half an OAuth2 token history cannot have: there, a token is the
    // result; here it is the credential a stream was created with, and the
    // interesting fact is which streams.
    used: []
  };
  rows.push(saved);
  write('token', TOKEN_KEY, rows);
  log.debug("Leaving recordTokens(). " + saved.id);
  return saved.id;
}

// Note that a token was used for something. Kept ON the token rather than only
// in the operations log because the operations log is a list of calls and this
// is the answer to "which credential was I holding" — a question asked long
// after the call, when a stream has stopped answering.
function noteTokenUse(id, what) {
  log.debug("Entering noteTokenUse(). " + id);
  if (!id) {
    log.debug("Leaving noteTokenUse(). No id.");
    return false;
  }
  var rows = read('token', TOKEN_KEY);
  var i;
  for (i = rows.length - 1; i >= 0; i--) {
    if (rows[i].id !== id) {
      continue;
    }
    rows[i].used = rows[i].used || [];
    rows[i].used.push({ at: new Date().toISOString(), what: String(what) });
    // Capped per token for the reason the histories are capped: a page left
    // polling overnight would otherwise put ten thousand rows on one entry.
    if (rows[i].used.length > 200) {
      rows[i].used.splice(0, rows[i].used.length - 200);
    }
    write('token', TOKEN_KEY, rows);
    log.debug("Leaving noteTokenUse(). Recorded.");
    return true;
  }
  log.debug("Leaving noteTokenUse(). No such token.");
  return false;
}

function tokens() {
  log.debug("Entering tokens().");
  var rows = read('token', TOKEN_KEY);
  log.debug("Leaving tokens(). " + rows.length + ".");
  return rows;
}

function clearTokens() {
  log.debug("Entering clearTokens().");
  var s = store('token');
  if (s) {
    try {
      s.removeItem(TOKEN_KEY);
    } catch (e) {
      // Nothing to remove, or no storage. Either way there is nothing to do.
    }
  }
  log.debug("Leaving clearTokens().");
}

// ---------------------------------------------------------------------------
// THE MESSAGE HISTORY.
//
// One entry per Security Event Token that crossed this page in either
// direction. `direction` is 'sent' or 'received' and it is the field the pane
// groups by, because the two answer different questions: what did I emit, and
// what arrived.
//
// **THE WHOLE TOKEN IS KEPT.** A SET is evidence rather than a credential —
// holding one grants nothing and presenting one achieves nothing — and a
// history of security events that dropped the events would be a list of
// timestamps. What is stripped is the `Authorization` header of the exchange
// that carried it, which IS a credential and is the only part of a push that
// is.
// ---------------------------------------------------------------------------
function redactExchange(exchange) {
  log.debug("Entering redactExchange().");
  if (!exchange || typeof exchange !== 'object') {
    log.debug("Leaving redactExchange(). Nothing.");
    return null;
  }
  var out = {
    method: String(exchange.method || ''),
    url: String(exchange.url || ''),
    status: Number(exchange.status) || 0,
    elapsedMs: Number(exchange.elapsedMs) || 0,
    requestHeaders: redactHeaders(exchange.requestHeaders),
    responseHeaders: redactHeaders(exchange.responseHeaders),
    responseBody: String(exchange.responseBody || '').slice(0, 4096)
  };
  log.debug("Leaving redactExchange().");
  return out;
}

function redactHeaders(headers) {
  log.debug("Entering redactHeaders().");
  var source = (headers && typeof headers === 'object') ? headers : {};
  var out = {};
  Object.keys(source).forEach(function (name) {
    out[name] = REDACTED_HEADERS.indexOf(String(name).toLowerCase()) >= 0
      ? REDACTED : String(source[name]);
  });
  log.debug("Leaving redactHeaders(). " + Object.keys(out).length + ".");
  return out;
}

function recordMessage(entry) {
  log.debug("Entering recordMessage().");
  var asked = entry || {};
  var rows = read('message', MESSAGE_KEY);
  var saved = {
    id: newId('msg'),
    timestamp: new Date().toISOString(),
    direction: asked.direction === 'sent' ? 'sent' : 'received',
    // 'push', 'poll' or 'manual' — how it moved, which is what tells a
    // delivered event from one this page decoded off a clipboard.
    via: String(asked.via || ''),
    streamId: String(asked.streamId || ''),
    jti: String(asked.jti || ''),
    types: Object.prototype.toString.call(asked.types) === '[object Array]'
      ? asked.types.map(String) : [],
    subject: String(asked.subject || ''),
    issuer: String(asked.issuer || ''),
    audience: String(asked.audience || ''),
    token: String(asked.token || ''),
    header: asked.header || null,
    claims: asked.claims || null,
    // Every check BY NAME rather than one boolean. A single "valid: true"
    // over a token whose audience is somebody else is the most dangerous
    // thing this page could say.
    verdicts: Object.prototype.toString.call(asked.verdicts) ===
      '[object Array]' ? asked.verdicts : [],
    signature: String(asked.signature || 'not checked'),
    outcome: String(asked.outcome || ''),
    detail: String(asked.detail || ''),
    exchange: redactExchange(asked.exchange)
  };
  rows.push(saved);
  write('message', MESSAGE_KEY, rows);
  log.debug("Leaving recordMessage(). " + saved.id + " " + saved.direction);
  return saved.id;
}

function messages() {
  log.debug("Entering messages().");
  var rows = read('message', MESSAGE_KEY);
  log.debug("Leaving messages(). " + rows.length + ".");
  return rows;
}

// Whether this page has already recorded a jti in this direction. A poll that
// returns the same event twice — which happens whenever an acknowledgement is
// lost — must not produce two rows, because the count in this pane is what a
// reader uses to decide whether delivery is working.
function hasMessage(jti, direction) {
  log.debug("Entering hasMessage(). " + jti);
  if (!jti) {
    log.debug("Leaving hasMessage(). No jti.");
    return false;
  }
  var wanted = direction === 'sent' ? 'sent' : 'received';
  var found = read('message', MESSAGE_KEY).some(function (row) {
    return row.jti === jti && row.direction === wanted;
  });
  log.debug("Leaving hasMessage(). " + found);
  return found;
}

function clearMessages() {
  log.debug("Entering clearMessages().");
  var s = store('message');
  if (s) {
    try {
      s.removeItem(MESSAGE_KEY);
    } catch (e) {
      // Nothing to remove, or no storage.
    }
  }
  log.debug("Leaving clearMessages().");
}

module.exports = {
  TOKEN_KEY: TOKEN_KEY,
  MESSAGE_KEY: MESSAGE_KEY,
  LIMIT: LIMIT,
  REDACTED: REDACTED,
  REDACTED_HEADERS: REDACTED_HEADERS,
  recordTokens: recordTokens,
  noteTokenUse: noteTokenUse,
  tokens: tokens,
  clearTokens: clearTokens,
  redactExchange: redactExchange,
  redactHeaders: redactHeaders,
  recordMessage: recordMessage,
  messages: messages,
  hasMessage: hasMessage,
  clearMessages: clearMessages
};
