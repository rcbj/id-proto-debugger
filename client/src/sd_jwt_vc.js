// File: sd_jwt_vc.js
//
// ---------------------------------------------------------------------------
// State and parsing shared by the SD-JWT VC issuance pages.
//
//   vc-issuance-1.html  discovery + configuration, then hands off to the
//                              OIDC Authorization Code flow on debugger.html
//   vc-issuance-2.html  the tokens that came back, the user's approval,
//                              and the OID4VCI Credential Request
//   vc-issuance-3.html  the issued SD-JWT VC
//   vc-issuance-4.html  refreshing it: a Refresh Token for a fresh
//                              Access Token, then the Credential Endpoint again
//                              (OID4VCI section 14.5)
//
// The workflow crosses several page loads and an identity provider round trip,
// so everything that has to survive that lives in localStorage under one set of
// keys, defined here once.
// ---------------------------------------------------------------------------


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "sd_jwt_vc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");
var vciMetadata = require("./vci_metadata");

var KEYS = {
  // "active" while the workflow is driving debugger.html / debugger2.html.
  FLOW: "sdjwtvc_flow",
  // Where debugger2.html should send the browser once it has the tokens.
  RETURN: "sdjwtvc_return",
  // The compact SD-JWT VC returned by the credential endpoint. When a batch was
  // requested this is the first of them; CREDENTIALS has them all, in the order
  // the proofs were sent.
  CREDENTIAL: "sdjwtvc_credential",
  CREDENTIALS: "sdjwtvc_credentials",
  // How it was obtained: { issuer, endpoint, configurationId, vct, requestedAt,
  //                        notificationId, request }
  CREDENTIAL_META: "sdjwtvc_credential_meta",
  // The holder key pair the proof of possession is signed with (JWK; the
  // private half never leaves the browser).
  HOLDER_JWK: "sdjwtvc_holder_jwk",
  HOLDER_PRIVATE_JWK: "sdjwtvc_holder_private_jwk",
  // Which OID4VCI Appendix H use case the workflow is running.
  USE_CASE: "sdjwtvc_use_case",
  // The Credential Offer, when the use case has one: { offer, source, receivedAt }.
  OFFER: "sdjwtvc_credential_offer",
  // ---- refreshing (step 4, OID4VCI section 14.5) --------------------------
  // What the issuer returned to the refresh request, held SEPARATELY from the
  // credential in hand: section 14.5 leaves it to the wallet to decide whether
  // to keep the old one, and a wallet that overwrites before the holder has
  // looked has made that decision for them.
  REFRESHED_CREDENTIAL: "sdjwtvc_refreshed_credential",
  REFRESHED_CREDENTIALS: "sdjwtvc_refreshed_credentials",
  REFRESHED_META: "sdjwtvc_refreshed_credential_meta",
  // The key a refresh bound the new credential to, when it was asked to bind a
  // NEW one. It becomes the wallet's holder key only if that credential is kept:
  // overwriting HOLDER_PRIVATE_JWK before then would throw away the private half
  // of the key the credential still in hand is bound to, leaving it impossible to
  // present.
  REFRESHED_HOLDER_JWK: "sdjwtvc_refreshed_holder_jwk",
  REFRESHED_HOLDER_PRIVATE_JWK: "sdjwtvc_refreshed_holder_private_jwk",
  // The credential that WAS in hand when a refresh replaced it, so what changed
  // is still there to look at afterwards — with the key it is bound to, because a
  // credential without its holder key cannot be presented at all.
  PREVIOUS_CREDENTIAL: "sdjwtvc_previous_credential",
  PREVIOUS_META: "sdjwtvc_previous_credential_meta",
  PREVIOUS_HOLDER_JWK: "sdjwtvc_previous_holder_jwk",
  PREVIOUS_HOLDER_PRIVATE_JWK: "sdjwtvc_previous_holder_private_jwk",
  // Every attempt — issuance, access-token refresh, Credential Request, deferred
  // poll — oldest first, with the outcome of each; and the id of the generation
  // in hand. See the credential history below.
  HISTORY: "sdjwtvc_credential_history",
  HISTORY_INDEX: "sdjwtvc_credential_history_index",
  // How many held generations the list has had to forget, so it can say so.
  HISTORY_DROPPED: "sdjwtvc_credential_history_dropped",
  // Whether the holder key pair's PRIVATE half may be written to localStorage
  // at all. "0" means no; anything else (including absent) means yes, which is
  // the default. See holderPrivateKeyMayBeStored() below.
  SAVE_HOLDER_KEY: "sdjwtvc_save_holder_key"
};

// The keys that hold private key material. Every one of these is the private
// half of a holder key pair, and every one of them is refused when the user has
// opted out of storing it.
var HOLDER_PRIVATE_KEYS = [
  "sdjwtvc_holder_private_jwk",
  "sdjwtvc_refreshed_holder_private_jwk",
  "sdjwtvc_previous_holder_private_jwk"
];

// ---------------------------------------------------------------------------
// Which use case the workflow is running.
//
// OID4VCI Appendix H describes several; they differ on the wire in how the
// issuance is started and which grant is used, so the workflow carries the
// choice rather than guessing. Step 0 (vc-issuance-0.html) is where it
// is made; every later page shows which one is running.
//
//   id           the value stored under KEYS.USE_CASE
//   label        the short name shown in the badge
//   spec         the Appendix H section
//   available    false for the ones not implemented yet — step 0 shows them,
//                clearly, rather than pretending they are not coming
// ---------------------------------------------------------------------------
var USE_CASES = [
  {
    id: "wallet-initiated",
    spec: "H.6",
    label: "Wallet-initiated",
    title: "Start from the wallet",
    summary: "You know which issuer you want. The wallet retrieves its metadata, you pick a credential, " +
             "and the wallet asks for it.",
    detail: "Nothing is offered to you: the wallet drives the whole thing. This is what the workflow did " +
            "before the other use cases existed, and it is the plain Authorization Code flow with no " +
            "Credential Offer involved.",
    mechanics: "Issuer metadata by URL → Authorization Code + PKCE → Credential Request.",
    available: true
  },
  {
    id: "offer-same-device",
    spec: "H.1",
    label: "Credential Offer — same device",
    title: "The issuer offers you a credential",
    summary: "You are on the issuer's web page and follow a link that offers you a credential. It hands " +
             "your wallet a Credential Offer, on this same device.",
    detail: "The issuer builds a Credential Offer naming itself, the credential on offer, and an " +
            "issuer_state that ties what follows back to the offer. Your wallet shows you what was " +
            "offered before anything is requested.",
    mechanics: "Credential Offer (by value or by reference) → Authorization Code + PKCE with issuer_state → " +
               "Credential Request.",
    available: true
  },
  {
    id: "offer-cross-device",
    spec: "H.2",
    label: "Credential Offer — cross device",
    title: "Scan a code, type a transaction code",
    summary: "The issuer shows a QR code on another screen. Your wallet scans it and you type a short " +
             "transaction code sent to you separately.",
    detail: "The offer carries a pre-authorized code instead of sending you to a login page, so there is " +
            "no authorization request at all — the transaction code is what proves it is really you.",
    mechanics: "Credential Offer with a pre-authorized_code grant + tx_code → Token Request → " +
               "Credential Request.",
    available: true
  },
  {
    id: "offer-deferred",
    spec: "H.3",
    label: "Credential Offer — deferred",
    title: "The credential is not ready yet",
    summary: "The issuer accepts your request but needs time — background checks, a human in the loop — " +
             "and your wallet collects the credential later.",
    detail: "The credential endpoint answers with a transaction identifier instead of a credential, and " +
            "the wallet comes back to the deferred endpoint until it is ready.",
    mechanics: "Credential Request → transaction_id → Deferred Credential Request → Credential.",
    available: true
  }
];

var DEFAULT_USE_CASE = "wallet-initiated";

function useCases() { return USE_CASES; }

function useCaseById(id) {
  for (var i = 0; i < USE_CASES.length; i++) {
    if (USE_CASES[i].id === id) return USE_CASES[i];
  }
  return null;
}

function currentUseCase() {
  return useCaseById(get(KEYS.USE_CASE)) || useCaseById(DEFAULT_USE_CASE);
}

function setUseCase(id) {
  var uc = useCaseById(id);
  if (!uc) return null;
  set(KEYS.USE_CASE, uc.id);
  // The use case can change part-way through a page's life — an arriving
  // Credential Offer switches it after the badge has already been drawn — so
  // redraw it here rather than leaving every caller to remember.
  if (typeof document !== "undefined" && document.getElementById("vc_use_case_badge")) {
    renderUseCaseBadge();
  }
  return uc;
}

// Show which use case is running, in the step indicator every page includes.
function renderUseCaseBadge() {
  var host = document.getElementById("vc_steps");
  if (!host) return null;
  var uc = currentUseCase();
  var existing = document.getElementById("vc_use_case_badge");
  if (existing) existing.parentNode.removeChild(existing);
  var badge = document.createElement("p");
  badge.id = "vc_use_case_badge";
  badge.className = "vc-use-case-badge";
  badge.innerHTML = 'Use case: <strong>' + uc.spec + ' &middot; ' + uc.label + '</strong> — ' +
                    uc.mechanics + ' <a href="/vc-issuance-0.html">change</a>';
  host.parentNode.insertBefore(badge, host.nextSibling);
  return uc;
}

// ---------------------------------------------------------------------------
// The Credential Offer (OID4VCI section 4), for the use cases that have one.
// ---------------------------------------------------------------------------
function storeOffer(offer, source) {
  setJson(KEYS.OFFER, { offer: offer, source: source, receivedAt: new Date().toISOString() });
}

function storedOffer() { return getJson(KEYS.OFFER); }

function forgetOffer() { remove(KEYS.OFFER); }

// The pre-authorized code grant, if that is what the offer carries. An offer has
// one grant or the other: authorization_code sends the End-User through the
// authorization server, pre-authorized_code says that already happened
// somewhere else and this code is the proof of it.
//
// Every one of these reads the STORED offer when called with no argument, the
// same way offerIssuerState() does — a page usually wants "the offer in hand".
var PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

function offerOrStored(offer) {
  if (offer) return offer;
  var stored = storedOffer();
  return (stored && stored.offer) || null;
}

function preAuthorizedGrant(offer) {
  var grants = (offerOrStored(offer) || {}).grants || {};
  return grants[PRE_AUTHORIZED_GRANT] || null;
}

// The Transaction Code the offer says is required — its SHAPE, never its value:
// the value reaches the End-User by another channel entirely, which is the
// point of it. { input_mode, length, description } or null.
function offerTxCode(offer) {
  var grant = preAuthorizedGrant(offer);
  return (grant && grant.tx_code) || null;
}

function offerPreAuthorizedCode(offer) {
  var grant = preAuthorizedGrant(offer);
  return (grant && grant["pre-authorized_code"]) || "";
}

// The issuer_state an authorization_code offer carries, if there is one. The
// authorization request has to send it back.
function offerIssuerState() {
  var stored = storedOffer();
  var grants = stored && stored.offer && stored.offer.grants;
  var authz = grants && grants.authorization_code;
  return (authz && authz.issuer_state) || "";
}

var FLOW_ACTIVE = "active";
var STEP2_URL = "/vc-issuance-2.html";
var STEP3_URL = "/vc-issuance-3.html";
var STEP4_URL = "/vc-issuance-4.html";
// Where the PRESENTATION workflow starts. It lives here rather than in
// sd_jwt_vp.js because the pages that link to it are issuance pages, which do not
// load that module.
var PRESENTATION_URL = "/vc-presentation-0.html";

function ls() {
  try {
    return window.localStorage;
  } catch (e) {
    // Blocked (private mode, third-party restrictions): the workflow degrades to
    // "nothing was remembered" rather than failing.
    return null;
  }
}
function get(key) {
  var s = ls();
  return s ? s.getItem(key) : null;
}

// ---------------------------------------------------------------------------
// Whether the holder key pair's private half may be kept in localStorage.
//
// The debugger's standing rule is that credentials do not go to localStorage.
// This workflow bends it, and unlike the SAML and WS-Trust key pairs it bends it
// hard: the holder private key is written on step 2, read again on step 4 to
// refresh, and read by a DIFFERENT workflow entirely — the presentation pages —
// to sign the Key Binding JWT. Those pages are where the two workflows meet, and
// they meet at this key.
//
// So it stays the default, and it is now a choice, made on step 2 where the pair
// is generated. The gate lives HERE, in set()/setJson(), rather than at the call
// sites: there are writers in three bundles (issuance step 2, issuance step 4's
// refresh and generation-activation, and the history), and a gate at each is a
// gate somebody will forget to add to the fourth.
function holderPrivateKeyMayBeStored() {
  // Only an explicit "0" disables it, so a missing or unreadable preference
  // keeps the previous behaviour rather than silently dropping a key the user
  // expects to still be there.
  return get(KEYS.SAVE_HOLDER_KEY) !== "0";
}

function isHolderPrivateKey(key) {
  return HOLDER_PRIVATE_KEYS.indexOf(key) >= 0;
}

// Remove every stored copy of the private half, including the per-generation
// copies inside the credential history. Stripping the history is the deliberate
// part: a generation whose holder key is gone cannot be presented, which is
// normally a bug (see recordHistoryEntry) — here it is the point, and it is what
// the user is warned about before choosing it.
function forgetStoredHolderPrivateKeys() {
  log.debug("Entering forgetStoredHolderPrivateKeys().");
  for (var i = 0; i < HOLDER_PRIVATE_KEYS.length; i++) {
    remove(HOLDER_PRIVATE_KEYS[i]);
  }
  var history = getJson(KEYS.HISTORY);
  if (history && history.length) {
    var stripped = 0;
    for (var j = 0; j < history.length; j++) {
      if (history[j].holderPrivateJwk) {
        history[j].holderPrivateJwk = null;
        stripped++;
      }
    }
    if (stripped) {
      // Written straight through set(), not setJson(): the history is not itself
      // a private key, and the rows have already had the private halves removed.
      set(KEYS.HISTORY, JSON.stringify(history));
    }
    log.debug("Leaving forgetStoredHolderPrivateKeys(). Stripped " + stripped + " history row(s).");
    return stripped;
  }
  log.debug("Leaving forgetStoredHolderPrivateKeys(). No history to strip.");
  return 0;
}

function set(key, value) {
  var s = ls();
  if (!s) return;
  if (isHolderPrivateKey(key) && !holderPrivateKeyMayBeStored()) {
    // Refused, and anything an earlier session wrote goes too — an opt-out that
    // leaves yesterday's private key in storage is not an opt-out. remove() is
    // called directly rather than via forgetStoredHolderPrivateKeys() to avoid
    // recursing back through set() on the history.
    remove(key);
    log.debug("set(): refused to store " + key + " — holder key saving is turned off.");
    return;
  }
  try {
    s.setItem(key, value);
  } catch (e) {
    // Over quota, or storage disabled: there is nothing to fall back to.
  }
}

function remove(key) {
  var s = ls();
  if (!s) return;
  try {
    s.removeItem(key);
  } catch (e) {
    // No storage in this context; nothing to remove.
  }
}

function getJson(key) {
  var raw = get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    // A value written by an older build, or hand-edited: treat it as absent.
    return null;
  }
}
function setJson(key, value) { set(key, JSON.stringify(value)); }

// Record the choice and enforce it immediately. Turning it off purges; turning
// it back on cannot un-purge, which the step 2 pane says out loud.
// Read the holder private key for a page that needs to SIGN with it.
//
// With storage on this is just a read. With storage off there is nothing to
// read, so the page offers a field to paste the downloaded key into and this
// falls back to it — which is the whole reason the opt-out is usable at all.
// The distinction between "no key" and "a key that will not parse" is returned
// rather than collapsed, because they need different things said to the user.
function readHolderPrivateJwk(inputId) {
  var stored = getJson(KEYS.HOLDER_PRIVATE_JWK);
  if (stored) return { jwk: stored, source: "storage", problem: null };
  var e = (typeof document !== "undefined" && inputId) ? document.getElementById(inputId) : null;
  var raw = (e && e.value) ? e.value.trim() : "";
  if (!raw) return { jwk: null, source: "none", problem: null };
  var parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { jwk: null, source: "pasted", problem: "the pasted holder key is not JSON: " + err.message };
  }
  // A downloaded pair is { publicJwk, privateJwk }; accept that as well as a
  // bare private JWK, because pasting back the file you were given is the
  // obvious thing to try.
  if (parsed && parsed.privateJwk) parsed = parsed.privateJwk;
  if (!parsed || !parsed.kty || !parsed.d) {
    return { jwk: null, source: "pasted",
             problem: "that JSON is not a private JWK — it needs at least kty and d" };
  }
  return { jwk: parsed, source: "pasted", problem: null };
}

function setHolderKeySaving(on) {
  log.debug("Entering setHolderKeySaving(). on=" + !!on);
  set(KEYS.SAVE_HOLDER_KEY, on ? "1" : "0");
  var stripped = 0;
  if (!on) stripped = forgetStoredHolderPrivateKeys();
  log.debug("Leaving setHolderKeySaving().");
  return stripped;
}

// ---------------------------------------------------------------------------
// The credential history: a log of every ATTEMPT, and the generations it produced.
//
// A credential is not one object over its life. The issuance produces one, and
// every refresh (OID4VCI section 14.5) is an attempt to produce another — which
// may be refused, may be deferred, may come back and be kept, or may come back
// and be thrown away. A wallet that records only the successes cannot answer "what
// did I try, what did the issuer say, and what am I holding now", which is exactly
// what a debugger is for. So EVERY attempt is recorded here, oldest first:
//
//   kind      what was attempted — an issuance, an access-token refresh
//             (RFC 6749 section 6), a Credential Request, or a poll of the
//             Deferred Credential Endpoint
//   outcome   what came of it — success / failed / deferred / pending (the issuer
//             returned a credential and the holder has not decided yet) /
//             kept / discarded
//   detail    what the issuer actually said, including the error
//
// The subset the wallet HOLDS — outcome "kept", with a credential — are the
// generations step 4 navigates; everything else is a log row that cannot be
// activated. Generation numbers are derived from that subset in order, not stored,
// so they stay consistent when the log is trimmed.
//
// A held entry carries its own holder key pair, because a credential whose cnf key
// the wallet has lost cannot be presented at all: going back to an earlier
// generation has to bring that key with it.
// ---------------------------------------------------------------------------
// The window the pane shows and the store keeps: 100 attempts. Log rows are
// cheap, and only held and pending entries carry a credential, so this is a few
// hundred KB at the very worst.
var HISTORY_LIMIT = 100;

var HISTORY_KIND = {
  ISSUANCE: "issuance",
  TOKEN_REFRESH: "token_refresh",
  CREDENTIAL_REQUEST: "credential_request",
  DEFERRED_POLL: "deferred_poll"
};

var HISTORY_OUTCOME = {
  SUCCESS: "success",
  FAILED: "failed",
  DEFERRED: "deferred",
  PENDING: "pending",
  KEPT: "kept",
  DISCARDED: "discarded"
};

// Read the log, upgrading anything written by an earlier build rather than
// discarding it: those entries were all credentials the wallet held.
function credentialHistory() {
  var history = getJson(KEYS.HISTORY);
  if (Object.prototype.toString.call(history) !== "[object Array]") return [];
  return history.map(function (entry, index) {
    var upgraded = entry || {};
    if (!upgraded.id) upgraded.id = index + 1;
    if (!upgraded.kind) {
      upgraded.kind = /^issued/.test(upgraded.source || "")
        ? HISTORY_KIND.ISSUANCE : HISTORY_KIND.CREDENTIAL_REQUEST;
    }
    if (!upgraded.outcome) upgraded.outcome = HISTORY_OUTCOME.KEPT;
    return upgraded;
  });
}

// The generations the wallet holds, oldest first: { id, entry, generation }.
function heldGenerations() {
  var out = [];
  credentialHistory().forEach(function (entry) {
    if (entry.outcome !== HISTORY_OUTCOME.KEPT || !entry.credential) return;
    out.push({ id: entry.id, entry: entry, generation: out.length + 1 });
  });
  return out;
}

// The generation in hand. HISTORY_INDEX holds the entry's id; an id that is no
// longer there (trimmed, cleared) means the newest generation, which is what has
// just been recorded.
function activeGeneration() {
  var held = heldGenerations();
  if (!held.length) return null;
  var wanted = parseInt(get(KEYS.HISTORY_INDEX), 10);
  for (var i = 0; i < held.length; i++) {
    if (held[i].id === wanted) return { index: i, id: held[i].id, entry: held[i].entry,
                                        generation: held[i].generation, total: held.length };
  }
  var last = held.length - 1;
  return { index: last, id: held[last].id, entry: held[last].entry,
           generation: held[last].generation, total: held.length };
}

// How many generations fell off the end of the list. Kept so the pane can say so:
// a history that silently forgets reads as a complete one.
function droppedGenerations() {
  var n = parseInt(get(KEYS.HISTORY_DROPPED) || "0", 10);
  return isNaN(n) ? 0 : n;
}

// The few things the history table shows about a credential, read off it once
// when it is recorded rather than on every render.
function summarizeCredential(serialized) {
  log.debug("Entering summarizeCredential().");
  var summary = { vct: "", iat: 0, nbf: 0, exp: 0, disclosures: 0, boundKey: "", signature: "",
                  format: "" };
  var parsed;
  try {
    // Format-aware: Credential History holds whatever the wallet was issued, and
    // a jwt_vc_json generation must summarise rather than fall into the
    // unparseable branch below and show a blank row.
    parsed = parseCredential(serialized);
  } catch (e) {
    // A credential this build cannot parse is still one the wallet held; it goes
    // in the history with an empty summary rather than being dropped.
    log.debug("Leaving summarizeCredential(). Unparseable: " + e.message);
    return summary;
  }
  var payload = parsed.payload || {};
  summary.format = parsed.format || "";
  // For a jwt_vc_json there is no vct; the row shows what the credential says it
  // is instead, so the column is never blank for a credential that parsed.
  summary.vct = payload.vct || credentialLabel(parsed);
  summary.iat = payload.iat || 0;
  summary.nbf = payload.nbf || 0;
  summary.exp = payload.exp || 0;
  summary.disclosures = (parsed.disclosures || []).length;
  summary.boundKey = (payload.cnf && payload.cnf.jwk && payload.cnf.jwk.x) || "";
  summary.signature = parsed.signature || "";
  log.debug("Leaving summarizeCredential(). vct=" + summary.vct);
  return summary;
}

// ---------------------------------------------------------------------------
// Recording.
//
// `recordHistoryEntry` appends one row per attempt and returns its id, which the
// caller keeps so the row can be resolved later: a Credential Request is recorded
// the moment the issuer answers, and becomes "kept" or "discarded" when the holder
// decides. Trimming drops the oldest LOG rows first and only touches a held
// generation when there is nothing else left to drop, so an audit trail of
// attempts never costs the ability to go back to a credential.
// ---------------------------------------------------------------------------
function recordHistoryEntry(entry) {
  log.debug("Entering recordHistoryEntry(). kind=" + (entry && entry.kind) +
            ", outcome=" + (entry && entry.outcome));
  var history = credentialHistory();
  var nextId = 1;
  history.forEach(function (e) { if (e.id >= nextId) nextId = e.id + 1; });
  var credential = entry.credential || "";
  var row = {
    id: nextId,
    at: new Date().toISOString(),
    kind: entry.kind || HISTORY_KIND.CREDENTIAL_REQUEST,
    outcome: entry.outcome || HISTORY_OUTCOME.SUCCESS,
    detail: entry.detail || "",
    source: entry.source || ""
  };
  if (credential) {
    row.credential = credential;
    row.credentials = entry.credentials && entry.credentials.length ? entry.credentials : [credential];
    row.meta = entry.meta || {};
    row.holderJwk = entry.holderJwk || null;
    // The private half is recorded per generation so an older credential can be
    // made current again and still be presentable — unless the user has opted
    // out of keeping holder private keys at all, in which case the row carries
    // the public half only and that generation is viewable but not presentable.
    row.holderPrivateJwk = holderPrivateKeyMayBeStored() ? (entry.holderPrivateJwk || null) : null;
    row.summary = summarizeCredential(credential);
  }
  history.push(row);
  trimHistory(history);
  setJson(KEYS.HISTORY, history);
  // Anything the wallet is now holding is also the generation in hand.
  if (row.outcome === HISTORY_OUTCOME.KEPT && credential) set(KEYS.HISTORY_INDEX, String(row.id));
  log.debug("Leaving recordHistoryEntry(). id=" + row.id + ", " + history.length + " row(s).");
  return row.id;
}

// Resolve an attempt already recorded: pending -> kept / discarded, deferred ->
// pending, and so on. Merging rather than appending keeps it one row per attempt.
function updateHistoryEntry(id, changes) {
  log.debug("Entering updateHistoryEntry(). id=" + id);
  var history = credentialHistory();
  var found = null;
  history.forEach(function (e) { if (e.id === id) found = e; });
  if (!found) {
    log.debug("Leaving updateHistoryEntry(). No entry " + id + " (trimmed or cleared).");
    return null;
  }
  Object.keys(changes || {}).forEach(function (k) {
    if (changes[k] === undefined) delete found[k];
    else found[k] = changes[k];
  });
  if (found.credential && !found.summary) found.summary = summarizeCredential(found.credential);
  setJson(KEYS.HISTORY, history);
  if (found.outcome === HISTORY_OUTCOME.KEPT && found.credential) {
    set(KEYS.HISTORY_INDEX, String(found.id));
  }
  log.debug("Leaving updateHistoryEntry(). outcome=" + found.outcome);
  return found;
}

function trimHistory(history) {
  log.debug("Entering trimHistory(). " + history.length + " row(s).");
  var droppedHeld = 0;
  while (history.length > HISTORY_LIMIT) {
    // The oldest row that is NOT a generation the wallet holds; if every row is
    // one, the oldest generation goes and is counted, because the pane says so.
    var victim = -1;
    for (var i = 0; i < history.length; i++) {
      if (history[i].outcome !== HISTORY_OUTCOME.KEPT || !history[i].credential) { victim = i; break; }
    }
    if (victim === -1) { victim = 0; droppedHeld++; }
    history.splice(victim, 1);
  }
  if (droppedHeld) {
    set(KEYS.HISTORY_DROPPED, String(droppedGenerations() + droppedHeld));
    log.debug("trimHistory(): dropped " + droppedHeld + " held generation(s) past the limit of " +
              HISTORY_LIMIT + ".");
  }
  log.debug("Leaving trimHistory().");
}

// Record a credential the wallet has taken into its hand (step 2's issuance), and
// make it the active generation.
function recordCredentialGeneration(entry) {
  log.debug("Entering recordCredentialGeneration(). source=" + (entry && entry.source));
  var credential = (entry && entry.credential) || "";
  if (!credential) {
    log.debug("Leaving recordCredentialGeneration(). There is no credential to record.");
    return -1;
  }
  // The same bytes twice in a row are one generation, not two: a page that
  // re-stores what it already stored (a reload, a retried click) must not make
  // the history say the wallet was issued two credentials.
  var held = heldGenerations();
  if (held.length && held[held.length - 1].entry.credential === credential) {
    set(KEYS.HISTORY_INDEX, String(held[held.length - 1].id));
    log.debug("Leaving recordCredentialGeneration(). Already the newest generation.");
    return held[held.length - 1].id;
  }
  var id = recordHistoryEntry({
    kind: entry.kind || HISTORY_KIND.ISSUANCE,
    outcome: HISTORY_OUTCOME.KEPT,
    detail: entry.detail || "",
    source: entry.source || "issued",
    credential: credential,
    credentials: entry.credentials,
    meta: entry.meta,
    holderJwk: entry.holderJwk,
    holderPrivateJwk: entry.holderPrivateJwk
  });
  log.debug("Leaving recordCredentialGeneration(). id=" + id);
  return id;
}

// Make an earlier (or later) generation the credential the wallet holds — with
// its holder key, or the credential could not be presented. Identified by entry
// id, so a log row appearing between two generations cannot shift it.
function activateCredentialGeneration(id) {
  log.debug("Entering activateCredentialGeneration(). id=" + id);
  var held = heldGenerations();
  var target = null;
  held.forEach(function (h) { if (h.id === id) target = h; });
  if (!target) {
    log.debug("Leaving activateCredentialGeneration(). No generation with id " + id + ".");
    return null;
  }
  var entry = target.entry;
  set(KEYS.CREDENTIAL, entry.credential);
  setJson(KEYS.CREDENTIALS, entry.credentials || [entry.credential]);
  setJson(KEYS.CREDENTIAL_META, entry.meta || {});
  if (entry.holderJwk && entry.holderPrivateJwk) {
    setJson(KEYS.HOLDER_JWK, entry.holderJwk);
    setJson(KEYS.HOLDER_PRIVATE_JWK, entry.holderPrivateJwk);
  }
  set(KEYS.HISTORY_INDEX, String(id));
  log.debug("Leaving activateCredentialGeneration(). Generation " + target.generation + " is now in hand.");
  return entry;
}

// Forget the list, not the credential: whatever is in hand stays in hand.
//
// An EMPTY list is written rather than the key removed, because "cleared on
// purpose" and "nothing was ever recorded" are different: only the second should
// make a page backfill the credential in hand as generation 1. hasCredentialHistory()
// is that distinction.
function clearCredentialHistory() {
  log.debug("Entering clearCredentialHistory().");
  setJson(KEYS.HISTORY, []);
  remove(KEYS.HISTORY_INDEX);
  remove(KEYS.HISTORY_DROPPED);
  log.debug("Leaving clearCredentialHistory().");
}

// Whether this browser has ever recorded a generation — as opposed to holding an
// empty list because someone cleared it.
function hasCredentialHistory() { return get(KEYS.HISTORY) !== null; }

// --- the hand-off to the OIDC pages ----------------------------------------
function startFlow() {
  set(KEYS.FLOW, FLOW_ACTIVE);
  set(KEYS.RETURN, STEP2_URL);
}
function isFlowActive() { return get(KEYS.FLOW) === FLOW_ACTIVE; }
// Consumed by debugger2.html the moment it forwards, so a later, unrelated
// token exchange on that page does not get redirected too.
function endFlow() { remove(KEYS.FLOW); }
function returnUrl() { return get(KEYS.RETURN) || STEP2_URL; }

// --- what the Credential Request needs --------------------------------------
// Read from localStorage rather than the DOM: steps 2 and 3 do not carry the
// Configuration Parameters pane, but they run on what it saved.
function storedRequestConfig() {
  log.debug("Entering storedRequestConfig().");
  function v(name) { return get(vciMetadata.idFor(name)) || ""; }
  log.debug("Leaving storedRequestConfig().");
  return {
    credentialIssuer: v("credential_issuer"),
    credentialEndpoint: v("credential_endpoint"),
    nonceEndpoint: v("nonce_endpoint"),
    notificationEndpoint: v("notification_endpoint"),
    // OPTIONAL, and absent from issuers that cannot defer an issuance at all.
    deferredCredentialEndpoint: v("deferred_credential_endpoint"),
    credentialConfigurationId: v("credential_configuration_id"),
    format: v("format"),
    vct: v("vct"),
    proofAlgs: v("proof_signing_alg_values_supported")
  };
}

// ---------------------------------------------------------------------------
// SD-JWT parsing — RFC 9901 section 4.
//
// Combined Serialization is
//
//   <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<Key Binding JWT>]
//
// with the trailing ~ REQUIRED when there is no Key Binding JWT. So an empty
// last part means "no KB-JWT", and a non-empty one is the KB-JWT.
//
// A Disclosure is base64url(JSON), either [salt, claim name, claim value] for
// an object property or [salt, value] for an array element.
// ---------------------------------------------------------------------------
function parseSdJwt(serialized) {
  log.debug("Entering parseSdJwt().");
  var raw = String(serialized || "").trim();
  if (!raw) throw new Error("There is no credential to parse.");
  var parts = raw.split("~");
  var issuerJwt = parts.shift();
  var kbJwt = "";
  if (parts.length && parts[parts.length - 1] !== "") {
    kbJwt = parts.pop();
  } else if (parts.length) {
    parts.pop(); // the required trailing empty part
  }
  var jwtParts = String(issuerJwt).split(".");
  if (jwtParts.length !== 3) throw new Error("The issuer-signed part is not a three-part JWS.");

  var header, payload;
  try {
    header = metadataClient.b64uToJson(jwtParts[0]);
  } catch (e) {
    throw new Error("Cannot read the issuer-signed JWT header: " + e.message);
  }
  try {
    payload = metadataClient.b64uToJson(jwtParts[1]);
  } catch (e) {
    throw new Error("Cannot read the issuer-signed JWT payload: " + e.message);
  }

  var disclosures = parts.filter(function (p) { return p !== ""; }).map(function (encoded) {
    var d = { encoded: encoded, salt: "", name: null, value: undefined, arrayElement: false, error: "" };
    try {
      var arr = metadataClient.b64uToJson(encoded);
      if (Object.prototype.toString.call(arr) !== "[object Array]") {
        throw new Error("a Disclosure must be a JSON array");
      }
      d.salt = arr[0];
      if (arr.length === 3) { d.name = arr[1]; d.value = arr[2]; }
      else if (arr.length === 2) { d.arrayElement = true; d.value = arr[1]; }
      else { throw new Error("a Disclosure has 2 (array element) or 3 (object property) members, got " + arr.length); }
    } catch (e) {
      d.error = e.message;
    }
    return d;
  });

  log.debug("Leaving parseSdJwt().");
  return {
    serialized: raw,
    issuerJwt: issuerJwt,
    header: header,
    payload: payload,
    signature: jwtParts[2],
    disclosures: disclosures,
    kbJwt: kbJwt
  };
}

// ---------------------------------------------------------------------------
// Two credential formats.
//
// The workflow issues and presents SD-JWT VC (dc+sd-jwt) and W3C VC secured as
// a JWT (jwt_vc_json). They differ in the one thing the workflow is about:
// jwt_vc_json has NO selective disclosure. Everything it carries is in the
// clear, so presenting it hands over all of it, and holder binding is done by
// signing a Verifiable Presentation JWT around it rather than by a Key Binding
// JWT.
//
// Rather than branch on the format at each of the dozen places that read a
// credential, they all go through parseCredential(), which returns the SAME
// shape for both: `disclosures` is simply an empty array for jwt_vc_json, and
// `claims` is the claim set either way.
// ---------------------------------------------------------------------------
var FORMAT_SD_JWT = "dc+sd-jwt";
var FORMAT_JWT_VC_JSON = "jwt_vc_json";
var FORMAT_LDP_VC = "ldp_vc";

// Which format some stored bytes are.
//
// The tilde decides it, and nothing else can: an SD-JWT Combined Serialization
// is <JWT>~<Disclosure>*~ and ALWAYS carries at least the trailing one, while a
// VC-JWT never does. Counting dot-separated parts does not work — the tildes
// hang off the signature segment, so an SD-JWT also splits into exactly three.
function credentialFormat(serialized) {
  // ldp_vc is the odd one out and is checked first: it is a JSON OBJECT with an
  // embedded proof, where the other two are compact-serialized strings. Stored
  // credentials are strings, so an ldp_vc arrives as JSON text beginning with
  // "{" — which neither of the others can.
  if (serialized && typeof serialized === "object") {
    return (serialized.proof && serialized.proof.type === "DataIntegrityProof") ? FORMAT_LDP_VC : "";
  }
  var raw = String(serialized || "").trim();
  if (!raw) return "";
  if (raw.charAt(0) === "{") {
    try {
      var doc = JSON.parse(raw);
      if (doc && doc.proof && doc.proof.type === "DataIntegrityProof") return FORMAT_LDP_VC;
    } catch (e) {
      // Not JSON after all; fall through to the string formats below.
      log.debug("credentialFormat(): leading brace but not JSON.");
    }
    return "";
  }
  if (raw.indexOf("~") >= 0) return FORMAT_SD_JWT;
  if (raw.split(".").length === 3) return FORMAT_JWT_VC_JSON;
  return "";
}

// An ldp_vc credential, parsed into the same shape as the other two.
//
// `disclosures` is empty as it is for jwt_vc_json, but for the OPPOSITE reason:
// jwt_vc_json cannot withhold anything, while ldp_vc can withhold nearly
// everything — just not by carrying Disclosures. What it selects over is
// canonical statements, and those are only known after canonicalization, which
// is async and therefore not done here.
function parseLdpVc(serialized) {
  log.debug("Entering parseLdpVc().");
  var doc = (serialized && typeof serialized === "object")
    ? serialized : JSON.parse(String(serialized));
  var subject = doc.credentialSubject || {};
  log.debug("Leaving parseLdpVc().");
  return {
    serialized: typeof serialized === "string" ? serialized : JSON.stringify(doc),
    document: doc,
    header: { cryptosuite: (doc.proof || {}).cryptosuite, type: (doc.proof || {}).type },
    payload: doc,
    signature: (doc.proof || {}).proofValue || "",
    credentialSubject: subject,
    disclosures: [],
    kbJwt: ""
  };
}

// A W3C Verifiable Credential secured as a JWT (VC-JWT). The credential object
// is in the `vc` claim; the JWT's own claims carry the issuer, subject and
// validity window.
function parseJwtVc(serialized) {
  log.debug("Entering parseJwtVc().");
  var raw = String(serialized || "").trim();
  if (!raw) throw new Error("There is no credential to parse.");
  var parts = raw.split(".");
  if (parts.length !== 3) throw new Error("A jwt_vc_json credential is a three-part JWS.");
  var header, payload;
  try {
    header = metadataClient.b64uToJson(parts[0]);
  } catch (e) {
    throw new Error("Cannot read the credential JWT header: " + e.message);
  }
  try {
    payload = metadataClient.b64uToJson(parts[1]);
  } catch (e) {
    throw new Error("Cannot read the credential JWT payload: " + e.message);
  }
  var vc = payload.vc || {};
  if (!vc || typeof vc !== "object") throw new Error("The JWT carries no vc claim, so it is not a VC-JWT.");
  log.debug("Leaving parseJwtVc().");
  return {
    serialized: raw, issuerJwt: raw, header: header, payload: payload,
    signature: parts[2], vc: vc,
    credentialSubject: vc.credentialSubject || {},
    disclosures: [], kbJwt: ""
  };
}

// The claim set a credential asserts, as a flat name -> value map, whichever
// format it is in. For an SD-JWT that is what its Disclosures reveal; for a
// jwt_vc_json it is credentialSubject, minus `id`, which identifies the subject
// rather than saying anything about them.
function claimsOf(parsed) {
  var out = {};
  if (!parsed) return out;
  if (parsed.format === FORMAT_JWT_VC_JSON || parsed.format === FORMAT_LDP_VC) {
    var subject = parsed.credentialSubject || {};
    Object.keys(subject).forEach(function (name) {
      if (name !== "id") out[name] = subject[name];
    });
    return out;
  }
  (parsed.disclosures || []).forEach(function (d) {
    if (d && d.name != null) out[d.name] = d.value;
  });
  return out;
}

// Parse whichever format the bytes are, into one shape.
function parseCredential(serialized) {
  log.debug("Entering parseCredential().");
  var format = credentialFormat(serialized);
  if (!format) throw new Error("This does not look like an SD-JWT VC or a jwt_vc_json credential.");
  var parsed = format === FORMAT_LDP_VC ? parseLdpVc(serialized)
             : format === FORMAT_JWT_VC_JSON ? parseJwtVc(serialized)
             : parseSdJwt(serialized);
  parsed.format = format;
  parsed.claims = claimsOf(parsed);
  // ldp_vc IS selectively disclosable — more so than SD-JWT, and unlinkably —
  // but over canonical statements rather than Disclosures.
  parsed.selectivelyDisclosable = format === FORMAT_SD_JWT || format === FORMAT_LDP_VC;
  // What the credential says it IS: a vct for an SD-JWT VC, a type array for a
  // W3C VC. Both are surfaced so a caller can name the credential without
  // knowing which format it holds.
  parsed.vct = (parsed.payload || {}).vct || "";
  parsed.types = format === FORMAT_JWT_VC_JSON ? [].concat((parsed.vc || {}).type || [])
               : format === FORMAT_LDP_VC ? [].concat((parsed.document || {}).type || [])
               : [];
  parsed.subject = (parsed.payload || {}).sub || (parsed.credentialSubject || {}).id || "";
  log.debug("Leaving parseCredential(). format=" + format + ", " +
            Object.keys(parsed.claims).length + " claim(s), " +
            parsed.disclosures.length + " disclosure(s).");
  return parsed;
}

// What to call this credential in a sentence.
function credentialLabel(parsed) {
  if (!parsed) return "credential";
  if (parsed.format === FORMAT_JWT_VC_JSON || parsed.format === FORMAT_LDP_VC) {
    var types = (parsed.types || []).filter(function (t) { return t !== "VerifiableCredential"; });
    return types.length ? types.join(", ") : "Verifiable Credential";
  }
  return parsed.vct || "credential";
}

// --- holder binding, whichever way the format expresses it ------------------
//
// A did:jwk identifier IS the key: the part after the method prefix is the
// base64url JWK itself, so it resolves with no network call. Shared rather than
// duplicated because issuance step 3 resolves an ISSUER key this way (walt.id
// signs with a did:jwk) and step 4 resolves a HOLDER key this way — the same
// decoding for two different purposes.
function jwkFromDid(did) {
  log.debug("Entering jwkFromDid(). did=" + String(did).slice(0, 40));
  var prefix = "did:jwk:";
  if (String(did || "").indexOf(prefix) !== 0) {
    log.debug("Leaving jwkFromDid(). Not a did:jwk.");
    return null;
  }
  var encoded = String(did).slice(prefix.length).split("#")[0];
  var jwk;
  try {
    jwk = metadataClient.b64uToJson(encoded);
  } catch (e) {
    // A did:jwk whose body is not base64url JSON is simply not resolvable here;
    // callers have other resolution paths, or report it as unresolvable.
    log.debug("Leaving jwkFromDid(). Undecodable: " + e.message);
    return null;
  }
  log.debug("Leaving jwkFromDid(). Decoded a " + (jwk && jwk.kty) + " key.");
  return jwk && jwk.kty ? jwk : null;
}

// The holder public key a credential is bound to — the thing a verifier will
// demand proof of possession of.
//
// The two families express it completely differently, and reading only one of
// them is what made issuance step 4 report an ldp_vc as unbound:
//
//   dc+sd-jwt, jwt_vc_json   payload.cnf.jwk — a confirmation claim, RFC 7800;
//   ldp_vc                   credentialSubject.id, a did:jwk. A W3C credential
//                            has no cnf claim at all, and holder binding at
//                            presentation time is the BBS derived proof itself
//                            rather than a separate signature by the holder.
//
// Returns a public JWK or null, so callers can compare it against a key they
// hold without caring which format produced it.
function boundHolderJwk(parsed) {
  if (!parsed) return null;
  if (parsed.format === FORMAT_LDP_VC) {
    return jwkFromDid((parsed.credentialSubject || {}).id);
  }
  var cnf = (parsed.payload || {}).cnf;
  return (cnf && cnf.jwk) || null;
}

// What that binding is CALLED in this format, for panes that name it. Naming
// cnf.jwk on a credential that has no cnf claim is how a correct pane still
// tells the user something false.
function bindingMemberName(parsed) {
  return (parsed && parsed.format === FORMAT_LDP_VC) ? "credentialSubject.id" : "cnf.jwk";
}

// What the credential's TYPE is called: an SD-JWT VC has a vct, a W3C credential
// has a type array. Same reasoning as bindingMemberName().
function typeMemberName(parsed) {
  return (parsed && (parsed.format === FORMAT_LDP_VC || parsed.format === FORMAT_JWT_VC_JSON))
    ? "type" : "vct";
}

// --- the validity window, whichever members carry it ------------------------
//
// The two families disagree here too, and in a way that reads as absence rather
// than as difference — which is worse, because a pane that says "no exp claim,
// so it does not expire on its own" about a credential that expires in a month
// is not merely unhelpful, it is wrong in the reassuring direction:
//
//   dc+sd-jwt, jwt_vc_json   nbf / exp, NumericDate (seconds since the epoch);
//   ldp_vc                   validFrom / validUntil, ISO 8601 strings. W3C VCDM
//                            1.1 called them issuanceDate / expirationDate, and
//                            a credential in the wild may still use those, so
//                            both spellings are read.
//
// Returns seconds since the epoch (or null), so callers format dates one way
// regardless of which member the value came out of, and the member NAMES so a
// pane can say which it read.
function validityWindowOf(parsed) {
  log.debug("Entering validityWindowOf().");
  var payload = (parsed && parsed.payload) || {};
  if (parsed && parsed.format === FORMAT_LDP_VC) {
    var from = payload.validFrom || payload.issuanceDate || "";
    var until = payload.validUntil || payload.expirationDate || "";
    log.debug("Leaving validityWindowOf(). ldp_vc: " + (from || "no start") + " → " +
              (until || "no end"));
    return {
      notBefore: epochFromIso(from),
      expires: epochFromIso(until),
      notBeforeMember: payload.issuanceDate && !payload.validFrom ? "issuanceDate" : "validFrom",
      expiresMember: payload.expirationDate && !payload.validUntil ? "expirationDate" : "validUntil"
    };
  }
  log.debug("Leaving validityWindowOf(). nbf/exp.");
  return {
    notBefore: typeof payload.nbf === "number" ? payload.nbf : null,
    expires: typeof payload.exp === "number" ? payload.exp : null,
    notBeforeMember: "nbf",
    expiresMember: "exp"
  };
}

// An ISO 8601 instant as seconds since the epoch. Null for anything unparseable,
// so a malformed date is reported as absent rather than as 1970.
function epochFromIso(value) {
  if (!value) return null;
  var ms = Date.parse(String(value));
  if (isNaN(ms)) {
    log.debug("epochFromIso(): not a parseable instant: " + String(value).slice(0, 40));
    return null;
  }
  return Math.floor(ms / 1000);
}

// Can what this wallet is holding actually be presented?
//
// Issuance steps 3 and 4 both offer a hand-off into the PRESENTATION workflow.
// Nothing is copied by that hand-off — the two workflows meet at these storage
// keys and nowhere else, so the credential is already where the other workflow
// looks. What the offer owes the user is therefore not a transfer but an honest
// answer to "will anything happen if I click this", and that answer is whatever
// presentation step 1 will decide when it gets there. This is that decision, in
// one place, so an offer and the workflow it leads to cannot disagree — the
// three-way distinction below mirrors renderRequest() in
// vc_presentation_1.js and must keep mirroring it.
function presentationReadiness() {
  log.debug("Entering presentationReadiness().");
  var raw = (get(KEYS.CREDENTIAL) || "").trim();
  if (!raw) {
    log.debug("Leaving presentationReadiness(). Nothing held.");
    return { ready: false, level: "vc-bad",
             message: "Nothing is held yet — the presentation workflow presents a credential this wallet " +
                      "already has." };
  }
  var parsed = null;
  try {
    parsed = parseCredential(raw);
  } catch (e) {
    log.debug("Leaving presentationReadiness(). Unparseable.");
    return { ready: false, level: "vc-bad",
             message: "The credential in storage cannot be parsed, so it cannot be presented: " + e.message };
  }
  // What a Verifier would be shown, said differently for the two formats
  // because the difference is the point: an SD-JWT offers a CHOICE of claims,
  // a jwt_vc_json offers all of them or nothing.
  var offered = parsed.format === FORMAT_JWT_VC_JSON
    ? "the " + credentialLabel(parsed) + " above — all " + Object.keys(parsed.claims).length +
      " of its claims, because jwt_vc_json has no selective disclosure"
    : parsed.format === FORMAT_LDP_VC
      ? "the " + credentialLabel(parsed) + " above (ldp_vc, bbs-2023) — you choose which statements " +
        "go, and each presentation is a fresh proof that cannot be linked to the last"
      : "the " + credentialLabel(parsed) + " above, with its " +
        parsed.disclosures.length + " selectively-disclosable claim(s)";
  // ldp_vc needs no holder private key to present: the BBS derived proof IS the
  // holder's act, and the credential names its subject by DID rather than by a
  // cnf key the wallet must sign with. Gating it on a holder key would strand
  // the user for a reason that does not apply to this format.
  if (parsed.format === FORMAT_LDP_VC) {
    log.debug("Leaving presentationReadiness(). ldp_vc, ready.");
    return { ready: true, level: "vc-ok", message: "A Verifier would be offered " + offered + "." };
  }
  if (getJson(KEYS.HOLDER_PRIVATE_JWK)) {
    log.debug("Leaving presentationReadiness(). Ready.");
    return { ready: true, level: "vc-ok",
             message: "A Verifier would be offered " + offered + ", signed with the holder key it is bound to." };
  }
  if (holderPrivateKeyMayBeStored()) {
    // Saving is ON and the key is still absent, so it was never generated in this
    // browser: there is nothing to paste, and presentation step 1 refuses to
    // continue past exactly this. Blocking here says so one page earlier.
    log.debug("Leaving presentationReadiness(). Key lost.");
    return { ready: false, level: "vc-bad",
             message: "The private half of the holder key is missing, so no Key Binding JWT could be signed " +
                      "for this credential — the presentation workflow would stop at step 1." };
  }
  // Deliberately not kept (the checkbox on issuance step 2). Presentation step 2
  // has a field to paste it into, so this is an advisory and must NOT block:
  // refusing here would strand the user two pages before the only field that
  // fixes it.
  log.debug("Leaving presentationReadiness(). Ready, key to be pasted.");
  return { ready: true, level: "vc-pending",
           message: "A Verifier would be offered " + offered + ". The holder key is not kept in this browser, " +
                    "by the choice made on issuance step 2 — you will be asked to paste it when the " +
                    "presentation is assembled." };
}

// The digest that an SD-JWT's _sd array carries for a Disclosure: the hash of
// the US-ASCII of the base64url-encoded Disclosure, base64url-encoded.
// _sd_alg defaults to sha-256 (RFC 9901 section 4.1.1).
function digestForDisclosure(encoded, sdAlg) {
  var alg = String(sdAlg || "sha-256").toLowerCase();
  var webcrypto = { "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" }[alg];
  if (!webcrypto) return Promise.reject(new Error('unsupported _sd_alg "' + sdAlg + '".'));
  var bytes = new Uint8Array(String(encoded).length);
  for (var i = 0; i < encoded.length; i++) { bytes[i] = encoded.charCodeAt(i) & 0xff; }
  return crypto.subtle.digest(webcrypto, bytes).then(function (buf) {
    return metadataClient.bytesToB64u(buf);
  });
}

// Every _sd digest in the payload, at any nesting depth, plus the {"...": digest}
// form used for selectively-disclosable ARRAY elements.
function collectSdDigests(node, out) {
  log.debug("Entering collectSdDigests().");
  out = out || [];
  if (!node || typeof node !== "object") return out;
  if (Object.prototype.toString.call(node) === "[object Array]") {
    node.forEach(function (item) {
      if (item && typeof item === "object" && typeof item["..."] === "string") out.push(item["..."]);
      else collectSdDigests(item, out);
    });
    return out;
  }
  Object.keys(node).forEach(function (k) {
    if (k === "_sd" && Object.prototype.toString.call(node[k]) === "[object Array]") {
      node[k].forEach(function (d) { if (typeof d === "string") out.push(d); });
    } else if (typeof node[k] === "object") {
      collectSdDigests(node[k], out);
    }
  });
  log.debug("Leaving collectSdDigests().");
  return out;
}

// The claim set a verifier would end up with: the always-visible claims of the
// payload (minus the SD-JWT machinery) plus every disclosed claim.
function disclosedClaims(parsed) {
  var claims = {};
  Object.keys(parsed.payload || {}).forEach(function (k) {
    if (k === "_sd" || k === "_sd_alg") return;
    claims[k] = parsed.payload[k];
  });
  (parsed.disclosures || []).forEach(function (d) {
    if (d.error || d.arrayElement || d.name === null) return;
    claims[d.name] = d.value;
  });
  return claims;
}

module.exports = {
  KEYS: KEYS,
  HOLDER_PRIVATE_KEYS: HOLDER_PRIVATE_KEYS,
  holderPrivateKeyMayBeStored: holderPrivateKeyMayBeStored,
  setHolderKeySaving: setHolderKeySaving,
  readHolderPrivateJwk: readHolderPrivateJwk,
  forgetStoredHolderPrivateKeys: forgetStoredHolderPrivateKeys,
  USE_CASES: USE_CASES,
  DEFAULT_USE_CASE: DEFAULT_USE_CASE,
  useCases: useCases,
  useCaseById: useCaseById,
  currentUseCase: currentUseCase,
  setUseCase: setUseCase,
  renderUseCaseBadge: renderUseCaseBadge,
  storeOffer: storeOffer,
  storedOffer: storedOffer,
  forgetOffer: forgetOffer,
  offerIssuerState: offerIssuerState,
  PRE_AUTHORIZED_GRANT: PRE_AUTHORIZED_GRANT,
  preAuthorizedGrant: preAuthorizedGrant,
  offerTxCode: offerTxCode,
  offerPreAuthorizedCode: offerPreAuthorizedCode,
  STEP2_URL: STEP2_URL,
  STEP3_URL: STEP3_URL,
  STEP4_URL: STEP4_URL,
  PRESENTATION_URL: PRESENTATION_URL,
  presentationReadiness: presentationReadiness,
  get: get,
  set: set,
  remove: remove,
  getJson: getJson,
  setJson: setJson,
  startFlow: startFlow,
  isFlowActive: isFlowActive,
  endFlow: endFlow,
  returnUrl: returnUrl,
  storedRequestConfig: storedRequestConfig,
  HISTORY_LIMIT: HISTORY_LIMIT,
  HISTORY_KIND: HISTORY_KIND,
  HISTORY_OUTCOME: HISTORY_OUTCOME,
  credentialHistory: credentialHistory,
  hasCredentialHistory: hasCredentialHistory,
  heldGenerations: heldGenerations,
  activeGeneration: activeGeneration,
  droppedGenerations: droppedGenerations,
  summarizeCredential: summarizeCredential,
  recordHistoryEntry: recordHistoryEntry,
  updateHistoryEntry: updateHistoryEntry,
  recordCredentialGeneration: recordCredentialGeneration,
  activateCredentialGeneration: activateCredentialGeneration,
  clearCredentialHistory: clearCredentialHistory,
  parseSdJwt: parseSdJwt,
  parseJwtVc: parseJwtVc,
  parseCredential: parseCredential,
  credentialFormat: credentialFormat,
  credentialLabel: credentialLabel,
  jwkFromDid: jwkFromDid,
  boundHolderJwk: boundHolderJwk,
  bindingMemberName: bindingMemberName,
  typeMemberName: typeMemberName,
  validityWindowOf: validityWindowOf,
  claimsOf: claimsOf,
  FORMAT_SD_JWT: FORMAT_SD_JWT,
  FORMAT_JWT_VC_JSON: FORMAT_JWT_VC_JSON,
  FORMAT_LDP_VC: FORMAT_LDP_VC,
  parseLdpVc: parseLdpVc,
  digestForDisclosure: digestForDisclosure,
  collectSdDigests: collectSdDigests,
  disclosedClaims: disclosedClaims
};
