// File: session_handoff.js
//
// ---------------------------------------------------------------------------
// A ONE-SHOT SESSION HANDOFF, from any browser sign-in workflow here to the
// Shared Signals page — which needs to know what a session IS and has no way
// of its own to establish one.
//
// **WHY THIS IS NOT `token_handoff.js` WITH ANOTHER FIELD**, which was the
// first thing tried. That module carries a BEARER TOKEN: its slot is the
// access token, its `deliver()` refuses a call with no token in it, and its
// scope member is advice about an OAuth grant. A SAML 2.0, SAML 1.1,
// WS-Federation or SPNEGO sign-in produces none of those — no access token, no
// scope, and nothing a `deliver(token, …)` could honestly be handed. Bending
// that module to carry a session would have meant a token slot holding
// something that is not a token, checked by a guard that had to stop checking.
//
// So this is a SIBLING and not a generalization, and the two are used together
// on exactly one path: the OAuth2 / OIDC workflow hands over a token set
// through that module AND a session through this one, because it is the only
// protocol here whose sign-in produces both.
//
// ---------------------------------------------------------------------------
// WHAT CROSSES, AND WHY IT IS THIS LIST.
//
// Everything `caep_session.js` needs to name a session in a CAEP subject, and
// nothing else:
//
//   protocol  which sign-in produced it — 'oidc', 'saml2', 'saml11',
//             'wsfed', 'spnego'. It is carried rather than inferred because
//             it is the one fact that decides how the rest is READ, and
//             because the pane says it on screen: a reader looking at a
//             session identifier needs to know whether the protocol that
//             minted it has one at all.
//   iss       the issuer, as the receiver would know it — an OIDC `iss`, a
//             SAML <saml:Issuer>, a WS-Federation token issuer.
//   sub       the subject: an OIDC `sub`, a SAML NameID/NameIdentifier, a
//             Kerberos client principal.
//   sid       THE SESSION IDENTIFIER, and the member this whole module
//             exists for. See the paragraph below.
//   name      a human label, where the protocol carried one.
//   acr, amr  how they authenticated: an OIDC `acr`/`amr`, a SAML 2.0
//             <saml:AuthnContextClassRef>, a SAML 1.1 AuthenticationMethod.
//   tenant    where the protocol names one.
//
// ---------------------------------------------------------------------------
// THREE OF THE FIVE PROTOCOLS HAVE NO SESSION IDENTIFIER ON THE WIRE, AND
// THAT IS THE MOST USEFUL THING THIS HANDOFF REPORTS.
//
// A CAEP event whose subject names a session identifier the DEBUGGER invented
// is an event about nothing at the far end. It is well-formed, it validates,
// a receiver accepts it, and it revokes a session nobody has. The existing
// pane already says this for the one case it could see — an ID Token with no
// `sid` — and the same sentence is true, for the same reason, three more
// times:
//
//   | protocol | where the session identifier comes from        |
//   |----------|-----------------------------------------------|
//   | oidc     | the ID Token's `sid` claim, WHEN IT HAS ONE    |
//   | saml2    | <saml:AuthnStatement SessionIndex="…">        |
//   | saml11   | NOTHING — the protocol has no session index    |
//   | wsfed    | the SessionIndex of the SAML 2.0 token it      |
//   |          | carries; NOTHING when it carries a 1.1 one     |
//   | spnego   | NOTHING — a service ticket names a service,    |
//   |          | not a session at the far end                   |
//
// So `real` is carried beside `sid`: TRUE when the wire supplied it and FALSE
// when this workflow made it up. The consuming pane draws the difference
// rather than hiding it, and `caep_session.js` puts the word `debugger-sid-`
// in an invented one so nobody pastes it into a real system.
//
// ---------------------------------------------------------------------------
// `sessionStorage`, ONE SHOT, AND A TTL — the three decisions
// `token_handoff.js` argues at length and this module makes identically.
//
// Tab-scoped because the round trip goes out of this tab and comes back to it;
// removed by `take()` because a session collected twice is two workflows
// believing they own one; and expiring, because a slot filled and never
// collected would otherwise be picked up an hour later by a visit that has
// nothing to do with it. A session is not a credential the way a bearer token
// is — which is why this module says so rather than repeating that argument —
// but it names one, and a stale one names somebody else's.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "session_handoff",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var KEYS = {
  // "1" while a workflow is waiting for a session.
  ACTIVE: "session_handoff_active",
  // Where the browser goes back to, once there is one.
  RETURN: "session_handoff_return",
  // What to call the waiting workflow, on the banners the sign-in pages put
  // up. Shown as TEXT and never as markup — it crosses a page load.
  LABEL: "session_handoff_label",
  // Which protocol the waiting workflow ASKED for, so a sign-in page can say
  // whether it is the one that was meant. Advice, never a gate: a reader who
  // signs in over a different protocol gets that session, and the pane says
  // which it got.
  WANTED: "session_handoff_wanted",
  // The delivered session, as JSON. ONE SHOT: take() removes it.
  SESSION: "session_handoff_session",
  // How it was obtained: { source, at }. Also read as TEXT.
  META: "session_handoff_meta"
};

// The five browser sign-in protocols this handoff can carry, and the ONE
// place that list is written down. `ssf.js` draws its selector from this and
// `caep_session.js` labels a seeded session from it, so a sixth protocol is
// a row here rather than an edit in three files.
//
// `sessionIdOnTheWire` is not decoration: it is what decides whether the
// consuming pane reports a session identifier or admits to having invented
// one, and getting it wrong in either direction produces a workflow that
// looks right. `false` for `wsfed` is the CONSERVATIVE half of a protocol
// that is genuinely both — see `sessionIdIsReal()` below.
var PROTOCOLS = [
  { id: 'oidc', label: 'OAuth 2.0 / OIDC', sessionIdOnTheWire: true,
    where: 'the ID Token\'s `sid` claim, when the OP issues one' },
  { id: 'saml2', label: 'SAML 2.0', sessionIdOnTheWire: true,
    where: 'the <saml:AuthnStatement> SessionIndex attribute' },
  { id: 'saml11', label: 'SAML 1.1', sessionIdOnTheWire: false,
    where: 'nowhere — SAML 1.1 has no session index at all' },
  { id: 'wsfed', label: 'WS-Federation', sessionIdOnTheWire: false,
    where: 'the SessionIndex of the SAML 2.0 token it carries, when it ' +
      'carries one; a SAML 1.1 token has none' },
  { id: 'spnego', label: 'SPNEGO / Kerberos', sessionIdOnTheWire: false,
    where: 'nowhere — a service ticket names a service and not a session' }
];

// How long a delivered session stays collectable, in milliseconds. The gap
// this has to cover is one click — the reader pressing "Return" on the banner
// — so half an hour is already generous, and it says nothing about how long
// the session itself is good for at the identity provider.
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
    // Storage disabled for this origin. Nothing to fall back to.
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
    s.setItem(key, String(value == null ? "" : value));
    log.debug("Leaving put(). Written.");
    return true;
  } catch (e) {
    log.debug("Leaving put(). Refused: " + e.message);
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
    // Nothing to do about it and nothing to report: the slot is either gone
    // or was never readable, and both are the state the caller wanted.
    log.debug("drop(): the store refused removeItem: " + e.message);
  }
  log.debug("Leaving drop().");
}

// ---------------------------------------------------------------------------
// THE PROTOCOL TABLE, for the pages that draw from it.
// ---------------------------------------------------------------------------
function protocols() {
  log.debug("Entering protocols().");
  var copy = PROTOCOLS.map(function (one) {
    return { id: one.id, label: one.label, where: one.where,
      sessionIdOnTheWire: one.sessionIdOnTheWire };
  });
  log.debug("Leaving protocols(). " + copy.length + " protocol(s).");
  return copy;
}

function protocolFor(id) {
  log.debug("Entering protocolFor(). " + id);
  var wanted = String(id || '');
  var found = null;
  PROTOCOLS.forEach(function (one) {
    if (one.id === wanted) {
      found = one;
    }
  });
  log.debug("Leaving protocolFor(). " + (found ? found.label : '(none)'));
  return found;
}

function labelForProtocol(id) {
  log.debug("Entering labelForProtocol(). " + id);
  var found = protocolFor(id);
  var label = found ? found.label : String(id || 'an unnamed protocol');
  log.debug("Leaving labelForProtocol(). " + label);
  return label;
}

// ---------------------------------------------------------------------------
// IS THE SESSION IDENTIFIER REAL?
//
// The question the table above can only half answer, because WS-Federation is
// genuinely two protocols in one: it carries a SAML 2.0 token (which has a
// SessionIndex) or a SAML 1.1 one (which has none), and which arrived is a
// property of the RESPONSE rather than of the profile. So the table's
// `sessionIdOnTheWire` is the conservative default and this function is what
// the producers actually call — it believes a non-empty `sid` that a producer
// says it read off the wire, whatever the table's default for that protocol
// says.
//
// It is deliberately NOT "does sid look like an identifier". An invented one
// looks exactly like a real one, which is the whole problem.
// ---------------------------------------------------------------------------
function sessionIdIsReal(descriptor) {
  log.debug("Entering sessionIdIsReal().");
  var asked = descriptor || {};
  var sid = String(asked.sid || '').trim();
  if (!sid) {
    log.debug("Leaving sessionIdIsReal(). No sid at all.");
    return false;
  }
  // A producer that read one off the wire says so, and is believed.
  if (asked.sidFromTheWire === true) {
    log.debug("Leaving sessionIdIsReal(). The producer read it.");
    return true;
  }
  if (asked.sidFromTheWire === false) {
    log.debug("Leaving sessionIdIsReal(). The producer invented it.");
    return false;
  }
  // No statement either way: fall back to what the protocol can carry, which
  // is right for a caller that has not been updated and wrong for nobody.
  var profile = protocolFor(asked.protocol);
  var real = !!(profile && profile.sessionIdOnTheWire);
  log.debug("Leaving sessionIdIsReal(). From the table: " + real);
  return real;
}

// ---------------------------------------------------------------------------
// STARTING one: the consuming workflow marks itself as waiting and says where
// to come back to.
// ---------------------------------------------------------------------------
function start(options) {
  log.debug("Entering start().");
  var settings = options || {};
  var returnUrl = String(settings.returnUrl || "");
  var label = String(settings.label || "the workflow that asked for it");
  var wanted = String(settings.protocol || "");
  if (!returnUrl) {
    log.warn("a session handoff was started with no return url, so there " +
        "would be nowhere to come back to");
    log.debug("Leaving start(). No return url.");
    return false;
  }
  put(KEYS.ACTIVE, "1");
  put(KEYS.RETURN, returnUrl);
  put(KEYS.LABEL, label);
  put(KEYS.WANTED, wanted);
  // A previous delivery that was never collected is DROPPED here rather than
  // left to expire: a workflow starting a new handoff must not collect the
  // session from the last one, which is the failure that reads as a sign-in
  // that silently did nothing.
  drop(KEYS.SESSION);
  drop(KEYS.META);
  log.debug("Leaving start(). Waiting for " + (wanted || "any protocol") + ".");
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

function wantedProtocol() {
  log.debug("Entering wantedProtocol().");
  var id = get(KEYS.WANTED);
  log.debug("Leaving wantedProtocol(). " + (id || "(any)"));
  return id;
}

function cancel() {
  log.debug("Entering cancel().");
  drop(KEYS.ACTIVE);
  drop(KEYS.RETURN);
  drop(KEYS.LABEL);
  drop(KEYS.WANTED);
  drop(KEYS.SESSION);
  drop(KEYS.META);
  log.debug("Leaving cancel(). Cleared.");
}

// ---------------------------------------------------------------------------
// DELIVERING one, from whichever sign-in page completed.
//
// It refuses when no handoff is active, exactly as the token one does: a
// sign-in page finishing normally must not fill a slot nobody is waiting on,
// or the next workflow to start a handoff would collect a session from a
// sign-in that happened before it asked.
// ---------------------------------------------------------------------------
function deliver(descriptor, source) {
  log.debug("Entering deliver(). source=" + source);
  if (!isActive()) {
    log.debug("Leaving deliver(). No handoff is active.");
    return false;
  }
  var asked = descriptor || {};
  var protocol = String(asked.protocol || '');
  if (!protocolFor(protocol)) {
    log.warn("a session handoff was delivered for protocol \"" + protocol +
        "\", which is not one this module knows; it is carried anyway and " +
        "the consuming pane will label it by its own name");
  }
  var session = {
    protocol: protocol,
    iss: String(asked.iss || ''),
    sub: String(asked.sub || ''),
    name: String(asked.name || ''),
    sid: String(asked.sid || ''),
    // THE MEMBER THIS MODULE EXISTS FOR — see the header. It is computed here
    // rather than by the caller so that every producer answers the question
    // the same way, and so a producer that says nothing gets the honest
    // default for its protocol rather than an optimistic one.
    //
    // **IT KEEPS THE PRODUCER'S OWN NAME, and that is not cosmetic.** It was
    // written as `sidIsReal` for one revision, and the consumer — which calls
    // `sessionIdIsReal()` a second time on what it collected — then found
    // neither `sidFromTheWire` nor a rule for it, fell through to the table,
    // and reported a REAL WS-Federation SessionIndex as an identifier this
    // workflow had invented. Nothing failed: the event was well-formed, the
    // pane's note was simply wrong in the one direction that matters. Two
    // names for one fact is what did it, so there is one.
    sidFromTheWire: sessionIdIsReal(asked),
    acr: String(asked.acr || ''),
    amr: toList(asked.amr),
    tenant: String(asked.tenant || '')
  };
  var written = put(KEYS.SESSION, JSON.stringify(session));
  if (!written) {
    log.debug("Leaving deliver(). The store refused it.");
    return false;
  }
  put(KEYS.META, JSON.stringify({
    source: String(source || labelForProtocol(protocol)),
    at: Date.now()
  }));
  log.debug("Leaving deliver(). Delivered a " + protocol + " session.");
  return true;
}

function isDelivered() {
  log.debug("Entering isDelivered().");
  var there = !!get(KEYS.SESSION);
  log.debug("Leaving isDelivered(). " + there);
  return there;
}

// A value that may be a string, an array or absent, as an array of strings.
// SAML carries one authentication method and OIDC's `amr` is a list, so both
// shapes arrive here and a consumer must not have to know which.
function toList(value) {
  log.debug("Entering toList().");
  var out = [];
  if (Array.isArray(value)) {
    out = value.map(function (one) {
      return String(one);
    }).filter(function (one) {
      return one !== '';
    });
  } else if (typeof value === 'string' && value.trim() !== '') {
    out = value.trim().split(/\s+/);
  }
  log.debug("Leaving toList(). " + out.length + " value(s).");
  return out;
}

// ---------------------------------------------------------------------------
// COLLECTING one. ONE SHOT: the slot is cleared whether or not there was
// anything in it, and an expired delivery is reported as expired rather than
// returned — a session named by a sign-in half an hour ago is very likely
// somebody else's by now.
// ---------------------------------------------------------------------------
function take() {
  log.debug("Entering take().");
  var raw = get(KEYS.SESSION);
  var meta = {};
  try {
    meta = JSON.parse(get(KEYS.META) || "{}") || {};
  } catch (e) {
    // Somebody else's bytes in our slot, or a half-written value. The session
    // is still usable; only the provenance is lost.
    meta = {};
  }
  var session = null;
  try {
    session = raw ? JSON.parse(raw) : null;
  } catch (e) {
    log.warn("the delivered session was not readable JSON and was dropped");
    session = null;
  }
  drop(KEYS.SESSION);
  drop(KEYS.META);
  drop(KEYS.ACTIVE);
  drop(KEYS.RETURN);
  drop(KEYS.LABEL);
  drop(KEYS.WANTED);
  if (!session) {
    log.debug("Leaving take(). Nothing waiting.");
    return { session: null, source: '', expired: false };
  }
  var at = Number(meta.at || 0);
  if (at && (Date.now() - at) > TTL_MS) {
    log.debug("Leaving take(). Expired.");
    return { session: null, source: String(meta.source || ''), expired: true };
  }
  log.debug("Leaving take(). A " + session.protocol + " session.");
  return { session: session, source: String(meta.source || ''),
    expired: false };
}

module.exports = {
  KEYS: KEYS,
  TTL_MS: TTL_MS,
  PROTOCOLS: PROTOCOLS,
  protocols: protocols,
  protocolFor: protocolFor,
  labelForProtocol: labelForProtocol,
  sessionIdIsReal: sessionIdIsReal,
  start: start,
  isActive: isActive,
  returnUrl: returnUrl,
  label: label,
  wantedProtocol: wantedProtocol,
  cancel: cancel,
  deliver: deliver,
  isDelivered: isDelivered,
  take: take
};
