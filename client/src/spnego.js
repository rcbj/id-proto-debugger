// File: spnego.js
//
// ---------------------------------------------------------------------------
// SPNEGO (spnego.html): the Kerberos ticket that travels in an HTTP header.
//
// This page adds NO protocol code to the Kerberos workflow. The AP-REQ is
// krb5_client.js's, the same one kerberos_ap.html presents over a socket; the
// negotiation around it is krb5_spnego.js; the panes are kerberos_panes.js's.
// What is here is the assembly and the HTTP, which is exactly the split
// krb5_gss.js's header promised when it said SPNEGO would be "a wrapper to be
// added later rather than a rewrite".
//
// ---------------------------------------------------------------------------
// FIVE THINGS THIS PAGE SHOWS THAT NOTHING ELSE HERE DOES.
//
//  * **Both halves of both round trips, verbatim.** The unauthenticated GET and
//    its bare `WWW-Authenticate: Negotiate`, then the GET carrying
//    `Authorization: Negotiate <token>` and the answer's own header. Those four
//    are the entire visible surface of the protocol, and the reason the request
//    goes through the api rather than from here is that a browser will not show
//    you either side: a cross-origin fetch can read a response header only if
//    the server exposed it, and the browser owns its own request headers.
//  * **The SPN this page GUESSED.** Nothing in the exchange carries it. The
//    client derives `HTTP/<host>` from the URL, and when that guess is wrong —
//    a CNAME, a load balancer, an SPN registered on another account — the
//    failure is `KDC_ERR_S_PRINCIPAL_UNKNOWN` from a KDC, three steps earlier,
//    naming nothing about HTTP. So it is a field rather than an assumption.
//  * **The mechanism list, and what its ORDER decides.** RFC 4178 section 5
//    makes the mechListMIC optional only when the acceptor selects the first
//    entry; anything else and the MIC is mandatory, because otherwise an
//    attacker who struck the preferred mechanism out of the list is
//    indistinguishable from an acceptor that does not support it.
//  * **The mechListMIC, computed over the bytes that actually count.** The DER
//    of `MechTypeList` and NOT of `[0] MechTypeList` — two bytes, and the
//    commonest mistake in this protocol. `krb5_spnego.js` hands the bytes back
//    from the encoder so this page cannot rebuild them wrongly.
//  * **The ticket inside, decrypted when you have the key.** The AP-REQ's
//    Authenticator opens with the ticket's session key, which this page holds.
//    The TICKET does not: it is sealed with the service's long-term key, so it
//    is opaque here until somebody supplies that — and that is the honest state
//    of a client, said out loud rather than left as an empty pane.
//
// The relay is `POST /krb5/spnego`. Unlike `POST /krb5/service` it needs no
// switch in the api configuration: it is an HTTP GET like every other outbound
// call there, and the only header the caller can influence is `Authorization`,
// whose value the api builds itself.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "spnego",
  level: appconfig.logLevel
});
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var gss = require("./krb5_gss.js");
var negotiate = require("./krb5_spnego.js");
var client = require("./krb5_client.js");
// NOT a require of krb5_describe.js: this page reaches the describer only
// through panes.renderMessage(), and the string-to-key it used to call directly
// is now kerberos_keys.js's job. A require left behind here would put the whole
// describer in this bundle twice over in the reader's mind and nowhere in the
// code — the key fields in the ticket pane are the only key-derivation path
// on this page.
var panes = require("./kerberos_panes.js");
var ophistory = require("./kerberos_history.js");
var tickets = require("./kerberos_tickets.js");
var hexview = require("./kerberos_hex.js");
// The key fields in the ticket pane. They are what open the PAC inside the
// ticket, which is the one thing on this page a client cannot read for itself
// — everything else the ticket says is shown from the KDC's own report of it,
// which the workflow kept when the TGS page obtained the ticket. This is the
// ONLY page in the workflow that collects a key: the ticket here is a service
// ticket, whose keytab a reader plausibly has, and the fields sit beside the
// ticket rather than in a pane of their own at the foot of the page.
var deckeys = require("./kerberos_keys.js");

var el = panes.el;
var val = panes.val;
var status = panes.status;
var make = panes.make;

// The ticket this page will spend, revived from the cache, and the AP-REQ built
// from it. Held in memory only: both carry a session key, and a subkey that
// exists for one context.
var chosenTicket = null;
var lastBuilt = null;
var lastTicketBytes = null;

// ---------------------------------------------------------------------------
// The SPN, derived from the URL — and shown, because it is a guess.
// ---------------------------------------------------------------------------
function hostOf(url) {
  log.debug("Entering hostOf().");
  try {
    var parsed = new URL(url);
    log.debug("Leaving hostOf(). " + parsed.hostname);
    return parsed.hostname;
  } catch (e) {
    // An unparseable URL is a field the user is still typing. Not an error
    // here — the button reports it when it is pressed.
    log.debug("Leaving hostOf(). Unparseable.");
    return null;
  }
}

function derivedSpn(url) {
  log.debug("Entering derivedSpn().");
  var host = hostOf(url);
  log.debug("Leaving derivedSpn().");
  return host ? "HTTP/" + host : "";
}

function onUrlChanged() {
  log.debug("Entering onUrlChanged().");
  var url = val("krb_spnego_url").trim();
  var derived = derivedSpn(url);
  var field = el("krb_spnego_spn");
  // Only fill it when the user has not overridden it. An SPN typed by hand is
  // the answer to a problem this page cannot see.
  if (field && (!field.value || field.getAttribute("data-krb-derived") ===
      field.value)) {
    field.value = derived;
    field.setAttribute("data-krb-derived", derived);
  }
  renderSpnNote(derived);
  renderCredentials();
  log.debug("Leaving onUrlChanged().");
}

// `reconciled` is reconcileSpn()'s verdict, and it is OPTIONAL on purpose: this
// note is painted on every keystroke in the URL field, long before anything has
// been asked of the far end, and at that point the derivation is genuinely all
// there is. Once the probe has run its verdict is appended rather than replacing
// the derivation — the reader needs to know both what this client guessed and what
// the service said, because on every service but this mock there is no second half.
function renderSpnNote(derived, reconciled) {
  log.debug("Entering renderSpnNote().");
  var host = el("krb_spn_note");
  if (!host) {
    log.debug("Leaving renderSpnNote(). No host.");
    return;
  }
  panes.clear(host);
  var spn = val("krb_spnego_spn").trim();
  var text = "Derived from the URL's host as " + (derived || "(nothing — the " +
      "URL does not parse)") + ".";
  if (spn && derived && spn !== derived) {
    text += " You have overridden it, which is a legitimate thing to do and " +
      "is exactly what a load-balanced or CNAMEd service needs — the ticket " +
      "must name the SPN the service holds a key for, not the name you " +
      "typed in the address bar.";
  } else {
    text += " Nothing in the SPNEGO exchange carries the SPN, so this guess " +
      "is the client's alone; when it is wrong the failure is a KDC saying " +
      "KDC_ERR_S_PRINCIPAL_UNKNOWN, which names nothing about HTTP.";
  }
  host.appendChild(make("p", "krb-note", text));
  if (reconciled && reconciled.note) {
    // krb-good when the guess was confirmed or corrected before it could fail,
    // krb-warn when the two disagree and the user's own value stands.
    host.appendChild(make("p", "krb-note " +
      (reconciled.filledIn || !reconciled.volunteered.principal ||
        spn === reconciled.volunteered.principal ? "krb-good" : "krb-warn"),
      reconciled.note));
  }
  log.debug("Leaving renderSpnNote().");
}

// ---------------------------------------------------------------------------
// What is held, and where to go for what is not.
//
// This is the pane that makes the workflow a workflow: it names the two pages
// that produce a ticket, carries the `?return=spnego` that brings the user
// back, and — when a matching ticket IS held — says so and enables the button.
// ---------------------------------------------------------------------------
function serviceTicketFor(spn) {
  log.debug("Entering serviceTicketFor(). spn=" + spn);
  var wanted = String(spn || "").split("@")[0].toLowerCase();
  var found = null;
  panes.readServiceTickets().forEach(function (entry) {
    var name = String(entry.service || "").split("@")[0].toLowerCase();
    if (!found && name === wanted) {
      found = entry;
    }
  });
  log.debug("Leaving serviceTicketFor(). " + (found ? "held" : "not held"));
  return found;
}

function stepLink(href, text) {
  log.debug("Entering stepLink().");
  var a = make("a", "krb-step-link", text);
  a.href = href;
  log.debug("Leaving stepLink().");
  return a;
}

function renderCredentials() {
  log.debug("Entering renderCredentials().");
  var host = el("krb_credentials_pane");
  if (!host) {
    log.debug("Leaving renderCredentials(). No host.");
    return;
  }
  panes.clear(host);
  var spn = val("krb_spnego_spn").trim();
  var entry = spn ? serviceTicketFor(spn) : null;
  var tgt = panes.readTgt();
  var pane = make("div", "krb-section");

  panes.renderTable(pane, [
    {
      name: "service ticket for " + (spn || "(no SPN yet)"),
      value: entry ? "HELD, until " + entry.endtime : "not held",
      note: entry
        ? "This is what SPNEGO spends. It names one service and proves " +
          "nothing to another."
        : "The TGS exchange buys one. Nothing here can obtain it — that is " +
          "step 2 of this workflow."
    },
    {
      name: "ticket-granting ticket",
      value: tgt ? "HELD, until " + tgt.endtime : "not held",
      note: tgt
        ? "which is what the TGS exchange spends"
        : "The AS exchange turns a password into one. That is step 1."
    }
  ]);

  var actions = make("p", "krb-actions");
  if (!tgt) {
    actions.appendChild(stepLink("/kerberos.html?return=spnego",
        "Get a TGT — the AS exchange →"));
  }
  actions.appendChild(stepLink(
    "/kerberos_tgs.html?return=spnego&spn=" + encodeURIComponent(spn),
    (entry ? "Buy another service ticket" : "Buy the service ticket") +
        " — the TGS exchange →"));
  pane.appendChild(actions);
  host.appendChild(pane);

  chosenTicket = null;
  if (!entry) {
    panes.disable("krb_authenticate_button", true);
    log.debug("Leaving renderCredentials(). No ticket.");
    return;
  }
  try {
    chosenTicket = revive(entry);
  } catch (e) {
    panes.disable("krb_authenticate_button", true);
    status("krb_spnego_status", "That stored ticket cannot be read back: " +
        e.message, "krb-bad");
    log.debug("Leaving renderCredentials(). Unreadable ticket.");
    return;
  }
  if (chosenTicket.endtime <= new Date()) {
    panes.disable("krb_authenticate_button", true);
    status("krb_spnego_status",
      "The held ticket for " + spn + " expired at " +
      chosenTicket.endtime.toISOString() + ". The service would refuse it " +
      "with KRB_AP_ERR_TKT_EXPIRED — buy a fresh one on the TGS page.",
      "krb-bad");
    log.debug("Leaving renderCredentials(). Expired.");
    return;
  }
  panes.disable("krb_authenticate_button", false);
  log.debug("Leaving renderCredentials(). Ready.");
}

// The stored form is JSON; the protocol wants bytes and structures. Same shape
// as kerberos_ap.js's, because it is the same cache.
function revive(entry) {
  log.debug("Entering revive().");
  log.debug("Leaving revive().");
  return {
    ticket: msgs.readTicket(panes.b64ToBytes(entry.ticket)),
    ticketBytes: panes.b64ToBytes(entry.ticket),
    sessionKey: prim.fromHex(entry.sessionKey),
    etype: entry.sessionKeyEtype,
    client: msgs.parsePrincipal(entry.client.split("@")[0],
        msgs.NAME_TYPE.PRINCIPAL),
    realm: entry.realm,
    service: entry.service,
    endtime: new Date(entry.endtime)
  };
}

// ---------------------------------------------------------------------------
// The HTTP panes. Headers, verbatim, both directions.
// ---------------------------------------------------------------------------
function headerRows(headers) {
  log.debug("Entering headerRows().");
  var rows = [];
  Object.keys(headers || {}).sort().forEach(function (name) {
    var value = headers[name];
    rows.push({
      name: name,
      value: Array.isArray(value) ? value.join(", ") : String(value),
      note: /^www-authenticate$/i.test(name)
        ? "The challenge. `Negotiate` alone is the bare first challenge of " +
          "RFC 4559 section 4; `Negotiate <base64>` carries a token."
        : (/^authorization$/i.test(name)
          ? "The whole of what this client sends. Everything below is inside " +
            "this one header value."
          : null)
    });
  });
  log.debug("Leaving headerRows(). " + rows.length + " header(s).");
  return rows;
}

function renderExchange(hostId, title, result, note) {
  log.debug("Entering renderExchange(). " + hostId);
  var host = el(hostId);
  if (!host) {
    log.debug("Leaving renderExchange(). No host.");
    return;
  }
  panes.clear(host);
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title", title));
  if (note) {
    pane.appendChild(make("p", "krb-section-note", note));
  }
  var request = make("div", "krb-http");
  request.appendChild(make("div", "krb-http-line",
      result.request.method + " " + result.request.url));
  panes.renderTable(request, headerRows(result.request.headers));
  pane.appendChild(make("h4", "krb-section-title", "Request"));
  pane.appendChild(request);
  var response = make("div", "krb-http");
  response.appendChild(make("div", "krb-http-line",
      "HTTP " + result.response.status + " " +
      (result.response.statusText || "")));
  panes.renderTable(response, headerRows(result.response.headers));
  pane.appendChild(make("h4", "krb-section-title", "Response"));
  pane.appendChild(response);
  host.appendChild(pane);
  log.debug("Leaving renderExchange().");
}

// The token out of a `WWW-Authenticate: Negotiate <base64>` header, or null.
// Parsed here rather than in the api because it is protocol rather than
// transport — the api relays HTTP and knows nothing about what is in a header.
// ---------------------------------------------------------------------------
// WHAT THE FAR END VOLUNTEERED ABOUT ITS OWN SPN, if anything.
//
// Nothing in SPNEGO carries the SPN. That is the protocol, it is why this page
// derives `HTTP/<url host>` like every browser does, and it is why a wrong guess
// fails at the KDC with `KDC_ERR_S_PRINCIPAL_UNKNOWN` — an error that names
// nothing about HTTP and sends people to look at DNS.
//
// So this is strictly opportunistic. The mock KDC's protected resource volunteers
// two headers on its 401 (`X-Krb5-Service-Principal` and
// `X-Krb5-Accepts-Spn-Hosts`), which are nobody's standard and which a real
// service will not send. When they are there the page uses them and SAYS it is
// using them; when they are absent nothing changes and the guess stands, labelled
// as a guess. What it must never do is present a header it was handed as though it
// were something the protocol told it — the reader would learn the wrong lesson
// about every service that is not this one.
// ---------------------------------------------------------------------------
function headerValue(result, name) {
  var headers = (result && result.response && result.response.headers) || {};
  var found = null;
  Object.keys(headers).forEach(function (key) {
    if (key.toLowerCase() === name) {
      found = Array.isArray(headers[key]) ? headers[key].join(", ") :
          String(headers[key]);
    }
  });
  return found;
}

function volunteeredSpn(result) {
  log.debug("Entering volunteeredSpn().");
  var principal = headerValue(result, "x-krb5-service-principal");
  var hosts = headerValue(result, "x-krb5-accepts-spn-hosts");
  if (!principal && !hosts) {
    log.debug("Leaving volunteeredSpn(). Nothing volunteered.");
    return null;
  }
  log.debug("Leaving volunteeredSpn(). principal=" + principal);
  return {
    // Without the realm: the SPN field names a principal, and the realm it lives
    // in is the TGS page's own field. Pasting `HTTP/x@EXAMPLE.COM` into it would
    // be asking for a service whose last component is a realm.
    principal: principal ? String(principal).split("@")[0] : null,
    realm: principal && principal.indexOf("@") !== -1
        ? String(principal).split("@").slice(1).join("@") : null,
    hosts: (hosts || "").split(",").map(function (h) {
      return h.trim().toLowerCase();
    }).filter(function (h) { return h.length > 0; })
  };
}

// Does the SPN this page derived name a host the far end says it answers for?
// Same rule the mock applies: the host IS one of the entries, or ends with a dot
// and one of them.
function hostIsCovered(host, hosts) {
  log.debug("Entering hostIsCovered().");
  var wanted = String(host || "").toLowerCase();
  var covered = (hosts || []).some(function (entry) {
    return wanted === entry || wanted.endsWith("." + entry);
  });
  log.debug("Leaving hostIsCovered(). " + covered);
  return covered;
}

// ---------------------------------------------------------------------------
// Reconcile the guess with what was volunteered, and say which happened.
//
// Three outcomes, and each is a different thing for the reader to know:
//
//   * the derived SPN is one the service answers for — nothing to change, and the
//     guess is CONFIRMED rather than merely unrefuted;
//   * the service names a different SPN and the field still holds the derived
//     guess — fill it in, because a ticket for the guess cannot be issued and the
//     next page would fail with an error naming nothing about HTTP;
//   * the service names a different SPN and the user has typed their own — leave
//     it ALONE and say both. Overwriting somebody's deliberate override is how a
//     debugger becomes untrustworthy, and an override is the legitimate case on
//     every load-balanced service there is.
// ---------------------------------------------------------------------------
function reconcileSpn(result) {
  log.debug("Entering reconcileSpn().");
  var volunteered = volunteeredSpn(result);
  if (!volunteered) {
    log.debug("Leaving reconcileSpn(). Nothing to reconcile.");
    return null;
  }
  var derived = derivedSpn(val("krb_spnego_url").trim());
  var current = val("krb_spnego_spn").trim();
  var host = hostOf(val("krb_spnego_url").trim());
  var outcome = { volunteered: volunteered, filledIn: false, note: null };
  if (volunteered.hosts.length && hostIsCovered(host, volunteered.hosts)) {
    outcome.note = "This service volunteered that it answers for any SPN whose " +
      "host is one of " + volunteered.hosts.join(", ") + ", and " + host +
      " is one — so the SPN derived from the URL is one it holds a key for. " +
      "Those headers are this mock's own courtesy (X-Krb5-Accepts-Spn-Hosts); " +
      "no real service sends them, and against one the derived name stays a " +
      "guess.";
    log.debug("Leaving reconcileSpn(). Derived name covered.");
    return outcome;
  }
  if (!volunteered.principal) {
    log.debug("Leaving reconcileSpn(). Hosts only, and not covered.");
    return outcome;
  }
  if (current && current !== derived) {
    outcome.note = "This service says it is " + volunteered.principal +
      ", and you have asked for " + current + ". Yours is left alone — an " +
      "override is the legitimate case on a load-balanced or CNAMEd service " +
      "— but only one of the two can have a key at the KDC.";
    log.debug("Leaving reconcileSpn(). Override respected.");
    return outcome;
  }
  panes.setVal("krb_spnego_spn", volunteered.principal);
  outcome.filledIn = true;
  outcome.note = "The SPN derived from this URL is " + (derived || "(none)") +
    ", and this service volunteered that it holds a key for " +
    volunteered.principal + " instead — so that is what the field now says. A " +
    "ticket for the derived name would have been refused by the KDC with " +
    "KDC_ERR_S_PRINCIPAL_UNKNOWN, which names nothing about HTTP. The header " +
    "carrying this (X-Krb5-Service-Principal) is this mock's own courtesy: " +
    "SPNEGO itself carries no SPN, so against a real service this is the one " +
    "thing you have to find out for yourself.";
  log.debug("Leaving reconcileSpn(). Filled in " + volunteered.principal);
  return outcome;
}

function challengeToken(result) {
  log.debug("Entering challengeToken().");
  var headers = (result && result.response && result.response.headers) || {};
  var raw = null;
  Object.keys(headers).forEach(function (name) {
    if (/^www-authenticate$/i.test(name)) {
      raw = Array.isArray(headers[name]) ? headers[name].join(", ") :
          String(headers[name]);
    }
  });
  if (!raw) {
    log.debug("Leaving challengeToken(). No challenge.");
    return { raw: null, bytes: null };
  }
  var match = /Negotiate\s+([A-Za-z0-9+/=]+)/i.exec(raw);
  if (!match) {
    log.debug("Leaving challengeToken(). Bare challenge.");
    return { raw: raw, bytes: null };
  }
  var bytes = null;
  try {
    bytes = panes.b64ToBytes(match[1]);
  } catch (e) {
    // A challenge that is not base64 is worth reporting as content rather than
    // throwing: it means something between here and the server rewrote the
    // header, which is a real and hard-to-see failure behind proxies.
    log.warn("the challenge is not base64: " + e.message);
  }
  log.debug("Leaving challengeToken(). " + (bytes ? bytes.length + " bytes" :
      "unreadable"));
  return { raw: raw, bytes: bytes };
}

// ---------------------------------------------------------------------------
// Round trip 1: ask without a ticket and read the challenge.
// ---------------------------------------------------------------------------
async function onProbe() {
  log.debug("Entering onProbe().");
  var url = val("krb_spnego_url").trim();
  ophistory.begin({
    operation: ophistory.OPS.SPNEGO_PROBE,
    principal: "(none — this request carries no credential)",
    target: url,
    statusId: "krb_spnego_status"
  });
  if (!url) {
    status("krb_spnego_status", "Give the URL of a protected resource.",
        "krb-bad");
    log.debug("Leaving onProbe(). No url.");
    return false;
  }
  status("krb_spnego_status", "Asking for " + url + " with no credential…",
      "krb-pending");
  var result;
  try {
    result = await panes.sendSpnego({ url: url });
  } catch (e) {
    status("krb_spnego_status", e.message, "krb-bad");
    log.debug("Leaving onProbe(). Send failed.");
    return false;
  }
  renderExchange("krb_probe_pane", "The unauthenticated request", result,
    "No Authorization header at all. What comes back is the challenge, and " +
    "on a correctly configured resource it is the bare word `Negotiate`.");

  var challenge = challengeToken(result);
  var negotiates = /(^|,)\s*Negotiate\b/i.test(challenge.raw || "");
  if (result.response.status !== 401) {
    status("krb_spnego_status",
      "The resource answered " + result.response.status + " to an " +
      "unauthenticated request, so it is not asking for authentication at " +
      "all. Whatever is at that URL, nothing about it needs a ticket.",
      "krb-bad");
    log.debug("Leaving onProbe(). Not a 401.");
    return false;
  }
  if (!negotiates) {
    status("krb_spnego_status",
      "A 401, but its WWW-Authenticate does not offer Negotiate: " +
      (challenge.raw || "(the header is absent entirely)") + ". This " +
      "resource wants some other scheme, and a Kerberos ticket is not what " +
      "it is asking for.", "krb-bad");
    log.debug("Leaving onProbe(). No Negotiate.");
    return false;
  }
  if (challenge.bytes) {
    // Legal in a continuation and wrong here: RFC 4559 section 4's first
    // challenge carries no token, and a client that treats this one as the
    // acceptor's first negotiation token has nothing to answer with.
    status("krb_spnego_status",
      "A 401 offering Negotiate — but the challenge carries a TOKEN (" +
      challenge.bytes.length + " bytes), and the first one should not. RFC " +
      "4559 section 4: the server says only that it will negotiate. Proceed " +
      "anyway; the token is decoded in the pane below.", "krb-warn");
    await renderNegotiationToken("krb_probe_pane", challenge.bytes,
        "The token in the first challenge");
    log.debug("Leaving onProbe(). Unexpected token.");
    return false;
  }
  // Before the reader is sent off for a ticket: did the far end volunteer which
  // SPN it holds a key for? Only this mock does, and only because the protocol's
  // silence here is the commonest cause of a SPNEGO failure there is.
  var reconciled = reconcileSpn(result);
  renderSpnNote(derivedSpn(val("krb_spnego_url").trim()), reconciled);
  renderCredentials();
  status("krb_spnego_status",
    "401 with a bare `Negotiate` challenge, which is exactly right. Nothing " +
    "in it says which realm, which KDC or which service principal name — so " +
    "everything from here is the client's own guess. Step 2 builds the " +
    "token." + (reconciled && reconciled.filledIn
      ? " This service did volunteer its SPN in a non-standard header, and the " +
        "field above has been set to " + val("krb_spnego_spn") + " — see the " +
        "note beside it."
      : ""), "krb-ok");
  log.debug("Leaving onProbe(). Challenged.");
  return false;
}

// A decoded negotiation token, rendered through the same describer the decoder
// page uses. One implementation of "explain these bytes", so a field cannot be
// described differently on two pages.
async function renderNegotiationToken(hostId, bytes, label) {
  log.debug("Entering renderNegotiationToken(). " + label);
  var doc = await panes.renderMessage(hostId, label, bytes,
    chosenTicket ? [{
      etype: chosenTicket.etype,
      key: chosenTicket.sessionKey,
      label: "the ticket's session key"
    }] : []);
  log.debug("Leaving renderNegotiationToken().");
  return doc;
}

// ---------------------------------------------------------------------------
// Which mechanisms to offer, in the order the checkboxes are read.
//
// The order is the initiator's preference and it decides whether the
// mechListMIC exchange is optional — so it is taken from a fixed reading order
// rather than from the DOM's, and the page says what it means below.
// ---------------------------------------------------------------------------
function selectedMechs() {
  log.debug("Entering selectedMechs().");
  var mechs = [];
  if (panes.checked("krb_mech_krb5")) {
    mechs.push(negotiate.KRB5_MECH_OID);
  }
  if (panes.checked("krb_mech_ms")) {
    mechs.push(negotiate.MS_KRB5_MECH_OID);
  }
  if (panes.checked("krb_mech_ntlm")) {
    mechs.push("1.3.6.1.4.1.311.2.2.10");
  }
  log.debug("Leaving selectedMechs(). " + mechs.length + " mechanism(s).");
  return mechs;
}

// ---------------------------------------------------------------------------
// Round trip 2: the token, the request that carries it, and the answer.
// ---------------------------------------------------------------------------
async function onAuthenticate() {
  log.debug("Entering onAuthenticate().");
  var url = val("krb_spnego_url").trim();
  ophistory.begin({
    operation: ophistory.OPS.SPNEGO_AUTH,
    principal: (chosenTicket && chosenTicket.client &&
        msgs.principalToString(chosenTicket.client, chosenTicket.realm)) ||
        "(no ticket)",
    target: url,
    statusId: "krb_spnego_status"
  });
  if (!chosenTicket) {
    status("krb_spnego_status",
      "No service ticket is held for that SPN. The TGS exchange page buys " +
      "one, and will offer you a link back here.", "krb-bad");
    log.debug("Leaving onAuthenticate(). No ticket.");
    return false;
  }
  var mechs = selectedMechs();
  if (!mechs.length) {
    status("krb_spnego_status",
      "Offer at least one mechanism: a NegTokenInit with an empty mechTypes " +
      "list is malformed (RFC 4178 section 4.1).", "krb-bad");
    log.debug("Leaving onAuthenticate(). No mechanisms.");
    return false;
  }

  status("krb_spnego_status", "Building the AP-REQ and wrapping it in a " +
      "NegTokenInit…", "krb-pending");
  var built;
  try {
    built = await client.buildApReq({
      ticket: chosenTicket,
      mutual: panes.checked("krb_flag_mutual"),
      gssFlags: [gss.GSS_FLAG.INTEG, gss.GSS_FLAG.CONF].concat(
        panes.checked("krb_flag_mutual") ? [gss.GSS_FLAG.MUTUAL] : [])
    });
  } catch (e) {
    status("krb_spnego_status", "The AP-REQ could not be built: " + e.message,
        "krb-bad");
    log.debug("Leaving onAuthenticate(). Build failed.");
    return false;
  }
  lastBuilt = built;
  lastTicketBytes = chosenTicket.ticketBytes;

  var mic = null;
  var mechListDer = negotiate.mechTypeListDer(mechs);
  if (panes.checked("krb_send_mic")) {
    try {
      // Signed with the subkey from this client's own Authenticator, because
      // at this moment that is the only context key in existence — the
      // acceptor has not answered yet, so its subkey does not exist. Sequence
      // number 0: this is the first per-message token of the context.
      mic = await negotiate.computeMechListMic({
        key: built.subkey.key,
        etype: built.subkey.etype,
        role: "initiator",
        mechListDer: mechListDer,
        sequenceNumber: 0
      });
    } catch (e) {
      status("krb_spnego_status", "The mechListMIC could not be computed: " +
          e.message, "krb-bad");
      log.debug("Leaving onAuthenticate(). MIC failed.");
      return false;
    }
  }

  var init = negotiate.encodeNegTokenInit({
    mechTypes: mechs,
    mechToken: built.token,
    mechListMic: mic
  });
  await renderWhatWentOut(init, built, mechs, mic);

  status("krb_spnego_status", "Sending it as `Authorization: Negotiate`…",
      "krb-pending");
  var result;
  try {
    result = await panes.sendSpnego({ url: url, token: init.token });
  } catch (e) {
    status("krb_spnego_status", e.message, "krb-bad");
    log.debug("Leaving onAuthenticate(). Send failed.");
    return false;
  }
  rememberFields();
  await readAnswer(result, built, init, mechs);
  log.debug("Leaving onAuthenticate().");
  return false;
}

async function renderWhatWentOut(init, built, mechs, mic) {
  log.debug("Entering renderWhatWentOut().");
  var host = el("krb_negtokeninit_pane");
  panes.clear(host);
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title",
      "The NegTokenInit this browser built"));
  pane.appendChild(make("p", "krb-section-note",
    "The initiator's first token, and the only one wrapped in an RFC 2743 " +
    "InitialContextToken: 0x60, SPNEGO's own OID 1.3.6.1.5.5.2, then [0] " +
    "NegTokenInit. Every token after this one, in both directions, is a bare " +
    "NegTokenResp beginning 0xa1."));
  var rows = mechs.map(function (oid, i) {
    return {
      name: "mechTypes[" + i + "]",
      value: oid + "  (" + negotiate.mechName(oid) + ")",
      note: i === 0
        ? "The first preference. RFC 4178 section 5 makes the mechListMIC " +
          "exchange optional ONLY if the acceptor selects this one."
        : null
    };
  });
  rows.push({
    name: "mechToken",
    value: built.token.length + " bytes",
    note: "The OPTIMISTIC token: this client's AP-REQ, sent before knowing " +
      "whether the acceptor will choose Kerberos at all. It is what lets the " +
      "whole handshake cost one round trip instead of two."
  });
  rows.push({
    name: "mechListMIC",
    value: mic ? prim.toHex(mic) : "(not sent)",
    note: mic
      ? "Computed over the DER of MechTypeList — the SEQUENCE, NOT the [0] " +
        "wrapper it sits behind here (RFC 4178 section 5). Two bytes, and " +
        "the difference between a MIC that verifies and one that verifies " +
        "against nothing. Keyed with this client's Authenticator subkey, " +
        "which is the only context key that exists yet."
      : "Without it the mechanism list is unprotected: an attacker who " +
        "struck a mechanism out of it on the wire would be indistinguishable " +
        "from an acceptor that does not support it."
  });
  rows.push({
    name: "MechTypeList bytes",
    value: prim.toHex(init.mechListDer),
    note: "Exactly what the MIC above covers."
  });
  rows.push({
    name: "total size",
    value: init.token.length + " bytes",
    note: "base64 of this is the whole Authorization header value."
  });
  panes.renderTable(pane, rows);
  host.appendChild(pane);

  await panes.renderMessage("krb_apreq_pane", "The AP-REQ inside mechToken",
    built.apReq, [{
      etype: chosenTicket.etype,
      key: chosenTicket.sessionKey,
      label: "the ticket's session key"
    }]);
  await renderChecksum(built);
  hexview.render("krb_sent_hex", init.token, "The SPNEGO token");
  await renderTicket();
  log.debug("Leaving renderWhatWentOut().");
}

// The 0x8003 structure, read back out of the Authenticator this page just
// built — read rather than remembered, so the pane shows what is on the wire.
async function renderChecksum(built) {
  log.debug("Entering renderChecksum().");
  var host = el("krb_checksum_pane");
  if (!host) {
    log.debug("Leaving renderChecksum(). No host.");
    return;
  }
  panes.clear(host);
  try {
    var profile = kcrypto.etypeById(chosenTicket.etype);
    var apReq = msgs.readApReq(built.apReq);
    var authenticator = msgs.readAuthenticator(await profile.decrypt(
      chosenTicket.sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH,
      apReq.authenticator.cipher));
    if (!authenticator.cksum ||
        authenticator.cksum.type !== gss.CHECKSUM_TYPE_GSS) {
      log.debug("Leaving renderChecksum(). Not a 0x8003 checksum.");
      return;
    }
    var parsed = gss.parseGssChecksum(authenticator.cksum.checksum);
    var pane = make("div", "krb-section");
    pane.appendChild(make("h4", "krb-section-title",
        "The Authenticator's 0x8003 checksum — the GSS flags"));
    pane.appendChild(make("p", "krb-section-note",
      "Note where the flags live. SPNEGO has a reqFlags field of its own and " +
      "RFC 4178 section 4.2.1 deprecates it — receivers MUST ignore it — so " +
      "the flags a service actually reads are these, inside the Kerberos " +
      "AP-REQ, little-endian in a protocol where everything else is " +
      "big-endian."));
    panes.renderTable(pane, [
      {
        name: "Flags",
        value: (parsed.flagNames.join(" | ") || "(none)") + "  = 0x" +
            parsed.flags.toString(16),
        note: parsed.flagNames.indexOf("MUTUAL") !== -1
          ? "MUTUAL is set, so the server must prove itself back with an " +
            "AP-REP in the 200's WWW-Authenticate header"
          : "MUTUAL is NOT set, so the server need not answer with anything " +
            "— and nothing will have proved it is who it claims to be"
      },
      {
        name: "Bnd",
        value: prim.toHex(parsed.channelBindings),
        note: parsed.hasChannelBindings
          ? "channel bindings are present, which is how a service ties this " +
            "context to the TLS connection underneath it"
          : "sixteen ZERO bytes, meaning no channel bindings — absent is not " +
            "the same as omitted"
      }
    ]);
    host.appendChild(pane);
  } catch (e) {
    // Not fatal: the request has been built and can still be sent. Reported,
    // because a checksum that cannot be read back is a real finding about a
    // token this page just produced.
    log.warn("could not read back the Authenticator for display: " + e.message);
    host.appendChild(make("p", "krb-note krb-bad",
      "The Authenticator this page just built could not be read back: " +
      e.message));
  }
  log.debug("Leaving renderChecksum().");
}

// ---------------------------------------------------------------------------
// The answer, and the three shapes it can take.
// ---------------------------------------------------------------------------
async function readAnswer(result, built, init, mechs) {
  log.debug("Entering readAnswer(). status=" + result.response.status);
  renderExchange("krb_response_headers_pane",
      "The request that carried the token", result,
    "The Authorization header is the whole of what this client sent. " +
    "Everything the panes below show is inside that one value.");
  renderBody(result);

  var challenge = challengeToken(result);
  if (!challenge.bytes) {
    status("krb_spnego_status",
      result.response.status === 200
        ? "HTTP 200, and no token came back — so the resource let this " +
          "client in and NOTHING has proved which server answered. That is " +
          "legitimate without MUTUAL, and it is the difference between " +
          "authenticating a client and authenticating a connection."
        : "HTTP " + result.response.status + " with no token in " +
          "WWW-Authenticate (" + (challenge.raw || "the header is absent") +
          "), so there is nothing here that says why.",
      result.response.status === 200 ? "krb-warn" : "krb-bad");
    log.debug("Leaving readAnswer(). No token.");
    return;
  }

  hexview.render("krb_received_hex", challenge.bytes,
      "The server's SPNEGO token");
  var parsed;
  try {
    parsed = negotiate.decodeNegotiationToken(challenge.bytes);
  } catch (e) {
    status("krb_spnego_status",
      "The server's token does not decode: " + e.message, "krb-bad");
    log.debug("Leaving readAnswer(). Undecodable.");
    return;
  }
  renderNegTokenResp(parsed, mechs);
  await renderNegotiationToken("krb_negtokenresp_pane", challenge.bytes,
      "The server's token");

  if (parsed.negState === negotiate.NEG_STATE.REQUEST_MIC) {
    await sendMicContinuation(built, init, parsed);
    log.debug("Leaving readAnswer(). request-mic.");
    return;
  }
  if (parsed.negState === negotiate.NEG_STATE.REJECT) {
    reportRejection(parsed);
    log.debug("Leaving readAnswer(). Rejected.");
    return;
  }
  if (parsed.negState === negotiate.NEG_STATE.ACCEPT_INCOMPLETE) {
    status("krb_spnego_status",
      "accept-incomplete: the server has selected " +
      (parsed.supportedMechName || "a mechanism") + " and wants another " +
      "token. That happens when the optimistic mechToken was absent or was " +
      "for a mechanism it did not choose.", "krb-warn");
    log.debug("Leaving readAnswer(). Incomplete.");
    return;
  }
  await confirmContext(parsed, built, init, result);
  log.debug("Leaving readAnswer(). Complete.");
}

function renderNegTokenResp(parsed, mechs) {
  log.debug("Entering renderNegTokenResp().");
  var host = el("krb_negtokenresp_pane");
  panes.clear(host);
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title",
      "The NegTokenResp the server sent"));
  var requirement = negotiate.micRequirement(mechs, parsed.supportedMech);
  panes.renderTable(pane, [
    {
      name: "negState",
      value: parsed.negState === null ? "(absent)" :
          parsed.negState + "  (" + parsed.negStateName + ")",
      note: parsed.negStateMeaning
    },
    {
      name: "supportedMech",
      value: parsed.supportedMech
        ? parsed.supportedMech + "  (" + parsed.supportedMechName + ")"
        : "(absent)",
      note: parsed.supportedMech
        ? requirement.reason
        : "Legal only in the acceptor's FIRST reply, so its absence on a " +
          "continuation is correct."
    },
    {
      name: "responseToken",
      value: parsed.responseToken
        ? parsed.responseToken.length + " bytes"
        : "(absent)",
      note: parsed.responseToken
        ? "The selected mechanism's own token — an AP-REP here, or a " +
          "KRB-ERROR when the ticket was refused."
        : "SPNEGO carries no error detail of its own, so a rejection with " +
          "nothing here cannot be told from a wrong password."
    },
    {
      name: "mechListMIC",
      value: parsed.mechListMic ? prim.toHex(parsed.mechListMic) :
          "(absent)",
      note: parsed.mechListMic
        ? "The acceptor's own MIC over the same MechTypeList, keyed with ITS " +
          "subkey — the context key once one has been offered (RFC 4121). " +
          "That is why the two MICs use different keys."
        : null
    }
  ]);
  host.appendChild(pane);
  log.debug("Leaving renderNegTokenResp().");
}

function renderBody(result) {
  log.debug("Entering renderBody().");
  var host = el("krb_body_pane");
  if (!host) {
    log.debug("Leaving renderBody(). No host.");
    return;
  }
  panes.clear(host);
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title",
      "The response body, as text"));
  pane.appendChild(make("p", "krb-section-note",
    "Shown as TEXT and never as markup. This is a document from a server " +
    "somebody else operates, and rendering it here would run their page in " +
    "this origin." + (result.response.bodyTruncated
      ? " Truncated by the api for display; the whole body was " +
        result.response.bodyLength + " characters."
      : "")));
  var pre = make("pre", "krb-body", result.response.body || "(empty)");
  pane.appendChild(pre);
  host.appendChild(pane);
  log.debug("Leaving renderBody().");
}

function reportRejection(parsed) {
  log.debug("Entering reportRejection().");
  var detail = "";
  if (parsed.responseToken) {
    try {
      var inner = gss.decodeInitialContextToken(parsed.responseToken);
      var error = msgs.readKrbError(inner.inner);
      detail = " The mechanism's own error token says " + error.error.name +
        " — " + error.error.meaning +
        (error.eText ? " (" + error.eText + ")" : "") + ".";
    } catch (e) {
      detail = " There is a responseToken but it is not a readable " +
        "KRB-ERROR: " + e.message + ".";
    }
  } else {
    detail = " There is no responseToken, so nothing anywhere says why. " +
      "SPNEGO's negState has no reason field: when a server can say more it " +
      "says it in the mechanism's own error token, and this one did not.";
  }
  status("krb_spnego_status", "REJECTED." + detail, "krb-bad");
  log.debug("Leaving reportRejection().");
}

// The acceptor asked for the MIC. Send it: a bare NegTokenResp carrying the
// mechListMIC and nothing else. This is the second round trip that RFC 4178
// section 5's rule costs, and it is worth seeing rather than hiding.
async function sendMicContinuation(built, init, parsed) {
  log.debug("Entering sendMicContinuation().");
  var url = val("krb_spnego_url").trim();
  ophistory.begin({
    operation: ophistory.OPS.SPNEGO_MIC,
    principal: msgs.principalToString(chosenTicket.client, chosenTicket.realm),
    target: url,
    statusId: "krb_spnego_status"
  });
  status("krb_spnego_status",
    "request-mic: the server accepted the ticket and will not finish until " +
    "the mechanism list is integrity protected. Sending the mechListMIC…",
    "krb-pending");
  var mic;
  try {
    mic = await negotiate.computeMechListMic({
      key: built.subkey.key,
      etype: built.subkey.etype,
      role: "initiator",
      mechListDer: init.mechListDer,
      sequenceNumber: 0
    });
  } catch (e) {
    status("krb_spnego_status", "The mechListMIC could not be computed: " +
        e.message, "krb-bad");
    log.debug("Leaving sendMicContinuation(). MIC failed.");
    return;
  }
  var result;
  try {
    result = await panes.sendSpnego({
      url: url,
      token: negotiate.encodeNegTokenResp({ mechListMic: mic })
    });
  } catch (e) {
    status("krb_spnego_status", e.message, "krb-bad");
    log.debug("Leaving sendMicContinuation(). Send failed.");
    return;
  }
  renderExchange("krb_response_headers_pane",
      "Round trip 3 — the mechListMIC continuation", result,
    "A bare NegTokenResp carrying only the MIC. Note what is NOT in it: no " +
    "mechanism list, no token, and no InitialContextToken — only the " +
    "initiator's first token is ever wrapped.");
  renderBody(result);
  var challenge = challengeToken(result);
  if (!challenge.bytes) {
    status("krb_spnego_status",
      "HTTP " + result.response.status + ", and no token came back from the " +
      "continuation.", result.response.status === 200 ? "krb-warn" :
          "krb-bad");
    log.debug("Leaving sendMicContinuation(). No token.");
    return;
  }
  var done;
  try {
    done = negotiate.decodeNegotiationToken(challenge.bytes);
  } catch (e) {
    status("krb_spnego_status", "The continuation's answer does not decode: " +
        e.message, "krb-bad");
    log.debug("Leaving sendMicContinuation(). Undecodable.");
    return;
  }
  hexview.render("krb_received_hex", challenge.bytes,
      "The server's SPNEGO token");
  await renderNegotiationToken("krb_negtokenresp_pane", challenge.bytes,
      "The server's token");
  if (done.negState === negotiate.NEG_STATE.REJECT) {
    reportRejection(done);
    log.debug("Leaving sendMicContinuation(). Rejected.");
    return;
  }
  status("krb_spnego_status",
    "accept-completed after the mechListMIC exchange: two round trips " +
    "instead of one, which is what protecting the mechanism list costs when " +
    "the acceptor insists on it.", "krb-ok");
  log.debug("Leaving sendMicContinuation(). Complete.");
}

// accept-completed. Check the two things that are worth checking, rather than
// treating a 200 as the answer.
async function confirmContext(parsed, built, init, result) {
  log.debug("Entering confirmContext().");
  var host = el("krb_context_pane");
  panes.clear(host);
  var rows = [];
  var problems = [];

  if (!parsed.responseToken) {
    rows.push({
      name: "mutual authentication",
      value: "NOT PERFORMED",
      note: "No AP-REP came back, so nothing has proved which server " +
        "answered. Legitimate when MUTUAL was not asked for; when it WAS, it " +
        "means the server did not do what it was asked."
    });
    if (panes.checked("krb_flag_mutual")) {
      problems.push("MUTUAL was requested and no AP-REP came back");
    }
  } else {
    var outcome;
    try {
      outcome = await client.readApRep({
        reply: parsed.responseToken,
        ticket: chosenTicket,
        sentCtime: built.ctime,
        sentCusec: built.cusec
      });
    } catch (e) {
      outcome = { ok: false, reason: e.message };
    }
    await panes.renderMessage("krb_aprep_pane",
        "The AP-REP inside responseToken", parsed.responseToken, [{
          etype: chosenTicket.etype,
          key: chosenTicket.sessionKey,
          label: "the ticket's session key"
        }]);
    if (outcome.error) {
      rows.push({
        name: "mutual authentication",
        value: "the mechanism answered an error",
        note: outcome.error.error.name + " — " + outcome.error.error.meaning
      });
      problems.push(outcome.error.error.name);
    } else if (!outcome.mutualOk) {
      rows.push({
        name: "mutual authentication",
        value: "FAILED",
        note: outcome.reason
      });
      problems.push("the AP-REP's echo did not match");
    } else {
      rows.push({
        name: "mutual authentication",
        value: "CONFIRMED",
        note: "The AP-REP echoed this client's ctime and cusec under the " +
          "ticket's session key. Only something holding the service's " +
          "long-term key could have decrypted the ticket to learn that key, " +
          "so the echo IS the server's identity — and a client that asks for " +
          "mutual authentication and does not CHECK the echo has only asked."
      });
      rows.push({
        name: "acceptor subkey",
        value: outcome.acceptorSubkey
          ? kcrypto.etypeName(outcome.acceptorSubkey.etype) + ", " +
            prim.toHex(outcome.acceptorSubkey.key)
          : "(none offered)",
        note: "A CREDENTIAL, held in memory and not persisted. Once offered " +
          "it becomes the context key — which is why the server's own " +
          "mechListMIC is keyed with it and this client's was not."
      });
      if (parsed.mechListMic && outcome.acceptorSubkey) {
        var verdict;
        try {
          verdict = await negotiate.verifyMechListMic({
            key: outcome.acceptorSubkey.key,
            etype: outcome.acceptorSubkey.etype,
            mic: parsed.mechListMic,
            mechListDer: init.mechListDer
          });
        } catch (e) {
          verdict = { ok: false, error: e.message };
        }
        rows.push({
          name: "the server's mechListMIC",
          value: verdict.ok ? "VERIFIES" : "DOES NOT VERIFY",
          note: verdict.ok
            ? "over the same MechTypeList this client sent, signed by the " +
              verdict.senderRole + " — the role is IN the token, and a " +
              "verifier must use the SENDER's key usage (23 for an acceptor, " +
              "25 for an initiator) rather than its own."
            : "so the server did not see the mechanism list this client " +
              "sent, or signed it with a different key" +
              (verdict.error ? " (" + verdict.error + ")" : "") + "."
        });
        if (!verdict.ok) {
          problems.push("the server's mechListMIC does not verify");
        }
      }
    }
  }

  rows.push({
    name: "HTTP",
    value: result.response.status + " " + (result.response.statusText || ""),
    note: result.response.status === 200
      ? "The resource was served. Everything above is what it took."
      : "accept-completed from SPNEGO, but the resource still did not serve " +
        "— authentication succeeded and authorization is a different question."
  });
  panes.renderTable(host, rows);

  if (problems.length) {
    status("krb_spnego_status",
      "The context completed, but: " + problems.join("; ") + ".", "krb-bad");
    log.debug("Leaving confirmContext(). With problems.");
    return;
  }
  status("krb_spnego_status",
    "accept-completed. The server accepted a Kerberos ticket carried in an " +
    "HTTP header" + (parsed.responseToken ? " and proved its own identity" :
        "") + ", in " + (result.response.status === 200 ? "one round trip " +
        "after the challenge" : "a completed negotiation") + ".", "krb-ok");
  log.debug("Leaving confirmContext(). Complete.");
}

// ---------------------------------------------------------------------------
// The ticket that was sent — and what it takes to see inside it.
//
// The key fields and the button live in the ticket pane itself (spnego.html),
// which is where they were before a shared pane briefly moved them to the foot
// of this page and to four other pages besides. kerberos_keys.js is still the
// implementation — one set of three routes to a key, shared with the decoder
// page — and mount() registers it with kerberos_panes.js, so the key reaches
// every message pane on this page without any render call being given one.
//
// The default salt is this page's own: it is the only page that knows the SPN
// it just used, so it is the only one that can offer realm + principal as an
// assumption. What it must never do is offer it silently — a computer account
// is salted REALM + "host" + short name + DNS domain, and a wrong salt is
// indistinguishable from a wrong password. kerberos_keys.js says which it
// assumed, in the pane, for exactly that reason.
// ---------------------------------------------------------------------------
function assumedServiceSalt() {
  log.debug("Entering assumedServiceSalt().");
  var salt = (chosenTicket ? chosenTicket.realm : "") +
    String(val("krb_spnego_spn")).split("@")[0];
  log.debug("Leaving assumedServiceSalt(). " + JSON.stringify(salt));
  return salt;
}

async function renderTicket() {
  log.debug("Entering renderTicket().");
  if (!lastTicketBytes) {
    log.debug("Leaving renderTicket(). Nothing sent yet.");
    return;
  }
  // No keys passed: this page holds none that open a ticket. What it does hold
  // — the ticket's own session key, and the KDC's report of what is inside it —
  // renderMessage() adds for itself, along with anything typed in the fields
  // below the pane.
  await panes.renderMessage("krb_ticket_pane", "The ticket inside the AP-REQ",
      lastTicketBytes);
  var host = el("krb_ticket_pane");
  var supplied = await panes.extraKeys();
  if (host && !supplied.length) {
    host.appendChild(make("p", "krb-note",
      "No service key supplied, so the ciphertext itself is unopened and the " +
      "contents above are the KDC's report of it rather than its plaintext — " +
      "which is the honest state of a CLIENT: it never holds the key its own " +
      "ticket is sealed with. The one field that report does not cover is the " +
      "PAC. For that, supply the service account's key, its password and " +
      "salt, or its keytab in the fields below, and this pane opens where it " +
      "stands."));
  }
  hexview.render("krb_ticket_hex", lastTicketBytes, "The ticket");
  log.debug("Leaving renderTicket().");
}

function rememberFields() {
  log.debug("Entering rememberFields().");
  try {
    window.localStorage.setItem(panes.KEYS.SPNEGO_URL,
        val("krb_spnego_url"));
    window.localStorage.setItem(panes.KEYS.SPNEGO_SPN,
        val("krb_spnego_spn"));
    // The service password and key are DELIBERATELY absent, as every password
    // on every page in this workflow is.
  } catch (e) {
    log.warn("could not store the SPNEGO fields: " + e.message);
  }
  log.debug("Leaving rememberFields().");
}

// The build's own defaults, applied BEFORE anything stored so a value the user has
// typed still wins — the same order and the same reason as the AS page's
// applyBuildDefaults(). The URL is fetched by the API rather than by the browser,
// so the working value differs per build (`sts` inside compose, loopback on a host
// run, nothing at all where there is no api), and it lived in the markup as one of
// those three. The SPN default is normally EMPTY and the derivation stands; a build
// sets it only for a service whose SPN does not match its URL host.
function applyBuildDefaults() {
  log.debug("Entering applyBuildDefaults().");
  var applied = 0;
  if (appconfig.krb5SpnegoUrlDefault) {
    panes.setVal("krb_spnego_url", appconfig.krb5SpnegoUrlDefault);
    applied++;
  }
  if (appconfig.krb5SpnegoSpnDefault) {
    panes.setVal("krb_spnego_spn", appconfig.krb5SpnegoSpnDefault);
    applied++;
  }
  log.debug("Leaving applyBuildDefaults(). applied=" + applied);
  return applied;
}

function loadFields() {
  log.debug("Entering loadFields().");
  applyBuildDefaults();
  try {
    var url = window.localStorage.getItem(panes.KEYS.SPNEGO_URL);
    var spn = window.localStorage.getItem(panes.KEYS.SPNEGO_SPN);
    if (url) {
      panes.setVal("krb_spnego_url", url);
    }
    if (spn) {
      panes.setVal("krb_spnego_spn", spn);
    }
  } catch (e) {
    // No storage: the defaults in the markup stand.
    log.warn("could not read the stored SPNEGO fields: " + e.message);
  }
  log.debug("Leaving loadFields().");
}

window.onload = async function () {
  log.debug("Entering onload().");
  panes.markCurrentStep("krb_step_spnego");
  panes.wirePanes();
  panes.wireTabs();
  var toggleAll = el("dbg_toggle_all");
  if (toggleAll) {
    toggleAll.addEventListener("change", function () {
      panes.setAllPanes(toggleAll.checked);
    });
  }
  panes.enforceStoragePreference();
  // Arriving HERE clears any return target: this page is the destination, and
  // a stale one left in storage would make the AS page offer to send somebody
  // back to a workflow they have already returned to.
  panes.clearReturnTarget();
  loadFields();
  onUrlChanged();
  await panes.reportEnvironment("krb_environment_note", {
    disableOnNoBackend: ["krb_probe_button", "krb_authenticate_button"]
  });
  // A service ticket is what this page spends, and a delegated one is a service
  // ticket obtained by S4U2Proxy — presented here exactly as any other, which
  // is the whole point of that equivalence.
  tickets.mount({
    slots: ["service", "delegated"],
    onActivate: function () {
      renderCredentials();
    }
  });
  ophistory.mount("krb_operation_history", "krb_clear_operations_button");
  // The key fields in the ticket pane. They register themselves with
  // kerberos_panes.js, so the keys they collect reach every message pane on
  // this page — the negotiation tokens, the AP-REQ and the ticket inside it —
  // without any of the render calls above knowing about it. The salt callback
  // is this page's own: see assumedServiceSalt().
  deckeys.mount({ defaultSalt: assumedServiceSalt });

  var url = el("krb_spnego_url");
  if (url) {
    url.addEventListener("change", onUrlChanged);
    url.addEventListener("blur", onUrlChanged);
  }
  var spn = el("krb_spnego_spn");
  if (spn) {
    spn.addEventListener("change", function () {
      renderSpnNote(derivedSpn(val("krb_spnego_url").trim()));
      renderCredentials();
    });
  }
  var probe = el("krb_probe_button");
  if (probe) {
    probe.addEventListener("click", function () { onProbe(); });
  }
  var authenticate = el("krb_authenticate_button");
  if (authenticate) {
    authenticate.addEventListener("click", function () { onAuthenticate(); });
  }
  log.debug("Leaving onload().");
};

module.exports = {
  onProbe: onProbe,
  onAuthenticate: onAuthenticate,
  assumedServiceSalt: assumedServiceSalt,
  derivedSpn: derivedSpn,
  applyBuildDefaults: applyBuildDefaults,
  reconcileSpn: reconcileSpn,
  selectedMechs: selectedMechs
};
