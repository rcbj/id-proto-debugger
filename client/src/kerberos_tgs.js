// File: kerberos_tgs.js
//
// ---------------------------------------------------------------------------
// The TGS exchange (kerberos_tgs.html): spend a TGT on a service ticket.
//
// The DOM helpers, the credential cache and the relay calls are in
// kerberos_panes.js; the protocol is in common/krb5/krb5_client.js, with no DOM in
// it, driven without a browser by tests/krb5_tgs_ap.js. What is left here is the
// page: reading the held TGT, asking for an SPN, and showing both messages.
//
// ---------------------------------------------------------------------------
// WHAT THIS PAGE EXISTS TO SHOW.
//
// A TGS-REQ is not an AS-REQ with a different tag, and its shape is the thing worth
// seeing: **the TGT travels as pre-authentication**, in a PA-TGS-REQ whose value is
// an entire AP-REQ, whose Authenticator carries a checksum over the encoded
// KDC-REQ-BODY. Three consequences the panes call out:
//
//  * the request is signed with the TGT's SESSION key, not the user's password —
//    which is why this page never asks for a password at all;
//  * the checksum covers the body's exact bytes, so the body is encoded once and
//    those same bytes go on the wire; and
//  * the reply comes back at key usage 8, or 9 if a subkey was sent. The page lets
//    you send one or not, and reports which usage opened the reply, because a client
//    that guesses wrong sees only an integrity failure.
//
// The commonest real failure here is KDC_ERR_S_PRINCIPAL_UNKNOWN: an SPN that is not
// registered, or registered on a different account. The page says so on that error
// rather than leaving "no such service" to be interpreted.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_tgs",
  level: appconfig.logLevel
});
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var client = require("./krb5_client.js");
var panes = require("./kerberos_panes.js");
var ophistory = require("./kerberos_history.js");
var tickets = require("./kerberos_tickets.js");

var el = panes.el;
var val = panes.val;
var status = panes.status;

// The TGT this page is spending, reconstituted from the cache. Held in memory
// because everything in it — the session key especially — is a credential.
var tgt = null;
var lastExchange = null;

function reviveTgt(entry) {
  log.debug("Entering reviveTgt().");
  if (!entry) {
    log.debug("Leaving reviveTgt().");
    return null;
  }
  try {
    log.debug("Leaving reviveTgt().");
    return {
      // The ticket goes back on the wire byte-for-byte: it is encrypted under
      // the KDC's own key and its DER is covered by checksums computed
      // elsewhere, so it is carried rather than rebuilt.
      ticket: msgs.readTicket(panes.b64ToBytes(entry.ticket)),
      sessionKey: prim.fromHex(entry.sessionKey),
      etype: entry.sessionKeyEtype,
      client: msgs.parsePrincipal(entry.client.split("@")[0],
          msgs.NAME_TYPE.PRINCIPAL),
      realm: entry.realm,
      endtime: new Date(entry.endtime)
    };
  } catch (e) {
    log.error("the stored TGT could not be revived: " + e.message);
    log.debug("Leaving reviveTgt().");
    return null;
  }
  log.debug("Leaving reviveTgt().");
}

function renderHeldTgt() {
  log.debug("Entering renderHeldTgt().");
  var entry = panes.readTgt();
  panes.renderTicketPane("krb_tgt_pane", entry, "The TGT this page will spend",
    "No TGT held. Get one on the AS exchange page first — this page spends a " +
        "TGT and cannot " +
    "obtain one.");
  if (!entry) {
    panes.disable("krb_tgs_button", true);
    status("krb_tgs_status", "No TGT held, so there is nothing to spend.",
        "krb-bad");
    log.debug("Leaving renderHeldTgt(). none held.");
    return false;
  }
  tgt = reviveTgt(entry);
  if (!tgt) {
    panes.disable("krb_tgs_button", true);
    status("krb_tgs_status",
      "A TGT is stored but this page cannot read it back — it may have been " +
          "written by an older " +
      "build. Get a fresh one on the AS exchange page.", "krb-bad");
    return false;
  }
  // An expired TGT cannot buy anything, and saying so beats a
  // KRB_AP_ERR_TKT_EXPIRED from the KDC that reads as a server problem.
  if (tgt.endtime <= new Date()) {
    panes.disable("krb_tgs_button", true);
    status("krb_tgs_status",
      "The held TGT expired at " + tgt.endtime.toISOString() + ". A TGS-REQ " +
          "with it would be " +
      "refused with KRB_AP_ERR_TKT_EXPIRED. Get a fresh one on the AS " +
          "exchange page.", "krb-bad");
    return false;
  }
  panes.disable("krb_tgs_button", false);
  status("krb_tgs_status",
    "Holding a TGT for " + entry.client + ", valid until " + entry.endtime +
    ". Name a service and ask the KDC for a ticket to it.", null);
  log.debug("Leaving renderHeldTgt(). ready.");
  return true;
}

// ---------------------------------------------------------------------------
// The way back, when somebody arrived from another workflow.
//
// The SPNEGO page spends a service ticket and cannot obtain one, so it sends
// people here with ?return=spnego and the SPN it wants. This offers the link
// back — as a LINK, never a redirect: the two decoded messages above are what
// this page exists to show, and navigating away the moment a ticket arrives
// takes them off the screen exactly when somebody wanted to read them.
//
// "Ready" is not "a ticket exists": it is "a ticket for THAT SPN exists". A
// held ticket for another service proves nothing to this one, and a banner
// that said otherwise would send somebody back to a page that refuses them.
// ---------------------------------------------------------------------------
function showReturnBanner() {
  log.debug("Entering showReturnBanner().");
  var wanted = String(val("krb_spn") || "").split("@")[0].toLowerCase();
  var held = false;
  panes.readServiceTickets().forEach(function (entry) {
    if (String(entry.service || "").split("@")[0].toLowerCase() === wanted) {
      held = true;
    }
  });
  panes.renderReturnBanner("krb_return_banner", {
    ready: held,
    readyText: "You now hold a service ticket for " + val("krb_spn") +
      ", which is what it spends.",
    needText: "It needs a service ticket for " + (val("krb_spn") ||
      "the SPN it derived from the URL") + ". Buy one here."
  });
  log.debug("Leaving showReturnBanner(). ready=" + held);
}

function renderServiceTickets() {
  log.debug("Entering renderServiceTickets().");
  // Repainted here rather than only on load, because whether the caller has
  // what it came for changes exactly when this list does.
  showReturnBanner();
  var host = el("krb_tickets_pane");
  if (!host) {
    log.debug("Leaving renderServiceTickets().");
    return;
  }
  panes.clear(host);
  var tickets = panes.readServiceTickets();
  if (!tickets.length) {
    host.appendChild(panes.make("p", "krb-note",
      "No service tickets yet. One will appear here after a successful " +
          "exchange, and the AP " +
      "exchange page presents it."));
    panes.disable("krb_forget_tickets_button", true);
    log.debug("Leaving renderServiceTickets().");
    return;
  }
  panes.disable("krb_forget_tickets_button", false);
  tickets.forEach(function (entry) {
    var pane = panes.make("div", "krb-section");
    pane.appendChild(panes.make("h4", "krb-section-title", entry.service));
    panes.renderTable(pane, panes.ticketRows(entry));
    host.appendChild(pane);
  });
  log.debug("Leaving renderServiceTickets().");
}

function requestedEtypes() {
  log.debug("Entering requestedEtypes().");
  var text = val("krb_etypes").trim();
  if (!text) {
    log.debug("Leaving requestedEtypes().");
    return [tgt ? tgt.etype : 18];
  }
  var ids = [];
  text.split(/[\s,]+/).forEach(function (part) {
    var id = parseInt(part, 10);
    if (Number.isInteger(id)) ids.push(id);
  });
  log.debug("Leaving requestedEtypes().");
  return ids.length ? ids : [tgt.etype];
}

async function onRequestServiceTicket() {
  log.debug("Entering onRequestServiceTicket().");
  // Opened before the guards, so clicking this with no TGT held is recorded as
  // the Failure it is. Every exit below sets a status on krb_tgs_status, and
  // that is what closes the row — see the note at the top of
  // kerberos_history.js. The principal is the TGT's client rather than a field
  // on this page, because a TGS-REQ acts as whoever the TGT was issued to and
  // that is the only place this page can learn it.
  ophistory.begin({
    operation: ophistory.OPS.TGS,
    principal: (tgt && tgt.client) || "(no TGT held)",
    target: val("krb_spn").trim() + " via " + val("krb_kdc_host").trim() +
        ":" + (val("krb_kdc_port") || "88"),
    statusId: "krb_tgs_status"
  });
  if (!tgt) {
    status("krb_tgs_status", "No usable TGT is held.", "krb-bad");
    return false;
  }
  var spnText = val("krb_spn").trim();
  if (!spnText) {
    status("krb_tgs_status",
      "Name the service you want a ticket for — an SPN such as " +
          "HTTP/web.example.com. On Active " +
      "Directory the service class is case-insensitive but the host part " +
          "must match what is " +
      "registered on the account.", "krb-bad");
    return false;
  }
  var spn;
  try {
    spn = msgs.parsePrincipal(spnText, msgs.NAME_TYPE.SRV_HST);
  } catch (e) {
    status("krb_tgs_status", "That is not a usable service name: " + e.message,
        "krb-bad");
    return false;
  }

  var useSubkey = panes.checked("krb_use_subkey");
  var subkey = null;
  if (useSubkey) {
    var profile = kcrypto.etypeById(tgt.etype);
    subkey = { etype: tgt.etype, key: kcrypto.randomBytes(profile.keyBytes) };
  }
  panes.saveKdcFields();
  try {
    window.localStorage.setItem(panes.KEYS.SERVICE_SPN, spnText);
  } catch (e) {
    // No storage: the field simply will not be remembered.
  }

  status("krb_tgs_status", "Building a TGS-REQ signed with the TGT's session " +
      "key…", "krb-pending");
  var built;
  try {
    built = await client.buildTgsReq({
      tgt: tgt,
      sname: { type: spn.type, name: spn.name },
      realm: val("krb_realm").trim() || tgt.realm,
      etypes: requestedEtypes(),
      subkey: subkey,
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE]
    });
  } catch (e) {
    status("krb_tgs_status", "The request could not be built: " + e.message,
        "krb-bad");
    return false;
  }

  // Both the outer request and the AP-REQ inside its padata are worth showing:
  // the nesting is the thing about this message people do not expect.
  await panes.renderMessage("krb_request_pane", "Sent", built.request,
    [{
      etype: tgt.etype,
      key: tgt.sessionKey,
      label: "the TGT's session key"
    }]);

  status("krb_tgs_status", "Sent. Waiting for the KDC…", "krb-pending");
  var result;
  try {
    result = await panes.sendToKdc({
      host: val("krb_kdc_host").trim(),
      port: parseInt(val("krb_kdc_port"), 10) || 88,
      transport: val("krb_transport") || "tcp",
      message: built.request
    });
  } catch (e) {
    // The request pane keeps what it was showing: the bytes that were sent are
    // the most useful thing on screen when the send failed.
    status("krb_tgs_status", e.message, "krb-bad");
    log.debug("Leaving onRequestServiceTicket(). send failed.");
    return false;
  }

  await panes.renderMessage("krb_reply_pane", "Received", result.reply,
    [{
      etype: tgt.etype,
      key: tgt.sessionKey,
      label: "the TGT's session key"
    }].concat(
      subkey ? [{
        etype: subkey.etype,
        key: subkey.key,
        label: "the Authenticator's subkey"
      }] : []));

  var outcome;
  try {
    outcome = await client.readTgsRep({
      tgt: tgt,
      reply: result.reply,
      nonce: built.nonce,
      subkey: subkey
    });
  } catch (e) {
    status("krb_tgs_status", "The reply could not be read: " + e.message,
        "krb-bad");
    return false;
  }

  if (!outcome.ok) {
    var error = outcome.error;
    var extra = "";
    if (error.errorCode === 7) {
      extra = " On Active Directory this means the SPN is not registered, or " +
          "is registered on a " +
        "different account — `setspn -Q " + spnText + "` is the check.";
    } else if (error.errorCode === 14) {
      extra = " The service account and this request have no encryption type " +
          "in common; in 2026 " +
        "that usually means RC4 has been disabled on one side.";
    } else if (error.errorCode === 50) {
      extra = " The Authenticator's checksum did not match the request body. " +
          "That is either a " +
        "key usage error (it must be 6) or the body being re-encoded after " +
            "it was signed.";
    }
    status("krb_tgs_status", error.error.name + " — " + error.error.meaning +
        extra, "krb-bad");
    log.debug("Leaving onRequestServiceTicket(). refused with " +
        error.error.name);
    return false;
  }

  var entry = {
    isTgt: false,
    realm: outcome.realm,
    client: msgs.principalToString(outcome.client, outcome.realm),
    service: msgs.principalToString(outcome.service, outcome.serviceRealm),
    ticket: panes.bytesToB64(outcome.ticket.raw),
    sessionKey: prim.toHex(outcome.sessionKey),
    sessionKeyEtype: outcome.etype,
    sessionKeyEtypeName: kcrypto.etypeName(outcome.etype),
    flags: outcome.flagNames,
    authtime: outcome.authtime.toISOString(),
    endtime: outcome.endtime.toISOString(),
    renewTill: outcome.renewTill ? outcome.renewTill.toISOString() : null,
    storedAt: new Date().toISOString()
  };
  panes.saveServiceTicket(entry);
  // Into the workflow-wide Ticket Cache & History as well, which every page
  // shows. Every page that OBTAINS a ticket records it; the pane is a record of
  // the whole workflow rather than of one page.
  panes.recordTicket(entry, "service");
  renderServiceTickets();
  tickets.refresh();
  lastExchange = outcome;

  // Which key usage opened the reply is reported, not hidden. A client that
  // always tries one of the two fails whenever the other applies, and the
  // symptom is an integrity failure that names nothing.
  status("krb_tgs_status",
    "A service ticket for " + entry.service + " was issued and stored, valid " +
        "until " +
    entry.endtime + ". Its enc-part was opened with " + outcome.openedWith +
        "." +
    (outcome.flagNames.indexOf("initial") === -1
      ? " Note it is NOT flagged `initial` — only the AS exchange issues an " +
          "initial ticket, and a " +
        "service may insist on that distinction."
      : ""),
    "krb-ok");
  log.debug("Leaving onRequestServiceTicket(). ok.");
  return false;
}

function onForgetTickets() {
  log.debug("Entering onForgetTickets().");
  var dropped = panes.readServiceTickets().length;
  panes.forgetServiceTickets();
  renderServiceTickets();
  // The tickets are still in the history — this discards the live cache, not
  // the record — so the pane below has to be repainted or it goes on marking
  // rows "in use" that nothing holds any more.
  tickets.refresh();
  ophistory.note({
    operation: ophistory.OPS.FORGET_TICKETS,
    detail: dropped + " service ticket(s) discarded."
  });
  status("krb_tgs_status", "The stored service tickets were cleared.", null);
  log.debug("Leaving onForgetTickets().");
  return false;
}

window.onload = async function () {
  log.debug("Entering onload().");
  // The shared chrome every workflow here has: the step trail marks where we
  // are, and the toggle collapses or expands every pane at once. wirePanes()
  // pairs each legend with its fieldset by id, so a pane added later is
  // clickable without anything being registered for it.
  panes.markCurrentStep("krb_step_tgs");
  panes.wirePanes();
  // The Decoded/Hex strips inside the message panes. Paired by their group
  // name the way the legends are paired with their fieldsets, so a strip
  // added to the markup needs nothing here.
  panes.wireTabs();
  var toggleAll = el("dbg_toggle_all");
  if (toggleAll) {
    toggleAll.addEventListener("change", function () {
      panes.setAllPanes(toggleAll.checked);
    });
  }
  panes.enforceStoragePreference();
  panes.loadKdcFields();
  try {
    var spn = window.localStorage.getItem(panes.KEYS.SERVICE_SPN);
    if (spn) panes.setVal("krb_spn", spn);
  } catch (e) {
    // No storage: the default in the markup stands.
  }
  // A caller may name the SPN it needs, and it wins over what was stored: the
  // SPNEGO page derived it from a URL that is the reason somebody is here, so
  // filling the field with the last SPN this page happened to use would send
  // them back with a ticket for the wrong service — which is refused a page
  // later with KRB_AP_ERR_NOT_US and reads as a broken ticket.
  panes.noteReturnTarget();
  try {
    var asked = new URLSearchParams(window.location.search).get("spn");
    if (asked) {
      panes.setVal("krb_spn", asked);
    }
  } catch (e) {
    // No URLSearchParams, or an unparseable query. The stored value stands.
    log.warn("could not read the requested SPN: " + e.message);
  }
  await panes.reportEnvironment("krb_environment_note", {
    disableOnNoBackend: ["krb_tgs_button"]
  });
  renderHeldTgt();
  renderServiceTickets();
  // The Ticket Cache & History pane, from partials/krb_tickets.html. This page
  // spends a TGT, so a TGT is what it can take back — and renderHeldTgt() is
  // what re-reads it, re-revives it and re-enables the button, which is why the
  // callback is that function rather than a repaint.
  tickets.mount({
    slots: ["TGT"],
    onActivate: function () {
      renderHeldTgt();
    }
  });
  ophistory.mount("krb_operation_history", "krb_clear_operations_button");
  var button = el("krb_tgs_button");
  if (button) button.addEventListener("click",
      function () { onRequestServiceTicket(); });
  var forget = el("krb_forget_tickets_button");
  if (forget) forget.addEventListener("click", onForgetTickets);
  log.debug("Leaving onload().");
};

module.exports = {
  onRequestServiceTicket: onRequestServiceTicket,
  onForgetTickets: onForgetTickets
};
