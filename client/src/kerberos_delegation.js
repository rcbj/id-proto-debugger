// File: kerberos_delegation.js
//
// ---------------------------------------------------------------------------
// Delegation (kerberos_delegation.html): acting as somebody else.
//
// The DOM helpers, the credential cache and the relay calls are in
// kerberos_panes.js; the protocol is in common/krb5/krb5_client.js, with no DOM in it,
// driven without a browser by tests/krb5_tgs_ap.js. What is left here is the page.
//
// ---------------------------------------------------------------------------
// WHAT THIS PAGE EXISTS TO SHOW, and why it is one page rather than four.
//
// Every mechanism here is an ordinary TGS exchange with one thing added, and they are
// side by side because the interesting part is the COMPARISON — a reader who has seen
// only one of them has the wrong model of the others:
//
//   **S4U2Self** — a service asks for a ticket TO ITSELF on behalf of a user who is not
//   involved at all: no password, no ticket of theirs, nothing they consented to. It is
//   how a service that authenticated somebody by other means (a form, a certificate,
//   NTLM) gets a Kerberos identity for them. It is NOT a privilege, because the ticket is
//   to yourself.
//
//   **S4U2Proxy** — that service then reaches ANOTHER service as that user, presenting
//   the first ticket as evidence. THIS is the privilege, and what stands between the two
//   is one attribute on one account. Two different attributes can grant it, on OPPOSITE
//   accounts, and the page makes you choose which one you are relying on:
//     * classic — `msDS-AllowedToDelegateTo` on the FRONT-END, set by a domain admin;
//     * resource-based — `msDS-AllowedToActOnBehalfOfOtherIdentity` on the BACK-END, set
//       by whoever controls that object, which is why RBCD turns "I can write to this
//       computer account" into "I can reach this service as anybody".
//
//   **Forwarding** — the client hands over its whole ticket-granting ticket in a
//   KRB-CRED. After that the holder can reach ANYTHING as that client with no further
//   reference to the KDC. There is no list of permitted targets because there is no
//   constraint, and the service's `ok-as-delegate` flag is only ADVICE to the client.
//
//   **Renewal** — not delegation at all, and here because it is the other thing people
//   try to do with a TGT and the same page already holds one. A renewed ticket must NOT
//   look freshly authenticated: authtime is preserved and renew-till does not move.
//
// ---------------------------------------------------------------------------
// THE THREE FAILURES THIS PAGE IS FOR, because each one points somewhere else.
//
//  * **S4U2Self succeeds and the ticket is not forwardable.** Classic S4U2Proxy then
//    refuses the evidence, complaining about the ticket — while the actual problem is a
//    missing TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION on the front-end account, two steps
//    away. The page reports forwardability on the evidence pane, at the moment it is
//    obtained, and says what it means.
//  * **KDC_ERR_BADOPTION with nothing about padata.** If only RBCD would permit the
//    delegation and PA-PAC-OPTIONS is absent, [MS-SFU] requires exactly that error. The
//    checkbox exists so the difference can be produced deliberately.
//  * **A refusal that names neither attribute.** The mock KDC's refusal lists both and
//    their current values; against a real KDC the error is bare, so the page says which
//    two attributes to go and look at.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_delegation",
  level: appconfig.logLevel
});
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var client = require("./krb5_client.js");
var kpac = require("./krb5_pac.js");
var panes = require("./kerberos_panes.js");
var ophistory = require("./kerberos_history.js");
var tickets = require("./kerberos_tickets.js");
// The Decryption keys pane. S4U_DELEGATION_INFO — the only record IN a ticket
// that a delegation happened — lives in the PAC of a ticket encrypted under
// the TARGET service's key, so this pane is what makes the audit trail
// readable on this page instead of on another one.
var deckeys = require("./kerberos_keys.js");

var el = panes.el;
var val = panes.val;
var status = panes.status;

var tgt = null;
var evidence = null;

// A cached credential comes back from JSON with its bytes as base64 and its
// dates as strings. Revived here rather than in the cache so the cache stays a
// store of plain data — and each page needs slightly different fields.
function revive(entry) {
  log.debug("Entering revive().");
  if (!entry) {
    log.debug("Leaving revive().");
    return null;
  }
  try {
    log.debug("Leaving revive().");
    return {
      ticket: msgs.readTicket(panes.b64ToBytes(entry.ticket)),
      // The cache stores a session key as HEX under `sessionKey` and its
      // encryption type under `sessionKeyEtype` — kerberos.js writes it,
      // kerberos_tgs.js and kerberos_ap.js read it, and this page must speak
      // the same dialect. Reading that hex as base64 SUCCEEDS, because every
      // hex digit is also a base64 character: it yields 48 plausible bytes
      // where 32 were issued, and nothing anywhere reports a key that is
      // merely wrong.
      sessionKey: prim.fromHex(entry.sessionKey),
      etype: entry.sessionKeyEtype,
      // A parsed principal, not the string the cache holds. buildTgsReq() puts
      // this in the Authenticator's cname and S4U2Self uses it as the sname,
      // and both read `.name` — which a string does not have, so a string here
      // encodes as a one-component name containing nothing.
      client: msgs.parsePrincipal(String(entry.client).split("@")[0],
          msgs.NAME_TYPE.PRINCIPAL),
      realm: entry.realm,
      service: entry.service ? msgs.parsePrincipal(entry.service,
          msgs.NAME_TYPE.SRV_HST) : null,
      serviceRealm: entry.serviceRealm || entry.realm,
      // The cache calls the ticket flags `flags` and stores them as NAMES.
      // Reading them from `flagNames` gives an empty list for every ticket the
      // AS page issued, and this page then says a perfectly forwardable TGT is
      // not forwardable — which reads as a KDC or an account problem.
      flags: entry.flags || [],
      flagNames: entry.flags || [],
      authtime: entry.authtime ? new Date(entry.authtime) : null,
      starttime: entry.starttime ? new Date(entry.starttime) : null,
      endtime: entry.endtime ? new Date(entry.endtime) : null,
      renewTill: entry.renewTill ? new Date(entry.renewTill) : null
    };
  } catch (e) {
    log.warn("a cached credential will not revive: " + e.message);
    log.debug("Leaving revive().");
    return null;
  }
  log.debug("Leaving revive().");
}

// What the cache should hold for a credential this page obtained.
//
// This is the shape every other page in the workflow reads: a HEX session key
// under `sessionKey`, its encryption type under `sessionKeyEtype`, and the
// ticket flags as NAMES under `flags`. Writing a different one here would not
// fail on this page — revive() would read its own dialect back perfectly — it
// would fail on the AP page, on the TGS page after a renewal replaced the live
// TGT, and on every Ticket Cache & History row that *Make active* hands
// back.
function toEntry(result, spnText) {
  log.debug("Entering toEntry().");
  log.debug("Leaving toEntry().");
  return {
    isTgt: ((result.service && result.service.name) || [])[0] === "krbtgt",
    ticket: panes.bytesToB64(msgs.encTicket(result.ticket)),
    sessionKey: prim.toHex(result.sessionKey),
    sessionKeyEtype: result.etype,
    sessionKeyEtypeName: kcrypto.etypeName(result.etype),
    client: result.client ? msgs.principalToString(result.client,
        result.realm) : null,
    realm: result.realm,
    service: spnText,
    serviceRealm: result.serviceRealm || result.realm,
    flags: result.flagNames || [],
    authtime: result.authtime ? result.authtime.toISOString() : null,
    starttime: result.starttime ? result.starttime.toISOString() : null,
    endtime: result.endtime ? result.endtime.toISOString() : null,
    renewTill: result.renewTill ? result.renewTill.toISOString() : null,
    storedAt: new Date().toISOString()
  };
}

function renderHeld() {
  log.debug("Entering renderHeld().");
  panes.enforceStoragePreference();
  tgt = revive(panes.readTgt());
  evidence = revive(panes.readEvidence());

  var host = el("krb_held_pane");
  if (!host) {
    return;
  }
  panes.clear(host);
  if (!tgt) {
    host.appendChild(panes.make("p", "krb-note",
      "No ticket-granting ticket is held. Get one on the Kerberos AS page " +
          "first — and note WHOSE " +
      "it should be: S4U2Self is a request a SERVICE makes, so for that half " +
          "the TGT wanted here " +
      "is the service account's own (authenticate as " +
          "HTTP/frontend.example.com, not as a user). " +
      "Forwarding and renewal want the USER's."));
  } else {
    panes.renderTicketPane("krb_held_pane", panes.readTgt(), "The " +
        "ticket-granting ticket held");
    // Whether this TGT can be forwarded at all, said here rather than at the
    // point of failure. An account flagged NOT_DELEGATED ("sensitive and cannot
    // be delegated") is never issued a forwardable ticket, and that is the only
    // visible sign of it.
    var forwardable = (tgt.flagNames || []).indexOf("forwardable") !== -1;
    host.appendChild(panes.make("p", forwardable ? "krb-note" : "krb-warn",
      forwardable
        ? "This ticket is forwardable, so it can be delegated."
        : "This ticket is NOT forwardable, so nothing on this page that " +
            "delegates it will work. " +
          "The KDC withholds that flag from an account flagged NOT_DELEGATED " +
              "(\"account is " +
          "sensitive and cannot be delegated\") however the client asked — " +
              "which is exactly how " +
          "that setting protects an account from every service at once."));
  }

  var evidenceHost = el("krb_evidence_pane");
  if (evidenceHost) {
    panes.clear(evidenceHost);
    if (!evidence) {
      evidenceHost.appendChild(panes.make("p", "krb-note",
        "No S4U2Self evidence ticket is held. Obtain one below to enable " +
            "S4U2Proxy."));
    } else {
      panes.renderTicketPane("krb_evidence_pane", panes.readEvidence(),
        "The evidence ticket (from S4U2Self)");
      var evForwardable = (evidence.flagNames ||
          []).indexOf("forwardable") !== -1;
      evidenceHost.appendChild(panes.make("p", evForwardable ? "krb-note" :
          "krb-warn",
        evForwardable
          ? "Forwardable, so it can be used as evidence for either kind of " +
              "constrained delegation."
          : "NOT forwardable — which CLASSIC constrained delegation " +
              "requires. A ticket from " +
            "S4U2Self is forwardable only when the requesting account has " +
            "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION set, so this usually " +
                "means that flag is " +
            "missing on the service account. Resource-based delegation would " +
                "not need it."));
    }
  }
  panes.disable("krb_s4u2proxy_button", !tgt || !evidence);
  log.debug("Leaving renderHeld(). tgt=" + !!tgt + ", evidence=" + !!evidence);
}

// ---------------------------------------------------------------------------
// Open an Operations History row for one of this page's four exchanges.
//
// Each has its own status line, so each closes independently and more than one
// can be in flight — which is why kerberos_history.js keys the open rows by
// status id rather than holding a single slot.
//
// Called at the TOP of each handler, before its guards, so that pressing
// S4U2Proxy with no evidence ticket is a recorded Failure rather than nothing
// at all. Fields are read unparsed: a name that would not parse is exactly the
// row worth having.
// ---------------------------------------------------------------------------
function beginDelegationOperation(operation, statusId, principal, detail) {
  log.debug("Entering beginDelegationOperation(). " + operation);
  ophistory.begin({
    operation: operation,
    principal: principal || "",
    target: val("krb_kdc_host").trim() + ":" + (val("krb_kdc_port") || "88") +
        "/" + (val("krb_transport") || "tcp"),
    statusId: statusId,
    detail: detail || ""
  });
  log.debug("Leaving beginDelegationOperation().");
}

function kdcTarget() {
  return {
    host: val("krb_kdc_host").trim(),
    port: parseInt(val("krb_kdc_port"), 10) || 88,
    transport: val("krb_transport") || "tcp"
  };
}

// Whose TGT this page is spending, AS TEXT.
//
// `revive()` hands back a PARSED principal — the builders need `.name`, and a
// string there encodes as a one-component name containing nothing — so the
// obvious `tgt.client` is an OBJECT. Four of this page's history rows passed it
// straight to the Operations History pane, which renders with `textContent`,
// and every one of them recorded its user as `[object Object]`. The realm is
// added back because revive() split it off: the column is asked which user
// acted, and `alice` alone does not say in which realm.
//
// kerberos_history.js normalizes a parsed principal too, as a backstop for the
// next call site; this exists because it can also supply the realm, and because
// the "As …" detail below is a string concatenation that no normalization
// inside the log could reach.
function heldClientText() {
  log.debug("Entering heldClientText().");
  if (!tgt || !tgt.client) {
    log.debug("Leaving heldClientText(). No TGT held.");
    return "(no TGT held)";
  }
  log.debug("Leaving heldClientText().");
  return msgs.principalToString(tgt.client, tgt.realm);
}

function tgtKeys() {
  return [{
    etype: tgt.etype,
    key: tgt.sessionKey,
    label: "the TGT's session key"
  }];
}

// One exchange, shown both ways round. Every button on this page does this and
// differs only in how the request was built and what to do with the reply — so
// it is one function rather than five, and a pane that behaved differently
// between them would be a bug visible only by comparing the panes.
//
// THE HEX TABS COME OUT OF THIS FUNCTION TOO, which is why there are five of
// them per exchange and not two. The request's and the reply's own bytes are
// filled by renderMessage() on the way past, by the `krb_x_pane` → `krb_x_hex`
// convention; the Ticket, the enc-part and the decrypted EncTGSRepPart are
// filled from the opened reply, by the convention one step down in
// panes.renderReplyPartsHex(). Doing it here rather than in each of the four
// handlers is the same argument as the rest of this function: three of them
// would have had the same three calls, and the fourth would have been the one
// somebody forgot.
async function exchange(opts) {
  log.debug("Entering exchange().");
  await panes.renderMessage(opts.requestPane, "Sent", opts.built.request,
      tgtKeys());
  // Emptied before the send, not filled after it. These three come from a reply
  // that has not arrived, and the previous attempt's are still in them — so on
  // any of the four paths out of this function that never opens a reply, they
  // would go on showing an earlier exchange's ticket beside a pane reporting
  // this one's refusal.
  panes.renderReplyPartsHex(opts.replyPane, null);
  status(opts.statusId, "Sent. Waiting for the KDC…", "krb-pending");
  var result;
  try {
    result = await panes.sendToKdc(Object.assign({ message: opts.built.request },
        kdcTarget()));
  } catch (e) {
    // The request pane keeps what it was showing: the bytes that went out are
    // the most useful thing on screen when the send failed.
    status(opts.statusId, e.message, "krb-bad");
    log.debug("Leaving exchange().");
    return null;
  }
  await panes.renderMessage(opts.replyPane, "Received", result.reply,
      tgtKeys());

  var read;
  try {
    read = await client.readTgsRep({
      tgt: tgt,
      reply: result.reply,
      nonce: opts.built.nonce,
      subkey: null,
      requestedSname: opts.built.sname
    });
  } catch (e) {
    status(opts.statusId, "The reply did not open: " + e.message, "krb-bad");
    log.debug("Leaving exchange().");
    return null;
  }
  if (!read.ok) {
    // A KRB-ERROR is a reply and its bytes are in the reply hex tab; it has no
    // ticket, no enc-part and no plaintext, so those three stay empty.
    status(opts.statusId, opts.explain(read.error), "krb-bad");
    log.debug("Leaving exchange().");
    return null;
  }
  panes.renderReplyPartsHex(opts.replyPane, read.bytes);
  log.debug("Leaving exchange().");
  return read;
}

// ---------------------------------------------------------------------------
// S4U2Self.
// ---------------------------------------------------------------------------
async function onS4u2Self() {
  log.debug("Entering onS4u2Self().");
  // The principal recorded is the IMPERSONATED user, not the service running
  // the exchange, because that is the whole question about an S4U2Self row:
  // whose identity was asserted without their taking any part in it. The
  // service is in the detail.
  beginDelegationOperation(ophistory.OPS.S4U2SELF, "krb_s4u2self_status",
      val("krb_impersonate").trim(),
      "As " + heldClientText() + ".");
  if (!tgt) {
    status("krb_s4u2self_status", "No usable TGT is held.", "krb-bad");
    return false;
  }
  var userText = val("krb_impersonate").trim();
  if (!userText) {
    status("krb_s4u2self_status",
      "Name the user to impersonate. They take no part in this — no " +
          "password, no ticket of " +
      "theirs, nothing they consent to — which is the whole point of " +
          "S4U2Self and the reason " +
      "the next step is the one that is gated.", "krb-bad");
    return false;
  }
  var user;
  try {
    user = msgs.parsePrincipal(userText, msgs.NAME_TYPE.PRINCIPAL);
  } catch (e) {
    status("krb_s4u2self_status", "That is not a usable principal name: " +
        e.message, "krb-bad");
    return false;
  }
  panes.saveKdcFields();
  try {
    window.localStorage.setItem(panes.KEYS.DELEGATION_USER, userText);
  } catch (e) {
    // No storage: the field simply will not be remembered.
  }

  status("krb_s4u2self_status",
    "Building a TGS-REQ for this service itself, with PA-FOR-USER naming " +
        userText + "…",
    "krb-pending");
  var built;
  try {
    built = await client.buildS4u2SelfReq({
      tgt: tgt,
      user: { type: user.type, name: user.name },
      userRealm: val("krb_realm").trim() || tgt.realm,
      // sname is the requesting service ITSELF. Taken from the TGT's own client
      // name rather than typed, because a mismatch is refused and typing it
      // would invite one — but typed as a SERVICE principal, which is what
      // tests/krb5_delegation_interop.js sends to both KDCs. The mock compares
      // the components only; a real KDC is entitled to be fussier.
      sname: {
        type: msgs.NAME_TYPE.SRV_INST,
        name: tgt.client.name
      },
      realm: val("krb_realm").trim() || tgt.realm
    });
  } catch (e) {
    status("krb_s4u2self_status", "The request could not be built: " +
        e.message, "krb-bad");
    return false;
  }

  var read = await exchange({
    built: built,
    requestPane: "krb_s4u2self_request_pane",
    replyPane: "krb_s4u2self_reply_pane",
    statusId: "krb_s4u2self_status",
    explain: function (error) {
      log.debug("Entering explain().");
      var name = error.error.name;
      var text = name + " (" + error.errorCode + ")" + (error.eText ? " — " +
          error.eText : "");
      if (error.errorCode === 13) {
        text += " KDC_ERR_BADOPTION here usually means the sname was not " +
            "this service itself: " +
          "S4U2Self asks for a ticket TO YOURSELF, and reaching another " +
              "service on a user's " +
          "behalf is S4U2Proxy.";
      }
      if (error.errorCode === 6) {
        text += " The KDC does not know that user. The name is looked up as " +
            "a principal in the " +
          "realm given, so a UPN or a sAMAccountName that differs from the " +
              "principal name will " +
          "read as absent.";
      }
      log.debug("Leaving explain().");
      return text;
    }
  });
  if (!read) {
    return false;
  }

  var entry = toEntry(read, msgs.principalToString(read.service));
  panes.saveEvidence(entry);
  // Labelled explicitly: an S4U2Self ticket is a service ticket to the
  // requesting service ITSELF, so nothing in its names distinguishes it from an
  // ordinary one, and what it is for — being handed back to the KDC as
  // evidence — is the only interesting thing about it.
  panes.recordTicket(entry, "evidence");
  renderHeld();
  tickets.refresh();

  var forwardable = (read.flagNames || []).indexOf("forwardable") !== -1;
  status("krb_s4u2self_status",
    "Got a ticket for " + msgs.principalToString(read.client) + " to " +
    msgs.principalToString(read.service) + ". " +
    (forwardable
      ? "It is FORWARDABLE, so it can be used as evidence for either kind of " +
          "constrained " +
        "delegation."
      : "It is NOT forwardable — usable for resource-based delegation but " +
          "not for classic, " +
        "which needs TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION on this service " +
            "account."),
    forwardable ? "krb-good" : "krb-warn");
  log.debug("Leaving onS4u2Self(). forwardable=" + forwardable);
  return true;
}

// ---------------------------------------------------------------------------
// S4U2Proxy.
// ---------------------------------------------------------------------------
async function onS4u2Proxy() {
  log.debug("Entering onS4u2Proxy().");
  beginDelegationOperation(ophistory.OPS.S4U2PROXY, "krb_s4u2proxy_status",
      (evidence && msgs.principalToString(evidence.client,
          evidence.realm)) || val("krb_impersonate").trim(),
      "To " + (val("krb_deleg_target").trim() || "(no target named)") +
      (panes.checked("krb_resource_based") ? ", resource-based." :
          ", classic."));
  if (!tgt || !evidence) {
    status("krb_s4u2proxy_status",
      "This needs both the service's own TGT and an evidence ticket from " +
          "S4U2Self.", "krb-bad");
    return false;
  }
  var targetText = val("krb_deleg_target").trim();
  if (!targetText) {
    status("krb_s4u2proxy_status",
      "Name the back-end service to reach on the user's behalf — an SPN such " +
          "as " +
      "HTTP/backend.example.com.", "krb-bad");
    return false;
  }
  var target;
  try {
    target = msgs.parsePrincipal(targetText, msgs.NAME_TYPE.SRV_HST);
  } catch (e) {
    status("krb_s4u2proxy_status", "That is not a usable service name: " +
        e.message, "krb-bad");
    return false;
  }
  var resourceBased = panes.checked("krb_resource_based");
  panes.saveKdcFields();
  try {
    window.localStorage.setItem(panes.KEYS.DELEGATION_TARGET, targetText);
  } catch (e) {
    // No storage: the field simply will not be remembered.
  }

  status("krb_s4u2proxy_status",
    "Building a TGS-REQ with cname-in-addl-tkt and the evidence ticket" +
    (resourceBased ? ", plus PA-PAC-OPTIONS with the resource-based bit" :
        "") + "…", "krb-pending");
  var built;
  try {
    built = await client.buildS4u2ProxyReq({
      tgt: tgt,
      evidenceTicket: evidence.ticket,
      sname: { type: target.type, name: target.name },
      realm: val("krb_realm").trim() || tgt.realm,
      resourceBased: resourceBased
    });
  } catch (e) {
    status("krb_s4u2proxy_status", "The request could not be built: " +
        e.message, "krb-bad");
    return false;
  }

  var read = await exchange({
    built: built,
    requestPane: "krb_s4u2proxy_request_pane",
    replyPane: "krb_s4u2proxy_reply_pane",
    statusId: "krb_s4u2proxy_status",
    explain: function (error) {
      log.debug("Entering explain().");
      var text = error.error.name + " (" + error.errorCode + ")" +
        (error.eText ? " — " + error.eText : "");
      if (error.errorCode === 13) {
        // The commonest failure on this page, and the error names none of the
        // causes.
        text += " KDC_ERR_BADOPTION is what a KDC returns for every refusal " +
            "here, so the " +
          "cause has to be narrowed by hand. Check, in this order: " +
          (resourceBased ? "" : "whether only RESOURCE-BASED delegation " +
              "would permit this pair, " +
            "in which case [MS-SFU] requires PA-PAC-OPTIONS and this request " +
                "did not send it — " +
            "tick the box; ") +
          "msDS-AllowedToDelegateTo on the requesting service, which is " +
              "classic constrained " +
          "delegation and must list " + targetText + " exactly; " +
          "msDS-AllowedToActOnBehalfOfOtherIdentity on " + targetText +
              ", which is " +
          "resource-based and must list the requesting service; and whether " +
              "the evidence " +
          "ticket is FORWARDABLE, which classic requires and resource-based " +
              "does not.";
      }
      log.debug("Leaving explain().");
      return text;
    }
  });
  if (!read) {
    return false;
  }

  var delegated = toEntry(read, targetText);
  panes.saveServiceTicket(delegated);
  panes.recordTicket(delegated, "delegated");
  tickets.refresh();
  await renderDelegationTrail(read, targetText);

  status("krb_s4u2proxy_status",
    "Got a ticket for " + msgs.principalToString(read.client) + " to " +
        targetText +
    ", authorized by " + (resourceBased ? "resource-based" : "classic") +
        " constrained " +
    "delegation. The service that asked for it appears nowhere in the ticket " +
        "— only in the " +
    "PAC's delegation trail.", "krb-good");
  log.debug("Leaving onS4u2Proxy().");
  return true;
}

// The audit trail, which is the only record IN the ticket that a delegation
// happened. Reading it needs the target service's key, so this pane says so
// when it has none rather than showing an empty box.
// The last delegation this page produced, so the note below can be repainted
// when a key arrives. Held for the same reason kerberos_panes.js remembers what
// each message pane rendered: the key that makes this readable is typed AFTER
// the exchange, and re-running an S4U2Proxy request to read a trail you already
// have is not an answer.
var lastDelegation = null;

async function renderDelegationTrail(read, targetText) {
  log.debug("Entering renderDelegationTrail().");
  lastDelegation = { read: read, targetText: targetText };
  var host = el("krb_trail_pane");
  if (!host) {
    log.debug("Leaving renderDelegationTrail(). No pane.");
    return;
  }
  var supplied = await panes.extraKeys();
  panes.clear(host);
  host.appendChild(panes.make("p", "krb-note",
    "The delegated ticket names " + msgs.principalToString(read.client) +
        " and nothing else: the " +
    "service that requested it is not in the ticket at all. The one record " +
        "is " +
    "S4U_DELEGATION_INFO inside the PAC — which is encrypted under " +
        targetText + "'s own key, " +
    "and a client never holds that: this page is the client here."));
  // Which of the two states the reader is in, said explicitly. "Supply the key"
  // read as an instruction that had nowhere to be carried out until the
  // Decryption keys pane existed on this page, and once a key HAS been supplied
  // the same sentence reads as though nothing happened.
  host.appendChild(panes.make("p", "krb-note", supplied.length
    ? "You have supplied " + supplied.length + " key(s), so the S4U2Proxy " +
      "reply pane above was re-read with them: if one of them is " +
      targetText + "'s, the ticket's EncTicketPart is open there and the " +
      "trail is inside its PAC. If it says the keys were tried and none " +
      "worked, the key is a different principal's or a stale kvno."
    : "Supply that key in the Decryption keys pane at the foot of this page " +
      "— as a raw key, as " + targetText + "'s password and salt, or as its " +
      "keytab — and the S4U2Proxy reply pane above opens where it stands, " +
      "PAC and trail included. Nothing typed there is stored or sent " +
      "anywhere."));
  log.debug("Leaving renderDelegationTrail(). supplied=" + supplied.length);
}

// The Decryption keys pane's onApply hook. The message panes replay themselves;
// this one is prose about them and has to be told.
function refreshDelegationTrail() {
  log.debug("Entering refreshDelegationTrail().");
  if (!lastDelegation) {
    log.debug("Leaving refreshDelegationTrail(). No delegation yet.");
    return false;
  }
  Promise.resolve()
    .then(function () {
      return renderDelegationTrail(lastDelegation.read,
          lastDelegation.targetText);
    })
    .catch(function (e) {
      log.error("the delegation trail could not be repainted: " + e.message);
    });
  log.debug("Leaving refreshDelegationTrail().");
  return true;
}

// ---------------------------------------------------------------------------
// Renewal.
// ---------------------------------------------------------------------------
async function onRenew() {
  log.debug("Entering onRenew().");
  beginDelegationOperation(ophistory.OPS.RENEW, "krb_renew_status",
      heldClientText(), "");
  if (!tgt) {
    status("krb_renew_status", "No usable TGT is held.", "krb-bad");
    return false;
  }
  if (!tgt.renewTill) {
    status("krb_renew_status",
      "This ticket carries no renew-till, so there is nothing to renew up " +
          "to. Renewability is " +
      "asked for when the ticket is FIRST obtained — tick 'renewable' on the " +
          "AS page — and " +
      "cannot be added afterwards.", "krb-bad");
    return false;
  }
  panes.saveKdcFields();
  status("krb_renew_status", "Building a TGS-REQ with the RENEW option…",
      "krb-pending");
  var built;
  try {
    built = await client.buildRenewReq({
      tgt: tgt,
      realm: val("krb_realm").trim() || tgt.realm,
      // Deliberately beyond renew-till, so the cap is visible rather than
      // theoretical.
      till: new Date(tgt.renewTill.getTime() + 24 * 3600 * 1000)
    });
  } catch (e) {
    status("krb_renew_status", "The request could not be built: " + e.message,
        "krb-bad");
    return false;
  }

  var before = {
    authtime: tgt.authtime,
    endtime: tgt.endtime,
    renewTill: tgt.renewTill
  };
  var read = await exchange({
    built: built,
    requestPane: "krb_renew_request_pane",
    replyPane: "krb_renew_reply_pane",
    statusId: "krb_renew_status",
    explain: function (error) {
      log.debug("Entering explain().");
      var text = error.error.name + " (" + error.errorCode + ")" +
        (error.eText ? " — " + error.eText : "");
      if (error.errorCode === 32) {
        text += " renew-till has passed. A renewable ticket can be renewed " +
            "repeatedly but only " +
          "up to that instant, which does not move — otherwise it would " +
              "never expire.";
      }
      log.debug("Leaving explain().");
      return text;
    }
  });
  if (!read) {
    return false;
  }

  var renewed = toEntry(read, msgs.principalToString(read.service));
  panes.saveTgt(renewed);
  // A renewal produces a TGT, and ticketKind() will say so from its krbtgt
  // service whatever label is passed here — which is the point of deriving it
  // rather than trusting the caller.
  panes.recordTicket(renewed, "TGT");
  renderHeld();
  tickets.refresh();

  // The two facts worth stating, because both are things a renewal must NOT do.
  var authtimeHeld = before.authtime && read.authtime &&
    read.authtime.getTime() === before.authtime.getTime();
  var cappedAt = read.endtime && before.renewTill &&
    read.endtime.getTime() <= before.renewTill.getTime();
  status("krb_renew_status",
    "Renewed until " + read.endtime.toISOString() + ". " +
    (authtimeHeld
      ? "authtime is unchanged, which is correct: the user did not " +
          "authenticate again, and a " +
        "service reading authtime to judge freshness must not be told " +
            "otherwise."
      : "WARNING: authtime MOVED, from " + (before.authtime ?
          before.authtime.toISOString() : "?") +
        " to " + read.authtime.toISOString() + ". A renewed ticket must not " +
            "look freshly " +
        "authenticated.") + " " +
    (cappedAt
      ? "The request asked for longer than renew-till and was capped at it, " +
          "which is what stops a " +
        "renewable ticket being immortal."
      : "WARNING: the new endtime is PAST the old renew-till."),
    authtimeHeld && cappedAt ? "krb-good" : "krb-warn");
  log.debug("Leaving onRenew(). authtimeHeld=" + authtimeHeld + ", capped=" +
      cappedAt);
  return true;
}

// ---------------------------------------------------------------------------
// Forwarding: unconstrained delegation.
// ---------------------------------------------------------------------------
async function onForward() {
  log.debug("Entering onForward().");
  beginDelegationOperation(ophistory.OPS.FORWARD, "krb_forward_status",
      heldClientText(), "");
  if (!tgt) {
    status("krb_forward_status", "No usable TGT is held.", "krb-bad");
    return false;
  }
  panes.saveKdcFields();
  status("krb_forward_status", "Asking the KDC for a ticket-granting ticket " +
      "flagged forwarded…",
    "krb-pending");
  var built;
  try {
    built = await client.buildForwardedTgtReq({
      tgt: tgt,
      realm: val("krb_realm").trim() || tgt.realm
    });
  } catch (e) {
    status("krb_forward_status", "The request could not be built: " +
        e.message, "krb-bad");
    return false;
  }

  var read = await exchange({
    built: built,
    requestPane: "krb_forward_request_pane",
    replyPane: "krb_forward_reply_pane",
    statusId: "krb_forward_status",
    explain: function (error) {
      log.debug("Entering explain().");
      var text = error.error.name + " (" + error.errorCode + ")" +
        (error.eText ? " — " + error.eText : "");
      if (error.errorCode === 13) {
        text += " Two things refuse this. The presented ticket must itself " +
            "be FORWARDABLE; and " +
          "the account must not be flagged NOT_DELEGATED (\"account is " +
              "sensitive and cannot be " +
          "delegated\"), which is checked even when an older forwardable " +
              "ticket exists — so " +
          "setting that flag takes effect without waiting for outstanding " +
              "tickets to expire.";
      }
      log.debug("Leaving explain().");
      return text;
    }
  });
  if (!read) {
    return false;
  }

  // Wrap it for one service. The key is that AP exchange's subkey in a real
  // flow; here a fresh one is generated and SHOWN, because the point of the
  // pane is the structure — and it is passed to the pane's own render below, so
  // the EncKrbCredPart opens where it stands rather than needing to be carried
  // anywhere. It is shown as well as used: the same bytes pasted into the
  // decoder page later must still be readable.
  var profile = kcrypto.etypeById(read.etype);
  var subkey = {
    etype: read.etype,
    key: kcrypto.randomBytes(profile.keyBytes)
  };
  var credential;
  try {
    credential = await client.wrapDelegatedCredential({
      forwarded: read,
      key: subkey
    });
  } catch (e) {
    status("krb_forward_status",
        "The forwarded ticket could not be wrapped: " + e.message,
      "krb-bad");
    return false;
  }

  // Shown as a KRB-CRED in its own right, decodable with the key beside it.
  await panes.renderMessage("krb_krbcred_pane", "KRB-CRED (the delegated " +
      "credential)", credential,
    [{
      etype: subkey.etype,
      key: subkey.key,
      label: "the subkey it was sealed with"
    }]);
  var host = el("krb_krbcred_pane");
  if (host) {
    host.appendChild(panes.make("p", "krb-warn",
      "Whoever holds these bytes AND the key below can obtain tickets to " +
          "ANYTHING as " +
      msgs.principalToString(read.client) + " until " +
      (read.endtime ? read.endtime.toISOString() : "it expires") +
          ", without this KDC being " +
      "asked again. There is no list of permitted targets, because there is " +
          "no constraint — " +
      "which is the whole difference from the two S4U mechanisms above, " +
          "where every hop returns " +
      "to the KDC and is checked against an attribute. In a real flow this " +
          "travels inside an " +
      "AP-REQ Authenticator's 0x8003 checksum, not on its own."));
    host.appendChild(panes.make("p", "krb-note",
      "Sealed with a subkey generated here: " + prim.toHex(subkey.key) + " (" +
      kcrypto.etypeName(subkey.etype) + "). Paste the KRB-CRED and this key " +
          "into the decoder " +
      "page to read the forwarded ticket's own session key out of it. In a " +
          "real exchange the key " +
      "would be the AP exchange's subkey, or the presented ticket's session " +
          "key when none was " +
      "sent — never a long-term key."));
  }

  status("krb_forward_status",
    "Got a forwarded TGT for " + msgs.principalToString(read.client) +
        " and wrapped it as a " +
    "KRB-CRED. Its flags are [" + (read.flagNames || []).join(", ") + "]" +
    ((read.flagNames || []).indexOf("forwarded") !== -1
      ? " — `forwarded` is the record a receiving service has that these " +
          "credentials were handed " +
        "over rather than presented by their owner."
      : " — note it is NOT flagged forwarded, which it should be."),
    "krb-good");
  log.debug("Leaving onForward().");
  return true;
}

function onForgetEvidence() {
  panes.forgetEvidence();
  renderHeld();
  // The ticket is still in the history — this discards the live slot, not the
  // record — so the pane below has to be repainted or it goes on marking that
  // row "in use" when nothing holds it.
  tickets.refresh();
  ophistory.note({
    operation: ophistory.OPS.FORGET_EVIDENCE,
    detail: "The evidence ticket has been discarded."
  });
  status("krb_s4u2self_status", "The evidence ticket has been discarded.",
      "krb-note");
}

function wire() {
  log.debug("Entering wire().");
  // The shared chrome every workflow here has: the step trail marks where we
  // are, and the toggle collapses or expands every pane at once. wirePanes()
  // pairs each legend with its fieldset by id, so a pane added later is
  // clickable without anything being registered for it.
  panes.markCurrentStep("krb_step_delegation");
  panes.wirePanes();
  // Without this the Hex buttons render, do nothing when clicked, and every
  // panel behind them stays `display: none` — which reads as a page that has no
  // hex view rather than as a missing call. Sixteen panels on this page, across
  // the S4U2Self, S4U2Proxy and forwarding panes.
  panes.wireTabs();
  var toggleAll = el("dbg_toggle_all");
  if (toggleAll) {
    toggleAll.addEventListener("change", function () {
      panes.setAllPanes(toggleAll.checked);
    });
  }
  panes.loadKdcFields();
  panes.setVal("krb_impersonate",
    window.localStorage.getItem(panes.KEYS.DELEGATION_USER) || "alice");
  panes.setVal("krb_deleg_target",
    window.localStorage.getItem(panes.KEYS.DELEGATION_TARGET) || "");
  panes.reportEnvironment("krb_environment");
  renderHeld();
  // The Ticket Cache & History pane, from partials/krb_tickets.html. This is
  // the one page holding TWO slots — a TGT to spend and an S4U2Self evidence
  // ticket to present as evidence — so both kinds can be taken back here, and
  // renderHeld() re-reads and re-revives both.
  tickets.mount({
    slots: ["TGT", "evidence"],
    onActivate: function () {
      renderHeld();
    }
  });
  ophistory.mount("krb_operation_history", "krb_clear_operations_button");
  // The Decryption keys pane, from partials/krb_keys.html. onApply re-renders
  // the delegation trail note as well, because that pane is not a message
  // pane and so is not replayed by panes.rerenderMessages().
  deckeys.mount({ onApply: refreshDelegationTrail });

  var wiring = [
    ["krb_s4u2self_button", onS4u2Self],
    ["krb_s4u2proxy_button", onS4u2Proxy],
    ["krb_renew_button", onRenew],
    ["krb_forward_button", onForward],
    ["krb_forget_evidence_button", onForgetEvidence]
  ];
  wiring.forEach(function (pair) {
    var button = el(pair[0]);
    if (button) {
      button.addEventListener("click", function () {
        // Every handler is async and returns a promise nobody awaits; a
        // rejection would otherwise be an unhandled one, and the page would
        // simply stop with no message.
        Promise.resolve()
          .then(pair[1])
          .catch(function (e) {
            log.error(pair[0] + " failed: " + (e.stack || e.message));
          });
      });
    }
  });
  log.debug("Leaving wire().");
}

if (typeof window !== "undefined" && window.document) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
}

module.exports = { revive: revive, toEntry: toEntry };
