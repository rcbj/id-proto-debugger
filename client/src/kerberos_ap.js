// File: kerberos_ap.js
//
// ---------------------------------------------------------------------------
// The AP exchange (kerberos_ap.html): present the ticket to the service.
//
// This is the end of the workflow and the only page that answers the question
// everything else was preparation for — will the service accept it. A KDC issuing a
// ticket says only that the KDC was willing.
//
// ---------------------------------------------------------------------------
// FOUR THINGS THIS PAGE SHOWS THAT NOTHING ELSE DOES.
//
//  * **A service is not sent a bare AP-REQ.** It is sent an RFC 2743
//    InitialContextToken: `0x60`, the Kerberos mechanism OID, the token id `01 00`,
//    then the AP-REQ. The pane shows the wrapper, because a bare AP-REQ is refused by
//    every real service and the refusal names nothing useful.
//  * **The Authenticator's checksum is type 0x8003 and is not a checksum.** It
//    carries the channel bindings and the GSS flags, and its integers are
//    LITTLE-endian in a protocol where everything else is big-endian. It is the
//    single most commonly botched field in Kerberos, so the page decodes it field by
//    field.
//  * **Mutual authentication is an ECHO, and this page CHECKS it.** The AP-REP
//    returns the Authenticator's ctime and cusec encrypted under the session key.
//    Only something holding the service's long-term key could have decrypted the
//    ticket to learn that key, so a correct echo is the service's identity. A client
//    that asks for mutual authentication and does not verify the echo has not
//    performed it — it has only asked — and the page says which it did.
//  * **Per-message tokens are keyed from the ACCEPTOR's subkey** once the service
//    offers one, not from the ticket's session key. Using the wrong one produces a
//    token the far end cannot verify, and the error names the checksum rather than the
//    key.
//
// The relay endpoint this page uses is `POST /krb5/service`, which is OFF by default
// in the api — a service can be on any port, so it is a broader capability than the
// KDC relay and is switched on deliberately. The page says so on arrival rather than
// failing when the button is pressed.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos_ap", level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var gss = require("./krb5_gss.js");
var client = require("./krb5_client.js");
var panes = require("./kerberos_panes.js");

var el = panes.el;
var val = panes.val;
var status = panes.status;

// The established context, held in memory only: it contains session and subkeys,
// which are credentials, and it is meaningless once the page is reloaded anyway.
var context = null;
var chosenTicket = null;

function revive(entry) {
  return {
    ticket: msgs.readTicket(panes.b64ToBytes(entry.ticket)),
    sessionKey: prim.fromHex(entry.sessionKey),
    etype: entry.sessionKeyEtype,
    client: msgs.parsePrincipal(entry.client.split("@")[0], msgs.NAME_TYPE.PRINCIPAL),
    realm: entry.realm,
    service: entry.service,
    endtime: new Date(entry.endtime)
  };
}

function renderTicketChoice() {
  log.debug("Entering renderTicketChoice().");
  var tickets = panes.readServiceTickets();
  var select = el("krb_ticket_select");
  var host = el("krb_ticket_pane");
  panes.clear(host);
  if (select) panes.clear(select);

  if (!tickets.length) {
    host.appendChild(panes.make("p", "krb-note",
      "No service ticket held. The TGS exchange page buys one; this page presents it. A TGT is not " +
      "enough — it is a ticket to krbtgt, and a service will refuse it with KRB_AP_ERR_NOT_US."));
    panes.disable("krb_present_button", true);
    status("krb_ap_status", "No service ticket to present.", "krb-bad");
    return false;
  }
  tickets.forEach(function (entry, index) {
    var option = panes.make("option", null, entry.service + "  (until " + entry.endtime + ")");
    option.value = String(index);
    if (select) select.appendChild(option);
  });
  onTicketChosen();
  log.debug("Leaving renderTicketChoice(). " + tickets.length + " ticket(s).");
  return true;
}

function onTicketChosen() {
  var tickets = panes.readServiceTickets();
  var index = parseInt(val("krb_ticket_select"), 10) || 0;
  var entry = tickets[index];
  if (!entry) return;
  panes.renderTicketPane("krb_ticket_pane", entry, "The ticket that will be presented", "");
  try {
    chosenTicket = revive(entry);
  } catch (e) {
    chosenTicket = null;
    status("krb_ap_status", "That stored ticket cannot be read back: " + e.message, "krb-bad");
    panes.disable("krb_present_button", true);
    return;
  }
  // Prefill the host from the SPN's second component, which is where a service's
  // host name lives — while making clear it is a guess, because an SPN's host part
  // and the address a service answers on are not required to agree.
  var parts = entry.service.split("@")[0].split("/");
  if (parts.length > 1 && !val("krb_service_host")) {
    panes.setVal("krb_service_host", parts[1].split(":")[0]);
  }
  if (chosenTicket.endtime <= new Date()) {
    panes.disable("krb_present_button", true);
    status("krb_ap_status",
      "That ticket expired at " + chosenTicket.endtime.toISOString() + ". A service would refuse it " +
      "with KRB_AP_ERR_TKT_EXPIRED. Buy a fresh one on the TGS exchange page.", "krb-bad");
    return;
  }
  panes.disable("krb_present_button", false);
  status("krb_ap_status", "Ready to present a ticket for " + entry.service + ".", null);
}

function selectedGssFlags() {
  var flags = [];
  if (panes.checked("krb_flag_mutual")) flags.push(gss.GSS_FLAG.MUTUAL);
  if (panes.checked("krb_flag_integ")) flags.push(gss.GSS_FLAG.INTEG);
  if (panes.checked("krb_flag_conf")) flags.push(gss.GSS_FLAG.CONF);
  if (panes.checked("krb_flag_replay")) flags.push(gss.GSS_FLAG.REPLAY);
  if (panes.checked("krb_flag_sequence")) flags.push(gss.GSS_FLAG.SEQUENCE);
  return flags;
}

// The 0x8003 structure, decoded field by field. This is the pane the page exists for.
function renderGssChecksum(hostId, checksumBytes) {
  var host = el(hostId);
  if (!host) return;
  panes.clear(host);
  var parsed;
  try {
    parsed = gss.parseGssChecksum(checksumBytes);
  } catch (e) {
    host.appendChild(panes.make("p", "krb-note krb-bad",
      "The 0x8003 checksum does not parse: " + e.message));
    return;
  }
  var pane = panes.make("div", "krb-section");
  pane.appendChild(panes.make("h4", "krb-section-title",
    "The Authenticator's checksum — type 0x8003, which is not a checksum"));
  pane.appendChild(panes.make("p", "krb-section-note",
    "RFC 4121's channel-bindings-and-flags structure. Every integer in it is LITTLE-endian, in a " +
    "protocol where everything else is big-endian, which is why it is the field that most often " +
    "goes wrong — and why a service answers KRB_AP_ERR_INAPP_CKSUM rather than anything that names " +
    "byte order."));
  panes.renderTable(pane, [
    { name: "Lgth", value: String(parsed.bindingsLength),
      note: "always 16, written little-endian as 10 00 00 00. Big-endian it reads as 268435456." },
    { name: "Bnd", value: prim.toHex(parsed.channelBindings),
      note: parsed.hasChannelBindings
        ? "channel bindings are present, so the service can tie this context to a transport"
        : "sixteen ZERO bytes, meaning no channel bindings — absent is not the same as omitted, " +
          "and a token without this field is malformed" },
    { name: "Flags", value: (parsed.flagNames.join(" | ") || "(none)") +
        "  = 0x" + parsed.flags.toString(16),
      note: parsed.flagNames.indexOf("MUTUAL") !== -1
        ? "MUTUAL is set, so the service must prove itself back with an AP-REP"
        : "MUTUAL is NOT set, so the service need not answer at all — and nothing will have " +
          "proved it is who it claims to be" },
    { name: "Deleg", value: parsed.delegation
        ? "option " + parsed.delegation.option + ", " + parsed.delegation.credential.length + " bytes"
        : "(none)",
      note: parsed.delegation ? "a forwarded TGT travels here, as a KRB-CRED" : null }
  ]);
  host.appendChild(pane);
}

async function onPresent() {
  log.debug("Entering onPresent().");
  if (!chosenTicket) {
    status("krb_ap_status", "No usable ticket is selected.", "krb-bad");
    return false;
  }
  var mutual = panes.checked("krb_flag_mutual");
  status("krb_ap_status", "Building an AP-REQ and wrapping it as a GSS token…", "krb-pending");

  var built;
  try {
    built = await client.buildApReq({
      ticket: chosenTicket,
      mutual: mutual,
      gssFlags: selectedGssFlags(),
      subkey: panes.checked("krb_send_subkey") ? undefined : null
    });
  } catch (e) {
    status("krb_ap_status", "The AP-REQ could not be built: " + e.message, "krb-bad");
    return false;
  }

  // The wrapper, then the AP-REQ, then the 0x8003 structure inside it.
  var host = el("krb_request_pane");
  panes.clear(host);
  var wrapperPane = panes.make("div", "krb-section");
  wrapperPane.appendChild(panes.make("h4", "krb-section-title", "The GSS InitialContextToken"));
  wrapperPane.appendChild(panes.make("p", "krb-section-note",
    "What a service is actually handed. A bare AP-REQ is refused by every real service, and the " +
    "refusal names nothing useful — so the wrapper is shown rather than assumed."));
  panes.renderTable(wrapperPane, [
    { name: "outer tag", value: "0x60  ([APPLICATION 0])", note: null },
    { name: "mechanism OID", value: gss.KRB5_MECH_OID + "  (" + prim.toHex(gss.KRB5_MECH_OID_DER) + ")",
      note: "Kerberos v5. SPNEGO's 1.3.6.1.5.5.2 would be a negotiation wrapper around this one, " +
            "and is not implemented here." },
    { name: "token id", value: "01 00  (AP-REQ)", note: null },
    { name: "total size", value: built.token.length + " bytes", note: null }
  ]);
  host.appendChild(wrapperPane);
  await panes.renderMessage("krb_apreq_pane", "The AP-REQ inside it", built.apReq,
    [{ etype: chosenTicket.etype, key: chosenTicket.sessionKey, label: "the ticket's session key" }]);

  // The checksum, read back out of the Authenticator this page just built — read
  // rather than remembered, so the pane shows what is actually on the wire.
  try {
    var profile = kcrypto.etypeById(chosenTicket.etype);
    var apReq = msgs.readApReq(built.apReq);
    var authenticator = msgs.readAuthenticator(await profile.decrypt(
      chosenTicket.sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, apReq.authenticator.cipher));
    if (authenticator.cksum && authenticator.cksum.type === gss.CHECKSUM_TYPE_GSS) {
      renderGssChecksum("krb_checksum_pane", authenticator.cksum.checksum);
    }
  } catch (e) {
    log.warn("could not read back the Authenticator for display: " + e.message);
  }

  status("krb_ap_status", "Presented. Waiting for the service…", "krb-pending");
  var result;
  try {
    result = await panes.sendToService({
      host: val("krb_service_host").trim(),
      port: parseInt(val("krb_service_port"), 10),
      message: built.token
    });
  } catch (e) {
    status("krb_ap_status", e.message, "krb-bad");
    log.debug("Leaving onPresent(). send failed.");
    return false;
  }

  try {
    window.localStorage.setItem(panes.KEYS.SERVICE_HOST, val("krb_service_host"));
    window.localStorage.setItem(panes.KEYS.SERVICE_PORT, val("krb_service_port"));
  } catch (e) {
    // No storage: the fields simply will not be remembered.
  }

  if (!result.reply) {
    // Accepted, with nothing to send back. Not a failure — and the important half is
    // what it means, which is that nothing has proved the service's identity.
    panes.clear(el("krb_reply_pane"));
    el("krb_reply_pane").appendChild(panes.make("p", "krb-note",
      result.note || "The service closed the connection without answering."));
    status("krb_ap_status",
      "The service accepted the connection and sent nothing back. That is legitimate — without " +
      "MUTUAL set it is not obliged to answer — but it means NOTHING has proved the service is who " +
      "it claims to be. Tick mutual authentication to require the proof.",
      mutual ? "krb-bad" : "krb-pending");
    return false;
  }

  await panes.renderMessage("krb_reply_pane", "Received", result.reply,
    [{ etype: chosenTicket.etype, key: chosenTicket.sessionKey, label: "the ticket's session key" }]);

  var outcome;
  try {
    outcome = await client.readApRep({
      reply: result.reply,
      ticket: chosenTicket,
      sentCtime: built.ctime,
      sentCusec: built.cusec
    });
  } catch (e) {
    status("krb_ap_status", "The service's answer could not be read: " + e.message, "krb-bad");
    return false;
  }

  if (outcome.error) {
    var e2 = outcome.error;
    var extra = "";
    if (e2.errorCode === 34) {
      extra = " The service has seen this Authenticator before. Its replay cache is doing its job — " +
        "build a fresh AP-REQ rather than resending one.";
    } else if (e2.errorCode === 44) {
      extra = " The ticket names a key version the service does not hold: its keytab is out of date " +
        "with the account's password.";
    } else if (e2.errorCode === 37) {
      extra = " The clocks disagree by more than the service tolerates — five minutes by default.";
    } else if (e2.errorCode === 50) {
      extra = " The Authenticator's checksum was not the 0x8003 structure a GSS caller must send.";
    }
    status("krb_ap_status", e2.error.name + " — " + e2.error.meaning + extra, "krb-bad");
    log.debug("Leaving onPresent(). refused with " + e2.error.name);
    return false;
  }

  if (!outcome.mutualOk) {
    // The echo did not match. Everything else about the reply may be correct, which
    // is exactly why this has to be checked rather than assumed.
    status("krb_ap_status", "MUTUAL AUTHENTICATION FAILED. " + outcome.reason, "krb-bad");
    return false;
  }

  context = {
    acceptorSubkey: outcome.acceptorSubkey,
    subkey: built.subkey,
    sessionKey: chosenTicket.sessionKey,
    etype: chosenTicket.etype,
    sequenceNumber: 1
  };
  var keying = client.perMessageKey(context);
  panes.renderTable(panes.clear(el("krb_context_pane")) || el("krb_context_pane"), [
    { name: "mutual authentication", value: "CONFIRMED",
      note: "the AP-REP echoed the Authenticator's ctime and cusec under the ticket's session key. " +
            "Only something holding the service's long-term key could have learned that key, so " +
            "the echo is the service's proof of identity." },
    { name: "acceptor subkey", value: outcome.acceptorSubkey
        ? kcrypto.etypeName(outcome.acceptorSubkey.etype) + ", " +
          prim.toHex(outcome.acceptorSubkey.key)
        : "(none offered)",
      note: "A CREDENTIAL, and not persisted." },
    { name: "per-message key", value: keying.which,
      note: "Once an acceptor offers a subkey, Wrap and GetMIC must use IT rather than the ticket's " +
            "session key. Using the wrong one produces a token the far end cannot verify, and the " +
            "error names the checksum rather than the key." },
    { name: "acceptor sequence number", value: String(outcome.sequenceNumber), note: null }
  ]);
  panes.disable("krb_mic_button", false);
  panes.disable("krb_wrap_button", false);
  status("krb_ap_status",
    "The service ACCEPTED the ticket and proved itself. A security context is established, and the " +
    "per-message tokens below are now keyed from " + keying.which + ".", "krb-ok");
  log.debug("Leaving onPresent(). context established.");
  return false;
}

// Per-message tokens over the established context. Both directions are computed
// locally: this page has no protocol partner for them, and the useful thing is
// seeing the token's shape and that verification is keyed by WHO signed it.
async function onPerMessage(seal) {
  log.debug("Entering onPerMessage(). seal=" + seal);
  if (!context) {
    status("krb_ap_status", "No security context: present a ticket with mutual authentication first.",
      "krb-bad");
    return false;
  }
  var message = val("krb_message") || "the quick brown fox";
  var keying = client.perMessageKey(context);
  var host = el("krb_permessage_pane");
  panes.clear(host);
  try {
    if (seal) {
      var wrapped = await gss.wrap({
        key: keying.key, etype: keying.etype, role: "initiator",
        acceptorSubkey: keying.acceptorSubkey,
        message: prim.utf8(message), sequenceNumber: context.sequenceNumber++
      });
      var opened = await gss.unwrap({ key: keying.key, etype: keying.etype, token: wrapped });
      var pane = panes.make("div", "krb-section");
      pane.appendChild(panes.make("h4", "krb-section-title", "GSS_Wrap — integrity and confidentiality"));
      panes.renderTable(pane, [
        { name: "token id", value: "05 04", note: null },
        { name: "token", value: prim.toHex(wrapped), note: wrapped.length + " bytes" },
        { name: "sequence number", value: String(opened.sequenceNumber), note: null },
        { name: "unwrapped", value: new TextDecoder().decode(opened.message),
          note: "The token's own header is appended to the plaintext before encryption and appears " +
                "twice — once in clear at the front, once encrypted at the back. A receiver compares " +
                "them, which is what stops the clear copy being altered." }
      ]);
      host.appendChild(pane);
      status("krb_ap_status", "Wrapped and unwrapped " + message.length + " characters.", "krb-ok");
    } else {
      var mic = await gss.getMic({
        key: keying.key, etype: keying.etype, role: "initiator",
        acceptorSubkey: keying.acceptorSubkey,
        message: prim.utf8(message), sequenceNumber: context.sequenceNumber++
      });
      var verified = await gss.verifyMic({
        key: keying.key, etype: keying.etype, token: mic, message: prim.utf8(message) });
      var tampered = await gss.verifyMic({
        key: keying.key, etype: keying.etype, token: mic,
        message: prim.utf8(message + " (altered)") });
      var micPane = panes.make("div", "krb-section");
      micPane.appendChild(panes.make("h4", "krb-section-title", "GSS_GetMIC — integrity only"));
      panes.renderTable(micPane, [
        { name: "token id", value: "04 04", note: null },
        { name: "token", value: prim.toHex(mic), note: mic.length + " bytes" },
        { name: "verifies", value: verified.ok ? "yes" : "NO", note: null },
        { name: "signed by", value: verified.senderRole,
          note: "The role is IN the token, and the verifier uses the SENDER's key usage — 25 for an " +
                "initiator, 23 for an acceptor. Using its own is the commonest way this fails." },
        { name: "over a modified message", value: tampered.ok ? "STILL VERIFIES — wrong" : "does not verify",
          note: "shown because a MIC that verified anything would be worse than none" }
      ]);
      host.appendChild(micPane);
      status("krb_ap_status", "Computed and verified a MIC over " + message.length + " characters.",
        "krb-ok");
    }
  } catch (e) {
    status("krb_ap_status", "The per-message token failed: " + e.message, "krb-bad");
  }
  log.debug("Leaving onPerMessage().");
  return false;
}

window.onload = async function () {
  log.debug("Entering onload().");
  panes.enforceStoragePreference();
  try {
    var host = window.localStorage.getItem(panes.KEYS.SERVICE_HOST);
    var port = window.localStorage.getItem(panes.KEYS.SERVICE_PORT);
    if (host) panes.setVal("krb_service_host", host);
    if (port) panes.setVal("krb_service_port", port);
  } catch (e) {
    // No storage: the defaults in the markup stand.
  }
  // needsService: this page uses POST /krb5/service, which the api disables by
  // default. Said on arrival rather than when the button is pressed.
  await panes.reportEnvironment("krb_environment_note", {
    needsService: true,
    disableOnNoBackend: ["krb_present_button", "krb_mic_button", "krb_wrap_button"],
    disableOnNoService: ["krb_present_button"]
  });
  renderTicketChoice();
  var select = el("krb_ticket_select");
  if (select) select.addEventListener("change", onTicketChosen);
  var present = el("krb_present_button");
  if (present) present.addEventListener("click", function () { onPresent(); });
  var mic = el("krb_mic_button");
  if (mic) mic.addEventListener("click", function () { onPerMessage(false); });
  var wrap = el("krb_wrap_button");
  if (wrap) wrap.addEventListener("click", function () { onPerMessage(true); });
  log.debug("Leaving onload().");
};

module.exports = {
  onPresent: onPresent,
  onPerMessage: onPerMessage
};
