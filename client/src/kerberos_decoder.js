// File: kerberos_decoder.js
//
// ---------------------------------------------------------------------------
// The Kerberos Decoder page (kerberos_decoder.html).
//
// A renderer, and nothing else. Every fact about Kerberos lives in
// common/krb5/krb5_describe.js, which has no DOM in it and is checked by
// tests/krb5_describe_output.js with no browser; this file turns the document
// that module returns into elements. The split is webauthn.js /
// webauthn_panes.js's, and the payoff is the same: a pane that disagreed with
// the protocol would be a rendering bug rather than a protocol bug.
//
// **NO `innerHTML` ANYWHERE IN THIS FILE.** Everything on this page arrived from
// a paste box or from a host somebody else operates, which makes every string
// here hostile by default — a ticket's realm, a KDC's e-text, a principal name,
// the hex of a cipher. `textContent` cannot be broken out of and needs no
// escaping, which is the only reason this page can be trusted with bytes whose
// author is unknown. `webauthn_panes.js` carries the same rule for the same
// reason, and the two files should stay alike.
//
// **This page ships to the static deployments**, alone among the Kerberos
// workflow. It is arithmetic over pasted bytes: no api, no KDC, no network at
// all, and no secure context needed except for the optional decryption, which
// uses Web Crypto and says so when it cannot. The rest of the workflow needs a
// socket and so cannot exist on idptools.com at all.
//
// **Nothing here is persisted.** The other workflows keep their configuration in
// localStorage; this one deliberately does not, because everything it is given
// is key material or a credential — a password, a keytab, a session key out of a
// decrypted ticket. A scratchpad that remembered them would be a worse place to
// leave a keytab than the file it came from. See the note the page itself makes
// of this.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_decoder",
  level: appconfig.logLevel
});
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var kcrypto = require("./krb5_crypto.js");
var describer = require("./krb5_describe.js");
var keytabReader = require("./krb5_keytab.js");
// The shared DOM half, so this page and the three exchange pages cannot
// disagree about how a message renders. Requiring it is safe on the STATIC
// deployments: it has no side effects at load, and the only thing in it that
// touches the network (reportEnvironment / relayLimits) is never called from
// here — this page talks to nothing.
var panes = require("./kerberos_panes.js");
var ophistory = require("./kerberos_history.js");
// The Ticket Cache & History pane, mounted READ-ONLY here for the same reason
// the Operations History pane is only displayed: this page must write nothing.
// It reads the list the other four pages fill and offers each row's bytes to
// the box above, which is a read of storage and a write to a textarea — see
// persistsNothing() in tests/kerberos_decoder_page.js, which asserts no krb*
// key exists in either store after this page has been used.
var tickets = require("./kerberos_tickets.js");

// The DOM helpers all come from kerberos_panes.js now. They used to be copied
// into this file, and into kerberos.js, which is exactly the duplication that
// module was extracted to remove: a pane that disagreed between two of these
// pages would be a bug visible only by opening both.
var el = panes.el;
var make = panes.make;
var clear = panes.clear;
var status = panes.status;
var renderRow = panes.renderRow;
var renderSection = panes.renderSection;
var renderTree = panes.renderTree;

// ---------------------------------------------------------------------------
// Rendering a document from krb5_describe.
// ---------------------------------------------------------------------------
function renderDocument(doc) {
  log.debug("Entering renderDocument(). kind=" + doc.kind);
  var host = el("krb_output");
  clear(host);

  var head = make("div", "krb-summary");
  head.appendChild(make("span", "krb-kind", doc.kind));
  head.appendChild(make("span", "krb-summary-text", doc.summary));
  host.appendChild(head);

  var inputPane = make("div", "krb-section");
  inputPane.appendChild(make("h4", "krb-section-title", "Input"));
  var inputTable = make("table", "krb-table");
  renderRow(inputTable, {
    name: "read as",
    value: doc.input.encoding,
    note: null
  });
  renderRow(inputTable, {
    name: "framing",
    value: doc.input.framing || "(none)",
    note: doc.input.framing
      ? "Kerberos over TCP prefixes every message with its length. It was " +
          "detected and removed; " +
        "left in place the ASN.1 parse fails on the first byte and blames " +
            "ASN.1."
      : null
  });
  renderRow(inputTable, {
    name: "length",
    value: doc.input.byteLength + " bytes",
    note: null
  });
  renderRow(inputTable, {
    name: "first bytes",
    value: doc.input.hex,
    note: null
  });
  inputPane.appendChild(inputTable);
  host.appendChild(inputPane);

  if (doc.problems && doc.problems.length) {
    var problems = make("div", "krb-problems");
    problems.appendChild(make("h4", "krb-section-title",
      doc.problems.length + " thing" + (doc.problems.length === 1 ? "" : "s") +
          " worth knowing"));
    var ul = make("ul");
    doc.problems.forEach(function (p) { ul.appendChild(make("li", null, p)); });
    problems.appendChild(ul);
    host.appendChild(problems);
  }

  (doc.sections || []).forEach(function (s) { renderSection(host, s, 0); });

  if (doc.tree) {
    var treePane = make("div", "krb-section");
    treePane.appendChild(make("h4", "krb-section-title", "ASN.1 structure"));
    treePane.appendChild(make("p", "krb-section-note",
      "No reader here recognises these bytes, so this is their structure. A " +
          "field under an unexpected " +
      "context tag is visible here and invisible in a decoded view that " +
          "skipped it."));
    renderTree(treePane, doc.tree, 0);
    host.appendChild(treePane);
  }
  log.debug("Leaving renderDocument().");
}

// ---------------------------------------------------------------------------
// Assembling the keys the reader has supplied.
//
// Three routes, because a reader is in one of three situations: they know a
// password (and, critically, the salt — which is not guessable and comes from the
// KDC's own ETYPE-INFO2), they have a raw key in hex, or they have a keytab.
// ---------------------------------------------------------------------------
async function collectKeys() {
  log.debug("Entering collectKeys().");
  var keys = [];
  var notes = [];

  var rawHex = (el("krb_key_hex").value || "").trim();
  if (rawHex) {
    var etype = parseInt(el("krb_key_etype").value, 10);
    try {
      var bytes = prim.fromHex(rawHex.replace(/[\s:]/g, ""));
      var profile = kcrypto.etypeById(etype);
      if (bytes.length !== profile.keyBytes) {
        notes.push("The key given is " + bytes.length + " bytes, but " +
            profile.name +
          " keys are " + profile.keyBytes + " bytes. It was offered anyway.");
      }
      keys.push({
        etype: etype,
        key: bytes,
        label: "the key you pasted (" + profile.name + ")"
      });
    } catch (e) {
      notes.push("The pasted key could not be read: " + e.message);
    }
  }

  var password = el("krb_password").value || "";
  var salt = (el("krb_salt").value || "").trim();
  if (password) {
    if (!salt) {
      notes.push("A password was given with no salt. The salt is NOT " +
          "guessable — take it from the " +
        "KDC's ETYPE-INFO2, which arrives in the KDC_ERR_PREAUTH_REQUIRED " +
            "error. Active Directory " +
        "uses the realm plus the sAMAccountName for a user, but a " +
            "host-shaped string for a computer " +
        "account. Keys were derived with an empty salt, which will almost " +
            "certainly be wrong.");
    }
    try {
      keys = keys.concat(await describer.keysFromPassword(password, salt,
          null));
    } catch (e) {
      notes.push("Could not derive keys from the password: " + e.message);
    }
  }

  var keytabText = (el("krb_keytab").value || "").trim();
  if (keytabText) {
    try {
      var parsedInput = describer.parseInput(keytabText);
      var kt = keytabReader.parseKeytab(parsedInput.bytes);
      var fromKeytab = keytabReader.keysFromKeytab(kt);
      keys = keys.concat(fromKeytab);
      notes.push("Keytab: version 0x" + kt.version.toString(16) + ", " +
          kt.entries.length +
        " entr" + (kt.entries.length === 1 ? "y" : "ies") +
        (kt.deletedSlots ? " and " + kt.deletedSlots + " deleted slot(s)" :
            "") +
        ", " + fromKeytab.length + " usable key(s): " +
        kt.entries.map(function (e) {
          return e.principal + " kvno " + e.kvno + " " + e.etypeName +
                 (e.supported ? "" : " (not performed here)");
        }).join("; "));
    } catch (e) {
      notes.push("Keytab could not be read: " + e.message);
    }
  }

  log.debug("Leaving collectKeys(). keys=" + keys.length);
  return { keys: keys, notes: notes };
}

// ---------------------------------------------------------------------------
// The button.
// ---------------------------------------------------------------------------
async function onDecode() {
  log.debug("Entering onDecode().");
  // NOT recorded in the Operations History. This page shows that log and never
  // adds to it: its one hard guarantee is that NOTHING it is given persists —
  // it is where somebody pastes a captured message together with the long-term
  // key that opens it, and the log lives in localStorage. Recording even "a
  // decode happened" put a `krb_operation_history` key into storage on this
  // page, which is what persistsNothing() in tests/kerberos_decoder_page.js
  // exists to catch, and it caught it. A decode is also the one action here
  // with no far end and no credential of its own to name, so the log loses
  // least by omitting it.
  var host = el("krb_output");
  clear(host);
  status("krb_status", "Decoding…", "krb-pending");

  var input = el("krb_input").value || "";
  var collected;
  try {
    collected = await collectKeys();
  } catch (e) {
    // Key assembly must never stop the decode: the structure is useful without
    // any key at all, and that is the common case.
    log.error("collectKeys failed: " + e.message);
    collected = {
      keys: [],
      notes: ["Keys could not be assembled: " + e.message]
    };
  }

  var doc;
  try {
    doc = await describer.describe(input, { keys: collected.keys });
  } catch (e) {
    log.error("describe failed: " + (e.stack || e.message));
    status("krb_status", e.message, "krb-bad");
    var pane = make("div", "krb-section");
    pane.appendChild(make("h4", "krb-section-title", "Nothing decoded"));
    pane.appendChild(make("p", "krb-section-note", e.message));
    host.appendChild(pane);
    log.debug("Leaving onDecode(). refused.");
    return false;
  }

  renderDocument(doc);

  if (collected.notes.length) {
    var notesPane = make("div", "krb-section");
    notesPane.appendChild(make("h4", "krb-section-title", "About the keys " +
        "you supplied"));
    var ul = make("ul");
    collected.notes.forEach(function (n) { ul.appendChild(make("li", null,
        n)); });
    notesPane.appendChild(ul);
    host.appendChild(notesPane);
  }

  var keyCount = collected.keys.length;
  status("krb_status",
    doc.kind + " decoded. " +
    (keyCount ? keyCount + " key(s) offered for decryption." : "No keys " +
        "supplied, so encrypted parts are " +
      "described but not opened.") +
    (doc.problems.length ? " " + doc.problems.length + " thing(s) worth " +
        "knowing — see below." : ""),
    doc.problems.length ? "krb-bad" : "krb-ok");
  log.debug("Leaving onDecode(). kind=" + doc.kind);
  return false;
}

// ---------------------------------------------------------------------------
// A row of the Ticket Cache & History pane, put in the box above.
//
// The bytes are copied into the input and decoded; nothing is stored, and the
// keys pane is left exactly as it was, because the key that opens a ticket is
// the SERVICE's long-term key and only the reader knows whether they have it.
// The status line says what to expect rather than letting an unopened enc-part
// read as a failed decode.
// ---------------------------------------------------------------------------
function onDecodeStoredTicket(entry) {
  log.debug("Entering onDecodeStoredTicket().");
  var input = el("krb_input");
  if (!input || !entry || !entry.ticket) {
    status("krb_status", "That ticket has no bytes to decode.", "krb-bad");
    log.debug("Leaving onDecodeStoredTicket(). Nothing to decode.");
    return false;
  }
  input.value = entry.ticket;
  // The note goes on the PANE's own status line rather than on krb_status,
  // which onDecode() is about to write to twice — a message posted here would
  // last until the decode finished and then vanish, which reads as a page that
  // changed its mind.
  status(tickets.STATUS_ID, "The ticket for " + (entry.service || "?") +
      " is in the box at the top of the page. It is encrypted under that " +
      "service's own long-term key, so its enc-part opens only if you supply " +
      "that key, or its keytab, in the keys pane.", null);
  onDecode();
  log.debug("Leaving onDecodeStoredTicket().");
  return false;
}

function onClear() {
  log.debug("Entering onClear().");
  ["krb_input", "krb_key_hex", "krb_password", "krb_salt",
      "krb_keytab"].forEach(function (id) {
    var e = el(id);
    if (e) e.value = "";
  });
  clear(el("krb_output"));
  status("krb_status", "Cleared. Nothing from this page is stored anywhere.",
      null);
  log.debug("Leaving onClear().");
  return false;
}

// Web Crypto is what the optional decryption needs, and it is absent on a
// plain-http origin that is not localhost. Say so on arrival rather than
// letting a decryption attempt fail with something that names AES.
function reportCryptoAvailability() {
  log.debug("Entering reportCryptoAvailability().");
  var available = !!(typeof globalThis !== "undefined" && globalThis.crypto &&
      globalThis.crypto.subtle);
  var note = el("krb_crypto_note");
  if (!note) {
    log.debug("Leaving reportCryptoAvailability().");
    return;
  }
  if (available) {
    note.textContent = "";
    log.debug("Leaving reportCryptoAvailability().");
    return;
  }
  note.textContent = "This page is not in a secure context, so Web Crypto is " +
      "unavailable and nothing " +
    "can be decrypted here. Decoding the structure still works — that is " +
        "arithmetic over the bytes. " +
    "Load this page over https (or from localhost) to supply keys.";
  note.className = "krb-note krb-bad";
  log.debug("Leaving reportCryptoAvailability().");
}

window.onload = function () {
  log.debug("Entering onload().");
  // The shared chrome every workflow here has: the step trail marks where we
  // are, and the toggle collapses or expands every pane at once. wirePanes()
  // pairs each legend with its fieldset by id, so a pane added later is
  // clickable without anything being registered for it.
  panes.markCurrentStep("krb_step_decoder");
  panes.wirePanes();
  var toggleAll = el("dbg_toggle_all");
  if (toggleAll) {
    toggleAll.addEventListener("change", function () {
      panes.setAllPanes(toggleAll.checked);
    });
  }
  var decode = el("krb_decode_button");
  if (decode) decode.addEventListener("click", function () { onDecode(); });
  var clearButton = el("krb_clear_button");
  if (clearButton) clearButton.addEventListener("click", onClear);
  reportCryptoAvailability();
  // Read-only: no slot to activate into, no Clear button (this page's own Clear
  // means something else entirely), and nothing written anywhere. Each row
  // offers its ticket to the box above instead, which is what this page is for
  // — a ticket is sealed with the SERVICE's long-term key, so what comes out
  // without a key is the envelope, and supplying that key is the pane above.
  tickets.mount({
    readOnly: true,
    onSelect: function (entry) {
      onDecodeStoredTicket(entry);
    }
  });
  ophistory.mount("krb_operation_history", "krb_clear_operations_button");
  status("krb_status", "Paste a Kerberos message and press Decode.", null);
  log.debug("Leaving onload().");
};

module.exports = {
  onDecode: onDecode,
  onDecodeStoredTicket: onDecodeStoredTicket,
  onClear: onClear
};
