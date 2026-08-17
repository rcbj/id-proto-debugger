// File: kerberos_tickets.js
//
// ---------------------------------------------------------------------------
// The Kerberos workflow's Ticket Cache & History pane, on all five pages.
//
// Sibling of kerberos_history.js, and the same shape: one partial
// (client/public/partials/krb_tickets.html), one mount() per page, one store.
// It was the AS page's pane and lived inside client/src/kerberos.js until
// 2026-08-17; what forced it out here is that every page in this workflow both
// FILLS the list and has something to do with a row in it, so a pane on one
// page was a pane you had to navigate away from to use.
//
// ---------------------------------------------------------------------------
// WHY THE PANE IS ONE AND THE SLOTS ARE MANY.
//
// The list is the workflow's, not a page's: the AS exchange records TGTs, the
// TGS exchange service tickets, the delegation page S4U2Self evidence,
// delegated tickets and renewals. What differs per page is the LIVE SLOT it
// holds — the AS and TGS pages spend a TGT, the AP page presents a service
// ticket, the delegation page needs both a TGT and an evidence ticket, and the
// decoder holds nothing at all. So each page mounts this with the kinds it can
// take back (`slots`), the table decides what a row may do from the ticket's
// own kind, and kerberos_panes.js's TICKET_SLOTS decides where an activated one
// is written. Nothing here chooses a destination from a label a caller passed.
//
// A row this page cannot activate is NAMED rather than left blank, and the
// title says which page can: a control that is simply absent reads as a pane
// that failed to render, and a disabled one with no explanation reads as a bug.
//
// ---------------------------------------------------------------------------
// TWO THINGS THIS MODULE MUST KEEP DOING.
//
// **It builds DOM nodes, never innerHTML.** Every value in a row — the client
// name above all — arrived from a KDC, and the rule across the Kerberos and
// WebAuthn pages is that nothing off the wire reaches innerHTML. A principal
// name is exactly the field an attacker controls.
//
// **On the decoder page it writes NOTHING.** That page's one hard guarantee is
// that nothing it is handed persists, and persistsNothing() in
// tests/kerberos_decoder_page.js asserts no `krb*` key exists in either store
// after using it. Reading the list is fine; so `readOnly: true` drops the Clear
// button and offers each row to the decoder's own input instead, which is a
// read of storage and a write to a textarea.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The level comes from the same configuration the pages read. A node caller
// loading this module directly may have no resolvable CONFIG_FILE, so fall
// back to info rather than failing to load — kerberos_history.js does the same
// and for the same reason.
var log = bunyan.createLogger({
  name: "kerberos_tickets",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var panes = require("./kerberos_panes.js");
var ophistory = require("./kerberos_history.js");

var el = panes.el;
var make = panes.make;
var clear = panes.clear;
var status = panes.status;

// The ids the partial defines. Spelled once here rather than passed in by five
// pages, because they all include the same file and an id a page got wrong
// would render into nothing with nothing reporting it.
var PANE_ID = "krb_ticket_history_pane";
var STATUS_ID = "krb_ticket_status";
var CLEAR_ID = "krb_clear_history_button";
var CAP_ID = "krb_history_cap";

// Where each kind of ticket is USED, for the row this page cannot activate.
// The point is to name the page that can, so the note is a direction rather
// than a refusal.
var USED_BY = {
  TGT: "the AS, TGS and delegation pages, which spend a TGT",
  service: "the AP exchange page, which presents it to a service",
  delegated: "the AP exchange page, which presents it to a service",
  evidence: "S4U2Proxy, on the delegation page"
};

// How this page was mounted. One object rather than five parameters threaded
// through the render, and re-read on every render so a page can change nothing
// and still be correct.
var config = {
  slots: [],
  onActivate: null,
  onSelect: null,
  readOnly: false
};

function canActivate(kind) {
  log.debug("Entering canActivate(). kind=" + kind);
  var yes = !config.readOnly && config.slots.indexOf(kind) !== -1;
  log.debug("Leaving canActivate(). " + yes);
  return yes;
}

// What this page holds, in prose, for the title on a row it cannot take.
function slotsHeld() {
  log.debug("Entering slotsHeld().");
  if (!config.slots.length) {
    log.debug("Leaving slotsHeld(). None.");
    return "no ticket of its own";
  }
  var names = [];
  config.slots.forEach(function (kind) {
    var slot = panes.TICKET_SLOTS[kind];
    var name = slot ? slot.name : kind;
    // Deduplicated, because two KINDS can share one slot: a delegated ticket
    // is a service ticket, so the AP page's two entries are one destination
    // and "the service ticket cache and the service ticket cache" is what
    // naming them separately reads as.
    if (names.indexOf(name) === -1) {
      names.push(name);
    }
  });
  log.debug("Leaving slotsHeld(). " + names.length + " slot(s).");
  return names.join(" and ");
}

// "A TGT" rather than "A TGT ticket", which is what expanding the abbreviation
// gives; every other kind here is an adjective and needs the noun.
function kindPhrase(kind) {
  log.debug("Entering kindPhrase(). kind=" + kind);
  log.debug("Leaving kindPhrase().");
  return kind === "TGT" ? "a TGT" : "a " + kind + " ticket";
}

// ---------------------------------------------------------------------------
// The Expires cell: the absolute time, because that is what the ticket says,
// and a relative one beside it, because "expired" or "in 7h" is the thing being
// looked for and nobody wants to do that subtraction by hand.
// ---------------------------------------------------------------------------
function expiryCell(entry) {
  log.debug("Entering expiryCell().");
  var cell = make("td", "krb-history-when");
  if (!entry.endtime) {
    cell.textContent = "—";
    log.debug("Leaving expiryCell(). None.");
    return cell;
  }
  var when = new Date(entry.endtime);
  var gone = when.getTime() <= Date.now();
  cell.textContent = when.toISOString().replace("T", " ").substring(0, 19) +
      "Z";
  var rel = make("span", gone ? "krb-history-gone" : null,
      "  (" + relativeTime(when) + ")");
  cell.appendChild(rel);
  if (gone) {
    cell.className += " krb-history-gone";
  }
  log.debug("Leaving expiryCell(). gone=" + gone);
  return cell;
}

function relativeTime(when) {
  log.debug("Entering relativeTime().");
  var seconds = Math.round((when.getTime() - Date.now()) / 1000);
  var past = seconds < 0;
  var n = Math.abs(seconds);
  var text;
  if (n < 90) {
    text = n + "s";
  } else if (n < 90 * 60) {
    text = Math.round(n / 60) + "m";
  } else if (n < 48 * 3600) {
    text = Math.round(n / 3600) + "h";
  } else {
    text = Math.round(n / 86400) + "d";
  }
  log.debug("Leaving relativeTime().");
  return past ? "expired " + text + " ago" : "in " + text;
}

// ---------------------------------------------------------------------------
// The last column: what this page can do with this row.
// ---------------------------------------------------------------------------
function actionCell(entry, index, kind, heldIn) {
  log.debug("Entering actionCell(). index=" + index + " kind=" + kind);
  var actions = make("td", "krb-history-act");

  // The decoder: it holds no slot, so every row is offered to its input
  // instead. A ticket is encrypted under the service's key, so this shows the
  // envelope unless a key is supplied — which is the page's whole subject.
  if (config.readOnly && config.onSelect) {
    var decode = make("button", "btn2 krb-history-activate", "Decode");
    decode.setAttribute("type", "button");
    decode.setAttribute("title", "Put this ticket's bytes in the box above. " +
        "Nothing is stored by doing so.");
    decode.addEventListener("click", (function (at) {
      return function () {
        onSelectTicket(at);
        return false;
      };
    })(index));
    actions.appendChild(decode);
    log.debug("Leaving actionCell(). Decode.");
    return actions;
  }

  if (canActivate(kind) && heldIn) {
    actions.appendChild(make("span", "krb-history-held-tag", "in use"));
    log.debug("Leaving actionCell(). In use.");
    return actions;
  }

  if (canActivate(kind)) {
    var button = make("button", "btn2 krb-history-activate", "Make active");
    button.setAttribute("type", "button");
    button.addEventListener("click", (function (at) {
      return function () {
        onActivateTicket(at);
        return false;
      };
    })(index));
    actions.appendChild(button);
    log.debug("Leaving actionCell(). Activatable.");
    return actions;
  }

  // Not for this page. Named, with the page that can use it in the title —
  // offering a button and refusing on click would be worse than not offering,
  // because the button would be the thing that looked wrong.
  var note = make("span", "krb-history-gone",
      heldIn ? "in use" : "not for this page");
  var phrase = kindPhrase(kind);
  note.setAttribute("title", "This page holds " + slotsHeld() + ". " +
      phrase.charAt(0).toUpperCase() + phrase.slice(1) + " is used by " +
      (USED_BY[kind] || "another page in this workflow") + ".");
  actions.appendChild(note);
  log.debug("Leaving actionCell(). Not for this page.");
  return actions;
}

// ---------------------------------------------------------------------------
// The pane. Numbered rows, newest at the top, a scrolling body under a sticky
// header, and a Clear button — debugger2.html's Operation History shape, which
// the Operations History pane below this one also follows.
// ---------------------------------------------------------------------------
function render() {
  log.debug("Entering render().");
  var host = el(PANE_ID);
  if (!host) {
    log.debug("Leaving render(). No host.");
    return;
  }
  clear(host);
  var history = panes.readTicketHistory();
  var clearButton = el(CLEAR_ID);
  if (clearButton) {
    clearButton.disabled = history.length === 0;
  }
  if (!history.length) {
    host.appendChild(make("p", "krb-note", "No tickets yet. Every exchange " +
        "in this workflow that obtains one adds it here, from whichever page " +
        "it happened on."));
    log.debug("Leaving render(). Empty.");
    return;
  }

  // Read once for the whole table rather than once per row.
  var held = panes.heldTickets();
  var scroll = make("div", "krb-history-scroll");
  var table = make("table", "krb-history");
  var head = make("tr");
  ["#", "Client", "Type", "Expires", ""].forEach(function (title, i) {
    var th = make("th", i === 0 ? "krb-history-num" :
        (i === 4 ? "krb-history-act" : null), title);
    head.appendChild(th);
  });
  table.appendChild(head);

  var inUse = 0;
  history.forEach(function (entry, index) {
    var heldIn = entry ? held[entry.ticket] : null;
    if (heldIn) {
      inUse += 1;
    }
    var row = make("tr", heldIn ? "krb-history-held" : null);
    // Numbered newest-first, so row 1 is the newest — the same order the list
    // is in. Operation History numbers by insertion instead, which means its
    // top row is the highest number; here the number IS the position.
    row.appendChild(make("td", "krb-history-num", String(index + 1)));

    var who = make("td", null, entry.client || "—");
    if (heldIn) {
      // The cache half of this pane, said on the row it is about: which of the
      // workflow's slots is holding this ticket right now.
      who.appendChild(make("span", "krb-history-held-tag",
          "  · in " + heldIn));
    }
    row.appendChild(who);

    // THE KIND, derived from the ticket rather than taken from a label. See
    // ticketKind() in kerberos_panes.js: krbtgt always wins, because a
    // mislabelled TGT is the error that would matter.
    var kind = panes.ticketKind(entry);
    var mine = canActivate(kind);
    var type = make("td", "krb-history-kind" +
        (mine || config.readOnly ? "" : " krb-history-gone"), kind);
    row.appendChild(type);
    row.appendChild(expiryCell(entry));
    row.appendChild(actionCell(entry, index, kind, heldIn));
    table.appendChild(row);
  });
  scroll.appendChild(table);
  host.appendChild(scroll);
  log.info("ticket cache & history rendered: " + history.length +
      " entry(ies), " + inUse + " held");
  log.debug("Leaving render().");
}

// The pane repaints where the action happened rather than on the next reload.
function refresh() {
  log.debug("Entering refresh().");
  render();
  log.debug("Leaving refresh().");
}

// ---------------------------------------------------------------------------
// Put a remembered ticket back in the live slot it belongs in.
//
// The kind is checked here as well as in the rendering, because the button is
// only one way in: the list is rebuilt as tickets arrive, so an index captured
// a moment ago can name a different row by the time the click lands.
// ---------------------------------------------------------------------------
function onActivateTicket(index) {
  log.debug("Entering onActivateTicket(). index=" + index);
  var candidate = panes.readTicketHistory()[index];
  if (!candidate) {
    ophistory.note({
      operation: ophistory.OPS.ACTIVATE,
      result: ophistory.FAILURE,
      detail: "Row " + index + " is no longer in the ticket history."
    });
    status(STATUS_ID, "That ticket is no longer in the history.", "krb-bad");
    render();
    log.debug("Leaving onActivateTicket(). Missing.");
    return false;
  }
  var kind = panes.ticketKind(candidate);
  if (!canActivate(kind)) {
    ophistory.note({
      operation: ophistory.OPS.ACTIVATE,
      principal: candidate.client || "",
      result: ophistory.FAILURE,
      detail: "Refused: " + kindPhrase(kind) + " does not go in " +
          slotsHeld() + "."
    });
    status(STATUS_ID, "That is " + kindPhrase(kind) + ". This page holds " +
        slotsHeld() + ", and it is " + (USED_BY[kind] || "another page in " +
        "this workflow") + " that uses one of those.", "krb-bad");
    render();
    log.debug("Leaving onActivateTicket(). Wrong kind.");
    return false;
  }
  var entry = panes.activateTicket(index, kind);
  if (!entry) {
    ophistory.note({
      operation: ophistory.OPS.ACTIVATE,
      result: ophistory.FAILURE,
      detail: "Row " + index + " could not be activated."
    });
    status(STATUS_ID, "That ticket could not be made active.", "krb-bad");
    render();
    log.debug("Leaving onActivateTicket(). Not activated.");
    return false;
  }
  var slot = panes.TICKET_SLOTS[kind];
  // The row that explains the next exchange. An exchange whose behaviour
  // changes for no visible reason is explained by this line above it.
  ophistory.note({
    operation: ophistory.OPS.ACTIVATE,
    principal: entry.client || "",
    detail: kindPhrase(kind) + " issued " + String(entry.storedAt || "?")
        .replace("T", " ").substring(0, 19) + "Z, expiring " + entry.endtime +
        ", put back in " + (slot ? slot.name : "its slot") + "."
  });
  render();
  status(STATUS_ID, "Now using " + kindPhrase(kind) + " for " +
      (entry.client || "?") + " issued " +
      String(entry.storedAt || "?").replace("T", " ").substring(0, 19) + "Z.");
  // The page re-renders whatever it shows about the live slot. Done through a
  // callback rather than here, because this module knows the store and the
  // pages know their own panes.
  if (config.onActivate) {
    config.onActivate(entry, kind);
  }
  log.debug("Leaving onActivateTicket().");
  return false;
}

// The decoder's action: hand a row's bytes to the page, which puts them in its
// input. Nothing is stored, and nothing is recorded in the Operations History —
// that page shows the log and never writes to it.
function onSelectTicket(index) {
  log.debug("Entering onSelectTicket(). index=" + index);
  var entry = panes.readTicketHistory()[index];
  if (!entry) {
    status(STATUS_ID, "That ticket is no longer in the history.", "krb-bad");
    render();
    log.debug("Leaving onSelectTicket(). Missing.");
    return false;
  }
  if (config.onSelect) {
    config.onSelect(entry, panes.ticketKind(entry));
  }
  log.debug("Leaving onSelectTicket().");
  return false;
}

// ---------------------------------------------------------------------------
// Clear. The two panes are deliberately independent: discarding the tickets
// does not clear the Operations History, and the row saying so is the only
// remaining evidence that those tickets were ever held.
//
// The LIVE slots are untouched, which is the other half of that independence: a
// ticket in use is not in this list's gift, and the pages have their own Forget
// buttons for it.
// ---------------------------------------------------------------------------
function onClearHistory() {
  log.debug("Entering onClearHistory().");
  var dropped = panes.readTicketHistory().length;
  panes.forgetTicketHistory();
  render();
  ophistory.note({
    operation: ophistory.OPS.CLEAR_TICKETS,
    detail: dropped + " ticket(s) discarded. Whatever is in use is untouched."
  });
  status(STATUS_ID, "Ticket history cleared. Any ticket in use is untouched.");
  log.debug("Leaving onClearHistory().");
  return false;
}

// ---------------------------------------------------------------------------
// Put the pane on the page: render it, fill in the cap, and wire its buttons.
//
// options:
//   slots      the kinds this page can take back — "TGT", "service",
//              "delegated", "evidence". Anything else in the list is a page
//              claiming a slot it does not have, so it is dropped and named.
//   onActivate called with (entry, kind) after a row was made active, so the
//              page can re-render what it shows about that slot.
//   readOnly   no Clear button and no activation. The decoder, which must
//              write nothing at all.
//   onSelect   readOnly pages only: called with (entry, kind) for the Decode
//              button on each row.
// ---------------------------------------------------------------------------
function mount(options) {
  log.debug("Entering mount().");
  if (typeof document === "undefined") {
    log.debug("Leaving mount(). No document.");
    return;
  }
  var opts = options || {};
  var wanted = opts.slots || [];
  var known = wanted.filter(function (kind) {
    return !!panes.TICKET_SLOTS[kind];
  });
  wanted.filter(function (kind) {
    return !panes.TICKET_SLOTS[kind];
  }).forEach(function (kind) {
    // Not fatal, but never silent: a page asking for a slot that does not
    // exist gets a pane that refuses every row of that kind, and the only
    // symptom would be a Make active button nobody can find.
    log.warn("mounted with slot " + JSON.stringify(kind) +
        ", which is not one of " + Object.keys(panes.TICKET_SLOTS).join(", "));
  });
  config = {
    slots: opts.readOnly ? [] : known,
    onActivate: opts.onActivate || null,
    onSelect: opts.onSelect || null,
    readOnly: !!opts.readOnly
  };

  // The cap is stated in the pane's prose and lives in kerberos_panes.js.
  // Filled in rather than typed into the partial, so the two cannot disagree.
  var cap = el(CAP_ID);
  if (cap) {
    cap.textContent = String(panes.TICKET_HISTORY_LIMIT);
  }

  var clearButton = el(CLEAR_ID);
  if (clearButton && config.readOnly) {
    // Removed rather than disabled: this page's own Clear button means
    // something else entirely, and two of them saying different things is
    // worse than one.
    if (clearButton.parentNode) {
      clearButton.parentNode.removeChild(clearButton);
    }
  } else if (clearButton) {
    clearButton.addEventListener("click", function () {
      onClearHistory();
    });
  }
  render();
  log.info("ticket cache & history mounted; slots=" +
      (config.slots.join(", ") || "(none)") +
      (config.readOnly ? ", read-only" : ""));
  log.debug("Leaving mount().");
}

module.exports = {
  PANE_ID: PANE_ID,
  STATUS_ID: STATUS_ID,
  CLEAR_ID: CLEAR_ID,
  mount: mount,
  refresh: refresh,
  render: render,
  relativeTime: relativeTime,
  onActivateTicket: onActivateTicket,
  onClearHistory: onClearHistory
};
