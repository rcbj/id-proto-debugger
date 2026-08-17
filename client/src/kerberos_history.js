// File: kerberos_history.js
//
// ---------------------------------------------------------------------------
// The Kerberos workflow's Operations History: one cumulative log of every
// action the debugger takes, across all five pages.
//
// Fourth sibling over op_history.js, after saml_history.js, wstrust_history.js
// and wsfed_history.js. Same three results, same cap, same localStorage.
//
// WHY THE LOG IS ONE AND THE PAGES ARE FIVE. A Kerberos exchange is a chain —
// the AS page's TGT is what the TGS page spends, and the ticket the TGS page
// gets is what the AP page presents — so the question a log has to answer here
// is almost never "what did this page do". It is "what happened, in order,
// across the whole run": which principal, against which KDC, and did the far
// end answer. That is one list, shown identically on every page, which is why
// the markup is a partial (client/public/partials/krb_history.html) rather than
// five copies to drift apart.
//
// ---------------------------------------------------------------------------
// HOW AN ENTRY IS CLOSED, AND WHY IT IS NOT CLOSED BY THE CALLER.
//
// The obvious design is record() at the top of a handler and update() on the
// way out. It does not survive contact with these handlers: onS4u2Self() alone
// has five `return false` paths before the request is even built, and every
// one of them would have to remember to close the row. A row nobody closes
// stays "Sent" for ever — and in this pane "Sent" MEANS "the far end never
// answered", so a forgotten update does not read as a missing log line, it
// reads as a broken KDC. wsfed_history.js has the same hazard from the other
// direction, and its note explains what a mis-spelled label costs there.
//
// So the close is driven from the one place every one of those exits already
// goes through: kerberos_panes.js's status(), which writes the page's status
// line. Every handler sets a status on every exit — it has to, or the page is
// left saying "Sending…" — so settle() cannot be jumped over the way an
// update() call can. The status id is the key: begin() is told which line will
// report this operation, and only a status on THAT line closes it. The
// delegation page has four operations with four status lines and can have more
// than one in flight, which is why this is a map rather than one slot.
//
// The mapping from the status class to a result is the page's own vocabulary:
//
//   krb-bad              Failure
//   krb-ok / krb-good    Success
//   krb-warn             Success — it answered, and the warning is the detail.
//                        The delegation page uses krb-warn for a ticket that
//                        was issued but is not forwardable: the call worked and
//                        the outcome is qualified, so recording it as a failure
//                        would be wrong in the direction that matters.
//   krb-pending / null   still open, still "Sent"
//
// An unrecognised class leaves the row open rather than guessing.
// ---------------------------------------------------------------------------
var createHistory = require("./op_history.js").createHistory;

// The log level comes from the same configuration the pages read. A node
// caller (tests/krb5_operation_history.js loads this module directly) may have
// no resolvable CONFIG_FILE, so fall back to info rather than failing to load.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// The operations, spelled once.
//
// Exported for the same reason wsfed_history.js exports its two: a label typed
// out at the recording site and again at a reading site is a pair that drifts,
// and the test asserts against these rather than against strings of its own.
// The wire names are used where there is one (AS-REQ, TGS-REQ) because that is
// what a capture beside this pane will show.
// ---------------------------------------------------------------------------
var OPS = {
  AS_NO_PREAUTH: "AS-REQ (no pre-authentication)",
  AS_PREAUTH: "AS-REQ (PA-ENC-TIMESTAMP)",
  TGS: "TGS-REQ (service ticket)",
  AP: "AP-REQ (presented to a service)",
  // The two halves of a SPNEGO handshake, logged separately because they are
  // separate HTTP requests and the first one is expected to FAIL: a 401 with a
  // bare challenge is the protocol working, so recording it as one operation
  // with the second would hide the round trip that the whole workflow is
  // about.
  SPNEGO_PROBE: "GET (unauthenticated, expecting a challenge)",
  SPNEGO_AUTH: "GET (Authorization: Negotiate)",
  SPNEGO_MIC: "GET (Negotiate, the mechListMIC continuation)",
  MIC: "GSS_GetMIC",
  WRAP: "GSS_Wrap",
  S4U2SELF: "S4U2Self (TGS-REQ, PA-FOR-USER)",
  S4U2PROXY: "S4U2Proxy (TGS-REQ, cname-in-addl-tkt)",
  RENEW: "TGS-REQ (RENEW)",
  FORWARD: "TGS-REQ (forwarded TGT)",
  // There is deliberately no DECODE. The decoder page DISPLAYS this log and
  // never writes to it: its one hard guarantee is that nothing it is handed
  // persists, and this log is in localStorage — see the note in
  // kerberos_decoder.js and persistsNothing() in
  // tests/kerberos_decoder_page.js, which is what caught it.
  ACTIVATE: "Make a stored ticket active",
  FORGET_TGT: "Discard the TGT",
  FORGET_TICKETS: "Discard the service tickets",
  FORGET_EVIDENCE: "Discard the evidence ticket",
  CLEAR_TICKETS: "Clear the ticket history"
};

// A status line is prose and can run to a paragraph; the Result cell is one
// column of a table. Long detail is cut rather than allowed to set the row
// height, and the full text is on the page's own status line anyway.
var DETAIL_LIMIT = 160;

var history = createHistory({
  storeKey: "krb_operation_history",
  emptyText: "No Kerberos operations recorded yet.",
  // Not the saml-* defaults: these pages do not link css/saml_common.css, and
  // checkStylesheetsLoaded() in tests/navigation.js fails a page that uses a
  // class from a stylesheet it never loaded. The result colours reuse the
  // status line's own, which already mean exactly these three things.
  classPrefix: "krb-op",
  resultClasses: { ok: "krb-ok", bad: "krb-bad", pending: "krb-pending" },
  columns: [
    { key: "operation", label: "Call made" },
    { key: "principal", label: "User / principal", className: "krb-op-who" },
    { key: "target", label: "Target", className: "krb-op-target" }
  ]
});

// statusId -> the id of the row that line will close. Per page load: a
// navigation ends every operation this page could still be waiting on, and a
// row left open across one is genuinely unresolved.
var open = {};

// Where the pane is, so a record can repaint it. Set by mount(); a page that
// records without mounting (none today) simply logs with nothing to show.
var hostId = null;

function clip(text) {
  log.debug("Entering clip().");
  var s = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
  if (s.length <= DETAIL_LIMIT) {
    log.debug("Leaving clip().");
    return s;
  }
  log.debug("Leaving clip(). Truncated.");
  return s.substring(0, DETAIL_LIMIT - 1) + "…";
}

// The pane repaints where the action happened rather than on the next reload —
// a log that lags the thing it is logging is one nobody trusts.
function refresh() {
  log.debug("Entering refresh().");
  if (!hostId || typeof document === "undefined") {
    log.debug("Leaving refresh(). No host.");
    return;
  }
  history.render(document.getElementById(hostId));
  log.debug("Leaving refresh().");
}

// ---------------------------------------------------------------------------
// Open a row for an operation that is about to be attempted.
//
// Called at the TOP of a handler, before its own guards run, so that clicking
// S4U2Proxy with no evidence ticket is recorded as the Failure it is. The
// principal and target are read as the fields have them, unparsed: what the
// user typed is what they will be looking for in this list, and a name that
// did not parse is precisely the row worth having.
// ---------------------------------------------------------------------------
function begin(entry) {
  log.debug("Entering begin().");
  entry = entry || {};
  // A status line can report more than one operation: the AP page's Present,
  // GetMIC and Wrap all write to krb_ap_status. If one is still open when the
  // next starts, this line is no longer watching it, so it stays Sent — which
  // is what Sent means — and says why rather than being left to look like a KDC
  // that never answered. Deliberately NOT recorded as a Failure: the earlier
  // call may well have succeeded, and nothing here knows.
  if (entry.statusId && open[entry.statusId]) {
    history.update(open[entry.statusId], history.SENT,
        "Superseded on this status line by " + (entry.operation || "another " +
        "operation") + " before an answer was recorded.");
    delete open[entry.statusId];
  }
  var id = history.record({
    operation: entry.operation || "(unnamed)",
    principal: entry.principal || "",
    target: entry.target || "",
    result: history.SENT,
    detail: entry.detail || ""
  });
  if (entry.statusId) {
    open[entry.statusId] = id;
  }
  refresh();
  log.info("kerberos operation started: " + (entry.operation || "(unnamed)") +
      " principal=" + (entry.principal || "-"));
  log.debug("Leaving begin().");
  return id;
}

// ---------------------------------------------------------------------------
// Close whatever the given status line is reporting on.
//
// Called from kerberos_panes.js's status() for EVERY status write on every
// page, so it must be cheap and it must do nothing at all when there is no
// operation open on that line — which is the common case, since most status
// writes are a page describing itself on load.
// ---------------------------------------------------------------------------
function settle(statusId, cls, text) {
  log.debug("Entering settle().");
  var id = statusId ? open[statusId] : null;
  if (!id) {
    log.debug("Leaving settle(). Nothing open on " + statusId + ".");
    return false;
  }
  var result = resultFor(cls);
  if (!result) {
    log.debug("Leaving settle(). " + cls + " is not terminal.");
    return false;
  }
  history.update(id, result, clip(text));
  delete open[statusId];
  refresh();
  log.info("kerberos operation on " + statusId + " settled as " + result);
  log.debug("Leaving settle().");
  return true;
}

// The page's status classes, mapped to the log's three results. Unknown and
// pending classes return null, which leaves the row open.
function resultFor(cls) {
  log.debug("Entering resultFor().");
  if (cls === "krb-bad") {
    log.debug("Leaving resultFor(). Failure.");
    return history.FAILURE;
  }
  if (cls === "krb-ok" || cls === "krb-good" || cls === "krb-warn") {
    log.debug("Leaving resultFor(). Success.");
    return history.SUCCESS;
  }
  log.debug("Leaving resultFor(). Not terminal.");
  return null;
}

// ---------------------------------------------------------------------------
// Close a row explicitly, for the cases the status line cannot say enough
// about.
//
// The AS page's first step is the one that needs this: the KDC answering
// KRB-ERROR 25 KDC_ERR_PREAUTH_REQUIRED is the EXPECTED outcome and the status
// line says so in prose, but the log wants the error's own name, because that
// is what a capture beside it will show.
// ---------------------------------------------------------------------------
function finish(statusId, result, detail) {
  log.debug("Entering finish().");
  var id = statusId ? open[statusId] : null;
  if (!id) {
    log.debug("Leaving finish(). Nothing open on " + statusId + ".");
    return false;
  }
  history.update(id, result, clip(detail));
  delete open[statusId];
  refresh();
  log.debug("Leaving finish().");
  return true;
}

// ---------------------------------------------------------------------------
// Record something that is over by the time it is recorded.
//
// The actions that touch the credential store rather than the network —
// activating a stored ticket, discarding one, clearing the ticket history. They
// have no pending phase and no far end, and they matter here for one reason: a
// TGS-REQ that suddenly starts working is explained by the row above it saying
// a different ticket was made active.
// ---------------------------------------------------------------------------
function note(entry) {
  log.debug("Entering note().");
  entry = entry || {};
  history.record({
    operation: entry.operation || "(unnamed)",
    principal: entry.principal || "",
    // These actions have no far end — they move a ticket between this page's
    // slots — so the Target column says where they happened rather than being
    // left blank. An empty cell in a column every other row fills reads as a
    // value that failed to arrive.
    target: entry.target || "this browser",
    result: entry.result || history.SUCCESS,
    detail: clip(entry.detail)
  });
  refresh();
  log.info("kerberos action recorded: " + (entry.operation || "(unnamed)"));
  log.debug("Leaving note().");
}

// ---------------------------------------------------------------------------
// Put the pane on the page: render it, and wire its Clear button.
//
// Every one of the five pages calls this with the same two ids, because they
// all include the same partial.
// ---------------------------------------------------------------------------
function mount(paneId, clearButtonId) {
  log.debug("Entering mount().");
  if (typeof document === "undefined") {
    log.debug("Leaving mount(). No document.");
    return;
  }
  hostId = paneId;
  refresh();
  var button = document.getElementById(clearButtonId);
  if (button) {
    button.addEventListener("click", function () {
      clear();
    });
  }
  log.debug("Leaving mount().");
}

// ---------------------------------------------------------------------------
// Empty the log, and forget which rows were open.
//
// Both halves, because a row id that no longer exists is a row settle() will
// try to close and cannot. Nothing is lost by dropping them: an operation still
// in flight when the log is cleared has had the row its answer would have
// landed on deleted, so that answer goes unrecorded either way. What forgetting
// them buys is that the next operation on the same status line does not report
// itself as having superseded a row that is not there.
// ---------------------------------------------------------------------------
function clear() {
  log.debug("Entering clear().");
  history.clear();
  open = {};
  refresh();
  log.debug("Leaving clear().");
}

// For the test: how many rows are open, and on which lines. Nothing on a page
// reads this.
function openCount() {
  log.debug("Entering openCount().");
  log.debug("Leaving openCount().");
  return Object.keys(open).length;
}

module.exports = {
  OPS: OPS,
  SENT: history.SENT,
  SUCCESS: history.SUCCESS,
  FAILURE: history.FAILURE,
  STORE_KEY: history.STORE_KEY,
  DETAIL_LIMIT: DETAIL_LIMIT,
  begin: begin,
  settle: settle,
  finish: finish,
  note: note,
  mount: mount,
  refresh: refresh,
  resultFor: resultFor,
  openCount: openCount,
  read: history.read,
  clear: clear,
  render: history.render
};
