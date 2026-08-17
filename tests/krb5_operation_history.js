// File: krb5_operation_history.js
//
// ---------------------------------------------------------------------------
// The Kerberos workflow's Operations History pane.
//
// Two halves, and the second is the one that matters.
//
// The BEHAVIOUR half drives client/src/kerberos_history.js directly: a row is
// opened Sent, closed by a status write on the line it named, and closed to the
// right result for each of the five status classes those pages use. That is
// cheap and it is where a mapping mistake shows up — krb-warn read as a failure
// would turn every non-forwardable S4U2Self ticket, which is a SUCCESSFUL
// exchange with a qualified outcome, into a red row.
//
// The WIRING half is the reason this file is long. The design closes a row from
// kerberos_panes.js's status() rather than from each handler's exits, because
// onS4u2Self() alone has five `return false` paths before its request is built
// and a row nobody closes stays "Sent" for ever — which in this pane MEANS "the
// far end never answered". So the load-bearing property is not that settle()
// works. It is:
//
//   for every operation a page opens, that page writes a TERMINAL status to the
//   line the operation named.
//
// Nothing at runtime can check that, and no browser test would catch it either:
// the pane renders, the row is there, and it says Sent — which is a legitimate
// value. So it is checked here, statically, per bundle. Same for the pane being
// mounted: a page that includes the partial and never calls mount() renders an
// empty div and looks exactly like a page with nothing to report.
//
// Node only. No browser, no services, never skipped.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_operation_history",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

const CLIENT_SRC = path.join(__dirname, "..", "client", "src");
const PUBLIC_DIR = path.join(__dirname, "..", "client", "public");

// The six page bundles, and for each one the status lines its operations name.
// Written out rather than derived so that a page losing its wiring fails here
// instead of shrinking the thing being checked to nothing.
const PAGES = [
  {
    bundle: "kerberos.js",
    page: "kerberos.html",
    statusIds: ["krb_as_status"]
  },
  {
    bundle: "kerberos_tgs.js",
    page: "kerberos_tgs.html",
    statusIds: ["krb_tgs_status"]
  },
  {
    bundle: "kerberos_ap.js",
    page: "kerberos_ap.html",
    statusIds: ["krb_ap_status"]
  },
  {
    bundle: "kerberos_delegation.js",
    page: "kerberos_delegation.html",
    statusIds: ["krb_s4u2self_status", "krb_s4u2proxy_status",
      "krb_renew_status", "krb_forward_status"]
  },
  {
    // SPNEGO opens THREE operations against one status line — the
    // unauthenticated probe, the authenticated request, and the mechListMIC
    // continuation — because they are three separate HTTP requests and the
    // first is expected to fail. A 401 with a bare challenge is the protocol
    // working, so folding it into the second would hide the round trip the
    // page exists to show.
    bundle: "spnego.js",
    page: "spnego.html",
    statusIds: ["krb_spnego_status"]
  },
  {
    bundle: "kerberos_decoder.js",
    page: "kerberos_decoder.html",
    // The decoder SHOWS the log and never writes to it, so it opens no rows.
    // Not an oversight and not an exemption from this test: `records: false` is
    // checked in the other direction below, because that page's one hard
    // guarantee is that nothing it is handed persists and this log lives in
    // localStorage. persistsNothing() in tests/kerberos_decoder_page.js caught
    // the first version of this feature breaking exactly that.
    statusIds: [],
    records: false
  }
];

const PARTIAL = "partials/krb_history.html";

// The classes client/src/op_history.js emits when configured with
// classPrefix "krb-op". Listed here because this test is the only thing that
// looks at them without a browser, and because the prefix is deliberately NOT
// "krb": `krb-history` and `krb-table` are already the ticket pane's.
const RENDERED_CLASSES = [
  "krb-op-history-empty",
  "krb-op-history-scroll",
  "krb-op-history",
  "krb-op-table",
  "krb-op-history-time",
  "krb-op-who",
  "krb-op-target"
];

// ---------------------------------------------------------------------------
// A localStorage that works, so the behaviour half is not testing nothing.
//
// op_history.js reaches storage through `window.localStorage` inside a
// try/catch, and in node `window` is undefined — so the ReferenceError is
// caught, read() answers [] for ever, and EVERY assertion below about rows
// would pass against an empty list. That is the shape of bug my own notes call
// out: a test that quietly does nothing and reports OK. So the shim is
// installed first and then PROVEN to work, before anything is asserted about
// what is in it.
// ---------------------------------------------------------------------------
function installStorage() {
  log.debug("Entering installStorage().");
  const store = {};
  const shim = {
    getItem: function (k) {
      return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null;
    },
    setItem: function (k, v) {
      store[k] = String(v);
    },
    removeItem: function (k) {
      delete store[k];
    }
  };
  // BOTH names, because op_history.js reaches storage under both and they are
  // the same object only in a browser: hasStorage() probes
  // `window.localStorage`, while read()/write()/clear() use the bare global.
  // With only the first, hasStorage() answers true and the very next line
  // throws ReferenceError — worse than the shim not working, because the
  // failure names localStorage in a module the test is not about.
  global.window = { localStorage: shim };
  global.localStorage = shim;
  log.debug("Leaving installStorage().");
  return shim;
}

function loadHistory() {
  log.debug("Entering loadHistory().");
  const mod = paths.requireSharedModule(
    [path.join(CLIENT_SRC, "kerberos_history.js"),
      path.join(__dirname, "kerberos_history.js")], "kerberos_history.js");
  log.debug("Leaving loadHistory().");
  return mod;
}

function readBundle(name) {
  log.debug("Entering readBundle(). " + name);
  const file = path.join(CLIENT_SRC, name);
  assert.ok(fs.existsSync(file), name + " is missing from client/src");
  log.debug("Leaving readBundle().");
  return fs.readFileSync(file, "utf8");
}

// Join a line to its continuations before matching, so a call that the
// 80-column rule wrapped is still one string to a regex. Every source-reading
// check in this suite has been broken once by a reformat that changed nothing
// about the property; see the note in tests/CLAUDE.md.
function statements(text) {
  log.debug("Entering statements().");
  const out = [];
  let current = "";
  text.split("\n").forEach(function (line) {
    const trimmed = line.trim();
    if (trimmed.startsWith("//")) {
      return;
    }
    current += (current ? " " : "") + trimmed;
    if (/[;{}]$/.test(trimmed)) {
      out.push(current);
      current = "";
    }
  });
  if (current) {
    out.push(current);
  }
  log.debug("Leaving statements(). " + out.length + " statement(s).");
  return out;
}

// ---------------------------------------------------------------------------
// The shim is real.
// ---------------------------------------------------------------------------
function theStorageShimActuallyStores(history) {
  log.debug("Entering theStorageShimActuallyStores().");
  history.clear();
  assert.strictEqual(history.read().length, 0,
    "the log did not start empty, so clear() is not reaching the shim");
  history.note({ operation: "probe", principal: "nobody" });
  const rows = history.read();
  assert.strictEqual(rows.length, 1,
    "a recorded row did not come back out of storage. Every assertion in " +
    "this file about rows would pass vacuously in that state — window/" +
    "localStorage is not wired up, so op_history.js's hasStorage() is " +
    "answering false and read() is returning [] regardless of what happened.");
  assert.strictEqual(rows[0].operation, "probe",
    "the row came back with the wrong operation: " + rows[0].operation);
  assert.ok(rows[0].timestamp && /^\d{4}-\d\d-\d\dT/.test(rows[0].timestamp),
    "the row carries no ISO timestamp, and the pane's first column is a " +
    "timestamp: got " + rows[0].timestamp);
  history.clear();
  log.info("the storage shim stores, so the assertions below are not vacuous");
  log.debug("Leaving theStorageShimActuallyStores().");
}

// ---------------------------------------------------------------------------
// The five status classes these pages use, mapped to three results.
// ---------------------------------------------------------------------------
function everyStatusClassMapsToTheRightResult(history) {
  log.debug("Entering everyStatusClassMapsToTheRightResult().");
  assert.strictEqual(history.resultFor("krb-bad"), history.FAILURE,
    "krb-bad must be a Failure");
  assert.strictEqual(history.resultFor("krb-ok"), history.SUCCESS,
    "krb-ok must be a Success");
  assert.strictEqual(history.resultFor("krb-good"), history.SUCCESS,
    "krb-good is the delegation page's spelling of krb-ok (kerberos.css says " +
    "so) and must be a Success too — miss it and every S4U2Proxy and every " +
    "forwarded TGT is left as a permanently pending row");
  assert.strictEqual(history.resultFor("krb-warn"), history.SUCCESS,
    "krb-warn must be a Success. The delegation page uses it for an exchange " +
    "that WORKED and produced a ticket with an unwelcome property — an " +
    "S4U2Self ticket that is not forwardable. Reading it as a Failure says " +
    "the KDC refused a request it in fact granted.");
  assert.strictEqual(history.resultFor("krb-pending"), null,
    "krb-pending is not terminal — the row must stay open");
  assert.strictEqual(history.resultFor(null), null,
    "a status with no class is not terminal");
  assert.strictEqual(history.resultFor("krb-note"), null,
    "krb-note is not terminal: the delegation page uses it for a note beside " +
    "a pane, not for an outcome");
  log.info("all five status classes map as intended");
  log.debug("Leaving everyStatusClassMapsToTheRightResult().");
}

// ---------------------------------------------------------------------------
// Open, then close from the status line.
// ---------------------------------------------------------------------------
function aRowIsOpenedSentAndClosedByItsStatusLine(history) {
  log.debug("Entering aRowIsOpenedSentAndClosedByItsStatusLine().");
  history.clear();
  history.begin({
    operation: history.OPS.TGS,
    principal: "alice@EXAMPLE.COM",
    target: "HTTP/web.example.com",
    statusId: "krb_tgs_status"
  });
  let rows = history.read();
  assert.strictEqual(rows.length, 1, "begin() did not record a row");
  assert.strictEqual(rows[0].result, history.SENT,
    "a row must open as Sent, not " + rows[0].result);
  assert.strictEqual(rows[0].operation, history.OPS.TGS,
    "the operation label did not survive");
  assert.strictEqual(rows[0].principal, "alice@EXAMPLE.COM",
    "the principal column is what the request asks for and it did not survive");
  assert.strictEqual(history.openCount(), 1, "the row is not open");

  // A status on a DIFFERENT line must not close it. This is the property that
  // makes the delegation page's four independent operations possible, and
  // getting it wrong would close whichever row happened to be open first.
  assert.strictEqual(history.settle("krb_as_status", "krb-ok", "unrelated"),
    false, "a status on another line closed this row");
  assert.strictEqual(history.read()[0].result, history.SENT,
    "a status on another line changed this row's result");

  // A non-terminal status on the right line must not close it either.
  assert.strictEqual(history.settle("krb_tgs_status", "krb-pending", "waiting"),
    false, "krb-pending closed the row");
  assert.strictEqual(history.read()[0].result, history.SENT,
    "krb-pending changed the row's result");

  assert.strictEqual(history.settle("krb_tgs_status", "krb-ok",
    "A ticket for HTTP/web.example.com was issued."), true,
  "the terminal status did not close the row");
  rows = history.read();
  assert.strictEqual(rows[0].result, history.SUCCESS,
    "the closed row reads " + rows[0].result);
  assert.ok(/issued/.test(rows[0].detail),
    "the status text is what the Result cell explains, and it did not make " +
    "it into the row: " + rows[0].detail);
  assert.strictEqual(history.openCount(), 0,
    "the row is still open after being closed, so the next status on this " +
    "line would close it a second time");
  log.info("a row opens Sent and is closed only by a terminal status on its " +
    "own line");
  log.debug("Leaving aRowIsOpenedSentAndClosedByItsStatusLine().");
}

// ---------------------------------------------------------------------------
// Four operations, four lines, in flight together — the delegation page.
// ---------------------------------------------------------------------------
function operationsOnDifferentLinesSettleIndependently(history) {
  log.debug("Entering operationsOnDifferentLinesSettleIndependently().");
  history.clear();
  const lines = ["krb_s4u2self_status", "krb_s4u2proxy_status",
    "krb_renew_status", "krb_forward_status"];
  lines.forEach(function (id, i) {
    history.begin({
      operation: "op" + i,
      principal: "user" + i,
      statusId: id
    });
  });
  assert.strictEqual(history.openCount(), 4,
    "the delegation page has four status lines and can have four operations " +
    "outstanding; only " + history.openCount() + " are open");

  history.settle("krb_renew_status", "krb-warn", "authtime MOVED");
  const byOp = {};
  history.read().forEach(function (r) { byOp[r.operation] = r; });
  assert.strictEqual(byOp.op2.result, history.SUCCESS,
    "the renewal did not settle");
  ["op0", "op1", "op3"].forEach(function (name) {
    assert.strictEqual(byOp[name].result, history.SENT,
      name + " settled when a different line was written. Four operations " +
      "share this page and closing the wrong one attributes an answer to a " +
      "call that never got it.");
  });
  assert.strictEqual(history.openCount(), 3, "the wrong number are still open");
  log.info("four operations on four lines settle independently");
  log.debug("Leaving operationsOnDifferentLinesSettleIndependently().");
}

// ---------------------------------------------------------------------------
// Two operations on ONE line — the AP page's Present, GetMIC and Wrap.
// ---------------------------------------------------------------------------
function anUnansweredRowIsSupersededRatherThanLost(history) {
  log.debug("Entering anUnansweredRowIsSupersededRatherThanLost().");
  history.clear();
  history.begin({
    operation: history.OPS.AP,
    statusId: "krb_ap_status"
  });
  history.begin({
    operation: history.OPS.MIC,
    statusId: "krb_ap_status"
  });
  const rows = history.read();
  assert.strictEqual(rows.length, 2,
    "the first operation's row was dropped rather than kept");
  const first = rows.filter(function (r) {
    return r.operation === history.OPS.AP;
  })[0];
  assert.ok(first, "the AP-REQ row is gone");
  assert.strictEqual(first.result, history.SENT,
    "the superseded row must stay Sent — Sent already means 'no answer " +
    "reached this debugger', which is exactly true. Marking it a Failure " +
    "claims the service refused a request that may well have been accepted; " +
    "it reads " + first.result);
  assert.ok(/[Ss]uperseded/.test(first.detail),
    "the superseded row says nothing about why it is still open, so it is " +
    "indistinguishable from a service that never answered: " + first.detail);
  assert.strictEqual(history.openCount(), 1,
    "one line cannot have two rows open on it at once");

  history.settle("krb_ap_status", "krb-ok", "Computed and verified a MIC.");
  const after = history.read().filter(function (r) {
    return r.operation === history.OPS.MIC;
  })[0];
  assert.strictEqual(after.result, history.SUCCESS,
    "the second operation did not settle onto its own row");
  log.info("an operation superseded on a shared status line is kept and " +
    "explained");
  log.debug("Leaving anUnansweredRowIsSupersededRatherThanLost().");
}

// ---------------------------------------------------------------------------
// note() is atomic: it can never leave a pending row.
// ---------------------------------------------------------------------------
function noteNeverLeavesARowOpen(history) {
  log.debug("Entering noteNeverLeavesARowOpen().");
  history.clear();
  history.note({
    operation: history.OPS.ACTIVATE,
    principal: "bob@EXAMPLE.COM",
    detail: "TGT issued 2026-08-16 10:00:00Z."
  });
  history.note({
    operation: history.OPS.ACTIVATE,
    result: history.FAILURE,
    detail: "Refused: a service ticket cannot go in this page's slot."
  });
  const rows = history.read();
  assert.strictEqual(rows.length, 2, "note() did not record both rows");
  assert.strictEqual(history.openCount(), 0,
    "note() left a row open. It is used for the local actions — activating " +
    "a stored ticket, discarding one — which are over by the time they are " +
    "recorded, so a pending one of those can never be closed by anything.");
  rows.forEach(function (r) {
    assert.notStrictEqual(r.result, history.SENT,
      "a noted action recorded as Sent, which in this pane means an answer " +
      "is still awaited: " + r.operation);
  });
  const failed = rows.filter(function (r) {
    return r.result === history.FAILURE;
  });
  assert.strictEqual(failed.length, 1,
    "a note() with an explicit Failure was not recorded as one — a refused " +
    "activation must not read as a successful one");
  log.info("note() records a finished action and never leaves it open");
  log.debug("Leaving noteNeverLeavesARowOpen().");
}

// ---------------------------------------------------------------------------
// The detail is bounded.
// ---------------------------------------------------------------------------
function aLongStatusLineDoesNotSetTheRowHeight(history) {
  log.debug("Entering aLongStatusLineDoesNotSetTheRowHeight().");
  history.clear();
  history.begin({ operation: history.OPS.S4U2SELF, statusId: "s" });
  // Real status texts on these pages run to a paragraph — the S4U2Self
  // not-forwardable explanation is over 300 characters — and the Result cell
  // is one column of a table.
  const long = "x".repeat(50) + "\n   " + "y".repeat(500);
  history.settle("s", "krb-warn", long);
  const row = history.read()[0];
  // Against an ABSOLUTE bound, not against history.DETAIL_LIMIT. Comparing the
  // clipped length to the constant that produced it is a tautology — raising
  // the constant to 100,000 leaves that assertion passing, which is how this
  // check was written the first time and what mutation-testing it found.
  const CELL_MAX = 240;
  assert.ok(row.detail.length <= CELL_MAX,
    "the detail is " + row.detail.length + " characters. One table cell " +
    "holding a paragraph sets the height of the row and pushes the Result " +
    "column off the pane; " + CELL_MAX + " is about three lines at this " +
    "font size.");
  assert.ok(row.detail.length < long.length,
    "a " + long.length + "-character status line was stored whole");
  assert.ok(history.DETAIL_LIMIT > 40 && history.DETAIL_LIMIT <= CELL_MAX,
    "DETAIL_LIMIT is " + history.DETAIL_LIMIT + ": below about 40 the detail " +
    "cannot name a KRB-ERROR and its meaning, and above " + CELL_MAX + " it " +
    "is a paragraph in a table cell");
  assert.ok(row.detail.indexOf("\n") === -1,
    "the detail carries a newline, which a table cell renders as a space " +
    "anyway and which makes the stored row harder to read");
  assert.ok(row.detail.startsWith("x"),
    "the detail was cut from the wrong end: the start of a status line is " +
    "the part that names what happened");
  log.info("a long status line is clipped to " + history.DETAIL_LIMIT);
  log.debug("Leaving aLongStatusLineDoesNotSetTheRowHeight().");
}

// ---------------------------------------------------------------------------
// WIRING: status() must close rows, or none of the above matters.
// ---------------------------------------------------------------------------
function panesStatusIsTheThingThatClosesARow() {
  log.debug("Entering panesStatusIsTheThingThatClosesARow().");
  const src = readBundle("kerberos_panes.js");
  assert.ok(/require\("\.\/kerberos_history\.js"\)/.test(src),
    "kerberos_panes.js does not require kerberos_history.js, so nothing " +
    "closes an Operations History row and every operation on every page is " +
    "recorded as Sent for ever");
  const calls = statements(src).filter(function (s) {
    return /\bhistory\.settle\s*\(/.test(s);
  });
  assert.strictEqual(calls.length, 1,
    "expected exactly one history.settle() call in kerberos_panes.js — the " +
    "one inside status() — and found " + calls.length + ". More than one " +
    "means a row can be closed twice; none means no row is ever closed.");
  // It has to be INSIDE status(), which is the function every handler exit
  // already goes through. Read the function's body rather than the file.
  const body = src.slice(src.indexOf("function status(id, text, cls)"));
  const end = body.indexOf("\n}\n");
  assert.ok(end > 0, "could not find the end of status() in kerberos_panes.js");
  assert.ok(/history\.settle\(id, cls, text\)/.test(body.slice(0, end)),
    "status() does not call history.settle(id, cls, text). That call is the " +
    "whole design: it is the one place every handler's every exit path " +
    "already passes through, which is why a row cannot be left open by a " +
    "`return` that forgot to close it.");
  log.info("kerberos_panes.js's status() is what closes a row");
  log.debug("Leaving panesStatusIsTheThingThatClosesARow().");
}

// ---------------------------------------------------------------------------
// WIRING: the property the whole design rests on.
//
// For every status line a page opens an operation against, that page must also
// write a TERMINAL status to it — one that maps to Success and one that maps to
// Failure. A line that only ever gets krb-pending leaves every operation on it
// showing "Sent", which is a legitimate-looking value and so is invisible in a
// browser test.
// ---------------------------------------------------------------------------
function everyOpenedRowHasAWayToBeClosed(history) {
  log.debug("Entering everyOpenedRowHasAWayToBeClosed().");
  const successClasses = ["krb-ok", "krb-good", "krb-warn"];
  PAGES.forEach(function (page) {
    const src = readBundle(page.bundle);
    assert.ok(/require\("\.\/kerberos_history\.js"\)/.test(src),
      page.bundle + " does not require kerberos_history.js, so this page " +
      "cannot even display the Operations History pane it carries");

    if (page.records === false) {
      // The read-only page. Assert it in the direction that matters: no
      // recording call of ANY kind, not merely no status lines to close.
      const writes = statements(src).filter(function (st) {
        return /ophistory\.(begin|note|finish|settle)\s*\(/.test(st);
      });
      assert.deepStrictEqual(writes, [],
        page.bundle + " calls " + writes.join(" | ") + ". That page must not " +
        "write to this log at all: it is where a captured message is pasted " +
        "together with the long-term key that opens it, its stated guarantee " +
        "is that nothing it is handed persists, and this log is in " +
        "localStorage. Even recording that a decode happened puts a " +
        "krb_operation_history key there — which is what persistsNothing() " +
        "in tests/kerberos_decoder_page.js fails on, and it is a browser " +
        "test, " +
        "so it costs a full run to find out.");
      // It must still SHOW the log, or the pane on that page is a dead box.
      assert.ok(/ophistory\.mount\(/.test(src),
        page.bundle + " neither records nor mounts, so its pane is empty " +
        "markup. Read-only means read-only, not absent.");
      log.info(page.bundle + " is read-only, and provably so");
      return;
    }

    // Which status ids does this bundle open an operation against? Read them
    // out of the source rather than trusting the list above — then check the
    // two agree, so a page that stops opening rows fails here instead of
    // shrinking this check to nothing.
    const opened = [];
    statements(src).forEach(function (s) {
      const m = /statusId:\s*"([a-z0-9_]+)"/.exec(s);
      if (m && opened.indexOf(m[1]) === -1) {
        opened.push(m[1]);
      }
    });
    assert.deepStrictEqual(opened.slice().sort(), page.statusIds.slice().sort(),
      page.bundle + " opens operations against [" + opened.join(", ") +
      "] but this test expects [" + page.statusIds.join(", ") + "]. If a " +
      "status line was added or removed, update the PAGES table above — an " +
      "operation on a line nobody listed is one nothing here checks.");

    page.statusIds.forEach(function (id) {
      const writes = statements(src).filter(function (s) {
        return s.indexOf('status("' + id + '"') !== -1;
      });
      assert.ok(writes.length > 0,
        page.bundle + " opens operations against " + id + " and never writes " +
        "a status to it, so every one of them stays Sent for ever");
      const joined = writes.join(" ");
      assert.ok(/"krb-bad"/.test(joined),
        page.bundle + " never writes a krb-bad status to " + id + ", so no " +
        "operation on that line can ever be recorded as a Failure — and " +
        "these handlers' guard clauses are all failures");
      assert.ok(successClasses.some(function (c) {
        return joined.indexOf('"' + c + '"') !== -1;
      }), page.bundle + " never writes a terminal SUCCESS status (" +
        successClasses.join(" / ") + ") to " + id + ", so a call that " +
        "worked is left showing Sent — which in this pane reads as a far end " +
        "that never answered");
    });
  });
  log.info("every status line an operation is opened against has both a " +
    "success and a failure path");
  log.debug("Leaving everyOpenedRowHasAWayToBeClosed().");
}

// ---------------------------------------------------------------------------
// WIRING: the pane is on every page, and every page mounts it.
// ---------------------------------------------------------------------------
function allFivePagesShowThePaneAndWireIt() {
  log.debug("Entering allFivePagesShowThePaneAndWireIt().");
  const partial = fs.readFileSync(path.join(PUBLIC_DIR, PARTIAL), "utf8");
  // The two ids the partial defines and every bundle must mount against.
  const paneId = /id="([a-z0-9_]*operation_history)"/.exec(partial);
  const clearId = /id="([a-z0-9_]*clear_operations_button)"/.exec(partial);
  assert.ok(paneId, PARTIAL + " defines no pane container id");
  assert.ok(clearId, PARTIAL + " defines no Clear button id");
  log.info("the partial's ids are " + paneId[1] + " / " + clearId[1]);

  PAGES.forEach(function (page) {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, page.page), "utf8");
    assert.ok(html.indexOf('file="/' + PARTIAL + '"') !== -1,
      page.page + " does not include " + PARTIAL + ". The log is one list " +
      "across the whole workflow, and a page that does not show it is a page " +
      "where the chain of exchanges is invisible.");
    // The pane must not also be spelled out in the page: that is the drift the
    // partial exists to prevent.
    assert.ok(html.indexOf('id="' + paneId[1] + '"') === -1,
      page.page + " carries its own copy of the pane markup as well as the " +
      "include, so there are two elements with id " + paneId[1] + " and only " +
      "one of them will ever be filled");

    const src = readBundle(page.bundle);
    const mounts = statements(src).filter(function (s) {
      return /ophistory\.mount\(/.test(s);
    });
    assert.strictEqual(mounts.length, 1,
      page.bundle + " calls mount() " + mounts.length + " times; expected " +
      "exactly one. Without it the page shows an empty div — which looks " +
      "exactly like a workflow that has done nothing.");
    assert.ok(mounts[0].indexOf('"' + paneId[1] + '"') !== -1,
      page.bundle + " mounts against an id that is not the partial's " +
      paneId[1] + ": " + mounts[0] + ". The render then goes nowhere and the " +
      "pane stays empty, with nothing anywhere reporting a problem.");
    assert.ok(mounts[0].indexOf('"' + clearId[1] + '"') !== -1,
      page.bundle + " does not wire the partial's Clear button (" +
      clearId[1] + "): " + mounts[0]);
  });
  log.info("all five pages include the pane and mount it against the " +
    "partial's own ids");
  log.debug("Leaving allFivePagesShowThePaneAndWireIt().");
}

// ---------------------------------------------------------------------------
// WIRING: every operation label is actually used by a page.
// ---------------------------------------------------------------------------
function everyOperationLabelIsRecordedSomewhere(history) {
  log.debug("Entering everyOperationLabelIsRecordedSomewhere().");
  // The five page bundles AND the shared modules they mount. The
  // credential-store labels (ACTIVATE, CLEAR_TICKETS) moved out of
  // kerberos.js when the Ticket Cache & History pane went on all five pages,
  // and they are recorded by that module rather than by any one page — reading
  // only the bundles would report them as dead labels.
  const sources = PAGES.map(function (p) {
    return readBundle(p.bundle);
  }).concat([readBundle("kerberos_tickets.js")]).join("\n");
  const names = Object.keys(history.OPS);
  assert.ok(names.length >= 15,
    "only " + names.length + " operations are named; the workflow has the " +
    "two AS forms, the TGS exchange, the AP exchange, two per-message " +
    "tokens, four delegation exchanges and the credential-store actions. " +
    "There is deliberately no decode label — see the note in OPS.");
  const unused = names.filter(function (name) {
    return sources.indexOf("OPS." + name) === -1;
  });
  assert.deepStrictEqual(unused, [],
    "these operation labels are defined and never recorded by any page: " +
    unused.join(", ") + ". Either the wiring for that action was lost — in " +
    "which case the action happens and no row appears — or the label is " +
    "dead and should go.");
  log.info("all " + names.length + " operation labels are recorded by a page");
  log.debug("Leaving everyOperationLabelIsRecordedSomewhere().");
}

// ---------------------------------------------------------------------------
// WIRING: the classes op_history renders are defined in the sheet these pages
// load.
//
// The reason this needs saying: op_history.js's defaults are `saml-*`, and
// these five pages do not link css/saml_common.css. Taking the defaults would
// give an unstyled pane and would fail checkStylesheetsLoaded() in
// tests/navigation.js — but only on a browser run, and only for whichever page
// that test happens to open.
// ---------------------------------------------------------------------------
function theRenderedClassesAreStyledByKerberosCss() {
  log.debug("Entering theRenderedClassesAreStyledByKerberosCss().");
  const css = fs.readFileSync(path.join(PUBLIC_DIR, "css", "kerberos.css"),
    "utf8");
  const history = readBundle("kerberos_history.js");
  assert.ok(/classPrefix:\s*"krb-op"/.test(history),
    "kerberos_history.js does not set classPrefix, so op_history.js renders " +
    "its saml-* defaults into pages that never load css/saml_common.css");
  assert.ok(/"krb-history"|classPrefix:\s*"krb"\s*,/.test(history) === false,
    "the prefix must not be plain \"krb\": op_history renders " +
    "<prefix>-history and <prefix>-table, and both of those names are " +
    "already the Ticket Cache & History table's on the same page");

  const missing = RENDERED_CLASSES.filter(function (name) {
    return css.indexOf("." + name) === -1;
  });
  assert.deepStrictEqual(missing, [],
    "op_history.js renders these classes with classPrefix krb-op and " +
    "kerberos.css defines none of them: " + missing.join(", "));

  // The result colours are the page's own, deliberately, so they cannot say
  // something different from the status line above them.
  assert.ok(/resultClasses:\s*\{/.test(history),
    "kerberos_history.js does not configure resultClasses, so the Result " +
    "cell gets saml-ok / saml-bad / saml-pending — undefined on these pages");
  ["krb-ok", "krb-bad", "krb-pending"].forEach(function (name) {
    assert.ok(history.indexOf(name) !== -1,
      "the Result cell does not use the page's own ." + name);
    assert.ok(css.indexOf("." + name) !== -1,
      "kerberos.css does not define ." + name);
  });
  log.info("every class the pane renders is defined in css/kerberos.css");
  log.debug("Leaving theRenderedClassesAreStyledByKerberosCss().");
}

// ---------------------------------------------------------------------------
// WIRING: the two panes' storage rules are different, on purpose.
//
// The ticket pane holds session keys, so unticking the credential-cache
// box purges it. This pane holds no key material, and purging an audit log
// because somebody stopped saving keys would remove the record exactly when it
// is most wanted. A future sweep over enforceStoragePreference() would add it
// without that being visible anywhere, so it is asserted with the reason.
// ---------------------------------------------------------------------------
function theOperationsLogIsNotPurgedWithTheCredentialCache(history) {
  log.debug("Entering theOperationsLogIsNotPurgedWithTheCredentialCache().");
  const panesSrc = readBundle("kerberos_panes.js");
  const fn = panesSrc.slice(panesSrc.indexOf(
    "function enforceStoragePreference()"));
  const body = fn.slice(0, fn.indexOf("\n}\n"));
  assert.ok(body.length > 0 && body.length < panesSrc.length,
    "could not isolate enforceStoragePreference() in kerberos_panes.js");
  assert.ok(body.indexOf("TICKET_HISTORY") !== -1,
    "enforceStoragePreference() no longer purges the ticket history, which " +
    "DOES hold a session key per row");
  assert.strictEqual(body.indexOf(history.STORE_KEY), -1,
    "enforceStoragePreference() purges " + history.STORE_KEY + " — the " +
    "Operations History. That log holds no key material (operation names, " +
    "principals, targets, statuses), and the credential-cache checkbox is " +
    "about key material. Purging the record of what was attempted because " +
    "somebody stopped storing session keys removes it exactly when it is " +
    "most useful. If the intent really has changed, say so here.");
  log.info(history.STORE_KEY + " is not purged with the credential cache");
  log.debug("Leaving theOperationsLogIsNotPurgedWithTheCredentialCache().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Kerberos Operations History pane.");
  try {
    installStorage();
    const history = loadHistory();

    theStorageShimActuallyStores(history);
    everyStatusClassMapsToTheRightResult(history);
    aRowIsOpenedSentAndClosedByItsStatusLine(history);
    operationsOnDifferentLinesSettleIndependently(history);
    anUnansweredRowIsSupersededRatherThanLost(history);
    noteNeverLeavesARowOpen(history);
    aLongStatusLineDoesNotSetTheRowHeight(history);

    panesStatusIsTheThingThatClosesARow();
    everyOpenedRowHasAWayToBeClosed(history);
    allFivePagesShowThePaneAndWireIt();
    everyOperationLabelIsRecordedSomewhere(history);
    theRenderedClassesAreStyledByKerberosCss();
    theOperationsLogIsNotPurgedWithTheCredentialCache(history);

    history.clear();
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_operation_history")
  .description("The Kerberos workflow's Operations History pane.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
