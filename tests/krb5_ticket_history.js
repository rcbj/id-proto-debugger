// File: krb5_ticket_history.js
//
// ---------------------------------------------------------------------------
// The workflow's Ticket Cache & History pane: its storage layer, and the
// wiring that puts it on all five pages.
//
// The pane itself is markup and needs a browser; what it STORES does not, and
// what it stores is the part that can hurt. Each row keeps a ticket and its
// session key so that "Make active" can put an earlier ticket back in use — a
// hundred credentials where the page used to hold one. That is a deliberate
// trade (see the comment above recordTicket in client/src/kerberos_panes.js),
// and it is only defensible while three things hold:
//
//   1. the list obeys krb_save_ccache like the single ticket does, so it is in
//      sessionStorage unless the box is ticked;
//   2. UNTICKING THE BOX PURGES IT. An opt-out that leaves a hundred session
//      keys in localStorage is not an opt-out, and this is the assertion that
//      would catch it — enforceStoragePreference() names each key explicitly,
//      so a new key is exactly the kind of thing that gets forgotten there;
//   3. the cap holds, and trims the OLDEST rather than emptying the list the
//      way oauth2_oidc_2.js's Operation History does.
//
// Node only: the module is driven against a fake window.localStorage /
// sessionStorage, which is all it touches. No browser, no services, never
// skipped.
// ---------------------------------------------------------------------------
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_ticket_history",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// A browser, to the extent this module needs one.
//
// Installed BEFORE the module is required, because kerberos_panes.js reads
// window at load. The DOM stub answers "nothing found" to everything: the
// storage functions under test never touch it, and a stub returning plausible
// elements would let a DOM bug through as a pass.
// ---------------------------------------------------------------------------
function fakeStore() {
  log.debug("Entering fakeStore().");
  const m = {};
  log.debug("Leaving fakeStore().");
  return {
    getItem: function (k) { return (k in m) ? m[k] : null; },
    setItem: function (k, v) { m[k] = String(v); },
    removeItem: function (k) { delete m[k]; },
    keys: function () { return Object.keys(m); }
  };
}

global.window = { localStorage: fakeStore(), sessionStorage: fakeStore() };
global.document = {
  getElementById: function () { return null; },
  querySelector: function () { return null; },
  querySelectorAll: function () { return []; },
  createElement: function () {
    return {
      style: {},
      setAttribute: function () {},
      appendChild: function () {},
      addEventListener: function () {}
    };
  }
};

// ---------------------------------------------------------------------------
// Loading the module, which needs the tests-image layout rather than a
// checkout's.
//
// kerberos_panes.js does require("./krb5_primitives.js"), and in a checkout
// that file is in common/krb5/ rather than beside it — client/build.js STAGES
// the codec into client/src before browserify runs and removes it afterwards,
// so the sibling only exists mid-build. A relative require does not consult
// NODE_PATH, so module_paths.js cannot help here the way it does elsewhere.
//
// So: assemble the flat layout the tests image already has, in a temp
// directory, and load from there. Nothing in the repository is written to,
// which matters because a test that staged files into client/src would leave
// them behind on any failure — and a stale krb5_*.js in client/src is
// something the next build would silently bundle.
// ---------------------------------------------------------------------------
function loadPanesFromFlatLayout() {
  log.debug("Entering loadPanesFromFlatLayout().");
  const flatInImage = path.join(__dirname, "kerberos_panes.js");
  if (fs.existsSync(flatInImage) &&
      fs.existsSync(path.join(__dirname, "krb5_primitives.js"))) {
    // Already flat: this is the tests image.
    log.debug("Leaving loadPanesFromFlatLayout(). Image layout.");
    return require(flatInImage);
  }
  const src = path.join(__dirname, "..", "client", "src",
      "kerberos_panes.js");
  const codec = path.join(__dirname, "..", "common", "krb5");
  assert.ok(fs.existsSync(src), "no client/src/kerberos_panes.js and no flat " +
      "copy beside this test — the checkout is incomplete.");
  assert.ok(fs.existsSync(codec), "no common/krb5 to stage.");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "krb5-hist-"));
  fs.readdirSync(codec).filter(function (f) {
    return f.endsWith(".js");
  }).forEach(function (f) {
    fs.copyFileSync(path.join(codec, f), path.join(dir, f));
  });
  fs.copyFileSync(src, path.join(dir, "kerberos_panes.js"));
  // kerberos_panes.js also requires ./kerberos_history.js (its status() closes
  // an Operations History row), and that requires ./op_history.js. Both are
  // client/src siblings rather than codec modules, so the loop above does not
  // bring them and the failure is a MODULE_NOT_FOUND naming a file this test is
  // not about. Copied by name rather than by globbing client/src: a whole
  // directory staged into a temp dir would hide the next such require instead
  // of failing on it here.
  ["kerberos_history.js", "op_history.js"].forEach(function (name) {
    const from = path.join(__dirname, "..", "client", "src", name);
    assert.ok(fs.existsSync(from),
      "client/src/" + name + " is missing; kerberos_panes.js requires it " +
      "(directly or through kerberos_history.js) and cannot load without it.");
    fs.copyFileSync(from, path.join(dir, name));
  });
  paths.addTestsModulesToResolutionPath();

  // CONFIG_FILE has to be ABSOLUTE while the staged copy loads. The module does
  // require(process.env.CONFIG_FILE) for its log level, and a relative value —
  // "./env/test.js", which is what the launchers pass — resolves against the
  // REQUIRING file's directory, which is now a temp directory with no env/ in
  // it. An absolute path resolves the same from anywhere. Restored immediately,
  // because everything else in this process expects the caller's value.
  const previous = process.env.CONFIG_FILE;
  if (previous && /^\.{1,2}\//.test(previous)) {
    process.env.CONFIG_FILE = path.resolve(__dirname, previous);
  }
  try {
    log.debug("Leaving loadPanesFromFlatLayout(). Staged in " + dir + ".");
    return require(path.join(dir, "kerberos_panes.js"));
  } finally {
    if (previous === undefined) {
      delete process.env.CONFIG_FILE;
    } else {
      process.env.CONFIG_FILE = previous;
    }
  }
}
const panes = loadPanesFromFlatLayout();

const HISTORY_KEY = "krb_ticket_history";
const SAVE_KEY = "krb_save_ccache";

function ticket(who, hoursFromNow, n, service) {
  log.debug("Entering ticket().");
  log.debug("Leaving ticket().");
  return {
    realm: "EXAMPLE.COM",
    client: who + "@EXAMPLE.COM",
    service: service || "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
    ticket: "TICKET-BYTES-" + n,
    sessionKey: "aabbcc" + n,
    sessionKeyEtype: 18,
    flags: ["forwardable", "renewable"],
    authtime: new Date().toISOString(),
    endtime: new Date(Date.now() + hoursFromNow * 3600e3).toISOString(),
    renewTill: null,
    storedAt: new Date().toISOString()
  };
}

function reset() {
  log.debug("Entering reset().");
  global.window.localStorage = fakeStore();
  global.window.sessionStorage = fakeStore();
  log.debug("Leaving reset().");
}

// ---------------------------------------------------------------------------
function itRecordsNewestFirstAndKeepsTheCredential() {
  log.debug("Entering itRecordsNewestFirstAndKeepsTheCredential().");
  reset();
  panes.recordTicket(ticket("alice", 8, 1));
  panes.recordTicket(ticket("bob", -2, 2));
  const history = panes.readTicketHistory();
  assert.strictEqual(history.length, 2, "both tickets should be recorded");
  assert.strictEqual(history[0].client, "bob@EXAMPLE.COM",
    "newest first, as the Operation History pane orders it; got " +
    history[0].client);
  // The whole point of the reversal from a metadata-only log: without these two
  // fields "Make active" has nothing to activate.
  assert.ok(history[0].ticket, "a row must keep the ticket bytes");
  assert.ok(history[0].sessionKey, "a row must keep the session key");
  log.info("records newest-first and keeps the credential");
  log.debug("Leaving itRecordsNewestFirstAndKeepsTheCredential().");
}

function itTrimsTheOldestAtTheCap() {
  log.debug("Entering itTrimsTheOldestAtTheCap().");
  reset();
  const limit = panes.TICKET_HISTORY_LIMIT;
  for (let i = 1; i <= limit + 5; i++) {
    panes.recordTicket(ticket("u" + i, 5, i));
  }
  const history = panes.readTicketHistory();
  assert.strictEqual(history.length, limit,
    "the list should stop at " + limit + "; it has " + history.length);
  assert.strictEqual(history[0].client, "u" + (limit + 5) + "@EXAMPLE.COM",
    "the newest must survive the trim");
  assert.strictEqual(history[history.length - 1].client, "u6@EXAMPLE.COM",
    "the OLDEST should be dropped, leaving u6 as the tail. Operation History " +
    "empties itself at the cap instead, which loses everything at the moment " +
    "there is most to look at; this must not copy that.");
  log.info("caps at " + limit + " and trims the oldest");
  log.debug("Leaving itTrimsTheOldestAtTheCap().");
}

function itCanPutAnEarlierTicketBackInUse() {
  log.debug("Entering itCanPutAnEarlierTicketBackInUse().");
  reset();
  for (let i = 1; i <= 5; i++) { panes.recordTicket(ticket("u" + i, 5, i)); }
  assert.strictEqual(panes.activeTicketIndex(), -1,
    "nothing is active until one is chosen");

  const chosen = panes.activateTicket(3);
  assert.ok(chosen, "row 4 should exist");
  const live = panes.readTgt();
  assert.ok(live, "activating must write the live ticket slot");
  assert.strictEqual(live.ticket, chosen.ticket,
    "the live ticket must be the row's ticket, byte for byte — activation " +
    "re-uses what was issued rather than re-deriving anything");
  assert.strictEqual(live.sessionKey, chosen.sessionKey,
    "and its session key, or the ticket cannot be used");
  assert.strictEqual(panes.activeTicketIndex(), 3,
    "the pane finds the active row by ticket bytes, not by a remembered index");

  // An index nobody has is not a crash.
  assert.strictEqual(panes.activateTicket(99), null,
    "activating a row that is not there returns null rather than throwing");
  log.info("an earlier ticket can be made active again");
  log.debug("Leaving itCanPutAnEarlierTicketBackInUse().");
}

function itFollowsTheStoragePreference() {
  log.debug("Entering itFollowsTheStoragePreference().");
  reset();
  // Default: no preference recorded means sessionStorage.
  panes.recordTicket(ticket("alice", 8, 1));
  assert.ok(global.window.sessionStorage.getItem(HISTORY_KEY),
    "by default the history belongs in sessionStorage");
  assert.strictEqual(global.window.localStorage.getItem(HISTORY_KEY), null,
    "and must not also be in localStorage");

  // Opted in.
  reset();
  global.window.localStorage.setItem(SAVE_KEY, "1");
  panes.recordTicket(ticket("alice", 8, 1));
  assert.ok(global.window.localStorage.getItem(HISTORY_KEY),
    "with the box ticked it goes to localStorage");
  assert.strictEqual(global.window.sessionStorage.getItem(HISTORY_KEY), null,
    "and the other store must not keep a stale copy");
  log.info("follows krb_save_ccache in both directions");
  log.debug("Leaving itFollowsTheStoragePreference().");
}

// The assertion this file exists for.
function untickingThePurgeTakesTheWholeList() {
  log.debug("Entering untickingThePurgeTakesTheWholeList().");
  reset();
  global.window.localStorage.setItem(SAVE_KEY, "1");
  for (let i = 1; i <= 20; i++) { panes.recordTicket(ticket("u" + i, 5, i)); }
  panes.saveTgt(ticket("live", 5, 0));
  assert.ok(global.window.localStorage.getItem(HISTORY_KEY),
    "precondition: twenty tickets are in localStorage");

  global.window.localStorage.setItem(SAVE_KEY, "0");
  panes.enforceStoragePreference();

  assert.strictEqual(global.window.localStorage.getItem(HISTORY_KEY), null,
    "UNTICKING LEFT THE HISTORY IN localStorage. Every row holds a session " +
    "key, so this is twenty credentials surviving an opt-out — the exact " +
    "thing the checkbox promises not to do. enforceStoragePreference() names " +
    "each key it purges, so a key added later is forgotten there by default.");
  assert.strictEqual(global.window.localStorage.getItem("krb_ccache"), null,
    "and the live ticket, which was already covered");
  log.info("unticking purges the whole list, not just the live ticket");
  log.debug("Leaving untickingThePurgeTakesTheWholeList().");
}

function clearingEmptiesItEverywhere() {
  log.debug("Entering clearingEmptiesItEverywhere().");
  reset();
  panes.recordTicket(ticket("alice", 8, 1));
  panes.forgetTicketHistory();
  assert.deepStrictEqual(panes.readTicketHistory(), [],
    "Clear should empty the list");
  assert.strictEqual(global.window.sessionStorage.getItem(HISTORY_KEY), null,
    "and remove it from sessionStorage");
  assert.strictEqual(global.window.localStorage.getItem(HISTORY_KEY), null,
    "and from localStorage, wherever it happened to be");
  log.info("Clear empties both stores");
  log.debug("Leaving clearingEmptiesItEverywhere().");
}

function rubbishInTheKeyIsNotACrash() {
  log.debug("Entering rubbishInTheKeyIsNotACrash().");
  reset();
  global.window.sessionStorage.setItem(HISTORY_KEY, '{"not":"a list"}');
  assert.deepStrictEqual(panes.readTicketHistory(), [],
    "a non-list under this key should read as empty rather than throw on " +
    "every render");
  log.info("a non-list under the key reads as empty");
  log.debug("Leaving rubbishInTheKeyIsNotACrash().");
}


// ---------------------------------------------------------------------------
// The history spans the whole workflow, so it holds more than one kind of
// ticket — and page 1 may only activate one of them.
// ---------------------------------------------------------------------------
function itTellsTheKindsApart() {
  log.debug("Entering itTellsTheKindsApart().");
  const tgt = ticket("alice", 8, 1);
  const svc = ticket("alice", 8, 2, "HTTP/web.example.com@EXAMPLE.COM");
  const evidence = ticket("alice", 8, 3,
      "HTTP/frontend.example.com@EXAMPLE.COM");

  assert.strictEqual(panes.ticketKind(tgt), "TGT",
    "a ticket whose service is krbtgt IS a TGT, by the protocol's own " +
    "definition");
  assert.strictEqual(panes.ticketKind(svc), "service",
    "anything else is a service ticket unless labelled");
  evidence.kind = "evidence";
  assert.strictEqual(panes.ticketKind(evidence), "evidence",
    "an S4U2Self ticket is a service ticket to the requester ITSELF, so only " +
    "the label can distinguish it");

  // The derivation must beat the label, which is the case that matters: a
  // mislabelled TGT would let page 1 refuse the one ticket it can use, and a
  // mislabelled service ticket would let it accept one it cannot.
  const mislabelled = ticket("alice", 8, 4);
  mislabelled.kind = "service";
  assert.strictEqual(panes.ticketKind(mislabelled), "TGT",
    "krbtgt must win over a wrong label; got " +
    panes.ticketKind(mislabelled));
  log.info("kinds are derived from the service, and the derivation wins");
  log.debug("Leaving itTellsTheKindsApart().");
}

function everyPagesTicketsLandInOneList() {
  log.debug("Entering everyPagesTicketsLandInOneList().");
  reset();
  // As the four store sites do it, in the order a workflow reaches them.
  panes.recordTicket(ticket("alice", 8, 1), "TGT");
  panes.recordTicket(ticket("alice", 8, 2,
      "HTTP/web.example.com@EXAMPLE.COM"), "service");
  panes.recordTicket(ticket("alice", 8, 3,
      "HTTP/frontend.example.com@EXAMPLE.COM"), "evidence");
  panes.recordTicket(ticket("alice", 8, 4,
      "HTTP/backend.example.com@EXAMPLE.COM"), "delegated");
  const history = panes.readTicketHistory();
  assert.strictEqual(history.length, 4,
    "all four pages' tickets belong in the one list; got " + history.length);
  const kinds = history.map(panes.ticketKind);
  assert.deepStrictEqual(kinds,
    ["delegated", "evidence", "service", "TGT"],
    "newest first, each keeping its kind; got " + kinds.join(", "));
  assert.strictEqual(kinds.filter(function (k) { return k === "TGT"; }).length,
    1, "exactly one of these is activatable on page 1");
  log.info("all four kinds land in one list, newest first");
  log.debug("Leaving everyPagesTicketsLandInOneList().");
}

function theSameTicketDoesNotPileUp() {
  log.debug("Entering theSameTicketDoesNotPileUp().");
  reset();
  const one = ticket("alice", 8, 1);
  panes.recordTicket(one, "TGT");
  panes.recordTicket(one, "TGT");
  panes.recordTicket(one, "TGT");
  assert.strictEqual(panes.readTicketHistory().length, 1,
    "the same ticket recorded three times is one row — every page records, " +
    "so re-activating and renewing would otherwise fill the list with copies");
  log.info("re-recording the same ticket does not duplicate it");
  log.debug("Leaving theSameTicketDoesNotPileUp().");
}

// ---------------------------------------------------------------------------
// A ticket goes back into the slot its KIND names, never one a caller chose.
//
// The pane is on all five pages now, and they hold different slots — a TGT on
// the AS, TGS and delegation pages, the service ticket cache on the AP page, an
// evidence ticket on the delegation page. So activation had to learn where to
// write, and the one thing that must not happen is a service ticket landing in
// the TGT slot: it is accepted there, and the failure arrives a page later as
// an encryption-type or integrity error that names nothing about tickets.
// ---------------------------------------------------------------------------
function eachKindGoesBackIntoItsOwnSlot() {
  log.debug("Entering eachKindGoesBackIntoItsOwnSlot().");
  reset();
  panes.recordTicket(ticket("alice", 8, 1), "TGT");
  panes.recordTicket(ticket("alice", 8, 2,
    "HTTP/web.example.com@EXAMPLE.COM"), "service");
  const evidence = ticket("alice", 8, 3,
    "HTTP/frontend.example.com@EXAMPLE.COM");
  evidence.kind = "evidence";
  panes.recordTicket(evidence, "evidence");
  // Newest first: 0 evidence, 1 service, 2 TGT.

  panes.activateTicket(2);
  assert.strictEqual((panes.readTgt() || {}).ticket, "TICKET-BYTES-1",
    "a TGT must go into the TGT slot");
  assert.strictEqual(panes.readServiceTickets().length, 0,
    "and nowhere else");

  panes.activateTicket(1);
  assert.deepStrictEqual(panes.readServiceTickets().map(function (t) {
    return t.ticket;
  }), ["TICKET-BYTES-2"],
  "a service ticket must go into the service ticket cache, which is the " +
  "list the AP page's dropdown is built from");
  assert.strictEqual((panes.readTgt() || {}).ticket, "TICKET-BYTES-1",
    "AND MUST NOT LAND IN THE TGT SLOT. A service ticket there is accepted " +
    "and fails a page later, with an error that names an encryption type " +
    "rather than a ticket.");

  panes.activateTicket(0);
  assert.strictEqual((panes.readEvidence() || {}).ticket, "TICKET-BYTES-3",
    "an S4U2Self evidence ticket must go into the evidence slot");

  // The `kind` argument is a CHECK, not an instruction: a caller that thinks
  // row 1 is a TGT gets null and nothing is written, rather than a service
  // ticket in the TGT slot.
  panes.forgetTgt();
  assert.strictEqual(panes.activateTicket(1, "TGT"), null,
    "activating row 1 AS a TGT must refuse: it is a service ticket, and the " +
    "kind is derived from the ticket rather than taken from the caller");
  assert.strictEqual(panes.readTgt(), null,
    "and nothing may have been written");
  log.info("each kind goes back into its own slot, and a wrong kind refuses");
  log.debug("Leaving eachKindGoesBackIntoItsOwnSlot().");
}

// What is held right now, which is the "Cache" half of the pane's title.
function itSaysWhichTicketsAreHeldAndWhere() {
  log.debug("Entering itSaysWhichTicketsAreHeldAndWhere().");
  reset();
  const tgt = ticket("alice", 8, 1);
  const svc = ticket("alice", 8, 2, "HTTP/web.example.com@EXAMPLE.COM");
  const ev = ticket("alice", 8, 3, "HTTP/frontend.example.com@EXAMPLE.COM");
  [tgt, svc, ev].forEach(function (t) { panes.recordTicket(t); });
  assert.deepStrictEqual(panes.heldTickets(), {},
    "nothing is held until something is activated");

  panes.saveTgt(tgt);
  panes.saveServiceTicket(svc);
  panes.saveEvidence(ev);
  const held = panes.heldTickets();
  assert.deepStrictEqual(Object.keys(held).sort(),
    ["TICKET-BYTES-1", "TICKET-BYTES-2", "TICKET-BYTES-3"],
    "all three live slots must be reported, keyed by the ticket bytes — " +
    "which are what make two tickets the same ticket");
  assert.strictEqual(held["TICKET-BYTES-1"], panes.TICKET_SLOTS.TGT.name,
    "and each must name the slot holding it, since that is what the row says");
  assert.strictEqual(held["TICKET-BYTES-3"], panes.TICKET_SLOTS.evidence.name,
    "including the evidence slot, which only the delegation page fills");
  log.info("heldTickets() names all three live slots");
  log.debug("Leaving itSaysWhichTicketsAreHeldAndWhere().");
}

// ---------------------------------------------------------------------------
// WIRING: the pane is on every page, and every page mounts it.
//
// The same shape as allFivePagesShowThePaneAndWireIt() in
// tests/krb5_operation_history.js, and for the same reason: a page that
// includes the partial and never mounts it shows an empty div, which looks
// exactly like a workflow that has obtained no tickets. Nothing at runtime can
// tell those apart, so it is checked here, statically, per bundle.
// ---------------------------------------------------------------------------
const CLIENT_SRC = path.join(__dirname, "..", "client", "src");
const PUBLIC_DIR = path.join(__dirname, "..", "client", "public");
const PARTIAL = "partials/krb_tickets.html";

// Which slots each page may take a ticket back into. Written out rather than
// read off the bundles, because the point is that the AP page cannot activate
// a TGT and the AS page cannot activate a service ticket — a list derived from
// what the code does would agree with the code by construction.
const PAGES = [
  { bundle: "kerberos.js", page: "kerberos.html", slots: ["TGT"] },
  { bundle: "kerberos_tgs.js", page: "kerberos_tgs.html", slots: ["TGT"] },
  {
    bundle: "kerberos_ap.js",
    page: "kerberos_ap.html",
    slots: ["service", "delegated"]
  },
  {
    bundle: "kerberos_delegation.js",
    page: "kerberos_delegation.html",
    slots: ["TGT", "evidence"]
  },
  {
    // SPNEGO spends a service ticket exactly as the AP page does — the only
    // difference between the two is the transport — so it takes back the same
    // kinds, a delegated one included.
    bundle: "spnego.js",
    page: "spnego.html",
    slots: ["service", "delegated"]
  },
  // The decoder holds no slot at all and must write NOTHING — see
  // persistsNothing() in tests/kerberos_decoder_page.js.
  {
    bundle: "kerberos_decoder.js",
    page: "kerberos_decoder.html",
    slots: [],
    readOnly: true
  }
];

function readClientFile(where, name) {
  log.debug("Entering readClientFile(). " + name);
  const file = path.join(where, name);
  assert.ok(fs.existsSync(file), name + " is missing from " + where +
    ". This check reads the pages and their bundles as TEXT; in the tests " +
    "image they arrive through the client/public and client/src COPY lines " +
    "in tests/Dockerfile.");
  log.debug("Leaving readClientFile().");
  return fs.readFileSync(file, "utf8");
}

// Every `tickets.mount(...)` call in a bundle, whitespace collapsed, so a call
// the 80-column rule wrapped is still one string to match against. Every
// source-reading check in this suite has been broken once by a reformat that
// changed nothing about the property; see the note in tests/CLAUDE.md.
function mountCalls(source) {
  log.debug("Entering mountCalls().");
  const calls = [];
  const NEEDLE = "tickets.mount(";
  let at = source.indexOf(NEEDLE);
  while (at !== -1) {
    let depth = 0;
    let i = at + NEEDLE.length - 1;
    for (; i < source.length; i++) {
      if (source[i] === "(") {
        depth += 1;
      } else if (source[i] === ")") {
        depth -= 1;
        if (depth === 0) {
          i += 1;
          break;
        }
      }
    }
    calls.push(source.slice(at, i).replace(/\s+/g, " "));
    at = source.indexOf(NEEDLE, i);
  }
  log.debug("Leaving mountCalls(). " + calls.length + " call(s).");
  return calls;
}

function allFivePagesShowThePaneAndWireIt() {
  log.debug("Entering allFivePagesShowThePaneAndWireIt().");
  const partial = readClientFile(PUBLIC_DIR, PARTIAL);
  const module_ = readClientFile(CLIENT_SRC, "kerberos_tickets.js");

  // The ids are spelled in the module and defined in the partial, and neither
  // is checkable against the other at runtime: a render into an id nothing
  // defines is an empty pane with nothing anywhere complaining.
  const ids = {};
  ["PANE_ID", "STATUS_ID", "CLEAR_ID"].forEach(function (name) {
    const found = new RegExp("var\\s+" + name +
      "\\s*=\\s*\"([a-z0-9_]+)\"").exec(module_);
    assert.ok(found, "kerberos_tickets.js no longer defines " + name);
    ids[name] = found[1];
    assert.ok(partial.indexOf('id="' + found[1] + '"') !== -1,
      PARTIAL + " defines no element with id " + found[1] + ", which " +
      "kerberos_tickets.js's " + name + " names. The pane renders into " +
      "nothing and no page reports a problem.");
  });
  log.info("the partial's ids are " + ids.PANE_ID + " / " + ids.STATUS_ID +
    " / " + ids.CLEAR_ID);

  PAGES.forEach(function (page) {
    const html = readClientFile(PUBLIC_DIR, page.page);
    assert.ok(html.indexOf('file="/' + PARTIAL + '"') !== -1,
      page.page + " does not include " + PARTIAL + ". The list is one store " +
      "across the whole workflow, and a page that does not show it is a page " +
      "where the tickets it just obtained are invisible.");
    // The pane must not ALSO be spelled out in the page: that is the drift the
    // partial exists to prevent, and kerberos.html carried this markup inline
    // until the pane went on all five pages.
    assert.ok(html.indexOf('id="' + ids.PANE_ID + '"') === -1,
      page.page + " carries its own copy of the pane markup as well as the " +
      "include, so there are two elements with id " + ids.PANE_ID + " and " +
      "only one of them will ever be filled");

    const source = readClientFile(CLIENT_SRC, page.bundle);
    const calls = mountCalls(source);
    assert.strictEqual(calls.length, 1,
      page.bundle + " calls tickets.mount() " + calls.length + " times; " +
      "expected exactly one. Without it the page shows an empty pane — which " +
      "looks exactly like a workflow that has obtained no tickets.");
    const call = calls[0];

    page.slots.forEach(function (slot) {
      assert.ok(call.indexOf('"' + slot + '"') !== -1,
        page.bundle + " does not mount the " + slot + " slot: " + call +
        ". That is a ticket this page can hold and offers no way back to.");
    });
    Object.keys(panes.TICKET_SLOTS).forEach(function (slot) {
      if (page.slots.indexOf(slot) !== -1) {
        return;
      }
      assert.ok(call.indexOf('"' + slot + '"') === -1,
        page.bundle + " mounts the " + slot + " slot, which this page does " +
        "not hold: " + call + ". Activating into a slot the page never reads " +
        "moves a credential somewhere nothing will look for it.");
    });
    if (page.readOnly) {
      assert.ok(/readOnly:\s*true/.test(call),
        page.bundle + " does not mount the pane read-only: " + call +
        ". That page's one hard guarantee is that nothing it is handed " +
        "persists, and an activation writes a ticket and its session key to " +
        "storage — which persistsNothing() in tests/kerberos_decoder_page.js " +
        "asserts can never happen there.");
    } else {
      assert.ok(/readOnly:\s*true/.test(call) === false,
        page.bundle + " mounts the pane read-only, so none of its rows can " +
        "be put back in use: " + call);
    }
  });
  log.info("all five pages include the pane, mount it once, and mount only " +
    "the slots they hold");
  log.debug("Leaving allFivePagesShowThePaneAndWireIt().");
}

// The pane's own module must not be the thing that empties the log below it,
// and the two panes' storage rules stay opposite — see the matching check in
// tests/krb5_operation_history.js, which asserts it from the other side.
function theTwoPanesStayIndependent() {
  log.debug("Entering theTwoPanesStayIndependent().");
  const module_ = readClientFile(CLIENT_SRC, "kerberos_tickets.js");
  assert.ok(module_.indexOf("ophistory.clear(") === -1,
    "kerberos_tickets.js clears the Operations History. Discarding the " +
    "tickets must leave the record of what was attempted: that row is the " +
    "only remaining evidence those tickets were ever held.");
  assert.ok(module_.indexOf("OPS.CLEAR_TICKETS") !== -1,
    "clearing the ticket history is no longer recorded in the Operations " +
    "History, so a hundred credentials can leave with no trace of it");
  log.info("the two panes stay independent");
  log.debug("Leaving theTwoPanesStayIndependent().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The workflow's Ticket Cache & History store.");
  try {
    itRecordsNewestFirstAndKeepsTheCredential();
    itTellsTheKindsApart();
    everyPagesTicketsLandInOneList();
    theSameTicketDoesNotPileUp();
    itTrimsTheOldestAtTheCap();
    itCanPutAnEarlierTicketBackInUse();
    eachKindGoesBackIntoItsOwnSlot();
    itSaysWhichTicketsAreHeldAndWhere();
    itFollowsTheStoragePreference();
    untickingThePurgeTakesTheWholeList();
    clearingEmptiesItEverywhere();
    rubbishInTheKeyIsNotACrash();
    allFivePagesShowThePaneAndWireIt();
    theTwoPanesStayIndependent();
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_ticket_history")
  .description("The Kerberos workflow's ticket cache & history: the " +
      "store, the slots, and the wiring on all five pages.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
