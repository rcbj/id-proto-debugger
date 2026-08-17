// File: kerberos_panes.js
//
// ---------------------------------------------------------------------------
// The DOM half of the Kerberos workflow, shared by all four of its pages.
//
// The protocol knowledge is in common/krb5 (no DOM, node-testable). This is the
// other half: the elements. It exists because the workflow has four pages —
// the decoder, the AS exchange, the TGS exchange and the AP exchange — and they
// render the same things. A message pane that disagreed between two of them would
// be a bug visible only by opening both, which is exactly the trap
// webauthn_panes.js was extracted to avoid.
//
// **NO `innerHTML` ANYWHERE.** Every value these pages show came from a KDC or a
// service somebody else operates: a realm, a principal name, an e-text, the hex of
// a cipher. `textContent` cannot be broken out of and needs no escaping, and
// tests/kerberos_decoder_page.js proves it by feeding the pages a payload that
// would execute — mutation-tested, so swapping one textContent for innerHTML fails
// that test.
//
// ---------------------------------------------------------------------------
// THE CREDENTIAL CACHE, and why it is here rather than in one page.
//
// The three exchange pages hand credentials to each other: the AS page produces a
// TGT, the TGS page spends it and produces a service ticket, the AP page presents
// that. So the cache is shared state, and shared state with three writers needs one
// implementation — three would drift on the question that matters most, which is
// WHERE it is kept.
//
// A ticket's session key is a credential: whatever holds it can use the ticket. So
// the default store is **sessionStorage**, gone when the tab closes, and
// `krb_save_ccache` opts into localStorage. Unticking that box PURGES what was
// already written — an opt-out that leaves yesterday's session key behind is not an
// opt-out — and the purge lives in this module rather than in a change handler on
// one page, so no page can forget it. Passwords are never stored at all.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_panes",
  level: appconfig.logLevel
});

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var describer = require("./krb5_describe.js");
var history = require("./kerberos_history.js");

// ---------------------------------------------------------------------------
// Storage keys. One list, so no page invents a variant.
// ---------------------------------------------------------------------------
var KEYS = {
  REALM: "krb_realm",
  KDC_HOST: "krb_kdc_host",
  KDC_PORT: "krb_kdc_port",
  TRANSPORT: "krb_transport",
  PRINCIPAL: "krb_principal",
  ETYPES: "krb_etypes",
  SAVE_CCACHE: "krb_save_ccache",
  // The TGT, and the service tickets bought with it. Separate entries because
  // they have different lifetimes and the TGS page needs the first while the AP
  // page needs the second.
  TGT: "krb_ccache",
  SERVICE_TICKETS: "krb_service_tickets",
  SERVICE_HOST: "krb_service_host",
  SERVICE_PORT: "krb_service_port",
  SERVICE_SPN: "krb_service_spn",
  // The S4U2Self ticket, which is the EVIDENCE a later S4U2Proxy request
  // presents. Kept apart from the service tickets above because it is not one:
  // it is a ticket a service holds to ITSELF, for a user who was never
  // involved, and its only use is being handed back to the KDC. Storing it
  // alongside ordinary service tickets would invite the AP page to offer it to
  // a service that has no idea what it is.
  EVIDENCE: "krb_s4u_evidence",
  DELEGATION_TARGET: "krb_deleg_target",
  DELEGATION_USER: "krb_deleg_user",
  // A LIST of every ticket this workflow has issued — metadata only, never a
  // key. See recordTicket() for why that distinction is the whole design.
  TICKET_HISTORY: "krb_ticket_history",
  // The SPNEGO page's own two fields. The URL is remembered like every other
  // endpoint on these pages; the SPN is derived from it and kept separately
  // because a user may legitimately override it — an SPN's host component and
  // the host in the URL are not required to agree, and on a load-balanced or
  // CNAMEd service they routinely do not. That disagreement is the single
  // commonest cause of a SPNEGO failure in the field, so it has to be
  // editable rather than computed and hidden.
  SPNEGO_URL: "krb_spnego_url",
  SPNEGO_SPN: "krb_spnego_spn",
  // Where to send the user back to. See noteReturnTarget() below: the SPNEGO
  // workflow needs a service ticket, the pages that obtain one are the AS and
  // TGS pages, and a workflow that sends you somewhere and does not bring you
  // back is a workflow you leave.
  RETURN_TO: "krb_return_to"
};

function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ""; }
function setVal(id, v) { var e = el(id); if (e) e.value = v === null ||
    v === undefined ? "" : v; }
function checked(id) { var e = el(id); return e ? !!e.checked : false; }
function disable(id, off) { var e = el(id); if (e) e.disabled = !!off; }

function make(tag, className, text) {
  var node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) { while (node &&
    node.firstChild) node.removeChild(node.firstChild); }

// Writing a status line is also how an Operations History row is CLOSED —
// see the long note at the top of kerberos_history.js for why the close is
// driven from here rather than from each handler's exits. settle() is a no-op
// unless an operation was opened against this exact status id, so the load-time
// and descriptive status writes (most of the 91 in these bundles) cost a map
// lookup and nothing else. It runs before the element check on purpose: a
// missing status element is a broken page, and losing the log entry too would
// hide the operation that noticed.
function status(id, text, cls) {
  history.settle(id, cls, text);
  var e = el(id);
  if (!e) {
    return;
  }
  e.textContent = text;
  e.className = "krb-status" + (cls ? " " + cls : "");
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------
function renderRow(table, r) {
  var tr = make("tr");
  tr.appendChild(make("td", "krb-name", r.name));
  var cell = make("td", "krb-value");
  cell.appendChild(make("span", "krb-mono", r.value));
  if (r.note) cell.appendChild(make("div", "krb-note", r.note));
  tr.appendChild(cell);
  table.appendChild(tr);
}

function renderTable(host, rows) {
  var table = make("table", "krb-table");
  (rows || []).forEach(function (r) { renderRow(table, r); });
  host.appendChild(table);
  return table;
}

function renderSection(host, section, depth) {
  var pane = make("div", "krb-section krb-depth-" + Math.min(depth || 0, 3));
  pane.appendChild(make("h4", "krb-section-title", section.title));
  if (section.note) pane.appendChild(make("p", "krb-section-note",
      section.note));
  if (section.rows && section.rows.length) renderTable(pane, section.rows);
  (section.sections || []).forEach(function (child) { renderSection(pane,
      child, (depth || 0) + 1); });
  host.appendChild(pane);
}

function renderTree(host, nodes, depth) {
  log.debug("Entering renderTree().");
  var list = make("ul", "krb-tree");
  (nodes || []).forEach(function (n) {
    var li = make("li");
    li.appendChild(make("span", "krb-tree-tag", n.tagName));
    li.appendChild(make("span", "krb-tree-meta",
      " offset " + n.offset + ", " + n.length + " byte" + (n.length === 1 ?
          "" : "s")));
    if (n.text !== undefined && n.text !== null) {
      li.appendChild(make("div", "krb-mono krb-tree-text", n.text));
    }
    if (n.depthLimited) li.appendChild(make("div", "krb-note", "Not expanded " +
        "further."));
    if (n.children) renderTree(li, n.children, (depth || 0) + 1);
    list.appendChild(li);
  });
  host.appendChild(list);
  log.debug("Leaving renderTree().");
}

// ---------------------------------------------------------------------------
// The hex view that belongs to a decoded pane, found BY CONVENTION.
//
// Every message pane on these pages is `krb_<something>_pane`, and the hex tab
// beside it is `krb_<something>_hex`. So the hex view does not need wiring at
// each call site: renderMessage() looks for the companion and fills it if the
// page has one. That matters because the alternative is a second call next to
// every renderMessage() — there are ten across four bundles — and the failure
// mode of forgetting one is a hex tab that silently keeps the PREVIOUS
// message's bytes while the decoded tab beside it shows the new one. Two panes
// disagreeing about what just happened is worse than no hex tab.
//
// A page opts in with markup alone: add the tab strip and a `_hex` div, and the
// view appears. Nothing here has to know which pages did.
//
// The require is INSIDE the function on purpose. kerberos_hex.js requires this
// module for el/make/clear, so a top-level require here would be a cycle — and
// in browserify a cycle is not a warning, it is `panes.el is not a function` at
// load time, because this module's exports object is not assigned until its
// last line. By call time both modules are complete.
// ---------------------------------------------------------------------------
function renderCompanionHex(hostId, bytes, label) {
  log.debug("Entering renderCompanionHex(). host=" + hostId);
  if (!/_pane$/.test(hostId)) {
    log.debug("Leaving renderCompanionHex(). Not a _pane id.");
    return null;
  }
  var hexId = hostId.replace(/_pane$/, "_hex");
  if (!el(hexId)) {
    log.debug("Leaving renderCompanionHex(). This page has no " + hexId + ".");
    return null;
  }
  var hexview = require("./kerberos_hex.js");
  log.debug("Leaving renderCompanionHex().");
  return hexview.render(hexId, bytes, label);
}

// ---------------------------------------------------------------------------
// The hex views of a reply's PARTS, found by the same convention one step down.
//
// A KDC reply has three byte strings inside it that a reader wants to see on
// their own, and the decoded pane already shows all three as sections: the
// **Ticket** (opaque to this client — sealed with the service's key), the
// **enc-part** envelope, and the **EncTGSRepPart** that comes out of it. The
// last of those is the interesting one: it is the only view in the workflow of
// plaintext that never crossed the wire in the clear, named field by field.
//
// The ids come off the reply pane's own, so a page opts in with markup alone
// exactly as it does for the reply's own hex tab:
//
//   krb_s4u2self_reply_pane  →  krb_s4u2self_ticket_hex
//                               krb_s4u2self_encpart_hex
//                               krb_s4u2self_encreppart_hex
//
// CALLED WITH NULL ON EVERY FAILURE PATH, and that is not defensive noise.
// These three panes are filled from a reply the caller has already opened, so
// they
// cannot be filled by renderMessage() on the way past — which means that unlike
// every other hex tab here they can go STALE: a second S4U2Self attempt the
// KDC refuses would leave the first attempt's ticket sitting under a tab beside
// a decoded pane showing KDC_ERR_BADOPTION. Two panes disagreeing about what
// just happened is the failure renderCompanionHex() exists to prevent, and this
// is the one place it has to be prevented by hand.
// ---------------------------------------------------------------------------
var REPLY_PART_HEX = [
  { suffix: "_ticket_hex", key: "ticket", label: "Ticket" },
  { suffix: "_encpart_hex", key: "encPart", label: "enc-part" },
  { suffix: "_encreppart_hex", key: "encPartPlain", label: "EncTGSRepPart" }
];

function renderReplyPartsHex(replyPaneId, bytes) {
  log.debug("Entering renderReplyPartsHex(). pane=" + replyPaneId);
  if (!/_reply_pane$/.test(replyPaneId)) {
    log.debug("Leaving renderReplyPartsHex(). Not a _reply_pane id.");
    return 0;
  }
  var stem = replyPaneId.replace(/_reply_pane$/, "");
  var hexview = require("./kerberos_hex.js");
  var filled = 0;
  REPLY_PART_HEX.forEach(function (part) {
    var id = stem + part.suffix;
    if (!el(id)) {
      return;
    }
    hexview.render(id, (bytes && bytes[part.key]) || null, part.label);
    filled += 1;
  });
  log.debug("Leaving renderReplyPartsHex(). " + filled + " pane(s).");
  return filled;
}

// ---------------------------------------------------------------------------
// THE KEYS A READER SUPPLIED, and why they are held here rather than passed in.
//
// Every page in this workflow hands renderMessage() the keys IT holds — the
// client key on the AS page, the TGT's session key on the TGS page, the
// ticket's on the AP page — and none of them holds the one key that opens the
// part people most want to see: a ticket's EncTicketPart is sealed with the
// SERVICE's own long-term key, which a client never has. That key can only come
// from the reader, so `kerberos_keys.js` mounts a pane that collects it and
// registers itself here. renderMessage() then adds those keys to whatever the
// caller passed, which means no page had to be changed for its message panes to
// start opening tickets — and a page that does not mount the pane is
// unaffected, because the supplier stays null.
//
// The rendered messages are REMEMBERED for the same reason: a key pasted after
// an exchange has already run must open the panes already on screen, and
// re-running the exchange to see inside a ticket you already have is exactly
// the friction that sends somebody to a different tool. rerenderMessages()
// replays the bytes each pane last rendered, through the same path, so nothing
// can drift between the first render and the second.
//
// Nothing here is stored. The supplier reads the fields on every call, so the
// keys live in the DOM for as long as the page is open and go no further.
// ---------------------------------------------------------------------------
var extraKeySupplier = null;
var lastRendered = {};

function setExtraKeys(supplier) {
  log.debug("Entering setExtraKeys().");
  extraKeySupplier = typeof supplier === "function" ? supplier : null;
  log.debug("Leaving setExtraKeys(). registered=" + !!extraKeySupplier);
}

async function extraKeys() {
  log.debug("Entering extraKeys().");
  if (!extraKeySupplier) {
    log.debug("Leaving extraKeys(). No supplier.");
    return [];
  }
  try {
    var supplied = await extraKeySupplier();
    log.debug("Leaving extraKeys(). " + (supplied || []).length + " key(s).");
    return supplied || [];
  } catch (e) {
    // A key the reader typed wrongly must never cost them the decode: the
    // structure is the useful part and it needs no key at all. The pane itself
    // reports what it could not read.
    log.error("the supplied keys could not be assembled: " + e.message);
    log.debug("Leaving extraKeys(). Failed.");
    return [];
  }
}

// Every message pane this page has rendered, replayed with whatever keys are
// available now. Awaited in order rather than in parallel: string-to-key is the
// expensive part and it is already done by the time this runs, and a page with
// nine panes repainting in a deterministic order is a page whose screen does
// not jump about while it fills.
async function rerenderMessages() {
  log.debug("Entering rerenderMessages().");
  var ids = Object.keys(lastRendered);
  for (var i = 0; i < ids.length; i++) {
    var record = lastRendered[ids[i]];
    await renderMessage(ids[i], record.label, record.bytes, record.keys);
  }
  log.debug("Leaving rerenderMessages(). " + ids.length + " pane(s).");
  return ids.length;
}

// One message, described by common/krb5/krb5_describe.js and rendered here.
//
// The pane is replaced in place and is NOT cleared before the new content is
// ready: a pane that empties and then fills reads as a page that lost your
// data, and on a slow exchange that gap is visible.
async function renderMessage(hostId, label, bytes, keys) {
  log.debug("Entering renderMessage(). " + label);
  var host = el(hostId);
  if (!host) {
    return null;
  }
  // Before the decode, and outside its try: bytes that will NOT decode are
  // exactly the bytes somebody wants to look at one at a time, so the hex view
  // must survive a message the describer refuses.
  renderCompanionHex(hostId, bytes, label);
  // Remembered before the decode, not after it, so bytes that do not decode can
  // still be retried when a key arrives — and remembered with the CALLER's keys
  // only, since the supplied ones are read fresh on every render.
  lastRendered[hostId] = {
    label: label,
    bytes: bytes,
    keys: (keys || []).slice()
  };
  var doc;
  try {
    doc = await describer.describe(prim.toBytes(bytes),
        { keys: (keys || []).concat(await extraKeys()) });
  } catch (e) {
    clear(host);
    host.appendChild(make("p", "krb-note krb-bad", label + " could not be " +
        "decoded: " + e.message));
    return null;
  }
  clear(host);
  var head = make("div", "krb-summary");
  head.appendChild(make("span", "krb-kind", label + " — " + doc.kind));
  head.appendChild(make("span", "krb-summary-text", doc.summary));
  host.appendChild(head);
  if (doc.problems && doc.problems.length) {
    var problems = make("div", "krb-problems");
    problems.appendChild(make("h4", "krb-section-title", "Worth knowing"));
    var ul = make("ul");
    doc.problems.forEach(function (p) { ul.appendChild(make("li", null, p)); });
    problems.appendChild(ul);
    host.appendChild(problems);
  }
  (doc.sections || []).forEach(function (s) { renderSection(host, s, 0); });
  if (doc.tree) {
    var treePane = make("div", "krb-section");
    treePane.appendChild(make("h4", "krb-section-title", "ASN.1 structure"));
    renderTree(treePane, doc.tree, 0);
    host.appendChild(treePane);
  }
  log.debug("Leaving renderMessage(). kind=" + doc.kind);
  return doc;
}

// ---------------------------------------------------------------------------
// base64, both ways. The api takes and returns base64 because JSON has no bytes.
// ---------------------------------------------------------------------------
function bytesToB64(bytes) {
  var b = prim.toBytes(bytes), s = "";
  for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return window.btoa(s);
}

function b64ToBytes(text) {
  var s = window.atob(String(text));
  var out = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// The two relay calls.
//
// They are separate endpoints on purpose: a KDC is on a Kerberos port and answers
// AS-REQ/TGS-REQ, while a service can be on ANY port and is presented with a
// GSS-wrapped AP-REQ. See api/CLAUDE.md — the service endpoint is off by default
// because it is the broader capability.
// ---------------------------------------------------------------------------
async function post(path, body) {
  log.debug("Entering post().");
  var response = await fetch(appconfig.apiUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  var parsed;
  try {
    parsed = await response.json();
  } catch (e) {
    log.debug("Leaving post().");
    throw new Error("the api answered " + response.status + " with something " +
        "that is not JSON");
  }
  if (!response.ok) {
    // 400 means this service will not do what was asked; 502 means it tried and
    // the far end did not deliver. The distinction is worth keeping in the
    // message, because one is a mistake to correct and the other is a fact
    // about the network.
    var kind = response.status === 400 ? "The api refused to send this" :
        "The far end could not be reached";
    log.debug("Leaving post().");
    throw new Error(kind + ": " + (parsed.error || response.statusText) +
      (parsed.code ? " [" + parsed.code + "]" : ""));
  }
  log.debug("Leaving post().");
  return parsed;
}

async function sendToKdc(options) {
  log.debug("Entering sendToKdc().");
  var body = await post("/krb5/kdc", {
    host: options.host,
    port: options.port,
    transport: options.transport || "tcp",
    message: bytesToB64(options.message)
  });
  log.debug("Leaving sendToKdc(). reply=" + body.replyMessage);
  return {
    reply: b64ToBytes(body.reply),
    replyMessage: body.replyMessage,
    timing: body.timing,
    target: body.target
  };
}

async function sendToService(options) {
  log.debug("Entering sendToService().");
  var body = await post("/krb5/service", {
    host: options.host,
    port: options.port,
    message: bytesToB64(options.message)
  });
  log.debug("Leaving sendToService(). reply=" + (body.replyMessage || "none"));
  return {
    // A service that closes without answering is not a failure — a client that
    // did not ask for mutual authentication is not owed a reply — so `reply`
    // may be null and the note says what that means.
    reply: body.reply ? b64ToBytes(body.reply) : null,
    replyMessage: body.replyMessage,
    note: body.note || null,
    timing: body.timing,
    target: body.target
  };
}

// ---------------------------------------------------------------------------
// The THIRD relay call, and the one that is not a socket.
//
// SPNEGO is Kerberos over HTTP, so this one goes through POST /krb5/spnego —
// an ordinary HTTP GET made on the page's behalf, with the Authorization
// header built by the api from a token this page supplies.
//
// It does not fetch() the resource directly, and the reason is the whole point
// of the SPNEGO page: a cross-origin fetch can read a response header only if
// the server chose to expose it, and `WWW-Authenticate` is exactly the header
// the workflow exists to show. The browser also owns its own request headers,
// so a page cannot report what it sent. Both sides come back from the api
// verbatim instead.
// ---------------------------------------------------------------------------
async function sendSpnego(options) {
  log.debug("Entering sendSpnego().");
  var body = await post("/krb5/spnego", {
    url: options.url,
    // Absent for the unauthenticated first request, which is a request with no
    // Authorization header rather than one with an empty token.
    token: options.token ? bytesToB64(options.token) : undefined,
    sslValidate: options.sslValidate !== false
  });
  log.debug("Leaving sendSpnego(). status=" + (body.response &&
      body.response.status));
  return body;
}

// What the relay will and will not do, so a page can say so before a call fails
// rather than reporting its own limits as somebody else's fault.
async function relayLimits() {
  var response = await fetch(appconfig.apiUrl + "/krb5/limits");
  if (!response.ok) {
    throw new Error("GET /krb5/limits answered " + response.status);
  }
  return response.json();
}

// ---------------------------------------------------------------------------
// The credential cache.
// ---------------------------------------------------------------------------
function savingToLocalStorage() {
  // Read the STORED preference rather than a checkbox, because the TGS and AP
  // pages have no such checkbox and must still honour the choice made on the AS
  // page.
  try {
    return window.localStorage.getItem(KEYS.SAVE_CCACHE) === "1";
  } catch (e) {
    return false;
  }
}

function cacheStore() {
  return savingToLocalStorage() ? window.localStorage : window.sessionStorage;
}

function writeEntry(key, value) {
  log.debug("Entering writeEntry().");
  try {
    cacheStore().setItem(key, JSON.stringify(value));
    // Whichever store is not in use must not keep a stale copy.
    var other = savingToLocalStorage() ? window.sessionStorage :
        window.localStorage;
    other.removeItem(key);
  } catch (e) {
    log.error("could not store " + key + ": " + e.message);
  }
  log.debug("Leaving writeEntry().");
}

function readEntry(key) {
  log.debug("Entering readEntry().");
  try {
    var raw = window.sessionStorage.getItem(key) ||
        window.localStorage.getItem(key);
    log.debug("Leaving readEntry().");
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    // Unreadable is the same as absent and must not stop a page loading.
    log.warn("could not read " + key + ": " + e.message);
    log.debug("Leaving readEntry().");
    return null;
  }
  log.debug("Leaving readEntry().");
}

function removeEntry(key) {
  try {
    window.sessionStorage.removeItem(key);
    window.localStorage.removeItem(key);
  } catch (e) {
    log.warn("could not remove " + key + ": " + e.message);
  }
}

function saveTgt(entry) { writeEntry(KEYS.TGT, entry); }
function readTgt() { return readEntry(KEYS.TGT); }
function forgetTgt() { removeEntry(KEYS.TGT); }

function saveEvidence(entry) { writeEntry(KEYS.EVIDENCE, entry); }
function readEvidence() { return readEntry(KEYS.EVIDENCE); }
function forgetEvidence() { removeEntry(KEYS.EVIDENCE); }

// Service tickets are a list keyed by SPN: a session may hold several, and the
// AP page needs to choose.
function saveServiceTicket(entry) {
  var all = readEntry(KEYS.SERVICE_TICKETS) || [];
  var kept = all.filter(function (t) { return t.service !== entry.service; });
  kept.unshift(entry);
  // Bounded, because each one carries a session key and an unbounded list of
  // credentials in a browser store is a worse place to leave them than one.
  writeEntry(KEYS.SERVICE_TICKETS, kept.slice(0, 8));
}
function readServiceTickets() { return readEntry(KEYS.SERVICE_TICKETS) || []; }
function forgetServiceTickets() { removeEntry(KEYS.SERVICE_TICKETS); }

// Enforced HERE rather than in a change handler, so that no page can leave a
// session key behind by forgetting to call it. Every page calls this on load.
function enforceStoragePreference() {
  log.debug("Entering enforceStoragePreference().");
  if (!savingToLocalStorage()) {
    try {
      window.localStorage.removeItem(KEYS.TGT);
      window.localStorage.removeItem(KEYS.SERVICE_TICKETS);
      // The evidence ticket carries a session key like any other, so it belongs
      // in the purge. A key left behind by an opt-out is not an opt-out.
      window.localStorage.removeItem(KEYS.EVIDENCE);
      // The history holds a session key per entry, so it is a hundred times
      // the reason the three above are here.
      window.localStorage.removeItem(KEYS.TICKET_HISTORY);
    } catch (e) {
      log.warn("could not purge localStorage: " + e.message);
    }
  }
  log.debug("Leaving enforceStoragePreference().");
}

// A ticket, as a row list. Shared so the three pages describe one the same way.
function ticketRows(entry) {
  log.debug("Leaving ticketRows().");
  log.debug("Entering ticketRows().");
  return [
    { name: "client", value: entry.client, note: null },
    {
      name: "service",
      value: entry.service,
      note: entry.isTgt
        ? "a TGT is a ticket for krbtgt; the TGS exchange spends it on a " +
            "service ticket"
        : null
    },
    {
      name: "flags",
      value: (entry.flags || []).join(", ") || "(none)",
      note: (entry.flags || []).indexOf("ok-as-delegate") !== -1
        ? "ok-as-delegate: the KDC is telling the client this service may be " +
            "trusted with " +
          "delegated credentials"
        : null
    },
    {
      name: "encryption type",
      value: entry.sessionKeyEtypeName || String(entry.sessionKeyEtype),
      note: null
    },
    {
      name: "session key",
      value: entry.sessionKey,
      note: "A CREDENTIAL. Anything holding this can use the ticket, which " +
          "is why it is not " +
            "persisted across visits unless you ask."
    },
    { name: "valid from", value: entry.authtime, note: null },
    { name: "valid until", value: entry.endtime, note: null },
    {
      name: "renewable until",
      value: entry.renewTill || "(not renewable)",
      note: null
    },
    {
      name: "ticket",
      value: (entry.ticket || "").slice(0, 96) + "…",
      note: "Opaque here: it is encrypted under the service's key. Paste it " +
          "into the Kerberos " +
            "Decoder with that key or its keytab to see inside."
    }
  ];
}

function renderTicketPane(hostId, entry, title, emptyText) {
  log.debug("Entering renderTicketPane().");
  var host = el(hostId);
  if (!host) {
    log.debug("Leaving renderTicketPane().");
    return;
  }
  clear(host);
  if (!entry) {
    host.appendChild(make("p", "krb-note", emptyText));
    log.debug("Leaving renderTicketPane().");
    return;
  }
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title", title));
  renderTable(pane, ticketRows(entry));
  host.appendChild(pane);
  log.debug("Leaving renderTicketPane().");
}

// ---------------------------------------------------------------------------
// What the environment can and cannot do, said on arrival.
// ---------------------------------------------------------------------------
async function reportEnvironment(hostId, options) {
  log.debug("Entering reportEnvironment().");
  var opts = options || {};
  var note = el(hostId);
  if (!note) {
    log.debug("Leaving reportEnvironment().");
    return { ok: false };
  }
  clear(note);

  if (appconfig.backendAvailable === false) {
    note.appendChild(make("p", "krb-note krb-bad",
      "This build has no api behind it, and Kerberos needs one: the protocol " +
          "speaks DER over a " +
      "TCP socket, which a browser cannot open. The Kerberos Decoder page " +
          "does work here — it " +
      "parses bytes you already have."));
    (opts.disableOnNoBackend || []).forEach(function (id) { disable(id,
        true); });
    log.debug("Leaving reportEnvironment().");
    return { ok: false, reason: "no api" };
  }
  if (!(window.crypto && window.crypto.subtle)) {
    note.appendChild(make("p", "krb-note krb-bad",
      "This page is not in a secure context, so Web Crypto is unavailable " +
          "and no key can be " +
      "derived or verified. Load it over https, or from localhost."));
  }
  try {
    var limits = await relayLimits();
    var text = "The api relays to KDC ports " + (limits.allowedPorts ||
        []).join(", ") + "; ";
    if (opts.needsService) {
      text += limits.serviceEnabled
        ? "presenting a ticket to a service is enabled for " +
          (limits.servicePorts === "any" ? "any port" : "port(s) " +
              limits.servicePorts.join(", ")) + "; "
        : "presenting a ticket to a service is NOT enabled on this " +
            "deployment — set " +
          "krb5ServicePorts in the api configuration. ";
    }
    text += "its address policy is " + (limits.addressPolicyEnabled ? "ON" :
        "off") +
      (limits.addressPolicyEnabled
        ? " (so a KDC or service on a private or loopback address will be " +
            "refused; the local and " +
          "containerized stacks turn it off for exactly that reason)"
        : "") + ".";
    note.appendChild(make("p", "krb-note", text));
    if (opts.needsService && !limits.serviceEnabled) {
      (opts.disableOnNoService || []).forEach(function (id) { disable(id,
          true); });
      log.debug("Leaving reportEnvironment().");
      return { ok: false, reason: "service relay disabled", limits: limits };
    }
    log.debug("Leaving reportEnvironment().");
    return { ok: true, limits: limits };
  } catch (e) {
    note.appendChild(make("p", "krb-note krb-bad",
      "The api at " + appconfig.apiUrl + " did not answer GET /krb5/limits (" +
          e.message +
      "), so it may not be running, or may be an older build without the " +
          "Kerberos relay."));
    log.debug("Leaving reportEnvironment().");
    return { ok: false, reason: e.message };
  }
  log.debug("Leaving reportEnvironment().");
}

// ---------------------------------------------------------------------------
// COMING BACK.
//
// The SPNEGO page needs a service ticket and has no way to obtain one: getting
// a ticket is the AS exchange followed by the TGS exchange, and those are two
// other pages in this workflow. Re-implementing either on a third page would
// be a second implementation of the thing this workflow exists to show, so the
// SPNEGO page sends you to them instead — and this is the half that brings you
// back, because a workflow that sends you away and does not return is one you
// leave.
//
// It is a LINK and never a redirect. The pages here re-render in place and do
// not navigate for you (see the note on Operations History): an automatic hop
// back the moment a TGT arrives takes the AS exchange's two decoded messages
// off the screen at exactly the moment somebody wanted to read them, which is
// what that page is FOR.
//
// The target is taken from `?return=` and then kept in storage, so it survives
// the AS page sending you on to the TGS page — the common route, and one where
// the query parameter would otherwise be lost at the first hop.
// ---------------------------------------------------------------------------
var RETURN_TARGETS = {
  spnego: {
    href: "/spnego.html",
    name: "SPNEGO",
    what: "Kerberos over HTTP"
  }
};

function noteReturnTarget() {
  log.debug("Entering noteReturnTarget().");
  var asked = null;
  try {
    asked = new URLSearchParams(window.location.search).get("return");
  } catch (e) {
    // No URLSearchParams, or an unparseable query. Not fatal — the trail at
    // the top of the page still reaches every other page — so the banner is
    // simply not offered.
    log.warn("could not read the query string: " + e.message);
  }
  if (asked && RETURN_TARGETS[asked]) {
    try {
      window.sessionStorage.setItem(KEYS.RETURN_TO, asked);
    } catch (e) {
      log.warn("could not remember the return target: " + e.message);
    }
    log.debug("Leaving noteReturnTarget(). " + asked);
    return RETURN_TARGETS[asked];
  }
  if (asked) {
    // An unknown value is dropped rather than turned into a link. This is a
    // navigation target read out of the URL, so anything but a name from the
    // table above would be somebody else choosing where this page points.
    log.warn("ignoring an unrecognised return target " + JSON.stringify(asked));
  }
  var remembered = null;
  try {
    remembered = window.sessionStorage.getItem(KEYS.RETURN_TO);
  } catch (e) {
    // No storage: the banner is offered only on the page the link landed on.
    remembered = null;
  }
  log.debug("Leaving noteReturnTarget(). " + (remembered || "none"));
  return remembered ? RETURN_TARGETS[remembered] || null : null;
}

function clearReturnTarget() {
  log.debug("Entering clearReturnTarget().");
  try {
    window.sessionStorage.removeItem(KEYS.RETURN_TO);
  } catch (e) {
    log.warn("could not clear the return target: " + e.message);
  }
  log.debug("Leaving clearReturnTarget().");
}

// Render the banner. `options.ready` decides which of two sentences it carries,
// and the distinction is the useful part: "you still need X" and "you have what
// you came for" are different instructions, and a banner that says neither is
// just a link.
function renderReturnBanner(hostId, options) {
  log.debug("Entering renderReturnBanner().");
  var opts = options || {};
  var host = el(hostId);
  var target = opts.target || noteReturnTarget();
  if (!host || !target) {
    log.debug("Leaving renderReturnBanner(). Nothing to show.");
    return null;
  }
  clear(host);
  var box = make("div", "krb-return-banner" + (opts.ready ? " krb-ok" : ""));
  box.appendChild(make("span", "krb-return-what",
      "You came here from " + target.name + " (" + target.what + ")."));
  box.appendChild(make("span", "krb-return-why",
      opts.ready
        ? (opts.readyText || "You now have what it needs.")
        : (opts.needText || "Finish this exchange and come back.")));
  var link = make("a", "krb-return-link",
      "Back to " + target.name + " →");
  link.href = target.href;
  box.appendChild(link);
  host.appendChild(box);
  log.debug("Leaving renderReturnBanner(). ready=" + !!opts.ready);
  return target;
}

// The KDC coordinates, shared by the AS and TGS pages. Read from storage so the
// TGS page does not ask again for what the AS page was already told.
function loadKdcFields() {
  log.debug("Entering loadKdcFields().");
  [KEYS.REALM, KEYS.KDC_HOST, KEYS.KDC_PORT, KEYS.TRANSPORT, KEYS.PRINCIPAL,
      KEYS.ETYPES]
    .forEach(function (key) {
      try {
        var stored = window.localStorage.getItem(key);
        if (stored !== null && stored !== undefined &&
            stored !== "") setVal(key, stored);
      } catch (e) {
        // No storage: the defaults in the markup stand.
      }
    });
  log.debug("Leaving loadKdcFields().");
}

function saveKdcFields() {
  log.debug("Entering saveKdcFields().");
  try {
    [KEYS.REALM, KEYS.KDC_HOST, KEYS.KDC_PORT, KEYS.TRANSPORT, KEYS.PRINCIPAL,
        KEYS.ETYPES]
      .forEach(function (key) {
        var e = el(key);
        if (e) window.localStorage.setItem(key, e.value);
      });
    // The PASSWORD is deliberately absent, as it is on every other page here.
  } catch (e) {
    log.error("could not store the configuration: " + e.message);
  }
  log.debug("Leaving saveKdcFields().");
}

// ---------------------------------------------------------------------------
// Panes: collapsing one, collapsing all, and marking the step trail.
//
// All five Kerberos pages share these for the same reason they share everything
// else in this module: a pane behaving differently on two of them would be a
// bug visible only by comparing the two.
//
// The markup contract. The CLASSES are the ones every other workflow here uses
// (css/debugger.css, and any dbg-pane in vc-presentation-3.html), so the panes
// look and behave identically:
//
//   <div class="dbg-pane" id="pane_x">
//     <legend class="dbg-legend" id="x_expand_button">Title</legend>
//     <fieldset name="x_fieldset" id="x_fieldset">...</fieldset>
//   </div>
//
// The WIRING differs from those workflows on purpose, and it is the one place
// this is not a copy. They put the fieldset's id in an inline
// onclick="...togglePane('x_fieldset')", which repeats the id in two places and
// fails silently when the two drift: a legend that does nothing at all, with
// nothing in the page complaining. wirePanes() below instead PAIRS them by
// convention — `x_expand_button` drives `x_fieldset` — so there is one id and
// nothing to get out of step. These pages already wire every other control from
// their bundle rather than inline, so this also matches how they are built.
// ---------------------------------------------------------------------------
function togglePane(bodyId) {
  log.debug("Entering togglePane().");
  var b = el(bodyId);
  if (b) {
    b.style.display = (b.style.display === "none") ? "block" : "none";
  }
  log.debug("Leaving togglePane().");
  return false;
}

// Expand or collapse every pane on the page.
//
// The fieldsets are DISCOVERED rather than listed, which is the difference from
// the other workflows' copies of this: they each hard-code an array of ids, and
// every one is a list a new pane has to be remembered into. Reading them off
// the DOM means a pane added later is covered by construction.
function setAllPanes(expand) {
  log.debug("Entering setAllPanes(). expand=" + !!expand);
  var panes = document.querySelectorAll(".dbg-pane fieldset");
  for (var i = 0; i < panes.length; i++) {
    panes[i].style.display = expand ? "block" : "none";
  }
  var text = document.querySelector(".dbg-toggle-text");
  if (text) {
    text.textContent = expand ? "Collapse all panes" : "Expand all panes";
  }
  log.debug("Leaving setAllPanes(). " + panes.length + " pane(s).");
  return false;
}

// Mark this page's entry in the shared step trail (partials/krb_steps.html).
// Called by each page's bundle with its own id, because the partial is one file
// serving five pages and cannot know which it is on.
function markCurrentStep(stepId) {
  log.debug("Entering markCurrentStep(). step=" + stepId);
  var li = el(stepId);
  if (li) {
    li.className = (li.className ? li.className + " " : "") +
        "krb-step-current";
  } else {
    // Not fatal: the trail is navigation, and a page missing it is still
    // usable. Worth a line though, because the usual cause is a renamed id in
    // the partial, and the symptom otherwise is a trail where nothing looks
    // current.
    log.warn("no step-trail entry with id " + stepId +
        "; is partials/krb_steps.html included on this page?");
  }
  log.debug("Leaving markCurrentStep().");
}

// Bind every pane's legend to its fieldset, pairing `x_expand_button` with
// `x_fieldset`. Called once from each page's own wire().
//
// A legend whose fieldset is missing is reported rather than ignored: it means
// the pair has drifted, which is the failure the id convention exists to
// prevent, and a silent skip would hide it again.
function wirePanes() {
  log.debug("Entering wirePanes().");
  var legends = document.querySelectorAll(".dbg-legend");
  var wired = 0;
  for (var i = 0; i < legends.length; i++) {
    var legend = legends[i];
    var id = legend.id || "";
    if (id.indexOf("_expand_button") === -1) {
      log.warn("a .dbg-legend has id " + JSON.stringify(id) +
          ", which does not end in _expand_button, so it cannot be paired " +
          "with a fieldset");
      continue;
    }
    var bodyId = id.replace("_expand_button", "_fieldset");
    if (!el(bodyId)) {
      log.warn("legend " + id + " names no fieldset " + bodyId +
          " — the pane's ids have drifted and the title will do nothing");
      continue;
    }
    legend.style.cursor = "pointer";
    legend.addEventListener("click", (function (target) {
      return function () {
        togglePane(target);
        return false;
      };
    })(bodyId));
    wired += 1;
  }
  log.debug("Leaving wirePanes(). " + wired + " pane(s) wired.");
  return wired;
}

// ---------------------------------------------------------------------------
// Tabs inside a pane.
//
// Markup, paired by a shared group name the way wirePanes() pairs legends with
// fieldsets — so there is one name to get right rather than two ids to keep in
// step:
//
//   <div class="krb-tabs" data-krb-tabs="request">
//     <button class="krb-tab krb-tab-on"
//             data-krb-tab="decoded">Decoded</button>
//     <button class="krb-tab" data-krb-tab="hex">Hex</button>
//   </div>
//   <div class="krb-tabpanel" data-krb-tabs="request"
//        data-krb-tab="decoded">…</div>
//   <div class="krb-tabpanel krb-tabpanel-off" data-krb-tabs="request"
//        data-krb-tab="hex">…</div>
//
// The panels are hidden with a class rather than inline display, so that
// setAllPanes() collapsing the fieldset above them does not fight with
// whichever tab happens to be showing.
// ---------------------------------------------------------------------------
function selectTab(group, name) {
  log.debug("Entering selectTab(). group=" + group + " tab=" + name);
  var i;
  var buttons = document.querySelectorAll(
      '.krb-tab[data-krb-tabs="' + group + '"]');
  // The buttons carry the group on their CONTAINER in the markup above, so read
  // it from either place: a button inside a group div, or one labelled itself.
  if (!buttons.length) {
    var holder = document.querySelector('.krb-tabs[data-krb-tabs="' + group +
        '"]');
    buttons = holder ? holder.querySelectorAll(".krb-tab") : [];
  }
  for (i = 0; i < buttons.length; i++) {
    var on = buttons[i].getAttribute("data-krb-tab") === name;
    buttons[i].className = "krb-tab" + (on ? " krb-tab-on" : "");
    buttons[i].setAttribute("aria-selected", on ? "true" : "false");
  }
  var panels = document.querySelectorAll(
      '.krb-tabpanel[data-krb-tabs="' + group + '"]');
  for (i = 0; i < panels.length; i++) {
    var show = panels[i].getAttribute("data-krb-tab") === name;
    panels[i].className = "krb-tabpanel" + (show ? "" : " krb-tabpanel-off");
  }
  log.debug("Leaving selectTab(). " + buttons.length + " button(s), " +
      panels.length + " panel(s).");
}

// Bind every tab strip on the page. Called once from each page's wire().
function wireTabs() {
  log.debug("Entering wireTabs().");
  var strips = document.querySelectorAll(".krb-tabs");
  var wired = 0;
  for (var i = 0; i < strips.length; i++) {
    var group = strips[i].getAttribute("data-krb-tabs");
    if (!group) {
      log.warn("a .krb-tabs strip has no data-krb-tabs group name, so its " +
          "buttons cannot be paired with panels");
      continue;
    }
    var buttons = strips[i].querySelectorAll(".krb-tab");
    for (var j = 0; j < buttons.length; j++) {
      buttons[j].addEventListener("click", (function (g, name) {
        return function () {
          selectTab(g, name);
          return false;
        };
      })(group, buttons[j].getAttribute("data-krb-tab")));
    }
    wired += buttons.length;
  }
  log.debug("Leaving wireTabs(). " + wired + " tab(s) wired.");
  return wired;
}

// ---------------------------------------------------------------------------
// The ticket cache & history: every ticket this workflow has obtained, and a
// way back to any of them.
//
// The STORE half. The pane over it is client/src/kerberos_tickets.js, on all
// five pages. Modelled on debugger2.js's Operation History — same pane shape, same
// newest-first ordering, same numbered column, same scrolling list. Two things
// differ, and the first is the important one.
//
// THIS IS A CREDENTIAL STORE, deliberately. Each entry keeps the ticket bytes
// and its session key, so any row can be made the active ticket again — which
// is the point: an AS exchange is cheap to repeat but a ticket is a moment in
// time, and comparing two of them, or going back to one issued before a
// configuration change, is exactly what this workflow is for.
//
// That decision has a cost and it is bounded in one place. A session key is a
// credential; whatever holds it can use the ticket. So the history obeys the
// SAME control as the single live ticket — krb_save_ccache — and it is in
// sessionStorage unless that box is ticked, writeEntry() clears the other store
// either way, and enforceStoragePreference() purges the list from localStorage
// the moment the box is cleared. It is in that purge list; leaving it out would
// have meant an opt-out that left a hundred session keys behind, which is not
// an opt-out. The cap exists for the same reason as much as for the display: a
// hundred is a bounded number of credentials to be holding.
//
// SECOND, WHAT HAPPENS AT THE CAP. Operation History empties itself when it
// fills — `if (history.length >= LIMIT) { history = []; }` — which loses
// everything at the moment there is most to look at. This trims the oldest
// instead, which is what a reader expects a capped log to do.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// What KIND of ticket this is, decided from the ticket itself.
//
// A ticket is a TGT if and only if its service is krbtgt — that is the
// protocol's own definition and it does not depend on a caller remembering to
// label anything. An explicit kind is accepted for the cases the service name
// cannot distinguish (an S4U2Self ticket is a service ticket to the requesting
// service ITSELF, which looks like any other), but krbtgt always wins: a
// mislabelled ticket is the error that would matter, because the kind is what
// chooses the live slot an activated ticket is written into (TICKET_SLOTS,
// below) — and the AS, TGS and delegation pages will try to SPEND whatever is
// in the TGT slot.
// ---------------------------------------------------------------------------
function ticketKind(entry) {
  log.debug("Entering ticketKind().");
  if (!entry) {
    log.debug("Leaving ticketKind(). None.");
    return "unknown";
  }
  var service = String(entry.service || "");
  if (/^krbtgt\//i.test(service)) {
    log.debug("Leaving ticketKind(). TGT.");
    return "TGT";
  }
  if (entry.kind) {
    log.debug("Leaving ticketKind(). " + entry.kind + ".");
    return entry.kind;
  }
  log.debug("Leaving ticketKind(). Service ticket.");
  return "service";
}

// ---------------------------------------------------------------------------
// WHICH LIVE SLOT A REMEMBERED TICKET GOES BACK INTO.
//
// One table rather than a decision at each call site, because the pages hold
// different slots and the pane that offers "Make active" is now on all five of
// them. The store function is the SAME one the page that obtained such a ticket
// wrote with — a ticket put back by hand must land where a freshly issued one
// would, or the next exchange reads a slot nobody filled.
//
// A `delegated` ticket is a service ticket obtained by S4U2Proxy, so it shares
// the service ticket cache: the AP page presents it exactly as it presents any
// other, and giving it a slot of its own would hide it from the page that uses
// it.
// ---------------------------------------------------------------------------
var TICKET_SLOTS = {
  TGT: { store: saveTgt, name: "the ticket-granting ticket slot" },
  evidence: { store: saveEvidence, name: "the evidence ticket slot" },
  service: { store: saveServiceTicket, name: "the service ticket cache" },
  delegated: { store: saveServiceTicket, name: "the service ticket cache" }
};

var TICKET_HISTORY_LIMIT = 100;

function recordTicket(entry, kind) {
  log.debug("Entering recordTicket(). kind=" + kind);
  if (!entry) {
    log.debug("Leaving recordTicket(). Nothing to record.");
    return null;
  }
  var history = readTicketHistory();
  // The WHOLE entry, ticket bytes and session key included, so activate() can
  // hand it straight back to saveTgt(). Copied rather than referenced: the
  // caller goes on to store its own copy under KEYS.TGT, and two names for one
  // object is how a later edit to the live ticket silently rewrites history.
  var row = JSON.parse(JSON.stringify(entry));
  // The label the caller gave, kept so an S4U2Self evidence ticket can say what
  // it is. ticketKind() still overrides it for anything addressed to krbtgt.
  if (kind) { row.kind = kind; }
  row.recordedAt = new Date().toISOString();
  // Every page in the workflow writes here, so a ticket bought twice — the same
  // service ticket re-requested, a TGT re-activated then renewed — would
  // otherwise pile up identical rows. Matched on the ticket bytes, which are
  // what make two tickets the same ticket.
  history = history.filter(function (h) {
    return !h || h.ticket !== row.ticket;
  });
  history.unshift(row);
  var trimmed = history.slice(0, TICKET_HISTORY_LIMIT);
  writeEntry(KEYS.TICKET_HISTORY, trimmed);
  log.info("ticket history: " + trimmed.length + " entr" +
      (trimmed.length === 1 ? "y" : "ies") +
      (history.length > trimmed.length ? " (oldest trimmed at the " +
        TICKET_HISTORY_LIMIT + " cap)" : ""));
  log.debug("Leaving recordTicket().");
  return trimmed;
}

function readTicketHistory() {
  log.debug("Entering readTicketHistory().");
  var list = readEntry(KEYS.TICKET_HISTORY);
  if (!list || !list.length) {
    log.debug("Leaving readTicketHistory(). Empty.");
    return [];
  }
  if (!Array.isArray(list)) {
    // Something else wrote this key. Treat it as empty rather than throwing on
    // every render — but say so, because it means two things share a name.
    log.warn(KEYS.TICKET_HISTORY + " does not hold a list; ignoring it.");
    log.debug("Leaving readTicketHistory(). Not a list.");
    return [];
  }
  log.debug("Leaving readTicketHistory(). " + list.length + " entry(ies).");
  return list;
}

// Make a remembered ticket the active one again.
//
// It is written to its slot unchanged — no re-issue, no re-derivation — because
// the whole value of a history is that the ticket is the one that was issued
// then, expiry and flags and all. An expired one is allowed through on purpose:
// the next exchange refusing it, and saying why, is more useful than this pane
// pretending it does not exist.
//
// WHICH slot comes from the ticket itself, through ticketKind() and the table
// above, never from the caller: a service ticket written into the TGT slot is
// accepted here and fails a page later, naming an encryption type. The `kind`
// argument is therefore a CHECK rather than an instruction — a caller offering
// "TGT" for a row that is not one gets null and nothing is written.
function activateTicket(index, kind) {
  log.debug("Entering activateTicket(). index=" + index + " kind=" + kind);
  var history = readTicketHistory();
  var entry = history[index];
  if (!entry) {
    log.warn("no ticket at history index " + index +
        "; the list has " + history.length + " entry(ies).");
    log.debug("Leaving activateTicket(). Not found.");
    return null;
  }
  var actual = ticketKind(entry);
  if (kind && kind !== actual) {
    log.warn("history row " + index + " is a " + actual + " ticket, not the " +
        kind + " the caller expected; nothing was activated.");
    log.debug("Leaving activateTicket(). Wrong kind.");
    return null;
  }
  var slot = TICKET_SLOTS[actual];
  if (!slot) {
    log.warn("a " + actual + " ticket has no live slot to go back into.");
    log.debug("Leaving activateTicket(). No slot.");
    return null;
  }
  slot.store(entry);
  log.info("activated the " + actual + " for " + (entry.client || "?") +
      " issued " + (entry.storedAt || "?") + " into " + slot.name +
      " (history row " + (index + 1) + ")");
  log.debug("Leaving activateTicket().");
  return entry;
}

// ---------------------------------------------------------------------------
// Which remembered tickets are being HELD right now, and where.
//
// Keyed by the ticket bytes, which are what make two tickets the same ticket —
// the same reason activeTicketIndex() matches on them rather than on an index.
// Read once per render rather than once per row: a hundred rows against three
// storage reads each is three hundred JSON parses for a table.
// ---------------------------------------------------------------------------
function heldTickets() {
  log.debug("Entering heldTickets().");
  var held = {};
  var tgt = readTgt();
  if (tgt && tgt.ticket) {
    held[tgt.ticket] = TICKET_SLOTS.TGT.name;
  }
  var evidence = readEvidence();
  if (evidence && evidence.ticket) {
    held[evidence.ticket] = TICKET_SLOTS.evidence.name;
  }
  readServiceTickets().forEach(function (entry) {
    if (entry && entry.ticket) {
      held[entry.ticket] = TICKET_SLOTS.service.name;
    }
  });
  log.debug("Leaving heldTickets(). " + Object.keys(held).length + " held.");
  return held;
}

// Which history row is the live ticket, or -1. Matched on the ticket bytes
// rather than on an index, because the list shifts as new tickets arrive and an
// index remembered across a render would drift onto a different row.
function activeTicketIndex() {
  log.debug("Entering activeTicketIndex().");
  var live = readTgt();
  if (!live || !live.ticket) {
    log.debug("Leaving activeTicketIndex(). None held.");
    return -1;
  }
  var history = readTicketHistory();
  for (var i = 0; i < history.length; i++) {
    if (history[i] && history[i].ticket === live.ticket) {
      log.debug("Leaving activeTicketIndex(). Row " + i + ".");
      return i;
    }
  }
  log.debug("Leaving activeTicketIndex(). Held ticket is not in the list.");
  return -1;
}

function forgetTicketHistory() {
  log.debug("Entering forgetTicketHistory().");
  removeEntry(KEYS.TICKET_HISTORY);
  log.debug("Leaving forgetTicketHistory().");
}

module.exports = {
  KEYS: KEYS,
  togglePane: togglePane,
  wirePanes: wirePanes,
  wireTabs: wireTabs,
  selectTab: selectTab,
  setAllPanes: setAllPanes,
  markCurrentStep: markCurrentStep,
  el: el,
  val: val,
  setVal: setVal,
  checked: checked,
  disable: disable,
  make: make,
  clear: clear,
  status: status,
  renderRow: renderRow,
  renderTable: renderTable,
  renderSection: renderSection,
  renderTree: renderTree,
  renderMessage: renderMessage,
  setExtraKeys: setExtraKeys,
  extraKeys: extraKeys,
  rerenderMessages: rerenderMessages,
  renderCompanionHex: renderCompanionHex,
  renderReplyPartsHex: renderReplyPartsHex,
  REPLY_PART_HEX: REPLY_PART_HEX,
  bytesToB64: bytesToB64,
  b64ToBytes: b64ToBytes,
  sendToKdc: sendToKdc,
  sendToService: sendToService,
  sendSpnego: sendSpnego,
  relayLimits: relayLimits,
  savingToLocalStorage: savingToLocalStorage,
  saveTgt: saveTgt,
  recordTicket: recordTicket,
  ticketKind: ticketKind,
  readTicketHistory: readTicketHistory,
  forgetTicketHistory: forgetTicketHistory,
  activateTicket: activateTicket,
  activeTicketIndex: activeTicketIndex,
  heldTickets: heldTickets,
  TICKET_SLOTS: TICKET_SLOTS,
  TICKET_HISTORY_LIMIT: TICKET_HISTORY_LIMIT,
  readTgt: readTgt,
  forgetTgt: forgetTgt,
  saveEvidence: saveEvidence,
  readEvidence: readEvidence,
  forgetEvidence: forgetEvidence,
  saveServiceTicket: saveServiceTicket,
  readServiceTickets: readServiceTickets,
  forgetServiceTickets: forgetServiceTickets,
  enforceStoragePreference: enforceStoragePreference,
  ticketRows: ticketRows,
  renderTicketPane: renderTicketPane,
  reportEnvironment: reportEnvironment,
  loadKdcFields: loadKdcFields,
  saveKdcFields: saveKdcFields,
  RETURN_TARGETS: RETURN_TARGETS,
  noteReturnTarget: noteReturnTarget,
  clearReturnTarget: clearReturnTarget,
  renderReturnBanner: renderReturnBanner
};
