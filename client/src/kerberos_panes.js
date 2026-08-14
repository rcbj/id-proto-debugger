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
var log = bunyan.createLogger({ name: "kerberos_panes", level: appconfig.logLevel });

var prim = require("./krb5_primitives.js");
var msgs = require("./krb5_messages.js");
var describer = require("./krb5_describe.js");

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
  // The TGT, and the service tickets bought with it. Separate entries because they
  // have different lifetimes and the TGS page needs the first while the AP page
  // needs the second.
  TGT: "krb_ccache",
  SERVICE_TICKETS: "krb_service_tickets",
  SERVICE_HOST: "krb_service_host",
  SERVICE_PORT: "krb_service_port",
  SERVICE_SPN: "krb_service_spn",
  // The S4U2Self ticket, which is the EVIDENCE a later S4U2Proxy request presents. Kept
  // apart from the service tickets above because it is not one: it is a ticket a service
  // holds to ITSELF, for a user who was never involved, and its only use is being handed
  // back to the KDC. Storing it alongside ordinary service tickets would invite the AP page
  // to offer it to a service that has no idea what it is.
  EVIDENCE: "krb_s4u_evidence",
  DELEGATION_TARGET: "krb_deleg_target",
  DELEGATION_USER: "krb_deleg_user"
};

function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ""; }
function setVal(id, v) { var e = el(id); if (e) e.value = v === null || v === undefined ? "" : v; }
function checked(id) { var e = el(id); return e ? !!e.checked : false; }
function disable(id, off) { var e = el(id); if (e) e.disabled = !!off; }

function make(tag, className, text) {
  var node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function status(id, text, cls) {
  var e = el(id);
  if (!e) return;
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
  if (section.note) pane.appendChild(make("p", "krb-section-note", section.note));
  if (section.rows && section.rows.length) renderTable(pane, section.rows);
  (section.sections || []).forEach(function (child) { renderSection(pane, child, (depth || 0) + 1); });
  host.appendChild(pane);
}

function renderTree(host, nodes, depth) {
  var list = make("ul", "krb-tree");
  (nodes || []).forEach(function (n) {
    var li = make("li");
    li.appendChild(make("span", "krb-tree-tag", n.tagName));
    li.appendChild(make("span", "krb-tree-meta",
      " offset " + n.offset + ", " + n.length + " byte" + (n.length === 1 ? "" : "s")));
    if (n.text !== undefined && n.text !== null) {
      li.appendChild(make("div", "krb-mono krb-tree-text", n.text));
    }
    if (n.depthLimited) li.appendChild(make("div", "krb-note", "Not expanded further."));
    if (n.children) renderTree(li, n.children, (depth || 0) + 1);
    list.appendChild(li);
  });
  host.appendChild(list);
}

// One message, described by common/krb5/krb5_describe.js and rendered here.
//
// The pane is replaced in place and is NOT cleared before the new content is ready:
// a pane that empties and then fills reads as a page that lost your data, and on a
// slow exchange that gap is visible.
async function renderMessage(hostId, label, bytes, keys) {
  log.debug("Entering renderMessage(). " + label);
  var host = el(hostId);
  if (!host) return null;
  var doc;
  try {
    doc = await describer.describe(prim.toBytes(bytes), { keys: keys || [] });
  } catch (e) {
    clear(host);
    host.appendChild(make("p", "krb-note krb-bad", label + " could not be decoded: " + e.message));
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
  var response = await fetch(appconfig.apiUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  var parsed;
  try {
    parsed = await response.json();
  } catch (e) {
    throw new Error("the api answered " + response.status + " with something that is not JSON");
  }
  if (!response.ok) {
    // 400 means this service will not do what was asked; 502 means it tried and the
    // far end did not deliver. The distinction is worth keeping in the message,
    // because one is a mistake to correct and the other is a fact about the network.
    var kind = response.status === 400 ? "The api refused to send this" : "The far end could not be reached";
    throw new Error(kind + ": " + (parsed.error || response.statusText) +
      (parsed.code ? " [" + parsed.code + "]" : ""));
  }
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
  return { reply: b64ToBytes(body.reply), replyMessage: body.replyMessage,
           timing: body.timing, target: body.target };
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
    // A service that closes without answering is not a failure — a client that did
    // not ask for mutual authentication is not owed a reply — so `reply` may be null
    // and the note says what that means.
    reply: body.reply ? b64ToBytes(body.reply) : null,
    replyMessage: body.replyMessage,
    note: body.note || null,
    timing: body.timing,
    target: body.target
  };
}

// What the relay will and will not do, so a page can say so before a call fails
// rather than reporting its own limits as somebody else's fault.
async function relayLimits() {
  var response = await fetch(appconfig.apiUrl + "/krb5/limits");
  if (!response.ok) throw new Error("GET /krb5/limits answered " + response.status);
  return response.json();
}

// ---------------------------------------------------------------------------
// The credential cache.
// ---------------------------------------------------------------------------
function savingToLocalStorage() {
  // Read the STORED preference rather than a checkbox, because the TGS and AP pages
  // have no such checkbox and must still honour the choice made on the AS page.
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
  try {
    cacheStore().setItem(key, JSON.stringify(value));
    // Whichever store is not in use must not keep a stale copy.
    var other = savingToLocalStorage() ? window.sessionStorage : window.localStorage;
    other.removeItem(key);
  } catch (e) {
    log.error("could not store " + key + ": " + e.message);
  }
}

function readEntry(key) {
  try {
    var raw = window.sessionStorage.getItem(key) || window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    // Unreadable is the same as absent and must not stop a page loading.
    log.warn("could not read " + key + ": " + e.message);
    return null;
  }
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

// Service tickets are a list keyed by SPN: a session may hold several, and the AP
// page needs to choose.
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
  if (!savingToLocalStorage()) {
    try {
      window.localStorage.removeItem(KEYS.TGT);
      window.localStorage.removeItem(KEYS.SERVICE_TICKETS);
      // The evidence ticket carries a session key like any other, so it belongs in the
      // purge. A key left behind by an opt-out is not an opt-out.
      window.localStorage.removeItem(KEYS.EVIDENCE);
    } catch (e) {
      log.warn("could not purge localStorage: " + e.message);
    }
  }
}

// A ticket, as a row list. Shared so the three pages describe one the same way.
function ticketRows(entry) {
  return [
    { name: "client", value: entry.client, note: null },
    { name: "service", value: entry.service, note: entry.isTgt
        ? "a TGT is a ticket for krbtgt; the TGS exchange spends it on a service ticket"
        : null },
    { name: "flags", value: (entry.flags || []).join(", ") || "(none)",
      note: (entry.flags || []).indexOf("ok-as-delegate") !== -1
        ? "ok-as-delegate: the KDC is telling the client this service may be trusted with " +
          "delegated credentials"
        : null },
    { name: "encryption type", value: entry.sessionKeyEtypeName || String(entry.sessionKeyEtype),
      note: null },
    { name: "session key", value: entry.sessionKey,
      note: "A CREDENTIAL. Anything holding this can use the ticket, which is why it is not " +
            "persisted across visits unless you ask." },
    { name: "valid from", value: entry.authtime, note: null },
    { name: "valid until", value: entry.endtime, note: null },
    { name: "renewable until", value: entry.renewTill || "(not renewable)", note: null },
    { name: "ticket", value: (entry.ticket || "").slice(0, 96) + "…",
      note: "Opaque here: it is encrypted under the service's key. Paste it into the Kerberos " +
            "Decoder with that key or its keytab to see inside." }
  ];
}

function renderTicketPane(hostId, entry, title, emptyText) {
  var host = el(hostId);
  if (!host) return;
  clear(host);
  if (!entry) {
    host.appendChild(make("p", "krb-note", emptyText));
    return;
  }
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title", title));
  renderTable(pane, ticketRows(entry));
  host.appendChild(pane);
}

// ---------------------------------------------------------------------------
// What the environment can and cannot do, said on arrival.
// ---------------------------------------------------------------------------
async function reportEnvironment(hostId, options) {
  log.debug("Entering reportEnvironment().");
  var opts = options || {};
  var note = el(hostId);
  if (!note) return { ok: false };
  clear(note);

  if (appconfig.backendAvailable === false) {
    note.appendChild(make("p", "krb-note krb-bad",
      "This build has no api behind it, and Kerberos needs one: the protocol speaks DER over a " +
      "TCP socket, which a browser cannot open. The Kerberos Decoder page does work here — it " +
      "parses bytes you already have."));
    (opts.disableOnNoBackend || []).forEach(function (id) { disable(id, true); });
    return { ok: false, reason: "no api" };
  }
  if (!(window.crypto && window.crypto.subtle)) {
    note.appendChild(make("p", "krb-note krb-bad",
      "This page is not in a secure context, so Web Crypto is unavailable and no key can be " +
      "derived or verified. Load it over https, or from localhost."));
  }
  try {
    var limits = await relayLimits();
    var text = "The api relays to KDC ports " + (limits.allowedPorts || []).join(", ") + "; ";
    if (opts.needsService) {
      text += limits.serviceEnabled
        ? "presenting a ticket to a service is enabled for " +
          (limits.servicePorts === "any" ? "any port" : "port(s) " + limits.servicePorts.join(", ")) + "; "
        : "presenting a ticket to a service is NOT enabled on this deployment — set " +
          "krb5ServicePorts in the api configuration. ";
    }
    text += "its address policy is " + (limits.addressPolicyEnabled ? "ON" : "off") +
      (limits.addressPolicyEnabled
        ? " (so a KDC or service on a private or loopback address will be refused; the local and " +
          "containerized stacks turn it off for exactly that reason)"
        : "") + ".";
    note.appendChild(make("p", "krb-note", text));
    if (opts.needsService && !limits.serviceEnabled) {
      (opts.disableOnNoService || []).forEach(function (id) { disable(id, true); });
      return { ok: false, reason: "service relay disabled", limits: limits };
    }
    return { ok: true, limits: limits };
  } catch (e) {
    note.appendChild(make("p", "krb-note krb-bad",
      "The api at " + appconfig.apiUrl + " did not answer GET /krb5/limits (" + e.message +
      "), so it may not be running, or may be an older build without the Kerberos relay."));
    return { ok: false, reason: e.message };
  }
}

// The KDC coordinates, shared by the AS and TGS pages. Read from storage so the TGS
// page does not ask again for what the AS page was already told.
function loadKdcFields() {
  [KEYS.REALM, KEYS.KDC_HOST, KEYS.KDC_PORT, KEYS.TRANSPORT, KEYS.PRINCIPAL, KEYS.ETYPES]
    .forEach(function (key) {
      try {
        var stored = window.localStorage.getItem(key);
        if (stored !== null && stored !== undefined && stored !== "") setVal(key, stored);
      } catch (e) {
        // No storage: the defaults in the markup stand.
      }
    });
}

function saveKdcFields() {
  try {
    [KEYS.REALM, KEYS.KDC_HOST, KEYS.KDC_PORT, KEYS.TRANSPORT, KEYS.PRINCIPAL, KEYS.ETYPES]
      .forEach(function (key) {
        var e = el(key);
        if (e) window.localStorage.setItem(key, e.value);
      });
    // The PASSWORD is deliberately absent, as it is on every other page here.
  } catch (e) {
    log.error("could not store the configuration: " + e.message);
  }
}

module.exports = {
  KEYS: KEYS,
  el: el, val: val, setVal: setVal, checked: checked, disable: disable,
  make: make, clear: clear, status: status,
  renderRow: renderRow, renderTable: renderTable, renderSection: renderSection,
  renderTree: renderTree, renderMessage: renderMessage,
  bytesToB64: bytesToB64, b64ToBytes: b64ToBytes,
  sendToKdc: sendToKdc, sendToService: sendToService, relayLimits: relayLimits,
  savingToLocalStorage: savingToLocalStorage,
  saveTgt: saveTgt, readTgt: readTgt, forgetTgt: forgetTgt,
  saveEvidence: saveEvidence, readEvidence: readEvidence, forgetEvidence: forgetEvidence,
  saveServiceTicket: saveServiceTicket, readServiceTickets: readServiceTickets,
  forgetServiceTickets: forgetServiceTickets,
  enforceStoragePreference: enforceStoragePreference,
  ticketRows: ticketRows, renderTicketPane: renderTicketPane,
  reportEnvironment: reportEnvironment,
  loadKdcFields: loadKdcFields, saveKdcFields: saveKdcFields
};
