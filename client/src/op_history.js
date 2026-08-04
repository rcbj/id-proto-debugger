// File: op_history.js
//
// The Operations History store, shared by the protocol workflows. Each workflow
// gets its own instance — its own localStorage key and its own columns — so the
// SAML and WS-Trust logs stay separate while the behaviour stays identical:
//
//   * a cumulative, newest-first log that survives the navigations a protocol
//     round-trip is made of, kept in localStorage and capped;
//   * three results, because the page that MAKES a call is usually not the page
//     that learns how it went:
//
//       Failure  the call never left the browser, or the peer refused it;
//       Sent     dispatched, no answer yet. NOT a success — an entry that stays
//                "Sent" means nothing ever came back to this debugger;
//       Success  the peer answered, and the answer says the call worked.
//
//     The requesting page records Failure or Sent; the response page resolves
//     the pending entry to Success or Failure.
//
// Rendering takes the container element, so no DOM ids are baked in.
//
//   createHistory({ storeKey, columns })
//     storeKey   localStorage key holding the log
//     columns    [{ key, label, className }] — the columns between "#"/"Time"
//                and "Result"; `key` names the field on a recorded entry.
//     emptyText  shown when nothing has been recorded yet.


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "op_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var RESULT_SENT = 'Sent';
var RESULT_SUCCESS = 'Success';
var RESULT_FAILURE = 'Failure';
var LIMIT = 1000;

function hasStorage() {
  try {
    return !!window.localStorage;
  } catch (e) {
    return false;
  }
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function newEntryId() {
  return 'op' + Date.now().toString(36) + Math.floor(Math.random() * 1e6).toString(36);
}

function resultClass(result) {
  if (result === RESULT_SUCCESS) return 'saml-ok';
  if (result === RESULT_FAILURE) return 'saml-bad';
  return 'saml-pending';
}

function createHistory(config) {
  log.debug("Entering createHistory().");
  var STORE_KEY = config.storeKey;
  var COLUMNS = config.columns || [];
  var EMPTY_TEXT = config.emptyText || 'No calls recorded yet.';

  function read() {
    if (!hasStorage()) return [];
    try {
      var h = JSON.parse(localStorage.getItem(STORE_KEY) || '[]');
      return Object.prototype.toString.call(h) === '[object Array]' ? h : [];
    } catch (e) {
      return [];
    }
  }

  function write(history) {
    if (!hasStorage()) return;
    // Keep the most recent entries once the cap is reached.
    if (history.length > LIMIT) history = history.slice(history.length - LIMIT);
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(history));
    } catch (e) {
      // No storage available in this context.
    }
  }

  // Append an entry. Its recognized fields are the configured columns plus
  // result/detail. Returns the id, so a caller can resolve it later.
  function record(entry) {
    log.debug("Entering record().");
    entry = entry || {};
    var saved = {
      id: newEntryId(),
      timestamp: new Date().toISOString(),
      result: entry.result || RESULT_SENT,
      detail: entry.detail || ''
    };
    COLUMNS.forEach(function (c) { saved[c.key] = entry[c.key] == null ? '' : entry[c.key]; });
    var history = read();
    history.push(saved);
    write(history);
    log.debug("Leaving record().");
    return saved.id;
  }

  function update(id, result, detail) {
    log.debug("Entering update().");
    if (!id) return false;
    var history = read();
    for (var i = history.length - 1; i >= 0; i--) {
      if (history[i].id !== id) continue;
      history[i].result = result;
      if (detail) history[i].detail = detail;
      history[i].resolvedAt = new Date().toISOString();
      write(history);
      return true;
    }
    log.debug("Leaving update().");
    return false;
  }

  // Resolve the newest still-"Sent" entry — the call this answer belongs to.
  // `match` narrows it: a string is matched against the first configured
  // column (the operation), an object against each of its fields.
  function resolvePending(result, detail, match) {
    log.debug("Entering resolvePending().");
    var want = null;
    if (typeof match === 'string' && COLUMNS.length) {
      want = {}; want[COLUMNS[0].key] = match;
    } else if (match && typeof match === 'object') {
      want = match;
    }
    var history = read();
    for (var i = history.length - 1; i >= 0; i--) {
      if (history[i].result !== RESULT_SENT) continue;
      if (want) {
        var mismatch = false;
        for (var k in want) { if (want.hasOwnProperty(k) && history[i][k] !== want[k]) mismatch = true; }
        if (mismatch) continue;
      }
      history[i].result = result;
      history[i].detail = detail || history[i].detail;
      history[i].resolvedAt = new Date().toISOString();
      write(history);
      return history[i];
    }
    log.debug("Leaving resolvePending().");
    return null;
  }

  function clear() {
    if (hasStorage()) localStorage.removeItem(STORE_KEY);
  }

  // Render the log newest-first into `box` (a DOM element).
  function render(box) {
    log.debug("Entering render().");
    if (!box) return;
    var history = read();
    if (!history.length) {
      box.innerHTML = '<p class="saml-history-empty">' + escapeHtml(EMPTY_TEXT) + '</p>';
      return;
    }
    var html = '<div class="saml-history-scroll"><table class="saml-table saml-history">' +
      '<thead><tr><th>#</th><th>Time (UTC)</th>';
    COLUMNS.forEach(function (c) { html += '<th>' + escapeHtml(c.label) + '</th>'; });
    html += '<th>Result</th></tr></thead><tbody>';
    for (var i = history.length - 1; i >= 0; i--) {
      var item = history[i] || {};
      var ts = String(item.timestamp || '');
      html += '<tr>' +
        '<td>' + (i + 1) + '</td>' +
        '<td class="saml-history-time">' + escapeHtml(ts.substring(0, 10)) + '<br>' +
          escapeHtml(ts.substring(11, 19)) + 'Z</td>';
      COLUMNS.forEach(function (c) {
        html += '<td' + (c.className ? ' class="' + c.className + '"' : '') + '>' +
          escapeHtml(item[c.key]) + '</td>';
      });
      html += '<td class="' + resultClass(item.result) + '">' + escapeHtml(item.result) +
        (item.detail ? ' — ' + escapeHtml(item.detail) : '') + '</td>' +
        '</tr>';
    }
    box.innerHTML = html + '</tbody></table></div>';
    log.debug("Leaving render().");
  }

  log.debug("Leaving createHistory().");
  return {
    SENT: RESULT_SENT,
    SUCCESS: RESULT_SUCCESS,
    FAILURE: RESULT_FAILURE,
    STORE_KEY: STORE_KEY,
    LIMIT: LIMIT,
    read: read,
    record: record,
    update: update,
    resolvePending: resolvePending,
    clear: clear,
    render: render
  };
}

module.exports = { createHistory: createHistory, SENT: RESULT_SENT, SUCCESS: RESULT_SUCCESS, FAILURE: RESULT_FAILURE };
