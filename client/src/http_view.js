// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: http_view.js
//
// THE HTTP TAB: one exchange drawn as the request line, its headers and its
// body, then the status line, its headers and its body, then timing. The
// drawing is the OAuth2 / OIDC workflow's (oauth2_oidc_2.js's
// drawHttpExchange() and the debugger.css `dbg-http-*` classes) as a module,
// so the GNAP page draws its exchanges the same way.
//
// Everything drawn is somebody else's bytes, so it is set as TEXT, never as
// markup.
//
// view = { note, request: { method, url, headers, body, note },
//          response: { status, statusText, headers, body, note } | null,
//          timing: [ "…" ], failure: string | null }

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "http_view",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// One element, with its text set as TEXT.
function httpNode(tag, className, text) {
  log.debug("Entering httpNode().");
  var node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  log.debug("Leaving httpNode().");
  return node;
}

// A two-column table of header names and values.
function httpHeaderTable(headers) {
  log.debug("Entering httpHeaderTable().");
  var table = httpNode("table", "dbg-http-table");
  var body = document.createElement("tbody");
  var names = Object.keys(headers || {}).sort();
  if (names.length === 0) {
    var empty = document.createElement("tr");
    var only = httpNode("td", null, "(none reported)");
    only.colSpan = 2;
    empty.appendChild(only);
    body.appendChild(empty);
  }
  names.forEach(function (name) {
    var value = headers[name];
    var row = document.createElement("tr");
    row.appendChild(httpNode("td", null, name));
    row.appendChild(httpNode("td", null,
        Array.isArray(value) ? value.join(", ") : String(value)));
    body.appendChild(row);
  });
  table.appendChild(body);
  log.debug("Leaving httpHeaderTable(). " + names.length + " header(s).");
  return table;
}

// One HTTP message: its first line, its headers, and its body.
function httpMessage(host, title, firstLine, headers, body, bodyNote) {
  log.debug("Entering httpMessage(). " + title);
  host.appendChild(httpNode("div", "dbg-http-title", title));
  var message = httpNode("div", "dbg-http");
  message.appendChild(httpNode("div", "dbg-http-line", firstLine));
  var headerBox = httpNode("div", "dbg-http-scroll");
  headerBox.appendChild(httpHeaderTable(headers));
  message.appendChild(headerBox);
  if (bodyNote) {
    message.appendChild(httpNode("div", "dbg-http-note", bodyNote));
  }
  message.appendChild(httpNode("div", "dbg-http-body",
      (body === null || body === undefined || body === "") ?
          "(no body)" : String(body)));
  host.appendChild(message);
  log.debug("Leaving httpMessage().");
}

// Draw a view into a host element, replacing what it held.
function drawHttpExchange(host, view, emptyText) {
  log.debug("Entering drawHttpExchange().");
  if (!host) {
    log.debug("Leaving drawHttpExchange(). No host element.");
    return;
  }
  while (host.firstChild) {
    host.removeChild(host.firstChild);
  }
  if (!view) {
    host.appendChild(httpNode("div", "dbg-http-note", emptyText));
    log.debug("Leaving drawHttpExchange(). Nothing to show.");
    return;
  }
  if (view.note) {
    host.appendChild(httpNode("div", "dbg-http-note", view.note));
  }
  httpMessage(host, "Request",
              view.request.method + " " + view.request.url,
              view.request.headers, view.request.body, view.request.note);
  if (view.response) {
    httpMessage(host, "Response",
                "HTTP " + view.response.status +
                    (view.response.statusText ?
                        " " + view.response.statusText : ""),
                view.response.headers, view.response.body,
                view.response.note);
  } else if (view.failure) {
    host.appendChild(httpNode("div", "dbg-http-title", "Response"));
    host.appendChild(httpNode("div", "dbg-http-fail",
        "No response. " + view.failure));
  } else {
    host.appendChild(httpNode("div", "dbg-http-title", "Response"));
    host.appendChild(httpNode("div", "dbg-http-note", "Waiting…"));
  }
  if (view.timing && view.timing.length) {
    host.appendChild(httpNode("div", "dbg-http-title", "Timing"));
    var timing = httpNode("div", "dbg-http");
    view.timing.forEach(function (line) {
      timing.appendChild(httpNode("div", "dbg-http-timing", line));
    });
    host.appendChild(timing);
  }
  log.debug("Leaving drawHttpExchange().");
}

// A fetch() Response's headers as a plain object. CORS decides which ones
// script is given, which is why the view says so.
function fetchHeaders(response) {
  log.debug("Entering fetchHeaders().");
  var out = {};
  if (response && response.headers && response.headers.forEach) {
    response.headers.forEach(function (value, name) {
      out[name] = value;
    });
  }
  log.debug("Leaving fetchHeaders().");
  return out;
}

// The view of an exchange the api made on the page's behalf, from the
// `http_exchange` it returned (api/server.js buildHttpTrace()).
function viewFromApiTrace(trace, what, roundTripMs) {
  log.debug("Entering viewFromApiTrace().");
  var body = trace.response ? trace.response.body : null;
  var timing = [];
  if (trace.timing && typeof trace.timing.totalMs === "number") {
    timing.push(what + ": " + trace.timing.totalMs +
                " ms, measured by the api around its own request.");
  }
  if (typeof roundTripMs === "number") {
    timing.push("Browser round trip to the api: " + roundTripMs + " ms.");
  }
  var view = {
    note: "Sent by the api on this browser's behalf. These are the bytes " +
          "between the api and the far end, which the browser cannot see.",
    request: {
      method: trace.request.method, url: trace.request.url,
      headers: trace.request.headers, body: trace.request.body, note: null },
    response: trace.response ? {
      status: trace.response.status,
      statusText: trace.response.statusText,
      headers: trace.response.headers,
      body: body,
      note: trace.response.bodyTruncated ? "Body truncated for display — " +
          "the first " + String(body ? body.length : 0) + " of " +
          String(trace.response.bodyLength) + " characters." : null
    } : null,
    timing: timing,
    failure: trace.error || null
  };
  log.debug("Leaving viewFromApiTrace().");
  return view;
}

// The view of an exchange this browser made itself.
function viewFromBrowser(sent, response, failure, roundTripMs) {
  log.debug("Entering viewFromBrowser().");
  var view = {
    note: "Sent by this browser.",
    request: { method: sent.method, url: sent.url,
               headers: sent.headers || {}, body: sent.body, note: null },
    response: response ? {
      status: response.status,
      statusText: response.statusText || "",
      headers: response.headers || {},
      body: response.body,
      note: "Only the response headers CORS exposes to script are listed."
    } : null,
    timing: typeof roundTripMs === "number" ?
        ["Total, measured in the browser around the request: " +
         roundTripMs + " ms."] : [],
    failure: response ? null : (failure ||
        "The browser reports no status, which is what a CORS refusal, a " +
        "network failure or an aborted request looks like from script.")
  };
  log.debug("Leaving viewFromBrowser().");
  return view;
}

module.exports = {
  drawHttpExchange: drawHttpExchange,
  fetchHeaders: fetchHeaders,
  viewFromApiTrace: viewFromApiTrace,
  viewFromBrowser: viewFromBrowser
};
