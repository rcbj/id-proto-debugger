// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: panes.js
//
// The collapsible-pane behaviour of the SAML pages (saml_common.css's
// `saml-pane`, `saml-legend`, `saml-pane-body` and the `saml-toggle` switch),
// for pages that are not SAML ones: the XACML editor, GNAP, the smart-card
// page, and the two WebAuthn pages, whose panes are `wa-pane` fieldsets with
// the same `saml-pane-body` inside (their look is webauthn.css; the switch
// and the legends' triangle are css/panes.css). A pane is
// collapsed by setting its body's inline display to none, which is also what
// saml_common.css reads to turn the legend's triangle.
//
// Markup this expects:
//
//   <fieldset class="saml-pane" id="X">
//     <legend class="saml-legend" onclick="return M.togglePane('X_body');">
//     <div class="saml-pane-body" id="X_body">...</div>
//   </fieldset>
//
//   <label class="saml-toggle">
//     <input type="checkbox" id="T" checked
//            onchange="return M.setAllPanes(this.checked);">
//     <span class="saml-toggle-slider"></span>
//     <span class="saml-toggle-text">Collapse all panes</span>
//   </label>
//
// where M is the page's bundle, which re-exports these.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "panes",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function bodies() {
  log.debug("Entering bodies().");
  var list = Array.prototype.slice.call(
      document.querySelectorAll(".saml-pane > .saml-pane-body, " +
                                 ".wa-pane > .saml-pane-body"));
  log.debug("Leaving bodies(). " + list.length);
  return list;
}

// Keep the switch's label in step with what it would do next.
function syncSwitch() {
  log.debug("Entering syncSwitch().");
  var anyOpen = bodies().some(function (b) {
    return b.style.display !== "none";
  });
  var box = document.querySelector(".saml-controls .saml-toggle input");
  if (box) {
    box.checked = anyOpen;
  }
  var text = document.querySelector(".saml-controls .saml-toggle-text");
  if (text) {
    text.textContent = anyOpen ? "Collapse all panes" : "Expand all panes";
  }
  log.debug("Leaving syncSwitch().");
}

function setOpen(body, open) {
  log.debug("Entering setOpen().");
  if (body) {
    body.style.display = open ? "block" : "none";
  }
  log.debug("Leaving setOpen().");
}

// A pane's legend was clicked.
function togglePane(bodyId) {
  log.debug("Entering togglePane(). " + bodyId);
  var b = document.getElementById(bodyId);
  if (b) {
    setOpen(b, b.style.display === "none");
  }
  syncSwitch();
  log.debug("Leaving togglePane().");
  return false;
}

// The collapse all / expand all switch.
function setAllPanes(expand) {
  log.debug("Entering setAllPanes(). expand=" + expand);
  bodies().forEach(function (b) {
    setOpen(b, !!expand);
  });
  syncSwitch();
  log.debug("Leaving setAllPanes().");
  return false;
}

// Open one pane, collapse every other, and bring it into view.
function focusPane(paneId) {
  log.debug("Entering focusPane(). " + paneId);
  var pane = document.getElementById(paneId);
  bodies().forEach(function (b) {
    setOpen(b, !!pane && pane.contains(b));
  });
  syncSwitch();
  if (pane && pane.scrollIntoView) {
    pane.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  log.debug("Leaving focusPane().");
  return false;
}

// Collapse the panes whose ids are given, at load: the ones a page starts
// with closed.
function collapse(paneIds) {
  log.debug("Entering collapse().");
  (paneIds || []).forEach(function (id) {
    var pane = document.getElementById(id);
    var b = pane ? pane.querySelector(".saml-pane-body") : null;
    setOpen(b, false);
  });
  syncSwitch();
  log.debug("Leaving collapse().");
}

module.exports = {
  togglePane: togglePane,
  setAllPanes: setAllPanes,
  focusPane: focusPane,
  collapse: collapse,
  syncSwitch: syncSwitch
};
