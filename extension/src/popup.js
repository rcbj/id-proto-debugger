// File: popup.js — the extension's own surface.
//
// Arming happens HERE and cannot happen anywhere else: permissions.request()
// needs a user gesture in the extension's own UI, so the debugger's pages can
// only tell the user to click this. That is a browser rule and the right one —
// a web page must not be able to talk a browser into observing another origin.
"use strict";

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// the extension is loaded raw by the browser, with no module system.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[popup]";
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

function byId(id) {
  log.debug("Entering byId().");
  log.debug("Leaving byId().");
  return document.getElementById(id);
}

function send(msg) {
  log.debug("Entering send().");
  log.debug("Leaving send().");
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(msg, function (r) { resolve(r || {}); });
  });
}

async function refresh() {
  log.debug("Entering refresh().");
  const r = await send({ type: "getCaptures" });
  const state = byId("state");
  if (r.armed) {
    state.className = "state on";
    state.textContent = "Observing " + r.armed.origin + " — " +
      (r.captures || []).length + " capture(s), until " +
      new Date(r.armed.expires).toLocaleTimeString() + ".";
    byId("origin").value = r.armed.origin;
  } else {
    state.className = "state off";
    state.textContent = "Inactive — nothing is being observed.";
  }
  log.debug("Leaving refresh().");
}

byId("arm").addEventListener("click", async function () {
  const raw = byId("origin").value.trim();
  let origin;
  try {
    origin = new URL(raw).origin;
  } catch (e) {
    byId("state").className = "state on";
    byId("state").textContent =
        "That is not a URL. Enter an origin such as https://login.example.com.";
    return;
  }
  // The browser asks, naming the single host. Nothing here can widen that.
  const granted = await chrome.permissions.request({ origins: [origin +
      "/*"] });
  if (!granted) {
    byId("state").className = "state off";
    byId("state").textContent =
         "Permission declined — nothing is being observed.";
    return;
  }
  await send({ type: "arm", origin: origin });
  await refresh();
});

byId("disarm").addEventListener("click", async function () {
  const r = await send({ type: "getCaptures" });
  if (r.armed) {
    // Hand the host permission back as well: a disarm that kept it would leave
    // the extension able to start watching again without asking.
    try {
      await chrome.permissions.remove({ origins: [r.armed.origin + "/*"] });
    } catch (e) {
      // Some origins cannot be given back (a manifest-granted one). The scripts
      // are unregistered either way, which is what stops the observing.
    }
  }
  await send({ type: "disarm", reason: "the user asked" });
  await refresh();
});

byId("uninstall").addEventListener("click", function () {
  // The browser's own confirmation dialog, not ours.
  chrome.management.uninstallSelf({ showConfirmDialog: true });
});

refresh();
