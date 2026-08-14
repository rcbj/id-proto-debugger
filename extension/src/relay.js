// File: relay.js  —  ISOLATED world, on an armed origin, beside shim.js.
//
// The shim runs in the page's world so it can see navigator.credentials; that
// world has no extension APIs. This file is the other half: it listens for the
// shim's window.postMessage and forwards to the background. Two content scripts
// on one origin, in two worlds, because neither can do the other's job.
//
// It validates the channel and the source before forwarding. A page can post
// anything it likes to itself, so a capture arriving here is untrusted input —
// it is stored and displayed, never executed, and the debugger's pages render
// it with textContent only.

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// the extension is loaded raw by the browser, with no module system.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[relay]";
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

(function () {
  "use strict";
  var CHANNEL = "idptools-webauthn-capture";
  window.addEventListener("message", function (event) {
    if (event.source !== window) {
      return;
    }
    var data = event.data;
    if (!data || data.channel !== CHANNEL || !data.capture) {
      return;
    }
    try {
      chrome.runtime.sendMessage({ type: "capture", capture: data.capture });
    } catch (e) {
      // The service worker is asleep or the extension is being unloaded. The
      // ceremony is already complete and the page is unaffected; only the
      // capture is lost.
    }
  }, false);
})();
