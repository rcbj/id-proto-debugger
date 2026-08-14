// coverage_beacon.js
//
// Ships browser-side code coverage to the client server so it survives page
// navigations (Istanbul resets window.__coverage__ on every full page load).
// This file is appended to the browserified bundles ONLY in the COVERAGE build
// (see client/Dockerfile); it is inert if the bundle is not instrumented
// because window.__coverage__ will be undefined.
//
// Coverage is shipped ASYNCHRONOUSLY while the page is alive. We cannot ship at
// dismissal time: Chrome drops synchronous XMLHttpRequest fired during page
// dismissal (pagehide/unload/visibilitychange-to-hidden), so a sync XHR there
// is silently discarded and never reaches the server. navigator.sendBeacon() /
// fetch(keepalive) are also out because coverage payloads routinely exceed
// their ~64KB body limit. Instead we POST the current window.__coverage__ on a
// short interval; since Istanbul accumulates coverage live, the last snapshot
// before a navigation captures that page's coverage. The client server writes
// each POST as a separate file and nyc merges them, so repeated snapshots are
// harmless (merge unions covered statements; inflated hit counts don't affect
// coverage %).

(function () {
  // The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
  // wants a `log` here, and bunyan is not reachable from this file: the
  // Dockerfile's coverage step APPENDS it to an already-browserified bundle
  // (`cat src/coverage_beacon.js >> public/js/${src_name}.js`), so it is never
  // run through browserify or envify at all. `require` and `process` are both
  // undefined in the browser, so a top-level `require("bunyan")` here is not a
  // logger but an uncaught ReferenceError on every instrumented page — which
  // is what it was between 2026-08-14's style sweep and this fix, and it
  // failed the 12 tests that assert the browser console is clean.
  // So this is the same call shape backed by console. Debug output is off by
  // default, so an ordinary run stays quiet; flip DEBUG to follow a call
  // through. Note the methods below are the one place the convention cannot
  // apply — a log line inside log.debug() is infinite recursion.
  //
  // It lives INSIDE this IIFE rather than at the top of the file, unlike the
  // other console-backed shims in the tree, because this file is appended to a
  // bundle: at the top it would be three new `var`s in the PAGE's global scope
  // on every instrumented page, and `log` is a name a page script could
  // plausibly want. Everything that logs here is in this function anyway.
  var DEBUG = false;
  var LOG_TAG = "[coverage_beacon]";
  var log = {
    debug: function () {
      if (!DEBUG) {
        return;
      }
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
  if (typeof window === "undefined") {
    return;
  }
  function shipCoverage() {
    log.debug("Entering shipCoverage().");
    try {
      if (!window.__coverage__) {
        log.debug("Leaving shipCoverage().");
        return;
      }
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "/coverage",
               true); // async: works outside page dismissal
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(JSON.stringify(window.__coverage__));
    } catch (e) {
      // Never let coverage shipping interfere with the page.
    }
    log.debug("Leaving shipCoverage().");
  }
  // Primary mechanism: periodic snapshot while the page is alive.
  setInterval(shipCoverage, 1000);
  // Best-effort extra snapshot as the page is being hidden/navigated away.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") {
      shipCoverage();
    }
  });
  window.addEventListener("pagehide", shipCoverage);
})();
