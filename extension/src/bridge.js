// File: bridge.js  —  ISOLATED world, on the DEBUGGER's own origins only.
//
// How captures reach the debugger's pages. The page cannot talk to an extension
// directly in a way that works in both browsers (externally_connectable is
// Chrome-only), so this content script sits on the debugger's origins and
// answers a namespaced window.postMessage handshake.
//
// It hands over captures and the extension's version, and takes two commands:
// clear the buffer, and disarm (which the workflow's completion pane uses, so
// that finishing a debugging session ends the observation without the user
// having to remember).
//
// The version travels because an unpacked extension does not auto-update: a
// stale copy speaking capture format v1 to a page expecting v2 would present as
// a mysteriously empty inbox rather than as a mismatch.
(function () {
  "use strict";
  var REQ = "idptools-webauthn-request";
  var RES = "idptools-webauthn-response";

  window.addEventListener("message", function (event) {
    if (event.source !== window) {
      return;
    }
    var data = event.data;
    if (!data || data.channel !== REQ) {
      return;
    }
    var want = String(data.action || "");
    var type = want === "clear" ? "clear" : (want === "disarm" ? "disarm" : "getCaptures");
    try {
      chrome.runtime.sendMessage({ type: type, reason: "the debugger finished a session" },
        function (result) {
          window.postMessage({ channel: RES, id: data.id, result: result || null },
                             window.location.origin);
        });
    } catch (e) {
      window.postMessage({ channel: RES, id: data.id, error: String(e && e.message) },
                         window.location.origin);
    }
  }, false);

  // Presence, two ways, because the page may load before or after this script.
  //
  // The attribute is the reliable one: it is set synchronously at
  // document_start, so a page can read it whenever it likes and tell "no
  // extension" from "not asked yet" without a round trip. The postMessage is for
  // a page already listening.
  try {
    document.documentElement.setAttribute(
      "data-idptools-webauthn-observer", chrome.runtime.getManifest().version_name ||
        chrome.runtime.getManifest().version);
  } catch (e) {
    // No documentElement yet (document_start on an odd document), or no manifest
    // access. The handshake below still works.
  }
  window.postMessage({ channel: RES, id: "hello", result: { present: true } },
                     window.location.origin);
})();
