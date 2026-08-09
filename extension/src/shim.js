// File: shim.js  —  runs in the PAGE's world (MAIN), on an armed origin only.
//
// ---------------------------------------------------------------------------
// The observer. It wraps navigator.credentials.create and .get, lets the call
// through untouched, and copies what passed. It is the only part of this
// extension that runs inside somebody else's page, so it is the part where being
// read-only has to be true rather than intended.
//
// FOUR RULES. Three of them are the ways a well-meaning wrapper stops being
// read-only, and the fourth is the one that breaks ceremonies.
//
// 1. NO MUTATION. Capture works on a structuredClone. A site holding a reference
//    to its own options object cannot observe this extension touching it.
//
// 2. NO ORIGINATION, AND NO OTHER PATCHES. This never calls create/get itself,
//    and leaves the rest of CredentialsContainer alone — store() and
//    preventSilentAccess() stay unpatched, because hooking those is write-shaped
//    behaviour with no debugging value.
//
// 3. EXCEPTION TRANSPARENCY. Every failure inside capture is caught and dropped.
//    A site's ceremony must never fail *because the debugger was watching*, and
//    that is exactly the failure mode of a naive wrapper.
//
// 4. NO `await` BEFORE CALLING THROUGH. navigator.credentials.get() consumes
//    transient user activation, which is time-bounded. A shim that awaited a
//    config read or a message round-trip before invoking the real API could let
//    the activation lapse, and the site would see a NotAllowedError
//    indistinguishable from the user declining. So the real call is made
//    SYNCHRONOUSLY, in the same task, and every asynchronous thing this file
//    does happens after the real promise has been handed back.
//
//    This rule reads like a micro-optimisation and will be refactored away by
//    somebody unless this comment is here. Whether an origin is observed is
//    decided by NOT INJECTING THIS FILE — never by a check inside it.
//
// Nothing here reads or writes storage, and nothing here can block. It posts to
// the isolated-world relay and forgets.
// ---------------------------------------------------------------------------

(function () {
  "use strict";

  var CHANNEL = "idptools-webauthn-capture";
  var container = navigator.credentials;
  if (!container || typeof container.create !== "function") {
    return;
  }
  // Idempotent: a page that navigates within itself, or two registrations of the
  // same script, must not stack wrappers. A stacked wrapper would still be
  // read-only, but it would report every ceremony twice.
  if (container.__idptoolsObserved) {
    return;
  }

  var realCreate = container.create.bind(container);
  var realGet = container.get.bind(container);

  // Buffers are not structuredClone-transferable into a postMessage in a form
  // the other side can read as base64url, so they are converted here. Anything
  // that is not an ArrayBuffer or a view is left alone.
  function encode(value, depth) {
    if (depth > 6 || value === null || value === undefined) {
      return value;
    }
    if (value instanceof ArrayBuffer) {
      return { __b64u: toBase64url(new Uint8Array(value)) };
    }
    if (ArrayBuffer.isView(value)) {
      return { __b64u: toBase64url(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) };
    }
    if (Array.isArray(value)) {
      return value.map(function (v) { return encode(v, depth + 1); });
    }
    if (typeof value === "object") {
      var out = {};
      Object.keys(value).forEach(function (k) {
        out[k] = encode(value[k], depth + 1);
      });
      return out;
    }
    return value;
  }

  function toBase64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // The Level 3 JSON form, produced here rather than depended on: toJSON() is
  // absent from older Chrome (measured absent on 121, present on 151), and a
  // capture format that changed shape with the browser would be useless.
  function credentialToJson(credential) {
    var r = credential.response || {};
    var response = {};
    if (r.attestationObject) {
      response.clientDataJSON = toBase64url(new Uint8Array(r.clientDataJSON));
      response.attestationObject = toBase64url(new Uint8Array(r.attestationObject));
      if (typeof r.getTransports === "function") {
        response.transports = r.getTransports();
      }
      if (typeof r.getPublicKeyAlgorithm === "function") {
        response.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
      }
    } else {
      response.clientDataJSON = toBase64url(new Uint8Array(r.clientDataJSON));
      response.authenticatorData = toBase64url(new Uint8Array(r.authenticatorData));
      response.signature = toBase64url(new Uint8Array(r.signature));
      response.userHandle = r.userHandle ? toBase64url(new Uint8Array(r.userHandle)) : null;
    }
    return {
      id: credential.id,
      rawId: toBase64url(new Uint8Array(credential.rawId)),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: typeof credential.getClientExtensionResults === "function"
        ? credential.getClientExtensionResults() : {},
      response: response,
    };
  }

  function post(envelope) {
    // Rule 3: nothing in here may throw into the page.
    try {
      window.postMessage({ channel: CHANNEL, capture: envelope }, window.location.origin);
    } catch (e) {
      // The relay is not listening, the origin is opaque, or the payload will
      // not serialise. All of those cost this extension a capture and cost the
      // page nothing, which is the correct trade.
    }
  }

  function wrap(ceremony, real) {
    return function (options) {
      var startedAt = Date.now();
      var requestCopy = null;
      // Rule 1 and Rule 4: clone FIRST (cheap, synchronous), call through
      // immediately, and do nothing else before returning the real promise.
      try {
        requestCopy = encode(options && options.publicKey ? { publicKey: options.publicKey } : options, 0);
      } catch (e) {
        // An options object that will not clone is still a perfectly good
        // ceremony. Record that we could not read it rather than interfering.
        requestCopy = { __unreadable: String(e && e.message) };
      }

      var promise = real(options);

      // Everything from here is after the real call. It cannot affect activation
      // and it cannot delay the page.
      try {
        promise.then(function (credential) {
          var envelope = null;
          try {
            envelope = {
              v: 1, ceremony: ceremony, capturedAt: new Date().toISOString(),
              origin: window.location.origin,
              rpId: rpIdOf(options, ceremony),
              request: requestCopy,
              response: credentialToJson(credential),
              error: null,
              timing: { startedMs: 0, endedMs: Date.now() - startedAt },
              redacted: [],
            };
          } catch (e) {
            // Rule 3 again: a credential shape this code cannot read must not
            // become an exception in the page's own then().
            envelope = null;
          }
          if (envelope) {
            post(envelope);
          }
        }, function (err) {
          // A refused ceremony is a first-class capture: a NotAllowedError after
          // a thirty-second wait is one of the things a user most needs to see,
          // and a format that recorded only successes would throw it away.
          post({
            v: 1, ceremony: ceremony, capturedAt: new Date().toISOString(),
            origin: window.location.origin,
            rpId: rpIdOf(options, ceremony),
            request: requestCopy,
            response: null,
            error: { name: String(err && err.name), message: String(err && err.message) },
            timing: { startedMs: 0, endedMs: Date.now() - startedAt },
            redacted: [],
          });
        });
      } catch (e) {
        // `promise` was not a promise, or .then threw. The page's own call is
        // unaffected — it already has the value `real()` returned.
      }

      return promise;
    };
  }

  function rpIdOf(options, ceremony) {
    try {
      var pk = options && options.publicKey;
      if (!pk) {
        return window.location.hostname;
      }
      if (ceremony === "create") {
        return (pk.rp && pk.rp.id) || window.location.hostname;
      }
      return pk.rpId || window.location.hostname;
    } catch (e) {
      // Unreadable options: the host is the only honest answer, since the
      // browser would have defaulted to it anyway.
      return window.location.hostname;
    }
  }

  try {
    container.create = wrap("create", realCreate);
    container.get = wrap("get", realGet);
    Object.defineProperty(container, "__idptoolsObserved", { value: true, enumerable: false });
  } catch (e) {
    // A CredentialsContainer this extension cannot patch is one it does not
    // observe. Leaving the page working is more important than observing it.
  }
})();
