// File: browser_secure_origin.js
//
// ---------------------------------------------------------------------------
// Make the page's origin a SECURE CONTEXT for the browser under test.
//
// `window.crypto.subtle` — all of Web Crypto — exists only in a secure context:
// HTTPS, or an origin the browser treats as trustworthy anyway, which in practice
// means localhost / 127.0.0.1 / [::1]. Everything else on plain HTTP gets
// `crypto.subtle === undefined`.
//
// That is a difference between the two ways this suite runs, and it is invisible
// until something asserts on it:
//
//   * locally the debugger is at http://localhost:3000 — trustworthy, Web Crypto
//     works, every SD-JWT VC test passes;
//   * in the containerized stack it is at http://client:3000 — plain HTTP on a DNS
//     name, NOT trustworthy, so there is no Web Crypto at all.
//
// The symptom is not an exception in one place. It is several unrelated-looking
// failures: a signed_metadata signature that "does not verify with any key"
// (importKey throws, each key is skipped, and the loop ends with nothing having
// verified), and timeouts waiting for holder key pairs, proofs of possession and
// Key Binding JWTs that are never produced. Diagnosing that from the outside took
// a full round trip, hence this file and the length of this comment.
//
// --unsafely-treat-insecure-origin-as-secure names origins to treat as
// trustworthy. Chrome ignores it unless a --user-data-dir is set as well, so the
// two flags always go together and the profile is a throwaway.
//
// Pages that need this: anything using client/src/jwt_tools.js, jose_jwe.js,
// vci_wallet.js, sd_jwt_vc.js, sd_jwt_vp.js, metadata_client.js (signature
// verification), token_detail.js, digital_signature.js or encoding_tools.js —
// i.e. most of the app. Any NEW browser test that touches signing, verification,
// encryption or hashing should call this too.
// ---------------------------------------------------------------------------
const fs = require("fs");
const os = require("os");
const path = require("path");

// Origins the browser already treats as trustworthy, so the flag is unnecessary.
const ALREADY_SECURE = /^https:|^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i;

function originOf(url) {
  var s = String(url || "").trim();
  if (!s) return "";
  try {
    return new URL(s).origin;
  } catch (e) {
    // Not parseable as a URL: fall back to the string without a trailing slash,
    // which is what the callers pass in practice ("http://client:3000").
    return s.replace(/\/+$/, "");
  }
}

// Adds the flags to a selenium-webdriver chrome.Options when, and only when, the
// origin under test would not otherwise be a secure context. Returns the same
// options object so it can be used inline.
function addSecureOriginFlags(options, baseUrl) {
  var origin = originOf(baseUrl);
  if (!origin || ALREADY_SECURE.test(origin)) {
    return options;
  }
  var profile = fs.mkdtempSync(path.join(os.tmpdir(), "chrome-secure-origin-"));
  options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + origin);
  options.addArguments("--user-data-dir=" + profile);
  return options;
}

module.exports = {
  addSecureOriginFlags: addSecureOriginFlags,
  originOf: originOf
};
