// File: browser_flags.js
//
// ---------------------------------------------------------------------------
// The Chrome flags a browser test needs to reach THIS suite's services, for the
// two ways the environment can be hostile to it. Both are invisible in the code
// under test and both produce failures that name something else entirely, which is
// why they live here with the reasoning attached.
//
// 1. PRIVATE NETWORK ACCESS / MIXED CONTENT — needed when the page is a deployed
//    https site and the services it must talk to are on this host's loopback
//    (./remote-run-tests.sh: Keycloak :8080, the mock STS :8081, the WS-Fed
//    Keycloak :8082, walt.id :7005 and :7003). A request from a public origin to a
//    private/local address is a Private Network Access request, and Chrome blocks
//    it or demands a preflight no plain HTTP service answers.
//
//    The failure says nothing about the network: the page's fetch simply never
//    resolves, so a status pane stays empty and the test reports a timeout waiting
//    for metadata, a verdict, or a credential. Every other browser test in this
//    suite has carried these flags for that reason; the four SD-JWT VC tests did
//    not, and all four failed against https://test.idptools.com while passing
//    locally, where an http page talking to http localhost raises none of this.
//
// 2. SECURE CONTEXT — needed when the page is served over plain HTTP from a name
//    that is not localhost, which is the containerized stack (http://client:3000).
//    `window.crypto.subtle` exists only in a secure context: HTTPS, or
//    localhost/127.0.0.1/[::1]. Everything else gets `crypto.subtle === undefined`,
//    so a page that signs, verifies, hashes or encrypts silently has no crypto —
//    surfacing as a signature that "does not verify with any key" (each importKey
//    throws and is skipped) and as timeouts waiting for holder key pairs, proofs of
//    possession and Key Binding JWTs that are never produced.
//
//    --unsafely-treat-insecure-origin-as-secure fixes that, and Chrome ignores it
//    unless a --user-data-dir is set too, so the two go together and the profile is
//    a throwaway. It is applied only where it is needed: an https or localhost
//    origin is already a secure context.
//
// Any new browser test should call addBrowserAccessFlags(). It is required for
// anything that signs, verifies, encrypts or hashes (client/src/jwt_tools.js,
// jose_jwe.js, vci_wallet.js, sd_jwt_vc.js, sd_jwt_vp.js, metadata_client.js,
// token_detail.js, digital_signature.js, encoding_tools.js), and for anything whose
// page must fetch one of this suite's local services.
// ---------------------------------------------------------------------------
const fs = require("fs");
const os = require("os");
const path = require("path");

// Origins the browser already treats as trustworthy, so no secure-context relaxing
// is needed (or possible — the flag rejects them).
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

// Adds both sets of flags as appropriate. Returns the same options object so it can
// be used inline.
function addBrowserAccessFlags(options, baseUrl) {
  // (1) Always: the services this suite runs are on loopback, and any page that is
  // not itself on loopback needs these to reach them. Harmless when it is.
  options.addArguments("--allow-running-insecure-content");
  options.addArguments("--disable-features=BlockInsecurePrivateNetworkRequests," +
                       "PrivateNetworkAccessSendPreflights,LocalNetworkAccessChecks");

  // (2) Only for an origin that would not otherwise be a secure context.
  var origin = originOf(baseUrl);
  if (origin && !ALREADY_SECURE.test(origin)) {
    var profile = fs.mkdtempSync(path.join(os.tmpdir(), "chrome-secure-origin-"));
    options.addArguments("--unsafely-treat-insecure-origin-as-secure=" + origin);
    options.addArguments("--user-data-dir=" + profile);
  }
  return options;
}

module.exports = {
  addBrowserAccessFlags: addBrowserAccessFlags,
  originOf: originOf
};
