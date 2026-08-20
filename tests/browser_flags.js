// File: browser_flags.js
//
// ---------------------------------------------------------------------------
// The Chrome flags a browser test needs to reach THIS suite's services, for the
// two ways the environment can be hostile to it. Both are invisible in the code
// under test and both produce failures that name something else entirely, which
// is why they live here with the reasoning attached.
//
// 1. PRIVATE NETWORK ACCESS / MIXED CONTENT — needed when the page is a
//    deployed https site and the services it must talk to are on this host's
//    loopback (./remote-run-tests.sh: Keycloak :8080, the mock STS :8081, the
//    WS-Fed Keycloak :8082, walt.id :7005 and :7003). A request from a public
//    origin to a private/local address is a Private Network Access request, and
//    Chrome blocks it or demands a preflight no plain HTTP service answers.
//
//    The failure says nothing about the network: the page's fetch simply never
//    resolves, so a status pane stays empty and the test reports a timeout
//    waiting for metadata, a verdict, or a credential. Every other browser test
//    in this suite has carried these flags for that reason; the four SD-JWT VC
//    tests did not, and all four failed against https://test.idptools.com while
//    passing locally, where an http page talking to http localhost raises none
//    of this.
//
// 2. SECURE CONTEXT — needed when the page is served over plain HTTP from a
//    name that is not localhost, which is the containerized stack
//    (http://client:3000). `window.crypto.subtle` exists only in a secure
//    context: HTTPS, or localhost/127.0.0.1/[::1]. Everything else gets
//    `crypto.subtle === undefined`, so a page that signs, verifies, hashes or
//    encrypts silently has no crypto — surfacing as a signature that "does not
//    verify with any key" (each importKey throws and is skipped) and as
//    timeouts waiting for holder key pairs, proofs of possession and Key
//    Binding JWTs that are never produced.
//
//    --unsafely-treat-insecure-origin-as-secure fixes that, and Chrome ignores
//    it unless a --user-data-dir is set too, so the two go together and the
//    profile is a throwaway. It is applied only where it is needed: an https or
//    localhost origin is already a secure context.
//
// 3. WEB CRYPTO Ed25519 — needed by a page that generates, imports or signs
//    with an Ed25519 key through `crypto.subtle`, which in this tree is the PKI
//    page and nothing else (client/src/digital_signature.js reaches Ed25519
//    through @noble, and is unaffected). Chrome shipped Ed25519 in the Web
//    Cryptography API on by default in **Chrome 137**; the tests image pins
//    **Chrome 121**, where it exists but is off, so every call naming it throws
//
//        Failed to execute 'generateKey' on 'SubtleCrypto':
//        Algorithm: Unrecognized name
//
//    addWebCryptoEd25519Flags() turns exactly that feature on. See its own
//    comment for why the failure arrives with 'importKey' in it instead.
//
// Any new browser test should call addBrowserAccessFlags(). It is required for
// anything that signs, verifies, encrypts or hashes (client/src/jwt_tools.js,
// jose_jwe.js, vci_wallet.js, sd_jwt_vc.js, sd_jwt_vp.js, metadata_client.js,
// token_detail.js, digital_signature.js, encoding_tools.js), and for anything
// whose page must fetch one of this suite's local services.
// ---------------------------------------------------------------------------
const fs = require("fs");
const os = require("os");
const path = require("path");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "browser_flags",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Origins the browser already treats as trustworthy, so no secure-context
// relaxing is needed (or possible — the flag rejects them).
const ALREADY_SECURE =
    /^https:|^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i;

function originOf(url) {
  log.debug("Entering originOf().");
  var s = String(url || "").trim();
  if (!s) {
    log.debug("Leaving originOf().");
    return "";
  }
  try {
    log.debug("Leaving originOf().");
    return new URL(s).origin;
  } catch (e) {
    // Not parseable as a URL: fall back to the string without a trailing slash,
    // which is what the callers pass in practice ("http://client:3000").
    log.debug("Leaving originOf().");
    return s.replace(/\/+$/, "");
  }
}

// Adds both sets of flags as appropriate. Returns the same options object so it
// can be used inline.
function addBrowserAccessFlags(options, baseUrl) {
  log.debug("Entering addBrowserAccessFlags().");
  // (1) Always: the services this suite runs are on loopback, and any page that
  // is not itself on loopback needs these to reach them. Harmless when it is.
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
                       "PrivateNetworkAccessSendPreflights," +
                           "LocalNetworkAccessChecks");

  // (2) Only for an origin that would not otherwise be a secure context.
  var origin = originOf(baseUrl);
  if (origin && !ALREADY_SECURE.test(origin)) {
    var profile = fs.mkdtempSync(path.join(os.tmpdir(),
        "chrome-secure-origin-"));
    options.addArguments("--unsafely-treat-insecure-origin-as-secure=" +
                         origin);
    options.addArguments("--user-data-dir=" + profile);
  }
  log.debug("Leaving addBrowserAccessFlags().");
  return options;
}

// (3) Ed25519 in Web Crypto, for the browser that has it and does not offer it.
//
// Chrome enabled Ed25519 in the Web Cryptography API by default in Chrome 137.
// The tests image pins Chrome 121 (see tests/Dockerfile), where the
// implementation is present but gated behind its Blink runtime flag, so
// generateKey/importKey/sign naming { name: 'Ed25519' } all reject with
//
//   Failed to execute 'generateKey' on 'SubtleCrypto':
//       Algorithm: Unrecognized name
//
// The narrow --enable-blink-features=WebCryptoCurve25519 is used rather than
// --enable-experimental-web-platform-features, which also works: this turns on
// ONE feature, where the broader flag turns on every unshipped web platform
// feature Chrome 121 carries and changes far more of the page than the test is
// about. A browser that already has Ed25519 ignores an already-enabled feature
// name, so this is a no-op from Chrome 137 on and on a host run.
//
// The failure it prevents does not name Ed25519 or the missing flag, and it
// does not name generateKey either. On the PKI page the key pair and the
// certificate are one button (pki.js's generateAndIssue()), so generation
// fails, its message is replaced by the next one, and what the test reports is
//
//   issuing Page View Ed25519 failed: Could not issue the certificate:
//       Failed to execute 'importKey' on 'SubtleCrypto':
//           Algorithm: Unrecognized name
//
// naming importKey — a call made on the key pair the page still had — on a
// certificate that had no key of its own. That cost the containerized run of
// 2026-08-19, where it was the only failure of 182 jobs and where a HOST run
// with any current Chrome passes.
function addWebCryptoEd25519Flags(options) {
  log.debug("Entering addWebCryptoEd25519Flags().");
  options.addArguments("--enable-blink-features=WebCryptoCurve25519");
  log.debug("Leaving addWebCryptoEd25519Flags().");
  return options;
}

module.exports = {
  addBrowserAccessFlags: addBrowserAccessFlags,
  addWebCryptoEd25519Flags: addWebCryptoEd25519Flags,
  originOf: originOf
};
