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
//    **--allow-running-insecure-content IS IGNORED BY THE OLD HEADLESS
//    IMPLEMENTATION, so a test carrying it is not necessarily covered by it.**
//    A test that asks for bare `--headless` rather than `--headless=new` gets
//    headless_shell, and in the Chrome 121 this image pins that binary blocks
//    the mixed-content fetch anyway: the XHR completes with `readyState 4,
//    status 0` and no console entry naming mixed content. Measured directly on
//    121.0.6167.85 through this suite's own chromedriver — an https page
//    fetching an http origin, both flags identical, the ONLY difference being
//    the headless mode: `--headless` fails, `--headless=new` returns 200.
//    --unsafely-treat-insecure-origin-as-secure on the target origin does NOT
//    rescue it, so section 2's flag is no substitute.
//
//    THAT COST THE CONTAINERIZED RUN OF 2026-08-31 — thirteen of its fourteen
//    failures. Once the api and the client moved to https
//    (common/tls_listener.js), every page in the suite became an https origin
//    while Keycloak stayed on http://keycloak:8080, so the discovery XHR the
//    OAuth2/OIDC page makes became mixed content for the first time. The
//    eleven scripts that still asked for bare `--headless` all failed at the
//    same line — `Waiting for element to be located By(css selector,
//    .btn_oidc_populate_meta_data)` — because that button is only rendered
//    when the discovery document arrives, so what the log named was a missing
//    button on a page that was fine. The jobs that populate the same metadata
//    from the same Keycloak under `--headless=new` (oidc_flows.js) passed in
//    half a second on the same run, which is the shape to look for: a failure
//    that splits along the headless mode and nothing else.
//
//    It does NOT reproduce on ./local-run-tests.sh, and that is the second
//    half of why it went unseen: there Keycloak is http://localhost:8080,
//    which Chrome already counts as potentially trustworthy, so nothing about
//    the request is mixed content and the old implementation has nothing to
//    block. Only the containerized stack gives Keycloak a name that is not
//    loopback.
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

// THE api's OWN ORIGIN, AS THIS PROCESS WAS TOLD TO REACH IT.
//
// Read from the environment for the same reason addStsTrustFlags() reads
// STS_SPKI_PIN there: the launchers already publish it, every caller of
// addBrowserAccessFlags() needs the same answer, and a per-test argument is a
// per-test chance to forget.
//
// TWO NAMES BECAUSE THE LAUNCHERS EXPORT DIFFERENT ONES, and neither alone
// covers every stack. `API_BASE_URL` is the SAML / WS-Federation variable —
// the address an identity provider is told to POST to (common/common.sh) —
// and remote-run-tests.sh exports it. `API_URL` is a process's own view of
// that same service, and it is what tests/run-tests-in-container.sh exports
// on the containerized stack, which is the one where any of this matters.
// Both unset is a run that never involves the api, and nothing is added.
function apiOrigins() {
  log.debug("Entering apiOrigins().");
  var found = [process.env.API_BASE_URL, process.env.API_URL]
    .map(originOf)
    .filter(function (one) {
      return one;
    });
  log.debug("Leaving apiOrigins(). " + found.length + " address(es).");
  return found;
}

// Adds both sets of flags as appropriate. Returns the same options object so it
// can be used inline. `extraOrigins` is optional and is for a test that POSTs
// to a service neither the base URL nor the api covers; the api's own address
// arrives without anybody passing it.
function addBrowserAccessFlags(options, baseUrl, extraOrigins) {
  log.debug("Entering addBrowserAccessFlags().");
  // (1) Always: the services this suite runs are on loopback, and any page that
  // is not itself on loopback needs these to reach them. Harmless when it is.
  options.addArguments("--allow-running-insecure-content");
  options.addArguments(
      "--disable-features=BlockInsecurePrivateNetworkRequests," +
                       "PrivateNetworkAccessSendPreflights," +
                           "LocalNetworkAccessChecks");

  // ---------------------------------------------------------------------
  // (2) EVERY INSECURE ORIGIN THIS SUITE OWNS, not just the page's own, and
  // the second one is what cost the containerized run of 2026-08-27 — 53 of
  // its 77 failures, across WS-Federation, WS-Trust delegation and the
  // federation grid.
  //
  // The flag was here for SECURE CONTEXT (see the header): a page on
  // http://client:3000 has no `crypto.subtle` until Chrome is told to treat
  // that origin as trustworthy. What it ALSO governs is Chrome's INSECURE
  // FORM SUBMISSION interstitial: a form on a potentially-trustworthy page
  // whose action is not potentially-trustworthy is not submitted at all, and
  // the browser stops on a full-page warning titled "Form is not secure"
  // ("The information you're about to submit is not secure ... Go back /
  // Send anyway").
  //
  // Every SAML and WS-Federation response in this suite is exactly that
  // shape. The mock STS serves https (STS_HTTPS=true in every compose file
  // here, because the RFC 9700 pass is only honest over TLS), and its
  // auto-posting form targets the api's landing — http://api:4000/samlacs,
  // http://api:4000/wsfed. Secure page, insecure action, no POST.
  //
  // IT DOES NOT HAPPEN ON A HOST RUN, and that is why it went unseen for so
  // long: there the api is http://localhost:4000, and Chrome already counts
  // loopback as potentially trustworthy, so the interstitial never fires and
  // the flag has nothing to do. It also does not happen under the OLD
  // headless implementation, which is what the SAML jobs that PASSED on the
  // same run use — `--headless` rather than `--headless=new` — so the run
  // failed in a pattern that looked like a WS-Federation and federation
  // problem and named a Lambda@Edge, an assertion consumer service and a
  // missing sign-in screen. The one thing none of those messages named was
  // the browser.
  //
  // The origins are ONE comma-separated flag: Chrome keeps the last
  // occurrence of a switch, so a second --unsafely-treat-insecure-origin-as-
  // secure would silently discard the first.
  // ---------------------------------------------------------------------
  var insecure = [originOf(baseUrl)]
    .concat(apiOrigins())
    .concat([].concat(extraOrigins || []).map(originOf))
    .filter(function (one) {
      return one && !ALREADY_SECURE.test(one);
    })
    .filter(function (one, at, all) {
      return all.indexOf(one) === at;
    });
  if (insecure.length) {
    // Chrome ignores --unsafely-treat-insecure-origin-as-secure unless a
    // --user-data-dir is set too, so the two go together and the profile is a
    // throwaway.
    var profile = fs.mkdtempSync(path.join(os.tmpdir(),
        "chrome-secure-origin-"));
    options.addArguments("--unsafely-treat-insecure-origin-as-secure=" +
                         insecure.join(","));
    options.addArguments("--user-data-dir=" + profile);
    log.info("Treating " + insecure.join(", ") + " as secure origin(s).");
  }

  // (4) The mock STS's key, when a run has one. See addStsTrustFlags() below
  // for why it is a pin rather than --ignore-certificate-errors, and why it
  // adds nothing at all when STS_SPKI_PIN is unset.
  addStsTrustFlags(options);
  log.debug("Leaving addBrowserAccessFlags().");
  return options;
}

// (4) THE MOCK STS'S CERTIFICATE, AS AN EXACT KEY PIN.
//
// That service serves its main port over TLS in every stack here
// (STS_HTTPS=true in local-tests.yml, docker-compose-run-tests.yml and
// keycloak-tests.yml), because the RFC 9700 pass is a TRUST REALM on the one
// instance now rather than a second container — a realm binds no socket of its
// own — and that pass is only honest over https, since requirement 8.1 is that
// every configured endpoint is https and the client under test enforces it.
//
// The certificate is SELF-SIGNED AND REGENERATED ON EVERY START of that
// service, so no browser profile, image or CA bundle can hold an anchor for it:
// it does not exist until the mock is up. common/common.sh's
// trustStsCertificate() fetches it once the service answers and exports
// STS_SPKI_PIN — the base64 SHA-256 of its SubjectPublicKeyInfo — and this is
// what puts that in front of Chrome.
//
// --ignore-certificate-errors-spki-list TRUSTS THAT ONE KEY AND NOTHING ELSE.
// It is a truststore of a single entry: a different self-signed certificate,
// including the one that same mock will generate on its next start, still meets
// an interstitial. The blunt --ignore-certificate-errors was rejected for the
// reason a suite like this one exists — url_safety_schemes.js, api_tls_probe.js
// and api_ssrf_guard.js are about certificates being REFUSED, and a flag that
// accepts every certificate makes those pass without testing anything.
//
// A NO-OP WHEN THE PIN IS UNSET, which is every run against a mock on plain
// http and every job that never touches one. Nothing is added to the command
// line, so a browser that had no reason to meet this certificate is exactly the
// browser it was before.
//
// It is called from addBrowserAccessFlags() below, so the twenty-odd tests that
// use that helper get it without an edit. The SIX that build their Chrome
// options by hand (wstrust.js, wstrust_operation_history.js,
// oauth2_metadata_rfc8414.js, saml11_sso.js, saml_sso.js, saml_logout.js) call
// it directly, and a seventh, rfc9700_flows.js, calls it in place of the blunt
// flag it used to carry.
//
// WHAT IT LOOKS LIKE WHEN ONE OF THEM IS MISSED, because two of the six were:
// saml_sso.js and saml_logout.js drove Chrome straight at the mock's https
// origin with no pin, met the certificate interstitial, and reported that "the
// identity provider never showed its sign-in screen (no #username field)" —
// four jobs naming a login form, on a page titled `Privacy error`. Adding the
// call is one line; finding out that it was the missing line is not.
//
// TWO PINS NOW, AND THE FLAG TAKES A LIST. Since the api and the client serve
// TLS as well (common/tls_listener.js), a browser here meets TWO self-signed
// certificates: the mock's, regenerated on its every start, and the stack's
// own, generated per run by common/common.sh's generateStackTlsCertificate().
// `--ignore-certificate-errors-spki-list` is comma-separated, and — this is
// the part that bites — CHROME KEEPS ONLY THE LAST OCCURRENCE OF A SWITCH, so
// adding the flag twice silently discards the first pin rather than merging
// them. The same trap is documented above for
// --unsafely-treat-insecure-origin-as-secure, and it is the same fix: build
// the list, add the flag once.
//
// Either pin may be absent — a run against a plain-http mock, a stack with TLS
// off — and an absent one contributes nothing rather than an empty list entry,
// which Chrome would read as a pin that matches no key.
function addStsTrustFlags(options) {
  log.debug("Entering addStsTrustFlags().");
  var pins = [process.env.STS_SPKI_PIN, process.env.STACK_TLS_SPKI_PIN]
    .map(function (one) {
      return String(one || "").trim();
    })
    .filter(function (one) {
      return one;
    })
    .filter(function (one, at, all) {
      return all.indexOf(one) === at;
    });
  if (!pins.length) {
    log.debug("Leaving addStsTrustFlags(). No pins; nothing added.");
    return options;
  }
  options.addArguments("--ignore-certificate-errors-spki-list=" +
                       pins.join(","));
  log.info("Trusting " + pins.length + " public key(s) by SPKI pin (the " +
           "mock STS, and this stack's own api and client where TLS is on).");
  log.debug("Leaving addStsTrustFlags().");
  return options;
}

// (5) THE CONSOLE ENTRY THAT REPORTS THE BROWSER RECONFIGURING ITSELF, which
// every "the console is clean" assertion in this suite would otherwise read as
// a page error.
//
// Chrome fails a request that is in flight when the configuration the request
// depends on is REPLACED under it, and it says so with an error code of its
// own rather than with the one the failure would have had:
//
//   net::ERR_CERT_VERIFIER_CHANGED  the certificate verifier's configuration
//                                   changed mid-request
//   net::ERR_NETWORK_CHANGED        the network configuration did
//
// Neither is a verdict on anything. The server was never asked and no
// certificate was rejected on its merits: the request was ABANDONED so that it
// could be made again against the new configuration, which is why Chrome's own
// net_error_list.h describes both as errors the caller should retry. What
// reaches the console is one line of `Failed to load resource`, naming the URL
// that happened to be in flight.
//
// It costs a run when the URL in flight belongs to the page under test. On
// 2026-08-28 (./remote-run-tests.sh against https://test.idptools.com) the one
// failure of 270 jobs was
//
//   the workflow logged browser errors while talking to walt.id:
//   https://test.idptools.com/css/bootstrap.css - Failed to load resource:
//       net::ERR_CERT_VERIFIER_CHANGED
//
// on a job whose every functional assertion had already passed — walt.id had
// issued a credential, it verified, and it was bound to the holder key. A
// stylesheet is what a page that is otherwise working loses to this.
//
// TWO THINGS CAN CHANGE THAT CONFIGURATION MID-RUN and this suite does not
// control either: Chrome's component updater landing a new CRLSet or root
// store while the browser is up, and the verifier configuration that carries
// addStsTrustFlags()' own --ignore-certificate-errors-spki-list being applied
// after the first navigations have started. Which one it was is not
// recoverable from the console line, and it does not change what the line
// means.
//
// THE FILTER IS TWO EXACT CODES AND NOTHING ELSE, which is the whole point. A
// filter on `Failed to load resource` would swallow every 404, every refused
// connection and every certificate this suite deliberately makes a browser
// reject — url_safety_schemes.js, api_tls_probe.js and the mock's own
// certificate are all about a load that MUST fail — so those keep failing the
// run. net::ERR_CERT_AUTHORITY_INVALID is a certificate that was verified and
// found wanting and stays a failure; net::ERR_CONNECTION_REFUSED is a service
// that is not there and stays a failure.
//
// Every drop is logged at info, so a run that hit one says so in its own log
// rather than passing with a silence that reads the same as never meeting it.
const TRANSIENT_LOAD_ERRORS = [
  /net::ERR_CERT_VERIFIER_CHANGED/,
  /net::ERR_NETWORK_CHANGED/
];

function isTransientLoadError(message) {
  log.debug("Entering isTransientLoadError().");
  var text = String(message === undefined || message === null ? "" : message);
  var transient = TRANSIENT_LOAD_ERRORS.some(function (one) {
    return one.test(text);
  });
  if (transient) {
    log.info("Ignoring a browser load error the browser itself caused by " +
             "changing its configuration mid-request: " + text.slice(0, 200));
  }
  log.debug("Leaving isTransientLoadError(). " + transient);
  return transient;
}

// The same judgement over an array of console MESSAGES, for the callers that
// have already mapped their log entries down to strings.
function withoutTransientLoadErrors(messages) {
  log.debug("Entering withoutTransientLoadErrors().");
  var kept = [].concat(messages || []).filter(function (one) {
    return !isTransientLoadError(one);
  });
  log.debug("Leaving withoutTransientLoadErrors(). " + kept.length + " kept.");
  return kept;
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
  isTransientLoadError: isTransientLoadError,
  withoutTransientLoadErrors: withoutTransientLoadErrors,
  addWebCryptoEd25519Flags: addWebCryptoEd25519Flags,
  addStsTrustFlags: addStsTrustFlags,
  originOf: originOf
};
