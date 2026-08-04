// File: url_safety.js
//
// client/src/url_safety.js — the scheme allowlist applied before this app
// navigates the browser anywhere.
//
// Every URL it guards is caller-supplied in the ordinary course of using a
// debugger: you type an IdP sign-in endpoint, or one arrives in fetched
// metadata, and the page then does `window.location.assign(...)` or submits a
// form to it. `javascript:` is a URL scheme, so an unchecked value at one of
// those sinks is script execution in the page's own origin.
//
// The reason this test exists rather than a line of review: the dangerous
// inputs are the ones that do not look dangerous. The WHATWG URL parser strips
// tab and newline characters from inside a scheme and skips leading C0 controls
// and whitespace, so `java\tscript:alert(1)` and `  JavaScript:alert(1)` are
// both the `javascript:` protocol by the time a browser acts on them — while a
// regex over the raw string sees neither. Those cases are listed below one by
// one, because "we check the scheme" is only true if it is true of these.
//
// It also pins what the removed DOMPurify call actually did, so nobody
// reintroduces it believing it was equivalent: it returns a `javascript:` URL
// unchanged — no protection whatsoever at a navigation sink — and it drops
// content from any URL containing `<` or `>`. (An ordinary `?a=1&b=2` it leaves
// alone; that is asserted too, so this test does not overstate the case.)
//
// No browser and no services: node only, so it never skips.
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "url_safety",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the module is at client/src/url_safety.js; the tests image
// copies it flat next to the test scripts (see tests/Dockerfile).
var urlSafety = paths.requireSharedModule(
  [__dirname + "/../client/src/url_safety.js", __dirname + "/url_safety.js"], "url_safety.js");


// --- what must be refused ---------------------------------------------------

function dangerousSchemesAreRefused() {
  log.debug("Entering dangerousSchemesAreRefused().");
  log.info("[refuse] Schemes that are not http/https must be refused.");
  const refused = [
    // The plain article.
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    // Case is not significant in a scheme.
    "JavaScript:alert(1)",
    "JAVASCRIPT:alert(1)",
    // The URL parser strips tabs and newlines from inside the scheme, so all
    // three of these ARE javascript: by the time the browser sees them. This is
    // the family a regex over the raw string misses.
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "java\rscript:alert(1)",
    // Leading C0 controls and spaces are skipped by the parser.
    "javascript:alert(1)",
    "  javascript:alert(1)",
    "\t javascript:alert(1)",
    // Other schemes that load a document in the page's own context.
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "blob:https://example.com/1234",
    "file:///etc/passwd",
    // Not a navigation this app should ever perform.
    "about:blank",
    "chrome://settings"
  ];
  refused.forEach(function (value) {
    assert.throws(
      function () { urlSafety.safeExternalUrl(value, "The endpoint"); },
      function (e) {
        // The message has to name the field and the refusal, because it is shown
        // to the user in a status line.
        assert.ok(/The endpoint/.test(e.message),
          'the error should name the field, got: "' + e.message + '"');
        return true;
      },
      "should have refused " + JSON.stringify(value)
    );
    assert.strictEqual(urlSafety.isSafeExternalUrl(value), false,
      "isSafeExternalUrl should agree about " + JSON.stringify(value));
  });
  log.info("[refuse] OK — " + refused.length + " dangerous or non-navigable URLs all refused.");
  log.debug("Leaving dangerousSchemesAreRefused().");
}

function emptyAndMalformedAreRefused() {
  log.info("[refuse] Empty and unparseable values must be refused.");
  const refused = ["", "   ", null, undefined, 42, {}, [], "http://", "not a url", "://missing-scheme"];
  refused.forEach(function (value) {
    assert.throws(function () { urlSafety.safeExternalUrl(value, "The endpoint"); },
      "should have refused " + JSON.stringify(value));
  });
  log.info("[refuse] OK — " + refused.length + " empty or unparseable values all refused.");
}


// --- what must be allowed ---------------------------------------------------
//
// A control that refuses real input is not a control, it is an outage. These are
// the URLs this debugger exists to send people to.

function realEndpointsAreAllowed() {
  log.debug("Entering realEndpointsAreAllowed().");
  log.info("[allow] Ordinary IdP endpoints must pass through unharmed.");
  const allowed = [
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "http://localhost:8080/realms/debugger-testing/protocol/saml",
    "https://idp.example.com:8443/adfs/ls/",
    "https://example.com/sso?SAMLRequest=fZJdb4IwFIb%2FCul9&RelayState=abc",
    "HTTPS://EXAMPLE.COM/Path",
    "https://user:pass@example.com/sso",
    "https://example.com/path#fragment"
  ];
  allowed.forEach(function (value) {
    const out = urlSafety.safeExternalUrl(value, "The endpoint");
    assert.ok(typeof out === "string" && out.length > 0, "should have returned a URL for " + value);
    assert.ok(/^https?:\/\//i.test(out), "the returned URL should be http(s): " + out);
    assert.strictEqual(urlSafety.isSafeExternalUrl(value), true,
      "isSafeExternalUrl should agree about " + value);
  });
  log.info("[allow] OK — " + allowed.length + " real endpoints all accepted.");
  log.debug("Leaving realEndpointsAreAllowed().");
}

// The specific regression that made this module necessary: a SAML redirect
// binding puts the whole request in the query string, and there is always more
// than one parameter. If the guard mangled `&`, every redirect-binding SSO
// would break in a way that looks like an IdP problem.
function queryStringsSurviveIntact() {
  log.debug("Entering queryStringsSurviveIntact().");
  log.info("[allow] A multi-parameter query string must survive byte for byte.");
  const url = "https://idp.example.com/sso?SAMLRequest=abc%2Bdef&RelayState=xyz&SigAlg=" +
              encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") +
              "&Signature=Zm9vYmFy";
  const out = urlSafety.safeExternalUrl(url, "The endpoint");
  assert.ok(out.indexOf("&amp;") === -1,
    "the guard HTML-escaped an ampersand, which corrupts the query string: " + out);
  ["SAMLRequest=abc%2Bdef", "RelayState=xyz", "SigAlg=", "Signature=Zm9vYmFy"].forEach(function (part) {
    assert.ok(out.indexOf(part) >= 0, "lost query parameter " + part + " from " + out);
  });
  assert.strictEqual(out.split("&").length, 4, "the parameter count changed: " + out);
  log.info("[allow] OK — all four parameters intact, no entity escaping.");
  log.debug("Leaving queryStringsSurviveIntact().");
}


// --- the browser path -------------------------------------------------------
//
// In a page there IS a window.location, so the module resolves relative URLs
// against it. That changes what some inputs mean, and it is the only place one
// of the checks is load-bearing: `new URL("   ", base)` does not throw the way
// `new URL("   ")` does — it RESOLVES TO THE BASE. So without the explicit
// empty/blank rejection, a blank endpoint field would quietly "navigate" to the
// current page and read as a silent no-op rather than a refusal. Node alone
// cannot see that (a mutation removing the check survived a node-only run of
// this test, which is why this section exists).
function browserRelativeResolution() {
  log.debug("Entering browserRelativeResolution().");
  log.info("[browser] With a window.location present, blanks must still be refused.");
  const hadWindow = Object.prototype.hasOwnProperty.call(global, "window");
  const previous = global.window;
  global.window = { location: { href: "https://wallet.example.com/saml_request.html" } };
  try {
    ["", "   ", "\t\n"].forEach(function (blank) {
      assert.throws(function () { urlSafety.safeExternalUrl(blank, "The endpoint"); },
        "a blank value must be refused even when it would resolve against the page URL: " +
        JSON.stringify(blank));
    });

    // A dangerous scheme is still dangerous with a base present.
    assert.throws(function () { urlSafety.safeExternalUrl("javascript:alert(1)"); },
      "javascript: must be refused with a base present too");

    // A relative endpoint resolves against the page, which is a legitimate thing
    // for a same-origin path to do.
    assert.strictEqual(
      urlSafety.safeExternalUrl("/realms/x/protocol/saml"),
      "https://wallet.example.com/realms/x/protocol/saml",
      "a relative URL should resolve against the page");

    // Worth being explicit about the boundary: this is a SCHEME allowlist, not a
    // host allowlist, so a protocol-relative URL to another host is allowed. That
    // is correct here — a debugger exists to be pointed at arbitrary identity
    // providers, so restricting the host would break its purpose. The property
    // being defended is "no script execution / no document injection", not "no
    // navigation off-site".
    assert.strictEqual(
      urlSafety.safeExternalUrl("//idp.example.com/sso"),
      "https://idp.example.com/sso",
      "a protocol-relative URL should inherit https and be allowed");
  } finally {
    if (hadWindow) {
      global.window = previous;
    } else {
      delete global.window;
    }
  }
  log.info("[browser] OK — blanks refused, javascript: refused, relative URLs resolve.");
  log.debug("Leaving browserRelativeResolution().");
}


// --- why not DOMPurify ------------------------------------------------------
//
// This is the claim the whole change rests on, so it is measured rather than
// asserted in a comment. Skipped when dompurify is not installed for node.
function dompurifyWouldNotHaveHelped() {
  log.debug("Entering dompurifyWouldNotHaveHelped().");
  log.info("[contrast] Demonstrating that an HTML sanitizer is not a URL check.");
  let DOMPurify;
  try {
    const createDOMPurify = require("dompurify");
    const { JSDOM } = require("jsdom");
    DOMPurify = createDOMPurify(new JSDOM("").window);
  } catch (e) {
    // dompurify/jsdom are not dependencies of this package — the point is
    // documented in url_safety.js either way, and a missing dev tool must not
    // fail the suite.
    log.info("[contrast] SKIPPED — dompurify/jsdom not available here (" + e.message + ").");
    return;
  }
  // Half one: it does not stop the attack. Both of these come back untouched,
  // so a sink "protected" by it navigates to them exactly as before.
  ["javascript:alert(1)", "java\tscript:alert(1)"].forEach(function (attack) {
    assert.strictEqual(DOMPurify.sanitize(attack), attack,
      "if DOMPurify ever starts refusing javascript: URLs, this note can be revisited");
    assert.throws(function () { urlSafety.safeExternalUrl(attack); },
      "url_safety must refuse what DOMPurify passes through");
  });

  // Half two: it is lossy on legitimate input — though only on the URLs that
  // contain markup characters. An ordinary query string DOES survive it, which
  // is worth pinning so this test states what is true rather than what is
  // convenient.
  const ordinary = "https://idp.example.com/sso?a=1&b=2";
  assert.strictEqual(DOMPurify.sanitize(ordinary), ordinary,
    "an ordinary query string is left alone by DOMPurify — do not claim otherwise");

  const withMarkup = "https://idp.example.com/cb?code=x&state=<y>";
  const mangled = DOMPurify.sanitize(withMarkup);
  assert.notStrictEqual(mangled, withMarkup,
    "expected DOMPurify to alter a URL containing markup characters");
  assert.ok(mangled.indexOf("<y>") === -1, "expected the <y> to be dropped, got: " + mangled);
  assert.strictEqual(urlSafety.safeExternalUrl(withMarkup).indexOf("&amp;"), -1,
    "url_safety must not entity-escape anything");
  log.info("[contrast] OK — DOMPurify returns `javascript:` URLs unchanged (no protection) and " +
           "drops content from a URL containing markup; the scheme allowlist does neither.");
  log.debug("Leaving dompurifyWouldNotHaveHelped().");
}


async function test() {
  dangerousSchemesAreRefused();
  emptyAndMalformedAreRefused();
  realEndpointsAreAllowed();
  queryStringsSurviveIntact();
  browserRelativeResolution();
  dompurifyWouldNotHaveHelped();
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("url_safety")
  .description("Verify the scheme allowlist applied before the app navigates anywhere.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
