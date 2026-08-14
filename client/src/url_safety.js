// File: url_safety.js
//
// ---------------------------------------------------------------------------
// One check, applied wherever this app navigates the browser to a URL it did
// not write itself: **the scheme must be http or https**.
//
// Every such URL here is user-supplied in the ordinary course of using a
// debugger — you type an IdP's sign-in endpoint, or a signed redirect is built
// from it, and the page then does `window.location.assign(...)` or submits a
// form to it. `javascript:` is a URL scheme, so a value that reaches one of
// those sinks unchecked is script execution, and `data:`/`blob:` are
// same-page-origin document loads. A scheme allowlist is what closes that, and
// it is the whole of what these sinks need.
//
// **This is deliberately not DOMPurify.** That is an HTML sanitizer: given a
// URL it parses it as an HTML fragment and hands most of it back. Measured
// against dompurify 3.x, `DOMPurify.sanitize('javascript:alert(1)')` returns
// the string **unchanged**, as does the `java\tscript:` form — so at a
// navigation sink it looks like a control and is not one, which is the whole
// point. (`data:text/html,<script>…</script>` it truncates to
// `data:text/html,`, mangled but still a `data:` URL.) Sanitizing is the wrong
// verb here in any case: a URL is not markup to be cleaned, it is a value to be
// accepted or refused.
//
// It is also lossy on the URLs that matter, though less often than one might
// assume: an ordinary `?a=1&b=2` survives it intact, but a URL containing `<`
// or `>` has that content **dropped** and its `&` escaped to `&amp;`. So it
// both fails to stop the attack and quietly corrupts a class of legitimate
// input. `tests/url_safety.js` pins both halves of that against the real
// package rather than leaving them as an assertion in a comment.
//
// The parsing is left to the WHATWG URL parser rather than a regular
// expression, because the interesting inputs are the ones that do not look
// like what they are: the parser strips tab and newline characters from inside
// a scheme and ignores leading C0 controls and spaces, so `java\tscript:` and
// `javascript:` both resolve to the `javascript:` protocol and are
// refused here, while a regex over the raw string sees neither.
// `tests/url_safety.js` holds that, case by case.
// ---------------------------------------------------------------------------


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "url_safety",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      // A missing log level must not stop the module loading.
      return "info";
    }
  })()
});

// The only two schemes this application ever has cause to navigate to. Note
// they are compared against `URL.protocol`, which always ends in a colon.
var ALLOWED_PROTOCOLS = ["http:", "https:"];


// Resolve a caller-supplied URL and return it, or throw naming the reason.
//
// `what` names the field in the error, because these all surface in a status
// line the user reads ("Send failed: ..."), and "not a usable URL" without
// saying which one is not worth showing.
function safeExternalUrl(value, what) {
  log.debug("Entering safeExternalUrl(). what=" + (what || "url"));
  var label = what || "URL";
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(label + " is empty.");
  }

  // A base makes a relative URL resolvable in the browser. In node (the tests)
  // there is no location, and these URLs are absolute anyway, so parsing with
  // no base is correct there and an unparseable value is refused below.
  var base;
  if (typeof window !== "undefined" && window.location &&
      window.location.href) {
    base = window.location.href;
  }

  var parsed;
  try {
    parsed = base ? new URL(value, base) : new URL(value);
  } catch (e) {
    throw new TypeError(label + " is not a valid URL: " + value);
  }

  if (ALLOWED_PROTOCOLS.indexOf(parsed.protocol) === -1) {
    // Name the scheme that was refused. This is the branch a `javascript:` URL
    // takes, and saying so is more use than a generic refusal.
    throw new TypeError(
      label + ' must be http or https, but the scheme is "' + parsed.protocol +
          '". Refused.'
    );
  }

  log.debug("Leaving safeExternalUrl(). Allowed " + parsed.protocol + " URL.");
  return parsed.href;
}

// The same test without the throw, for somewhere that wants to disable a button
// rather than report a failure.
function isSafeExternalUrl(value) {
  log.debug("Entering isSafeExternalUrl().");
  try {
    safeExternalUrl(value);
    log.debug("Leaving isSafeExternalUrl().");
    return true;
  } catch (e) {
    // The reason is the return value here; callers wanting it use
    // safeExternalUrl() and read the message off the exception.
    log.debug("Leaving isSafeExternalUrl().");
    return false;
  }
}


module.exports = {
  safeExternalUrl: safeExternalUrl,
  isSafeExternalUrl: isSafeExternalUrl,
  ALLOWED_PROTOCOLS: ALLOWED_PROTOCOLS
};
