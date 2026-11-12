// File: rfc6750.js
//
// RFC 6750 section 2.1, the Authorization header a resource server must
// accept:
//
//   b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
//                 *"="
//   credentials = "Bearer" 1*SP b64token
//
// RFC 9449 uses the same production with the scheme "DPoP". The value
// Copy Token writes is the credentials production alone — one space,
// scheme spelling normalised — and not the "Authorization:" line around
// it. RFC 9700 section 4.3.2 forbids the query-parameter method of RFC
// 6750 section 2.3, so this module never builds one.
//
// A token that is not a b64token cannot be credentials: a space, a comma
// or a quote is where a header parser splits, and copying it labelled
// Bearer would be a header no resource server can read. An unknown
// token_type is the same refusal. Missing and empty mean Bearer, which
// is what a token response omits when it means that.
//
// tokenValue() is the other direction. A field that prefixes a scheme
// itself must accept either the raw token or credentials, or a paste of
// what Copy Token wrote becomes "Bearer Bearer <token>".

var bunyan = require("bunyan");
// A node consumer (the engine tests load a page module that requires this
// one) may have no CONFIG_FILE, so fall back to info rather than failing
// to load.
var log = bunyan.createLogger({
  name: "rfc6750",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Equals are padding and may only trail. Putting "=" in the first class
// would accept "ab=cd", which the ABNF does not.
var HEADER_RE = /^Authorization:[ \t]+(.+)$/i;
var CREDENTIALS_RE =
    /^(Bearer|DPoP)[ \t]+([A-Za-z0-9\-._~+/]+=*)$/i;
var B64TOKEN_RE = /^[A-Za-z0-9\-._~+/]+=*$/;

function schemeName(tokenType) {
  log.debug("Entering schemeName().");
  if (tokenType === null || tokenType === undefined) {
    log.debug("Leaving schemeName(). Bearer, absent.");
    return "Bearer";
  }
  var text = String(tokenType).trim();
  if (text === "") {
    log.debug("Leaving schemeName(). Bearer, empty.");
    return "Bearer";
  }
  if (/^bearer$/i.test(text)) {
    log.debug("Leaving schemeName(). Bearer.");
    return "Bearer";
  }
  if (/^dpop$/i.test(text)) {
    log.debug("Leaving schemeName(). DPoP.");
    return "DPoP";
  }
  log.debug("Leaving schemeName(). Unrecognised.");
  return null;
}

function isB64Token(token) {
  log.debug("Entering isB64Token().");
  var ok = typeof token === "string" && B64TOKEN_RE.test(token);
  log.debug("Leaving isB64Token(). " + ok);
  return ok;
}

// Credentials already written, with the scheme spelling normalised.
// null when `text` is not that production. `text` is trimmed by the
// caller; this only strips an Authorization prefix.
function recognized(text) {
  log.debug("Entering recognized().");
  var header = text.match(HEADER_RE);
  var body = header ? header[1].trim() : text;
  var match = body.match(CREDENTIALS_RE);
  if (!match || !isB64Token(match[2])) {
    log.debug("Leaving recognized(). None.");
    return null;
  }
  var scheme = schemeName(match[1]);
  if (!scheme) {
    log.debug("Leaving recognized(). No scheme.");
    return null;
  }
  log.debug("Leaving recognized().");
  return { scheme: scheme, token: match[2] };
}

function credentials(token, tokenType) {
  log.debug("Entering credentials().");
  if (typeof token !== "string") {
    log.debug("Leaving credentials(). Not a string.");
    return null;
  }
  var found = recognized(token.trim());
  if (found) {
    log.debug("Leaving credentials(). Already credentials.");
    return found.scheme + " " + found.token;
  }
  var scheme = schemeName(tokenType);
  if (!scheme) {
    log.debug("Leaving credentials(). Unknown token_type.");
    return null;
  }
  var text = token.trim();
  var header = text.match(HEADER_RE);
  if (header) {
    text = header[1].trim();
  }
  if (!isB64Token(text)) {
    log.debug("Leaving credentials(). Not a b64token.");
    return null;
  }
  log.debug("Leaving credentials().");
  return scheme + " " + text;
}

function tokenValue(value) {
  log.debug("Entering tokenValue().");
  if (typeof value !== "string") {
    log.debug("Leaving tokenValue(). Not a string.");
    return "";
  }
  var found = recognized(value.trim());
  if (found) {
    log.debug("Leaving tokenValue(). Stripped a scheme.");
    return found.token;
  }
  var text = value.trim();
  if (isB64Token(text)) {
    log.debug("Leaving tokenValue(). Bare b64token.");
    return text;
  }
  log.debug("Leaving tokenValue(). Unchanged.");
  return value;
}

module.exports = {
  schemeName: schemeName,
  credentials: credentials,
  tokenValue: tokenValue
};
