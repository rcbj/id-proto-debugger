// File: spiffe_id.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE ID GRAMMAR, and nothing else.
//
// A SPIFFE ID is `spiffe://<trust domain>/<path>`, and it is the one value the
// whole workflow passes around: the page validates one before sending it, the
// api refuses a registration entry naming another trust domain, an X509-SVID
// carries one in a URI subjectAltName, and the SPIRE Server API takes one apart
// into a `spire.api.types.SPIFFEID` message — a trust domain and a path as two
// separate fields — and puts it back together again.
//
// IT LIVES IN common/ BECAUSE IT IS NEEDED IN THREE PLACES AND MUST NOT EXIST
// THREE TIMES. `api/spiffe_client.js` checks an identifier before it opens a
// socket, `client/src/spiffe_id_pane.js` checks the one a user typed with no
// network at all, and `tests/spiffe_id_grammar.js` drives it against the
// specification's own examples. That is the argument `common/krb5` makes about
// a wire codec, applied to a much smaller thing for the same reason: a grammar
// implemented twice is a grammar that disagrees with itself, and the
// disagreement shows up as an identifier one half of this workflow accepts and
// the other refuses.
//
// NO DOM, so the browser bundle and node run the same code. It is staged into
// client/src at build time exactly as common/krb5 is — see client/build.js.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A FILE RATHER THAN A REGULAR EXPRESSION AT FOUR CALL SITES
//
// Because the grammar is STRICTER THAN A URL PARSER, and every way of getting
// it wrong produces an identifier that `new URL()` accepts, that looks right in
// a log, and that a real SPIFFE implementation then refuses — or, worse,
// accepts and understands as naming something else. Four of them:
//
//   * **A trust domain name is lower-case.** `spiffe://Example.org/x` is not a
//     valid SPIFFE ID, and it is not another spelling of
//     `spiffe://example.org/x` either: they are different identifiers.
//     `new URL()` lower-cases a host for you, which HIDES the defect — the
//     client that sent the wrong form gets an SVID naming the right one and
//     never learns. So the check is made on the RAW TEXT before any URL
//     parsing, and the upper-case form is REFUSED rather than normalised.
//
//   * **The path is not a URL path.** No percent-encoding, no empty segment
//     (so no trailing slash and no `//`), no `.` and no `..`. A URL parser
//     accepts all of those and normalises three of them away.
//
//   * **No port, no userinfo, no query, no fragment.** Each is a way of writing
//     an identifier that a naive `startsWith()` treats as belonging to a trust
//     domain it does not belong to, which is an authorization bug in anything
//     that federates. Membership is decided by comparing the PARSED trust
//     domain here (`memberOf()`), never by a prefix test.
//
//   * **`/spire` is reserved** for a SPIFFE implementation's own account — the
//     server's identity and every agent it attests — so a registration entry
//     there names something the server also mints for itself.
//
// The lengths are the specification's: 2048 bytes for the whole identifier and
// 255 for the trust domain name, counted in BYTES rather than characters
// because the specification says bytes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE LOGGER, AND WHY IT IS THE ONE IN THIS TREE THAT TRIES BUNYAN AND COPES
// WITHOUT IT.
//
// The Entering/Leaving convention (see the repo-root CLAUDE.md) wants a `log`,
// and this module is loaded from THREE places whose `node_modules` are three
// different directories:
//
//   * browserified into a client bundle, where `common/spiffe` has been staged
//     into `client/src` and `require("bunyan")` resolves against
//     `client/node_modules` like every other module there;
//   * required by `tests/*`, where `tests/module_paths.js` has put
//     `tests/node_modules` on NODE_PATH for exactly this reason;
//   * required by `api/spiffe_client.js` as `../common/spiffe/spiffe_id.js`,
//     where it CANNOT be resolved: node walks up from the REAL directory, so
//     it looks in `common/node_modules` and the repository root and never in
//     `api/node_modules`. That is the same fact `common/sp_keypair.js` records
//     about `common/` being outside the reach of `tests/node_modules`.
//
// A checked-in copy under `api/` (which is what `api/data.js` is) would solve
// it and would put the grammar in two files, which is the one thing this module
// exists to prevent. So bunyan is TRIED and a console-backed logger of the same
// shape stands in when it is not there. Browserify resolves the `require` at
// build time, so the bundle still gets the real one and the `catch` is dead
// code there. Note the shim's own methods are the one place the convention
// cannot apply — a log line inside `log.debug()` is infinite recursion.
// ---------------------------------------------------------------------------
var log = (function () {
  try {
    var bunyan = require("bunyan");
    return bunyan.createLogger({
      name: "spiffe_id",
      level: (function () {
        try {
          return require(process.env.CONFIG_FILE).logLevel || "info";
        } catch (e) {
          // No CONFIG_FILE resolvable here — a node caller, not a bundle.
          return "info";
        }
      })()
    });
  } catch (e) {
    var DEBUG = false;
    var TAG = "[spiffe_id]";
    return {
      debug: function () {
        if (!DEBUG) {
          return;
        }
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      info: function () {
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      warn: function () {
        console.warn.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      error: function () {
        console.error.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      }
    };
  }
})();

// The scheme, written once. Read case-insensitively, because a URI scheme is
// case-insensitive per RFC 3986, and always written lower-case.
var SCHEME = "spiffe";
var PREFIX = SCHEME + "://";

var MAX_ID_BYTES = 2048;
var MAX_TRUST_DOMAIN_BYTES = 255;

// The two character classes, written as the specification writes them rather
// than as the shortest regular expression that happens to match. The trust
// domain has NO upper case and the path does — that asymmetry is real and is
// the single most common thing to get wrong here.
var TRUST_DOMAIN_CHARS = /^[a-z0-9.\-_]+$/;
var PATH_SEGMENT_CHARS = /^[a-zA-Z0-9.\-_]+$/;

// Reserved for the SPIFFE implementation itself.
var RESERVED_PREFIX = "/spire";

// Byte length without Buffer, because this module is browserified and pulling
// in the Buffer shim for one measurement is a large dependency for a small
// fact. encodeURIComponent gives the UTF-8 byte count exactly.
function byteLength(text) {
  log.debug("Entering byteLength().");
  var value = String(text == null ? "" : text);
  var bytes = encodeURIComponent(value).replace(/%[0-9A-F]{2}/gi, "x").length;
  log.debug("Leaving byteLength(). " + bytes + " bytes.");
  return bytes;
}

// ---------------------------------------------------------------------------
// READING ONE.
//
// Returns an object and never throws, and it always returns an object. Every
// caller is answering somebody — a gRPC status, a 400, a line in a pane — and
// each wants the REASON in its own words. A thrown Error would make all of them
// write the same try/catch and would lose the distinction between "this is not
// a SPIFFE ID" and "this is a SPIFFE ID belonging to somebody else".
//
//   { ok: true,  id, trustDomain, path, segments, reserved }
//   { ok: false, reason }
//
// `path` is "" for a trust-domain-only identifier — `spiffe://example.org` —
// which IS a valid SPIFFE ID and is what names a trust domain itself in a
// bundle map. That case is why `path` is not defaulted to "/".
// ---------------------------------------------------------------------------
function parse(value) {
  log.debug("Entering parse().");
  var text = String(value == null ? "" : value);
  if (!text) {
    log.debug("Leaving parse(). Empty.");
    return { ok: false, reason: "A SPIFFE ID is required and none was given." };
  }
  if (byteLength(text) > MAX_ID_BYTES) {
    log.debug("Leaving parse(). Too long.");
    return { ok: false,
             reason: "A SPIFFE ID may be at most " + MAX_ID_BYTES +
                     " bytes; this one is " + byteLength(text) + "." };
  }
  if (text.slice(0, PREFIX.length).toLowerCase() !== PREFIX) {
    log.debug("Leaving parse(). Wrong scheme.");
    return { ok: false,
             reason: "A SPIFFE ID begins with " + PREFIX +
                     "; this one begins with " + text.slice(0, 16) + "." };
  }
  var rest = text.slice(PREFIX.length);
  var slash = rest.indexOf("/");
  var authority = slash === -1 ? rest : rest.slice(0, slash);
  var path = slash === -1 ? "" : rest.slice(slash);

  // The authority is the trust domain name and NOTHING else. Userinfo and a
  // port are refused by name rather than by the character class, because
  // "invalid character @" says much less than naming the shape of the thing.
  if (!authority) {
    log.debug("Leaving parse(). No trust domain.");
    return { ok: false,
             reason: "A SPIFFE ID names a trust domain between " + PREFIX +
                     " and the first /; this one names none." };
  }
  if (authority.indexOf("@") !== -1) {
    log.debug("Leaving parse(). Userinfo.");
    return { ok: false,
             reason: "A SPIFFE ID carries no userinfo; the trust domain is " +
                     "the whole authority." };
  }
  if (authority.indexOf(":") !== -1) {
    log.debug("Leaving parse(). Port.");
    return { ok: false,
             reason: "A SPIFFE ID carries no port; the trust domain is the " +
                     "whole authority." };
  }
  if (byteLength(authority) > MAX_TRUST_DOMAIN_BYTES) {
    log.debug("Leaving parse(). Trust domain too long.");
    return { ok: false,
             reason: "A trust domain name may be at most " +
                     MAX_TRUST_DOMAIN_BYTES + " bytes; this one is " +
                     byteLength(authority) + "." };
  }
  if (!TRUST_DOMAIN_CHARS.test(authority)) {
    // The upper-case case is called out on its own, because it is the one a
    // reader will otherwise stare at: `spiffe://Example.org/x` looks like a
    // perfectly ordinary URI and is refused for a reason nothing else says.
    var upper = /[A-Z]/.test(authority);
    log.debug("Leaving parse(). Bad trust domain characters.");
    return { ok: false, reason: upper
      ? "A trust domain name is lower-case: " + authority + " is not a valid " +
        "trust domain, and it is not another spelling of " +
        authority.toLowerCase() + " either — they are different identifiers."
      : "A trust domain name holds only lower-case letters, digits, dots, " +
        "dashes and underscores; this one is " + authority + "." };
  }

  var segments = [];
  if (path) {
    if (path.indexOf("?") !== -1 || path.indexOf("#") !== -1) {
      log.debug("Leaving parse(). Query or fragment.");
      return { ok: false,
               reason: "A SPIFFE ID carries no query and no fragment." };
    }
    if (path.indexOf("%") !== -1) {
      log.debug("Leaving parse(). Percent-encoding.");
      return { ok: false,
               reason: "A SPIFFE ID path is not percent-encoded; % is not a " +
                       "permitted character." };
    }
    var parts = path.split("/");
    // parts[0] is always "" because the path begins with "/".
    for (var i = 1; i < parts.length; i++) {
      var segment = parts[i];
      if (!segment) {
        log.debug("Leaving parse(). Empty segment.");
        return { ok: false,
                 reason: "A SPIFFE ID path has no empty segment, so no " +
                         "trailing slash and no //." };
      }
      if (segment === "." || segment === "..") {
        log.debug("Leaving parse(). Relative segment.");
        return { ok: false,
                 reason: "A SPIFFE ID path has no relative segment: . and " +
                         ".. are not permitted." };
      }
      if (!PATH_SEGMENT_CHARS.test(segment)) {
        log.debug("Leaving parse(). Bad path characters.");
        return { ok: false,
                 reason: "A SPIFFE ID path segment holds only letters, " +
                         "digits, dots, dashes and underscores; this one is " +
                         segment + "." };
      }
      segments.push(segment);
    }
  }
  log.debug("Leaving parse(). trustDomain=" + authority);
  return { ok: true, id: PREFIX + authority + path, trustDomain: authority,
           path: path, segments: segments, reserved: isReservedPath(path) };
}

// The plain question, for the callers that want only yes or no.
function isValid(value) {
  log.debug("Entering isValid().");
  var ok = parse(value).ok;
  log.debug("Leaving isValid(). " + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// WRITING ONE.
//
// `make("example.org", "ns/default/sa/web")` and the same call with a leading
// slash are one call: the slash is supplied where it is missing, because half
// the callers have a path that came off a protobuf field (which carries it) and
// half are building one out of parts. It THROWS on something invalid, which is
// the opposite of parse() and is deliberate — a caller building an identifier
// out of its own values has a bug if the result is not one, where a caller
// reading one has been handed something.
// ---------------------------------------------------------------------------
function make(trustDomain, path) {
  log.debug("Entering make().");
  var domain = String(trustDomain == null ? "" : trustDomain).trim();
  var tail = String(path == null ? "" : path).trim();
  if (tail && tail.charAt(0) !== "/") {
    tail = "/" + tail;
  }
  var parsed = parse(PREFIX + domain + tail);
  if (!parsed.ok) {
    log.debug("Leaving make(). Invalid.");
    throw new Error("Cannot build a SPIFFE ID from trust domain \"" + domain +
                    "\" and path \"" + path + "\": " + parsed.reason);
  }
  log.debug("Leaving make(). id=" + parsed.id);
  return parsed.id;
}

// The trust domain as an identifier in its own right — `spiffe://example.org`,
// with no path. This is what keys a bundle map on BOTH the Workload API and the
// SPIRE Server API, and it is an ordinary SPIFFE ID rather than a special case.
// A bare trust domain NAME used as a map key is a map the far end silently
// finds nothing in, which is the failure this function exists to prevent.
function trustDomainId(trustDomain) {
  log.debug("Entering trustDomainId().");
  var id = PREFIX +
    String(trustDomain == null ? "" : trustDomain).trim().toLowerCase();
  log.debug("Leaving trustDomainId(). " + id);
  return id;
}

// The trust domain NAME out of an identifier, or "" if it is not one. Named
// separately from parse() because a great many callers want only this, and
// reading `.trustDomain` off a failed parse silently gives undefined.
function trustDomainOf(value) {
  log.debug("Entering trustDomainOf().");
  var parsed = parse(value);
  log.debug("Leaving trustDomainOf().");
  return parsed.ok ? parsed.trustDomain : "";
}

// The SPIFFE ID a SPIRE server holds for itself, and the one a caller checks
// the SPIRE Server API's TLS certificate against. Written here rather than at
// the two call sites because getting it wrong turns SPIFFE-aware server
// verification into a check that always passes.
function serverId(trustDomain) {
  log.debug("Entering serverId().");
  var id = make(trustDomain, "/spire/server");
  log.debug("Leaving serverId(). " + id);
  return id;
}

// Whether a path belongs to the SPIFFE implementation's own reserved space.
// `/spire` itself and everything under it; `/spireman` is NOT under it, which
// is why this is a segment comparison and not a `startsWith`.
function isReservedPath(path) {
  log.debug("Entering isReservedPath().");
  var text = String(path == null ? "" : path);
  var reserved = text === RESERVED_PREFIX ||
                 text.slice(0, RESERVED_PREFIX.length + 1) ===
                   RESERVED_PREFIX + "/";
  log.debug("Leaving isReservedPath(). " + reserved);
  return reserved;
}

// ---------------------------------------------------------------------------
// MEMBERSHIP, which is the reason the grammar is strict.
//
// "Does this identifier belong to that trust domain" is the question every
// federation decision turns on, and the wrong way to answer it is
// `id.startsWith('spiffe://example.org')` — which says yes to
// `spiffe://example.org.attacker.test/x` and to `spiffe://example.org@evil/x`.
// Both are refused by parse() above, but a caller that never parsed would never
// find out. So membership is a comparison of two PARSED trust domains and
// nothing else.
// ---------------------------------------------------------------------------
function memberOf(value, trustDomain) {
  log.debug("Entering memberOf().");
  var parsed = parse(value);
  if (!parsed.ok) {
    log.debug("Leaving memberOf(). Not a SPIFFE ID.");
    return false;
  }
  var wanted = String(trustDomain == null ? "" : trustDomain).trim();
  // The wanted side may be given as a name or as a trust-domain identifier;
  // both spellings reach this function from real call sites.
  if (wanted.slice(0, PREFIX.length).toLowerCase() === PREFIX) {
    var other = parse(wanted);
    wanted = other.ok ? other.trustDomain : "";
  }
  var same = !!wanted && parsed.trustDomain === wanted;
  log.debug("Leaving memberOf(). " + same);
  return same;
}

// ---------------------------------------------------------------------------
// THE PROTOBUF SHAPE, both ways.
//
// `spire.api.types.SPIFFEID` is `{ trust_domain, path }` — the NAME without the
// scheme, and the path WITH its leading slash. Both halves are easy to get
// wrong in a way that produces a message the far end accepts and reads as
// naming something else: a `trust_domain` of `spiffe://example.org` names a
// trust domain called "spiffe://example.org", and a `path` with no leading
// slash names a different path.
// ---------------------------------------------------------------------------
function toProto(value) {
  log.debug("Entering toProto().");
  var parsed = parse(value);
  if (!parsed.ok) {
    log.debug("Leaving toProto(). Invalid.");
    throw new Error("Cannot put " + value + " into a SPIFFEID message: " +
                    parsed.reason);
  }
  log.debug("Leaving toProto().");
  return { trust_domain: parsed.trustDomain, path: parsed.path };
}

function fromProto(message) {
  log.debug("Entering fromProto().");
  if (!message) {
    log.debug("Leaving fromProto(). No message.");
    return "";
  }
  var domain = String(message.trust_domain || "");
  var path = String(message.path || "");
  if (!domain) {
    log.debug("Leaving fromProto(). No trust domain.");
    return "";
  }
  if (path && path.charAt(0) !== "/") {
    path = "/" + path;
  }
  log.debug("Leaving fromProto().");
  return PREFIX + domain + path;
}

module.exports = {
  SCHEME: SCHEME,
  PREFIX: PREFIX,
  MAX_ID_BYTES: MAX_ID_BYTES,
  MAX_TRUST_DOMAIN_BYTES: MAX_TRUST_DOMAIN_BYTES,
  RESERVED_PREFIX: RESERVED_PREFIX,
  parse: parse,
  isValid: isValid,
  make: make,
  trustDomainId: trustDomainId,
  trustDomainOf: trustDomainOf,
  serverId: serverId,
  isReservedPath: isReservedPath,
  memberOf: memberOf,
  toProto: toProto,
  fromProto: fromProto
};
