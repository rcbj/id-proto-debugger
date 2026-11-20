// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: scim_client.js
//
// ---------------------------------------------------------------------------
// SCIM 2.0 (RFC 7642, 7643, 7644) — WHAT TO SEND, WHAT CAME BACK, AND WHAT A
// SCENARIO IS. NO DOM AND NO NETWORK.
//
// This module builds SCIM requests and reads SCIM answers. It does not perform
// one: `scim.js` does that in the browser or hands it to the api, and which of
// those happened is a choice the page offers rather than a fact this file
// knows. That split is the same one `symmetric_crypto.js`, `x509.js` and
// `krb5_client.js` already have here, and it exists for one reason — a module
// with no DOM and no socket can be driven end to end in node, so
// `tests/scim_engine.js` asserts every request this workflow can compose
// against RFC 7643's own field list without a browser, a server or a page.
//
// The alternative — building the request inside a click handler — is what makes
// a provisioning bug indistinguishable from a page bug. A `PATCH` whose `path`
// grammar is wrong and a `PATCH` that the button never sent both present as
// "nothing changed".
//
// ---------------------------------------------------------------------------
// THE CATALOGUE IS THE MODULE, AND IT IS NOT A LIST OF URLs.
//
// `OPERATIONS` below is the single source for six things that would otherwise
// drift apart:
//
//   * the method and path template of every endpoint RFC 7644 defines,
//   * which of them take a body and what SHAPE that body is,
//   * which query parameters section 3.4.2 allows on each,
//   * the SCOPE each needs (`read`, `write`, or none), which is what the mock
//     STS's `scim_auth.js` enforces and what the page has to be able to
//     demonstrate FAILING,
//   * the label the page draws and the label the history log records,
//   * what a scenario step compiles down to.
//
// A seventh endpoint added as a button on the page and not as a row here is the
// defect this arrangement exists to prevent: it would be uncovered by
// `tests/scim_engine.js`'s completeness check, which walks this table rather
// than the page.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS ARE LOAD-BEARING.
//
// **THE `id` IS OPAQUE AND IS PERCENT-ENCODED EXACTLY ONCE.** RFC 7643 section
// 3.1 says a client must not parse it, and against this project's mock STS it
// is an LDAP DN — `uid=alice,ou=users,dc=example,dc=com` — which contains `=`
// and `,` and, on a name with an escape in it, `\`. So every id goes through
// `encodeURIComponent` on its way into a path segment and NOTHING else touches
// it. Encoding twice is the failure that looks like a missing user: the server
// decodes once, gets `uid%3Dalice...`, and answers 404 about an id nobody has.
// `idPathSegment()` is the only place this happens, and it is one function so
// that there is one place for it to be right.
//
// **A FILTER IS SENT AS THE CALLER WROTE IT.** Section 3.4.2.2's grammar is the
// server's to parse, and a client that "helpfully" quotes or escapes a filter
// makes the one error a debugger exists to show — `invalidFilter` —
// unreachable.
// So `filter` is carried verbatim into the query string (URL-encoded as a
// parameter value, which is transport and not grammar) and the page's own
// filter presets are strings a person can read and edit.
//
// **EVERY OPTIONAL FIELD RFC 7643 DEFINES IS GENERABLE.** `randomUser()` emits
// the complete section 4.1 User — including the six sub-attributes of `name`,
// the five multi-valued types with their `type`/`primary`/`display`, all four
// `addresses` sub-attributes plus `formatted`, and the whole section 4.3
// enterprise extension — because a provisioning client that has only ever sent
// `userName` and `emails` has tested nothing about the fields it will meet in
// the field. What the mock STS STORES is a narrower window than that (see
// `scim_map.js` there), and the difference is the point: a field that round-
// trips and a field that is accepted and dropped are different answers, and
// this page shows which one you got.
//
// **RANDOM IS SEEDED, AND THAT IS WHY IT IS USEFUL.** `newRng()` is a
// mulberry32 over a caller-supplied seed, so "randomly define a scenario" is
// reproducible: the page shows the seed, a test pins one, and a failure that
// only happens on the 7th generated user can be re-run exactly. An unseeded
// `Math.random()` would make every interesting failure a story rather than a
// test. The seed is a string so a person can type one.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The three hash functions HTTP Digest needs, and NONE of them is Web Crypto —
// see the DIGEST_ALGORITHMS note below for why that is the point rather than a
// preference. Both packages are already dependencies of this build.
var forge = require("node-forge");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512_256 = require("@noble/hashes/sha512").sha512_256;
// RFC 6750 section 2.1. A pasted access token may already be
// "Bearer <token>" or "DPoP <token>", because Copy Token writes
// credentials. tokenValue() returns the b64token either way.
var rfc6750 = require("./rfc6750");

// A node consumer (tests/scim_engine.js and tests/scim_protocol.js load this
// module directly) may have no CONFIG_FILE, so fall back to info rather than
// failing to load.
var log = bunyan.createLogger({
  name: "scim_client",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// THE URNs. RFC 7643 section 3 and RFC 7644 sections 3.4.3, 3.7 and 3.12.
//
// Spelled out rather than built by concatenation: every one of these is
// compared byte for byte by a receiving server, and a URN assembled from parts
// is a URN with a place for a typo to hide. They are also what the page's
// "which schema is this" readout matches against.
// ---------------------------------------------------------------------------
var USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
var GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
var ENTERPRISE_SCHEMA =
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
var SERVICE_PROVIDER_CONFIG_SCHEMA =
  'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
var RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
var SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';
var LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
var SEARCH_REQUEST_SCHEMA =
  'urn:ietf:params:scim:api:messages:2.0:SearchRequest';
var PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
var BULK_REQUEST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest';
var BULK_RESPONSE_SCHEMA =
  'urn:ietf:params:scim:api:messages:2.0:BulkResponse';
var ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

// The media type. RFC 7644 section 3.1: a SCIM server answers with this and
// accepts it on a request body. `application/json` is accepted by most servers
// and by this project's mock, which is exactly why the page sends the right one
// — a debugger that gets away with the wrong header teaches the wrong habit.
var SCIM_CONTENT_TYPE = 'application/scim+json';

// The default base path. Every implementation uses it and the mock STS bakes it
// into every `meta.location`, so it is a default rather than a constant: a
// caller pointing this page at somebody else's server may need another.
var DEFAULT_BASE_PATH = '/scim/v2';

// RFC 7486's algorithm registry, and there is currently ONE entry that matters:
// "0" is RSA-SHA256. It is a string and not the number 0 because it goes into
// the signed blob as a field, where its LENGTH is prefixed — so `0` and `"0"`
// would produce `1:0` either way and an integer that ever reached two digits
// would not. Spelled as a string so it cannot be arithmetic by accident.
//
// The consequence worth knowing before generating a key: HOBA here means an
// **RSA** key. An ECDSA key produces a signature this scheme has no algorithm
// identifier for, and the server has nothing to check it with.
var HOBA_ALG_RSA_SHA256 = '0';

// RFC 7486 section 7 puts key registration here, and this project's mock STS
// implements it: a form-encoded POST carrying `pub=<PEM public key>` and
// `username=<who it is for>`. It is a well-known path on the SERVER'S ORIGIN
// and not under the SCIM base path, which is why the page composes it from the
// origin rather than from the service root.
var HOBA_REGISTRATION_PATH = '/.well-known/hoba/register';

// ---------------------------------------------------------------------------
// THE CATALOGUES: RFC 7644 section 3.12's error codes, section 2's
// authentication schemes, and the endpoints of sections 3.2 through 3.12 and
// 4. They are rows, not code, so they are written once in
// models/catalog/scim.tsp — where the reasoning for each table now lives —
// and generated into client/src/catalog/ (models/CLAUDE.md, "Catalogues").
//
// `SCIM_TYPES` is a CLOSED list (a server may not invent a scimType), and the
// model's ScimErrorTypes is closed with it. `AUTH_SCHEMES` is section 2's six
// plus `none` and Digest; DO NOT ADD AN API KEY ROW, for the reason the model
// gives. `OPERATIONS[].query` is what the page builds its query-string editor
// from, so an operation that does not accept `sortBy` does not offer one.
// ---------------------------------------------------------------------------
var SCIM_TYPES = require("./catalog/scim_error_types.json");
var AUTH_SCHEMES = require("./catalog/scim_auth_schemes.json");
var OPERATIONS = require("./catalog/scim_operations.json");

var OPERATIONS_BY_ID = (function () {
  var index = {};
  OPERATIONS.forEach(function (row) {
    index[row.id] = row;
  });
  return index;
})();

function operation(id) {
  log.debug("Entering operation(). id=" + id);
  var row = OPERATIONS_BY_ID[String(id)];
  if (!row) {
    log.debug("Leaving operation(). No such operation.");
    return null;
  }
  log.debug("Leaving operation().");
  return row;
}

function operationsInGroup(group) {
  log.debug("Entering operationsInGroup(). group=" + group);
  var rows = OPERATIONS.filter(function (row) {
    return row.group === group;
  });
  log.debug("Leaving operationsInGroup(). " + rows.length + " operation(s).");
  return rows;
}

function authScheme(id) {
  log.debug("Entering authScheme(). id=" + id);
  var found = null;
  AUTH_SCHEMES.forEach(function (row) {
    if (row.id === String(id)) {
      found = row;
    }
  });
  log.debug("Leaving authScheme().");
  return found;
}

// ---------------------------------------------------------------------------
// URL CONSTRUCTION.
//
// `baseUrl` is the SERVICE root (`https://host/scim/v2`) with any trailing
// slash removed, because every path template below starts with one and
// `//Users` is a different URL from `/Users` to a server that routes on the
// literal path. This has bitten a client here before, on the metadata pages.
// ---------------------------------------------------------------------------
function normalizeBaseUrl(url) {
  log.debug("Entering normalizeBaseUrl().");
  var text = String(url || '').trim();
  while (text.length > 1 && text.charAt(text.length - 1) === '/') {
    text = text.slice(0, text.length - 1);
  }
  log.debug("Leaving normalizeBaseUrl(). " + text);
  return text;
}

// ---------------------------------------------------------------------------
// THE RESOURCE ENDPOINT, WHICH IS DISCOVERED AND NOT ASSUMED.
//
// Every path template above carries `/Users` or `/Groups`, and both are
// conventions rather than requirements: RFC 7643 section 6 defines a
// ResourceType's `endpoint` as "the resource's HTTP-addressable endpoint
// relative to the Base URL", RFC 7644 section 4 has the server publish one per
// type, and a server answering on `/user` is conformant. A client that hard
// codes the convention meets that server with a 404 on every operation — a
// failure that names an id nobody has rather than a path nobody serves.
//
// So `buildRequest` takes an OPTIONAL `endpoints` map, `{ User: '/Users',
// Group: '/Groups' }`, which the page fills from the ResourceTypes document
// and lets the user override in the Configuration Parameters pane. Absent, or
// naming the default, nothing changes — the swap is a prefix substitution on
// the rows that name a resource type, and the discovery, `/.search`, `/Bulk`
// and `/Me` paths carry none and are left exactly as they are.
// ---------------------------------------------------------------------------
var DEFAULT_ENDPOINTS = { User: '/Users', Group: '/Groups' };

function normalizeEndpoint(text) {
  log.debug("Entering normalizeEndpoint().");
  var value = String(text === undefined || text === null ? '' : text).trim();
  if (value === '') {
    log.debug("Leaving normalizeEndpoint(). Empty.");
    return '';
  }
  if (value.charAt(0) !== '/') {
    value = '/' + value;
  }
  while (value.length > 1 && value.charAt(value.length - 1) === '/') {
    value = value.slice(0, value.length - 1);
  }
  log.debug("Leaving normalizeEndpoint(). " + value);
  return value;
}

function resourcePath(row, endpoints) {
  log.debug("Entering resourcePath(). operation=" + row.id);
  var fallback = DEFAULT_ENDPOINTS[row.resourceType || ''];
  var wanted = (endpoints && row.resourceType)
    ? normalizeEndpoint(endpoints[row.resourceType]) : '';
  if (!fallback || wanted === '' || wanted === fallback) {
    log.debug("Leaving resourcePath(). The default.");
    return row.path;
  }
  if (row.path.indexOf(fallback) !== 0) {
    // A row naming a resource type whose path does not begin with that
    // type's endpoint. There is no such row today, and one added later is a
    // defect in the catalogue rather than an override to apply blindly — a
    // silent substitution here would produce a URL nobody wrote.
    log.warn('the ' + row.id + ' operation names the ' + row.resourceType +
        ' resource type but its path (' + row.path + ') does not begin with ' +
        fallback + ', so the discovered endpoint was not applied');
    log.debug("Leaving resourcePath(). Not a prefix.");
    return row.path;
  }
  var swapped = wanted + row.path.slice(fallback.length);
  log.debug("Leaving resourcePath(). " + swapped);
  return swapped;
}

// The one place an id becomes a path segment. See the header: exactly once,
// and nowhere else.
function idPathSegment(id) {
  log.debug("Entering idPathSegment().");
  var segment = encodeURIComponent(String(id === undefined ? '' : id));
  log.debug("Leaving idPathSegment().");
  return segment;
}

function queryString(params) {
  log.debug("Entering queryString().");
  var parts = [];
  Object.keys(params || {}).forEach(function (name) {
    var value = params[name];
    if (value === undefined || value === null || String(value) === '') {
      return;
    }
    parts.push(encodeURIComponent(name) + '=' + encodeURIComponent(value));
  });
  var text = parts.length ? '?' + parts.join('&') : '';
  log.debug("Leaving queryString(). " + parts.length + " parameter(s).");
  return text;
}

// ---------------------------------------------------------------------------
// BUILDING ONE REQUEST.
//
// Returns a plain object — method, url, headers, body — and performs nothing.
// The page hands it to `fetch` or to the api; `tests/scim_engine.js` reads it.
//
// `endpoints` is optional and is the discovered `/Users` / `/Groups` override
// described above; absent, the catalogue's own paths are used unchanged.
//
// `body` is returned as an OBJECT and not as a string, and the serialization
// happens at the edge. Two reasons: the api's proxy wants JSON it can forward
// as JSON, and a test asserting the shape of a PatchOp should not have to parse
// its own fixture back out of a string to do it.
// ---------------------------------------------------------------------------
function buildRequest(spec) {
  log.debug("Entering buildRequest(). operation=" +
      (spec && spec.operation));
  var row = operation(spec && spec.operation);
  if (!row) {
    log.debug("Leaving buildRequest(). Unknown operation.");
    throw new Error('Unknown SCIM operation: ' + (spec && spec.operation));
  }
  var base = normalizeBaseUrl(spec.baseUrl);
  var path = resourcePath(row, spec.endpoints);
  if (path.indexOf('{id}') >= 0) {
    if (spec.id === undefined || String(spec.id) === '') {
      log.debug("Leaving buildRequest(). This operation needs an id.");
      throw new Error(row.label + ' needs a resource id.');
    }
    path = path.replace('{id}', idPathSegment(spec.id));
  }
  var query = {};
  (row.query || []).forEach(function (name) {
    if (spec.query && spec.query[name] !== undefined) {
      query[name] = spec.query[name];
    }
  });
  var headers = { Accept: SCIM_CONTENT_TYPE };
  var body = spec.body === undefined ? null : spec.body;
  if (row.body && body !== null) {
    headers['Content-Type'] = SCIM_CONTENT_TYPE;
  }
  var request = {
    operation: row.id,
    label: row.label,
    resourceType: row.resourceType || '',
    need: row.need,
    method: row.method,
    url: base + path + queryString(query),
    headers: headers,
    body: body
  };
  log.debug("Leaving buildRequest(). " + request.method + " " + request.url);
  return request;
}

// ---------------------------------------------------------------------------
// AUTHENTICATION, APPLIED TO A BUILT REQUEST.
//
// One function per scheme, all returning the same shape, so the page's
// selector is a lookup rather than a switch that grows a branch per scheme.
// Each returns `{headers, credentials, note}` — `credentials` being the fetch
// option a cookie needs, and `note` being what the page shows about a scheme
// that adds nothing to the request, so that "nothing was added" is a statement
// rather than a silence.
//
// **NOTHING HERE COMPUTES A SIGNATURE.** DPoP and HOBA return the string to be
// signed and the page signs it with Web Crypto; Digest returns what it needs
// from the challenge and the page hashes it. See the header for why.
// ---------------------------------------------------------------------------
function basicHeader(username, password) {
  log.debug("Entering basicHeader().");
  var raw = String(username || '') + ':' + String(password || '');
  var encoded;
  try {
    // btoa in a browser, Buffer in node. Both are here because this module is
    // loaded in both and neither exists in the other.
    if (typeof btoa === 'function') {
      encoded = btoa(unescape(encodeURIComponent(raw)));
    } else {
      encoded = Buffer.from(raw, 'utf8').toString('base64');
    }
  } catch (e) {
    log.debug("Leaving basicHeader(). Could not encode: " + e.message);
    throw e;
  }
  log.debug("Leaving basicHeader().");
  return 'Basic ' + encoded;
}

// ---------------------------------------------------------------------------
// HTTP DIGEST (RFC 7616), COMPUTED HERE AND NOT IN THE PAGE.
//
// This is the one scheme whose credential is a cryptographic computation over
// values the SERVER chose, and it lives in this DOM-free module for the reason
// everything else here does: `tests/scim_engine.js` can then check the response
// hash against a fixed vector with no browser, and `tests/scim_protocol.js` can
// perform a real two-leg handshake in node against the mock. A version of this
// inside a click handler would be checkable only by whether a server said yes,
// which cannot tell a wrong hash from a wrong password.
//
// **ALL THREE REGISTERED ALGORITHMS ARE HERE, AND THAT IS DELIBERATE.** RFC
// 7616 section 6.1 registers MD5, SHA-256 and SHA-512-256, each with a `-sess`
// variant, and the mock STS offers all three — its challenge is THREE `Digest`
// challenges in one header, one per algorithm, sharing a nonce. An
// implementation that did SHA-256 only would work against that server and fail
// against the many real ones that still offer MD5 alone, reporting it as bad
// credentials.
//
// They are SYNCHRONOUS and none of them is Web Crypto, which is what makes this
// possible at all: `crypto.subtle` has neither MD5 (removed from browsers on
// purpose) nor SHA-512/256 (a different function from SHA-512 truncated, with
// its own initial values), and it is asynchronous, which would make a
// credential a promise. node-forge supplies MD5 and @noble/hashes the other
// two, and both are already dependencies of this build.
//
// **MD5 IS OFFERED AND IS NOT ENDORSED.** It is broken for collision resistance
// and Digest's use of it is a keyed construction rather than a signature, so it
// is not immediately broken here — but a debugger's job is to reach the server
// in front of it and say what it found, not to refuse to speak to it. The page
// labels it.
// ---------------------------------------------------------------------------
var DIGEST_ALGORITHMS = [
  // In PREFERENCE order, strongest first. `chooseDigestChallenge()` walks this
  // list and takes the first the server offered — so a server offering all
  // three gets SHA-256, and one offering only MD5 still works.
  { token: 'SHA-256', hash: sha256Hex },
  { token: 'SHA-512-256', hash: sha512_256Hex },
  { token: 'MD5', hash: md5Hex }
];

function sha256Hex(text) {
  log.debug("Entering sha256Hex().");
  var out = hexOf(nobleSha256(new Uint8Array(utf8Bytes(text))));
  log.debug("Leaving sha256Hex().");
  return out;
}

function sha512_256Hex(text) {
  log.debug("Entering sha512_256Hex().");
  var out = hexOf(nobleSha512_256(new Uint8Array(utf8Bytes(text))));
  log.debug("Leaving sha512_256Hex().");
  return out;
}

function md5Hex(text) {
  log.debug("Entering md5Hex().");
  var digest = forge.md.md5.create();
  // forge's `update` takes a binary string; `utf8` tells it to encode first,
  // which is what makes a non-ASCII password hash the same here as it does on
  // a server that hashed the UTF-8 bytes.
  digest.update(String(text), 'utf8');
  var out = digest.digest().toHex();
  log.debug("Leaving md5Hex().");
  return out;
}

function utf8Bytes(text) {
  log.debug("Entering utf8Bytes().");
  var bytes;
  if (typeof TextEncoder === 'function') {
    bytes = new TextEncoder().encode(String(text));
  } else {
    bytes = Buffer.from(String(text), 'utf8');
  }
  log.debug("Leaving utf8Bytes(). " + bytes.length + " byte(s).");
  return bytes;
}

function hexOf(bytes) {
  // Hot: called once per hash, and a Digest credential is five of them.
  var out = '';
  var i;
  for (i = 0; i < bytes.length; i++) {
    out += ('0' + bytes[i].toString(16)).slice(-2);
  }
  return out;
}

// The algorithm token as it appears in a challenge, with the `-sess` suffix
// separated off. RFC 7616 section 3.4.2: the `-sess` variants fold the two
// nonces into A1 so the long-term secret is hashed once per session rather than
// once per request. It is a different A1 and the same everything else, which is
// why it is a flag here rather than three more rows.
function digestAlgorithm(token) {
  log.debug("Entering digestAlgorithm(). token=" + token);
  var text = String(token || 'MD5');
  var session = /-sess$/i.test(text);
  var base = text.replace(/-sess$/i, '').toUpperCase();
  var found = null;
  DIGEST_ALGORITHMS.forEach(function (row) {
    if (row.token.toUpperCase() === base) {
      found = row;
    }
  });
  if (!found) {
    log.debug("Leaving digestAlgorithm(). Unknown: " + base);
    return null;
  }
  log.debug("Leaving digestAlgorithm(). " + found.token +
      (session ? '-sess' : ''));
  return { row: found, session: session, token: text };
}

// ---------------------------------------------------------------------------
// Pick which of the server's Digest challenges to answer.
//
// A server may send SEVERAL — the mock sends three, one per algorithm, sharing
// one nonce — and RFC 7235 section 4.1 allows it. Taking the LAST one parsed is
// the obvious mistake and it is the wrong answer twice over: it is arbitrary,
// and because the list is conventionally ordered weakest-last it reliably picks
// MD5 over SHA-256. So this walks the PREFERENCE order above and takes the
// first the server actually offered.
// ---------------------------------------------------------------------------
function chooseDigestChallenge(challenges) {
  log.debug("Entering chooseDigestChallenge().");
  var offered = (challenges || []).filter(function (row) {
    return String(row.scheme).toLowerCase() === 'digest';
  });
  if (!offered.length) {
    log.debug("Leaving chooseDigestChallenge(). The server offered none.");
    return null;
  }
  var i;
  var j;
  for (i = 0; i < DIGEST_ALGORITHMS.length; i++) {
    for (j = 0; j < offered.length; j++) {
      var named = offered[j].params.algorithm || 'MD5';
      var parsed = digestAlgorithm(named);
      if (parsed && parsed.row.token === DIGEST_ALGORITHMS[i].token) {
        log.debug("Leaving chooseDigestChallenge(). " + named);
        return { challenge: offered[j], algorithm: parsed };
      }
    }
  }
  // Every challenge names an algorithm this build cannot compute. Returned as
  // a REFUSAL carrying the list rather than as null, so the page can say which
  // algorithms were asked for instead of "Digest failed".
  var names = offered.map(function (row) {
    return row.params.algorithm || 'MD5';
  });
  log.debug("Leaving chooseDigestChallenge(). None computable: " +
      names.join(', '));
  return { unsupported: names };
}

// ---------------------------------------------------------------------------
// Build the credential. RFC 7616 sections 3.4.2 through 3.4.6.
//
// Three details are the ones implementations get wrong, and each has its own
// line below:
//
//   * **`uri` is the REQUEST-TARGET, not the absolute URL** — the path and
//     query, exactly as it will appear on the request line. It is hashed into
//     A2 and compared by the server against what actually arrived, so an
//     absolute URL here produces a perfectly well-formed credential that
//     matches nothing.
//   * **`nc` MUST increase per nonce.** It is what makes a Digest credential
//     single-use, and a server that tracks it — the mock does — refuses a
//     repeat as a replay, WITHOUT `stale=true`. A client that hardcodes
//     00000001 therefore works exactly once per nonce and then starts failing
//     in a way that reads as expired credentials. The counter is the caller's,
//     which is why it is a parameter.
//   * **`nc` and `qop` are UNQUOTED and everything else is quoted.** A server
//     that parses strictly refuses a quoted `nc`, and that refusal also reads
//     as bad credentials.
// ---------------------------------------------------------------------------
function digestCredential(options) {
  log.debug("Entering digestCredential().");
  var settings = options || {};
  var parsed = settings.algorithm ||
      digestAlgorithm((settings.params && settings.params.algorithm) || 'MD5');
  if (!parsed) {
    log.debug("Leaving digestCredential(). Unknown algorithm.");
    return null;
  }
  var hash = parsed.row.hash;
  var params = settings.params || {};
  var realm = settings.realm || params.realm || '';
  var nonce = params.nonce || '';
  var cnonce = settings.cnonce || '';
  var nc = settings.nc || '00000001';
  // The server offers `qop="auth"`; `auth-int` hashes the entity body and is
  // deliberately not attempted — see the mock's own note on why it does not
  // offer it either.
  var qop = String(params.qop || '').split(',')[0].trim().toLowerCase();
  if (qop && qop !== 'auth') {
    qop = 'auth';
  }
  var uri = settings.uri;
  var ha1 = hash(String(settings.username) + ':' + realm + ':' +
      String(settings.password));
  if (parsed.session) {
    ha1 = hash(ha1 + ':' + nonce + ':' + cnonce);
  }
  var ha2 = hash(String(settings.method).toUpperCase() + ':' + uri);
  var response = qop === 'auth'
    ? hash(ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':auth:' + ha2)
    : hash(ha1 + ':' + nonce + ':' + ha2);
  var fields = {
    username: settings.username,
    realm: realm,
    nonce: nonce,
    uri: uri,
    response: response,
    opaque: params.opaque || '',
    algorithm: parsed.token
  };
  if (qop === 'auth') {
    fields.cnonce = cnonce;
    fields.qop = 'auth';
    fields.nc = nc;
  }
  // Kept so the caller can check the server's own Authentication-Info against
  // it without recomputing HA1 — see verifyAuthenticationInfo().
  fields.ha1 = ha1;
  log.debug("Leaving digestCredential(). " + parsed.token + ", nc=" + nc);
  return fields;
}

// ---------------------------------------------------------------------------
// RFC 7616 section 3.5 — the half nobody implements.
//
// `Authentication-Info: rspauth="..."` is how a client authenticates the
// SERVER: it is the same construction as the response with an EMPTY method in
// A2, so only somebody who knows the password could have produced it. Leaving
// it out is the commonest way to implement Digest, and a client that never
// checks it has mutual authentication available and unused.
//
// This is why `digestCredential()` hands back `ha1`: recomputing it here would
// mean carrying the password to a second place.
// ---------------------------------------------------------------------------
function verifyAuthenticationInfo(options) {
  log.debug("Entering verifyAuthenticationInfo().");
  var settings = options || {};
  var header = String(settings.header || '').trim();
  if (header === '') {
    log.debug("Leaving verifyAuthenticationInfo(). The server sent none.");
    return { present: false, ok: false,
      note: 'The server sent no Authentication-Info header. RFC 7616 section ' +
          '3.5 makes it the way a client authenticates the SERVER, and it is ' +
          'the half of Digest most implementations leave out — so its ' +
          'absence is ordinary rather than suspicious, and it does mean this ' +
          'exchange authenticated one direction only.' };
  }
  var parsed = { scheme: '', params: {} };
  header.split(/,\s*/).forEach(function (token) {
    addChallengeParam(parsed, token);
  });
  var given = String(parsed.params.rspauth || '').toLowerCase();
  if (given === '') {
    log.debug("Leaving verifyAuthenticationInfo(). No rspauth in it.");
    return { present: true, ok: false,
      note: 'The Authentication-Info header carries no rspauth, so there is ' +
          'nothing in it to check the server against.' };
  }
  var fields = settings.fields || {};
  var parsedAlgorithm = digestAlgorithm(fields.algorithm || 'MD5');
  if (!parsedAlgorithm) {
    log.debug("Leaving verifyAuthenticationInfo(). Unknown algorithm.");
    return { present: true, ok: false,
      note: 'The credential named an algorithm this build cannot compute, so ' +
          'the server\'s rspauth cannot be checked either.' };
  }
  var hash = parsedAlgorithm.row.hash;
  // A2 with an EMPTY method — that is the whole difference from the request
  // side, and it is what stops the server simply echoing the client's own
  // response back.
  var ha2 = hash(':' + fields.uri);
  var expected = fields.qop === 'auth'
    ? hash(fields.ha1 + ':' + fields.nonce + ':' + fields.nc + ':' +
           fields.cnonce + ':auth:' + ha2)
    : hash(fields.ha1 + ':' + fields.nonce + ':' + ha2);
  var same = given === expected;
  log.debug("Leaving verifyAuthenticationInfo(). " + same);
  return {
    present: true,
    ok: same,
    note: same
      ? 'The server\'s rspauth verifies: it knows the password too, so this ' +
        'exchange authenticated BOTH directions. That is RFC 7616 section ' +
        '3.5, and it is the half most implementations leave out.'
      : 'The server sent an rspauth that does not verify against this ' +
        'credential. Either it computed it differently or something between ' +
        'here and there rewrote the exchange.'
  };
}

// RFC 7616 section 3.4. The ORDERED FIELD LIST and the exact quoting rules,
// which is the half implementations get wrong. `qop=auth` fields are unquoted
// (`nc`, `qop`) and so is `algorithm`; everything else is quoted. A server that
// parses strictly refuses a quoted `nc`, and that refusal reads as bad
// credentials.
function digestHeader(fields) {
  log.debug("Entering digestHeader().");
  var quoted = ['username', 'realm', 'nonce', 'uri', 'response', 'opaque',
                'cnonce'];
  var bare = ['qop', 'nc', 'algorithm'];
  var parts = [];
  quoted.concat(bare).forEach(function (name) {
    var value = fields[name];
    if (value === undefined || value === null || String(value) === '') {
      return;
    }
    if (quoted.indexOf(name) >= 0) {
      parts.push(name + '="' + String(value).split('"').join('\\"') + '"');
      return;
    }
    parts.push(name + '=' + value);
  });
  var header = 'Digest ' + parts.join(', ');
  log.debug("Leaving digestHeader(). " + parts.length + " field(s).");
  return header;
}

// RFC 7235 section 4.1. A challenge is `Scheme param=value, param="value"` and
// there may be SEVERAL of them in one header, which is the part a naive split
// on ',' destroys — `Digest realm="x", nonce="y", Basic realm="z"` is two
// challenges and five commas. So the scheme names are found first and the
// parameters between them are parsed per challenge.
function parseChallenges(headerValue) {
  log.debug("Entering parseChallenges().");
  var text = String(headerValue || '').trim();
  var out = [];
  if (text === '') {
    log.debug("Leaving parseChallenges(). Nothing to parse.");
    return out;
  }
  // A scheme token is a bare word followed by whitespace-and-a-parameter or by
  // the end; a parameter is name=value. Walk the string keeping the current
  // challenge open until a token that is a scheme name appears.
  var tokens = text.split(/,\s*/);
  var current = null;
  tokens.forEach(function (token) {
    var schemeMatch = token.match(/^([A-Za-z][A-Za-z0-9_-]*)(\s+(.*))?$/);
    var isParameter = /^[A-Za-z0-9_-]+\s*=/.test(token);
    if (schemeMatch && !isParameter) {
      current = { scheme: schemeMatch[1], params: {} };
      out.push(current);
      if (schemeMatch[3]) {
        addChallengeParam(current, schemeMatch[3]);
      }
      return;
    }
    if (current === null) {
      current = { scheme: '', params: {} };
      out.push(current);
    }
    addChallengeParam(current, token);
  });
  log.debug("Leaving parseChallenges(). " + out.length + " challenge(s).");
  return out;
}

// Every challenge for one scheme, which is not always one: RFC 7235 section 4.1
// allows several, and the mock STS sends three Digest challenges in a single
// header — one per algorithm, sharing a nonce. A helper that returned "the"
// challenge for a scheme would have to pick, and picking is a decision that
// belongs to whoever knows what it can compute.
function challengesFor(challenges, scheme) {
  log.debug("Entering challengesFor(). scheme=" + scheme);
  var wanted = String(scheme).toLowerCase();
  var out = (challenges || []).filter(function (row) {
    return String(row.scheme).toLowerCase() === wanted;
  });
  log.debug("Leaving challengesFor(). " + out.length + " challenge(s).");
  return out;
}

function addChallengeParam(challenge, text) {
  log.debug("Entering addChallengeParam().");
  var match = String(text).match(/^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$/);
  if (!match) {
    log.debug("Leaving addChallengeParam(). Not a parameter.");
    return;
  }
  var value = match[2].trim();
  if (value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') {
    value = value.slice(1, value.length - 1);
  }
  challenge.params[match[1].toLowerCase()] = value;
  log.debug("Leaving addChallengeParam(). " + match[1]);
}

// RFC 7486 section 5. THE BLOB IS LENGTH-PREFIXED, NOT DELIMITED: each field
// becomes its length in OCTETS, a colon, then the field, and the six are
// concatenated with nothing between them. That is the detail worth stating
// twice, because a dot-joined or newline-joined version looks perfectly
// reasonable, produces a signature of exactly the right size and shape, and
// verifies against nothing at all — and the only error a server can give back
// is "this does not verify", which sends everybody to look at their key.
//
// The ORDER is normative too: nonce, algorithm, origin, realm, key id,
// challenge.
//
// The length is in octets and not in characters, which is why this counts UTF-8
// bytes rather than `String.length`. Every field here is ASCII in practice, so
// the two agree — until a realm carries an accent, at which point they do not
// and the failure is the same silent one.
function hobaToBeSigned(parts) {
  log.debug("Entering hobaToBeSigned().");
  var fields = [parts.nonce, parts.alg, parts.origin, parts.realm,
                parts.kid, parts.challenge];
  var text = fields.map(function (value) {
    var field = String(value === undefined || value === null ? '' : value);
    return utf8Length(field) + ':' + field;
  }).join('');
  log.debug("Leaving hobaToBeSigned(). " + text.length + " characters.");
  return text;
}

// The length of a string in UTF-8 OCTETS. `Buffer` in node, and in a browser
// the encoder — neither exists in the other, and this module is loaded in both.
function utf8Length(text) {
  log.debug("Entering utf8Length().");
  var length;
  if (typeof TextEncoder === 'function') {
    length = new TextEncoder().encode(String(text)).length;
  } else {
    length = Buffer.byteLength(String(text), 'utf8');
  }
  log.debug("Leaving utf8Length(). " + length);
  return length;
}

// The origin a HOBA signature is bound to: scheme, host and PORT, and nothing
// else. A path in there is the mistake that makes one registration work on one
// endpoint of a server and not another.
//
// **THE PORT IS ALWAYS EXPLICIT, INCLUDING THE DEFAULT ONE.** RFC 7486 gives
// the origin no serialization of its own, so `https://host` and
// `https://host:443` are two different strings over which two different
// signatures are computed — and a browser's `location.origin` omits the default
// port while a server reconstructing it from Host usually does not. This spells
// it out, which is what makes a signature made here verify there.
function originOf(url) {
  log.debug("Entering originOf().");
  var match = String(url || '')
    .match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#:]+)(?::(\d+))?/);
  if (!match) {
    log.debug("Leaving originOf(). Not an absolute URL.");
    return '';
  }
  var scheme = match[1].toLowerCase();
  var port = match[3] || (scheme === 'https' ? '443' : '80');
  var origin = scheme + '://' + match[2] + ':' + port;
  log.debug("Leaving originOf(). " + origin);
  return origin;
}

// ---------------------------------------------------------------------------
// Apply a scheme to a built request. `secrets` carries whatever that scheme
// needs and is never stored by this module — persistence is the page's decision
// and its rule is in scim.js.
// ---------------------------------------------------------------------------
function applyAuth(request, auth) {
  log.debug("Entering applyAuth(). scheme=" + (auth && auth.scheme));
  var scheme = authScheme(auth && auth.scheme ? auth.scheme : 'none');
  var out = {
    headers: {},
    credentials: 'same-origin',
    note: '',
    scheme: scheme ? scheme.id : 'none'
  };
  if (!scheme || scheme.id === 'none') {
    out.note = 'Nothing was added to this request.';
    log.debug("Leaving applyAuth(). Anonymous.");
    return out;
  }
  if (scheme.id === 'bearer') {
    var bearerToken = rfc6750.tokenValue(String(auth.token || ''));
    out.headers.Authorization = 'Bearer ' + bearerToken;
    out.note = 'Authorization: Bearer, ' +
        bearerToken.length + ' characters.';
    log.debug("Leaving applyAuth(). Bearer.");
    return out;
  }
  if (scheme.id === 'dpop') {
    var dpopToken = rfc6750.tokenValue(String(auth.token || ''));
    out.headers.Authorization = 'DPoP ' + dpopToken;
    if (auth.proof) {
      out.headers.DPoP = String(auth.proof);
    }
    out.note = auth.proof ? 'Authorization: DPoP, with a proof JWT bound to ' +
        request.method + ' ' + request.url + '.'
      : 'Authorization: DPoP, but NO proof was minted — the server will ' +
        'refuse this.';
    log.debug("Leaving applyAuth(). DPoP.");
    return out;
  }
  if (scheme.id === 'basic') {
    out.headers.Authorization = basicHeader(auth.username, auth.password);
    out.note = 'Authorization: Basic, as ' + String(auth.username || '') + '.';
    log.debug("Leaving applyAuth(). Basic.");
    return out;
  }
  if (scheme.id === 'digest') {
    if (!auth.digest) {
      out.note = 'No challenge has been collected yet. The first request is ' +
          'sent without credentials on purpose; its 401 carries the nonce ' +
          'this scheme needs.';
      log.debug("Leaving applyAuth(). Digest, first leg.");
      return out;
    }
    out.headers.Authorization = digestHeader(auth.digest);
    out.note = 'Authorization: Digest, over the nonce from the 401.';
    log.debug("Leaving applyAuth(). Digest, second leg.");
    return out;
  }
  if (scheme.id === 'hoba') {
    if (!auth.hoba) {
      out.note = 'No HOBA signature was produced, so nothing was added.';
      log.debug("Leaving applyAuth(). HOBA with no signature.");
      return out;
    }
    out.headers.Authorization = 'HOBA result="' +
        String(auth.hoba.kid) + '.' + String(auth.hoba.challenge) + '.' +
        String(auth.hoba.nonce) + '.' + String(auth.hoba.signature) + '"';
    out.note = 'Authorization: HOBA, signed by key ' +
        String(auth.hoba.kid) + '.';
    log.debug("Leaving applyAuth(). HOBA.");
    return out;
  }
  if (scheme.id === 'cookie') {
    out.credentials = 'include';
    out.note = 'Nothing was added to the request. The browser attaches a ' +
        'cookie for that origin if it has one, and this call was made with ' +
        'credentials so that it may.';
    log.debug("Leaving applyAuth(). Cookie.");
    return out;
  }
  // clientcert
  out.note = 'Nothing was added to the request. A client certificate is ' +
      'chosen during the TLS handshake, so the browser will offer one if ' +
      'the server asks for it and the keychain has a match.';
  log.debug("Leaving applyAuth(). Client certificate.");
  return out;
}

// ---------------------------------------------------------------------------
// READING WHAT CAME BACK.
//
// A SCIM answer is one of five things and telling them apart is most of what a
// reader wants: a resource, a ListResponse, a BulkResponse, an Error, or an
// empty 204. `describeResponse()` names which, so the page can say it in a
// sentence and the history log can record it.
//
// The status in a section 3.12 Error is A STRING. That is the detail everybody
// gets wrong and the one this reader is deliberately generous about: it accepts
// either and reports the disagreement, because a server sending a number is
// non-conforming in a way its own client will never notice.
// ---------------------------------------------------------------------------
function isScimError(body) {
  log.debug("Entering isScimError().");
  var schemas = body && body.schemas;
  var yes = Array.isArray(schemas) && schemas.indexOf(ERROR_SCHEMA) >= 0;
  log.debug("Leaving isScimError(). " + yes);
  return yes;
}

function describeResponse(status, body) {
  log.debug("Entering describeResponse(). status=" + status);
  var out = {
    status: status,
    kind: 'unknown',
    ok: status >= 200 && status < 300,
    summary: '',
    scimType: '',
    detail: '',
    count: null,
    conformance: []
  };
  if (status === 204) {
    out.kind = 'empty';
    out.summary = '204 No Content — the operation succeeded and there is no ' +
        'body. A delete answers this, and so does a PATCH that changed ' +
        'nothing.';
    log.debug("Leaving describeResponse(). Empty.");
    return out;
  }
  if (isScimError(body)) {
    out.kind = 'error';
    out.ok = false;
    out.scimType = String(body.scimType || '');
    out.detail = String(body.detail || '');
    if (typeof body.status === 'number') {
      out.conformance.push('The "status" member of this Error is a NUMBER. ' +
          'RFC 7644 section 3.12 defines it as a string.');
    }
    if (body.status !== undefined && String(body.status) !== String(status)) {
      out.conformance.push('The Error body says status ' + body.status +
          ' and the HTTP response said ' + status + '.');
    }
    out.summary = status + (out.scimType ? ' ' + out.scimType : '') +
        (out.detail ? ' — ' + out.detail : '');
    log.debug("Leaving describeResponse(). Error.");
    return out;
  }
  var schemas = (body && Array.isArray(body.schemas)) ? body.schemas : [];
  if (schemas.indexOf(LIST_RESPONSE_SCHEMA) >= 0) {
    out.kind = 'list';
    out.count = Number(body.totalResults);
    out.summary = 'A ListResponse: ' + body.totalResults + ' total, ' +
        ((body.Resources || []).length) + ' in this page, starting at ' +
        (body.startIndex === undefined ? 1 : body.startIndex) + '.';
    log.debug("Leaving describeResponse(). List.");
    return out;
  }
  if (schemas.indexOf(BULK_RESPONSE_SCHEMA) >= 0) {
    out.kind = 'bulk';
    var operations = (body && body.Operations) || [];
    out.count = operations.length;
    var failed = operations.filter(function (row) {
      return Number(row.status) >= 400;
    }).length;
    out.summary = 'A BulkResponse: ' + operations.length + ' operation(s), ' +
        failed + ' of them refused. Each carries its own status — the 200 on ' +
        'the envelope says the bulk was processed, not that everything in ' +
        'it worked.';
    log.debug("Leaving describeResponse(). Bulk.");
    return out;
  }
  if (schemas.indexOf(SERVICE_PROVIDER_CONFIG_SCHEMA) >= 0) {
    out.kind = 'serviceProviderConfig';
    out.summary = 'The ServiceProviderConfig.';
    log.debug("Leaving describeResponse(). ServiceProviderConfig.");
    return out;
  }
  if (schemas.indexOf(USER_SCHEMA) >= 0 || schemas.indexOf(GROUP_SCHEMA) >= 0) {
    out.kind = 'resource';
    out.summary = 'One resource, id ' + (body && body.id) + '.';
    log.debug("Leaving describeResponse(). Resource.");
    return out;
  }
  if (Array.isArray(body)) {
    out.kind = 'array';
    out.count = body.length;
    out.summary = 'An array of ' + body.length + ' item(s). The Schemas and ' +
        'ResourceTypes endpoints may answer this way rather than with a ' +
        'ListResponse; both are seen in the field.';
    log.debug("Leaving describeResponse(). Array.");
    return out;
  }
  out.summary = status + ' — a body this page does not recognise as any of ' +
      'RFC 7644\'s five shapes.';
  log.debug("Leaving describeResponse(). Unknown shape.");
  return out;
}

function explainScimType(scimType) {
  log.debug("Entering explainScimType().");
  var text = SCIM_TYPES[String(scimType)] || '';
  log.debug("Leaving explainScimType().");
  return text;
}

// ---------------------------------------------------------------------------
// THE SEEDED GENERATOR.
//
// mulberry32 over a hash of the caller's seed string. Small, well known, and —
// the only property that matters here — deterministic: the same seed produces
// the same fifty users, so a scenario that failed can be run again.
//
// It is NOT cryptography and must never be used for any, which is why it lives
// beside the generators it feeds rather than in `crypto_bytes.js` where
// somebody would eventually reach for it.
// ---------------------------------------------------------------------------
function hashSeed(text) {
  log.debug("Entering hashSeed().");
  var value = 2166136261;
  var input = String(text === undefined || text === null ? '' : text);
  for (var i = 0; i < input.length; i++) {
    value = value ^ input.charCodeAt(i);
    value = Math.imul(value, 16777619);
  }
  var out = value >>> 0;
  log.debug("Leaving hashSeed(). " + out);
  return out;
}

function newRng(seed) {
  log.debug("Entering newRng(). seed=" + seed);
  var state = hashSeed(seed);
  // The generator itself is a HOT PATH — a fifty-user scenario calls it several
  // hundred times — so it carries no Entering/Leaving pair of its own. Same
  // exception cbor.js's item decoder takes, and for the same reason.
  var rng = function () {
    state = state + 0x6D2B79F5 | 0;
    var t = Math.imul(state ^ state >>> 15, 1 | state);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
  log.debug("Leaving newRng().");
  return rng;
}

// Also hot: called once per generated field.
function pick(rng, list) {
  return list[Math.floor(rng() * list.length) % list.length];
}

function pickInt(rng, low, high) {
  return low + Math.floor(rng() * (high - low + 1));
}

// ---------------------------------------------------------------------------
// THE VOCABULARY the generator draws from: models/catalog/scim.tsp,
// SCIM_USER_VOCABULARY, which says why it is boring and ASCII. Each list is
// drawn from by index with the seeded generator, so its ORDER is data too.
// ---------------------------------------------------------------------------
var VOCABULARY = require("./catalog/scim_user_vocabulary.json");
var GIVEN_NAMES = VOCABULARY.givenNames;
var FAMILY_NAMES = VOCABULARY.familyNames;
var HONORIFIC_PREFIXES = VOCABULARY.honorificPrefixes;
var HONORIFIC_SUFFIXES = VOCABULARY.honorificSuffixes;
var TITLES = VOCABULARY.titles;
var USER_TYPES = VOCABULARY.userTypes;
var DEPARTMENTS = VOCABULARY.departments;
var DIVISIONS = VOCABULARY.divisions;
var ORGANIZATIONS = VOCABULARY.organizations;
var COST_CENTERS = VOCABULARY.costCenters;
var LOCALES = VOCABULARY.locales;
var LANGUAGES = VOCABULARY.languages;
var TIMEZONES = VOCABULARY.timezones;
var STREETS = VOCABULARY.streets;
var LOCALITIES = VOCABULARY.localities;
var REGIONS = VOCABULARY.regions;
var COUNTRIES = VOCABULARY.countries;
var IM_TYPES = VOCABULARY.imTypes;
var PHOTO_TYPES = VOCABULARY.photoTypes;
var GROUP_NOUNS = VOCABULARY.groupNouns;

// ---------------------------------------------------------------------------
// A GENERATED USER, WITH EVERY OPTIONAL FIELD RFC 7643 SECTION 4.1 DEFINES.
//
// The complete list, and the reason it is complete is in the header: a
// provisioning client tested only against `userName` and `emails` has tested
// nothing about the fields it will actually meet. What this project's mock STS
// STORES is narrower — `scim_map.js` there is the window — and the difference
// between "accepted and stored" and "accepted and dropped" is exactly what the
// page's round-trip comparison is for.
//
// `options.minimal` produces the other extreme: userName and nothing else,
// which is the smallest legal User and the one a create should never fail on.
//
// `options.types` — `canonicalTypesOf()`'s map — fits every `type` to what the
// server publishes, after generation, so the same seed names the same people
// with or without it. See fitTypes().
// ---------------------------------------------------------------------------
function randomUser(options) {
  log.debug("Entering randomUser().");
  var settings = options || {};
  var rng = settings.rng || newRng(settings.seed);
  var index = settings.index === undefined ? 0 : settings.index;
  var prefix = settings.prefix === undefined ? 'scim' : settings.prefix;
  var given = pick(rng, GIVEN_NAMES);
  var family = pick(rng, FAMILY_NAMES);
  var middle = pick(rng, GIVEN_NAMES);
  var tag = pickInt(rng, 100000, 999999);
  var userName = prefix + '.' + given.toLowerCase() + '.' +
      family.toLowerCase() + '.' + tag;
  var domain = settings.domain || 'example.com';
  if (settings.minimal) {
    log.debug("Leaving randomUser(). Minimal.");
    return { schemas: [USER_SCHEMA], userName: userName };
  }
  var user = {
    schemas: [USER_SCHEMA, ENTERPRISE_SCHEMA],
    userName: userName,
    externalId: 'ext-' + prefix + '-' + tag + '-' + index,
    name: {
      formatted: pick(rng, HONORIFIC_PREFIXES) + ' ' + given + ' ' +
          middle + ' ' + family,
      familyName: family,
      givenName: given,
      middleName: middle,
      honorificPrefix: pick(rng, HONORIFIC_PREFIXES),
      honorificSuffix: pick(rng, HONORIFIC_SUFFIXES)
    },
    displayName: given + ' ' + family,
    nickName: given.toLowerCase() + tag,
    profileUrl: 'https://' + domain + '/people/' + userName,
    title: pick(rng, TITLES),
    userType: pick(rng, USER_TYPES),
    preferredLanguage: pick(rng, LANGUAGES),
    locale: pick(rng, LOCALES),
    timezone: pick(rng, TIMEZONES),
    active: true,
    emails: [
      { value: userName + '@' + domain, type: 'work', primary: true,
        display: given + ' at work' },
      { value: given.toLowerCase() + tag + '@' + domain, type: 'home',
        primary: false, display: given + ' at home' }
    ],
    phoneNumbers: [
      { value: '+1-555-' + pickInt(rng, 1000, 9999), type: 'work',
        primary: true },
      { value: '+1-555-' + pickInt(rng, 1000, 9999), type: 'mobile',
        primary: false },
      { value: '+1-555-' + pickInt(rng, 1000, 9999), type: 'fax',
        primary: false }
    ],
    ims: [
      { value: userName + '@im.' + domain, type: pick(rng, IM_TYPES),
        primary: true }
    ],
    photos: [
      { value: 'https://' + domain + '/photos/' + userName + '.jpg',
        type: pick(rng, PHOTO_TYPES), primary: true }
    ],
    addresses: [
      { type: 'work', primary: true,
        streetAddress: pick(rng, STREETS),
        locality: pick(rng, LOCALITIES),
        region: pick(rng, REGIONS),
        postalCode: String(pickInt(rng, 10000, 99999)),
        country: pick(rng, COUNTRIES),
        formatted: '' },
      { type: 'home', primary: false,
        streetAddress: pick(rng, STREETS),
        locality: pick(rng, LOCALITIES),
        region: pick(rng, REGIONS),
        postalCode: String(pickInt(rng, 10000, 99999)),
        country: pick(rng, COUNTRIES),
        formatted: '' }
    ],
    entitlements: [
      { value: 'entitlement-' + pickInt(rng, 1, 99), type: 'license',
        primary: true }
    ],
    // ---------------------------------------------------------------------
    // THE TWO THAT CARRY `display` WHERE EVERY OTHER MULTI-VALUED ATTRIBUTE
    // CARRIES `type`, AND IT IS DELIBERATE.
    //
    // RFC 7643 section 8.7.1 declares `"canonicalValues": []` on the `type`
    // sub-attribute of `roles` and of `x509Certificates` and on no other one
    // — section 4.1.2 says of roles that "no vocabulary or syntax is
    // specified" — and a strict server reads that empty list as an exhaustive
    // one. scimmy, which this project's mock STS is built on and which a
    // fair number of real SCIM servers are built on too, then refuses ANY
    // value there: `400 invalidValue: Attribute 'type' contains non-canonical
    // value from complex attribute 'roles'`, before a single attribute is
    // stored. A generator whose full User cannot be created is a generator
    // nobody can use, and the refusal names a sub-attribute rather than the
    // schema rule behind it.
    //
    // `display` is defined on both, is constrained on neither, and is the
    // sub-attribute a reader wanted from that field in the first place. The
    // `type`-selecting PATCH paths the scenarios exercise are on `emails` and
    // `phoneNumbers`, which keep theirs. tests/scim_engine.js pins this so
    // that re-adding a `type` here fails in node with the reason rather than
    // as a 400 from whichever server is being debugged. See
    // docs/v0.9.5/scim.md.
    // ---------------------------------------------------------------------
    roles: [
      { value: pick(rng, ['reader', 'writer', 'approver']),
        display: 'Application role', primary: true }
    ],
    x509Certificates: [
      // A DER-shaped placeholder rather than a real certificate: this is a
      // provisioning test and the value is opaque to SCIM. The PKI workflow is
      // where a real one comes from, and pasting one here is a supported
      // manual edit rather than something a generator should mint.
      { value: 'MIIBkTCB+wIJAKZ' + String(tag) + 'PLACEHOLDER',
        display: 'Workstation certificate', primary: true }
    ]
  };
  // `formatted` is built from the parts rather than generated independently,
  // because an address whose formatted line disagrees with its own fields is
  // the one thing a reader cannot tell from a server bug.
  user.addresses.forEach(function (address) {
    address.formatted = address.streetAddress + '\n' + address.locality +
        ', ' + address.region + ' ' + address.postalCode + '\n' +
        address.country;
  });
  user[ENTERPRISE_SCHEMA] = {
    employeeNumber: 'E' + pickInt(rng, 10000, 99999),
    costCenter: pick(rng, COST_CENTERS),
    organization: pick(rng, ORGANIZATIONS),
    division: pick(rng, DIVISIONS),
    department: pick(rng, DEPARTMENTS)
    // `manager` is deliberately absent. It is a reference to another user's
    // id, and a generator inventing one produces a dangling reference on every
    // single user — which is a scenario worth running on purpose and a poor
    // default. The scenarios below set it once both parties exist.
  };
  if (settings.types) {
    fitTypes(user, settings.types);
  }
  if (settings.password) {
    // RFC 7643 4.1: `password` is writeOnly and never returned. It is not
    // generated by default because this project's mock checks no password and
    // storing one would be the only secret this workflow ever wrote.
    user.password = settings.password;
  }
  log.debug("Leaving randomUser(). userName=" + userName);
  return user;
}

// ---------------------------------------------------------------------------
// THE `type` VALUES A SERVER SAYS IT TAKES, AND A RESOURCE FITTED TO THEM.
//
// RFC 7643 section 7 puts `canonicalValues` on the attribute it constrains,
// and for a complex multi-valued attribute that is the `type` SUB-attribute —
// section 8.7.1 declares `emails.type` as work/home/other there and nothing
// on `emails` itself. A server may narrow that list, and a strict one refuses
// the whole create over one value outside it: this project's mock STS offers
// `emails.type` = work alone since iya-sts #206, because the LDAP attribute
// behind it has nowhere to put `home`, and answers anything else with
// `400 invalidValue: Attribute 'type' contains non-canonical value`.
//
// canonicalTypesOf() reads one Schemas resource into
// `{ emails: ['work'], ... }`, taking only attributes whose `type`
// sub-attribute publishes a NON-EMPTY list — an empty one is "none
// suggested" (section 8.7.1 has three), not "none allowed", and reading it as
// the latter is the scimmy defect the note on `roles` above describes.
//
// fitTypes() re-types each value outside its attribute's list to the first
// type in the list nobody else in that attribute already carries, or to the
// list's first when every one is taken. It RE-TYPES rather than drops, so a
// generated User keeps its second email — the one a value-filter PATCH
// removes — and every value it generated still reaches the server. It
// changes `resource` in place and answers one note per change.
// ---------------------------------------------------------------------------
function canonicalTypesOf(schema) {
  log.debug("Entering canonicalTypesOf().");
  var out = {};
  var attributes = (schema && schema.attributes) || [];
  attributes.forEach(function (attribute) {
    var subs = (attribute && attribute.subAttributes) || [];
    subs.forEach(function (sub) {
      if (sub && sub.name === 'type' && sub.canonicalValues &&
          sub.canonicalValues.length) {
        out[attribute.name] = sub.canonicalValues.map(String);
      }
    });
  });
  log.debug("Leaving canonicalTypesOf(). " + Object.keys(out).length +
      " attribute(s).");
  return out;
}

function fitTypes(resource, types) {
  log.debug("Entering fitTypes().");
  var notes = [];
  if (!resource || !types) {
    log.debug("Leaving fitTypes(). Nothing to fit.");
    return notes;
  }
  Object.keys(types).forEach(function (name) {
    var allowed = types[name] || [];
    var rows = resource[name];
    if (!allowed.length || !Array.isArray(rows)) {
      return;
    }
    rows.forEach(function (row) {
      if (!row || row.type === undefined ||
          allowed.indexOf(String(row.type)) >= 0) {
        return;
      }
      var taken = rows.map(function (other) {
        return other && String(other.type);
      });
      var free = allowed.filter(function (type) {
        return taken.indexOf(type) < 0;
      });
      var chosen = free.length ? free[0] : allowed[0];
      notes.push('changed a ' + name + ' type from "' + row.type + '" to "' +
          chosen + '" — the server\'s Schemas document offers only ' +
          allowed.join('/'));
      row.type = chosen;
    });
  });
  log.debug("Leaving fitTypes(). " + notes.length + " change(s).");
  return notes;
}

function randomGroup(options) {
  log.debug("Entering randomGroup().");
  var settings = options || {};
  var rng = settings.rng || newRng(settings.seed);
  var prefix = settings.prefix === undefined ? 'scim' : settings.prefix;
  var tag = pickInt(rng, 100000, 999999);
  var group = {
    schemas: [GROUP_SCHEMA],
    displayName: prefix + ' ' + pick(rng, GROUP_NOUNS) + ' ' + tag,
    externalId: 'ext-group-' + prefix + '-' + tag
  };
  if (settings.members && settings.members.length) {
    group.members = settings.members.map(function (member) {
      return typeof member === 'string'
        ? { value: member, type: 'User' }
        : member;
    });
  }
  log.debug("Leaving randomGroup(). displayName=" + group.displayName);
  return group;
}

// ---------------------------------------------------------------------------
// THE MESSAGE BODIES RFC 7644 DEFINES, built rather than typed.
//
// Each of these is a place a client is commonly wrong in a way its own tests
// do not catch, because the server accepts the request and does something
// other than what was meant.
// ---------------------------------------------------------------------------
function searchRequest(options) {
  log.debug("Entering searchRequest().");
  var settings = options || {};
  var body = { schemas: [SEARCH_REQUEST_SCHEMA] };
  if (settings.filter) {
    body.filter = String(settings.filter);
  }
  if (settings.sortBy) {
    body.sortBy = String(settings.sortBy);
  }
  if (settings.sortOrder) {
    body.sortOrder = String(settings.sortOrder);
  }
  if (settings.startIndex !== undefined && settings.startIndex !== '') {
    body.startIndex = Number(settings.startIndex);
  }
  if (settings.count !== undefined && settings.count !== '') {
    body.count = Number(settings.count);
  }
  // ARRAYS here, and a comma-separated string in a query string. That
  // asymmetry is in RFC 7644 itself (section 3.4.2.5 against section 3.4.3)
  // and is the single most common reason a /.search returns every attribute
  // when the caller asked for two.
  if (settings.attributes) {
    body.attributes = splitList(settings.attributes);
  }
  if (settings.excludedAttributes) {
    body.excludedAttributes = splitList(settings.excludedAttributes);
  }
  log.debug("Leaving searchRequest().");
  return body;
}

function splitList(value) {
  log.debug("Entering splitList().");
  if (Array.isArray(value)) {
    log.debug("Leaving splitList(). Already an array.");
    return value.slice(0);
  }
  var parts = String(value || '').split(',').map(function (part) {
    return part.trim();
  }).filter(function (part) {
    return part !== '';
  });
  log.debug("Leaving splitList(). " + parts.length + " item(s).");
  return parts;
}

// RFC 7644 section 3.5.2. `op` is lower case in the specification's own
// examples and several servers compare it case-sensitively; `path` is OPTIONAL
// on add and replace, where its absence means "the value is a partial resource
// to merge", which is the form most clients never send and most servers
// support.
function patchOp(operations) {
  log.debug("Entering patchOp().");
  var body = {
    schemas: [PATCH_OP_SCHEMA],
    Operations: (operations || []).map(function (row) {
      var out = { op: String(row.op || 'replace').toLowerCase() };
      if (row.path !== undefined && row.path !== '') {
        out.path = String(row.path);
      }
      if (row.value !== undefined) {
        out.value = row.value;
      }
      return out;
    })
  };
  log.debug("Leaving patchOp(). " + body.Operations.length + " operation(s).");
  return body;
}

// RFC 7644 section 3.7. `bulkId` is required on every POST inside a bulk and
// is what a later operation references as `bulkId:name` — which is the feature
// that makes a bulk more than a loop, and the one this generator uses when it
// creates a group whose members are users created in the same request.
function bulkRequest(operations, options) {
  log.debug("Entering bulkRequest().");
  var settings = options || {};
  var body = {
    schemas: [BULK_REQUEST_SCHEMA],
    Operations: (operations || []).map(function (row) {
      var out = { method: String(row.method || 'POST').toUpperCase() };
      if (row.bulkId) {
        out.bulkId = String(row.bulkId);
      }
      if (row.path) {
        out.path = String(row.path);
      }
      if (row.data !== undefined) {
        out.data = row.data;
      }
      if (row.version) {
        out.version = String(row.version);
      }
      return out;
    })
  };
  if (settings.failOnErrors !== undefined && settings.failOnErrors !== '') {
    body.failOnErrors = Number(settings.failOnErrors);
  }
  log.debug("Leaving bulkRequest(). " + body.Operations.length +
      " operation(s).");
  return body;
}

module.exports = {
  USER_SCHEMA: USER_SCHEMA,
  GROUP_SCHEMA: GROUP_SCHEMA,
  ENTERPRISE_SCHEMA: ENTERPRISE_SCHEMA,
  SERVICE_PROVIDER_CONFIG_SCHEMA: SERVICE_PROVIDER_CONFIG_SCHEMA,
  RESOURCE_TYPE_SCHEMA: RESOURCE_TYPE_SCHEMA,
  SCHEMA_SCHEMA: SCHEMA_SCHEMA,
  LIST_RESPONSE_SCHEMA: LIST_RESPONSE_SCHEMA,
  SEARCH_REQUEST_SCHEMA: SEARCH_REQUEST_SCHEMA,
  PATCH_OP_SCHEMA: PATCH_OP_SCHEMA,
  BULK_REQUEST_SCHEMA: BULK_REQUEST_SCHEMA,
  BULK_RESPONSE_SCHEMA: BULK_RESPONSE_SCHEMA,
  ERROR_SCHEMA: ERROR_SCHEMA,
  SCIM_CONTENT_TYPE: SCIM_CONTENT_TYPE,
  DEFAULT_BASE_PATH: DEFAULT_BASE_PATH,
  HOBA_ALG_RSA_SHA256: HOBA_ALG_RSA_SHA256,
  HOBA_REGISTRATION_PATH: HOBA_REGISTRATION_PATH,
  utf8Length: utf8Length,
  SCIM_TYPES: SCIM_TYPES,
  AUTH_SCHEMES: AUTH_SCHEMES,
  OPERATIONS: OPERATIONS,
  operation: operation,
  operationsInGroup: operationsInGroup,
  authScheme: authScheme,
  normalizeBaseUrl: normalizeBaseUrl,
  DEFAULT_ENDPOINTS: DEFAULT_ENDPOINTS,
  normalizeEndpoint: normalizeEndpoint,
  resourcePath: resourcePath,
  idPathSegment: idPathSegment,
  queryString: queryString,
  buildRequest: buildRequest,
  basicHeader: basicHeader,
  DIGEST_ALGORITHMS: DIGEST_ALGORITHMS,
  digestAlgorithm: digestAlgorithm,
  chooseDigestChallenge: chooseDigestChallenge,
  digestCredential: digestCredential,
  verifyAuthenticationInfo: verifyAuthenticationInfo,
  digestHeader: digestHeader,
  sha256Hex: sha256Hex,
  sha512_256Hex: sha512_256Hex,
  md5Hex: md5Hex,
  parseChallenges: parseChallenges,
  challengesFor: challengesFor,
  hobaToBeSigned: hobaToBeSigned,
  originOf: originOf,
  applyAuth: applyAuth,
  isScimError: isScimError,
  describeResponse: describeResponse,
  explainScimType: explainScimType,
  hashSeed: hashSeed,
  newRng: newRng,
  VOCABULARY: VOCABULARY,
  randomUser: randomUser,
  canonicalTypesOf: canonicalTypesOf,
  fitTypes: fitTypes,
  randomGroup: randomGroup,
  searchRequest: searchRequest,
  splitList: splitList,
  patchOp: patchOp,
  bulkRequest: bulkRequest
};
