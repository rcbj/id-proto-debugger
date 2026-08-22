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
// THE ERROR CODES RFC 7644 SECTION 3.12 DEFINES, with what each one actually
// means to somebody reading it off this page.
//
// `scimType` is a CLOSED list — a server may not invent one — and it is the
// single most useful thing in a SCIM error, because the HTTP status alone
// cannot tell `uniqueness` (this userName is taken) from `invalidValue` (this
// userName is not allowed). Both are 400 on many servers.
// ---------------------------------------------------------------------------
var SCIM_TYPES = {
  invalidFilter: 'The filter is not valid section 3.4.2.2 grammar, or asks ' +
      'for something this server cannot evaluate.',
  tooMany: 'The filter matched more than the server is willing to return. ' +
      'Narrow it or page it.',
  uniqueness: 'A value that has to be unique is already somebody else\'s — ' +
      'on a User that is almost always userName.',
  mutability: 'A read-only attribute was written, or an immutable one was ' +
      'changed after it was set.',
  invalidSyntax: 'The body is not the structure this operation expects — a ' +
      'missing or wrong "schemas" member is the usual cause.',
  invalidPath: 'The PATCH "path" is not valid section 3.5.2 path grammar.',
  noTarget: 'The PATCH path is valid grammar but names nothing on this ' +
      'resource, and the operation needs a target that exists.',
  invalidValue: 'A value is the wrong type, is missing when required, or is ' +
      'not one this attribute accepts.',
  invalidVers: 'The version in the request is not one this server speaks.',
  sensitive: 'The request put something sensitive in the URL. Send it in a ' +
      'POST body instead — that is what /.search is for.'
};

// ---------------------------------------------------------------------------
// THE AUTHENTICATION SCHEMES, which are RFC 7644 SECTION 2's SIX AND NOT AN
// INVENTED SET.
//
// That section names TLS client authentication, HOBA, bearer tokens,
// proof-of-possession tokens, cookies and HTTP Basic (which it discourages, in
// those words), and states the only two normative things about any of them: a
// server SHALL advertise what it supports in `WWW-Authenticate`, and it MUST be
// able to map an authenticated client to an access control policy.
//
// **DO NOT ADD AN API KEY ROW.** A shared secret in a custom header is what
// most provisioning integrations actually use in the field, it is in no
// specification, and a client built against it here would interoperate with
// nothing. The mock STS's `scim_auth.js` refuses to grow one for the same
// reason, and these two tables are meant to name the same six things.
//
// `needsProof` marks the two that cannot be composed from configuration alone:
// DPoP needs a signed proof JWT over this exact method and URL, and HOBA needs
// a signature over an origin-bound string. Both are Web Crypto operations, so
// this module produces the STRING TO BE SIGNED and the header FORMAT and the
// page produces the signature — which keeps the cryptography where the key is
// and keeps this file loadable in node.
//
// `sendsCredential` is false for the two that put nothing in an Authorization
// header: a cookie rides on the request because the browser attaches it, and a
// client certificate is chosen during the TLS handshake. Both are therefore
// unavailable to the api path and only one of them is available to the browser
// path, which the page says rather than leaving to be discovered.
// ---------------------------------------------------------------------------
var AUTH_SCHEMES = [
  { id: 'none', label: 'None (anonymous)', type: '',
    spec: 'RFC 7644 section 2',
    sendsCredential: false, needsProof: false, scoped: false,
    browser: true, backend: true,
    what: 'Send nothing. Against a server with authentication turned on this ' +
        'is the 401 that shows you what the WWW-Authenticate challenge says ' +
        'you may use — which is the SHALL in section 2 and the fastest way ' +
        'to find out what a server will accept.' },
  { id: 'bearer', label: 'OAuth 2.0 Bearer token', type: 'oauthbearertoken',
    spec: 'RFC 6750',
    sendsCredential: true, needsProof: false, scoped: true,
    browser: true, backend: true,
    what: 'Authorization: Bearer <token>. The scope is what decides what you ' +
        'may do: the read scope to read and the write scope to write. Get ' +
        'one from the OAuth2 / OIDC workflow with any grant, or paste one.' },
  { id: 'dpop', label: 'OAuth 2.0 DPoP (proof of possession)', type: 'oauth2',
    spec: 'RFC 9449',
    sendsCredential: true, needsProof: true, scoped: true,
    browser: true, backend: true,
    what: 'Authorization: DPoP <token> plus a DPoP proof JWT signed over ' +
        'THIS method and URL and carrying the access token\'s hash. The ' +
        'proof is minted per request, so a captured one is not replayable ' +
        'against another endpoint.' },
  { id: 'basic', label: 'HTTP Basic', type: 'httpbasic',
    spec: 'RFC 7617',
    sendsCredential: true, needsProof: false, scoped: false,
    browser: true, backend: true,
    what: 'Authorization: Basic base64(user:password). Section 2 names it ' +
        'and discourages it in the same sentence. It carries no scope, so a ' +
        'server that accepts it usually lets the caller do everything.' },
  { id: 'digest', label: 'HTTP Digest', type: 'httpdigest',
    spec: 'RFC 7616',
    sendsCredential: true, needsProof: true, scoped: false,
    browser: true, backend: true,
    what: 'Two requests, not one: the first is answered 401 with a nonce, ' +
        'and the second carries a digest computed over it. This page makes ' +
        'both and shows you both, because the handshake is the interesting ' +
        'part and a library normally hides it.' },
  { id: 'hoba', label: 'HOBA (HTTP Origin-Bound Authentication)', type: 'hoba',
    spec: 'RFC 7486',
    sendsCredential: true, needsProof: true, scoped: false,
    browser: true, backend: false,
    what: 'A signature by a key you registered, over a string bound to this ' +
        'origin and this realm. No password crosses the wire at all. The ' +
        'signing key lives in this browser, which is why the api cannot ' +
        'make this call for you.' },
  { id: 'cookie', label: 'Session cookie', type: 'httpcookie',
    spec: 'RFC 7644 section 2 ("Cookies")',
    sendsCredential: false, needsProof: false, scoped: false,
    browser: true, backend: false,
    what: 'Nothing is added to the request: the browser attaches the cookie ' +
        'if it has one for that origin and the request is made with ' +
        'credentials. Sign in to the server first. The api has no session ' +
        'and no cookie jar, so this is a browser-only scheme.' },
  { id: 'clientcert', label: 'TLS client certificate', type: 'tlsclientauth',
    spec: 'RFC 8446 / RFC 5280',
    sendsCredential: false, needsProof: false, scoped: false,
    browser: true, backend: false,
    what: 'Chosen during the TLS handshake and never in a header, so no ' +
        'code here can put it there — the browser offers what its keychain ' +
        'holds when the server asks. Nothing is added to the request; this ' +
        'row exists so the page can say that rather than appear to have ' +
        'left the scheme out.' }
];

// ---------------------------------------------------------------------------
// THE ENDPOINTS. RFC 7644 sections 3.2 through 3.12.
//
// `need` is the scope the mock STS's access control policy asks for and is NOT
// a claim about somebody else's server — it is what this page predicts, so that
// a 403 can be shown beside the prediction that expected it. `discovery` needs
// nothing anywhere: a client has to be able to read a ServiceProviderConfig
// before it knows how to authenticate, which is the one bootstrapping problem
// section 2 leaves to the reader.
//
// `query` lists the section 3.4.2 parameters each operation accepts. It is not
// decorative: the page builds its query-string editor from it, so an operation
// that does not accept `sortBy` does not offer one.
// ---------------------------------------------------------------------------
var QUERY_ALL = ['filter', 'sortBy', 'sortOrder', 'startIndex', 'count',
                 'attributes', 'excludedAttributes'];
var QUERY_ONE = ['attributes', 'excludedAttributes'];

var OPERATIONS = [
  { id: 'serviceProviderConfig', label: 'ServiceProviderConfig',
    group: 'discovery', method: 'GET', path: '/ServiceProviderConfig',
    need: 'none', body: null, query: [],
    section: 'RFC 7644 section 4',
    what: 'What this server supports: filtering, sorting, PATCH, bulk, ETag, ' +
        'changePassword, and the authentication schemes it advertises. Read ' +
        'it first — everything else on this page is a promise it made.' },
  { id: 'resourceTypes', label: 'ResourceTypes', group: 'discovery',
    method: 'GET', path: '/ResourceTypes', need: 'none', body: null,
    query: [],
    section: 'RFC 7644 section 4',
    what: 'The resource types this server has, and for each one its endpoint ' +
        'and the schema extensions it carries.' },
  { id: 'resourceType', label: 'One ResourceType', group: 'discovery',
    method: 'GET', path: '/ResourceTypes/{id}', need: 'none', body: null,
    query: [], idLabel: 'Type name', idExample: 'User',
    section: 'RFC 7644 section 4',
    what: 'One of them, by name — "User" or "Group". Note the id here is a ' +
        'NAME and not a resource id; that asymmetry is in the specification.' },
  { id: 'schemas', label: 'Schemas', group: 'discovery', method: 'GET',
    path: '/Schemas', need: 'none', body: null, query: [],
    section: 'RFC 7643 section 7',
    what: 'Every attribute this server knows, with its characteristics: ' +
        'required, canonical values, mutability, returned, uniqueness. This ' +
        'is the document that says whether a field you sent was ever going ' +
        'to be stored.' },
  { id: 'schema', label: 'One Schema', group: 'discovery', method: 'GET',
    path: '/Schemas/{id}', need: 'none', body: null, query: [],
    idLabel: 'Schema URN', idExample: USER_SCHEMA,
    section: 'RFC 7643 section 7',
    what: 'One schema by its URN.' },

  { id: 'listUsers', label: 'List users', group: 'user', resourceType: 'User',
    method: 'GET', path: '/Users', need: 'read', body: null, query: QUERY_ALL,
    section: 'RFC 7644 section 3.4.2',
    what: 'The list, filtered, sorted, paged and projected by the query ' +
        'string. An empty filter means everybody, which is what count and ' +
        'startIndex are for.' },
  { id: 'createUser', label: 'Create user', group: 'user',
    resourceType: 'User', method: 'POST', path: '/Users', need: 'write',
    body: 'User', query: QUERY_ONE,
    section: 'RFC 7644 section 3.3',
    what: '201 with the created resource and a Location header. userName is ' +
        'the one required attribute and the one with a uniqueness ' +
        'constraint, so this is where a 409 comes from.' },
  { id: 'searchUsers', label: 'Search users (POST /.search)', group: 'user',
    resourceType: 'User', method: 'POST', path: '/Users/.search',
    need: 'read', body: 'SearchRequest', query: [],
    section: 'RFC 7644 section 3.4.3',
    what: 'The same query as a POST body. It exists for a filter too long ' +
        'for a URL and for one carrying something that should not be in a ' +
        'server\'s access log.' },
  { id: 'readUser', label: 'Read user', group: 'user', resourceType: 'User',
    method: 'GET', path: '/Users/{id}', need: 'read', body: null,
    query: QUERY_ONE,
    section: 'RFC 7644 section 3.4.1',
    what: 'One user by id. The id is opaque — do not build it, use the one ' +
        'the create or the list gave you.' },
  { id: 'replaceUser', label: 'Replace user (PUT)', group: 'user',
    resourceType: 'User', method: 'PUT', path: '/Users/{id}', need: 'write',
    body: 'User', query: QUERY_ONE,
    section: 'RFC 7644 section 3.5.1',
    what: 'Replaces the resource with what you send. Every attribute you ' +
        'leave out is one you are asking to have removed — which is the ' +
        'difference between this and PATCH and the mistake this operation ' +
        'exists to let you make on purpose.' },
  { id: 'modifyUser', label: 'Modify user (PATCH)', group: 'user',
    resourceType: 'User', method: 'PATCH', path: '/Users/{id}',
    need: 'write', body: 'PatchOp', query: QUERY_ONE,
    section: 'RFC 7644 section 3.5.2',
    what: 'add, replace and remove against a path — and the path grammar is ' +
        'the part everybody gets wrong: emails[type eq "work"].value is a ' +
        'path, not a property name. A PATCH that changes nothing answers ' +
        '204 with no body.' },
  { id: 'deleteUser', label: 'Delete user', group: 'user',
    resourceType: 'User', method: 'DELETE', path: '/Users/{id}',
    need: 'write', body: null, query: [],
    section: 'RFC 7644 section 3.6',
    what: '204 and no body. There is no soft delete in SCIM — active:false ' +
        'is a different thing and does not do this.' },

  { id: 'listGroups', label: 'List groups', group: 'group',
    resourceType: 'Group', method: 'GET', path: '/Groups', need: 'read',
    body: null, query: QUERY_ALL,
    section: 'RFC 7644 section 3.4.2',
    what: 'The list. A group\'s members come back as ids with a $ref.' },
  { id: 'createGroup', label: 'Create group', group: 'group',
    resourceType: 'Group', method: 'POST', path: '/Groups', need: 'write',
    body: 'Group', query: QUERY_ONE,
    section: 'RFC 7644 section 3.3',
    what: 'displayName is the required attribute. Members may be sent at ' +
        'creation or added afterwards with a PATCH.' },
  { id: 'searchGroups', label: 'Search groups (POST /.search)',
    group: 'group', resourceType: 'Group', method: 'POST',
    path: '/Groups/.search', need: 'read', body: 'SearchRequest', query: [],
    section: 'RFC 7644 section 3.4.3',
    what: 'The same query as a POST body.' },
  { id: 'readGroup', label: 'Read group', group: 'group',
    resourceType: 'Group', method: 'GET', path: '/Groups/{id}', need: 'read',
    body: null, query: QUERY_ONE,
    section: 'RFC 7644 section 3.4.1',
    what: 'One group by id, with its members resolved.' },
  { id: 'replaceGroup', label: 'Replace group (PUT)', group: 'group',
    resourceType: 'Group', method: 'PUT', path: '/Groups/{id}',
    need: 'write', body: 'Group', query: QUERY_ONE,
    section: 'RFC 7644 section 3.5.1',
    what: 'Replaces it, membership included. Sending a group with no ' +
        'members empties it.' },
  { id: 'modifyGroup', label: 'Modify group (PATCH)', group: 'group',
    resourceType: 'Group', method: 'PATCH', path: '/Groups/{id}',
    need: 'write', body: 'PatchOp', query: QUERY_ONE,
    section: 'RFC 7644 section 3.5.2',
    what: 'How membership is normally changed: add or remove against the ' +
        '"members" path. Membership is a fact about the GROUP, so it is ' +
        'never changed through a User resource.' },
  { id: 'deleteGroup', label: 'Delete group', group: 'group',
    resourceType: 'Group', method: 'DELETE', path: '/Groups/{id}',
    need: 'write', body: null, query: [],
    section: 'RFC 7644 section 3.6',
    what: '204. Deleting a group deletes the membership, not the members.' },

  { id: 'searchAll', label: 'Search everything (POST /.search)',
    group: 'query', method: 'POST', path: '/.search', need: 'read',
    body: 'SearchRequest', query: [],
    section: 'RFC 7644 section 3.4.3',
    what: 'One query across BOTH resource types at once, which is the one ' +
        'thing the per-type /.search cannot do. The ListResponse comes back ' +
        'mixed, so read each entry\'s schemas to tell a User from a Group.' },
  { id: 'bulk', label: 'Bulk', group: 'query', method: 'POST', path: '/Bulk',
    need: 'write', body: 'BulkRequest', query: [],
    section: 'RFC 7644 section 3.7',
    what: 'Many operations in one request, each with a bulkId the later ones ' +
        'can reference as bulkId:name. There is no read operation inside a ' +
        'bulk, so it is a write however harmless the contents look.' },
  { id: 'me', label: '/Me', group: 'query', method: 'GET', path: '/Me',
    need: 'read', body: null, query: QUERY_ONE,
    section: 'RFC 7644 section 3.11',
    what: 'An alias for whoever the request authenticated as. A server with ' +
        'no authenticated subject has nothing to alias, and this project\'s ' +
        'mock answers 501 saying so — which is a more useful answer than a ' +
        '404 or a guess.' }
];

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
  var path = row.path;
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
    out.headers.Authorization = 'Bearer ' + String(auth.token || '');
    out.note = 'Authorization: Bearer, ' +
        String(auth.token || '').length + ' characters.';
    log.debug("Leaving applyAuth(). Bearer.");
    return out;
  }
  if (scheme.id === 'dpop') {
    out.headers.Authorization = 'DPoP ' + String(auth.token || '');
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
// THE VOCABULARY the generator draws from.
//
// Deliberately BORING and deliberately ASCII. A generator that produced
// realistic-looking names would put somebody's actual name in somebody's test
// directory, and one that produced interesting Unicode would make every
// failure a question about encoding rather than about SCIM. The characters RFC
// 4514 reserves — the ones that cannot go in a DN unescaped — have their own
// negative case in the scenarios instead, where the point is to be refused.
// ---------------------------------------------------------------------------
var GIVEN_NAMES = ['Ada', 'Bram', 'Cleo', 'Dara', 'Emil', 'Fen', 'Gale',
                   'Hana', 'Ivo', 'Juno', 'Kit', 'Lior', 'Mira', 'Nils',
                   'Oona', 'Piet', 'Quin', 'Rune', 'Sena', 'Taro', 'Ulla',
                   'Vera', 'Wim', 'Xan', 'Yuki', 'Zev'];
var FAMILY_NAMES = ['Aalto', 'Bergman', 'Coelho', 'Dahl', 'Esposito',
                    'Fournier', 'Garza', 'Haas', 'Ibarra', 'Jansen',
                    'Kovac', 'Lindqvist', 'Moreau', 'Novak', 'Oyelaran',
                    'Pereira', 'Quesada', 'Rasmussen', 'Silva', 'Tanaka',
                    'Ustinov', 'Vogel', 'Weber', 'Xiong', 'Yilmaz', 'Zima'];
var HONORIFIC_PREFIXES = ['Dr.', 'Prof.', 'Ms.', 'Mr.', 'Mx.'];
var HONORIFIC_SUFFIXES = ['PhD', 'Jr.', 'III', 'MSc'];
var TITLES = ['Systems Engineer', 'Directory Architect', 'Support Analyst',
              'Security Lead', 'Product Manager', 'Data Steward',
              'Field Technician', 'Compliance Officer'];
var USER_TYPES = ['Employee', 'Contractor', 'Intern', 'Vendor', 'Partner'];
var DEPARTMENTS = ['Engineering', 'Operations', 'Finance', 'Legal',
                   'Research', 'Support'];
var DIVISIONS = ['Platform', 'Directory', 'Identity', 'Infrastructure'];
var ORGANIZATIONS = ['Example Corp', 'Example Holdings', 'Example Labs'];
var COST_CENTERS = ['CC-1000', 'CC-2000', 'CC-3000', 'CC-4000'];
var LOCALES = ['en-US', 'en-GB', 'de-DE', 'fr-FR', 'ja-JP', 'pt-BR'];
var LANGUAGES = ['en', 'en-US', 'de', 'fr', 'ja', 'pt-BR'];
var TIMEZONES = ['America/Los_Angeles', 'America/New_York', 'Europe/London',
                 'Europe/Berlin', 'Asia/Tokyo', 'Australia/Sydney'];
var STREETS = ['1 Directory Way', '42 Schema Street', '7 Bind Lane',
               '100 Filter Road', '15 Attribute Close'];
var LOCALITIES = ['Springfield', 'Riverton', 'Fairview', 'Ashford',
                  'Kingsmere'];
var REGIONS = ['CA', 'NY', 'TX', 'WA', 'IL'];
var COUNTRIES = ['US', 'GB', 'DE', 'FR', 'JP', 'BR'];
var IM_TYPES = ['aim', 'gtalk', 'icq', 'xmpp', 'msn', 'skype', 'qq', 'yahoo'];
var PHOTO_TYPES = ['photo', 'thumbnail'];
var GROUP_NOUNS = ['Engineering', 'Operations', 'Directory Admins',
                   'Auditors', 'Support', 'Contractors', 'Reviewers',
                   'Release Managers'];

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
    roles: [
      { value: pick(rng, ['reader', 'writer', 'approver']), type: 'app',
        primary: true }
    ],
    x509Certificates: [
      // A DER-shaped placeholder rather than a real certificate: this is a
      // provisioning test and the value is opaque to SCIM. The PKI workflow is
      // where a real one comes from, and pasting one here is a supported
      // manual edit rather than something a generator should mint.
      { value: 'MIIBkTCB+wIJAKZ' + String(tag) + 'PLACEHOLDER',
        type: 'work', primary: true }
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
  if (settings.password) {
    // RFC 7643 4.1: `password` is writeOnly and never returned. It is not
    // generated by default because this project's mock checks no password and
    // storing one would be the only secret this workflow ever wrote.
    user.password = settings.password;
  }
  log.debug("Leaving randomUser(). userName=" + userName);
  return user;
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
  randomUser: randomUser,
  randomGroup: randomGroup,
  searchRequest: searchRequest,
  splitList: splitList,
  patchOp: patchOp,
  bulkRequest: bulkRequest
};
