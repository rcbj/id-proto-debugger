// File: scim_engine.js
//
// ---------------------------------------------------------------------------
// THE SCIM WORKFLOW'S ENGINES, DRIVEN IN NODE WITH NO SERVER AND NO BROWSER.
//
// `client/src/scim_client.js` composes every request this workflow can send and
// reads every answer; `client/src/scim_scenarios.js` plans the multi-step runs
// and judges them; `api/scim_proxy.js` decides what the backend call path will
// and will not forward. None of the three has a DOM and none of them opens a
// socket, which is what this file exists to take advantage of.
//
// **WHY THIS IS SEPARATE FROM `scim_protocol.js` AND `scim_page.js`.** Those
// two
// need a mock STS and a browser respectively, so a failure in either can be
// three things: this client is wrong, that server is wrong, or the two are fine
// and something in between is not. Here there is nothing in between. A failure
// in this file is a defect in the request this workflow composes — asserted
// against the RFCs' own text and against fixed vectors — and it names the field
// rather than naming a page.
//
// That distinction has already earned its keep on this project twice: the SCIM
// `id` is an LDAP DN, so a double-encoded path segment produces a 404 that
// reads exactly like a missing user, and a Digest credential with a wrong hash
// produces a 401 that reads exactly like a wrong password. Both are invisible
// to a test that only reads statuses off a live server.
//
// SEVEN SECTIONS:
//
//   1. the endpoint catalogue — that it covers RFC 7644 and composes correctly
//   2. the generator — that EVERY optional RFC 7643 attribute is emitted, and
//      that a seed is reproducible
//   3. the message bodies — SearchRequest, PatchOp, BulkRequest
//   4. authentication — Basic, the challenge parser, HOBA's length-prefixed
//      blob, and Digest's three algorithms against vectors computed with node's
//      own crypto, which is what the mock STS uses
//   5. reading an answer — the five RFC 7644 shapes and the conformance notes
//   6. scenarios — planning, reference resolution, and that `judge()` calls a
//      refusal a PASS where the plan expected one
//   7. the api proxy's refusals
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "scim_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The modules under test. requireSharedModule() is what makes a module borrowed
// from client/src resolve its own dependencies — node resolves those relative
// to where the MODULE lives, and a checkout that installed only the tests'
// dependencies has no client/node_modules. See tests/module_paths.js.
// In a checkout these live under client/src; the tests image copies them flat
// next to the test scripts (see tests/Dockerfile).
const scim = paths.requireSharedModule(
  [__dirname + "/../client/src/scim_client.js", __dirname + "/scim_client.js"],
  "scim_client.js");
const scenarios = paths.requireSharedModule(
  [__dirname + "/../client/src/scim_scenarios.js",
   __dirname + "/scim_scenarios.js"], "scim_scenarios.js");
const scimProxy = paths.requireSharedModule(
  [__dirname + "/../api/scim_proxy.js", __dirname + "/scim_proxy.js"],
  "scim_proxy.js");

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// 1. THE ENDPOINT CATALOGUE.
// ---------------------------------------------------------------------------

// Every endpoint RFC 7644 defines, spelled out here INDEPENDENTLY of the
// catalogue under test. That independence is the whole value of this check: a
// list derived from `scim.OPERATIONS` would agree with it by construction and
// could not notice an endpoint nobody implemented.
const RFC_7644_ENDPOINTS = [
  { method: 'GET', path: '/ServiceProviderConfig', section: '4' },
  { method: 'GET', path: '/ResourceTypes', section: '4' },
  { method: 'GET', path: '/ResourceTypes/{id}', section: '4' },
  { method: 'GET', path: '/Schemas', section: '4' },
  { method: 'GET', path: '/Schemas/{id}', section: '4' },
  { method: 'GET', path: '/Users', section: '3.4.2' },
  { method: 'POST', path: '/Users', section: '3.3' },
  { method: 'POST', path: '/Users/.search', section: '3.4.3' },
  { method: 'GET', path: '/Users/{id}', section: '3.4.1' },
  { method: 'PUT', path: '/Users/{id}', section: '3.5.1' },
  { method: 'PATCH', path: '/Users/{id}', section: '3.5.2' },
  { method: 'DELETE', path: '/Users/{id}', section: '3.6' },
  { method: 'GET', path: '/Groups', section: '3.4.2' },
  { method: 'POST', path: '/Groups', section: '3.3' },
  { method: 'POST', path: '/Groups/.search', section: '3.4.3' },
  { method: 'GET', path: '/Groups/{id}', section: '3.4.1' },
  { method: 'PUT', path: '/Groups/{id}', section: '3.5.1' },
  { method: 'PATCH', path: '/Groups/{id}', section: '3.5.2' },
  { method: 'DELETE', path: '/Groups/{id}', section: '3.6' },
  { method: 'POST', path: '/.search', section: '3.4.3' },
  { method: 'POST', path: '/Bulk', section: '3.7' },
  { method: 'GET', path: '/Me', section: '3.11' }
];

function theCatalogueCoversRfc7644() {
  log.debug("Entering theCatalogueCoversRfc7644().");
  log.info("1. The endpoint catalogue.");
  const have = {};
  scim.OPERATIONS.forEach(function (row) {
    have[row.method + ' ' + row.path] = row;
  });
  RFC_7644_ENDPOINTS.forEach(function (wanted) {
    check('RFC 7644 section ' + wanted.section + ': ' + wanted.method + ' ' +
        wanted.path + ' is in the catalogue', function () {
      assert.ok(have[wanted.method + ' ' + wanted.path],
          wanted.method + ' ' + wanted.path + ' is defined by RFC 7644 ' +
          'section ' + wanted.section + ' and no operation in ' +
          'scim_client.js composes it. The page can only offer what this ' +
          'table holds, so an endpoint missing here is an endpoint the ' +
          'workflow cannot reach at all.');
    });
  });
  check('the catalogue has nothing BEYOND RFC 7644', function () {
    const wanted = {};
    RFC_7644_ENDPOINTS.forEach(function (row) {
      wanted[row.method + ' ' + row.path] = true;
    });
    const extra = Object.keys(have).filter(function (key) {
      return !wanted[key];
    });
    assert.deepStrictEqual(extra, [],
        'These operations are in the catalogue and are not endpoints RFC ' +
        '7644 defines: ' + extra.join(', ') + '. An invented endpoint is one ' +
        'a client would be built against and that would interoperate with ' +
        'nothing.');
  });
  check('every operation names the scope it needs', function () {
    scim.OPERATIONS.forEach(function (row) {
      assert.ok(['none', 'read', 'write'].indexOf(row.need) >= 0,
          row.id + ' has need="' + row.need + '", which is not one of none, ' +
          'read, write.');
    });
  });
  check('discovery needs no scope and every write needs the write scope',
      function () {
    scim.operationsInGroup('discovery').forEach(function (row) {
      assert.strictEqual(row.need, 'none',
          row.id + ' is a discovery endpoint and must need no scope: a ' +
          'client has to be able to read a ServiceProviderConfig BEFORE it ' +
          'knows how to authenticate.');
    });
    scim.OPERATIONS.forEach(function (row) {
      const writes =
          ['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(row.method) >= 0;
      const isSearch = row.path.indexOf('.search') >= 0;
      if (writes && !isSearch) {
        assert.strictEqual(row.need, 'write',
            row.id + ' is a ' + row.method + ' and does not need the write ' +
            'scope.');
      }
    });
  });
  check('a bulk needs the WRITE scope even though it is a POST of a list',
      function () {
    assert.strictEqual(scim.operation('bulk').need, 'write',
        'RFC 7644 section 3.7 defines no read operation inside a bulk, so a ' +
        'bulk is a write whatever is in it. A server deciding per-operation ' +
        'would let a bulk of nothing but deletes through on a read ' +
        'credential because the envelope looked harmless.');
  });
  log.debug("Leaving theCatalogueCoversRfc7644().");
}

function theIdIsEncodedExactlyOnce() {
  log.debug("Entering theIdIsEncodedExactlyOnce().");
  log.info("1b. Composing a request.");
  // The id this project's mock STS actually issues: an LDAP DN, with the two
  // characters that MUST be encoded in a path segment and one that must not be
  // touched twice.
  const dn = 'uid=alice,ou=users,dc=example,dc=com';
  check('an id becomes exactly one percent-encoded path segment', function () {
    const request = scim.buildRequest({
      operation: 'readUser', baseUrl: 'https://host/scim/v2', id: dn });
    assert.strictEqual(request.url,
        'https://host/scim/v2/Users/uid%3Dalice%2Cou%3Dusers%2Cdc%3Dexample' +
        '%2Cdc%3Dcom');
    assert.ok(request.url.indexOf('%25') < 0,
        'The URL contains %25, which is an encoded percent sign — the id has ' +
        'been encoded twice. The server decodes once, gets uid%3Dalice..., ' +
        'and answers 404 about an id nobody has. That failure reads exactly ' +
        'like a deleted user.');
    assert.strictEqual(decodeURIComponent(
        request.url.split('/Users/')[1]), dn,
        'The encoded segment does not decode back to the id that went in.');
  });
  check('a trailing slash on the service root does not double up', function () {
    const request = scim.buildRequest({
      operation: 'listUsers', baseUrl: 'https://host/scim/v2/' });
    assert.strictEqual(request.url, 'https://host/scim/v2/Users',
        '//Users is a different URL from /Users to a server that routes on ' +
        'the literal path.');
  });
  check('a filter is carried verbatim and is not re-quoted', function () {
    const filter = 'emails[type eq "work"].value sw "a.b"';
    const request = scim.buildRequest({
      operation: 'listUsers', baseUrl: 'https://h/scim/v2',
      query: { filter: filter } });
    const sent = decodeURIComponent(request.url.split('filter=')[1]);
    assert.strictEqual(sent, filter,
        'The filter grammar is the SERVER\'s to parse. A client that quotes ' +
        'or escapes a filter makes invalidFilter unreachable, which is the ' +
        'one error a filter debugger exists to show.');
  });
  check('only the query parameters an operation accepts are sent', function () {
    // readUser takes attributes/excludedAttributes and NOT filter or sortBy.
    const request = scim.buildRequest({
      operation: 'readUser', baseUrl: 'https://h/scim/v2', id: 'x',
      query: { attributes: 'userName', filter: 'userName pr',
               sortBy: 'userName' } });
    assert.ok(request.url.indexOf('attributes=userName') >= 0);
    assert.ok(request.url.indexOf('filter=') < 0,
        'A filter was sent on a single-resource read, which accepts none.');
    assert.ok(request.url.indexOf('sortBy=') < 0);
  });
  check('an operation that needs an id refuses to compose without one',
      function () {
    assert.throws(function () {
      scim.buildRequest({ operation: 'readUser',
                         baseUrl: 'https://h/scim/v2' });
    }, /needs a resource id/,
        'Composing /Users/undefined would produce a 404 that reads as a ' +
        'deleted user rather than as a missing field.');
  });
  check('a body-carrying operation sets the SCIM content type', function () {
    const request = scim.buildRequest({
      operation: 'createUser', baseUrl: 'https://h/scim/v2',
      body: { schemas: [scim.USER_SCHEMA], userName: 'a' } });
    assert.strictEqual(request.headers['Content-Type'],
        'application/scim+json');
    assert.strictEqual(request.headers.Accept, 'application/scim+json');
  });
  check('a GET carries no content type', function () {
    const request = scim.buildRequest({
      operation: 'listUsers', baseUrl: 'https://h/scim/v2' });
    assert.strictEqual(request.headers['Content-Type'], undefined,
        'A Content-Type on a request with no body is a header describing ' +
        'nothing, and some servers reject it.');
  });
  log.debug("Leaving theIdIsEncodedExactlyOnce().");
}

// ---------------------------------------------------------------------------
// 2. THE GENERATOR.
// ---------------------------------------------------------------------------

// RFC 7643 section 4.1's complete User, written out here independently of the
// generator — same reasoning as the endpoint list above. `singular` are the
// simple attributes; `multi` are the multi-valued ones, each of which has to
// carry its sub-attributes; `name` is the one complex singular attribute.
//
// THIS IS THE LIST THE USER ASKED FOR IN SO MANY WORDS: the tests must include
// every optional field, to make sure they actually work.
const RFC_7643_USER_SINGULAR = ['userName', 'displayName', 'nickName',
    'profileUrl', 'title', 'userType', 'preferredLanguage', 'locale',
    'timezone', 'active'];
const RFC_7643_NAME_SUB = ['formatted', 'familyName', 'givenName',
    'middleName', 'honorificPrefix', 'honorificSuffix'];
const RFC_7643_USER_MULTI = ['emails', 'phoneNumbers', 'ims', 'photos',
    'addresses', 'entitlements', 'roles', 'x509Certificates'];
const RFC_7643_ADDRESS_SUB = ['formatted', 'streetAddress', 'locality',
    'region', 'postalCode', 'country', 'type'];
const RFC_7643_ENTERPRISE = ['employeeNumber', 'costCenter', 'organization',
    'division', 'department'];

function theGeneratorEmitsEveryOptionalAttribute() {
  log.debug("Entering theGeneratorEmitsEveryOptionalAttribute().");
  log.info("2. The generator.");
  const user = scim.randomUser({ seed: 'engine-test', index: 0 });
  check('the generated user declares both schemas', function () {
    assert.deepStrictEqual(user.schemas,
        [scim.USER_SCHEMA, scim.ENTERPRISE_SCHEMA]);
  });
  check('externalId is present', function () {
    assert.ok(user.externalId && String(user.externalId).length > 0);
  });
  RFC_7643_USER_SINGULAR.forEach(function (name) {
    check('RFC 7643 4.1: ' + name + ' is generated', function () {
      assert.ok(user[name] !== undefined && user[name] !== '',
          name + ' is an attribute RFC 7643 section 4.1 defines and the ' +
          'generator does not emit it. A field that is never sent is a field ' +
          'this workflow can never find out whether the server stores.');
    });
  });
  RFC_7643_NAME_SUB.forEach(function (name) {
    check('RFC 7643 4.1: name.' + name + ' is generated', function () {
      assert.ok(user.name && user.name[name],
          'name.' + name + ' is missing. All six sub-attributes are ' +
          'optional and all six are the ones a provisioning client meets ' +
          'and has never tested.');
    });
  });
  RFC_7643_USER_MULTI.forEach(function (name) {
    check('RFC 7643 4.1: ' + name + ' is generated with sub-attributes',
        function () {
      assert.ok(Array.isArray(user[name]) && user[name].length > 0,
          name + ' is a multi-valued attribute RFC 7643 section 4.1 defines ' +
          'and the generator emits none.');
      assert.ok(user[name][0].value !== undefined ||
          name === 'addresses',
          name + '[0] carries no `value`. Every multi-valued attribute but ' +
          'addresses is a list of {value, type, primary, display}.');
      assert.ok(user[name][0].type !== undefined,
          name + '[0] carries no `type`, which is the sub-attribute a ' +
          'server uses to tell one value from another — and the one a PATCH ' +
          'value-filter path selects on.');
    });
  });
  check('emails carries a primary and a non-primary', function () {
    const primaries = user.emails.filter(function (row) {
      return row.primary === true;
    });
    assert.strictEqual(primaries.length, 1,
        'RFC 7643 section 2.4: at most ONE value of a multi-valued ' +
        'attribute may be primary. Sending two is a conformance error a ' +
        'permissive server will accept silently.');
    assert.ok(user.emails.length > 1,
        'One email cannot exercise a value-filter path such as ' +
        'emails[type eq "home"], which is what the PATCH scenarios remove on.');
  });
  check('every multi-valued attribute has at most one primary', function () {
    RFC_7643_USER_MULTI.forEach(function (name) {
      const primaries = user[name].filter(function (row) {
        return row.primary === true;
      });
      assert.ok(primaries.length <= 1,
          name + ' carries ' + primaries.length + ' primary values and RFC ' +
          '7643 section 2.4 allows at most one.');
    });
  });
  RFC_7643_ADDRESS_SUB.forEach(function (name) {
    check('RFC 7643 4.1: addresses[0].' + name + ' is generated', function () {
      assert.ok(user.addresses[0][name] !== undefined &&
          user.addresses[0][name] !== '',
          'addresses[0].' + name + ' is missing.');
    });
  });
  check('the formatted address agrees with its own parts', function () {
    const address = user.addresses[0];
    assert.ok(address.formatted.indexOf(address.streetAddress) >= 0 &&
        address.formatted.indexOf(address.postalCode) >= 0 &&
        address.formatted.indexOf(address.country) >= 0,
        'An address whose formatted line disagrees with its own fields is ' +
        'the one difference a reader cannot tell from a server bug.');
  });
  RFC_7643_ENTERPRISE.forEach(function (name) {
    check('RFC 7643 4.3: enterprise ' + name + ' is generated', function () {
      assert.ok(user[scim.ENTERPRISE_SCHEMA][name],
          'The enterprise extension is missing ' + name + '.');
    });
  });
  check('the enterprise manager is NOT invented', function () {
    assert.strictEqual(user[scim.ENTERPRISE_SCHEMA].manager, undefined,
        'manager is a reference to another user\'s id. A generator ' +
        'inventing one produces a dangling reference on EVERY user, which ' +
        'is a scenario worth running on purpose and a poor default. The ' +
        'enterprise scenario sets it once both parties exist.');
  });
  check('a minimal user is userName and nothing else', function () {
    const minimal = scim.randomUser({ seed: 'engine-test', minimal: true });
    assert.deepStrictEqual(Object.keys(minimal).sort(),
        ['schemas', 'userName'],
        'The minimal user is the smallest legal User and the one a create ' +
        'should never fail on; anything extra in it makes that a weaker test.');
  });
  check('no password is generated unless one is asked for', function () {
    assert.strictEqual(user.password, undefined,
        'RFC 7643 4.1 makes password writeOnly. Generating one would make ' +
        'this the only workflow here that wrote a secret nobody asked for.');
    const withPassword = scim.randomUser({ seed: 's', password: 'hunter2' });
    assert.strictEqual(withPassword.password, 'hunter2');
  });
  log.debug("Leaving theGeneratorEmitsEveryOptionalAttribute().");
}

function theSeedIsReproducible() {
  log.debug("Entering theSeedIsReproducible().");
  log.info("2b. Reproducibility.");
  check('the same seed produces byte-identical users', function () {
    const a = scim.randomUser({ seed: 'repeat-me', index: 3 });
    const b = scim.randomUser({ seed: 'repeat-me', index: 3 });
    assert.strictEqual(JSON.stringify(a), JSON.stringify(b),
        'An unseeded generator makes every interesting failure a story ' +
        'rather than a test: "it failed on the seventh user" cannot be run ' +
        'again.');
  });
  check('a different seed produces a different user', function () {
    const a = scim.randomUser({ seed: 'seed-a' });
    const b = scim.randomUser({ seed: 'seed-b' });
    assert.notStrictEqual(a.userName, b.userName,
        'Two seeds produced the same userName, so the seed is not reaching ' +
        'the generator and every "random" run is the same run.');
  });
  check('one rng threaded through N users gives N DISTINCT userNames',
      function () {
    const rng = scim.newRng('bulk-seed');
    const names = {};
    let i;
    for (i = 0; i < 50; i++) {
      names[scim.randomUser({ rng: rng, index: i }).userName] = true;
    }
    assert.strictEqual(Object.keys(names).length, 50,
        'A fifty-user scenario generated a duplicate userName. Every ' +
        'duplicate is a 409 the plan did not expect, and it reads as a ' +
        'server fault rather than as a generator fault.');
  });
  check('a seeded rng is deterministic across calls', function () {
    const first = [];
    const second = [];
    const rngA = scim.newRng('x');
    const rngB = scim.newRng('x');
    let i;
    for (i = 0; i < 20; i++) {
      first.push(rngA());
      second.push(rngB());
    }
    assert.deepStrictEqual(first, second);
    first.forEach(function (value) {
      assert.ok(value >= 0 && value < 1, 'mulberry32 produced ' + value);
    });
  });
  log.debug("Leaving theSeedIsReproducible().");
}

// ---------------------------------------------------------------------------
// 3. THE MESSAGE BODIES.
// ---------------------------------------------------------------------------
function theMessageBodiesAreRfcShaped() {
  log.debug("Entering theMessageBodiesAreRfcShaped().");
  log.info("3. The message bodies.");
  check('a SearchRequest carries its URN and ARRAY attributes', function () {
    const body = scim.searchRequest({ filter: 'userName pr',
        attributes: 'userName,id', count: 10, startIndex: 1 });
    assert.deepStrictEqual(body.schemas, [scim.SEARCH_REQUEST_SCHEMA]);
    assert.deepStrictEqual(body.attributes, ['userName', 'id'],
        'attributes is an ARRAY in a SearchRequest and a comma-separated ' +
        'STRING in a query string. That asymmetry is in RFC 7644 itself ' +
        '(section 3.4.2.5 against 3.4.3) and is the single most common ' +
        'reason a /.search returns every attribute when two were asked for.');
    assert.strictEqual(typeof body.count, 'number',
        'count in a SearchRequest is a number, not the string a query ' +
        'string carries.');
  });
  check('an empty SearchRequest carries only its URN', function () {
    assert.deepStrictEqual(scim.searchRequest({}),
        { schemas: [scim.SEARCH_REQUEST_SCHEMA] },
        'A member with an empty value is not the same as an absent one: ' +
        'filter="" asks a server to parse the empty string as a filter.');
  });
  check('a PatchOp lower-cases op and omits an empty path', function () {
    const body = scim.patchOp([
      { op: 'Replace', path: 'title', value: 'x' },
      { op: 'add', value: { title: 'y' } }
    ]);
    assert.deepStrictEqual(body.schemas, [scim.PATCH_OP_SCHEMA]);
    assert.strictEqual(body.Operations[0].op, 'replace',
        'Several servers compare `op` case-sensitively against the lower ' +
        'case of RFC 7644\'s own examples.');
    assert.strictEqual(body.Operations[1].path, undefined,
        'path is OPTIONAL on add and replace, where its absence means "the ' +
        'value is a partial resource to merge". Sending path:"" instead is ' +
        'a path the server has to parse and cannot.');
    assert.strictEqual(body.Operations[1].value.title, 'y');
  });
  check('the Operations member is capitalised', function () {
    const body = scim.patchOp([{ op: 'remove', path: 'x' }]);
    assert.ok(Array.isArray(body.Operations),
        'RFC 7644 section 3.5.2 spells it "Operations" with a capital O. ' +
        'Lower case is accepted by permissive servers and by nobody else.');
    assert.strictEqual(body.operations, undefined);
  });
  check('a BulkRequest carries bulkIds and failOnErrors', function () {
    const body = scim.bulkRequest([
      { method: 'post', bulkId: 'u1', path: '/Users', data: { userName: 'a' } },
      { method: 'DELETE', path: '/Users/x' }
    ], { failOnErrors: 1 });
    assert.deepStrictEqual(body.schemas, [scim.BULK_REQUEST_SCHEMA]);
    assert.strictEqual(body.Operations[0].method, 'POST',
        'The method inside a bulk operation is upper case.');
    assert.strictEqual(body.Operations[0].bulkId, 'u1');
    assert.strictEqual(body.Operations[1].bulkId, undefined,
        'bulkId is required on a POST and meaningless on a DELETE.');
    assert.strictEqual(body.failOnErrors, 1);
  });
  log.debug("Leaving theMessageBodiesAreRfcShaped().");
}

// ---------------------------------------------------------------------------
// 4. AUTHENTICATION.
//
// The six schemes RFC 7644 section 2 names, plus anonymous. This is the section
// the whole workflow's authentication rests on, and it is here rather than in
// scim_protocol.js because a wrong hash and a wrong password produce the same
// 401 from a server.
// ---------------------------------------------------------------------------
function everySchemeInSection2IsSupported() {
  log.debug("Entering everySchemeInSection2IsSupported().");
  log.info("4. Authentication.");
  // RFC 7644 section 2's own list, written out independently.
  const SECTION_2 = ['clientcert', 'hoba', 'bearer', 'dpop', 'cookie', 'basic',
                     'digest'];
  check('every scheme RFC 7644 section 2 names is offered', function () {
    SECTION_2.forEach(function (id) {
      assert.ok(scim.authScheme(id),
          'RFC 7644 section 2 names this way of authenticating and the ' +
          'workflow does not offer it: ' + id);
    });
  });
  check('no scheme is offered that section 2 does NOT name', function () {
    const extra = scim.AUTH_SCHEMES.map(function (row) {
      return row.id;
    }).filter(function (id) {
      return id !== 'none' && SECTION_2.indexOf(id) < 0;
    });
    assert.deepStrictEqual(extra, [],
        'These schemes are offered and are in no specification: ' +
        extra.join(', ') + '. The temptation is an API key in a shared ' +
        'header, which is what most provisioning integrations use in the ' +
        'field — a client built against it here would interoperate with ' +
        'nothing.');
  });
  check('only the two OAuth schemes carry scopes', function () {
    scim.AUTH_SCHEMES.forEach(function (row) {
      const shouldBeScoped = row.id === 'bearer' || row.id === 'dpop';
      assert.strictEqual(row.scoped, shouldBeScoped,
          row.id + ' has scoped=' + row.scoped + '. A Basic credential, a ' +
          'client certificate and a HOBA signature carry no scope, so a ' +
          'server accepting them has no per-operation policy to apply — ' +
          'which is worth knowing before concluding a scope restriction ' +
          'works.');
    });
  });
  check('cookie and clientcert are browser-only', function () {
    ['cookie', 'clientcert'].forEach(function (id) {
      assert.strictEqual(scim.authScheme(id).backend, false,
          id + ' is marked as available through the api. It is not: the api ' +
          'has no cookie jar and would present its OWN certificate, which is ' +
          'a different identity and a misleading one.');
    });
    ['bearer', 'dpop', 'basic', 'digest'].forEach(function (id) {
      assert.strictEqual(scim.authScheme(id).backend, true,
          id + ' is a header the api can carry and is marked browser-only.');
    });
  });
  check('Basic is base64(user:password) per RFC 7617', function () {
    assert.strictEqual(scim.basicHeader('alice', 'password!'),
        'Basic ' + Buffer.from('alice:password!', 'utf8').toString('base64'));
  });
  check('Basic encodes non-ASCII as UTF-8', function () {
    const header = scim.basicHeader('aliçe', 'päss');
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    assert.strictEqual(decoded, 'aliçe:päss',
        'RFC 7617 section 2.1 makes UTF-8 the charset. Latin-1 here ' +
        'authenticates a different name than the one typed.');
  });
  check('applyAuth adds the right header for each scheme', function () {
    const request = { method: 'GET', url: 'https://h/scim/v2/Users',
                      headers: {} };
    assert.strictEqual(
        scim.applyAuth(request, { scheme: 'bearer', token: 'T' })
          .headers.Authorization, 'Bearer T');
    const dpop = scim.applyAuth(request,
        { scheme: 'dpop', token: 'T', proof: 'P' });
    assert.strictEqual(dpop.headers.Authorization, 'DPoP T');
    assert.strictEqual(dpop.headers.DPoP, 'P',
        'A DPoP-bound token needs BOTH the Authorization header and the ' +
        'proof in its own DPoP header.');
    assert.strictEqual(
        scim.applyAuth(request, { scheme: 'cookie' }).credentials, 'include',
        'A cookie rides on the request only if the call is made with ' +
        'credentials. Without that the browser sends nothing and the 401 ' +
        'reads as a missing session.');
    const cert = scim.applyAuth(request, { scheme: 'clientcert' });
    assert.deepStrictEqual(cert.headers, {},
        'A client certificate is chosen during the TLS handshake. Any ' +
        'header here would be a fabrication.');
    assert.ok(cert.note.length > 0,
        'A scheme that adds nothing must SAY it added nothing, or the page ' +
        'looks like it did not run.');
  });
  check('a HOBA credential is result="kid.challenge.nonce.sig"', function () {
    const applied = scim.applyAuth(
        { method: 'GET', url: 'https://h/x', headers: {} },
        { scheme: 'hoba', hoba: { kid: 'k1', challenge: 'ch',
                                  nonce: 'n1', signature: 'sig' } });
    assert.strictEqual(applied.headers.Authorization,
        'HOBA result="k1.ch.n1.sig"',
        'RFC 7486 section 6: four base64url fields separated by full stops, ' +
        'in that order.');
  });
  log.debug("Leaving everySchemeInSection2IsSupported().");
}

function theHobaBlobIsLengthPrefixed() {
  log.debug("Entering theHobaBlobIsLengthPrefixed().");
  log.info("4b. HOBA (RFC 7486).");
  check('the to-be-signed blob is length-prefixed, not delimited', function () {
    const tbs = scim.hobaToBeSigned({ nonce: 'abc', alg: '0',
        origin: 'https://h:443', realm: 'SCIM', kid: 'k1', challenge: 'ch' });
    assert.strictEqual(tbs, '3:abc1:013:https://h:4434:SCIM2:k12:ch',
        'RFC 7486 section 5 prefixes each field with its length in octets ' +
        'and a colon and concatenates them with nothing between. A ' +
        'dot-joined version looks reasonable, is the right size and shape, ' +
        'and verifies against NOTHING — and the only error a server can give ' +
        'back is "this does not verify", which sends everybody to look at ' +
        'their key.');
  });
  check('the field order is nonce, alg, origin, realm, kid, challenge',
      function () {
    const tbs = scim.hobaToBeSigned({ nonce: 'N', alg: 'A', origin: 'O',
        realm: 'R', kid: 'K', challenge: 'C' });
    assert.strictEqual(tbs, '1:N1:A1:O1:R1:K1:C',
        'The order is normative. Getting it wrong produces a signature of ' +
        'the right shape that verifies against nothing.');
  });
  check('the length is in OCTETS and not characters', function () {
    // A two-character string that is three bytes in UTF-8.
    const tbs = scim.hobaToBeSigned({ nonce: 'aé', alg: '0', origin: '',
        realm: '', kid: '', challenge: '' });
    assert.ok(tbs.indexOf('3:aé') === 0,
        'A realm carrying an accent makes octets and characters disagree, ' +
        'and the failure is the same silent one.');
  });
  check('the origin always carries an explicit port', function () {
    assert.strictEqual(scim.originOf('https://host/scim/v2/Users'),
        'https://host:443',
        'RFC 7486 gives the origin no serialization of its own, so ' +
        'https://host and https://host:443 are two different strings over ' +
        'which two different signatures are computed. A browser\'s ' +
        'location.origin omits the default port and a server ' +
        'reconstructing it from Host usually does not.');
    assert.strictEqual(scim.originOf('http://host/x'), 'http://host:80');
    assert.strictEqual(scim.originOf('http://host:8081/scim/v2'),
        'http://host:8081');
  });
  check('the algorithm identifier is the string "0" (RSA-SHA256)',
      function () {
    assert.strictEqual(scim.HOBA_ALG_RSA_SHA256, '0');
    assert.strictEqual(typeof scim.HOBA_ALG_RSA_SHA256, 'string',
        'It goes into the signed blob as a field whose LENGTH is prefixed, ' +
        'so it must not be arithmetic by accident.');
  });
  log.debug("Leaving theHobaBlobIsLengthPrefixed().");
}

// The mock STS hashes with node's own crypto (`crypto.createHash`), so these
// vectors are computed the same way here. That is the point: the client's
// hashes are @noble/hashes and node-forge — completely different
// implementations — and this compares them against the ones the server will
// actually use.
function mockDigestHash(algorithm, text) {
  log.debug("Entering mockDigestHash(). algorithm=" + algorithm);
  const map = { 'SHA-256': 'sha256', 'SHA-512-256': 'sha512-256',
                'MD5': 'md5' };
  const base = String(algorithm).replace(/-sess$/i, '').toUpperCase();
  if (!map[base]) {
    log.debug("Leaving mockDigestHash(). Unknown algorithm.");
    return null;
  }
  const out = crypto.createHash(map[base]).update(text, 'utf8').digest('hex');
  log.debug("Leaving mockDigestHash().");
  return out;
}

function digestMatchesTheServersArithmetic() {
  log.debug("Entering digestMatchesTheServersArithmetic().");
  log.info("4c. HTTP Digest (RFC 7616).");
  check('all three registered algorithms are implemented', function () {
    const tokens = scim.DIGEST_ALGORITHMS.map(function (row) {
      return row.token;
    });
    ['SHA-256', 'SHA-512-256', 'MD5'].forEach(function (name) {
      assert.ok(tokens.indexOf(name) >= 0,
          'RFC 7616 section 6.1 registers ' + name + ' and this build ' +
          'cannot compute it. Web Crypto has neither MD5 nor SHA-512/256, ' +
          'so a client that reached for crypto.subtle would report every ' +
          'MD5-only server as bad credentials.');
    });
  });
  check('SHA-256 is preferred over MD5 when both are offered', function () {
    assert.strictEqual(scim.DIGEST_ALGORITHMS[0].token, 'SHA-256',
        'The preference order decides which of a server\'s challenges is ' +
        'answered, and the conventional ordering in a header puts the ' +
        'weakest last — so taking the last one parsed reliably picks MD5.');
  });
  ['SHA-256', 'SHA-512-256', 'MD5', 'SHA-256-sess', 'MD5-sess']
    .forEach(function (algorithm) {
      check('the ' + algorithm + ' response matches the server\'s own ' +
          'arithmetic', function () {
        const header = 'Digest realm="SCIM", qop="auth", algorithm=' +
            algorithm + ', nonce="abc123", opaque="dead", charset=UTF-8';
        const chosen = scim.chooseDigestChallenge(scim.parseChallenges(header));
        assert.ok(chosen && chosen.challenge,
            'The challenge naming ' + algorithm + ' was not chosen at all.');
        const fields = scim.digestCredential({
          params: chosen.challenge.params, algorithm: chosen.algorithm,
          username: 'alice', password: 'password!', method: 'GET',
          uri: '/scim/v2/Users?count=1', nc: '00000003', cnonce: 'cnv1'
        });
        const base = algorithm.replace(/-sess$/i, '');
        const session = /-sess$/i.test(algorithm);
        let ha1 = mockDigestHash(base, 'alice:SCIM:password!');
        if (session) {
          ha1 = mockDigestHash(base, ha1 + ':abc123:cnv1');
        }
        const ha2 = mockDigestHash(base, 'GET:/scim/v2/Users?count=1');
        const expected = mockDigestHash(base,
            ha1 + ':abc123:00000003:cnv1:auth:' + ha2);
        assert.strictEqual(fields.response, expected,
            'The ' + algorithm + ' digest response does not match what a ' +
            'server computing it with node\'s crypto would expect. That ' +
            'produces a 401 indistinguishable from a wrong password.');
        assert.strictEqual(fields.algorithm, algorithm,
            'The credential must name the algorithm it used, including the ' +
            '-sess suffix; a server defaults to MD5 when it is absent.');
      });
    });
  check('the -sess variants really do fold the nonces into A1', function () {
    const plain = scim.digestCredential({
      params: { realm: 'SCIM', nonce: 'n', qop: 'auth', algorithm: 'SHA-256' },
      algorithm: scim.digestAlgorithm('SHA-256'),
      username: 'a', password: 'p', method: 'GET', uri: '/x',
      nc: '00000001', cnonce: 'c' });
    const session = scim.digestCredential({
      params: { realm: 'SCIM', nonce: 'n', qop: 'auth',
                algorithm: 'SHA-256-sess' },
      algorithm: scim.digestAlgorithm('SHA-256-sess'),
      username: 'a', password: 'p', method: 'GET', uri: '/x',
      nc: '00000001', cnonce: 'c' });
    assert.notStrictEqual(plain.response, session.response,
        'SHA-256 and SHA-256-sess produced the same response, so the -sess ' +
        'branch is not running and the suffix is decoration.');
  });
  check('the strongest of THREE challenges in one header is chosen',
      function () {
    // Exactly what this project's mock STS sends: three Digest challenges in
    // one WWW-Authenticate header, sharing a nonce, weakest last.
    const header =
      'Digest realm="SCIM", qop="auth", algorithm=SHA-256, nonce="n1", ' +
      'opaque="o1", charset=UTF-8, ' +
      'Digest realm="SCIM", qop="auth", algorithm=SHA-512-256, nonce="n1", ' +
      'opaque="o1", charset=UTF-8, ' +
      'Digest realm="SCIM", qop="auth", algorithm=MD5, nonce="n1", ' +
      'opaque="o1", charset=UTF-8';
    const parsed = scim.parseChallenges(header);
    assert.strictEqual(parsed.length, 3,
        'Three challenges in one header parsed as ' + parsed.length + '. A ' +
        'naive split on "," destroys this: there are three challenges and ' +
        'fifteen commas.');
    const chosen = scim.chooseDigestChallenge(parsed);
    assert.strictEqual(chosen.algorithm.row.token, 'SHA-256',
        'MD5 was chosen over SHA-256 — which is what taking the last ' +
        'challenge parsed does, every time, because the weakest is ' +
        'conventionally last.');
  });
  check('a challenge naming only an uncomputable algorithm is REPORTED',
      function () {
    const chosen = scim.chooseDigestChallenge(scim.parseChallenges(
        'Digest realm="R", nonce="n", algorithm=SHA-1'));
    assert.ok(chosen.unsupported,
        'A server offering only an algorithm this build cannot compute must ' +
        'produce a named refusal, not a silent failure that reads as bad ' +
        'credentials.');
    assert.deepStrictEqual(chosen.unsupported, ['SHA-1']);
  });
  check('nc and qop and algorithm are UNQUOTED and the rest are quoted',
      function () {
    const header = scim.digestHeader({
      username: 'alice', realm: 'SCIM', nonce: 'n', uri: '/x',
      response: 'r', opaque: 'o', cnonce: 'c', qop: 'auth', nc: '00000002',
      algorithm: 'SHA-256' });
    assert.ok(header.indexOf('nc=00000002') >= 0 &&
        header.indexOf('nc="') < 0,
        'A server that parses strictly refuses a quoted nc, and that ' +
        'refusal also reads as bad credentials. Header was: ' + header);
    assert.ok(header.indexOf('qop=auth') >= 0 && header.indexOf('qop="') < 0);
    assert.ok(header.indexOf('algorithm=SHA-256') >= 0);
    assert.ok(header.indexOf('username="alice"') >= 0 &&
        header.indexOf('nonce="n"') >= 0 && header.indexOf('uri="/x"') >= 0);
    assert.ok(header.indexOf('ha1') < 0,
        'The internal HA1 leaked into the Authorization header. It is kept ' +
        'on the credential only so Authentication-Info can be checked ' +
        'without carrying the password to a second place.');
  });
  check('the server\'s rspauth is verified — RFC 7616 section 3.5',
      function () {
    const params = { realm: 'SCIM', nonce: 'abc123', qop: 'auth',
                     opaque: 'o', algorithm: 'SHA-256' };
    const fields = scim.digestCredential({
      params: params, algorithm: scim.digestAlgorithm('SHA-256'),
      username: 'alice', password: 'password!', method: 'GET',
      uri: '/scim/v2/Users', nc: '00000001', cnonce: 'c1' });
    const ha1 = mockDigestHash('SHA-256', 'alice:SCIM:password!');
    // A2 with an EMPTY method — that is the whole difference from the request
    // side, and it is what stops a server echoing the client's own response.
    const rspauth = mockDigestHash('SHA-256', ha1 + ':abc123:00000001:c1:' +
        'auth:' + mockDigestHash('SHA-256', ':/scim/v2/Users'));
    const verdict = scim.verifyAuthenticationInfo({
      header: 'qop=auth, rspauth="' + rspauth + '", cnonce="c1", nc=00000001',
      fields: fields });
    assert.ok(verdict.present && verdict.ok,
        'rspauth is how a client authenticates the SERVER, and a client ' +
        'that never checks it has mutual authentication available and ' +
        'unused. Verdict: ' + verdict.note);
    const wrong = scim.verifyAuthenticationInfo({
      header: 'qop=auth, rspauth="' + rspauth.replace(/^./, '0') + '"',
      fields: fields });
    assert.strictEqual(wrong.ok, false,
        'A tampered rspauth verified, so the check is not really running.');
  });
  check('an absent Authentication-Info is reported and is not a failure',
      function () {
    const verdict = scim.verifyAuthenticationInfo({ header: '', fields: {} });
    assert.strictEqual(verdict.present, false);
    assert.strictEqual(verdict.ok, false);
    assert.ok(verdict.note.indexOf('most implementations leave out') >= 0,
        'Its absence is ordinary rather than suspicious, and the page has ' +
        'to say so or it reads as a failed check.');
  });
  log.debug("Leaving digestMatchesTheServersArithmetic().");
}

function theChallengeParserHandlesSeveralSchemes() {
  log.debug("Entering theChallengeParserHandlesSeveralSchemes().");
  log.info("4d. Parsing WWW-Authenticate.");
  check('several schemes in one header are parsed separately', function () {
    const parsed = scim.parseChallenges(
      'Bearer realm="SCIM", scope="scim:read scim:write", ' +
      'Basic realm="SCIM", charset=UTF-8, ' +
      'HOBA challenge="ch1", max-age="600", realm="SCIM"');
    assert.strictEqual(parsed.length, 3,
        'RFC 7235 section 4.1 allows several challenges in one header and a ' +
        'split on "," destroys them. Parsed ' + parsed.length + '.');
    assert.deepStrictEqual(parsed.map(function (row) {
      return row.scheme;
    }), ['Bearer', 'Basic', 'HOBA']);
    assert.strictEqual(parsed[0].params.scope, 'scim:read scim:write',
        'A quoted value containing a SPACE was truncated.');
    assert.strictEqual(parsed[2].params.challenge, 'ch1');
    assert.strictEqual(parsed[2].params['max-age'], '600',
        'A parameter name with a hyphen in it was dropped.');
  });
  check('challengesFor picks out one scheme\'s challenges', function () {
    const parsed = scim.parseChallenges(
      'Digest realm="R", nonce="n1", algorithm=SHA-256, ' +
      'Digest realm="R", nonce="n1", algorithm=MD5, Basic realm="R"');
    assert.strictEqual(scim.challengesFor(parsed, 'digest').length, 2);
    assert.strictEqual(scim.challengesFor(parsed, 'basic').length, 1);
    assert.strictEqual(scim.challengesFor(parsed, 'bearer').length, 0);
  });
  check('an empty header parses to nothing rather than throwing', function () {
    assert.deepStrictEqual(scim.parseChallenges(''), []);
    assert.deepStrictEqual(scim.parseChallenges(undefined), []);
  });
  log.debug("Leaving theChallengeParserHandlesSeveralSchemes().");
}

// ---------------------------------------------------------------------------
// 5. READING AN ANSWER.
// ---------------------------------------------------------------------------
function theFiveShapesAreToldApart() {
  log.debug("Entering theFiveShapesAreToldApart().");
  log.info("5. Reading an answer.");
  check('a ListResponse is recognised and counted', function () {
    const described = scim.describeResponse(200, {
      schemas: [scim.LIST_RESPONSE_SCHEMA], totalResults: 42, startIndex: 1,
      Resources: [{}, {}] });
    assert.strictEqual(described.kind, 'list');
    assert.strictEqual(described.count, 42);
    assert.ok(described.ok);
  });
  check('a BulkResponse counts the operations that FAILED INSIDE it',
      function () {
    const described = scim.describeResponse(200, {
      schemas: [scim.BULK_RESPONSE_SCHEMA],
      Operations: [{ status: '201' }, { status: '409' }, { status: '201' }] });
    assert.strictEqual(described.kind, 'bulk');
    assert.ok(described.summary.indexOf('1 of them refused') >= 0,
        'The 200 on the envelope says the bulk was PROCESSED, not that ' +
        'everything in it worked. A reader who stops at the envelope has ' +
        'been told the opposite of what happened. Summary: ' +
        described.summary);
  });
  check('an Error carries its scimType and detail', function () {
    const described = scim.describeResponse(409, {
      schemas: [scim.ERROR_SCHEMA], status: '409', scimType: 'uniqueness',
      detail: 'that userName is taken' });
    assert.strictEqual(described.kind, 'error');
    assert.strictEqual(described.ok, false);
    assert.strictEqual(described.scimType, 'uniqueness');
    assert.deepStrictEqual(described.conformance, [],
        'A conforming Error produced a conformance complaint.');
  });
  check('a NUMERIC status in an Error is reported as non-conforming',
      function () {
    const described = scim.describeResponse(409, {
      schemas: [scim.ERROR_SCHEMA], status: 409, scimType: 'uniqueness' });
    assert.ok(described.conformance.length > 0 &&
        described.conformance[0].indexOf('NUMBER') >= 0,
        'RFC 7644 section 3.12 defines status as a STRING. That is the ' +
        'detail everybody gets wrong and every client checks — and a server ' +
        'sending a number is non-conforming in a way its own client will ' +
        'never notice.');
  });
  check('an Error whose status disagrees with the HTTP status is flagged',
      function () {
    const described = scim.describeResponse(400, {
      schemas: [scim.ERROR_SCHEMA], status: '409' });
    assert.ok(described.conformance.some(function (note) {
      return note.indexOf('409') >= 0 && note.indexOf('400') >= 0;
    }), 'A body claiming a different status from the response it arrived on ' +
        'went unremarked.');
  });
  check('204 is an answer and not an empty failure', function () {
    const described = scim.describeResponse(204, null);
    assert.strictEqual(described.kind, 'empty');
    assert.ok(described.ok,
        'A delete answers 204 and so does a PATCH that changed nothing. ' +
        'Reading an empty body as a failure would make every successful ' +
        'delete look broken.');
  });
  check('a single resource is recognised', function () {
    const described = scim.describeResponse(201, {
      schemas: [scim.USER_SCHEMA], id: 'uid=a,ou=users' });
    assert.strictEqual(described.kind, 'resource');
  });
  check('every scimType RFC 7644 section 3.12 defines is explained',
      function () {
    // The closed list from the specification, written out independently.
    ['invalidFilter', 'tooMany', 'uniqueness', 'mutability', 'invalidSyntax',
     'invalidPath', 'noTarget', 'invalidValue', 'invalidVers', 'sensitive']
      .forEach(function (name) {
        assert.ok(scim.explainScimType(name).length > 0,
            'scimType "' + name + '" is in RFC 7644\'s closed list and the ' +
            'page has nothing to say about it. The HTTP status alone cannot ' +
            'tell uniqueness from invalidValue — both are 400 on many ' +
            'servers.');
      });
  });
  log.debug("Leaving theFiveShapesAreToldApart().");
}

// ---------------------------------------------------------------------------
// 6. SCENARIOS.
// ---------------------------------------------------------------------------
function everyScenarioPlans() {
  log.debug("Entering everyScenarioPlans().");
  log.info("6. Scenarios.");
  scenarios.SCENARIOS.forEach(function (definition) {
    check('the "' + definition.id + '" scenario plans', function () {
      const plan = scenarios.plan(definition.id,
          { userCount: 3, seed: 'plan-test', prefix: 'pt' });
      assert.ok(plan.steps.length > 0,
          definition.id + ' planned no steps at all, which would run green ' +
          'having done nothing — this project\'s recurring defect.');
      plan.steps.forEach(function (step, index) {
        assert.ok(step.id, definition.id + ' step ' + index + ' has no id.');
        assert.ok(scim.operation(step.operation),
            definition.id + ' step ' + index + ' names the operation "' +
            step.operation + '", which is not in the catalogue.');
        assert.ok(step.expect.status.length > 0,
            definition.id + ' step ' + index + ' carries no expectation. A ' +
            'step with none is judged "no expectation, therefore fine", ' +
            'which is a silent pass.');
        assert.ok(step.title, definition.id + ' step ' + index +
            ' has no title, so the runner table would show a blank row.');
      });
    });
  });
  check('every step id in a plan is unique', function () {
    scenarios.SCENARIOS.forEach(function (definition) {
      const plan = scenarios.plan(definition.id, { userCount: 5 });
      const seen = {};
      plan.steps.forEach(function (step) {
        assert.ok(!seen[step.id],
            definition.id + ' has two steps called "' + step.id + '". A ' +
            'duplicate id makes one step resolve the other\'s references, ' +
            'which is a scenario deleting a user another step is still ' +
            'using — and it looks like the server losing one.');
        seen[step.id] = true;
      });
    });
  });
  check('every reference names a step that runs EARLIER', function () {
    scenarios.SCENARIOS.forEach(function (definition) {
      const plan = scenarios.plan(definition.id, { userCount: 4 });
      const seen = {};
      plan.steps.forEach(function (step, index) {
        collectRefs(step).forEach(function (name) {
          assert.ok(seen[name],
              definition.id + ' step ' + index + ' ("' + step.id + '") ' +
              'references "' + name + '", which has not run yet. That ' +
              'reference can never resolve, so the step is always skipped — ' +
              'and a skipped step is a step that never tested anything.');
        });
        if (step.capture) {
          seen[step.id] = true;
        }
      });
    });
  });
  check('a captured step really does capture', function () {
    scenarios.SCENARIOS.forEach(function (definition) {
      const plan = scenarios.plan(definition.id, { userCount: 3 });
      const referenced = {};
      plan.steps.forEach(function (step) {
        collectRefs(step).forEach(function (name) {
          referenced[name] = true;
        });
      });
      plan.steps.forEach(function (step) {
        if (referenced[step.id]) {
          assert.ok(step.capture,
              definition.id + ': step "' + step.id + '" is referenced by a ' +
              'later step and captures nothing, so every reference to it ' +
              'resolves to an unresolved marker.');
        }
      });
    });
  });
  check('a scenario with N users creates N users', function () {
    const plan = scenarios.plan('deprovision',
        { userCount: 7, seed: 's', prefix: 'p' });
    const creates = plan.steps.filter(function (step) {
      return step.operation === 'createUser';
    });
    const deletes = plan.steps.filter(function (step) {
      return step.operation === 'deleteUser';
    });
    assert.strictEqual(creates.length, 7);
    assert.strictEqual(deletes.length, 7,
        'A deprovisioning scenario that creates seven and deletes six ' +
        'leaves one behind on every run.');
    const names = {};
    creates.forEach(function (step) {
      names[step.body.userName] = true;
    });
    assert.strictEqual(Object.keys(names).length, 7,
        'Two of the created users share a userName, so one create is a 409 ' +
        'the plan did not expect.');
  });
  check('the user count is capped', function () {
    const plan = scenarios.plan('deprovision', { userCount: 5000 });
    const creates = plan.steps.filter(function (step) {
      return step.operation === 'createUser';
    });
    assert.strictEqual(creates.length, 50,
        'Fifty users is around 150 requests, which is a long run and still ' +
        'a run; five hundred is a page that appears to have hung.');
  });
  check('the bulk scenario references users by bulkId', function () {
    const plan = scenarios.plan('bulk',
        { userCount: 3, seed: 's', prefix: 'p' });
    const bulk = plan.steps[0];
    const group = bulk.body.Operations[bulk.body.Operations.length - 1];
    assert.strictEqual(group.path, '/Groups');
    assert.strictEqual(group.data.members.length, 3);
    group.data.members.forEach(function (member) {
      assert.ok(String(member.value).indexOf('bulkId:') === 0,
          'A member is "' + member.value + '" rather than a bulkId ' +
          'reference. Referencing users created in the SAME request is the ' +
          'feature that makes a bulk more than a loop, and without it this ' +
          'scenario tests a loop.');
    });
  });
  check('the negative scenario EXPECTS refusals', function () {
    const plan = scenarios.plan('negatives', { seed: 's', prefix: 'p' });
    const duplicate = plan.steps.filter(function (step) {
      return step.id === 'duplicate';
    })[0];
    assert.ok(duplicate, 'The duplicate-userName step is missing.');
    assert.deepStrictEqual(duplicate.expect.status, ['409']);
    assert.strictEqual(duplicate.expect.scimType, 'uniqueness');
    const refused = plan.steps.filter(function (step) {
      return step.expect.status.some(function (status) {
        return String(status).charAt(0) === '4' ||
            String(status).charAt(0) === '5';
      });
    });
    assert.ok(refused.length >= 6,
        'Only ' + refused.length + ' steps of the negatives scenario expect ' +
        'a refusal. A client\'s error handling is the half that is never ' +
        'exercised, because a permissive server is hard to make say no.');
  });
  check('the filter tour sends every RFC 7644 3.4.2.2 operator', function () {
    const plan = scenarios.plan('filter-tour', { seed: 's', prefix: 'p' });
    const sent = plan.steps.filter(function (step) {
      return step.operation === 'listUsers' && step.query && step.query.filter;
    }).map(function (step) {
      return step.query.filter;
    }).join(' | ');
    ['eq', 'ne', 'co', 'sw', 'ew', 'pr', 'gt', 'ge', 'lt', 'le']
      .forEach(function (operator) {
        assert.ok(new RegExp('(^|[\\s|])[^|]*\\s' + operator + '[\\s"]')
            .test(sent) || sent.indexOf(' ' + operator + ' ') >= 0 ||
            sent.indexOf(' ' + operator) >= 0,
            'The filter tour never sends the "' + operator + '" operator. A ' +
            'server advertises filtering as ONE boolean, so this tour is ' +
            'the only way to find out which of the operators it really ' +
            'evaluates.');
      });
    assert.ok(sent.indexOf('not (') >= 0, 'The "not" grouping is never sent.');
    assert.ok(sent.indexOf(' and ') >= 0 && sent.indexOf(' or ') >= 0);
    assert.ok(sent.indexOf('emails[type eq "work"]') >= 0,
        'The complex value-filter grammar is never sent, and it is where a ' +
        'hand-rolled filter parser stops working.');
  });
  check('a random scenario is reproducible from its seed', function () {
    const a = scenarios.plan('random', { seed: 'abc', userCount: 4 });
    const b = scenarios.plan('random', { seed: 'abc', userCount: 4 });
    assert.strictEqual(JSON.stringify(a), JSON.stringify(b),
        'An unseeded random harness produces failures that cannot be ' +
        'reproduced, which is a bug report nobody can act on.');
    const c = scenarios.plan('random', { seed: 'xyz', userCount: 4 });
    assert.notStrictEqual(JSON.stringify(a), JSON.stringify(c),
        'Two different seeds composed the same scenario, so the seed is not ' +
        'reaching the shape generator.');
  });
  check('a random scenario namespaces its phases so they cannot collide',
      function () {
    // Several seeds, because one composes only three of the ten phases and a
    // collision between two phases that never met would go unnoticed.
    ['collide', 'abc', 'xyz', 'seed-4', 'seed-5'].forEach(function (seed) {
      const plan = scenarios.plan('random', { seed: seed, userCount: 6 });
      const names = {};
      plan.steps.forEach(function (step) {
        if (!step.body || !step.body.userName) {
          return;
        }
        // The negatives phase creates a duplicate ON PURPOSE and expects the
        // 409 — that is the whole of that step. So the rule is about the
        // creates that expect to SUCCEED: two of those sharing a name is an
        // unplanned 409, and it reads as a server fault rather than as a
        // generator fault.
        const expectsSuccess = step.expect.status.every(function (status) {
          return String(status).charAt(0) === '2';
        });
        if (!expectsSuccess) {
          return;
        }
        assert.ok(!names[step.body.userName],
            'Seed "' + seed + '": steps "' + names[step.body.userName] +
            '" and "' + step.id + '" both expect to create ' +
            step.body.userName + ' successfully. Each phase of a random ' +
            'scenario gets its own prefix and seed precisely so this cannot ' +
            'happen.');
        names[step.body.userName] = step.id;
      });
    });
  });
  check('a random scenario composes at least two phases', function () {
    ['collide', 'abc', 'xyz', 'seed-4', 'seed-5'].forEach(function (seed) {
      const plan = scenarios.plan('random', { seed: seed, userCount: 6 });
      assert.ok(plan.phases.length >= 2,
          'Seed "' + seed + '" composed ' + plan.phases.length + ' phase(s). ' +
          'A one-phase random scenario is just that scenario under another ' +
          'name.');
      assert.ok(plan.steps.length > 0,
          'Seed "' + seed + '" composed no steps at all.');
    });
  });
  log.debug("Leaving everyScenarioPlans().");
}

function collectRefs(value) {
  // Hot: walks every node of every body in a plan.
  if (scenarios.isRef(value)) {
    return [value.ref];
  }
  if (Array.isArray(value)) {
    return value.reduce(function (all, item) {
      return all.concat(collectRefs(item));
    }, []);
  }
  if (value !== null && typeof value === 'object') {
    return Object.keys(value).reduce(function (all, name) {
      return all.concat(collectRefs(value[name]));
    }, []);
  }
  return [];
}

function referencesResolveAndJudgeIsHonest() {
  log.debug("Entering referencesResolveAndJudgeIsHonest().");
  log.info("6b. References and judgement.");
  check('a reference resolves from what an earlier step captured',
      function () {
    const captured = { create: { id: 'uid=a,ou=users' } };
    assert.strictEqual(
        scenarios.resolve(scenarios.ref('create', 'id'), captured),
        'uid=a,ou=users');
    const nested = scenarios.resolve(
        { members: [{ value: scenarios.ref('create', 'id') }] }, captured);
    assert.strictEqual(nested.members[0].value, 'uid=a,ou=users',
        'A reference nested inside a body was not substituted, so the ' +
        'group would be created with a literal reference object as a member.');
  });
  check('an unresolvable reference is DIAGNOSED and not sent', function () {
    const step = scenarios.step({ id: 's', operation: 'readUser',
        resourceId: scenarios.ref('never-ran', 'id'), expect: {} });
    const prepared = scenarios.prepare(step, {});
    assert.strictEqual(prepared.skipped, true,
        'A step whose reference cannot resolve was prepared for sending. ' +
        'That composes a request to /Users/undefined, which a server ' +
        'answers 404 and a reader reads as a deleted user.');
    assert.ok(prepared.reason.indexOf('never-ran') >= 0,
        'The skip reason does not name the step that did not run.');
  });
  check('a string placeholder is substituted from a reference', function () {
    const step = scenarios.step({ id: 's', operation: 'modifyGroup',
        resourceId: 'g',
        body: { path: 'members[value eq "MEMBER_ID"]' }, expect: {} });
    step.substitute = { MEMBER_ID: scenarios.ref('user-0', 'id') };
    const prepared = scenarios.prepare(step,
        { 'user-0': { id: 'uid=a,ou=users' } });
    assert.strictEqual(prepared.skipped, false);
    assert.strictEqual(prepared.body.path,
        'members[value eq "uid=a,ou=users"]',
        'A reference cannot be a FRAGMENT of a string, which is why those ' +
        'steps carry a placeholder map. An unsubstituted SHOUTED ' +
        'placeholder is visible in the request; a silently-empty one is not.');
  });
  check('judge() passes a step that got what the plan expected', function () {
    const step = scenarios.step({ id: 's', operation: 'createUser',
        expect: { status: '201' } });
    assert.ok(scenarios.judge(step, { status: 201, body: {}, headers: {} }).ok);
  });
  check('judge() calls a REFUSAL a pass where one was expected', function () {
    const step = scenarios.step({ id: 's', operation: 'createUser',
        expect: { status: '409', scimType: 'uniqueness' } });
    const verdict = scenarios.judge(step,
        { status: 409, scimType: 'uniqueness', body: {}, headers: {} });
    assert.ok(verdict.ok,
        'A 409 on a duplicate userName is what the negatives scenario ' +
        'EXPECTS. A runner that recorded what came back rather than judging ' +
        'it against the plan would show this as a failure — and would show ' +
        'a 201 on a duplicate as a success, which is exactly backwards.');
    const wrong = scenarios.judge(step,
        { status: 201, body: {}, headers: {} });
    assert.strictEqual(wrong.ok, false,
        'The server ALLOWED a duplicate userName and the step passed. That ' +
        'is the failure this whole arrangement exists to catch.');
  });
  check('judge() fails on the right status with the wrong scimType',
      function () {
    const step = scenarios.step({ id: 's', operation: 'createUser',
        expect: { status: '400', scimType: 'invalidPath' } });
    const verdict = scenarios.judge(step,
        { status: 400, scimType: 'invalidFilter', body: {}, headers: {} });
    assert.strictEqual(verdict.ok, false,
        'invalidPath and invalidFilter are different grammars that look ' +
        'alike, and a step that accepted either would not be testing which ' +
        'one the server used.');
    assert.ok(verdict.why.indexOf('invalidFilter') >= 0);
  });
  check('a 2xx wildcard matches any success and nothing else', function () {
    assert.ok(scenarios.statusMatches(['2xx'], 200));
    assert.ok(scenarios.statusMatches(['2xx'], 204));
    assert.strictEqual(scenarios.statusMatches(['2xx'], 404), false);
    assert.ok(scenarios.statusMatches(['200', '204'], 204));
  });
  check('no answer at all is not a status', function () {
    const step = scenarios.step({ id: 's', operation: 'readUser',
        expect: { status: '404' } });
    const verdict = scenarios.judge(step,
        { transportError: 'Failed to fetch' });
    assert.strictEqual(verdict.ok, false,
        'A request that never left was judged against a status. "The server ' +
        'said 404" and "nothing came back" are the two states people most ' +
        'often confuse, and one of them is not a SCIM result at all.');
    assert.ok(verdict.why.indexOf('not a SCIM result') >= 0);
  });
  check('the body checks really check', function () {
    assert.ok(scenarios.runCheck('hasId', { body: { id: 'x' } }) === '');
    assert.ok(scenarios.runCheck('hasId', { body: {} }).length > 0);
    assert.ok(scenarios.runCheck('hasLocation',
        { headers: { Location: 'https://h/Users/x' } }) === '');
    assert.ok(scenarios.runCheck('hasLocation', { headers: {} }).length > 0);
    assert.ok(scenarios.runCheck('bulkAllSucceeded',
        { body: { Operations: [{ status: '201' }] } }) === '');
    assert.ok(scenarios.runCheck('bulkAllSucceeded',
        { body: { Operations: [{ status: '409' }] } }).length > 0,
        'A bulk with a refused operation inside it passed a check meant to ' +
        'read inside the envelope.');
    assert.ok(scenarios.runCheck('bulkAllSucceeded',
        { body: { Operations: [] } }).length > 0,
        'An EMPTY BulkResponse passed "all succeeded", which is the silent ' +
        'pass this project keeps rediscovering.');
  });
  check('an unknown check name is a scenario defect and says so', function () {
    const why = scenarios.runCheck('noSuchCheck', { body: {} });
    assert.ok(why.indexOf('does not exist') >= 0,
        'A misspelled check name silently passed. That is a check that will ' +
        'never run, reported as green.');
  });
  log.debug("Leaving referencesResolveAndJudgeIsHonest().");
}

// ---------------------------------------------------------------------------
// 7. THE api PROXY'S REFUSALS.
//
// Every one of them, with no server on the other end — which is the point: a
// rule that stopped being enforced fails a test naming the rule rather than
// timing out against a host.
// ---------------------------------------------------------------------------
function theProxyRefusesWhatItShould() {
  log.debug("Entering theProxyRefusesWhatItShould().");
  log.info("7. The api proxy.");
  const config = { maxContentLength: 1048576, callTimeout: 10000 };
  check('a relative URL is refused', function () {
    const decided = scimProxy.describeRequest({ url: '/Users' }, config);
    assert.strictEqual(decided.ok, false);
    assert.ok(decided.error.indexOf('absolute') >= 0,
        'Resolving a relative URL against this service\'s own address would ' +
        'make the endpoint a way to reach the api\'s own routes.');
  });
  check('a non-http scheme is refused', function () {
    ['file:///etc/passwd', 'gopher://h/x', 'ftp://h/x'].forEach(function (url) {
      assert.strictEqual(
          scimProxy.describeRequest({ url: url }, config).ok, false,
          url + ' was accepted.');
    });
  });
  check('only RFC 7644\'s five methods are forwarded', function () {
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].forEach(function (method) {
      assert.strictEqual(scimProxy.describeRequest(
          { url: 'https://h/scim/v2/Users', method: method,
            body: method === 'GET' || method === 'DELETE' ? null : {} },
          config).ok, true, method + ' was refused.');
    });
    ['TRACE', 'OPTIONS', 'HEAD', 'CONNECT', 'PROPFIND'].forEach(
      function (method) {
        assert.strictEqual(scimProxy.describeRequest(
            { url: 'https://h/x', method: method }, config).ok, false,
            method + ' was forwarded. Forwarding an arbitrary method makes ' +
            'this endpoint useful for something other than SCIM.');
      });
  });
  check('the framing and hop-by-hop headers are refused', function () {
    ['Host', 'Content-Length', 'Transfer-Encoding', 'Connection',
     'Keep-Alive', 'Upgrade', 'TE', 'Trailer', 'Proxy-Authorization']
      .forEach(function (name) {
        const headers = {};
        headers[name] = 'x';
        const decided = scimProxy.describeRequest(
            { url: 'https://h/x', headers: headers }, config);
        assert.strictEqual(decided.ok, false,
            'The ' + name + ' header was forwarded. These are refused ' +
            'because they change the SHAPE of the request rather than its ' +
            'content — Host redirects it to another virtual host, and the ' +
            'framing pair is request smuggling.');
        assert.ok(decided.error.indexOf(name) >= 0,
            'The refusal does not name the header.');
      });
  });
  check('the header names are matched case-insensitively', function () {
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x', headers: { 'HoSt': 'evil' } }, config).ok, false,
        'A refused header slipped through in different case, which is the ' +
        'whole of the bypass.');
  });
  check('CR or LF in a header value is refused', function () {
    ['a\r\nX-Injected: 1', 'a\nb', 'a\rb'].forEach(function (value) {
      const decided = scimProxy.describeRequest(
          { url: 'https://h/x', headers: { 'X-Tenant': value } }, config);
      assert.strictEqual(decided.ok, false,
          'A header value carrying CR/LF was forwarded. That is header ' +
          'injection rather than a header value.');
    });
  });
  check('a header name that is not a token is refused', function () {
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x', headers: { 'X Tenant': 'a' } }, config).ok,
        false);
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x', headers: { 'X:Tenant': 'a' } }, config).ok,
        false);
  });
  check('an ordinary vendor header IS forwarded', function () {
    const decided = scimProxy.describeRequest({ url: 'https://h/x',
        headers: { 'X-Tenant-Id': 'acme', Authorization: 'Bearer t',
                   'If-Match': 'W/"1"', DPoP: 'proof' } }, config);
    assert.strictEqual(decided.ok, true,
        'An allowlist would have been shorter to write and would have made ' +
        'this endpoint useless against the third server somebody pointed it ' +
        'at.');
    assert.strictEqual(decided.headers['X-Tenant-Id'], 'acme');
    assert.strictEqual(decided.headers.Authorization, 'Bearer t');
    assert.strictEqual(decided.headers.DPoP, 'proof');
  });
  check('a body on a GET or a DELETE is refused rather than dropped',
      function () {
    ['GET', 'DELETE'].forEach(function (method) {
      const decided = scimProxy.describeRequest(
          { url: 'https://h/x', method: method, body: { a: 1 } }, config);
      assert.strictEqual(decided.ok, false,
          'A body on a ' + method + ' was silently dropped. A proxy that ' +
          'discards a body makes the wrong method invisible.');
    });
  });
  check('the SCIM media type is DEFAULTED and not FORCED', function () {
    const defaulted = scimProxy.describeRequest({ url: 'https://h/x',
        method: 'POST', body: {} }, config);
    assert.strictEqual(defaulted.headers['Content-Type'],
        'application/scim+json');
    const chosen = scimProxy.describeRequest({ url: 'https://h/x',
        method: 'POST', body: {},
        headers: { 'Content-Type': 'application/json' } }, config);
    assert.strictEqual(chosen.headers['Content-Type'], 'application/json',
        'A debugger has to be able to send application/json on purpose to ' +
        'find out whether a server insists on the SCIM media type. Forcing ' +
        'the right one makes that question unaskable.');
  });
  check('a body past the cap is refused with the number in the message',
      function () {
    const decided = scimProxy.describeRequest({ url: 'https://h/x',
        method: 'POST', body: { pad: 'x'.repeat(200) } },
        { scimMaxRequestBytes: 100 });
    assert.strictEqual(decided.ok, false);
    assert.ok(decided.error.indexOf('100') >= 0);
  });
  check('TLS validation defaults ON and only an explicit false turns it off',
      function () {
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x' }, config).sslValidate, true);
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x', sslValidate: 'no' }, config).sslValidate, true,
        'A misspelled opt-out turned certificate validation off.');
    assert.strictEqual(scimProxy.describeRequest(
        { url: 'https://h/x', sslValidate: false }, config).sslValidate,
        false);
  });
  check('a SCIM error from the far end is read as an ANSWER', function () {
    const answer = scimProxy.readResponse(409, {}, JSON.stringify({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '409', scimType: 'uniqueness', detail: 'taken' }));
    assert.strictEqual(answer.status, 409);
    assert.strictEqual(answer.ok, false);
    assert.strictEqual(answer.scimType, 'uniqueness',
        'The scimType is the single most useful thing in a SCIM error and ' +
        'it must survive the proxy.');
  });
  check('a non-JSON error body is named as something in FRONT of the server',
      function () {
    const answer = scimProxy.readResponse(502, {},
        '<html><body>Bad Gateway</body></html>');
    assert.ok(answer.detail.indexOf('did not come from a SCIM server') >= 0,
        'An HTML error page from a load balancer is a very common thing to ' +
        'meet, and the fix is in a different place entirely — saying so is ' +
        'more useful than reporting a parse failure.');
  });
  check('the published limits describe the status rule', function () {
    const limits = scimProxy.limits(config);
    assert.deepStrictEqual(limits.methods,
        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
    assert.ok(limits.refusedHeaders.indexOf('host') >= 0);
    assert.ok(limits.statusRule.indexOf('502') >= 0 &&
        limits.statusRule.indexOf('400') >= 0,
        'The page says what the api will do BEFORE a call fails, so a ' +
        'refusal is a sentence rather than a surprise.');
  });
  log.debug("Leaving theProxyRefusesWhatItShould().");
}

function test() {
  log.debug("Entering test().");
  theCatalogueCoversRfc7644();
  theIdIsEncodedExactlyOnce();
  theGeneratorEmitsEveryOptionalAttribute();
  theSeedIsReproducible();
  theMessageBodiesAreRfcShaped();
  everySchemeInSection2IsSupported();
  theHobaBlobIsLengthPrefixed();
  digestMatchesTheServersArithmetic();
  theChallengeParserHandlesSeveralSchemes();
  theFiveShapesAreToldApart();
  everyScenarioPlans();
  referencesResolveAndJudgeIsHonest();
  theProxyRefusesWhatItShould();
  // A count, and it is asserted rather than only printed: this file needs no
  // server and no browser, so there is no legitimate reason for it to run
  // fewer checks than it has. A sudden drop means a section stopped being
  // called, which is the way a suite quietly stops testing something.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 120,
      'Only ' + checks + ' checks ran and this file defines well over a ' +
      'hundred. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("scim_engine")
  .description("Drive the SCIM workflow's engines in node with no server and " +
      "no browser: the endpoint catalogue against RFC 7644, the generator " +
      "against every optional attribute RFC 7643 defines, the Digest and " +
      "HOBA credentials against the arithmetic the mock STS uses, the " +
      "scenario planner and its judgements, and every refusal the api's " +
      "SCIM proxy can produce.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
