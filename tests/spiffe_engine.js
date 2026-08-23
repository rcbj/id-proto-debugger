// File: spiffe_engine.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE WORKFLOW'S ENGINES, DRIVEN IN NODE WITH NO SERVER AND NO BROWSER.
//
// `common/spiffe/spiffe_id.js` is the ID grammar,
// `common/spiffe/spiffe_bundle.js`
// reads a trust bundle document, `api/spiffe_client.js` decides what will and
// will not be dialled and derives the method catalogue from the vendored
// protos, and `client/src/x509.js` builds the PKCS#10 request that five of the
// forty-nine methods take. None of the four needs a network, which is what this
// file exists to take advantage of.
//
// **WHY THIS IS SEPARATE FROM `spiffe_protocol.js` AND `spiffe_page.js`.**
// Those
// two need a mock STS and a browser respectively, so a failure in either can be
// three things: this client is wrong, that server is wrong, or the two are fine
// and something in between is not. Here there is nothing in between. A failure
// in this file names a rule.
//
// SIX SECTIONS, and three of them are the kind of check that only works from
// outside the code they check:
//
//  1. THE GRAMMAR, against the specification's own rules, written out here
//     independently. A table derived from the module under test would agree
//     with it by construction.
//  2. THE BUNDLE READER, against documents that are wrong in one way each —
//     including the one that matters, a JWK with no `use`, which makes a bundle
//     verify NOTHING while reporting no error anywhere.
//  3. THE CATALOGUE AGAINST THE PROTOS, both ways round. The method list is
//     DERIVED from the vendored `.proto` files, so this asserts the count the
//     specifications give (7 + 42) and that every derived method carries a
//     note and every note names a derived method. Without the second half a
//     note could name a method that no longer exists and nothing would say so.
//  4. THE VENDORED PROTOS AGAINST THE MOCK'S COPIES, byte for byte. The whole
//     reason `@grpc/grpc-js` is a dependency is that the wire matches what a
//     real client expects, and a local edit to one of these files would give
//     that up silently — the debugger would go on agreeing with the mock and
//     interoperate with nothing.
//  5. THE ADDRESS AND SOCKET RULES, every refusal, by the code it produces
//     rather than by "it was refused". The four checks that bound a Unix
//     socket path each catch most of what the others catch, so a test that
//     only asserted THAT a path was refused would stay green with three of
//     them removed.
//  6. THE CERTIFICATION REQUEST, verified with **OPENSSL** rather than by
//     reading back what the same code just wrote. That is the rule
//     tests/pki_x509.js records and the only kind of check that catches an
//     encoding which is wrong and self-consistent — of which the ECDSA
//     non-minimal INTEGER is a real one that produced a request every reader
//     here accepted and OpenSSL refused as a bad signature.
//
// It needs NOTHING — not the api, not the mock, not Chrome — so it is never
// gated and never skipped, and it runs on every target including the static
// ones. OpenSSL is the one exception and section 6 says so when it is absent.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { execFileSync, spawnSync } = require("child_process");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "spiffe_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The modules under test. requireSharedModule() is what makes a module borrowed
// from common/ or client/src resolve its own dependencies — node resolves those
// relative to where the MODULE lives, and `common/` has no node_modules of its
// own at all. See tests/module_paths.js.
const spiffeId = paths.requireSharedModule(
  [__dirname + "/../common/spiffe/spiffe_id.js",
   __dirname + "/spiffe_id.js"], "spiffe_id.js");
const spiffeBundle = paths.requireSharedModule(
  [__dirname + "/../common/spiffe/spiffe_bundle.js",
   __dirname + "/spiffe_bundle.js"], "spiffe_bundle.js");
const spiffeClient = paths.requireSharedModule(
  [__dirname + "/../api/spiffe_client.js",
   __dirname + "/spiffe_client.js"], "spiffe_client.js");
const x509 = paths.requireSharedModule(
  [__dirname + "/../client/src/x509.js", __dirname + "/x509.js"], "x509.js");
const keyMaterial = paths.requireSharedModule(
  [__dirname + "/../client/src/key_material.js",
   __dirname + "/key_material.js"], "key_material.js");

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// A client with the address policy OFF and nothing dialled. Every call here
// either refuses before a socket is opened or never gets that far.
function quietClient(config) {
  log.debug("Entering quietClient().");
  const quiet = { debug() {}, info() {}, warn() {}, error() {} };
  const client = spiffeClient.createSpiffeClient(config || {},
    { enabled: false, blockedRangeFor: function () { return null; } }, quiet);
  log.debug("Leaving quietClient().");
  return client;
}

// The code a refused call produced, or '' if it was not refused. Written as a
// helper because section 5 asserts the CODE on every negative: "it was
// refused" is satisfied by the wrong refusal, which is how a layered check
// stops testing three of its four layers.
async function refusalCode(client, options) {
  log.debug("Entering refusalCode().");
  try {
    await client.call(options);
  } catch (e) {
    log.debug("Leaving refusalCode(). " + e.code);
    return e.code || '';
  }
  log.debug("Leaving refusalCode(). Not refused.");
  return '';
}

// ---------------------------------------------------------------------------
// 1. THE SPIFFE ID GRAMMAR.
//
// Written out here from the specification rather than derived from the module,
// because a table built out of what the module does agrees with it by
// construction and cannot notice a rule that stopped being enforced.
// ---------------------------------------------------------------------------
const GRAMMAR_CASES = [
  // valid
  { id: 'spiffe://example.org/workload', ok: true,
    td: 'example.org', path: '/workload' },
  { id: 'spiffe://example.org', ok: true, td: 'example.org', path: '',
    why: 'a trust-domain-only identifier IS valid and is what keys a ' +
         'bundle map' },
  { id: 'spiffe://ex_ample-1.org/A/b.c-d_e', ok: true,
    td: 'ex_ample-1.org', path: '/A/b.c-d_e',
    why: 'the PATH may carry upper case even though the trust domain may not' },
  { id: 'SPIFFE://example.org/x', ok: true, td: 'example.org', path: '/x',
    why: 'a URI scheme is case-insensitive per RFC 3986' },
  { id: 'spiffe://example.org/spire/server', ok: true, reserved: true,
    td: 'example.org', path: '/spire/server' },
  { id: 'spiffe://example.org/spireman', ok: true, reserved: false,
    td: 'example.org', path: '/spireman',
    why: '/spireman is not under /spire — the reserved test is on SEGMENTS, ' +
         'and a startsWith would get this wrong' },
  // invalid
  { id: 'spiffe://Example.org/x', ok: false, must: /lower-case/,
    why: 'a URL parser lower-cases the host for you, which HIDES this' },
  { id: 'spiffe://example.org:8081/x', ok: false, must: /no port/ },
  { id: 'spiffe://user@example.org/x', ok: false, must: /no userinfo/ },
  { id: 'spiffe://example.org/a//b', ok: false, must: /empty segment/ },
  { id: 'spiffe://example.org/a/', ok: false, must: /empty segment/,
    why: 'a trailing slash is an empty segment' },
  { id: 'spiffe://example.org/./b', ok: false, must: /relative segment/ },
  { id: 'spiffe://example.org/../b', ok: false, must: /relative segment/ },
  { id: 'spiffe://example.org/a%2Fb', ok: false, must: /percent-encoded/ },
  { id: 'spiffe://example.org/a?b=1', ok: false, must: /query/ },
  { id: 'spiffe://example.org/a#f', ok: false, must: /fragment/ },
  { id: 'http://example.org/x', ok: false, must: /begins with/ },
  { id: '', ok: false, must: /required/ },
  { id: 'spiffe://', ok: false, must: /names none/ },
  { id: 'spiffe:///x', ok: false, must: /names none/ },
  { id: 'spiffe://example.org/' + 'a'.repeat(2100), ok: false,
    must: /at most 2048 bytes/ },
  { id: 'spiffe://' + 'd'.repeat(300) + '/x', ok: false,
    must: /at most 255 bytes/ }
];

function testGrammar() {
  log.debug("Entering testGrammar().");
  GRAMMAR_CASES.forEach(function (row) {
    check('the grammar on ' + JSON.stringify(row.id.slice(0, 48)) +
          (row.why ? ' — ' + row.why : ''), function () {
      const parsed = spiffeId.parse(row.id);
      assert.strictEqual(parsed.ok, row.ok,
        'expected ok=' + row.ok + ' and got ' + parsed.ok +
        (parsed.reason ? ' (' + parsed.reason + ')' : ''));
      if (row.ok) {
        assert.strictEqual(parsed.trustDomain, row.td);
        assert.strictEqual(parsed.path, row.path);
        if (row.reserved !== undefined) {
          assert.strictEqual(parsed.reserved, row.reserved);
        }
      } else {
        assert.ok(row.must.test(parsed.reason),
          'the reason should have matched ' + row.must + ' and was: ' +
          parsed.reason);
      }
    });
  });

  // MEMBERSHIP, which is the reason the grammar is strict at all. A prefix test
  // says yes to both of these, and each is an authorization bug in anything
  // that federates.
  check('membership is a parsed comparison and never a prefix test',
    function () {
    assert.strictEqual(
      spiffeId.memberOf('spiffe://example.org/x', 'example.org'), true);
    assert.strictEqual(
      spiffeId.memberOf('spiffe://example.org.attacker.test/x', 'example.org'),
      false, 'a suffixed trust domain must not pass for the one it extends');
    assert.strictEqual(
      spiffeId.memberOf('spiffe://example.org@evil.test/x', 'example.org'),
      false, 'userinfo must not make an identifier look like a member');
    assert.strictEqual(
      spiffeId.memberOf('spiffe://example.org/x', 'spiffe://example.org'),
      true, 'the wanted side may be a name or a trust-domain identifier');
  });

  check('the protobuf shape goes both ways and keeps the leading slash',
    function () {
      const message =
        spiffeId.toProto('spiffe://example.org/ns/default/sa/web');
      assert.deepStrictEqual(message,
        { trust_domain: 'example.org', path: '/ns/default/sa/web' },
        'trust_domain is the NAME with no scheme — a trust_domain of ' +
        'spiffe://example.org names a trust domain called that');
      assert.strictEqual(spiffeId.fromProto(message),
        'spiffe://example.org/ns/default/sa/web');
      assert.strictEqual(
        spiffeId.fromProto({ trust_domain: 'example.org', path: 'x' }),
        'spiffe://example.org/x',
        'a path arriving without its leading slash names a different path, ' +
        'so it is supplied');
      assert.strictEqual(spiffeId.fromProto({}), '');
    });

  check('serverId() derives what a SPIRE server is verified against',
    function () {
      assert.strictEqual(spiffeId.serverId('example.org'),
        'spiffe://example.org/spire/server');
      assert.throws(function () {
        spiffeId.serverId('Example.org');
      }, /lower-case/,
      'an upper-case trust domain must not silently produce a server id');
    });

  check('trustDomainId() is a valid SPIFFE ID in its own right', function () {
    const id = spiffeId.trustDomainId('example.org');
    assert.strictEqual(id, 'spiffe://example.org');
    assert.ok(spiffeId.isValid(id),
      'a bare trust domain is what keys a bundle map in both response ' +
      'messages, so it has to parse');
  });
  log.debug("Leaving testGrammar().");
}

// ---------------------------------------------------------------------------
// 2. THE TRUST BUNDLE READER.
// ---------------------------------------------------------------------------
const GOOD_BUNDLE = {
  keys: [
    { kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB', use: 'x509-svid',
      x5c: ['MIIBAAA='] },
    { kty: 'EC', crv: 'P-256', x: 'CC', y: 'DD', use: 'jwt-svid', kid: 'k1' }
  ],
  spiffe_sequence: 3,
  spiffe_refresh_hint: 300
};

function testBundle() {
  log.debug("Entering testBundle().");
  check('a well-formed bundle reads clean, with both uses counted',
    function () {
    const report = spiffeBundle.describe(JSON.stringify(GOOD_BUNDLE));
    assert.strictEqual(report.ok, true, report.errors.join('; '));
    assert.strictEqual(report.sequence, 3);
    assert.strictEqual(report.refreshHint, 300);
    assert.strictEqual(report.counts['x509-svid'], 1);
    assert.strictEqual(report.counts['jwt-svid'], 1);
    assert.strictEqual(report.warnings.length, 0,
      'nothing here should warn: ' + report.warnings.join('; '));
    assert.strictEqual(spiffeBundle.keysFor(report, 'x509-svid').length, 1);
  });

  // THE ONE THAT MATTERS. A consumer MUST IGNORE a JWK with no `use`, so a
  // bundle of them is not slightly imperfect: it verifies nothing, and the
  // failure surfaces as an SVID that will not validate rather than as anything
  // naming the bundle. It is an ERROR here for that reason.
  check('a bundle whose every key lacks `use` is an ERROR, not a warning',
    function () {
      const report = spiffeBundle.describe(JSON.stringify(
        { keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB' }],
          spiffe_sequence: 1 }));
      assert.strictEqual(report.ok, false);
      assert.strictEqual(report.keys.length, 0);
      assert.strictEqual(report.ignored.length, 1);
      assert.ok(/MUST IGNORE/.test(report.ignored[0].reason));
      assert.ok(report.errors.some(function (line) {
        return /verifies nothing/.test(line);
      }), 'the error has to say what the consequence is: ' +
          report.errors.join('; '));
    });

  check('an unrecognised `use` is IGNORED rather than refused', function () {
    const report = spiffeBundle.describe(JSON.stringify({
      keys: [GOOD_BUNDLE.keys[0],
             { kty: 'EC', use: 'wit-svid', kid: 'future' }],
      spiffe_sequence: 1 }));
    assert.strictEqual(report.ignored.length, 1);
    assert.strictEqual(report.ignored[0].use, 'wit-svid');
    assert.ok(/ignores what it does not recognise/
      .test(report.ignored[0].reason),
      'a `use` this build has never heard of is not a defect in somebody ' +
      'else\'s bundle');
    assert.strictEqual(report.ok, true,
      'one usable key is still a usable bundle');
  });

  check('a private member in a published bundle is called out as a disclosure',
    function () {
      const report = spiffeBundle.describe(JSON.stringify({
        keys: [{ kty: 'EC', use: 'jwt-svid', kid: 'k', d: 'secret' }] }));
      assert.ok(report.warnings.some(function (line) {
        return /private member/.test(line) && /compromised/.test(line);
      }), 'a bundle endpoint is fetched by everybody who federates: ' +
          report.warnings.join('; '));
    });

  check('an x509-svid key with no x5c has nothing to build a chain from',
    function () {
      const report = spiffeBundle.describe(JSON.stringify({
        keys: [{ kty: 'EC', use: 'x509-svid', x: 'AA', y: 'BB' }] }));
      assert.ok(report.warnings.some(function (line) {
        return /x5c/.test(line);
      }), report.warnings.join('; '));
      assert.strictEqual(
        spiffeBundle.keysFor(report, 'x509-svid')[0].x5c.length, 0);
    });

  check('x5c is base64 and NOT base64url, and the reader says so', function () {
    const report = spiffeBundle.describe(JSON.stringify({
      keys: [{ kty: 'EC', use: 'x509-svid', x5c: ['MIIB-_AA'] }] }));
    assert.ok(report.warnings.some(function (line) {
      return /base64url/.test(line);
    }), 'that is the opposite of every other member of a JWK and is the ' +
        'mistake to look for first: ' + report.warnings.join('; '));
  });

  check('a jwt-svid key with no kid makes a verifier try every key',
    function () {
      const report = spiffeBundle.describe(JSON.stringify({
        keys: [{ kty: 'EC', use: 'jwt-svid' }] }));
      assert.ok(report.warnings.some(function (line) {
        return /no kid/.test(line);
      }), report.warnings.join('; '));
    });

  check('an HTML error page is named as one rather than as a bad bundle',
    function () {
      const report = spiffeBundle.describe('<html><body>502</body></html>');
      assert.strictEqual(report.ok, false);
      assert.ok(/not JSON/.test(report.errors[0]));
      assert.ok(/proxy/.test(report.errors[0]),
        'that is the usual thing to find here instead: ' + report.errors[0]);
    });

  check('a document with no keys member is refused by name', function () {
    const report = spiffeBundle.describe('{}');
    assert.strictEqual(report.ok, false);
    assert.ok(/keys member/.test(report.errors[0]));
  });

  check('a missing spiffe_sequence warns rather than failing', function () {
    const report = spiffeBundle.describe(JSON.stringify(
      { keys: GOOD_BUNDLE.keys }));
    assert.strictEqual(report.ok, true);
    assert.ok(report.warnings.some(function (line) {
      return /spiffe_sequence/.test(line);
    }), 'a consumer holding a cached copy cannot order two without it');
  });

  check('spiffe_refresh_hint of 0 is called out for what it asks for',
    function () {
      const report = spiffeBundle.describe(JSON.stringify(
        { keys: GOOD_BUNDLE.keys, spiffe_sequence: 1,
          spiffe_refresh_hint: 0 }));
      assert.ok(report.warnings.some(function (line) {
        return /as often as it can/.test(line);
      }), 'it reads as "do not cache" and means the opposite: ' +
          report.warnings.join('; '));
    });

  check('a negative spiffe_sequence is an error', function () {
    const report = spiffeBundle.describe(JSON.stringify(
      { keys: GOOD_BUNDLE.keys, spiffe_sequence: -1 }));
    assert.strictEqual(report.ok, false);
  });
  log.debug("Leaving testBundle().");
}

// ---------------------------------------------------------------------------
// 3. THE CATALOGUE, AGAINST THE SPECIFICATIONS' OWN COUNTS AND AGAINST ITSELF.
// ---------------------------------------------------------------------------

// Written out from the `.proto` files' own service definitions, independently
// of the catalogue under test — the same rule scim_engine.js follows about RFC
// 7644's endpoint list.
const EXPECTED = {
  workload: ['FetchX509SVID', 'FetchX509Bundles', 'FetchJWTSVID',
             'FetchJWTBundles', 'ValidateJWTSVID', 'FetchWITSVID',
             'FetchWITBundles'],
  entry: ['CountEntries', 'ListEntries', 'GetEntry', 'BatchCreateEntry',
          'BatchUpdateEntry', 'BatchDeleteEntry', 'GetAuthorizedEntries',
          'SyncAuthorizedEntries'],
  agent: ['CountAgents', 'ListAgents', 'GetAgent', 'DeleteAgent', 'BanAgent',
          'AttestAgent', 'RenewAgent', 'CreateJoinToken', 'PostStatus'],
  bundle: ['CountBundles', 'GetBundle', 'AppendBundle', 'PublishJWTAuthority',
           'PublishWITAuthority', 'ListFederatedBundles',
           'GetFederatedBundle', 'BatchCreateFederatedBundle',
           'BatchUpdateFederatedBundle', 'BatchSetFederatedBundle',
           'BatchDeleteFederatedBundle'],
  svid: ['MintX509SVID', 'MintJWTSVID', 'MintWITSVID', 'BatchNewX509SVID',
         'NewJWTSVID', 'BatchNewWITSVID', 'NewDownstreamX509CA'],
  trustdomain: ['ListFederationRelationships', 'GetFederationRelationship',
                'BatchCreateFederationRelationship',
                'BatchUpdateFederationRelationship',
                'BatchDeleteFederationRelationship', 'RefreshBundle'],
  debug: ['GetInfo']
};

// The methods that are STREAMS, which is the property the api has to get right
// or a rotation is invisible and a bidirectional call answers with nothing.
const STREAMING = {
  'workload.FetchX509SVID': { req: false, res: true },
  'workload.FetchX509Bundles': { req: false, res: true },
  'workload.FetchJWTBundles': { req: false, res: true },
  'workload.FetchWITSVID': { req: false, res: true },
  'workload.FetchWITBundles': { req: false, res: true },
  'entry.SyncAuthorizedEntries': { req: true, res: true },
  'agent.AttestAgent': { req: true, res: true }
};

function flatten(catalogue) {
  log.debug("Entering flatten().");
  const rows = [];
  ['workload', 'server'].forEach(function (surface) {
    (catalogue[surface] || []).forEach(function (group) {
      group.methods.forEach(function (method) {
        rows.push(method);
      });
    });
  });
  log.debug("Leaving flatten(). " + rows.length);
  return rows;
}

function testCatalogue() {
  log.debug("Entering testCatalogue().");
  const catalogue = quietClient().catalogue();
  const rows = flatten(catalogue);

  check('the catalogue is 49 methods: 7 on the Workload API and 42 across ' +
        'the SPIRE Server API\'s six services', function () {
    const wanted = Object.keys(EXPECTED).reduce(function (n, service) {
      return n + EXPECTED[service].length;
    }, 0);
    assert.strictEqual(wanted, 49, 'the expectation itself must add to 49');
    assert.strictEqual(rows.length, 49,
      'the catalogue is DERIVED from the vendored protos, so a different ' +
      'number here means a proto changed rather than a list going stale');
  });

  Object.keys(EXPECTED).forEach(function (service) {
    check('the ' + service + ' service has exactly its ' +
          EXPECTED[service].length + ' methods', function () {
      const got = rows.filter(function (row) {
        return row.service === service;
      }).map(function (row) {
        return row.name;
      }).sort();
      assert.deepStrictEqual(got, EXPECTED[service].slice().sort());
    });
  });

  // BOTH WAYS ROUND. Without the second half a note could name a method that
  // no longer exists and nothing would ever say so.
  check('every derived method carries a note', function () {
    const undescribed = rows.filter(function (row) {
      return !row.described || !row.what;
    }).map(function (row) {
      return row.service + '.' + row.name;
    });
    assert.deepStrictEqual(undescribed, [],
      'these methods are on a surface and undescribed, so the page would ' +
      'offer them with no explanation');
  });

  check('every note names a method that exists', function () {
    const live = {};
    rows.forEach(function (row) {
      live[row.service + '.' + row.name] = true;
    });
    const orphans = Object.keys(spiffeClient.METHOD_NOTES)
      .filter(function (key) {
        return !live[key];
      });
    assert.deepStrictEqual(orphans, [],
      'these notes name methods the protos no longer have');
  });

  check('the seven streaming methods are reported as streams, and the two ' +
        'bidirectional ones as both', function () {
    rows.forEach(function (row) {
      const key = row.service + '.' + row.name;
      const wanted = STREAMING[key] || { req: false, res: false };
      assert.strictEqual(row.requestStream, wanted.req,
        key + ' requestStream');
      assert.strictEqual(row.responseStream, wanted.res,
        key + ' responseStream');
    });
  });

  check('every method path is the fully-qualified gRPC one', function () {
    rows.forEach(function (row) {
      assert.ok(/^\/[A-Za-z0-9_.]+\/[A-Za-z0-9_]+$/.test(row.path),
        row.name + ' has path ' + row.path);
      assert.ok(row.path.endsWith('/' + row.name),
        row.path + ' should end with the method name as the .proto writes ' +
        'it — grpc-js lowers the first letter of its own accessor, and a ' +
        'lookup that silently missed would produce a client that answers ' +
        'Unimplemented to everything');
    });
  });

  // THE WELL-KNOWN-TYPE TABLES. Both are typed out in api/spiffe_client.js
  // rather than derived, for the reason stated there — so this is what keeps
  // them honest, by walking the descriptors the protos actually produced.
  check('every google.protobuf wrapper field in the protos is in ' +
        'WRAPPED_FIELDS, and every Struct field is in STRUCT_FIELDS',
    function () {
      const found = walkProtosForWellKnown();
      const wrapped = [];
      Object.keys(spiffeClient.WRAPPED_FIELDS).forEach(function (key) {
        spiffeClient.WRAPPED_FIELDS[key].forEach(function (dotted) {
          wrapped.push(dotted.split('.').pop());
        });
      });
      found.wrappers.forEach(function (name) {
        assert.ok(wrapped.indexOf(name) !== -1,
          'the field ' + name + ' is a google.protobuf wrapper on the wire, ' +
          'so a bare value sent for it serialises to NOTHING with no throw ' +
          'and no warning — add it to WRAPPED_FIELDS');
      });
      const structs = [];
      Object.keys(spiffeClient.STRUCT_FIELDS).forEach(function (key) {
        spiffeClient.STRUCT_FIELDS[key].forEach(function (name) {
          structs.push(name);
        });
      });
      found.structs.forEach(function (name) {
        assert.ok(structs.indexOf(name) !== -1,
          'the field ' + name + ' is a google.protobuf.Struct, whose members ' +
          'are camelCase in a family that is otherwise snake_case — add it ' +
          'to STRUCT_FIELDS');
      });
      assert.ok(found.wrappers.length > 0 && found.structs.length > 0,
        'this check found no wrapper and no Struct field at all, which means ' +
        'it is reading the protos wrongly and asserting nothing');
    });
  log.debug("Leaving testCatalogue().");
}

// Read the vendored .proto TEXT for wrapper and Struct fields. The text rather
// than the loaded descriptors, deliberately: proto-loader reports a field's
// type name RELATIVELY (`Filter`, `types.EntryMask`), so resolving one means
// implementing protobuf's own name resolution — and a check that needed that
// would be a second place to be wrong about the thing it is checking.
function walkProtosForWellKnown() {
  log.debug("Entering walkProtosForWellKnown().");
  const root = protoDir();
  const wrappers = [];
  const structs = [];
  listProtos(root).forEach(function (file) {
    fs.readFileSync(file, 'utf8').split('\n').forEach(function (line) {
      // One line for the reason api/spiffe_client.js gives about its own:
      // breaking a regular expression means building it out of strings, which
      // is a second place for it to be wrong.
      let m = /google\.protobuf\.(StringValue|BoolValue|Int32Value|Int64Value|UInt32Value|UInt64Value|FloatValue|DoubleValue|BytesValue)\s+([a-z0-9_]+)\s*=/
        .exec(line);
      if (m) wrappers.push(m[2]);
      m = /google\.protobuf\.Struct\s+([a-z0-9_]+)\s*=/.exec(line);
      if (m) structs.push(m[1]);
    });
  });
  log.debug("Leaving walkProtosForWellKnown(). " + wrappers.length + '/' +
            structs.length);
  return { wrappers: wrappers, structs: structs };
}

function protoDir() {
  log.debug("Entering protoDir().");
  const candidates = [path.join(__dirname, '..', 'api', 'protos'),
                      path.join(__dirname, 'protos')];
  for (const one of candidates) {
    if (fs.existsSync(one)) {
      log.debug("Leaving protoDir(). " + one);
      return one;
    }
  }
  throw new Error('could not find the vendored protos (looked in: ' +
                  candidates.join(', ') + ')');
}

function listProtos(dir) {
  log.debug("Entering listProtos().");
  const out = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      listProtos(full).forEach(function (one) {
        out.push(one);
      });
      return;
    }
    if (entry.name.endsWith('.proto')) out.push(full);
  });
  log.debug("Leaving listProtos(). " + out.length);
  return out;
}

// ---------------------------------------------------------------------------
// 4. THE VENDORED PROTOS AGAINST THE MOCK STS'S COPIES.
//
// The whole reason `@grpc/grpc-js` is a dependency here is that the wire
// matches what a REAL client and a REAL SPIRE server expect. A local edit to
// one of these files would give that up silently: the debugger would go on
// agreeing with the mock and interoperate with nothing. This is
// tests/krb5_codec_sync.js's argument about a vendored codec, applied to the
// one other place in this tree where the same bytes are described twice.
// ---------------------------------------------------------------------------
function testProtoSync() {
  log.debug("Entering testProtoSync().");
  const mine = protoDir();
  // Located via the mock's own `spiffe_grpc.js` rather than by naming
  // `spiffe/protos` here, for the reason module_paths.js gives about searching
  // for a module by NAME: the mock moved every module into folders on
  // 2026-08-23 and a path written down in this repository would have broken.
  // `protos` is in that searcher's skip list — it looks for JS — so the
  // directory is derived from the module that reads it, which is the file that
  // would have to move with it.
  const grpcModule = paths.mockStsModule('spiffe_grpc.js', function (say) {
    log.warn(say);
  });
  const theirsRoot = grpcModule
    ? path.join(path.dirname(grpcModule), 'protos', 'workloadapi.proto')
    : null;
  if (!theirsRoot || !fs.existsSync(theirsRoot)) {
    // Skipped rather than passed, and it says why. The mock STS is a submodule
    // and an uninitialised one is an empty directory.
    log.warn('SKIPPING the proto comparison: the mock STS checkout does not ' +
             'carry workloadapi.proto. Run `git submodule update --init ' +
             '--recursive` — an uninitialised submodule is an EMPTY ' +
             'DIRECTORY, so nothing here fails, it simply stops checking.');
    log.debug("Leaving testProtoSync(). Skipped.");
    return;
  }
  const theirs = path.dirname(theirsRoot);
  const files = listProtos(mine).map(function (one) {
    return path.relative(mine, one);
  }).sort();
  check('the vendored protos are the same 21 files the mock STS carries',
    function () {
      const others = listProtos(theirs).map(function (one) {
        return path.relative(theirs, one);
      }).sort();
      assert.deepStrictEqual(files, others,
        'the two copies must hold the same set of .proto files');
    });
  files.forEach(function (relative) {
    check('api/protos/' + relative + ' is byte-identical to the mock\'s',
      function () {
        const a = fs.readFileSync(path.join(mine, relative));
        const b = fs.readFileSync(path.join(theirs, relative));
        assert.ok(a.equals(b),
          relative + ' differs between api/protos and the mock STS. These ' +
          'are the SPIFFE project\'s and the spire-api-sdk\'s own files and ' +
          'are vendored VERBATIM on both sides; an edit to either makes this ' +
          'debugger agree with this mock and interoperate with nothing.');
      });
  });
  log.debug("Leaving testProtoSync().");
}

// ---------------------------------------------------------------------------
// 5. WHAT WILL AND WILL NOT BE DIALLED.
//
// Every negative asserts the CODE, not merely that something was refused. The
// four checks bounding a Unix socket path each catch most of what the others
// catch, so "it was refused" stays satisfied with three of them removed — the
// same false negative tests/api_krb5_relay.js records about its layered
// pre-flight.
// ---------------------------------------------------------------------------
const ADDRESS_CASES = [
  { address: 'sts:8181', ok: true, kind: 'tcp', host: 'sts', port: 8181 },
  { address: 'tcp://sts:8181', ok: true, kind: 'tcp', host: 'sts', port: 8181 },
  { address: '[::1]:8181', ok: true, kind: 'tcp', host: '::1', port: 8181,
    why: 'an IPv6 literal is in brackets and the colon inside is not the ' +
         'port separator' },
  { address: 'unix:///tmp/spire-agent/public/api.sock', ok: true,
    kind: 'unix', socketPath: '/tmp/spire-agent/public/api.sock' },
  { address: 'unix:/tmp/spire-agent/public/api.sock', ok: true, kind: 'unix',
    socketPath: '/tmp/spire-agent/public/api.sock',
    why: 'grpc\'s own one-slash spelling, which SPIFFE_ENDPOINT_SOCKET ' +
         'usually carries' },
  { address: 'htp://sts:8181', ok: false, must: /scheme/ },
  { address: 'https://sts:8181', ok: false, must: /scheme/,
    why: 'grpc-js treats an unknown scheme as a DNS name, so this would be ' +
         'dialled as a host called https' },
  { address: 'sts', ok: false, must: /no port/,
    why: 'gRPC has no default port and guessing one dials something nobody ' +
         'asked for' },
  { address: 'sts:0', ok: false, must: /1 to 65535/ },
  { address: 'sts:70000', ok: false, must: /1 to 65535/ },
  { address: '::1:8181', ok: false, must: /brackets/ },
  { address: 'unix:relative/path.sock', ok: false, must: /ABSOLUTE/ },
  { address: '', ok: false, must: /required/ }
];

async function testAddressing() {
  log.debug("Entering testAddressing().");
  ADDRESS_CASES.forEach(function (row) {
    check('the address ' + JSON.stringify(row.address) +
          (row.why ? ' — ' + row.why : ''), function () {
      const parsed = spiffeClient.parseAddress(row.address);
      assert.strictEqual(parsed.ok, row.ok,
        'expected ok=' + row.ok + ', got ' + parsed.ok + ' ' +
        (parsed.reason || ''));
      if (!row.ok) {
        assert.ok(row.must.test(parsed.reason),
          'the reason should have matched ' + row.must + ' and was: ' +
          parsed.reason);
        return;
      }
      assert.strictEqual(parsed.kind, row.kind);
      if (row.kind === 'tcp') {
        assert.strictEqual(parsed.host, row.host);
        assert.strictEqual(parsed.port, row.port);
      } else {
        assert.strictEqual(parsed.socketPath, row.socketPath);
      }
    });
  });

  const client = quietClient();
  const REFUSALS = [
    { what: 'a port outside spiffeAllowedPorts',
      options: { address: '198.51.100.7:22', service: 'debug',
                 method: 'GetInfo' },
      code: 'ESPIFFEPORTNOTALLOWED' },
    { what: 'a service that is not on either surface',
      options: { address: '198.51.100.7:8181', service: 'nope',
                 method: 'GetInfo' },
      code: 'ESPIFFENOSERVICE' },
    { what: 'a method that service does not have',
      options: { address: '198.51.100.7:8181', service: 'debug',
                 method: 'GetEverything' },
      code: 'ESPIFFENOMETHOD' },
    { what: 'a Unix socket outside spiffeAllowedSocketPaths',
      options: { address: 'unix:///etc/passwd', service: 'debug',
                 method: 'GetInfo' },
      code: 'ESPIFFESOCKETNOTALLOWED' },
    { what: 'a Unix socket path past sun_path — refused BY NAME, because the ' +
            'operating system fails a longer one with a message about the ' +
            'address being in use, which names something that is not the ' +
            'problem',
      options: { address: 'unix:///tmp/spire-agent/' + 'x'.repeat(120) +
                          '.sock', service: 'debug', method: 'GetInfo' },
      code: 'ESPIFFESOCKETPATHTOOLONG' },
    { what: 'a Unix socket path that names nothing',
      options: { address: 'unix:///tmp/spire-agent/not-there-at-all.sock',
                 service: 'debug', method: 'GetInfo' },
      code: 'ESPIFFESOCKETMISSING' },
    { what: 'a metadata name that is not a token',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', metadata: { 'not a token': 'x' } },
      code: 'ESPIFFEBADMETADATA' },
    { what: 'a metadata value carrying a line feed',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', metadata: { 'x-thing': 'a\nb' } },
      code: 'ESPIFFEBADMETADATA' },
    { what: 'the reserved grpc- metadata prefix, which is the framing itself',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', metadata: { 'grpc-timeout': '1S' } },
      code: 'ESPIFFEBADMETADATA' },
    { what: 'a server identity mode that is not one of the three',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', serverIdentityMode: 'trust-me' },
      code: 'ESPIFFEBADMODE' },
    { what: 'verifying a server with neither an expected ID nor a trust ' +
            'domain to derive one from',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle' },
      code: 'ESPIFFENOSERVERID' },
    { what: 'an upper-case trust domain, which cannot name a server',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', trustDomain: 'Example.org' },
      code: 'ESPIFFEBADTRUSTDOMAIN' },
    { what: 'verifying a server with no trust bundle to verify it against',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', trustDomain: 'example.org' },
      code: 'ESPIFFENOTRUSTBUNDLE' },
    { what: 'a client certificate with no private key — an X509-SVID without ' +
            'its key proves nothing',
      options: { address: '198.51.100.7:8181', service: 'bundle',
                 method: 'GetBundle', trustDomain: 'example.org',
                 trustBundle: '-----BEGIN CERTIFICATE-----\nAA==\n' +
                              '-----END CERTIFICATE-----\n',
                 identity: { certPem: '-----BEGIN CERTIFICATE-----\nAA==\n' +
                                      '-----END CERTIFICATE-----\n' } },
      code: 'ESPIFFEBADIDENTITY' }
  ];
  for (const row of REFUSALS) {
    const code = await refusalCode(client, row.options);
    check('refused: ' + row.what, function () {
      assert.strictEqual(code, row.code,
        'the refusal must name WHICH check fired — "it was refused" is ' +
        'satisfied by the wrong one, which is how a layered check stops ' +
        'testing most of itself');
    });
  }

  check('spiffeAllowedPorts accepts the word "any", and it is a WORD so that ' +
        'widening it cannot be a plausible typo', function () {
    const wide = quietClient({ spiffeAllowedPorts: 'any' });
    assert.strictEqual(wide.limits().ports, 'any');
    const narrow = quietClient({});
    assert.deepStrictEqual(narrow.limits().ports,
      spiffeClient.DEFAULT_ALLOWED_PORTS);
  });

  check('spiffeAllowedSocketPaths does the same for a filesystem path — the ' +
        'one bound in this service the address policy cannot judge',
    function () {
      const wide = quietClient({ spiffeAllowedSocketPaths: 'any' });
      assert.strictEqual(wide.limits().socketPaths, 'any');
      const narrow = quietClient({});
      assert.deepStrictEqual(narrow.limits().socketPaths,
        spiffeClient.DEFAULT_ALLOWED_SOCKET_PATHS);
    });

  check('a stream gets a LONGER deadline than a unary call, and both are ' +
        'published', function () {
    const limits = quietClient({}).limits();
    assert.ok(limits.streamTimeoutMs > limits.callTimeoutMs,
      'the mock STS re-sends on a Workload API stream at a floor of thirty ' +
      'seconds, so a stream bounded by callTimeout could never observe a ' +
      'rotation — it would always report a timeout after one message, which ' +
      'is indistinguishable from a server that sent one and went quiet');
    assert.ok(limits.streamTimeoutMs >= 35000,
      'anything under the mock\'s thirty-second floor makes rotation ' +
      'unobservable, which is most of what a Workload API stream is for');
  });

  check('the address policy is REUSED from the guard rather than copied',
    function () {
      const quiet = { debug() {}, info() {}, warn() {}, error() {} };
      let asked = null;
      const client2 = spiffeClient.createSpiffeClient({}, {
        enabled: true,
        blockedRangeFor: function (address) {
          asked = address;
          return '127.0.0.0/8';
        } }, quiet);
      return client2.call({ address: '127.0.0.1:8181', service: 'bundle',
        method: 'GetBundle', serverIdentityMode: 'none' })
        .then(function () {
          throw new Error('a blocked address must be refused');
        }, function (error) {
          assert.strictEqual(error.code, 'EBLOCKEDADDRESS');
          assert.strictEqual(asked, '127.0.0.1',
            'the guard\'s own decision must be what was consulted — two ' +
            'implementations of an address policy is one implementation and ' +
            'one hole');
        });
    });
  log.debug("Leaving testAddressing().");
}

// The one above returns a promise from inside check(), which check() does not
// await. Run it separately so a failure cannot be swallowed.
async function testAddressPolicy() {
  log.debug("Entering testAddressPolicy().");
  const quiet = { debug() {}, info() {}, warn() {}, error() {} };
  let asked = null;
  const client = spiffeClient.createSpiffeClient({}, {
    enabled: true,
    blockedRangeFor: function (address) {
      asked = address;
      return '127.0.0.0/8';
    } }, quiet);
  const code = await refusalCode(client, { address: '127.0.0.1:8181',
    service: 'bundle', method: 'GetBundle', serverIdentityMode: 'none' });
  check('a blocked address is refused, and by the GUARD\'s own decision',
    function () {
      assert.strictEqual(code, 'EBLOCKEDADDRESS');
      assert.strictEqual(asked, '127.0.0.1');
    });
  log.debug("Leaving testAddressPolicy().");
}

// ---------------------------------------------------------------------------
// 5b. CONCATENATED DER, AND WHY IT HAS TO BE SPLIT.
//
// `FetchX509SVID` hands the trust bundle back as CONCATENATED DER, and node's
// `ca` option reads a DER buffer as ONE certificate and silently ignores
// everything after it. A trust domain that has rotated — which is every one
// that has been up for a day — publishes two authorities, node keeps the first,
// and an SVID signed by the second is refused with a message about a signature
// and nothing about the bundle.
// ---------------------------------------------------------------------------
function testDerSplitting() {
  log.debug("Entering testDerSplitting().");
  // Three DER SEQUENCEs with the three length forms: short, one-octet long,
  // two-octet long. Not real certificates — the splitter reads lengths and
  // nothing else, which is the property being asserted.
  const short = Buffer.concat([Buffer.from([0x30, 0x03]),
                               Buffer.from([1, 2, 3])]);
  const long1 = Buffer.concat([Buffer.from([0x30, 0x81, 0x80]),
                               Buffer.alloc(0x80, 7)]);
  const long2 = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x00]),
                               Buffer.alloc(0x100, 9)]);

  check('concatenated DER splits into its separate certificates, whatever ' +
        'length form each one used', function () {
    const parts = spiffeClient.splitDerCertificates(
      Buffer.concat([short, long1, long2]));
    assert.strictEqual(parts.length, 3);
    assert.strictEqual(parts[0].length, short.length);
    assert.strictEqual(parts[1].length, long1.length);
    assert.strictEqual(parts[2].length, long2.length);
  });

  check('a truncated trailing certificate stops the walk rather than ' +
        'throwing — a bundle that could not be split whole is still worth ' +
        'the readable part of', function () {
    const parts = spiffeClient.splitDerCertificates(
      Buffer.concat([short, Buffer.from([0x30, 0x40, 1, 2])]));
    assert.strictEqual(parts.length, 1);
  });

  check('bundleToPem() turns concatenated DER into SEPARATE PEM blocks, ' +
        'because node reads concatenated DER as ONE certificate', function () {
    const pem = spiffeClient.bundleToPem(
      Buffer.concat([short, long1]).toString('base64'));
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----/g) || [];
    assert.strictEqual(blocks.length, 2,
      'one block here means an SVID signed by the second authority is ' +
      'refused with a message about a signature and nothing about the bundle');
  });

  check('bundleToPem() passes PEM through and accepts a list of either',
    function () {
      const pem = spiffeClient.bundleToPem(
        ['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
         short.toString('base64')]);
      assert.strictEqual((pem.match(/-----BEGIN CERTIFICATE-----/g) || [])
        .length, 2);
    });

  check('uriNamesOf() reads the URI subjectAltNames node reports as one ' +
        'comma-separated string', function () {
    assert.deepStrictEqual(spiffeClient.uriNamesOf({ subjectaltname:
      'URI:spiffe://example.org/spire/server, DNS:sts, IP Address:127.0.0.1' }),
      ['spiffe://example.org/spire/server']);
    assert.deepStrictEqual(spiffeClient.uriNamesOf({ subjectaltname: 'DNS:x' }),
      [], 'a certificate with no URI SAN carries no SPIFFE ID at all');
    assert.deepStrictEqual(spiffeClient.uriNamesOf({}), []);
  });
  log.debug("Leaving testDerSplitting().");
}

// ---------------------------------------------------------------------------
// 6. THE CERTIFICATION REQUEST, CHECKED WITH OPENSSL.
//
// Five of the forty-nine methods take one, so a CSR this codebase can read back
// and nothing else accepts would make five methods unusable while every test
// here passed. OpenSSL is the second implementation — the rule
// tests/pki_x509.js records, and the one that caught the ECDSA non-minimal
// INTEGER that produced a perfectly readable request refused as a bad
// signature.
// ---------------------------------------------------------------------------
function openSslAvailable() {
  log.debug("Entering openSslAvailable().");
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    log.debug("Leaving openSslAvailable(). Yes.");
    return true;
  } catch (e) {
    log.debug("Leaving openSslAvailable(). No.");
    return false;
  }
}

async function testCsr() {
  log.debug("Entering testCsr().");
  const haveOpenSsl = openSslAvailable();
  if (!haveOpenSsl) {
    // Said out loud rather than passed quietly: without OpenSSL this section
    // checks only that this codebase agrees with itself, which is the one
    // thing it cannot usefully check.
    log.warn('openssl is not on PATH, so the certification requests below ' +
             'are checked only against this codebase\'s own reader. That is ' +
             'exactly the check that cannot catch an encoding which is wrong ' +
             'and self-consistent.');
  }
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'spiffe-csr-'));
  try {
    for (const alg of ['ec-p256', 'ec-p521', 'rsa-2048', 'ed25519']) {
      const pair = await keyMaterial.generateKeyPair(alg);
      const csr = await x509.certificationRequest({
        subject: 'C=US,O=SPIRE',
        publicKeyPem: pair.publicPem,
        privateKeyPem: pair.privatePem,
        subjectAltName: [{ kind: 'uri',
                           value: 'spiffe://example.org/example' }]
      });
      check('a ' + alg + ' certification request is well formed and carries ' +
            'the SPIFFE ID in a URI subjectAltName', function () {
        assert.ok(/^-----BEGIN CERTIFICATE REQUEST-----/.test(csr.pem));
        assert.ok(csr.base64.length > 100);
        assert.ok(!/[^A-Za-z0-9+/=]/.test(csr.base64),
          'a gRPC bytes field takes base64, so this must be base64 with no ' +
          'PEM armour and no whitespace');
      });
      if (!haveOpenSsl) continue;
      const file = path.join(tmp, alg + '.pem');
      fs.writeFileSync(file, csr.pem);
      // BOTH STREAMS. `openssl req -verify` writes its verdict to STDERR and
      // the decoded request to stdout, so reading stdout alone finds no
      // "verify OK" and fails every request this codebase produces — which
      // looks exactly like the encoding defect this check exists to catch.
      const run = spawnSync('openssl',
        ['req', '-in', file, '-noout', '-verify', '-text'],
        { encoding: 'utf8' });
      const text = String(run.stdout || '') + String(run.stderr || '');
      check('OPENSSL verifies the ' + alg + ' request\'s self-signature and ' +
            'reads its URI subjectAltName', function () {
        assert.ok(/verify OK/i.test(text),
          'openssl refused the signature on a ' + alg + ' request. That is ' +
          'the failure mode a reader in this codebase cannot see: the ' +
          'request parses perfectly here and is refused by everybody else. ' +
          'openssl said: ' + text.slice(0, 400));
        assert.ok(/spiffe:\/\/example\.org\/example/.test(text),
          'the URI subjectAltName is the only place a SPIFFE identity can be ' +
          'asked for, and MintX509SVID is the method that reads it');
      });
    }
    check('a certification request with no private key is refused — the ' +
          'signature IS the proof of possession', function () {
      return assert.rejects(function () {
        return x509.certificationRequest({ subject: 'C=US,O=SPIRE',
          publicKeyPem: 'x' });
      });
    });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  log.debug("Leaving testCsr().");
}

async function test() {
  log.debug("Entering test().");
  testGrammar();
  testBundle();
  testCatalogue();
  testProtoSync();
  await testAddressing();
  await testAddressPolicy();
  testDerSplitting();
  await testCsr();

  // A FLOOR ON THE COUNT. Without it a section that stopped being called would
  // leave this file green while checking a fraction of what it names — the
  // recurring failure tests/CLAUDE.md records about a test that quietly does
  // nothing.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 90,
    'Only ' + checks + ' checks ran and this file defines well over ninety. ' +
    'A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("spiffe_engine")
  .description("Drive the SPIFFE workflow's engines in node with no server " +
    "and no browser: the ID grammar against the specification's own rules, " +
    "the trust bundle reader against documents that are wrong in one way " +
    "each, the method catalogue against the vendored protos both ways round, " +
    "those protos against the mock STS's copies byte for byte, every address " +
    "and socket refusal by its code, and the PKCS#10 request five methods " +
    "take — verified with OpenSSL.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
    "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
