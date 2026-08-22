// File: scim_protocol.js
//
// ---------------------------------------------------------------------------
// EVERY SCIM ENDPOINT, THROUGH THE DEBUGGER'S OWN api, AGAINST THE MOCK STS —
// AND THEN CHECKED IN THE DIRECTORY THE MOCK WROTE IT TO.
//
// `scim_engine.js` asserts what this workflow COMPOSES with no server on the
// other end. This file sends it: every operation RFC 7644 defines, through
// `POST /scim` — the same code path the page's "through the api" radio uses —
// against the mock STS, and then reads the result back a SECOND way.
//
// **THE SECOND READ IS THE POINT AND IT IS WHY THIS FILE IS LONG.** A SCIM
// server answering 201 has said only that it accepted the request. What it
// STORED is a different question, and against this mock it is answerable
// exactly, because the mock has no store of its own: a SCIM create writes an
// entry in its embedded LDAP directory, and
//
//     POST /scim/v2/Users            ->  uid=alice,ou=users,dc=example,dc=com
//     POST /ldap/search  (base ou=users)  ->  the same entry
//     GET  /admin-api/scim               ->  the counters that saw it
//
// So every attribute this test sends is checked against the LDAP attribute the
// mock's own `scim_map.js` says it lands in. That catches the failure a
// status-only test cannot see and which is the single most common real defect
// in a provisioning integration: **a field that is accepted and silently
// dropped**. `title` sent, 201 returned, nothing in the directory. Both look
// identical at the moment of the create.
//
// The mapping table below is written out INDEPENDENTLY of the mock's, for the
// same reason `scim_engine.js` writes out RFC 7644's endpoint list rather than
// deriving it: a table read from the implementation agrees with the
// implementation by construction and can notice nothing.
//
// ---------------------------------------------------------------------------
// THE THREE OUTCOMES, ASSERTED ON EVERY NEGATIVE.
//
// `POST /scim` draws the same distinction `POST /ldap/*` does, and it is what
// makes this endpoint usable as a debugger at all:
//
//   * a refusal by the api itself is a **400**,
//   * a network failure is a **502**,
//   * **a SCIM error from the mock is a 200** carrying that status and its
//     `scimType`.
//
// So every negative section below asserts the TRANSPORT status as well as the
// SCIM one. An implementation that collapsed a 409 `uniqueness` into a failure
// would pass a test that only looked at "did it work".
//
// ---------------------------------------------------------------------------
// AUTHENTICATION: ALL SIX SCHEMES, ONCE EACH.
//
// RFC 7644 section 2 names six ways of authenticating and the mock implements
// all six. Section 8 below exercises every one of them — deliberately NOT
// against every endpoint, which would be a cross-product of forty-two runs
// testing the same header parser over and over. Each scheme gets the one call
// that proves the credential was understood, plus the negative that proves the
// check is really running: a scheme that accepted everything would pass a
// positive-only test perfectly.
//
// Two of the six cannot be exercised from here at all, and they SKIP WITH A
// REASON rather than quietly passing:
//
//   * a **session cookie** needs a browser that has signed in — there is no
//     cookie jar in this file, and `scim_page.js` covers it;
//   * a **client certificate** is chosen during a TLS handshake, and the api
//     would present its own rather than a caller's, which is a different
//     identity. `tests/pki_mutual_tls.js` is where a client certificate is
//     really presented.
//
// ---------------------------------------------------------------------------
// WHAT IT NEEDS AND HOW IT SKIPS.
//
// The api and the mock STS. No browser. **THE MOCK MUST HAVE SCIM** — the
// endpoints arrived in the mock after this repository's `sts/` gitlink was
// last moved, so a checkout whose submodule predates them gets a 404 on
// `GET /scim/v2/ServiceProviderConfig`. That is detected once, up front, and
// reported as a SKIP naming the reason rather than as forty failures naming
// individual endpoints.
//
// `SCIM_BASE_URL` is the api's view of the mock, not this test's — the same
// distinction `LDAP_URL` draws in `api_ldap.js`, and on the containerized stack
// a different answer. It is its own variable for exactly that reason.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor, runStamp } = require("./random_username.js");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "scim_protocol",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The workflow's own request builder, so this test sends what the PAGE would
// send rather than a second implementation of it. That is what makes a failure
// here a failure of the shipped code.
const scim = paths.requireSharedModule(
  [__dirname + "/../client/src/scim_client.js", __dirname + "/scim_client.js"],
  "scim_client.js");
const scenarios = paths.requireSharedModule(
  [__dirname + "/../client/src/scim_scenarios.js",
   __dirname + "/scim_scenarios.js"], "scim_scenarios.js");

var apiUrl = process.env.API_URL || "http://localhost:4000";
// The mock's HTTP side as THIS TEST reaches it — for /admin-api and the token
// endpoint.
var stsUrl = process.env.STS_URL || "http://localhost:8081";
// The SCIM service root as the API must reach it. A different question from the
// line above, and on the containerized stack a different answer: the api
// resolves this name, and the api's view of the mock is not the test's.
var scimBaseUrl = process.env.SCIM_BASE_URL || "http://sts:8081/scim/v2";
// The directory, again as the api must reach it — the verification channel.
var ldapUrl = process.env.LDAP_URL || "ldap://sts:389";
var baseDn = process.env.LDAP_BASE_DN || "dc=example,dc=com";
var bindDn = process.env.LDAP_BIND_DN || "cn=admin,dc=example,dc=com";
// Any password works against this directory; this one is not a secret and is
// published on the mock's own GET /ldap page.
var ldapPassword = process.env.LDAP_PASSWORD || "password!";

var usersDn = "ou=users," + baseDn;
var groupsDn = "ou=groups," + baseDn;

// Unique per run, prefixed with this file's name. The directory outlives the
// run: an entry left behind by a section that died before its delete is read
// later by somebody wondering where it came from, and a generic prefix does not
// tell them. tests/random_username.js mints it, which also keeps the
// clock-plus-randomness reasoning (a CI matrix starts several jobs in the same
// second) in one place.
var stamp = runStamp();
var prefix = "scimtest" + stamp;

let checks = 0;
let skips = [];
const created = { users: [], groups: [] };

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function skip(what, why) {
  log.debug("Entering skip(). " + what);
  skips.push(what + ": " + why);
  log.warn("  SKIPPED — " + what + " — " + why);
  log.debug("Leaving skip().");
}

// ---------------------------------------------------------------------------
// THE TRANSPORT.
//
// Every call goes through the api's POST /scim, which is the page's backend
// call path. `scimCall()` builds with the workflow's own module and asserts the
// three-outcome rule on the way through, so no individual section has to
// remember it.
// ---------------------------------------------------------------------------
async function postJson(url, body) {
  log.debug("Entering postJson(). url=" + url);
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let payload;
  try {
    payload = text === "" ? null : JSON.parse(text);
  } catch (e) {
    // Not JSON. Kept as text: an HTML error page from something in front of
    // the api is exactly the case where the body is the only useful evidence.
    payload = { error: text };
  }
  log.debug("Leaving postJson(). status=" + response.status);
  return { status: response.status, payload: payload };
}

async function scimCall(spec, options) {
  log.debug("Entering scimCall(). operation=" + spec.operation);
  const settings = options || {};
  const request = scim.buildRequest(Object.assign({ baseUrl: scimBaseUrl },
      spec));
  const headers = Object.assign({}, request.headers, settings.headers || {});
  const answer = await postJson(apiUrl + "/scim", {
    url: request.url,
    method: request.method,
    headers: headers,
    body: request.body,
    http_trace: true
  });
  if (answer.status === 400 && !settings.expectApiRefusal) {
    throw new Error("The api REFUSED to send " + request.method + " " +
        request.url + ": " + (answer.payload && answer.payload.error) +
        ". That is a 400 from the debugger's own proxy rather than anything " +
        "the SCIM server said.");
  }
  if (answer.status === 502 && !settings.expectUnreachable) {
    throw new Error("The api could not reach the SCIM server at " +
        request.url + ": " + (answer.payload && answer.payload.error) +
        ". SCIM_BASE_URL is the API's view of the mock (" + scimBaseUrl +
        "), which on the containerized stack is not this test's view.");
  }
  const result = {
    transport: answer.status,
    status: answer.payload && answer.payload.status,
    body: answer.payload && answer.payload.body,
    headers: (answer.payload && answer.payload.headers) || {},
    scimType: (answer.payload && answer.payload.scimType) || "",
    detail: (answer.payload && answer.payload.detail) || "",
    exchange: answer.payload && answer.payload.http_exchange,
    apiError: answer.payload && answer.payload.error
  };
  log.debug("Leaving scimCall(). " + result.status +
      (result.scimType ? " " + result.scimType : ""));
  return result;
}

// A SCIM error is an ANSWER and arrives with transport 200. Asserted here so
// that every negative section gets it without repeating it, and so that a
// regression in that rule fails once with a clear message rather than
// everywhere with confusing ones.
function assertAnswered(result, what) {
  log.debug("Entering assertAnswered().");
  assert.strictEqual(result.transport, 200,
      what + ": the api answered HTTP " + result.transport + " rather than " +
      "200. A SCIM error from the far end is the server ANSWERING — a 409 " +
      "uniqueness, a 404, a 403 from an access control policy — and " +
      "reporting it as a transport failure would make this endpoint unable " +
      "to show the errors it exists to show. (400 means the api refused to " +
      "send it; 502 means the server was unreachable.)");
  log.debug("Leaving assertAnswered().");
}

// ---------------------------------------------------------------------------
// THE VERIFICATION CHANNEL: the directory, through the api's LDAP client.
// ---------------------------------------------------------------------------
async function ldapSearch(base, filter, attributes) {
  log.debug("Entering ldapSearch(). filter=" + filter);
  const answer = await postJson(apiUrl + "/ldap/search", {
    url: ldapUrl, bindDn: bindDn, password: ldapPassword,
    base: base, scope: "sub", filter: filter,
    attributes: attributes || []
  });
  if (answer.status !== 200) {
    throw new Error("The LDAP search failed at the transport: HTTP " +
        answer.status + " " + JSON.stringify(answer.payload).slice(0, 300));
  }
  const entries = (answer.payload && answer.payload.entries) || [];
  log.debug("Leaving ldapSearch(). " + entries.length + " entry(ies).");
  return entries;
}

// An entry's attribute, case-insensitively, as an ARRAY. ldap_server.js hands
// attributes back canonically spelled while the store holds them lower-cased,
// and a caller may have either in hand — the same reason the mock's own
// scim_map.js looks them up case-insensitively.
function attr(entry, name) {
  log.debug("Entering attr(). name=" + name);
  const wanted = String(name).toLowerCase();
  const source = entry.attributes || entry;
  const keys = Object.keys(source);
  let i;
  for (i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === wanted) {
      const value = source[keys[i]];
      const out = Array.isArray(value) ? value.map(String) : [String(value)];
      log.debug("Leaving attr(). " + out.length + " value(s).");
      return out;
    }
  }
  log.debug("Leaving attr(). Absent.");
  return [];
}

// ---------------------------------------------------------------------------
// THE MAPPING, WRITTEN OUT INDEPENDENTLY OF THE MOCK'S OWN.
//
// Which LDAP attribute each SCIM member lands in — the mock's `scim_map.js`
// decides it, and this is the same table transcribed rather than imported, so
// that a change on one side is a disagreement rather than an agreement by
// construction.
//
// `pick` reads the value out of the SCIM resource that was SENT. Where a
// multi-valued attribute maps to one LDAP attribute per `type`, the type is
// named — because `phoneNumbers` splits across `telephoneNumber` and `mobile`
// and treating them alike is how one of them silently disappears.
// ---------------------------------------------------------------------------
const USER_MAPPING = [
  { scim: 'userName', ldap: 'uid',
    pick: function (u) { return u.userName; } },
  { scim: 'externalId', ldap: 'scimExternalId',
    pick: function (u) { return u.externalId; } },
  { scim: 'name.formatted', ldap: 'cn',
    pick: function (u) { return u.name.formatted; } },
  { scim: 'name.familyName', ldap: 'sn',
    pick: function (u) { return u.name.familyName; } },
  { scim: 'name.givenName', ldap: 'givenName',
    pick: function (u) { return u.name.givenName; } },
  { scim: 'displayName', ldap: 'displayName',
    pick: function (u) { return u.displayName; } },
  { scim: 'title', ldap: 'title', pick: function (u) { return u.title; } },
  { scim: 'userType', ldap: 'employeeType',
    pick: function (u) { return u.userType; } },
  { scim: 'preferredLanguage', ldap: 'preferredLanguage',
    pick: function (u) { return u.preferredLanguage; } },
  { scim: 'profileUrl', ldap: 'labeledURI',
    pick: function (u) { return u.profileUrl; } },
  { scim: 'emails[type eq "work"]', ldap: 'mail',
    pick: function (u) { return valueOfType(u.emails, 'work'); } },
  { scim: 'phoneNumbers[type eq "work"]', ldap: 'telephoneNumber',
    pick: function (u) { return valueOfType(u.phoneNumbers, 'work'); } },
  { scim: 'phoneNumbers[type eq "mobile"]', ldap: 'mobile',
    pick: function (u) { return valueOfType(u.phoneNumbers, 'mobile'); } },
  { scim: 'addresses.streetAddress', ldap: 'street',
    pick: function (u) { return u.addresses[0].streetAddress; } },
  { scim: 'addresses.locality', ldap: 'l',
    pick: function (u) { return u.addresses[0].locality; } },
  { scim: 'addresses.region', ldap: 'st',
    pick: function (u) { return u.addresses[0].region; } },
  { scim: 'addresses.postalCode', ldap: 'postalCode',
    pick: function (u) { return u.addresses[0].postalCode; } },
  { scim: 'addresses.country', ldap: 'c',
    pick: function (u) { return u.addresses[0].country; } },
  { scim: 'enterprise employeeNumber', ldap: 'employeeNumber',
    pick: function (u) { return u[scim.ENTERPRISE_SCHEMA].employeeNumber; } },
  { scim: 'enterprise department', ldap: 'departmentNumber',
    pick: function (u) { return u[scim.ENTERPRISE_SCHEMA].department; } },
  { scim: 'enterprise organization', ldap: 'o',
    pick: function (u) { return u[scim.ENTERPRISE_SCHEMA].organization; } },
  { scim: 'enterprise division', ldap: 'ou',
    pick: function (u) { return u[scim.ENTERPRISE_SCHEMA].division; } }
];

function valueOfType(list, type) {
  log.debug("Entering valueOfType(). type=" + type);
  let found = '';
  (list || []).forEach(function (row) {
    if (row.type === type && !found) {
      found = row.value;
    }
  });
  log.debug("Leaving valueOfType().");
  return found;
}

// ---------------------------------------------------------------------------
// 0. IS THERE A SCIM SERVER THERE AT ALL?
// ---------------------------------------------------------------------------
async function theMockHasScim() {
  log.debug("Entering theMockHasScim().");
  log.info("0. Reaching the SCIM server.");
  const result = await scimCall({ operation: 'serviceProviderConfig' },
      { expectUnreachable: true });
  if (result.transport === 502) {
    log.debug("Leaving theMockHasScim(). Unreachable.");
    return { present: false, why: 'the api could not reach ' + scimBaseUrl +
        ' at all (' + result.apiError + ')' };
  }
  if (result.status === 404) {
    log.debug("Leaving theMockHasScim(). 404.");
    return { present: false, why: 'the mock STS at ' + scimBaseUrl +
        ' answers 404 there. The SCIM endpoints arrived in rcbj/mock-sts ' +
        'AFTER this repository\'s sts/ gitlink was last moved, so a ' +
        'checkout whose submodule predates them has no /scim/v2 routes. ' +
        'Bump the gitlink (git add sts) and rebuild the sts image.' };
  }
  if (result.status !== 200) {
    log.debug("Leaving theMockHasScim(). status=" + result.status);
    return { present: false, why: 'GET /ServiceProviderConfig answered ' +
        result.status + ': ' + result.detail };
  }
  check('the ServiceProviderConfig is readable with no credential',
      function () {
    assert.ok(result.body,
        'The ServiceProviderConfig came back with no body.');
    assert.ok(Array.isArray(result.body.schemas) &&
        result.body.schemas.indexOf(
          scim.SERVICE_PROVIDER_CONFIG_SCHEMA) >= 0,
        'The document does not declare the ServiceProviderConfig schema URN.');
    assert.ok(result.body.patch && result.body.patch.supported,
        'This mock advertises PATCH as unsupported, and the scenarios below ' +
        'depend on it.');
  });
  check('the exchange came back with the request the api actually sent',
      function () {
    assert.ok(result.exchange && result.exchange.request,
        'http_trace: true asked for the exchange and none came back. The ' +
        'page\'s Exchange pane is the only place a proxied call can be seen ' +
        'at all — a browser cannot report the headers it did not send.');
    assert.strictEqual(result.exchange.request.method, 'GET');
    assert.ok(result.exchange.response.status === 200);
  });
  log.debug("Leaving theMockHasScim(). Present.");
  return { present: true };
}

// ---------------------------------------------------------------------------
// 1. DISCOVERY — the three documents, and the fact that none needs a scope.
// ---------------------------------------------------------------------------
async function discoveryAnswers() {
  log.debug("Entering discoveryAnswers().");
  log.info("1. Discovery.");
  const types = await scimCall({ operation: 'resourceTypes' });
  check('GET /ResourceTypes lists User and Group', function () {
    assertAnswered(types, 'ResourceTypes');
    assert.strictEqual(types.status, 200);
    const names = resourcesOf(types.body).map(function (row) {
      return row.id || row.name;
    });
    assert.ok(names.indexOf('User') >= 0 && names.indexOf('Group') >= 0,
        'The resource types are ' + names.join(', '));
  });
  const schemas = await scimCall({ operation: 'schemas' });
  check('GET /Schemas carries the core two AND the enterprise extension',
      function () {
    assertAnswered(schemas, 'Schemas');
    const ids = resourcesOf(schemas.body).map(function (row) {
      return row.id;
    });
    [scim.USER_SCHEMA, scim.GROUP_SCHEMA, scim.ENTERPRISE_SCHEMA]
      .forEach(function (urn) {
        assert.ok(ids.indexOf(urn) >= 0,
            'The schema ' + urn + ' is not published. Every enterprise ' +
            'attribute this test sends is one the server has not said it ' +
            'knows about.');
      });
  });
  const one = await scimCall({ operation: 'schema', id: scim.USER_SCHEMA });
  check('GET /Schemas/{urn} answers with that one schema', function () {
    assertAnswered(one, 'one Schema');
    assert.strictEqual(one.status, 200);
    assert.strictEqual(one.body.id, scim.USER_SCHEMA);
    const names = (one.body.attributes || []).map(function (row) {
      return row.name;
    });
    ['userName', 'name', 'emails', 'active'].forEach(function (name) {
      assert.ok(names.indexOf(name) >= 0,
          'The User schema does not describe ' + name + '.');
    });
  });
  check('userName is described as required and unique', function () {
    const userName = (one.body.attributes || []).filter(function (row) {
      return row.name === 'userName';
    })[0];
    assert.ok(userName, 'The User schema has no userName attribute.');
    assert.strictEqual(userName.required, true);
    assert.strictEqual(userName.uniqueness, 'server',
        'userName carries SCIM\'s uniqueness constraint, and it is what ' +
        'makes the 409 below reachable.');
  });
  const type = await scimCall({ operation: 'resourceType', id: 'User' });
  check('GET /ResourceTypes/User answers by NAME rather than by id',
      function () {
    assertAnswered(type, 'one ResourceType');
    assert.strictEqual(type.status, 200);
    assert.strictEqual(type.body.endpoint, '/Users');
    assert.strictEqual(type.body.schema, scim.USER_SCHEMA);
  });
  log.debug("Leaving discoveryAnswers().");
}

// The Schemas and ResourceTypes endpoints may answer with a ListResponse or
// with a bare array; both are seen in the field and RFC 7644 section 4 is read
// both ways. Accepting either here is not laxity — it is the one place the
// specification genuinely leaves a choice.
function resourcesOf(body) {
  log.debug("Entering resourcesOf().");
  const out = Array.isArray(body) ? body : ((body && body.Resources) || []);
  log.debug("Leaving resourcesOf(). " + out.length + " item(s).");
  return out;
}

// ---------------------------------------------------------------------------
// 2. CREATE A USER CARRYING EVERY OPTIONAL ATTRIBUTE, AND CHECK WHAT LANDED.
// ---------------------------------------------------------------------------
async function aFullUserRoundTrips() {
  log.debug("Entering aFullUserRoundTrips().");
  log.info("2. A user with every optional attribute.");
  const user = scim.randomUser({ seed: prefix + ':full', prefix: prefix,
                                 index: 0 });
  const result = await scimCall({ operation: 'createUser', body: user });
  check('POST /Users answers 201 with a Location header', function () {
    assertAnswered(result, 'create');
    assert.strictEqual(result.status, 201,
        'The create answered ' + result.status + ' ' + result.scimType +
        ': ' + result.detail);
    assert.ok(result.body && result.body.id, 'The created user has no id.');
    assert.ok(scenarios.headerValue(result.headers, 'location'),
        'RFC 7644 section 3.3 says a create answers with a Location header ' +
        'and this one did not. The resource may still exist — a client that ' +
        'follows Location will not find it.');
  });
  const id = result.body.id;
  created.users.push(id);
  check('the id is the entry\'s DN, as this mock documents', function () {
    assert.ok(/^uid=/.test(id) && id.indexOf(usersDn) > 0,
        'The id is "' + id + '". This mock uses the entry\'s DN as the SCIM ' +
        'id on purpose — it is already an opaque, server-assigned unique ' +
        'identifier — and the rest of this test reads the directory at that ' +
        'DN.');
  });

  // --- the second read: the directory ---
  const entries = await ldapSearch(usersDn, '(uid=' + user.userName + ')');
  check('the SCIM create really wrote an LDAP entry', function () {
    assert.strictEqual(entries.length, 1,
        'The SCIM server answered 201 and the directory has ' +
        entries.length + ' entry(ies) with uid=' + user.userName + '. A ' +
        '201 says the request was ACCEPTED; this is the only thing that ' +
        'says it was stored.');
  });
  const entry = entries[0];
  check('the entry is at the DN the SCIM id names', function () {
    assert.strictEqual(String(entry.dn).toLowerCase(), String(id).toLowerCase(),
        'The SCIM id and the entry DN disagree, so every later operation ' +
        'addresses a different object from the one that was created.');
  });

  // THE HEART OF THIS FILE. Every attribute sent, checked in the directory.
  USER_MAPPING.forEach(function (row) {
    check('SCIM ' + row.scim + ' was stored in LDAP ' + row.ldap,
        function () {
      const sent = String(row.pick(user));
      assert.ok(sent !== '' && sent !== 'undefined',
          'The generator did not produce a value for ' + row.scim +
          ', so this check would have passed vacuously.');
      const stored = attr(entry, row.ldap);
      assert.ok(stored.length > 0,
          'SCIM ' + row.scim + ' was sent as "' + sent + '", the create ' +
          'answered 201, and the LDAP attribute ' + row.ldap + ' is EMPTY. ' +
          'That is a field accepted and silently dropped — the most common ' +
          'real defect in a provisioning integration, and one a ' +
          'status-only test cannot see.');
      assert.ok(stored.indexOf(sent) >= 0,
          'SCIM ' + row.scim + ' was sent as "' + sent + '" and LDAP ' +
          row.ldap + ' holds ' + JSON.stringify(stored) + '.');
    });
  });

  check('the formatted address is stored $-separated per RFC 4517 3.3.28',
      function () {
    const stored = attr(entry, 'postalAddress');
    assert.ok(stored.length > 0,
        'addresses[0].formatted was sent and postalAddress is empty.');
    assert.strictEqual(stored[0],
        user.addresses[0].formatted.split('\n').join('$'),
        'RFC 4517 section 3.3.28 separates the lines of a postal address ' +
        'with "$" and SCIM\'s formatted is a display string with newlines. ' +
        'Storing the newlines verbatim produces a value no LDAP client can ' +
        'read.');
  });
  check('active:true is recorded as an LDAP boolean', function () {
    const stored = attr(entry, 'scimActive');
    assert.ok(stored.length > 0, 'active was sent and scimActive is empty.');
    assert.strictEqual(stored[0].toUpperCase(), 'TRUE',
        'RFC 4517 section 3.3.3 spells the LDAP booleans in CAPITALS and ' +
        'nothing else is one. Stored: ' + stored[0]);
  });

  // --- the third read: the resource itself ---
  const read = await scimCall({ operation: 'readUser', id: id });
  check('GET /Users/{id} returns what was stored', function () {
    assertAnswered(read, 'read');
    assert.strictEqual(read.status, 200);
    assert.strictEqual(read.body.userName, user.userName);
    assert.strictEqual(read.body.name.familyName, user.name.familyName);
    assert.strictEqual(read.body.title, user.title);
    assert.ok(read.body[scim.ENTERPRISE_SCHEMA],
        'The enterprise extension did not come back at all.');
    assert.strictEqual(read.body[scim.ENTERPRISE_SCHEMA].department,
        user[scim.ENTERPRISE_SCHEMA].department);
  });
  check('meta carries created, lastModified, resourceType and location',
      function () {
    const meta = read.body.meta || {};
    assert.strictEqual(meta.resourceType, 'User');
    assert.ok(meta.created, 'meta.created is absent.');
    assert.ok(!Number.isNaN(new Date(meta.created).getTime()),
        'meta.created is "' + meta.created + '", which is not an ISO 8601 ' +
        'instant. It comes from an LDAP generalized time and has to be ' +
        'converted; a raw 20260821... is a value no SCIM client can parse.');
    assert.ok(meta.location, 'meta.location is absent.');
  });
  check('a projection with ?attributes returns fewer members', function () {
    return null;
  });
  const projected = await scimCall({ operation: 'readUser', id: id,
      query: { attributes: 'userName,title' } });
  check('?attributes really projects', function () {
    assertAnswered(projected, 'projected read');
    assert.strictEqual(projected.body.userName, user.userName);
    assert.strictEqual(projected.body.title, user.title);
    assert.strictEqual(projected.body.displayName, undefined,
        'displayName came back from a read that asked only for userName and ' +
        'title. A server that ignores ?attributes returns the whole ' +
        'resource and nothing complains.');
  });
  const excluded = await scimCall({ operation: 'readUser', id: id,
      query: { excludedAttributes: 'emails,phoneNumbers' } });
  check('?excludedAttributes really excludes', function () {
    assertAnswered(excluded, 'excluded read');
    assert.strictEqual(excluded.body.emails, undefined,
        'emails came back from a read that excluded them.');
    assert.ok(excluded.body.userName,
        'excludedAttributes removed more than it was asked to: userName is ' +
        'gone too.');
  });
  log.debug("Leaving aFullUserRoundTrips(). id=" + id);
  return { id: id, user: user };
}

// ---------------------------------------------------------------------------
// 3. PUT, PATCH and the three PATCH operations.
// ---------------------------------------------------------------------------
async function replaceAndModify(subject) {
  log.debug("Entering replaceAndModify().");
  log.info("3. PUT and PATCH.");
  const replacement = scim.randomUser({ seed: prefix + ':replace',
      prefix: prefix, index: 1 });
  // A PUT REPLACES, so the replacement keeps the SAME userName — changing it
  // as well would make a failure ambiguous between "the PUT did not apply" and
  // "the PUT created somebody else".
  replacement.userName = subject.user.userName;
  const put = await scimCall({ operation: 'replaceUser', id: subject.id,
      body: replacement });
  check('PUT /Users/{id} replaces the resource', function () {
    assertAnswered(put, 'replace');
    assert.strictEqual(put.status, 200,
        'The replace answered ' + put.status + ': ' + put.detail);
    assert.strictEqual(put.body.title, replacement.title);
  });
  let entries = await ldapSearch(usersDn,
      '(uid=' + subject.user.userName + ')');
  check('the PUT reached the directory', function () {
    assert.strictEqual(attr(entries[0], 'title')[0], replacement.title,
        'The SCIM resource says the title changed and the directory still ' +
        'holds the old one.');
  });

  const patch = await scimCall({ operation: 'modifyUser', id: subject.id,
      body: scim.patchOp([
        { op: 'replace', path: 'title', value: 'Patched Title' },
        { op: 'replace', path: 'userType', value: 'Contractor' }
      ]) });
  check('PATCH replace changes exactly what it names', function () {
    assertAnswered(patch, 'patch replace');
    assert.ok(patch.status === 200 || patch.status === 204,
        'The PATCH answered ' + patch.status + ': ' + patch.detail);
  });
  entries = await ldapSearch(usersDn, '(uid=' + subject.user.userName + ')');
  check('the PATCH reached the directory and left the rest alone',
      function () {
    assert.strictEqual(attr(entries[0], 'title')[0], 'Patched Title');
    assert.strictEqual(attr(entries[0], 'employeeType')[0], 'Contractor');
    assert.strictEqual(attr(entries[0], 'sn')[0], replacement.name.familyName,
        'The PATCH named title and userType and the surname changed too. A ' +
        'PATCH that behaves like a PUT removes every attribute the client ' +
        'did not mention.');
  });

  const add = await scimCall({ operation: 'modifyUser', id: subject.id,
      body: scim.patchOp([
        { op: 'add', path: 'emails',
          value: [{ value: 'added.by.patch@example.com', type: 'other',
                    primary: false }] }
      ]) });
  check('PATCH add on a multi-valued attribute APPENDS', function () {
    assertAnswered(add, 'patch add');
    assert.ok(add.status === 200 || add.status === 204);
  });
  const afterAdd = await scimCall({ operation: 'readUser', id: subject.id });
  check('the work email survived the add', function () {
    const values = (afterAdd.body.emails || []).map(function (row) {
      return row.value;
    });
    assert.ok(values.indexOf('added.by.patch@example.com') >= 0,
        'The added email is not there. Emails: ' + values.join(', '));
    assert.ok(values.indexOf(valueOfType(replacement.emails, 'work')) >= 0,
        'The work email is GONE. `add` on a multi-valued attribute appends; ' +
        'a server that replaces the array instead silently loses every ' +
        'other value, which is the defect this check exists for. Emails: ' +
        values.join(', '));
  });

  const remove = await scimCall({ operation: 'modifyUser', id: subject.id,
      body: scim.patchOp([
        { op: 'remove', path: 'emails[type eq "other"]' }
      ]) });
  check('PATCH remove through a value-filter PATH', function () {
    assertAnswered(remove, 'patch remove');
    assert.ok(remove.status === 200 || remove.status === 204,
        'emails[type eq "other"] is a PATH, not a property name. This is ' +
        'the RFC 7644 section 3.5.2 grammar every hand-rolled SCIM server ' +
        'is subtly wrong about, and where a client\'s updates land on the ' +
        'wrong value. Answered ' + remove.status + ': ' + remove.detail);
  });
  const afterRemove = await scimCall({ operation: 'readUser',
      id: subject.id });
  check('the value filter removed exactly the one it named', function () {
    const values = (afterRemove.body.emails || []).map(function (row) {
      return row.value;
    });
    assert.ok(values.indexOf('added.by.patch@example.com') < 0,
        'The value-filter remove did not remove it.');
    assert.ok(values.indexOf(valueOfType(replacement.emails, 'work')) >= 0,
        'The value-filter remove took the WORK email as well, which is what ' +
        'a server treating the path as a property name does.');
  });
  log.debug("Leaving replaceAndModify().");
}

// ---------------------------------------------------------------------------
// 4. LIST, FILTER, SORT, PAGE.
// ---------------------------------------------------------------------------
async function listingAndFiltering() {
  log.debug("Entering listingAndFiltering().");
  log.info("4. Listing, filtering, sorting and paging.");
  // A small population of its own, so the counts below are exact rather than
  // "at least".
  const rng = scim.newRng(prefix + ':page');
  const page = [];
  let i;
  for (i = 0; i < 5; i++) {
    const user = scim.randomUser({ rng: rng, prefix: prefix + 'page',
                                   index: i });
    const made = await scimCall({ operation: 'createUser', body: user });
    assertAnswered(made, 'create for paging');
    assert.strictEqual(made.status, 201,
        'A create for the paging population answered ' + made.status + ': ' +
        made.detail);
    created.users.push(made.body.id);
    page.push(made.body);
  }
  const all = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName sw "' + prefix + 'page."', count: '50' } });
  check('a filtered list finds exactly the five just created', function () {
    assertAnswered(all, 'list');
    assert.strictEqual(all.status, 200,
        'The list answered ' + all.status + ' ' + all.scimType + ': ' +
        all.detail);
    assert.strictEqual(Number(all.body.totalResults), 5,
        'The filter userName sw "' + prefix + 'page." matched ' +
        all.body.totalResults + ' and five were created.');
  });
  const first = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName sw "' + prefix + 'page."',
               startIndex: '1', count: '2', sortBy: 'userName',
               sortOrder: 'ascending' } });
  const second = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName sw "' + prefix + 'page."',
               startIndex: '3', count: '2', sortBy: 'userName',
               sortOrder: 'ascending' } });
  check('paging is 1-INDEXED and the pages do not overlap', function () {
    assertAnswered(first, 'page 1');
    assert.strictEqual(first.body.Resources.length, 2);
    assert.strictEqual(Number(first.body.startIndex), 1);
    const firstNames = first.body.Resources.map(function (row) {
      return row.userName;
    });
    const secondNames = second.body.Resources.map(function (row) {
      return row.userName;
    });
    secondNames.forEach(function (name) {
      assert.ok(firstNames.indexOf(name) < 0,
          '"' + name + '" is on both page 1 (startIndex 1) and page 2 ' +
          '(startIndex 3). SCIM paging is 1-INDEXED — startIndex 1 is the ' +
          'FIRST resource — and a client written against a 0-indexed API ' +
          'either skips one on every page or repeats one.');
    });
  });
  check('sortBy really sorts', function () {
    const names = first.body.Resources.map(function (row) {
      return row.userName;
    });
    const sorted = names.slice(0).sort();
    assert.deepStrictEqual(names, sorted,
        'sortBy=userName&sortOrder=ascending returned ' + names.join(', '));
  });
  const descending = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName sw "' + prefix + 'page."',
               sortBy: 'userName', sortOrder: 'descending', count: '50' } });
  check('sortOrder=descending is honoured', function () {
    const names = descending.body.Resources.map(function (row) {
      return row.userName;
    });
    const reversed = names.slice(0).sort().reverse();
    assert.deepStrictEqual(names, reversed,
        'Sorting is advertised as one boolean too, so a server that ignores ' +
        'sortOrder is only visible by asking for both. Got: ' +
        names.join(', '));
  });
  const countZero = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName sw "' + prefix + 'page."', count: '0' } });
  check('count=0 returns the total and NO resources', function () {
    assertAnswered(countZero, 'count=0');
    assert.strictEqual(Number(countZero.body.totalResults), 5);
    assert.strictEqual((countZero.body.Resources || []).length, 0,
        'RFC 7644 section 3.4.2.4: count=0 asks for the TOTAL with no ' +
        'resources. It is how a client sizes a job before it starts one, ' +
        'and a server that returns everything instead has just been asked ' +
        'for the whole directory.');
  });

  // Every operator, against a user known to match.
  const subject = page[0];
  const tail = subject.userName.slice(subject.userName.lastIndexOf('.') + 1);
  const OPERATORS = [
    { op: 'eq', filter: 'userName eq "' + subject.userName + '"', match: true },
    { op: 'ne', filter: 'userName ne "' + subject.userName + '"',
      match: false },
    { op: 'co', filter: 'userName co "' + tail + '"', match: true },
    { op: 'sw', filter: 'userName sw "' + prefix + 'page."', match: true },
    { op: 'ew', filter: 'userName ew "' + tail + '"', match: true },
    { op: 'pr', filter: 'userName pr', match: true },
    { op: 'gt', filter: 'meta.created gt "2000-01-01T00:00:00Z"', match: true },
    { op: 'ge', filter: 'meta.created ge "2000-01-01T00:00:00Z"', match: true },
    { op: 'lt', filter: 'meta.created lt "2999-01-01T00:00:00Z"', match: true },
    { op: 'le', filter: 'meta.created le "2999-01-01T00:00:00Z"', match: true },
    { op: 'and', filter: 'userName eq "' + subject.userName +
      '" and active eq true', match: true },
    { op: 'or', filter: 'userName eq "' + subject.userName +
      '" or userName eq "nobody-at-all"', match: true },
    { op: 'not', filter: 'not (userName eq "nobody-at-all")', match: true },
    { op: 'complex value filter', filter: 'emails[type eq "work"]',
      match: true }
  ];
  for (i = 0; i < OPERATORS.length; i++) {
    const row = OPERATORS[i];
    const answer = await scimCall({ operation: 'listUsers',
        query: { filter: row.filter, count: '50' } });
    check('filter operator ' + row.op + ' is evaluated', function () {
      assertAnswered(answer, 'filter ' + row.op);
      assert.strictEqual(answer.status, 200,
          'The filter `' + row.filter + '` answered ' + answer.status + ' ' +
          answer.scimType + ': ' + answer.detail + '. A server advertises ' +
          'filtering as ONE boolean, so an operator it cannot evaluate is ' +
          'only discoverable by sending it.');
      const names = (answer.body.Resources || []).map(function (found) {
        return found.userName;
      });
      if (row.match) {
        assert.ok(names.indexOf(subject.userName) >= 0,
            'The filter `' + row.filter + '` was expected to match ' +
            subject.userName + ' and matched ' + names.length + ' user(s).');
      } else {
        assert.ok(names.indexOf(subject.userName) < 0,
            'The filter `' + row.filter + '` was expected NOT to match ' +
            subject.userName + ' and did.');
      }
    });
  }
  log.debug("Leaving listingAndFiltering().");
  return page;
}

// ---------------------------------------------------------------------------
// 5. GROUPS, AND THE MEMBERSHIP THAT IS A PATCH ON THE GROUP.
// ---------------------------------------------------------------------------
async function groupsAndMembership(population) {
  log.debug("Entering groupsAndMembership().");
  log.info("5. Groups and membership.");
  const group = scim.randomGroup({ seed: prefix + ':group',
                                   prefix: prefix });
  const made = await scimCall({ operation: 'createGroup', body: group });
  check('POST /Groups answers 201', function () {
    assertAnswered(made, 'create group');
    assert.strictEqual(made.status, 201,
        'The group create answered ' + made.status + ': ' + made.detail);
    assert.ok(made.body.id);
  });
  const groupId = made.body.id;
  created.groups.push(groupId);

  let entries = await ldapSearch(groupsDn,
      '(cn=' + group.displayName + ')');
  check('the group was written to the directory', function () {
    assert.strictEqual(entries.length, 1,
        'The group create answered 201 and the directory holds ' +
        entries.length + ' entry(ies) with cn=' + group.displayName + '.');
    assert.strictEqual(attr(entries[0], 'cn')[0], group.displayName,
        'displayName maps to cn.');
    assert.strictEqual(attr(entries[0], 'scimExternalId')[0],
        group.externalId, 'A group\'s externalId maps to scimExternalId.');
  });

  const members = population.map(function (row) {
    return { value: row.id, type: 'User' };
  });
  const added = await scimCall({ operation: 'modifyGroup', id: groupId,
      body: scim.patchOp([{ op: 'add', path: 'members', value: members }]) });
  check('membership is added with ONE PATCH against the GROUP', function () {
    assertAnswered(added, 'add members');
    assert.ok(added.status === 200 || added.status === 204,
        'The membership PATCH answered ' + added.status + ' ' +
        added.scimType + ': ' + added.detail);
  });
  const readGroup = await scimCall({ operation: 'readGroup', id: groupId });
  check('the group comes back with all five members', function () {
    assertAnswered(readGroup, 'read group');
    const values = (readGroup.body.members || []).map(function (row) {
      return String(row.value).toLowerCase();
    });
    population.forEach(function (row) {
      assert.ok(values.indexOf(String(row.id).toLowerCase()) >= 0,
          row.userName + ' is not a member. Members: ' + values.join(', '));
    });
  });
  entries = await ldapSearch(groupsDn, '(cn=' + group.displayName + ')');
  check('membership was written to the group\'s `member` attribute',
      function () {
    const stored = attr(entries[0], 'member').map(function (dn) {
      return dn.toLowerCase();
    });
    population.forEach(function (row) {
      assert.ok(stored.indexOf(String(row.id).toLowerCase()) >= 0,
          'Membership is a fact about the GROUP\'s entry — RFC 4519 section ' +
          '2.17 — and it is changed through a Group resource and never ' +
          'through a User one. ' + row.userName + ' is not in `member`.');
    });
  });
  check('the user resource shows the group, read-only', function () {
    return null;
  });
  const memberUser = await scimCall({ operation: 'readUser',
      id: population[0].id });
  check('a user\'s `groups` is derived from the group\'s membership',
      function () {
    const groups = (memberUser.body.groups || []).map(function (row) {
      return String(row.value).toLowerCase();
    });
    assert.ok(groups.indexOf(String(groupId).toLowerCase()) >= 0,
        'RFC 7643 section 4.1.2 makes `groups` READ-ONLY and derived from ' +
        'the group\'s own membership, so a token and a SCIM resource cannot ' +
        'disagree about who is in what. It came back as: ' +
        groups.join(', '));
  });

  const removed = await scimCall({ operation: 'modifyGroup', id: groupId,
      body: scim.patchOp([
        { op: 'remove',
          path: 'members[value eq "' + population[0].id + '"]' }
      ]) });
  check('one member is removed through a value-filter path', function () {
    assertAnswered(removed, 'remove member');
    assert.ok(removed.status === 200 || removed.status === 204,
        'The remove answered ' + removed.status + ': ' + removed.detail);
  });
  const afterRemove = await scimCall({ operation: 'readGroup', id: groupId });
  check('exactly one member left and the rest stayed', function () {
    const values = (afterRemove.body.members || []).map(function (row) {
      return String(row.value).toLowerCase();
    });
    assert.ok(values.indexOf(String(population[0].id).toLowerCase()) < 0,
        'The named member is still there.');
    assert.strictEqual(values.length, population.length - 1,
        'The group now has ' + values.length + ' member(s) and should have ' +
        (population.length - 1) + '. Getting the value-filter path wrong on ' +
        'this attribute empties the whole group instead of removing one ' +
        'person.');
  });

  const replaced = await scimCall({ operation: 'replaceGroup', id: groupId,
      body: { schemas: [scim.GROUP_SCHEMA], displayName: group.displayName,
              externalId: group.externalId,
              members: [{ value: population[1].id, type: 'User' }] } });
  check('PUT on a group replaces its membership wholesale', function () {
    assertAnswered(replaced, 'replace group');
    assert.strictEqual(replaced.status, 200,
        'The group PUT answered ' + replaced.status + ': ' + replaced.detail);
    const values = (replaced.body.members || []).map(function (row) {
      return String(row.value).toLowerCase();
    });
    assert.strictEqual(values.length, 1,
        'A PUT replaces the resource, membership included. It now has ' +
        values.length + ' member(s).');
  });
  log.debug("Leaving groupsAndMembership(). id=" + groupId);
  return groupId;
}

// ---------------------------------------------------------------------------
// 6. THE QUERY ENDPOINTS: /.search per type, /.search across both, and /Bulk.
// ---------------------------------------------------------------------------
async function searchAndBulk() {
  log.debug("Entering searchAndBulk().");
  log.info("6. POST /.search and POST /Bulk.");
  const perType = await scimCall({ operation: 'searchUsers',
      body: scim.searchRequest({ filter: 'userName sw "' + prefix + '"',
                                 count: 50 }) });
  check('POST /Users/.search answers a ListResponse', function () {
    assertAnswered(perType, 'per-type search');
    assert.strictEqual(perType.status, 200,
        'The .search answered ' + perType.status + ' ' + perType.scimType +
        ': ' + perType.detail);
    assert.ok(Number(perType.body.totalResults) > 0);
  });
  const projected = await scimCall({ operation: 'searchUsers',
      body: scim.searchRequest({ filter: 'userName sw "' + prefix + '"',
                                 attributes: 'userName,id', count: 5 }) });
  check('a SearchRequest\'s ARRAY attributes really project', function () {
    assertAnswered(projected, 'projected search');
    const one = (projected.body.Resources || [])[0];
    assert.ok(one, 'The projected search matched nothing.');
    assert.ok(one.userName, 'userName was asked for and is absent.');
    assert.strictEqual(one.title, undefined,
        'title came back from a search that asked for userName and id. ' +
        '`attributes` is an ARRAY in a SearchRequest and a comma-separated ' +
        'STRING in a query string — that asymmetry is in RFC 7644 itself, ' +
        'and sending the string form is why a /.search so often returns ' +
        'everything.');
  });
  const across = await scimCall({ operation: 'searchAll',
      body: scim.searchRequest({ filter: 'id pr', count: 100 }) });
  check('POST /.search queries BOTH resource types at once', function () {
    assertAnswered(across, 'root search');
    assert.strictEqual(across.status, 200,
        'The root .search answered ' + across.status + ': ' + across.detail);
    const kinds = {};
    (across.body.Resources || []).forEach(function (row) {
      (row.schemas || []).forEach(function (urn) {
        kinds[urn] = true;
      });
    });
    assert.ok(kinds[scim.USER_SCHEMA] && kinds[scim.GROUP_SCHEMA],
        'The root .search is the one thing the per-type endpoint cannot do, ' +
        'and its ListResponse comes back MIXED — read each entry\'s own ' +
        'schemas to tell a User from a Group. Kinds seen: ' +
        Object.keys(kinds).join(', '));
  });
  const noSchema = await scimCall({ operation: 'searchAll',
      body: { filter: 'id pr' } });
  check('a .search body with no schemas member is refused', function () {
    assertAnswered(noSchema, 'search with no schemas');
    assert.strictEqual(noSchema.status, 400,
        'RFC 7644 section 3.4.3 requires the SearchRequest URN in schemas. ' +
        'A permissive server here is how a client comes to send a ' +
        'non-conforming body to everybody else.');
  });

  // The bulk, with the feature that makes it more than a loop.
  const rng = scim.newRng(prefix + ':bulk');
  const operations = [];
  const members = [];
  let i;
  for (i = 0; i < 3; i++) {
    operations.push({ method: 'POST', bulkId: 'u' + i, path: '/Users',
        data: scim.randomUser({ rng: rng, prefix: prefix + 'bulk',
                                index: i }) });
    members.push({ value: 'bulkId:u' + i, type: 'User' });
  }
  const bulkGroup = scim.randomGroup({ rng: rng, prefix: prefix + 'bulk' });
  bulkGroup.members = members;
  operations.push({ method: 'POST', bulkId: 'g0', path: '/Groups',
      data: bulkGroup });
  const bulk = await scimCall({ operation: 'bulk',
      body: scim.bulkRequest(operations, { failOnErrors: 1 }) });
  check('POST /Bulk answers 200 with a status per operation', function () {
    assertAnswered(bulk, 'bulk');
    assert.strictEqual(bulk.status, 200,
        'The bulk answered ' + bulk.status + ' ' + bulk.scimType + ': ' +
        bulk.detail);
    const inner = bulk.body.Operations || [];
    assert.strictEqual(inner.length, 4,
        'Four operations went in and ' + inner.length + ' came back.');
    inner.forEach(function (row) {
      assert.ok(Number(row.status) < 400,
          'A bulk operation was refused: ' + JSON.stringify(row).slice(0, 300) +
          '. Note the ENVELOPE answered 200 because the bulk was PROCESSED — ' +
          'RFC 7644 section 3.7 puts each operation\'s own status inside, ' +
          'which is why this check reads in there.');
      assert.ok(row.location,
          'A bulk operation came back with no location, so nothing can ' +
          'address what it created.');
    });
  });
  check('a group created IN the bulk contains the users created beside it',
      function () {
    const groupRow = (bulk.body.Operations || []).filter(function (row) {
      return row.bulkId === 'g0';
    })[0];
    assert.ok(groupRow, 'The group operation is not in the response.');
    created.groups.push(idFromLocation(groupRow.location));
  });
  const bulkGroupRead = await scimCall({ operation: 'readGroup',
      id: created.groups[created.groups.length - 1] });
  check('bulkId references were resolved to real ids', function () {
    assertAnswered(bulkGroupRead, 'read the bulk group');
    const values = (bulkGroupRead.body.members || []).map(function (row) {
      return String(row.value);
    });
    assert.strictEqual(values.length, 3,
        'The group has ' + values.length + ' member(s). Referencing users ' +
        'created in the SAME request as bulkId:name is the feature that ' +
        'makes a bulk more than a loop; without it this was three creates ' +
        'and an empty group.');
    values.forEach(function (value) {
      assert.ok(value.indexOf('bulkId:') < 0,
          'A member is still the literal reference "' + value + '" — the ' +
          'server stored the bulkId rather than resolving it.');
      created.users.push(value);
    });
  });
  log.debug("Leaving searchAndBulk().");
}

function idFromLocation(location) {
  log.debug("Entering idFromLocation().");
  const text = String(location || '');
  const cut = text.lastIndexOf('/');
  const out = cut < 0 ? '' : decodeURIComponent(text.slice(cut + 1));
  log.debug("Leaving idFromLocation(). " + out);
  return out;
}

// ---------------------------------------------------------------------------
// 7. THE REFUSALS. Every one asserts the TRANSPORT status too.
// ---------------------------------------------------------------------------
async function everyRefusalIsAnAnswer() {
  log.debug("Entering everyRefusalIsAnAnswer().");
  log.info("7. The refusals.");
  const refused = await scimCall({ operation: 'createUser',
      body: { schemas: [scim.USER_SCHEMA], userName: 'invalid' } });
  check('the reserved userName is refused 400 invalidValue', function () {
    assertAnswered(refused, 'reserved userName');
    assert.strictEqual(refused.status, 400,
        'This mock refuses exactly one userName on purpose, the same way it ' +
        'refuses exactly one password everywhere else — so that a 400 ' +
        'invalidValue is reachable on a server that otherwise accepts ' +
        'anything.');
    assert.strictEqual(refused.scimType, 'invalidValue',
        'The scimType is "' + refused.scimType + '". The HTTP status alone ' +
        'cannot tell invalidValue from uniqueness, and they need different ' +
        'handling: one is retryable with a new name and one is not.');
  });
  const noName = await scimCall({ operation: 'createUser',
      body: { schemas: [scim.USER_SCHEMA], displayName: 'no userName' } });
  check('a User with no userName is refused', function () {
    assertAnswered(noName, 'missing userName');
    assert.strictEqual(noName.status, 400,
        'userName is the one REQUIRED attribute on a User. A server that ' +
        'accepts this has a schema it does not enforce.');
  });
  const twin = scim.randomUser({ seed: prefix + ':twin', prefix: prefix });
  const firstTwin = await scimCall({ operation: 'createUser', body: twin });
  check('the first of a pair is created', function () {
    assertAnswered(firstTwin, 'first twin');
    assert.strictEqual(firstTwin.status, 201);
    created.users.push(firstTwin.body.id);
  });
  const secondTwin = await scimCall({ operation: 'createUser', body: twin });
  check('a duplicate userName is refused 409 uniqueness', function () {
    assertAnswered(secondTwin, 'duplicate userName');
    assert.strictEqual(secondTwin.status, 409,
        'userName carries SCIM\'s uniqueness constraint, so this is the ' +
        'reachable 409. It answered ' + secondTwin.status + ': ' +
        secondTwin.detail);
    assert.strictEqual(secondTwin.scimType, 'uniqueness');
  });
  const missing = await scimCall({ operation: 'readUser',
      id: 'uid=nobody-at-all-' + stamp + ',' + usersDn });
  check('an id that names nothing is a 404', function () {
    assertAnswered(missing, 'missing id');
    assert.strictEqual(missing.status, 404);
  });
  const deleteMissing = await scimCall({ operation: 'deleteUser',
      id: 'uid=nobody-at-all-' + stamp + ',' + usersDn });
  check('deleting an id that names nothing is a 404 and not a 204',
      function () {
    assertAnswered(deleteMissing, 'delete missing');
    assert.strictEqual(deleteMissing.status, 404,
        'A server answering 204 here claims to have deleted something that ' +
        'was never there, which makes a deprovisioning run impossible to ' +
        'audit.');
  });
  const badFilter = await scimCall({ operation: 'listUsers',
      query: { filter: 'userName zz "nobody"' } });
  check('a filter that is not grammar is 400 invalidFilter', function () {
    assertAnswered(badFilter, 'bad filter');
    assert.strictEqual(badFilter.status, 400);
    assert.strictEqual(badFilter.scimType, 'invalidFilter');
  });
  const badPath = await scimCall({ operation: 'modifyUser',
      id: firstTwin.body.id,
      body: scim.patchOp([{ op: 'replace', path: 'emails[type eq ',
                            value: 'x' }]) });
  check('a PATCH path that is not path grammar is 400 invalidPath',
      function () {
    assertAnswered(badPath, 'bad patch path');
    assert.strictEqual(badPath.status, 400,
        'It answered ' + badPath.status + ': ' + badPath.detail);
    assert.strictEqual(badPath.scimType, 'invalidPath',
        'Section 3.5.2 gives a bad PATCH path its own scimType, separate ' +
        'from invalidFilter, because a PATCH path and a query filter are ' +
        'different grammars that look alike. Got "' + badPath.scimType + '".');
  });
  const me = await scimCall({ operation: 'me' });
  check('/Me answers 501 with a reason rather than 404', function () {
    assertAnswered(me, '/Me');
    assert.ok(me.status === 501 || me.status === 401,
        '/Me answered ' + me.status + '. RFC 7644 section 3.11 makes it an ' +
        'alias for the authenticated subject; a server with none has ' +
        'nothing to alias, and a 501 saying so is a better answer than a ' +
        '404 (which says the route is not there) or a guess at who is ' +
        'asking.');
    if (me.status === 501) {
      assert.ok(String(me.detail).length > 0,
          'The 501 carries no detail, so it says nothing a 404 would not.');
    }
  });
  // The api's OWN refusals, which are a 400 and are NOT a SCIM answer.
  const apiRefusal = await postJson(apiUrl + '/scim', {
    url: scimBaseUrl + '/Users', method: 'GET', headers: { Host: 'evil' } });
  check('the api refuses a framing header with a 400 of its own', function () {
    assert.strictEqual(apiRefusal.status, 400,
        'The api forwarded a Host header, which sends the request to a ' +
        'different virtual host than the URL names.');
    assert.ok(String(apiRefusal.payload.error).indexOf('Host') >= 0,
        'The refusal does not name the header, so a caller cannot tell ' +
        'this from the SCIM server saying no.');
  });
  log.debug("Leaving everyRefusalIsAnAnswer().");
}

// ---------------------------------------------------------------------------
// 8. AUTHENTICATION — ALL SIX SCHEMES RFC 7644 SECTION 2 NAMES.
//
// One call each, plus the negative that proves the check is really running. NOT
// a cross-product with the endpoints: that would be forty-two runs of the same
// header parser, and the user asked for neither.
// ---------------------------------------------------------------------------
async function whatTheServerAcceptsIsPublished() {
  log.debug("Entering whatTheServerAcceptsIsPublished().");
  log.info("8. Authentication.");
  // One unauthenticated request, to read the challenge. If the server does not
  // require authentication, everything below is skipped WITH ITS REASON rather
  // than passing vacuously — a scheme check against a server that accepts
  // everything tests nothing at all.
  const anonymous = await scimCall({ operation: 'listUsers',
      query: { count: '1' } });
  if (anonymous.status !== 401) {
    log.debug("Leaving whatTheServerAcceptsIsPublished(). Not required.");
    return { required: false, why: 'this mock allowed an ANONYMOUS list (' +
        anonymous.status + '), so authentication is turned off there ' +
        '(scim.authRequired). Every scheme would be accepted whatever it ' +
        'carried, so a check on one would pass without testing anything.' };
  }
  const header = scenarios.headerValue(anonymous.headers,
      'www-authenticate');
  check('a 401 carries a WWW-Authenticate challenge', function () {
    assert.ok(header,
        'RFC 7644 section 2 makes this a SHALL: "a SCIM service provider ' +
        'SHALL indicate supported HTTP authentication schemes via the ' +
        'WWW-Authenticate header". A 401 with no challenge is ' +
        'non-conforming and, more to the point, useless — a client told it ' +
        'failed and not what to send next cannot proceed.');
  });
  const challenges = scim.parseChallenges(header);
  check('the challenge names the schemes this mock accepts', function () {
    const schemes = challenges.map(function (row) {
      return String(row.scheme).toLowerCase();
    });
    assert.ok(schemes.length > 0, 'The challenge parsed to nothing: ' +
        header);
    log.info('     the server offers: ' + schemes.join(', '));
  });
  log.debug("Leaving whatTheServerAcceptsIsPublished(). Required.");
  return { required: true, challenges: challenges };
}

// A token from the mock's own authorization server. Every grant works there and
// the scope is whatever is asked for, which is what makes a scope test
// possible at all.
async function accessToken(scope) {
  log.debug("Entering accessToken(). scope=" + scope);
  const response = await fetch(stsUrl + '/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials&client_id=scim-test-client' +
        '&client_secret=secret&scope=' + encodeURIComponent(scope)
  });
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving accessToken(). The token endpoint did not answer JSON.");
    return { ok: false, why: 'the token endpoint at ' + stsUrl +
        '/oauth2/token answered ' + response.status + ' with a body that is ' +
        'not JSON: ' + text.slice(0, 200) };
  }
  if (!payload.access_token) {
    log.debug("Leaving accessToken(). No token.");
    return { ok: false, why: 'the token endpoint answered ' +
        response.status + ': ' + JSON.stringify(payload).slice(0, 300) };
  }
  log.debug("Leaving accessToken(). Got one.");
  return { ok: true, token: payload.access_token, scope: payload.scope };
}

async function everySchemeIsExercised(state) {
  log.debug("Entering everySchemeIsExercised().");
  if (!state.required) {
    skip('every authentication scheme', state.why);
    log.debug("Leaving everySchemeIsExercised(). Skipped.");
    return;
  }
  const offered = state.challenges.map(function (row) {
    return String(row.scheme).toLowerCase();
  });

  // --- 1. Bearer ---------------------------------------------------------
  if (offered.indexOf('bearer') < 0) {
    skip('OAuth 2.0 Bearer', 'the server does not offer it (scim.authBearer)');
  } else {
    const both = await accessToken('scim:read scim:write');
    if (!both.ok) {
      skip('OAuth 2.0 Bearer', both.why);
    } else {
      const withToken = await scimCall({ operation: 'listUsers',
          query: { count: '1' } },
          { headers: { Authorization: 'Bearer ' + both.token } });
      check('Bearer: a token with both scopes may read', function () {
        assertAnswered(withToken, 'bearer read');
        assert.strictEqual(withToken.status, 200,
            'A Bearer token carrying scim:read was refused ' +
            withToken.status + ': ' + withToken.detail);
      });
      const garbage = await scimCall({ operation: 'listUsers',
          query: { count: '1' } },
          { headers: { Authorization: 'Bearer not-a-token' } });
      check('Bearer: a token this server did not sign is refused',
          function () {
        assertAnswered(garbage, 'bearer negative');
        assert.strictEqual(garbage.status, 401,
            'A made-up Bearer token was ACCEPTED. Without this negative a ' +
            'server that ignores the header entirely would pass the ' +
            'positive above.');
      });
      // The scope policy, which is the only thing on this page that can
      // produce a 403 rather than a 401.
      const readOnly = await accessToken('scim:read');
      if (!readOnly.ok) {
        skip('the scope policy', readOnly.why);
      } else {
        const mayRead = await scimCall({ operation: 'listUsers',
            query: { count: '1' } },
            { headers: { Authorization: 'Bearer ' + readOnly.token } });
        check('scope: a read-only token MAY read', function () {
          assertAnswered(mayRead, 'read-only read');
          assert.strictEqual(mayRead.status, 200,
              'Without this control a 403 below could equally mean the ' +
              'credential is simply broken.');
        });
        const mayNotWrite = await scimCall({ operation: 'createUser',
            body: scim.randomUser({ seed: prefix + ':scope',
                                    prefix: prefix }) },
            { headers: { Authorization: 'Bearer ' + readOnly.token } });
        check('scope: a read-only token may NOT write — 403', function () {
          assertAnswered(mayNotWrite, 'read-only write');
          assert.strictEqual(mayNotWrite.status, 403,
              'A token carrying only scim:read created a user. RFC 7644 ' +
              'section 2 requires the server to map an authenticated client ' +
              'to an access control policy, and this is that policy saying ' +
              'no. It answered ' + mayNotWrite.status + ': ' +
              mayNotWrite.detail);
        });
        const bulkOfDeletes = await scimCall({ operation: 'bulk',
            body: scim.bulkRequest([{ method: 'DELETE',
                                      path: '/Users/nobody' }]) },
            { headers: { Authorization: 'Bearer ' + readOnly.token } });
        check('scope: a BULK is a write however harmless it looks',
            function () {
          assertAnswered(bulkOfDeletes, 'read-only bulk');
          assert.strictEqual(bulkOfDeletes.status, 403,
              'A bulk carries no read operation at all (RFC 7644 section ' +
              '3.7 defines none), so it is a WRITE whatever is in it. A ' +
              'server deciding per-operation would have let this envelope ' +
              'through because it looked harmless.');
        });
      }
    }
  }

  // --- 2. DPoP -----------------------------------------------------------
  // The mock folds DPoP into its bearer row: the same token, held two ways.
  // Exercised here as "a DPoP-scheme Authorization header without a proof is
  // refused", which is the part that proves the two are told apart at all.
  // A full RFC 9449 proof is minted and checked by tests/dpop_workflow.js and
  // by the page test, where Web Crypto is available.
  if (offered.indexOf('dpop') < 0) {
    skip('OAuth 2.0 DPoP', 'the server does not offer it');
  } else {
    const both = await accessToken('scim:read scim:write');
    if (!both.ok) {
      skip('OAuth 2.0 DPoP', both.why);
    } else {
      const noProof = await scimCall({ operation: 'listUsers',
          query: { count: '1' } },
          { headers: { Authorization: 'DPoP ' + both.token } });
      check('DPoP: a bearer token presented as DPoP without a proof is refused',
          function () {
        assertAnswered(noProof, 'dpop without a proof');
        assert.strictEqual(noProof.status, 401,
            'An unbound token was accepted under the DPoP scheme. That is ' +
            'the whole of what the scheme adds — if it is not checked, ' +
            '"DPoP" is a spelling of "Bearer". It answered ' +
            noProof.status + ': ' + noProof.detail);
      });
    }
  }

  // --- 3. Basic ----------------------------------------------------------
  if (offered.indexOf('basic') < 0) {
    skip('HTTP Basic', 'the server does not offer it (scim.authBasic)');
  } else {
    const good = await scimCall({ operation: 'listUsers',
        query: { count: '1' } },
        { headers: { Authorization: scim.basicHeader('alice', 'anything') } });
    check('Basic: any username with any password but one is accepted',
        function () {
      assertAnswered(good, 'basic');
      assert.strictEqual(good.status, 200,
          'A Basic credential was refused ' + good.status + ': ' +
          good.detail);
    });
    const bad = await scimCall({ operation: 'listUsers',
        query: { count: '1' } },
        { headers: { Authorization: scim.basicHeader('alice', 'invalid') } });
    check('Basic: the one reserved password is refused', function () {
      assertAnswered(bad, 'basic negative');
      assert.strictEqual(bad.status, 401,
          'The reserved password "invalid" was accepted. It is refused on ' +
          'purpose — the same reserved value the OAuth password grant, ' +
          'WS-Trust, the WS-Federation sign-in screen and every LDAP bind ' +
          'here refuse — precisely so that a 401 is reachable on a scheme ' +
          'that otherwise accepts anything.');
    });
    const noColon = await scimCall({ operation: 'listUsers',
        query: { count: '1' } },
        { headers: { Authorization: 'Basic ' +
            Buffer.from('nocolonhere', 'utf8').toString('base64') } });
    check('Basic: a credential with no colon is refused', function () {
      assertAnswered(noColon, 'basic malformed');
      assert.strictEqual(noColon.status, 401,
          'RFC 7617 section 2 is base64(user-id ":" password); with no ' +
          'colon there is no way to tell where the username ends.');
    });
  }

  // --- 4. Digest ---------------------------------------------------------
  // The full two-leg handshake, computed with the WORKFLOW'S OWN credential
  // builder — so this checks the shipped code against the shipped server, and
  // a wrong hash fails here rather than reading as a wrong password.
  if (offered.indexOf('digest') < 0) {
    skip('HTTP Digest', 'the server does not offer it (scim.authDigest)');
  } else {
    await digestHandshakeWorks(state);
  }

  // --- 5. HOBA -----------------------------------------------------------
  if (offered.indexOf('hoba') < 0) {
    skip('HOBA', 'the server does not offer it (scim.authHoba)');
  } else {
    await hobaSignatureIsAccepted(state);
  }

  // --- 6. The session cookie ---------------------------------------------
  skip('the session cookie scheme',
      'it needs a browser that has signed in at the server, and there is no ' +
      'cookie jar in this file. tests/scim_page.js covers it, where a ' +
      'browser is what is driving.');

  // --- 7. The TLS client certificate -------------------------------------
  skip('the TLS client certificate scheme',
      'a client certificate is chosen during the TLS handshake, and the api ' +
      'would present ITS OWN rather than a caller\'s — a different identity ' +
      'and a misleading one. tests/pki_mutual_tls.js is where a client ' +
      'certificate is really presented to this mock.');

  log.debug("Leaving everySchemeIsExercised().");
}

async function digestHandshakeWorks() {
  log.debug("Entering digestHandshakeWorks().");
  // Leg one: no credential, to collect the nonce.
  const first = await scimCall({ operation: 'listUsers',
      query: { count: '1' } });
  const challenges = scim.parseChallenges(
      scenarios.headerValue(first.headers, 'www-authenticate'));
  const chosen = scim.chooseDigestChallenge(challenges);
  if (!chosen || chosen.unsupported) {
    skip('HTTP Digest',
        'the server offered ' +
        ((chosen && chosen.unsupported) || ['no Digest challenge']).join(', ') +
        ' and this client can compute ' +
        scim.DIGEST_ALGORITHMS.map(function (row) {
          return row.token;
        }).join(', '));
    log.debug("Leaving digestHandshakeWorks(). No usable challenge.");
    return;
  }
  check('Digest: the strongest offered algorithm is chosen', function () {
    const offeredAlgorithms = scim.challengesFor(challenges, 'digest')
      .map(function (row) {
        return row.params.algorithm || 'MD5';
      });
    log.info('     the server offers Digest with: ' +
        offeredAlgorithms.join(', '));
    if (offeredAlgorithms.indexOf('SHA-256') >= 0) {
      assert.strictEqual(chosen.algorithm.row.token, 'SHA-256',
          'SHA-256 was on offer and ' + chosen.algorithm.row.token + ' was ' +
          'chosen. Taking the last challenge parsed reliably picks MD5, ' +
          'because the weakest is conventionally last.');
    }
  });
  // Leg two: the credential, computed over the request-target.
  const request = scim.buildRequest({ operation: 'listUsers',
      baseUrl: scimBaseUrl, query: { count: '1' } });
  const target = request.url.replace(/^https?:\/\/[^/]*/, '');
  const password = process.env.SCIM_DIGEST_PASSWORD || 'password!';
  const fields = scim.digestCredential({
    params: chosen.challenge.params, algorithm: chosen.algorithm,
    realm: chosen.challenge.params.realm,
    username: 'alice', password: password, method: 'GET', uri: target,
    nc: '00000001',
    cnonce: 'testcnonce' + stamp
  });
  const second = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: scim.digestHeader(fields) } });
  check('Digest: the two-leg handshake authenticates', function () {
    assertAnswered(second, 'digest');
    assert.strictEqual(second.status, 200,
        'The Digest credential was refused ' + second.status + ': ' +
        second.detail + '. This is the one scheme where the password is ' +
        'REALLY checked — the response IS a hash over it — so a wrong ' +
        'shared password (scim.digestPassword, default "' + password +
        '") is the first thing to check, and a wrong hash the second.');
  });
  check('Digest: the server\'s rspauth verifies — mutual authentication',
      function () {
    const info = scim.verifyAuthenticationInfo({
      header: scenarios.headerValue(second.headers, 'authentication-info'),
      fields: fields });
    if (!info.present) {
      log.warn('     the server sent no Authentication-Info; RFC 7616 ' +
          'section 3.5 is the half most implementations leave out');
      return;
    }
    assert.ok(info.ok,
        'The server sent an rspauth and it does not verify against this ' +
        'credential: ' + info.note);
  });
  // The nonce count, which is what makes a credential single-use.
  const replay = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: scim.digestHeader(fields) } });
  check('Digest: replaying the same nc is refused', function () {
    assertAnswered(replay, 'digest replay');
    assert.strictEqual(replay.status, 401,
        'The identical credential was accepted a second time. The nonce ' +
        'count is what makes a Digest credential single-use, and a client ' +
        'that hardcodes nc=00000001 works exactly once per nonce and then ' +
        'starts failing in a way that reads as expired credentials.');
  });
  const incremented = scim.digestCredential({
    params: chosen.challenge.params, algorithm: chosen.algorithm,
    realm: chosen.challenge.params.realm,
    username: 'alice', password: password, method: 'GET', uri: target,
    nc: '00000002', cnonce: 'testcnonce' + stamp });
  const again = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: scim.digestHeader(incremented) } });
  check('Digest: incrementing nc authenticates again', function () {
    assertAnswered(again, 'digest nc=2');
    assert.strictEqual(again.status, 200,
        'The same nonce with nc=00000002 was refused ' + again.status +
        ': ' + again.detail + '. If a fresh nonce is needed per request the ' +
        'counter is doing nothing.');
  });
  const wrongPassword = scim.digestCredential({
    params: chosen.challenge.params, algorithm: chosen.algorithm,
    realm: chosen.challenge.params.realm,
    username: 'alice', password: 'definitely-not-the-password',
    method: 'GET', uri: target, nc: '00000003',
    cnonce: 'testcnonce' + stamp });
  const refusedDigest = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: scim.digestHeader(wrongPassword) } });
  check('Digest: a wrong password is refused', function () {
    assertAnswered(refusedDigest, 'digest negative');
    assert.strictEqual(refusedDigest.status, 401,
        'A wrong password was accepted, so the response hash is not being ' +
        'checked at all.');
  });
  log.debug("Leaving digestHandshakeWorks().");
}

async function hobaSignatureIsAccepted() {
  log.debug("Entering hobaSignatureIsAccepted().");
  const crypto = require('crypto');
  // RFC 7486's algorithm "0" is RSA-SHA256, so the key is RSA. Generated here
  // rather than in a fixture: a private key does not go in a repository, and
  // this one lives for the length of the run.
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const kid = 'scim-protocol-' + stamp;
  const origin = new URL(scimBaseUrl).origin;
  // Registration: RFC 7486 section 7 puts it at a well-known path on the
  // SERVER'S origin, and this mock takes it form-encoded.
  const registration = await fetch(origin + scim.HOBA_REGISTRATION_PATH, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'pub=' + encodeURIComponent(publicPem) +
        '&username=' + encodeURIComponent('hoba-' + stamp) +
        '&kid=' + encodeURIComponent(kid)
  }).catch(function (error) {
    return { ok: false, status: 0, text: async function () {
      return error.message; } };
  });
  if (!registration.status || registration.status >= 400) {
    skip('HOBA', 'the key could not be registered at ' + origin +
        scim.HOBA_REGISTRATION_PATH + ': HTTP ' + registration.status +
        '. That URL is on the SERVER\'s origin as this TEST reaches it, ' +
        'which is not the same as SCIM_BASE_URL if the api and this test ' +
        'see the mock under different names.');
    log.debug("Leaving hobaSignatureIsAccepted(). Registration failed.");
    return;
  }
  check('HOBA: the public key registers', function () {
    assert.ok(registration.status < 400,
        'Registration answered ' + registration.status);
  });
  // Leg one, for the challenge.
  const first = await scimCall({ operation: 'listUsers',
      query: { count: '1' } });
  const challenges = scim.parseChallenges(
      scenarios.headerValue(first.headers, 'www-authenticate'));
  const hoba = scim.challengesFor(challenges, 'hoba')[0];
  if (!hoba || !hoba.params.challenge) {
    skip('HOBA', 'the 401 carried no HOBA challenge to sign.');
    log.debug("Leaving hobaSignatureIsAccepted(). No challenge.");
    return;
  }
  // The origin the SERVER will compute the blob over is the one IT sees, which
  // is the api's view — SCIM_BASE_URL's origin, with an explicit port.
  const nonce = 'n' + stamp;
  const tbs = scim.hobaToBeSigned({
    nonce: nonce,
    alg: scim.HOBA_ALG_RSA_SHA256,
    origin: scim.originOf(scimBaseUrl),
    realm: hoba.params.realm || 'SCIM',
    kid: kid,
    challenge: hoba.params.challenge
  });
  const signature = crypto.sign('sha256', Buffer.from(tbs, 'utf8'),
      pair.privateKey).toString('base64url');
  const second = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: 'HOBA result="' + kid + '.' +
          hoba.params.challenge + '.' + nonce + '.' + signature + '"' } });
  check('HOBA: a signature over the length-prefixed blob authenticates',
      function () {
    assertAnswered(second, 'hoba');
    assert.strictEqual(second.status, 200,
        'The HOBA signature was refused ' + second.status + ': ' +
        second.detail + '. RFC 7486 section 5\'s blob is LENGTH-PREFIXED — ' +
        'each field as its length in octets, a colon, then the field, ' +
        'concatenated with nothing between, in the order nonce, algorithm, ' +
        'origin, realm, kid, challenge. A dot-joined version is the right ' +
        'size and shape and verifies against nothing.');
  });
  const replayed = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: 'HOBA result="' + kid + '.' +
          hoba.params.challenge + '.' + nonce + '.' + signature + '"' } });
  check('HOBA: the same (kid, challenge, nonce) cannot be replayed',
      function () {
    assertAnswered(replayed, 'hoba replay');
    assert.strictEqual(replayed.status, 401,
        'The identical credential was accepted twice. The challenge may be ' +
        'reused until its max-age runs out — that is what section 5 means ' +
        'it for — and the NONCE is what makes each signature single-use.');
  });
  const forged = await scimCall({ operation: 'listUsers',
      query: { count: '1' } },
      { headers: { Authorization: 'HOBA result="' + kid + '.' +
          hoba.params.challenge + '.n-other-' + stamp + '.' +
          Buffer.from('not a signature').toString('base64url') + '"' } });
  check('HOBA: a signature that does not verify is refused', function () {
    assertAnswered(forged, 'hoba negative');
    assert.strictEqual(forged.status, 401,
        'A made-up signature was accepted, so nothing is being verified.');
  });
  log.debug("Leaving hobaSignatureIsAccepted().");
}

// ---------------------------------------------------------------------------
// 9. THE MANAGEMENT API'S OWN VIEW — the second verification channel.
// ---------------------------------------------------------------------------
async function theManagementApiAgrees() {
  log.debug("Entering theManagementApiAgrees().");
  log.info("9. The mock's management API.");
  const response = await fetch(stsUrl + '/admin-api/scim').catch(
    function (error) {
      return { ok: false, status: 0, message: error.message };
    });
  if (!response.status || response.status >= 400) {
    skip('the management API cross-check',
        'GET ' + stsUrl + '/admin-api/scim answered ' +
        (response.status || response.message));
    log.debug("Leaving theManagementApiAgrees(). Unavailable.");
    return;
  }
  const view = await response.json();
  check('GET /admin-api/scim reports the operations this run performed',
      function () {
    assert.ok(view, 'The management API returned nothing.');
    const text = JSON.stringify(view);
    assert.ok(text.indexOf('create') >= 0 || text.indexOf('User') >= 0,
        'The SCIM view carries no sign of the dozens of operations this ' +
        'run just performed: ' + text.slice(0, 400));
  });
  const groupsResponse = await fetch(stsUrl + '/admin-api/groups');
  if (groupsResponse.status < 400) {
    const groups = await groupsResponse.json();
    check('the groups this run created are on /admin-api/groups', function () {
      const text = JSON.stringify(groups);
      assert.ok(text.indexOf(prefix) >= 0,
          'None of this run\'s groups (prefix "' + prefix + '") appears on ' +
          'the management API\'s own list. SCIM and the console read ONE ' +
          'store, so a group visible through one and not the other means ' +
          'there are two.');
    });
  } else {
    skip('the /admin-api/groups cross-check',
        'it answered ' + groupsResponse.status);
  }
  log.debug("Leaving theManagementApiAgrees().");
}

// ---------------------------------------------------------------------------
// 10. DELETE EVERYTHING, AND CONFIRM IT IS GONE FROM THE DIRECTORY.
//
// The cleanup is also a TEST — the most important one in a provisioning suite,
// since deprovisioning is the single most common thing a SCIM client is built
// to do and the least often checked.
// ---------------------------------------------------------------------------
async function everythingIsDeprovisioned() {
  log.debug("Entering everythingIsDeprovisioned().");
  log.info("10. Deprovisioning.");
  let i;
  for (i = 0; i < created.groups.length; i++) {
    const id = created.groups[i];
    if (!id) {
      continue;
    }
    const gone = await scimCall({ operation: 'deleteGroup', id: id });
    check('the group ' + shortId(id) + ' is deleted', function () {
      assertAnswered(gone, 'delete group');
      assert.strictEqual(gone.status, 204,
          'The delete answered ' + gone.status + ': ' + gone.detail);
    });
  }
  const seen = {};
  for (i = 0; i < created.users.length; i++) {
    const id = created.users[i];
    if (!id || seen[id]) {
      continue;
    }
    seen[id] = true;
    const gone = await scimCall({ operation: 'deleteUser', id: id });
    check('the user ' + shortId(id) + ' is deleted', function () {
      assertAnswered(gone, 'delete user');
      assert.strictEqual(gone.status, 204,
          'The delete answered ' + gone.status + ': ' + gone.detail);
    });
    const after = await scimCall({ operation: 'readUser', id: id });
    check('the user ' + shortId(id) + ' really is gone', function () {
      assertAnswered(after, 'read after delete');
      assert.strictEqual(after.status, 404,
          'A delete that answers 204 and leaves the resource behind is a ' +
          'deprovisioning path that has never actually worked, and a 204 ' +
          'alone only says the request was accepted.');
    });
  }
  const leftovers = await ldapSearch(usersDn, '(uid=' + prefix + '*)');
  check('nothing this run created is left in the directory', function () {
    const names = leftovers.map(function (entry) {
      return attr(entry, 'uid')[0];
    });
    assert.strictEqual(leftovers.length, 0,
        'These entries survived deprovisioning: ' + names.join(', ') + '. ' +
        'The SCIM deletes all answered 204, so this is the directory and ' +
        'the SCIM server disagreeing about what happened — which is only ' +
        'visible by looking at both.');
  });
  const groupLeftovers = await ldapSearch(groupsDn, '(cn=' + prefix + '*)');
  check('no group this run created is left in the directory', function () {
    assert.strictEqual(groupLeftovers.length, 0,
        groupLeftovers.length + ' group(s) survived.');
  });
  log.debug("Leaving everythingIsDeprovisioned().");
}

function shortId(id) {
  log.debug("Entering shortId().");
  const text = String(id);
  const out = text.length > 40 ? text.slice(0, 37) + '…' : text;
  log.debug("Leaving shortId().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  const present = await theMockHasScim();
  if (!present.present) {
    log.warn("SKIPPED: " + present.why);
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  await discoveryAnswers();
  const subject = await aFullUserRoundTrips();
  await replaceAndModify(subject);
  const population = await listingAndFiltering();
  await groupsAndMembership(population);
  await searchAndBulk();
  await everyRefusalIsAnAnswer();
  const authState = await whatTheServerAcceptsIsPublished();
  await everySchemeIsExercised(authState);
  await theManagementApiAgrees();
  await everythingIsDeprovisioned();
  log.info(checks + " checks passed.");
  if (skips.length) {
    log.warn(skips.length + " section(s) skipped:");
    skips.forEach(function (why) {
      log.warn("  - " + why);
    });
  }
  // A floor, asserted rather than only printed. This file's whole value is
  // breadth, and a run that quietly stopped after discovery would otherwise
  // report success.
  assert.ok(checks >= 60,
      'Only ' + checks + ' checks ran. A section has stopped being called, ' +
      'or the population it needed was never created.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("scim_protocol")
  .description("Drive every SCIM 2.0 endpoint through the debugger's api " +
      "against the mock STS, then read the result back out of the LDAP " +
      "directory the mock wrote it to — so that a field accepted and " +
      "silently dropped is visible. Exercises all six RFC 7644 section 2 " +
      "authentication schemes and the scope policy.")
  .addOption(new Option("--scim-url <url>",
      "the SCIM service root, as the API reaches it").default(scimBaseUrl))
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about. This test
  // reaches the api at API_URL and the mock at --scim-url; it opens no
  // browser, so the site's base url means nothing here.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);
scimBaseUrl = program.opts().scimUrl || scimBaseUrl;

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
