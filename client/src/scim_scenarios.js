// File: scim_scenarios.js
//
// ---------------------------------------------------------------------------
// A SCENARIO IS A PLAN, AND A PLAN IS DATA.
//
// This is the half of the SCIM workflow that turns "create ten users, put them
// in a group, change five of them and delete the lot" into a list of requests
// somebody can read before any of them is sent. It has no DOM, no network and
// no timers: `plan()` takes a scenario and returns steps, `resolve()` fills in
// the values that could only be known once an earlier step answered, and
// `judge()` says whether a step did what the plan said it would.
//
// The runner that performs them is in `scim.js`, because performing them is
// where the page, the progress table and the two call paths live. Keeping the
// PLAN here is what lets `tests/scim_engine.js` assert that the ten-user
// scenario really does compose ten distinct userNames and one group whose
// members are those ten ids — without a server, so a failure names the plan
// rather than the provisioning.
//
// ---------------------------------------------------------------------------
// A STEP CARRIES ITS OWN EXPECTATION, AND THAT IS THE WHOLE DESIGN.
//
// Every step says what it expects to happen: `expect.status` is the status or
// statuses that mean this step did its job, and `expect.scimType` is the RFC
// 7644 section 3.12 code where one is expected. So a scenario is not a script
// that runs and produces a log — it is a set of assertions, and the runner's
// green tick means "this is what the plan said would happen" rather than "the
// server answered something".
//
// That distinction is the reason the NEGATIVE scenarios work at all. A plan
// whose steps only recorded what came back would show a 409 as a failure and a
// 200 on a duplicate userName as a success — which is exactly backwards, and is
// how a provisioning client comes to be shipped with error handling nobody has
// ever seen run.
//
// ---------------------------------------------------------------------------
// REFERENCES: WHY A STEP CANNOT SIMPLY HOLD AN id.
//
// The id of a user created by step 3 is not known when the plan is built, so
// steps that need it hold a REFERENCE — `{ ref: 'user-3', field: 'id' }` — and
// `resolve()` substitutes it from the recorded results just before that step is
// sent. Three reasons this is a reference rather than a callback:
//
//   * a plan with a function in it cannot be shown to a person, stored, or
//     compared by a test,
//   * the substitution is then ONE piece of code, so a scenario that references
//     an id in a URL and a scenario that references one inside a PATCH body
//     cannot disagree about what a missing reference means,
//   * a reference that cannot be resolved is a DIAGNOSABLE state — the runner
//     reports "step 7 wanted the id from step 3, which did not run" — rather
//     than a request to `/Users/undefined`, which a server answers 404 and a
//     reader reads as a deleted user.
//
// ---------------------------------------------------------------------------
// RANDOM SCENARIOS ARE SEEDED AND THEREFORE REPRODUCIBLE.
//
// `randomScenario()` composes a shape, counts and a mix of operations out of
// `scim_client.js`'s seeded generator, so the page can show the seed beside the
// result and a person can re-run precisely the run that failed. That is the
// only thing that makes a random test harness worth having: an unseeded one
// produces failures that cannot be reproduced, which is a bug report nobody can
// act on.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var scim = require("./scim_client");

// A node consumer (tests/scim_engine.js) may have no CONFIG_FILE, so fall back
// to info rather than failing to load.
var log = bunyan.createLogger({
  name: "scim_scenarios",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// THE FILTER TOUR.
//
// RFC 7644 section 3.4.2.2 defines these operators and a server advertises
// filter support as one boolean — so a client that has only ever sent `eq` has
// no idea which of the other ten its server actually evaluates. Each row is a
// filter TEMPLATE with `{userName}` and `{family}` substituted at plan time.
//
// `pr` takes no comparison value and `not`/`and`/`or` are grouping rather than
// comparison, which is why they are separate rows rather than a value on one.
// ---------------------------------------------------------------------------
var FILTER_TOUR = [
  { op: 'eq', filter: 'userName eq "{userName}"', expectMatch: true,
    what: 'equal — the one every client sends' },
  { op: 'ne', filter: 'userName ne "{userName}"', expectMatch: false,
    what: 'not equal' },
  { op: 'co', filter: 'userName co "{tag}"', expectMatch: true,
    what: 'contains' },
  { op: 'sw', filter: 'userName sw "{prefix}"', expectMatch: true,
    what: 'starts with' },
  { op: 'ew', filter: 'userName ew "{tag}"', expectMatch: true,
    what: 'ends with' },
  { op: 'pr', filter: 'userName pr', expectMatch: true,
    what: 'present — no comparison value at all' },
  { op: 'gt', filter: 'meta.created gt "2000-01-01T00:00:00Z"',
    expectMatch: true, what: 'greater than, on a dateTime' },
  { op: 'ge', filter: 'meta.created ge "2000-01-01T00:00:00Z"',
    expectMatch: true, what: 'greater than or equal' },
  { op: 'lt', filter: 'meta.created lt "2999-01-01T00:00:00Z"',
    expectMatch: true, what: 'less than' },
  { op: 'le', filter: 'meta.created le "2999-01-01T00:00:00Z"',
    expectMatch: true, what: 'less than or equal' },
  { op: 'and', filter: 'userName eq "{userName}" and active eq true',
    expectMatch: true, what: 'and' },
  { op: 'or', filter: 'userName eq "{userName}" or userName eq "nobody"',
    expectMatch: true, what: 'or' },
  { op: 'not', filter: 'not (userName eq "nobody")', expectMatch: true,
    what: 'not, with the grouping parentheses it needs' },
  { op: 'complex', filter: 'emails[type eq "work"]', expectMatch: true,
    what: 'a complex attribute filter — the value filter grammar, which is ' +
        'where a hand-rolled parser stops working' }
];

// ---------------------------------------------------------------------------
// Step construction. One function so that every step in every scenario has the
// same members, including the ones a scenario does not use — a step missing
// `expect` would be judged as "no expectation, therefore fine", which is the
// silent pass this whole arrangement exists to avoid.
// ---------------------------------------------------------------------------
function step(row) {
  log.debug("Entering step(). " + (row && row.id));
  var out = {
    id: String(row.id),
    operation: String(row.operation),
    title: String(row.title || ''),
    why: String(row.why || ''),
    // A reference or a literal. Resolved by resolve() immediately before the
    // request is built.
    resourceId: row.resourceId === undefined ? null : row.resourceId,
    body: row.body === undefined ? null : row.body,
    query: row.query === undefined ? null : row.query,
    expect: {
      status: normalizeStatuses(row.expect && row.expect.status),
      scimType: (row.expect && row.expect.scimType) || '',
      // A named check the runner runs against the response body. The names are
      // a closed list in judge() below, for the same reason scimType is a
      // closed list in the specification: an open one is a place for a typo to
      // become a check that never runs.
      check: (row.expect && row.expect.check) || ''
    },
    // What of this step's answer later steps may reference.
    capture: row.capture === undefined ? null : row.capture
  };
  log.debug("Leaving step().");
  return out;
}

function normalizeStatuses(value) {
  log.debug("Entering normalizeStatuses().");
  if (value === undefined || value === null) {
    log.debug("Leaving normalizeStatuses(). Defaulting to any 2xx.");
    return ['2xx'];
  }
  var list = Array.isArray(value) ? value : [value];
  var out = list.map(function (item) {
    return String(item);
  });
  log.debug("Leaving normalizeStatuses(). " + out.length + " accepted.");
  return out;
}

function ref(stepId, field) {
  log.debug("Entering ref(). " + stepId + "." + field);
  var out = { ref: String(stepId), field: String(field || 'id') };
  log.debug("Leaving ref().");
  return out;
}

// Hot: called on every node of every body a plan walks, by resolve(),
// renameRefs() and the tests' own reference sweep. A log pair in a one-line
// predicate is not a trace, it is the entire log.
function isRef(value) {
  return value !== null && typeof value === 'object' &&
      typeof value.ref === 'string';
}

// ---------------------------------------------------------------------------
// RESOLVING REFERENCES.
//
// Walks a value — a scalar, an object or an array — and replaces every
// reference with what the named step captured. A reference to a step that did
// not run, or that captured nothing, is returned as an UNRESOLVED marker rather
// than as undefined: the runner refuses to send a request carrying one, which
// is the difference between a diagnosable skip and a 404 about `undefined`.
// ---------------------------------------------------------------------------
function resolve(value, captured) {
  // A HOT PATH: a fifty-user scenario walks several thousand nodes through
  // this function and its own recursion. It logs at plan and run boundaries in
  // the runner instead. Same exception cbor.js's item decoder takes.
  if (isRef(value)) {
    var source = captured[value.ref];
    if (source === undefined || source === null ||
        source[value.field] === undefined) {
      return { unresolved: value.ref + '.' + value.field };
    }
    return source[value.field];
  }
  if (Array.isArray(value)) {
    return value.map(function (item) {
      return resolve(item, captured);
    });
  }
  if (value !== null && typeof value === 'object') {
    var out = {};
    Object.keys(value).forEach(function (name) {
      out[name] = resolve(value[name], captured);
    });
    return out;
  }
  return value;
}

// Whether a resolved value still carries an unresolved marker anywhere in it.
//
// Hot, and for the same reason resolve() above is: it recurses over every node
// of every body, so it logs at the caller (prepare()) rather than here.
function unresolvedIn(value) {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'object' && typeof value.unresolved === 'string') {
    return value.unresolved;
  }
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) {
      var found = unresolvedIn(value[i]);
      if (found) {
        return found;
      }
    }
    return '';
  }
  if (typeof value === 'object') {
    var names = Object.keys(value);
    for (var n = 0; n < names.length; n++) {
      var hit = unresolvedIn(value[names[n]]);
      if (hit) {
        return hit;
      }
    }
  }
  return '';
}

// ---------------------------------------------------------------------------
// JUDGING ONE STEP.
//
// The status is matched against the accepted list, where `2xx` matches any
// success — a create answering 201 and a PATCH answering 200 or 204 are all
// "it worked", and pinning the exact number would make the plan a test of one
// server's choices rather than of the protocol. Where the exact number IS the
// point (204 on a delete, 501 on /Me, 409 on a duplicate) the scenario names
// it and no wildcard is used.
//
// `check` is a closed list of named body assertions. Keep it closed: an
// arbitrary predicate here would have to be a function, and a plan with a
// function in it is a plan a test cannot compare and a page cannot show.
// ---------------------------------------------------------------------------
function statusMatches(accepted, status) {
  log.debug("Entering statusMatches(). status=" + status);
  var text = String(status);
  var hit = false;
  accepted.forEach(function (want) {
    if (want === text) {
      hit = true;
      return;
    }
    if (/^[1-5]xx$/.test(want) && text.charAt(0) === want.charAt(0)) {
      hit = true;
    }
  });
  log.debug("Leaving statusMatches(). " + hit);
  return hit;
}

function judge(oneStep, result) {
  log.debug("Entering judge(). step=" + oneStep.id);
  var verdict = { ok: false, why: '' };
  if (!result || result.transportError) {
    verdict.why = 'No answer came back: ' +
        ((result && result.transportError) || 'the request was never sent') +
        '. That is not a SCIM result — it is the call not happening.';
    log.debug("Leaving judge(). No answer.");
    return verdict;
  }
  if (!statusMatches(oneStep.expect.status, result.status)) {
    verdict.why = 'Expected ' + oneStep.expect.status.join(' or ') +
        ' and the server answered ' + result.status +
        (result.scimType ? ' ' + result.scimType : '') + '.';
    log.debug("Leaving judge(). Wrong status.");
    return verdict;
  }
  if (oneStep.expect.scimType &&
      String(result.scimType || '') !== oneStep.expect.scimType) {
    verdict.why = 'Expected scimType "' + oneStep.expect.scimType +
        '" and got "' + (result.scimType || '(none)') + '". The status was ' +
        'right, so the server refused this for a different reason than the ' +
        'plan expected — which is the interesting half of a negative case.';
    log.debug("Leaving judge(). Wrong scimType.");
    return verdict;
  }
  var checkWhy = runCheck(oneStep.expect.check, result);
  if (checkWhy) {
    verdict.why = checkWhy;
    log.debug("Leaving judge(). Body check failed.");
    return verdict;
  }
  verdict.ok = true;
  verdict.why = 'As planned.';
  log.debug("Leaving judge(). Passed.");
  return verdict;
}

function runCheck(name, result) {
  log.debug("Entering runCheck(). check=" + (name || '(none)'));
  var body = result.body;
  if (!name) {
    log.debug("Leaving runCheck(). No check on this step.");
    return '';
  }
  if (name === 'hasId') {
    if (!body || !body.id) {
      log.debug("Leaving runCheck(). No id.");
      return 'The resource came back with no "id", so nothing later in this ' +
          'scenario can refer to it.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'hasLocation') {
    if (!result.headers || !headerValue(result.headers, 'location')) {
      log.debug("Leaving runCheck(). No Location.");
      return 'RFC 7644 section 3.3 says a create answers with a Location ' +
          'header and this one did not. The resource may still have been ' +
          'created — a client that follows Location will not find it.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'listNotEmpty') {
    if (!body || Number(body.totalResults) < 1) {
      log.debug("Leaving runCheck(). Empty list.");
      return 'The filter matched nothing. It was expected to match at least ' +
          'the resource this scenario just created.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'listEmpty') {
    if (body && Number(body.totalResults) > 0) {
      log.debug("Leaving runCheck(). List not empty.");
      return 'The filter matched ' + body.totalResults + ' resource(s) and ' +
          'was expected to match none.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'bulkAllSucceeded') {
    var operations = (body && body.Operations) || [];
    var bad = operations.filter(function (row) {
      return Number(row.status) >= 400;
    });
    if (!operations.length) {
      log.debug("Leaving runCheck(). Empty BulkResponse.");
      return 'The BulkResponse carried no operations at all.';
    }
    if (bad.length) {
      log.debug("Leaving runCheck(). " + bad.length + " refused.");
      return bad.length + ' of ' + operations.length + ' operations inside ' +
          'the bulk were refused — the envelope answered 200 because the ' +
          'bulk was processed, which is section 3.7 working as specified ' +
          'and is why this check reads inside it.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'membersPresent') {
    var members = (body && body.members) || [];
    if (!members.length) {
      log.debug("Leaving runCheck(). No members.");
      return 'The group came back with no members.';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  if (name === 'membersEmpty') {
    var left = (body && body.members) || [];
    if (left.length) {
      log.debug("Leaving runCheck(). " + left.length + " members remain.");
      return 'The group still has ' + left.length + ' member(s).';
    }
    log.debug("Leaving runCheck(). Passed.");
    return '';
  }
  log.debug("Leaving runCheck(). Unknown check name.");
  return 'This step names a check "' + name + '" that does not exist. That ' +
      'is a defect in the scenario, not in the server.';
}

function headerValue(headers, name) {
  log.debug("Entering headerValue(). name=" + name);
  var wanted = String(name).toLowerCase();
  var found = '';
  Object.keys(headers || {}).forEach(function (key) {
    if (key.toLowerCase() === wanted) {
      found = headers[key];
    }
  });
  log.debug("Leaving headerValue().");
  return found;
}

// ---------------------------------------------------------------------------
// THE SCENARIOS.
//
// Each row is a definition rather than a plan: `build(options)` produces the
// steps, because the count of users, the seed and the prefix are the caller's.
// `userCount`/`groupCount` say which of those a scenario reads, so the page can
// show only the controls a scenario actually uses instead of a fixed form with
// three fields that do nothing on eight of the twelve.
// ---------------------------------------------------------------------------
var SCENARIOS = [
  {
    id: 'discovery',
    label: 'Discovery — what does this server support?',
    takes: [],
    writes: false,
    what: 'Reads the three documents a client should read before it sends ' +
        'anything: the ServiceProviderConfig, the ResourceTypes and the ' +
        'Schemas. Needs no scope anywhere, which is what makes it the right ' +
        'first thing to run against a server you have not met.',
    build: buildDiscovery
  },
  {
    id: 'user-lifecycle',
    label: 'One user, all the way round',
    takes: ['seed', 'prefix'],
    writes: true,
    what: 'Create a user carrying every optional attribute RFC 7643 section ' +
        '4.1 defines, read it back, replace it with a PUT, modify it with ' +
        'three PATCH operations, then delete it and confirm the id is gone. ' +
        'The read-back is the interesting step: what comes back is what the ' +
        'server actually STORED, and the difference from what was sent is ' +
        'the answer to "does this field work".',
    build: buildUserLifecycle
  },
  {
    id: 'provision-team',
    label: 'Provision a team',
    takes: ['userCount', 'seed', 'prefix'],
    writes: true,
    what: 'Create N users, create a group, add all of them to it in one ' +
        'PATCH, read the group back, remove one member, then tear the whole ' +
        'thing down. This is what a provisioning integration does on its ' +
        'first run, and the membership PATCH is where most of them are ' +
        'wrong: membership is a fact about the GROUP and is never changed ' +
        'through a User resource.',
    build: buildProvisionTeam
  },
  {
    id: 'deprovision',
    label: 'Deprovision — create N, then delete N',
    takes: ['userCount', 'seed', 'prefix'],
    writes: true,
    what: 'The single most common thing a SCIM client is built to do and the ' +
        'least often tested. Each delete is followed by a read that expects ' +
        'a 404, because a delete that answers 204 and leaves the resource ' +
        'behind is a deprovisioning path that has never actually worked.',
    build: buildDeprovision
  },
  {
    id: 'modify-sweep',
    label: 'Modify a population',
    takes: ['userCount', 'seed', 'prefix'],
    writes: true,
    what: 'Create N users and then PATCH every one of them three ways: ' +
        'replace a simple attribute, add a value to a multi-valued one, and ' +
        'remove a sub-attribute through a value filter path — ' +
        'emails[type eq "home"], which is the section 3.5.2 path grammar ' +
        'that a server treating a path as a property name gets wrong.',
    build: buildModifySweep
  },
  {
    id: 'bulk',
    label: 'Bulk — many operations, one request',
    takes: ['userCount', 'seed', 'prefix'],
    writes: true,
    what: 'One BulkRequest that creates N users and a group whose members ' +
        'are those users, referenced as bulkId:name — the feature that makes ' +
        'a bulk more than a loop, because the group is created in the same ' +
        'request as the users it contains. Then one more bulk that deletes ' +
        'the lot.',
    build: buildBulk
  },
  {
    id: 'paging',
    label: 'Paging and sorting',
    takes: ['userCount', 'seed', 'prefix'],
    writes: true,
    what: 'Create N users, then walk the list a page at a time with count ' +
        'and startIndex, sorted both ways. SCIM paging is 1-INDEXED — ' +
        'startIndex 1 is the first resource, not the second — which is the ' +
        'off-by-one every client written against a 0-indexed API brings ' +
        'with it.',
    build: buildPaging
  },
  {
    id: 'filter-tour',
    label: 'Every filter operator',
    takes: ['seed', 'prefix'],
    writes: true,
    what: 'Create one user, then send all fourteen forms of RFC 7644 ' +
        'section 3.4.2.2 filter against it: the ten comparison operators, ' +
        'the three grouping ones, and a complex value filter. A server ' +
        'advertises filtering as one boolean, so this is the only way to ' +
        'find out which of them it really evaluates.',
    build: buildFilterTour
  },
  {
    id: 'search-post',
    label: 'Query by POST (/.search)',
    takes: ['seed', 'prefix'],
    writes: true,
    what: 'The same queries as a POST body — per resource type and then ' +
        'across both at once, which the per-type endpoint cannot do. Note ' +
        'that attributes and excludedAttributes are ARRAYS in a ' +
        'SearchRequest and a comma-separated string in a query string; that ' +
        'asymmetry is in the specification and is why a /.search often ' +
        'returns everything when the caller asked for two fields.',
    build: buildSearchPost
  },
  {
    id: 'enterprise',
    label: 'The enterprise extension',
    takes: ['seed', 'prefix'],
    writes: true,
    what: 'Create two users, set the second as the first\'s manager, and ' +
        'PATCH the section 4.3 extension attributes through their full URN ' +
        'paths — which is what makes an extension attribute different from a ' +
        'core one and is the part a client that has only sent core ' +
        'attributes has never exercised.',
    build: buildEnterprise
  },
  {
    id: 'negatives',
    label: 'The refusals',
    takes: ['seed', 'prefix'],
    writes: true,
    what: 'Every error this server can be made to produce on purpose: a ' +
        'refused userName, a duplicate one, an id that names nothing, a ' +
        'filter that cannot be parsed, a PATCH path that is not path ' +
        'grammar, and /Me. A client\'s error handling is the half that is ' +
        'never exercised, because a permissive server is hard to make say ' +
        'no — so these steps expect the refusal and FAIL if the server ' +
        'allows it.',
    build: buildNegatives
  },
  {
    id: 'scope-refusal',
    label: 'Read scope cannot write',
    takes: [],
    writes: true,
    needsAuth: true,
    what: 'Sends a write with a credential that carries only the read ' +
        'scope and expects a 403. It is the one scenario that asserts the ' +
        'access control policy rather than the protocol, so it needs a ' +
        'server with authentication turned on and a second, read-only ' +
        'credential configured in the pane above.',
    build: buildScopeRefusal
  }
];

var SCENARIOS_BY_ID = (function () {
  var index = {};
  SCENARIOS.forEach(function (row) {
    index[row.id] = row;
  });
  return index;
})();

function scenario(id) {
  log.debug("Entering scenario(). id=" + id);
  var row = SCENARIOS_BY_ID[String(id)] || null;
  log.debug("Leaving scenario().");
  return row;
}

// ---------------------------------------------------------------------------
// Options, normalized once so that every builder below reads the same shape and
// none of them has to defend against a missing count.
// ---------------------------------------------------------------------------
function settingsFrom(options) {
  log.debug("Entering settingsFrom().");
  var given = options || {};
  var out = {
    seed: given.seed === undefined || given.seed === ''
      ? 'scim-default-seed' : String(given.seed),
    prefix: given.prefix === undefined || given.prefix === ''
      ? 'scim' : String(given.prefix),
    userCount: Number(given.userCount) > 0 ? Math.floor(Number(given.userCount))
      : 5,
    groupCount: Number(given.groupCount) > 0
      ? Math.floor(Number(given.groupCount)) : 1,
    domain: given.domain || 'example.com'
  };
  // A ceiling, and it is here rather than on the page's number field because a
  // scenario built by randomScenario() never touches that field. Fifty users
  // is 150-odd requests, which is a long run and still a run; five hundred is
  // a page that appears to have hung.
  if (out.userCount > 50) {
    out.userCount = 50;
  }
  log.debug("Leaving settingsFrom(). userCount=" + out.userCount);
  return out;
}

function buildDiscovery() {
  log.debug("Entering buildDiscovery().");
  var steps = [
    step({ id: 'spc', operation: 'serviceProviderConfig',
      title: 'Read the ServiceProviderConfig',
      why: 'Everything else this page can do is a promise made here.',
      expect: { status: '200' } }),
    step({ id: 'resource-types', operation: 'resourceTypes',
      title: 'Read the ResourceTypes',
      why: 'Which resources exist and what extensions they carry.',
      expect: { status: '200' } }),
    step({ id: 'schemas', operation: 'schemas',
      title: 'Read the Schemas',
      why: 'Every attribute, with required/mutability/returned/uniqueness. ' +
          'This is the document that says whether a field you send was ever ' +
          'going to be stored.',
      expect: { status: '200' } }),
    step({ id: 'user-schema', operation: 'schema',
      resourceId: scim.USER_SCHEMA,
      title: 'Read the User schema by URN',
      why: 'One schema, fetched by its own identifier.',
      expect: { status: '200' } }),
    step({ id: 'user-type', operation: 'resourceType', resourceId: 'User',
      title: 'Read the User ResourceType',
      why: 'Note the id here is a NAME and not a resource id. That ' +
          'asymmetry is in the specification.',
      expect: { status: '200' } })
  ];
  log.debug("Leaving buildDiscovery(). " + steps.length + " step(s).");
  return steps;
}

function buildUserLifecycle(options) {
  log.debug("Entering buildUserLifecycle().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var full = scim.randomUser({ rng: rng, prefix: settings.prefix, index: 0,
                               domain: settings.domain });
  var replacement = scim.randomUser({ rng: rng, prefix: settings.prefix,
                                      index: 1, domain: settings.domain });
  // A PUT REPLACES, so the replacement keeps the SAME userName — changing it
  // as well would make a failure ambiguous between "the PUT did not apply" and
  // "the PUT created somebody else".
  replacement.userName = full.userName;
  var steps = [
    step({ id: 'create', operation: 'createUser', body: full,
      title: 'Create a user with every optional attribute',
      why: 'Everything RFC 7643 section 4.1 defines, the enterprise ' +
          'extension included. What comes back is what was stored.',
      expect: { status: '201', check: 'hasLocation' },
      capture: 'resource' }),
    step({ id: 'read-back', operation: 'readUser',
      resourceId: ref('create', 'id'),
      title: 'Read it back',
      why: 'The comparison against what was sent is the whole point: a ' +
          'field that is accepted and dropped and a field that round-trips ' +
          'are different answers and look the same at the moment of the ' +
          'create.',
      expect: { status: '200', check: 'hasId' } }),
    step({ id: 'read-projected', operation: 'readUser',
      resourceId: ref('create', 'id'),
      query: { attributes: 'userName,name.familyName' },
      title: 'Read it again, projected',
      why: 'attributes= asks for a subset. A server that ignores it returns ' +
          'the whole resource and nothing complains.',
      expect: { status: '200' } }),
    step({ id: 'replace', operation: 'replaceUser',
      resourceId: ref('create', 'id'), body: replacement,
      title: 'Replace it with a PUT',
      why: 'Every attribute left out of a PUT is one you are asking to have ' +
          'REMOVED. That is the difference from PATCH and it is the mistake ' +
          'worth making on purpose here.',
      expect: { status: '200' } }),
    step({ id: 'patch-replace', operation: 'modifyUser',
      resourceId: ref('create', 'id'),
      body: scim.patchOp([
        { op: 'replace', path: 'title', value: 'Directory Architect' },
        { op: 'replace', path: 'active', value: false }
      ]),
      title: 'PATCH — replace two simple attributes',
      why: 'The ordinary case, and the only PATCH most clients ever send.',
      expect: { status: ['200', '204'] } }),
    step({ id: 'patch-add', operation: 'modifyUser',
      resourceId: ref('create', 'id'),
      body: scim.patchOp([
        { op: 'add', path: 'emails',
          value: [{ value: 'added.by.patch@' + settings.domain,
                    type: 'other', primary: false }] }
      ]),
      title: 'PATCH — add to a multi-valued attribute',
      why: 'add on a multi-valued attribute APPENDS. A server that replaces ' +
          'the array instead silently loses the other addresses.',
      expect: { status: ['200', '204'] } }),
    step({ id: 'patch-remove', operation: 'modifyUser',
      resourceId: ref('create', 'id'),
      body: scim.patchOp([
        { op: 'remove', path: 'emails[type eq "other"]' }
      ]),
      title: 'PATCH — remove through a value filter path',
      why: 'emails[type eq "other"] is a PATH, not a property name. This is ' +
          'the section 3.5.2 grammar every hand-rolled SCIM server is ' +
          'subtly wrong about, and where a client\'s updates land on the ' +
          'wrong value.',
      expect: { status: ['200', '204'] } }),
    step({ id: 'delete', operation: 'deleteUser',
      resourceId: ref('create', 'id'),
      title: 'Delete it',
      why: 'There is no soft delete in SCIM. active:false is a different ' +
          'thing and does not do this.',
      expect: { status: '204' } }),
    step({ id: 'read-gone', operation: 'readUser',
      resourceId: ref('create', 'id'),
      title: 'Read it again and expect a 404',
      why: 'A delete that answers 204 and leaves the resource behind is a ' +
          'deprovisioning path that has never worked. This step FAILS if ' +
          'the user is still there.',
      expect: { status: '404' } })
  ];
  log.debug("Leaving buildUserLifecycle(). " + steps.length + " step(s).");
  return steps;
}

function buildProvisionTeam(options) {
  log.debug("Entering buildProvisionTeam().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var steps = [];
  var memberRefs = [];
  var i;
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'user-' + i, operation: 'createUser',
      body: scim.randomUser({ rng: rng, prefix: settings.prefix, index: i,
                              domain: settings.domain }),
      title: 'Create user ' + (i + 1) + ' of ' + settings.userCount,
      why: i === 0 ? 'Each user carries the full attribute set.' : '',
      expect: { status: '201', check: 'hasId' },
      capture: 'resource'
    }));
    memberRefs.push({ value: ref('user-' + i, 'id'), type: 'User' });
  }
  steps.push(step({
    id: 'group', operation: 'createGroup',
    body: scim.randomGroup({ rng: rng, prefix: settings.prefix }),
    title: 'Create the group, empty',
    why: 'Created empty on purpose, so that the membership change below is ' +
        'a PATCH against the group and can be read as one.',
    expect: { status: '201', check: 'hasId' },
    capture: 'resource'
  }));
  steps.push(step({
    id: 'add-members', operation: 'modifyGroup',
    resourceId: ref('group', 'id'),
    body: scim.patchOp([{ op: 'add', path: 'members', value: memberRefs }]),
    title: 'Add all ' + settings.userCount + ' users to the group',
    why: 'ONE PATCH against the GROUP. Membership is a fact about the ' +
        'group, so it is never changed through a User resource — which is ' +
        'where most provisioning integrations put it, and it looks right ' +
        'until somebody reads the group.',
    expect: { status: ['200', '204'] }
  }));
  steps.push(step({
    id: 'read-group', operation: 'readGroup', resourceId: ref('group', 'id'),
    title: 'Read the group back',
    why: 'The members should be there, as ids with a $ref each.',
    expect: { status: '200', check: 'membersPresent' }
  }));
  steps.push(step({
    id: 'groups-of-user', operation: 'listUsers',
    query: { filter: 'groups.value eq "GROUP_ID"' },
    title: 'Ask which users are in that group, from the User side',
    why: 'The groups attribute on a User is READ-ONLY (section 4.1.2) and ' +
        'is resolved from the group\'s own membership. Filtering on it is ' +
        'how the two sides are checked against each other.',
    expect: { status: ['200', '400'] }
  }));
  steps.push(step({
    id: 'remove-one', operation: 'modifyGroup',
    resourceId: ref('group', 'id'),
    body: scim.patchOp([
      { op: 'remove', path: 'members[value eq "MEMBER_ID"]' }
    ]),
    title: 'Remove one member through a value filter path',
    why: 'The path grammar again, on the attribute where getting it wrong ' +
        'empties the whole group instead of removing one person.',
    expect: { status: ['200', '204'] }
  }));
  steps.push(step({
    id: 'delete-group', operation: 'deleteGroup',
    resourceId: ref('group', 'id'),
    title: 'Delete the group',
    why: 'Deleting a group deletes the membership, not the members — the ' +
        'users below are still there to be deleted individually.',
    expect: { status: '204' }
  }));
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'delete-user-' + i, operation: 'deleteUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Delete user ' + (i + 1),
      why: '', expect: { status: '204' }
    }));
  }
  // The two steps above carry a literal placeholder in a filter and a path,
  // because a REFERENCE cannot appear inside a string the way it can in a
  // structure. They are substituted by the runner, which is the one place that
  // knows both the plan and the captured ids — see substituteInStrings().
  steps.forEach(function (row) {
    if (row.id === 'groups-of-user') {
      row.substitute = { GROUP_ID: ref('group', 'id') };
    }
    if (row.id === 'remove-one') {
      row.substitute = { MEMBER_ID: ref('user-0', 'id') };
    }
  });
  log.debug("Leaving buildProvisionTeam(). " + steps.length + " step(s).");
  return steps;
}

function buildDeprovision(options) {
  log.debug("Entering buildDeprovision().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var steps = [];
  var i;
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'user-' + i, operation: 'createUser',
      body: scim.randomUser({ rng: rng, prefix: settings.prefix, index: i,
                              domain: settings.domain }),
      title: 'Create user ' + (i + 1) + ' of ' + settings.userCount,
      why: '', expect: { status: '201', check: 'hasId' }, capture: 'resource'
    }));
  }
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'delete-' + i, operation: 'deleteUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Delete user ' + (i + 1),
      why: '', expect: { status: '204' }
    }));
    steps.push(step({
      id: 'gone-' + i, operation: 'readUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Confirm user ' + (i + 1) + ' is gone',
      why: i === 0 ? 'Every delete is followed by a read that expects 404. ' +
          'A 204 on the delete only says the request was accepted.' : '',
      expect: { status: '404' }
    }));
  }
  log.debug("Leaving buildDeprovision(). " + steps.length + " step(s).");
  return steps;
}

function buildModifySweep(options) {
  log.debug("Entering buildModifySweep().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var steps = [];
  var i;
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'user-' + i, operation: 'createUser',
      body: scim.randomUser({ rng: rng, prefix: settings.prefix, index: i,
                              domain: settings.domain }),
      title: 'Create user ' + (i + 1),
      why: '', expect: { status: '201', check: 'hasId' }, capture: 'resource'
    }));
  }
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'replace-title-' + i, operation: 'modifyUser',
      resourceId: ref('user-' + i, 'id'),
      body: scim.patchOp([
        { op: 'replace', path: 'title', value: 'Modified by sweep ' + i },
        { op: 'replace', path: 'userType', value: 'Contractor' }
      ]),
      title: 'PATCH replace on user ' + (i + 1),
      why: '', expect: { status: ['200', '204'] }
    }));
    steps.push(step({
      id: 'add-phone-' + i, operation: 'modifyUser',
      resourceId: ref('user-' + i, 'id'),
      body: scim.patchOp([
        { op: 'add', path: 'phoneNumbers',
          value: [{ value: '+1-555-0' + (100 + i), type: 'pager',
                    primary: false }] }
      ]),
      title: 'PATCH add on user ' + (i + 1),
      why: '', expect: { status: ['200', '204'] }
    }));
    steps.push(step({
      id: 'remove-home-' + i, operation: 'modifyUser',
      resourceId: ref('user-' + i, 'id'),
      body: scim.patchOp([
        { op: 'remove', path: 'emails[type eq "home"]' }
      ]),
      title: 'PATCH remove through a value filter on user ' + (i + 1),
      why: '', expect: { status: ['200', '204'] }
    }));
    steps.push(step({
      id: 'verify-' + i, operation: 'readUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Read user ' + (i + 1) + ' back',
      why: '', expect: { status: '200', check: 'hasId' }
    }));
  }
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'cleanup-' + i, operation: 'deleteUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Delete user ' + (i + 1),
      why: '', expect: { status: '204' }
    }));
  }
  log.debug("Leaving buildModifySweep(). " + steps.length + " step(s).");
  return steps;
}

function buildBulk(options) {
  log.debug("Entering buildBulk().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var creates = [];
  var members = [];
  var i;
  for (i = 0; i < settings.userCount; i++) {
    creates.push({
      method: 'POST', bulkId: 'user' + i, path: '/Users',
      data: scim.randomUser({ rng: rng, prefix: settings.prefix, index: i,
                              domain: settings.domain })
    });
    // THE FEATURE THAT MAKES A BULK MORE THAN A LOOP: the group below is
    // created in the SAME request as the users it contains, and refers to them
    // by the bulkId they have not been given an id for yet.
    members.push({ value: 'bulkId:user' + i, type: 'User' });
  }
  var group = scim.randomGroup({ rng: rng, prefix: settings.prefix });
  group.members = members;
  creates.push({ method: 'POST', bulkId: 'group0', path: '/Groups',
                 data: group });
  var steps = [
    step({ id: 'bulk-create', operation: 'bulk',
      body: scim.bulkRequest(creates, { failOnErrors: 1 }),
      title: 'One BulkRequest: ' + settings.userCount +
          ' users and a group that already contains them',
      why: 'failOnErrors:1 asks the server to stop at the first refusal. ' +
          'The envelope answers 200 because the bulk was PROCESSED — each ' +
          'operation carries its own status inside, which is what the check ' +
          'on this step reads.',
      expect: { status: '200', check: 'bulkAllSucceeded' },
      capture: 'bulk' }),
    step({ id: 'list-after', operation: 'listUsers',
      query: { filter: 'userName sw "' + settings.prefix + '."',
               count: '100' },
      title: 'List the users the bulk created',
      why: 'Read from the outside, so that "the bulk said 201" and "the ' +
          'user is there" are two separate findings.',
      expect: { status: '200', check: 'listNotEmpty' } })
  ];
  log.debug("Leaving buildBulk(). " + steps.length + " step(s).");
  return steps;
}

function buildPaging(options) {
  log.debug("Entering buildPaging().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var steps = [];
  var i;
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'user-' + i, operation: 'createUser',
      body: scim.randomUser({ rng: rng, prefix: settings.prefix, index: i,
                              domain: settings.domain }),
      title: 'Create user ' + (i + 1),
      why: '', expect: { status: '201', check: 'hasId' }, capture: 'resource'
    }));
  }
  var pageSize = Math.max(1, Math.floor(settings.userCount / 3));
  var pages = Math.ceil(settings.userCount / pageSize);
  for (i = 0; i < pages; i++) {
    steps.push(step({
      id: 'page-' + i, operation: 'listUsers',
      query: { filter: 'userName sw "' + settings.prefix + '."',
               startIndex: String(i * pageSize + 1),
               count: String(pageSize), sortBy: 'userName',
               sortOrder: 'ascending' },
      title: 'Page ' + (i + 1) + ' of ' + pages + ' — startIndex ' +
          (i * pageSize + 1) + ', count ' + pageSize,
      why: i === 0 ? 'SCIM paging is 1-INDEXED: startIndex 1 is the FIRST ' +
          'resource. A client written against a 0-indexed API skips one ' +
          'resource on every page and never notices.' : '',
      expect: { status: '200', check: 'listNotEmpty' }
    }));
  }
  steps.push(step({
    id: 'sort-descending', operation: 'listUsers',
    query: { filter: 'userName sw "' + settings.prefix + '."',
             sortBy: 'userName', sortOrder: 'descending',
             count: String(settings.userCount) },
    title: 'The same list, sorted the other way',
    why: 'Sorting is advertised as one boolean too. Both orders are asked ' +
        'for so that a server that ignores sortOrder is visible.',
    expect: { status: '200', check: 'listNotEmpty' }
  }));
  steps.push(step({
    id: 'count-zero', operation: 'listUsers',
    query: { filter: 'userName sw "' + settings.prefix + '."', count: '0' },
    title: 'count=0 — how many are there?',
    why: 'Section 3.4.2.4: count=0 asks for the TOTAL with no resources. It ' +
        'is how a client sizes a job before it starts one, and a server ' +
        'that returns everything instead has just been asked for the whole ' +
        'directory.',
    expect: { status: '200' }
  }));
  for (i = 0; i < settings.userCount; i++) {
    steps.push(step({
      id: 'cleanup-' + i, operation: 'deleteUser',
      resourceId: ref('user-' + i, 'id'),
      title: 'Delete user ' + (i + 1),
      why: '', expect: { status: '204' }
    }));
  }
  log.debug("Leaving buildPaging(). " + steps.length + " step(s).");
  return steps;
}

function buildFilterTour(options) {
  log.debug("Entering buildFilterTour().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var user = scim.randomUser({ rng: rng, prefix: settings.prefix, index: 0,
                               domain: settings.domain });
  var tag = user.userName.slice(user.userName.lastIndexOf('.') + 1);
  var steps = [
    step({ id: 'create', operation: 'createUser', body: user,
      title: 'Create the user the filters will look for',
      why: '', expect: { status: '201', check: 'hasId' }, capture: 'resource' })
  ];
  FILTER_TOUR.forEach(function (row) {
    var filter = row.filter
      .split('{userName}').join(user.userName)
      .split('{tag}').join(tag)
      .split('{prefix}').join(settings.prefix + '.')
      .split('{family}').join(user.name.familyName);
    steps.push(step({
      id: 'filter-' + row.op, operation: 'listUsers',
      query: { filter: filter, count: '50' },
      title: row.op + ' — ' + row.what,
      why: filter,
      // A server that does not evaluate an operator answers 400 invalidFilter,
      // which is a legitimate answer and NOT a failure of this page — so both
      // are accepted and the readout says which happened. A scenario that
      // failed on 400 here would be asserting that every server implements
      // every operator, which no specification requires.
      expect: { status: ['200', '400'] }
    }));
  });
  steps.push(step({
    id: 'bad-filter', operation: 'listUsers',
    query: { filter: 'userName zz "nobody"' },
    title: 'A filter that is not grammar at all',
    why: 'zz is not an operator. This is the reachable invalidFilter, and ' +
        'this step FAILS if the server accepts it.',
    expect: { status: '400', scimType: 'invalidFilter' }
  }));
  steps.push(step({
    id: 'cleanup', operation: 'deleteUser', resourceId: ref('create', 'id'),
    title: 'Delete the user', why: '', expect: { status: '204' }
  }));
  log.debug("Leaving buildFilterTour(). " + steps.length + " step(s).");
  return steps;
}

function buildSearchPost(options) {
  log.debug("Entering buildSearchPost().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var user = scim.randomUser({ rng: rng, prefix: settings.prefix, index: 0,
                               domain: settings.domain });
  var group = scim.randomGroup({ rng: rng, prefix: settings.prefix });
  var steps = [
    step({ id: 'create-user', operation: 'createUser', body: user,
      title: 'Create a user', why: '',
      expect: { status: '201', check: 'hasId' }, capture: 'resource' }),
    step({ id: 'create-group', operation: 'createGroup', body: group,
      title: 'Create a group', why: '',
      expect: { status: '201', check: 'hasId' }, capture: 'resource' }),
    step({ id: 'search-users', operation: 'searchUsers',
      body: scim.searchRequest({ filter: 'userName eq "' + user.userName +
                                 '"', count: 10 }),
      title: 'POST /Users/.search',
      why: 'The same query as a body. It exists for a filter too long for a ' +
          'URL, and for one carrying something that should not be in an ' +
          'access log.',
      expect: { status: '200', check: 'listNotEmpty' } }),
    step({ id: 'search-projected', operation: 'searchUsers',
      body: scim.searchRequest({ filter: 'userName eq "' + user.userName +
                                 '"', attributes: 'userName,id' }),
      title: 'The same search, asking for two attributes',
      why: 'attributes is an ARRAY in a SearchRequest and a comma-separated ' +
          'STRING in a query string. That asymmetry is in the ' +
          'specification, and sending the string form here is why a ' +
          '/.search so often returns everything.',
      expect: { status: '200', check: 'listNotEmpty' } }),
    step({ id: 'search-groups', operation: 'searchGroups',
      body: scim.searchRequest({ filter: 'displayName eq "' +
                                 group.displayName + '"' }),
      title: 'POST /Groups/.search', why: '',
      expect: { status: '200', check: 'listNotEmpty' } }),
    step({ id: 'search-all', operation: 'searchAll',
      body: scim.searchRequest({ filter: 'id pr', count: 20 }),
      title: 'POST /.search — across BOTH resource types',
      why: 'The one thing the per-type endpoint cannot do. The ListResponse ' +
          'comes back mixed, so read each entry\'s own schemas to tell a ' +
          'User from a Group.',
      expect: { status: '200', check: 'listNotEmpty' } }),
    step({ id: 'search-no-schema', operation: 'searchAll',
      body: { filter: 'id pr' },
      title: 'A .search body with no schemas member',
      why: 'Section 3.4.3 requires the SearchRequest URN in schemas. This ' +
          'step FAILS if the server accepts a body without it — a ' +
          'permissive server here is how a client comes to send a ' +
          'non-conforming body to everybody else.',
      expect: { status: '400' } }),
    step({ id: 'cleanup-user', operation: 'deleteUser',
      resourceId: ref('create-user', 'id'),
      title: 'Delete the user', why: '', expect: { status: '204' } }),
    step({ id: 'cleanup-group', operation: 'deleteGroup',
      resourceId: ref('create-group', 'id'),
      title: 'Delete the group', why: '', expect: { status: '204' } })
  ];
  log.debug("Leaving buildSearchPost(). " + steps.length + " step(s).");
  return steps;
}

function buildEnterprise(options) {
  log.debug("Entering buildEnterprise().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var manager = scim.randomUser({ rng: rng, prefix: settings.prefix,
                                  index: 0, domain: settings.domain });
  var report = scim.randomUser({ rng: rng, prefix: settings.prefix,
                                 index: 1, domain: settings.domain });
  var ext = scim.ENTERPRISE_SCHEMA;
  var steps = [
    step({ id: 'manager', operation: 'createUser', body: manager,
      title: 'Create the manager', why: '',
      expect: { status: '201', check: 'hasId' }, capture: 'resource' }),
    step({ id: 'report', operation: 'createUser', body: report,
      title: 'Create the direct report',
      why: 'Both carry the whole section 4.3 extension already; what is ' +
          'missing from both is manager, because a generator inventing one ' +
          'produces a dangling reference on every user.',
      expect: { status: '201', check: 'hasId' }, capture: 'resource' }),
    step({ id: 'set-manager', operation: 'modifyUser',
      resourceId: ref('report', 'id'),
      body: scim.patchOp([
        { op: 'replace', path: ext + ':manager',
          value: { value: 'MANAGER_ID' } }
      ]),
      title: 'PATCH the manager through the extension URN path',
      why: 'An extension attribute is addressed by its FULL URN followed by ' +
          'a colon and the attribute name. That is what makes it different ' +
          'from a core attribute, and a client that has only sent core ones ' +
          'has never exercised this path form.',
      expect: { status: ['200', '204'] } }),
    step({ id: 'read-report', operation: 'readUser',
      resourceId: ref('report', 'id'),
      title: 'Read the report back',
      why: 'The extension object should carry both what was created and ' +
          'the manager just patched in.',
      expect: { status: '200', check: 'hasId' } }),
    step({ id: 'read-extension-only', operation: 'readUser',
      resourceId: ref('report', 'id'),
      query: { attributes: ext + ':department,' + ext + ':employeeNumber' },
      title: 'Read only two extension attributes',
      why: 'A projection naming extension attributes by URN. A server that ' +
          'only understands core attribute names returns everything.',
      expect: { status: '200' } }),
    step({ id: 'filter-extension', operation: 'listUsers',
      query: { filter: ext + ':department eq "' +
               (report[ext] && report[ext].department) + '"', count: '50' },
      title: 'Filter on an extension attribute',
      why: 'Filtering by URN-qualified name. Accepted or refused, the ' +
          'answer is worth knowing before a migration depends on it.',
      expect: { status: ['200', '400'] } }),
    step({ id: 'cleanup-report', operation: 'deleteUser',
      resourceId: ref('report', 'id'), title: 'Delete the report', why: '',
      expect: { status: '204' } }),
    step({ id: 'cleanup-manager', operation: 'deleteUser',
      resourceId: ref('manager', 'id'), title: 'Delete the manager', why: '',
      expect: { status: '204' } })
  ];
  steps.forEach(function (row) {
    if (row.id === 'set-manager') {
      row.substitute = { MANAGER_ID: ref('manager', 'id') };
    }
  });
  log.debug("Leaving buildEnterprise(). " + steps.length + " step(s).");
  return steps;
}

function buildNegatives(options) {
  log.debug("Entering buildNegatives().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var first = scim.randomUser({ rng: rng, prefix: settings.prefix, index: 0,
                                domain: settings.domain });
  var duplicate = scim.randomUser({ rng: rng, prefix: settings.prefix,
                                    index: 1, domain: settings.domain });
  duplicate.userName = first.userName;
  var steps = [
    step({ id: 'refused-name', operation: 'createUser',
      body: { schemas: [scim.USER_SCHEMA], userName: 'invalid' },
      title: 'Create a user named "invalid"',
      why: 'This project\'s mock refuses exactly one userName, the same way ' +
          'it refuses exactly one password everywhere else — so that a 400 ' +
          'invalidValue is reachable on a server that otherwise accepts ' +
          'anything. Against somebody else\'s server this step may well ' +
          'succeed, and the readout says so.',
      expect: { status: '400', scimType: 'invalidValue' } }),
    step({ id: 'no-username', operation: 'createUser',
      body: { schemas: [scim.USER_SCHEMA], displayName: 'No userName here' },
      title: 'Create a user with no userName',
      why: 'userName is the one REQUIRED attribute on a User. A server that ' +
          'accepts this has a schema it does not enforce.',
      expect: { status: '400' } }),
    step({ id: 'wrong-schema', operation: 'createUser',
      body: { schemas: [scim.GROUP_SCHEMA], userName: 'wrong.schema.user' },
      title: 'Create a user whose schemas says Group',
      why: 'The schemas member is what tells the server what it is being ' +
          'sent. A mismatch is invalidSyntax or invalidValue depending on ' +
          'where the server notices.',
      expect: { status: ['400', '404'] } }),
    step({ id: 'create-first', operation: 'createUser', body: first,
      title: 'Create a user, legitimately',
      why: 'So that the next step has somebody to collide with.',
      expect: { status: '201', check: 'hasId' }, capture: 'resource' }),
    step({ id: 'duplicate', operation: 'createUser', body: duplicate,
      title: 'Create a second user with the same userName',
      why: 'userName carries SCIM\'s uniqueness constraint, so this is the ' +
          'reachable 409. A client that treats every 4xx alike cannot tell ' +
          'this from a malformed request, and they need different handling: ' +
          'one is retryable with a new name and one is not retryable at all.',
      expect: { status: '409', scimType: 'uniqueness' } }),
    step({ id: 'missing-id', operation: 'readUser',
      resourceId: 'this-id-names-nobody',
      title: 'Read an id that names nothing',
      why: 'The plain 404.',
      expect: { status: '404' } }),
    step({ id: 'delete-missing', operation: 'deleteUser',
      resourceId: 'this-id-names-nobody',
      title: 'Delete an id that names nothing',
      why: 'Also a 404. A server answering 204 here is claiming to have ' +
          'deleted something that was never there, which makes a ' +
          'deprovisioning run impossible to audit.',
      expect: { status: '404' } }),
    step({ id: 'bad-patch-path', operation: 'modifyUser',
      resourceId: ref('create-first', 'id'),
      body: scim.patchOp([
        { op: 'replace', path: 'emails[type eq ', value: 'x' }
      ]),
      title: 'PATCH with a path that is not path grammar',
      why: 'An unterminated value filter. Section 3.5.2 gives this its own ' +
          'scimType — invalidPath — separate from invalidFilter, because a ' +
          'PATCH path and a query filter are different grammars that look ' +
          'alike.',
      expect: { status: '400', scimType: ['invalidPath'] } }),
    step({ id: 'no-target', operation: 'modifyUser',
      resourceId: ref('create-first', 'id'),
      body: scim.patchOp([
        { op: 'remove', path: 'emails[type eq "nosuchtype"]' }
      ]),
      title: 'PATCH remove against a path that matches nothing',
      why: 'Valid grammar, no target. Section 3.5.2 says a remove needs a ' +
          'target that exists — noTarget — though several servers treat it ' +
          'as a no-op and answer 204, so both are accepted here and the ' +
          'readout says which you got.',
      expect: { status: ['400', '200', '204'] } }),
    step({ id: 'me', operation: 'me',
      title: 'GET /Me',
      why: 'An alias for the authenticated subject. A server with no ' +
          'authenticated subject has nothing to alias; this project\'s mock ' +
          'answers 501 saying exactly that, which is more use than a 404.',
      expect: { status: ['501', '401', '404', '200'] } }),
    step({ id: 'cleanup', operation: 'deleteUser',
      resourceId: ref('create-first', 'id'),
      title: 'Delete the user', why: '', expect: { status: '204' } })
  ];
  // scimType is a single string on a step; the bad-patch-path row above wants
  // one value and is written as a list for readability. Flatten it here rather
  // than teaching judge() a second shape.
  steps.forEach(function (row) {
    if (Array.isArray(row.expect.scimType)) {
      row.expect.scimType = row.expect.scimType[0];
    }
  });
  log.debug("Leaving buildNegatives(). " + steps.length + " step(s).");
  return steps;
}

function buildScopeRefusal(options) {
  log.debug("Entering buildScopeRefusal().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed);
  var steps = [
    step({ id: 'read-allowed', operation: 'listUsers',
      query: { count: '1' },
      title: 'A read, with the read-only credential',
      why: 'The credential holds the read scope, so this is allowed and is ' +
          'the control: without it a 403 below could equally mean the ' +
          'credential is simply broken.',
      expect: { status: '200' } }),
    step({ id: 'write-refused', operation: 'createUser',
      body: scim.randomUser({ rng: rng, prefix: settings.prefix, index: 0,
                              domain: settings.domain }),
      title: 'A write, with the same read-only credential',
      why: 'RFC 7644 section 2 requires the server to map an authenticated ' +
          'client to an access control policy. This is that policy saying ' +
          'no, and the step FAILS if the write is allowed.',
      expect: { status: '403' } }),
    step({ id: 'bulk-refused', operation: 'bulk',
      body: scim.bulkRequest([
        { method: 'DELETE', path: '/Users/nobody' }
      ]),
      title: 'A bulk of nothing but a delete, with the read-only credential',
      why: 'A bulk carries no read operation at all, so it is a WRITE ' +
          'whatever is in it. A server that decided per-operation would let ' +
          'this envelope through because it looked harmless.',
      expect: { status: '403' } })
  ];
  log.debug("Leaving buildScopeRefusal(). " + steps.length + " step(s).");
  return steps;
}

// ---------------------------------------------------------------------------
// A RANDOM SCENARIO.
//
// Composed out of the same builders rather than out of a second set of steps,
// because a random scenario made of its own step-building code would be the one
// path nothing else covers. What is random is the SHAPE — which phases run, in
// what order, over how many users — and it is seeded, so the page can show the
// seed and a person can run precisely this again.
// ---------------------------------------------------------------------------
var RANDOM_PHASES = [
  { id: 'user-lifecycle', weight: 2 },
  { id: 'provision-team', weight: 3 },
  { id: 'deprovision', weight: 2 },
  { id: 'modify-sweep', weight: 2 },
  { id: 'bulk', weight: 2 },
  { id: 'paging', weight: 1 },
  { id: 'filter-tour', weight: 1 },
  { id: 'search-post', weight: 1 },
  { id: 'enterprise', weight: 1 },
  { id: 'negatives', weight: 1 }
];

function randomScenario(options) {
  log.debug("Entering randomScenario().");
  var settings = settingsFrom(options);
  var rng = scim.newRng(settings.seed + ':shape');
  var pool = [];
  RANDOM_PHASES.forEach(function (row) {
    var i;
    for (i = 0; i < row.weight; i++) {
      pool.push(row.id);
    }
  });
  var phaseCount = 2 + Math.floor(rng() * 3);
  var chosen = [];
  var guard = 0;
  while (chosen.length < phaseCount && guard < 100) {
    guard++;
    var candidate = pool[Math.floor(rng() * pool.length) % pool.length];
    if (chosen.indexOf(candidate) < 0) {
      chosen.push(candidate);
    }
  }
  var steps = [];
  var titles = [];
  chosen.forEach(function (id, index) {
    var definition = scenario(id);
    if (!definition) {
      return;
    }
    // Each phase gets its own PREFIX and its own SEED derived from the run's,
    // so two phases in one random scenario cannot collide on a userName — which
    // would produce a 409 that the plan did not expect and that reads as a
    // server fault rather than as a generator fault.
    var phaseSteps = definition.build({
      seed: settings.seed + ':' + id + ':' + index,
      prefix: settings.prefix + 'r' + index,
      userCount: 1 + Math.floor(rng() * Math.min(settings.userCount, 6)),
      domain: settings.domain
    });
    titles.push(definition.label);
    phaseSteps.forEach(function (row) {
      // Namespace every step id, or two phases that both have a step called
      // `create` would resolve each other's references — which is a scenario
      // deleting a user another phase is still using, and it would look like
      // the server losing one.
      var copy = renameStep(row, 'p' + index + '-');
      steps.push(copy);
    });
  });
  var out = {
    id: 'random',
    label: 'Random — ' + titles.join(', '),
    seed: settings.seed,
    phases: chosen,
    steps: steps
  };
  log.debug("Leaving randomScenario(). " + chosen.length + " phase(s), " +
      steps.length + " step(s).");
  return out;
}

function renameStep(row, prefix) {
  log.debug("Entering renameStep().");
  var copy = JSON.parse(JSON.stringify(row));
  copy.id = prefix + copy.id;
  copy.resourceId = renameRefs(copy.resourceId, prefix);
  copy.body = renameRefs(copy.body, prefix);
  copy.substitute = renameRefs(copy.substitute, prefix);
  log.debug("Leaving renameStep(). " + copy.id);
  return copy;
}

// Hot: walks every node of every body in a scenario.
function renameRefs(value, prefix) {
  if (isRef(value)) {
    return { ref: prefix + value.ref, field: value.field };
  }
  if (Array.isArray(value)) {
    return value.map(function (item) {
      return renameRefs(item, prefix);
    });
  }
  if (value !== null && typeof value === 'object') {
    var out = {};
    Object.keys(value).forEach(function (name) {
      out[name] = renameRefs(value[name], prefix);
    });
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// THE PLAN a caller actually runs.
//
// One entry point for both the named scenarios and the random one, so the
// runner has a single shape to consume and the page has a single thing to draw.
// ---------------------------------------------------------------------------
function plan(id, options) {
  log.debug("Entering plan(). id=" + id);
  if (String(id) === 'random') {
    var random = randomScenario(options);
    log.debug("Leaving plan(). Random, " + random.steps.length + " step(s).");
    return random;
  }
  var definition = scenario(id);
  if (!definition) {
    log.debug("Leaving plan(). No such scenario.");
    throw new Error('No such scenario: ' + id);
  }
  var settings = settingsFrom(options);
  var out = {
    id: definition.id,
    label: definition.label,
    seed: settings.seed,
    phases: [definition.id],
    steps: definition.build(settings)
  };
  log.debug("Leaving plan(). " + out.steps.length + " step(s).");
  return out;
}

// ---------------------------------------------------------------------------
// STRING SUBSTITUTION, which is the second half of references.
//
// A reference can be a value in a structure; it cannot be a fragment of a
// string, and several steps need exactly that — an id inside a filter, an id
// inside a PATCH value-filter path. So those steps carry a `substitute` map of
// placeholder to reference, and this replaces the placeholder everywhere in the
// step once the reference resolves.
//
// The placeholders are SHOUTED (`GROUP_ID`) so that one left unsubstituted is
// visible in the request the page shows rather than being mistaken for a value.
// ---------------------------------------------------------------------------
function substituteInStrings(value, replacements) {
  // Hot: walks every node of a body.
  if (typeof value === 'string') {
    var out = value;
    Object.keys(replacements).forEach(function (name) {
      out = out.split(name).join(replacements[name]);
    });
    return out;
  }
  if (Array.isArray(value)) {
    return value.map(function (item) {
      return substituteInStrings(item, replacements);
    });
  }
  if (value !== null && typeof value === 'object') {
    var copy = {};
    Object.keys(value).forEach(function (name) {
      copy[name] = substituteInStrings(value[name], replacements);
    });
    return copy;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Prepare one step for sending: resolve its references, apply its string
// substitutions, and report an unresolved one rather than sending it.
// ---------------------------------------------------------------------------
function prepare(oneStep, captured) {
  log.debug("Entering prepare(). step=" + oneStep.id);
  var resourceId = resolve(oneStep.resourceId, captured);
  var body = resolve(oneStep.body, captured);
  var query = resolve(oneStep.query, captured);
  var missing = unresolvedIn(resourceId) || unresolvedIn(body) ||
      unresolvedIn(query);
  if (missing) {
    log.debug("Leaving prepare(). Unresolved reference: " + missing);
    return { skipped: true, reason: 'This step needs ' + missing +
        ', which no earlier step produced — usually because that step did ' +
        'not run or was refused. It was not sent.' };
  }
  if (oneStep.substitute) {
    var replacements = {};
    var unresolvedName = '';
    Object.keys(oneStep.substitute).forEach(function (name) {
      var value = resolve(oneStep.substitute[name], captured);
      var gap = unresolvedIn(value);
      if (gap) {
        unresolvedName = gap;
        return;
      }
      replacements[name] = String(value);
    });
    if (unresolvedName) {
      log.debug("Leaving prepare(). Unresolved substitution.");
      return { skipped: true, reason: 'This step needs ' + unresolvedName +
          ' to fill a placeholder in its filter or path, and that step did ' +
          'not produce one. It was not sent.' };
    }
    resourceId = substituteInStrings(resourceId, replacements);
    body = substituteInStrings(body, replacements);
    query = substituteInStrings(query, replacements);
  }
  var out = { skipped: false, resourceId: resourceId, body: body,
              query: query };
  log.debug("Leaving prepare(). Ready.");
  return out;
}

// What a step contributes to `captured` once it has answered.
function capture(oneStep, result) {
  log.debug("Entering capture(). step=" + oneStep.id);
  if (!oneStep.capture || !result || !result.body) {
    log.debug("Leaving capture(). Nothing to capture.");
    return null;
  }
  if (oneStep.capture === 'resource') {
    var captured = { id: result.body.id,
                     userName: result.body.userName,
                     displayName: result.body.displayName,
                     location: headerValue(result.headers, 'location') };
    log.debug("Leaving capture(). id=" + captured.id);
    return captured;
  }
  if (oneStep.capture === 'bulk') {
    // Each BulkResponse operation carries the bulkId it was given and the
    // location of what it created; that pair is the only way a later step can
    // reach something a bulk made.
    var byBulkId = {};
    ((result.body && result.body.Operations) || []).forEach(function (row) {
      if (row.bulkId) {
        byBulkId[row.bulkId] = row.location || '';
      }
    });
    log.debug("Leaving capture(). " + Object.keys(byBulkId).length +
        " bulkId(s).");
    return { bulkIds: byBulkId };
  }
  log.debug("Leaving capture(). Unknown capture kind.");
  return null;
}

module.exports = {
  FILTER_TOUR: FILTER_TOUR,
  SCENARIOS: SCENARIOS,
  RANDOM_PHASES: RANDOM_PHASES,
  scenario: scenario,
  settingsFrom: settingsFrom,
  step: step,
  ref: ref,
  isRef: isRef,
  resolve: resolve,
  unresolvedIn: unresolvedIn,
  statusMatches: statusMatches,
  judge: judge,
  runCheck: runCheck,
  headerValue: headerValue,
  plan: plan,
  randomScenario: randomScenario,
  substituteInStrings: substituteInStrings,
  prepare: prepare,
  capture: capture
};
